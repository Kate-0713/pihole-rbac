// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"sync"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/auth"
)

const (
	// pendingLoginTTL is how long someone has to enter their code after their password was accepted.
	pendingLoginTTL = 5 * time.Minute
	// pendingLoginAttempts is how many wrong codes one pending login allows before the password is needed again.
	pendingLoginAttempts = 5
	// maxPendingLogins caps the map, so a flood of half-finished logins can't grow it without bound. Each needs a
	// correct password for an account with two-factor login on, so reaching it honestly isn't plausible.
	maxPendingLogins = 10000
)

// pendingLogin is a login whose password was accepted and which now waits for a two-factor code. It is who the
// password proved the user to be, not a session: it can do nothing but be finished with a code.
type pendingLogin struct {
	id       *auth.Identity // as the authenticator returned it; for an LDAP user, with the groups the bind found
	userID   int64
	created  time.Time
	attempts int // wrong codes so far
}

// pendingLogins holds the logins waiting for a code, in memory, keyed by the browser's anonymous cookie ID. A
// restart loses them, and those users enter their password again. One browser has at most one: a new password
// login replaces it.
type pendingLogins struct {
	mu  sync.Mutex
	m   map[string]*pendingLogin
	now func() time.Time
}

func newPendingLogins() *pendingLogins {
	return &pendingLogins{m: map[string]*pendingLogin{}, now: time.Now}
}

// put records a pending login for the browser, replacing any it had.
func (p *pendingLogins) put(anonID []byte, id *auth.Identity, userID int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	p.sweep(now)
	key := string(anonID)
	if _, replacing := p.m[key]; !replacing && len(p.m) >= maxPendingLogins {
		p.dropOldest()
	}
	p.m[key] = &pendingLogin{id: id, userID: userID, created: now}
}

// get returns a copy of the browser's pending login, if it has one that hasn't run out of time.
func (p *pendingLogins) get(anonID []byte) (pendingLogin, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	pl, ok := p.m[string(anonID)]
	if !ok {
		return pendingLogin{}, false
	}
	if p.now().Sub(pl.created) >= pendingLoginTTL {
		delete(p.m, string(anonID))
		return pendingLogin{}, false
	}
	return *pl, true
}

// fail counts a wrong code. It reports whether that was the last attempt, in which case the pending login is gone.
func (p *pendingLogins) fail(anonID []byte) (spent bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	pl, ok := p.m[string(anonID)]
	if !ok {
		return true
	}
	pl.attempts++
	if pl.attempts >= pendingLoginAttempts {
		delete(p.m, string(anonID))
		return true
	}
	return false
}

// remove forgets the browser's pending login: it was finished, or can't be.
func (p *pendingLogins) remove(anonID []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.m, string(anonID))
}

// sweep drops the pending logins that have run out of time. The caller holds the lock.
func (p *pendingLogins) sweep(now time.Time) {
	for k, pl := range p.m {
		if now.Sub(pl.created) >= pendingLoginTTL {
			delete(p.m, k)
		}
	}
}

// dropOldest makes room for one more. The caller holds the lock.
func (p *pendingLogins) dropOldest() {
	var oldest string
	var at time.Time
	for k, pl := range p.m {
		if oldest == "" || pl.created.Before(at) {
			oldest, at = k, pl.created
		}
	}
	delete(p.m, oldest)
}
