// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ratelimit provides a small in-memory failure limiter and the client-IP lookup it is keyed on. It holds no
// state on disk: a restart forgets every count, which is fine for a login throttle.
package ratelimit

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Limiter blocks a key once it has racked up max failures inside a rolling window, and keeps blocking until the
// oldest of those failures ages out.
//
// A nil *Limiter allows everything, so code that has none configured (tests, mostly) needs no special casing.
type Limiter struct {
	max    int
	window time.Duration
	now    func() time.Time // replaced in tests

	mu        sync.Mutex
	fails     map[string][]time.Time
	lastSweep time.Time
}

// New returns a Limiter that allows max failures per key per window.
func New(max int, window time.Duration) *Limiter {
	return &Limiter{
		max:    max,
		window: window,
		now:    time.Now,
		fails:  map[string][]time.Time{},
	}
}

// Allow reports whether key may attempt now. If not, retryAfter is how long until it may. Allow never records
// anything, so blocked attempts don't extend their own block.
func (l *Limiter) Allow(key string) (ok bool, retryAfter time.Duration) {
	if l == nil {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	recent := l.prune(key, now)
	if len(recent) < l.max {
		return true, 0
	}
	return false, recent[0].Add(l.window).Sub(now)
}

// Fail records one failure for key and reports whether it was the one that tripped the limit, so callers can log a
// lockout once rather than on every blocked attempt.
func (l *Limiter) Fail(key string) (tripped bool) {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.sweep(now)
	recent := l.prune(key, now)
	if len(recent) >= l.max {
		return false // already blocked; don't grow the slice or re-report
	}
	l.fails[key] = append(recent, now)
	return len(recent)+1 == l.max
}

// Reset forgets key's failures, e.g. after a successful login.
func (l *Limiter) Reset(key string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	delete(l.fails, key)
	l.mu.Unlock()
}

// prune drops key's failures that have aged out of the window and returns what's left. Callers hold l.mu.
func (l *Limiter) prune(key string, now time.Time) []time.Time {
	times := l.fails[key]
	cutoff := now.Add(-l.window)
	i := 0
	for i < len(times) && !times[i].After(cutoff) {
		i++
	}
	if i == 0 {
		return times
	}
	if i == len(times) {
		delete(l.fails, key)
		return nil
	}
	times = times[i:]
	l.fails[key] = times
	return times
}

// sweep drops every expired key, at most once per window, so keys that are never seen again (typo'd usernames,
// one-off addresses) don't pile up. Callers hold l.mu.
func (l *Limiter) sweep(now time.Time) {
	if now.Sub(l.lastSweep) < l.window {
		return
	}
	l.lastSweep = now
	for key := range l.fails {
		l.prune(key, now)
	}
}

func isTrusted(a netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ClientIP returns the address to attribute r to. X-Forwarded-For is only believed when the connection itself comes
// from a trusted proxy (PIHOLE_RBAC_TRUSTED_PROXIES); otherwise any client could pick its own "address" and dodge
// the limiter. With a trusted proxy in front, the header is read right to left and the first address that isn't
// itself a trusted proxy wins, since anything further left was supplied by the client and can be forged.
func ClientIP(r *http.Request, trusted []netip.Prefix) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remote, err := netip.ParseAddr(host)
	if err != nil {
		return host // not an IP (unix socket, test): use it as is
	}
	remote = remote.Unmap()
	if !isTrusted(remote, trusted) {
		return remote.String()
	}

	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return remote.String() // malformed header: don't guess
		}
		a = a.Unmap()
		if !isTrusted(a, trusted) {
			return a.String()
		}
	}
	return remote.String()
}
