// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/config"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

const (
	// SessionCookie holds the session ID and its HMAC.
	SessionCookie = "pihole_rbac_session"

	DefaultLifetime    = 8 * time.Hour
	DefaultIdleTimeout = time.Hour

	// DefaultRecheckInterval is how often an LDAP user's group membership is rechecked during a session.
	DefaultRecheckInterval = 10 * time.Minute
	// DefaultRecheckGrace is how long past the recheck interval an LDAP session keeps its roles while the directory
	// can't be reached. After that the session ends.
	DefaultRecheckGrace = 30 * time.Minute

	sessionIDSize = 32
	publicIDSize  = 16
	// touchInterval limits how often last_seen_at is written: once a minute per session is plenty for an idle
	// timeout measured in tens of minutes, and saves a write on every request.
	touchInterval = time.Minute
)

// ErrNoSession means the request has no valid session: no cookie, a forged or stale cookie, or a session that has
// expired, gone idle, been revoked or belongs to a disabled user.
var ErrNoSession = errors.New("no valid session")

var b64 = base64.RawURLEncoding

// SessionOptions configures Sessions. Zero durations take the defaults.
type SessionOptions struct {
	Lifetime    time.Duration // absolute, from login
	IdleTimeout time.Duration // since the last request
	// RecheckInterval and RecheckGrace bound how long an LDAP session can go without a successful role recheck: it
	// ends once roles_checked_at is older than their sum. See Rechecker.
	RecheckInterval time.Duration
	RecheckGrace    time.Duration
	CookieSecure    config.CookieSecure
	TrustedProxies  []netip.Prefix
}

// Sessions stores sessions in SQLite. The cookie holds the session ID and an HMAC of it under the session key; the
// database holds only a SHA-256 of the ID, so a copy of the database can't be used to hijack a session.
type Sessions struct {
	st   *store.Store
	key  func() secrets.Value
	opts SessionOptions
	now  func() time.Time

	// The lifetimes are runtime settings, so they can change while the server runs (see SetLifetimes).
	lifetime atomic.Int64 // nanoseconds
	idle     atomic.Int64
}

// NewSessions returns a session store. key is called on every use, so a reloaded session key takes effect at once
// (and, by design, ends every session and invalidates every CSRF token).
func NewSessions(st *store.Store, key func() secrets.Value, opts SessionOptions) *Sessions {
	if opts.Lifetime <= 0 {
		opts.Lifetime = DefaultLifetime
	}
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = DefaultIdleTimeout
	}
	if opts.RecheckInterval <= 0 {
		opts.RecheckInterval = DefaultRecheckInterval
	}
	if opts.RecheckGrace <= 0 {
		opts.RecheckGrace = DefaultRecheckGrace
	}
	s := &Sessions{st: st, key: key, opts: opts, now: time.Now}
	s.lifetime.Store(int64(opts.Lifetime))
	s.idle.Store(int64(opts.IdleTimeout))
	return s
}

// SetLifetimes changes the absolute lifetime and the idle timeout. A new lifetime applies to sessions created from now
// on, since each session's end is fixed when it starts; a new idle timeout applies to every session at once. Zero
// keeps a value as it is.
func (s *Sessions) SetLifetimes(lifetime, idle time.Duration) {
	if lifetime > 0 {
		s.lifetime.Store(int64(lifetime))
	}
	if idle > 0 {
		s.idle.Store(int64(idle))
	}
}

// Lifetimes returns the current absolute lifetime and idle timeout.
func (s *Sessions) Lifetimes() (lifetime, idle time.Duration) {
	return time.Duration(s.lifetime.Load()), time.Duration(s.idle.Load())
}

// Session is a logged-in session.
type Session struct {
	PublicID       string // safe to show and log; can't be used to authenticate
	UserID         int64
	Username       string
	Source         Method
	RoleIDs        []int64
	CreatedAt      time.Time
	ExpiresAt      time.Time
	LastSeenAt     time.Time
	RolesCheckedAt time.Time
	IP             string
	UserAgent      string

	id     []byte // the secret session ID; binds CSRF tokens
	idHash []byte
}

// NewSession describes a session to create at login.
type NewSession struct {
	UserID    int64
	RoleIDs   []int64
	IP        string
	UserAgent string
}

// Create inserts a session and its roles through q, normally the login transaction, and returns the cookie value.
// Call SetCookie with it once the transaction has committed.
func (s *Sessions) Create(ctx context.Context, q *db.Queries, n NewSession) (cookie string, sess *Session, err error) {
	id := make([]byte, sessionIDSize)
	pub := make([]byte, publicIDSize)
	if _, err := rand.Read(id); err != nil {
		return "", nil, err
	}
	if _, err := rand.Read(pub); err != nil {
		return "", nil, err
	}
	hash := sha256.Sum256(id)
	// Stored as Unix milliseconds, so round here too: the login response then shows the same times as a later
	// GET /auth/session.
	now := s.now().Truncate(time.Millisecond)
	sess = &Session{
		PublicID:       b64.EncodeToString(pub),
		UserID:         n.UserID,
		RoleIDs:        n.RoleIDs,
		CreatedAt:      now,
		ExpiresAt:      now.Add(time.Duration(s.lifetime.Load())),
		LastSeenAt:     now,
		RolesCheckedAt: now,
		IP:             n.IP,
		UserAgent:      truncate(n.UserAgent, 512),
		id:             id,
		idHash:         hash[:],
	}
	if err := q.CreateSession(ctx, db.CreateSessionParams{
		IDHash:         sess.idHash,
		PublicID:       sess.PublicID,
		UserID:         sess.UserID,
		CreatedAt:      store.Millis(sess.CreatedAt),
		ExpiresAt:      store.Millis(sess.ExpiresAt),
		LastSeenAt:     store.Millis(sess.LastSeenAt),
		RolesCheckedAt: store.Millis(sess.RolesCheckedAt),
		Ip:             sess.IP,
		UserAgent:      sess.UserAgent,
	}); err != nil {
		return "", nil, fmt.Errorf("create session: %w", err)
	}
	for _, r := range n.RoleIDs {
		if err := q.AddSessionRole(ctx, db.AddSessionRoleParams{SessionIDHash: sess.idHash, RoleID: r}); err != nil {
			return "", nil, fmt.Errorf("add session role: %w", err)
		}
	}
	return b64.EncodeToString(id) + "." + s.sign("session", id), sess, nil
}

// sign returns a base64 HMAC of id under the session key. purpose separates the cookie signature from CSRF tokens.
func (s *Sessions) sign(purpose string, id []byte) string {
	m := hmac.New(sha256.New, s.key().RevealBytes())
	m.Write([]byte(purpose + "|"))
	m.Write(id)
	return b64.EncodeToString(m.Sum(nil))
}

// parseCookie returns the session ID in a cookie value if its signature is valid under the current key.
func (s *Sessions) parseCookie(v string) ([]byte, bool) {
	idPart, sig, ok := strings.Cut(v, ".")
	if !ok {
		return nil, false
	}
	id, err := b64.DecodeString(idPart)
	if err != nil || len(id) != sessionIDSize {
		return nil, false
	}
	if !hmac.Equal([]byte(sig), []byte(s.sign("session", id))) {
		return nil, false
	}
	return id, true
}

// Get returns the request's session, or ErrNoSession. Any other error is a database failure. A valid session's
// last_seen_at is updated at most once a minute.
func (s *Sessions) Get(ctx context.Context, r *http.Request) (*Session, error) {
	c, err := r.Cookie(SessionCookie)
	if err != nil {
		return nil, ErrNoSession
	}
	id, ok := s.parseCookie(c.Value)
	if !ok {
		return nil, ErrNoSession
	}
	hash := sha256.Sum256(id)
	q := s.st.Read()
	row, err := q.GetSessionWithUser(ctx, hash[:])
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoSession
	}
	if err != nil {
		return nil, fmt.Errorf("load session: %w", err)
	}

	now := s.now()
	lastSeen := store.FromMillis(row.LastSeenAt)
	if row.Disabled || !now.Before(store.FromMillis(row.ExpiresAt)) || now.Sub(lastSeen) >= time.Duration(s.idle.Load()) {
		// Best effort: Prune removes it later if this fails.
		_ = s.st.WithTx(ctx, func(q *db.Queries) error { return q.DeleteSession(ctx, hash[:]) })
		return nil, ErrNoSession
	}

	// An LDAP session whose roles haven't been confirmed for longer than the interval plus the grace period ends,
	// even if the directory is the reason they couldn't be: fail closed rather than keep roles nobody has checked.
	if Method(row.Source) == MethodLDAP &&
		now.Sub(store.FromMillis(row.RolesCheckedAt)) > s.opts.RecheckInterval+s.opts.RecheckGrace {
		_ = s.st.WithTx(ctx, func(q *db.Queries) error { return q.DeleteSession(ctx, hash[:]) })
		return nil, ErrNoSession
	}

	roles, err := q.ListSessionRoleIDs(ctx, hash[:])
	if err != nil {
		return nil, fmt.Errorf("load session roles: %w", err)
	}
	sess := &Session{
		PublicID:       row.PublicID,
		UserID:         row.UserID,
		Username:       row.Username,
		Source:         Method(row.Source),
		RoleIDs:        roles,
		CreatedAt:      store.FromMillis(row.CreatedAt),
		ExpiresAt:      store.FromMillis(row.ExpiresAt),
		LastSeenAt:     lastSeen,
		RolesCheckedAt: store.FromMillis(row.RolesCheckedAt),
		IP:             row.Ip,
		UserAgent:      row.UserAgent,
		id:             id,
		idHash:         hash[:],
	}
	if now.Sub(lastSeen) >= touchInterval {
		err := s.st.WithTx(ctx, func(q *db.Queries) error {
			return q.TouchSession(ctx, db.TouchSessionParams{LastSeenAt: store.Millis(now), IDHash: hash[:]})
		})
		if err == nil {
			sess.LastSeenAt = now
		}
		// A failed touch only shortens the idle window; the request can still go ahead.
	}
	return sess, nil
}

// Delete ends sess through q, normally the logout transaction.
func (s *Sessions) Delete(ctx context.Context, q *db.Queries, sess *Session) error {
	return q.DeleteSession(ctx, sess.idHash)
}

// DeleteForUser ends every session of a user through q, for when they are disabled or deleted, or their password or
// roles change. It returns how many sessions it ended.
func (s *Sessions) DeleteForUser(ctx context.Context, q *db.Queries, userID int64) (int64, error) {
	return q.DeleteUserSessions(ctx, userID)
}

// Prune deletes sessions that have expired or gone idle and returns how many. Get already refuses them; this only
// keeps the table small.
func (s *Sessions) Prune(ctx context.Context) (int64, error) {
	now := s.now()
	var n int64
	err := s.st.WithTx(ctx, func(q *db.Queries) error {
		var err error
		n, err = q.DeleteExpiredSessions(ctx, db.DeleteExpiredSessionsParams{
			Now:        store.Millis(now),
			IdleCutoff: store.Millis(now.Add(-time.Duration(s.idle.Load()))),
		})
		return err
	})
	return n, err
}

// SetCookie sets the session cookie, expiring with the session.
func (s *Sessions) SetCookie(w http.ResponseWriter, r *http.Request, value string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    value,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   s.Secure(r),
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearCookie removes the session cookie from the browser.
func (s *Sessions) ClearCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.Secure(r),
		SameSite: http.SameSiteLaxMode,
	})
}

// Secure reports whether cookies on this response get the Secure flag. In auto mode that's when the request
// arrived over TLS, or a trusted proxy says the client connected over HTTPS.
func (s *Sessions) Secure(r *http.Request) bool {
	switch s.opts.CookieSecure {
	case config.CookieSecureAlways:
		return true
	case config.CookieSecureNever:
		return false
	}
	return IsHTTPS(r, s.opts.TrustedProxies)
}

// IsHTTPS reports whether the client connected over HTTPS: directly over TLS, or through a trusted proxy that sent
// X-Forwarded-Proto: https. The header is ignored from anyone else.
func IsHTTPS(r *http.Request, trusted []netip.Prefix) bool {
	if r.TLS != nil {
		return true
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, p := range trusted {
		if p.Contains(a) {
			// With several proxies the header may be a list; the first value is the client-facing one.
			proto, _, _ := strings.Cut(r.Header.Get("X-Forwarded-Proto"), ",")
			return strings.EqualFold(strings.TrimSpace(proto), "https")
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
