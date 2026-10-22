// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/config"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// sessionEnv is a database, a Sessions with a settable clock and key, and helpers to log users in.
type sessionEnv struct {
	t   *testing.T
	st  *store.Store
	s   *Sessions
	now time.Time
	key secrets.Value
}

func newSessionEnv(t *testing.T, opts SessionOptions) *sessionEnv {
	t.Helper()
	st, err := store.Open(context.Background(), store.Options{
		DataDir: t.TempDir(),
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	e := &sessionEnv{
		t:   t,
		st:  st,
		now: time.Date(2026, 10, 23, 9, 0, 0, 0, time.UTC),
		key: secrets.NewValue(bytes.Repeat([]byte{1}, secrets.KeySize)),
	}
	e.s = NewSessions(st, func() secrets.Value { return e.key }, opts)
	e.s.now = func() time.Time { return e.now }
	return e
}

func (e *sessionEnv) createUser(name string) int64 {
	e.t.Helper()
	var id int64
	err := e.st.WithTx(context.Background(), func(q *db.Queries) error {
		u, err := q.CreateLocalUser(context.Background(), db.CreateLocalUserParams{
			Username:     name,
			PasswordHash: sql.NullString{String: "x", Valid: true},
			CreatedAt:    store.Millis(e.now),
		})
		id = u.ID
		return err
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return id
}

// login creates a session for userID and returns its cookie.
func (e *sessionEnv) login(userID int64, roles ...int64) *http.Cookie {
	e.t.Helper()
	var value string
	var sess *Session
	err := e.st.WithTx(context.Background(), func(q *db.Queries) error {
		var err error
		value, sess, err = e.s.Create(context.Background(), q, NewSession{UserID: userID, RoleIDs: roles, IP: "10.0.0.1", UserAgent: "test"})
		return err
	})
	if err != nil {
		e.t.Fatal(err)
	}
	w := httptest.NewRecorder()
	e.s.SetCookie(w, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil), value, sess.ExpiresAt)
	return w.Result().Cookies()[0]
}

func (e *sessionEnv) get(c *http.Cookie) (*Session, error) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if c != nil {
		r.AddCookie(c)
	}
	return e.s.Get(context.Background(), r)
}

func (e *sessionEnv) valid(c *http.Cookie) bool {
	e.t.Helper()
	_, err := e.get(c)
	if err != nil && !errors.Is(err, ErrNoSession) {
		e.t.Fatal(err)
	}
	return err == nil
}

func TestSessionRoundTrip(t *testing.T) {
	e := newSessionEnv(t, SessionOptions{})
	alice := e.createUser("alice")
	c := e.login(alice, 1)

	if c.Name != SessionCookie || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" {
		t.Fatalf("cookie = %+v", c)
	}
	sess, err := e.get(c)
	if err != nil {
		t.Fatal(err)
	}
	if sess.Username != "alice" || sess.Source != MethodLocal || sess.UserID != alice ||
		len(sess.RoleIDs) != 1 || sess.RoleIDs[0] != 1 || len(sess.PublicID) != 22 ||
		!sess.ExpiresAt.Equal(e.now.Add(DefaultLifetime)) || sess.IP != "10.0.0.1" || sess.UserAgent != "test" {
		t.Fatalf("session = %+v", sess)
	}
}

func TestDatabaseHoldsOnlyTheHash(t *testing.T) {
	e := newSessionEnv(t, SessionOptions{})
	c := e.login(e.createUser("alice"))
	id, ok := e.s.parseCookie(c.Value)
	if !ok {
		t.Fatal("own cookie doesn't parse")
	}
	sum := sha256.Sum256(id)
	row, err := e.st.Read().GetSessionWithUser(context.Background(), sum[:])
	if err != nil {
		t.Fatalf("no row under the SHA-256 of the ID: %v", err)
	}
	if bytes.Equal(row.IDHash, id) || strings.Contains(row.PublicID, b64.EncodeToString(id)) {
		t.Fatal("raw session ID stored")
	}
	if _, err := e.st.Read().GetSessionWithUser(context.Background(), id); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("session found under the raw ID")
	}
}

func TestInvalidCookies(t *testing.T) {
	e := newSessionEnv(t, SessionOptions{})
	good := e.login(e.createUser("alice"))
	idPart, sig, _ := strings.Cut(good.Value, ".")
	other := e.login(e.createUser("bob"))
	_, otherSig, _ := strings.Cut(other.Value, ".")

	tests := []struct {
		name  string
		value string
	}{
		{"empty", ""},
		{"no signature", idPart},
		{"bad signature", idPart + ".AAAA"},
		{"another session's signature", idPart + "." + otherSig},
		{"tampered ID", "A" + idPart[1:] + "." + sig},
		{"short ID", "AAAA." + sig},
		{"not base64", "!!!." + sig},
		{"unknown but well-signed ID", b64.EncodeToString(bytes.Repeat([]byte{9}, sessionIDSize)) + "." + e.s.sign("session", bytes.Repeat([]byte{9}, sessionIDSize))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if e.valid(&http.Cookie{Name: SessionCookie, Value: tt.value}) {
				t.Fatal("accepted")
			}
		})
	}
	if e.valid(nil) {
		t.Fatal("no cookie accepted")
	}
	if !e.valid(good) {
		t.Fatal("good cookie rejected after the others")
	}
}

func TestSessionExpiry(t *testing.T) {
	tests := []struct {
		name    string
		advance []time.Duration // requests made after each step
		valid   bool
	}{
		{"fresh", nil, true},
		{"just inside idle timeout", []time.Duration{59 * time.Minute}, true},
		{"idle timeout reached", []time.Duration{time.Hour}, false},
		{"activity keeps it alive", []time.Duration{50 * time.Minute, 50 * time.Minute, 50 * time.Minute}, true},
		{"absolute lifetime ends it despite activity", repeat(50*time.Minute, 10), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newSessionEnv(t, SessionOptions{})
			c := e.login(e.createUser("alice"))
			ok := true
			for _, d := range tt.advance {
				e.now = e.now.Add(d)
				ok = e.valid(c)
				if !ok {
					break
				}
			}
			if ok != tt.valid {
				t.Fatalf("valid = %v, want %v (now %v)", ok, tt.valid, e.now)
			}
		})
	}
}

func repeat(d time.Duration, n int) []time.Duration {
	out := make([]time.Duration, n)
	for i := range out {
		out[i] = d
	}
	return out
}

func TestTouchIsThrottled(t *testing.T) {
	e := newSessionEnv(t, SessionOptions{})
	c := e.login(e.createUser("alice"))
	start := e.now

	e.now = start.Add(30 * time.Second)
	if s, _ := e.get(c); !s.LastSeenAt.Equal(start) {
		t.Fatalf("touched after 30s: %v", s.LastSeenAt)
	}
	e.now = start.Add(2 * time.Minute)
	if s, _ := e.get(c); !s.LastSeenAt.Equal(e.now) {
		t.Fatalf("not touched after 2m: %v", s.LastSeenAt)
	}
	e.now = start.Add(2*time.Minute + 10*time.Second)
	if s, _ := e.get(c); !s.LastSeenAt.Equal(start.Add(2 * time.Minute)) {
		t.Fatalf("last_seen_at not persisted: %v", s.LastSeenAt)
	}
}

func TestDisabledUserSessionIsRefused(t *testing.T) {
	e := newSessionEnv(t, SessionOptions{})
	alice := e.createUser("alice")
	c := e.login(alice)
	if err := e.st.WithTx(context.Background(), func(q *db.Queries) error {
		return q.SetUserDisabled(context.Background(), db.SetUserDisabledParams{Disabled: true, ID: alice})
	}); err != nil {
		t.Fatal(err)
	}
	if e.valid(c) {
		t.Fatal("session of a disabled user accepted")
	}
}

// Ported from v1's TestDestroyUserOnlyEndsMatchingSessions. Usernames are unique across local and LDAP in v2, so
// the user ID alone identifies whose sessions to end.
func TestDeleteForUserOnlyEndsThatUsersSessions(t *testing.T) {
	e := newSessionEnv(t, SessionOptions{})
	alice, bob := e.createUser("alice"), e.createUser("bob")
	alice1, alice2, bob1 := e.login(alice), e.login(alice), e.login(bob)

	var n int64
	err := e.st.WithTx(context.Background(), func(q *db.Queries) error {
		var err error
		n, err = e.s.DeleteForUser(context.Background(), q, alice)
		return err
	})
	if err != nil || n != 2 {
		t.Fatalf("ended %d sessions (err %v), want 2", n, err)
	}
	if e.valid(alice1) || e.valid(alice2) {
		t.Fatal("alice's sessions should be gone")
	}
	if !e.valid(bob1) {
		t.Fatal("bob's session must survive")
	}
}

func TestLogoutDeletesOnlyThatSession(t *testing.T) {
	e := newSessionEnv(t, SessionOptions{})
	alice := e.createUser("alice")
	c1, c2 := e.login(alice), e.login(alice)
	sess, err := e.get(c1)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.WithTx(context.Background(), func(q *db.Queries) error {
		return e.s.Delete(context.Background(), q, sess)
	}); err != nil {
		t.Fatal(err)
	}
	if e.valid(c1) || !e.valid(c2) {
		t.Fatal("logout should end only its own session")
	}
}

// Ported from v1's TestCreatePurgesExpiredSessions: expired sessions are removed from storage, not just refused.
func TestPrune(t *testing.T) {
	e := newSessionEnv(t, SessionOptions{})
	alice := e.createUser("alice")
	stale := e.login(alice)
	e.now = e.now.Add(45 * time.Minute)
	fresh := e.login(alice)
	e.now = e.now.Add(20 * time.Minute) // stale is now idle for 65 minutes, fresh for 20

	n, err := e.s.Prune(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("pruned %d (err %v), want 1", n, err)
	}
	if e.valid(stale) || !e.valid(fresh) {
		t.Fatal("wrong session pruned")
	}
}

// Ported from v1's TestCloseEndsSessionsAndRefusesNewOnes and TestSetSessionStoreClosesTheOldOne: replacing the
// session key ends every session.
func TestKeyChangeEndsSessions(t *testing.T) {
	e := newSessionEnv(t, SessionOptions{})
	c := e.login(e.createUser("alice"))
	e.key = secrets.NewValue(bytes.Repeat([]byte{2}, secrets.KeySize))
	if e.valid(c) {
		t.Fatal("session survived a session key change")
	}
}

func TestSessionRolesAreStored(t *testing.T) {
	e := newSessionEnv(t, SessionOptions{})
	// The builtin admin role (id 1) exists from the first migration.
	c := e.login(e.createUser("alice"), 1)
	s, err := e.get(c)
	if err != nil || len(s.RoleIDs) != 1 || s.RoleIDs[0] != 1 {
		t.Fatalf("roles = %v, %v", s, err)
	}
	// A role that doesn't exist is refused by the foreign key, failing the login transaction.
	err = e.st.WithTx(context.Background(), func(q *db.Queries) error {
		_, _, err := e.s.Create(context.Background(), q, NewSession{UserID: s.UserID, RoleIDs: []int64{999}})
		return err
	})
	if store.Constraint(err) != store.ForeignKey {
		t.Fatalf("err = %v, want a foreign key error", err)
	}
}

func TestCookieSecure(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")}
	tests := []struct {
		name   string
		mode   config.CookieSecure
		tls    bool
		remote string
		proto  string
		want   bool
	}{
		{"auto, plain HTTP", config.CookieSecureAuto, false, "203.0.113.5:1", "", false},
		{"auto, direct TLS", config.CookieSecureAuto, true, "203.0.113.5:1", "", true},
		{"auto, trusted proxy says https", config.CookieSecureAuto, false, "10.0.0.2:1", "https", true},
		{"auto, trusted proxy list", config.CookieSecureAuto, false, "10.0.0.2:1", "https, http", true},
		{"auto, trusted proxy says http", config.CookieSecureAuto, false, "10.0.0.2:1", "http", false},
		{"auto, untrusted client claims https", config.CookieSecureAuto, false, "203.0.113.5:1", "https", false},
		{"auto, ipv4-mapped trusted proxy", config.CookieSecureAuto, false, "[::ffff:10.0.0.2]:1", "HTTPS", true},
		{"always", config.CookieSecureAlways, false, "203.0.113.5:1", "", true},
		{"never, even over TLS", config.CookieSecureNever, true, "203.0.113.5:1", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSessions(nil, nil, SessionOptions{CookieSecure: tt.mode, TrustedProxies: trusted})
			r := httptest.NewRequest(http.MethodPost, "/", nil)
			r.RemoteAddr = tt.remote
			if tt.tls {
				r.TLS = &tls.ConnectionState{}
			}
			if tt.proto != "" {
				r.Header.Set("X-Forwarded-Proto", tt.proto)
			}
			if got := s.Secure(r); got != tt.want {
				t.Fatalf("Secure = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClearCookie(t *testing.T) {
	s := NewSessions(nil, nil, SessionOptions{})
	w := httptest.NewRecorder()
	s.ClearCookie(w, httptest.NewRequest(http.MethodPost, "/", nil))
	c := w.Result().Cookies()[0]
	if c.Name != SessionCookie || c.MaxAge != -1 || c.Value != "" {
		t.Fatalf("cookie = %+v", c)
	}
}

func TestStoreUsers(t *testing.T) {
	e := newSessionEnv(t, SessionOptions{})
	ctx := context.Background()
	hash := mustHash(t, "alice-password-1")
	err := e.st.WithTx(ctx, func(q *db.Queries) error {
		_, err := q.CreateLocalUser(ctx, db.CreateLocalUserParams{
			Username: "alice", PasswordHash: sql.NullString{String: string(hash), Valid: true}, CreatedAt: 0,
		})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	a := NewLocalAuthenticator(StoreUsers{e.st})
	if id, err := a.Authenticate(ctx, "Alice", "alice-password-1"); err != nil || id.Username != "alice" {
		t.Fatalf("got %+v, %v", id, err)
	}
	if _, err := (StoreUsers{e.st}).LocalUserByName(ctx, "nobody"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("err = %v", err)
	}
}
