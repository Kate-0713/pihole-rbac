// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/auth"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

func TestLoginLogoutFlow(t *testing.T) {
	e := newTestEnv(t)
	aliceID := e.addUser("alice", "alice-password-1", true)
	c := e.client("10.0.0.1:1")

	c.fetchCSRF()
	anonToken := c.csrf
	if c.cookies[auth.AnonCookie] == nil {
		t.Fatal("GET /auth/csrf didn't set the anonymous cookie")
	}

	res := c.login(" Alice ", "alice-password-1")
	if res.Code != http.StatusOK {
		t.Fatalf("login: %d %s", res.Code, res.Body)
	}
	var s gen.CurrentSession
	if err := json.Unmarshal(res.Body.Bytes(), &s); err != nil {
		t.Fatal(err)
	}
	if s.User.Username != "alice" || s.User.Id != aliceID || s.User.Source != gen.Local || len(s.PublicId) != 22 ||
		s.CsrfToken == "" || s.CsrfToken == anonToken || s.ExpiresAt.IsZero() {
		t.Fatalf("session = %+v", s)
	}
	ck := res.cookie(auth.SessionCookie)
	if ck == nil || !ck.HttpOnly || ck.SameSite != http.SameSiteLaxMode || ck.Secure {
		t.Fatalf("session cookie = %+v", ck)
	}

	// GET /auth/session and /auth/csrf now return the session's token.
	if got := c.do(http.MethodGet, "/api/v1/auth/session", nil); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), s.CsrfToken) {
		t.Fatalf("GET /auth/session: %d %s", got.Code, got.Body)
	}
	c.fetchCSRF()
	if c.csrf != s.CsrfToken {
		t.Fatal("GET /auth/csrf with a session didn't return the session's token")
	}

	// The anonymous token is useless now.
	c.csrf = anonToken
	if res := c.do(http.MethodPost, "/api/v1/auth/logout", nil); res.Code != http.StatusForbidden {
		t.Fatalf("logout with the anonymous token: %d", res.Code)
	}

	c.csrf = s.CsrfToken
	held := *c.cookies[auth.SessionCookie]
	res = c.do(http.MethodPost, "/api/v1/auth/logout", nil)
	if res.Code != http.StatusNoContent {
		t.Fatalf("logout: %d %s", res.Code, res.Body)
	}
	if ck := res.cookie(auth.SessionCookie); ck == nil || ck.MaxAge != -1 {
		t.Fatalf("logout didn't clear the cookie: %+v", ck)
	}

	// The old cookie no longer works, even if a client kept it.
	stale := c.request(http.MethodGet, "/api/v1/auth/session", nil)
	stale.AddCookie(&held)
	if got := c.send(stale); got.Code != http.StatusUnauthorized {
		t.Fatalf("session still valid after logout: %d", got.Code)
	}

	rows := e.auditRows()
	if len(rows) != 2 || rows[0].Action != audit.ActionLogin || rows[0].Result != audit.ResultSuccess ||
		rows[0].UserID.Int64 != aliceID || rows[0].Ip != "10.0.0.1" ||
		rows[1].Action != audit.ActionLogout || rows[1].Result != audit.ResultSuccess {
		t.Fatalf("audit rows = %+v", rows)
	}
	if !strings.Contains(rows[0].Detail, s.PublicId) || !strings.Contains(rows[0].Detail, `"method":"local"`) {
		t.Fatalf("login detail = %s", rows[0].Detail)
	}
	if lines := e.auditLines(); len(lines) != 2 || !strings.Contains(lines[0], `user="alice" action=login`) {
		t.Fatalf("AUDIT lines = %q", lines)
	}
}

func TestLoginReplacesExistingSession(t *testing.T) {
	e := newTestEnv(t)
	e.addUser("alice", "alice-password-1", true)
	c := e.client("10.0.0.1:1")
	if res := c.login("alice", "alice-password-1"); res.Code != http.StatusOK {
		t.Fatal(res.Code)
	}
	first := *c.cookies[auth.SessionCookie]

	if res := c.login("alice", "alice-password-1"); res.Code != http.StatusOK {
		t.Fatalf("second login: %d %s", res.Code, res.Body)
	}
	if c.cookies[auth.SessionCookie].Value == first.Value {
		t.Fatal("session ID wasn't replaced")
	}
	r := c.request(http.MethodGet, "/api/v1/auth/session", nil)
	r.Header.Del("Cookie")
	r.AddCookie(&first)
	if res := c.send(r); res.Code != http.StatusUnauthorized {
		t.Fatalf("previous session still valid: %d", res.Code)
	}
}

func TestLoginFailures(t *testing.T) {
	e := newTestEnv(t)
	e.addUser("alice", "alice-password-1", true)
	e.addUser("norole", "norole-password-1", false)

	tests := []struct {
		name, user, pw string
		wantCode       int
		wantError      string
	}{
		{"wrong password", "alice", "wrong", http.StatusUnauthorized, "invalid_credentials"},
		{"unknown user", "nobody", "wrong", http.StatusUnauthorized, "invalid_credentials"},
		{"valid credentials, no role", "norole", "norole-password-1", http.StatusForbidden, "no_access"},
		{"empty username", "  ", "x", http.StatusBadRequest, "validation_failed"},
		{"empty password", "alice", "", http.StatusBadRequest, "validation_failed"},
		{"username too long", strings.Repeat("a", 257), "x", http.StatusBadRequest, "validation_failed"},
	}
	var messages = map[string]string{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := e.client("10.0.0.1:1")
			res := c.login(tt.user, tt.pw)
			if res.Code != tt.wantCode || res.errorCode() != tt.wantError {
				t.Fatalf("got %d %q, want %d %q", res.Code, res.errorCode(), tt.wantCode, tt.wantError)
			}
			if res.cookie(auth.SessionCookie) != nil {
				t.Fatal("failed login set a session cookie")
			}
			var body gen.Error
			_ = json.Unmarshal(res.Body.Bytes(), &body)
			messages[tt.name] = body.Error.Message
		})
	}
	if messages["wrong password"] != messages["unknown user"] {
		t.Fatal("wrong password and unknown user must look the same")
	}

	rows := e.auditRows()
	if len(rows) != 3 {
		t.Fatalf("audit rows = %d, want 3 (validation failures aren't audited)", len(rows))
	}
	for _, r := range rows {
		if r.Action != audit.ActionLogin || r.Result != audit.ResultFailure || r.UserID.Valid {
			t.Fatalf("row = %+v", r)
		}
	}
	if !strings.Contains(rows[2].Detail, auth.ErrNoAccess.Error()) {
		t.Fatalf("no-access detail = %s", rows[2].Detail)
	}
}

// Ported from v1's TestLoginLockedPerUsernameAcrossAddresses.
func TestLoginLockedPerUsernameAcrossAddresses(t *testing.T) {
	e := newTestEnv(t, withLimits)
	e.addUser("alice", "right-password", true)
	e.addUser("bob", "right-password", true)

	for i, ip := range []string{"10.0.0.1:1", "10.0.0.2:1", "10.0.0.3:1"} {
		if res := e.client(ip).login("alice", "wrong"); res.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d: status %d", i+1, res.Code)
		}
	}
	before := e.authn.calls

	// Even the right password is refused, from a fresh address, without the authenticator being asked at all.
	res := e.client("10.0.0.4:1").login("Alice ", "right-password")
	if res.Code != http.StatusTooManyRequests || res.errorCode() != "rate_limited" {
		t.Fatalf("status = %d %q, want 429 rate_limited", res.Code, res.errorCode())
	}
	if res.Header().Get("Retry-After") == "" {
		t.Fatal("missing Retry-After")
	}
	if e.authn.calls != before {
		t.Fatal("blocked attempt still reached the authenticator")
	}

	// Other usernames from that address are unaffected.
	if res := e.client("10.0.0.4:1").login("bob", "right-password"); res.Code != http.StatusOK {
		t.Fatalf("bob: status %d", res.Code)
	}

	// The lockout is recorded once, on the failure that tripped it.
	var locked int
	for _, r := range e.auditRows() {
		if strings.Contains(r.Detail, "locked_out") {
			locked++
		}
	}
	if locked != 1 {
		t.Fatalf("lockout recorded %d times, want 1", locked)
	}
}

// Ported from v1's TestLoginLockedPerAddressAcrossUsernames.
func TestLoginLockedPerAddressAcrossUsernames(t *testing.T) {
	e := newTestEnv(t, withLimits)
	e.addUser("e", "right-password", true)

	for _, u := range []string{"a", "b", "c", "d"} {
		e.client("10.0.0.9:1").login(u, "wrong")
	}
	if res := e.client("10.0.0.9:1").login("e", "right-password"); res.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", res.Code)
	}
	if res := e.client("10.0.0.10:1").login("e", "right-password"); res.Code != http.StatusOK {
		t.Fatalf("other address: status %d", res.Code)
	}
}

// Ported from v1's TestLoginSuccessClearsUsernameCountOnly.
func TestLoginSuccessClearsUsernameCountOnly(t *testing.T) {
	e := newTestEnv(t, withLimits)
	e.addUser("alice", "right-password", true)

	e.client("10.0.0.1:1").login("alice", "wrong")
	e.client("10.0.0.1:1").login("alice", "wrong")
	if res := e.client("10.0.0.1:1").login("alice", "right-password"); res.Code != http.StatusOK {
		t.Fatalf("login: %d", res.Code)
	}
	// Two more failures would have hit the limit of 3 without the reset.
	e.client("10.0.0.2:1").login("alice", "wrong")
	e.client("10.0.0.2:1").login("alice", "wrong")
	if res := e.client("10.0.0.3:1").login("alice", "right-password"); res.Code != http.StatusOK {
		t.Fatalf("count wasn't reset by the success: %d", res.Code)
	}

	// The address's own count was not reset: 2 failures + success + 2 more failures from .1 is 4 in total, which is
	// its limit.
	e.client("10.0.0.1:1").login("x", "wrong")
	e.client("10.0.0.1:1").login("y", "wrong")
	if res := e.client("10.0.0.1:1").login("alice", "right-password"); res.Code != http.StatusTooManyRequests {
		t.Fatalf("a success reset the address's count: %d", res.Code)
	}
}

// Ported from v1's TestLoginNoAccessIsNotCounted.
func TestLoginNoAccessIsNotCounted(t *testing.T) {
	e := newTestEnv(t, withLimits)
	e.addUser("noaccess", "right-password", false)
	for i := 0; i < 10; i++ {
		res := e.client("10.0.0.1:1").login("noaccess", "right-password")
		if res.Code != http.StatusForbidden || res.errorCode() != "no_access" {
			t.Fatalf("attempt %d: %d %q", i+1, res.Code, res.errorCode())
		}
	}
}

// Ported from v1's TestLoginUsesForwardedAddressOnlyFromTrustedProxy.
func TestLoginUsesForwardedAddressOnlyFromTrustedProxy(t *testing.T) {
	e := newTestEnv(t, withLimits, withTrustedProxy("10.0.0.2/32"))
	e.addUser("e", "right-password", true)

	behind := func(xff string) *client {
		c := e.client("10.0.0.2:5000")
		c.xff = xff
		return c
	}
	// Four failures from client A behind the proxy exhaust A's budget...
	for _, u := range []string{"a", "b", "c", "d"} {
		behind("198.51.100.1").login(u, "wrong")
	}
	if res := behind("198.51.100.1").login("e", "right-password"); res.Code != http.StatusTooManyRequests {
		t.Fatalf("client A: %d, want 429", res.Code)
	}
	// ...but client B behind the same proxy is fine,
	if res := behind("198.51.100.2").login("e", "right-password"); res.Code != http.StatusOK {
		t.Fatalf("client B: %d, want 200", res.Code)
	}
	// and someone connecting directly can't dodge by claiming an address.
	direct := func(xff string) *client {
		c := e.client("203.0.113.9:1")
		c.xff = xff
		return c
	}
	for _, u := range []string{"a", "b", "c", "d"} {
		direct("198.51.100.77").login(u, "wrong")
	}
	if res := direct("198.51.100.88").login("e", "right-password"); res.Code != http.StatusTooManyRequests {
		t.Fatalf("spoofed header dodged the limit: %d", res.Code)
	}

	// The audit log records the client address, not the proxy's.
	if rows := e.auditRows(); rows[0].Ip != "198.51.100.1" {
		t.Fatalf("audit ip = %q", rows[0].Ip)
	}
}

func TestDisabledUserCantLogIn(t *testing.T) {
	e := newTestEnv(t)
	e.addUser("dave", "dave-password-1", true)
	if res := e.client("10.0.0.1:1").login("dave", "dave-password-1"); res.Code != http.StatusOK {
		t.Fatal(res.Code)
	}
	disableUser(t, e, "dave")
	if res := e.client("10.0.0.1:1").login("dave", "dave-password-1"); res.Code != http.StatusUnauthorized {
		t.Fatalf("disabled user: %d", res.Code)
	}
}

func disableUser(t *testing.T, e *testEnv, name string) {
	t.Helper()
	ctx := context.Background()
	err := e.st.WithTx(ctx, func(q *db.Queries) error {
		u, err := q.GetUserByUsername(ctx, name)
		if err != nil {
			return err
		}
		return q.SetUserDisabled(ctx, db.SetUserDisabledParams{Disabled: true, ID: u.ID})
	})
	if err != nil {
		t.Fatal(err)
	}
}
