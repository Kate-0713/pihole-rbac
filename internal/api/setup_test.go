// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/auth"
	"github.com/Kate-0713/pihole-rbac/internal/setup"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

func (e *testEnv) setupToken() string {
	e.t.Helper()
	tok, _, err := setup.NewToken(context.Background(), e.st, time.Now())
	if err != nil {
		e.t.Fatal(err)
	}
	return tok
}

func (c *client) completeSetup(token, username, password string) response {
	c.e.t.Helper()
	if c.csrf == "" {
		c.fetchCSRF()
	}
	res := c.do(http.MethodPost, "/api/v1/setup", gen.SetupRequest{Token: token, Username: username, Password: password})
	if res.Code == http.StatusOK {
		var s gen.CurrentSession
		if err := json.Unmarshal(res.Body.Bytes(), &s); err != nil {
			c.e.t.Fatal(err)
		}
		c.csrf = s.CsrfToken
	}
	return res
}

func (c *client) setupRequired() bool {
	c.e.t.Helper()
	res := c.do(http.MethodGet, "/api/v1/setup/status", nil)
	if res.Code != http.StatusOK {
		c.e.t.Fatalf("GET /setup/status: %d", res.Code)
	}
	var s gen.SetupStatus
	_ = json.Unmarshal(res.Body.Bytes(), &s)
	return s.SetupRequired
}

func TestEverythingElseWaitsForSetup(t *testing.T) {
	e := newSetupEnv(t)
	c := e.client("10.0.0.1:1")
	if !c.setupRequired() {
		t.Fatal("fresh install doesn't report setup as required")
	}
	c.fetchCSRF() // works before setup, because setup itself is a POST

	for _, tt := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/auth/session"},
		{http.MethodPost, "/api/v1/auth/login"},
		{http.MethodPost, "/api/v1/auth/logout"},
	} {
		var body any
		if tt.method == http.MethodPost {
			body = map[string]string{"username": "x", "password": "y"}
		}
		if res := c.do(tt.method, tt.path, body); res.Code != http.StatusServiceUnavailable || res.errorCode() != "setup_required" {
			t.Errorf("%s %s: %d %q, want 503 setup_required", tt.method, tt.path, res.Code, res.errorCode())
		}
	}
	for _, path := range []string{"/healthz", "/api/v1/about"} {
		if res := c.do(http.MethodGet, path, nil); res.Code != http.StatusOK {
			t.Errorf("GET %s before setup: %d", path, res.Code)
		}
	}
}

func TestSetupFlow(t *testing.T) {
	e := newSetupEnv(t)
	token := e.setupToken()
	c := e.client("10.0.0.1:1")

	res := c.completeSetup(token, " Kate ", "first-admin-password")
	if res.Code != http.StatusOK {
		t.Fatalf("setup: %d %s", res.Code, res.Body)
	}
	var s gen.CurrentSession
	_ = json.Unmarshal(res.Body.Bytes(), &s)
	if s.User.Username != "kate" || s.User.Source != gen.Local || res.cookie(auth.SessionCookie) == nil {
		t.Fatalf("session = %+v", s)
	}
	if !slices.Contains(s.Permissions.Global, "users.manage") || len(s.Permissions.Targets) != 0 {
		t.Fatalf("the new admin's permissions = %+v (no instances exist yet)", s.Permissions)
	}

	// Logged in straight away, as an admin.
	if got := c.do(http.MethodGet, "/api/v1/auth/session", nil); got.Code != http.StatusOK {
		t.Fatalf("GET /auth/session after setup: %d", got.Code)
	}
	if roles := e.sessionRoles(c); len(roles) != 1 || roles[0] != adminRoleID {
		t.Fatalf("session roles = %v", roles)
	}
	if c.setupRequired() {
		t.Fatal("setup still reported as required")
	}

	// Setup is closed: the same request again is refused, and logging in works.
	if res := e.client("10.0.0.2:1").completeSetup(token, "other", "other-admin-password"); res.Code != http.StatusConflict || res.errorCode() != "setup_complete" {
		t.Fatalf("second setup: %d %q", res.Code, res.errorCode())
	}
	if res := e.client("10.0.0.3:1").login("kate", "first-admin-password"); res.Code != http.StatusOK {
		t.Fatalf("login after setup: %d", res.Code)
	}

	rows := e.auditRows()
	if len(rows) == 0 || rows[0].Action != audit.ActionSetup || rows[0].Result != audit.ResultSuccess || rows[0].Username != "kate" {
		t.Fatalf("audit rows = %+v", rows)
	}
	if strings.Contains(e.audit.String(), token) {
		t.Fatal("the setup token reached the audit log")
	}
}

func TestSetupFailures(t *testing.T) {
	tests := []struct {
		name      string
		token     func(real string) string
		user, pw  string
		wantCode  int
		wantError string
		wantMsg   string
	}{
		{"wrong token", func(string) string { return "nope" }, "kate", "first-admin-password", http.StatusUnauthorized, "invalid_setup_token", "setup --print-token"},
		{"bad username", func(r string) string { return r }, "kate/o", "first-admin-password", http.StatusBadRequest, "validation_failed", "username must be"},
		{"short password", func(r string) string { return r }, "kate", "short", http.StatusBadRequest, "validation_failed", "at least 12"},
		{"long password", func(r string) string { return r }, "kate", strings.Repeat("x", 73), http.StatusBadRequest, "validation_failed", "at most 72"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newSetupEnv(t)
			c := e.client("10.0.0.1:1")
			res := c.completeSetup(tt.token(e.setupToken()), tt.user, tt.pw)
			var body gen.Error
			_ = json.Unmarshal(res.Body.Bytes(), &body)
			if res.Code != tt.wantCode || body.Error.Code != tt.wantError || !strings.Contains(body.Error.Message, tt.wantMsg) {
				t.Fatalf("got %d %+v", res.Code, body.Error)
			}
			if !c.setupRequired() {
				t.Fatal("a failed setup closed it")
			}
		})
	}
}

func TestSetupNeedsCSRF(t *testing.T) {
	e := newSetupEnv(t)
	c := e.client("10.0.0.1:1")
	res := c.do(http.MethodPost, "/api/v1/setup", gen.SetupRequest{Token: e.setupToken(), Username: "kate", Password: "first-admin-password"})
	if res.Code != http.StatusForbidden || res.errorCode() != "csrf_failed" {
		t.Fatalf("setup without a CSRF token: %d %q", res.Code, res.errorCode())
	}
}

func TestWrongSetupTokensAreRateLimited(t *testing.T) {
	e := newSetupEnv(t, withLimits) // 4 failures per address
	token := e.setupToken()
	for i := 0; i < 4; i++ {
		if res := e.client("10.0.0.1:1").completeSetup("wrong", "kate", "first-admin-password"); res.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i+1, res.Code)
		}
	}
	if res := e.client("10.0.0.1:1").completeSetup(token, "kate", "first-admin-password"); res.Code != http.StatusTooManyRequests {
		t.Fatalf("after 4 wrong tokens: %d, want 429", res.Code)
	}
	if res := e.client("10.0.0.2:1").completeSetup(token, "kate", "first-admin-password"); res.Code != http.StatusOK {
		t.Fatalf("other address: %d", res.Code)
	}
	var failures int
	for _, r := range e.auditRows() {
		if r.Action == audit.ActionSetup && r.Result == audit.ResultFailure {
			failures++
		}
	}
	if failures != 4 {
		t.Fatalf("audited %d wrong tokens, want 4", failures)
	}
}

// reset-admin in another process can close setup; the server must notice rather than keep answering 503.
func TestSetupClosedElsewhereIsNoticed(t *testing.T) {
	e := newSetupEnv(t)
	c := e.client("10.0.0.1:1")
	if res := c.do(http.MethodGet, "/api/v1/auth/session", nil); res.Code != http.StatusServiceUnavailable {
		t.Fatalf("before: %d", res.Code)
	}
	ctx := context.Background()
	if err := e.st.WithTx(ctx, func(q *db.Queries) error {
		_, err := setup.ResetAdmin(ctx, q, "rescue", "rescue-password-1", time.Now())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if res := c.do(http.MethodGet, "/api/v1/auth/session", nil); res.Code != http.StatusUnauthorized {
		t.Fatalf("after reset-admin: %d, want 401 (setup closed, not logged in)", res.Code)
	}
	if res := c.login("rescue", "rescue-password-1"); res.Code != http.StatusOK {
		t.Fatalf("login as the rescue admin: %d", res.Code)
	}
}
