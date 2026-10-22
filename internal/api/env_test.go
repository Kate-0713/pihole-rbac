// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/auth"
	"github.com/Kate-0713/pihole-rbac/internal/ratelimit"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// adminRoleID is the builtin admin role created by the first migration.
const adminRoleID = 1

// countingAuth counts how often the authenticator is asked, so tests can check that a blocked login never reaches it.
type countingAuth struct {
	inner auth.Authenticator
	calls int
}

func (c *countingAuth) Authenticate(ctx context.Context, u, p string) (*auth.Identity, error) {
	c.calls++
	return c.inner.Authenticate(ctx, u, p)
}

// testEnv is a server over a real database, with local users, real sessions and the AUDIT lines captured.
type testEnv struct {
	t     *testing.T
	st    *store.Store
	srv   *Server
	h     http.Handler
	authn *countingAuth
	audit *bytes.Buffer
}

func newTestEnv(t *testing.T, modify ...func(*Options)) *testEnv {
	t.Helper()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(context.Background(), store.Options{DataDir: t.TempDir(), Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	key := secrets.NewValue(bytes.Repeat([]byte{1}, secrets.KeySize))
	ca := &countingAuth{inner: auth.NewLocalAuthenticator(auth.StoreUsers{St: st})}
	var auditBuf bytes.Buffer
	o := Options{
		Store:    st,
		Sessions: auth.NewSessions(st, func() secrets.Value { return key }, auth.SessionOptions{}),
		Auth:     ca,
		Audit:    audit.NewLogger(&auditBuf),
		Logger:   quiet,
	}
	for _, m := range modify {
		m(&o)
	}
	srv := New(o)
	return &testEnv{t: t, st: st, srv: srv, h: srv.Handler(), authn: ca, audit: &auditBuf}
}

// withLimits sets small login limits: 4 failures per address, 3 per username.
func withLimits(o *Options) {
	o.LoginByIP = ratelimit.New(4, 15*60e9)
	o.LoginByUser = ratelimit.New(3, 15*60e9)
}

func withTrustedProxy(p string) func(*Options) {
	return func(o *Options) {
		o.TrustedProxies = []netip.Prefix{netip.MustParsePrefix(p)}
		o.Sessions = auth.NewSessions(o.Store, func() secrets.Value {
			return secrets.NewValue(bytes.Repeat([]byte{1}, secrets.KeySize))
		}, auth.SessionOptions{TrustedProxies: o.TrustedProxies})
	}
}

// addUser creates a local user. With withRole, the user gets the builtin admin role; without, they have no role.
func (e *testEnv) addUser(name, password string, withRole bool) int64 {
	e.t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		e.t.Fatal(err)
	}
	var id int64
	ctx := context.Background()
	err = e.st.WithTx(ctx, func(q *db.Queries) error {
		u, err := q.CreateLocalUser(ctx, db.CreateLocalUserParams{
			Username: name, PasswordHash: sql.NullString{String: string(hash), Valid: true},
		})
		if err != nil {
			return err
		}
		id = u.ID
		if !withRole {
			return nil
		}
		return q.AddUserRole(ctx, db.AddUserRoleParams{UserID: u.ID, RoleID: adminRoleID})
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return id
}

// client is a browser: it keeps cookies and the current CSRF token, and sends a same-origin Origin header.
type client struct {
	e       *testEnv
	remote  string
	xff     string
	cookies map[string]*http.Cookie
	csrf    string
}

func (e *testEnv) client(remote string) *client {
	return &client{e: e, remote: remote, cookies: map[string]*http.Cookie{}}
}

type response struct {
	*httptest.ResponseRecorder
}

func (r response) errorCode() string {
	var body gen.Error
	_ = json.Unmarshal(r.Body.Bytes(), &body)
	return body.Error.Code
}

func (r response) cookie(name string) *http.Cookie {
	for _, c := range r.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// request builds a request from the client, before any per-test changes.
func (c *client) request(method, path string, body any) *http.Request {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			c.e.t.Fatal(err)
		}
		rdr = bytes.NewReader(b)
	}
	r := httptest.NewRequest(method, path, rdr)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	r.RemoteAddr = c.remote
	if c.xff != "" {
		r.Header.Set("X-Forwarded-For", c.xff)
	}
	if !isSafeMethod(method) {
		r.Header.Set("Origin", "http://example.com") // httptest's default Host
		if c.csrf != "" {
			r.Header.Set(auth.CSRFHeader, c.csrf)
		}
	}
	for _, ck := range c.cookies {
		r.AddCookie(ck)
	}
	return r
}

// send serves r and keeps any cookies the response sets.
func (c *client) send(r *http.Request) response {
	w := httptest.NewRecorder()
	c.e.h.ServeHTTP(w, r)
	for _, ck := range w.Result().Cookies() {
		if ck.MaxAge < 0 {
			delete(c.cookies, ck.Name)
		} else {
			c.cookies[ck.Name] = ck
		}
	}
	return response{w}
}

func (c *client) do(method, path string, body any) response {
	return c.send(c.request(method, path, body))
}

// fetchCSRF gets a token the way the SPA does.
func (c *client) fetchCSRF() {
	c.e.t.Helper()
	res := c.do(http.MethodGet, "/api/v1/auth/csrf", nil)
	if res.Code != http.StatusOK {
		c.e.t.Fatalf("GET /auth/csrf: %d %s", res.Code, res.Body)
	}
	var tok gen.CSRFToken
	if err := json.Unmarshal(res.Body.Bytes(), &tok); err != nil {
		c.e.t.Fatal(err)
	}
	c.csrf = tok.CsrfToken
}

// login fetches an anonymous token if needed, posts the credentials and, on success, keeps the session's token.
func (c *client) login(username, password string) response {
	c.e.t.Helper()
	if c.csrf == "" {
		c.fetchCSRF()
	}
	res := c.do(http.MethodPost, "/api/v1/auth/login", gen.LoginRequest{Username: username, Password: password})
	if res.Code == http.StatusOK {
		var s gen.CurrentSession
		if err := json.Unmarshal(res.Body.Bytes(), &s); err != nil {
			c.e.t.Fatal(err)
		}
		c.csrf = s.CsrfToken
	}
	return res
}

// auditLines returns the AUDIT lines written so far.
func (e *testEnv) auditLines() []string {
	return strings.Split(strings.TrimSpace(e.audit.String()), "\n")
}

// auditRows returns the audit_log rows, oldest first.
func (e *testEnv) auditRows() []db.AuditLog {
	e.t.Helper()
	var rows []db.AuditLog
	for id := int64(1); ; id++ {
		row, err := e.st.Read().GetAudit(context.Background(), id)
		if err != nil {
			return rows
		}
		rows = append(rows, row)
	}
}
