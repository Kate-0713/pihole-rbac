// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/auth"
	"github.com/Kate-0713/pihole-rbac/internal/spa"
	"github.com/Kate-0713/pihole-rbac/web"
)

func TestSecurityHeaders(t *testing.T) {
	e := newTestEnv(t)
	c := e.client("10.0.0.1:1")
	for _, path := range []string{"/healthz", "/api/v1/about", "/api/v1/auth/session", "/api/v1/nope", "/not-api"} {
		t.Run(path, func(t *testing.T) {
			res := c.do(http.MethodGet, path, nil)
			h := res.Header()
			if h.Get("Content-Security-Policy") != ContentSecurityPolicy ||
				h.Get("X-Content-Type-Options") != "nosniff" ||
				h.Get("Referrer-Policy") != "same-origin" {
				t.Fatalf("headers = %v", h)
			}
			if h.Get("Strict-Transport-Security") != "" {
				t.Fatal("HSTS sent over plain HTTP")
			}
		})
	}
	if strings.Contains(ContentSecurityPolicy, "script-src 'self' 'unsafe-inline'") {
		t.Fatal("'unsafe-inline' must never be in script-src")
	}

	r := c.request(http.MethodGet, "/api/v1/about", nil)
	r.TLS = &tls.ConnectionState{}
	if c.send(r).Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("no HSTS over HTTPS")
	}
}

func TestAPIResponsesAreNotCached(t *testing.T) {
	c := newTestEnv(t).client("10.0.0.1:1")
	for _, path := range []string{"/healthz", "/api/v1/about", "/api/v1/auth/session", "/api/v1/nope"} {
		if got := c.do(http.MethodGet, path, nil).Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s: Cache-Control = %q", path, got)
		}
	}
}

func TestUnknownAPIPaths(t *testing.T) {
	c := newTestEnv(t).client("10.0.0.1:1")
	tests := []struct {
		method, path string
		wantCode     int
		wantError    string
		wantAllow    string
	}{
		{http.MethodGet, "/api/v1/nope", http.StatusNotFound, "not_found", ""},
		{http.MethodGet, "/api/v2/anything", http.StatusNotFound, "not_found", ""},
		{http.MethodGet, "/api/v1/auth/login", http.StatusMethodNotAllowed, "method_not_allowed", "POST"},
		{http.MethodDelete, "/api/v1/auth/session", http.StatusMethodNotAllowed, "method_not_allowed", "GET"},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			res := c.do(tt.method, tt.path, nil)
			if res.Code != tt.wantCode || res.errorCode() != tt.wantError || res.Header().Get("Allow") != tt.wantAllow {
				t.Fatalf("got %d %q (Allow %q), want %d %q (Allow %q)", res.Code, res.errorCode(),
					res.Header().Get("Allow"), tt.wantCode, tt.wantError, tt.wantAllow)
			}
		})
	}
}

func TestSessionRequiredUnlessPublic(t *testing.T) {
	e := newTestEnv(t)
	c := e.client("10.0.0.1:1")
	c.fetchCSRF() // a valid anonymous token, so only the missing session can fail

	for _, tt := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/auth/session"},
		{http.MethodPost, "/api/v1/auth/logout"},
	} {
		if res := c.do(tt.method, tt.path, nil); res.Code != http.StatusUnauthorized || res.errorCode() != "unauthenticated" {
			t.Errorf("%s %s: %d %q, want 401 unauthenticated", tt.method, tt.path, res.Code, res.errorCode())
		}
	}
	for path := range map[string]bool{"/healthz": true, "/api/v1/about": true, "/api/v1/auth/csrf": true} {
		if res := c.do(http.MethodGet, path, nil); res.Code != http.StatusOK {
			t.Errorf("public GET %s: %d", path, res.Code)
		}
	}
}

func TestStateChangingRequestsNeedJSON(t *testing.T) {
	e := newTestEnv(t)
	c := e.client("10.0.0.1:1")
	c.fetchCSRF()

	for _, ct := range []string{"application/x-www-form-urlencoded", "text/plain", "multipart/form-data; boundary=x", ""} {
		t.Run(ct, func(t *testing.T) {
			r := c.request(http.MethodPost, "/api/v1/auth/login", nil)
			r.Body = nopCloser{strings.NewReader("{}")}
			r.ContentLength = 2
			if ct != "" {
				r.Header.Set("Content-Type", ct)
			}
			if res := c.send(r); res.Code != http.StatusUnsupportedMediaType || res.errorCode() != "unsupported_media_type" {
				t.Fatalf("got %d %q", res.Code, res.errorCode())
			}
		})
	}
	r := c.request(http.MethodPost, "/api/v1/auth/login", nil)
	r.Body = nopCloser{strings.NewReader(`{"username":"a","password":"b"}`)}
	r.ContentLength = 31
	r.Header.Set("Content-Type", "application/json; charset=utf-8")
	if res := c.send(r); res.Code == http.StatusUnsupportedMediaType {
		t.Fatal("application/json with a charset refused")
	}
}

type nopCloser struct{ *strings.Reader }

func (nopCloser) Close() error { return nil }

func TestCSRFAndOriginChecks(t *testing.T) {
	e := newTestEnv(t, withTrustedProxy("10.9.9.9/32"))
	e.addUser("alice", "alice-password-1", true)
	login := map[string]string{"username": "alice", "password": "alice-password-1"}

	tests := []struct {
		name   string
		remote string
		modify func(r *http.Request)
		want   int
	}{
		{"same origin, valid token", "10.0.0.1:1", nil, http.StatusOK},
		{"missing token", "10.0.0.1:1", func(r *http.Request) { r.Header.Del(auth.CSRFHeader) }, http.StatusForbidden},
		{"wrong token", "10.0.0.1:1", func(r *http.Request) { r.Header.Set(auth.CSRFHeader, "bogus") }, http.StatusForbidden},
		{"cross-site origin", "10.0.0.1:1", func(r *http.Request) { r.Header.Set("Origin", "http://evil.example") }, http.StatusForbidden},
		{"null origin", "10.0.0.1:1", func(r *http.Request) { r.Header.Set("Origin", "null") }, http.StatusForbidden},
		{"https origin over plain http", "10.0.0.1:1", func(r *http.Request) { r.Header.Set("Origin", "https://example.com") }, http.StatusForbidden},
		{"no origin, same-origin referer", "10.0.0.1:1", func(r *http.Request) {
			r.Header.Del("Origin")
			r.Header.Set("Referer", "http://example.com/login")
		}, http.StatusOK},
		{"no origin, cross-site referer", "10.0.0.1:1", func(r *http.Request) {
			r.Header.Del("Origin")
			r.Header.Set("Referer", "http://evil.example/")
		}, http.StatusForbidden},
		{"neither origin nor referer", "10.0.0.1:1", func(r *http.Request) { r.Header.Del("Origin") }, http.StatusForbidden},
		{"https origin behind trusted proxy", "10.9.9.9:1", func(r *http.Request) {
			r.Header.Set("X-Forwarded-Proto", "https")
			r.Header.Set("Origin", "https://example.com")
		}, http.StatusOK},
		{"untrusted client claims https", "10.0.0.1:1", func(r *http.Request) {
			r.Header.Set("X-Forwarded-Proto", "https")
			r.Header.Set("Origin", "https://example.com")
		}, http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := e.client(tt.remote)
			c.fetchCSRF()
			r := c.request(http.MethodPost, "/api/v1/auth/login", login)
			if tt.modify != nil {
				tt.modify(r)
			}
			res := c.send(r)
			if res.Code != tt.want {
				t.Fatalf("status = %d (%s), want %d", res.Code, res.Body, tt.want)
			}
			if tt.want == http.StatusForbidden && res.errorCode() != "csrf_failed" {
				t.Fatalf("code = %q, want csrf_failed", res.errorCode())
			}
		})
	}
}

func TestRequestBodyErrors(t *testing.T) {
	e := newTestEnv(t)
	c := e.client("10.0.0.1:1")
	c.fetchCSRF()

	r := c.request(http.MethodPost, "/api/v1/auth/login", nil)
	r.Header.Set("Content-Type", "application/json")
	r.Body = nopCloser{strings.NewReader(`{"username":`)}
	r.ContentLength = 12
	if res := c.send(r); res.Code != http.StatusBadRequest || res.errorCode() != "validation_failed" {
		t.Fatalf("malformed JSON: %d %q", res.Code, res.errorCode())
	}

	big := `{"username":"` + string(bytes.Repeat([]byte("x"), MaxBodyBytes)) + `","password":"x"}`
	r = c.request(http.MethodPost, "/api/v1/auth/login", nil)
	r.Header.Set("Content-Type", "application/json")
	r.Body = nopCloser{strings.NewReader(big)}
	r.ContentLength = int64(len(big))
	if res := c.send(r); res.Code != http.StatusRequestEntityTooLarge || res.errorCode() != "validation_failed" {
		t.Fatalf("oversized body: %d %q", res.Code, res.errorCode())
	}
}

func TestRetryAfterSeconds(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want int
	}{{0, 1}, {time.Millisecond, 1}, {time.Second, 1}, {1500 * time.Millisecond, 2}, {8 * time.Minute, 480}}
	for _, tt := range tests {
		if got := retryAfterSeconds(tt.d); got != tt.want {
			t.Errorf("retryAfterSeconds(%v) = %d, want %d", tt.d, got, tt.want)
		}
	}
}

func withFrontend(t *testing.T, files fstest.MapFS) func(*Options) {
	t.Helper()
	h, err := spa.New(files)
	if err != nil {
		t.Fatal(err)
	}
	return func(o *Options) { o.Frontend = h }
}

// inlineScriptHashes hashes the text of every <script> without attributes, in the order they appear, independently of
// the spa package, so the tests check the header against the page rather than the code against itself. The built
// page has two: app.html's theme script in the head, and SvelteKit's bootstrap in the body.
func inlineScriptHashes(t *testing.T, page string) string {
	t.Helper()
	var hashes []string
	rest := page
	for {
		_, after, ok := strings.Cut(rest, "<script>")
		if !ok {
			break
		}
		text, tail, ok := strings.Cut(after, "</script>")
		if !ok {
			t.Fatal("unterminated <script>")
		}
		sum := sha256.Sum256([]byte(strings.ReplaceAll(text, "\r\n", "\n")))
		hashes = append(hashes, "'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'")
		rest = tail
	}
	if len(hashes) == 0 {
		t.Fatal("page has no inline <script>")
	}
	return strings.Join(hashes, " ")
}

func scriptSrc(t *testing.T, csp string) string {
	t.Helper()
	for _, d := range strings.Split(csp, ";") {
		if d = strings.TrimSpace(d); strings.HasPrefix(d, "script-src ") {
			return d
		}
	}
	t.Fatalf("no script-src in %q", csp)
	return ""
}

func TestFrontendServed(t *testing.T) {
	page := `<!doctype html><html><body><script>boot()</script></body></html>`
	e := newTestEnv(t, withFrontend(t, fstest.MapFS{
		"index.html":            {Data: []byte(page)},
		"_app/immutable/app.js": {Data: []byte("x")},
	}))
	c := e.client("10.0.0.1:1")
	want := "script-src 'self' " + inlineScriptHashes(t, page)

	for _, path := range []string{"/", "/login", "/domains?target=i-1", "/_app/immutable/app.js", "/api/v1/about", "/healthz"} {
		res := c.do(http.MethodGet, path, nil)
		if res.Code != http.StatusOK {
			t.Errorf("%s: status %d", path, res.Code)
		}
		if got := scriptSrc(t, res.Header().Get("Content-Security-Policy")); got != want {
			t.Errorf("%s: %s, want %s", path, got, want)
		}
	}
	if res := c.do(http.MethodGet, "/login", nil); res.Body.String() != page {
		t.Errorf("/login body = %q, want index.html", res.Body.String())
	}
	// /api/ stays the API's: no index.html fallback for unknown endpoints.
	if res := c.do(http.MethodGet, "/api/v1/nope", nil); res.Code != http.StatusNotFound || res.errorCode() != "not_found" {
		t.Errorf("/api/v1/nope: %d %q", res.Code, res.errorCode())
	}
	if res := c.do(http.MethodGet, "/_app/immutable/gone.js", nil); res.Code != http.StatusNotFound {
		t.Errorf("missing chunk: %d", res.Code)
	}
}

func TestFrontendNotBuilt(t *testing.T) {
	c := newTestEnv(t).client("10.0.0.1:1")
	res := c.do(http.MethodGet, "/login", nil)
	if res.Code != http.StatusServiceUnavailable || !strings.Contains(res.Body.String(), "Frontend not built") {
		t.Fatalf("got %d %q", res.Code, res.Body.String())
	}
	if got := res.Header().Get("Content-Security-Policy"); got != ContentSecurityPolicy {
		t.Fatalf("CSP = %q", got)
	}
}

// The header served with the real embedded build must allow exactly that page's inline scripts.
func TestCSPMatchesEmbeddedPage(t *testing.T) {
	dist, built := web.Dist()
	if !built {
		t.Skip("frontend not built")
	}
	h, err := spa.New(dist)
	if err != nil {
		t.Fatal(err)
	}
	e := newTestEnv(t, func(o *Options) { o.Frontend = h })
	res := e.client("10.0.0.1:1").do(http.MethodGet, "/", nil)
	want := "script-src 'self' " + inlineScriptHashes(t, res.Body.String())
	if n := strings.Count(want, "'sha256-"); n != 2 {
		t.Errorf("the built page has %d inline scripts, want 2 (the theme script and the bootstrap); if web/build is "+
			"older than web/src/app.html, rebuild it (make web or .\\build.ps1 web)", n)
	}
	if got := scriptSrc(t, res.Header().Get("Content-Security-Policy")); got != want {
		t.Fatalf("%s, want %s", got, want)
	}
}

// A state-changing request whose session has ended is answered 401, not 403 csrf_failed: the session is checked
// before the CSRF token, so the SPA knows to send the user to log in. Public routes still get the CSRF check, and a
// live session with a bad token is still refused as csrf_failed.
func TestEndedSessionWriteIsUnauthenticated(t *testing.T) {
	e := newTestEnv(t)
	e.addUser("alice", "alice-password-1", true)
	c := e.loggedIn("alice", "alice-password-1")
	held := *c.cookies[auth.SessionCookie]
	heldToken := c.csrf
	if res := c.do(http.MethodPost, "/api/v1/auth/logout", nil); res.Code != http.StatusNoContent {
		t.Fatalf("logout: %d", res.Code)
	}

	stale := func(method, path string, modify func(*http.Request)) response {
		r := c.request(method, path, nil)
		r.AddCookie(&held)
		r.Header.Set(auth.CSRFHeader, heldToken)
		if modify != nil {
			modify(r)
		}
		return c.send(r)
	}
	tests := []struct {
		name     string
		path     string
		modify   func(*http.Request)
		wantCode int
		want     string
	}{
		{"ended session, its old token", "/api/v1/auth/logout", nil, http.StatusUnauthorized, "unauthenticated"},
		{"ended session, no token", "/api/v1/system/reload", func(r *http.Request) { r.Header.Del(auth.CSRFHeader) }, http.StatusUnauthorized, "unauthenticated"},
		{"ended session, cross-site", "/api/v1/system/reload", func(r *http.Request) { r.Header.Set("Origin", "http://evil.example") }, http.StatusUnauthorized, "unauthenticated"},
		{"public route still checks CSRF", "/api/v1/auth/login", nil, http.StatusForbidden, "csrf_failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if res := stale(http.MethodPost, tt.path, tt.modify); res.Code != tt.wantCode || res.errorCode() != tt.want {
				t.Fatalf("got %d %q, want %d %q", res.Code, res.errorCode(), tt.wantCode, tt.want)
			}
		})
	}

	live := e.loggedIn("alice", "alice-password-1")
	live.csrf = "bogus"
	if res := live.do(http.MethodPost, "/api/v1/auth/logout", nil); res.Code != http.StatusForbidden || res.errorCode() != "csrf_failed" {
		t.Fatalf("live session, bad token: %d %q", res.Code, res.errorCode())
	}
}
