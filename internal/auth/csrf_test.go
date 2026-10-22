// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Kate-0713/pihole-rbac/internal/secrets"
)

// post builds a state-changing request with an optional token and cookies.
func post(token string, cookies ...*http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/x", nil)
	if token != "" {
		r.Header.Set(CSRFHeader, token)
	}
	for _, c := range cookies {
		if c != nil {
			r.AddCookie(c)
		}
	}
	return r
}

func (e *sessionEnv) checkCSRF(r *http.Request) bool {
	e.t.Helper()
	ok, err := e.s.CheckRequestCSRF(context.Background(), r)
	if err != nil {
		e.t.Fatal(err)
	}
	return ok
}

func (e *sessionEnv) sessionToken(c *http.Cookie) string {
	e.t.Helper()
	s, err := e.get(c)
	if err != nil {
		e.t.Fatal(err)
	}
	return e.s.CSRFToken(s)
}

func TestCSRFSessionToken(t *testing.T) {
	e := newSessionEnv(t, SessionOptions{})
	a, b := e.login(e.createUser("alice")), e.login(e.createUser("bob"))
	tok := e.sessionToken(a)

	tests := []struct {
		name string
		r    *http.Request
		want bool
	}{
		{"valid header token", post(tok, a), true},
		{"missing token", post("", a), false},
		{"wrong token", post("bogus", a), false},
		{"token from another session", post(tok, b), false},
		{"no session or anonymous cookie", post(tok), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := e.checkCSRF(tt.r); got != tt.want {
				t.Fatalf("CheckCSRF = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCSRFTokenIsStablePerSession(t *testing.T) {
	// The SPA fetches the token once and sends it on every request.
	e := newSessionEnv(t, SessionOptions{})
	c := e.login(e.createUser("alice"))
	if e.sessionToken(c) != e.sessionToken(c) {
		t.Fatal("token changed between requests in one session")
	}
}

func TestCSRFAnonymousLoginToken(t *testing.T) {
	e := newSessionEnv(t, SessionOptions{})

	// First visit: no cookies yet, so an anonymous cookie is issued.
	w := httptest.NewRecorder()
	tok, err := e.s.AnonCSRFToken(w, httptest.NewRequest(http.MethodGet, "/api/v1/auth/csrf", nil))
	if err != nil {
		t.Fatal(err)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != AnonCookie || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode {
		t.Fatalf("expected one HttpOnly anonymous cookie, got %v", cookies)
	}
	anon := cookies[0]

	if !e.checkCSRF(post(tok, anon)) {
		t.Fatal("login token rejected with its own anonymous cookie")
	}
	if e.checkCSRF(post(tok)) {
		t.Fatal("login token accepted without the anonymous cookie")
	}
	if e.checkCSRF(post(tok, &http.Cookie{Name: AnonCookie, Value: b64.EncodeToString(bytes.Repeat([]byte{7}, anonIDSize))})) {
		t.Fatal("login token accepted with another anonymous cookie")
	}

	// Later visits reuse the cookie rather than issuing another.
	w = httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/auth/csrf", nil)
	r.AddCookie(anon)
	if again, _ := e.s.AnonCSRFToken(w, r); again != tok || len(w.Result().Cookies()) != 0 {
		t.Fatal("anonymous cookie should be reused, not reissued")
	}

	// An anonymous-bound token is no good once there's a session, even with the anonymous cookie still present.
	sess := e.login(e.createUser("alice"))
	if e.checkCSRF(post(tok, sess, anon)) {
		t.Fatal("anonymous token accepted for a session")
	}
	// And a session token is no good for the anonymous binding.
	if e.checkCSRF(post(e.sessionToken(sess), anon)) {
		t.Fatal("session token accepted without the session")
	}
}

func TestCSRFMalformedAnonCookieIsReplaced(t *testing.T) {
	e := newSessionEnv(t, SessionOptions{})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/auth/csrf", nil)
	r.AddCookie(&http.Cookie{Name: AnonCookie, Value: "not-base64!"})
	if _, err := e.s.AnonCSRFToken(w, r); err != nil {
		t.Fatal(err)
	}
	if len(w.Result().Cookies()) != 1 {
		t.Fatal("malformed anonymous cookie wasn't replaced")
	}
	if e.checkCSRF(post("anything", &http.Cookie{Name: AnonCookie, Value: "not-base64!"})) {
		t.Fatal("malformed anonymous cookie accepted")
	}
}

func TestCSRFKeyRotationInvalidatesTokens(t *testing.T) {
	e := newSessionEnv(t, SessionOptions{})
	w := httptest.NewRecorder()
	tok, err := e.s.AnonCSRFToken(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if err != nil {
		t.Fatal(err)
	}
	anon := w.Result().Cookies()[0]

	e.key = secrets.NewValue(bytes.Repeat([]byte{2}, secrets.KeySize))
	if e.checkCSRF(post(tok, anon)) {
		t.Fatal("token survived a session key change")
	}
}

func TestCSRFTokenIsNotTheCookieSignature(t *testing.T) {
	// The cookie's HMAC and the CSRF token use different labels, so reading one never yields the other.
	e := newSessionEnv(t, SessionOptions{})
	c := e.login(e.createUser("alice"))
	if _, sig, _ := bytes.Cut([]byte(c.Value), []byte(".")); string(sig) == e.sessionToken(c) {
		t.Fatal("CSRF token equals the cookie signature")
	}
}
