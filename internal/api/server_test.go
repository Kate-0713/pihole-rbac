// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"bytes"
	"crypto/tls"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/auth"
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
