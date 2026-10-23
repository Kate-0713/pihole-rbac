// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package piholetest is a fake Pi-hole v6 API for tests. It implements login, logout, session checks and the
// blocking endpoints; tests add anything else with Handle.
package piholetest

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// Server is a fake Pi-hole.
type Server struct {
	*httptest.Server

	password string

	mu       sync.Mutex
	validity int
	sessions map[string]bool
	logins   int
	logouts  int
	blocking bool
	handle   func(w http.ResponseWriter, r *http.Request) bool
}

// New starts a plain HTTP fake that accepts password. It is closed when the test ends.
func New(t testing.TB, password string) *Server {
	s := newServer(password)
	s.Server = httptest.NewServer(s)
	t.Cleanup(s.Close)
	return s
}

// NewTLS starts an HTTPS fake with httptest's self-signed certificate.
func NewTLS(t testing.TB, password string) *Server {
	s := newServer(password)
	s.Server = httptest.NewTLSServer(s)
	t.Cleanup(s.Close)
	return s
}

func newServer(password string) *Server {
	return &Server{password: password, validity: 1800, sessions: map[string]bool{}, blocking: true}
}

// SetValidity sets the session lifetime, in seconds, that later logins report.
func (s *Server) SetValidity(seconds int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.validity = seconds
}

// Handle installs a handler that runs, after the session check, before the built-in endpoints. It returns true if it
// handled the request.
func (s *Server) Handle(h func(w http.ResponseWriter, r *http.Request) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handle = h
}

// ForgetSessions drops every session, as a Pi-hole restart does.
func (s *Server) ForgetSessions() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions = map[string]bool{}
}

// Sessions returns how many sessions are open.
func (s *Server) Sessions() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// Logins returns how many logins succeeded.
func (s *Server) Logins() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.logins
}

// Logouts returns how many sessions were ended with DELETE /api/auth.
func (s *Server) Logouts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.logouts
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/api/auth" && r.Method == http.MethodPost:
		s.login(w, r)
		return
	case r.URL.Path == "/api/auth" && r.Method == http.MethodDelete:
		s.logout(w, r)
		return
	}

	s.mu.Lock()
	ok := s.sessions[r.Header.Get("X-FTL-SID")]
	handle := s.handle
	s.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]string{"key": "unauthorized"}})
		return
	}
	if handle != nil && handle(w, r) {
		return
	}

	switch {
	case r.URL.Path == "/api/dns/blocking" && r.Method == http.MethodGet:
		s.mu.Lock()
		state := map[bool]string{true: "enabled", false: "disabled"}[s.blocking]
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"blocking": state})
	case r.URL.Path == "/api/dns/blocking" && r.Method == http.MethodPost:
		var in struct {
			Blocking bool `json:"blocking"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]string{"key": "bad_request"}})
			return
		}
		s.mu.Lock()
		s.blocking = in.Blocking
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"blocking": in.Blocking})
	case r.URL.Path == "/api/action/restartdns" && r.Method == http.MethodPost:
		writeJSON(w, http.StatusOK, map[string]any{"status": "restarting"})
	default:
		writeJSON(w, http.StatusNotFound, map[string]any{"error": map[string]string{"key": "not_found"}})
	}
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Password string `json:"password"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	s.mu.Lock()
	defer s.mu.Unlock()
	if in.Password != s.password {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"session": map[string]any{"valid": false, "sid": nil, "validity": -1},
			"error":   map[string]string{"key": "unauthorized"},
		})
		return
	}
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	sid := base64.RawURLEncoding.EncodeToString(b)
	s.sessions[sid] = true
	s.logins++
	writeJSON(w, http.StatusOK, map[string]any{
		"session": map[string]any{"valid": true, "sid": sid, "validity": s.validity},
	})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	sid := r.Header.Get("X-FTL-SID")
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.sessions[sid] {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]string{"key": "unauthorized"}})
		return
	}
	delete(s.sessions, sid)
	s.logouts++
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
