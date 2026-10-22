// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Kate-0713/pihole-rbac/internal/buildinfo"
)

func TestGetAbout(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		wantCode int
	}{
		{"get", http.MethodGet, http.StatusOK},
		{"post rejected", http.MethodPost, http.StatusMethodNotAllowed},
		{"delete rejected", http.MethodDelete, http.StatusMethodNotAllowed},
	}
	mux := NewMux()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(tt.method, "/api/v1/about", nil))
			if rec.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantCode)
			}
		})
	}
}

// The body must match the spec exactly: source_url and license, nothing else (in particular, no version).
func TestGetAboutBody(t *testing.T) {
	rec := httptest.NewRecorder()
	NewMux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/about", nil))

	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON %q: %v", rec.Body.String(), err)
	}
	want := map[string]string{"source_url": buildinfo.Source, "license": buildinfo.License}
	if len(body) != len(want) {
		t.Fatalf("body has keys %v, want exactly %v", body, want)
	}
	for k, v := range want {
		if body[k] != v {
			t.Errorf("%s = %v, want %q", k, body[k], v)
		}
	}
}
