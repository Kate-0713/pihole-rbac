// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"net/http"
	"testing"
)

func TestHealthz(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		wantCode int
		wantBody string
	}{
		{"get", http.MethodGet, http.StatusOK, "ok"},
		{"head", http.MethodHead, http.StatusOK, ""},
		{"post rejected", http.MethodPost, http.StatusMethodNotAllowed, ""},
	}
	e := newTestEnv(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := e.client("10.0.0.1:1").do(tt.method, "/healthz", nil)
			if res.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d", res.Code, tt.wantCode)
			}
			if tt.wantBody != "" && res.Body.String() != tt.wantBody {
				t.Fatalf("body = %q, want %q", res.Body.String(), tt.wantBody)
			}
		})
	}
}
