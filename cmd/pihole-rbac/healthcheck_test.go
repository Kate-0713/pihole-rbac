// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthURL(t *testing.T) {
	tests := []struct {
		listen  string
		want    string
		wantErr bool
	}{
		{":8080", "http://127.0.0.1:8080/healthz", false},
		{"0.0.0.0:9000", "http://127.0.0.1:9000/healthz", false},
		{"[::]:8080", "http://[::1]:8080/healthz", false},
		{"127.0.0.1:8080", "http://127.0.0.1:8080/healthz", false},
		{"192.168.1.10:8080", "http://192.168.1.10:8080/healthz", false},
		{"[fd00::5]:8080", "http://[fd00::5]:8080/healthz", false},
		{"localhost:8080", "http://localhost:8080/healthz", false},
		{"8080", "", true},
	}
	for _, tt := range tests {
		got, err := healthURL(tt.listen)
		if (err != nil) != tt.wantErr || got != tt.want {
			t.Errorf("healthURL(%q) = %q, %v; want %q, error %v", tt.listen, got, err, tt.want, tt.wantErr)
		}
	}
}

func TestHealthcheck(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		wantErr string // "" means healthy
	}{
		{"ok", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }, ""},
		{"error status", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "ok", http.StatusServiceUnavailable)
		}, "503"},
		{"wrong body", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) }, "200"},
		{"redirect not followed", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		}, "302"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var path string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				path = r.URL.Path
				tt.handler(w, r)
			}))
			defer srv.Close()
			t.Setenv("PIHOLE_RBAC_LISTEN", srv.Listener.Addr().String())
			// A proxy in the environment must not be used for the loopback check.
			t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
			t.Setenv("http_proxy", "http://127.0.0.1:1")
			t.Setenv("NO_PROXY", "")
			t.Setenv("no_proxy", "")

			err := run([]string{"healthcheck"})
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("err = %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want it to mention %q", err, tt.wantErr)
			}
			if path != "/healthz" {
				t.Fatalf("path = %q", path)
			}
		})
	}
}

func TestHealthcheckNothingListening(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	t.Setenv("PIHOLE_RBAC_LISTEN", addr)
	if err := run([]string{"healthcheck"}); err == nil || !strings.Contains(err.Error(), "unhealthy") {
		t.Fatalf("err = %v", err)
	}
}

func TestHealthcheckArgs(t *testing.T) {
	if err := run([]string{"healthcheck", "extra"}); err == nil {
		t.Fatal("extra argument accepted")
	}
	t.Setenv("PIHOLE_RBAC_LOG_LEVEL", "loud")
	if err := run([]string{"healthcheck"}); err == nil || !strings.Contains(err.Error(), "configuration") {
		t.Fatalf("err = %v", err)
	}
}
