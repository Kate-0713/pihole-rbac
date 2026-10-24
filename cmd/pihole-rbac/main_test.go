// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kate-0713/pihole-rbac/internal/buildinfo"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
	"github.com/Kate-0713/pihole-rbac/internal/store"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{"version", []string{"version"}, false},
		{"help", []string{"help"}, false},
		{"unknown", []string{"frobnicate"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := run(tt.args); (err != nil) != tt.wantErr {
				t.Fatalf("run(%v) err = %v, wantErr %v", tt.args, err, tt.wantErr)
			}
		})
	}
}

func TestVersionTextReportsFrontend(t *testing.T) {
	got := versionText()
	if !strings.Contains(got, "frontend: embedded") && !strings.Contains(got, "frontend: not built") {
		t.Fatalf("versionText() = %q, missing frontend line", got)
	}
	if !strings.Contains(got, "source: "+buildinfo.Source) {
		t.Fatalf("versionText() = %q, missing source line", got)
	}
}

// serve must fail on bad configuration or secrets before it opens (and possibly migrates) the database.
func TestServeFailsBeforeOpeningStore(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		setup   func(t *testing.T, dataDir string)
		wantErr string
	}{
		{name: "bad config", env: map[string]string{"PIHOLE_RBAC_LOG_LEVEL": "loud"}, wantErr: "configuration"},
		{name: "secret and _FILE both set", env: map[string]string{
			"PIHOLE_RBAC_LDAP_BIND_PASSWORD":      "x",
			"PIHOLE_RBAC_LDAP_BIND_PASSWORD_FILE": "y",
		}, wantErr: "both set"},
		{name: "malformed master key", env: map[string]string{"PIHOLE_RBAC_SECRET_KEY": "short"}, wantErr: "PIHOLE_RBAC_SECRET_KEY"},
		{name: "malformed session.key", setup: func(t *testing.T, dataDir string) {
			if err := os.WriteFile(filepath.Join(dataDir, secrets.SessionKeyFile), []byte("garbage"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, wantErr: "session.key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataDir := t.TempDir()
			t.Setenv("PIHOLE_RBAC_DATA_DIR", dataDir)
			t.Setenv("PIHOLE_RBAC_LISTEN", "127.0.0.1:0")
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			if tt.setup != nil {
				tt.setup(t, dataDir)
			}
			err := run([]string{"serve"})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want it to mention %q", err, tt.wantErr)
			}
			if _, err := os.Stat(filepath.Join(dataDir, store.FileName)); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("database was created before the error: %v", err)
			}
		})
	}
}
