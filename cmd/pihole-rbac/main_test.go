// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kate-0713/pihole-rbac/internal/buildinfo"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
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

func TestNewAuthenticator(t *testing.T) {
	ldapSettings := `{"url":"ldaps://dc01.example.local","bind_dn":"cn=svc,dc=example,dc=local","base_dn":"dc=example,dc=local","user_filter":"(uid=%s)"}`
	tests := []struct {
		name          string
		settings      map[string]string
		wantErr       string
		wantDirectory bool
	}{
		{name: "defaults: local only"},
		{name: "local and ldap", settings: map[string]string{"auth": `{"methods":["local","ldap"]}`, "ldap": ldapSettings}, wantDirectory: true},
		{name: "ldap enabled, not configured", settings: map[string]string{"auth": `{"methods":["ldap"]}`}, wantErr: "no LDAP settings"},
		{name: "ldap settings invalid", settings: map[string]string{
			"auth": `{"methods":["ldap"]}`,
			"ldap": `{"url":"http://dc01","bind_dn":"cn=svc,dc=x","base_dn":"dc=x","user_filter":"(uid=%s)"}`,
		}, wantErr: "url"},
		{name: "login settings invalid", settings: map[string]string{"auth": `{"methods":[]}`}, wantErr: "at least one"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			st, err := store.Open(ctx, store.Options{DataDir: dir, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			for k, v := range tt.settings {
				if err := st.WithTx(ctx, func(q *db.Queries) error {
					return q.UpsertSetting(ctx, db.UpsertSettingParams{Key: k, Value: v})
				}); err != nil {
					t.Fatal(err)
				}
			}
			sec, err := secrets.Load(secrets.Options{DataDir: dir, Getenv: func(string) string { return "" }, Environ: func() []string { return nil }})
			if err != nil {
				t.Fatal(err)
			}
			_, directory, err := newAuthenticator(ctx, st, sec, "", slog.New(slog.NewTextHandler(io.Discard, nil)))
			if tt.wantErr == "" && err != nil {
				t.Fatal(err)
			}
			if tt.wantErr == "" && (directory != nil) != tt.wantDirectory {
				t.Fatalf("directory = %v, want one: %v", directory, tt.wantDirectory)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("err = %v, want it to mention %q", err, tt.wantErr)
			}
		})
	}
}
