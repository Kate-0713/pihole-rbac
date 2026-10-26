// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/Kate-0713/pihole-rbac/internal/auth/ldaptest"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi/piholetest"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
	"github.com/Kate-0713/pihole-rbac/internal/setup"
	"github.com/Kate-0713/pihole-rbac/internal/store"
)

// TestImportJSONCommand runs a dry run and an import against a fake Pi-hole and a small LDAP server, as the command
// would be run against v1's real files.
func TestImportJSONCommand(t *testing.T) {
	c := newCLI(t)
	t.Setenv("PIHOLE_RBAC_SECRET_KEY", secrets.NewKey())

	pihole := piholetest.New(t, "pihole-v1-password")
	pihole.AddGroup("AUTOSET-lab")
	dir, err := ldaptest.Start("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dir.Close() })
	fx := ldaptest.Example(dir)

	v1 := t.TempDir()
	hash, err := bcrypt.GenerateFromPassword([]byte("kate-v1-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	writeJSON(t, filepath.Join(v1, "config.json"), map[string]any{
		"enabled_auth_methods": []string{"local", "ldap"},
		"session_key":          "0123456789abcdef",
		"ldap": map[string]any{
			"url": fx.URL, "bind_dn": fx.BindDN, "bind_password": fx.BindPassword, "base_dn": fx.BaseDN,
			"user_filter": fx.UserFilter, "admin_group_dn": fx.AdminGroup, "staff_group_dn": fx.StaffGroup,
		},
		"pihole":           map[string]any{"base_url": pihole.URL, "api_password": "pihole-v1-password"},
		"permissions_file": "permissions.json",
		"notifications": map[string]any{
			"discord_webhooks": []any{map[string]any{"url": "https://discord.com/api/webhooks/42/v1-webhook-token"}},
			"events":           []string{"toggle_blocking"},
		},
		"client_reset": map[string]any{"enabled": true, "schedule_time": "03:00", "target_client_prefixes": []string{"TEST-"},
			"target_group_prefixes": []string{"AUTOSET-"}},
	})
	writeJSON(t, filepath.Join(v1, "permissions.json"), map[string]any{
		"staff": []string{"view_domains", "view_clients", "edit_clients"}, "reader": []string{"view_domains"},
		"admin": []string{"view_query_log"},
	})
	writeJSON(t, filepath.Join(v1, "local-users.json"), []any{
		map[string]any{"username": "kate", "password_hash": string(hash), "roles": []string{"admin"}},
	})
	cfg := filepath.Join(v1, "config.json")
	secretsIn := []string{"pihole-v1-password", fx.BindPassword, "v1-webhook-token", string(hash)}
	noSecrets := func(step string) {
		t.Helper()
		for _, s := range secretsIn {
			if strings.Contains(c.out.String(), s) || strings.Contains(c.errOut.String(), s) {
				t.Fatalf("%s printed a secret:\n%s\n%s", step, c.out, c.errOut)
			}
		}
	}

	// The schedule needs its time zone.
	if err := c.run("", "import-json", "--config", cfg); err == nil || !strings.Contains(c.out.String(), "--time-zone") {
		t.Fatalf("without --time-zone: %v\n%s", err, c.out)
	}

	// A dry run tests the connections and changes nothing.
	if err := c.run("", "import-json", "--config", cfg, "--time-zone", "Europe/London"); err != nil {
		t.Fatalf("dry run: %v\n%s", err, c.out)
	}
	for _, want := range []string{"Dry run", "connection test: passed", "imported switched on", "service bind: passed",
		"login methods: local, ldap", "mapping: admin ← " + fx.AdminGroup, "kate: admin", "Run the same command with --apply"} {
		if !strings.Contains(c.out.String(), want) {
			t.Fatalf("dry run output lacks %q:\n%s", want, c.out)
		}
	}
	noSecrets("the dry run")
	if _, err := os.Stat(filepath.Join(c.dataDir, store.FileName)); !os.IsNotExist(err) {
		t.Fatalf("the dry run created the database: %v", err)
	}

	// The import.
	if err := c.run("", "import-json", "--config", cfg, "--time-zone", "Europe/London", "--apply"); err != nil {
		t.Fatalf("import: %v\n%s\n%s", err, c.out, c.errOut)
	}
	if !strings.Contains(c.out.String(), "First-run setup is closed") || !strings.Contains(c.errOut.String(), `action=instance_create target="instance:pihole1"`) {
		t.Fatalf("import output:\n%s\n%s", c.out, c.errOut)
	}
	noSecrets("the import")
	if pihole.Logins() == 0 || pihole.Logouts() != pihole.Logins() {
		t.Fatalf("the connection tests logged in %d times and out %d", pihole.Logins(), pihole.Logouts())
	}
	st := c.store()
	ctx := context.Background()
	if open, err := setup.Required(ctx, st.Read()); err != nil || open {
		t.Fatalf("setup open %v, %v", open, err)
	}
	inst, err := st.Read().GetInstance(ctx, 1)
	if err != nil || !inst.Enabled || inst.BaseUrl != pihole.URL {
		t.Fatalf("instance %+v, %v", inst, err)
	}
	st.Close()

	// Running it again finds a database that isn't new, in a dry run and an import alike.
	if err := c.run("", "import-json", "--config", cfg, "--time-zone", "Europe/London"); err == nil ||
		!strings.Contains(c.out.String(), "first-run setup is complete") {
		t.Fatalf("second dry run: %v\n%s", err, c.out)
	}
	if err := c.run("", "import-json", "--config", cfg, "--time-zone", "Europe/London", "--apply"); err == nil ||
		!strings.Contains(err.Error(), "not a fresh database") {
		t.Fatalf("second import: %v", err)
	}
}

func TestImportJSONUsage(t *testing.T) {
	c := newCLI(t)
	if err := c.run("", "import-json"); err == nil || !strings.Contains(c.errOut.String(), "usage: pihole-rbac import-json") {
		t.Fatalf("no --config: %v %q", err, c.errOut)
	}
	if err := c.run("", "import-json", "--config", filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("a missing config.json was accepted")
	}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
