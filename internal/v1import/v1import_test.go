// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1import

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/auth"
	"github.com/Kate-0713/pihole-rbac/internal/clientreset"
	"github.com/Kate-0713/pihole-rbac/internal/instances"
	"github.com/Kate-0713/pihole-rbac/internal/loginsettings"
	"github.com/Kate-0713/pihole-rbac/internal/notifications"
	"github.com/Kate-0713/pihole-rbac/internal/notify"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
	"github.com/Kate-0713/pihole-rbac/internal/setup"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

var t0 = time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)

// The secret values in the example files. No report, error or audit row may contain any of them.
const (
	piholePassword = "pihole-v1-app-password"
	bindPassword   = "ldap-v1-bind-password"
	webhookURL     = "https://discord.com/api/webhooks/123456789012345678/v1-webhook-token"
	matrixToken    = "syt_v1_matrix_token"
)

var allSecrets = []string{piholePassword, bindPassword, "v1-webhook-token", matrixToken}

// exampleConfig is a v1 config.json like v1's example, as a map so a test can change it.
func exampleConfig() map[string]any {
	return map[string]any{
		"listen_addr":          ":8090",
		"enabled_auth_methods": []any{"local", "ldap"},
		"session_key":          "0123456789abcdef0123456789abcdef",
		"trusted_proxies":      []any{},
		"ldap": map[string]any{
			"url":             "ldaps://dc01.example.local:636",
			"bind_dn":         "cn=pihole-rbac-svc,ou=service-accounts,dc=example,dc=local",
			"bind_password":   bindPassword,
			"base_dn":         "dc=example,dc=local",
			"user_filter":     "(sAMAccountName=%s)",
			"admin_group_dn":  "cn=pihole-admin,ou=groups,dc=example,dc=local",
			"staff_group_dn":  "cn=pihole-staff,ou=groups,dc=example,dc=local",
			"reader_group_dn": "CN=pihole-reader,OU=groups,DC=example,DC=local",
		},
		"pihole":           map[string]any{"base_url": "http://10.0.0.5", "api_password": piholePassword},
		"local_users_file": "local-users.json",
		"permissions_file": "permissions.json",
		"notifications": map[string]any{
			"discord_webhooks": []any{map[string]any{"url": webhookURL, "enabled": true}},
			"matrix_accounts": []any{map[string]any{"homeserver": "https://matrix.example.org", "room_id": "!room:example.org",
				"access_token": matrixToken, "enabled": false}},
			"events":           []any{"toggle_blocking", "restart_dns", "reload_config"},
			"protected_groups": []any{"Staff Devices"},
		},
		"client_reset": map[string]any{
			"enabled": true, "schedule_time": "03:00", "target_client_prefixes": []any{"NINJA-", "TEST-"},
			"group_id_mode": false, "target_group_prefixes": []any{"AUTOSET-"}, "target_group_ids": []any{},
		},
	}
}

func examplePermissions() map[string]any {
	return map[string]any{
		"staff":  []any{"view_domains", "view_clients", "edit_clients"},
		"reader": []any{"view_domains", "view_clients"},
		"admin": []any{"view_query_log", "view_domains", "edit_domains", "view_clients", "edit_clients", "restart_dns",
			"enable_disable", "reload_config", "manage_config", "run_client_reset", "manage_users"},
	}
}

func hash(t *testing.T, pw string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}

func exampleUsers(t *testing.T) []any {
	return []any{
		map[string]any{"username": "kate", "password_hash": hash(t, "kate-v1-password"), "roles": []any{"admin"}},
		map[string]any{"username": "bob", "password_hash": hash(t, "bob-v1-password"), "roles": []any{"staff", "reader"}},
	}
}

// writeFiles writes the v1 files into a new directory and returns config.json's path. A nil value isn't written.
func writeFiles(t *testing.T, cfg, perms map[string]any, users []any) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name string, v any) {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("config.json", cfg)
	if perms != nil {
		write("permissions.json", perms)
	}
	if users != nil {
		write("local-users.json", users)
	}
	return filepath.Join(dir, "config.json")
}

// fakeSecrets stands in for the loaded secrets: an optional master key and environment overrides.
type fakeSecrets struct {
	c        *secrets.Cipher
	instance map[string]string
	ldap     string
	channel  map[string]string
}

func (f *fakeSecrets) Cipher() *secrets.Cipher { return f.c }
func (f *fakeSecrets) InstancePassword(env string) (secrets.Value, bool) {
	v, ok := f.instance[env]
	return secrets.NewValue([]byte(v)), ok
}
func (f *fakeSecrets) LDAPBindPassword() (secrets.Value, bool) {
	return secrets.NewValue([]byte(f.ldap)), f.ldap != ""
}
func (f *fakeSecrets) ChannelSecret(env string) (secrets.Value, bool) {
	v, ok := f.channel[env]
	return secrets.NewValue([]byte(v)), ok
}

func withKey(t *testing.T) *fakeSecrets {
	t.Helper()
	c, err := secrets.NewCipher(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return &fakeSecrets{c: c}
}

// fakeProber answers Check without contacting anything.
type fakeProber struct {
	groups    []piholeapi.Group
	piholeErr error
	ldapErr   error
	piholePW  string // the password the connection test was given
	ldapPW    string
}

func (f *fakeProber) Pihole(_ context.Context, _ instances.Input, pw secrets.Value) ([]piholeapi.Group, error) {
	f.piholePW = pw.Reveal()
	return f.groups, f.piholeErr
}

func (f *fakeProber) LDAPBind(_ context.Context, _ auth.LDAPSettings, pw secrets.Value) error {
	f.ldapPW = pw.Reveal()
	return f.ldapErr
}

func okProber() *fakeProber {
	return &fakeProber{groups: []piholeapi.Group{{ID: 0, Name: "Default"}, {ID: 4, Name: "AUTOSET-lab"}, {ID: 7, Name: "Staff Devices"}}}
}

func plan(t *testing.T, cfg, perms map[string]any, users []any, opts Options) *Plan {
	t.Helper()
	v, err := Read(Files{Config: writeFiles(t, cfg, perms, users)})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Secrets == nil {
		opts.Secrets = withKey(t)
	}
	return Build(v, opts)
}

func has(list []string, sub string) bool {
	return slices.ContainsFunc(list, func(s string) bool { return strings.Contains(s, sub) })
}

func TestRead(t *testing.T) {
	t.Run("files named in config.json, next to it", func(t *testing.T) {
		v, err := Read(Files{Config: writeFiles(t, exampleConfig(), examplePermissions(), exampleUsers(t))})
		if err != nil {
			t.Fatal(err)
		}
		if len(v.Users) != 2 || v.Permissions["staff"] == nil || v.UsersFrom == "" || v.PermissionsFrom == "" {
			t.Fatalf("read %+v", v)
		}
	})
	t.Run("no permissions_file means v1's defaults", func(t *testing.T) {
		cfg := exampleConfig()
		delete(cfg, "permissions_file")
		v, err := Read(Files{Config: writeFiles(t, cfg, nil, exampleUsers(t))})
		if err != nil || v.PermissionsFrom != "" || !slices.Contains(v.Permissions["staff"], "edit_clients") {
			t.Fatalf("err %v, from %q, perms %v", err, v.PermissionsFrom, v.Permissions)
		}
	})
	t.Run("a named permissions file that is missing", func(t *testing.T) {
		_, err := Read(Files{Config: writeFiles(t, exampleConfig(), nil, exampleUsers(t))})
		if err == nil || !strings.Contains(err.Error(), "--permissions") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("no users file is no users, unless it was given", func(t *testing.T) {
		path := writeFiles(t, exampleConfig(), examplePermissions(), nil)
		v, err := Read(Files{Config: path})
		if err != nil || v.Users != nil || v.UsersFrom != "" {
			t.Fatalf("err %v, users %v", err, v.Users)
		}
		if _, err := Read(Files{Config: path, Users: filepath.Join(filepath.Dir(path), "nope.json")}); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("named users file: err = %v", err)
		}
	})
	t.Run("a broken file doesn't repeat what is in it", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")
		if err := os.WriteFile(path, []byte(`{"pihole": {"api_password": "`+piholePassword+`" oops}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := Read(Files{Config: path})
		if err == nil || strings.Contains(err.Error(), piholePassword) || !strings.Contains(err.Error(), "isn't valid JSON") {
			t.Fatalf("err = %v", err)
		}
		if err := os.WriteFile(path, []byte(`{"pihole": {"api_password": 42}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Read(Files{Config: path}); err == nil || !strings.Contains(err.Error(), "wrong type") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestBuildExample(t *testing.T) {
	p := plan(t, exampleConfig(), examplePermissions(), exampleUsers(t), Options{TimeZone: "Europe/London"})
	if len(p.Errors) > 0 {
		t.Fatalf("errors: %v", p.Errors)
	}
	if p.Instance.Input.Name != DefaultInstanceName || p.Instance.Input.BaseURL != "http://10.0.0.5" || !p.Instance.Store || p.Instance.Input.EnvName != "" {
		t.Fatalf("instance %+v", p.Instance)
	}
	want := []PlannedRole{
		{Name: "staff", Description: "Imported from v1's staff role.", Permissions: []string{"clients.edit", "clients.view", "domains.view"}},
		{Name: "reader", Description: "Imported from v1's reader role.", Permissions: []string{"clients.view", "domains.view"}},
	}
	if !slices.EqualFunc(p.Roles, want, func(a, b PlannedRole) bool {
		return a.Name == b.Name && a.Description == b.Description && slices.Equal(a.Permissions, b.Permissions)
	}) {
		t.Fatalf("roles %+v", p.Roles)
	}
	if len(p.Users) != 2 || p.admins() != 1 || !slices.Equal(p.Users[1].Roles, []string{"staff", "reader"}) {
		t.Fatalf("users %+v", p.Users)
	}
	if p.LDAP == nil || !p.LDAP.Want || !p.LDAP.Store || p.LDAP.Settings.TLSMode != auth.LDAPTLSVerify || p.LDAP.Settings.AllowCNFallback {
		t.Fatalf("ldap %+v", p.LDAP)
	}
	if len(p.Mappings) != 3 || p.Mappings[2].Norm != "cn=pihole-reader,ou=groups,dc=example,dc=local" {
		t.Fatalf("mappings %+v", p.Mappings)
	}
	if !slices.Equal(p.Methods, []auth.Method{auth.MethodLocal, auth.MethodLDAP}) {
		t.Fatalf("methods %v", p.Methods)
	}
	if len(p.Channels) != 2 || p.Channels[0].Input.Kind != notify.Discord || !p.Channels[0].Input.Enabled ||
		p.Channels[1].Input.Kind != notify.Matrix || p.Channels[1].Input.Enabled || !p.Channels[0].Store {
		t.Fatalf("channels %+v", p.Channels)
	}
	wantEvents := []string{"blocking_set", "config_reload", "dns_restart", "protected_group_add"}
	if !slices.Equal(p.Channels[0].Input.Events, wantEvents) {
		t.Fatalf("events %v", p.Channels[0].Input.Events)
	}
	if !slices.Equal(p.Protected, []string{"Staff Devices"}) || len(p.Rules) != 2 || p.Rules[0].Match != clientreset.MatchPrefixes {
		t.Fatalf("protected %v, rules %+v", p.Protected, p.Rules)
	}
	if p.Schedule == nil || *p.Schedule != (loginsettings.ResetSchedule{Enabled: true, Time: "03:00", TimeZone: "Europe/London"}) {
		t.Fatalf("schedule %+v", p.Schedule)
	}
	if !has(p.ToDo, "PIHOLE_RBAC_LISTEN") || !has(p.ToDo, "everyone logs in again") {
		t.Fatalf("to do %v", p.ToDo)
	}
}

func TestBuildProblems(t *testing.T) {
	type change func(cfg, perms map[string]any, users []any) []any
	tests := []struct {
		name     string
		change   change
		opts     Options
		errors   []string
		warnings []string
		todo     []string
		check    func(t *testing.T, p *Plan)
	}{
		{
			name: "manage_config on staff is left out",
			change: func(_, perms map[string]any, u []any) []any {
				perms["staff"] = []any{"view_domains", "manage_config"}
				return u
			},
			warnings: []string{"staff role had manage_config"},
			check: func(t *testing.T, p *Plan) {
				if !slices.Equal(p.Roles[0].Permissions, []string{"domains.view"}) {
					t.Fatalf("staff %v", p.Roles[0].Permissions)
				}
			},
		},
		{
			name: "every v1 permission maps",
			change: func(_, perms map[string]any, u []any) []any {
				perms["reader"] = []any{"view_query_log", "view_domains", "edit_domains", "view_clients", "edit_clients",
					"restart_dns", "enable_disable", "reload_config", "run_client_reset", "manage_users"}
				return u
			},
			check: func(t *testing.T, p *Plan) {
				want := []string{"blocking.toggle", "clientreset.run", "clients.edit", "clients.view", "config.reload",
					"dns.restart", "domains.edit", "domains.view", "querylog.view", "users.manage"}
				if !slices.Equal(p.Roles[1].Permissions, want) {
					t.Fatalf("reader %v", p.Roles[1].Permissions)
				}
			},
		},
		{
			name: "a v1 admin with fewer permissions",
			change: func(_, perms map[string]any, u []any) []any {
				perms["admin"] = []any{"view_domains", "manage_users"}
				return u
			},
			warnings: []string{"v1's admin role didn't have view_query_log"},
		},
		{
			name: "a role or permission v1 would have refused",
			change: func(_, perms map[string]any, u []any) []any {
				perms["owner"] = []any{"view_domains"}
				perms["staff"] = []any{"view_everything"}
				return u
			},
			errors: []string{`a role "owner"`, `the permission "view_everything"`},
		},
		{
			name: "a role missing from permissions.json",
			change: func(_, perms map[string]any, u []any) []any {
				delete(perms, "reader")
				return u
			},
			warnings: []string{"doesn't list the reader role"},
		},
		{
			name: "usernames",
			change: func(_, _ map[string]any, u []any) []any {
				return append(u,
					map[string]any{"username": "Carol", "password_hash": u[0].(map[string]any)["password_hash"], "roles": []any{"reader"}},
					map[string]any{"username": "carol", "password_hash": u[0].(map[string]any)["password_hash"], "roles": []any{"reader"}},
					map[string]any{"username": "bad name", "password_hash": u[0].(map[string]any)["password_hash"], "roles": []any{"reader"}},
					map[string]any{"username": "dave", "password_hash": "plain-text", "roles": []any{"reader"}},
					map[string]any{"username": "erin", "password_hash": u[0].(map[string]any)["password_hash"], "roles": []any{"root"}},
					map[string]any{"username": "fred", "password_hash": u[0].(map[string]any)["password_hash"], "roles": []any{}},
				)
			},
			errors:   []string{`"carol"): it is the same user as "Carol"`, `("bad name")`, `("dave"): its password_hash isn't a bcrypt hash`, `role "root"`},
			warnings: []string{`"Carol" becomes "carol"`, `"fred" has no roles`},
		},
		{
			name:     "no local admin leaves setup open",
			change:   func(_, _ map[string]any, u []any) []any { return u[1:] },
			warnings: []string{"first-run setup stays open"},
		},
		{
			name: "LDAP-only v1 keeps local login after LDAP",
			change: func(cfg, _ map[string]any, u []any) []any {
				cfg["enabled_auth_methods"] = []any{"ldap"}
				return u
			},
			warnings: []string{"v1 only allowed LDAP login"},
			check: func(t *testing.T, p *Plan) {
				if !slices.Equal(p.Methods, []auth.Method{auth.MethodLDAP, auth.MethodLocal}) {
					t.Fatalf("methods %v", p.Methods)
				}
			},
		},
		{
			name: "the old auth_backend setting",
			change: func(cfg, _ map[string]any, u []any) []any {
				delete(cfg, "enabled_auth_methods")
				cfg["auth_backend"] = "local"
				return u
			},
			check: func(t *testing.T, p *Plan) {
				if !slices.Equal(p.Methods, []auth.Method{auth.MethodLocal}) || p.LDAP.Want {
					t.Fatalf("methods %v, want %v", p.Methods, p.LDAP.Want)
				}
			},
		},
		{
			name: "an unknown login method",
			change: func(cfg, _ map[string]any, u []any) []any {
				cfg["enabled_auth_methods"] = []any{"local", "saml"}
				return u
			},
			errors: []string{`login method "saml"`},
		},
		{
			name: "LDAP settings that don't validate, in use",
			change: func(cfg, _ map[string]any, u []any) []any {
				cfg["ldap"].(map[string]any)["user_filter"] = "(uid=%s)(cn=%s)"
				return u
			},
			errors: []string{"The LDAP settings in config.json"},
		},
		{
			name: "LDAP settings that don't validate, not in use",
			change: func(cfg, _ map[string]any, u []any) []any {
				cfg["enabled_auth_methods"] = []any{"local"}
				cfg["ldap"].(map[string]any)["url"] = "https://not-ldap"
				return u
			},
			warnings: []string{"aren't imported, since LDAP login was off"},
			check: func(t *testing.T, p *Plan) {
				if p.LDAP != nil || len(p.Mappings) != 0 {
					t.Fatalf("ldap %+v, mappings %v", p.LDAP, p.Mappings)
				}
			},
		},
		{
			name: "LDAP certificate settings",
			change: func(cfg, _ map[string]any, u []any) []any {
				l := cfg["ldap"].(map[string]any)
				l["insecure_skip_verify"] = true
				l["ca_cert_file"] = "/opt/pihole-rbac/ca.pem"
				return u
			},
			warnings: []string{"TLS mode is insecure", "Common Name"},
			todo:     []string{"PIHOLE_RBAC_LDAP_CA_FILE"},
			check: func(t *testing.T, p *Plan) {
				if p.LDAP.Settings.TLSMode != auth.LDAPTLSInsecure || p.LDAP.Settings.AllowCNFallback {
					t.Fatalf("settings %+v", p.LDAP.Settings)
				}
			},
		},
		{
			name: "allow_cn_fallback false needs no note, and a CA file already set needs no copying",
			change: func(cfg, _ map[string]any, u []any) []any {
				l := cfg["ldap"].(map[string]any)
				l["ca_cert_file"] = "/opt/pihole-rbac/ca.pem"
				l["allow_cn_fallback"] = false
				return u
			},
			opts: Options{LDAPCAFile: "/etc/pihole-rbac/ca.pem"},
			check: func(t *testing.T, p *Plan) {
				if has(p.Warnings, "Common Name") || has(p.ToDo, "PIHOLE_RBAC_LDAP_CA_FILE") {
					t.Fatalf("warnings %v, to do %v", p.Warnings, p.ToDo)
				}
			},
		},
		{
			name: "a bad group DN",
			change: func(cfg, _ map[string]any, u []any) []any {
				cfg["ldap"].(map[string]any)["staff_group_dn"] = "not a dn"
				return u
			},
			errors: []string{"ldap.staff_group_dn isn't a valid DN"},
		},
		{
			name: "events v2 doesn't have, or v1 didn't send",
			change: func(cfg, _ map[string]any, u []any) []any {
				cfg["notifications"].(map[string]any)["events"] = []any{"restart_app", "made_up", "update_permissions", "Login"}
				return u
			},
			warnings: []string{`no "restart_app" event`, `"made_up" isn't one v1 sent`},
			check: func(t *testing.T, p *Plan) {
				want := []string{"login", "protected_group_add", "role_create", "role_delete", "role_grants", "role_update"}
				if !slices.Equal(p.Channels[0].Input.Events, want) {
					t.Fatalf("events %v", p.Channels[0].Input.Events)
				}
			},
		},
		{
			name: "a Discord URL v2 won't send to",
			change: func(cfg, _ map[string]any, u []any) []any {
				cfg["notifications"].(map[string]any)["discord_webhooks"] = []any{map[string]any{"url": "https://evil.example/hook"}}
				return u
			},
			warnings: []string{"discord_webhooks[0] isn't imported"},
			check: func(t *testing.T, p *Plan) {
				if len(p.Channels) != 1 || p.Channels[0].Input.Kind != notify.Matrix {
					t.Fatalf("channels %+v", p.Channels)
				}
			},
		},
		{
			name: "plain HTTP Matrix, and a destination with no secret",
			change: func(cfg, _ map[string]any, u []any) []any {
				cfg["notifications"].(map[string]any)["matrix_accounts"] = []any{map[string]any{
					"homeserver": "http://matrix.lan:8008", "room_id": "!room:matrix.lan"}}
				return u
			},
			warnings: []string{"uses plain HTTP", "has no secret"},
			check: func(t *testing.T, p *Plan) {
				m := p.Channels[1]
				if !m.Input.Matrix.AllowHTTP || m.Input.Secret != nil || m.Store || !m.Input.Enabled {
					t.Fatalf("matrix %+v", m)
				}
			},
		},
		{
			name: "without a master key, secrets are expected in variables",
			opts: Options{Secrets: &fakeSecrets{}},
			todo: []string{"PIHOLE_RBAC_INSTANCE_PIHOLE1_PASSWORD", "PIHOLE_RBAC_LDAP_BIND_PASSWORD",
				"PIHOLE_RBAC_NOTIFY_DISCORD_1_SECRET", "PIHOLE_RBAC_NOTIFY_MATRIX_1_SECRET"},
			check: func(t *testing.T, p *Plan) {
				if p.Instance.Store || p.Instance.Input.EnvName != "PIHOLE1" || p.LDAP.Store || p.Channels[0].Store ||
					p.Channels[0].Input.EnvName != "DISCORD_1" {
					t.Fatalf("plan %+v", p)
				}
			},
		},
		{
			name: "variables already set, one not to v1's value",
			opts: Options{Secrets: &fakeSecrets{
				instance: map[string]string{"SITE_A": "another-password"},
				ldap:     bindPassword,
				channel:  map[string]string{"DISCORD_1": strings.Replace(webhookURL, "https://discord.com", "https://DISCORD.com", 1)},
			}, InstanceName: "site-a"},
			warnings: []string{"PIHOLE_RBAC_INSTANCE_SITE_A_PASSWORD is set, but not to v1's"},
			check: func(t *testing.T, p *Plan) {
				if !p.Instance.EnvSet || !p.LDAP.EnvSet || !p.Channels[0].EnvSet || has(p.ToDo, "PIHOLE_RBAC_LDAP_BIND_PASSWORD") ||
					has(p.ToDo, "DISCORD_1") || has(p.Warnings, "DISCORD_1") {
					t.Fatalf("plan %+v, warnings %v, to do %v", p, p.Warnings, p.ToDo)
				}
			},
		},
		{
			name: "a bad base URL",
			change: func(cfg, _ map[string]any, u []any) []any {
				cfg["pihole"].(map[string]any)["base_url"] = "http://10.0.0.5/admin"
				return u
			},
			errors: []string{"The instance (pihole.base_url"},
		},
		{
			name: "client reset in group ID mode waits for the groups",
			change: func(cfg, _ map[string]any, u []any) []any {
				cr := cfg["client_reset"].(map[string]any)
				cr["group_id_mode"], cr["target_group_ids"] = true, []any{4, 7}
				return u
			},
			check: func(t *testing.T, p *Plan) {
				if len(p.Rules) != 2 || p.Rules[0].Match != clientreset.MatchNames || !slices.Equal(p.Rules[0].groupIDs, []int{4, 7}) {
					t.Fatalf("rules %+v", p.Rules)
				}
			},
		},
		{
			name: "client reset prefixes without groups",
			change: func(cfg, _ map[string]any, u []any) []any {
				cfg["client_reset"].(map[string]any)["target_group_prefixes"] = []any{}
				return u
			},
			warnings: []string{"no target groups", "no rules for it to run"},
		},
		{
			name:   "a schedule that is on needs its time zone",
			opts:   Options{TimeZone: ""},
			errors: []string{"--time-zone"},
		},
		{
			name: "a schedule that is off defaults to UTC, and 3:00 is 03:00",
			change: func(cfg, _ map[string]any, u []any) []any {
				cr := cfg["client_reset"].(map[string]any)
				cr["enabled"], cr["schedule_time"] = false, "3:00"
				return u
			},
			opts: Options{TimeZone: ""},
			check: func(t *testing.T, p *Plan) {
				if p.Schedule == nil || *p.Schedule != (loginsettings.ResetSchedule{Time: "03:00", TimeZone: "UTC"}) {
					t.Fatalf("schedule %+v", p.Schedule)
				}
			},
		},
		{
			name:   "an unknown time zone",
			opts:   Options{TimeZone: "Mars/Olympus"},
			errors: []string{"The client reset schedule"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, perms, users := exampleConfig(), examplePermissions(), exampleUsers(t)
			if tc.change != nil {
				users = tc.change(cfg, perms, users)
			}
			opts := tc.opts
			if opts.TimeZone == "" && !strings.Contains(tc.name, "time zone") && !strings.Contains(tc.name, "UTC") {
				opts.TimeZone = "Europe/London"
			}
			p := plan(t, cfg, perms, users, opts)
			if tc.check != nil {
				tc.check(t, p) // what Build planned, before Check decides what can be switched on
			}
			Check(context.Background(), p, nil, "--offline")
			for _, want := range tc.errors {
				if !has(p.Errors, want) {
					t.Errorf("no error with %q in %q", want, p.Errors)
				}
			}
			if len(tc.errors) == 0 && len(p.Errors) > 0 {
				t.Errorf("errors: %q", p.Errors)
			}
			for _, want := range tc.warnings {
				if !has(p.Warnings, want) {
					t.Errorf("no warning with %q in %q", want, p.Warnings)
				}
			}
			for _, want := range tc.todo {
				if !has(p.ToDo, want) {
					t.Errorf("nothing to do with %q in %q", want, p.ToDo)
				}
			}
			var out bytes.Buffer
			p.Report(&out)
			for _, s := range allSecrets {
				if strings.Contains(out.String(), s) || has(p.Errors, s) || has(p.Warnings, s) || has(p.ToDo, s) {
					t.Fatalf("a secret was printed:\n%s", out.String())
				}
			}
		})
	}
}

func TestCheck(t *testing.T) {
	tests := []struct {
		name    string
		secrets *fakeSecrets // nil: with a master key
		change  func(cfg map[string]any)
		prober  *fakeProber
		check   func(t *testing.T, p *Plan, f *fakeProber)
	}{
		{
			name:   "everything passes",
			prober: okProber(),
			check: func(t *testing.T, p *Plan, f *fakeProber) {
				if !p.Instance.Enable || !p.LDAP.Enable || !slices.Contains(p.Methods, auth.MethodLDAP) {
					t.Fatalf("instance %v, ldap %v, methods %v", p.Instance.Enable, p.LDAP.Enable, p.Methods)
				}
				if f.piholePW != piholePassword || f.ldapPW != bindPassword {
					t.Fatalf("tested with %q and %q", f.piholePW, f.ldapPW)
				}
				if has(p.Warnings, "No Pi-hole group starts with") || has(p.Warnings, "aren't on the Pi-hole") {
					t.Fatalf("warnings %v", p.Warnings)
				}
			},
		},
		{
			name:   "the Pi-hole and LDAP fail",
			prober: &fakeProber{piholeErr: piholeapi.ErrAuthRejected, ldapErr: errors.New("invalid credentials")},
			check: func(t *testing.T, p *Plan, _ *fakeProber) {
				if p.Instance.Enable || p.Instance.Test != instances.Kind(piholeapi.ErrAuthRejected) || p.LDAP.Enable ||
					slices.Contains(p.Methods, auth.MethodLDAP) {
					t.Fatalf("instance %+v, ldap %+v, methods %v", p.Instance, p.LDAP, p.Methods)
				}
				if !has(p.Warnings, "imported switched off") || !has(p.Warnings, "LDAP login is imported switched off") {
					t.Fatalf("warnings %v", p.Warnings)
				}
				if len(p.Rules) != 2 {
					t.Fatalf("prefix rules don't need the groups: %+v", p.Rules)
				}
			},
		},
		{
			name:    "without a master key or variables, nothing can be switched on",
			secrets: &fakeSecrets{},
			prober:  okProber(),
			check: func(t *testing.T, p *Plan, f *fakeProber) {
				if p.Instance.Test != "ok" || p.Instance.Enable || p.LDAP.Test != "ok" || p.LDAP.Enable || slices.Contains(p.Methods, auth.MethodLDAP) {
					t.Fatalf("instance %+v, ldap %+v", p.Instance, p.LDAP)
				}
				if f.piholePW != piholePassword {
					t.Fatalf("tested with %q", f.piholePW)
				}
			},
		},
		{
			name:    "without a master key, variables that are set are used",
			secrets: &fakeSecrets{instance: map[string]string{"PIHOLE1": "env-password"}, ldap: "env-bind"},
			prober:  okProber(),
			check: func(t *testing.T, p *Plan, f *fakeProber) {
				if !p.Instance.Enable || !p.LDAP.Enable || f.piholePW != "env-password" || f.ldapPW != "env-bind" {
					t.Fatalf("instance %v, ldap %v, tested with %q and %q", p.Instance.Enable, p.LDAP.Enable, f.piholePW, f.ldapPW)
				}
			},
		},
		{
			name: "group IDs become names, and missing ones are reported",
			change: func(cfg map[string]any) {
				cr := cfg["client_reset"].(map[string]any)
				cr["group_id_mode"], cr["target_group_ids"] = true, []any{4, 9}
			},
			prober: okProber(),
			check: func(t *testing.T, p *Plan, _ *fakeProber) {
				if len(p.Rules) != 2 || !slices.Equal(p.Rules[0].Groups, []string{"AUTOSET-lab"}) || p.Rules[0].Match != clientreset.MatchNames {
					t.Fatalf("rules %+v", p.Rules)
				}
				if !has(p.Warnings, "target_group_ids 9 aren't groups") {
					t.Fatalf("warnings %v", p.Warnings)
				}
			},
		},
		{
			name: "group IDs that are all missing",
			change: func(cfg map[string]any) {
				cr := cfg["client_reset"].(map[string]any)
				cr["group_id_mode"], cr["target_group_ids"] = true, []any{99}
			},
			prober: okProber(),
			check: func(t *testing.T, p *Plan, _ *fakeProber) {
				if len(p.Rules) != 0 || !has(p.Warnings, "None of client_reset's target groups") {
					t.Fatalf("rules %+v, warnings %v", p.Rules, p.Warnings)
				}
			},
		},
		{
			name: "group IDs without the Pi-hole",
			change: func(cfg map[string]any) {
				cr := cfg["client_reset"].(map[string]any)
				cr["group_id_mode"], cr["target_group_ids"] = true, []any{4}
			},
			prober: &fakeProber{piholeErr: piholeapi.ErrUnreachable},
			check: func(t *testing.T, p *Plan, _ *fakeProber) {
				if len(p.Rules) != 0 || !has(p.Warnings, "its rules aren't imported") {
					t.Fatalf("rules %+v, warnings %v", p.Rules, p.Warnings)
				}
			},
		},
		{
			name: "groups the Pi-hole doesn't have",
			change: func(cfg map[string]any) {
				cfg["client_reset"].(map[string]any)["target_group_prefixes"] = []any{"NOPE-"}
				cfg["notifications"].(map[string]any)["protected_groups"] = []any{"staff devices", "Visitors"}
			},
			prober: okProber(),
			check: func(t *testing.T, p *Plan, _ *fakeProber) {
				if !has(p.Warnings, "No Pi-hole group starts with NOPE-") || !has(p.Warnings, "protected groups Visitors aren't") {
					t.Fatalf("warnings %v", p.Warnings)
				}
			},
		},
		{
			name: "LDAP login that was off isn't tested",
			change: func(cfg map[string]any) {
				cfg["enabled_auth_methods"] = []any{"local"}
			},
			prober: okProber(),
			check: func(t *testing.T, p *Plan, f *fakeProber) {
				if f.ldapPW != "" || p.LDAP.Enable || p.LDAP.Test != "" || !slices.Equal(p.Methods, []auth.Method{auth.MethodLocal}) {
					t.Fatalf("ldap %+v, methods %v", p.LDAP, p.Methods)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := exampleConfig()
			if tc.change != nil {
				tc.change(cfg)
			}
			opts := Options{TimeZone: "Europe/London"}
			if tc.secrets != nil {
				opts.Secrets = tc.secrets
			}
			p := plan(t, cfg, examplePermissions(), exampleUsers(t), opts)
			Check(context.Background(), p, tc.prober, "")
			if len(p.Errors) > 0 {
				t.Fatalf("errors %v", p.Errors)
			}
			tc.check(t, p, tc.prober)
		})
	}

	t.Run("offline", func(t *testing.T) {
		cfg := exampleConfig()
		cr := cfg["client_reset"].(map[string]any)
		cr["group_id_mode"], cr["target_group_ids"] = true, []any{4}
		p := plan(t, cfg, examplePermissions(), exampleUsers(t), Options{TimeZone: "UTC"})
		Check(context.Background(), p, nil, "--offline")
		if p.Checked || p.Instance.Enable || p.LDAP.Enable || slices.Contains(p.Methods, auth.MethodLDAP) || len(p.Rules) != 0 {
			t.Fatalf("plan %+v", p)
		}
		var out bytes.Buffer
		p.Report(&out)
		if !strings.Contains(out.String(), "connection test: not run (--offline)") {
			t.Fatal(out.String())
		}
	})
}

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), store.Options{DataDir: t.TempDir(), Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestApply(t *testing.T) {
	ctx := context.Background()
	sec := withKey(t)
	sec.channel = map[string]string{}
	p := plan(t, exampleConfig(), examplePermissions(), exampleUsers(t), Options{TimeZone: "Europe/London", Secrets: sec})
	Check(ctx, p, okProber(), "")
	st := openStore(t)
	var log bytes.Buffer
	res, err := Apply(ctx, st, audit.NewLogger(&log), sec.c, p, "(cli)", t0)
	if err != nil {
		t.Fatal(err)
	}
	if !res.SetupClosed || res.Entries != 16 {
		t.Fatalf("result %+v", res)
	}
	q := st.Read()

	// The instance, switched on, with v1's password stored for its row.
	inst, err := q.GetInstance(ctx, res.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if !inst.Enabled || inst.Name != "pihole1" || inst.EnvName.Valid {
		t.Fatalf("instance %+v", inst)
	}
	pw, err := sec.c.Open(secrets.Sealed{KeyID: inst.PasswordKeyID.String, Nonce: inst.PasswordNonce, Ciphertext: inst.PasswordCiphertext},
		secrets.AAD("instances", inst.ID))
	if err != nil || pw.Reveal() != piholePassword || inst.PasswordUpdatedBy.String != "(cli)" {
		t.Fatalf("password %v, by %q", err, inst.PasswordUpdatedBy.String)
	}

	// Users keep their v1 passwords; setup is closed.
	kate, err := q.GetUserByUsername(ctx, "kate")
	if err != nil || !auth.CheckPassword(kate.PasswordHash.String, "kate-v1-password") {
		t.Fatalf("kate %+v, %v", kate, err)
	}
	if open, err := setup.Required(ctx, q); err != nil || open {
		t.Fatalf("setup open %v, %v", open, err)
	}
	if n, err := q.CountEnabledLocalAdmins(ctx); err != nil || n != 1 {
		t.Fatalf("admins %d, %v", n, err)
	}
	bob, _ := q.GetUserByUsername(ctx, "bob")
	bobRoles, _ := q.ListUserRoleIDs(ctx, bob.ID)
	staff, _ := q.GetRoleByName(ctx, "staff")
	reader, _ := q.GetRoleByName(ctx, "reader")
	if !slices.Equal(bobRoles, []int64{staff.ID, reader.ID}) {
		t.Fatalf("bob's roles %v", bobRoles)
	}
	grants, _ := q.ListGrantsForRole(ctx, staff.ID)
	if len(grants) != 3 {
		t.Fatalf("staff grants %+v", grants)
	}
	mappings, _ := q.ListAllLDAPMappings(ctx)
	if len(mappings) != 3 {
		t.Fatalf("mappings %+v", mappings)
	}

	// The settings load as the app loads them at startup: the login chain with LDAP, and the schedule.
	login := &loginsettings.Service{Store: st, Audit: audit.NewLogger(io.Discard), Secrets: sec}
	if err := login.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(login.Methods(), []auth.Method{auth.MethodLocal, auth.MethodLDAP}) ||
		login.ResetSchedule() != (loginsettings.ResetSchedule{Enabled: true, Time: "03:00", TimeZone: "Europe/London"}) {
		t.Fatalf("methods %v, schedule %+v", login.Methods(), login.ResetSchedule())
	}
	if v := login.LDAP(); v.PasswordSource != loginsettings.SourceStored {
		t.Fatalf("bind password %+v", v)
	}
	row, _ := q.GetSetting(ctx, auth.LDAPSettingsKey)
	bpw, err := sec.c.Open(secrets.Sealed{KeyID: row.SecretKeyID.String, Nonce: row.SecretNonce, Ciphertext: row.SecretCiphertext}, loginsettings.BindPasswordAAD)
	if err != nil || bpw.Reveal() != bindPassword {
		t.Fatalf("bind password %v", err)
	}

	// Channels, with their secrets readable as the notifier reads them.
	channels := &notifications.Service{Store: st, Audit: audit.NewLogger(io.Discard), Secrets: sec, Notifier: &notify.Notifier{}}
	if err := channels.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	list, err := channels.List(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("channels %+v, %v", list, err)
	}
	if d := list[0]; d.Name != "Discord 1" || d.SecretSource != notifications.SourceStored || d.SecretProblem != "" || d.WebhookID != "123456789012345678" ||
		!d.Enabled || !slices.Contains(d.Events, "protected_group_add") {
		t.Fatalf("discord %+v", d)
	}
	if m := list[1]; m.Matrix.Homeserver != "https://matrix.example.org" || m.SecretSource != notifications.SourceStored || m.Enabled {
		t.Fatalf("matrix %+v", m)
	}
	if prot, err := channels.ProtectedFor(ctx, res.InstanceID); err != nil || !slices.Equal(prot, []string{"Staff Devices"}) {
		t.Fatalf("protected %v, %v", prot, err)
	}

	// Client reset rules, as the rules page shows them.
	resets := &clientreset.Service{Store: st, Audit: audit.NewLogger(io.Discard)}
	rules, err := resets.Rules(ctx)
	if err != nil || len(rules.Rules) != 2 || rules.Rules[0].ScopeName != "pihole1" || !slices.Equal(rules.Rules[1].Groups, []string{"AUTOSET-"}) {
		t.Fatalf("rules %+v, %v", rules, err)
	}

	// The audit rows: one per thing created, by (cli), marked as imported, with no secret anywhere.
	rows, err := q.ListRecentAudit(ctx, 100)
	if err != nil || len(rows) != 16 {
		t.Fatalf("audit rows %d, %v", len(rows), err)
	}
	for _, r := range rows {
		if r.Username != "(cli)" || !strings.Contains(r.Detail, `"via":"import-json"`) || r.Result != audit.ResultSuccess {
			t.Fatalf("audit row %+v", r)
		}
		for _, s := range allSecrets {
			if strings.Contains(r.Detail, s) || strings.Contains(r.Target, s) {
				t.Fatalf("a secret in the audit row %+v", r)
			}
		}
	}
	for _, s := range allSecrets {
		if strings.Contains(log.String(), s) {
			t.Fatalf("a secret in the AUDIT lines:\n%s", log.String())
		}
	}

	// A second import is refused, and changes nothing.
	_, err = Apply(ctx, st, audit.NewLogger(io.Discard), sec.c, p, "(cli)", t0)
	if !errors.Is(err, ErrNotFresh) || !strings.Contains(err.Error(), "first-run setup is complete") {
		t.Fatalf("second import: %v", err)
	}
	if rows2, _ := q.ListRecentAudit(ctx, 100); len(rows2) != 16 {
		t.Fatalf("audit rows after a refused import: %d", len(rows2))
	}
}

func TestApplyWithoutKey(t *testing.T) {
	ctx := context.Background()
	sec := &fakeSecrets{instance: map[string]string{"PIHOLE1": piholePassword}}
	cfg := exampleConfig()
	cfg["enabled_auth_methods"] = []any{"local"}
	p := plan(t, cfg, examplePermissions(), exampleUsers(t)[1:], Options{TimeZone: "UTC", Secrets: sec})
	Check(ctx, p, okProber(), "")
	st := openStore(t)
	res, err := Apply(ctx, st, audit.NewLogger(io.Discard), nil, p, "(cli)", t0)
	if err != nil {
		t.Fatal(err)
	}
	if res.SetupClosed {
		t.Fatal("setup closed without a local admin")
	}
	q := st.Read()
	if open, _ := setup.Required(ctx, q); !open {
		t.Fatal("setup isn't open")
	}
	inst, _ := q.GetInstance(ctx, res.InstanceID)
	if !inst.Enabled || inst.EnvName.String != "PIHOLE1" || len(inst.PasswordCiphertext) != 0 {
		t.Fatalf("instance %+v", inst)
	}
	chs, _ := q.ListChannels(ctx)
	if len(chs) != 2 || chs[0].EnvName.String != "DISCORD_1" || len(chs[0].SecretCiphertext) != 0 {
		t.Fatalf("channels %+v", chs)
	}
	if _, err := q.GetSetting(ctx, auth.SettingsKey); err == nil {
		t.Fatal("the default login methods were saved")
	}
	// Setup still works afterwards, and keeps the imported staff and reader roles.
	token, _, err := setup.NewToken(ctx, st, t0)
	if err != nil {
		t.Fatal(err)
	}
	err = st.WithTx(ctx, func(q *db.Queries) error {
		_, _, err := setup.Complete(ctx, q, token, "admin", "a-long-admin-password", t0)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	staff, _ := q.GetRoleByName(ctx, "staff")
	if staff.Description != "Imported from v1's staff role." {
		t.Fatalf("staff %+v", staff)
	}
}

func TestApplyRefusals(t *testing.T) {
	ctx := context.Background()
	sec := withKey(t)

	t.Run("a plan with problems", func(t *testing.T) {
		p := plan(t, exampleConfig(), examplePermissions(), exampleUsers(t), Options{Secrets: sec})
		Check(ctx, p, okProber(), "")
		if _, err := Apply(ctx, openStore(t), audit.NewLogger(io.Discard), sec.c, p, "(cli)", t0); err == nil || !strings.Contains(err.Error(), "1 problem") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("a plan that wasn't checked", func(t *testing.T) {
		p := plan(t, exampleConfig(), examplePermissions(), exampleUsers(t), Options{Secrets: sec, TimeZone: "UTC"})
		if _, err := Apply(ctx, openStore(t), audit.NewLogger(io.Discard), sec.c, p, "(cli)", t0); err == nil {
			t.Fatal("applied an unchecked plan")
		}
	})
	t.Run("secrets to store without the key", func(t *testing.T) {
		p := plan(t, exampleConfig(), examplePermissions(), exampleUsers(t), Options{Secrets: sec, TimeZone: "UTC"})
		Check(ctx, p, okProber(), "")
		if _, err := Apply(ctx, openStore(t), audit.NewLogger(io.Discard), nil, p, "(cli)", t0); err == nil {
			t.Fatal("applied without the key")
		}
	})
	t.Run("a database setup was finished in", func(t *testing.T) {
		st := openStore(t)
		token, _, err := setup.NewToken(ctx, st, t0)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.WithTx(ctx, func(q *db.Queries) error {
			_, _, err := setup.Complete(ctx, q, token, "admin", "a-long-admin-password", t0)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		p := plan(t, exampleConfig(), examplePermissions(), exampleUsers(t), Options{Secrets: sec, TimeZone: "UTC"})
		Check(ctx, p, okProber(), "")
		_, err = Apply(ctx, st, audit.NewLogger(io.Discard), sec.c, p, "(cli)", t0)
		if !errors.Is(err, ErrNotFresh) || !strings.Contains(err.Error(), "1 user") || !strings.Contains(err.Error(), "2 roles besides admin") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("a failure part-way leaves nothing behind", func(t *testing.T) {
		st := openStore(t)
		p := plan(t, exampleConfig(), examplePermissions(), exampleUsers(t), Options{Secrets: sec, TimeZone: "UTC"})
		Check(ctx, p, okProber(), "")
		p.Users = append(p.Users, p.Users[0]) // Build refuses duplicates; the database's unique index is the backstop
		_, err := Apply(ctx, st, audit.NewLogger(io.Discard), sec.c, p, "(cli)", t0)
		if err == nil || store.Constraint(errors.Unwrap(err)) != store.Unique {
			t.Fatalf("err = %v", err)
		}
		if err := Fresh(ctx, st.Read()); err != nil {
			t.Fatalf("not fresh after a failed import: %v", err)
		}
		if rows, _ := st.Read().ListRecentAudit(ctx, 10); len(rows) != 0 {
			t.Fatalf("audit rows %+v", rows)
		}
	})
}

// TestMapsCoverV1 checks the permission and event maps against every name v1 had, and that every v2 name they give
// exists.
func TestMapsCoverV1(t *testing.T) {
	for _, perms := range v1DefaultPermissions() {
		for _, p := range perms {
			if _, ok := permissionMap[p]; !ok {
				t.Errorf("v1 permission %s isn't mapped", p)
			}
		}
	}
	events := map[string]bool{}
	for _, e := range notifications.Events() {
		events[e.Name] = true
	}
	for v1, v2s := range eventMap {
		for _, e := range v2s {
			if !events[e] {
				t.Errorf("v1 event %s maps to %s, which isn't a v2 event", v1, e)
			}
		}
	}
	// v1's README lists the action names it audited.
	for _, e := range []string{"login", "logout", "toggle_blocking", "restart_dns", "add_domain", "update_domain_groups",
		"update_client_groups", "client_reset", "reload_permissions", "reload_config", "update_permissions", "update_config",
		"restart_app", "create_user", "update_user_roles", "reset_user_password", "delete_user", "csrf_rejected", "login_locked"} {
		if _, ok := eventMap[e]; !ok {
			t.Errorf("v1 event %s isn't mapped", e)
		}
	}
}
