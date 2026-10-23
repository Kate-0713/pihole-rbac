// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/auth"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// addRoleUser creates a role with the given permissions at scope all and a local user who has only that role.
func (e *testEnv) addRoleUser(name, password string, perms ...rbac.Permission) int64 {
	e.t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		e.t.Fatal(err)
	}
	ctx := context.Background()
	var id int64
	err = e.st.WithTx(ctx, func(q *db.Queries) error {
		role, err := q.CreateRole(ctx, db.CreateRoleParams{Name: name + "-role", CreatedAt: 1})
		if err != nil {
			return err
		}
		for _, p := range perms {
			if err := q.InsertGrant(ctx, db.InsertGrantParams{RoleID: role, Permission: string(p), ScopeType: "all"}); err != nil {
				return err
			}
		}
		u, err := q.CreateLocalUser(ctx, db.CreateLocalUserParams{
			Username: name, PasswordHash: sql.NullString{String: string(hash), Valid: true},
		})
		if err != nil {
			return err
		}
		id = u.ID
		return q.AddUserRole(ctx, db.AddUserRoleParams{UserID: u.ID, RoleID: role})
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return id
}

func (e *testEnv) loggedIn(name, password string) *client {
	e.t.Helper()
	c := e.client("10.0.0.1:1")
	if res := c.login(name, password); res.Code != http.StatusOK {
		e.t.Fatalf("login %s: %d %s", name, res.Code, res.Body)
	}
	return c
}

func (e *testEnv) auditActions() []string {
	var out []string
	for _, r := range e.auditRows() {
		out = append(out, r.Action)
	}
	return out
}

func decode[T any](t *testing.T, res response) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(res.Body.Bytes(), &v); err != nil {
		t.Fatalf("decoding %s: %v", res.Body, err)
	}
	return v
}

func TestSystemRoutesNeedConfigReload(t *testing.T) {
	e := newTestEnv(t)
	e.addUser("admin", "admin-password-1", true)
	e.addRoleUser("reader", "reader-password-1", rbac.DomainsView, rbac.AuditView)
	e.addRoleUser("reloader", "reloader-password-1", rbac.ConfigReload)
	anon := e.client("10.0.0.9:1")
	anon.fetchCSRF()

	tests := []struct {
		name         string
		who          *client
		method, path string
		want         int
		deniedAudit  bool
	}{
		{"anonymous list", anon, http.MethodGet, "/api/v1/system/secrets", http.StatusUnauthorized, false},
		{"anonymous reload", anon, http.MethodPost, "/api/v1/system/reload", http.StatusUnauthorized, false},
		{"reader list", e.loggedIn("reader", "reader-password-1"), http.MethodGet, "/api/v1/system/secrets", http.StatusForbidden, false},
		{"reader reload", e.loggedIn("reader", "reader-password-1"), http.MethodPost, "/api/v1/system/reload", http.StatusForbidden, true},
		{"reloader list", e.loggedIn("reloader", "reloader-password-1"), http.MethodGet, "/api/v1/system/secrets", http.StatusOK, false},
		{"reloader reload", e.loggedIn("reloader", "reloader-password-1"), http.MethodPost, "/api/v1/system/reload", http.StatusOK, false},
		{"admin list", e.loggedIn("admin", "admin-password-1"), http.MethodGet, "/api/v1/system/secrets", http.StatusOK, false},
		{"admin reload", e.loggedIn("admin", "admin-password-1"), http.MethodPost, "/api/v1/system/reload", http.StatusOK, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := len(e.auditRows())
			var body any
			if tt.method == http.MethodPost {
				body = struct{}{}
			}
			res := tt.who.do(tt.method, tt.path, body)
			if res.Code != tt.want {
				t.Fatalf("status %d, want %d: %s", res.Code, tt.want, res.Body)
			}
			if tt.want == http.StatusForbidden {
				if res.errorCode() != "forbidden" {
					t.Errorf("code %q, want forbidden", res.errorCode())
				}
				d := decode[gen.Error](t, res).Error.Details
				if d == nil || (*d)["permission"] != "config.reload" {
					t.Errorf("details %v, want permission config.reload", d)
				}
			}

			var added []string
			for _, r := range e.auditRows()[before:] {
				if r.Action != audit.ActionLogin {
					added = append(added, r.Action)
				}
			}
			switch {
			case tt.deniedAudit:
				if !slices.Equal(added, []string{audit.ActionPermissionDenied}) {
					t.Errorf("audit %v, want a single permission_denied", added)
				}
			case tt.method == http.MethodPost && tt.want == http.StatusOK:
				if !slices.Equal(added, []string{audit.ActionConfigReload}) {
					t.Errorf("audit %v, want a single config_reload", added)
				}
			default:
				if len(added) != 0 {
					t.Errorf("audit %v, want nothing (a refused read is only logged)", added)
				}
			}
		})
	}
}

func TestPermissionDeniedAudit(t *testing.T) {
	e := newTestEnv(t)
	e.addRoleUser("reader", "reader-password-1", rbac.DomainsView)
	c := e.loggedIn("reader", "reader-password-1")
	if res := c.do(http.MethodPost, "/api/v1/system/reload", struct{}{}); res.Code != http.StatusForbidden {
		t.Fatalf("status %d", res.Code)
	}

	rows := e.auditRows()
	row := rows[len(rows)-1]
	if row.Action != audit.ActionPermissionDenied || row.Username != "reader" || row.Result != audit.ResultFailure {
		t.Fatalf("audit row = %+v", row)
	}
	var detail map[string]any
	if err := json.Unmarshal([]byte(row.Detail), &detail); err != nil {
		t.Fatal(err)
	}
	if detail["attempted"] != "POST /api/v1/system/reload" || detail["permission"] != "config.reload" {
		t.Errorf("detail = %v", detail)
	}
	if lines := e.auditLines(); !strings.Contains(lines[len(lines)-1], "action=permission_denied") {
		t.Errorf("last AUDIT line = %q", lines[len(lines)-1])
	}
}

// TestRevokedPermissionAppliesAtOnce: permissions are resolved on every request, so removing a grant takes effect
// for a session that already exists.
func TestRevokedPermissionAppliesAtOnce(t *testing.T) {
	e := newTestEnv(t)
	e.addRoleUser("reloader", "reloader-password-1", rbac.ConfigReload)
	c := e.loggedIn("reloader", "reloader-password-1")
	if res := c.do(http.MethodGet, "/api/v1/system/secrets", nil); res.Code != http.StatusOK {
		t.Fatalf("before: %d", res.Code)
	}

	ctx := context.Background()
	if err := e.st.WithTx(ctx, func(q *db.Queries) error {
		roleID, err := q.GetRoleByName(ctx, "reloader-role")
		if err != nil {
			return err
		}
		return q.DeleteRoleGrants(ctx, roleID.ID)
	}); err != nil {
		t.Fatal(err)
	}
	if res := c.do(http.MethodGet, "/api/v1/system/secrets", nil); res.Code != http.StatusForbidden {
		t.Fatalf("after: %d, want 403", res.Code)
	}
}

func TestSecretsListNeverShowsValues(t *testing.T) {
	dir := t.TempDir()
	pwFile := filepath.Join(dir, "bind")
	if err := os.WriteFile(pwFile, []byte("bind-secret-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		secrets.VarLDAPBindPassword + "_FILE": pwFile,
		secrets.InstanceVar("PIHOLE1"):        "pihole1-secret-value",
	}
	e := newTestEnv(t, withSecrets(t, env))
	e.addUser("admin", "admin-password-1", true)
	ctx := context.Background()
	if err := e.st.WithTx(ctx, func(q *db.Queries) error {
		for _, n := range []string{"PIHOLE1", "PIHOLE2"} { // PIHOLE2 has no variable at all
			if _, err := q.CreateInstance(ctx, db.CreateInstanceParams{Name: strings.ToLower(n), BaseUrl: "http://" + n, EnvName: n, TlsMode: "verify", CreatedAt: 1}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	res := e.loggedIn("admin", "admin-password-1").do(http.MethodGet, "/api/v1/system/secrets", nil)
	if res.Code != http.StatusOK {
		t.Fatalf("status %d: %s", res.Code, res.Body)
	}
	for _, leak := range []string{"bind-secret-value", "pihole1-secret-value", pwFile} {
		if strings.Contains(res.Body.String(), leak) {
			t.Errorf("response contains %q", leak)
		}
	}

	got := map[string]gen.SecretStatus{}
	var order []string
	for _, s := range decode[gen.SecretList](t, res).Secrets {
		got[s.Name] = s
		order = append(order, s.Name)
	}
	src := func(s gen.SecretStatusSource) *gen.SecretStatusSource { return &s }
	want := map[string]gen.SecretStatus{
		secrets.VarSecretKey:           {Name: secrets.VarSecretKey, Kind: "master_key", Set: false},
		secrets.VarSessionKey:          {Name: secrets.VarSessionKey, Kind: "session_key", Set: true, Source: src("generated")},
		secrets.VarLDAPBindPassword:    {Name: secrets.VarLDAPBindPassword, Kind: "ldap_bind_password", Set: true, Source: src("file")},
		secrets.InstanceVar("PIHOLE1"): {Name: secrets.InstanceVar("PIHOLE1"), Kind: "instance_password", Set: true, Source: src("env")},
		secrets.InstanceVar("PIHOLE2"): {Name: secrets.InstanceVar("PIHOLE2"), Kind: "instance_password", Set: false},
	}
	if len(got) != len(want) {
		t.Errorf("listed %v, want %d secrets", order, len(want))
	}
	for name, w := range want {
		g, ok := got[name]
		if !ok {
			t.Errorf("%s isn't listed", name)
			continue
		}
		if g.Kind != w.Kind || g.Set != w.Set || (g.Source == nil) != (w.Source == nil) || (w.Source != nil && *g.Source != *w.Source) {
			t.Errorf("%s = %+v, want %+v", name, g, w)
		}
	}
}

// withSecrets loads a secrets manager from a fake environment.
func withSecrets(t *testing.T, env map[string]string) func(*Options) {
	t.Helper()
	return func(o *Options) {
		sec, err := secrets.Load(secrets.Options{
			DataDir: t.TempDir(),
			Getenv:  func(k string) string { return env[k] },
			Environ: func() []string {
				var out []string
				for k, v := range env {
					out = append(out, k+"="+v)
				}
				return out
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		o.Secrets = sec
	}
}

func TestReloadReportsChangesAndFailures(t *testing.T) {
	dir := t.TempDir()
	bindFile := filepath.Join(dir, "bind")
	pihole1 := filepath.Join(dir, "pihole1")
	write := func(path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(bindFile, "bind-old")
	write(pihole1, "pihole1-old")
	env := map[string]string{
		secrets.VarLDAPBindPassword + "_FILE":    bindFile,
		secrets.InstanceVar("PIHOLE1") + "_FILE": pihole1,
	}
	e := newTestEnv(t, withSecrets(t, env))
	e.addUser("admin", "admin-password-1", true)
	c := e.loggedIn("admin", "admin-password-1")

	reload := func() (gen.ReloadResult, response) {
		t.Helper()
		res := c.do(http.MethodPost, "/api/v1/system/reload", struct{}{})
		if res.Code != http.StatusOK {
			t.Fatalf("status %d: %s", res.Code, res.Body)
		}
		return decode[gen.ReloadResult](t, res), res
	}

	r, _ := reload()
	if len(r.Changed) != 0 || len(r.Failed) != 0 || r.SessionEnded {
		t.Fatalf("nothing changed, got %+v", r)
	}

	write(bindFile, "bind-new")
	if err := os.Remove(pihole1); err != nil {
		t.Fatal(err)
	}
	r, res := reload()
	if !slices.Equal(r.Changed, []string{secrets.VarLDAPBindPassword}) {
		t.Errorf("changed = %v", r.Changed)
	}
	if len(r.Failed) != 1 || r.Failed[0].Name != secrets.InstanceVar("PIHOLE1") {
		t.Fatalf("failed = %+v", r.Failed)
	}
	if r.SessionEnded {
		t.Error("session_ended is true, but the session key didn't change")
	}
	for _, leak := range []string{pihole1, bindFile, "bind-new", "bind-old", dir} {
		if strings.Contains(res.Body.String(), leak) {
			t.Errorf("response contains %q: %s", leak, res.Body)
		}
	}

	rows := e.auditRows()
	row := rows[len(rows)-1]
	if row.Action != audit.ActionConfigReload || row.Result != audit.ResultFailure {
		t.Fatalf("audit row = %+v", row)
	}
	for _, leak := range []string{pihole1, bindFile, "bind-new", dir} {
		if strings.Contains(row.Detail, leak) {
			t.Errorf("audit detail contains %q: %s", leak, row.Detail)
		}
	}
	if !strings.Contains(row.Detail, secrets.InstanceVar("PIHOLE1")) {
		t.Errorf("audit detail should name the failed secret: %s", row.Detail)
	}
}

func TestReloadOfSessionKeyEndsSessions(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "session-key")
	if err := os.WriteFile(keyFile, []byte(secrets.NewKey()), 0o600); err != nil {
		t.Fatal(err)
	}
	e := newTestEnv(t, withSecrets(t, map[string]string{secrets.VarSessionKey + "_FILE": keyFile}), func(o *Options) {
		o.Sessions = auth.NewSessions(o.Store, o.Secrets.SessionKey, auth.SessionOptions{})
	})
	e.addUser("admin", "admin-password-1", true)
	c := e.loggedIn("admin", "admin-password-1")

	if err := os.WriteFile(keyFile, []byte(secrets.NewKey()), 0o600); err != nil {
		t.Fatal(err)
	}
	res := c.do(http.MethodPost, "/api/v1/system/reload", struct{}{})
	if res.Code != http.StatusOK {
		t.Fatalf("status %d: %s", res.Code, res.Body)
	}
	if r := decode[gen.ReloadResult](t, res); !r.SessionEnded || !slices.Equal(r.Changed, []string{secrets.VarSessionKey}) {
		t.Errorf("result = %+v", r)
	}
	if res := c.do(http.MethodGet, "/api/v1/auth/session", nil); res.Code != http.StatusUnauthorized {
		t.Errorf("session after key change: %d, want 401", res.Code)
	}
}
