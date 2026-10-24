// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/auth/ldaptest"
	"github.com/Kate-0713/pihole-rbac/internal/loginsettings"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
)

// testSecrets gives the login settings a master key and no environment override.
type testSecrets struct{ cipher *secrets.Cipher }

func (testSecrets) LDAPBindPassword() (secrets.Value, bool) { return secrets.Value{}, false }
func (s testSecrets) Cipher() *secrets.Cipher               { return s.cipher }

// newDirectoryEnv is a server whose logins go through the login settings service, with a fake directory to point
// it at.
func newDirectoryEnv(t *testing.T) (*testEnv, ldaptest.Fixture, *ldaptest.Server) {
	t.Helper()
	dir, err := ldaptest.Start("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dir.Close() })
	f := ldaptest.Example(dir)
	c, err := secrets.NewCipher(bytes.Repeat([]byte{5}, secrets.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	e := newTestEnv(t, func(o *Options) {
		svc := &loginsettings.Service{
			Store: o.Store, Audit: o.Audit, Secrets: testSecrets{c}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		}
		if err := svc.Load(context.Background()); err != nil {
			t.Fatal(err)
		}
		o.LoginSettings = svc
		o.Auth = svc.Authenticator()
	})
	return e, f, dir
}

func ldapInput(f ldaptest.Fixture, password string) gen.LDAPSettingsInput {
	in := gen.LDAPSettingsInput{Url: f.URL, BindDn: f.BindDN, BaseDn: f.BaseDN, UserFilter: f.UserFilter}
	if password != "" {
		in.BindPassword = &password
	}
	return in
}

func TestLDAPSettingsAPI(t *testing.T) {
	e, f, _ := newDirectoryEnv(t)
	e.addUser("admin", "admin-password-1", true)
	e.mapGroup(f.AdminGroup, adminRoleID)
	c := e.loggedIn("admin", "admin-password-1")

	v := decode[gen.LDAPSettingsView](t, c.do(http.MethodGet, "/api/v1/settings/ldap", nil))
	if v.Settings != nil || v.Enabled || v.BindPassword.Source != "none" || !v.CanStorePassword ||
		v.BindPassword.Variable != secrets.VarLDAPBindPassword {
		t.Errorf("before saving: %+v", v)
	}
	if m := decode[gen.LoginMethods](t, c.do(http.MethodGet, "/api/v1/settings/auth", nil)); fmt.Sprint(m.Methods) != "[local]" {
		t.Errorf("default methods: %v", m.Methods)
	}

	// Turning LDAP on before it is set up is refused.
	res := c.do(http.MethodPut, "/api/v1/settings/auth", gen.LoginMethods{Methods: []gen.LoginMethodsMethods{"local", "ldap"}})
	if res.Code != http.StatusBadRequest || errorDetails(t, res)["field"] != "methods" {
		t.Errorf("LDAP on without settings: %d %s", res.Code, res.Body)
	}

	res = c.do(http.MethodPut, "/api/v1/settings/ldap", ldapInput(f, f.BindPassword))
	mustStatus(t, res, http.StatusOK)
	if strings.Contains(res.Body.String(), f.BindPassword) {
		t.Fatal("the bind password is in the response")
	}
	v = decode[gen.LDAPSettingsView](t, res)
	if v.Settings == nil || v.Settings.Url != f.URL || v.Settings.TlsMode != "verify" || v.BindPassword.Source != "stored" ||
		v.BindPassword.UpdatedBy == nil || *v.BindPassword.UpdatedBy != "admin" {
		t.Errorf("after saving: %+v", v)
	}

	// The confirmation rule: a new address needs the password again.
	moved := ldapInput(f, "")
	moved.Url = "ldap://127.0.0.1:9"
	res = c.do(http.MethodPut, "/api/v1/settings/ldap", moved)
	if res.Code != http.StatusBadRequest || errorDetails(t, res)["field"] != "bind_password" {
		t.Errorf("new address without the password: %d %s", res.Code, res.Body)
	}

	mustStatus(t, c.do(http.MethodPut, "/api/v1/settings/auth", gen.LoginMethods{Methods: []gen.LoginMethodsMethods{"ldap", "local"}}), http.StatusOK)
	if res := e.client("10.0.0.2:1").login("lucy", f.Password("lucy")); res.Code != http.StatusOK {
		t.Fatalf("LDAP login once enabled: %d %s", res.Code, res.Body)
	}
	res = c.do(http.MethodPut, "/api/v1/settings/auth", gen.LoginMethods{Methods: []gen.LoginMethodsMethods{"ldap"}})
	if res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "Local login must stay on") {
		t.Errorf("LDAP only: %d %s", res.Code, res.Body)
	}

	// While LDAP is on, settings that don't bind are refused with the reason, and nothing changes.
	broken := ldapInput(f, "")
	broken.BindDn = "cn=nobody,dc=example,dc=local"
	res = c.do(http.MethodPut, "/api/v1/settings/ldap", broken)
	if res.Code != http.StatusBadGateway || res.errorCode() != "ldap_failed" || errorDetails(t, res)["detail"] == nil ||
		!strings.Contains(res.Body.String(), "refused the bind DN or password") {
		t.Errorf("settings that don't bind: %d %s", res.Code, res.Body)
	}
	if v := decode[gen.LDAPSettingsView](t, c.do(http.MethodGet, "/api/v1/settings/ldap", nil)); v.Settings.BindDn != f.BindDN || !v.Enabled {
		t.Errorf("a refused save changed something: %+v", v.Settings)
	}

	res = c.do(http.MethodPut, "/api/v1/settings/ldap", gen.LDAPSettingsInput{Url: "http://x", BindDn: f.BindDN, BaseDn: f.BaseDN, UserFilter: f.UserFilter})
	if res.Code != http.StatusBadRequest || errorDetails(t, res)["field"] != "url" {
		t.Errorf("bad URL: %d %s", res.Code, res.Body)
	}
	noSecretsAudited(t, e, f.BindPassword)
	if n := slices.Index(e.auditActions(), "settings_update"); n < 0 {
		t.Errorf("no settings_update row: %v", e.auditActions())
	}
}

func TestLDAPToolsAPI(t *testing.T) {
	e, f, _ := newDirectoryEnv(t)
	e.addUser("admin", "admin-password-1", true)
	e.addRoleUser("roles", "roles-password-1", rbac.RolesManage)
	e.addRoleUser("settings", "settings-pass-1", rbac.SettingsManage)
	admin := e.loggedIn("admin", "admin-password-1")
	lead := e.loggedIn("roles", "roles-password-1")

	res := lead.do(http.MethodPost, "/api/v1/ldap/test-user", gen.LDAPUserTestInput{Username: "lucy"})
	if res.Code != http.StatusConflict || !strings.Contains(res.Body.String(), "save the LDAP settings first") {
		t.Errorf("test-user before any settings: %d %s", res.Code, res.Body)
	}
	mustStatus(t, admin.do(http.MethodPut, "/api/v1/settings/ldap", ldapInput(f, f.BindPassword)), http.StatusOK)

	// Map the staff group to the starter-like role the lead holds, and look the group up as part of it.
	leadRole := roleNamed(t, decode[gen.RoleList](t, admin.do(http.MethodGet, "/api/v1/roles", nil)).Roles, "roles-role").Id
	res = lead.do(http.MethodPost, rolePath(leadRole, "/ldap-groups"), gen.LDAPGroupInput{GroupDn: f.StaffGroup})
	mustStatus(t, res, http.StatusCreated)
	created := decode[gen.LDAPMappingCreated](t, res)
	if created.Check == nil || !created.Check.Exists || created.Check.Members != 2 || created.Mapping.GroupDn != f.StaffGroup {
		t.Errorf("mapping created: %+v", created)
	}
	res = lead.do(http.MethodPost, rolePath(leadRole, "/ldap-groups"), gen.LDAPGroupInput{GroupDn: "cn=later,ou=groups,dc=example,dc=local"})
	mustStatus(t, res, http.StatusCreated)
	if later := decode[gen.LDAPMappingCreated](t, res); later.Check == nil || later.Check.Exists {
		t.Errorf("a group that doesn't exist yet is saved, with a warning: %+v", later)
	}
	// The lead can't map the admin role: it holds more than they do.
	if res := lead.do(http.MethodPost, rolePath(adminRoleID, "/ldap-groups"), gen.LDAPGroupInput{GroupDn: f.AdminGroup}); res.Code != http.StatusForbidden {
		t.Errorf("mapping a role above you: %d %s", res.Code, res.Body)
	}
	list := decode[gen.LDAPMappingList](t, lead.do(http.MethodGet, rolePath(leadRole, "/ldap-groups"), nil)).Mappings
	if len(list) != 2 {
		t.Fatalf("mappings: %+v", list)
	}

	test := decode[gen.LDAPUserTest](t, lead.do(http.MethodPost, "/api/v1/ldap/test-user", gen.LDAPUserTestInput{Username: " Mark "}))
	if !test.Found || test.Username != "mark" || *test.Dn != f.Users["mark"] || len(test.Groups) != 1 ||
		len(test.Mappings) != 1 || test.Mappings[0].Role.Name != "roles-role" || len(test.Roles) != 1 ||
		!slices.Equal(test.Permissions.Global, []string{"roles.manage"}) {
		t.Errorf("mark: %+v", test)
	}
	if nina := decode[gen.LDAPUserTest](t, lead.do(http.MethodPost, "/api/v1/ldap/test-user", gen.LDAPUserTestInput{Username: "nina"})); !nina.Found || len(nina.Roles) != 0 {
		t.Errorf("nina, in no mapped group: %+v", nina)
	}
	if ghost := decode[gen.LDAPUserTest](t, lead.do(http.MethodPost, "/api/v1/ldap/test-user", gen.LDAPUserTestInput{Username: "admin"})); ghost.Found || !ghost.LocalAccount {
		t.Errorf("a local username: %+v", ghost)
	}

	check := decode[gen.LDAPGroupCheck](t, lead.do(http.MethodPost, "/api/v1/ldap/check-group", gen.LDAPGroupInput{GroupDn: f.EmptyGroup}))
	if !check.Exists || check.Members != 0 {
		t.Errorf("check-group: %+v", check)
	}

	// A mapping ID under the wrong role is not found; under its own role it goes.
	if res := lead.do(http.MethodDelete, rolePath(adminRoleID, fmt.Sprintf("/ldap-groups/%d", list[0].Id)), nil); res.Code != http.StatusNotFound {
		t.Errorf("mapping under another role: %d", res.Code)
	}
	mustStatus(t, lead.do(http.MethodDelete, rolePath(leadRole, fmt.Sprintf("/ldap-groups/%d", list[0].Id)), nil), http.StatusNoContent)

	for _, want := range []string{"ldap_mapping_add", "ldap_mapping_remove", "ldap_mapping_check"} {
		if !slices.Contains(e.auditActions(), want) {
			t.Errorf("no %s row: %v", want, e.auditActions())
		}
	}

	// Each half of the page needs its own permission.
	settings := e.loggedIn("settings", "settings-pass-1")
	if res := settings.do(http.MethodPost, "/api/v1/ldap/test-user", gen.LDAPUserTestInput{Username: "lucy"}); res.Code != http.StatusForbidden {
		t.Errorf("settings.manage using the tools: %d", res.Code)
	}
	if res := lead.do(http.MethodGet, "/api/v1/settings/ldap", nil); res.Code != http.StatusForbidden {
		t.Errorf("roles.manage reading the LDAP settings: %d", res.Code)
	}
	mustStatus(t, settings.do(http.MethodGet, "/api/v1/settings/ldap", nil), http.StatusOK)
}

func TestLDAPDirectoryDown(t *testing.T) {
	e, f, dir := newDirectoryEnv(t)
	e.addUser("admin", "admin-password-1", true)
	c := e.loggedIn("admin", "admin-password-1")
	mustStatus(t, c.do(http.MethodPut, "/api/v1/settings/ldap", ldapInput(f, f.BindPassword)), http.StatusOK)
	dir.Close()

	res := c.do(http.MethodPost, "/api/v1/ldap/test-user", gen.LDAPUserTestInput{Username: "lucy"})
	if res.Code != http.StatusBadGateway || res.errorCode() != "ldap_failed" || !strings.Contains(res.Body.String(), "couldn't be reached") {
		t.Errorf("test-user with the directory down: %d %s", res.Code, res.Body)
	}
	res = c.do(http.MethodPut, "/api/v1/settings/auth", gen.LoginMethods{Methods: []gen.LoginMethodsMethods{"local", "ldap"}})
	if res.Code != http.StatusBadGateway {
		t.Errorf("turning LDAP on with the directory down: %d %s", res.Code, res.Body)
	}
	// Mapping still works; the check says why it couldn't look.
	res = c.do(http.MethodPost, rolePath(adminRoleID, "/ldap-groups"), gen.LDAPGroupInput{GroupDn: f.AdminGroup})
	mustStatus(t, res, http.StatusCreated)
	if m := decode[gen.LDAPMappingCreated](t, res); m.Check != nil || m.CheckError == nil {
		t.Errorf("mapping with the directory down: %+v", m)
	}
}
