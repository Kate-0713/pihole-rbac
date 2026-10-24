// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"database/sql"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

func rolePath(id int64, suffix string) string { return fmt.Sprintf("/api/v1/roles/%d%s", id, suffix) }

func grantAll(p rbac.Permission) gen.Grant {
	return gen.Grant{Permission: string(p), Scope: gen.GrantScopeAll}
}

func grantOn(p rbac.Permission, scope gen.GrantScope, id int64) gen.Grant {
	return gen.Grant{Permission: string(p), Scope: scope, Id: &id}
}

func roleNamed(t *testing.T, roles []gen.Role, name string) gen.Role {
	t.Helper()
	i := slices.IndexFunc(roles, func(r gen.Role) bool { return r.Name == name })
	if i < 0 {
		t.Fatalf("no role %q in %v", name, roles)
	}
	return roles[i]
}

func TestListRoles(t *testing.T) {
	e := newTestEnv(t)
	e.addUser("admin", "admin-password-1", true)
	e.addRoleUser("staffer", "staffer-password", rbac.DomainsView, rbac.ClientsView)
	c := e.loggedIn("admin", "admin-password-1")

	res := c.do(http.MethodGet, "/api/v1/roles", nil)
	if res.Code != http.StatusOK {
		t.Fatalf("GET /roles: %d %s", res.Code, res.Body)
	}
	roles := decode[gen.RoleList](t, res).Roles
	if names := []string{roles[0].Name, roles[1].Name}; !slices.Equal(names, []string{"admin", "staffer-role"}) {
		t.Errorf("roles sorted by name: %v", names)
	}
	admin := roleNamed(t, roles, "admin")
	if !admin.Builtin || len(admin.Grants) != len(rbac.Catalogue()) || !slices.Equal(admin.Users, []string{"admin"}) || !admin.Manageable {
		t.Errorf("admin role: %+v", admin)
	}
	staff := roleNamed(t, roles, "staffer-role")
	want := []gen.Grant{grantAll(rbac.ClientsView), grantAll(rbac.DomainsView)}
	if !slices.EqualFunc(staff.Grants, want, grantEqual) || staff.Builtin || len(staff.LdapGroups) != 0 {
		t.Errorf("staff role: %+v", staff)
	}

	// One role reads the same.
	one := decode[gen.Role](t, c.do(http.MethodGet, rolePath(staff.Id, ""), nil))
	if one.Name != staff.Name || !slices.EqualFunc(one.Grants, staff.Grants, grantEqual) || !slices.Equal(one.Users, []string{"staffer"}) {
		t.Errorf("GET /roles/%d: %+v", staff.Id, one)
	}
	if res := c.do(http.MethodGet, rolePath(99, ""), nil); res.Code != http.StatusNotFound || res.errorCode() != "not_found" {
		t.Errorf("missing role: %d %s", res.Code, res.Body)
	}
}

func grantEqual(a, b gen.Grant) bool {
	return a.Permission == b.Permission && a.Scope == b.Scope && (a.Id == nil) == (b.Id == nil) && (a.Id == nil || *a.Id == *b.Id)
}

// TestRolesReadableWithUsersManage: users.manage is enough to read roles, not to change them; with neither
// permission the refusal names both.
func TestRolesReadableWithUsersManage(t *testing.T) {
	e := newTestEnv(t)
	e.addUser("admin", "admin-password-1", true)
	e.addRoleUser("hr", "hr-password-123", rbac.UsersManage)
	e.addRoleUser("auditor", "auditor-password", rbac.AuditView)

	hr := e.loggedIn("hr", "hr-password-123")
	if res := hr.do(http.MethodGet, "/api/v1/roles", nil); res.Code != http.StatusOK {
		t.Fatalf("users.manage reading roles: %d %s", res.Code, res.Body)
	}
	roles := decode[gen.RoleList](t, hr.do(http.MethodGet, "/api/v1/roles", nil)).Roles
	if roleNamed(t, roles, "admin").Manageable || !roleNamed(t, roles, "hr-role").Manageable {
		t.Errorf("manageable should follow the caller's grants: %+v", roles)
	}
	res := hr.do(http.MethodPost, "/api/v1/roles", gen.RoleCreate{Name: "new"})
	if res.Code != http.StatusForbidden || !strings.Contains(res.Body.String(), `"permission":"roles.manage"`) {
		t.Errorf("users.manage creating a role: %d %s", res.Code, res.Body)
	}
	if res := hr.do(http.MethodGet, "/api/v1/roles/catalogue", nil); res.Code != http.StatusForbidden {
		t.Errorf("users.manage reading the catalogue: %d", res.Code)
	}

	aud := e.loggedIn("auditor", "auditor-password")
	res = aud.do(http.MethodGet, "/api/v1/roles", nil)
	if res.Code != http.StatusForbidden || !strings.Contains(res.Body.String(), `"permission":"roles.manage|users.manage"`) ||
		!strings.Contains(res.Body.String(), "roles.manage or users.manage") {
		t.Errorf("neither permission: %d %s", res.Code, res.Body)
	}
}

func TestRoleLifecycle(t *testing.T) {
	e := newTestEnv(t)
	e.topology()
	e.addUser("admin", "admin-password-1", true)
	c := e.loggedIn("admin", "admin-password-1")

	desc := "Site A operators"
	res := c.do(http.MethodPost, "/api/v1/roles", gen.RoleCreate{
		Name: "  operators  ", Description: &desc,
		Grants: &[]gen.Grant{
			grantOn(rbac.DomainsEdit, gen.GrantScopeInstance, 1),
			grantOn(rbac.DriftView, gen.GrantScopeGroup, 1),
			grantAll(rbac.DomainsView),
			grantAll(rbac.DomainsView), // duplicates are dropped
		},
	})
	if res.Code != http.StatusCreated {
		t.Fatalf("POST /roles: %d %s", res.Code, res.Body)
	}
	role := decode[gen.Role](t, res)
	want := []gen.Grant{
		grantOn(rbac.DomainsEdit, gen.GrantScopeInstance, 1),
		grantAll(rbac.DomainsView),
		grantOn(rbac.DriftView, gen.GrantScopeGroup, 1),
	}
	if role.Name != "operators" || role.Description != desc || !role.Manageable {
		t.Errorf("created role: %+v", role)
	}
	if !slices.EqualFunc(role.Grants, want, grantEqual) {
		t.Errorf("grants %+v, want %+v", role.Grants, want)
	}

	res = c.do(http.MethodPut, rolePath(role.Id, ""), gen.RoleInput{Name: "site-a"})
	if res.Code != http.StatusOK || decode[gen.Role](t, res).Name != "site-a" || decode[gen.Role](t, res).Description != "" {
		t.Errorf("rename: %d %s", res.Code, res.Body)
	}

	res = c.do(http.MethodPut, rolePath(role.Id, "/grants"), gen.GrantsInput{Grants: []gen.Grant{grantAll(rbac.QueryLogView)}})
	if res.Code != http.StatusOK || !slices.EqualFunc(decode[gen.Role](t, res).Grants, []gen.Grant{grantAll(rbac.QueryLogView)}, grantEqual) {
		t.Errorf("set grants: %d %s", res.Code, res.Body)
	}

	if res := c.do(http.MethodDelete, rolePath(role.Id, ""), nil); res.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", res.Code, res.Body)
	}
	if res := c.do(http.MethodGet, rolePath(role.Id, ""), nil); res.Code != http.StatusNotFound {
		t.Errorf("deleted role still there: %d", res.Code)
	}
	if got := e.auditActions(); !slices.Equal(got[len(got)-4:], []string{"role_create", "role_update", "role_grants", "role_delete"}) {
		t.Errorf("audit actions %v", got)
	}
}

func TestRoleRefusals(t *testing.T) {
	e := newTestEnv(t)
	e.topology()
	e.addUser("admin", "admin-password-1", true)
	e.addRoleUser("staffer", "staffer-password", rbac.DomainsView)
	c := e.loggedIn("admin", "admin-password-1")
	staffRole := int64(2)

	tests := []struct {
		name   string
		method string
		path   string
		body   any
		status int
		code   string
		says   string
	}{
		{"unknown scope", http.MethodPost, "/api/v1/roles",
			gen.RoleCreate{Name: "x", Grants: &[]gen.Grant{{Permission: "domains.view", Scope: "planet"}}},
			http.StatusBadRequest, "validation_failed", "all, group or instance"},
		{"instance scope without an id", http.MethodPost, "/api/v1/roles",
			gen.RoleCreate{Name: "x", Grants: &[]gen.Grant{{Permission: "domains.view", Scope: gen.GrantScopeInstance}}},
			http.StatusBadRequest, "validation_failed", "needs the id"},
		{"scope all with an id", http.MethodPost, "/api/v1/roles",
			gen.RoleCreate{Name: "x", Grants: &[]gen.Grant{grantOn(rbac.DomainsView, gen.GrantScopeAll, 1)}},
			http.StatusBadRequest, "validation_failed", "has no id"},
		{"unknown permission", http.MethodPost, "/api/v1/roles",
			gen.RoleCreate{Name: "x", Grants: &[]gen.Grant{{Permission: "domains.burn", Scope: gen.GrantScopeAll}}},
			http.StatusBadRequest, "validation_failed", "isn't a known permission"},
		{"no such instance", http.MethodPost, "/api/v1/roles",
			gen.RoleCreate{Name: "x", Grants: &[]gen.Grant{grantOn(rbac.DomainsView, gen.GrantScopeInstance, 9)}},
			http.StatusBadRequest, "validation_failed", "no instance with ID 9"},
		{"global permission on an instance", http.MethodPost, "/api/v1/roles",
			gen.RoleCreate{Name: "x", Grants: &[]gen.Grant{grantOn(rbac.UsersManage, gen.GrantScopeInstance, 1)}},
			http.StatusConflict, "invariant_violated", "can't be granted on a single instance"},
		{"drift on an independent group", http.MethodPost, "/api/v1/roles",
			gen.RoleCreate{Name: "x", Grants: &[]gen.Grant{grantOn(rbac.DriftView, gen.GrantScopeGroup, 2)}},
			http.StatusConflict, "invariant_violated", ""},
		{"empty name", http.MethodPost, "/api/v1/roles", gen.RoleCreate{Name: "   "},
			http.StatusBadRequest, "validation_failed", "1-64 characters"},
		{"name taken, ignoring case", http.MethodPost, "/api/v1/roles", gen.RoleCreate{Name: "STAFFER-ROLE"},
			http.StatusConflict, "conflict", "already a role"},
		{"renaming the builtin role", http.MethodPut, rolePath(adminRoleID, ""), gen.RoleInput{Name: "boss"},
			http.StatusConflict, "invariant_violated", "builtin admin role"},
		{"changing the builtin role's grants", http.MethodPut, rolePath(adminRoleID, "/grants"), gen.GrantsInput{Grants: []gen.Grant{}},
			http.StatusConflict, "invariant_violated", "builtin admin role"},
		{"deleting a role in use", http.MethodDelete, rolePath(staffRole, ""), nil,
			http.StatusConflict, "invariant_violated", "still in use"},
		{"no such role", http.MethodPut, rolePath(99, "/grants"), gen.GrantsInput{Grants: []gen.Grant{}},
			http.StatusNotFound, "not_found", ""},
		{"a path id that isn't a number", http.MethodGet, "/api/v1/roles/abc", nil,
			http.StatusBadRequest, "validation_failed", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := c.do(tt.method, tt.path, tt.body)
			if res.Code != tt.status || res.errorCode() != tt.code || !strings.Contains(res.Body.String(), tt.says) {
				t.Errorf("%d %s, want %d %s containing %q", res.Code, res.Body, tt.status, tt.code, tt.says)
			}
		})
	}
	if res := c.do(http.MethodGet, rolePath(staffRole, ""), nil); decode[gen.Role](t, res).Name != "staffer-role" {
		t.Errorf("a refused change left the role changed: %s", res.Body)
	}
}

// TestRoleNoEscalation: someone with roles.manage can only grant what they hold, and can't touch a role holding more.
func TestRoleNoEscalation(t *testing.T) {
	e := newTestEnv(t)
	e.topology()
	e.addUser("admin", "admin-password-1", true)
	e.addGrantUser("lead", "lead-password-1",
		db.InsertGrantParams{Permission: string(rbac.RolesManage), ScopeType: "all"},
		db.InsertGrantParams{Permission: string(rbac.DomainsView), ScopeType: "instance", InstanceID: sql.NullInt64{Int64: 1, Valid: true}},
	)
	c := e.loggedIn("lead", "lead-password-1")

	res := c.do(http.MethodPost, "/api/v1/roles", gen.RoleCreate{Name: "more", Grants: &[]gen.Grant{grantAll(rbac.DomainsView)}})
	if res.Code != http.StatusForbidden || !strings.Contains(res.Body.String(), "domains.view on all") {
		t.Errorf("granting beyond own scope: %d %s", res.Code, res.Body)
	}
	res = c.do(http.MethodPost, "/api/v1/roles", gen.RoleCreate{Name: "same", Grants: &[]gen.Grant{grantOn(rbac.DomainsView, gen.GrantScopeInstance, 1)}})
	if res.Code != http.StatusCreated {
		t.Errorf("granting what they hold: %d %s", res.Code, res.Body)
	}
	if res := c.do(http.MethodDelete, rolePath(adminRoleID, ""), nil); res.Code != http.StatusConflict {
		t.Errorf("deleting the admin role: %d %s", res.Code, res.Body)
	}
	if !slices.Contains(e.auditActions(), "permission_denied") {
		t.Errorf("a refused grant is audited as permission_denied: %v", e.auditActions())
	}
}

// TestRoleGrantsNeedConfirmation: taking away your own last roles.manage asks first, and goes ahead with confirm=true.
func TestRoleGrantsNeedConfirmation(t *testing.T) {
	e := newTestEnv(t)
	e.addUser("admin", "admin-password-1", true)
	e.addRoleUser("lead", "lead-password-1", rbac.RolesManage, rbac.DomainsView)
	c := e.loggedIn("lead", "lead-password-1")
	leadRole := int64(2)

	body := gen.GrantsInput{Grants: []gen.Grant{grantAll(rbac.DomainsView)}}
	res := c.do(http.MethodPut, rolePath(leadRole, "/grants"), body)
	if res.Code != http.StatusConflict || res.errorCode() != "confirmation_required" || !strings.Contains(res.Body.String(), `"would_lose":["roles.manage"]`) {
		t.Fatalf("losing own roles.manage: %d %s", res.Code, res.Body)
	}
	for _, q := range []string{"?confirm=false", "?confirm=nope"} {
		if res := c.do(http.MethodPut, rolePath(leadRole, "/grants"+q), body); res.Code == http.StatusOK {
			t.Errorf("%s went ahead", q)
		}
	}
	if res := c.do(http.MethodPut, rolePath(leadRole, "/grants?confirm=true"), body); res.Code != http.StatusOK {
		t.Fatalf("confirmed: %d %s", res.Code, res.Body)
	}
	// Permissions are worked out per request, so the same session has lost roles.manage at once.
	if res := c.do(http.MethodGet, "/api/v1/roles", nil); res.Code != http.StatusForbidden {
		t.Errorf("after losing roles.manage: %d", res.Code)
	}
}

func TestRoleCatalogue(t *testing.T) {
	e := newTestEnv(t)
	e.topology()
	e.addUser("admin", "admin-password-1", true)
	c := e.loggedIn("admin", "admin-password-1")

	res := c.do(http.MethodGet, "/api/v1/roles/catalogue", nil)
	if res.Code != http.StatusOK {
		t.Fatalf("GET /roles/catalogue: %d %s", res.Code, res.Body)
	}
	cat := decode[gen.RoleCatalogue](t, res)
	if len(cat.Permissions) != len(rbac.Catalogue()) {
		t.Errorf("%d permissions, want %d", len(cat.Permissions), len(rbac.Catalogue()))
	}
	classes := map[string]gen.PermissionInfoClass{}
	for _, p := range cat.Permissions {
		classes[p.Name] = p.Class
		if p.Description == "" {
			t.Errorf("%s has no description", p.Name)
		}
	}
	if classes["domains.edit"] != "instance" || classes["drift.view"] != "group" || classes["users.manage"] != "global" {
		t.Errorf("classes %v", classes)
	}
	if len(cat.Instances) != 3 || cat.Instances[0].Name != "A" {
		t.Errorf("instances %+v", cat.Instances)
	}
	if len(cat.Groups) != 2 || cat.Groups[0].Name != "labs" || cat.Groups[0].Mode != "independent" || cat.Groups[1].Mode != "mirrored" {
		t.Errorf("groups %+v", cat.Groups)
	}
}
