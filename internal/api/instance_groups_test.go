// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"net/http"
	"slices"
	"strconv"
	"testing"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
)

func groupPath(id int64) string { return "/api/v1/instance-groups/" + strconv.FormatInt(id, 10) }

func memberNamesOf(g gen.InstanceGroup) []string {
	var out []string
	for _, m := range g.Members {
		out = append(out, m.Name)
	}
	return out
}

func TestInstanceGroupLifecycle(t *testing.T) {
	e := newTestEnv(t, withInstances(t, nil))
	e.addUser("admin", "admin-password-1", true)
	c := e.loggedIn("admin", "admin-password-1")
	var ids []int64
	for _, name := range []string{"zeta", "alpha", "beta"} {
		res := c.do(http.MethodPost, "/api/v1/instances", gen.InstanceInput{Name: name, BaseUrl: "http://192.0.2.1"})
		mustStatus(t, res, http.StatusCreated)
		ids = append(ids, decode[gen.Instance](t, res).Id)
	}
	zeta, alpha, beta := ids[0], ids[1], ids[2]

	res := c.do(http.MethodPost, "/api/v1/instance-groups", gen.InstanceGroupInput{
		Name: "site", Mode: "mirrored", Members: []int64{zeta, alpha}, PrimaryInstanceId: ptr(zeta),
	})
	mustStatus(t, res, http.StatusCreated)
	g := decode[gen.InstanceGroup](t, res)
	if g.Mode != "mirrored" || g.PrimaryInstanceId == nil || *g.PrimaryInstanceId != zeta ||
		!slices.Equal(memberNamesOf(g), []string{"alpha", "zeta"}) || g.Members[0].Enabled {
		t.Fatalf("created %+v", g)
	}
	if got := decode[gen.InstanceGroup](t, c.do(http.MethodGet, groupPath(g.Id), nil)); got.Name != "site" || len(got.Members) != 2 {
		t.Errorf("get %+v", got)
	}

	res = c.do(http.MethodPut, groupPath(g.Id), gen.InstanceGroupInput{Name: "site", Mode: "independent", Members: []int64{beta}})
	mustStatus(t, res, http.StatusOK)
	if got := decode[gen.InstanceGroup](t, res); got.Mode != "independent" || got.PrimaryInstanceId != nil ||
		!slices.Equal(memberNamesOf(got), []string{"beta"}) {
		t.Errorf("updated %+v", got)
	}
	if rows := e.auditRows(); rows[len(rows)-1].Action != audit.ActionGroupUpdate {
		t.Errorf("last audit row %+v", rows[len(rows)-1])
	}

	list := decode[gen.InstanceGroupList](t, c.do(http.MethodGet, "/api/v1/instance-groups", nil))
	if len(list.Groups) != 1 || list.Groups[0].Id != g.Id {
		t.Errorf("list %+v", list)
	}
	// The grant editor's catalogue names the group.
	cat := decode[gen.RoleCatalogue](t, c.do(http.MethodGet, "/api/v1/roles/catalogue", nil))
	if len(cat.Groups) != 1 || cat.Groups[0].Name != "site" {
		t.Errorf("catalogue groups %+v", cat.Groups)
	}

	// An instance in a group can't be deleted until it leaves.
	res = c.do(http.MethodDelete, instancePath(beta, ""), nil)
	mustStatus(t, res, http.StatusConflict)

	mustStatus(t, c.do(http.MethodDelete, groupPath(g.Id), nil), http.StatusNoContent)
	mustStatus(t, c.do(http.MethodGet, groupPath(g.Id), nil), http.StatusNotFound)
	mustStatus(t, c.do(http.MethodDelete, instancePath(beta, ""), nil), http.StatusNoContent)
}

func TestInstanceGroupErrors(t *testing.T) {
	e := newTestEnv(t, withInstances(t, nil))
	e.addUser("admin", "admin-password-1", true)
	c := e.loggedIn("admin", "admin-password-1")
	res := c.do(http.MethodPost, "/api/v1/instances", gen.InstanceInput{Name: "pi1", BaseUrl: "http://192.0.2.1"})
	mustStatus(t, res, http.StatusCreated)
	pi1 := decode[gen.Instance](t, res).Id
	res = c.do(http.MethodPost, "/api/v1/instance-groups", gen.InstanceGroupInput{
		Name: "mirror", Mode: "mirrored", Members: []int64{pi1}, PrimaryInstanceId: ptr(pi1),
	})
	mustStatus(t, res, http.StatusCreated)
	mirror := decode[gen.InstanceGroup](t, res).Id

	tests := []struct {
		name   string
		method string
		path   string
		body   any
		status int
		code   string
		field  string
	}{
		{"bad mode", http.MethodPost, "/api/v1/instance-groups", gen.InstanceGroupInput{Name: "x", Mode: "cluster", Members: []int64{}}, 400, "validation_failed", "mode"},
		{"no primary", http.MethodPost, "/api/v1/instance-groups", gen.InstanceGroupInput{Name: "x", Mode: "mirrored", Members: []int64{pi1}}, 400, "validation_failed", "primary_instance_id"},
		{"unknown member", http.MethodPost, "/api/v1/instance-groups", gen.InstanceGroupInput{Name: "x", Mode: "independent", Members: []int64{42}}, 400, "validation_failed", "members"},
		{"name taken", http.MethodPost, "/api/v1/instance-groups", gen.InstanceGroupInput{Name: "Mirror", Mode: "independent", Members: []int64{}}, 409, "conflict", "name"},
		{"second mirrored group", http.MethodPost, "/api/v1/instance-groups", gen.InstanceGroupInput{Name: "x", Mode: "mirrored", Members: []int64{pi1}, PrimaryInstanceId: ptr(pi1)}, 409, "conflict", "members"},
		{"missing group", http.MethodPut, groupPath(99), gen.InstanceGroupInput{Name: "x", Mode: "independent", Members: []int64{}}, 404, "not_found", ""},
		{"bad id", http.MethodGet, "/api/v1/instance-groups/abc", nil, 400, "validation_failed", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := c.do(tc.method, tc.path, tc.body)
			if res.Code != tc.status || res.errorCode() != tc.code {
				t.Fatalf("%d %s, want %d %s", res.Code, res.Body, tc.status, tc.code)
			}
			if tc.field != "" && errorDetails(t, res)["field"] != tc.field {
				t.Errorf("details %v", errorDetails(t, res))
			}
		})
	}

	t.Run("invariant 6", func(t *testing.T) {
		res := c.do(http.MethodPost, "/api/v1/roles", gen.RoleCreate{
			Name: "watchers", Grants: &[]gen.Grant{{Permission: string(rbac.DriftView), Scope: "group", Id: ptr(mirror)}},
		})
		mustStatus(t, res, http.StatusCreated)
		res = c.do(http.MethodPut, groupPath(mirror), gen.InstanceGroupInput{Name: "mirror", Mode: "independent", Members: []int64{pi1}})
		if res.Code != http.StatusConflict || res.errorCode() != "invariant_violated" {
			t.Fatalf("%d %s", res.Code, res.Body)
		}
		res = c.do(http.MethodDelete, groupPath(mirror), nil)
		if res.Code != http.StatusConflict || res.errorCode() != "conflict" {
			t.Fatalf("delete: %d %s", res.Code, res.Body)
		}
		if roles, _ := errorDetails(t, res)["roles"].([]any); len(roles) != 1 || roles[0] != "watchers" {
			t.Errorf("details %v", errorDetails(t, res))
		}
	})
}

func TestInstanceGroupRoutesNeedInstancesManage(t *testing.T) {
	e := newTestEnv(t, withInstances(t, nil))
	e.addUser("admin", "admin-password-1", true)
	e.addRoleUser("reader", "reader-password-1", rbac.DomainsView)
	admin := e.loggedIn("admin", "admin-password-1")
	res := admin.do(http.MethodPost, "/api/v1/instance-groups", gen.InstanceGroupInput{Name: "site", Mode: "independent", Members: []int64{}})
	mustStatus(t, res, http.StatusCreated)
	id := decode[gen.InstanceGroup](t, res).Id
	reader := e.loggedIn("reader", "reader-password-1")

	input := gen.InstanceGroupInput{Name: "x", Mode: "independent", Members: []int64{}}
	for _, tt := range []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, "/api/v1/instance-groups", nil},
		{http.MethodPost, "/api/v1/instance-groups", input},
		{http.MethodGet, groupPath(id), nil},
		{http.MethodPut, groupPath(id), input},
		{http.MethodDelete, groupPath(id), nil},
	} {
		before := len(e.auditRows())
		res := reader.do(tt.method, tt.path, tt.body)
		if res.Code != http.StatusForbidden || errorDetails(t, res)["permission"] != "instances.manage" {
			t.Errorf("%s %s: %d %s", tt.method, tt.path, res.Code, res.Body)
			continue
		}
		if added := e.auditRows()[before:]; isSafeMethod(tt.method) != (len(added) == 0) {
			t.Errorf("%s %s: %d audit rows", tt.method, tt.path, len(added))
		}
	}
}
