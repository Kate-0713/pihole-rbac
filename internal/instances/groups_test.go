// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package instances

import (
	"database/sql"
	"slices"
	"testing"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// threeInstances adds pi1, pi2 and pi3 (disabled; groups don't need them enabled) and returns their IDs.
func (e *svcEnv) threeInstances() (int64, int64, int64) {
	e.t.Helper()
	a := e.create("pi1", "", "http://192.0.2.1")
	b := e.create("pi2", "", "http://192.0.2.2")
	c := e.create("pi3", "", "http://192.0.2.3")
	return a.ID, b.ID, c.ID
}

func (e *svcEnv) createGroup(in GroupInput) Group {
	e.t.Helper()
	g, err := e.svc.CreateGroup(e.ctx, e.admin, in)
	if err != nil {
		e.t.Fatalf("CreateGroup %s: %v", in.Name, err)
	}
	return g
}

// grantOnGroup gives a new role the permission p on group g.
func (e *svcEnv) grantOnGroup(role string, p rbac.Permission, g int64) {
	e.t.Helper()
	e.tx(func(q *db.Queries) error {
		id, err := q.CreateRole(e.ctx, db.CreateRoleParams{Name: role, CreatedAt: 1})
		if err != nil {
			return err
		}
		return q.InsertGrant(e.ctx, db.InsertGrantParams{
			RoleID: id, Permission: string(p), ScopeType: "group", GroupID: sql.NullInt64{Int64: g, Valid: true},
		})
	})
}

func TestCreateGroup(t *testing.T) {
	e := newSvcEnv(t)
	a, b, c := e.threeInstances()

	g := e.createGroup(GroupInput{Name: " site A ", Mode: rbac.Mirrored, Primary: b, Members: []int64{c, b}})
	if g.Name != "site A" || g.Mode != rbac.Mirrored || g.Primary != b || !slices.Equal(g.Members, []int64{b, c}) {
		t.Fatalf("created %+v", g)
	}
	got, err := e.svc.GetGroup(e.ctx, g.ID)
	if err != nil || got.Name != g.Name || got.Primary != b || !slices.Equal(got.Members, g.Members) || !got.CreatedAt.Equal(g.CreatedAt) {
		t.Fatalf("GetGroup = %+v, %v; want %+v", got, err, g)
	}
	row := e.lastAudit()
	d := detail(t, row)
	if row.Action != audit.ActionGroupCreate || row.Target != "group:site A" || row.Result != audit.ResultSuccess ||
		d["primary"] != "pi2" || d["mode"] != "mirrored" || !slices.Equal(anyStrings(d["members"]), []string{"pi2", "pi3"}) {
		t.Errorf("audit row %+v, detail %v", row, d)
	}

	lab := e.createGroup(GroupInput{Name: "lab", Mode: rbac.Independent, Members: []int64{a, b}})
	empty := e.createGroup(GroupInput{Name: "empty", Mode: rbac.Independent})
	list, err := e.svc.ListGroups(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, x := range list {
		names = append(names, x.Name)
		switch x.ID {
		case lab.ID:
			if !slices.Equal(x.Members, []int64{a, b}) || x.Primary != 0 {
				t.Errorf("listed lab as %+v", x)
			}
		case empty.ID:
			if len(x.Members) != 0 {
				t.Errorf("listed empty as %+v", x)
			}
		}
	}
	if !slices.Equal(names, []string{"empty", "lab", "site A"}) {
		t.Errorf("ListGroups names = %v", names)
	}
}

func TestGroupInputRules(t *testing.T) {
	e := newSvcEnv(t)
	a, b, c := e.threeInstances()
	e.createGroup(GroupInput{Name: "mirror", Mode: rbac.Mirrored, Primary: a, Members: []int64{a, b}})
	before := e.auditCount()

	tests := []struct {
		name  string
		in    GroupInput
		code  rbac.Code
		field string
	}{
		{"empty name", GroupInput{Name: "  ", Mode: rbac.Independent}, rbac.CodeValidation, "name"},
		{"control char", GroupInput{Name: "a\nb", Mode: rbac.Independent}, rbac.CodeValidation, "name"},
		{"bad mode", GroupInput{Name: "x", Mode: "cluster"}, rbac.CodeValidation, "mode"},
		{"mirrored without primary", GroupInput{Name: "x", Mode: rbac.Mirrored, Members: []int64{c}}, rbac.CodeValidation, "primary_instance_id"},
		{"primary not a member", GroupInput{Name: "x", Mode: rbac.Mirrored, Primary: c, Members: []int64{a}}, rbac.CodeValidation, "primary_instance_id"},
		{"independent with primary", GroupInput{Name: "x", Mode: rbac.Independent, Primary: c, Members: []int64{c}}, rbac.CodeValidation, "primary_instance_id"},
		{"duplicate member", GroupInput{Name: "x", Mode: rbac.Independent, Members: []int64{c, c}}, rbac.CodeValidation, "members"},
		{"unknown member", GroupInput{Name: "x", Mode: rbac.Independent, Members: []int64{999}}, rbac.CodeValidation, "members"},
		{"name taken", GroupInput{Name: "MIRROR", Mode: rbac.Independent}, rbac.CodeConflict, "name"},
		{"in another mirrored group", GroupInput{Name: "x", Mode: rbac.Mirrored, Primary: c, Members: []int64{b, c}}, rbac.CodeConflict, "members"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := e.svc.CreateGroup(e.ctx, e.admin, tc.in)
			wantCode(t, err, tc.code, tc.field)
		})
	}
	if n := e.auditCount(); n != before {
		t.Errorf("refusals wrote %d audit rows", n-before)
	}

	// An instance can be in a mirrored group and any number of independent ones.
	e.createGroup(GroupInput{Name: "labels", Mode: rbac.Independent, Members: []int64{a, b, c}})
}

func TestUpdateGroup(t *testing.T) {
	e := newSvcEnv(t)
	a, b, c := e.threeInstances()
	g := e.createGroup(GroupInput{Name: "site", Mode: rbac.Independent, Members: []int64{a, b}})

	t.Run("no change", func(t *testing.T) {
		before := e.auditCount()
		got, err := e.svc.UpdateGroup(e.ctx, e.admin, g.ID, GroupInput{Name: "site", Mode: rbac.Independent, Members: []int64{b, a}})
		if err != nil || got.Name != "site" || e.auditCount() != before {
			t.Fatalf("UpdateGroup = %+v, %v; audit rows %d -> %d", got, err, before, e.auditCount())
		}
	})

	t.Run("mirrored with new members", func(t *testing.T) {
		got, err := e.svc.UpdateGroup(e.ctx, e.admin, g.ID, GroupInput{Name: "Site", Mode: rbac.Mirrored, Primary: c, Members: []int64{b, c}})
		if err != nil || got.Mode != rbac.Mirrored || got.Primary != c || !slices.Equal(got.Members, []int64{b, c}) {
			t.Fatalf("UpdateGroup = %+v, %v", got, err)
		}
		stored, err := e.svc.GetGroup(e.ctx, g.ID)
		if err != nil || stored.Name != "Site" || stored.Mode != rbac.Mirrored || !slices.Equal(stored.Members, []int64{b, c}) {
			t.Fatalf("stored %+v, %v", stored, err)
		}
		// The members' copy of the mode followed, so the one-mirrored-group rule applies to them.
		members, err := e.st.Read().ListGroupMembership(e.ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range members {
			if m.GroupID == g.ID && m.Mode != "mirrored" {
				t.Errorf("membership %+v", m)
			}
		}
		row := e.lastAudit()
		d := detail(t, row)
		if row.Action != audit.ActionGroupUpdate || row.Target != "group:Site" || d["name_before"] != "site" ||
			!slices.Equal(anyStrings(d["changed"]), []string{"name", "mode", "primary", "members"}) ||
			!slices.Equal(anyStrings(d["members_added"]), []string{"pi3"}) ||
			!slices.Equal(anyStrings(d["members_removed"]), []string{"pi1"}) || d["primary"] != "pi3" {
			t.Errorf("audit row %+v, detail %v", row, d)
		}
	})

	t.Run("switching to mirrored clashes", func(t *testing.T) {
		other := e.createGroup(GroupInput{Name: "other", Mode: rbac.Independent, Members: []int64{a, b}})
		_, err := e.svc.UpdateGroup(e.ctx, e.admin, other.ID, GroupInput{Name: "other", Mode: rbac.Mirrored, Primary: a, Members: []int64{a, b}})
		wantCode(t, err, rbac.CodeConflict, "members")
		if got, _ := e.svc.GetGroup(e.ctx, other.ID); got.Mode != rbac.Independent {
			t.Errorf("mode changed to %s", got.Mode)
		}
	})

	t.Run("invariant 6", func(t *testing.T) {
		e.grantOnGroup("drift watchers", rbac.DriftView, g.ID)
		_, err := e.svc.UpdateGroup(e.ctx, e.admin, g.ID, GroupInput{Name: "Site", Mode: rbac.Independent, Members: []int64{b, c}})
		wantCode(t, err, rbac.CodeInvariant, "")
		if e, _ := rbac.AsError(err); !slices.Equal(e.Details["roles"].([]string), []string{"drift watchers"}) {
			t.Errorf("details %v", e.Details)
		}
		// Other changes are still allowed.
		if _, err := e.svc.UpdateGroup(e.ctx, e.admin, g.ID, GroupInput{Name: "Site", Mode: rbac.Mirrored, Primary: b, Members: []int64{b, c}}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("missing", func(t *testing.T) {
		_, err := e.svc.UpdateGroup(e.ctx, e.admin, 999, GroupInput{Name: "x", Mode: rbac.Independent})
		wantCode(t, err, rbac.CodeNotFound, "")
	})
}

func TestDeleteGroup(t *testing.T) {
	e := newSvcEnv(t)
	a, b, _ := e.threeInstances()
	g := e.createGroup(GroupInput{Name: "site", Mode: rbac.Mirrored, Primary: a, Members: []int64{a, b}})
	e.grantOnGroup("site ops", rbac.DomainsEdit, g.ID)

	err := e.svc.DeleteGroup(e.ctx, e.admin, g.ID)
	wantCode(t, err, rbac.CodeConflict, "")
	if e, _ := rbac.AsError(err); !slices.Equal(e.Details["roles"].([]string), []string{"site ops"}) {
		t.Errorf("details %v", e.Details)
	}

	free := e.createGroup(GroupInput{Name: "free", Mode: rbac.Independent, Members: []int64{a}})
	if err := e.svc.DeleteGroup(e.ctx, e.admin, free.ID); err != nil {
		t.Fatal(err)
	}
	row := e.lastAudit()
	if row.Action != audit.ActionGroupDelete || row.Target != "group:free" || row.Result != audit.ResultSuccess {
		t.Errorf("audit row %+v", row)
	}
	_, err = e.svc.GetGroup(e.ctx, free.ID)
	wantCode(t, err, rbac.CodeNotFound, "")
	// The instances stay; pi1 is only in the remaining group now.
	if _, err := e.svc.Get(e.ctx, a); err != nil {
		t.Fatal(err)
	}
	err = e.svc.DeleteGroup(e.ctx, e.admin, free.ID)
	wantCode(t, err, rbac.CodeNotFound, "")
}

func TestGroupsForbidden(t *testing.T) {
	e := newSvcEnv(t)
	a, _, _ := e.threeInstances()
	g := e.createGroup(GroupInput{Name: "site", Mode: rbac.Independent, Members: []int64{a}})
	in := GroupInput{Name: "x", Mode: rbac.Independent}

	_, err := e.svc.CreateGroup(e.ctx, e.viewer, in)
	wantCode(t, err, rbac.CodeForbidden, "")
	row := e.lastAudit()
	if row.Action != audit.ActionPermissionDenied || detail(t, row)["attempted"] != audit.ActionGroupCreate {
		t.Errorf("audit row %+v", row)
	}
	_, err = e.svc.UpdateGroup(e.ctx, e.viewer, g.ID, in)
	wantCode(t, err, rbac.CodeForbidden, "")
	err = e.svc.DeleteGroup(e.ctx, e.viewer, g.ID)
	wantCode(t, err, rbac.CodeForbidden, "")
	if got, _ := e.svc.GetGroup(e.ctx, g.ID); got.Name != "site" {
		t.Errorf("group changed: %+v", got)
	}
}

func anyStrings(v any) []string {
	list, _ := v.([]any)
	out := make([]string, len(list))
	for i, x := range list {
		out[i], _ = x.(string)
	}
	return out
}
