// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package rbac

import (
	"context"
	"database/sql"
	"maps"
	"slices"
	"testing"

	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// Fixture topology used by the table tests:
//
//	instances 1-6
//	group 10, independent: 1, 2
//	group 20, mirrored:    3, 4
//	group 30, mirrored:    5
//	group 40, independent: no members
//	instance 6 is in no group
func fixture() *Topology {
	return NewTopology(
		[]int64{1, 2, 3, 4, 5, 6},
		map[int64]GroupMode{10: Independent, 20: Mirrored, 30: Mirrored, 40: Independent},
		map[int64][]int64{10: {1, 2}, 20: {3, 4}, 30: {5}},
	)
}

func g(p Permission, s Scope) Grant { return Grant{Permission: p, Scope: s} }

func TestCan(t *testing.T) {
	tests := []struct {
		name   string
		grants []Grant
		perm   Permission
		target Target
		want   bool
	}{
		{"no grants", nil, DomainsView, InstanceTarget(1), false},
		{"all covers an instance", []Grant{g(DomainsView, AllScope())}, DomainsView, InstanceTarget(6), true},
		{"all covers a mirrored group", []Grant{g(DomainsView, AllScope())}, DomainsView, GroupTarget(20), true},
		{"all covers a mirrored member directly", []Grant{g(DomainsEdit, AllScope())}, DomainsEdit, InstanceTarget(3), true},
		{"other permission doesn't count", []Grant{g(DomainsView, AllScope())}, DomainsEdit, InstanceTarget(1), false},

		{"instance grant covers it", []Grant{g(DomainsView, InstanceScope(1))}, DomainsView, InstanceTarget(1), true},
		{"instance grant not another", []Grant{g(DomainsView, InstanceScope(1))}, DomainsView, InstanceTarget(2), false},
		{"instance grant not its mirrored group", []Grant{g(DomainsView, InstanceScope(3))}, DomainsView, GroupTarget(20), false},
		{"grants on every member don't add up to the group",
			[]Grant{g(DomainsView, InstanceScope(3)), g(DomainsView, InstanceScope(4))}, DomainsView, GroupTarget(20), false},

		{"independent group covers a member", []Grant{g(DomainsEdit, GroupScope(10))}, DomainsEdit, InstanceTarget(2), true},
		{"independent group not a non-member", []Grant{g(DomainsEdit, GroupScope(10))}, DomainsEdit, InstanceTarget(3), false},
		{"independent group isn't a target", []Grant{g(DomainsEdit, GroupScope(10))}, DomainsEdit, GroupTarget(10), false},
		{"independent group isn't a target even with all", []Grant{g(DomainsEdit, AllScope())}, DomainsEdit, GroupTarget(10), false},

		{"mirrored group covers itself", []Grant{g(ClientsEdit, GroupScope(20))}, ClientsEdit, GroupTarget(20), true},
		{"mirrored group not a member directly", []Grant{g(ClientsEdit, GroupScope(20))}, ClientsEdit, InstanceTarget(3), false},
		{"mirrored group not another group", []Grant{g(ClientsEdit, GroupScope(20))}, ClientsEdit, GroupTarget(30), false},

		{"group permission on its mirrored group", []Grant{g(DriftView, GroupScope(20))}, DriftView, GroupTarget(20), true},
		{"group permission at all", []Grant{g(DriftReconcile, AllScope())}, DriftReconcile, GroupTarget(30), true},
		{"group permission never on an instance", []Grant{g(DriftView, AllScope())}, DriftView, InstanceTarget(3), false},

		{"global permission isn't target-scoped", []Grant{g(UsersManage, AllScope())}, UsersManage, InstanceTarget(1), false},
		{"unknown instance", []Grant{g(DomainsView, AllScope())}, DomainsView, InstanceTarget(99), false},
		{"unknown group", []Grant{g(DomainsView, AllScope())}, DomainsView, GroupTarget(99), false},
		{"unknown permission", []Grant{g("domains.delete", AllScope())}, "domains.delete", InstanceTarget(1), false},
		{"zero target", []Grant{g(DomainsView, AllScope())}, DomainsView, Target{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewSet(tt.grants, fixture()).Can(tt.perm, tt.target); got != tt.want {
				t.Errorf("Can(%s, %s) = %v, want %v", tt.perm, tt.target, got, tt.want)
			}
		})
	}
}

func TestCanGlobal(t *testing.T) {
	s := NewSet([]Grant{
		g(UsersManage, AllScope()),
		g(AuditView, InstanceScope(1)), // invalid, never stored by the app; must not count
		g(DomainsView, AllScope()),
	}, fixture())
	for p, want := range map[Permission]bool{UsersManage: true, AuditView: false, RolesManage: false, DomainsView: false} {
		if got := s.CanGlobal(p); got != want {
			t.Errorf("CanGlobal(%s) = %v, want %v", p, got, want)
		}
	}
	if got, want := s.Global(), []Permission{UsersManage}; !slices.Equal(got, want) {
		t.Errorf("Global() = %v, want %v", got, want)
	}
}

func TestHolds(t *testing.T) {
	tests := []struct {
		name  string
		have  []Grant
		grant Grant
		want  bool
	}{
		{"nothing", nil, g(DomainsView, AllScope()), false},
		{"all holds all", []Grant{g(DomainsView, AllScope())}, g(DomainsView, AllScope()), true},
		{"all holds a group", []Grant{g(DomainsView, AllScope())}, g(DomainsView, GroupScope(20)), true},
		{"all holds an instance", []Grant{g(DomainsView, AllScope())}, g(DomainsView, InstanceScope(6)), true},
		{"different permission", []Grant{g(DomainsView, AllScope())}, g(DomainsEdit, AllScope()), false},
		{"group doesn't hold all", []Grant{g(DomainsView, GroupScope(10))}, g(DomainsView, AllScope()), false},
		{"independent group holds itself", []Grant{g(DomainsView, GroupScope(10))}, g(DomainsView, GroupScope(10)), true},
		{"independent group holds a member", []Grant{g(DomainsView, GroupScope(10))}, g(DomainsView, InstanceScope(1)), true},
		{"independent group not a non-member", []Grant{g(DomainsView, GroupScope(10))}, g(DomainsView, InstanceScope(6)), false},
		{"independent group not another group", []Grant{g(DomainsView, GroupScope(10))}, g(DomainsView, GroupScope(40)), false},
		{"mirrored group holds itself", []Grant{g(DomainsView, GroupScope(20))}, g(DomainsView, GroupScope(20)), true},
		{"mirrored group not a member", []Grant{g(DomainsView, GroupScope(20))}, g(DomainsView, InstanceScope(3)), false},
		{"instance holds itself", []Grant{g(DomainsView, InstanceScope(3))}, g(DomainsView, InstanceScope(3)), true},
		{"instance not its group", []Grant{g(DomainsView, InstanceScope(3))}, g(DomainsView, GroupScope(20)), false},
		{"every member doesn't add up to the group",
			[]Grant{g(DomainsView, InstanceScope(3)), g(DomainsView, InstanceScope(4))}, g(DomainsView, GroupScope(20)), false},
		{"unknown permission", []Grant{g("x.y", AllScope())}, g("x.y", AllScope()), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewSet(tt.have, fixture()).Holds(tt.grant); got != tt.want {
				t.Errorf("Holds(%s) = %v, want %v", tt.grant, got, tt.want)
			}
		})
	}
}

func TestMissing(t *testing.T) {
	s := NewSet([]Grant{g(DomainsView, AllScope()), g(ClientsEdit, GroupScope(10))}, fixture())
	got := s.Missing([]Grant{
		g(DomainsView, InstanceScope(1)),
		g(ClientsEdit, InstanceScope(2)),
		g(UsersManage, AllScope()),
		g(ClientsEdit, InstanceScope(3)),
		g(UsersManage, AllScope()),
	})
	want := []Grant{g(ClientsEdit, InstanceScope(3)), g(UsersManage, AllScope())}
	if !slices.Equal(got, want) {
		t.Errorf("Missing = %v, want %v", got, want)
	}
	if got := s.Missing([]Grant{g(DomainsView, GroupScope(20))}); got != nil {
		t.Errorf("Missing = %v, want nil", got)
	}
}

func TestByTarget(t *testing.T) {
	s := NewSet([]Grant{
		g(DomainsView, AllScope()),
		g(DomainsEdit, GroupScope(10)),
		g(ClientsEdit, GroupScope(20)),
		g(DriftView, GroupScope(20)),
		g(QueryLogView, InstanceScope(5)),
		g(UsersManage, AllScope()),
	}, fixture())
	want := map[Target][]Permission{
		InstanceTarget(1): {DomainsEdit, DomainsView},
		InstanceTarget(2): {DomainsEdit, DomainsView},
		InstanceTarget(3): {DomainsView},
		InstanceTarget(4): {DomainsView},
		InstanceTarget(5): {DomainsView, QueryLogView},
		InstanceTarget(6): {DomainsView},
		GroupTarget(20):   {ClientsEdit, DomainsView, DriftView},
		GroupTarget(30):   {DomainsView},
	}
	got := s.ByTarget()
	if !maps.EqualFunc(got, want, slices.Equal) {
		t.Errorf("ByTarget =\n  %v\nwant\n  %v", got, want)
	}
	if got := NewSet(nil, fixture()).ByTarget(); len(got) != 0 {
		t.Errorf("ByTarget with no grants = %v, want empty", got)
	}
}

func TestValidateGrant(t *testing.T) {
	tests := []struct {
		grant Grant
		code  Code // "" for valid
	}{
		{g(DomainsView, AllScope()), ""},
		{g(DomainsView, InstanceScope(1)), ""},
		{g(DomainsView, GroupScope(10)), ""},
		{g(DomainsView, GroupScope(20)), ""},
		{g(DriftView, AllScope()), ""},
		{g(DriftView, GroupScope(20)), ""},
		{g(UsersManage, AllScope()), ""},

		{g("domains.delete", AllScope()), CodeValidation},
		{g(DomainsView, Scope{Type: "site"}), CodeValidation},
		{g(DomainsView, Scope{Type: ScopeAll, ID: 3}), CodeValidation},
		{g(DomainsView, InstanceScope(99)), CodeValidation},
		{g(DomainsView, GroupScope(99)), CodeValidation},
		{g(DriftView, GroupScope(10)), CodeInvariant},
		{g(DriftReconcile, InstanceScope(3)), CodeInvariant},
		{g(UsersManage, GroupScope(20)), CodeInvariant},
		{g(AuditView, InstanceScope(1)), CodeInvariant},
	}
	for _, tt := range tests {
		err := ValidateGrant(fixture(), tt.grant)
		switch {
		case tt.code == "" && err != nil:
			t.Errorf("ValidateGrant(%s) = %v, want nil", tt.grant, err)
		case tt.code != "" && !IsCode(err, tt.code):
			t.Errorf("ValidateGrant(%s) = %v, want code %s", tt.grant, err, tt.code)
		}
	}
}

// Resolve reads grants and the topology from the database; this checks the queries and the row mapping.
func TestResolve(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	var roleA, roleB, inst1, inst2, grp int64
	err := st.WithTx(ctx, func(q *db.Queries) error {
		var err error
		must := func(id int64, e error) int64 {
			if err == nil {
				err = e
			}
			return id
		}
		inst1 = must(q.CreateInstance(ctx, db.CreateInstanceParams{Name: "one", BaseUrl: "https://one", EnvName: "ONE", CreatedAt: 1}))
		inst2 = must(q.CreateInstance(ctx, db.CreateInstanceParams{Name: "two", BaseUrl: "https://two", EnvName: "TWO", CreatedAt: 1}))
		grp = must(q.CreateInstanceGroup(ctx, db.CreateInstanceGroupParams{
			Name: "pair", Mode: string(Mirrored), PrimaryInstanceID: sql.NullInt64{Int64: inst1, Valid: true}, CreatedAt: 1,
		}))
		roleA = must(q.CreateRole(ctx, db.CreateRoleParams{Name: "a", CreatedAt: 1}))
		roleB = must(q.CreateRole(ctx, db.CreateRoleParams{Name: "b", CreatedAt: 1}))
		if err != nil {
			return err
		}
		for _, id := range []int64{inst1, inst2} {
			if err := q.AddInstanceGroupMember(ctx, db.AddInstanceGroupMemberParams{GroupID: grp, InstanceID: id}); err != nil {
				return err
			}
		}
		for _, p := range []db.InsertGrantParams{
			{RoleID: roleA, Permission: string(DomainsView), ScopeType: string(ScopeInstance), InstanceID: sql.NullInt64{Int64: inst2, Valid: true}},
			{RoleID: roleA, Permission: "retired.permission", ScopeType: string(ScopeAll)},
			{RoleID: roleB, Permission: string(DriftView), ScopeType: string(ScopeGroup), GroupID: sql.NullInt64{Int64: grp, Valid: true}},
		} {
			if err := q.InsertGrant(ctx, p); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	s, err := Resolve(ctx, st.Read(), []int64{roleA, roleB})
	if err != nil {
		t.Fatal(err)
	}
	want := []Grant{g(DomainsView, InstanceScope(inst2)), g(DriftView, GroupScope(grp))}
	if got := s.Grants(); !slices.Equal(got, want) {
		t.Errorf("Grants = %v, want %v (unknown permissions dropped)", got, want)
	}
	if !s.Can(DriftView, GroupTarget(grp)) || !s.Can(DomainsView, InstanceTarget(inst2)) || s.Can(DomainsView, InstanceTarget(inst1)) {
		t.Errorf("unexpected Can results for %v", s.Grants())
	}

	none, err := Resolve(ctx, st.Read(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(none.Grants()) != 0 {
		t.Errorf("no roles resolved to %v", none.Grants())
	}
}
