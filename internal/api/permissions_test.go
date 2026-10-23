// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"database/sql"
	"maps"
	"net/http"
	"slices"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// topology makes instances i-1, i-2 and i-3, a mirrored group g-1 of i-1 and i-2, and an independent group g-2 of
// i-2 and i-3.
func (e *testEnv) topology() {
	e.t.Helper()
	ctx := context.Background()
	if err := e.st.WithTx(ctx, func(q *db.Queries) error {
		for _, n := range []string{"A", "B", "C"} {
			if _, err := q.CreateInstance(ctx, db.CreateInstanceParams{Name: n, BaseUrl: "http://" + n, EnvName: n, TlsMode: "verify", CreatedAt: 1}); err != nil {
				return err
			}
		}
		mirrored, err := q.CreateInstanceGroup(ctx, db.CreateInstanceGroupParams{
			Name: "mirror", Mode: "mirrored", PrimaryInstanceID: sql.NullInt64{Int64: 1, Valid: true}, CreatedAt: 1,
		})
		if err != nil {
			return err
		}
		independent, err := q.CreateInstanceGroup(ctx, db.CreateInstanceGroupParams{Name: "labs", Mode: "independent", CreatedAt: 1})
		if err != nil {
			return err
		}
		for _, m := range [][2]int64{{mirrored, 1}, {mirrored, 2}, {independent, 2}, {independent, 3}} {
			if err := q.AddInstanceGroupMember(ctx, db.AddInstanceGroupMemberParams{GroupID: m[0], InstanceID: m[1]}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		e.t.Fatal(err)
	}
}

// addGrantUser creates a user whose one role has exactly the given grants.
func (e *testEnv) addGrantUser(name, password string, grants ...db.InsertGrantParams) {
	e.t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		e.t.Fatal(err)
	}
	ctx := context.Background()
	if err := e.st.WithTx(ctx, func(q *db.Queries) error {
		role, err := q.CreateRole(ctx, db.CreateRoleParams{Name: name + "-role", CreatedAt: 1})
		if err != nil {
			return err
		}
		for _, g := range grants {
			g.RoleID = role
			if err := q.InsertGrant(ctx, g); err != nil {
				return err
			}
		}
		u, err := q.CreateLocalUser(ctx, db.CreateLocalUserParams{Username: name, PasswordHash: sql.NullString{String: string(hash), Valid: true}})
		if err != nil {
			return err
		}
		return q.AddUserRole(ctx, db.AddUserRoleParams{UserID: u.ID, RoleID: role})
	}); err != nil {
		e.t.Fatal(err)
	}
}

func grant(p rbac.Permission, scope string, id int64) db.InsertGrantParams {
	g := db.InsertGrantParams{Permission: string(p), ScopeType: scope}
	switch scope {
	case "instance":
		g.InstanceID = sql.NullInt64{Int64: id, Valid: true}
	case "group":
		g.GroupID = sql.NullInt64{Int64: id, Valid: true}
	}
	return g
}

func TestSessionPermissions(t *testing.T) {
	e := newTestEnv(t)
	e.topology()
	e.addUser("admin", "admin-password-1", true)
	e.addGrantUser("scoped", "scoped-password-1",
		grant(rbac.AuditView, "all", 0),
		grant(rbac.DomainsView, "instance", 1),
		grant(rbac.DriftView, "group", 1),   // mirrored group g-1: covers the group, not its members
		grant(rbac.ClientsView, "group", 2), // independent group g-2: covers its members i-2 and i-3
	)
	e.addGrantUser("nothing", "nothing-password-1", grant(rbac.AuditView, "all", 0))

	tests := []struct {
		user, password string
		wantGlobal     []string
		wantTargets    map[string][]string
	}{
		{
			user: "scoped", password: "scoped-password-1",
			wantGlobal: []string{"audit.view"},
			wantTargets: map[string][]string{
				"i-1": {"domains.view"},
				"i-2": {"clients.view"},
				"i-3": {"clients.view"},
				"g-1": {"drift.view"},
			},
		},
		{user: "nothing", password: "nothing-password-1", wantGlobal: []string{"audit.view"}, wantTargets: map[string][]string{}},
	}
	for _, tt := range tests {
		t.Run(tt.user, func(t *testing.T) {
			c := e.client("10.0.0.1:1")
			login := c.login(tt.user, tt.password)
			if login.Code != http.StatusOK {
				t.Fatalf("login: %d %s", login.Code, login.Body)
			}
			fromLogin := decode[gen.CurrentSession](t, login).Permissions
			fromSession := decode[gen.CurrentSession](t, c.do(http.MethodGet, "/api/v1/auth/session", nil)).Permissions
			for name, got := range map[string]gen.Permissions{"login": fromLogin, "session": fromSession} {
				if !slices.Equal(got.Global, tt.wantGlobal) {
					t.Errorf("%s: global = %v, want %v", name, got.Global, tt.wantGlobal)
				}
				if !maps.EqualFunc(got.Targets, tt.wantTargets, slices.Equal) {
					t.Errorf("%s: targets = %v, want %v", name, got.Targets, tt.wantTargets)
				}
			}
		})
	}
}

// TestAdminSessionPermissions: the builtin admin holds every permission in the catalogue.
func TestAdminSessionPermissions(t *testing.T) {
	e := newTestEnv(t)
	e.topology()
	e.addUser("admin", "admin-password-1", true)
	c := e.client("10.0.0.1:1")
	res := c.login("admin", "admin-password-1")
	if res.Code != http.StatusOK {
		t.Fatal(res.Body)
	}
	perms := decode[gen.CurrentSession](t, res).Permissions

	var wantGlobal, onInstance, onGroup []string
	for _, info := range rbac.Catalogue() {
		name := string(info.Name)
		switch info.Class {
		case rbac.ClassGlobal:
			wantGlobal = append(wantGlobal, name)
		case rbac.ClassInstance:
			onInstance = append(onInstance, name)
			onGroup = append(onGroup, name)
		case rbac.ClassGroup:
			onGroup = append(onGroup, name) // only mirrored groups
		}
	}
	for _, l := range [][]string{wantGlobal, onInstance, onGroup} {
		slices.Sort(l)
	}
	if !slices.Equal(perms.Global, wantGlobal) {
		t.Errorf("global = %v, want %v", perms.Global, wantGlobal)
	}
	for target, want := range map[string][]string{"i-1": onInstance, "i-3": onInstance, "g-1": onGroup} {
		if got := perms.Targets[target]; !slices.Equal(got, want) {
			t.Errorf("%s = %v, want %v", target, got, want)
		}
	}
	if _, ok := perms.Targets["g-2"]; ok {
		t.Error("g-2 is an independent group and isn't a target")
	}
}

// sessionContext is the context a handler would get for the client's session.
func sessionContext(t *testing.T, e *testEnv, c *client) context.Context {
	t.Helper()
	r := c.request(http.MethodGet, "/api/v1/auth/session", nil)
	sess, err := e.srv.Sessions.Get(r.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	return context.WithValue(r.Context(), reqInfoKey{}, &reqInfo{r: r, sess: sess})
}

// TestAuthorize covers authorize on the same topology: instance, mirrored group, and an independent group's members.
func TestAuthorize(t *testing.T) {
	e := newTestEnv(t)
	e.topology()
	e.addGrantUser("scoped", "scoped-password-1",
		grant(rbac.DomainsView, "instance", 1),
		grant(rbac.DriftView, "group", 1),
		grant(rbac.ClientsView, "group", 2),
	)
	c := e.client("10.0.0.1:1")
	c.login("scoped", "scoped-password-1")

	tests := []struct {
		name   string
		p      rbac.Permission
		target string
		want   bool
	}{
		{"instance grant, that instance", rbac.DomainsView, "i-1", true},
		{"instance grant, another instance", rbac.DomainsView, "i-2", false},
		{"instance grant, the mirrored group", rbac.DomainsView, "g-1", false},
		{"mirrored group grant, the group", rbac.DriftView, "g-1", true},
		{"mirrored group grant, a member", rbac.DriftView, "i-1", false},
		{"independent group grant, a member", rbac.ClientsView, "i-3", true},
		{"independent group grant, a non-member", rbac.ClientsView, "i-1", false},
		{"permission not granted", rbac.DomainsEdit, "i-1", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, err := rbac.ParseTarget(tt.target)
			if err != nil {
				t.Fatal(err)
			}
			ctx := sessionContext(t, e, c)
			err = e.srv.authorize(ctx, tt.p, target)
			switch {
			case tt.want && err != nil:
				t.Errorf("refused: %v", err)
			case !tt.want && !rbac.IsCode(err, rbac.CodeForbidden):
				t.Errorf("err = %v, want forbidden", err)
			case !tt.want:
				ee, _ := rbac.AsError(err)
				if ee.Details["permission"] != string(tt.p) || ee.Details["target"] != tt.target {
					t.Errorf("details = %v", ee.Details)
				}
			}
		})
	}
}
