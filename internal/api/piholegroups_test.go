// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi/piholetest"
	"github.com/Kate-0713/pihole-rbac/internal/piholegroups"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// addRefs stores client reset rules and protected groups directly. A scope is "i-<id>" or "g-<id>".
type refIn struct {
	scope  string
	prefix string // a client reset rule's comment prefix; "" for a protected group
	match  string
	names  []string
}

func (e *testEnv) addRefs(refs ...refIn) {
	e.t.Helper()
	ctx := context.Background()
	if err := e.st.WithTx(ctx, func(q *db.Queries) error {
		for _, r := range refs {
			t, err := rbac.ParseTarget(r.scope)
			if err != nil {
				return err
			}
			var inst, grp sql.NullInt64
			if t.Kind == rbac.TargetGroup {
				grp = sql.NullInt64{Int64: t.ID, Valid: true}
			} else {
				inst = sql.NullInt64{Int64: t.ID, Valid: true}
			}
			if r.prefix == "" {
				for _, n := range r.names {
					if err := q.AddProtectedGroup(ctx, db.AddProtectedGroupParams{InstanceID: inst, GroupID: grp, PiholeGroup: n}); err != nil {
						return err
					}
				}
				continue
			}
			b, _ := json.Marshal(r.names)
			if err := q.AddClientResetRule(ctx, db.AddClientResetRuleParams{InstanceID: inst, GroupID: grp,
				CommentPrefix: r.prefix, GroupMatch: r.match, TargetGroups: string(b)}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		e.t.Fatal(err)
	}
}

// refsNow lists the stored references as "scope kind prefix names", sorted.
func (e *testEnv) refsNow() []string {
	e.t.Helper()
	refs, err := piholegroups.Load(context.Background(), e.st.Read())
	if err != nil {
		e.t.Fatal(err)
	}
	var out []string
	for _, r := range refs {
		names := r.Groups
		if r.Kind == piholegroups.KindProtected || r.Kind == piholegroups.KindWindow {
			names = []string{r.Name}
		}
		if r.Kind == piholegroups.KindOverride {
			names = []string{strings.Join(r.Original, ",") + " -> " + strings.Join(r.Override, ",")}
		}
		out = append(out, r.Scope.String()+" "+string(r.Kind)+" "+r.Prefix+" "+strings.Join(names, ","))
	}
	slices.Sort(out)
	return out
}

func groupNamed(t *testing.T, ph *piholetest.Server, name string) (piholetest.Group, bool) {
	t.Helper()
	gs := ph.Groups()
	i := slices.IndexFunc(gs, func(g piholetest.Group) bool { return g.Name == name })
	if i < 0 {
		return piholetest.Group{}, false
	}
	return gs[i], true
}

func TestPiholeGroupWrites(t *testing.T) {
	te := newTargetEnv(t)
	kids := te.ph.AddGroup("kids")
	te.ph.AddGroup("guests")

	t.Run("add", func(t *testing.T) {
		r := okResult[gen.PiholeGroupWriteResult](te, te.admin.do(http.MethodPost, te.path("/groups"),
			gen.PiholeGroupInput{Name: "lab night", Comment: strp("after hours"), Enabled: ptr(false)}))
		g, ok := groupNamed(t, te.ph, "lab night")
		if !ok || g.Enabled || g.Comment != "after hours" || r.Entry == nil || r.Entry.Id != g.ID {
			t.Fatalf("group %+v, result %+v", g, r.Entry)
		}
		row, detail := te.lastAudit()
		if row.Action != audit.ActionPiholeGroupAdd || detail["name"] != "lab night" {
			t.Errorf("audit %s %v", row.Action, detail)
		}
		res := te.admin.do(http.MethodPost, te.path("/groups"), gen.PiholeGroupInput{Name: "kids"})
		if res.Code != http.StatusBadRequest || res.errorCode() != "pihole_rejected" {
			t.Errorf("a taken name: %d %s", res.Code, res.Body)
		}
	})

	t.Run("names are checked before anything is sent", func(t *testing.T) {
		for _, name := range []string{"", " kids", "kids ", "a\tb", "a\nb", strings.Repeat("x", 256)} {
			writes := len(te.piholeWrites())
			res := te.admin.do(http.MethodPost, te.path("/groups"), gen.PiholeGroupInput{Name: name})
			if res.Code != http.StatusBadRequest || res.errorCode() != "validation_failed" {
				t.Errorf("%q: %d %s", name, res.Code, res.Body)
			}
			res = te.admin.do(http.MethodPatch, te.path("/groups"), gen.PiholeGroupUpdate{Name: "kids", NewName: &name})
			if res.Code != http.StatusBadRequest || res.errorCode() != "validation_failed" {
				t.Errorf("renaming to %q: %d %s", name, res.Code, res.Body)
			}
			if len(te.piholeWrites()) != writes {
				t.Errorf("%q reached Pi-hole", name)
			}
		}
	})

	tests := []struct {
		name    string
		body    gen.PiholeGroupUpdate
		confirm bool
		status  int
		code    string
		action  string // the audit row's action; "" for none
		check   func(t *testing.T, detail map[string]any)
	}{
		{name: "a comment", body: gen.PiholeGroupUpdate{Name: "kids", Comment: strp("school nights")},
			status: http.StatusOK, action: audit.ActionPiholeGroupUpdate,
			check: func(t *testing.T, d map[string]any) {
				if g, _ := groupNamed(t, te.ph, "kids"); g.Comment != "school nights" || !g.Enabled {
					t.Errorf("group %+v: the enabled flag must be kept", g)
				}
			}},
		{name: "a change that changes nothing isn't sent", body: gen.PiholeGroupUpdate{Name: "kids", Comment: strp("school nights")},
			status: http.StatusOK},
		{name: "disabling", body: gen.PiholeGroupUpdate{Name: "kids", Enabled: ptr(false)},
			status: http.StatusOK, action: audit.ActionPiholeGroupDisable,
			check: func(t *testing.T, d map[string]any) {
				if g, _ := groupNamed(t, te.ph, "kids"); g.Enabled || g.Comment != "school nights" {
					t.Errorf("group %+v: the comment must be kept", g)
				}
			}},
		{name: "renaming and enabling is one enable row", body: gen.PiholeGroupUpdate{Name: "kids", NewName: strp("children"), Enabled: ptr(true)},
			status: http.StatusOK, action: audit.ActionPiholeGroupEnable,
			check: func(t *testing.T, d map[string]any) {
				if g, ok := groupNamed(t, te.ph, "children"); !ok || g.ID != kids || !g.Enabled {
					t.Errorf("group %+v", g)
				}
				if d["name"] != "kids" || d["new_name"] != "children" {
					t.Errorf("detail %v", d)
				}
			}},
		{name: "a group that doesn't exist is a 404", body: gen.PiholeGroupUpdate{Name: "kids", Comment: strp("x")},
			status: http.StatusNotFound, code: "not_found"},
		{name: "Default can't be renamed", body: gen.PiholeGroupUpdate{Name: "Default", NewName: strp("Everyone")},
			status: http.StatusBadRequest, code: "validation_failed"},
		{name: "disabling Default needs confirming", body: gen.PiholeGroupUpdate{Name: "Default", Enabled: ptr(false)},
			status: http.StatusConflict, code: "confirmation_required"},
		{name: "disabling Default, confirmed", body: gen.PiholeGroupUpdate{Name: "Default", Enabled: ptr(false)}, confirm: true,
			status: http.StatusOK, action: audit.ActionPiholeGroupDisable},
		{name: "Default's comment needs no confirming", body: gen.PiholeGroupUpdate{Name: "Default", Comment: strp("everyone")},
			status: http.StatusOK, action: audit.ActionPiholeGroupUpdate},
		{name: "enabling Default needs no confirming", body: gen.PiholeGroupUpdate{Name: "Default", Enabled: ptr(true)},
			status: http.StatusOK, action: audit.ActionPiholeGroupEnable},
		{name: "renaming to a taken name is rejected by Pi-hole", body: gen.PiholeGroupUpdate{Name: "children", NewName: strp("guests")},
			status: http.StatusBadRequest, code: "pihole_rejected", action: audit.ActionPiholeGroupUpdate},
		{name: "nothing to change", body: gen.PiholeGroupUpdate{Name: "children", NewName: strp("children")},
			status: http.StatusBadRequest, code: "validation_failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rows, writes := te.auditCount(), len(te.piholeWrites())
			path := te.path("/groups")
			if tt.confirm {
				path += "?confirm=true"
			}
			res := te.admin.do(http.MethodPatch, path, tt.body)
			if res.Code != tt.status || (tt.code != "" && res.errorCode() != tt.code) {
				t.Fatalf("%d %s, want %d %s", res.Code, res.Body, tt.status, tt.code)
			}
			if tt.code == "confirmation_required" {
				if d := errorDetails(t, res); d["default_group"] != true {
					t.Errorf("details %v", d)
				}
			}
			if tt.action == "" {
				if te.auditCount() != rows || len(te.piholeWrites()) != writes {
					t.Error("written or audited when nothing should be")
				}
				return
			}
			row, detail := te.lastAudit()
			if te.auditCount() != rows+1 || row.Action != tt.action {
				t.Fatalf("audit %d rows, last %s, want %s", te.auditCount()-rows, row.Action, tt.action)
			}
			if tt.check != nil {
				tt.check(t, detail)
			}
		})
	}

	t.Run("delete", func(t *testing.T) {
		te.ph.AddDomain(piholetest.Domain{Domain: "a.example", Type: "deny", Kind: "exact", Groups: []int{0, kids}, Enabled: true})
		te.ph.AddClient(piholetest.Client{Client: "10.0.0.5", Groups: []int{kids}})
		te.ph.AddList(piholetest.List{Address: "https://lists.example/a.txt", Type: "block", Groups: []int{kids}, Enabled: true})
		u := decode[gen.PiholeGroupUsage](t, te.admin.do(http.MethodGet, te.path("/groups/usage?name=children"), nil))
		if u.Id != kids || u.Domains != 1 || u.Clients != 1 || u.Lists != 1 || u.References.Counts != (gen.PiholeGroupReferenceCounts{}) {
			t.Errorf("usage %+v", u)
		}
		if res := te.admin.do(http.MethodGet, te.path("/groups/usage?name=nobody"), nil); res.Code != http.StatusNotFound {
			t.Errorf("usage of a missing group: %d", res.Code)
		}
		okResult[gen.DeleteResult](te, te.admin.do(http.MethodDelete, te.path("/groups"), gen.PiholeGroupKey{Name: "children"}))
		if _, ok := groupNamed(t, te.ph, "children"); ok {
			t.Error("not deleted")
		}
		row, detail := te.lastAudit()
		if row.Action != audit.ActionPiholeGroupDelete || detail["name"] != "children" {
			t.Errorf("audit %s %v", row.Action, detail)
		}
		for name, want := range map[string]int{"children": http.StatusNotFound, "Default": http.StatusBadRequest} {
			writes := len(te.piholeWrites())
			if res := te.admin.do(http.MethodDelete, te.path("/groups"), gen.PiholeGroupKey{Name: name}); res.Code != want {
				t.Errorf("deleting %s: %d %s", name, res.Code, res.Body)
			}
			if len(te.piholeWrites()) != writes {
				t.Errorf("deleting %s reached Pi-hole", name)
			}
		}
	})
}

// TestPiholeGroupPermissions: writes and the usage read need piholegroups.edit on the target; reading the groups
// needs any permission there.
func TestPiholeGroupPermissions(t *testing.T) {
	te := newTargetEnv(t)
	te.ph.AddGroup("kids")
	te.addGrantUser("viewer", "viewer-password-1", grant(rbac.ClientsView, "instance", te.id))
	te.addGrantUser("editor", "editor-password-1", grant(rbac.PiholeGroupsEdit, "instance", te.id))
	viewer, editor := te.loggedIn("viewer", "viewer-password-1"), te.loggedIn("editor", "editor-password-1")
	mustStatus(t, viewer.do(http.MethodGet, te.path("/groups"), nil), http.StatusOK)
	reqs := []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, "/groups", gen.PiholeGroupInput{Name: "lab"}},
		{http.MethodPatch, "/groups", gen.PiholeGroupUpdate{Name: "kids", Comment: strp("x")}},
		{http.MethodGet, "/groups/usage?name=kids", nil},
		{http.MethodDelete, "/groups", gen.PiholeGroupKey{Name: "kids"}},
	}
	for _, r := range reqs {
		writes := len(te.piholeWrites())
		res := viewer.do(r.method, te.path(r.path), r.body)
		if res.Code != http.StatusForbidden || errorDetails(t, res)["permission"] != string(rbac.PiholeGroupsEdit) {
			t.Errorf("%s %s by a viewer: %d %s", r.method, r.path, res.Code, res.Body)
		}
		if len(te.piholeWrites()) != writes {
			t.Errorf("%s %s by a viewer reached Pi-hole", r.method, r.path)
		}
	}
	for _, r := range reqs {
		if res := editor.do(r.method, te.path(r.path), r.body); res.Code != http.StatusOK {
			t.Errorf("%s %s by an editor: %d %s", r.method, r.path, res.Code, res.Body)
		}
	}
}

// TestPiholeGroupReferences: renaming or deleting a group the app refers to needs confirming; the 409 always counts
// the references, and lists only those the caller manages; a rename updates exact names, lists prefix rules to
// check, and leaves other instances' references alone; a delete leaves every reference as it was.
func TestPiholeGroupReferences(t *testing.T) {
	te := newTargetEnv(t)
	te.ph.AddGroup("kids")
	te.ph.AddGroup("lab")
	other := te.addInstance("pihole2")
	te.addRefs(
		refIn{scope: te.target, prefix: "TEST-", match: "names", names: []string{"Default", "kids"}},
		refIn{scope: te.target, prefix: "LAB-", match: "prefixes", names: []string{"ki"}},
		refIn{scope: te.target, names: []string{"Kids"}},
		refIn{scope: other, prefix: "TEST-", match: "names", names: []string{"kids"}},
	)
	te.addGrantUser("editor", "editor-password-1", grant(rbac.PiholeGroupsEdit, "instance", te.id))
	te.addGrantUser("resetter", "resetter-password-1", grant(rbac.PiholeGroupsEdit, "instance", te.id), grant(rbac.SettingsManage, "all", 0))
	rename := gen.PiholeGroupUpdate{Name: "kids", NewName: strp("children")}

	for _, tt := range []struct {
		user, password string
		kinds          []string
	}{
		{"editor", "editor-password-1", nil},
		{"resetter", "resetter-password-1", []string{"client_reset_rule", "client_reset_rule"}},
		{"admin", "", []string{"client_reset_rule", "client_reset_rule", "protected_group"}},
	} {
		c := te.admin
		if tt.password != "" {
			c = te.loggedIn(tt.user, tt.password)
		}
		res := c.do(http.MethodPatch, te.path("/groups"), rename)
		if res.Code != http.StatusConflict || res.errorCode() != "confirmation_required" {
			t.Fatalf("%s: %d %s", tt.user, res.Code, res.Body)
		}
		raw, _ := json.Marshal(errorDetails(t, res)["references"])
		var refs gen.PiholeGroupReferences
		_ = json.Unmarshal(raw, &refs)
		var kinds []string
		for _, r := range refs.Items {
			kinds = append(kinds, string(r.Kind))
		}
		if refs.Counts != (gen.PiholeGroupReferenceCounts{ClientResetRules: 2, ProtectedGroups: 1}) || !slices.Equal(kinds, tt.kinds) {
			t.Errorf("%s sees %+v", tt.user, refs)
		}
		res = c.do(http.MethodDelete, te.path("/groups"), gen.PiholeGroupKey{Name: "kids"})
		if res.Code != http.StatusConflict || res.errorCode() != "confirmation_required" {
			t.Errorf("%s deleting: %d %s", tt.user, res.Code, res.Body)
		}
	}
	if _, ok := groupNamed(t, te.ph, "kids"); !ok {
		t.Fatal("an unconfirmed change reached Pi-hole")
	}

	res := te.admin.do(http.MethodPatch, te.path("/groups?confirm=true"), rename)
	mustStatus(t, res, http.StatusOK)
	body := decode[gen.PiholeGroupWriteResults](t, res)
	if body.References == nil || body.References.Error != nil ||
		body.References.Updated.Counts != (gen.PiholeGroupReferenceCounts{ClientResetRules: 1, ProtectedGroups: 1}) ||
		body.References.ToCheck.Counts != (gen.PiholeGroupReferenceCounts{ClientResetRules: 1}) ||
		*body.References.ToCheck.Items[0].Reason != gen.PrefixMatchChanges {
		t.Fatalf("references %s", res.Body)
	}
	want := sorted(
		other+" client_reset_rule TEST- kids",
		te.target+" client_reset_rule LAB- ki",
		te.target+" client_reset_rule TEST- Default,children",
		te.target+" protected_group  children",
	)
	if got := te.refsNow(); !slices.Equal(got, want) {
		t.Errorf("references after the rename:\n got %q\nwant %q", got, want)
	}
	row, detail := te.lastAudit()
	if row.Action != audit.ActionPiholeGroupUpdate || len(anyList(detail["references_updated"])) != 2 || len(anyList(detail["references_to_check"])) != 1 {
		t.Errorf("audit %s %v", row.Action, detail)
	}

	res = te.admin.do(http.MethodDelete, te.path("/groups?confirm=true"), gen.PiholeGroupKey{Name: "children"})
	mustStatus(t, res, http.StatusOK)
	if del := decode[gen.PiholeGroupDeleteResults](t, res); del.References == nil || len(del.References.Items) != 2 {
		t.Errorf("delete references %s", res.Body)
	}
	if got := te.refsNow(); !slices.Equal(got, want) {
		t.Errorf("a delete changed references: %q", got)
	}
	if _, detail := te.lastAudit(); len(anyList(detail["references"])) != 2 {
		t.Errorf("delete audit %v", detail)
	}
}

// addWindow stores a one-off group window on a scope ("i-<id>" or "g-<id>") directly.
func (e *testEnv) addWindow(scope, name, group string) {
	e.t.Helper()
	ctx := context.Background()
	t, err := rbac.ParseTarget(scope)
	if err != nil {
		e.t.Fatal(err)
	}
	p := db.CreateScheduleParams{
		Name: name, Kind: "group_enabled", PiholeGroup: sql.NullString{String: group, Valid: true}, Repeat: "once",
		StartsAt: sql.NullInt64{Int64: 10, Valid: true}, EndsAt: sql.NullInt64{Int64: 20, Valid: true},
		ActiveFrom: 1, Enabled: 1, CreatedAt: 1, CreatedBy: "admin", UpdatedAt: 1, UpdatedBy: "admin",
	}
	if t.Kind == rbac.TargetGroup {
		p.GroupID = sql.NullInt64{Int64: t.ID, Valid: true}
	} else {
		p.InstanceID = sql.NullInt64{Int64: t.ID, Valid: true}
	}
	if err := e.st.WithTx(ctx, func(q *db.Queries) error { _, err := q.CreateSchedule(ctx, p); return err }); err != nil {
		e.t.Fatal(err)
	}
}

// TestPiholeGroupWindowReferences: a schedule's group window is a reference to its Pi-hole group, counted for
// everyone and shown in full only to holders of schedules.manage on its target; a rename updates it, and a delete
// lists it without removing it.
func TestPiholeGroupWindowReferences(t *testing.T) {
	te := newTargetEnv(t)
	te.ph.AddGroup("kids")
	te.addWindow(te.target, "Bedtime", "kids")
	te.addWindow(te.target, "Other", "Kids") // names match exactly
	te.addGrantUser("editor", "editor-password-1", grant(rbac.PiholeGroupsEdit, "instance", te.id))
	te.addGrantUser("scheduler", "scheduler-password-1", grant(rbac.PiholeGroupsEdit, "instance", te.id), grant(rbac.SchedulesManage, "instance", te.id))
	for _, tt := range []struct {
		user, password string
		items          int
	}{{"editor", "editor-password-1", 0}, {"scheduler", "scheduler-password-1", 1}} {
		u := decode[gen.PiholeGroupUsage](t, te.loggedIn(tt.user, tt.password).do(http.MethodGet, te.path("/groups/usage?name=kids"), nil))
		if u.References.Counts != (gen.PiholeGroupReferenceCounts{GroupWindows: 1}) || len(u.References.Items) != tt.items {
			t.Errorf("%s sees %+v", tt.user, u.References)
			continue
		}
		if tt.items == 1 {
			it := u.References.Items[0]
			if it.Kind != gen.PiholeGroupReferenceKindGroupWindow || it.ScheduleName == nil || *it.ScheduleName != "Bedtime" ||
				it.ScheduleKind == nil || *it.ScheduleKind != "group_enabled" || !slices.Equal(it.Names, []string{"kids"}) {
				t.Errorf("item %+v", it)
			}
		}
	}

	rename := gen.PiholeGroupUpdate{Name: "kids", NewName: strp("children")}
	if res := te.admin.do(http.MethodPatch, te.path("/groups"), rename); res.Code != http.StatusConflict {
		t.Fatalf("unconfirmed rename: %d %s", res.Code, res.Body)
	}
	res := te.admin.do(http.MethodPatch, te.path("/groups?confirm=true"), rename)
	mustStatus(t, res, http.StatusOK)
	if body := decode[gen.PiholeGroupWriteResults](t, res); body.References == nil ||
		body.References.Updated.Counts != (gen.PiholeGroupReferenceCounts{GroupWindows: 1}) {
		t.Fatalf("references %s", res.Body)
	}
	want := sorted(te.target+" group_window  children", te.target+" group_window  Kids")
	if got := te.refsNow(); !slices.Equal(got, want) {
		t.Errorf("after the rename:\n got %q\nwant %q", got, want)
	}
	if _, detail := te.lastAudit(); len(anyList(detail["references_updated"])) != 1 {
		t.Errorf("audit %v", detail)
	}

	res = te.admin.do(http.MethodDelete, te.path("/groups?confirm=true"), gen.PiholeGroupKey{Name: "children"})
	mustStatus(t, res, http.StatusOK)
	if del := decode[gen.PiholeGroupDeleteResults](t, res); del.References == nil || del.References.Counts.GroupWindows != 1 {
		t.Errorf("delete references %s", res.Body)
	}
	if got := te.refsNow(); !slices.Equal(got, want) {
		t.Errorf("a delete changed references: %q", got)
	}
}

// addOverride stores an active temporary client change on an instance directly: the client was in original and the
// change put it in override.
func (e *testEnv) addOverride(instanceID int64, client string, original, override string) {
	e.t.Helper()
	ctx := context.Background()
	err := e.st.WithTx(ctx, func(q *db.Queries) error {
		id, err := q.CreateClientOverride(ctx, db.CreateClientOverrideParams{
			InstanceID: sql.NullInt64{Int64: instanceID, Valid: true}, Client: client, StartsAt: 10, EndsAt: 20, CreatedBy: "admin", CreatedAt: 10,
		})
		if err != nil {
			return err
		}
		_, err = q.CreateClientOverrideMember(ctx, db.CreateClientOverrideMemberParams{
			OverrideID: id, InstanceID: instanceID, Client: client, OriginalGroups: original, OverrideGroups: override,
		})
		return err
	})
	if err != nil {
		e.t.Fatal(err)
	}
}

// TestPiholeGroupOverrideReferences: an active temporary client change is a reference to the Pi-hole groups it names,
// counted for everyone and shown in full only to holders of clients.edit on its instance; a rename updates both its
// original and its override groups, and a delete lists it without removing it.
func TestPiholeGroupOverrideReferences(t *testing.T) {
	te := newTargetEnv(t)
	te.ph.AddGroup("kids")
	te.ph.AddGroup("open")
	te.addOverride(te.id, "10.0.0.5", `["Default","kids"]`, `["Default","open"]`)
	te.addOverride(te.id, "10.0.0.6", `["Default"]`, `["Default","Kids"]`) // names match exactly
	te.addGrantUser("editor", "editor-password-1", grant(rbac.PiholeGroupsEdit, "instance", te.id))
	te.addGrantUser("clients", "clients-password-1", grant(rbac.PiholeGroupsEdit, "instance", te.id), grant(rbac.ClientsEdit, "instance", te.id))
	for _, tt := range []struct {
		user, password string
		items          int
	}{{"editor", "editor-password-1", 0}, {"clients", "clients-password-1", 1}} {
		u := decode[gen.PiholeGroupUsage](t, te.loggedIn(tt.user, tt.password).do(http.MethodGet, te.path("/groups/usage?name=kids"), nil))
		if u.References.Counts != (gen.PiholeGroupReferenceCounts{ClientOverrides: 1}) || len(u.References.Items) != tt.items {
			t.Errorf("%s sees %+v", tt.user, u.References)
			continue
		}
		if tt.items == 1 {
			it := u.References.Items[0]
			if it.Kind != gen.PiholeGroupReferenceKindClientOverride || it.Client == nil || *it.Client != "10.0.0.5" ||
				it.OriginalNames == nil || !slices.Equal(*it.OriginalNames, []string{"Default", "kids"}) || !slices.Equal(it.Names, []string{"Default", "open"}) {
				t.Errorf("item %+v", it)
			}
		}
	}

	rename := gen.PiholeGroupUpdate{Name: "kids", NewName: strp("children")}
	if res := te.admin.do(http.MethodPatch, te.path("/groups"), rename); res.Code != http.StatusConflict {
		t.Fatalf("unconfirmed rename: %d %s", res.Code, res.Body)
	}
	res := te.admin.do(http.MethodPatch, te.path("/groups?confirm=true"), rename)
	mustStatus(t, res, http.StatusOK)
	body := decode[gen.PiholeGroupWriteResults](t, res)
	if body.References == nil || body.References.Updated.Counts != (gen.PiholeGroupReferenceCounts{ClientOverrides: 1}) {
		t.Fatalf("references %s", res.Body)
	}
	want := sorted(te.target+" client_override  Default,children -> Default,open", te.target+" client_override  Default -> Default,Kids")
	if got := te.refsNow(); !slices.Equal(got, want) {
		t.Errorf("after the rename:\n got %q\nwant %q", got, want)
	}
	_, detail := te.lastAudit()
	updated := anyList(detail["references_updated"])
	if len(updated) != 1 {
		t.Fatalf("audit %v", detail)
	}
	if d, _ := updated[0].(map[string]any); d["client"] != "10.0.0.5" || d["override_id"] == nil || d["original_names"] == nil || d["original_before"] == nil {
		t.Errorf("audit reference %v", updated[0])
	}

	res = te.admin.do(http.MethodDelete, te.path("/groups?confirm=true"), gen.PiholeGroupKey{Name: "children"})
	mustStatus(t, res, http.StatusOK)
	if del := decode[gen.PiholeGroupDeleteResults](t, res); del.References == nil || del.References.Counts.ClientOverrides != 1 || len(del.References.Items) != 1 {
		t.Errorf("delete references %s", res.Body)
	}
	if got := te.refsNow(); !slices.Equal(got, want) {
		t.Errorf("a delete changed references: %q", got)
	}
}

// TestGroupPiholeGroups covers Pi-hole group changes through a mirrored group: a rename everywhere updates the
// group's references, a member without the group fails and leaves them, a retry that completes the rename updates
// them, and a direct rename on one member never touches the group's.
func TestGroupPiholeGroups(t *testing.T) {
	ge := newGroupEnv(t)
	for _, n := range []string{"alpha", "beta", "gamma"} {
		ge.ph[n].AddGroup("kids")
		ge.ph[n].AddGroup("lab")
	}
	alpha := "i-" + itoa(ge.ids["alpha"])
	ge.addRefs(
		refIn{scope: ge.target, prefix: "TEST-", match: "names", names: []string{"kids", "lab"}},
		refIn{scope: ge.target, names: []string{"lab"}},
		refIn{scope: alpha, names: []string{"lab"}},
	)

	t.Run("a rename everywhere", func(t *testing.T) {
		res := ge.admin.do(http.MethodPatch, ge.path("/groups?confirm=true"), gen.PiholeGroupUpdate{Name: "kids", NewName: strp("children")})
		mustStatus(t, res, http.StatusOK)
		want := sorted(alpha+" protected_group  lab", ge.target+" client_reset_rule TEST- children,lab", ge.target+" protected_group  lab")
		if got := ge.refsNow(); !slices.Equal(got, want) {
			t.Errorf("got %q", got)
		}
	})

	t.Run("a member that fails leaves the group's references", func(t *testing.T) {
		ge.ph["gamma"].Handle(func(w http.ResponseWriter, r *http.Request) bool {
			if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/api/groups/") {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":{"key":"database_error","message":"refused for the test"}}`))
				return true
			}
			return false
		})
		res := ge.admin.do(http.MethodPatch, ge.path("/groups?confirm=true"), gen.PiholeGroupUpdate{Name: "lab", NewName: strp("lab-old")})
		mustStatus(t, res, http.StatusMultiStatus)
		if got := summarise(results(t, res)); !slices.Equal(got, []string{"alpha:ok", "beta:ok", "gamma:failed:pihole_rejected"}) {
			t.Errorf("results %v", got)
		}
		body := decode[gen.PiholeGroupWriteResults](t, res)
		if body.References.Updated.Counts.ProtectedGroups != 1 || body.References.ToCheck.Counts != (gen.PiholeGroupReferenceCounts{ClientResetRules: 1, ProtectedGroups: 1}) {
			t.Errorf("references %s", res.Body)
		}
		want := sorted(alpha+" protected_group  lab-old", ge.target+" client_reset_rule TEST- children,lab", ge.target+" protected_group  lab")
		if got := ge.refsNow(); !slices.Equal(got, want) {
			t.Errorf("got %q", got)
		}

		ge.ph["gamma"].Handle(nil)
		res = ge.admin.do(http.MethodPatch, ge.path("/groups?confirm=true&members="+itoa(ge.ids["gamma"])), gen.PiholeGroupUpdate{Name: "lab", NewName: strp("lab-old")})
		mustStatus(t, res, http.StatusOK)
		want = sorted(alpha+" protected_group  lab-old", ge.target+" client_reset_rule TEST- children,lab-old", ge.target+" protected_group  lab-old")
		if got := ge.refsNow(); !slices.Equal(got, want) {
			t.Errorf("after the retry got %q", got)
		}
	})

	t.Run("a direct rename on a member leaves the group's references", func(t *testing.T) {
		res := ge.admin.do(http.MethodPatch, ge.instPath("alpha", "/groups?confirm=true"), gen.PiholeGroupUpdate{Name: "lab-old", NewName: strp("lab")})
		mustStatus(t, res, http.StatusOK)
		body := decode[gen.PiholeGroupWriteResults](t, res)
		if body.References.ToCheck.Counts != (gen.PiholeGroupReferenceCounts{ClientResetRules: 1, ProtectedGroups: 1}) {
			t.Errorf("references %s", res.Body)
		}
		want := sorted(alpha+" protected_group  lab", ge.target+" client_reset_rule TEST- children,lab-old", ge.target+" protected_group  lab-old")
		if got := ge.refsNow(); !slices.Equal(got, want) {
			t.Errorf("got %q", got)
		}
	})

	t.Run("delete through the group", func(t *testing.T) {
		ge.ph["alpha"].AddGroup("guests")
		ge.ph["beta"].AddGroup("guests")
		res := ge.admin.do(http.MethodDelete, ge.path("/groups"), gen.PiholeGroupKey{Name: "guests"})
		mustStatus(t, res, http.StatusOK)
		if got := summarise(results(t, res)); !slices.Equal(got, []string{"alpha:ok", "beta:ok", "gamma:ok"}) {
			t.Errorf("results %v: gamma doesn't have it, which is ok", got)
		}
		for _, n := range []string{"alpha", "beta"} {
			if _, ok := groupNamed(t, ge.ph[n], "guests"); ok {
				t.Errorf("%s still has it", n)
			}
		}
	})

	t.Run("a member without the group fails a rename", func(t *testing.T) {
		ge.ph["alpha"].AddGroup("solo")
		res := ge.admin.do(http.MethodPatch, ge.path("/groups"), gen.PiholeGroupUpdate{Name: "solo", Comment: strp("x")})
		mustStatus(t, res, http.StatusMultiStatus)
		if got := summarise(results(t, res)); !slices.Equal(got, []string{"alpha:ok", "beta:failed:not_found", "gamma:failed:not_found"}) {
			t.Errorf("results %v", got)
		}
	})
}

func itoa(id int64) string { return strconv.FormatInt(id, 10) }

// addInstance stores a disabled instance directly, for references on another instance, and returns its target.
func (e *testEnv) addInstance(name string) string {
	e.t.Helper()
	ctx := context.Background()
	var id int64
	if err := e.st.WithTx(ctx, func(q *db.Queries) error {
		var err error
		id, err = q.CreateInstance(ctx, db.CreateInstanceParams{Name: name, BaseUrl: "http://192.0.2.9", TlsMode: "verify", CreatedAt: 1})
		return err
	}); err != nil {
		e.t.Fatal(err)
	}
	return "i-" + itoa(id)
}

func sorted(s ...string) []string { return slices.Sorted(slices.Values(s)) }
