// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package piholegroups_test

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"reflect"
	"testing"

	"github.com/Kate-0713/pihole-rbac/internal/piholegroups"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// TestLoadAndApply reads the references from a real database, renames kids to children on pihole1, and reads them
// back: the names-mode rule, the protected group and the group window on pihole1 follow, a protected group whose
// scope already lists the new name is dropped, a blocking window isn't a reference, and pihole2's are renamed too.
func TestLoadAndApply(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, store.Options{DataDir: t.TempDir(), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	var p1, p2 int64
	if err := st.WithTx(ctx, func(q *db.Queries) error {
		var err error
		if p1, err = q.CreateInstance(ctx, db.CreateInstanceParams{Name: "pihole1", BaseUrl: "http://192.0.2.1", TlsMode: "verify", CreatedAt: 1}); err != nil {
			return err
		}
		if p2, err = q.CreateInstance(ctx, db.CreateInstanceParams{Name: "pihole2", BaseUrl: "http://192.0.2.2", TlsMode: "verify", CreatedAt: 1}); err != nil {
			return err
		}
		inst := func(id int64) sql.NullInt64 { return sql.NullInt64{Int64: id, Valid: true} }
		for _, r := range []db.AddClientResetRuleParams{
			{InstanceID: inst(p1), CommentPrefix: "TEST-", GroupMatch: "names", TargetGroups: `["Default","kids"]`},
			{InstanceID: inst(p1), CommentPrefix: "LAB-", GroupMatch: "prefixes", TargetGroups: `["chil"]`},
			{InstanceID: inst(p2), CommentPrefix: "TEST-", GroupMatch: "names", TargetGroups: `["kids"]`},
		} {
			if err := q.AddClientResetRule(ctx, r); err != nil {
				return err
			}
		}
		for _, p := range []db.AddProtectedGroupParams{
			{InstanceID: inst(p1), PiholeGroup: "Kids"},
			{InstanceID: inst(p2), PiholeGroup: "kids"},
			{InstanceID: inst(p2), PiholeGroup: "children"},
		} {
			if err := q.AddProtectedGroup(ctx, p); err != nil {
				return err
			}
		}
		for _, w := range []db.CreateScheduleParams{
			{Name: "Bedtime", InstanceID: inst(p1), Kind: "group_enabled", PiholeGroup: sql.NullString{String: "kids", Valid: true}},
			{Name: "Lab mornings", InstanceID: inst(p1), Kind: "blocking_off"},
		} {
			w.Repeat, w.StartsAt, w.EndsAt, w.ActiveFrom, w.Enabled, w.CreatedBy, w.UpdatedBy = "once", inst(10), inst(20), 1, 1, "admin", "admin"
			if _, err := q.CreateSchedule(ctx, w); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	refs, err := piholegroups.Load(ctx, st.Read())
	if err != nil {
		t.Fatal(err)
	}
	s1, s2 := piholegroups.Scope{InstanceID: p1}, piholegroups.Scope{InstanceID: p2}
	if c := piholegroups.Count(piholegroups.Matching(refs, []piholegroups.Scope{s1}, "kids")); c != (piholegroups.Counts{ResetRules: 1, Protected: 1, GroupWindows: 1}) {
		t.Errorf("counts on pihole1: %+v", c)
	}
	rename := func(s piholegroups.Scope) {
		t.Helper()
		var in []piholegroups.Ref
		for _, r := range refs {
			if r.Scope == s {
				in = append(in, r)
			}
		}
		plan := piholegroups.PlanRename(in, "kids", "children", piholegroups.Renamed{
			Renamed: func(piholegroups.Scope) bool { return true },
			Left:    func(piholegroups.Scope) []string { return []string{"Default", "children"} },
		})
		if err := st.WithTx(ctx, func(q *db.Queries) error { return piholegroups.Apply(ctx, q, plan) }); err != nil {
			t.Fatal(err)
		}
	}
	rename(s1)
	rename(s2)

	after, err := piholegroups.Load(ctx, st.Read())
	if err != nil {
		t.Fatal(err)
	}
	type row struct {
		kind   piholegroups.Kind
		scope  string
		groups []string
		name   string
	}
	var got []row
	for _, r := range after {
		got = append(got, row{r.Kind, r.ScopeName, r.Groups, r.Name})
	}
	want := []row{
		{piholegroups.KindResetRule, "pihole1", []string{"chil"}, ""},
		{piholegroups.KindResetRule, "pihole1", []string{"Default", "children"}, ""},
		{piholegroups.KindResetRule, "pihole2", []string{"children"}, ""},
		{piholegroups.KindProtected, "pihole1", nil, "children"},
		{piholegroups.KindProtected, "pihole2", nil, "children"},
		{piholegroups.KindWindow, "pihole1", nil, "children"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("after the rename:\n got %+v\nwant %+v", got, want)
	}
}
