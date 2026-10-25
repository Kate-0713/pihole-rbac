// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package notifications

import (
	"context"
	"database/sql"
	"slices"
	"strings"
	"testing"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/notify"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

func TestProtectedAdded(t *testing.T) {
	for _, tt := range []struct {
		before, after, protected, want []string
	}{
		{[]string{"Default"}, []string{"Default", "Kids"}, []string{"kids"}, []string{"Kids"}},
		{[]string{"Kids"}, []string{"Kids"}, []string{"kids"}, nil},
		{[]string{"Default"}, []string{"Default", "Guests"}, []string{"kids"}, nil},
		{nil, []string{"Kids", "Guests", "KIDS"}, []string{"KIDS", "guests"}, []string{"Kids", "Guests"}},
		{[]string{"Kids"}, nil, []string{"kids"}, nil},
	} {
		if got := ProtectedAdded(tt.before, tt.after, tt.protected); !slices.Equal(got, tt.want) {
			t.Errorf("%v → %v with %v: %v, want %v", tt.before, tt.after, tt.protected, got, tt.want)
		}
	}
}

// seedInstances adds instances a, b and c, with a and b in the mirrored group m and c in the independent group i.
func (e *env) seedInstances() (ids map[string]int64, mirrored, independent int64) {
	e.t.Helper()
	ctx := context.Background()
	ids = map[string]int64{}
	if err := e.st.WithTx(ctx, func(q *db.Queries) error {
		for _, n := range []string{"a", "b", "c"} {
			id, err := q.CreateInstance(ctx, db.CreateInstanceParams{Name: n, BaseUrl: "http://" + n + ".lan", TlsMode: "verify", CreatedAt: 1})
			if err != nil {
				return err
			}
			ids[n] = id
		}
		var err error
		if mirrored, err = q.CreateInstanceGroup(ctx, db.CreateInstanceGroupParams{Name: "m", Mode: "mirrored",
			PrimaryInstanceID: sql.NullInt64{Int64: ids["a"], Valid: true}, CreatedAt: 1}); err != nil {
			return err
		}
		if independent, err = q.CreateInstanceGroup(ctx, db.CreateInstanceGroupParams{Name: "i", Mode: "independent", CreatedAt: 1}); err != nil {
			return err
		}
		for _, m := range []db.AddInstanceGroupMemberParams{
			{GroupID: mirrored, InstanceID: ids["a"]}, {GroupID: mirrored, InstanceID: ids["b"]}, {GroupID: independent, InstanceID: ids["c"]},
		} {
			if err := q.AddInstanceGroupMember(ctx, m); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		e.t.Fatal(err)
	}
	return ids, mirrored, independent
}

func TestProtectedFor(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ids, mirrored, independent := e.seedInstances()
	if _, err := e.svc.SetProtectedGroups(ctx, e.admin, []ProtectedInput{
		{Scope: ScopeInstance, ID: ids["a"], Groups: []string{"Kids"}},
		{Scope: ScopeGroup, ID: mirrored, Groups: []string{"Guests"}},
		{Scope: ScopeInstance, ID: ids["c"], Groups: []string{"Lab"}},
	}); err != nil {
		t.Fatal(err)
	}
	// An independent group can't be a scope.
	if _, err := e.svc.SetProtectedGroups(ctx, e.admin, []ProtectedInput{{Scope: ScopeGroup, ID: independent, Groups: []string{"x"}}}); field(err) != "id" {
		t.Errorf("independent group: %v", err)
	}
	// c's independent group adds nothing; it has only its own.
	for n, want := range map[string]string{"a": "Guests,Kids", "b": "Guests", "c": "Lab"} {
		got, err := e.svc.ProtectedFor(ctx, ids[n])
		slices.Sort(got)
		if err != nil || strings.Join(got, ",") != want {
			t.Errorf("%s: %v, %v; want %s", n, got, err, want)
		}
	}

	// Deleting an instance takes its protected groups with it.
	if err := e.st.WithTx(ctx, func(q *db.Queries) error {
		if err := q.RemoveInstanceGroupMember(ctx, db.RemoveInstanceGroupMemberParams{GroupID: independent, InstanceID: ids["c"]}); err != nil {
			return err
		}
		return q.DeleteInstance(ctx, ids["c"])
	}); err != nil {
		t.Fatal(err)
	}
	got, _ := e.svc.ProtectedGroups(ctx)
	if len(got.Entries) != 2 || slices.ContainsFunc(got.Entries, func(p Protected) bool { return p.Name == "c" }) {
		t.Errorf("after deleting c: %+v", got.Entries)
	}
}

func TestProtectedGroupsGuardAndPermission(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ids, _, _ := e.seedInstances()
	if _, err := e.svc.Create(ctx, e.admin, Input{Kind: notify.Discord, Name: "Alerts", Enabled: true, Secret: val(hook("81")),
		Events: []string{notify.EventProtectedGroupAdd}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Create(ctx, e.admin, Input{Kind: notify.Discord, Name: "Other", Enabled: true, Secret: val(hook("82")),
		Events: []string{audit.ActionLogin}}); err != nil {
		t.Fatal(err)
	}
	set := func(groups ...string) error {
		_, err := e.svc.SetProtectedGroups(ctx, e.admin, []ProtectedInput{{Scope: ScopeInstance, ID: ids["b"], Groups: groups}})
		return err
	}
	if err := set("Kids", "Guests"); err != nil {
		t.Fatal(err)
	}
	if err := set("Guests"); err != nil {
		t.Fatal(err)
	}
	got := e.sink.waitFor(t, "81", 1)
	if !strings.Contains(got[0], "no more alerts when a client is added to Kids on b") || !strings.Contains(got[0], "admin") {
		t.Errorf("guard: %q", got[0])
	}
	if n := len(e.sink.to("82")); n != 0 {
		t.Errorf("a channel without protected_group_add was told: %d", n)
	}
	row := e.rows()[0]
	if row.Action != audit.ActionProtectedGroups || !strings.Contains(row.Detail, `"removed":["Kids on b"]`) {
		t.Errorf("audit row: %+v", row)
	}

	if _, err := e.svc.SetProtectedGroups(ctx, e.nobody, nil); code(err) != "forbidden" {
		t.Errorf("without the permission: %v", err)
	}
	if e.rows()[0].Action != audit.ActionPermissionDenied {
		t.Errorf("the refusal wasn't recorded: %s", e.rows()[0].Action)
	}
}
