// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package clientreset

import (
	"context"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi/piholetest"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
)

func mustZone(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

func TestNextRun(t *testing.T) {
	london, ny := mustZone(t, "Europe/London"), mustZone(t, "America/New_York")
	at := func(loc *time.Location, s string) time.Time {
		v, err := time.ParseInLocation("2006-01-02 15:04", s, loc)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	for _, tc := range []struct {
		name  string
		sch   Schedule
		after time.Time
		want  time.Time
	}{
		{"later today", Schedule{Hour: 3, Location: time.UTC}, at(time.UTC, "2026-10-25 01:00"), at(time.UTC, "2026-10-25 03:00")},
		{"exactly then is tomorrow's", Schedule{Hour: 3, Location: time.UTC}, at(time.UTC, "2026-10-25 03:00"), at(time.UTC, "2026-10-26 03:00")},
		{"passed today", Schedule{Hour: 3, Minute: 30, Location: time.UTC}, at(time.UTC, "2026-10-25 22:04"), at(time.UTC, "2026-10-26 03:30")},
		{"in the zone, not UTC", Schedule{Hour: 3, Location: ny}, at(time.UTC, "2026-07-01 06:00"), at(time.UTC, "2026-07-01 07:00")},
		{"British summer time", Schedule{Hour: 3, Location: london}, at(time.UTC, "2026-07-01 00:00"), at(time.UTC, "2026-07-01 02:00")},
		{"after the clocks go back", Schedule{Hour: 3, Location: london}, at(time.UTC, "2026-10-25 00:00"), at(time.UTC, "2026-10-25 03:00")},
		// 01:30 doesn't exist in London on 2026-03-29: it comes out as 02:30 BST, which is 01:30 UTC.
		{"skipped by the clocks going forward", Schedule{Hour: 1, Minute: 30, Location: london}, at(time.UTC, "2026-03-29 00:00"), at(time.UTC, "2026-03-29 01:30")},
		{"the day after", Schedule{Hour: 1, Minute: 30, Location: london}, at(time.UTC, "2026-03-29 01:30"), at(time.UTC, "2026-03-30 00:30")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := NextRun(tc.sch, tc.after); !got.Equal(tc.want) {
				t.Errorf("NextRun after %s = %s, want %s", tc.after.UTC(), got.UTC(), tc.want.UTC())
			}
		})
	}

	// 01:30 happens twice in London on 2026-10-25 (BST, then GMT): it runs once that day.
	sch := Schedule{Hour: 1, Minute: 30, Location: london}
	first := NextRun(sch, at(time.UTC, "2026-10-24 12:00"))
	if second := NextRun(sch, first); second.Sub(first) < 23*time.Hour {
		t.Errorf("ran at %s and again at %s", first.UTC(), second.UTC())
	}
}

func TestSchedulerCheck(t *testing.T) {
	e := newEnv(t)
	e.gammaSetup()
	sch := Schedule{Enabled: true, Hour: 3, Location: time.UTC}
	sc := &Scheduler{Service: e.svc, Schedule: func() Schedule { return sch }}
	due := time.Date(2026, 10, 26, 3, 0, 0, 0, time.UTC)
	runs := func() int {
		r, err := e.svc.Runs(e.ctx, "", 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		return len(r)
	}

	if sc.Check(e.ctx, due.Add(-time.Minute), due.Add(-time.Second)) || runs() != 0 {
		t.Error("ran before its time")
	}
	if !sc.Check(e.ctx, due.Add(-30*time.Second), due) || runs() != 1 {
		t.Fatal("didn't run at its time")
	}
	// The next tick starts from the last check: no second run.
	if sc.Check(e.ctx, due, due.Add(30*time.Second)) || runs() != 1 {
		t.Error("ran twice")
	}
	// Found more than an hour late (the host was asleep): skipped.
	next := due.Add(24 * time.Hour)
	if sc.Check(e.ctx, next.Add(-time.Minute), next.Add(61*time.Minute)) || runs() != 1 {
		t.Error("ran a run found too late")
	}
	// An hour late at most is still run.
	if !sc.Check(e.ctx, next.Add(-time.Minute), next.Add(59*time.Minute)) || runs() != 2 {
		t.Error("didn't run a run found 59 minutes late")
	}
	sch.Enabled = false
	if sc.Check(e.ctx, due.Add(48*time.Hour-time.Minute), due.Add(48*time.Hour)) || runs() != 2 {
		t.Error("ran while off")
	}
	sch = Schedule{Enabled: true} // no location: a zone that didn't load
	if sc.Check(e.ctx, due.Add(-time.Minute), due) {
		t.Error("ran without a time zone")
	}
}

func TestRunAll(t *testing.T) {
	e := newEnv(t)
	e.gammaSetup()
	for _, n := range []string{"alpha", "beta"} {
		e.ph[n].AddGroup("AUTOSET-lab")
		e.ph[n].AddClient(piholetest.Client{Client: "10.0.0.8", Comment: "TEST-x"})
	}
	// gamma (two rules, one run), site, and beta on its own, which is then disabled and skipped.
	e.setRules(
		RuleInput{Scope: ScopeInstance, ID: e.ids["gamma"], Prefix: "TEST-", Match: MatchNames, Groups: []string{"AUTOSET-lab"}},
		RuleInput{Scope: ScopeInstance, ID: e.ids["gamma"], Prefix: "NINJA-", Match: MatchPrefixes, Groups: []string{"AUTOSET-"}},
		RuleInput{Scope: ScopeGroup, ID: e.site, Prefix: "TEST-", Match: MatchNames, Groups: []string{"AUTOSET-lab"}},
		RuleInput{Scope: ScopeInstance, ID: e.ids["beta"], Prefix: "NINJA-", Match: MatchNames, Groups: []string{"AUTOSET-lab"}},
	)
	if _, err := e.inst.SetEnabled(e.ctx, e.admin, e.ids["beta"], false); err != nil {
		t.Fatal(err)
	}
	runs := e.svc.RunAll(e.ctx)
	if len(runs) != 2 || runs[0].Target != rbac.InstanceTarget(e.ids["gamma"]).String() || runs[1].Target != rbac.GroupTarget(e.site).String() {
		t.Fatalf("runs %+v", runs)
	}
	for _, r := range runs {
		if r.Trigger != TriggerSchedule || r.Username != audit.SystemUser || r.UserID != 0 || r.Status != StatusOK {
			t.Errorf("run %+v", r)
		}
	}
	if g := runs[1].Summary.Instances; len(g) != 1 || g[0].Instance != "alpha" || len(g[0].Reset) != 1 {
		t.Errorf("site with beta disabled: %+v", g)
	}
	rows := e.auditRows(audit.ActionClientReset)
	if len(rows) == 0 || rows[0].Username != audit.SystemUser || rows[0].UserID.Valid {
		t.Errorf("audit %+v", rows)
	}

	// A cancelled pass stops before its next target.
	ctx, cancel := context.WithCancel(e.ctx)
	cancel()
	if got := e.svc.RunAll(ctx); len(got) != 0 {
		t.Errorf("a cancelled pass ran %d targets", len(got))
	}
}
