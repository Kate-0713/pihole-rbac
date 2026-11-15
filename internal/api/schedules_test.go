// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/loginsettings"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/schedules"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// withSchedules gives the server a schedule service. It must come after withInstances, and after withLoginSettings
// when a test needs the group window limit.
func withSchedules(o *Options) {
	svc := &schedules.Service{Store: o.Store, Audit: o.Audit, Instances: o.Instances, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if o.LoginSettings != nil {
		svc.Limits = o.LoginSettings.ScheduleLimits
	}
	o.Schedules = svc
}

func blockingInput(name string) gen.ScheduleInput {
	return gen.ScheduleInput{Name: name, Kind: "blocking_off", Repeat: "weekly", Days: ptr(31), Start: ptr("08:00"),
		End: ptr("08:30"), TimeZone: ptr("Europe/London")}
}

func windowInput(name, group string) gen.ScheduleInput {
	return gen.ScheduleInput{Name: name, Kind: "group_enabled", PiholeGroup: ptr(group), Repeat: "weekly", Days: ptr(127),
		Start: ptr("21:00"), End: ptr("07:00"), EndDays: ptr(1), TimeZone: ptr("UTC")}
}

func schedulePath(te *targetEnv, id int64) string {
	return te.path("/schedules/" + strconv.FormatInt(id, 10))
}

func TestScheduleCRUD(t *testing.T) {
	te := newTargetEnv(t, withSchedules)
	te.ph.AddGroup("bedtime")
	res := te.admin.do(http.MethodPost, te.path("/schedules"), blockingInput("Lab mornings"))
	mustStatus(t, res, http.StatusCreated)
	lab := decode[gen.Schedule](t, res)
	if lab.Target != te.target || lab.TargetName != "pihole1" || !lab.Enabled || lab.LengthMinutes != 30 || *lab.Start != "08:00" ||
		*lab.TimeZone != "Europe/London" || lab.NextEdge == nil || lab.NextEdge.Edge != "start" || len(lab.Results) != 0 || lab.CreatedBy != "admin" {
		t.Errorf("created %+v", lab)
	}
	row, detail := te.lastAudit()
	if row.Action != audit.ActionScheduleCreate || detail["name"] != "Lab mornings" || detail["start"] != "08:00" {
		t.Errorf("audit %s %v", row.Action, detail)
	}
	res = te.admin.do(http.MethodPost, te.path("/schedules"), windowInput("Bedtime", "bedtime"))
	mustStatus(t, res, http.StatusCreated)
	if res := te.admin.do(http.MethodPost, te.path("/schedules"), blockingInput("LAB MORNINGS")); res.Code != http.StatusConflict {
		t.Errorf("a taken name: %d %s", res.Code, res.Body)
	}

	list := decode[gen.ScheduleList](t, te.admin.do(http.MethodGet, te.path("/schedules"), nil))
	if len(list.Schedules) != 2 || list.Schedules[0].Name != "Bedtime" || *list.Schedules[0].PiholeGroup != "bedtime" || len(list.FromGroups) != 0 ||
		list.GroupWindowMaxMinutes != 1440 {
		t.Errorf("list %+v", list)
	}

	res = te.admin.do(http.MethodPatch, schedulePath(te, lab.Id), gen.ScheduleUpdate{End: ptr("09:00"), Enabled: ptr(false)})
	mustStatus(t, res, http.StatusOK)
	changed := decode[gen.Schedule](t, res)
	if *changed.End != "09:00" || changed.Enabled || *changed.Start != "08:00" || changed.LengthMinutes != 60 || changed.NextEdge != nil {
		t.Errorf("changed %+v", changed)
	}
	row, detail = te.lastAudit()
	if row.Action != audit.ActionScheduleUpdate || detail["end"] != "09:00" || detail["before"].(map[string]any)["end"] != "08:30" {
		t.Errorf("update audit %s %v", row.Action, detail)
	}
	// Changing to a one-off needs its own fields.
	res = te.admin.do(http.MethodPatch, schedulePath(te, lab.Id), gen.ScheduleUpdate{Repeat: ptr(gen.ScheduleRepeat("once"))})
	if res.Code != http.StatusBadRequest || errorDetails(t, res)["field"] != "starts_at" {
		t.Errorf("to once without times: %d %s", res.Code, res.Body)
	}
	start := time.Now().Add(time.Hour).Truncate(time.Second)
	res = te.admin.do(http.MethodPatch, schedulePath(te, lab.Id), gen.ScheduleUpdate{Repeat: ptr(gen.ScheduleRepeat("once")),
		StartsAt: ptr(start), EndsAt: ptr(start.Add(2 * time.Hour))})
	mustStatus(t, res, http.StatusOK)
	if once := decode[gen.Schedule](t, res); once.Days != nil || !once.StartsAt.Equal(start) || once.LengthMinutes != 120 {
		t.Errorf("to once %+v", once)
	}

	if res := te.admin.do(http.MethodGet, te.path("/schedules/999"), nil); res.Code != http.StatusNotFound {
		t.Errorf("a missing schedule: %d", res.Code)
	}
	other := te.addInstance("pihole2")
	if res := te.admin.do(http.MethodGet, "/api/v1/targets/"+other+"/schedules/"+strconv.FormatInt(lab.Id, 10), nil); res.Code != http.StatusNotFound {
		t.Errorf("a schedule through another target: %d", res.Code)
	}
	mustStatus(t, te.admin.do(http.MethodDelete, schedulePath(te, lab.Id), nil), http.StatusNoContent)
	if row, _ := te.lastAudit(); row.Action != audit.ActionScheduleDelete {
		t.Errorf("delete audit %s", row.Action)
	}
	if res := te.admin.do(http.MethodGet, schedulePath(te, lab.Id), nil); res.Code != http.StatusNotFound {
		t.Errorf("after deleting: %d", res.Code)
	}
}

// TestSchedulePermissions: schedules need schedules.manage on the target, and a save also needs what the schedule does
// (blocking.toggle, or piholegroups.edit); a delete needs schedules.manage alone; the status needs any permission.
func TestSchedulePermissions(t *testing.T) {
	te := newTargetEnv(t, withSchedules)
	te.ph.AddGroup("bedtime")
	te.addGrantUser("planner", "planner-password-1", grant(rbac.SchedulesManage, "instance", te.id))
	te.addGrantUser("blocker", "blocker-password-1", grant(rbac.SchedulesManage, "instance", te.id), grant(rbac.BlockingToggle, "instance", te.id))
	te.addGrantUser("grouper", "grouper-password-1", grant(rbac.SchedulesManage, "instance", te.id), grant(rbac.PiholeGroupsEdit, "instance", te.id))
	te.addGrantUser("viewer", "viewer-password-1", grant(rbac.DomainsView, "instance", te.id))
	planner, blocker := te.loggedIn("planner", "planner-password-1"), te.loggedIn("blocker", "blocker-password-1")
	grouper, viewer := te.loggedIn("grouper", "grouper-password-1"), te.loggedIn("viewer", "viewer-password-1")

	for _, tt := range []struct {
		who  *client
		in   gen.ScheduleInput
		want int
	}{
		{planner, blockingInput("a"), http.StatusForbidden},
		{planner, windowInput("b", "bedtime"), http.StatusForbidden},
		{grouper, blockingInput("c"), http.StatusForbidden},
		{blocker, windowInput("d", "bedtime"), http.StatusForbidden},
		{blocker, blockingInput("e"), http.StatusCreated},
		{grouper, windowInput("f", "bedtime"), http.StatusCreated},
		{viewer, blockingInput("g"), http.StatusForbidden},
	} {
		if res := tt.who.do(http.MethodPost, te.path("/schedules"), tt.in); res.Code != tt.want {
			t.Errorf("%s: %d %s, want %d", tt.in.Name, res.Code, res.Body, tt.want)
		}
	}
	list := decode[gen.ScheduleList](t, planner.do(http.MethodGet, te.path("/schedules"), nil))
	if len(list.Schedules) != 2 {
		t.Fatalf("list %+v", list)
	}
	byName := map[string]int64{}
	for _, sc := range list.Schedules {
		byName[sc.Name] = sc.Id
	}
	if res := planner.do(http.MethodPatch, schedulePath(te, byName["e"]), gen.ScheduleUpdate{End: ptr("09:00")}); res.Code != http.StatusForbidden {
		t.Errorf("changing without blocking.toggle: %d", res.Code)
	}
	if res := viewer.do(http.MethodGet, te.path("/schedules"), nil); res.Code != http.StatusForbidden {
		t.Errorf("listing without schedules.manage: %d", res.Code)
	}
	if st := decode[gen.ScheduleStatus](t, viewer.do(http.MethodGet, te.path("/schedules/status"), nil)); len(st.Schedules) != 2 {
		t.Errorf("status for a viewer %+v", st)
	}
	mustStatus(t, planner.do(http.MethodDelete, schedulePath(te, byName["e"]), nil), http.StatusNoContent)
}

func TestScheduleValidation(t *testing.T) {
	var login *loginsettings.Service
	te := newTargetEnv(t, withLoginSettings(t, &login), withSchedules)
	te.ph.AddGroup("bedtime")
	future := time.Now().Add(time.Hour)
	for _, tt := range []struct {
		name  string
		in    gen.ScheduleInput
		field string
		code  int
	}{
		{"the Default group", windowInput("x", "Default"), "pihole_group", http.StatusBadRequest},
		{"a group Pi-hole doesn't have", windowInput("x", "nobody"), "pihole_group", http.StatusBadRequest},
		{"a group window without a group", gen.ScheduleInput{Name: "x", Kind: "group_enabled", Repeat: "weekly", Days: ptr(1), Start: ptr("08:00"), End: ptr("09:00"), TimeZone: ptr("UTC")}, "pihole_group", http.StatusBadRequest},
		{"an unknown zone", func() gen.ScheduleInput { in := blockingInput("x"); in.TimeZone = ptr("Mars/Olympus"); return in }(), "time_zone", http.StatusBadRequest},
		{"weekly without days", func() gen.ScheduleInput { in := blockingInput("x"); in.Days = nil; return in }(), "days", http.StatusBadRequest},
		{"past midnight without end_days", func() gen.ScheduleInput { in := windowInput("x", "bedtime"); in.EndDays = nil; return in }(), "end", http.StatusBadRequest},
		{"a one-off in the past", gen.ScheduleInput{Name: "x", Kind: "blocking_off", Repeat: "once", StartsAt: ptr(time.Now().Add(-time.Hour)), EndsAt: ptr(future)}, "starts_at", http.StatusBadRequest},
		{"a one-off without an end", gen.ScheduleInput{Name: "x", Kind: "blocking_off", Repeat: "once", StartsAt: ptr(future)}, "ends_at", http.StatusBadRequest},
		{"an unknown kind", gen.ScheduleInput{Name: "x", Kind: "blocking_on", Repeat: "once"}, "kind", http.StatusBadRequest},
	} {
		res := te.admin.do(http.MethodPost, te.path("/schedules"), tt.in)
		if res.Code != tt.code || errorDetails(t, res)["field"] != tt.field {
			t.Errorf("%s: %d %s", tt.name, res.Code, res.Body)
		}
	}
	if len(te.ph.Requests()) == 0 {
		t.Fatal("the group checks didn't read Pi-hole")
	}

	// The group window limit comes from the general settings.
	res := te.admin.do(http.MethodPut, "/api/v1/settings/general", gen.GeneralSettingsInput{
		SessionLifetimeMinutes: 480, IdleTimeoutMinutes: 60, ScheduleGroupWindowMaxMinutes: ptr(360),
	})
	mustStatus(t, res, http.StatusOK)
	if g := decode[gen.GeneralSettings](t, res); g.ScheduleGroupWindowMaxMinutes != 360 {
		t.Errorf("settings %+v", g)
	}
	res = te.admin.do(http.MethodPost, te.path("/schedules"), windowInput("Bedtime", "bedtime"))
	if res.Code != http.StatusBadRequest || errorDetails(t, res)["max_minutes"] != float64(360) {
		t.Errorf("over the limit: %d %s", res.Code, res.Body)
	}
	in := windowInput("Bedtime", "bedtime")
	in.Start = ptr("22:00")
	in.End = ptr("04:00")
	mustStatus(t, te.admin.do(http.MethodPost, te.path("/schedules"), in), http.StatusCreated)
	// Lowered later: the schedule is marked over the limit, but keeps running.
	mustStatus(t, te.admin.do(http.MethodPut, "/api/v1/settings/general", gen.GeneralSettingsInput{
		SessionLifetimeMinutes: 480, IdleTimeoutMinutes: 60, ScheduleGroupWindowMaxMinutes: ptr(60),
	}), http.StatusOK)
	list := decode[gen.ScheduleList](t, te.admin.do(http.MethodGet, te.path("/schedules"), nil))
	if len(list.Schedules) != 1 || !list.Schedules[0].OverLimit || !list.Schedules[0].Enabled || list.GroupWindowMaxMinutes != 60 {
		t.Errorf("after lowering the limit %+v", list.Schedules)
	}
}

// TestGroupSchedules: a schedule on a mirrored group is checked on its primary, shows in each member's from_groups for
// someone who manages it, and in the members' status.
func TestGroupSchedules(t *testing.T) {
	ge := newGroupEnv(t, withSchedules)
	ge.ph["alpha"].AddGroup("bedtime")
	res := ge.admin.do(http.MethodPost, ge.path("/schedules"), windowInput("Bedtime", "bedtime"))
	mustStatus(t, res, http.StatusCreated)
	if sc := decode[gen.Schedule](t, res); sc.TargetName != "site" {
		t.Errorf("created %+v", sc)
	}
	list := decode[gen.ScheduleList](t, ge.admin.do(http.MethodGet, ge.instPath("beta", "/schedules"), nil))
	if len(list.Schedules) != 0 || len(list.FromGroups) != 1 || list.FromGroups[0].Name != "Bedtime" {
		t.Errorf("beta's list %+v", list)
	}
	ge.addGrantUser("local", "local-password-1", grant(rbac.SchedulesManage, "instance", ge.ids["beta"]))
	local := ge.loggedIn("local", "local-password-1")
	if list := decode[gen.ScheduleList](t, local.do(http.MethodGet, ge.instPath("beta", "/schedules"), nil)); len(list.FromGroups) != 0 {
		t.Errorf("the group's schedules shown without schedules.manage on it: %+v", list.FromGroups)
	}
	st := decode[gen.ScheduleStatus](t, local.do(http.MethodGet, ge.instPath("beta", "/schedules/status"), nil))
	if len(st.Schedules) != 1 || st.Schedules[0].Target != ge.target || st.Schedules[0].NextEdge == nil {
		t.Errorf("beta's status %+v", st)
	}
	// The primary has no group of that name: refused, though the other members might have one.
	ge.ph["beta"].AddGroup("kids")
	if res := ge.admin.do(http.MethodPost, ge.path("/schedules"), windowInput("Kids", "kids")); res.Code != http.StatusBadRequest {
		t.Errorf("a group only a member has: %d %s", res.Code, res.Body)
	}
}

// TestScheduleStatus: the status lists the open window first, with when it ends, and leaves out schedules that are
// off.
func TestScheduleStatus(t *testing.T) {
	te := newTargetEnv(t, withSchedules)
	now := time.Now().UTC()
	open := gen.ScheduleInput{Name: "Now", Kind: "blocking_off", Repeat: "weekly", Days: ptr(127),
		Start: ptr(now.Add(-time.Hour).Format("15:04")), End: ptr(now.Add(time.Hour).Format("15:04")), TimeZone: ptr("UTC")}
	if now.Add(-time.Hour).Day() != now.Add(time.Hour).Day() {
		t.Skip("too close to midnight UTC for this window")
	}
	mustStatus(t, te.admin.do(http.MethodPost, te.path("/schedules"), open), http.StatusCreated)
	later := blockingInput("Later")
	mustStatus(t, te.admin.do(http.MethodPost, te.path("/schedules"), later), http.StatusCreated)
	off := blockingInput("Off")
	off.Enabled = ptr(false)
	mustStatus(t, te.admin.do(http.MethodPost, te.path("/schedules"), off), http.StatusCreated)
	// A one-off whose window has passed, which the scheduler hasn't marked finished yet: nothing to say about it.
	soon := time.Now().Add(time.Hour)
	res := te.admin.do(http.MethodPost, te.path("/schedules"), gen.ScheduleInput{Name: "Passed", Kind: "blocking_off", Repeat: "once", StartsAt: &soon, EndsAt: ptr(soon.Add(time.Minute))})
	mustStatus(t, res, http.StatusCreated)
	passed := decode[gen.Schedule](t, res)
	ago := func(d time.Duration) sql.NullInt64 {
		return sql.NullInt64{Int64: time.Now().Add(-d).UnixMilli(), Valid: true}
	}
	if err := te.st.WithTx(context.Background(), func(q *db.Queries) error {
		return q.UpdateSchedule(context.Background(), db.UpdateScheduleParams{Name: "Passed", Repeat: "once", StartsAt: ago(2 * time.Hour),
			EndsAt: ago(time.Hour), ActiveFrom: ago(3 * time.Hour).Int64, Enabled: 1, UpdatedAt: 1, UpdatedBy: "admin", ID: passed.Id})
	}); err != nil {
		t.Fatal(err)
	}
	st := decode[gen.ScheduleStatus](t, te.admin.do(http.MethodGet, te.path("/schedules/status"), nil))
	if len(st.Schedules) != 2 || st.Schedules[0].Name != "Now" || !st.Schedules[0].Open || st.Schedules[0].OpenUntil == nil ||
		st.Schedules[1].Name != "Later" || st.Schedules[1].Open {
		t.Errorf("status %+v", st)
	}
}
