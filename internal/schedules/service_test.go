// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package schedules

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/instances"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi/piholetest"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

const password = "app-password"

type passwords struct{}

func (passwords) InstancePassword(string) (secrets.Value, bool) {
	return secrets.NewValue([]byte(password)), true
}
func (passwords) Cipher() *secrets.Cipher { return nil }

// sink keeps the audit entries, as the notifier would get them.
type sink struct {
	mu      sync.Mutex
	entries []audit.Entry
}

func (s *sink) add(e audit.Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, e)
}

// take returns the entries since the last take.
func (s *sink) take() []audit.Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.entries
	s.entries = nil
	return out
}

// env is three enabled instances on fake Pi-holes: alpha and beta in the mirrored group "site" (alpha the primary),
// and gamma on its own, each with a disabled Pi-hole group "bedtime"; and a clock the test moves.
type env struct {
	t     *testing.T
	ctx   context.Context
	st    *store.Store
	inst  *instances.Service
	svc   *Service
	ph    map[string]*piholetest.Server
	ids   map[string]int64
	site  rbac.Target
	admin rbac.Actor
	sunk  *sink
	now   time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(ctx, store.Options{DataDir: t.TempDir(), Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	pool := instances.New(instances.Options{Passwords: passwords{}, Timeout: 2 * time.Second, Logger: logger})
	t.Cleanup(func() { pool.Close(context.Background()) })
	auditLog := audit.NewLogger(io.Discard)
	e := &env{t: t, ctx: ctx, st: st, ph: map[string]*piholetest.Server{}, ids: map[string]int64{}, sunk: &sink{}}
	auditLog.SetSink(e.sunk.add)
	e.inst = &instances.Service{Store: st, Audit: auditLog, Pool: pool}
	e.svc = &Service{Store: st, Audit: auditLog, Instances: e.inst, Logger: logger, Now: func() time.Time { return e.now }}
	if err := st.WithTx(ctx, func(q *db.Queries) error {
		role, err := q.GetBuiltinRole(ctx)
		if err != nil {
			return err
		}
		u, err := q.CreateLocalUser(ctx, db.CreateLocalUserParams{Username: "alice", PasswordHash: sql.NullString{String: "x", Valid: true}, CreatedAt: 1})
		e.admin = rbac.Actor{UserID: u.ID, Username: "alice", RoleIDs: []int64{role.ID}, IP: "192.0.2.1"}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"alpha", "beta", "gamma"} {
		ph := piholetest.New(t, password)
		ph.AddGroup("bedtime")
		pw := secrets.NewValue([]byte(password))
		inst, err := e.inst.Create(ctx, e.admin, instances.Input{Name: n, BaseURL: ph.URL, EnvName: strings.ToUpper(n), Password: &pw})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.inst.SetEnabled(ctx, e.admin, inst.ID, true); err != nil {
			t.Fatal(err)
		}
		e.ph[n], e.ids[n] = ph, inst.ID
	}
	g, err := e.inst.CreateGroup(ctx, e.admin, instances.GroupInput{Name: "site", Mode: rbac.Mirrored, Primary: e.ids["alpha"],
		Members: []int64{e.ids["alpha"], e.ids["beta"]}})
	if err != nil {
		t.Fatal(err)
	}
	e.site = rbac.GroupTarget(g.ID)
	e.setGroup("alpha", "bedtime", false)
	e.setGroup("beta", "bedtime", false)
	e.setGroup("gamma", "bedtime", false)
	e.sunk.take()
	return e
}

func (e *env) target(name string) rbac.Target { return rbac.InstanceTarget(e.ids[name]) }

// at sets the clock to a time in UTC: "2027-03-01 08:00" (a Monday).
func (e *env) at(s string) time.Time {
	e.t.Helper()
	v, err := time.ParseInLocation("2006-01-02 15:04", s, time.UTC)
	if err != nil {
		e.t.Fatal(err)
	}
	e.now = v
	return v
}

func (e *env) check(when string) []audit.Entry {
	e.t.Helper()
	e.at(when)
	e.svc.Check(e.ctx)
	return e.sunk.take()
}

func (e *env) create(t rbac.Target, in Input) Schedule {
	e.t.Helper()
	sc, err := e.svc.Create(e.ctx, e.admin, t, in)
	if err != nil {
		e.t.Fatal(err)
	}
	e.sunk.take()
	return sc
}

func (e *env) get(id int64) Schedule {
	e.t.Helper()
	sc, err := e.svc.Get(e.ctx, id)
	if err != nil {
		e.t.Fatal(err)
	}
	return sc
}

func (e *env) setGroup(instance, name string, enabled bool) {
	e.t.Helper()
	if err := e.inst.Pool.Do(e.ctx, e.ids[instance], func(ctx context.Context, c *piholeapi.Client) error {
		gs, err := c.ListGroups(ctx)
		if err != nil {
			return err
		}
		for _, g := range gs {
			if g.Name == name {
				g.Enabled = enabled
				return c.UpdateGroup(ctx, g)
			}
		}
		return nil
	}); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) groupOn(instance, name string) bool {
	e.t.Helper()
	for _, g := range e.ph[instance].Groups() {
		if g.Name == name {
			return g.Enabled
		}
	}
	e.t.Fatalf("no group %s on %s", name, instance)
	return false
}

// blocking returns whether blocking is on, and the timer in seconds (-1 for none).
func (e *env) blocking(instance string) (bool, int) {
	on, timer := e.ph[instance].Blocking()
	if timer == nil {
		return on, -1
	}
	return on, int(*timer)
}

func (e *env) setBlocking(instance string, on bool, timer time.Duration) {
	e.t.Helper()
	if err := e.inst.Pool.Do(e.ctx, e.ids[instance], func(ctx context.Context, c *piholeapi.Client) error {
		_, err := c.SetBlocking(ctx, on, timer)
		return err
	}); err != nil {
		e.t.Fatal(err)
	}
}

func weeklyUTC(days int, start, end string, endDays int) Window {
	return weekly(time.UTC, days, start, end, endDays)
}

func onceUTC(t *testing.T, start, end string) Window {
	return Window{Repeat: RepeatOnce, StartsAt: at(t, time.UTC, start), EndsAt: at(t, time.UTC, end)}
}

func runRows(t *testing.T, entries []audit.Entry) []string {
	t.Helper()
	var out []string
	for _, en := range entries {
		if en.Action != audit.ActionScheduleRun {
			t.Errorf("unexpected %s", en.Action)
			continue
		}
		s := en.InstanceName + " " + en.Detail["edge"].(string)
		if en.Err != nil {
			s += " failed " + en.Detail["error_code"].(string)
		}
		if en.Detail["retry"] == true {
			s += " retry"
		}
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}

func TestSchedulerBlocking(t *testing.T) {
	e := newEnv(t)
	e.at("2027-03-01 07:00")
	lab := e.create(e.target("gamma"), Input{Spec{Name: "Lab mornings", Kind: KindBlockingOff, Window: weeklyUTC(weekdays, "08:00", "08:30", 0)}, true})

	if rows := e.check("2027-03-01 07:59"); len(rows) != 0 {
		t.Errorf("before the start: %v", rows)
	}
	rows := e.check("2027-03-01 08:00")
	if got := runRows(t, rows); !slices.Equal(got, []string{"gamma start"}) {
		t.Fatalf("at the start: %v", got)
	}
	if on, timer := e.blocking("gamma"); on || timer != 1800 {
		t.Errorf("blocking %v, timer %d", on, timer)
	}
	if d := rows[0].Detail; d["timer"] != int64(1800) || d["schedule"] != "Lab mornings" || rows[0].Username != audit.SystemUser ||
		d["summary"] != "Lab mornings: blocking off until 08:30 UTC" {
		t.Errorf("row %+v", rows[0])
	}
	sc := e.get(lab.ID)
	if sc.LastEdge != "start" || sc.Results[e.ids["gamma"]].Status != StatusOK {
		t.Errorf("recorded %+v", sc)
	}

	// Turned back on by hand: the scheduler never re-applies between edges.
	e.setBlocking("gamma", true, 0)
	if rows := e.check("2027-03-01 08:10"); len(rows) != 0 {
		t.Errorf("between edges: %v", rows)
	}
	if on, _ := e.blocking("gamma"); !on {
		t.Error("a manual change was undone")
	}
	// The end sends nothing: Pi-hole's timer ends the window.
	if rows := e.check("2027-03-01 08:30"); len(rows) != 0 {
		t.Errorf("at the end: %v", rows)
	}
	if e.get(lab.ID).LastEdge != "end" {
		t.Error("the end wasn't recorded")
	}

	// Off by hand with no timer: left alone, and nothing audited.
	e.setBlocking("gamma", false, 0)
	if rows := e.check("2027-03-02 08:00"); len(rows) != 0 {
		t.Errorf("off by hand: %v", rows)
	}
	if on, timer := e.blocking("gamma"); on || timer != -1 {
		t.Errorf("off by hand became %v, %d", on, timer)
	}
	if r := e.get(lab.ID).Results[e.ids["gamma"]]; r.Skip != SkipUnchanged {
		t.Errorf("result %+v", r)
	}
}

// TestSchedulerLateAndOverlapping: a start missed while the app was down applies for what remains, a window inside
// another doesn't cut it short, and a start found after its window ended does nothing.
func TestSchedulerLateAndOverlapping(t *testing.T) {
	e := newEnv(t)
	e.at("2027-03-01 07:00")
	e.create(e.target("gamma"), Input{Spec{Name: "Long", Kind: KindBlockingOff, Window: onceUTC(t, "2027-03-01 08:00", "2027-03-01 10:00")}, true})
	e.create(e.target("gamma"), Input{Spec{Name: "Short", Kind: KindBlockingOff, Window: onceUTC(t, "2027-03-01 08:00", "2027-03-01 08:30")}, true})
	rows := e.check("2027-03-01 08:20") // twenty minutes late
	if got := runRows(t, rows); !slices.Equal(got, []string{"gamma start"}) {
		t.Fatalf("rows %v", got)
	}
	if on, timer := e.blocking("gamma"); on || timer != 100*60 {
		t.Errorf("blocking %v, timer %d: want off until 10:00", on, timer)
	}

	e.setBlocking("gamma", true, 0)
	e.create(e.target("gamma"), Input{Spec{Name: "Missed", Kind: KindBlockingOff, Window: onceUTC(t, "2027-03-01 11:00", "2027-03-01 11:30")}, true})
	if rows := e.check("2027-03-01 11:40"); len(rows) != 0 {
		t.Errorf("a window found after it ended: %v", rows)
	}
	if on, _ := e.blocking("gamma"); !on {
		t.Error("blocking turned off after the window")
	}
}

// TestSchedulerGroupWindows: a group window through a mirrored group switches the group on every member; another
// window for the same group on one member holds it on there past the first one's end; a new schedule acts from its
// next edge.
func TestSchedulerGroupWindows(t *testing.T) {
	e := newEnv(t)
	e.at("2027-03-01 12:00")
	bedtime := e.create(e.site, Input{Spec{Name: "Bedtime", Kind: KindGroupEnabled, PiholeGroup: "bedtime", Window: weeklyUTC(AllDays, "21:00", "07:00", 1)}, true})
	e.create(e.target("alpha"), Input{Spec{Name: "Early", Kind: KindGroupEnabled, PiholeGroup: "bedtime", Window: onceUTC(t, "2027-03-02 06:00", "2027-03-02 08:00")}, true})

	rows := e.check("2027-03-01 21:00")
	if got := runRows(t, rows); !slices.Equal(got, []string{"alpha start", "beta start"}) {
		t.Fatalf("at the start: %v", got)
	}
	if !e.groupOn("alpha", "bedtime") || !e.groupOn("beta", "bedtime") || e.groupOn("gamma", "bedtime") {
		t.Error("bedtime isn't on just on the site's members")
	}
	if rows[0].Detail["via"] != e.site.String() || rows[0].Detail["enabled"] != true || rows[0].Detail["summary"] != "Bedtime: bedtime enabled" {
		t.Errorf("detail %v", rows[0].Detail)
	}
	if rows := e.check("2027-03-02 06:00"); len(rows) != 0 { // Early starts: alpha is already on
		t.Errorf("Early's start: %v", rows)
	}
	rows = e.check("2027-03-02 07:00")
	if got := runRows(t, rows); !slices.Equal(got, []string{"beta end"}) {
		t.Fatalf("at the end: %v", got)
	}
	if !e.groupOn("alpha", "bedtime") || e.groupOn("beta", "bedtime") {
		t.Error("alpha should stay on for Early, beta go off")
	}
	if r := e.get(bedtime.ID).Results[e.ids["alpha"]]; r.Skip != SkipStillOpen || r.Other != "Early" {
		t.Errorf("alpha's result %+v", r)
	}
	if got := runRows(t, e.check("2027-03-02 08:00")); !slices.Equal(got, []string{"alpha end"}) {
		t.Errorf("Early's end: %v", got)
	}
	if e.groupOn("alpha", "bedtime") {
		t.Error("alpha still on after Early")
	}

	// A schedule saved during its window doesn't act until its next edge.
	e.at("2027-03-02 22:00")
	strict := e.create(e.target("gamma"), Input{Spec{Name: "Late", Kind: KindGroupEnabled, PiholeGroup: "bedtime", Window: weeklyUTC(AllDays, "21:00", "07:00", 1)}, true})
	e.check("2027-03-02 22:01")
	if e.groupOn("gamma", "bedtime") {
		t.Error("a new schedule acted on a window already open")
	}
	if next, ok := e.get(strict.ID).NextEdge(e.now); !ok || next.Start || !next.At.Equal(e.at("2027-03-03 07:00")) {
		t.Errorf("next edge %+v %v", next, ok)
	}
}

// TestSchedulerMissedEdge: an edge missed while the app was down is applied when it next looks, once; a manual change
// after that sticks.
func TestSchedulerMissedEdge(t *testing.T) {
	e := newEnv(t)
	e.at("2027-03-01 12:00")
	e.create(e.target("gamma"), Input{Spec{Name: "Bedtime", Kind: KindGroupEnabled, PiholeGroup: "bedtime", Window: weeklyUTC(AllDays, "21:00", "07:00", 1)}, true})
	if got := runRows(t, e.check("2027-03-01 23:00")); !slices.Equal(got, []string{"gamma start"}) {
		t.Fatalf("late start: %v", got)
	}
	e.setGroup("gamma", "bedtime", false)
	if rows := e.check("2027-03-01 23:30"); len(rows) != 0 || e.groupOn("gamma", "bedtime") {
		t.Errorf("a manual change was undone: %v", rows)
	}
	// Down through a whole window and past the next start: only the latest edge, the start, is applied.
	if got := runRows(t, e.check("2027-03-03 22:00")); !slices.Equal(got, []string{"gamma start"}) {
		t.Errorf("after two days: %v", got)
	}
}

// TestSchedulerRetry: a member that fails an edge is retried each pass until it works, audited when it first fails
// and when it succeeds, not each time it fails the same way; a one-off's end is given up after a week.
func TestSchedulerRetry(t *testing.T) {
	e := newEnv(t)
	e.at("2027-03-01 12:00")
	sc := e.create(e.site, Input{Spec{Name: "Evening", Kind: KindGroupEnabled, PiholeGroup: "bedtime", Window: onceUTC(t, "2027-03-01 21:00", "2027-03-01 23:00")}, true})
	refuse := func(on bool) {
		e.ph["beta"].Handle(func(w http.ResponseWriter, r *http.Request) bool {
			if on && r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/api/groups/") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"error":{"key":"database_error","message":"locked"}}`))
				return true
			}
			return false
		})
	}
	refuse(true)
	got := runRows(t, e.check("2027-03-01 21:00"))
	if len(got) != 2 || got[0] != "alpha start" || !strings.HasPrefix(got[1], "beta start failed ") {
		t.Fatalf("at the start: %v", got)
	}
	if rows := e.check("2027-03-01 21:01"); len(rows) != 0 {
		t.Errorf("a retry failing the same way was audited again: %v", runRows(t, rows))
	}
	if r := e.get(sc.ID).Results[e.ids["beta"]]; r.Status != StatusFailed || r.Attempts != 2 {
		t.Errorf("beta %+v", r)
	}
	refuse(false)
	if got := runRows(t, e.check("2027-03-01 21:02")); !slices.Equal(got, []string{"beta start retry"}) {
		t.Errorf("the retry that worked: %v", got)
	}
	if !e.groupOn("beta", "bedtime") {
		t.Error("beta not on after the retry")
	}

	// The end fails on beta, and keeps failing: given up after a week, and the schedule finished.
	refuse(true)
	if got := runRows(t, e.check("2027-03-01 23:00")); len(got) != 2 || !strings.HasPrefix(got[1], "beta end failed") {
		t.Fatalf("at the end: %v", got)
	}
	if e.get(sc.ID).Finished() {
		t.Error("finished with beta still failing")
	}
	e.check("2027-03-05 23:00")
	rows := e.check("2027-03-08 23:01")
	if len(rows) != 1 || rows[0].Detail["status"] != StatusGivenUp || rows[0].Err == nil {
		t.Fatalf("giving up: %+v", rows)
	}
	after := e.get(sc.ID)
	if !after.Finished() || after.Results[e.ids["beta"]].Status != StatusGivenUp {
		t.Errorf("after giving up: %+v", after)
	}
	if rows := e.check("2027-03-09 00:00"); len(rows) != 0 {
		t.Errorf("a finished schedule ran: %v", rows)
	}
}

// TestSchedulerFinishes: a one-off schedule is finished once its end has been applied everywhere, and one switched on
// after its end finishes without acting.
func TestSchedulerFinishes(t *testing.T) {
	e := newEnv(t)
	e.at("2027-03-01 12:00")
	a := e.create(e.target("gamma"), Input{Spec{Name: "Once", Kind: KindGroupDisabled, PiholeGroup: "bedtime", Window: onceUTC(t, "2027-03-01 13:00", "2027-03-01 14:00")}, true})
	e.setGroup("gamma", "bedtime", true)
	e.check("2027-03-01 13:00")
	if e.groupOn("gamma", "bedtime") {
		t.Error("a disable window didn't disable")
	}
	e.check("2027-03-01 14:00")
	if !e.groupOn("gamma", "bedtime") || !e.get(a.ID).Finished() {
		t.Error("not back on and finished")
	}
	if _, err := e.svc.Update(e.ctx, e.admin, e.get(a.ID), Input{e.get(a.ID).Spec(), true}); !rbac.IsCode(err, rbac.CodeConflict) {
		t.Errorf("changing a finished schedule: %v", err)
	}

	b := e.create(e.target("gamma"), Input{Spec{Name: "Off", Kind: KindGroupEnabled, PiholeGroup: "bedtime", Window: onceUTC(t, "2027-03-01 15:00", "2027-03-01 16:00")}, false})
	e.at("2027-03-01 17:00")
	in := Input{e.get(b.ID).Spec(), true}
	in.Window.StartsAt, in.Window.EndsAt = e.at("2027-03-01 18:00"), e.at("2027-03-01 19:00")
	e.at("2027-03-01 17:00")
	if _, err := e.svc.Update(e.ctx, e.admin, e.get(b.ID), in); err != nil {
		t.Fatal(err)
	}
	e.sunk.take()
	e.check("2027-03-01 18:00")
	e.check("2027-03-01 19:00")
	if !e.get(b.ID).Finished() {
		t.Error("not finished after its end")
	}
}

// TestSchedulerConflict: opposite kinds for one group that would overlap on a shared instance are refused at save;
// one that appears anyway (the save checks only what's there) is reported at its edge rather than fought over.
func TestSchedulerConflict(t *testing.T) {
	e := newEnv(t)
	e.ph["beta"].AddGroup("kids")
	e.at("2027-03-01 12:00")
	e.create(e.site, Input{Spec{Name: "Bedtime", Kind: KindGroupEnabled, PiholeGroup: "bedtime", Window: weeklyUTC(AllDays, "21:00", "07:00", 1)}, true})
	off := Input{Spec{Name: "Off", Kind: KindGroupDisabled, PiholeGroup: "bedtime", Window: onceUTC(t, "2027-03-01 22:00", "2027-03-01 23:00")}, true}
	if _, err := e.svc.Create(e.ctx, e.admin, e.target("beta"), off); !rbac.IsCode(err, rbac.CodeConflict) {
		t.Errorf("an overlapping opposite window on a member: %v", err)
	}
	for _, ok := range []struct {
		t  rbac.Target
		in Input
	}{
		{e.target("gamma"), off}, // not a member
		{e.target("beta"), Input{Spec{Name: "Day", Kind: KindGroupDisabled, PiholeGroup: "bedtime", Window: onceUTC(t, "2027-03-01 13:00", "2027-03-01 14:00")}, true}},
		{e.target("beta"), Input{Spec{Name: "Other", Kind: KindGroupDisabled, PiholeGroup: "kids", Window: off.Window}, true}},
		{e.target("beta"), Input{Spec{Name: "Off but off", Kind: KindGroupDisabled, PiholeGroup: "bedtime", Window: off.Window}, false}},
	} {
		if _, err := e.svc.Create(e.ctx, e.admin, ok.t, ok.in); err != nil {
			t.Errorf("%s: %v", ok.in.Name, err)
		}
	}
	// Switching the last one on is refused too.
	all, _ := e.svc.For(e.ctx, e.target("beta"))
	i := slices.IndexFunc(all, func(sc Schedule) bool { return sc.Name == "Off but off" })
	if _, err := e.svc.Update(e.ctx, e.admin, all[i], Input{all[i].Spec(), true}); !rbac.IsCode(err, rbac.CodeConflict) {
		t.Errorf("switching it on: %v", err)
	}
	// Written past the check, as a member added to a group later would be: reported at the edge, nothing sent.
	if err := e.st.WithTx(e.ctx, func(q *db.Queries) error {
		return q.UpdateSchedule(e.ctx, db.UpdateScheduleParams{Name: "Off but off", PiholeGroup: sql.NullString{String: "bedtime", Valid: true},
			Repeat: "once", StartsAt: sql.NullInt64{Int64: e.at("2027-03-01 22:00").UnixMilli(), Valid: true},
			EndsAt: sql.NullInt64{Int64: e.at("2027-03-01 23:00").UnixMilli(), Valid: true}, ActiveFrom: e.at("2027-03-01 12:00").UnixMilli(),
			Enabled: 1, UpdatedAt: 5, UpdatedBy: "x", ID: all[i].ID})
	}); err != nil {
		t.Fatal(err)
	}
	e.sunk.take()
	e.check("2027-03-01 21:00")
	got := runRows(t, e.check("2027-03-01 22:00"))
	if !slices.Equal(got, []string{"beta start", "beta start failed schedule_conflict"}) { // Other switched kids off
		t.Errorf("at the conflicting start: %v", got)
	}
	if !e.groupOn("beta", "bedtime") {
		t.Error("the conflicting window changed the group")
	}
}

// TestScheduleChanges: creating, changing and deleting are audited with the schedule; names are unique per target
// ignoring case; a save during a window clears the results and acts from the next edge.
func TestScheduleChanges(t *testing.T) {
	e := newEnv(t)
	e.at("2027-03-01 12:00")
	in := Input{Spec{Name: "Lab", Kind: KindBlockingOff, Window: weeklyUTC(weekdays, "08:00", "08:30", 0)}, true}
	sc, err := e.svc.Create(e.ctx, e.admin, e.target("gamma"), in)
	if err != nil {
		t.Fatal(err)
	}
	rows := e.sunk.take()
	if len(rows) != 1 || rows[0].Action != audit.ActionScheduleCreate || rows[0].Detail["start"] != "08:00" || rows[0].Target != e.target("gamma").String() {
		t.Errorf("create rows %+v", rows)
	}
	if sc.TargetName != "gamma" || !sc.ActiveFrom.Equal(e.now) {
		t.Errorf("created %+v", sc)
	}
	dup := in
	dup.Name = "LAB"
	if _, err := e.svc.Create(e.ctx, e.admin, e.target("gamma"), dup); !rbac.IsCode(err, rbac.CodeConflict) {
		t.Errorf("a taken name: %v", err)
	}
	if _, err := e.svc.Create(e.ctx, e.admin, e.target("alpha"), dup); err != nil {
		t.Errorf("the same name on another target: %v", err)
	}
	bad := in
	bad.Window.Days = 0
	if _, err := e.svc.Create(e.ctx, e.admin, e.target("gamma"), bad); !rbac.IsCode(err, rbac.CodeValidation) {
		t.Errorf("no days: %v", err)
	}
	e.sunk.take()

	e.check("2027-03-02 08:00")
	if len(e.get(sc.ID).Results) != 1 {
		t.Fatal("no results after the start")
	}
	e.at("2027-03-02 08:10")
	changed := in
	changed.Window.End = 45
	changed.Window.End, _ = ParseClock("08:45")
	after, err := e.svc.Update(e.ctx, e.admin, e.get(sc.ID), changed)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Results) != 0 || !after.ActiveFrom.Equal(e.now) || after.LastEdge != "start" {
		t.Errorf("after the change %+v", after)
	}
	rows = e.sunk.take()
	if len(rows) != 1 || rows[0].Action != audit.ActionScheduleUpdate || rows[0].Detail["end"] != "08:45" ||
		rows[0].Detail["before"].(map[string]any)["end"] != "08:30" {
		t.Errorf("update rows %+v", rows)
	}
	if rows := e.check("2027-03-02 08:20"); len(rows) != 0 {
		t.Errorf("the change applied the open window again: %v", rows)
	}

	if err := e.svc.Delete(e.ctx, e.admin, after); err != nil {
		t.Fatal(err)
	}
	if rows := e.sunk.take(); len(rows) != 1 || rows[0].Action != audit.ActionScheduleDelete {
		t.Errorf("delete rows %+v", rows)
	}
	if _, err := e.svc.Get(e.ctx, sc.ID); !rbac.IsCode(err, rbac.CodeNotFound) {
		t.Errorf("after deleting: %v", err)
	}
}

// TestRecordSkipsAChangedSchedule: results worked out for a version of a schedule that has since been saved aren't
// stored over it.
func TestRecordSkipsAChangedSchedule(t *testing.T) {
	e := newEnv(t)
	e.at("2027-03-01 12:00")
	sc := e.create(e.target("gamma"), Input{Spec{Name: "Lab", Kind: KindBlockingOff, Window: weeklyUTC(weekdays, "13:00", "13:30", 0)}, true})
	e.at("2027-03-01 12:30")
	if _, err := e.svc.Update(e.ctx, e.admin, sc, Input{sc.Spec(), true}); err != nil {
		t.Fatal(err)
	}
	e.at("2027-03-01 13:00")
	e.svc.record(e.ctx, sc, Edge{At: e.now, Start: true}, map[int64]Result{1: {Status: StatusOK}}, e.now)
	if got := e.get(sc.ID); !got.LastEdgeAt.IsZero() || len(got.Results) != 0 {
		t.Errorf("stored over the newer version: %+v", got)
	}
}

// TestSchedulerLostTimer: FTL comes back from a restart with blocking off and no timer. At the end of a window that
// turned blocking off, blocking is turned back on; where another blocking window is still open, its timer is put
// back instead. Blocking off by hand before a window isn't the window's, and stays off.
func TestSchedulerLostTimer(t *testing.T) {
	e := newEnv(t)
	e.at("2027-03-01 07:00")
	e.create(e.target("gamma"), Input{Spec{Name: "A", Kind: KindBlockingOff, Window: onceUTC(t, "2027-03-01 08:00", "2027-03-01 08:30")}, true})
	e.create(e.target("gamma"), Input{Spec{Name: "B", Kind: KindBlockingOff, Window: onceUTC(t, "2027-03-01 08:15", "2027-03-01 09:00")}, true})
	e.check("2027-03-01 08:00")
	if got := runRows(t, e.check("2027-03-01 08:15")); !slices.Equal(got, []string{"gamma start"}) { // B runs past A's timer
		t.Fatalf("B's start: %v", got)
	}
	e.setBlocking("gamma", false, 0) // FTL restarted: off, no timer
	rows := e.check("2027-03-01 08:30")
	if got := runRows(t, rows); !slices.Equal(got, []string{"gamma end"}) {
		t.Fatalf("A's end: %v", got)
	}
	if on, timer := e.blocking("gamma"); on || timer != 30*60 {
		t.Errorf("after A's end: blocking %v, timer %d; want off until B's end", on, timer)
	}
	if rows[0].Detail["timer_lost"] != true || rows[0].Detail["summary"] != "A: blocking off until 09:00 UTC (Pi-hole had lost its timer)" {
		t.Errorf("row %v", rows[0].Detail)
	}
	e.setBlocking("gamma", false, 0) // and again
	rows = e.check("2027-03-01 09:00")
	if got := runRows(t, rows); !slices.Equal(got, []string{"gamma end"}) {
		t.Fatalf("B's end: %v", got)
	}
	if on, _ := e.blocking("gamma"); !on {
		t.Error("blocking still off after the last window")
	}
	if rows[0].Detail["summary"] != "B: blocking back on (Pi-hole had lost its timer)" {
		t.Errorf("row %v", rows[0].Detail)
	}

	// Off by hand before the window: the window didn't turn it off, so its end leaves it.
	e.create(e.target("gamma"), Input{Spec{Name: "C", Kind: KindBlockingOff, Window: onceUTC(t, "2027-03-01 10:00", "2027-03-01 10:30")}, true})
	e.setBlocking("gamma", false, 0)
	e.check("2027-03-01 10:00")
	if rows := e.check("2027-03-01 10:30"); len(rows) != 0 {
		t.Errorf("C's end: %v", runRows(t, rows))
	}
	if on, timer := e.blocking("gamma"); on || timer != -1 {
		t.Errorf("blocking turned off by hand was changed: %v, %d", on, timer)
	}

	// Still off at the end with a timer running (set by hand, or another window's): Pi-hole's timer is left to end it.
	e.create(e.target("gamma"), Input{Spec{Name: "E", Kind: KindBlockingOff, Window: onceUTC(t, "2027-03-01 10:40", "2027-03-01 10:50")}, true})
	e.setBlocking("gamma", true, 0)
	e.check("2027-03-01 10:40")
	e.setBlocking("gamma", false, 20*time.Minute)
	if rows := e.check("2027-03-01 10:50"); len(rows) != 0 {
		t.Errorf("E's end with a timer running: %v", runRows(t, rows))
	}
	if on, timer := e.blocking("gamma"); on || timer != 20*60 {
		t.Errorf("a running timer was changed: %v, %d", on, timer)
	}

	// A failed end is retried, still knowing the window had turned blocking off.
	e.setBlocking("gamma", true, 0)
	d := e.create(e.target("gamma"), Input{Spec{Name: "D", Kind: KindBlockingOff, Window: onceUTC(t, "2027-03-01 11:00", "2027-03-01 11:30")}, true})
	e.check("2027-03-01 11:00")
	e.setBlocking("gamma", false, 0)
	var refuse atomic.Bool
	refuse.Store(true)
	e.ph["gamma"].Handle(func(w http.ResponseWriter, r *http.Request) bool {
		if refuse.Load() && r.Method == http.MethodPost && r.URL.Path == "/api/dns/blocking" {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":{"key":"x","message":"busy"}}`))
			return true
		}
		return false
	})
	if got := runRows(t, e.check("2027-03-01 11:30")); len(got) != 1 || !strings.HasPrefix(got[0], "gamma end failed") {
		t.Fatalf("D's end: %v", got)
	}
	refuse.Store(false)
	if got := runRows(t, e.check("2027-03-01 11:31")); !slices.Equal(got, []string{"gamma end retry"}) {
		t.Fatalf("D's retry: %v", got)
	}
	if on, _ := e.blocking("gamma"); !on || !e.get(d.ID).Finished() {
		t.Error("blocking not back on, or D not finished, after the retry")
	}
}
