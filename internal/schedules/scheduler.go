// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package schedules

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/instances"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// Scheduler applies schedules' edges. It looks every Tick, and once when it starts, rather than sleeping until the
// next edge, so a saved change applies within a Tick with nothing to notify it, and a clock that jumps can't make it
// miss an edge: each pass applies the latest edge it finds due, however late.
type Scheduler struct {
	Service *Service
	Tick    time.Duration // default 30 seconds
}

// Run checks once at once, then every Tick until ctx ends.
func (sc *Scheduler) Run(ctx context.Context) {
	sc.Service.Check(ctx)
	tick := time.NewTicker(cmp.Or(sc.Tick, 30*time.Second))
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			sc.Service.Check(ctx)
		}
	}
}

const (
	// callTimeout bounds one instance's reads and write at an edge.
	callTimeout = 20 * time.Second
	// GiveUpAfter is how long a one-off schedule's end edge is retried, having no next edge to stop at.
	GiveUpAfter = 7 * 24 * time.Hour
)

// Check is one pass: for each enabled schedule that isn't finished, it applies the latest edge if it hasn't been,
// and otherwise retries the latest edge on the instances it failed on, while it still applies. One pass at a time:
// Run calls it from one goroutine.
func (s *Service) Check(ctx context.Context) {
	now := s.now()
	all, err := s.All(ctx)
	if err != nil {
		s.log().Error("schedules: reading the schedules", "err", err)
		return
	}
	// Which instances each schedule reaches, and from each instance, which schedules reach it.
	reach := map[int64][]member{}
	byInstance := map[int64][]Reach{}
	for _, sc := range all {
		if !sc.Enabled || sc.Finished() {
			continue
		}
		ms, err := s.reaches(ctx, sc.Target)
		if err != nil {
			s.log().Error("schedules: finding a schedule's instances", "schedule", sc.ID, "err", err)
			continue
		}
		reach[sc.ID] = ms
		for _, m := range ms {
			byInstance[m.id] = append(byInstance[m.id], sc.reach())
		}
	}
	for _, sc := range all {
		if ctx.Err() != nil {
			return
		}
		if ms, ok := reach[sc.ID]; ok {
			s.pass(ctx, sc, ms, byInstance, now)
		}
	}
}

// pass is what one Check does for one schedule.
func (s *Service) pass(ctx context.Context, sc Schedule, ms []member, byInstance map[int64][]Reach, now time.Time) {
	e, ok := sc.Window.LatestEdge(now)
	due := ok && e.At.After(sc.ActiveFrom) && (sc.LastEdgeAt.IsZero() || e.At.After(sc.LastEdgeAt))
	switch {
	case due:
		results := map[int64]Result{}
		s.apply(ctx, sc, e, ms, byInstance, now, false, results)
		s.record(ctx, sc, e, results, now)
	case !sc.LastEdgeAt.IsZero() && slices.ContainsFunc(ms, func(m member) bool { return sc.Results[m.id].pending() }):
		// The latest edge applied: e, the same moment as LastEdgeAt (an edge between would be due).
		last := Edge{At: sc.LastEdgeAt, Start: sc.LastEdge == "start"}
		if last.Start {
			last.Window, _ = sc.Window.OpenAt(sc.LastEdgeAt)
		}
		results := cloneResults(sc.Results)
		var retry []member
		for _, m := range ms {
			if results[m.id].pending() {
				retry = append(retry, m)
			}
		}
		if sc.Window.Repeat == RepeatOnce && !last.Start && now.Sub(last.At) > GiveUpAfter {
			for _, m := range retry {
				r := results[m.id]
				r.Status, r.At = StatusGivenUp, now
				results[m.id] = r
				s.log().Warn("schedules: gave up on a one-off schedule's end", "schedule", sc.Name, "instance", m.name, "code", r.Code)
			}
			s.record(ctx, sc, last, results, now)
			s.auditGivenUp(ctx, sc, retry, results, now)
			return
		}
		s.apply(ctx, sc, last, retry, byInstance, now, true, results)
		s.record(ctx, sc, last, results, now)
	case sc.Window.Repeat == RepeatOnce && !sc.Window.EndsAt.After(now) && !sc.Window.EndsAt.After(sc.ActiveFrom):
		// A one-off saved or switched on after its end: it will never act.
		s.record(ctx, sc, Edge{}, sc.Results, now)
	}
}

func cloneResults(rs map[int64]Result) map[int64]Result {
	out := make(map[int64]Result, len(rs))
	for k, v := range rs {
		out[k] = v
	}
	return out
}

// record stores the edge and the results, and finishes a one-off schedule once its end edge is settled everywhere.
// A schedule saved since this pass read it is left alone: the results are for a version that no longer exists.
func (s *Service) record(ctx context.Context, sc Schedule, e Edge, results map[int64]Result, now time.Time) {
	var finished sql.NullInt64
	if sc.Window.Repeat == RepeatOnce && !sc.Window.EndsAt.After(now) &&
		(e.At.IsZero() || (!e.Start && !slices.ContainsFunc(mapValues(results), Result.pending))) {
		finished = nullInt(store.Millis(now), true)
	}
	p := db.RecordScheduleEdgeParams{ID: sc.ID, UpdatedAt: store.Millis(sc.UpdatedAt), FinishedAt: finished}
	if e.At.IsZero() {
		p.LastEdgeAt, p.LastEdge.String, p.LastEdge.Valid = nullInt(store.Millis(sc.LastEdgeAt), !sc.LastEdgeAt.IsZero()), sc.LastEdge, sc.LastEdge != ""
	} else {
		p.LastEdgeAt, p.LastEdge.String, p.LastEdge.Valid = nullInt(store.Millis(e.At), true), e.Name(), true
	}
	var err error
	if p.LastResults, err = resultsJSON(results); err == nil {
		bg := context.WithoutCancel(ctx)
		err = s.Store.WithTx(bg, func(q *db.Queries) error {
			_, err := q.RecordScheduleEdge(bg, p)
			return err
		})
	}
	if err != nil {
		s.log().Error("schedules: recording an edge", "schedule", sc.ID, "err", err)
	}
}

func mapValues(rs map[int64]Result) []Result {
	out := make([]Result, 0, len(rs))
	for _, r := range rs {
		out = append(out, r)
	}
	return out
}

// outcome is what an edge did on one instance, for its result and audit row.
type outcome struct {
	result Result
	sent   bool           // something was sent to Pi-hole
	detail map[string]any // what was sent
	err    error
}

// apply applies edge e of sc on each of ms at once, puts each result in results, and writes the audit rows: one per
// instance something was sent to or failed on. A retry that fails again the same way isn't audited again.
func (s *Service) apply(ctx context.Context, sc Schedule, e Edge, ms []member, byInstance map[int64][]Reach, now time.Time,
	retry bool, results map[int64]Result) {
	outs := make([]outcome, len(ms))
	var wg sync.WaitGroup
	for i, m := range ms {
		wg.Go(func() {
			cctx, cancel := context.WithTimeout(ctx, callTimeout)
			defer cancel()
			outs[i] = s.on(cctx, sc, e, m, OpenAt(byInstance[m.id], now), now, owned(sc, e, m.id, retry))
		})
	}
	wg.Wait()
	var entries []audit.Entry
	for i, m := range ms {
		o := outs[i]
		prev, had := results[m.id]
		o.result.Instance, o.result.At = m.name, now
		o.result.Attempts = 1
		if retry && had {
			o.result.Attempts = prev.Attempts + 1
		}
		results[m.id] = o.result
		repeat := retry && had && o.result.pending() && prev.Code == o.result.Code
		if (o.sent || o.result.pending()) && !repeat {
			entries = append(entries, s.runEntry(sc, e, m, o, retry, now))
		}
	}
	if len(entries) == 0 {
		return
	}
	s.writeEntries(ctx, sc, entries)
}

// owned reports whether blocking window sc turned blocking off on instance id at the start of the window that edge e
// ends: the start's result says so, or, for a retried end, the end's own result carries it on.
func owned(sc Schedule, e Edge, id int64, retry bool) bool {
	if sc.Kind != KindBlockingOff || e.Start {
		return false
	}
	prev := sc.Results[id]
	if retry || (sc.LastEdge == "start" && sc.LastEdgeAt.Equal(e.Window.Start)) {
		return prev.Owned
	}
	return false
}

// runEntry is the schedule_run row for one instance.
func (s *Service) runEntry(sc Schedule, e Edge, m member, o outcome, retry bool, now time.Time) audit.Entry {
	d := map[string]any{"schedule_id": sc.ID, "schedule": sc.Name, "kind": string(sc.Kind), "edge": e.Name(), "retry": retry,
		"status": o.result.Status}
	if sc.Kind.Group() {
		d["pihole_group"] = sc.Group
	}
	if sc.Target.Kind == rbac.TargetGroup {
		d["via"] = sc.Target.String()
	}
	for k, v := range o.detail {
		d[k] = v
	}
	d["summary"] = runSummary(sc, o)
	en := audit.Entry{At: now, Username: SystemActor.Username, Action: audit.ActionScheduleRun, Target: sc.Target.String(),
		InstanceID: m.id, InstanceName: m.name, Detail: d}
	if o.result.pending() {
		d["error_code"] = o.result.Code
		en.Err = o.err
		if en.Err == nil {
			en.Err = errors.New(o.result.Code)
		}
	}
	return en
}

// auditGivenUp writes a row for each instance a one-off's end edge was given up on.
func (s *Service) auditGivenUp(ctx context.Context, sc Schedule, ms []member, results map[int64]Result, now time.Time) {
	var entries []audit.Entry
	for _, m := range ms {
		r := results[m.id]
		d := map[string]any{"schedule_id": sc.ID, "schedule": sc.Name, "kind": string(sc.Kind), "edge": "end", "retry": true,
			"status": StatusGivenUp, "error_code": r.Code, "attempts": r.Attempts}
		if sc.Kind.Group() {
			d["pihole_group"] = sc.Group
		}
		entries = append(entries, audit.Entry{At: now, Username: SystemActor.Username, Action: audit.ActionScheduleRun,
			Target: sc.Target.String(), InstanceID: m.id, InstanceName: m.name, Detail: d,
			Err: fmt.Errorf("gave up after %d attempts over %s", r.Attempts, describeLength(GiveUpAfter))})
	}
	s.writeEntries(ctx, sc, entries)
}

// on applies edge e of sc on one instance, given the schedules open there now. owned is whether a blocking window
// turned blocking off there at its start.
func (s *Service) on(ctx context.Context, sc Schedule, e Edge, m member, open []Open, now time.Time, owned bool) outcome {
	if sc.Kind.Group() {
		return s.groupOn(ctx, sc, e, m, open)
	}
	if !e.Start {
		return s.blockingEnd(ctx, sc, m, open, now, owned)
	}
	until, ok := BlockingUntil(now, e.Window, open)
	if !ok || !e.Window.End.After(now) {
		return outcome{result: Result{Status: StatusOK, Skip: SkipWindowOver}}
	}
	var o outcome
	called := false
	err := s.Instances.Pool.Do(ctx, m.id, func(ctx context.Context, c *piholeapi.Client) error {
		called = true
		st, err := c.GetStatus(ctx)
		if err != nil {
			return err
		}
		if !NeedsBlockingOff(blockingStatus(st), now, until) {
			o.result = Result{Status: StatusOK, Skip: SkipUnchanged}
			return nil
		}
		timer := until.Sub(now)
		if _, err := c.SetBlocking(ctx, false, timer); err != nil {
			return err
		}
		o.sent = true
		o.detail = map[string]any{"enabled": false, "timer": int64((timer + time.Second - 1) / time.Second),
			"until": until.UTC().Format(time.RFC3339)}
		o.result = Result{Status: StatusOK, Owned: true}
		return nil
	})
	return finish(o, err, called)
}

// blockingEnd is a blocking window's end on one instance. Pi-hole's own timer normally turns blocking back on, so
// nothing is sent. But FTL doesn't keep the timer across a restart: it comes back with blocking off and no timer,
// which would last for good. So where this window turned blocking off, and it is now off with no timer, the timer is
// put back for another blocking window still open there, or blocking turned back on. Blocking turned off by hand
// before the window isn't the window's, and is left alone; turned off by hand during it, it is undone here, as any
// manual change lasts until the next edge.
func (s *Service) blockingEnd(ctx context.Context, sc Schedule, m member, open []Open, now time.Time, owned bool) outcome {
	timerEnds := outcome{result: Result{Status: StatusOK, Skip: "timer", Owned: owned}}
	if !owned {
		return timerEnds
	}
	var others []Open
	for _, o := range open {
		if o.Kind == KindBlockingOff && o.ID != sc.ID {
			others = append(others, o)
		}
	}
	var o outcome
	called := false
	err := s.Instances.Pool.Do(ctx, m.id, func(ctx context.Context, c *piholeapi.Client) error {
		called = true
		st, err := c.GetStatus(ctx)
		if err != nil {
			return err
		}
		if b := blockingStatus(st); !b.Disabled || b.Timer != nil {
			o = timerEnds
			return nil
		}
		if until, ok := BlockingUntil(now, Interval{now, now}, others); ok {
			timer := until.Sub(now)
			if _, err := c.SetBlocking(ctx, false, timer); err != nil {
				return err
			}
			o.detail = map[string]any{"enabled": false, "timer": int64((timer + time.Second - 1) / time.Second),
				"until": until.UTC().Format(time.RFC3339), "timer_lost": true}
		} else {
			if _, err := c.SetBlocking(ctx, true, 0); err != nil {
				return err
			}
			o.detail = map[string]any{"enabled": true, "timer_lost": true}
		}
		o.sent = true
		o.result = Result{Status: StatusOK, Owned: true}
		return nil
	})
	o = finish(o, err, called)
	o.result.Owned = owned
	return o
}

// groupOn applies a group window's edge on one instance.
func (s *Service) groupOn(ctx context.Context, sc Schedule, e Edge, m member, open []Open) outcome {
	act := GroupEdge(sc.reach(), e.Start, open)
	switch act.Skip {
	case SkipStillOpen:
		return outcome{result: Result{Status: StatusOK, Skip: SkipStillOpen, Other: act.Other}}
	case SkipConflict:
		return outcome{result: Result{Status: StatusFailed, Code: SkipConflict, Other: act.Other},
			err: fmt.Errorf("the schedule %q turns %s the other way at the same time", act.Other, sc.Group)}
	}
	var o outcome
	called := false
	err := s.Instances.Pool.Do(ctx, m.id, func(ctx context.Context, c *piholeapi.Client) error {
		called = true
		groups, err := c.ListGroups(ctx)
		if err != nil {
			return err
		}
		i := slices.IndexFunc(groups, func(g piholeapi.Group) bool { return g.Name == sc.Group })
		switch {
		case i < 0:
			o.result = Result{Status: StatusFailed, Code: "not_found"}
			o.err = fmt.Errorf("there's no Pi-hole group %q", sc.Group)
			return nil
		case groups[i].ID == 0:
			o.result = Result{Status: StatusFailed, Code: "validation_failed"}
			o.err = fmt.Errorf("%q is the Default group, which a schedule can't switch", sc.Group)
			return nil
		case groups[i].Enabled == act.Enabled:
			o.result = Result{Status: StatusOK, Skip: SkipUnchanged}
			return nil
		}
		g := groups[i]
		g.Enabled = act.Enabled
		if err := c.UpdateGroup(ctx, g); err != nil {
			return err
		}
		o.sent = true
		o.detail = map[string]any{"enabled": act.Enabled}
		o.result = Result{Status: StatusOK}
		return nil
	})
	return finish(o, err, called)
}

// finish turns a call's error into the result: skipped when the pool didn't call the instance, failed otherwise.
func finish(o outcome, err error, called bool) outcome {
	if err == nil {
		return o
	}
	o.err, o.result = err, Result{Status: StatusFailed, Code: codeOf(err)}
	if !called {
		o.result.Status = StatusSkipped
	}
	return o
}

func blockingStatus(st *piholeapi.Status) BlockingStatus {
	out := BlockingStatus{Disabled: st.Blocking == "disabled"}
	if st.Timer != nil {
		d := time.Duration(*st.Timer * float64(time.Second))
		out.Timer = &d
	}
	return out
}

// codeOf is an error's code for a result: a Pi-hole or instance code, or internal.
func codeOf(err error) string {
	if errors.Is(err, instances.ErrNotFound) {
		return "not_found"
	}
	if code := instances.Kind(err); code != "" {
		return code
	}
	return "internal"
}

// writeEntries writes a pass's audit rows for a schedule in one transaction, and logs them once it has committed.
// They are written even if ctx has ended: the change on Pi-hole has happened.
func (s *Service) writeEntries(ctx context.Context, sc Schedule, entries []audit.Entry) {
	bg := context.WithoutCancel(ctx)
	if err := s.Store.WithTx(bg, func(q *db.Queries) error {
		for _, en := range entries {
			if _, err := audit.Insert(bg, q, en); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		s.log().Error("schedules: writing audit rows", "schedule", sc.ID, "err", err)
		return
	}
	for _, en := range entries {
		s.Audit.Log(en)
	}
}

// runSummary says in a few words what a schedule_run row did, for its notification: "Lab mornings: blocking off
// until 08:30 UTC", "Bedtime: bedtime enabled", or the schedule's name alone for a failure.
func runSummary(sc Schedule, o outcome) string {
	switch {
	case o.result.pending() || !o.sent:
		return sc.Name
	case sc.Kind.Group() && o.detail["enabled"] == true:
		return sc.Name + ": " + sc.Group + " enabled"
	case sc.Kind.Group():
		return sc.Name + ": " + sc.Group + " disabled"
	}
	if o.detail["enabled"] == true {
		return sc.Name + ": blocking back on (Pi-hole had lost its timer)"
	}
	until, _ := o.detail["until"].(string)
	lost := ""
	if o.detail["timer_lost"] == true {
		lost = " (Pi-hole had lost its timer)"
	}
	if t, err := time.Parse(time.RFC3339, until); err == nil {
		return sc.Name + ": blocking off until " + t.Format("15:04 MST") + lost
	}
	return sc.Name + ": blocking off" + lost
}
