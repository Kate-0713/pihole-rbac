// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package clientreset

import (
	"cmp"
	"context"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/rbac"
)

// Schedule is when client reset runs by itself: daily at Hour:Minute in Location, while Enabled.
type Schedule struct {
	Enabled      bool
	Hour, Minute int
	Location     *time.Location
}

// NextRun returns the first scheduled time strictly after t. A time a daylight saving change skips (01:30 on the
// night the clocks go forward in London) comes out an hour later, as time.Date normalises it; a time that happens
// twice when the clocks go back runs once, at whichever of the two time.Date gives.
func NextRun(s Schedule, t time.Time) time.Time {
	local := t.In(s.Location)
	y, m, d := local.Date()
	for i := 0; ; i++ {
		next := time.Date(y, m, d+i, s.Hour, s.Minute, 0, 0, s.Location)
		if next.After(t) {
			return next
		}
	}
}

// Scheduler runs every target's rules at the scheduled time. It looks at the schedule every Tick rather than
// sleeping until the run, so a changed schedule applies within a Tick, with nothing to notify it, and a clock that
// jumps can't make it miss or repeat a run. A run found more than MaxLate after its time (the host was asleep, say)
// is skipped and logged: like v1, the scheduler doesn't catch up on runs it missed, including while the app was
// stopped.
type Scheduler struct {
	Service  *Service
	Schedule func() Schedule
	Tick     time.Duration    // how often the schedule is checked; default 30 seconds
	MaxLate  time.Duration    // default an hour
	Now      func() time.Time // nil means time.Now
}

func (sc *Scheduler) now() time.Time {
	if sc.Now != nil {
		return sc.Now()
	}
	return time.Now()
}

// Run checks the schedule every Tick until ctx ends.
func (sc *Scheduler) Run(ctx context.Context) {
	tick := time.NewTicker(cmp.Or(sc.Tick, 30*time.Second))
	defer tick.Stop()
	last := sc.now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			now := sc.now()
			sc.Check(ctx, last, now)
			last = now
		}
	}
}

// Check runs the scheduled pass if a scheduled time falls after last and at or before now, and reports whether it
// did. Run calls it each Tick with the previous check's time.
func (sc *Scheduler) Check(ctx context.Context, last, now time.Time) bool {
	s := sc.Schedule()
	if !s.Enabled || s.Location == nil {
		return false
	}
	due := NextRun(s, last)
	if due.After(now) {
		return false
	}
	if late := now.Sub(due); late > cmp.Or(sc.MaxLate, time.Hour) {
		sc.Service.log().Warn("client reset: skipped a scheduled run found too late", "due", due, "late", late.Round(time.Second))
		return false
	}
	sc.Service.RunAll(ctx)
	return true
}

// RunAll runs every target that has rules, one after another, as scheduled runs, and returns the runs it recorded.
// A target that can't run (a disabled instance, or another run in progress) is logged and skipped.
func (s *Service) RunAll(ctx context.Context) []Run {
	st, err := s.Rules(ctx)
	if err != nil {
		s.log().Error("client reset: reading the rules for a scheduled run", "err", err)
		return nil
	}
	var targets []rbac.Target
	seen := map[rbac.Target]bool{}
	for _, r := range st.Rules {
		t := rbac.InstanceTarget(r.ScopeID)
		if r.Scope == ScopeGroup {
			t = rbac.GroupTarget(r.ScopeID)
		}
		if !seen[t] {
			seen[t] = true
			targets = append(targets, t)
		}
	}
	var runs []Run
	for _, t := range targets {
		if ctx.Err() != nil {
			break
		}
		run, err := s.Run(ctx, SystemActor, TriggerSchedule, t)
		switch {
		case rbac.IsCode(err, rbac.CodeNotFound):
			s.log().Info("client reset: a scheduled run skipped a target that can't be used", "target", t.String(), "reason", err)
		case err != nil:
			s.log().Warn("client reset: a scheduled run of a target failed", "target", t.String(), "err", err)
		default:
			runs = append(runs, run)
		}
	}
	if len(runs) > 0 {
		s.log().Info("client reset: scheduled run done", "targets", len(runs))
	}
	return runs
}
