// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/schedules"
)

var errNoSchedules = errors.New("api: no schedule service configured")

// scheduleTarget parses a {target} and checks schedules.manage on it, without needing the target to be usable now:
// a schedule on a disabled instance can still be read and deleted.
func (s *Server) scheduleTarget(ctx context.Context, raw string) (rbac.Target, error) {
	if s.Schedules == nil {
		return rbac.Target{}, errNoSchedules
	}
	t, err := rbac.ParseTarget(raw)
	if err != nil {
		return rbac.Target{}, invalid("target", `The target must be "i-<id>" for an instance or "g-<id>" for a mirrored group.`)
	}
	if err := s.authorize(ctx, rbac.SchedulesManage, t); err != nil {
		return rbac.Target{}, err
	}
	return t, nil
}

// scheduleOn returns the schedule id when it is set on t: a 404 otherwise, so the target's permission is the one
// that counts.
func (s *Server) scheduleOn(ctx context.Context, t rbac.Target, id int64) (schedules.Schedule, error) {
	sc, err := s.Schedules.Get(ctx, id)
	if err == nil && sc.Target != t {
		err = &rbac.Error{Code: rbac.CodeNotFound, Message: "There's no schedule with that ID on " + t.String() + "."}
	}
	return sc, err
}

// checkUnderlying checks that the session can do what a schedule of kind k does on the target, and for a group
// window, that its Pi-hole group exists there (on a mirrored group's primary, which must answer) and isn't Default.
func (s *Server) checkUnderlying(ctx context.Context, raw string, k schedules.Kind, group string) (target, error) {
	p := rbac.BlockingToggle
	if k.Group() {
		p = rbac.PiholeGroupsEdit
	}
	tg, err := s.resolveTarget(ctx, raw, p)
	if err != nil || !k.Group() {
		return tg, err
	}
	if group == "" {
		return tg, invalid("pihole_group", "A group window needs a Pi-hole group.")
	}
	g, err := s.primaryGroup(ctx, tg, group, "")
	if rbac.IsCode(err, rbac.CodeNotFound) {
		e, _ := rbac.AsError(err)
		return tg, &rbac.Error{Code: rbac.CodeValidation, Message: e.Message, Details: map[string]any{"field": "pihole_group"}}
	}
	if err != nil {
		return tg, err
	}
	if g.ID == 0 {
		return tg, invalid("pihole_group", "The Default group can't be a schedule's group: one edge of every window would disable it, which turns filtering off for most clients.")
	}
	return tg, nil
}

func (s *Server) ListSchedules(ctx context.Context, req gen.ListSchedulesRequestObject) (gen.ListSchedulesResponseObject, error) {
	t, err := s.scheduleTarget(ctx, req.Target)
	if err != nil {
		return nil, err
	}
	all, err := s.Schedules.All(ctx)
	if err != nil {
		return nil, err
	}
	set, err := s.permissions(ctx)
	if err != nil {
		return nil, err
	}
	var group rbac.Target
	if t.Kind == rbac.TargetInstance {
		if id, _, ok, err := s.Instances.MirroredGroupOf(ctx, t.ID); err != nil {
			return nil, err
		} else if ok {
			group = rbac.GroupTarget(id)
		}
	}
	now := time.Now()
	limits := s.scheduleLimits()
	out := gen.ScheduleList{Schedules: []gen.Schedule{}, FromGroups: []gen.Schedule{},
		GroupWindowMaxMinutes: int(limits.MaxLength(schedules.KindGroupEnabled, schedules.RepeatOnce) / time.Minute)}
	for _, sc := range all {
		switch {
		case sc.Target == t:
			out.Schedules = append(out.Schedules, scheduleJSON(sc, now, limits))
		case group.ID != 0 && sc.Target == group && set.Can(rbac.SchedulesManage, group):
			out.FromGroups = append(out.FromGroups, scheduleJSON(sc, now, limits))
		}
	}
	return gen.ListSchedules200JSONResponse(out), nil
}

func (s *Server) scheduleLimits() schedules.Limits {
	if s.LoginSettings == nil {
		return schedules.Limits{}
	}
	return s.LoginSettings.ScheduleLimits()
}

func (s *Server) GetSchedule(ctx context.Context, req gen.GetScheduleRequestObject) (gen.GetScheduleResponseObject, error) {
	t, err := s.scheduleTarget(ctx, req.Target)
	if err != nil {
		return nil, err
	}
	sc, err := s.scheduleOn(ctx, t, req.Id)
	if err != nil {
		return nil, err
	}
	return gen.GetSchedule200JSONResponse(scheduleJSON(sc, time.Now(), s.scheduleLimits())), nil
}

func (s *Server) CreateSchedule(ctx context.Context, req gen.CreateScheduleRequestObject) (gen.CreateScheduleResponseObject, error) {
	t, err := s.scheduleTarget(ctx, req.Target)
	if err != nil {
		return nil, err
	}
	b := req.Body
	if b == nil {
		return nil, invalid("body", "The request body is missing.")
	}
	in := schedules.Input{Spec: schedules.Spec{Name: b.Name, Kind: schedules.Kind(b.Kind)}, Enabled: b.Enabled == nil || *b.Enabled}
	if b.PiholeGroup != nil {
		in.PiholeGroup = *b.PiholeGroup
	}
	if !in.Kind.Valid() {
		return nil, invalid("kind", "The kind is blocking_off, group_enabled or group_disabled.")
	}
	if err := windowFrom(&in.Window, gen.ScheduleRepeat(b.Repeat), b.Days, b.Start, b.End, b.EndDays, b.TimeZone, b.StartsAt, b.EndsAt); err != nil {
		return nil, err
	}
	if err := in.Check(time.Now(), s.scheduleLimits()); err != nil {
		return nil, err // before reading Pi-hole: a form mistake needs no Pi-hole to answer
	}
	if _, err := s.checkUnderlying(ctx, req.Target, in.Kind, in.PiholeGroup); err != nil {
		return nil, err
	}
	sc, err := s.Schedules.Create(ctx, actor(ctx), t, in)
	if err != nil {
		return nil, err
	}
	return gen.CreateSchedule201JSONResponse(scheduleJSON(sc, time.Now(), s.scheduleLimits())), nil
}

func (s *Server) UpdateSchedule(ctx context.Context, req gen.UpdateScheduleRequestObject) (gen.UpdateScheduleResponseObject, error) {
	t, err := s.scheduleTarget(ctx, req.Target)
	if err != nil {
		return nil, err
	}
	b := req.Body
	if b == nil {
		return nil, invalid("body", "The request body is missing.")
	}
	before, err := s.scheduleOn(ctx, t, req.Id)
	if err != nil {
		return nil, err
	}
	in := schedules.Input{Spec: before.Spec(), Enabled: before.Enabled}
	if b.Name != nil {
		in.Name = *b.Name
	}
	if b.PiholeGroup != nil {
		in.PiholeGroup = *b.PiholeGroup
	}
	if b.Enabled != nil {
		in.Enabled = *b.Enabled
	}
	repeat := gen.ScheduleRepeat(before.Window.Repeat)
	if b.Repeat != nil {
		repeat = *b.Repeat
	}
	// The window starts from what is saved, with the fields given laid over it.
	days, endDays := before.Window.Days, before.Window.EndDays
	start, end := schedules.FormatClock(before.Window.Start), schedules.FormatClock(before.Window.End)
	zone := before.TimeZone
	startsAt, endsAt := before.Window.StartsAt, before.Window.EndsAt
	if b.Days != nil {
		days = *b.Days
	}
	if b.EndDays != nil {
		endDays = *b.EndDays
	}
	if b.Start != nil {
		start = *b.Start
	}
	if b.End != nil {
		end = *b.End
	}
	if b.TimeZone != nil {
		zone = *b.TimeZone
	}
	if b.StartsAt != nil {
		startsAt = *b.StartsAt
	}
	if b.EndsAt != nil {
		endsAt = *b.EndsAt
	}
	var startsPtr, endsPtr *time.Time
	if !startsAt.IsZero() {
		startsPtr = &startsAt
	}
	if !endsAt.IsZero() {
		endsPtr = &endsAt
	}
	if err := windowFrom(&in.Window, repeat, &days, &start, &end, &endDays, &zone, startsPtr, endsPtr); err != nil {
		return nil, err
	}
	if before.Finished() {
		return nil, &rbac.Error{Code: rbac.CodeConflict, Message: "A finished one-off schedule can't be changed, only deleted."}
	}
	if err := in.Check(time.Now(), s.scheduleLimits()); err != nil {
		return nil, err
	}
	// The group is only read again when it changes: a schedule whose group has since gone can still be switched off.
	group := in.PiholeGroup
	if group == before.Group {
		group = ""
	}
	if in.Kind.Group() && group == "" {
		if _, err := s.resolveTarget(ctx, req.Target, rbac.PiholeGroupsEdit); err != nil {
			return nil, err
		}
	} else if _, err := s.checkUnderlying(ctx, req.Target, in.Kind, group); err != nil {
		return nil, err
	}
	sc, err := s.Schedules.Update(ctx, actor(ctx), before, in)
	if err != nil {
		return nil, err
	}
	return gen.UpdateSchedule200JSONResponse(scheduleJSON(sc, time.Now(), s.scheduleLimits())), nil
}

func (s *Server) DeleteSchedule(ctx context.Context, req gen.DeleteScheduleRequestObject) (gen.DeleteScheduleResponseObject, error) {
	t, err := s.scheduleTarget(ctx, req.Target)
	if err != nil {
		return nil, err
	}
	sc, err := s.scheduleOn(ctx, t, req.Id)
	if err != nil {
		return nil, err
	}
	if err := s.Schedules.Delete(ctx, actor(ctx), sc); err != nil {
		return nil, err
	}
	return gen.DeleteSchedule204Response{}, nil
}

// GetScheduleStatus lists the enabled schedules that reach the target, with the windows open now first. It shows
// names and times only, so any permission on the target is enough.
func (s *Server) GetScheduleStatus(ctx context.Context, req gen.GetScheduleStatusRequestObject) (gen.GetScheduleStatusResponseObject, error) {
	if s.Schedules == nil {
		return nil, errNoSchedules
	}
	tg, err := s.resolveTarget(ctx, req.Target, "")
	if err != nil {
		return nil, err
	}
	reaching := []rbac.Target{tg.t}
	if !tg.isGroup() {
		if id, _, ok, err := s.Instances.MirroredGroupOf(ctx, tg.t.ID); err != nil {
			return nil, err
		} else if ok {
			reaching = append(reaching, rbac.GroupTarget(id))
		}
	}
	all, err := s.Schedules.All(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	out := gen.ScheduleStatus{Schedules: []gen.ScheduleStatusItem{}}
	for _, sc := range all {
		if !sc.Enabled || sc.Finished() || !slices.Contains(reaching, sc.Target) {
			continue
		}
		it := gen.ScheduleStatusItem{Id: sc.ID, Name: sc.Name, Kind: gen.ScheduleKind(sc.Kind), Target: sc.Target.String(), TargetName: sc.TargetName}
		if sc.Kind.Group() {
			it.PiholeGroup = &sc.Group
		}
		if iv, ok := sc.Window.OpenAt(now); ok {
			it.Open, it.OpenUntil = true, &iv.End
		}
		if e, ok := sc.NextEdge(now); ok {
			it.NextEdge = edgeJSON(e.At, e.Start)
		}
		if !it.Open && it.NextEdge == nil {
			continue // a one-off past its end, not yet marked finished: nothing to say
		}
		out.Schedules = append(out.Schedules, it)
	}
	slices.SortStableFunc(out.Schedules, func(a, b gen.ScheduleStatusItem) int {
		if a.Open != b.Open {
			if a.Open {
				return -1
			}
			return 1
		}
		return cmp.Compare(edgeTime(a.NextEdge), edgeTime(b.NextEdge))
	})
	return gen.GetScheduleStatus200JSONResponse(out), nil
}

func edgeTime(e *gen.ScheduleEdge) int64 {
	if e == nil {
		return 1<<63 - 1
	}
	return e.At.UnixMilli()
}

// windowFrom builds a window from the API's fields, refusing a field that doesn't parse or belongs to the other
// repeat. Lengths and the rest are checked by the spec.
func windowFrom(w *schedules.Window, repeat gen.ScheduleRepeat, days *int, start, end *string, endDays *int, zone *string,
	startsAt, endsAt *time.Time) error {
	*w = schedules.Window{Repeat: schedules.Repeat(repeat)}
	switch w.Repeat {
	case schedules.RepeatWeekly:
		if days == nil || start == nil || end == nil || zone == nil {
			field := "days"
			switch {
			case days == nil:
			case start == nil:
				field = "start"
			case end == nil:
				field = "end"
			default:
				field = "time_zone"
			}
			return invalid(field, "A weekly schedule needs days, a start, an end and a time zone.")
		}
		var ok bool
		if w.Start, ok = schedules.ParseClock(*start); !ok {
			return invalid("start", "The start is HH:MM, from 00:00 to 23:59.")
		}
		if w.End, ok = schedules.ParseClock(*end); !ok {
			return invalid("end", "The end is HH:MM, from 00:00 to 23:59.")
		}
		loc, err := schedules.LoadZone(*zone)
		if err != nil {
			return invalid("time_zone", "%q isn't a time zone this server knows, such as Europe/London or UTC.", *zone)
		}
		w.Days, w.Location = *days, loc
		if endDays != nil {
			w.EndDays = *endDays
		}
	case schedules.RepeatOnce:
		if startsAt == nil {
			return invalid("starts_at", "A one-off schedule needs a start.")
		}
		if endsAt == nil {
			return invalid("ends_at", "A one-off schedule needs an end.")
		}
		w.StartsAt, w.EndsAt = *startsAt, *endsAt
	default:
		return invalid("repeat", "A schedule repeats weekly or happens once.")
	}
	return nil
}

func edgeJSON(at time.Time, start bool) *gen.ScheduleEdge {
	e := gen.ScheduleEdge{At: at, Edge: gen.ScheduleEdgeEdge("end")}
	if start {
		e.Edge = gen.ScheduleEdgeEdge("start")
	}
	return &e
}

func scheduleJSON(sc schedules.Schedule, now time.Time, limits schedules.Limits) gen.Schedule {
	out := gen.Schedule{
		Id: sc.ID, Name: sc.Name, Target: sc.Target.String(), TargetName: sc.TargetName, Kind: gen.ScheduleKind(sc.Kind),
		Repeat: gen.ScheduleRepeat(sc.Window.Repeat), Enabled: sc.Enabled,
		LengthMinutes: int(sc.Window.Nominal() / time.Minute), Results: []gen.ScheduleResult{},
		OverLimit: sc.Spec().OverLimit(limits),
		CreatedAt: sc.CreatedAt, CreatedBy: sc.CreatedBy, UpdatedAt: sc.UpdatedAt, UpdatedBy: sc.UpdatedBy,
	}
	if sc.Kind.Group() {
		out.PiholeGroup = &sc.Group
	}
	w := sc.Window
	if w.Repeat == schedules.RepeatWeekly {
		days, endDays := w.Days, w.EndDays
		start, end, zone := schedules.FormatClock(w.Start), schedules.FormatClock(w.End), sc.TimeZone
		out.Days, out.EndDays, out.Start, out.End, out.TimeZone = &days, &endDays, &start, &end, &zone
	} else {
		startsAt, endsAt := w.StartsAt, w.EndsAt
		out.StartsAt, out.EndsAt = &startsAt, &endsAt
	}
	if sc.Enabled && !sc.Finished() {
		if iv, ok := w.OpenAt(now); ok {
			out.Open, out.OpenUntil = true, &iv.End
		}
	}
	if e, ok := sc.NextEdge(now); ok {
		out.NextEdge = edgeJSON(e.At, e.Start)
	}
	if !sc.LastEdgeAt.IsZero() {
		out.LastEdge = edgeJSON(sc.LastEdgeAt, sc.LastEdge == "start")
	}
	if sc.Finished() {
		f := sc.FinishedAt
		out.FinishedAt = &f
	}
	for id, r := range sc.Results {
		gr := gen.ScheduleResult{InstanceId: id, Instance: r.Instance, Status: gen.ScheduleResultStatus(r.Status), At: r.At, Attempts: r.Attempts}
		if r.Code != "" {
			gr.Code = &r.Code
		}
		if r.Skip != "" {
			skip := gen.ScheduleResultSkip(r.Skip)
			gr.Skip = &skip
		}
		if r.Other != "" {
			gr.Other = &r.Other
		}
		out.Results = append(out.Results, gr)
	}
	slices.SortFunc(out.Results, func(a, b gen.ScheduleResult) int { return cmp.Compare(a.Instance, b.Instance) })
	return out
}
