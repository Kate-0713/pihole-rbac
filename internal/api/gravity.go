// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"errors"
	"regexp"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/gravity"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
)

// Gravity runs. A run is started here and carries on in the background (internal/gravity); the page polls it. It is
// audited as gravity_start when it starts, so who started it is recorded even if the app restarts before it ends, and
// as gravity_run for each instance as its part ends, never with the output.

func (s *Server) StartGravity(ctx context.Context, req gen.StartGravityRequestObject) (gen.StartGravityResponseObject, error) {
	tg, err := s.resolveTarget(ctx, req.Target, rbac.GravityRun)
	if err != nil {
		return nil, err
	}
	refs := map[int64]instanceRef{}
	members := make([]gravity.Member, len(tg.members))
	names := make([]string, len(tg.members))
	for i, m := range tg.members {
		refs[m.id] = m
		members[i] = gravity.Member{ID: m.id, Name: m.name, Primary: m.primary}
		names[i] = m.name
	}
	ri := info(ctx)
	snap, err := s.Gravity.Start(ctx, tg.t.String(), ri.user.Username, members, gravity.Hooks{
		// Before the run sends anything, so gravity_start always precedes its gravity_run rows, and a run that was
		// started is recorded as soon as it exists.
		Started: func(ctx context.Context, runID string) {
			s.auditPihole(ctx, tg.main, audit.ActionGravityStart, nil, map[string]any{"run_id": runID, "instances": names})
		},
		Finished: func(ctx context.Context, runID string, r gravity.Result) {
			detail := map[string]any{"run_id": runID, "outcome": r.Status, "duration_ms": r.Duration.Milliseconds()}
			if r.Status == gravity.InstanceOK {
				detail["domains"], detail["lists_failed"] = r.Domains, r.ListsFailed
			}
			err := r.Err
			if errors.Is(err, gravity.ErrEmpty) {
				detail["error_code"] = gravity.CodeEmpty
			}
			s.auditPihole(ctx, refs[r.ID], audit.ActionGravityRun, err, detail)
		},
	})
	var be *gravity.BusyError
	if errors.As(err, &be) {
		busy := make([]string, len(be.Members))
		for i, m := range be.Members {
			busy[i] = m.Name
		}
		return nil, &rbac.Error{
			Code:    rbac.CodeConflict,
			Message: "Gravity is already running on " + joinNames(busy) + ". Wait for that run to end.",
			Details: map[string]any{"instances": busy},
		}
	}
	if err != nil {
		return nil, err
	}
	return gen.StartGravity202JSONResponse(gravityJSON(snap)), nil
}

func (s *Server) GetLatestGravity(ctx context.Context, req gen.GetLatestGravityRequestObject) (gen.GetLatestGravityResponseObject, error) {
	tg, err := s.resolveTarget(ctx, req.Target, rbac.ListsView)
	if err != nil {
		return nil, err
	}
	after, err := afterOf(req.Params.After)
	if err != nil {
		return nil, err
	}
	snap, ok := s.Gravity.Latest(tg.t.String(), after)
	if !ok {
		return nil, &rbac.Error{Code: rbac.CodeNotFound, Message: "There hasn't been a gravity run on this target since the app started."}
	}
	return gen.GetLatestGravity200JSONResponse(gravityJSON(snap)), nil
}

func (s *Server) GetGravityRun(ctx context.Context, req gen.GetGravityRunRequestObject) (gen.GetGravityRunResponseObject, error) {
	tg, err := s.resolveTarget(ctx, req.Target, rbac.ListsView)
	if err != nil {
		return nil, err
	}
	if !runIDPattern.MatchString(req.Run) {
		return nil, invalid("run", "That isn't a gravity run's ID.")
	}
	after, err := afterOf(req.Params.After)
	if err != nil {
		return nil, err
	}
	snap, ok := s.Gravity.Get(tg.t.String(), req.Run, after)
	if !ok {
		return nil, &rbac.Error{Code: rbac.CodeNotFound, Message: "That gravity run isn't known: runs are kept for an hour after they end, and not over a restart."}
	}
	return gen.GetGravityRun200JSONResponse(gravityJSON(snap)), nil
}

var runIDPattern = regexp.MustCompile(`^[0-9a-f]{24}$`)

func afterOf(p *gen.GravityAfter) (int, error) {
	switch {
	case p == nil:
		return 0, nil
	case *p < 0:
		return 0, invalid("after", "after can't be negative.")
	}
	return *p, nil
}

func joinNames(names []string) string {
	switch len(names) {
	case 0:
		return ""
	case 1:
		return `"` + names[0] + `"`
	}
	out := ""
	for i, n := range names {
		switch {
		case i == 0:
		case i == len(names)-1:
			out += " and "
		default:
			out += ", "
		}
		out += `"` + n + `"`
	}
	return out
}

func gravityJSON(snap gravity.Snapshot) gen.GravityRun {
	out := gen.GravityRun{
		Id: snap.ID, Target: snap.Target, Status: gen.GravityRunStatus(snap.Status), StartedAt: snap.Started.UTC(),
		StartedBy: snap.StartedBy, Results: make([]gen.GravityInstanceResult, len(snap.Results)),
		Output: make([]gen.GravityLine, len(snap.Lines)), OutputLastSeq: snap.LastSeq, OutputTruncated: snap.Truncated,
	}
	if !snap.Finished.IsZero() {
		f := snap.Finished.UTC()
		out.FinishedAt = &f
	}
	for i, l := range snap.Lines {
		out.Output[i] = gen.GravityLine{Seq: l.Seq, InstanceId: l.Instance, Text: l.Text}
	}
	for i, r := range snap.Results {
		res := gen.GravityInstanceResult{
			Instance: r.Name, InstanceId: r.ID, Primary: r.Primary, Status: gen.GravityInstanceResultStatus(r.Status),
		}
		if r.Reason != "" {
			reason := gen.GravityInstanceResultReason(r.Reason)
			res.Reason = &reason
		}
		if r.Duration > 0 {
			ms := r.Duration.Milliseconds()
			res.DurationMs = &ms
		}
		if r.Status == gravity.InstanceOK || errors.Is(r.Err, gravity.ErrEmpty) {
			domains, failed := r.Domains, r.ListsFailed
			res.Domains, res.ListsFailed = &domains, &failed
			res.LastUpdate = unixTime(r.LastUpdate)
		}
		if r.Err != nil && r.Status == gravity.InstanceFailed {
			res.Error = gravityError(r)
		}
		out.Results[i] = res
	}
	return out
}

// gravityError describes an instance's failure as a write's error is described.
func gravityError(r gravity.Result) *gen.WriteError {
	if errors.Is(r.Err, gravity.ErrEmpty) {
		return &gen.WriteError{
			Code:    gravity.CodeEmpty,
			Message: "Gravity on Pi-hole \"" + r.Name + "\" ended with no domains, so the run stopped there. Check its lists.",
		}
	}
	f := describeCode(&piholeFailure{Instance: r.Name, Err: r.Err})
	if f.internal {
		return &gen.WriteError{Code: "internal", Message: "Something went wrong."}
	}
	return &gen.WriteError{Code: f.code, Message: f.message}
}
