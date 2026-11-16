// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/clientoverrides"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
)

// Temporary client group changes (v2.6.0). The API does what any client write does: it checks the permission on the
// target, reads each member, fans the write out and answers with a result per instance. The override is stored
// between the read and the write, so an app that stops in between still knows what to put back; the service keeps
// it, settles the reverts and writes their audit rows.

func (s *Server) overrides() (*clientoverrides.Service, error) {
	if s.ClientOverrides == nil {
		return nil, errNoInstances
	}
	return s.ClientOverrides, nil
}

func (s *Server) ListTemporaryClientChanges(ctx context.Context, req gen.ListTemporaryClientChangesRequestObject) (gen.ListTemporaryClientChangesResponseObject, error) {
	svc, err := s.overrides()
	if err != nil {
		return nil, err
	}
	tg, err := s.resolveTarget(ctx, req.Target, rbac.ClientsView)
	if err != nil {
		return nil, err
	}
	list, err := svc.List(ctx, tg.t)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if svc.Now != nil {
		now = svc.Now()
	}
	out := gen.TemporaryClientChangeList{Changes: make([]gen.TemporaryClientChange, 0, len(list))}
	for _, o := range list {
		out.Changes = append(out.Changes, changeJSON(o, now, ""))
	}
	if !tg.isGroup() {
		covering, err := svc.Covering(ctx, tg.t.ID)
		if err != nil {
			return nil, err
		}
		for _, o := range covering {
			// Only those the user could see on the group itself: they name a client and a reason.
			out.Changes = append(out.Changes, changeJSON(o, now, o.Target.String()))
		}
	}
	lim := svc.CurrentLimits()
	out.MaxMinutes, out.ReasonRequired = int(lim.Max/time.Minute), lim.ReasonRequired
	return gen.ListTemporaryClientChanges200JSONResponse(out), nil
}

// startRead is what a start learns from one member before anything is stored.
type startRead struct {
	original []string
	ids      []int
	groups   []piholeapi.Group
}

func (s *Server) StartTemporaryClientChange(ctx context.Context, req gen.StartTemporaryClientChangeRequestObject) (gen.StartTemporaryClientChangeResponseObject, error) {
	svc, err := s.overrides()
	if err != nil {
		return nil, err
	}
	b := req.Body
	if b == nil {
		return nil, invalid("body", "The request body is missing.")
	}
	lim := svc.CurrentLimits()
	if err := clientoverrides.CheckClient(b.Client); err != nil {
		return nil, err
	}
	if err := clientoverrides.CheckGroups(b.Groups); err != nil {
		return nil, err
	}
	reason := ""
	if b.Reason != nil {
		reason = *b.Reason
	}
	if reason, err = clientoverrides.CheckReason(reason, lim.ReasonRequired); err != nil {
		return nil, err
	}
	now := time.Now()
	if svc.Now != nil {
		now = svc.Now()
	}
	endsAt, err := clientoverrides.StartEnd(now, b.DurationMinutes, b.EndsAt, lim)
	if err != nil {
		return nil, err
	}
	tg, err := s.resolveTarget(ctx, req.Target, rbac.ClientsEdit)
	if err != nil {
		return nil, err
	}
	if tg.isGroup() {
		if err := s.primaryHas(ctx, tg, "client "+b.Client, func(ctx context.Context, c *piholeapi.Client) (bool, error) {
			_, found, err := lookupClient(ctx, c, b.Client)
			return found, err
		}); err != nil {
			return nil, err
		}
	}

	// Read every member: its client, and the groups by name. A member without the client, or without a group of a
	// name, fails on its own and isn't stored.
	n := len(tg.members)
	reads := make([]startRead, n)
	outs, err := s.fanOut(ctx, tg, func(ctx context.Context, i int, m instanceRef, c *piholeapi.Client) error {
		cur, found, err := lookupClient(ctx, c, b.Client)
		if err != nil {
			return err
		}
		if !found {
			return tg.missing(m, "There's no client "+b.Client+" on "+m.name+".")
		}
		groups, err := c.ListGroups(ctx)
		if err != nil {
			return err
		}
		ids, missing := clientoverrides.Resolve(b.Groups, groups)
		if len(missing) > 0 {
			return &memberError{code: codePiholeGroupMissing, message: fmt.Sprintf("%s has no Pi-hole group named %q.", m.name, missing[0])}
		}
		reads[i] = startRead{original: clientoverrides.Names(cur.Groups, groups), ids: ids, groups: groups}
		return nil
	})
	if err != nil {
		return nil, err
	}
	var members []clientoverrides.NewMember
	var readOK []int
	changes := false
	for i, m := range tg.members {
		if !outs[i].ok() {
			continue
		}
		readOK = append(readOK, i)
		changes = changes || !clientoverrides.Same(reads[i].original, b.Groups)
		members = append(members, clientoverrides.NewMember{InstanceID: m.id, Instance: m.name, Original: reads[i].original, Override: dedupNames(b.Groups)})
	}
	if len(members) == 0 {
		// Nothing was stored: no member could be read. The request fails with the first member's failure.
		_, err := s.finishWrite(ctx, outs, startResults(outs, nil, nil, nil))
		return nil, err
	}
	if !changes {
		return nil, invalid("groups", "%s is already in exactly those groups, so there's nothing to change.", b.Client)
	}
	a := actor(ctx)
	o, err := svc.Create(ctx, clientoverrides.NewInput{Target: tg.t, Client: b.Client, StartsAt: now, EndsAt: endsAt, Reason: reason,
		By: a.Username, Members: members})
	if err != nil {
		return nil, err
	}

	// Change the members that took the read, at once. A member whose groups already match isn't written.
	sub := tg
	sub.members = make([]instanceRef, len(readOK))
	for j, i := range readOK {
		sub.members[j] = tg.members[i]
	}
	k := len(readOK)
	attempted, details := make([]bool, k), make([]map[string]any, k)
	wouts, werr := s.fanOut(ctx, sub, func(ctx context.Context, j int, m instanceRef, c *piholeapi.Client) error {
		r := reads[readOK[j]]
		if clientoverrides.Same(r.original, b.Groups) {
			return nil
		}
		cur, found, err := lookupClient(ctx, c, b.Client)
		if err != nil {
			return err
		}
		if !found {
			return tg.missing(m, "There's no client "+b.Client+" on "+m.name+".")
		}
		details[j] = map[string]any{"override_id": o.ID, "client": b.Client, "reason": reason,
			"ends_at": endsAt.UTC().Format(time.RFC3339), "groups_before": r.original, "groups_after": dedupNames(b.Groups)}
		attempted[j] = true
		_, err = c.UpdateClientGroups(ctx, cur.Client, cur.Comment, r.ids)
		return err
	})
	var entries []audit.Entry
	var failed []int64
	for j, m := range sub.members {
		if wouts[j].callErr != nil {
			failed = append(failed, m.id)
		}
		if !attempted[j] {
			continue
		}
		if wouts[j].callErr == nil {
			s.markProtected(ctx, m, details[j])
		}
		entries = append(entries, s.piholeEntry(ctx, m, audit.ActionClientTempSet, wouts[j].callErr, details[j]))
	}
	saved, derr := svc.Drop(ctx, o.ID, failed, entries)
	if derr != nil {
		s.Logger.Error("recording a temporary client change", "override", o.ID, "err", derr)
	}
	s.pokeDrift(ctx, tg)
	if werr != nil {
		return nil, werr
	}
	// One result per member, as read: those that couldn't be read keep their read failure.
	final := make([]outcome, n)
	for i := range outs {
		final[i] = outs[i]
	}
	for j, i := range readOK {
		final[i] = wouts[j]
	}
	results := startResults(final, tg.members, reads, b.Groups)
	multi, err := s.finishWrite(ctx, final, results)
	if err != nil {
		return nil, err
	}
	for i := range tg.members {
		if final[i].ok() && clientoverrides.Same(reads[i].original, b.Groups) {
			u := true
			results[i].Unchanged = &u
		}
	}
	out := gen.TemporaryClientWriteResults{Results: results}
	if derr == nil {
		c := changeJSON(saved, now, "")
		out.Change = &c
	}
	if multi {
		return gen.StartTemporaryClientChange207JSONResponse(out), nil
	}
	return gen.StartTemporaryClientChange200JSONResponse(out), nil
}

func dedupNames(names []string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}

// startResults builds a start's results from its outcomes, in member order. reads and want are nil for a request
// that failed before anything was stored.
func startResults(outs []outcome, members []instanceRef, reads []startRead, want []string) []gen.TemporaryClientWriteResult {
	return resultsOf(outs, func(i int, o outcome, st gen.WriteStatus, we *gen.WriteError) gen.TemporaryClientWriteResult {
		r := gen.TemporaryClientWriteResult{Instance: o.ref.name, InstanceId: o.ref.id, Status: st, Error: we}
		if o.ok() && reads != nil {
			g := dedupNames(want)
			r.Groups = &g
		}
		return r
	})
}

func (s *Server) UpdateTemporaryClientChange(ctx context.Context, req gen.UpdateTemporaryClientChangeRequestObject) (gen.UpdateTemporaryClientChangeResponseObject, error) {
	svc, err := s.overrides()
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, invalid("body", "The request body is missing.")
	}
	tg, err := s.resolveTarget(ctx, req.Target, rbac.ClientsEdit)
	if err != nil {
		return nil, err
	}
	o, err := svc.SetEnd(ctx, actor(ctx), req.Id, tg.t, req.Body.EndsAt)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if svc.Now != nil {
		now = svc.Now()
	}
	return gen.UpdateTemporaryClientChange200JSONResponse(changeJSON(o, now, "")), nil
}

func (s *Server) EndTemporaryClientChange(ctx context.Context, req gen.EndTemporaryClientChangeRequestObject) (gen.EndTemporaryClientChangeResponseObject, error) {
	svc, err := s.overrides()
	if err != nil {
		return nil, err
	}
	tg, err := s.resolveTarget(ctx, req.Target, rbac.ClientsEdit)
	if err != nil {
		return nil, err
	}
	o, err := svc.BeginEnd(ctx, actor(ctx), req.Id, tg.t)
	if err != nil {
		return nil, err
	}
	res, multi, err := s.revertThrough(ctx, svc, tg, o, false)
	if err != nil {
		return nil, err
	}
	if multi {
		return gen.EndTemporaryClientChange207JSONResponse(res), nil
	}
	return gen.EndTemporaryClientChange200JSONResponse(res), nil
}

func (s *Server) RetryTemporaryClientChange(ctx context.Context, req gen.RetryTemporaryClientChangeRequestObject) (gen.RetryTemporaryClientChangeResponseObject, error) {
	svc, err := s.overrides()
	if err != nil {
		return nil, err
	}
	tg, err := s.resolveTarget(ctx, req.Target, rbac.ClientsEdit)
	if err != nil {
		return nil, err
	}
	o, err := svc.BeginRetry(ctx, req.Id, tg.t)
	if err != nil {
		return nil, err
	}
	res, multi, err := s.revertThrough(ctx, svc, tg, o, true)
	if err != nil {
		return nil, err
	}
	if multi {
		return gen.RetryTemporaryClientChange207JSONResponse(res), nil
	}
	return gen.RetryTemporaryClientChange200JSONResponse(res), nil
}

// revertThrough puts back the members of o that aren't yet, at once, and settles them. A member that is disabled isn't
// in the target, so isn't tried here: the scheduler retries it. Whatever was tried is settled even when the request
// fails.
func (s *Server) revertThrough(ctx context.Context, svc *clientoverrides.Service, tg target, o clientoverrides.Override, retry bool) (gen.TemporaryClientWriteResults, bool, error) {
	pending := o.Pending()
	sub := tg
	sub.members = slices.DeleteFunc(slices.Clone(tg.members), func(m instanceRef) bool {
		return !slices.ContainsFunc(pending, func(p clientoverrides.Member) bool { return p.InstanceID == m.id })
	})
	if len(sub.members) == 0 {
		return gen.TemporaryClientWriteResults{}, false, &rbac.Error{Code: rbac.CodeConflict,
			Message: "None of that change's instances is enabled. The app puts the client back when one is.",
			Details: map[string]any{"override_id": o.ID}}
	}
	n := len(sub.members)
	changes, raw, called := make([]clientoverrides.Change, n), make([]error, n), make([]bool, n)
	outs, ferr := s.fanOut(ctx, sub, func(ctx context.Context, i int, m instanceRef, c *piholeapi.Client) error {
		called[i] = true
		p := pending[slices.IndexFunc(pending, func(p clientoverrides.Member) bool { return p.InstanceID == m.id })]
		ch, err := clientoverrides.RevertMember(ctx, c, p.Client, p.Original, p.Override)
		changes[i], raw[i] = ch, err
		if errors.Is(err, clientoverrides.ErrClientGone) {
			return &memberError{code: codeNotFound, message: "There's no client " + p.Client + " on " + m.name + " any more."}
		}
		return err
	})
	atts := make([]clientoverrides.Attempt, 0, n)
	for i, m := range sub.members {
		p := pending[slices.IndexFunc(pending, func(p clientoverrides.Member) bool { return p.InstanceID == m.id })]
		err := raw[i]
		if err == nil && outs[i].callErr != nil {
			err = outs[i].callErr // the pool refused, or the call failed before the function ran
		}
		atts = append(atts, clientoverrides.Attempt{Member: p, Called: called[i], Change: changes[i], Err: err})
	}
	a := actor(ctx)
	saved, serr := svc.Settle(ctx, o, atts, clientoverrides.SettleOptions{Actor: &a, Retry: retry})
	s.pokeDrift(ctx, tg)
	if ferr != nil {
		return gen.TemporaryClientWriteResults{}, false, ferr
	}
	results := resultsOf(outs, func(i int, oc outcome, st gen.WriteStatus, we *gen.WriteError) gen.TemporaryClientWriteResult {
		r := gen.TemporaryClientWriteResult{Instance: oc.ref.name, InstanceId: oc.ref.id, Status: st, Error: we}
		if oc.ok() {
			g := changes[i].After
			if g == nil {
				g = []string{}
			}
			r.Groups = &g
			if !changes[i].Sent {
				u := true
				r.Unchanged = &u
			}
			if len(changes[i].Missing) > 0 {
				m := changes[i].Missing
				r.MissingGroups = &m
			}
		}
		return r
	})
	multi, err := s.finishWrite(ctx, outs, results)
	if err != nil {
		return gen.TemporaryClientWriteResults{}, false, err
	}
	out := gen.TemporaryClientWriteResults{Results: results}
	if serr == nil {
		now := time.Now()
		if svc.Now != nil {
			now = svc.Now()
		}
		c := changeJSON(saved, now, "")
		out.Change = &c
	}
	return out, multi, nil
}

// changeJSON is an override as the API shows it. via is the mirrored group's target when it is listed on an instance
// it was made on through the group.
func changeJSON(o clientoverrides.Override, now time.Time, via string) gen.TemporaryClientChange {
	out := gen.TemporaryClientChange{Id: o.ID, Target: o.Target.String(), TargetName: o.TargetName, Client: o.Client,
		StartsAt: o.StartsAt, EndsAt: o.EndsAt, Reason: o.Reason, Status: gen.TemporaryClientChangeStatus(o.Status),
		Overdue: o.Overdue(now), CreatedBy: o.CreatedBy, Members: make([]gen.TemporaryClientMember, 0, len(o.Members))}
	if via != "" {
		out.Via = &via
	}
	if o.EndedBy != "" {
		by, at := o.EndedBy, o.EndedAt
		out.EndedBy, out.EndedAt = &by, &at
	}
	if !o.FinishedAt.IsZero() {
		at := o.FinishedAt
		out.FinishedAt = &at
	}
	for _, m := range o.Members {
		gm := gen.TemporaryClientMember{InstanceId: m.InstanceID, Instance: m.Instance, OriginalGroups: nonNilStrings(m.Original),
			OverrideGroups: nonNilStrings(m.Override), RevertStatus: gen.TemporaryClientMemberRevertStatus(m.Status), Attempts: m.Attempts}
		if m.Code != "" {
			code := m.Code
			gm.RevertCode = &code
		}
		if mg, ok := m.Details["missing_groups"].([]any); ok && len(mg) > 0 {
			names := make([]string, 0, len(mg))
			for _, v := range mg {
				if sv, ok := v.(string); ok {
					names = append(names, sv)
				}
			}
			gm.MissingGroups = &names
		}
		if !m.RevertedAt.IsZero() {
			at := m.RevertedAt
			gm.RevertedAt = &at
		}
		out.Members = append(out.Members, gm)
	}
	return out
}
