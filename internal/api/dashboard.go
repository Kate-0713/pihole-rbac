// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
)

// memberSummary is what one instance reports for the dashboard.
type memberSummary struct {
	st   *piholeapi.Status
	day  *piholeapi.DatabaseSummary
	live *piholeapi.LiveSummary
}

func readSummary(ctx context.Context, c *piholeapi.Client) (memberSummary, error) {
	var ms memberSummary
	var err error
	if ms.st, err = c.GetStatus(ctx); err != nil {
		return ms, err
	}
	until := time.Now()
	if ms.day, err = c.GetDatabaseSummary(ctx, until.Add(-24*time.Hour), until); err != nil {
		return ms, err
	}
	ms.live, err = c.GetLiveSummary(ctx)
	return ms, err
}

// GetTargetSummary reads the blocking status and both sets of counters in one go. For an instance, if any of them
// fails the request fails: the dashboard polls, so a partial picture would only flicker. A mirrored group reads every
// member at once and adds up those that answered (see TargetSummary in the spec); it fails only when none did.
func (s *Server) GetTargetSummary(ctx context.Context, req gen.GetTargetSummaryRequestObject) (gen.GetTargetSummaryResponseObject, error) {
	tg, err := s.resolveTarget(ctx, req.Target, "")
	if err != nil {
		return nil, err
	}
	sums := make([]memberSummary, len(tg.members))
	outs, err := s.fanOut(ctx, tg, func(ctx context.Context, i int, _ instanceRef, c *piholeapi.Client) error {
		var err error
		sums[i], err = readSummary(ctx, c)
		return err
	})
	if err != nil {
		return nil, err
	}
	if !anyOK(outs) {
		return nil, firstFailure(outs)
	}
	var answered []memberSummary
	var states []*piholeapi.Status
	for i, o := range outs {
		if o.ok() {
			answered = append(answered, sums[i])
			states = append(states, sums[i].st)
		}
	}
	out := summaryJSON(answered, outs[0].ok())
	out.Blocking = combinedBlocking(states)
	out.Members = memberReads(tg, outs, func(i int, r *gen.MemberRead) {
		b := blockingJSON(sums[i].st)
		r.Blocking = &b
	})
	return gen.GetTargetSummary200JSONResponse(out), nil
}

// summaryJSON adds up the counters of the instances that answered. Percentages are worked out from the sums; the
// blocklist is the same on every member of a mirrored group, so its size is the primary's (the first, when
// primaryAnswered) or else the largest.
func summaryJSON(sums []memberSummary, primaryAnswered bool) gen.TargetSummary {
	var out gen.TargetSummary
	out.Live.Status, out.Live.Replies = map[string]int{}, map[string]int{}
	for i, ms := range sums {
		d, l := ms.day, ms.live
		out.Last24h.Queries += d.TotalQueries
		out.Last24h.Blocked += d.BlockedQueries
		out.Last24h.Clients += d.TotalClients
		out.Live.Queries += l.Queries.Total
		out.Live.Blocked += l.Queries.Blocked
		out.Live.UniqueDomains += l.Queries.UniqueDomains
		out.Live.Forwarded += l.Queries.Forwarded
		out.Live.Cached += l.Queries.Cached
		out.Live.ActiveClients += l.Clients.Active
		out.Live.TotalClients += l.Clients.Total
		for k, v := range l.Queries.Status {
			out.Live.Status[k] += v
		}
		for k, v := range l.Queries.Replies {
			out.Live.Replies[k] += v
		}
		if (i == 0 && primaryAnswered) || (!primaryAnswered && l.Gravity.DomainsBeingBlocked > out.Live.DomainsOnBlocklist) {
			out.Live.DomainsOnBlocklist = l.Gravity.DomainsBeingBlocked
		}
	}
	if len(sums) == 1 {
		// One instance: Pi-hole's own percentages, exactly as before.
		out.Last24h.PercentBlocked = sums[0].day.PercentBlocked
		out.Live.PercentBlocked = sums[0].live.Queries.PercentBlocked
		return out
	}
	out.Last24h.PercentBlocked = percent(out.Last24h.Blocked, out.Last24h.Queries)
	out.Live.PercentBlocked = percent(out.Live.Blocked, out.Live.Queries)
	return out
}

func percent(part, whole int) float64 {
	if whole == 0 {
		return 0
	}
	return float64(part) * 100 / float64(whole)
}

// combinedBlocking is the blocking state of the instances that answered: their common state, or mixed when they
// differ. A timer is the soonest of theirs, when they all agree.
func combinedBlocking(states []*piholeapi.Status) gen.BlockingStatus {
	out := blockingJSON(states[0])
	for _, st := range states[1:] {
		b := blockingJSON(st)
		if b.Blocking != out.Blocking {
			return gen.BlockingStatus{Blocking: gen.BlockingStatusBlockingMixed}
		}
		if b.Timer != nil && (out.Timer == nil || *b.Timer < *out.Timer) {
			out.Timer = b.Timer
		}
	}
	return out
}

func (s *Server) GetBlocking(ctx context.Context, req gen.GetBlockingRequestObject) (gen.GetBlockingResponseObject, error) {
	tg, err := s.resolveTarget(ctx, req.Target, "")
	if err != nil {
		return nil, err
	}
	sts := make([]*piholeapi.Status, len(tg.members))
	outs, err := s.fanOut(ctx, tg, func(ctx context.Context, i int, _ instanceRef, c *piholeapi.Client) error {
		var err error
		sts[i], err = c.GetStatus(ctx)
		return err
	})
	if err != nil {
		return nil, err
	}
	if !anyOK(outs) {
		return nil, firstFailure(outs)
	}
	var answered []*piholeapi.Status
	for i, o := range outs {
		if o.ok() {
			answered = append(answered, sts[i])
		}
	}
	return gen.GetBlocking200JSONResponse(combinedBlocking(answered)), nil
}

// SetBlocking sets an explicit state rather than toggling, so a repeated or crossed request can't flip it the wrong
// way.
func (s *Server) SetBlocking(ctx context.Context, req gen.SetBlockingRequestObject) (gen.SetBlockingResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, invalid("body", "The request body is missing.")
	}
	var timer time.Duration
	if b.Timer != nil {
		if b.Enabled {
			return nil, invalid("timer", "A timer can only be set when disabling blocking.")
		}
		if *b.Timer < 1 || *b.Timer > maxBlockingTimer {
			return nil, invalid("timer", "The timer must be between 1 and %d seconds.", maxBlockingTimer)
		}
		timer = time.Duration(*b.Timer) * time.Second
	}
	tg, err := s.resolveTarget(ctx, req.Target, rbac.BlockingToggle)
	if err != nil {
		return nil, err
	}
	sts := make([]*piholeapi.Status, len(tg.members))
	outs, err := s.fanOut(ctx, tg, func(ctx context.Context, i int, _ instanceRef, c *piholeapi.Client) error {
		var err error
		sts[i], err = c.SetBlocking(ctx, b.Enabled, timer)
		return err
	})
	for i, m := range tg.members {
		if outs[i].ran {
			detail := map[string]any{"enabled": b.Enabled}
			if b.Timer != nil {
				detail["timer"] = *b.Timer
			}
			s.auditPihole(ctx, m, audit.ActionBlockingSet, outs[i].callErr, detail)
		}
	}
	if err != nil {
		return nil, err
	}
	results := resultsOf(outs, func(i int, o outcome, st gen.WriteStatus, we *gen.WriteError) gen.BlockingWriteResult {
		r := gen.BlockingWriteResult{Instance: o.ref.name, InstanceId: o.ref.id, Status: st, Error: we}
		if o.ok() {
			bs := blockingJSON(sts[i])
			r.Blocking = &bs
		}
		return r
	})
	multi, err := s.finishWrite(ctx, outs, results)
	if err != nil {
		return nil, err
	}
	if multi {
		return gen.SetBlocking207JSONResponse{Results: results}, nil
	}
	return gen.SetBlocking200JSONResponse{Results: results}, nil
}

// RestartDNS checks the Pi-hole answers before asking for the restart, so a Pi-hole that is down is reported as
// such. FTL's API goes down with the resolver, so a connection dropped by the restart request itself is reported as
// unconfirmed rather than as a failure, and doesn't mark the instance down.
func (s *Server) RestartDNS(ctx context.Context, req gen.RestartDNSRequestObject) (gen.RestartDNSResponseObject, error) {
	tg, err := s.resolveTarget(ctx, req.Target, rbac.DNSRestart)
	if err != nil {
		return nil, err
	}
	n := len(tg.members)
	sent, confirmed := make([]bool, n), make([]bool, n)
	outs, err := s.fanOut(ctx, tg, func(ctx context.Context, i int, _ instanceRef, c *piholeapi.Client) error {
		sent[i], confirmed[i] = false, false
		if _, err := c.GetStatus(ctx); err != nil {
			return err
		}
		sent[i] = true
		err := c.RestartDNS(ctx)
		if errors.Is(err, piholeapi.ErrUnreachable) && ctx.Err() == nil {
			return nil // the restart took the connection down with it
		}
		confirmed[i] = err == nil
		return err
	})
	for i, m := range tg.members {
		if sent[i] {
			s.auditPihole(ctx, m, audit.ActionDNSRestart, outs[i].callErr, map[string]any{"confirmed": confirmed[i]})
		}
	}
	if err != nil {
		return nil, err
	}
	results := resultsOf(outs, func(i int, o outcome, st gen.WriteStatus, we *gen.WriteError) gen.DNSRestartResult {
		r := gen.DNSRestartResult{Instance: o.ref.name, InstanceId: o.ref.id, Status: st, Error: we}
		if o.ok() {
			c := confirmed[i]
			r.Confirmed = &c
		}
		return r
	})
	multi, err := s.finishWrite(ctx, outs, results)
	if err != nil {
		return nil, err
	}
	if multi {
		return gen.RestartDNS207JSONResponse{Results: results}, nil
	}
	return gen.RestartDNS200JSONResponse{Results: results}, nil
}

// blockingJSON reports Pi-hole's blocking state, with anything it doesn't document as unknown, and the timer in
// whole seconds, rounded up.
func blockingJSON(st *piholeapi.Status) gen.BlockingStatus {
	state := st.Blocking
	switch state {
	case piholeapi.BlockingEnabled, piholeapi.BlockingDisabled, "failed", "unknown":
	default:
		state = "unknown"
	}
	out := gen.BlockingStatus{Blocking: gen.BlockingStatusBlocking(state)}
	if st.Timer != nil && *st.Timer > 0 {
		secs := int(math.Ceil(*st.Timer))
		out.Timer = &secs
	}
	return out
}

func nonNilCounts(m map[string]int) map[string]int {
	if m == nil {
		return map[string]int{}
	}
	return m
}
