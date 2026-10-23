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

// GetTargetSummary reads the blocking status and both sets of counters in one go. If any of them fails the request
// fails: the dashboard polls, so a partial picture would only flicker.
func (s *Server) GetTargetSummary(ctx context.Context, req gen.GetTargetSummaryRequestObject) (gen.GetTargetSummaryResponseObject, error) {
	ref, err := s.resolveTarget(ctx, req.Target, "")
	if err != nil {
		return nil, err
	}
	var (
		st   *piholeapi.Status
		day  *piholeapi.DatabaseSummary
		live *piholeapi.LiveSummary
	)
	err = s.call(ctx, ref, func(ctx context.Context, c *piholeapi.Client) error {
		var err error
		if st, err = c.GetStatus(ctx); err != nil {
			return err
		}
		until := time.Now()
		if day, err = c.GetDatabaseSummary(ctx, until.Add(-24*time.Hour), until); err != nil {
			return err
		}
		live, err = c.GetLiveSummary(ctx)
		return err
	})
	if err != nil {
		return nil, err
	}
	out := gen.TargetSummary{
		Blocking: blockingJSON(st),
		Last24h: gen.DatabaseTotals{
			Queries: day.TotalQueries, Blocked: day.BlockedQueries, PercentBlocked: day.PercentBlocked,
			Clients: day.TotalClients,
		},
		Live: gen.LiveCounters{
			Queries: live.Queries.Total, Blocked: live.Queries.Blocked, PercentBlocked: live.Queries.PercentBlocked,
			UniqueDomains: live.Queries.UniqueDomains, Forwarded: live.Queries.Forwarded, Cached: live.Queries.Cached,
			ActiveClients: live.Clients.Active, TotalClients: live.Clients.Total,
			DomainsOnBlocklist: live.Gravity.DomainsBeingBlocked,
			Status:             nonNilCounts(live.Queries.Status), Replies: nonNilCounts(live.Queries.Replies),
		},
	}
	return gen.GetTargetSummary200JSONResponse(out), nil
}

func (s *Server) GetBlocking(ctx context.Context, req gen.GetBlockingRequestObject) (gen.GetBlockingResponseObject, error) {
	ref, err := s.resolveTarget(ctx, req.Target, "")
	if err != nil {
		return nil, err
	}
	var st *piholeapi.Status
	err = s.call(ctx, ref, func(ctx context.Context, c *piholeapi.Client) error {
		var err error
		st, err = c.GetStatus(ctx)
		return err
	})
	if err != nil {
		return nil, err
	}
	return gen.GetBlocking200JSONResponse(blockingJSON(st)), nil
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
	ref, err := s.resolveTarget(ctx, req.Target, rbac.BlockingToggle)
	if err != nil {
		return nil, err
	}
	var st *piholeapi.Status
	var attempted bool
	err = s.call(ctx, ref, func(ctx context.Context, c *piholeapi.Client) error {
		attempted = true
		var err error
		st, err = c.SetBlocking(ctx, b.Enabled, timer)
		return err
	})
	if attempted {
		detail := map[string]any{"enabled": b.Enabled}
		if b.Timer != nil {
			detail["timer"] = *b.Timer
		}
		s.auditPihole(ctx, ref, audit.ActionBlockingSet, err, detail)
	}
	if err != nil {
		return nil, err
	}
	return gen.SetBlocking200JSONResponse(blockingJSON(st)), nil
}

// RestartDNS checks the Pi-hole answers before asking for the restart, so a Pi-hole that is down is reported as
// such. FTL's API goes down with the resolver, so a connection dropped by the restart request itself is reported as
// unconfirmed rather than as a failure, and doesn't mark the instance down.
func (s *Server) RestartDNS(ctx context.Context, req gen.RestartDNSRequestObject) (gen.RestartDNSResponseObject, error) {
	ref, err := s.resolveTarget(ctx, req.Target, rbac.DNSRestart)
	if err != nil {
		return nil, err
	}
	var sent, confirmed bool
	err = s.call(ctx, ref, func(ctx context.Context, c *piholeapi.Client) error {
		sent, confirmed = false, false
		if _, err := c.GetStatus(ctx); err != nil {
			return err
		}
		sent = true
		err := c.RestartDNS(ctx)
		if errors.Is(err, piholeapi.ErrUnreachable) && ctx.Err() == nil {
			return nil // the restart took the connection down with it
		}
		confirmed = err == nil
		return err
	})
	if sent {
		s.auditPihole(ctx, ref, audit.ActionDNSRestart, err, map[string]any{"confirmed": confirmed})
	}
	if err != nil {
		return nil, err
	}
	return gen.RestartDNS200JSONResponse{Confirmed: confirmed}, nil
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
