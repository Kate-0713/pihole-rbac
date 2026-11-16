// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package clientoverrides

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
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

// callTimeout bounds one instance's reads and write in a revert.
const callTimeout = 20 * time.Second

// Attempt is how one member's revert went.
type Attempt struct {
	Member Member
	Called bool // the pool called the instance; false means it was skipped (down, disabled, no password)
	Change Change
	Err    error
}

// SettleOptions say who reverted and how.
type SettleOptions struct {
	// Actor is the person who ended the override or retried it; nil means the app's scheduler.
	Actor *rbac.Actor
	// Retry is a manual retry of a given-up revert: a member that fails again is given up on at once.
	Retry bool
}

// codeOf is an error's code for a member's result: a Pi-hole or instance code, or internal.
func codeOf(err error) string {
	switch {
	case errors.Is(err, ErrClientGone), errors.Is(err, instances.ErrNotFound):
		return "not_found"
	}
	if code := instances.Kind(err); code != "" {
		return code
	}
	return "internal"
}

// Settle records how a revert went on each member and writes the audit rows, in one transaction. A member that went
// back, or whose client is gone, is settled. Any other failure leaves it to be retried on the next pass, until a
// week after the override's end, when it is given up on. The override finishes when every member has settled:
// reverted, ended (a person ended it early), or failed when a member was given up on or lost its client.
func (s *Service) Settle(ctx context.Context, o Override, atts []Attempt, opts SettleOptions) (Override, error) {
	now := s.now()
	bg := context.WithoutCancel(ctx)
	var entries []audit.Entry
	err := s.Store.WithTx(bg, func(q *db.Queries) error {
		entries = entries[:0]
		for _, a := range atts {
			m := a.Member
			active, status, code := int64(0), RevertOK, ""
			details := map[string]any{}
			switch {
			case a.Err == nil:
				if len(a.Change.Missing) > 0 {
					details["missing_groups"] = a.Change.Missing
				}
			case errors.Is(a.Err, ErrClientGone):
				status, code = RevertFailed, "not_found"
			default:
				code = codeOf(a.Err)
				status = RevertFailed
				if !a.Called {
					status = RevertSkipped
				}
				active = 1
				if opts.Retry || now.Sub(o.EndsAt) > GiveUpAfter {
					status, active = RevertGivenUp, 0
				}
			}
			var rev sql.NullInt64
			if active == 0 {
				rev = sql.NullInt64{Int64: store.Millis(now), Valid: true}
			}
			dj, _ := json.Marshal(details)
			if err := q.SettleOverrideMember(bg, db.SettleOverrideMemberParams{ID: m.ID, Active: active, RevertStatus: status,
				RevertCode: sql.NullString{String: code, Valid: code != ""}, RevertDetails: string(dj), Attempts: int64(m.Attempts + 1), RevertedAt: rev}); err != nil {
				return err
			}
			if en, ok := s.entry(bg, o, a, status, code, details, opts, now); ok {
				entries = append(entries, en)
			}
		}
		fresh, err := s.get(bg, q, o.ID)
		if err != nil {
			return err
		}
		if fresh.Status == StatusActive && len(fresh.Pending()) == 0 {
			status := StatusReverted
			switch {
			case slices.ContainsFunc(fresh.Members, func(m Member) bool { return m.Status == RevertGivenUp || m.Status == RevertFailed }):
				status = StatusFailed
			case fresh.EndedBy != "":
				status = StatusEnded
			}
			if err := q.FinishClientOverride(bg, db.FinishClientOverrideParams{Status: status,
				FinishedAt: sql.NullInt64{Int64: store.Millis(now), Valid: true}, ID: o.ID}); err != nil {
				return err
			}
		}
		for _, e := range entries {
			if _, err := audit.Insert(bg, q, e); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		s.log().Error("client overrides: settling a revert", "override", o.ID, "err", err)
		return Override{}, err
	}
	for _, e := range entries {
		s.Audit.Log(e)
	}
	return s.Get(bg, o.ID)
}

// entry is the audit row of one member's revert. A person's end or retry writes one for every member. The app's own
// reverts write one only for a member something was sent to or that failed, and not again for a retry that fails the
// same way.
func (s *Service) entry(ctx context.Context, o Override, a Attempt, status, code string, details map[string]any,
	opts SettleOptions, now time.Time) (audit.Entry, bool) {
	m := a.Member
	failed := a.Err != nil
	repeat := failed && (m.Status == RevertFailed || m.Status == RevertSkipped) && m.Code == code && status != RevertGivenUp
	if opts.Actor == nil && !a.Change.Sent && (!failed || repeat) {
		return audit.Entry{}, false
	}
	d := map[string]any{"override_id": o.ID, "client": m.Client, "reason": o.Reason, "retry": opts.Retry || m.Attempts > 0,
		"status": status, "groups_before": nonNil(a.Change.Before), "groups_after": nonNil(a.Change.After)}
	for k, v := range details {
		d[k] = v
	}
	if o.Target.Kind == rbac.TargetGroup {
		d["via"] = o.Target.String()
	}
	if a.Change.Sent && s.ProtectedAdded != nil {
		if added := s.ProtectedAdded(ctx, m.InstanceID, a.Change.Before, a.Change.After); len(added) > 0 {
			d["protected_added"] = added
		}
	}
	en := audit.Entry{At: now, Username: SystemActor.Username, Action: audit.ActionClientTempRevert, Target: o.Target.String(),
		InstanceID: m.InstanceID, InstanceName: m.Instance, Detail: d}
	if opts.Actor != nil {
		en.UserID, en.Username, en.IP, en.Action = opts.Actor.UserID, opts.Actor.Username, opts.Actor.IP, audit.ActionClientTempEnd
	}
	if failed {
		d["error_code"] = code
		en.Err = a.Err
		if en.Err == nil {
			en.Err = errors.New(code)
		}
		if status == RevertGivenUp {
			en.Err = fmt.Errorf("gave up after %d attempts: %w", m.Attempts+1, en.Err)
		}
	}
	return en, true
}

// Check is one scheduler pass: it reverts every active override that is past its end, on the members not yet put
// back, which includes the ones an earlier pass failed on. One pass at a time: Run calls it from one goroutine.
func (s *Service) Check(ctx context.Context) {
	now := s.now()
	all, err := s.Active(ctx)
	if err != nil {
		s.log().Error("client overrides: reading the overrides", "err", err)
		return
	}
	for _, o := range all {
		if ctx.Err() != nil {
			return
		}
		if o.Overdue(now) {
			s.revert(ctx, o)
		}
	}
}

// revert puts back the members of o that aren't yet, each on its own instance at once, and settles them.
func (s *Service) revert(ctx context.Context, o Override) {
	pending := o.Pending()
	atts := make([]Attempt, len(pending))
	var wg sync.WaitGroup
	for i, m := range pending {
		wg.Go(func() {
			cctx, cancel := context.WithTimeout(ctx, callTimeout)
			defer cancel()
			atts[i] = Attempt{Member: m}
			atts[i].Err = s.Instances.Pool.Do(cctx, m.InstanceID, func(ctx context.Context, c *piholeapi.Client) error {
				atts[i].Called = true
				var err error
				atts[i].Change, err = RevertMember(ctx, c, m.Client, m.Original, m.Override)
				return err
			})
		})
	}
	wg.Wait()
	if _, err := s.Settle(ctx, o, atts, SettleOptions{}); err != nil {
		return
	}
	for _, a := range atts {
		if a.Err != nil && !errors.Is(a.Err, ErrClientGone) {
			s.log().Warn("client overrides: revert failed, will retry", "override", o.ID, "instance", a.Member.Instance, "code", codeOf(a.Err))
		}
	}
}

// Scheduler runs Check at start and every Tick.
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
