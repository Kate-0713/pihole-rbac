// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package clientoverrides

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/instances"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// Statuses of an override, and of a member's revert.
const (
	StatusActive   = "active"
	StatusReverted = "reverted" // it ran its time and every member went back
	StatusEnded    = "ended"    // a person ended it early and every member went back
	StatusFailed   = "failed"   // a member was given up on, or lost its client

	RevertPending = "pending"
	RevertOK      = "ok"
	RevertFailed  = "failed"
	RevertSkipped = "skipped" // the pool didn't call the instance (down, or missing its password)
	RevertGivenUp = "given_up"
)

// GiveUpAfter is how long after ends_at a revert is retried automatically before a member is given up on.
const GiveUpAfter = 7 * 24 * time.Hour

// SystemActor is who runs reverts.
var SystemActor = rbac.Actor{Username: audit.SystemUser}

// Service keeps temporary client changes and puts clients back. Permission checks and the Pi-hole writes of a start
// are the API's, which fans out like any client write; the service stores the override before that write, settles
// the reverts (its own pass, and an end or retry the API fans out) and writes their audit rows.
type Service struct {
	Store     *store.Store
	Audit     *audit.Logger
	Instances *instances.Service
	// Limits returns the settings a start or a change is checked against; nil means the defaults.
	Limits func() Limits
	// ProtectedAdded returns which of the groups a client was added to, by name, are protected Pi-hole groups on the
	// instance; nil means none are.
	ProtectedAdded func(ctx context.Context, instanceID int64, before, after []string) []string
	Logger         *slog.Logger
	// Now returns the current time; nil means time.Now.
	Now func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) log() *slog.Logger {
	if s.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return s.Logger
}

// CurrentLimits returns the limits a start or a change is checked against.
func (s *Service) CurrentLimits() Limits {
	if s.Limits == nil {
		return DefaultLimits
	}
	return s.Limits()
}

// Member is one instance an override changed.
type Member struct {
	ID         int64
	InstanceID int64
	Instance   string
	Client     string
	Original   []string
	Override   []string
	Active     bool // not settled yet
	Status     string
	Code       string
	Details    map[string]any
	Attempts   int
	RevertedAt time.Time
}

// Override is a temporary change of one client's groups on a target.
type Override struct {
	ID         int64
	Target     rbac.Target
	TargetName string
	Client     string
	StartsAt   time.Time
	EndsAt     time.Time
	Reason     string
	Status     string
	CreatedBy  string
	CreatedAt  time.Time
	EndedBy    string
	EndedAt    time.Time
	FinishedAt time.Time
	Members    []Member
}

// Overdue reports whether the override is past its end and still being put back.
func (o Override) Overdue(now time.Time) bool {
	return o.Status == StatusActive && !o.EndsAt.After(now)
}

// Pending returns the members still to be put back.
func (o Override) Pending() []Member {
	var out []Member
	for _, m := range o.Members {
		if m.Active {
			out = append(out, m)
		}
	}
	return out
}

func targetOf(instance, group sql.NullInt64) rbac.Target {
	if group.Valid {
		return rbac.GroupTarget(group.Int64)
	}
	return rbac.InstanceTarget(instance.Int64)
}

func nullTime(t time.Time) time.Time {
	if t.IsZero() {
		return t
	}
	return t.UTC()
}

func fromRow(id int64, instance, group sql.NullInt64, targetName, client string, starts, ends int64, reason, status, createdBy string,
	createdAt int64, endedBy sql.NullString, endedAt, finishedAt sql.NullInt64) Override {
	o := Override{ID: id, Target: targetOf(instance, group), TargetName: targetName, Client: client,
		StartsAt: store.FromMillis(starts), EndsAt: store.FromMillis(ends), Reason: reason, Status: status,
		CreatedBy: createdBy, CreatedAt: store.FromMillis(createdAt), EndedBy: endedBy.String}
	if endedAt.Valid {
		o.EndedAt = store.FromMillis(endedAt.Int64)
	}
	if finishedAt.Valid {
		o.FinishedAt = store.FromMillis(finishedAt.Int64)
	}
	return o
}

func memberOf(r db.ListOverrideMembersRow) Member {
	m := Member{ID: r.ID, InstanceID: r.InstanceID, Instance: r.InstanceName, Client: r.Client, Active: r.Active == 1,
		Status: r.RevertStatus, Code: r.RevertCode.String, Attempts: int(r.Attempts), Details: map[string]any{}}
	_ = json.Unmarshal([]byte(r.OriginalGroups), &m.Original)
	_ = json.Unmarshal([]byte(r.OverrideGroups), &m.Override)
	_ = json.Unmarshal([]byte(r.RevertDetails), &m.Details)
	if r.RevertedAt.Valid {
		m.RevertedAt = store.FromMillis(r.RevertedAt.Int64)
	}
	return m
}

// Get returns an override with its members.
func (s *Service) Get(ctx context.Context, id int64) (Override, error) {
	var o Override
	err := s.Store.WithTx(ctx, func(q *db.Queries) error {
		var err error
		o, err = s.get(ctx, q, id)
		return err
	})
	return o, err
}

func notFound(id int64) error {
	return &rbac.Error{Code: rbac.CodeNotFound, Message: "There's no such temporary change.", Details: map[string]any{"override_id": id}}
}

func (s *Service) get(ctx context.Context, q *db.Queries, id int64) (Override, error) {
	r, err := q.GetClientOverride(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return Override{}, notFound(id)
	}
	if err != nil {
		return Override{}, err
	}
	o := fromRow(r.ID, r.InstanceID, r.GroupID, r.TargetName, r.Client, r.StartsAt, r.EndsAt, r.Reason, r.Status, r.CreatedBy,
		r.CreatedAt, r.EndedBy, r.EndedAt, r.FinishedAt)
	return o, s.members(ctx, q, &o)
}

func (s *Service) members(ctx context.Context, q *db.Queries, o *Override) error {
	rows, err := q.ListOverrideMembers(ctx, o.ID)
	if err != nil {
		return err
	}
	o.Members = o.Members[:0]
	for _, r := range rows {
		o.Members = append(o.Members, memberOf(r))
	}
	return nil
}

// List returns a target's active overrides and those that finished in the last 30 days, active first, then the
// latest to end.
func (s *Service) List(ctx context.Context, t rbac.Target) ([]Override, error) {
	p := db.ListClientOverridesOnTargetParams{Since: sql.NullInt64{Int64: store.Millis(s.now().Add(-30 * 24 * time.Hour)), Valid: true}}
	if t.Kind == rbac.TargetGroup {
		p.GroupID = sql.NullInt64{Int64: t.ID, Valid: true}
	} else {
		p.InstanceID = sql.NullInt64{Int64: t.ID, Valid: true}
	}
	var out []Override
	err := s.Store.WithTx(ctx, func(q *db.Queries) error {
		rows, err := q.ListClientOverridesOnTarget(ctx, p)
		if err != nil {
			return err
		}
		for _, r := range rows {
			o := fromRow(r.ID, r.InstanceID, r.GroupID, r.TargetName, r.Client, r.StartsAt, r.EndsAt, r.Reason, r.Status,
				r.CreatedBy, r.CreatedAt, r.EndedBy, r.EndedAt, r.FinishedAt)
			if err := s.members(ctx, q, &o); err != nil {
				return err
			}
			out = append(out, o)
		}
		return nil
	})
	return out, err
}

// Covering returns the active overrides made through a mirrored group that have a member on this instance, for the
// instance's own list to show read-only.
func (s *Service) Covering(ctx context.Context, instanceID int64) ([]Override, error) {
	var out []Override
	err := s.Store.WithTx(ctx, func(q *db.Queries) error {
		rows, err := q.ListClientOverridesCovering(ctx, instanceID)
		if err != nil {
			return err
		}
		for _, r := range rows {
			o := fromRow(r.ID, r.InstanceID, r.GroupID, r.TargetName, r.Client, r.StartsAt, r.EndsAt, r.Reason, r.Status,
				r.CreatedBy, r.CreatedAt, r.EndedBy, r.EndedAt, r.FinishedAt)
			if err := s.members(ctx, q, &o); err != nil {
				return err
			}
			out = append(out, o)
		}
		return nil
	})
	return out, err
}

// Active returns every active override, for the dashboard and the scheduler.
func (s *Service) Active(ctx context.Context) ([]Override, error) {
	var out []Override
	err := s.Store.WithTx(ctx, func(q *db.Queries) error {
		rows, err := q.ListActiveClientOverrides(ctx)
		if err != nil {
			return err
		}
		for _, r := range rows {
			o := fromRow(r.ID, r.InstanceID, r.GroupID, r.TargetName, r.Client, r.StartsAt, r.EndsAt, r.Reason, r.Status,
				r.CreatedBy, r.CreatedAt, r.EndedBy, r.EndedAt, r.FinishedAt)
			if err := s.members(ctx, q, &o); err != nil {
				return err
			}
			out = append(out, o)
		}
		return nil
	})
	return out, err
}

// NewMember is what a start records for one instance before anything is changed on it.
type NewMember struct {
	InstanceID int64
	Instance   string
	Original   []string
	Override   []string
}

// NewInput is a start, after the groups were read from each member.
type NewInput struct {
	Target   rbac.Target
	Client   string
	StartsAt time.Time
	EndsAt   time.Time
	Reason   string
	By       string
	Members  []NewMember
}

func conflict(client string, overrideID int64, instance string) error {
	return &rbac.Error{Code: rbac.CodeConflict,
		Message: fmt.Sprintf("%s already has a temporary change on %s. Extend it or end it first.", client, instance),
		Details: map[string]any{"override_id": overrideID, "instance": instance}}
}

// Create stores an override and its members, before the Pi-holes are changed, so that an app that stops in between
// still knows what to put back. A client with an active override on any of the members is a 409.
func (s *Service) Create(ctx context.Context, in NewInput) (Override, error) {
	var id int64
	err := s.Store.WithTx(ctx, func(q *db.Queries) error {
		for _, m := range in.Members {
			active, err := q.ListActiveOverrideClientsOnInstance(ctx, m.InstanceID)
			if err != nil {
				return err
			}
			if i := slices.IndexFunc(active, func(a db.ListActiveOverrideClientsOnInstanceRow) bool { return a.Client == in.Client }); i >= 0 {
				return conflict(in.Client, active[i].OverrideID, m.Instance)
			}
		}
		p := db.CreateClientOverrideParams{Client: in.Client, StartsAt: store.Millis(in.StartsAt), EndsAt: store.Millis(in.EndsAt),
			Reason: in.Reason, CreatedBy: in.By, CreatedAt: store.Millis(in.StartsAt)}
		if in.Target.Kind == rbac.TargetGroup {
			p.GroupID = sql.NullInt64{Int64: in.Target.ID, Valid: true}
		} else {
			p.InstanceID = sql.NullInt64{Int64: in.Target.ID, Valid: true}
		}
		var err error
		if id, err = q.CreateClientOverride(ctx, p); err != nil {
			return err
		}
		for _, m := range in.Members {
			orig, _ := json.Marshal(nonNil(m.Original))
			over, _ := json.Marshal(nonNil(m.Override))
			if _, err := q.CreateClientOverrideMember(ctx, db.CreateClientOverrideMemberParams{OverrideID: id,
				InstanceID: m.InstanceID, Client: in.Client, OriginalGroups: string(orig), OverrideGroups: string(over)}); err != nil {
				return err
			}
		}
		return nil
	})
	if store.Constraint(err) == store.Unique {
		// Another start slipped in between the check and the insert.
		return Override{}, conflict(in.Client, 0, "one of its instances")
	}
	if err != nil {
		return Override{}, err
	}
	return s.Get(ctx, id)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// Drop removes the members a start couldn't change, and the override itself when none took the change, and writes
// the start's audit rows, all in one transaction.
func (s *Service) Drop(ctx context.Context, id int64, failed []int64, entries []audit.Entry) (Override, error) {
	bg := context.WithoutCancel(ctx)
	var o Override
	err := s.Store.WithTx(bg, func(q *db.Queries) error {
		for _, inst := range failed {
			if err := q.DeleteOverrideMember(bg, db.DeleteOverrideMemberParams{OverrideID: id, InstanceID: inst}); err != nil {
				return err
			}
		}
		var err error
		if o, err = s.get(bg, q, id); err != nil {
			return err
		}
		if len(o.Members) == 0 {
			if err := q.DeleteClientOverride(bg, id); err != nil {
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
		return Override{}, err
	}
	for _, e := range entries {
		s.Audit.Log(e)
	}
	return o, nil
}

// SetEnd moves an active override's end, later or sooner but in the future and within the maximum measured from its
// start. It changes only the app's database: the revert is the scheduler's.
func (s *Service) SetEnd(ctx context.Context, actor rbac.Actor, id int64, t rbac.Target, newEnd time.Time) (Override, error) {
	now := s.now()
	var o Override
	var e audit.Entry
	err := s.Store.WithTx(ctx, func(q *db.Queries) error {
		var err error
		if o, err = s.get(ctx, q, id); err != nil {
			return err
		}
		if o.Target != t {
			return notFound(id)
		}
		if o.Status != StatusActive || !o.EndsAt.After(now) {
			return &rbac.Error{Code: rbac.CodeConflict, Message: "That temporary change is over, so its end can't be changed. Look at its revert instead.",
				Details: map[string]any{"override_id": id, "status": o.Status}}
		}
		if err := CheckExtend(now, o.StartsAt, newEnd, s.CurrentLimits()); err != nil {
			return err
		}
		newEnd = newEnd.Truncate(time.Millisecond)
		if err := q.SetOverrideEndOnly(ctx, db.SetOverrideEndOnlyParams{EndsAt: store.Millis(newEnd), ID: id}); err != nil {
			return err
		}
		e = audit.Entry{At: now, UserID: actor.UserID, Username: actor.Username, Action: audit.ActionClientTempUpdate,
			Target: o.Target.String(), IP: actor.IP, Detail: map[string]any{"override_id": id, "client": o.Client, "reason": o.Reason,
				"ends_at_before": o.EndsAt.UTC().Format(time.RFC3339), "ends_at_after": newEnd.UTC().Format(time.RFC3339)}}
		_, err = audit.Insert(ctx, q, e)
		o.EndsAt = newEnd
		return err
	})
	if err != nil {
		return Override{}, err
	}
	s.Audit.Log(e)
	return o, nil
}

// BeginEnd marks an override ended now by actor, so its members can be reverted before the answer. It is 409 for an
// override that is over. Members that are already settled are not part of the revert.
func (s *Service) BeginEnd(ctx context.Context, actor rbac.Actor, id int64, t rbac.Target) (Override, error) {
	now := s.now()
	var o Override
	err := s.Store.WithTx(ctx, func(q *db.Queries) error {
		var err error
		if o, err = s.get(ctx, q, id); err != nil {
			return err
		}
		if o.Target != t {
			return notFound(id)
		}
		if o.Status != StatusActive {
			return &rbac.Error{Code: rbac.CodeConflict, Message: "That temporary change is already over.",
				Details: map[string]any{"override_id": id, "status": o.Status}}
		}
		end := now
		if !end.After(o.StartsAt) {
			end = o.StartsAt.Add(time.Millisecond)
		}
		if o.EndsAt.Before(end) {
			end = o.EndsAt // already overdue: it keeps its own end
		}
		if err := q.SetOverrideEnd(ctx, db.SetOverrideEndParams{EndsAt: store.Millis(end),
			EndedBy: sql.NullString{String: actor.Username, Valid: true}, EndedAt: sql.NullInt64{Int64: store.Millis(now), Valid: true}, ID: id}); err != nil {
			return err
		}
		o.EndsAt, o.EndedBy, o.EndedAt = end, actor.Username, now
		return nil
	})
	return o, err
}

// BeginRetry reopens the members of a failed override that were given up on, so the revert can run on them again at
// once. A client that has an active override on an instance since is a 409.
func (s *Service) BeginRetry(ctx context.Context, id int64, t rbac.Target) (Override, error) {
	var o Override
	err := s.Store.WithTx(ctx, func(q *db.Queries) error {
		var err error
		if o, err = s.get(ctx, q, id); err != nil {
			return err
		}
		if o.Target != t {
			return notFound(id)
		}
		if o.Status != StatusFailed || !slices.ContainsFunc(o.Members, func(m Member) bool { return m.Status == RevertGivenUp }) {
			return &rbac.Error{Code: rbac.CodeConflict, Message: "Only a temporary change that failed to revert can be retried.",
				Details: map[string]any{"override_id": id, "status": o.Status}}
		}
		if err := q.ReopenClientOverride(ctx, id); err != nil {
			return err
		}
		for _, m := range o.Members {
			if m.Status == RevertGivenUp {
				if err := q.ReopenOverrideMember(ctx, m.ID); err != nil {
					return err
				}
			}
		}
		return s.members(ctx, q, &o)
	})
	if store.Constraint(err) == store.Unique {
		return Override{}, &rbac.Error{Code: rbac.CodeConflict,
			Message: "That client has a newer temporary change on one of those instances. End it first.",
			Details: map[string]any{"override_id": id}}
	}
	return o, err
}

// UsedBy lists the active overrides that stop an instance or a mirrored group being deleted.
func (s *Service) UsedBy(ctx context.Context, t rbac.Target) ([]UseRef, error) {
	var out []UseRef
	err := s.Store.WithTx(ctx, func(q *db.Queries) error {
		if t.Kind == rbac.TargetGroup {
			rows, err := q.ListActiveOverridesOnGroup(ctx, sql.NullInt64{Int64: t.ID, Valid: true})
			for _, r := range rows {
				out = append(out, UseRef{ID: r.ID, Client: r.Client})
			}
			return err
		}
		rows, err := q.ListActiveOverridesBlockingInstance(ctx, db.ListActiveOverridesBlockingInstanceParams{InstanceID: sql.NullInt64{Int64: t.ID, Valid: true}, InstanceID_2: t.ID})
		for _, r := range rows {
			out = append(out, UseRef{ID: r.ID, Client: r.Client})
		}
		return err
	})
	return out, err
}

// UseRef is an active override named in a refusal to delete what it uses.
type UseRef struct {
	ID     int64
	Client string
}

// ActiveClients returns the clients with an active override on an instance, with the override's ID, for client reset
// to leave alone. An overdue override still counts until it is reverted.
func (s *Service) ActiveClients(ctx context.Context, instanceID int64) (map[string]int64, error) {
	out := map[string]int64{}
	err := s.Store.WithTx(ctx, func(q *db.Queries) error {
		rows, err := q.ListActiveOverrideClientsOnInstance(ctx, instanceID)
		for _, r := range rows {
			out[r.Client] = r.OverrideID
		}
		return err
	})
	return out, err
}
