// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package schedules

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/instances"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// Service keeps schedules and runs them. Permission checks are the API's: a save needs schedules.manage and the
// underlying permission on the target, and the Pi-hole group must exist there and not be Default, which needs a
// Pi-hole read the API already has the means for.
type Service struct {
	Store     *store.Store
	Audit     *audit.Logger
	Instances *instances.Service
	// Limits returns the limits a save is checked against; nil means the defaults.
	Limits func() Limits
	Logger *slog.Logger
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

func (s *Service) limits() Limits {
	if s.Limits == nil {
		return Limits{}
	}
	return s.Limits()
}

// SystemActor is who runs schedules.
var SystemActor = rbac.Actor{Username: audit.SystemUser}

// Result statuses, per instance, of the latest edge.
const (
	StatusOK      = "ok"
	StatusFailed  = "failed"
	StatusSkipped = "skipped"  // the pool didn't call the instance (down, or missing its password)
	StatusGivenUp = "given_up" // a one-off's end edge that kept failing for a week
)

// Result is what the latest edge, or its last retry, did on one instance.
type Result struct {
	Instance string    `json:"instance"`
	Status   string    `json:"status"`
	Code     string    `json:"code,omitempty"`  // why it failed or was skipped
	Skip     string    `json:"skip,omitempty"`  // why nothing was sent, when it was ok without sending
	Other    string    `json:"other,omitempty"` // the schedule still open, or in conflict
	At       time.Time `json:"at"`
	Attempts int       `json:"attempts"`
	// Owned is set when a blocking window turned blocking off there at its start, and carried to its end's result:
	// only then does the end check that Pi-hole still has the timer, which an FTL restart loses.
	Owned bool `json:"owned,omitempty"`
}

// pending reports whether the edge still has to be applied there: it failed or was skipped.
func (r Result) pending() bool { return r.Status == StatusFailed || r.Status == StatusSkipped }

// Schedule is a saved schedule.
type Schedule struct {
	ID         int64
	Name       string
	Target     rbac.Target
	TargetName string
	Kind       Kind
	Group      string // the Pi-hole group, for the group kinds
	Window     Window
	TimeZone   string // a weekly schedule's zone, as saved
	Enabled    bool

	ActiveFrom time.Time
	LastEdgeAt time.Time // zero before the first edge
	LastEdge   string    // "start" or "end"
	Results    map[int64]Result
	FinishedAt time.Time // a one-off schedule, once done

	CreatedAt, UpdatedAt time.Time
	CreatedBy, UpdatedBy string
}

// Spec returns what was saved, for checking it again.
func (sc Schedule) Spec() Spec {
	return Spec{Name: sc.Name, Kind: sc.Kind, PiholeGroup: sc.Group, Window: sc.Window}
}

// Finished reports whether a one-off schedule is done.
func (sc Schedule) Finished() bool { return !sc.FinishedAt.IsZero() }

// reach is the schedule as seen from an instance it reaches.
func (sc Schedule) reach() Reach {
	return Reach{ID: sc.ID, Name: sc.Name, Kind: sc.Kind, Group: sc.Group, Window: sc.Window}
}

// NextEdge returns the schedule's next edge after t that it will act on: none when it is off or finished, and none
// at or before ActiveFrom.
func (sc Schedule) NextEdge(t time.Time) (Edge, bool) {
	if !sc.Enabled || sc.Finished() {
		return Edge{}, false
	}
	return sc.Window.NextEdge(latestOf(t, sc.ActiveFrom))
}

func nullInt(v int64, ok bool) sql.NullInt64 { return sql.NullInt64{Int64: v, Valid: ok} }

func fromRow(r db.Schedule, instanceName, groupName string) (Schedule, error) {
	sc := Schedule{
		ID: r.ID, Name: r.Name, Kind: Kind(r.Kind), Group: r.PiholeGroup.String, Enabled: r.Enabled != 0,
		ActiveFrom: store.FromMillis(r.ActiveFrom), LastEdge: r.LastEdge.String,
		CreatedAt: store.FromMillis(r.CreatedAt), CreatedBy: r.CreatedBy,
		UpdatedAt: store.FromMillis(r.UpdatedAt), UpdatedBy: r.UpdatedBy,
		Results: map[int64]Result{},
	}
	if r.GroupID.Valid {
		sc.Target, sc.TargetName = rbac.GroupTarget(r.GroupID.Int64), groupName
	} else {
		sc.Target, sc.TargetName = rbac.InstanceTarget(r.InstanceID.Int64), instanceName
	}
	if r.LastEdgeAt.Valid {
		sc.LastEdgeAt = store.FromMillis(r.LastEdgeAt.Int64)
	}
	if r.FinishedAt.Valid {
		sc.FinishedAt = store.FromMillis(r.FinishedAt.Int64)
	}
	sc.Window.Repeat = Repeat(r.Repeat)
	if sc.Window.Repeat == RepeatWeekly {
		loc, err := LoadZone(r.TimeZone.String)
		if err != nil {
			return Schedule{}, fmt.Errorf("schedule %d: %w", r.ID, err)
		}
		sc.TimeZone = r.TimeZone.String
		sc.Window.Days, sc.Window.Start, sc.Window.End = int(r.Days.Int64), int(r.StartMin.Int64), int(r.EndMin.Int64)
		sc.Window.EndDays, sc.Window.Location = int(r.EndDays.Int64), loc
	} else {
		sc.Window.StartsAt, sc.Window.EndsAt = store.FromMillis(r.StartsAt.Int64), store.FromMillis(r.EndsAt.Int64)
	}
	var raw map[string]Result
	if err := json.Unmarshal([]byte(r.LastResults), &raw); err != nil {
		return Schedule{}, fmt.Errorf("schedule %d results: %w", r.ID, err)
	}
	for k, v := range raw {
		id, err := strconv.ParseInt(k, 10, 64)
		if err != nil {
			return Schedule{}, fmt.Errorf("schedule %d results: instance %q", r.ID, k)
		}
		sc.Results[id] = v
	}
	return sc, nil
}

func resultsJSON(rs map[int64]Result) (string, error) {
	out := make(map[string]Result, len(rs))
	for id, r := range rs {
		out[strconv.FormatInt(id, 10)] = r
	}
	b, err := json.Marshal(out)
	return string(b), err
}

// All returns every schedule, instances' first, then by target and name.
func (s *Service) All(ctx context.Context) ([]Schedule, error) {
	rows, err := s.Store.Read().ListSchedules(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Schedule, 0, len(rows))
	for _, r := range rows {
		sc, err := fromRow(db.Schedule{
			ID: r.ID, Name: r.Name, InstanceID: r.InstanceID, GroupID: r.GroupID, Kind: r.Kind, PiholeGroup: r.PiholeGroup,
			Repeat: r.Repeat, Days: r.Days, StartMin: r.StartMin, EndMin: r.EndMin, EndDays: r.EndDays, TimeZone: r.TimeZone,
			StartsAt: r.StartsAt, EndsAt: r.EndsAt, ActiveFrom: r.ActiveFrom, LastEdgeAt: r.LastEdgeAt, LastEdge: r.LastEdge,
			LastResults: r.LastResults, FinishedAt: r.FinishedAt, Enabled: r.Enabled, CreatedAt: r.CreatedAt,
			CreatedBy: r.CreatedBy, UpdatedAt: r.UpdatedAt, UpdatedBy: r.UpdatedBy,
		}, r.InstanceName, r.GroupName)
		if err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, nil
}

// For returns the schedules set on t.
func (s *Service) For(ctx context.Context, t rbac.Target) ([]Schedule, error) {
	all, err := s.All(ctx)
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(all, func(sc Schedule) bool { return sc.Target != t }), nil
}

// Get returns one schedule, or a 404.
func (s *Service) Get(ctx context.Context, id int64) (Schedule, error) {
	r, err := s.Store.Read().GetSchedule(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return Schedule{}, &rbac.Error{Code: rbac.CodeNotFound, Message: fmt.Sprintf("There's no schedule with ID %d.", id)}
	}
	if err != nil {
		return Schedule{}, err
	}
	return fromRow(db.Schedule{
		ID: r.ID, Name: r.Name, InstanceID: r.InstanceID, GroupID: r.GroupID, Kind: r.Kind, PiholeGroup: r.PiholeGroup,
		Repeat: r.Repeat, Days: r.Days, StartMin: r.StartMin, EndMin: r.EndMin, EndDays: r.EndDays, TimeZone: r.TimeZone,
		StartsAt: r.StartsAt, EndsAt: r.EndsAt, ActiveFrom: r.ActiveFrom, LastEdgeAt: r.LastEdgeAt, LastEdge: r.LastEdge,
		LastResults: r.LastResults, FinishedAt: r.FinishedAt, Enabled: r.Enabled, CreatedAt: r.CreatedAt,
		CreatedBy: r.CreatedBy, UpdatedAt: r.UpdatedAt, UpdatedBy: r.UpdatedBy,
	}, r.InstanceName, r.GroupName)
}

// member is an instance a schedule reaches.
type member struct {
	id   int64
	name string
}

// reaches returns the enabled instances a target reaches: an instance itself, or a mirrored group's enabled members
// (the primary first, then by name). A target that can't be used (a disabled instance, a group that isn't mirrored
// any more, or whose primary is disabled) reaches nothing.
func (s *Service) reaches(ctx context.Context, t rbac.Target) ([]member, error) {
	pool := s.Instances.Pool
	if t.Kind == rbac.TargetInstance {
		if name, ok := pool.Name(t.ID); ok {
			return []member{{t.ID, name}}, nil
		}
		return nil, nil
	}
	g, err := s.Instances.GetGroup(ctx, t.ID)
	if rbac.IsCode(err, rbac.CodeNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	primary, ok := pool.Name(g.Primary)
	if g.Mode != rbac.Mirrored || !ok {
		return nil, nil
	}
	out := []member{{g.Primary, primary}}
	var others []member
	for _, id := range g.Members {
		if name, ok := pool.Name(id); ok && id != g.Primary {
			others = append(others, member{id, name})
		}
	}
	slices.SortFunc(others, func(a, b member) int { return cmp.Compare(a.name, b.name) })
	return append(out, others...), nil
}

// Input is a save: a spec, and whether the schedule is on.
type Input struct {
	Spec
	Enabled bool
}

func params(in Input) (days, start, end, endDays sql.NullInt64, zone sql.NullString, startsAt, endsAt sql.NullInt64) {
	w := in.Window
	if w.Repeat == RepeatWeekly {
		return nullInt(int64(w.Days), true), nullInt(int64(w.Start), true), nullInt(int64(w.End), true),
			nullInt(int64(w.EndDays), true), sql.NullString{String: w.Location.String(), Valid: true}, sql.NullInt64{}, sql.NullInt64{}
	}
	return sql.NullInt64{}, sql.NullInt64{}, sql.NullInt64{}, sql.NullInt64{}, sql.NullString{},
		nullInt(store.Millis(w.StartsAt), true), nullInt(store.Millis(w.EndsAt), true)
}

// detail describes a schedule for its audit rows.
func detail(name string, in Input, t rbac.Target) map[string]any {
	d := map[string]any{"name": name, "kind": string(in.Kind), "repeat": string(in.Window.Repeat), "enabled": in.Enabled}
	if in.Kind.Group() {
		d["pihole_group"] = in.PiholeGroup
	}
	w := in.Window
	if w.Repeat == RepeatWeekly {
		d["days"], d["start"], d["end"], d["end_days"], d["time_zone"] = w.Days, FormatClock(w.Start), FormatClock(w.End), w.EndDays, w.Location.String()
	} else {
		d["starts_at"], d["ends_at"] = w.StartsAt.UTC().Format(time.RFC3339), w.EndsAt.UTC().Format(time.RFC3339)
	}
	if t.Kind == rbac.TargetGroup {
		d["via"] = t.String()
	}
	return d
}

// conflicts refuses a group window whose windows would overlap one of the opposite kind for the same Pi-hole group
// on an instance both reach. exclude is the schedule being changed.
func (s *Service) conflicts(ctx context.Context, t rbac.Target, in Input, exclude int64, now time.Time) error {
	if !in.Kind.Group() || !in.Enabled {
		return nil
	}
	mine, err := s.reaches(ctx, t)
	if err != nil {
		return err
	}
	all, err := s.All(ctx)
	if err != nil {
		return err
	}
	for _, o := range all {
		if o.ID == exclude || !o.Enabled || o.Finished() || !o.Kind.Group() || o.Kind == in.Kind || o.Group != in.PiholeGroup {
			continue
		}
		theirs, err := s.reaches(ctx, o.Target)
		if err != nil {
			return err
		}
		shared := slices.ContainsFunc(mine, func(m member) bool {
			return slices.ContainsFunc(theirs, func(x member) bool { return x.id == m.id })
		})
		if !shared && o.Target != t {
			continue
		}
		if at, ok := Overlap(in.Window, o.Window, now); ok {
			return &rbac.Error{Code: rbac.CodeConflict,
				Message: fmt.Sprintf("This would overlap the schedule %q on %s, which turns %s the other way, from %s.",
					o.Name, o.TargetName, in.PiholeGroup, at.UTC().Format(time.RFC3339)),
				Details: map[string]any{"schedule_id": o.ID, "schedule": o.Name, "at": at.UTC().Format(time.RFC3339)}}
		}
	}
	return nil
}

func nameTaken(err error, name string) error {
	if store.Constraint(err) == store.Unique {
		e := &rbac.Error{Code: rbac.CodeConflict, Message: fmt.Sprintf("There's already a schedule called %q here.", name),
			Details: map[string]any{"field": "name"}}
		return e
	}
	return err
}

// Create saves a new schedule on t, as a. The schedule acts from its next edge.
func (s *Service) Create(ctx context.Context, a rbac.Actor, t rbac.Target, in Input) (Schedule, error) {
	now := s.now()
	if err := in.Check(now, s.limits()); err != nil {
		return Schedule{}, err
	}
	if err := s.conflicts(ctx, t, in, 0, now); err != nil {
		return Schedule{}, err
	}
	days, start, end, endDays, zone, startsAt, endsAt := params(in)
	var id int64
	err := s.write(ctx, func(q *db.Queries) (audit.Entry, error) {
		p := db.CreateScheduleParams{
			Name: in.Name, Kind: string(in.Kind), PiholeGroup: sql.NullString{String: in.PiholeGroup, Valid: in.Kind.Group()},
			Repeat: string(in.Window.Repeat), Days: days, StartMin: start, EndMin: end, EndDays: endDays, TimeZone: zone,
			StartsAt: startsAt, EndsAt: endsAt, ActiveFrom: store.Millis(now), Enabled: boolInt(in.Enabled),
			CreatedAt: store.Millis(now), CreatedBy: a.Username, UpdatedAt: store.Millis(now), UpdatedBy: a.Username,
		}
		if t.Kind == rbac.TargetGroup {
			p.GroupID = nullInt(t.ID, true)
		} else {
			p.InstanceID = nullInt(t.ID, true)
		}
		var err error
		if id, err = q.CreateSchedule(ctx, p); err != nil {
			return audit.Entry{}, err
		}
		d := detail(in.Name, in, t)
		d["schedule_id"] = id
		return audit.Entry{At: now, UserID: a.UserID, Username: a.Username, Action: audit.ActionScheduleCreate,
			Target: t.String(), Detail: d, IP: a.IP}, nil
	})
	if err != nil {
		return Schedule{}, nameTaken(err, in.Name)
	}
	return s.Get(ctx, id)
}

// Update saves a change to a schedule. A finished one-off schedule can't be changed, only deleted. The schedule acts
// from its next edge after the save, with no results until then.
func (s *Service) Update(ctx context.Context, a rbac.Actor, before Schedule, in Input) (Schedule, error) {
	if before.Finished() {
		return Schedule{}, &rbac.Error{Code: rbac.CodeConflict, Message: "A finished one-off schedule can't be changed, only deleted."}
	}
	now := s.now()
	if err := in.Check(now, s.limits()); err != nil {
		return Schedule{}, err
	}
	if err := s.conflicts(ctx, before.Target, in, before.ID, now); err != nil {
		return Schedule{}, err
	}
	days, start, end, endDays, zone, startsAt, endsAt := params(in)
	err := s.write(ctx, func(q *db.Queries) (audit.Entry, error) {
		if err := q.UpdateSchedule(ctx, db.UpdateScheduleParams{
			Name: in.Name, PiholeGroup: sql.NullString{String: in.PiholeGroup, Valid: in.Kind.Group()},
			Repeat: string(in.Window.Repeat), Days: days, StartMin: start, EndMin: end, EndDays: endDays, TimeZone: zone,
			StartsAt: startsAt, EndsAt: endsAt, ActiveFrom: store.Millis(now), Enabled: boolInt(in.Enabled),
			UpdatedAt: store.Millis(now), UpdatedBy: a.Username, ID: before.ID,
		}); err != nil {
			return audit.Entry{}, err
		}
		d := detail(in.Name, in, before.Target)
		d["schedule_id"] = before.ID
		d["before"] = detail(before.Name, Input{before.Spec(), before.Enabled}, before.Target)
		return audit.Entry{At: now, UserID: a.UserID, Username: a.Username, Action: audit.ActionScheduleUpdate,
			Target: before.Target.String(), Detail: d, IP: a.IP}, nil
	})
	if err != nil {
		return Schedule{}, nameTaken(err, in.Name)
	}
	return s.Get(ctx, before.ID)
}

// Delete deletes a schedule. Nothing is sent to Pi-hole: a blocking window's timer runs on, and a group stays as it
// is.
func (s *Service) Delete(ctx context.Context, a rbac.Actor, sc Schedule) error {
	now := s.now()
	return s.write(ctx, func(q *db.Queries) (audit.Entry, error) {
		if err := q.DeleteSchedule(ctx, sc.ID); err != nil {
			return audit.Entry{}, err
		}
		d := detail(sc.Name, Input{sc.Spec(), sc.Enabled}, sc.Target)
		d["schedule_id"] = sc.ID
		return audit.Entry{At: now, UserID: a.UserID, Username: a.Username, Action: audit.ActionScheduleDelete,
			Target: sc.Target.String(), Detail: d, IP: a.IP}, nil
	})
}

// write makes a change and its audit row in one transaction, and logs the row once it has committed.
func (s *Service) write(ctx context.Context, fn func(q *db.Queries) (audit.Entry, error)) error {
	var e audit.Entry
	if err := s.Store.WithTx(ctx, func(q *db.Queries) error {
		var err error
		if e, err = fn(q); err != nil {
			return err
		}
		_, err = audit.Insert(ctx, q, e)
		return err
	}); err != nil {
		return err
	}
	s.Audit.Log(e)
	return nil
}

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
