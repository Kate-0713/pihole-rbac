// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package clientreset

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/instances"
	"github.com/Kate-0713/pihole-rbac/internal/notifications"
	"github.com/Kate-0713/pihole-rbac/internal/notify"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// Trigger says what started a run.
type Trigger string

const (
	TriggerManual   Trigger = "manual"
	TriggerSchedule Trigger = "schedule"
)

// Statuses, of a run and of each instance in it.
const (
	StatusRunning = "running" // a run only
	StatusOK      = "ok"
	StatusPartial = "partial" // some clients reset, some failed
	StatusFailed  = "failed"  // nothing that needed resetting was reset
	StatusSkipped = "skipped" // an instance only: the pool didn't call it (down, or missing its password)
)

// InstanceResult is what a run did on one instance, or, in a preview, what it would do.
type InstanceResult struct {
	InstanceID int64  `json:"instance_id"`
	Instance   string `json:"instance"`
	Primary    bool   `json:"primary,omitempty"`
	Status     string `json:"status"`
	// Code is why the instance couldn't be read or changed at all, when it couldn't.
	Code      string        `json:"code,omitempty"`
	Reset     []Change      `json:"reset"`
	Failed    []Failure     `json:"failed"`
	Unchanged int           `json:"unchanged"`
	Problems  []RuleProblem `json:"problems"`
}

// Summary is a run's summary column: what happened on each instance. Error says why a run that couldn't finish
// didn't.
type Summary struct {
	Rules     int              `json:"rules"`
	Instances []InstanceResult `json:"instances"`
	Error     string           `json:"error,omitempty"`
}

// Run is one run of one target's rules.
type Run struct {
	ID         int64
	StartedAt  time.Time
	FinishedAt time.Time // zero while running
	Trigger    Trigger
	UserID     int64 // 0 for a scheduled run, or once the user is deleted
	Username   string
	Target     string // i-<id> or g-<id>
	TargetName string
	Status     string
	Summary    Summary
}

// Preview is what running a target's rules would do now.
type Preview struct {
	Target     string
	TargetName string
	Rules      int
	Instances  []InstanceResult
}

// RunTimeout bounds a whole run: every instance's reads and writes.
const RunTimeout = 10 * time.Minute

// member is an instance a run acts on.
type member struct {
	id      int64
	name    string
	primary bool
}

// resolved is a target ready to run: its name, its enabled instances (a mirrored group's primary first, then by
// name), and for an instance in a mirrored group, that group's name.
type resolved struct {
	t          rbac.Target
	name       string
	members    []member
	mirroredOf string
}

func notFound(t rbac.Target, format string, args ...any) *rbac.Error {
	return &rbac.Error{Code: rbac.CodeNotFound, Message: fmt.Sprintf(format, args...), Details: map[string]any{"target": t.String()}}
}

// resolve finds a target's enabled instances. A disabled instance, a group that doesn't exist or isn't mirrored, and
// a mirrored group whose primary is disabled are not found.
func (s *Service) resolve(ctx context.Context, t rbac.Target) (resolved, error) {
	pool := s.Instances.Pool
	if t.Kind == rbac.TargetInstance {
		name, ok := pool.Name(t.ID)
		if !ok {
			return resolved{}, notFound(t, "There's no enabled instance with ID %d.", t.ID)
		}
		r := resolved{t: t, name: name, members: []member{{id: t.ID, name: name}}}
		if _, group, ok, err := s.Instances.MirroredGroupOf(ctx, t.ID); err != nil {
			return resolved{}, err
		} else if ok {
			r.mirroredOf = group
		}
		return r, nil
	}
	g, err := s.Instances.GetGroup(ctx, t.ID)
	if rbac.IsCode(err, rbac.CodeNotFound) || (err == nil && g.Mode != rbac.Mirrored) {
		return resolved{}, notFound(t, "There's no mirrored group with ID %d.", t.ID)
	}
	if err != nil {
		return resolved{}, err
	}
	primary, ok := pool.Name(g.Primary)
	if !ok {
		return resolved{}, notFound(t, "%s can't be used: its primary instance is disabled.", g.Name)
	}
	r := resolved{t: t, name: g.Name, members: []member{{id: g.Primary, name: primary, primary: true}}}
	var others []member
	for _, id := range g.Members {
		if name, ok := pool.Name(id); ok && id != g.Primary {
			others = append(others, member{id: id, name: name})
		}
	}
	slices.SortFunc(others, func(a, b member) int { return cmp.Compare(a.name, b.name) })
	r.members = append(r.members, others...)
	return r, nil
}

// rulesFor returns a target's rules, by prefix.
func (s *Service) rulesFor(ctx context.Context, t rbac.Target) ([]Rule, error) {
	p := db.ListClientResetRulesForParams{}
	if t.Kind == rbac.TargetInstance {
		p.InstanceID = sql.NullInt64{Int64: t.ID, Valid: true}
	} else {
		p.GroupID = sql.NullInt64{Int64: t.ID, Valid: true}
	}
	rows, err := s.Store.Read().ListClientResetRulesFor(ctx, p)
	if err != nil {
		return nil, err
	}
	rules := make([]Rule, 0, len(rows))
	for _, r := range rows {
		rule := Rule{Prefix: r.CommentPrefix, Match: Match(r.GroupMatch)}
		if err := json.Unmarshal([]byte(r.TargetGroups), &rule.Groups); err != nil {
			return nil, fmt.Errorf("client reset rule %d: %w", r.ID, err)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// RuleCount returns how many rules a target has.
func (s *Service) RuleCount(ctx context.Context, t rbac.Target) (int, error) {
	rules, err := s.rulesFor(ctx, t)
	return len(rules), err
}

// prepare finds a target's rules and instances. A target without rules is a conflict: there is nothing to run.
func (s *Service) prepare(ctx context.Context, t rbac.Target) ([]Rule, resolved, error) {
	rules, err := s.rulesFor(ctx, t)
	if err != nil {
		return nil, resolved{}, err
	}
	r, err := s.resolve(ctx, t)
	if err != nil {
		return nil, resolved{}, err
	}
	if len(rules) == 0 {
		return nil, resolved{}, &rbac.Error{Code: rbac.CodeConflict,
			Message: fmt.Sprintf("%s has no client reset rules.", r.name), Details: map[string]any{"target": t.String()}}
	}
	return rules, r, nil
}

// Preview reads every instance of a target and says what running its rules would change, without changing anything.
func (s *Service) Preview(ctx context.Context, t rbac.Target) (Preview, error) {
	rules, r, err := s.prepare(ctx, t)
	if err != nil {
		return Preview{}, err
	}
	return Preview{Target: t.String(), TargetName: r.name, Rules: len(rules), Instances: s.each(ctx, r, rules, false)}, nil
}

// each runs, or with apply false plans, the rules on every instance of a target at once.
func (s *Service) each(ctx context.Context, r resolved, rules []Rule, apply bool) []InstanceResult {
	out := make([]InstanceResult, len(r.members))
	var wg sync.WaitGroup
	for i, m := range r.members {
		wg.Go(func() { out[i] = s.on(ctx, m, rules, apply) })
	}
	wg.Wait()
	return out
}

// on runs the rules on one instance. Each client is changed on its own, and one that fails doesn't stop the others;
// but once the instance stops answering, the clients left are failed with its error rather than each waiting out a
// timeout.
func (s *Service) on(ctx context.Context, m member, rules []Rule, apply bool) InstanceResult {
	res := InstanceResult{InstanceID: m.id, Instance: m.name, Primary: m.primary,
		Reset: []Change{}, Failed: []Failure{}, Problems: []RuleProblem{}}
	ran := false
	err := s.Instances.Pool.Do(ctx, m.id, func(ctx context.Context, c *piholeapi.Client) error {
		ran = true
		clients, err := c.ListClients(ctx)
		if err != nil {
			return err
		}
		groups, err := c.ListGroups(ctx)
		if err != nil {
			return err
		}
		p := makePlan(rules, clients, groups)
		res.Unchanged, res.Problems = p.unchanged, append(res.Problems, p.problems...)
		res.Failed = append(res.Failed, p.failures...)
		if !apply {
			res.Reset = append(res.Reset, p.changes...)
			return nil
		}
		for i, ch := range p.changes {
			_, err := c.UpdateClientGroups(ctx, ch.Client, ch.Comment, ch.ids)
			if err == nil {
				res.Reset = append(res.Reset, ch)
				continue
			}
			code := codeOf(err)
			res.Failed = append(res.Failed, Failure{Client: ch.Client, Comment: ch.Comment, Prefix: ch.Prefix, Code: code})
			if piholeapi.Down(err) || ctx.Err() != nil {
				for _, rest := range p.changes[i+1:] {
					res.Failed = append(res.Failed, Failure{Client: rest.Client, Comment: rest.Comment, Prefix: rest.Prefix, Code: code})
				}
				return err // so the pool records the instance as down
			}
			s.log().Info("client reset: a client wasn't changed", "instance", m.name, "client", ch.Client, "code", code, "err", err)
		}
		return nil
	})
	switch {
	case err != nil && len(res.Reset) == 0 && len(res.Failed) == 0:
		// Couldn't read the instance, or the pool didn't call it.
		res.Code = codeOf(err)
		res.Status = StatusFailed
		if !ran {
			res.Status = StatusSkipped
		}
		s.log().Warn("client reset: instance couldn't be used", "instance", m.name, "code", res.Code, "err", err)
	case len(res.Failed) > 0 && len(res.Reset) == 0:
		res.Status = StatusFailed
	case len(res.Failed) > 0:
		res.Status = StatusPartial
	default:
		res.Status = StatusOK
	}
	return res
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

// overall is a run's status from its instances': ok when all are, failed when none reset anything and something
// failed, partial otherwise.
func overall(results []InstanceResult) string {
	ok, reset := true, false
	for _, r := range results {
		if r.Status != StatusOK {
			ok = false
		}
		if len(r.Reset) > 0 {
			reset = true
		}
	}
	switch {
	case ok:
		return StatusOK
	case reset:
		return StatusPartial
	}
	return StatusFailed
}

// Run runs a target's rules now and records the run. a is who asked: a session's user, or SystemActor for a
// scheduled run. Only one run happens at a time, across every target: while another is running, Run is a conflict.
// A run carries on if the request that started it goes away, so it is always recorded.
func (s *Service) Run(ctx context.Context, a rbac.Actor, trigger Trigger, t rbac.Target) (Run, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), RunTimeout)
	defer cancel()
	rules, r, err := s.prepare(ctx, t)
	if err != nil {
		return Run{}, err
	}
	started := s.now()
	run := Run{StartedAt: started, Trigger: trigger, UserID: a.UserID, Username: a.Username, Target: t.String(),
		TargetName: r.name, Status: StatusRunning}
	err = s.Store.WithTx(ctx, func(q *db.Queries) error {
		p := db.StartClientResetRunParams{
			StartedAt: store.Millis(started), Trigger: string(trigger),
			UserID: sql.NullInt64{Int64: a.UserID, Valid: a.UserID != 0}, Username: a.Username,
			Target: run.Target, TargetName: r.name,
		}
		if t.Kind == rbac.TargetInstance {
			p.InstanceID = sql.NullInt64{Int64: t.ID, Valid: true}
		} else {
			p.GroupID = sql.NullInt64{Int64: t.ID, Valid: true}
		}
		run.ID, err = q.StartClientResetRun(ctx, p)
		return err
	})
	if store.Constraint(err) == store.Unique {
		return Run{}, &rbac.Error{Code: rbac.CodeConflict, Message: "A client reset is already running. Try again when it has finished.",
			Details: map[string]any{"target": run.Target}}
	}
	if err != nil {
		return Run{}, err
	}

	results := s.each(ctx, r, rules, true)
	run.Summary = Summary{Rules: len(rules), Instances: results}
	run.Status = overall(results)
	run.FinishedAt = s.now()
	entries := make([]audit.Entry, 0, len(results))
	for _, res := range results {
		if e, ok := s.entryFor(ctx, a, run, r, res); ok {
			entries = append(entries, e)
		}
	}
	summary, err := json.Marshal(run.Summary)
	if err != nil {
		return Run{}, err
	}
	// The row and its audit rows are written together, after the context of the run: a run that took long still
	// finishes its record.
	err = s.Store.WithTx(context.WithoutCancel(ctx), func(q *db.Queries) error {
		if err := q.FinishClientResetRun(ctx, db.FinishClientResetRunParams{
			FinishedAt: sql.NullInt64{Int64: store.Millis(run.FinishedAt), Valid: true},
			Status:     run.Status, Summary: string(summary), ID: run.ID,
		}); err != nil {
			return err
		}
		for _, e := range entries {
			if _, err := audit.Insert(ctx, q, e); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return Run{}, fmt.Errorf("recording client reset run %d: %w", run.ID, err)
	}
	for _, e := range entries {
		s.Audit.Log(e)
	}
	run.StartedAt, run.FinishedAt = store.FromMillis(store.Millis(run.StartedAt)), store.FromMillis(store.Millis(run.FinishedAt))
	return run, nil
}

// SystemActor is who scheduled runs are made by.
var SystemActor = rbac.Actor{Username: audit.SystemUser}

// entryFor is the audit row for one instance of a run, and false when the run found nothing to change there and
// nothing went wrong, which isn't audited.
func (s *Service) entryFor(ctx context.Context, a rbac.Actor, run Run, r resolved, res InstanceResult) (audit.Entry, bool) {
	if len(res.Reset) == 0 && len(res.Failed) == 0 && res.Code == "" {
		return audit.Entry{}, false
	}
	detail := map[string]any{
		"run_id": run.ID, "trigger": string(run.Trigger), "summary": describeResult(res),
		"reset": res.Reset, "failed": res.Failed, "unchanged": res.Unchanged,
	}
	if len(res.Problems) > 0 {
		detail["problems"] = res.Problems
	}
	if r.t.Kind == rbac.TargetGroup {
		detail["via"] = r.t.String()
	}
	if r.mirroredOf != "" {
		// A change to one member of a mirrored group on its own: the group now differs until it is reconciled.
		detail["mirrored_member"] = true
		detail["mirrored_group"] = r.mirroredOf
	}
	if protected := s.protected(ctx, res); len(protected) > 0 {
		detail["protected"] = protected
	}
	e := audit.Entry{
		At: run.FinishedAt, UserID: a.UserID, Username: a.Username, Action: audit.ActionClientReset, Target: run.Target,
		InstanceID: res.InstanceID, InstanceName: res.Instance, Detail: detail, IP: a.IP,
	}
	if res.Status != StatusOK {
		code := res.Code
		if code == "" && len(res.Failed) > 0 {
			code = res.Failed[0].Code
		}
		detail["error_code"] = code
		e.Err = errors.New(describeResult(res))
	}
	return e, true
}

// protected lists the clients a run put in protected Pi-hole groups on an instance, for the protected_group_add
// alert. A failure to read the protected names is logged: the clients have been changed already.
func (s *Service) protected(ctx context.Context, res InstanceResult) []notify.ProtectedClient {
	if s.Protected == nil || len(res.Reset) == 0 {
		return nil
	}
	names, err := s.Protected(ctx, res.InstanceID)
	if err != nil {
		s.log().Error("client reset: reading protected groups", "instance", res.Instance, "err", err)
		return nil
	}
	var out []notify.ProtectedClient
	for _, ch := range res.Reset {
		if added := notifications.ProtectedAdded(ch.Before, ch.After, names); len(added) > 0 {
			out = append(out, notify.ProtectedClient{Client: ch.Client, Groups: added})
		}
	}
	return out
}

// describeResult says in a few words what a run did on an instance, for its audit row and notifications.
func describeResult(res InstanceResult) string {
	if res.Code != "" {
		return "couldn't use the instance (" + res.Code + ")"
	}
	s := plural(len(res.Reset), "client") + " reset"
	if len(res.Failed) > 0 {
		s += ", " + strconv.Itoa(len(res.Failed)) + " failed"
	}
	return s
}

func plural(n int, what string) string {
	if n == 1 {
		return "1 " + what
	}
	return strconv.Itoa(n) + " " + what + "s"
}

// Runs lists runs newest first, for one target ("i-<id>" or "g-<id>") or every one (""), older than beforeID when it
// isn't 0, at most limit.
func (s *Service) Runs(ctx context.Context, target string, beforeID int64, limit int) ([]Run, error) {
	rows, err := s.Store.Read().ListClientResetRuns(ctx, db.ListClientResetRunsParams{
		Target: target, BeforeID: beforeID, RowLimit: int64(limit),
	})
	if err != nil {
		return nil, err
	}
	out := make([]Run, 0, len(rows))
	for _, row := range rows {
		r, err := runOf(row)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// GetRun returns one run, and a not-found error if there is none.
func (s *Service) GetRun(ctx context.Context, id int64) (Run, error) {
	row, err := s.Store.Read().GetClientResetRun(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return Run{}, &rbac.Error{Code: rbac.CodeNotFound, Message: fmt.Sprintf("There's no client reset run %d.", id)}
	}
	if err != nil {
		return Run{}, err
	}
	return runOf(row)
}

func runOf(row db.ClientResetRun) (Run, error) {
	r := Run{
		ID: row.ID, StartedAt: store.FromMillis(row.StartedAt), Trigger: Trigger(row.Trigger),
		UserID: row.UserID.Int64, Username: row.Username, Target: row.Target, TargetName: row.TargetName, Status: row.Status,
	}
	if row.FinishedAt.Valid {
		r.FinishedAt = store.FromMillis(row.FinishedAt.Int64)
	}
	if err := json.Unmarshal([]byte(row.Summary), &r.Summary); err != nil {
		return Run{}, fmt.Errorf("client reset run %d: %w", row.ID, err)
	}
	if r.Summary.Instances == nil {
		r.Summary.Instances = []InstanceResult{}
	}
	return r, nil
}

// FailInterrupted marks runs left running by a process that stopped as failed, so the one-run-at-a-time rule doesn't
// block every later run. It is called at startup, before anything can start a run, and returns how many it marked.
func (s *Service) FailInterrupted(ctx context.Context) (int64, error) {
	summary, err := json.Marshal(Summary{Instances: []InstanceResult{}, Error: "interrupted: the app stopped during the run"})
	if err != nil {
		return 0, err
	}
	var n int64
	err = s.Store.WithTx(ctx, func(q *db.Queries) error {
		n, err = q.FailInterruptedClientResetRuns(ctx, db.FailInterruptedClientResetRunsParams{
			FinishedAt: sql.NullInt64{Int64: store.Millis(s.now()), Valid: true}, Summary: string(summary),
		})
		return err
	})
	if n > 0 {
		s.log().Warn("client reset runs were interrupted by a stop, and are marked failed", "runs", n)
	}
	return n, err
}
