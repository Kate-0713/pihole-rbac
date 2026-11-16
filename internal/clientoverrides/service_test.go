// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package clientoverrides

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/instances"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi/piholetest"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

const password = "app-password"
const tablet = "10.0.0.5"

type passwords struct{}

func (passwords) InstancePassword(string) (secrets.Value, bool) {
	return secrets.NewValue([]byte(password)), true
}
func (passwords) Cipher() *secrets.Cipher { return nil }

type sink struct {
	mu      sync.Mutex
	entries []audit.Entry
}

func (s *sink) add(e audit.Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, e)
}

func (s *sink) take() []audit.Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.entries
	s.entries = nil
	return out
}

// env is three instances on fake Pi-holes: alpha and beta in the mirrored group "site" (alpha the primary), and
// gamma on its own. Each has the Pi-hole groups Default, kids, open and guests, and the client tablet in Default and
// kids. The clock is the test's.
type env struct {
	t     *testing.T
	ctx   context.Context
	st    *store.Store
	inst  *instances.Service
	svc   *Service
	ph    map[string]*piholetest.Server
	ids   map[string]int64
	site  rbac.Target
	admin rbac.Actor
	sunk  *sink
	now   time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(ctx, store.Options{DataDir: t.TempDir(), Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	pool := instances.New(instances.Options{Passwords: passwords{}, Timeout: 2 * time.Second, Logger: logger})
	t.Cleanup(func() { pool.Close(context.Background()) })
	auditLog := audit.NewLogger(io.Discard)
	e := &env{t: t, ctx: ctx, st: st, ph: map[string]*piholetest.Server{}, ids: map[string]int64{}, sunk: &sink{},
		now: time.Date(2027, 3, 1, 12, 0, 0, 0, time.UTC)}
	auditLog.SetSink(e.sunk.add)
	e.inst = &instances.Service{Store: st, Audit: auditLog, Pool: pool}
	e.svc = &Service{Store: st, Audit: auditLog, Instances: e.inst, Logger: logger, Now: func() time.Time { return e.now }}
	if err := st.WithTx(ctx, func(q *db.Queries) error {
		role, err := q.GetBuiltinRole(ctx)
		if err != nil {
			return err
		}
		u, err := q.CreateLocalUser(ctx, db.CreateLocalUserParams{Username: "alice", PasswordHash: sql.NullString{String: "x", Valid: true}, CreatedAt: 1})
		e.admin = rbac.Actor{UserID: u.ID, Username: "alice", RoleIDs: []int64{role.ID}, IP: "192.0.2.1"}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"alpha", "beta", "gamma"} {
		ph := piholetest.New(t, password)
		kids := ph.AddGroup("kids")
		ph.AddGroup("open")
		ph.AddGroup("guests")
		ph.AddClient(piholetest.Client{Client: tablet, Comment: "tablet", Groups: []int{0, kids}})
		pw := secrets.NewValue([]byte(password))
		in, err := e.inst.Create(ctx, e.admin, instances.Input{Name: n, BaseURL: ph.URL, EnvName: strings.ToUpper(n), Password: &pw})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.inst.SetEnabled(ctx, e.admin, in.ID, true); err != nil {
			t.Fatal(err)
		}
		e.ph[n], e.ids[n] = ph, in.ID
	}
	g, err := e.inst.CreateGroup(ctx, e.admin, instances.GroupInput{Name: "site", Mode: rbac.Mirrored, Primary: e.ids["alpha"],
		Members: []int64{e.ids["alpha"], e.ids["beta"]}})
	if err != nil {
		t.Fatal(err)
	}
	e.site = rbac.GroupTarget(g.ID)
	e.sunk.take()
	return e
}

func (e *env) target(name string) rbac.Target { return rbac.InstanceTarget(e.ids[name]) }

// groups is the client's Pi-hole groups on an instance, by name, sorted.
func (e *env) groups(instance string) []string {
	e.t.Helper()
	for _, c := range e.ph[instance].Clients() {
		if c.Client == tablet {
			var names []string
			for _, id := range c.Groups {
				for _, g := range e.ph[instance].Groups() {
					if g.ID == id {
						names = append(names, g.Name)
					}
				}
			}
			slices.Sort(names)
			return names
		}
	}
	e.t.Fatalf("%s has no %s", instance, tablet)
	return nil
}

// setGroups changes the client's groups on an instance, as someone outside the app would.
func (e *env) setGroups(instance string, names ...string) {
	e.t.Helper()
	if err := e.inst.Pool.Do(e.ctx, e.ids[instance], func(ctx context.Context, c *piholeapi.Client) error {
		gs, err := c.ListGroups(ctx)
		if err != nil {
			return err
		}
		ids, _ := Resolve(names, gs)
		_, err = c.UpdateClientGroups(ctx, tablet, "tablet", ids)
		return err
	}); err != nil {
		e.t.Fatal(err)
	}
}

// start does what a start does: store the override, change the members, and drop the ones that failed.
func (e *env) start(t rbac.Target, minutes int, groups ...string) Override {
	e.t.Helper()
	var members []NewMember
	for _, name := range e.reach(t) {
		members = append(members, NewMember{InstanceID: e.ids[name], Instance: name, Original: e.groups(name), Override: groups})
	}
	o, err := e.svc.Create(e.ctx, NewInput{Target: t, Client: tablet, StartsAt: e.now, EndsAt: e.now.Add(time.Duration(minutes) * time.Minute),
		By: "alice", Members: members})
	if err != nil {
		e.t.Fatal(err)
	}
	for _, name := range e.reach(t) {
		e.setGroups(name, groups...)
	}
	if _, err := e.svc.Drop(e.ctx, o.ID, nil, nil); err != nil {
		e.t.Fatal(err)
	}
	return o
}

func (e *env) reach(t rbac.Target) []string {
	switch {
	case t == e.site:
		return []string{"alpha", "beta"}
	case t == e.target("alpha"):
		return []string{"alpha"}
	case t == e.target("beta"):
		return []string{"beta"}
	}
	return []string{"gamma"}
}

func (e *env) advance(d time.Duration) { e.now = e.now.Add(d) }

func (e *env) get(id int64) Override {
	e.t.Helper()
	o, err := e.svc.Get(e.ctx, id)
	if err != nil {
		e.t.Fatal(err)
	}
	return o
}

func rows(es []audit.Entry, action string) []audit.Entry {
	return slices.DeleteFunc(slices.Clone(es), func(en audit.Entry) bool { return en.Action != action })
}

func eq(t *testing.T, what string, got []string, want ...string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("%s = %v, want %v", what, got, want)
	}
}

func TestRevertAtTheEnd(t *testing.T) {
	e := newEnv(t)
	o := e.start(e.site, 60, "Default", "open")
	eq(t, "alpha during", e.groups("alpha"), "Default", "open")
	eq(t, "beta during", e.groups("beta"), "Default", "open")
	eq(t, "gamma is untouched", e.groups("gamma"), "Default", "kids")

	e.advance(59 * time.Minute)
	e.svc.Check(e.ctx)
	eq(t, "alpha before the end", e.groups("alpha"), "Default", "open")
	if got := e.get(o.ID); got.Status != StatusActive {
		t.Errorf("status before the end = %s", got.Status)
	}

	e.advance(2 * time.Minute)
	e.svc.Check(e.ctx)
	eq(t, "alpha after", e.groups("alpha"), "Default", "kids")
	eq(t, "beta after", e.groups("beta"), "Default", "kids")
	got := e.get(o.ID)
	if got.Status != StatusReverted || got.FinishedAt.IsZero() || len(got.Pending()) != 0 {
		t.Errorf("after the end: %+v", got)
	}
	revs := rows(e.sunk.take(), audit.ActionClientTempRevert)
	if len(revs) != 2 || revs[0].Username != audit.SystemUser || revs[0].Err != nil {
		t.Fatalf("revert rows = %+v", revs)
	}
	if revs[0].Detail["via"] != e.site.String() || revs[0].Detail["override_id"] != o.ID {
		t.Errorf("revert detail = %v", revs[0].Detail)
	}

	// Nothing left to do: a later pass sends nothing and writes nothing.
	e.svc.Check(e.ctx)
	if n := len(e.sunk.take()); n != 0 {
		t.Errorf("a pass with nothing to do wrote %d rows", n)
	}
}

// The revert undoes only the override's own change: groups someone else added since are kept, and a client never
// changed on a member (it failed at the start) comes out unchanged without sending anything.
func TestRevertKeepsOtherChanges(t *testing.T) {
	e := newEnv(t)
	e.start(e.target("gamma"), 30, "Default")
	e.setGroups("gamma", "Default", "guests")
	e.advance(31 * time.Minute)
	e.svc.Check(e.ctx)
	eq(t, "gamma", e.groups("gamma"), "Default", "guests", "kids")
}

func TestRevertRetriedUntilItWorks(t *testing.T) {
	e := newEnv(t)
	o := e.start(e.site, 10, "Default", "open")
	var refuse atomic.Bool
	refuse.Store(true)
	e.ph["beta"].Handle(func(w http.ResponseWriter, r *http.Request) bool {
		if refuse.Load() && r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/api/clients/") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":{"key":"database_error","message":"locked"}}`))
			return true
		}
		return false
	})
	e.advance(11 * time.Minute)
	e.svc.Check(e.ctx)
	eq(t, "alpha went back", e.groups("alpha"), "Default", "kids")
	eq(t, "beta is still changed", e.groups("beta"), "Default", "open")
	got := e.get(o.ID)
	if got.Status != StatusActive || !got.Overdue(e.now) || len(got.Pending()) != 1 || got.Pending()[0].Instance != "beta" {
		t.Fatalf("one member should be pending: %+v", got)
	}
	revs := rows(e.sunk.take(), audit.ActionClientTempRevert)
	if len(revs) != 2 || revs[0].Err != nil && revs[1].Err != nil {
		t.Fatalf("first pass rows = %+v", revs)
	}

	// The same failure again is not audited again.
	e.advance(time.Minute)
	e.svc.Check(e.ctx)
	if n := len(e.sunk.take()); n != 0 {
		t.Errorf("a retry that failed the same way wrote %d rows", n)
	}
	if m := e.get(o.ID).Members; m[1].Attempts != 2 {
		t.Errorf("attempts = %d, want 2", m[1].Attempts)
	}

	refuse.Store(false)
	e.advance(time.Minute)
	e.svc.Check(e.ctx)
	eq(t, "beta went back", e.groups("beta"), "Default", "kids")
	if got := e.get(o.ID); got.Status != StatusReverted {
		t.Errorf("status = %s, want reverted", got.Status)
	}
	if revs := rows(e.sunk.take(), audit.ActionClientTempRevert); len(revs) != 1 || revs[0].Err != nil {
		t.Errorf("the success wasn't audited once: %+v", revs)
	}
}

func TestGiveUpThenRetry(t *testing.T) {
	e := newEnv(t)
	o := e.start(e.target("gamma"), 10, "Default", "open")
	var refuse atomic.Bool
	refuse.Store(true)
	e.ph["gamma"].Handle(func(w http.ResponseWriter, r *http.Request) bool {
		if refuse.Load() && r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/api/clients/") {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":{"key":"x","message":"busy"}}`))
			return true
		}
		return false
	})
	e.advance(11 * time.Minute)
	e.svc.Check(e.ctx)
	e.sunk.take()
	e.advance(GiveUpAfter)
	e.svc.Check(e.ctx)
	got := e.get(o.ID)
	if got.Status != StatusFailed || got.Members[0].Status != RevertGivenUp || got.Members[0].Active {
		t.Fatalf("after a week: %+v", got)
	}
	if revs := rows(e.sunk.take(), audit.ActionClientTempRevert); len(revs) != 1 || revs[0].Err == nil {
		t.Errorf("the give-up wasn't audited: %+v", revs)
	}
	// Nothing retries it by itself.
	e.svc.Check(e.ctx)
	if n := len(e.sunk.take()); n != 0 {
		t.Errorf("a failed override was tried again: %d rows", n)
	}

	// A retry that fails again goes straight back to given up, without waiting another week.
	re, err := e.svc.BeginRetry(e.ctx, o.ID, e.target("gamma"))
	if err != nil {
		t.Fatal(err)
	}
	m := re.Pending()[0]
	if _, err := e.svc.Settle(e.ctx, re, []Attempt{{Member: m, Called: true, Err: &piholeapi.RejectedError{Message: "busy"}}},
		SettleOptions{Actor: &e.admin, Retry: true}); err != nil {
		t.Fatal(err)
	}
	if got := e.get(o.ID); got.Status != StatusFailed || got.Members[0].Status != RevertGivenUp {
		t.Fatalf("a failed retry: %+v", got)
	}

	refuse.Store(false)
	re, err = e.svc.BeginRetry(e.ctx, o.ID, e.target("gamma"))
	if err != nil {
		t.Fatal(err)
	}
	m = re.Pending()[0]
	ch, err := e.revertNow(m)
	if _, serr := e.svc.Settle(e.ctx, re, []Attempt{{Member: m, Called: true, Change: ch, Err: err}}, SettleOptions{Actor: &e.admin, Retry: true}); serr != nil {
		t.Fatal(serr)
	}
	eq(t, "gamma", e.groups("gamma"), "Default", "kids")
	if got := e.get(o.ID); got.Status != StatusReverted {
		t.Errorf("status after a good retry = %s", got.Status)
	}
	ends := rows(e.sunk.take(), audit.ActionClientTempEnd)
	if len(ends) != 2 || ends[0].Username != "alice" || ends[1].Err != nil {
		t.Errorf("retry rows = %+v", ends)
	}
	// Only a failed override can be retried.
	if _, err := e.svc.BeginRetry(e.ctx, o.ID, e.target("gamma")); !rbac.IsCode(err, rbac.CodeConflict) {
		t.Errorf("retrying a finished override: %v", err)
	}
}

func (e *env) revertNow(m Member) (Change, error) {
	var ch Change
	err := e.inst.Pool.Do(e.ctx, m.InstanceID, func(ctx context.Context, c *piholeapi.Client) error {
		var err error
		ch, err = RevertMember(ctx, c, m.Client, m.Original, m.Override)
		return err
	})
	return ch, err
}

func TestClientDeletedDuringOverride(t *testing.T) {
	e := newEnv(t)
	o := e.start(e.target("gamma"), 10, "Default", "open")
	if err := e.inst.Pool.Do(e.ctx, e.ids["gamma"], func(ctx context.Context, c *piholeapi.Client) error {
		return c.DeleteClient(ctx, tablet)
	}); err != nil {
		t.Fatal(err)
	}
	e.advance(11 * time.Minute)
	e.svc.Check(e.ctx)
	got := e.get(o.ID)
	if got.Status != StatusFailed || got.Members[0].Code != "not_found" || got.Members[0].Active {
		t.Errorf("a deleted client settles as failed: %+v", got)
	}
	e.sunk.take()
	e.svc.Check(e.ctx)
	if n := len(e.sunk.take()); n != 0 {
		t.Errorf("a settled member was tried again: %d rows", n)
	}
}

func TestDeletedGroupIsReportedNotRetried(t *testing.T) {
	e := newEnv(t)
	o := e.start(e.target("gamma"), 10, "Default", "open")
	if err := e.inst.Pool.Do(e.ctx, e.ids["gamma"], func(ctx context.Context, c *piholeapi.Client) error {
		return c.DeleteGroup(ctx, "kids")
	}); err != nil {
		t.Fatal(err)
	}
	e.advance(11 * time.Minute)
	e.svc.Check(e.ctx)
	got := e.get(o.ID)
	if got.Status != StatusReverted {
		t.Fatalf("status = %s, want reverted", got.Status)
	}
	if missing, _ := got.Members[0].Details["missing_groups"].([]any); len(missing) != 1 || missing[0] != "kids" {
		t.Errorf("details = %v", got.Members[0].Details)
	}
	eq(t, "gamma", e.groups("gamma"), "Default")
}

func TestOneActiveOverridePerClientPerInstance(t *testing.T) {
	e := newEnv(t)
	first := e.start(e.site, 60, "Default", "open")
	// alpha is covered by the group's override, so neither alpha alone nor the group again can start one.
	for name, target := range map[string]rbac.Target{"the member": e.target("alpha"), "the group": e.site} {
		_, err := e.svc.Create(e.ctx, NewInput{Target: target, Client: tablet, StartsAt: e.now, EndsAt: e.now.Add(time.Hour), By: "alice",
			Members: []NewMember{{InstanceID: e.ids["alpha"], Instance: "alpha", Original: []string{"Default"}, Override: []string{"open"}}}})
		if !rbac.IsCode(err, rbac.CodeConflict) {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if re, _ := rbac.AsError(err); re.Details["override_id"] != first.ID || re.Details["instance"] != "alpha" {
			t.Errorf("%s: details %v", name, re.Details)
		}
	}
	// Another instance is free, and so is the client once the first has finished.
	if _, err := e.svc.Create(e.ctx, NewInput{Target: e.target("gamma"), Client: tablet, StartsAt: e.now, EndsAt: e.now.Add(time.Hour), By: "alice",
		Members: []NewMember{{InstanceID: e.ids["gamma"], Instance: "gamma", Original: []string{"Default"}, Override: []string{"open"}}}}); err != nil {
		t.Errorf("another instance: %v", err)
	}
	e.advance(61 * time.Minute)
	e.svc.Check(e.ctx)
	if _, err := e.svc.Create(e.ctx, NewInput{Target: e.target("alpha"), Client: tablet, StartsAt: e.now, EndsAt: e.now.Add(time.Hour), By: "alice",
		Members: []NewMember{{InstanceID: e.ids["alpha"], Instance: "alpha", Original: []string{"Default", "kids"}, Override: []string{"open"}}}}); err != nil {
		t.Errorf("after the first finished: %v", err)
	}
}

func TestDropRemovesFailedMembers(t *testing.T) {
	e := newEnv(t)
	mk := func() Override {
		o, err := e.svc.Create(e.ctx, NewInput{Target: e.site, Client: tablet, StartsAt: e.now, EndsAt: e.now.Add(time.Hour), By: "alice",
			Members: []NewMember{{InstanceID: e.ids["alpha"], Instance: "alpha", Original: []string{"Default"}, Override: []string{"open"}},
				{InstanceID: e.ids["beta"], Instance: "beta", Original: []string{"Default"}, Override: []string{"open"}}}})
		if err != nil {
			t.Fatal(err)
		}
		return o
	}
	o := mk()
	got, err := e.svc.Drop(e.ctx, o.ID, []int64{e.ids["beta"]}, []audit.Entry{{Username: "alice", Action: audit.ActionClientTempSet, Target: e.site.String()}})
	if err != nil || len(got.Members) != 1 || got.Members[0].Instance != "alpha" {
		t.Fatalf("one member failed: %+v, %v", got, err)
	}
	if rows(e.sunk.take(), audit.ActionClientTempSet) == nil {
		t.Error("the start's audit row wasn't written")
	}
	// Dropping the only member removes the override, and frees the client.
	if _, err := e.svc.Drop(e.ctx, o.ID, []int64{e.ids["alpha"]}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Get(e.ctx, o.ID); !rbac.IsCode(err, rbac.CodeNotFound) {
		t.Errorf("an override no member took is still there: %v", err)
	}
	mk()
}

func TestSetEndAndEndNow(t *testing.T) {
	e := newEnv(t)
	e.svc.Limits = func() Limits { return Limits{Max: 4 * time.Hour, ReasonRequired: false} }
	o := e.start(e.target("gamma"), 60, "Default", "open")
	gamma := e.target("gamma")

	for name, tc := range map[string]struct {
		end  time.Time
		want bool
	}{
		"extend within the maximum":       {e.now.Add(3 * time.Hour), true},
		"past the maximum from the start": {e.now.Add(5 * time.Hour), false},
		"in the past":                     {e.now.Add(-time.Minute), false},
	} {
		_, err := e.svc.SetEnd(e.ctx, e.admin, o.ID, gamma, tc.end)
		if (err == nil) != tc.want {
			t.Errorf("%s: %v", name, err)
		}
	}
	if got := e.get(o.ID); !got.EndsAt.Equal(e.now.Add(3 * time.Hour)) {
		t.Errorf("ends_at = %v", got.EndsAt)
	}
	if ups := rows(e.sunk.take(), audit.ActionClientTempUpdate); len(ups) != 1 || ups[0].Detail["ends_at_after"] == nil {
		t.Errorf("update rows = %+v", ups)
	}
	if _, err := e.svc.SetEnd(e.ctx, e.admin, o.ID, e.site, e.now.Add(time.Hour)); !rbac.IsCode(err, rbac.CodeNotFound) {
		t.Errorf("another target's id: %v", err)
	}

	// End now: ended by the person, and the revert is theirs.
	e.advance(time.Minute)
	ended, err := e.svc.BeginEnd(e.ctx, e.admin, o.ID, gamma)
	if err != nil || ended.EndedBy != "alice" || ended.EndsAt.After(e.now) {
		t.Fatalf("begin end: %+v, %v", ended, err)
	}
	m := ended.Pending()[0]
	ch, rerr := e.revertNow(m)
	got, err := e.svc.Settle(e.ctx, ended, []Attempt{{Member: m, Called: true, Change: ch, Err: rerr}}, SettleOptions{Actor: &e.admin})
	if err != nil || got.Status != StatusEnded {
		t.Fatalf("settle: %+v, %v", got, err)
	}
	eq(t, "gamma", e.groups("gamma"), "Default", "kids")
	if ends := rows(e.sunk.take(), audit.ActionClientTempEnd); len(ends) != 1 || ends[0].Username != "alice" {
		t.Errorf("end rows = %+v", ends)
	}
	// It is over now.
	if _, err := e.svc.BeginEnd(e.ctx, e.admin, o.ID, gamma); !rbac.IsCode(err, rbac.CodeConflict) {
		t.Errorf("ending twice: %v", err)
	}
	if _, err := e.svc.SetEnd(e.ctx, e.admin, o.ID, gamma, e.now.Add(time.Hour)); !rbac.IsCode(err, rbac.CodeConflict) {
		t.Errorf("changing a finished override: %v", err)
	}
}

func TestMemberDownIsSkippedThenRetried(t *testing.T) {
	e := newEnv(t)
	o := e.start(e.site, 10, "Default", "open")
	if _, err := e.inst.SetEnabled(e.ctx, e.admin, e.ids["beta"], false); err != nil {
		t.Fatal(err)
	}
	e.advance(11 * time.Minute)
	e.svc.Check(e.ctx)
	got := e.get(o.ID)
	if got.Status != StatusActive || got.Members[1].Status != RevertSkipped {
		t.Fatalf("a disabled member is skipped, not settled: %+v", got)
	}
	if _, err := e.inst.SetEnabled(e.ctx, e.admin, e.ids["beta"], true); err != nil {
		t.Fatal(err)
	}
	e.advance(time.Minute)
	e.svc.Check(e.ctx)
	eq(t, "beta", e.groups("beta"), "Default", "kids")
	if got := e.get(o.ID); got.Status != StatusReverted {
		t.Errorf("status = %s", got.Status)
	}
}

func TestUsedByAndActiveClients(t *testing.T) {
	e := newEnv(t)
	o := e.start(e.site, 60, "Default", "open")
	for name, tg := range map[string]rbac.Target{"the group": e.site, "a member": e.target("beta")} {
		refs, err := e.svc.UsedBy(e.ctx, tg)
		if err != nil || len(refs) != 1 || refs[0].ID != o.ID || refs[0].Client != tablet {
			t.Errorf("%s: %+v, %v", name, refs, err)
		}
	}
	if refs, _ := e.svc.UsedBy(e.ctx, e.target("gamma")); len(refs) != 0 {
		t.Errorf("gamma: %+v", refs)
	}
	if got, _ := e.svc.ActiveClients(e.ctx, e.ids["alpha"]); got[tablet] != o.ID {
		t.Errorf("active clients on alpha = %v", got)
	}
	if got, _ := e.svc.ActiveClients(e.ctx, e.ids["gamma"]); len(got) != 0 {
		t.Errorf("active clients on gamma = %v", got)
	}
	e.advance(61 * time.Minute)
	e.svc.Check(e.ctx)
	if refs, _ := e.svc.UsedBy(e.ctx, e.site); len(refs) != 0 {
		t.Errorf("a finished override still blocks: %+v", refs)
	}
}
