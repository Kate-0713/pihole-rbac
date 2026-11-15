// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package gravity

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi/piholetest"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
)

const password = "app-password"

type env struct {
	t       *testing.T
	svc     *Service
	ph      map[string]*piholetest.Server
	members map[string]Member

	mu       sync.Mutex
	finished []Result
}

// newEnv starts a fake Pi-hole per name, the first being the primary. A name ending in "!" is an instance that can't
// be reached.
func newEnv(t *testing.T, names ...string) *env {
	t.Helper()
	e := &env{t: t, ph: map[string]*piholetest.Server{}, members: map[string]Member{}}
	clients := map[int64]*piholeapi.Client{}
	for i, n := range names {
		url := ""
		name := strings.TrimSuffix(n, "!")
		if name != n {
			dead := httptest.NewServer(nil)
			url = dead.URL
			dead.Close()
		} else {
			ph := piholetest.New(t, password)
			ph.AddList(piholetest.List{Address: "https://lists.example/ads.txt", Type: "block", Enabled: true})
			e.ph[name] = ph
			url = ph.URL
		}
		c, err := piholeapi.New(piholeapi.Options{BaseURL: url, Password: secrets.NewValue([]byte(password))})
		if err != nil {
			t.Fatal(err)
		}
		id := int64(i + 1)
		clients[id] = c
		e.members[name] = Member{ID: id, Name: name, Primary: i == 0}
	}
	e.svc = &Service{Call: func(ctx context.Context, id int64, fn func(context.Context, *piholeapi.Client) error) error {
		return fn(ctx, clients[id])
	}}
	t.Cleanup(e.svc.Wait)
	return e
}

func (e *env) list(names ...string) []Member {
	var out []Member
	for _, n := range names {
		out = append(out, e.members[n])
	}
	return out
}

func (e *env) start(target string, names ...string) Snapshot {
	e.t.Helper()
	snap, err := e.svc.Start(context.Background(), target, "admin", e.list(names...), Hooks{Finished: func(_ context.Context, _ string, r Result) {
		e.mu.Lock()
		defer e.mu.Unlock()
		e.finished = append(e.finished, r)
	}})
	if err != nil {
		e.t.Fatal(err)
	}
	return snap
}

// finish waits for run id to end (not every run: another may be held on purpose) and returns it.
func (e *env) finish(target, id string) Snapshot {
	e.t.Helper()
	var snap Snapshot
	waitFor(e.t, func() bool {
		var ok bool
		if snap, ok = e.svc.Get(target, id, 0); !ok {
			e.t.Fatalf("run %s gone", id)
		}
		return snap.Status == StatusDone
	})
	return snap
}

func outcomes(snap Snapshot) []string {
	var out []string
	for _, r := range snap.Results {
		s := r.Name + ":" + r.Status
		if r.Reason != "" {
			s += ":" + r.Reason
		}
		if r.Err != nil {
			code := piholeapi.Kind(r.Err)
			if errors.Is(r.Err, ErrEmpty) {
				code = CodeEmpty
			}
			s += ":" + code
		}
		out = append(out, s)
	}
	return out
}

func TestRunOneInstance(t *testing.T) {
	e := newEnv(t, "alpha")
	e.ph["alpha"].AddList(piholetest.List{Address: "https://lists.example/broken.txt", Type: "block", Enabled: true})
	e.ph["alpha"].SetGravity(piholetest.GravityRun{
		Lines:    []string{"  [i] one", "  [i] two\r\x1b[K  [✓] two"},
		Statuses: map[string]int{"https://lists.example/broken.txt": piholeapi.ListStatusCached},
	})
	snap := e.start("i-1", "alpha")
	if snap.Status != StatusRunning || snap.ID == "" || snap.StartedBy != "admin" || len(snap.Results) != 1 {
		t.Errorf("started %+v", snap)
	}
	snap = e.finish("i-1", snap.ID)
	if got := outcomes(snap); !slices.Equal(got, []string{"alpha:ok"}) {
		t.Fatalf("results %v", got)
	}
	r := snap.Results[0]
	if r.Domains != 2000 || r.LastUpdate == 0 || r.ListsFailed != 1 || r.Duration <= 0 {
		t.Errorf("result %+v", r)
	}
	var lines []string
	for _, l := range snap.Lines {
		lines = append(lines, fmt.Sprintf("%d %d %s", l.Seq, l.Instance, l.Text))
	}
	if want := []string{"1 1   [i] one", "2 1   [✓] two"}; !slices.Equal(lines, want) {
		t.Errorf("lines %q, want %q", lines, want)
	}
	if snap.Status != StatusDone || snap.Finished.IsZero() || snap.LastSeq != 2 {
		t.Errorf("snapshot %+v", snap)
	}
	if len(e.finished) != 1 || e.finished[0].Status != InstanceOK {
		t.Errorf("finished hooks %+v", e.finished)
	}
	if latest, ok := e.svc.Latest("i-1", 0); !ok || latest.ID != snap.ID {
		t.Error("not the latest")
	}
	if _, ok := e.svc.Get("i-2", snap.ID, 0); ok {
		t.Error("a run was found through another target")
	}
	// The lock is gone, so another run can start.
	e.finish("i-1", e.start("i-1", "alpha").ID)
}

// TestRollingRun: through a group, members run one at a time, primary first; the first failure stops the run, a
// member that can't be reached is skipped, and a member whose count drops to 0 counts as a failure.
func TestRollingRun(t *testing.T) {
	tests := []struct {
		name    string
		members []string
		setup   func(e *env)
		want    []string
		ran     []string // which fakes ran gravity
	}{
		{
			name:    "every member",
			members: []string{"alpha", "beta", "gamma"},
			want:    []string{"alpha:ok", "beta:ok", "gamma:ok"},
			ran:     []string{"alpha", "beta", "gamma"},
		},
		{
			name:    "a failure stops the run",
			members: []string{"alpha", "beta", "gamma"},
			setup:   func(e *env) { e.ph["beta"].SetGravity(piholetest.GravityRun{Fail: true}) },
			want:    []string{"alpha:ok", "beta:failed:gravity_failed", "gamma:skipped:stopped"},
			ran:     []string{"alpha", "beta"},
		},
		{
			name:    "the primary failing stops it before anything else",
			members: []string{"alpha", "beta"},
			setup:   func(e *env) { e.ph["alpha"].SetGravity(piholetest.GravityRun{CutShort: true}) },
			want:    []string{"alpha:failed:gravity_failed", "beta:skipped:stopped"},
			ran:     []string{"alpha"},
		},
		{
			name:    "a member that can't be reached is skipped",
			members: []string{"alpha", "beta!", "gamma"},
			want:    []string{"alpha:ok", "beta:skipped:down:pihole_unreachable", "gamma:ok"},
			ran:     []string{"alpha", "gamma"},
		},
		{
			name:    "dropping to no domains stops the run",
			members: []string{"alpha", "beta", "gamma"},
			setup:   func(e *env) { e.ph["beta"].SetGravity(piholetest.GravityRun{Domains: -1}) },
			want:    []string{"alpha:ok", "beta:failed:gravity_empty", "gamma:skipped:stopped"},
			ran:     []string{"alpha", "beta"},
		},
		{
			name:    "no domains before and after is fine",
			members: []string{"alpha", "beta"},
			setup: func(e *env) {
				e.ph["alpha"].SetGravityState(0, 0)
				e.ph["alpha"].SetGravity(piholetest.GravityRun{Domains: -1})
			},
			want: []string{"alpha:ok", "beta:ok"},
			ran:  []string{"alpha", "beta"},
		},
		{
			name:    "Pi-hole already running gravity is a failure",
			members: []string{"alpha", "beta"},
			setup: func(e *env) {
				e.ph["alpha"].Handle(func(w http.ResponseWriter, r *http.Request) bool {
					if r.URL.Path != "/api/action/gravity" {
						return false
					}
					w.WriteHeader(http.StatusConflict)
					return true
				})
			},
			want: []string{"alpha:failed:gravity_running", "beta:skipped:stopped"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t, tt.members...)
			if tt.setup != nil {
				tt.setup(e)
			}
			names := make([]string, len(tt.members))
			for i, n := range tt.members {
				names[i] = strings.TrimSuffix(n, "!")
			}
			snap := e.finish("g-1", e.start("g-1", names...).ID)
			if got := outcomes(snap); !slices.Equal(got, tt.want) {
				t.Errorf("results %v, want %v", got, tt.want)
			}
			var ran []string
			for _, n := range names {
				if ph, ok := e.ph[n]; ok && ph.GravityRuns() > 0 {
					ran = append(ran, n)
				}
			}
			if !slices.Equal(ran, tt.ran) {
				t.Errorf("ran on %v, want %v", ran, tt.ran)
			}
			// Hooks for every member that ran or failed, never for a skipped one.
			for _, f := range e.finished {
				if f.Status == InstanceSkipped {
					t.Errorf("finished hook for skipped %s", f.Name)
				}
			}
		})
	}

	t.Run("a single instance that can't be reached is a failure, not skipped", func(t *testing.T) {
		e := newEnv(t, "alpha!")
		snap := e.finish("i-1", e.start("i-1", "alpha").ID)
		if got := outcomes(snap); !slices.Equal(got, []string{"alpha:failed:pihole_unreachable"}) {
			t.Errorf("results %v", got)
		}
	})
}

// TestOneRunPerInstance: a run is refused while any instance it would cover is in another, whatever the target.
func TestOneRunPerInstance(t *testing.T) {
	e := newEnv(t, "alpha", "beta", "gamma")
	hold := make(chan struct{})
	e.ph["beta"].SetGravity(piholetest.GravityRun{Hold: hold})
	first := e.start("g-1", "alpha", "beta")
	waitFor(t, func() bool {
		s, _ := e.svc.Get("g-1", first.ID, 0)
		return s.Results[1].Status == InstanceRunning
	})
	_, err := e.svc.Start(context.Background(), "i-2", "admin", e.list("beta"), Hooks{})
	var be *BusyError
	if !errors.As(err, &be) || len(be.Members) != 1 || be.Members[0].Name != "beta" {
		t.Errorf("err = %v", err)
	}
	// alpha has finished its part, so it's free again; gamma never was in the run.
	e.finish("i-3", e.start("i-3", "gamma").ID)
	if s, _ := e.svc.Get("g-1", first.ID, 0); s.Results[0].Status != InstanceOK {
		t.Fatalf("alpha %+v", s.Results[0])
	}
	e.start("i-1", "alpha")
	close(hold)
	if s := e.finish("g-1", first.ID); s.Status != StatusDone || s.Results[1].Status != InstanceOK {
		t.Errorf("first run %v", outcomes(s))
	}
	e.finish("i-2", e.start("i-2", "beta").ID)
}

// TestRunOutlivesRequest: the request's context ending doesn't stop the run, but its values are kept for the hooks.
func TestRunOutlivesRequest(t *testing.T) {
	e := newEnv(t, "alpha")
	hold := make(chan struct{})
	e.ph["alpha"].SetGravity(piholetest.GravityRun{Hold: hold})
	type key struct{}
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), key{}, "who"))
	var seen any
	var seenID string
	snap, err := e.svc.Start(ctx, "i-1", "admin", e.list("alpha"), Hooks{Finished: func(ctx context.Context, id string, r Result) { seen, seenID = ctx.Value(key{}), id }})
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	close(hold)
	if s := e.finish("i-1", snap.ID); s.Results[0].Status != InstanceOK {
		t.Errorf("results %v", outcomes(s))
	}
	if seen != "who" || seenID != snap.ID {
		t.Errorf("hook context value %v, run %q", seen, seenID)
	}
}

func TestOutput(t *testing.T) {
	e := newEnv(t, "alpha", "beta")
	var lines []string
	for i := range MaxLinesPerInstance + 100 {
		lines = append(lines, fmt.Sprintf("line %d", i))
	}
	lines = append(lines, strings.Repeat("é", MaxLineRunes+10))
	e.ph["alpha"].SetGravity(piholetest.GravityRun{Lines: lines})
	e.ph["beta"].SetGravity(piholetest.GravityRun{Lines: []string{"beta one", "beta two"}})
	snap := e.finish("g-1", e.start("g-1", "alpha", "beta").ID)

	total := len(lines) + 2
	if snap.LastSeq != total {
		t.Errorf("last seq %d, want %d", snap.LastSeq, total)
	}
	if len(snap.Lines) != MaxServedLines || !snap.Truncated || snap.Lines[len(snap.Lines)-1].Text != "beta two" {
		t.Errorf("%d lines served, truncated %v, last %q", len(snap.Lines), snap.Truncated, snap.Lines[len(snap.Lines)-1].Text)
	}
	long := snap.Lines[len(snap.Lines)-3]
	if long.Instance != 1 || len([]rune(long.Text)) != MaxLineRunes {
		t.Errorf("the long line: %d runes, instance %d", len([]rune(long.Text)), long.Instance)
	}
	// Only what's new since a seq.
	newer, _ := e.svc.Get("g-1", snap.ID, total-2)
	if len(newer.Lines) != 2 || newer.Truncated || newer.Lines[0].Text != "beta one" {
		t.Errorf("after %d: %+v", total-2, newer.Lines)
	}
	if none, _ := e.svc.Get("g-1", snap.ID, total); len(none.Lines) != 0 || none.Truncated {
		t.Errorf("after the last: %+v", none.Lines)
	}
	// alpha's oldest lines were dropped: asking from the start gets truncated output from line 101 on at most.
	e.svc.mu.Lock()
	r := e.svc.runs[snap.ID]
	kept := 0
	for _, l := range r.snap.Lines {
		if l.Instance == 1 {
			kept++
		}
	}
	first := r.snap.Lines[0]
	e.svc.mu.Unlock()
	if kept != MaxLinesPerInstance || first.Text != "line 101" {
		t.Errorf("alpha kept %d lines, the first %q", kept, first.Text)
	}
}

func TestPrune(t *testing.T) {
	e := newEnv(t, "alpha", "beta")
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	e.svc.Now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	old := e.finish("i-1", e.start("i-1", "alpha").ID)
	latest := e.finish("i-1", e.start("i-1", "alpha").ID)
	other := e.finish("i-2", e.start("i-2", "beta").ID)
	mu.Lock()
	now = now.Add(Keep + time.Minute)
	mu.Unlock()
	if _, ok := e.svc.Get("i-1", old.ID, 0); ok {
		t.Error("an old run was kept")
	}
	if _, ok := e.svc.Get("i-1", latest.ID, 0); !ok {
		t.Error("the target's latest run was dropped")
	}
	if _, ok := e.svc.Latest("i-2", 0); !ok {
		t.Errorf("another target's latest run %s was dropped", other.ID)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
