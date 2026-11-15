// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package gravity runs gravity updates on Pi-holes in the background and keeps their progress in memory, for the
// page to poll. A run covers one instance, or a mirrored group's members one at a time: the primary first, then the
// others by name, stopping at the first member that fails, so a list change that breaks gravity only breaks it on one
// Pi-hole.
//
// Nothing is stored: runs, their output and the locks that stop two runs on one instance live in memory and are lost
// on a restart. Pi-hole carries on with a run whose client has gone away, so a run that was going still finishes on
// the Pi-hole. The audit log, which the caller writes from the Started and Finished hooks, is the lasting record.
package gravity

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"slices"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
)

// Limits.
const (
	// RunLimit bounds a whole run, every member of a group included. Each member's own gravity call is bounded by
	// the Pi-hole client's gravity timeout.
	RunLimit = time.Hour
	// MaxLinesPerInstance is how many lines of an instance's output are kept; older ones are dropped.
	MaxLinesPerInstance = 2000
	// MaxServedLines is the most lines one read returns.
	MaxServedLines = 200
	// MaxLineRunes caps a kept line.
	MaxLineRunes = 500
	// Keep is how long a finished run is kept after it ends, unless it is its target's latest.
	Keep = time.Hour
)

// Run and instance states.
const (
	StatusRunning = "running"
	StatusDone    = "done"

	InstancePending = "pending"
	InstanceRunning = "running"
	InstanceOK      = "ok"
	InstanceFailed  = "failed"
	InstanceSkipped = "skipped"

	// Why an instance was skipped.
	ReasonStopped = "stopped" // an earlier member failed
	ReasonDown    = "down"    // the instance couldn't be reached, in a run through a group

	// CodeEmpty is an instance whose gravity ended with no domains when it had some before.
	CodeEmpty = "gravity_empty"
)

// Call makes one call to an instance through the client pool (instances.Pool.Do).
type Call func(ctx context.Context, id int64, fn func(context.Context, *piholeapi.Client) error) error

// Member is an instance a run covers.
type Member struct {
	ID      int64
	Name    string
	Primary bool // a mirrored group's primary
}

// Result is how an instance's part of a run went.
type Result struct {
	Member
	Status string
	Reason string // for skipped
	Err    error  // for failed; instances.Kind gives its code, or CodeEmpty
	// For ok, and for an instance that ended with no domains:
	Domains     int
	LastUpdate  int64 // Unix seconds, from Pi-hole
	ListsFailed int   // enabled lists whose download failed (status 3 or 4)
	Started     time.Time
	Duration    time.Duration
}

// ErrEmpty is the error of an instance whose gravity ended with no domains when it had some before.
var ErrEmpty = errors.New("gravity ended with no domains")

// Line is a line of output.
type Line struct {
	Seq      int // from 1, across the whole run
	Instance int64
	Text     string
}

// Snapshot is a run as it stands: a copy, safe to use after the call that returned it.
type Snapshot struct {
	ID         string
	Target     string
	StartedBy  string
	Started    time.Time
	Finished   time.Time // zero while running
	Status     string
	Results    []Result
	Lines      []Line // the newest MaxServedLines after the seq asked for
	LastSeq    int    // the seq of the newest line so far
	Truncated  bool   // lines after the seq asked for were dropped, or not served, before the first in Lines
	instanceOf map[int64]int
}

// BusyError is a run refused because instances it would cover are already in a run started by this app.
type BusyError struct{ Members []Member }

func (e *BusyError) Error() string {
	return "gravity is already running on an instance this run would cover"
}

// Hooks are called from a run's goroutine.
type Hooks struct {
	// Finished is called when an instance's part ends, ok or failed, but not for a skipped one, with the run's ID.
	Finished func(ctx context.Context, runID string, r Result)
}

// Service holds the runs.
type Service struct {
	Call Call
	Now  func() time.Time // time.Now if nil

	mu     sync.Mutex
	busy   map[int64]string // instance ID to the run it is in
	runs   map[string]*run
	latest map[string]string // target to its latest run
	wg     sync.WaitGroup
}

type run struct {
	snap  Snapshot      // Lines holds every kept line; the rest as served
	count map[int64]int // kept lines per instance
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Start starts a run on target (an API target string, "i-1" or "g-2") over members, in the order given (the caller
// puts a group's primary first), as startedBy. ctx's values (the caller's identity, for audit rows) are kept, but not
// its cancellation: the run carries on after the request that started it. It returns the run as it starts, or a
// *BusyError naming the members already in a run.
func (s *Service) Start(ctx context.Context, target, startedBy string, members []Member, hooks Hooks) (Snapshot, error) {
	if len(members) == 0 {
		return Snapshot{}, errors.New("gravity: a run needs at least one instance")
	}
	id, err := newID()
	if err != nil {
		return Snapshot{}, err
	}
	s.mu.Lock()
	if s.busy == nil {
		s.busy, s.runs, s.latest = map[int64]string{}, map[string]*run{}, map[string]string{}
	}
	var busy []Member
	for _, m := range members {
		if _, ok := s.busy[m.ID]; ok {
			busy = append(busy, m)
		}
	}
	if busy != nil {
		s.mu.Unlock()
		return Snapshot{}, &BusyError{Members: busy}
	}
	r := &run{
		snap: Snapshot{
			ID: id, Target: target, StartedBy: startedBy, Started: s.now(), Status: StatusRunning,
			instanceOf: map[int64]int{},
		},
		count: map[int64]int{},
	}
	for i, m := range members {
		s.busy[m.ID] = id
		r.snap.Results = append(r.snap.Results, Result{Member: m, Status: InstancePending})
		r.snap.instanceOf[m.ID] = i
	}
	s.runs[id] = r
	s.latest[target] = id
	s.prune()
	snap := r.served(0)
	s.mu.Unlock()

	s.wg.Go(func() {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), RunLimit)
		defer cancel()
		s.execute(rctx, r, members, hooks)
	})
	return snap, nil
}

// Wait waits for every run to end, for tests and shutdown.
func (s *Service) Wait() { s.wg.Wait() }

// Get returns run id of target, with the lines after seq after.
func (s *Service) Get(target, id string, after int) (Snapshot, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	r, ok := s.runs[id]
	if !ok || r.snap.Target != target {
		return Snapshot{}, false
	}
	return r.served(after), true
}

// Latest returns target's latest run, with the lines after seq after.
func (s *Service) Latest(target string, after int) (Snapshot, bool) {
	s.mu.Lock()
	id, ok := s.latest[target]
	s.mu.Unlock()
	if !ok {
		return Snapshot{}, false
	}
	return s.Get(target, id, after)
}

// prune drops finished runs older than Keep, except each target's latest. Called with s.mu held.
func (s *Service) prune() {
	cutoff := s.now().Add(-Keep)
	for id, r := range s.runs {
		if r.snap.Status == StatusDone && r.snap.Finished.Before(cutoff) && s.latest[r.snap.Target] != id {
			delete(s.runs, id)
		}
	}
}

// served copies the run with the lines after seq after: the newest MaxServedLines of them. Called with s.mu held.
func (r *run) served(after int) Snapshot {
	snap := r.snap
	snap.Results = slices.Clone(r.snap.Results)
	snap.instanceOf = nil
	snap.LastSeq = 0
	if n := len(r.snap.Lines); n > 0 {
		snap.LastSeq = r.snap.Lines[n-1].Seq
	}
	i, _ := slices.BinarySearchFunc(r.snap.Lines, after+1, func(l Line, seq int) int { return l.Seq - seq })
	lines := r.snap.Lines[i:]
	firstWanted := after + 1
	if len(lines) > MaxServedLines {
		lines = lines[len(lines)-MaxServedLines:]
	}
	snap.Truncated = len(lines) > 0 && lines[0].Seq > firstWanted
	snap.Lines = slices.Clone(lines)
	return snap
}

func (s *Service) setResult(r *run, res Result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r.snap.Results[r.snap.instanceOf[res.ID]] = res
}

// addLine keeps a line of an instance's output, dropping that instance's oldest once it has MaxLinesPerInstance.
func (s *Service) addLine(r *run, instance int64, text string) {
	if utf8.RuneCountInString(text) > MaxLineRunes {
		text = string([]rune(text)[:MaxLineRunes])
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	seq := 1
	if n := len(r.snap.Lines); n > 0 {
		seq = r.snap.Lines[n-1].Seq + 1
	}
	if r.count[instance] >= MaxLinesPerInstance {
		i := slices.IndexFunc(r.snap.Lines, func(l Line) bool { return l.Instance == instance })
		r.snap.Lines = slices.Delete(r.snap.Lines, i, i+1)
	} else {
		r.count[instance]++
	}
	r.snap.Lines = append(r.snap.Lines, Line{Seq: seq, Instance: instance, Text: text})
}

func (s *Service) execute(ctx context.Context, r *run, members []Member, hooks Hooks) {
	group := len(members) > 1
	stopped := false
	for _, m := range members {
		if stopped {
			s.setResult(r, Result{Member: m, Status: InstanceSkipped, Reason: ReasonStopped})
			s.release(m.ID)
			continue
		}
		res := s.runOne(ctx, r, m)
		if group && res.Status == InstanceFailed && isDown(res.Err) && res.Duration == 0 {
			// Couldn't be reached at the start: in a group, skip it and go on.
			res = Result{Member: m, Status: InstanceSkipped, Reason: ReasonDown, Err: res.Err}
		}
		s.setResult(r, res)
		if res.Status != InstanceSkipped && hooks.Finished != nil {
			hooks.Finished(ctx, r.snap.ID, res)
		}
		s.release(m.ID)
		if res.Status == InstanceFailed {
			stopped = true
		}
	}
	s.mu.Lock()
	r.snap.Status, r.snap.Finished = StatusDone, s.now()
	s.mu.Unlock()
}

func (s *Service) release(id int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.busy, id)
}

// isDown reports whether err means the instance couldn't be used at all (unreachable, password refused, in its
// backoff, or not set up), rather than gravity failing on it.
func isDown(err error) bool {
	if errors.Is(err, piholeapi.ErrGravityFailed) || errors.Is(err, piholeapi.ErrGravityRunning) || errors.Is(err, ErrEmpty) {
		return false
	}
	var se *piholeapi.StatusError
	return !errors.As(err, &se) && !errors.Is(err, piholeapi.ErrRejected)
}

// runOne runs gravity on one instance: it reads the domain count first, runs gravity with its output kept as it
// arrives, then reads the count, the time and the lists. Duration stays zero when the instance couldn't be called at
// all.
func (s *Service) runOne(ctx context.Context, r *run, m Member) Result {
	res := Result{Member: m, Status: InstanceRunning, Started: s.now()}
	s.setResult(r, res)
	before := -1
	err := s.Call(ctx, m.ID, func(ctx context.Context, c *piholeapi.Client) error {
		sum, err := c.GetLiveSummary(ctx)
		if err != nil {
			return err
		}
		before = sum.Gravity.DomainsBeingBlocked
		return nil
	})
	if err != nil {
		res.Status, res.Err = InstanceFailed, err
		return res
	}
	err = s.Call(ctx, m.ID, func(ctx context.Context, c *piholeapi.Client) error {
		return c.RunGravity(ctx, func(line string) { s.addLine(r, m.ID, line) })
	})
	res.Duration = max(s.now().Sub(res.Started), time.Millisecond)
	if err != nil {
		res.Status, res.Err = InstanceFailed, err
		return res
	}
	// The run itself went well; the reads after it only add detail, and a failed read isn't the run failing.
	_ = s.Call(ctx, m.ID, func(ctx context.Context, c *piholeapi.Client) error {
		sum, err := c.GetLiveSummary(ctx)
		if err != nil {
			return err
		}
		res.Domains, res.LastUpdate = sum.Gravity.DomainsBeingBlocked, sum.Gravity.LastUpdate
		if res.Domains == 0 && before > 0 {
			res.Status, res.Err = InstanceFailed, ErrEmpty
		}
		all, err := c.ListLists(ctx)
		if err != nil {
			return err
		}
		for _, l := range all {
			if l.Enabled && (l.Status == piholeapi.ListStatusCached || l.Status == piholeapi.ListStatusFailed) {
				res.ListsFailed++
			}
		}
		return nil
	})
	if res.Status == InstanceRunning {
		res.Status = InstanceOK
	}
	return res
}

func newID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
