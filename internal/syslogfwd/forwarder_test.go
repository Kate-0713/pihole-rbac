// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package syslogfwd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/store/db"
	"github.com/Kate-0713/pihole-rbac/internal/syslogfwd/syslogtest"
)

// memStore is a Store in memory.
type memStore struct {
	mu          sync.Mutex
	rows        []db.AuditLog
	cursors     map[int64]int64
	failSets    int  // the next SetCursor calls that fail
	noCursor    bool // Cursor says there is none
	setCalls    int
	lastSetFail error
}

func newMem(n int) *memStore {
	m := &memStore{cursors: map[int64]int64{}}
	for i := 1; i <= n; i++ {
		m.add()
	}
	return m
}

func (m *memStore) add() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := int64(len(m.rows)) + 1
	if n := len(m.rows); n > 0 {
		id = m.rows[n-1].ID + 1
	}
	m.rows = append(m.rows, db.AuditLog{ID: id, At: 1_700_000_000_000 + id, Username: "alice", Action: "domain_add", Target: "i-1",
		Result: "success", Detail: fmt.Sprintf(`{"n":%d}`, id)})
	return id
}

func (m *memStore) NextRows(_ context.Context, after int64, limit int) ([]db.AuditLog, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []db.AuditLog
	for _, r := range m.rows {
		if r.ID > after && len(out) < limit {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *memStore) Cursor(_ context.Context, d int64) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.noCursor {
		return 0, ErrNoCursor
	}
	return m.cursors[d], nil
}

func (m *memStore) SetCursor(_ context.Context, d, last int64, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.setCalls++
	if m.failSets > 0 {
		m.failSets--
		return errors.New("disk full")
	}
	m.cursors[d] = last
	return nil
}

func (m *memStore) cursor(d int64) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cursors[d]
}

// ids returns the row IDs in the collector's messages, in order.
func ids(t *testing.T, msgs []string) []int64 {
	t.Helper()
	out := make([]int64, len(msgs))
	for i, m := range msgs {
		var j struct{ ID int64 }
		if err := json.Unmarshal([]byte(split(t, []byte(m)).text), &j); err != nil {
			t.Fatalf("message %q: %v", m, err)
		}
		out[i] = j.ID
	}
	return out
}

func seq(from, to int64) []int64 {
	var out []int64
	for i := from; i <= to; i++ {
		out = append(out, i)
	}
	return out
}

func fast(f *Forwarder) *Forwarder {
	f.Poll, f.BackoffMin, f.BackoffMax = 10*time.Millisecond, 5*time.Millisecond, 20*time.Millisecond
	f.Hostname = "test-host"
	return f
}

// run starts f and stops it, and waits for it to stop, when the test ends or stop is called.
func run(t *testing.T, f *Forwarder) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.Run(ctx); close(done) }()
	var once sync.Once
	stop = func() { once.Do(func() { cancel(); <-done }) }
	t.Cleanup(stop)
	return stop
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func dest(c *syslogtest.Collector, transport string) Destination {
	return Destination{ID: 1, Name: "test", Config: cfgFor(c, transport)}
}

func TestForwarderSendsNewRowsInOrderAndKeepsTheCursor(t *testing.T) {
	c := syslogtest.NewTCP(t)
	st := newMem(5)
	f := fast(&Forwarder{Dest: dest(c, TransportTCP), Store: st})
	run(t, f)

	if got := ids(t, c.Wait(5, 2*time.Second)); !slices.Equal(got, seq(1, 5)) {
		t.Errorf("first rows: %v", got)
	}
	waitFor(t, "the cursor", func() bool { return st.cursor(1) == 5 })

	st.add()
	st.add()
	f.Nudge()
	if got := ids(t, c.Wait(7, 2*time.Second)); !slices.Equal(got, seq(1, 7)) {
		t.Errorf("after a nudge: %v", got)
	}
	waitFor(t, "the cursor", func() bool { return st.cursor(1) == 7 })
	s := f.Status()
	if s.State != StateOK || s.LastID != 7 || s.Sent != 7 || s.LastSentAt.IsZero() {
		t.Errorf("status: %+v", s)
	}
}

// A row written by a command, with nobody to nudge, is found by the poll.
func TestForwarderPollFindsRowsNobodyNudgedFor(t *testing.T) {
	c := syslogtest.NewTCP(t)
	st := newMem(0)
	run(t, fast(&Forwarder{Dest: dest(c, TransportTCP), Store: st}))
	time.Sleep(30 * time.Millisecond)
	st.add()
	if got := ids(t, c.Wait(1, 2*time.Second)); !slices.Equal(got, []int64{1}) {
		t.Errorf("got %v", got)
	}
}

func TestForwarderResumesFromTheCursorAfterARestart(t *testing.T) {
	c := syslogtest.NewTCP(t)
	st := newMem(4)
	stop := run(t, fast(&Forwarder{Dest: dest(c, TransportTCP), Store: st}))
	c.Wait(4, 2*time.Second)
	waitFor(t, "the cursor", func() bool { return st.cursor(1) == 4 })
	stop()

	st.add()
	st.add()
	run(t, fast(&Forwarder{Dest: dest(c, TransportTCP), Store: st}))
	if got := ids(t, c.Wait(6, 2*time.Second)); !slices.Equal(got, seq(1, 6)) {
		t.Errorf("a new forwarder sent %v: rows before the cursor were sent again, or some were missed", got)
	}
}

func TestForwarderBatches(t *testing.T) {
	c := syslogtest.NewTCP(t)
	st := newMem(10)
	run(t, fast(&Forwarder{Dest: dest(c, TransportTCP), Store: st, BatchSize: 3}))
	if got := ids(t, c.Wait(10, 2*time.Second)); !slices.Equal(got, seq(1, 10)) {
		t.Errorf("got %v", got)
	}
	waitFor(t, "the cursor", func() bool { return st.cursor(1) == 10 })
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.setCalls != 4 {
		t.Errorf("the cursor was saved %d times, want 4 (once a batch)", st.setCalls)
	}
}

// A collector that is down loses nothing: the rows wait, and arrive in order when it is back.
func TestForwarderCollectorDownThenUp(t *testing.T) {
	c := syslogtest.NewTCP(t)
	c.Stop()
	st := newMem(3)
	f := fast(&Forwarder{Dest: dest(c, TransportTCP), Store: st})
	run(t, f)
	waitFor(t, "a failure", func() bool { return f.Status().State == StateFailing })
	if s := f.Status(); s.LastCode != CodeDial || s.Failures == 0 || s.FailingSince.IsZero() {
		t.Errorf("status while down: %+v", s)
	}
	st.add()
	st.add() // written while it is down
	f.Nudge()
	time.Sleep(30 * time.Millisecond)
	if st.cursor(1) != 0 {
		t.Errorf("the cursor moved to %d with nothing delivered", st.cursor(1))
	}

	c.Restart()
	if got := ids(t, c.Wait(5, 3*time.Second)); !slices.Equal(got, seq(1, 5)) {
		t.Errorf("after the collector came back: %v", got)
	}
	waitFor(t, "recovery", func() bool { return f.Status().State == StateOK })
	waitFor(t, "the cursor", func() bool { return st.cursor(1) == 5 })
	if s := f.Status(); !s.FailingSince.IsZero() {
		t.Errorf("still failing since %v", s.FailingSince)
	}
}

// A collector that goes away part-way through: rows written to a connection it had already closed are found by the
// check before each batch, so they go to the new connection.
func TestForwarderSurvivesTheCollectorDroppingConnections(t *testing.T) {
	c := syslogtest.NewTLS(t)
	st := newMem(2)
	f := fast(&Forwarder{Dest: dest(c, TransportTLS), Store: st})
	run(t, f)
	c.Wait(2, 2*time.Second)
	c.DropConnections()
	time.Sleep(50 * time.Millisecond)
	st.add()
	f.Nudge()
	if got := ids(t, c.Wait(3, 2*time.Second)); !slices.Equal(got, seq(1, 3)) {
		t.Errorf("got %v", got)
	}
}

// Rows are written, then the cursor can't be saved: the batch is sent again with the same ids, so a collector can
// drop the repeats, and nothing is missed.
func TestForwarderAtLeastOnce(t *testing.T) {
	c := syslogtest.NewTCP(t)
	st := newMem(3)
	st.failSets = 1
	f := fast(&Forwarder{Dest: dest(c, TransportTCP), Store: st})
	run(t, f)
	waitFor(t, "the cursor", func() bool { return st.cursor(1) == 3 })
	got := ids(t, c.Wait(6, 2*time.Second))
	if !slices.Equal(got, []int64{1, 2, 3, 1, 2, 3}) {
		t.Errorf("got %v, want the batch twice", got)
	}
	// The repeat is the same message, byte for byte.
	if m := c.Messages(); m[0] != m[3] || m[1] != m[4] || m[2] != m[5] {
		t.Errorf("a repeated row differs from its first copy: %q", m)
	}
}

func TestForwarderOutageCallbacks(t *testing.T) {
	c := syslogtest.NewTCP(t)
	c.Stop()
	st := newMem(2)
	var mu sync.Mutex
	var failing, recovered []Outage
	f := fast(&Forwarder{Dest: dest(c, TransportTCP), Store: st, FailAfter: 60 * time.Millisecond,
		OnFailing:   func(o Outage) { mu.Lock(); failing = append(failing, o); mu.Unlock() },
		OnRecovered: func(o Outage) { mu.Lock(); recovered = append(recovered, o); mu.Unlock() }})
	run(t, f)

	time.Sleep(25 * time.Millisecond)
	mu.Lock()
	if len(failing) != 0 {
		t.Errorf("OnFailing after only 25ms of failing: %v", failing)
	}
	mu.Unlock()
	waitFor(t, "OnFailing", func() bool { mu.Lock(); defer mu.Unlock(); return len(failing) == 1 })
	time.Sleep(150 * time.Millisecond) // many more failed attempts: still one call
	mu.Lock()
	if len(failing) != 1 || failing[0].Code != CodeDial || failing[0].Attempts < 2 || failing[0].Since.IsZero() || failing[0].Destination.Name != "test" {
		t.Errorf("failing: %+v", failing)
	}
	if len(recovered) != 0 {
		t.Errorf("recovered while down: %v", recovered)
	}
	mu.Unlock()

	c.Restart()
	c.Wait(2, 3*time.Second)
	waitFor(t, "OnRecovered", func() bool { mu.Lock(); defer mu.Unlock(); return len(recovered) == 1 })
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(recovered) != 1 || recovered[0].LastID != 2 {
		t.Errorf("recovered: %+v", recovered)
	}
}

// An outage that ends before FailAfter writes nothing: no failing call, so no recovered call.
func TestForwarderShortOutageIsQuiet(t *testing.T) {
	c := syslogtest.NewTCP(t)
	c.Stop()
	st := newMem(1)
	var calls int
	var mu sync.Mutex
	count := func(Outage) { mu.Lock(); calls++; mu.Unlock() }
	f := fast(&Forwarder{Dest: dest(c, TransportTCP), Store: st, FailAfter: time.Hour, OnFailing: count, OnRecovered: count})
	run(t, f)
	waitFor(t, "a failure", func() bool { return f.Status().State == StateFailing })
	c.Restart()
	c.Wait(1, 3*time.Second)
	waitFor(t, "recovery", func() bool { return f.Status().State == StateOK })
	mu.Lock()
	defer mu.Unlock()
	if calls != 0 {
		t.Errorf("%d callbacks for an outage under FailAfter", calls)
	}
}

func TestForwarderCountsRowsPrunedBeforeTheyWereSent(t *testing.T) {
	c := syslogtest.NewTCP(t)
	st := newMem(0)
	st.rows = []db.AuditLog{{ID: 5, At: 1, Action: "login", Result: "success", Detail: "{}"}, {ID: 6, At: 2, Action: "login", Result: "success", Detail: "{}"}}
	st.cursors[1] = 1 // rows 2 to 4 were pruned
	f := fast(&Forwarder{Dest: dest(c, TransportTCP), Store: st})
	run(t, f)
	if got := ids(t, c.Wait(2, 2*time.Second)); !slices.Equal(got, []int64{5, 6}) {
		t.Errorf("got %v", got)
	}
	waitFor(t, "the cursor", func() bool { return st.cursor(1) == 6 })
	if s := f.Status(); s.SkippedPruned != 3 {
		t.Errorf("skipped %d, want 3", s.SkippedPruned)
	}
}

func TestForwarderDrain(t *testing.T) {
	c := syslogtest.NewTCP(t)
	st := newMem(10)
	f := fast(&Forwarder{Dest: dest(c, TransportTCP), Store: st, BatchSize: 4})
	if err := f.Drain(context.Background(), 6); err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if got := ids(t, c.Wait(6, 2*time.Second)); !slices.Equal(got, seq(1, 6)) {
		t.Errorf("got %v", got)
	}
	time.Sleep(30 * time.Millisecond)
	if n := len(c.Messages()); n != 6 || st.cursor(1) != 6 {
		t.Errorf("%d messages and cursor %d after draining up to 6", n, st.cursor(1))
	}
	// Draining a collector that is down reports it.
	c.Stop()
	g := fast(&Forwarder{Dest: Destination{ID: 2, Name: "down", Config: dest(c, TransportTCP).Config}, Store: st})
	if err := g.Drain(context.Background(), 10); CodeOf(err) != CodeDial {
		t.Errorf("drain to a stopped collector: %v", err)
	}
}

func TestForwarderUDP(t *testing.T) {
	c := syslogtest.NewUDP(t)
	st := newMem(3)
	f := fast(&Forwarder{Dest: dest(c, TransportUDP), Store: st})
	run(t, f)
	if got := ids(t, c.Wait(3, 2*time.Second)); !slices.Equal(got, seq(1, 3)) {
		t.Errorf("got %v", got)
	}
	waitFor(t, "the cursor", func() bool { return st.cursor(1) == 3 })
}

func TestForwarderTruncatesOverUDPNotOverTCP(t *testing.T) {
	big := fmt.Sprintf(`{"x":%q}`, strings.Repeat("y", 4000))
	for _, tc := range []struct {
		name      string
		start     func(testing.TB) *syslogtest.Collector
		transport string
		truncated bool
	}{{"udp", syslogtest.NewUDP, TransportUDP, true}, {"tcp", syslogtest.NewTCP, TransportTCP, false}} {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.start(t)
			st := newMem(0)
			st.rows = []db.AuditLog{{ID: 1, At: 1, Action: "domain_add", Result: "success", Detail: big}}
			run(t, fast(&Forwarder{Dest: dest(c, tc.transport), Store: st}))
			m := c.Wait(1, 2*time.Second)[0]
			if got := strings.Contains(m, `"truncated":true`); got != tc.truncated {
				t.Errorf("truncated %v, want %v (%d bytes)", got, tc.truncated, len(m))
			}
			if tc.truncated && len(m) > UDPLimit {
				t.Errorf("%d bytes over UDP", len(m))
			}
		})
	}
}

// A detail with via_token (a request made with an API token) is forwarded whole.
func TestForwarderSendsTheWholeDetail(t *testing.T) {
	c := syslogtest.NewTCP(t)
	st := newMem(0)
	st.rows = []db.AuditLog{{ID: 1, At: 1, Username: "ha", Action: "blocking_set", Result: "failure",
		Detail: `{"via_token":"home assistant","token_id":"abcdefghijklmnop","error":"pihole_unreachable"}`}}
	run(t, fast(&Forwarder{Dest: dest(c, TransportTCP), Store: st}))
	p := split(t, []byte(c.Wait(1, 2*time.Second)[0]))
	for _, want := range []string{`"via_token":"home assistant"`, `"token_id":"abcdefghijklmnop"`, `"error":"pihole_unreachable"`} {
		if !strings.Contains(p.text, want) {
			t.Errorf("%s missing from %s", want, p.text)
		}
	}
	if p.pri != "108" || p.msgid != "blocking_set" {
		t.Errorf("header: %+v", p)
	}
}

func TestForwarderWithoutACursor(t *testing.T) {
	c := syslogtest.NewTCP(t)
	st := newMem(2)
	st.noCursor = true
	f := fast(&Forwarder{Dest: dest(c, TransportTCP), Store: st})
	run(t, f)
	waitFor(t, "a failure", func() bool { return f.Status().State == StateFailing })
	if s := f.Status(); s.LastCode != CodeCursorAbsent {
		t.Errorf("code %q, want %s", s.LastCode, CodeCursorAbsent)
	}
	if n := len(c.Messages()); n != 0 {
		t.Errorf("%d messages sent from nowhere", n)
	}
}

// A nudge during a backoff doesn't make the forwarder try again at once.
func TestForwarderNudgeDoesNotCutABackoffShort(t *testing.T) {
	c := syslogtest.NewTCP(t)
	c.Stop()
	st := newMem(1)
	f := &Forwarder{Dest: dest(c, TransportTCP), Store: st, Hostname: "h", Poll: time.Hour, BackoffMin: 300 * time.Millisecond, BackoffMax: 300 * time.Millisecond}
	run(t, f)
	waitFor(t, "a failure", func() bool { return f.Status().Failures >= 1 })
	for range 20 {
		f.Nudge()
		time.Sleep(5 * time.Millisecond)
	}
	if n := f.Status().Failures; n != 1 {
		t.Errorf("%d failed passes within a 300ms backoff, want 1", n)
	}
}

func TestForwarderCount(t *testing.T) {
	c := syslogtest.NewTCP(t)
	c.Stop()
	st := newMem(3)
	var mu sync.Mutex
	got := map[string]int{}
	f := fast(&Forwarder{Dest: dest(c, TransportTCP), Store: st, Count: func(result string, n int) {
		mu.Lock()
		got[result] += n
		mu.Unlock()
	}})
	run(t, f)
	count := func(r string) int { mu.Lock(); defer mu.Unlock(); return got[r] }
	waitFor(t, "a failure", func() bool { return count("failed") > 0 })
	if count("sent") != 0 {
		t.Errorf("sent %d with the collector down", count("sent"))
	}
	c.Restart()
	waitFor(t, "the rows", func() bool { return count("sent") == 3 })
}
