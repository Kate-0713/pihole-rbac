// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package syslogfwd

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// Store is what a Forwarder reads and keeps: the audit rows after a given ID, and each destination's cursor, the ID
// of the last row sent to it.
type Store interface {
	// NextRows returns up to limit rows with an ID above after, oldest first.
	NextRows(ctx context.Context, after int64, limit int) ([]db.AuditLog, error)
	// Cursor returns the destination's last sent ID, or ErrNoCursor.
	Cursor(ctx context.Context, destination int64) (int64, error)
	SetCursor(ctx context.Context, destination, lastID int64, at time.Time) error
}

// ErrNoCursor says a destination has no cursor. One is made with the destination, so this means something is wrong.
var ErrNoCursor = errors.New("syslogfwd: the destination has no cursor")

// Defaults.
const (
	DefaultBatch      = 200
	DefaultPoll       = 5 * time.Second
	DefaultBackoffMin = time.Second
	DefaultBackoffMax = time.Minute
	DefaultFailAfter  = 5 * time.Minute

	saveTimeout = 5 * time.Second // the longest a cursor save may take once rows have been written
)

// Codes of a failure that isn't a send.
const (
	CodeRead         = "read_failed"
	CodeCursor       = "cursor_failed"
	CodeCursorAbsent = "cursor_missing"
)

// Destination is one collector: its ID in log_destinations, its name for logs, and where to send.
type Destination struct {
	ID     int64
	Name   string
	Config Config
}

// Outage describes a destination that has been failing, for the rows written when it starts and ends.
type Outage struct {
	Destination Destination
	Since       time.Time // the first failure of the streak
	Code        string    // the latest failure's code
	Attempts    int       // failed passes in the streak
	LastID      int64     // the last row sent
}

// State is what a destination's page shows.
type State string

const (
	StateIdle    State = "idle"    // nothing sent yet
	StateOK      State = "ok"      // the last pass worked
	StateFailing State = "failing" // the last pass failed
)

// Status is a snapshot of one forwarder, in memory only: a restart starts it again at idle.
type Status struct {
	State         State
	LastSentAt    time.Time // when a row was last written to the collector
	LastCode      string    // the latest failure's code
	FailingSince  time.Time
	LastID        int64 // the cursor
	Sent          int64 // rows written since start (a row sent again counts again)
	Failures      int64 // failed passes since start
	SkippedPruned int64 // rows the retention deleted before they were sent, since start
}

// Forwarder sends the audit rows after its destination's cursor and keeps the cursor current. Run it in a goroutine
// and call Nudge when a row is written. It sends again from the cursor after any failure, with a growing wait, so
// delivery is at least once: a batch written whose cursor then failed to save is sent again, with the same ids.
type Forwarder struct {
	Dest     Destination
	Store    Store
	Hostname string // cleaned by the message formatter
	Logger   *slog.Logger
	// Writer overrides the transport, for tests. It must send to Dest.Config.
	Writer *Writer

	BatchSize  int
	Poll       time.Duration // how often to look for rows nobody nudged for, such as a command's
	BackoffMin time.Duration
	BackoffMax time.Duration
	FailAfter  time.Duration // continuous failure before OnFailing
	Now        func() time.Time

	// OnFailing is called once an outage has lasted FailAfter, and OnRecovered once it ends. Both run on the
	// forwarder's goroutine, so they should be quick.
	OnFailing   func(Outage)
	OnRecovered func(Outage)

	// Count, when set, is told how a pass went: ("sent", rows) for rows written to the collector (a row sent again
	// counts again) and ("failed", 1) for each failed pass.
	Count func(result string, n int)

	initOnce sync.Once
	nudge    chan struct{}
	passMu   sync.Mutex // one pass at a time, whether from Run or Drain
	w        *Writer
	cursor   int64
	loaded   bool

	mu       sync.Mutex
	st       Status
	attempts int
	notified bool
}

func (f *Forwarder) init() {
	f.initOnce.Do(func() {
		f.nudge = make(chan struct{}, 1)
		f.w = f.Writer
		if f.w == nil {
			f.w = NewWriter(f.Dest.Config)
		}
		f.st.State = StateIdle
	})
}

func (f *Forwarder) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

func (f *Forwarder) log() *slog.Logger {
	if f.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return f.Logger
}

func or[T comparable](v, d T) T {
	var zero T
	if v == zero {
		return d
	}
	return v
}

// Nudge asks Run to look for new rows now. It never blocks.
func (f *Forwarder) Nudge() {
	f.init()
	select {
	case f.nudge <- struct{}{}:
	default:
	}
}

// Status returns a snapshot.
func (f *Forwarder) Status() Status {
	f.init()
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.st
}

// Close closes the connection to the collector.
func (f *Forwarder) Close() error {
	f.init()
	return f.w.Close()
}

// Run sends until ctx ends. It looks for rows when nudged and every Poll, and after a failure waits BackoffMin,
// doubling up to BackoffMax, before trying again from the cursor.
func (f *Forwarder) Run(ctx context.Context) {
	f.init()
	defer f.Close()
	backoff := or(f.BackoffMin, DefaultBackoffMin)
	for {
		sent, err := f.pass(ctx, 0)
		if ctx.Err() != nil {
			return
		}
		wait := or(f.Poll, DefaultPoll)
		if err != nil {
			f.failed(err)
			wait = backoff
			backoff = min(backoff*2, or(f.BackoffMax, DefaultBackoffMax))
		} else {
			f.succeeded(sent)
			backoff = or(f.BackoffMin, DefaultBackoffMin)
		}
		// A nudge cuts a wait short only after a success. After a failure the collector is down, and the next try is
		// when the backoff says.
		t := time.NewTimer(wait)
		for waiting := true; waiting; {
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
				waiting = false
			case <-f.nudge:
				if err == nil {
					t.Stop()
					waiting = false
				}
			}
		}
	}
}

// Drain sends every row up to and including upTo, now, and returns the first error. It is for a destination about to
// be redirected or switched off, so what was waiting for it isn't lost. Stop Run first, or it competes for the pass.
func (f *Forwarder) Drain(ctx context.Context, upTo int64) error {
	f.init()
	_, err := f.pass(ctx, upTo)
	return err
}

// pass sends batches until it has caught up, or reached upTo when that is above 0. It returns the rows written.
func (f *Forwarder) pass(ctx context.Context, upTo int64) (int, error) {
	f.passMu.Lock()
	defer f.passMu.Unlock()
	if !f.loaded {
		c, err := f.Store.Cursor(ctx, f.Dest.ID)
		if err != nil {
			if errors.Is(err, ErrNoCursor) {
				return 0, &Error{CodeCursorAbsent, err}
			}
			return 0, &Error{CodeRead, err}
		}
		f.cursor, f.loaded = c, true
		f.mu.Lock()
		f.st.LastID = c
		f.mu.Unlock()
	}
	batch := or(f.BatchSize, DefaultBatch)
	total := 0
	for ctx.Err() == nil {
		rows, err := f.Store.NextRows(ctx, f.cursor, batch)
		if err != nil {
			return total, &Error{CodeRead, err}
		}
		more := len(rows) == batch
		if upTo > 0 {
			for i, r := range rows {
				if r.ID > upTo {
					rows, more = rows[:i], false
					break
				}
			}
		}
		if len(rows) == 0 {
			return total, nil
		}
		if gap := rows[0].ID - f.cursor - 1; gap > 0 {
			f.mu.Lock()
			f.st.SkippedPruned += gap
			f.mu.Unlock()
		}
		msgs := make([][]byte, len(rows))
		for i, r := range rows {
			msgs[i] = Format(RowFromAudit(r), f.Hostname, f.Dest.Config.Limit())
		}
		if err := f.w.Write(ctx, msgs); err != nil {
			return total, err
		}
		last := rows[len(rows)-1].ID
		now := f.now()
		f.mu.Lock()
		f.st.LastSentAt, f.st.Sent = now, f.st.Sent+int64(len(rows))
		f.mu.Unlock()
		if f.Count != nil {
			f.Count("sent", len(rows))
		}
		total += len(rows)
		// The rows are on the wire, so saving the cursor mustn't be undone by the caller stopping us: a cancel landing
		// here would leave the cursor behind rows the collector already has, and a drain after the stop sends them again.
		saveCtx, cancelSave := context.WithTimeout(context.WithoutCancel(ctx), saveTimeout)
		err = f.Store.SetCursor(saveCtx, f.Dest.ID, last, now)
		cancelSave()
		if err != nil {
			// The rows are written, but not recorded, so they are sent again: at least once.
			return total, &Error{CodeCursor, err}
		}
		f.cursor = last
		f.mu.Lock()
		f.st.LastID = last
		f.mu.Unlock()
		if !more {
			return total, nil
		}
	}
	return total, ctx.Err()
}

func (f *Forwarder) failed(err error) {
	code := CodeOf(err)
	now := f.now()
	f.mu.Lock()
	f.attempts++
	f.st.Failures++
	f.st.LastCode = code
	if f.st.State != StateFailing {
		f.st.State, f.st.FailingSince = StateFailing, now
	}
	o := Outage{Destination: f.Dest, Since: f.st.FailingSince, Code: code, Attempts: f.attempts, LastID: f.st.LastID}
	notify := !f.notified && now.Sub(f.st.FailingSince) >= or(f.FailAfter, DefaultFailAfter)
	if notify {
		f.notified = true
	}
	f.mu.Unlock()
	if f.Count != nil {
		f.Count("failed", 1)
	}
	f.log().Warn("log forwarding failed", "destination", f.Dest.Name, "code", code, "attempts", o.Attempts)
	if notify && f.OnFailing != nil {
		f.OnFailing(o)
	}
}

// succeeded ends an outage. A pass that found nothing to send doesn't show the collector is back, unless the outage
// was in reading or keeping the cursor, which it does show.
func (f *Forwarder) succeeded(sent int) {
	f.mu.Lock()
	wasFailing, code := f.st.State == StateFailing, f.st.LastCode
	if sent == 0 && wasFailing && !isLocal(code) {
		f.mu.Unlock()
		return
	}
	o := Outage{Destination: f.Dest, Since: f.st.FailingSince, Code: code, Attempts: f.attempts, LastID: f.st.LastID}
	notified := f.notified
	if wasFailing {
		f.st.FailingSince = time.Time{}
	}
	if f.st.LastSentAt.IsZero() {
		f.st.State = StateIdle
	} else {
		f.st.State = StateOK
	}
	f.attempts, f.notified = 0, false
	f.mu.Unlock()
	if wasFailing {
		f.log().Info("log forwarding recovered", "destination", f.Dest.Name)
		if notified && f.OnRecovered != nil {
			f.OnRecovered(o)
		}
	}
}

func isLocal(code string) bool {
	return code == CodeRead || code == CodeCursor || code == CodeCursorAbsent
}
