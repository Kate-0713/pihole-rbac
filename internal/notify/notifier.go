// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package notify sends short messages to Discord webhooks and Matrix rooms when audited events happen.
//
// Every audit entry reaches Notifier.Notify once its transaction has committed (audit.Logger's sink). The notifier
// looks up which channels want that event and queues a message for each. Sending is asynchronous, through a bounded
// in-memory queue, so a slow or unreachable destination never delays a request: a message gets one attempt and up to
// three retries, about 1, 5 and 30 seconds apart (longer if Discord asks for it), and a full queue drops new messages.
// Messages still queued at shutdown are lost.
//
// Guard messages (a channel's old destination told that it was changed) go through the same queue, but when one
// still fails after its retries, Failed is called so the failure can be audited.
package notify

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
)

// Route is one enabled channel and the events it receives.
type Route struct {
	Destination Destination
	Events      map[string]bool
}

// Job is one message for one destination.
type Job struct {
	Destination Destination
	Message     *Message
	Event       string // what it's about, for logs: an event name, or "test" or "guard"
	Guard       bool   // a final failure is passed to Notifier.Failed
	attempt     int
}

// Defaults.
const (
	DefaultQueueSize = 256
	DefaultWorkers   = 2
)

// DefaultDelays are the waits before each retry.
var DefaultDelays = []time.Duration{time.Second, 5 * time.Second, 30 * time.Second}

// Notifier routes audit entries to channels and sends the messages. Its fields are set before Run and not changed
// after; the routes change with SetRoutes.
type Notifier struct {
	Sender    *Sender
	Logger    *slog.Logger
	QueueSize int
	Workers   int
	Delays    []time.Duration
	// Failed is called, from a worker, for a guard message that gave up: refused, or still failing after its retries.
	Failed func(Job, Result)

	once    sync.Once
	queue   chan Job
	routes  atomic.Pointer[[]Route]
	stopped atomic.Bool
	dropped atomic.Int64
}

func (n *Notifier) init() {
	n.once.Do(func() {
		size := n.QueueSize
		if size <= 0 {
			size = DefaultQueueSize
		}
		n.queue = make(chan Job, size)
		if n.Sender == nil {
			n.Sender = &Sender{}
		}
		if n.Delays == nil {
			n.Delays = DefaultDelays
		}
	})
}

// SetRoutes replaces the channels and the events each receives. Disabled channels aren't routes.
func (n *Notifier) SetRoutes(routes []Route) {
	r := append([]Route(nil), routes...)
	n.routes.Store(&r)
}

// Notify queues a message for every channel that wants the entry's event, and a protected-group alert for every
// channel that wants those. It's audit.Logger's sink, so it is called after the entry's transaction has committed,
// and it never blocks.
func (n *Notifier) Notify(e audit.Entry) {
	rp := n.routes.Load()
	if rp == nil {
		return
	}
	protected := ProtectedGroups(e)
	for _, r := range *rp {
		if r.Events[e.Action] {
			n.Enqueue(Job{Destination: r.Destination, Message: ForEntry(e), Event: e.Action})
		}
		if len(protected) > 0 && r.Events[EventProtectedGroupAdd] {
			n.Enqueue(Job{Destination: r.Destination, Message: ForProtectedGroup(e, protected), Event: EventProtectedGroupAdd})
		}
	}
}

// Enqueue queues a job without blocking. It reports false when the queue is full or the notifier has stopped; the
// job is then dropped and logged.
func (n *Notifier) Enqueue(j Job) bool {
	n.init()
	if !n.stopped.Load() {
		select {
		case n.queue <- j:
			return true
		default:
		}
	}
	// Log the first drop and every hundredth after it, so a storm of events can't flood the log as well.
	if d := n.dropped.Add(1); d == 1 || d%100 == 0 {
		n.log().Warn("notification dropped: the queue is full", "channel", j.Destination.Name, "event", j.Event, "dropped", d)
	}
	if j.Guard && n.Failed != nil {
		n.Failed(j, Result{Err: errQueueFull})
	}
	return false
}

type queueError string

func (e queueError) Error() string { return string(e) }

const errQueueFull = queueError("the notification queue is full")

// Send makes one attempt now and waits for it, for Send test. It doesn't use the queue or retry.
func (n *Notifier) Send(ctx context.Context, d Destination, m *Message) Result {
	n.init()
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	return n.Sender.Send(ctx, d, m)
}

// Run sends queued messages until ctx ends.
func (n *Notifier) Run(ctx context.Context) {
	n.init()
	workers := n.Workers
	if workers <= 0 {
		workers = DefaultWorkers
	}
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for {
				select {
				case <-ctx.Done():
					return
				case j := <-n.queue:
					n.attempt(ctx, j)
				}
			}
		})
	}
	<-ctx.Done()
	n.stopped.Store(true)
	wg.Wait()
}

func (n *Notifier) attempt(ctx context.Context, j Job) {
	sctx, cancel := context.WithTimeout(ctx, sendTimeout)
	r := n.Sender.Send(sctx, j.Destination, j.Message)
	cancel()
	if r.OK() {
		if j.attempt > 0 {
			n.log().Info("notification sent after retrying", "channel", j.Destination.Name, "event", j.Event, "attempts", j.attempt+1)
		}
		return
	}
	if ctx.Err() != nil {
		return // shutting down: the message is lost, as queued ones are
	}
	if r.Retryable() && j.attempt < len(n.Delays) {
		wait := max(n.Delays[j.attempt], r.RetryAfter)
		n.log().Debug("notification failed; retrying", "channel", j.Destination.Name, "event", j.Event,
			"attempt", j.attempt+1, "in", wait, "err", r.Err)
		j.attempt++
		time.AfterFunc(wait, func() {
			if !n.stopped.Load() {
				n.Enqueue(j)
			}
		})
		return
	}
	n.log().Warn("notification failed", "channel", j.Destination.Name, "kind", j.Destination.Kind, "event", j.Event,
		"attempts", j.attempt+1, "status", r.Status, "err", r.Err)
	if j.Guard && n.Failed != nil {
		n.Failed(j, r)
	}
}

func (n *Notifier) log() *slog.Logger {
	if n.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return n.Logger
}
