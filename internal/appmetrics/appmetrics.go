// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package appmetrics registers the metrics that are read when Prometheus scrapes, as opposed to the counters that code
// increments where an event happens: instance health, drift, sessions, queues, forwarding lag, client reset runs and
// whether an update is available.
//
// A series that would be a guess is left out rather than written as zero: an instance not yet called, a group not yet
// checked, an update check that is off. Anything that needs the database is read at most once per CacheFor, with a
// time limit, so a scrape every few seconds can't load it and a slow database can't hold a scrape up; a read that
// fails leaves its own series out and is reported through the registry's ErrorFunc.
package appmetrics

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/instances"
	"github.com/Kate-0713/pihole-rbac/internal/logdestinations"
	"github.com/Kate-0713/pihole-rbac/internal/metrics"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// Defaults for Sources.
const (
	DefaultCacheFor = 10 * time.Second
	DefaultTimeout  = 5 * time.Second
)

// Sources is where the collectors read from. A nil source leaves out the series that depend on it.
type Sources struct {
	Pool *instances.Pool
	// Report is a group's latest drift report, if it has been checked (Drift.Report).
	Report func(groupID int64) (instances.Report, bool)
	// Groups lists the instance groups, for the mirrored ones' drift reports.
	Groups func(ctx context.Context) ([]instances.Group, error)
	// Destinations lists the log destinations with their status.
	Destinations func(ctx context.Context) ([]logdestinations.Destination, error)
	// QueueLength is how many notifications are waiting.
	QueueLength func() int
	// Update says whether the update check is on (known) and whether a newer release is known (available).
	Update func(ctx context.Context) (known, available bool, err error)
	Store  *store.Store
	// Lifetimes gives the session idle timeout, which decides which sessions are live.
	Lifetimes func() (lifetime, idle time.Duration)

	Now      func() time.Time
	CacheFor time.Duration
	Timeout  time.Duration
}

// cached holds the result of a read for a while, errors included, so a failing database is asked once per interval
// too.
type cached[T any] struct {
	mu       sync.Mutex
	ttl, max time.Duration
	now      func() time.Time
	at       time.Time
	v        T
	err      error
}

func (c *cached[T]) get(load func(ctx context.Context) (T, error)) (T, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now := c.now(); c.at.IsZero() || now.Sub(c.at) >= c.ttl {
		ctx, cancel := context.WithTimeout(context.Background(), c.max)
		c.v, c.err = load(ctx)
		cancel()
		c.at = c.now()
	}
	return c.v, c.err
}

func newCached[T any](s Sources) *cached[T] {
	return &cached[T]{ttl: s.CacheFor, max: s.Timeout, now: s.Now}
}

func gauge1(v float64, labels ...string) metrics.Sample {
	s := metrics.Sample{Value: v}
	for i := 0; i+1 < len(labels); i += 2 {
		s.Labels = append(s.Labels, metrics.Label{Name: labels[i], Value: labels[i+1]})
	}
	return s
}

// unix is t in seconds since the epoch. Seconds and nanoseconds are added apart: UnixNano is too big for a float64.
func unix(t time.Time) float64 { return float64(t.Unix()) + float64(t.Nanosecond())/1e9 }

// Register adds the collectors to r. A nil registry does nothing.
func Register(r *metrics.Registry, s Sources) {
	if r == nil {
		return
	}
	if s.Now == nil {
		s.Now = time.Now
	}
	if s.CacheFor <= 0 {
		s.CacheFor = DefaultCacheFor
	}
	if s.Timeout <= 0 {
		s.Timeout = DefaultTimeout
	}
	if s.Pool != nil {
		r.Collect(s.instances)
	}
	if s.Report != nil && s.Groups != nil {
		groups := newCached[[]instances.Group](s)
		r.Collect(func(w *metrics.Writer) error { return s.drift(w, groups) })
	}
	if s.Store != nil && s.Lifetimes != nil {
		sessions := newCached[int64](s)
		r.Collect(func(w *metrics.Writer) error { return s.sessions(w, sessions) })
	}
	if s.QueueLength != nil {
		r.Collect(func(w *metrics.Writer) error {
			return w.Gauge("pihole_rbac_notification_queue_length", "Notification messages waiting to be sent.",
				gauge1(float64(s.QueueLength())))
		})
	}
	if s.Destinations != nil {
		dests := newCached[[]logdestinations.Destination](s)
		r.Collect(func(w *metrics.Writer) error { return s.forwarding(w, dests) })
	}
	if s.Store != nil {
		runs := newCached[[]db.ListLastClientResetRunsRow](s)
		r.Collect(func(w *metrics.Writer) error { return s.clientReset(w, runs) })
	}
	if s.Update != nil {
		type answer struct{ known, available bool }
		upd := newCached[answer](s)
		r.Collect(func(w *metrics.Writer) error {
			a, err := upd.get(func(ctx context.Context) (answer, error) {
				k, av, err := s.Update(ctx)
				return answer{k, av}, err
			})
			if err != nil {
				return fmt.Errorf("update status: %w", err)
			}
			if !a.known {
				return nil
			}
			v := 0.0
			if a.available {
				v = 1
			}
			return w.Gauge("pihole_rbac_update_available",
				"1 when a release newer than the running version is known, else 0. Absent while the update check is off or has found nothing.",
				gauge1(v))
		})
	}
}

// instances: memory only, so it isn't cached.
func (s Sources) instances(w *metrics.Writer) error {
	var up, last []metrics.Sample
	for _, m := range s.Pool.States() {
		switch m.Health.State {
		case instances.StateUp:
			up = append(up, gauge1(1, "instance", m.Name))
		case instances.StateDown:
			up = append(up, gauge1(0, "instance", m.Name))
		}
		if !m.Health.LastSuccess.IsZero() {
			last = append(last, gauge1(unix(m.Health.LastSuccess), "instance", m.Name))
		}
	}
	if err := w.Gauge("pihole_rbac_instance_up",
		"1 when the instance's Pi-hole answered its last call, 0 when it was unreachable, refused the password or couldn't be set up. No series until the instance has been called.", up...); err != nil {
		return err
	}
	return w.Gauge("pihole_rbac_instance_last_success_timestamp_seconds",
		"When the instance last answered a call, in seconds since the Unix epoch. No series before its first success.", last...)
}

func (s Sources) drift(w *metrics.Writer, groups *cached[[]instances.Group]) error {
	gs, err := groups.get(s.Groups)
	if err != nil {
		return fmt.Errorf("groups: %w", err)
	}
	var items, checked []metrics.Sample
	for _, g := range gs {
		if g.Mode != rbac.Mirrored {
			continue
		}
		rep, ok := s.Report(g.ID)
		if !ok {
			continue // not checked yet
		}
		checked = append(checked, gauge1(unix(rep.CheckedAt), "group", g.Name))
		if !rep.PrimaryOK {
			continue // nothing was compared, so zero differences would be a guess
		}
		for _, t := range []struct {
			name string
			n    int
		}{
			{"domains", len(rep.Domains)}, {"clients", len(rep.Clients)}, {"groups", len(rep.Groups)},
			{"lists", len(rep.Lists)}, {"local_dns", len(rep.LocalDNS)},
		} {
			items = append(items, gauge1(float64(t.n), "group", g.Name, "type", t.name))
		}
	}
	if err := w.Gauge("pihole_rbac_group_drift_items",
		"Differences between a mirrored group's members and its primary, by type, from the last drift check. No series until the group has been checked, or while its primary can't be read.", items...); err != nil {
		return err
	}
	return w.Gauge("pihole_rbac_group_drift_last_check_timestamp_seconds",
		"When the mirrored group's drift was last checked, in seconds since the Unix epoch.", checked...)
}

func (s Sources) sessions(w *metrics.Writer, c *cached[int64]) error {
	n, err := c.get(func(ctx context.Context) (int64, error) {
		_, idle := s.Lifetimes()
		now := s.Now()
		return s.Store.Read().CountLiveSessions(ctx, db.CountLiveSessionsParams{
			Now: store.Millis(now), IdleCutoff: store.Millis(now.Add(-idle)),
		})
	})
	if err != nil {
		return fmt.Errorf("sessions: %w", err)
	}
	return w.Gauge("pihole_rbac_sessions_active", "Sessions that haven't expired or gone idle.", gauge1(float64(n)))
}

func (s Sources) forwarding(w *metrics.Writer, c *cached[[]logdestinations.Destination]) error {
	ds, err := c.get(s.Destinations)
	if err != nil {
		return fmt.Errorf("log destinations: %w", err)
	}
	var behind []metrics.Sample
	for _, d := range ds {
		if d.Enabled { // a disabled destination falls further behind for ever, which says nothing
			behind = append(behind, gauge1(float64(d.Status.Behind), "destination", d.Name))
		}
	}
	return w.Gauge("pihole_rbac_log_forward_behind",
		"Audit rows an enabled log destination hasn't been sent yet.", behind...)
}

func (s Sources) clientReset(w *metrics.Writer, c *cached[[]db.ListLastClientResetRunsRow]) error {
	rows, err := c.get(func(ctx context.Context) ([]db.ListLastClientResetRunsRow, error) {
		return s.Store.Read().ListLastClientResetRuns(ctx)
	})
	if err != nil {
		return fmt.Errorf("client reset runs: %w", err)
	}
	var finished, ok []metrics.Sample
	for _, r := range rows {
		typ := "instance"
		if len(r.Target) > 0 && r.Target[0] == 'g' {
			typ = "group"
		}
		if !r.FinishedAt.Valid {
			continue
		}
		finished = append(finished, gauge1(unix(store.FromMillis(r.FinishedAt.Int64)), "target_type", typ, "target", r.Name))
		v := 0.0
		if r.Status == "ok" {
			v = 1
		}
		ok = append(ok, gauge1(v, "target_type", typ, "target", r.Name))
	}
	if err := w.Gauge("pihole_rbac_client_reset_last_run_timestamp_seconds",
		"When the target's last client reset run finished, in seconds since the Unix epoch. No series until it has one.", finished...); err != nil {
		return err
	}
	return w.Gauge("pihole_rbac_client_reset_last_run_ok",
		"1 when the target's last client reset run was ok, 0 when it was partial or failed.", ok...)
}
