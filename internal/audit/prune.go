// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package audit

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// Pruner deletes audit rows, and finished client reset runs, older than the retention: once at startup, then daily,
// and soon after Poke (called when the retention setting changes). A prune that deletes rows records it as
// audit_prune in the same transaction; one that deletes nothing writes nothing, so the log doesn't gain a row a day.
type Pruner struct {
	Store     *store.Store
	Audit     *Logger
	Retention func() int // days to keep
	Logger    *slog.Logger
	Interval  time.Duration    // between scheduled prunes; default a day
	Delay     time.Duration    // from a Poke to the prune; default 10 seconds, so several saves make one prune
	Now       func() time.Time // for tests

	once sync.Once
	poke chan struct{}
}

func (p *Pruner) init() {
	p.once.Do(func() { p.poke = make(chan struct{}, 1) })
}

// Poke asks for a prune soon. It never blocks, and is safe to call before Run.
func (p *Pruner) Poke() {
	p.init()
	select {
	case p.poke <- struct{}{}:
	default:
	}
}

// Run prunes at startup, every Interval and Delay after a Poke, until ctx ends.
func (p *Pruner) Run(ctx context.Context) {
	p.init()
	interval, delay := p.Interval, p.Delay
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	if delay <= 0 {
		delay = 10 * time.Second
	}
	p.runOnce(ctx)
	tick := time.NewTicker(interval)
	defer tick.Stop()
	var soon <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			p.runOnce(ctx)
		case <-p.poke:
			if soon == nil {
				soon = time.After(delay)
			}
		case <-soon:
			soon = nil
			p.runOnce(ctx)
		}
	}
}

func (p *Pruner) runOnce(ctx context.Context) {
	n, err := p.Prune(ctx)
	if err != nil {
		if ctx.Err() == nil && p.Logger != nil {
			p.Logger.Warn("pruning the audit log failed", "err", err)
		}
		return
	}
	if n > 0 && p.Logger != nil {
		p.Logger.Info("pruned the audit log", "deleted", n)
	}
}

// Prune deletes the audit rows and finished client reset runs older than the retention now, and returns how many
// audit rows it deleted.
func (p *Pruner) Prune(ctx context.Context) (int64, error) {
	now := time.Now()
	if p.Now != nil {
		now = p.Now()
	}
	days := p.Retention()
	cutoff := now.Add(-time.Duration(days) * 24 * time.Hour)
	var n, runs int64
	entry := Entry{At: now, Username: SystemUser, Action: ActionAuditPrune, Target: "audit_log"}
	err := p.Store.WithTx(ctx, func(q *db.Queries) error {
		var err error
		if n, err = q.DeleteAuditBefore(ctx, store.Millis(cutoff)); err != nil {
			return err
		}
		if runs, err = q.DeleteClientResetRunsBefore(ctx, store.Millis(cutoff)); err != nil {
			return err
		}
		if n == 0 && runs == 0 {
			return nil
		}
		entry.Detail = map[string]any{
			"deleted": n, "client_reset_runs_deleted": runs, "before": cutoff.UTC().Format(time.RFC3339),
			"retention_days": days,
		}
		_, err = Insert(ctx, q, entry)
		return err
	})
	if err != nil {
		return 0, err
	}
	if n+runs > 0 && p.Audit != nil {
		p.Audit.Log(entry)
	}
	return n, nil
}
