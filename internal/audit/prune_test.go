// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package audit

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// insertAt writes a login row at the given time.
func insertAt(t *testing.T, st *store.Store, at time.Time) {
	t.Helper()
	ctx := context.Background()
	if err := st.WithTx(ctx, func(q *db.Queries) error {
		_, err := Insert(ctx, q, Entry{At: at, Username: "alice", Action: ActionLogin})
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func rowsOf(t *testing.T, st *store.Store) []db.AuditLog {
	t.Helper()
	rows, err := st.Read().ListRecentAudit(context.Background(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestPrune(t *testing.T) {
	st := openStore(t)
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	insertAt(t, st, now.Add(-400*24*time.Hour))
	insertAt(t, st, now.Add(-366*24*time.Hour))
	insertAt(t, st, now.Add(-364*24*time.Hour))
	insertAt(t, st, now.Add(-time.Hour))
	l, buf := testLogger()
	days := 365
	p := &Pruner{Store: st, Audit: l, Retention: func() int { return days }, Now: func() time.Time { return now }}

	n, err := p.Prune(context.Background())
	if err != nil || n != 2 {
		t.Fatalf("Prune: %d, %v", n, err)
	}
	rows := rowsOf(t, st)
	if len(rows) != 3 {
		t.Fatalf("%d rows left, want 2 logins and the prune row", len(rows))
	}
	prune := rows[0]
	if prune.Action != ActionAuditPrune || prune.Username != SystemUser || prune.Target != "audit_log" ||
		prune.Result != ResultSuccess || prune.UserID.Valid {
		t.Errorf("prune row: %+v", prune)
	}
	var d map[string]any
	if err := json.Unmarshal([]byte(prune.Detail), &d); err != nil {
		t.Fatal(err)
	}
	if d["deleted"] != float64(2) || d["retention_days"] != float64(365) || d["before"] != "2025-10-25T12:00:00Z" {
		t.Errorf("prune detail: %v", d)
	}
	if !strings.Contains(buf.String(), "action=audit_prune") {
		t.Errorf("no AUDIT line: %q", buf.String())
	}

	// Nothing more to delete: no row and no line.
	buf.Reset()
	if n, err := p.Prune(context.Background()); err != nil || n != 0 {
		t.Fatalf("second Prune: %d, %v", n, err)
	}
	if len(rowsOf(t, st)) != 3 || buf.Len() != 0 {
		t.Errorf("an empty prune wrote something: %d rows, %q", len(rowsOf(t, st)), buf.String())
	}

	// A shorter retention takes the 364-day-old row, and keeps the hour-old login and the prune row just written.
	days = 30
	if n, err := p.Prune(context.Background()); err != nil || n != 1 {
		t.Fatalf("Prune at 30 days: %d, %v", n, err)
	}
	rows = rowsOf(t, st)
	if len(rows) != 3 || rows[0].Action != ActionAuditPrune || rows[1].Action != ActionAuditPrune || rows[2].Action != ActionLogin {
		t.Errorf("after the 30-day prune: %+v", rows)
	}
}

// Run prunes at startup, and once more after pokes, several pokes making one prune.
func TestPrunerRun(t *testing.T) {
	st := openStore(t)
	var calls atomic.Int32
	days := atomic.Int32{}
	days.Store(365)
	p := &Pruner{
		Store: st, Retention: func() int { calls.Add(1); return int(days.Load()) },
		Interval: time.Hour, Delay: 20 * time.Millisecond,
	}
	p.Poke() // before Run: must not block or be lost
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()

	waitFor(t, func() bool { return calls.Load() >= 2 }) // the startup prune, then the early poke
	insertAt(t, st, time.Now().Add(-100*24*time.Hour))
	days.Store(30)
	before := calls.Load()
	for range 5 {
		p.Poke()
	}
	waitFor(t, func() bool { return len(rowsOf(t, st)) == 1 && rowsOf(t, st)[0].Action == ActionAuditPrune })
	time.Sleep(60 * time.Millisecond)
	if got := calls.Load() - before; got != 1 {
		t.Errorf("five pokes made %d prunes, want 1", got)
	}
	cancel()
	<-done
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
