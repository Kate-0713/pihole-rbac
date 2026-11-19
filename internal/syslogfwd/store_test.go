// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package syslogfwd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
	"github.com/Kate-0713/pihole-rbac/internal/syslogfwd/syslogtest"
)

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), store.Options{DataDir: t.TempDir(), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// makeDestination adds a destination row and its cursor, as the service will, and returns its ID.
func makeDestination(t *testing.T, st *store.Store, cursor int64) int64 {
	t.Helper()
	ctx := context.Background()
	var id int64
	err := st.WithTx(ctx, func(q *db.Queries) error {
		var err error
		id, err = q.CreateLogDestination(ctx, db.CreateLogDestinationParams{Name: "test", Host: "127.0.0.1", Port: 6514, Transport: "tls",
			TlsMode: "verify", Enabled: true, CreatedAt: 1, UpdatedAt: 1})
		if err != nil {
			return err
		}
		return q.SetLogCursor(ctx, db.SetLogCursorParams{DestinationID: id, LastID: cursor, UpdatedAt: 1})
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func insert(t *testing.T, st *store.Store, e audit.Entry) int64 {
	t.Helper()
	ctx := context.Background()
	var id int64
	if err := st.WithTx(ctx, func(q *db.Queries) (err error) { id, err = audit.Insert(ctx, q, e); return }); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestDBStoreCursor(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	s := DBStore{S: st}
	if _, err := s.Cursor(ctx, 99); !errors.Is(err, ErrNoCursor) {
		t.Errorf("a destination with no cursor: %v", err)
	}
	id := makeDestination(t, st, 7)
	if got, err := s.Cursor(ctx, id); err != nil || got != 7 {
		t.Errorf("cursor %d, %v, want 7", got, err)
	}
	if err := s.SetCursor(ctx, id, 12, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Cursor(ctx, id); err != nil || got != 12 {
		t.Errorf("cursor %d, %v, want 12", got, err)
	}
	// A cursor can't be made for a destination that isn't there.
	if err := s.SetCursor(ctx, 99, 1, time.Now()); err == nil {
		t.Error("a cursor for no destination was saved")
	}
}

// Row IDs are given in commit order, and a reader sees a row once its transaction commits: reading from a cursor
// never skips a row that a later read would find. The forwarder's cursor depends on this.
func TestDBStoreRowsAppearInIDOrderWithNoGaps(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	s := DBStore{S: st}
	const writers, each = 4, 60

	var wg sync.WaitGroup
	for w := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range each {
				insert(t, st, audit.Entry{Username: fmt.Sprint("w", w), Action: audit.ActionLogin, Target: fmt.Sprint(i)})
			}
		}()
	}
	var cursor int64
	deadline := time.Now().Add(20 * time.Second)
	for cursor < writers*each {
		if time.Now().After(deadline) {
			t.Fatalf("read only %d of %d rows", cursor, writers*each)
		}
		rows, err := s.NextRows(ctx, cursor, 17)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			if r.ID != cursor+1 {
				t.Fatalf("read row %d after row %d: a row appeared late or was skipped", r.ID, cursor)
			}
			cursor = r.ID
		}
	}
	wg.Wait()
}

// The forwarder over the real database: a row written the way a request writes it, one written the way a command does
// (no nudge), one made with an API token, and one written after the retention deleted every row.
func TestForwarderOverTheDatabase(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	c := syslogtest.NewTLS(t)
	destID := makeDestination(t, st, 0)
	f := fast(&Forwarder{Dest: Destination{ID: destID, Name: "db", Config: cfgFor(c, TransportTLS)}, Store: DBStore{S: st}})
	logger := audit.NewLogger(io.Discard)
	logger.SetSink(func(audit.Entry) { f.Nudge() })
	run(t, f)

	// As a request does: the row in its transaction, then the AUDIT line and the sink.
	e := audit.Entry{At: time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC), Username: "alice", Action: audit.ActionDomainAdd, Target: "i-1",
		Detail: map[string]any{"domain": "a.example"}, IP: "10.0.0.5"}
	if err := logger.Record(ctx, st, e); err != nil {
		t.Fatal(err)
	}
	m := c.Wait(1, 3*time.Second)[0]
	p := split(t, []byte(m))
	if p.msgid != "domain_add" || p.ts != "2026-11-18T12:00:00.000Z" || !strings.Contains(p.text, `"domain":"a.example"`) || !strings.Contains(p.text, `"id":1`) {
		t.Errorf("a row written by a request: %q", m)
	}

	// As a command does: written with no logger, so nothing is nudged. A request made with a token carries via_token,
	// which Insert adds and the AUDIT line's entry doesn't have.
	tokCtx := audit.WithToken(ctx, "home assistant", "abcdefghijklmnop")
	if err := st.WithTx(tokCtx, func(q *db.Queries) error {
		_, err := audit.Insert(tokCtx, q, audit.Entry{Username: "ha", Action: audit.ActionBlockingSet, Target: "i-1"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	insert(t, st, audit.Entry{Username: "(cli)", Action: audit.ActionRotateKey, Target: "secrets"})
	got := c.Wait(3, 3*time.Second)
	if !strings.Contains(got[1], `"via_token":"home assistant"`) || !strings.Contains(got[1], `"token_id":"abcdefghijklmnop"`) {
		t.Errorf("a row made with a token: %q", got[1])
	}
	if p := split(t, []byte(got[2])); p.msgid != "rotate_key" {
		t.Errorf("a row written by a command wasn't forwarded: %q", got[2])
	}
	waitFor(t, "the cursor", func() bool {
		cur, err := DBStore{S: st}.Cursor(ctx, destID)
		return err == nil && cur == 3
	})

	// The retention deletes every row, then writes its own. The new row's ID is above the cursor, so it is sent.
	if err := st.WithTx(ctx, func(q *db.Queries) error {
		_, err := q.DeleteAuditBefore(ctx, time.Now().Add(time.Hour).UnixMilli())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if n, err := st.Read().CountAuditAfter(ctx, 0); err != nil || n != 0 {
		t.Fatalf("rows left after deleting them all: %d, %v", n, err)
	}
	insert(t, st, audit.Entry{Username: audit.SystemUser, Action: audit.ActionAuditPrune, Target: "audit_log"})
	all := c.Wait(4, 3*time.Second)
	if p := split(t, []byte(all[3])); p.msgid != "audit_prune" {
		t.Errorf("the row after a full prune: %q", all[3])
	}
	var j struct{ ID int64 }
	if err := json.Unmarshal([]byte(split(t, []byte(all[3])).text), &j); err != nil || j.ID != 4 {
		t.Errorf("the row after a full prune has id %d (%v), want 4: an ID was used twice", j.ID, err)
	}
	if ids := ids(t, all); !slices.Equal(ids, []int64{1, 2, 3, 4}) {
		t.Errorf("ids %v", ids)
	}
}
