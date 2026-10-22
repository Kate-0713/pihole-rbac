// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// testLogger returns a Logger without the date prefix, so lines can be compared exactly.
func testLogger() (*Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return &Logger{l: log.New(&buf, "", 0)}, &buf
}

func TestLogFormat(t *testing.T) {
	l, buf := testLogger()
	l.Log(Entry{Username: "alice", Action: "toggle_blocking", Target: "disable"})
	want := "AUDIT user=\"alice\" action=toggle_blocking target=\"disable\" result=success\n"
	if got := buf.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}

	buf.Reset()
	l.Log(Entry{Username: "bob", Action: ActionLogin, Err: errors.New("invalid username or password")})
	want = "AUDIT user=\"bob\" action=login target=\"\" result=failure error=\"invalid username or password\"\n"
	if got := buf.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// A login username comes straight from the request, so it can contain newlines. It must never be able to start a
// second, forged AUDIT line.
func TestLogCannotBeForged(t *testing.T) {
	forged := "mallory\n2026/09/24 12:00:00 AUDIT user=\"admin\" action=delete_user target=\"bob\" result=success"

	cases := map[string]Entry{
		"username": {Username: forged, Action: ActionLogin},
		"target":   {Username: "mallory", Action: ActionLogin, Target: forged},
		// Errors can embed user input too, e.g. LDAP "user %s is not a member".
		"error": {Username: "mallory", Action: ActionLogin, Err: errors.New(forged)},
	}
	for name, e := range cases {
		t.Run(name, func(t *testing.T) {
			l, buf := testLogger()
			l.Log(e)
			got := buf.String()
			if n := strings.Count(got, "\n"); n != 1 {
				t.Errorf("expected exactly 1 log line, got %d: %q", n, got)
			}
			if strings.Contains(got, "\nAUDIT") || strings.Contains(got, "\n2026") {
				t.Errorf("forged line present: %q", got)
			}
		})
	}
}

func TestNewLoggerPrefixesUTCTime(t *testing.T) {
	var buf bytes.Buffer
	NewLogger(&buf).Log(Entry{Username: "a", Action: ActionLogout})
	if !strings.Contains(buf.String(), " AUDIT user=\"a\" action=logout") {
		t.Fatalf("line = %q", buf.String())
	}
	if _, err := time.Parse("2006/01/02 15:04:05", buf.String()[:19]); err != nil {
		t.Fatalf("line doesn't start with a timestamp: %q", buf.String())
	}
}

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), store.Options{
		DataDir: t.TempDir(),
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestInsert(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	at := time.Date(2026, 10, 23, 9, 30, 0, 0, time.UTC)

	tests := []struct {
		name       string
		entry      Entry
		wantResult string
		wantDetail map[string]any
	}{
		{
			name:       "success with detail",
			entry:      Entry{At: at, Username: "alice", Action: ActionLogin, IP: "10.0.0.1", Detail: map[string]any{"method": "local"}},
			wantResult: ResultSuccess,
			wantDetail: map[string]any{"method": "local"},
		},
		{
			name:       "failure records the error",
			entry:      Entry{At: at, Username: "nobody", Action: ActionLogin, Err: errors.New("invalid username or password")},
			wantResult: ResultFailure,
			wantDetail: map[string]any{"error": "invalid username or password"},
		},
		{
			name:       "no detail is an empty object",
			entry:      Entry{At: at, Username: "alice", Action: ActionLogout},
			wantResult: ResultSuccess,
			wantDetail: map[string]any{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var id int64
			err := st.WithTx(ctx, func(q *db.Queries) error {
				var err error
				id, err = Insert(ctx, q, tt.entry)
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			row, err := st.Read().GetAudit(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			if row.Result != tt.wantResult || row.Username != tt.entry.Username || row.Action != tt.entry.Action ||
				row.Ip != tt.entry.IP || store.FromMillis(row.At) != at || row.UserID.Valid || row.InstanceID.Valid {
				t.Fatalf("row = %+v", row)
			}
			var detail map[string]any
			if err := json.Unmarshal([]byte(row.Detail), &detail); err != nil {
				t.Fatal(err)
			}
			if len(detail) != len(tt.wantDetail) {
				t.Fatalf("detail = %v, want %v", detail, tt.wantDetail)
			}
			for k, v := range tt.wantDetail {
				if detail[k] != v {
					t.Fatalf("detail = %v, want %v", detail, tt.wantDetail)
				}
			}
		})
	}
}

func TestInsertRollsBackWithItsTransaction(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	var id int64
	boom := errors.New("change failed")
	err := st.WithTx(ctx, func(q *db.Queries) error {
		var err error
		if id, err = Insert(ctx, q, Entry{Username: "alice", Action: ActionLogin}); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if _, err := st.Read().GetAudit(ctx, id); err == nil {
		t.Fatal("audit row survived the rollback")
	}
}

func TestRecord(t *testing.T) {
	st := openStore(t)
	l, buf := testLogger()
	if err := l.Record(context.Background(), st, Entry{Username: "bob", Action: ActionLogin, Err: errors.New("nope")}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `user="bob" action=login`) {
		t.Fatalf("no AUDIT line: %q", buf.String())
	}
	row, err := st.Read().GetAudit(context.Background(), 1)
	if err != nil || row.Result != ResultFailure {
		t.Fatalf("row = %+v, %v", row, err)
	}
}
