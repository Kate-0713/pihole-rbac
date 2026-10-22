// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package audit records security-relevant events: logins, logouts, and every write to Pi-hole, users, roles or
// settings. Read-only actions aren't audited.
//
// Each event is recorded twice. Insert writes the audit_log row, inside the same transaction as the change it
// describes, so the change and its record commit or roll back together. Log then writes the v1-style AUDIT line to
// the log stream once the transaction has committed, so the line can be grepped or routed separately:
//
//	journalctl -u pihole-rbac | grep AUDIT
//
// Secret values never belong in an Entry: not in Target, not in Detail, not in the error.
package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// Result values stored in audit_log.result.
const (
	ResultSuccess = "success"
	ResultFailure = "failure"
)

// Actions. They are constants from our own code, which is why the AUDIT line can write them unquoted.
const (
	ActionLogin  = "login"
	ActionLogout = "logout"
)

// Entry is one audit event.
type Entry struct {
	At           time.Time // zero means now
	UserID       int64     // 0 when there is no user row (a failed login with an unknown username)
	Username     string    // the acting user, or the username typed into a failed login
	Action       string
	Target       string // what the action was performed against, or ""
	InstanceID   int64  // 0 when the action isn't about one Pi-hole instance
	InstanceName string
	Err          error          // nil for success; its text is recorded as detail.error
	Detail       map[string]any // extra JSON detail; never secret values
	IP           string
}

// Result returns ResultSuccess or ResultFailure.
func (e Entry) Result() string {
	if e.Err != nil {
		return ResultFailure
	}
	return ResultSuccess
}

func (e Entry) detailJSON() (string, error) {
	d := make(map[string]any, len(e.Detail)+1)
	for k, v := range e.Detail {
		d[k] = v
	}
	if e.Err != nil {
		d["error"] = e.Err.Error()
	}
	b, err := json.Marshal(d)
	if err != nil {
		return "", fmt.Errorf("audit: detail: %w", err)
	}
	return string(b), nil
}

// Insert writes e to audit_log through q, normally the transaction that made the change.
func Insert(ctx context.Context, q *db.Queries, e Entry) (int64, error) {
	if e.At.IsZero() {
		e.At = time.Now()
	}
	detail, err := e.detailJSON()
	if err != nil {
		return 0, err
	}
	return q.InsertAudit(ctx, db.InsertAuditParams{
		At:           store.Millis(e.At),
		UserID:       sql.NullInt64{Int64: e.UserID, Valid: e.UserID != 0},
		Username:     e.Username,
		Action:       e.Action,
		Target:       e.Target,
		InstanceID:   sql.NullInt64{Int64: e.InstanceID, Valid: e.InstanceID != 0},
		InstanceName: e.InstanceName,
		Result:       e.Result(),
		Detail:       detail,
		Ip:           e.IP,
	})
}

// Logger writes AUDIT lines.
type Logger struct {
	l *log.Logger
}

// NewLogger writes AUDIT lines to w, each prefixed with the UTC date and time.
func NewLogger(w io.Writer) *Logger {
	return &Logger{l: log.New(w, "", log.LstdFlags|log.LUTC)}
}

// Log writes one AUDIT line for e. Call it after the transaction that inserted e has committed.
//
// username, target and the error text are written with %q: any of them can contain attacker-controlled input (a
// login username, or an error that echoes it), and a raw newline would let that input forge extra AUDIT lines.
// action is always a constant from our own code, so it stays bare.
func (l *Logger) Log(e Entry) {
	if e.Err != nil {
		l.l.Printf("AUDIT user=%q action=%s target=%q result=failure error=%q", e.Username, e.Action, e.Target, e.Err.Error())
	} else {
		l.l.Printf("AUDIT user=%q action=%s target=%q result=success", e.Username, e.Action, e.Target)
	}
}

// Record inserts e in its own transaction and logs it. It's for events that change nothing else in the database,
// such as a failed login.
func (l *Logger) Record(ctx context.Context, st *store.Store, e Entry) error {
	if err := st.WithTx(ctx, func(q *db.Queries) error {
		_, err := Insert(ctx, q, e)
		return err
	}); err != nil {
		return err
	}
	l.Log(e)
	return nil
}
