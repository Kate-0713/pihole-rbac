// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package logdestinations manages the syslog destinations the audit log is forwarded to, and runs one
// syslogfwd.Forwarder for each enabled one.
//
// Every change runs in one transaction that checks logging.manage, applies it and writes its audit row. A change
// that would send the log somewhere else, or stop sending it (a new host, port, transport or TLS setting, or the
// destination disabled or deleted), is guarded: once it has committed, the old destination is sent everything it
// hasn't had up to and including the change's own audit row, from its old settings. So the log can't be quietly
// redirected without the place that was receiving it hearing about it. The changed destination then starts at that
// row, so the new place gets what happens after the change.
package logdestinations

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/metrics"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
	"github.com/Kate-0713/pihole-rbac/internal/syslogfwd"
)

// Limits.
const (
	maxName         = 80
	maxCAFile       = 4096
	MaxDestinations = 10
	// DrainTimeout is how long a redirected destination's old place is tried for.
	DrainTimeout = 10 * time.Second
)

// actionTest only appears as the attempted action of a permission_denied row: a test changes nothing.
const actionTest = "logdest_test"

// State is what the page shows for a destination.
type State string

const (
	StateOK       State = "ok"
	StateFailing  State = "failing"
	StateDisabled State = "disabled"
	StateIdle     State = "idle" // enabled, nothing sent since the app started
)

// Delivery says how sure a destination's messages are to arrive.
const (
	DeliveryAtLeastOnce = "at_least_once"
	DeliveryBestEffort  = "best_effort"
)

// Status is how a destination is doing. It lives in memory: a restart starts it again at idle.
type Status struct {
	State         State
	LastSentAt    time.Time
	LastError     string // a code, never text from the collector
	FailingSince  time.Time
	Behind        int64 // audit rows after the cursor, not yet sent
	SkippedPruned int64
	Delivery      string
}

// Destination is a saved destination with its status.
type Destination struct {
	ID        int64
	Name      string
	Host      string
	Port      int
	Transport string
	TLSMode   string
	CAFile    string
	Enabled   bool
	CreatedAt time.Time
	CreatedBy string
	UpdatedAt time.Time
	UpdatedBy string
	Status    Status
}

// Input is what a create or change asks for.
type Input struct {
	Name      string
	Host      string
	Port      int
	Transport string // "" means tls
	TLSMode   string // "" means verify
	CAFile    string
	Enabled   bool
	// Confirm goes ahead with a plain tcp or udp transport, which sends the log unencrypted.
	Confirm bool
}

// Service makes every change to log destinations and keeps their forwarders in step.
type Service struct {
	Store  *store.Store
	Audit  *audit.Logger
	Logger *slog.Logger
	Now    func() time.Time
	// Hostname is the HOSTNAME in each message; "" uses the machine's.
	Hostname string
	// Tune adjusts each forwarder before it starts, for tests (short waits).
	Tune func(*syslogfwd.Forwarder)
	// DrainTimeout overrides the package's, for tests.
	DrainTimeout time.Duration
	// Metrics receives pihole_rbac_log_forward_total{destination,result}. nil counts nothing.
	Metrics *metrics.Registry

	mu sync.Mutex // one change at a time, from reading the destination to starting its forwarder

	rmu       sync.Mutex
	root      context.Context
	running   map[int64]*runner
	forwarded *metrics.Counter // nil without Metrics
	names     map[int64]string // each started destination's current name, for the metric label
	wg        sync.WaitGroup
}

type runner struct {
	f      *syslogfwd.Forwarder
	cfg    syslogfwd.Config
	cancel context.CancelFunc
	done   chan struct{}
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) log() *slog.Logger {
	if s.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return s.Logger
}

func (s *Service) hostname() string {
	if s.Hostname != "" {
		return s.Hostname
	}
	return syslogfwd.Hostname()
}

func validation(field, format string, args ...any) *rbac.Error {
	return &rbac.Error{Code: rbac.CodeValidation, Message: fmt.Sprintf(format, args...), Details: map[string]any{"field": field}}
}

func conflict(field, format string, args ...any) *rbac.Error {
	return &rbac.Error{Code: rbac.CodeConflict, Message: fmt.Sprintf(format, args...), Details: map[string]any{"field": field}}
}

func notFound(id int64) *rbac.Error {
	return &rbac.Error{Code: rbac.CodeNotFound, Message: fmt.Sprintf("There is no log destination with ID %d.", id),
		Details: map[string]any{"destination_id": id}}
}

func target(name string) string { return "logdest:" + name }

func nullString(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }

func (in Input) config() syslogfwd.Config {
	return syslogfwd.Config{Host: in.Host, Port: in.Port, Transport: in.Transport, TLSMode: in.TLSMode, CAFile: in.CAFile}
}

// Normalize fills in defaults, trims, and refuses settings that can't work. The error is a validation *rbac.Error
// naming the field.
func (in Input) Normalize() (Input, error) {
	in.Name = strings.TrimSpace(in.Name)
	switch n := utf8.RuneCountInString(in.Name); {
	case n == 0:
		return in, validation("name", "Give the destination a name.")
	case n > maxName:
		return in, validation("name", "The name is at most %d characters.", maxName)
	}
	for _, r := range in.Name {
		if unicode.IsControl(r) {
			return in, validation("name", "The name can't contain control characters.")
		}
	}
	in.Host = strings.TrimSpace(in.Host)
	if in.Transport == "" {
		in.Transport = syslogfwd.TransportTLS
	}
	if in.TLSMode == "" {
		in.TLSMode = syslogfwd.TLSVerify
	}
	in.CAFile = strings.TrimSpace(in.CAFile)
	if len(in.CAFile) > maxCAFile {
		return in, validation("ca_file", "The CA file path is at most %d characters.", maxCAFile)
	}
	for _, r := range in.CAFile {
		if unicode.IsControl(r) {
			return in, validation("ca_file", "The CA file path can't contain control characters.")
		}
	}
	if in.CAFile != "" && !filepath.IsAbs(in.CAFile) {
		return in, validation("ca_file", "The CA file path must be absolute.")
	}
	if in.Transport != syslogfwd.TransportTLS && in.TLSMode != syslogfwd.TLSVerify {
		return in, validation("tls_mode", "A TLS mode only applies to the tls transport.")
	}
	if err := in.config().Validate(); err != nil {
		var ce *syslogfwd.ConfigError
		if errors.As(err, &ce) {
			return in, validation(ce.Field, "%s", ce.Message)
		}
		return in, err
	}
	return in, nil
}

func (s *Service) fromRow(r db.LogDestination) Destination {
	return Destination{
		ID: r.ID, Name: r.Name, Host: r.Host, Port: int(r.Port), Transport: r.Transport, TLSMode: r.TlsMode,
		CAFile: r.CaFile.String, Enabled: r.Enabled, CreatedAt: store.FromMillis(r.CreatedAt), CreatedBy: r.CreatedBy,
		UpdatedAt: store.FromMillis(r.UpdatedAt), UpdatedBy: r.UpdatedBy,
	}
}

func (d Destination) config() syslogfwd.Config {
	return syslogfwd.Config{Host: d.Host, Port: d.Port, Transport: d.Transport, TLSMode: d.TLSMode, CAFile: d.CAFile}
}

// sameAddress reports whether two settings send to the same place the same way.
func sameAddress(a, b syslogfwd.Config) bool { return a == b }

func (s *Service) status(ctx context.Context, q *db.Queries, d Destination) Status {
	st := Status{State: StateDisabled, Delivery: DeliveryAtLeastOnce}
	if d.Transport == syslogfwd.TransportUDP {
		st.Delivery = DeliveryBestEffort
	}
	var last int64
	if c, err := q.GetLogCursor(ctx, d.ID); err == nil {
		last = c.LastID
	}
	if n, err := q.CountAuditAfter(ctx, last); err == nil {
		st.Behind = n
	}
	if !d.Enabled {
		return st
	}
	st.State = StateIdle
	s.rmu.Lock()
	r := s.running[d.ID]
	s.rmu.Unlock()
	if r == nil {
		return st
	}
	fs := r.f.Status()
	st.LastSentAt, st.SkippedPruned = fs.LastSentAt, fs.SkippedPruned
	switch fs.State {
	case syslogfwd.StateOK:
		st.State = StateOK
	case syslogfwd.StateFailing:
		st.State, st.LastError, st.FailingSince = StateFailing, fs.LastCode, fs.FailingSince
	}
	return st
}

func (s *Service) get(ctx context.Context, q *db.Queries, id int64) (Destination, error) {
	r, err := q.GetLogDestination(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return Destination{}, notFound(id)
	}
	if err != nil {
		return Destination{}, err
	}
	d := s.fromRow(r)
	d.Status = s.status(ctx, q, d)
	return d, nil
}

// List returns every destination by name, with its status.
func (s *Service) List(ctx context.Context) ([]Destination, error) {
	q := s.Store.Read()
	rows, err := q.ListLogDestinations(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Destination, 0, len(rows))
	for _, r := range rows {
		d := s.fromRow(r)
		d.Status = s.status(ctx, q, d)
		out = append(out, d)
	}
	return out, nil
}

// Get returns one destination with its status.
func (s *Service) Get(ctx context.Context, id int64) (Destination, error) {
	return s.get(ctx, s.Store.Read(), id)
}

// txn is one change in progress.
type txn struct {
	ctx   context.Context
	q     *db.Queries
	now   time.Time
	entry *audit.Entry
}

// do runs fn in a transaction with its audit row, and returns the row's ID. A refusal for lack of logging.manage is
// recorded as permission_denied, as other services do.
func (s *Service) do(ctx context.Context, a rbac.Actor, action string, fn func(t *txn) error) (int64, error) {
	now := s.now()
	entry := audit.Entry{At: now, UserID: a.UserID, Username: a.Username, Action: action, IP: a.IP, Detail: map[string]any{}}
	var rowID int64
	err := s.Store.WithTx(ctx, func(q *db.Queries) error {
		set, err := rbac.Resolve(ctx, q, a.RoleIDs)
		if err != nil {
			return err
		}
		if !set.CanGlobal(rbac.LoggingManage) {
			return rbac.Forbidden(rbac.LoggingManage)
		}
		if err := fn(&txn{ctx: ctx, q: q, now: now, entry: &entry}); err != nil {
			return err
		}
		rowID, err = audit.Insert(ctx, q, entry)
		return err
	})
	switch {
	case rbac.IsCode(err, rbac.CodeForbidden):
		denied := audit.Entry{
			At: now, UserID: a.UserID, Username: a.Username, Action: audit.ActionPermissionDenied,
			Target: entry.Target, Err: err, Detail: map[string]any{"attempted": action, "permission": string(rbac.LoggingManage)},
			IP: a.IP,
		}
		if rerr := s.Audit.Record(ctx, s.Store, denied); rerr != nil {
			return 0, fmt.Errorf("audit refusal: %w", rerr)
		}
		return 0, err
	case err != nil:
		return 0, err
	}
	s.Audit.Log(entry)
	return rowID, nil
}

// precheck refuses a caller without logging.manage before any work, recording it as the change would.
func (s *Service) precheck(ctx context.Context, a rbac.Actor, action string) error {
	set, err := rbac.Resolve(ctx, s.Store.Read(), a.RoleIDs)
	if err != nil {
		return err
	}
	if set.CanGlobal(rbac.LoggingManage) {
		return nil
	}
	_, err = s.do(ctx, a, action, func(*txn) error { return nil }) // refused inside, and recorded
	return err
}

func (t *txn) checkName(name string, self int64) error {
	taken, err := t.q.LogDestinationNameTaken(t.ctx, db.LogDestinationNameTakenParams{Name: name, ID: self})
	if err != nil {
		return err
	}
	if taken {
		return conflict("name", "There is already a log destination called %s.", name)
	}
	return nil
}

func plainConfirm(in Input) error {
	if in.Confirm {
		return nil
	}
	return &rbac.Error{
		Code: rbac.CodeConfirmation,
		Message: fmt.Sprintf("%s sends the audit log unencrypted, so anyone on the path can read it and change it. "+
			"Send it again with confirm=true to use it anyway.", in.Transport),
		Details: map[string]any{"field": "transport", "transport": in.Transport},
	}
}

func (in Input) auditDetail(d map[string]any) {
	d["host"], d["port"], d["transport"], d["tls_mode"], d["enabled"] = in.Host, in.Port, in.Transport, in.TLSMode, in.Enabled
	if in.CAFile != "" {
		d["ca_file"] = in.CAFile
	}
}

// Create adds a destination. It starts at the newest audit row, so it sends new events only, which includes its own
// creation. Plain tcp and udp need Confirm.
func (s *Service) Create(ctx context.Context, a rbac.Actor, in Input) (Destination, error) {
	if err := s.precheck(ctx, a, audit.ActionLogDestCreate); err != nil {
		return Destination{}, err
	}
	norm, err := in.Normalize()
	if err != nil {
		return Destination{}, err
	}
	if norm.config().Plain() {
		if err := plainConfirm(norm); err != nil {
			return Destination{}, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var id int64
	_, err = s.do(ctx, a, audit.ActionLogDestCreate, func(t *txn) error {
		t.entry.Target = target(norm.Name)
		if err := t.checkName(norm.Name, 0); err != nil {
			return err
		}
		rows, err := t.q.ListLogDestinations(t.ctx)
		if err != nil {
			return err
		}
		if len(rows) >= MaxDestinations {
			return conflict("name", "There can be at most %d log destinations.", MaxDestinations)
		}
		ms := store.Millis(t.now)
		if id, err = t.q.CreateLogDestination(t.ctx, db.CreateLogDestinationParams{
			Name: norm.Name, Host: norm.Host, Port: int64(norm.Port), Transport: norm.Transport, TlsMode: norm.TLSMode,
			CaFile: nullString(norm.CAFile), Enabled: norm.Enabled, CreatedAt: ms, CreatedBy: a.Username,
			UpdatedAt: ms, UpdatedBy: a.Username,
		}); err != nil {
			return err
		}
		newest, err := t.q.NewestAuditID(t.ctx)
		if err != nil {
			return err
		}
		if err := t.q.SetLogCursor(t.ctx, db.SetLogCursorParams{DestinationID: id, LastID: newest, UpdatedAt: ms}); err != nil {
			return err
		}
		t.entry.Detail["destination_id"] = id
		norm.auditDetail(t.entry.Detail)
		return nil
	})
	if err != nil {
		return Destination{}, err
	}
	if norm.Enabled {
		s.startByID(ctx, id)
	}
	return s.Get(ctx, id)
}

// redirect is what a guarded change leaves to do once it has committed.
type redirect struct {
	old      Destination // the destination as it was
	changeID int64       // the change's own audit row
	by       string
	drain    bool // the old place is told: it was receiving, and now won't
	moved    bool // the settings point somewhere else, so the new place starts at changeID
	deleted  bool
	cursor   int64 // a deleted destination's cursor, read before it went
	restart  bool  // the forwarder must be stopped, and started again if the destination is enabled
	enable   bool
}

// Update replaces a destination's settings. Changing where or how it sends, or switching off one that was sending,
// first sends the old place everything up to and including this change. Plain tcp and udp need Confirm when the
// transport changes to them.
func (s *Service) Update(ctx context.Context, a rbac.Actor, id int64, in Input) (Destination, error) {
	if err := s.precheck(ctx, a, audit.ActionLogDestUpdate); err != nil {
		return Destination{}, err
	}
	norm, err := in.Normalize()
	if err != nil {
		return Destination{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	before, err := s.Get(ctx, id)
	if err != nil {
		return Destination{}, err
	}
	if norm.config().Plain() && before.Transport != norm.Transport {
		if err := plainConfirm(norm); err != nil {
			return Destination{}, err
		}
	}
	moved := !sameAddress(before.config(), norm.config())
	rd := &redirect{
		old: before, by: a.Username, moved: moved,
		drain:   before.Enabled && (moved || !norm.Enabled),
		restart: moved || before.Enabled != norm.Enabled,
		enable:  norm.Enabled,
	}
	changeID, err := s.do(ctx, a, audit.ActionLogDestUpdate, func(t *txn) error {
		cur, err := s.get(t.ctx, t.q, id)
		if err != nil {
			return err
		}
		t.entry.Target = target(norm.Name)
		if err := t.checkName(norm.Name, id); err != nil {
			return err
		}
		changes := map[string]any{}
		note := func(field string, from, to any) {
			if from != to {
				changes[field] = map[string]any{"from": from, "to": to}
			}
		}
		note("name", cur.Name, norm.Name)
		note("host", cur.Host, norm.Host)
		note("port", cur.Port, norm.Port)
		note("transport", cur.Transport, norm.Transport)
		note("tls_mode", cur.TLSMode, norm.TLSMode)
		note("ca_file", cur.CAFile, norm.CAFile)
		note("enabled", cur.Enabled, norm.Enabled)
		if err := t.q.UpdateLogDestination(t.ctx, db.UpdateLogDestinationParams{
			Name: norm.Name, Host: norm.Host, Port: int64(norm.Port), Transport: norm.Transport, TlsMode: norm.TLSMode,
			CaFile: nullString(norm.CAFile), Enabled: norm.Enabled, UpdatedAt: store.Millis(t.now), UpdatedBy: a.Username,
			ID: id,
		}); err != nil {
			return err
		}
		t.entry.Detail["destination_id"] = id
		t.entry.Detail["changes"] = changes
		if rd.drain {
			t.entry.Detail["old_destination_told"] = true
		}
		return nil
	})
	if err != nil {
		return Destination{}, err
	}
	rd.changeID = changeID
	s.apply(ctx, rd)
	if before.Name != norm.Name {
		s.rmu.Lock()
		if _, ok := s.names[id]; ok {
			s.names[id] = norm.Name
		}
		s.rmu.Unlock()
		s.forgetSeries(id, before.Name, false)
	}
	return s.Get(ctx, id)
}

// Delete removes a destination and its cursor. One that was sending is first sent everything up to and including
// the deletion.
func (s *Service) Delete(ctx context.Context, a rbac.Actor, id int64) error {
	if err := s.precheck(ctx, a, audit.ActionLogDestDelete); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	before, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	rd := &redirect{old: before, by: a.Username, deleted: true, drain: before.Enabled, restart: true}
	changeID, err := s.do(ctx, a, audit.ActionLogDestDelete, func(t *txn) error {
		cur, err := s.get(t.ctx, t.q, id)
		if err != nil {
			return err
		}
		t.entry.Target = target(cur.Name)
		t.entry.Detail["destination_id"] = id
		cur.auditDetail(t.entry.Detail)
		if rd.drain {
			t.entry.Detail["old_destination_told"] = true
		}
		if c, err := t.q.GetLogCursor(t.ctx, id); err == nil {
			rd.cursor = c.LastID
		}
		return t.q.DeleteLogDestination(t.ctx, id)
	})
	if err != nil {
		return err
	}
	rd.changeID = changeID
	s.apply(ctx, rd)
	return nil
}

func (d Destination) auditDetail(m map[string]any) {
	Input{Host: d.Host, Port: d.Port, Transport: d.Transport, TLSMode: d.TLSMode, CAFile: d.CAFile, Enabled: d.Enabled}.auditDetail(m)
}

// apply does what a committed change leaves: stop the forwarder it replaces, tell the old place, then start the new
// one. The old place is told in the background, so the caller isn't held for as long as it takes to give up; the new
// forwarder starts when that is done, so it can't read a cursor the old one is still moving.
func (s *Service) apply(ctx context.Context, rd *redirect) {
	var old *runner
	if rd.restart {
		old = s.stop(rd.old.ID)
	}
	if !rd.drain && !rd.deleted {
		s.settle(ctx, rd)
		return
	}
	if !rd.drain {
		if rd.deleted {
			s.forgetSeries(rd.old.ID, rd.old.Name, true)
		}
		return
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.tellOld(old, rd)
		if rd.deleted {
			s.forgetSeries(rd.old.ID, rd.old.Name, true)
		}
		s.settle(context.WithoutCancel(ctx), rd)
	}()
}

// settle finishes a change once the old place has been dealt with: the cursor of a destination that moved starts at
// the change, and an enabled destination's forwarder starts.
func (s *Service) settle(ctx context.Context, rd *redirect) {
	if rd.deleted {
		return
	}
	if rd.moved {
		err := s.Store.WithTx(ctx, func(q *db.Queries) error {
			return q.AdvanceLogCursor(ctx, db.AdvanceLogCursorParams{
				LastID: rd.changeID, UpdatedAt: store.Millis(s.now()), DestinationID: rd.old.ID,
			})
		})
		if err != nil {
			s.log().Error("moving a log destination's cursor", "destination", rd.old.ID, "err", err)
		}
	}
	if rd.restart && rd.enable {
		s.startByID(ctx, rd.old.ID)
	}
}

// tellOld sends the old place everything up to and including the change, from the old settings, trying again for
// DrainTimeout. A failure is audited as logdest_failed by the app, with who made the change.
func (s *Service) tellOld(old *runner, rd *redirect) {
	timeout := s.DrainTimeout
	if timeout == 0 {
		timeout = DrainTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var f *syslogfwd.Forwarder
	if old != nil {
		f = old.f
	} else {
		f = s.newForwarder(rd.old)
	}
	if rd.deleted {
		// The cursor row is gone, so the drain reads from the last position it knew and doesn't try to keep it.
		last := rd.cursor
		if old != nil {
			last = max(last, old.f.Status().LastID)
		}
		f = s.newForwarder(rd.old)
		f.Store = fixedCursor{syslogfwd.DBStore{S: s.Store}, last}
	}
	defer f.Close()
	var err error
	for attempt := 0; ; attempt++ {
		if err = f.Drain(ctx, rd.changeID); err == nil {
			return
		}
		if attempt >= 4 || ctx.Err() != nil {
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(time.Second << attempt):
		}
	}
	code := syslogfwd.CodeOf(err)
	s.log().Warn("telling a log destination's old place failed", "destination", rd.old.Name, "code", code)
	s.record(audit.Entry{
		At: s.now(), Username: audit.SystemUser, Action: audit.ActionLogDestFailed, Target: target(rd.old.Name),
		Err: errors.New(code),
		Detail: map[string]any{
			"destination_id": rd.old.ID, "code": code, "stage": "old_destination", "changed_by": rd.by,
			"host": rd.old.Host, "port": rd.old.Port, "transport": rd.old.Transport,
		},
	})
}

// fixedCursor reads rows as syslogfwd.DBStore does, but takes its cursor from last and doesn't write one: for a
// destination that has just been deleted.
type fixedCursor struct {
	syslogfwd.DBStore
	last int64
}

func (f fixedCursor) Cursor(context.Context, int64) (int64, error)             { return f.last, nil }
func (f fixedCursor) SetCursor(context.Context, int64, int64, time.Time) error { return nil }

func (s *Service) record(e audit.Entry) {
	ctx := context.Background()
	s.rmu.Lock()
	if s.root != nil {
		ctx = context.WithoutCancel(s.root)
	}
	s.rmu.Unlock()
	if err := s.Audit.Record(ctx, s.Store, e); err != nil {
		s.log().Error("recording a log forwarding event", "action", e.Action, "err", err)
	}
}

func (s *Service) newForwarder(d Destination) *syslogfwd.Forwarder {
	f := &syslogfwd.Forwarder{
		Dest:     syslogfwd.Destination{ID: d.ID, Name: d.Name, Config: d.config()},
		Store:    syslogfwd.DBStore{S: s.Store},
		Hostname: s.hostname(),
		Logger:   s.Logger,
	}
	if s.Tune != nil {
		s.Tune(f)
	}
	return f
}

// Start runs a forwarder for every enabled destination until ctx ends. Changes made later start and stop forwarders
// as needed.
func (s *Service) Start(ctx context.Context) error {
	s.rmu.Lock()
	s.root = ctx
	if s.running == nil {
		s.running = map[int64]*runner{}
	}
	if s.forwarded == nil && s.Metrics != nil {
		s.forwarded = s.Metrics.Counter("pihole_rbac_log_forward_total",
			"Audit log forwarding by destination name: sent (rows written to the collector; a row sent again counts again) and failed (passes that failed).",
			"destination", "result")
	}
	s.rmu.Unlock()
	rows, err := s.Store.Read().ListLogDestinations(ctx)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if r.Enabled {
			s.startRow(s.fromRow(r))
		}
	}
	return nil
}

func (s *Service) startByID(ctx context.Context, id int64) {
	r, err := s.Store.Read().GetLogDestination(ctx, id)
	if err != nil {
		s.log().Error("starting a log forwarder", "destination", id, "err", err)
		return
	}
	if r.Enabled {
		s.startRow(s.fromRow(r))
	}
}

func (s *Service) startRow(d Destination) {
	s.rmu.Lock()
	defer s.rmu.Unlock()
	if s.root == nil || s.root.Err() != nil || s.running[d.ID] != nil {
		return
	}
	if s.running == nil {
		s.running = map[int64]*runner{}
	}
	f := s.newForwarder(d)
	f.OnFailing, f.OnRecovered = s.onFailing, s.onRecovered
	if s.forwarded != nil {
		if s.names == nil {
			s.names = map[int64]string{}
		}
		s.names[d.ID] = d.Name
		f.Count = s.countFor(d.ID)
	}
	ctx, cancel := context.WithCancel(s.root)
	r := &runner{f: f, cfg: d.config(), cancel: cancel, done: make(chan struct{})}
	s.running[d.ID] = r
	go func() {
		defer close(r.done)
		f.Run(ctx)
	}()
}

// countFor counts a destination's forwarding under its current name. A destination that was deleted has no name any
// more, so a forwarder still finishing can't bring its series back.
func (s *Service) countFor(id int64) func(string, int) {
	return func(result string, n int) {
		s.rmu.Lock()
		name, ok := s.names[id]
		s.rmu.Unlock()
		if ok {
			s.forwarded.Add(float64(n), name, result)
		}
	}
}

// forgetSeries drops a destination's series, and stops counting it if it was deleted rather than renamed.
func (s *Service) forgetSeries(id int64, name string, deleted bool) {
	s.rmu.Lock()
	defer s.rmu.Unlock()
	if deleted {
		delete(s.names, id)
	}
	s.forwarded.DeleteMatching("destination", name)
}

// stop ends a destination's forwarder and waits for it, returning it, or nil if none was running.
func (s *Service) stop(id int64) *runner {
	s.rmu.Lock()
	r := s.running[id]
	delete(s.running, id)
	s.rmu.Unlock()
	if r == nil {
		return nil
	}
	r.cancel()
	<-r.done
	return r
}

// Nudge tells every forwarder a row was written. It is the audit logger's sink, alongside the notifier.
func (s *Service) Nudge() {
	s.rmu.Lock()
	defer s.rmu.Unlock()
	for _, r := range s.running {
		r.f.Nudge()
	}
}

// Wait returns when every background send to an old destination has finished. For tests and shutdown.
func (s *Service) Wait() { s.wg.Wait() }

func (s *Service) onFailing(o syslogfwd.Outage) {
	s.record(audit.Entry{
		At: s.now(), Username: audit.SystemUser, Action: audit.ActionLogDestFailed, Target: target(s.nameOf(o.Destination)),
		Err: errors.New(o.Code),
		Detail: map[string]any{
			"destination_id": o.Destination.ID, "code": o.Code, "failing_since": o.Since.UTC().Format(time.RFC3339),
			"attempts": o.Attempts, "last_id": o.LastID,
		},
	})
}

func (s *Service) onRecovered(o syslogfwd.Outage) {
	s.record(audit.Entry{
		At: s.now(), Username: audit.SystemUser, Action: audit.ActionLogDestRecovered, Target: target(s.nameOf(o.Destination)),
		Detail: map[string]any{
			"destination_id": o.Destination.ID, "failing_since": o.Since.UTC().Format(time.RFC3339),
			"attempts": o.Attempts, "last_id": o.LastID,
		},
	})
}

// nameOf is a destination's current name, which may have changed since its forwarder started.
func (s *Service) nameOf(d syslogfwd.Destination) string {
	if r, err := s.Store.Read().GetLogDestination(context.Background(), d.ID); err == nil {
		return r.Name
	}
	return d.Name
}

// TestResult is how a test went. Message is ours, never the collector's.
type TestResult struct {
	OK      bool
	Code    string
	Message string
}

var testMessages = map[string]string{
	syslogfwd.CodeConfig:  "The settings can't be used.",
	syslogfwd.CodeCAFile:  "The CA file couldn't be read or has no certificates in it.",
	syslogfwd.CodeDial:    "Couldn't connect. Check the host, the port and any firewall.",
	syslogfwd.CodeTLS:     "Connected, but the TLS handshake failed. Check the certificate and the CA file.",
	syslogfwd.CodeTimeout: "The collector didn't answer in time.",
	syslogfwd.CodeWrite:   "Connected, but sending failed.",
}

// Test sends one test message to a destination's saved settings and waits for the write. It works for a disabled
// destination too, and isn't audited: it changes nothing. UDP can only say the datagram was handed to the network.
func (s *Service) Test(ctx context.Context, a rbac.Actor, id int64) (TestResult, error) {
	if err := s.precheck(ctx, a, actionTest); err != nil {
		return TestResult{}, err
	}
	d, err := s.Get(ctx, id)
	if err != nil {
		return TestResult{}, err
	}
	tctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := syslogfwd.Test(tctx, d.config(), s.hostname()); err != nil {
		code := syslogfwd.CodeOf(err)
		msg := testMessages[code]
		if msg == "" {
			msg = "Sending failed."
		}
		return TestResult{Code: code, Message: msg}, nil
	}
	msg := "Sent."
	if d.Transport == syslogfwd.TransportUDP {
		msg = "Sent. UDP doesn't say whether it arrived, so check the collector."
	}
	return TestResult{OK: true, Message: msg}, nil
}
