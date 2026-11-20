// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package logdestinations

import (
	"bytes"
	"context"
	"github.com/Kate-0713/pihole-rbac/internal/metrics/metricstest"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/metrics"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
	"github.com/Kate-0713/pihole-rbac/internal/syslogfwd"
	"github.com/Kate-0713/pihole-rbac/internal/syslogfwd/syslogtest"
)

type env struct {
	t      *testing.T
	st     *store.Store
	svc    *Service
	admin  rbac.Actor
	nobody rbac.Actor
}

func newEnv(t *testing.T, modify ...func(*Service)) *env {
	t.Helper()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(context.Background(), store.Options{DataDir: t.TempDir(), Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	al := audit.NewLogger(&bytes.Buffer{})
	svc := &Service{
		Store: st, Audit: al, Logger: quiet, Hostname: "host", DrainTimeout: 1500 * time.Millisecond,
		Tune: func(f *syslogfwd.Forwarder) {
			f.Poll, f.BackoffMin, f.BackoffMax, f.FailAfter = 20*time.Millisecond, 10*time.Millisecond, 40*time.Millisecond, 150*time.Millisecond
		},
	}
	for _, m := range modify {
		m(svc)
	}
	al.SetSink(func(audit.Entry) { svc.Nudge() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); svc.Wait() })
	if err := svc.Start(ctx); err != nil {
		t.Fatal(err)
	}
	var noneRole int64
	if err := st.WithTx(context.Background(), func(q *db.Queries) error {
		var err error
		noneRole, err = q.CreateRole(context.Background(), db.CreateRoleParams{Name: "none", CreatedAt: 1})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return &env{
		t: t, st: st, svc: svc,
		admin:  rbac.Actor{Username: "admin", RoleIDs: []int64{1}, IP: "10.0.0.1"},
		nobody: rbac.Actor{Username: "nobody", RoleIDs: []int64{noneRole}, IP: "10.0.0.2"},
	}
}

func (e *env) rows() []db.AuditLog {
	e.t.Helper()
	rows, err := e.st.Read().ListRecentAudit(context.Background(), 1000)
	if err != nil {
		e.t.Fatal(err)
	}
	return rows // newest first
}

// find returns the newest audit row with an action, waiting for it.
func (e *env) find(action string) db.AuditLog {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		for _, r := range e.rows() {
			if r.Action == action {
				return r
			}
		}
		if time.Now().After(deadline) {
			e.t.Fatalf("no %s row; have %v", action, e.actions())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (e *env) actions() []string {
	var out []string
	for _, r := range e.rows() {
		out = append(out, r.Action)
	}
	return out
}

func tcp(name string, c *syslogtest.Collector) Input {
	return Input{Name: name, Host: c.Host, Port: c.Port, Transport: "tcp", Enabled: true, Confirm: true}
}

func code(err error) string {
	if e, ok := rbac.AsError(err); ok {
		return string(e.Code)
	}
	if err != nil {
		return err.Error()
	}
	return ""
}

func field(err error) string {
	if e, ok := rbac.AsError(err); ok {
		f, _ := e.Details["field"].(string)
		return f
	}
	return ""
}

func has(msgs []string, sub string) bool {
	for _, m := range msgs {
		if strings.Contains(m, sub) {
			return true
		}
	}
	return false
}

// waitHas waits until the collector holds a message containing sub.
func waitHas(t *testing.T, c *syslogtest.Collector, sub string) []string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		m := c.Messages()
		if has(m, sub) {
			return m
		}
		if time.Now().After(deadline) {
			t.Fatalf("collector never got %q; has %d messages", sub, len(m))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestCreateStartsAtNewestAndSendsItself(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	// Something that happened before the destination existed.
	if err := e.svc.Audit.Record(ctx, e.st, audit.Entry{At: time.Now(), Username: "u", Action: audit.ActionLogin, Target: "before"}); err != nil {
		t.Fatal(err)
	}
	c := syslogtest.NewTCP(t)
	d, err := e.svc.Create(ctx, e.admin, tcp("Main", c))
	if err != nil {
		t.Fatal(err)
	}
	if d.Transport != "tcp" || d.TLSMode != "verify" || !d.Enabled || d.CreatedBy != "admin" {
		t.Fatalf("destination %+v", d)
	}
	msgs := waitHas(t, c, "logdest_create")
	if has(msgs, `"target":"before"`) {
		t.Fatalf("a row from before the destination was sent: %v", msgs)
	}
	row := e.find(audit.ActionLogDestCreate)
	if row.Username != "admin" || row.Target != "logdest:Main" {
		t.Fatalf("row %+v", row)
	}
}

func TestPlainTransportNeedsConfirm(t *testing.T) {
	e := newEnv(t)
	c := syslogtest.NewTCP(t)
	in := tcp("Plain", c)
	in.Confirm = false
	if _, err := e.svc.Create(context.Background(), e.admin, in); code(err) != "confirmation_required" {
		t.Fatalf("create err = %v", err)
	}
	if list, _ := e.svc.List(context.Background()); len(list) != 0 {
		t.Fatalf("unconfirmed create saved %v", list)
	}
	in.Confirm = true
	d, err := e.svc.Create(context.Background(), e.admin, in)
	if err != nil {
		t.Fatal(err)
	}
	// Changing to a plain transport from tls needs it again; staying on one doesn't.
	tlsIn := Input{Name: "Plain", Host: c.Host, Port: c.Port, Transport: "tls", Enabled: false}
	if d, err = e.svc.Update(context.Background(), e.admin, d.ID, tlsIn); err != nil {
		t.Fatal(err)
	}
	back := tcp("Plain", c)
	back.Enabled, back.Confirm = false, false
	if _, err := e.svc.Update(context.Background(), e.admin, d.ID, back); code(err) != "confirmation_required" {
		t.Fatalf("update err = %v", err)
	}
	back.Confirm = true
	if d, err = e.svc.Update(context.Background(), e.admin, d.ID, back); err != nil {
		t.Fatal(err)
	}
	back.Confirm, back.Name = false, "Renamed"
	if _, err := e.svc.Update(context.Background(), e.admin, d.ID, back); err != nil {
		t.Fatalf("a change that stays on tcp: %v", err)
	}
}

func TestInputRules(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ok := Input{Name: "A", Host: "logs.example.com", Port: 6514, Enabled: false}
	if _, err := e.svc.Create(ctx, e.admin, ok); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		edit  func(*Input)
		field string
		code  string
	}{
		{"no name", func(i *Input) { i.Name = " " }, "name", "validation_failed"},
		{"long name", func(i *Input) { i.Name = strings.Repeat("x", 81) }, "name", "validation_failed"},
		{"duplicate ignoring case", func(i *Input) { i.Name = "a" }, "name", "conflict"},
		{"url as host", func(i *Input) { i.Name, i.Host = "B", "https://logs" }, "host", "validation_failed"},
		{"host with port", func(i *Input) { i.Name, i.Host = "B", "logs:514" }, "host", "validation_failed"},
		{"no host", func(i *Input) { i.Name, i.Host = "B", "" }, "host", "validation_failed"},
		{"port 0", func(i *Input) { i.Name, i.Port = "B", 0 }, "port", "validation_failed"},
		{"port too big", func(i *Input) { i.Name, i.Port = "B", 70000 }, "port", "validation_failed"},
		{"bad transport", func(i *Input) { i.Name, i.Transport = "B", "http" }, "transport", "validation_failed"},
		{"bad tls mode", func(i *Input) { i.Name, i.TLSMode = "B", "off" }, "tls_mode", "validation_failed"},
		{"insecure on tcp", func(i *Input) { i.Name, i.Transport, i.TLSMode, i.Confirm = "B", "tcp", "insecure", true }, "tls_mode", "validation_failed"},
		{"relative ca file", func(i *Input) { i.Name, i.CAFile = "B", "ca.pem" }, "ca_file", "validation_failed"},
		{"ca file with insecure", func(i *Input) { i.Name, i.TLSMode, i.CAFile = "B", "insecure", "/etc/ca.pem" }, "ca_file", "validation_failed"},
		{"ca file on tcp", func(i *Input) { i.Name, i.Transport, i.CAFile, i.Confirm = "B", "tcp", "/etc/ca.pem", true }, "ca_file", "validation_failed"},
	} {
		in := ok
		tc.edit(&in)
		_, err := e.svc.Create(ctx, e.admin, in)
		if code(err) != tc.code || field(err) != tc.field {
			t.Errorf("%s: err = %v (code %s, field %s)", tc.name, err, code(err), field(err))
		}
	}
	if list, _ := e.svc.List(ctx); len(list) != 1 {
		t.Fatalf("refused creates saved something: %v", list)
	}
}

func TestLimit(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < MaxDestinations; i++ {
		in := Input{Name: string(rune('A' + i)), Host: "logs.example.com", Port: 6514}
		if _, err := e.svc.Create(context.Background(), e.admin, in); err != nil {
			t.Fatal(err)
		}
	}
	_, err := e.svc.Create(context.Background(), e.admin, Input{Name: "one more", Host: "logs.example.com", Port: 6514})
	if code(err) != "conflict" {
		t.Fatalf("err = %v", err)
	}
}

func TestRefusedWithoutPermission(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	c := syslogtest.NewTCP(t)
	d, err := e.svc.Create(ctx, e.admin, tcp("Main", c))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		attempted string
		call      func() error
	}{
		{"logdest_create", func() error { _, err := e.svc.Create(ctx, e.nobody, tcp("X", c)); return err }},
		{"logdest_update", func() error { _, err := e.svc.Update(ctx, e.nobody, d.ID, tcp("X", c)); return err }},
		{"logdest_delete", func() error { return e.svc.Delete(ctx, e.nobody, d.ID) }},
		{"logdest_test", func() error { _, err := e.svc.Test(ctx, e.nobody, d.ID); return err }},
	} {
		if err := tc.call(); code(err) != "forbidden" {
			t.Errorf("%s: err = %v", tc.attempted, err)
			continue
		}
		row := e.find(audit.ActionPermissionDenied)
		if row.Username != "nobody" || !strings.Contains(row.Detail, `"attempted":"`+tc.attempted+`"`) ||
			!strings.Contains(row.Detail, `"permission":"logging.manage"`) {
			t.Errorf("%s: denied row %+v", tc.attempted, row)
		}
	}
	got, err := e.svc.Get(ctx, d.ID)
	if err != nil || got.Name != "Main" {
		t.Fatalf("destination changed: %+v %v", got, err)
	}
}

func TestMovingTellsOldPlaceAndStartsNewAtTheChange(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	oldC, newC := syslogtest.NewTCP(t), syslogtest.NewTCP(t)
	d, err := e.svc.Create(ctx, e.admin, tcp("Main", oldC))
	if err != nil {
		t.Fatal(err)
	}
	waitHas(t, oldC, "logdest_create")
	if _, err := e.svc.Update(ctx, e.admin, d.ID, tcp("Main", newC)); err != nil {
		t.Fatal(err)
	}
	e.svc.Wait()
	old := waitHas(t, oldC, "logdest_update")
	if !has(old, newC.Host) {
		t.Fatalf("the old place wasn't told where the log went: %v", old)
	}
	// The new place gets what follows the change, not the change or what came before it.
	if err := e.svc.Audit.Record(ctx, e.st, audit.Entry{At: time.Now(), Username: "u", Action: audit.ActionLogin, Target: "after"}); err != nil {
		t.Fatal(err)
	}
	msgs := waitHas(t, newC, `"target":"after"`)
	if has(msgs, "logdest_update") || has(msgs, "logdest_create") {
		t.Fatalf("the new place got rows from before the move: %v", msgs)
	}
	if has(oldC.Messages(), `"target":"after"`) {
		t.Fatal("the old place still receives")
	}
}

// The cursor query has to run against a real database, and only ever moves a cursor forward. Its generated SQL once
// asked for more arguments than it was given, which nothing here noticed and only showed up as an error in the log of
// a browser test.
func TestAdvanceLogCursorOnlyMovesForward(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	in := tcp("Cursor", syslogtest.NewTCP(t))
	in.Enabled = false // no forwarder, so nothing else moves the cursor
	d, err := e.svc.Create(ctx, e.admin, in)
	if err != nil {
		t.Fatal(err)
	}
	cursor := func() int64 {
		t.Helper()
		c, err := e.st.Read().GetLogCursor(ctx, d.ID)
		if err != nil {
			t.Fatal(err)
		}
		return c.LastID
	}
	advance := func(to int64) {
		t.Helper()
		err := e.st.WithTx(ctx, func(q *db.Queries) error {
			return q.AdvanceLogCursor(ctx, db.AdvanceLogCursorParams{LastID: to, UpdatedAt: 1, DestinationID: d.ID})
		})
		if err != nil {
			t.Fatalf("advancing to %d: %v", to, err)
		}
	}
	start := cursor()
	advance(start + 10)
	if got := cursor(); got != start+10 {
		t.Fatalf("cursor after advancing: %d, want %d", got, start+10)
	}
	advance(start + 3) // behind it: ignored
	if got := cursor(); got != start+10 {
		t.Fatalf("cursor moved back to %d", got)
	}
}

func TestDisablingTellsOldPlaceAndKeepsPosition(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	c := syslogtest.NewTCP(t)
	in := tcp("Main", c)
	d, err := e.svc.Create(ctx, e.admin, in)
	if err != nil {
		t.Fatal(err)
	}
	in.Enabled = false
	if d, err = e.svc.Update(ctx, e.admin, d.ID, in); err != nil {
		t.Fatal(err)
	}
	e.svc.Wait()
	waitHas(t, c, "logdest_update")
	if d.Status.State != StateDisabled {
		t.Fatalf("state %s", d.Status.State)
	}
	// Rows while disabled wait, and go when it is switched on again.
	if err := e.svc.Audit.Record(ctx, e.st, audit.Entry{At: time.Now(), Username: "u", Action: audit.ActionLogin, Target: "while-off"}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if has(c.Messages(), "while-off") {
		t.Fatal("a disabled destination sent")
	}
	if got, _ := e.svc.Get(ctx, d.ID); got.Status.Behind < 1 {
		t.Fatalf("behind = %d", got.Status.Behind)
	}
	in.Enabled = true
	if _, err := e.svc.Update(ctx, e.admin, d.ID, in); err != nil {
		t.Fatal(err)
	}
	waitHas(t, c, "while-off")
}

func TestRenameDoesNotRestart(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	c := syslogtest.NewTCP(t)
	in := tcp("Main", c)
	d, err := e.svc.Create(ctx, e.admin, in)
	if err != nil {
		t.Fatal(err)
	}
	e.svc.rmu.Lock()
	before := e.svc.running[d.ID]
	e.svc.rmu.Unlock()
	in.Name = "Renamed"
	if _, err := e.svc.Update(ctx, e.admin, d.ID, in); err != nil {
		t.Fatal(err)
	}
	e.svc.rmu.Lock()
	after := e.svc.running[d.ID]
	e.svc.rmu.Unlock()
	if before == nil || before != after {
		t.Fatal("a rename restarted the forwarder")
	}
	row := e.find(audit.ActionLogDestUpdate)
	if strings.Contains(row.Detail, "old_destination_told") {
		t.Fatalf("a rename told the old place: %s", row.Detail)
	}
}

func TestDeleteTellsOldPlace(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	c := syslogtest.NewTCP(t)
	d, err := e.svc.Create(ctx, e.admin, tcp("Main", c))
	if err != nil {
		t.Fatal(err)
	}
	waitHas(t, c, "logdest_create")
	if err := e.svc.Delete(ctx, e.admin, d.ID); err != nil {
		t.Fatal(err)
	}
	e.svc.Wait()
	waitHas(t, c, "logdest_delete")
	if _, err := e.svc.Get(ctx, d.ID); code(err) != "not_found" {
		t.Fatalf("Get after delete: %v", err)
	}
	if _, err := e.st.Read().GetLogCursor(ctx, d.ID); err == nil {
		t.Fatal("the cursor outlived the destination")
	}
}

func TestOldPlaceUnreachableIsAudited(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	oldC, newC := syslogtest.NewTCP(t), syslogtest.NewTCP(t)
	d, err := e.svc.Create(ctx, e.admin, tcp("Main", oldC))
	if err != nil {
		t.Fatal(err)
	}
	waitHas(t, oldC, "logdest_create")
	oldC.Stop()
	if _, err := e.svc.Update(ctx, e.admin, d.ID, tcp("Main", newC)); err != nil {
		t.Fatal(err)
	}
	e.svc.Wait()
	row := e.find(audit.ActionLogDestFailed)
	if row.Username != audit.SystemUser || !strings.Contains(row.Detail, `"changed_by":"admin"`) ||
		!strings.Contains(row.Detail, `"stage":"old_destination"`) {
		t.Fatalf("row %+v", row)
	}
	if strings.Contains(row.Detail, "secret") {
		t.Fatal("detail mentions a secret")
	}
}

func TestOutageAuditedOnceAndRecovery(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	c := syslogtest.NewTCP(t)
	d, err := e.svc.Create(ctx, e.admin, tcp("Main", c))
	if err != nil {
		t.Fatal(err)
	}
	waitHas(t, c, "logdest_create")
	c.Stop()
	if err := e.svc.Audit.Record(ctx, e.st, audit.Entry{At: time.Now(), Username: "u", Action: audit.ActionLogin, Target: "down"}); err != nil {
		t.Fatal(err)
	}
	failed := e.find(audit.ActionLogDestFailed)
	if failed.Username != audit.SystemUser || failed.Target != "logdest:Main" {
		t.Fatalf("row %+v", failed)
	}
	if got, _ := e.svc.Get(ctx, d.ID); got.Status.State != StateFailing || got.Status.LastError == "" {
		t.Fatalf("status %+v", got.Status)
	}
	time.Sleep(300 * time.Millisecond)
	n := 0
	for _, a := range e.actions() {
		if a == audit.ActionLogDestFailed {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d failed rows for one outage", n)
	}
	c.Restart()
	e.find(audit.ActionLogDestRecovered)
	waitHas(t, c, `"target":"down"`)
}

func TestTest(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	c := syslogtest.NewTCP(t)
	in := tcp("Main", c)
	in.Enabled = false
	d, err := e.svc.Create(ctx, e.admin, in)
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.svc.Test(ctx, e.admin, d.ID)
	if err != nil || !r.OK {
		t.Fatalf("test = %+v, %v", r, err)
	}
	waitHas(t, c, " test ")
	before := len(e.rows())
	c.Stop()
	r, err = e.svc.Test(ctx, e.admin, d.ID)
	if err != nil || r.OK || r.Code != syslogfwd.CodeDial {
		t.Fatalf("test of a stopped collector = %+v, %v", r, err)
	}
	if len(e.rows()) != before {
		t.Fatal("a test was audited")
	}
	if _, err := e.svc.Test(ctx, e.admin, 999); code(err) != "not_found" {
		t.Fatalf("missing: %v", err)
	}
}

func TestStartRunsEnabledDestinations(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	c := syslogtest.NewTCP(t)
	if _, err := e.svc.Create(ctx, e.admin, tcp("Main", c)); err != nil {
		t.Fatal(err)
	}
	// A second service over the same store, as after a restart.
	again := &Service{Store: e.st, Audit: e.svc.Audit, Hostname: "host", Tune: e.svc.Tune}
	rctx, cancel := context.WithCancel(ctx)
	defer func() { cancel(); again.Wait() }()
	if err := again.Start(rctx); err != nil {
		t.Fatal(err)
	}
	again.rmu.Lock()
	n := len(again.running)
	again.rmu.Unlock()
	if n != 1 {
		t.Fatalf("%d forwarders running", n)
	}
}

func TestForwardMetrics(t *testing.T) {
	reg := metrics.New()
	e := newEnv(t, func(s *Service) { s.Metrics = reg })
	ctx := context.Background()
	scrape := func() string {
		var b strings.Builder
		if _, err := reg.WriteTo(&b); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}
	waitSeries := func(want string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for !strings.Contains(scrape(), want) {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %q in:\n%s", want, scrape())
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	c := syslogtest.NewTCP(t)
	in := tcp("Main", c)
	d, err := e.svc.Create(ctx, e.admin, in)
	if err != nil {
		t.Fatal(err)
	}
	waitHas(t, c, "logdest_create")
	waitSeries(`pihole_rbac_log_forward_total{destination="Main",result="sent"} `)

	// A rename moves the series without restarting the forwarder, and the next rows count under the new name.
	in.Name = "Renamed"
	if _, err := e.svc.Update(ctx, e.admin, d.ID, in); err != nil {
		t.Fatal(err)
	}
	waitSeries(`pihole_rbac_log_forward_total{destination="Renamed",result="sent"} `)
	if out := scrape(); strings.Contains(out, `destination="Main"`) {
		t.Errorf("the old name is still a series:\n%s", out)
	}

	// Deleting drops them, and the drain's last rows can't bring them back.
	if err := e.svc.Delete(ctx, e.admin, d.ID); err != nil {
		t.Fatal(err)
	}
	e.svc.Wait()
	if out := scrape(); strings.Contains(out, "destination=") {
		t.Errorf("a deleted destination still has series:\n%s", out)
	}
	metricstest.Dump(t, reg)
}
