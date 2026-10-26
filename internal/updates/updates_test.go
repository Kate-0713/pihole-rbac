// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package updates

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/release"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

type fakeReleases struct {
	rel   release.Release
	err   error
	calls int
}

func (f *fakeReleases) Latest(context.Context) (release.Release, error) {
	f.calls++
	return f.rel, f.err
}

func mustTag(t *testing.T, s string) release.Version {
	t.Helper()
	v, err := release.ParseTag(s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

type env struct {
	t        *testing.T
	st       *store.Store
	svc      *Service
	releases *fakeReleases
	now      time.Time
	current  string // "" for a development build
	audited  []audit.Entry
	lines    *bytes.Buffer
}

func newEnv(t *testing.T, install Install) *env {
	t.Helper()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(context.Background(), store.Options{DataDir: t.TempDir(), Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	e := &env{t: t, st: st, releases: &fakeReleases{err: release.ErrNoRelease}, current: "v2.0.0",
		now: time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC), lines: &bytes.Buffer{}}
	logger := audit.NewLogger(e.lines)
	logger.SetSink(func(en audit.Entry) { e.audited = append(e.audited, en) })
	e.svc = &Service{
		Store: st, Audit: logger, Releases: e.releases, Install: install,
		RequestFile: filepath.Join(t.TempDir(), "update.request"),
		Current: func() (release.Version, bool) {
			if e.current == "" {
				return release.Version{}, false
			}
			return mustTag(t, e.current), true
		},
		Now:    func() time.Time { return e.now },
		Logger: quiet,
	}
	return e
}

func (e *env) status() Status {
	e.t.Helper()
	s, err := e.svc.Status(context.Background(), strings.TrimPrefix(e.current, "v"))
	if err != nil {
		e.t.Fatal(err)
	}
	return s
}

func (e *env) auditRows() []db.AuditLog {
	e.t.Helper()
	var rows []db.AuditLog
	for id := int64(1); ; id++ {
		row, err := e.st.Read().GetAudit(context.Background(), id)
		if err != nil {
			return rows
		}
		rows = append(rows, row)
	}
}

// addRequest inserts a request and moves it to status as the updater would, with log.
func (e *env) addRequest(at time.Time, target, status, log string) int64 {
	e.t.Helper()
	ctx := context.Background()
	var id int64
	err := e.st.WithTx(ctx, func(q *db.Queries) error {
		r, err := q.InsertUpdateRequest(ctx, db.InsertUpdateRequestParams{
			RequestedAt: store.Millis(at), RequestedByName: "admin",
			TargetVersion: sql.NullString{String: target, Valid: target != ""},
		})
		if err != nil || status == "pending" {
			id = r.ID
			return err
		}
		id = r.ID
		if _, err := q.ClaimUpdateRequest(ctx); err != nil {
			return err
		}
		if err := q.AppendUpdateLog(ctx, db.AppendUpdateLogParams{Line: log, ID: id}); err != nil {
			return err
		}
		if status == "running" {
			return nil
		}
		_, err = q.FinishUpdateRequest(ctx, db.FinishUpdateRequestParams{
			Status: status, FinishedAt: sql.NullInt64{Int64: store.Millis(at.Add(time.Minute)), Valid: true}, ID: id,
		})
		return err
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return id
}

// finish marks every pending request done, as the updater would.
func (e *env) finishPending() {
	e.t.Helper()
	ctx := context.Background()
	err := e.st.WithTx(ctx, func(q *db.Queries) error {
		r, err := q.ClaimUpdateRequest(ctx)
		if err != nil {
			return err
		}
		_, err = q.FinishUpdateRequest(ctx, db.FinishUpdateRequestParams{
			Status: "done", FinishedAt: sql.NullInt64{Int64: 1, Valid: true}, ID: r.ID,
		})
		return err
	})
	if err != nil {
		e.t.Fatal(err)
	}
}

func TestCheck(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, InstallLXC)

	// Nothing published yet.
	if err := e.svc.Check(ctx, false); err != nil {
		t.Fatal(err)
	}
	s := e.status()
	if s.Latest != nil || s.UpdateAvailable || s.CheckError != "" || !s.CheckedAt.Equal(e.now) || !s.CheckEnabled {
		t.Fatalf("no release: %+v", s)
	}

	// A newer release, but asked again within a minute: not checked.
	e.releases.err, e.releases.rel = nil, release.Release{Version: mustTag(t, "v2.1.0"), PublishedAt: e.now.Add(-time.Hour)}
	e.now = e.now.Add(30 * time.Second)
	if err := e.svc.Check(ctx, false); err != nil {
		t.Fatal(err)
	}
	if e.releases.calls != 1 {
		t.Fatalf("checked again within a minute: %d calls", e.releases.calls)
	}
	// Forced, it is.
	if err := e.svc.Check(ctx, true); err != nil {
		t.Fatal(err)
	}
	s = e.status()
	if s.Latest == nil || s.Latest.Tag() != "v2.1.0" || !s.UpdateAvailable || !s.PublishedAt.Equal(time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)) {
		t.Fatalf("newer release: %+v", s)
	}

	// A failed check keeps the release found before and says why.
	e.releases.err = errors.New("GitHub answered 502 Bad Gateway")
	e.now = e.now.Add(2 * time.Minute)
	if err := e.svc.Check(ctx, false); err != nil {
		t.Fatal(err)
	}
	s = e.status()
	if s.Latest == nil || s.Latest.Tag() != "v2.1.0" || !strings.Contains(s.CheckError, "502") || !s.CheckedAt.Equal(e.now) {
		t.Fatalf("failed check: %+v", s)
	}

	// The running version decides whether it's an update.
	for _, tt := range []struct {
		current string
		want    bool
	}{{"v2.1.0", false}, {"v2.2.0", false}, {"v2.1.0-rc.1", true}, {"", false}} {
		e.current = tt.current
		if s := e.status(); s.UpdateAvailable != tt.want || s.Development != (tt.current == "") {
			t.Errorf("running %q: UpdateAvailable %v, Development %v", tt.current, s.UpdateAvailable, s.Development)
		}
	}

	// Off: nothing is asked.
	e.svc.Releases = nil
	calls := e.releases.calls
	if err := e.svc.Check(ctx, true); err != nil || e.releases.calls != calls {
		t.Fatalf("check off: err %v, calls %d", err, e.releases.calls)
	}
	if e.status().CheckEnabled {
		t.Error("CheckEnabled with no Releases")
	}
	// No check is audited: it only reads.
	if rows := e.auditRows(); len(rows) != 0 {
		t.Errorf("checks were audited: %v", rows)
	}
}

func TestRequest(t *testing.T) {
	ctx := context.Background()
	who := Actor{UserID: 0, Username: "admin", IP: "10.0.0.1"}

	refusals := []struct {
		name    string
		install Install
		current string
		target  string
		code    rbac.Code
		want    string
	}{
		{"docker", InstallDocker, "v2.0.0", "", rbac.CodeConflict, "docker compose pull"},
		{"other", InstallOther, "v2.0.0", "", rbac.CodeConflict, "LXC install"},
		{"development build", InstallLXC, "", "", rbac.CodeConflict, "development build"},
		{"not a version", InstallLXC, "v2.0.0", "2.1.0", rbac.CodeValidation, "isn't a version"},
		{"a path", InstallLXC, "v2.0.0", "v2.1.0/../x", rbac.CodeValidation, "isn't a version"},
		{"same version", InstallLXC, "v2.0.0", "v2.0.0", rbac.CodeValidation, "isn't newer than the running v2.0.0"},
		{"older version", InstallLXC, "v2.0.0", "v1.9.9", rbac.CodeValidation, "isn't newer"},
		{"its own prerelease", InstallLXC, "v2.0.0", "v2.0.0-rc.9", rbac.CodeValidation, "isn't newer"},
	}
	for _, tt := range refusals {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t, tt.install)
			e.current = tt.current
			_, err := e.svc.Request(ctx, who, tt.target)
			re, ok := rbac.AsError(err)
			if !ok || re.Code != tt.code || !strings.Contains(re.Message, tt.want) {
				t.Fatalf("err = %v, want %s containing %q", err, tt.code, tt.want)
			}
			if tt.code == rbac.CodeValidation && re.Details["field"] != "target_version" {
				t.Errorf("details = %v", re.Details)
			}
			if len(e.status().Requests) != 0 || len(e.auditRows()) != 0 {
				t.Error("a refused request left a row")
			}
			if _, err := os.Stat(e.svc.RequestFile); !errors.Is(err, os.ErrNotExist) {
				t.Error("a refused request touched the file")
			}
		})
	}

	t.Run("latest, then one at a time", func(t *testing.T) {
		e := newEnv(t, InstallLXC)
		if !e.status().CanRequest {
			t.Fatal("CanRequest false on a fresh LXC install")
		}
		r, err := e.svc.Request(ctx, Actor{UserID: 0, Username: "(cli)"}, "")
		if err != nil {
			t.Fatal(err)
		}
		if r.Status != "pending" || r.TargetVersion != "" || r.RequestedBy != "(cli)" || !r.RequestedAt.Equal(e.now) {
			t.Fatalf("request = %+v", r)
		}
		b, err := os.ReadFile(e.svc.RequestFile)
		if err != nil || string(b) != "1\n" {
			t.Fatalf("request file = %q, %v", b, err)
		}
		rows := e.auditRows()
		if len(rows) != 1 || rows[0].Action != audit.ActionUpdateRequest || rows[0].Username != "(cli)" ||
			rows[0].Result != audit.ResultSuccess {
			t.Fatalf("audit = %+v", rows)
		}
		var d map[string]any
		_ = json.Unmarshal([]byte(rows[0].Detail), &d)
		if d["version"] != "latest" || d["from"] != "v2.0.0" || d["request_id"] != float64(1) {
			t.Errorf("detail = %v", d)
		}
		if len(e.audited) != 1 || !strings.Contains(e.lines.String(), "action=update_request") {
			t.Error("the request wasn't logged after the commit")
		}
		if e.status().CanRequest {
			t.Error("CanRequest while a request is pending")
		}

		_, err = e.svc.Request(ctx, who, "v2.1.0")
		if !rbac.IsCode(err, rbac.CodeConflict) || !strings.Contains(err.Error(), "already pending or running") {
			t.Fatalf("second request: %v", err)
		}
	})

	t.Run("a prerelease target", func(t *testing.T) {
		e := newEnv(t, InstallLXC)
		e.current = "v2.0.0-rc.1"
		r, err := e.svc.Request(ctx, who, "v2.0.0-rc.2")
		if err != nil || r.TargetVersion != "v2.0.0-rc.2" {
			t.Fatalf("request = %+v, %v", r, err)
		}
	})

	t.Run("stale requests don't block", func(t *testing.T) {
		e := newEnv(t, InstallLXC)
		// The helper claims the oldest pending request, so the running one goes in first.
		running := e.addRequest(e.now.Add(-RunningTimeout-time.Second), "", "running", "downloading\n")
		pending := e.addRequest(e.now.Add(-PendingTimeout-time.Second), "", "pending", "")
		if _, err := e.svc.Request(ctx, who, ""); err != nil {
			t.Fatal(err)
		}
		for _, r := range e.status().Requests {
			if (r.ID == pending || r.ID == running) && (r.Status != "failed" || !strings.Contains(r.Log, "pihole-rbac-update.path")) {
				t.Errorf("stale request %d = %+v", r.ID, r)
			}
		}
	})

	t.Run("a recent pending request still blocks", func(t *testing.T) {
		e := newEnv(t, InstallLXC)
		e.addRequest(e.now.Add(-PendingTimeout+time.Minute), "", "pending", "")
		if _, err := e.svc.Request(ctx, who, ""); !rbac.IsCode(err, rbac.CodeConflict) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("request file can't be written", func(t *testing.T) {
		e := newEnv(t, InstallLXC)
		e.svc.RequestFile = filepath.Join(t.TempDir(), "missing", "update.request")
		_, err := e.svc.Request(ctx, who, "")
		if !rbac.IsCode(err, rbac.CodeConflict) || !strings.Contains(err.Error(), "install.sh") {
			t.Fatalf("err = %v", err)
		}
		if len(e.status().Requests) != 0 || len(e.auditRows()) != 0 || len(e.audited) != 0 {
			t.Error("the request was kept although the updater couldn't be told")
		}
	})
}

func TestAnnounce(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, InstallLXC)
	e.current = "v2.1.0"
	done := e.addRequest(e.now.Add(-time.Hour), "", "done", "verified v2.1.0\nhealthy\n")
	e.addRequest(e.now.Add(-50*time.Minute), "v2.2.0", "failed", "downloading\nchecking the signature of v2.2.0's checksums: not valid\n")
	e.addRequest(e.now.Add(-40*time.Minute), "v2.3.0", "rolled_back", "restarted\nnot healthy after 60s; restored v2.1.0\n")
	e.addRequest(e.now.Add(-time.Minute), "", "pending", "")

	if err := e.svc.Announce(ctx); err != nil {
		t.Fatal(err)
	}
	rows := e.auditRows()
	if len(rows) != 3 {
		t.Fatalf("got %d audit rows, want 3", len(rows))
	}
	want := []struct{ action, result, summary, errText string }{
		{audit.ActionUpdateDone, audit.ResultSuccess, "now running v2.1.0", ""},
		{audit.ActionUpdateFailed, audit.ResultFailure, "to v2.2.0", "not valid"},
		{audit.ActionUpdateRolledBack, audit.ResultFailure, "to v2.3.0", "restored v2.1.0"},
	}
	for i, w := range want {
		var d map[string]any
		_ = json.Unmarshal([]byte(rows[i].Detail), &d)
		if rows[i].Action != w.action || rows[i].Result != w.result || rows[i].Username != audit.SystemUser ||
			d["summary"] != w.summary {
			t.Errorf("row %d = %s %s %s %v", i, rows[i].Action, rows[i].Result, rows[i].Username, d)
		}
		if errText, _ := d["error"].(string); !strings.Contains(errText, w.errText) {
			t.Errorf("row %d error = %q, want %q", i, errText, w.errText)
		}
	}
	if d := rows[0].Detail; !strings.Contains(d, `"request_id":`+strconv.FormatInt(done, 10)) {
		t.Errorf("done detail = %s", d)
	}
	if len(e.audited) != 3 {
		t.Errorf("sink got %d entries", len(e.audited))
	}

	// Announced once only.
	if err := e.svc.Announce(ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(e.auditRows()); n != 3 {
		t.Errorf("announced again: %d rows", n)
	}

	// The pending one finishes later and is announced then; the check's own state is untouched.
	e.finishPending()
	if err := e.svc.Check(ctx, true); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Announce(ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(e.auditRows()); n != 4 {
		t.Errorf("after the fourth finished: %d rows", n)
	}
	if !e.status().CheckedAt.Equal(e.now) {
		t.Error("announcing lost the check's state")
	}
}

func TestAnnounceMarksStale(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, InstallLXC)
	e.addRequest(e.now.Add(-PendingTimeout-time.Minute), "", "pending", "")
	if err := e.svc.Announce(ctx); err != nil {
		t.Fatal(err)
	}
	rows := e.auditRows()
	if len(rows) != 1 || rows[0].Action != audit.ActionUpdateFailed || !strings.Contains(rows[0].Detail, "pihole-rbac-update.path") {
		t.Fatalf("rows = %+v", rows)
	}
}

func TestNextCheck(t *testing.T) {
	started := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	delay, jitter := 3*time.Minute, -20*time.Minute
	tests := []struct {
		name    string
		checked time.Time
		want    time.Time
	}{
		{"never checked", time.Time{}, started.Add(delay)},
		{"checked long ago", started.Add(-72 * time.Hour), started.Add(delay)},
		{"checked an hour ago", started.Add(-time.Hour), started.Add(-time.Hour + CheckInterval + jitter)},
		{"checked just before starting", started.Add(-time.Second), started.Add(-time.Second + CheckInterval + jitter)},
	}
	for _, tt := range tests {
		var st state
		if !tt.checked.IsZero() {
			st.CheckedAt = store.Millis(tt.checked)
		}
		if got := nextCheck(st, started, delay, jitter); !got.Equal(tt.want) {
			t.Errorf("%s: %v, want %v", tt.name, got, tt.want)
		}
	}
}
