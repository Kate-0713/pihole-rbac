// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package updater

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/minisign"
	"github.com/Kate-0713/pihole-rbac/internal/release"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

func tag(t *testing.T, s string) release.Version {
	t.Helper()
	v, err := release.ParseTag(s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func archiveWith(t *testing.T, binary []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	if err := tw.WriteHeader(&tar.Header{Name: release.BinaryName, Mode: 0o755, Size: int64(len(binary)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	_, _ = tw.Write(binary)
	_ = tw.Close()
	_ = zw.Close()
	return buf.Bytes()
}

// fakeSource serves one release, or fails where told to.
type fakeSource struct {
	latest       release.Version
	latestErr    error
	checksumsErr error
	archive      []byte
	asked        []string
}

func (f *fakeSource) Latest(context.Context) (release.Release, error) {
	f.asked = append(f.asked, "latest")
	return release.Release{Version: f.latest}, f.latestErr
}

func (f *fakeSource) Checksums(_ context.Context, v release.Version) (release.Checksums, error) {
	f.asked = append(f.asked, "checksums "+v.Tag())
	return release.Checksums{}, f.checksumsErr
}

func (f *fakeSource) Archive(_ context.Context, v release.Version, arch string, _ release.Checksums) ([]byte, error) {
	f.asked = append(f.asked, "archive "+v.Tag()+" "+arch)
	return f.archive, nil
}

// fakeSystem records systemctl calls; restart runs onRestart (standing in for the new version starting, which may
// migrate the database), and health answers from healthy.
type fakeSystem struct {
	calls     []string
	version   string // what BinaryVersion prints
	healthy   func(call int) bool
	health    int
	onRestart func()
	chowned   []string
}

func (f *fakeSystem) Systemctl(_ context.Context, args ...string) error {
	f.calls = append(f.calls, strings.Join(args, " "))
	if args[0] == "restart" && f.onRestart != nil {
		f.onRestart()
	}
	return nil
}

func (f *fakeSystem) Health(context.Context) error {
	f.health++
	if f.healthy == nil || f.healthy(f.health) {
		return nil
	}
	return errors.New("connection refused")
}

func (f *fakeSystem) BinaryVersion(_ context.Context, path string) (string, error) {
	if _, err := os.Stat(path); err != nil {
		return "", err
	}
	return f.version, nil
}

func (f *fakeSystem) Chown(dir *os.Root, name string) error {
	if _, err := dir.Lstat(name); err != nil {
		return err
	}
	f.chowned = append(f.chowned, filepath.Base(name))
	return nil
}

type env struct {
	t       *testing.T
	u       *Updater
	src     *fakeSource
	sys     *fakeSystem
	current string
	out     *bytes.Buffer
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dataDir := t.TempDir()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(context.Background(), store.Options{DataDir: dataDir, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	binDir := t.TempDir()
	bin := filepath.Join(binDir, "pihole-rbac")
	if err := os.WriteFile(bin, []byte("old binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	e := &env{
		t:       t,
		src:     &fakeSource{latest: tag(t, "v2.1.0"), archive: archiveWith(t, []byte("new binary"))},
		sys:     &fakeSystem{version: "pihole-rbac 2.1.0 (commit abc, built today)\nfrontend: embedded\nsource: x\n"},
		current: "v2.0.0",
		out:     &bytes.Buffer{},
	}
	reqFile := filepath.Join(t.TempDir(), "update.request")
	_ = os.WriteFile(reqFile, []byte("1\n"), 0o640)
	e.u = &Updater{
		DataDir: dataDir, Binary: bin, RequestFile: reqFile, Arch: "amd64", Source: e.src, System: e.sys,
		Current: func() (release.Version, bool) {
			if e.current == "" {
				return release.Version{}, false
			}
			return tag(t, e.current), true
		},
		Out: e.out, HealthWait: 200 * time.Millisecond, HealthPoll: time.Millisecond, Stable: time.Millisecond,
	}
	return e
}

// exec runs a statement on the database as another process would.
func (e *env) exec(query string, args ...any) {
	e.t.Helper()
	d, err := store.OpenUnmigrated(context.Background(), e.u.DataDir)
	if err != nil {
		e.t.Fatal(err)
	}
	defer d.Close()
	if _, err := d.Exec(query, args...); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) request(target string) {
	e.t.Helper()
	e.exec(`INSERT INTO update_requests (requested_at, requested_by_name, target_version) VALUES (?, 'admin', ?)`,
		time.Now().UnixMilli(), sql.NullString{String: target, Valid: target != ""})
}

func (e *env) row() db.UpdateRequest {
	e.t.Helper()
	d, err := store.OpenUnmigrated(context.Background(), e.u.DataDir)
	if err != nil {
		e.t.Fatal(err)
	}
	defer d.Close()
	rows, err := db.New(d).ListUpdateRequests(context.Background(), 1)
	if err != nil || len(rows) != 1 {
		e.t.Fatalf("rows %v, %v", rows, err)
	}
	return rows[0]
}

func (e *env) markers() int {
	e.t.Helper()
	d, err := store.OpenUnmigrated(context.Background(), e.u.DataDir)
	if err != nil {
		e.t.Fatal(err)
	}
	defer d.Close()
	var n int
	if err := d.QueryRow(`SELECT count(*) FROM settings WHERE key = 'migrated-by-new-version'`).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func (e *env) binary() string {
	e.t.Helper()
	b, err := os.ReadFile(e.u.Binary)
	if err != nil {
		e.t.Fatal(err)
	}
	return string(b)
}

func (e *env) backups() []string {
	entries, _ := os.ReadDir(store.BackupDir(e.u.DataDir))
	var names []string
	for _, en := range entries {
		names = append(names, en.Name())
	}
	return names
}

func (e *env) run() string {
	e.t.Helper()
	status, err := e.u.Run(context.Background())
	if err != nil {
		e.t.Fatalf("Run: %v\n%s", err, e.out)
	}
	return status
}

func TestUpdateLatest(t *testing.T) {
	e := newEnv(t)
	e.request("")
	if got := e.run(); got != StatusDone {
		t.Fatalf("status %q\n%s", got, e.out)
	}
	if e.binary() != "new binary" {
		t.Errorf("binary = %q", e.binary())
	}
	if b, _ := os.ReadFile(e.u.Binary + ".prev"); string(b) != "old binary" {
		t.Errorf(".prev = %q", b)
	}
	if _, err := os.Stat(e.u.Binary + ".new"); !errors.Is(err, os.ErrNotExist) {
		t.Error(".new left behind")
	}
	if _, err := os.Stat(e.u.RequestFile); !errors.Is(err, os.ErrNotExist) {
		t.Error("the request file wasn't removed")
	}
	if !slices.Equal(e.sys.calls, []string{"restart pihole-rbac.service"}) {
		t.Errorf("systemctl = %v", e.sys.calls)
	}
	if !slices.Equal(e.src.asked, []string{"latest", "checksums v2.1.0", "archive v2.1.0 amd64"}) {
		t.Errorf("asked = %v", e.src.asked)
	}
	b := e.backups()
	if len(b) != 1 || !strings.HasPrefix(b[0], "v2.0.0-") || !strings.HasSuffix(b[0], ".db") {
		t.Errorf("backups = %v", b)
	}
	if fi, err := os.Stat(filepath.Join(store.BackupDir(e.u.DataDir), b[0])); err != nil || (fi.Mode().Perm() != 0o600 && os.PathSeparator == '/') {
		t.Errorf("backup mode: %v %v", fi.Mode(), err)
	}
	if !slices.Contains(e.sys.chowned, b[0]) || !slices.Contains(e.sys.chowned, "backups") {
		t.Errorf("chowned = %v", e.sys.chowned)
	}
	r := e.row()
	if r.Status != StatusDone || !r.FinishedAt.Valid {
		t.Errorf("row = %+v", r)
	}
	for _, want := range []string{"taken by the updater", "Updating from v2.0.0 to v2.1.0", "signed with the release key",
		"Backed up the database", "Installed", "is running and healthy"} {
		if !strings.Contains(r.Log, want) {
			t.Errorf("log lacks %q:\n%s", want, r.Log)
		}
	}
	if !strings.Contains(e.out.String(), "is running and healthy") {
		t.Error("progress wasn't printed for the journal")
	}
}

func TestUpdateTarget(t *testing.T) {
	e := newEnv(t)
	e.current = "v2.0.0"
	e.sys.version = "pihole-rbac 2.0.1-rc.1 (commit abc, built today)\nfrontend: embedded\n"
	e.request("v2.0.1-rc.1")
	if got := e.run(); got != StatusDone {
		t.Fatalf("status %q\n%s", got, e.out)
	}
	if !slices.Equal(e.src.asked, []string{"checksums v2.0.1-rc.1", "archive v2.0.1-rc.1 amd64"}) {
		t.Errorf("asked = %v (an explicit target needs no lookup)", e.src.asked)
	}
}

func TestUpdateRefusalsChangeNothing(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		setup   func(*env)
		status  string
		wantLog string
	}{
		{name: "older target", target: "v1.9.0", status: StatusFailed, wantLog: "downgrades are refused"},
		{name: "same target", target: "v2.0.0", status: StatusFailed, wantLog: "downgrades are refused"},
		// The table's CHECK lets this through; the updater's own parse doesn't.
		{name: "not a tag", target: "v02.1.0", status: StatusFailed, wantLog: "isn't a release tag"},
		{name: "already latest", setup: func(e *env) { e.src.latest = tag(e.t, "v2.0.0") }, status: StatusDone, wantLog: "nothing to do"},
		{name: "latest is older", setup: func(e *env) { e.src.latest = tag(e.t, "v1.0.0") }, status: StatusDone, wantLog: "nothing to do"},
		{name: "no release yet", setup: func(e *env) { e.src.latestErr = release.ErrNoRelease }, status: StatusFailed, wantLog: "No release has been published"},
		{name: "development build", setup: func(e *env) { e.current = "" }, status: StatusFailed, wantLog: "development build"},
		{name: "unsupported arch", setup: func(e *env) { e.u.Arch = "riscv64" }, status: StatusFailed, wantLog: "riscv64"},
		{name: "bad signature", setup: func(e *env) {
			e.src.checksumsErr = fmt.Errorf("checking the signature: %w", minisign.ErrInvalid)
		}, status: StatusFailed, wantLog: "signature is not valid"},
		{name: "no such release", target: "v9.0.0", setup: func(e *env) { e.src.checksumsErr = release.ErrNotFound }, status: StatusFailed, wantLog: "doesn't exist"},
		{name: "not an archive", setup: func(e *env) { e.src.archive = []byte("junk") }, status: StatusFailed, wantLog: "reading the archive"},
		{name: "wrong version inside", setup: func(e *env) {
			e.sys.version = "pihole-rbac 2.0.9 (commit abc, built today)\nfrontend: embedded\n"
		}, status: StatusFailed, wantLog: "not 2.1.0"},
		{name: "no frontend", setup: func(e *env) {
			e.sys.version = "pihole-rbac 2.1.0 (commit abc, built today)\nfrontend: not built\n"
		}, status: StatusFailed, wantLog: "without the frontend"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			if tt.setup != nil {
				tt.setup(e)
			}
			e.request(tt.target)
			if got := e.run(); got != tt.status {
				t.Fatalf("status %q, want %q\n%s", got, tt.status, e.out)
			}
			if r := e.row(); r.Status != tt.status || !strings.Contains(r.Log, tt.wantLog) {
				t.Errorf("row %s, log:\n%s", r.Status, r.Log)
			}
			if e.binary() != "old binary" || len(e.sys.calls) != 0 || len(e.backups()) != 0 {
				t.Errorf("something changed: binary %q, systemctl %v, backups %v", e.binary(), e.sys.calls, e.backups())
			}
			for _, suffix := range []string{".new", ".new.tmp", ".prev"} {
				if _, err := os.Stat(e.u.Binary + suffix); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("%s left behind", suffix)
				}
			}
		})
	}
}

func TestUpdateRollsBack(t *testing.T) {
	e := newEnv(t)
	e.request("")
	// The new version migrates the database, then never answers /healthz.
	e.sys.onRestart = func() {
		e.exec(`INSERT INTO settings (key, value, updated_at) VALUES ('migrated-by-new-version', '{}', 1)`)
		e.sys.healthy = func(int) bool { return false }
	}
	// After the rollback, the old version is healthy again.
	orig := e.sys
	e.u.System = &rollbackSystem{fakeSystem: orig, afterStart: func() { orig.healthy = nil }}

	if got := e.run(); got != StatusRolledBack {
		t.Fatalf("status %q\n%s", got, e.out)
	}
	if e.binary() != "old binary" {
		t.Errorf("binary = %q", e.binary())
	}
	if e.markers() != 0 {
		t.Error("the database wasn't restored from the backup")
	}
	if !slices.Equal(orig.calls, []string{"restart pihole-rbac.service", "stop pihole-rbac.service", "start pihole-rbac.service"}) {
		t.Errorf("systemctl = %v", orig.calls)
	}
	r := e.row()
	if r.Status != StatusRolledBack {
		t.Errorf("status %s", r.Status)
	}
	// Lines written after the backup were lost with the restore and written again.
	for _, want := range []string{"Backed up the database", "Installed", "didn't become healthy", "Rolling back to v2.0.0",
		"Rolled back: v2.0.0 is running and healthy again"} {
		if !strings.Contains(r.Log, want) {
			t.Errorf("log lacks %q:\n%s", want, r.Log)
		}
	}
	if strings.Count(r.Log, "Backed up the database") != 1 {
		t.Errorf("a line was written twice:\n%s", r.Log)
	}
	if !slices.Contains(orig.chowned, "pihole-rbac.db.restore") {
		t.Errorf("the restored database wasn't given to the service user: %v", orig.chowned)
	}
}

// rollbackSystem runs afterStart when the service is started again, so the old version can become healthy.
type rollbackSystem struct {
	*fakeSystem
	afterStart func()
}

func (r *rollbackSystem) Systemctl(ctx context.Context, args ...string) error {
	err := r.fakeSystem.Systemctl(ctx, args...)
	if args[0] == "start" {
		r.afterStart()
	}
	return err
}

func TestRollbackNeedsAttention(t *testing.T) {
	e := newEnv(t)
	e.request("")
	e.sys.healthy = func(int) bool { return false } // neither version becomes healthy
	if got := e.run(); got != StatusRolledBack {
		t.Fatalf("status %q", got)
	}
	r := e.row()
	if !strings.Contains(r.Log, "The rollback needs attention") || !strings.Contains(r.Log, ".prev") {
		t.Errorf("log:\n%s", r.Log)
	}
	if e.binary() != "old binary" {
		t.Errorf("binary = %q", e.binary())
	}
}

func TestHealthMustLast(t *testing.T) {
	e := newEnv(t)
	e.request("")
	// Healthy once, then gone: a version that crashes soon after starting is rolled back.
	e.sys.healthy = func(call int) bool { return call == 1 || call > 2 }
	if got := e.run(); got != StatusRolledBack {
		t.Fatalf("status %q\n%s", got, e.out)
	}
	if r := e.row(); !strings.Contains(r.Log, "healthy at first, then not") {
		t.Errorf("log:\n%s", r.Log)
	}
}

func TestNoPendingRequest(t *testing.T) {
	e := newEnv(t)
	if got := e.run(); got != "" {
		t.Fatalf("status %q", got)
	}
	if len(e.src.asked) != 0 || len(e.sys.calls) != 0 {
		t.Error("did something with no request")
	}
}

func TestStaleRequestStaysFailed(t *testing.T) {
	e := newEnv(t)
	e.request("")
	// The app gives up on the request while the updater is busy with it.
	e.src.latestErr = nil
	e.sys.onRestart = func() {
		e.exec(`UPDATE update_requests SET status = 'failed', finished_at = 1`)
	}
	if got := e.run(); got != StatusDone {
		t.Fatalf("status %q", got)
	}
	r := e.row()
	if r.Status != StatusFailed || !strings.Contains(r.Log, "already marked this request failed") {
		t.Errorf("row %s:\n%s", r.Status, r.Log)
	}
}

func TestPruneBackups(t *testing.T) {
	dir := t.TempDir()
	names := []string{
		"v2.0.0-20261001T000000.000Z.db",
		"v10.0.0-20261002T000000.000Z.db",
		"v2.0.0-rc.1-20261003T000000.000Z.db",
		"v2.1.0-20261004T000000.000Z.db",
		"v2.1.1-20261005T000000.000Z.db",
		"v2.2.0-20261006T000000.000Z.db",
		"v2.3.0-20261007T000000.000Z.db",
		"pre-migrate-20261001T000000.000Z-from1.db", // the app's, never touched here
		"v2.0.0-notatime.db",                        // not ours
		"notes.txt",
	}
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := pruneBackups(root, ".", 5); err != nil {
		t.Fatal(err)
	}
	var left []string
	entries, _ := os.ReadDir(dir)
	for _, en := range entries {
		left = append(left, en.Name())
	}
	for _, gone := range names[:2] {
		if slices.Contains(left, gone) {
			t.Errorf("%s kept", gone)
		}
	}
	for _, kept := range names[2:] {
		if !slices.Contains(left, kept) {
			t.Errorf("%s removed", kept)
		}
	}
}
