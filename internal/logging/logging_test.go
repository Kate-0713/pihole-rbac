// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package logging

import (
	"bytes"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// clock is a settable time source for the tests.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func day(s string) time.Time {
	t, err := time.ParseInLocation("2006-01-02 15:04", s, time.Local)
	if err != nil {
		panic(err)
	}
	return t
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func files(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	slices.Sort(out)
	return out
}

func TestStdoutOnly(t *testing.T) {
	var stdout bytes.Buffer
	l, err := Open(Options{Stdout: &stdout, Level: slog.LevelInfo})
	if err != nil {
		t.Fatal(err)
	}
	l.Logger.Debug("hidden")
	l.Logger.Info("hello", "k", "v")
	if got := stdout.String(); !strings.Contains(got, "msg=hello k=v") || strings.Contains(got, "hidden") {
		t.Fatalf("stdout = %q", got)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFileAndStdout(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logs") // created by Open
	c := &clock{day("2026-10-26 09:00")}
	var stdout bytes.Buffer
	l, err := Open(Options{Dir: dir, RetentionDays: 30, Stdout: &stdout, Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	l.Logger.Info("first")
	if _, err := l.Writer.Write([]byte("AUDIT line\n")); err != nil {
		t.Fatal(err)
	}

	got := read(t, Name(dir, "2026-10-26"))
	if !strings.Contains(got, "msg=first") || !strings.Contains(got, "AUDIT line") {
		t.Fatalf("file = %q", got)
	}
	if !strings.Contains(stdout.String(), "msg=first") || !strings.Contains(stdout.String(), "AUDIT line") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if runtime.GOOS != "windows" { // Windows has no Unix permission bits
		fi, err := os.Stat(Name(dir, "2026-10-26"))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm()&0o007 != 0 {
			t.Fatalf("log file mode %v is readable by others", fi.Mode().Perm())
		}
		di, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if di.Mode().Perm()&0o007 != 0 {
			t.Fatalf("log directory mode %v is open to others", di.Mode().Perm())
		}
	}
}

func TestRotatesAtMidnight(t *testing.T) {
	dir := t.TempDir()
	c := &clock{day("2026-10-26 23:59")}
	l, err := Open(Options{Dir: dir, Stdout: &bytes.Buffer{}, Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	l.Logger.Info("before")
	c.t = day("2026-10-27 00:00")
	l.Logger.Info("after")

	if got := files(t, dir); !slices.Equal(got, []string{"pihole-rbac-2026-10-26.log", "pihole-rbac-2026-10-27.log"}) {
		t.Fatalf("files = %v", got)
	}
	if a, b := read(t, Name(dir, "2026-10-26")), read(t, Name(dir, "2026-10-27")); !strings.Contains(a, "before") ||
		strings.Contains(a, "after") || !strings.Contains(b, "after") {
		t.Fatalf("26th %q, 27th %q", a, b)
	}
}

func TestRestartAppends(t *testing.T) {
	dir := t.TempDir()
	c := &clock{day("2026-10-26 10:00")}
	for _, msg := range []string{"run one", "run two"} {
		l, err := Open(Options{Dir: dir, Stdout: &bytes.Buffer{}, Now: c.now})
		if err != nil {
			t.Fatal(err)
		}
		l.Logger.Info(msg)
		if err := l.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if got := read(t, Name(dir, "2026-10-26")); !strings.Contains(got, "run one") || !strings.Contains(got, "run two") {
		t.Fatalf("file = %q", got)
	}
}

func TestPrune(t *testing.T) {
	tests := []struct {
		name      string
		retention int
		want      []string
	}{
		{"keeps the last 7 days", 7, []string{
			"notes.txt", "pihole-rbac-2026-10-19.log", "pihole-rbac-2026-10-25.log", "pihole-rbac-2026-10-26.log",
			"pihole-rbac-backup.log", "pihole-rbac-old.log.gz", "subdir",
		}},
		{"0 keeps everything", 0, []string{
			"notes.txt", "pihole-rbac-2026-01-01.log", "pihole-rbac-2026-10-18.log", "pihole-rbac-2026-10-19.log",
			"pihole-rbac-2026-10-25.log", "pihole-rbac-2026-10-26.log", "pihole-rbac-backup.log",
			"pihole-rbac-old.log.gz", "subdir",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			// Ours by name and date, and things that only look like ours, which must survive.
			for _, name := range []string{
				"pihole-rbac-2026-01-01.log", "pihole-rbac-2026-10-18.log", "pihole-rbac-2026-10-19.log",
				"pihole-rbac-2026-10-25.log", "pihole-rbac-backup.log", "pihole-rbac-old.log.gz", "notes.txt",
			} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte("x\n"), 0o640); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Mkdir(filepath.Join(dir, "subdir"), 0o750); err != nil {
				t.Fatal(err)
			}
			c := &clock{day("2026-10-26 08:00")}
			l, err := Open(Options{Dir: dir, RetentionDays: tt.retention, Stdout: &bytes.Buffer{}, Now: c.now})
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			if got := files(t, dir); !slices.Equal(got, tt.want) {
				t.Fatalf("files = %v\nwant    %v", got, tt.want)
			}
		})
	}
}

func TestPruneOnRotation(t *testing.T) {
	dir := t.TempDir()
	c := &clock{day("2026-10-26 12:00")}
	l, err := Open(Options{Dir: dir, RetentionDays: 1, Stdout: &bytes.Buffer{}, Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	l.Logger.Info("a")
	c.t = day("2026-10-27 12:00")
	l.Logger.Info("b")
	c.t = day("2026-10-28 12:00")
	l.Logger.Info("c")
	if got := files(t, dir); !slices.Equal(got, []string{"pihole-rbac-2026-10-27.log", "pihole-rbac-2026-10-28.log"}) {
		t.Fatalf("files = %v", got)
	}
}

func TestUnwritableDirectoryFailsOpen(t *testing.T) {
	// A regular file where the directory should be fails on every platform, as root too.
	parent := t.TempDir()
	blocker := filepath.Join(parent, "logs")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Open(Options{Dir: blocker, Stdout: &bytes.Buffer{}})
	if err == nil || !strings.Contains(err.Error(), "log directory") {
		t.Fatalf("err = %v, want a log directory error", err)
	}
}

// A file that can't be opened at a day change keeps the previous day's file and reports the problem once, and the
// line still reaches stdout.
func TestRotationFailureKeepsWriting(t *testing.T) {
	dir := t.TempDir()
	c := &clock{day("2026-10-26 23:00")}
	var stdout, stderr bytes.Buffer
	l, err := Open(Options{Dir: dir, Stdout: &stdout, Stderr: &stderr, Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	// A directory where the next day's file should be makes opening it fail.
	if err := os.Mkdir(Name(dir, "2026-10-27"), 0o750); err != nil {
		t.Fatal(err)
	}
	c.t = day("2026-10-27 00:01")
	l.Logger.Info("one")
	l.Logger.Info("two")

	if got := read(t, Name(dir, "2026-10-26")); !strings.Contains(got, "one") || !strings.Contains(got, "two") {
		t.Fatalf("previous file = %q", got)
	}
	if !strings.Contains(stdout.String(), "two") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if n := strings.Count(stderr.String(), "logging:"); n != 1 {
		t.Fatalf("stderr reported %d times: %q", n, stderr.String())
	}
}

func TestWriteAfterClose(t *testing.T) {
	dir := t.TempDir()
	var stdout bytes.Buffer
	l, err := Open(Options{Dir: dir, Stdout: &stdout})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	l.Logger.Info("late")
	if !strings.Contains(stdout.String(), "late") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		t.Fatal("directory removed")
	}
}
