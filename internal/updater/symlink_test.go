// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package updater

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kate-0713/pihole-rbac/internal/store"
)

// The updater runs as root in a data directory the service user owns, so a compromised app could plant symlinks
// there. None may lead the updater outside the directory: a backups directory pointing at /usr/local/bin would
// otherwise be chowned to the app, handing it the binary root runs.

func TestBackupsSymlinkIsRefused(t *testing.T) {
	e := newEnv(t)
	outside := t.TempDir()
	if err := os.Symlink(outside, store.BackupDir(e.u.DataDir)); err != nil {
		t.Fatal(err)
	}
	e.request("")
	if got := e.run(); got != StatusFailed {
		t.Fatalf("status %q, want failed\n%s", got, e.out)
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Errorf("the updater wrote through the symlink: %v", entries)
	}
	if fi, err := os.Stat(outside); err != nil || fi.Mode().Perm() == 0o750 {
		t.Errorf("the symlink's target was changed: %v %v", fi.Mode(), err)
	}
	if len(e.sys.chowned) != 0 {
		t.Errorf("chowned %v", e.sys.chowned)
	}
	if e.binary() != "old binary" || len(e.sys.calls) != 0 {
		t.Errorf("something changed: binary %q, systemctl %v", e.binary(), e.sys.calls)
	}
	if !strings.Contains(e.row().Log, "isn't a directory") {
		t.Errorf("log:\n%s", e.row().Log)
	}
}

func TestDatabaseSymlinkIsRefused(t *testing.T) {
	e := newEnv(t)
	e.request("")
	// Move the real database elsewhere and leave a symlink to it.
	outside := filepath.Join(t.TempDir(), "elsewhere.db")
	db := filepath.Join(e.u.DataDir, store.FileName)
	if err := os.Rename(db, outside); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, db); err != nil {
		t.Fatal(err)
	}
	if _, err := e.u.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "isn't a regular file") {
		t.Fatalf("Run: %v", err)
	}
	if e.binary() != "old binary" || len(e.sys.calls) != 0 || len(e.sys.chowned) != 0 {
		t.Errorf("something changed: binary %q, systemctl %v, chowned %v", e.binary(), e.sys.calls, e.sys.chowned)
	}
}

func TestRollbackDoesNotRestoreThroughASymlink(t *testing.T) {
	e := newEnv(t)
	e.request("")
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("root's secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	// While the new version runs, the backup is swapped for a symlink to a file only root can read; then the new
	// version never becomes healthy, so the updater rolls back and restores "the backup".
	e.sys.onRestart = func() {
		dir := store.BackupDir(e.u.DataDir)
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 1 {
			t.Fatalf("backups %v %v", entries, err)
		}
		backup := filepath.Join(dir, entries[0].Name())
		if err := os.Remove(backup); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(secret, backup); err != nil {
			t.Fatal(err)
		}
		e.sys.healthy = func(int) bool { return false }
	}
	orig := e.sys
	e.u.System = &rollbackSystem{fakeSystem: orig, afterStart: func() { orig.healthy = nil }}

	if got := e.run(); got != StatusRolledBack {
		t.Fatalf("status %q\n%s", got, e.out)
	}
	if b, _ := os.ReadFile(filepath.Join(e.u.DataDir, store.FileName)); strings.Contains(string(b), "root's secret") {
		t.Fatal("the symlink's target was copied over the database")
	}
	if !strings.Contains(e.out.String(), "needs attention") || !strings.Contains(e.out.String(), "isn't a regular file") {
		t.Errorf("the refused restore wasn't reported:\n%s", e.out)
	}
}
