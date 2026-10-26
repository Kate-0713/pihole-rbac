// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package updater

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/Kate-0713/pihole-rbac/internal/store"
)

// pihole-rbac-update.service runs with UMask=0077. Whatever the updater creates must still get the modes the app and
// install.sh use: the backups directory 0750, backups and a restored database 0600, the binary and .prev 0755.
func TestModesUnderTheUnitsUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(old) })

	e := newEnv(t)
	e.request("")
	if got := e.run(); got != StatusDone {
		t.Fatalf("status %q\n%s", got, e.out)
	}
	dir := store.BackupDir(e.u.DataDir)
	backups := e.backups()
	if len(backups) != 1 {
		t.Fatalf("backups = %v", backups)
	}
	for path, want := range map[string]os.FileMode{
		dir:                            0o750,
		filepath.Join(dir, backups[0]): 0o600,
		e.u.Binary:                     0o755,
		e.u.Binary + ".prev":           0o755,
	} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != want {
			t.Errorf("%s is %o, want %o", path, fi.Mode().Perm(), want)
		}
	}
}
