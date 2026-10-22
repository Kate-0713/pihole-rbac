// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const (
	// Pre-migration backups are named pre-migrate-<UTC time>-from<schema version>.db. The time comes first and is
	// fixed width, so sorting by name sorts by age. The updater's own backups use a different prefix and aren't
	// touched by pruneBackups.
	backupPrefix     = "pre-migrate-"
	backupTimeFormat = "20060102T150405.000Z"
	backupDirName    = "backups"
)

func (s *Store) backupDir() string {
	return filepath.Join(s.dataDir, backupDirName)
}

// backup writes a consistent copy of the database to the backups directory with VACUUM INTO and returns its path.
// It fails if the file already exists.
func (s *Store) backup(ctx context.Context, name string) (string, error) {
	dir := s.backupDir()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	dst := filepath.Join(dir, name)
	if _, err := os.Stat(dst); err == nil {
		return "", fmt.Errorf("%s already exists", dst)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	if _, err := s.w.ExecContext(ctx, `VACUUM INTO ?`, dst); err != nil {
		return "", err
	}
	_ = os.Chmod(dst, 0o600) // best effort; the directory is 0750 anyway
	return dst, nil
}

// pruneBackups keeps the newest `keep` pre-migration backups in dir and deletes the rest.
func pruneBackups(dir string, keep int) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		if e.Type().IsRegular() && strings.HasPrefix(e.Name(), backupPrefix) && strings.HasSuffix(e.Name(), ".db") {
			names = append(names, e.Name())
		}
	}
	if len(names) <= keep {
		return nil
	}
	slices.Sort(names)
	var errs []error
	for _, n := range names[:len(names)-keep] {
		errs = append(errs, os.Remove(filepath.Join(dir, n)))
	}
	return errors.Join(errs...)
}
