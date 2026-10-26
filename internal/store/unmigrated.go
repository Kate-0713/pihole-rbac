// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// OpenUnmigrated opens an existing database in dataDir for the updater, with one writer connection and the same
// pragmas as Open, but runs no migrations and doesn't check the schema version: after an update the database can be
// newer than the updater's own code. The updater only touches update_requests, whose columns must therefore never
// change incompatibly. It doesn't create the database.
//
// Run as root, SQLite gives a -wal or -shm file it creates the database file's owner, so the service user can still
// open them afterwards.
func OpenUnmigrated(ctx context.Context, dataDir string) (*sql.DB, error) {
	path := filepath.Join(dataDir, FileName)
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("store: no database at %s", path)
		}
		return nil, err
	}
	d, err := sql.Open("sqlite", dsn(path, false))
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	d.SetMaxOpenConns(1)
	d.SetMaxIdleConns(1)
	if err := checkPragmas(ctx, d, false); err != nil {
		d.Close()
		return nil, err
	}
	return d, nil
}

// BackupTimeFormat is the UTC time in backup file names: fixed width, so names with the same prefix sort by age.
const BackupTimeFormat = backupTimeFormat

// BackupDir is the backups directory inside a data directory.
func BackupDir(dataDir string) string { return filepath.Join(dataDir, backupDirName) }
