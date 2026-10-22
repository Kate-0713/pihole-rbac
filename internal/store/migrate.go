// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"fmt"
	"io/fs"
	"time"

	"github.com/pressly/goose/v3"
)

// gooseTable is goose's default version table.
const gooseTable = "goose_db_version"

// migrate applies pending migrations. An existing database is backed up with VACUUM INTO first. A fresh one isn't,
// since there's nothing to lose. It refuses to touch a database that has tables but no migration history (probably
// the wrong file), or one whose schema is newer than this binary (an old binary after a partial rollback).
func (s *Store) migrate(ctx context.Context, migrationsFS fs.FS) error {
	p, err := goose.NewProvider(goose.DialectSQLite3, s.w, migrationsFS)
	if err != nil {
		return fmt.Errorf("store: load migrations: %w", err)
	}
	sources := p.ListSources()
	if len(sources) == 0 {
		return fmt.Errorf("store: no migrations found")
	}
	latest := sources[len(sources)-1].Version

	versioned, err := s.tableExists(ctx, gooseTable)
	if err != nil {
		return err
	}
	if !versioned {
		var n int
		if err := s.w.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_schema WHERE type = 'table'`).Scan(&n); err != nil {
			return fmt.Errorf("store: inspect database: %w", err)
		}
		if n > 0 {
			return fmt.Errorf("store: %s has %d tables but no %s table, refusing to migrate it", s.path, n, gooseTable)
		}
	}

	if versioned {
		current, err := p.GetDBVersion(ctx)
		if err != nil {
			return fmt.Errorf("store: read schema version: %w", err)
		}
		if current > latest {
			return fmt.Errorf("store: database schema is version %d but this binary only knows up to %d", current, latest)
		}
		pending, err := hasPending(ctx, p)
		if err != nil {
			return err
		}
		if !pending {
			return nil
		}
		name := fmt.Sprintf("%s%s-from%d.db", backupPrefix, time.Now().UTC().Format(backupTimeFormat), current)
		path, err := s.backup(ctx, name)
		if err != nil {
			return fmt.Errorf("store: backup before migrating: %w", err)
		}
		s.log.Info("database backed up before migrating", "path", path, "from_version", current)
		if err := pruneBackups(s.backupDir(), s.keepBackups); err != nil {
			// Not fatal: a failed prune only leaves extra backups behind.
			s.log.Warn("pruning old database backups failed", "err", err)
		}
	}

	results, err := p.Up(ctx)
	for _, r := range results {
		s.log.Info("migration applied", "version", r.Source.Version, "file", r.Source.Path, "duration", r.Duration)
	}
	if err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	return nil
}

func hasPending(ctx context.Context, p *goose.Provider) (bool, error) {
	statuses, err := p.Status(ctx)
	if err != nil {
		return false, fmt.Errorf("store: migration status: %w", err)
	}
	for _, st := range statuses {
		if st.State == goose.StatePending {
			return true, nil
		}
	}
	return false, nil
}

func (s *Store) tableExists(ctx context.Context, name string) (bool, error) {
	var n int
	err := s.w.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = ?`, name).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("store: inspect database: %w", err)
	}
	return n > 0, nil
}
