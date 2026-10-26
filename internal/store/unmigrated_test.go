// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenUnmigrated(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if _, err := OpenUnmigrated(ctx, dir); err == nil || !strings.Contains(err.Error(), "no database") {
		t.Fatalf("missing database: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, FileName)); err == nil {
		t.Fatal("OpenUnmigrated created a database")
	}

	st, err := Open(ctx, Options{DataDir: dir, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	// A schema newer than this binary, as after an update: Open refuses it, OpenUnmigrated doesn't care.
	d, err := OpenUnmigrated(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO goose_db_version (version_id, is_applied) VALUES (999, 1)`); err != nil {
		t.Fatal(err)
	}
	d.Close()
	if _, err := Open(ctx, Options{DataDir: dir, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}); err == nil {
		t.Fatal("Open accepted a newer schema")
	}
	d, err = OpenUnmigrated(ctx, dir)
	if err != nil {
		t.Fatalf("OpenUnmigrated on a newer schema: %v", err)
	}
	defer d.Close()
	var n int
	if err := d.QueryRow(`SELECT count(*) FROM update_requests`).Scan(&n); err != nil {
		t.Fatal(err)
	}
}
