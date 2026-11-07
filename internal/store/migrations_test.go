// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"testing"

	"github.com/Kate-0713/pihole-rbac/migrations"
)

// Migrations are append-only once released: goose records a version as applied and never runs it again, so an edit
// to a released migration would reach fresh installs but never an existing database. Each released migration's
// SHA-256 (with line endings normalised to LF) is pinned here. A new migration is added to this list when the
// release that contains it ships, never changed afterwards.
var releasedMigrations = map[string]string{
	"00001_initial.sql": "591c78db4325b3908552fa32d64d5acb39f2347c9c3d08a9f5390d8d2caa25cf", // v2.0.0
}

func TestReleasedMigrationsUnchanged(t *testing.T) {
	for name, want := range releasedMigrations {
		data, err := fs.ReadFile(migrations.FS, name)
		if err != nil {
			t.Errorf("released migration %s is missing: %v", name, err)
			continue
		}
		sum := sha256.Sum256(bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n")))
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Errorf("released migration %s has changed (sha256 %s, want %s): add a new migration instead", name, got, want)
		}
	}
}

// TestUpgradeFromV2_0_0: a database as v2.0.0 left it gets blocking.indefinite on the builtin admin role only, and
// every channel that received client_reset also receives client_reset_scheduled.
func TestUpgradeFromV2_0_0(t *testing.T) {
	dir := t.TempDir()
	s, err := openAt(t, dir, migrationsUpTo(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO roles (id, name, created_at) VALUES (10, 'operators', 1)`,
		`INSERT INTO role_grants (role_id, permission, scope_type) VALUES (10, 'blocking.toggle', 'all')`,
		`INSERT INTO notification_channels (id, kind, name, created_at) VALUES (1, 'discord', 'resets', 1)`,
		`INSERT INTO notification_channels (id, kind, name, created_at) VALUES (2, 'discord', 'logins', 1)`,
		`INSERT INTO notification_rules (channel_id, event) VALUES (1, 'client_reset'), (1, 'login'), (2, 'login')`,
	} {
		if _, err := s.w.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	s.Close()

	s, err = openAt(t, dir, migrations.FS)
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := s.r.QueryRow(q, args...).Scan(&n); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return n
	}
	grants := `SELECT count(*) FROM role_grants WHERE role_id = ? AND permission = 'blocking.indefinite' AND scope_type = 'all'`
	if n := count(grants, 1); n != 1 {
		t.Errorf("builtin admin has %d blocking.indefinite grants, want 1", n)
	}
	if n := count(grants, 10); n != 0 {
		t.Errorf("a role with blocking.toggle was given blocking.indefinite (%d grants)", n)
	}
	rules := `SELECT count(*) FROM notification_rules WHERE channel_id = ? AND event = ?`
	for _, tt := range []struct {
		channel int
		event   string
		want    int
	}{
		{1, "client_reset", 1},
		{1, "client_reset_scheduled", 1},
		{1, "login", 1},
		{2, "login", 1},
		{2, "client_reset_scheduled", 0},
	} {
		if n := count(rules, tt.channel, tt.event); n != tt.want {
			t.Errorf("channel %d, event %s: %d rules, want %d", tt.channel, tt.event, n, tt.want)
		}
	}
}
