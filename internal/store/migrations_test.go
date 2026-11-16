// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"

	"github.com/Kate-0713/pihole-rbac/migrations"
)

// Migrations are append-only once released: goose records a version as applied and never runs it again, so an edit
// to a released migration would reach fresh installs but never an existing database. Each released migration's
// SHA-256 (with line endings normalised to LF) is pinned here. A new migration is added to this list when the
// release that contains it ships, never changed afterwards.
var releasedMigrations = map[string]string{
	"00001_initial.sql":                      "591c78db4325b3908552fa32d64d5acb39f2347c9c3d08a9f5390d8d2caa25cf", // v2.0.0
	"00002_blocking_indefinite.sql":          "535cbc74e10592a8d1fb651e1e791fc8e5bc2e126887ca446bb57197f56a90a9", // v2.1.0
	"00003_client_reset_scheduled_event.sql": "17763399adcd6fdda0a87ca77fd98c17ef70102912471595596d8bf840f4b094", // v2.1.0
	"00004_piholegroups_edit.sql":            "47b6db8acabd7369e41a283d7137099eb1531119c75a783fe649c72306f5def0", // v2.2.0
	"00005_lists_gravity.sql":                "e021f6da7d3a49a4d49eba551b3e0c19ea690577a06e24d9777141f925a5842a", // v2.3.0
	"00006_localdns.sql":                     "f5a0d8ab1e2eaadd1fcc082618d1ed7e21fc9202483601fd957947e1d57a701f", // v2.4.0
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

// TestUpgradeFromV2_1_3: a database as v2.1.3 left it (version 3, unchanged since v2.1.0) gets piholegroups.edit on
// the builtin admin role only. A role that can edit domains and clients doesn't get it.
func TestUpgradeFromV2_1_3(t *testing.T) {
	dir := t.TempDir()
	s, err := openAt(t, dir, migrationsUpTo(t, 3))
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO roles (id, name, created_at) VALUES (10, 'operators', 1)`,
		`INSERT INTO role_grants (role_id, permission, scope_type) VALUES (10, 'domains.edit', 'all'), (10, 'clients.edit', 'all')`,
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
	grants := `SELECT count(*) FROM role_grants WHERE role_id = ? AND permission = 'piholegroups.edit' AND scope_type = 'all'`
	for _, tt := range []struct {
		role int
		want int
	}{{1, 1}, {10, 0}} {
		var n int
		if err := s.r.QueryRow(grants, tt.role).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != tt.want {
			t.Errorf("role %d has %d piholegroups.edit grants, want %d", tt.role, n, tt.want)
		}
	}
}

// TestUpgradeFromV2_2_0: a database as v2.2.0 left it (version 4) gets lists.view, lists.edit and gravity.run on the
// builtin admin role only. A role that can edit domains and Pi-hole groups doesn't get them. Migrating down to 4
// removes them everywhere, and up again restores the builtin admin's.
func TestUpgradeFromV2_2_0(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := openAt(t, dir, migrationsUpTo(t, 4))
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO roles (id, name, created_at) VALUES (10, 'operators', 1)`,
		`INSERT INTO role_grants (role_id, permission, scope_type) VALUES (10, 'domains.edit', 'all'), (10, 'piholegroups.edit', 'all')`,
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
	perms := []string{"lists.view", "lists.edit", "gravity.run"}
	check := func(when string, want map[int]int) {
		t.Helper()
		for role, n := range want {
			for _, p := range perms {
				var got int
				q := `SELECT count(*) FROM role_grants WHERE role_id = ? AND permission = ? AND scope_type = 'all'`
				if err := s.r.QueryRow(q, role, p).Scan(&got); err != nil {
					t.Fatal(err)
				}
				if got != n {
					t.Errorf("%s: role %d has %d %s grants, want %d", when, role, got, p, n)
				}
			}
		}
	}
	check("after upgrading", map[int]int{1: 1, 10: 0})

	// A grant on another role, so the Down section's first DELETE has something to remove.
	if _, err := s.w.Exec(`INSERT INTO role_grants (role_id, permission, scope_type) VALUES (10, 'lists.view', 'all')`); err != nil {
		t.Fatal(err)
	}
	p, err := goose.NewProvider(goose.DialectSQLite3, s.w, migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.DownTo(ctx, 4); err != nil {
		t.Fatalf("down to 4: %v", err)
	}
	check("after migrating down", map[int]int{1: 0, 10: 0})
	if _, err := s.w.Exec(`DELETE FROM role_grants WHERE role_id = 1 AND permission = 'domains.view'`); err == nil {
		t.Error("the builtin admin's grants can be deleted after migrating down: the trigger wasn't recreated")
	}
	if _, err := p.Up(ctx); err != nil {
		t.Fatalf("up again: %v", err)
	}
	check("after migrating up again", map[int]int{1: 1, 10: 0})
}

// TestUpgradeFromV2_3_0: a database as v2.3.0 left it (version 5) gets localdns.view and localdns.edit on the builtin
// admin role only. A role that can edit lists doesn't get them. Migrating down to 5 removes them everywhere, and up
// again restores the builtin admin's.
func TestUpgradeFromV2_3_0(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := openAt(t, dir, migrationsUpTo(t, 5))
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO roles (id, name, created_at) VALUES (10, 'operators', 1)`,
		`INSERT INTO role_grants (role_id, permission, scope_type) VALUES (10, 'lists.edit', 'all'), (10, 'domains.edit', 'all')`,
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
	perms := []string{"localdns.view", "localdns.edit"}
	check := func(when string, want map[int]int) {
		t.Helper()
		for role, n := range want {
			for _, p := range perms {
				var got int
				q := `SELECT count(*) FROM role_grants WHERE role_id = ? AND permission = ? AND scope_type = 'all'`
				if err := s.r.QueryRow(q, role, p).Scan(&got); err != nil {
					t.Fatal(err)
				}
				if got != n {
					t.Errorf("%s: role %d has %d %s grants, want %d", when, role, got, p, n)
				}
			}
		}
	}
	check("after upgrading", map[int]int{1: 1, 10: 0})

	// A grant on another role, so the Down section's first DELETE has something to remove.
	if _, err := s.w.Exec(`INSERT INTO role_grants (role_id, permission, scope_type) VALUES (10, 'localdns.view', 'all')`); err != nil {
		t.Fatal(err)
	}
	p, err := goose.NewProvider(goose.DialectSQLite3, s.w, migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.DownTo(ctx, 5); err != nil {
		t.Fatalf("down to 5: %v", err)
	}
	check("after migrating down", map[int]int{1: 0, 10: 0})
	var lists int
	if err := s.r.QueryRow(`SELECT count(*) FROM role_grants WHERE role_id = 10 AND permission = 'lists.edit'`).Scan(&lists); err != nil || lists != 1 {
		t.Errorf("migrating down touched other grants: %d lists.edit grants on role 10, %v", lists, err)
	}
	if _, err := s.w.Exec(`DELETE FROM role_grants WHERE role_id = 1 AND permission = 'domains.view'`); err == nil {
		t.Error("the builtin admin's grants can be deleted after migrating down: the trigger wasn't recreated")
	}
	if _, err := p.Up(ctx); err != nil {
		t.Fatalf("up again: %v", err)
	}
	check("after migrating up again", map[int]int{1: 1, 10: 0})
}

// TestUpgradeFromV2_4_0: a database as v2.4.0 left it (version 6) gets the schedules table and schedules.manage on
// the builtin admin role only. A role that can toggle blocking doesn't get it. The table's checks refuse a schedule
// that mixes the weekly and one-off fields, and deleting an instance deletes its schedules. Migrating down to 6
// removes both, and up again restores them.
func TestUpgradeFromV2_4_0(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := openAt(t, dir, migrationsUpTo(t, 6))
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO roles (id, name, created_at) VALUES (10, 'operators', 1)`,
		`INSERT INTO role_grants (role_id, permission, scope_type) VALUES (10, 'blocking.toggle', 'all'), (10, 'piholegroups.edit', 'all')`,
		`INSERT INTO instances (id, name, base_url, created_at) VALUES (5, 'pihole1', 'https://pihole1', 1)`,
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
	check := func(when string, want map[int]int) {
		t.Helper()
		for role, n := range want {
			var got int
			q := `SELECT count(*) FROM role_grants WHERE role_id = ? AND permission = 'schedules.manage' AND scope_type = 'all'`
			if err := s.r.QueryRow(q, role).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != n {
				t.Errorf("%s: role %d has %d schedules.manage grants, want %d", when, role, got, n)
			}
		}
	}
	check("after upgrading", map[int]int{1: 1, 10: 0})

	const cols = `(name, instance_id, kind, pihole_group, repeat, days, start_min, end_min, end_days, time_zone, starts_at,
		ends_at, active_from, created_at, created_by, updated_at, updated_by)`
	if _, err := s.w.Exec(`INSERT INTO schedules ` + cols + ` VALUES ('Bedtime', 5, 'group_enabled', 'bedtime', 'weekly',
		31, 1260, 420, 1, 'Europe/London', NULL, NULL, 1, 1, 'admin', 1, 'admin')`); err != nil {
		t.Fatalf("a weekly group window: %v", err)
	}
	for name, values := range map[string]string{
		"weekly with a start time":  `('a', 5, 'blocking_off', NULL, 'weekly', 31, 480, 510, 0, 'UTC', 5, 10, 1, 1, 'a', 1, 'a')`,
		"once without an end":       `('b', 5, 'blocking_off', NULL, 'once', NULL, NULL, NULL, NULL, NULL, 5, NULL, 1, 1, 'a', 1, 'a')`,
		"once ending at its start":  `('c', 5, 'blocking_off', NULL, 'once', NULL, NULL, NULL, NULL, NULL, 5, 5, 1, 1, 'a', 1, 'a')`,
		"a group window, no group":  `('d', 5, 'group_disabled', NULL, 'once', NULL, NULL, NULL, NULL, NULL, 5, 10, 1, 1, 'a', 1, 'a')`,
		"blocking with a group":     `('e', 5, 'blocking_off', 'x', 'once', NULL, NULL, NULL, NULL, NULL, 5, 10, 1, 1, 'a', 1, 'a')`,
		"end_days over 7":           `('f', 5, 'blocking_off', NULL, 'weekly', 31, 480, 510, 8, 'UTC', NULL, NULL, 1, 1, 'a', 1, 'a')`,
		"a name taken, in any case": `('BEDTIME', 5, 'blocking_off', NULL, 'once', NULL, NULL, NULL, NULL, NULL, 5, 10, 1, 1, 'a', 1, 'a')`,
		"no instance and no group":  `('g', NULL, 'blocking_off', NULL, 'once', NULL, NULL, NULL, NULL, NULL, 5, 10, 1, 1, 'a', 1, 'a')`,
	} {
		if _, err := s.w.Exec(`INSERT INTO schedules ` + cols + ` VALUES ` + values); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := s.w.Exec(`DELETE FROM instances WHERE id = 5`); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.r.QueryRow(`SELECT count(*) FROM schedules`).Scan(&n); err != nil || n != 0 {
		t.Errorf("deleting the instance left %d schedules, %v", n, err)
	}

	// A grant on another role, so the Down section's first DELETE has something to remove.
	if _, err := s.w.Exec(`INSERT INTO role_grants (role_id, permission, scope_type) VALUES (10, 'schedules.manage', 'all')`); err != nil {
		t.Fatal(err)
	}
	p, err := goose.NewProvider(goose.DialectSQLite3, s.w, migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.DownTo(ctx, 6); err != nil {
		t.Fatalf("down to 6: %v", err)
	}
	check("after migrating down", map[int]int{1: 0, 10: 0})
	if err := s.r.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name = 'schedules'`).Scan(&n); err != nil || n != 0 {
		t.Errorf("migrating down left the schedules table: %d, %v", n, err)
	}
	var toggle int
	if err := s.r.QueryRow(`SELECT count(*) FROM role_grants WHERE role_id = 10 AND permission = 'blocking.toggle'`).Scan(&toggle); err != nil || toggle != 1 {
		t.Errorf("migrating down touched other grants: %d blocking.toggle grants on role 10, %v", toggle, err)
	}
	if _, err := s.w.Exec(`DELETE FROM role_grants WHERE role_id = 1 AND permission = 'domains.view'`); err == nil {
		t.Error("the builtin admin's grants can be deleted after migrating down: the trigger wasn't recreated")
	}
	if _, err := p.Up(ctx); err != nil {
		t.Fatalf("up again: %v", err)
	}
	check("after migrating up again", map[int]int{1: 1, 10: 0})
}

// TestUpgradeFromV2_6_0: a database as v2.6.0 left it (version 8) gets dhcp.view, dhcp.edit and dhcp.config on the
// builtin admin role only. A role that can edit local DNS doesn't get them. Migrating down to 8 removes them
// everywhere, and up again restores the builtin admin's.
func TestUpgradeFromV2_6_0(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := openAt(t, dir, migrationsUpTo(t, 8))
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO roles (id, name, created_at) VALUES (10, 'operators', 1)`,
		`INSERT INTO role_grants (role_id, permission, scope_type) VALUES (10, 'localdns.edit', 'all'), (10, 'domains.edit', 'all')`,
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
	perms := []string{"dhcp.view", "dhcp.edit", "dhcp.config"}
	check := func(when string, want map[int]int) {
		t.Helper()
		for role, n := range want {
			for _, p := range perms {
				var got int
				q := `SELECT count(*) FROM role_grants WHERE role_id = ? AND permission = ? AND scope_type = 'all'`
				if err := s.r.QueryRow(q, role, p).Scan(&got); err != nil {
					t.Fatal(err)
				}
				if got != n {
					t.Errorf("%s: role %d has %d %s grants, want %d", when, role, got, p, n)
				}
			}
		}
	}
	check("after upgrading", map[int]int{1: 1, 10: 0})

	// A grant on another role, so the Down section's first DELETE has something to remove.
	if _, err := s.w.Exec(`INSERT INTO role_grants (role_id, permission, scope_type) VALUES (10, 'dhcp.config', 'all')`); err != nil {
		t.Fatal(err)
	}
	p, err := goose.NewProvider(goose.DialectSQLite3, s.w, migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.DownTo(ctx, 8); err != nil {
		t.Fatalf("down to 8: %v", err)
	}
	check("after migrating down", map[int]int{1: 0, 10: 0})
	var dns int
	if err := s.r.QueryRow(`SELECT count(*) FROM role_grants WHERE role_id = 10 AND permission = 'localdns.edit'`).Scan(&dns); err != nil || dns != 1 {
		t.Errorf("migrating down touched other grants: %d localdns.edit grants on role 10, %v", dns, err)
	}
	if _, err := s.w.Exec(`DELETE FROM role_grants WHERE role_id = 1 AND permission = 'domains.view'`); err == nil {
		t.Error("the builtin admin's grants can be deleted after migrating down: the trigger wasn't recreated")
	}
	if _, err := p.Up(ctx); err != nil {
		t.Fatalf("up again: %v", err)
	}
	check("after migrating up again", map[int]int{1: 1, 10: 0})
}

// TestUpgradeFromV2_5_0: a database as v2.5.0 left it (version 7) gets the two temporary client change tables and no
// permission changes of its own (the DHCP grants a later migration adds aren't counted). The checks refuse an override with no target, two targets, an end before its start, or an
// unfinished status with a finish time. A client can have one active member row per instance, whatever the override,
// and a settled row frees it. A member can't be pending while inactive or settled as ok while active. Deleting an
// instance deletes its overrides, and an override's members go with it. Migrating down to 7 removes both tables, and
// up again restores them.
func TestUpgradeFromV2_5_0(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := openAt(t, dir, migrationsUpTo(t, 7))
	if err != nil {
		t.Fatal(err)
	}
	var grantsBefore int
	if err := s.r.QueryRow(`SELECT count(*) FROM role_grants WHERE permission NOT LIKE 'dhcp.%'`).Scan(&grantsBefore); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO instances (id, name, base_url, created_at) VALUES (5, 'pihole1', 'https://pihole1', 1), (6, 'pihole2', 'https://pihole2', 1)`,
		`INSERT INTO instance_groups (id, name, mode, primary_instance_id, created_at) VALUES (9, 'site', 'mirrored', 5, 1)`,
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
	var grantsAfter int
	if err := s.r.QueryRow(`SELECT count(*) FROM role_grants WHERE permission NOT LIKE 'dhcp.%'`).Scan(&grantsAfter); err != nil || grantsAfter != grantsBefore {
		t.Errorf("the upgrade changed grants: %d before, %d after, %v", grantsBefore, grantsAfter, err)
	}

	const cols = `(instance_id, group_id, client, starts_at, ends_at, status, created_by, created_at, finished_at)`
	insert := func(values string) error {
		_, err := s.w.Exec(`INSERT INTO client_group_overrides ` + cols + ` VALUES ` + values)
		return err
	}
	if err := insert(`(5, NULL, '10.0.0.5', 10, 20, 'active', 'admin', 1, NULL)`); err != nil {
		t.Fatalf("an override on an instance: %v", err)
	}
	if err := insert(`(NULL, 9, '10.0.0.5', 10, 20, 'active', 'admin', 1, NULL)`); err != nil {
		t.Fatalf("an override through a mirrored group: %v", err)
	}
	for name, values := range map[string]string{
		"no target":                 `(NULL, NULL, 'a', 10, 20, 'active', 'admin', 1, NULL)`,
		"two targets":               `(5, 9, 'a', 10, 20, 'active', 'admin', 1, NULL)`,
		"ending at its start":       `(5, NULL, 'a', 10, 10, 'active', 'admin', 1, NULL)`,
		"an empty client":           `(5, NULL, '', 10, 20, 'active', 'admin', 1, NULL)`,
		"an unknown status":         `(5, NULL, 'a', 10, 20, 'paused', 'admin', 1, NULL)`,
		"active with a finish time": `(5, NULL, 'a', 10, 20, 'active', 'admin', 1, 30)`,
		"reverted with no finish":   `(5, NULL, 'a', 10, 20, 'reverted', 'admin', 1, NULL)`,
	} {
		if err := insert(values); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := s.w.Exec(`UPDATE client_group_overrides SET ended_by = 'admin' WHERE id = 1`); err == nil {
		t.Error("ended_by without ended_at: accepted")
	}
	if _, err := s.w.Exec(`INSERT INTO client_group_overrides (instance_id, client, starts_at, ends_at, reason, created_by, created_at)
		VALUES (5, 'x', 1, 2, ?, 'a', 1)`, strings.Repeat("r", 201)); err == nil {
		t.Error("a reason over 200 characters: accepted")
	}

	const mcols = `(override_id, instance_id, client, original_groups, override_groups, active, revert_status)`
	member := func(values string) error {
		_, err := s.w.Exec(`INSERT INTO client_group_override_members ` + mcols + ` VALUES ` + values)
		return err
	}
	if err := member(`(1, 5, '10.0.0.5', '["Default","kids"]', '["Default"]', 1, 'pending')`); err != nil {
		t.Fatalf("a member: %v", err)
	}
	// The same client on the same instance through the group's override: one active override per client per instance.
	if err := member(`(2, 5, '10.0.0.5', '["Default"]', '["open"]', 1, 'pending')`); err == nil {
		t.Error("a second active override for a client on an instance was accepted")
	}
	if err := member(`(2, 6, '10.0.0.5', '["Default"]', '["open"]', 1, 'pending')`); err != nil {
		t.Errorf("the same client on another instance: %v", err)
	}
	if err := member(`(1, 5, '10.0.0.9', '[]', '[]', 1, 'pending')`); err == nil {
		t.Error("two member rows for one override and instance were accepted")
	}
	for name, values := range map[string]string{
		"original groups not an array": `(1, 6, '10.0.0.7', '{}', '[]', 1, 'pending')`,
		"not JSON":                     `(1, 6, '10.0.0.7', '[]', 'x', 1, 'pending')`,
		"settled ok but active":        `(1, 6, '10.0.0.7', '[]', '[]', 1, 'ok')`,
		"given up but active":          `(1, 6, '10.0.0.7', '[]', '[]', 1, 'given_up')`,
		"pending but inactive":         `(1, 6, '10.0.0.7', '[]', '[]', 0, 'pending')`,
		"an unknown revert status":     `(1, 6, '10.0.0.7', '[]', '[]', 1, 'done')`,
	} {
		if err := member(values); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := s.w.Exec(`UPDATE client_group_override_members SET active = 0, revert_status = 'ok' WHERE override_id = 1`); err != nil {
		t.Fatalf("settling a member: %v", err)
	}
	if err := member(`(2, 5, '10.0.0.5', '["Default"]', '["open"]', 1, 'pending')`); err != nil {
		t.Errorf("a settled member didn't free the client on its instance: %v", err)
	}

	// Deleting the mirrored group deletes the override made through it, and its members go with it. Deleting an
	// instance does the same for the overrides made on it.
	if _, err := s.w.Exec(`DELETE FROM instance_groups WHERE id = 9`); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.r.QueryRow(`SELECT count(*) FROM client_group_overrides WHERE id = 2`).Scan(&n); err != nil || n != 0 {
		t.Errorf("deleting the group left its override, %d, %v", n, err)
	}
	if err := s.r.QueryRow(`SELECT count(*) FROM client_group_override_members WHERE override_id = 2`).Scan(&n); err != nil || n != 0 {
		t.Errorf("deleting an override left %d members, %v", n, err)
	}
	if _, err := s.w.Exec(`DELETE FROM instances WHERE id = 5`); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"client_group_overrides", "client_group_override_members"} {
		if err := s.r.QueryRow(`SELECT count(*) FROM ` + table + ` WHERE instance_id = 5`).Scan(&n); err != nil || n != 0 {
			t.Errorf("deleting the instance left %d rows in %s, %v", n, table, err)
		}
	}

	p, err := goose.NewProvider(goose.DialectSQLite3, s.w, migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.DownTo(ctx, 7); err != nil {
		t.Fatalf("down to 7: %v", err)
	}
	if err := s.r.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name LIKE 'client_group_override%'`).Scan(&n); err != nil || n != 0 {
		t.Errorf("migrating down left %d objects, %v", n, err)
	}
	if _, err := p.Up(ctx); err != nil {
		t.Fatalf("up again: %v", err)
	}
	if err := s.r.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name IN ('client_group_overrides', 'client_group_override_members', 'client_group_override_members_active')`).Scan(&n); err != nil || n != 3 {
		t.Errorf("up again restored %d of 3 objects, %v", n, err)
	}
}
