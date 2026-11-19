// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
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
	"00007_schedules.sql":                    "319fb6d3405008ce0dc8f5526639e6af374ca5f5ca64a8978901887c094c71e0", // v2.5.0
	"00008_client_overrides.sql":             "5d25b3286763bd1f845cc6528a703a3277a8d219a6405805d0af4d7e661553de", // v2.6.0
	"00009_dhcp.sql":                         "9cc6d2d1141ecec2065dcc95f5283a75a080ccb5e749dba01caac7167cc26769", // v2.7.0
	"00010_totp.sql":                         "442ecf854f8c9b742d1567b37ba6b5b6081c7fff82e49ce6d2d0921ead89aeb9", // v2.8.0
	"00011_api_tokens.sql":                   "1d0a803a56da1f85b968a03b65ab2cab93838fe4c8ff8d0a49e7bf7738559d9b", // v2.9.0
	"00012_api_token_roles.sql":              "0121e51b26bb964e46b38519b2936c73ad4d8388b622fbda072aaee7538c17b1", // v2.9.0
	"00013_api_token_revoked_by.sql":         "3bd6a1e5871b5c26ec0f11665de7b19ff234b46c46fd42e36f6ef87139ddad0f", // v2.9.0
	"00014_log_destinations.sql":             "60d80598566f6b149f20338d60832022347cbca0ae48aa589292d4506c43acf6", // v2.10.0
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
// permission changes of its own (the DHCP and tokens.use grants later migrations add aren't counted). The checks refuse an override with no target, two targets, an end before its start, or an
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
	if err := s.r.QueryRow(`SELECT count(*) FROM role_grants WHERE permission NOT LIKE 'dhcp.%' AND permission NOT IN ('tokens.use', 'logging.manage')`).Scan(&grantsBefore); err != nil {
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
	if err := s.r.QueryRow(`SELECT count(*) FROM role_grants WHERE permission NOT LIKE 'dhcp.%' AND permission NOT IN ('tokens.use', 'logging.manage')`).Scan(&grantsAfter); err != nil || grantsAfter != grantsBefore {
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

// TestUpgradeFromV2_7_0: a database as v2.7.0 left it (version 9) gets the four two-factor tables and no change to
// its users, roles, grants or sessions (the tokens.use grant a later migration adds isn't counted). A secret needs its
// nonce and key ID, a user has one secret, recovery codes need a secret and go with it, the builtin admin role can be
// made to require TOTP, a user's own setting is required or exempt, and deleting a user removes all of theirs.
// Migrating down to 9 removes the tables, and up again restores them empty.
func TestUpgradeFromV2_7_0(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := openAt(t, dir, migrationsUpTo(t, 9))
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO users (id, username, source, password_hash, created_at) VALUES (5, 'alice', 'local', 'x', 1)`,
		`INSERT INTO users (id, username, source, ldap_dn, created_at) VALUES (6, 'bob', 'ldap', 'cn=bob,dc=lab', 1)`,
		`INSERT INTO roles (id, name, created_at) VALUES (10, 'operators', 1)`,
		`INSERT INTO role_grants (role_id, permission, scope_type) VALUES (10, 'domains.edit', 'all')`,
		`INSERT INTO user_roles (user_id, role_id) VALUES (5, 1), (5, 10)`,
		`INSERT INTO sessions (id_hash, public_id, user_id, created_at, expires_at, last_seen_at, roles_checked_at)
			VALUES (zeroblob(32), 'AAAAAAAAAAAAAAAAAAAAAA', 6, 1, 2, 1, 1)`,
		`INSERT INTO session_roles (session_id_hash, role_id) VALUES (zeroblob(32), 10)`,
	} {
		if _, err := s.w.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	counts := func(st *Store) string {
		t.Helper()
		var out []string
		for _, table := range []string{"users", "roles", "role_grants", "user_roles", "sessions", "session_roles"} {
			q := `SELECT count(*) FROM ` + table
			if table == "role_grants" {
				q += ` WHERE permission NOT IN ('tokens.use', 'logging.manage')` // added to the builtin admin by a later migration
			}
			var n int
			if err := st.r.QueryRow(q).Scan(&n); err != nil {
				t.Fatal(err)
			}
			out = append(out, fmt.Sprintf("%s=%d", table, n))
		}
		return strings.Join(out, " ")
	}
	before := counts(s)
	s.Close()

	s, err = openAt(t, dir, migrations.FS)
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	if after := counts(s); after != before {
		t.Errorf("the upgrade changed existing rows: %s before, %s after", before, after)
	}
	tables := []string{"user_totp", "user_recovery_codes", "role_totp_required", "user_totp_policy"}
	empty := func(when string) {
		t.Helper()
		for _, table := range tables {
			var n int
			if err := s.r.QueryRow(`SELECT count(*) FROM ` + table).Scan(&n); err != nil || n != 0 {
				t.Errorf("%s: %s has %d rows, %v", when, table, n, err)
			}
		}
	}
	empty("after upgrading")

	exec := func(q string, args ...any) error {
		_, err := s.w.Exec(q, args...)
		return err
	}
	const secret = `INSERT INTO user_totp (user_id, secret_ciphertext, secret_nonce, secret_key_id, created_at) VALUES `
	if err := exec(secret + `(5, x'0102', zeroblob(12), 'k1', 1)`); err != nil {
		t.Fatalf("a secret: %v", err)
	}
	var enabled sql.NullInt64
	var lastStep int64
	if err := s.r.QueryRow(`SELECT enabled_at, last_step FROM user_totp WHERE user_id = 5`).Scan(&enabled, &lastStep); err != nil || enabled.Valid || lastStep != 0 {
		t.Errorf("a new secret: enabled %v, last step %d, %v: want not enabled, step 0", enabled, lastStep, err)
	}
	for name, values := range map[string]string{
		"a second secret for a user": `(5, x'0102', zeroblob(12), 'k1', 1)`,
		"a secret for nobody":        `(99, x'0102', zeroblob(12), 'k1', 1)`,
		"an empty ciphertext":        `(6, x'', zeroblob(12), 'k1', 1)`,
		"no ciphertext":              `(6, NULL, zeroblob(12), 'k1', 1)`,
		"a short nonce":              `(6, x'0102', zeroblob(8), 'k1', 1)`,
		"no nonce":                   `(6, x'0102', NULL, 'k1', 1)`,
		"an empty key ID":            `(6, x'0102', zeroblob(12), '', 1)`,
		"no key ID":                  `(6, x'0102', zeroblob(12), NULL, 1)`,
	} {
		if err := exec(secret + values); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := exec(`UPDATE user_totp SET last_step = -1 WHERE user_id = 5`); err == nil {
		t.Error("a negative last step: accepted")
	}

	const code = `INSERT INTO user_recovery_codes (user_id, code_hash) VALUES `
	if err := exec(code + `(5, zeroblob(32))`); err != nil {
		t.Fatalf("a recovery code: %v", err)
	}
	for name, values := range map[string]string{
		"the same code twice":              `(5, zeroblob(32))`,
		"a code for a user with no secret": `(6, zeroblob(32))`,
		"a hash that isn't 32 bytes":       `(5, zeroblob(20))`,
	} {
		if err := exec(code + values); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// The builtin admin role's own row can't be updated, but it can be listed here.
	if err := exec(`INSERT INTO role_totp_required (role_id, set_at, set_by) VALUES (1, 1, 'alice'), (10, 1, 'alice')`); err != nil {
		t.Fatalf("requiring TOTP for the builtin admin role and another: %v", err)
	}
	if err := exec(`INSERT INTO role_totp_required (role_id, set_at) VALUES (99, 1)`); err == nil {
		t.Error("a requirement for a role that doesn't exist: accepted")
	}
	if err := exec(`INSERT INTO user_totp_policy (user_id, policy, set_at, set_by) VALUES (5, 'required', 1, 'alice'), (6, 'exempt', 1, 'alice')`); err != nil {
		t.Fatalf("users' own settings: %v", err)
	}
	for name, values := range map[string]string{
		"an unknown setting":   `(5, 'optional', 1, 'alice')`,
		"a second setting":     `(6, 'required', 1, 'alice')`,
		"a setting for nobody": `(99, 'required', 1, 'alice')`,
	} {
		if err := exec(`INSERT INTO user_totp_policy (user_id, policy, set_at, set_by) VALUES ` + values); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// Removing a role removes its requirement. Deleting a user removes their secret, codes and setting.
	if err := exec(`DELETE FROM role_grants WHERE role_id = 10`); err != nil {
		t.Fatal(err)
	}
	if err := exec(`DELETE FROM user_roles WHERE role_id = 10`); err != nil {
		t.Fatal(err)
	}
	if err := exec(`DELETE FROM sessions`); err != nil {
		t.Fatal(err)
	}
	if err := exec(`DELETE FROM roles WHERE id = 10`); err != nil {
		t.Fatalf("deleting a role that requires TOTP: %v", err)
	}
	var left int
	if err := s.r.QueryRow(`SELECT count(*) FROM role_totp_required`).Scan(&left); err != nil || left != 1 {
		t.Errorf("requirements after deleting a role: %d, %v, want 1", left, err)
	}
	if err := exec(`DELETE FROM users WHERE id = 5`); err != nil {
		t.Fatalf("deleting a user with TOTP: %v", err)
	}
	for table, want := range map[string]int{"user_totp": 0, "user_recovery_codes": 0, "user_totp_policy": 1} {
		var n int
		if err := s.r.QueryRow(`SELECT count(*) FROM ` + table).Scan(&n); err != nil || n != want {
			t.Errorf("after deleting the user: %s has %d rows, %v, want %d", table, n, err, want)
		}
	}

	p, err := goose.NewProvider(goose.DialectSQLite3, s.w, migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.DownTo(ctx, 9); err != nil {
		t.Fatalf("down to 9: %v", err)
	}
	for _, table := range tables {
		if ok, err := s.tableExists(ctx, table); err != nil || ok {
			t.Errorf("after migrating down: %s still exists (%v)", table, err)
		}
	}
	if _, err := p.Up(ctx); err != nil {
		t.Fatalf("up again: %v", err)
	}
	empty("after migrating up again")
}

// TestUpgradeFromV2_8_0: a database as v2.8.0 left it (version 10) gets tokens.use on the builtin admin role only, and
// the two API token tables, with no other change to its users, roles, grants or sessions. A token needs a 16-character
// public ID, a 32-byte hash, a name, an owner and an expiry after its creation. A name is unique per user among tokens
// that aren't revoked. A token's grants have role_grants' scope checks, can't be repeated, and go with the token, and
// deleting an instance or group a grant names is refused. Deleting a user removes their tokens. Migrating down to 10
// removes the tables and tokens.use everywhere and leaves the builtin admin's grants protected, and up again restores
// them.
func TestUpgradeFromV2_8_0(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := openAt(t, dir, migrationsUpTo(t, 10))
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO users (id, username, source, password_hash, created_at) VALUES (5, 'alice', 'local', 'x', 1)`,
		`INSERT INTO users (id, username, source, ldap_dn, created_at) VALUES (6, 'bob', 'ldap', 'cn=bob,dc=lab', 1)`,
		`INSERT INTO roles (id, name, created_at) VALUES (10, 'operators', 1)`,
		`INSERT INTO role_grants (role_id, permission, scope_type) VALUES (10, 'domains.edit', 'all')`,
		`INSERT INTO user_roles (user_id, role_id) VALUES (5, 1), (5, 10)`,
		`INSERT INTO instances (id, name, base_url, created_at) VALUES (7, 'pihole1', 'https://pihole1', 1), (8, 'pihole2', 'https://pihole2', 1)`,
		`INSERT INTO instance_groups (id, name, mode, primary_instance_id, created_at) VALUES (9, 'site', 'mirrored', 7, 1)`,
	} {
		if _, err := s.w.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	counts := func() string {
		t.Helper()
		var out []string
		for _, table := range []string{"users", "roles", "role_grants", "user_roles", "sessions", "user_totp"} {
			q := `SELECT count(*) FROM ` + table
			if table == "role_grants" {
				q += ` WHERE permission NOT IN ('tokens.use', 'logging.manage')`
			}
			var n int
			if err := s.r.QueryRow(q).Scan(&n); err != nil {
				t.Fatal(err)
			}
			out = append(out, fmt.Sprintf("%s=%d", table, n))
		}
		return strings.Join(out, " ")
	}
	before := counts()
	s.Close()

	s, err = openAt(t, dir, migrations.FS)
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	if after := counts(); after != before {
		t.Errorf("the upgrade changed existing rows: %s before, %s after", before, after)
	}
	tokensUse := func(when string, want map[int]int) {
		t.Helper()
		for role, n := range want {
			var got int
			q := `SELECT count(*) FROM role_grants WHERE role_id = ? AND permission = 'tokens.use' AND scope_type = 'all'`
			if err := s.r.QueryRow(q, role).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != n {
				t.Errorf("%s: role %d has %d tokens.use grants, want %d", when, role, got, n)
			}
		}
	}
	tokensUse("after upgrading", map[int]int{1: 1, 10: 0})

	exec := func(q string, args ...any) error {
		_, err := s.w.Exec(q, args...)
		return err
	}
	const token = `INSERT INTO api_tokens (id, public_id, user_id, name, secret_hash, created_at, expires_at, revoked_at) VALUES `
	if err := exec(token + `(1, 'aaaaaaaaaaaaaaaa', 5, 'home assistant', zeroblob(32), 1, 2, NULL)`); err != nil {
		t.Fatalf("a token: %v", err)
	}
	if err := exec(token + `(2, 'bbbbbbbbbbbbbbbb', 6, 'home assistant', zeroblob(32), 1, 2, NULL)`); err != nil {
		t.Fatalf("another user's token with the same name: %v", err)
	}
	if err := exec(token + `(3, 'cccccccccccccccc', 5, 'cron', zeroblob(32), 1, 2, 5)`); err != nil {
		t.Fatalf("a revoked token: %v", err)
	}
	if err := exec(token + `(4, 'dddddddddddddddd', 5, 'cron', zeroblob(32), 1, 2, NULL)`); err != nil {
		t.Fatalf("the name of a revoked token used again: %v", err)
	}
	for name, values := range map[string]string{
		"a name used twice":      `(10, 'eeeeeeeeeeeeeeee', 5, 'home assistant', zeroblob(32), 1, 2, NULL)`,
		"a public ID used twice": `(10, 'aaaaaaaaaaaaaaaa', 6, 'other', zeroblob(32), 1, 2, NULL)`,
		"a short public ID":      `(10, 'eeee', 5, 'other', zeroblob(32), 1, 2, NULL)`,
		"a short hash":           `(10, 'eeeeeeeeeeeeeeee', 5, 'other', zeroblob(20), 1, 2, NULL)`,
		"no hash":                `(10, 'eeeeeeeeeeeeeeee', 5, 'other', NULL, 1, 2, NULL)`,
		"an empty name":          `(10, 'eeeeeeeeeeeeeeee', 5, '', zeroblob(32), 1, 2, NULL)`,
		"no owner":               `(10, 'eeeeeeeeeeeeeeee', 99, 'other', zeroblob(32), 1, 2, NULL)`,
		"no expiry":              `(10, 'eeeeeeeeeeeeeeee', 5, 'other', zeroblob(32), 1, NULL, NULL)`,
		"expiring as it's made":  `(10, 'eeeeeeeeeeeeeeee', 5, 'other', zeroblob(32), 2, 2, NULL)`,
	} {
		if err := exec(token + values); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	const grant = `INSERT INTO api_token_grants (token_id, permission, scope_type, instance_id, group_id) VALUES `
	if err := exec(grant + `(1, 'blocking.toggle', 'all', NULL, NULL), (1, 'domains.view', 'instance', 8, NULL), (1, 'drift.view', 'group', NULL, 9)`); err != nil {
		t.Fatalf("grants at each scope: %v", err)
	}
	for name, values := range map[string]string{
		"the same grant twice":         `(1, 'domains.view', 'instance', 8, NULL)`,
		"scope all with an instance":   `(1, 'domains.edit', 'all', 7, NULL)`,
		"an instance scope without ID": `(1, 'domains.edit', 'instance', NULL, NULL)`,
		"a group scope with both":      `(1, 'domains.edit', 'group', 7, 9)`,
		"an unknown scope":             `(1, 'domains.edit', 'everywhere', NULL, NULL)`,
		"an empty permission":          `(1, '', 'all', NULL, NULL)`,
		"no token":                     `(99, 'domains.edit', 'all', NULL, NULL)`,
		"no such instance":             `(1, 'domains.edit', 'instance', 99, NULL)`,
	} {
		if err := exec(grant + values); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := exec(`DELETE FROM instance_groups WHERE id = 9`); err == nil {
		t.Error("deleting a group a token's grant names: accepted")
	}
	if err := exec(`DELETE FROM instances WHERE id = 8`); err == nil {
		t.Error("deleting an instance a token's grant names: accepted")
	}

	// Deleting a token removes its grants. Deleting a user removes their tokens.
	if err := exec(`DELETE FROM api_tokens WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	var grants int
	if err := s.r.QueryRow(`SELECT count(*) FROM api_token_grants`).Scan(&grants); err != nil || grants != 0 {
		t.Errorf("grants after deleting their token: %d, %v", grants, err)
	}
	if err := exec(`DELETE FROM users WHERE id = 5`); err != nil {
		t.Fatalf("deleting a user with tokens: %v", err)
	}
	var left int
	if err := s.r.QueryRow(`SELECT count(*) FROM api_tokens`).Scan(&left); err != nil || left != 1 {
		t.Errorf("tokens after deleting their owner: %d, %v, want bob's 1", left, err)
	}

	// A grant on another role, so the Down section's first DELETE has something to remove.
	if err := exec(`INSERT INTO role_grants (role_id, permission, scope_type) VALUES (10, 'tokens.use', 'all')`); err != nil {
		t.Fatal(err)
	}
	p, err := goose.NewProvider(goose.DialectSQLite3, s.w, migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.DownTo(ctx, 10); err != nil {
		t.Fatalf("down to 10: %v", err)
	}
	for _, table := range []string{"api_tokens", "api_token_grants"} {
		if ok, err := s.tableExists(ctx, table); err != nil || ok {
			t.Errorf("after migrating down: %s still exists (%v)", table, err)
		}
	}
	tokensUse("after migrating down", map[int]int{1: 0, 10: 0})
	var edits int
	if err := s.r.QueryRow(`SELECT count(*) FROM role_grants WHERE role_id = 10 AND permission = 'domains.edit'`).Scan(&edits); err != nil || edits != 1 {
		t.Errorf("migrating down touched other grants: %d domains.edit grants on role 10, %v", edits, err)
	}
	if err := exec(`DELETE FROM role_grants WHERE role_id = 1 AND permission = 'domains.view'`); err == nil {
		t.Error("the builtin admin's grants can be deleted after migrating down: the trigger wasn't recreated")
	}
	if _, err := p.Up(ctx); err != nil {
		t.Fatalf("up again: %v", err)
	}
	tokensUse("after migrating up again", map[int]int{1: 1, 10: 0})
	for _, table := range []string{"api_tokens", "api_token_grants"} {
		var n int
		if err := s.r.QueryRow(`SELECT count(*) FROM ` + table).Scan(&n); err != nil || n != 0 {
			t.Errorf("after migrating up again: %s has %d rows, %v", table, n, err)
		}
	}
}

// TestUpgradeFrom00011: a database that ran 00011 before v2.9.0 was tagged (its first phase, on a test install) gets
// roles_checked_at on api_tokens, empty for the tokens it has, and api_token_roles. A token's role is unique, needs a
// token and a role, and goes with either. Migrating down to 11 removes both and keeps the tokens, and up again
// restores them.
func TestUpgradeFrom00011(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := openAt(t, dir, migrationsUpTo(t, 11))
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO users (id, username, source, password_hash, created_at) VALUES (5, 'alice', 'local', 'x', 1)`,
		`INSERT INTO users (id, username, source, ldap_dn, created_at) VALUES (6, 'bob', 'ldap', 'cn=bob,dc=lab', 1)`,
		`INSERT INTO roles (id, name, created_at) VALUES (10, 'operators', 1), (11, 'readers', 1)`,
		`INSERT INTO api_tokens (id, public_id, user_id, name, secret_hash, created_at, expires_at)
			VALUES (1, 'aaaaaaaaaaaaaaaa', 5, 'cron', zeroblob(32), 1, 2)`,
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
	exec := func(q string, args ...any) error {
		_, err := s.w.Exec(q, args...)
		return err
	}
	var checked sql.NullInt64
	if err := s.r.QueryRow(`SELECT roles_checked_at FROM api_tokens WHERE id = 1`).Scan(&checked); err != nil || checked.Valid {
		t.Errorf("an existing token: roles_checked_at %v, %v; want NULL", checked, err)
	}
	if err := exec(`INSERT INTO api_tokens (id, public_id, user_id, name, secret_hash, created_at, expires_at, roles_checked_at)
		VALUES (2, 'bbbbbbbbbbbbbbbb', 6, 'ldap', zeroblob(32), 1, 2, 1)`); err != nil {
		t.Fatalf("an LDAP user's token: %v", err)
	}
	if err := exec(`INSERT INTO api_token_roles (token_id, role_id) VALUES (2, 10), (2, 11)`); err != nil {
		t.Fatalf("its roles: %v", err)
	}
	for name, values := range map[string]string{
		"a role twice":          `(2, 10)`,
		"a token that's absent": `(99, 10)`,
		"a role that's absent":  `(2, 99)`,
	} {
		if err := exec(`INSERT INTO api_token_roles (token_id, role_id) VALUES ` + values); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	count := func() int {
		var n int
		if err := s.r.QueryRow(`SELECT count(*) FROM api_token_roles`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if err := exec(`DELETE FROM roles WHERE id = 11`); err != nil {
		t.Fatalf("deleting a role a token holds: %v", err)
	}
	if n := count(); n != 1 {
		t.Errorf("after deleting a role: %d token roles, want 1", n)
	}
	if err := exec(`DELETE FROM api_tokens WHERE id = 2`); err != nil {
		t.Fatal(err)
	}
	if n := count(); n != 0 {
		t.Errorf("after deleting the token: %d token roles, want 0", n)
	}

	p, err := goose.NewProvider(goose.DialectSQLite3, s.w, migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.DownTo(ctx, 11); err != nil {
		t.Fatalf("down to 11: %v", err)
	}
	if ok, err := s.tableExists(ctx, "api_token_roles"); err != nil || ok {
		t.Errorf("after migrating down: api_token_roles still exists (%v)", err)
	}
	if err := s.r.QueryRow(`SELECT roles_checked_at FROM api_tokens`).Scan(&checked); err == nil {
		t.Error("after migrating down: api_tokens still has roles_checked_at")
	}
	var tokens int
	if err := s.r.QueryRow(`SELECT count(*) FROM api_tokens`).Scan(&tokens); err != nil || tokens != 1 {
		t.Errorf("after migrating down: %d tokens, %v; want alice's 1", tokens, err)
	}
	if _, err := p.Up(ctx); err != nil {
		t.Fatalf("up again: %v", err)
	}
	if ok, err := s.tableExists(ctx, "api_token_roles"); err != nil || !ok {
		t.Errorf("after migrating up again: no api_token_roles (%v)", err)
	}
}

// TestUpgradeFrom00012: a database that ran 00012 before v2.9.0 was tagged gets revoked_by and revoked_reason on
// api_tokens, empty for the tokens it has. revoked_by is self, admin or recheck; a reason can't be empty. Migrating
// down to 12 removes both and keeps the tokens.
func TestUpgradeFrom00012(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := openAt(t, dir, migrationsUpTo(t, 12))
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO users (id, username, source, password_hash, created_at) VALUES (5, 'alice', 'local', 'x', 1)`,
		`INSERT INTO api_tokens (id, public_id, user_id, name, secret_hash, created_at, expires_at, revoked_at)
			VALUES (1, 'aaaaaaaaaaaaaaaa', 5, 'old', zeroblob(32), 1, 2, 2)`,
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
	var by, reason sql.NullString
	if err := s.r.QueryRow(`SELECT revoked_by, revoked_reason FROM api_tokens WHERE id = 1`).Scan(&by, &reason); err != nil || by.Valid || reason.Valid {
		t.Errorf("a token revoked before: by %v, reason %v, %v; want both NULL", by, reason, err)
	}
	update := func(by, reason any) error {
		_, err := s.w.Exec(`UPDATE api_tokens SET revoked_by = ?, revoked_reason = ? WHERE id = 1`, by, reason)
		return err
	}
	for _, v := range []string{"self", "admin", "recheck"} {
		if err := update(v, nil); err != nil {
			t.Errorf("revoked_by %s: %v", v, err)
		}
	}
	if err := update("recheck", "not in the directory"); err != nil {
		t.Errorf("a reason: %v", err)
	}
	if err := update("somebody", nil); err == nil {
		t.Error("an unknown revoked_by: accepted")
	}
	if err := update("recheck", ""); err == nil {
		t.Error("an empty reason: accepted")
	}

	p, err := goose.NewProvider(goose.DialectSQLite3, s.w, migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.DownTo(ctx, 12); err != nil {
		t.Fatalf("down to 12: %v", err)
	}
	if err := s.r.QueryRow(`SELECT revoked_by FROM api_tokens`).Scan(&by); err == nil {
		t.Error("after migrating down: api_tokens still has revoked_by")
	}
	var n int
	if err := s.r.QueryRow(`SELECT count(*) FROM api_tokens`).Scan(&n); err != nil || n != 1 {
		t.Errorf("after migrating down: %d tokens, %v", n, err)
	}
	if _, err := p.Up(ctx); err != nil {
		t.Fatalf("up again: %v", err)
	}
}

// TestUpgradeFromV2_9_0: a database as v2.9.0 left it (version 13) gets logging.manage on the builtin admin role only,
// and the two log forwarding tables, with no other change to its users, roles or grants. audit_log is rebuilt: its
// rows keep their IDs, content and indexes, and an ID is never used twice, even after every row is deleted (a cursor
// is an ID, so a reused one would be passed over). A destination needs a name unique ignoring case, a port from 1 to
// 65535, a known transport and TLS mode, and a CA file only with TLS and verify. A cursor goes with its destination.
// Migrating down to 13 removes the tables and logging.manage everywhere, leaves the builtin admin's grants
// protected and the audit rows in place, and up again restores them.
func TestUpgradeFromV2_9_0(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := openAt(t, dir, migrationsUpTo(t, 13))
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO users (id, username, source, password_hash, created_at) VALUES (5, 'alice', 'local', 'x', 1)`,
		`INSERT INTO roles (id, name, created_at) VALUES (10, 'operators', 1)`,
		`INSERT INTO role_grants (role_id, permission, scope_type) VALUES (10, 'domains.edit', 'all')`,
		`INSERT INTO user_roles (user_id, role_id) VALUES (5, 1), (5, 10)`,
		`INSERT INTO instances (id, name, base_url, created_at) VALUES (7, 'pihole1', 'https://pihole1', 1)`,
		`INSERT INTO audit_log (id, at, user_id, username, action, target, instance_id, instance_name, result, detail, ip)
		 VALUES (3, 100, 5, 'alice', 'domain_add', 'i-7', 7, 'pihole1', 'success', '{"domain":"a.example"}', '10.0.0.5'),
		        (9, 200, NULL, 'ghost', 'login', '', NULL, '', 'failure', '{"error":"bad password"}', '10.0.0.6')`,
	} {
		if _, err := s.w.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	counts := func() string {
		t.Helper()
		var out []string
		for _, table := range []string{"users", "roles", "role_grants", "user_roles", "sessions", "api_tokens"} {
			q := `SELECT count(*) FROM ` + table
			if table == "role_grants" {
				q += ` WHERE permission <> 'logging.manage'`
			}
			var n int
			if err := s.r.QueryRow(q).Scan(&n); err != nil {
				t.Fatal(err)
			}
			out = append(out, fmt.Sprintf("%s=%d", table, n))
		}
		return strings.Join(out, " ")
	}
	auditRows := func() string {
		t.Helper()
		rows, err := s.r.Query(`SELECT id, at, ifnull(user_id, 0), username, action, target, ifnull(instance_id, 0), instance_name, result, detail, ip FROM audit_log ORDER BY id`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var id, at, uid, iid int64
			var user, action, target, iname, result, detail, ip string
			if err := rows.Scan(&id, &at, &uid, &user, &action, &target, &iid, &iname, &result, &detail, &ip); err != nil {
				t.Fatal(err)
			}
			out = append(out, fmt.Sprint(id, at, uid, user, action, target, iid, iname, result, detail, ip))
		}
		return strings.Join(out, "|")
	}
	before, auditBefore := counts(), auditRows()
	s.Close()

	s, err = openAt(t, dir, migrations.FS)
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	if after := counts(); after != before {
		t.Errorf("the upgrade changed existing rows: %s before, %s after", before, after)
	}
	if after := auditRows(); after != auditBefore {
		t.Errorf("the upgrade changed the audit rows:\n before %s\n after  %s", auditBefore, after)
	}
	loggingManage := func(when string, want map[int]int) {
		t.Helper()
		for role, n := range want {
			var got int
			q := `SELECT count(*) FROM role_grants WHERE role_id = ? AND permission = 'logging.manage' AND scope_type = 'all'`
			if err := s.r.QueryRow(q, role).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != n {
				t.Errorf("%s: role %d has %d logging.manage grants, want %d", when, role, got, n)
			}
		}
	}
	loggingManage("after upgrading", map[int]int{1: 1, 10: 0})

	exec := func(q string, args ...any) error {
		_, err := s.w.Exec(q, args...)
		return err
	}
	// The rebuilt table keeps its indexes and its foreign keys: a user or instance that goes leaves the row, as before.
	for _, index := range []string{"audit_log_at", "audit_log_user", "audit_log_action", "audit_log_instance"} {
		var n int
		if err := s.r.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name = ? AND tbl_name = 'audit_log'`, index).Scan(&n); err != nil || n != 1 {
			t.Errorf("index %s on audit_log: %d, %v", index, n, err)
		}
	}
	if err := exec(`DELETE FROM users WHERE id = 5`); err != nil {
		t.Fatalf("deleting a user named by an audit row: %v", err)
	}
	var uid sql.NullInt64
	if err := s.r.QueryRow(`SELECT user_id FROM audit_log WHERE id = 3`).Scan(&uid); err != nil || uid.Valid {
		t.Errorf("an audit row after its user was deleted: user_id %v, %v, want NULL", uid, err)
	}
	// An ID is never used twice: new rows continue after the highest ID there was, even once every row is gone.
	insert := `INSERT INTO audit_log (at, username, action, result) VALUES (300, 'system', 'audit_prune', 'success')`
	if err := exec(insert); err != nil {
		t.Fatal(err)
	}
	var id int64
	if err := s.r.QueryRow(`SELECT max(id) FROM audit_log`).Scan(&id); err != nil || id != 10 {
		t.Errorf("the first row after the upgrade has ID %d, %v, want 10 (after the highest, 9)", id, err)
	}
	if err := exec(`DELETE FROM audit_log`); err != nil {
		t.Fatal(err)
	}
	if err := exec(insert); err != nil {
		t.Fatal(err)
	}
	if err := s.r.QueryRow(`SELECT max(id) FROM audit_log`).Scan(&id); err != nil || id != 11 {
		t.Errorf("the first row after every row was deleted has ID %d, %v, want 11: an ID was used twice", id, err)
	}

	const dest = `INSERT INTO log_destinations (id, name, host, port, transport, tls_mode, ca_file, enabled, created_at, updated_at) VALUES `
	if err := exec(dest + `(1, 'Graylog', 'graylog.lab', 6514, 'tls', 'verify', '/etc/ssl/lab-ca.pem', 1, 1, 1),
		(2, 'rsyslog', '10.0.0.9', 514, 'udp', 'verify', NULL, 1, 1, 1),
		(3, 'wazuh', 'wazuh.lab', 6514, 'tls', 'insecure', NULL, 0, 1, 1)`); err != nil {
		t.Fatalf("destinations: %v", err)
	}
	var transport, tlsMode string
	if err := s.r.QueryRow(`SELECT transport, tls_mode FROM log_destinations WHERE id = 1`).Scan(&transport, &tlsMode); err != nil {
		t.Fatal(err)
	}
	if err := exec(`INSERT INTO log_destinations (name, host, port, created_at, updated_at) VALUES ('defaults', 'h', 6514, 1, 1)`); err != nil {
		t.Fatalf("a destination with only the required fields: %v", err)
	}
	if err := s.r.QueryRow(`SELECT transport, tls_mode FROM log_destinations WHERE name = 'defaults'`).Scan(&transport, &tlsMode); err != nil || transport != "tls" || tlsMode != "verify" {
		t.Errorf("defaults: transport %q and TLS mode %q, %v, want tls and verify", transport, tlsMode, err)
	}
	for name, values := range map[string]string{
		"a name used twice, in other case": `(10, 'GRAYLOG', 'h', 6514, 'tls', 'verify', NULL, 1, 1, 1)`,
		"an empty name":                    `(10, '', 'h', 6514, 'tls', 'verify', NULL, 1, 1, 1)`,
		"an empty host":                    `(10, 'x', '', 6514, 'tls', 'verify', NULL, 1, 1, 1)`,
		"port 0":                           `(10, 'x', 'h', 0, 'tls', 'verify', NULL, 1, 1, 1)`,
		"port 65536":                       `(10, 'x', 'h', 65536, 'tls', 'verify', NULL, 1, 1, 1)`,
		"an unknown transport":             `(10, 'x', 'h', 514, 'http', 'verify', NULL, 1, 1, 1)`,
		"an unknown TLS mode":              `(10, 'x', 'h', 6514, 'tls', 'skip', NULL, 1, 1, 1)`,
		"a CA file with insecure":          `(10, 'x', 'h', 6514, 'tls', 'insecure', '/ca.pem', 1, 1, 1)`,
		"a CA file without TLS":            `(10, 'x', 'h', 514, 'tcp', 'verify', '/ca.pem', 1, 1, 1)`,
		"an empty CA file":                 `(10, 'x', 'h', 6514, 'tls', 'verify', '', 1, 1, 1)`,
		"enabled as 2":                     `(10, 'x', 'h', 6514, 'tls', 'verify', NULL, 2, 1, 1)`,
		"no creation time":                 `(10, 'x', 'h', 6514, 'tls', 'verify', NULL, 1, NULL, 1)`,
	} {
		if err := exec(dest + values); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	const cursor = `INSERT INTO log_destination_cursors (destination_id, last_id, updated_at) VALUES `
	if err := exec(cursor + `(1, 11, 5), (2, 0, 5)`); err != nil {
		t.Fatalf("cursors: %v", err)
	}
	for name, values := range map[string]string{
		"a second cursor for one destination": `(1, 12, 6)`,
		"a cursor for no destination":         `(99, 1, 6)`,
		"a negative cursor":                   `(3, -1, 6)`,
	} {
		if err := exec(cursor + values); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := exec(`DELETE FROM log_destinations WHERE id = 2`); err != nil {
		t.Fatal(err)
	}
	var cursors int
	if err := s.r.QueryRow(`SELECT count(*) FROM log_destination_cursors`).Scan(&cursors); err != nil || cursors != 1 {
		t.Errorf("cursors after deleting a destination: %d, %v, want 1", cursors, err)
	}

	// A grant on another role, so the Down section's first DELETE has something to remove.
	if err := exec(`INSERT INTO role_grants (role_id, permission, scope_type) VALUES (10, 'logging.manage', 'all')`); err != nil {
		t.Fatal(err)
	}
	if err := exec(`INSERT INTO audit_log (at, username, action, result) VALUES (400, 'system', 'audit_prune', 'success')`); err != nil {
		t.Fatal(err)
	}
	downAudit := auditRows()
	p, err := goose.NewProvider(goose.DialectSQLite3, s.w, migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.DownTo(ctx, 13); err != nil {
		t.Fatalf("down to 13: %v", err)
	}
	for _, table := range []string{"log_destinations", "log_destination_cursors"} {
		if ok, err := s.tableExists(ctx, table); err != nil || ok {
			t.Errorf("after migrating down: %s still exists (%v)", table, err)
		}
	}
	loggingManage("after migrating down", map[int]int{1: 0, 10: 0})
	if after := auditRows(); after != downAudit {
		t.Errorf("migrating down changed the audit rows:\n before %s\n after  %s", downAudit, after)
	}
	var edits int
	if err := s.r.QueryRow(`SELECT count(*) FROM role_grants WHERE role_id = 10 AND permission = 'domains.edit'`).Scan(&edits); err != nil || edits != 1 {
		t.Errorf("migrating down touched other grants: %d domains.edit grants on role 10, %v", edits, err)
	}
	if err := exec(`DELETE FROM role_grants WHERE role_id = 1 AND permission = 'domains.view'`); err == nil {
		t.Error("the builtin admin's grants can be deleted after migrating down: the trigger wasn't recreated")
	}
	if _, err := p.Up(ctx); err != nil {
		t.Fatalf("up again: %v", err)
	}
	loggingManage("after migrating up again", map[int]int{1: 1, 10: 0})
	if after := auditRows(); after != downAudit {
		t.Errorf("migrating up again changed the audit rows:\n before %s\n after  %s", downAudit, after)
	}
	for _, table := range []string{"log_destinations", "log_destination_cursors"} {
		var n int
		if err := s.r.QueryRow(`SELECT count(*) FROM ` + table).Scan(&n); err != nil || n != 0 {
			t.Errorf("after migrating up again: %s has %d rows, %v", table, n, err)
		}
	}
}
