// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/store/db"
	"github.com/Kate-0713/pihole-rbac/migrations"
)

var quietLog = slog.New(slog.NewTextHandler(io.Discard, nil))

func openAt(t *testing.T, dir string, fsys fs.FS) (*Store, error) {
	t.Helper()
	s, err := open(context.Background(), Options{DataDir: dir, Logger: quietLog}, fsys)
	if err == nil {
		// Registered after t.TempDir, so it runs first: Windows can't delete open database files.
		t.Cleanup(func() { s.Close() })
	}
	return s, err
}

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := openAt(t, t.TempDir(), migrations.FS)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return s
}

// withExtraMigration is the real migrations plus a trivial 00002, to simulate an upgrade.
func withExtraMigration(t *testing.T) fs.FS {
	t.Helper()
	initial, err := fs.ReadFile(migrations.FS, "00001_initial.sql")
	if err != nil {
		t.Fatal(err)
	}
	return fstest.MapFS{
		"00001_initial.sql": {Data: initial},
		"00002_extra.sql": {Data: []byte("-- +goose Up\nCREATE TABLE extra (id INTEGER PRIMARY KEY);\n\n" +
			"-- +goose Down\nDROP TABLE extra;\n")},
	}
}

func schemaVersion(t *testing.T, d *sql.DB) int64 {
	t.Helper()
	var v int64
	if err := d.QueryRow(`SELECT max(version_id) FROM goose_db_version WHERE is_applied`).Scan(&v); err != nil {
		t.Fatalf("read schema version: %v", err)
	}
	return v
}

func hasTable(t *testing.T, d *sql.DB, name string) bool {
	t.Helper()
	var n int
	if err := d.QueryRow(`SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = ?`, name).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n > 0
}

func listBackups(t *testing.T, dataDir string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dataDir, backupDirName))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestOpenFreshDatabase(t *testing.T) {
	dir := t.TempDir()
	s, err := openAt(t, dir, migrations.FS)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if v := schemaVersion(t, s.w); v != 1 {
		t.Errorf("schema version = %d, want 1", v)
	}
	if b := listBackups(t, dir); len(b) != 0 {
		t.Errorf("fresh database was backed up: %v", b)
	}
	var setupRows int
	if err := s.r.QueryRow(`SELECT count(*) FROM setup_state`).Scan(&setupRows); err != nil || setupRows != 1 {
		t.Errorf("setup_state rows = %d (err %v), want 1", setupRows, err)
	}
}

func TestReaderIsReadOnly(t *testing.T) {
	s := openTest(t)
	_, err := s.r.Exec(`INSERT INTO settings (key, value, updated_at) VALUES ('k', '1', 0)`)
	if err == nil {
		t.Fatal("write through the reader pool succeeded, want an error")
	}
}

func TestBuiltinAdminSeeded(t *testing.T) {
	// Once internal/rbac holds the permission catalogue, this list should come from there instead.
	want := []string{
		"app.update", "audit.view", "blocking.toggle", "clientreset.run", "clients.edit", "clients.view",
		"config.reload", "dns.restart", "domains.edit", "domains.view", "drift.reconcile", "drift.view",
		"instances.manage", "notifications.manage", "querylog.view", "roles.manage", "sessions.manage",
		"settings.manage", "users.manage",
	}
	s := openTest(t)
	ctx := context.Background()
	role, err := s.Read().GetRoleByName(ctx, "admin")
	if err != nil {
		t.Fatalf("admin role: %v", err)
	}
	if !role.Builtin {
		t.Error("admin role is not builtin")
	}
	grants, err := s.Read().ListGrantsForRole(ctx, role.ID)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, g := range grants {
		if g.ScopeType != "all" {
			t.Errorf("admin grant %s has scope %q, want all", g.Permission, g.ScopeType)
		}
		got = append(got, g.Permission)
	}
	if !slices.Equal(got, want) {
		t.Errorf("admin grants =\n  %v\nwant\n  %v", got, want)
	}
}

func TestReopenWithNothingPendingSkipsBackup(t *testing.T) {
	dir := t.TempDir()
	s, err := openAt(t, dir, migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := openAt(t, dir, migrations.FS); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if b := listBackups(t, dir); len(b) != 0 {
		t.Errorf("backup made with nothing pending: %v", b)
	}
}

func TestPendingMigrationBacksUpFirst(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := openAt(t, dir, migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	err = s.WithTx(ctx, func(q *db.Queries) error {
		return q.UpsertSetting(ctx, db.UpsertSettingParams{Key: "marker", Value: `"before"`, UpdatedAt: 1, UpdatedBy: "test"})
	})
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	s2, err := openAt(t, dir, withExtraMigration(t))
	if err != nil {
		t.Fatalf("open with a pending migration: %v", err)
	}
	if !hasTable(t, s2.w, "extra") {
		t.Error("migration 00002 wasn't applied")
	}

	backups := listBackups(t, dir)
	if len(backups) != 1 || !strings.HasPrefix(backups[0], backupPrefix) || !strings.HasSuffix(backups[0], "-from1.db") {
		t.Fatalf("backups = %v, want one pre-migrate-*-from1.db", backups)
	}
	b, err := sql.Open("sqlite", filepath.Join(dir, backupDirName, backups[0]))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if v := schemaVersion(t, b); v != 1 {
		t.Errorf("backup schema version = %d, want 1", v)
	}
	if hasTable(t, b, "extra") {
		t.Error("backup was taken after migrating, want before")
	}
	var value string
	if err := b.QueryRow(`SELECT value FROM settings WHERE key = 'marker'`).Scan(&value); err != nil || value != `"before"` {
		t.Errorf("backup marker = %q (err %v), want \"before\"", value, err)
	}
}

func TestRefusesNewerSchema(t *testing.T) {
	dir := t.TempDir()
	s, err := openAt(t, dir, withExtraMigration(t))
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := openAt(t, dir, migrations.FS); err == nil || !strings.Contains(err.Error(), "only knows up to 1") {
		t.Fatalf("open older binary against newer schema: err = %v, want a refusal", err)
	}
}

func TestRefusesUnversionedDatabase(t *testing.T) {
	dir := t.TempDir()
	d, err := sql.Open("sqlite", filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`CREATE TABLE something_else (x)`); err != nil {
		t.Fatal(err)
	}
	d.Close()
	if _, err := openAt(t, dir, migrations.FS); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("err = %v, want a refusal to migrate an unknown database", err)
	}
}

func TestPruneBackups(t *testing.T) {
	dir := t.TempDir()
	var backups []string
	for i := range 7 {
		backups = append(backups, fmt.Sprintf("%s2026102%dT120000.000Z-from1.db", backupPrefix, i))
	}
	others := []string{"v2.0.0-20261022T120000Z.db", "pre-migrate-notes.txt"} // updater backups, unrelated files
	for _, n := range append(slices.Clone(backups), others...) {
		if err := os.WriteFile(filepath.Join(dir, n), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := pruneBackups(dir, 5); err != nil {
		t.Fatal(err)
	}
	var got []string
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		got = append(got, e.Name())
	}
	want := append(slices.Clone(backups[2:]), others...)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("after prune:\n  %v\nwant\n  %v", got, want)
	}
}

func TestWithTx(t *testing.T) {
	errBoom := errors.New("boom")
	tests := []struct {
		name       string
		fn         func(q *db.Queries) error
		panics     bool
		wantErr    error
		wantStored bool
	}{
		{"commit", func(q *db.Queries) error { return nil }, false, nil, true},
		{"error rolls back", func(q *db.Queries) error { return errBoom }, false, errBoom, false},
		{"panic rolls back", func(q *db.Queries) error { panic("boom") }, true, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			s := openTest(t)
			run := func() (err error) {
				defer func() {
					if r := recover(); r != nil && !tt.panics {
						panic(r)
					}
				}()
				return s.WithTx(ctx, func(q *db.Queries) error {
					if err := q.UpsertSetting(ctx, db.UpsertSettingParams{Key: "k", Value: "1", UpdatedAt: 1}); err != nil {
						return err
					}
					return tt.fn(q)
				})
			}
			if err := run(); !errors.Is(err, tt.wantErr) {
				t.Fatalf("WithTx err = %v, want %v", err, tt.wantErr)
			}
			_, err := s.Read().GetSetting(ctx, "k")
			if stored := err == nil; stored != tt.wantStored {
				t.Errorf("setting stored = %v (err %v), want %v", stored, err, tt.wantStored)
			}
			// The writer's only connection must be free again, or the next write would hang.
			if err := s.WithTx(ctx, func(q *db.Queries) error { return nil }); err != nil {
				t.Errorf("next transaction: %v", err)
			}
		})
	}
}

// Concurrent writers queue on the single writer connection and readers run alongside, with no SQLITE_BUSY.
func TestConcurrentWritesAndReads(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s := openTest(t)

	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for w := range 8 {
		wg.Go(func() {
			for i := range 25 {
				err := s.WithTx(ctx, func(q *db.Queries) error {
					return q.UpsertSetting(ctx, db.UpsertSettingParams{
						Key: fmt.Sprintf("w%d", w), Value: fmt.Sprint(i), UpdatedAt: int64(i),
					})
				})
				if err != nil {
					errs <- err
					return
				}
			}
		})
	}
	for range 4 {
		wg.Go(func() {
			for range 50 {
				if _, err := s.Read().GetRoleByName(ctx, "admin"); err != nil {
					errs <- err
					return
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// fixture: three instances, a mirrored group (1: primary and member pihole1), an independent group (2: pihole1 and
// pihole2), role staff (2) held by local user kate (1) with a grant on pihole3.
const fixture = `
INSERT INTO instances (id, name, base_url, env_name, created_at) VALUES
    (1, 'pihole1', 'http://10.0.0.1', 'PIHOLE1', 0),
    (2, 'pihole2', 'http://10.0.0.2', 'PIHOLE2', 0),
    (3, 'pihole3', 'http://10.0.0.3', 'PIHOLE3', 0);
INSERT INTO instance_groups (id, name, mode, primary_instance_id, created_at) VALUES
    (1, 'mirror-a', 'mirrored', 1, 0),
    (2, 'site-b', 'independent', NULL, 0);
INSERT INTO instance_group_members (group_id, group_mode, instance_id) VALUES
    (1, 'mirrored', 1), (2, 'independent', 1), (2, 'independent', 2);
INSERT INTO roles (id, name, created_at) VALUES (2, 'staff', 0);
INSERT INTO users (id, username, source, password_hash, created_at) VALUES (1, 'kate', 'local', 'hash', 0);
INSERT INTO user_roles (user_id, role_id) VALUES (1, 2);
INSERT INTO role_grants (role_id, permission, scope_type, instance_id) VALUES (2, 'domains.view', 'instance', 3);
`

func TestConstraints(t *testing.T) {
	tests := []struct {
		name  string
		setup []string
		stmt  string
		want  ConstraintKind // NotConstraint means the statement must succeed
	}{
		// Grants and scopes
		{"instance scope needs an instance", nil,
			`INSERT INTO role_grants (role_id, permission, scope_type) VALUES (2, 'domains.view', 'instance')`, Check},
		{"all scope can't name an instance", nil,
			`INSERT INTO role_grants (role_id, permission, scope_type, instance_id) VALUES (2, 'domains.view', 'all', 1)`, Check},
		{"group scope can't also name an instance", nil,
			`INSERT INTO role_grants (role_id, permission, scope_type, instance_id, group_id) VALUES (2, 'drift.view', 'group', 1, 1)`, Check},
		{"duplicate all-scope grant", nil,
			`INSERT INTO role_grants (role_id, permission, scope_type) VALUES (2, 'clients.view', 'all'), (2, 'clients.view', 'all')`, Unique},
		{"duplicate instance grant", nil,
			`INSERT INTO role_grants (role_id, permission, scope_type, instance_id) VALUES (2, 'domains.view', 'instance', 3)`, Unique},
		{"same permission on another instance is fine", nil,
			`INSERT INTO role_grants (role_id, permission, scope_type, instance_id) VALUES (2, 'domains.view', 'instance', 2)`, NotConstraint},

		// Referenced things can't be deleted
		{"instance referenced by a grant", nil, `DELETE FROM instances WHERE id = 3`, ForeignKey},
		{"instance in a group", nil, `DELETE FROM instances WHERE id = 2`, ForeignKey},
		{"group referenced by a grant",
			[]string{`INSERT INTO role_grants (role_id, permission, scope_type, group_id) VALUES (2, 'domains.view', 'group', 2)`},
			`DELETE FROM instance_groups WHERE id = 2`, ForeignKey},
		{"group referenced by a client reset target",
			[]string{`INSERT INTO client_reset_targets (group_id) VALUES (2)`},
			`DELETE FROM instance_groups WHERE id = 2`, ForeignKey},
		{"unreferenced group deletes with its members", nil, `DELETE FROM instance_groups WHERE id = 2`, NotConstraint},
		{"role held by a user", nil, `DELETE FROM roles WHERE id = 2`, ForeignKey},
		{"role mapped to an LDAP group",
			[]string{
				`DELETE FROM user_roles`,
				`INSERT INTO role_ldap_groups (role_id, group_dn, group_dn_norm, created_at) VALUES (2, 'CN=Staff,DC=x', 'cn=staff,dc=x', 0)`,
			},
			`DELETE FROM roles WHERE id = 2`, ForeignKey},
		{"unused role deletes with its grants", []string{`DELETE FROM user_roles`}, `DELETE FROM roles WHERE id = 2`, NotConstraint},

		// Builtin admin (invariant 1)
		{"delete builtin admin", nil, `DELETE FROM roles WHERE id = 1`, Trigger},
		{"rename builtin admin", nil, `UPDATE roles SET name = 'root' WHERE id = 1`, Trigger},
		{"remove a builtin admin grant", nil, `DELETE FROM role_grants WHERE role_id = 1 AND permission = 'users.manage'`, Trigger},
		{"move a builtin admin grant", nil, `UPDATE role_grants SET role_id = 2 WHERE role_id = 1 AND permission = 'audit.view'`, Trigger},
		{"scoped grant on builtin admin", nil,
			`INSERT INTO role_grants (role_id, permission, scope_type, instance_id) VALUES (1, 'domains.view', 'instance', 1)`, Trigger},
		{"second builtin role", nil, `INSERT INTO roles (name, builtin, created_at) VALUES ('root', 1, 0)`, Unique},
		{"role names are case-insensitive", nil, `INSERT INTO roles (name, created_at) VALUES ('ADMIN', 0)`, Unique},

		// Mirrored groups
		{"instance in two mirrored groups",
			[]string{`INSERT INTO instance_groups (id, name, mode, primary_instance_id, created_at) VALUES (3, 'mirror-c', 'mirrored', 2, 0)`},
			`INSERT INTO instance_group_members (group_id, group_mode, instance_id) VALUES (3, 'mirrored', 1)`, Unique},
		{"switching a group to mirrored re-checks its members", nil,
			`UPDATE instance_groups SET mode = 'mirrored', primary_instance_id = 2 WHERE id = 2`, Unique},
		{"member must carry its group's mode", nil,
			`INSERT INTO instance_group_members (group_id, group_mode, instance_id) VALUES (1, 'independent', 3)`, ForeignKey},
		{"mirrored group needs a primary", nil,
			`INSERT INTO instance_groups (name, mode, created_at) VALUES ('m', 'mirrored', 0)`, Check},
		{"independent group can't have a primary", nil,
			`INSERT INTO instance_groups (name, mode, primary_instance_id, created_at) VALUES ('i', 'independent', 1, 0)`, Check},

		// Users and instances
		{"username must be lowercase", nil,
			`INSERT INTO users (username, source, password_hash, created_at) VALUES ('Kate2', 'local', 'h', 0)`, Check},
		{"local user needs a password hash", nil,
			`INSERT INTO users (username, source, created_at) VALUES ('nopass', 'local', 0)`, Check},
		{"LDAP user can't have a password hash", nil,
			`INSERT INTO users (username, source, ldap_dn, password_hash, created_at) VALUES ('l', 'ldap', 'CN=l', 'h', 0)`, Check},
		{"env_name is upper case", nil,
			`INSERT INTO instances (name, base_url, env_name, created_at) VALUES ('p4', 'http://x', 'pihole4', 0)`, Check},
		{"env_name is unique", nil,
			`INSERT INTO instances (name, base_url, env_name, created_at) VALUES ('p4', 'http://x', 'PIHOLE1', 0)`, Unique},

		// Everything else
		{"one setup_state row", nil, `INSERT INTO setup_state (id) VALUES (2)`, Check},
		{"one running client reset", nil,
			`INSERT INTO client_reset_runs (started_at, trigger, status) VALUES (0, 'manual', 'running'), (1, 'schedule', 'running')`, Unique},
		{"client reset target is an instance or a group", nil,
			`INSERT INTO client_reset_targets (instance_id, group_id) VALUES (1, 2)`, Check},
		{"settings value is JSON", nil, `INSERT INTO settings (key, value, updated_at) VALUES ('k', '{nope', 0)`, Check},
		{"session hash is 32 bytes", nil,
			`INSERT INTO sessions (id_hash, public_id, user_id, created_at, expires_at, last_seen_at, roles_checked_at)
			 VALUES (x'00', 'AAAAAAAAAAAAAAAAAAAAAA', 1, 0, 1, 0, 0)`, Check},
		{"notification secret is all or nothing", nil,
			`INSERT INTO notification_channels (kind, name, secret_ciphertext, created_at) VALUES ('discord', 'd', x'01', 0)`, Check},
		{"channel env_name is upper case", nil,
			`INSERT INTO notification_channels (kind, name, env_name, created_at) VALUES ('discord', 'd', 'alerts', 0)`, Check},
		{"channel env_name isn't empty", nil,
			`INSERT INTO notification_channels (kind, name, env_name, created_at) VALUES ('discord', 'd', '', 0)`, Check},
		{"channel env_name is unique",
			[]string{`INSERT INTO notification_channels (kind, name, env_name, created_at) VALUES ('discord', 'd1', 'ALERTS', 0)`},
			`INSERT INTO notification_channels (kind, name, env_name, created_at) VALUES ('matrix', 'm1', 'ALERTS', 0)`, Unique},
		{"update target version looks like a tag", nil,
			`INSERT INTO update_requests (requested_at, target_version) VALUES (0, 'https://evil.example/x')`, Check},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := openTest(t)
			if _, err := s.w.Exec(fixture); err != nil {
				t.Fatalf("fixture: %v", err)
			}
			for _, q := range tt.setup {
				if _, err := s.w.Exec(q); err != nil {
					t.Fatalf("setup %q: %v", q, err)
				}
			}
			_, err := s.w.Exec(tt.stmt)
			if got := Constraint(err); got != tt.want {
				t.Fatalf("constraint = %v, want %v (err: %v)", got, tt.want, err)
			}
			if tt.want == NotConstraint && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// History rows outlive the user and instance they mention, keeping the copied names.
func TestHistorySurvivesDeletion(t *testing.T) {
	s := openTest(t)
	for _, q := range []string{
		fixture,
		`INSERT INTO audit_log (id, at, user_id, username, action, instance_id, instance_name, result)
		 VALUES (1, 0, 1, 'kate', 'domains.add', 3, 'pihole3', 'ok')`,
		`INSERT INTO client_reset_runs (started_at, finished_at, trigger, user_id, username, status) VALUES (0, 1, 'manual', 1, 'kate', 'ok')`,
		`INSERT INTO update_requests (requested_at, requested_by, requested_by_name) VALUES (0, 1, 'kate')`,
		`DELETE FROM role_grants WHERE instance_id = 3`,
		`DELETE FROM users WHERE id = 1`,
		`DELETE FROM instances WHERE id = 3`,
	} {
		if _, err := s.w.Exec(q); err != nil {
			t.Fatalf("%q: %v", q, err)
		}
	}
	var userID, instanceID sql.NullInt64
	var username, instanceName string
	err := s.r.QueryRow(`SELECT user_id, username, instance_id, instance_name FROM audit_log WHERE id = 1`).
		Scan(&userID, &username, &instanceID, &instanceName)
	if err != nil {
		t.Fatal(err)
	}
	if userID.Valid || instanceID.Valid || username != "kate" || instanceName != "pihole3" {
		t.Errorf("audit row = user %v %q, instance %v %q, want NULL ids and the names kept", userID, username, instanceID, instanceName)
	}
	for _, q := range []string{
		`SELECT count(*) FROM client_reset_runs WHERE user_id IS NULL AND username = 'kate'`,
		`SELECT count(*) FROM update_requests WHERE requested_by IS NULL AND requested_by_name = 'kate'`,
	} {
		var n int
		if err := s.r.QueryRow(q).Scan(&n); err != nil || n != 1 {
			t.Errorf("%q = %d (err %v), want 1", q, n, err)
		}
	}
}

func TestConstraintOnOtherErrors(t *testing.T) {
	for _, err := range []error{nil, errors.New("x"), sql.ErrNoRows} {
		if got := Constraint(err); got != NotConstraint {
			t.Errorf("Constraint(%v) = %v, want none", err, got)
		}
	}
}

func TestMillisRoundTrip(t *testing.T) {
	in := time.Date(2026, 10, 22, 21, 33, 5, 123_456_789, time.FixedZone("BST", 3600))
	got := FromMillis(Millis(in))
	if want := in.Truncate(time.Millisecond).UTC(); !got.Equal(want) || got.Location() != time.UTC {
		t.Errorf("FromMillis(Millis(%v)) = %v, want %v in UTC", in, got, want)
	}
}
