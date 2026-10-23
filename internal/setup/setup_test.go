// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package setup

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"slices"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/Kate-0713/pihole-rbac/internal/auth"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

var t0 = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), store.Options{DataDir: t.TempDir(), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func complete(t *testing.T, st *store.Store, token, user, pw string, now time.Time) (int64, error) {
	t.Helper()
	var id int64
	err := st.WithTx(context.Background(), func(q *db.Queries) error {
		var err error
		id, _, err = Complete(context.Background(), q, token, user, pw, now)
		return err
	})
	return id, err
}

func required(t *testing.T, st *store.Store) bool {
	t.Helper()
	r, err := Required(context.Background(), st.Read())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestFreshDatabaseNeedsSetup(t *testing.T) {
	if !required(t, openStore(t)) {
		t.Fatal("a fresh database doesn't need setup")
	}
}

func TestComplete(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	token, expires, err := NewToken(ctx, st, t0)
	if err != nil {
		t.Fatal(err)
	}
	if !expires.Equal(t0.Add(TokenTTL)) || len(token) != 43 {
		t.Fatalf("token %q expires %v", token, expires)
	}
	state, _ := st.Read().GetSetupState(ctx)
	if string(state.SetupTokenHash) == token {
		t.Fatal("token stored in plain text")
	}

	id, err := complete(t, st, "  "+token+"\n", " Admin ", "first-admin-password", t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if required(t, st) {
		t.Fatal("setup still open")
	}
	q := st.Read()
	u, err := q.GetUser(ctx, id)
	if err != nil || u.Username != "admin" || u.Source != "local" || u.Disabled ||
		bcrypt.CompareHashAndPassword([]byte(u.PasswordHash.String), []byte("first-admin-password")) != nil {
		t.Fatalf("admin = %+v, %v", u, err)
	}
	if roles, _ := q.ListUserRoleIDs(ctx, id); !slices.Equal(roles, []int64{1}) {
		t.Fatalf("admin roles = %v", roles)
	}
	for _, r := range StarterRoles {
		role, err := q.GetRoleByName(ctx, r.Name)
		if err != nil {
			t.Fatalf("starter role %s: %v", r.Name, err)
		}
		grants, _ := q.ListGrantsForRole(ctx, role.ID)
		var perms []string
		for _, g := range grants {
			if g.ScopeType != "all" {
				t.Fatalf("%s grant %+v isn't scope all", r.Name, g)
			}
			perms = append(perms, g.Permission)
		}
		want := slices.Sorted(slices.Values(r.Permissions))
		if !slices.Equal(perms, want) {
			t.Fatalf("%s grants = %v, want %v", r.Name, perms, want)
		}
	}
	state, _ = q.GetSetupState(ctx)
	if state.SetupTokenHash != nil || state.TokenExpiresAt.Valid || !state.CompletedAt.Valid {
		t.Fatalf("setup state after completion = %+v", state)
	}

	// Setup is closed for good: the old token, a new token and a second completion all fail.
	if _, err := complete(t, st, token, "other", "other-admin-password", t0.Add(2*time.Minute)); !errors.Is(err, ErrComplete) {
		t.Fatalf("second completion: err = %v", err)
	}
	if _, _, err := NewToken(ctx, st, t0); !errors.Is(err, ErrComplete) {
		t.Fatalf("new token after setup: err = %v", err)
	}
}

func TestCompleteFailuresChangeNothing(t *testing.T) {
	tests := []struct {
		name     string
		token    func(real string) string
		user, pw string
		at       time.Duration // after the token was made
		want     error
	}{
		{"wrong token", func(string) string { return "wrong" }, "admin", "first-admin-password", 0, ErrInvalidToken},
		{"empty token", func(string) string { return "" }, "admin", "first-admin-password", 0, ErrInvalidToken},
		{"expired token", func(r string) string { return r }, "admin", "first-admin-password", TokenTTL, ErrInvalidToken},
		{"bad username", func(r string) string { return r }, "a/b", "first-admin-password", 0, auth.ErrInvalidUsername},
		{"short password", func(r string) string { return r }, "admin", "short", 0, auth.ErrPasswordTooShort},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := openStore(t)
			token, _, err := NewToken(context.Background(), st, t0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := complete(t, st, tt.token(token), tt.user, tt.pw, t0.Add(tt.at)); !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if !required(t, st) {
				t.Fatal("a failed completion closed setup")
			}
			if _, err := st.Read().GetUserByUsername(context.Background(), "admin"); !errors.Is(err, sql.ErrNoRows) {
				t.Fatal("a failed completion created a user")
			}
		})
	}
}

func TestNoTokenYet(t *testing.T) {
	// Before any token is made (e.g. the token step failed), nothing can complete setup.
	if _, err := complete(t, openStore(t), "", "admin", "first-admin-password", t0); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("err = %v", err)
	}
}

func TestNewTokenReplacesOld(t *testing.T) {
	st := openStore(t)
	old, _, _ := NewToken(context.Background(), st, t0)
	if _, _, err := NewToken(context.Background(), st, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := complete(t, st, old, "admin", "first-admin-password", t0); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("old token after a new one: err = %v", err)
	}
}

func resetAdmin(t *testing.T, st *store.Store, user, pw string) (ResetResult, error) {
	t.Helper()
	var res ResetResult
	err := st.WithTx(context.Background(), func(q *db.Queries) error {
		var err error
		res, err = ResetAdmin(context.Background(), q, user, pw, t0)
		return err
	})
	return res, err
}

func TestResetAdmin(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	token, _, _ := NewToken(ctx, st, t0)
	adminID, err := complete(t, st, token, "admin", "first-admin-password", t0)
	if err != nil {
		t.Fatal(err)
	}

	// The admin is locked out: disabled, with a session still around and a role removed by hand.
	err = st.WithTx(ctx, func(q *db.Queries) error {
		if err := q.SetUserDisabled(ctx, db.SetUserDisabledParams{Disabled: true, ID: adminID}); err != nil {
			return err
		}
		return q.CreateSession(ctx, db.CreateSessionParams{
			IDHash: make([]byte, 32), PublicID: "AAAAAAAAAAAAAAAAAAAAAA", UserID: adminID, CreatedAt: 0, ExpiresAt: 1,
		})
	})
	if err != nil {
		t.Fatal(err)
	}

	res, err := resetAdmin(t, st, "Admin", "recovered-password-1")
	if err != nil {
		t.Fatal(err)
	}
	if res.Created || res.UserID != adminID || res.SessionsEnded != 1 {
		t.Fatalf("result = %+v", res)
	}
	u, _ := st.Read().GetUser(ctx, adminID)
	if u.Disabled || bcrypt.CompareHashAndPassword([]byte(u.PasswordHash.String), []byte("recovered-password-1")) != nil {
		t.Fatalf("admin after reset = %+v", u)
	}

	// A new name creates a new local admin.
	res, err = resetAdmin(t, st, "rescue", "recovered-password-2")
	if err != nil || !res.Created {
		t.Fatalf("result = %+v, %v", res, err)
	}
	if roles, _ := st.Read().ListUserRoleIDs(ctx, res.UserID); !slices.Equal(roles, []int64{1}) {
		t.Fatalf("rescue roles = %v", roles)
	}
}

func TestResetAdminRefusals(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	if err := st.WithTx(ctx, func(q *db.Queries) error {
		_, err := q.CreateLDAPUser(ctx, db.CreateLDAPUserParams{Username: "ldapuser", LdapDn: sql.NullString{String: "cn=x", Valid: true}})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, user, pw string
		want           error
	}{
		{"LDAP account", "ldapuser", "recovered-password-1", ErrNotLocal},
		{"short password", "admin", "short", auth.ErrPasswordTooShort},
		{"bad new username", "a/b", "recovered-password-1", auth.ErrInvalidUsername},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := resetAdmin(t, st, tt.user, tt.pw); !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
	if !required(t, st) {
		t.Fatal("a refused reset closed setup")
	}
}

func TestResetAdminBeforeSetupClosesIt(t *testing.T) {
	st := openStore(t)
	if _, err := resetAdmin(t, st, "admin", "recovered-password-1"); err != nil {
		t.Fatal(err)
	}
	if required(t, st) {
		t.Fatal("setup still open after reset-admin created an admin")
	}
	for _, r := range StarterRoles {
		if _, err := st.Read().GetRoleByName(context.Background(), r.Name); err != nil {
			t.Fatalf("starter role %s missing: %v", r.Name, err)
		}
	}
}
