// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package setup handles first-run setup and the break-glass admin reset.
//
// Until setup is complete, the app accepts only a one-time setup token, printed to the log at startup (or by
// `pihole-rbac setup --print-token`), and uses it to create the first local admin. Completing setup closes it for
// good; after that, `pihole-rbac user reset-admin` is the way back in if every admin is locked out.
package setup

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/auth"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// TokenTTL is how long a setup token stays valid.
const TokenTTL = time.Hour

var (
	ErrComplete     = errors.New("setup is already complete")
	ErrInvalidToken = errors.New("the setup token is wrong or has expired")
	ErrUsernameUsed = errors.New("that username is already taken")
	ErrNotLocal     = errors.New("that username belongs to an LDAP account; reset-admin only works on local accounts")
)

// StarterRole is an editable role created at setup, matching one of v1's fixed roles. All grants are at scope all.
type StarterRole struct {
	Name        string
	Description string
	Permissions []string
}

// StarterRoles are created when setup completes.
var StarterRoles = []StarterRole{
	{"staff", "View domains and clients, and edit clients' groups and comments. Matches v1's staff role.",
		[]string{"domains.view", "clients.view", "clients.edit"}},
	{"reader", "View domains and clients. Matches v1's reader role.",
		[]string{"domains.view", "clients.view"}},
}

// Required reports whether first-run setup is still open.
func Required(ctx context.Context, q *db.Queries) (bool, error) {
	st, err := q.GetSetupState(ctx)
	if err != nil {
		return false, fmt.Errorf("read setup state: %w", err)
	}
	return !st.CompletedAt.Valid, nil
}

// NewToken makes a fresh setup token, replacing any previous one, and returns it with its expiry. Only its SHA-256
// is stored. It returns ErrComplete once setup is done.
func NewToken(ctx context.Context, st *store.Store, now time.Time) (string, time.Time, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(token))
	expires := now.Add(TokenTTL)
	err := st.WithTx(ctx, func(q *db.Queries) error {
		n, err := q.SetSetupToken(ctx, db.SetSetupTokenParams{
			SetupTokenHash: hash[:],
			TokenExpiresAt: sql.NullInt64{Int64: store.Millis(expires), Valid: true},
		})
		if err == nil && n == 0 {
			err = ErrComplete
		}
		return err
	})
	if err != nil {
		return "", time.Time{}, err
	}
	return token, expires, nil
}

// checkToken compares token with the stored hash in constant time. Surrounding spaces, as left by copying from a
// terminal, are ignored.
func checkToken(st db.SetupState, token string, now time.Time) error {
	if st.CompletedAt.Valid {
		return ErrComplete
	}
	if st.SetupTokenHash == nil || !st.TokenExpiresAt.Valid || !now.Before(store.FromMillis(st.TokenExpiresAt.Int64)) {
		return ErrInvalidToken
	}
	got := sha256.Sum256([]byte(strings.TrimSpace(token)))
	if subtle.ConstantTimeCompare(got[:], st.SetupTokenHash) != 1 {
		return ErrInvalidToken
	}
	return nil
}

// Complete checks the setup token, creates the first local admin and the starter roles, and closes setup, all
// through q (the caller's transaction, which also writes the audit entry and the new session). It returns the
// admin's user ID and the builtin admin role's ID. Field errors are the auth package's validation errors, written to
// be shown to the user.
func Complete(ctx context.Context, q *db.Queries, token, username, password string, now time.Time) (userID, adminRoleID int64, err error) {
	state, err := q.GetSetupState(ctx)
	if err != nil {
		return 0, 0, err
	}
	if err := checkToken(state, token, now); err != nil {
		return 0, 0, err
	}
	username = auth.NormalizeUsername(username)
	if err := auth.ValidateUsername(username); err != nil {
		return 0, 0, err
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return 0, 0, err
	}

	u, err := q.CreateLocalUser(ctx, db.CreateLocalUserParams{
		Username: username, PasswordHash: sql.NullString{String: string(hash), Valid: true}, CreatedAt: store.Millis(now),
	})
	if store.Constraint(err) == store.Unique {
		return 0, 0, ErrUsernameUsed
	}
	if err != nil {
		return 0, 0, fmt.Errorf("create admin: %w", err)
	}
	admin, err := q.GetBuiltinRole(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("builtin admin role: %w", err)
	}
	if err := q.AddUserRole(ctx, db.AddUserRoleParams{UserID: u.ID, RoleID: admin.ID}); err != nil {
		return 0, 0, err
	}
	if err := createStarterRoles(ctx, q, now); err != nil {
		return 0, 0, err
	}
	if n, err := q.CompleteSetup(ctx, sql.NullInt64{Int64: store.Millis(now), Valid: true}); err != nil {
		return 0, 0, err
	} else if n == 0 {
		return 0, 0, ErrComplete
	}
	return u.ID, admin.ID, nil
}

// createStarterRoles creates any starter role that doesn't exist yet.
func createStarterRoles(ctx context.Context, q *db.Queries, now time.Time) error {
	for _, r := range StarterRoles {
		if _, err := q.GetRoleByName(ctx, r.Name); err == nil {
			continue
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		id, err := q.CreateRole(ctx, db.CreateRoleParams{Name: r.Name, Description: r.Description, CreatedAt: store.Millis(now)})
		if err != nil {
			return fmt.Errorf("create role %s: %w", r.Name, err)
		}
		for _, p := range r.Permissions {
			if err := q.AddRoleGrantAll(ctx, db.AddRoleGrantAllParams{RoleID: id, Permission: p}); err != nil {
				return fmt.Errorf("grant %s to %s: %w", p, r.Name, err)
			}
		}
	}
	return nil
}

// ResetResult says what ResetAdmin did.
type ResetResult struct {
	UserID        int64
	Created       bool  // the account didn't exist and was created
	SessionsEnded int64 // the account's sessions, ended because its password changed
}

// ResetAdmin is the break-glass recovery: it sets a local account's password, enables it and makes sure it holds the
// builtin admin role, creating the account if it doesn't exist. Every session of the account ends. If setup was
// still open, it is closed, since there is now an admin, and the starter roles are created. It works through q, the
// caller's transaction, which also writes the audit entry.
func ResetAdmin(ctx context.Context, q *db.Queries, username, password string, now time.Time) (ResetResult, error) {
	username = auth.NormalizeUsername(username)
	hash, err := auth.HashPassword(password)
	if err != nil {
		return ResetResult{}, err
	}
	pw := sql.NullString{String: string(hash), Valid: true}
	admin, err := q.GetBuiltinRole(ctx)
	if err != nil {
		return ResetResult{}, fmt.Errorf("builtin admin role: %w", err)
	}

	var res ResetResult
	u, err := q.GetUserByUsername(ctx, username)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if err := auth.ValidateUsername(username); err != nil {
			return ResetResult{}, err
		}
		created, err := q.CreateLocalUser(ctx, db.CreateLocalUserParams{Username: username, PasswordHash: pw, CreatedAt: store.Millis(now)})
		if err != nil {
			return ResetResult{}, fmt.Errorf("create admin: %w", err)
		}
		res.UserID, res.Created = created.ID, true
	case err != nil:
		return ResetResult{}, err
	case auth.Method(u.Source) != auth.MethodLocal:
		return ResetResult{}, ErrNotLocal
	default:
		res.UserID = u.ID
		if err := q.SetUserPassword(ctx, db.SetUserPasswordParams{PasswordHash: pw, ID: u.ID}); err != nil {
			return ResetResult{}, err
		}
		if err := q.SetUserDisabled(ctx, db.SetUserDisabledParams{Disabled: false, ID: u.ID}); err != nil {
			return ResetResult{}, err
		}
		if res.SessionsEnded, err = q.DeleteUserSessions(ctx, u.ID); err != nil {
			return ResetResult{}, err
		}
	}

	roles, err := q.ListUserRoleIDs(ctx, res.UserID)
	if err != nil {
		return ResetResult{}, err
	}
	hasAdmin := false
	for _, r := range roles {
		hasAdmin = hasAdmin || r == admin.ID
	}
	if !hasAdmin {
		if err := q.AddUserRole(ctx, db.AddUserRoleParams{UserID: res.UserID, RoleID: admin.ID}); err != nil {
			return ResetResult{}, err
		}
	}
	closed, err := q.CompleteSetup(ctx, sql.NullInt64{Int64: store.Millis(now), Valid: true})
	if err != nil {
		return ResetResult{}, err
	}
	if closed == 1 {
		// Setup never ran, so the starter roles it creates don't exist yet.
		if err := createStarterRoles(ctx, q, now); err != nil {
			return ResetResult{}, err
		}
	}
	return res, nil
}
