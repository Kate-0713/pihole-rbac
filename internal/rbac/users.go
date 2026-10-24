// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package rbac

import (
	"context"
	"database/sql"
	"errors"
	"slices"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/auth"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

func userTarget(username string) string { return "user:" + username }

// hashPassword hashes outside the write transaction, since bcrypt is slow and the writer is a single connection.
// field names the request field, for the refusal.
func hashPassword(field, password string) (string, error) {
	h, err := auth.HashPassword(password)
	if err != nil {
		return "", newError(CodeValidation, map[string]any{"field": field}, "The password %s.", trimPrefix(err.Error(), "password "))
	}
	return string(h), nil
}

func trimPrefix(s, prefix string) string {
	if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):]
	}
	return s
}

// rolesExist loads the roles and returns their IDs (sorted, without duplicates) and grants.
func (t *txn) rolesExist(roleIDs []int64) ([]int64, []Grant, error) {
	ids := slices.Compact(slices.Sorted(slices.Values(roleIDs)))
	for _, id := range ids {
		if _, err := t.q.GetRole(t.ctx, id); errors.Is(err, sql.ErrNoRows) {
			return nil, nil, newError(CodeValidation, map[string]any{"role_id": id}, "There is no role with ID %d.", id)
		} else if err != nil {
			return nil, nil, err
		}
	}
	grants, err := roleGrants(t.ctx, t.q, ids)
	return ids, grants, err
}

// CreateLocalUser creates a local user with the given roles. It needs users.manage and every grant of the roles
// (invariant 3). Usernames are unique across local and LDAP users.
func (m *Manager) CreateLocalUser(ctx context.Context, a Actor, username, password string, roleIDs []int64) (int64, error) {
	username = auth.NormalizeUsername(username)
	if err := auth.ValidateUsername(username); err != nil {
		return 0, newError(CodeValidation, map[string]any{"field": "username"}, "The username must be %s.", trimPrefix(err.Error(), "username must be "))
	}
	hash, err := hashPassword("password", password)
	if err != nil {
		return 0, err
	}
	var id int64
	err = m.do(ctx, a, audit.ActionUserCreate, func(t *txn) error {
		t.entry.Target = userTarget(username)
		if err := t.require(UsersManage); err != nil {
			return err
		}
		ids, grants, err := t.rolesExist(roleIDs)
		if err != nil {
			return err
		}
		if err := t.requireHolds(grants, "give a user roles"); err != nil {
			return err
		}
		u, err := t.q.CreateLocalUser(t.ctx, db.CreateLocalUserParams{
			Username: username, PasswordHash: sql.NullString{String: hash, Valid: true}, CreatedAt: store.Millis(t.now),
		})
		if store.Constraint(err) == store.Unique {
			return newError(CodeConflict, map[string]any{"field": "username"}, "The username %q is already taken.", username)
		}
		if err != nil {
			return err
		}
		id = u.ID
		for _, r := range ids {
			if err := t.q.AddUserRole(t.ctx, db.AddUserRoleParams{UserID: id, RoleID: r}); err != nil {
				return err
			}
		}
		t.entry.Detail["user_id"] = id
		t.entry.Detail["roles"] = ids
		return nil
	})
	return id, err
}

// managedUser loads a user for a change that invariant 7 covers: the actor needs users.manage and every grant of
// every role the user has.
func (t *txn) managedUser(userID int64) (db.User, error) {
	if err := t.require(UsersManage); err != nil {
		return db.User{}, err
	}
	u, err := t.user(userID)
	if err != nil {
		return u, err
	}
	t.entry.Target = userTarget(u.Username)
	t.entry.Detail["user_id"] = u.ID
	return u, t.requireNotAbove(u)
}

// SetUserRoles replaces a local user's roles. It needs users.manage, every grant of the user's current roles
// (invariant 7) and of every role added or removed (invariant 3). At least one enabled local admin must remain
// (invariant 2), and changing one's own roles so as to lose roles.manage or users.manage needs confirm (invariant 4).
// The user's sessions get the new roles in the same transaction, or end if no role is left.
func (m *Manager) SetUserRoles(ctx context.Context, a Actor, userID int64, roleIDs []int64, confirm bool) error {
	return m.do(ctx, a, audit.ActionUserRoles, func(t *txn) error {
		u, err := t.managedUser(userID)
		if err != nil {
			return err
		}
		if auth.Method(u.Source) != auth.MethodLocal {
			return newError(CodeValidation, map[string]any{"user_id": userID},
				"%s is an LDAP user, whose roles come from LDAP group mappings.", u.Username)
		}
		ids, grants, err := t.rolesExist(roleIDs)
		if err != nil {
			return err
		}
		if err := t.requireHolds(grants, "give a user roles"); err != nil {
			return err
		}
		old, err := t.q.ListUserRoleIDs(t.ctx, userID)
		if err != nil {
			return err
		}
		if slices.Equal(old, ids) {
			return errNoChange
		}
		if userID == t.actor.UserID {
			after, err := t.setAfter(ids, nil)
			if err != nil {
				return err
			}
			if err := t.confirmSelfDemotion(after, confirm); err != nil {
				return err
			}
		}
		if err := t.q.DeleteUserRoles(t.ctx, userID); err != nil {
			return err
		}
		for _, r := range ids {
			if err := t.q.AddUserRole(t.ctx, db.AddUserRoleParams{UserID: userID, RoleID: r}); err != nil {
				return err
			}
		}
		if err := t.checkAdmins(); err != nil {
			return err
		}
		t.entry.Detail["roles"] = ids
		t.entry.Detail["previous_roles"] = old
		if len(ids) == 0 {
			// No role means no access: fail closed rather than keep a session that can do nothing.
			return t.endSessions(userID, "")
		}
		if err := t.q.ClearSessionRolesForUser(t.ctx, userID); err != nil {
			return err
		}
		for _, r := range ids {
			if err := t.q.AddSessionRoleForUser(t.ctx, db.AddSessionRoleForUserParams{RoleID: r, UserID: userID}); err != nil {
				return err
			}
		}
		return nil
	})
}

// SetUserDisabled disables or enables a user. It needs users.manage and every grant of the user's roles (invariant 7).
// Disabling ends the user's sessions, must leave an enabled local admin (invariant 2), and needs confirm for one's own
// account (invariant 4).
func (m *Manager) SetUserDisabled(ctx context.Context, a Actor, userID int64, disabled, confirm bool) error {
	action := audit.ActionUserEnable
	if disabled {
		action = audit.ActionUserDisable
	}
	return m.do(ctx, a, action, func(t *txn) error {
		u, err := t.managedUser(userID)
		if err != nil {
			return err
		}
		if u.Disabled == disabled {
			return errNoChange
		}
		if disabled && userID == t.actor.UserID && !confirm {
			return newError(CodeConfirmation, map[string]any{"would_lose": "account"},
				"This would disable your own account and end your session. Confirm to go ahead.")
		}
		if err := t.q.SetUserDisabled(t.ctx, db.SetUserDisabledParams{Disabled: disabled, ID: userID}); err != nil {
			return err
		}
		if !disabled {
			return nil
		}
		if err := t.checkAdmins(); err != nil {
			return err
		}
		return t.endSessions(userID, "")
	})
}

// DeleteUser deletes a user, their role assignments and sessions. It needs users.manage and every grant of the
// user's roles (invariant 7), must leave an enabled local admin (invariant 2), and needs confirm for one's own
// account (invariant 4). The audit log keeps the username.
func (m *Manager) DeleteUser(ctx context.Context, a Actor, userID int64, confirm bool) error {
	return m.do(ctx, a, audit.ActionUserDelete, func(t *txn) error {
		u, err := t.managedUser(userID)
		if err != nil {
			return err
		}
		self := userID == t.actor.UserID
		if self && !confirm {
			return newError(CodeConfirmation, map[string]any{"would_lose": "account"},
				"This would delete your own account and end your session. Confirm to go ahead.")
		}
		t.entry.Detail["source"] = u.Source
		if err := t.q.DeleteUser(t.ctx, userID); err != nil {
			return err
		}
		if self {
			// The audit row's user_id references users; the username is kept in the row.
			t.entry.UserID = 0
		}
		return t.checkAdmins()
	})
}

// SetUserPassword sets a local user's password. It needs users.manage and every grant of the user's roles
// (invariant 7), so nobody can take over an account more privileged than their own. The user's sessions end, except
// the actor's current one when they set their own password.
func (m *Manager) SetUserPassword(ctx context.Context, a Actor, userID int64, password string) error {
	hash, err := hashPassword("password", password)
	if err != nil {
		return err
	}
	return m.do(ctx, a, audit.ActionUserPassword, func(t *txn) error {
		u, err := t.managedUser(userID)
		if err != nil {
			return err
		}
		if auth.Method(u.Source) != auth.MethodLocal {
			return newError(CodeValidation, map[string]any{"user_id": userID},
				"%s is an LDAP user, whose password is managed in the directory.", u.Username)
		}
		if err := t.q.SetUserPassword(t.ctx, db.SetUserPasswordParams{PasswordHash: sql.NullString{String: hash, Valid: true}, ID: userID}); err != nil {
			return err
		}
		keep := ""
		if userID == t.actor.UserID {
			keep = t.actor.PublicID
		}
		return t.endSessions(userID, keep)
	})
}

// ChangeOwnPassword changes the actor's own password, given their current one. It needs no permission: every local
// user may change their own password. A wrong current password is auth.ErrInvalidCredentials, which the API counts
// against the login limits and audits, so this can't be used to guess passwords faster than the login page. The
// actor's other sessions end; the one they changed it from is kept.
func (m *Manager) ChangeOwnPassword(ctx context.Context, a Actor, current, password string) error {
	if a.Source != auth.MethodLocal {
		return newError(CodeValidation, map[string]any{"field": "current_password"},
			"Your password is managed in the directory, so it can't be changed here.")
	}
	// The new password's rules first: they say nothing about the current one, and need no bcrypt.
	if err := auth.ValidatePassword(password); err != nil {
		return newError(CodeValidation, map[string]any{"field": "new_password"}, "The new password %s.", trimPrefix(err.Error(), "password "))
	}
	before, err := m.Store.Read().GetUser(ctx, a.UserID)
	if err != nil {
		return err
	}
	if !before.PasswordHash.Valid || !auth.CheckPassword(before.PasswordHash.String, current) {
		return auth.ErrInvalidCredentials
	}
	if current == password {
		return newError(CodeValidation, map[string]any{"field": "new_password"}, "The new password must be different from the current one.")
	}
	hash, err := hashPassword("new_password", password)
	if err != nil {
		return err
	}
	return m.do(ctx, a, audit.ActionPasswordChange, func(t *txn) error {
		u, err := t.user(a.UserID)
		if err != nil {
			return err
		}
		t.entry.Target = userTarget(u.Username)
		t.entry.Detail["user_id"] = u.ID
		if u.PasswordHash != before.PasswordHash {
			// Someone set it between the check above and now, so the current password checked may be out of date.
			return newError(CodeConflict, nil, "Your password was changed at the same time by someone else. Try again.")
		}
		if err := t.q.SetUserPassword(t.ctx, db.SetUserPasswordParams{PasswordHash: sql.NullString{String: hash, Valid: true}, ID: u.ID}); err != nil {
			return err
		}
		return t.endSessions(u.ID, a.PublicID)
	})
}
