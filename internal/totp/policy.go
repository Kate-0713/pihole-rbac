// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package totp

import (
	"context"
	"database/sql"
	"errors"
	"slices"

	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// Policy is a user's own setting for whether they must use TOTP. It wins over their roles'.
type Policy string

const (
	// PolicyRoles is no setting of their own: the user must use TOTP if any role they hold requires it.
	PolicyRoles Policy = ""
	// PolicyRequired makes the user use TOTP whatever their roles say.
	PolicyRequired Policy = "required"
	// PolicyExempt lets the user go without it whatever their roles say. They can still turn it on themselves.
	PolicyExempt Policy = "exempt"
)

// Valid reports whether p is one of the three policies.
func (p Policy) Valid() bool {
	return p == PolicyRoles || p == PolicyRequired || p == PolicyExempt
}

// Required reports whether someone must use TOTP: their own setting if they have one, otherwise whether any of the
// roles they hold is one that requires it.
func Required(user Policy, roleIDs, requiredRoleIDs []int64) bool {
	switch user {
	case PolicyRequired:
		return true
	case PolicyExempt:
		return false
	}
	for _, id := range roleIDs {
		if slices.Contains(requiredRoleIDs, id) {
			return true
		}
	}
	return false
}

// RequiredFor reads the settings and applies Required. roleIDs are the roles the user holds now: a session's roles,
// which for an LDAP user are the only record of them.
func RequiredFor(ctx context.Context, q *db.Queries, userID int64, roleIDs []int64) (bool, error) {
	user := PolicyRoles
	row, err := q.GetUserTOTPPolicy(ctx, userID)
	switch {
	case err == nil:
		user = Policy(row.Policy)
	case !errors.Is(err, sql.ErrNoRows):
		return false, err
	}
	if user != PolicyRoles {
		return Required(user, nil, nil), nil
	}
	required, err := q.ListTOTPRequiredRoleIDs(ctx)
	if err != nil {
		return false, err
	}
	return Required(user, roleIDs, required), nil
}

// Enabled reports whether the user has TOTP on: a secret confirmed with a code. A secret still waiting for its
// first code doesn't count.
func Enabled(ctx context.Context, q *db.Queries, userID int64) (bool, error) {
	row, err := q.GetUserTOTP(ctx, userID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return row.EnabledAt.Valid, nil
}
