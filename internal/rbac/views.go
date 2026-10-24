// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package rbac

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// RoleDetails is a role as the admin pages show it: its grants, and what uses it.
type RoleDetails struct {
	Role       db.Role
	Grants     []Grant  // sorted
	Users      []string // local users holding the role, by username
	LDAPGroups []string // group DNs mapped to the role, as entered
}

// ListRoles returns every role with its details, sorted by name.
func ListRoles(ctx context.Context, q *db.Queries) ([]RoleDetails, error) {
	roles, err := q.ListRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("rbac: list roles: %w", err)
	}
	grants, err := q.ListAllGrants(ctx)
	if err != nil {
		return nil, fmt.Errorf("rbac: list grants: %w", err)
	}
	users, err := q.ListRoleUsernames(ctx)
	if err != nil {
		return nil, fmt.Errorf("rbac: list role users: %w", err)
	}
	mappings, err := q.ListAllLDAPMappings(ctx)
	if err != nil {
		return nil, fmt.Errorf("rbac: list LDAP mappings: %w", err)
	}

	byID := make(map[int64]*RoleDetails, len(roles))
	out := make([]RoleDetails, len(roles))
	for i, r := range roles {
		out[i] = RoleDetails{Role: r, Grants: []Grant{}, Users: []string{}, LDAPGroups: []string{}}
		byID[r.ID] = &out[i]
	}
	for _, g := range grants {
		if d := byID[g.RoleID]; d != nil {
			d.Grants = append(d.Grants, grantFromRow(g))
		}
	}
	for _, u := range users {
		if d := byID[u.RoleID]; d != nil {
			d.Users = append(d.Users, u.Username)
		}
	}
	for _, m := range mappings {
		if d := byID[m.RoleID]; d != nil {
			d.LDAPGroups = append(d.LDAPGroups, m.GroupDn)
		}
	}
	for i := range out {
		SortGrants(out[i].Grants)
	}
	return out, nil
}

// GetRoleDetails returns one role with its details, or a not_found refusal.
func GetRoleDetails(ctx context.Context, q *db.Queries, id int64) (RoleDetails, error) {
	r, err := q.GetRole(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return RoleDetails{}, newError(CodeNotFound, map[string]any{"role_id": id}, "There is no role with ID %d.", id)
	}
	if err != nil {
		return RoleDetails{}, err
	}
	grants, err := roleGrants(ctx, q, []int64{id})
	if err != nil {
		return RoleDetails{}, err
	}
	SortGrants(grants)
	users, err := q.ListUsernamesWithRole(ctx, id)
	if err != nil {
		return RoleDetails{}, err
	}
	mappings, err := q.ListLDAPMappingsForRole(ctx, id)
	if err != nil {
		return RoleDetails{}, err
	}
	d := RoleDetails{Role: r, Grants: grants, Users: users, LDAPGroups: make([]string, len(mappings))}
	if d.Grants == nil {
		d.Grants = []Grant{}
	}
	if d.Users == nil {
		d.Users = []string{}
	}
	for i, m := range mappings {
		d.LDAPGroups[i] = m.GroupDn
	}
	return d, nil
}

// ForbiddenEither is the refusal for an operation that any one of several global permissions allows.
// details.permission names them as the spec's x-permission does, separated by "|".
func ForbiddenEither(ps ...Permission) *Error {
	names := make([]string, len(ps))
	for i, p := range ps {
		names[i] = string(p)
	}
	return newError(CodeForbidden, map[string]any{"permission": strings.Join(names, "|")},
		"You need the %s permission to do that.", joinOr(names))
}

// joinOr joins with commas and a final "or": "a", "a or b", "a, b or c".
func joinOr(s []string) string {
	j := joinStrings(s)
	if len(s) < 2 {
		return j
	}
	// joinStrings ends with " and <last>"; swap that one for " or ".
	last := " and " + s[len(s)-1]
	return j[:len(j)-len(last)] + " or " + s[len(s)-1]
}
