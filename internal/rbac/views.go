// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package rbac

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// RoleDetails is a role as the admin pages show it: its grants, and what uses it.
type RoleDetails struct {
	Role       db.Role
	Grants     []Grant  // sorted
	Users      []string // local users holding the role, by username
	LDAPGroups []string // group DNs mapped to the role, as entered
	// TOTPRequired says whether the role's holders must use two-factor login.
	TOTPRequired bool
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
	required, err := q.ListTOTPRequiredRoleIDs(ctx)
	if err != nil {
		return nil, fmt.Errorf("rbac: list roles requiring TOTP: %w", err)
	}
	for i := range out {
		SortGrants(out[i].Grants)
		out[i].TOTPRequired = slices.Contains(required, out[i].Role.ID)
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
	required, err := q.ListTOTPRequiredRoleIDs(ctx)
	if err != nil {
		return RoleDetails{}, err
	}
	d := RoleDetails{
		Role: r, Grants: grants, Users: users, LDAPGroups: make([]string, len(mappings)),
		TOTPRequired: slices.Contains(required, id),
	}
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

// UserDetails is a user as the admin pages show them: their roles, and the grants those roles carry, so the caller
// can tell whether they may manage the user (invariant 7).
type UserDetails struct {
	User   db.User
	Roles  []RoleRef // sorted by name
	Grants []Grant   // every grant of every role, for working out whether the caller holds them all
	// TOTPEnabled says whether the user has two-factor login on. A secret waiting for its first code doesn't count.
	TOTPEnabled bool
	// TOTPPolicy is the user's own setting: "required", "exempt", or "" when their roles decide.
	TOTPPolicy string
	// TOTPRequired says whether the user must use two-factor login: by their own setting, or failing that by one of
	// Roles. An LDAP user's roles are only known while they are logged in.
	TOTPRequired bool
}

// RoleRef names a role.
type RoleRef struct {
	ID   int64
	Name string
}

// ListUsers returns every user with their roles, sorted by username. A local user's roles are their assigned ones;
// an LDAP user's are the roles their current sessions hold, which is the only record of them (they come from the
// directory at login and at each recheck), so an LDAP user who isn't logged in has none listed.
func ListUsers(ctx context.Context, q *db.Queries) ([]UserDetails, error) {
	users, err := q.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("rbac: list users: %w", err)
	}
	roles, err := q.ListRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("rbac: list roles: %w", err)
	}
	grants, err := q.ListAllGrants(ctx)
	if err != nil {
		return nil, fmt.Errorf("rbac: list grants: %w", err)
	}
	local, err := q.ListAllUserRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("rbac: list user roles: %w", err)
	}
	ldap, err := q.ListLDAPSessionRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("rbac: list LDAP session roles: %w", err)
	}
	totp, err := q.ListTOTPUserIDs(ctx)
	if err != nil {
		return nil, fmt.Errorf("rbac: list users with TOTP: %w", err)
	}
	policies, err := q.ListUserTOTPPolicies(ctx)
	if err != nil {
		return nil, fmt.Errorf("rbac: list users' TOTP settings: %w", err)
	}
	policy := make(map[int64]string, len(policies))
	for _, p := range policies {
		policy[p.UserID] = p.Policy
	}
	requiring, err := q.ListTOTPRequiredRoleIDs(ctx)
	if err != nil {
		return nil, fmt.Errorf("rbac: list roles requiring TOTP: %w", err)
	}

	// ListRoles is sorted by name, so each user's roles come out in that order.
	order := make(map[int64]int, len(roles))
	for i, r := range roles {
		order[r.ID] = i
	}
	byRole := map[int64][]Grant{}
	for _, g := range grants {
		byRole[g.RoleID] = append(byRole[g.RoleID], grantFromRow(g))
	}
	held := map[int64][]int64{}
	for _, r := range local {
		held[r.UserID] = append(held[r.UserID], r.RoleID)
	}
	for _, r := range ldap {
		held[r.UserID] = append(held[r.UserID], r.RoleID)
	}

	out := make([]UserDetails, len(users))
	for i, u := range users {
		ids := held[u.ID]
		slices.SortFunc(ids, func(a, b int64) int { return order[a] - order[b] })
		d := UserDetails{User: u, Roles: make([]RoleRef, 0, len(ids)), Grants: []Grant{}, TOTPEnabled: slices.Contains(totp, u.ID)}
		for _, id := range ids {
			d.Roles = append(d.Roles, RoleRef{ID: id, Name: roles[order[id]].Name})
			d.Grants = append(d.Grants, byRole[id]...)
			d.TOTPRequired = d.TOTPRequired || slices.Contains(requiring, id)
		}
		// The user's own setting wins over their roles', as totp.Required has it.
		switch d.TOTPPolicy = policy[u.ID]; d.TOTPPolicy {
		case "required":
			d.TOTPRequired = true
		case "exempt":
			d.TOTPRequired = false
		}
		out[i] = d
	}
	return out, nil
}

// GetUserDetails returns one user with their roles, or a not_found refusal. It reads the whole list, which is a
// handful of rows in any install, so the two can't disagree about what a user's roles are.
func GetUserDetails(ctx context.Context, q *db.Queries, id int64) (UserDetails, error) {
	all, err := ListUsers(ctx, q)
	if err != nil {
		return UserDetails{}, err
	}
	for _, d := range all {
		if d.User.ID == id {
			return d, nil
		}
	}
	return UserDetails{}, newError(CodeNotFound, map[string]any{"user_id": id}, "There is no user with ID %d.", id)
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
