// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package rbac

import (
	"context"
	"fmt"

	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// Resolve builds the permission set for a list of role IDs, normally a session's, from their grants and the current
// topology. There is no cache: it is three small indexed reads, and with nothing to invalidate, a change to grants,
// group membership or group mode applies to the next request.
func Resolve(ctx context.Context, q *db.Queries, roleIDs []int64) (*Set, error) {
	topo, err := LoadTopology(ctx, q)
	if err != nil {
		return nil, err
	}
	grants, err := roleGrants(ctx, q, roleIDs)
	if err != nil {
		return nil, err
	}
	return NewSet(grants, topo), nil
}

// roleGrants returns the grants of the given roles.
func roleGrants(ctx context.Context, q *db.Queries, roleIDs []int64) ([]Grant, error) {
	if len(roleIDs) == 0 {
		return nil, nil
	}
	rows, err := q.ListGrantsForRoles(ctx, roleIDs)
	if err != nil {
		return nil, fmt.Errorf("rbac: list grants: %w", err)
	}
	out := make([]Grant, len(rows))
	for i, r := range rows {
		out[i] = grantFromRow(r)
	}
	return out, nil
}

func grantFromRow(r db.RoleGrant) Grant {
	g := Grant{Permission: Permission(r.Permission), Scope: Scope{Type: ScopeType(r.ScopeType)}}
	switch g.Scope.Type {
	case ScopeInstance:
		g.Scope.ID = r.InstanceID.Int64
	case ScopeGroup:
		g.Scope.ID = r.GroupID.Int64
	}
	return g
}

// ValidateGrant checks a grant against the catalogue and the topology (invariant 6, valid scope): the permission
// exists, its scope is one the permission's class allows, and the instance or group exists. A group-class permission
// can only be granted on a mirrored group.
func ValidateGrant(topo *Topology, g Grant) error {
	info, ok := Lookup(string(g.Permission))
	if !ok {
		return newError(CodeValidation, map[string]any{"permission": g.Permission}, "%q isn't a known permission.", g.Permission)
	}
	details := map[string]any{"grant": g.String()}
	switch g.Scope.Type {
	case ScopeAll:
		if g.Scope.ID != 0 {
			return newError(CodeValidation, details, "A grant at scope all has no instance or group.")
		}
		return nil
	case ScopeInstance:
		if !topo.HasInstance(g.Scope.ID) {
			return newError(CodeValidation, details, "There is no instance with ID %d.", g.Scope.ID)
		}
		if info.Class != ClassInstance {
			return newError(CodeInvariant, details, "%s can't be granted on a single instance: %s", g.Permission, classRule(info.Class))
		}
		return nil
	case ScopeGroup:
		mode, ok := topo.Group(g.Scope.ID)
		if !ok {
			return newError(CodeValidation, details, "There is no group with ID %d.", g.Scope.ID)
		}
		switch {
		case info.Class == ClassGlobal:
			return newError(CodeInvariant, details, "%s can't be granted on a group: %s", g.Permission, classRule(info.Class))
		case info.Class == ClassGroup && mode != Mirrored:
			return newError(CodeInvariant, details, "%s can't be granted on an independent group: %s", g.Permission, classRule(info.Class))
		}
		return nil
	}
	return newError(CodeValidation, details, "%q isn't a scope; use all, group or instance.", g.Scope.Type)
}

func classRule(c Class) string {
	switch c {
	case ClassGlobal:
		return "it applies to the whole app, so it is only granted at scope all."
	case ClassGroup:
		return "it only means something for mirrored groups, so it is granted at scope all or on a mirrored group."
	}
	return "it can be granted at scope all, on a group or on an instance."
}
