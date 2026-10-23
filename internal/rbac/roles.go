// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package rbac

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/auth"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

const (
	maxRoleName    = 64
	maxDescription = 500
	maxDNLength    = 1024
)

// RoleInput is a role's editable fields.
type RoleInput struct {
	Name        string
	Description string
}

func (in RoleInput) normalize() (RoleInput, error) {
	in.Name = strings.TrimSpace(in.Name)
	in.Description = strings.TrimSpace(in.Description)
	if n := utf8.RuneCountInString(in.Name); n == 0 || n > maxRoleName || hasControl(in.Name, false) {
		return in, newError(CodeValidation, map[string]any{"field": "name"},
			"A role name is 1-%d characters, with no control characters.", maxRoleName)
	}
	if utf8.RuneCountInString(in.Description) > maxDescription || hasControl(in.Description, true) {
		return in, newError(CodeValidation, map[string]any{"field": "description"},
			"A description is at most %d characters, with no control characters other than line breaks.", maxDescription)
	}
	return in, nil
}

// hasControl reports whether s contains control characters (or invalid UTF-8). Line breaks and tabs are allowed when
// multiline is set.
func hasControl(s string, multiline bool) bool {
	if !utf8.ValidString(s) {
		return true
	}
	for _, r := range s {
		if multiline && (r == '\n' || r == '\t') {
			continue
		}
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func roleTarget(name string) string { return "role:" + name }

// CreateRole creates a role with the given grants. It needs roles.manage, and the actor must hold every grant
// (invariant 3), each of which must be valid for its permission (invariant 6).
func (m *Manager) CreateRole(ctx context.Context, a Actor, in RoleInput, grants []Grant) (int64, error) {
	var id int64
	err := m.do(ctx, a, audit.ActionRoleCreate, func(t *txn) error {
		in, err := in.normalize()
		if err != nil {
			return err
		}
		t.entry.Target = roleTarget(in.Name)
		if err := t.require(RolesManage); err != nil {
			return err
		}
		grants, err := t.normalizeGrants(grants)
		if err != nil {
			return err
		}
		if err := t.requireHolds(grants, "create a role"); err != nil {
			return err
		}
		id, err = t.q.CreateRole(t.ctx, db.CreateRoleParams{Name: in.Name, Description: in.Description, CreatedAt: store.Millis(t.now)})
		if store.Constraint(err) == store.Unique {
			return newError(CodeConflict, map[string]any{"field": "name"}, "There is already a role called %q.", in.Name)
		}
		if err != nil {
			return err
		}
		t.entry.Detail["role_id"] = id
		t.entry.Detail["grants"] = grantStrings(grants)
		return t.insertGrants(id, grants)
	})
	return id, err
}

// UpdateRole renames a role or changes its description. It needs roles.manage and every grant the role has
// (invariant 3). The builtin admin role can't be changed (invariant 1).
func (m *Manager) UpdateRole(ctx context.Context, a Actor, roleID int64, in RoleInput) error {
	return m.do(ctx, a, audit.ActionRoleUpdate, func(t *txn) error {
		if err := t.require(RolesManage); err != nil {
			return err
		}
		in, err := in.normalize()
		if err != nil {
			return err
		}
		r, grants, err := t.editableRole(roleID)
		if err != nil {
			return err
		}
		if err := t.requireHolds(grants, "change a role"); err != nil {
			return err
		}
		if in.Name == r.Name && in.Description == r.Description {
			return errNoChange
		}
		err = t.q.UpdateRole(t.ctx, db.UpdateRoleParams{Name: in.Name, Description: in.Description, ID: roleID})
		if store.Constraint(err) == store.Unique {
			return newError(CodeConflict, map[string]any{"field": "name"}, "There is already a role called %q.", in.Name)
		}
		t.entry.Detail["role_id"] = roleID
		if in.Name != r.Name {
			t.entry.Detail["renamed_from"] = r.Name
		}
		return err
	})
}

// editableRole loads a role that may be changed: any role but the builtin admin (invariant 1). It also sets the
// audit target.
func (t *txn) editableRole(roleID int64) (db.Role, []Grant, error) {
	r, grants, err := t.role(roleID)
	if err != nil {
		return r, nil, err
	}
	t.entry.Target = roleTarget(r.Name)
	if r.Builtin {
		return r, nil, newError(CodeInvariant, map[string]any{"role_id": roleID}, "The builtin admin role can't be changed or deleted.")
	}
	return r, grants, nil
}

// SetRoleGrants replaces a role's grants. It needs roles.manage, and the actor must hold every grant the role has
// before and after the change (invariant 3). If the change would take away the actor's own last route to
// roles.manage or users.manage, it needs confirm (invariant 4). Sessions need nothing: permissions are resolved from
// role IDs on every request.
func (m *Manager) SetRoleGrants(ctx context.Context, a Actor, roleID int64, grants []Grant, confirm bool) error {
	return m.do(ctx, a, audit.ActionRoleGrants, func(t *txn) error {
		if err := t.require(RolesManage); err != nil {
			return err
		}
		_, old, err := t.editableRole(roleID)
		if err != nil {
			return err
		}
		grants, err := t.normalizeGrants(grants)
		if err != nil {
			return err
		}
		if err := t.requireHolds(append(slices.Clone(old), grants...), "change a role's grants"); err != nil {
			return err
		}
		added, removed := diffGrants(old, grants)
		if len(added) == 0 && len(removed) == 0 {
			return errNoChange
		}
		if containsID(t.actor.RoleIDs, roleID) {
			after, err := t.setAfter(t.actor.RoleIDs, map[int64][]Grant{roleID: grants})
			if err != nil {
				return err
			}
			if err := t.confirmSelfDemotion(after, confirm); err != nil {
				return err
			}
		}
		if err := t.q.DeleteRoleGrants(t.ctx, roleID); err != nil {
			return err
		}
		t.entry.Detail["role_id"] = roleID
		t.entry.Detail["added"] = grantStrings(added)
		t.entry.Detail["removed"] = grantStrings(removed)
		return t.insertGrants(roleID, grants)
	})
}

// DeleteRole deletes a role that no user or LDAP mapping uses (invariant 5). It needs roles.manage and every grant
// the role has (invariant 3).
func (m *Manager) DeleteRole(ctx context.Context, a Actor, roleID int64) error {
	return m.do(ctx, a, audit.ActionRoleDelete, func(t *txn) error {
		if err := t.require(RolesManage); err != nil {
			return err
		}
		r, grants, err := t.editableRole(roleID)
		if err != nil {
			return err
		}
		if err := t.requireHolds(grants, "delete a role"); err != nil {
			return err
		}
		users, err := t.q.ListUsernamesWithRole(t.ctx, roleID)
		if err != nil {
			return err
		}
		mappings, err := t.q.ListLDAPMappingsForRole(t.ctx, roleID)
		if err != nil {
			return err
		}
		if len(users) > 0 || len(mappings) > 0 {
			dns := make([]string, len(mappings))
			for i, mp := range mappings {
				dns[i] = mp.GroupDn
			}
			return newError(CodeInvariant, map[string]any{"users": users, "ldap_groups": dns},
				"The role %q is still in use. Remove it from %s first.", r.Name, inUse(users, dns))
		}
		t.entry.Detail["role_id"] = roleID
		t.entry.Detail["grants"] = grantStrings(grants)
		return t.q.DeleteRole(t.ctx, roleID)
	})
}

// AddLDAPMapping maps an LDAP group to a role, so members of the group get the role at login and recheck. It needs
// roles.manage and every grant in the role (invariant 3). The DN is stored as given and in normalised form, which is
// what logins match against.
func (m *Manager) AddLDAPMapping(ctx context.Context, a Actor, roleID int64, groupDN string) (int64, error) {
	var id int64
	err := m.do(ctx, a, audit.ActionLDAPMappingAdd, func(t *txn) error {
		if err := t.require(RolesManage); err != nil {
			return err
		}
		r, grants, err := t.role(roleID)
		if err != nil {
			return err
		}
		t.entry.Target = roleTarget(r.Name)
		if err := t.requireHolds(grants, "map a role to an LDAP group"); err != nil {
			return err
		}
		groupDN = strings.TrimSpace(groupDN)
		norm, err := auth.NormalizeDN(groupDN)
		if err != nil || norm == "" || len(groupDN) > maxDNLength || hasControl(groupDN, false) {
			return newError(CodeValidation, map[string]any{"field": "group_dn"},
				"That isn't a valid LDAP distinguished name, such as cn=pihole-staff,ou=groups,dc=example,dc=com.")
		}
		id, err = t.q.CreateLDAPMapping(t.ctx, db.CreateLDAPMappingParams{
			RoleID: roleID, GroupDn: groupDN, GroupDnNorm: norm, CreatedAt: store.Millis(t.now),
		})
		if store.Constraint(err) == store.Unique {
			return newError(CodeConflict, map[string]any{"field": "group_dn"}, "That group is already mapped to %q.", r.Name)
		}
		t.entry.Detail["mapping_id"] = id
		t.entry.Detail["group_dn"] = groupDN
		return err
	})
	return id, err
}

// RemoveLDAPMapping removes a mapping. It needs roles.manage and every grant in the role (invariant 3). An LDAP actor
// who holds the role may lose it, so if it is their last route to roles.manage or users.manage the change needs
// confirm (invariant 4); whether another of their groups also maps to the role isn't known without asking the
// directory, so this errs on the side of asking.
//
// LDAP sessions holding the role are made due for recheck rather than changed directly: sessions don't store group
// DNs, and the user may still get the role through another group.
func (m *Manager) RemoveLDAPMapping(ctx context.Context, a Actor, mappingID int64, confirm bool) error {
	interval := m.RecheckInterval
	if interval <= 0 {
		interval = auth.DefaultRecheckInterval
	}
	return m.do(ctx, a, audit.ActionLDAPMappingRemove, func(t *txn) error {
		if err := t.require(RolesManage); err != nil {
			return err
		}
		mp, err := t.q.GetLDAPMapping(t.ctx, mappingID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return newError(CodeNotFound, map[string]any{"mapping_id": mappingID}, "There is no LDAP mapping with ID %d.", mappingID)
			}
			return err
		}
		r, grants, err := t.role(mp.RoleID)
		if err != nil {
			return err
		}
		t.entry.Target = roleTarget(r.Name)
		if err := t.requireHolds(grants, "unmap a role from an LDAP group"); err != nil {
			return err
		}
		if t.actor.Source == auth.MethodLDAP && containsID(t.actor.RoleIDs, mp.RoleID) {
			after, err := t.setAfter(withoutID(t.actor.RoleIDs, mp.RoleID), nil)
			if err != nil {
				return err
			}
			if err := t.confirmSelfDemotion(after, confirm); err != nil {
				return err
			}
		}
		if err := t.q.DeleteLDAPMapping(t.ctx, mappingID); err != nil {
			return err
		}
		n, err := t.q.MarkRoleSessionsDue(t.ctx, db.MarkRoleSessionsDueParams{
			Due: store.Millis(t.now.Add(-interval)), RoleID: mp.RoleID,
		})
		t.entry.Detail["mapping_id"] = mappingID
		t.entry.Detail["group_dn"] = mp.GroupDn
		if n > 0 {
			t.entry.Detail["sessions_rechecked"] = n
		}
		return err
	})
}

// diffGrants returns the grants in after but not before, and in before but not after. Both inputs are sorted and
// free of duplicates.
func diffGrants(before, after []Grant) (added, removed []Grant) {
	for _, g := range after {
		if !containsGrant(before, g) {
			added = append(added, g)
		}
	}
	for _, g := range before {
		if !containsGrant(after, g) {
			removed = append(removed, g)
		}
	}
	return added, removed
}

func containsGrant(gs []Grant, g Grant) bool { return slices.Contains(gs, g) }

func inUse(users, dns []string) string {
	var parts []string
	if len(users) > 0 {
		parts = append(parts, "users "+joinStrings(users))
	}
	if len(dns) > 0 {
		parts = append(parts, "LDAP groups "+joinStrings(dns))
	}
	return strings.Join(parts, " and ")
}
