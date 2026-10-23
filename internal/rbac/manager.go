// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package rbac

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/auth"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// Actor is the user making a change, as their session describes them.
type Actor struct {
	UserID   int64
	Username string
	Source   auth.Method
	RoleIDs  []int64 // the acting session's roles; permissions are resolved from these inside the transaction
	PublicID string  // the acting session's public ID, kept when the actor resets their own password
	IP       string
}

// Manager makes every change to roles, grants, user roles, LDAP mappings and users. Each change runs in one
// transaction that checks the actor's permissions and the invariants, applies the change, keeps sessions in step and
// writes the audit row, so they all commit or roll back together. The AUDIT log line is written after the commit.
//
// Refusals are *Error values whose Code is the API error code. A refusal for a missing permission, or for granting
// more than the actor holds, is itself audited as permission_denied.
type Manager struct {
	Store *store.Store
	Audit *audit.Logger
	// RecheckInterval is the LDAP recheck interval, used to make sessions due for recheck when a mapping is removed.
	// Zero means auth.DefaultRecheckInterval.
	RecheckInterval time.Duration
	// Now returns the current time; nil means time.Now.
	Now func() time.Time
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// errNoChange ends a change that would leave everything as it is: nothing is written and nothing is audited.
var errNoChange = errors.New("no change")

// txn is one change in progress.
type txn struct {
	ctx   context.Context
	q     *db.Queries
	actor Actor
	set   *Set // the actor's permissions before the change
	topo  *Topology
	now   time.Time
	entry *audit.Entry
}

// do runs fn as one audited change.
func (m *Manager) do(ctx context.Context, a Actor, action string, fn func(t *txn) error) error {
	now := m.now()
	entry := audit.Entry{At: now, UserID: a.UserID, Username: a.Username, Action: action, IP: a.IP, Detail: map[string]any{}}
	err := m.Store.WithTx(ctx, func(q *db.Queries) error {
		set, err := Resolve(ctx, q, a.RoleIDs)
		if err != nil {
			return err
		}
		t := &txn{ctx: ctx, q: q, actor: a, set: set, topo: set.Topology(), now: now, entry: &entry}
		if err := fn(t); err != nil {
			return err
		}
		_, err = audit.Insert(ctx, q, entry)
		return err
	})
	switch {
	case errors.Is(err, errNoChange):
		return nil
	case IsCode(err, CodeForbidden):
		e, _ := AsError(err)
		detail := map[string]any{"attempted": action}
		for k, v := range e.Details {
			detail[k] = v
		}
		denied := audit.Entry{
			At: now, UserID: a.UserID, Username: a.Username, Action: audit.ActionPermissionDenied,
			Target: entry.Target, Err: err, Detail: detail, IP: a.IP,
		}
		if rerr := m.Audit.Record(ctx, m.Store, denied); rerr != nil {
			return fmt.Errorf("audit refusal: %w", rerr)
		}
		return err
	case err != nil:
		return err
	}
	m.Audit.Log(entry)
	return nil
}

// require refuses unless the actor holds a global permission.
func (t *txn) require(p Permission) error {
	if t.set.CanGlobal(p) {
		return nil
	}
	return Forbidden(p)
}

// requireHolds refuses unless the actor holds every grant (invariant 3). what says what the grants are, for the
// message.
func (t *txn) requireHolds(grants []Grant, what string) error {
	missing := t.set.Missing(grants)
	if len(missing) == 0 {
		return nil
	}
	return newError(CodeForbidden, map[string]any{"missing": grantStrings(missing)},
		"You can only %s with permissions you hold yourself. You don't hold: %s.", what, joinGrants(missing))
}

// role loads a role and its grants.
func (t *txn) role(id int64) (db.Role, []Grant, error) {
	r, err := t.q.GetRole(t.ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return db.Role{}, nil, newError(CodeNotFound, map[string]any{"role_id": id}, "There is no role with ID %d.", id)
	}
	if err != nil {
		return db.Role{}, nil, err
	}
	grants, err := roleGrants(t.ctx, t.q, []int64{id})
	return r, grants, err
}

// user loads a user.
func (t *txn) user(id int64) (db.User, error) {
	u, err := t.q.GetUser(t.ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return db.User{}, newError(CodeNotFound, map[string]any{"user_id": id}, "There is no user with ID %d.", id)
	}
	return u, err
}

// userRoleIDs returns a user's roles: from user_roles for a local user, and from their current sessions for an LDAP
// user, whose roles come from the directory at login and recheck.
func (t *txn) userRoleIDs(u db.User) ([]int64, error) {
	if auth.Method(u.Source) == auth.MethodLocal {
		return t.q.ListUserRoleIDs(t.ctx, u.ID)
	}
	return t.q.ListSessionRoleIDsForUser(t.ctx, u.ID)
}

// requireNotAbove refuses unless the actor holds every grant of every role the user has (invariant 7), so nobody can
// take over, lock out or remove an account more privileged than their own.
func (t *txn) requireNotAbove(u db.User) error {
	roles, err := t.userRoleIDs(u)
	if err != nil {
		return err
	}
	grants, err := roleGrants(t.ctx, t.q, roles)
	if err != nil {
		return err
	}
	missing := t.set.Missing(grants)
	if len(missing) == 0 {
		return nil
	}
	return newError(CodeForbidden, map[string]any{"missing": grantStrings(missing)},
		"You can't manage %s: they hold permissions you don't (%s).", u.Username, joinGrants(missing))
}

// checkAdmins enforces invariant 2 after a change has been applied: at least one enabled local user holds the builtin
// admin role. The change is in the same transaction, so refusing rolls it back.
func (t *txn) checkAdmins() error {
	n, err := t.q.CountEnabledLocalAdmins(t.ctx)
	if err != nil {
		return err
	}
	if n == 0 {
		return newError(CodeInvariant, nil,
			"At least one enabled local user must hold the admin role, so there is always a way in if LDAP fails.")
	}
	return nil
}

// setAfter returns the permissions the given roles would have, with the grants in override replacing those stored.
func (t *txn) setAfter(roleIDs []int64, override map[int64][]Grant) (*Set, error) {
	var stored []int64
	var grants []Grant
	for _, id := range roleIDs {
		if gs, ok := override[id]; ok {
			grants = append(grants, gs...)
		} else {
			stored = append(stored, id)
		}
	}
	more, err := roleGrants(t.ctx, t.q, stored)
	if err != nil {
		return nil, err
	}
	return NewSet(append(grants, more...), t.topo), nil
}

// confirmSelfDemotion enforces invariant 4: a change that would take away the actor's own last route to roles.manage
// or users.manage needs confirm.
func (t *txn) confirmSelfDemotion(after *Set, confirm bool) error {
	var lost []Permission
	for _, p := range []Permission{RolesManage, UsersManage} {
		if t.set.CanGlobal(p) && !after.CanGlobal(p) {
			lost = append(lost, p)
		}
	}
	if len(lost) == 0 || confirm {
		return nil
	}
	return newError(CodeConfirmation, map[string]any{"would_lose": lost},
		"This would remove your own %s permission. Confirm to go ahead.", joinPermissions(lost))
}

// normalizeGrants validates grants (invariant 6), drops duplicates and sorts them.
func (t *txn) normalizeGrants(grants []Grant) ([]Grant, error) {
	out := make([]Grant, 0, len(grants))
	for _, g := range grants {
		if err := ValidateGrant(t.topo, g); err != nil {
			return nil, err
		}
		if !slices.Contains(out, g) {
			out = append(out, g)
		}
	}
	SortGrants(out)
	return out, nil
}

func (t *txn) insertGrants(roleID int64, grants []Grant) error {
	for _, g := range grants {
		p := db.InsertGrantParams{RoleID: roleID, Permission: string(g.Permission), ScopeType: string(g.Scope.Type)}
		switch g.Scope.Type {
		case ScopeInstance:
			p.InstanceID = sql.NullInt64{Int64: g.Scope.ID, Valid: true}
		case ScopeGroup:
			p.GroupID = sql.NullInt64{Int64: g.Scope.ID, Valid: true}
		}
		if err := t.q.InsertGrant(t.ctx, p); err != nil {
			return fmt.Errorf("insert grant %s: %w", g, err)
		}
	}
	return nil
}

// endSessions ends a user's sessions, except the one with keepPublicID if that isn't empty, and records how many.
func (t *txn) endSessions(userID int64, keepPublicID string) error {
	var n int64
	var err error
	if keepPublicID == "" {
		n, err = t.q.DeleteUserSessions(t.ctx, userID)
	} else {
		n, err = t.q.DeleteUserSessionsExcept(t.ctx, db.DeleteUserSessionsExceptParams{UserID: userID, PublicID: keepPublicID})
	}
	if err == nil && n > 0 {
		t.entry.Detail["sessions_ended"] = n
	}
	return err
}

// CheckGroupModeChange enforces the second half of invariant 6 for a change of an instance group's mode: a mirrored
// group can't become independent while any role holds a group-scope permission on it. Call it in the transaction
// that changes the mode.
func CheckGroupModeChange(ctx context.Context, q *db.Queries, groupID int64, newMode GroupMode) error {
	if newMode != Independent {
		return nil
	}
	var perms []string
	for _, p := range catalogue {
		if p.Class == ClassGroup {
			perms = append(perms, string(p.Name))
		}
	}
	roles, err := q.ListRolesWithGrantsOnGroup(ctx, db.ListRolesWithGrantsOnGroupParams{
		GroupID: sql.NullInt64{Int64: groupID, Valid: true}, Permissions: perms,
	})
	if err != nil {
		return err
	}
	if len(roles) > 0 {
		return newError(CodeInvariant, map[string]any{"roles": roles},
			"The group can't become independent while roles hold mirrored-group permissions on it. Remove them first from: %s.",
			joinStrings(roles))
	}
	return nil
}
