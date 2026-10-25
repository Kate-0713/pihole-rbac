// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package instances

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// Group is an instance group. An independent group is a label for organising instances and scoping grants; a
// mirrored group treats its members as one Pi-hole, with Primary as the reference for reads and drift checks.
type Group struct {
	ID        int64
	Name      string
	Mode      rbac.GroupMode
	Primary   int64   // 0 for an independent group
	Members   []int64 // instance IDs, sorted
	CreatedAt time.Time
}

// GroupInput is a group's editable settings. A change replaces all of them.
type GroupInput struct {
	Name    string
	Mode    rbac.GroupMode
	Primary int64 // required for a mirrored group, which must list it among Members; 0 for an independent group
	Members []int64
}

const maxGroupMembers = 100

func groupTarget(name string) string { return "group:" + name }

func groupNotFound(id int64) *rbac.Error {
	return &rbac.Error{Code: rbac.CodeNotFound, Message: fmt.Sprintf("There is no instance group with ID %d.", id),
		Details: map[string]any{"group_id": id}}
}

// normalize checks the settings that don't need the database and returns them trimmed, with the members sorted.
func (in GroupInput) normalize() (GroupInput, error) {
	in.Name = strings.TrimSpace(in.Name)
	if n := utf8.RuneCountInString(in.Name); n == 0 || n > maxName || hasControl(in.Name) {
		return in, validation("name", "A group name is 1-%d characters, with no control characters.", maxName)
	}
	if len(in.Members) > maxGroupMembers {
		return in, validation("members", "A group has at most %d members.", maxGroupMembers)
	}
	in.Members = slices.Sorted(slices.Values(in.Members))
	if len(slices.Compact(slices.Clone(in.Members))) != len(in.Members) {
		return in, validation("members", "An instance is listed more than once.")
	}
	switch in.Mode {
	case rbac.Mirrored:
		if in.Primary == 0 {
			return in, validation("primary_instance_id", "A mirrored group needs a primary instance.")
		}
		if !slices.Contains(in.Members, in.Primary) {
			return in, validation("primary_instance_id", "The primary instance must be one of the group's members.")
		}
	case rbac.Independent:
		if in.Primary != 0 {
			return in, validation("primary_instance_id", "Only a mirrored group has a primary instance.")
		}
	default:
		return in, validation("mode", `The mode must be "independent" or "mirrored".`)
	}
	return in, nil
}

func groupFromRow(r db.InstanceGroup, members []int64) Group {
	return Group{
		ID: r.ID, Name: r.Name, Mode: rbac.GroupMode(r.Mode), Primary: r.PrimaryInstanceID.Int64,
		Members: members, CreatedAt: store.FromMillis(r.CreatedAt),
	}
}

// ListGroups returns every instance group, by name.
func (s *Service) ListGroups(ctx context.Context) ([]Group, error) {
	q := s.Store.Read()
	rows, err := q.ListInstanceGroups(ctx)
	if err != nil {
		return nil, fmt.Errorf("instances: list groups: %w", err)
	}
	membership, err := q.ListGroupMembership(ctx)
	if err != nil {
		return nil, fmt.Errorf("instances: list groups: %w", err)
	}
	members := map[int64][]int64{}
	for _, m := range membership {
		if m.InstanceID.Valid {
			members[m.GroupID] = append(members[m.GroupID], m.InstanceID.Int64)
		}
	}
	out := make([]Group, len(rows))
	for i, r := range rows {
		out[i] = groupFromRow(r, members[r.ID])
	}
	return out, nil
}

// GetGroup returns one instance group.
func (s *Service) GetGroup(ctx context.Context, id int64) (Group, error) {
	return getGroup(ctx, s.Store.Read(), id)
}

func getGroup(ctx context.Context, q *db.Queries, id int64) (Group, error) {
	r, err := q.GetInstanceGroup(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return Group{}, groupNotFound(id)
	}
	if err != nil {
		return Group{}, err
	}
	members, err := q.ListInstanceGroupMembers(ctx, id)
	if err != nil {
		return Group{}, err
	}
	return groupFromRow(r, members), nil
}

// loadGroup reads a group and makes it the audit target.
func (t *txn) loadGroup(id int64) (Group, error) {
	g, err := getGroup(t.ctx, t.q, id)
	if err != nil {
		return Group{}, err
	}
	t.entry.Target = groupTarget(g.Name)
	return g, nil
}

// checkGroup checks a group's settings against the database: the name is free (ignoring case), every member exists,
// and, for a mirrored group, no member is already in another mirrored group. It returns every instance's name by ID,
// for the audit detail. The UNIQUE constraint and the one-mirrored-group index back this up.
func (t *txn) checkGroup(in GroupInput, self int64) (map[int64]string, error) {
	groups, err := t.q.ListInstanceGroups(t.ctx)
	if err != nil {
		return nil, err
	}
	groupNames := map[int64]string{}
	for _, g := range groups {
		groupNames[g.ID] = g.Name
		if g.ID != self && strings.EqualFold(g.Name, in.Name) {
			return nil, &rbac.Error{Code: rbac.CodeConflict, Message: fmt.Sprintf("There is already a group called %q.", g.Name),
				Details: map[string]any{"field": "name"}}
		}
	}
	insts, err := t.q.ListInstances(t.ctx)
	if err != nil {
		return nil, err
	}
	names := make(map[int64]string, len(insts))
	for _, inst := range insts {
		names[inst.ID] = inst.Name
	}
	for _, id := range in.Members {
		if _, ok := names[id]; !ok {
			return nil, validation("members", "There is no instance with ID %d.", id)
		}
	}
	if in.Mode != rbac.Mirrored {
		return names, nil
	}
	membership, err := t.q.ListGroupMembership(t.ctx)
	if err != nil {
		return nil, err
	}
	for _, m := range membership {
		if m.GroupID == self || m.Mode != string(rbac.Mirrored) || !m.InstanceID.Valid {
			continue
		}
		if id := m.InstanceID.Int64; slices.Contains(in.Members, id) {
			return nil, &rbac.Error{
				Code: rbac.CodeConflict,
				Message: fmt.Sprintf("%s is already in the mirrored group %q. An instance can be in only one mirrored group.",
					names[id], groupNames[m.GroupID]),
				Details: map[string]any{"field": "members", "instance": names[id], "group": groupNames[m.GroupID]},
			}
		}
	}
	return names, nil
}

func groupBackstop(err error) error {
	switch store.Constraint(err) {
	case store.Unique:
		return &rbac.Error{Code: rbac.CodeConflict,
			Message: "Another group already has that name, or an instance is already in another mirrored group."}
	case store.ForeignKey:
		return &rbac.Error{Code: rbac.CodeConflict, Message: "A member instance no longer exists."}
	}
	return err
}

func memberNames(ids []int64, names map[int64]string) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = names[id]
	}
	slices.Sort(out)
	return out
}

func nullID(id int64) sql.NullInt64 { return sql.NullInt64{Int64: id, Valid: id != 0} }

// CreateGroup adds an instance group with its members.
func (s *Service) CreateGroup(ctx context.Context, a rbac.Actor, in GroupInput) (Group, error) {
	in, normErr := in.normalize()
	var g Group
	err := s.do(ctx, a, audit.ActionGroupCreate, func(t *txn) error {
		t.entry.Target = groupTarget(strings.TrimSpace(in.Name))
		if err := t.require(); err != nil {
			return err
		}
		if normErr != nil {
			return normErr
		}
		names, err := t.checkGroup(in, 0)
		if err != nil {
			return err
		}
		id, err := t.q.CreateInstanceGroup(t.ctx, db.CreateInstanceGroupParams{
			Name: in.Name, Mode: string(in.Mode), PrimaryInstanceID: nullID(in.Primary), CreatedAt: store.Millis(t.now),
		})
		if err != nil {
			return groupBackstop(err)
		}
		for _, m := range in.Members {
			if err := t.q.AddInstanceGroupMember(t.ctx, db.AddInstanceGroupMemberParams{GroupID: id, InstanceID: m}); err != nil {
				return groupBackstop(err)
			}
		}
		g = Group{ID: id, Name: in.Name, Mode: in.Mode, Primary: in.Primary, Members: in.Members,
			CreatedAt: store.FromMillis(store.Millis(t.now))}
		t.entry.Detail["group_id"] = id
		t.entry.Detail["mode"] = string(in.Mode)
		t.entry.Detail["members"] = memberNames(in.Members, names)
		if in.Primary != 0 {
			t.entry.Detail["primary"] = names[in.Primary]
		}
		return nil
	})
	if err != nil {
		return Group{}, err
	}
	return g, nil
}

// UpdateGroup replaces a group's name, mode, members and primary. A mirrored group can't become independent while a
// role holds a mirrored-group permission on it (invariant 6). A change that changes nothing isn't written or audited.
func (s *Service) UpdateGroup(ctx context.Context, a rbac.Actor, id int64, in GroupInput) (Group, error) {
	in, normErr := in.normalize()
	var g Group
	err := s.do(ctx, a, audit.ActionGroupUpdate, func(t *txn) error {
		before, err := t.loadGroup(id)
		if err != nil {
			return err
		}
		if err := t.require(); err != nil {
			return err
		}
		if normErr != nil {
			return normErr
		}
		g = before
		names, err := t.checkGroup(in, id)
		if err != nil {
			return err
		}
		if before.Mode != in.Mode {
			if err := rbac.CheckGroupModeChange(t.ctx, t.q, id, in.Mode); err != nil {
				return err
			}
		}
		var added, removed []int64
		for _, m := range in.Members {
			if !slices.Contains(before.Members, m) {
				added = append(added, m)
			}
		}
		for _, m := range before.Members {
			if !slices.Contains(in.Members, m) {
				removed = append(removed, m)
			}
		}
		var changes []string
		if before.Name != in.Name {
			changes = append(changes, "name")
			t.entry.Detail["name_before"] = before.Name
		}
		if before.Mode != in.Mode {
			changes = append(changes, "mode")
			t.entry.Detail["mode"] = string(in.Mode)
		}
		if before.Primary != in.Primary {
			changes = append(changes, "primary")
			if in.Primary != 0 {
				t.entry.Detail["primary"] = names[in.Primary]
			}
		}
		if len(added)+len(removed) > 0 {
			changes = append(changes, "members")
		}
		if len(changes) == 0 {
			return errNoChange
		}
		// Members leave first and join last, so a join copies the group's new mode.
		for _, m := range removed {
			if err := t.q.RemoveInstanceGroupMember(t.ctx, db.RemoveInstanceGroupMemberParams{GroupID: id, InstanceID: m}); err != nil {
				return err
			}
		}
		if err := t.q.UpdateInstanceGroup(t.ctx, db.UpdateInstanceGroupParams{
			Name: in.Name, Mode: string(in.Mode), PrimaryInstanceID: nullID(in.Primary), ID: id,
		}); err != nil {
			return groupBackstop(err)
		}
		for _, m := range added {
			if err := t.q.AddInstanceGroupMember(t.ctx, db.AddInstanceGroupMemberParams{GroupID: id, InstanceID: m}); err != nil {
				return groupBackstop(err)
			}
		}
		t.entry.Target = groupTarget(in.Name)
		t.entry.Detail["group_id"] = id
		t.entry.Detail["changed"] = changes
		if len(added) > 0 {
			t.entry.Detail["members_added"] = memberNames(added, names)
		}
		if len(removed) > 0 {
			t.entry.Detail["members_removed"] = memberNames(removed, names)
		}
		g = Group{ID: id, Name: in.Name, Mode: in.Mode, Primary: in.Primary, Members: in.Members, CreatedAt: before.CreatedAt}
		return nil
	})
	if err != nil {
		return Group{}, err
	}
	return g, nil
}

// DeleteGroup removes a group and its memberships. It is refused while a role grant or a client-reset target refers
// to the group, with a message that lists them.
func (s *Service) DeleteGroup(ctx context.Context, a rbac.Actor, id int64) error {
	return s.do(ctx, a, audit.ActionGroupDelete, func(t *txn) error {
		g, err := t.loadGroup(id)
		if err != nil {
			return err
		}
		if err := t.require(); err != nil {
			return err
		}
		ref := sql.NullInt64{Int64: id, Valid: true}
		roles, err := t.q.ListRolesWithAnyGrantOnGroup(t.ctx, ref)
		if err != nil {
			return err
		}
		resets, err := t.q.CountClientResetTargetsForGroup(t.ctx, ref)
		if err != nil {
			return err
		}
		var uses []string
		if len(roles) > 0 {
			uses = append(uses, plural(len(roles), "role")+" "+quoteJoin(roles))
		}
		if resets > 0 {
			uses = append(uses, plural(int(resets), "client reset target"))
		}
		if len(uses) > 0 {
			return &rbac.Error{
				Code:    rbac.CodeConflict,
				Message: fmt.Sprintf("%s is still used by %s. Remove it from them first.", g.Name, strings.Join(uses, "; ")),
				Details: map[string]any{"roles": roles, "client_reset_targets": resets},
			}
		}
		if err := t.q.DeleteInstanceGroup(t.ctx, id); err != nil {
			if store.Constraint(err) == store.ForeignKey {
				return &rbac.Error{Code: rbac.CodeConflict, Message: fmt.Sprintf("%s is still in use.", g.Name)}
			}
			return err
		}
		t.entry.Detail["group_id"] = id
		return nil
	})
}

// MirroredGroupOf returns the mirrored group an instance belongs to, if any.
func (s *Service) MirroredGroupOf(ctx context.Context, instanceID int64) (id int64, name string, ok bool, err error) {
	r, err := s.Store.Read().GetMirroredGroupOfInstance(ctx, instanceID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", false, nil
	}
	if err != nil {
		return 0, "", false, err
	}
	return r.ID, r.Name, true, nil
}
