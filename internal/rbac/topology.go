// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package rbac

import (
	"context"
	"fmt"
	"slices"

	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// GroupMode is an instance group's mode, as stored in instance_groups.mode.
type GroupMode string

const (
	Independent GroupMode = "independent"
	Mirrored    GroupMode = "mirrored"
)

// Topology is the instances and groups that exist, and which instances belong to which group. Scope checks need it:
// a grant on an independent group covers its current members, and only mirrored groups are targets. It is read from
// the database for every check rather than cached, so membership and mode changes apply at once.
type Topology struct {
	instances []int64                  // sorted
	groups    map[int64]GroupMode      // group ID -> mode
	members   map[int64]map[int64]bool // group ID -> member instance IDs
}

// NewTopology builds a topology from its parts. members maps a group ID to its member instance IDs. It's for tests and
// for callers that already have the data; LoadTopology reads it from the database.
func NewTopology(instances []int64, groups map[int64]GroupMode, members map[int64][]int64) *Topology {
	t := &Topology{
		instances: slices.Sorted(slices.Values(instances)),
		groups:    make(map[int64]GroupMode, len(groups)),
		members:   make(map[int64]map[int64]bool, len(members)),
	}
	for id, mode := range groups {
		t.groups[id] = mode
	}
	for g, ms := range members {
		set := make(map[int64]bool, len(ms))
		for _, m := range ms {
			set[m] = true
		}
		t.members[g] = set
	}
	return t
}

// LoadTopology reads the instances, groups and memberships.
func LoadTopology(ctx context.Context, q *db.Queries) (*Topology, error) {
	ids, err := q.ListInstanceIDs(ctx)
	if err != nil {
		return nil, fmt.Errorf("rbac: list instances: %w", err)
	}
	rows, err := q.ListGroupMembership(ctx)
	if err != nil {
		return nil, fmt.Errorf("rbac: list groups: %w", err)
	}
	groups := make(map[int64]GroupMode)
	members := make(map[int64][]int64)
	for _, r := range rows {
		groups[r.GroupID] = GroupMode(r.Mode)
		if r.InstanceID.Valid {
			members[r.GroupID] = append(members[r.GroupID], r.InstanceID.Int64)
		}
	}
	return NewTopology(ids, groups, members), nil
}

// HasInstance reports whether the instance exists.
func (t *Topology) HasInstance(id int64) bool {
	_, found := slices.BinarySearch(t.instances, id)
	return found
}

// Group returns a group's mode, and whether the group exists.
func (t *Topology) Group(id int64) (GroupMode, bool) {
	m, ok := t.groups[id]
	return m, ok
}

// IsMember reports whether the instance belongs to the group.
func (t *Topology) IsMember(group, instance int64) bool {
	return t.members[group][instance]
}

// Exists reports whether a target exists and can be a target: any instance, or a mirrored group. An independent group
// is a label for scoping grants, not a target.
func (t *Topology) Exists(target Target) bool {
	switch target.Kind {
	case TargetInstance:
		return t.HasInstance(target.ID)
	case TargetGroup:
		mode, ok := t.Group(target.ID)
		return ok && mode == Mirrored
	}
	return false
}

// Targets returns every possible target: all instances, then all mirrored groups, each in ID order.
func (t *Topology) Targets() []Target {
	out := make([]Target, 0, len(t.instances)+len(t.groups))
	for _, id := range t.instances {
		out = append(out, InstanceTarget(id))
	}
	var mirrored []int64
	for id, mode := range t.groups {
		if mode == Mirrored {
			mirrored = append(mirrored, id)
		}
	}
	slices.Sort(mirrored)
	for _, id := range mirrored {
		out = append(out, GroupTarget(id))
	}
	return out
}
