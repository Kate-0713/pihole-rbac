// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package rbac

import (
	"cmp"
	"slices"
)

// Set is what a user may do: the union of their roles' grants, read against the current topology. It's built per
// request (see Resolve) and is safe to share once built, since nothing modifies it.
type Set struct {
	scopes map[Permission][]Scope
	topo   *Topology
}

// NewSet builds a set from grants. Grants of permissions the catalogue doesn't know are dropped, so a stale row
// grants nothing. Duplicates are harmless.
func NewSet(grants []Grant, topo *Topology) *Set {
	s := &Set{scopes: make(map[Permission][]Scope), topo: topo}
	for _, g := range grants {
		if !g.Permission.Known() || slices.Contains(s.scopes[g.Permission], g.Scope) {
			continue
		}
		s.scopes[g.Permission] = append(s.scopes[g.Permission], g.Scope)
	}
	return s
}

// Topology returns the topology the set was built against.
func (s *Set) Topology() *Topology { return s.topo }

// CanGlobal reports whether the set holds a global permission. Only scope-all grants count, which is also the only
// scope a global permission can be granted at.
func (s *Set) CanGlobal(p Permission) bool {
	return p.Class() == ClassGlobal && slices.Contains(s.scopes[p], AllScope())
}

// Can reports whether the set allows an instance- or group-class permission on a target. The target has to suit the
// permission and exist: an instance-class permission takes an instance or a mirrored group, a group-class one a
// mirrored group. Anything else, including global permissions (use CanGlobal), is refused.
//
// What covers what:
//   - scope all covers every target, including a single member of a mirrored group;
//   - an instance grant covers that instance;
//   - a grant on an independent group covers each of its current members (the group itself isn't a target);
//   - a grant on a mirrored group covers the group, but not its members one by one, so group-level users can't
//     break the mirror by editing one member.
func (s *Set) Can(p Permission, t Target) bool {
	class := p.Class()
	if class != ClassInstance && class != ClassGroup {
		return false
	}
	if !s.topo.Exists(t) || (class == ClassGroup && t.Kind != TargetGroup) {
		return false
	}
	for _, sc := range s.scopes[p] {
		if s.covers(sc, t) {
			return true
		}
	}
	return false
}

// CanAny reports whether the set allows at least one instance- or group-class permission on a target. It gates reads
// that every user of a target needs, such as its dashboard and the names of its Pi-hole groups.
func (s *Set) CanAny(t Target) bool {
	for p := range s.scopes {
		if s.Can(p, t) {
			return true
		}
	}
	return false
}

func (s *Set) covers(sc Scope, t Target) bool {
	switch sc.Type {
	case ScopeAll:
		return true
	case ScopeInstance:
		return t.Kind == TargetInstance && t.ID == sc.ID
	case ScopeGroup:
		if t.Kind == TargetGroup {
			return t.ID == sc.ID
		}
		mode, ok := s.topo.Group(sc.ID)
		return ok && mode == Independent && s.topo.IsMember(sc.ID, t.ID)
	}
	return false
}

// Holds reports whether the set holds a grant, in the sense of invariant 3 (no privilege escalation): one of its
// grants for the same permission has a scope that contains the grant's scope. Scope all contains every scope; an
// independent group contains itself and its current members; a mirrored group or an instance contains only itself.
func (s *Set) Holds(g Grant) bool {
	if !g.Permission.Known() {
		return false
	}
	for _, sc := range s.scopes[g.Permission] {
		if s.contains(sc, g.Scope) {
			return true
		}
	}
	return false
}

func (s *Set) contains(outer, inner Scope) bool {
	switch outer.Type {
	case ScopeAll:
		return true
	case ScopeInstance:
		return inner == outer
	case ScopeGroup:
		if inner == outer {
			return true
		}
		mode, ok := s.topo.Group(outer.ID)
		return inner.Type == ScopeInstance && ok && mode == Independent && s.topo.IsMember(outer.ID, inner.ID)
	}
	return false
}

// Missing returns the grants the set doesn't hold, sorted, or nil if it holds them all.
func (s *Set) Missing(grants []Grant) []Grant {
	var out []Grant
	for _, g := range grants {
		if !s.Holds(g) && !slices.Contains(out, g) {
			out = append(out, g)
		}
	}
	SortGrants(out)
	return out
}

// Global returns the global permissions the set holds, sorted.
func (s *Set) Global() []Permission {
	var out []Permission
	for p := range s.scopes {
		if s.CanGlobal(p) {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return out
}

// ByTarget returns, for every existing target where the set allows at least one permission, the permissions it
// allows there, sorted. Targets with nothing are left out.
func (s *Set) ByTarget() map[Target][]Permission {
	out := make(map[Target][]Permission)
	for _, t := range s.topo.Targets() {
		var ps []Permission
		for p := range s.scopes {
			if s.Can(p, t) {
				ps = append(ps, p)
			}
		}
		if len(ps) > 0 {
			slices.Sort(ps)
			out[t] = ps
		}
	}
	return out
}

// Grants returns the set's grants, sorted.
func (s *Set) Grants() []Grant {
	var out []Grant
	for p, scs := range s.scopes {
		for _, sc := range scs {
			out = append(out, Grant{Permission: p, Scope: sc})
		}
	}
	SortGrants(out)
	return out
}

// SortGrants sorts grants by permission, then scope type, then ID.
func SortGrants(gs []Grant) {
	slices.SortFunc(gs, func(a, b Grant) int {
		return cmp.Or(
			cmp.Compare(a.Permission, b.Permission),
			cmp.Compare(a.Scope.Type, b.Scope.Type),
			cmp.Compare(a.Scope.ID, b.Scope.ID),
		)
	})
}
