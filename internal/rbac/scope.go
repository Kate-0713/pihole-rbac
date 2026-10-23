// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package rbac

import (
	"errors"
	"fmt"
	"strconv"
)

// ScopeType is where a grant applies. The values are those stored in role_grants.scope_type.
type ScopeType string

const (
	ScopeAll      ScopeType = "all"
	ScopeGroup    ScopeType = "group"
	ScopeInstance ScopeType = "instance"
)

// Scope is a grant's scope: all instances, one group, or one instance. ID is 0 for ScopeAll.
type Scope struct {
	Type ScopeType
	ID   int64
}

// AllScope, GroupScope and InstanceScope build scopes.
func AllScope() Scope              { return Scope{Type: ScopeAll} }
func GroupScope(id int64) Scope    { return Scope{Type: ScopeGroup, ID: id} }
func InstanceScope(id int64) Scope { return Scope{Type: ScopeInstance, ID: id} }

func (s Scope) String() string {
	switch s.Type {
	case ScopeAll:
		return "all"
	case ScopeGroup:
		return fmt.Sprintf("group %d", s.ID)
	case ScopeInstance:
		return fmt.Sprintf("instance %d", s.ID)
	}
	return fmt.Sprintf("%s %d", s.Type, s.ID)
}

// Grant is one permission within one scope.
type Grant struct {
	Permission Permission
	Scope      Scope
}

func (g Grant) String() string { return string(g.Permission) + " on " + g.Scope.String() }

// TargetKind says whether a target is an instance or a group.
type TargetKind int

const (
	TargetInstance TargetKind = iota + 1
	TargetGroup
)

// Target is what a Pi-hole action is aimed at: one instance (i-<id>) or a mirrored group (g-<id>).
type Target struct {
	Kind TargetKind
	ID   int64
}

// InstanceTarget and GroupTarget build targets.
func InstanceTarget(id int64) Target { return Target{Kind: TargetInstance, ID: id} }
func GroupTarget(id int64) Target    { return Target{Kind: TargetGroup, ID: id} }

// String returns the form used in URLs and the API: i-<id> or g-<id>.
func (t Target) String() string {
	switch t.Kind {
	case TargetInstance:
		return "i-" + strconv.FormatInt(t.ID, 10)
	case TargetGroup:
		return "g-" + strconv.FormatInt(t.ID, 10)
	}
	return ""
}

// ErrBadTarget is returned by ParseTarget for anything other than i-<id> or g-<id>.
var ErrBadTarget = errors.New(`a target is "i-<id>" for an instance or "g-<id>" for a group`)

// ParseTarget parses i-<id> or g-<id>. The ID must be a positive decimal number written without a sign or leading
// zeros, so each target has exactly one spelling (which keeps audit entries and permission maps unambiguous).
func ParseTarget(s string) (Target, error) {
	if len(s) < 3 || s[1] != '-' {
		return Target{}, ErrBadTarget
	}
	var kind TargetKind
	switch s[0] {
	case 'i':
		kind = TargetInstance
	case 'g':
		kind = TargetGroup
	default:
		return Target{}, ErrBadTarget
	}
	digits := s[2:]
	if digits[0] < '1' || digits[0] > '9' {
		return Target{}, ErrBadTarget
	}
	id, err := strconv.ParseInt(digits, 10, 64)
	if err != nil {
		return Target{}, ErrBadTarget
	}
	return Target{Kind: kind, ID: id}, nil
}
