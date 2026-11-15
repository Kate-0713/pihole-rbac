// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package piholegroups finds and updates the app's references to Pi-hole groups, which are by name: client reset
// rules (exact names, or name prefixes), protected groups and schedules' group windows. Renaming or deleting a Pi-hole group would silently
// break them, so a rename or delete lists them first, and a rename updates the exact names where the old name is
// really gone.
package piholegroups

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// Kind is what a reference is.
type Kind string

const (
	KindResetRule Kind = "client_reset_rule" // client_reset_targets
	KindProtected Kind = "protected_group"   // notification_protected_groups
	KindWindow    Kind = "group_window"      // schedules with a group kind
)

// Match modes of a client reset rule, as stored.
const (
	MatchNames    = "names"
	MatchPrefixes = "prefixes"
)

// Scope is the instance or mirrored group a reference is set on. Exactly one of the two is set.
type Scope struct {
	InstanceID int64
	GroupID    int64
}

func (s Scope) String() string {
	if s.GroupID != 0 {
		return fmt.Sprintf("g-%d", s.GroupID)
	}
	return fmt.Sprintf("i-%d", s.InstanceID)
}

// Ref is one reference to Pi-hole groups by name.
type Ref struct {
	Kind      Kind
	ID        int64 // its row
	Scope     Scope
	ScopeName string // the instance's or group's name

	// A client reset rule: its comment prefix, how it matches groups, and the names or prefixes it lists.
	Prefix string
	Match  string
	Groups []string

	// A protected group: the name, matched ignoring case, as its alerts are. A group window: the group's name,
	// matched exactly, as Pi-hole compares names.
	Name string

	// A group window: the schedule's name and kind (group_enabled or group_disabled).
	Schedule     string
	ScheduleKind string
}

// Load reads every reference: every client reset rule, protected group and group window.
func Load(ctx context.Context, q *db.Queries) ([]Ref, error) {
	rules, err := q.ListClientResetRules(ctx)
	if err != nil {
		return nil, err
	}
	protected, err := q.ListProtectedGroups(ctx)
	if err != nil {
		return nil, err
	}
	schedules, err := q.ListSchedules(ctx)
	if err != nil {
		return nil, err
	}
	refs := make([]Ref, 0, len(rules)+len(protected)+len(schedules))
	for _, r := range rules {
		var groups []string
		if err := json.Unmarshal([]byte(r.TargetGroups), &groups); err != nil {
			return nil, fmt.Errorf("client reset rule %d: %w", r.ID, err)
		}
		refs = append(refs, Ref{
			Kind: KindResetRule, ID: r.ID, Scope: Scope{r.InstanceID.Int64, r.GroupID.Int64},
			ScopeName: r.InstanceName + r.GroupName, Prefix: r.CommentPrefix, Match: r.GroupMatch, Groups: groups,
		})
	}
	for _, p := range protected {
		refs = append(refs, Ref{
			Kind: KindProtected, ID: p.ID, Scope: Scope{p.InstanceID.Int64, p.GroupID.Int64},
			ScopeName: p.InstanceName + p.GroupName, Name: p.PiholeGroup,
		})
	}
	for _, w := range schedules {
		if !w.PiholeGroup.Valid {
			continue // a blocking window
		}
		refs = append(refs, Ref{
			Kind: KindWindow, ID: w.ID, Scope: Scope{w.InstanceID.Int64, w.GroupID.Int64},
			ScopeName: w.InstanceName + w.GroupName, Name: w.PiholeGroup.String, Schedule: w.Name, ScheduleKind: w.Kind,
		})
	}
	return refs, nil
}

// refersTo reports whether r names the Pi-hole group called name: a names-mode rule lists it exactly, a
// prefixes-mode rule has a prefix it starts with, a protected group matches it ignoring case, and a group window
// names it exactly.
func (r Ref) refersTo(name string) bool {
	switch {
	case r.Kind == KindWindow:
		return r.Name == name
	case r.Kind == KindProtected:
		return strings.EqualFold(r.Name, name)
	case r.Match == MatchPrefixes:
		return slices.ContainsFunc(r.Groups, func(p string) bool { return strings.HasPrefix(name, p) })
	default:
		return slices.Contains(r.Groups, name)
	}
}

// Matching returns the references in scopes that refer to the Pi-hole group called name, in the order given.
func Matching(refs []Ref, scopes []Scope, name string) []Ref {
	var out []Ref
	for _, r := range refs {
		if slices.Contains(scopes, r.Scope) && r.refersTo(name) {
			out = append(out, r)
		}
	}
	return out
}

// Counts are how many references there are of each kind.
type Counts struct {
	ResetRules   int `json:"client_reset_rules"`
	Protected    int `json:"protected_groups"`
	GroupWindows int `json:"group_windows"`
}

// Count counts refs by kind.
func Count(refs []Ref) Counts {
	var c Counts
	for _, r := range refs {
		switch r.Kind {
		case KindResetRule:
			c.ResetRules++
		case KindProtected:
			c.Protected++
		case KindWindow:
			c.GroupWindows++
		}
	}
	return c
}

// Why a reference a rename touches is left for someone to check rather than updated.
const (
	CheckPrefix     = "prefix_match_changes" // a prefixes-mode rule whose prefixes match only one of the names
	CheckNotEvery   = "not_renamed_everywhere"
	CheckStillInUse = "old_name_still_used" // a protected group still matching a group left on its scope
)

// Change is one reference a rename updates. Before and After are the rule's names, or the protected group's or
// group window's name in a one-element list; Dropped means a protected group was removed because its scope already lists the new name.
type Change struct {
	Ref     Ref
	Before  []string
	After   []string
	Dropped bool
}

// Check is a reference a rename leaves alone for someone to look at.
type Check struct {
	Ref    Ref
	Reason string
}

// Plan is what a rename does to the app's references.
type Plan struct {
	Changes []Change
	Checks  []Check
}

// Renamed says where a rename took effect: renamed(scope) reports whether the old name is gone from that scope (the
// instance renamed it; for a mirrored group, every member did). left(scope) lists the Pi-hole group names on the
// scope once the rename is done (for a group, on every member), for protected groups, which match ignoring case.
type Renamed struct {
	Renamed func(Scope) bool
	Left    func(Scope) []string
}

// PlanRename works out what renaming the Pi-hole group from to to does to refs, which should be the references in
// the scopes the rename was made through. Exact names are updated where the old name is gone. Prefixes are never
// rewritten: a prefixes-mode rule whose prefixes now match only one of the two names is listed to check, as is any
// reference on a scope the rename didn't fully reach.
func PlanRename(refs []Ref, from, to string, where Renamed) Plan {
	var p Plan
	for _, r := range refs {
		if r.Kind == KindResetRule && r.Match == MatchPrefixes {
			if r.refersTo(from) != r.refersTo(to) {
				p.Checks = append(p.Checks, Check{r, CheckPrefix})
			}
			continue
		}
		if !r.refersTo(from) {
			continue
		}
		if !where.Renamed(r.Scope) {
			p.Checks = append(p.Checks, Check{r, CheckNotEvery})
			continue
		}
		if r.Kind == KindResetRule {
			p.Changes = append(p.Changes, Change{Ref: r, Before: r.Groups, After: renameIn(r.Groups, from, to)})
			continue
		}
		if r.Kind == KindWindow {
			p.Changes = append(p.Changes, Change{Ref: r, Before: []string{r.Name}, After: []string{to}})
			continue
		}
		// Another group left on the scope that the entry also matches (Kids renamed while kids remains) keeps it.
		if slices.ContainsFunc(where.Left(r.Scope), func(n string) bool { return n != to && strings.EqualFold(n, r.Name) }) {
			p.Checks = append(p.Checks, Check{r, CheckStillInUse})
			continue
		}
		if r.Name == to {
			continue // a case-only rename to the spelling the entry already has
		}
		dup := slices.ContainsFunc(refs, func(o Ref) bool {
			return o.Kind == KindProtected && o.ID != r.ID && o.Scope == r.Scope && strings.EqualFold(o.Name, to)
		})
		p.Changes = append(p.Changes, Change{Ref: r, Before: []string{r.Name}, After: []string{to}, Dropped: dup})
	}
	return p
}

// renameIn replaces from with to in names, keeping its place, or drops from when to is already there.
func renameIn(names []string, from, to string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		if n == from {
			n = to
		}
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}

// Apply makes a plan's changes through q, normally the transaction that also writes the rename's audit rows.
func Apply(ctx context.Context, q *db.Queries, p Plan) error {
	for _, c := range p.Changes {
		var err error
		switch {
		case c.Ref.Kind == KindResetRule:
			var b []byte
			if b, err = json.Marshal(c.After); err == nil {
				err = q.UpdateClientResetRuleGroups(ctx, db.UpdateClientResetRuleGroupsParams{TargetGroups: string(b), ID: c.Ref.ID})
			}
		case c.Ref.Kind == KindWindow:
			err = q.RenameScheduleGroup(ctx, db.RenameScheduleGroupParams{PiholeGroup: sql.NullString{String: c.After[0], Valid: true}, ID: c.Ref.ID})
		case c.Dropped:
			err = q.DeleteProtectedGroup(ctx, c.Ref.ID)
		default:
			err = q.RenameProtectedGroup(ctx, db.RenameProtectedGroupParams{PiholeGroup: c.After[0], ID: c.Ref.ID})
		}
		if err != nil {
			return fmt.Errorf("updating %s %d: %w", c.Ref.Kind, c.Ref.ID, err)
		}
	}
	return nil
}
