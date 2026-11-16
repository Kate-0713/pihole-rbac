// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package piholegroups

import (
	"reflect"
	"slices"
	"testing"
)

var (
	pihole1 = Scope{InstanceID: 1}
	pihole2 = Scope{InstanceID: 2}
	mirror  = Scope{GroupID: 7}
)

func rule(id int64, s Scope, match string, groups ...string) Ref {
	return Ref{Kind: KindResetRule, ID: id, Scope: s, Prefix: "TEST-", Match: match, Groups: groups}
}

func protected(id int64, s Scope, name string) Ref {
	return Ref{Kind: KindProtected, ID: id, Scope: s, Name: name}
}

func window(id int64, s Scope, name string) Ref {
	return Ref{Kind: KindWindow, ID: id, Scope: s, Name: name, Schedule: "Bedtime", ScheduleKind: "group_enabled"}
}

func override(id int64, s Scope, original, over []string) Ref {
	return Ref{Kind: KindOverride, ID: id, Scope: s, Client: "10.0.0.5", Original: original, Override: over, OverrideID: 100 + id}
}

func ids(refs []Ref) []int64 {
	out := []int64{}
	for _, r := range refs {
		out = append(out, r.ID)
	}
	return out
}

func TestMatching(t *testing.T) {
	refs := []Ref{
		rule(1, pihole1, MatchNames, "kids", "Default"),
		rule(2, pihole1, MatchNames, "Kids"),           // names match exactly, as a run does
		rule(3, pihole1, MatchPrefixes, "ki", "guest"), // a prefix the name starts with
		rule(4, pihole1, MatchPrefixes, "kids-"),       // longer than the name: no match
		protected(5, pihole1, "KIDS"),                  // protected groups ignore case, as alerts do
		protected(6, pihole1, "kidsroom"),              // not a prefix match
		rule(7, pihole2, MatchNames, "kids"),           // another scope
		protected(8, mirror, "kids"),
		window(9, pihole1, "kids"),  // group windows match exactly, as Pi-hole compares names
		window(10, pihole1, "Kids"), // so another spelling doesn't
		window(11, mirror, "kids"),
		override(12, pihole1, []string{"Default", "kids"}, []string{"Default"}), // names it among the originals
		override(13, pihole1, []string{"Default"}, []string{"Default", "kids"}), // or among the override's groups
		override(14, pihole1, []string{"Default"}, []string{"Default", "Kids"}), // exactly, as Pi-hole compares names
		override(15, pihole2, []string{"kids"}, nil),
	}
	tests := []struct {
		name   string
		scopes []Scope
		group  string
		want   []int64
	}{
		{"one instance", []Scope{pihole1}, "kids", []int64{1, 3, 5, 9, 12, 13}},
		{"an instance and its mirrored group", []Scope{pihole1, mirror}, "kids", []int64{1, 3, 5, 8, 9, 11, 12, 13}},
		{"another name", []Scope{pihole1, pihole2}, "Kids", []int64{2, 5, 10, 14}},
		{"nothing", []Scope{pihole2}, "guests", []int64{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ids(Matching(refs, tt.scopes, tt.group)); !slices.Equal(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
	if c := Count(Matching(refs, []Scope{pihole1, mirror}, "kids")); c != (Counts{ResetRules: 2, Protected: 2, GroupWindows: 2, ClientOverrides: 2}) {
		t.Errorf("counts %+v", c)
	}
}

func TestPlanRename(t *testing.T) {
	everywhere := func(Scope) bool { return true }
	type change struct {
		id      int64
		after   []string
		dropped bool
	}
	type check struct {
		id     int64
		reason string
	}
	tests := []struct {
		name     string
		refs     []Ref
		from, to string
		renamed  func(Scope) bool
		left     map[Scope][]string
		changes  []change
		checks   []check
	}{
		{
			name: "exact names are updated in place",
			refs: []Ref{rule(1, pihole1, MatchNames, "Default", "kids", "lab"), protected(2, pihole1, "kids")},
			from: "kids", to: "children", renamed: everywhere,
			left:    map[Scope][]string{pihole1: {"Default", "children", "lab"}},
			changes: []change{{1, []string{"Default", "children", "lab"}, false}, {2, []string{"children"}, false}},
		},
		{
			name: "a group window follows the new name",
			refs: []Ref{window(1, pihole1, "kids"), window(2, pihole1, "Kids")},
			from: "kids", to: "children", renamed: everywhere,
			left:    map[Scope][]string{pihole1: {"Kids", "children"}},
			changes: []change{{1, []string{"children"}, false}},
		},
		{
			name: "a rule that already names the new group doesn't name it twice",
			refs: []Ref{rule(1, pihole1, MatchNames, "kids", "children")},
			from: "kids", to: "children", renamed: everywhere,
			changes: []change{{1, []string{"children"}, false}},
		},
		{
			name: "a protected group is dropped when its scope already lists the new name",
			refs: []Ref{protected(1, pihole1, "kids"), protected(2, pihole1, "Children")},
			from: "kids", to: "children", renamed: everywhere,
			changes: []change{{1, []string{"children"}, true}},
		},
		{
			name: "a protected group still matching a group left on the scope is kept",
			refs: []Ref{protected(1, pihole1, "kids")},
			from: "Kids", to: "children", renamed: everywhere,
			left:   map[Scope][]string{pihole1: {"children", "kids"}},
			checks: []check{{1, CheckStillInUse}},
		},
		{
			name: "a case-only rename follows the new spelling",
			refs: []Ref{protected(1, pihole1, "kids"), rule(2, pihole1, MatchNames, "kids")},
			from: "kids", to: "Kids", renamed: everywhere,
			left:    map[Scope][]string{pihole1: {"Kids"}},
			changes: []change{{1, []string{"Kids"}, false}, {2, []string{"Kids"}, false}},
		},
		{
			name: "a protected group already spelt as the new name is left alone",
			refs: []Ref{protected(1, pihole1, "Kids")},
			from: "kids", to: "Kids", renamed: everywhere,
			left: map[Scope][]string{pihole1: {"Kids"}},
		},
		{
			name: "prefixes are never rewritten; a change in what they match is listed",
			refs: []Ref{
				rule(1, pihole1, MatchPrefixes, "kid"),      // matched the old name only
				rule(2, pihole1, MatchPrefixes, "AUTOSET-"), // matches neither
				rule(3, pihole1, MatchPrefixes, "child"),    // matches the new name only
				rule(4, pihole1, MatchPrefixes, "k", "ch"),  // matches both: nothing to say
			},
			from: "kids", to: "children", renamed: everywhere,
			checks: []check{{1, CheckPrefix}, {3, CheckPrefix}},
		},
		{
			name: "an old name matched by a prefix only is listed",
			refs: []Ref{rule(1, pihole1, MatchPrefixes, "AUTOSET-")},
			from: "AUTOSET-lab", to: "lab", renamed: everywhere,
			checks: []check{{1, CheckPrefix}},
		},
		{
			name: "references on a scope the rename didn't fully reach are left and listed",
			refs: []Ref{
				rule(1, mirror, MatchNames, "kids"), protected(2, mirror, "kids"),
				rule(3, pihole1, MatchNames, "kids"), rule(4, pihole2, MatchNames, "kids"),
				window(5, mirror, "kids"), window(6, pihole1, "kids"),
			},
			from: "kids", to: "children",
			renamed: func(s Scope) bool { return s == pihole1 },
			changes: []change{{3, []string{"children"}, false}, {6, []string{"children"}, false}},
			checks:  []check{{1, CheckNotEvery}, {2, CheckNotEvery}, {4, CheckNotEvery}, {5, CheckNotEvery}},
		},
		{
			name: "a temporary change's original and override groups both follow the new name",
			refs: []Ref{
				override(1, pihole1, []string{"Default", "kids"}, []string{"Default", "open"}),
				override(2, pihole1, []string{"Default"}, []string{"kids", "open"}),
				override(3, pihole1, []string{"Default"}, []string{"Default"}), // doesn't name it
			},
			from: "kids", to: "children", renamed: everywhere,
			changes: []change{{1, []string{"Default", "open"}, false}, {2, []string{"children", "open"}, false}},
		},
		{
			name: "a temporary change on a member the rename didn't reach is listed",
			refs: []Ref{override(1, pihole1, []string{"kids"}, nil), override(2, pihole2, []string{"kids"}, nil)},
			from: "kids", to: "children",
			renamed: func(s Scope) bool { return s == pihole2 },
			changes: []change{{2, []string{}, false}},
			checks:  []check{{1, CheckNotEvery}},
		},
		{
			name: "references to other groups are untouched",
			refs: []Ref{rule(1, pihole1, MatchNames, "guests"), protected(2, pihole1, "guests")},
			from: "kids", to: "children", renamed: everywhere,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := PlanRename(tt.refs, tt.from, tt.to, Renamed{Renamed: tt.renamed, Left: func(s Scope) []string { return tt.left[s] }})
			var changes []change
			for _, c := range p.Changes {
				changes = append(changes, change{c.Ref.ID, c.After, c.Dropped})
			}
			var checks []check
			for _, c := range p.Checks {
				checks = append(checks, check{c.Ref.ID, c.Reason})
			}
			if !reflect.DeepEqual(changes, tt.changes) {
				t.Errorf("changes %+v, want %+v", changes, tt.changes)
			}
			if !reflect.DeepEqual(checks, tt.checks) {
				t.Errorf("checks %+v, want %+v", checks, tt.checks)
			}
		})
	}
}
