// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package clientreset

import (
	"slices"
	"testing"

	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
)

func TestRuleFor(t *testing.T) {
	rules := []Rule{{Prefix: "TEST-"}, {Prefix: "TEST-LAB-"}, {Prefix: "NINJA-"}}
	for _, tc := range []struct {
		comment string
		want    int
	}{
		{"TEST-laptop", 0},
		{"TEST-LAB-printer", 1}, // the longest prefix wins
		{"NINJA-", 2},
		{"test-laptop", -1}, // case-sensitive, as v1 and the original script
		{" TEST-x", -1},
		{"", -1},
		{"Kitchen tablet", -1},
	} {
		if got := ruleFor(rules, tc.comment); got != tc.want {
			t.Errorf("ruleFor(%q) = %d, want %d", tc.comment, got, tc.want)
		}
	}
	if ruleFor([]Rule{{Prefix: ""}}, "anything") != -1 {
		t.Error("an empty prefix matched")
	}
}

var piholeGroups = []piholeapi.Group{
	{ID: 0, Name: "Default"}, {ID: 4, Name: "AUTOSET-lab"}, {ID: 7, Name: "AUTOSET-staff"},
	{ID: 9, Name: "kids"}, {ID: 12, Name: "AUTOASSIGNED-x"},
}

func TestResolve(t *testing.T) {
	for _, tc := range []struct {
		name    string
		rule    Rule
		want    []int
		code    string
		missing []string
	}{
		{"names", Rule{Match: MatchNames, Groups: []string{"kids", "AUTOSET-lab"}}, []int{4, 9}, "", nil},
		{"names are exact", Rule{Match: MatchNames, Groups: []string{"autoset-lab", "AUTOSET-lab", "Kid"}}, nil, CodeGroupMissing,
			[]string{"autoset-lab", "Kid"}},
		{"prefixes", Rule{Match: MatchPrefixes, Groups: []string{"AUTOSET-", "AUTOASSIGNED-"}}, []int{4, 7, 12}, "", nil},
		{"overlapping prefixes", Rule{Match: MatchPrefixes, Groups: []string{"AUTO", "AUTOSET-"}}, []int{4, 7, 12}, "", nil},
		{"prefixes matching nothing", Rule{Match: MatchPrefixes, Groups: []string{"NOPE-"}}, nil, CodeNoTargetGroups, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, pr := resolve(tc.rule, piholeGroups)
			if tc.code == "" {
				if pr != nil || !slices.Equal(got, tc.want) {
					t.Errorf("got %v %+v, want %v", got, pr, tc.want)
				}
				return
			}
			if pr == nil || pr.Code != tc.code || !slices.Equal(pr.Missing, tc.missing) || got != nil {
				t.Errorf("got %v %+v, want %s %v", got, pr, tc.code, tc.missing)
			}
		})
	}
}

func TestMakePlan(t *testing.T) {
	rules := []Rule{
		{Prefix: "TEST-", Match: MatchNames, Groups: []string{"AUTOSET-lab"}},
		{Prefix: "NINJA-", Match: MatchPrefixes, Groups: []string{"AUTOSET-"}},
		{Prefix: "BROKEN-", Match: MatchNames, Groups: []string{"gone"}},
		{Prefix: "UNUSED-", Match: MatchPrefixes, Groups: []string{"NOPE-"}},
	}
	clients := []piholeapi.ClientEntry{
		{Client: "10.0.0.1", Comment: "TEST-laptop", Groups: []int{0, 9}},
		{Client: "10.0.0.2", Comment: "TEST-done", Groups: []int{4, 4}}, // already right, despite the duplicate
		{Client: "10.0.0.3", Comment: "NINJA-phone", Groups: []int{7, 4}},
		{Client: "10.0.0.4", Comment: "NINJA-tv", Groups: []int{9}},
		{Client: "10.0.0.5", Comment: "BROKEN-x", Groups: []int{0}},
		{Client: "10.0.0.6", Comment: "Kitchen", Groups: []int{9}},
	}
	p := makePlan(rules, clients, piholeGroups)
	if p.unchanged != 2 {
		t.Errorf("unchanged %d, want 2 (10.0.0.2 and 10.0.0.3)", p.unchanged)
	}
	if len(p.changes) != 2 {
		t.Fatalf("changes %+v", p.changes)
	}
	laptop, tv := p.changes[0], p.changes[1]
	if laptop.Client != "10.0.0.1" || laptop.Prefix != "TEST-" || !slices.Equal(laptop.Before, []string{"Default", "kids"}) ||
		!slices.Equal(laptop.After, []string{"AUTOSET-lab"}) || !slices.Equal(laptop.ids, []int{4}) {
		t.Errorf("laptop %+v", laptop)
	}
	if tv.Client != "10.0.0.4" || !slices.Equal(tv.After, []string{"AUTOSET-lab", "AUTOSET-staff"}) || !slices.Equal(tv.ids, []int{4, 7}) {
		t.Errorf("tv %+v", tv)
	}
	if len(p.failures) != 1 || p.failures[0].Client != "10.0.0.5" || p.failures[0].Code != CodeGroupMissing {
		t.Errorf("failures %+v", p.failures)
	}
	// Both broken rules are reported, though no client matches UNUSED- yet.
	if len(p.problems) != 2 || p.problems[0].Prefix != "BROKEN-" || p.problems[1].Code != CodeNoTargetGroups {
		t.Errorf("problems %+v", p.problems)
	}
}

func TestGroupNames(t *testing.T) {
	if got := groupNames([]int{9, 0, 99}, piholeGroups); !slices.Equal(got, []string{"#99", "Default", "kids"}) {
		t.Errorf("groupNames = %v", got)
	}
}

func TestOverall(t *testing.T) {
	ok := InstanceResult{Status: StatusOK}
	reset := InstanceResult{Status: StatusOK, Reset: []Change{{}}}
	failed := InstanceResult{Status: StatusFailed}
	partial := InstanceResult{Status: StatusPartial, Reset: []Change{{}}}
	for _, tc := range []struct {
		in   []InstanceResult
		want string
	}{
		{[]InstanceResult{ok, reset}, StatusOK},
		{[]InstanceResult{reset, failed}, StatusPartial},
		{[]InstanceResult{partial}, StatusPartial},
		{[]InstanceResult{ok, failed}, StatusFailed},
		{[]InstanceResult{{Status: StatusSkipped}}, StatusFailed},
	} {
		if got := overall(tc.in); got != tc.want {
			t.Errorf("overall(%+v) = %s, want %s", tc.in, got, tc.want)
		}
	}
}
