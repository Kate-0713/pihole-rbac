// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package clientreset puts Pi-hole clients back in their usual groups. A rule, on an instance or a mirrored group,
// says that clients whose comment starts with a prefix (such as "TEST-") belong in exactly some Pi-hole groups. A run
// reads each instance's clients and groups, works out which matching clients aren't in exactly those groups, and
// changes them. It runs on demand and on a daily schedule.
//
// A rule names its groups either by exact name or by name prefix (every group whose name starts with one of them).
// Either way they are looked up on each instance when the rule runs, since Pi-hole's group IDs differ between
// instances. A rule whose groups can't be found on an instance changes nothing there: putting clients in fewer groups
// than the rule names, or in none, would be worse than leaving them.
package clientreset

import (
	"slices"
	"strconv"
	"strings"

	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
)

// Match says how a rule's groups are matched against an instance's Pi-hole groups.
type Match string

const (
	MatchNames    Match = "names"    // each is a group's exact name, which every instance must have
	MatchPrefixes Match = "prefixes" // every group whose name starts with one of them; at least one must
)

// Rule is one client reset rule as it runs.
type Rule struct {
	Prefix string // a client's comment must start with it (case-sensitive)
	Match  Match
	Groups []string
}

// Problem codes, for a rule that can't run on an instance.
const (
	CodeGroupMissing   = "pihole_group_missing" // a group the rule names isn't on the instance
	CodeNoTargetGroups = "no_target_groups"     // no group on the instance matches the rule's prefixes
)

// RuleProblem is why a rule changed nothing on an instance. The clients it matches are listed as failed with Code.
type RuleProblem struct {
	Prefix  string   `json:"prefix"`
	Code    string   `json:"code"`
	Missing []string `json:"missing,omitempty"` // the names not found, for pihole_group_missing
}

// Change is a client a run puts in its rule's groups (or would, in a preview). Groups are by name.
type Change struct {
	Client  string   `json:"client"`
	Comment string   `json:"comment"`
	Prefix  string   `json:"prefix"` // the rule's
	Before  []string `json:"groups_before"`
	After   []string `json:"groups_after"`

	ids []int // the groups to set, by this instance's IDs
}

// Failure is a client a run couldn't change.
type Failure struct {
	Client  string `json:"client"`
	Comment string `json:"comment"`
	Prefix  string `json:"prefix"`
	Code    string `json:"code"`
}

// plan is what a run would do on one instance.
type plan struct {
	changes   []Change
	failures  []Failure // clients whose rule has a problem
	problems  []RuleProblem
	unchanged int // clients already in exactly their rule's groups
}

// ruleFor returns the index of the rule whose prefix a comment starts with, the longest when several do, or -1. A
// client with no comment matches nothing, since a rule's prefix is never empty.
func ruleFor(rules []Rule, comment string) int {
	best := -1
	for i, r := range rules {
		if r.Prefix != "" && strings.HasPrefix(comment, r.Prefix) && (best < 0 || len(r.Prefix) > len(rules[best].Prefix)) {
			best = i
		}
	}
	return best
}

// resolve finds a rule's groups among an instance's, as sorted IDs, or says why it can't.
func resolve(r Rule, groups []piholeapi.Group) ([]int, *RuleProblem) {
	var ids []int
	switch r.Match {
	case MatchPrefixes:
		for _, g := range groups {
			if slices.ContainsFunc(r.Groups, func(p string) bool { return strings.HasPrefix(g.Name, p) }) {
				ids = append(ids, g.ID)
			}
		}
		if len(ids) == 0 {
			return nil, &RuleProblem{Prefix: r.Prefix, Code: CodeNoTargetGroups}
		}
	default:
		var missing []string
		for _, name := range r.Groups {
			i := slices.IndexFunc(groups, func(g piholeapi.Group) bool { return g.Name == name })
			if i < 0 {
				missing = append(missing, name)
				continue
			}
			ids = append(ids, groups[i].ID)
		}
		if len(missing) > 0 {
			return nil, &RuleProblem{Prefix: r.Prefix, Code: CodeGroupMissing, Missing: missing}
		}
	}
	slices.Sort(ids)
	return slices.Compact(ids), nil
}

// makePlan works out what the rules do to an instance's clients, given its clients and Pi-hole groups. Clients keep
// the order Pi-hole lists them in.
func makePlan(rules []Rule, clients []piholeapi.ClientEntry, groups []piholeapi.Group) plan {
	var p plan
	targets := make([][]int, len(rules))
	problems := make([]*RuleProblem, len(rules))
	for i, r := range rules {
		// A rule that can't run here is reported whether or not a client matches it now, so it can be fixed first.
		if targets[i], problems[i] = resolve(r, groups); problems[i] != nil {
			p.problems = append(p.problems, *problems[i])
		}
	}
	for _, c := range clients {
		i := ruleFor(rules, c.Comment)
		if i < 0 {
			continue
		}
		if pr := problems[i]; pr != nil {
			p.failures = append(p.failures, Failure{Client: c.Client, Comment: c.Comment, Prefix: rules[i].Prefix, Code: pr.Code})
			continue
		}
		current := slices.Clone(c.Groups)
		slices.Sort(current)
		current = slices.Compact(current)
		if slices.Equal(current, targets[i]) {
			p.unchanged++
			continue
		}
		p.changes = append(p.changes, Change{
			Client: c.Client, Comment: c.Comment, Prefix: rules[i].Prefix,
			Before: groupNames(current, groups), After: groupNames(targets[i], groups), ids: targets[i],
		})
	}
	return p
}

// groupNames names group IDs by the instance's groups, sorted; an ID it doesn't have is "#<id>".
func groupNames(ids []int, groups []piholeapi.Group) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		i := slices.IndexFunc(groups, func(g piholeapi.Group) bool { return g.ID == id })
		if i < 0 {
			out = append(out, "#"+strconv.Itoa(id))
			continue
		}
		out = append(out, groups[i].Name)
	}
	slices.Sort(out)
	return out
}
