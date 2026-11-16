// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package clientoverrides is temporary client group changes: a client moved into other Pi-hole groups until a set
// time, then put back by the app, since Pi-hole has no timer for group membership. Groups are always names, never
// Pi-hole IDs, so they match across the members of a mirrored group and survive a group being recreated. The group
// maths and the checks are pure; the service and scheduler that use them come later.
package clientoverrides

import "slices"

// Net is what an override changed: added are the override's groups the client wasn't in, removed the original groups
// it was taken out of. Both keep the order of the list they come from, and neither has duplicates.
func Net(original, override []string) (added, removed []string) {
	for _, n := range dedup(override) {
		if !slices.Contains(original, n) {
			added = append(added, n)
		}
	}
	for _, n := range dedup(original) {
		if !slices.Contains(override, n) {
			removed = append(removed, n)
		}
	}
	return added, removed
}

// Revert gives the groups a client should be in when the override ends: the groups it is in now, without the ones the
// override added, plus the ones it removed. Any other change made since is kept (decided Nov 14): the override
// moved {Default, Kids} to {Default}, someone then added Guests, and the revert gives {Default, Guests, Kids}.
// Groups keep the order they have now, and the ones put back follow in their original order.
func Revert(current, original, override []string) []string {
	added, removed := Net(original, override)
	out := make([]string, 0, len(current)+len(removed))
	for _, n := range current {
		if !slices.Contains(added, n) && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	for _, n := range removed {
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}

// Present splits names into those that exist (by exists) and those that don't, in order. A revert puts back what is
// left of the original groups, and reports the rest as missing: Pi-hole took the client out of a group itself when
// the group was deleted, so there is nothing to retry.
func Present(names []string, exists func(string) bool) (kept, missing []string) {
	for _, n := range names {
		if exists(n) {
			kept = append(kept, n)
		} else {
			missing = append(missing, n)
		}
	}
	return kept, missing
}

// Same reports whether two lists of group names hold the same names, whatever their order or duplicates.
func Same(a, b []string) bool {
	for _, n := range a {
		if !slices.Contains(b, n) {
			return false
		}
	}
	for _, n := range b {
		if !slices.Contains(a, n) {
			return false
		}
	}
	return true
}

func dedup(names []string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}
