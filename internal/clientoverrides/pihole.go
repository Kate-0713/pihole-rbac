// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package clientoverrides

import (
	"context"
	"errors"
	"slices"

	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
)

// ErrClientGone is a revert that found the client deleted. No retry can fix that, so the member settles as failed
// with the code not_found.
var ErrClientGone = errors.New("the client no longer exists")

// Names returns the names of the Pi-hole groups with these IDs, in the order of ids. An ID Pi-hole has no group for
// is left out.
func Names(ids []int, groups []piholeapi.Group) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if i := slices.IndexFunc(groups, func(g piholeapi.Group) bool { return g.ID == id }); i >= 0 {
			out = append(out, groups[i].Name)
		}
	}
	return out
}

// Resolve returns the sorted IDs of the groups with these names, and the names Pi-hole has no group for.
func Resolve(names []string, groups []piholeapi.Group) (ids []int, missing []string) {
	ids = []int{}
	for _, n := range names {
		i := slices.IndexFunc(groups, func(g piholeapi.Group) bool { return g.Name == n })
		switch {
		case i < 0:
			missing = append(missing, n)
		case !slices.Contains(ids, groups[i].ID):
			ids = append(ids, groups[i].ID)
		}
	}
	slices.Sort(ids)
	return ids, missing
}

// Change is what a revert did on one member.
type Change struct {
	Sent    bool     // the groups were changed on Pi-hole
	Before  []string // the client's groups before, by name
	After   []string // and after
	Missing []string // original groups that no longer exist on Pi-hole, left out
}

// RevertMember puts one member's client back: its groups as they are now, without the groups the override added and
// with the ones it removed (see Revert). Groups that no longer exist are left out and reported, since Pi-hole took
// the client out of them itself. A revert that changes nothing sends nothing, so it is safe to run again: a member
// that was never changed, or that an earlier attempt already put back, comes out the same. The client's comment is
// kept. A client that is gone is ErrClientGone.
func RevertMember(ctx context.Context, c *piholeapi.Client, client string, original, override []string) (Change, error) {
	list, err := c.ListClients(ctx)
	if err != nil {
		return Change{}, err
	}
	i := slices.IndexFunc(list, func(ce piholeapi.ClientEntry) bool { return ce.Client == client })
	if i < 0 {
		return Change{}, ErrClientGone
	}
	cur := list[i]
	groups, err := c.ListGroups(ctx)
	if err != nil {
		return Change{}, err
	}
	now := Names(cur.Groups, groups)
	exists := func(n string) bool {
		return slices.ContainsFunc(groups, func(g piholeapi.Group) bool { return g.Name == n })
	}
	kept, missing := Present(Revert(now, original, override), exists)
	ch := Change{Before: now, After: kept, Missing: missing}
	if Same(kept, now) {
		ch.After = now
		return ch, nil
	}
	ids, _ := Resolve(kept, groups)
	if _, err := c.UpdateClientGroups(ctx, cur.Client, cur.Comment, ids); err != nil {
		return ch, err
	}
	ch.Sent = true
	return ch, nil
}
