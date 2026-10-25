// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package instances

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
)

// Reconciling a mirrored group makes its members match the primary: what is missing on a member is added, what
// differs is changed to the primary's settings, and list entries and clients that only a member has are deleted.
// Pi-hole groups are created and changed by name, but never deleted, since entries and clients outside the group's
// view may still use them. The members are read again first, so a reconcile acts on what is there now rather than
// on the last drift report. Each member is changed on its own (members at once), Pi-hole groups first, so the
// entries and clients after them can use them; a Pi-hole group an entry or client needs that the member doesn't have
// is created as part of that item. One item failing doesn't stop the others.

// DomainKey names a list entry on a member.
type DomainKey struct {
	Member int64
	Domain string
	Type   string
	Kind   string
}

// ClientKey names a client on a member.
type ClientKey struct {
	Member int64
	Client string
}

// GroupKey names a Pi-hole group on a member.
type GroupKey struct {
	Member int64
	Name   string
}

// Selection is what to reconcile: everything, or the items named.
type Selection struct {
	All     bool
	Domains []DomainKey
	Clients []ClientKey
	Groups  []GroupKey
}

// Action is what reconciling did to an item.
type Action string

const (
	ActionAdd    Action = "add"
	ActionUpdate Action = "update"
	ActionDelete Action = "delete"
	ActionNone   Action = "none" // already matched the primary
)

// ItemKind says which list an item is in.
type ItemKind string

const (
	ItemDomain ItemKind = "domain"
	ItemClient ItemKind = "client"
	ItemGroup  ItemKind = "group"
)

// ReconcileItem is what happened to one item on one member. Err is nil when it worked.
type ReconcileItem struct {
	Member     int64
	MemberName string
	Kind       ItemKind
	Domain     DomainKey // for a domain
	Client     string    // for a client
	Group      string    // for a Pi-hole group
	Action     Action
	Err        error
}

// ReconcileResult is what a reconcile did: each item, and the members that couldn't be read (Code set), who were
// left as they were.
type ReconcileResult struct {
	Members []MemberCheck // the members asked, with Code set for those that couldn't be read
	Items   []ReconcileItem
}

// ErrNotReconcilable is a selected item reconcile won't change: a Pi-hole group only a member has, which is never
// deleted.
var ErrNotReconcilable = errors.New("Pi-hole groups only a member has aren't deleted: entries or clients outside the group may use them")

// ErrPrimaryUnavailable means the group's primary is disabled, so there is nothing to copy from.
var ErrPrimaryUnavailable = errors.New("the group's primary is disabled")

// PrimaryError is the primary failing to answer, so nothing was compared or changed.
type PrimaryError struct {
	Name string
	Err  error
}

func (e *PrimaryError) Error() string { return "reading the primary " + e.Name + ": " + e.Err.Error() }
func (e *PrimaryError) Unwrap() error { return e.Err }

// Reconcile makes the members of mirrored group groupID match its primary, for the items sel names (or all of
// them). The caller checks drift.reconcile and audits the result.
func (d *Drift) Reconcile(ctx context.Context, groupID int64, sel Selection) (ReconcileResult, error) {
	g, err := d.Service.GetGroup(ctx, groupID)
	if err != nil {
		return ReconcileResult{}, err
	}
	if g.Mode != rbac.Mirrored {
		return ReconcileResult{}, errNotMirrored
	}
	pool := d.Service.Pool
	primaryName, ok := pool.Name(g.Primary)
	if !ok {
		return ReconcileResult{}, ErrPrimaryUnavailable
	}
	var primary snapshot
	if err := pool.Do(ctx, g.Primary, func(ctx context.Context, c *piholeapi.Client) error {
		var err error
		primary, err = readSnapshot(ctx, c)
		return err
	}); err != nil {
		return ReconcileResult{}, &PrimaryError{Name: primaryName, Err: err}
	}

	// The members to change: every enabled one but the primary, or those the selection names.
	named := map[int64]bool{}
	for _, k := range sel.Domains {
		named[k.Member] = true
	}
	for _, k := range sel.Clients {
		named[k.Member] = true
	}
	for _, k := range sel.Groups {
		named[k.Member] = true
	}
	var members []MemberCheck
	for _, id := range g.Members {
		name, ok := pool.Name(id)
		if !ok || id == g.Primary || (!sel.All && !named[id]) {
			continue
		}
		members = append(members, MemberCheck{ID: id, Name: name})
	}
	slices.SortFunc(members, func(a, b MemberCheck) int { return cmp.Compare(a.Name, b.Name) })

	items := make([][]ReconcileItem, len(members))
	var wg sync.WaitGroup
	for i := range members {
		wg.Go(func() {
			m := &members[i]
			err := pool.Do(ctx, m.ID, func(ctx context.Context, c *piholeapi.Client) error {
				var err error
				items[i], err = reconcileMember(ctx, c, primary, *m, sel)
				return err
			})
			if err != nil {
				m.Code = Kind(err)
				if m.Code == "" {
					m.Code = "internal"
				}
			}
		})
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return ReconcileResult{}, err
	}
	res := ReconcileResult{Members: members}
	for _, list := range items {
		res.Items = append(res.Items, list...)
	}
	return res, nil
}

// reconcileMember changes one member to match the primary. It returns an error only when the member couldn't be
// read at all; a change that fails is that item's Err.
func reconcileMember(ctx context.Context, c *piholeapi.Client, primary snapshot, m MemberCheck, sel Selection) ([]ReconcileItem, error) {
	member, err := readSnapshot(ctx, c)
	if err != nil {
		return nil, err
	}
	var rep Report
	compare(&rep, primary, member, m)
	var out []ReconcileItem

	// Pi-hole groups first, so the entries and clients after them can use them.
	wantGroup := func(name string) bool {
		return sel.All || slices.Contains(sel.Groups, GroupKey{Member: m.ID, Name: name})
	}
	seen := map[string]bool{}
	for _, gd := range rep.Groups {
		if !wantGroup(gd.Name) {
			continue
		}
		seen[gd.Name] = true
		it := ReconcileItem{Member: m.ID, MemberName: m.Name, Kind: ItemGroup, Group: gd.Name}
		switch gd.Difference {
		case Missing:
			it.Action = ActionAdd
			it.Err = c.AddGroup(ctx, piholeapi.Group{Name: gd.Name, Comment: gd.Primary.Comment, Enabled: gd.Primary.Enabled})
		case Changed:
			it.Action = ActionUpdate
			it.Err = c.UpdateGroup(ctx, piholeapi.Group{Name: gd.Name, Comment: gd.Primary.Comment, Enabled: gd.Primary.Enabled})
		case Extra:
			if sel.All {
				continue // never deleted, and not something "all" asks for
			}
			it.Action, it.Err = ActionNone, ErrNotReconcilable
		}
		out = append(out, it)
	}
	for _, k := range sel.Groups {
		if k.Member == m.ID && !seen[k.Name] {
			out = append(out, ReconcileItem{Member: m.ID, MemberName: m.Name, Kind: ItemGroup, Group: k.Name, Action: ActionNone})
		}
	}

	// The member's groups as they are now, to map the primary's group names to the member's IDs. A group an item
	// needs that the member still doesn't have is created, as the primary has it.
	groups, err := c.ListGroups(ctx)
	if err != nil {
		groups = member.groups
	}
	idsFor := func(names []string) ([]int, error) {
		ids := []int{}
		for _, name := range names {
			i := slices.IndexFunc(groups, func(g piholeapi.Group) bool { return g.Name == name })
			if i < 0 {
				p := slices.IndexFunc(primary.groups, func(g piholeapi.Group) bool { return g.Name == name })
				if p < 0 {
					return nil, fmt.Errorf("%w: no group %q on the primary", piholeapi.ErrInvalidArgument, name)
				}
				if err := c.AddGroup(ctx, primary.groups[p]); err != nil {
					return nil, err
				}
				out = append(out, ReconcileItem{Member: m.ID, MemberName: m.Name, Kind: ItemGroup, Group: name, Action: ActionAdd})
				if groups, err = c.ListGroups(ctx); err != nil {
					return nil, err
				}
				if i = slices.IndexFunc(groups, func(g piholeapi.Group) bool { return g.Name == name }); i < 0 {
					return nil, fmt.Errorf("%w: group %q wasn't created", piholeapi.ErrBadResponse, name)
				}
			}
			ids = append(ids, groups[i].ID)
		}
		slices.Sort(ids)
		return ids, nil
	}

	wantDomain := func(k DomainKey) bool { return sel.All || slices.Contains(sel.Domains, k) }
	seenDomains := map[DomainKey]bool{}
	for _, dd := range rep.Domains {
		k := DomainKey{Member: m.ID, Domain: dd.Domain, Type: dd.Type, Kind: dd.Kind}
		if !wantDomain(k) {
			continue
		}
		seenDomains[k] = true
		it := ReconcileItem{Member: m.ID, MemberName: m.Name, Kind: ItemDomain, Domain: k}
		entry := piholeapi.DomainEntry{Domain: dd.Domain, Type: dd.Type, Kind: dd.Kind}
		switch dd.Difference {
		case Missing, Changed:
			it.Action = ActionAdd
			if dd.Difference == Changed {
				it.Action = ActionUpdate
			}
			entry.Comment, entry.Enabled = dd.Primary.Comment, dd.Primary.Enabled
			if entry.Groups, it.Err = idsFor(dd.Primary.Groups); it.Err == nil {
				if dd.Difference == Missing {
					_, it.Err = c.AddDomainAs(ctx, entry)
				} else {
					_, it.Err = c.UpdateDomain(ctx, entry)
				}
			}
		case Extra:
			it.Action = ActionDelete
			it.Err = c.DeleteDomain(ctx, dd.Domain, dd.Type, dd.Kind)
		}
		out = append(out, it)
	}
	for _, k := range sel.Domains {
		if k.Member == m.ID && !seenDomains[k] {
			out = append(out, ReconcileItem{Member: m.ID, MemberName: m.Name, Kind: ItemDomain, Domain: k, Action: ActionNone})
		}
	}

	wantClient := func(id string) bool {
		return sel.All || slices.Contains(sel.Clients, ClientKey{Member: m.ID, Client: id})
	}
	seenClients := map[string]bool{}
	for _, cd := range rep.Clients {
		if !wantClient(cd.Client) {
			continue
		}
		seenClients[cd.Client] = true
		it := ReconcileItem{Member: m.ID, MemberName: m.Name, Kind: ItemClient, Client: cd.Client}
		switch cd.Difference {
		case Missing, Changed:
			it.Action = ActionAdd
			if cd.Difference == Changed {
				it.Action = ActionUpdate
			}
			var ids []int
			if ids, it.Err = idsFor(cd.Primary.Groups); it.Err == nil {
				if cd.Difference == Missing {
					_, it.Err = c.AddClient(ctx, cd.Client, cd.Primary.Comment, ids)
				} else {
					_, it.Err = c.UpdateClientGroups(ctx, cd.Client, cd.Primary.Comment, ids)
				}
			}
		case Extra:
			it.Action = ActionDelete
			it.Err = c.DeleteClient(ctx, cd.Client)
		}
		out = append(out, it)
	}
	for _, k := range sel.Clients {
		if k.Member == m.ID && !seenClients[k.Client] {
			out = append(out, ReconcileItem{Member: m.ID, MemberName: m.Name, Kind: ItemClient, Client: k.Client, Action: ActionNone})
		}
	}
	return out, nil
}
