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

	"github.com/Kate-0713/pihole-rbac/internal/lists"
	"github.com/Kate-0713/pihole-rbac/internal/localdns"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
)

// Reconciling a mirrored group makes its members match the primary: what is missing on a member is added, what
// differs is changed to the primary's settings, and list entries and clients that only a member has are deleted.
// Pi-hole groups are created and changed by name, but never deleted, since entries and clients outside the group's
// view may still use them. The members are read again first, so a reconcile acts on what is there now rather than
// on the last drift report. Each member is changed on its own (members at once), Pi-hole groups first, so the
// lists, entries and clients after them can use them; a Pi-hole group an entry or client needs that the member doesn't have
// is created as part of that item. Local DNS comes last: CNAME changes restart FTL, so members change their CNAMEs one
// at a time, each sending them so that FTL restarts once, and waiting for it to answer again. One item failing doesn't
// stop the others.

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

// ListKey names a subscribed list on a member. Address is as Pi-hole has it, or as the API shows it (redacted, for
// one with a password in it), which matches too.
type ListKey struct {
	Member  int64
	Address string
	Type    string
}

// LocalDNSKey names a local DNS record or CNAME on a member: Kind is LocalDNSRecord or LocalDNSCNAME, Key as in
// internal/localdns.
type LocalDNSKey struct {
	Member int64
	Kind   string
	Key    string
}

// Selection is what to reconcile: everything, or the items named.
type Selection struct {
	All     bool
	Domains []DomainKey
	Clients []ClientKey
	Groups  []GroupKey
	Lists   []ListKey
	// LocalDNS are local DNS records and CNAMEs. Only missing and extra ones can differ.
	LocalDNS []LocalDNSKey
	// CheckList, if set, says whether a list missing on a member may be added to it: the app's rules for new lists'
	// addresses (see lists.CheckAddress), so reconcile doesn't copy an address the app wouldn't accept. It is called
	// for several members at once.
	CheckList func(address string) error
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
	ItemDomain   ItemKind = "domain"
	ItemClient   ItemKind = "client"
	ItemGroup    ItemKind = "group"
	ItemList     ItemKind = "list"
	ItemLocalDNS ItemKind = "local_dns"
)

// ReconcileItem is what happened to one item on one member. Err is nil when it worked.
type ReconcileItem struct {
	Member     int64
	MemberName string
	Kind       ItemKind
	Domain     DomainKey // for a domain
	Client     string    // for a client
	Group      string    // for a Pi-hole group
	List       ListKey   // for a subscribed list, with the address as Pi-hole has it
	// NeedsGravity is set for a list added, or enabled, on the member: it waits for gravity there.
	NeedsGravity bool
	LocalDNS     LocalDNSKey // for a local DNS record or CNAME
	// RestartPending is set for a CNAME changed on a member that hadn't answered again within RestartWait of
	// restarting its resolver.
	RestartPending bool
	Action         Action
	Err            error
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

// ErrNotWritable is a primary's local DNS entry reconcile won't copy: one the app couldn't have written itself
// (several names, a comment, or a value it wouldn't accept).
var ErrNotWritable = errors.New("the primary's entry has several names, a comment, or a value the app doesn't write, so it isn't copied")

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
	for _, k := range sel.Lists {
		named[k.Member] = true
	}
	for _, k := range sel.LocalDNS {
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
				items[i], err = reconcileMember(ctx, c, primary, *m, sel, &d.cnameMu)
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
func reconcileMember(ctx context.Context, c *piholeapi.Client, primary snapshot, m MemberCheck, sel Selection, cnameMu *sync.Mutex) ([]ReconcileItem, error) {
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

	// Called on its own line: idsFor appends the Pi-hole groups it creates to out, which append(out, ...) would lose.
	listItems := reconcileLists(ctx, c, rep.Lists, m, sel, idsFor)
	out = append(out, listItems...)

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
	out = append(out, reconcileLocalDNS(ctx, c, rep.LocalDNS, primary, member, m, sel, cnameMu)...)
	return out, nil
}

// reconcileLocalDNS adds the local DNS entries member m is missing and deletes those only it has, for the differences
// in drift that sel asks for. A missing entry is added as the app builds it, never by copying the primary's string,
// and only if the app could have written it. Host records are changed at once; CNAMEs, which restart FTL, wait for
// cnameMu so one member restarts at a time, and are sent so that FTL restarts once.
func reconcileLocalDNS(ctx context.Context, c *piholeapi.Client, drift []LocalDNSDrift, primary, member snapshot, m MemberCheck, sel Selection, cnameMu *sync.Mutex) []ReconcileItem {
	var out []ReconcileItem
	seen := map[LocalDNSKey]bool{}
	// opsOf[i] are the indexes in cnameOps of item i's CNAME changes.
	var cnameOps []piholeapi.CNAMEOp
	opsOf := map[int][]int{}
	ignore := func(err error) error { // already as asked
		var se *piholeapi.StatusError
		if errors.Is(err, piholeapi.ErrAlreadyPresent) || (errors.As(err, &se) && se.Code == 404) {
			return nil
		}
		return err
	}
	for _, ld := range drift {
		k := LocalDNSKey{Member: m.ID, Kind: ld.Kind, Key: ld.Key}
		if !sel.All && !slices.Contains(sel.LocalDNS, k) {
			continue
		}
		seen[k] = true
		it := ReconcileItem{Member: m.ID, MemberName: m.Name, Kind: ItemLocalDNS, LocalDNS: k, Action: ActionAdd}
		var values []string // the strings to send: the one to add, or the member's to delete
		if ld.Difference == Extra {
			it.Action = ActionDelete
			values = member.localDNSValues(ld.Kind, ld.Key)
		} else {
			v, err := primary.buildLocalDNS(ld.Kind, ld.Key)
			if err != nil {
				it.Err = err
				out = append(out, it)
				continue
			}
			values = []string{v}
		}
		if ld.Kind == LocalDNSRecord {
			for _, v := range values {
				var err error
				if it.Action == ActionDelete {
					err = c.DeleteHostRecord(ctx, v)
				} else {
					err = c.AddHostRecord(ctx, v)
				}
				if err = ignore(err); err != nil && it.Err == nil {
					it.Err = err
				}
			}
			out = append(out, it)
			continue
		}
		i := len(out)
		out = append(out, it)
		for _, v := range values {
			opsOf[i] = append(opsOf[i], len(cnameOps))
			cnameOps = append(cnameOps, piholeapi.CNAMEOp{Delete: it.Action == ActionDelete, Value: v})
		}
	}
	if len(cnameOps) > 0 {
		cnameMu.Lock()
		errs, restarted, since := c.ApplyCNAMEs(ctx, cnameOps)
		pending := restarted && c.WaitRestarted(ctx, since, piholeapi.RestartWait) != nil
		cnameMu.Unlock()
		for i, ops := range opsOf {
			for _, op := range ops {
				if err := ignore(errs[op]); err != nil && out[i].Err == nil {
					out[i].Err = err
				}
			}
			out[i].RestartPending = pending && out[i].Err == nil
		}
	}
	for _, k := range sel.LocalDNS {
		if k.Member == m.ID && !seen[k] {
			out = append(out, ReconcileItem{Member: m.ID, MemberName: m.Name, Kind: ItemLocalDNS, LocalDNS: k, Action: ActionNone})
		}
	}
	return out
}

// localDNSValues is every string s has for the local DNS entry of kind with key: usually one, but Pi-hole matches
// strings exactly, so two spellings of one record can both be there.
func (s snapshot) localDNSValues(kind, key string) []string {
	var out []string
	for _, e := range s.localDNS() {
		if e.kind == kind && e.key == key {
			out = append(out, e.value)
		}
	}
	return out
}

// buildLocalDNS is the string the app writes for s's local DNS entry of kind with key, or ErrNotWritable for one it
// couldn't have written.
func (s snapshot) buildLocalDNS(kind, key string) (string, error) {
	if kind == LocalDNSRecord {
		for _, h := range s.hosts {
			if h.Key == key && h.Writable() {
				b, err := localdns.NewHost(h.IP.String(), h.Hostnames[0])
				if err == nil {
					return b.Value, nil
				}
			}
		}
		return "", ErrNotWritable
	}
	for _, c := range s.cnames {
		if c.Key == key && c.Writable() {
			b, err := localdns.NewCNAME(c.Aliases[0], c.Target, c.TTL)
			if err == nil {
				return b.Value, nil
			}
		}
	}
	return "", ErrNotWritable
}

// reconcileLists makes member m's subscribed lists match the primary's, for the differences in drift that sel asks
// for, and reports each selected list that already matched as unchanged. idsFor maps the primary's group names to the
// member's IDs.
func reconcileLists(ctx context.Context, c *piholeapi.Client, drift []ListDrift, m MemberCheck, sel Selection, idsFor func([]string) ([]int, error)) []ReconcileItem {
	// selected returns the selection's key for a difference: the key as the request gave it, so one that matched
	// nothing can be reported as unchanged.
	selected := func(ld ListDrift) (ListKey, bool) {
		if sel.All {
			return ListKey{Member: m.ID, Address: ld.Address, Type: ld.Type}, true
		}
		for _, k := range sel.Lists {
			if k.Member == m.ID && k.Type == ld.Type && (k.Address == ld.Address || k.Address == lists.Redacted(ld.Address)) {
				return k, true
			}
		}
		return ListKey{}, false
	}
	var out []ReconcileItem
	seen := map[ListKey]bool{}
	for _, ld := range drift {
		k, ok := selected(ld)
		if !ok {
			continue
		}
		seen[k] = true
		key := ListKey{Member: m.ID, Address: ld.Address, Type: ld.Type}
		it := ReconcileItem{Member: m.ID, MemberName: m.Name, Kind: ItemList, List: key}
		entry := piholeapi.ListEntry{Address: ld.Address, Type: ld.Type}
		switch ld.Difference {
		case Missing, Changed:
			it.Action = ActionAdd
			if ld.Difference == Changed {
				it.Action = ActionUpdate
			}
			entry.Comment, entry.Enabled = ld.Primary.Comment, ld.Primary.Enabled
			it.NeedsGravity = entry.Enabled && (ld.Difference == Missing || !ld.Other.Enabled)
			if ld.Difference == Missing && sel.CheckList != nil {
				if it.Err = sel.CheckList(ld.Address); it.Err != nil {
					it.NeedsGravity = false
					break
				}
			}
			if entry.Groups, it.Err = idsFor(ld.Primary.Groups); it.Err == nil {
				if ld.Difference == Missing {
					_, it.Err = c.AddList(ctx, entry)
				} else {
					_, it.Err = c.UpdateList(ctx, entry)
				}
			}
			if it.Err != nil {
				it.NeedsGravity = false
			}
		case Extra:
			it.Action = ActionDelete
			it.Err = c.DeleteList(ctx, ld.Address, ld.Type)
		}
		out = append(out, it)
	}
	for _, k := range sel.Lists {
		if k.Member == m.ID && !seen[k] {
			out = append(out, ReconcileItem{Member: m.ID, MemberName: m.Name, Kind: ItemList, List: k, Action: ActionNone})
		}
	}
	return out
}
