// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package instances

import (
	"cmp"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
)

// Drift keeps, in memory, what differs between the members of each mirrored group: every enabled member is compared
// with the primary, the group's source of truth. Domains are matched by domain, type and kind, clients by their
// identifier, and Pi-hole groups by name, since Pi-hole's IDs differ per instance; group memberships are compared by
// group name for the same reason. A group is checked when Run starts, every Interval after that, and soon after Poke
// (a write through the group, say). Nothing is stored: a restart checks again.
type Drift struct {
	Service *Service
	// Interval is how often every mirrored group is checked (default 5 minutes).
	Interval time.Duration
	// Delay is how long Poke waits before checking, so a burst of writes leads to one check (default 2 seconds).
	Delay  time.Duration
	Logger *slog.Logger
	// Now returns the current time; nil means time.Now.
	Now func() time.Time

	mu      sync.Mutex
	reports map[int64]Report
	locks   map[int64]*sync.Mutex // one check of a group at a time
	pending map[int64]bool        // poked, not yet checked
	wake    chan struct{}
}

// Difference is how a member differs from the primary for one item.
type Difference string

const (
	Missing Difference = "missing" // on the primary, not on the member
	Extra   Difference = "extra"   // on the member, not on the primary
	Changed Difference = "changed" // on both, with different settings
)

// DomainState is a list entry's settings, with its Pi-hole groups by name, sorted.
type DomainState struct {
	Comment string
	Groups  []string
	Enabled bool
}

type DomainDrift struct {
	Member     int64
	MemberName string
	Domain     string
	Type       string
	Kind       string
	Difference Difference
	Primary    *DomainState // nil when Extra
	Other      *DomainState // the member's; nil when Missing
}

type ClientState struct {
	Comment string
	Groups  []string
}

type ClientDrift struct {
	Member     int64
	MemberName string
	Client     string
	Difference Difference
	Primary    *ClientState
	Other      *ClientState
}

type GroupState struct {
	Comment string
	Enabled bool
}

type GroupDrift struct {
	Member     int64
	MemberName string
	Name       string
	Difference Difference
	Primary    *GroupState
	Other      *GroupState
}

// MemberCheck is how reading one member went. Code is empty when it answered, otherwise the error's code (Kind).
type MemberCheck struct {
	ID      int64
	Name    string
	Primary bool
	Code    string
}

// Report is the result of checking one mirrored group.
type Report struct {
	GroupID   int64
	CheckedAt time.Time
	Members   []MemberCheck // the enabled members, the primary first, then by name
	// PrimaryOK says whether the primary answered. Without it nothing can be compared, and the lists are empty.
	PrimaryOK bool
	Domains   []DomainDrift
	Clients   []ClientDrift
	Groups    []GroupDrift
}

// Drifted says whether any member was found to differ from the primary. Members that didn't answer don't count:
// they are unknown, not different.
func (r Report) Drifted() bool {
	return len(r.Domains)+len(r.Clients)+len(r.Groups) > 0
}

// DomainsDrifted and ClientsDrifted are the per-type flags behind the badges on the domains and clients pages.
func (r Report) DomainsDrifted() bool { return len(r.Domains) > 0 }
func (r Report) ClientsDrifted() bool { return len(r.Clients) > 0 }

func (d *Drift) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

func (d *Drift) init() {
	if d.reports == nil {
		d.reports = map[int64]Report{}
		d.locks = map[int64]*sync.Mutex{}
		d.pending = map[int64]bool{}
		d.wake = make(chan struct{}, 1)
	}
}

// Report returns a group's latest report, if it has been checked.
func (d *Drift) Report(groupID int64) (Report, bool) {
	if d == nil {
		return Report{}, false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.init()
	r, ok := d.reports[groupID]
	return r, ok
}

// Forget drops a group's report: the group was deleted, or its members or mode changed, so the report no longer
// describes it.
func (d *Drift) Forget(groupID int64) {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.init()
	delete(d.reports, groupID)
}

// Poke asks for a group to be checked soon. It never blocks; several pokes before the check lead to one check.
func (d *Drift) Poke(groupID int64) {
	if d == nil {
		return
	}
	d.mu.Lock()
	d.init()
	d.pending[groupID] = true
	d.mu.Unlock()
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// errNotMirrored is returned by Check for a group that doesn't exist or isn't mirrored.
var errNotMirrored = errors.New("instances: not a mirrored group")

// Check reads every enabled member of a mirrored group at once, compares each with the primary, stores the report and
// returns it. A group whose primary is disabled has no members to compare and gets a report with PrimaryOK false.
func (d *Drift) Check(ctx context.Context, groupID int64) (Report, error) {
	d.mu.Lock()
	d.init()
	lock := d.locks[groupID]
	if lock == nil {
		lock = &sync.Mutex{}
		d.locks[groupID] = lock
	}
	d.mu.Unlock()
	lock.Lock()
	defer lock.Unlock()

	g, err := d.Service.GetGroup(ctx, groupID)
	if rbac.IsCode(err, rbac.CodeNotFound) || (err == nil && g.Mode != rbac.Mirrored) {
		d.Forget(groupID)
		return Report{}, errNotMirrored
	}
	if err != nil {
		return Report{}, err
	}
	pool := d.Service.Pool
	rep := Report{GroupID: groupID, CheckedAt: d.now()}
	if name, ok := pool.Name(g.Primary); ok {
		rep.Members = append(rep.Members, MemberCheck{ID: g.Primary, Name: name, Primary: true})
	}
	var others []MemberCheck
	for _, id := range g.Members {
		if name, ok := pool.Name(id); ok && id != g.Primary {
			others = append(others, MemberCheck{ID: id, Name: name})
		}
	}
	slices.SortFunc(others, func(a, b MemberCheck) int { return cmp.Compare(a.Name, b.Name) })
	if len(rep.Members) == 0 {
		// The primary is disabled: the group isn't usable, and there is nothing to compare with. The report says so,
		// with the other members listed but unread.
		rep.Members = others
		d.store(rep)
		return rep, nil
	}
	rep.Members = append(rep.Members, others...)

	snaps := make([]snapshot, len(rep.Members))
	var wg sync.WaitGroup
	for i, m := range rep.Members {
		wg.Go(func() {
			err := pool.Do(ctx, m.ID, func(ctx context.Context, c *piholeapi.Client) error {
				var err error
				snaps[i], err = readSnapshot(ctx, c)
				return err
			})
			if err != nil {
				rep.Members[i].Code = Kind(err)
				if rep.Members[i].Code == "" {
					rep.Members[i].Code = "internal"
				}
			}
		})
	}
	wg.Wait()
	if ctx.Err() != nil {
		return Report{}, ctx.Err()
	}
	rep.PrimaryOK = rep.Members[0].Code == ""
	if rep.PrimaryOK {
		for i := 1; i < len(rep.Members); i++ {
			if rep.Members[i].Code == "" {
				compare(&rep, snaps[0], snaps[i], rep.Members[i])
			}
		}
	}
	d.store(rep)
	return rep, nil
}

func (d *Drift) store(rep Report) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.reports[rep.GroupID] = rep
}

// CheckAll checks every mirrored group, and forgets the reports of groups that are gone or no longer mirrored.
func (d *Drift) CheckAll(ctx context.Context) {
	groups, err := d.Service.ListGroups(ctx)
	if err != nil {
		d.log().Warn("drift check: listing groups", "err", err)
		return
	}
	mirrored := map[int64]bool{}
	for _, g := range groups {
		if g.Mode != rbac.Mirrored {
			continue
		}
		mirrored[g.ID] = true
		if _, err := d.Check(ctx, g.ID); err != nil && !errors.Is(err, errNotMirrored) && ctx.Err() == nil {
			d.log().Warn("drift check failed", "group", g.Name, "err", err)
		}
	}
	d.mu.Lock()
	for id := range d.reports {
		if !mirrored[id] {
			delete(d.reports, id)
		}
	}
	d.mu.Unlock()
}

// Run checks every mirrored group at once and then every Interval, and checks a poked group after Delay, until ctx
// is done.
func (d *Drift) Run(ctx context.Context) {
	d.mu.Lock()
	d.init()
	wake := d.wake
	d.mu.Unlock()
	interval, delay := cmp.Or(d.Interval, 5*time.Minute), cmp.Or(d.Delay, 2*time.Second)

	d.CheckAll(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.CheckAll(ctx)
		case <-wake:
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
			d.mu.Lock()
			due := make([]int64, 0, len(d.pending))
			for id := range d.pending {
				due = append(due, id)
			}
			clear(d.pending)
			d.mu.Unlock()
			slices.Sort(due)
			for _, id := range due {
				if _, err := d.Check(ctx, id); err != nil && !errors.Is(err, errNotMirrored) && ctx.Err() == nil {
					d.log().Warn("drift check failed", "group_id", id, "err", err)
				}
			}
		}
	}
}

func (d *Drift) log() *slog.Logger {
	if d.Logger != nil {
		return d.Logger
	}
	return slog.New(slog.DiscardHandler)
}

// snapshot is what one member has: its lists, clients and Pi-hole groups.
type snapshot struct {
	domains []piholeapi.DomainEntry
	clients []piholeapi.ClientEntry
	groups  []piholeapi.Group
}

func readSnapshot(ctx context.Context, c *piholeapi.Client) (snapshot, error) {
	var s snapshot
	var err error
	if s.domains, err = c.ListDomains(ctx); err != nil {
		return s, err
	}
	if s.clients, err = c.ListClients(ctx); err != nil {
		return s, err
	}
	s.groups, err = c.ListGroups(ctx)
	return s, err
}

// names turns Pi-hole group IDs into sorted names, so memberships can be compared across instances. An ID the
// instance doesn't list is kept as "#<id>".
func (s snapshot) names(ids []int) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		i := slices.IndexFunc(s.groups, func(g piholeapi.Group) bool { return g.ID == id })
		if i >= 0 {
			out = append(out, s.groups[i].Name)
		} else {
			out = append(out, "#"+strconv.Itoa(id))
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// compare adds to rep how member m (with snapshot other) differs from the primary (snapshot primary).
func compare(rep *Report, primary, other snapshot, m MemberCheck) {
	type dkey struct{ domain, typ, kind string }
	pd := map[dkey]piholeapi.DomainEntry{}
	for _, e := range primary.domains {
		pd[dkey{e.Domain, e.Type, e.Kind}] = e
	}
	od := map[dkey]piholeapi.DomainEntry{}
	for _, e := range other.domains {
		od[dkey{e.Domain, e.Type, e.Kind}] = e
	}
	dstate := func(s snapshot, e piholeapi.DomainEntry) *DomainState {
		return &DomainState{Comment: e.Comment, Groups: s.names(e.Groups), Enabled: e.Enabled}
	}
	var domains []DomainDrift
	for k, pe := range pd {
		dd := DomainDrift{Member: m.ID, MemberName: m.Name, Domain: k.domain, Type: k.typ, Kind: k.kind}
		oe, ok := od[k]
		ps := dstate(primary, pe)
		switch {
		case !ok:
			dd.Difference, dd.Primary = Missing, ps
		default:
			os := dstate(other, oe)
			if os.Comment == ps.Comment && os.Enabled == ps.Enabled && slices.Equal(os.Groups, ps.Groups) {
				continue
			}
			dd.Difference, dd.Primary, dd.Other = Changed, ps, os
		}
		domains = append(domains, dd)
	}
	for k, oe := range od {
		if _, ok := pd[k]; !ok {
			domains = append(domains, DomainDrift{
				Member: m.ID, MemberName: m.Name, Domain: k.domain, Type: k.typ, Kind: k.kind,
				Difference: Extra, Other: dstate(other, oe),
			})
		}
	}
	slices.SortFunc(domains, func(a, b DomainDrift) int {
		return cmp.Or(cmp.Compare(a.Domain, b.Domain), cmp.Compare(a.Type, b.Type), cmp.Compare(a.Kind, b.Kind))
	})
	rep.Domains = append(rep.Domains, domains...)

	pc := map[string]piholeapi.ClientEntry{}
	for _, c := range primary.clients {
		pc[c.Client] = c
	}
	oc := map[string]piholeapi.ClientEntry{}
	for _, c := range other.clients {
		oc[c.Client] = c
	}
	var clients []ClientDrift
	for id, pce := range pc {
		cd := ClientDrift{Member: m.ID, MemberName: m.Name, Client: id}
		ps := &ClientState{Comment: pce.Comment, Groups: primary.names(pce.Groups)}
		oce, ok := oc[id]
		if !ok {
			cd.Difference, cd.Primary = Missing, ps
		} else {
			os := &ClientState{Comment: oce.Comment, Groups: other.names(oce.Groups)}
			if os.Comment == ps.Comment && slices.Equal(os.Groups, ps.Groups) {
				continue
			}
			cd.Difference, cd.Primary, cd.Other = Changed, ps, os
		}
		clients = append(clients, cd)
	}
	for id, oce := range oc {
		if _, ok := pc[id]; !ok {
			clients = append(clients, ClientDrift{
				Member: m.ID, MemberName: m.Name, Client: id, Difference: Extra,
				Other: &ClientState{Comment: oce.Comment, Groups: other.names(oce.Groups)},
			})
		}
	}
	slices.SortFunc(clients, func(a, b ClientDrift) int { return cmp.Compare(a.Client, b.Client) })
	rep.Clients = append(rep.Clients, clients...)

	pg := map[string]piholeapi.Group{}
	for _, g := range primary.groups {
		pg[g.Name] = g
	}
	og := map[string]piholeapi.Group{}
	for _, g := range other.groups {
		og[g.Name] = g
	}
	var groups []GroupDrift
	for name, p := range pg {
		gd := GroupDrift{Member: m.ID, MemberName: m.Name, Name: name}
		o, ok := og[name]
		if !ok {
			gd.Difference, gd.Primary = Missing, &GroupState{Comment: p.Comment, Enabled: p.Enabled}
		} else {
			if o.Comment == p.Comment && o.Enabled == p.Enabled {
				continue
			}
			gd.Difference = Changed
			gd.Primary, gd.Other = &GroupState{Comment: p.Comment, Enabled: p.Enabled}, &GroupState{Comment: o.Comment, Enabled: o.Enabled}
		}
		groups = append(groups, gd)
	}
	for name, o := range og {
		if _, ok := pg[name]; !ok {
			groups = append(groups, GroupDrift{Member: m.ID, MemberName: m.Name, Name: name, Difference: Extra,
				Other: &GroupState{Comment: o.Comment, Enabled: o.Enabled}})
		}
	}
	slices.SortFunc(groups, func(a, b GroupDrift) int { return cmp.Compare(a.Name, b.Name) })
	rep.Groups = append(rep.Groups, groups...)
}
