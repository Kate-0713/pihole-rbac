// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
)

// A /targets/{target} request acts on one instance or on a mirrored group. A mirrored group is its enabled members:
// its domains, clients and Pi-hole groups are read from the primary alone (the group's source of truth; the others
// may have drifted), its dashboard and query log from every member, and writes go to every member at once. Disabled
// members are left out of everything.

// instanceRef is one instance a target request acts on.
type instanceRef struct {
	target rbac.Target // the API target: the instance itself, or the mirrored group it is reached through
	id     int64
	name   string
	// Set when the instance is reached through a mirrored group: the group's name, and whether this is its primary.
	group   string
	primary bool
	// Set when the target is an instance that belongs to a mirrored group: that group's name. A write to it alone
	// makes it differ from the group, and the audit row says so.
	mirroredOf string
}

// target is what a target request acts on.
type target struct {
	t     rbac.Target
	group string // the mirrored group's name; empty for an instance
	// The instance; or the group's enabled members, the primary first, then by name (narrowed by only). Never empty.
	members []instanceRef
	// The instance itself, or the group's primary, which reads and the group's checks use even when only has left it
	// out of members.
	main instanceRef
}

func (tg target) isGroup() bool        { return tg.t.Kind == rbac.TargetGroup }
func (tg target) primary() instanceRef { return tg.main }

// only narrows a mirrored group's write to the members a request names in ?members=, to retry those that failed:
// nil leaves every member. Naming members is a 400 for an instance target, or for an ID that isn't an enabled member.
func (tg target) only(ids *gen.Members) (target, error) {
	if ids == nil {
		return tg, nil
	}
	if !tg.isGroup() {
		return target{}, invalid("members", "Members can only be named for a mirrored group.")
	}
	if len(*ids) == 0 {
		return target{}, invalid("members", "Name at least one member.")
	}
	for _, id := range *ids {
		if !slices.ContainsFunc(tg.members, func(m instanceRef) bool { return m.id == id }) {
			return target{}, invalid("members", "Instance %d isn't an enabled member of %s.", id, tg.group)
		}
	}
	out := tg
	out.members = slices.DeleteFunc(slices.Clone(tg.members), func(m instanceRef) bool { return !slices.Contains(*ids, m.id) })
	return out, nil
}

// resolveTarget parses a {target}, checks that the session holds p on it (any permission when p is ""), and finds
// what it names. A target the user holds nothing on is a 403 whether or not it exists, so the answer reveals nothing;
// an independent group isn't a target, so it is refused the same way. A disabled instance, or a mirrored group whose
// primary is disabled, is a 404.
func (s *Server) resolveTarget(ctx context.Context, raw string, p rbac.Permission) (target, error) {
	if s.Instances == nil {
		return target{}, errNoInstances
	}
	t, err := rbac.ParseTarget(raw)
	if err != nil {
		return target{}, invalid("target", `The target must be "i-<id>" for an instance or "g-<id>" for a mirrored group.`)
	}
	if p == "" {
		err = s.authorizeAny(ctx, t)
	} else {
		err = s.authorize(ctx, p, t)
	}
	if err != nil {
		return target{}, err
	}
	if t.Kind == rbac.TargetInstance {
		name, ok := s.Instances.Pool.Name(t.ID)
		if !ok {
			return target{}, targetNotFound(t)
		}
		ref := instanceRef{target: t, id: t.ID, name: name}
		if _, group, ok, err := s.Instances.MirroredGroupOf(ctx, t.ID); err != nil {
			return target{}, err
		} else if ok {
			ref.mirroredOf = group
		}
		return target{t: t, members: []instanceRef{ref}, main: ref}, nil
	}

	g, err := s.Instances.GetGroup(ctx, t.ID)
	if rbac.IsCode(err, rbac.CodeNotFound) || (err == nil && g.Mode != rbac.Mirrored) {
		return target{}, targetNotFound(t) // changed since the permission check
	}
	if err != nil {
		return target{}, err
	}
	primaryName, ok := s.Instances.Pool.Name(g.Primary)
	if !ok {
		return target{}, &rbac.Error{
			Code:    rbac.CodeNotFound,
			Message: fmt.Sprintf("%s can't be used: its primary instance is disabled.", g.Name),
			Details: map[string]any{"target": t.String()},
		}
	}
	tg := target{t: t, group: g.Name}
	tg.members = append(tg.members, instanceRef{target: t, id: g.Primary, name: primaryName, group: g.Name, primary: true})
	var others []instanceRef
	for _, id := range g.Members {
		if id == g.Primary {
			continue
		}
		if name, ok := s.Instances.Pool.Name(id); ok {
			others = append(others, instanceRef{target: t, id: id, name: name, group: g.Name})
		}
	}
	slices.SortFunc(others, func(a, b instanceRef) int { return cmp.Compare(a.name, b.name) })
	tg.members = append(tg.members, others...)
	tg.main = tg.members[0]
	return tg, nil
}

// memberError is a change a member of a mirrored group can't take, though the Pi-hole answered: the entry isn't on
// it, or it has no Pi-hole group with a name the change uses. It is that member's failure, not the request's.
type memberError struct {
	code    string // not_found or pihole_group_missing
	message string
}

func (e *memberError) Error() string { return e.message }

const (
	codeNotFound           = "not_found"
	codePiholeGroupMissing = "pihole_group_missing"
)

// missing reports an entry that isn't on member m: for an instance target the request's 404, as always; through a
// mirrored group, that member's failure.
func (tg target) missing(m instanceRef, message string) error {
	if tg.isGroup() {
		return &memberError{code: codeNotFound, message: message}
	}
	return &rbac.Error{Code: rbac.CodeNotFound, Message: message, Details: map[string]any{"instance": m.name}}
}

// fanOut runs fn for every member of tg at once, each through s.call, and reports how each went, in member order.
// For an instance target it is s.write: an error that isn't a Pi-hole or member failure (an entry that doesn't exist,
// a cancelled request) fails the request. Through a mirrored group, a *memberError is that member's failure, and
// anything else fails the request once every member has finished. i is the member's index, for per-member state.
func (s *Server) fanOut(ctx context.Context, tg target, fn func(ctx context.Context, i int, m instanceRef, c *piholeapi.Client) error) ([]outcome, error) {
	outs := make([]outcome, len(tg.members))
	errs := make([]error, len(tg.members))
	var wg sync.WaitGroup
	for i, m := range tg.members {
		wg.Go(func() {
			outs[i], errs[i] = s.write(ctx, m, func(ctx context.Context, c *piholeapi.Client) error {
				return fn(ctx, i, m, c)
			})
		})
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return outs, err
		}
	}
	return outs, nil
}

// firstFailure returns the error a read through a mirrored group fails with when no member answered: the first
// member's (the primary's) failure.
func firstFailure(outs []outcome) error {
	for _, o := range outs {
		if !o.ok() {
			return o.err
		}
	}
	return nil
}

// anyOK reports whether at least one member answered.
func anyOK(outs []outcome) bool {
	return slices.ContainsFunc(outs, outcome.ok)
}

// groupWant is the Pi-hole groups a change asks for. For an instance target they are IDs on that instance. Through a
// mirrored group they are the primary's groups, held by name, which each member maps to its own IDs, since Pi-hole
// IDs differ per instance. The Default group is ID 0 on every Pi-hole, so it needs no name.
type groupWant struct {
	ids    []int    // instance target: the IDs as given
	byName bool     // mirrored group: use names
	names  []string // the groups by name; "" is the Default group
}

// wantGroups prepares the Pi-hole groups a change asks for. Through a mirrored group, IDs other than Default are
// looked up on the primary, so a primary that can't be read fails the request before anything is sent; an ID the
// primary doesn't have is a 400.
func (s *Server) wantGroups(ctx context.Context, tg target, ids []int) (groupWant, error) {
	if !tg.isGroup() {
		return groupWant{ids: ids}, nil
	}
	ids = slices.Compact(slices.Sorted(slices.Values(ids)))
	w := groupWant{byName: true, names: []string{}}
	if !slices.ContainsFunc(ids, func(id int) bool { return id != defaultGroupID }) {
		for range ids {
			w.names = append(w.names, "")
		}
		return w, nil
	}
	var groups []piholeapi.Group
	err := s.call(ctx, tg.primary(), func(ctx context.Context, c *piholeapi.Client) error {
		var err error
		groups, err = c.ListGroups(ctx)
		return err
	})
	if err != nil {
		return groupWant{}, err
	}
	if _, err := resolveGroups(ids, groups); err != nil {
		return groupWant{}, err
	}
	for _, id := range ids {
		if id == defaultGroupID {
			w.names = append(w.names, "")
			continue
		}
		i := slices.IndexFunc(groups, func(g piholeapi.Group) bool { return g.ID == id })
		w.names = append(w.names, groups[i].Name)
	}
	return w, nil
}

// on returns the IDs of the wanted groups on member m, given its groups: for an instance target, the IDs checked
// against them; through a mirrored group, the member's own IDs for the names, or a *memberError naming those it
// doesn't have.
func (w groupWant) on(m instanceRef, groups []piholeapi.Group) ([]int, error) {
	if !w.byName {
		return resolveGroups(w.ids, groups)
	}
	ids := []int{}
	var missing []string
	for _, name := range w.names {
		if name == "" {
			ids = append(ids, defaultGroupID)
			continue
		}
		i := slices.IndexFunc(groups, func(g piholeapi.Group) bool { return g.Name == name })
		if i < 0 {
			missing = append(missing, name)
			continue
		}
		ids = append(ids, groups[i].ID)
	}
	if len(missing) > 0 {
		return nil, &memberError{
			code:    codePiholeGroupMissing,
			message: fmt.Sprintf("Pi-hole %q has no group called %s.", m.name, quoted(missing)),
		}
	}
	slices.Sort(ids)
	return slices.Compact(ids), nil
}

// primaryHas checks, before a change through a mirrored group goes anywhere, that the primary has the entry the
// change names: a change to something the group's source of truth doesn't have is a 404. A primary that can't be read
// doesn't stop the change; the other members still get it, and each checks for itself.
func (s *Server) primaryHas(ctx context.Context, tg target, what string, has func(ctx context.Context, c *piholeapi.Client) (bool, error)) error {
	var found bool
	err := s.call(ctx, tg.primary(), func(ctx context.Context, c *piholeapi.Client) error {
		var err error
		found, err = has(ctx, c)
		return err
	})
	var pf *piholeFailure
	switch {
	case errors.As(err, &pf):
		return nil
	case err != nil:
		return err
	case !found:
		p := tg.primary()
		return &rbac.Error{
			Code:    rbac.CodeNotFound,
			Message: fmt.Sprintf("There's no %s on %s, the primary of %s.", what, p.name, tg.group),
			Details: map[string]any{"instance": p.name, "group": tg.group},
		}
	}
	return nil
}

// quoted lists names in quotes, separated by commas.
func quoted(names []string) string {
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = strconv.Quote(n)
	}
	return strings.Join(q, ", ")
}
