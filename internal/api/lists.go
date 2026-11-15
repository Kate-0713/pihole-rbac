// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/instances"
	"github.com/Kate-0713/pihole-rbac/internal/lists"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
)

// Subscribed lists (adlists). A list is named by its address and type: the same address can be both a blocklist and
// an allowlist. An address with a user name or password in it (a list added in Pi-hole's own admin) is never shown
// or audited as it is: the API shows lists.Redacted, and a request may name the list by that form. Lists are mirrored
// like domains, matched by address and type, but their download status isn't: it differs per member, so a list read
// through a mirrored group carries every member's.

// listsOf is what one instance has: its lists, and when gravity last finished there (Unix seconds, 0 if never).
type listsOf struct {
	lists      []piholeapi.ListEntry
	lastUpdate int64
}

func readLists(ctx context.Context, c *piholeapi.Client) (listsOf, error) {
	var out listsOf
	var err error
	if out.lists, err = c.ListLists(ctx); err != nil {
		return out, err
	}
	sum, err := c.GetLiveSummary(ctx)
	if err != nil {
		return out, err
	}
	out.lastUpdate = sum.Gravity.LastUpdate
	return out, nil
}

// needsGravity: an enabled list changed since the instance's last gravity run (see the architecture document: a
// list's date_updated only moves when its content changed, so it can't be used).
func needsGravity(l piholeapi.ListEntry, lastUpdate int64) bool {
	return l.Enabled && l.DateModified > lastUpdate
}

func (s *Server) ListLists(ctx context.Context, req gen.ListListsRequestObject) (gen.ListListsResponseObject, error) {
	tg, err := s.resolveTarget(ctx, req.Target, rbac.ListsView)
	if err != nil {
		return nil, err
	}
	if !tg.isGroup() {
		var got listsOf
		err := s.call(ctx, tg.primary(), func(ctx context.Context, c *piholeapi.Client) error {
			var err error
			got, err = readLists(ctx, c)
			return err
		})
		if err != nil {
			return nil, err
		}
		out := gen.PiholeListList{Lists: make([]gen.PiholeList, 0, len(got.lists)), GravityLastUpdate: unixTime(got.lastUpdate)}
		for _, l := range got.lists {
			out.Lists = append(out.Lists, listJSON(l, needsGravity(l, got.lastUpdate)))
		}
		return gen.ListLists200JSONResponse(out), nil
	}

	// A mirrored group: every member is read, since status isn't mirrored. The settings are the primary's, and a
	// primary that can't be read fails the request, as for other reads through a group.
	n := len(tg.members)
	reads, outs := make([]listsOf, n), make([]outcome, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i, m := range tg.members {
		wg.Go(func() {
			outs[i], errs[i] = s.write(ctx, m, func(ctx context.Context, c *piholeapi.Client) error {
				var err error
				reads[i], err = readLists(ctx, c)
				return err
			})
		})
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	if !outs[0].ok() {
		return nil, outs[0].err
	}
	primary := reads[0]
	out := gen.PiholeListList{
		Lists: make([]gen.PiholeList, 0, len(primary.lists)), GravityLastUpdate: unixTime(primary.lastUpdate),
		Members: memberReads(tg, outs, nil),
	}
	if rep, ok := s.driftReport(tg); ok && rep.PrimaryOK {
		drifted := rep.ListsDrifted()
		out.Drifted = &drifted
	}
	for _, pl := range primary.lists {
		j := listJSON(pl, false)
		members := make([]gen.PiholeListMemberStatus, n)
		for i, m := range tg.members {
			ms := gen.PiholeListMemberStatus{Instance: m.name, InstanceId: m.id, Primary: m.primary}
			k := slices.IndexFunc(reads[i].lists, func(l piholeapi.ListEntry) bool { return l.Address == pl.Address && l.Type == pl.Type })
			switch {
			case !outs[i].ok():
				ms.State = gen.PiholeListMemberStatusState("unreadable")
			case k < 0:
				ms.State = gen.PiholeListMemberStatusState("missing")
			default:
				ml := reads[i].lists[k]
				st, domains, invalid := listStatus(ml.Status), ml.Number, ml.InvalidDomains
				needs := needsGravity(ml, reads[i].lastUpdate)
				ms.State = gen.PiholeListMemberStatusState("ok")
				ms.Status, ms.Domains, ms.InvalidDomains, ms.UpdatedAt, ms.NeedsGravity = &st, &domains, &invalid, unixTime(ml.DateUpdated), &needs
				j.NeedsGravity = j.NeedsGravity || needs
			}
			members[i] = ms
		}
		j.Members = &members
		out.Lists = append(out.Lists, j)
	}
	return gen.ListLists200JSONResponse(out), nil
}

func (s *Server) AddList(ctx context.Context, req gen.AddListRequestObject) (gen.AddListResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, invalid("body", "The request body is missing.")
	}
	entry := piholeapi.ListEntry{Address: strings.TrimSpace(b.Address), Type: string(b.Type), Enabled: true}
	if !piholeapi.ValidListType(entry.Type) {
		return nil, invalid("type", `The type must be "block" or "allow".`)
	}
	if err := lists.CheckAddress(entry.Address, s.allowFileLists()); err != nil {
		return nil, addressRefused(err)
	}
	if b.Comment != nil {
		if err := checkText("comment", *b.Comment, maxCommentRunes); err != nil {
			return nil, err
		}
		entry.Comment = *b.Comment
	}
	if b.Enabled != nil {
		entry.Enabled = *b.Enabled
	}
	wanted := []int{defaultGroupID}
	if b.Groups != nil {
		if err := checkGroupIDs(*b.Groups); err != nil {
			return nil, err
		}
		wanted = *b.Groups
	}
	tg, err := s.resolveTarget(ctx, req.Target, rbac.ListsEdit)
	if err != nil {
		return nil, err
	}
	if tg, err = tg.only(req.Params.Members); err != nil {
		return nil, err
	}
	want, err := s.wantGroups(ctx, tg, wanted)
	if err != nil {
		return nil, err
	}

	n := len(tg.members)
	saved, names, attempted := make([]piholeapi.ListEntry, n), make([][]string, n), make([]bool, n)
	outs, err := s.fanOut(ctx, tg, func(ctx context.Context, i int, m instanceRef, c *piholeapi.Client) error {
		attempted[i] = false
		groups, err := c.ListGroups(ctx)
		if err != nil {
			return err
		}
		e := entry
		if e.Groups, err = want.on(m, groups); err != nil {
			return err
		}
		names[i] = groupNames(e.Groups, groups)
		attempted[i] = true
		saved[i], err = c.AddList(ctx, e)
		return err
	})
	for i, m := range tg.members {
		if attempted[i] {
			s.auditPihole(ctx, m, audit.ActionListAdd, outs[i].callErr, map[string]any{
				"address": lists.Redacted(entry.Address), "type": entry.Type, "comment": entry.Comment,
				"groups": names[i], "enabled": entry.Enabled,
			})
		}
	}
	s.pokeDrift(ctx, tg)
	if err != nil {
		return nil, err
	}
	results := listResults(outs, saved, func(i int) bool { return saved[i].Enabled })
	multi, err := s.finishWrite(ctx, outs, results)
	if err != nil {
		return nil, err
	}
	if multi {
		return gen.AddList207JSONResponse{Results: results}, nil
	}
	return gen.AddList200JSONResponse{Results: results}, nil
}

// UpdateList reads the list first: Pi-hole's PUT would create a list that doesn't exist, enable a disabled one and
// clear its comment unless told otherwise. The change is merged into the list as read, and a change that changes
// nothing isn't sent or audited. Through a mirrored group, the primary must have the list, and each member merges the
// change into its own copy.
func (s *Server) UpdateList(ctx context.Context, req gen.UpdateListRequestObject) (gen.UpdateListResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, invalid("body", "The request body is missing.")
	}
	key, err := checkListKey(b.Address, string(b.Type))
	if err != nil {
		return nil, err
	}
	if b.Comment == nil && b.Groups == nil && b.Enabled == nil {
		return nil, invalid("body", "Give a comment, groups or enabled to change.")
	}
	if b.Comment != nil {
		if err := checkText("comment", *b.Comment, maxCommentRunes); err != nil {
			return nil, err
		}
	}
	if b.Groups != nil {
		if err := checkGroupIDs(*b.Groups); err != nil {
			return nil, err
		}
	}
	tg, err := s.resolveTarget(ctx, req.Target, rbac.ListsEdit)
	if err != nil {
		return nil, err
	}
	if tg, err = tg.only(req.Params.Members); err != nil {
		return nil, err
	}
	var want groupWant
	if b.Groups != nil {
		if want, err = s.wantGroups(ctx, tg, *b.Groups); err != nil {
			return nil, err
		}
	}
	if tg.isGroup() {
		if err := s.primaryHas(ctx, tg, listWhat(key), func(ctx context.Context, c *piholeapi.Client) (bool, error) {
			_, found, err := lookupList(ctx, c, key)
			return found, err
		}); err != nil {
			return nil, err
		}
	}

	n := len(tg.members)
	saved, details, attempted := make([]piholeapi.ListEntry, n), make([]map[string]any, n), make([]bool, n)
	reenabled := make([]bool, n)
	outs, err := s.fanOut(ctx, tg, func(ctx context.Context, i int, m instanceRef, c *piholeapi.Client) error {
		attempted[i] = false
		cur, groups, err := findList(ctx, c, tg, m, key)
		if err != nil {
			return err
		}
		after := cur
		after.Groups = sortedIDs(cur.Groups)
		if b.Groups != nil {
			if after.Groups, err = want.on(m, groups); err != nil {
				return err
			}
		}
		if b.Comment != nil {
			after.Comment = *b.Comment
		}
		if b.Enabled != nil {
			after.Enabled = *b.Enabled
		}
		if after.Comment == cur.Comment && after.Enabled == cur.Enabled && slices.Equal(after.Groups, sortedIDs(cur.Groups)) {
			saved[i] = cur
			return nil
		}
		reenabled[i] = after.Enabled && !cur.Enabled
		details[i] = map[string]any{
			"address": lists.Redacted(cur.Address), "type": cur.Type,
			"groups_before": groupNames(cur.Groups, groups), "groups_after": groupNames(after.Groups, groups),
			"comment_changed": after.Comment != cur.Comment,
			"enabled_before":  cur.Enabled, "enabled_after": after.Enabled,
		}
		attempted[i] = true
		saved[i], err = c.UpdateList(ctx, after)
		return err
	})
	for i, m := range tg.members {
		if attempted[i] {
			s.auditPihole(ctx, m, audit.ActionListUpdate, outs[i].callErr, details[i])
		}
	}
	s.pokeDrift(ctx, tg)
	if err != nil {
		return nil, err
	}
	results := listResults(outs, saved, func(i int) bool { return reenabled[i] })
	multi, err := s.finishWrite(ctx, outs, results)
	if err != nil {
		return nil, err
	}
	if multi {
		return gen.UpdateList207JSONResponse{Results: results}, nil
	}
	return gen.UpdateList200JSONResponse{Results: results}, nil
}

// DeleteList reads the list first, so a delete of something that isn't there is a 404 and the audit row can say
// what was removed. Through a mirrored group, the primary must have the list; a member that doesn't is already as
// asked, so its result is ok and nothing is sent to it or audited.
func (s *Server) DeleteList(ctx context.Context, req gen.DeleteListRequestObject) (gen.DeleteListResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, invalid("body", "The request body is missing.")
	}
	key, err := checkListKey(b.Address, string(b.Type))
	if err != nil {
		return nil, err
	}
	tg, err := s.resolveTarget(ctx, req.Target, rbac.ListsEdit)
	if err != nil {
		return nil, err
	}
	if tg, err = tg.only(req.Params.Members); err != nil {
		return nil, err
	}
	if tg.isGroup() {
		if err := s.primaryHas(ctx, tg, listWhat(key), func(ctx context.Context, c *piholeapi.Client) (bool, error) {
			_, found, err := lookupList(ctx, c, key)
			return found, err
		}); err != nil {
			return nil, err
		}
	}

	n := len(tg.members)
	details, attempted := make([]map[string]any, n), make([]bool, n)
	outs, err := s.fanOut(ctx, tg, func(ctx context.Context, i int, m instanceRef, c *piholeapi.Client) error {
		attempted[i] = false
		cur, groups, err := findList(ctx, c, tg, m, key)
		var me *memberError
		if errors.As(err, &me) && me.code == codeNotFound {
			return nil // already gone from this member
		}
		if err != nil {
			return err
		}
		details[i] = map[string]any{
			"address": lists.Redacted(cur.Address), "type": cur.Type, "comment": cur.Comment,
			"groups": groupNames(cur.Groups, groups), "enabled": cur.Enabled,
		}
		attempted[i] = true
		return c.DeleteList(ctx, cur.Address, cur.Type)
	})
	for i, m := range tg.members {
		if attempted[i] {
			s.auditPihole(ctx, m, audit.ActionListDelete, outs[i].callErr, details[i])
		}
	}
	s.pokeDrift(ctx, tg)
	if err != nil {
		return nil, err
	}
	results := resultsOf(outs, func(_ int, o outcome, st gen.WriteStatus, we *gen.WriteError) gen.DeleteResult {
		return gen.DeleteResult{Instance: o.ref.name, InstanceId: o.ref.id, Status: st, Error: we}
	})
	multi, err := s.finishWrite(ctx, outs, results)
	if err != nil {
		return nil, err
	}
	if multi {
		return gen.DeleteList207JSONResponse{Results: results}, nil
	}
	return gen.DeleteList200JSONResponse{Results: results}, nil
}

// driftReport is the latest drift report of the mirrored group tg is, if there is one.
func (s *Server) driftReport(tg target) (instances.Report, bool) {
	if s.Drift == nil || !tg.isGroup() {
		return instances.Report{}, false
	}
	return s.Drift.Report(tg.t.ID)
}

// allowFileLists is the general setting, off when there are no settings (in tests).
func (s *Server) allowFileLists() bool {
	return s.LoginSettings != nil && s.LoginSettings.AllowFileLists()
}

// addressRefused reports an address lists.CheckAddress refused, as a validation error on the address.
func addressRefused(err error) error {
	var ae *lists.AddressError
	if !errors.As(err, &ae) {
		return err
	}
	e := invalid("address", "%s", ae.Message+".")
	e.Details["reason"] = ae.Reason
	return e
}

// checkListKey checks the fields that name an existing list. The address isn't held to the rules for new lists (an
// existing list may have any address Pi-hole accepted), only kept to text of a sane length.
func checkListKey(address, listType string) (piholeapi.ListEntry, error) {
	if !piholeapi.ValidListType(listType) {
		return piholeapi.ListEntry{}, invalid("type", `The type must be "block" or "allow".`)
	}
	if address == "" {
		return piholeapi.ListEntry{}, invalid("address", "The address can't be empty.")
	}
	if len(address) > lists.MaxAddressLength {
		return piholeapi.ListEntry{}, invalid("address", "The address is longer than %d bytes.", lists.MaxAddressLength)
	}
	if err := checkText("address", address, lists.MaxAddressLength); err != nil {
		return piholeapi.ListEntry{}, err
	}
	return piholeapi.ListEntry{Address: address, Type: listType}, nil
}

func listWhat(key piholeapi.ListEntry) string {
	return fmt.Sprintf("%s list %q", key.Type, lists.Redacted(key.Address))
}

// lookupList reads the lists and returns the one key names: by its address exactly, or by the address as the API
// shows it (redacted). Two lists that both match only when redacted are a conflict, since the request can't say which.
func lookupList(ctx context.Context, c *piholeapi.Client, key piholeapi.ListEntry) (piholeapi.ListEntry, bool, error) {
	all, err := c.ListLists(ctx)
	if err != nil {
		return piholeapi.ListEntry{}, false, err
	}
	var matches []piholeapi.ListEntry
	for _, l := range all {
		if l.Type != key.Type {
			continue
		}
		if l.Address == key.Address {
			return l, true, nil
		}
		if lists.Redacted(l.Address) == key.Address {
			matches = append(matches, l)
		}
	}
	switch len(matches) {
	case 0:
		return piholeapi.ListEntry{}, false, nil
	case 1:
		return matches[0], true, nil
	}
	return piholeapi.ListEntry{}, false, &rbac.Error{
		Code:    rbac.CodeConflict,
		Message: "More than one list has that address once its user name or password is hidden. Change or delete them in Pi-hole's own admin.",
		Details: map[string]any{"field": "address"},
	}
}

// findList reads member m's lists and groups, and returns the list key names, or tg.missing.
func findList(ctx context.Context, c *piholeapi.Client, tg target, m instanceRef, key piholeapi.ListEntry) (piholeapi.ListEntry, []piholeapi.Group, error) {
	l, found, err := lookupList(ctx, c, key)
	if err != nil {
		return piholeapi.ListEntry{}, nil, err
	}
	if !found {
		return piholeapi.ListEntry{}, nil, tg.missing(m, "There's no "+listWhat(key)+" on "+m.name+".")
	}
	groups, err := c.ListGroups(ctx)
	if err != nil {
		return piholeapi.ListEntry{}, nil, err
	}
	return l, groups, nil
}

// listResults builds a list write's results; needs says, for an ok result, whether the list waits for gravity (added
// enabled, or enabled again).
func listResults(outs []outcome, saved []piholeapi.ListEntry, needs func(i int) bool) []gen.PiholeListWriteResult {
	return resultsOf(outs, func(i int, o outcome, st gen.WriteStatus, we *gen.WriteError) gen.PiholeListWriteResult {
		r := gen.PiholeListWriteResult{Instance: o.ref.name, InstanceId: o.ref.id, Status: st, Error: we}
		if o.ok() {
			l := listJSON(saved[i], needs(i))
			r.Entry = &l
		}
		return r
	})
}

func listStatus(code int) gen.PiholeListStatus {
	switch code {
	case piholeapi.ListStatusUpdated:
		return "updated"
	case piholeapi.ListStatusUnchanged:
		return "unchanged"
	case piholeapi.ListStatusCached:
		return "cached"
	case piholeapi.ListStatusFailed:
		return "failed"
	}
	return "never"
}

func listJSON(l piholeapi.ListEntry, needs bool) gen.PiholeList {
	marks := []gen.PiholeListMarks{}
	for _, m := range lists.Marks(l.Address) {
		marks = append(marks, gen.PiholeListMarks(m))
	}
	return gen.PiholeList{
		Address: lists.Redacted(l.Address), Type: gen.PiholeListType(l.Type), Comment: l.Comment,
		Groups: nonNilInts(l.Groups), Enabled: l.Enabled, Status: listStatus(l.Status),
		Domains: l.Number, InvalidDomains: l.InvalidDomains, NeedsGravity: needs, Marks: marks,
		AddedAt: unixTime(l.DateAdded), ModifiedAt: unixTime(l.DateModified), UpdatedAt: unixTime(l.DateUpdated),
	}
}
