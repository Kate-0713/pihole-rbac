// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"math"
	"slices"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
)

func (s *Server) ListPiholeGroups(ctx context.Context, req gen.ListPiholeGroupsRequestObject) (gen.ListPiholeGroupsResponseObject, error) {
	tg, err := s.resolveTarget(ctx, req.Target, "")
	if err != nil {
		return nil, err
	}
	var list []piholeapi.Group
	err = s.call(ctx, tg.primary(), func(ctx context.Context, c *piholeapi.Client) error {
		var err error
		list, err = c.ListGroups(ctx)
		return err
	})
	if err != nil {
		return nil, err
	}
	out := gen.PiholeGroupList{Groups: make([]gen.PiholeGroup, 0, len(list))}
	for _, g := range list {
		out.Groups = append(out.Groups, gen.PiholeGroup{Id: g.ID, Name: g.Name, Comment: g.Comment, Enabled: g.Enabled})
	}
	return gen.ListPiholeGroups200JSONResponse(out), nil
}

// ListQueries reads one page of the query log, with every filter applied by Pi-hole. An instance, or one member of
// a mirrored group picked with member, is read a page at a time; a group's merged log reads each member from the
// start, merges and cuts the page, no deeper than mergedQueryDepth entries.
func (s *Server) ListQueries(ctx context.Context, req gen.ListQueriesRequestObject) (gen.ListQueriesResponseObject, error) {
	p := req.Params
	f, err := queryFilters{
		from: p.From, until: p.Until, domain: p.Domain, client: p.Client,
		status: asString(p.Status), qtype: asString(p.Type), result: asString(p.Result),
	}.filter()
	if err != nil {
		return nil, err
	}
	page, size, err := queryPaging(p.Page, asInt(p.PageSize))
	if err != nil {
		return nil, err
	}
	var snap querySnapshot
	if p.Snapshot != nil && *p.Snapshot != "" {
		if snap, err = decodeSnapshot(*p.Snapshot); err != nil {
			return nil, invalid("snapshot", "The snapshot isn't one this server gave out. Search again without it.")
		}
	}
	tg, err := s.resolveTarget(ctx, req.Target, rbac.QueryLogView)
	if err != nil {
		return nil, err
	}
	if p.Member != nil {
		if !tg.isGroup() {
			return nil, invalid("member", "A member can only be picked for a mirrored group.")
		}
		i := slices.IndexFunc(tg.members, func(m instanceRef) bool { return m.id == *p.Member })
		if i < 0 {
			return nil, invalid("member", "Instance %d isn't an enabled member of %s.", *p.Member, tg.group)
		}
		tg.members = tg.members[i : i+1]
	}
	merged := tg.isGroup() && p.Member == nil
	f.Start, f.Length = queryWindow(merged, page, size)

	pages := make([]*piholeapi.QueryPage, len(tg.members))
	seen := make([]snapshotMember, len(tg.members))
	outs, err := s.fanOut(ctx, tg, func(ctx context.Context, i int, m instanceRef, c *piholeapi.Client) error {
		var prev *snapshotMember
		if sm, ok := snap[m.id]; ok {
			prev = &sm
		}
		var err error
		pages[i], seen[i], err = readMember(ctx, c.QueryLog, f, prev)
		return err
	})
	if err != nil {
		return nil, err
	}
	if !anyOK(outs) {
		return nil, firstFailure(outs)
	}

	next := querySnapshot{}
	var lists [][]taggedQuery
	var disk []bool
	total := 0
	for i, o := range outs {
		if !o.ok() {
			if sm, ok := snap[o.ref.id]; ok {
				next[o.ref.id] = sm // kept, so the member's later pages match if it comes back
			}
			continue
		}
		next[o.ref.id] = seen[i]
		disk = append(disk, seen[i].Disk)
		total += pages[i].Filtered
		list := make([]taggedQuery, 0, len(pages[i].Queries))
		for _, q := range pages[i].Queries {
			list = append(list, taggedQuery{q, o.ref.name})
		}
		lists = append(lists, list)
	}
	entries := slices.Concat(lists...)
	if merged {
		entries = pageOf(mergeQueries(lists), page, size)
	}
	n, capped := pagesFor(merged, total, size)
	out := gen.QueryLog{
		Queries: make([]gen.QueryLogEntry, 0, len(entries)), Members: memberReads(tg, outs, nil),
		Page: page, PageSize: size, Total: total, Pages: n, Capped: capped,
		Snapshot: next.encode(), Source: gen.QuerySource(sourceOf(disk)),
	}
	for _, t := range entries {
		out.Queries = append(out.Queries, queryJSON(t.q, t.instance))
	}
	return gen.ListQueries200JSONResponse(out), nil
}

func queryJSON(q piholeapi.QueryLogEntry, instance string) gen.QueryLogEntry {
	sec, frac := math.Modf(q.Time)
	out := gen.QueryLogEntry{
		Instance: instance, Time: time.Unix(int64(sec), int64(frac*1e9)).UTC(), Type: q.Type, Domain: q.Domain,
		ClientIp: q.Client.IP, Status: q.Status, ReplyType: q.Reply.Type,
	}
	if q.Client.Name != "" && q.Client.Name != q.Client.IP {
		name := q.Client.Name
		out.ClientName = &name
	}
	if q.Reply.Time >= 0 && q.Reply.Type != "" {
		ms := q.Reply.Time * 1000
		out.ReplyTimeMs = &ms
	}
	if q.Upstream != "" {
		up := q.Upstream
		out.Upstream = &up
	}
	if q.DNSSEC != "" {
		d := q.DNSSEC
		out.Dnssec = &d
	}
	return out
}
