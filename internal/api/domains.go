// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
)

// defaultGroupID is Pi-hole's Default group, which always exists. New entries go there unless the request says
// otherwise, as in Pi-hole's own interface.
const defaultGroupID = 0

func (s *Server) ListDomains(ctx context.Context, req gen.ListDomainsRequestObject) (gen.ListDomainsResponseObject, error) {
	tg, err := s.resolveTarget(ctx, req.Target, rbac.DomainsView)
	if err != nil {
		return nil, err
	}
	var list []piholeapi.DomainEntry
	err = s.call(ctx, tg.primary(), func(ctx context.Context, c *piholeapi.Client) error {
		var err error
		list, err = c.ListDomains(ctx)
		return err
	})
	if err != nil {
		return nil, err
	}
	out := gen.DomainList{Domains: make([]gen.Domain, 0, len(list))}
	for _, d := range list {
		out.Domains = append(out.Domains, domainJSON(d))
	}
	return gen.ListDomains200JSONResponse(out), nil
}

func (s *Server) AddDomain(ctx context.Context, req gen.AddDomainRequestObject) (gen.AddDomainResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, invalid("body", "The request body is missing.")
	}
	entry := piholeapi.DomainEntry{Domain: strings.TrimSpace(b.Domain), Type: string(b.Type), Kind: string(b.Kind)}
	if err := checkDomainKey(entry.Domain, entry.Type, entry.Kind); err != nil {
		return nil, err
	}
	if b.Comment != nil {
		if err := checkText("comment", *b.Comment, maxCommentRunes); err != nil {
			return nil, err
		}
		entry.Comment = *b.Comment
	}
	wanted := []int{defaultGroupID}
	if b.Groups != nil {
		if err := checkGroupIDs(*b.Groups); err != nil {
			return nil, err
		}
		wanted = *b.Groups
	}
	tg, err := s.resolveTarget(ctx, req.Target, rbac.DomainsEdit)
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
	saved, names, attempted := make([]piholeapi.DomainEntry, n), make([][]string, n), make([]bool, n)
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
		saved[i], err = c.AddDomain(ctx, e)
		return err
	})
	for i, m := range tg.members {
		if attempted[i] {
			s.auditPihole(ctx, m, audit.ActionDomainAdd, outs[i].callErr, map[string]any{
				"domain": entry.Domain, "type": entry.Type, "kind": entry.Kind, "comment": entry.Comment, "groups": names[i],
			})
		}
	}
	if err != nil {
		return nil, err
	}
	results := resultsOf(outs, func(i int, o outcome, st gen.WriteStatus, we *gen.WriteError) gen.DomainWriteResult {
		r := gen.DomainWriteResult{Instance: o.ref.name, InstanceId: o.ref.id, Status: st, Error: we}
		if o.ok() {
			d := domainJSON(saved[i])
			r.Entry = &d
		}
		return r
	})
	multi, err := s.finishWrite(ctx, outs, results)
	if err != nil {
		return nil, err
	}
	if multi {
		return gen.AddDomain207JSONResponse{Results: results}, nil
	}
	return gen.AddDomain200JSONResponse{Results: results}, nil
}

// UpdateDomain reads the entry first: Pi-hole's PUT would create an entry that doesn't exist, and would enable a
// disabled one unless told otherwise. The change is merged into the entry as read, so fields the request leaves out,
// and the enabled flag, keep their value. A change that changes nothing isn't sent or audited. Through a mirrored
// group, the primary must have the entry, and each member merges the change into its own copy.
func (s *Server) UpdateDomain(ctx context.Context, req gen.UpdateDomainRequestObject) (gen.UpdateDomainResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, invalid("body", "The request body is missing.")
	}
	key := piholeapi.DomainEntry{Domain: b.Domain, Type: string(b.Type), Kind: string(b.Kind)}
	if err := checkDomainKey(key.Domain, key.Type, key.Kind); err != nil {
		return nil, err
	}
	if b.Comment == nil && b.Groups == nil {
		return nil, invalid("body", "Give a comment or groups to change.")
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
	tg, err := s.resolveTarget(ctx, req.Target, rbac.DomainsEdit)
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
		if err := s.primaryHas(ctx, tg, domainWhat(key), func(ctx context.Context, c *piholeapi.Client) (bool, error) {
			_, found, err := lookupDomain(ctx, c, key)
			return found, err
		}); err != nil {
			return nil, err
		}
	}

	n := len(tg.members)
	saved, details, attempted := make([]piholeapi.DomainEntry, n), make([]map[string]any, n), make([]bool, n)
	outs, err := s.fanOut(ctx, tg, func(ctx context.Context, i int, m instanceRef, c *piholeapi.Client) error {
		attempted[i] = false
		cur, groups, err := findDomain(ctx, c, tg, m, key)
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
		if after.Comment == cur.Comment && slices.Equal(after.Groups, sortedIDs(cur.Groups)) {
			saved[i] = cur
			return nil
		}
		details[i] = map[string]any{
			"domain": key.Domain, "type": key.Type, "kind": key.Kind,
			"groups_before": groupNames(cur.Groups, groups), "groups_after": groupNames(after.Groups, groups),
			"comment_changed": after.Comment != cur.Comment,
		}
		attempted[i] = true
		saved[i], err = c.UpdateDomain(ctx, after)
		return err
	})
	for i, m := range tg.members {
		if attempted[i] {
			s.auditPihole(ctx, m, audit.ActionDomainUpdate, outs[i].callErr, details[i])
		}
	}
	if err != nil {
		return nil, err
	}
	results := resultsOf(outs, func(i int, o outcome, st gen.WriteStatus, we *gen.WriteError) gen.DomainWriteResult {
		r := gen.DomainWriteResult{Instance: o.ref.name, InstanceId: o.ref.id, Status: st, Error: we}
		if o.ok() {
			d := domainJSON(saved[i])
			r.Entry = &d
		}
		return r
	})
	multi, err := s.finishWrite(ctx, outs, results)
	if err != nil {
		return nil, err
	}
	if multi {
		return gen.UpdateDomain207JSONResponse{Results: results}, nil
	}
	return gen.UpdateDomain200JSONResponse{Results: results}, nil
}

// DeleteDomain reads the entry first, so a delete of something that isn't there is a 404 and the audit row can say
// what was removed. Through a mirrored group, the primary must have the entry; a member that doesn't is already as
// asked, so its result is ok and nothing is sent to it or audited.
func (s *Server) DeleteDomain(ctx context.Context, req gen.DeleteDomainRequestObject) (gen.DeleteDomainResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, invalid("body", "The request body is missing.")
	}
	key := piholeapi.DomainEntry{Domain: b.Domain, Type: string(b.Type), Kind: string(b.Kind)}
	if err := checkDomainKey(key.Domain, key.Type, key.Kind); err != nil {
		return nil, err
	}
	tg, err := s.resolveTarget(ctx, req.Target, rbac.DomainsEdit)
	if err != nil {
		return nil, err
	}
	if tg, err = tg.only(req.Params.Members); err != nil {
		return nil, err
	}
	if tg.isGroup() {
		if err := s.primaryHas(ctx, tg, domainWhat(key), func(ctx context.Context, c *piholeapi.Client) (bool, error) {
			_, found, err := lookupDomain(ctx, c, key)
			return found, err
		}); err != nil {
			return nil, err
		}
	}

	n := len(tg.members)
	details, attempted := make([]map[string]any, n), make([]bool, n)
	outs, err := s.fanOut(ctx, tg, func(ctx context.Context, i int, m instanceRef, c *piholeapi.Client) error {
		attempted[i] = false
		cur, groups, err := findDomain(ctx, c, tg, m, key)
		var me *memberError
		if errors.As(err, &me) && me.code == codeNotFound {
			return nil // already gone from this member
		}
		if err != nil {
			return err
		}
		details[i] = map[string]any{
			"domain": key.Domain, "type": key.Type, "kind": key.Kind, "comment": cur.Comment,
			"groups": groupNames(cur.Groups, groups), "enabled": cur.Enabled,
		}
		attempted[i] = true
		return c.DeleteDomain(ctx, key.Domain, key.Type, key.Kind)
	})
	for i, m := range tg.members {
		if attempted[i] {
			s.auditPihole(ctx, m, audit.ActionDomainDelete, outs[i].callErr, details[i])
		}
	}
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
		return gen.DeleteDomain207JSONResponse{Results: results}, nil
	}
	return gen.DeleteDomain200JSONResponse{Results: results}, nil
}

func domainWhat(key piholeapi.DomainEntry) string {
	return key.Kind + " entry for that domain on the " + key.Type + " list"
}

// lookupDomain reads the lists and returns the entry key names exactly, if there is one.
func lookupDomain(ctx context.Context, c *piholeapi.Client, key piholeapi.DomainEntry) (piholeapi.DomainEntry, bool, error) {
	list, err := c.ListDomains(ctx)
	if err != nil {
		return piholeapi.DomainEntry{}, false, err
	}
	i := slices.IndexFunc(list, func(d piholeapi.DomainEntry) bool {
		return d.Domain == key.Domain && d.Type == key.Type && d.Kind == key.Kind
	})
	if i < 0 {
		return piholeapi.DomainEntry{}, false, nil
	}
	return list[i], true, nil
}

// findDomain reads member m's lists and groups, and returns the entry key names exactly, or tg.missing.
func findDomain(ctx context.Context, c *piholeapi.Client, tg target, m instanceRef, key piholeapi.DomainEntry) (piholeapi.DomainEntry, []piholeapi.Group, error) {
	entry, found, err := lookupDomain(ctx, c, key)
	if err != nil {
		return piholeapi.DomainEntry{}, nil, err
	}
	if !found {
		return piholeapi.DomainEntry{}, nil, tg.missing(m, "There's no "+domainWhat(key)+" of "+m.name+".")
	}
	groups, err := c.ListGroups(ctx)
	if err != nil {
		return piholeapi.DomainEntry{}, nil, err
	}
	return entry, groups, nil
}

func domainJSON(d piholeapi.DomainEntry) gen.Domain {
	return gen.Domain{
		Domain: d.Domain, Type: gen.DomainType(d.Type), Kind: gen.DomainKind(d.Kind), Comment: d.Comment,
		Groups: nonNilInts(d.Groups), Enabled: d.Enabled,
		AddedAt: unixTime(d.DateAdded), ModifiedAt: unixTime(d.DateModified),
	}
}

// unixTime converts Pi-hole's Unix seconds, or returns nil when Pi-hole didn't report a time.
func unixTime(secs int64) *time.Time {
	if secs <= 0 {
		return nil
	}
	t := time.Unix(secs, 0).UTC()
	return &t
}
