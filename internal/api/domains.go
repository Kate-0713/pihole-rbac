// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
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
	ref, err := s.resolveTarget(ctx, req.Target, rbac.DomainsView)
	if err != nil {
		return nil, err
	}
	var list []piholeapi.DomainEntry
	err = s.call(ctx, ref, func(ctx context.Context, c *piholeapi.Client) error {
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
	ref, err := s.resolveTarget(ctx, req.Target, rbac.DomainsEdit)
	if err != nil {
		return nil, err
	}

	var saved piholeapi.DomainEntry
	var names []string
	var attempted bool
	err = s.call(ctx, ref, func(ctx context.Context, c *piholeapi.Client) error {
		attempted = false
		groups, err := c.ListGroups(ctx)
		if err != nil {
			return err
		}
		if entry.Groups, err = resolveGroups(wanted, groups); err != nil {
			return err
		}
		names = groupNames(entry.Groups, groups)
		attempted = true
		saved, err = c.AddDomain(ctx, entry)
		return err
	})
	if attempted {
		s.auditPihole(ctx, ref, audit.ActionDomainAdd, err, map[string]any{
			"domain": entry.Domain, "type": entry.Type, "kind": entry.Kind, "comment": entry.Comment, "groups": names,
		})
	}
	if err != nil {
		return nil, err
	}
	return gen.AddDomain201JSONResponse(domainJSON(saved)), nil
}

// UpdateDomain reads the entry first: Pi-hole's PUT would create an entry that doesn't exist, and would enable a
// disabled one unless told otherwise. The change is merged into the entry as read, so fields the request leaves out,
// and the enabled flag, keep their value. A change that changes nothing isn't sent or audited.
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
	ref, err := s.resolveTarget(ctx, req.Target, rbac.DomainsEdit)
	if err != nil {
		return nil, err
	}

	var saved piholeapi.DomainEntry
	var detail map[string]any
	var attempted bool
	err = s.call(ctx, ref, func(ctx context.Context, c *piholeapi.Client) error {
		attempted = false
		cur, groups, err := findDomain(ctx, c, ref, key)
		if err != nil {
			return err
		}
		after := cur
		after.Groups = sortedIDs(cur.Groups)
		if b.Groups != nil {
			if after.Groups, err = resolveGroups(*b.Groups, groups); err != nil {
				return err
			}
		}
		if b.Comment != nil {
			after.Comment = *b.Comment
		}
		if after.Comment == cur.Comment && slices.Equal(after.Groups, sortedIDs(cur.Groups)) {
			saved = cur
			return nil
		}
		detail = map[string]any{
			"domain": key.Domain, "type": key.Type, "kind": key.Kind,
			"groups_before": groupNames(cur.Groups, groups), "groups_after": groupNames(after.Groups, groups),
			"comment_changed": after.Comment != cur.Comment,
		}
		attempted = true
		saved, err = c.UpdateDomain(ctx, after)
		return err
	})
	if attempted {
		s.auditPihole(ctx, ref, audit.ActionDomainUpdate, err, detail)
	}
	if err != nil {
		return nil, err
	}
	return gen.UpdateDomain200JSONResponse(domainJSON(saved)), nil
}

// DeleteDomain reads the entry first, so a delete of something that isn't there is a 404 and the audit row can say
// what was removed.
func (s *Server) DeleteDomain(ctx context.Context, req gen.DeleteDomainRequestObject) (gen.DeleteDomainResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, invalid("body", "The request body is missing.")
	}
	key := piholeapi.DomainEntry{Domain: b.Domain, Type: string(b.Type), Kind: string(b.Kind)}
	if err := checkDomainKey(key.Domain, key.Type, key.Kind); err != nil {
		return nil, err
	}
	ref, err := s.resolveTarget(ctx, req.Target, rbac.DomainsEdit)
	if err != nil {
		return nil, err
	}

	var detail map[string]any
	var attempted bool
	err = s.call(ctx, ref, func(ctx context.Context, c *piholeapi.Client) error {
		attempted = false
		cur, groups, err := findDomain(ctx, c, ref, key)
		if err != nil {
			return err
		}
		detail = map[string]any{
			"domain": key.Domain, "type": key.Type, "kind": key.Kind, "comment": cur.Comment,
			"groups": groupNames(cur.Groups, groups), "enabled": cur.Enabled,
		}
		attempted = true
		return c.DeleteDomain(ctx, key.Domain, key.Type, key.Kind)
	})
	if attempted {
		s.auditPihole(ctx, ref, audit.ActionDomainDelete, err, detail)
	}
	if err != nil {
		return nil, err
	}
	return gen.DeleteDomain204Response{}, nil
}

// findDomain reads the lists and the groups, and returns the entry key names exactly, or a 404.
func findDomain(ctx context.Context, c *piholeapi.Client, ref instanceRef, key piholeapi.DomainEntry) (piholeapi.DomainEntry, []piholeapi.Group, error) {
	list, err := c.ListDomains(ctx)
	if err != nil {
		return piholeapi.DomainEntry{}, nil, err
	}
	i := slices.IndexFunc(list, func(d piholeapi.DomainEntry) bool {
		return d.Domain == key.Domain && d.Type == key.Type && d.Kind == key.Kind
	})
	if i < 0 {
		return piholeapi.DomainEntry{}, nil, &rbac.Error{
			Code:    rbac.CodeNotFound,
			Message: "There's no " + key.Kind + " entry for that domain on the " + key.Type + " list of " + ref.name + ".",
			Details: map[string]any{"instance": ref.name},
		}
	}
	groups, err := c.ListGroups(ctx)
	if err != nil {
		return piholeapi.DomainEntry{}, nil, err
	}
	return list[i], groups, nil
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
