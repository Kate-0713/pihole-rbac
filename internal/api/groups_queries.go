// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"math"
	"strings"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
)

func (s *Server) ListPiholeGroups(ctx context.Context, req gen.ListPiholeGroupsRequestObject) (gen.ListPiholeGroupsResponseObject, error) {
	ref, err := s.resolveTarget(ctx, req.Target, "")
	if err != nil {
		return nil, err
	}
	var list []piholeapi.Group
	err = s.call(ctx, ref, func(ctx context.Context, c *piholeapi.Client) error {
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

// defaultQueryLength is how many query log entries are read when the request doesn't say.
const defaultQueryLength = 100

// ListQueries reads the newest entries and filters them here, as v1 did, so the filters only ever look at what was
// read.
func (s *Server) ListQueries(ctx context.Context, req gen.ListQueriesRequestObject) (gen.ListQueriesResponseObject, error) {
	length := defaultQueryLength
	if req.Params.Length != nil {
		length = *req.Params.Length
		if length < 1 || length > 1000 {
			return nil, invalid("length", "The length must be between 1 and 1000.")
		}
	}
	var domainFilter, clientFilter string
	if req.Params.Domain != nil {
		if err := checkText("domain filter", *req.Params.Domain, maxFilterRunes); err != nil {
			return nil, err
		}
		domainFilter = strings.ToLower(strings.TrimSpace(*req.Params.Domain))
	}
	if req.Params.Client != nil {
		if err := checkText("client filter", *req.Params.Client, maxFilterRunes); err != nil {
			return nil, err
		}
		clientFilter = strings.ToLower(strings.TrimSpace(*req.Params.Client))
	}
	ref, err := s.resolveTarget(ctx, req.Target, rbac.QueryLogView)
	if err != nil {
		return nil, err
	}
	var list []piholeapi.QueryLogEntry
	err = s.call(ctx, ref, func(ctx context.Context, c *piholeapi.Client) error {
		var err error
		list, err = c.ListQueries(ctx, length)
		return err
	})
	if err != nil {
		return nil, err
	}
	out := gen.QueryLog{Queries: make([]gen.QueryLogEntry, 0, len(list))}
	for _, q := range list {
		if domainFilter != "" && !strings.Contains(strings.ToLower(q.Domain), domainFilter) {
			continue
		}
		if clientFilter != "" && !strings.Contains(strings.ToLower(q.Client.IP), clientFilter) &&
			!strings.Contains(strings.ToLower(q.Client.Name), clientFilter) {
			continue
		}
		out.Queries = append(out.Queries, queryJSON(q))
	}
	return gen.ListQueries200JSONResponse(out), nil
}

func queryJSON(q piholeapi.QueryLogEntry) gen.QueryLogEntry {
	sec, frac := math.Modf(q.Time)
	out := gen.QueryLogEntry{
		Time: time.Unix(int64(sec), int64(frac*1e9)).UTC(), Type: q.Type, Domain: q.Domain,
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
