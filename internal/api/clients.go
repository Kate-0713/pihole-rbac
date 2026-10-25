// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"slices"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
)

func (s *Server) ListClients(ctx context.Context, req gen.ListClientsRequestObject) (gen.ListClientsResponseObject, error) {
	tg, err := s.resolveTarget(ctx, req.Target, rbac.ClientsView)
	if err != nil {
		return nil, err
	}
	var list []piholeapi.ClientEntry
	err = s.call(ctx, tg.primary(), func(ctx context.Context, c *piholeapi.Client) error {
		var err error
		list, err = c.ListClients(ctx)
		return err
	})
	if err != nil {
		return nil, err
	}
	out := gen.ClientList{Clients: make([]gen.PiholeClient, 0, len(list))}
	for _, ce := range list {
		out.Clients = append(out.Clients, clientJSON(ce))
	}
	return gen.ListClients200JSONResponse(out), nil
}

// UpdateClient reads the client first: Pi-hole's PUT would create a client that doesn't exist, which clients.edit
// doesn't allow. Fields the request leaves out keep their value; a change that changes nothing isn't sent or
// audited. Through a mirrored group, the primary must have the client, and a member that doesn't fails with
// not_found rather than having it created.
func (s *Server) UpdateClient(ctx context.Context, req gen.UpdateClientRequestObject) (gen.UpdateClientResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, invalid("body", "The request body is missing.")
	}
	if b.Client == "" || len(b.Client) > maxClientIDBytes {
		return nil, invalid("client", "The client must be 1 to %d bytes.", maxClientIDBytes)
	}
	if err := checkText("client", b.Client, maxClientIDBytes); err != nil {
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
	tg, err := s.resolveTarget(ctx, req.Target, rbac.ClientsEdit)
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
		if err := s.primaryHas(ctx, tg, "client "+b.Client, func(ctx context.Context, c *piholeapi.Client) (bool, error) {
			_, found, err := lookupClient(ctx, c, b.Client)
			return found, err
		}); err != nil {
			return nil, err
		}
	}

	n := len(tg.members)
	saved, details, attempted := make([]piholeapi.ClientEntry, n), make([]map[string]any, n), make([]bool, n)
	outs, err := s.fanOut(ctx, tg, func(ctx context.Context, i int, m instanceRef, c *piholeapi.Client) error {
		attempted[i] = false
		cur, found, err := lookupClient(ctx, c, b.Client)
		if err != nil {
			return err
		}
		if !found {
			return tg.missing(m, "There's no client "+b.Client+" on "+m.name+".")
		}
		groups, err := c.ListGroups(ctx)
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
			"client": cur.Client, "comment": after.Comment,
			"groups_before": groupNames(cur.Groups, groups), "groups_after": groupNames(after.Groups, groups),
			"comment_changed": after.Comment != cur.Comment,
		}
		attempted[i] = true
		got, err := c.UpdateClientGroups(ctx, cur.Client, after.Comment, after.Groups)
		saved[i] = after
		if got != nil {
			saved[i] = *got
		}
		return err
	})
	for i, m := range tg.members {
		if attempted[i] {
			s.auditPihole(ctx, m, audit.ActionClientUpdate, outs[i].callErr, details[i])
		}
	}
	if err != nil {
		return nil, err
	}
	results := resultsOf(outs, func(i int, o outcome, st gen.WriteStatus, we *gen.WriteError) gen.ClientWriteResult {
		r := gen.ClientWriteResult{Instance: o.ref.name, InstanceId: o.ref.id, Status: st, Error: we}
		if o.ok() {
			c := clientJSON(saved[i])
			r.Entry = &c
		}
		return r
	})
	multi, err := s.finishWrite(ctx, outs, results)
	if err != nil {
		return nil, err
	}
	if multi {
		return gen.UpdateClient207JSONResponse{Results: results}, nil
	}
	return gen.UpdateClient200JSONResponse{Results: results}, nil
}

// lookupClient reads the clients and returns the one named exactly, if there is one.
func lookupClient(ctx context.Context, c *piholeapi.Client, client string) (piholeapi.ClientEntry, bool, error) {
	list, err := c.ListClients(ctx)
	if err != nil {
		return piholeapi.ClientEntry{}, false, err
	}
	i := slices.IndexFunc(list, func(ce piholeapi.ClientEntry) bool { return ce.Client == client })
	if i < 0 {
		return piholeapi.ClientEntry{}, false, nil
	}
	return list[i], true, nil
}

func clientJSON(ce piholeapi.ClientEntry) gen.PiholeClient {
	out := gen.PiholeClient{
		Client: ce.Client, Comment: ce.Comment, Groups: nonNilInts(ce.Groups),
		AddedAt: unixTime(ce.DateAdded), ModifiedAt: unixTime(ce.DateModified),
	}
	if ce.Name != "" && ce.Name != ce.Client {
		name := ce.Name
		out.Name = &name
	}
	return out
}
