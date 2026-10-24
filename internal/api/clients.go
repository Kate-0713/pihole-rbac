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
	ref, err := s.resolveTarget(ctx, req.Target, rbac.ClientsView)
	if err != nil {
		return nil, err
	}
	var list []piholeapi.ClientEntry
	err = s.call(ctx, ref, func(ctx context.Context, c *piholeapi.Client) error {
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
// audited.
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
	ref, err := s.resolveTarget(ctx, req.Target, rbac.ClientsEdit)
	if err != nil {
		return nil, err
	}

	var saved piholeapi.ClientEntry
	var detail map[string]any
	var attempted bool
	o, err := s.write(ctx, ref, func(ctx context.Context, c *piholeapi.Client) error {
		attempted = false
		list, err := c.ListClients(ctx)
		if err != nil {
			return err
		}
		i := slices.IndexFunc(list, func(ce piholeapi.ClientEntry) bool { return ce.Client == b.Client })
		if i < 0 {
			return &rbac.Error{
				Code: rbac.CodeNotFound, Message: "There's no client " + b.Client + " on " + ref.name + ".",
				Details: map[string]any{"instance": ref.name},
			}
		}
		cur := list[i]
		groups, err := c.ListGroups(ctx)
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
			"client": cur.Client, "comment": after.Comment,
			"groups_before": groupNames(cur.Groups, groups), "groups_after": groupNames(after.Groups, groups),
			"comment_changed": after.Comment != cur.Comment,
		}
		attempted = true
		got, err := c.UpdateClientGroups(ctx, cur.Client, after.Comment, after.Groups)
		saved = after
		if got != nil {
			saved = *got
		}
		return err
	})
	if attempted {
		s.auditPihole(ctx, ref, audit.ActionClientUpdate, o.callErr, detail)
	}
	if err != nil {
		return nil, err
	}
	outs := []outcome{o}
	results := resultsOf(outs, func(o outcome, st gen.WriteStatus, we *gen.WriteError) gen.ClientWriteResult {
		r := gen.ClientWriteResult{Instance: o.ref.name, InstanceId: o.ref.id, Status: st, Error: we}
		if o.ok() {
			c := clientJSON(saved)
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
