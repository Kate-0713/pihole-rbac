// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"cmp"
	"context"
	"errors"
	"slices"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/instances"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
)

const maxReconcileItems = 1000

// codeNotReconcilable is an item reconcile won't change: a Pi-hole group only a member has.
const codeNotReconcilable = "not_reconcilable"

// ReconcileGroup makes a mirrored group's members match its primary (see instances.Drift.Reconcile), audits what was
// done on each member, checks the group for drift again, and answers with every item's result and the new report.
func (s *Server) ReconcileGroup(ctx context.Context, req gen.ReconcileGroupRequestObject) (gen.ReconcileGroupResponseObject, error) {
	if s.Instances == nil {
		return nil, errNoInstances
	}
	if s.Drift == nil {
		return nil, errNoDrift
	}
	b := req.Body
	if b == nil {
		return nil, invalid("body", "The request body is missing.")
	}
	t := rbac.GroupTarget(req.Id)
	if err := s.authorize(ctx, rbac.DriftReconcile, t); err != nil {
		return nil, err
	}
	g, err := s.Instances.GetGroup(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	sel, err := s.selection(b, g)
	if err != nil {
		return nil, err
	}

	res, err := s.Drift.Reconcile(ctx, req.Id, sel)
	var pe *instances.PrimaryError
	switch {
	case errors.As(err, &pe):
		return nil, &piholeFailure{Instance: pe.Name, Err: pe.Err, PrimaryOf: g.Name}
	case errors.Is(err, instances.ErrPrimaryUnavailable):
		return nil, &rbac.Error{Code: rbac.CodeConflict, Message: g.Name + " can't be reconciled: its primary instance is disabled."}
	case err != nil:
		return nil, err
	}

	// One audit row per member asked, with what was done there.
	for _, m := range res.Members {
		ref := instanceRef{target: t, id: m.ID, name: m.Name, group: g.Name}
		detail := map[string]any{}
		var rowErr error
		if m.Code != "" {
			rowErr = codeError(m.Code)
		}
		lists := map[string][]string{}
		for _, it := range res.Items {
			if it.Member != m.ID {
				continue
			}
			key := string(it.Kind) + " " + itemKey(it)
			switch {
			case it.Err != nil:
				lists["failed"] = append(lists["failed"], key)
				rowErr = cmp.Or(rowErr, it.Err)
			case it.Action == instances.ActionNone:
				lists["unchanged"] = append(lists["unchanged"], key)
			default:
				lists[string(it.Action)] = append(lists[string(it.Action)], key)
			}
		}
		for k, v := range lists {
			detail[k] = v
		}
		s.auditPihole(ctx, ref, audit.ActionGroupReconcile, rowErr, detail)
	}

	// The report after the change; if the check fails, the last one is still accurate about what it says.
	rep, checkErr := s.Drift.Check(ctx, req.Id)
	if checkErr != nil {
		rep, _ = s.Drift.Report(req.Id)
	}
	set, err := s.permissions(ctx)
	if err != nil {
		return nil, err
	}
	out := gen.ReconcileResult{
		Results: make([]gen.ReconcileItemResult, len(res.Items)),
		Members: make([]gen.MemberRead, len(res.Members)),
		Report:  driftJSON(g, rep, set),
	}
	if checkErr != nil && rep.CheckedAt.IsZero() {
		out.Report = gen.DriftReport{GroupId: g.ID, Group: g.Name, State: gen.DriftReportState("not_checked"), Members: []gen.MemberRead{}}
	}
	partial := false
	for i, m := range res.Members {
		r := gen.MemberRead{Instance: m.Name, InstanceId: m.ID, Status: gen.WriteStatus("ok")}
		if m.Code != "" {
			partial = true
			r.Status = gen.WriteStatus("failed")
			r.Error = &gen.WriteError{Code: m.Code, Message: describeFailure(&piholeFailure{Instance: m.Name, Err: codeError(m.Code)}).message}
		}
		out.Members[i] = r
	}
	for i, it := range res.Items {
		r := gen.ReconcileItemResult{
			Instance: it.MemberName, InstanceId: it.Member, Item: gen.ReconcileItemResultItem(it.Kind),
			Action: gen.ReconcileItemResultAction(it.Action), Status: gen.ReconcileItemResultStatus("ok"),
		}
		switch it.Kind {
		case instances.ItemDomain:
			d, ty, k := it.Domain.Domain, gen.ReconcileItemResultType(it.Domain.Type), gen.ReconcileItemResultKind(it.Domain.Kind)
			r.Domain, r.Type, r.Kind = &d, &ty, &k
		case instances.ItemClient:
			c := it.Client
			r.Client = &c
		case instances.ItemGroup:
			gn := it.Group
			r.Group = &gn
		}
		if it.Err != nil {
			partial = true
			r.Status = gen.ReconcileItemResultStatus("failed")
			r.Error = reconcileError(it)
		}
		out.Results[i] = r
	}
	if partial {
		return gen.ReconcileGroup207JSONResponse(out), nil
	}
	return gen.ReconcileGroup200JSONResponse(out), nil
}

// selection checks a reconcile request: all, or at least one item, each naming an enabled member that isn't the
// primary, with a valid entry key.
func (s *Server) selection(b *gen.ReconcileInput, g instances.Group) (instances.Selection, error) {
	var sel instances.Selection
	all := b.All != nil && *b.All
	n := 0
	if b.Domains != nil {
		n += len(*b.Domains)
	}
	if b.Clients != nil {
		n += len(*b.Clients)
	}
	if b.Groups != nil {
		n += len(*b.Groups)
	}
	switch {
	case all && n > 0:
		return sel, invalid("all", "Give all, or the items to reconcile, not both.")
	case all:
		sel.All = true
		return sel, nil
	case n == 0:
		return sel, invalid("all", "Give all, or at least one item to reconcile.")
	case n > maxReconcileItems:
		return sel, invalid("domains", "At most %d items can be reconciled at once.", maxReconcileItems)
	}
	member := func(field string, id int64) error {
		if id == g.Primary {
			return invalid(field, "The primary is the group's source of truth; it is never changed by a reconcile.")
		}
		if _, ok := s.Instances.Pool.Name(id); !ok || !slices.Contains(g.Members, id) {
			return invalid(field, "Instance %d isn't an enabled member of %s.", id, g.Name)
		}
		return nil
	}
	if b.Domains != nil {
		for _, d := range *b.Domains {
			if err := member("domains", d.InstanceId); err != nil {
				return sel, err
			}
			if err := checkDomainKey(d.Domain, string(d.Type), string(d.Kind)); err != nil {
				return sel, err
			}
			sel.Domains = append(sel.Domains, instances.DomainKey{Member: d.InstanceId, Domain: d.Domain, Type: string(d.Type), Kind: string(d.Kind)})
		}
	}
	if b.Clients != nil {
		for _, c := range *b.Clients {
			if err := member("clients", c.InstanceId); err != nil {
				return sel, err
			}
			if c.Client == "" || len(c.Client) > maxClientIDBytes {
				return sel, invalid("clients", "A client is 1 to %d bytes.", maxClientIDBytes)
			}
			sel.Clients = append(sel.Clients, instances.ClientKey{Member: c.InstanceId, Client: c.Client})
		}
	}
	if b.Groups != nil {
		for _, gr := range *b.Groups {
			if err := member("groups", gr.InstanceId); err != nil {
				return sel, err
			}
			if err := checkText("groups", gr.Name, maxCommentRunes); err != nil || gr.Name == "" {
				return sel, invalid("groups", "A Pi-hole group name is 1 to %d characters.", maxCommentRunes)
			}
			sel.Groups = append(sel.Groups, instances.GroupKey{Member: gr.InstanceId, Name: gr.Name})
		}
	}
	return sel, nil
}

func itemKey(it instances.ReconcileItem) string {
	switch it.Kind {
	case instances.ItemDomain:
		return it.Domain.Domain + " (" + it.Domain.Type + ", " + it.Domain.Kind + ")"
	case instances.ItemClient:
		return it.Client
	}
	return it.Group
}

// reconcileError describes an item that failed, as a write's per-instance error is described.
func reconcileError(it instances.ReconcileItem) *gen.WriteError {
	if errors.Is(it.Err, instances.ErrNotReconcilable) {
		return &gen.WriteError{Code: codeNotReconcilable, Message: "Pi-hole groups only a member has aren't deleted: entries or clients outside the group may use them."}
	}
	f := describeFailure(&piholeFailure{Instance: it.MemberName, Err: it.Err})
	we := &gen.WriteError{Code: f.code, Message: f.message}
	if f.piholeMessage != "" {
		pm := f.piholeMessage
		we.PiholeMessage = &pm
	}
	if f.internal && errors.Is(it.Err, piholeapi.ErrInvalidArgument) {
		we.Message = "The primary's settings couldn't be copied to " + it.MemberName + "."
	}
	return we
}
