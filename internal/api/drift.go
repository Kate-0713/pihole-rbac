// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"errors"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/instances"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
)

var errNoDrift = errors.New("api: no drift checker configured")

// GetGroupDrift answers with a mirrored group's latest drift report, filtered by what the caller may see.
func (s *Server) GetGroupDrift(ctx context.Context, req gen.GetGroupDriftRequestObject) (gen.GetGroupDriftResponseObject, error) {
	g, set, err := s.driftGroup(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	rep, ok := s.Drift.Report(req.Id)
	if !ok {
		return gen.GetGroupDrift200JSONResponse(gen.DriftReport{
			GroupId: g.ID, Group: g.Name, State: gen.DriftReportState("not_checked"),
			Members: []gen.MemberRead{}, Counts: gen.DriftCounts{},
		}), nil
	}
	return gen.GetGroupDrift200JSONResponse(driftJSON(g, rep, set)), nil
}

// CheckGroupDrift checks a mirrored group now and answers with the new report.
func (s *Server) CheckGroupDrift(ctx context.Context, req gen.CheckGroupDriftRequestObject) (gen.CheckGroupDriftResponseObject, error) {
	g, set, err := s.driftGroup(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	rep, err := s.Drift.Check(ctx, req.Id)
	if err != nil {
		if ctx.Err() == nil && rbac.IsCode(err, rbac.CodeNotFound) {
			return nil, err
		}
		if _, getErr := s.Instances.GetGroup(ctx, req.Id); rbac.IsCode(getErr, rbac.CodeNotFound) {
			return nil, getErr // deleted meanwhile
		}
		return nil, err
	}
	return gen.CheckGroupDrift200JSONResponse(driftJSON(g, rep, set)), nil
}

// driftGroup checks drift.view on mirrored group id and returns the group and the caller's permissions. A group that
// doesn't exist, or isn't mirrored, is refused like one the caller holds nothing on.
func (s *Server) driftGroup(ctx context.Context, id int64) (instances.Group, *rbac.Set, error) {
	if s.Instances == nil {
		return instances.Group{}, nil, errNoInstances
	}
	if s.Drift == nil {
		return instances.Group{}, nil, errNoDrift
	}
	t := rbac.GroupTarget(id)
	if err := s.authorize(ctx, rbac.DriftView, t); err != nil {
		return instances.Group{}, nil, err
	}
	set, err := s.permissions(ctx)
	if err != nil {
		return instances.Group{}, nil, err
	}
	g, err := s.Instances.GetGroup(ctx, id)
	if err != nil {
		return instances.Group{}, nil, err
	}
	return g, set, nil
}

// driftJSON reports a drift check. Domain differences are only given to callers who can list the group's domains,
// and client differences to those who can list its clients, so drift.view never reveals entries the caller couldn't
// otherwise see; the counts are always given.
func driftJSON(g instances.Group, rep instances.Report, set *rbac.Set) gen.DriftReport {
	t := rbac.GroupTarget(g.ID)
	at := rep.CheckedAt.UTC()
	out := gen.DriftReport{
		GroupId: g.ID, Group: g.Name, State: gen.DriftReportState("checked"), CheckedAt: &at,
		Drifted: rep.Drifted(), Members: make([]gen.MemberRead, len(rep.Members)),
		Counts: gen.DriftCounts{Domains: len(rep.Domains), Clients: len(rep.Clients), Groups: len(rep.Groups)},
		Groups: &[]gen.PiholeGroupDrift{},
	}
	if !rep.PrimaryOK {
		out.State = gen.DriftReportState("primary_unavailable")
	}
	for i, m := range rep.Members {
		r := gen.MemberRead{Instance: m.Name, InstanceId: m.ID, Primary: m.Primary, Status: gen.WriteStatus("ok")}
		if m.Code != "" {
			r.Status = gen.WriteStatus("failed")
			r.Error = &gen.WriteError{Code: m.Code, Message: describeFailure(&piholeFailure{Instance: m.Name, Err: codeError(m.Code)}).message}
		}
		out.Members[i] = r
	}
	if set.Can(rbac.DomainsView, t) {
		list := make([]gen.DomainDrift, len(rep.Domains))
		for i, d := range rep.Domains {
			list[i] = gen.DomainDrift{
				Instance: d.MemberName, InstanceId: d.Member, Domain: d.Domain, Type: gen.DomainDriftType(d.Type),
				Kind: gen.DomainDriftKind(d.Kind), Difference: gen.DriftDifference(d.Difference),
				Primary: domainState(d.Primary), Member: domainState(d.Other),
			}
		}
		out.Domains = &list
	}
	if set.Can(rbac.ClientsView, t) {
		list := make([]gen.ClientDrift, len(rep.Clients))
		for i, c := range rep.Clients {
			list[i] = gen.ClientDrift{
				Instance: c.MemberName, InstanceId: c.Member, Client: c.Client, Difference: gen.DriftDifference(c.Difference),
				Primary: clientState(c.Primary), Member: clientState(c.Other),
			}
		}
		out.Clients = &list
	}
	for _, gd := range rep.Groups {
		*out.Groups = append(*out.Groups, gen.PiholeGroupDrift{
			Instance: gd.MemberName, InstanceId: gd.Member, Name: gd.Name, Difference: gen.DriftDifference(gd.Difference),
			Primary: groupState(gd.Primary), Member: groupState(gd.Other),
		})
	}
	return out
}

func domainState(s *instances.DomainState) *gen.DriftDomainState {
	if s == nil {
		return nil
	}
	return &gen.DriftDomainState{Comment: s.Comment, Groups: nonNilStrings(s.Groups), Enabled: s.Enabled}
}

func clientState(s *instances.ClientState) *gen.DriftClientState {
	if s == nil {
		return nil
	}
	return &gen.DriftClientState{Comment: s.Comment, Groups: nonNilStrings(s.Groups)}
}

func groupState(s *instances.GroupState) *gen.DriftGroupState {
	if s == nil {
		return nil
	}
	return &gen.DriftGroupState{Comment: s.Comment, Enabled: s.Enabled}
}

func nonNilStrings(ss []string) []string {
	if ss == nil {
		return []string{}
	}
	return ss
}

// codeError stands in for the error behind a member's error code, so its message can be described the same way as
// a write's: a drift report keeps only codes.
func codeError(code string) error {
	switch code {
	case piholeapi.CodeUnreachable:
		return piholeapi.ErrUnreachable
	case piholeapi.CodeAuthRejected:
		return piholeapi.ErrAuthRejected
	case instances.CodePasswordMissing:
		return instances.ErrNoPassword
	case instances.CodeMisconfigured:
		return instances.ErrMisconfigured
	case piholeapi.CodeStatusError:
		return piholeapi.ErrBadResponse
	}
	return errors.New(code) // no code of its own: described as "Something went wrong."
}

// pokeDrift asks for a fresh drift check of the mirrored group a target is, or belongs to, after a write: a write
// that failed on a member, or went to one member alone, makes the group differ.
func (s *Server) pokeDrift(ctx context.Context, tg target) {
	if s.Drift == nil {
		return
	}
	if tg.isGroup() {
		s.Drift.Poke(tg.t.ID)
		return
	}
	if id, _, ok, err := s.Instances.MirroredGroupOf(ctx, tg.t.ID); err == nil && ok {
		s.Drift.Poke(id)
	}
}
