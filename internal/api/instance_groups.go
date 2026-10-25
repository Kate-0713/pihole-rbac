// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"cmp"
	"context"
	"slices"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/instances"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
)

func (s *Server) ListInstanceGroups(ctx context.Context, _ gen.ListInstanceGroupsRequestObject) (gen.ListInstanceGroupsResponseObject, error) {
	if s.Instances == nil {
		return nil, errNoInstances
	}
	groups, err := s.Instances.ListGroups(ctx)
	if err != nil {
		return nil, err
	}
	insts, err := s.instanceIndex(ctx)
	if err != nil {
		return nil, err
	}
	out := gen.InstanceGroupList{Groups: make([]gen.InstanceGroup, len(groups))}
	for i, g := range groups {
		out.Groups[i] = groupJSON(g, insts)
	}
	return gen.ListInstanceGroups200JSONResponse(out), nil
}

func (s *Server) GetInstanceGroup(ctx context.Context, req gen.GetInstanceGroupRequestObject) (gen.GetInstanceGroupResponseObject, error) {
	if s.Instances == nil {
		return nil, errNoInstances
	}
	g, err := s.Instances.GetGroup(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return gen.GetInstanceGroup200JSONResponse(s.groupResponse(ctx, g)), nil
}

func (s *Server) CreateInstanceGroup(ctx context.Context, req gen.CreateInstanceGroupRequestObject) (gen.CreateInstanceGroupResponseObject, error) {
	if s.Instances == nil {
		return nil, errNoInstances
	}
	g, err := s.Instances.CreateGroup(ctx, actor(ctx), groupInput(req.Body))
	if err != nil {
		return nil, err
	}
	s.Drift.Poke(g.ID)
	return gen.CreateInstanceGroup201JSONResponse(s.groupResponse(ctx, g)), nil
}

func (s *Server) UpdateInstanceGroup(ctx context.Context, req gen.UpdateInstanceGroupRequestObject) (gen.UpdateInstanceGroupResponseObject, error) {
	if s.Instances == nil {
		return nil, errNoInstances
	}
	g, err := s.Instances.UpdateGroup(ctx, actor(ctx), req.Id, groupInput(req.Body))
	if err != nil {
		return nil, err
	}
	// The old report may describe other members or the old primary.
	s.Drift.Forget(g.ID)
	s.Drift.Poke(g.ID)
	return gen.UpdateInstanceGroup200JSONResponse(s.groupResponse(ctx, g)), nil
}

func (s *Server) DeleteInstanceGroup(ctx context.Context, req gen.DeleteInstanceGroupRequestObject) (gen.DeleteInstanceGroupResponseObject, error) {
	if s.Instances == nil {
		return nil, errNoInstances
	}
	if err := s.Instances.DeleteGroup(ctx, actor(ctx), req.Id); err != nil {
		return nil, err
	}
	s.Drift.Forget(req.Id)
	return gen.DeleteInstanceGroup204Response{}, nil
}

func groupInput(b *gen.InstanceGroupInput) instances.GroupInput {
	in := instances.GroupInput{Name: b.Name, Mode: rbac.GroupMode(b.Mode), Members: b.Members}
	if b.PrimaryInstanceId != nil {
		in.Primary = *b.PrimaryInstanceId
	}
	return in
}

// instanceIndex returns every instance by ID, for naming group members.
func (s *Server) instanceIndex(ctx context.Context) (map[int64]instances.Instance, error) {
	insts, err := s.Instances.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[int64]instances.Instance, len(insts))
	for _, inst := range insts {
		out[inst.ID] = inst
	}
	return out, nil
}

// groupResponse is groupJSON for a single group, answered after a change has committed. If the instances can't be
// read now, the members are reported by ID alone rather than failing a change that has already been made.
func (s *Server) groupResponse(ctx context.Context, g instances.Group) gen.InstanceGroup {
	insts, err := s.instanceIndex(ctx)
	if err != nil {
		s.Logger.Error("reading instances for a group response", "err", err)
	}
	return groupJSON(g, insts)
}

func groupJSON(g instances.Group, insts map[int64]instances.Instance) gen.InstanceGroup {
	out := gen.InstanceGroup{
		Id: g.ID, Name: g.Name, Mode: gen.InstanceGroupMode(g.Mode), CreatedAt: g.CreatedAt.UTC(),
		Members: make([]gen.InstanceGroupMember, len(g.Members)),
	}
	if g.Primary != 0 {
		p := g.Primary
		out.PrimaryInstanceId = &p
	}
	for i, id := range g.Members {
		inst := insts[id]
		out.Members[i] = gen.InstanceGroupMember{Id: id, Name: inst.Name, Enabled: inst.Enabled}
	}
	slices.SortFunc(out.Members, func(a, b gen.InstanceGroupMember) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Id, b.Id))
	})
	return out
}
