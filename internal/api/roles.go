// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"errors"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/store"
)

var errNoRoles = errors.New("api: no role manager configured")

// maxGrants caps the grants in one request. The spec says so too, but the generated decoder doesn't enforce it.
const maxGrants = 1000

func (s *Server) ListRoles(ctx context.Context, _ gen.ListRolesRequestObject) (gen.ListRolesResponseObject, error) {
	set, err := s.permissions(ctx)
	if err != nil {
		return nil, err
	}
	roles, err := rbac.ListRoles(ctx, s.Store.Read())
	if err != nil {
		return nil, err
	}
	out := gen.RoleList{Roles: make([]gen.Role, len(roles))}
	for i, r := range roles {
		out.Roles[i] = roleJSON(r, set)
	}
	return gen.ListRoles200JSONResponse(out), nil
}

func (s *Server) GetRole(ctx context.Context, req gen.GetRoleRequestObject) (gen.GetRoleResponseObject, error) {
	role, err := s.roleJSON(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return gen.GetRole200JSONResponse(role), nil
}

func (s *Server) CreateRole(ctx context.Context, req gen.CreateRoleRequestObject) (gen.CreateRoleResponseObject, error) {
	if s.Roles == nil {
		return nil, errNoRoles
	}
	var grants []gen.Grant
	if req.Body.Grants != nil {
		grants = *req.Body.Grants
	}
	gs, err := grantsFromJSON(grants)
	if err != nil {
		return nil, err
	}
	id, err := s.Roles.CreateRole(ctx, actor(ctx), roleInput(req.Body.Name, req.Body.Description), gs)
	if err != nil {
		return nil, err
	}
	role, err := s.roleJSON(ctx, id)
	if err != nil {
		return nil, err
	}
	return gen.CreateRole201JSONResponse(role), nil
}

func (s *Server) UpdateRole(ctx context.Context, req gen.UpdateRoleRequestObject) (gen.UpdateRoleResponseObject, error) {
	if s.Roles == nil {
		return nil, errNoRoles
	}
	if err := s.Roles.UpdateRole(ctx, actor(ctx), req.Id, roleInput(req.Body.Name, req.Body.Description)); err != nil {
		return nil, err
	}
	role, err := s.roleJSON(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return gen.UpdateRole200JSONResponse(role), nil
}

func (s *Server) DeleteRole(ctx context.Context, req gen.DeleteRoleRequestObject) (gen.DeleteRoleResponseObject, error) {
	if s.Roles == nil {
		return nil, errNoRoles
	}
	if err := s.Roles.DeleteRole(ctx, actor(ctx), req.Id); err != nil {
		return nil, err
	}
	return gen.DeleteRole204Response{}, nil
}

func (s *Server) SetRoleGrants(ctx context.Context, req gen.SetRoleGrantsRequestObject) (gen.SetRoleGrantsResponseObject, error) {
	if s.Roles == nil {
		return nil, errNoRoles
	}
	gs, err := grantsFromJSON(req.Body.Grants)
	if err != nil {
		return nil, err
	}
	if err := s.Roles.SetRoleGrants(ctx, actor(ctx), req.Id, gs, confirmed(req.Params.Confirm)); err != nil {
		return nil, err
	}
	role, err := s.roleJSON(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return gen.SetRoleGrants200JSONResponse(role), nil
}

// GetRoleCatalogue lists what a grant can name: the permissions with their classes, and every instance and group.
func (s *Server) GetRoleCatalogue(ctx context.Context, _ gen.GetRoleCatalogueRequestObject) (gen.GetRoleCatalogueResponseObject, error) {
	q := s.Store.Read()
	out := gen.RoleCatalogue{
		Permissions: []gen.PermissionInfo{}, Instances: []gen.ScopeName{}, Groups: []gen.GroupScopeName{},
	}
	for _, p := range rbac.Catalogue() {
		out.Permissions = append(out.Permissions, gen.PermissionInfo{
			Name: string(p.Name), Class: gen.PermissionInfoClass(p.Class.String()), Description: p.Description,
		})
	}
	insts, err := q.ListInstances(ctx)
	if err != nil {
		return nil, err
	}
	for _, i := range insts {
		out.Instances = append(out.Instances, gen.ScopeName{Id: i.ID, Name: i.Name})
	}
	groups, err := q.ListInstanceGroups(ctx)
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		out.Groups = append(out.Groups, gen.GroupScopeName{Id: g.ID, Name: g.Name, Mode: gen.GroupScopeNameMode(g.Mode)})
	}
	return gen.GetRoleCatalogue200JSONResponse(out), nil
}

// roleJSON reads one role for a response, with whether the caller holds all its grants.
func (s *Server) roleJSON(ctx context.Context, id int64) (gen.Role, error) {
	set, err := s.permissions(ctx)
	if err != nil {
		return gen.Role{}, err
	}
	d, err := rbac.GetRoleDetails(ctx, s.Store.Read(), id)
	if err != nil {
		return gen.Role{}, err
	}
	return roleJSON(d, set), nil
}

func roleJSON(d rbac.RoleDetails, caller *rbac.Set) gen.Role {
	out := gen.Role{
		Id: d.Role.ID, Name: d.Role.Name, Description: d.Role.Description, Builtin: d.Role.Builtin,
		CreatedAt: store.FromMillis(d.Role.CreatedAt), Grants: make([]gen.Grant, len(d.Grants)),
		Users: d.Users, LdapGroups: d.LDAPGroups, Manageable: len(caller.Missing(d.Grants)) == 0,
	}
	for i, g := range d.Grants {
		out.Grants[i] = gen.Grant{Permission: string(g.Permission), Scope: gen.GrantScope(g.Scope.Type)}
		if g.Scope.Type != rbac.ScopeAll {
			id := g.Scope.ID
			out.Grants[i].Id = &id
		}
	}
	return out
}

func roleInput(name string, description *string) rbac.RoleInput {
	in := rbac.RoleInput{Name: name}
	if description != nil {
		in.Description = *description
	}
	return in
}

// grantsFromJSON turns request grants into rbac grants. It checks the shape (a known scope, an id exactly when the
// scope needs one); the rbac layer checks the rest inside its transaction: that the permission exists, that the scope
// suits it and that the instance or group exists.
func grantsFromJSON(in []gen.Grant) ([]rbac.Grant, error) {
	if len(in) > maxGrants {
		return nil, invalid("grants", "A role can have at most %d grants.", maxGrants)
	}
	out := make([]rbac.Grant, len(in))
	for i, g := range in {
		if !g.Scope.Valid() {
			return nil, invalid("grants", "A grant's scope is all, group or instance.")
		}
		out[i] = rbac.Grant{Permission: rbac.Permission(g.Permission), Scope: rbac.Scope{Type: rbac.ScopeType(g.Scope)}}
		switch {
		case g.Scope == gen.GrantScopeAll && g.Id != nil:
			return nil, invalid("grants", "A grant at scope all has no id.")
		case g.Scope != gen.GrantScopeAll && (g.Id == nil || *g.Id < 1):
			return nil, invalid("grants", "A grant at scope %s needs the id of the %s.", g.Scope, g.Scope)
		case g.Id != nil:
			out[i].Scope.ID = *g.Id
		}
	}
	return out, nil
}

// confirmed reads the optional confirm query parameter.
func confirmed(c *gen.Confirm) bool { return c != nil && *c }
