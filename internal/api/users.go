// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/store"
)

// maxRoleIDs caps the roles in one request. The spec says so too, but the generated decoder doesn't enforce it.
const maxRoleIDs = 1000

func (s *Server) ListUsers(ctx context.Context, _ gen.ListUsersRequestObject) (gen.ListUsersResponseObject, error) {
	set, err := s.permissions(ctx)
	if err != nil {
		return nil, err
	}
	users, err := rbac.ListUsers(ctx, s.Store.Read())
	if err != nil {
		return nil, err
	}
	out := gen.UserList{Users: make([]gen.User, len(users))}
	for i, u := range users {
		out.Users[i] = userJSON(u, set)
	}
	return gen.ListUsers200JSONResponse(out), nil
}

func (s *Server) GetUser(ctx context.Context, req gen.GetUserRequestObject) (gen.GetUserResponseObject, error) {
	u, err := s.userJSON(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return gen.GetUser200JSONResponse(u), nil
}

func (s *Server) CreateUser(ctx context.Context, req gen.CreateUserRequestObject) (gen.CreateUserResponseObject, error) {
	if s.Roles == nil {
		return nil, errNoRoles
	}
	if err := checkRoleIDs(req.Body.RoleIds); err != nil {
		return nil, err
	}
	id, err := s.Roles.CreateLocalUser(ctx, actor(ctx), req.Body.Username, req.Body.Password, req.Body.RoleIds)
	if err != nil {
		return nil, err
	}
	u, err := s.userJSON(ctx, id)
	if err != nil {
		return nil, err
	}
	return gen.CreateUser201JSONResponse(u), nil
}

func (s *Server) DeleteUser(ctx context.Context, req gen.DeleteUserRequestObject) (gen.DeleteUserResponseObject, error) {
	if s.Roles == nil {
		return nil, errNoRoles
	}
	if err := s.Roles.DeleteUser(ctx, actor(ctx), req.Id, confirmed(req.Params.Confirm)); err != nil {
		return nil, err
	}
	s.clearCookieIfSelf(ctx, req.Id)
	return gen.DeleteUser204Response{}, nil
}

func (s *Server) EnableUser(ctx context.Context, req gen.EnableUserRequestObject) (gen.EnableUserResponseObject, error) {
	if s.Roles == nil {
		return nil, errNoRoles
	}
	if err := s.Roles.SetUserDisabled(ctx, actor(ctx), req.Id, false, false); err != nil {
		return nil, err
	}
	u, err := s.userJSON(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return gen.EnableUser200JSONResponse(u), nil
}

func (s *Server) DisableUser(ctx context.Context, req gen.DisableUserRequestObject) (gen.DisableUserResponseObject, error) {
	if s.Roles == nil {
		return nil, errNoRoles
	}
	if err := s.Roles.SetUserDisabled(ctx, actor(ctx), req.Id, true, confirmed(req.Params.Confirm)); err != nil {
		return nil, err
	}
	s.clearCookieIfSelf(ctx, req.Id)
	u, err := s.userJSON(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return gen.DisableUser200JSONResponse(u), nil
}

func (s *Server) SetUserPassword(ctx context.Context, req gen.SetUserPasswordRequestObject) (gen.SetUserPasswordResponseObject, error) {
	if s.Roles == nil {
		return nil, errNoRoles
	}
	if err := s.Roles.SetUserPassword(ctx, actor(ctx), req.Id, req.Body.Password); err != nil {
		return nil, err
	}
	return gen.SetUserPassword204Response{}, nil
}

func (s *Server) SetUserRoles(ctx context.Context, req gen.SetUserRolesRequestObject) (gen.SetUserRolesResponseObject, error) {
	if s.Roles == nil {
		return nil, errNoRoles
	}
	if err := checkRoleIDs(req.Body.RoleIds); err != nil {
		return nil, err
	}
	if err := s.Roles.SetUserRoles(ctx, actor(ctx), req.Id, req.Body.RoleIds, confirmed(req.Params.Confirm)); err != nil {
		return nil, err
	}
	u, err := s.userJSON(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return gen.SetUserRoles200JSONResponse(u), nil
}

// clearCookieIfSelf clears the session cookie after the caller disabled or deleted their own account, whose sessions
// have just ended, so the browser doesn't keep sending a cookie that no longer works.
func (s *Server) clearCookieIfSelf(ctx context.Context, userID int64) {
	ri := info(ctx)
	if ri.sess != nil && ri.sess.UserID == userID {
		s.Sessions.ClearCookie(ri.w, ri.r)
	}
}

func checkRoleIDs(ids []int64) error {
	if len(ids) > maxRoleIDs {
		return invalid("role_ids", "A user can have at most %d roles.", maxRoleIDs)
	}
	for _, id := range ids {
		if id < 1 {
			return invalid("role_ids", "A role ID is a positive number.")
		}
	}
	return nil
}

// userJSON reads one user for a response, with whether the caller may manage them.
func (s *Server) userJSON(ctx context.Context, id int64) (gen.User, error) {
	set, err := s.permissions(ctx)
	if err != nil {
		return gen.User{}, err
	}
	d, err := rbac.GetUserDetails(ctx, s.Store.Read(), id)
	if err != nil {
		return gen.User{}, err
	}
	return userJSON(d, set), nil
}

func userJSON(d rbac.UserDetails, caller *rbac.Set) gen.User {
	u := d.User
	out := gen.User{
		Id: u.ID, Username: u.Username, Source: gen.UserSource(u.Source), Disabled: u.Disabled,
		CreatedAt: store.FromMillis(u.CreatedAt), Roles: make([]gen.RoleRef, len(d.Roles)),
		Manageable: len(caller.Missing(d.Grants)) == 0,
	}
	if u.LdapDn.Valid {
		dn := u.LdapDn.String
		out.LdapDn = &dn
	}
	if u.LastLoginAt.Valid {
		t := store.FromMillis(u.LastLoginAt.Int64)
		out.LastLoginAt = &t
	}
	for i, r := range d.Roles {
		out.Roles[i] = gen.RoleRef{Id: r.ID, Name: r.Name}
	}
	return out
}
