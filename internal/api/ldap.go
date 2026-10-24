// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/auth"
	"github.com/Kate-0713/pihole-rbac/internal/loginsettings"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
	"github.com/Kate-0713/pihole-rbac/internal/store"
)

var errNoLogin = errors.New("api: no login settings service configured")

// ldapReason says in a few words why an LDAP server couldn't be used; the full error goes in details.detail.
func ldapReason(err error) string {
	switch {
	case ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials):
		return "it refused the bind DN or password."
	case ldap.IsErrorWithCode(err, ldap.ErrorNetwork):
		return "it couldn't be reached."
	case strings.Contains(err.Error(), "no LDAP bind password"):
		return "no bind password is set."
	}
	return "see the detail below."
}

func (s *Server) GetLoginMethods(context.Context, gen.GetLoginMethodsRequestObject) (gen.GetLoginMethodsResponseObject, error) {
	if s.LoginSettings == nil {
		return nil, errNoLogin
	}
	return gen.GetLoginMethods200JSONResponse(methodsJSON(s.LoginSettings.Methods())), nil
}

func (s *Server) SetLoginMethods(ctx context.Context, req gen.SetLoginMethodsRequestObject) (gen.SetLoginMethodsResponseObject, error) {
	if s.LoginSettings == nil {
		return nil, errNoLogin
	}
	if len(req.Body.Methods) > len(auth.AllMethods()) {
		return nil, invalid("methods", "There are only %d login methods.", len(auth.AllMethods()))
	}
	methods := make([]auth.Method, len(req.Body.Methods))
	for i, m := range req.Body.Methods {
		methods[i] = auth.Method(m)
	}
	if err := s.LoginSettings.SaveMethods(ctx, actor(ctx), methods); err != nil {
		return nil, err
	}
	return gen.SetLoginMethods200JSONResponse(methodsJSON(s.LoginSettings.Methods())), nil
}

func methodsJSON(ms []auth.Method) gen.LoginMethods {
	out := gen.LoginMethods{Methods: make([]gen.LoginMethodsMethods, len(ms))}
	for i, m := range ms {
		out.Methods[i] = gen.LoginMethodsMethods(m)
	}
	return out
}

func (s *Server) GetLDAPSettings(context.Context, gen.GetLDAPSettingsRequestObject) (gen.GetLDAPSettingsResponseObject, error) {
	if s.LoginSettings == nil {
		return nil, errNoLogin
	}
	return gen.GetLDAPSettings200JSONResponse(ldapViewJSON(s.LoginSettings.LDAP())), nil
}

func (s *Server) SetLDAPSettings(ctx context.Context, req gen.SetLDAPSettingsRequestObject) (gen.SetLDAPSettingsResponseObject, error) {
	if s.LoginSettings == nil {
		return nil, errNoLogin
	}
	b := req.Body
	in := loginsettings.LDAPInput{Settings: auth.LDAPSettings{
		URL: b.Url, BindDN: b.BindDn, BaseDN: b.BaseDn, UserFilter: b.UserFilter,
	}}
	if b.TlsMode != nil {
		in.Settings.TLSMode = string(*b.TlsMode)
	}
	if b.AllowCnFallback != nil {
		in.Settings.AllowCNFallback = *b.AllowCnFallback
	}
	if b.BindPassword != nil {
		if *b.BindPassword == "" {
			return nil, invalid("bind_password", "Leave the bind password out to keep the current one.")
		}
		v := secrets.NewValue([]byte(*b.BindPassword))
		in.BindPassword = &v
	}
	if err := s.LoginSettings.SaveLDAP(ctx, actor(ctx), in); err != nil {
		return nil, err
	}
	return gen.SetLDAPSettings200JSONResponse(ldapViewJSON(s.LoginSettings.LDAP())), nil
}

func ldapViewJSON(v loginsettings.LDAPView) gen.LDAPSettingsView {
	out := gen.LDAPSettingsView{
		Enabled: v.Enabled, CanStorePassword: v.CanStorePassword, CaFileSet: v.CAFileSet,
		BindPassword: gen.LDAPBindPasswordStatus{
			Source: gen.LDAPBindPasswordStatusSource(v.PasswordSource), Variable: secrets.VarLDAPBindPassword,
		},
	}
	if v.Settings != nil {
		ls := v.Settings
		out.Settings = &gen.LDAPConnection{
			Url: ls.URL, BindDn: ls.BindDN, BaseDn: ls.BaseDN, UserFilter: ls.UserFilter,
			TlsMode: gen.LDAPConnectionTlsMode(ls.TLSMode), AllowCnFallback: ls.AllowCNFallback,
		}
		if out.Settings.TlsMode == "" {
			out.Settings.TlsMode = gen.LDAPConnectionTlsMode(auth.LDAPTLSVerify)
		}
		at, by := v.UpdatedAt, v.UpdatedBy
		out.UpdatedAt, out.UpdatedBy = &at, &by
	}
	if v.PasswordSource == loginsettings.SourceStored {
		at, by := v.PasswordUpdated, v.PasswordBy
		out.BindPassword.UpdatedAt, out.BindPassword.UpdatedBy = &at, &by
	}
	return out
}

// TestLDAPUser looks a user up in the directory and works out what logging in would give them, as login does: the
// mappings their groups match, the roles, and the permissions.
func (s *Server) TestLDAPUser(ctx context.Context, req gen.TestLDAPUserRequestObject) (gen.TestLDAPUserResponseObject, error) {
	if s.LoginSettings == nil {
		return nil, errNoLogin
	}
	username := auth.NormalizeUsername(req.Body.Username)
	if username == "" || len(username) > 256 {
		return nil, invalid("username", "Enter a username.")
	}
	out := gen.LDAPUserTest{
		Username: username, Groups: []string{}, Mappings: []gen.LDAPMatchedMapping{}, Roles: []gen.RoleRef{},
		Permissions: gen.TestedPermissions{Global: []string{}, Targets: []gen.TargetPermissions{}},
	}
	q := s.Store.Read()
	if u, err := q.GetUserByUsername(ctx, username); err == nil {
		out.LocalAccount = auth.Method(u.Source) == auth.MethodLocal
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	id, found, err := s.LoginSettings.LookupUser(ctx, username)
	if err != nil {
		return nil, err
	}
	if !found {
		return gen.TestLDAPUser200JSONResponse(out), nil
	}
	out.Found, out.Dn, out.Groups = true, &id.DN, id.Groups

	norm, _ := auth.NormalizeDNs(id.Groups)
	mappings, err := q.ListAllLDAPMappings(ctx)
	if err != nil {
		return nil, err
	}
	roles, err := q.ListRoles(ctx)
	if err != nil {
		return nil, err
	}
	names := map[int64]string{}
	for _, r := range roles {
		names[r.ID] = r.Name
	}
	var roleIDs []int64
	for _, m := range mappings {
		if slices.Contains(norm, m.GroupDnNorm) {
			out.Mappings = append(out.Mappings, gen.LDAPMatchedMapping{GroupDn: m.GroupDn, Role: gen.RoleRef{Id: m.RoleID, Name: names[m.RoleID]}})
			if !slices.Contains(roleIDs, m.RoleID) {
				roleIDs = append(roleIDs, m.RoleID)
			}
		}
	}
	for _, r := range roles { // sorted by name
		if slices.Contains(roleIDs, r.ID) {
			out.Roles = append(out.Roles, gen.RoleRef{Id: r.ID, Name: r.Name})
		}
	}
	set, err := rbac.Resolve(ctx, q, roleIDs)
	if err != nil {
		return nil, err
	}
	for _, p := range set.Global() {
		out.Permissions.Global = append(out.Permissions.Global, string(p))
	}
	targetNames, err := s.targetNames(ctx)
	if err != nil {
		return nil, err
	}
	for t, ps := range set.ByTarget() {
		tp := gen.TargetPermissions{Target: t.String(), Name: targetNames[t.String()], Permissions: make([]string, len(ps))}
		for i, p := range ps {
			tp.Permissions[i] = string(p)
		}
		out.Permissions.Targets = append(out.Permissions.Targets, tp)
	}
	slices.SortFunc(out.Permissions.Targets, func(a, b gen.TargetPermissions) int { return strings.Compare(a.Name, b.Name) })
	return gen.TestLDAPUser200JSONResponse(out), nil
}

// targetNames maps i-<id> and g-<id> to the instance's or group's name.
func (s *Server) targetNames(ctx context.Context) (map[string]string, error) {
	q := s.Store.Read()
	out := map[string]string{}
	insts, err := q.ListInstances(ctx)
	if err != nil {
		return nil, err
	}
	for _, i := range insts {
		out[rbac.InstanceTarget(i.ID).String()] = i.Name
	}
	groups, err := q.ListInstanceGroups(ctx)
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		out[rbac.GroupTarget(g.ID).String()] = g.Name
	}
	return out, nil
}

func (s *Server) CheckLDAPGroup(ctx context.Context, req gen.CheckLDAPGroupRequestObject) (gen.CheckLDAPGroupResponseObject, error) {
	if s.LoginSettings == nil {
		return nil, errNoLogin
	}
	c, err := s.LoginSettings.CheckGroup(ctx, actor(ctx), req.Body.GroupDn)
	if err != nil {
		return nil, err
	}
	return gen.CheckLDAPGroup200JSONResponse{Exists: c.Exists, Members: c.Members}, nil
}

func (s *Server) ListLDAPMappings(ctx context.Context, req gen.ListLDAPMappingsRequestObject) (gen.ListLDAPMappingsResponseObject, error) {
	q := s.Store.Read()
	if _, err := rbac.GetRoleDetails(ctx, q, req.Id); err != nil {
		return nil, err
	}
	rows, err := q.ListLDAPMappingsForRole(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	out := gen.LDAPMappingList{Mappings: make([]gen.LDAPMapping, len(rows))}
	for i, m := range rows {
		out.Mappings[i] = gen.LDAPMapping{Id: m.ID, RoleId: m.RoleID, GroupDn: m.GroupDn, CreatedAt: store.FromMillis(m.CreatedAt)}
	}
	return gen.ListLDAPMappings200JSONResponse(out), nil
}

// AddLDAPMapping saves a mapping, then looks the group up, so the page can warn about a DN the directory doesn't have.
// The lookup never stops the save: a mapping can be made before its group exists.
func (s *Server) AddLDAPMapping(ctx context.Context, req gen.AddLDAPMappingRequestObject) (gen.AddLDAPMappingResponseObject, error) {
	if s.Roles == nil {
		return nil, errNoRoles
	}
	id, err := s.Roles.AddLDAPMapping(ctx, actor(ctx), req.Id, req.Body.GroupDn)
	if err != nil {
		return nil, err
	}
	m, err := s.Store.Read().GetLDAPMapping(ctx, id)
	if err != nil {
		return nil, err
	}
	out := gen.LDAPMappingCreated{Mapping: gen.LDAPMapping{Id: m.ID, RoleId: m.RoleID, GroupDn: m.GroupDn, CreatedAt: store.FromMillis(m.CreatedAt)}}
	if s.LoginSettings != nil {
		c, err := s.LoginSettings.CheckGroup(ctx, actor(ctx), m.GroupDn)
		var de *loginsettings.DirectoryError
		switch {
		case err == nil:
			out.Check = &gen.LDAPGroupCheck{Exists: c.Exists, Members: c.Members}
		case errors.As(err, &de):
			msg := "The LDAP server couldn't be asked about the group: " + ldapReason(de.Err)
			out.CheckError = &msg
		default:
			if e, ok := rbac.AsError(err); ok {
				out.CheckError = &e.Message
			} else {
				return nil, err
			}
		}
	}
	return gen.AddLDAPMapping201JSONResponse(out), nil
}

func (s *Server) RemoveLDAPMapping(ctx context.Context, req gen.RemoveLDAPMappingRequestObject) (gen.RemoveLDAPMappingResponseObject, error) {
	if s.Roles == nil {
		return nil, errNoRoles
	}
	// The path names the role too, so a mapping ID from another role is not found rather than removed.
	m, err := s.Store.Read().GetLDAPMapping(ctx, req.MappingId)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && m.RoleID != req.Id) {
		return nil, &rbac.Error{Code: rbac.CodeNotFound, Message: "That role has no such LDAP mapping.",
			Details: map[string]any{"mapping_id": req.MappingId}}
	}
	if err != nil {
		return nil, err
	}
	if err := s.Roles.RemoveLDAPMapping(ctx, actor(ctx), req.MappingId, confirmed(req.Params.Confirm)); err != nil {
		return nil, err
	}
	return gen.RemoveLDAPMapping204Response{}, nil
}
