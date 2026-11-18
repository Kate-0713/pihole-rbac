// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"errors"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/auth"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
	"github.com/Kate-0713/pihole-rbac/internal/totp"
)

// None of these accept an API token: the gate refuses them before they are reached (tokenRoutes), so they use the
// session directly.

// ListMyTokens lists the caller's own tokens.
func (s *Server) ListMyTokens(ctx context.Context, _ gen.ListMyTokensRequestObject) (gen.ListMyTokensResponseObject, error) {
	ts, err := rbac.ListUserTokens(ctx, s.Store.Read(), info(ctx).sess.UserID, s.now(), s.Sessions.RolesValidFor())
	if err != nil {
		return nil, err
	}
	if err := rbac.TokenRefusals(ctx, s.Store.Read(), ts, s.totpSetupRequired); err != nil {
		return nil, err
	}
	return gen.ListMyTokens200JSONResponse(tokenListJSON(ts)), nil
}

// ListTokens lists every user's tokens (sessions.manage, checked by the gate).
func (s *Server) ListTokens(ctx context.Context, _ gen.ListTokensRequestObject) (gen.ListTokensResponseObject, error) {
	ts, err := rbac.ListAllTokens(ctx, s.Store.Read(), s.now(), s.Sessions.RolesValidFor())
	if err != nil {
		return nil, err
	}
	if err := rbac.TokenRefusals(ctx, s.Store.Read(), ts, s.totpSetupRequired); err != nil {
		return nil, err
	}
	return gen.ListTokens200JSONResponse(tokenListJSON(ts)), nil
}

// GetTokenGrantable says what a token of the caller's can hold, for the form that makes one (tokens.use, checked by
// the gate). Only the instances and groups it names are listed by name.
func (s *Server) GetTokenGrantable(ctx context.Context, _ gen.GetTokenGrantableRequestObject) (gen.GetTokenGrantableResponseObject, error) {
	set, err := s.permissions(ctx)
	if err != nil {
		return nil, err
	}
	out := gen.TokenGrantable{Permissions: []gen.GrantablePermission{}, Instances: []gen.ScopeName{}, Groups: []gen.GroupScopeName{}}
	usedInstances, usedGroups := map[int64]bool{}, map[int64]bool{}
	for _, ts := range rbac.GrantableForToken(set) {
		out.Permissions = append(out.Permissions, gen.GrantablePermission{
			Name: string(ts.Permission.Name), Class: gen.GrantablePermissionClass(ts.Permission.Class.String()),
			Description: ts.Permission.Description, All: ts.All, Instances: ts.Instances, Groups: ts.Groups,
		})
		for _, id := range ts.Instances {
			usedInstances[id] = true
		}
		for _, id := range ts.Groups {
			usedGroups[id] = true
		}
	}
	q := s.Store.Read()
	insts, err := q.ListInstances(ctx)
	if err != nil {
		return nil, err
	}
	for _, i := range insts {
		if usedInstances[i.ID] {
			out.Instances = append(out.Instances, gen.ScopeName{Id: i.ID, Name: i.Name})
		}
	}
	groups, err := q.ListInstanceGroups(ctx)
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		if usedGroups[g.ID] {
			out.Groups = append(out.Groups, gen.GroupScopeName{Id: g.ID, Name: g.Name, Mode: gen.GroupScopeNameMode(g.Mode)})
		}
	}
	return gen.GetTokenGrantable200JSONResponse(out), nil
}

// CreateToken makes a token for the caller. The gate has checked tokens.use. The password is checked here, the way
// it was at login, and a two-factor code inside the token's transaction, so it is only spent if the token is made.
// Wrong ones count against the login limits and are audited, as for turning two-factor login off, so a stolen session
// can't be used to guess either faster than the login page allows, nor be turned into a year-long credential.
func (s *Server) CreateToken(ctx context.Context, req gen.CreateTokenRequestObject) (gen.CreateTokenResponseObject, error) {
	if s.Roles == nil {
		return nil, errNoRoles
	}
	if s.TOTP == nil {
		return nil, errNoTOTP
	}
	ri := info(ctx)
	in := req.Body
	if in.Password == "" || len(in.Password) > 1024 {
		return nil, invalid("password", "Enter your password.")
	}
	code := ""
	if in.Code != nil {
		code = *in.Code
	}
	if len(code) > 64 {
		return nil, invalid("code", "Enter a code.")
	}
	grants, err := grantsFromJSON(in.Grants)
	if err != nil {
		return nil, err
	}
	// Refusals that cost nothing to find come before the password, so they never cost an attempt.
	totpOn, err := totp.Enabled(ctx, s.Store.Read(), ri.sess.UserID)
	if err != nil {
		return nil, err
	}
	if totpOn && code == "" {
		return nil, invalid("code", "Enter a code from your authenticator app, or a recovery code.")
	}
	if wait, limited := s.totpLimited(ri); limited {
		return gen.CreateToken429JSONResponse{RateLimitedJSONResponse: rateLimited(wait, msgTOTPRateLimited)}, nil
	}

	id, err := s.Auth.Authenticate(ctx, ri.sess.Username, in.Password)
	if err == nil && (id.Source != ri.sess.Source || auth.NormalizeUsername(id.Username) != ri.sess.Username) {
		err = auth.ErrInvalidCredentials
	}
	if errors.Is(err, auth.ErrInvalidCredentials) {
		if err := s.totpFailed(ctx, audit.ActionTokenCreate, err, "wrong password"); err != nil {
			return nil, err
		}
		return gen.CreateToken401JSONResponse{TOTPInvalidJSONResponse: gen.TOTPInvalidJSONResponse(errorBody("invalid_credentials", msgWrongPassword))}, nil
	}
	if err != nil {
		return nil, err
	}

	var used *audit.Entry
	tin := rbac.TokenInput{Name: in.Name, ExpiresAt: in.ExpiresAt, Grants: grants}
	if totpOn {
		tin.Verify = func(q *db.Queries) error {
			var err error
			used, err = s.TOTP.CheckInTx(ctx, q, totpActor(ctx), code)
			return err
		}
	}
	nt, err := s.Roles.CreateToken(ctx, actor(ctx), tin)
	if errors.Is(err, totp.ErrInvalidCode) {
		if err := s.totpFailed(ctx, audit.ActionTokenCreate, nil, "wrong code"); err != nil {
			return nil, err
		}
		return gen.CreateToken401JSONResponse{TOTPInvalidJSONResponse: gen.TOTPInvalidJSONResponse(errorBody("totp_invalid", msgTOTPInvalid))}, nil
	}
	if err != nil {
		return nil, totpRefusal(err) // rbac refusals pass through unchanged
	}
	s.TOTP.LogUsed(used)
	s.LoginByUser.Reset(ri.sess.Username)
	return gen.CreateToken201JSONResponse{Token: nt.Secret, ApiToken: tokenJSON(nt.Token)}, nil
}

// RevokeMyToken revokes one of the caller's own tokens. Another user's is 404, whatever the caller holds.
func (s *Server) RevokeMyToken(ctx context.Context, req gen.RevokeMyTokenRequestObject) (gen.RevokeMyTokenResponseObject, error) {
	if s.Roles == nil {
		return nil, errNoRoles
	}
	if err := s.Roles.RevokeToken(ctx, actor(ctx), req.PublicId, false); err != nil {
		return nil, err
	}
	return gen.RevokeMyToken204Response{}, nil
}

// RevokeToken revokes anyone's token (sessions.manage, checked by the gate and again by the role manager).
func (s *Server) RevokeToken(ctx context.Context, req gen.RevokeTokenRequestObject) (gen.RevokeTokenResponseObject, error) {
	if s.Roles == nil {
		return nil, errNoRoles
	}
	if err := s.Roles.RevokeToken(ctx, actor(ctx), req.PublicId, true); err != nil {
		return nil, err
	}
	return gen.RevokeToken204Response{}, nil
}

func tokenListJSON(ts []rbac.Token) gen.APITokenList {
	out := gen.APITokenList{Tokens: make([]gen.APIToken, len(ts))}
	for i, t := range ts {
		out.Tokens[i] = tokenJSON(t)
	}
	return out
}

func tokenJSON(t rbac.Token) gen.APIToken {
	out := gen.APIToken{
		PublicId: t.PublicID, Name: t.Name, UserId: t.UserID, Username: t.Username, Grants: grantsJSON(t.Grants),
		CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt, LastUsedIp: t.LastUsedIP, State: gen.APITokenState(t.State),
	}
	if !t.LastUsedAt.IsZero() {
		at := t.LastUsedAt
		out.LastUsedAt = &at
	}
	if !t.RevokedAt.IsZero() {
		at := t.RevokedAt
		out.RevokedAt = &at
	}
	if t.RevokedBy != "" {
		by := gen.APITokenRevokedBy(t.RevokedBy)
		out.RevokedBy = &by
	}
	if t.RevokedReason != "" {
		reason := t.RevokedReason
		out.RevokedReason = &reason
	}
	if t.Refused != rbac.TokenNotRefused {
		refused := gen.APITokenRefused(t.Refused)
		out.Refused = &refused
	}
	return out
}
