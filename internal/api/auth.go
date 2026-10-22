// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/auth"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// Login messages. The invalid-credentials one never says whether the username exists.
const (
	msgInvalidCredentials = "Invalid username or password."
	msgNoAccess           = "Your account is valid, but you don't have access to this app. Ask an administrator to give you a role."
	msgRateLimited        = "Too many failed login attempts. Try again later."
)

// GetCSRFToken returns the session's CSRF token, or for a visitor without a session one bound to the anonymous
// cookie (set here if needed).
func (s *Server) GetCSRFToken(ctx context.Context, _ gen.GetCSRFTokenRequestObject) (gen.GetCSRFTokenResponseObject, error) {
	ri := info(ctx)
	if ri.sess != nil {
		return gen.GetCSRFToken200JSONResponse{CsrfToken: s.Sessions.CSRFToken(ri.sess)}, nil
	}
	tok, err := s.Sessions.AnonCSRFToken(ri.w, ri.r)
	if err != nil {
		return nil, err
	}
	return gen.GetCSRFToken200JSONResponse{CsrfToken: tok}, nil
}

// GetSession returns the current session. The gate has already refused requests without one.
func (s *Server) GetSession(ctx context.Context, _ gen.GetSessionRequestObject) (gen.GetSessionResponseObject, error) {
	return gen.GetSession200JSONResponse(s.currentSession(info(ctx).sess)), nil
}

func (s *Server) currentSession(sess *auth.Session) gen.CurrentSession {
	return gen.CurrentSession{
		User: gen.SessionUser{
			Id:       sess.UserID,
			Username: sess.Username,
			Source:   gen.SessionUserSource(sess.Source),
		},
		PublicId:  sess.PublicID,
		ExpiresAt: sess.ExpiresAt.UTC(),
		CsrfToken: s.Sessions.CSRFToken(sess),
	}
}

// Login checks the credentials and starts a session. Failed attempts count against the client address and the
// username; while either is over its limit, attempts are refused without reaching the authenticator. A user with
// valid credentials but no role is refused (fail closed) and doesn't count as a failure.
func (s *Server) Login(ctx context.Context, req gen.LoginRequestObject) (gen.LoginResponseObject, error) {
	ri := info(ctx)
	username := auth.NormalizeUsername(req.Body.Username)
	password := req.Body.Password
	if username == "" || password == "" || len(username) > 256 || len(password) > 1024 {
		return gen.Login400JSONResponse{ValidationFailedJSONResponse: gen.ValidationFailedJSONResponse(
			errorBody("validation_failed", "Enter a username and password."))}, nil
	}

	if ok, wait := s.LoginByIP.Allow(ri.ip); !ok {
		return loginRateLimited(wait), nil
	}
	if ok, wait := s.LoginByUser.Allow(username); !ok {
		return loginRateLimited(wait), nil
	}

	entry := audit.Entry{Username: username, Action: audit.ActionLogin, IP: ri.ip}
	id, err := s.Auth.Authenticate(ctx, username, password)
	if errors.Is(err, auth.ErrInvalidCredentials) {
		trippedIP := s.LoginByIP.Fail(ri.ip)
		trippedUser := s.LoginByUser.Fail(username)
		entry.Err = err // keeps any operational cause (LDAP unreachable) for the audit log
		if trippedIP || trippedUser {
			entry.Detail = map[string]any{"locked_out": lockedOut(trippedIP, trippedUser)}
		}
		if err := s.Audit.Record(ctx, s.Store, entry); err != nil {
			return nil, err
		}
		return gen.Login401JSONResponse(errorBody("invalid_credentials", msgInvalidCredentials)), nil
	}
	if err != nil && !errors.Is(err, auth.ErrNoAccess) {
		return nil, fmt.Errorf("authenticate: %w", err)
	}

	var cookie string
	var sess *auth.Session
	if err == nil {
		entry.Detail = map[string]any{"method": string(id.Source)}
		err = s.Store.WithTx(ctx, func(q *db.Queries) error {
			userID, roles, err := s.rolesFor(ctx, q, id)
			if err != nil {
				return err
			}
			if len(roles) == 0 {
				return auth.ErrNoAccess // fail closed: no default role
			}
			if ri.sess != nil {
				// A new login replaces the previous session rather than leaving it usable.
				if err := s.Sessions.Delete(ctx, q, ri.sess); err != nil {
					return err
				}
			}
			cookie, sess, err = s.Sessions.Create(ctx, q, auth.NewSession{
				UserID: userID, RoleIDs: roles, IP: ri.ip, UserAgent: ri.r.UserAgent(),
			})
			if err != nil {
				return err
			}
			if err := q.SetUserLastLogin(ctx, db.SetUserLastLoginParams{
				LastLoginAt: sql.NullInt64{Int64: store.Millis(sess.CreatedAt), Valid: true}, ID: userID,
			}); err != nil {
				return err
			}
			entry.UserID = userID
			entry.Detail["session"] = sess.PublicID
			_, err = audit.Insert(ctx, q, entry)
			return err
		})
	}
	if errors.Is(err, auth.ErrNoAccess) {
		// Valid credentials, so not a failed attempt for the limiter.
		entry.Err = auth.ErrNoAccess
		entry.UserID = 0
		delete(entry.Detail, "session")
		if err := s.Audit.Record(ctx, s.Store, entry); err != nil {
			return nil, err
		}
		return gen.Login403JSONResponse(errorBody("no_access", msgNoAccess)), nil
	}
	if err != nil {
		return nil, fmt.Errorf("start session: %w", err)
	}

	s.Audit.Log(entry)
	s.LoginByUser.Reset(username)
	s.Sessions.SetCookie(ri.w, ri.r, cookie, sess.ExpiresAt)
	sess.Username = id.Username
	sess.Source = id.Source
	return gen.Login200JSONResponse(s.currentSession(sess)), nil
}

// rolesFor returns the user row and role IDs for a verified identity, inside the login transaction.
func (s *Server) rolesFor(ctx context.Context, q *db.Queries, id *auth.Identity) (userID int64, roles []int64, err error) {
	switch id.Source {
	case auth.MethodLocal:
		roles, err := q.ListUserRoleIDs(ctx, id.UserID)
		return id.UserID, roles, err
	}
	return 0, nil, fmt.Errorf("no role lookup for login method %q", id.Source)
}

func loginRateLimited(wait time.Duration) gen.Login429JSONResponse {
	secs := retryAfterSeconds(wait)
	return gen.Login429JSONResponse{RateLimitedJSONResponse: gen.RateLimitedJSONResponse{
		Body:    errorBody("rate_limited", msgRateLimited),
		Headers: gen.RateLimitedResponseHeaders{RetryAfter: &secs},
	}}
}

func lockedOut(byIP, byUser bool) string {
	switch {
	case byIP && byUser:
		return "address and username"
	case byIP:
		return "address"
	}
	return "username"
}

// Logout ends the current session.
func (s *Server) Logout(ctx context.Context, _ gen.LogoutRequestObject) (gen.LogoutResponseObject, error) {
	ri := info(ctx)
	entry := audit.Entry{
		UserID: ri.sess.UserID, Username: ri.sess.Username, Action: audit.ActionLogout, IP: ri.ip,
		Detail: map[string]any{"session": ri.sess.PublicID},
	}
	err := s.Store.WithTx(ctx, func(q *db.Queries) error {
		if err := s.Sessions.Delete(ctx, q, ri.sess); err != nil {
			return err
		}
		_, err := audit.Insert(ctx, q, entry)
		return err
	})
	if err != nil {
		return nil, err
	}
	s.Audit.Log(entry)
	s.Sessions.ClearCookie(ri.w, ri.r)
	return gen.Logout204Response{}, nil
}
