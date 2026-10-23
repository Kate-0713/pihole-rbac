// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"errors"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/auth"
	"github.com/Kate-0713/pihole-rbac/internal/setup"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// setupRequired reports whether first-run setup is still open. Setup never reopens, so once it is complete the
// answer is cached; until then the database is asked each time, because `pihole-rbac user reset-admin` in another
// process can also close it.
func (s *Server) setupRequired(ctx context.Context) (bool, error) {
	if s.setupDone.Load() {
		return false, nil
	}
	needed, err := setup.Required(ctx, s.Store.Read())
	if err != nil {
		return false, err
	}
	if !needed {
		s.setupDone.Store(true)
	}
	return needed, nil
}

// GetSetupStatus says whether the setup page is needed.
func (s *Server) GetSetupStatus(ctx context.Context, _ gen.GetSetupStatusRequestObject) (gen.GetSetupStatusResponseObject, error) {
	needed, err := s.setupRequired(ctx)
	if err != nil {
		return nil, err
	}
	return gen.GetSetupStatus200JSONResponse{SetupRequired: needed}, nil
}

// CompleteSetup checks the setup token, creates the first admin and the starter roles, closes setup and logs the
// admin in, all in one transaction with its audit entry. Wrong tokens count against the address's login limit.
func (s *Server) CompleteSetup(ctx context.Context, req gen.CompleteSetupRequestObject) (gen.CompleteSetupResponseObject, error) {
	ri := info(ctx)
	if ok, wait := s.LoginByIP.Allow(ri.ip); !ok {
		secs := retryAfterSeconds(wait)
		return gen.CompleteSetup429JSONResponse{RateLimitedJSONResponse: gen.RateLimitedJSONResponse{
			Body:    errorBody("rate_limited", msgRateLimited),
			Headers: gen.RateLimitedResponseHeaders{RetryAfter: &secs},
		}}, nil
	}
	b := req.Body
	if len(b.Token) > 256 || len(b.Username) > 256 || len(b.Password) > 1024 {
		return setupValidation("A field is too long."), nil
	}

	username := auth.NormalizeUsername(b.Username)
	entry := audit.Entry{Username: username, Action: audit.ActionSetup, Target: username, IP: ri.ip}
	now := time.Now()
	var cookie string
	var sess *auth.Session
	err := s.Store.WithTx(ctx, func(q *db.Queries) error {
		userID, adminRole, err := setup.Complete(ctx, q, b.Token, b.Username, b.Password, now)
		if err != nil {
			return err
		}
		cookie, sess, err = s.Sessions.Create(ctx, q, auth.NewSession{
			UserID: userID, RoleIDs: []int64{adminRole}, IP: ri.ip, UserAgent: ri.r.UserAgent(),
		})
		if err != nil {
			return err
		}
		entry.UserID = userID
		entry.Detail = map[string]any{"session": sess.PublicID}
		_, err = audit.Insert(ctx, q, entry)
		return err
	})

	switch {
	case err == nil:
	case errors.Is(err, setup.ErrComplete):
		s.setupDone.Store(true)
		return gen.CompleteSetup409JSONResponse(errorBody("setup_complete", "Setup has already been completed. Log in instead.")), nil
	case errors.Is(err, setup.ErrInvalidToken):
		s.LoginByIP.Fail(ri.ip)
		entry.Err = err
		if err := s.Audit.Record(ctx, s.Store, entry); err != nil {
			return nil, err
		}
		return gen.CompleteSetup401JSONResponse(errorBody("invalid_setup_token",
			"That setup token is wrong or has expired. Check the log, or run `pihole-rbac setup --print-token` for a new one.")), nil
	case errors.Is(err, auth.ErrInvalidUsername), errors.Is(err, auth.ErrPasswordTooShort),
		errors.Is(err, auth.ErrPasswordTooLong), errors.Is(err, setup.ErrUsernameUsed):
		// These messages are written to be shown as they are.
		return setupValidation(err.Error()), nil
	default:
		return nil, err
	}

	s.setupDone.Store(true)
	s.Audit.Log(entry)
	s.Sessions.SetCookie(ri.w, ri.r, cookie, sess.ExpiresAt)
	sess.Username = username
	sess.Source = auth.MethodLocal
	return gen.CompleteSetup200JSONResponse(s.currentSession(sess)), nil
}

func setupValidation(msg string) gen.CompleteSetup400JSONResponse {
	return gen.CompleteSetup400JSONResponse{ValidationFailedJSONResponse: gen.ValidationFailedJSONResponse(errorBody("validation_failed", msg))}
}
