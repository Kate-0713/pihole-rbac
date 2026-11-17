// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/auth"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/totp"
)

var errNoTOTP = errors.New("api: no two-factor service configured")

const (
	msgTOTPInvalid     = "That code isn't right. Check the time on your phone and try the next code."
	msgTOTPRateLimited = "Too many wrong passwords or codes. Try again later."
	msgWrongPassword   = "Your password is wrong."
)

func totpActor(ctx context.Context) totp.Actor {
	ri := info(ctx)
	return totp.Actor{UserID: ri.sess.UserID, Username: ri.sess.Username, PublicID: ri.sess.PublicID, IP: ri.ip}
}

// totpRefusal turns the totp package's refusals into API errors. A wrong code isn't one of them: each handler
// answers that itself, since some count it against the login limits.
func totpRefusal(err error) error {
	conflict := func(reason, message string) error {
		return &rbac.Error{Code: rbac.CodeConflict, Message: message, Details: map[string]any{"reason": reason}}
	}
	switch {
	case errors.Is(err, totp.ErrUnavailable):
		return conflict("no_master_key", "Two-factor login needs the app's master key, which isn't set. Ask whoever runs the app to set PIHOLE_RBAC_MASTER_KEY.")
	case errors.Is(err, totp.ErrEnabled):
		return conflict("enabled", "Two-factor login is already on. Turn it off first to set it up again.")
	case errors.Is(err, totp.ErrNotPending):
		return conflict("not_pending", "There is no two-factor setup waiting for a code. Start setting it up again.")
	case errors.Is(err, totp.ErrNotEnabled):
		return conflict("not_enabled", "Two-factor login isn't on.")
	}
	return err
}

// GetTOTP returns the caller's own two-factor login: on or off, required or not, and the recovery codes left.
func (s *Server) GetTOTP(ctx context.Context, _ gen.GetTOTPRequestObject) (gen.GetTOTPResponseObject, error) {
	if s.TOTP == nil {
		return nil, errNoTOTP
	}
	sess := info(ctx).sess
	st, err := s.TOTP.Status(ctx, sess.UserID, sess.RoleIDs)
	if err != nil {
		return nil, err
	}
	out := gen.TOTPStatus{
		Available: st.Available, Enabled: st.Enabled, Pending: st.Pending, Required: st.Required,
		RecoveryCodesLeft: st.RecoveryCodesLeft,
	}
	if st.Enabled {
		at := st.EnabledAt.UTC()
		out.EnabledAt = &at
	}
	return gen.GetTOTP200JSONResponse(out), nil
}

// SetupTOTP makes the caller a new secret and returns it for their authenticator app.
func (s *Server) SetupTOTP(ctx context.Context, _ gen.SetupTOTPRequestObject) (gen.SetupTOTPResponseObject, error) {
	if s.TOTP == nil {
		return nil, errNoTOTP
	}
	e, err := s.TOTP.Setup(ctx, totpActor(ctx))
	if err != nil {
		return nil, totpRefusal(err)
	}
	return gen.SetupTOTP200JSONResponse{Secret: e.Secret, Uri: e.URI, Qr: e.QR}, nil
}

// ConfirmTOTP turns two-factor login on once the caller proves their authenticator has the secret. A wrong code
// isn't counted against the login limits: the caller was just shown the secret, so there is nothing to guess.
func (s *Server) ConfirmTOTP(ctx context.Context, req gen.ConfirmTOTPRequestObject) (gen.ConfirmTOTPResponseObject, error) {
	if s.TOTP == nil {
		return nil, errNoTOTP
	}
	if req.Body.Code == "" || len(req.Body.Code) > 64 {
		return nil, invalid("code", "Enter a code.")
	}
	codes, err := s.TOTP.Confirm(ctx, totpActor(ctx), req.Body.Code)
	if errors.Is(err, totp.ErrInvalidCode) {
		return gen.ConfirmTOTP401JSONResponse{TOTPInvalidJSONResponse: gen.TOTPInvalidJSONResponse(errorBody("totp_invalid", msgTOTPInvalid))}, nil
	}
	if err != nil {
		return nil, totpRefusal(err)
	}
	return gen.ConfirmTOTP200JSONResponse{RecoveryCodes: codes}, nil
}

// DisableTOTP turns the caller's two-factor login off, given their password and a code. Wrong ones count against the
// login limits and are audited, so a stolen session can't be used to guess either faster than the login page allows.
func (s *Server) DisableTOTP(ctx context.Context, req gen.DisableTOTPRequestObject) (gen.DisableTOTPResponseObject, error) {
	if s.TOTP == nil {
		return nil, errNoTOTP
	}
	ri := info(ctx)
	password, code := req.Body.Password, req.Body.Code
	if password == "" || len(password) > 1024 {
		return nil, invalid("password", "Enter your password.")
	}
	if code == "" || len(code) > 64 {
		return nil, invalid("code", "Enter a code.")
	}
	if wait, limited := s.totpLimited(ri); limited {
		return gen.DisableTOTP429JSONResponse{RateLimitedJSONResponse: rateLimited(wait, msgTOTPRateLimited)}, nil
	}
	// Nothing to turn off is a conflict before anything is checked, so it never costs an attempt.
	if on, err := totp.Enabled(ctx, s.Store.Read(), ri.sess.UserID); err != nil {
		return nil, err
	} else if !on {
		return nil, totpRefusal(totp.ErrNotEnabled)
	}

	// The password is checked the way it was at login: bcrypt for a local user, a bind for an LDAP user. It has to
	// be the caller's own account by the same method, not just some account the password opens.
	id, err := s.Auth.Authenticate(ctx, ri.sess.Username, password)
	if err == nil && (id.Source != ri.sess.Source || auth.NormalizeUsername(id.Username) != ri.sess.Username) {
		err = auth.ErrInvalidCredentials
	}
	if errors.Is(err, auth.ErrInvalidCredentials) {
		if err := s.totpFailed(ctx, audit.ActionTOTPDisable, err, "wrong password"); err != nil {
			return nil, err
		}
		return gen.DisableTOTP401JSONResponse{TOTPInvalidJSONResponse: gen.TOTPInvalidJSONResponse(errorBody("invalid_credentials", msgWrongPassword))}, nil
	}
	if err != nil {
		return nil, err
	}

	err = s.TOTP.Disable(ctx, totpActor(ctx), code)
	if errors.Is(err, totp.ErrInvalidCode) {
		if err := s.totpFailed(ctx, audit.ActionTOTPDisable, nil, "wrong code"); err != nil {
			return nil, err
		}
		return gen.DisableTOTP401JSONResponse{TOTPInvalidJSONResponse: gen.TOTPInvalidJSONResponse(errorBody("totp_invalid", msgTOTPInvalid))}, nil
	}
	if err != nil {
		return nil, totpRefusal(err)
	}
	s.LoginByUser.Reset(ri.sess.Username)
	return gen.DisableTOTP204Response{}, nil
}

// RegenerateRecoveryCodes replaces the caller's recovery codes, given a code. A wrong one counts against the login
// limits and is audited, as for DisableTOTP.
func (s *Server) RegenerateRecoveryCodes(ctx context.Context, req gen.RegenerateRecoveryCodesRequestObject) (gen.RegenerateRecoveryCodesResponseObject, error) {
	if s.TOTP == nil {
		return nil, errNoTOTP
	}
	ri := info(ctx)
	code := req.Body.Code
	if code == "" || len(code) > 64 {
		return nil, invalid("code", "Enter a code.")
	}
	if wait, limited := s.totpLimited(ri); limited {
		return gen.RegenerateRecoveryCodes429JSONResponse{RateLimitedJSONResponse: rateLimited(wait, msgTOTPRateLimited)}, nil
	}
	codes, err := s.TOTP.RegenerateRecoveryCodes(ctx, totpActor(ctx), code)
	if errors.Is(err, totp.ErrInvalidCode) {
		if err := s.totpFailed(ctx, audit.ActionRecoveryCodesRegenerate, nil, "wrong code"); err != nil {
			return nil, err
		}
		return gen.RegenerateRecoveryCodes401JSONResponse{TOTPInvalidJSONResponse: gen.TOTPInvalidJSONResponse(errorBody("totp_invalid", msgTOTPInvalid))}, nil
	}
	if err != nil {
		return nil, totpRefusal(err)
	}
	s.LoginByUser.Reset(ri.sess.Username)
	return gen.RegenerateRecoveryCodes200JSONResponse{RecoveryCodes: codes}, nil
}

// totpLimited reports whether a login limit applies to the caller's address or username, and for how long.
func (s *Server) totpLimited(ri *reqInfo) (wait time.Duration, limited bool) {
	if ok, wait := s.LoginByIP.Allow(ri.ip); !ok {
		return wait, true
	}
	if ok, wait := s.LoginByUser.Allow(ri.sess.Username); !ok {
		return wait, true
	}
	return 0, false
}

// totpFailed counts a wrong password or code against the login limits and audits it. cause is the authenticator's
// error, if any, which keeps an operational reason (an LDAP server that couldn't be reached) for the audit row.
func (s *Server) totpFailed(ctx context.Context, action string, cause error, reason string) error {
	ri := info(ctx)
	trippedIP := s.LoginByIP.Fail(ri.ip)
	trippedUser := s.LoginByUser.Fail(ri.sess.Username)
	entry := audit.Entry{
		UserID: ri.sess.UserID, Username: ri.sess.Username, Action: action, Target: "user:" + ri.sess.Username,
		IP: ri.ip, Err: errors.New(reason), Detail: map[string]any{"user_id": ri.sess.UserID},
	}
	if cause != nil {
		entry.Err = fmt.Errorf("%s: %w", reason, cause)
	}
	if trippedIP || trippedUser {
		entry.Detail["locked_out"] = lockedOut(trippedIP, trippedUser)
	}
	return s.Audit.Record(ctx, s.Store, entry)
}

// RemoveUserTOTP removes another user's two-factor login.
func (s *Server) RemoveUserTOTP(ctx context.Context, req gen.RemoveUserTOTPRequestObject) (gen.RemoveUserTOTPResponseObject, error) {
	if s.Roles == nil {
		return nil, errNoRoles
	}
	if err := s.Roles.RemoveUserTOTP(ctx, actor(ctx), req.Id); err != nil {
		return nil, err
	}
	u, err := s.userJSON(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return gen.RemoveUserTOTP200JSONResponse(u), nil
}

// SetRoleTOTPRequired says whether a role's holders must use two-factor login.
func (s *Server) SetRoleTOTPRequired(ctx context.Context, req gen.SetRoleTOTPRequiredRequestObject) (gen.SetRoleTOTPRequiredResponseObject, error) {
	if s.Roles == nil {
		return nil, errNoRoles
	}
	if err := s.Roles.SetRoleTOTPRequired(ctx, actor(ctx), req.Id, req.Body.Required); err != nil {
		return nil, err
	}
	role, err := s.roleJSON(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return gen.SetRoleTOTPRequired200JSONResponse(role), nil
}

// SetUserTOTPPolicy sets a user's own two-factor setting.
func (s *Server) SetUserTOTPPolicy(ctx context.Context, req gen.SetUserTOTPPolicyRequestObject) (gen.SetUserTOTPPolicyResponseObject, error) {
	if s.Roles == nil {
		return nil, errNoRoles
	}
	policy := string(req.Body.Policy)
	switch req.Body.Policy {
	case gen.TOTPPolicy("roles"):
		policy = ""
	case gen.TOTPPolicy("required"), gen.TOTPPolicy("exempt"):
	default:
		return nil, invalid("policy", "The setting is roles, required or exempt.")
	}
	if err := s.Roles.SetUserTOTPPolicy(ctx, actor(ctx), req.Id, policy); err != nil {
		return nil, err
	}
	u, err := s.userJSON(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return gen.SetUserTOTPPolicy200JSONResponse(u), nil
}

// totpSetupRoutes are the operations a session can still use while its user must use two-factor login and hasn't
// turned it on: enough to see where they stand, set it up, or leave. Public operations aren't listed; they never
// reach the check.
var totpSetupRoutes = map[string]bool{
	"GET /api/v1/auth/session":       true,
	"GET /api/v1/auth/csrf":          true,
	"POST /api/v1/auth/logout":       true,
	"GET /api/v1/auth/totp":          true,
	"POST /api/v1/auth/totp/setup":   true,
	"POST /api/v1/auth/totp/confirm": true,
}

const msgTOTPSetupRequired = "You need to set up two-factor login before you can use the app."

// totpSetupRequired reports whether a user must use two-factor login and hasn't turned it on, for the roles their
// session or API token holds. It is worked out from the database on each request, like permissions, so a requirement
// set on a role or a user applies to their open sessions and tokens at once, and setting it up lifts it at once.
func (s *Server) totpSetupRequired(ctx context.Context, userID int64, roleIDs []int64) (bool, error) {
	q := s.Store.Read()
	required, err := totp.RequiredFor(ctx, q, userID, roleIDs)
	if err != nil || !required {
		return false, err
	}
	on, err := totp.Enabled(ctx, q, userID)
	return !on, err
}
