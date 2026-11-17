// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/auth"
	"github.com/Kate-0713/pihole-rbac/internal/ratelimit"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
	"github.com/Kate-0713/pihole-rbac/internal/tokens"
)

const (
	// touchEvery is how often a token's last use is written: at most once a minute, so a busy script doesn't turn
	// every read into a database write.
	touchEvery = time.Minute
	// expiredUseEvery is how often using an expired token is audited, per token.
	expiredUseEvery = time.Hour

	msgInvalidToken    = "The API token is missing, malformed, revoked or not valid."
	msgTokenExpired    = "The API token has expired. Make a new one."
	msgTokenNotAllowed = "This can't be done with an API token. Log in to the app instead."

	msgTokenRateLimited = "Too many failed attempts from this address. Try again later."
)

// tokenCaller is what the gate learned about a request that authenticated with an API token.
type tokenCaller struct {
	id       int64
	publicID string
	name     string
}

// tokenClock keeps, per token, when something was last done for it, so that it is done at most once per interval.
// It forgets a token once its interval has passed, so it can't grow without bound.
type tokenClock struct {
	mu   sync.Mutex
	last map[int64]time.Time
}

// due reports whether the interval has passed since the last time for id, and if so records now.
func (c *tokenClock) due(id int64, now time.Time, every time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.last == nil {
		c.last = map[int64]time.Time{}
	}
	if t, ok := c.last[id]; ok && now.Sub(t) < every {
		return false
	}
	for k, t := range c.last {
		if now.Sub(t) >= every {
			delete(c.last, k)
		}
	}
	c.last[id] = now
	return true
}

// parseBearer returns the token in an Authorization header. The scheme is case-insensitive (RFC 9110); the token
// itself is checked by tokens.Parse.
func parseBearer(h string) (string, bool) {
	scheme, token, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	return strings.TrimSpace(token), true
}

// authenticateToken handles a request that carries an Authorization header, in place of the session and CSRF
// checks. Cookies are ignored completely, and a request that fails here never falls back to a session. It answers
// the request itself and returns nil when the request is refused. In order:
//   - while the per-address login limit applies, 429, and the token isn't looked at;
//   - an unknown, malformed or revoked token, a wrong secret, or a disabled or missing owner is 401 invalid_token
//     and counts against the per-address limit;
//   - a correct secret on an expired token is 401 token_expired, audited at most once an hour per token, and doesn't
//     count;
//   - a route that doesn't accept tokens (x-token in the spec) is 403 token_not_allowed;
//   - an owner who must set up two-factor login and hasn't is 403 totp_setup_required;
//   - an owner who no longer holds tokens.use is 403 forbidden.
//
// The request's permissions are then the token's grants intersected with what its owner's roles hold now.
func (s *Server) authenticateToken(w http.ResponseWriter, r *http.Request) *reqInfo {
	ctx := r.Context()
	ip := ratelimit.ClientIP(r, s.TrustedProxies)
	invalid := func() *reqInfo {
		if s.LoginByIP.Fail(ip) {
			s.Logger.Warn("API token attempts from one address reached the login limit", "ip", ip)
		}
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeError(w, http.StatusUnauthorized, "invalid_token", msgInvalidToken)
		return nil
	}
	if ok, wait := s.LoginByIP.Allow(ip); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(wait)))
		writeError(w, http.StatusTooManyRequests, "rate_limited", msgTokenRateLimited)
		return nil
	}

	raw, ok := parseBearer(r.Header.Get("Authorization"))
	if !ok {
		return invalid()
	}
	publicID, hash, ok := tokens.Parse(raw)
	if !ok {
		return invalid()
	}
	q := s.Store.Read()
	row, err := q.GetAPITokenForAuth(ctx, publicID)
	if errors.Is(err, sql.ErrNoRows) {
		return invalid()
	}
	if err != nil {
		s.Logger.Error("loading an API token", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "Something went wrong.")
		return nil
	}
	// Phase 1 has tokens for local users only; an LDAP user's token can't have been made, but refuse one anyway.
	if !tokens.Equal(row.SecretHash, hash) || row.RevokedAt.Valid || row.Disabled || auth.Method(row.Source) != auth.MethodLocal {
		return invalid()
	}

	now := s.now()
	tc := &tokenCaller{id: row.ID, publicID: row.PublicID, name: row.Name}
	if !now.Before(store.FromMillis(row.ExpiresAt)) {
		if s.expiredUses.due(row.ID, now, expiredUseEvery) {
			entry := audit.Entry{
				At: now, UserID: row.UserID, Username: row.Username, Action: audit.ActionTokenExpiredUse,
				Target: "token:" + row.Username + "/" + row.Name, IP: ip,
				Detail: map[string]any{"token_id": row.PublicID, "request": r.Pattern},
			}
			if err := s.Audit.Record(ctx, s.Store, entry); err != nil {
				s.Logger.Error("recording token_expired_use", "err", err)
			}
		}
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeError(w, http.StatusUnauthorized, "token_expired", msgTokenExpired)
		return nil
	}

	if !tokenRoutes[r.Pattern] {
		writeError(w, http.StatusForbidden, "token_not_allowed", msgTokenNotAllowed)
		return nil
	}

	roleIDs, err := q.ListUserRoleIDs(ctx, row.UserID)
	if err != nil {
		s.Logger.Error("loading a token owner's roles", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "Something went wrong.")
		return nil
	}
	hold, err := s.totpSetupRequired(ctx, row.UserID, roleIDs)
	if err != nil {
		s.Logger.Error("checking the two-factor requirement", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "Something went wrong.")
		return nil
	}
	if hold {
		writeError(w, http.StatusForbidden, "totp_setup_required", msgTOTPSetupRequired)
		return nil
	}

	owner, err := rbac.Resolve(ctx, q, roleIDs)
	if err != nil {
		s.Logger.Error("resolving a token owner's permissions", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "Something went wrong.")
		return nil
	}
	ri := &reqInfo{
		w: w, ip: ip, token: tc,
		user: &caller{UserID: row.UserID, Username: row.Username, Source: auth.MethodLocal, RoleIDs: roleIDs},
	}
	if !owner.CanGlobal(rbac.TokensUse) {
		// Answered by the gate once the request carries ri, so a refused write is audited like any other.
		ri.tokenRefusal = rbac.Forbidden(rbac.TokensUse)
		return ri
	}
	grants, err := tokenGrants(ctx, q, row.ID)
	if err != nil {
		s.Logger.Error("loading a token's grants", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "Something went wrong.")
		return nil
	}
	ri.perms = rbac.Intersect(rbac.NewSet(grants, owner.Topology()), owner)

	if s.tokenTouches.due(row.ID, now, touchEvery) {
		if err := s.Store.WithTx(ctx, func(q *db.Queries) error {
			return q.TouchAPIToken(ctx, db.TouchAPITokenParams{
				ID: row.ID, LastUsedAt: sql.NullInt64{Int64: store.Millis(now), Valid: true}, LastUsedIp: ip,
			})
		}); err != nil {
			// Not worth failing the request over.
			s.Logger.Warn("recording an API token's last use", "err", err)
		}
	}
	return ri
}

// tokenGrants loads a token's grants.
func tokenGrants(ctx context.Context, q *db.Queries, tokenID int64) ([]rbac.Grant, error) {
	rows, err := q.ListAPITokenGrants(ctx, []int64{tokenID})
	if err != nil {
		return nil, err
	}
	out := make([]rbac.Grant, len(rows))
	for i, g := range rows {
		out[i] = rbac.Grant{Permission: rbac.Permission(g.Permission), Scope: rbac.Scope{Type: rbac.ScopeType(g.ScopeType)}}
		switch out[i].Scope.Type {
		case rbac.ScopeInstance:
			out[i].Scope.ID = g.InstanceID.Int64
		case rbac.ScopeGroup:
			out[i].Scope.ID = g.GroupID.Int64
		}
	}
	return out, nil
}
