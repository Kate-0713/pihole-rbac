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
	msgTokenSuspended  = "The API token is suspended: its owner's directory roles couldn't be confirmed recently. It works again once they are."
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
//   - an unknown, malformed or revoked token, a wrong secret, or a disabled or missing owner is 401 invalid_token;
//     only an unknown or malformed token or a wrong secret counts against the per-address limit;
//   - a correct secret on an expired token is 401 token_expired, audited at most once an hour per token, and doesn't
//     count;
//   - an LDAP user's token whose roles haven't been confirmed for longer than the recheck interval plus the grace
//     period is 401 token_suspended, and doesn't count;
//   - a route that doesn't accept tokens (x-token in the spec) is 403 token_not_allowed;
//   - an owner who must set up two-factor login and hasn't is 403 totp_setup_required;
//   - an owner who no longer holds tokens.use is 403 forbidden.
//
// The request's permissions are then the token's grants intersected with what its owner's roles hold now: a local
// user's user_roles, or the roles an LDAP user's token holds.
func (s *Server) authenticateToken(w http.ResponseWriter, r *http.Request) *reqInfo {
	ctx := r.Context()
	ip := ratelimit.ClientIP(r, s.TrustedProxies)
	// guessed is for a token that doesn't check out: unknown, malformed, or the wrong secret. Only those count against
	// the login limit, since only they could be someone guessing. A revoked token, or one whose owner is disabled, has
	// the right secret, so it is refused with the same answer but not counted: a script left running with it would
	// otherwise lock out everyone behind the same address, logins included.
	reject := func(guessed bool) *reqInfo {
		if guessed && s.LoginByIP.Fail(ip) {
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
		return reject(true)
	}
	publicID, hash, ok := tokens.Parse(raw)
	if !ok {
		return reject(true)
	}
	q := s.Store.Read()
	row, err := q.GetAPITokenForAuth(ctx, publicID)
	if errors.Is(err, sql.ErrNoRows) {
		return reject(true)
	}
	if err != nil {
		s.Logger.Error("loading an API token", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "Something went wrong.")
		return nil
	}
	// An LDAP user's token holds its roles and when they were confirmed; one without a check time can't have been made
	// by CreateToken, so it is refused like any token that isn't valid.
	source := auth.Method(row.Source)
	ldap := source == auth.MethodLDAP
	if !tokens.Equal(row.SecretHash, hash) {
		return reject(true)
	}
	if row.RevokedAt.Valid || row.Disabled || (ldap && !row.RolesCheckedAt.Valid) {
		return reject(false)
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

	// An LDAP user's token whose roles the directory hasn't confirmed for too long is suspended, not ended: a script
	// can't log in again, and the next successful recheck resumes it. Sessions end at the same point. It doesn't count
	// as a failure, since the secret was right.
	var checked time.Time
	if ldap {
		checked = store.FromMillis(row.RolesCheckedAt.Int64)
		if rbac.RolesStale(checked, now, s.Sessions.RolesValidFor()) {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			writeError(w, http.StatusUnauthorized, "token_suspended", msgTokenSuspended)
			return nil
		}
	}

	if !tokenRoutes[r.Pattern] {
		writeError(w, http.StatusForbidden, "token_not_allowed", msgTokenNotAllowed)
		return nil
	}

	// A local user's roles are user_roles; an LDAP user's token holds its own, kept by the recheck.
	var roleIDs []int64
	if ldap {
		roleIDs, err = q.ListAPITokenRoleIDs(ctx, row.ID)
	} else {
		roleIDs, err = q.ListUserRoleIDs(ctx, row.UserID)
	}
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
		user: &caller{UserID: row.UserID, Username: row.Username, Source: source, RoleIDs: roleIDs, RolesCheckedAt: checked},
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
