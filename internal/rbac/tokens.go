// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package rbac

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/auth"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
	"github.com/Kate-0713/pihole-rbac/internal/tokens"
)

// TokenState says whether a token can still be used, apart from what its owner holds.
type TokenState string

const (
	TokenActive  TokenState = "active"
	TokenExpired TokenState = "expired"
	TokenRevoked TokenState = "revoked"
	// TokenSuspended is an LDAP user's token whose roles haven't been confirmed by the directory for longer than the
	// recheck interval plus the grace period. It is refused until a recheck succeeds, which makes it active again.
	TokenSuspended TokenState = "suspended"
)

// TokenRefusal says why a live token is refused because of its owner, though the token itself is fine. Unlike a
// revoked token, it works again once the owner's account does: enabled again, two-factor login set up, or tokens.use
// held again (for an LDAP user, after the recheck has seen the group).
type TokenRefusal string

const (
	TokenNotRefused       TokenRefusal = ""
	RefusedOwnerDisabled  TokenRefusal = "owner_disabled"
	RefusedTOTPSetup      TokenRefusal = "totp_setup_required"
	RefusedLacksTokensUse TokenRefusal = "lacks_tokens_use"
)

// TokenInput is a new token as its owner asks for it.
type TokenInput struct {
	Name      string
	ExpiresAt time.Time
	Grants    []Grant
	// Verify, if set, runs in the transaction after every other check passes and before the token is stored, so
	// whatever it spends (a two-factor code) is only spent if the token is made. An error from it is returned as is.
	Verify func(q *db.Queries) error
}

// Token describes a token, never its secret or the secret's hash.
type Token struct {
	PublicID   string
	UserID     int64
	Username   string
	Name       string
	Grants     []Grant
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastUsedAt time.Time // zero if never used
	LastUsedIP string
	RevokedAt  time.Time // zero unless revoked
	// RevokedBy is who revoked it: "self" (its owner), "admin" or "recheck" (the LDAP recheck, which also gives
	// RevokedReason). Empty when not revoked, or revoked before this was recorded.
	RevokedBy     string
	RevokedReason string
	State         TokenState
	// Refused is set by TokenRefusals; empty if it hasn't run or the owner allows the token.
	Refused TokenRefusal

	id            int64
	ownerLDAP     bool
	ownerDisabled bool
}

// NewToken is a token just made: the whole token, shown once, and its description.
type NewToken struct {
	Secret string
	Token  Token
}

func tokenTarget(username, name string) string { return "token:" + username + "/" + name }

// CreateToken makes an API token for the actor. Checking their password is the caller's job, before calling this; a
// two-factor code is checked by in.Verify, in the transaction. In one transaction it checks that:
//   - the actor holds tokens.use;
//   - the name is 1 to 64 characters, with no control characters, and not used by another of their unrevoked tokens;
//   - the expiry is in the future and at most a year away;
//   - there is at least one grant, each valid (invariant 6), one a token can hold, and held by the actor (invariant 3);
//   - the actor has fewer than tokens.MaxLive live tokens.
//
// The audit row records the name, public ID, expiry and grants.
func (m *Manager) CreateToken(ctx context.Context, a Actor, in TokenInput) (NewToken, error) {
	var out NewToken
	err := m.do(ctx, a, audit.ActionTokenCreate, func(t *txn) error {
		name := strings.TrimSpace(in.Name)
		t.entry.Target = tokenTarget(a.Username, name)
		if err := t.require(TokensUse); err != nil {
			return err
		}
		if name == "" || utf8.RuneCountInString(name) > tokens.MaxNameLen || hasControl(name, false) {
			return newError(CodeValidation, map[string]any{"field": "name"},
				"A token's name must be 1 to %d characters, with no control characters.", tokens.MaxNameLen)
		}
		expires := in.ExpiresAt.UTC().Truncate(time.Millisecond)
		if !expires.After(t.now) || expires.Sub(t.now) > tokens.MaxLifetime {
			return newError(CodeValidation, map[string]any{"field": "expires_at"},
				"A token must expire in the future, and at most a year from now.")
		}
		if len(in.Grants) == 0 {
			return newError(CodeValidation, map[string]any{"field": "grants"}, "A token needs at least one permission.")
		}
		for _, g := range in.Grants {
			if _, known := Lookup(string(g.Permission)); known && !TokenPermission(g.Permission) {
				return newError(CodeValidation, map[string]any{"field": "grants", "permission": g.Permission},
					"%s can't be given to a token: tokens can only use Pi-hole permissions and audit.view.", g.Permission)
			}
		}
		grants, err := t.normalizeGrants(in.Grants)
		if err != nil {
			return err
		}
		if err := t.requireHolds(grants, "create a token"); err != nil {
			return err
		}
		live, err := t.q.CountLiveAPITokensForUser(t.ctx, db.CountLiveAPITokensForUserParams{UserID: a.UserID, Now: store.Millis(t.now)})
		if err != nil {
			return err
		}
		if live >= tokens.MaxLive {
			return newError(CodeConflict, map[string]any{"reason": "too_many_tokens", "limit": tokens.MaxLive},
				"You already have %d tokens. Revoke one you no longer need first.", tokens.MaxLive)
		}

		if in.Verify != nil {
			if err := in.Verify(t.q); err != nil {
				return err
			}
		}

		// An LDAP user's roles come from the directory, so the token holds the roles of the session making it, and
		// starts from when they were last confirmed (not now: the token is no fresher than that check). The recheck
		// keeps them in step from then on. A local user's token uses user_roles and holds none.
		ldap := a.Source == auth.MethodLDAP
		var checked sql.NullInt64
		if ldap {
			if len(a.RoleIDs) == 0 || a.RolesCheckedAt.IsZero() {
				return newError(CodeConflict, map[string]any{"reason": "no_roles"}, "Your roles haven't been confirmed by the directory. Log in again.")
			}
			checked = sql.NullInt64{Int64: store.Millis(a.RolesCheckedAt), Valid: true}
		}

		secret, publicID, hash := tokens.New()
		id, err := t.q.InsertAPIToken(t.ctx, db.InsertAPITokenParams{
			PublicID: publicID, UserID: a.UserID, Name: name, SecretHash: hash,
			CreatedAt: store.Millis(t.now), ExpiresAt: store.Millis(expires), RolesCheckedAt: checked,
		})
		if store.Constraint(err) == store.Unique {
			return newError(CodeConflict, map[string]any{"field": "name", "reason": "name_taken"},
				"You already have a token called %q. Choose another name, or revoke that one first.", name)
		}
		if err != nil {
			return err
		}
		for _, g := range grants {
			p := db.InsertAPITokenGrantParams{TokenID: id, Permission: string(g.Permission), ScopeType: string(g.Scope.Type)}
			switch g.Scope.Type {
			case ScopeInstance:
				p.InstanceID = sql.NullInt64{Int64: g.Scope.ID, Valid: true}
			case ScopeGroup:
				p.GroupID = sql.NullInt64{Int64: g.Scope.ID, Valid: true}
			}
			if err := t.q.InsertAPITokenGrant(t.ctx, p); err != nil {
				return fmt.Errorf("insert token grant %s: %w", g, err)
			}
		}
		if ldap {
			for _, role := range a.RoleIDs {
				if err := t.q.AddAPITokenRole(t.ctx, db.AddAPITokenRoleParams{TokenID: id, RoleID: role}); err != nil {
					return fmt.Errorf("insert token role: %w", err)
				}
			}
		}
		t.entry.Detail["token_id"] = publicID
		t.entry.Detail["expires_at"] = expires.Format(time.RFC3339)
		t.entry.Detail["grants"] = grantStrings(grants)
		out = NewToken{Secret: secret, Token: Token{
			PublicID: publicID, UserID: a.UserID, Username: a.Username, Name: name, Grants: grants,
			CreatedAt: t.now, ExpiresAt: expires, State: TokenActive,
		}}
		return nil
	})
	if err != nil {
		return NewToken{}, err
	}
	return out, nil
}

// RevokeToken revokes a token. Anyone may revoke their own. Another user's needs sessions.manage and asAdmin, which
// says the caller is using the admin list: without it someone else's token is not found, so the account page can't
// learn whether a public ID exists. Revoking a token that is already revoked changes nothing and isn't audited.
func (m *Manager) RevokeToken(ctx context.Context, a Actor, publicID string, asAdmin bool) error {
	return m.do(ctx, a, audit.ActionTokenRevoke, func(t *txn) error {
		notFound := newError(CodeNotFound, map[string]any{"token_id": publicID}, "There is no such token.")
		row, err := t.q.GetAPIToken(t.ctx, publicID)
		if errors.Is(err, sql.ErrNoRows) {
			return notFound
		}
		if err != nil {
			return err
		}
		t.entry.Target = tokenTarget(row.Username, row.Name)
		t.entry.Detail["token_id"] = row.PublicID
		by := "self"
		if row.UserID == a.UserID {
			t.entry.Detail["by"] = by
		} else {
			if !asAdmin {
				return notFound
			}
			if err := t.require(SessionsManage); err != nil {
				return err
			}
			by = "admin"
			t.entry.Detail["by"] = by
			t.entry.Detail["owner"] = row.Username
		}
		n, err := t.q.RevokeAPIToken(t.ctx, db.RevokeAPITokenParams{
			ID: row.ID, RevokedAt: sql.NullInt64{Int64: store.Millis(t.now), Valid: true},
			RevokedBy: sql.NullString{String: by, Valid: true},
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return errNoChange
		}
		return nil
	})
}

// ListUserTokens lists a user's tokens, newest first, including revoked and expired ones not yet pruned. rolesValidFor
// is how long an LDAP user's token's roles stay usable without a recheck (Sessions.RolesValidFor), past which it is
// listed as suspended; zero never suspends.
func ListUserTokens(ctx context.Context, q *db.Queries, userID int64, now time.Time, rolesValidFor time.Duration) ([]Token, error) {
	rows, err := q.ListAPITokensForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	conv := make([]db.GetAPITokenRow, len(rows))
	for i, r := range rows {
		conv[i] = db.GetAPITokenRow(r)
	}
	return tokensWithGrants(ctx, q, conv, now, rolesValidFor)
}

// ListAllTokens lists every user's tokens, by username, then newest first. rolesValidFor is as for ListUserTokens.
func ListAllTokens(ctx context.Context, q *db.Queries, now time.Time, rolesValidFor time.Duration) ([]Token, error) {
	rows, err := q.ListAllAPITokens(ctx)
	if err != nil {
		return nil, err
	}
	conv := make([]db.GetAPITokenRow, len(rows))
	for i, r := range rows {
		conv[i] = db.GetAPITokenRow(r)
	}
	return tokensWithGrants(ctx, q, conv, now, rolesValidFor)
}

func tokensWithGrants(ctx context.Context, q *db.Queries, rows []db.GetAPITokenRow, now time.Time, rolesValidFor time.Duration) ([]Token, error) {
	out := make([]Token, len(rows))
	if len(rows) == 0 {
		return out, nil
	}
	ids := make([]int64, len(rows))
	index := make(map[int64]int, len(rows))
	for i, r := range rows {
		ids[i], index[r.ID] = r.ID, i
		out[i] = tokenFromRow(r, now, rolesValidFor)
	}
	grants, err := q.ListAPITokenGrants(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("rbac: list token grants: %w", err)
	}
	for _, g := range grants {
		i := index[g.TokenID]
		out[i].Grants = append(out[i].Grants, grantFromRow(db.RoleGrant{
			Permission: g.Permission, ScopeType: g.ScopeType, InstanceID: g.InstanceID, GroupID: g.GroupID,
		}))
	}
	for i := range out {
		SortGrants(out[i].Grants)
	}
	return out, nil
}

func tokenFromRow(r db.GetAPITokenRow, now time.Time, rolesValidFor time.Duration) Token {
	t := Token{
		PublicID: r.PublicID, UserID: r.UserID, Username: r.Username, Name: r.Name,
		CreatedAt: store.FromMillis(r.CreatedAt), ExpiresAt: store.FromMillis(r.ExpiresAt), LastUsedIP: r.LastUsedIp,
		Grants: []Grant{}, State: TokenActive,
		id: r.ID, ownerLDAP: r.OwnerSource == "ldap", ownerDisabled: r.OwnerDisabled,
	}
	if r.LastUsedAt.Valid {
		t.LastUsedAt = store.FromMillis(r.LastUsedAt.Int64)
	}
	switch {
	case r.RevokedAt.Valid:
		t.RevokedAt, t.State = store.FromMillis(r.RevokedAt.Int64), TokenRevoked
		t.RevokedBy, t.RevokedReason = r.RevokedBy.String, r.RevokedReason.String
	case !t.ExpiresAt.After(now):
		t.State = TokenExpired
	case r.RolesCheckedAt.Valid && RolesStale(store.FromMillis(r.RolesCheckedAt.Int64), now, rolesValidFor):
		t.State = TokenSuspended
	}
	return t
}

// TokenRefusals fills in Refused for each live token, in the order the gate checks them: a disabled owner refuses an
// active or suspended token; a suspended one is otherwise left to its state, since its roles aren't trusted; an active
// one is refused while its owner must set up two-factor login (totpHold, given the roles the token is checked with),
// then while those roles lack tokens.use. Those roles are the user's for a local user and the token's own for an LDAP
// user's, so two of an LDAP user's tokens can differ until the next recheck.
func TokenRefusals(ctx context.Context, q *db.Queries, ts []Token,
	totpHold func(ctx context.Context, userID int64, roleIDs []int64) (bool, error)) error {
	userRoles := map[int64][]int64{}
	for i := range ts {
		t := &ts[i]
		if t.State != TokenActive && t.State != TokenSuspended {
			continue
		}
		if t.ownerDisabled {
			t.Refused = RefusedOwnerDisabled
			continue
		}
		if t.State != TokenActive {
			continue
		}
		var roleIDs []int64
		var err error
		if t.ownerLDAP {
			roleIDs, err = q.ListAPITokenRoleIDs(ctx, t.id)
		} else if r, ok := userRoles[t.UserID]; ok {
			roleIDs = r
		} else {
			roleIDs, err = q.ListUserRoleIDs(ctx, t.UserID)
			userRoles[t.UserID] = roleIDs
		}
		if err != nil {
			return fmt.Errorf("rbac: token owner's roles: %w", err)
		}
		hold, err := totpHold(ctx, t.UserID, roleIDs)
		if err != nil {
			return err
		}
		if hold {
			t.Refused = RefusedTOTPSetup
			continue
		}
		set, err := Resolve(ctx, q, roleIDs)
		if err != nil {
			return err
		}
		if !set.CanGlobal(TokensUse) {
			t.Refused = RefusedLacksTokensUse
		}
	}
	return nil
}

// RolesStale reports whether roles last confirmed at checked are too old to use at now: older than rolesValidFor,
// the recheck interval plus the grace period. Zero rolesValidFor is never stale. Sessions end at the same point; the
// gate suspends a token there, and the token list says so.
func RolesStale(checked, now time.Time, rolesValidFor time.Duration) bool {
	return rolesValidFor > 0 && now.Sub(checked) > rolesValidFor
}

// PruneTokens deletes tokens revoked or expired more than tokens.KeepFor ago, and returns how many. Their audit rows
// keep their names.
func PruneTokens(ctx context.Context, st *store.Store, now time.Time) (int64, error) {
	var n int64
	err := st.WithTx(ctx, func(q *db.Queries) error {
		var err error
		n, err = q.PruneAPITokens(ctx, sql.NullInt64{Int64: store.Millis(now.Add(-tokens.KeepFor)), Valid: true})
		return err
	})
	return n, err
}

// TokenScopes is where a user could grant one permission to a token of theirs: at scope all, and on which instances
// and groups. A token's grant must be one its owner holds (invariant 3), so this is what the token form offers.
type TokenScopes struct {
	Permission Info
	All        bool
	Instances  []int64
	Groups     []int64
}

// GrantableForToken lists, in catalogue order, the permissions a token can hold (TokenPermission) that set holds
// somewhere, with every scope set holds them at. A grant on an independent group also offers its members one by one,
// and scope all offers every instance and group the permission's class allows, as Holds and ValidateGrant decide.
func GrantableForToken(set *Set) []TokenScopes {
	topo := set.Topology()
	var out []TokenScopes
	for _, p := range catalogue {
		if !TokenPermission(p.Name) {
			continue
		}
		ts := TokenScopes{Permission: p, All: set.Holds(Grant{Permission: p.Name, Scope: AllScope()}), Instances: []int64{}, Groups: []int64{}}
		if p.Class != ClassGlobal {
			for _, id := range topo.Instances() {
				g := Grant{Permission: p.Name, Scope: InstanceScope(id)}
				if ValidateGrant(topo, g) == nil && set.Holds(g) {
					ts.Instances = append(ts.Instances, id)
				}
			}
			for _, id := range topo.Groups() {
				g := Grant{Permission: p.Name, Scope: GroupScope(id)}
				if ValidateGrant(topo, g) == nil && set.Holds(g) {
					ts.Groups = append(ts.Groups, id)
				}
			}
		}
		if ts.All || len(ts.Instances) > 0 || len(ts.Groups) > 0 {
			out = append(out, ts)
		}
	}
	return out
}

// TokenName names a token in a refusal: "name" (owner).
func TokenName(username, name string) string {
	return fmt.Sprintf("%q (%s)", name, username)
}
