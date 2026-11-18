// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"slices"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// recheckEvery is how often the job looks for LDAP users that are due.
const recheckEvery = time.Minute

// Directory looks users up with the service account. *LDAPAuthenticator is one.
type Directory interface {
	// Lookup returns the user's current DN and groups, ErrNoSuchUser if the directory no longer has the user, or any
	// other error if it couldn't be asked.
	Lookup(ctx context.Context, username string) (*Identity, error)
}

// Rechecker keeps the roles of LDAP users' sessions and API tokens in step with the directory. An LDAP user's roles
// live only in their sessions and tokens, taken from their groups at login (and from the session that made a token),
// so without this a user removed from a group would keep the role until their session ended or their token expired.
//
// It runs in the background, never in a request. Every minute it finds the LDAP users that have a session, or a live
// token, whose roles were last checked more than Interval ago, looks each one up with the service account, and
// replaces the roles of all their sessions and live tokens with what their groups map to now. A user with no role
// left, or no longer in the directory, loses their sessions and has their tokens revoked. If the directory can't be
// reached nothing changes: Sessions.Get ends sessions whose last successful check is older than the interval plus the
// grace period, and the API suspends tokens in the same state until a recheck succeeds. A disabled user's sessions are
// removed, but their tokens are left alone: they are refused while the account is disabled, and are rechecked once it
// is enabled again.
type Rechecker struct {
	Store *store.Store
	Audit *audit.Logger
	// Directory returns the current directory, or nil when LDAP login isn't configured. It is a function so that
	// saving new LDAP settings can swap the directory without restarting the job.
	Directory func() Directory
	Interval  time.Duration // zero means DefaultRecheckInterval
	Logger    *slog.Logger  // nil means slog.Default()
	Now       func() time.Time
}

// Run rechecks every minute until ctx ends.
func (r *Rechecker) Run(ctx context.Context) {
	t := time.NewTicker(recheckEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := r.RunOnce(ctx); err != nil && ctx.Err() == nil {
				r.logger().Error("LDAP recheck failed", "err", err)
			}
		}
	}
}

func (r *Rechecker) logger() *slog.Logger {
	if r.Logger != nil {
		return r.Logger
	}
	return slog.Default()
}

func (r *Rechecker) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// RunOnce rechecks the users that are due. A directory that can't be reached is logged once and isn't an error; the
// error is for the database.
func (r *Rechecker) RunOnce(ctx context.Context) error {
	interval := r.Interval
	if interval <= 0 {
		interval = DefaultRecheckInterval
	}
	now := r.now()
	due, err := r.Store.Read().ListLDAPUsersDueForRecheck(ctx, db.ListLDAPUsersDueForRecheckParams{
		Cutoff: store.Millis(now.Add(-interval)), Now: store.Millis(now),
	})
	if err != nil || len(due) == 0 {
		return err
	}
	var dir Directory
	if r.Directory != nil {
		dir = r.Directory()
	}

	for i, u := range due {
		if u.Disabled {
			// Their sessions are already refused; this only removes them.
			if err := r.apply(ctx, u, nil, false); err != nil {
				return err
			}
			continue
		}
		if dir == nil {
			r.logger().Warn("LDAP sessions are due for a recheck but LDAP login isn't configured; they end once the grace period does",
				"users", len(due)-i)
			return nil
		}
		id, err := dir.Lookup(ctx, u.Username)
		switch {
		case err == nil:
			err = r.apply(ctx, u, id, true)
		case errors.Is(err, ErrNoSuchUser):
			err = r.apply(ctx, u, nil, true)
		default:
			if ctx.Err() != nil {
				return nil
			}
			// The directory is down or misconfigured, so every other lookup would fail the same way and wait out its
			// timeout. Sessions keep their roles; Sessions.Get ends them when the grace period runs out. Failures are
			// logged but not audited, so an outage doesn't fill the audit log.
			r.logger().Warn("LDAP recheck: directory lookup failed; sessions keep their roles until the grace period ends",
				"err", err, "users_unchecked", len(due)-i)
			return nil
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// apply brings one user's sessions and live tokens in step with the directory. id is nil when the user is gone from
// it, or disabled in the app. The roles are worked out inside the transaction, so a mapping changed while the lookup
// was running is not applied late. A change is audited after the commit: as ldap_recheck for the user, and as
// token_revoke (by recheck, with the reason) for each token it revokes.
func (r *Rechecker) apply(ctx context.Context, u db.ListLDAPUsersDueForRecheckRow, id *Identity, record bool) error {
	now := r.now()
	entry := audit.Entry{UserID: u.ID, Username: u.Username, Action: audit.ActionLDAPRecheck, Target: u.Username, Detail: map[string]any{}}
	var revoked []audit.Entry
	changed := false

	err := r.Store.WithTx(ctx, func(q *db.Queries) error {
		sessions, err := q.ListUserSessions(ctx, u.ID)
		if err != nil {
			return err
		}
		// A disabled user's tokens aren't touched (see Rechecker), so only their sessions count here.
		var tokens []db.ListLiveLDAPTokensForUserRow
		if !u.Disabled {
			if tokens, err = q.ListLiveLDAPTokensForUser(ctx, db.ListLiveLDAPTokensForUserParams{UserID: u.ID, Now: store.Millis(now)}); err != nil {
				return err
			}
		}
		if len(sessions) == 0 && len(tokens) == 0 {
			return nil
		}
		end := func(reason string) error {
			n, err := q.DeleteUserSessions(ctx, u.ID)
			if err != nil {
				return err
			}
			entry.Detail["reason"], entry.Detail["sessions_ended"] = reason, n
			for _, tk := range tokens {
				if _, err := q.RevokeAPIToken(ctx, db.RevokeAPITokenParams{
					ID: tk.ID, RevokedAt: sql.NullInt64{Int64: store.Millis(now), Valid: true},
					RevokedBy: sql.NullString{String: "recheck", Valid: true}, RevokedReason: sql.NullString{String: reason, Valid: true},
				}); err != nil {
					return err
				}
				revoked = append(revoked, audit.Entry{
					At: now, UserID: u.ID, Username: u.Username, Action: audit.ActionTokenRevoke,
					Target: "token:" + u.Username + "/" + tk.Name,
					Detail: map[string]any{"token_id": tk.PublicID, "by": "recheck", "reason": reason},
				})
			}
			if len(tokens) > 0 {
				entry.Detail["tokens_revoked"] = len(tokens)
			}
			if !record {
				return nil
			}
			changed = true
			if _, err := audit.Insert(ctx, q, entry); err != nil {
				return err
			}
			for _, e := range revoked {
				if _, err := audit.Insert(ctx, q, e); err != nil {
					return err
				}
			}
			return nil
		}
		if id == nil {
			if u.Disabled {
				return end("account disabled")
			}
			return end("not in the directory")
		}

		var roles []int64
		norm, invalid := NormalizeDNs(id.Groups)
		if len(invalid) > 0 {
			r.logger().Warn("LDAP returned group DNs that don't parse; they can't match a role", "user", u.Username, "dns", invalid)
		}
		if len(norm) > 0 {
			if roles, err = q.ListRoleIDsForLDAPGroups(ctx, norm); err != nil {
				return err
			}
		}
		if len(roles) == 0 {
			return end("no role maps to their groups")
		}

		if dn := (sql.NullString{String: id.DN, Valid: true}); u.LdapDn != dn {
			if err := q.SetUserLDAPDN(ctx, db.SetUserLDAPDNParams{LdapDn: dn, ID: u.ID}); err != nil {
				return err
			}
		}
		// What the user held before: their sessions' roles, or with no session, their tokens'.
		var current []int64
		if len(sessions) > 0 {
			current, err = q.ListSessionRoleIDsForUser(ctx, u.ID)
		} else {
			current, err = q.ListLiveLDAPTokenRoleIDsForUser(ctx, db.ListLiveLDAPTokenRoleIDsForUserParams{UserID: u.ID, Now: store.Millis(now)})
		}
		if err != nil {
			return err
		}
		if !slices.Equal(current, roles) {
			entry.Detail["roles_added"] = difference(roles, current)
			entry.Detail["roles_removed"] = difference(current, roles)
			changed = true
		}
		if len(sessions) > 0 && !slices.Equal(current, roles) {
			if err := q.ClearSessionRolesForUser(ctx, u.ID); err != nil {
				return err
			}
			for _, role := range roles {
				if err := q.AddSessionRoleForUser(ctx, db.AddSessionRoleForUserParams{RoleID: role, UserID: u.ID}); err != nil {
					return err
				}
			}
		}
		// Every live token gets the roles, whatever it held: tokens made at different times can differ, and writing a
		// few rows is cheaper than comparing each.
		for _, tk := range tokens {
			if err := q.ClearAPITokenRoles(ctx, tk.ID); err != nil {
				return err
			}
			for _, role := range roles {
				if err := q.AddAPITokenRole(ctx, db.AddAPITokenRoleParams{TokenID: tk.ID, RoleID: role}); err != nil {
					return err
				}
			}
		}
		if err := q.SetUserSessionsRolesChecked(ctx, db.SetUserSessionsRolesCheckedParams{RolesCheckedAt: store.Millis(now), UserID: u.ID}); err != nil {
			return err
		}
		if err := q.SetUserTokensRolesChecked(ctx, db.SetUserTokensRolesCheckedParams{
			RolesCheckedAt: sql.NullInt64{Int64: store.Millis(now), Valid: true}, UserID: u.ID,
		}); err != nil {
			return err
		}
		if !changed {
			return nil
		}
		_, err = audit.Insert(ctx, q, entry)
		return err
	})
	if err != nil {
		return err
	}
	if changed {
		r.Audit.Log(entry)
		for _, e := range revoked {
			r.Audit.Log(e)
		}
	}
	return nil
}

// difference returns the IDs in a that aren't in b.
func difference(a, b []int64) []int64 {
	out := []int64{}
	for _, v := range a {
		if !slices.Contains(b, v) {
			out = append(out, v)
		}
	}
	return out
}
