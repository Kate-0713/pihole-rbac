// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// nextTokenID makes the test tokens' public IDs unique.
var nextTokenID atomic.Int64

// token gives a user an API token directly, holding roles last checked at checked and expiring at expires.
func (e *recheckEnv) token(userID int64, name string, checked, expires time.Time, roles ...int64) int64 {
	e.t.Helper()
	ctx := context.Background()
	var id int64
	err := e.st.WithTx(ctx, func(q *db.Queries) error {
		var err error
		id, err = q.InsertAPIToken(ctx, db.InsertAPITokenParams{
			PublicID: fmt.Sprintf("token%011d", nextTokenID.Add(1)), UserID: userID, Name: name,
			SecretHash: make([]byte, 32), CreatedAt: store.Millis(checked), ExpiresAt: store.Millis(expires),
			RolesCheckedAt: sql.NullInt64{Int64: store.Millis(checked), Valid: true},
		})
		if err != nil {
			return err
		}
		for _, r := range roles {
			if err := q.AddAPITokenRole(ctx, db.AddAPITokenRoleParams{TokenID: id, RoleID: r}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return id
}

type tokenState struct {
	roles     []int64
	checked   time.Time
	revoked   bool
	revokedBy string
	reason    string
}

func (e *recheckEnv) tokenState(id int64) tokenState {
	e.t.Helper()
	ctx := context.Background()
	q := e.st.Read()
	rows, err := q.ListAllAPITokens(ctx)
	if err != nil {
		e.t.Fatal(err)
	}
	for _, r := range rows {
		if r.ID != id {
			continue
		}
		roles, err := q.ListAPITokenRoleIDs(ctx, id)
		if err != nil {
			e.t.Fatal(err)
		}
		return tokenState{
			roles: roles, checked: store.FromMillis(r.RolesCheckedAt.Int64), revoked: r.RevokedAt.Valid,
			revokedBy: r.RevokedBy.String, reason: r.RevokedReason.String,
		}
	}
	e.t.Fatalf("no token %d", id)
	return tokenState{}
}

func (e *recheckEnv) setDisabled(userID int64, disabled bool) {
	e.t.Helper()
	ctx := context.Background()
	if err := e.st.WithTx(ctx, func(q *db.Queries) error {
		return q.SetUserDisabled(ctx, db.SetUserDisabledParams{Disabled: disabled, ID: userID})
	}); err != nil {
		e.t.Fatal(err)
	}
}

// A user with a token and no session is rechecked when the token is due: every live token gets the roles the
// directory maps to now, the clock moves, and the change is audited once.
func TestRecheckTokensWithoutASession(t *testing.T) {
	e := newRecheckEnv(t)
	staff := e.mappedRole("staff", staffDN)
	admins := e.mappedRole("admins", adminsDN)
	alice := e.createLDAPUser("alice")
	far := e.now.Add(30 * 24 * time.Hour)
	older := e.token(alice, "cron", e.now.Add(-time.Minute), far, staff)
	newer := e.token(alice, "home assistant", e.now, far, staff, admins)
	e.in("alice", "CN=alice,DC=example", adminsDN)

	e.now = e.now.Add(9*time.Minute + 30*time.Second) // the older token is due, the newer isn't yet
	e.run()
	if !slices.Equal(e.dir.asked, []string{"alice"}) {
		t.Fatalf("asked %v, want alice", e.dir.asked)
	}
	for _, id := range []int64{older, newer} {
		st := e.tokenState(id)
		if !slices.Equal(st.roles, []int64{admins}) || !st.checked.Equal(e.now) || st.revoked {
			t.Errorf("token %d: %+v, want roles [%d] checked now", id, st, admins)
		}
	}
	rows := e.audits()
	if len(rows) != 1 || rows[0].Action != audit.ActionLDAPRecheck {
		t.Fatalf("audit rows %v, want one ldap_recheck", rows)
	}
	var d struct {
		Added   []int64 `json:"roles_added"`
		Removed []int64 `json:"roles_removed"`
	}
	// With no session, what she held is read from her tokens: staff and admins between them.
	if err := json.Unmarshal([]byte(rows[0].Detail), &d); err != nil || len(d.Added) != 0 || !slices.Equal(d.Removed, []int64{staff}) {
		t.Errorf("detail %s (%v)", rows[0].Detail, err)
	}
}

// Nobody is looked up for a token that isn't due, has expired or is revoked.
func TestRecheckOnlyLiveDueTokens(t *testing.T) {
	e := newRecheckEnv(t)
	staff := e.mappedRole("staff", staffDN)
	start := e.now
	e.token(e.createLDAPUser("fresh"), "t", start.Add(5*time.Minute), start.Add(time.Hour), staff)
	e.token(e.createLDAPUser("expired"), "t", start, start.Add(5*time.Minute), staff)
	revoked := e.token(e.createLDAPUser("revoked"), "t", start, start.Add(time.Hour), staff)
	if err := e.st.WithTx(context.Background(), func(q *db.Queries) error {
		_, err := q.RevokeAPIToken(context.Background(), db.RevokeAPITokenParams{ID: revoked, RevokedAt: sql.NullInt64{Int64: 1, Valid: true}})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	e.now = start.Add(11 * time.Minute)
	e.run()
	if len(e.dir.asked) != 0 {
		t.Fatalf("asked %v, want nobody", e.dir.asked)
	}
}

// No role left, or gone from the directory: the sessions end and the tokens are revoked, each audited.
func TestRecheckRevokesTokensWhenNothingIsLeft(t *testing.T) {
	for _, tt := range []struct {
		name   string
		setup  func(e *recheckEnv)
		reason string
	}{
		{"removed from every mapped group", func(e *recheckEnv) { e.in("alice", "CN=alice,DC=example", "CN=Unrelated,DC=example") }, "no role maps to their groups"},
		{"gone from the directory", func(e *recheckEnv) { delete(e.dir.users, "alice") }, "not in the directory"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e := newRecheckEnv(t)
			staff := e.mappedRole("staff", staffDN)
			alice := e.createLDAPUser("alice")
			c := e.login(alice, staff)
			tok := e.token(alice, "cron", e.now, e.now.Add(time.Hour), staff)
			tt.setup(e)

			e.now = e.now.Add(11 * time.Minute)
			e.run()
			if e.valid(c) {
				t.Error("the session survived")
			}
			if st := e.tokenState(tok); !st.revoked || st.revokedBy != "recheck" || st.reason != tt.reason {
				t.Errorf("the token wasn't revoked by the recheck with its reason: %+v", st)
			}
			var actions []string
			for _, r := range e.audits() {
				actions = append(actions, r.Action)
				if r.Action == audit.ActionTokenRevoke {
					var d map[string]any
					_ = json.Unmarshal([]byte(r.Detail), &d)
					if d["by"] != "recheck" || d["reason"] != tt.reason || r.Target != "token:alice/cron" {
						t.Errorf("token_revoke row %+v", r)
					}
				}
			}
			if !slices.Equal(actions, []string{audit.ActionLDAPRecheck, audit.ActionTokenRevoke}) {
				t.Errorf("audit actions %v", actions)
			}
			if n := strings.Count(e.auditB.String(), "AUDIT "); n != 2 {
				t.Errorf("%d AUDIT lines, want 2", n)
			}
		})
	}
}

// A disabled user's tokens are left alone: not looked up for, not revoked when their due sessions are removed, and
// rechecked once the account is enabled again.
func TestRecheckLeavesDisabledUsersTokens(t *testing.T) {
	e := newRecheckEnv(t)
	staff := e.mappedRole("staff", staffDN)
	alice := e.createLDAPUser("alice")
	tok := e.token(alice, "cron", e.now, e.now.Add(48*time.Hour), staff)
	e.in("alice", "CN=alice,DC=example", staffDN)
	e.setDisabled(alice, true)

	e.now = e.now.Add(11 * time.Minute)
	e.run()
	if len(e.dir.asked) != 0 {
		t.Fatalf("asked %v for a disabled user's token", e.dir.asked)
	}

	// A due session of hers is removed, without a lookup, and the token stays.
	c := e.login(alice, staff)
	e.now = e.now.Add(11 * time.Minute)
	e.run()
	if e.valid(c) || len(e.dir.asked) != 0 {
		t.Fatalf("session valid %v, asked %v", e.valid(c), e.dir.asked)
	}
	if st := e.tokenState(tok); st.revoked || !slices.Equal(st.roles, []int64{staff}) {
		t.Fatalf("the token was touched: %+v", st)
	}

	// Enabled again, the next pass rechecks it.
	e.setDisabled(alice, false)
	e.run()
	if st := e.tokenState(tok); !st.checked.Equal(e.now) || st.revoked {
		t.Errorf("after enabling: %+v", st)
	}
}

// A directory that can't be reached changes nothing: the token keeps its roles and its old check time, so the API
// suspends it once the grace period runs out, and a later pass resumes it.
func TestRecheckDirectoryFailureLeavesTokens(t *testing.T) {
	e := newRecheckEnv(t)
	staff := e.mappedRole("staff", staffDN)
	alice := e.createLDAPUser("alice")
	start := e.now
	tok := e.token(alice, "cron", start, start.Add(48*time.Hour), staff)
	e.dir.users["alice"] = lookupResult{err: errors.New("connection refused")}

	e.now = start.Add(11 * time.Minute)
	e.run()
	if st := e.tokenState(tok); st.revoked || !st.checked.Equal(start) || !slices.Equal(st.roles, []int64{staff}) {
		t.Fatalf("after a failed lookup: %+v", st)
	}
	if len(e.audits()) != 0 {
		t.Error("a failed lookup was audited")
	}
	e.in("alice", "CN=alice,DC=example", staffDN)
	e.now = start.Add(60 * time.Minute)
	e.run()
	if st := e.tokenState(tok); !st.checked.Equal(e.now) {
		t.Errorf("after the directory came back: %+v", st)
	}
}
