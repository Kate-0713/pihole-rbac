// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package instances

import (
	"database/sql"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

type tokenState int

const (
	live tokenState = iota
	revoked
	expired
)

// token gives the admin user an API token named name with p on an instance or group, directly.
func (e *svcEnv) token(name string, state tokenState, p rbac.Permission, instance, group int64) {
	e.t.Helper()
	e.tx(func(q *db.Queries) error {
		expires := t0.Add(time.Hour)
		if state == expired {
			expires = t0.Add(-time.Hour)
		}
		id, err := q.InsertAPIToken(e.ctx, db.InsertAPITokenParams{
			PublicID: fmt.Sprintf("%-16s", name)[:16], UserID: e.admin.UserID, Name: name, SecretHash: make([]byte, 32),
			CreatedAt: store.Millis(t0.Add(-2 * time.Hour)), ExpiresAt: store.Millis(expires),
		})
		if err != nil {
			return err
		}
		if state == revoked {
			if _, err := q.RevokeAPIToken(e.ctx, db.RevokeAPITokenParams{ID: id, RevokedAt: sql.NullInt64{Int64: 1, Valid: true}}); err != nil {
				return err
			}
		}
		p := db.InsertAPITokenGrantParams{TokenID: id, Permission: string(p), ScopeType: "instance", InstanceID: sql.NullInt64{Int64: instance, Valid: true}}
		if group != 0 {
			p.ScopeType, p.InstanceID, p.GroupID = "group", sql.NullInt64{}, sql.NullInt64{Int64: group, Valid: true}
		}
		return q.InsertAPITokenGrant(e.ctx, p)
	})
}

func TestDeleteInstanceUsedByToken(t *testing.T) {
	e := newSvcEnv(t)
	a, b, _ := e.threeInstances()
	e.token("cron", live, rbac.DomainsView, a, 0)
	e.token("old", revoked, rbac.DomainsView, b, 0)
	e.token("lapsed", expired, rbac.DomainsEdit, b, 0)

	err := e.svc.Delete(e.ctx, e.admin, a)
	wantCode(t, err, rbac.CodeConflict, "")
	if ee, _ := rbac.AsError(err); !slices.Equal(ee.Details["api_tokens"].([]string), []string{`"cron" (alice)`}) ||
		!strings.Contains(ee.Message, `1 API token "cron" (alice)`) {
		t.Errorf("refusal %q, details %v", ee.Message, ee.Details)
	}

	// Revoked and expired tokens don't hold an instance up, and their grants on it go with it.
	if err := e.svc.Delete(e.ctx, e.admin, b); err != nil {
		t.Fatalf("deleting an instance only dead tokens name: %v", err)
	}
	toks, err := rbac.ListUserTokens(e.ctx, e.st.Read(), e.admin.UserID, t0)
	if err != nil {
		t.Fatal(err)
	}
	for _, tk := range toks {
		if want := tk.Name == "cron"; (len(tk.Grants) == 1) != want {
			t.Errorf("%s has grants %v", tk.Name, tk.Grants)
		}
	}
}

func TestDeleteGroupUsedByToken(t *testing.T) {
	e := newSvcEnv(t)
	a, b, c := e.threeInstances()
	used := e.createGroup(GroupInput{Name: "site", Mode: rbac.Mirrored, Primary: a, Members: []int64{a, b}})
	free := e.createGroup(GroupInput{Name: "spare", Mode: rbac.Independent, Members: []int64{c}})
	e.token("drift monitor", live, rbac.DriftView, 0, used.ID)
	e.token("old", revoked, rbac.DomainsView, 0, free.ID)
	e.token("lapsed", expired, rbac.DomainsView, 0, free.ID)

	err := e.svc.DeleteGroup(e.ctx, e.admin, used.ID)
	wantCode(t, err, rbac.CodeConflict, "")
	if ee, _ := rbac.AsError(err); !slices.Equal(ee.Details["api_tokens"].([]string), []string{`"drift monitor" (alice)`}) ||
		len(ee.Details["roles"].([]string)) != 0 {
		t.Errorf("details %v", ee.Details)
	}
	if err := e.svc.DeleteGroup(e.ctx, e.admin, free.ID); err != nil {
		t.Fatalf("deleting a group only dead tokens name: %v", err)
	}

	// A live token's mirrored-group permission also keeps the group mirrored.
	_, err = e.svc.UpdateGroup(e.ctx, e.admin, used.ID, GroupInput{Name: "site", Mode: rbac.Independent, Members: []int64{a, b}})
	wantCode(t, err, rbac.CodeInvariant, "")
}
