// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package rbac

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/auth"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

var t0 = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

// env is a database with the builtin admin role, some instances and groups, and helpers to add users, roles and
// sessions directly (bypassing the Manager, so tests can set up states the Manager would refuse).
type env struct {
	t     *testing.T
	ctx   context.Context
	st    *store.Store
	m     *Manager
	admin int64 // builtin admin role ID

	inst1, inst2, inst3 int64 // inst1 and inst2 are in the independent group; inst2 and inst3 in the mirrored one
	indep, mirror       int64
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, ctx: context.Background(), st: openStore(t)}
	e.m = &Manager{Store: e.st, Audit: audit.NewLogger(io.Discard), Now: func() time.Time { return t0 }}
	e.tx(func(q *db.Queries) error {
		r, err := q.GetBuiltinRole(e.ctx)
		e.admin = r.ID
		if err != nil {
			return err
		}
		mk := func(name, env string) int64 {
			id, err := q.CreateInstance(e.ctx, db.CreateInstanceParams{Name: name, BaseUrl: "https://" + name, EnvName: env, TlsMode: "verify", CreatedAt: 1})
			if err != nil {
				t.Fatal(err)
			}
			return id
		}
		e.inst1, e.inst2, e.inst3 = mk("one", "ONE"), mk("two", "TWO"), mk("three", "THREE")
		if e.indep, err = q.CreateInstanceGroup(e.ctx, db.CreateInstanceGroupParams{Name: "site", Mode: "independent", CreatedAt: 1}); err != nil {
			return err
		}
		if e.mirror, err = q.CreateInstanceGroup(e.ctx, db.CreateInstanceGroupParams{
			Name: "pair", Mode: "mirrored", PrimaryInstanceID: sql.NullInt64{Int64: e.inst2, Valid: true}, CreatedAt: 1,
		}); err != nil {
			return err
		}
		for _, m := range []db.AddInstanceGroupMemberParams{
			{GroupID: e.indep, InstanceID: e.inst1}, {GroupID: e.indep, InstanceID: e.inst2},
			{GroupID: e.mirror, InstanceID: e.inst2}, {GroupID: e.mirror, InstanceID: e.inst3},
		} {
			if err := q.AddInstanceGroupMember(e.ctx, m); err != nil {
				return err
			}
		}
		return nil
	})
	return e
}

func (e *env) tx(fn func(q *db.Queries) error) {
	e.t.Helper()
	if err := e.st.WithTx(e.ctx, fn); err != nil {
		e.t.Fatal(err)
	}
}

// role creates a role with grants, directly.
func (e *env) role(name string, grants ...Grant) int64 {
	e.t.Helper()
	var id int64
	e.tx(func(q *db.Queries) error {
		var err error
		if id, err = q.CreateRole(e.ctx, db.CreateRoleParams{Name: name, CreatedAt: 1}); err != nil {
			return err
		}
		t := &txn{ctx: e.ctx, q: q}
		return t.insertGrants(id, grants)
	})
	return id
}

// local creates an enabled local user with roles, directly.
func (e *env) local(name string, roles ...int64) int64 {
	e.t.Helper()
	var id int64
	e.tx(func(q *db.Queries) error {
		u, err := q.CreateLocalUser(e.ctx, db.CreateLocalUserParams{Username: name, PasswordHash: sql.NullString{String: "x", Valid: true}, CreatedAt: 1})
		if err != nil {
			return err
		}
		id = u.ID
		for _, r := range roles {
			if err := q.AddUserRole(e.ctx, db.AddUserRoleParams{UserID: id, RoleID: r}); err != nil {
				return err
			}
		}
		return nil
	})
	return id
}

// ldapUser creates an LDAP user row.
func (e *env) ldapUser(name string) int64 {
	e.t.Helper()
	var id int64
	e.tx(func(q *db.Queries) error {
		var err error
		id, err = q.CreateLDAPUser(e.ctx, db.CreateLDAPUserParams{Username: name, LdapDn: sql.NullString{String: "uid=" + name + ",dc=example", Valid: true}, CreatedAt: 1})
		return err
	})
	return id
}

// session creates a session for a user holding roles, checked at checkedAt, and returns its public ID.
func (e *env) session(userID int64, checkedAt time.Time, roles ...int64) string {
	e.t.Helper()
	raw := make([]byte, 32)
	rand.Read(raw)
	hash := sha256.Sum256(raw)
	pub := make([]byte, 16)
	rand.Read(pub)
	publicID := base64.RawURLEncoding.EncodeToString(pub)
	e.tx(func(q *db.Queries) error {
		if err := q.CreateSession(e.ctx, db.CreateSessionParams{
			IDHash: hash[:], PublicID: publicID, UserID: userID, CreatedAt: 1, ExpiresAt: store.Millis(t0.Add(time.Hour)),
			LastSeenAt: 1, RolesCheckedAt: store.Millis(checkedAt),
		}); err != nil {
			return err
		}
		for _, r := range roles {
			if err := q.AddSessionRole(e.ctx, db.AddSessionRoleParams{SessionIDHash: hash[:], RoleID: r}); err != nil {
				return err
			}
		}
		return nil
	})
	return publicID
}

// actor returns an Actor for a user, with their roles as a session would hold them.
func (e *env) actor(userID int64) Actor {
	e.t.Helper()
	q := e.st.Read()
	u, err := q.GetUser(e.ctx, userID)
	if err != nil {
		e.t.Fatal(err)
	}
	var roles []int64
	if auth.Method(u.Source) == auth.MethodLocal {
		roles, err = q.ListUserRoleIDs(e.ctx, userID)
	} else {
		roles, err = q.ListSessionRoleIDsForUser(e.ctx, userID)
	}
	if err != nil {
		e.t.Fatal(err)
	}
	return Actor{UserID: u.ID, Username: u.Username, Source: auth.Method(u.Source), RoleIDs: roles, IP: "192.0.2.1"}
}

func (e *env) grants(roleID int64) []Grant {
	e.t.Helper()
	gs, err := roleGrants(e.ctx, e.st.Read(), []int64{roleID})
	if err != nil {
		e.t.Fatal(err)
	}
	SortGrants(gs)
	return gs
}

func (e *env) userRoles(userID int64) []int64 {
	e.t.Helper()
	ids, err := e.st.Read().ListUserRoleIDs(e.ctx, userID)
	if err != nil {
		e.t.Fatal(err)
	}
	return ids
}

func (e *env) sessions(userID int64) []db.Session {
	e.t.Helper()
	s, err := e.st.Read().ListUserSessions(e.ctx, userID)
	if err != nil {
		e.t.Fatal(err)
	}
	return s
}

func (e *env) sessionRoles(s db.Session) []int64 {
	e.t.Helper()
	ids, err := e.st.Read().ListSessionRoleIDs(e.ctx, s.IDHash)
	if err != nil {
		e.t.Fatal(err)
	}
	return ids
}

// lastAudit returns the newest audit row.
func (e *env) lastAudit() db.AuditLog {
	e.t.Helper()
	rows, err := e.st.Read().ListRecentAudit(e.ctx, 1)
	if err != nil || len(rows) == 0 {
		e.t.Fatalf("no audit rows (%v)", err)
	}
	return rows[0]
}

func (e *env) auditCount() int {
	e.t.Helper()
	rows, err := e.st.Read().ListRecentAudit(e.ctx, 1000)
	if err != nil {
		e.t.Fatal(err)
	}
	return len(rows)
}

func detail(t *testing.T, row db.AuditLog) map[string]any {
	t.Helper()
	var d map[string]any
	if err := json.Unmarshal([]byte(row.Detail), &d); err != nil {
		t.Fatal(err)
	}
	return d
}

// wantCode fails unless err is an *Error with code ("" means no error).
func wantCode(t *testing.T, err error, code Code) {
	t.Helper()
	if code == "" {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	if !IsCode(err, code) {
		t.Fatalf("error = %v, want code %s", err, code)
	}
}

// wantDenied checks that the last audit row records a refusal of the given action.
func wantDenied(t *testing.T, e *env, action string) {
	t.Helper()
	row := e.lastAudit()
	if row.Action != audit.ActionPermissionDenied || row.Result != audit.ResultFailure || detail(t, row)["attempted"] != action {
		t.Errorf("last audit row = %s %s %s, want permission_denied for %s", row.Action, row.Result, row.Detail, action)
	}
}
