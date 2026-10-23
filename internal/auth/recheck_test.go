// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

type lookupResult struct {
	id  *Identity
	err error
}

// fakeLookup is a Directory that answers from a map and records who was asked.
type fakeLookup struct {
	users map[string]lookupResult
	asked []string
}

func (f *fakeLookup) Lookup(_ context.Context, username string) (*Identity, error) {
	f.asked = append(f.asked, username)
	r, ok := f.users[username]
	if !ok {
		return nil, ErrNoSuchUser
	}
	return r.id, r.err
}

type recheckEnv struct {
	*sessionEnv
	dir    *fakeLookup
	r      *Rechecker
	auditB *bytes.Buffer
}

func newRecheckEnv(t *testing.T) *recheckEnv {
	t.Helper()
	e := &recheckEnv{sessionEnv: newSessionEnv(t, SessionOptions{IdleTimeout: 24 * time.Hour}), dir: &fakeLookup{users: map[string]lookupResult{}}, auditB: &bytes.Buffer{}}
	e.r = &Rechecker{
		Store:     e.st,
		Audit:     audit.NewLogger(e.auditB),
		Directory: func() Directory { return e.dir },
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:       func() time.Time { return e.now },
	}
	return e
}

// mappedRole makes a role that the group DN maps to.
func (e *recheckEnv) mappedRole(name, groupDN string) int64 {
	e.t.Helper()
	ctx := context.Background()
	var id int64
	err := e.st.WithTx(ctx, func(q *db.Queries) error {
		var err error
		if id, err = q.CreateRole(ctx, db.CreateRoleParams{Name: name, CreatedAt: 1}); err != nil {
			return err
		}
		norm, err := NormalizeDN(groupDN)
		if err != nil {
			return err
		}
		return q.AddRoleLDAPGroup(ctx, db.AddRoleLDAPGroupParams{RoleID: id, GroupDn: groupDN, GroupDnNorm: norm, CreatedAt: 1})
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return id
}

func (e *recheckEnv) in(username, dn string, groups ...string) {
	e.dir.users[username] = lookupResult{id: &Identity{Username: username, Source: MethodLDAP, DN: dn, Groups: groups}}
}

func (e *recheckEnv) run() {
	e.t.Helper()
	if err := e.r.RunOnce(context.Background()); err != nil {
		e.t.Fatal(err)
	}
}

func (e *recheckEnv) rolesOf(c *http.Cookie) []int64 {
	e.t.Helper()
	s, err := e.get(c)
	if err != nil {
		e.t.Fatalf("session: %v", err)
	}
	return s.RoleIDs
}

func (e *recheckEnv) audits() []db.AuditLog {
	e.t.Helper()
	rows, err := e.st.Read().ListRecentAudit(context.Background(), 100)
	if err != nil {
		e.t.Fatal(err)
	}
	slices.Reverse(rows)
	return rows
}

func (e *recheckEnv) checkedAt(userID int64) []time.Time {
	e.t.Helper()
	rows, err := e.st.Read().ListUserSessions(context.Background(), userID)
	if err != nil {
		e.t.Fatal(err)
	}
	var out []time.Time
	for _, r := range rows {
		out = append(out, store.FromMillis(r.RolesCheckedAt))
	}
	return out
}

const (
	staffDN  = "CN=Staff,OU=Groups,DC=example,DC=local"
	adminsDN = "CN=Admins,OU=Groups,DC=example,DC=local"
)

func TestRecheckOnlyLooksAtUsersThatAreDue(t *testing.T) {
	e := newRecheckEnv(t)
	staff := e.mappedRole("staff", staffDN)
	alice := e.createLDAPUser("alice")
	e.login(alice, staff)
	e.createUser("local-bob") // local users have no directory entry
	e.login(e.createUser("local-carol"), staff)
	e.in("alice", "CN=alice,DC=example", staffDN)

	e.now = e.now.Add(9 * time.Minute)
	e.run()
	if len(e.dir.asked) != 0 {
		t.Fatalf("asked %v before the interval was up", e.dir.asked)
	}

	e.now = e.now.Add(time.Minute) // exactly 10 minutes
	e.run()
	if !slices.Equal(e.dir.asked, []string{"alice"}) {
		t.Fatalf("asked %v, want only alice", e.dir.asked)
	}
}

func TestRecheckUnchangedRolesOnlyMoveTheClock(t *testing.T) {
	e := newRecheckEnv(t)
	staff := e.mappedRole("staff", staffDN)
	alice := e.createLDAPUser("alice")
	c1, c2 := e.login(alice, staff), e.login(alice, staff)
	e.in("alice", "CN=alice,DC=example", staffDN, "CN=Unmapped,DC=example")

	e.now = e.now.Add(11 * time.Minute)
	e.run()

	for _, got := range e.checkedAt(alice) {
		if !got.Equal(e.now) {
			t.Fatalf("roles_checked_at = %v, want %v on every session", got, e.now)
		}
	}
	if !slices.Equal(e.rolesOf(c1), []int64{staff}) || !slices.Equal(e.rolesOf(c2), []int64{staff}) {
		t.Fatal("roles changed")
	}
	if rows := e.audits(); len(rows) != 0 || e.auditB.Len() != 0 {
		t.Fatalf("an unchanged recheck was audited: %v", rows)
	}
}

func TestRecheckReplacesRolesInAllSessionsAndAuditsOnce(t *testing.T) {
	e := newRecheckEnv(t)
	staff := e.mappedRole("staff", staffDN)
	admins := e.mappedRole("admins", adminsDN)
	alice := e.createLDAPUser("alice")
	c1, c2 := e.login(alice, staff), e.login(alice, staff)
	// Moved from Staff to Admins, and renamed in the directory.
	e.in("alice", "CN=Alice Renamed,DC=example", adminsDN)

	e.now = e.now.Add(11 * time.Minute)
	e.run()

	for i, c := range []*http.Cookie{c1, c2} {
		if got := e.rolesOf(c); !slices.Equal(got, []int64{admins}) {
			t.Fatalf("session %d roles = %v, want [%d]", i+1, got, admins)
		}
	}
	u, err := e.st.Read().GetUser(context.Background(), alice)
	if err != nil || u.LdapDn.String != "CN=Alice Renamed,DC=example" {
		t.Fatalf("user = %+v, %v", u, err)
	}

	rows := e.audits()
	if len(rows) != 1 {
		t.Fatalf("audit rows = %d, want one per user: %v", len(rows), rows)
	}
	r := rows[0]
	if r.Action != audit.ActionLDAPRecheck || r.Username != "alice" || r.Result != audit.ResultSuccess || r.UserID.Int64 != alice {
		t.Fatalf("row = %+v", r)
	}
	var d struct {
		Added   []int64 `json:"roles_added"`
		Removed []int64 `json:"roles_removed"`
	}
	if err := json.Unmarshal([]byte(r.Detail), &d); err != nil || !slices.Equal(d.Added, []int64{admins}) || !slices.Equal(d.Removed, []int64{staff}) {
		t.Fatalf("detail = %s (%v)", r.Detail, err)
	}
	if n := strings.Count(e.auditB.String(), "AUDIT "); n != 1 || !strings.Contains(e.auditB.String(), "action=ldap_recheck") {
		t.Fatalf("AUDIT lines = %q", e.auditB.String())
	}

	// A second pass right away finds nothing due and says nothing.
	e.run()
	if len(e.audits()) != 1 {
		t.Fatal("second pass was audited")
	}
}

func TestRecheckEndsSessionsWhenNothingIsLeft(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(e *recheckEnv)
		reason string
	}{
		{"removed from every mapped group", func(e *recheckEnv) {
			e.in("alice", "CN=alice,DC=example", "CN=Unrelated,DC=example")
		}, "no role maps to their groups"},
		{"no groups at all", func(e *recheckEnv) { e.in("alice", "CN=alice,DC=example") }, "no role maps to their groups"},
		{"gone from the directory", func(e *recheckEnv) { delete(e.dir.users, "alice") }, "not in the directory"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newRecheckEnv(t)
			staff := e.mappedRole("staff", staffDN)
			alice := e.createLDAPUser("alice")
			c1, c2 := e.login(alice, staff), e.login(alice, staff)
			bob := e.createLDAPUser("bob")
			cb := e.login(bob, staff)
			e.in("bob", "CN=bob,DC=example", staffDN)
			tt.setup(e)

			e.now = e.now.Add(11 * time.Minute)
			e.run()

			if e.valid(c1) || e.valid(c2) {
				t.Fatal("alice's sessions survived")
			}
			if !e.valid(cb) {
				t.Fatal("bob's session ended")
			}
			rows := e.audits()
			if len(rows) != 1 || rows[0].Action != audit.ActionLDAPRecheck || rows[0].Username != "alice" {
				t.Fatalf("audit = %+v", rows)
			}
			var d struct {
				Reason string `json:"reason"`
				Ended  int    `json:"sessions_ended"`
			}
			if err := json.Unmarshal([]byte(rows[0].Detail), &d); err != nil || d.Reason != tt.reason || d.Ended != 2 {
				t.Fatalf("detail = %s (%v)", rows[0].Detail, err)
			}
		})
	}
}

func TestRecheckDirectoryFailureChangesNothing(t *testing.T) {
	e := newRecheckEnv(t)
	staff := e.mappedRole("staff", staffDN)
	alice, bob := e.createLDAPUser("alice"), e.createLDAPUser("bob")
	ca, cb := e.login(alice, staff), e.login(bob, staff)
	e.dir.users["alice"] = lookupResult{err: errors.New("connecting to LDAP: i/o timeout")}
	e.in("bob", "CN=bob,DC=example", "CN=Unrelated,DC=example")

	e.now = e.now.Add(11 * time.Minute)
	e.run()

	// One failure stops the pass: the directory is down, so asking again would only wait for another timeout.
	if !slices.Equal(e.dir.asked, []string{"alice"}) {
		t.Fatalf("asked %v", e.dir.asked)
	}
	if !e.valid(ca) || !e.valid(cb) || !slices.Equal(e.rolesOf(ca), []int64{staff}) {
		t.Fatal("a session or its roles changed while the directory was down")
	}
	if len(e.audits()) != 0 || e.auditB.Len() != 0 {
		t.Fatal("a directory failure was audited")
	}
	for _, got := range e.checkedAt(alice) {
		if got.Equal(e.now) {
			t.Fatal("roles_checked_at moved without a successful check")
		}
	}

	// The grace period then does its job: 41 minutes after the last check, the session is refused.
	e.now = e.now.Add(30 * time.Minute)
	if e.valid(ca) {
		t.Fatal("session outlived interval + grace with the directory down")
	}
}

func TestRecheckRecoversAfterAnOutage(t *testing.T) {
	e := newRecheckEnv(t)
	staff := e.mappedRole("staff", staffDN)
	alice := e.createLDAPUser("alice")
	c := e.login(alice, staff)
	e.dir.users["alice"] = lookupResult{err: errors.New("down")}

	e.now = e.now.Add(11 * time.Minute)
	e.run()
	e.now = e.now.Add(10 * time.Minute) // 21 minutes: past the interval, inside the grace period
	e.in("alice", "CN=alice,DC=example", staffDN)
	e.run()

	e.now = e.now.Add(35 * time.Minute) // 35 minutes after the successful check
	if !e.valid(c) {
		t.Fatal("session ended although the recheck succeeded 35 minutes ago")
	}
}

func TestRecheckDisabledUsersSessionsAreRemovedWithoutALookup(t *testing.T) {
	e := newRecheckEnv(t)
	staff := e.mappedRole("staff", staffDN)
	alice := e.createLDAPUser("alice")
	e.login(alice, staff)
	if err := e.st.WithTx(context.Background(), func(q *db.Queries) error {
		return q.SetUserDisabled(context.Background(), db.SetUserDisabledParams{Disabled: true, ID: alice})
	}); err != nil {
		t.Fatal(err)
	}

	e.now = e.now.Add(11 * time.Minute)
	e.run()

	if len(e.dir.asked) != 0 {
		t.Fatalf("asked %v about a disabled user", e.dir.asked)
	}
	if left, _ := e.st.Read().ListUserSessions(context.Background(), alice); len(left) != 0 {
		t.Fatalf("%d sessions left", len(left))
	}
	if len(e.audits()) != 0 {
		t.Fatal("cleaning up a disabled user's sessions was audited; disabling already was")
	}
}

func TestRecheckWithoutADirectoryChangesNothing(t *testing.T) {
	e := newRecheckEnv(t)
	staff := e.mappedRole("staff", staffDN)
	c := e.login(e.createLDAPUser("alice"), staff)
	e.r.Directory = func() Directory { return nil }

	e.now = e.now.Add(11 * time.Minute)
	e.run()
	if !e.valid(c) {
		t.Fatal("session ended")
	}
}

func TestRecheckHonoursMarkedSessions(t *testing.T) {
	e := newRecheckEnv(t)
	staff := e.mappedRole("staff", staffDN)
	alice := e.createLDAPUser("alice")
	c := e.login(alice, staff)
	e.in("alice", "CN=alice,DC=example", "CN=Unrelated,DC=example")

	// Removing a mapping makes the sessions holding the role due at once, without waiting out the interval.
	e.now = e.now.Add(2 * time.Minute)
	if err := e.st.WithTx(context.Background(), func(q *db.Queries) error {
		_, err := q.MarkRoleSessionsDue(context.Background(), db.MarkRoleSessionsDueParams{Due: store.Millis(e.now.Add(-DefaultRecheckInterval)), RoleID: staff})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	e.run()
	if e.valid(c) {
		t.Fatal("marked session wasn't rechecked on the next pass")
	}
}
