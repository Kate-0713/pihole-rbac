// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/Kate-0713/pihole-rbac/internal/auth"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// stubLDAP answers like LDAPAuthenticator: a known username with the right password gets an identity with the
// configured DN and groups.
type stubLDAP struct {
	users map[string]stubLDAPUser
}

type stubLDAPUser struct {
	password string
	dn       string
	groups   []string
}

func (s *stubLDAP) Authenticate(_ context.Context, username, password string) (*auth.Identity, error) {
	username = auth.NormalizeUsername(username)
	u, ok := s.users[username]
	if !ok || password != u.password {
		return nil, auth.ErrInvalidCredentials
	}
	return &auth.Identity{Username: username, Source: auth.MethodLDAP, DN: u.dn, Groups: u.groups}, nil
}

const adminGroupDN = "CN=Pihole-Admin,OU=Groups,DC=example,DC=local"

// newLDAPEnv is a server whose login chain is local first, then the stub directory, with the admin group mapped to
// the builtin admin role.
func newLDAPEnv(t *testing.T, dir *stubLDAP, modify ...func(*Options)) *testEnv {
	t.Helper()
	e := newTestEnv(t, append([]func(*Options){func(o *Options) {
		chain, err := auth.Build([]auth.Method{auth.MethodLocal, auth.MethodLDAP}, map[auth.Method]auth.Authenticator{
			auth.MethodLocal: auth.NewLocalAuthenticator(auth.StoreUsers{St: o.Store}),
			auth.MethodLDAP:  dir,
		})
		if err != nil {
			t.Fatal(err)
		}
		o.Auth = chain
	}}, modify...)...)
	e.mapGroup(adminGroupDN, adminRoleID)
	return e
}

func (e *testEnv) mapGroup(dn string, roleID int64) {
	e.t.Helper()
	norm, err := auth.NormalizeDN(dn)
	if err != nil {
		e.t.Fatal(err)
	}
	ctx := context.Background()
	if err := e.st.WithTx(ctx, func(q *db.Queries) error {
		return q.AddRoleLDAPGroup(ctx, db.AddRoleLDAPGroupParams{RoleID: roleID, GroupDn: dn, GroupDnNorm: norm})
	}); err != nil {
		e.t.Fatal(err)
	}
}

func (e *testEnv) user(name string) (db.User, bool) {
	u, err := e.st.Read().GetUserByUsername(context.Background(), name)
	return u, err == nil
}

// sessionRoles returns the role IDs stored for the client's session.
func (e *testEnv) sessionRoles(c *client) []int64 {
	e.t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(c.cookies[auth.SessionCookie])
	s, err := e.srv.Sessions.Get(context.Background(), r)
	if err != nil {
		e.t.Fatal(err)
	}
	return s.RoleIDs
}

func TestLDAPLoginCreatesUserAndMapsRoles(t *testing.T) {
	dir := &stubLDAP{users: map[string]stubLDAPUser{"bob": {
		password: "bob-ldap-pw",
		dn:       "CN=Bob,OU=Staff,DC=example,DC=local",
		// The directory returns the group DN in a different case and spacing from the mapping.
		groups: []string{"cn=pihole-admin, ou=groups, dc=example, dc=local", "CN=Unmapped,DC=example,DC=local"},
	}}}
	e := newLDAPEnv(t, dir)
	c := e.client("10.0.0.1:1")

	res := c.login("Bob", "bob-ldap-pw")
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"source":"ldap"`) {
		t.Fatalf("login: %d %s", res.Code, res.Body)
	}
	u, ok := e.user("bob")
	if !ok || u.Source != "ldap" || u.LdapDn.String != "CN=Bob,OU=Staff,DC=example,DC=local" || u.PasswordHash.Valid || !u.LastLoginAt.Valid {
		t.Fatalf("user row = %+v", u)
	}
	if roles := e.sessionRoles(c); !slices.Equal(roles, []int64{adminRoleID}) {
		t.Fatalf("session roles = %v", roles)
	}

	// Moved in the directory: the next login reuses the row and records the new DN.
	dir.users["bob"] = stubLDAPUser{password: "bob-ldap-pw", dn: "CN=Bob,OU=Admins,DC=example,DC=local", groups: []string{adminGroupDN}}
	if res := e.client("10.0.0.2:1").login("bob", "bob-ldap-pw"); res.Code != http.StatusOK {
		t.Fatalf("second login: %d", res.Code)
	}
	if u2, _ := e.user("bob"); u2.ID != u.ID || u2.LdapDn.String != "CN=Bob,OU=Admins,DC=example,DC=local" {
		t.Fatalf("user row after move = %+v", u2)
	}
}

func TestLDAPLoginRefusals(t *testing.T) {
	dir := &stubLDAP{users: map[string]stubLDAPUser{
		"nomap":    {password: "pw-nomap-123", dn: "CN=Nomap,DC=example,DC=local", groups: []string{"CN=Unmapped,DC=example,DC=local"}},
		"nogroups": {password: "pw-nogroups-1", dn: "CN=Nogroups,DC=example,DC=local"},
		"alice":    {password: "alice-ldap-pw", dn: "CN=Alice,DC=example,DC=local", groups: []string{adminGroupDN}},
		"dave":     {password: "dave-ldap-pw", dn: "CN=Dave,DC=example,DC=local", groups: []string{adminGroupDN}},
	}}
	e := newLDAPEnv(t, dir, withLimits)
	e.addUser("alice", "alice-local-password", true) // a local account with the same username as an LDAP user

	// dave logs in once, then is disabled in the app.
	if res := e.client("10.0.0.1:1").login("dave", "dave-ldap-pw"); res.Code != http.StatusOK {
		t.Fatalf("dave: %d", res.Code)
	}
	disableUser(t, e, "dave")

	tests := []struct {
		name, user, pw string
		wantCode       int
		wantError      string
		wantReason     string
	}{
		{"no group maps to a role", "nomap", "pw-nomap-123", http.StatusForbidden, "no_access", "authorised"},
		{"no groups at all", "nogroups", "pw-nogroups-1", http.StatusForbidden, "no_access", "authorised"},
		{"username belongs to a local account", "alice", "alice-ldap-pw", http.StatusForbidden, "no_access", "local account"},
		{"disabled in the app", "dave", "dave-ldap-pw", http.StatusUnauthorized, "invalid_credentials", "account disabled"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Repeated more times than the limits allow: the password is right, so these aren't failed attempts.
			for i := 0; i < 5; i++ {
				res := e.client("10.0.0.9:1").login(tt.user, tt.pw)
				if res.Code != tt.wantCode || res.errorCode() != tt.wantError {
					t.Fatalf("attempt %d: %d %q, want %d %q", i+1, res.Code, res.errorCode(), tt.wantCode, tt.wantError)
				}
			}
		})
	}

	// Refused LDAP users get no user row, and the local alice is untouched.
	for _, name := range []string{"nomap", "nogroups"} {
		if _, ok := e.user(name); ok {
			t.Fatalf("a row was created for %s", name)
		}
	}
	if u, _ := e.user("alice"); u.Source != "local" {
		t.Fatalf("local alice changed: %+v", u)
	}

	// The audit log says why, and for LDAP users what the directory returned.
	var found int
	for _, r := range e.auditRows() {
		for _, tt := range tests {
			if r.Username == tt.user && r.Result == "failure" && strings.Contains(r.Detail, tt.wantReason) {
				found++
				if !strings.Contains(r.Detail, `"dn":`) || !strings.Contains(r.Detail, `"groups":`) {
					t.Fatalf("detail without dn and groups: %s", r.Detail)
				}
				break
			}
		}
	}
	if found != 5*len(tests) {
		t.Fatalf("matching audit rows = %d, want %d", found, 5*len(tests))
	}
}

func TestLocalLoginStillWinsFirst(t *testing.T) {
	// alice has a local account and an LDAP account with a different password. Local is tried first, so the local
	// password logs in locally without LDAP being involved.
	dir := &stubLDAP{users: map[string]stubLDAPUser{
		"alice": {password: "alice-ldap-pw", dn: "CN=Alice,DC=example,DC=local", groups: []string{adminGroupDN}},
	}}
	e := newLDAPEnv(t, dir)
	e.addUser("alice", "alice-local-password", true)
	res := e.client("10.0.0.1:1").login("alice", "alice-local-password")
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"source":"local"`) {
		t.Fatalf("login: %d %s", res.Code, res.Body)
	}
}
