// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package ldaptest_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/Kate-0713/pihole-rbac/internal/auth"
	"github.com/Kate-0713/pihole-rbac/internal/auth/ldaptest"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
)

func start(t *testing.T) (*ldaptest.Server, ldaptest.Fixture) {
	t.Helper()
	s, err := ldaptest.Start("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, ldaptest.Example(s)
}

// TestWithTheRealAuthenticator: the app's own LDAP code logs in and looks users up against the fake.
func TestWithTheRealAuthenticator(t *testing.T) {
	s, f := start(t)
	a, err := auth.NewLDAPAuthenticator(auth.LDAPSettings{
		URL: f.URL, BindDN: f.BindDN, BaseDN: f.BaseDN, UserFilter: f.UserFilter,
	}, func() (secrets.Value, bool) { return secrets.NewValue([]byte(f.BindPassword)), true }, "")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	id, err := a.Authenticate(ctx, "Lucy", f.Password("lucy"))
	if err != nil {
		t.Fatalf("lucy: %v", err)
	}
	slices.Sort(id.Groups)
	if id.DN != f.Users["lucy"] || !slices.Equal(id.Groups, []string{f.AdminGroup, f.StaffGroup}) {
		t.Errorf("lucy: %+v", id)
	}
	if s.Binds() == 0 {
		t.Error("binds not counted")
	}
	for _, tt := range []struct{ user, password string }{{"lucy", "wrong"}, {"nobody", "x"}, {"lucy*", f.Password("lucy")}} {
		if _, err := a.Authenticate(ctx, tt.user, tt.password); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Errorf("%s/%s: %v", tt.user, tt.password, err)
		}
	}
	id, err = a.Lookup(ctx, "nina")
	if err != nil || id.DN != f.Users["nina"] || len(id.Groups) != 0 {
		t.Errorf("nina: %+v %v", id, err)
	}
	if _, err := a.Lookup(ctx, "gone"); !errors.Is(err, auth.ErrNoSuchUser) {
		t.Errorf("gone: %v", err)
	}

	// A wrong service password is an operational error, not a wrong user password.
	s.SetPassword(f.BindDN, "rotated")
	if _, err := a.Authenticate(ctx, "lucy", f.Password("lucy")); err == nil || errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("service bind with an old password: %v", err)
	}
}

func TestSearches(t *testing.T) {
	_, f := start(t)
	conn, err := ldap.DialURL(f.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	search := func(base string, scope int, filter string, attrs ...string) (*ldap.SearchResult, error) {
		return conn.Search(ldap.NewSearchRequest(base, scope, ldap.NeverDerefAliases, 0, 0, false, filter, attrs, nil))
	}
	if _, err := search(f.BaseDN, ldap.ScopeWholeSubtree, "(uid=lucy)"); !ldap.IsErrorWithCode(err, ldap.LDAPResultInsufficientAccessRights) {
		t.Errorf("search before binding: %v", err)
	}
	if err := conn.Bind(f.BindDN, f.BindPassword); err != nil {
		t.Fatal(err)
	}

	res, err := search(f.BaseDN, ldap.ScopeWholeSubtree, "(|(uid=mark)(uid=nina))")
	if err != nil || len(res.Entries) != 2 {
		t.Errorf("or: %v %v", res, err)
	}
	res, err = search(f.BaseDN, ldap.ScopeWholeSubtree, "(&(objectClass=groupOfNames)(!(member=*)))")
	if err != nil || len(res.Entries) != 1 || res.Entries[0].DN != f.EmptyGroup {
		t.Errorf("and/not/present: %v %v", res, err)
	}
	res, err = search(f.StaffGroup, ldap.ScopeBaseObject, "(objectClass=*)", "member")
	if err != nil || len(res.Entries) != 1 || len(res.Entries[0].GetAttributeValues("member")) != 2 {
		t.Errorf("base search with attributes: %v %v", res, err)
	}
	if _, err := search("cn=missing,ou=groups,dc=example,dc=local", ldap.ScopeBaseObject, "(objectClass=*)"); !ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		t.Errorf("missing base: %v", err)
	}
	// Members are compared as DNs, so case and spacing don't matter.
	res, err = search(f.BaseDN, ldap.ScopeWholeSubtree, "(member=UID=Mark, OU=People, OU=Headquarters,DC=example,DC=local)")
	if err != nil || len(res.Entries) != 1 {
		t.Errorf("member as a DN: %v %v", res, err)
	}
}
