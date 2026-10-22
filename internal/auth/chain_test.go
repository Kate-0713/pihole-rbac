// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// stub is an Authenticator that returns a fixed result.
type stub struct {
	id  *Identity
	err error
}

func (s stub) Authenticate(context.Context, string, string) (*Identity, error) { return s.id, s.err }

func chainOf(methods ...namedAuthenticator) *ChainAuthenticator {
	return &ChainAuthenticator{methods: methods}
}

func TestChainFirstSuccessWins(t *testing.T) {
	local := &Identity{Username: "alice", Source: MethodLocal}
	ldap := &Identity{Username: "alice", Source: MethodLDAP}
	c := chainOf(
		namedAuthenticator{MethodLocal, stub{id: local}},
		namedAuthenticator{MethodLDAP, stub{id: ldap}},
	)
	id, err := c.Authenticate(context.Background(), "alice", "pw")
	if err != nil || id.Source != MethodLocal {
		t.Fatalf("got %+v, %v; want the local user", id, err)
	}
}

func TestChainFallsThroughToLaterMethod(t *testing.T) {
	ldap := &Identity{Username: "bob", Source: MethodLDAP}
	c := chainOf(
		namedAuthenticator{MethodLocal, stub{err: ErrInvalidCredentials}},
		namedAuthenticator{MethodLDAP, stub{id: ldap}},
	)
	id, err := c.Authenticate(context.Background(), "bob", "pw")
	if err != nil || id.Source != MethodLDAP {
		t.Fatalf("got %+v, %v; want the ldap user", id, err)
	}
}

func TestChainUnreachableMethodDoesNotBlockOthers(t *testing.T) {
	local := &Identity{Username: "root", Source: MethodLocal}
	c := chainOf(
		namedAuthenticator{MethodLDAP, stub{err: errors.New("connecting to LDAP: timeout")}},
		namedAuthenticator{MethodLocal, stub{id: local}},
	)
	if _, err := c.Authenticate(context.Background(), "root", "pw"); err != nil {
		t.Fatalf("local login should succeed despite LDAP failing: %v", err)
	}
}

func TestChainFailureKeepsDiagnosticsButIsInvalidCredentials(t *testing.T) {
	c := chainOf(
		namedAuthenticator{MethodLocal, stub{err: ErrInvalidCredentials}},
		namedAuthenticator{MethodLDAP, stub{err: errors.New("service account bind failed")}},
	)
	_, err := c.Authenticate(context.Background(), "x", "pw")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("err = %v; want it to match ErrInvalidCredentials", err)
	}
	if errors.Is(err, ErrNoAccess) {
		t.Fatal("must not be reported as ErrNoAccess")
	}
	if got := err.Error(); !strings.Contains(got, "ldap: service account bind failed") {
		t.Fatalf("err %q should keep the ldap failure reason for the audit log", got)
	}
}

func TestChainNoAccessIsPreserved(t *testing.T) {
	c := chainOf(
		namedAuthenticator{MethodLocal, stub{err: ErrInvalidCredentials}},
		namedAuthenticator{MethodLDAP, stub{err: ErrNoAccess}},
	)
	if _, err := c.Authenticate(context.Background(), "x", "pw"); !errors.Is(err, ErrNoAccess) {
		t.Fatalf("err = %v; want ErrNoAccess", err)
	}
}

func TestBuildValidatesAndOrdersMethods(t *testing.T) {
	available := map[Method]Authenticator{MethodLocal: stub{}, MethodLDAP: stub{}}
	tests := []struct {
		name    string
		enabled []Method
		want    []Method // nil means an error is expected
	}{
		{"none enabled", nil, nil},
		{"unknown method", []Method{"kerberos"}, nil},
		{"duplicate", []Method{MethodLocal, MethodLocal}, nil},
		{"default order", []Method{MethodLocal, MethodLDAP}, []Method{MethodLocal, MethodLDAP}},
		{"order is kept", []Method{MethodLDAP, MethodLocal}, []Method{MethodLDAP, MethodLocal}},
		{"one method", []Method{MethodLDAP}, []Method{MethodLDAP}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain, err := Build(tt.enabled, available)
			if tt.want == nil {
				if err == nil {
					t.Fatal("Build succeeded")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var got []Method
			for _, m := range chain.methods {
				got = append(got, m.method)
			}
			if !equalMethods(got, tt.want) {
				t.Fatalf("methods = %v, want %v", got, tt.want)
			}
		})
	}

	if _, err := Build([]Method{MethodLocal, MethodLDAP}, map[Method]Authenticator{MethodLocal: stub{}}); err == nil {
		t.Fatal("enabled method without an authenticator should be an error")
	}
}

func TestSwappable(t *testing.T) {
	s := NewSwappable(stub{err: ErrInvalidCredentials})
	if _, err := s.Authenticate(context.Background(), "a", "b"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("err = %v", err)
	}
	s.Set(stub{id: &Identity{Username: "a"}})
	if id, err := s.Authenticate(context.Background(), "a", "b"); err != nil || id.Username != "a" {
		t.Fatalf("after Set: %+v, %v", id, err)
	}
}

func equalMethods(a, b []Method) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
