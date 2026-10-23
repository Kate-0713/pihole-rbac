// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"slices"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func TestNormalizeDN(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		same bool
	}{
		// Ported from v1's TestRolesForGroupsIgnoresDNCase.
		{"case", "cn=pihole-admin,ou=groups,dc=example,dc=local", "CN=Pihole-Admin,OU=Groups,DC=example,DC=local", true},
		{"spaces around separators", "cn=pihole-admin, ou=groups , dc=example,dc=local", "cn=pihole-admin,ou=groups,dc=example,dc=local", true},
		{"multi-valued RDN order", "cn=a+uid=b,dc=x", "uid=b+cn=a,dc=x", true},
		{"escaped comma vs separator", `cn=a\,b,dc=x`, "cn=a,cn=b,dc=x", false},
		{"hex-escaped value", `cn=a\2cb,dc=x`, `cn=a\,b,dc=x`, true},
		{"different group", "cn=pihole-admin,ou=groups,dc=example,dc=local", "cn=pihole-reader,ou=groups,dc=example,dc=local", false},
		{"different parent", "cn=admins,ou=a,dc=x", "cn=admins,ou=b,dc=x", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			na, err := NormalizeDN(tt.a)
			if err != nil {
				t.Fatal(err)
			}
			nb, err := NormalizeDN(tt.b)
			if err != nil {
				t.Fatal(err)
			}
			if (na == nb) != tt.same {
				t.Fatalf("NormalizeDN(%q) = %q, NormalizeDN(%q) = %q; want same=%v", tt.a, na, tt.b, nb, tt.same)
			}
			// Our canonical form must agree with go-ldap's own case-insensitive comparison.
			pa, _ := ldap.ParseDN(tt.a)
			pb, _ := ldap.ParseDN(tt.b)
			if pa.EqualFold(pb) != tt.same {
				t.Fatalf("ldap EqualFold = %v, want %v", pa.EqualFold(pb), tt.same)
			}
		})
	}

	if _, err := NormalizeDN("not a dn"); err == nil {
		t.Fatal("invalid DN accepted")
	}
}

func TestNormalizeDNs(t *testing.T) {
	norm, invalid := NormalizeDNs([]string{"CN=A,DC=x", "cn=a, dc=x", "garbage", "cn=b,dc=x"})
	if !slices.Equal(norm, []string{"cn=a,dc=x", "cn=b,dc=x"}) || !slices.Equal(invalid, []string{"garbage"}) {
		t.Fatalf("norm = %v, invalid = %v", norm, invalid)
	}
}
