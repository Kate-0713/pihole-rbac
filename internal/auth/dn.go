// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"slices"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// NormalizeDN returns the canonical form of an LDAP distinguished name, used to match the group DNs a directory
// returns against role_ldap_groups.group_dn_norm. The DN is parsed with ldap.ParseDN, so escaping and spacing around
// separators don't matter; attribute types and values are lowercased, because directories return DNs in whatever
// case they like; and the parts of a multi-valued RDN are sorted. Two DNs that ldap.DN.EqualFold considers equal
// normalise to the same string.
func NormalizeDN(dn string) (string, error) {
	parsed, err := ldap.ParseDN(dn)
	if err != nil {
		return "", err
	}
	rdns := make([]string, 0, len(parsed.RDNs))
	for _, rdn := range parsed.RDNs {
		parts := make([]string, 0, len(rdn.Attributes))
		for _, a := range rdn.Attributes {
			parts = append(parts, strings.ToLower(a.Type)+"="+escapeDNValue(strings.ToLower(a.Value)))
		}
		slices.Sort(parts)
		rdns = append(rdns, strings.Join(parts, "+"))
	}
	return strings.Join(rdns, ","), nil
}

// NormalizeDNs normalises each DN and drops duplicates. DNs that don't parse are returned separately, so the caller
// can log them; they can never match a mapping.
func NormalizeDNs(dns []string) (norm []string, invalid []string) {
	for _, dn := range dns {
		n, err := NormalizeDN(dn)
		if err != nil {
			invalid = append(invalid, dn)
			continue
		}
		if !slices.Contains(norm, n) {
			norm = append(norm, n)
		}
	}
	return norm, invalid
}

// escapeDNValue escapes the characters that would otherwise make the canonical string ambiguous.
func escapeDNValue(v string) string {
	var b strings.Builder
	for _, r := range v {
		switch r {
		case '\\', ',', '+', '=', '"', '<', '>', ';', '#':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}
