// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package tokens

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
)

func TestNewAndParse(t *testing.T) {
	shape := regexp.MustCompile(`^prt_[a-z2-7]{16}_[a-z2-7]{52}$`)
	seen := map[string]bool{}
	for range 50 {
		token, publicID, hash := New()
		if !shape.MatchString(token) || len(token) != Len {
			t.Fatalf("token %q isn't shaped as prt_<16>_<52>", token)
		}
		if !strings.HasPrefix(token, Prefix+publicID+"_") {
			t.Fatalf("token %q doesn't carry its public ID %q", token, publicID)
		}
		if len(hash) != 32 {
			t.Fatalf("hash is %d bytes, want 32", len(hash))
		}
		if seen[publicID] {
			t.Fatalf("public ID %q made twice", publicID)
		}
		seen[publicID] = true

		gotID, gotHash, ok := Parse(token)
		if !ok || gotID != publicID || !Equal(gotHash, hash) {
			t.Fatalf("Parse(%q) = %q, %x, %v; want %q, %x", token, gotID, gotHash, ok, publicID, hash)
		}
		if bytes.Contains(hash, []byte(token[len(Prefix)+PublicIDLen+1:])) {
			t.Fatal("the hash contains the secret")
		}
	}
}

func TestParseRefuses(t *testing.T) {
	good, _, _ := New()
	id, secret := good[len(Prefix):len(Prefix)+PublicIDLen], good[len(Prefix)+PublicIDLen+1:]
	for name, token := range map[string]string{
		"empty":                   "",
		"the prefix alone":        Prefix,
		"no prefix":               "xyz_" + id + "_" + secret,
		"upper case prefix":       "PRT_" + id + "_" + secret,
		"upper case":              Prefix + strings.ToUpper(id) + "_" + strings.ToUpper(secret),
		"a hyphen for the _":      Prefix + id + "-" + secret,
		"a short secret":          Prefix + id + "_" + secret[1:],
		"a long secret":           Prefix + id + "_" + secret + "a",
		"a short public ID":       Prefix + id[1:] + "_a" + secret,
		"base32 padding":          Prefix + id + "_" + secret[:len(secret)-1] + "=",
		"a digit base32 lacks":    Prefix + id + "_" + secret[:len(secret)-1] + "1",
		"a space":                 Prefix + id + "_" + secret[:len(secret)-1] + " ",
		"Bearer left on":          "Bearer " + good[7:],
		"base64url in the secret": Prefix + id + "_" + secret[:len(secret)-1] + "-",
	} {
		if _, _, ok := Parse(token); ok {
			t.Errorf("%s: %q parsed", name, token)
		}
	}
}

func TestHashIsOfTheSecretText(t *testing.T) {
	a, b := HashSecret("aaaa"), HashSecret("aaab")
	if Equal(a, b) {
		t.Error("different secrets have the same hash")
	}
	if !Equal(HashSecret("aaaa"), a) {
		t.Error("the same secret hashed twice differs")
	}
	if Equal(a, a[:31]) {
		t.Error("a hash equals its own prefix")
	}
}
