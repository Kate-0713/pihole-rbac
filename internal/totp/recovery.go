// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package totp

import (
	"crypto/rand"
	"crypto/sha256"
	"strings"
)

const (
	// RecoveryCodeCount is how many recovery codes a user is given at a time.
	RecoveryCodeCount = 10

	// recoveryBytes is 80 bits of randomness per code: 16 base32 characters.
	recoveryBytes = 10
	recoveryChars = 16
	recoveryGroup = 4
)

// NewRecoveryCodes returns a fresh set of codes as shown to the user ("abcd-efgh-ijkl-mnop") and the hash of each
// to store. The codes themselves are never stored.
func NewRecoveryCodes() (codes []string, hashes [][]byte) {
	for len(codes) < RecoveryCodeCount {
		b := make([]byte, recoveryBytes)
		if _, err := rand.Read(b); err != nil {
			panic(err) // crypto/rand.Read doesn't fail on supported platforms (Go 1.24+)
		}
		raw := b32.EncodeToString(b)
		hash, _ := HashRecoveryCode(raw)
		var parts []string
		for i := 0; i < len(raw); i += recoveryGroup {
			parts = append(parts, raw[i:i+recoveryGroup])
		}
		codes = append(codes, strings.ToLower(strings.Join(parts, "-")))
		hashes = append(hashes, hash)
	}
	return codes, hashes
}

// HashRecoveryCode returns the stored form of a recovery code as a user typed it: hyphens and spaces are dropped
// and case is ignored. ok is false if what remains isn't shaped like a recovery code, so the caller can tell one
// from a mistyped six-digit code without a database read.
//
// The hash is a plain SHA-256. A code has 80 random bits, so there is nothing for a slow hash to protect, unlike a
// password.
func HashRecoveryCode(input string) (hash []byte, ok bool) {
	s := strings.ToUpper(strings.NewReplacer("-", "", " ", "", "\t", "").Replace(strings.TrimSpace(input)))
	if len(s) != recoveryChars {
		return nil, false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z') && !(c >= '2' && c <= '7') {
			return nil, false
		}
	}
	sum := sha256.Sum256([]byte(s))
	return sum[:], true
}
