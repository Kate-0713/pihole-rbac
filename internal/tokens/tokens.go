// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tokens makes and reads personal API tokens. A token is "prt_<public_id>_<secret>": the public ID finds the
// token's row and is safe to show and log, and the secret proves the caller holds the token. Both are lowercase base32
// without padding, so neither contains "_" and the token splits unambiguously. Only the SHA-256 of the secret is
// stored: the secret is 256 random bits, so there is nothing for a slow hash to protect.
//
// The rules about who may create a token and what it may hold are in package rbac, with the other grant invariants.
package tokens

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"strings"
	"time"
)

const (
	// Prefix starts every token, so one is easy to recognise in a script or a secret scanner.
	Prefix = "prt_"
	// PublicIDLen is the length of the public ID: 10 random bytes.
	PublicIDLen = 16
	// SecretLen is the length of the secret: 32 random bytes.
	SecretLen = 52
	// Len is the length of a whole token.
	Len = len(Prefix) + PublicIDLen + 1 + SecretLen

	// MaxLifetime is the longest a token can last. A token can't be extended: make a new one.
	MaxLifetime = 365 * 24 * time.Hour
	// MaxLive is how many tokens a user can have that are neither revoked nor expired.
	MaxLive = 50
	// MaxNameLen is the longest a token's name can be, in characters.
	MaxNameLen = 64
	// KeepFor is how long revoked and expired tokens stay listed before they are pruned.
	KeepFor = 30 * 24 * time.Hour
)

var encoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// New makes a token. It returns the token to show once, its public ID and the hash of its secret to store.
func New() (token, publicID string, secretHash []byte) {
	id := make([]byte, 10)
	secret := make([]byte, 32)
	for _, b := range [][]byte{id, secret} {
		if _, err := rand.Read(b); err != nil {
			panic(err) // crypto/rand.Read doesn't fail on supported platforms (Go 1.24+)
		}
	}
	publicID = encoding.EncodeToString(id)
	s := encoding.EncodeToString(secret)
	return Prefix + publicID + "_" + s, publicID, HashSecret(s)
}

// Parse splits a token into its public ID and the hash of its secret. ok is false for anything that isn't shaped
// like a token, which callers treat the same as a wrong token.
func Parse(token string) (publicID string, secretHash []byte, ok bool) {
	if len(token) != Len || !strings.HasPrefix(token, Prefix) {
		return "", nil, false
	}
	rest := token[len(Prefix):]
	publicID, secret := rest[:PublicIDLen], rest[PublicIDLen+1:]
	if rest[PublicIDLen] != '_' || !isBase32(publicID) || !isBase32(secret) {
		return "", nil, false
	}
	return publicID, HashSecret(secret), true
}

// HashSecret is what is stored for a secret. It hashes the secret's text, so there is exactly one text per hash.
func HashSecret(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// Equal compares two secret hashes in constant time.
func Equal(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

func isBase32(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '2' || c > '7') {
			return false
		}
	}
	return true
}
