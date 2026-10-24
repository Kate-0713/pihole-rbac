// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// KeySize is the length of the master key and the session key.
const KeySize = 32

var (
	// ErrWrongKey means a sealed value was encrypted under a different master key (see Sealed.KeyID).
	ErrWrongKey = errors.New("secrets: value was encrypted with a different master key")
	// ErrDecrypt means the ciphertext, nonce or associated data don't match: corrupted, tampered with, or moved to
	// another row.
	ErrDecrypt = errors.New("secrets: decryption failed")
)

// Sealed is a tier 2 secret as stored in the database: notification_channels.secret_key_id, secret_nonce and
// secret_ciphertext.
type Sealed struct {
	KeyID      string
	Nonce      []byte // 12 bytes
	Ciphertext []byte // includes the GCM tag
}

// Cipher encrypts tier 2 secrets with AES-256-GCM under the master key.
type Cipher struct {
	id   string
	aead cipher.AEAD
}

// NewCipher builds a cipher from a 32-byte key.
func NewCipher(key []byte) (*Cipher, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("secrets: key must be %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Cipher{id: keyID(key), aead: aead}, nil
}

// keyID identifies a key without revealing it: the first 8 bytes of an HMAC of a fixed label, in hex. It lets
// rotate-key tell which rows are under which key, and lets Open fail clearly when the key has changed.
func keyID(key []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("pihole-rbac master key id v1"))
	return hex.EncodeToString(m.Sum(nil)[:8])
}

// KeyID returns the identifier stored alongside every value this cipher seals.
func (c *Cipher) KeyID() string { return c.id }

// Seal encrypts plaintext with a fresh random nonce. aad binds the ciphertext to where it's stored (see AAD), so a
// ciphertext copied to another row won't decrypt.
func (c *Cipher) Seal(plaintext Value, aad []byte) (Sealed, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Sealed{}, err
	}
	return Sealed{KeyID: c.id, Nonce: nonce, Ciphertext: c.aead.Seal(nil, nonce, plaintext.b, aad)}, nil
}

// Open decrypts s. It returns ErrWrongKey if s was sealed under another key and ErrDecrypt if it doesn't
// authenticate.
func (c *Cipher) Open(s Sealed, aad []byte) (Value, error) {
	if s.KeyID != c.id {
		return Value{}, ErrWrongKey
	}
	if len(s.Nonce) != c.aead.NonceSize() {
		return Value{}, ErrDecrypt
	}
	b, err := c.aead.Open(nil, s.Nonce, s.Ciphertext, aad)
	if err != nil {
		return Value{}, ErrDecrypt
	}
	return Value{b: b}, nil
}

// AAD is the associated data for a secret stored in table row id, e.g. AAD("notification_channels", 3).
func AAD(table string, id int64) []byte {
	return []byte("pihole-rbac:" + table + ":" + strconv.FormatInt(id, 10))
}

// AADKey is the associated data for a secret stored in a table row identified by a text key, e.g. AADKey("settings",
// "ldap").
func AADKey(table, key string) []byte {
	return []byte("pihole-rbac:" + table + ":" + key)
}

// DecodeKey parses a base64 32-byte key, as in PIHOLE_RBAC_SECRET_KEY, PIHOLE_RBAC_SESSION_KEY and session.key.
// Standard and URL-safe alphabets are accepted, with or without padding. Errors never include the input.
func DecodeKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			if len(b) != KeySize {
				return nil, fmt.Errorf("key must decode to %d bytes, got %d", KeySize, len(b))
			}
			return b, nil
		}
	}
	return nil, fmt.Errorf("key is not valid base64 (generate one with: openssl rand -base64 %d)", KeySize)
}

// NewKey returns a random 32-byte key, base64-encoded.
func NewKey() string {
	return encodeKey(randomBytes(KeySize))
}

func encodeKey(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand.Read doesn't fail on supported platforms (Go 1.24+)
	}
	return b
}
