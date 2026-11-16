// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package totp is the second login factor: time-based one-time codes (RFC 6238) as authenticator apps make them,
// single-use recovery codes, and the rule for who must use them. It holds no HTTP and no sessions; the login and
// account handlers call it.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // RFC 6238's default, and the only algorithm every authenticator app supports
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"net/url"
	"strings"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/secrets"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

const (
	// Digits and Period are the values every authenticator app assumes when a URI doesn't say otherwise. They are
	// in the URI anyway.
	Digits = 6
	Period = 30 * time.Second

	// SecretSize is 160 bits, the length RFC 4226 recommends and the output size of HMAC-SHA-1.
	SecretSize = 20

	// skew is how many time steps either side of the current one are accepted, for a clock that is a little off or
	// a code typed as it changed.
	skew = 1
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret returns a random secret.
func NewSecret() secrets.Value {
	b := make([]byte, SecretSize)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand.Read doesn't fail on supported platforms (Go 1.24+)
	}
	return secrets.NewValue(b)
}

// Encode returns the secret as authenticator apps take it for manual entry: base32 without padding.
func Encode(secret secrets.Value) string {
	return b32.EncodeToString(secret.RevealBytes())
}

// URI is the otpauth:// URI a QR code carries. issuer names the app in the authenticator's list and account the
// user. A colon separates the two in the label, so it is removed from both.
func URI(issuer, account string, secret secrets.Value) string {
	issuer = strings.ReplaceAll(issuer, ":", "")
	account = strings.ReplaceAll(account, ":", "")
	q := url.Values{}
	q.Set("secret", Encode(secret))
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	// url.Values writes a space as "+", which some authenticator apps show as a plus sign. A real "+" is written
	// as %2B, so every "+" left is a space.
	query := strings.ReplaceAll(q.Encode(), "+", "%20")
	u := url.URL{Scheme: "otpauth", Host: "totp", Path: "/" + issuer + ":" + account, RawQuery: query}
	return u.String()
}

// Step is the time step t falls in: the counter a code is made from.
func Step(t time.Time) int64 {
	return t.Unix() / int64(Period/time.Second)
}

// hotp is RFC 4226's HOTP value for a counter, as a zero-padded decimal string.
func hotp(secret []byte, counter int64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter))
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	out := make([]byte, digits)
	for i := digits - 1; i >= 0; i-- {
		out[i] = byte('0' + v%10)
		v /= 10
	}
	return string(out)
}

// Code returns the code for the time step t falls in.
func Code(secret secrets.Value, t time.Time) string {
	return hotp(secret.RevealBytes(), Step(t), Digits)
}

// NormalizeCode strips the spaces authenticator apps show in a code ("123 456"). ok is false unless six digits
// remain.
func NormalizeCode(input string) (code string, ok bool) {
	code = strings.Join(strings.Fields(input), "")
	if len(code) != Digits {
		return "", false
	}
	for i := 0; i < len(code); i++ {
		if code[i] < '0' || code[i] > '9' {
			return "", false
		}
	}
	return code, true
}

// Verify checks a code against the current time step and one either side. A step at or before lastStep is never
// accepted, so a code can't be used twice and an older code can't follow a newer one. On success it returns the step
// that matched, for the caller to store with db.AdvanceUserTOTPStep, whose row count settles two requests racing
// with the same code.
//
// Every candidate step is compared, in constant time, whether or not an earlier one matched.
func Verify(secret secrets.Value, input string, now time.Time, lastStep int64) (step int64, ok bool) {
	code, valid := NormalizeCode(input)
	if !valid {
		return 0, false
	}
	key := secret.RevealBytes()
	current := Step(now)
	for s := current - skew; s <= current+skew; s++ {
		match := subtle.ConstantTimeCompare([]byte(hotp(key, s, Digits)), []byte(code)) == 1
		if match && s > lastStep && !ok {
			step, ok = s, true
		}
	}
	return step, ok
}

// AAD binds a sealed secret to its user's row, so a ciphertext copied to another user doesn't decrypt.
func AAD(userID int64) []byte {
	return secrets.AAD("user_totp", userID)
}

// Seal encrypts a secret for user_totp.
func Seal(c *secrets.Cipher, userID int64, secret secrets.Value) (secrets.Sealed, error) {
	return c.Seal(secret, AAD(userID))
}

// Open decrypts a user_totp row's secret.
func Open(c *secrets.Cipher, row db.UserTotp) (secrets.Value, error) {
	return c.Open(Sealed(row), AAD(row.UserID))
}

// Sealed is a user_totp row's secret as stored.
func Sealed(row db.UserTotp) secrets.Sealed {
	return secrets.Sealed{KeyID: row.SecretKeyID, Nonce: row.SecretNonce, Ciphertext: row.SecretCiphertext}
}
