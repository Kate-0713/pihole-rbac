// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package minisign verifies minisign signatures (https://jedisct1.github.io/minisign/), which sign the release
// checksums. Only verification is implemented, and only the prehashed algorithm ("ED", BLAKE2b-512 then Ed25519),
// which minisign has used by default since 0.10. Legacy signatures over the raw file ("Ed") are refused: the release
// workflow never makes them, so accepting them would only widen what a forged file could try.
//
// A signature file has four lines:
//
//	untrusted comment: <anything; not covered by the signature>
//	base64("ED" || key ID (8 bytes) || Ed25519 signature of BLAKE2b-512(file) (64 bytes))
//	trusted comment: <text>
//	base64(Ed25519 signature of (the signature above || the trusted comment text) (64 bytes))
//
// The trusted comment is covered by the second ("global") signature, so callers can rely on it, for example to check
// that a signature names the release it is meant for.
package minisign

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/blake2b"
)

const (
	untrustedPrefix = "untrusted comment: "
	trustedPrefix   = "trusted comment: "

	// MaxSignatureSize bounds a signature file; a real one is well under 1 KiB.
	MaxSignatureSize = 4 << 10
	// maxTrustedComment matches minisign's own limit on the trusted comment.
	maxTrustedComment = 1024
)

var (
	keyAlgorithm       = [2]byte{'E', 'd'}
	prehashedAlgorithm = [2]byte{'E', 'D'}
)

// ErrInvalid is wrapped by every verification failure, so callers can tell a bad signature from, say, a failed
// download with errors.Is.
var ErrInvalid = errors.New("minisign: signature is not valid")

// PublicKey is a minisign public key.
type PublicKey struct {
	ID  [8]byte
	key ed25519.PublicKey
}

// KeyID returns the key ID as minisign prints it: 16 upper-case hex digits of the little-endian ID.
func (k PublicKey) KeyID() string {
	return fmt.Sprintf("%016X", binary.LittleEndian.Uint64(k.ID[:]))
}

// ParsePublicKey reads a public key either as the base64 line alone or as the contents of a minisign.pub file (an
// untrusted comment line, then the base64 line).
func ParsePublicKey(s string) (PublicKey, error) {
	lines := strings.Split(strings.TrimSpace(strings.ReplaceAll(s, "\r\n", "\n")), "\n")
	line := lines[len(lines)-1]
	if len(lines) > 2 || (len(lines) == 2 && !strings.HasPrefix(lines[0], untrustedPrefix)) {
		return PublicKey{}, errors.New("minisign: a public key is one base64 line, optionally after an untrusted comment")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(line))
	if err != nil {
		return PublicKey{}, fmt.Errorf("minisign: public key is not valid base64: %w", err)
	}
	if len(raw) != 2+8+ed25519.PublicKeySize {
		return PublicKey{}, fmt.Errorf("minisign: public key is %d bytes, want %d", len(raw), 2+8+ed25519.PublicKeySize)
	}
	if !bytes.Equal(raw[:2], keyAlgorithm[:]) {
		return PublicKey{}, fmt.Errorf("minisign: unsupported public key algorithm %q", raw[:2])
	}
	var k PublicKey
	copy(k.ID[:], raw[2:10])
	k.key = ed25519.PublicKey(bytes.Clone(raw[10:]))
	return k, nil
}

// Signature is a parsed signature file.
type Signature struct {
	Algorithm      [2]byte
	KeyID          [8]byte
	sig            [ed25519.SignatureSize]byte
	TrustedComment string
	globalSig      [ed25519.SignatureSize]byte
}

// ParseSignature parses a signature file. It checks the format only; Verify checks the signatures.
func ParseSignature(b []byte) (Signature, error) {
	if len(b) > MaxSignatureSize {
		return Signature{}, fmt.Errorf("%w: signature file is over %d bytes", ErrInvalid, MaxSignatureSize)
	}
	text := strings.ReplaceAll(string(b), "\r\n", "\n")
	text = strings.TrimSuffix(text, "\n")
	lines := strings.Split(text, "\n")
	if len(lines) != 4 {
		return Signature{}, fmt.Errorf("%w: signature file has %d lines, want 4", ErrInvalid, len(lines))
	}
	if !strings.HasPrefix(lines[0], untrustedPrefix) {
		return Signature{}, fmt.Errorf("%w: first line is not an untrusted comment", ErrInvalid)
	}
	if !strings.HasPrefix(lines[2], trustedPrefix) {
		return Signature{}, fmt.Errorf("%w: third line is not a trusted comment", ErrInvalid)
	}

	var s Signature
	raw, err := base64.StdEncoding.Strict().DecodeString(lines[1])
	if err != nil || len(raw) != 2+8+ed25519.SignatureSize {
		return Signature{}, fmt.Errorf("%w: malformed signature line", ErrInvalid)
	}
	copy(s.Algorithm[:], raw[:2])
	copy(s.KeyID[:], raw[2:10])
	copy(s.sig[:], raw[10:])

	s.TrustedComment = strings.TrimPrefix(lines[2], trustedPrefix)
	if len(s.TrustedComment) > maxTrustedComment {
		return Signature{}, fmt.Errorf("%w: trusted comment is over %d bytes", ErrInvalid, maxTrustedComment)
	}

	global, err := base64.StdEncoding.Strict().DecodeString(lines[3])
	if err != nil || len(global) != ed25519.SignatureSize {
		return Signature{}, fmt.Errorf("%w: malformed global signature line", ErrInvalid)
	}
	copy(s.globalSig[:], global)
	return s, nil
}

// Verify checks that sigFile is a valid signature of msg by key, including the signature over the trusted comment,
// and returns the trusted comment. Every failure wraps ErrInvalid.
func Verify(key PublicKey, msg, sigFile []byte) (trustedComment string, err error) {
	s, err := ParseSignature(sigFile)
	if err != nil {
		return "", err
	}
	if s.Algorithm != prehashedAlgorithm {
		if s.Algorithm == keyAlgorithm {
			return "", fmt.Errorf("%w: legacy (not prehashed) signatures are not accepted", ErrInvalid)
		}
		return "", fmt.Errorf("%w: unsupported signature algorithm %q", ErrInvalid, s.Algorithm[:])
	}
	if s.KeyID != key.ID {
		return "", fmt.Errorf("%w: signed with key %016X, not the release key %s", ErrInvalid,
			binary.LittleEndian.Uint64(s.KeyID[:]), key.KeyID())
	}
	if len(key.key) != ed25519.PublicKeySize {
		return "", fmt.Errorf("%w: no public key", ErrInvalid)
	}

	digest := blake2b.Sum512(msg)
	if !ed25519.Verify(key.key, digest[:], s.sig[:]) {
		return "", fmt.Errorf("%w: the file does not match its signature", ErrInvalid)
	}
	global := make([]byte, 0, len(s.sig)+len(s.TrustedComment))
	global = append(append(global, s.sig[:]...), s.TrustedComment...)
	if !ed25519.Verify(key.key, global, s.globalSig[:]) {
		return "", fmt.Errorf("%w: the trusted comment does not match its signature", ErrInvalid)
	}
	return s.TrustedComment, nil
}
