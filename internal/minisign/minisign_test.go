// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package minisign

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/blake2b"
)

// The project's release key and the checksums of v2.0.0-rc.1 with their signature, as published by the release
// workflow (signed by minisign itself, not by this package).
const releaseKey = `untrusted comment: minisign public key 7AF25727730A4FA2
RWSiTwpzJ1fyeg5FbD9k+fgdn1h28wLmH8lid3NJsRYxw5iv7iHhzUI/
`

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// testKey makes a key pair with the given ID, in the format minisign uses.
func testKey(t *testing.T, id byte) (PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	raw := append([]byte("Ed"), bytes.Repeat([]byte{id}, 8)...)
	raw = append(raw, pub...)
	k, err := ParsePublicKey(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}
	return k, priv
}

// sign makes a signature file as minisign would, with the given algorithm.
func sign(priv ed25519.PrivateKey, key PublicKey, alg string, msg []byte, trusted string) []byte {
	signed := msg
	if alg == "ED" {
		d := blake2b.Sum512(msg)
		signed = d[:]
	}
	sig := ed25519.Sign(priv, signed)
	line := append(append([]byte(alg), key.ID[:]...), sig...)
	global := ed25519.Sign(priv, append(append([]byte{}, sig...), trusted...))
	return []byte("untrusted comment: test\n" +
		base64.StdEncoding.EncodeToString(line) + "\n" +
		"trusted comment: " + trusted + "\n" +
		base64.StdEncoding.EncodeToString(global) + "\n")
}

func TestReleaseVector(t *testing.T) {
	key, err := ParsePublicKey(releaseKey)
	if err != nil {
		t.Fatal(err)
	}
	if got := key.KeyID(); got != "7AF25727730A4FA2" {
		t.Errorf("KeyID = %s, want 7AF25727730A4FA2 (as minisign printed it)", got)
	}
	msg := readTestdata(t, "checksums.txt")
	sig := readTestdata(t, "checksums.txt.minisig")

	trusted, err := Verify(key, msg, sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if trusted != "pihole-rbac v2.0.0-rc.1" {
		t.Errorf("trusted comment = %q", trusted)
	}

	tampered := bytes.Replace(msg, []byte("53a144ff"), []byte("53a144fe"), 1)
	if _, err := Verify(key, tampered, sig); !errors.Is(err, ErrInvalid) {
		t.Errorf("tampered file: err = %v, want ErrInvalid", err)
	}
	// Passing the signature off as another release's: the trusted comment is covered by the global signature.
	relabelled := bytes.Replace(sig, []byte("v2.0.0-rc.1"), []byte("v2.0.1"), 1)
	if _, err := Verify(key, msg, relabelled); !errors.Is(err, ErrInvalid) {
		t.Errorf("relabelled trusted comment: err = %v, want ErrInvalid", err)
	}
	// The untrusted comment really isn't covered.
	recommented := bytes.Replace(sig, []byte("signature from minisign secret key"), []byte("anything"), 1)
	if _, err := Verify(key, msg, recommented); err != nil {
		t.Errorf("changed untrusted comment: %v", err)
	}
	// Windows line endings, in case a file passes through an editor.
	crlf := bytes.ReplaceAll(sig, []byte("\n"), []byte("\r\n"))
	if _, err := Verify(key, msg, crlf); err != nil {
		t.Errorf("CRLF signature: %v", err)
	}
}

func TestVerify(t *testing.T) {
	key, priv := testKey(t, 0x11)
	otherKey, otherPriv := testKey(t, 0x22)
	// Same ID, different key: the ID only picks the key, it proves nothing.
	sameIDKey, sameIDPriv := testKey(t, 0x11)
	msg := []byte("hello\n")
	good := sign(priv, key, "ED", msg, "pihole-rbac v1.2.3")

	tests := []struct {
		name    string
		key     PublicKey
		msg     []byte
		sig     []byte
		wantErr string
	}{
		{name: "valid", key: key, msg: msg, sig: good},
		{name: "empty trusted comment", key: key, msg: msg, sig: sign(priv, key, "ED", msg, "")},
		{name: "empty file", key: key, msg: nil, sig: sign(priv, key, "ED", nil, "x")},
		{name: "other message", key: key, msg: []byte("hello"), sig: good, wantErr: "does not match its signature"},
		{name: "other key ID", key: otherKey, msg: msg, sig: good, wantErr: "not the release key"},
		{name: "signed by another key", key: key, msg: msg, sig: sign(otherPriv, key, "ED", msg, "x"), wantErr: "does not match"},
		{name: "same ID, other key", key: sameIDKey, msg: msg, sig: good, wantErr: "does not match"},
		{name: "same ID key signs", key: key, msg: msg, sig: sign(sameIDPriv, key, "ED", msg, "x"), wantErr: "does not match"},
		{name: "legacy algorithm", key: key, msg: msg, sig: sign(priv, key, "Ed", msg, "x"), wantErr: "legacy"},
		{name: "unknown algorithm", key: key, msg: msg, sig: sign(priv, key, "XX", msg, "x"), wantErr: "unsupported signature algorithm"},
		{name: "global signature swapped", key: key, msg: msg, sig: swapGlobal(good, sign(priv, key, "ED", msg, "other")), wantErr: "trusted comment does not match"},
		{name: "three lines", key: key, msg: msg, sig: firstLines(good, 3), wantErr: "has 3 lines"},
		{name: "five lines", key: key, msg: msg, sig: append(bytes.Clone(good), "extra\n"...), wantErr: "has 5 lines"},
		{name: "no untrusted comment", key: key, msg: msg, sig: replaceLine(good, 0, "comment: x"), wantErr: "untrusted comment"},
		{name: "no trusted comment", key: key, msg: msg, sig: replaceLine(good, 2, "comment: x"), wantErr: "trusted comment"},
		{name: "bad base64", key: key, msg: msg, sig: replaceLine(good, 1, "!!!"), wantErr: "malformed signature line"},
		{name: "short signature", key: key, msg: msg, sig: replaceLine(good, 1, base64.StdEncoding.EncodeToString([]byte("EDshort"))), wantErr: "malformed signature line"},
		{name: "short global", key: key, msg: msg, sig: replaceLine(good, 3, "AAAA"), wantErr: "malformed global"},
		{name: "oversized", key: key, msg: msg, sig: append(bytes.Clone(good), make([]byte, MaxSignatureSize)...), wantErr: "over"},
		{name: "long trusted comment", key: key, msg: msg, sig: sign(priv, key, "ED", msg, strings.Repeat("a", maxTrustedComment+1)), wantErr: "trusted comment is over"},
		{name: "zero key", key: PublicKey{ID: key.ID}, msg: msg, sig: good, wantErr: "no public key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Verify(tt.key, tt.msg, tt.sig)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want ErrInvalid containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestParsePublicKey(t *testing.T) {
	line := "RWSiTwpzJ1fyeg5FbD9k+fgdn1h28wLmH8lid3NJsRYxw5iv7iHhzUI/"
	tests := []struct {
		name, in string
		ok       bool
	}{
		{"line", line, true},
		{"file", releaseKey, true},
		{"file with CRLF", strings.ReplaceAll(releaseKey, "\n", "\r\n"), true},
		{"empty", "", false},
		{"comment without key", "untrusted comment: x\n", false},
		{"not a comment", "something\n" + line, false},
		{"three lines", "untrusted comment: x\n" + line + "\n" + line, false},
		{"bad base64", "RWS!", false},
		{"short", base64.StdEncoding.EncodeToString([]byte("Edshort")), false},
		{"wrong algorithm", base64.StdEncoding.EncodeToString(append([]byte("XX"), make([]byte, 40)...)), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePublicKey(tt.in)
			if (err == nil) != tt.ok {
				t.Fatalf("err = %v, want ok=%v", err, tt.ok)
			}
		})
	}
}

func lines(b []byte) []string { return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") }

func firstLines(b []byte, n int) []byte { return []byte(strings.Join(lines(b)[:n], "\n") + "\n") }

func replaceLine(b []byte, i int, s string) []byte {
	l := lines(b)
	l[i] = s
	return []byte(strings.Join(l, "\n") + "\n")
}

// swapGlobal puts the global signature of from into b, keeping b's trusted comment.
func swapGlobal(b, from []byte) []byte { return replaceLine(b, 3, lines(from)[3]) }
