// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kate-0713/pihole-rbac/internal/secrets"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// keyPair is an old and a new master key, with ciphers, and the old one written to a file.
type keyPair struct {
	oldFile    string
	old, new   *secrets.Cipher
	newEncoded string
}

func newKeys(t *testing.T, c *cli) keyPair {
	t.Helper()
	oldEnc, newEnc := secrets.NewKey(), secrets.NewKey()
	k := keyPair{oldFile: filepath.Join(t.TempDir(), "old.key"), newEncoded: newEnc}
	// Written as an editor on Windows might: with CRLF at the end, which is removed as for _FILE secrets.
	if err := os.WriteFile(k.oldFile, []byte(oldEnc+"\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	k.old, k.new = cipherOf(t, oldEnc), cipherOf(t, newEnc)
	t.Setenv("PIHOLE_RBAC_SECRET_KEY", newEnc)
	return k
}

func cipherOf(t *testing.T, enc string) *secrets.Cipher {
	t.Helper()
	b, err := secrets.DecodeKey(enc)
	if err != nil {
		t.Fatal(err)
	}
	c, err := secrets.NewCipher(b)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func seal(t *testing.T, c *secrets.Cipher, plain string, aad []byte) secrets.Sealed {
	t.Helper()
	s, err := c.Seal(secrets.NewValue([]byte(plain)), aad)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func ns(s string) sql.NullString { return sql.NullString{String: s, Valid: true} }
func ni(n int64) sql.NullInt64   { return sql.NullInt64{Int64: n, Valid: true} }

// seedSecrets stores an instance password and the LDAP bind password under c1, a channel secret under c1 and another
// under c2, and returns the row IDs.
func seedSecrets(t *testing.T, st *store.Store, c1, c2 *secrets.Cipher) (instance, ch1, ch2 int64) {
	t.Helper()
	ctx := context.Background()
	err := st.WithTx(ctx, func(q *db.Queries) error {
		var err error
		if instance, err = q.CreateInstance(ctx, db.CreateInstanceParams{Name: "pihole1", BaseUrl: "http://p.lan", TlsMode: "verify", CreatedAt: 1}); err != nil {
			return err
		}
		s := seal(t, c1, "pihole-password", secrets.AAD("instances", instance))
		if err := q.SetInstancePassword(ctx, db.SetInstancePasswordParams{PasswordCiphertext: s.Ciphertext, PasswordNonce: s.Nonce,
			PasswordKeyID: ns(s.KeyID), PasswordUpdatedAt: ni(111), PasswordUpdatedBy: ns("alice"), ID: instance}); err != nil {
			return err
		}
		if err := q.UpsertSetting(ctx, db.UpsertSettingParams{Key: "ldap", Value: "{}", UpdatedAt: 1, UpdatedBy: "alice"}); err != nil {
			return err
		}
		s = seal(t, c1, "bind-password", secrets.AADKey("settings", "ldap"))
		if _, err := q.SetSettingSecret(ctx, db.SetSettingSecretParams{SecretCiphertext: s.Ciphertext, SecretNonce: s.Nonce,
			SecretKeyID: ns(s.KeyID), SecretUpdatedAt: ni(222), SecretUpdatedBy: ns("alice"), Key: "ldap"}); err != nil {
			return err
		}
		for i, c := range []*secrets.Cipher{c1, c2} {
			id, err := q.CreateChannel(ctx, db.CreateChannelParams{Kind: "matrix", Name: []string{"Ops", "Room"}[i], Config: "{}", Enabled: true, CreatedAt: 1})
			if err != nil {
				return err
			}
			s := seal(t, c, "token-"+[]string{"ops", "room"}[i], secrets.AAD("notification_channels", id))
			if err := q.SetChannelSecret(ctx, db.SetChannelSecretParams{SecretCiphertext: s.Ciphertext, SecretNonce: s.Nonce,
				SecretKeyID: ns(s.KeyID), SecretUpdatedAt: ni(333), SecretUpdatedBy: ns("alice"), ID: id}); err != nil {
				return err
			}
			if i == 0 {
				ch1 = id
			} else {
				ch2 = id
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return instance, ch1, ch2
}

// opens checks every stored secret opens with c and holds what was stored, with its "last changed" left alone.
func opens(t *testing.T, st *store.Store, c *secrets.Cipher, instance, ch1, ch2 int64) {
	t.Helper()
	ctx := context.Background()
	q := st.Read()
	check := func(what string, s secrets.Sealed, aad []byte, want string) {
		t.Helper()
		v, err := c.Open(s, aad)
		if err != nil || v.Reveal() != want {
			t.Errorf("%s: %v", what, err)
		}
	}
	i, _ := q.GetInstance(ctx, instance)
	check("instance", secrets.Sealed{KeyID: i.PasswordKeyID.String, Nonce: i.PasswordNonce, Ciphertext: i.PasswordCiphertext},
		secrets.AAD("instances", instance), "pihole-password")
	if i.PasswordUpdatedAt.Int64 != 111 || i.PasswordUpdatedBy.String != "alice" {
		t.Errorf("instance password's last change was rewritten: %v %v", i.PasswordUpdatedAt, i.PasswordUpdatedBy)
	}
	l, _ := q.GetSetting(ctx, "ldap")
	check("ldap", secrets.Sealed{KeyID: l.SecretKeyID.String, Nonce: l.SecretNonce, Ciphertext: l.SecretCiphertext},
		secrets.AADKey("settings", "ldap"), "bind-password")
	for id, want := range map[int64]string{ch1: "token-ops", ch2: "token-room"} {
		ch, _ := q.GetChannel(ctx, id)
		check("channel", secrets.Sealed{KeyID: ch.SecretKeyID.String, Nonce: ch.SecretNonce, Ciphertext: ch.SecretCiphertext},
			secrets.AAD("notification_channels", id), want)
		if ch.SecretUpdatedAt.Int64 != 333 {
			t.Errorf("channel %d's last change was rewritten", id)
		}
	}
}

func auditCount(t *testing.T, st *store.Store, action string) int {
	t.Helper()
	rows, err := st.Read().ListRecentAudit(context.Background(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range rows {
		if r.Action == action {
			n++
		}
	}
	return n
}

func TestRotateKey(t *testing.T) {
	c := newCLI(t)
	k := newKeys(t, c)
	st := c.store()
	// Room's secret is already under the new key, as after a rotation interrupted by hand.
	instance, ch1, ch2 := seedSecrets(t, st, k.old, k.new)

	if err := c.run("", "rotate-key", "--old-key-file", k.oldFile); err != nil {
		t.Fatalf("rotate-key: %v\n%s", err, c.errOut)
	}
	out := c.out.String()
	for _, want := range []string{
		"Re-encrypted 3 stored secrets under the new key: instance pihole1, the LDAP bind password, channel Ops.",
		"1 was already under it: channel Room.",
		"reload secrets", "still hold these secrets under the old key",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	opens(t, st, k.new, instance, ch1, ch2)
	if !strings.Contains(c.errOut.String(), `AUDIT user="(cli)" action=rotate_key target="secrets" result=success`) {
		t.Errorf("AUDIT line: %q", c.errOut)
	}
	for _, secret := range []string{"pihole-password", "bind-password", "token-ops", k.newEncoded} {
		if strings.Contains(c.out.String()+c.errOut.String(), secret) {
			t.Errorf("a secret was printed: %s", secret)
		}
	}
	rows, _ := st.Read().ListRecentAudit(context.Background(), 1)
	if rows[0].Action != "rotate_key" || !strings.Contains(rows[0].Detail, `"rotated":["instance pihole1","the LDAP bind password","channel Ops"]`) ||
		!strings.Contains(rows[0].Detail, `"already":["channel Room"]`) || rows[0].Username != cliUser {
		t.Errorf("audit row: %+v", rows[0])
	}

	// Again: nothing to do, and nothing audited.
	if err := c.run("", "rotate-key", "--old-key-file", k.oldFile); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(c.out.String(), "Every stored secret (4) is already under the new key") || auditCount(t, st, "rotate_key") != 1 {
		t.Errorf("second run: %q, %d rows", c.out, auditCount(t, st, "rotate_key"))
	}
}

// A secret under neither key, or one that doesn't decrypt, stops the whole rotation.
func TestRotateKeyRefusesWhatItCantOpen(t *testing.T) {
	for _, tt := range []struct {
		name    string
		spoil   func(t *testing.T, st *store.Store, k keyPair, ch2 int64)
		message string
	}{
		{"under a third key", func(t *testing.T, st *store.Store, k keyPair, ch2 int64) {
			third := cipherOf(t, secrets.NewKey())
			s := seal(t, third, "x", secrets.AAD("notification_channels", ch2))
			setChannelSecret(t, st, ch2, s)
		}, "channel Room (under neither key)"},
		{"tampered", func(t *testing.T, st *store.Store, k keyPair, ch2 int64) {
			s := seal(t, k.old, "x", secrets.AAD("notification_channels", ch2))
			s.Ciphertext[0] ^= 1
			setChannelSecret(t, st, ch2, s)
		}, "channel Room (under the old key, but it doesn't decrypt)"},
		{"moved from another row", func(t *testing.T, st *store.Store, k keyPair, ch2 int64) {
			s := seal(t, k.old, "x", secrets.AAD("notification_channels", ch2+100))
			setChannelSecret(t, st, ch2, s)
		}, "channel Room (under the old key, but it doesn't decrypt)"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newCLI(t)
			k := newKeys(t, c)
			st := c.store()
			instance, ch1, ch2 := seedSecrets(t, st, k.old, k.old)
			tt.spoil(t, st, k, ch2)
			err := c.run("", "rotate-key", "--old-key-file", k.oldFile)
			if err == nil || !strings.Contains(err.Error(), "nothing was changed") || !strings.Contains(err.Error(), tt.message) {
				t.Fatalf("error: %v", err)
			}
			// Everything else is still under the old key, and nothing was audited.
			i, _ := st.Read().GetInstance(context.Background(), instance)
			ch, _ := st.Read().GetChannel(context.Background(), ch1)
			if i.PasswordKeyID.String != k.old.KeyID() || ch.SecretKeyID.String != k.old.KeyID() || auditCount(t, st, "rotate_key") != 0 {
				t.Errorf("something changed: %s %s", i.PasswordKeyID.String, ch.SecretKeyID.String)
			}
		})
	}
}

func setChannelSecret(t *testing.T, st *store.Store, id int64, s secrets.Sealed) {
	t.Helper()
	ctx := context.Background()
	if err := st.WithTx(ctx, func(q *db.Queries) error {
		return q.ReencryptChannelSecret(ctx, db.ReencryptChannelSecretParams{SecretCiphertext: s.Ciphertext, SecretNonce: s.Nonce, SecretKeyID: ns(s.KeyID), ID: id})
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRotateKeyArguments(t *testing.T) {
	c := newCLI(t)
	k := newKeys(t, c)
	c.store() // a database with no secrets

	if err := c.run("", "rotate-key"); err == nil {
		t.Error("no --old-key-file accepted")
	}
	if err := c.run("", "rotate-key", "--old-key-file", k.oldFile, "extra"); err == nil {
		t.Error("an extra argument accepted")
	}
	if err := c.run("", "rotate-key", "--old-key-file", filepath.Join(t.TempDir(), "missing")); err == nil || !strings.Contains(err.Error(), "old key file") {
		t.Errorf("missing file: %v", err)
	}
	bad := filepath.Join(t.TempDir(), "bad.key")
	_ = os.WriteFile(bad, []byte("not-a-key-but-a-secret-looking-string\n"), 0o600)
	if err := c.run("", "rotate-key", "--old-key-file", bad); err == nil || strings.Contains(err.Error(), "secret-looking") {
		t.Errorf("bad key: %v", err)
	}
	big := filepath.Join(t.TempDir(), "big.key")
	_ = os.WriteFile(big, bytes.Repeat([]byte("A"), maxKeyFile+1), 0o600)
	if err := c.run("", "rotate-key", "--old-key-file", big); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("big file: %v", err)
	}
	same := filepath.Join(t.TempDir(), "same.key")
	_ = os.WriteFile(same, []byte(k.newEncoded), 0o600)
	if err := c.run("", "rotate-key", "--old-key-file", same); err == nil || !strings.Contains(err.Error(), "same key") {
		t.Errorf("same key: %v", err)
	}
	if err := c.run("", "rotate-key", "--old-key-file", k.oldFile); err != nil || !strings.Contains(c.out.String(), "no stored secrets") {
		t.Errorf("no secrets: %v %q", err, c.out)
	}
	t.Setenv("PIHOLE_RBAC_SECRET_KEY", "")
	if err := c.run("", "rotate-key", "--old-key-file", k.oldFile); err == nil || !strings.Contains(err.Error(), "new master key isn't set") {
		t.Errorf("no new key: %v", err)
	}
}
