// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/config"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// maxKeyFile is the most of an old key file that is read; a key is 44 characters of base64.
const maxKeyFile = 64 << 10

// cmdRotateKey is `pihole-rbac rotate-key --old-key-file <path>`: it re-encrypts every stored secret (instance
// passwords, the LDAP bind password, notification channel secrets) from the old master key, read from the file, to
// the new one, from PIHOLE_RBAC_SECRET_KEY (or _FILE) as serve reads it. The old key never appears on the command
// line or in the process list.
func cmdRotateKey(args []string) error {
	fs := flag.NewFlagSet("rotate-key", flag.ContinueOnError)
	fs.SetOutput(stderr)
	oldFile := fs.String("old-key-file", "", "a file holding the old master key (base64), as PIHOLE_RBAC_SECRET_KEY_FILE would")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: pihole-rbac rotate-key --old-key-file <path>")
		fmt.Fprintln(stderr, "Put the new key in PIHOLE_RBAC_SECRET_KEY (or _FILE) first, then run this, then reload or restart pihole-rbac.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *oldFile == "" {
		fs.Usage()
		return errors.New("rotate-key needs --old-key-file and no other arguments")
	}

	oldKey, err := readKeyFile(*oldFile)
	if err != nil {
		return err
	}
	oldC, err := secrets.NewCipher(oldKey)
	if err != nil {
		return err
	}
	cfg, err := config.FromEnv()
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	sec, err := secrets.Load(secrets.Options{DataDir: cfg.DataDir})
	if err != nil {
		return fmt.Errorf("secrets: %w", err)
	}
	newC := sec.Cipher()
	if newC == nil {
		return errors.New("the new master key isn't set: put it in PIHOLE_RBAC_SECRET_KEY (or PIHOLE_RBAC_SECRET_KEY_FILE) first")
	}
	if newC.KeyID() == oldC.KeyID() {
		return errors.New("the old key file holds the same key as PIHOLE_RBAC_SECRET_KEY: nothing to rotate")
	}

	ctx := context.Background()
	st, err := openForCLI(ctx)
	if err != nil {
		return err
	}
	defer st.Close()

	r, err := rotateKey(ctx, st, audit.NewLogger(stderr), oldC, newC)
	if err != nil {
		return err
	}
	switch {
	case len(r.rotated) == 0 && len(r.already) == 0:
		fmt.Fprintln(stdout, "There are no stored secrets: nothing to re-encrypt.")
		return nil
	case len(r.rotated) == 0:
		fmt.Fprintf(stdout, "Every stored secret (%d) is already under the new key: nothing to do.\n", len(r.already))
		return nil
	}
	fmt.Fprintf(stdout, "Re-encrypted %d stored %s under the new key: %s.\n", len(r.rotated), plural(len(r.rotated), "secret"),
		strings.Join(r.rotated, ", "))
	if len(r.already) > 0 {
		fmt.Fprintf(stdout, "%d %s already under it: %s.\n", len(r.already), isAre(len(r.already)), strings.Join(r.already, ", "))
	}
	fmt.Fprintln(stdout, "Now reload secrets (System page, or POST /api/v1/system/reload) or restart pihole-rbac, so it uses the new key.")
	fmt.Fprintln(stdout, "Backups made before now (pre-migrate-*.db, and the updater's) still hold these secrets under the old key.")
	return nil
}

func plural(n int, word string) string {
	if n == 1 {
		return word
	}
	return word + "s"
}

func isAre(n int) string {
	if n == 1 {
		return "was"
	}
	return "were"
}

// readKeyFile reads a key from a file as the secrets loader reads _FILE secrets: trailing line endings removed,
// nothing over 64 KiB. Errors name the file, never what is in it.
func readKeyFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("old key file: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxKeyFile+1))
	if err != nil {
		return nil, fmt.Errorf("old key file %s: %w", path, err)
	}
	if len(b) > maxKeyFile {
		return nil, fmt.Errorf("old key file %s is larger than %d KiB", path, maxKeyFile>>10)
	}
	b = bytes.TrimRight(b, "\r\n")
	key, err := secrets.DecodeKey(string(b))
	if err != nil {
		return nil, fmt.Errorf("old key file %s: %w", path, err)
	}
	return key, nil
}

// rotation says what rotateKey did, each secret named by its table and row.
type rotation struct {
	rotated []string // re-encrypted from the old key to the new one
	already []string // already under the new key, and checked to open with it
}

// sealedRow is one stored secret, however its table names its columns.
type sealedRow struct {
	label  string // what the output and audit row call it: "instance pihole1", "the LDAP bind password", "channel Ops"
	aad    []byte
	sealed secrets.Sealed
	save   func(q *db.Queries, s secrets.Sealed) error
}

// rotateKey re-encrypts every stored secret under the old key with the new one, in one transaction with one audit
// row. Rows already under the new key are left alone, so running it again is safe. If any row is under neither key,
// or doesn't decrypt, nothing is changed and the error lists those rows.
func rotateKey(ctx context.Context, st *store.Store, al *audit.Logger, oldC, newC *secrets.Cipher) (rotation, error) {
	var r rotation
	entry := audit.Entry{Username: cliUser, Action: audit.ActionRotateKey, Target: "secrets", Detail: map[string]any{}}
	err := st.WithTx(ctx, func(q *db.Queries) error {
		rows, err := sealedRows(ctx, q)
		if err != nil {
			return err
		}
		var problems []string
		type change struct {
			row    sealedRow
			sealed secrets.Sealed
		}
		var changes []change
		for _, row := range rows {
			switch row.sealed.KeyID {
			case newC.KeyID():
				if _, err := newC.Open(row.sealed, row.aad); err != nil {
					problems = append(problems, row.label+" (under the new key, but it doesn't decrypt)")
					continue
				}
				r.already = append(r.already, row.label)
			case oldC.KeyID():
				v, err := oldC.Open(row.sealed, row.aad)
				if err != nil {
					problems = append(problems, row.label+" (under the old key, but it doesn't decrypt)")
					continue
				}
				s, err := newC.Seal(v, row.aad)
				if err != nil {
					return err
				}
				changes = append(changes, change{row, s})
				r.rotated = append(r.rotated, row.label)
			default:
				problems = append(problems, row.label+" (under neither key)")
			}
		}
		if len(problems) > 0 {
			return fmt.Errorf("nothing was changed: %d stored %s can't be re-encrypted: %s. Store %s again in the app after rotating, or run this with the key %s under",
				len(problems), plural(len(problems), "secret"), strings.Join(problems, "; "), itThem(len(problems)), itThey(len(problems)))
		}
		if len(changes) == 0 {
			return errNothingToRotate
		}
		for _, c := range changes {
			if err := c.row.save(q, c.sealed); err != nil {
				return err
			}
		}
		entry.Detail["rotated"] = r.rotated
		if len(r.already) > 0 {
			entry.Detail["already"] = r.already
		}
		_, err = audit.Insert(ctx, q, entry)
		return err
	})
	if errors.Is(err, errNothingToRotate) {
		return r, nil
	}
	if err != nil {
		return rotation{}, err
	}
	al.Log(entry)
	return r, nil
}

var errNothingToRotate = errors.New("nothing to rotate")

func itThem(n int) string {
	if n == 1 {
		return "it"
	}
	return "them"
}

func itThey(n int) string {
	if n == 1 {
		return "is"
	}
	return "are"
}

// sealedRows lists every stored secret: instance passwords, settings secrets (the LDAP bind password) and channel
// secrets, each with the associated data it was sealed with.
func sealedRows(ctx context.Context, q *db.Queries) ([]sealedRow, error) {
	var out []sealedRow
	instances, err := q.ListSealedInstancePasswords(ctx)
	if err != nil {
		return nil, err
	}
	for _, i := range instances {
		id := i.ID
		out = append(out, sealedRow{
			label:  "instance " + i.Name,
			aad:    secrets.AAD("instances", id),
			sealed: secrets.Sealed{KeyID: i.PasswordKeyID.String, Nonce: i.PasswordNonce, Ciphertext: i.PasswordCiphertext},
			save: func(q *db.Queries, s secrets.Sealed) error {
				return q.ReencryptInstancePassword(ctx, db.ReencryptInstancePasswordParams{
					PasswordCiphertext: s.Ciphertext, PasswordNonce: s.Nonce, PasswordKeyID: validString(s.KeyID), ID: id,
				})
			},
		})
	}
	settings, err := q.ListSealedSettings(ctx)
	if err != nil {
		return nil, err
	}
	for _, sr := range settings {
		key := sr.Key
		label := "the " + key + " setting's secret"
		if key == "ldap" {
			label = "the LDAP bind password"
		}
		out = append(out, sealedRow{
			label:  label,
			aad:    secrets.AADKey("settings", key),
			sealed: secrets.Sealed{KeyID: sr.SecretKeyID.String, Nonce: sr.SecretNonce, Ciphertext: sr.SecretCiphertext},
			save: func(q *db.Queries, s secrets.Sealed) error {
				return q.ReencryptSettingSecret(ctx, db.ReencryptSettingSecretParams{
					SecretCiphertext: s.Ciphertext, SecretNonce: s.Nonce, SecretKeyID: validString(s.KeyID), Key: key,
				})
			},
		})
	}
	channels, err := q.ListSealedChannelSecrets(ctx)
	if err != nil {
		return nil, err
	}
	for _, c := range channels {
		id := c.ID
		out = append(out, sealedRow{
			label:  "channel " + c.Name,
			aad:    secrets.AAD("notification_channels", id),
			sealed: secrets.Sealed{KeyID: c.SecretKeyID.String, Nonce: c.SecretNonce, Ciphertext: c.SecretCiphertext},
			save: func(q *db.Queries, s secrets.Sealed) error {
				return q.ReencryptChannelSecret(ctx, db.ReencryptChannelSecretParams{
					SecretCiphertext: s.Ciphertext, SecretNonce: s.Nonce, SecretKeyID: validString(s.KeyID), ID: id,
				})
			},
		})
	}
	return out, nil
}

func validString(s string) sql.NullString { return sql.NullString{String: s, Valid: true} }
