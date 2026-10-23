// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/setup"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// cli points the commands at a temporary data directory and captures their output. in is what they read on stdin.
type cli struct {
	t       *testing.T
	dataDir string
	out     *bytes.Buffer
	errOut  *bytes.Buffer
}

func newCLI(t *testing.T) *cli {
	t.Helper()
	c := &cli{t: t, dataDir: t.TempDir(), out: &bytes.Buffer{}, errOut: &bytes.Buffer{}}
	t.Setenv("PIHOLE_RBAC_DATA_DIR", c.dataDir)
	oldIn, oldOut, oldErr, oldSecret := stdin, stdout, stderr, readSecret
	t.Cleanup(func() { stdin, stdout, stderr, readSecret = oldIn, oldOut, oldErr, oldSecret })
	stdout, stderr = c.out, c.errOut
	stdin = strings.NewReader("")
	return c
}

func (c *cli) run(in string, args ...string) error {
	c.out.Reset()
	c.errOut.Reset()
	stdin = strings.NewReader(in)
	return run(args)
}

func (c *cli) store() *store.Store {
	c.t.Helper()
	st, err := store.Open(context.Background(), store.Options{DataDir: c.dataDir, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		c.t.Fatal(err)
	}
	c.t.Cleanup(func() { st.Close() })
	return st
}

var tokenLine = regexp.MustCompile(`Setup token \(valid until [^)]+\): (\S+)\n`)

func TestSetupCommand(t *testing.T) {
	c := newCLI(t)
	if err := c.run("", "setup"); err != nil || !strings.Contains(c.out.String(), "setup is open") {
		t.Fatalf("setup: %v %q", err, c.out)
	}

	if err := c.run("", "setup", "--print-token"); err != nil {
		t.Fatal(err)
	}
	m := tokenLine.FindStringSubmatch(c.out.String())
	if m == nil {
		t.Fatalf("no token printed: %q", c.out)
	}
	if !strings.Contains(c.errOut.String(), "action=setup_token") || strings.Contains(c.errOut.String(), m[1]) {
		t.Fatalf("AUDIT line = %q (it must not contain the token)", c.errOut)
	}

	// The printed token completes setup.
	st := c.store()
	ctx := context.Background()
	if err := st.WithTx(ctx, func(q *db.Queries) error {
		_, _, err := setup.Complete(ctx, q, m[1], "kate", "first-admin-password", time.Now())
		return err
	}); err != nil {
		t.Fatalf("printed token didn't work: %v", err)
	}

	if err := c.run("", "setup", "--print-token"); err == nil || !strings.Contains(err.Error(), "reset-admin") {
		t.Fatalf("--print-token after setup: %v", err)
	}
	if err := c.run("", "setup"); err != nil || !strings.Contains(c.out.String(), "complete") {
		t.Fatalf("setup after completion: %v %q", err, c.out)
	}
	if err := c.run("", "setup", "extra"); err == nil {
		t.Fatal("setup with an argument accepted")
	}
}

func TestResetAdminCommand(t *testing.T) {
	c := newCLI(t)
	if err := c.run("rescue-password-1\n", "user", "reset-admin", "Rescue"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(c.out.String(), `Created local admin "rescue"`) {
		t.Fatalf("output = %q", c.out)
	}
	if strings.Contains(c.out.String()+c.errOut.String(), "rescue-password-1") {
		t.Fatal("the password was printed")
	}

	st := c.store()
	ctx := context.Background()
	u, err := st.Read().GetUserByUsername(ctx, "rescue")
	if err != nil || bcrypt.CompareHashAndPassword([]byte(u.PasswordHash.String), []byte("rescue-password-1")) != nil {
		t.Fatalf("user = %+v, %v", u, err)
	}
	if needed, _ := setup.Required(ctx, st.Read()); needed {
		t.Fatal("setup still open after reset-admin created an admin")
	}
	row, err := st.Read().GetAudit(ctx, 1)
	if err != nil || row.Action != audit.ActionResetAdmin || row.Username != cliUser || row.Target != "rescue" || row.UserID.Int64 != u.ID {
		t.Fatalf("audit row = %+v, %v", row, err)
	}

	// Running it again resets the same account.
	if err := c.run("rescue-password-2\r\n", "user", "reset-admin", "rescue"); err != nil {
		t.Fatal(err)
	}
	if u2, _ := st.Read().GetUserByUsername(ctx, "rescue"); u2.ID != u.ID ||
		bcrypt.CompareHashAndPassword([]byte(u2.PasswordHash.String), []byte("rescue-password-2")) != nil {
		t.Fatal("password not reset")
	}
}

func TestResetAdminCommandRefusals(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		args    []string
		wantErr string
	}{
		{"no subcommand", "", []string{"user"}, "subcommand"},
		{"unknown subcommand", "", []string{"user", "delete", "x"}, "subcommand"},
		{"no username", "", []string{"user", "reset-admin"}, "exactly one"},
		{"password as a flag", "", []string{"user", "reset-admin", "--password=x"}, "exactly one"},
		{"nothing on stdin", "", []string{"user", "reset-admin", "rescue"}, "no password"},
		{"short password", "short\n", []string{"user", "reset-admin", "rescue"}, "at least 12"},
		{"LDAP account", "rescue-password-1\n", []string{"user", "reset-admin", "ldapuser"}, "LDAP"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newCLI(t)
			st := c.store()
			ctx := context.Background()
			if err := st.WithTx(ctx, func(q *db.Queries) error {
				_, err := q.CreateLDAPUser(ctx, db.CreateLDAPUserParams{Username: "ldapuser", LdapDn: sql.NullString{String: "cn=x", Valid: true}})
				return err
			}); err != nil {
				t.Fatal(err)
			}
			err := c.run(tt.in, tt.args...)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want it to mention %q", err, tt.wantErr)
			}
			if needed, _ := setup.Required(ctx, st.Read()); !needed {
				t.Fatal("a refused reset-admin closed setup")
			}
		})
	}
}

func TestResetAdminAsksTwiceOnATerminal(t *testing.T) {
	tests := []struct {
		name    string
		answers []string
		wantErr string
	}{
		{"matching", []string{"rescue-password-1", "rescue-password-1"}, ""},
		{"mismatch", []string{"rescue-password-1", "rescue-password-2"}, "don't match"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newCLI(t)
			var prompts []string
			readSecret = func(prompt string) (string, bool, error) {
				prompts = append(prompts, prompt)
				if len(prompts) > len(tt.answers) {
					return "", true, errors.New("asked too often")
				}
				return tt.answers[len(prompts)-1], true, nil
			}
			err := c.run("ignored-when-interactive\n", "user", "reset-admin", "rescue")
			if tt.wantErr == "" && err != nil || tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
			if len(prompts) != 2 {
				t.Fatalf("prompts = %q, want two", prompts)
			}
		})
	}
}

func TestAnnounceSetup(t *testing.T) {
	c := newCLI(t)
	st := c.store()
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))
	ctx := context.Background()

	if err := announceSetup(ctx, st, logger); err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`token=(\S+)`).FindStringSubmatch(logBuf.String())
	if m == nil || !strings.Contains(logBuf.String(), "/setup") {
		t.Fatalf("log = %q", logBuf.String())
	}
	if err := st.WithTx(ctx, func(q *db.Queries) error {
		_, _, err := setup.Complete(ctx, q, m[1], "kate", "first-admin-password", time.Now())
		return err
	}); err != nil {
		t.Fatalf("logged token didn't work: %v", err)
	}

	logBuf.Reset()
	if err := announceSetup(ctx, st, logger); err != nil || logBuf.Len() != 0 {
		t.Fatalf("after setup: err %v, log %q", err, logBuf.String())
	}
}
