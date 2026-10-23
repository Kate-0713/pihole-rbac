// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/config"
	"github.com/Kate-0713/pihole-rbac/internal/setup"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// The CLI commands read and write through these, so tests can replace them.
var (
	stdin  io.Reader = os.Stdin
	stdout io.Writer = os.Stdout
	stderr io.Writer = os.Stderr
	// readSecret reads a line without echoing it, when stdin is a terminal. ok is false otherwise.
	readSecret = func(prompt string) (string, bool, error) {
		fd := int(os.Stdin.Fd())
		if stdin != os.Stdin || !term.IsTerminal(fd) {
			return "", false, nil
		}
		fmt.Fprint(stderr, prompt)
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(stderr)
		return string(b), true, err
	}
)

// cliUser is the audit log's "user" for changes made from the command line, where nobody is logged in.
const cliUser = "(cli)"

// openForCLI opens the database the same way serve does, logging only warnings and errors.
func openForCLI(ctx context.Context) (*store.Store, error) {
	cfg, err := config.FromEnv()
	if err != nil {
		return nil, fmt.Errorf("configuration: %w", err)
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	return store.Open(ctx, store.Options{DataDir: cfg.DataDir, Logger: logger})
}

// announceSetup makes a setup token and logs it if first-run setup is still open. A new token is made on every
// start, so an expired one never blocks setup for longer than a restart.
func announceSetup(ctx context.Context, st *store.Store, logger *slog.Logger) error {
	needed, err := setup.Required(ctx, st.Read())
	if err != nil || !needed {
		return err
	}
	token, expires, err := setup.NewToken(ctx, st, time.Now())
	if err != nil {
		return fmt.Errorf("first-run setup: %w", err)
	}
	logger.Warn("first-run setup is open: go to /setup and enter this setup token. Run `pihole-rbac setup --print-token` for a new one",
		"token", token, "expires", expires.UTC().Format(time.RFC3339))
	return nil
}

// cmdSetup is `pihole-rbac setup [--print-token]`.
func cmdSetup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	printToken := fs.Bool("print-token", false, "make a new setup token (valid for 1 hour) and print it; the previous one stops working")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: pihole-rbac setup [--print-token]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return errors.New("setup takes no arguments")
	}

	ctx := context.Background()
	st, err := openForCLI(ctx)
	if err != nil {
		return err
	}
	defer st.Close()

	if !*printToken {
		needed, err := setup.Required(ctx, st.Read())
		if err != nil {
			return err
		}
		if needed {
			fmt.Fprintln(stdout, "First-run setup is open. Run `pihole-rbac setup --print-token` for a setup token.")
		} else {
			fmt.Fprintln(stdout, "First-run setup is complete. If every admin is locked out, use `pihole-rbac user reset-admin`.")
		}
		return nil
	}

	token, expires, err := setup.NewToken(ctx, st, time.Now())
	if errors.Is(err, setup.ErrComplete) {
		return errors.New("first-run setup is already complete; if every admin is locked out, use `pihole-rbac user reset-admin`")
	}
	if err != nil {
		return err
	}
	entry := audit.Entry{Username: cliUser, Action: audit.ActionSetupToken, Detail: map[string]any{"expires": expires.UTC().Format(time.RFC3339)}}
	if err := audit.NewLogger(stderr).Record(ctx, st, entry); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Setup token (valid until %s): %s\n", expires.Local().Format("2006-01-02 15:04 MST"), token)
	return nil
}

// cmdUser is `pihole-rbac user <subcommand>`.
func cmdUser(args []string) error {
	if len(args) == 0 || args[0] != "reset-admin" {
		fmt.Fprintln(stderr, "usage: pihole-rbac user reset-admin <username>")
		return errors.New("unknown or missing user subcommand")
	}
	if len(args) != 2 || strings.HasPrefix(args[1], "-") {
		fmt.Fprintln(stderr, "usage: pihole-rbac user reset-admin <username>")
		fmt.Fprintln(stderr, "The new password is read from the terminal (asked twice), or from the first line of stdin.")
		return errors.New("reset-admin takes exactly one argument, the username")
	}
	return resetAdmin(args[1])
}

// resetAdmin is the break-glass recovery. The password never appears on the command line, where it would be visible
// in the process list and shell history.
func resetAdmin(username string) error {
	password, err := readNewPassword()
	if err != nil {
		return err
	}

	ctx := context.Background()
	st, err := openForCLI(ctx)
	if err != nil {
		return err
	}
	defer st.Close()

	entry := audit.Entry{Username: cliUser, Action: audit.ActionResetAdmin, Target: strings.ToLower(strings.TrimSpace(username))}
	var res setup.ResetResult
	err = st.WithTx(ctx, func(q *db.Queries) error {
		var err error
		if res, err = setup.ResetAdmin(ctx, q, username, password, time.Now()); err != nil {
			return err
		}
		entry.UserID = res.UserID
		entry.Detail = map[string]any{"created": res.Created, "sessions_ended": res.SessionsEnded}
		_, err = audit.Insert(ctx, q, entry)
		return err
	})
	if err != nil {
		return err
	}
	audit.NewLogger(stderr).Log(entry)

	if res.Created {
		fmt.Fprintf(stdout, "Created local admin %q.\n", entry.Target)
	} else {
		fmt.Fprintf(stdout, "Reset %q: new password set, account enabled, admin role ensured, %d session(s) ended.\n", entry.Target, res.SessionsEnded)
	}
	return nil
}

// readNewPassword asks twice without echo on a terminal; otherwise it reads the first line of stdin, for scripts.
func readNewPassword() (string, error) {
	pw, interactive, err := readSecret("New password: ")
	if err != nil {
		return "", err
	}
	if interactive {
		again, _, err := readSecret("Repeat the password: ")
		if err != nil {
			return "", err
		}
		if pw != again {
			return "", errors.New("the passwords don't match")
		}
		return pw, nil
	}
	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return "", errors.New("no password given on stdin")
	}
	return line, nil
}
