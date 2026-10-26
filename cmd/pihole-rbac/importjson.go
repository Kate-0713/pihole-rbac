// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/config"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/v1import"
)

// importTimeout bounds the connection test and the bind test together.
const importTimeout = 2 * time.Minute

// cmdImportJSON is `pihole-rbac import-json --config config.json [--permissions …] [--users …] [--apply]`: it reads
// a v1 installation's files and prints what it would import; with --apply it imports it into a new database. It
// contacts the Pi-hole and the LDAP server (unless --offline) to decide what can be switched on.
func cmdImportJSON(args []string) error {
	fs := flag.NewFlagSet("import-json", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configFile := fs.String("config", "", "v1's config.json (required)")
	permissions := fs.String("permissions", "", "v1's permissions.json (default: the permissions_file config.json names, next to it)")
	users := fs.String("users", "", "v1's local-users.json (default: the local_users_file config.json names, next to it)")
	instanceName := fs.String("instance-name", v1import.DefaultInstanceName, "the name for v1's Pi-hole")
	timeZone := fs.String("time-zone", "", "the time zone of v1's client reset schedule (the v1 host's), such as Europe/London")
	offline := fs.Bool("offline", false, "don't contact the Pi-hole or the LDAP server: nothing is switched on")
	apply := fs.Bool("apply", false, "import into the database; without it, only show what would be imported")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: pihole-rbac import-json --config <config.json> [--permissions <file>] [--users <file>] [--instance-name <name>] [--time-zone <zone>] [--offline] [--apply]")
		fmt.Fprintln(stderr, "Shows what would be imported from v1; --apply imports it into a new database (PIHOLE_RBAC_DATA_DIR).")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *configFile == "" {
		fs.Usage()
		return errors.New("import-json needs --config and no other arguments")
	}

	cfg, err := config.FromEnv()
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	sec, err := secrets.Load(secrets.Options{DataDir: cfg.DataDir})
	if err != nil {
		return fmt.Errorf("secrets: %w", err)
	}
	v1, err := v1import.Read(v1import.Files{Config: *configFile, Permissions: *permissions, Users: *users})
	if err != nil {
		return err
	}
	plan := v1import.Build(v1, v1import.Options{
		InstanceName: *instanceName, TimeZone: *timeZone, Secrets: sec, LDAPCAFile: cfg.LDAPCAFile,
	})

	ctx, cancel := context.WithTimeout(context.Background(), importTimeout)
	defer cancel()
	var prober v1import.Prober
	if !*offline {
		prober = v1import.Live{LDAPCAFile: cfg.LDAPCAFile}
	}
	v1import.Check(ctx, plan, prober, "--offline")

	if *apply {
		fmt.Fprintf(stdout, "Importing v1's settings into %s.\n", filepath.Join(cfg.DataDir, store.FileName))
	} else {
		fmt.Fprintf(stdout, "Dry run: this is what --apply would import into %s. Nothing has been changed.\n", filepath.Join(cfg.DataDir, store.FileName))
	}
	if sec.Cipher() == nil {
		fmt.Fprintln(stdout, "PIHOLE_RBAC_SECRET_KEY isn't set, so no secret can be stored: each one is expected in an environment variable instead.")
		fmt.Fprintln(stdout, "To store them encrypted, set PIHOLE_RBAC_SECRET_KEY to the key the app will run with, and run this again.")
	}
	plan.Report(stdout)
	fmt.Fprintln(stdout)

	if !*apply {
		if err := checkTarget(ctx, cfg.DataDir); err != nil {
			fmt.Fprintf(stdout, "The database can't be imported into: %v.\n", err)
			return errors.New("the database isn't new")
		}
		if len(plan.Errors) > 0 {
			return fmt.Errorf("%d %s to fix before --apply", len(plan.Errors), plural(len(plan.Errors), "problem"))
		}
		fmt.Fprintln(stdout, "Run the same command with --apply to import. Stop pihole-rbac first if it is running on this data directory.")
		return nil
	}
	if len(plan.Errors) > 0 {
		return fmt.Errorf("nothing was imported: %d %s to fix first", len(plan.Errors), plural(len(plan.Errors), "problem"))
	}

	st, err := openForCLI(ctx)
	if err != nil {
		return err
	}
	defer st.Close()
	res, err := v1import.Apply(ctx, st, audit.NewLogger(stderr), sec.Cipher(), plan, cliUser, time.Now())
	if err != nil {
		return fmt.Errorf("nothing was imported: %w", err)
	}
	fmt.Fprintf(stdout, "Imported. The audit log has an entry for each thing created (%d), by %s.\n", res.Entries, cliUser)
	if res.SetupClosed {
		fmt.Fprintln(stdout, "First-run setup is closed: log in with a v1 local admin's username and password.")
	} else {
		fmt.Fprintln(stdout, "First-run setup is still open: start pihole-rbac and finish setup with the token it logs to create a local admin.")
	}
	fmt.Fprintln(stdout, "Do the steps under \"To do by hand\" above, then start pihole-rbac.")
	return nil
}

// checkTarget says whether the data directory's database can be imported into, without creating one: a database that
// doesn't exist yet will be new.
func checkTarget(ctx context.Context, dataDir string) error {
	if _, err := os.Stat(filepath.Join(dataDir, store.FileName)); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	st, err := openForCLI(ctx)
	if err != nil {
		return err
	}
	defer st.Close()
	return v1import.Fresh(ctx, st.Read())
}
