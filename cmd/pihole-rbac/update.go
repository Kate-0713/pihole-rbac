// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/config"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/release"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
	"github.com/Kate-0713/pihole-rbac/internal/updater"
	"github.com/Kate-0713/pihole-rbac/internal/updates"
)

// The LXC install's fixed paths (see deploy/lxc/install.sh).
const (
	lxcBinary   = "/usr/local/bin/pihole-rbac"
	lxcEnvFile  = "/etc/pihole-rbac/env"
	serviceUser = "pihole-rbac"
)

// These are variables so tests can change them.
var (
	updateRequestFile = updates.RequestFile
	updatePoll        = time.Second
	// updateWaitLimit covers the updater's work plus the app's own limit for a request nobody picks up.
	updateWaitLimit = 25 * time.Minute
)

// cmdUpdate is `pihole-rbac update [--no-wait] [vX.Y.Z]`: the command-line version of Update now. It records a
// request for the updater and, unless --no-wait is given, follows it until it finishes. On an LXC install, root's
// `sudo pihole-rbac update` runs it as the service user (see reexecAsService).
func cmdUpdate(args []string) error {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(stderr)
	noWait := fs.Bool("no-wait", false, "record the request and return without following it")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: pihole-rbac update [--no-wait] [vX.Y.Z]")
		fmt.Fprintln(stderr, "Updates to the given release, or to the latest one. LXC installs only.")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 1 {
		fs.Usage()
		return errors.New("update takes at most one version")
	}
	cfg, err := config.FromEnv()
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	st, err := openForCLI(ctx)
	if err != nil {
		return err
	}
	svc := &updates.Service{
		Store: st, Audit: audit.NewLogger(stderr), Install: updates.Install(cfg.Install), RequestFile: updateRequestFile,
	}
	r, err := svc.Request(ctx, updates.Actor{Username: cliUser}, strings.TrimSpace(fs.Arg(0)))
	st.Close()
	if e, ok := rbac.AsError(err); ok {
		return errors.New(e.Message)
	}
	if err != nil {
		return err
	}
	what := "the latest release"
	if r.TargetVersion != "" {
		what = r.TargetVersion
	}
	fmt.Fprintf(stdout, "Update request %d recorded: updating to %s.\n", r.ID, what)
	if *noWait {
		fmt.Fprintln(stdout, "Follow it on the System page, or with: journalctl -fu pihole-rbac-update")
		return nil
	}
	return followUpdate(ctx, cfg.DataDir, r.ID)
}

// followUpdate prints the request's log as it grows until the request finishes. It opens the database afresh for
// each look: a rollback replaces the file, and after an update the schema may be newer than this binary's.
func followUpdate(ctx context.Context, dataDir string, id int64) error {
	ctx, cancel := context.WithTimeout(ctx, updateWaitLimit)
	defer cancel()
	printed := 0
	for {
		r, err := readUpdateRequest(ctx, dataDir, id)
		if err != nil && ctx.Err() == nil {
			fmt.Fprintf(stderr, "reading the request (retrying): %v\n", err)
		}
		if err == nil {
			if len(r.Log) > printed {
				fmt.Fprint(stdout, r.Log[printed:])
				printed = len(r.Log)
			}
			switch r.Status {
			case updater.StatusDone:
				fmt.Fprintln(stdout, "Update finished.")
				return nil
			case updater.StatusFailed:
				return errors.New("the update failed; nothing was changed")
			case updater.StatusRolledBack:
				return errors.New("the update was rolled back; the previous version is running")
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("stopped following update request %d (it carries on): %w", id, ctx.Err())
		case <-time.After(updatePoll):
		}
	}
}

func readUpdateRequest(ctx context.Context, dataDir string, id int64) (db.UpdateRequest, error) {
	d, err := store.OpenUnmigrated(ctx, dataDir)
	if err != nil {
		return db.UpdateRequest{}, err
	}
	defer d.Close()
	rows, err := db.New(d).ListUpdateRequests(ctx, updates.History)
	if err != nil {
		return db.UpdateRequest{}, err
	}
	for _, r := range rows {
		if r.ID == id {
			return r, nil
		}
	}
	return db.UpdateRequest{}, fmt.Errorf("update request %d isn't in the database", id)
}

// cmdUpdater is `pihole-rbac updater`, run as root by pihole-rbac-update.service: it carries out the oldest pending
// update request. It exits with an error when the update failed or was rolled back, so the unit shows as failed.
func cmdUpdater(args []string) error {
	if len(args) != 0 {
		return errors.New("updater takes no arguments")
	}
	if os.Geteuid() != 0 {
		return errors.New("pihole-rbac updater is run as root by pihole-rbac-update.service; to ask for an update, run sudo pihole-rbac update")
	}
	cfg, err := config.FromEnv()
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	url, err := healthURL(cfg.Listen)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()

	u := &updater.Updater{
		DataDir:     cfg.DataDir,
		Binary:      lxcBinary,
		RequestFile: updateRequestFile,
		Arch:        runtime.GOARCH,
		Source:      release.NewClient(5 * time.Minute),
		System:      &hostSystem{healthURL: url},
		Out:         stdout,
	}
	status, err := u.Run(ctx)
	switch {
	case err != nil:
		return err
	case status == updater.StatusFailed || status == updater.StatusRolledBack:
		return fmt.Errorf("update %s", strings.ReplaceAll(status, "_", " "))
	}
	return nil
}

// hostSystem is the updater's access to the host.
type hostSystem struct {
	healthURL string
	uid, gid  int
	looked    bool
}

func (h *hostSystem) Systemctl(ctx context.Context, args ...string) error {
	out, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (h *hostSystem) Health(context.Context) error { return checkHealth(h.healthURL) }

func (h *hostSystem) BinaryVersion(ctx context.Context, path string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "version").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func (h *hostSystem) Chown(path string) error {
	if !h.looked {
		u, err := user.Lookup(serviceUser)
		if err != nil {
			return err
		}
		if h.uid, err = strconv.Atoi(u.Uid); err != nil {
			return err
		}
		if h.gid, err = strconv.Atoi(u.Gid); err != nil {
			return err
		}
		h.looked = true
	}
	return os.Chown(path, h.uid, h.gid)
}
