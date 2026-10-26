// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/buildinfo"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// updateCLI is a CLI on an LXC install running release v2.0.0, with the request file in a temporary directory.
func updateCLI(t *testing.T) *cli {
	t.Helper()
	c := newCLI(t)
	c.store() // create the database
	t.Setenv("PIHOLE_RBAC_INSTALL", "lxc")
	oldVersion, oldFile, oldPoll := buildinfo.Version, updateRequestFile, updatePoll
	t.Cleanup(func() { buildinfo.Version, updateRequestFile, updatePoll = oldVersion, oldFile, oldPoll })
	buildinfo.Version = "2.0.0"
	updateRequestFile = filepath.Join(t.TempDir(), "update.request")
	updatePoll = 5 * time.Millisecond
	return c
}

// finishLater plays the updater: once a request is pending it takes it, logs a line and finishes it with status.
func (c *cli) finishLater(status string) {
	go func() {
		ctx := context.Background()
		for range 2000 {
			time.Sleep(2 * time.Millisecond)
			d, err := store.OpenUnmigrated(ctx, c.dataDir)
			if err != nil {
				continue
			}
			q := db.New(d)
			r, err := q.ClaimUpdateRequest(ctx)
			if errors.Is(err, sql.ErrNoRows) {
				d.Close()
				continue
			}
			_ = q.AppendUpdateLog(ctx, db.AppendUpdateLogParams{Line: "12:00:00 the updater was here\n", ID: r.ID})
			_, _ = q.FinishUpdateRequest(ctx, db.FinishUpdateRequestParams{
				Status: status, FinishedAt: sql.NullInt64{Int64: 1, Valid: true}, ID: r.ID,
			})
			d.Close()
			return
		}
	}()
}

func TestUpdateCommandNoWait(t *testing.T) {
	c := updateCLI(t)
	if err := c.run("", "update", "--no-wait", "v2.1.0"); err != nil {
		t.Fatalf("update: %v\n%s", err, c.errOut)
	}
	if !strings.Contains(c.out.String(), "Update request 1 recorded: updating to v2.1.0.") ||
		!strings.Contains(c.out.String(), "journalctl -fu pihole-rbac-update") {
		t.Errorf("output:\n%s", c.out)
	}
	if b, err := os.ReadFile(updateRequestFile); err != nil || string(b) != "1\n" {
		t.Errorf("request file = %q, %v", b, err)
	}
	row, err := c.store().Read().GetAudit(context.Background(), 1)
	if err != nil || row.Action != audit.ActionUpdateRequest || row.Username != cliUser {
		t.Errorf("audit = %+v, %v", row, err)
	}

	// One at a time.
	err = c.run("", "update", "--no-wait")
	if err == nil || !strings.Contains(err.Error(), "already pending or running") {
		t.Errorf("second request: %v", err)
	}
}

func TestUpdateCommandFollows(t *testing.T) {
	tests := []struct {
		status  string
		wantErr string
	}{
		{"done", ""},
		{"failed", "the update failed"},
		{"rolled_back", "rolled back"},
	}
	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			c := updateCLI(t)
			c.finishLater(tt.status)
			err := c.run("", "update")
			if tt.wantErr == "" && err != nil || tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
			if !strings.Contains(c.out.String(), "updating to the latest release") ||
				!strings.Contains(c.out.String(), "the updater was here") {
				t.Errorf("output:\n%s", c.out)
			}
			if (tt.wantErr == "") != strings.Contains(c.out.String(), "Update finished.") {
				t.Errorf("output:\n%s", c.out)
			}
		})
	}
}

func TestUpdateCommandRefusals(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		setup   func()
		wantErr string
	}{
		{"docker", []string{"update"}, func() { os.Setenv("PIHOLE_RBAC_INSTALL", "docker") }, "docker compose pull"},
		{"not an install kind we update", []string{"update"}, func() { os.Unsetenv("PIHOLE_RBAC_INSTALL") }, "LXC install"},
		{"development build", []string{"update"}, func() { buildinfo.Version = "dev" }, "development build"},
		{"older", []string{"update", "v1.0.0"}, nil, "isn't newer"},
		{"not a version", []string{"update", "latest"}, nil, "isn't a version"},
		{"two versions", []string{"update", "v2.1.0", "v2.2.0"}, nil, "at most one version"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := updateCLI(t)
			if tt.setup != nil {
				tt.setup()
			}
			err := c.run("", tt.args...)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
			if _, err := os.Stat(updateRequestFile); !errors.Is(err, os.ErrNotExist) {
				t.Error("a refused request touched the request file")
			}
		})
	}
}

func TestUpdaterNeedsRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: the updater would really run")
	}
	newCLI(t)
	err := run([]string{"updater"})
	if err == nil || !strings.Contains(err.Error(), "run as root") {
		t.Fatalf("err = %v", err)
	}
}

func TestShouldReexec(t *testing.T) {
	none := func(string) string { return "" }
	set := func(k string) string {
		if k == noReexecVar {
			return "1"
		}
		return ""
	}
	tests := []struct {
		name   string
		cmd    string
		euid   int
		getenv func(string) string
		lxc    bool
		want   bool
	}{
		{"root on LXC: setup", "setup", 0, none, true, true},
		{"root on LXC: update", "update", 0, none, true, true},
		{"root on LXC: import-json", "import-json", 0, none, true, true},
		{"root on LXC: serve", "serve", 0, none, true, false},
		{"root on LXC: the updater itself", "updater", 0, none, true, false},
		{"root on LXC: version", "version", 0, none, true, false},
		{"already the service user", "setup", 999, none, true, false},
		{"not an LXC install", "setup", 0, none, false, false},
		{"asked not to", "setup", 0, set, true, false},
	}
	for _, tt := range tests {
		if got := shouldReexec(tt.cmd, tt.euid, tt.getenv, tt.lxc); got != tt.want {
			t.Errorf("%s: %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestServiceRunArgs(t *testing.T) {
	got := serviceRunArgs("/usr/bin/systemd-run", "/usr/local/bin/pihole-rbac", "setup", []string{"--print-token"})
	want := []string{"/usr/bin/systemd-run", "--quiet", "--pipe", "--wait", "--collect",
		"--uid=pihole-rbac", "--gid=pihole-rbac", "--property=EnvironmentFile=/etc/pihole-rbac/env",
		"--setenv=PIHOLE_RBAC_INSTALL=lxc", "--setenv=PIHOLE_RBAC_NO_REEXEC=1",
		"/usr/local/bin/pihole-rbac", "setup", "--print-token"}
	if !slices.Equal(got, want) {
		t.Errorf("setup:\n got %q\nwant %q", got, want)
	}
	got = serviceRunArgs("/usr/bin/systemd-run", "/usr/local/bin/pihole-rbac", "import-json", []string{"--config", "config.json"})
	if !slices.Contains(got, "--same-dir") || !slices.Equal(got[len(got)-3:], []string{"import-json", "--config", "config.json"}) {
		t.Errorf("import-json: %q", got)
	}
}
