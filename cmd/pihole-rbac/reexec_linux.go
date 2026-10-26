// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"syscall"
)

// reexecAsService replaces the process with `systemd-run ... pihole-rbac <cmd> <args>` running as the service user,
// when root runs a command that touches the data directory on an LXC install (the service user and its env file
// exist). Otherwise it returns nil and the command runs as it is. It only returns if it can't re-run.
func reexecAsService(cmd string, args []string) error {
	lxc := func() bool {
		if _, err := os.Stat(lxcEnvFile); err != nil {
			return false
		}
		_, err := user.Lookup(serviceUser)
		return err == nil
	}
	if !shouldReexec(cmd, os.Geteuid(), os.Getenv, lxc()) {
		return nil
	}
	run, err := exec.LookPath("systemd-run")
	if err != nil {
		return errors.New("systemd-run isn't available to run this as the pihole-rbac user; set " + noReexecVar +
			"=1 to run it as root anyway (files it creates in the data directory then need chown pihole-rbac:pihole-rbac)")
	}
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("finding this binary to run it as the pihole-rbac user: %w", err)
	}
	argv := serviceRunArgs(run, exe, cmd, args)
	return fmt.Errorf("running as the pihole-rbac user: %w", syscall.Exec(run, argv, os.Environ()))
}
