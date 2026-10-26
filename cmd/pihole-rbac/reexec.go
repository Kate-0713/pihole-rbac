// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// noReexecVar, when set, stops a command run as root from re-running itself as the service user. The re-run sets it,
// so it can't loop; an admin can set it to run a command as root on purpose.
const noReexecVar = "PIHOLE_RBAC_NO_REEXEC"

// serviceUserCommands touch the data directory, so on an LXC install they must run as the service user: files they
// create as root would leave the service unable to open them. The value says whether the command takes file paths,
// which must then be resolved from the caller's directory.
var serviceUserCommands = map[string]bool{
	"setup":       false,
	"user":        false,
	"update":      false,
	"rotate-key":  true,
	"import-json": true,
}

// shouldReexec decides whether a command run by root on an LXC install should run itself again as the service user.
func shouldReexec(cmd string, euid int, getenv func(string) string, lxcInstall bool) bool {
	_, ok := serviceUserCommands[cmd]
	return ok && euid == 0 && getenv(noReexecVar) == "" && lxcInstall
}

// serviceRunArgs is the systemd-run command line that runs `exe cmd args...` as the service user with the service's
// environment, as the documented long form does, waiting for it and passing stdin, stdout and stderr through (so a
// password can still be typed at the terminal).
func serviceRunArgs(systemdRun, exe, cmd string, args []string) []string {
	argv := []string{systemdRun, "--quiet", "--pipe", "--wait", "--collect",
		"--uid=" + serviceUser, "--gid=" + serviceUser,
		"--property=EnvironmentFile=" + lxcEnvFile,
		"--setenv=PIHOLE_RBAC_INSTALL=lxc", "--setenv=" + noReexecVar + "=1"}
	if serviceUserCommands[cmd] {
		// Relative paths in the arguments mean the caller's directory, which the service user must be able to enter.
		argv = append(argv, "--same-dir")
	}
	argv = append(argv, exe, cmd)
	return append(argv, args...)
}
