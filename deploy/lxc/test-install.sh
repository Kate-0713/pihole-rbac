#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Kate O'Grady
# SPDX-License-Identifier: AGPL-3.0-or-later

# Exercises install.sh end to end with a locally built binary: install, the files and modes it leaves, the running
# service, a second run that changes nothing, a crash and restart, --uninstall keeping the data, a reinstall keeping
# the master key, and --uninstall --purge. CI runs it on the Ubuntu runner.
#
# Only for a throwaway host with systemd, run as root: it installs and then purges pihole-rbac, deleting any data in
# /var/lib/pihole-rbac and the config in /etc/pihole-rbac.
#
#   sudo bash deploy/lxc/test-install.sh bin/pihole-rbac

set -euo pipefail

bin=${1:?usage: test-install.sh <binary>}
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
install_sh="$here/install.sh"
out="$(mktemp)"
trap 'rm -f "$out"' EXIT

step() { printf '\n### %s\n' "$*"; }
fail() {
	echo "test failed: $*" >&2
	journalctl -u pihole-rbac --no-pager -n 50 >&2 || true
	exit 1
}
# expect_stat PATH OWNER:GROUP MODE
expect_stat() {
	local got
	got="$(stat -c '%U:%G %a' "$1")" || fail "$1 is missing"
	[ "$got" = "$2 $3" ] || fail "$1 is $got, want $2 $3"
}
healthy() {
	for _ in $(seq 1 30); do
		[ "$(curl -fsS http://127.0.0.1:8080/healthz 2>/dev/null)" = ok ] && return 0
		sleep 1
	done
	return 1
}

[ "$(id -u)" -eq 0 ] || fail "run as root"

step "first install"
bash "$install_sh" --binary "$bin" | tee "$out"
systemctl is-active --quiet pihole-rbac || fail "the service isn't running"
systemctl is-enabled --quiet pihole-rbac || fail "the service isn't enabled"
healthy || fail "/healthz isn't answering"
grep -q 'Setup token (valid until' "$out" || fail "no setup token was shown"
grep -q 'A new master key is in' "$out" || fail "the master key wasn't announced"

step "files, owners and modes"
id pihole-rbac >/dev/null || fail "no pihole-rbac user"
[ "$(getent passwd pihole-rbac | cut -d: -f7)" = /usr/sbin/nologin ] || fail "the pihole-rbac user has a shell"
expect_stat /usr/local/bin/pihole-rbac root:root 755
expect_stat /etc/systemd/system/pihole-rbac.service root:root 644
expect_stat /etc/pihole-rbac root:pihole-rbac 750
expect_stat /etc/pihole-rbac/secrets root:pihole-rbac 750
expect_stat /etc/pihole-rbac/env root:pihole-rbac 640
expect_stat /var/lib/pihole-rbac pihole-rbac:pihole-rbac 750
expect_stat /var/log/pihole-rbac pihole-rbac:pihole-rbac 750
expect_stat /var/lib/pihole-rbac/pihole-rbac.db pihole-rbac:pihole-rbac 640
log_file="/var/log/pihole-rbac/pihole-rbac-$(date +%F).log"
expect_stat "$log_file" pihole-rbac:pihole-rbac 640
grep -q 'msg=listening' "$log_file" || fail "the log file has no listening line"
key="$(sed -n 's/^PIHOLE_RBAC_SECRET_KEY=//p' /etc/pihole-rbac/env)"
[ "$(printf '%s' "$key" | base64 -d | wc -c)" -eq 32 ] || fail "the master key isn't 32 bytes of base64"
user="$(ps -o user= -p "$(systemctl show -p MainPID --value pihole-rbac)")"
[ "$user" = pihole-rbac ] || fail "the service runs as $user"
systemd-analyze verify /etc/systemd/system/pihole-rbac.service || fail "systemd-analyze verify found problems"
systemd-analyze security --no-pager pihole-rbac | tail -n 1

step "second run changes nothing"
env_sum="$(sha256sum /etc/pihole-rbac/env)"
pid="$(systemctl show -p MainPID --value pihole-rbac)"
bash "$install_sh" --binary "$bin" | tee "$out"
grep -q 'already this version' "$out" || fail "the binary was reinstalled"
grep -q 'Keeping the existing /etc/pihole-rbac/env' "$out" || fail "the env file wasn't kept"
[ "$(sha256sum /etc/pihole-rbac/env)" = "$env_sum" ] || fail "the env file changed"
[ "$(systemctl show -p MainPID --value pihole-rbac)" = "$pid" ] || fail "the service was restarted"

step "a crash is restarted"
kill -9 "$pid"
sleep 7 # RestartSec=5
healthy || fail "the service didn't come back after a crash"
[ "$(systemctl show -p MainPID --value pihole-rbac)" != "$pid" ] || fail "the same process is still there?"

step "uninstall keeps config and data"
bash "$install_sh" --uninstall
! systemctl is-active --quiet pihole-rbac || fail "the service is still running"
[ ! -e /etc/systemd/system/pihole-rbac.service ] || fail "the unit is still there"
[ ! -e /usr/local/bin/pihole-rbac ] || fail "the binary is still there"
[ "$(sha256sum /etc/pihole-rbac/env)" = "$env_sum" ] || fail "the env file changed"
[ -f /var/lib/pihole-rbac/pihole-rbac.db ] || fail "the database was removed"

step "reinstall keeps the master key and the database"
bash "$install_sh" --binary "$bin" | tee "$out"
[ "$(sha256sum /etc/pihole-rbac/env)" = "$env_sum" ] || fail "the env file changed"
healthy || fail "/healthz isn't answering after the reinstall"

step "purge"
bash "$install_sh" --uninstall --purge </dev/null && fail "--purge without --yes went ahead without a terminal"
bash "$install_sh" --uninstall --purge --yes
for p in /etc/pihole-rbac /var/lib/pihole-rbac /var/log/pihole-rbac /usr/local/bin/pihole-rbac \
	/etc/systemd/system/pihole-rbac.service; do
	[ ! -e "$p" ] || fail "$p is still there"
done
! getent passwd pihole-rbac >/dev/null || fail "the pihole-rbac user is still there"
! getent group pihole-rbac >/dev/null || fail "the pihole-rbac group is still there"

echo
echo "install test passed"
