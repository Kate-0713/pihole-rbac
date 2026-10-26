#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Kate O'Grady
# SPDX-License-Identifier: AGPL-3.0-or-later

# Exercises the LXC updater end to end with real systemd: installs a base version with install.sh --binary, then
# updates it through `sudo pihole-rbac update` (the root re-exec, the request file, the path unit, the root updater,
# signature and checksum checks, the database backup, the swap, the restart and the health wait), refuses a
# downgrade, and updates to a version that never starts, which must be rolled back. Releases come from a local server
# signed with a throwaway minisign key, so both binaries must be built with -tags updatertest (which reads
# PIHOLE_RBAC_TEST_RELEASES_URL and PIHOLE_RBAC_TEST_RELEASE_KEY) and the versions 2.0.0 and 2.0.1. CI runs it on the
# Ubuntu runner after test-install.sh.
#
# Only for a throwaway host with systemd, run as root: it installs and then purges pihole-rbac.
#
#   sudo bash deploy/lxc/test-update.sh bin/test-2.0.0 bin/test-2.0.1

set -euo pipefail

base=${1:?usage: test-update.sh <binary 2.0.0> <binary 2.0.1>}
next=${2:?usage: test-update.sh <binary 2.0.0> <binary 2.0.1>}
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
install_sh="$here/install.sh"
work="$(mktemp -d)"
port=8099
server_pid=""
repo=Kate-0713/pihole-rbac

cleanup() {
	if [ -n "$server_pid" ]; then kill "$server_pid" 2>/dev/null || true; fi
	rm -rf "$work"
}
trap cleanup EXIT

step() { printf '\n### %s\n' "$*"; }
fail() {
	echo "test failed: $*" >&2
	journalctl -u pihole-rbac -u pihole-rbac-update --no-pager -n 80 >&2 || true
	exit 1
}
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
installed_version() { /usr/local/bin/pihole-rbac version | head -n 1 | cut -d' ' -f2; }
# wait_log PATTERN waits up to 90 seconds for an AUDIT line in today's log file (the app announces finished updates
# within a minute).
wait_log() {
	for _ in $(seq 1 90); do
		grep -q "$1" /var/log/pihole-rbac/pihole-rbac-*.log 2>/dev/null && return 0
		sleep 1
	done
	return 1
}

[ "$(id -u)" -eq 0 ] || fail "run as root"
command -v minisign >/dev/null || fail "minisign is needed to sign the test releases"
# Output is read into a variable before grep -q looks at it, never piped: under pipefail, grep -q stopping at the
# first match can fail the check with SIGPIPE although the text was there.
for b in "$base" "$next"; do
	out="$("$b" version)"
	grep -q '^TEST BUILD' <<<"$out" || fail "$b wasn't built with -tags updatertest"
done
out="$("$base" version)"
grep -q '^pihole-rbac 2\.0\.0 ' <<<"$out" || fail "$base isn't version 2.0.0"
out="$("$next" version)"
grep -q '^pihole-rbac 2\.0\.1 ' <<<"$out" || fail "$next isn't version 2.0.1"

case "$(uname -m)" in
x86_64) arch=amd64 ;;
aarch64) arch=arm64 ;;
*) fail "no release architecture for $(uname -m)" ;;
esac

step "test releases, signed with a throwaway key"
minisign -G -W -p "$work/key.pub" -s "$work/key.sec" >/dev/null
key="$(tail -n 1 "$work/key.pub")"
root="$work/www"
mkdir -p "$root/api/repos/$repo/releases"
# release TAG BINARY: an archive holding the binary, its checksum, and the signature with the trusted comment the
# release workflow uses.
release() {
	local tag=$1 bin=$2 dir="$root/$repo/releases/download/$1"
	local archive="pihole-rbac_${tag#v}_linux_${arch}.tar.gz"
	mkdir -p "$dir" "$work/pkg-$tag"
	cp "$bin" "$work/pkg-$tag/pihole-rbac"
	chmod 0755 "$work/pkg-$tag/pihole-rbac"
	tar -czf "$dir/$archive" -C "$work/pkg-$tag" pihole-rbac
	(cd "$dir" && sha256sum "$archive" >checksums.txt)
	minisign -S -s "$work/key.sec" -m "$dir/checksums.txt" -x "$dir/checksums.txt.minisig" -t "pihole-rbac $tag" >/dev/null
}
release v2.0.1 "$next"
# v2.0.2 passes every check before the swap but never starts, so the update must be rolled back.
cat >"$work/broken" <<'EOF'
#!/bin/sh
if [ "$1" = version ]; then
	printf 'pihole-rbac 2.0.2 (commit test, built test)\nfrontend: embedded\n'
	exit 0
fi
echo "this version never starts" >&2
exit 1
EOF
release v2.0.2 "$work/broken"
printf '{"tag_name":"v2.0.1","draft":false,"prerelease":false,"published_at":"2026-10-26T00:00:00Z"}\n' \
	>"$root/api/repos/$repo/releases/latest"
python3 -m http.server --bind 127.0.0.1 --directory "$root" "$port" >"$work/server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 20); do
	curl -fsS "http://127.0.0.1:$port/api/repos/$repo/releases/latest" >/dev/null 2>&1 && break
	sleep 0.5
done

step "install 2.0.0"
bash "$install_sh" --binary "$base" >/dev/null
# Both the app's check and the updater read the env file.
printf 'PIHOLE_RBAC_TEST_RELEASES_URL=http://127.0.0.1:%s\nPIHOLE_RBAC_TEST_RELEASE_KEY=%s\n' "$port" "$key" >>/etc/pihole-rbac/env
systemctl restart pihole-rbac
healthy || fail "2.0.0 isn't healthy"
systemctl is-enabled --quiet pihole-rbac-update.path || fail "pihole-rbac-update.path isn't enabled"
systemctl is-active --quiet pihole-rbac-update.path || fail "pihole-rbac-update.path isn't active"
expect_stat /etc/systemd/system/pihole-rbac-update.path root:root 644
expect_stat /etc/systemd/system/pihole-rbac-update.service root:root 644
systemd-analyze verify /etc/systemd/system/pihole-rbac-update.path /etc/systemd/system/pihole-rbac-update.service ||
	fail "systemd-analyze verify found problems in the update units"
systemd-analyze security --no-pager pihole-rbac-update.service | tail -n 1

step "root's commands run as the service user"
out="$(/usr/local/bin/pihole-rbac setup)"
grep -q 'First-run setup is open' <<<"$out" || fail "sudo pihole-rbac setup didn't report setup open"
[ -z "$(find /var/lib/pihole-rbac -user root)" ] || fail "root-owned files in the data directory: $(find /var/lib/pihole-rbac -user root)"

step "a downgrade is refused before anything happens"
if out="$(/usr/local/bin/pihole-rbac update --no-wait v1.9.0 2>&1)"; then fail "a downgrade was accepted: $out"; fi
grep -q "isn't newer" <<<"$out" || fail "unexpected refusal: $out"

step "update to the latest release (2.0.1)"
/usr/local/bin/pihole-rbac update | tee "$work/update.out" || fail "the update failed"
grep -q 'Update finished.' "$work/update.out" || fail "the update didn't report finishing"
grep -q 'signed with the release key' "$work/update.out" || fail "no signature check in the log"
[ "$(installed_version)" = 2.0.1 ] || fail "installed version is $(installed_version)"
healthy || fail "2.0.1 isn't healthy"
cmp -s /usr/local/bin/pihole-rbac.prev "$base" || fail "pihole-rbac.prev isn't the previous binary"
expect_stat /usr/local/bin/pihole-rbac root:root 755
backup="$(find /var/lib/pihole-rbac/backups -name 'v2.0.0-*.db' | head -n 1)"
[ -n "$backup" ] || fail "no update backup in /var/lib/pihole-rbac/backups"
expect_stat "$backup" pihole-rbac:pihole-rbac 600
expect_stat /var/lib/pihole-rbac/backups pihole-rbac:pihole-rbac 750
for f in /var/lib/pihole-rbac/pihole-rbac.db /var/lib/pihole-rbac/pihole-rbac.db-wal /var/lib/pihole-rbac/pihole-rbac.db-shm; do
	[ ! -e "$f" ] || [ "$(stat -c %U "$f")" = pihole-rbac ] || fail "$f is owned by $(stat -c %U "$f")"
done
[ ! -e /run/pihole-rbac/update.request ] || fail "the request file is still there"
wait_log 'action=update_done' || fail "the app didn't announce update_done"

step "update to a version that never starts (2.0.2): rolled back"
if /usr/local/bin/pihole-rbac update v2.0.2 | tee "$work/rollback.out"; then fail "a broken update reported success"; fi
grep -q 'Rolled back: v2.0.1 is running and healthy again' "$work/rollback.out" || fail "no successful rollback in the log"
[ "$(installed_version)" = 2.0.1 ] || fail "installed version is $(installed_version) after the rollback"
healthy || fail "2.0.1 isn't healthy after the rollback"
[ -z "$(find /var/lib/pihole-rbac -user root)" ] || fail "root-owned files in the data directory: $(find /var/lib/pihole-rbac -user root)"
expect_stat /var/lib/pihole-rbac/pihole-rbac.db pihole-rbac:pihole-rbac 600
wait_log 'action=update_rolled_back' || fail "the app didn't announce update_rolled_back"

step "already up to date"
/usr/local/bin/pihole-rbac update | tee "$work/noop.out" || fail "updating to the version already running failed"
grep -q 'nothing to do' "$work/noop.out" || fail "expected nothing to do"

step "uninstall removes the update units"
bash "$install_sh" --uninstall --purge --yes >/dev/null
for p in /etc/systemd/system/pihole-rbac-update.path /etc/systemd/system/pihole-rbac-update.service \
	/usr/local/bin/pihole-rbac.prev; do
	[ ! -e "$p" ] || fail "$p is still there"
done

echo
echo "update test passed"
