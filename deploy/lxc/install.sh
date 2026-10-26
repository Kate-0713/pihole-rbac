#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Kate O'Grady
# SPDX-License-Identifier: AGPL-3.0-or-later

# Installs, upgrades or removes pihole-rbac on Debian 12+ or Ubuntu 24.04+ with systemd (an LXC container or a VM).
# Run as root. Safe to run again: it replaces the binary and the unit only when they change, and never touches the
# env file, the secrets or the data once they exist.
#
#   install.sh                       install or upgrade to the latest release (signature and checksum verified)
#   install.sh --version v1.2.3      install or upgrade to that release
#   install.sh --binary <file>       install a binary already on this host, e.g. from `make build` (not verified);
#                                    the unit and env template are taken from beside this script
#   install.sh --uninstall           remove the service and the binary; keep config, data and logs
#   install.sh --uninstall --purge   also remove /etc/pihole-rbac, /var/lib/pihole-rbac, /var/log/pihole-rbac and
#                                    the pihole-rbac user (asks first unless --yes is given)

set -euo pipefail
umask 022

readonly REPO="Kate-0713/pihole-rbac"
# The release signing key (minisign). Written into the script so a download is checked against a key that didn't
# come from the same place as the download. Empty until the first signed release exists; until then only --binary
# installs are possible.
readonly MINISIGN_PUBKEY=""

readonly APP=pihole-rbac
readonly BIN=/usr/local/bin/pihole-rbac
readonly UNIT=/etc/systemd/system/pihole-rbac.service
readonly CONF_DIR=/etc/pihole-rbac
readonly ENV_FILE=/etc/pihole-rbac/env
readonly SECRETS_DIR=/etc/pihole-rbac/secrets
readonly DATA_DIR=/var/lib/pihole-rbac
readonly LOG_DIR=/var/log/pihole-rbac

mode=install
version=""
binary=""
purge=false
yes=false
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp=""

info() { printf '==> %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}

usage() {
	sed -n '5,16p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

cleanup() {
	if [ -n "$tmp" ]; then
		rm -rf "$tmp"
	fi
}
trap cleanup EXIT

parse_args() {
	while [ $# -gt 0 ]; do
		case "$1" in
		--version)
			[ $# -ge 2 ] || die "--version needs a value such as v1.2.3"
			version="$2"
			shift 2
			;;
		--binary)
			[ $# -ge 2 ] || die "--binary needs a file"
			binary="$2"
			shift 2
			;;
		--uninstall) mode=uninstall; shift ;;
		--purge) purge=true; shift ;;
		--yes | -y) yes=true; shift ;;
		-h | --help)
			usage
			exit 0
			;;
		*) die "unknown option $1 (see --help)" ;;
		esac
	done
	if [ -n "$version" ] && ! [[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
		die "--version must look like v1.2.3"
	fi
	if [ -n "$version" ] && [ -n "$binary" ]; then
		die "--version and --binary can't be used together"
	fi
	if $purge && [ "$mode" != uninstall ]; then
		die "--purge only goes with --uninstall"
	fi
	if [ "$mode" = uninstall ] && { [ -n "$version" ] || [ -n "$binary" ]; }; then
		die "--uninstall takes no --version or --binary"
	fi
}

# version_ge A B: is the dotted version A at least B? Compares the first two numbers.
version_ge() {
	local a_major a_minor b_major b_minor
	IFS=. read -r a_major a_minor _ <<<"$1."
	IFS=. read -r b_major b_minor _ <<<"$2."
	a_minor=${a_minor:-0} b_minor=${b_minor:-0}
	[[ "$a_major" =~ ^[0-9]+$ && "$a_minor" =~ ^[0-9]+$ ]] || return 1
	((10#$a_major > 10#$b_major || (10#$a_major == 10#$b_major && 10#$a_minor >= 10#$b_minor)))
}

check_system() {
	[ "$(id -u)" -eq 0 ] || die "run this as root (sudo $0 ...)"
	[ -d /run/systemd/system ] || die "systemd isn't running here; pihole-rbac needs it"
	[ -r /etc/os-release ] || die "can't read /etc/os-release to check the system"
	local id version_id
	# shellcheck disable=SC1091
	id="$(. /etc/os-release && echo "${ID:-}")"
	# shellcheck disable=SC1091
	version_id="$(. /etc/os-release && echo "${VERSION_ID:-}")"
	case "$id" in
	debian) version_ge "$version_id" 12 || die "Debian $version_id is too old: Debian 12 or later is needed" ;;
	ubuntu) version_ge "$version_id" 24.04 || die "Ubuntu $version_id is too old: Ubuntu 24.04 or later is needed" ;;
	*) die "${id:-this system} isn't supported: Debian 12+ or Ubuntu 24.04+ is needed" ;;
	esac
}

detect_arch() {
	case "$(uname -m)" in
	x86_64 | amd64) echo amd64 ;;
	aarch64 | arm64) echo arm64 ;;
	*) die "no release for $(uname -m); releases are built for amd64 and arm64" ;;
	esac
}

# need_packages installs the Debian packages for any missing commands, given as command:package pairs.
need_packages() {
	local pair missing=()
	for pair in "$@"; do
		command -v "${pair%%:*}" >/dev/null 2>&1 || missing+=("${pair#*:}")
	done
	if [ ${#missing[@]} -gt 0 ]; then
		info "Installing ${missing[*]}"
		DEBIAN_FRONTEND=noninteractive apt-get update -qq
		DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "${missing[@]}" >/dev/null
	fi
}

# fetch_release downloads the release into $tmp, verifies it and leaves the binary, unit and env template there.
fetch_release() {
	[ -n "$MINISIGN_PUBKEY" ] ||
		die "this install script has no release signing key yet, so it can't verify a download; use --binary <file>"
	need_packages curl:curl minisign:minisign tar:tar sha256sum:coreutils
	[ -r /etc/ssl/certs/ca-certificates.crt ] || need_packages update-ca-certificates:ca-certificates

	local arch tag url
	arch="$(detect_arch)"
	tag="$version"
	if [ -z "$tag" ]; then
		# The latest release page redirects to .../releases/tag/vX.Y.Z; this avoids the API and its rate limit.
		url="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest")" ||
			die "can't reach GitHub to find the latest release"
		tag="${url##*/}"
		[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "couldn't find the latest release (got '$tag')"
	fi
	local archive="${APP}_${tag#v}_linux_${arch}.tar.gz"
	local base="https://github.com/$REPO/releases/download/$tag"
	info "Downloading pihole-rbac $tag for $arch"
	for f in checksums.txt checksums.txt.minisig "$archive"; do
		curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/$f" "$base/$f" || die "downloading $base/$f failed"
	done

	info "Verifying the signature and checksum"
	minisign -Vqm "$tmp/checksums.txt" -P "$MINISIGN_PUBKEY" >/dev/null ||
		die "the signature of checksums.txt doesn't match the release key: not installing"
	# The archive name carries the version, so a signed checksums file from another release can't vouch for it.
	local line
	line="$(grep -E "^[0-9a-f]{64}  ${archive//./\\.}\$" "$tmp/checksums.txt")" ||
		die "$archive isn't in the signed checksums: not installing"
	(cd "$tmp" && sha256sum --quiet -c - <<<"$line") || die "$archive doesn't match its signed checksum: not installing"

	mkdir "$tmp/release"
	tar -xzf "$tmp/$archive" -C "$tmp/release" --no-same-owner
	for f in pihole-rbac deploy/lxc/pihole-rbac.service deploy/lxc/env.example; do
		[ -f "$tmp/release/$f" ] || die "the release archive has no $f"
	done
	cp "$tmp/release/pihole-rbac" "$tmp/pihole-rbac"
	cp "$tmp/release/deploy/lxc/pihole-rbac.service" "$tmp/pihole-rbac.service"
	cp "$tmp/release/deploy/lxc/env.example" "$tmp/env.example"
}

# use_local_binary copies --binary and the files beside this script into $tmp.
use_local_binary() {
	[ -f "$binary" ] || die "$binary doesn't exist"
	for f in pihole-rbac.service env.example; do
		[ -f "$script_dir/$f" ] || die "$f isn't beside this script; run it from deploy/lxc in a checkout of the repo"
	done
	warn "installing $binary as given: it was not signature-checked"
	cp "$binary" "$tmp/pihole-rbac"
	cp "$script_dir/pihole-rbac.service" "$tmp/pihole-rbac.service"
	cp "$script_dir/env.example" "$tmp/env.example"
}

# check_binary refuses a binary that doesn't run here or was built without the frontend.
check_binary() {
	chmod 0755 "$tmp/pihole-rbac"
	local out
	out="$("$tmp/pihole-rbac" version 2>&1)" || die "the new binary doesn't run on this system: $out"
	grep -qx 'frontend: embedded' <<<"$out" || die "the new binary was built without the frontend"
	info "New binary: $(head -n 1 <<<"$out")"
}

ensure_user() {
	if ! getent group "$APP" >/dev/null; then
		info "Creating the $APP group"
		groupadd --system "$APP"
	fi
	if ! getent passwd "$APP" >/dev/null; then
		info "Creating the $APP user"
		useradd --system --gid "$APP" --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin \
			--comment "pihole-rbac service" "$APP"
	fi
}

ensure_dirs() {
	install -d -o root -g "$APP" -m 0750 "$CONF_DIR" "$SECRETS_DIR"
	install -d -o "$APP" -g "$APP" -m 0750 "$DATA_DIR" "$LOG_DIR"
}

# ensure_env writes the env file with a new master key, only if there is none.
ensure_env() {
	if [ -e "$ENV_FILE" ]; then
		info "Keeping the existing $ENV_FILE"
		return
	fi
	info "Writing $ENV_FILE with a new master key"
	grep -q '@SECRET_KEY@' "$tmp/env.example" || die "the env template has no @SECRET_KEY@ placeholder"
	local key
	key="$(head -c 32 /dev/urandom | base64 -w 0)"
	# Written to a temporary file with the final mode first, so the key is never readable by others.
	local new="$ENV_FILE.new.$$"
	install -o root -g "$APP" -m 0640 /dev/null "$new"
	sed "s|@SECRET_KEY@|$key|" "$tmp/env.example" >"$new"
	mv "$new" "$ENV_FILE"
	echo
	echo "    A new master key is in $ENV_FILE (PIHOLE_RBAC_SECRET_KEY). Keep a copy of it somewhere safe:"
	echo "    the passwords stored in the app can't be read without it, and it isn't in the database backups."
	echo
}

# install_binary puts the new binary in place atomically. Prints "changed" if it replaced a different one.
install_binary() {
	if [ -f "$BIN" ] && cmp -s "$tmp/pihole-rbac" "$BIN"; then
		return
	fi
	install -o root -g root -m 0755 "$tmp/pihole-rbac" "$BIN.new"
	mv -f "$BIN.new" "$BIN"
	echo changed
}

# install_unit puts the unit in place. Prints "changed" if it was new or different.
install_unit() {
	if [ -f "$UNIT" ] && cmp -s "$tmp/pihole-rbac.service" "$UNIT"; then
		return
	fi
	install -o root -g root -m 0644 "$tmp/pihole-rbac.service" "$UNIT"
	echo changed
}

# wait_healthy waits up to 60 seconds for /healthz, reading the listen address from the env file.
wait_healthy() {
	local listen
	listen="$(sed -n 's/^PIHOLE_RBAC_LISTEN=//p' "$ENV_FILE" | tail -n 1)"
	for _ in $(seq 1 60); do
		if PIHOLE_RBAC_LISTEN="${listen:-:8080}" "$BIN" healthcheck >/dev/null 2>&1; then
			return 0
		fi
		systemctl is-active --quiet "$APP" || break
		sleep 1
	done
	return 1
}

# as_service runs the binary as the service user with the service's environment, so files it creates in the data
# directory have the right owner.
as_service() {
	systemd-run --quiet --pipe --wait --collect --uid="$APP" --gid="$APP" \
		--property=EnvironmentFile="$ENV_FILE" "$BIN" "$@"
}

show_setup() {
	local status
	status="$(as_service setup 2>/dev/null)" || {
		warn "couldn't ask the app whether first-run setup is open"
		return
	}
	if grep -q 'First-run setup is open' <<<"$status"; then
		local token
		token="$(as_service setup --print-token 2>/dev/null)" || token="(no token could be made: see journalctl -u $APP)"
		echo
		echo "    First-run setup is open. Open http://<this host>:<port>/setup (or the reverse proxy's address)"
		echo "    and enter the setup token, valid for an hour:"
		echo
		echo "    $token"
		echo
		echo "    For a new token later:"
		echo "    sudo systemd-run --quiet --pipe --wait --collect --uid=$APP --gid=$APP \\"
		echo "      --property=EnvironmentFile=$ENV_FILE $BIN setup --print-token"
		echo
	else
		info "First-run setup is already complete"
	fi
}

do_install() {
	check_system
	tmp="$(mktemp -d)"
	if [ -n "$binary" ]; then
		use_local_binary
	else
		fetch_release
	fi
	check_binary

	ensure_user
	ensure_dirs
	ensure_env

	local bin_changed unit_changed
	bin_changed="$(install_binary)"
	unit_changed="$(install_unit)"
	if [ -n "$bin_changed" ]; then info "Installed $BIN"; else info "$BIN is already this version"; fi
	if [ -n "$unit_changed" ]; then
		info "Installed $UNIT"
		systemctl daemon-reload
	fi
	systemctl enable --quiet "$APP"

	if ! systemctl is-active --quiet "$APP"; then
		info "Starting $APP"
		systemctl start "$APP"
	elif [ -n "$bin_changed" ] || [ -n "$unit_changed" ]; then
		info "Restarting $APP"
		systemctl restart "$APP"
	fi

	if ! wait_healthy; then
		systemctl --no-pager --lines=30 status "$APP" >&2 || true
		die "$APP didn't become healthy; see journalctl -u $APP"
	fi
	info "$APP is running: $("$BIN" version | head -n 1)"
	show_setup
	echo "Logs: journalctl -u $APP, and $LOG_DIR. Settings: $ENV_FILE."
}

do_uninstall() {
	[ "$(id -u)" -eq 0 ] || die "run this as root (sudo $0 ...)"
	if $purge && ! $yes; then
		[ -t 0 ] || die "--purge deletes the database and config; add --yes to confirm when not at a terminal"
		printf 'This deletes %s, %s and %s, including the database and the master key. Type yes to go on: ' \
			"$CONF_DIR" "$DATA_DIR" "$LOG_DIR"
		local answer
		read -r answer
		[ "$answer" = yes ] || die "not purging"
	fi
	if [ -d /run/systemd/system ]; then
		systemctl disable --now --quiet "$APP" 2>/dev/null || true
	fi
	rm -f "$UNIT"
	if $purge; then
		# Local drop-ins (systemctl edit) are config too, so they go only with --purge.
		rm -rf "/etc/systemd/system/$APP.service.d"
	fi
	if [ -d /run/systemd/system ]; then
		systemctl daemon-reload
	fi
	rm -f "$BIN" "$BIN.new" "$BIN.prev"
	info "Removed the service and $BIN"
	if $purge; then
		rm -rf "$CONF_DIR" "$DATA_DIR" "$LOG_DIR"
		if getent passwd "$APP" >/dev/null; then userdel "$APP"; fi
		if getent group "$APP" >/dev/null; then groupdel "$APP"; fi
		info "Removed $CONF_DIR, $DATA_DIR, $LOG_DIR and the $APP user"
	else
		info "Kept $CONF_DIR, $DATA_DIR and $LOG_DIR; --uninstall --purge removes them"
	fi
}

parse_args "$@"
case "$mode" in
install) do_install ;;
uninstall) do_uninstall ;;
esac
