#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Kate O'Grady
# SPDX-License-Identifier: AGPL-3.0-or-later

# Writes web/build/app/THIRD_PARTY_NOTICES.txt: the licences of the Go modules linked into the binary (from
# go-licenses, which also fails on a licence outside the allowed list), the Go standard library's, and those of the
# npm packages bundled into the frontend (web/build/notices-web.txt, written by the frontend build, which checks
# their licences itself). Run after `npm run build` and before `go build`, so the file is embedded and served at
# /THIRD_PARTY_NOTICES.txt. GoReleaser and the Dockerfile run it; ordinary dev builds don't need it.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

readonly allowed="Apache-2.0,BSD-2-Clause,BSD-3-Clause,ISC,MIT,MPL-2.0"
readonly self="github.com/Kate-0713/pihole-rbac"
readonly pkg="./cmd/pihole-rbac"
readonly web="web/build/notices-web.txt"
readonly out="web/build/app/THIRD_PARTY_NOTICES.txt"
readonly rule="--------------------------------------------------------------------------------"

# Modules whose licence go-licenses can't classify, as "module licence sha256-of-its-LICENSE-file". Each was read by
# hand; the checksum makes an update that changes the file fail here, so it's read again. go-licenses skips them and
# their LICENSE comes from the module cache.
#   modernc.org/mathutil: BSD-3-Clause, worded "the names of the authors", which go-licenses v1.6.0 doesn't match.
readonly manual=(
	"modernc.org/mathutil BSD-3-Clause bfa9bf72a72ca009fd62a8f84fca3dca67e51d93af96352723646599898b6cf5"
)

die() {
	echo "notices: $*" >&2
	exit 1
}
[ -f "$web" ] && [ -f web/build/app/index.html ] || die "build the frontend first (npm --prefix web run build)"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Releases are Linux-only; resolve the packages as they are built for it.
export GOOS=linux CGO_ENABLED=0
golicenses() { go tool -modfile=tools/go.mod go-licenses "$@"; }

ignore=(--ignore "$self")
linked="$(go list -deps -f '{{with .Module}}{{.Path}}{{end}}' "$pkg" | sort -u)"
for entry in "${manual[@]}"; do
	read -r mod _ sum <<<"$entry"
	grep -qxF "$mod" <<<"$linked" || die "$mod is no longer linked into the binary: remove it from the manual list"
	dir="$(go list -m -f '{{.Dir}}' "$mod")"
	[ -f "$dir/LICENSE" ] || die "$mod has no LICENSE file any more: read its licence again"
	[ "$(sha256sum "$dir/LICENSE" | cut -d' ' -f1)" = "$sum" ] ||
		die "$mod's LICENSE has changed: read it again and update its entry in the manual list"
	ignore+=(--ignore "$mod")
done

golicenses check "$pkg" "${ignore[@]}" --allowed_licenses="$allowed"
golicenses save "$pkg" "${ignore[@]}" --save_path "$tmp/go"
golicenses report "$pkg" "${ignore[@]}" >"$tmp/report.csv"
[ -s "$tmp/report.csv" ] || die "go-licenses reported no modules"

# notice NAME LICENCE SOURCE FILE...: one entry, its licence files one after another.
notice() {
	local name="$1" licence="$2" source="$3"
	shift 3
	printf '%s\nLicense: %s\n' "$name" "$licence"
	[ -n "$source" ] && printf 'Source: %s\n' "$source"
	local f
	for f in "$@"; do
		printf '\n'
		cat "$f"
	done
	printf '\n%s\n\n' "$rule"
}

{
	cat <<EOF
Third-party notices for pihole-rbac

pihole-rbac is licensed under the GNU Affero General Public License v3.0 or later (see LICENCE.md; source at
https://github.com/Kate-0713/pihole-rbac). It includes the software below, each under its own licence.

$rule

GO MODULES

$rule

EOF
	notice "Go standard library and runtime" "BSD-3-Clause" "https://go.dev" "$(go env GOROOT)/LICENSE"
	sort "$tmp/report.csv" | while IFS=, read -r lib url licence; do
		files=()
		while IFS= read -r f; do files+=("$f"); done < <(
			find "$tmp/go/$lib" -maxdepth 1 -type f \( -iname 'licen[cs]e*' -o -iname 'copying*' -o -iname 'notice*' \) | sort
		)
		[ ${#files[@]} -gt 0 ] || die "no licence file saved for $lib"
		notice "$lib" "$licence" "$url" "${files[@]}"
	done
	for entry in "${manual[@]}"; do
		read -r mod licence _ <<<"$entry"
		notice "$mod $(go list -m -f '{{.Version}}' "$mod")" "$licence" "https://pkg.go.dev/$mod" \
			"$(go list -m -f '{{.Dir}}' "$mod")/LICENSE"
	done
	cat <<EOF
FRONTEND PACKAGES (bundled into the web interface)

$rule

EOF
	cat "$web"
	printf '\n'
} >"$tmp/notices.txt"

mv "$tmp/notices.txt" "$out"
echo "notices: wrote $out ($(grep -c '^License: ' "$out") entries)"
