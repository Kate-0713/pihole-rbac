#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Kate O'Grady
# SPDX-License-Identifier: AGPL-3.0-or-later

# Smoke-tests a built image: the frontend is embedded, the container starts read-only as the non-root user with no
# capabilities, reports healthy, serves /healthz, /api/v1/about, the SPA and the third-party notices, logs the setup
# token, and the documented `setup --print-token` works through docker exec. Used by CI; runs anywhere with Docker,
# curl and openssl.
#
#   deploy/docker/smoke-test.sh pihole-rbac:dev

set -euo pipefail

image=${1:?usage: smoke-test.sh <image>}
name="pihole-rbac-smoke-$$"

fail() {
	echo "smoke test failed: $*" >&2
	exit 1
}

cleanup() {
	local status=$?
	if [ "$status" -ne 0 ] && docker inspect "$name" >/dev/null 2>&1; then
		echo "--- container log ---" >&2
		docker logs "$name" >&2 || true
	fi
	docker rm -f "$name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

out="$(docker run --rm "$image" version)"
echo "$out"
grep -qx 'frontend: embedded' <<<"$out" || fail "the frontend is not embedded"

# The key is passed as a plain variable here; compose.example.yaml uses a Docker secret.
docker run -d --name "$name" \
	-e PIHOLE_RBAC_SECRET_KEY="$(openssl rand -base64 32)" \
	-p 127.0.0.1::8080 \
	--read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true \
	"$image" >/dev/null

status=""
for _ in $(seq 1 60); do
	[ "$(docker inspect -f '{{.State.Running}}' "$name")" = true ] || fail "the container exited"
	status="$(docker inspect -f '{{.State.Health.Status}}' "$name")"
	[ "$status" = healthy ] && break
	sleep 1
done
[ "$status" = healthy ] || fail "not healthy after 60 seconds (status: $status)"
echo "health: $status"

port="$(docker port "$name" 8080/tcp | head -n 1 | sed 's/.*://')"
base="http://127.0.0.1:$port"

[ "$(curl -fsS "$base/healthz")" = ok ] || fail "/healthz did not answer ok"
curl -fsS "$base/api/v1/about" | grep -q '"license":"AGPL-3.0-or-later"' || fail "/api/v1/about is wrong"
curl -fsS "$base/" | grep -qi '<!doctype html>' || fail "the SPA is not served"
# Read into a variable first: grep -q stops reading early, which would fail curl on a large file under pipefail.
notices="$(curl -fsS "$base/THIRD_PARTY_NOTICES.txt")" || fail "THIRD_PARTY_NOTICES.txt is not served"
grep -q '^Third-party notices for pihole-rbac' <<<"$notices" || fail "THIRD_PARTY_NOTICES.txt is wrong"

user="$(docker inspect -f '{{.Config.User}}' "$image")"
[ "$user" = "65532:65532" ] || fail "the image runs as '$user', not 65532:65532"
uids="$(docker top "$name" -o uid | tail -n +2 | sort -u)"
[ "$uids" = 65532 ] || fail "processes run as UID(s) $uids"

docker logs "$name" 2>&1 | grep -q 'first-run setup is open' || fail "the setup token was not logged"
docker exec "$name" pihole-rbac setup --print-token >/dev/null || fail "setup --print-token failed"

echo "smoke test passed: $image"
