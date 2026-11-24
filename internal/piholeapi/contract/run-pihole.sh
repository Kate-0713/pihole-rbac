#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Kate O'Grady
# SPDX-License-Identifier: AGPL-3.0-or-later

# Runs the Pi-hole contract tests against a real Pi-hole: starts a throwaway container from the image given, waits
# for its API, runs the tests in this directory against it, and removes the container. Used by CI (pihole.yml); runs
# on any Linux machine with bash, curl, Docker and Go, from the repository root:
#
#   bash internal/piholeapi/contract/run-pihole.sh pihole/pihole:2026.11.0
#
# The container uses the host's network, so the Pi-hole can download the small list the gravity test serves on
# 127.0.0.1. Its web server and DNS server listen on ports that are rarely taken (PIHOLE_WEB_PORT, PIHOLE_DNS_PORT).
# Only the web interface password, the two ports and dhcp.leaseTime are set through FTLCONF_ variables: an item set
# that way can't be changed through the API, and dhcp.leaseTime is the one the tests expect to find locked. The app
# password and app_sudo are set by the tests themselves, through the API.

set -euo pipefail

image=${1:?usage: run-pihole.sh <pihole image>}
web_port=${PIHOLE_WEB_PORT:-18080}
dns_port=${PIHOLE_DNS_PORT:-15353}
name="pihole-rbac-contract-$$"
password="$(head -c 24 /dev/urandom | base64 | tr -d '/+=')"

cleanup() {
	local status=$?
	if [ "$status" -ne 0 ]; then
		echo "--- the Pi-hole container's output:" >&2
		docker logs --tail 200 "$name" >&2 2>&1 || true
	fi
	docker rm -f "$name" >/dev/null 2>&1 || true
	exit "$status"
}
trap cleanup EXIT

docker run --detach --name "$name" --network host \
	-e FTLCONF_webserver_api_password="$password" \
	-e FTLCONF_webserver_port="$web_port" \
	-e FTLCONF_dns_port="$dns_port" \
	-e FTLCONF_dhcp_leaseTime=24h \
	"$image" >/dev/null
docker image inspect --format 'Pi-hole image: {{index .RepoDigests 0}}' "$image" || true

# The image runs gravity before it starts FTL, so once the API answers the gravity database is there.
url="http://127.0.0.1:$web_port"
for _ in $(seq 1 180); do
	if curl -fsS -o /dev/null "$url/api/info/login" 2>/dev/null; then
		break
	fi
	if [ "$(docker inspect --format '{{.State.Running}}' "$name")" != true ]; then
		echo "the Pi-hole container stopped" >&2
		exit 1
	fi
	sleep 1
done
curl -fsS -o /dev/null "$url/api/info/login" || { echo "Pi-hole's API didn't answer within 3 minutes" >&2; exit 1; }
docker exec "$name" pihole-FTL --version

PIHOLE_RBAC_TEST_PIHOLE="$url" \
	PIHOLE_RBAC_TEST_PIHOLE_PASSWORD="$password" \
	PIHOLE_RBAC_TEST_PIHOLE_DNS="127.0.0.1:$dns_port" \
	go test -count=1 -v ./internal/piholeapi/contract/
