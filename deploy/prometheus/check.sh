#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Kate O'Grady
# SPDX-License-Identifier: AGPL-3.0-or-later

# Checks the Prometheus side of the app against the real tools: the example configuration and rules are valid and the
# rules pass their tests, and a running binary's /metrics output passes `promtool check metrics`. With PROMETHEUS set
# too, a real Prometheus scrapes the binary with the example's bearer-token authorization and the app's own series
# are queried back. Used by CI; runs anywhere with bash, curl, openssl and the Prometheus release (promtool, and
# prometheus for the last step).
#
#   deploy/prometheus/check.sh bin/pihole-rbac /path/to/prometheus-release-dir

set -euo pipefail

bin=${1:?usage: check.sh <pihole-rbac binary> <dir holding promtool and prometheus>}
tools=${2:?usage: check.sh <pihole-rbac binary> <dir holding promtool and prometheus>}
here="$(cd "$(dirname "$0")" && pwd)"
promtool="$tools/promtool"
prometheus="$tools/prometheus"
work="$(mktemp -d)"
pids=()

fail() {
	echo "prometheus check failed: $*" >&2
	exit 1
}

cleanup() {
	local status=$?
	for pid in "${pids[@]:-}"; do kill "$pid" 2>/dev/null || true; done
	if [ "$status" -ne 0 ] && [ -f "$work/app.log" ]; then
		echo "--- app log ---" >&2
		tail -n 40 "$work/app.log" >&2 || true
	fi
	rm -rf "$work"
}
trap cleanup EXIT

[ -x "$promtool" ] || fail "no promtool in $tools"

# The files, as they are checked in.
"$promtool" check rules "$here/alerts.example.yml"
"$promtool" test rules "$here/alerts.test.yml"

# The example configuration with its absolute paths pointed at a scratch directory; nothing else is changed.
mkdir -p "$work/etc/secrets" "$work/data"
token="$(openssl rand -base64 32)"
printf '%s' "$token" >"$work/etc/secrets/pihole_rbac_metrics_token"
cp "$here/alerts.example.yml" "$work/etc/pihole-rbac-alerts.yml"
sed "s#/etc/prometheus#$work/etc#g" "$here/prometheus.example.yml" >"$work/etc/prometheus.yml"
"$promtool" check config "$work/etc/prometheus.yml"

# A running binary. /metrics answers before setup, so no instance is needed.
port=$((20000 + RANDOM % 20000))
PIHOLE_RBAC_LISTEN="127.0.0.1:$port" \
	PIHOLE_RBAC_DATA_DIR="$work/data" \
	PIHOLE_RBAC_LOG_LEVEL=info \
	PIHOLE_RBAC_SECRET_KEY="$(openssl rand -base64 32)" \
	PIHOLE_RBAC_METRICS_TOKEN="$token" \
	"$bin" serve >"$work/app.log" 2>&1 &
pids+=($!)
for _ in $(seq 1 60); do
	[ "$(curl -fsS "http://127.0.0.1:$port/healthz" 2>/dev/null || true)" = ok ] && break
	kill -0 "${pids[0]}" 2>/dev/null || fail "the app exited"
	sleep 0.5
done
base="http://127.0.0.1:$port"
[ "$(curl -fsS "$base/healthz")" = ok ] || fail "the app did not become healthy"

code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
[ "$(code "$base/metrics")" = 401 ] || fail "/metrics without a token was not 401"
[ "$(code -H 'Authorization: Bearer wrong' "$base/metrics")" = 401 ] || fail "/metrics with a wrong token was not 401"
[ "$(code -H "Authorization: Bearer $token" "$base/metrics")" = 200 ] || fail "/metrics with the token was not 200"

curl -fsS -H "Authorization: Bearer $token" "$base/metrics" >"$work/metrics.txt"
grep -q '^pihole_rbac_build_info{' "$work/metrics.txt" || fail "no build_info in the output"
"$promtool" check metrics <"$work/metrics.txt" || fail "promtool check metrics rejected the output"
echo "promtool check metrics: ok ($(grep -vc '^#' "$work/metrics.txt") series)"

# The families a bare install doesn't write (instances, drift, forwarding, tokens and the rest) come from the tests that
# fill a registry with them, which write their output when PIHOLE_RBAC_METRICS_DUMP_DIR is set. Needs the Go toolchain.
if command -v go >/dev/null 2>&1; then
	(cd "$here/../.." && PIHOLE_RBAC_METRICS_DUMP_DIR="$work/dump" go test -count=1 \
		-run 'TestHTTPMetrics|TestWriteMetrics|TestTokenMetrics|TestLoginMetrics|TestInstanceSeries|TestDriftSeries|TestSessionsAndClientResetFromTheDatabase|TestPoolMetrics|TestNotifierMetrics|TestForwardMetrics|TestLoggerMetrics' \
		./internal/api ./internal/appmetrics ./internal/instances ./internal/notify ./internal/logdestinations ./internal/audit >/dev/null) \
		|| fail "the tests that write metrics for the lint failed"
	n=0
	for f in "$work"/dump/*.txt; do
		[ -s "$f" ] || continue
		"$promtool" check metrics <"$f" || fail "promtool check metrics rejected $(basename "$f")"
		n=$((n + 1))
	done
	[ "$n" -ge 8 ] || fail "only $n test outputs were written for the lint"
	echo "promtool check metrics: ok for $n test outputs"
else
	echo "no go toolchain: skipping the lint of the families a bare install doesn't write"
fi

[ -x "$prometheus" ] || { echo "no prometheus in $tools: skipping the real scrape"; exit 0; }

# A real Prometheus, scraping with the example's authorization block over plain HTTP (a local run has no proxy).
sed -e "s#scheme: https#scheme: http#" -e "s#pihole-rbac.example.lan#127.0.0.1:$port#" \
	-e 's#scrape_interval: 30s#scrape_interval: 2s#' -e 's#evaluation_interval: 30s#evaluation_interval: 2s#' \
	"$work/etc/prometheus.yml" >"$work/etc/prometheus-local.yml"
pport=$((40000 + RANDOM % 20000))
"$prometheus" --config.file="$work/etc/prometheus-local.yml" --storage.tsdb.path="$work/tsdb" \
	--web.listen-address="127.0.0.1:$pport" >"$work/prometheus.log" 2>&1 &
pids+=($!)

query() { curl -fsS --get "http://127.0.0.1:$pport/api/v1/query" --data-urlencode "query=$1" 2>/dev/null; }
ok=""
for _ in $(seq 1 40); do
	if query 'up{job="pihole-rbac"}' | grep -q '"value":\[[0-9.]*,"1"\]'; then ok=1; break; fi
	kill -0 "${pids[1]}" 2>/dev/null || { tail -n 20 "$work/prometheus.log" >&2; fail "prometheus exited"; }
	sleep 1
done
[ -n "$ok" ] || { tail -n 20 "$work/prometheus.log" >&2; fail "prometheus never scraped the app successfully"; }
for q in pihole_rbac_build_info pihole_rbac_http_requests_total pihole_rbac_notification_queue_length go_goroutines; do
	query "$q" | grep -q '"result":\[{' || fail "prometheus has no series for $q"
done
curl -fsS "http://127.0.0.1:$pport/api/v1/rules" | grep -q PiholeRbacInstanceDown || fail "prometheus did not load the alert rules"
echo "prometheus: scraped the app and loaded the rules"
