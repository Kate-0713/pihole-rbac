<!--
SPDX-FileCopyrightText: 2026 Kate O'Grady
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Monitoring with Prometheus

pihole-rbac can expose its health and the state of the Pi-holes it manages at `GET /metrics`, in the Prometheus text
format. It is off until you set a token.

| File | What it is |
| --- | --- |
| `prometheus.example.yml` | A scrape job with the token read from a file |
| `alerts.example.yml` | Alert rules (the instance, the app, drift, forwarding, notifications, updates) |
| `alerts.test.yml` | Unit tests for the rules: `promtool test rules alerts.test.yml` |
| `check.sh` | What CI runs: checks the files with `promtool`, lints `/metrics` and scrapes a running binary with a real Prometheus |

## Turn it on

1. Make a token: `openssl rand -base64 32`. It must be 32 to 256 printable characters with no spaces.
2. Give it to the app as `PIHOLE_RBAC_METRICS_TOKEN`, or better `PIHOLE_RBAC_METRICS_TOKEN_FILE`:
   - **LXC:** a file under `/etc/pihole-rbac/secrets/` (group `pihole-rbac`, mode `0640`), then the line in
     `/etc/pihole-rbac/env` and `sudo systemctl restart pihole-rbac`.
   - **Docker:** a Compose secret, as in `deploy/docker/compose.example.yaml`.
3. Give Prometheus the same token in a file only it can read. A trailing newline is fine on both sides.
4. Copy `prometheus.example.yml` and `alerts.example.yml` into your Prometheus configuration and change the target.

With the token set, `Authorization: Bearer <token>` returns the metrics. A missing or wrong token is a 401, and
`/metrics` with no token configured is a 404, so a scraper with a mistyped token tells you which. The token opens
nothing but `/metrics`, and an API token (Admin, API tokens) doesn't open it. Changing the token file takes effect
after **Reload secrets** in the app (System), with nothing to restart.

Wrong tokens are counted per client address, separately from logins: ten in 15 minutes gets a 429 with `Retry-After`,
and never locks anyone out of logging in.

## Scrape through your reverse proxy

The app speaks plain HTTP behind the proxy that ends TLS, so a scrape straight to the app sends the token in clear.
Scrape the proxy's HTTPS address (`scheme: https` in the example). On a trusted network you can accept that and use
the app's own address instead. `/metrics` doesn't need to be reachable from outside your network: restrict it in the
proxy if you like (the app still checks the token).

## What you get

Every label value is an instance, group, destination or target name that an admin set, or a value from a fixed list.
Nothing a client sends, and no secret, becomes a label.

| Metric | Meaning |
| --- | --- |
| `pihole_rbac_instance_up{instance}` | 1 up, 0 down. No series until the instance has been called after a start |
| `pihole_rbac_instance_last_success_timestamp_seconds{instance}` | When it last answered |
| `pihole_rbac_pihole_requests_total{instance,result}` | Operations on a Pi-hole by result (`ok`, `rejected`, `error`, `down`, `backoff`) |
| `pihole_rbac_pihole_request_duration_seconds{instance}` | Histogram of those that reached it |
| `pihole_rbac_group_drift_items{group,type}` | Differences in a mirrored group. No series before its first check |
| `pihole_rbac_group_drift_last_check_timestamp_seconds{group}` | When the group was last checked |
| `pihole_rbac_writes_total{result}` | API writes: `ok`, `partial`, `failed` |
| `pihole_rbac_logins_total{result}` | Finished logins: `ok`, `failed`, `locked_out` |
| `pihole_rbac_audit_events_total{action,result}` | Audit rows by action |
| `pihole_rbac_api_token_requests_total{result}` | API token requests by result |
| `pihole_rbac_sessions_active` | Live sessions |
| `pihole_rbac_notifications_total{result}`, `pihole_rbac_notification_queue_length` | Notifications sent, failed, dropped; the queue |
| `pihole_rbac_log_forward_total{destination,result}`, `pihole_rbac_log_forward_behind{destination}` | Audit forwarding |
| `pihole_rbac_client_reset_last_run_timestamp_seconds`, `..._last_run_ok` `{target_type,target}` | Last finished client reset run |
| `pihole_rbac_update_available` | 1 when a newer release is known. Absent when the update check is off |
| `pihole_rbac_http_requests_total{route,code_class}`, `pihole_rbac_http_request_duration_seconds{route}` | The app's own requests, by route pattern |
| `pihole_rbac_build_info{version}`, `process_start_time_seconds`, `go_*` | Build and Go runtime basics |

Counters start again at zero when the app restarts, as usual; use `rate()` and `increase()`. Pi-hole's own query
statistics are not included: they would load every Pi-hole on every scrape, and exporters for them exist. Prometheus
can scrape those directly.

## The alerts

| Alert | Fires when |
| --- | --- |
| `PiholeRbacDown` | Prometheus can't scrape the app for 5 minutes (down, unreachable, or the token is wrong or unset) |
| `PiholeRbacInstanceDown` | A Pi-hole has been down for 5 minutes |
| `PiholeRbacGroupDrift` | A mirrored group has differed from its primary for 15 minutes |
| `PiholeRbacGroupDriftNotChecked` | A group's drift hasn't been checked for an hour, so the drift alert can't be trusted |
| `PiholeRbacLogForwardBehind` | An enabled log destination is more than 100 rows behind for 15 minutes |
| `PiholeRbacNotificationsDropped` | Notifications were dropped because the queue was full |
| `PiholeRbacNotificationsFailing` | Notifications failed after their retries |
| `PiholeRbacUpdateAvailable` | A newer release has been known for an hour (the app never updates itself) |

The thresholds are starting points. Check changes to the rules with `promtool check rules alerts.example.yml` and
`promtool test rules alerts.test.yml`.

## Checking it yourself

`check.sh` needs `bash`, `curl`, `openssl`, a built binary and a Prometheus release directory (it uses `promtool`, and
`prometheus` for the last step):

```sh
go build -o bin/pihole-rbac ./cmd/pihole-rbac
deploy/prometheus/check.sh bin/pihole-rbac /path/to/prometheus-3.5.0.linux-amd64
```
