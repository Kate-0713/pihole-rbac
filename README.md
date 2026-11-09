# pihole-rbac v2

A web portal in front of the Pi-hole v6 REST API that adds role-based access
control. Only this app holds Pi-hole credentials; every action is
permission-checked before it reaches Pi-hole.

v2 is a rebuild of v1: a Go JSON API with an embedded SvelteKit SPA and a
SQLite database, shipped as one static binary.

## Features

### Hand out Pi-hole access without handing out the password

- Staff sign in to pihole-rbac, never to Pi-hole itself. Only the app holds
  the Pi-hole app passwords, and every action is checked against the user's
  permissions on the server before anything reaches Pi-hole.
- The everyday Pi-hole tasks, each behind its own permission:
  - **Dashboard:** status and query counters, turn blocking off for a set
    time (preset or custom, up to 24 hours) or until turned back on, and
    restart DNS.
  - **Domains:** add and remove allow and deny entries, and change their
    groups and comments.
  - **Clients:** change a client's groups and comment.
  - **Query log:** search and filter recent queries.
- People only see the pages and buttons they're allowed to use.

### Roles you define, scoped to where they apply

- Build your own roles from a fixed list of permissions. A built-in admin
  role is always there, and first-run setup adds editable `staff` and
  `reader` roles to start from.
- Each permission in a role can apply to every Pi-hole, to a group of them,
  or to a single one: a site lead can edit domains on Site A's Pi-holes and
  only view everything else.
- Guard rails stop mistakes and privilege escalation: nobody can grant or
  assign more than they hold, change a more privileged user's account, or
  remove the last enabled local admin, and the admin role can't be edited.

### Local accounts and LDAP / Active Directory

- Local accounts and LDAP login, in the order you choose. Local login stays
  on, so there is always a way in if the directory is down.
- Map directory groups to roles. Group membership is rechecked during a
  session, so removing someone from a group removes their access within
  minutes, not at their next login. A user whose groups map to no role is
  refused: there is no default role.
- A test tool shows what a given user would get (their groups, matching
  mappings, roles and effective permissions), and each mapping can be
  checked against the directory.
- Users can see and end their own sessions; admins can see and revoke
  anyone's.

### Several Pi-holes from one place

- Add any number of Pi-hole v6 instances, each with its own health shown in
  the header, and pick which one to work on from anywhere in the app.
- **Independent groups** label instances ("Site A", "Lab") so permissions
  can be granted on the whole group.
- **Mirrored groups** treat several Pi-holes as one: changes go to every
  member, and the result is shown per instance, so a partial failure is
  never hidden and can be retried. Drift between members is detected
  automatically, and **Reconcile** brings them back in line with the group's
  primary, item by item or all at once.

### Client reset

- Rules put clients whose comment starts with a prefix (`TEST-`, say) back
  into a fixed set of Pi-hole groups after someone has been testing with
  them, on demand or on a daily schedule.
- A preview shows exactly which clients a run would change before it runs,
  and the history shows what every run did.

### Audit log and notifications

- Every change is recorded: who did what, where, from which address, and
  whether it worked, with per-instance results for mirrored groups. Filter
  it in the app or export it as CSV, and choose how long to keep it.
- Send chosen events to any number of Discord and Matrix channels, including
  an alert when a client is added to a protected Pi-hole group.
- A notification channel can't be silenced quietly: changing, disabling or
  deleting one sends a warning to its old destination first.

### Security built in

- Server-side sessions, CSRF protection on every change, a strict Content
  Security Policy and no externally loaded scripts, fonts or styles.
- Login rate limiting, and stored secrets (Pi-hole passwords, the LDAP bind
  password, notification credentials) encrypted at rest and never shown
  again once saved.

### Simple to run and keep up to date

- One self-contained binary with its own SQLite database: nothing else to
  install or run alongside it.
- **Debian or Ubuntu LXC:** an install script that verifies signed releases
  and sets up a hardened systemd service. Updates are started by an admin
  from the app or the command line, and a separate updater verifies the
  release, backs up the database, and rolls back automatically if the new
  version doesn't come up healthy.
- **Docker:** images for amd64 and arm64 (including Raspberry Pi), with the
  app telling you when a new release is out.
- Guided first-run setup, light and dark themes, and an import command that
  brings users, roles, settings and notifications across from v1.

## Installation

pihole-rbac serves plain HTTP on port 8080 and expects a reverse proxy
(Caddy, Traefik, nginx) in front of it for HTTPS. You'll need a Pi-hole v6
instance with an app password (in Pi-hole, under **Settings → Web interface /
API**) for each Pi-hole you want to manage.

### Debian or Ubuntu (LXC or VM)

Debian 12 or later, or Ubuntu 24.04 or later, with systemd. As root:

```sh
curl -fsSLO https://github.com/Kate-0713/pihole-rbac/releases/latest/download/install.sh
less install.sh   # worth a read before running anything as root
bash install.sh
```

The script downloads the latest release, verifies its signature and
checksum, creates a `pihole-rbac` service user, writes
`/etc/pihole-rbac/env` with a newly generated master key, starts the
service, and prints a setup token. **Keep a copy of the master key** from
that file: without it, the passwords stored in the app can't be read.

Other options: `--version vX.Y.Z` installs a specific release, `--uninstall`
removes the service and binary but keeps your data, and `--uninstall --purge`
removes everything. Running the script again upgrades to the latest release
and never touches your config or data.

Settings such as `PIHOLE_RBAC_TRUSTED_PROXIES` go in `/etc/pihole-rbac/env`
(the comments there explain each one); restart with
`sudo systemctl restart pihole-rbac` after changing it.

### Docker

Images for amd64 and arm64 are published at
`ghcr.io/kate-0713/pihole-rbac`. Copy
[`deploy/docker/compose.example.yaml`](deploy/docker/compose.example.yaml) to
`compose.yaml`, then:

```sh
mkdir -p secrets
openssl rand -base64 32 > secrets/secret_key   # the master key; keep a copy somewhere safe
sudo chown 65532:65532 secrets/* && sudo chmod 0400 secrets/*
docker compose up -d
docker compose logs pihole-rbac | grep 'setup token'
```

The container runs as UID 65532, hence the `chown`. The example binds the
port to `127.0.0.1` for a reverse proxy on the same host; the comments in it
cover the other settings.

### Reverse proxy

- Set `PIHOLE_RBAC_TRUSTED_PROXIES` to the proxy's address, as narrowly as
  possible. Login rate limits and the audit log use the client address the
  proxy passes on, and only listed proxies are believed.
- The proxy must pass the original `Host` header through. Caddy and Traefik
  do by default; nginx needs `proxy_set_header Host $host;`.
- Pass `X-Forwarded-Proto` too, so cookies are marked `Secure` over HTTPS.

### First run

1. Open `https://<your address>/setup` and enter the setup token, then
   choose the first admin's username and password. If the token has
   expired or you missed it, make a new one with
   `sudo pihole-rbac setup --print-token` (LXC) or
   `docker compose exec pihole-rbac pihole-rbac setup --print-token`
   (Docker).
2. Under **Admin → Instances**, add each Pi-hole with its address and app
   password, test the connection, and enable it. New instances start
   disabled.
3. Under **Admin → Roles** and **Admin → Users**, set up roles and accounts,
   and under **Admin → LDAP** connect your directory if you use one.

Locked out? `sudo pihole-rbac user reset-admin <username>` (or the
`docker compose exec` form) resets a local admin's password from the
command line.

### Updating

- **LXC:** when a new release is out, the app shows a banner. An admin can
  click **Update now** on **Admin → System**, or run
  `sudo pihole-rbac update`. The database is backed up first and the
  previous version is restored automatically if the new one doesn't start.
- **Docker:** run `docker compose pull && docker compose up -d`. The new
  container backs up the database and migrates it on startup.

### Moving from v1

`pihole-rbac import-json --config config.json` shows what it would bring
across from a v1 install (users, roles, LDAP, notifications, client reset
rules) and what you'll need to do by hand. Add `--apply` to import it into a
fresh v2 install, before first-run setup. Run `pihole-rbac help` for the
options.

## Layout

```
cmd/pihole-rbac/      main binary and its subcommands (serve, setup, update, import-json, …)
internal/             application packages (api, auth, rbac, store, updater, …)
api/openapi.yaml      API contract (spec-first)
migrations/           goose migrations, embedded and run on startup; append-only once released
queries/              SQL for sqlc, which generates internal/store/db
web/                  SvelteKit app; web/embed.go embeds web/build/app
deploy/lxc/           install.sh, systemd units (app and updater) and the env template
deploy/docker/        Dockerfile, compose.example.yaml and the image smoke test
deploy/notices/       builds THIRD_PARTY_NOTICES.txt for releases
tools/                pinned code generators and checkers (sqlc, oapi-codegen, go-licenses)
.github/workflows/    CI and release
.goreleaser.yaml      release build: archives, checksums and minisign signature
minisign.pub          public key that release signatures are checked against
Makefile / build.ps1  build tasks for Linux / Windows (same task names)
```

## Prerequisites (Windows and Debian/Ubuntu)

- Go: the version in `go.mod` (currently 1.27.3). With an older Go installed,
  the default `GOTOOLCHAIN=auto` downloads the right one automatically.
- Node.js 22.17 or later (24 LTS recommended) with npm.
- Git.
- No C compiler: everything builds with `CGO_ENABLED=0`.
- Optional: [GoReleaser](https://goreleaser.com) v2 for `snapshot`, and
  [air](https://github.com/air-verse/air) for auto-reload.

### Debian / Ubuntu

```sh
sudo apt install make git
# Go: download the tarball from https://go.dev/dl/ (the apt package lags behind)
# Node: https://nodejs.org or NodeSource; Debian's nodejs package may be too old
```

### Windows

```powershell
winget install GoLang.Go OpenJS.NodeJS.LTS Git.Git
```

If PowerShell refuses to run `build.ps1`, allow local scripts for your user
once with `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, or run
`powershell -ExecutionPolicy Bypass -File .\build.ps1 <task>`.

## Tasks

The same tasks exist on both platforms:

| Task | Debian/Ubuntu | Windows | What it does |
| --- | --- | --- | --- |
| test | `make test` | `.\build.ps1 test` | `go vet` and `go test` |
| web | `make web` | `.\build.ps1 web` | Build the SvelteKit app into `web/build/app` |
| web-check | `make web-check` | `.\build.ps1 web-check` | Type-check the SvelteKit app |
| web-test | `make web-test` | `.\build.ps1 web-test` | Run the frontend unit tests (Vitest) |
| e2e | `make e2e` | `.\build.ps1 e2e` | Build, then run the browser tests (Playwright) against the binary and fake Pi-holes; downloads Playwright's Chromium on first run |
| build | `make build` | `.\build.ps1 build` | Build the frontend, then `bin/pihole-rbac[.exe]` with it embedded, and check it's there |
| check-embedded | `make check-embedded` | `.\build.ps1 check-embedded` | Fail unless the built binary contains the frontend |
| generate | `make generate` | `.\build.ps1 generate` | Regenerate `internal/store/db` (sqlc), `internal/api/gen` (oapi-codegen) and `web/src/lib/api/schema.d.ts` (openapi-typescript) |
| generate-check | `make generate-check` | `.\build.ps1 generate-check` | Fail if the generated code is out of date; changes nothing |
| dev-api | `make dev-api` | `.\build.ps1 dev-api` | Run the server on `:8080` with data in `./.devdata` |
| dev-web | `make dev-web` | `.\build.ps1 dev-web` | Run the Vite dev server, proxying `/api` to `:8080` |
| docker | `make docker` | `.\build.ps1 docker` | Build the Docker image for this machine's platform as `pihole-rbac:dev` |
| snapshot | `make snapshot` | `.\build.ps1 snapshot` | GoReleaser snapshot of the Linux release artifacts into `dist/` |
| clean | `make clean` | `.\build.ps1 clean` | Remove `bin/`, `dist/` and `web/build/app` |

Plain Go commands work too, with no frontend build needed:

```sh
go test ./...
go run ./cmd/pihole-rbac serve
go run ./cmd/pihole-rbac version
```

A binary built before `npm run build` reports `frontend: not built`. CI and
the release build fail unless it reports `frontend: embedded`.

## Development loop

1. Run one or two throwaway Pi-hole v6 containers (two for mirrored groups).
2. Terminal 1: `make dev-api` / `.\build.ps1 dev-api`.
3. Terminal 2: `make dev-web` / `.\build.ps1 dev-web`, then open the URL Vite
   prints. Vite proxies `/api` to `:8080`, so the browser sees one origin.

## CI

GitHub Actions (`.github/workflows/ci.yml`) runs on Ubuntu and Windows:
web type-check and build, `go vet`, `go test`, and a binary build that must
embed the frontend. A GoReleaser snapshot job then builds the Linux amd64
and arm64 release artifacts.

## Copyright

Copyright (C) 2026 Kate O'Grady

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public Licence as
published by the Free Software Foundation, either version 3 of the
Licence, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public Licence for more details.

You should have received a copy of the GNU Affero General Public Licence
along with this program.  If not, see <https://gnu.org>.
