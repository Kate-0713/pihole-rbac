# pihole-rbac v2

A web portal in front of the Pi-hole v6 REST API that adds role-based access
control. Only this app holds Pi-hole credentials; every action is
permission-checked before it reaches Pi-hole.

v2 is a rebuild of v1: a Go JSON API with an embedded SvelteKit SPA and a
SQLite database, shipped as one static binary. The architecture document in
the pihole-rbac-v2 project is the source of truth for design decisions.

> Status: repo skeleton - The binary serves `/healthz` and
> reports its version; nothing else works yet.

## Layout

```
cmd/pihole-rbac/     main binary
internal/            api, buildinfo (more packages arrive with each milestone)
api/openapi.yaml     API contract (spec-first)
web/                 SvelteKit app; web/embed.go embeds web/build/app
.github/workflows/   CI
Makefile / build.ps1 build tasks for Linux / Windows (same task names)
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
| build | `make build` | `.\build.ps1 build` | Build the frontend, then `bin/pihole-rbac[.exe]` with it embedded, and check it's there |
| dev-api | `make dev-api` | `.\build.ps1 dev-api` | Run the server on `:8080` with data in `./.devdata` |
| dev-web | `make dev-web` | `.\build.ps1 dev-web` | Run the Vite dev server, proxying `/api` to `:8080` |
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
