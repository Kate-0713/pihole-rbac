# Contributing and quality policy

Thank you for helping with pihole-rbac. This is how changes are made, checked and released. It applies to everyone who contributes, the maintainer included. The security properties it protects are described in [SECURITY.md](SECURITY.md); **please report suspected vulnerabilities privately, never in an issue or a pull request.**

This is a solo-maintained project, so response times vary, and a change that is small, tested and focused is far more likely to be merged quickly.

## Getting started

You need the Go version in `go.mod`, Node 26 with npm 11 or later, and either `make` (Linux) or Windows PowerShell (`.\build.ps1`, with the same task names). The README has the install notes and the full task table. The tasks you will use most:

```sh
make test         # go vet and go test
make web-check    # type-check the frontend
make web-test     # frontend unit tests
make e2e          # browser tests; downloads Chromium on the first run
make generate     # after changing a migration, a query or api/openapi.yaml
make dev-api      # run the API on :8080 (and make dev-web for the frontend)
```

Before opening a pull request, run at least `test`, `web-check` and `web-test`, and `e2e` for anything the browser sees. `make release-check` runs everything the maintainer runs before a release; it is not required for a pull request.

Found a bug or have an idea? Open an issue with one of the templates. For anything that changes the data model, the API or a security rule, agree it in an issue before writing code (see below).

## Licence

pihole-rbac is licensed under AGPL-3.0-or-later, and contributions are accepted under the same licence. New hand-written files carry the two-line SPDX header that existing files have.

## Principles

1. **The design is deliberate.** A change that conflicts with how the project is designed (the RBAC model, the API contract in `api/openapi.yaml`, the security properties in SECURITY.md) is raised first, and the code, the spec and the documentation move together if the design does. Nothing diverges quietly.
2. **Small, reviewable changes.** One concern per pull request, with file paths and the reason for the change stated.
3. **Security rules are not trade-offs.** The checks in SECURITY.md (server-side permissions, CSRF and Origin, CSP, secret handling, RBAC invariants) are never relaxed to ship a feature.
4. **Tests come with the code.** A behaviour change without a test that fails before it and passes after is not finished.
5. **Fail loudly and honestly.** Partial failures are reported per instance and never hidden, and errors use the standard envelope.

## Decisions that need agreement first

Open an issue or discussion before writing code for a change that would alter:

- the **data model** (schema or migrations);
- the **API contract** (`api/openapi.yaml`);
- a **security rule** (authentication, sessions, CSRF, CSP, secrets, permissions, the updater);
- the **dependency set**, which needs a reason and the standard-library alternative.

Bug fixes, tests, documentation and changes inside the existing design can go straight to a pull request.

## Definition of done

A pull request is ready when all of these are true:

- [ ] It does what the linked issue or milestone says, and nothing unrelated.
- [ ] Tests are added or updated (see below) and pass locally and in CI.
- [ ] Every route it adds or changes does a server-side permission check, declared with `x-permission` in the OpenAPI spec.
- [ ] Every write path writes an audit entry, and no audit entry, log line or error holds a secret value.
- [ ] Multi-step database changes run in one transaction (`store.WithTx`), with any RBAC invariant checked inside it.
- [ ] If the API, a query or a migration changed, `make generate` (or `.\build.ps1 generate`) was run and the regenerated code is committed.
- [ ] The OpenAPI spec and the generated types agree with the code.
- [ ] Errors come back in the standard envelope: `{"error":{"code","message","details"}}`.
- [ ] Documentation is updated if behaviour or design changed.
- [ ] New hand-written files carry the SPDX header (`AGPL-3.0-or-later`).
- [ ] User-facing changes are checked at desktop and phone widths, and are keyboard-usable.

## Testing standard

| Area | What is expected |
| --- | --- |
| Go | Table-driven tests alongside the code. |
| RBAC | Every invariant has a test that tries to break it: builtin admin immutability, at least one enabled local admin, no granting or assigning beyond what you hold, roles in use cannot be deleted, scope resolution. |
| Auth, sessions, CSRF, rate limiting | Required tests, including the failure paths: wrong or missing token, bad `Origin`, expired session, unknown user timing, limits tripping and clearing. |
| LDAP | Filter escaping, DN comparison, and the no-mapped-role case failing closed. |
| Pi-hole client and fan-out | Per-instance results including partial failure, path escaping and the value whitelist. Pi-hole behaviour the app relies on has a contract test in `internal/piholeapi/contract`, which runs against both the fake Pi-hole and a real one, and the fake is changed to match. |
| Database | Migrations are append-only: a released migration is never edited, and an upgrade test from the previous release must pass. |
| Frontend | Vitest for logic (stores, permissions, URL and redirect handling) and Playwright for flows. Anything that reads API or Pi-hole data must never render it as HTML. |
| Security regressions | A fixed vulnerability gets a test that fails without the fix, in the same pull request. |
| Concurrency | New code that shares state across goroutines is run under the race detector. |
| Deployment | The Docker smoke test and the LXC install and update scripts are kept working. |

## What CI checks

Every push to `master` and every pull request runs these jobs, and a release is built only if all of them pass: the release workflow runs the whole suite first.

- **test** (Linux and Windows): generated code is up to date (`sqlc diff`, oapi-codegen and openapi-typescript regeneration compared with the committed files); `svelte-check`; Vitest; the frontend build; `gofmt` (Linux); `go vet ./...`; `go test ./...`; the built binary reports the frontend as embedded; and, on Linux, the Playwright browser tests.
- **race detector**: `go test -race ./...`.
- **vulnerability check**: `govulncheck` and `npm audit`. This also runs weekly on its own.
- **docker**: the amd64 image is built and smoke-tested, and the arm64 image is built.
- **install**: ShellCheck on the shell scripts; a real install, restart, uninstall and purge on a systemd host; and a real update through the path unit and the root updater, a refused downgrade, and a rollback of a version that never starts.
- **rsyslog** and **prometheus**: log forwarding and the metrics output checked against the real programs.
- **pihole contract**: the Pi-hole client's contract tests against real Pi-hole containers, pinned by digest: the oldest supported Pi-hole (FTL v6.9) and the newest release. The same tests run weekly against the newest image, unpinned, as an early warning; that run doesn't hold back a release.
- **snapshot**: the release configuration still builds the Linux artifacts and the third-party notices.

## Reviewing a change

Reviewers look at, in this order:

1. **Authorisation.** Who can reach this, and is it checked on the server, against the right scope?
2. **Input and output.** Validation, escaping, the CSP, and whether any untrusted value reaches a path, a filter, a query or HTML.
3. **State.** Transactions, invariants, audit rows, and what happens on partial failure.
4. **Tests.** Do they fail for the right reason?
5. **Compatibility.** Migrations, the API contract, upgrades from the previous release, and the v1 import.
6. **Everything else.** Naming, size, comments, documentation.

Security findings in review are fixed in the pull request, not deferred.

## Dependencies

- Add one only when the standard library or an existing dependency cannot reasonably do the job, and say so in the pull request.
- Prefer pure-Go dependencies, because the binary builds with `CGO_ENABLED=0`.
- Licences must be compatible with AGPL-3.0-or-later. The release build lists third-party licences, and a dependency it cannot classify is handled by hand.
- Pin tool versions (`tools/go.mod`) so that generated code is reproducible.
- Keep the Go toolchain, Node and the runtime base image current; a security update to any of them does not wait for a feature release.

## Documentation

The README, the OpenAPI spec and this policy are kept current with the code. A change that makes any of them wrong includes the correction.

## For the maintainer

These sections describe how releases are made and how problems are triaged.

### Release checks

Before tagging, the maintainer runs `make release-check` (or `.\build.ps1 release-check`). It runs, in order, a clean-tree check, `gofmt`, the generated-code check, `go vet` and `go test`, the race detector, `govulncheck`, `npm audit`, `svelte-check`, Vitest, the browser tests (which build the binary and check the frontend is embedded), ShellCheck, the Docker smoke test and the GoReleaser snapshot, and stops at the first failure. A check can be skipped only by naming it in `RELEASE_CHECK_SKIP`, and skipped checks are listed at the end.

Some things need a person, and the command ends by listing them:

- CI is green on the release commit, including the jobs that need a systemd host or downloads (the LXC install and update tests, rsyslog, Prometheus and the Pi-hole contract tests);
- security-sensitive changes since the last release have been reviewed;
- both deployments (LXC and Docker) are tried by hand when the installer, updater or image changed.

### Releases

- One repository, one version, one release: the Go binary and the embedded web app always ship together, as Semantic Versions.
- A release is cut from a tagged commit by the release workflow, which runs CI in full, builds the Linux amd64 and arm64 binaries and the multi-architecture images, and signs `checksums.txt` with minisign.
- Release notes say what changed, call out security fixes, any upgrade step (for example a systemd unit change that needs `install.sh` run again) and any permission or behaviour change that needs an admin's attention.
- Migrations run on startup after a `VACUUM INTO` backup, and the updater rolls back automatically when a new version fails its health check.

### Bugs

| Severity | Examples | Handling |
| --- | --- | --- |
| Security | Anything in the scope of SECURITY.md | Reported privately, fixed first, released promptly. |
| High | Data loss, a wrong permission decision, a failed update that does not roll back | Fixed in the next release, with a regression test. |
| Medium | A feature broken for a deployment or a role | Scheduled for the next release. |
| Low | Cosmetic issues, rough edges, documentation | Fixed as time allows. |

Every bug fix includes a test that would have caught it.

## Changing this policy

Changes to this file and to SECURITY.md are made by pull request like any other change, and a change that weakens a requirement states why.
