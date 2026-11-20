# Security Policy

pihole-rbac sits in front of your Pi-hole instances and holds their credentials, so we treat security reports as the highest-priority work on the project. Thank you for taking the time to report one responsibly.

## Supported versions

Only the **latest release** receives security fixes. Releases are small and frequent, and there are no back-ported patches to older minor versions. Upgrading is a single step on both supported deployments (a new Docker image, or the LXC updater).

| Version | Supported |
| --- | --- |
| Latest `v2.x` release | Yes |
| Older `v2.x` releases | No, upgrade to the latest |
| `v1.x` (the htmx/JSON-file version) | No |
| Release candidates (`-rc.N`) | No |

## Reporting a vulnerability

**Please do not open a public issue, pull request or discussion for a security problem.**

Report it privately through GitHub:

1. Go to the **Security** tab of this repository.
2. Choose **Report a vulnerability** (or open <https://github.com/Kate-0713/pihole-rbac/security/advisories/new>).
3. Describe the problem, with as much of the following as you can:
   - the version (`pihole-rbac version`) and deployment (LXC or Docker);
   - the steps to reproduce, or a proof of concept;
   - what an attacker gains, and what they need first (an account, a role, network position);
   - any suggested fix.

Please never include real credentials, session cookies or the contents of someone's database in a report.

### What to expect

This is maintained by one person, so these are targets rather than guarantees:

| Stage | Target |
| --- | --- |
| Acknowledgement of your report | within 7 days |
| First assessment (accepted, needs more information, or declined, with reasons) | within 14 days |
| Fix and release for a confirmed high or critical issue | as fast as it can be done safely, normally within 30 days |
| Fix and release for a medium or low issue | in the next regular release |

We will keep you informed, agree a disclosure date with you, and publish a GitHub Security Advisory (with a CVE where one applies) when the fixed release is out. Reporters are credited in the advisory unless they prefer not to be.

## Scope

**In scope**

- Bypassing authentication, a permission check, or a role scope (`all`, `group`, `instance`), including acting on an instance or group you hold no grant for.
- Breaking the RBAC invariants: gaining the builtin admin role, granting or assigning beyond what you hold, removing the last enabled local admin.
- Session, CSRF, `Origin`, login rate-limit and API-token weaknesses.
- Injection of any kind: LDAP filters or DN comparison, SQL, paths sent to Pi-hole, XSS (including anything that bypasses the CSP).
- Server-side request forgery or secret exposure through notification channels.
- Secrets appearing in logs, audit entries, API responses or backups.
- Weaknesses in the update path: the root updater, signature verification, downgrade protection, or anything that lets the app account gain root or replace its own binary.
- Weaknesses in how releases are built and signed (the minisign signature on `checksums.txt`, the Docker images, `install.sh`).

**Out of scope**

- Vulnerabilities in Pi-hole, your LDAP server, your reverse proxy, Docker or the operating system. Please report those upstream.
- Findings that need an administrator who already holds the permission in question to do what that permission allows.
- Volumetric denial of service, and attacks that need access to the host, the database file or the master key.
- Deployments that ignore the hardening guidance below, for example exposing the app over plain HTTP on an untrusted network, or listing an untrusted address as a trusted proxy.
- Missing hardening that has no demonstrated impact, and automated-scanner output with no working exploit.
- A vulnerable dependency with no reachable path from this application. Tell us anyway if you are unsure, and we will check.

### Safe harbour

If you act in good faith, test only against your own installation, avoid privacy violations and data destruction, and give us reasonable time to fix the problem before you disclose it, we will not take or support legal action against you.

## How the project is designed to resist attack

A summary of the properties that reports are measured against.

- **Server-side authorisation on every route.** Hiding something in the interface is cosmetic. Permissions come from a fixed catalogue in code; roles and grants are data, and the invariants above are enforced in the same database transaction as the change.
- **The app alone holds Pi-hole, LDAP and notification credentials.** Notification secrets are AES-256-GCM encrypted at rest with a master key that comes only from the environment, and are write-only through the API.
- **Sessions are stored server-side.** Only a hash of the session ID is kept, the cookie is `HttpOnly` and `SameSite=Lax`, and there are no JWTs in browser storage.
- **Every state-changing request is protected twice**: a CSRF token header and a matching `Origin`. The API accepts `application/json` only. Personal API tokens use a separate path that does not rely on cookies.
- **Strict Content-Security-Policy** with no external assets and no inline script except hashed bootstrap scripts, and no `{@html}` on API or Pi-hole data.
- **Login throttling** per address and per username, timing-safe login for unknown users, a 1 MiB body cap and server timeouts.
- **LDAP fails closed:** a user whose groups map to no role gets no access, and group membership is rechecked on an interval.
- **Secrets are never logged or audited.**
- **The app never updates itself.** On Docker it only notifies. On LXC a separate root service verifies a minisign signature against a key built into the installed binary, refuses downgrades, backs up the database, health-checks the new binary and rolls back on failure. It never accepts a download URL from the app, and it treats everything in the data directory as untrusted.

## Verifying a release

Each release publishes Linux binaries for amd64 and arm64, `checksums.txt`, a minisign signature `checksums.txt.minisig`, and multi-architecture images on GHCR.

```sh
minisign -Vm checksums.txt -p minisign.pub   # minisign.pub is at the repository root
sha256sum --check --ignore-missing checksums.txt
```

The signature's trusted comment reads `pihole-rbac <tag>`, which ties it to one release. The LXC install script and updater perform these checks for you.

## Deploying safely

- Put the app behind a reverse proxy that ends TLS, and set `PIHOLE_RBAC_COOKIE_SECURE` accordingly. Only list proxies you control as trusted proxies, because `X-Forwarded-*` headers are believed from nothing else.
- Make the proxy pass the original `Host` header through, since the `Origin` check depends on it.
- Keep the master key and session key in the environment, a Docker secret or a root-only file, never in the repository or the image.
- Use LDAPS for the directory, and a service account that can only search for users and read their groups.
- Create a dedicated Pi-hole app password per instance, and give the app account nothing else.
- Keep the data directory private to the service user, and back it up: it holds sessions, roles and the audit log.
- Run the supported deployments as shipped (the systemd unit on LXC, the distroless non-root image on Docker), and stay on the latest release.
- Set a short LDAP recheck interval if group changes need to take effect quickly.

## Dependencies and supply chain

- Go and npm dependencies are locked (`go.sum`, `package-lock.json`), and each new dependency has to be justified in its pull request, with the standard-library alternative stated.
- Release builds are produced by the release workflow from a tagged commit, after the full CI suite passes, and list their third-party licences in `THIRD_PARTY_NOTICES.txt`.
- `govulncheck` (Go dependencies and standard library, reachable code only) and `npm audit` (frontend, failing on high or critical) run in CI on every push and pull request, before every release, and weekly on their own, since new advisories appear without any change to the code. Anything they report is fixed, or explained in the release notes.
- The runtime base image is tracked by Dependabot.

## Past security fixes

Confirmed vulnerabilities are published as GitHub Security Advisories on this repository, and fixes are called out in the release notes.
