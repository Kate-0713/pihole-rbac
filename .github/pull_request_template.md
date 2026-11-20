## What and why

<!-- What does this change, and why? Link the issue it closes, if there is one. -->

Closes #

## Type of change

- [ ] Bug fix
- [ ] New feature or behaviour change
- [ ] Documentation, tests or tooling only

## Does it touch anything security-sensitive?

<!-- Authentication, sessions, CSRF, permissions or roles, the updater, secrets, notifications, the CSP, the data
model or the API contract. If yes, say what and why. If you changed the data model, the API contract or a security
rule, was it agreed in an issue first? Suspected vulnerabilities do not belong in a public pull request: see
SECURITY.md. -->

## Checklist

- [ ] Tests are added or updated and pass (`make test`, and `make e2e` for anything the browser sees)
- [ ] Every route added or changed does a server-side permission check, declared with `x-permission` in `api/openapi.yaml`
- [ ] Every write path writes an audit entry, and no secret ends up in a log, an audit entry or an error
- [ ] Multi-step database changes run in one transaction
- [ ] If the API, a query or a migration changed, I ran `make generate` and committed the result
- [ ] Errors use the standard envelope
- [ ] New hand-written files carry the SPDX header
- [ ] Documentation is updated if behaviour or design changed

<!-- The full policy is in CONTRIBUTING.md. `make release-check` runs the whole suite of checks in one go. -->
