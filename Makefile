# SPDX-FileCopyrightText: 2026 Kate O'Grady
# SPDX-License-Identifier: AGPL-3.0-or-later

# Build tasks for Linux and CI. build.ps1 provides the same tasks on Windows;
# keep the two in step (same task names, same underlying commands).

SHELL := /bin/bash
.DEFAULT_GOAL := help

BIN      := bin/pihole-rbac
PKG      := github.com/Kate-0713/pihole-rbac/internal/buildinfo
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE     ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS  := -s -w -X $(PKG).Version=$(VERSION) -X $(PKG).Commit=$(COMMIT) -X $(PKG).Date=$(DATE)

# sqlc is pinned in tools/go.mod, not the main go.mod (see the comment there).
SQLC     := go tool -modfile=tools/go.mod sqlc
OAPI     := go tool -modfile=tools/go.mod oapi-codegen -config api/oapi-codegen.yaml api/openapi.yaml
# openapi-typescript generates the frontend's API types from the same spec.
WEBGEN   := npm --prefix web run --silent generate
API_GEN  := internal/api/gen/api.gen.go web/src/lib/api/schema.d.ts

# The shell scripts ShellCheck covers (the same list as the CI install job).
SHELL_SCRIPTS := deploy/lxc/install.sh deploy/lxc/test-install.sh deploy/lxc/test-update.sh deploy/docker/smoke-test.sh internal/piholeapi/contract/run-pihole.sh

# The checks release-check runs, in this order: quick ones first, slow ones last. Skip some with
# RELEASE_CHECK_SKIP="race docker-smoke" (space or comma separated); skipped checks are listed at the end.
RELEASE_CHECKS := tree-check fmt-check generate-check test race vulncheck audit web-check web-test e2e shellcheck docker-smoke snapshot
comma := ,
SKIP_LIST := $(subst $(comma), ,$(RELEASE_CHECK_SKIP))

export CGO_ENABLED := 0
export PIHOLE_RBAC_DATA_DIR ?= $(CURDIR)/.devdata

.PHONY: help web web-check web-test e2e build check-embedded test tree-check fmt-check race vulncheck audit shellcheck docker-smoke release-check generate generate-check dev-api dev-web docker snapshot clean

help: ## List tasks
	@grep -E '^[a-z0-9-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-15s %s\n", $$1, $$2}'

web/node_modules: web/package-lock.json
	npm --prefix web ci
	@touch web/node_modules

web: web/node_modules ## Build the SvelteKit app into web/build/app
	npm --prefix web run build

web-check: web/node_modules ## Type-check the SvelteKit app
	npm --prefix web run check

web-test: web/node_modules ## Run the frontend unit tests (Vitest)
	npm --prefix web test

# Playwright downloads its Chromium once; later runs find it installed.
e2e: build ## Run the browser tests (Playwright) against the built binary and a fake Pi-hole
	npm --prefix web exec -- playwright install chromium
	npm --prefix web run e2e

build: web ## Build the frontend, then the binary with it embedded
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/pihole-rbac
	@$(MAKE) --no-print-directory check-embedded

check-embedded: ## Fail unless the built binary contains the frontend
	@out="$$(./$(BIN) version)"; echo "$$out"; grep -qx 'frontend: embedded' <<< "$$out" \
		|| { echo "error: frontend is not embedded in $(BIN)" >&2; exit 1; }

test: ## go vet and go test
	go vet ./...
	go test ./...

tree-check: ## Fail if there are uncommitted changes
	@if [ -n "$$(git status --porcelain)" ]; then \
		echo "error: the working tree has uncommitted changes:" >&2; git status --short >&2; exit 1; fi

fmt-check: ## Fail if a tracked Go file isn't gofmt-formatted
	@out="$$(gofmt -l $$(git ls-files '*.go'))" || exit 1; \
	if [ -n "$$out" ]; then echo "error: these files need gofmt (gofmt -w):" >&2; echo "$$out" >&2; exit 1; fi

# The race detector needs cgo, so a C compiler, unlike the rest of the build.
race: ## go test -race (needs a C compiler)
	@command -v gcc >/dev/null || command -v cc >/dev/null \
		|| { echo "error: the race detector needs a C compiler (gcc)" >&2; exit 1; }
	CGO_ENABLED=1 go test -race ./...

# govulncheck is pinned in tools/go.mod with the other dev tools.
vulncheck: ## govulncheck on the Go dependencies and standard library
	go tool -modfile=tools/go.mod govulncheck ./...

audit: ## npm audit on the frontend dependencies (fails on high or critical)
	npm --prefix web audit --audit-level=high

shellcheck: ## ShellCheck on the shell scripts
	@command -v shellcheck >/dev/null || { echo "error: shellcheck is not installed" >&2; exit 1; }
	shellcheck $(SHELL_SCRIPTS)

docker-smoke: docker ## Build the Docker image and smoke-test it (needs Docker, curl and openssl)
	bash deploy/docker/smoke-test.sh pihole-rbac:dev

release-check: ## Run every check a release needs, in order, stopping at the first failure (RELEASE_CHECK_SKIP="name ..." skips named checks)
	@set -e; \
	for s in $(SKIP_LIST); do \
		case " $(RELEASE_CHECKS) " in *" $$s "*) ;; \
		*) echo "error: RELEASE_CHECK_SKIP names an unknown check '$$s' (checks: $(RELEASE_CHECKS))" >&2; exit 1;; esac; \
	done; \
	total=$(words $(RELEASE_CHECKS)); n=0; skipped=""; \
	for s in $(RELEASE_CHECKS); do \
		n=$$((n+1)); \
		case " $(SKIP_LIST) " in *" $$s "*) \
			echo; echo "==> [$$n/$$total] $$s: SKIPPED"; skipped="$$skipped $$s"; continue;; esac; \
		echo; echo "==> [$$n/$$total] $$s"; \
		$(MAKE) --no-print-directory $$s; \
	done; \
	echo; \
	if [ -n "$$skipped" ]; then echo "release-check: passed, but these were SKIPPED:$$skipped"; \
	else echo "release-check: all $$total checks passed"; fi; \
	echo; \
	echo "Still to do by hand:"; \
	echo "  - CI is green on this commit (the LXC install and update, rsyslog, Prometheus and Pi-hole contract jobs need"; \
	echo "    a systemd host, Docker or downloads, so they run only there)"; \
	echo "  - security-sensitive changes since the last release are reviewed (CONTRIBUTING.md, Release checks)"; \
	echo "  - both deployments are tried by hand if the installer, updater or image changed"

generate: web/node_modules ## Regenerate internal/store/db (sqlc), internal/api/gen (oapi-codegen) and web/src/lib/api/schema.d.ts (openapi-typescript)
	$(SQLC) generate
	$(OAPI)
	$(WEBGEN)

generate-check: web/node_modules ## Fail if the generated code is out of date (compares with the files as they are now; changes nothing)
	$(SQLC) diff
	@tmp=$$(mktemp -d); for f in $(API_GEN); do cp $$f $$tmp/$$(basename $$f); done; \
	status=0; { $(OAPI) && $(WEBGEN) >/dev/null; } || status=1; \
	for f in $(API_GEN); do \
		if [ $$status -eq 0 ] && ! cmp -s $$tmp/$$(basename $$f) $$f; then \
			echo "error: $$f is out of date with api/openapi.yaml; run make generate" >&2; status=1; fi; \
		cp $$tmp/$$(basename $$f) $$f; \
	done; \
	rm -rf $$tmp; exit $$status

dev-api: ## Run the API on :8080 with the dev data dir (no frontend build needed)
	@mkdir -p "$(PIHOLE_RBAC_DATA_DIR)"
	go run ./cmd/pihole-rbac serve

dev-web: web/node_modules ## Run the Vite dev server (proxies /api to :8080)
	npm --prefix web run dev

docker: ## Build the Docker image for this machine's platform as pihole-rbac:dev
	docker build -f deploy/docker/Dockerfile -t pihole-rbac:dev \
		--build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg DATE=$(DATE) .

snapshot: ## GoReleaser snapshot build into dist/ (unsigned; needs bash, as the notices script does)
	goreleaser release --snapshot --clean --skip=sign

clean: ## Remove build output
	rm -rf bin dist web/build/app web/test-results web/playwright-report
