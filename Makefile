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

export CGO_ENABLED := 0
export PIHOLE_RBAC_DATA_DIR ?= $(CURDIR)/.devdata

.PHONY: help web web-check build check-embedded test generate generate-check dev-api dev-web snapshot clean

help: ## List tasks
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-15s %s\n", $$1, $$2}'

web/node_modules: web/package-lock.json
	npm --prefix web ci
	@touch web/node_modules

web: web/node_modules ## Build the SvelteKit app into web/build/app
	npm --prefix web run build

web-check: web/node_modules ## Type-check the SvelteKit app
	npm --prefix web run check

build: web ## Build the frontend, then the binary with it embedded
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/pihole-rbac
	@$(MAKE) --no-print-directory check-embedded

check-embedded: ## Fail unless the built binary contains the frontend
	@out="$$(./$(BIN) version)"; echo "$$out"; grep -qx 'frontend: embedded' <<< "$$out" \
		|| { echo "error: frontend is not embedded in $(BIN)" >&2; exit 1; }

test: ## go vet and go test
	go vet ./...
	go test ./...

generate: ## Regenerate the sqlc code in internal/store/db
	$(SQLC) generate

generate-check: ## Fail if the generated sqlc code is out of date
	$(SQLC) diff

dev-api: ## Run the API on :8080 with the dev data dir (no frontend build needed)
	@mkdir -p "$(PIHOLE_RBAC_DATA_DIR)"
	go run ./cmd/pihole-rbac serve

dev-web: web/node_modules ## Run the Vite dev server (proxies /api to :8080)
	npm --prefix web run dev

snapshot: ## GoReleaser snapshot build into dist/
	goreleaser release --snapshot --clean

clean: ## Remove build output
	rm -rf bin dist web/build/app
