# Build tasks for Linux and CI. build.ps1 provides the same tasks on Windows;
# keep the two in step (same task names, same underlying commands).

SHELL := /bin/bash
.DEFAULT_GOAL := help

BIN      := bin/pihole-rbac
PKG      := pihole-rbac/internal/buildinfo
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE     ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS  := -s -w -X $(PKG).Version=$(VERSION) -X $(PKG).Commit=$(COMMIT) -X $(PKG).Date=$(DATE)

export CGO_ENABLED := 0
export PIHOLE_RBAC_DATA_DIR ?= $(CURDIR)/.devdata

.PHONY: help web web-check build check-embedded test dev-api dev-web snapshot clean

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
	@./$(BIN) version | tee /dev/stderr | grep -q '^frontend: embedded$$' \
		|| { echo "error: frontend is not embedded in $(BIN)" >&2; exit 1; }

test: ## go vet and go test
	go vet ./...
	go test ./...

dev-api: ## Run the API on :8080 with the dev data dir (no frontend build needed)
	@mkdir -p "$(PIHOLE_RBAC_DATA_DIR)"
	go run ./cmd/pihole-rbac serve

dev-web: web/node_modules ## Run the Vite dev server (proxies /api to :8080)
	npm --prefix web run dev

snapshot: ## GoReleaser snapshot build into dist/
	goreleaser release --snapshot --clean

clean: ## Remove build output
	rm -rf bin dist web/build/app
