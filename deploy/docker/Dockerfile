# syntax=docker/dockerfile:1
# SPDX-FileCopyrightText: 2026 Kate O'Grady
# SPDX-License-Identifier: AGPL-3.0-or-later

# Multi-arch image for pihole-rbac. Build from the repo root:
#   docker build -f deploy/docker/Dockerfile -t pihole-rbac:dev .
#   docker buildx build -f deploy/docker/Dockerfile --platform linux/amd64,linux/arm64 .
#
# The frontend and Go stages run on the build machine's platform and Go cross-compiles for the target, so an arm64
# image builds without emulation. Only the final stage is per-platform.

ARG GO_VERSION=1.27.3
# GO_VERSION follows go.mod. NODE_VERSION follows CI.
ARG NODE_VERSION=24

FROM --platform=$BUILDPLATFORM node:${NODE_VERSION}-trixie-slim AS web
WORKDIR /src/web
# Dependencies first, so a source change doesn't reinstall them. `prepare` runs `svelte-kit sync`, which tolerates the
# sources not being there yet.
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build && test -f build/app/index.html

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-trixie AS go
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/build/app ./web/build/app
# /out/lib/pihole-rbac becomes the data directory (0750, owned by the image's non-root user below), so a new named
# volume mounted there takes that owner. Copying its parent keeps the directory's own mode.
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags "-s -w \
        -X github.com/Kate-0713/pihole-rbac/internal/buildinfo.Version=${VERSION} \
        -X github.com/Kate-0713/pihole-rbac/internal/buildinfo.Commit=${COMMIT} \
        -X github.com/Kate-0713/pihole-rbac/internal/buildinfo.Date=${DATE}" \
      -o /out/pihole-rbac ./cmd/pihole-rbac \
 && mkdir -p /out/lib && mkdir -m 0750 /out/lib/pihole-rbac

# A literal FROM, so Dependabot can keep it current; it also keeps a digest current if one is pinned with @sha256:.
FROM gcr.io/distroless/static-debian13:nonroot
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown
LABEL org.opencontainers.image.title="pihole-rbac" \
      org.opencontainers.image.description="Role-based access control in front of the Pi-hole v6 API" \
      org.opencontainers.image.source="https://github.com/Kate-0713/pihole-rbac" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${DATE}"

COPY --from=go /out/pihole-rbac /usr/local/bin/pihole-rbac
COPY --from=go --chown=65532:65532 /out/lib/ /var/lib/
COPY LICENCE.md README.md /usr/share/doc/pihole-rbac/

# distroless :nonroot is UID/GID 65532. Logs go to stdout unless PIHOLE_RBAC_LOG_DIR is set.
USER 65532:65532
ENV PIHOLE_RBAC_LISTEN=:8080 \
    PIHOLE_RBAC_DATA_DIR=/var/lib/pihole-rbac
EXPOSE 8080

# distroless has no curl, so the binary checks its own /healthz. The start period covers migrations on a first start
# after an upgrade; during it Docker 25 and later check every 2 seconds, so the container reports healthy promptly.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --start-interval=2s --retries=3 \
  CMD ["/usr/local/bin/pihole-rbac", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/pihole-rbac"]
CMD ["serve"]
