# Build on the native builder platform and cross-compile (no emulation for Go).
# golang:1.27-alpine
FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
ARG TARGETOS
ARG TARGETARCH
# VERSION: semver (a release tag's, else 0.0.0-edge), the same as the
# agent's: servers.Compatible pairs them.
ARG VERSION=0.0.0-dev
# GO_TAGS: Go build tags, empty by default. Core's CI builds its e2e
# images with GO_TAGS=e2etest (internal/e2etest's test hooks); a default
# image has none of that code (CI checks it).
ARG GO_TAGS=""
WORKDIR /src
# Module download sits in its own layer keyed on go.mod/go.sum, so source
# edits don't invalidate it. The cache mounts keep the module and build caches
# across builds on the same builder (local rebuilds); they are not part of the
# image and are not exported to the CI layer cache.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -tags "${GO_TAGS}" -ldflags="-s -w -X github.com/portcullis/hub/internal/version.Version=${VERSION}" -o /hub ./cmd/hub \
 && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /portcullis ./cmd/portcullis

# alpine:3.24
FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
# git: template sources. docker-cli + compose plugin: `compose up/down`
# (everything else goes through the Engine API). Both talk to DOCKER_HOST,
# i.e. the Hub's socket proxy over TCP, so no socket file and no root needed.
RUN apk add --no-cache ca-certificates git docker-cli docker-cli-compose \
 && addgroup -S -g 10001 hub \
 && adduser -S -D -u 10001 -G hub -h /home/hub hub \
 && mkdir -p /data /secrets \
 && chown 10001:10001 /data /secrets \
 && chmod 0700 /secrets
COPY --from=build /hub /usr/local/bin/hub
# The Portcullis CLI (contract §18): the server's `portcullis` wrapper runs
# it from the Hub's image (a release build: no test overrides).
COPY --from=build /portcullis /usr/local/bin/portcullis
# Writable paths (must be owned by / writable for uid 10001):
#   /data               HUB_DATA_DIR — a fresh named volume inherits this ownership
#   /secrets            HUB_SECRETS_DIR (core's hub_secrets): 10001:10001 0700, checked at start
#   /project/templates  bind mount of <core>/templates on the host
USER 10001:10001
ENV HOME=/home/hub
EXPOSE 8888 8889 8891
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s \
  CMD wget -q -O /dev/null http://127.0.0.1:8888/healthz || exit 1
ENTRYPOINT ["hub"]
