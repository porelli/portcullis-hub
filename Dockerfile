# Build on the native builder platform and cross-compile (no emulation for Go).
# golang:1.27-alpine
FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:eb61c3873c97416fff0116553fff65d67a3549f72e11d9758849a689cdd8b523 AS build
ARG TARGETOS
ARG TARGETARCH
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
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /hub ./cmd/hub

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
