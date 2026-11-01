# Build on the native builder platform and cross-compile (no emulation for Go).
# golang:1.27-alpine
FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build
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
FROM alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
# git: template sources. docker-cli + compose plugin: `compose up/down`
# (everything else goes through the Engine API). Both talk to DOCKER_HOST,
# i.e. the Hub's socket proxy over TCP, so no socket file and no root needed.
RUN apk add --no-cache ca-certificates git docker-cli docker-cli-compose \
 && addgroup -S -g 10001 hub \
 && adduser -S -D -u 10001 -G hub -h /home/hub hub \
 && mkdir -p /data \
 && chown 10001:10001 /data
COPY --from=build /hub /usr/local/bin/hub
# Writable paths (must be owned by / writable for uid 10001):
#   /data               HUB_DATA_DIR — a fresh named volume inherits this ownership
#   /project/templates  bind mount of <core>/templates on the host
USER 10001:10001
ENV HOME=/home/hub
EXPOSE 8888 8889
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s \
  CMD wget -q -O /dev/null http://127.0.0.1:8888/healthz || exit 1
ENTRYPOINT ["hub"]
