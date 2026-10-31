# Portcullis Hub — Claude Code Instructions

## Project Overview

Web management UI for Portcullis. Go binary with an embedded single-page UI, published as `ghcr.io/porelli/portcullis-hub`. It manages one docker compose project per app (`portcullis-<app-id>`), writes the group-gate policy file and registers Keycloak OIDC clients. The cross-repo interfaces are defined in `portcullis-docs/docs/guides/integration-contracts.md` — change that page first.

## Layout

| Path | Purpose |
|------|---------|
| `cmd/hub` | `main`: env config, wiring, HTTP server, reconcile loop |
| `internal/hub` | App core: catalog, enable/disable/restart (per-app lock), env + override generation, sources, policy-file writer, runtime (status/logs/exec), drift reconcile |
| `internal/templates` | Manifest types, discovery + validation, strict Traefik rule parsing (`ParseRoutes`), template file sync to `/project/templates/<id>` |
| `internal/policy` | Auth-policy model (LoA/ACR/TLS tier) and group-gate policy file v2 (`Build`, `Write`) |
| `internal/state` | `state.yaml` load/save (atomic; corrupt file = refuse to start) |
| `internal/compose` | `docker compose` CLI wrapper — **up/down only**, behind the `Runner` interface |
| `internal/docker` | Engine API client over `DOCKER_HOST` (net/http): containers, logs (stream demux), exec, events |
| `internal/keycloak` | Keycloak admin API client (net/http) |
| `internal/httpapi` | Handlers, proxy-secret middleware, CSRF guard |
| `internal/fsutil` | Atomic writes, path confinement |
| `web/` | `index.html` (vanilla JS) + `web.go` embed |

## Critical Rules

- Dependencies: **stdlib + `gopkg.in/yaml.v3` only**. No Docker SDK, no web framework, no other modules.
- Run `go vet ./... && go test -race ./...` and `gofmt -l .` after every change; CI runs the same.
- Docker: everything read-only (status, logs, exec, events) goes through `internal/docker`; the `docker compose` CLI is used only for `up`/`down` (compose has no API). Both use `DOCKER_HOST` (the Hub's socket proxy, `tcp://socket-proxy-hub:2375`).
- `--project-directory` must be the HOST path (`PROJECT_HOST_DIR`) so the daemon resolves bind mounts.
- Every request except `GET /healthz` needs `X-Portcullis-Proxy-Secret` == `HUB_PROXY_SECRET` (≥ 32 chars, or the Hub won't start).
- group-gate keys policies, groups and path groups **by subdomain only**. Templates whose Traefik rules the Hub can't fully resolve to `<sub>.${PORTCULLIS_DOMAIN}` hosts are rejected; two enabled apps may not route the same subdomain.
- Never hold `Hub.mu` across docker/network calls; lifecycle ops take the per-app lock (`lockApp`).
- Fail closed: `state.yaml` `published` keeps each enabled app's last published config; the policy writer falls back to it when the template is missing, and denies (`policy.DenyGroup`) subdomains of running app projects it has no config for.
- Reconcile reports drift, it never fixes it; actions are explicit (`/api/drift/resolve`).
- No migration/back-compat code: there are no installs to upgrade from.
- Frontend is vanilla JS in `web/index.html` — no build step, no npm. Escape everything with `escapeHtml`.
- Templates come from git sources (`state.yaml` `sources`), not the local filesystem.
- The image runs as uid/gid 10001; `/data` and the host's `<core>/templates` must be writable by it.
- Pin GitHub Actions by full commit SHA (`# vX.Y.Z` comment) and base images by digest.

## Related Repos

| Repo | Purpose |
|------|---------|
| `porelli/portcullis` | Core stack (Traefik, Keycloak, LLDAP, group-gate, CLI) |
| `porelli/portcullis-templates` | Default app marketplace (`TestRealTemplates` loads a sibling checkout if present) |
| `porelli/portcullis-docs` | Documentation site, incl. the integration contracts |
