# Portcullis Hub — Claude Code Instructions

## Project Overview

Web management UI for Portcullis. Go binary with embedded HTML, published as `ghcr.io/porelli/portcullis-hub`.

## Architecture

- Single Go binary (`main.go` ~2600 lines) with embedded `web/index.html`
- Manages app templates via Docker Compose (per-app isolated projects)
- Auto-clones default templates from `porelli/portcullis-templates` on first startup
- Per-app .env files stored in Hub data volume
- Docker socket access for container management

## Critical Rules

- Keep it a single `main.go` — no framework, no external deps beyond `gopkg.in/yaml.v3`
- Frontend is vanilla JS in `web/index.html` — no build step, no npm
- Hub runs inside Docker, Docker CLI talks to host daemon via socket
- `--project-directory` must use HOST path (not container path) for bind mount resolution
- Templates come from git repos (sources), not local filesystem
- After changes, test with: `go build -o /dev/null .` then `docker build .`

## Related Repos

| Repo | Purpose |
|------|---------|
| `porelli/portcullis` | Core stack (Traefik, Keycloak, LLDAP, etc.) |
| `porelli/portcullis-templates` | Default app marketplace |
| `porelli/portcullis-docs` | Documentation site |
