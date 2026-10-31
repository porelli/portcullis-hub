# Portcullis Hub

Web management UI for [Portcullis](https://github.com/porelli/portcullis) — the self-hosted YubiKey authentication gateway.

## Features

- App catalog with auth badges (SSO, Group Access, Group Admin)
- One-click enable/disable; each app is its own compose project (`portcullis-<app-id>`)
- Per-app settings (media folders, ports, options) and access policy (mTLS / WebAuthn / password, any/all)
- Container status, logs and a container shell via the Docker Engine API
- Drift detection: flags apps that are enabled but not running, or running but not enabled, and offers explicit fixes
- Writes the group-gate policy file (v2: policies, groups and admin `path_groups` per subdomain)
- Expert mode: compose editor, env vars
- Template marketplace: add community template repos

## Docker Image

Images are published to `ghcr.io/porelli/portcullis-hub`:

| Tag | When |
|-----|------|
| `X.Y.Z`, `X.Y`, `X`, `sha-<short>` | release tags `vX.Y.Z` |
| `edge` | every push to `main` |

There is no `latest` tag. Pin a release by tag and digest. Every pushed image has SBOM and provenance attestations and is signed with cosign (keyless, GitHub OIDC). To verify:

```bash
cosign verify ghcr.io/porelli/portcullis-hub:1.0.0 \
  --certificate-identity-regexp '^https://github.com/porelli/portcullis-hub/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The core Portcullis stack runs the Hub; you don't need to run it standalone.

## Configuration

| Env Var | Description | Default |
|---------|-------------|---------|
| `HUB_PROXY_SECRET` | **Required**, at least 32 chars. Traefik sends it as `X-Portcullis-Proxy-Secret`; every request except `GET /healthz` must carry it | — |
| `DOCKER_HOST` | Docker endpoint for the Engine API and `docker compose` (`tcp://host:port` or `unix:///path`) | `unix:///var/run/docker.sock` |
| `PROJECT_DIR` | Container path to the core checkout | `/project` |
| `PROJECT_HOST_DIR` | Host path of the same checkout (for bind mounts) | same as `PROJECT_DIR` |
| `HUB_DATA_DIR` | Writable data directory | `$PROJECT_DIR/.hub` |
| `HUB_LISTEN_ADDR` | Listen address | `:8888` |
| `HUB_RECONCILE_INTERVAL` | Periodic drift check (Go duration, ≥ 5s); Docker events also trigger it | `1m` |
| `PORTCULLIS_DOMAIN` | Domain for all services | `portcullis.local` |
| `PORTAL_DISPLAY_NAME` | Name shown in the header | `Portcullis` |
| `DEFAULT_TEMPLATES_URL` | Git URL cloned as source `portcullis` on first start | _(none)_ |
| `KEYCLOAK_URL`, `KEYCLOAK_ADMIN`, `KEYCLOAK_ADMIN_PASSWORD` | Keycloak admin API | `http://keycloak:8080` |
| `LLDAP_HTTP_URL`, `LLDAP_ADMIN_USER`, `LLDAP_ADMIN_PASSWORD` | LLDAP (username shown in the header) | `http://lldap:17170`, `admin` |

### Runtime user and permissions

The image runs as **uid/gid 10001** (non-root). It doesn't need the Docker socket: it talks to its socket proxy over TCP (`DOCKER_HOST=tcp://socket-proxy-hub:2375`). The paths it writes must be writable by 10001:

- `/data` (`HUB_DATA_DIR`): a fresh named volume gets the right ownership from the image. For an existing volume or a bind mount, run `chown -R 10001:10001` on it.
- `/project/templates`: the host's `<core>/templates` directory. Run `chown 10001:10001 templates` on the host.
- `/project/.env` must be readable by 10001. The Hub copies variables that templates reference from this file.

### Endpoints

- `GET /healthz` returns `200 ok` and needs no secret (use it for container health checks).
- `GET /api/drift` returns the latest reconcile report. `POST /api/drift` re-checks now.
- `POST /api/drift/resolve` takes `{"id", "action"}`, where `action` is `start`, `disable`, `stop` or `adopt`.

## Development

```bash
go vet ./... && go test -race ./...
go build -o hub ./cmd/hub
HUB_PROXY_SECRET=$(openssl rand -hex 24) HUB_DATA_DIR=/tmp/hub PROJECT_DIR=/tmp/core ./hub
```

Dependencies are limited to the Go standard library and `gopkg.in/yaml.v3`. See `CLAUDE.md` for the package layout.

## License

MIT
