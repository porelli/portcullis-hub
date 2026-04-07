# Portcullis Hub

Web management UI for [Portcullis](https://github.com/porelli/portcullis) — the self-hosted YubiKey authentication gateway.

## Features

- App catalog with auth badges (SSO, Group Access, Group Admin)
- One-click enable/disable apps via Docker Compose
- Per-app settings (media folders, config options)
- Container status monitoring and log viewer
- Expert mode: compose editor, env vars, container shell
- Template marketplace: add community template repos

## Docker Image

```bash
docker pull ghcr.io/porelli/portcullis-hub:latest
```

Used by the core Portcullis stack — no need to run standalone.

## Configuration

| Env Var | Description | Default |
|---------|-------------|---------|
| `PROJECT_DIR` | Container path to project root | `/project` |
| `PROJECT_HOST_DIR` | Host path (for Docker bind mounts) | same as PROJECT_DIR |
| `HUB_DATA_DIR` | Writable data directory | `/data` |
| `PORTCULLIS_DOMAIN` | Domain for all services | `portcullis.local` |
| `DEFAULT_TEMPLATES_URL` | Git URL for default marketplace | _(none)_ |
| `KEYCLOAK_URL` | Keycloak internal URL | `http://keycloak:8080` |
| `LLDAP_HTTP_URL` | LLDAP internal URL | `http://lldap:17170` |

## Development

```bash
go build -o hub .
./hub
```

## License

MIT
