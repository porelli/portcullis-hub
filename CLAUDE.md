# Portcullis Hub — Claude Code Instructions

## Project Overview

Web management UI for Portcullis. Go binary with an embedded single-page UI, published as `ghcr.io/porelli/portcullis-hub`. It manages one docker compose project per app (`portcullis-<app-id>`), writes the group-gate policy file and registers Keycloak OIDC clients. The cross-repo interfaces are defined in `portcullis-docs/docs/guides/integration-contracts.md` — change that page first.

## Layout

| Path | Purpose |
|------|---------|
| `cmd/hub` | `main`: env config, wiring, HTTP server, reconcile loop |
| `internal/hub` | App core: catalog, enable/disable/restart (per-app lock), env + override generation, custom override validation (`useroverride.go`), per-app last-operation records (`ops.go`), sources, policy-file writer, runtime (status/logs/exec), drift reconcile |
| `internal/templates` | Manifest types, discovery + validation, strict Traefik rule parsing (`ParseRoutes`), template file sync to `/project/templates/<id>` |
| `internal/policy` | Auth-policy model (LoA/ACR/TLS tier), per-method capabilities (`CapabilityFor`, `Resolve`, `Check`) and group-gate policy file v3 (`Build`, `Write`) |
| `internal/state` | `state.yaml` load/save (atomic; corrupt file = refuse to start) |
| `internal/compose` | `docker compose` CLI wrapper — **up/down only**, behind the `Runner` interface; failures are `*compose.Error` with the output tail (8 KiB) |
| `internal/docker` | Engine API client over `DOCKER_HOST` (net/http): containers, logs (stream demux), exec, events |
| `internal/keycloak` | Keycloak admin API client (net/http): clients, and users (lazy LDAP import, required actions, passkeys, sessions); `kctest` = in-memory fake |
| `internal/lldap` | LLDAP client: GraphQL (`/api/graphql`, JWT from `/auth/simple/login`, refresh/re-login on 401) + minimal LDAP codec for the Password Modify extended op (passwords); credentials from files; `lldaptest` = in-memory fake (HTTP + LDAP) |
| `internal/invite` | Client for core's one-time invite API (contract §9.4) |
| `internal/directory` | Users & groups service: guardrails, onboarding (invite / password fallback), audit log (`audit.jsonl`) |
| `internal/httpapi` | Handlers (`directory.go`: `/api/directory/*`, `/api/portal/apps`), proxy-secret middleware, CSRF guard |
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
- Lifecycle ops record their outcome in `<data>/ops/<id>.json` (`finishOp`; secret-looking env values redacted) and fail as `*hub.OpError` → JSON `{error, op, output, hint, rolled_back}`. A failed enable compose up is rolled back (`down --remove-orphans`, volumes kept): no half-created project may stay behind to trip the deny/drift.
- Compose files, in order: template `compose.yml` (read-only, never written by the Hub), Hub override `<data>/overrides/<id>.override.yml` (always regenerated in `composeUp`), custom override `<data>/overrides/<id>.user.yml` (Expert; validated on save and before every up). The custom override may never set `traefik.*`/`com.docker.compose.*` labels, networks, namespaces or privileges, may bind-mount only `./templates/<id>/` and paths under `HUB_OVERRIDE_BIND_ROOTS` (default `/srv:/mnt:/media`, validated in `New`), and may contain no unescaped `$` anywhere (compose interpolates after our checks; `$$` = literal) (`useroverride.go` allowlist) — routing is computed from the template alone, so it must stay that way; its host ports count in the port checks.
- No migration/back-compat code: there are no installs to upgrade from.
- Frontend is vanilla JS in `web/index.html` — no build step, no npm. Escape everything with `escapeHtml`.
- Templates come from git sources (`state.yaml` `sources`), not the local filesystem.
- The image runs as uid/gid 10001; `/data` and the host's `<core>/templates` must be writable by it.
- Users & groups (contract §9): LLDAP credentials come only from files (`HUB_LLDAP_CREDENTIALS_DIR`), never env vars; without them the Users page is disabled and nothing else changes. Passwords are set over LDAP (Password Modify ext op) because LLDAP's HTTP password flow is client-side OPAQUE. Never log, audit or put in errors a password, token or invite link. Guardrails live in `internal/directory`: the service account and the bootstrap `admin` are untouchable by every user-targeting operation (`checkTarget`; `TestProtectedAccountsParity` reflects over `Service` methods, so a new operation must be added there); administrators (members of `ProtectedGroups`: `lldap_admin`, `lldap_password_manager`, `INVITE_PROTECTED_GROUPS`, group-gate's core-subdomain groups — the same set core's invite API refuses) get no invites from the Hub (`./portcullis invite <user>` on the server; a 409 from core says so too); passwords / passkey resets for another administrator need the name typed and are flagged in the audit; no self-delete; last human `lldap_admin` member stays. and every mutation is audited with the `X-Forwarded-User` actor (refused without one).
- Users & groups permissions (`internal/directory/authz.go`): every mutating `Service` method takes a `*Caller` built once per request by `CallerFor` (httpapi `s.caller`); `run` re-checks it inside the lock (`gate`) and audits refusals as `refused`. Admin = member of `lldap_admin` (re-checked per mutation). Delegated permissions (`directory.yaml` `permissions`: perm → group): `edit_details` (UpdateUser), `invite` (CreateUser by invite with no groups, SendInvite), `remove` (DeleteUser); everything else is admins only (403). Delegates never target themselves, the protected accounts, administrators, or members of any permission group (403); a delegate's new account must have no Keycloak credential of any type, and a delegate re-invites (SendInvite) only accounts in `created_by` that still have zero Keycloak credentials (Keycloak missing/failing → refused); they can't create a tombstoned name or one still named in exceptions/expiries. Residual: client certificates aren't Keycloak credentials and the Hub can't see them, so a delegate-created account an admin later gives only a client certificate still looks keyless — admins should re-invite such accounts themselves. An admin's SetPassword, SendInvite, RemovePasskeys or RequirePasskey clears the account's `created_by` (saved first; fail → 503), so delegates can't re-invite an account an admin has taken over (covers LLDAP passwords, which Keycloak doesn't count). DeleteUser saves only the tombstone (`deleted`) BEFORE deleting in LLDAP (save fails → 503, nothing deleted) and purges the name from exceptions, expiries and `created_by` only AFTER the LLDAP delete succeeded (a failed delete leaves them in force; a failed purge is a warning + `purge=FAILED` in the audit). An admin's CreateUser purges leftovers naming the new account (warning lists them) and clears its tombstone. A delegate's CreateUser records `created_by`. Emails are unique across LLDAP users (409, case-insensitive).
- Onboarding is a one-time invite link by default (core's invite API); passwords are an advanced fallback.
- Per-app policy is capability-aware (`internal/hub/access.go`): forward-auth/header-auth enforce mtls+webauthn per request, native-oidc at login (acr; per connection only with protected@file), mtls only mtls (always, even under a public default), custom/public nothing ("handles its own sign-in", public@file). TLS tier and acr come from the resolved policy (configured ∩ supported); overrides with unsupported factors are a 400. `password` is no factor: refused by the API, stored policies naming it are rewritten by `policy.Normalize` (never weaker) and flagged in the view.
- `auth.native_login` (custom only): sign-in mode in `state.yaml` `sign_in`; default = Portcullis sign-in, the override prepends `portcullis-auth@docker,portcullis-groups@docker` to every router; `native` (only with `allow_without_gateway`) = template's middlewares without them, public@file, no group published. Router middlewares of such apps are exposure labels (drift); mode changes are audited (`app.sign_in`). Never edit the template for this.
- `portal-apps.json` (contract §10) is written with the policy file; keep both in `WritePolicy`.
- Pin GitHub Actions by full commit SHA (`# vX.Y.Z` comment) and base images by digest.

## Related Repos

| Repo | Purpose |
|------|---------|
| `porelli/portcullis` | Core stack (Traefik, Keycloak, LLDAP, group-gate, CLI) |
| `porelli/portcullis-templates` | Default app marketplace (`TestRealTemplates` loads a sibling checkout if present) |
| `porelli/portcullis-docs` | Documentation site, incl. the integration contracts |
