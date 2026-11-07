# Integration Contracts

Portcullis is split across four repositories that meet at a few well-defined interfaces. This page is the **single source of truth** for those interfaces. Change it first, then change the repos on both sides.

| Repo | Role |
|------|------|
| `porelli/portcullis` (core) | Compose stack, `./portcullis` CLI, group-gate, enroll, socket proxies |
| `porelli/portcullis-hub` | Hub image (`ghcr.io/porelli/portcullis-hub`) |
| `porelli/portcullis-templates` | App templates (public; accepts outside contributions) |
| `porelli/portcullis-docs` | This site |

## 1. Versions and releases

- **Tags.** Every repo uses semver tags `vMAJOR.MINOR.PATCH`. A breaking change to any contract on this page bumps MAJOR in every repo it affects.
- **Hub image.** It is published as `X.Y.Z`, `X.Y`, `X` and `sha-<short>` for tags, and `edge` for `main`. Each release image is signed with cosign (keyless, GitHub OIDC) and carries SBOM and provenance attestations. There is **no `latest` tag**.
- **Core pins the Hub.** On core `main` the `HUB_IMAGE` default is `ghcr.io/porelli/portcullis-hub:edge`. A core **release** must pin a released Hub tag by digest, e.g. `ghcr.io/porelli/portcullis-hub:1.4.0@sha256:…`; `release.yml` refuses to publish otherwise (the tag must be a published Hub release that still resolves to that digest). Operators override it in `.env` and should pin tag + digest in production.
- **Core releases** carry a `CHANGELOG.md` section (Keep a Changelog) and a reproducible tarball with `VERSION` and its sha256; `portcullis version` reports the core version and the Hub image in use.
- **Core pins its own images.** Every image in core's `docker-compose.yml` is `tag@sha256:…`; core CI fails on an unpinned one.
- **Templates pin core.** The templates CI tests against the core ref in `.core-ref` in the templates repo: a tag, or `main` during development.
- **Templates pin their images.** Every template image is `tag@sha256:…` (enforced by `tests/validate.py`); Dependabot proposes updates.
- **Templates are versioned by tag.** The Hub tracks the source's default branch.
- **Template contract v3** (§13 Settings, §4.1 user-attributes v2, §5.1 `/api/me/apps`, §6 exec stdin and kill, §8 per-client setting mappers) is a MAJOR bump.
- **Shared folders** (§13.15 the `path` option's `folder` block, `checks` and `ports[].lan_only`; the `folder:<id>` value form; §6 the folder fixer; §14) add optional fields to template contract v3: a MINOR bump. A Hub without them refuses `folder` and `checks` (reserved fields, §13.2) and ignores `lan_only`, so a template that uses them lands only after a Hub that implements §14 is published (`edge`): merge order docs → Hub → templates → core.
- **File sharing** (§13.2 the `person_secret` and `person_id` types, §13.7 `tsv` data files, §13.8 the `credential_change` trigger and hook reports, §13.16 per-person credentials and ids, §13.17 the file-sharing templates; §3 router-less `custom` templates and `PORTCULLIS_LOCAL_NETWORKS`; §5.1 the credential routes; §6 the `hub_secrets` mount; §10 url-less portal entries; §11.5 / §11.6 credentials outside backups) add optional fields to template contract v3: a MINOR bump. A Hub without them refuses `person_secret` and `person_id` (reserved types), so the templates that use them land only after a Hub that implements them is published (`edge`): merge order docs → Hub (wait for `edge`) → templates (`.core-ref` back to `main`) → core (whose file-sharing e2e needs Hub `edge` and templates `main`).
- **AI support** (§3.2 the `ai:` block, required in every template; §3.1 the AI instance variables; §2 `PORTCULLIS_MCP_GATE_IP`; §4 the core host `mcp` and the gate files; §5 the MCP routers; §5.1 the AI and confirmation routes; §6 split exec output; §8 AI clients and `mcp:*` scopes; §9.5 `via` / `client`; §11 AI state; §13.8 the `ai` trigger; §14.5 the AI doctor kinds; §15) is part of template contract v3. A Hub with it refuses a template without an `ai:` block, so every template gets its block in the same change that makes the validators require it. Merge order docs → Hub (wait for `edge`) → templates (`.core-ref` back to `main`) → core (the Hub may list the core names `mcp-gate`, `mcp_gate_data` and `mcp` before core has them: its core-names check is one-directional, core ⊆ Hub; core's AI e2e needs Hub `edge`).
- **Current state.** No repository has a release tag yet: `HUB_IMAGE` defaults to `edge` and `.core-ref` is `main`.

## 2. Core environment variables available to templates

When a template's `compose.yml` references a variable, the Hub copies its value into the app's env from `/project/.env`. That file is **not** the core `.env`: core generates it as `secrets/hub/core.env` on every `./portcullis up`, with only the variables below, `PORTAL_DISPLAY_NAME`, the `HEADSCALE_*` / `HEADPLANE_*` / `NETBIRD_*` / `COTURN_*` variables, and any names the operator lists in `HUB_SHARED_ENV` (core secrets are refused). Templates may rely on:

| Variable | Meaning |
|----------|---------|
| `PORTCULLIS_DOMAIN` | Main (base) domain. Core hosts live at `<sub>.${PORTCULLIS_DOMAIN}` (e.g. Keycloak at `auth.${PORTCULLIS_DOMAIN}`). A contract v2 template uses it only for core hosts, never for its own hostnames (§3.1) |
| `PORTCULLIS_PROXY_SUBNET` | Subnet of the `portcullis-proxy` network (default `172.31.250.0/24`) |
| `PORTCULLIS_PROXY_IP_RANGE` | Dynamic allocation range (default `172.31.250.128/25`) |
| `PORTCULLIS_TRAEFIK_IP` | Traefik's static IP on `portcullis-proxy` (default `172.31.250.2`). The **only** peer allowed to send identity headers to an app |
| `PORTCULLIS_MCP_GATE_IP` | **NEW (AI support).** `mcp-gate`'s static IP on `portcullis-proxy` (default `172.31.250.3`: inside `PORTCULLIS_PROXY_SUBNET`, outside `PORTCULLIS_PROXY_IP_RANGE`, never equal to `PORTCULLIS_TRAEFIK_IP`; `./portcullis` refuses anything else). The only peer that calls companions (§15). It sends identity headers only to an `identity_headers` companion, together with the caller secret the companion must check (§15.5); an app never trusts identity headers from it |
| `PORTCULLIS_MCP_SUBNET`, `PORTCULLIS_MCP_IP_RANGE` | **NEW (AI support).** The internal network `portcullis-mcp` (`internal: true`; default `172.31.253.0/28`, dynamic range `172.31.253.8/29` = the gate's own address). Its members are exactly `mcp-gate`, `keycloak` and `hub`; the gate is on `portcullis-proxy` and `portcullis-mcp` only (never `portcullis`). |
| `PORTCULLIS_MCP_KEYCLOAK_IP`, `PORTCULLIS_MCP_HUB_IP` | **NEW (AI support).** Keycloak's and the Hub's pinned addresses on `portcullis-mcp` (defaults `172.31.253.2`, `172.31.253.3`). The gate maps `keycloak` and `hub` to them through `extra_hosts` (its URLs keep the names, so `Host` is unchanged) and never resolves them through DNS; the Hub's `:8890` is reachable on `portcullis-mcp` too. `./portcullis init / up / upgrade / restore / status` refuse (`status --json` key `dns_shadows`) any container on `portcullis-proxy` that isn't one of the core project's own containers (`docker compose ps`) yet answers to a core service name; a docker error there fails closed. |

Always use the default form, e.g. `${PORTCULLIS_TRAEFIK_IP:-172.31.250.2}`. Any other required variable must be declared in the manifest's `env:` with `generate: random`. The Hub writes those into the per-app `.env`.

**NEW (contract v2):** the Hub also writes instance-scoped variables into every instance's `.env`: `PORTCULLIS_INSTANCE`, `PORTCULLIS_HOST_<ROUTER>`, `PORTCULLIS_OIDC_CLIENT_ID`, `PORTCULLIS_OIDC_CLIENT_ID_<KEY>`, `PORTCULLIS_ACCESS_GROUP` and `PORTCULLIS_ADMIN_GROUP` (§3.1). They don't come from `core.env` and templates don't declare them in the manifest. For shared folders (§13.15, §14) it also writes `PORTCULLIS_FOLDER_GID_<KEY>` and `PORTCULLIS_FOLDER_UID_<KEY>` for every `path` option; the whole prefix `PORTCULLIS_FOLDER_` is reserved. Every instance's `.env` also carries `PORTCULLIS_LOCAL_NETWORKS` (§3.1), which LAN-only templates read (§13.17). **NEW (AI support):** templates with `ai.mcp` also get `PORTCULLIS_AI_ENABLED` and `PORTCULLIS_AI_READONLY_<COMPANION>`, and `ai-chat` instances the provider variables `PORTCULLIS_AI_PROVIDER_<NAME>_<FIELD>` (§3.1, §3.2).

## 3. Template layout

- **Location.** One directory per app at the root of a template source repo: `<app-id>/manifest.yaml` and `<app-id>/compose.yml`. The `<app-id>` must match `^[a-z0-9]+(-[a-z0-9]+)*$` and be at most 64 characters: letters and digits joined by single `-` (no `_`, no `--`, no trailing `-`), and no `-`-separated segment may be `portcullis` (case-insensitive). This is the Hub's id shape check (`CheckIDShape`): an id must be its own Traefik-normalised form, so two ids never give the same automatic Traefik name (`<service>-portcullis-<id>`). The Hub skips a template whose id fails it.
- **Manifest schema.** Manifests must validate against `schema/manifest.schema.json` in the templates repo (JSON Schema 2020-12). The Hub enforces the same rules and skips templates that fail.
- **Compose invocation.** The Hub runs one compose project per **instance** (§11): `docker compose -p portcullis-<instance-id> -f <template>/compose.yml [-f <data>/overrides/<instance-id>.override.yml] [-f <data>/overrides/<instance-id>.user.yml] --project-directory <core host path> --env-file <data>/env/<instance-id>.env up --no-start --no-deps` (create, pulling images; the image-label check below runs on the created containers), then the same with `up -d --no-deps --pull never` (start exactly the images that were checked), and `down --remove-orphans`; volumes are removed only by a guarded delete, §11.4. The default instance's id is the template id, so for it this is exactly `portcullis-<app-id>`, `<app-id>.override.yml` and `<app-id>.env`. The template's `compose.yml` is read-only to the Hub. The second file is the Hub's override, regenerated from Settings before every `up`. The third is the operator's custom override (Hub Expert tab), stored outside the template clone; it is validated against the template and may not set `traefik.*` or `com.docker.compose.*` labels, `networks`, `network_mode`, `pid`/`ipc`/`uts`, `privileged`, `cap_add`, `devices`, `security_opt`, bind mounts outside `./templates/<app-id>/` and the bind roots (`HUB_OVERRIDE_BIND_ROOTS`, default `/srv:/mnt:/media`), unescaped `$` (compose interpolation) in any key or value, or YAML `!reset`/`!override` tags (full list in [Hub Management](../operations/hub.md#custom-override)). So everything this page derives from a template's labels (routes, hostnames, tiers, middlewares) comes from `compose.yml` and the Hub's override only.

- **Support files.** Files that ship with a template are bind-mounted as `./templates/<app-id>/<file>`. Compose resolves relative paths against the core checkout on the host. Before every `compose up`, the Hub copies the template directory to `<core>/templates/<app-id>/`; core mounts `./templates` read-write into the Hub at `/project/templates`. All instances of a template share this copy, so support files are mounted read-only (`:ro`).
- **Networks.** Frontends join the external network `portcullis-proxy`; internal services join only `default`. A service name on `portcullis-proxy` is ambiguous once a template has two instances, so services address each other only over `default` (Traefik reaches containers by IP, not by name).
- **Volumes.** A `single` template may name a (non-external) volume only inside its own namespace: `name: portcullis_<template-id>`, or a name starting with `portcullis_<template-id>-` or `portcullis_<template-id>_` (without `name:` compose calls it `portcullis-<template-id>_<key>`); any other name — another app's, core's, a bare `portcullis_<key>`, a name outside `portcullis_` — is refused. A `multi` template (§3.1) declares **no** `name:`; the Hub's override sets it (§11.2). A name two templates' default instances (or an instance and a default instance, §11.1) would share — template `a`'s `portcullis_a-b-data` and template `a-b`'s, a `multi` default instance's `portcullis_<key>` — is a name collision: the Hub loads only the first template (enabled ones first, then source order) and refuses such an instance. Core's volume keys (`postgres_data`, `vault_data`, `lldap_data`, `hub_data`, `hub_secrets`, `traefik_acme`, `domains_data`, `mcp_gate_data`, `prometheus_data`, `alertmanager_data`, `grafana_data`: Docker names `portcullis_<key>`) are refused as volume keys and as volume names, and an external volume may not be named `portcullis*` (an external volume without `name:` is named by its key): that is core's or another instance's data. Volume names must be literals. The top-level volume key **`portcullis-hub-secrets`** is reserved for the Hub's override (§6, the per-person secrets mount): the Hub's and the templates repo's validators refuse it as a template volume key, as the source of a service's volume and in `volumes_from`, and the custom override refuses it as a named-volume source. The custom override's top-level volumes may set only `labels` (no `driver`, `driver_opts`, `external` or `name`), so it can declare no external volume at all, `portcullis*` ones included ([Hub Management](../operations/hub.md#custom-override)).
- **Middlewares.** Forward-auth and header-auth routers use `portcullis-auth@docker,portcullis-groups@docker` (on extra-domain hosts the Hub's override renders `portcullis-auth-ext@docker` instead, §5; templates always write `portcullis-auth@docker`). Native-OIDC host-wide routers must not, nor may `mtls`, `custom` or `public` routers. For a `custom` template with `auth.native_login` the Hub's override sets every router's `middlewares` label: `portcullis-auth@docker,portcullis-groups@docker,<the template's own>` (Portcullis sign-in, the default) or the template's own without the pair ("own login only", only with `allow_without_gateway: true`; TLS tier `public@file`, no `groups` entry). The template is never edited.
- **Public exceptions.** A template may declare share-link paths in `auth.public_access` (`enabled_by_default`, `default_mode` `listed|all`, `token_pattern`, `credential_headers`, `credential_cookies`, `credential_query`, `static_extensions`, `service`, `paths[]` with `prefix` (optionally one whole `{token}` segment), `description`, `supporting`, `exact`, `broad` + `justification`); header-auth templates with it also declare `auth.identity_headers`. Fields and rules: [Manifest reference](manifest-reference.md#authpublic_access). The template never ships the public router: the Hub generates it (§5). Router and middleware names starting with `portcullis-public-` are reserved for the Hub.
- **Core names are off limits (NEW, domains).** The Hub rejects a template whose `compose.yml` mentions `forward-auth-ext`, `portcullis-auth-ext` or `portcullis-oauth2-` anywhere (the extra-domain sign-in is rendered by the Hub only, §5), sets `name:` or `external:` on any top-level network other than the `portcullis-proxy` placeholder (key exactly `portcullis-proxy`, `external: true`, `name` absent or exactly `portcullis-proxy`): every other network, `default` included, is project-scoped and may use any key, so a template can't join a core network (`portcullis`, `portcullis-auth`, `portcullis-certs`, …), another instance's `<project>_default` or any foreign network by name, sets `network_mode` to anything but exactly `none`, `host` or `service:<another service of the same template>` (any other value is a network name — `network_mode: portcullis` would put the service on core's internal network, `portcullis-proxy` or another project's network likewise; Docker matches the keywords exactly, so `Host` or ` none` are refused as network names; `container:…` is refused in any case or spacing; `network_mode` together with `networks` is refused), answers to a name ending in `-internal` — a gate's upstream (gated backends sit on the default network only, behind the template's gate) — on any network other than the project's own `default` or a project network the template declares as exactly `{internal: true}` (no other key; both are reachable only from the template's own services, e.g. an `identity_headers` companion's trust network, §3.2) (service name, `container_name` and `hostname` count on every network the service joins, an alias on its network; case-insensitive, trailing dot ignored; a service under `network_mode` has no DNS name of its own), or answers to a core DNS name (service name, `container_name`, `hostname` or a network alias; also as the first label of a dotted name, case-insensitively): every service name of core's `docker-compose.yml` (`traefik`, `socket-proxy-traefik`, `socket-proxy-hub`, `postgres`, `vault`, `lldap`, `keycloak`, `forward-auth`, `forward-auth-ext`, `group-gate`, `hub`, `enroll`, `domains`, `mcp-gate`, `prometheus`, `alertmanager`, `blackbox`, `textfile-exporter`, `grafana`) and compose's container names for them (`portcullis-<service>-<n>`). Core's monitoring `grafana` is included (the Grafana template's compose service is `dashboards`). Network names, external names, `container_name`, `hostname`, `network_mode` and aliases must be literals (no `${…}` / `$VAR`; `$$` is a literal dollar), except that `hostname` may be exactly `${PORTCULLIS_HOST_<ROUTER>:-<sub>.portcullis.local}` (the §3.1 form) for a hostname variable of the template's own host routers, with a default that isn't reserved; compose `include` and service `extends` are refused. The checks run on the decoded YAML (anchors, merge keys, quoting and escapes resolved), and a present value of an unexpected shape (services, networks or a network's configuration that isn't a mapping with string keys) is refused. Also refused: more than one YAML document in `compose.yml` or `manifest.yaml` (any second document, even an empty one: compose merges documents, the checks read one); `container:` in `pid`, `ipc` or `volumes_from`; `ipv4_address` / `ipv6_address` / `link_local_ips` on `portcullis-proxy`; interpolation in any label key or in any `traefik.*` value other than an HTTP router `rule` (the template's own host variables excepted); Traefik label keys with surrounding whitespace or upper case in `traefik.<proto>.<kind>.<name>` (router keys: anywhere); reserved names split by a variable or written with characters that case-fold to them; label keys with non-ASCII characters (Traefik's label decoder compares with Unicode case folding, so `routerſ`, `middlewareſ` or `tlſ` would be read as `routers`, `middlewares`, `tls`); `traefik.*` keys other than `traefik.enable`, `traefik.docker.network` and `traefik.http.<routers|services|middlewares>.<name>.<attribute>`, every part compared case-folded like Traefik's decoder: router attributes `rule`, `entrypoints`, `middlewares`, `service`, `priority`, `tls`, `tls.options`, `observability.*` (no `tls.certresolver` or `tls.domains`: certificates are core's); service attributes only `loadbalancer.server.port`, `loadbalancer.server.scheme`, `loadbalancer.passhostheader`, `loadbalancer.responseforwarding.flushinterval` and `loadbalancer.sticky.cookie[.*]` — a service balances over the labelled container itself, never `server.url` / `servers[n].url` (Traefik would proxy to any address it reaches: the socket proxies, the Hub, Keycloak from the trusted Traefik address), a `serverstransport`, a `weighted` / `mirroring` / `failover` service, or a `healthcheck` (Traefik's own requests, sent from the address core's header-auth services trust, with the template's method and headers, following redirects); middleware types only `addprefix`, `stripprefix`, `stripprefixregex`, `replacepath`, `replacepathregex`, `redirectregex`, `redirectscheme`, `headers`, `compress`, `contenttype`, `chain`, `ratelimit`, `inflightreq` (no `redis.*`), `ipallowlist`, `buffering`, `retry`, `circuitbreaker`, `grpcweb`, each with its own attributes — never `forwardauth`, `errors`, `plugin`, `basicauth`, `digestauth`, `passtlsclientcert`; no `serverstransports`; explicit YAML tags other than the core `!!` ones (compose's `!reset` / `!override`); any `traefik.*` key segment outside `[A-Za-z0-9_-]` with an optional `[n]` (a stray `]` or `[`, or an empty segment, crashes Traefik's label decoder and stops its docker provider) and any name segment outside `^[a-z0-9][a-z0-9_-]*$`; TCP and UDP routing (`traefik.tcp.*`, `traefik.udp.*`); defining a router, service or middleware with a name core uses (core's `@docker` names: `hub`, `keycloak`, `portcullis-auth`, `hub-proxy-secret`, …); a router `service` that isn't a service the template defines itself (`<name>` or `<name>@docker`; never core's, another app's, `@file` or `@internal`), router / chain `middlewares` other than the template's own, `portcullis-auth@docker`, `portcullis-groups@docker` and core's five `@file` middlewares from `traefik/dynamic/middlewares.yml` — `client-headers@file`, `client-cert-pem@file`, `rate-limit@file`, `rate-limit-auth@file`, `security-headers@file` (never an administrator's own objects under `traefik/dynamic/local/`); a reference — router `service`, router `middlewares`, chain `middlewares` — whose key or value isn't lowercase (Traefik reads them case-insensitively, the Hub renames them per instance: both must read the same names); a service name whose container in the template's project (`portcullis-<id>-<service>-<n>`, also `portcullis_<id>_<service>_<n>`) is a core service's (`forward` + `auth` = `portcullis-forward-auth-1`) — for the default instance the template is skipped, for another instance the id is refused; compose keys outside an allowlist (top level: `services`, `volumes`, `networks`, `name`, `x-*`; per service the usual runtime keys — never `label_file`, `deploy`, `annotations`, `env_file`, `build`, `configs`, `secrets`, `profiles`, `links`, …). Templates join core only through `portcullis-proxy`.
- **Image labels.** Docker merges an image's `LABEL`s into its containers' labels. The Hub first runs `compose up --no-start` (containers created, none started) and compares each created container's `traefik.*` label keys (folded like Traefik's decoder) with the keys compose was given (the template's and the Hub override's); any other key takes the project down (volumes kept) and fails the operation (`409`, naming the labels) before anything starts; the same check runs again after the real `up`. Reconcile reports such running containers as exposure drift.
- **Trust model.** A template source is code the admin chose to install: `privileged`, `cap_add`, devices and host networking stay allowed in templates (their own containers). The Hub's checks protect core: routing it can see, no core networks, names or sign-in plumbing, no namespace or volume sharing with other containers. Bind mounts of host paths outside `./templates/<app-id>/` are host-level access, like `privileged`: the Hub doesn't confine them in templates (a template that bind-mounts Docker's volume directory reads core's data), so installing a template source means trusting it with the host. Custom overrides (Expert) are stricter (§5, the allowlist).
- **HTTP routers (NEW, file sharing).** Every auth method except `custom` needs at least one HTTP router: a template without one is refused with a `400` naming the method (a forward-auth template with no router would protect nothing). An `auth.method: custom` template may have **zero** Traefik routers (no service with `traefik.enable: "true"`): a **router-less** template, such as the SMB templates (§13.17). It may then set `group_access: true` with an `access_group` and no `native_login`; the access group decides only who is in the population (§13.3, §13.16) and gates nothing on the network. A router-less instance has no hostnames, publishes no policy, group or denied host (§4), gets no Keycloak client or access role (§8) and no public router, and is never reported as exposure drift. `person_secret` and `person_id` options (§13.2) are allowed only on router-less templates with `group_access: true` and an `access_group`.
- **`auth.notes`** is shown on the portal (§10, as the entry's `note` when the instance has no URL), in the policy view and on the app detail, besides the app's docs page.

### 3.1 Template contract v2: instances and hostname variables — NEW (contract v2)

Contract v2 lets a template run as several independent instances (§11) whose hostnames the admin chooses, on the main domain or on an enrolled domain (§12). The templates repo's schema, `tests/validate.py` and the Hub implement exactly what this section says.

- **`instances`** (manifest, top level): `multi` or `single`; default `single`. The Hub creates instances other than the default one (§11) only for `multi` templates; for a `single` template it refuses with `409` and the reason. A template stays `single` only when it needs host-level uniqueness (e.g. fixed host devices), justified in `auth.notes`. Host ports are no reason: they are per-instance settings with the existing port collision check, so a second instance must pick free ports (or disable them) before it can start.
- **Host routers.** Each hostname a template serves has exactly one **host router**: the router whose rule is a `Host()` alone, with no path matcher. Path-scoped routers on the same hostname (`Host(...) && <path matchers>`, e.g. `vaultwarden-admin`) reuse the host router's variable. A v2 template may not have a hostname without a host router.
- **Hostname variables.** Each host router `<router>` gets the variable **`PORTCULLIS_HOST_<ROUTER>`**: `<ROUTER>` is the template's **original** router name (never the per-instance name of the Traefik-names bullet below) upper-cased, with `-` and `.` turned into `_` (`grafana` → `PORTCULLIS_HOST_GRAFANA`, `litellm-ui` → `PORTCULLIS_HOST_LITELLM_UI`). Two host routers that map to the same variable are an error. The value is the **full hostname**: lowercase, no scheme, port or trailing dot (e.g. `grafana.team-b.example.org`). The Hub writes one variable per host router into every instance's `.env`, the default instance included. The same original router name keys `{{HOST_<ROUTER>}}`, the `hosts` maps of the Hub API (§11.7) and the sign-in router's name (§5).
- **Rule form.** Every router rule of a v2 template is exactly `` Host(`${PORTCULLIS_HOST_<ROUTER>:-<sub>.portcullis.local}`) ``, optionally followed by ` && <path matchers>` (`PathPrefix`, `Path`, or a parenthesised `||` of them, as today). The default value names the template's **default subdomain** `<sub>`, a single DNS label (`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`): the default instance's hostname is `<sub>.<main domain>`, and a new instance's pre-filled hostname is derived from it (§11.3). Each variable is written with the same default everywhere it appears. A template uses one rule form for all its routers: it may not mix this form with the `${PORTCULLIS_DOMAIN}` form of the conversion period.
- **Own hostnames everywhere.** Wherever a v2 template names one of its own hosts (env URLs, `hostname:`, middleware values such as a `redirectregex` replacement), it uses the variable in the same default form, e.g. `APP_URL: https://${PORTCULLIS_HOST_FIREFLY:-finance.portcullis.local}`. Core hosts keep `${PORTCULLIS_DOMAIN}`: `https://auth.${PORTCULLIS_DOMAIN:-portcullis.local}/realms/portcullis`.
- **Manifest placeholders.** `{{HOST_<ROUTER>}}` in `urls[].url` and `keycloak_clients[].redirect_uri` / `redirect_uris` is replaced with the instance's hostname for that host router; `{{DOMAIN}}` stays the main domain. A `multi` template writes its own hosts only as `{{HOST_<ROUTER>}}`. In a `multi` template, `{{DOMAIN}}` in those fields may only form a core host: the URL's host is exactly `<core subdomain>.{{DOMAIN}}` for a core subdomain (§4, e.g. `https://auth.{{DOMAIN}}/realms/portcullis`); the apex `{{DOMAIN}}` alone, any other `<label>.{{DOMAIN}}` (its own hosts included) and anything under a core host are refused at discovery.
- **Instance variables.** The Hub writes these into every instance's `.env` too. Templates use them instead of hard-coding the values, always in the default form with the **default instance's** value (e.g. `${PORTCULLIS_ACCESS_GROUP:-users_grafana}`):

    | Variable | Value |
    |----------|-------|
    | `PORTCULLIS_INSTANCE` | The instance id (§11.1); the template id for the default instance |
    | `PORTCULLIS_HOST_<ROUTER>` | The instance's full hostname for that host router |
    | `PORTCULLIS_OIDC_CLIENT_ID` | Keycloak client id of the first `keycloak_clients` entry for this instance (§11.2); empty without clients |
    | `PORTCULLIS_OIDC_CLIENT_ID_<KEY>` | The same for **every** entry; `<KEY>` is the entry's manifest `client_id` upper-cased with `-` and `.` turned into `_` (headscale: `PORTCULLIS_OIDC_CLIENT_ID_HEADSCALE`, `PORTCULLIS_OIDC_CLIENT_ID_HEADPLANE`). Two entries whose `client_id`s map to the same `<KEY>` are an error |
    | `PORTCULLIS_ACCESS_GROUP` | The instance's access group (§11.2); empty if the manifest has no `access_group` |
    | `PORTCULLIS_ADMIN_GROUP` | The instance's admin group (§11.2); empty if the manifest has no `admin_group` |
    | `PORTCULLIS_LOCAL_NETWORKS` | **NEW (file sharing).** The Hub's Local networks (§14.7) as comma-separated canonical CIDR prefixes, from `LocalNetworksView()`: the saved list, or `DefaultLocalNetworks` (`10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7,100.64.0.0/10`) when none was saved. Empty **only** when an empty list (`[]`, loopback only) was saved; a template that reads it must then refuse to serve (fail closed, §13.17). Written in every `.env` write (`prepareUp`) |
    | `PORTCULLIS_AI_ENABLED` | **NEW (AI support).** `true` while at least one of the instance's companions has AI support on (§15), else `false`. Written only for templates with `ai.mcp` (§3.2) |
    | `PORTCULLIS_AI_READONLY_<COMPANION>` | **NEW (AI support).** Per companion: `true` unless the companion is on in mode `read_write`. `<COMPANION>` is the companion's `name` upper-cased with `-` turned into `_` (`gitea` → `PORTCULLIS_AI_READONLY_GITEA`). Written only for templates with `ai.mcp` |
    | `PORTCULLIS_AI_PROVIDER_<NAME>_<FIELD>` | **NEW (AI support).** Only in the `.env` of an instance whose template has `ai.chat` (§3.2), one per secret field of each model provider the instance selected; never referenced by a template (§3.2) |

    These names are reserved: a manifest may not declare them in `env`, `settings` or `ports` (**NEW, AI support:** the prefixes `PORTCULLIS_AI_` and `PORTCULLIS_AI_PROVIDER_` and the core variable `PORTCULLIS_MCP_GATE_IP` too). A template may reference `PORTCULLIS_AI_ENABLED` only as exactly `${PORTCULLIS_AI_ENABLED:-false}` and `PORTCULLIS_AI_READONLY_<COMPANION>` only as exactly `${PORTCULLIS_AI_READONLY_<COMPANION>:-true}` for one of its own companions (the defaults fail closed), and never references `PORTCULLIS_AI_PROVIDER_*` (§3.2, `ai.chat.env`). `PORTCULLIS_LOCAL_NETWORKS` is the one exception to the default form: compose may reference it **only** as exactly `${PORTCULLIS_LOCAL_NETWORKS}`; every form with a default or alternate (`${PORTCULLIS_LOCAL_NETWORKS:-…}`, `-`, `:+`, `+`, `?`) and `$PORTCULLIS_LOCAL_NETWORKS` are refused, so no template default can widen `hosts allow`. Saving Local networks (`PUT /api/settings/local-networks`) queues a restart of every enabled instance whose `compose.yml` references the variable (found at discovery), and only of those.
- **`multi` templates also** have no `${PORTCULLIS_DOMAIN}` in any router rule, no volume `name:` (the Hub sets it, §11.2), and no hard-coded Keycloak client id or group name in `compose.yml` (they use the variables above). Router, service and middleware names a template defines may not start with `portcullis-` (reserved for core and the Hub) and may not contain `_` (every v2 template, so the per-instance prefix below can't be ambiguous).
- **Traefik names per instance.** Traefik's Docker provider merges same-named routers and services across containers, so two instances must never define the same name. For every instance **except the default one**, the Hub's override renames each router, service and middleware the template's labels define from `<name>` to `<instance-id>_<name>`. It also rewrites the references to them in `routers.*.service` and `routers.*.middlewares` (`<name>@docker`). Names the template doesn't define (`portcullis-auth@docker`, `security-headers@file`, …) are kept. The override replaces each labelled service's `labels` with compose's `!override` tag, so no original name survives. Neither instance ids nor v2 template names contain `_`, so the prefix can't be ambiguous. The default instance keeps the template's names unchanged. Every name an instance's Traefik objects use is a name claim (§11.1): two templates whose default instances define the same router, service or middleware name are not both loaded (enabled templates first, then source order), since Traefik would merge them and one app would receive the other's traffic, forward-auth identity headers included.
- **Conversion period.** Until every template is converted, the Hub sets `PORTCULLIS_HOST_*` for every instance (default included). An `instances: single` template may still use `` Host(`<sub>.${PORTCULLIS_DOMAIN:-portcullis.local}`) `` rules. Such a template runs only as its default instance, its hostnames are fixed at `<sub>.<main domain>`, and the Hub refuses hostname changes for it (`409`). Its host keys are still its host routers' names. It uses that form for all its routers (no mixing).

Example (`grafana`, contract v2):

```yaml
# manifest.yaml (excerpt)
instances: multi
auth:
  method: header-auth
  group_access: true
  access_group: users_grafana     # the default instance's group
urls:
  - label: Dashboards
    url: "https://{{HOST_GRAFANA}}"
```

```yaml
# compose.yml (excerpt)
services:
  dashboards:                     # not grafana: core's monitoring service name is reserved (§3)
    environment:
      GF_SERVER_ROOT_URL: https://${PORTCULLIS_HOST_GRAFANA:-grafana.portcullis.local}
    volumes:
      - grafana-data:/var/lib/grafana
    labels:
      traefik.enable: "true"
      traefik.http.routers.grafana.rule: Host(`${PORTCULLIS_HOST_GRAFANA:-grafana.portcullis.local}`)
      traefik.http.routers.grafana.entrypoints: websecure
      traefik.http.routers.grafana.tls.options: public@file
      traefik.http.routers.grafana.middlewares: portcullis-auth@docker,portcullis-groups@docker,security-headers@file
      traefik.http.services.grafana.loadbalancer.server.port: "3000"
volumes:
  grafana-data: {}                # no name: the Hub sets it per instance
```

For the instance `grafana-team-b` on `grafana.team-b.example.org`, the Hub writes `PORTCULLIS_INSTANCE=grafana-team-b`, `PORTCULLIS_HOST_GRAFANA=grafana.team-b.example.org`, `PORTCULLIS_ACCESS_GROUP=users_grafana-team-b`, `PORTCULLIS_ADMIN_GROUP=admin_grafana-team-b` and `PORTCULLIS_OIDC_CLIENT_ID=` (no clients) into `<data>/env/grafana-team-b.env`. Its override renames the router and the service to `grafana-team-b_grafana`, renders the router's middlewares as `portcullis-auth-ext@docker,portcullis-groups@docker,security-headers@file` (an extra-domain host, §5), adds the sign-in router `portcullis-oauth2-grafana-team-b_grafana`, and names the volume `portcullis_grafana-team-b-grafana-data`.

### 3.2 AI support: the `ai:` block — NEW (AI support)

Every template says in its manifest whether the AI can act in the app, and how (§15). The templates repo's schema, `tests/validate.py` and the Hub's `ValidateAI` implement exactly what this section says, with the same refusals; the Hub skips a template that fails them.

- **Required, in exactly one of two forms.** A template without an `ai:` block, with both forms or with neither is refused:
    - `ai.mcp`: a non-empty list of **companions**, the MCP servers the AI talks to (below);
    - `ai.unsupported`: one sentence (a single line, 1–200 characters) shown to the admin on the instance's AI tab and in the catalog, e.g. `"No official MCP server; community servers are small and not vetted by Portcullis"`.
- **`ai.alternative`** `{name, source, note}`, only with `ai.unsupported`: a community server the admin may evaluate on their own. `name` a single line ≤ 64, `source` an `https://` URL, `note` a single line ≤ 200 (e.g. `"community, 248★, last change Nov 2025, API token per person"`). The Hub only displays it, labelled "not vetted by Portcullis", and never installs it.
- **Companions are never Portcullis code.** A companion is the app's built-in MCP server (`kind: builtin`) or a service running the upstream's published image (`upstream: official`) or a vetted community project's published image (`upstream: community`), pinned `tag@sha256:…` like every template image (§1). Templates never build images (`build` is refused, §3) and never ship MCP server, adapter, wrapper or proxy code; template review refuses one written for Portcullis, inside or outside the template repo. "Vetted" means a template reviewer checked the project (maintained, licence, a multi-user identity that fits an identity mode, no shared admin identity) and pinned a release; the template's docs page records why. Mint and revoke hooks (below) are glue that calls the app's own CLI or API; they never see tool traffic and define no tools.
- **`ai.mcp[]`**, one entry per companion:

    | Field | Rule | Meaning |
    |-------|------|---------|
    | `name` | `^[a-z][a-z0-9]*(-[a-z0-9]+)*$`, at most 31 characters, unique in the template (no `--`, no trailing `-`) | Names the companion: scope `mcp:<instance-id>.<name>`, alias and router `portcullis-mcp-<instance-id>--<name>`, `PORTCULLIS_AI_READONLY_<NAME>` |
    | `label` | single line, 1–64 | The **companion label**: the resource's `label` (§15.4), its RFC 9728 `resource_name`, the aggregate's description prefix and the gate's messages ("Preparing your access to <label>…"). The consent text and the confirmation page's typed check use the **instance label** instead (§8, §15.6) |
    | `kind` | `companion` or `builtin` | `companion`: a compose service that exists only for AI. `builtin`: the app's own service serves MCP |
    | `service` | a service of `compose.yml` whose name matches `^[a-z0-9]+(-[a-z0-9]+)*$` | Where MCP is served (either kind; the same shape as instance ids: no `_`, no `--`, no trailing `-`). A `companion` service backs exactly one companion |
    | `port` | 1–65535 | The container port of `service` (unused for `app_oauth`) |
    | `path` | absolute, clean, no `?` / `#`; default `/mcp` | The upstream's MCP path |
    | `router` | a host router of the template (§3.1) | The companion's endpoint is on this router's hostname: `https://<host><public_path>` |
    | `public_path` | absolute, clean; default `/mcp` | The path people connect to. Not `/`, never at or under `/.well-known/` or `/oauth2/`, never at or under (or above) a path of `auth.public_access`, never at, under or above another companion's endpoint path on the same router (its `public_path`, or an `app_oauth` companion's `path`). Refused on `app_oauth` companions (the endpoint is then the app's own route `https://<host><path>`, which the Hub doesn't route) |
    | `identity` | object, below | How the person's identity reaches the companion |
    | `modes` | non-empty subset of `read_only`, `read_write`, no repeats | What the admin may choose. `app_oauth`: exactly `[read_write]` |
    | `default_mode` | one of `modes` | Required when `modes` has two entries |
    | `tools` | `{writes, confirm, never}`, each a list (≤ 256) of patterns | Tool classes (§15.5): patterns are tool names with `*` globs, or `tool:method` for consolidated tools (matches `tool` when its argument `method` equals `method`); `^[A-Za-z0-9_.*-]{1,128}(:[A-Za-z0-9_.*-]{1,128})?$`, matched case-insensitively |
    | `aggregate` | boolean, default `true` | Whether the companion's tools are in "all my apps" (§15.9). `app_oauth`: never (`true` is refused; the default becomes `false`) |
    | `upstream` | `official` or `community` | Shown to the admin ("community-maintained companion"). `builtin` ⇒ `official` |
    | `source` | `https://` URL, required | The companion project's home |
    | `protocol` | non-empty list of `2025-06-18`, `2025-11-25`, `2026-07-28` | The MCP versions the companion speaks; the gate speaks the newest common one upstream (§15.3) |

- **`identity`** (`mode` plus that mode's parameters only; any other key is refused):

    | `mode` | Parameters | Meaning |
    |--------|------------|---------|
    | `app_token` | `header` (an HTTP header name, default `Authorization`); exactly one of `format` (`^[A-Za-z][A-Za-z0-9-]{0,31} \{credential\}$`, e.g. `"token {credential}"`, `"Bearer {credential}"`) and `basic` `{user, password}` (HTTP Basic: `user` exactly `{username}` or a single-line literal without `:`, `{` or `}`; `password` exactly `{credential}`); `mint` and `revoke` (hook names, required); `scopes` `{read_only: [...], read_write: [...]}` (optional; keys from `modes`; each a list of single-line strings ≤ 128) | A per-person app credential, minted by the Hub through the `mint` hook on first use and injected by the gate on every request (§15.5) |
    | `identity_headers` | `caller_secret` `{env, header, format}`, required: `env` an `env` entry with `generate: random`, `header` an HTTP header name (default `Authorization`), `format` containing `{secret}` exactly once (default `"Bearer {secret}"`, `^[A-Za-z][A-Za-z0-9-]{0,31} \{secret\}$` or exactly `{secret}`) | The gate sends the person's identity headers plus the caller secret; the companion must refuse every caller without the secret |
    | `app_oauth` | `revoke` (hook name, required) | The app is its own MCP authorization server (signing in through Keycloak); the gate is not in the path. Only `kind: builtin`, `modes: [read_write]`, never aggregated |

    A `header` is `^[A-Za-z0-9-]{1,64}$` and never `Host`, `Cookie`, `Content-Type`, `Accept`, `Proxy-Authorization`, the hop-by-hop and framing headers (`Content-Length`, `Transfer-Encoding`, `Connection`, `Keep-Alive`, `TE`, `Trailer`, `Upgrade`, `Proxy-Connection`), `Mcp-*`, `MCP-Protocol-Version`, `Mcp-Session-Id`, `X-Forwarded-*`, `X-Auth-Request-*`, `Remote-*` or `X-Portcullis-*` (case-insensitive). No mode runs requests as one shared admin identity.
- **`ai.on_change`** (a hook name, only with `ai.mcp`): run when a companion's AI support or mode changes, with the stdin of §15.5 (e.g. to turn an app's own MCP integration on or off). Optional: `PORTCULLIS_AI_ENABLED` / `PORTCULLIS_AI_READONLY_<COMPANION>` (§3.1) often suffice.
- **Hooks an `ai:` block names** (`mint`, `revoke`, `on_change`) must exist, have exactly `when: [ai]` (§13.8) and run on a service that isn't a `kind: companion` service (a companion is at `scale: 0` while off, and `revoke_all` runs before every switch-on); a hook with `ai` that no `ai:` field names is refused.
- **`ai.chat`** (only with `ai.unsupported`): the template is an AI page, an MCP client people chat in (the `ai-chat` template), not an app the AI drives. Fields, all required:
    - `provider_kinds`: `{<kind>: one|many}` for the model provider kinds the template can render (`litellm`, `openai_compatible`, `anthropic`, `openai`, `google`, `bedrock`, `azure_openai`; at least one). `one`: at most one provider of that kind per instance;
    - `file: {service, mount}`: the service that reads `ai-providers.json` (below) and the absolute, clean container directory it is mounted at read-only (the rules of a `files[]` mount, §13.7);
    - `env: {service}`: the one service whose environment receives the selected providers' secret variables (§15.12). The Hub's override adds `environment: {<VAR>: ${<VAR>}}` for each of them to that service only; compose `env_file` stays refused (§3).

    A template with `ai.chat` has exactly one `keycloak_clients[]` entry with `ai_client: true` (§8; refused without `ai.chat`); its other clients are ordinary. The data file name `ai-providers` is reserved (`files[]` may not use it).
- **Also refused** (the Hub at discover, `tests/validate.py` alike):
    - `ai.mcp` on a template with `auth.admin_paths` (the gate can't apply path groups), with `auth.method` `public` or `mtls` (no Portcullis identity, or LoA 3: §15.2), or on a router-less template (§3);
    - a companion `service` (either kind) whose name doesn't match `^[a-z0-9]+(-[a-z0-9]+)*$`; a `companion` service with any `traefik.*` label, on `portcullis-proxy` itself, with `network_mode`, `container_name`, `hostname`, host `ports` (the gate is its only way in), or used by two companions; any service with `network_mode: service:<a companion service>` (it would share the companion's network namespace); an `identity_headers` `caller_secret.env` that isn't a `generate: random` env entry; an `identity_headers` companion without a **trust network** (below); `upstream: community` with `kind: builtin`;
    - the prefix **`portcullis-mcp-`** (case-insensitive) anywhere in `compose.yml` — a Traefik router, service or middleware name, a compose service name, `container_name`, `hostname`, a network alias on any network, or any other key or value (the Hub's override owns it);
    - a `keycloak_clients[].client_id` starting with `portcullis-ai-` (the Hub's AI clients, §8);
    - `mcp` as a default subdomain (a core host, §4);
    - any reference to `${PORTCULLIS_AI_PROVIDER_…}` or `$PORTCULLIS_AI_PROVIDER_…` in `compose.yml`, and the AI variables in any other form than §3.1's; a service that sets a `PORTCULLIS_AI_PROVIDER_*` variable itself (an `environment` map key or list item, any case: only the Hub sets them); an `environment` variable name built by interpolation (any `$` in the name); a `${…}` whose default or alternate text contains `PORTCULLIS_AI_` (any case). `PORTCULLIS_MCP_GATE_IP` may be read only in the core default form `${PORTCULLIS_MCP_GATE_IP:-172.31.250.3}` and never declared;
    - for `ai.chat`: an `ai_client` entry without `secret_env` (the AI page's client is confidential), and an `ai.chat.file.mount` that collides with a `files[]` mount on the same service. The `ai-chat` template's client is read as `PORTCULLIS_OIDC_CLIENT_ID_AI_CHAT_MCP` (§3.1). Its renderer refuses an `ai-providers.json` it can't render (for example `per_person` on `azure_openai`) and starts with the welcome text "The AI page's model configuration was refused; ask your administrator"; with no provider it shows "No model provider configured; ask your administrator".
- **What the Hub renders** (its override, for every instance; never the template):
    - a `companion` service gets `scale: 0` while its companion is off and `scale: 1` while it is on;
    - while a companion is on (`app_token` and `identity_headers` only), its service joins `portcullis-proxy` with the alias **`portcullis-mcp-<instance-id>--<companion>`** (for a `builtin` service, added to its existing attachment), and the router of §5 is added. Template and instance ids pass the Hub's id shape check (§3, `[a-z0-9]+(-[a-z0-9]+)*`), so they never contain `--`; the first `--` of the alias therefore always ends the instance id and the pair is unambiguous (a single `-` wouldn't be: `a` + `b-c` = `a-b` + `c`). `--` is valid in a DNS label, and companion names and companion services have the same shape (no `--`). The alias is **one DNS label**: `15 + len(<instance-id>) + 2 + len(<companion>) ≤ 63` (`portcullis-mcp-` is 15 characters). The Hub checks it at discover for the default instance (the template id with each companion name: the template is refused, naming the limit), at instance create and restore-as for other instances (`400` naming the limit and the companion) and again at AI switch-on (`409`). Switching on is also refused (`409`) while another container on `portcullis-proxy` already answers to that name;
    - nothing for `app_oauth` companions but `PORTCULLIS_AI_*` and the `on_change` hook: their endpoint is the app's own route;
    - switching a companion on or off on an enabled instance recreates the project (`compose up`): the router labels live on the instance's first `traefik.enable` service, so the app restarts (the answer says `restarts: true`, §15.11). On a disabled instance the switch only saves state.
- **Companions are reachable on `portcullis-proxy`.** Any container on that network can reach a companion by its alias, not only the gate. A companion must therefore serve nothing without the identity mode's credential: the app's own authentication of the minted credential (`app_token`), or the caller secret (`identity_headers`). It never trusts identity headers alone, and the app behind an `identity_headers` companion trusts them only from that companion (template responsibility; a template that can't prove it uses `ai.unsupported`).
- **Trust network (`identity_headers`, kind `companion`).** The companion service joins exactly one network in `compose.yml`, its trust network: a project network other than `default` and `portcullis-proxy`, declared at the top level as exactly `{internal: true}` (no `ipam`, `driver`, `driver_opts`, `enable_ipv6`, `attachable`, `labels`, `name` or `external`: an address plan or a driver option could make the trusted subnet cover other addresses), whose members are exactly the companion service and the service(s) carrying the companion's `router` (the app that trusts the headers). No other service joins it, no service uses `network_mode: service:<a member>` or `pid: service:<a member>` (the companion included), and no service of a template with an `identity_headers` companion (either kind) uses `network_mode: host` (it would send from the host's addresses, the trust network's gateway included) or `pid: host`. The caller secret's variable (`caller_secret.env`) may be interpolated (`${VAR…}`, `$VAR`, nested defaults included) only in the companion's own service. Since the Hub refuses foreign network names (§3), nothing outside the project can join it either, so the app may trust identity headers from that network's addresses: no IP or subnet is pinned, the app reads the prefix from its own interface at start and refuses to start when it is ambiguous — the default route must be on portcullis-proxy and the trust interface must carry only its connected prefix (Grafana: `grafana/portcullis/trust.sh` adds that prefix without its own address — a data source pointing at the app itself —, the bridge gateway — the host's side, which host processes and host-network containers come from; Docker's builtin IPAM's first address — and the network and broadcast addresses to `GF_AUTH_PROXY_WHITELIST`, next to Traefik's). The companion reaches the app by a name ending in `-internal` on the trust network (an exactly `{internal: true}` network, §3): on `portcullis-proxy` the app's service name is shared by every instance.
- **`ai-providers.json`** (the AI page's data file, Hub → template). For an `ai.chat` instance the Hub writes `<appfiles>/<instance-id>/ai-providers/ai-providers.json` (mode 0640, directory 0750, atomic, like the data files of §13.7; delivery unit `file:ai-providers`) and bind-mounts its directory read-only at `ai.chat.file.mount` in `ai.chat.file.service`:

    ```json
    {
      "version": 1,
      "instance": "ai-chat",
      "providers": [
        {
          "name": "ollama-gpu",
          "label": "Ollama on the office GPU",
          "kind": "openai_compatible",
          "base_url": "http://gpu.lan:11434/v1",
          "region": "",
          "instance_name": "",
          "api_version": "",
          "deployments": {},
          "models": {"fetch": false, "list": ["llama3.3:70b", "qwen3:32b"]},
          "credentials": "admin",
          "env": {"key": "PORTCULLIS_AI_PROVIDER_OLLAMA_GPU_KEY"}
        }
      ]
    }
    ```

    - one entry per provider the instance selected (§15.12), sorted by `name`; every field always present (`""`, `{}` or `[]` when the kind has no such field); `deployments` maps an Azure deployment to its model; `models.fetch` only where the kind allows it (`litellm`, `openai_compatible`, `openai`);
    - `credentials` is `admin` or `per_person` (each person enters their own key in the chat app; the Hub stores none);
    - `env` maps each of the kind's secret fields whose value is set to the **name** of the variable that holds it (`PORTCULLIS_AI_PROVIDER_<NAME>_<FIELD>`, §15.12); `{}` for `per_person`. The file **never** holds a secret value. The template renders its own configuration from it (the `ai-chat` template's `config` init service writes `librechat.yaml` with env references such as `apiKey: "${PORTCULLIS_AI_PROVIDER_OLLAMA_GPU_KEY}"`), so no secret is written into a file either.

Example (`gitea`, abridged; hooks in §13.8):

```yaml
# manifest.yaml (excerpt)
ai:
  mcp:
    - name: gitea
      label: Gitea
      kind: companion
      service: gitea-mcp
      port: 8080
      router: gitea                 # https://<gitea host>/mcp
      upstream: official
      source: https://gitea.com/gitea/gitea-mcp
      protocol: ["2026-07-28", "2025-11-25"]
      modes: [read_only, read_write]
      default_mode: read_write
      identity:
        mode: app_token
        format: "token {credential}"
        mint: mcp-mint
        revoke: mcp-revoke
        scopes:
          read_only:  [read:repository, read:issue, read:user]
          read_write: [write:repository, write:issue, read:user]
      tools:
        writes:  ["*_write", "create_*", "update_*", "merge_*", "delete_*"]
        confirm: ["delete_*", "repo_write:delete"]
        never:   []
```

```yaml
# compose.yml (excerpt)
services:
  gitea-mcp:                         # no Traefik labels, not on portcullis-proxy
    image: docker.gitea.com/gitea-mcp-server:<tag>@sha256:<digest>
    environment:
      GITEA_READONLY: ${PORTCULLIS_AI_READONLY_GITEA:-true}
    networks: [default]
```

## 4. Policy file (Hub → group-gate)

The Hub writes `group-gate-policy.json` atomically (temp file + rename) to the `hub_data` volume. group-gate mounts that volume read-only and re-reads the file on every request.

**NEW (policy v5):** the file is `version: 5` and every per-app map is keyed by **full hostname** instead of subdomain, so instances on the main domain and on enrolled domains (§11, §12) each get their own policy. Format:

```json
{
  "version": 5,
  "default":  {"factors": ["mtls", "webauthn"], "op": "any"},
  "extra_domains": ["<enrolled domain>"],
  "policies": {"<hostname>": {"factors": ["mtls", "webauthn"], "op": "any|all"}},
  "groups":   {"<hostname>": "<required LLDAP group>"},
  "path_groups": {
    "<hostname>": [{"prefix": "/admin", "group": "<LLDAP group>"}]
  },
  "public_paths": {
    "<hostname>": {
      "paths": [{"path": "/s/{token}", "match": "prefix"}, {"path": "/dist", "match": "static"}],
      "token_pattern": "^[A-Za-z0-9-]{1,32}$",
      "static_extensions": ["css", "js", "..."],
      "credential_headers": ["Authorization", "Proxy-Authorization"],
      "credential_cookies": ["nc_token"],
      "credential_query": []
    }
  },
  "expiring": [
    {"user": "jsmith", "group": "contractors", "at": "2027-03-31T23:59:59Z"}
  ]
}
```

Example: main domain `portcullis.example.com`, two Grafana instances (`grafana-team-a` on the main domain, `grafana-team-b` on the enrolled domain `team-b.example.org`, its hostname edited to `grafana.team-b.example.org`) and the default instance of Vaultwarden. Core hosts (`portcullis.example.com`, `auth.portcullis.example.com`, `hub.portcullis.example.com`, `people.portcullis.example.com`, …) are **not** in the file: they come from `group-gate-map.conf`.

```json
{
  "version": 5,
  "default": {"factors": ["mtls", "webauthn"], "op": "any"},
  "extra_domains": ["team-b.example.org"],
  "policies": {
    "grafana-team-a.portcullis.example.com": {"factors": ["webauthn"], "op": "any"},
    "grafana.team-b.example.org": {"factors": ["mtls", "webauthn"], "op": "all"}
  },
  "groups": {
    "grafana-team-a.portcullis.example.com": "users_grafana-team-a",
    "grafana.team-b.example.org": "users_grafana-team-b",
    "passwords.portcullis.example.com": "users_vaultwarden"
  },
  "path_groups": {
    "passwords.portcullis.example.com": [{"prefix": "/admin", "group": "admin_vaultwarden"}]
  },
  "public_paths": {
    "grafana-team-a.portcullis.example.com": {
      "paths": [
        {"path": "/public-dashboards/{token}", "match": "prefix"},
        {"path": "/api/public/dashboards/{token}", "match": "prefix"},
        {"path": "/public/build", "match": "static"}
      ],
      "token_pattern": "^[0-9a-f]{32}$",
      "static_extensions": ["css", "js", "svg", "woff2"],
      "credential_headers": ["Authorization", "Proxy-Authorization", "X-Access-Token", "X-Grafana-Id"],
      "credential_cookies": ["grafana_session", "renderKey"],
      "credential_query": ["auth_token"]
    }
  },
  "expiring": []
}
```

- **`factors`** is a subset of `mtls` and `webauthn`; the Hub never writes anything else. There is no `password` factor (no password sign-in exists): group-gate treats it as an unknown factor and **denies** (fail closed). The Hub rewrites stored policies naming it on load, never into a weaker one (`all`: dropped; alternative or alone: `any of [mtls, webauthn]`). `op` is `any` or `all`, and is ignored when there is at most one factor. An empty factor list means public.
- **Unknown values fail closed.** An unknown factor, op or key shape, a file that exists but can't be parsed, or a `version` other than the one group-gate supports (currently 5) makes group-gate deny the request.
- **Version 5** (**NEW**; the Hub always writes 5). group-gate serves **only** version 5 and denies every request on a version-4 (or older) file; a group-gate that knows only version 4 denies every request on a version-5 file. **The Hub and core must be upgraded together.**
- **`expiring`** is unchanged from version 4:
    - an array of `{"user": "<lowercase username>", "group": "<LLDAP group>", "at": "<RFC 3339 UTC timestamp>"}` entries for temporary group memberships. group-gate treats the membership as **absent** once `now >= at`, regardless of what the user's token says. Usernames are lowercase; timestamps are RFC 3339 in UTC (e.g., `2027-03-31T23:59:59Z`).
    - The Hub writes **at most one entry** per `(user, group)` pair: the **earliest** `at` when multiple expiries exist for the same membership.
    - The Hub writes every pending expiry into this array so that expiry enforcement is strict even while the Hub is down. The Hub keeps publishing an expired entry until the membership is actually removed from LLDAP, plus a 10-minute grace period afterwards (cleared on regrant). One exception: the end of an "added" exception of a rule group is not written while the user is a current member, the group's rule matches them and the evaluator keeps them (they stay by rule after the end). Manual expiries and grace entries are always written.
    - **Which removals revoke Keycloak sessions.** The Hub signs the user out of Keycloak (`POST …/users/{id}/logout`) after: every membership the evaluator removes (rule, exception or expiry), an admin's member removal, a group deletion (every former member), and a password change; a user deletion removes the Keycloak copy. OIDC apps then lose access at their next token refresh, forward-auth sessions within about a minute (oauth2-proxy cookie refresh). Core runs Keycloak's LDAP federation with `cachePolicy: NO_CACHE`, so that refresh reads the user's current groups and attributes from LLDAP instead of a cached copy.
    - When group-gate strips an expired membership for a request, it also withholds `Authorization` and `X-Forwarded-Access-Token`. The `portcullis-groups` middleware lists both in `authResponseHeaders` and echoes them to the backend only when the request is allowed.
- **Keys are full hostnames** (**NEW**, policy v5). `policies`, `groups`, `path_groups` and `public_paths` are keyed by the lowercase hostnames that **enabled** instances route, e.g. `grafana.team-b.example.org` — never by template or instance id. A key is a **valid hostname**: at most 253 characters and matching `^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$` (lowercase, at least two labels, no port, no trailing dot, no wildcard). This page uses "valid hostname" in exactly this sense. Any other key shape makes group-gate deny.
- **`extra_domains`** (**NEW**, policy v5): every enrolled domain (§12) the Hub knows, sorted, each a valid hostname. A host equal to or under one of them is an **extra-domain host** (§5); group-gate uses this to build the step-up URL. The Hub writes it from its last known list of enrolled domains (§12.3), so it is never empty just because the domains service is down. A malformed entry makes group-gate deny.
- **Host matching** (**NEW**, policy v5). group-gate takes the request host from `X-Forwarded-Host` (first value), lowercases it, strips a numeric `:<port>` and trailing dots, and looks it up **exactly** (`Grafana-A.Team-A.com.:443` → `grafana-a.team-a.com`). It never falls back to a subdomain-only or parent-domain match: a host with no entry gets `default` and no group, as an unlisted subdomain did before. A host that is not a valid hostname after normalisation is denied, and so is a host Portcullis can't serve: anything that is neither a core host, nor `<label>.<main domain>`, nor an enrolled domain `<d>` or `<label>.<d>` from `extra_domains` (as before, when only `<label>.<main domain>` was served). `extra_domains` entries that are the main domain, a parent of it, a core host or under one (`x.hub.<main domain>`) are malformed (deny).
- **Routing must be fully visible.** The Hub parses every `traefik.http.routers.*.rule` label in a template's compose file and only accepts the contract v2 form `` Host(`${PORTCULLIS_HOST_<ROUTER>:-<sub>.portcullis.local}`) `` (§3.1), or, for `single` templates during the conversion period, the literal form `` Host(`<sub>.${PORTCULLIS_DOMAIN…}`) ``, each optionally `&& <path matchers>`. It rejects any template with `HostRegexp`/`HostHeader`/`HostSNI`, other domains, other variables in the label, routers without a rule, TCP routers, or a rule branch that is not restricted by `Host()`. The Hub resolves each rule to the instance's hostname. A host the Hub can't see would get no policy and no group (fail open).
- **`policies`** has an entry for each hostname of an enabled instance that has a per-instance policy. Instances that inherit the default publish nothing; group-gate falls back to `default`. An override only names factors the app's auth method can enforce (the Hub refuses others with `400`: `mtls` apps only `mtls`, `custom`/`public` apps without Portcullis sign-in none); every app that runs group-gate can enforce both, so for those the default applies unchanged.
- **One owner per hostname.** The Hub refuses to enable an instance, or to set a hostname (§11.3), that another instance or a core host already uses. If a collision still reaches the writer, it publishes the stricter policy (higher LoA, then `all` over `any`), merges path groups, keeps the group of the lowest instance id, and logs the collision.
- **`groups`** comes from enabled instances of templates with `auth.group_access: true`: each hostname maps to the instance's access group (§11.2). Not for a `custom` app switched to its own login only (its routers have no group-gate); the fail-closed snapshot records that (`native_login_only`).
- **Fail closed when a template goes missing.** At enable time the Hub stores each instance's published config (hostnames, groups, admin paths, policy override) in its state. If an enabled instance's template later stops loading, the Hub keeps publishing that last known config and reports it as drift. If there is no stored config, every hostname the instance's running containers route (or a running `portcullis-*` app project that isn't an enabled instance) gets `groups[host] = "__portcullis_deny__"`. group-gate matches groups exactly and nobody is in that group, so all requests are denied. Never create an LLDAP group with that name.
- **`path_groups`** comes from enabled instances of templates that declare `auth.admin_paths` (a list of path prefixes). Each prefix requires the instance's admin group, **in addition** to the hostname's group.
    - Matching uses group-gate's normalized `X-Forwarded-Uri` path: percent-decoded once, `//` collapsed, dot-segments resolved.
    - It is a prefix match on segment boundaries (`/admin` matches `/admin` and `/admin/x`, not `/administrator`). The longest matching prefix wins.
- **Core hosts** are never taken from this file. `group-gate-map.conf` in core owns them; it keeps `<sub>=<group>` entries, and group-gate expands each `<sub>` to `<sub>.<main domain>` (**NEW**, policy v5; `PORTCULLIS_DOMAIN` is required). The core hosts are `<main domain>` itself (the portal) and `<sub>.<main domain>` for the core subdomains `auth`, `traefik`, `hub`, `directory`, `enroll`, `people`, `metrics`, `mcp` (**NEW**, AI support). A policy-file entry for a core host is ignored, as before. The map file's app entries (e.g. `grafana=users_grafana`) expand the same way and, as before, policy-file entries add to or override them.
    - `mcp` (**NEW**, AI support) is the "all my apps" MCP endpoint (§15). Its map entry is `mcp=*`, but its router has no forward-auth (§5): group-gate never sees MCP requests; `mcp-gate` authorizes them. Listing it makes `mcp.<main domain>` a core host everywhere (group-gate, `policy.CoreHosts`, the templates validator), so no template or instance can take it.
    - `people` is accessible to any signed-in user (§5.1); `metrics` (Grafana of core's optional [monitoring](../operations/monitoring.md) profile) is a core subdomain too. All appear in group-gate, the Hub (`policy.CoreHosts(mainDomain)`) and the templates validator.
    - **Extra domains never route core services**: no core host is on an enrolled domain, and the Hub never assigns a core host to an instance.
- **`public_paths`** is, per hostname, the configuration of core's public guard (§5) for an enabled instance whose public router exists:
    - `paths`: `{path, match}` patterns. `match` is `prefix` (segment boundary), `exact` or `static` (files below `path`: dot-free directories, a file name with one of `static_extensions`). One whole segment may be `{token}`, which matches one segment that `token_pattern` (anchored) accepts. Listed share tokens are published as `{token}`: tokens are secrets and stay in the Hub's `state.yaml`; Traefik's rule routes only the listed ones.
    - `credential_headers` (always including `Authorization` and `Proxy-Authorization`), `credential_cookies`, `credential_query`: credentials the guard refuses.
    - Any unknown key, malformed pattern or bad regex makes the guard deny. Missing-template snapshots keep publishing the entry (the containers keep their public router).
- **Older files.** A policy file **without** a `version` key, or with `version` 4 or lower, is **denied** by group-gate (only version 5 is served). A missing file (the Hub has never written one, or the volume is gone) is treated as an empty policy with no groups or path groups.

### 4.1 User attributes file (Hub → group-gate) — NEW

The Hub writes `user-attributes.json` atomically to the same directory as the policy file (`hub_data` volume). group-gate reads it on every request to populate attribute headers for apps. A missing or corrupt file results in no attribute headers being sent (never a deny).

**File format (version 2):**

```json
{
  "version": 2,
  "fields": {
    "department": "Department",
    "cost_center": "Cost-Center",
    "office_location": "Office-Location"
  },
  "users": {
    "jsmith": {
      "department": ["Engineering"],
      "cost_center": ["CC-1234"],
      "office_location": ["Milan"]
    },
    "alee": {
      "department": ["HR", "Operations"],
      "office_location": ["Berlin"]
    }
  },
  "hosts": {
    "grafana.team-b.example.org": {
      "Grafana-Role": {
        "alice": "Admin",
        "bob": "Editor"
      }
    }
  }
}
```

- **`version`**: always 2. The Hub writes only version 2. Version 1 is refused (no attribute headers): the Hub and core must be upgraded together.
- **`fields`**: maps each custom field name to its header name. The header name has each underscore-separated word capitalized (e.g., `cost_center` → `Cost-Center`). Only fields with the **ShareWithApps** flag are included. Field names match `^[a-z][a-z0-9]*(_[a-z0-9]+)*$` and are at most 31 characters (no leading, trailing or doubled `_`), so the underscore-to-hyphen-plus-capitalize mapping is **injective** (no collisions possible) and always gives a valid header name. group-gate **skips** (and logs) a field whose name or header name is invalid; the other fields still produce headers. Only an unreadable or malformed file (or two fields on one header) means no attribute headers at all.
- **`users`**: maps each lowercase username to their field values. Each field is an array of strings (even for single-valued fields). Users with no shared field values are omitted.
- **`hosts`** (**NEW**, version 2): per-host header deliveries (§13.6). Each full hostname (lowercase) maps to header **suffix** → lowercase username → rendered value. The suffix is the part after `X-Forwarded-Attr-` (`Grafana-Role` for `X-Forwarded-Attr-Grafana-Role`); group-gate adds the prefix. Each suffix matches `^[A-Za-z0-9]+(-[A-Za-z0-9]+){0,30}$` and is unique on its host, compared case-insensitively (the Hub drops one that isn't: group-gate would refuse the file). `hosts` is always an object. group-gate sends these headers only for that host, on allow. The value is sent as is after control characters are stripped. Over 1 KB it is dropped (not delivered). There is no `,` encoding: it is one value. A host header replaces a same-named field header on that host.
- **Written atomically** with mode `0644`, using temp file + rename, at the same time as the policy file.
- **Encoding (field headers):** Each attribute value is percent-encoded before being joined: `%` becomes `%25` and `,` becomes `%2C`. After encoding, values are joined with `, ` (comma-space). Apps must percent-decode each value after splitting on `, `. The **1 KB limit** per value is measured **before** percent-encoding; a value over 1 KB (before encoding) is dropped and logged.
- **Security:** group-gate returns these headers only on **allow** (after auth factors are satisfied). Client copies of `X-Forwarded-Attr-*` headers are stripped by `authResponseHeadersRegex: ^X-Forwarded-Attr-` on **every** forwardAuth middleware in Traefik (Traefik cannot delete headers by prefix in a headers middleware, so each middleware's regex is the mechanism). Routers **without** a forwardAuth middleware in their chain (such as `keycloak`, `enroll-invite`, `headscale`, `netbird`, and `docs`) do not strip these headers, so backends on those routes **must not trust** `X-Forwarded-Attr-*` headers.
- **Logging:** A corrupt `user-attributes.json` file is logged by group-gate; no attribute headers are sent (never a deny).
- **`mcp-gate` reads it too (NEW, AI support).** For `identity_headers` companions the gate sends the same `X-Forwarded-Attr-*` headers group-gate would send on the companion's host (fields, then `hosts[<host>]`), read from this file with the same rules; a missing or corrupt file means no attribute headers, never a deny, and a person missing from it gets none (§15.5).

### 4.2 AI gate files (Hub → mcp-gate) — NEW (AI support)

Next to the policy file, in the same `hub_data` directory, the Hub writes **`mcp-gate.json`** (every MCP resource, who may use it, the limits; rewritten in the same pass as every policy-file write, so a membership change reaches the gate as fast as it reaches group-gate) and **`mcp-credentials.json`** (per-person app credentials and caller secrets, age-encrypted to the gate; rewritten on every credential change). Both are mode 0640, group 10001, written atomically (temp file + rename). `mcp-gate` mounts `hub_data` read-only with `group_add: ["10001"]` and nothing else of the Hub's. Formats, example and rules: §15.4.

- **Fail closed.** A missing `mcp-gate.json` means AI support is off: every MCP request is `503` "AI support is off on this Portcullis", like the master switch off (`enabled: false`). A file that exists but can't be read or doesn't decode strictly (unknown fields, trailing data, another `version`, a value outside its rule) makes the gate refuse **every** MCP request (`503`) until a good file appears; the last good configuration is dropped, never kept. A missing `mcp-credentials.json` is an empty one (companions mint on first use); one that exists but can't be read, decoded or decrypted refuses every request the same way.
- **Re-read.** The gate polls both files every second and re-reads a file when its (device, inode, size, mtime in ns) changed. The Hub never writes a credential or a population anywhere else the gate reads.
- **Group-readable `hub_data`.** The only group-readable files in `HUB_DATA_DIR` are the policy file, `portal-apps.json`, `user-attributes.json`, `mcp-gate.json` and `mcp-credentials.json`. At start the Hub logs any other group- or world-readable file there and sets it to 0600 (the gate's group 10001 must not read the rest of the Hub's data).


## 5. Hub ⇄ Traefik

- **Proxy secret.** Traefik adds the header `X-Portcullis-Proxy-Secret: ${HUB_PROXY_SECRET}` to every request it routes to the Hub, using a `headers.customRequestHeaders` middleware on the Hub router.
    - The Hub rejects any request without a matching header, compared in constant time.
    - The only exception is `GET /healthz`.
    - `HUB_PROXY_SECRET` is generated by `portcullis init`, and the Hub refuses to start without it.
- **Identity headers.** Behind `portcullis-auth@docker,portcullis-groups@docker`, every backend (the Hub, enroll, header-auth apps) receives:
    - `X-Forwarded-User` and `X-Auth-Request-User`: the **immutable LLDAP username** (`preferred_username`; oauth2-proxy `userIDClaim`)
    - `X-Forwarded-Email` and `X-Auth-Request-Email`: the **user-editable** email (LLDAP lets users change it; Keycloak `trustEmail=false`)
    - `X-Auth-Request-Groups`: comma-separated groups

    Traefik guarantees these because each one is listed in the forward-auth middlewares' `authResponseHeaders`, so client copies are deleted. The Hub shows `X-Forwarded-User` as-is and never looks the signed-in user up in LDAP to identify them. Its LLDAP service account (§9) is used only for user and group management.
- **Attribute headers (NEW).** When custom user fields are defined (§9.6) and the **ShareWithApps** flag is enabled on a field, group-gate returns additional headers on **every request it allows** through `portcullis-groups`:
    - **`X-Forwarded-Attr-<Header-Name>`**, where `<Header-Name>` is the field's name with each underscore-separated word capitalized (e.g., `cost_center` → `Cost-Center`).
    - **Values** are percent-encoded (`%` → `%25`, `,` → `%2C`), then joined with `, ` (comma-space). Control characters (ASCII 0x00–0x1F and 0x7F) are stripped from each value before encoding. Each individual value is limited to **1 KB** (measured **before** percent-encoding); longer values are **dropped** (not truncated) and logged by group-gate. Apps must percent-decode each value after splitting on `, `.
    - group-gate reads field values from `user-attributes.json` (§4.1). A missing or corrupt file results in no attribute headers (never a deny). Users absent from the file get no attribute headers.
    - **Scope:** attribute headers are returned for **all requests** that pass through `portcullis-groups`, including every instance hostname (main or enrolled domain) and the core hosts (`auth`, `traefik`, `hub`, `directory`, `enroll`, `people`, `metrics`). They are **not** returned on public routers (which have no `portcullis-auth` or `portcullis-groups` middlewares).
    - **Forwarding:** Client copies of `X-Forwarded-Attr-*` headers are stripped by `authResponseHeadersRegex: ^X-Forwarded-Attr-` on **every** forwardAuth middleware. Traefik cannot delete headers by prefix in a headers middleware, so the regex on every forwardAuth middleware is the stripping mechanism. Routers **without** forwardAuth in their chain (such as `keycloak`, `enroll-invite`, `headscale`, `netbird`, and `docs`) do not strip these headers, so backends on those routes **must not trust** `X-Forwarded-Attr-*` headers.
- **Email is never an identity or linking key.** No repo may authorise, create, match or link accounts by email. Native-OIDC templates key accounts on `sub` / `preferred_username`. `sub` is the person's Keycloak user id, and a re-created username has a new `sub` (§8 "User link"): an app that matches accounts by `preferred_username` alone, or by email, links a new person to the old account, so templates key on `sub` or turn username linking off.
- **Order.** On the Hub router, `hub-proxy-secret@docker` comes **after** `portcullis-auth@docker,portcullis-groups@docker`, so the secret is never sent to oauth2-proxy or group-gate.
- **TLS tier per host.** Traefik selects TLS options per SNI host, so every router of a host must carry the same `tls.options`; on a mismatch Traefik uses its default options and answers `421 Misdirected Request`. The Hub writes one tier for all routers of an app: `public@file`, `authaware@file` or `protected@file` from the app's **effective** policy (its override or the default, intersected with what its method can enforce: an `mtls` app always gets `protected@file`, an app that handles its own sign-in `public@file`), except that `protected@file` becomes `authaware@file` for **all** of the app's routers while its public router exists (`policy.HostTier`).
- **Public router.** When an app's public exceptions are on and open at least one path, the Hub's override adds, on the `public_access.service` (default: the only routed service):
    - `traefik.http.routers.portcullis-public-<instance-id>`: rule `` Host(`<host>`) && (<entries>) `` over the app's hosts on that service. Entries: `` Path(`p`) || PathPrefix(`p/`) `` for prefixes (and each listed `{token}` expansion), `` Path(`p`) `` for `exact` paths, and for other supporting paths `` PathRegexp(`^p(/[A-Za-z0-9_~@+-]+)*/[A-Za-z0-9_~@+-][A-Za-z0-9._~@+-]*\.(<static extensions>)$`) `` (written with compose's `$$`). Then `entrypoints: websecure`, the host's tier, a priority above every router of the app (explicit priorities, and rule length plus 253 per `${…}` for implicit ones), the service's single Traefik service;
    - middlewares `portcullis-public-guard@docker,portcullis-public-strip-<instance-id>@docker,rate-limit@file,security-headers@file` (`rate-limit` and `security-headers` come from core's `traefik/dynamic/middlewares.yml`). No `portcullis-auth`, no `portcullis-groups`;
    - `traefik.http.middlewares.portcullis-public-strip-<instance-id>.headers.customrequestheaders.<H>: ""` for each core identity header (`X-Forwarded-User`, `X-Forwarded-Email`, `X-Forwarded-Groups`, `X-Forwarded-Preferred-Username`, `X-Forwarded-Access-Token`, `X-Auth-Request-User`, `-Email`, `-Groups`, `-Preferred-Username`, `-Access-Token`, `Remote-User`, `-Email`, `-Groups`, `-Name`), `Authorization`, `Proxy-Authorization`, each `auth.identity_headers` and `public_access.credential_headers` entry, each also with `_` for `-`. Without forward-auth nothing else deletes client copies; core's entrypoints also drop alias headers (`aliasHeadersStrategy=delete`).
- **Public guard (core).** `portcullis-public-guard@docker` is a forwardAuth middleware defined on group-gate (`http://group-gate:8080/public-guard`, no `authResponseHeaders`). It runs first, so it sees the request before the strip middleware. It answers 403 (no redirect) unless:
    - the policy file is version 5 and has a `public_paths` entry for the request's normalised hostname (§4; never a core host);
    - `X-Forwarded-Uri` has no `#`, no encoded `/`, `\`, NUL or `#` in the path, and every normalised form of the path (decoded once, `//` collapsed, dot-segments resolved; as for `path_groups`) is inside a published pattern;
    - no request header is a credential header (case-insensitive, `_` read as `-`);
    - no cookie (every `Cookie` header, split on `;` and `,`) and no query key (everything after the first `?`, split on `&` and `;`) names a credential. Names are compared case-insensitively after PHP's mangling (php-src `main/php_variables.c`, `php_register_variable_ex`: leading spaces dropped, ` ` and `.` become `_`, `name[…]` is `name`, an unclosed `[` becomes `_`, NUL ends the name), both raw and percent- / `+`-decoded; a name that isn't valid UTF-8 after decoding (overlong forms) or has control characters is refused.

    On allow it returns 200 without identity headers. Its logs mask token-like path segments and show query parameter names only.

- **Exposure drift.** The Hub compares every exposure label of each running container (each router's `tls.options`, all `portcullis-public-<instance-id>`, `portcullis-oauth2-<instance-id>_<router>` and `portcullis-mcp-<instance-id>--<companion>` router labels and the strip middleware, the `portcullis-mcp-` network aliases, every router's `middlewares` of `native_login` apps and of routers on extra-domain hosts) with what it would render now, `PORTCULLIS_DOMAIN` and the instance's `PORTCULLIS_HOST_*` expanded; any difference is `public_access_mismatch` drift.
- **Extra-domain hosts — NEW (contract v2 / domains).** An instance hostname equal to or under an enrolled domain (§12; listed in the policy file's `extra_domains`, §4) is an **extra-domain host**. That includes enrolled subdomains of the main domain: with `team-a.portcullis.example.com` enrolled, both `team-a.portcullis.example.com` and `x.team-a.portcullis.example.com` are extra-domain hosts. Every other instance hostname is a **main-domain host** (`<label>.<main domain>`). On extra-domain hosts:
    - **Same protection.** Routers carry the same middleware chain, `tls.options` tier, public router and group-gate checks they would carry on the main domain, with one substitution: the Hub's override renders `portcullis-auth-ext@docker` in place of `portcullis-auth@docker` (in the template's middlewares and in the `native_login` prepend alike). `portcullis-groups@docker` is unchanged. Nothing else about an instance's protection depends on its domain.
    - **Second oauth2-proxy (core).** Core runs a second oauth2-proxy service, **`forward-auth-ext`**, that serves extra-domain hosts only. It uses the same Keycloak client (`portcullis-forward-auth`) and the same cookie secret source (`FORWARD_AUTH_COOKIE_SECRET`) as `forward-auth`, a **relative** redirect URL `/oauth2/callback` (resolved against the request host) and a **host-only** cookie named **`__Host-portcullis_ext`** (the `__Host-` prefix: browsers accept it only `Secure`, without `Domain`, with `Path=/`, so a sibling host can't plant or widen it; the CSRF and split-session cookies inherit the prefix). The distinct name keeps it apart from the main domain's `.<main domain>` cookie, which a host under an enrolled subdomain of the main domain also receives. Core defines its forwardAuth middleware **`portcullis-auth-ext`** (`http://forward-auth-ext:4180`) with the same `trustForwardHeader`, `authResponseHeaders` and `authResponseHeadersRegex` as `portcullis-auth`. `forward-auth`, `portcullis-auth`, the `auth.<main domain>` callback and the `.<main domain>` cookie stay exactly as they are.
    - **Certificates.** Traefik serves the enrolled domain's wildcard certificate, picked by SNI, which its HTTP provider fetches from the domains service (§12.4). The Hub assigns a host on an enrolled domain only while that domain is assignable (§12.3).
    - **Sign-in router.** For every extra-domain host on which any of the instance's routers, as rendered (including the `native_login` prepend), uses `portcullis-auth-ext@docker`, the Hub's override adds a router to `forward-auth-ext`. The labels go on the instance's first service, in `compose.yml` order, that has `traefik.enable: "true"`. Example host `grafana.team-b.example.org`, instance `grafana-team-b`, host router `grafana`:

        ```yaml
        traefik.http.routers.portcullis-oauth2-grafana-team-b_grafana.rule: Host(`grafana.team-b.example.org`) && PathPrefix(`/oauth2/`)
        traefik.http.routers.portcullis-oauth2-grafana-team-b_grafana.entrypoints: websecure
        traefik.http.routers.portcullis-oauth2-grafana-team-b_grafana.tls.options: authaware@file   # the host's tier
        traefik.http.routers.portcullis-oauth2-grafana-team-b_grafana.priority: "<above the public router and every router of the instance>"
        traefik.http.routers.portcullis-oauth2-grafana-team-b_grafana.service: forward-auth-ext@docker
        ```

        It is named `portcullis-oauth2-<instance-id>_<host router>` (the original router name, §3.1), carries no middlewares (like core's `oauth2-callback` router on `auth.<main domain>`), and is Host-scoped, so it gets the host's TLS options and core CI's "no host-less router" rule still holds. On extra-domain hosts the path prefix `/oauth2/` belongs to Portcullis: a `multi` template must not serve its own paths there. Router names starting with `portcullis-oauth2-` are reserved for the Hub.
    - **Callback and cookie.** On an extra-domain host the callback is `https://<host>/oauth2/callback` (served by `forward-auth-ext` through the sign-in router) and the session cookie is the host-only `__Host-portcullis_ext`. On main-domain hosts nothing changes: `forward-auth`, callback `https://auth.<main domain>/oauth2/callback`, cookie for `.<main domain>`. The user's Keycloak session at `auth.<main domain>` makes the extra-domain sign-in a silent redirect (no key touch) unless the instance's policy needs a stronger factor than the session has.
    - **Callback redirect URIs.** The Hub keeps `https://<host>/oauth2/callback` for every extra-domain host with a sign-in router in the redirect URIs of core's Keycloak client `portcullis-forward-auth` (shared by both oauth2-proxy services). It adds and removes only such entries (Keycloak has no wildcard host matching), on enable, hostname change, disable and delete, and when an enabled instance's sign-in mode changes (gateway ↔ native, `auth.native_login`): the change takes the instance's lock (`409` busy while another operation on it runs), the Keycloak update comes first, and a failure is a `502` with nothing changed. A failed enable removes the callbacks it added. Core's `./portcullis keycloak configure` keeps redirect URIs of that form that it didn't set itself, and the Hub's access sync loop (§8) re-asserts the running instances' callbacks.
    - **Step-up URL.** group-gate builds the step-up URL from the request host: `https://auth.<main domain>/oauth2/start?acr_values=<acr>&rd=https://<host>/` for main-domain hosts (unchanged), and `https://<host>/oauth2/start?acr_values=<acr>&rd=/` for extra-domain hosts (`extra_domains`, §4; served by `forward-auth-ext`; same host, so `rd` needs no whitelist entry).
    - **Never core.** Extra domains never route core services: no core router has a host on an enrolled domain, and the portal, Hub, people, auth, enroll, directory, traefik and metrics pages and the `mcp` endpoint exist only on the main domain.
- **MCP routes — NEW (AI support).** MCP requests (§15) go to core's `mcp-gate` service (`mcp-gate@docker`, port 8080, on `portcullis-proxy` at `PORTCULLIS_MCP_GATE_IP`), never through forward-auth:
    - **Per companion** (the Hub's override, while the companion is on; `app_token` and `identity_headers` companions only), labels on the instance's first service with `traefik.enable: "true"`, like the sign-in router:

        ```yaml
        traefik.http.routers.portcullis-mcp-gitea--gitea.rule: Host(`gitea.example.com`) && (Path(`/mcp`) || Path(`/.well-known/oauth-protected-resource/mcp`))
        traefik.http.routers.portcullis-mcp-gitea--gitea.entrypoints: websecure
        traefik.http.routers.portcullis-mcp-gitea--gitea.tls.options: authaware@file   # the host's tier
        traefik.http.routers.portcullis-mcp-gitea--gitea.priority: "<above every router of the instance, its public and sign-in routers>"
        traefik.http.routers.portcullis-mcp-gitea--gitea.service: mcp-gate@docker
        traefik.http.routers.portcullis-mcp-gitea--gitea.middlewares: rate-limit@file,security-headers@file
        ```

        Named `portcullis-mcp-<instance-id>--<companion>` (the alias of §3.2 has the same form); the rule is `` Host(`<the router's hosts>`) && (Path(`<public_path>`) || Path(`/.well-known/oauth-protected-resource<public_path>`)) `` with exact `Path` matchers only, so the companion's other paths and the app's own routes are never reachable through the gate, and the app's routers never see those two paths. The host's TLS tier as for every router of the host (above); the priority is computed like the public router's. Router names starting with `portcullis-mcp-` are reserved for the Hub. Its labels are exposure labels (drift, below) and Hub labels for the image-label check (§3).
    - **Core routers** (core's compose, labels on `mcp-gate`): `mcp` — `` Host(`mcp.<main domain>`) ``, every path, `authaware@file`; `hub-mcp` and `people-mcp` — `` Host(`hub.<main domain>`) `` / `` Host(`people.<main domain>`) `` `&& (Path(`/mcp`) || Path(`/.well-known/oauth-protected-resource/mcp`))`, priority above `hub` / `people`, and **the same `tls.options` value as the `hub` / `people` router** of that host (one SNI host, one TLS option; core CI asserts they are equal). All three: middlewares `rate-limit@file,security-headers@file`, service `mcp-gate`. Never on an extra domain.
    - **No forward-auth, no bearer on browser routes.** MCP routers carry no `portcullis-auth`, `portcullis-auth-ext`, `portcullis-groups` or proxy-secret middleware, and the gate reads no cookie and sets none. Browser routers keep oauth2-proxy, which never accepts bearer tokens: `skip_jwt_bearer_tokens` stays off in both oauth2-proxy services (core CI asserts there is no `skipJwtBearerTokens: true` and no `--skip-jwt-bearer-tokens`). An MCP token opens no page and a session cookie authorizes no MCP request.
    - **Extra-domain instances** work the same: the companion's resource is on the extra-domain host; the authorization server stays `https://auth.<main domain>/realms/portcullis`.
    - The Hub's `:8890` MCP listener (§15.7) is never a Traefik target (core CI asserts no router points at port 8890).

### 5.1 People subdomain (NEW)

- **`people.<domain>`** is a new core subdomain that routes to the Hub's directory UI/API. It is accessible to **any signed-in user** (not just administrators).
- **Hub listener.** The Hub serves a second HTTP listener on port **8889** (configurable via `HUB_PEOPLE_ADDR`, default `:8889`). This listener serves only the directory UI and API (Users, Groups, Org chart, Import), with per-request permission checks. App, policy, drift, compose and Docker endpoints are **not** registered on this listener.
- **Core routing.** Core routes `people.<domain>` to `http://hub:8889` with the middleware chain: `rate-limit@file`, `client-headers@file`, `portcullis-auth@docker`, `portcullis-groups@docker`, `hub-proxy-secret@docker`, `security-headers@file`. The same `X-Portcullis-Proxy-Secret` header is required.
- **group-gate-map.conf.** The map file uses the special value **`*`** (asterisk) for the `people` subdomain, meaning "any signed-in user". This value is valid **only** in `group-gate-map.conf`, never in the policy file.
- **Redirect.** The existing `directory.<domain>` subdomain redirects to `https://people.<domain>/` (previously it redirected to `https://hub.<domain>/#users`).
- **My apps route.** The people listener registers exactly **nine** app routes (all caller-only, read or write the caller's own data; none takes a username): the three below, the two credential routes after them, and the four AI routes (**NEW**, AI support): `GET /api/me/ai`, `DELETE /api/me/ai/connections/{client}`, `GET /confirm/{id}` and `POST /api/me/confirmations/{id}`. The two AI routes `/api/me/ai*` exist only on the people listener (`404` on the Hub listener). The two confirmation routes are also registered on the Hub listener, for confirmations of admin tools (§15.6); each listener answers only for confirmations created for it.
  - `GET /api/me/apps`: answers for `X-Forwarded-User` (lowercase) with `{"apps": [...], "fresh_auth": {...}}` — `apps` are the enabled instances whose population includes them. Each entry has: instance id, name, link (`url`, empty for a router-less instance, §3), the caller's per-person values (label, displayed value, reason — only the caller's own groups —, when it applies; see §13), the caller's own person-entered `entries` (key, label, description, applies, input constraints, `unique`, the value only when stored under the caller's current LLDAP account, `set_by_admin` — never the admin's name —, `updated_at`) and the caller's own `credentials` (one per `person_secret` option, §13.16: `{key, label, status, since, reason, info}`; `status` is `none`, `active` (`since` = created), `voided` (`reason: "restore"`, `since` = when it was voided) or `unavailable` (`reason` = the template's username reason); `info` = the option's `info` lines rendered for the caller). An app with values, entries, a `person_secret` option or AI support on for the caller is listed; apps with none of them are left out. Options marked `self_visible: false` are left out; `person_id` values are never shown. Instance options, secrets, hashes and other people are never included. `fresh_auth` (**NEW**, file sharing) is present only when some listed app has a `person_secret` option: `{authorize_url, client_id, redirect_uri}` of the fresh-auth client (§8).
    - **NEW (AI support), per app:** an app with a companion that is on, whose population includes the caller, carries `"ai": {"companions": [{"name", "label", "url", "identity_mode", "mode", "official", "aggregate"}]}`: `aggregate` whether the companion is in "all my apps" (§15.9; always `false` for `app_oauth`); `label` the companion label (§15), `url` the companion's resource URL (§15.1) or, for `app_oauth`, the app's own MCP route; `official` = `upstream: official`.
    - **NEW (AI support), top level:** `"ai": {"aggregate_url": "https://mcp.<domain>/mcp", "clients": {"claude": {"client_id", "admin"}, "claude_code": {"client_id", "callback_port": 33418, "admin"}, "generic": {"client_id", "redirect_uris": [...], "admin"}}, "admin_url": "https://hub.<domain>/mcp"}`.
        - `clients` lists only the clients the admin offers (§8) whose Keycloak setup last succeeded (an unhealthy client is left out, as in the gate file, §15.4); `admin` is that client's admin flag.
        - `admin_url` is present only for `lldap_admin` members, while the Portcullis admin MCP is on and at least one offered client has its admin flag.
        - The whole `ai` key is present only while the master switch is on and the caller has at least one AI resource (a companion, or the people MCP); otherwise there is no `ai` key anywhere.
  - `PUT /api/me/apps/{instance}/values/{key}` with `{"value": <json>}`: writes the caller's own person-entered value (§13.13). Returns 200 with the caller's entry. Refusals: 404 (instance not enabled, key not `person_entered`, or caller not in population — same answer for all three, no leak); 400 (constraint); 409 (uniqueness); 503 (LLDAP unavailable)
  - `DELETE /api/me/apps/{instance}/values/{key}`: clears the caller's value. Returns 204, also when nothing was set. Clearing a value stored under the caller's current LLDAP account always works (also outside the population or on a disabled instance); anything else gets the 404 above
  - `POST /api/me/apps/{instance}/credentials/{key}` (**NEW**, file sharing) with `{"code": "…", "code_verifier": "…", "nonce": "…"}` (the fresh-auth proof, below; body ≤ 8 KiB): creates the caller's file-share password for that `person_secret` option, or regenerates it (a new password replaces the old one at once). Returns 200 `{"password": "<29 characters>", "credential": <the caller's credential entry, status active>}` with `Cache-Control: no-store` and `Pragma: no-cache`; this answer is the only place the password ever appears (§13.16). Refusals, in this order: 404 (instance not enabled, key not a `person_secret` option, or caller not in the population — one answer for all three); 409 with the template's reason (the username rule, §13.16; checked **before** the proof, so a refused name doesn't consume it); 503 (LLDAP unavailable, the caller's LLDAP uuid unknown, or the secrets volume not usable, §6; also before the proof); 403 with the fixed text "a fresh passkey sign-in is required" (any fresh-auth failure; the reason goes only to the audit); 503 with a generic text when the Hub itself can't verify a proof: the fresh-auth client is not in place (§8) or Keycloak's token endpoint can't be reached. Refused creates count toward the refused-save limit below (429); the two 503 answers of a fresh-auth outage, like every 5xx, never do
  - `DELETE /api/me/apps/{instance}/credentials/{key}` (**NEW**, file sharing): revokes the caller's own credential (`reason: self`, audited `credential.revoke`), applied exactly like every other revocation (§13.16 "How it is applied", steps 1–3). No fresh auth: it only removes access. Returns 204, also when nothing was active; it works outside the population and on a disabled instance too
  - `GET /api/me/ai` (**NEW**, AI support): the caller's AI connections and activity. `200` `{"connections": [{"client", "label", "consented_at", "last_used_at", "expires_at"}], "activity": [<access-log line>]}`: one connection per AI client (§8) the caller has a consent or an offline session for (`label` the Hub's name for the client, `expires_at` the offline session's end, each time RFC 3339 or `null`), and the caller's own last 50 access-log lines (§15.8), newest first. Only the caller's own data; `503` with a generic text when Keycloak or the access log can't be read
  - `DELETE /api/me/ai/connections/{client}` (**NEW**, AI support): revokes the caller's consent and offline sessions for that AI client (§8; Keycloak admin API), audited `ai.connection.revoke`. `{client}` must be one of the Hub's AI client ids (the three of §8 and the `ai_client` clients); anything else is `404`. `204`, also when nothing was there. Refusals count toward the refused-save limit below (`429`)
  - `GET /confirm/{id}` (**NEW**, AI support): the confirmation page of §15.6, for the person the confirmation was created for only (anyone else, an unknown id, and a confirmation created for the other listener: `404`). A Hub-rendered HTML page (every value escaped, `Cache-Control: no-store`) with the action, its consequences and arguments, the typed check and the listener's fresh-auth `{authorize_url, client_id, redirect_uri}`; a decided or expired confirmation shows its state and offers nothing
  - `POST /api/me/confirmations/{id}` (**NEW**, AI support) with `{"decision": "approve"|"decline", "typed": "…", "code": "…", "code_verifier": "…", "nonce": "…"}` (body ≤ 8 KiB; `typed` and the proof only for `approve`): records the caller's decision. `200` `{"state": "approved"|"declined"}`. Refusals, in this order: `404` (as the page); `409` `{"state": "<state>"}` when it isn't pending (approved, declined, consumed or expired); `409` "type <check> to confirm" when the typed check doesn't match (nothing recorded); `403` with the fixed text "a fresh passkey sign-in is required" when the proof fails, or when its `auth_time` is earlier than 60 s before the confirmation was created (a sign-in from before the request never approves it); `503` when the Hub can't verify proofs (as for credentials). A decline needs neither the typed check nor a proof. Refused approvals count toward the refused-save limit below (`429`)
  - **Fresh auth** (people.html): the page opens `authorize_url` in a popup with `response_type=code`, `client_id`, `redirect_uri`, `scope=openid`, a random `state` and `nonce`, `code_challenge` (S256) of a random verifier, `prompt=login`, `max_age=0` and `acr_values=hwk`. The popup lands on `https://people.<domain>/`; the page there acts only when `window.opener` is same-origin, drops `code` / `state` from the URL at once (`history.replaceState`), posts them to the opener with `targetOrigin = location.origin` and closes; without an opener it ignores the parameters. Every page of the people listener is served with `Referrer-Policy: no-referrer`, so the `code` / `state` in the callback URL never reach a `Referer` header. The opener accepts only a message with `event.origin === location.origin` and its stored `state`, deletes its `sessionStorage` entries and posts `{code, code_verifier, nonce}`. The Hub exchanges the code itself (server-side, PKCE) and verifies the ID token (§8). **NEW (AI support):** the confirmation page uses exactly this popup flow on both listeners: on the Hub listener the popup lands on `https://hub.<domain>/`, where `index.html` runs the same callback handler, and every Hub-listener answer is served with `Referrer-Policy: no-referrer` too. Each listener has its own verifier, whose redirect URI is its own host (§8)
  - Common rules: no `X-Forwarded-User` is 401; a body over 4 KiB (credentials and confirmations: 8 KiB) is 413; unknown fields or trailing data are 400 with a fixed usage text; 4xx answers carry the Hub's text (never another person's name or value), 5xx a generic message. After **10 refused saves in a minute** (any 4xx, 404 included; 5xx never count) every save of that caller is `429` until the minute ends (in memory, per caller; refusals past the limit are not audited one by one). Admins on the Hub listener are never limited, except for refused confirmation approvals (§15.6), which count there too
  
  These are the **only** app-related routes on the people listener. They are read-only or self-service only (the caller's own data) and CSRF-guarded. The people listener's MCP endpoint (`people.<domain>/mcp`) is not one of its routes: core routes it to `mcp-gate` (§5), which forwards to the Hub's MCP listener (§15.7).

## 6. Docker access

Neither Traefik nor the Hub mounts `/var/run/docker.sock` directly. Each gets its own socket proxy, on its own internal network:

| Client | Proxy endpoint | Allowed |
|--------|----------------|---------|
| Traefik | `tcp://socket-proxy-traefik:2375` | read-only (`POST=0`): containers, networks, events, version, ping |
| Hub | `tcp://socket-proxy-hub:2375` | containers, images, networks, volumes, exec, events, info, version, ping, logs, plus POST/PUT/DELETE. No build, commit, swarm, nodes, services, tasks, plugins, secrets, configs, system (df/prune), auth, distribution or session |

The Hub reads `DOCKER_HOST` for both the `docker compose` CLI (only `up`/`down`) and its own Engine API calls (status, logs, exec, events, and for instance backups (§11.5): volume list / inspect / create / remove, image pull of the helper image, container create / remove and the archive endpoints `GET`/`PUT /containers/{id}/archive`). `CONTAINERS`, `IMAGES`, `VOLUMES` and `POST=1` above cover it, plus `ALLOW_ARCHIVE=1`: the proxy denies `/containers/{id}/archive` without it (the Hub's exec rights already reach any container's files, so it adds no new kind of access). Core CI checks that only the two proxies mount the socket and that each proxy network has exactly its two members. See [Security & Hardening](../operations/hardening.md#docker-socket-proxies).

**Helper containers.** The Hub uses two kinds, both labelled `io.portcullis.hub.helper` and both removed at Hub start if one was left behind (§11.5 Leftovers):

- **Volume helper** (§11.5), **created but never started.** The daemon itself reads and writes the one volume it mounts, through the archive endpoints. Unchanged.
- **Folder fixer** (§14), **started.** Docker's archive endpoints can't change group owners recursively, set modes in place or write ACLs, so shared folders need a process. It is the only helper that runs:
    - **Image:** the Hub's own image, by **image ID** (`sha256:…`), found by inspecting the Hub's own container by its **full container ID**, read from `/proc/self/mountinfo` (the `…/docker/containers/<64 hex>/` root of the `/etc/hostname`, `/etc/hosts` or `/etc/resolv.conf` mount; every such mount must name the same ID). The answer's ID must equal it and carry core's compose labels `com.docker.compose.project=portcullis` and `com.docker.compose.service=hub`; any failure is the `503` below, with no fallback to the hostname (a name or short-ID prefix another container could shadow). No new image to trust or pull. `HUB_FIXER_IMAGE` (must contain `@sha256:`) replaces it for development only: it is honoured only with `HUB_DEV=1` and refused otherwise (an env-selected, root-capable image would be a privilege pivot). Image not found: every folder disk operation answers `503` "the Hub can't find its own image".
    - **Command:** `Entrypoint` is the full argv `["/usr/local/bin/hub", "folderfix", <mode>, <flags>…]`, built from a Go struct, never a shell; `Cmd` is empty. Modes `probe`, `scan`, `snapshot`, `apply`, `restore`, `restore --dry-run` (§14.2–14.4) and **`childfix`** (**NEW**, file sharing: `childfix --rel <tree> --child <name>:<uid> --expect-uid <uid> --expect-dev/--expect-ino/--expect-mount-root <the child's>`, exactly one child; every component opened `O_PATH|O_NOFOLLOW|O_DIRECTORY` and its fd's device/inode compared with the lstat, the owner and mode changed through that fd; refused — exit 2, nothing changed — when the child is a symlink, not a directory, another mount (its own dataset/subvolume: "fix it on the host"), another device/inode/mount root than expected, or owned by another uid than `--expect-uid`; caps `CHOWN`, `FOWNER` only (the tree's path must be searchable by others); §14.6 `person_tree_owner`). `scan --top-only` reads a per-person tree's first level only. Paths aren't secrets, and no secret is ever passed.
    - **Isolation:** `User "0:0"`, `NetworkMode "none"`, `no-new-privileges`, read-only rootfs, `CapDrop: ALL`, `Privileged false`, no devices, no port bindings, pids 16, memory 256 MiB, `Healthcheck {Test: ["NONE"]}` (the Hub image's own `HEALTHCHECK` would run `wget`), `LogConfig {Type: "json-file"}` (the report is read from the logs), no `Tty` / `OpenStdin`, `AutoRemove false` (the Hub removes it), label value `folder:<id>` for a folder's runs.
    - **Mounts:** one bind mount (`Type: bind`, never the `Binds` string form), at `/folder`: the folder (or a hand-typed path the doctor scans), read-only for `scan` and `snapshot`. `probe` binds the folder's **bind root** at `/broot` instead (read-only; read-write only for `probe --create`). Anonymous scratch volumes `/out` (`snapshot`) and `/in` (`restore`) only where the mode needs them; removing the container removes them. Docker's `CreateMountpoint` is never used: it would create a missing host path following host symlinks in its ancestors. Missing directories are created by `probe --create` (`mkdirat` under an `O_DIRECTORY|O_NOFOLLOW` fd of `/broot`, with no capability beyond `DAC_READ_SEARCH`; any failure is a `409`) and by `apply --mkdir` inside the folder.
    - **Capabilities by mode** (each the measured minimum; the Hub's `docker`-tagged CI test drops each in turn): `probe`, `scan`, `snapshot`, `restore --dry-run` → `DAC_READ_SEARCH`; `apply`, `restore` → `CHOWN`, `FOWNER`, `FSETID`, `DAC_READ_SEARCH`, plus `DAC_OVERRIDE` for an `apply` with `--mkdir` only; `childfix` → `CHOWN`, `FOWNER`. **`childfix`** (a per-person tree's top-level directory, §13.17): its preview is a read-only probe that records the child's device, inode and mount root (the folder path rules and the Docker-root rule apply, as for doctor scans), and the plan hash covers them; the apply probes again, opens the child `O_NOFOLLOW|O_DIRECTORY` relative to the tree, refuses a symlink, a non-directory or another mount (exit `2`), then `fchown <uid>:<uid>` and `fchmod 0700` through that fd. Not recursive: nothing inside the child changes. `DAC_READ_SEARCH`: read and search entries uid 0 doesn't own (a `0750` directory of uid 1000). `CHOWN`: the new group (and owner under `must_own`). `FOWNER`: `fchmod` and the `system.posix_acl_*` xattrs of entries uid 0 doesn't own. `FSETID`: the fixer runs as uid 0, which isn't in the folder's group, so without it the kernel clears setgid when it sets a directory's mode or access ACL. `DAC_OVERRIDE`: `mkdirat` in a directory uid 0 has no write bit on; every other change goes through an open fd, which no write permission check applies to. `SETFCAP` is never given (it guards `security.capability`, which the fixer never writes). A `chown` clears setuid/setgid bits whatever the capabilities, so the fixer sets the mode again after changing the owner (order in §14.2).
    - **Run:** create → copy `/in` (restore) → start → wait for not-running (called after start; a timeout kills it and fails the run) → logs (demuxed) → copy `/out` (snapshot) → remove, always, also on failure. Exit `0` = done, `2` = refused (`409` with the report's first error; nothing changed), `1` = failed (`500`). The report is the last non-empty stdout line, one JSON document (≤ 256 KiB, decoded strictly; stderr ≤ 16 KiB, crashes only).
    - **Refusals before any run:** a daemon whose `Info` reports `userns` or `rootless` in `SecurityOptions` (ids inside the helper are translated: owners would read as 65534 and ACL entries would be written for the wrong ids) → `503`, explain-only. Every run on a **defined** folder (after its create) passes the folder root's stored device and inode (`--expect-dev`, `--expect-ino`) and its stored mount root (the root field of `/folder`'s line in `/proc/self/mountinfo`, recorded at create and at every path change, §14.1); the fixer exits `2` with nothing changed when `/folder` isn't that directory or its mount root isn't **exactly** the stored one (a symlink Docker resolved on the host). Check path, the create-time probe and scans of hand-typed paths have nothing stored yet and run unchecked.
- **Proxy flags.** `CONTAINERS` and `POST` (plus the existing `ALLOW_LOGS`, `ALLOW_ARCHIVE` and `INFO`) already cover create, start, wait, kill, logs, archive and info. **No flag of `socket-proxy-hub` changes.** The compose `up` path already starts containers through the same proxy.

**Exec with stdin (§13.8).** The Hub runs `POST /containers/{id}/exec` with `AttachStdin: true` and hijacks the connection to send JSON on stdin to the process. Used for hooks that receive the full desired state.

**Split output for AI hooks (NEW, AI support; §15.5).** `ai` hooks run through the same exec endpoint with `Tty: false`, and the Hub demultiplexes stdout and stderr into two separate capped buffers (stdout ≤ 64 KiB, more is a failure; stderr the first 16 KiB), never one merged stream: a credential printed on stdout can't reach the stderr text that a failure records. No proxy flag changes.

**Container kill (§13.8).** The Hub sends signals with `POST /containers/{id}/kill?signal=<HUP|USR1|USR2>` for reload actions. No change to `socket-proxy-hub` (already `CONTAINERS` + `POST`).

**Per-person secrets volume (NEW, file sharing; §13.16).** File-share password hashes live on their own volume, never on `hub_data`:

- **Core** declares the volume `hub_secrets` (`name: portcullis_hub_secrets`), mounts it into the Hub at `/secrets` and sets `HUB_SECRETS_DIR=/secrets` and `HUB_SECRETS_VOLUME=portcullis_hub_secrets` (the defaults). `./portcullis init`, `upgrade` and `restore` make sure the volume root is owned by `10001:10001` with mode `0700` (through the helper image, as restore already does for volume roots). Core's backup never copies it and core's restore empties it (§11.5, §11.6). Before any destructive step the restore takes down (`compose down`, volumes kept) every app project with a container mounting the volume — any failure, or a container left, aborts with nothing restored — and lists them afterwards: they are started again from the Hub (drift shows them not running), never by the restore, since their credentials were just voided.
- **The Hub** checks at start that `HUB_SECRETS_DIR` is owned by its own uid and is mode `0700`. Otherwise it fails closed: the credential routes (§5.1, §13.16) answer `503` and every instance with a `person_secret` option refuses to enable or start, naming the reason. It keeps one directory per (instance, option) on the volume: `<secrets>/<instance>/<key>/` (`0700`) holding one `<username>.nt` per active credential (`0600`, 32 uppercase hex characters and `\n`), all owned by uid 10001, plus `<secrets>/.epoch` (§11.6). The directory exists before every `up` of the instance.
- **The Hub's override** mounts it into the option's `mount.service` only, read-only, as a subpath of the external volume:

    ```yaml
    volumes:
      portcullis-hub-secrets:            # reserved key (§3)
        external: true
        name: portcullis_hub_secrets     # HUB_SECRETS_VOLUME
    services:
      <mount.service>:
        volumes:
          - type: volume
            source: portcullis-hub-secrets
            target: <mount.path>
            read_only: true
            volume: {subpath: <instance>/<key>}
    ```

    So a container sees only its own instance's and option's hash files, never another instance's. Before every `up` the Hub checks the rendered project (template, Hub override and custom override merged): every top-level volume whose resolved name is `HUB_SECRETS_VOLUME`, under **any** key, is mounted only by `mount.service`, with exactly that subpath, read-only, and only through the key `portcullis-hub-secrets`; anything else refuses the `up` (`409`). Templates and custom overrides can't name the key, and can't declare a volume with that name (§3: templates may not name an external volume `portcullis*`; the custom override may not set `external` or `name` on any volume).
- **Requirements:** Docker Engine API **≥ 1.45** (Docker Engine 26.0, the first with volume subpath mounts) and `docker compose` **≥ 2.26.0** (the first release that passes `volume.subpath` to the Engine). The Hub refuses to start with an older compose (its startup version check), and before every `up` of an instance that mounts the secrets volume it checks the daemon's API version (an older daemon would ignore the subpath and mount the whole volume: refused).
- **Proxy flags:** none change (volume mounts are part of the container create the Hub already does through compose).

## 7. Docs ⇄ templates

- **Generator.** `scripts/generate-app-docs.py` in the docs repo reads every `<app-id>/manifest.yaml` and writes `docs/apps/*.md` plus `docs/apps/.nav.yml`.
- **Triggers.**
    - On push to `main`, the templates repo sends a `repository_dispatch` event (`templates-updated`) to the docs repo, which rebuilds the site. This needs the `DOCS_DISPATCH_TOKEN` secret in the templates repo.
    - The docs repo also rebuilds daily as a fallback.

## 8. Keycloak clients (core ⇄ Hub ⇄ templates)

- **Client scopes core provides.** `./portcullis keycloak configure` keeps these realm client scopes in place (idempotent):
    - `acr` (with an `amr` mapper) and `groups` (claim `groups`, plain group names).
    - `email-unverified`: protocol `openid-connect`, included in the token `scope`, with exactly **one** mapper, `email` (user property `email` → claim `email` in the ID token, access token, userinfo and introspection). It has **no** `email_verified` mapper; any other mapper on the scope is deleted on the next run.
- **What the Hub attaches.** A client the Hub creates for a template's `keycloak_clients[]` entry gets the default client scopes `profile`, `acr`, `groups` and exactly one of the two email scopes; on reconcile the Hub re-attaches `acr`, `groups` and that email scope if they are missing:
    - `email` (the default): tokens carry `email` and `email_verified: false`, because LLDAP email is user-editable and the LDAP federation has `trustEmail=false`.
    - `email-unverified`, when the entry sets `email_verified_claim: false`: tokens carry `email` and no `email_verified` claim.

    On create and on every reconcile (enable, ACR push), the Hub attaches the wanted one first, then detaches the other one from the client's default **and** optional scopes. It does this only for clients it may reconcile (owner tag, or an untagged client that points only at the instance's hosts; see [Hub → Keycloak clients](../operations/hub.md#keycloak-clients)). If the realm has no `email-unverified` scope, the Hub reports an error and leaves the client's `email` scope attached.
- **What the template must do.** An app with `email_verified_claim: false` must not request the `email` scope: Keycloak answers `invalid_scope` to a requested scope the client doesn't have. `email-unverified` is a default scope, so the email claim arrives without being requested. `tests/validate.py` rejects `*SCOPE*` environment values that contain `email` for such templates.
- **Use it only for apps that refuse `email_verified=false` but accept it absent** (Vaultwarden SSO signups). The email is exactly as unverified as before: identity stays `sub` / `preferred_username` (§5), and the app must still never link accounts by email.
- **Clients per instance (NEW, contract v2).** Each instance has its own Keycloak clients, one per `keycloak_clients[]` entry, with ids from §11.2 and redirect URIs with `{{HOST_<ROUTER>}}` expanded to the instance's hostnames. A hostname change rewrites those redirect URIs (and web origins) in place (§11.3); a guarded delete removes the clients (§11.4). The Hub also maintains the extra-domain callback URIs on `portcullis-forward-auth` (§5). Core's two oauth2-proxy services, `forward-auth` (main domain) and `forward-auth-ext` (extra-domain hosts), both use that client.
- **Access role (NEW, instances).** A native-OIDC app that can't restrict sign-in to its access group itself lets every realm user in, and with several instances team B could open team A's. The Hub enforces the group in Keycloak for every instance whose template has `auth.method: native-oidc`, an `access_group`, and either `group_access: false` or `auth.keycloak_access_role: true` (a native-oidc template with `group_access: false` must declare an `access_group`; the Hub rejects it otherwise):
    - each of the instance's clients gets the client role `access`; exactly the instance's access group (the realm group core's LDAP group mapper imports from LLDAP) has it — other groups, direct user grants and composite roles containing it (e.g. `default-roles-portcullis`, or another client's role) lose it. A group Keycloak hasn't imported yet is imported with the mapper's "sync LDAP groups to Keycloak"; if LLDAP doesn't have it either, the client denies everybody until it exists.
    - the client's browser flow override is a Hub-managed flow `portcullis-client-access-<clientId>-<random>`. At its top level: a REQUIRED sub-flow with a copy of the realm's browser flow (core's `portcullis-universal`, without the identity-provider redirector); a CONDITIONAL sub-flow `<top>.member` — "Condition - user role" `<clientId>.access` → "Allow access"; a CONDITIONAL sub-flow `<top>.deny` — "Condition - sub-flow executed" (`<top>.member`, `not-executed`) → "Deny access". The check runs after every sign-in path, the SSO cookie included, and fails closed: a deleted `access` role (Keycloak's role condition is false for a role that doesn't exist) or a renamed member sub-flow skips the member check, and the deny fires.
    - the Hub reads the bound copy back on every sync and compares it with what it would build from the realm's current browser flow (structure, requirements, aliases, authenticator configs). When core rebuilds its browser flow, or someone edits the copy, the Hub builds a fresh copy (with its own configs), rebinds the client and deletes the old one.
    - direct access grants, implicit flow, service accounts, device and CIBA grants and standard token exchange are switched off on **every** client of such an instance — only the browser flow signs in. A template that needs any of them on its client can't use the access role.
    - Set up on enable (the Hub refuses to start the app if it can't), kept consistent after directory changes and every 10 minutes, removed on delete (§11.4 step 4) and when the template stops needing it (only the role the Hub created).
    - **Residuals.**
        - Keycloak checks the role at sign-in only, never at token refresh. Removing a member through the Hub (Users & Groups, rule evaluator, expiry, user delete) signs them out of Keycloak (`POST /users/{id}/logout`): that ends their sessions and sets the user's not-before, which Keycloak checks on every refresh, offline tokens included. Issued access tokens stay valid until they expire (5 minutes). Changes made directly in LLDAP sign nobody out: sessions and refresh/offline tokens live until they expire (the next sign-in is denied).
        - Invite links. Keycloak's broker endpoint finishes a brokered login through the invite IdP's post-broker flow (`portcullis-invite-session`), not the client's browser flow, so core restricts that flow to the one client setup links use: it admits only clients that have the marker client scope `portcullis-invite-client` as a default scope (`Condition - client scope`, not negated), then denies everything that check did not admit (`Condition - sub-flow executed`, `not-executed` → `Deny access`), so a missing scope or sub-flow denies too. It then records the session's LoA like the browser flow does for a passkey: LoA 1 (sub-flow `portcullis-invite-loa-1`) and LoA 2 (`portcullis-invite-loa`), amr `hwk` — so an mtls step-up right after a setup link asks only for the client certificate. `./portcullis keycloak configure` creates the scope (no mappers, not in tokens) and keeps it a default scope of `portcullis-forward-auth` only: it removes it from every other client and from the realm's default scopes. An unused link therefore can't sign in to an access-role app; it can still only do what it always could on `portcullis-forward-auth` (and so `forward-auth-ext`), where group-gate checks the groups. The Hub must never attach `portcullis-invite-client` to a client.
        - Token exchange is off on the instance's clients only. Another client with standard token exchange on and an audience mapper adding this client could exchange a user's token for one this client accepts, without the role check. The Hub creates no audience mappers; don't add them for such clients.
        - A realm admin can still open the client (remove the browser flow override; Keycloak then uses the realm's browser flow) until the Hub's next sync rebinds it. Keycloak refuses to delete a flow a client override binds.
- **Backchannel logout (NEW).** A `keycloak_clients[]` entry with `backchannel_logout_url` (`https://{{HOST_<ROUTER>}}/<path>`) gets it as the client's backchannel logout URL, with "backchannel logout session required" on; it moves with hostname changes (§11.3). Keycloak then POSTs a logout token there whenever a session ends, so the app ends its own session. The path must be reachable from Keycloak without forward-auth. Supported upstream by Nextcloud `user_oidc` (`/index.php/apps/user_oidc/backchannel-logout/<provider>`) and Synapse (`/_synapse/client/oidc/backchannel_logout`, `backchannel_logout_enabled: true`).
- **Setting claims (§13).** For each (instance, option) with a claim delivery, the Hub creates a Hub-owned LLDAP user attribute named `ps-<hash>` (LLDAP attribute names allow only letters, digits and `-`; a short hash of instance and key), STRING type, not visible, not editable. It writes each person's rendered value into it and adds an LDAP attribute mapper (on the LLDAP federation) plus a protocol mapper on the instance's client only (per-client, not shared), both named `portcullis-setting-<attr>` (e.g. `portcullis-setting-ps-0123456789ab`). The Hub owns every mapper with that prefix: on the client it keeps exactly the claims it delivers (other `portcullis-setting-*` mappers of that client are deleted, no other mapper is touched), the LDAP mapper goes with its attribute, and `./portcullis keycloak configure` must leave them alone (like the `portcullis-attr-<field>` mappers, §9.6). The attribute and mappers are removed when the instance is deleted.
- **Fresh-auth client (NEW, file sharing; shared with the certificates project).** The Hub owns one Keycloak client, **`portcullis-fresh-auth`**, for proofs of a fresh hardware sign-in (§5.1, §13.16; **NEW, AI support:** confirmations, §15.6). It creates and re-asserts it in the directory sync loop (retried), tagged like every Hub-owned client (`portcullis.hub.template` = `portcullis-fresh-auth`; an untagged client of that id is a conflict and is left alone, so fresh auth then fails closed). Settings, each checked by the Hub's tests:
    - public client, standard flow only; `pkce.code.challenge.method=S256`; no direct access grants, implicit flow, service accounts or device grant; `use.refresh.tokens=false`;
    - default client scopes exactly `basic` and `acr` (with `openid`); no `groups`, no attributes scope, never `portcullis-invite-client`;
    - redirect URIs exactly `[https://people.<domain>/, https://hub.<domain>/]`, web origins exactly `[https://people.<domain>, https://hub.<domain>]` (**NEW, AI support:** the Hub listener's confirmation page signs in through the same client). The Hub keeps one verifier per listener, each with its own redirect URI (`https://people.<domain>/` / `https://hub.<domain>/`), behind one readiness gate;
    - an untagged or foreign-tagged client of that id, or any failed ensure, makes every proof fail closed until an ensure succeeds: the create answers `503` with a generic text ("fresh-auth client not in place" goes only to the log and the audit), not counted as the caller's refusal (§5.1);
    - exactly one protocol mapper on the client itself: the username as `preferred_username`, in the ID token only (with only `basic` + `acr` Keycloak 26 puts no username in the token); the Hub removes any other mapper on it. Templates may not use the client id (it is a protected client).

    `./portcullis keycloak configure` leaves it alone. The Hub reaches Keycloak internally for the code exchange (`http://keycloak:8080/realms/portcullis/protocol/openid-connect/token`, with the PKCE verifier) and the keys (`…/certs`), and checks tokens against the public issuer `<HUB_KEYCLOAK_PUBLIC_URL>/realms/portcullis` (core sets `HUB_KEYCLOAK_PUBLIC_URL=https://auth.<domain>`). A token endpoint that can't be reached is a `503` with a generic text (the Hub's outage, not counted as the caller's refusal). Otherwise a proof is accepted only when every one of these holds; anything else is a `403` with the generic text:
    - the code exchange succeeds (Keycloak's codes are single-use: a replay fails);
    - the browser makes the nonce; it binds nothing on its own: the binding is the PKCE verifier (only the page that started the flow holds it) plus the username match. The code passes through Traefik's access log in the redirect URL; single use and PKCE make it worthless there;
    - the ID token is signed RS256 or ES256 by the realm's keys, `iss` is the public issuer, `exp` is in the future, `iat` ≤ now + 60 s;
    - `aud` contains `portcullis-fresh-auth`, and `azp`, when present, is `portcullis-fresh-auth` (several `aud` values need `azp`);
    - `nonce` is present and equals the one posted;
    - `auth_time` is present and ≥ now − 300 s;
    - `amr` is present, non-empty and contains `hwk` or `mtls`; neither `amr` nor `acr` contains `file`;
    - `preferred_username`, lowercased, is the caller.

    The code, verifier, nonce and token never appear in logs, the audit (refusals record only the reason), errors or answers.
- **User link (core).** Keycloak's LDAP federation links a user by LLDAP's immutable per-account uuid (`uuidLDAPAttribute: entryUUID`; the Keycloak user's `LDAP_ID` attribute is LLDAP's `uuid`), never by the username; `./portcullis keycloak configure` re-asserts it on every run. An LLDAP account deleted and re-created under the same name is a **new** Keycloak user with a new `sub`: the old copy, with its passkeys, sessions, consents and grants, is removed at the next lookup. A Keycloak id is not a permanent person id either: it also changes whenever Keycloak removes and re-imports a user's copy. Repos that must recognise a person across that use LLDAP's uuid; repos that must not carry identity across a re-creation (app accounts, AI grants) key on `sub` and treat a new `sub` as a new person.
- **AI clients (NEW, AI support).** While the master switch "AI support" is on (Hub Settings → AI, §15.11), the Hub owns one Keycloak client per AI client kind the admin offers, created and re-asserted in the directory sync loop like the fresh-auth client, tagged `portcullis.hub.template` = `portcullis-ai` (an untagged or foreign-tagged client of that id is a conflict, left alone, and not listed in `mcp-gate.json`'s `clients`):

    | Client | Type | Redirect URIs |
    |--------|------|---------------|
    | `portcullis-ai-claude` | public | exactly `https://claude.ai/api/mcp/auth_callback` (claude.ai, Claude desktop and mobile) |
    | `portcullis-ai-claude-code` | public | `http://localhost:33418/callback`, `http://127.0.0.1:33418/callback` (Claude Code with `--callback-port 33418`) |
    | `portcullis-ai-generic` | public | the same two loopback URIs (other MCP clients that accept a client id) |

    Settings on each, checked by the Hub's tests: standard flow only; `pkce.code.challenge.method=S256` required; direct access grants, implicit flow, service accounts, device grant (`oauth2.device.authorization.grant.enabled=false`), CIBA (`oidc.ciba.grant.enabled=false`) and standard token exchange (`standard.token.exchange.enabled=false`) off; `consentRequired: true`; `default.acr.values=hwk` (an AI sign-in is a passkey or hardware-certificate touch); `fullScopeAllowed=false`; `client.offline.session.idle.timeout` and `client.offline.session.max.lifespan` from Settings → AI "Connection length" (idle default 7 days, bounds 1–30; max default 30 days, bounds 1–90; in seconds); no flow overrides.
    - **Exact scopes, no personal data beyond the username.** Default client scopes exactly `basic` and `acr` (`acr` carries the `amr` mapper); optional scopes exactly `offline_access` plus the Hub's `mcp:*` scopes below. The realm-default `profile`, `email`, `roles`, `groups` and `web-origins` scopes are removed from the client, and `portcullis-attributes` is never attached: the Hub's attribute-scope sync skips clients owned by `portcullis-ai` and every `ai_client` client. One protocol mapper on the client itself puts the username into `preferred_username`, in the access token and the ID token (with only `basic` + `acr`, Keycloak 26 puts no username in the token; same shape as the fresh-auth client's mapper, plus the access token). An MCP token therefore carries `sub`, `preferred_username`, `acr`, `amr`, `azp`, `aud`, `scope` and the standard times, nothing else Portcullis-specific.
    - **Lifecycle.** Unticking a client in Settings → AI deletes it (only when tagged `portcullis-ai`). Switching the master switch off keeps the clients and scopes (the gate refuses everything: `enabled: false`, §15.4). The prefix `portcullis-ai-` is protected: templates can't name such a client (§3.2) and client registration never adopts one.
    - **Connection length and rotation.** AI clients may request `offline_access` (Claude does), so a connection outlives the browser session until the offline session's idle or max time, then the person touches their passkey again. Access tokens live 5 minutes (realm default). Core's realm sets the offline upper bounds (`offlineSessionIdleTimeout` 30 days, `offlineSessionMaxLifespanEnabled`, `offlineSessionMaxLifespan` 90 days); the Hub's per-client values are shorter. **Refresh tokens do not rotate** (realm `revokeRefreshToken` false, pinned; verified on Keycloak 26.8.1, core Task 6): Keycloak 26.8 has no client-level rotation switch (`suppress-refresh-token-rotation` only hides the new token, the realm still enforces single use), and realm-wide rotation breaks every forward-auth session at its second refresh — Traefik's forwardAuth never hands oauth2-proxy's refreshed cookie back to the browser. Core's e2e-login `refresh_rotation` check fails if rotation is turned on. Compensations: the offline bounds above, each person's "Disconnect" on people.<d> (§5.1, revokes consent and offline sessions), and every Hub-made removal signing the person out of Keycloak (§9.6: not-before, which also ends offline sessions). **Residual:** a stolen AI refresh token stays usable until one of those, or the idle/max limit. Turning rotation on needs forwardAuth to pass the refreshed cookie back plus a shared, locked session store (a core follow-up).
    - **Verified on Keycloak 26.8.1** by `TestLiveAIObjects`: loopback redirect URIs match **exactly, port included** (`127.0.0.1:40123`, `localhost:40123` and `[::1]:33418` are refused), so Claude Code must use `--callback-port 33418`; requesting a scope the client lacks fails with `invalid_scope`; `default.acr.values=hwk` only *requests* `hwk` — the realm's browser flow (core's `portcullis-universal`) and the gate's `min_loa` check enforce it (on Keycloak's built-in flow a password sign-in still gets `pwd`); the consent screen lists each requested scope's text and asks again for a new scope or after a disconnect; the offline refresh token lives the client's idle setting; refresh tokens are reusable (no rotation); the real token carries only the claims above. **Disconnect** (§5.1 `DELETE /api/me/ai/connections/{client}`) refuses the client's offline **and** online refresh tokens at once; only access tokens already issued stay valid, for up to 5 minutes; other AI clients are unaffected. Requesting two resources' scopes in one authorization yields one token with both audiences, which the gate refuses at both (§15.2; core's `e2e-ai`): an MCP client asks for one resource's scope per token. The passkey `acr`/`amr` = `hwk` check is manual (it needs a WebAuthn authenticator).
- **`mcp:*` scopes (NEW, AI support).** One **optional** client scope per MCP resource (§15.1), owned by the Hub (`./portcullis keycloak configure` never deletes or rewrites a scope named `mcp:*` or a client tagged `portcullis-ai`):

    | Scope | Audience (the resource URL) | Consent text |
    |-------|-----------------------------|--------------|
    | `mcp:<instance-id>.<companion>` | `https://<host of the router><public_path>` | `Use <instance label> (<host>) as you` |
    | `mcp:all` | `https://mcp.<main domain>/mcp` | `Use all your Portcullis apps as you` |
    | `mcp:portcullis.admin` | `https://hub.<main domain>/mcp` | `Manage Portcullis as you — administrator` |
    | `mcp:portcullis.people` | `https://people.<main domain>/mcp` | `Use your Portcullis account as you` |

    Each has `include.in.token.scope=true`, `consent.screen.text` as above, `display.on.consent.screen=true`, and exactly one protocol mapper, an Audience mapper named `portcullis-mcp-audience` with `included.custom.audience` = the resource URL, in the access token only. No group or attribute mappers. This is Keycloak's documented way to put a resource in `aud`; the experimental resource-indicators feature stays off, and so do dynamic client registration and client ID metadata documents (CIMD).
    - **Attached only** as optional scopes of the AI clients: every companion scope, `mcp:all` and `mcp:portcullis.people` on the three clients above; `mcp:portcullis.admin` **only on the AI clients the admin enabled it for**: Settings → AI has a per-client admin flag (`clients.<kind>.admin`, §15.11; default off: the admin enables it client by client), and the scope is attached to a client only while that client is offered, its admin flag is on and "Portcullis MCP for admins" is on (turning any of them off detaches it at once); never on an `ai_client` client, which gets only `mcp:all`. **The Hub attaches an `mcp:*` scope nowhere else**: never to an app client, `portcullis-forward-auth`, `portcullis-fresh-auth` or the realm's default scopes.
    - **Follows the resource.** A companion's scope exists while its AI support is on (master switch on). A hostname change (§11.3) rewrites its audience and consent text in the same Keycloak step as the redirect URIs (undone with them); old tokens stop matching. Switching the companion off, deleting the instance (§11.4 step 4) or dropping the companion from the template (§15.11) deletes the scope, detached from every client first, and with it every consent that named it.
- **`ai_client` entries (NEW, AI support).** A `keycloak_clients[]` entry with `ai_client: true` (only in a template with `ai.chat`, §3.2) is the AI page's MCP client: the Hub registers it through the AI client path, not as an app client — confidential with the entry's `secret_env`, standard flow only, the entry's redirect URIs, `consentRequired: true`, `default.acr.values=hwk`, the AI clients' exact scopes and username mapper (above) with the one optional MCP scope `mcp:all`, the offline settings of Settings → AI — tagged with the **instance id** like the instance's other clients, and with the instance's **access role and access flow** unchanged (only the access group's members sign in through it). It is listed in `mcp-gate.json`'s `clients` while AI support is on.
- **Disconnecting.** `DELETE /api/me/ai/connections/{client}` (§5.1) and the Hub's leaver cleanup (§15.5) delete the person's consent for that client (`/users/{id}/consents/{client}`) and its offline sessions. **Residual:** Keycloak 26.8.1 then refuses the client's offline and online refresh tokens (verified), but access tokens already issued stay valid for up to 5 minutes; the gate's per-request population check (§15.2) still refuses a person who left, and the People card and the admin guide say so.
- **The `mtls` amr invariant (NEW).** Core's flows emit amr `mtls` **only** for a login with a hardware (`pki_int`) certificate; a login with a file certificate emits `file` in `amr` and `acr`. Fresh auth relies on it: it accepts `mtls` as a hardware proof. Today every certificate is `pki_int`; the certificates project adds file certificates together with a test of this invariant.

## 9. Hub ⇄ LLDAP (users & groups)

Day-to-day user administration happens in the Hub's **Users & Groups** tab. The Hub is already behind forward-auth, `lldap_admin` and WebAuthn step-up; LLDAP's own web UI (0.6.3) has a separate login and no SSO or header auth. It stays available as a fallback.

### 9.1 Service account (core provides)

- **Account.** Core creates an LLDAP user `portcullis-hub`, makes it a member of `lldap_admin`, and gives it a random password (≥ 32 characters). It keeps the account in place idempotently on every `./portcullis up`: create it if missing, re-add it to `lldap_admin`, and reset the password if the files and LLDAP disagree.
- **Credentials are files, never env vars.** Core mounts them read-only into the Hub as `/run/portcullis/lldap/username` and `/run/portcullis/lldap/password`, owned by group 10001 with mode 0640 (directory 0750). The Hub reads them on every LLDAP login, so a rotated password needs no restart. One trailing newline is ignored.
- **Hub configuration.**

    | Env var (Hub) | Default | Meaning |
    |---|---|---|
    | `HUB_LLDAP_CREDENTIALS_DIR` | `/run/portcullis/lldap` | directory with `username` and `password` |
    | `LLDAP_HTTP_URL` | `http://lldap:17170` | LLDAP HTTP API |
    | `LLDAP_LDAP_URL` | `ldap://lldap:3890` | LLDAP LDAP, used **only** to set passwords (`ldaps://` also accepted) |
    | `LLDAP_BASE_DN` | `dc=portcullis,dc=local` | must equal LLDAP's `LLDAP_LDAP_BASE_DN` (core: `${LLDAP_BASE_DN}`) |

- **Not configured.** If the files are missing, empty, or the username isn't a valid username, the Users & Groups tab shows "user management is disabled" and why. Every `/api/directory` mutation answers 503, and the rest of the Hub works as before.
- **Network.** The Hub reaches `lldap:17170` and `lldap:3890` on the `portcullis` network, the same way Keycloak's LDAP federation and enroll do.
- **Why `lldap_admin`.** LLDAP 0.6.3's narrower `lldap_password_manager` can only change passwords of non-admins: `createUser`, `createGroup`, `addUserToGroup`, `deleteUser` and the other GraphQL mutations go through `get_admin_handler`, which requires `Permission::Admin` (`crates/graphql-server/src/mutation/mod.rs`, `crates/access-control/src/lib.rs`).
- **Contained.** The account can never sign in through the gateway: Keycloak's LDAP federation has the user filter `(!(uid=portcullis-hub))`, so it is never imported (`keycloak configure` also deletes a copy imported earlier), and group-gate denies the username `portcullis-hub` on every endpoint (`GATE_DENY_USERS`).
- **Why this is acceptable.** `lldap_admin` can put anyone into `lldap_admin`. The Hub could already start arbitrary containers through its socket proxy (§6), so it is host-root-equivalent anyway. Every change it makes is attributed to the signed-in admin and audited (§9.5).

### 9.2 What the Hub calls

- **Login.** `POST /auth/simple/login` `{"username","password"}` returns `{token, refreshToken}`. The JWT is cached until one minute before its `exp`. On expiry or on a `401`, the Hub tries `GET /auth/refresh` with the `Refresh-Token` header first, then logs in again.
- **GraphQL** (`POST /api/graphql`, `Authorization: Bearer <jwt>`). The Hub uses only these operations: `users { id email displayName creationDate groups { id displayName } }`, `groups { id displayName creationDate users { id } }`, `createUser`, `updateUser` (email, displayName), `deleteUser`, `createGroup`, `deleteGroup`, `addUserToGroup`, `removeUserFromGroup`.
- **Passwords: LDAP Password Modify (RFC 3062), not HTTP.** LLDAP stores passwords with OPAQUE. Its HTTP endpoints (`/auth/opaque/register/start|finish`) expect the *client* half of the OPAQUE registration (ristretto255 + argon2), which the Go standard library can't do. LLDAP 0.6.3 has no GraphQL password mutation. Its LDAP server, however, implements the Password Modify extended operation (`1.3.6.1.4.1.4203.1.11.1`) and runs the OPAQUE registration server-side (`crates/ldap/src/password.rs`; `lldap_admin` may change any password). So the Hub:
    1. simple-binds as `uid=portcullis-hub,ou=people,<base DN>`;
    2. sends `userIdentity = uid=<user>,ou=people,<base DN>` and `newPasswd`;
    3. unbinds.

    The password crosses the internal `portcullis` network in clear text, like Keycloak's and enroll's LDAP binds today. Core may switch to LDAPS by setting `LLDAP_LDAP_URL=ldaps://…`.

### 9.3 Keycloak side

- LDAP users are imported into Keycloak lazily. The Hub uses its existing Keycloak admin credentials (`KEYCLOAK_ADMIN`, `KEYCLOAK_ADMIN_PASSWORD`) and imports a user explicitly with `GET /admin/realms/portcullis/users?username=<u>&exact=true`, which makes the LDAP federation import the user.
- **Status shown.** The Hub shows whether a user is imported, their WebAuthn credential count (`webauthn` + `webauthn-passwordless`) and their pending required actions. It doesn't show client certificates: they live in Vault/enroll, not in Keycloak.
- **Status lookups.** The Hub lists users (`GET …/users?max=1000&briefRepresentation=false`) and the realm's LDAP provider (`GET …/components?type=org.keycloak.storage.UserStorageProvider`, `providerId` `ldap`), then reads `GET …/users/{id}/credentials` per user. A failed credentials lookup marks only that user.
- **Stale records.** A Keycloak user whose `federationLink` is the LDAP provider but whose username isn't in LLDAP is listed as stale. The Hub deletes such a copy by id only on an explicit, confirmed request. Never for `admin`, the service account, users LLDAP has, or Keycloak-local users.
- **Remove passkeys.** Deletes every WebAuthn credential, signs the user out (`POST …/users/{id}/logout`), then either requests a new invite (§9.4) or, for password users, adds `webauthn-register-passwordless`.
- **Password reset.** Signs the user out of Keycloak.
- **Delete.** The Hub deletes the user in LLDAP, then deletes the Keycloak copy by id. The federation is `READ_ONLY`, so this never writes to LDAP.
- **No other changes.** The Hub doesn't touch the federation's settings or its built-in mappers (it adds only its own `portcullis-attr-<field>` mappers, §9.6, and `portcullis-setting-<attr>` mappers, §13.6). Core sets the federation's `cachePolicy` to `NO_CACHE` (realm export and `./portcullis keycloak configure`), so LLDAP group and attribute changes reach the next token.

### 9.4 One-time invites (core provides)

New users are onboarded **without a password**. The admin creates the user in the Hub and gets a one-time link. The user opens it, registers their security key, and is signed in. There are no other manual steps.

- **Endpoint.** Core (enroll) serves `POST /internal/invites` on a listener that Traefik does **not** route: `http://enroll:8444`, the `portcullis` network only.
    - Hub configuration: `HUB_INVITE_API_URL` (default `http://enroll:8444/internal/invites`).
    - Shared secret: a file of ≥ 32 characters, mounted read-only into both containers. In the Hub it is at `HUB_INVITE_SECRET_FILE` (default `/run/portcullis/invite/secret`, group 10001, 0640). Never an env var. Core keeps it in `secrets/enroll/invite-api-secret` (enroll) and `secrets/hub/invite/secret` (Hub), generated by `./portcullis up`.
- **Request.** `Authorization: Bearer <secret>`, `Content-Type: application/json`, body `{"username": "<lldap user id>"}`.
- **Response.** `201` with `{"url": "https://enroll.<domain>/invite/<token>", "expires_at": "<RFC 3339>"}`. The Hub accepts only `https` URLs with a host and no userinfo, and requires `expires_at`.
- **Errors.** Non-2xx with an optional `{"error": "<message>"}`, which the Hub shows to the admin (truncated to 200 characters). Suggested codes:
    - `401`/`403`: wrong secret;
    - `404`: no such LLDAP user;
    - `409`: refused, e.g. a protected account.
- **Semantics (core).**
    - The token is random (256 bit), stored only as a hash, single-use and expires after 72 h. Invites live in enroll's memory: restarting enroll invalidates pending ones (issue a new invite).
    - Creating an invite revokes the user's earlier unredeemed invites. A user who already has keys gets one more (core's login theme gives every new passkey a unique label); to replace lost keys, delete them first (the Hub's "Reset passkeys", or `./portcullis invite <user> --replace-keys`).
    - Opening the link (`GET`) does not use it; the page's same-origin `POST` does. Redeeming adds `webauthn-register-passwordless` to the Keycloak user (enroll's service account `portcullis-enroll`), signs the user in through the hidden Keycloak identity provider `portcullis-invite` (first login links the existing LLDAP user, never creates one), requires the passkey registration, and lands on `https://<domain>/` (the portal). The session has `acr=hwk`, `amr=[hwk]`.
    - Core's API refuses (`409`) `portcullis-hub`, `admin` and **every member** of `lldap_admin`, `lldap_password_manager`, the groups of the core subdomains in `group-gate-map.conf` and `INVITE_PROTECTED_GROUPS`: an invite hands the account to whoever holds the link, so the API secret must not be a way to take over an administrator. It looks the groups up in LLDAP and fails closed (`503`) when it can't. For invites made through this API the check is repeated when the link is redeemed and again in the identity-provider steps (authorization code, token): a user added to a protected group after the invite was created gets a "no longer usable" page, and their pending API invites are cancelled. Administrators are invited / recovered only from the server (`./portcullis invite <user>`, a loopback listener reached through `docker exec`), never through the Hub.
    - Sign-in has no password: the browser flow is passkey / client cert only. A password set through the Hub's fallback works for LLDAP's own UI and LDAP-binding apps, not for Keycloak.
- **What the Hub does.**
    - **New user (invite mode, the default).** LLDAP `createUser` with no password, group memberships, pre-import into Keycloak, then `POST /internal/invites`. The Hub sets **no** required action: the invite registers the key. If the invite secret is missing, the Hub refuses invite-mode creation before creating anything.
    - **"Send new invite"** on any user except `portcullis-hub`, `admin` and administrators.
    - **"Reset passkeys".** Removes the passkeys (§9.3), then sends a new invite (administrators: none, see below).
    - **Administrators.** The Hub computes the same administrator set as core: `lldap_admin`, `lldap_password_manager`, `INVITE_PROTECTED_GROUPS` (Hub env, same value as enroll's), and the groups of the core subdomains in `group-gate-map.conf` (Hub: `HUB_GATE_MAP_FILE`, default `$PROJECT_DIR/group-gate/group-gate-map.conf`, re-read on use).
        - It never sends invite requests for administrators. "Reset passkeys" for them skips the invite and checks this before removing anything.
        - A new user created into an administrator group is created without an invite. The Hub shows `./portcullis invite <user>` instead.
        - A `409` from core is shown as "administrators are recovered from the server: `./portcullis invite <user>`", prefixed with core's `error` text if any.
    - **Never stored.** The link is shown to the admin once (copy button). The Hub doesn't store it, log it or put it in the audit log.
- **Password fallback.** Off by default, under "Advanced". The Hub generates a 26-character random password, shown once, or the admin types one (12 to 256 characters). Optionally it adds `webauthn-register-passwordless`. The same fallback exists as "Password…" on existing users.

### 9.5 Guardrails and audit (Hub)

- **Protected accounts.** `portcullis-hub` (the account named in the `username` file) and `admin` (core's `LLDAP_LDAP_USER_DN`; Keycloak's federation and enroll bind as it with `LLDAP_ADMIN_PASSWORD`) can't be changed through the Hub at all: no delete, edit, password, invite, passkey action or group change. An invite or passkey reset for `admin` would hand the root account to whoever gets the link, so the bootstrap admin is recovered from the server only (`./portcullis invite admin`). The Hub's tests check that every user-targeting operation refuses both accounts.
- **Another administrator.** An invite, a passkey reset or a password for **another** `lldap_admin` member hands the acting admin that account. Core refuses invites for administrators (§9.4): the Hub doesn't offer them and shows "administrators are recovered from the server: `./portcullis invite <user>`". A passkey reset or a password for another administrator is allowed only with the target's username typed again (`{"confirm": "<username>"}`; without it the Hub answers `400`), and the audit entry carries `target_is_lldap_admin=true`.
- **Reserved names.** `admin` and every `portcullis-*` username (case-insensitive) are reserved: the Hub's own service account is `portcullis-hub`, and templates create internal app accounts with the prefix (`portcullis-hooks`, `portcullis-breakglass`), so a person signing in under such a name could claim that account. The Hub never creates one (`400`), lists one as importable from a CSV, sends one an invite (`409`, including a passkey reset with a new invite) or sets one's password: `SetPassword` refuses (`409`) a `portcullis-*` account even when it was made outside the Hub, for example in the LLDAP console. `portcullis-hub` itself stays a protected account (above). Usernames must match `^[a-z0-9][a-z0-9._-]{0,63}$`, stricter than LLDAP, because they end up in DNs and URLs. Group names must match `^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`, must not start with `lldap_`, and must not duplicate an existing group (case-insensitive). LLDAP's built-in groups can't be deleted.
- **Self-protection.** You can't delete yourself (`X-Forwarded-User`) or remove yourself from `lldap_admin`.
- **Last admin.** The last remaining human `lldap_admin` member (every member except `portcullis-hub`) can't be deleted or removed from `lldap_admin`.
- **Confirmation.** Deleting a user or a group and removing passkeys require the name typed again (`{"confirm": "<name>"}`).
- **Request guards.** Mutations are POST/PUT/DELETE under `/api/directory/`, behind the proxy secret (§5) and the CSRF guard (same origin, JSON body). Mutations without `X-Forwarded-User` are refused (403). Checks and changes are serialised.
- **Audit.** Every mutation, including refused and failed ones, is appended to `$HUB_DATA_DIR/audit.jsonl` (mode 0600) as one JSON object per line:

    ```json
    {"time","actor","action","target","detail","result","error"}
    ```

    `result` is `ok`, `refused` or `error`. The log never contains passwords, tokens or invite links. `GET /api/directory/audit` and the UI show the last 100 entries.

    **NEW (AI support).** Two more keys, present only on entries made through the Portcullis MCP (§15.10): `"via": "ai"` and `"client": "<azp>"` (the AI client, e.g. `portcullis-ai-claude-code`). The Hub sets them **only** from the identity the gate sent on the MCP listener (§15.7); the Hub and people listeners never read them from a request, so a browser can't forge "via AI". Everything else is unchanged: `actor` is the person, `action` exactly the HTTP handler's action name (e.g. `instance.delete`, `group.rule`, `group.add_member`), `result` `ok` / `refused` / `error`, and refusals are audited too. `GET /api/directory/audit?via=ai` returns only such entries.

    New actions, with their HTTP and MCP twins: `ai.enable`, `ai.disable`, `ai.mode` (instance, companion, before → after), `ai.providers` (an AI page instance's provider selection), `ai.credential.mint`, `ai.credential.revoke` (instance, companion, person, app-side id or count; never a credential), `ai.connection.revoke` (person, client), `ai.confirm` (§15.6: `approved`, `declined`, `expired`, `refused`; the argument digest, never arguments), `settings.ai` (Hub Settings → AI; the changed keys), `ai.provider.add`, `ai.provider.update`, `ai.provider.secret` (which field was replaced, never the value), `ai.provider.delete`. These mutations are audited too, for parity with their tools: `instance.enable`, `instance.disable`, `instance.restart`, `instance.exec` (detail: the service and the exit code, never the command's output), `app.env`, `drift.resolve`, `source.add`, `source.remove`, `source.sync` (a source's detail is `scheme://host/path` only: never credentials, query or fragment), `settings.default_policy`. `ai.credential.*` (app credentials for AI) and file sharing's `credential.*` are distinct families. Actions on app companions are not Hub actions: they are in the gate's access log (§15.8).

### 9.6 Custom fields and delegated permissions (NEW)

Portcullis now supports **custom user fields** (e.g., department, manager, cost center), **rule-based groups** (membership computed from field values), and **delegated permissions** (allowing non-admins to manage people).

#### Custom fields

- **Storage.** Custom fields are LLDAP user attributes created by the Hub using LLDAP's schema API (`addUserAttribute`). Each field has:
    - **Type:** `STRING` (LLDAP 0.6.3 limitation)
    - **Flags:** `visible=true`, `editable=false` (users cannot edit their own fields through LLDAP's UI)
    - **Name:** the field name with `_` → `-` (field `cost_center` is LLDAP attribute `cost-center`; LLDAP 0.6.3 refuses `_` in attribute names). Only the Hub's LLDAP calls and Keycloak's LDAP mapper (`ldap.attribute`) use this name; rules, `attr_<field>` claims, `X-Forwarded-Attr-<Field>` headers, CSV columns and `user-attributes.json` keep the field name. LLDAP attributes containing `_` are never a field.
- **Field types** (Hub-managed):
    - **Free text:** arbitrary string values
    - **List:** predefined values the admin maintains
    - **Person:** references another user by username (e.g., manager field for org charts)
- **Field flags** (per field):
    - **ShareWithApps** (default **on**): field values are sent to apps as OIDC claims and identity headers (§4.1, §5)
    - **Admin-only:** only administrators may edit this field (security rule: see below)
- **Visibility.** Everyone signed in can see everyone's field values and the org chart.

**Example field definitions in directory.yaml:**

```yaml
fields:
  - name: department
    type: list
    share_with_apps: true
    admin_only: false
    list_values:
      - Engineering
      - HR
      - Operations
  - name: manager
    type: person
    share_with_apps: true
    admin_only: false
  - name: security_clearance
    type: list
    share_with_apps: false
    admin_only: true
    list_values:
      - Public
      - Confidential
      - Secret
```

#### Rule-based groups

- **Group types.** A group is either **manual** (membership managed by hand) or **rule-based** (membership computed from field values by the Hub).
- **Rules.** A rule combines conditions with all/any blocks (nestable). Conditions: `is`, `is not`, `is one of`, `is empty`, and for person fields, `reports to (directly or indirectly)`.
- **Exceptions.** On a rule-based group, a person can be **added** (although they don't match) or **kept out** (although they match). Every exception requires a written **reason**, which is stored and shown.
- **Expiry.** Any membership (exceptions, and members of manual groups too) can have an **expiry date/time**. When a membership expires, the person is removed automatically, and the Hub writes the expiry into the policy file's `expiring` array (§4) so group-gate enforces it strictly.
- **Reconciliation.** The Hub writes computed membership into the real LLDAP groups. group-gate, Keycloak and apps treat rule-based groups exactly like manual groups. Re-evaluation happens on every detail change, rule change, import, exception change, and **periodically at most every 60 seconds** (binding). group-gate enforces `expiring` entries exactly regardless of the Hub's reconcile cadence.
- **Audit.** Every membership change from rules, expiry or import is audited with its cause.

**Example rule (conceptual; stored in directory.yaml):**

```yaml
groups:
  - name: nextcloud_milan
    type: rule
    rule:
      all:
        - field: office_location
          op: is
          value: Milan
        - field: department
          op: is_one_of
          values: [Engineering, Operations]
    exceptions:
      - user: jsmith
        mode: added
        reason: "Contractor working with Milan team"
        added_by: admin
        added_at: "2026-11-01T10:00:00Z"
```

#### Hub-private state: directory.yaml

The Hub stores field definitions, rules, exceptions, expiries and permission grants in `directory.yaml` under `$HUB_DATA_DIR`. This file is:

- **Atomic** (like `state.yaml`): corrupt file = refuse to start.
- **Never exposed** to clients or other repos.
- **LLDAP holds only:** user attribute schemas (name, type, flags) and current values; group membership (reconciled by the Hub for rule-based groups).

#### Delegated permissions

Three permissions can be granted to groups (manual or rule-based):

1. **`edit_details`**: edit user fields, bulk import (CSV review + apply)
2. **`invite`**: create new users via invite link (with no group memberships)
3. **`remove`**: delete users

- **Grants.** Each permission is granted to an LLDAP group the admin picks. Members of that group (non-admins) get the permission. Admins always have all permissions.
- **Scope.** Delegation is global for now (all users, subject to the constraints below). Scoped delegation (e.g., "HR Milan edits only Milan people") is a non-goal for this release.
- **Protected targets.** Delegates may **never** target:
    - Themselves (`X-Forwarded-User`)
    - The service account (`portcullis-hub`)
    - The bootstrap `admin`
    - Any member of `lldap_admin`, `lldap_password_manager`, `INVITE_PROTECTED_GROUPS`, or the core-subdomain groups in `group-gate-map.conf`
    - Any member of a permission group
- **Delegate invite constraints:**
    - A delegate's invite creates a user with **no groups** and **no password**. The new account is marked `created_by: <delegate username>`.
    - With `edit_details`, delegates can fill in fields, making the person match rules. This is visible: the audit records the inviter, and rule memberships show "via rule, account created by X".
    - Delegates can **re-invite** (send a new invite link) only accounts they created (`created_by` matches) that still have **zero Keycloak credentials** (no passkeys, no password). An admin taking over an account (setting a password, resetting passkeys, or sending an invite) clears `created_by`, so delegates can no longer re-invite it.
- **Manual groups, exceptions, expiries.** Delegates may not modify membership of manual groups, add exceptions, or set expiries. These are admin-only.
- **Security rules:**
    - **Reserved attribute prefix.** Custom field names may not start with `ps_` (LLDAP attribute `ps-…`). That prefix is reserved for Hub-managed setting claim attributes (§8, §13.6).
    - **App admin groups** (§13): groups that carry per-group values of a privileged option become **guarding groups** (exactly like `admin_<id>` today). They get the same restrictions: rules on admin-only fields only, no rule matching an empty person, the evaluator never adds `created_by` accounts. An admin-only field they use can't be turned off. The Hub computes these groups on the fly from the current settings (no `directory.yaml` field); removing the per-group row ends the guarding at once.
    - Rules of **protected groups** (`lldap_admin`, `lldap_password_manager`, `INVITE_PROTECTED_GROUPS`, core-subdomain groups), **permission groups**, and **path-admin groups** (`admin_group`, `path_groups` admin access) may only reference **admin-only** fields. A field used by such a rule cannot lose its admin-only flag.
    - A rule of such a group must also **not match a person with no field values** (every new account): refused with 409.
    - The evaluator **never adds** an account still marked `created_by` (a delegate created it, no admin has acted on it since) to such a group; it reports it instead.
    - Built-in groups (`lldap_admin`, `lldap_password_manager`, `INVITE_PROTECTED_GROUPS`, core-subdomain groups) can never be rule-based.
- **Deleting a group** deletes it in LLDAP first, then removes its rule, exceptions, expiries, grace entries and permission grants from `directory.yaml`; creating a group purges any leftovers for that name first. A re-created group inherits nothing.

**Example permissions in directory.yaml:**

```yaml
permissions:
  edit_details:
    granted_to: hr_team
  invite:
    granted_to: hr_team
  remove:
    granted_to: hr_managers
```

#### Fields reach apps

- **Native-OIDC apps:** The Hub creates a Keycloak client scope `portcullis-attributes` with LDAP attribute mappers and protocol mappers for each shared field. Each field becomes a claim `attr_<field>` (e.g., `attr_department`) in **access tokens, ID tokens and userinfo**. The scope is a **default client scope** on Hub-registered clients (always included).
- **Forward-auth and header-auth apps:** The Hub writes `user-attributes.json` (§4.1); group-gate returns `X-Forwarded-Attr-<Header-Name>` headers (§5); the `portcullis-groups` middleware forwards them.

## 10. Landing portal app list (Hub → core)

- **File.** The Hub writes `portal-apps.json` atomically into `hub_data` (`/data`, next to `group-gate-policy.json`, mode 0644) whenever it writes the policy file (enable, disable, template sync, settings). A core landing portal reads it like group-gate reads the policy file: mount `hub_data` read-only.
- **Endpoint.** `GET /api/portal/apps` returns the same document, behind the proxy secret like every other Hub route.
- **Format, version 1.**

    ```json
    {
      "version": 1,
      "domains": ["team-b.example.org"],
      "apps": [
        {
          "id": "grafana-team-b",
          "template": "grafana",
          "name": "Grafana (grafana-team-b)",
          "description": "…",
          "icon": "📊",
          "category": "monitoring",
          "urls": [{"label": "Dashboards", "url": "https://grafana.team-b.example.org"}],
          "auth_method": "header-auth",
          "access_group": "users_grafana-team-b",
          "admin_group": "admin_grafana-team-b"
        },
        {
          "id": "immich",
          "template": "immich",
          "name": "Immich",
          "description": "…",
          "icon": "📷",
          "category": "media",
          "urls": [{"label": "Photos", "url": "https://photos.portcullis.example.com"}],
          "auth_method": "native-oidc",
          "access_group": "users_immich",
          "admin_group": "admin_immich"
        }
      ]
    }
    ```

    - Only enabled apps whose template is present are listed, sorted by `id`.
    - **NEW (instances):** one entry per enabled instance (§11). `id` is the instance id and `template` the template id; for the default instance both are the template id. `name` is the template's name, followed by ` (<instance-id>)` for other instances.
    - `{{DOMAIN}}` and `{{HOST_<ROUTER>}}` in URLs are already expanded (the instance's hostnames).
    - **NEW (domains):** `domains` lists, sorted, every enrolled domain (§12) on which at least one listed instance has a hostname.
    - `access_group` is the group group-gate requires (`auth.group_access`); `""` means any signed-in user.
    - `admin_group` is informational.
    - **NEW (file sharing):** a router-less instance (§3) has `"urls": []` and a `note`: the first paragraph of the template's `auth.notes` (up to its first blank line, trimmed) when it is at most 300 runes, else `"No web page."` (also when `auth.notes` is empty). `note` is always present on router-less entries and only on them.
- **Rendering.** The portal filters by the signed-in user's groups (`X-Auth-Request-Groups`) and must escape every field. An unknown `version` means: show nothing. An entry with `urls: []` is rendered as a card with its name, icon, description and `note`, and no link.
- **Core's portal** is group-gate's `/portal` at `https://<domain>/` (router `portal`: forward-auth, then `replacePath`). It reads `/hub-data/portal-apps.json`, shows only `https` URLs whose host is on the main domain or on a domain in `domains` (url-less entries as above), and adds the Hub, the Keycloak realm console, enrollment, LLDAP and Traefik for `lldap_admin`, plus every user's passkeys (account console) and certificate (`enroll.<domain>/self`).

## 11. App instances (Hub) — NEW (instances)

A template can run as several fully separate **instances**. Each instance has its own compose project, containers, volumes, settings, env and generated secrets, Keycloak clients, groups, auth policy, public exceptions, sign-in mode, drift tracking and last-operation record. Instances share nothing; only the read-only template files under `<core>/templates/<app-id>/` (§3) are common. Every instance operation is admin-only and audited (§11.7).

### 11.1 Instance ids and the default instance

- **Default instance.** Every enabled template has a default instance whose id **is the template id**, so it follows the template-id rule of §3, not the instance-id one. Its project, files, hostnames, groups, Keycloak clients, volumes and policy keys are exactly what a single deployment of the template uses, so existing state is the default instance as-is.
- **Other instances.** Their ids match `^[a-z][a-z0-9]*(-[a-z0-9]+)*$`, at most 31 characters (a DNS label in the Hub's id shape, §3: no `_`, no `--`, no trailing `-`, no `portcullis` segment). The Hub suggests `<template>-<suffix>` (e.g. `grafana-team-a`). An id must not start with `portcullis`, and must not equal any template id of any source (those are the default instances' ids) or another instance's id.
- **Collisions are refused** (`409`) before anything is created: a compose project, volume name, Keycloak client id or group name (case-insensitive) derived from the id (§11.2) that already exists and doesn't belong to this instance, or that equals a name the **default instance of any template of any source** would use (its volumes — `portcullis_<key>` for `multi`, a `single` template's declared names —, manifest `client_id`s, `access_group`, `admin_group` and Traefik names), enabled or not. The ids of instances whose template is missing keep `portcullis_<id>-*`, `<id>-*` and `<id>_*` reserved; an enabled instance whose template is missing also keeps the volume names, Keycloak client ids and Traefik names of its published snapshot. In the catalog, enabled templates claim volume and Traefik names first, then templates whose default instance has any other state (settings, policies, public access, sign-in mode, published snapshot, ops record), then the rest in source order. Creating an instance (and restoring into a new id) also lists the Docker volumes: an existing volume with one of the new instance's volume names, or labelled with its compose project, is a `409` — a new instance never adopts a deleted instance's leftover or anyone else's volume.
- **`instances: single`** templates have only the default instance (§3.1).

### 11.2 Derived names

| What | Default instance (id = template id) | Other instance `<id>` |
|------|-------------------------------------|-----------------------|
| Compose project | `portcullis-<template>` | `portcullis-<id>` |
| Hub files | `<data>/env/<template>.env`, `<data>/overrides/<template>.override.yml`, `<template>.user.yml`, `<data>/ops/<template>.json` | the same with `<id>` |
| Volume `<key>` | `multi`: `portcullis_<key>`; `single`: its declared `portcullis_<template-id>[-_…]` name, else `portcullis-<template>_<key>` | `portcullis_<id>-<key>` |
| Traefik routers, services, middlewares the template defines | the template's names | `<id>_<name>` (§3.1) |
| Public router / strip middleware | `portcullis-public-<template>`, `portcullis-public-strip-<template>` | `portcullis-public-<id>`, `portcullis-public-strip-<id>` |
| Keycloak clients | the manifest's `client_id`s | first `keycloak_clients` entry: `<id>`; each further entry: `<id>-<manifest client_id>` |
| Access group | manifest `access_group` | `users_<id>` |
| Admin group | manifest `admin_group` | `admin_<id>` |
| `PORTCULLIS_INSTANCE` | `<template>` | `<id>` |

- The Hub's override sets every volume's `name:` from this table for `multi` templates (which declare none), default instance included; a `single` template's volumes keep what compose names them.
- Creating an instance generates fresh values for every `generate: random` env entry, and creates `users_<id>` (if the manifest has `access_group`) and `admin_<id>` (if it has `admin_group`) in LLDAP as empty manual groups. The Hub tags each Keycloak client with the **instance id** that owns it and reconciles only clients with its own tag.
- **Enabling** an instance (`POST /api/templates/enable` with `{"id": "<instance-id>"}`, the default instance included) first creates its missing access / admin groups, but only derived names: `users_<id>` / `admin_<id>` for an instance; for a default instance the manifest's `access_group` / `admin_group` when they are exactly `users_<template>` / `admin_<template>`. They are created through the Users & Groups guardrails (`CreateGroup`, audited as `group.create`) as the enabling admin, who must resolve as an LLDAP administrator before anything is created. Existing groups are left alone; a missing group with any other name is never created (a warning). A failure creating a group leaves the instance not enabled (groups created before it stay). Without an `X-Forwarded-User` or without Users & Groups nothing is created (a warning). The enable runs in the background (§11.7): **NEW (operation progress)** it answers `202`; an unknown instance is `404`. The groups it created are listed in its op record's `created.groups` and the `groups` step's `detail` (with the ones that already existed), its warnings in `warnings`, and groups created also in `result.groups_created` (comma-separated) in the final record. **The synchronous route answer no longer has `groups_created` or `status` fields; they live in the record.** Stopping the enable deletes exactly the groups in `created.groups` (§11.7 "Stop"). A missing access group only ever denies (§8, fail closed). **Lifecycle audits** (`instance.enable`, `instance.disable`, `instance.restart`) are now written when the op ends: a failed enable is audited `error`, a stopped one `refused`.
- Settings, auth policies, public exceptions and share tokens, sign-in mode, the fail-closed `published` snapshot, ops records and drift are keyed by instance id.
- **Instance states.** `created` (exists, never started: `POST /api/instances` creates without enabling), `enabled` (the project is up), `disabled` (stopped, everything kept), `deleting` (a guarded delete started and hasn't finished, §11.4), `restoring` (a restore started and hasn't finished — same instance, or a new id being restored into, §11.6), `error` (the last lifecycle operation failed; its ops record says why).

### 11.3 Hostnames

- **Pre-filled.** For a new instance on domain `<domain>`, each host router with default subdomain `<sub>` (§3.1) gets `<sub>-<suffix>.<domain>`, where `<suffix>` is the instance id without a leading `<template>-` (the whole id if it has no such prefix). If the label `<sub>-<suffix>` would be longer than 63 characters, the suffix is truncated to fit (a trailing `-` dropped); if the hostname is then still not a valid hostname (§4), creation is refused with an error that names the host router and asks for an explicit hostname. `grafana-team-a` on `portcullis.example.com` → `grafana-team-a.portcullis.example.com`; an instance `litellm-lab` → `llm-lab.<domain>`. The default instance's hostnames are `<sub>.<main domain>`. Every hostname is individually editable.
- **Immutable hostnames.** A host router listed in the manifest's `hosts.immutable` (e.g. Synapse's `server_name`) keeps the hostname the instance was created with: creating an instance (or restoring into a new id, §11.6) may set it, every later change is refused (`409`), the default instance's too. The default instance's immutable hosts start as `<sub>.<main domain>` and are **pinned in `state.yaml` on its first enable**. A later change of Portcullis's main domain never moves them: the instance keeps its old hostnames and is listed as `error` (fail closed, through its published snapshot) until the old domain is enrolled as an extra domain (§12) or the hostnames are fixed — their data is bound to the old name.
- **Valid hostnames.** A hostname is a valid hostname (§4) and either lies on an **assignable** enrolled domain `<d>` (§12.3) — `<d>` itself or `<label>.<d>`; enrolled domains never nest (§12.3), so at most one matches — or, if it is at or under no enrolled domain, is a main-domain host `<label>.<main domain>`. `<label>` matches `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`. Deeper names are refused: the wildcard certificates cover one label. An enrolled subdomain of the main domain (e.g. `team-a.<main domain>`) is assignable as its own apex only as an extra-domain host, on that enrolled domain.
- **Refused before anything changes** (`400` invalid, `409` collision): a hostname that is invalid, on a domain that isn't enrolled or isn't assignable, a core host (§4), used by any other instance (enabled or not), still routed by another instance's running compose project (the Hub's runtime view; `409` "still routed by the running project of `<id>` — restart or stop it first"), or used twice within the instance. Templates still using `${PORTCULLIS_DOMAIN}` rules (§3.1) can't change hostnames at all (`409`).
- **Hostnames a router can't serve** are a `400` at create, hostname change and restore into a new id (not only at enable): a router whose hosts mix main-domain and extra-domain hostnames, and a router on extra-domain hosts that reaches `portcullis-auth` through the template's own chain middlewares (nested chains included, with or without `@docker`). The extra-domain sign-in (§5) swaps only a `portcullis-auth@docker` (or bare `portcullis-auth`) listed on the router itself, so templates list it on the router, never inside a chain.
- **A change applies immediately.** In order:
    1. **Validate** (the refusals above): nothing has changed yet.
    2. **Keycloak**: the instance's clients' redirect URIs and web origins, the `portcullis-forward-auth` callback URIs (§5) and (**NEW**, AI support) the audience and consent text of its companions' `mcp:*` scopes (§8) are updated for the new hostnames.
    3. **Env and override**: the instance's `.env` and compose override are regenerated with the new hostnames.
    4. **Save state — the commit point.** The Hub records the new hostnames in its state. A failure before this step leaves the recorded hostnames, the policy file and the routing as they were; retrying the change reconciles Keycloak, env and override.
    5. **Policy**: the policy file, `portal-apps.json` and `mcp-gate.json` are rewritten (the old hostnames vanish from them at once; a companion's resource URL moves to the new host).
    6. **Restart** the instance (`compose up`).

    Public share links keep their tokens and move to the new host. **There are no redirects:** the old hostnames stop routing. A step that fails after the commit point is reported like any lifecycle operation (`OpError`, op `hosts`), and the instance is reconciled by retrying the change: the same hostnames again re-apply every step while the last **hostname-change** record (`<data>/ops/<id>.hosts.json`, kept apart from the instance's other op records) is a failure — another operation in between doesn't hide it.
- Audited as `instance.update` with the old and new hostnames.

### 11.4 Guarded delete

Deleting an instance is permanent and needs the instance id typed: `{"confirm": "<instance-id>"}` (missing or different: `400`). The acting admin must resolve as an LLDAP administrator (it deletes the groups); otherwise the delete is refused before step 1. The Hub:

1. **Takes a backup** (§11.5, reason `delete`). If it fails, the delete stops and nothing is removed.
2. Records `deleting` (and the backup path) in its state and marks the instance disabled. From here on the instance is listed as **partially deleted** until the delete completes, and the only action offered is Delete (retry).
3. Stops and removes the project (`down --remove-orphans`) and marks it disabled (the policy file drops it). Up to here the delete can be stopped (§11.7 "Stop"). The **point of no return** is the first volume removal: from the start of the `volumes` step the op record is `point_of_no_return: true` and Stop is refused. In that step the Hub first removes its per-person secrets (`<secrets>/<id>/` on `hub_secrets` and its credential metadata, §13.16; each active credential audited `credential.revoke_leave` reason `deleted`, actor the deleting admin), so a delete that fails later leaves no credential behind, then (**NEW**, AI support) removes its AI state: every AI credential entry of the instance in `mcp-credentials.json` (each audited `ai.credential.revoke` with detail `id <id> reason deleted`, actor the deleting admin; no revoke hook runs — the project is down and the app's tokens go with its volumes), its `app_oauth` record (`oauth-seen`, **NEW**) and its `AIInstances` entry (**NEW**, `state.yaml` `ai_instances`), rewriting the gate file so its resources vanish; then removes its volumes: the volumes compose labelled with the project (`com.docker.compose.project=portcullis-<id>`); external volumes aren't the instance's and are never removed.
4. Removes its access roles and access flows (§8 "Access role"), deletes its Keycloak clients (only clients tagged with this instance; any other is kept with a warning), its `mcp:<instance-id>.*` scopes (§8; **NEW**, AI support) and the callback URIs of its hosts on `portcullis-forward-auth`.
5. Deletes its access and admin groups through the Users & Groups guardrails (`DeleteGroup` as the acting admin, which also purges the group from `directory.yaml` and signs former members out) — only groups named exactly `users_<id>` / `admin_<id>`. Kept, with a warning: a group with any other name (a manifest's own group of a default instance), a built-in, administrator, permission or rule group, and a group another instance or another template's default instance also uses (templates may share a group). Without Users & Groups (no LLDAP credentials) the groups stay, with a warning. Without Keycloak configured step 4 is a warning. An instance whose template is missing and whose snapshot lists no clients gets its derived first client id (`<id>`) deleted, with a warning.
6. Removes its env file, overrides, ops record, generated secrets, share tokens and state entry, and rewrites the policy file and `portal-apps.json`.

Every step is idempotent. **Stopping a delete** before its point of no return cancels it and puts the app back as before: the `deleting` record is cleared, the instance is enabled again if it was enabled (exactly like an enable) and the delete's backup stays listed; the per-person secrets, AI state, volumes, clients and groups were not touched yet. A failure after step 2 is reported like a lifecycle failure (`OpError`, op `delete`); the instance stays `deleting` (enable, drift start/apply, settings, env, custom override, hostname changes, backup and same-instance restore are refused with `409`). A retry skips step 1 (the first backup is kept) and continues where the last attempt failed. Backups are not removed with the instance: they stay listed (`GET /api/backups`) and can be restored into a new instance (§11.6). Audited as `instance.delete` with the backup path. Disabling an instance stops it and keeps everything, except the callback URIs of its extra-domain hosts on `portcullis-forward-auth` (enable adds them back); its Keycloak clients and access role stay (the access role keeps denying sign-in to anyone outside the access group).

The **default instance** can be deleted the same way. That removes the manifest's `access_group` and `admin_group` (by convention `users_<template>` / `admin_<template>`) through the same guardrails; the template stays in the catalog and enabling it again creates a fresh default instance.

### 11.5 Backups

- **When.** On demand (`instance.backup`), before every delete and before every restore.
- **Path.** `<data>/backups/<instance-id>/<UTC timestamp>.tar`, the timestamp as `YYYYMMDDTHHMMSSZ` (e.g. `<data>/backups/grafana-team-a/20261102T153000Z.tar`). Written to a temporary name and renamed when complete; files `0600`, directories `0700`, owned by the Hub (uid 10001). Never pruned automatically.
- **Consistency.** A running instance is stopped (`compose down`, volumes kept) while its volumes are copied, then started again (not for the backups a delete or restore takes), so databases — SQLite included — are copied at rest. Manifests have no field marking database files, and none is needed while the app is down. A failed backup writes no archive and starts the instance again.
- **Free space.** A backup needs at least 64 MiB free on the Hub's data volume before it starts (otherwise `507` and nothing is stopped), and the staged size plus 64 MiB before the archive is assembled (otherwise `507` after the volumes were copied: no archive is written and a manual backup starts the instance again, as after any failed backup); staging an archive for a restore needs its size plus 64 MiB (otherwise `507` before anything changes).
- **Stop** (§11.7). Stopping a manual backup deletes the partial archive (the `.partial` file and the staging directory) and starts the instance again if it was running; no archive is listed.
- **Leftovers.** At startup the Hub removes helper containers (label `io.portcullis.hub.helper`), staging directories and `.partial` archives an interrupted backup or restore left behind.
- **Helper.** Volume I/O goes through a helper container per volume, through the Hub's socket proxy (§6): image `alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a` (the same pin as core's `PORTCULLIS_HELPER_IMAGE`), pulled if missing, **created but never started** — the daemon itself reads (`GET /containers/{id}/archive?path=/data`) and writes (`PUT …?path=/` with `noOverwriteDirNonDir`, owners as archived) the one volume it mounts at `/data` (no copy-up). It has no network (`none`), every capability dropped, `no-new-privileges`, uid 65534, a pids and memory limit, and is removed afterwards. Backup helpers mount the volume read-only and have a read-only rootfs; restore helpers need a writable rootfs, because the daemon refuses an upload to `/` of a read-only rootfs and only an upload to `/` applies the volume root's own owner and mode. Restore replaces a volume's contents by removing it and creating it again with the same driver and labels — only plain `local` volumes without driver options (a bind or NFS device's data would survive the remove; otherwise `409`).
- **Layout** (an uncompressed tar):

    ```text
    MANIFEST.json
    config/instance.yaml       # the instance's state entry: template, hostnames, settings, auth policy,
                               # public exceptions and share tokens, sign-in mode, published snapshot
    config/env                 # <data>/env/<instance-id>.env (generated secrets included)
    config/override.yml        # the Hub override as last applied
    config/user.yml            # the custom override, only if there is one
    config/ai.json             # NEW (AI support): the instance's AI state (below), only for templates with ai.mcp or ai.chat
    volumes/<volume key>.tar   # one inner tar per volume as the daemon's archive endpoint writes it: entries
                               # "data/" (the volume root) and "data/…"; numeric uid/gid, modes and mtimes preserved
    ```

    `MANIFEST.json` is the first tar member; the other members follow sorted by path (byte order). It lists the sha256 (lowercase hex, 64 characters) of every other member:

    ```json
    {
      "version": 1,
      "instance": "grafana-team-a",
      "template": "grafana",
      "template_commit": "170866c0f2…",
      "created_at": "2026-11-02T15:30:00Z",
      "reason": "manual",
      "volumes": {"grafana-data": "portcullis_grafana-team-a-grafana-data"},
      "files": {
        "config/env": "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752",
        "config/instance.yaml": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "config/override.yml": "fd61a03af4f77d870fc21e05e7e80678095c92d808cfb3b5c279ee04c74aca13",
        "volumes/grafana-data.tar": "a3f5c2a4d1e6b7c8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2"
      }
    }
    ```

    `reason` is `manual`, `delete` or `restore`; `volumes` maps each volume key to the volume name it was copied from (the volumes compose labelled with the instance's project; an instance that never ran has none); `template_commit` is the template checkout's git commit and is left out when unknown. Members are written with mode `0600`. `config/instance.yaml` holds `id`, `template`, `default`, `hosts`, `enabled`, `settings` (the typed settings as in §13, person-entered values included), `auth_policy`, `public_access`, `public_mode`, `public_tokens`, `sign_in` and `published`. `config/settings-secrets.json` (also in `config/`) holds the secret store. Restore drops per-group rows whose group id no longer matches (warning).
- **AI state (NEW, AI support).** `config/ai.json` is the instance's `AIInstances` entry (**NEW** state, `state.yaml` `ai_instances`, §15.11): `{"companions": {"<name>": {"enabled": <bool>, "mode": "read_only|read_write"}}, "providers": ["<provider name>", …]}`. It never holds a credential, a caller secret, an `oauth-seen` record or a provider secret: AI credentials live only in `mcp-credentials.json`, encrypted to the gate, and are minted again lazily; provider variables in `config/env` are blanked by name like secret options (§15.12).
- **Shared folders are not backed up.** An instance backup copies the instance's volumes only. Shared folders (§14) and every other host path a `path` option mounts are host data: their contents are never in an archive. A `folder:<id>[/<subpath>]` value is a setting and is archived as text in `config/instance.yaml`, like a host path. The folder definitions and permission snapshots (§14.4) live in the Hub's state and `<data>/folder-snapshots/`, not in instance archives.
- **Per-person credentials (NEW, file sharing).** No instance archive contains a `person_secret` hash, its credential metadata (`config/instance.yaml` has no `credentials` key) or anything from `hub_secrets`: that volume is external to the instance's project, so it is never archived, replaced or removed by a backup, restore or delete of the instance. No stored digest holds hash bytes (§13.16). The Hub-wide person ids (§13.16) live in `state.yaml`, not in instance archives.
- **Offsite.** Core's `./portcullis backup` archives the `hub_data` volume, so `<data>/backups/` is included (and shipped with `--offsite`), and so are `<data>/folder-snapshots/`, the folder definitions and the person-id pools in `state.yaml`. Credential metadata stays in core backups: it lives in `state.yaml` and holds no secret, and on a core restore the epoch check voids it (§11.6). Hashes and the secrets volume are never in a backup: core's backup never copies `hub_secrets` (it lists the volumes it copies by name; core's tests assert that `hub_secrets` isn't one of them).
- The archive contains the instance's generated secrets in clear; it is protected like the rest of `hub_data`.

### 11.6 Restore

A backup restores into the **same** instance (replacing its data) or into a **new** instance id. Audited as `instance.restore` with the archive and the target.

- **Checks first, nothing changes on failure:** `MANIFEST.json` is the first member and its `version` is 1; every listed file is present once, as a regular file, with a matching sha256 and there are no unlisted files; every volume archive's entries lie under `data/` (no `..`, no device files, hard links inside the volume); `config/instance.yaml` names the manifest's instance and template (any mismatch: `409`, refused). The archive's settings, sign-in mode, policy override and public exceptions must pass the same checks as saving them in the Hub's settings, against the template as it is now (`409` listing every problem). The archive is unpacked to a staging directory under `<data>/backups/.staging/` and verified there before anything else happens. The template exists and has every archived volume key. For a new id: the id rules and collisions of §11.1 (Docker volumes included), the template must be `multi`, and the hostnames (below) must be placeable and free, validated like a create (§11.3).
- **Same instance** (`POST /api/instances/{id}/restore`). The Hub takes a backup (reason `restore`) and stops the instance. It replaces every volume's contents, the env (`config/env`), the custom override (`config/user.yml`, removed if the archive has none) and the instance's state from `config/instance.yaml`, **except its hostnames: the current hostnames are kept**. The Hub override is **regenerated**, not restored (`config/override.yml` is informational). Before the first destructive step the Hub records `restoring` with the pre-restore backup in its state and marks the instance disabled; while `restoring` the instance is refused like a `deleting` one (`409`) and listed with state `restoring`. A restore the Hub didn't finish (it stopped half-way) is rolled back from that pre-restore backup at the next start or by the next restore of the instance — only if the recorded archive is the instance's own pre-restore backup (its directory and manifest name the instance, its template is the instance's, its reason is `restore`) and verifies; otherwise `409` and nothing is touched. The record is cleared when the restore or the rollback completes (an instance that was `created` stays `created`); a failed save of that is reported as a warning. Deleting a `restoring` instance warns with the pre-restore backup's name. A restored policy is stored normalised (a legacy factor rewritten, never weaker); public exceptions that can't be routed are refused like on save. The project's volumes the archive doesn't have are emptied (warning; their data is in the pre-restore backup). Then, if it was enabled, the Hub enables it again exactly like an enable (the Keycloak clients with the restored secrets, access role, forward-auth callback URIs, policy file and `portal-apps.json`, `compose up`); a disabled instance stays disabled. If any step fails, it puts the pre-restore backup back the same way (volumes it lacks are emptied) and reports the failure (`OpError`, op `restore`, `rolled_back: true`): the instance's previous data is kept.
- **New id** (`POST /api/instances/restore`), from any listed archive, including one of a deleted instance; the deleted instance's id may be reused. The Hub creates the instance from the archive's config with: the hostnames given in the request's optional `hosts`, otherwise the archive's hostname for each `hosts.immutable` router (an immutable router given a different hostname is a `409`) and the new id's defaults on the main domain (§11.3) for every other router, new empty groups `users_<id>` / `admin_<id>` (created through the Users & Groups guardrails; an existing group is kept with a warning — its members get access), new volumes (labelled with the new project) filled from the archive, the archive's settings, policy, public exceptions and share tokens, sign-in mode, custom override and env with the instance variables rewritten, except each Keycloak client's `secret_env`, which is regenerated. Its Keycloak clients are created when it is first enabled, as for any instance. `type: path` settings keep the same host path: the result warns that the two instances share that directory. The acting admin must resolve as an LLDAP administrator before anything is created. A volume is only filled if it really is new (it must not exist before, and must carry the new project's labels after creation). Setuid/setgid bits and every other mode bit are restored as archived (archives are written by the Hub). A failure after the instance was created removes it again (state, files, the volumes and groups it created). While it runs the new instance is in state `restoring` (`restore_as: <archive>` in `state.yaml`), and `created` (not started) once it completes — it is never started on its own: an admin enables it (which also creates any of its groups still missing); a restore into a new id that the Hub didn't finish is removed at the next Hub start (project volumes, files, per-instance state and the entry; the groups it may have created stay and are logged, as there is no acting admin at start-up).

- **Stop** (§11.7). Stopping a same-instance restore rolls it back from the pre-restore backup exactly like a failure (`rolled_back: true`); stopped before the pre-restore backup was taken, nothing has changed and nothing is rolled back. The pre-restore backup stays listed. Stopping a restore into a new id removes the new instance completely, like a failure after it was created (state, files, and the volumes and groups in the op record's `created`).

- **Shared-folder values** (§14), both restores. Before the checks above, every setting value that names a shared folder that doesn't exist (`folder:gone`) is cleared (the option is back to its default), with the warning "setting <key> named shared folder <id>, which doesn't exist; cleared". A restore never runs the folder fixer and changes nothing on disk.
    - **Same instance:** values naming an existing folder are kept; the next `up` mounts the folder with its group as for any assigned instance (§13.15).
    - **New id:** folder values are **kept** (it is the same host data). The new instance gets folder access without an assignment preview, so the result warns "instance <new id> now uses shared folder <name> (read-only)" or "(write, as its template declares)". An admin's write confirmation for a template without a `folder` block (§13.15) is per instance and is **not** copied: such a use is mounted read-only until an assignment confirms write again. The doctor's config checks, computed on every `GET /api/doctor`, show any `exclusive` conflict (§14.5).

- **Per-person credentials (NEW, file sharing; §13.16).** Any restore voids every credential of the instance: a restored hash could revive a password someone regenerated because it leaked.
    - **Same instance:** after the volumes are replaced and **before** the instance is enabled again, the Hub removes every hash file of the instance and marks each active credential `voided` (`reason: restore`), so the restored start never sees an old account. A restore rolled back before the void step voids nothing; credentials voided before a later rollback stay voided.
    - **New id:** the new instance has no credentials (archives carry none) and nothing is audited.
    - **Audit:** one `credential.void_restore` per instance with the count only (`count=N`), only when N > 0. My apps then shows "Your password was reset by a restore on <date>; create a new one" (status `voided`).
- **AI support (NEW).** Any restore may bring back an app database holding `portcullis-ai-*` credentials the gate no longer knows, so:
    - **Same instance:** the instance's AI credential entries are deleted before the volumes are replaced; the archive's AI state is restored; before any of its companions is in `mcp-gate.json` again, the Hub runs each companion's `revoke` hook with `revoke_all` (§15.5) in the restored app. A companion whose `revoke_all` fails stays out of the gate file (switched off, the error on its AI tab and in the op record) until a switch-on succeeds. `app_oauth` companions get `revoke_all` too, and the people revoked since the backup are revoked again for every `app_oauth` companion, whether it ends on or off (§15.5 `app_oauth` leavers).
    - **New id:** every companion starts **off** (the archive's modes and provider selection are kept). Switching one on runs `revoke_all` first (§15.5), which covers the tokens copied from the archive's app database. For an `app_oauth` companion the Hub records the people the source instance's record knew (holders, revoked, unmatched) as copied, with a warning naming how many. Residual: the copy holds their app accounts; those outside the new instance's population are listed as unmatched until an administrator deals with them in the app, and their non-AI app tokens remain until then.
    - **Restored off, with a warning** (either kind of restore): a companion whose archive state says on while the master switch is off, the template now has `ai.unsupported`, the effective policy reaches LoA 3, the companion no longer exists in the template (dropped), or its mode is outside `modes` (the default mode is kept, off). A `Pruned` companion (a template update's `revoke_all` still owed) stays off. An undecodable `config/ai.json` restores AI support off with a warning, never a refusal. After a failed `revoke_all` the companion is switched off (audited `ai.disable`, detail `restore: revoke_all failed`) and the op record is `ai`.
    - The archive's provider selection is checked provider by provider against the selection rules (§15.12): one that no longer passes is dropped with a warning.
    - Provider variables are rewritten from the provider store for the restored instance's own selection only (§15.12).
- **Core restore (`./portcullis restore`) empties `hub_secrets`** (removes the volume and creates it again with core's project labels, root `10001:10001 0700`) before the Hub starts. The Hub detects it, and any other mismatch between `state.yaml` and the volume, with the **secrets epoch**:
    - the Hub writes a random epoch (16 random bytes, hex) both into `state.yaml` (`secrets_epoch`) and into `<secrets>/.epoch`, and rotates it on **every** credential mutation (create, regenerate, revoke, void): the volume file first, then `state.yaml`. A failed `state.yaml` save keeps the in-memory epoch equal to the volume's and answers `500`;
    - at boot and before every `credentials:<key>` delivery unit (§13.12) it compares them. `.epoch` missing or different (a core restore, a restored `state.yaml` next to a newer volume, a new volume, a crash between the two writes) → every credential of every instance is voided (`reason: restore`, audited `credential.void_restore` per instance with its count), the volume is emptied, and a new epoch is written to both. Then hash files without active metadata are deleted and active metadata without a hash file is voided;
    - a mismatch found in the middle of a run (before a `credentials:<key>` unit) also applies, for every instance it voided, the revocation's live steps (§13.16 "How it is applied": the hooks within 8 s, else the kill);
    - on that mismatch it also advances every person-id pool's next id by 1000 before any allocation (logged), so a pool restored from an older `state.yaml` never hands out a uid that files on disk may already carry (§13.16);
    - a crash in the middle of a credential mutation therefore voids every password (fail closed, accepted). People create new ones on My apps.

### 11.7 Hub API and audit

Instance and domain operations live on the Hub listener only (never on the people listener, §5.1), are **admin-only** (`lldap_admin`; delegates get `403`) and pass the proxy-secret and CSRF guards. Each one is appended to `audit.jsonl` (§9.5) as one of `instance.create`, `instance.update`, `instance.delete`, `instance.backup`, `instance.restore`, `<op>.stop` (a Stop, below: e.g. `enable.stop`, `delete.stop`), `domain.enroll`, `domain.token`, `domain.delete` (**NEW**, AI support: also `instance.enable`, `instance.disable`, `instance.restart`, `instance.exec`, `app.env`, `drift.resolve`, and the AI actions of §9.5), with `result` `ok`, `refused` or `error`. AI routes: §15.11. DNS credentials never appear in audit entries, logs, errors or responses.

| Route | Body | Does |
|-------|------|------|
| `GET /api/instances` | — | Every instance (shape below) |
| `POST /api/instances` | `{"template": "grafana", "id": "grafana-team-a", "hosts": {"grafana": "grafana-team-a.portcullis.example.com"}}` | Create without enabling (state `created`; §11.1–11.3) and its empty groups `users_<id>` / `admin_<id>` through the Users & Groups guardrails as the acting admin (who must resolve as an LLDAP administrator before anything is created; an existing group is kept with a warning; a failure creating a group removes the instance again); `hosts` omitted = the defaults on the main domain; in the background (**NEW (operation progress)**: today `201`): `202` (op `create`, the op record is the new id's); result `instance`, the warnings in the record's `warnings` |
| `GET /api/instances/defaults?template=<t>&id=<id>&domain=<d>` | — | For the hostname editor: `{"template", "id", "domain", "multi", "legacy", "routers": [{"router", "subdomain", "immutable"}], "domains": [{"name", "main", "state", "assignable"}], "hosts": {"<router>": "<pre-filled hostname>"}}` — the main domain first, then the enrolled domains (`assignable` only when `ready`); `hosts` are the pre-filled hostnames of `id` on `domain` (default: the main domain; §11.3), empty for an invalid id; an unknown `domain` is `400` |
| `PUT /api/instances/{id}/hosts` | `{"hosts": {"<host router>": "<hostname>"}}` | Change hostnames (§11.3); `200` with the instance |
| `DELETE /api/instances/{id}` | `{"confirm": "<id>"}` | Guarded delete (§11.4), in the background: `202` (below); result `backup` (the delete's archive) |
| `GET /api/backups` | — | Every archive under `<data>/backups/`, deleted instances' included (shape below) |
| `GET /api/instances/{id}/backups` | — | The same, for one instance id |
| `POST /api/instances/{id}/backups` | — | Back up now (§11.5), in the background: `202`; result `archive` |
| `POST /api/instances/{id}/restore` | `{"archive": "grafana-team-a/20261102T153000Z.tar"}` | Restore into the same instance (§11.6); the archive must belong to `{id}`; in the background: `202`; result `archive`, `pre_restore_backup` |
| `POST /api/instances/restore` | `{"archive": "grafana-team-a/20261102T153000Z.tar", "id": "grafana-team-c", "hosts": {"grafana": "grafana-team-c.portcullis.example.com"}}` | Restore into a new instance (§11.6); `hosts` optional (omitted routers: the archive's hostname for `hosts.immutable` routers, else the new id's default); in the background: `202`, the op record is the new id's; result `archive`, `instance` |
| `GET /api/instances/missing-groups` | — | Enabled instances whose access / admin groups are missing in LLDAP: `{"instances": [{"instance", "creatable": [...], "other": [...]}], "error"?}` — `creatable` are the derived names enable would create (§11.2), `other` any other name (create it in Users & Groups); `error` when Users & Groups didn't answer |
| `POST /api/instances/missing-groups` | `{}` (every enabled instance) or `{"ids": ["<id>", …]}` | Create the `creatable` groups as the acting admin (§11.2; actor resolved first, else nothing is created); `200` `{"results": [{"instance", "created", "warnings", "error"}]}` — a busy, unknown or disabled instance is reported in its row |
| `GET /api/keycloak/user-sweep` | — | The guarded stale-record cleanup: `{"configured", "paused", "reason", "paused_at", "skipped", "last_ok_count", "last_ok_at", "last_run_at", "resumed_by", "resumed_at"}` — paused when LLDAP lacks `admin` or the Hub's service account or its user count dropped > 20 % and > 2 since the last successful run; skipped while LLDAP or Keycloak is unreachable |
| `POST /api/keycloak/user-sweep/resume` | `{"confirm": "resume"}` | Resume a paused cleanup as the acting admin (LLDAP administrator); LLDAP's current user count becomes the baseline; audited `keycloak.sweep_resume`; `409` when not paused |
| `GET /api/instances/{id}/op` | — | The instance's op record (below), also of a deleted instance or of the new id of a restore; `404` when none was recorded |
| `POST /api/instances/{id}/op/stop` | `{}` | **NEW (operation progress)** Stop the instance's operation and undo what it did (below): `202` with the record (`stopping: true`); `409` with the record when nothing runs, past the point of no return or already stopping; `404` unknown instance or no record; audited `<op>.stop` |
| `GET /api/domains` | — | The domains service's list (§12.2), passed through; `503` with `{"error": "…", "domains": [<last known list>]}` while it is unreachable, plus `"disabled": true` without a readable secret file |
| `POST /api/domains` | `{"name": "team-b.example.org", "provider": "cloudflare", "credentials": {"api_token": "…"}}` | Enroll (§12.3); `202` with the domain object |
| `POST /api/domains/{name}/token` | `{"provider": "cloudflare", "credentials": {…}}` | Replace the credentials; `202` with the domain object |
| `DELETE /api/domains/{name}` | — | Remove; `204`, or `200` with the service's `{"warning"}`; `409` while any instance uses the domain |

`archive` is always `<instance-id>/<timestamp>.tar`, relative to `<data>/backups/`; anything else is `400`. Errors are plain text, or for a failed lifecycle step (`OpError`) JSON `{error, op, output, hint, rolled_back}`; `409` covers refusals and a busy instance (another operation holds its lock; the body is then the running op record, below), `507` too little free space (§11.5). Bodies are strict JSON (unknown fields: `400`).

**Long operations run in the background.** Every lifecycle operation on an instance runs in the background: enable, disable, restart and an AI switch that restarts the app or runs its hooks (**NEW (operation progress)**: these four answer `202` too), create (`POST /api/instances`), backup, restore, restore into a new id and delete. They can take minutes (downloading images, waiting for health checks, copying volumes), longer than a request may stay open through Traefik (its entrypoints keep the default timeouts). The Hub answers `202` with `{"op_id": "<16 hex>", "op": "<op>", "instance": "<id>", "poll": "/api/instances/<id>/op"}` once the request is validated, the acting admin resolved and the instance's lock acquired. `op` is `enable`, `disable`, `restart`, `ai`, `create`, `backup`, `restore` or `delete`. Refusals before that are synchronous as above: bad body or archive name `400`, delete without the typed id `400`, unknown instance `404`, missing archive `404`, create or restore into an id that exists `409`, an actor that isn't an LLDAP administrator, and the checks an operation makes before it changes anything (e.g. an enable's port and hostname collisions, `409`). Verifying the archive is part of the background work: a refusal there is the operation's failure, with nothing changed. Enable, disable and restart keep their per-app routes, which are not rows of the table above: `POST /api/templates/enable` and `POST /api/templates/disable` with `{"id": "<instance-id>"}`, and `POST /api/templates/restart/{id}`; the AI switch is `PUT /api/instances/{id}/ai` (§15.11).

**One operation per instance, one record.** The operation keeps the instance's lock until it ends, the undo of a Stop included. Every way of starting it takes the same lock and writes the same op record: the route, its Portcullis MCP tool (§15.10) and the Hub's own calls (a queued restart, a restore's enable). So the UI, the MCP, a second tab and a second admin all see the same running operation. A request refused because the instance is busy answers `409` with (**NEW (operation progress)**) the running op record as its JSON body (`running: true`, with its `op`, `op_id`, `actor`, `at` and `steps`), so the client can show the running operation instead of starting another. When the lock is held by work that keeps no record on the instance (a shared-folder apply, §14.3), the refusal is the plain-text busy `409`.

**The op record.** Progress and outcome are the instance's op record (`<data>/ops/<id>.json`, `0600`). `GET /api/instances/{id}/op` returns it, and so does `GET /api/templates/lastop/{id}` while the instance exists. While an enable runs it looks like this:

```json
{
  "op": "enable",
  "op_id": "3f9c0a1b2c3d4e5f",
  "at": "2026-11-07T10:00:00Z",
  "running": true,
  "actor": "alice",
  "steps": [
    {"key": "groups", "label": "Groups", "state": "done", "detail": "users_gitea created; admin_gitea already exists",
     "started_at": "2026-11-07T10:00:00Z", "ended_at": "2026-11-07T10:00:01Z"},
    {"key": "keycloak", "label": "Sign-in client in Keycloak", "state": "done",
     "started_at": "2026-11-07T10:00:01Z", "ended_at": "2026-11-07T10:00:02Z"},
    {"key": "images", "label": "Downloading images", "state": "running", "percent": 45,
     "detail": "gitea/gitea:1.25 — 312 of 690 MB", "started_at": "2026-11-07T10:00:02Z"},
    {"key": "create", "label": "Creating containers", "state": "waiting"},
    {"key": "start", "label": "Starting services", "state": "waiting"},
    {"key": "healthy", "label": "Waiting until healthy", "state": "waiting"},
    {"key": "settings", "label": "Applying settings", "state": "waiting"}
  ],
  "created": {"volumes": [], "keycloak_clients": ["gitea"], "groups": ["users_gitea"]},
  "before": {"enabled": "false"},
  "stopping": false,
  "stoppable": true,
  "point_of_no_return": false,
  "interrupted": false
}
```

- `op`, `op_id`: the operation and the request's id. `at`: the start while it runs, the end once it has ended. `running`: true until it ended, the undo of a Stop included. `actor`: the user who started it (the user only, never `via` / `client`); left out when the Hub started it on its own.
- **NEW (operation progress)**: `steps`, `created`, **`before`**, `stopping`, `stopped_by`, `stopped_at`, `stoppable`, `point_of_no_return` and `interrupted` (the next items).
- `steps`: the operation's steps in order (keys below), each `{key, label, state, percent?, detail?, started_at?, ended_at?}`. `key` is stable; `label` is display text and may change. `state` is `waiting`, `running`, `done`, `failed`, `stopped` (cut short by a Stop or by a Hub stop) or `undone` (its effect reversed by a Stop). `percent` (0–100) is only present where there is something to measure. `detail` is one line, redacted like every record field and never holding a secret. `started_at` / `ended_at` (RFC 3339, UTC) are set when the step starts and ends, so a client can show how long each step took. A step that doesn't apply to this run is not listed (a backup of an instance that isn't running has no `stop` / `start`).
- `created`: what this operation made, written as it happens: `volumes` (Docker volumes this operation created; volumes that existed before are never listed), `keycloak_clients` (client ids this operation registered; a client that already existed is not listed) and `groups` (LLDAP groups it created; existing ones are not listed). All three lists are always present, possibly empty. A Stop undoes exactly these entries. Nothing is inferred at Stop time.
- **NEW (operation progress)** `before`: what a Stop puts back, written before the operation changes anything. Keys: **`enabled`** (`"true"` when the app was enabled; left out = false; for delete and disable), **`running`** (`"false"` when the app was stopped; left out = true; for backup and restart), **`stopped`** (`"true"` when a same-instance restore restarted the app that was stopped; left out = false), **`companion:<name>`** (for an AI switch: each AI companion's `{enabled, mode}` before the switch, e.g. `"on read_write"` / `"off"`; left out when the master switch is off or the companion didn't exist), **`restoring`** (`"true"` when a same-instance restore is armed — it started but hasn't committed; left out otherwise; for the rollback class), **`new_id`** (`"true"` for a restore into a new instance id; left out otherwise; for its undo class). Boolean keys are left out when false.
- `stoppable`: a Stop would be accepted now. `point_of_no_return`: the operation is past the step where it can still be undone (only delete has one, §11.4); `stoppable` is then false. `stopping`: a Stop was accepted and the undo runs. `stopped_by` (the user), `stopped_at`: who pressed Stop and when, present once a Stop was accepted.
- `interrupted`: the Hub stopped while the operation ran (below).
- When it ends: `ok`, `error`, `status` (the HTTP status a failure stands for: `409`, `507`, …), `output`, `hint`, `rolled_back`, `result` (the names listed per route above: `archive`, `backup`, `pre_restore_backup`, `instance`) and `warnings`. `steps` and `created` stay in the final record.

The record is rewritten (atomically) whenever a step starts, ends or changes state, whenever `created` grows, when a Stop is accepted and when the operation ends. A running step's `percent` and `detail` are written at most every 500 ms. A client polls until `op_id` is its own and `running` is false. A deleted instance's record is kept (its id may be reused). A `running` record is no failure: it doesn't count as a failed operation and doesn't put the instance in state `error`.

**Steps per operation** (stable keys):

| `op` | Steps |
|------|-------|
| `enable` | `groups` (the derived groups: created or already there), `keycloak` (sign-in clients), `images` (downloading images), `create` (containers created), `start` (services started, n of m), `healthy` (waiting until healthy, n of m), `settings` (start hooks and data files) |
| `disable` | `stop`, `callbacks` (the extra-domain sign-in callback URIs) |
| `restart` | `down`, `images`, `start`, `healthy`, `settings` |
| `ai` | `revoke` (`revoke_all`, §15.5), `scopes`, `restart`, `hooks` (`on_change` and the owed hooks) |
| `create` | `instance` (state entry, env and generated secrets), `groups` |
| `backup` | `stop`, one `volume:<volume key>` per volume, `archive`, `start` |
| `restore` (same instance) | `verify`, `pre_backup`, `volumes`, `config`, `start` |
| `restore` (new id) | `verify`, `instance`, `groups`, `volumes`, `config` |
| `delete` | `backup`, `stop`, `volumes`, `keycloak`, `groups`, `files` |

Percentages: `images` from the byte counts of the image pulls, summed per image (the Hub pulls each pinned image of the project through the Engine API before `compose up --no-start`, which then finds them present; an image already present counts as complete; `detail` names the image and its bytes). `start` and `healthy` from the number of services (`detail` "n of m"). A backup's `volume:<key>` steps, a restore's `verify` and `volumes` from the bytes copied or checked. Downloaded images are never removed, by a failure or by a Stop.

**Stop** (**NEW (operation progress)**). `POST /api/instances/{id}/op/stop` (Hub listener, admins only, proxy-secret and CSRF guards, body `{}`) stops the instance's operation and puts things back as they were before it. It is accepted while the record is `stoppable` and not `stopping`: an operation that is running and not past its point of no return, an interrupted one (below), or one whose undo failed. The Hub answers `202` with the record (`stopping: true`, `stopped_by`, `stopped_at`). It answers `409` with the record when nothing runs (the last operation ended on its own), when the record is `point_of_no_return` ("past the point of no return — finishing"), when it is already `stopping`, or when **the operation is finishing** (an op that closed Stop — `stoppable: false` — and is running its final step: the record answers `"finishing"` in the message). It answers `404` for an unknown instance or when no record exists. Every Stop is audited as `<op>.stop` (e.g. `enable.stop`): target the instance id, detail the key of the step that was running, actor the stopping admin (with `via` / `client` when it comes from the AI, §9.5), result `ok` or `refused`.

**Each operation closes Stop just before its commit** (the state write that makes the instance enabled, disabled, created, or the file write that makes the backup or archive), so an enable accepts Stop up to and including its last step (applying settings), and a stopped enable that ran its settings step turns everything back off. Once the commit succeeds Stop is refused: the operation ends `ok` (committed despite the Stop), `stopped_by` is kept in the final record and **`ok: true` with `stopped_by` set is impossible** for enable (its commit gate stops the operation before the commit). Other operations (disable, restart, AI switch, backup, restore, create, restore-as, delete) may commit after a Stop was accepted — the gate is enable-only —, so their final record may be `ok: true` with `stopped_by` (finished before Stop took effect; the undo doesn't run).

The Hub cancels the operation (a running compose command is killed, an Engine call is aborted) and marks the running step `stopped`. It then runs the operation's undo as further steps appended to `steps`, with keys `undo:<name>` (e.g. `undo:down`, `undo:volumes`, `undo:keycloak`, `undo:groups`). These go `waiting` → `running` → `done` or `failed`, with a `percent` where there is something to measure. A forward step whose effect an undo step reversed becomes `undone`. Undo steps are idempotent and recorded as they finish.

**A resumed Stop** (of an interrupted record or a record whose undo failed) re-reads the record under the instance lock before running the undo, so it reverses what the interrupted operation wrote to the record (its `created` list), not what was in memory at the last Stop try.

**Cannot be stopped:**
- An op record written without an op id (hook, hosts, reload, credentials, drift: operations that take an app-scoped lock, never a lifecycle lock, and keep no `running` record).
- An AI switch driven by a Hub policy change (§15.11: the AI master switch turned off because the effective policy reached LoA 3): that switch writes no `running` record; the op record's `actor` is the Hub.
- An operation that closed Stop and is past its commit (`stoppable: false`, the final record `interrupted: true` after a Hub restart while it was writing its last outcomes).

- **Stopped:** `running: false`, `stopping: false`, `stoppable: false`, `ok: false`, no `error`. A stopped operation is no failure: the instance is not in state `error` and the record is not listed as a failed operation.
- **Undo failed:** `running: false`, `stopping: false`, `ok: false`, `error` / `hint` / `output` / `status` of the failed undo step (which is `failed`), and `stoppable: true`. The instance is in state `error`. Stop again retries the undo, skipping the undo steps already `done`.
- **Restart:** a failed or stopped restart leaves an owed restart owed (queued via `TriggerDelivery`), so the app is restarted once a delivery can run (the app not busy, not restoring or deleting).

| Operation | Stop does | Stop unavailable |
|---|---|---|
| Enable | Undo everything this enable did: containers removed; volumes this enable created removed (pre-existing volumes kept); the Keycloak client and groups deleted **only if this enable created them**; downloaded images kept | never |
| Restart | The app back running as before | never |
| AI on/off / mode | The switch back as it was, with its credentials, scopes and clients | never |
| Back up | The partial archive deleted; the app restarted if it was running | never |
| Restore | Rolled back from the pre-restore backup (today's failure path) | never |
| Create / restore into a new id | The new instance removed completely | never |
| Delete | The delete cancelled, the app back as before | once data removal starts: the panel shows "past the point of no return — finishing" |
| Disable | The app turned back on | never |

- **Enable.** Undo, in order: `compose down` (containers and network); remove the volumes in `created.volumes`; delete the Keycloak clients in `created.keycloak_clients` (only clients tagged with this instance); delete the groups in `created.groups` through the Users & Groups guardrails as the stopping admin (`DeleteGroup`, who must resolve as an LLDAP administrator, else that undo step fails). The instance is left not enabled (its state as before the enable) and the policy file and `portal-apps.json` are rewritten. Volumes, clients and groups that existed before the enable are kept; downloaded images are kept.
- **Disable.** The instance is enabled again, exactly like an enable (its sign-in callback URIs added back). Nothing new is created.
- **Restart.** The instance is started again with its current files, as it was running before.
- **AI switch.** The companion's previous `{enabled, mode}` is applied again through the same switch path (§15.11: `revoke_all`, scopes, gate file, `compose up`, `on_change`). Credentials revoked by the stopped switch are not brought back: they are minted again lazily (§15.5).
- **Backup**, **restore**, **create**, **restore into a new id** and **delete**: §11.5, §11.6, this table and §11.4. Stopping a create removes the new instance completely: its state entry and files, and the groups in `created.groups`.

**Shutdown and interruption.** On shutdown the Hub waits up to about 50 s for running operations (core gives the Hub container `stop_grace_period: 60s`). An op record still `running` when the Hub starts is rewritten as `running: false`, `interrupted: true`, `ok: false`, `status: 500`, error `interrupted: …`. The step that was running is marked `stopped`, and the other steps and `created` are kept as last written. Such a record is `stoppable: true`: a Stop runs the operation's undo from the record (its `created` list and its steps), so nothing runs twice. Three cases are already handled at start and are `stoppable: false`. A same-instance restore is rolled back from its pre-restore backup (§11.6). An unfinished restore into a new id is removed (§11.6). A delete past its point of no return stays `deleting` (retry the delete, §11.4).

`GET /api/instances` returns, sorted by `id`:

```json
[
  {
    "id": "grafana-team-b",
    "template": "grafana",
    "default": false,
    "state": "enabled",
    "hosts": {"grafana": "grafana.team-b.example.org"},
    "access_group": "users_grafana-team-b",
    "admin_group": "admin_grafana-team-b",
    "keycloak_clients": [],
    "project": "portcullis-grafana-team-b"
  }
]
```

`state` is one of `created`, `enabled`, `disabled`, `deleting`, `restoring`, `error` (§11.2); `hosts` is keyed by the original host-router name (§3.1).

`GET /api/backups` (and `GET /api/instances/{id}/backups`) returns, newest first:

```json
[
  {
    "archive": "grafana-team-a/20261102T153000Z.tar",
    "instance": "grafana-team-a",
    "template": "grafana",
    "created_at": "2026-11-02T15:30:00Z",
    "reason": "delete",
    "size": 73400320,
    "instance_exists": false
  }
]
```

The fields come from the archive's `MANIFEST.json`; `size` is in bytes; `instance_exists` says whether an instance with that id exists now.

**Existing per-app routes take the instance id.** Their paths are unchanged; the `{id}` path segment or the `"id"` body field is now an **instance** id (the template id still names the default instance): `POST /api/templates/enable` and `POST /api/templates/disable` (`{"id": "<instance-id>"}`), `/api/templates/settings/{id}`, `/api/templates/status/{id}`, `/api/templates/logs/{id}`, `/api/templates/compose/{id}`, `/api/templates/env/{id}`, `/api/templates/exec/{id}`, `/api/templates/restart/{id}`, `/api/templates/lastop/{id}` and `POST /api/drift/resolve` (`{"id": "<instance-id>", …}`); `GET /api/drift` reports drift per instance id. `GET /api/templates` stays the template catalog, keyed by template id, with each template's instance ids.

### 11.8 Template source sync (core ⇄ Hub)

- **When.** The Hub fast-forwards every git source it cloned (`git pull --ff-only`) at every start, before its first policy write; on `SIGHUP`; and on `POST /api/sources/sync`. Syncs run one at a time.
- **Fail-safe.** A failed pull leaves the checkout unchanged. If a source's new commit leaves an enabled instance without a valid template, the source is reset to its previous commit (`git reset --keep`) and reported as kept. A sync never opens access: an enabled instance whose template is missing stays denied (§4, published snapshot).
- **Status.** `<data>/source-sync.json` (and `GET /api/sources/sync` → `{"last": …}`), written when a sync starts (`running: true`) and when it ends:

    ```json
    {"trigger": "signal", "running": false, "started_at": "…", "finished_at": "…", "started_unix": 1793645564, "finished_unix": 1793645566,
     "ok": true, "sources": [{"name": "portcullis", "ok": true, "before": "<commit>", "after": "<commit>", "updated": true}],
     "missing_templates": []}
    ```

    `trigger` is `startup`, `signal` or `api`; a source's `error` is fixed text (never git output); `rolled_back` / `rolled_back_for` mark a reset version; `missing_templates` lists enabled instances still without a valid template.
- **Core.** `./portcullis upgrade` reads the file (`docker compose exec hub cat /data/source-sync.json`). Only when it was written since the running Hub container started (an older Hub never writes it, and would exit on `SIGHUP`) it sends `SIGHUP` (`docker compose kill -s HUP hub`), waits for a status with `started_unix` ≥ the time it signalled and `running: false`, and prints each source's result. It never fails the run.
- **Settings and template updates (§13.14).** Discover never changes stored settings. After the final Discover of a sync, the Hub prunes values for options that no longer exist or whose type changed, and person-entered values that no longer pass constraints or are duplicates under newly-declared `unique` (audited `settings.purge` / `settings.person_value` `invalidated`). Until then, resolution ignores values that don't match the current option.

## 12. Domains service (core ⇄ Hub ⇄ Traefik) — NEW (domains API)

Extra domains and subdomains (e.g. `team-b.example.org`, `team-a.portcullis.example.com`) are enrolled by Hub admins. A new core service, **`domains`**, owns their DNS credentials, creates their records, and obtains and renews a wildcard certificate per domain. The main domain is not handled by it: it keeps Traefik's built-in resolver and `./portcullis dns setup`.

### 12.1 Service, network and secrets (core)

- **Service.** `domains` (Go: `github.com/go-acme/lego/v4` as a library for ACME DNS-01, `github.com/libdns/<provider>` for records, `filippo.io/age` for encryption at rest). It listens on `:8080` on the internal network `portcullis-domains`, whose only members are `domains` and the Hub; it reaches ACME and the DNS providers over a separate network with internet access (`domains-egress`, its only member). Traefik never routes it. Image `portcullis-domains` (built locally from core's `domains/`), uid/gid 10004, read-only root filesystem, plus group 10001 to read the API secret it shares with the Hub.
- **Volumes.** `domains_data` (domains only, read-write): encrypted credentials, ACME account, per-domain state, issued certificates — all in one age-encrypted file (`store.age`, written to a temporary name and renamed, mode 0600). No volume is shared with Traefik: it fetches the certificates over HTTP (§12.4).
- **Certificate endpoint network.** `portcullis-certs` (`internal: true`), whose only members are `domains` and Traefik (CI checks the membership, like the socket-proxy networks); the Hub is not on it. It is defense in depth: the certificate endpoint (§12.4) requires a client certificate on every interface it listens on, so reaching the port is never enough.
- **API secret.** `secrets/domains/api-secret` (≥ 32 characters, generated by `./portcullis init` / `up`), mounted read-only into `domains` and into the Hub, group 10001, mode 0640. Never an env var.
- **Encryption key.** `secrets/domains/age.key` (an age X25519 identity, generated by `init` / `up`), mounted read-only into `domains` only.
- **Configuration.** `PORTCULLIS_DOMAIN` (the main domain), `ACME_EMAIL` and `ACME_CA_SERVER` (as for Traefik's resolver), and the server's public IPv4 and, when present, IPv6 (`DOMAINS_PUBLIC_IPV4` / `_IPV6`). They reach the service through `secrets/domains/public-ips.env` (mode 0600, compose `env_file` with `required: false`, so compose ≥ 2.24), which `./portcullis init` / `up` / `upgrade` write; a manual `docker compose up` uses the same file.
    - **Public addresses (fail closed).** An explicit `PORTCULLIS_PUBLIC_IPV4` / `_IPV6` (environment or `.env`; an empty `_IPV6` means "no IPv6") always wins. Otherwise `./portcullis up` (and `dns setup`, through the same helper) detects them over HTTPS only (`--proto =https --tlsv1.2`), requires at least two independent services to answer and all answers to agree, and accepts only global unicast addresses (no private, shared, loopback, link-local, documentation, benchmark, multicast or reserved ranges). Anything else gives no address: without an IPv4 the service publishes no record and sets the domain's `last_error`; without an IPv6 it publishes no AAAA (and removes existing AAAA records at `<d>` / `*.<d>`).
    - A detection that ran and failed keeps the last detected address (`secrets/domains/last-public-ipv4` / `last-public-ipv6`; only then — skipped lookups never use it), because "no IPv6" removes the AAAA records; an explicit empty `PORTCULLIS_PUBLIC_IPV6=` still means none. The service records the addresses it last set; records set to other addresses than the configured ones are redone at start.
    - **No lookups with nothing enrolled.** `./portcullis` skips both detections while the running domains service reports no enrolled domain (`domains enrolled`); when it can't tell (not running), the lookups run. With nothing enrolled, **no address is published** to the service unless `.env` sets `PORTCULLIS_PUBLIC_IPV4` / `_IPV6`. So the first enrolled domain may need one more `./portcullis up` (or the address set in `.env`) before its records are created.
    - **IPv4 unknown.** The service keeps the records it set before (the records check compares against the applied addresses) and still renews certificates; a configured IPv6 is still used; with no address ever known, it publishes no records.
    - **API network.** `portcullis-domains` has a fixed subnet (`PORTCULLIS_DOMAINS_SUBNET`, default `172.31.252.0/28`, passed as `DOMAINS_API_SUBNET`; `./portcullis` checks it is a valid CIDR of at least /29, overlaps neither the proxy nor the auth subnet, and matches the existing `portcullis_portcullis-domains` network); the API accepts only connections addressed to it there (or loopback, the health check), never from Traefik on `portcullis-certs` or on `domains-egress`.
    - `DOMAINS_RESOLVERS` (default `1.1.1.1:53,8.8.8.8:53`) are the resolvers of the records check, the zone (SOA) lookup and lego's propagation check; only CI changes it (to its fake DNS server).
- **Hub configuration.**

    | Env var (Hub) | Default | Meaning |
    |---|---|---|
    | `HUB_DOMAINS_API_URL` | `http://domains:8080` | Base URL of the domains API |
    | `HUB_DOMAINS_SECRET_FILE` | `/run/portcullis/domains/api-secret` | The API secret |

    Without a readable secret file the Hub's Domains section is disabled and says why; instances can then use only main-domain hosts.

### 12.2 API

Every request carries `Authorization: Bearer <api-secret>` (compared in constant time; otherwise `401`). `GET /healthz` is open (Docker health check). Bodies are JSON. Errors are non-2xx with `{"error": "<message>"}`; messages never contain credentials. The Hub is the only caller and the service trusts it: it doesn't check instance assignments (§12.3).

`{name}` is a valid hostname (§4), not the main domain, not a parent of it, and not at or under a core subdomain host `<sub>.<main domain>` (`auth`, `hub`, …; `400` otherwise).

| Request | Success | Errors |
|---------|---------|--------|
| `PUT /domains/{name}` `{"provider": "<p>", "credentials": {…}}` | `202` with the domain object (`state: pending`); work starts in the background | `400` bad name, provider or credential keys; `409` already enrolled |
| `GET /domains` | `200` with an array of domain objects, sorted by `name` | — |
| `POST /domains/{name}/token` `{"provider": "<p>", "credentials": {…}}` | `202` with the domain object; replaces the stored credentials (the provider may change) and re-runs records and, if needed, issuance. A running records step finishes (and records what it created) first | `400`; `404` not enrolled; `503` if a records step doesn't finish within the request's time (retry) |
| `DELETE /domains/{name}` | `204`; or `200` with `{"warning": "<message>"}` if some DNS records couldn't be removed. The certificate leaves the endpoint at once; if a records step is running, the answer waits for it, so the records it creates are removed too | `404` not enrolled; `503` if that step doesn't finish within the request's time (nothing changed; retry) |

Time budget of `DELETE`: waiting for a records step ≤ 90 s, removing records ≤ 60 s, the API's write timeout 3 min, the Hub's client timeout 4 min. When the Hub gets no answer, the domain stays `deleting` (not assignable) until the service's list shows the outcome. Every provider HTTP request has a 2-minute deadline, body included.

**Credentials per provider** (exactly these keys; strings of at least 8 characters — `hosted_zone_id` excepted — so redaction always applies; unknown keys are `400`):

| `provider` | `credentials` keys |
|------------|--------------------|
| `cloudflare` | `api_token` |
| `porkbun` | `api_key`, `secret_api_key` |
| `route53` | `access_key_id`, `secret_access_key`, `hosted_zone_id` (optional) |
| `digitalocean` | `auth_token` |
| `hetzner` | `api_token` |

**Domain object:**

```json
{
  "name": "team-b.example.org",
  "provider": "cloudflare",
  "records_ok": true,
  "cert_not_after": "2027-01-31T08:14:02Z",
  "last_error": "",
  "state": "ready"
}
```

- `records_ok`: the last check found `<name>` and the probe name `portcullis-probe.<name>` (answered by the `*.<name>` record) resolving to exactly the server's addresses (A, and AAAA when the server has IPv6) at **both** public resolvers `1.1.1.1:53` and `8.8.8.8:53`.
- `cert_not_after`: RFC 3339 UTC expiry of the certificate currently served, or `null` if there is none.
- `last_error`: the last failure, `""` after a success. Every DNS-provider error is redacted against the domain's credentials before it is logged, stored or returned (providers may echo tokens or request bodies).
- A stored name that no longer passes the `{name}` rule (e.g. after a main-domain change) gets `state: error` and no records or ACME orders. An issued certificate that the endpoint would refuse (§12.4) is not stored; the attempt fails with backoff.
- Work never crosses enrollments: each enrollment and each credentials replacement gets a never-reused generation; work started for an older one (a deleted and re-enrolled name included) commits nothing.
- `state`:

    | `state` | Meaning |
    |---------|---------|
    | `pending` | Enrolled or credentials replaced; work not started yet |
    | `records` | Creating and verifying the A/AAAA records |
    | `issuing` | ACME DNS-01 order for `<name>` and `*.<name>` in progress |
    | `ready` | Records OK; a valid certificate is served on the certificate endpoint (§12.4) |
    | `renewing` | Less than 30 days left; renewal in progress, the current certificate stays served |
    | `error` | The last step failed (`last_error`); retried with backoff. A still-valid certificate stays served |

    The Hub adds one state of its own, `missing` (§12.3), for a domain the service no longer lists while instances use it.

Example: `PUT /domains/team-b.example.org` with `{"provider": "porkbun", "credentials": {"api_key": "pk1_…", "secret_api_key": "sk1_…"}}` → `202` `{"name": "team-b.example.org", "provider": "porkbun", "records_ok": false, "cert_not_after": null, "last_error": "", "state": "pending"}`.

### 12.3 What the Hub does

- **Enroll.** The Hub refuses (`409`) a name equal to, below or above an already enrolled domain (enrolled domains never nest), a name at or below any core subdomain host `<sub>.<main domain>` (e.g. `auth.<main domain>`, `x.hub.<main domain>`), and a hostname an instance uses. Other names under the main domain are allowed, deeper ones included (`team-a.<main domain>`, `lab.team-a.<main domain>`). It forwards the credentials once (`PUT`) and forgets them: they are never stored in its state, ops records, logs, audit or errors, and its API never returns them (the token field is write-only in the UI). Replacing them is `POST /domains/{name}/token`.
- **No reclassification.** Enrollment is also refused (`409`) for a name equal to or above any hostname the Hub knows: an instance's (any state, published snapshots included), a running app project's, or the default hostname `<sub>.<main domain>` of any template of any source — enrolling `team-a.<main domain>` while a template defaults to subdomain `team-a`, or while an instance routes `x.team-a.<main domain>`, would turn those hosts into extra-domain hosts. The main domain or a parent of it is `400`. The checks run before the credentials are forwarded and again after the service accepted them; a conflict found then deletes the enrollment again.
- **Assignable.** A domain may receive instance hostnames (create, hostname change, restore) only while `records_ok` is `true`, `cert_not_after` is in the future and the domains service is reachable (otherwise `503` for new hostnames on it). A domain that stops being assignable keeps its existing hostnames; the Hub shows a warning.
- **Known domains (fail closed).** The Hub keeps the enrolled domain names (with their provider and last known status, **never credentials**) in `state.yaml`. When the domains service is unreachable, new assignments (create, hostname change, restore onto an enrolled domain) and domain operations get `503`, and the last known list keeps feeding `extra_domains` in the policy file and `domains` in `portal-apps.json`.
- **The Hub is the authority on assignments.** It refuses `DELETE /api/domains/{name}` with `409` (naming the instances) while any instance (enabled or not, published snapshots included) has a hostname on the domain, before asking the service. The domains service doesn't check assignments (and the Hub doesn't send it any).
- **Deleting.** The Hub checks the users and marks the domain `deleting` (not assignable) under one lock before asking the service, so no hostname can be assigned between the check and the delete; a failed delete clears the mark.
- **The service's list is checked.** Entries that break the enrollment rules (not a valid hostname, the main domain or a parent, at or under a core host, nested) are ignored and logged. Unknown providers are refused (`400`) before anything is forwarded, logged or audited.
- **Refresh.** The Hub reads `GET /domains` every 30 s and on `GET /api/domains`; while reachable, the service's list replaces the known list (names, provider, status) in `state.yaml`.
- **Missing (fail closed).** A known domain the service no longer lists while instances still have hostnames on it is kept with state **`missing`** (`records_ok` false, `last_error` "no longer listed … still used by …", logged once on the transition). It stays in the known list, in `extra_domains` (§4) and in the portal's `domains` (§10); its hosts stay extra-domain hosts (sign-in routers, callbacks, §5); it is not assignable (`409` "no longer listed … re-enroll it"); existing hostnames are kept. A listed entry that would nest with an in-use missing name is dropped and logged. Re-enrolling the same name is allowed while the only hostnames under it are instances' (a template's default hostname there still refuses, as "No reclassification" above). It is dropped once no instance uses it.
- **Status.** The Domains section shows, per domain: records OK, certificate valid until, last error, state.

### 12.4 Records and certificates

- **Records.** `<name>` and `*.<name>`: A to the server's IPv4 and, when it has one, AAAA to its IPv6; TTL 300; existing A/AAAA records at those two names are replaced. The zone is found with a SOA lookup (lego's `dns01.FindZoneByFqdn`), so a subdomain of a zone works with that zone's credentials; for `route53`, `hosted_zone_id` skips the lookup. The service tracks the records it created per zone (the zone found may change over a domain's life) and `DELETE` removes all of them, in every zone. Without an IPv6, existing AAAA records at the two names are removed (the records check then expects none).
- **Certificates.** One certificate per domain with SANs `<name>` and `*.<name>`, from `ACME_CA_SERVER` by DNS-01 with the domain's own credentials (so two accounts at one provider can coexist). Renewed when less than 30 days remain. Failures back off.
- **Certificate endpoint (domains → Traefik).** Traefik's **HTTP provider** polls the domains service; there is no shared volume (Traefik's file provider doesn't watch subdirectories, and a reload sidecar in Traefik's PID namespace could read Traefik's environment, DNS-provider tokens included).
    - **Endpoint.** `GET https://domains:8443/traefik/dynamic`, reached by Traefik over the `portcullis-certs` network (a listener separate from the API on `:8080`). The listener requires and verifies a client certificate on **every** interface (TLS `RequireAndVerifyClientCert` against the endpoint CA); the network membership is only defense in depth.
    - **Authentication.** Mutual TLS, from files only — Traefik's provider can send custom headers only from its static configuration, which core sets through environment variables visible in `docker inspect`, so no bearer token. `./portcullis init` / `up` generate a private CA and two certificates under `secrets/domains/certs-endpoint/`: a server certificate for `domains` (SAN `DNS:domains`) and a client certificate for Traefik. `domains` mounts the CA, its server certificate and key read-only. Traefik mounts the CA, its client certificate and key read-only (group 0, mode 0640) and verifies the server against that CA. `domains` answers only clients with a certificate from that CA, so the Hub and other containers can't fetch private keys even if they reach the port.
        - **Validity and rotation.** The CA is valid 10 years; the server and client certificates are valid until the CA expires (ECDSA P-256, `extendedKeyUsage` `serverAuth` / `clientAuth` respectively). `./portcullis up` (and `upgrade`) renew a certificate with less than 30 days left (the CA with less than 1 year left: then all three) and, after any renewal, restart `domains`, wait for it to be healthy, then restart `traefik`, so both load the new files (neither re-reads them while running). `./portcullis status` warns when one expires within 30 days.
    - **Traefik static configuration** (core, shipped with the domains service — Traefik tolerates an unreachable endpoint: it retries with backoff, the other providers keep working, and the last fetched configuration stays in place while `domains` is down): `TRAEFIK_PROVIDERS_HTTP_ENDPOINT=https://domains:8443/traefik/dynamic`, `TRAEFIK_PROVIDERS_HTTP_POLLINTERVAL=10s`, `TRAEFIK_PROVIDERS_HTTP_POLLTIMEOUT=5s`, `TRAEFIK_PROVIDERS_HTTP_MAXRESPONSEBODYSIZE=4194304`, `TRAEFIK_PROVIDERS_HTTP_TLS_CA`, `_TLS_CERT` and `_TLS_KEY` set to the mounted file paths (paths only, never key material). Changes are live within one poll interval, no restart.
    - **Response.** JSON dynamic configuration with **only** `tls.certificates`: one entry per domain with a valid certificate, `certFile` the full chain and `keyFile` the private key as **inline PEM** (Traefik's `FileOrContent`), no `stores` key. With no certificates: `{"tls": {"certificates": []}}`. A renewal replaces the entry in place; `DELETE` drops it.
    - **Never anything else.** Traefik's HTTP provider applies whatever dynamic configuration it receives and can't be limited to certificates, so the restriction is the domains service's: it builds the response from a type that has only `tls.certificates` and must never emit routers, services, middlewares, TLS options, stores or servers transports (a router there could take over any host, e.g. `auth.<main domain>`).
    - **Only enrolled-domain names.** Every served certificate's SANs must be exactly `<d>` and `*.<d>` (both, nothing else, DNS names only; the subject common name, if any, is `<d>` or `*.<d>`) for a domain `<d>` that is currently enrolled in the domains service — the list the Hub publishes as `extra_domains` (§4), since the Hub enrolls and removes domains only through it; the service doesn't read the policy file — never the main domain, a core host or any other main-domain host. Traefik picks a certificate whose names match the SNI more exactly over the ACME wildcard, so a certificate naming `auth.<main domain>` would take over the sign-in host. The domains service checks this itself before serving: it parses every certificate it is about to emit and drops (and logs, without key material) one whose SANs aren't exactly `{<d>, *.<d>}` for an enrolled domain, or which names the main domain or a host at or under it — except an enrolled subdomain of the main domain `<d>` itself, which `extra_domains` allows (§4).
    - **Checks** (domains service tests and core CI, with the domains service): the served document's keys are exactly `{"tls": {"certificates": [...]}}` with only `certFile` / `keyFile` per entry (no `stores`; Traefik's API has no endpoint for TLS options and stores, so those are checked on the served document); every `certFile` is parsed and its SANs asserted as above; Traefik's API lists no `@http` object in `/api/http/routers`, `/api/http/services`, `/api/http/middlewares`, `/api/tcp/routers`, `/api/tcp/services`, `/api/tcp/middlewares`, `/api/udp/routers` or `/api/udp/services`, and no `@http` key anywhere in `/api/rawdata` (servers transports have no endpoint of their own); and after a test certificate is published, `auth.<main domain>` (and another core host) still serve the main domain's certificate.
    - **CI** (with the domains service): a certificate published there is served by SNI within ~20 s without restarting Traefik (`StartedAt` unchanged), and a deleted one stops being served. CI builds the image with the Go build tag `testprovider` (an extra provider `fake` whose records live in memory and are served as DNS by the container itself) and runs Pebble against it; the production image is built without it.
- **Secrets at rest.** Credentials exist only in `domains_data`, encrypted with the age key; the volume is in `./portcullis backup` only in that encrypted form. The same backup also contains `secrets/` (age key included), so it must be protected like the keys themselves, as for Vault's. Credentials are never logged, never returned by the API and never put in `last_error`.
## 13. Settings

Templates may declare configurable options in `settings`. Each option has a type, a scope (instance-wide, per person or per group), constraints, and deliveries that specify how the value reaches the app. The Hub validates, resolves and delivers values; templates stay declarative.

### 13.1 Options

Every option has these fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `key` | `^[a-z][a-z0-9_]{0,39}$` | Yes | Identifier (not an env name). Must be unique across the template's settings |
| `label` | single line, non-empty, ≤ 64 characters (runes, also for choice and column labels) | Yes | Display label |
| `description` | text, ≤ 500 | No | Help text shown in the panel |
| `section` | `^[A-Za-z0-9][A-Za-z0-9 ]{0,31}$` | No | Panel section name. Options in the same section are grouped |
| `type` | enum | Yes | `string`, `int`, `size`, `duration`, `bool`, `enum`, `multi_enum`, `list`, `table`, `path`, `secret`, `group`, `groups`, `user`, `users`, `person_secret`, `person_id`. See §13.2 |
| `scope` | `instance`, `person`, `group` or `person_entered` | No (default `instance`) | Who the option applies to. See §13.3. Refused on `person_secret` and `person_id`, whose effective scope is always `person` (one value per person, set by the Hub) |
| `required` | boolean | No (default `false`) | The value must be non-empty. For `person` scope the default must be non-empty (the validator refuses an empty one), so every person in the population gets a non-empty resolved value. Not for `group` scope (its records are optional) |
| `default` | typed value | Contextual | Fallback value. Required for `person` scope; refused for `person_entered` and `group` scopes. For other scopes it is optional |
| `privileged` | boolean | No (default `false`) | The option grants a privilege (role, admin flag). Per-group values may come only from groups delegates can't steer (§13.3). Requires `scope: person` and type `enum` or `bool`; the default must be the lowest-ranked value (the first option, or `false`) and `group_values` may not use `{{ACCESS_GROUP}}` |
| `self_visible` | boolean | No (default `true`) | Whether the option is shown on My apps (`GET /api/me/apps`, §5.1). `false` hides sensitive resolved values from people. Requires the (effective) scope `person`. Refused for `person_entered`. `person_id` must set `self_visible: false`. **NEW (file sharing):** an instance option may set `self_visible: true` (never `false`) so that a `person_secret` `info` line may show it (`{value:<key>}`, §13.2); nothing else about it changes |
| `applies` | enum | No | When a change takes effect: `live`, `reload`, `next_request`, `next_sign_in`, `restart`, `account_creation`. See §13.9. The default is `restart` for `scope: instance`, `next_sign_in` for claims and `next_request` for headers |
| `requires` | list of option keys | No | Other instance options that must be non-empty when this one is. See §13.9 |
| `requires_any` | list of option keys | No | **NEW (file sharing).** Instance options only: when this one is non-empty, **at least one** of the listed instance options must be non-empty. See §13.9 |
| `delivery` | list | Yes, except an instance option (default `env: <UPPER(key)>`) and `path` (delivered as its `target`) | How the value reaches the app. See §13.6. `person_secret` takes only the scalar `delivery: file` (§13.2) |

Type-specific constraints are in §13.2. A `person` option needs `resolve` (§13.4) and at least one per-person delivery (claim, header, file or hook). Per-group options (`scope: group`) are delivered as maps through env (JSON), files or hooks. Person-entered options (`scope: person_entered`) follow the rules of §13.13.

### 13.2 Types

Each type has validation constraints:

**string**

- `pattern`: anchored regex `^...$`, ≤ 500 characters. Applied to the whole value
- `min_len` / `max_len`: character bounds (0–65535)
- `format`: `hostname`, `ip`, `cidr`, `url`, `email`, `iana_tz`, `locale`, `cron`, `semver`, `hex`. Formats give specialized UI pickers. `hostname` is a valid hostname in the §4 sense (lowercase, at least two labels, ≤ 253 characters); a dotted IPv4 address such as `192.168.1.10` matches it too, so an "address people connect to" option uses `hostname`. An IPv6 address and a single-label name (`nas`) don't

**int**

- `min` / `max`: bounds (int64)
- `step`: granularity (positive int64, default 1). Values must be `min + k × step`
- `unit`: label (e.g. `days`, `retries`). Shown next to the input; does not affect the stored value

**size**

- Stored in bytes (int64, non-negative)
- UI uses binary units (MiB, GiB, TiB) and labels them as such
- `step`: granularity in bytes (positive int64). Values must be `k × step`
- `min` / `max`: bounds (sizes)
- Input takes binary units only (`10GiB`, `512MiB`; `10GB` and `10G` are refused)
- `allow_unlimited`: boolean. When true, the value `unlimited` is allowed. It is stored as the **string `"unlimited"`**, never as a number: `-1`, `0` or `none` are only what one delivery renders for it (`render.unlimited`, §13.5), which every delivery of such an option must set

**duration**

- Stored in seconds (int64, non-negative)
- `min` / `max`: bounds in seconds

**bool**

- Values: `true` or `false`

**enum**

- `options`: list of `{value, label}`, at least one. `value` is a string without control characters (≤ 128 chars); `label` is a single line (≤ 64 chars)
- The list order is the option's rank: first option has rank 1, second has rank 2, etc. Used by `resolve: max|min`

**multi_enum**

- A set of `enum` values
- Same `options` shape as `enum`

**list**

- `items`: the item type, one of `{type: string}`, `{type: int}`, `{type: bool}`, `{type: enum, options: […]}`. Item types may have their own constraints (string `pattern`/`min_len`/`max_len`/`format`, int `min`/`max`, enum `options`)
- `min_items` / `max_items`: bounds (0–1000)
- `unique`: boolean. When true, items must be unique (compared in canonical form)

**table**

- Records with typed columns
- `columns`: list of `{name, label, type, …}`, at least one. Column names match `^[a-z][a-z0-9_]{0,31}$` and are unique. Each column's type is `string`, `int`, `bool` or `enum`, with the same constraints as those scalar types
- `key_column`: optional column name. When set, that column's values must be unique across rows (the column becomes the row key). Records are delivered as a map keyed by that column when this is set

**path**

- A host directory the app bind-mounts
- `target`: `{service, mount}`. The service and container path (same shape as today's `target`)
- `mode`: `ro` or `rw`
- `needs`: `read` or `write`. Documents what the app does with the path (shown in the panel)
- `writes_as`: `{uid, gid}`. Numbers or references to other instance option keys (e.g. `{uid: puid, gid: pgid}` when the template has integer options `puid` and `pgid`). Documents the identity the app writes files as
- `folder`: what the app needs on a shared folder (`access`, `runs_as`, `joins_group`, `must_own`). It **replaces** `mode`, `needs` and `writes_as` (refused together). See §13.15
- `checks`: template-declared doctor checks on this option (§13.15; `requires_group_value` goes on `scope: person` options of any type)
- The value is a host path, or a shared folder: `folder:<id>` or `folder:<id>/<subpath>` (§13.15). Folder values are set only by an assignment (§14.3), never by a settings save

**secret**

- `scope: instance` only (a group or person value would be stored and shown in plaintext; a per-person credential is `person_secret`, below)
- Write-only value
- `generate`: `{length, charset}` or absent. When present, the Hub can generate a value (`crypto/rand`). `length` is 8–128 and within the option's `min_len` / `max_len`; `charset` is one of `hex` (0-9a-f), `alphanumeric` (A-Za-z0-9), `ascii_printable` (printable ASCII without space, `'` and `\`: 0x21–0x7E minus `'` and `\`)
- `min_len` / `max_len`; no `default`. A value may not contain `'` or control characters
- GET returns `{set: true|false, updated_at}` only, never the value
- Delivered through env (in the 0600 `.env`), file (a secrets file, mode 0600) or hook stdin. Never in argv, logs or the audit

**group** / **groups**

- LLDAP group names
- `group`: one group
- `groups`: a set of groups (like `multi_enum` over groups)
- **NEW (file sharing): instance values are id-bound.** An instance-scope `group` / `groups` value is stored with each group's LLDAP id, like per-group rows (§13.11): a group deleted or re-created under the same name grants nothing and is purged from the value (audited `settings.purge`)
- A file delivery of a `group` / `groups` option may set `render: {expand_members: true}` (§13.5): the file then holds the members of the bound groups that are in the instance's population, not the group names

**user** / **users**

- LLDAP usernames (immutable identity, never email)
- `user`: one username
- `users`: a set of usernames

**person_secret** (**NEW**, file sharing; §13.16)

- A per-person **file-share password**: each person in the population creates their own on My apps (§5.1) after a fresh hardware sign-in, sees it once, and can regenerate or revoke it. The Hub stores only its hash, on the `hub_secrets` volume (§6), never the password. Admins list and revoke, never create
- Effective scope `person`; `scope`, `default`, `required`, `resolve`, `resolve_choices`, `group_values`, `privileged`, `requires`, `requires_any`, `self_visible` and `checks` are refused. `applies`, when given, is `live`
- `hash`: required, exactly `nt` (the NT hash, §13.16)
- `length`: required, an integer ≥ 24 and a multiple of 4 (the password is shown in groups of 4)
- `delivery`: required, exactly the scalar `file` (not a list): the hash files are mounted as below. Env, claim, header, hook and data-file deliveries are refused
- `mount`: required, `{service, path}`: the compose service (it must exist) and the container directory (absolute, clean, no `:`) where the Hub mounts this option's directory of `<username>.nt` files, read-only (§6). It may not collide with a path option's target or a data file's mount on that service
- `revoke_on_leave`: required, exactly `true` (§13.16 "Revocation")
- **A `credential_change` hook is required:** the template must declare at least one hook on `mount.service` whose `when` includes `credential_change` (it applies revocations live, §13.16). Both validators refuse a `person_secret` option without one
- `on_restore`: required, exactly `void` (§11.6)
- `username`: optional `{pattern, reserved, reason}`: the usernames the app can serve. `pattern` is an anchored regex `^…$` limited to what Go RE2 and busybox ERE read alike (literals, bracket classes, `{m,n}`; nothing else); `reserved` a list of lowercase names, compared case-insensitively (the image's own accounts); `reason` one line, ≤ 200 characters, shown to a person whose name fails. Checked when My apps is built (status `unavailable`) and again on the create route (`409`). A template that also gives the rule to its container writes it in compose `environment:` as `PORTCULLIS_USERNAME_PATTERN` with every `$` doubled (`$$`); the validators require its unescaped value to equal `username.pattern`
- `info`: optional list of `{label, value}` lines shown on the person's credential card (§5.1): `label` one line ≤ 64 characters; `value` text with placeholders, rendered for the person as plain text (the UI escapes it):
    - `{user}`: the person's lowercase username;
    - `{value:<key>}`: the displayed value of an instance option of type `string`, `int`, `enum` or `bool` that sets `self_visible: true` explicitly (never a secret, a path or any other type);
    - `{port:<KEY>}`: the host port of the declared port `<KEY>` (`ports[].key`) for this instance;
    - `{port_suffix:<KEY>:<default>}`: empty when that host port equals `<default>`, else `:<port>` (so `smb://{value:connect_address}{port_suffix:SMB:445}/…` shows a non-default port only).

    Any other `{…}`, or a placeholder naming an unknown or ineligible option or port, is refused by both validators
- Only on router-less `custom` templates with `group_access: true` and an `access_group` (§3); its population is the access group's members minus expired entries (§13.3)
- Values are never parsed from an admin (any admin input is refused "set by the Hub"); the settings panel and `PUT …/settings` never address it. Displayed only as a status (§5.1)

**person_id** (**NEW**, file sharing; §13.16)

- A stable per-person number the Hub allocates, e.g. the Unix uid a file server gives each person
- Effective scope `person`; `scope`, `default`, `required`, `resolve`, `resolve_choices`, `group_values`, `privileged`, `requires` and `requires_any` are refused
- `pool`: required, exactly `posix_uid` (the only pool: Hub-wide, §13.16)
- `self_visible`: required, exactly `false` (never shown on My apps)
- `delivery`: only `file` deliveries (`{file: {name, field}}`): the person's id in the data file's people section. Every other delivery is refused
- Values are never parsed from an admin ("set by the Hub"); displayed as the number (admin panel and File sharing tab only)
- Only on router-less `custom` templates with `group_access: true` and an `access_group` (§3)

Neither type is a SaveSettings key, a panel instance value, a seeded default, a pruned value, an env name (no implicit `UPPER(key)` env) or a My apps value.

**Reserved types.** `folder` stays reserved: it is refused with "a shared folder is a type: path option with a folder block" (shared folders add no type: they are `path` values, §13.15). A Hub without §14 refuses the option keys `folder` and `checks` as reserved (§1); a Hub without file sharing refuses the types `person_secret` and `person_id` and the `folder` fields `runs_as.uid_from` / `gid_from`.

### 13.3 Scopes and population

**instance**

- One value for the whole instance
- The simplest scope; every delivery mechanism works

**person**

- Resolved per person from the default and per-group values
- The admin sets:
  - a default for "everyone else with access"
  - zero or more group rows, each giving a value for that group
- Resolution picks one value per person using the option's `resolve` rule (§13.4)
- Requires a `default` and at least one per-person delivery (claim, header, file or hook). Per-person env deliveries are refused

**Population (person options).** The people a `person` option applies to:

- With an access group (group access on, or access role enforced): the current members of the instance's access group, minus anyone in an expired-but-not-removed entry of the published `expiring` list (§4)
- Without one (group access off, no access role): every LLDAP user except the service account
- Admin, extra and core groups never widen the population. A member of `admin_<id>` who isn't in the access group can't reach the app
- Public routes add nobody (anonymous visitors aren't people)
- `sign_in: native`, method `public`, and `custom` without `native_login`: the population is empty (Portcullis passes no identity). The panel says why (`population.why`); a draft that switches to `sign_in: native` previews nobody
- **NEW (file sharing):** a router-less `custom` template (§3) with `group_access: true` and an `access_group` is the exception: its population is the access group's current members minus expired entries, as above. People reach such an app only through credentials the Hub issues to that population (§13.16), not through Portcullis identity on a route
- A disabled instance keeps its population for the preview, but delivers nothing

**Privileged options.** An option marked `privileged: true` may take per-group values only from groups delegates can't steer:

- Manual groups
- Rule groups whose rules reference only admin-only fields (§9.6)

Adding such a group to a privileged option makes it an "app admin group" (§9.6 Security rules). The group picker shows other groups greyed out with the reason. The default of a privileged option must be its lowest-ranked value.

**group**

- One record per group the admin adds, not resolved per person
- Used for app-resolved maps: library or ACL per group, rooms per group
- Delivered as a map through env (JSON), files or hooks
- No `default`; the records are the values
- **Records may only grant.** A record is delivered only when its group exists in the directory snapshot with the LLDAP id it was saved with; with the directory unavailable a run delivers no records at all (env: `[]`; files and hooks keep their last delivery). An app must therefore read a missing record as "nothing granted" and never as "no restriction" (a per-group deny list would fail open)

**person_entered**

- One value per person, entered by that person on My apps
- Not resolved, no default, no group rows
- The person must be in the option's population both to enter a value and to have it delivered
- For identity-less routes (method `public` or `custom`, or a template whose `native_login` allows the app's own login only), the population is the members of the template's `access_group` minus expired `expiring` entries. The validator requires `auth.access_group` on such templates
- Admin, extra and core groups never widen it
- See §13.13 for the full rules

### 13.4 Resolution

For `person` options, resolution picks one value per person from the default and the group rows. The template declares `resolve`:

- **max** / **min**: for `int`, `size`, `duration`, `enum` (by option order). `unlimited` (where allowed) beats any number under `max` and loses under `min`
- **priority**: for any type. The admin orders the group rows; the first matching group wins
- **union** / **intersection**: for `list`, `multi_enum`, `groups`
- **any** / **all**: for `bool`

The default is a fallback only: it applies to people in none of the groups that have a value. It never takes part in max/min/union.

When resolution finds no value (no matching group row, no default), the person gets nothing delivered for that option.

The template may list `resolve_choices` the admin can switch to (validated: same type family).

### 13.5 Rendering

Values are stored in canonical form (bytes, seconds, typed JSON). Each delivery has its own `render`:

- `unit`: for `size`, `duration` or `int` with a `unit`. Sizes: `B`/`KiB`/`MiB`/`GiB`/`TiB` (binary, 1024) or `KB`/`MB`/`GB`/`TB` (decimal, 1000), strictly (`GB` = 10⁹, `GiB` = 2³⁰); durations: `s`/`m`/`h`/`d`; an `int`: its own `unit` label (e.g. `days`, not converted). Output is the canonical value divided by the unit. For sizes and durations, `integer: true` refuses fractional results
- `unlimited`: for `size` with `allow_unlimited`, and required there. What this delivery renders when the stored value is the string `"unlimited"` (e.g. `"0"`, `"-1"`, `"none"`): an app's own sentinel, never a stored value
- `true` / `false`: for `bool`. The strings rendered for true and false (default `"true"` / `"false"`)
- `join`: for `list`, `multi_enum`, `groups`, `users`. The separator (default `","`). Items are rendered in their stored order (list) or sorted (sets)
- `format`: for structured values that don't fit a single env value. One of `json`, `yaml`, `csv`. `yaml` and `csv` are multi-line: only file and hook deliveries take them, and never for a `person_entered` scalar (outside env it is the person's own value). `json` is compact and never HTML-escapes `&`, `<`, `>`
- `expand_members` (**NEW**, file sharing): for a file delivery of a `group` / `groups` option. `true` renders the value as the sorted lowercase usernames of the members of its bound groups (§13.2) who are in the instance's population, instead of the group names. A member outside the population is left out (the panel warns at save: "1 member of office_milan has no access to Samba and won't get this share"). With the directory unavailable the file keeps its last delivery

A value that doesn't fit a delivery's granularity (e.g. 1.5 GiB rendered as an integer-GiB claim) is refused at save, naming the app and its unit.

**Checked at discovery.** The validator renders the default and every `group_values` value through every delivery (the implicit `env: <UPPER(key)>` and each `NAME_{n}` item included), with the env rule below: a template whose own values can't be delivered is refused. On an env delivery, `render.true`, `false`, `unlimited` and `join` may not contain `'` or `\`. With `allow_unlimited`, a numeric `render.unlimited` that a size within the option's `min`/`max` also renders as (e.g. `"0"` with no `min`) is refused: the app would take that value for unlimited.

**Env values** are single-quoted. Values containing `'`, `\` or newlines are refused at save, naming the option and the variable (structured values use `format: json`; JSON escapes a `"` or `\` inside a string with a backslash, so such items can't go in an env value either). Env, header and claim values are one line; a header value is at most 1024 bytes and a claim value 4096 bytes.

### 13.6 Deliveries

Each option has at least one delivery. The value is rendered per delivery.

**env**

- Form: `{env: <NAME>}` or `{env: <NAME_{n}>}` (indexed, for `type: list` with `scope: instance`)
- The variable name (env key). An instance option with no `delivery` defaults to `env: <UPPER(key)>`
- Reserved names (§2) and names hard-coded in `compose.yml` are refused. Duplicate env names across the template's settings are refused
- `person` options may not use env delivery (per-person env is refused). A `person_entered` option may deliver as env with `render.join` or `render.format: json` (the collection, not per-person values)
- Instance and group options are written to the `.env` on save and before every start (empty when unset; secrets from the secrets store). A group env value is one JSON list `[{"group", "value"}]` of the records whose group id matches the run's directory snapshot
- **Person-entered env lists** are written by the delivery engine: the values of the delivered entries (§13.13) in user order, no usernames. With `render.format: json` the variable is a JSON list `[<item>, …]` (each item JSON-encoded, without HTML escaping); otherwise the items' text joined with `render.join` (default `,`). An item the list can't carry (it holds the separator, or can't be single-quoted) is refused at save; one that slipped through (stored before a template change) is left out and logged with its user, and the other items are still delivered — one bad item never drops the whole list. If the list as a whole can't be written, the variable is left as it was (never emptied)
- **Indexed env delivery** (for `type: list`, `scope: instance`): the form `{env: NAME_{n}}` writes `NAME_1`, `NAME_2`, ..., `NAME_<max_items>` as separate variables (1-indexed). Unused indices are written as empty strings. The validator requires `max_items` and that every index `{n}` the template references in `compose.yml` is declared (through `max_items`). Used for device lists (scrutiny `SCRUTINY_DISK_1..8`, motioneye `MOTIONEYE_VIDEO_1..4`) where compose needs separate variables for `devices:` entries

**path (mounts)**

- The same bind mount mechanism as today's `path` settings. The Hub writes the bind mount into its override
- Only for `type: path`, `scope: instance`
- Read-only whenever the option's `folder.access` is `read`; shared-folder values in compose's long syntax with `create_host_path: false`, plus the folder's group (§13.15)

**claim**

- Form: `{claim: {client: <key>, name: <claim name>, json_type: int|string|bool|json, render: {…}}}`
- `client`: the `client_id` of a `keycloak_clients[]` entry. The mapper goes on that client only
- `name`: the claim name in tokens (e.g. `immich_quota`), `^[a-z][a-z0-9_]{0,63}$`. Must not be a standard OIDC / JWT claim, a Keycloak claim, `attr_*` or `portcullis_*`; one option per claim and client
- `json_type`: the claim's JSON type in the token: `string` (default), `int`, `bool` or `json`. Keycloak converts the attribute, so:
    - `int` is a **32-bit** integer: a size must be rendered in a unit (`render.unit: GiB`), and `render.unlimited` must be a 32-bit integer;
    - `bool` needs a `bool` option rendering exactly `true` / `false`;
    - `json` must be valid JSON: `render.format: json`, a table, or numbers (a `render.unlimited` such as `-1` or `null`).

    The validator refuses every mismatch it can see in the manifest. At delivery each value is checked again; a value that doesn't fit is not delivered (that person's attribute is cleared)
- The Hub creates a Hub-owned LLDAP user attribute (`ps-<12 hex>`: `ps-` plus the first 12 hex digits of sha256(`<instance>\x00<key>`); LLDAP attribute names allow only letters, digits and `-`), writes each person's rendered value into it, and adds an LDAP attribute mapper plus a protocol mapper on the instance's client, both named `portcullis-setting-<attr>` (Hub-owned, §8: core never touches them; the client keeps exactly the claims the Hub delivers, the LDAP mapper goes with its attribute). STRING type, not visible, not editable. The attribute is cleared for people outside the population
- Removing the instance removes its attributes and mappers
- Allowed only on `native-oidc` templates with a declared client
- Only for `person` and `person_entered` scopes
- People outside the population get the attribute cleared

**header**

- Form: `{header: {name: <Header-Name>, render: {…}}}`
- `name`: the header name, exactly `^X-Forwarded-Attr-[A-Za-z0-9]+(-[A-Za-z0-9]+){0,30}$` (group-gate's own pattern); one option per header
- Per-host headers in `user-attributes.json` v2 (§4.1), keyed by the header **suffix** (the part after `X-Forwarded-Attr-`) on every host of every router whose chain has `portcullis-groups@docker`. group-gate returns them on allow for that host only
- The validator refuses a header delivery unless clients can't send the header themselves: the template needs routers with `portcullis-groups@docker`; every router that reaches the delivering backend's network namespace (`network_mode: service:` followed, cycles refused) must run Portcullis forward-auth; no Traefik-labelled service may run in the host's network namespace (`network_mode: host`); method `public`, `custom` without `native_login`, and `native_login.allow_without_gateway` are refused. The Hub refuses `sign_in: native` (400) while the template delivers headers
- **Public routers** (§5, public exceptions) have no forward-auth: their strip middleware deletes every declared header-delivery name, and the same name with `_` for `-`
- Only for `person` and `person_entered` scopes
- **A missing header is not a value.** group-gate sends no header for a person whose value is UNRESOLVED or empty, whose value is over 1 KB, or when `user-attributes.json` is missing or malformed (§4.1). An app that syncs a value from a header only when it is present keeps its last synced value: Grafana's auth proxy keeps the person's last org role (an earlier `Admin` stays `Admin`), it doesn't fall back to Viewer. Taking access away means removing the person from the instance's access group, not relying on the header
- **Declared from enable on.** Every enabled instance's header-delivery suffixes are declared on every host its routers gate from the moment it is enabled, with an empty user map until the first delivery (also after re-enable, while the directory is down, after a failed seed at Hub start, and on a host `SetHosts` just added). A declared suffix replaces the same-named field header on that host, so a shared field never reaches the app under the delivery's header name before the Hub has delivered. If the Hub can't resolve the hosts it gates, the policy suppresses the colliding field header everywhere (fail closed)

**file**

- Form: `{file: {name: <file key>, field: <field name>, render: {…}}}`  (person/person_entered)  
  or `{file: {name: <file key>}}`  (instance/group: the whole file for the option)
- `name`: the key of a declared `files[]` entry (§13.7)
- `field`: for `person` and `person_entered` scopes (and `person_id`), the field name in the data file's `people` or `entries` section (`^[a-z][a-z0-9_]{0,39}$`, default the option key; one option per field)
- A `person_secret` option has no file delivery into a data file: its scalar `delivery: file` is its own hash-file mount (§13.2, §6)
- The Hub writes the data file and, when the file holds a secret option, its secrets file (layout and modes in §13.7)
- Bind-mounted read-only into the declared service. The Hub mounts the file's directory, not the file, because an atomic rename gives a new inode
- The template's init one-shot renders the app's config from it

**hook**

- Form: `{hook: <hook name>, render: {…}}`
- The name of a declared `hooks[]` entry (§13.8)
- Delivered through stdin when the hook runs
- A hook can receive several options

**Cross-checks.** The validator refuses:

- A `person` option without a per-person delivery
- A `person_entered` option with deliveries that don't match `applies` (§13.13)
- Claim delivery without `method: native-oidc` and a declared client
- Header delivery without forward-auth, or when a public router or `sign_in: native` would let clients forge the header

### 13.7 Data files

Templates declare named data files for file delivery:

```yaml
files:
  - name: <key>
    service: <service>
    mount: <container directory>
    format: json|tsv
    on_membership_change: restart|reload|hook|none
```

- `name`: matches `^[a-z][a-z0-9_-]{0,31}$`, unique across the template's files
- `service`: the compose service
- `mount`: container directory (absolute, clean, no `:`; not a single file). The file is `<mount>/<name>.json` (`<mount>/<name>.tsv` for `format: tsv`). It may not collide with another file's mount or a path option's target on the same service
- `format` (**NEW**, file sharing): `json` (default) or `tsv` (below; for apps that read the file with a POSIX shell). A secret option delivered into a `tsv` file is refused at validation: secrets go only to a JSON file's `<name>.secrets.json`
- `on_membership_change`: `restart`, `reload` (needs `reload`), `hook` (needs a hook with `membership_change`) or `none` (default): what happens when a membership-driven delivery changes the file (§13.8); with `hook`, any run that changes the file (a save included) runs the hooks it names in that run

**Host layout.** The Hub writes the files under `<ProjectDir>/appfiles` (core's `./appfiles`, mounted in the Hub at `/project/appfiles`; created by `./portcullis up`, 0750, owned by uid 10001). The daemon-side path the override mounts is `<ProjectHostDir>/appfiles`. `HUB_APPFILES_DIR` (the Hub's path) and `HUB_APPFILES_HOST_DIR` (the daemon's path for the same directory) move it; they are set together or not at all (one alone: the Hub refuses to start).

```text
<appfiles>/<instance>/                     0750
<appfiles>/<instance>/<name>/              0750, bind-mounted read-only at the file's mount
<appfiles>/<instance>/<name>/<name>.json           0640  data file (<name>.tsv for format: tsv)
<appfiles>/<instance>/<name>/<name>.secrets.json   0600  only when the file holds a secret option (never for tsv)
```

Every file is owned by the Hub (uid 10001) and written atomically. Secret values are only in the secrets file, never in the data file. The override bind-mounts `<ProjectHostDir>/appfiles/<instance>/<name>` at `mount`, read-only (`$` written as `$$`). The files are generated from the Hub's state (not backed up); deleting the instance removes `<appfiles>/<instance>/`.

**Data file format (DataFileDoc):**

```json
{
  "version": 1,
  "instance": "<id>",
  "values": {"<key>": <rendered>},
  "people": {"<lowercase user>": {"<field>": <rendered>}},
  "groups": {"<key>": [{"group": "<name>", "value": <rendered>}]},
  "entries": {"<field>": [{"user": "<lowercase user>", "value": <rendered>}]}
}
```

- `values`: instance-scoped option values (key → rendered value)
- `people`: per-person resolved values, keyed by lowercase username. Each user maps to their fields
- `groups`: per-group records for `scope: group` options. Each option key maps to an array of `{group, value}` records
- `entries`: person-entered values for `scope: person_entered` options. Each field (the delivery's `field`, default the option key) maps to an array of `{user, value}` entries, sorted by user. Only population members whose stored LLDAP uuid matches their current account; under `unique`, only the earliest of equal values (§13.13). Person-entered values never appear under `people`
- Every section is always an object (never `null`); `version` is 1

**Secrets file format (SecretsFileDoc):**

```json
{
  "version": 1,
  "instance": "<id>",
  "secrets": {"<key>": "<value>"}
}
```

Only secret option values, keyed by option key.

**tsv format (NEW, file sharing).** The same document as `DataFileDoc`, one record per line: UTF-8, fields separated by one tab, each line ended by `\n`. The first line is the `version` line and the second the `instance` line; every other line follows, sorted by its bytes:

```text
version	1
instance	<id>
value	<key>	<rendered>
person	<user>	<field>	<rendered>
group	<key>	<group>	<rendered>
entry	<field>	<user>	<rendered>
```

- `value`: an instance option's rendered value (the JSON `values`); `person`: a person's resolved value (the JSON `people`; `person_id` values are here, e.g. `person	alice	uid	20000`); `group`: one `scope: group` record (the JSON `groups`); `entry`: one person-entered value (the JSON `entries`; `<field>` is the delivery's field, default the option key), one line per (field, user) pair. People and users are lowercase usernames.
- Lists and sets render comma-joined (so `expand_members` gives `value	share1_readers	alice,bob`). An empty value is an empty last field.
- No field may hold a tab or a newline, and no list item a comma: such a value is refused when the file is rendered, naming the option and field (the unit fails, the last delivery stays). There is no escaping and no quoting.
- There are no table-row lines: a `table` option delivered into a `tsv` file is refused at validation (deliver it to a JSON file).
- A delivery into a `tsv` file may not set `render.format` (the Hub's and the templates repo's validators refuse every `format`): values render only as the default text, a scalar as is and a list comma-joined. A value the tsv renderer has no text for is an error (the unit fails), never a fallback text.

**Reading.** The service runs as root or, when not root, with `group_add: ["10001"]` to read the 0640 data file. The 0600 secrets file is readable only by root or `user: "10001"`. The validator warns when a service that is neither reads a secrets file.

**Starting.** The data files are written before the containers are created, so an init one-shot always reads the current state. A file with per-person, group or entry values that was never delivered while Users & Groups is unavailable makes the start fail (503) rather than start the app without it.

### 13.8 Hooks and reload

**Hooks** (runtime API delivery):

```yaml
hooks:
  - name: <key>
    service: <service>
    command: [<argv>]
    user: <user>
    when: [start, settings_change, membership_change, credential_change]   # or exactly [ai]
    timeout: <duration>
```

- `name`: matches `^[a-z][a-z0-9_-]{0,31}$`, unique across the template's hooks
- `service`: the compose service
- `command`: argv list, run directly (not through `sh -c`)
- `user`: optional user to run as (default: container's user)
- `command`: a non-empty argv list of non-empty strings without control characters
- `when`: list of triggers (at least one). `start` runs after every successful start; `settings_change` after a save; `membership_change` after a membership-driven delivery (people joining or leaving, person-entered values) changed its input, or after any run changed a data file with `on_membership_change: hook`; `credential_change` (**NEW**, file sharing) after a `person_secret` credential was created, regenerated, revoked or voided (§13.16), immediately (never debounced)
- `timeout`: Go duration (e.g. `60s`). Default 30s, **at most 10m**
- **`ai` (NEW, AI support).** A hook with `when: [ai]` is run **only** by the AI machinery (§15.5: `mint`, `revoke`, `revoke_all`, `on_change`), never by the settings delivery engine: not on any settings trigger, not on a retry from the panel (`POST …/settings/retry`), not by a forced or start run, and its input is never built. `ai` can't be combined with another trigger, and no option delivery `{hook: …}` and no `reload: {hook: …}` may name an `ai` hook (refused). Every hook an `ai:` block names must be an `ai` hook (§3.2). An `ai` hook gets the AI stdin of §15.5 instead of the HookInput, its stdout is never stored and its output is split (§6, §15.5). The validators' refusal texts name all five triggers (`start`, `settings_change`, `membership_change`, `credential_change`, `ai`)

The Hub runs the command verbatim (never through a shell) with Docker exec in a running container of the hook's service in this instance (replica 1 preferred) and sends the full desired state as JSON on stdin, the **HookInput**: the data-file document (§13.7) of the options delivered to that hook, plus `trigger` and `secrets`. It is never a diff.

**HookInput:**

```json
{
  "trigger": "start|settings_change|membership_change|credential_change",
  "version": 1,
  "instance": "<id>",
  "values": {"<key>": <rendered>},
  "people": {"<lowercase user>": {"<field>": <rendered>}},
  "groups": {"<key>": [{"group": "<name>", "value": <rendered>}]},
  "entries": {"<field>": [{"user": "<lowercase user>", "value": <rendered>}]},
  "secrets": {"<key>": "<value>"},
  "credentials": {"<key>": {"<lowercase user>": {"id": "<hex>", "version": <n>}}}
}
```

- `trigger`: the run's trigger when the hook declares it, else `settings_change` if declared, else its first `when`. It is always the **first** key of the JSON object, so a script can read the trigger from the start of stdin without parsing the whole document
- `secrets`: the secret options delivered to the hook. **Secrets reach a hook only on stdin**: never in argv, its environment, logs, op records or errors
- `credentials` (**NEW**, file sharing): for every `person_secret` option of the template, the people with an **active** credential, each with the credential's `id` (hex, new on every create and regenerate) and `version` (1 on create, +1 on every regenerate). Never a hash or a password: the hook reads the hashes from its own read-only mount (§6). Always an object (`{}` without such options)

Hooks must be idempotent. Exit 0 means applied. Any other exit code (or the timeout) is "failed", recorded in the instance's op record (`hook`; a later success clears it). The output is redacted (the secrets sent, the instance's stored secrets in their JSON and HTML encodings, and the instance's current hashes as §13.16 says), then clipped.

**Hook reports (NEW, file sharing).** A hook may print **one** line starting with `PORTCULLIS-REPORT ` (with the space) followed by one JSON `HookReport`; every other output line is log only. The Hub reads it as untrusted input:

```json
{"version": 1,
 "findings": [{"code": "former_account", "severity": "warning", "subject": "alice", "message": "alice's Time Machine folder belongs to a former account (uid 20023)", "uid": 20023}],
 "folders": [{"option": "storage", "name": "alice", "uid": 20000, "former": false, "bytes": 107374182400}]}
```

- exactly one such line, at most 64 KiB, strict JSON (unknown fields refused, one document), `version` 1; at most 500 `findings` and 500 `folders`;
- `code` is one of `former_account`, `wrong_owner`, `name_refused`, `owner_unwritable`; `severity` `problem`, `warning` or `info`; `subject` (a username; for `name_refused` a share name or a username the script refuses), `message`, `option` and `name` are one line, at most 200 runes, without control characters; `uid` a whole number; `bytes` a whole number or `null` (unknown); `former` true when the folder's owner isn't the person's current id;
- a `folders` entry describes one top-level directory of a per-person tree (§13.17): `option` is the `path` option, `name` the directory (a username);
- findings whose subject isn't in the population, and folders of an unknown option, are dropped; a `name_refused` is kept when its subject is a share name the instance's settings hold or a population member (a username the script won't serve: doctor Info naming the user); a malformed report is logged and ignored, and the hook unit stays OK;
- the Hub stores the last accepted report with the time it received it (`<data>/settings/<id>/hook-report.json`) for the File sharing tab and the doctor (§14.5). A report never drives revocation or authorization;
- the line is removed from op records and logs (after redaction, §13.16).

A hook runs when its `when` has the trigger and its input changed (a hash of the document and the secrets' `updated_at`, never their values) or its last run failed; every `start` hook runs on every start, and every hook on a retry (except `ai` hooks, which the engine never runs). Runs per instance are serialised. A hook that timed out (Docker can't kill an exec) blocks the next run until it ends: meanwhile the hooks are skipped `previous run still running` and re-queued with backoff. With no running container the hook is skipped `not running` and the next start delivers it. The admin can retry from the panel.

**Reload:**

Templates may declare one top-level `reload` action:

```yaml
reload:
  service: <service>
  signal: HUP|USR1|USR2
```

or

```yaml
reload:
  hook: <hook name>
```

- Signal form (`HUP`, `USR1` or `USR2`): the Hub sends the signal to the service's running containers via `POST /containers/{id}/kill?signal=…` (`socket-proxy-hub` already allows `CONTAINERS` + `POST`). Counts as applied when the call returns 2xx and the container is still running after a 10 s grace period (and, if it has a healthcheck, not unhealthy). Otherwise "failed" in the op record (`reload`)
- Hook form: the declared hook with the same stdin and exit-code rules; it runs once per delivery run
- Not both forms. A template without `reload` reports the reload unit as `not supported`

`applies: reload` and `on_membership_change: reload` are refused by the validator unless the template has a `reload`.

Data files are written before the reload. If the instance isn't running, nothing is sent (the next start reads the files).

### 13.9 Applies and effects

`applies` declares when a change takes effect:

| `applies` | Meaning |
|-----------|---------|
| `live` | A hook applied it |
| `reload` | The template's `reload` action (§13.8) |
| `next_request` | Headers (each request reads the attributes file) |
| `next_sign_in` | Claims (Keycloak reads LLDAP at sign-in) |
| `restart` | The instance restarts |
| `account_creation` | Only new accounts get it. The UI warns "existing accounts keep their value" |

Defaults:

- `restart` for `scope: instance` (unless delivered only through hooks with `applies: live`)
- `next_sign_in` for claim delivery
- `next_request` for header delivery

The delivery engine picks the strongest effect among changed options: `live`, `next_request`, `next_sign_in` and `account_creation` need no action; then `reload`; then `restart`. Several reloads in one save become one reload, and a restart covers them. Restarts always run in the background. On an enabled instance a changed port, path, env-delivered option or override always restarts. A disabled instance stores the values and delivers nothing.

**Membership deliveries** (people joining or leaving, person-entered values) are debounced **60 s per instance**, so a batch of changes gives one effect; the Hub also runs them after every directory sync and every 10 minutes. A changed data file then applies its `on_membership_change`, and hooks with `membership_change` run.

**Requires.** An instance option with `requires: [<key>, …]` is refused at save when it is non-empty and any listed key is empty. The listed keys must exist, be instance-scoped, and not self-reference. The panel shows the pair together. Used for Craft version + sha256 pairs.

**Requires any (NEW, file sharing).** An instance option with `requires_any: [<key>, …]` is refused at save (`400`, naming the option) when it is non-empty and **every** listed key is empty. The listed keys must exist, be instance-scoped and not self-reference. A save judges `requires_any` only for the options it touches and for the options whose `requires_any` lists an option it touches, so a slot left without groups by a group purge (§13.11; the doctor's `served_to_nobody`) doesn't block an unrelated save. Used by the Samba share slots: a slot's folder needs at least one reader or writer group (§13.17).

**Credential changes (NEW, file sharing).** A credential mutation (§13.16) queues an immediate delivery with the trigger `credential_change`, which ranks above `settings_change`: a queued run that merges it keeps it, so hooks declaring `credential_change` still run. **Removals are immediate:** for an instance with `person_secret` options, a membership removal from its access group or from any group one of its instance `group` / `groups` options names delivers that instance's data files and runs its hooks at once, skipping the 60 s debounce above. Additions keep the debounce.

**Order of a run.** Data files, then claims, then headers, then hooks, then the effect (one reload or one background restart). A run whose settings change under it stops at its next write (`superseded`) and is re-queued with the strongest effect it still owed. A run superseded after it wrote a data file with `on_membership_change: hook` carries a forced run of those hooks into its re-queue: the re-run runs them even though the file is now unchanged, and records the delivered members (§13.16) only when they succeeded.

**Lifecycle downs and revocations (NEW, file sharing).** Every lifecycle down of an instance (backup, restore, delete, restart, disable) takes the instance's delivery lock after its own lock and waits for it **once**, at most 10 s, before it takes the containers down, so a revocation hook in flight (§13.16) finishes first; after 10 s it goes on regardless. A restart's start step then waits for the delivery lock without a time limit (its data files are written under it before the containers are created).

### 13.10 Secrets

`secret` options:

- GET returns `{set: true|false, updated_at}` only, never the value
- PUT accepts exactly one of `{value}`, `{generate: true}` (when the template declares `generate`) or `{clear: true}`; an empty value without `clear` is refused (400). Clearing a secret a `required` or `requires` rule needs is refused
- Stored in `<data>/settings/<id>/secrets.json` (0600, directory 0700, atomic); `state.yaml` holds only `{set, updated_at, generated}`
- Audited `replaced`, `generated` or `cleared`, never with the value

Delivered through env (in the 0600 `.env`, written from the store), file (secrets file, mode 0600) or hook stdin. Never in argv, logs, op records, errors (redacted, then clipped) or the audit. Expert's env editor shows `[set]` and refuses to change an option-owned variable. Backups carry the store as `config/settings-secrets.json` (the archived env has secret variables blanked); a same-instance restore puts it back, a restore into a new id copies it and regenerates `generate`-declared secrets.

### 13.11 Groups disappearing

When an LLDAP group is deleted (through the Hub or outside it), the Hub purges:

- Per-group values and `scope: group` records that reference it (every instance)
- **NEW (file sharing):** the group from every instance-scope `group` / `groups` value (§13.2), the same way and with the same audit; a re-created group of the same name grants nothing
- The purge is audited `settings.purge`: by the deleting admin when the group is deleted through the Hub (immediately, then a delivery), by `hub` when the next reconcile finds a group gone or re-created outside the Hub

Purges are irreversible. The reconcile purges only when the LDAP sanity check passes (the sweep baseline: `admin` and the service account present, and no drop of more than 20% and more than 2 users); otherwise it logs a warning and delivery only filters. A privileged option's row from a group that can no longer hold privileged values grants its lowest value at once and is purged the same way. A template's `group_values` preset row purged with its group comes back only when the Hub itself re-creates that group (enable, create missing groups).

Re-creating a group with the same name inherits nothing. Each per-group row and record stores the LLDAP group id; resolution matches by name and id; a missing group or a mismatched id grants nothing. The next reconcile purges it.

### 13.12 Admin API

Settings are read and edited only on the Hub listener by admins. Settings need Users & Groups: without the directory every route answers `503`; no `X-Forwarded-User` is `401`; delegates and non-admins `403`. The routes:

- `GET /api/instances/{id}/settings` → the settings panel: options with their defaults and warnings, stored values (never secrets), per-person and group rows with their `group_id`, secrets as `{set, updated_at, generated}`, ports, `population {count, why}`, `deliveries`, `entries`, `directory_groups`
- `PUT /api/instances/{id}/settings` → save: `values`, `person` (`{default, resolve, rows: [{group, value, group_id}]}`), `groups`, `secrets` (`{value}` / `{generate}` / `{clear}`), `ports`, `auth_policy`, `auth_policy_inherit`, `public_access`, `public_mode`, `public_tokens`, `sign_in`; only what changed. Unknown fields, trailing data and bodies over 256 KiB are refused with a fixed message (never echoing a value). Answers `{effect, changed, warnings, deliveries}`. A row sent with a `group_id` no stored row of that group has (purged or re-created since the panel loaded) is `409`; a row without one is new
- `POST /api/instances/{id}/settings/preview` → the same body, nothing stored: per person option every member's value and reason (including the losing rows, only here), `changes`, `no_access`, `population`, the effect and (**NEW**, AI support) `plan_hash` (a digest of the update and this preview; the Portcullis MCP's `save_settings` requires it and recomputes it before saving, `409` when it differs; the HTTP `PUT` doesn't take it) and `warnings` (e.g. a policy that reaches LoA 3 switches AI support off, §15.11)
- `POST /api/instances/{id}/settings/retry` → run the delivery again (every hook included except `ai` hooks, §13.8), audited `settings.retry`; answers the `DeliveryReport`
- `PUT /api/instances/{id}/settings/entries/{key}/{user}` `{"value": …}` and `DELETE …` → an admin sets (only with `admin_override`, else 403) or clears (always) a person-entered value (§13.13)

**Delivery status** (`deliveries` in the panel, `DeliveryReport` from save and retry): one result per unit, `{unit, ok, skipped, message, error, at}`, plus `pending` (a run is queued) and the last `trigger`. Units: `env`, `env:values` (only while some option value can't go in the `.env`: those variables are written empty, the unit's error names them, never the value), `file:<name>`, `credentials:<key>` (**NEW**, file sharing: one per `person_secret` option; it reconciles the option's hash files with the credential metadata — orphan files deleted, active metadata without a file voided, after the secrets-epoch check of §11.6 — and records a digest of the active metadata only: ids and versions, never hash bytes), `claim:<attribute>`, `headers`, `hook:<name>`, `reload`, `restart`, and `delivery` (the run as a whole, when it couldn't run). `error` is redacted, then clipped. `skipped` is one of these stable strings:

| `skipped` | Meaning |
|-----------|---------|
| `unchanged` | Nothing new to deliver |
| `not running` | No running container; the next start delivers |
| `directory unavailable` | No directory snapshot; the last delivery is kept |
| `busy` | The instance was busy (lifecycle operation, restore, delete); re-queued shortly |
| `superseded` | The settings changed during the run; a newer run follows |
| `not supported` | `reload` on a template without a reload action |
| `previous run still running` | A timed-out hook exec hasn't ended yet; re-queued with backoff |

A failed unit is also logged: `settings: <id>: delivery unit <unit> failed: <redacted error>`.

Every change is audited as `settings.change` with:

- instance and key
- scope and group (for per-group rows)
- before → after (secrets: "replaced")
- the actor

### 13.13 Person-entered values

`scope: person_entered` lets each person enter their own value (e.g. their Mozilla account id for the Firefox Sync allowlist).

**Declaration:**

- Types: `string`, `int`, `bool`, `enum` only (not `secret`)
- Constraints: the type's own (`pattern`, `min_len`/`max_len`, `format`, `min`/`max`, `options`). A `string` must declare `max_len` ≤ 256 or a `pattern`/`format` that bounds it
- `unique: true` (string/int only): no two people of one instance hold the same value. Compared in canonical form (templates with case-insensitive ids use a lowercase `pattern`)
- `admin_override: true`: admins may set a value on someone's behalf. Default false. Admins can always clear
- Refused: `default`, `required`, `resolve`, `resolve_choices`, `group_values`, `privileged`, `requires` (either direction), `self_visible: false`, `applies: account_creation`
- Deliveries (§13.6 rendering):
  - `file`: the data file's `entries` section
  - `hook`: the same, on stdin
  - `env`: the list of values as one variable (shape in §13.6). Needs `render.join` or `render.format: json` and `applies: restart`
  - `claim`/`header`: each person's own value, per person. People with no value get none
- `applies` must match the delivery: file `applies` = the file's `on_membership_change` (`restart` → `restart`, `reload` → `reload`, `hook` → `live`; a file without one is refused), hook `applies: live` with `membership_change` in `when`, claim `next_sign_in`, header `next_request`
- Templates whose routes can run without Portcullis identity (method `public` or `custom`, or `native_login.allow_without_gateway`) must declare `auth.access_group`

**Population:** who may enter and whose values are delivered (§13.3). When routes carry Portcullis identity: the person-option population of §13.3. When they don't: the members of `auth.access_group` minus expired `expiring` entries.

**Leaving, rejoining, deleting:**

- Leaving the population: the stored value is kept, but no longer delivered. Rejoining: it is delivered again
- Deleting the account through the Hub: deletes the person's values in every instance (audited, admin actor)
- Each value stores the LLDAP user uuid. An account deleted outside the Hub or re-created no longer matches; from that moment the value is not delivered, and the next reconcile purges it (audited, actor `hub`)
- A disabled instance keeps its values and delivers none
- Backups carry them; restore into a new id copies them (the uuid check still applies)
- A template update that removes/retypes the option or tightens constraints drops values. Duplicates when `unique: true` is newly declared: the earliest `updated_at` stays. Audited

**Saving:** the value must parse under the option's constraints and fit every delivery (an env item holding the separator, a `'` or `\`, or a header/claim value that doesn't render, is a 400). An unchanged value (same value, account and setter) stores and audits nothing; a person re-saving an admin's value makes it theirs.

**Uniqueness:** checked at save against every stored value of that option in that instance, delivered or not (so a rejoin never collides), for admins too. Conflict: `409` "<label>: this value is already registered for <app> by another person" (never names the holder). The audit records refusals with the holder's name.

**Refused-save limit:** a person's refused self-service saves (any 4xx) are limited to 10 a minute, then every save is `429` until the minute ends (§5.1). 5xx answers don't count, and the limit is checked before the directory is asked.

**Clearing:** a person can always clear their own value (stored under their current account), also outside the population or on a disabled instance. Admins can always clear any value

**Delivery:** the `entries` section of data files and hook stdin (§13.7); env deliveries are the list of §13.6 (user order, no usernames, one bad item left out, never the whole list); per-person claims/headers for population members with a value. Delivered values: population members whose stored uuid equals their current LLDAP uuid (with the directory unavailable, nobody new), values that still parse, under `unique` the earliest of equal values. Changes go through the membership path: debounced 60 s, the file's `on_membership_change`, hooks with `membership_change`

**Visibility:**

- My apps: the person sees only their own value (status: not set / set / set by admin, when), input constraints, when it applies. Never others' values
- Admin panel: every stored value with person, when, by whom, "delivered" or why not ("no access", "account changed"). Population members with no value listed as "not set". Admins can clear any; set when `admin_override`

**Routes:**

- People listener, caller only (`X-Forwarded-User`, CSRF guard, body ≤ 4 KiB):
  - `PUT /api/me/apps/{instance}/values/{key}` `{"value": <json>}` → 200 with the caller's entry
  - `DELETE /api/me/apps/{instance}/values/{key}` → 204 (also when nothing was set)
  - Refusals: 404 (instance not enabled, key not `person_entered`, caller not in population — same answer for all); 400 (constraint, unknown fields); 409 (uniqueness); 413 (body); 429 (refused-save limit); 503 (LLDAP unavailable)
- Hub listener, admins only: `PUT /api/instances/{id}/settings/entries/{key}/{user}` `{"value"}` → 200 with the row; `DELETE` → 204, always. PUT without `admin_override` is 403, for someone outside the population 404. Uniqueness applies

**Audit:** `settings.person_value`, target `<instance>/<key>/<user>`, actor = person / admin / `hub`. Detail: `set: <before|unset> -> <after>`, `cleared`, `deleted` (account deleted), `purged` (account changed), `invalidated` (template update). Refusals audited `refused`, except saves past the refused-save limit. Values shown (not secrets)

**State:** `state.yaml` per instance: key → lowercase user → `{value, uuid, updated_at, set_by}` (`set_by` empty for person, admin name otherwise). Not in `delivered.json` beyond per-unit hashes.

### 13.14 Source sync and template updates

When a template source syncs (`./portcullis upgrade`, SIGHUP, Hub startup), discovering the templates never changes stored settings. After the final discovery of a sync (and at startup), the Hub prunes:

- values of options that no longer exist, or whose scope or type changed (audited `settings.purge`)
- person-entered values that no longer pass the constraints, and later duplicates under a newly declared `unique` (audited `settings.person_value` … `invalidated`)

The app-updates preview lists both before an update is applied.

Until then, resolution ignores values that don't match the current option.

### 13.15 Shared folders, checks and LAN-only ports

Three optional template fields (a MINOR addition to contract v3, §1) let a `path` option use a **shared folder** (§14): a host directory the admin defines once and several app instances use with consistent ownership. They also declare doctor checks and LAN-only ports. The templates repo's schema, `tests/validate.py` and the Hub implement exactly what this section says.

**The `folder` block** (on a `type: path` option, `scope: instance` only):

| Field | Required | Description |
|-------|----------|-------------|
| `access` | Yes | `read` or `write`: what the app does on this mount. `read` is **always** mounted read-only, on a shared folder and on a custom host path alike |
| `runs_as` | Yes | The uid and gid the app's process uses on this mount. Each of `uid` and `gid` has exactly one source: a number (`uid`, `gid`), or the env name of an instance `int` option of the same template (`uid_env`, `gid_env`; e.g. `PUID` / `PGID` images), or (**NEW**, file sharing) `uid_from` / `gid_from`: the key of a `person_id` option of the same template, meaning "each person's own id" (below). Both ids need a source, except that `uid_from` with `joins_group: template` needs no gid source (the template applies the folder gid itself) |
| `joins_group` | No (default `group_add`) | How the app joins the folder's group: `group_add` (the Hub adds the folder gid as a supplementary group of the target service), `gid_env` (the folder gid becomes the app's primary group through `runs_as.gid_env`, which is then required), or `template` (the template does it itself, e.g. Samba's `force group`, from `PORTCULLIS_FOLDER_GID_<KEY>`) |
| `must_own` | No (default `false`) | The app refuses files it doesn't own: the Hub also sets the owner to the app's uid. Only with `access: write`; at most one `must_own` use per folder (§14.3) |

The validator refuses, naming the option and the reason:

- `folder` on any type but `path`, or on a `path` with another scope;
- `folder` together with `mode`, `needs` or `writes_as`, with the hint "folder.access and folder.runs_as replace them";
- a missing or unknown `access`, a missing `runs_as`, two sources for one id or none for one;
- a `uid_env` / `gid_env` that isn't the env name (`EnvName()`: its `env` delivery, else `UPPER(key)`) of an instance `int` option of the template; any `PORTCULLIS_*` name;
- numeric `runs_as` ids that don't match the service's compose `user:` when it sets one; a `user:` of the form `${PUID:-1000}:${PGID:-1000}` matches only the `_env` form naming those variables; a non-numeric `user:` (`www-data`) next to a `folder` block ("give numbers in compose `user:`");
- `joins_group` outside the three values, `gid_env` without `runs_as.gid_env`, `must_own` with `access: read`;
- two folder options of one service naming the same `uid_env` or `gid_env` with different `runs_as` or `joins_group` (one primary gid per process; sharing the variable with identical blocks is normal); a service with a `gid_env` join where another folder option on it doesn't use that `gid_env` ("every folder option on it must use runs_as.gid_env <G>");
- a `joins_group: gid_env` block whose variable another service, one no such folder option targets, reads in its compose `user:` gid or `group_add` ("only the services the folder options target may use a gid_env variable");
- next to a folder block, a `group_add` entry of the target service that isn't a number or exactly one `${NAME}` of an instance `int` option (group names such as `video` included: a hardware-transcoding group needs a declared `int` option, e.g. `group_add: ["${RENDER_GID:-109}"]`);
- the default of an option a `runs_as.uid_env` / `gid_env` or a `writes_as` key names that isn't a whole number ("whose default … is not a whole number"; ints, whole floats and decimal strings are read), and a non-integer numeric `runs_as` id ("want a whole number, not …", a variable goes in `uid_env` / `gid_env`);
- (**NEW**, file sharing) a `uid_from` / `gid_from` that doesn't name a `person_id` option of the template; `gid_from` without `uid_from`; `gid_from` with a `joins_group` other than `template`; `uid_from` together with a numeric `uid` or `uid_env` (two sources for one id).

**Per-person owners (NEW, file sharing).** `uid_from` / `gid_from` say that the app writes on this mount as **each person's** Hub-allocated id (§13.16), not as one fixed process id. Two forms:

- **A shared folder written by every person** (the Samba share slots, §13.17): `runs_as: {uid_from: <person_id key>}` with `joins_group: template` and no gid source. Files land as `<person's uid>:<folder gid>`; the group is the folder gid the template applies itself from `PORTCULLIS_FOLDER_GID_<KEY>` (Samba's `force group`). This is project 2's full model: assignment, plan, undo, probes and the doctor work unchanged, with the owner unknown (`OwnerKnown` false: the plan is group-only, no principal uid).
- **A per-person tree** (Time Machine storage, Samba homes): `runs_as: {uid_from: <person_id key>, gid_from: <person_id key>}` (each person's private group equals their uid) with `joins_group: template`. Such an option can't take a `folder:<id>` value: a settings save, its preview and an assignment refuse one with `409`. It gets no `PORTCULLIS_FOLDER_GID_<KEY>` (empty), no setgid / group ACL / mask plan, and is never a `shared_path` or `folder_owner` subject; the doctor checks each top-level directory instead (§13.17, §14.5).

**The folder gid range.** Gids **60000–60999** are the folder groups (§14.1); only a folder assignment gives them to an app. Every **gid reference** is range-checked; uid sources never are (a uid in that range is harmless). The gid references are: a numeric `runs_as.gid`, `runs_as.gid_env`, a numeric `writes_as.gid` or the option a `writes_as` gid key names, and on **every** service the compose `user:` gid part and each `group_add` entry. The validator refuses, without a `setting` prefix and before the options are checked (services in sorted order):

- a gid in the range given as a number, as the numeric default of `${X:-n}` / `${X-n}`, or as the default of the option `${X}` / `$X` names ("service <s>: compose user: gid <n> … is in 60000-60999 (shared folder groups)", the same for `group_add`); `!!int` scalars are decoded as YAML does first, so an octal `0165141` is 60001; YAML aliases are followed;
- a gid source in any other form than a whole number, a plain group name (`group_add` only), `$NAME`, `${NAME}`, `${NAME:-n}` or `${NAME-n}` with a whole-number `n`: mixed text (`${X:-6}0001`, `1${X}`, `${A}${B}`), nesting, `$` in a fallback, `$$` escapes, an empty or text fallback, `${NAME?err}` and the `+` forms `${NAME:+n}` / `${NAME+n}` ("must be a whole number … or exactly one ${NAME} / $NAME (no mixed forms)"); the compose `user:` uid part follows the same rule, a plain user name also allowed (`www-data`; still refused next to a folder block); a `user:` whose `${…}` fallback holds anything but digits is refused before it is split at `:`;
- a `$NAME` / `${NAME…}` uid or gid source that doesn't name an instance `int` option of the template, matched against every env delivery of each option ("must name an instance int option of this template (not a string option, an undeclared variable or PORTCULLIS_*)");
- a `group_add` that isn't a list, an entry that isn't a scalar, a `user:` that isn't a string or a whole number;
- YAML `!!binary` anywhere in `compose.yml` or `manifest.yaml` ("a binary scalar decodes to text no check sees"); `user:` / `group_add` scalars accept only `!!str`, `!!int` and `!!null`.

The Hub enforces the same range at run time: a settings save and its preview refuse a value in it for an option a gid reference names (below), rendering refuses (`409`) a gid reference that would reach an app in the range or a `gid_env` variable another service reads (the folder gid is then never written there, and the `.env` gets the variable empty), and the custom override refuses a `user:` gid in the range ("gid 60000–60999 is reserved for shared folder groups"; leading zeros read as the number). The doctor's runtime check (§14.5 `gid_collision`) covers what no static rule sees: root containers changing groups, an image's `USER`, a `PGID` passed through `environment:`.

**Values.** A `path` option holds a host path or a shared folder: `folder:<id>` or `folder:<id>/<subpath>`. The id matches `^[a-z][a-z0-9-]{0,30}$` (§14.1). The subpath is relative, equal to its own `path.Clean` (no `//`, no trailing `/`, no `.` segment), has no `..`, no `:`, no control characters and is at most 255 bytes; the apply creates it when missing (§14.3). A template without a `folder` block can be pointed at a shared folder too (the doctor reports "this template doesn't say how it writes", Info); its mount is read-only unless the admin confirmed write access in the assignment (stored per instance and option).

**Rendering** of a folder value (host path = the folder's path, plus `/<subpath>`):

- **Mount:** compose's long syntax, `{type: bind, source: <host path>, target: <mount>, read_only: <bool>, bind: {create_host_path: false}}` (`$` written as `$$`), so a missing folder or subpath fails the `up` instead of Docker creating it as a `root:root 0755` directory. Read-only when `access: read`, or when there is no `folder` block and no confirmed write.
- **Group:** with `joins_group: group_add` (and for options without a `folder` block), `group_add: ["<gid>"]` on the target service (strings; compose merges them with the template's own list). Only the gids of the folders the instance mounts. Never in the custom override: `group_add` stays forbidden there and the Hub never writes that file.
- **`gid_env`:** the variable named by `runs_as.gid_env` is written with the folder gid instead of the option's stored value, on every `.env` write (save, start, delivery); no `group_add`.
- **`template`:** no `group_add`; the template reads the variable below.
- **Variables:** for **every** `path` option of the instance, every `.env` write carries `PORTCULLIS_FOLDER_GID_<UPPER(key)>` (the folder gid when the value is a folder value, else empty) and `PORTCULLIS_FOLDER_UID_<UPPER(key)>` (the `must_own` use's uid when the folder has one, else empty), single-quoted like every Hub-written value. Writing them empty clears them when a folder is unassigned. The prefix `PORTCULLIS_FOLDER_` is reserved (§2): no template may declare a name under it, and the Expert env editor refuses to change one ("set by the Hub"). **NEW (file sharing):** a template may pass the folder gid to its container: `${PORTCULLIS_FOLDER_GID_<KEY>}` is allowed in a service's compose `environment:` values, in exactly that form (no default or alternate), only when `<KEY>` is a `path` option with a `folder` block that targets that service. Everywhere else a `PORTCULLIS_FOLDER_*` reference stays refused.
- Before every `up` of an instance with a folder value that has a subpath, a read-only probe checks the subpath (§14.2).

**Settings saves.** Folder values change only through an assignment (§14.3). A settings save **and** its preview (§13.12) refuse (`409`):

- a value `folder:…`, or replacing or clearing one: "assign through Settings → Shared folders";
- a change of an option a folder writes through `gid_env`: "set by shared folder <name> (gid <N>)";
- a value in 60000–60999 for an option a gid reference names (`runs_as.gid_env`, a `writes_as` gid key, a compose `user:` gid or `group_add` `${X}`; never a uid source): "gid 60000–60999 is reserved for shared folder groups" (such values come only from a folder assignment's `gid_env`);
- (**NEW**, file sharing) a `folder:` value on an option with `runs_as.gid_from` (a per-person tree, above).

Restores don't apply these refusals; they clear values naming a missing folder instead (§11.6).

**Docker's data root (NEW, file sharing).** A settings save, its preview and both restores refuse (`400`; Docker's data root unreadable: `503`) a hand-typed `path` value at, above or under Docker's data root (`DockerRootDir`, the same rule as for folder paths, §14.1). It protects `hub_secrets` and every other volume.

**`checks`** (option level, next to `folder`, never inside it): a list of doctor checks from a fixed catalog. Each entry has `kind` and a required `reason` (one line, ≤ 200 characters, no control characters) that the doctor shows. Adding a check kind is Hub work and a contract change; adding a check is template work.

| `kind` | On | Parameters | Finding (§14.5) |
|--------|----|------------|-----------------|
| `filesystem` | a `path` option with a `folder` block | `needs`: subset of `[xattr, acl]`; `not`: subset of `[nfs, cifs, fuse]` | Disk: the path's filesystem lacks a `needs` feature or is in `not` → Problem, explain-only |
| `exclusive` | a `path` option with `folder.access: write` | — | Config: another instance (of the same template too) writes the same folder or host path → Problem, explain-only |
| `free_space` | a `path` option | `min`: a size in binary units (`500GiB`; `500GB` and `lots` are refused, as for `size` options) | Disk: less free space than `min` → Warning; evaluated when the path is scanned (§14.5 scan targets) |
| `requires_group_value` | a `scope: person` option | — | Config: no group row sets the option → Warning (instead of Info) |

An unknown kind is refused, listing the catalog; `kind: lan_only` is refused with the hint "set lan_only: true on the port"; a parameter the kind doesn't take is refused.

**`ports[].lan_only`** (boolean, default `false`): the port should be reachable only from the local networks (LAN, VPN). It changes nothing in how the port is bound; the doctor judges its binding (§14.7). A Hub without §14 ignores it. Ports without it are never an exposure finding.

**Example** (`jellyfin`, as converted):

```yaml
# manifest.yaml (excerpt)
settings:
  sections: [Libraries]
  options:
    - key: movies_path
      label: Movies folder
      description: Host path to your movies library
      section: Libraries
      type: path
      target: {service: jellyfin, mount: /data/movies}
      folder:
        access: read                  # always mounted read-only
        runs_as: {uid: 0, gid: 0}     # the image runs as root (no compose user:)
        joins_group: group_add        # the default
      applies: restart
```

With `movies_path` = `folder:media/movies` (folder `media` at `/srv/media`, gid 60001) the Hub's override gets:

```yaml
services:
  jellyfin:
    group_add: ["60001"]
    volumes:
      - type: bind
        source: /srv/media/movies
        target: /data/movies
        read_only: true
        bind: {create_host_path: false}
```

and the `.env` `PORTCULLIS_FOLDER_GID_MOVIES_PATH='60001'` and an empty `PORTCULLIS_FOLDER_UID_MOVIES_PATH` (no `must_own` use).

**Example** (Samba, one of its share slots, §13.17):

```yaml
# manifest.yaml (excerpt)
settings:
  options:
    - key: share1_folder
      label: Share 1 folder
      type: path
      target: {service: samba, mount: /shares/1}
      folder:
        access: write
        runs_as: {uid_from: uid}                  # each person's Hub-allocated uid (person_id option uid)
        joins_group: template                     # reads PORTCULLIS_FOLDER_GID_SHARE1_FOLDER
      requires_any: [share1_readers, share1_writers]
      checks:                                     # option level, next to folder
        - kind: filesystem
          needs: [xattr, acl]
          not: [nfs, cifs, fuse]
          reason: macOS clients store metadata in extended attributes
ports:
  - key: SAMBA_SMB
    label: SMB
    container: 445
    default: 445
    protocol: tcp
    service: samba
    lan_only: true
```

```yaml
# compose.yml (excerpt)
services:
  samba:
    environment:
      SHARE1_GID: ${PORTCULLIS_FOLDER_GID_SHARE1_FOLDER}   # the one allowed form (§13.15 Variables)
```

### 13.16 Per-person credentials and ids — NEW (file sharing)

The Hub implements `person_secret` and `person_id` (§13.2) generically: it knows nothing about Samba. Every Samba value (username rule, reserved names, share names) is in the templates' manifests (§13.17).

**Passwords.**

- One credential per (person, instance, `person_secret` option): a person with two file-sharing apps has two passwords, and regenerating one doesn't touch the other. **Self-service only:** only the person creates or regenerates theirs (§5.1); admins list and revoke, never create (an admin who created one would have seen it).
- `length` characters (24 for both templates) drawn with `crypto/rand` (no modulo bias) from exactly this 54-character alphabet: `23456789ABCDEFGHJKLMNPQRSTUVWXYabcdefghjkmnpqrstuvwxyz` — the digits without `0 1`, upper case without `I O Z`, lower case without `i l o`; 24 characters are about 138 bits.
- Shown as groups of 4 joined by `-` (29 characters for 24). The dashes are part of the password: what people read is what they type.
- **NT hash:** the uppercase hex of MD4 over the UTF-16LE encoding of the whole dashed password (`golang.org/x/crypto/md4`). One file per person: `<secrets>/<instance>/<key>/<username>.nt` on `hub_secrets` (§6), 32 hex characters and `\n`, `0600`; directories `0700`; owner uid 10001.
- **The secret never leaves its place.** Neither the password nor the hash appears in `state.yaml`, `instance.yaml`, env, argv, logs, the audit, op records, hook stdin or hook output, instance or core backups, or any API answer other than the one create / regenerate answer (`Cache-Control: no-store`). The password is a byte buffer zeroed once that answer is written. For an instance with `person_secret` options, every current hash (upper and lower case) is redacted from hook output, op records, unit errors, Exec answers and the container logs API of that instance. No digest or hash the Hub stores (`delivered.json`, the hook input hash, plan hashes) includes hash bytes or a function of them.
- **Safe paths:** independently of the template's username rule, the Hub refuses (`500`, logged) any username or option key outside `^[a-z0-9_][a-z0-9_.-]{0,63}$` when it builds a secrets path, and confines the result under `HUB_SECRETS_DIR`.
- **Metadata** in `state.yaml` `credentials`: instance → key → lowercase user → `{id, version, uuid, created_at, created_by, revoked_at, revoked_by, reason}`. `id` is new on every create and regenerate, `version` is 1 on create and +1 on every regenerate, `uuid` the person's LLDAP user uuid at creation, `created_by` always the person. `reason` is one of `self`, `admin`, `leave`, `deleted`, `restore`. Not in instance archives (§11.5).
- **Statuses** on My apps (`MyCredential.status`, §5.1): `none`; `active` (`since` = created_at); `voided` (`reason: "restore"`, `since` = when it was voided; "Your password was reset by a restore on <date>; create a new one"); `unavailable` (`reason` = the template's username reason, also for the hard rules of create step 2; no button).

**Create and regenerate** (`POST /api/me/apps/{instance}/credentials/{key}`, §5.1), in this order:

1. the instance is enabled, the key is a `person_secret` option and the caller is in its population; else `404` (one answer for all);
2. the username rule (`username.pattern` and `reserved`) and, for every `person_secret` option whatever its pattern, the hard rules a Unix and Samba account name can't break: no `..`, no `/`, no leading `.` or `-`, and not `^pfg[0-9]+$` (the shared-folder group names, §13.17); else `409` with the template's reason (the card shows `unavailable` with that reason). The fresh-auth proof is not consumed;
3. the caller's LLDAP uuid is known (`Membership.UUIDs`); else `503`. The secrets volume is usable (§6); else `503`;
4. the fresh-auth proof (§8); else `403` with the generic text;
5. the password and its hash; under the Hub's lock the hash file (rotating the secrets epoch, §11.6), the metadata and `state.yaml`;
6. the audit (`credential.create` or `credential.regenerate`), then the answer;
7. an immediate `credential_change` delivery (§13.9) and a non-blocking holder check (below), so a removal that raced the create is revoked at once. A **regenerate** removes the old hash like a revocation: after the commit the Hub applies it live exactly as "How it is applied" steps 1–3 below say (the hooks within 8 s, else the kill), so a skipped or failing hook can't leave the old password working.

Refused creates count toward the people listener's per-caller limit (10 refusals a minute, then `429`, §5.1). Revoking your own (`DELETE`, `reason: self`) needs no fresh auth and is applied like every revocation (below).

**Revocation** (`revoke_on_leave: true`). A credential is destroyed, not paused: its hash file and active metadata go, and coming back means creating a new password.

- **Who is revoked** (one pure holder check shared by the revoker and the doctor's canary, §14.5). With LLDAP answering, an active credential is revoked when its holder is absent from LLDAP (`reason: deleted`), outside the instance's population (`leave`), or has a non-empty uuid other than the recorded one (`deleted`: the account was deleted and created again). An **empty** current uuid revokes nothing on that ground; the doctor shows the Problem "can't verify <user>'s account". An LLDAP that answers but lacks the access group revokes everyone (fail closed, irreversible; logged loudly). LLDAP unreadable: the check does nothing, and the next one retries.
- **When.** Hub-made changes (member removal, user or group deletion, instance delete) and the rule evaluator's removals revoke at once, with no debounce. Edits made directly in LLDAP are caught by the holder check on the evaluator's 60 s tick (the evaluator always runs while Users & Groups is configured): within about 60 s plus the hook. The same tick also compares, for every `person_secret` instance, the expanded members of each `groups` option (`render.expand_members`, the share readers and writers) with what the last delivered data file holds (`delivered.json` keeps the population and each option's expanded members, recorded only by a run whose file and hook units all succeeded); a removal triggers an immediate delivery (§13.9) — additions keep the 60 s debounce —, and the template's hook ends the sessions of people whose shares shrank (§13.17). People should therefore be managed through the Hub.
- **How it is applied** — the same path for **every** revocation (self, admin, leave, deleted; only the audit action differs: `credential.revoke` for self and admin, `credential.revoke_leave` for leave and deleted), independently of the delivery engine: under the Hub's lock the hash file and the metadata go (epoch rotated), then the audit. Then, per affected instance:
    1. no running container of the hook's service: done (the next start's converge has no account for them);
    2. otherwise the Hub runs every hook whose `when` lists `credential_change` with a freshly built `HookInput`, under the instance's delivery lock (taken with retries for at most 2 s) and with an exec timeout of min(the hook's timeout, 8 s); every one exiting 0: done. Zero hooks run (none declared or every one skipped) is not done: it goes to step 3;
    3. anything else (no hook run, the lock not obtained, a skip, an error, a timeout, the directory unavailable, a previous exec still running): the Hub kills the project (`compose down`, else by container name, else SIGKILL to its containers) without waiting for a lifecycle operation, records op `credentials` "revocation could not be applied live; the instance was stopped", and starts it again in the background (the start-time converge has no account for them). If that start fails, the instance stays down and enabled (drift shows it).

    A normal immediate `credential_change` delivery follows for the bookkeeping. A template's hook must therefore apply a revocation within 8 s.

    **A hash that may remain.** When a revocation's removal of the **old** hash file failed, or the secrets volume couldn't be opened, that file may still be there: the Hub skips step 2 and goes straight to step 3 (the kill), and records the failure as a secrets reconcile error: every start of a `person_secret` instance is refused until a reconcile succeeds, and a start's delivery refuses while the instance has a `credentials:<key>` unit error. A failed **regenerate** whose **new** hash file may remain is different: that hash belongs to a password nobody received, so the Hub voids the credential and still runs the hooks (steps 2–3 as usual).
- **Keys no longer `person_secret`.** Active credentials on a key that is no longer a `person_secret` option of the instance's template (renamed or dropped by a source sync, §11.8) are revoked (`reason: leave`, logged as an error), the instance's project is killed by name, and it is then started again in the background on the current template.
- **Instance delete** removes the instance's secrets right after its compose down (§11.4). **Restore** voids (§11.6).
- **Self and admin revokes** take the same steps 1–3: self (`DELETE /api/me/apps/{instance}/credentials/{key}`, §5.1, `reason: self`, audited `credential.revoke` actor `self`) and admin (`DELETE /api/instances/{id}/credentials/{key}/{user}`, `reason: admin`, `revoked_by` = the admin, audited `credential.revoke` with the admin as actor).

**Admin routes** (Hub listener, `adminOnly`, CSRF-guarded; never on the people listener):

- `GET /api/instances/{id}/credentials` → `[CredentialsView]`, metadata only: per `person_secret` option `{instance, key, label, population, active, rows, folders, last_sync}`, each row `{user, status, since, reason, ids, values}` (`status`: `none`, `active`, `voided` (`reason: restore`), `revoked` (with `reason` = `self`, `admin`, `leave` or `deleted`) or `unavailable` (`reason` = the template's username reason, as on My apps); `ids`: the person's `person_id` values by key; `values`: their displayed person-scope values), `folders` the last hook report's folders (§13.8). Never a password or hash;
- `DELETE /api/instances/{id}/credentials/{key}/{user}` → `204`.

**Audit** (`audit.jsonl`, §9.5): `credential.create`, `credential.regenerate`, `credential.revoke` (actor `self` or the admin), `credential.revoke_leave` (reason `leave` or `deleted`), `credential.void_restore` (the count only). Fields: instance, key, username, actor, reason. Never the password, the hash, or a fresh-auth code, verifier, nonce or token; a refused create is audited `refused` with the refusal's reason only.

**Person ids** (`person_id`, pool `posix_uid`).

- **Range 20000–59999.** The allocator also refuses every id in a static reserved set: 0–999, 1000, 10000–10099 (the Hub's 10001, enroll's 10002, …), 65534 and 60000–60999 (the shared-folder gids, §14.1), and skips any uid that a hook report or a per-person tree scan lists as an owner. A person sharing the Hub's uid could read every hash and data file.
- **Hub-wide:** every `person_id` option with that pool, in every instance, gives a person the same id. Allocated the first time a person needs one, from the pool's `next` upwards (ids only increase), keyed by (lowercase username, LLDAP user uuid). **Never reused:** a changed uuid (the account was deleted and created again) retires the old id and allocates a new one, so a re-created account never owns a former account's files; a uuid that comes back (LLDAP restored) gets its own entry and id again and the current one is retired; a uuid held under another name, or one with control characters, gets no id. An exhausted pool is an error ("uid pool posix_uid is exhausted"), nothing saved.
- **A pool never rewinds:** on a secrets-epoch mismatch (§11.6, a core restore) every pool's `next` advances by 1000 before any allocation, under the same lock and in the same `state.yaml` save as the epoch rotation, before it. No id is allocated while a secrets reconcile has failed (above).
- **Allocated before rendering**, in one short locked section that saves `state.yaml` once if anything was allocated, before the delivery's render and before a start's data files. A population member without a uuid gets no id and is left out of the file (logged); the rest is delivered. The whole delivery is skipped only while the directory is unavailable.
- **State:** `state.yaml` `person_ids`: pool → `{next, entries: [{user, uuid, id, retired_at}], seen_owners: [{id, at}]}` (`seen_owners`: ids inside the range that a hook report or a per-person-tree scan found owning files, first-seen time; sorted, at most 4096, the earliest dropped first; never allocated). Carried by core's backup with `state.yaml`; not in instance archives, so an instance restore keeps everyone's id.
- Never shown on My apps; the admin panel and the File sharing tab show it.

### 13.17 File-sharing templates (Samba, Time Machine) — NEW (file sharing)

The templates repo's `samba` (ServerContainers, `smbd-only`) and `timemachine` (`mbentley/timemachine`) templates implement this section; their CI asserts it. The Hub enforces none of it beyond §13.2–13.16: these are the templates' obligations.

**Common shape.**

- `instances: multi`, `auth.method: custom` with **no** Traefik router, `group_access: true`, `access_group: users_<id>` (§3); `auth.notes` "No web page: file sharing over SMB …".
- A `person_secret` option `share_password` (`hash: nt`, `length: 24`, `delivery: file`, `mount` at `/portcullis/secrets`, `revoke_on_leave: true`, `on_restore: void`, `username` `^[a-z_][a-z0-9_.-]{0,31}$` plus every account of the image, `info` with `smb://{value:connect_address}{port_suffix:<PORT KEY>:445}/<share>` and `{user}`) and a `person_id` option `uid` (pool `posix_uid`, `self_visible: false`, delivered to the people file).
- A `tsv` people file (§13.7) and one hook, `sync` (`portcullis-sync`, `when: [start, settings_change, membership_change, credential_change]`, `timeout: 60s`).
- `connect_address`: `string`, `format: hostname` (an IPv4 address matches too, §13.2), `required`, `self_visible: true`.
- One port, 445/tcp, `lan_only: true` (no 137–139).

**The converge script `portcullis-sync`** (busybox sh; one copy shared by both templates, kept identical by a test) runs before smbd starts and as the hook, idempotently:

- It owns `smb.conf` entirely; the effective configuration may hold no `include`, `config backend` or `registry shares` (exit 4).
- `[global]` has exactly: `server min protocol = SMB3`, `server smb encrypt = required`, `server signing = mandatory`, `ntlm auth = ntlmv2-only`, `lanman auth = no`, `map to guest = never`, `restrict anonymous = 2`, `disable netbios = yes`, `smb ports = 445`, `wide links = no`, `follow symlinks = no`, `smb3 unix extensions = no`, `hosts allow = <PORTCULLIS_LOCAL_NETWORKS, space-separated>`, `hosts deny = 0.0.0.0/0 ::/0`. Every share has `guest ok = no`. `testparm -s` must show these values (as it normalises them), otherwise the script exits non-zero and nothing serves.
- An empty `PORTCULLIS_LOCAL_NETWORKS` (§3.1): it never renders an allow-all `hosts allow`; the container doesn't start (the doctor's `local_networks_empty`, §14.5).
- **No share is ever rendered with an empty `valid users`** (Samba reads it as "everyone"): a share whose user list is empty is left out.
- The passdb and Samba's state are on tmpfs (`/var/lib/samba`, `/var/cache/samba`, `/run/samba`, `/run/portcullis`), so no hash reaches a Docker volume or an instance backup. It reads the Hub's files as uid/gid 10001 (a privilege drop, not `DAC_OVERRIDE` / `DAC_READ_SEARCH`, which the cap set doesn't have) and imports hashes from a `0600` root-owned temp file on tmpfs, never from argv.
- Unix users get their Hub uid; every account not in the desired state is removed; a name that fails the username rule is skipped and reported.
- **Neither image's own entrypoint runs** (Time Machine: s6 started directly; Samba: runit's `runsvdir`): no default account, share or throwaway password, and none of the images' config switches apply. A fail-closed stop writes a down marker that `--check` (the healthcheck) refuses until a good run, whatever the supervisor restarts. Samba's smbd runs in its own process group (under runit, smbd's group signal would otherwise take `runsv` down); Time Machine's runs with `--no-process-group`, since s6-supervise already makes its run script a session leader.
- It ends a user's open sessions (the smbd PIDs `smbstatus -p -n` lists for their uid — by number, since a removed account no longer resolves by name —: `TERM`, then `KILL` after 2 s; if the session list can't be read, or a targeted session survives, the hook exits non-zero and the Hub stops the app, §13.16) when their account goes, when their `.nt` changed (it keeps each hash's sha256 on tmpfs, never printed), and when the set of shares served to them shrank or a share's access went from write to read (the served state records `user`, `share`, the slot (`1`–`8`, or `Home`) and `rw|ro`, so a share name moved to another slot, another folder behind the same name, also ends the sessions; Samba checks `write list` only at connect).
- It prints one hook report (§13.8): former accounts, wrong owners, refused share and user names, unwritable owners, and each per-person folder with its size. **Sizes are measured off the hook's path:** a detached background job runs `du -sk` as each folder's owner (at most 20 s per folder, 30 s per job) and caches the results (their age goes to the hook's log only — the report has no field for it; the Hub's receive time stands in); it starts after boot and after every hook run but a `credential_change` one, one job at a time; the hook exits after the converge without waiting for it, so the Hub's delivery lock is never held while `du` runs and a revocation never waits behind it. Every hook run reports the cached sizes (`bytes: null` for a folder not measured yet). The report line stays below **60 KiB**: entries that wouldn't fit are dropped before the cap (folders first, then findings from the lowest severity) and the hook prints one plain line `report truncated: <n> entries dropped` outside the report (the report format has no field for it); a line over the cap is never printed.

**Per-person trees** (Time Machine `storage`, Samba `homes`): `path` options with `runs_as: {uid_from: uid, gid_from: uid}` and `joins_group: template` (§13.15). Each top-level `<username>` directory must be `<uid>:<uid>`, mode `0700`. Before serving one the script checks its owner: another uid (a deleted account whose name was created again) is **not** served and is reported `former_account`; the right uid with another gid or mode is `wrong_owner` (the doctor offers the one-click `person_tree_owner`, §14.6). Former members' folders stay on disk.

**Samba.**

- **Eight fixed share slots** `share<n>_*`, n = 1–8 (no table rows): `share<n>_folder` (`type: path`, `target.mount: /shares/<n>`, `folder: {access: write, runs_as: {uid_from: uid}, joins_group: template}`, `requires_any: [share<n>_readers, share<n>_writers]`), `share<n>_name` (`string`, the share name pattern), `share<n>_readers` and `share<n>_writers` (`groups`, instance scope, delivered to the people file with `expand_members`, §13.5). A slot's folder is assigned like any shared folder (§14.3).
- A slot is served only when `/shares/<n>` is a mount point (an assigned shared folder; `/shares` itself is a small tmpfs), so a slot without a folder serves nothing.
- A slot's share: `valid users` = readers ∪ writers (population members only), `write list` = writers, `read only = yes`, `force group` = the folder gid (from `${PORTCULLIS_FOLDER_GID_SHARE<n>_FOLDER}` in compose `environment:`, §13.15), `create mask = 0660`, `directory mask = 2770`: files land as `<person uid>:<folder gid>`. Other people of the instance can't open it; to share with everyone who has access, pick `users_<id>` as a reader group. A slot without a folder, a name or a served user is not rendered.
- Share names are refused, case-insensitively, when they are `global`, `homes`, `printers`, `print$`, `ipc$` or `home`, or a duplicate of another slot's: such a share isn't served and is reported `name_refused` (doctor Info). A username the script refuses is reported `name_refused` with the username as subject.
- `[Home]`: `path = /homes/%u`, `valid users` = the explicit list of people served (never empty, never `%U`).
- No `ACCOUNT_*` env (it would put hashes in `docker inspect`); with no `ACCOUNT_*` the image creates no account or share, and never re-adds defaults on restart.

**Time Machine.**

- **mbentley's entrypoint never runs.** The start command is `portcullis-sync --boot`, then `exec s6-svscan` over a copy of `/etc/s6` without `avahi`, `dbus` and `nmbd`. There are no throwaway passwords and no `EXTERNAL_CONF`; the image's default `timemachine` account is never created, with nobody eligible or with people (CI asserts both).
- One share per person with a password: `<share_prefix>-<username>`, with `fruit:time machine max size` = their resolved limit (cooperative: Time Machine prunes to fit; not a hard quota).

**Bonjour (both).** Off by default: people connect with the `smb://` address on My apps. Opt-in: a `path` option mounts the host's Avahi services directory at `/portcullis/avahi`, and a `bool` option `advertise` (`applies: live`) controls the file `portcullis-<instance>.service` there: `_smb._tcp` on the published port (Time Machine also `_adisk._tcp` and `_device-info._tcp`). With `advertise` false (while the directory is mounted) the script removes the file; it also removes it when the container stops, first thing on a stop (both templates set `stop_grace_period: 30s`, so the stop finishes inside Docker's grace). The option's help says that advertising shows every share name, usernames included, to the local network, and to turn advertising off before clearing the directory.

## 14. Shared folders and the doctor

The admin defines a **shared folder** once (name, host path) and assigns the app instances that use it. The Hub keeps its ownership consistent: one group per folder, setgid directories, default ACLs, so the apps' uids and umasks don't matter. It does so only through the folder fixer helper (§6), never a host shell or SSH. The **doctor** checks the whole setup, folders set up by hand included, reports findings by severity, and offers previewed, audited one-click fixes where they are safe; risky ones it only explains.

Everything here is **admin-only, on the Hub listener, audited** (§14.8), and needs Users & Groups (like settings, §13.12: `503` without it). Nothing on disk changes without a preview the admin applied: the doctor never fixes anything by itself.

### 14.1 Folder definitions and groups

- **Fields:** `id` (`^[a-z][a-z0-9-]{0,30}$`, immutable), `name` (≤ 64 characters, one line), `description` (≤ 500), `path`. No control characters anywhere.
- **Path rules** (checked on create and on every path change; the stored path is the cleaned one):
    - absolute and `path.Clean`ed before any comparison (`/srv/photos/` and `/srv//photos` are `/srv/photos`); no `..`, `:`, `$` or control characters, no invisible or lookalike characters (Unicode format characters such as U+200B / U+200E / U+FEFF, spaces other than ASCII's), no component that starts or ends with a space;
    - strictly under one of the Hub's bind roots (`HUB_OVERRIDE_BIND_ROOTS`, §3), never a bind root itself;
    - not a system path or a sensitive path (the custom override's lists: `/proc`, `/sys`, `/dev`, `/etc`, `/var/lib`, Docker's and containerd's storage and sockets, …), not at, above or under the core checkout (`PROJECT_HOST_DIR`), not at, above or under the data files' host directory (`HUB_APPFILES_HOST_DIR`, §13.7), not at, above or under Docker's data root as the daemon reports it (`DockerRootDir`, wherever it was moved; unreadable: `503`);
    - no symlink in any component below the bind root (the probe, §14.2); the bind root itself is operator configuration and trusted;
    - no overlap with another shared folder (neither at nor under the other), and not the same directory as another folder: a probed root device and inode equal to a stored folder's is `409` (one tree reached through a host bind mount or another spelling);
    - the overlap and the core checkout / data files rules also compare the paths NFC-normalised and case-folded, so `/srv/Photos` and `/srv/photos` collide (fail closed, for case-insensitive or normalising filesystems: ZFS `casesensitivity=insensitive`, ext4 casefold); being under a bind root is judged on the path as given;
    - **Residual:** a folder *nested* in another through a host bind mount (`/mnt/b` bound from `/srv/photos/sub`) has its own device and inode and a path that doesn't overlap, so the Hub can't see it: two gids would then apply to one subtree. Don't define folders across bind mounts of each other;
    - not on `nfs`, `cifs` / `smb2`, `fuse` (virtiofs included), `overlay`, `tmpfs`, `9p` (WSL's `/mnt/c`, VM shares), `ceph`, `ramfs` or `ecryptfs` (by `statfs` magic): the Hub can't keep ownership consistent where a server, a VM host, a userspace or stacked driver decides it, or in memory. The fixer itself writes only on ext4, xfs, btrfs and zfs (§14.2): a folder on another local filesystem (vfat, exfat, NTFS) can be scanned, never applied.
- **Check path** (`POST /api/folders/check`): a probe (optionally creating the path, §6) and a scan capped at 30 s. Answer: `exists`, `created`, `fs_type`, ACL and xattr support, files, dirs, `partial`, the top owners, `problems` in plain words and a summary such as "exists · ext4 · ACLs and xattrs supported · 12,410 files · owners 1000:1000 (all)".
- **Create** runs the probe and the check outside the Hub's lock, then saves under it, re-checking the overlap, the same directory and the gid (a lost race is `409`). A lost race after `create` made the path leaves that empty directory in place (owned by the bind root's owner, no folder defined); the probe never creates inside or above another folder. A state save that fails is `500` with nothing defined. It stores the folder root's device and inode (from the probe) and its mount root (from the check's run on `/folder`); a path change stores all three again the same way. Every later run on the folder must find exactly them (§6, §14.2).
- **Group (gid)** per folder, a number only: no `/etc/group`, no LLDAP group, no group created in containers. The display name is the folder's name ("gid 60001 is allocated for this folder (shown as *Family photos*)").
    - **Allocated** from **60000–60999**, lowest free first, in the same locked save as the definition; stable and **never reused**: `state.yaml` `folder_gids` keeps every gid ever allocated, so deleting a folder doesn't free its gid. All used: `409` "no free folder group".
    - **Adopted** (an existing host group, typed by number; the Hub never looks up host group names): ≥ 1000, not 65534, outside 60000–60999, not 10001 (the Hub, which reads the data files) or 10002 (enroll's secrets), not used by another folder. The answer carries the warning "anything mounted with gid <N> becomes reachable by this folder's apps".
- **State** (`state.yaml`): `folders` (id → name, path, description, gid, adopted, created_at, the root's device, inode and mount root, the per-use write confirmations, `last_apply` `{at, files, owner_uid, snapshot}`, cleared by an undo) and `folder_gids`. A corrupt entry stops the Hub at start, like any corrupt `state.yaml`.
- **Uses are derived** from the setting values (`folder:<id>[/<subpath>]`), never stored separately: "assigned but not applied" is never a stored state (§14.3).
- **Update:** name and description at any time; a path change while any instance uses the folder is `409`. **Delete:** `409` while any instance's value names it (listing them); it never touches files and its gid stays used. Deleting an instance drops its uses (its values go with it) and its write confirmations; the folder stays.
- **Re-check identity** (`POST /api/folders/{id}/recheck/preview` / `.../recheck/apply {plan_hash, confirm_different_directory}`): after a reboot on btrfs or LVM, the folder's device number or mount root may change while the folder path stays the same; messages caused by a device-number or mount-root mismatch then say "the folder's identity changed (e.g. after a reboot on btrfs/LVM): re-check it in Shared folders" instead of "re-apply". An inode mismatch, or the device number and the mount root changing together (a filesystem or subvolume root keeps its inode: 2 on ext4, 256 on every btrfs subvolume), is not a reboot: the folder's root is another directory, and those messages say "the folder's root is a different directory now; if you didn't move it, someone may have swapped it" (no pointer to re-check). The preview probes and scans the folder, showing old → new device/inode/mount root (`different_directory` true in those cases); apply re-stores them (audited `folder.update recheck`) after a confirmation. The folder is still usable (restart needed for the new identity to reach containers). A change of only the device number (a btrfs/LVM reboot) or only the mount root keeps `last_apply` (same tree; Undo last fix still checks its snapshot against the root it recorded). A different directory needs a second confirmation (`confirm_different_directory: true`, otherwise `400`) and forgets `last_apply`: its snapshot is of the old directory, so Undo last fix is no longer offered.

### 14.2 On disk

**Consistent ownership** (what an apply produces and the doctor's disk check expects):

- the group owner of every entry is the folder gid;
- directories get `g+rwx` and setgid; regular files `g+rw` when any use writes, `g+r` when every use only reads (`g+x` only where the file's user bits have `x`), and never less than the "others" bits (a folder-group member no longer falls through to "others");
- every directory gets an access ACL entry for the owning group (`rwx`) and a mask of `rwx`, and a **default ACL** of exactly the creator (`USER_OBJ`), the owning group `rwx`, mask `rwx` and `other::---`, so files created later land in the folder's group with group write whatever the app's umask, and open to nobody else. A directory that already had a default ACL keeps its own entries (named ones narrowed to its mask) and its "others"; the default ACL never gets an entry for a previous group or owner (they keep their access to what exists, not to files made later);
- groups that had permissions keep them through named group entries with the same bits in the access ACL; under `must_own` the previous owner uids keep theirs through named user entries the same way ("group 1000 keeps rw through an ACL on 12,410 files"), and the new owner keeps whatever it could already do (its user bits gain what it reached through a named entry, a group entry or "others", plus the folder group's bits);
- before the mask is raised, every existing named entry is narrowed to what it grants today (entry ∧ old mask): nobody's effective rights change, and the preview counts them ("4 existing ACL entries are narrowed to what they grant today");
- file owners are left alone except under `must_own`; "others" bits are never changed; nothing is ever removed;
- regular files with setuid or setgid are never changed at all (no other group, owner, mode or ACL: a new group, owner or a group `x` on such a file would let the folder's group or the app act as its owner or group): they are skipped and counted (`setid`, an explain-only finding);
- regular files with file capabilities (a `security.capability` xattr) are never changed at all either: any `chown`, a new group included, makes the kernel drop that xattr, and nothing may be removed. They are skipped and counted (`skipped.filecaps`, explain-only); a restore leaves a file that has file capabilities now alone ("changed since the fix");
- conformance (the doctor's check and the apply's verify) compares effective rights: the same entries, mask, user and "others" bits, and every group-class entry once masked — a file an app creates under the default ACL conforms as it is;
- Order per entry: `fchown` → set the access ACL → `fchmod` (user and other bits as before, group bits = the mask, setgid on directories) → set the default ACL (directories). ACLs are the `system.posix_acl_access` / `system.posix_acl_default` xattrs, the same bytes in snapshots (§14.4). **Layout**, little-endian: a header `u32 version` = `2`, then 8-byte entries `{u16 tag, u16 perm, u32 id}`, sorted by tag, then id. Tags `USER_OBJ` `0x01`, `USER` `0x02`, `GROUP_OBJ` `0x04`, `GROUP` `0x08`, `MASK` `0x10`, `OTHER` `0x20`; perm bits `r` 4, `w` 2, `x` 1; `id` is the uid / gid for `USER` / `GROUP` and `0xFFFFFFFF` for the other tags (decoding accepts any id there). Another version, an unknown tag or a truncated buffer is refused. Every ACL is validated like the kernel's `posix_acl_valid` before it is written (exactly one `USER_OBJ`, `GROUP_OBJ` and `OTHER`, a `MASK` whenever there are named entries, sorted, no duplicate ids); an invalid one is a refusal with nothing written.
- **Without ACL support** the fix is group + setgid + mode only. A change that would cut a previous group's or owner's bits is explain-only; under `must_own` the owner change is dropped with the warning "uid <N> would lose access: ownership stays; the group part still applies".

**Walk rules** (every mode):

- the walk never leaves the root's device: a directory on another device is not entered, not changed, and reported;
- each entry is first `fstatat(…, AT_SYMLINK_NOFOLLOW)`; only regular files and directories are opened (`openat` relative to the parent's fd, `O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC`, `O_DIRECTORY` for directories), and the opened fd's device, inode and type must equal the `fstatat` result (a race is skipped and counted); every change goes through that fd;
- regular files are opened `O_PATH` first and re-opened through `/proc/self/fd` only once `fstat` on that fd says they are regular, so a device or FIFO swapped in after the `fstatat` is never opened (the helper needs `/proc`);
- symlinks are never followed and never changed; regular files with more than one link are skipped and reported (their inode may be reachable outside the folder; the link count is checked again after each change, and a link made meanwhile puts the entry back as it was and fails the run); devices, sockets and FIFOs are skipped and reported, never opened;
- another mount is recognised by its device, its mount id (`statx`) or its `/proc/self/mountinfo` line (a bind mount of the same filesystem has the root's device);
- before an entry is changed, the walk checks that it is still in the folder: a directory's `..` is the directory it was found in, a file is still under its name there, and every open directory above it still has its recorded `..`. A subtree moved out while the walk is in it is left alone and counted (`races`). **Residual:** a move between that check and the change itself (one entry), or of a directory above the open ones' chain check between two entries, can still reach an entry that just left; only a process with a wider view of the same filesystem than the fixer's bind mount (a host process, another container with a broader bind) can move anything out at all — inside the folder's own mount namespace a rename out of the mount fails;
- an entry the walk can't read for lack of permission (`EACCES` / `EPERM` opening it, or reading its state) is counted `failed`, never as a race; a `scan` with failed entries exits `1` (failed) with its report, and an `apply` refuses (exit `2`, nothing changed);
- entries the fix would change but a snapshot can't record are skipped and reported, never changed: a path over 4096 bytes (`skipped.path_too_long`) or a snapshot line over 64 KiB (`skipped.acl_too_large`, huge ACLs);
- at most 1,000,000 names per directory and 512 levels are walked (beyond: the run is partial, `partial_reason` `names` / `depth`, and an apply refuses);
- `apply` and `restore` write only on ext4, xfs, btrfs and zfs (another filesystem, including vfat, exfat and NTFS: exit `2`, nothing changed), never under a user namespace with translated ids, and take no entry or time cap (`--max-entries` / `--max-time` are for `scan` only): a plan once accepted is applied whole;
- an apply re-plans and refuses (exit `2`, nothing changed) unless the plan changes exactly `--expect` entries **and** its digest (sha256 over each entry to change: path, inode, uid, gid, mode and both ACL xattrs, in walk order — the scan's and snapshot's `plan.digest`) is `--expect-digest`. The planning walk records each entry to change by path, inode and current state, and the change walk changes only an entry that matches a recorded one exactly (each at most once); an entry altered or added between the two walks is left alone and counted (`races`): the entries changed are exactly the snapshot's lines (directories `--mkdir` creates are added to that set). Once anything was created (`--mkdir`, `probe --create`) a later error exits `1`, never `2`;
- on a defined folder the root must be the stored device and inode and its mount root exactly the stored one (§6; `apply` and `restore` require `--expect-mount-root`), or the run exits `2` with nothing changed.

**The probe** (`probe`, the bind root mounted at `/broot`) answers the path's device, inode, the first symlink component (if any), whether it exists (and was created, with `--create`) and its mount root. **Before every `up`** of an instance with a folder value that has a subpath, a read-only probe checks that the subpath has no symlink component and that the folder root's device and inode equal the stored ones; otherwise the `up` fails with `409` "shared folder <name> changed on disk: re-apply it". (A writer app could replace a subpath with a symlink, and Docker resolves bind sources on the host.) **Right after the containers start** the probe runs again (no symlink component, the same root device and inode, the same subpath device and inode as the first probe); a mismatch takes the project down at once (`compose down`, volumes kept), fails the `up` with the same `409`, and the doctor shows a Problem `folder_changed` naming the folder, subpath and instance, explain-only. **Residual:** this narrows the window, it doesn't close it. Another instance that writes the folder keeps running while this one starts, so it can swap the subpath for a symlink between the first probe and Docker resolving the bind source, and swap it back before the second probe; the container would then hold the symlink's target. The window is the time between the first probe and the container start.

### 14.3 Assignment and apply

- **The definition** (name, id, path, description) is a plain synchronous save: it allocates the gid and changes nothing on disk or in any app.
- **Assigning** is one previewed, asynchronous operation, like a doctor fix. The request is the **full desired set** of uses of the folder: `{"uses": [{"instance", "key", "subpath", "write"}]}` (`write` only for options without a `folder` block: the admin's write confirmation).
- **Preview** (`POST /api/folders/{id}/assign/preview`) changes nothing (a probe and a scan capped at 30 s run). It answers the plan: per use `add` / `remove` / `keep` with its access, read-only flag, `joins_group` and env; the disk plan (files `rw`/`r`, owner under `must_own`, subpaths to create, counts per change: group, setgid, default ACL, owner, narrowed entries, previous groups and owners kept); the instances restarted; the downtime; the preview text (e.g. "gid 60001 is allocated for this folder (shown as *Family photos*). 12,410 files and 312 folders change group 1000 → 60001; group 1000 keeps read/write through an ACL. … Immich mounts it read-only. Samba and Immich are stopped for about 1 minute, then started. A permissions snapshot is saved first."), warnings and the **plan hash**. Only removals: no disk plan, no fixer run.
- **Refusals** (`400` for an unknown instance or key or a non-`path` option; otherwise `409`): two options of one service whose `uid_env` / `gid_env` would get different values ("point both settings at the same shared folder", no `group_add` fallback: PUID images drop supplementary groups); two `must_own` uses; an option that already uses another folder ("unassign it from <name> first"); a change that would remove someone's access on a filesystem without ACLs (explain-only); a rendering or custom-override problem (below).
- **Plan hash:** sha256 of the canonical JSON of the plan's decisions (folder id, path, gid, every use without its label, the disk plan without its counts, the restarts) plus the current values of every affected option and port. Apply (`POST /api/folders/{id}/assign/apply` `{plan_hash, uses}`) recomputes the plan: any difference is `409` "the setup changed since the preview", before the operation is accepted. Then `202` (§14.8).
- **Locks:** the folder's lock (try-lock; busy `409`) → the per-instance lock of **every** affected instance in sorted id order, all or none (the first busy one releases those taken; `409`) → the delivery lock, only inside each instance's `up`. The folder lock is never taken while holding an instance or delivery lock. The Hub's state lock is never held across a Docker call.
- **While it runs** the affected instances are marked "applying": settings saves and previews, Expert env and custom override saves, hostname changes, backups and drift start/apply on them answer `409` "shared folder <name> is being applied"; enable, disable, restart, restore and delete get `409` busy from their lock. The settings delivery engine sees them busy and re-queues.
- **Sequence:**
    1. Render every affected instance's override and env from the **planned** values (a dry run on a copy) and check its custom override. Any refusal is `409` and nothing stops.
    2. Write the marker `<data>/folders/<id>.applying.json` `{instances, snapshot, phase: "disk"}`.
    3. Stop (`compose down`, volumes kept) the affected instances that were running when the operation started. Enabled-but-stopped ones are regenerated but not started (the result says so).
    4. With a disk plan: free-space check on `<data>` (`507`), `snapshot` run (§14.4), `apply --expect <N> --mkdir <subpath>…` (the fixer re-plans and refuses, unchanged, when its count differs), then a verify `scan`: every conformance count must be 0.
    5. Phase `state`: under the Hub's lock set the values to `folder:<id>[/<subpath>]` (removed uses: the value is deleted, back to the default), the write confirmations and `last_apply`; save `state.yaml`.
    6. Regenerate env and override, start the stopped instances (`compose up`, which also clears an owed restart), remove the marker.
    7. Queue a settings delivery (trigger save, effect none: the apply restarted the apps itself, so nothing is owed) for every instance whose values changed, store the verify scan as the folder's doctor scan, and audit: `settings.change` for every changed key (actor the admin), `folder.assign`, and `folder.apply` when the disk changed.
- **Failure** before the state save: the stopped instances are started again with their old configuration, the values are unchanged, and the op record names the snapshot (the doctor then shows the drift with an undo). After it: the op fails with the new state kept.
- **Interrupted** (the Hub stopped mid-apply): at the next start, after restores are recovered and before owed restarts are re-queued, in the background: phase `disk` → the listed instances are started with their unchanged configuration; phase `state` → regenerated and started with the new one; the op record is marked interrupted and names the snapshot. The fixer itself was removed by the start-up sweep (§11.5).
- **Downtime** is estimated from the scan's entry count (5,000 entries a second for each of the three runs: "under a minute", "about N minutes"). An apply that holds an instance lock beyond 20 minutes makes restarts queued for it give up; they stay owed and run at the next Hub start.
- Op key `_folder.<id>` (instance ids can't start with `_` or contain `.`), polled at `GET /api/folders/{id}/op`. Folder and doctor op records are never listed as failed apps.

### 14.4 Snapshots and undo

- **The backup before a permissions fix is a permissions snapshot:** path, inode, type, uid, gid, mode and both ACL xattrs of every entry the fix will change. A data copy of a multi-terabyte folder isn't practical, and the contents don't change.
- **Format:** gzip NDJSON. A header `{"version":1,"kind":"apply|undo","rules":R,"root_dev":D,"root_ino":I,"gid":N,"files":"rw|r","owner_uid":U|null,"created_at":"…","entries":N}` (`gid`, `files` and `owner_uid` are the apply's target: the folder gid, files `rw` or `r`, the `must_own` uid or `null`; `rules` is the version of the §14.2 rules the fixer applies, currently `1`: a restore recomputes what the apply produced, so it refuses a snapshot of other rules), then one `{"p":"<relative path>","t":"d|f","ino":I,"u":U,"g":G,"m":MODE,"a":"<base64 access xattr>","d":"<base64 default xattr>"}` per entry, plus `"pb":"<base64 of the path's bytes>"` when the name isn't valid UTF-8 (`p` then holds it with U+FFFD in place of the bad bytes, for reading only; `pb` is refused on a UTF-8 name). Lines are at most 64 KiB; the fixer checks every line as a restore will read it before writing it, so a snapshot it wrote always reads back.
- **Transfer:** the fixer writes `/out/snapshot.ndjson.gz`; the Hub accepts exactly one regular tar entry `out/snapshot.ndjson.gz` from the archive endpoint, at most 2 GiB and within the free space left after the 64 MiB margin (§11.5; checked first), and computes the sha256 itself while streaming.
- **Storage:** `<data>/folder-snapshots/<folder>/<YYYYMMDDTHHMMSSZ>.ndjson.gz` plus `<same>.sha256`, data then checksum, each atomic; files `0600`, directories `0700`; the last **3** per folder are kept, plus the one Undo needs. The checksum catches corruption only: write access to `<data>` is Hub compromise.
- **Undo last fix** is itself a previewed fix (`POST /api/folders/{id}/undo/preview` / `…/undo/apply {plan_hash}`) built from `last_apply.snapshot` (an apply snapshot); without one — no apply yet, or the last operation was an undo — it is `404`. The preview names the snapshot time and entry count, the uses that lose group access, and the entries "changed since the fix". Its counts come from **`restore --dry-run`**: the fixer reads the apply snapshot, walks to each entry like a restore and counts what a restore would rewrite (`to_restore`) and what changed since the fix (`changed_since`), writing nothing (the folder mounted read-only, `DAC_READ_SEARCH` only). It runs the apply's sequence: stop → an **undo snapshot** (header `kind: "undo"`: every entry the restore will rewrite, in its current state) → `restore` (the apply snapshot copied in at `/in`) → verify → start. **An undo can't be undone:** it clears `last_apply`; its undo snapshot is kept only as a safety copy (with the others, last 3) and is never offered for an undo. Verify after an undo: a second `restore --dry-run` finds 0 entries still to rewrite (otherwise the undo fails, `last_apply` is kept and Undo can run again: a restore rewrites only entries still as the apply left them). The setting values don't change. Audited `folder.apply` (`undo snapshot=<ts>`).
- **Restore** validates the header (`rules` the fixer's, `root_dev`, `root_ino` and `gid` equal the folder's) and every path (`pb`'s bytes when present, else `p`: clean, relative, no `..`, ≤ 4096 bytes), walks to each entry with `openat` per component (`O_NOFOLLOW`, never a joined path string), and rewrites an entry only while its type and inode are the recorded ones **and** its uid, gid, mode and ACLs are still exactly what the apply produced from that line, recomputed from the header's `gid`, `files` and `owner_uid` plus the line (the rules of §14.2). Anything else is skipped and counted "changed since the fix", so an undo never takes away access granted since.

### 14.5 The doctor

- **Severities:** `problem` (broken or unsafe now: a writer can't write, a LAN-only port on a public address), `warning` (likely to break or weaker than intended: drift, a LAN-only port on all interfaces, no ACL support), `info` (worth knowing: a per-person option with no group values, a template that doesn't say how it writes).
- **Findings** say what is wrong, why it matters, which instances, folders and paths are affected, and what the fix would do: `{fp, kind, severity, title, why, fix_text, instances, folders, paths, fix_class, fix_kind, more_fix_kinds, steps, link, partial, muted}` (`more_fix_kinds`: further one-click fixes the finding offers, e.g. `undo_folder` on `folder_owner`; `link` is `{instance, option, tab}` — **NEW**, AI support: `tab` opens a tab of the instance, today only `"ai"`, instead of a settings option). They are sorted by severity, then title, then `fp`; the report also has `counts` (unmuted Problems, Warnings, Infos), `muted` and the disk scans `{target, at, partial, entries}`. Only **enabled** instances are judged.
- **Fingerprint** `fp` = the first 16 hex digits of sha256(`<kind>\x00<subjects, sorted, joined by \x00>`): stable across runs and order.
- **Mutes:** an admin mutes a finding with a reason (non-empty, ≤ 200 characters). The mute stores the finding's inputs digest; the finding comes back as soon as its inputs change. Muted findings stay in the answer with `muted`, outside `counts`. Mutes and unmutes are audited. Unknown `fp` → `404`.
- **Config checks** (state, manifests, overrides, ports, settings values, the directory's group membership) are cheap: they run on every `GET /api/doctor` and after every relevant save or restore. **Disk checks** (fixer `scan`) run on demand (`POST /api/doctor/scan`), after every folder apply, and daily; results are cached with their time in `<data>/doctor/scans.json` (`0600`) and survive a Hub restart. One scan at a time (`409` busy). Scheduled scans skip a folder whose lock is held and keep its previous result.
- **Scan targets:** every shared folder, and every distinct hand-typed host path used by two or more uses or by a writer, under the bind roots, nested ones collapsed to the outermost (its principals are the outermost path's own uses: **residual**, a writer of a nested hand-typed path isn't judged on its own; make the path a shared folder to have it checked). A hand-typed target passes the folder path rules and a probe before it is bound (otherwise a `scan_failed` Warning naming why). **Caps:** 2,000,000 entries or 10 minutes per scan (30 s in previews and Check path). A scan that hits a cap is **partial**: its findings carry `partial` and the text "(partial scan: stopped after <N> entries)". A failed target is a `scan_failed` Warning; the others continue.
- **Kinds** (severity, fix class §14.6):
    - `shared_path`: two or more uses of the same or nested hand-typed host paths (settings and custom-override mounts). The same exact path, all under the bind roots, no custom-override mount → Warning, `manage_as_folder`; nested or overlapping → Warning, explain-only; with a disk scan, a writer that can't write or a reader that can't read → Problem with the counts ("Jellyfin and Samba both use `/srv/media`. Samba writes as uid 10001 (group 10001); Jellyfin reads as uid 1000 and can't read 412 new files.").
    - `folder_owner`: a folder's disk differs from consistent ownership → Warning "drifted since the last apply", `reapply_folder` (and the undo, while `last_apply` holds an apply snapshot); a writer that can't write or a reader that can't read → Problem.
    - `path_outside_roots`: a `path` value outside the bind roots → Warning, explain-only.
    - `undeclared_template`: a folder use without a `folder` block → Info "this template doesn't say how it writes".
    - `primary_gid_conflict`: hand-typed paths on one service whose `gid_env` would need different gids → Problem, explain-only.
    - `custom_override_mount`: a custom-override bind mount that shares or nests with another use → Warning, explain-only with the steps.
    - `must_own_conflict`: two `must_own` uses of one path or folder → Problem, explain-only.
    - `gid_collision`: an instance whose resolved primary or supplementary gid (compose `user:` included) is a folder gid it isn't assigned → Problem, explain-only.
    - `exclusive`, `filesystem`, `free_space` (template checks, §13.15).
    - `person_option`: a per-person option with no group rows → Info (Warning with `requires_group_value`, showing its reason; "No rows" counts only rows bound to an existing group id); a row whose group has nobody in the instance's population → Warning naming the group; a row whose group id no longer exists → Warning. All link to the option in the settings panel.
    - `no_acl`: a folder or scanned path without ACL support → Warning. `skipped_entries`: hard links, nested mount points, specials, setid files, files with file capabilities (`filecaps`), paths over 4096 bytes and entries with ACLs too large to snapshot → Warning, explain-only, with counts and samples.
    - `folder_changed`: the post-start probe found a folder's subpath or root changed (§14.2) → Problem, explain-only.
    - `folder_reachable_above`: a target service (or any service the folder gid reaches) has another mount (setting, custom override) at or above the folder's path → Problem, explain-only with the mounts. The assignment preview refuses this setup with `409` before any run.
    - `lan_only_exposed`, `host_network` (§14.7). `scan_failed`.
- **File sharing (NEW)** registers more kinds through the same check interface (§13.16–13.17):
    - `credential_without_access`: an active credential whose holder the holder check would revoke (a canary for a failed revocation; it should never fire) → Problem, one-click `revoke_leaver`;
    - `former_account_folder`: a per-person tree's top-level directory owned by another uid than the person's ("alice's Time Machine folder belongs to a former account (uid 20023)"), from the tree scan or the hook report (same fingerprint) → Warning, explain-only (moving or deleting it is the admin's call);
    - `person_tree_owner`: the person's uid but another gid or a mode other than `0700` → Warning, one-click `person_tree_owner`; anything else at a tree's top level → Info; files inside a person's tree aren't checked;
    - `local_networks_empty`: Local networks saved empty while an enabled instance references `PORTCULLIS_LOCAL_NETWORKS` → Problem, linking to Settings → Local networks ("Local networks is empty; file sharing is off");
    - `unverifiable_account`: an active credential whose holder LLDAP lists with an empty uuid → Problem "can't verify <user>'s account", explain-only;
    - `served_to_nobody` (Warning): a `person_secret` instance's folder option with `requires_any` set but none of those options holding a group ("<label> of <app> is served to nobody");
    - the hook report's `name_refused` (a share name, or a username the template's script won't serve) and `owner_unwritable` findings (kinds named after the codes), with the report's severity and text (the templates send `name_refused` as `info`); its `former_account` and `wrong_owner` findings feed the two tree kinds above.

    Per-person trees (`gid_from` options with a value) are scan targets with their top-level children read (owner, group, mode); they are never `shared_path` or `folder_owner` subjects.
- **AI support (NEW)** registers more kinds through the same check interface (§15), each linking to the instance's AI tab (`link {instance, tab: "ai"}`):
    - `ai_companion_unhealthy` (Problem): a companion with AI support on whose service isn't running or is unhealthy;
    - `ai_policy_needs_mtls` (Problem): AI support on for an instance whose effective policy now reaches LoA 3 (a canary: a policy save switches AI off first, §15.11);
    - `ai_credentials_revoking` (Warning): AI credential entries stuck in `revoking` (the revoke hook keeps failing, or the template dropped the companion or its hook), naming the instance and the count; also the `app_oauth` problems of §15.5 (an owed `revoke_all`, records without a uuid or whose id lookup failed 3 passes, a failed record write, unmatched leavers — each with a `dismiss` item —, records nothing can revoke), and an `mcp-credentials.json` the Hub can't read (owed revocations are on hold until it is fixed or removed; deleting an instance or dropping a companion's entries then fails instead of reporting success). A lost hook and the `app_oauth` leftovers are explain-only with by-hand steps;
    - `ai_companion_image_old` (Warning): a running companion whose image digest isn't the template's pinned one (only `kind: companion` services: a `builtin` service is the app's own image).

    The Hub's inputs per companion with AI on (master on, instance enabled and not busy, switched on, not owing a `revoke_all`): the container status, the effective policy and LoA, the pinned and running digests, the instance and companion labels, and the revocation state (`Revoking`, `Pruned`, `NoHook`, `Recorded`, the reason).


### 14.6 Fix classes

- **One-click** (preview → plan hash → Apply, `202`; `409` "the setup changed since the preview" on a mismatch; audited `doctor.fix` besides what the steps audit). **NEW (AI support):** the preview's `FixPlan` carries `touches_data`, true for the fixes that change data on disk or revoke access (the folder assignment and undo, `person_tree_owner`, `revoke_leaver`); the Portcullis MCP's `doctor_apply_fix` is class D (a confirmation, §15.6) exactly when it is set:
    - `manage_as_folder` (params `name`, `id`; default the path's base name, slugged): the folder definition lines plus the assignment plan for the finding's uses. The apply predicts the gid, holds the new id's folder lock across creating the definition and validating the assignment, and on a refusal or hash mismatch deletes the just-created definition (its gid stays used) and answers `409`.
    - `reapply_folder`: the assignment of the folder's current uses (§14.3).
    - `rebind_port` (param `address`): bind a LAN-only port to an address the admin types — a valid IP, not `0.0.0.0` / `::`, inside the local networks, not a main-domain address (`400` otherwise). Preview: "SAMBA_SMB bind 0.0.0.0 → 192.168.1.10, Samba restarts". Apply under the instance's lock (op `rebind`, the instance's op record): checked like a port save, `<KEY>_BIND` written to state, override and env, restarted at once if enabled; if the restart fails the old bind is put back and the instance started again (`rolled_back`, with the reason). Audited `settings.change` (`ports`) and `doctor.fix`.
    - `revoke_leaver` (**NEW**, file sharing): preview "revoke <user>'s file-share password for <app>"; apply = the admin revoke (§13.16, `reason: admin`, actor the admin).
    - `person_tree_owner` (**NEW**, file sharing): preview exactly one line, "chown <uid>:<uid> + chmod 0700 <tree>/<user> (not recursive)", only for a folder the person's uid already owns (another owner is `former_account_folder`, explain-only: 409 at preview), with the plan hash over the child's owner, device, inode and mount root; apply = the fixer's `childfix` mode (§6) on that one child. Audited `doctor.fix`.
    - **Undo the last fix** (§14.4), fix kind `undo_folder`, offered by `folder_owner` in `more_fix_kinds` while the folder's `last_apply` holds an apply snapshot. The param `fix` picks one of a finding's fixes (`fix_kind` by default; another value it doesn't offer is `400`).
    - Every fix that touches data goes through the assignment or undo operation (snapshot + verify), never another path. There is no "mount read-only" fix: `access: read` always mounts read-only.
- **Explain-only** (the finding lists the steps; preview `409` "explain-only"): moving or merging data, nested or overlapping paths, custom-override mounts (remove the mount in Expert and use the template's folder setting with a shared folder, where it has one), hard links, nested mount points, setid files and files with file capabilities, `must_own` without ACLs when previous owners would lose access, two `must_own` uses, paths outside the bind roots or on unsupported filesystems, a userns-remapped or rootless Docker (§6), host networking (firewall steps).
- **Link-out:** per-person option findings open the settings panel at the option, AI findings the instance's AI tab; the doctor never edits settings values or AI switches itself.

### 14.7 Local networks and exposure

- **Local networks** (Hub Settings, `GET` / `PUT /api/settings/local-networks`): a list of CIDRs, ≤ 64 entries, no host bits, no `/0` prefix. `null` = the defaults `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`, `100.64.0.0/10` (RFC 1918, IPv6 ULA, the tailnet); `[]` = loopback only (saveable: `PORTCULLIS_LOCAL_NETWORKS` is then empty, §3.1, and LAN-only file sharing refuses to start). Every instance's `.env` carries the list as `PORTCULLIS_LOCAL_NETWORKS`; a save restarts the enabled instances whose compose references it (§3.1). Loopback (`127.0.0.0/8`, `::1`) always counts as local. Stored in `state.yaml` `local_networks`; audited `settings.local_networks` (`<N> networks`). **Residual (measured on Docker 29.9.3):** with Docker's userland proxy on (the default), every connection to a published port, even one on `127.0.0.1`, reaches the app from the bridge gateway of the instance's network, which is inside Docker's default pools and so inside the default Local networks; an app's `hosts allow` then can't tell clients apart. The boundary is who can reach the published port (bind a LAN address, host firewall); `"userland-proxy": false` lets the app see client addresses (not measured for LAN clients).
- **Only `lan_only` ports are judged** (§13.15), template ports and custom-override ports alike (matched by service and container port). Addresses are unmapped (`::ffff:192.168.1.10` is `192.168.1.10`) before every comparison; no address means all interfaces. **Ephemeral ports** (host port `0`, `-` alone in compose short form, or long syntax without `published`, or `IP::container` without a host port: Docker picks a free host port at start) are judged with their bind address (loopback counted as local); collision checks skip port 0.
- `lan_only_exposed`: bound to `0.0.0.0`, `::` or no address → **Warning**; to an address outside the local networks, or to an address the main domain's A / AAAA records point at → **Problem**. Both offer `rebind_port` for template ports; a custom-override port is explain-only (edit the override), A `lan_only` port of a `network_mode_host` service is always a **Problem**, explain-only, whatever its `<KEY>_BIND` says: compose publishes nothing for it, so the bind has no effect (steps: the app's own listen address, the host firewall); the bind isn't an input of its mute. The main domain is resolved with a 2 s timeout and cached for 5 minutes; a failed lookup escalates nothing and the finding says "couldn't resolve <domain>".
- `host_network`: a `lan_only` port of a `network_mode_host` service → **Warning**, explain-only: "Docker publishes around host firewalls such as ufw; restrict the port in your router or host firewall". The Hub can't see host firewalls or NAT and doesn't probe reachability from outside.

### 14.8 API and audit

Hub listener only (the people listener gets no new route, §5.1), `adminOnly` (no `X-Forwarded-User` `401`, delegates `403`, no Users & Groups `503`), proxy-secret and CSRF guards. Bodies are strict JSON (`DisallowUnknownFields`, trailing data refused), at most 64 KiB.

- `GET /api/folders` → `{"folders": [FolderView]}`;
- `POST /api/folders` `{id, name, path, description, gid?, create?}` → 201 `{folder, warnings}`;
- `PUT /api/folders/{id}` `{name, path, description}`;
- `DELETE /api/folders/{id}` (409 while used);
- `POST /api/folders/check` `{path, create}` → `PathCheck`;
- `POST /api/folders/{id}/assign/preview` `AssignRequest` → `AssignPlan`;
- `POST /api/folders/{id}/assign/apply` `{plan_hash, uses}` → 202 `{op_id, op, folder, poll: "/api/folders/{id}/op"}`;
- `POST /api/folders/{id}/undo/preview`, `POST /api/folders/{id}/undo/apply {plan_hash}`;
- `GET /api/folders/{id}/op` → `OpRecord`;
- `GET /api/doctor` → `doctor.Report`;
- `POST /api/doctor/scan` → 202 (`poll: "/api/doctor/op"`); `GET /api/doctor/op`;
- `POST /api/doctor/findings/{fp}/preview` `{params}` → `FixPlan`;
- `POST /api/doctor/findings/{fp}/apply` `{plan_hash, params}` → 202;
- `POST /api/doctor/findings/{fp}/mute` `{token, reason}` (the finding's opaque `token` from the report JSON; a mismatch → `409` "the finding changed since you saw it"); 
  `DELETE /api/doctor/findings/{fp}/mute`;
- `GET|PUT /api/settings/local-networks` `{networks: [..] | null}` →
  `{networks, default}`.

Every field of these answers is snake_case. `FolderView`: `id`, `name`, `path`, `description`, `gid`, `adopted`, `uses` (`instance`, `key`, `label`, `subpath`, `access`, `declared`, `read_only`), `last_op`, `last_check`. The `202` answers and op records follow §11.7 (`op_id`, `op`, `poll`; records `running`, then `ok`, `error`, `status`, `output`, `hint`, `rolled_back`, `result`, `warnings`); doctor scans use the op key `_doctor`, a rebind the instance's own record. Status meanings: `400` bad input, `404` unknown folder, finding or snapshot, `409` refused, busy or "the setup changed since the preview", `503` no Users & Groups, the Hub's own image not found, or a userns-remapped / rootless Docker, `507` too little free space.

**Audit actions** (`audit.jsonl`, §9.5; result `ok`, `refused` or `error`; written after the Hub's lock is released): `folder.create`, `folder.update`, `folder.delete`, `folder.assign`, `folder.apply`, `doctor.fix`, `doctor.mute`, `doctor.unmute`, `doctor.scan`, `settings.local_networks`, plus `settings.change` for every setting value an apply or rebind changes. The detail holds counts and ids, never file lists: `folder.create` target `<id>`, detail `gid=<N> path=<path>`; `folder.assign` `add=<n> remove=<n> entries=<n> snapshot=<ts>`; `folder.apply` the disk change (`undo snapshot=<ts>` for an undo); `doctor.fix` target `<fp>`, detail `fix=<kind> <ids>`; `doctor.mute` the reason; `doctor.scan` (an on-demand disk check, `POST /api/doctor/scan`) target `disks`, detail `targets=<n> scanned=<n> failed=<n> skipped=<n> containers=<n>`, a refusal (`401`, `503`, `409` busy) `refused`; `settings.local_networks` `<N> networks`.

## 15. AI support (MCP) — NEW (AI support)

People use their Portcullis apps from Claude or any other MCP client, and from an AI page, as themselves. A core service, **`mcp-gate`**, terminates every MCP request: it validates the Keycloak access token for exactly that resource, checks that the person is in the resource's population right now, applies tool policy, rate limits and confirmations, writes the access log, and forwards the request to the upstream with the person's identity in the form the template declared (§3.2). It never forwards the person's token. The Hub manages everything around it: Keycloak AI clients and `mcp:*` scopes (§8), the gate's files (§15.4), per-person app credentials, the companion containers (§3.2, §5), the confirmation pages, the Portcullis MCP itself (§15.10), the People card (§5.1) and Settings → AI (§15.11). No template id appears in Hub or gate code: everything app-specific is the template's `ai:` block and hooks.

**Labels.** The **instance label** is the name the portal shows for the instance (§10 `name`: the template's name, followed by ` (<instance-id>)` for other instances than the default one). The **companion label** is `ai.mcp[].label` (§3.2). Consent texts (§8) and the companion confirmation's typed check (§15.6) use the instance label: they name the app the person recognises. The resource's `label`, RFC 9728 `resource_name`, the aggregate's description prefix and the gate's messages use the companion label.

**Service, networks and secrets (core):**

- **`mcp-gate`**: a Go service in core's repo (`mcp-gate/`, the official MCP Go SDK), image built like `domains` with pinned base images, uid/gid 10005 with `group_add: ["10001"]` only, read-only root filesystem, the hardening anchor. Networks: only `portcullis-mcp` (internal; Keycloak's JWKS at `http://keycloak:8080/realms/portcullis/protocol/openid-connect/certs` and the Hub at `http://hub:8890`, both through `extra_hosts` to their pinned addresses, §2) and `portcullis-proxy` at **`PORTCULLIS_MCP_GATE_IP`** (§2). No Docker access, no LLDAP or Keycloak admin credentials.
- **Volumes:** `hub_data` mounted read-only at `/hub-data` (§4.2); its own **`mcp_gate_data`** at `/data` (the access log, §15.8), which core mounts read-only into the Hub at `/mcp-gate-data` (`HUB_MCP_GATE_DATA_DIR`). Core reserves the service name `mcp-gate`, the volume key `mcp_gate_data` and the subdomain `mcp` (§3, §4).
- **Secrets**, generated by `./portcullis init` / `up` when missing (never env vars): `secrets/mcp-gate/age.key` (an age X25519 identity, the gate only: group 10005, 0640), `secrets/mcp-gate/age.pub` (its recipient, for the Hub: group 10001, 0640, mounted at `HUB_MCP_GATE_RECIPIENT_FILE`, default `/run/portcullis/mcp-gate/age.pub`) and `secrets/mcp-gate/hub-secret` (48 random characters, shared by the gate and the Hub: group 10001, 0640, mounted at `HUB_MCP_GATE_SECRET_FILE`, default `/run/portcullis/mcp-gate/hub-secret`). The Hub encrypts to the recipient and holds no identity: it can replace or delete a credential entry, never read one back.
- **Without the gate.** A Hub without a readable recipient file writes `mcp-gate.json` with `enabled: false` and Settings → AI says "This core has no mcp-gate". Without the gate secret file the Hub doesn't start its MCP listener (§15.7) and AI support stays off; a secret file under 32 characters makes the Hub refuse to start.
- **Gate configuration** (env): `MCP_GATE_LISTEN` (`:8080`), `MCP_GATE_HUB_DATA` (`/hub-data`), `MCP_GATE_DATA` (`/data`), `MCP_GATE_AGE_KEY_FILE`, `MCP_GATE_HUB_SECRET_FILE`, `MCP_GATE_JWKS_URL`, `MCP_GATE_HUB_URL` (`http://hub:8890`).

### 15.1 Resources

Each MCP endpoint is its own OAuth protected resource, identified by its canonical URL, which is also its audience:

| Resource | URL | Scope | Population |
|---|---|---|---|
| companion | `https://<host of router><public_path>` | `mcp:<instance-id>.<companion>` | the instance's settings population (§13.3), instance enabled |
| all my apps | `https://mcp.<d>/mcp` | `mcp:all` | every LLDAP user except the service account |
| Portcullis admin | `https://hub.<d>/mcp` | `mcp:portcullis.admin` | `lldap_admin` members |
| Portcullis people | `https://people.<d>/mcp` | `mcp:portcullis.people` | every LLDAP user except the service account |

- `<d>` is the main domain; a companion's host may be an extra-domain host (§5). A companion is a resource only while its AI support is on, the master switch is on and it isn't `app_oauth` (the gate isn't in its path). The admin resource exists while "Portcullis MCP for admins" is on, the people resource while "… for people" is on (§15.11). The population of a companion is the settings population: the access group's members minus expired-not-removed entries, everyone when group access is off and no access role applies, nobody for `sign_in: native` instances (no identity).
- **Metadata (RFC 9728).** For each resource the gate serves `GET /.well-known/oauth-protected-resource<path>` on the same host (e.g. `https://gitea.example.com/.well-known/oauth-protected-resource/mcp`), no authentication, no cookie:

    ```json
    {"resource": "https://gitea.example.com/mcp",
     "authorization_servers": ["https://auth.example.com/realms/portcullis"],
     "scopes_supported": ["mcp:gitea.gitea"],
     "bearer_methods_supported": ["header"],
     "resource_name": "Gitea on Portcullis"}
    ```

    `resource_name` is `<companion label> on Portcullis` for a companion (`ai.mcp[].label`, §3.2) and `<label> on Portcullis` with the resource's fixed label (`All my apps`, `Portcullis (admin)`, `Portcullis`) for the others. The authorization server is always `https://auth.<main domain>/realms/portcullis` (Keycloak's own discovery; the `keycloak` router has no forward-auth). An unknown path is `404`.
- **Challenges.** A request without a valid token gets `401` with `WWW-Authenticate: Bearer resource_metadata="<metadata URL>", scope="<scope>"`; a valid token without the resource's scope gets `403` with `WWW-Authenticate: Bearer error="insufficient_scope", scope="<scope>", resource_metadata="<metadata URL>"`.

### 15.2 Token rules

The gate serves a request only when every rule holds:

- **Resource from the request line only.** The resource is looked up from `Host` (lowercased, a numeric `:<port>` and trailing dots stripped) and the exact path; `X-Forwarded-*` headers are never read for routing.
- `Authorization: Bearer <JWT>` only: never a token in the query, a cookie or another header.
- Signature RS256 or ES256 by a key of the realm's JWKS (never `none`, never HS*). An unknown `kid` refreshes the key set at most once per 60 s, gate-wide (every 5 s until the first fetch succeeds, so a gate started before Keycloak recovers quickly); otherwise it is a `401` with no fetch. A token whose `kid` is known re-fetches the set first once the last successful fetch is more than **10 minutes** old (through the same 60 s throttle); the fetched set replaces the old one, so a key Keycloak no longer publishes (rotated out, disabled, deleted) stops verifying within about 11 minutes, and a failed fetch keeps the old set. The key set is fetched only from the internal Keycloak URL, without redirects or proxies.
- `iss` exactly `https://auth.<main domain>/realms/portcullis` (the file's `issuer`); `exp` > now − 60 s, and `nbf` and `iat` (when present) ≤ now + 60 s; `typ` `Bearer`.
- `azp` is in **this resource's** `clients` (§15.4): the offered AI clients plus every `ai_client` client for companions and the people resource, only offered clients with their admin flag on for the admin resource (never an `ai_client`), and the offered plus the `ai_client` clients for the aggregate — through the aggregate each upstream's own `clients` decide again, so an `ai_client` reaches the companions and Portcullis's people tools, never the admin tools (§8). Never `portcullis-forward-auth`, `portcullis-fresh-auth` or an app's client; a token from a client that may not use this resource is a `401`.
- **Audience:** `aud` contains this resource's URL, and no other `http://` or `https://` value at all (a URL of another resource, of a deleted or renamed one, or any other URL is a `401`: a token minted for several resources at once works nowhere). Non-URL values (client ids such as `account`) are ignored.
- `scope` contains this resource's scope (else `403 insufficient_scope`).
- `acr`, mapped through the file's `acr_loa` (`{"public": 0, "pwd": 1, "hwk": 2, "mtls": 3}`), is at least the resource's `min_loa` (an unknown `acr` is LoA 0). `min_loa` is the instance's effective policy LoA (`policy.LoA(policy.Resolve(<effective policy>, <capability>).Policy)`) for a companion, `2` for the other three. An instance whose effective policy reaches LoA 3 can't get AI support (`409`; no MCP client can present the person's certificate) — no exception. Residual: the admin resource is always listed with `min_loa` `2`, also when the hub host is made mTLS-only (the Hub has no policy model for its own host); Traefik's TLS options then refuse every client without a certificate, so no MCP client reaches it in practice.
- `preferred_username` is ASCII and, lowercased, matches the Hub's username rule `^[a-z0-9][a-z0-9._-]{0,63}$` (the same pattern in the gate file) and is in the resource's `population` and not at or past its `expiring` time. The gate checks this on **every** request, so a person who leaves is refused from their next request, without waiting for token expiry.
- An `Origin` header, if present, is in the file's `allowed_origins` (default empty): the MCP rule against DNS rebinding.

Answers: `401` bad or missing token; `403` a valid token that isn't allowed (population, LoA, `Origin`), `403 error="insufficient_scope"` without the scope; `429` with `Retry-After` over a limit (§15.9); `503` "AI support is off on this Portcullis" while the master switch is off or `mcp-gate.json` is missing (a companion host answers `404` instead while its app restarts after a master-switch change: its MCP router is gone with the app, nothing reaches the app); `503` for every request while the file exists but doesn't decode (§4.2), or while `mcp-credentials.json` exists but doesn't decode or decrypt (§15.4). Insufficient scope and the challenges follow §15.1.

### 15.3 Protocol versions

- The gate and the Hub's MCP listener accept exactly `2025-06-18`, `2025-11-25` and `2026-07-28`, from the `MCP-Protocol-Version` header or, for `initialize`, the body's `protocolVersion`. Anything else is `400` "unsupported protocol version".
- On 2026-07-28 requests the `Mcp-Method` / `Mcp-Name` headers must match the body, else `400` with JSON-RPC error `-32020`. Decisions always use the parsed body, never the headers alone.
- Towards a companion the gate speaks the newest version in the companion's `protocol` list that it supports.

### 15.4 Hub → gate files

Both files live in `hub_data` next to the policy file (§4.2): mode 0640, group 10001, written atomically. Both are JSON, `version` 1, decoded **strictly** by the gate (unknown fields, trailing data, a missing field or a value outside its rule refuse the whole file, §4.2). The Hub writes them in Go's `encoding/json` indented form (two spaces, keys in the order shown, map keys sorted, lists sorted as stated, a trailing newline). The examples below are a complete shared test vector: the same bytes are committed in the Hub (`internal/aigate/testdata/`) and the gate (`internal/config/testdata/`), and both sides must decode them strictly and re-encode them byte for byte.

**`mcp-gate.json`** (written with every policy-file write):

```json
{
  "version": 1,
  "enabled": true,
  "issuer": "https://auth.example.com/realms/portcullis",
  "main_domain": "example.com",
  "clients": [
    "ai-chat-mcp",
    "portcullis-ai-claude",
    "portcullis-ai-claude-code",
    "portcullis-ai-generic"
  ],
  "allowed_origins": [],
  "acr_loa": {
    "hwk": 2,
    "mtls": 3,
    "public": 0,
    "pwd": 1
  },
  "limits": {
    "resource_rpm": 120,
    "resource_burst": 30,
    "person_rpm": 600,
    "tool_calls_rpm": 60,
    "confirmations_per_hour": 10,
    "mints_per_minute": 10,
    "fanout": 4,
    "max_request_bytes": 8388608,
    "max_result_bytes": 16777216,
    "upstream_timeout_s": 120
  },
  "core_hosts": [
    "auth.example.com",
    "directory.example.com",
    "enroll.example.com",
    "example.com",
    "hub.example.com",
    "mcp.example.com",
    "metrics.example.com",
    "people.example.com",
    "traefik.example.com"
  ],
  "resources": [
    {
      "url": "https://gitea.example.com/mcp",
      "scope": "mcp:gitea.gitea",
      "clients": [
        "ai-chat-mcp",
        "portcullis-ai-claude",
        "portcullis-ai-claude-code",
        "portcullis-ai-generic"
      ],
      "kind": "companion",
      "instance": "gitea",
      "companion": "gitea",
      "label": "Gitea",
      "host": "gitea.example.com",
      "hosts": [
        "gitea.example.com"
      ],
      "app_url": "https://gitea.example.com",
      "min_loa": 2,
      "upstream": "http://portcullis-mcp-gitea--gitea:8080/mcp",
      "protocol": [
        "2026-07-28",
        "2025-11-25"
      ],
      "mode": "read_write",
      "identity": {
        "mode": "app_token",
        "header": "Authorization",
        "format": "token {credential}",
        "basic_user": "",
        "secret_ref": ""
      },
      "tools": {
        "writes": [
          "*_write",
          "create_*",
          "update_*",
          "merge_*",
          "delete_*"
        ],
        "confirm": [
          "delete_*",
          "repo_write:delete"
        ],
        "never": []
      },
      "aggregate": true,
      "population": [
        "alice",
        "bob"
      ],
      "expiring": {
        "bob": "2027-03-31T23:59:59Z"
      }
    },
    {
      "url": "https://grafana.example.com/mcp",
      "scope": "mcp:grafana.grafana",
      "clients": [
        "ai-chat-mcp",
        "portcullis-ai-claude",
        "portcullis-ai-claude-code",
        "portcullis-ai-generic"
      ],
      "kind": "companion",
      "instance": "grafana",
      "companion": "grafana",
      "label": "Grafana",
      "host": "grafana.example.com",
      "hosts": [
        "grafana.example.com"
      ],
      "app_url": "https://grafana.example.com",
      "min_loa": 2,
      "upstream": "http://portcullis-mcp-grafana--grafana:8000/mcp",
      "protocol": [
        "2025-11-25"
      ],
      "mode": "read_only",
      "identity": {
        "mode": "identity_headers",
        "header": "Authorization",
        "format": "Bearer {secret}",
        "basic_user": "",
        "secret_ref": "grafana/grafana"
      },
      "tools": {
        "writes": [
          "create_*",
          "update_*",
          "delete_*"
        ],
        "confirm": [
          "delete_*"
        ],
        "never": []
      },
      "aggregate": true,
      "population": [
        "alice"
      ],
      "expiring": {},
      "people": {
        "alice": {
          "email": "alice@example.org",
          "groups": [
            "design",
            "users_grafana"
          ]
        }
      }
    },
    {
      "url": "https://hub.example.com/mcp",
      "scope": "mcp:portcullis.admin",
      "clients": [
        "portcullis-ai-claude",
        "portcullis-ai-claude-code"
      ],
      "kind": "portcullis_admin",
      "instance": "",
      "companion": "",
      "label": "Portcullis (admin)",
      "host": "hub.example.com",
      "hosts": [],
      "app_url": "",
      "min_loa": 2,
      "upstream": "",
      "protocol": [],
      "mode": "",
      "identity": {
        "mode": "none",
        "header": "",
        "format": "",
        "basic_user": "",
        "secret_ref": ""
      },
      "tools": {
        "writes": [],
        "confirm": [],
        "never": []
      },
      "aggregate": false,
      "population": [
        "root"
      ],
      "expiring": {}
    },
    {
      "url": "https://mcp.example.com/mcp",
      "scope": "mcp:all",
      "clients": [
        "ai-chat-mcp",
        "portcullis-ai-claude",
        "portcullis-ai-claude-code",
        "portcullis-ai-generic"
      ],
      "kind": "aggregate",
      "instance": "",
      "companion": "",
      "label": "All my apps",
      "host": "mcp.example.com",
      "hosts": [],
      "app_url": "",
      "min_loa": 2,
      "upstream": "",
      "protocol": [],
      "mode": "",
      "identity": {
        "mode": "none",
        "header": "",
        "format": "",
        "basic_user": "",
        "secret_ref": ""
      },
      "tools": {
        "writes": [],
        "confirm": [],
        "never": []
      },
      "aggregate": false,
      "population": [
        "alice",
        "bob",
        "carol",
        "root"
      ],
      "expiring": {}
    },
    {
      "url": "https://people.example.com/mcp",
      "scope": "mcp:portcullis.people",
      "clients": [
        "ai-chat-mcp",
        "portcullis-ai-claude",
        "portcullis-ai-claude-code",
        "portcullis-ai-generic"
      ],
      "kind": "portcullis_people",
      "instance": "",
      "companion": "",
      "label": "Portcullis",
      "host": "people.example.com",
      "hosts": [],
      "app_url": "",
      "min_loa": 2,
      "upstream": "",
      "protocol": [],
      "mode": "",
      "identity": {
        "mode": "none",
        "header": "",
        "format": "",
        "basic_user": "",
        "secret_ref": ""
      },
      "tools": {
        "writes": [],
        "confirm": [],
        "never": []
      },
      "aggregate": true,
      "population": [
        "alice",
        "bob",
        "carol",
        "root"
      ],
      "expiring": {}
    }
  ]
}
```

- `enabled`: the master switch (§15.11); `false` (or a Hub without the gate's recipient) means every request is `503` "AI support is off on this Portcullis". `issuer` the realm's public issuer; `main_domain` the main domain; `clients` every AI client id the gate knows (sorted): the offered clients of §8 and every enabled `ai_client` client — the union of the resources' `clients`, which decide per resource (§15.2); `allowed_origins` Settings → AI's list (`https://<host>[:port]` each, sorted); `acr_loa` the realm's map.
- `limits` (§15.9): positive integers. The first seven come from Settings → AI; `max_request_bytes`, `max_result_bytes` and `upstream_timeout_s` are fixed at these values in this release.
- `core_hosts`: every core host (§4), sorted; it must list at least the main domain and `auth.`, `hub.`, `people.` and `mcp.<main domain>`, else the file is refused. A resource of kind `companion` whose `host` or `hosts` names a core host refuses the file, and so does one naming the main domain or any of the eight core subdomains whatever `core_hosts` lists.
- `resources`: sorted by `url`. A `Resource`:
    - `url` (§15.1), `scope`, `clients` (the `azp` values allowed on this resource, sorted, each also in the top-level `clients`, else the file is refused: companion, people and aggregate resources the offered AI clients plus every enabled `ai_client` (the aggregate's fan-out checks each companion's `clients`, §15.9); the admin resource only offered clients whose admin flag is on, §8, never an `ai_client`; a client whose Keycloak setup last failed is on none), `kind` (`companion`, `aggregate`, `portcullis_admin`, `portcullis_people`; at most one of each of the last three), `label`, `host` (the URL's host; the lookup key with the URL's path);
    - companion only, else `""` / `[]`: `instance`, `companion`, `hosts` (every hostname of the instance, sorted; where its URL elicitations may point, §15.5), `app_url` (`https://<host>`, for the "open it once" message), `upstream`, `protocol` (from the template), `mode` (`read_only` or `read_write`, the admin's choice);
    - `upstream`: for a companion exactly `http://portcullis-mcp-<instance>--<companion>:<port><path>` (any other value refuses the file); `""` for the other kinds — the gate serves the aggregate itself and sends the Portcullis kinds only to its own `MCP_GATE_HUB_URL` (`/mcp/admin`, `/mcp/people`), never to a URL from the file;
    - `min_loa` (§15.2);
    - `identity`: `{mode, header, format, basic_user, secret_ref}`. `mode` is `app_token`, `identity_headers` or `none` (the non-companion kinds). `app_token`: `header` and either `format` (`token {credential}`) or, for HTTP Basic, `format` `""` and `basic_user` the user template (`{username}` or a literal); the password is the credential. `identity_headers`: `header` and `format` of the caller secret (`Bearer {secret}`) and `secret_ref` = `<instance>/<companion>`, the `caller_secrets` entry. Unused fields are `""`;
    - `tools`: the template's `{writes, confirm, never}` patterns (§3.2), in the template's order;
    - `aggregate`: whether the resource's tools are in "all my apps" (§15.9): the companion's `aggregate`, `true` for the people resource, `false` for the others;
    - `population`: lowercase usernames, sorted (§15.1); `expiring`: `{"<user>": "<RFC 3339 UTC>"}`, the earliest pending expiry of the membership that puts the person in the population (the gate refuses from that time on, even before the Hub removes them); `{}` when none;
    - `people`: **only** for `identity_headers` companions: per population member with an email (members without one are left out) `{email, groups}` — the LLDAP email and the groups group-gate would let through (LLDAP groups minus memberships past their expiry), sorted. A person missing from it gets no `X-Forwarded-Email` or `X-Auth-Request-Groups`, never a stale value.
- **Never listed:** AI clients whose Keycloak setup last failed (on no resource and not in `clients`; Settings → AI doesn't show this health, §15.11), `app_oauth` companions, companions that are off, instances that are disabled, deleting or restoring, templates with `ai.unsupported`, and companions whose restore `revoke_all` hasn't succeeded (§11.6).
- **Write failures fail closed.** When the directory can't be read, the Hub keeps the last `mcp-gate.json` (like `expiring` in the policy file) and retries; it never writes a file with populations it couldn't compute.

**`mcp-credentials.json`** (written on every mint, revocation, caller-secret change and AI switch):

```json
{
  "version": 1,
  "credentials": [
    {
      "instance": "gitea",
      "companion": "gitea",
      "user": "alice",
      "id": "7",
      "minted_at": "2026-11-05T09:30:00Z",
      "state": "active",
      "age": "-----BEGIN AGE ENCRYPTED FILE-----\nYWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBleGFtcGxl\n-----END AGE ENCRYPTED FILE-----\n"
    },
    {
      "instance": "gitea",
      "companion": "gitea",
      "user": "carol",
      "id": "4",
      "minted_at": "2026-11-01T14:02:11Z",
      "state": "revoking",
      "age": ""
    }
  ],
  "caller_secrets": [
    {
      "ref": "grafana/grafana",
      "age": "-----BEGIN AGE ENCRYPTED FILE-----\nYWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBleGFtcGxl\n-----END AGE ENCRYPTED FILE-----\n"
    }
  ]
}
```

- `credentials`: sorted by `instance`, `companion`, `user`; at most one entry per (instance, companion, user). `id` is the app-side id the mint hook returned (`^[A-Za-z0-9._:-]{1,128}$`), `minted_at` RFC 3339 UTC, `state` `active` or `revoking`, `age` the credential as ASCII-armored age ciphertext to the gate's recipient (`age.pub`). A `revoking` entry has `age` `""` (the Hub drops the ciphertext when it marks the entry) and is **never** used: the gate treats the person as having no credential.
- `caller_secrets`: one per enabled `identity_headers` companion, sorted by `ref` (`<instance>/<companion>`); `age` the value of the companion's `caller_secret.env` variable, encrypted the same way.
- An entry whose (instance, companion) has no resource in `mcp-gate.json` is ignored. A ciphertext the gate can't decrypt refuses the file (the error names the entry's index, never the ciphertext).
- **A refused file takes every AI resource down**: the gate answers `503` on companions, both Portcullis resources and the aggregate (§15.2) until the file decodes again. This is what happens when `secrets/mcp-gate/age.key` is lost or replaced: `init` / `up` / `upgrade` / `restore` generate a new key when it is missing and rewrite `age.pub`, and every ciphertext to the old recipient becomes undecryptable. The Hub re-encrypts the caller secrets to the new recipient at its next gate-file write (it reads the values from the instances' env files). It can't re-encrypt app credentials (it never holds their plaintext): they stay until dropped. Only `active` entries of listed resources are decrypted, so switching each `app_token` companion off (its resource leaves `mcp-gate.json` at once; `revoke_all` then revokes the app-side credentials and removes the entries) and back on recovers; each person's credential is minted again on their next request (the gate asks the Hub to mint, §15.5 `app_token`). The master switch doesn't help: switching it back on runs no `revoke_all` for `app_token` companions. While the file is refused, the gate's `/healthz` stays `200` (Traefik would drop an unhealthy container) and adds a line `refusing every AI request (503): <why>`, which `./portcullis status` reports as a failure (`mcp_gate.refusing` in `--json`); the command that generates a new key while an `age.pub` exists warns about it. Keep `age.key` with the backups of `secrets/` ([Backups](../operations/backups.md)).
- The `age` values above are shortened placeholders: the vector tests decoding and encoding, not decryption.

### 15.5 Identity modes, tool policy and hook I/O

**Towards the upstream** the gate sends only what the identity mode defines plus `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`, `Mcp-Param-*` (built from the already-checked arguments), `Last-Event-Id` (only ids the upstream itself sent), a fixed `User-Agent`, `Content-Type`, `Accept` and the upstream's session id. It never forwards `Cookie`, `Authorization` (the person's token), `Proxy-Authorization`, any `X-Forwarded-*` or `X-Auth-Request-*` header the client sent, `Remote-*` or `X-Portcullis-*`; it strips `Set-Cookie` from upstream answers and sets no cookie itself.

- **`app_token`.** The gate injects the person's credential from `mcp-credentials.json`: `<header>: <format with {credential}>` (e.g. `Authorization: token <credential>`), or with `basic_user` `<header>: Basic <base64(<user>:<credential>)>` (`{username}` = the lowercase username). Without an active entry it never calls the upstream anonymously: it asks the Hub to mint one (`POST /internal/credentials`, §15.7), waits up to **20 s** for the entry to appear in the file and then proceeds; otherwise the request gets a JSON-RPC error "Preparing your access to <label>, try again in a moment". A Hub answer `409 no_account` gives "Open <label> (<app_url>) in your browser once, then try again". Concurrent requests of one person for one resource share one mint (single flight).
- **`identity_headers`.** The gate sends `X-Forwarded-User` (the lowercase username), `X-Forwarded-Email` and `X-Auth-Request-Groups` (comma-joined) from the resource's `people`, the `X-Forwarded-Attr-*` headers group-gate would send on the resource's host (§4.1), and the caller secret: `<caller_secret.header>: <format with {secret}>`. A person missing from `people` or from `user-attributes.json` gets no such header. Group names in `X-Auth-Request-Groups` aren't escaped, as with group-gate: a group whose name contains `,` reaches the companion as two groups.
- **`app_oauth`.** The gate is not in the path: the person's client talks to the app's own MCP route, signing in through the app (which signs in through Keycloak). The gate's population check, tool filtering, confirmations, rate limits and access log don't apply there; the app's own rules do, and the AI tab and People card say so ("<label> applies its own rules; Portcullis doesn't log or confirm its AI actions"). What still holds: Keycloak sign-in with the instance's access role, the `revoke` hook on leaving (below), and AI support off turns it off (`on_change`).

**Tool policy** (companions; the gate decides every `tools/call` from the template's policy and the admin's mode, whether or not the tool was listed before):

- Patterns are matched case-insensitively on both sides; `tool:method` matches the tool whose arguments' `method` equals `method`; `tool:*` also matches a missing or empty `method`; a `method` that isn't a string, or is outside `^[A-Za-z0-9_.-]{1,64}$`, matches every `tool:<method>` pattern (each list only refuses or confirms, so this is always the stricter reading). Tool names outside `[A-Za-z0-9_./-]{1,128}` are hidden and refused.
- A person's upstream session is closed (an MCP `DELETE`) when they leave, with the identity of that session's last request (kept in memory only; none = no `DELETE`). At most 16 live sessions per person and resource (a new one evicts the oldest); at most 8 input requests per round.
- `never` tools are hidden from `tools/list` and refused in every mode; in `read_only` mode `writes` tools are hidden and refused too (a JSON-RPC error, logged `deny:never` / `deny:read_only`). Where the template supports it, read-only is also enforced by the companion (`PORTCULLIS_AI_READONLY_<COMPANION>`) and the credential's scopes; for a companion that does neither (Nextcloud: its app password is full-scope), read-only rests on the gate alone.
- `confirm` tools need a confirmation (§15.6). A tool the companion annotates `destructiveHint: true` that `confirm` misses needs one too (a template warning in the gate's log). Annotations come from the gate's own cached `tools/list` of that upstream for that person (fetched first when it has none); an annotation never relaxes a rule (`readOnlyHint` on a `writes` tool doesn't unhide it) and a missing one changes nothing.
- **Server-to-client requests** from a companion: a request for `sampling` or `roots` ends the tool call with an `isError` result, nothing is answered to the companion (logged `deny:sampling` / `deny:roots`: a companion must not drive the person's model or see their files); form-mode elicitation is passed through (the gate waits at most 60 s for each answer from the client; no answer declines); URL-mode elicitation is passed through only for an `https://` URL whose host is one of the resource's `hosts` or `people.<main domain>` — never `auth.`, `hub.`, `mcp.` or any other host (declined, logged `deny:url_elicitation`).
- **Sessions** are bound to the person: the gate gives clients its own opaque session ids mapped to (person, resource, upstream session); another person presenting one gets `404`. Pooled upstream sessions of a person who left a population are closed at the next file change.

**Hook I/O.** The Hub runs `mint`, `revoke` and `on_change` hooks (`when: [ai]`, §13.8) like other hooks — argv verbatim, never a shell, in a running container of the hook's service in this instance, the hook's `user` and `timeout` — but outside the settings delivery engine, with split output (§6), one JSON document on stdin and these rules:

| Action | stdin | stdout | Exit |
|--------|-------|--------|------|
| mint | `{"action": "mint", "user": "alice", "sub": "<alice's Keycloak user id>", "instance": "gitea", "companion": "gitea", "name": "portcullis-ai-k3x9q2m7w1ab", "mode": "read_write", "scopes": ["write:repository", "…"]}` (`sub` is the person's current Keycloak id, checked by the Hub against their LLDAP uuid (`LDAP_ID`); no checked id → no mint, `502`. A hook whose app stores the sign-in `sub` mints only for the account linked to it, so a re-created username never gets the former person's account; an app that keys accounts on the username alone ignores it) | exactly one JSON document `{"credential": "…", "id": "…"}` (strict; `credential` 1–4096 printable ASCII characters other than `"` and `\` (so it is written without JSON escapes; the Hub refuses an escaped one), `id` as in §15.4) | `0` minted; `3` the person has no app account yet (they never signed in to the app; the hook never creates accounts); anything else failed |
| revoke | `{"action": "revoke", "user": "alice", "ids": ["7"]}` (`ids` `[]` for `app_oauth`: every app-side token the person holds for MCP; `app_oauth` adds `"sub": "<the person's Keycloak user id>"`, the `sub` the app received at sign-in — apps match the person by it, never by a name the person can change; the Hub looks it up and fails the revoke (retried) when it can't) | ignored | `0` revoked, else failed |
| revoke_all | `{"action": "revoke_all", "prefix": "portcullis-ai-"}` (every credential whose name starts with the prefix, every person; for `app_oauth` every person's MCP tokens) | ignored | `0` done, else failed |
| on_change | `{"action": "on_change", "enabled": true, "mode": "read_write", "companion": "gitea"}` | ignored | `0` applied, else failed |

- `name` is `portcullis-ai-` + 12 random `[a-z0-9]`: the name the app shows for the credential. `scopes` is the template's `identity.scopes[<mode>]` (`[]` when absent).
- **stdout is never stored.** On success the mint output is parsed, the credential encrypted to the gate (§15.4) and every plaintext copy zeroed; any other output is dropped unread. Stdout is never logged, audited, put in an op record, an error or an answer. On failure the op record (op `ai`) and the companion's last error on the AI tab get the exit code and stderr only, redacted (the instance's secrets, any stdout bytes) and then clipped. Hook output is never parsed for `PORTCULLIS-REPORT` lines.
- **Locks.** Mint and revoke never take the instance's lifecycle try-lock (a backup would make them `409`): they take a per-instance AI lock that waits, plus single flight per (resource, user). Lifecycle operations (switching AI on or off, restore, delete) take the lifecycle lock, then the AI lock. A hook whose service has no running container fails (mint: `502 mint_failed`; revoke: retried).

**Credential lifecycle.**

- **Mint** (lazy, on a person's first request): the Hub re-checks the population against a fresh directory snapshot, returns the existing active entry's id if there is one (a credential belongs to the LLDAP account it was minted for: an entry minted for a former holder of a re-created name is revoked and never reused, and the newcomer gets a new one), else runs `mint`, writes the entry (`active`) and answers; audited `ai.credential.mint` (target `<instance>/<companion>/<user>`, detail `id <id>`; never the credential). Residual: a mint hook that times out may still create an app credential the Hub never learns of; nobody holds its plaintext, and the companion's next `revoke_all` (which removes every `portcullis-ai-*` credential) ends it.
- **Revoke on leave.** When a person leaves a companion's population (rule evaluator, admin removal, expiry, user or group deletion, instance disabled), the same Hub pass that rewrites `mcp-gate.json` marks their entries `revoking` (the gate stops using them at its next reload, within seconds), then runs `revoke` with their ids; success removes the entries, a failure keeps them `revoking`, retried at every reconcile and shown on the AI tab (never reported as done). Audited `ai.credential.revoke`. The policy write itself marks leavers' entries `revoking` from its own directory snapshot, right after the gate file (no hook; the reconcile runs the revocations); the Hub's other files (§15.4) live in `<data>/ai/`: `oauth-seen.json`, `orphans.json` (ids of minted credentials that couldn't be stored, revoked and retried) and `connections-seen.json` (who could use an AI resource, for the cleanup below).
- **`app_oauth` leavers.** The Hub records who could use each `app_oauth` companion (`<data>/ai/oauth-seen.json`, 0600): the instance's population while its AI support is on, each person with the LLDAP uuid seen when they were first recorded and every Keycloak user id looked up for them since (a list: a person's id changes when Keycloak re-imports their copy, §8 "User link"); ids are looked up only while the live uuid equals the recorded one. A disabled instance, a policy or sign-in change is not leaving (holders aren't judged then). A person who left with a **verified** record (uuid and at least one id) gets `revoke` with `ids: []` and `sub` for each recorded id; once all succeed they are marked revoked (replayed after a restore: a same-instance restore marks the replay for every `app_oauth` companion of the template whatever its switch, and a companion the archive had on but that was restored off, or whose AI state can't be read, owes a `revoke_all`, run while it is off). A person who left with an **unverifiable** record (no uuid, another live uuid, an id lookup failing 3 passes, or a record a failed write left out) makes the companion's `revoke_all` run (every person's AI-client tokens in the app), after which the record is rebuilt from the current holders and the person is listed as *unmatched* (AI tab, doctor `ai_credentials_revoking`) until an admin dismisses them (`POST /api/instances/{id}/ai/dismiss`, §15.11): their non-AI app tokens remain until the admin deactivates the account in the app.
- **`revoke_all`** runs before every switch-on and every mode change of a companion (app-side scopes encode the mode, and a restore-as copy may hold old tokens; a failure is a `502` with the redacted stderr and AI stays off), when a companion is switched off (its entries removed after success), and after a same-instance restore (§11.6). On a running instance, switching an `app_token` or `identity_headers` companion off runs `revoke_all` **before** the recreate, while the app still runs with its current configuration (mint waits on the AI lock, so no credential appears in between); if that fails the switch-off still commits and the revoke is owed and retried after the up. `app_oauth` revokes after the up (the app grants its own tokens while the companion is still on). Every hook the Hub runs right after a compose up (`on_change`, after-up and owed revokes) waits up to 60 s for its service to leave the `starting` health state, retrying while the service has no healthcheck or is still starting; a timed-out run is never repeated. Switching off also runs `on_change` with `enabled: false`. For `app_oauth` switching off runs `revoke_all` only; the record is kept, so a recorded person who leaves later still gets their own `revoke`. Owed `revoke_all` and `on_change` runs are kept in the state: when the Hub stops between a switch's (or the master switch's) commit and the compose up that runs them, the Hub owes every enabled instance carrying one a restart at its next start, and that start runs them.
- **Template updates.** After the final Discover of a source sync, and at start, a companion that disappeared from its template or whose identity mode changed is switched off (audited `ai.disable`, detail `template changed`), its entries marked `revoking`, and `revoke_all` runs while the hook still exists; otherwise the entries stay `revoking` and the doctor warns (`ai_credentials_revoking`, §14.5). A switch whose plan such a change overtakes is refused at its commit (`409` "the template changed meanwhile: try again"), and a companion stamped with another identity mode than the template's is never listed or rendered. Residual: a template update that only changes a companion's `identity.scopes` or its hooks doesn't touch existing credentials; they keep the scopes they were minted with until the person leaves or a switch or mode change runs `revoke_all`.
- **No AI resource left.** When a person can use no AI resource at all any more (deleted, or in no population), the Hub also deletes their consents and offline sessions for every AI client (§8). The resources that count are a switched-on companion's population, everyone while the people MCP is on and `lldap_admin` while the admin MCP is on; the aggregate alone keeps nobody's connections. The cleanup doesn't run while the master switch is off; while an instance is being deleted or restored, that instance's people are spared.
- **Not judged, never guessed.** While the directory can't be read, the master switch is off, or a companion owes a `revoke_all`, nobody is judged a leaver; a failing revoke is audited once per distinct error text, and every success is audited.

### 15.6 Confirmations

**What needs one:** class **D** tools of the Portcullis MCP (§15.10) and companion tools that `confirm` (or a destructive annotation) catches (§15.5). Calling such a tool without a matching approved confirmation never acts: it creates a confirmation and answers with a link to it.

- **Id and binding.** 128 random bits, base32 (RFC 4648, no padding), shown uppercase in groups of four joined by `-` (`7Q2M-KDWX-…`); the Hub accepts it case-insensitively with or without the dashes. The id is not a credential: opening the URL signed out just leads to sign-in. A confirmation is bound to (person, resource, tool, `args_sha256`): the resource URL (a companion's own URL also when the call came through the aggregate), the tool's name as its server knows it, and the lowercase hex SHA-256 of the arguments' RFC 8785 canonical JSON (absent or `null` arguments are `{}`). Any argument change needs a new confirmation.
- **Life.** `pending` → `approved` or `declined`; valid **10 minutes** from creation (then `expired`); single use: the first matching retry consumes an approved one (`consumed`). Creating one while a pending one with the same binding exists returns that one. Kept in the Hub's memory only (a Hub restart expires them).
- **Limits** (Hub-side, over both creation paths): ≤ 10 created per person per hour, ≤ 20 pending per person, ≤ 1000 pending in total; over a limit the tool answers `isError` "Too many confirmations requested; try again later", audited `ai.confirm` `refused`. The gate applies its own `confirmations_per_hour` before asking.
- **The page** is on the listener the tool belongs to: `https://hub.<d>/confirm/<id>` for admin tools, `https://people.<d>/confirm/<id>` for people tools and companions (§5.1; a confirmation is `404` on the other listener). It is a normal browser page behind forward-auth and:
    1. refuses (`404`) every signed-in user but the person it was created for;
    2. shows the action as the Hub renders it from the stored request, never text the model wrote: the tool, its target, the consequences (e.g. "Takes a backup, then permanently removes its containers, volumes, Keycloak client and groups users_x, admin_x"), the requesting AI client and time, and the arguments as their canonical JSON (escaped; never clipped — arguments over 4 KiB never get a confirmation, §15.7). Request-derived values appear in the consequences only as names the Hub validated or quoted (`"…"`). Every field of the page shows control, format (bidi controls, zero-width characters, U+FEFF), line and paragraph separator, non-ASCII space, default-ignorable and private-use characters as `\uXXXX` (`\U00XXXXXX` above the BMP), so nothing on it can be hidden or reordered;
    3. asks for the typed check: the tool's existing one for admin tools (the instance id, the person's or group's name, the domain; the tool's name when a tool has none), the **instance label** for companion tools. The check is exact: the typed text, trimmed, must equal it as shown, case-sensitive (a check holding an invisible character is typed in its `\u…` form);
    4. asks for a fresh passkey touch through `portcullis-fresh-auth` (the popup flow of §5.1; the proof of §8: `auth_time` ≤ 5 minutes old, `amr` `hwk` or `mtls`, never `file`) whose `auth_time` is no earlier than 60 s before the confirmation was created;
    5. records approve or decline (`POST /api/me/confirmations/{id}`, §5.1); a decline needs no passkey.
- **Answers to the AI.** Never HTTP `401`/`403` (a client would treat it as a sign-in problem) and never form-mode elicitation (a client or script can answer it without the person). A 2026-07-28 client that declared `elicitation.url` gets an `InputRequiredResult` with a URL-mode elicitation (`message` "<Tool> on <label> needs your confirmation in your browser.", the page's URL); the gate, which keeps per-person sessions, sends a 2025-11-25 client that declared it a URL-mode `elicitation/create` request; the Hub's MCP is stateless (§15.10) and gives 2025-06-18 and 2025-11-25 clients the text only. Every other case is a tool result with `isError: true` and exactly: `This needs your confirmation in your browser: open <url>, then ask me to try again.` A retry while pending answers "Still waiting for your confirmation in your browser"; after a decline "You declined this in your browser". A client that declines or cancels the gate's own URL elicitation gets "You cancelled the confirmation; nothing was done" (logged `deny:declined`; the Hub isn't asked). A 2025-11-25 client's answer to `elicitation/create` is never taken as approval: the gate waits at most 60 s, then answers the text, and the call runs only on a retry that consumes the approved confirmation. **Continuation:** when a call that has just consumed its confirmation is then asked for input by the companion (2026-07-28 `input_required`), the gate keeps the companion's request state itself and gives the client a single-use, 10-minute token bound to person, resource, tool and the arguments' sha256; a retry carrying it continues without a second confirmation (logged with the consumed confirmation id); an unknown, expired or mismatched token is a fresh call (it goes through consume again). At most 16 such pending states per person (over it: the text answer, or "busy" for a continuation).
- **Binding checks.** On create the Hub refuses (`400`) an `args_preview` whose SHA-256 isn't `args_sha256`, or that isn't its own RFC 8785 canonical form; consume re-checks that the resource is still a current companion of the person and that they are in its population (anything else is `404`, a directory it can't read `503`). Refused approvals count toward the refused-save limit (§5.1) on both listeners, also for administrators on the Hub listener.
- **Audit:** `ai.confirm` with `approved`, `declined`, `expired` (by the sweeper) or `refused` (a failed approval or a limit), the tool, the resource and `args_sha256`; never the arguments. The tool's own audit entry (§9.5) carries `confirmation <id>` in its detail.

### 15.7 Gate ⇄ Hub internal API

The Hub's third listener, **`HUB_MCP_ADDR`** (default `:8890`). **Every request except `GET /healthz` needs `X-Portcullis-MCP-Secret`** equal to `HUB_MCP_GATE_SECRET` (the file of §15 intro, ≥ 32 characters), compared in constant time, else `401`; there are no other exemptions, and the header is removed before any handler runs. With the secret, the only routes are `/mcp/admin`, `/mcp/people`, `POST /internal/credentials`, `POST /internal/confirmations` and `POST /internal/confirmations/consume`; anything else is `404`. It is bound on all interfaces, so it is reachable from every network the Hub joins — `portcullis-mcp` (where mcp-gate calls it), `portcullis`, `socket-proxy-hub` and `portcullis-domains` (binding per interface isn't portable): the secret is the only protection, and no Traefik router or service targets port 8890 (§5; core CI checks it). Without a secret file the listener isn't started and the gate file says `enabled: false`. No CSRF guard (no browser reaches it); bodies are strict JSON (`DisallowUnknownFields`, no trailing data, ≤ 64 KiB, else `400` / `413`).

- **Identity** for `/mcp/*`: the gate sends `X-Forwarded-User` (the token's lowercase `preferred_username`), `X-Portcullis-AI-Client` (`azp`) and `X-Portcullis-AI-Resource` (the resource URL), replacing anything the client sent. The Hub trusts them **only** on this listener; its Hub and people listeners never read `X-Portcullis-AI-*`. `/mcp/admin` accepts only `X-Portcullis-AI-Resource: https://hub.<main domain>/mcp` and `/mcp/people` only `https://people.<main domain>/mcp`; any other value, or none, is `403`. The gate never passes on the client's `Mcp-Param-*` headers, and refuses a `tools/call` whose arguments don't have one canonical form (§15.6: duplicate keys, unsafe numbers) with `400` `deny:bad_arguments` before the Hub is called.
- **`POST /internal/credentials`** `{"resource": "<url>", "user": "<username>"}` → `200 {"id"}` (an active entry is in the file) | `409 {"code": "no_account", "app_url"}` (mint exit 3) | `403` (not in the population, re-checked against a fresh directory snapshot) | `404` (not a current `app_token` companion resource of the Hub's own configuration) | `502 {"code": "mint_failed"}` (the hook failed or its output was refused). Rate: the gate's `mints_per_minute` per person.
- **`POST /internal/confirmations`** `{"user", "client", "resource", "tool", "args_sha256", "args_preview", "reason"}` → `201 {"id", "url", "expires_at"}` | `403` (not in the population) | `404` (not a current companion resource) | `400` (the tool isn't caught by the companion's `confirm` patterns and `reason` isn't `destructive`) | `429 {"code": "too_many"}` (§15.6). `reason` is `confirm` (a `confirm` pattern) or `destructive` (the upstream's annotation); `args_preview` = the canonical JSON (RFC 8785) of the arguments, which are also exactly the bytes forwarded upstream; arguments whose canonical form is over 4 KiB are refused (never a clipped preview: "these arguments are too long to confirm safely"), and so are arguments that don't round-trip (duplicate keys, numbers outside the safe-integer range, U+2028/U+2029); `url` is `https://people.<d>/confirm/<id>`.
- **`POST /internal/confirmations/consume`** `{"user", "resource", "tool", "args_sha256"}` → `200 {"id"}` (an approved match, now consumed) | `404` (none: the gate creates a new one) | `409 {"state": "pending|declined"}`.
- The `/internal` API serves **companion** resources only; it never creates, reads or consumes a confirmation of a Portcullis tool (those are the Hub's own, §15.10).
- **Fail closed (gate side).** A transport error, a timeout, a `5xx` or any answer not listed above, on mint, create or consume, is an `isError` result "can't check this right now; try again", and the upstream is never called.
- **`/mcp/admin`, `/mcp/people`**: the Portcullis MCP (§15.10), Streamable HTTP.
- **Hub configuration:** `HUB_MCP_ADDR` (`:8890`), `HUB_MCP_GATE_SECRET_FILE`, `HUB_MCP_GATE_RECIPIENT_FILE`, `HUB_MCP_GATE_DATA_DIR` (`/mcp-gate-data`).

### 15.8 Access log

The gate appends one JSON line per MCP request (tool calls through the aggregate count once per upstream call) to `mcp_gate_data/access.jsonl`:

```json
{"time": "2026-11-05T10:16:02Z", "user": "alice", "client": "portcullis-ai-claude", "resource": "https://gitea.example.com/mcp", "instance": "gitea", "companion": "gitea", "via": "aggregate", "method": "tools/call", "tool": "list_issues", "args_sha256": "<64 hex>", "decision": "allow", "upstream_status": 200, "duration_ms": 184}
```

- Every key but `confirmation_id` always present. `user` / `client` `""` when no valid token was presented; `instance` / `companion` `""` for non-companion resources; `via` `direct` or `aggregate`; `method` the JSON-RPC method; `tool` and `args_sha256` (§15.6) only for `tools/call` (else `""`); `upstream_status`: for a companion `200` when it answered, `502` when the call to it failed, `0` when it wasn't called (the gate's MCP client doesn't expose the literal HTTP status per call); for the Portcullis resources the Hub's real HTTP status.
- `decision`: `allow`, `deny:<reason>` (a fixed lowercase reason, e.g. `token`, `scope`, `population`, `loa`, `origin`, `protocol`, `never`, `read_only`, `url_elicitation`, `sampling`, `roots`, `too_large`, `no_account`, `mint_failed`, `hub_unavailable`, `declined`, `off`, `not_confirmable`, `bad_arguments`, `too_long`, `unloggable`, `busy`, `body_timeout`, `pending`, `too_many_inputs`, `client_gone`, and for the aggregate `unknown` (a name not in the person's table), `input` (an input request it can't pass on) and `upstream` (an upstream that failed)), `confirm:<id>` or `rate_limited`.
- `confirmation_id` (**optional**, the only key not always present): on a `tools/call` that consumed a confirmation, or continued after one (§15.6), the id of that confirmation; absent otherwise.
- Never the arguments, a result, a token, a credential or a caller secret.
- File mode 0640, group 10001 (the Hub reads it through its read-only mount), directory 0750; lines older than **90 days** are pruned by an atomic rewrite with the same mode. The Hub reads the last 4 MiB and skips a torn last line (AI tab, `GET /api/ai/activity`, the merged audit view, the person's own `GET /api/me/ai`).
- **Unloggable calls are refused.** A `tools/call` is forwarded only after a line for it has been reserved in the log's queue, and that line (the call's outcome, refused calls included) is never dropped. While the log writer is failing at all, has been stuck on one write for 5 s, or no line can be reserved, every `tools/call` answers `503` "AI activity can't be logged right now" (logged `deny:unloggable`, never forwarded); `initialize` and the list methods still work.

### 15.9 Rate limits and "all my apps"

**Limits** (per person, not per IP: every hosted Claude user comes from Anthropic's range; defaults, `limits` of §15.4):

- 120 requests per minute per person and resource (burst 30); 600 per minute per person across resources;
- 60 `tools/call` per minute per person and resource;
- 10 confirmations started per person per hour; 10 mints per person per minute;
- the aggregate calls at most 4 upstreams in parallel per request;
- request bodies ≤ 8 MiB (`413`), tool results ≤ 16 MiB (JSON-RPC error "result too large"), upstream timeout 120 s;
- fixed memory bounds, checked before a body is read: at most **6 POST requests in flight per person** across resources (over it `429`, logged `rate_limited`; GET streams and `DELETE` aren't counted), and a gate-wide body budget of **512 MiB**, each POST holding 3× its body size (its `Content-Length`, else the 8 MiB maximum until the body has been read) until it ends; no room within 2 s is `503` "the gate is busy" with `Retry-After`, logged `deny:busy`. The budget covers request bodies only, not tool results (≤ 16 MiB each) or the aggregate's list refreshes: one person can't exhaust the gate's memory, but many people at once still can, and the container then restarts (in-flight calls fail).

Over a limit: `429` with `Retry-After`, never `401`/`403`. Core's `rate-limit@file` (per source IP) stays in front as the backstop; it is shared by every person whose client runs in Anthropic's cloud, which the admin guide says.

**"All my apps"** (`https://mcp.<d>/mcp`, served by the gate itself):

- `tools/list` for a person is the union, over companions with `aggregate: true` whose population includes them and whose `min_loa` their token meets, of what the per-app endpoint would show them (same filtering), plus the people resource's tools when it is listed with `aggregate: true` — never the delegate tools (`invite_person`, `update_person`, `delete_person`: only on `people.<d>/mcp`, §15.10; the gate drops them by name, and the Hub's `TestCoreAggregateDelegatesComplete` keeps its list equal to the Hub's delegate tools), never admin tools, never `app_oauth` companions.
- **Names** come from a per-person table: `<instance-id>__<tool>` for companions, `portcullis__<tool>` for the people tools (no instance id contains `_` or has `portcullis` as a segment, §3, so the prefixes can't be confused); a name longer than 64 characters becomes its first 55 characters + `_` + the first 8 hex digits of sha256(the full name). Two tools whose names collide, literally or after shortening, are **both** dropped (and logged as a template warning). Calls, resource URIs and prompts are mapped through the same table; a name is never parsed back.
- Descriptions are prefixed `[<companion label> · <host>] ` (the companion's `ai.mcp[].label`, never the instance label; `[Portcullis · people.<d>] ` for the people tools); resources and prompts get the same prefix.
- Two names that are equal after case folding also count as a collision. Resource templates aren't aggregated (`resources/templates/list` is empty); plain resources are aggregated by URI and prompts through the name table. A per-upstream limit reached inside an aggregate request is answered in-band (`isError` or a JSON-RPC error, logged `rate_limited`), not as HTTP `429`. The gate's own client of `/mcp/people` declares no elicitation, so people D and U tools reached through the aggregate get the text form of §15.6.
- Every call is routed to its upstream with the person's identity exactly as on the per-app route (lazy minting included). **Per upstream** (the upstream resource's own entry decides): the population and `expiring` (§15.2), its `min_loa` against the token's `acr`, its tool policy and mode (§15.5), confirmations (§15.6, bound to the upstream's resource URL), the per-resource limits (§15.9; the per-person limit counts across everything) and the access log (one line per upstream call naming the upstream's resource, `via: aggregate`). **The aggregate's own:** the token's audience and scope (`https://mcp.<d>/mcp`, `mcp:all`) and `azp` (the aggregate's `clients`); the token is never checked against an upstream's audience or scope, and is never sent upstream.
- The list is cached 60 s per person and invalidated on any population or configuration change; with `subscriptions/listen` the gate sends `notifications/tools/list_changed`. An upstream that is down drops out with the line "<label> is unavailable right now" in the server's `instructions`; it never fails the endpoint.

### 15.10 The Portcullis MCP

The only MCP server Portcullis writes: the Hub's, at `https://hub.<d>/mcp` (`/mcp/admin`, admins only) and `https://people.<d>/mcp` (`/mcp/people`, anyone signed in). Its scope is Portcullis and what Portcullis manages — never an action inside an app (those go only through the app's companion). The gate forwards to it through the same pipeline as a companion (§15.2–15.3, §15.8–15.9: token, population, `Origin`, protocol and header checks on the parsed body, limits including `tools/call`, body caps, one access-log line per request with the hub or people URL as `resource`).

- **Same methods, same rules.** Each tool resolves the caller with `CallerFor` (the `directory.Caller` gains the **NEW** fields `Via` = `"ai"` and `Client` = the gate's `X-Portcullis-AI-Client`; `directory.AuditEntry` gains `Via` / `Client`, §9.5) and calls the **same** Hub or directory method its HTTP twin calls (no HTTP loopback), so authorization, guardrails, locks, errors and audit (§9.5) are identical. `/mcp/admin` answers only admins (re-checked per mutation); `/mcp/people` gives exactly the people listener's view (`OverviewFor(caller)`, `/api/me/*`) and delegated operations only through the caller's permissions. Every Hub-listener route is some admin tool's twin or explicitly listed as having none (the page, `/static/`, `/healthz`, `GET /api/portal/apps`, `GET /api/directory/me`, the multipart CSV `import/review`, which has a JSON tool instead); the Hub's tests check it both ways.
- **Stateless.** Streamable HTTP without sessions: 2026-07-28 URL elicitations go in an `InputRequiredResult`; 2025-06-18 and 2025-11-25 clients get the text form of §15.6 (a stateless server can't send `elicitation/create`).
- **Classes.** **R** read; **W** write (audited); **D** destructive — needs a confirmation (§15.6); **U** needs a secret from the person — the tool has no argument for it and returns a URL elicitation (or the same link as text) to the Hub's existing form, pre-filled with the non-secret context (e.g. `https://hub.<d>/#settings/domains?enroll=<name>`). Annotations: R `readOnlyHint`; D `destructiveHint`; W and U `destructiveHint: false`; `idempotentHint` where the twin is a `PUT`.
- **D** is every tool whose twin has a typed confirmation today, or deletes, restores over, revokes or runs code (`delete_instance`, `restore_instance`, `restore_as`, `exec`, `save_env`, `save_custom_override`, `resolve_drift`, `remove_source`, `delete_domain`, `delete_person`, `delete_group`, `delete_field`, `require_passkey`, `remove_passkeys`, `revoke_ai_access`, `dismiss_ai_revoke_problem`, `add_model_provider`, `delete_model_provider`, `admin_revoke_credential`, `resume_user_sweep`, `remove_stale_keycloak_user`, `delete_folder`, `folder_undo_apply`; `doctor_apply_fix` when its plan `touches_data`, §14.6; the tool list below is authoritative), **and every access-widening call**: `add_member` / `set_member_expiry` into an administrator, permission or guarding group; `set_permission`; `set_group_rule` on a guarding group; `set_public_access` turning it on; `set_policy` to a policy that isn't stricter than the current one; `set_sign_in_mode` to `native`; `add_source`; `save_hub_settings` changing the AI clients or allowed origins; `set_ai_mode` to `read_write`. `create_person` and `send_invite` are U (the invite or password is set on the Hub's form). Destructive tools are never batched.
- **Delegate tools** (`update_person` with `edit_details`, `invite_person` with `invite`, `delete_person` with `remove`) exist only on `people.<d>/mcp`, never in the aggregate or on the AI page; they are hidden from callers without the permission and refused if called anyway.
- **Secrets never reach the model.**
    - *Arguments:* a U tool takes no argument whose name matches `token`, `password`, `secret` or `key` (case-insensitive), and no tool accepts an argument its schema doesn't declare (`additionalProperties: false`): such a call is an `isError` "secrets are never passed through the AI; use <url>". A declared argument name may match that pattern only from a reviewed allowlist (e.g. `finding_token`, the doctor mute's digest; a settings entry's `key`); values of custom-field arguments are never judged by name.
    - *Results:* the API's rules (secret settings as `{set, updated_at}`, credentials never echoed, env and logs redacted, then clipped) plus: no invite links, no fallback passwords and no server-invite internals in directory results (`create_person` says "run ./portcullis invite <user> on the server" when an invite must come from the server), no file-share passwords (`my_file_share_password` returns the People-page link only), no share tokens (listed tokens show as `•••` with their path), no `HUB_*` secret, no model provider secret. Every result goes through one redactor: the union of every instance's redaction set, the provider secrets, the Hub's file secrets (proxy, MCP gate, invite, domains) and the LLDAP credentials; redact, then clip (≤ 1 MiB). If the set can't be built the result is replaced by "result hidden: secrets couldn't be read". Residual: `get_compose` and `get_custom_override` return the custom override as written, so a secret typed into it as a literal (`environment: {X: hunter2}`) is in no redaction set and reaches the model, as it reaches an admin through the HTTP twin; keep secrets in settings, not in the override.
- **Long operations** (`create_instance`, `enable_instance`, `disable_instance`, `restart_instance`, `set_ai_support` / `set_ai_mode` when the twin answers `202`, `backup_instance`, `restore_instance`, `restore_as`, `delete_instance`; **NEW (operation progress)**: the enable, disable, restart and AI switch tools) return the twin's `202` body `{op_id, op, instance, poll}` at once (no progress notifications: the Hub's MCP is stateless; poll with `wait_for_op`). They take the same instance lock and write the same op record as the route (§11.7), so the UI and the AI see one running operation. `wait_for_op` / `get_op` show the record, its `steps` (**NEW (operation progress)**) (state, percent, detail, times), `created` and stop fields included, and then the outcome. A busy instance is an `isError` `409: ` with the running record (**NEW (operation progress)**), not a protocol error.
- **NEW (operation progress)** **`stop_op`** is **classified per call by what the undo turns back on** (§11.7 `before`), not flat W. It is **D** (needs confirmation) when the undo re-enables or switches something on: a disable; a delete or a same-instance restore of an enabled instance (unless `before.enabled` is `"false"` and, for restore, `before.restoring` is not set); an AI switch-off; an AI record whose `before` isn't written yet (fail closed). It is **W** otherwise (an enable's or a create's undo removes what they made; a restart's and a backup's start only what was running; every AI companion goes back off). A **D call needs `op_id`**: the confirmation names that operation (§15.6), and the Hub refuses any other operation under its lock (`409` "the operation changed"). Refused `stop_op` calls (any 4xx, 404 included) are audited `<op>.stop` refused. It answers the record (`stopping: true`); audited `<op>.stop` with `via` / `client`.
- **`save_settings`** requires the preview's `plan_hash` (§13.12); `save_hub_settings` may turn the Portcullis admin MCP off, never on.
- Read-only MCP resources: the docs pages the Hub ships (`portcullis://docs/…`), each loaded template's manifest (`portcullis://templates/<id>`, generated env values never included) and the doctor's check catalogue; prompts "Diagnose this app", "Set up an app for a team", "Why can't <person> open <app>?".
- **Tool list** (the Hub's registry; `TestAdminToolsSameAsHTTP` and the parity tests check every twin both ways). "D or W per call" tools are registered D and decide per call from their canonical arguments, failing closed to D (G37): `create_instance` / `enable_instance` when the instance's derived groups already exist with people: members, the people their rule matches before the evaluator runs, or active include exceptions (a group with a rule counts even when it matches nobody yet); `save_settings` unless it changes only non-privileged string, int, size, duration, bool, enum or multi_enum options (no ports, no value group ids): anything else, unknown options and new types included, is D; `stop_op` when the undo re-enables or switches something on (§15.10, above); `set_policy` to a policy that isn't stricter; `set_sign_in_mode` to `native`; `set_public_access` turning it on; `set_local_networks` unless every network is inside the current list (back to the defaults is judged as that list); `set_ai_support` on; `set_ai_mode` to `read_write`; `set_ai_providers` when it adds a provider; `save_model_provider` on a destination change; `save_hub_settings` unless it only turns things off or lowers limits and days; `set_default_policy` like `set_policy`; `set_details` / `import_apply` setting a field a guarding group's rule, or the rule of an existing instance's access or admin group, uses (and `import_apply` remove rows); `update_field` of a guarded field's `admin_only: false`, `kind`, `values` or `multi`; `add_member`, `remove_member`, `set_member_expiry`, `add_exception`, `remove_exception`, `set_group_rule`, `convert_group` on an administrator, permission or guarding group (`Membership.Guarding`, `GuardedFields`, `Administrators`), and `set_group_rule`, `convert_group`, `add_exception` and `remove_exception` on an existing instance's access or admin group; `doctor_apply_fix` when its plan `touches_data` (judged on the plan with the call's hash); `doctor_mute` of a Problem or an `ai_credentials_revoking` finding (or one it can't find); `folder_apply` unless the plan only removes uses; `folder_recheck_apply` for a different directory. An unreadable template, directory or plan is D.
- **Names before a confirmation.** A tool that may ask for a confirmation first checks the names in its arguments, nested ones included (import rows, convert previews, `attrs` keys): usernames and group names must be valid or known to the directory (`400`), field names valid (`400`), instance, template and folder ids and doctor finding fingerprints in the twin route's form (`404`, as the route answers); the typed check must be a valid id, username, group name or hostname, or known to the directory (`400`). A refused call creates no confirmation.

    Admin (`/mcp/admin`):

    | Tool | Class | HTTP twin |
    |------|-------|-----------|
    | `hub_status` | R | `/api/status` |
    | `explain_policy` | R | `GET /api/instances/{id}/settings` |
    | `list_instances` | R | `GET /api/instances` |
    | `get_instance` | R | `/api/templates/lastop/` |
    | `instance_defaults` | R | `GET /api/instances/defaults` |
    | `create_instance` | D or W per call | `POST /api/instances` |
    | `enable_instance` | D or W per call | `/api/templates/enable` |
    | `disable_instance` | W | `/api/templates/disable` |
    | `restart_instance` | W | `/api/templates/restart/` |
    | `set_hosts` | W | `PUT /api/instances/{id}/hosts` |
    | `get_op` | R | `GET /api/instances/{id}/op` |
    | `wait_for_op` | R | `GET /api/instances/{id}/op` |
    | `stop_op` (**NEW (operation progress)**) | D or W per call | `POST /api/instances/{id}/op/stop` |
    | `delete_instance` | D | `DELETE /api/instances/{id}` |
    | `get_settings` | R | `GET /api/instances/{id}/settings` |
    | `preview_settings` | R | `POST /api/instances/{id}/settings/preview` |
    | `save_settings` | D or W per call | `PUT /api/instances/{id}/settings` |
    | `set_secret_setting` | U | `PUT /api/instances/{id}/settings` |
    | `set_policy` | D or W per call | `PUT /api/instances/{id}/settings` |
    | `set_sign_in_mode` | D or W per call | `PUT /api/instances/{id}/settings` |
    | `set_public_access` | D or W per call | `PUT /api/instances/{id}/settings` |
    | `get_logs` | R | `/api/templates/logs/` |
    | `get_status` | R | `/api/templates/status/` |
    | `exec` | D | `/api/templates/exec/` |
    | `get_compose` | R | `/api/templates/compose/` |
    | `get_env` | R | `/api/templates/env/` |
    | `save_env` | D | `/api/templates/env/` |
    | `get_custom_override` | R | `/api/templates/compose/` |
    | `save_custom_override` | D | `/api/templates/compose/` |
    | `list_drift` | R | `/api/drift` |
    | `resolve_drift` | D | `/api/drift/resolve` |
    | `set_person_value` | W | `PUT /api/instances/{id}/settings/entries/{key}/{user}` |
    | `clear_person_value` | W | `DELETE /api/instances/{id}/settings/entries/{key}/{user}` |
    | `retry_deliveries` | W | `POST /api/instances/{id}/settings/retry` |
    | `missing_groups` | R | `GET /api/instances/missing-groups` |
    | `create_missing_groups` | W | `POST /api/instances/missing-groups` |
    | `list_credentials` | R | `GET /api/instances/{id}/credentials` |
    | `admin_revoke_credential` | D | `DELETE /api/instances/{id}/credentials/{key}/{user}` |
    | `get_local_networks` | R | `GET /api/settings/local-networks` |
    | `set_local_networks` | D or W per call | `PUT /api/settings/local-networks` |
    | `list_templates` | R | `/api/templates` |
    | `get_template` | R | `/api/templates` |
    | `list_sources` | R | `/api/sources` |
    | `sync_sources` | W | `/api/sources/sync` |
    | `add_source` | D | `/api/sources/add` |
    | `remove_source` | D | `/api/sources/remove` |
    | `list_backups` | R | `GET /api/instances/{id}/backups` |
    | `list_backups_all` | R | `GET /api/backups` |
    | `backup_instance` | W | `POST /api/instances/{id}/backups` |
    | `restore_instance` | D | `POST /api/instances/{id}/restore` |
    | `restore_as` | D | `POST /api/instances/restore` |
    | `list_domains` | R | `GET /api/domains` |
    | `enroll_domain` | U | `POST /api/domains` |
    | `replace_domain_token` | U | `POST /api/domains/{name}/token` |
    | `delete_domain` | D | `DELETE /api/domains/{name}` |
    | `ai_status` | R | `GET /api/instances/{id}/ai` |
    | `set_ai_support` | D or W per call | `PUT /api/instances/{id}/ai` |
    | `set_ai_mode` | D or W per call | `PUT /api/instances/{id}/ai` |
    | `set_ai_providers` | D or W per call | `PUT /api/instances/{id}/ai` |
    | `revoke_ai_access` | D | `POST /api/instances/{id}/ai/revoke` |
    | `dismiss_ai_revoke_problem` | D | `POST /api/instances/{id}/ai/dismiss` |
    | `ai_activity` | R | `GET /api/ai/activity` |
    | `list_model_providers` | R | `GET /api/ai/providers` |
    | `add_model_provider` | D | `POST /api/ai/providers` |
    | `save_model_provider` | D or W per call | `PUT /api/ai/providers/{name}` |
    | `set_model_provider_secret` | U | `PUT /api/ai/providers/{name}/secrets/{field}` |
    | `delete_model_provider` | D | `DELETE /api/ai/providers/{name}` |
    | `get_hub_settings` | R | `GET /api/ai/settings` |
    | `save_hub_settings` | D or W per call | `PUT /api/ai/settings` |
    | `set_default_policy` | D or W per call | `/api/settings` |
    | `preview_default_policy` | R | `POST /api/settings/preview` |
    | `user_sweep_status` | R | `GET /api/keycloak/user-sweep` |
    | `resume_user_sweep` | D | `POST /api/keycloak/user-sweep/resume` |
    | `remove_stale_keycloak_user` | D | `DELETE /api/directory/keycloak-stale/{username}` |
    | `directory_overview` | R | `GET /api/directory` |
    | `get_person` | R | `GET /api/directory` |
    | `preview_rule` | R | `POST /api/directory/rules/preview` |
    | `convert_group_preview` | R | `POST /api/directory/groups/{group}/convert-preview` |
    | `import_review` | R | `POST /api/directory/import/apply` |
    | `audit_recent` | R | `GET /api/directory/audit` |
    | `create_person` | U | `POST /api/directory/users` |
    | `update_person` | W | `PUT /api/directory/users/{username}` |
    | `set_details` | D or W per call | `PUT /api/directory/users/{username}/details` |
    | `require_passkey` | D | `POST /api/directory/users/{username}/require-passkey` |
    | `remove_passkeys` | D | `POST /api/directory/users/{username}/remove-passkeys` |
    | `set_password` | U | `POST /api/directory/users/{username}/password` |
    | `send_invite` | U | `POST /api/directory/users/{username}/invite` |
    | `clear_actions` | W | `POST /api/directory/users/{username}/clear-actions` |
    | `delete_person` | D | `DELETE /api/directory/users/{username}` |
    | `create_group` | W | `POST /api/directory/groups` |
    | `delete_group` | D | `DELETE /api/directory/groups/{group}` |
    | `add_member` | D or W per call | `POST /api/directory/groups/{group}/members` |
    | `remove_member` | D or W per call | `DELETE /api/directory/groups/{group}/members/{username}` |
    | `set_member_expiry` | D or W per call | `PUT /api/directory/groups/{group}/members/{username}/expiry` |
    | `set_group_rule` | D or W per call | `PUT /api/directory/groups/{group}/rule` |
    | `convert_group` | D or W per call | `POST /api/directory/groups/{group}/convert` |
    | `add_exception` | D or W per call | `POST /api/directory/groups/{group}/exceptions` |
    | `remove_exception` | D or W per call | `DELETE /api/directory/groups/{group}/exceptions/{username}` |
    | `set_permission` | D | `PUT /api/directory/permissions/{perm}` |
    | `create_field` | W | `POST /api/directory/fields` |
    | `update_field` | D or W per call | `PUT /api/directory/fields/{name}` |
    | `delete_field` | D | `DELETE /api/directory/fields/{name}` |
    | `import_apply` | D or W per call | `POST /api/directory/import/apply` |
    | `doctor_findings` | R | `GET /api/doctor` |
    | `doctor_scan` | W | `POST /api/doctor/scan` |
    | `doctor_op` | R | `GET /api/doctor/op` |
    | `doctor_preview_fix` | R | `POST /api/doctor/findings/{fp}/preview` |
    | `doctor_apply_fix` | D or W per call | `POST /api/doctor/findings/{fp}/apply` |
    | `doctor_mute` | D or W per call | `POST /api/doctor/findings/{fp}/mute` |
    | `doctor_unmute` | W | `DELETE /api/doctor/findings/{fp}/mute` |
    | `list_folders` | R | `GET /api/folders` |
    | `create_folder` | W | `POST /api/folders` |
    | `update_folder` | W | `PUT /api/folders/{id}` |
    | `delete_folder` | D | `DELETE /api/folders/{id}` |
    | `check_folder_path` | R | `POST /api/folders/check` |
    | `folder_preview` | R | `POST /api/folders/{id}/assign/preview` |
    | `folder_apply` | D or W per call | `POST /api/folders/{id}/assign/apply` |
    | `folder_undo_preview` | R | `POST /api/folders/{id}/undo/preview` |
    | `folder_undo_apply` | D | `POST /api/folders/{id}/undo/apply` |
    | `folder_recheck_preview` | R | `POST /api/folders/{id}/recheck/preview` |
    | `folder_recheck_apply` | D or W per call | `POST /api/folders/{id}/recheck/apply` |
    | `folder_op` | R | `GET /api/folders/{id}/op` |

    People (`/mcp/people`; the three with a permission are the delegate tools):

    | Tool | Class | HTTP twin |
    |------|-------|-----------|
    | `my_apps` | R | `GET /api/me/apps` |
    | `my_profile` | R | `GET /api/directory/me` |
    | `directory` | R | `GET /api/directory` |
    | `my_ai_connections` | R | `GET /api/me/ai` |
    | `disconnect_ai` | W | `DELETE /api/me/ai/connections/{client}` |
    | `my_file_share_password` | R | `POST /api/me/apps/{instance}/credentials/{key}` |
    | `update_person` | W (needs `edit_details`) | `PUT /api/directory/users/{username}` |
    | `invite_person` | U (needs `invite`) | `POST /api/directory/users` |
    | `delete_person` | D (needs `remove`) | `DELETE /api/directory/users/{username}` |

- **Never tools.** The confirmation routes (`GET /confirm/{id}`, `POST /api/me/confirmations/{id}`: an AI must never approve its own confirmation), credential create and revoke (`/api/me/apps/{instance}/credentials/{key}`: `my_file_share_password` only returns the People-page link), the multipart CSV `import/review` (`import_review` takes JSON and calls what the route's JSON branch calls; its twin is `import/apply`'s), and the page, `/static/` and `/healthz`. There is no `my_certificates` (certificates self-service adds it).
- **Answers.** Tool errors are `isError` results prefixed `<status>: ` (an `OpError` as its JSON record, redacted and clipped); a people tool refused for a missing permission is `403: not allowed: needs <perm>` and, like every W, D and U refusal before `Run`, audited `refused` under the twin's action; a non-admin on `/mcp/admin` gets empty lists and the JSON-RPC error "admins only" for reads and prompts; while the caller can't be resolved (the directory is down) a `tools/call` still gets a tool result (`isError`), never a protocol error; a request without an identity on the MCP listener is `403` (§15.7). `wait_for_op` answers `{done, record}` and `get_op` the record, both with the record's `steps` and `created` (**NEW (operation progress)**); `stop_op` the record (`stopping: true`); `get_instance` mirrors the last-operation route; `audit_recent` `{entries, offset, next_offset}` (limit 1–200, default 50, offset ≤ 10000, optional `via=ai`); `create_person` / `send_invite` state `{created, expires_at, note}` (never the link); `invite_person` `{exists, created_by, last_invite, expires_at, pending}` (the caller's own invite; `pending` is evidence, not proof); `my_file_share_password` `{link, note}`; `revoke_ai_access` `{status, instance, companion, user}`; `ai_activity` `{lines}` (default 50); `replace_domain_token` reports `last_replaced` from the audit log; `preview_settings` carries the `plan_hash` `save_settings` needs; `doctor_preview_fix` the `FixPlan` with `touches_data` always present; `check_folder_path` creates nothing. A Hub method an AI actor reaches without a confirmation where one is required answers `409` (defence in depth: a data fix, a widening assignment, an undo, a folder delete, a re-check of a different directory).
- **Refused arguments.** `save_env` refuses secret-looking and Hub-owned names (a client `secret_env`, a generated variable, `[set]`) on the tool path; `add_source` refuses URLs with credentials; `save_hub_settings` refuses turning the admin MCP on (`403`, checked and audited `refused` before its class is judged, so no confirmation is created for it). The global redactor never hides `PORTCULLIS_HOST_*` and the other Hub-set public instance variables for their name.
- **U tools.** The first call answers the form's URL (a URL elicitation, or the text "secrets are never passed through the AI; use <url>"); the tool runs only on a 2026-07-28 retry whose input reply is `accept`. Text-only clients never reach it: they get the link, and an R tool reports the result. Input keys: `portcullis_confirmation` (D) and `portcullis_secret_form` (U). Deep links: `#app/<id>/settings[/<option>]`, `#app/<id>/ai`, `#settings/domains?enroll=<name>[&provider=<p>]`, `#settings/domains?token=<name>`, `#settings/ai?provider=<name>&field=<field>`, `#users/<name>[?password|?invite]`, `#users?create&username=&email=&display_name=&groups=` (Hub; `groups=` carries only plain groups — known and guarding nothing, none while the directory can't be read — and the dialog never ticks an administrator or permission group from a link); `#invite?username=&email=&display_name=` and `#myapps` (people page).
- **Resources and prompts.** `portcullis://docs/<name>` (both scopes), `portcullis://templates` and `portcullis://templates/{id}`, `portcullis://doctor/checks` and the prompts are admin-only. Long operations send no progress notifications (stateless: the twin's `202` body at once, then `wait_for_op`).
- **Canonical JSON.** The Hub's `internal/mcpsdk/canon.go` is a copy of the gate's `internal/canon` (one can't import the other across repos); both keep the same vectors.

### 15.11 Hub API, switches and audit

Admin routes on the Hub listener only (`adminOnly`: no `X-Forwarded-User` `401`, delegates `403`), proxy-secret and CSRF guards, strict JSON bodies ≤ 64 KiB. Every answer shows secrets as `{set, updated_at}` only.

| Route | Body | Does |
|-------|------|------|
| `GET /api/ai/settings` | — | Settings → AI (`gate_present`: the Hub has a parseable gate recipient; without the gate secret file the MCP listener doesn't start either, §15.7; no field reports a client's health: an unhealthy client is left out of the gate file and the People cards without the UI saying so): `{enabled, gate_present, clients: {claude: {offered, admin}, claude_code: {offered, admin}, generic: {offered, admin}}, portcullis_admin, portcullis_people, offline_idle_days, offline_max_days, limits: {resource_rpm, resource_burst, person_rpm, tool_calls_rpm, confirmations_per_hour, mints_per_minute, fanout}, allowed_origins}` |
| `PUT /api/ai/settings` | the same fields but `gate_present` (only what changed) | Save; audited `settings.ai` with the changed keys. Defaults on a new install: `enabled` false, all three clients offered with `admin` off (§8: the admin enables it client by client), both Portcullis MCPs on, 7 / 30 days, the limits of §15.9, no origins. Idle 1–30, max 1–90 days, idle ≤ max; origins `https://<host>[:port]`; else `400` |
| `GET /api/ai/providers` · `POST /api/ai/providers` | provider (§15.12), no secret fields | List `{providers}` (`secrets` per field `{set, updated_at}`, `used_by` `[{instance, group, people, restarts}]`) · add: `201 {provider}` (`ai.provider.add`) |
| `PUT` · `DELETE /api/ai/providers/{name}` | provider · — | Update: `{provider, restarts}` (`ai.provider.update`; `restarts` the enabled AI page instances re-delivered and restarted) · delete (`ai.provider.delete`; `409` naming the instances while any selects it; its secrets removed) |
| `PUT /api/ai/providers/{name}/secrets/{field}` | `{"value": "…"}` or `{"clear": true}` | Set or clear one secret field; answers `{set, updated_at, restarts}`; audited `ai.provider.secret` (`<field> replaced` / `cleared`) |
| `GET /api/instances/{id}/ai` | — | The instance's AI tab: `{unsupported, alternative, master_off, refused, companions: [{name, label, url, kind, identity_mode, upstream, source, modes, mode, enabled, status, last_error, population, credentials, revoking, connections, confirm, never, own_rules, unmatched}], providers, provider_kinds}` (`refused` the reason a switch-on would be refused, e.g. LoA 3; `own_rules` for `app_oauth`; `unmatched` the `app_oauth` leavers to dismiss, §15.5; `providers` and `provider_kinds` (kind → `one`/`many`) only for `ai.chat`; `connections` is always `0`: Keycloak has no per-scope count, and the UI hides it) |
| `PUT /api/instances/{id}/ai` | `{"companions": {"<name>": {"enabled": true, "mode": "read_write"}}, "providers": ["…"]}` (one part per request: both is `400`) | Switch companions on / off, change modes (`ai.enable`, `ai.disable`, `ai.mode` before → after) or, for `ai.chat` templates, set the provider selection (`ai.providers`, detail `<before> -> <after>`); (**NEW (operation progress)**) a companion switch or mode change on an enabled instance (it restarts the app and runs its hooks) runs in the background: `202` `{op_id, op: "ai", instance, poll}` (§11.7; steps `revoke`, `scopes`, `restart`, `hooks`; the warnings in the record's `warnings`); on a disabled instance (state, scopes and gate file only) and for the provider selection it answers `200` with the tab plus `restarts` (true when an enabled instance's project is recreated, §3.2) and `warnings` |
| `POST /api/instances/{id}/ai/revoke` | `{"companion": "…", "user": "…"}` (`user` omitted = everyone) | Revoke one person's or everyone's AI credentials for a companion now (`revoke` / `revoke_all`); answers `{status: "revoked", instance, companion, user}` (`user` `everyone` for all); audited `ai.credential.revoke`. `409` for `identity_headers` (nothing to revoke), and for an `app_oauth` person with no recorded or an unverifiable record |
| `POST /api/instances/{id}/ai/dismiss` | `{"user": "…", "companion": "…"}` (`companion` omitted = every companion) | Dismiss an unmatched `app_oauth` leaver (§15.5) once the admin has deactivated the account in the app; answers `{status: "dismissed", instance, user}`; audited `ai.credential.revoke` `dismissed` |
| `GET /api/ai/activity?instance=&user=&n=` | — | `{lines}`: access-log lines (§15.8), newest first, filtered by instance and user (lowercased) when given; `n` 1–200 when given (else `400`), default 50 |
| `GET /api/directory/audit?via=ai[&include=access]` | — | `via=ai`: the last 100 audit entries with `via: ai` (`[AuditEntry]`); with `include=access`, merged with the last 100 access-log lines as `[{source: "audit"\|"access", time, entry\|line}]`, newest first. `include` without `via=ai`, or another value, is `400` |
| `POST /api/settings/preview` | `{"default_auth_policy": {...}}` | `{warnings}`: what saving that Hub default policy would do, e.g. the instances whose AI support it would switch off (LoA 3); nothing stored. `PUT /api/settings` answers the same `warnings` after the save |

- **Switching on** (`PUT …/ai`, a companion `enabled: true`): refused `409` while the master switch is off, the instance is `deleting` / `restoring`, the template has `ai.unsupported`, the instance's effective policy reaches LoA 3 (`policy.LoA(…) == 3`: "needs a client certificate on every request; AI clients can't present one"), or another container answers the alias (§3.2); `404` unknown companion; `400` a mode outside `modes`. Steps: `revoke_all` (§15.5; failure `502`, nothing changed) → state saved → scope ensured and attached (§8) → gate files → override + `compose up` on an enabled instance (the app restarts) → `on_change`; in the op record they are the steps `revoke`, `scopes`, `restart` and `hooks`. **NEW (operation progress)**: on an enabled instance the `202` comes once the request's refusals (above) are checked and the lock is held, so a `revoke_all` failure is the operation's failure (`status: 502`, nothing changed). A failure after the state save is an `OpError` (op `ai`); the same request re-applies every step. **Stop** (§11.7) puts the companion's previous `{enabled, mode}` back through the same path; credentials the stopped switch revoked are minted again lazily. Switching off reverses it: router, alias and scope removed, `scale: 0`, `revoke_all`, entries removed, `on_change` `enabled: false`.
- **Policy saves.** Saving an instance policy, or the Hub default policy (`/api/settings`) for every inheriting instance, that reaches LoA 3 first switches AI support off on those instances (audited `ai.disable`, detail `policy needs mTLS`); the preview lists them.
- **Master switch.** On: the offered AI clients exist and follow Settings → AI (§8). Off: the gate refuses everything (`enabled: false`), per-app switches are greyed out, People cards are hidden; clients and scopes are kept.
- State: `state.yaml` `ai` (the Settings → AI values and provider definitions; never a secret) and `ai_instances` (per instance id `{companions: {<name>: {enabled, mode}}, providers}`); per-instance AI state is in backups (§11.5).

### 15.12 Model providers and the AI page

An AI page is an instance of a template with `ai.chat` (the `ai-chat` template, LibreChat): an MCP client whose one MCP server is "all my apps" through its `ai_client` (§8, scope `mcp:all`). Its models come from the providers in Settings → AI.

- **Provider:** `{name, label, kind, instance, base_url, region, instance_name, api_version, deployments, models: {fetch, list}, credentials}`. `name` `^[a-z][a-z0-9-]{0,30}$`, unique; `label` single line ≤ 64 (shown to people with the data-egress note "What people send on the AI page, and what their apps return to it, goes to <label>."); `credentials` `admin` (default) or `per_person`; `azure_openai` can't use `per_person` (the AI page can't take each person's own Azure key), so the Hub answers `400` to an add or an update that sets it. Per kind:

    | `kind` | Fields | Secret fields |
    |--------|--------|---------------|
    | `litellm` | `instance` (an installed LiteLLM instance; the Hub fills `base_url` from it) | `key` |
    | `openai_compatible` | `base_url` (required) | `key` (optional: Ollama needs none) |
    | `anthropic`, `openai`, `google` | `base_url` (optional) | `key` |
    | `bedrock` | `region` | `access_key_id`, `secret_access_key` |
    | `azure_openai` | `instance_name` or `base_url`, `api_version`, `deployments` | `key` |

    The `litellm` kind is tied to the LiteLLM template by name, an exception to "no template id in Hub code" (ruling T9): its `instance` must be an instance of the template `litellm`, and `base_url` is `https://` + the host of that instance's router `litellm`.

    `models.fetch` only for `litellm`, `openai_compatible`, `openai`. A kind is offered only while an installed `ai.chat` template declares it (`400` "no installed AI page supports kind <k>" otherwise).
- **Secrets are write-only.** Entered in `type=password` inputs, cleared on submit, never rendered back. Stored only in `<data>/ai/provider-secrets.json` (0600, atomic; the Hub's secret store for providers) and in the `.env` of each AI page instance that selected the provider, single-quoted, as **`PORTCULLIS_AI_PROVIDER_<NAME>_<FIELD>`** (`<NAME>` and `<FIELD>` upper-cased, `-` → `_`). Never in `state.yaml`, `ai-providers.json`, logs, the audit, op records, errors, answers or tool results. A provider whose variable for any field would equal another provider's (`x` + `secret_access_key` vs `x-secret-access` + `key`) is a `409`.
    - **Delivery to the app.** The Hub's override adds `environment: {<VAR>: ${<VAR>}}` for each selected provider variable to the `ai.chat.env.service` only (§3.2); templates never reference the variables.
    - **Masked and blanked.** Expert Env shows a set provider variable as `[set]` and `SaveEnv` treats them as Hub-set (a changed value is `400`); backups blank them by name; a restore and a restore-as rewrite them from the store for that instance's own selection only; every provider secret value is in the redaction set (§15.10).
- **Selection** per AI page instance: `PUT /api/instances/{id}/ai` `providers` (§15.11). An instance with no selection yet gets the default at create and at its first enable: every provider whose kind the template supports, and for a `one` kind the first by name; from then on the selection is the admin's (it never follows new providers, and an emptied one stays empty); two providers of a `one` kind, or a kind the template doesn't declare, is a `400`. A change re-delivers `ai-providers.json` (§3.2) and the env and restarts that instance only. A provider update, a secret change and a hostname change of the LiteLLM instance a provider points at restart every enabled AI page that renders it (named in `restarts`); every affected page's `.env` is rewritten at once, disabled ones included. Deleting a LiteLLM instance a provider points at is `409`. Everyone who can open an instance can use every provider selected for it; to give a group other providers, the admin adds another `ai-chat` instance with its own access group.
- Hub Settings → AI shows, per provider, the instances using it with their access groups and population counts, and the reachability note "Claude desktop and claude.ai connect from Anthropic's servers (160.79.104.0/21): `auth.<domain>` and every app host must be reachable from the internet."
