# Multiple servers (one primary, worker servers) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let one primary Portcullis (its Hub) place app instances on worker servers. The worker dials out over WireGuard, and every request still enters through the primary's Traefik, forward-auth, group-gate and TLS tier. Admins add, watch, move and revoke servers from the Hub, and the agent API is the only remote access to an engine.

**Architecture:**
- **Core.** The `wg` service gains its third role, **link**: a WireGuard server whose netstack has zero listeners. It is an HTTP CONNECT dialer on two internal Docker networks: the Hub's control path to `<worker>:7443`, and the relays' data path to `<worker>:7000`, gated by a per-instance bearer. It reads `link.json` v1 from a new `link_doc` volume.
- **Hub.** The Hub writes `link.json`, enrols and pins workers (a new Vault intermediate `pki_node`, signed through enroll), and talks to a worker's **`portcullis-agent`** through a new `internal/runtime/agent` backend of the Kubernetes plan's `runtime.Instances` interface (the spec's `Engine`).
- **Relays on the primary.** A placed instance's project on the primary contains only **`portcullis-relay`** services. They carry the Hub's rendered Traefik labels unchanged and filter Portcullis cookies.
- **Worker.** The worker runs `agent` plus `socket-proxy-agent` from core's `docker-compose.worker.yml`, installed with `./portcullis worker join`.

**Tech Stack:**
- Go 1.27:
  - Hub, `cmd/portcullis-agent`, `cmd/portcullis-relay`; core `wg`, `enroll`;
  - `golang.zx2c4.com/wireguard` + `tun/netstack` (the wg module's pins), `crypto/tls`, `crypto/x509`, `net/http/httputil.ReverseProxy`;
  - `github.com/prometheus/client_golang`, `github.com/compose-spec/compose-go/v2` (already in the Hub), `github.com/hashicorp/vault/api` (already in enroll).
- bash 3.2 + jq (core CLI).
- Python 3 (templates validator).
- GitHub Actions (a pinned `docker:dind`).
- Zensical.

**Spec:** `/Volumes/workspace/portcullis/portcullis-hub/docs/superpowers/specs/2026-11-13-multi-server-design.md` (binding). The §14 open questions take their defaults:
- Q1: WireGuard alone protects data; control is mTLS inside WireGuard.
- Q2: accept the hop. Task 21 measures throughput, and under 200 Mbit/s it is noted as a follow-up.
- Q3: 7 days.
- Q4: filter always; a template that breaks gets `placement: primary_only`.

Related plans (structure copied): `2026-11-13-vpn-only-access.md` (the `wg` service, `tunnel` package, `vpn_doc` volume pattern), `2026-11-13-rootless-podman.md` (runtime selection, socket proxies) and `2026-11-14-kubernetes.md` (`internal/runtime.Instances`, `RuntimeCompat`, `kubeDeliverer`).

## Global Constraints

- **Base: Kubernetes (`kube1`) must be merged to `main` in all four repos first** (assistant's call). This plan's `Engine` *is* the Kubernetes plan's `internal/runtime.Instances` (Hub `internal/runtime/runtime.go` on `kube1`), and the agent backend is a third implementation next to `docker` and `kube`. If `kube1` isn't merged when execution starts, stop and wait. Never base on `kube1`, and never re-create a second engine interface. At execution, re-read every file this plan names on the merged main. Names below are from Hub `origin/kube1` `f9fd020` and core/templates/docs `origin/main` (core `166633c`, templates `df900fc`, docs `1900fb6`). Where the merge renamed something, follow main and note it in the task's commit.
- **Branches and worktrees:**
  - Branch `ms1` in core, Hub, templates and docs, at `/Volumes/workspace/portcullis/wt-ms1/{portcullis,portcullis-hub,portcullis-templates,portcullis-docs}`. Create each with `git -C <main checkout> worktree add -b ms1 <path> origin/main`, and record the base SHAs in Task 1's commit message.
  - Main checkouts may hold other people's work: never edit, stash or commit there.
- **Contract first.** Task 1 lands on docs `ms1` before any code task. After Task 1 and Task 20, resync the Hub copies with `PORTCULLIS_DOCS_DIR=/Volumes/workspace/portcullis/wt-ms1/portcullis-docs web/docs/sync.sh` in the Hub worktree, then commit `web/docs`.
- **Project rules:**
  - **Secrets never on argv, in logs or in the audit.** This covers join codes, the bootstrap private key, the enrolment secret, relay tokens, private keys and CSRs. `./portcullis worker join` reads the code from **stdin** (or an interactive no-echo prompt), never from an argument: it refuses one (exit 2, "the join code is a secret: paste it when asked, or pipe it in"). `tests/test_cli.sh`'s argv grep covers `worker join`. The Hub shows a join code once, in one response with `Cache-Control: no-store`. It is never in an op record, the audit, a log line or an MCP transcript.
  - **Fail closed.** Everything a worker sends is untrusted input. The Hub refuses rather than guessing: an unknown server, an unready server, an unverifiable cert, a skewed agent version, an unreadable `/info`, a failed pre-pull, or an unknown placement. Each item in "Fail closed" below gets a test in its task.
  - **Never weaken access control.** No setting, placement or server state can remove or reorder `portcullis-auth` / `portcullis-groups` (or any rendered middleware) on an instance's routers. Relays carry exactly the labels `desiredRouteLabelsLocked` / the override render today. A worker never gets a Traefik, an oauth2-proxy, group-gate, a session cookie, the proxy secret or any core credential. The policy file stays **v7**, unchanged.
  - **Identity = the LLDAP username.** Audit actors and server owners are usernames; a node certificate never names a person.
  - **No migration or back-compat code.** `link.json` v1 and agent API v1 are new, with no reader of any other version. The test server is fixed by hand.
  - **Prefer mature libraries** (Tech Stack). No hand-rolled WireGuard, TLS, X.509, HTTP CONNECT or tar code: use `archive/tar` with the Hub's existing `checkVolumeEntry` rules.
  - **No private identifiers in public repos:** no host names, IPs, account ids or cloud profiles of the test servers in code, docs or commits (Task 21 keeps them in the ledger only).
  - **CI size:** core `ci.yml` stays **≤ 450,000 bytes** (`tests/lint_ci_size.sh`; it is 320,094 bytes on `kube1`). Every step longer than ~15 lines goes to `.github/ci/e2e-servers-<step>.sh`.
  - **Test server:** always `ACME_STAGING=true` (memory). Workers never get ACME or DNS credentials.
- **Never on the network:** a Docker/Podman socket or the Engine API. On a worker, `${PORTCULLIS_ENGINE_SOCKET:-/var/run/docker.sock}:/var/run/docker.sock:ro` is mounted only into `socket-proxy-agent`. The core literal count in `tests/test_cli.sh` becomes "twice in `docker-compose.yml`, once in `docker-compose.worker.yml`".
- **Fail closed (each item below gets a test in its task):**
  - `link_doc/link.json` is missing, unparsable, of another version, or has duplicate keys/addresses → link has **no peers** and refuses every CONNECT (Task 15).
  - A CONNECT on `portcullis-link` to anything but `<ready or enrolling peer ip>:7443` → 403. A CONNECT on `portcullis-link-data` without a bearer whose sha256 is in `link.json`, or naming another instance than the token's, → 403 (Task 15).
  - The agent refuses any control request whose client certificate isn't `hub.control` (or `link.control` for `GET /v1/metrics` only) under the pinned `pki_node` CA, and any data connection whose source isn't `10.214.0.1` (Task 5).
  - The Hub refuses a worker whose certificate SPKI or serial differs from state (`server_identity_mismatch`, every call 502, server state `offline`) (Task 8).
  - An agent outside {same minor, previous minor} → every lifecycle call 409 `server_agent_incompatible` (Task 8).
  - A server not `ready` → every lifecycle operation of its instances 409 "server <name> is offline" (or "… is revoked"). Its relays answer the static 503 page (Tasks 7, 10).
  - Placement refusals are 409 before anything is created (Task 10).
  - A failed move step before the switch restarts the source. Two routed copies never exist (Task 11).
  - `HUB_LINK_DOC_DIR` unset, or link's status file missing → Servers is "off" (503 "run ./portcullis link init on the primary"). Primary instances are unaffected (Task 9).
- **TDD everywhere.** Write the failing test, see it fail, implement, see it pass, commit. Gates:
  - Core: `bash tests/test_shell_libs.sh && bash tests/test_cli.sh && shellcheck -S warning portcullis scripts/lib/*.sh tests/*.sh .github/ci/*.sh && actionlint && bash tests/lint_ci_size.sh`, plus `cd wg && gofmt -l . && go vet ./... && go test -race ./...` and the same in `enroll`.
  - Hub: `go vet ./... && go test -race ./... && gofmt -l .` (gofmt prints nothing).
  - Templates: `python3 tests/validate.py && python3 tests/test_validate.py`.
  - Docs: `python3 scripts/check-lists.py && bash scripts/check-branding.sh && zensical build --strict --clean`.
- **CI:**
  - Core: `gh workflow run ci.yml --ref ms1 -f jobs=<names>`; only the controller dispatches core CI on `ms1` (the concurrency group cancels). Task 19 adds `e2e-servers` and `e2e-servers-podman` to ci.yml and to the `workflow_dispatch` description list.
  - Hub: `gh workflow run build.yml --ref ms1`. Templates: lint.yml and Test Apps on `ms1`.
  - Run your own background watcher on every dispatched run (memory).
- **Merges** (spec order docs → Hub → templates → core):
  - Through detached worktrees: `git worktree add --detach /tmp/merge-<repo> origin/main` → `git merge --no-ff origin/ms1 -m "merge ms1: multiple servers"` → push → `git worktree remove`.
  - There is **no outage window**: a Hub without `HUB_LINK_DOC_DIR` simply has Servers off. Still merge core right after templates. After the Hub merge, run `gh workflow run build.yml --ref main -f compare_ref=ms1` and wait for `edge` of all three images (hub, agent, relay).
  - Finally delete every `ms1` branch (local and remote), every worktree and `/tmp/merge-*` (memory: branches mainlined).
- **Values from the spec (verbatim):**
  - link:
    - `${PORTCULLIS_LINK_PORT:-51821}/udp`, `${PORTCULLIS_LINK_SUBNET:-10.214.0.0/24}`, link `.1`, workers `.10`–`.250`, MTU **1380**, AllowedIPs = the peer's /32, keepalive **25 s** set on the worker.
    - Key `secrets/wg/link.key`, compose profile `wg`, uid 10006, no capabilities, read-only.
  - Agent: uid **10008**, read-only, no capabilities, `no-new-privileges`; control `:7443` (mTLS), data `:7000` (from `10.214.0.1` only), both inside its netstack only. Image `ghcr.io/porelli/portcullis-agent`.
  - Relay image `ghcr.io/porelli/portcullis-relay`.
  - `pki_node` roles:
    - `node-worker` CN/SAN `<server-id>.node.portcullis.internal`, client+server, TTL **30 d**;
    - `node-control` CN `hub.control`, client;
    - `node-link` CN `link.control`, client.
    - Renewal at **⅓** remaining life.
  - Join code: valid **15 min**, single use, a **256-bit** secret (hash stored), server id `^[a-z][a-z0-9-]{0,30}$`.
  - Offline = **3** missed **30 s** polls or no handshake for **3 min**.
  - Doctor: `server_cert_expiring` Warning ≤ **7 d**, `server_disk_low` Warning < **10 %**, `server_no_recent_backup` **14 d**, `server_move_leftover` after **7 d**.
  - Alerts: `PortcullisServerDown` (no handshake for **5 min**), `PortcullisServerDiskLow`, `PortcullisServerContainerUnhealthy`.
  - Scheduled backups: off / daily / weekly at an hour, default off, keep the last **3** scheduled archives per instance; manual archives are never pruned.
  - Version skew: the same or the previous minor version.
  - Copy:
    - relay 503: "<app> runs on <server>, which is offline";
    - move with folders: "unbind folders first; folder contents aren't moved";
    - lifecycle while offline: "server <name> is offline".
- **Values this plan adds (assistant's calls, binding for every task):**
  - **`link.json` lives on a new named volume `link_doc`**, not in `hub_data` (spec defect 1: core's rule is that `wg` never mounts `hub_data`). The Hub mounts it rw at `/link-doc` (`HUB_LINK_DOC_DIR=/link-doc`, `HUB_LINK_DOC_GID=10009`); `wg` mounts it ro with `group_add` += `10009`. Ownership: `volume_own link_doc 10001:10009 2750`, file 0640, `CT_GID_LINK_DOC=10009`. It is not backed up: the Hub rewrites it from `state.yaml` at start (primary DR still works, spec §9).
  - Networks (all internal, fixed IPAM, added to `vpn_reserved_ranges` and `network_check`):
    - `portcullis-link`: `${PORTCULLIS_LINK_NET:-172.31.254.80/29}`, Hub `${PORTCULLIS_LINK_HUB_IP:-172.31.254.82}`, wg `${PORTCULLIS_LINK_WG_IP:-172.31.254.83}`, members exactly hub + wg.
    - `portcullis-link-data`: `${PORTCULLIS_LINK_DATA_NET:-172.31.254.128/26}`, wg `${PORTCULLIS_LINK_DATA_WG_IP:-172.31.254.130}`, dynamic range `${PORTCULLIS_LINK_DATA_IP_RANGE:-172.31.254.160/27}`, members wg + relays only.
  - link's CONNECT listeners (plain HTTP on those Docker networks, never in the netstack):
    - control `<PORTCULLIS_LINK_WG_IP>:3128`;
    - data `<PORTCULLIS_LINK_DATA_WG_IP>:3129`. Relays CONNECT to the pseudo-target `<instance>.<service>.relay:<port>` with `Proxy-Authorization: Bearer <token>`. link checks the token's instance and **writes the data preamble itself** (`{"instance","service","port"}\n`), so a relay can't name another instance (spec defect 5).
  - link status `wg_data/status.json` gains `link{ok, error, peers[{id, ip, handshake, rx, tx}]}`. The Hub reads it (`HUB_VPN_STATUS_FILE`, already mounted) for handshake ages.
  - **`node-link` certificate** (spec defect 4): `./portcullis link init` and every `up` / `upgrade` sign link's CSR directly with Vault `pki_node/sign/node-link`. The CLI holds the root token, as `pki setup` does. TTL **90 d**, renewed at ⅓. The key is `secrets/wg/link-tls.key` (generated in place by `wg genkey-tls`), the cert `secrets/wg/link-tls.crt`. The Hub never holds link's key. **`node-control`**: the Hub makes its key at `<data>/nodes/control.key` (0600), has the CSR signed by enroll, TTL 30 d, renewed at ⅓.
  - enroll's internal listener (same `:8444`, same bearer as the invites): `POST /internal/nodes/sign {"role","common_name","csr"}` → 201 `{"certificate","serial","not_after","ca"}` and `POST /internal/nodes/revoke {"serial"}` → 204. Allowed roles are only `node-worker` and `node-control`, and the CN must match the role's pattern. The policy `enroll.hcl` gains `pki_node/sign/node-worker`, `pki_node/sign/node-control`, `pki_node/revoke` and `pki_node/crl/rotate`, never `node-link`.
  - **Enrolment proof bound to the TLS channel** (spec defect 11): `HMAC-SHA256(secret, "portcullis-enrol-v1" || nonce || server_id || sha256(agent enrolling-cert SPKI))`.
  - **Join code format:** `pcj1.` + base64url (no padding) of the JSON `{"v":1,"endpoint":"<d>:<port>","link_pub","server_id","tunnel_ip","bootstrap_key","ca_sha256","secret","proxy_subnet","traefik_ip"}`. The agent creates the worker's `portcullis-proxy` from `proxy_subnet` and pins itself at `traefik_ip`.
  - The agent's data dir is the worker checkout's `./worker-data`, bind-mounted at **the same absolute host path** (`${PORTCULLIS_WORKER_DATA:?}`, written by `worker join` as `$PWD/worker-data`). Bundles go to `<data>/projects/<id>/`. Env, override and user-override files are 0600; template files and `appfiles/` keep the modes the Hub's bundle manifest gives (the primary's modes; spec defect 12: "0600" would make template binds unreadable to app containers). The agent runs `user: 10008:10008` with `group_add: ["10001"]`, so appfiles keep group 10001 as on the primary.
  - **Folder roots are the worker host's** (spec defect 6): `.env` `PORTCULLIS_WORKER_BIND_ROOTS` (default `/srv:/mnt:/media`, the `HUB_OVERRIDE_BIND_ROOTS` default), reported in `/info`, enforced by the agent and shown read-only in the Hub. The **Local networks** of a worker are a Hub setting per server (default = the Hub's default Local networks).
  - `PORTCULLIS_ROLE=primary|worker` in `.env` (`init` writes `primary`; `worker join` writes `worker`; every other command but `worker …`, `help`, `version` and `status` refuses on a worker: "this host is a Portcullis worker: use ./portcullis worker …").
  - Images: core `.env` / compose `AGENT_IMAGE` (default `ghcr.io/porelli/portcullis-agent:edge`) and `RELAY_IMAGE` (default `ghcr.io/porelli/portcullis-relay:edge`, passed to the Hub as `HUB_RELAY_IMAGE`). A release pins both by digest (`release.yml` preflight, like `HUB_IMAGE`).
  - **Primary-only templates** (detected, spec §7, plus what the spec missed):
    - core volumes (`hub_secrets`, `hub_data`, any `CORE_SERVICE_NAMES` volume);
    - `traefik.tcp.*` / `traefik.udp.*` labels;
    - a `person_secret` option;
    - **an `ai:` block or companion** (mcp-gate reaches companions on `portcullis-mcp-<id>--*`; spec defect 3);
    - **a `vpn:` block** (spec §8);
    - `host-gateway` in `extra_hosts`;
    - an absolute bind outside the folder roots;
    - `placement: primary_only` in the manifest.
  - The primary runtime must be Docker or Podman for Servers (assistant's call). On `CONTAINER_RUNTIME=kubernetes`, Servers is off: 409 "servers need a Docker or Podman primary". `worker join` refuses `--runtime kubernetes` (Kubernetes workers are a non-goal).
  - Reserved server id: `primary` (spec §7 lists it as the local engine). Tunnel IPs are allocated lowest-free from `.10`, and a revoked server's IP is quarantined 7 days.
  - Move state: `Instance.State = "moving"` with `Instance.Move = {from, to, archive, started_at, phase}`. The source volumes are kept under `Instance.MovedFrom = {server, at}` until undo or removal. Orphaned instances have `Instance.State = "orphaned"`.
  - Agent API additions beyond spec §5 (narrow, same scope rules): `PUT /v1/projects/{id}/appfiles/{name}` (a data file delivery, written atomically in its directory, as `deliver_files.go`), `PUT /v1/network` (enrol: the `portcullis-proxy` parameters, once), `POST /v1/leave` (Remove server), `GET /v1/enrol/nonce` and `POST /v1/enrol` (enrolling mode only).
  - The relay token is 32 random bytes, base64url. It is written to the relay project's env file (`PORTCULLIS_RELAY_TOKEN`, 0600 like every instance env, never in state.yaml); `link.json` holds its sha256 hex. It rotates on revoke and on move.

## Review Focus

1. **The worker's clock is off.** A join a minute after the code is shown must still work if the worker's clock is 10 min fast, and a TLS handshake that fails on validity must say so. The Hub judges code expiry by its own clock only. Vault backdates `not_before` by 30 s, and the agent verifies the Hub cert with a tolerance of ±5 min. Beyond that, enrolment fails with "the worker's clock is <n> off; fix its time (NTP)". Pinned by `TestEnrolReportsClockSkew` (Task 9) and `TestAgentClockTolerance` (Task 5).
2. **The Hub restarts in the middle of a move** (after the source backup, before the switch). On start, an instance in `moving` whose phase is before `switch` must route to the source again and start it, and leave the target's half-restored volumes to the `server_move_leftover` cleanup. It must never route to the target and never leave the instance stopped. Pinned by `TestMoveRecoveryAfterHubRestart` (Task 11).
3. **Cookie spellings.** `Domain=.app.<d>`, `Domain=APP.<d>`, `Domain=<d>`, `Domain=app.<d>.` (trailing dot), several `Set-Cookie` headers in one response, `__Host-` / `__Secure-` prefixes, and a request `Cookie:` header carrying `_oauth2_proxy_0`, `_oauth2_proxy_csrf_x` and `__Host-portcullis_ext-2`. Only host-only cookies or `Domain` equal (case-folded, trailing dot stripped) to the request host survive; every Portcullis cookie is deleted in the request. Pinned by `TestCookieFilterDomainVariants` and `TestRequestCookiesStripped` (Task 7).
4. **Long-lived streams at revocation.** An open WebSocket or long download through relay → link → agent must end within the reload when the server is revoked or the instance's token rotates, not at the next reconnect. Pinned by `TestRevokeClosesOpenStreams` (Task 15) and the e2e `revoke_cuts_websocket` (Task 19).
5. **Hostile bundle and archive entries.** A bundle tar with a symlink, a hardlink, `..`, an absolute name, a duplicate entry, a device node, or a file over the cap; and a helper archive from the agent with the same. Both sides refuse the whole thing, and nothing is written outside `<data>/projects/<id>/` or the staging dir. Pinned by `TestBundleRefusesLinksAndEscapes` (Task 6) and `TestAgentArchiveEntriesChecked` (Task 8).

---

## File structure

**Docs (`wt-ms1/portcullis-docs`):** `docs/guides/integration-contracts.md` (§2, §3, §5, §6, §11, §14.5, §15, §16, new §17); `docs/operations/servers.md` (new) + `.nav.yml`; `hardening.md`, `backups.md`, `monitoring.md`, `cli.md`, `hub.md`, `testing.md`, `vpn.md` (link role cross-link); `docs/guides/manifest-reference.md` (`placement`); `includes/abbreviations.md` (primary, worker, link, relay, agent).

**Hub (`wt-ms1/portcullis-hub`)**

| File | Responsibility |
|---|---|
| `internal/servers/` (new, pure: `id.go`, `alloc.go`, `joincode.go`, `proof.go`, `version.go`) | ids, tunnel IP allocation, join code encode/decode, enrolment HMAC, version skew |
| `internal/linkdoc/` (new, pure: `doc.go`, `testdata/link_json_vectors.json`) | `link.json` v1 types, writer, strict reader (core keeps a byte copy of the vectors) |
| `internal/agentapi/` (new: `types.go`, `bundle.go`, `scope.go`, `limits.go`, `testdata/bundle_vectors.json`) | API v1 wire types, bundle manifest + tar rules, the §5 scope rules, size caps, shared by agent and Hub |
| `internal/agent/` (new: `tunnel.go`, `identity.go`, `enrol.go`, `server.go`, `projects.go`, `helpers.go`, `data.go`, `metrics.go`) + `cmd/portcullis-agent/main.go` | the worker agent |
| `internal/relay/` (new: `proxy.go`, `cookies.go`, `offline.go`) + `cmd/portcullis-relay/main.go` | the relay |
| `Dockerfile.agent`, `Dockerfile.relay` (new); `.github/workflows/build.yml` | images, matrix build + publish |
| `internal/runtime/agent/` (new: `backend.go`, `client.go`, `deliver.go`) | `runtime.Instances` over the agent API (+ `DeliverFile`) |
| `internal/state/servers.go` (new); `internal/state/state.go` (`Instance.Server`, `Move`, `MovedFrom`, `AppState.Servers`, `PrimaryBackups`) | servers state |
| `internal/hub/servers.go`, `servers_enrol.go`, `servers_poll.go`, `servers_revoke.go`, `servers_link.go`, `nodecerts.go` (new) | registry, enrolment, renewal, polling, revocation, `link.json` publishing, the control cert |
| `internal/hub/rtfor.go`, `placement.go`, `relays.go`, `move.go`, `backup_schedule.go` (new); `lifecycle.go`, `override.go`, `prepareUp` callers, `backup.go`, `restore.go`, `reconcile.go`, `kube.go` (`kubeDeliverer` → `fileDeliverer`), `localnet.go`, `folders.go` | per-instance runtime, placement, relays, moves, schedules |
| `internal/templates/placement.go` (new), `testdata/placement_vectors.json` (new), `manifest.go` (`Placement`) | primary-only detection |
| `internal/doctor/servers.go` (new); `internal/hub/doctor_servers.go` (new) | the 8 kinds |
| `internal/httpapi/servers.go`, `mcptools_servers.go` (new); `server.go`, parity tests | API, MCP |
| `web/servers.html`, `web/servers.js` (new); `web/index.html`, `web/apps.js`, `web/folders.js`, `web/web.go` | Settings → Servers, Runs on, Move… |
| `cmd/hub/main.go` | wiring (`HUB_LINK_DOC_DIR`, `HUB_LINK_DOC_GID`, `HUB_LINK_PROXY`, `HUB_RELAY_IMAGE`; enroll reached through the existing invite client) |

**Templates (`wt-ms1/portcullis-templates`):** `schema/manifest.schema.json`, `tests/validate.py`, `tests/test_validate.py`, `tests/placement_vectors.json` (byte copy), `CONTRIBUTING.md`, `CLAUDE.md`.

**Core (`wt-ms1/portcullis`)**

| File | Responsibility |
|---|---|
| `wg/internal/linkdoc/`, `wg/internal/link/` (new); `wg/main.go`, `wg/internal/status/status.go` | link role, CONNECT dialers, metrics, `genkey-tls`, `link-csr` |
| `tests/link_json_vectors.json` (byte copy) | shared vectors |
| `enroll/nodes.go`, `enroll/nodes_test.go` (new); `enroll/invite.go` (routes); `vault/policies/enroll.hcl` | `/internal/nodes/sign|revoke` |
| `scripts/lib/pki.sh` (`_pki_create_node_ca`, `_pki_write_node_roles`), `scripts/lib/link.sh` (new), `scripts/lib/worker.sh` (new), `network.sh`, `common.sh`, `status.sh`, `stack.sh`, `portcullis` | `link init`, `worker …`, networks, core.env, status, role guard |
| `docker-compose.yml`, `docker-compose.podman.yml`, `docker-compose.podman-selinux.yml`, `docker-compose.worker.yml` (new) | link wiring; the worker stack |
| `monitoring/prometheus/{prometheus.yml,alerts.yml,tests/alerts_test.yml}` | job `link`, 3 alerts |
| `.github/workflows/ci.yml`, `.github/ci/e2e-servers-*.sh` (new), `tests/e2e/e2e_servers.py` (new) | CI |
| `CLAUDE.md`, `.env.example`, `CHANGELOG.md`, `.github/workflows/release.yml` | rules, pins |

---

### Task 1: Contract (docs, first)

**Files:**
- Modify: `docs/guides/integration-contracts.md` (§2, §3, §5, §6, §11, §11.5, §11.7, §14.5, §15, §16, new §17)
- Modify (Hub): `web/docs/*` via `sync.sh`

**Interfaces — Produces (binding for Tasks 2–19):**
- **§2:** the reserved core-only variables `PORTCULLIS_LINK_*`, `PORTCULLIS_ROLE`, `PORTCULLIS_WORKER_*`, `AGENT_IMAGE` and `RELAY_IMAGE`; the validator refuses them in templates.
- **§3 "Worker-placeable templates":**
  - the primary-only list in Global Constraints, with the refusal reasons (the strings of Task 3);
  - the manifest field `placement: primary_only | any` (default `any`);
  - "cookies must be host-only; the relay drops the rest".
- **§5:**
  - relays carry the rendered labels;
  - the cookie filter (request: delete `_oauth2_proxy`, `_oauth2_proxy_*`, `__Host-portcullis_ext`, `__Host-portcullis_ext-*` and the oauth2-proxy CSRF cookies `*_csrf*`; response: drop any `Set-Cookie` with one of those names or a `Domain` other than the request host);
  - the 503 page text.
- **§6:** "On a worker the socket rule holds for `socket-proxy-agent`; the agent API (§17) is the only remote access to an engine; no Engine API on any network."
- **§11:**
  - instance `server` (`""` = primary);
  - states `moving`, `orphaned`; derived view state `unreachable`;
  - placement refusals (409);
  - `POST /api/instances/{id}/move {server}` (op `move`) and `POST /api/instances/{id}/move/undo`;
  - `DELETE /api/instances/{id}/move-leftover`.
- **§11.5:** backup reason `move` and `scheduled`; archives of worker instances live in the primary's `hub_data/backups/<id>/`; scheduled retention 3.
- **§11.7 audit kinds:** `server.add`, `server.enrolled`, `server.enrol_refused`, `server.revoked`, `server.removed`, `server.renewed`, `server.settings`, `instance.move`, `instance.move_undo`, `instance.move_leftover_removed`, `instance.forget`.
- **§14.5:** the 8 doctor kinds with severities (spec §10).
- **§15:** `list_servers`, `get_server` (R), `move_instance`, `set_backup_schedule` (D, per-call confirmation). Never a join code or a revocation.
- **§16:** the link role is the third role of `wg`: separate key, port, subnet, peers, no forwarding between roles; a link peer has no route to `vpnsecure`.
- **New §17 "Servers":**
  - topology;
  - `link_doc` + `link.json` v1:

    ```json
    {"version":1,"written_at":"<RFC3339>","subnet":"10.214.0.0/24","peers":[{"id","public_key","ip","state":"enrolling|ready"}],"relays":[{"token_sha256","instance","server"}]}
    ```

    with these rules: unknown/duplicate keys refused, ip inside subnet in `.10–.250`, unique ids/keys/ips, `relays[].server` must be a `ready` peer, ≤ 250 peers and ≤ 4096 relays; anything invalid → no peers;
  - the CONNECT rules (Global Constraints) and "the netstack has zero listeners";
  - agent API v1: the spec §5 table plus the additions in Global Constraints, the caps (`/info` ≤ 64 KiB, JSON ≤ 1 MiB, logs ≤ 4 MiB, ndjson line ≤ 64 KiB, bundle ≤ 64 MiB, helper archive = the Hub's existing restore caps), the error shape `{"error"}` ≤ 200 chars;
  - `pki_node` roles, enroll's `/internal/nodes/*`, the control/link certs;
  - the join code format, the enrolment steps and HMAC input;
  - renewal at ⅓, revocation steps 1–5, removal, version skew;
  - the worker's `.env` keys.
- **§1:** a "Multiple servers (NEW)" entry: no policy-file change (v7), `vpn.json` stays v2, new `link.json` v1 (Hub ⇄ core lockstep), agent API v1 (Hub ⇄ agent, same or previous minor).

- [ ] **Step 1:** Create the four `ms1` worktrees, then write the sections in the contract's style ("NEW (multiple servers)" markers).
- [ ] **Step 2:** Run the docs gate. Expected: exit 0.
- [ ] **Step 3:** Commit (`docs: contract for multiple servers (link role, link.json v1, relays, agent API v1, pki_node, placement, move, doctor kinds, MCP tools)`) with the base SHAs; push `ms1`.
- [ ] **Step 4:** Resync Hub `web/docs`, commit (`docs: sync contract`), push.

---

## Hub stream (Tasks 2–13)

### Task 2: Hub pure packages: `internal/servers`, `internal/linkdoc`

**Files:**
- Create: `internal/servers/{id.go,alloc.go,joincode.go,proof.go,version.go}` + `_test.go` each
- Create: `internal/linkdoc/doc.go`, `doc_test.go`, `testdata/link_json_vectors.json`

**Interfaces — Produces:**

```go
package servers
var IDRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)
func ValidID(id string) error // reserved "primary" → error "primary is the local server's name"
func AllocIP(subnet netip.Prefix, used []netip.Addr, quarantined map[netip.Addr]time.Time, now time.Time) (netip.Addr, error) // lowest free in .10–.250
type JoinCode struct{ V int; Endpoint, LinkPub, ServerID string; TunnelIP netip.Addr; BootstrapKey, CASHA256, Secret string; ProxySubnet netip.Prefix; TraefikIP netip.Addr }
func (c JoinCode) Encode() string            // "pcj1." + base64url(JSON)
func DecodeJoinCode(s string) (JoinCode, error) // strict: unknown keys, wrong prefix, v != 1 refused
func Proof(secret []byte, nonce []byte, serverID string, agentSPKI []byte) []byte
func VerifyProof(secret, nonce []byte, serverID string, agentSPKI, got []byte) bool // hmac.Equal
func Compatible(hub, agent string) bool     // same major, agent minor ∈ {hub, hub-1}
```

```go
package linkdoc
type Peer struct{ ID, PublicKey string; IP netip.Addr; State string }
type Relay struct{ TokenSHA256, Instance, Server string }
type Doc struct{ Version int; WrittenAt time.Time; Subnet netip.Prefix; Peers []Peer; Relays []Relay }
func Parse(b []byte) (*Doc, error) // the §17 rules
func Write(dir string, gid int, d *Doc) error // fsutil.WriteFileAtomic 0640, chgrp gid
```

- [ ] **Step 1: Write the failing tests.**
  - `TestValidIDReservesPrimary`.
  - `TestAllocIPSkipsQuarantine` (the quarantined `.10` is skipped until 7 d pass).
  - `TestJoinCodeRoundTripAndStrict` (a round trip; plus `pcj2.`, an extra key, bad base64 and a missing secret are each refused).
  - `TestProofBindsSPKI` (another SPKI fails).
  - `TestCompatible` (`1.4`/`1.4` ok, `1.4`/`1.3` ok, `1.4`/`1.2` no, `1.4`/`1.5` no, `2.0`/`1.9` no).
  - `TestLinkDocVectors` reads `testdata/link_json_vectors.json`, ≥ 30 cases with `{name, doc, valid, error}` covering every §17 rule.
- [ ] **Step 2:** Run `go test ./internal/servers/... ./internal/linkdoc/...`. Expected: FAIL (packages missing).
- [ ] **Step 3:** Implement. Use `encoding/json` `DisallowUnknownFields` plus a duplicate-key pre-scan (the same approach as `internal/vpn` `doc.go`).
- [ ] **Step 4:** Run the Hub gate. Expected: PASS.
- [ ] **Step 5:** Commit (`hub: servers ids, tunnel allocation, join codes, enrolment proof, link.json v1`).

### Task 3: Hub placement rules (primary-only detection)

**Files:**
- Create: `internal/templates/placement.go`, `placement_test.go`, `testdata/placement_vectors.json`
- Modify: `internal/templates/manifest.go` (field `Placement string` `yaml:"placement,omitempty"`, values `""|any|primary_only`)

**Interfaces — Produces:** `func Placement(compose []byte, m Manifest, env map[string]string, bindRoots []string) (primaryOnly bool, reasons []string)`. Reason strings (shared with validate.py, exact):
- `mounts the core volume <v>`
- `has a Traefik TCP/UDP router (<label>)`
- `has a per-person secret option (<key>)`
- `has AI companions (mcp-gate reaches them on the primary)`
- `is a VPN provider (vpn: block)`
- `uses host-gateway (<service>)`
- `binds <path> outside the server's folder roots`
- `is marked placement: primary_only`

- [ ] **Step 1:** Write `TestPlacementVectors`, which reads the vectors (≥ 20 cases, one per reason plus clean ones, incl. long-syntax volumes and a `${VAR}` bind). Write `TestRealTemplatesPlacement`, which loads `testdata` templates samba (person_secret), headscale (vpn) and an echo (clean).
- [ ] **Step 2:** Run `go test ./internal/templates -run Placement`. Expected: FAIL.
- [ ] **Step 3:** Implement on the same compose parse `RuntimeCompat` uses (`runtimecompat.go`). Don't fold it into `RuntimeCompat`: placement is a server property, not a runtime one.
- [ ] **Step 4:** Run the Hub gate. Expected: PASS.
- [ ] **Step 5:** Commit (`hub: primary-only detection and placement: field; shared vectors`).

### Task 4: Hub `internal/agentapi` (shared wire types, bundle rules, scope)

**Files:**
- Create: `internal/agentapi/{types.go,bundle.go,scope.go,limits.go}` + tests, `testdata/bundle_vectors.json`

**Interfaces — Produces:**

```go
package agentapi
const Version = "v1"
type Info struct{ AgentVersion, API, Runtime, Arch, EngineVersion string; Rootless bool; UIDMap, GIDMap string; CPUs int; MemBytes, DiskTotal, DiskFree, DataTotal, DataFree int64; SecurityOptions []string; SELinux bool; UnprivilegedPortStart int; BindRoots []string; PortBinds []PortBind; Clock time.Time }
type PortBind struct{ Project, Service, HostIP string; HostPort int; Proto string }
type BundleManifest struct{ Instance string; Files map[string]FileEntry } // path → {sha256, mode, size}
type FileEntry struct{ SHA256 string; Mode uint32; Size int64 }
type HelperSpec struct{ Kind string /* volume_io|folder_fix */; Volume, Mode string; Paths []string }
type DataPreamble struct{ Instance, Service string; Port int }
func ReadBundle(r io.Reader, m BundleManifest, maxBytes int64, write func(name string, mode fs.FileMode, data io.Reader) error) error
func ValidateBundle(model *types.Project, instance string, bindRoots []string, bundleDir string) error // useroverride/coreref rules
func ProjectLabelOK(labels map[string]string, bundled map[string]bool) (string, bool)            // com.docker.compose.project=portcullis-<id>
const MaxInfo = 64 << 10; const MaxJSON = 1 << 20; const MaxLogs = 4 << 20; const MaxLine = 64 << 10; const MaxBundle = 64 << 20
```

- `ValidateBundle` calls the Hub's existing user-override and core-ref checks (`useroverride.go`, `coreref.go`): no `privileged`, `devices`, `userns_mode`, disallowed `network_mode`, `pid`/`ipc: host`, `cap_add` beyond what `RuntimeCompat` allows, bind sources only inside `bundleDir` or `bindRoots`. Move those checks into exported functions in `internal/templates` if they live in `internal/hub` today (a move, no behaviour change; the existing tests keep passing).

- [ ] **Step 1:** Write `TestBundleVectors` (≥ 25: symlink, hardlink, `..`, absolute, duplicate, device, fifo, size over cap, sha mismatch, a file missing from the manifest, an extra file → refused; a clean bundle → ok), `TestValidateBundleRefusesEscapes` (privileged, devices, `/etc` bind, `../` bind, `network_mode: host`), and `TestProjectLabelOK`.
- [ ] **Step 2:** Run it. Expected: FAIL.
- [ ] **Step 3:** Implement. `ReadBundle` uses `archive/tar` and accepts only `TypeReg` / `TypeDir`.
- [ ] **Step 4:** Run the Hub gate. Expected: PASS, with the moved checks' old tests unchanged.
- [ ] **Step 5:** Commit (`hub: agent API v1 types, bundle rules, scope checks`).

### Task 5: Agent: tunnel, identity, enrolment, `/info`, `/metrics`

**Files:**
- Create: `internal/agent/{tunnel.go,identity.go,enrol.go,server.go,metrics.go}` + tests; `cmd/portcullis-agent/main.go`

**Interfaces:**
- Consumes: `servers.DecodeJoinCode`, `servers.Proof` (Task 2); `agentapi.Info` (Task 4).
- Produces:
  - `portcullis-agent run`: env `AGENT_DATA` (abs path), `AGENT_ENGINE=tcp://socket-proxy-agent:2375`, `AGENT_BIND_ROOTS`, `AGENT_RUNTIME=docker|podman`.
  - `portcullis-agent join` reads the code from **stdin** (≤ 4 KiB), validates it and writes `<data>/identity/join.json` (0600). `portcullis-agent status` prints JSON; `portcullis-agent healthcheck`; `portcullis-agent leave` wipes the identity.
  - Identity files: `<data>/identity/{wg.key, tls.key, tls.crt, ca.crt, pins.json}` (0600).
  - States: `joining` (bootstrap key, self-signed cert, only `/v1/enrol/*` and `/v1/info`) → `ready`.
  - `tunnel.go`: wireguard-go + netstack (same pins as core's `wg/go.mod`), MTU 1380, the peer = link at `Endpoint` with keepalive 25 s, AllowedIPs `10.214.0.1/32`. Listeners only `ListenTCP(:7443)` and `ListenTCP(:7000)` on the netstack.
  - TLS: `tls.Config{ClientAuth: RequireAndVerifyClientCert, ClientCAs: pinned pki_node CA, MinVersion: TLS13}`, then `VerifyPeerCertificate` checks CN ∈ {`hub.control`, `link.control`} with a ±5 min clock tolerance (verify with `x509.VerifyOptions.CurrentTime` at now, now−5m and now+5m; accept if one passes). `link.control` reaches only `GET /v1/metrics`.
  - `POST /v1/enrol {"proof","csr_cn"}` → `{"wg_public_key","csr"}` after a good proof (the nonce from `GET /v1/enrol/nonce`, single use, 60 s). Then `PUT /v1/identity/cert` and `PUT /v1/identity/wg {link_pub}` switch to `ready` (new WG key in use, bootstrap key deleted). `POST /v1/identity/csr` (renewal, ready only) → a new CSR from a new key, swapped on `PUT /v1/identity/cert`.
  - `GET /v1/info` = `agentapi.Info` from the engine (`/info`, `/version`) and `statfs` of `DockerRootDir` and `AGENT_DATA`.

- [ ] **Step 1: Write the failing tests** (real netstack pairs on loopback UDP, like core's `wg/internal/tunnel` tests):
  - `TestNetstackOnlyTwoListeners` (every other port on the agent's tunnel IP refuses);
  - `TestDataOnlyFromLink` (a second peer IP is refused at `:7000`);
  - `TestEnrolProofAndSwap` (good proof → CSR; a wrong HMAC, a reused nonce, an expired nonce → 403, and three failures stop the agent: "enrolment refused; run ./portcullis worker join again");
  - `TestControlCertPins` (a `pki_int` person cert, another CA, CN `x.node…`, and `link.control` on `/v1/projects` → refused);
  - `TestAgentClockTolerance` (a Hub cert valid from now+4m is accepted, from now+6m refused with "clock" in the error);
  - `TestJoinReadsStdinOnly` (an argument → exit 2).
- [ ] **Step 2:** Run `go test ./internal/agent/... ./cmd/portcullis-agent/...`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the Hub gate. Expected: PASS.
- [ ] **Step 5:** Commit (`agent: userspace tunnel, enrolment, pinned mTLS, /info, metrics`).

### Task 6: Agent: projects, scope table, helpers, events, data listener

**Files:**
- Create: `internal/agent/{projects.go,helpers.go,data.go,events.go}` + tests

**Interfaces:**
- Consumes: `agentapi.ReadBundle`, `ValidateBundle`, `ProjectLabelOK`, `HelperSpec` (Task 4); the Hub's `internal/compose` CLI runner and `internal/docker` client (unchanged, pointed at `AGENT_ENGINE`); the Hub's fixed helper specs: `hub.HelperImage` and the fixer `RunSpec` builders. Move them to `internal/runtime/docker` exported functions if they're Hub-private; this is a move, with byte-identical specs asserted by a test.
- Produces: every route of spec §5 plus the additions, each enforcing its scope column. The rules:
  - `{id}` must match `archiveRe`'s instance part and have a bundle (else 404). Containers must carry `com.docker.compose.project=portcullis-<id>` of a bundled project (else 403).
  - Volumes must be compose-labelled with a bundled project or be a §11.2 name of one. Image pulls only for refs in a bundle's model or the pinned helper/fixer image.
  - `folder_fix` paths must be under `AGENT_BIND_ROOTS`. Helper specs are byte-equal to the fixed specs (else 403 "not a fixed helper").
  - `PUT /v1/projects/{id}/bundle` writes into `<data>/projects/<id>.new/`, re-validates (load the model with compose-go from those files, `ValidateBundle`), then renames over the old directory. Appfiles live outside it, at `<data>/appfiles/<id>/` (kept across bundles), so directory bind mounts survive.
  - `up` / `down` stream ndjson progress lines `{"step","service","done","total"}`. `DELETE /v1/ops/{op}` cancels like `stop_op`.
  - Data: read one preamble line ≤ 1 KiB within 5 s. Only `{instance, service, port}` of a bundled, enabled project whose model routes that service on that port (a `traefik.http.services.*.loadbalancer.server.port` label) is accepted. Then dial the container's address on the worker's `portcullis-proxy` and splice.

- [ ] **Step 1: Write the failing tests** (fake engine + fake runner, as `runtimetest`):
  - `TestScopeTable` (one case per row: foreign project, foreign container, foreign volume, unlisted image, non-fixed helper spec, fixer outside roots → 403; the in-scope twin → 200);
  - `TestBundleRefusesLinksAndEscapes` (Review Focus 5: nothing written outside `projects/<id>`);
  - `TestBundleSwapKeepsAppfiles`;
  - `TestDataPreambleChecks` (unplaced instance, unrouted port, a slow preamble, an oversized line → closed);
  - `TestResponsesCapped` (logs > 4 MiB truncated with `Truncated`, events line > 64 KiB dropped);
  - `TestNoRawPassthrough` (`/v1/engine/…`, `/libpod/…`, `/build` → 404).
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the Hub gate. Expected: PASS.
- [ ] **Step 5:** Commit (`agent: projects API with the scope table, helpers, events, data listener`).

### Task 7: Relay, images and publishing

**Files:**
- Create: `internal/relay/{proxy.go,cookies.go,offline.go}` + tests, `cmd/portcullis-relay/main.go`, `Dockerfile.agent`, `Dockerfile.relay`
- Modify: `.github/workflows/build.yml` (matrix `image: [hub, agent, relay]`, same tags/cosign/SBOM as the Hub image), `CLAUDE.md`

**Interfaces — Produces:**
- `portcullis-relay` env:
  - `RELAY_LISTEN` (`:<port>`, one per relay container);
  - `RELAY_TARGET` (`<instance>.<service>.relay:<port>`);
  - `RELAY_LINK` (`<PORTCULLIS_LINK_DATA_WG_IP>:3129`);
  - `PORTCULLIS_RELAY_TOKEN`;
  - `RELAY_APP_LABEL` and `RELAY_SERVER_LABEL` (display only, HTML-escaped).
- Transport: `httputil.ReverseProxy` with a `Transport.DialContext` that opens a CONNECT to `RELAY_LINK` and returns the tunnelled conn. WebSocket and HTTP upgrades are supported. `X-Forwarded-*` are passed through from Traefik unchanged.
- `func FilterRequestCookies(h http.Header)` and `func FilterResponseCookies(h http.Header, host string)`.
- On a dial failure the relay answers 503 with the static page "<app> runs on <server>, which is offline" (`Cache-Control: no-store`, no cookie).
- Images: `Dockerfile.agent` is distroless static plus the pinned `docker compose` plugin binary the Hub image already ships, uid 10008. `Dockerfile.relay` is distroless static, uid 65534. Both are fully qualified and pinned by digest.

- [ ] **Step 1:** Write `TestCookieFilterDomainVariants` and `TestRequestCookiesStripped` (Review Focus 3, every spelling listed there), `TestWebSocketThroughRelay` (a fake link CONNECT server), `TestOfflinePage` (the copy, escaping `<script>` in labels), and `TestRelayHasNoOtherListener`.
- [ ] **Step 2:** Run `go test ./internal/relay/...`. Expected: FAIL.
- [ ] **Step 3:** Implement, and add the build matrix.
- [ ] **Step 4:** Run the Hub gate and `docker build -f Dockerfile.agent .` / `-f Dockerfile.relay .`. Expected: PASS, both images build, `docker run --rm <relay> --help` exits 0.
- [ ] **Step 5:** Commit (`relay: reverse proxy over link with cookie filter and offline page; agent and relay images`).
- [ ] **Step 6 (controller):** `gh workflow run build.yml --ref ms1`. Expected: green, three images built (not pushed on a branch).

### Task 8: Hub `internal/runtime/agent` backend and `rtFor`

**Files:**
- Create: `internal/runtime/agent/{backend.go,client.go,deliver.go}` + tests
- Create: `internal/hub/rtfor.go`
- Modify: `internal/hub/kube.go` (`kubeDeliverer` → `fileDeliverer`, gated by "the instance's runtime implements it" instead of `kubeOn()`), every `h.rt.` call site that acts on one instance (the 30 files counted on `kube1`: `grep -lE 'h\.rt\b' internal/hub/*.go`) → `rt, err := h.rtFor(id)`; global calls (`List{All}`, `Events`, `Info` for the doctor, the helper sweep) iterate `h.runtimes()`

**Interfaces:**
- Consumes: `runtime.Instances` (kube plan), `agentapi` (Task 4).
- Produces:

```go
package agent // internal/runtime/agent
type Dialer interface{ DialContext(ctx context.Context, network, addr string) (net.Conn, error) } // CONNECT through link (HUB_LINK_PROXY)
type Config struct{ ServerID string; TunnelIP netip.Addr; CACert *x509.Certificate; SPKI []byte; Serial string; ControlCert tls.Certificate; Dial Dialer }
func New(cfg Config) *Backend // implements runtime.Instances + DeliverFile + PushBundle
func (b *Backend) PushBundle(ctx context.Context, id string, files fs.FS, m agentapi.BundleManifest) error
func (b *Backend) Info(ctx context.Context) (runtime.Info, error) // agentapi.Info → runtime.Info (Kind docker|podman, SELinux, IDMapped, ForbiddenRoots = [DockerRootDir])
func (b *Backend) AgentInfo(ctx context.Context) (agentapi.Info, error)
```

```go
// internal/hub/rtfor.go
func (h *Hub) rtFor(id string) (runtime.Instances, error) // "" server → h.rt; ready → its agent backend; else *StatusError 409 "server <name> is offline" | "… is revoked" | "… isn't ready yet"
func (h *Hub) runtimes() map[string]runtime.Instances      // "primary" + every ready server
func (h *Hub) serverOf(id string) string                    // under mu
```

- The client: `http.Transport{DialTLSContext: CONNECT via Dialer, then tls.Client with ServerName "<id>.node.portcullis.internal", RootCAs = pki_node CA, Certificates = control cert}`. `VerifyConnection` compares the leaf SPKI sha256 and serial with state; a mismatch returns `ErrIdentityMismatch` and the server goes `offline` with `server_identity_mismatch`. Every response body goes through `io.LimitReader` at the §17 cap, and decoding is strict.
- `VolumeOut`/`VolumeIn` stream the helper archive. The Hub checks each entry with the existing `checkVolumeEntry` before writing (Review Focus 5).
- `Pull` is `POST /v1/images/pull` with ndjson progress mapped to `onBytes`.

- [ ] **Step 1: Write the failing tests:**
  - `TestAgentBackendAgainstFakeAgent` (an `httptest` TLS server with real `pki_node`-shaped certs from a test CA; each `runtime.Instances` method maps to its route);
  - `TestIdentityMismatch` (another server's cert, a new serial not in state → refused);
  - `TestAgentArchiveEntriesChecked`;
  - `TestOversizedInfoCut` (`/v1/info` of 65 KiB → error, not a partial decode);
  - `TestRtForStates` (primary, ready, offline, revoked, enrolling);
  - `TestDockerPathUnchanged`: the primary path makes the same calls in the same order as before (run with `runtimetest.Fake`).
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement. Convert the call sites mechanically.
- [ ] **Step 4:** Run the Hub gate. Expected: PASS, and `git diff --stat origin/main -- '*_test.go'` shows only new tests and fake plumbing.
- [ ] **Step 5:** Commit (`hub: agent runtime backend; rtFor per instance`).

### Task 9: Hub servers: state, `link.json`, control cert, enrolment, renewal, polling, revocation, removal

**Files:**
- Create: `internal/state/servers.go`, `internal/hub/{servers.go,servers_link.go,nodecerts.go,servers_enrol.go,servers_poll.go,servers_revoke.go}` + tests
- Modify: `internal/state/state.go` (`AppState.Servers map[string]Server`, `Instance.Server`), `cmd/hub/main.go`

**Interfaces:**
- Consumes: Tasks 2, 8; enroll's `/internal/nodes/sign|revoke` (Task 16) through the existing invite client config (`/run/portcullis/invite/secret`); Keycloak `IdP` (client secret rotation: the existing `RegisterClient` regeneration path).
- Produces:

```go
package state
type Server struct {
	Name string; TunnelIP netip.Addr; WGPublicKey, CertSerial, SPKI string
	State string // enrolling|ready|offline|revoked
	LocalNetworks *[]string; BackupSchedule BackupSchedule
	CertNotAfter time.Time; LastContact time.Time; AgentVersion string
	Enrol *Enrol // while enrolling: SecretSHA256, BootstrapPub, ExpiresAt, Used bool
	QuarantinedUntil time.Time // revoked: IP reuse barrier
}
type BackupSchedule struct{ Mode string /* off|daily|weekly */; Hour, Weekday int }
```

```go
func (h *Hub) AddServer(ctx context.Context, actor directory.Actor, id, name string) (code string, expires time.Time, err error) // fresh sign-in checked by httpapi
func (h *Hub) Servers(ctx context.Context) []ServerView
func (h *Hub) RevokeServer(ctx context.Context, actor directory.Actor, id string) error
func (h *Hub) RemoveServer(ctx context.Context, actor directory.Actor, id string) error // 409 while instances remain
func (h *Hub) RunServers(ctx context.Context, every time.Duration)                       // 30 s: enrol watch, polls, renewals, link.json
func (h *Hub) publishLinkLocked() error
```

- **Enrolment:**
  - On a handshake (`wg_data/status.json` `link.peers[].handshake` newer than the code) the Hub opens control with its `hub.control` cert. In enrolling mode it skips the SPKI pin and pins `ca_sha256` the other way: the agent checks the Hub cert.
  - It runs nonce → proof → CSR, has enroll sign the CSR (`node-worker`, CN `<id>.node.portcullis.internal`), pushes the cert and `PUT /v1/identity/wg`, swaps the peer key in `link.json`, then `PUT /v1/network`.
  - `server.enrolled` is audited. The secret is compared by sha256, and the code is single use (`Used` is set before the first try).
  - Expired code, reuse or a wrong HMAC → `server.enrol_refused`, and the bootstrap peer is removed.
- **Renewal:** at ⅓ remaining life: `POST /v1/identity/csr` → sign → `PUT /v1/identity/cert` → new serial and SPKI pinned (`server.renewed`).
- **Polling:**
  - `GET /v1/info` every 30 s. Offline after 3 misses or a handshake older than 3 min.
  - On return: reconcile + doctor.
- **Revocation (spec §6, in this order; each step is retried at the next tick until it succeeds, and the server is `revoked` from step 1 on):**
  1. remove the peer and its relays from `link.json`;
  2. `/internal/nodes/revoke`;
  3. unpin;
  4. take the relays down (`DownByName`);
  5. rotate each placed instance's Keycloak client secrets and relay tokens.

  Its instances become `orphaned`. `server.revoked` is audited.
- **Removal:** with no instances, `POST /v1/leave`, then revocation; `server.removed`.
- `cmd/hub/main.go`:
  - `HUB_LINK_DOC_DIR` (default `/link-doc`) and `HUB_LINK_DOC_GID` (default 10009, 1–65535, never 10001, else refuse to start);
  - `HUB_LINK_PROXY` (default `172.31.254.83:3128`, an IPv4:port);
  - `HUB_RELAY_IMAGE` (required when `HUB_LINK_DOC_DIR` is set and exists; `@sha256` or `:edge`);
  - `go h.RunServers(ctx, 30*time.Second)`.

- [ ] **Step 1: Write the failing tests:**
  - `TestAddServerCodeShownOnce` (the code is in no state field, log or audit: grep the captured log and audit for the secret);
  - `TestEnrolHappyPath` (fake agent);
  - `TestEnrolRefusals` (expired, reused, wrong HMAC → bootstrap peer gone, audited);
  - `TestEnrolReportsClockSkew` (Review Focus 1);
  - `TestRenewAtOneThird`;
  - `TestOfflineAfterThreeMisses`;
  - `TestRevokeOrderAndRetry` (enroll down at step 2: steps 1 and 3–5 still done, step 2 retried; the peer is gone from `link.json` before anything else);
  - `TestRevokeRotatesClientSecretsAndTokens`;
  - `TestRemoveRefusesWithInstances`;
  - `TestLinkJSONRewrittenAtStart`;
  - `TestServersOffWithoutLinkDoc` (503 text from Global Constraints);
  - `TestKubernetesPrimaryRefusesServers`.
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the Hub gate. Expected: PASS.
- [ ] **Step 5:** Commit (`hub: servers — link.json, control cert, enrolment, renewal, polling, revocation, removal`).

### Task 10: Hub placement, relay projects, lifecycle on workers

**Files:**
- Create: `internal/hub/placement.go`, `relays.go` + tests
- Modify: `internal/hub/lifecycle.go` (`prepareUp`, `composeUp`, `startUp`: render with the **target server's** engine facts; push the bundle), `override.go` (the render view gets `engineFacts{Rootless, SELinux, UnprivilegedPortStart, ForbiddenRoots}` from `rtFor(id).Info`, instead of `h.rootlessOn()` / `readEngineSELinux` / `unprivilegedPortStart()`), `instances.go` (create with `server`), `reconcile.go` (drift reads the relay containers on the primary for routes and the agent for state), `localnet.go` (per-server Local networks), `folders.go` (a folder records its server; `FolderHostPath` resolves per server; binding a folder of another server refuses)

**Interfaces:**
- Consumes: Tasks 3, 8, 9.
- Produces:
  - `POST /api/instances` gains `"server"`. `func (h *Hub) checkPlacement(ctx context.Context, t *templates.Template, server string) error` returns a 409 *StatusError with one of: not ready, `templates.Placement` reasons ("<template> can't run on a worker: <reason>"), `RuntimeCompat(<server runtime>)` refused, or a pre-pull failure ("<image> has no <arch> image").
  - `func (h *Hub) renderRelaysLocked(t *templates.Template, model *types.Project) ([]byte, error)`: a compose file with project `portcullis-<id>` and, per service whose final labels contain `traefik.enable=true`:
    - `image: $HUB_RELAY_IMAGE`, `user: 65534:65534`, `read_only`, `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, mem 64m, pids 64, `restart` like the template's;
    - `networks: {portcullis-proxy: {}, portcullis-link-data: {}}` (both external);
    - `labels` = exactly the service's `traefik.*` labels from the loaded model (the same values the instance would carry on the primary; `com.docker.compose.*` never copied);
    - `environment` from the relay env file.
  - The bundle = the files `project(t)` names (compose, override, user override, env), `templates/<app>/`, the instance's appfiles and `certs/ca-bundle.crt`, with modes from the primary's files.
- **Order of an up on a worker:**
  1. bundle;
  2. `Pull`;
  3. agent `Create`/`Up`;
  4. relay env + token → `link.json`;
  5. relays up on the primary.

  A down runs relays down first. Delete removes relays, the token, and the agent project and volumes as today. An `orphaned` instance can only be restored elsewhere or **forgotten** (`DELETE /api/instances/{id}?forget=1`, typed id, `instance.forget`: state, clients and groups removed, nothing on the dead worker touched).

- [ ] **Step 1: Write the failing tests:**
  - `TestRelayLabelsEqualPrimaryGoldens`: for every golden under `testdata/golden/*.override.yml` (incl. the six `vpn_*` ones), the relay's labels equal the labels the instance's container would carry on the primary;
  - `TestRelayNeverDropsAuthMiddlewares` (mutation: removing `portcullis-groups` from the model fails the test);
  - `TestPlacementRefusals` (each 409, nothing created: no project, no client, no group);
  - `TestRenderUsesTargetEngineFacts` (podman+SELinux worker, docker primary → `z` labels and `restart: always` only in the worker's bundle);
  - `TestLifecycleOfflineIs409`;
  - `TestOrphanForget`;
  - `TestFolderOfOtherServerRefused`;
  - `TestLanOnlyUsesServerLocalNetworks`.
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the Hub gate. Expected: PASS, with every existing golden unchanged.
- [ ] **Step 5:** Commit (`hub: placement, relay projects, instances on workers`).

### Task 11: Hub move / undo, scheduled backups

**Files:**
- Create: `internal/hub/move.go`, `backup_schedule.go` + tests
- Modify: `internal/hub/backup.go` (`BackupMove = "move"`, `BackupScheduled = "scheduled"`, pruning of scheduled archives only), `restore.go` (restore into the same id on a given runtime), `internal/state/state.go` (`Move`, `MovedFrom`, `AppState.PrimaryBackups BackupSchedule`), `cmd/hub/main.go` (`go h.RunBackupSchedules(ctx, time.Minute)`, and `h.RecoverMoves()` after the engine guard)

**Interfaces — Produces:**
- `func (h *Hub) MoveInstance(ctx context.Context, id, to string, actor directory.Actor) (*OpRecord, error)`, op `move`, Stop like `stop_op`. Phases:
  1. `check` (target ready, `checkPlacement`; bound shared folders → 409 "unbind folders first; folder contents aren't moved");
  2. `backup` (reason `move`, which stops the instance);
  3. `restore` (same id, target runtime, new volumes);
  4. `switch` (relays point at the target, or are removed when the target is the primary; new relay token; then start);
  5. `keep` (`MovedFrom{server, at}`).

  A failure or a Stop before `switch` restarts the source and ends with `Instance.State` cleared. `instance.move` is audited.
- `func (h *Hub) UndoMove(...)`: only within 7 days, with a confirm dialog that says changes since the move are lost (the API needs `{"confirm": "<id>"}`). It switches routing back to the source volumes, starts there and stops the target (`instance.move_undo`).
- `func (h *Hub) RemoveMoveLeftover(...)`: typed id; removes the source volumes through the source runtime (`instance.move_leftover_removed`).
- `func (h *Hub) RecoverMoves()`: Review Focus 2.
- `func (h *Hub) RunBackupSchedules(ctx, every)`: per server (primary included) at the chosen hour (the Hub's local time zone from `TZ`, default UTC), one instance at a time, the existing consistency rule (stop briefly). Keep the 3 newest `scheduled` archives per instance; never touch others. A server offline at the hour gets skipped with an op-record note.

- [ ] **Step 1: Write the failing tests:**
  - `TestMoveFailureAtEveryPhase` (table: fail at check/backup/restore/switch-before-route → the source runs, routes unchanged, no second routed copy);
  - `TestMoveStopMidRestore`;
  - `TestMoveRecoveryAfterHubRestart`;
  - `TestMoveRefusesBoundFolders`;
  - `TestUndoWithin7Days` (and after 7 d → 409);
  - `TestScheduledPruneKeepsManual`;
  - `TestScheduleSkipsOfflineServer`;
  - `TestMoveToPrimaryRemovesRelays`.
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement on the existing backup/restore machinery: `backupCtx`, `restoreSteps` and `applyRestore` take a `runtime.Instances`.
- [ ] **Step 4:** Run the Hub gate. Expected: PASS.
- [ ] **Step 5:** Commit (`hub: move and undo between servers; scheduled backups`).

### Task 12: Hub API, UI, MCP, audit

**Files:**
- Create: `internal/httpapi/servers.go`, `mcptools_servers.go`, `web/servers.html`, `web/servers.js` + tests
- Modify: `internal/httpapi/server.go` (routes, parity tables), `web/index.html` (Settings → Servers), `web/apps.js` (*Runs on* badge and setup-form select with free disk/memory/runtime/arch; *Move…* in Instance → Manage; the undo banner), `web/folders.js` (server column), `web/web.go`

**Interfaces — Produces:**
- Routes (all admin; ones marked † need a fresh sign-in, as the VPN device routes do):
  - `GET /api/servers`, `GET /api/servers/{id}`;
  - `POST /api/servers` † → `{"code","expires_at"}` with `no-store`;
  - `PUT /api/servers/{id}/settings {name, local_networks, backup_schedule}`;
  - `PUT /api/servers/primary/settings {backup_schedule}`;
  - `POST /api/servers/{id}/revoke` † `{"confirm":"<id>"}`;
  - `DELETE /api/servers/{id}` † `{"confirm":"<id>"}`;
  - instance move routes (Task 1 §11).
- MCP (`registerServerTools`, admin):
  - `list_servers`, `get_server` (ClassRead; no code, no key, no serial);
  - `move_instance` (ClassDestructive, `Typed: idOf`, consequences name the downtime and size);
  - `set_backup_schedule` (ClassWrite).
  - The parity test lists `POST /api/servers`, `/revoke` and `DELETE /api/servers/{id}` as `noToolRoutes` with the reasons "a join code must never land in a transcript" and "revocation stays a human action".
- The UI follows the VPN page's patterns. The code dialog shows the command `./portcullis worker join` and a *Copy code* button; the code itself isn't rendered into the DOM after the dialog closes.

- [ ] **Step 1:** Write `TestServersRoutesAdminOnly`, `TestAddServerNoStore`, `TestRevokeNeedsFreshAuthAndTypedID`, `TestMCPNoJoinCodeTool` (parity), `TestServerViewHasNoSecrets`, and a `web` test that the code isn't in `localStorage` or the DOM after close (the existing web test harness).
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the Hub gate. Expected: PASS.
- [ ] **Step 5:** Commit (`hub: servers API, UI, MCP tools`).

### Task 13: Hub doctor kinds

**Files:**
- Create: `internal/doctor/servers.go`, `internal/hub/doctor_servers.go` + tests
- Modify: `internal/doctor/doctor.go` (`Inputs.Servers *ServersIn`), the `lan_only_exposed` check (reads each server's `PortBinds` against that server's Local networks)

**Interfaces — Produces:** kinds and severities from spec §10:
- `server_offline` (Problem);
- `server_cert_expiring` (Warning ≤ 7 d);
- `server_agent_incompatible` (Problem) / `server_agent_outdated` (Info, older minor);
- `server_disk_low` (Warning < 10 % of DockerRootDir or data dir);
- `server_no_recent_backup` (Warning: a worker instance without a backup in 14 d);
- `server_move_leftover` (Info after 7 d; fix = `RemoveMoveLeftover`, typed);
- `link_subnet_overlap` (Problem: the link subnet overlaps the VPN subnet, a wired provider range or a Local network of any server);
- `instance_orphaned` (Problem).

`ServersIn{Servers []ServerIn; LinkSubnet netip.Prefix; Now time.Time}`; `nil` = no findings.

- [ ] **Step 1:** Write `TestServerKinds` (table: each kind fires on its input and not on the boundary value: 7 d vs 7 d+1 s, 10 % vs 9.9 %) and `TestLanOnlyExposedPerServer`.
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the Hub gate. Expected: PASS.
- [ ] **Step 5:** Commit (`hub: doctor kinds for servers`).
- [ ] **Step 6 (controller):** Hub stream review. Then `gh workflow run build.yml --ref ms1`. Expected: green.

---

## Templates stream (Task 14)

### Task 14: Templates validator: `placement`, worker rules

**Files:**
- Modify: `schema/manifest.schema.json` (`placement`: enum `any`, `primary_only`), `tests/validate.py` (`placement_reasons()` with the exact strings of Task 3; a `--placement` report line per template: `worker-placeable` or `primary-only: <reasons>`), `tests/test_validate.py`, `CONTRIBUTING.md` ("Running on a worker": host-only cookies, no `host-gateway`, no TCP/UDP routers), `CLAUDE.md`
- Create: `tests/placement_vectors.json` (byte copy of Hub `internal/templates/testdata/placement_vectors.json` at the Task 3 commit)

- [ ] **Step 1:** Write `test_placement_vectors` (reads the copy, same verdicts and reasons) and `test_placement_field_enum`.
- [ ] **Step 2:** Run `python3 tests/test_validate.py`. Expected: FAIL.
- [ ] **Step 3:** Implement. Add `placement: primary_only` only to templates that set a parent-domain cookie the relay would strip; none is known. If Test Apps shows one, mark it and list it in the commit.
- [ ] **Step 4:** Run the templates gate. Expected: PASS. The lint workflow compares the vectors with the same-named Hub branch (add the comparison next to the existing `vpn_vectors.json` / `runtime_vectors.json` checks).
- [ ] **Step 5:** Commit (`templates: placement field and worker-placeable rules; vectors = Hub <sha>`).

---

## Core stream (Tasks 15–19)

### Task 15: Core `wg` link role

**Files:**
- Create: `wg/internal/linkdoc/{linkdoc.go,linkdoc_test.go}`, `wg/internal/link/{link.go,connect.go,metrics.go,link_test.go}`, `tests/link_json_vectors.json` (byte copy of the Hub's)
- Modify: `wg/main.go` (env `WG_LINK=on|off`, `WG_LINK_KEY=/run/portcullis/wg/link.key`, `WG_LINK_PORT`, `WG_LINK_SUBNET`, `WG_LINK_FILE=/link-doc/link.json`, `WG_LINK_CONTROL_ADDR=<ip>:3128`, `WG_LINK_DATA_ADDR=<ip>:3129`, `WG_LINK_TLS_KEY`, `WG_LINK_TLS_CERT`; subcommands `genkey-tls <path>` (P-256, in place, never printed) and `link-csr` (CSR for CN `link.control` on stdout)), `wg/internal/status/status.go` (`Link` block), `wg/main_test.go`

**Interfaces — Produces:**
- `link.New(stack *tunnel.Stack, doc func() *linkdoc.Doc) *Link`.
- `(*Link).ServeControl(ctx, ln net.Listener)` and `(*Link).ServeData(ctx, ln net.Listener)`: `net/http` CONNECT handlers. Everything else is 405. The upstream is dialled with `stack.DialTCP`.
- `(*Link).Reload(d *linkdoc.Doc)`: `SyncPeers` (peers from ready+enrolling entries, AllowedIPs /32, no endpoint) and **closes every open stream** whose peer or token is gone.
- The netstack opens **no** listener. Metrics: `wg_link_peer_handshake_age_seconds{server}`, `wg_link_peer_rx_bytes_total{server}` / `tx`, `wg_link_connect_rejected_total{path,reason}`, plus each ready agent's `/v1/metrics`, fetched with the `link.control` cert and re-labelled `server=`.
- The link role reuses `internal/tunnel` unchanged (separate stack, key, port and subnet; no code path between the people/edge stacks and the link stack).

- [ ] **Step 1: Write the failing tests:**
  - `TestLinkDocVectors` (byte copy);
  - `TestLinkZeroNetstackListeners` (a peer probing every TCP port 1–65535 on `10.214.0.1` from the peer's netstack gets RST; run on a sample of 2000 ports plus 22, 80, 443, 3128, 3129, 7000, 7443, 8080);
  - `TestControlConnectRules`;
  - `TestDataConnectRules` (no bearer, unknown token, a token for instance A targeting B → 403; the preamble is written by link);
  - `TestReloadDropsPeers`;
  - `TestRevokeClosesOpenStreams` (Review Focus 4);
  - `TestBadDocMeansNoPeers`;
  - `TestLinkRoleIsolated` (the people stack can't reach a link peer and vice versa).
- [ ] **Step 2:** Run `cd wg && go test -race ./...`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the core Go gate for `wg`. Expected: PASS.
- [ ] **Step 5:** Commit (`wg: link role — CONNECT dialers, link.json v1, zero netstack listeners, metrics`).

### Task 16: Core `pki_node` and enroll `/internal/nodes/*`

**Files:**
- Create: `enroll/nodes.go`, `enroll/nodes_test.go`
- Modify: `enroll/invite.go` (routes beside `/internal/certificates/revoke`, not on the loopback listener), `vault/policies/enroll.hcl`, `scripts/lib/pki.sh` (`_pki_create_node_ca` like `_pki_create_browser_ca`, under the same root, CN `<org> Node CA`; `_pki_write_node_roles` every `pki setup` run; export `certs/node-ca.crt`, which is **not** in `ca-chain.crt`, `ca-chain-yubikey.crt`, the truststore or any Traefik/Keycloak/group-gate file), `tests/test_shell_libs.sh`

**Interfaces — Produces:**
- `POST /internal/nodes/sign` and `POST /internal/nodes/revoke` (Global Constraints shapes).
- Roles:
  - `node-worker`: `allowed_domains=node.portcullis.internal`, `allow_subdomains=true`, `server_flag=true`, `client_flag=true`, `ttl=720h`, `max_ttl=720h`;
  - `node-control`: `allowed_domains=hub.control`, `allow_bare_domains=true`, `client_flag=true`, `server_flag=false`, `ttl=720h`;
  - `node-link`: `allowed_domains=link.control`, `allow_bare_domains=true`, client only, `ttl=2160h`;
  - all with `key_type=ec`, `key_bits=256`, `allow_ip_sans=false`, `no_store=false`, `not_before_duration=30s`.
- The policy adds update on `pki_node/sign/node-worker`, `pki_node/sign/node-control` and `pki_node/revoke`, read on `pki_node/crl/rotate`, each with the same `denied_parameters` as the other sign paths.

- [ ] **Step 1:** Write `TestNodeSignRoleAndCN` (node-link refused, a CN not matching the role refused, alt names refused, body > 64 KiB → 413, no CSR in logs), `TestNodeRevoke`, and the shell tests `test_pki_node_ca_not_trusted` (node-ca.crt absent from every chain file and the truststore) and `test_enroll_policy_node_paths`.
- [ ] **Step 2:** Run `cd enroll && go test ./...` and `bash tests/test_shell_libs.sh`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the core gate. Expected: PASS.
- [ ] **Step 5:** Commit (`enroll, pki: pki_node intermediate, node roles, /internal/nodes/sign and revoke`).

### Task 17: Core compose wiring, `link init`, status, alerts

**Files:**
- Create: `scripts/lib/link.sh`
- Modify: `docker-compose.yml` (wg: `link_doc:/link-doc:ro`, `group_add` += `"10009"`, networks `portcullis-link` / `portcullis-link-data` pinned, `${PORTCULLIS_LINK_PORT:-51821}:51821/udp` on `wg-egress`, `secrets/wg/link.key` + `link-tls.*` ro, `WG_LINK: ${PORTCULLIS_LINK:-off}`; Hub: `link_doc:/link-doc`, `group_add` += `"10009"`, `portcullis-link` pinned, `HUB_LINK_DOC_DIR`, `HUB_LINK_DOC_GID: "10009"`, `HUB_LINK_PROXY`, `HUB_RELAY_IMAGE: ${RELAY_IMAGE:-ghcr.io/porelli/portcullis-relay:edge}`; networks and volume `link_doc`), `docker-compose.podman.yml` / `-selinux.yml` (the new binds, `Z`), `scripts/lib/network.sh` (`validate_link_network_config`, mismatch guards, `vpn_reserved_ranges` += the two nets), `scripts/lib/common.sh` (`CT_GID_LINK_DOC=10009`, `HUB_ENV_VARS` += `PORTCULLIS_LINK_SUBNET`), `scripts/lib/stack.sh` (`stack_prepare`: `volume_own link_doc 10001:10009 2750`, empty `link.key` / `link-tls.*` placeholders 0640 group 10006; `up` / `upgrade` renew `link-tls.crt` at ⅓), `scripts/lib/status.sh` (a "Servers" block: link up, peers and handshake ages from `wg status`; `servers{}` in `--json`; a peer whose handshake is > 3 min old is a problem), `monitoring/prometheus/{prometheus.yml,alerts.yml,tests/alerts_test.yml}` (job `link` via `secrets/monitoring/prometheus/link-targets.json`, empty while off; alerts `PortcullisServerDown` `wg_link_peer_handshake_age_seconds > 300` for 1m, `PortcullisServerDiskLow` on the agent's disk-free ratio < 0.10 for 15m, `PortcullisServerContainerUnhealthy`), `portcullis` (dispatch), `tests/test_cli.sh`, `.github/ci/unit-tests-compose-files-are-valid-generated.sh` (the reserved-ranges expectation gains the two nets), `CLAUDE.md`, `.env.example`, `CHANGELOG.md`

**Interfaces — Produces:**
- `./portcullis link init [--port N] [--subnet CIDR]`:
  - it refuses an overlap with the VPN subnet, `vpn_reserved_ranges` (minus itself) or a Local network from `hub vpn host-info`;
  - adds `wg` to `COMPOSE_PROFILES` once;
  - `PORTCULLIS_LINK=on`, `_PORT`, `_SUBNET`;
  - the WireGuard key once (`wg genkey`, as `vpn_genkey`), the TLS key once (`wg genkey-tls`);
  - the CSR through `wg link-csr`, signed with Vault `pki_node/sign/node-link` (`key=-` bodies, token through `-H @<(...)`);
  - `hub_env_write`, `stack_compose_up wg traefik hub`.
- `./portcullis link status [--json]`.
- `help_link`.

- [ ] **Step 1:** Write the CLI tests:
  - `test_link_init_refuses_overlap`;
  - `test_link_init_idempotent`;
  - `test_link_no_secret_argv` (the argv grep);
  - `test_link_network_validation`;
  - `test_link_doc_owner`;
  - the compose wiring checks in `unit-tests` (portcullis-link members exactly {hub, wg}, portcullis-link-data members exactly {wg} in core, no `hub_data` on wg, wg still without caps);
  - the promtool rule tests for the three alerts.
- [ ] **Step 2:** Run `bash tests/test_cli.sh && bash tests/test_shell_libs.sh`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the core gate. Expected: PASS.
- [ ] **Step 5:** Commit (`core: link init, link_doc, portcullis-link networks, Hub wiring, status Servers block, alerts`).

### Task 18: Core worker stack and `worker …` commands

**Files:**
- Create: `docker-compose.worker.yml`, `scripts/lib/worker.sh`
- Modify: `portcullis` (`PORTCULLIS_ROLE` guard), `scripts/lib/common.sh` (`need_env` honours the role), `scripts/lib/runtime.sh` (the worker uses `runtime_check` / `runtime_host_checks` unchanged), `tests/test_cli.sh` (socket literal count, role guard), `.github/workflows/release.yml` (preflight: `AGENT_IMAGE` / `RELAY_IMAGE` pinned to released digests), `CLAUDE.md`, `.env.example`

**Interfaces — Produces:**
- `docker-compose.worker.yml` (project `portcullis-worker`):
  - **`socket-proxy-agent`**: the same image, environment and limits as `socket-proxy-hub`, the engine socket ro, network `socket-proxy-agent` (internal).
  - **`agent`** `${AGENT_IMAGE:-ghcr.io/porelli/portcullis-agent:edge}`:
    - `user: "10008:10008"`, `group_add: ["10001"]`, `<<: *hardening` (read_only, `cap_drop: ALL`, no-new-privileges, mem 256m, pids 256), tmpfs `/tmp`;
    - `./worker-data:${PORTCULLIS_WORKER_DATA:?}`;
    - env `AGENT_DATA`, `AGENT_ENGINE`, `AGENT_BIND_ROOTS: ${PORTCULLIS_WORKER_BIND_ROOTS:-/srv:/mnt:/media}`, `AGENT_RUNTIME: ${CONTAINER_RUNTIME:?}`;
    - networks `socket-proxy-agent` and `worker-egress`. The agent itself joins `portcullis-proxy` (created by the agent at enrol, external) at `traefik_ip`.
  - `restart: unless-stopped` (`docker-compose.podman.yml`'s `always` applies on Podman).
- **`./portcullis worker join`** (stdin or no-echo prompt):
  - it refuses an argument, a kubernetes runtime, a host that already has `PORTCULLIS_ROLE=primary`, and an existing identity without `--force`;
  - writes `.env` (`PORTCULLIS_ROLE=worker`, `CONTAINER_RUNTIME` from `runtime_detect` or `--runtime docker|podman`, `PORTCULLIS_WORKER_DATA=$PWD/worker-data`);
  - `runtime_require_host`, then `mkdir -m 0750 worker-data`, owned `10008:10001` via `ct_own`;
  - `up -d`, then `dc exec -T agent portcullis-agent join` with the code on stdin;
  - waits ≤ 5 min for `portcullis-agent status` = `ready`, printing the state.
- `worker status [--json]`, `worker upgrade` (pull + up), `worker leave [--yes]` (agent `leave`, down, `-v` of the agent's volumes only, `worker-data` removed after a typed confirmation), and `worker stop|start <instance>` (`docker compose -p portcullis-<instance>` from the bundle directory, break-glass, never touching what the primary routes). `help_worker`.

- [ ] **Step 1:** Write the CLI tests:
  - `test_worker_join_refuses_argv_code`;
  - `test_worker_join_reads_stdin` (stub docker records stdin, never argv);
  - `test_worker_role_guard` (`up` on a worker → exit 1 with the copy);
  - `test_socket_literal_count` (2 + 1);
  - `test_worker_compose_hardening` (the baseline lint over `docker-compose.worker.yml`, healthchecks lint, image lint);
  - `test_worker_refuses_kubernetes`.
- [ ] **Step 2:** Run `bash tests/test_cli.sh`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the core gate. Expected: PASS.
- [ ] **Step 5:** Commit (`core: worker stack (agent + socket-proxy-agent) and worker join|status|upgrade|leave|stop|start`).

### Task 19: Core CI `e2e-servers` and `e2e-servers-podman`

**Files:**
- Create: `.github/ci/e2e-servers-{setup,worker,asserts,rogue}.sh`, `tests/e2e/e2e_servers.py` (stdlib + Playwright for the sign-in, `tests/e2e/e2e_ops.py` for op polling)
- Modify: `.github/workflows/ci.yml` (two jobs, 60 min each, `needs: jobs-input`; the dispatch description list), `tests/lint_ci_size.sh` stays green

**Interfaces — Produces:**
- `e2e-servers`:
  - Primary: the full stack + Hub (same-named Hub branch) + `link init` + Pebble (as `e2e-instances`), `ACME_STAGING`-style, and the echo template.
  - Worker: a pinned `docker.io/library/docker:<ver>-dind@sha256:…`, privileged (**CI only, the one reviewed exception**, with a `# reviewed exception` comment and an allowlist entry in the privileged lint). It has its own daemon and a checkout of `ms1` inside, runs `./portcullis worker join` with the code on stdin, and reaches the primary only over UDP to the runner's published link port. The Hub's agent and relay images come from the same-named Hub branch (`.github/actions/hub-image` extended to build all three).
- `e2e-servers-podman`: the same primary on Docker, and the worker as rootless Podman under a second runner user `worker` (its own user socket, linger, subuid range), joined the same way.
- Assertions (one function each in `e2e_servers.py`, in this order):
  - `join_ok`, `join_code_reused_refused`, `join_code_expired_refused` (the Hub's clock advanced via a CI-only `HUB_DEV=1` hook);
  - `echo_on_worker_signed_in` (same TLS tier and factors as an echo on the primary) and `echo_on_worker_denied_without_sign_in`;
  - `no_portcullis_cookie_reaches_app` (whoami echo) and `parent_domain_set_cookie_stripped`;
  - `move_worker_primary_worker_keeps_data`;
  - `wg_stopped_fails_closed` (`docker stop` of wg: the app is unreachable, its containers still run on the worker) and `wg_back_routes_again`;
  - `rogue_worker`:
    - from the worker's netns every port on `10.214.0.1` is closed;
    - server B's agent cert is refused for server A (two dind workers);
    - a forged data preamble for an unplaced instance is refused;
    - an oversized `/info` (a CI-only agent flag `AGENT_TEST_OVERSIZE_INFO=1`, built only with tag `e2etest`) is cut off;
  - `revoke_drops_handshake_and_rotates` (handshake gone within the reload, Keycloak client secret changed) and `revoke_cuts_websocket`;
  - `socket_rule_both_stacks` (only the proxies mount the socket, on both).
- Secrets: the join code goes into a 0700 temp dir and through `::add-mask::`, and is never in artifacts.

- [ ] **Step 1:** Write the jobs and scripts (they fail until Tasks 7–18 are on the branch).
- [ ] **Step 2:** Run `actionlint && bash tests/lint_ci_size.sh && shellcheck .github/ci/e2e-servers-*.sh`. Expected: PASS, ci.yml ≤ 450,000 bytes.
- [ ] **Step 3 (controller):** `gh workflow run ci.yml --ref ms1 -f jobs=e2e-servers,e2e-servers-podman`. Expected: green. Then one full run. Expected: green.
- [ ] **Step 4:** Commit (`ci: e2e-servers (dind worker) and e2e-servers-podman, rogue-worker asserts`).

---

## Docs (Task 20)

### Task 20: Docs pages

**Files:** `docs/operations/servers.md` (new: model, join, placement and primary-only list, move/undo, revoke/remove, DR, break-glass, what works while the primary is down, the cookie rule, bandwidth), `.nav.yml`, `hardening.md` (agent, socket-proxy-agent, link, relays, `pki_node`, the threat model of spec §3; per-service table rows), `backups.md` (worker instances, scheduled backups), `monitoring.md` (job `link`, 3 alerts), `cli.md` (`link …`, `worker …`, restating the real `--help`), `hub.md` (Settings → Servers, Runs on, Move…), `testing.md` (both jobs), `vpn.md` (the link role), `manifest-reference.md` (`placement`), `includes/abbreviations.md`; core `CLAUDE.md` (the socket rule incl. the worker).

- [ ] **Step 1:** Write the pages against the code on `ms1` (verify every statement; report inconsistencies in the commit).
- [ ] **Step 2:** Run the docs gate. Expected: exit 0.
- [ ] **Step 3:** Commit (`docs: servers page and updates for multiple servers`), push, resync Hub `web/docs`.

---

## Deploy (Task 21)

### Task 21: Full CI, merges, deploy to the test server with a second server, cleanup

- [ ] **Step 1 (controller):** Final whole-branch review across the four repos; full core CI, Hub build, templates lint + Test Apps on `ms1`. Expected: green.
- [ ] **Step 2:** Merge in order docs → Hub (wait for `edge` of hub, agent, relay) → templates → core, through detached worktrees (Global Constraints).
- [ ] **Step 3:** Primary: connect with the SSH command and install directory given in `2026-11-13-rootless-podman.md` Global Constraints, `git pull --ff-only && ./portcullis upgrade`, confirm `ACME_STAGING=true` (memory), then run `./portcullis link init`. Opening UDP 51821 in the cloud firewall is the **user's** action; the plan never edits cloud settings.
- [ ] **Step 4: ASK THE USER NOW** (the controller stops here and asks; nothing is assumed):
  - (a) a second server to use as a worker: SSH access, OS, Docker or rootless Podman;
  - (b) optionally a third host behind NAT (or the same second host behind NAT);
  - (c) that UDP 51821 is open on the primary.

  Record the answers in the SDD ledger only (no private identifiers in any repo).
- [ ] **Step 5:**
  - On the worker: check out core main, then `./portcullis worker join`, pasting the code from Hub → Settings → Servers → *Add server*.
  - Expected: `ready` within 5 min, and the Servers page shows runtime, arch, disk and cert expiry.
- [ ] **Step 6:**
  - Create an echo instance *Runs on* the worker; sign in from a browser and check the TLS tier and the step-up as on the primary.
  - Move it to the primary and back, then *Undo move*.
  - Stop `wg` on the primary (fail closed), start it again.
  - Run a scheduled backup at the next hour.
  - Measure throughput through relay + link (`curl` of a 1 GiB file); record it, and if < 200 Mbit/s record the Q2 follow-up.
- [ ] **Step 7:** Behind NAT (if given): join; check keepalive recovery after the NAT mapping expires (idle 10 min, then load the app).
- [ ] **Step 8:** Revoke the NAT worker with *Revoke now* while it's online; check the handshake is gone and its instance is `orphaned`; *forget* it. Remove the other worker cleanly only if the user asks; otherwise keep it as the test worker.
- [ ] **Step 9:** Delete every `ms1` branch (local and remote), every worktree and `/tmp/merge-*`. Update memory (`multi_server_2026_11.md`: rulings, follow-ups, test-server worker kept).

---

## Self-review (done while writing)

- **Spec coverage:**

  | Spec section | Tasks |
  |---|---|
  | §2 | 8–10, by construction |
  | §3 goals 1–5 | 9 and 12, 10 and 11, 8 and 10, 9, 13 and 17–20 |
  | §3 non-goals / anti-goals | Global Constraints, 4–6, 15 |
  | §4 | 5–7, 15, 17, 18 |
  | §5 | 4–6, 8 |
  | §6 | 2, 9, 16 |
  | §7 | 3, 10, 11 |
  | §8 | 10, 13, 17 |
  | §9 | 9, 11 |
  | §10 | 12, 13, 17 |
  | §11 | 1 |
  | §12 | 19, 20; Kubernetes stays a non-goal |
  | §13 parked items | not built |

- **Spec defects found and resolved here:**
  1. `hub_data/link.json`: wg may never mount `hub_data`, so it moves to the `link_doc` volume.
  2. `worker join <code>` would put a secret on argv, so the code goes on stdin.
  3. AI companions aren't addressed, so they are primary-only.
  4. The `node-link` issuance path is unspecified, so the CLI signs it through Vault.
  5. A relay's preamble could name another instance on the same worker, so link writes the preamble.
  6. Folder roots must be enforced by the agent, so they come from the worker host's `.env`.
  7. `primary` must be a reserved id.
  8. enroll needs `pki_node/revoke` too.
  9. Bundles "stored 0600" would make template binds unreadable, so files keep the Hub's modes.
  10. The enrolment HMAC isn't bound to the channel, so the agent SPKI is added.
  11. The override's rootless/SELinux decisions must come from the target server, not the primary (Task 10).
- **Type consistency:** `runtime.Instances` (kube plan) is used throughout. `rtFor` / `runtimes()` are defined in Task 8 and used in 9–13. `agentapi.Info` maps to `runtime.Info` in Task 8. `linkdoc.Doc` is written by the Hub (Task 9) and read by wg (Task 15) through the shared vectors.
