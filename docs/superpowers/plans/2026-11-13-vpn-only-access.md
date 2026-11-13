# VPN-only access (per app and whole server) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an admin make any app instance reachable only through a Portcullis-wired VPN, or switch the whole server to VPN-only except a short public set. Any marketplace VPN app whose template declares a `vpn:` block can be a provider (user ruling 1), and the built-in userspace WireGuard role of a new core `wg` service is the default provider (user ruling 2). The VPN is always an extra condition after the normal sign-in, never a credential.

**Architecture:** Core gains the `wg` service (Go, wireguard-go + gVisor netstack, no capabilities, no TUN). It has two roles in this plan, `edge` and `people`. **edge** is the only PROXY-v2 client of Traefik's new `vpnsecure` entrypoint. It checks every claimed client address against the provider's ranges and its fresh device map. **people** is the built-in WireGuard provider, with its own resolver. The Hub validates `vpn:` blocks and wires providers. It runs their identity and DNS hooks, keeps built-in devices and publishes `hub_data/vpn.json` v2. It renders entrypoints, the `portcullis-vpnallow-<id>` allowlist, the friendly `/vpn-required` router and the gateway network attachment, and writes the policy file v7 `vpn` section. group-gate enforces the device ↔ person binding. The `link` role (server tunnels) reuses the same `wg/internal/tunnel` package and lands with the multi-server plan. The Kubernetes mapping waits for the Kubernetes plan.

**Tech Stack:** Go 1.27 (`wg`, `portcullis-forwarder`: `golang.zx2c4.com/wireguard` + `tun/netstack`, `github.com/pires/go-proxyproto`, `github.com/miekg/dns`, `github.com/prometheus/client_golang`, `github.com/mdp/qrterminal/v3`), Python 3 (group-gate, stdlib `ipaddress`), bash 3.2 + jq (core CLI), Go + vanilla JS (Hub; WebCrypto X25519 and vendored `qrcode-generator`), Python 3 (templates validator; the headscale glue uses only the official Python image's stdlib), GitHub Actions, Zensical.

**Spec:** `/Volumes/workspace/portcullis/portcullis-hub/docs/superpowers/specs/2026-11-13-vpn-only-access-design.md` (revision 2, binding). §16 open questions take their defaults: Q1 keep `10.213.0.0/22` with overlap refusal, Q2 `public_enrol` on, Q3 no binding for internet apps, Q4 userspace only, Q5 verified in Task 10 Step 1 (fallback as the spec says), Q6 60 s, admin-tunable, Q7 A records only. Related: rootless Podman plan `2026-11-13-rootless-podman.md` (runtime abstraction, compat lints, contract §6), multi-server spec (the `link` role).

## Global Constraints

- **Base.** Rootless Podman (`podman1`) must be merged to `main` in all four repos first. If it isn't, stop and wait. Never base on `podman1`.
- **Branches and worktrees.**
  - Branch `vpn1` in core, Hub, templates and docs, at `/Volumes/workspace/portcullis/wt-vpn1/{portcullis,portcullis-hub,portcullis-templates,portcullis-docs}`. Create each with `git -C <main checkout> worktree add -b vpn1 <path> origin/main` and record the base SHAs in the Task 1 commit message.
  - A second templates branch `vpn2` (Task 19) is cut from main after the core merge.
  - Main checkouts may hold others' work: never edit, stash or commit there.
- **Contract first.** Task 1 lands on docs `vpn1` before any code task. After Task 1 and Task 18, resync the Hub copies: `PORTCULLIS_DOCS_DIR=/Volumes/workspace/portcullis/wt-vpn1/portcullis-docs web/docs/sync.sh` in the Hub worktree, then commit `web/docs`.
- **Project rules:**
  - No back-compat or migration code. Policy v6 → v7 and `vpn.json` v2 are a lockstep upgrade with no reader of older versions. The test server is fixed by hand if needed.
  - Prefer the mature libraries listed in Tech Stack. No hand-rolled WireGuard, PROXY or DNS wire code.
  - Identity = the LLDAP username. A marketplace owner `oidc_sub` resolves to a username through Keycloak's LDAP-federated user, never an email.
  - Never name private repos, cloud profiles or account ids in code, docs or commits.
- **Fail closed (each item below gets a test in its task):**
  - The `wg` service is down, or `vpn.json` is missing, unparsable, of an unknown version or key, or has overlapping ranges, while anything needs it → every VPN request is denied by the edge and by group-gate.
  - A provider past its `stale_after` (by the reader's own clock) → its own addresses are denied.
  - A malformed policy `vpn` section denies everything.
  - A VPN-only router never exists on `websecure`.
  - The Hub's engine guard is unverified (503) → hooks don't run, so maps go stale.
  - The Hub refuses `vpn` reach with no live provider (`409` "wire a VPN first") and refuses wiring while `wg` isn't running (`409` "the VPN service isn't running: run ./portcullis vpn init on the host").
- **Never wider:**
  - Every switch only narrows. No admin surface gains a route because a VPN exists.
  - The edge, the allowlist and the binding are added to sign-in, never in place of it. The VPN never counts as a sign-in method or factor.
- **No secrets anywhere visible:**
  - Client private keys never reach the Hub, the server, logs, the audit or an MCP transcript.
  - The host CLI's `vpn add-device` keeps the generated private key in shell variables and stdin only (never argv, never a file), and `tests/test_cli.sh`'s argv grep stays green.
  - Hook stdout is never stored raw, and op records redact it (`secretRedactor`, redact then clip).
- **Runtime matrix (decided; the rootless contract §6 and compat lints apply to `wg` like any core service):**

  | | Docker (rootful) | Rootless Podman | Kubernetes |
  |---|---|---|---|
  | core `wg` (edge, people) | userspace netstack; no `cap_add`, no `devices`, no `sysctls`, no `/dev/net/tun`, not privileged; UDP published by the engine | identical: netstack is an ordinary process in the container. The people UDP port (≥ 51820 > `ip_unprivileged_port_start` 80) goes through rootlessport/pasta, which rewrites the outer source. That is harmless: WireGuard authenticates by key and the reply path is the same forwarder. `restart: always` comes from `docker-compose.podman.yml`, and the `secrets/wg` bind from `docker-compose.podman-selinux.yml` (`Z`) | not on main: no task here. The Kubernetes plan maps `portcullis-vpn` to NetworkPolicy (spec §5) |
  | kernel/TUN WireGuard in core | **refused on every runtime** (Q4 default: userspace only). The existing unit-tests lint "no NET_ADMIN / SYS_ADMIN" (ci.yml:272) plus Task 14's new `wg` lint enforce it | refused | refused |
  | marketplace gateway with TUN + NET_ADMIN (netbird, wireguard) | allowed as today; doctor `vpn_gateway_privileged` Info | `RootlessCompat` rule 6 → `degraded` ("uses TUN/NET_ADMIN inside the rootless network namespace (prefer a userspace mode)"). It works because NET_ADMIN in a rootless container is a capability of the container's user namespace, valid only in the network namespace that namespace owns (the container's own). The client creates its tun device and routes there. Podman bind-passes the 0666 `/dev/net/tun` node, and the host needs the `tun` module loaded (the docs give `modprobe tun` / `modules-load.d`). The forwarder shares that netns (`network_mode: service:`), so it sees tunnel source addresses. Nothing reaches host networking | refused unless userspace (Kubernetes plan) |
  | headscale gateway (`tailscale/tailscale`, `TS_USERSPACE=true`) | ok, no caps | ok | ok (userspace) |

  - The Hub's new engine calls (hook exec, gateway inspect for `vpn_gateway_privileged`) all go through the guarded client (rootless plan Task 2).
  - `wg` never touches the engine socket. The Hub reads `wg` state from `wg_data/status.json`, never through the engine.
- **TDD everywhere.** Write the failing test, see it fail, implement, see it pass, commit. Gates:
  - Core: `bash tests/test_shell_libs.sh && bash tests/test_cli.sh && shellcheck -S warning portcullis scripts/lib/*.sh tests/*.sh && actionlint && python3 -m pytest -q tests/test_group_gate.py`, plus `cd wg && gofmt -l . && go vet ./... && go test -race ./...` and the same in `forwarder`.
  - Hub: `go vet ./... && go test -race ./... && gofmt -l .` (gofmt prints nothing).
  - Templates: `python3 tests/validate.py && python3 tests/test_validate.py`.
  - Docs: `python3 scripts/check-lists.py && bash scripts/check-branding.sh && zensical build --strict --clean`.
- **CI.**
  - Core: dispatch targeted runs with `gh workflow run ci.yml --ref vpn1 -f jobs=<names>`, then one full run. Only the controller dispatches core CI on `vpn1` (the concurrency group cancels).
  - Task 17 adds the job `e2e-vpn` and its name to the `workflow_dispatch` description list (`jobs-input` reads names from ci.yml with `yq`).
  - Hub: `gh workflow run build.yml --ref vpn1`. Templates: lint.yml and Test Apps on `vpn1`.
- **Merges** (spec order docs → Hub → templates → core; core and Hub land together for policy v7 / `vpn.json` v2):
  - Merge each repo through a detached worktree: `git worktree add --detach /tmp/merge-<repo> origin/main` → `git merge --no-ff origin/vpn1 -m "merge vpn1: …"` → push → `git worktree remove`.
  - After the Hub merge, run `gh workflow run build.yml --ref main -f compare_ref=vpn1` and wait for `edge`.
  - Then merge templates `vpn1`, then core **at once**. In the window between Hub and core, `edge` writes policy v7 and core main's group-gate serves v6, so every app is denied: dispatch no core CI on main and upgrade no server in that window.
  - After core main publishes `ghcr.io/porelli/portcullis-forwarder:edge`, do Task 19 (templates `vpn2`).
  - Finally delete every `vpn1`/`vpn2` branch (local and remote), every worktree and `/tmp/merge-*` (memory: branches mainlined).
- **Test server (Task 20):** connect with the SSH command and install directory given in `2026-11-13-rootless-podman.md` Global Constraints, then `git pull --ff-only && ./portcullis upgrade`. `ACME_STAGING=true` stays (memory). Never touch the LLDAP `admin` user. Opening UDP 51820 in the server's cloud firewall is the user's action; the plan never edits cloud settings.
- **Values from the spec (verbatim):**
  - `wg`:
    - uid **10006**, read_only, `cap_drop: ALL`, `no-new-privileges`, compose profile **`wg`** (off by default).
    - people: key `secrets/wg/people.key`, `${PORTCULLIS_VPN_PORT:-51820}/udp`, tunnel `${PORTCULLIS_VPN_SUBNET:-10.213.0.0/22}`, server `.1`, MTU **1280**, client `AllowedIPs = 10.213.0.1/32`, `DNS = 10.213.0.1`.
    - Netstack listeners: TCP 443 (to edge), TCP 80 (`308` to https), UDP/TCP 53.
    - Link reserved (not built here): `secrets/wg/link.key`, `${PORTCULLIS_LINK_PORT:-51821}/udp`, `${PORTCULLIS_LINK_SUBNET:-10.214.0.0/24}`.
  - Networks: `portcullis-vpn` internal, `${PORTCULLIS_VPN_NET:-172.31.254.0/26}`: Traefik `.2`, `wg` `.3`, gateways `.16`–`.62`. `wg-egress` for the UDP ports and resolver upstreams.
  - Edge: one TCP port per wired provider, **`9001 + slot`**, on `wg`'s `portcullis-vpn` address. PROXY v2 header within **5 s**. Metric `wg_edge_rejected_total{provider,reason}`.
  - Traefik: `vpnsecure` at `${PORTCULLIS_VPN_TRAEFIK_IP:-172.31.254.2}:8443`, `PROXYPROTOCOL_TRUSTEDIPS` = `wg`'s IP only, `aliasHeadersStrategy: delete`, no `forwardedHeaders.trustedIPs`/`insecure`.
  - Resolver upstream `${PORTCULLIS_VPN_DNS_UPSTREAM:-1.1.1.1,9.9.9.9}`. Rewrite A → `10.213.0.1`, AAAA → NODATA, never AD, RRSIGs stripped.
  - `vpn:` block:
    - `label` single line 1–64.
    - `ranges` 1–8 IPv4, each /8–/30, no overlaps.
    - `proxy_protocol: v2` only.
    - `identity.source` `hook|static`, `owner` `oidc_sub|username`, `refresh` 15s–10m, default 60s.
    - `dns` exactly one of `hook` / `manual: true`.
  - Hook stdin `{"version":1,"trigger":"vpn","instance":"<id>","op":"devices","ranges":[...]}`. Stdout ≤ **4 MiB**, ≤ **10 000** devices. Stale = `3 × refresh`, at least **3 min**.
  - Built-in devices:
    - **Devices per person 10**; expiry default **1 year** (Settings: 30 d–never); a removed address is quarantined **7 days**.
    - Fresh sign-in max age **5 min**.
    - The lock-out guard wants an admin device seen in the last **10 minutes**.
    - Doctor windows: `vpn_no_admin_device` 30 days, `vpn_device_stale` 90 days, `vpn_expiring` 14 days.
  - Policy **v7** `vpn` = `{"hosts": {"<hostname>": {"via": ["*"]}}, "server_mode": false, "admin_only": false, "public_enrol": true, "devices_file": "vpn.json"}`; `vpn.json` **version 2** (spec §6.4 shape plus the additions in Task 1).
  - Names:
    - Hub-rendered: `portcullis-vpnallow-<id>` (middleware), `portcullis-vpnonly-<id>` (friendly router).
    - The prefix `portcullis-vpn` is reserved for the Hub.
    - Core: router `people-vpn-enrol` (`PathPrefix(/vpn/)`).
    - Entrypoint variables `${PORTCULLIS_EP_CORE:-websecure,vpnsecure}`, `${PORTCULLIS_EP_ADMIN:-…}`, `${PORTCULLIS_EP_ENROL:-…}`.
  - Copy:
    - `/vpn-required`: "This app is only reachable over a Portcullis VPN. Connect your device and reload."
    - Reason pages: "this device isn't yours; sign in on your own device", "your VPN's device list is out of date; try again in a minute".
- **Values this plan adds (assistant's calls, binding for every task):**
  - `.env` `PORTCULLIS_VPN_BUILTIN=on|off` (written by `vpn init`; its default flag is `on`; the compose default when unset is `off`; an empty key file also means off).
  - `.env` `PORTCULLIS_VPN_MODE=apps|admin|server` (default `apps`) and `PORTCULLIS_VPN_PUBLIC_ENROL=true|false` (default `true`).
  - `PORTCULLIS_VPN_WG_IP` (default `172.31.254.3`).
  - The Hub's core.env gets `PORTCULLIS_VPN_MODE`, `PORTCULLIS_VPN_PUBLIC_ENROL`, `PORTCULLIS_VPN_NET`, `PORTCULLIS_VPN_BUILTIN`. None is a template variable: contract §2 lists them as reserved, and the validator refuses `${PORTCULLIS_VPN_*}` (`$$PORTCULLIS_VPN_EDGE` shell references are allowed).
  - `wg` runs as `10006:10006` with `group_add: ["10001"]`. `vpn.json` (Hub-written) and `wg_data/status.json` (`wg`-written) are 0640 with group 10001, so group-gate (10003 + group 10001) and the Hub read them. This replaces the spec's "group 10006" wording.
  - Policy `devices_file` must be exactly `"vpn.json"` (any other value denies).

## Review Focus

1. **A gateway service with no `networks:` key** (implicit `default`). Adding `portcullis-vpn` in the override must keep `default` and any declared networks, or the gateway loses its app network and egress and the provider silently goes stale. Pinned by `TestGatewayOverrideKeepsTemplateNetworks` (Task 5).
2. **A person deleted and re-created in LLDAP under the same username.** The new account must not inherit the old one's built-in devices. Devices record the LLDAP uuid and are dropped on mismatch, and marketplace owners resolve through the Keycloak id, which changes on re-creation. Pinned by `TestRecreatedPersonDoesNotInheritDevices` (Task 6).
3. **The Hub restarts.** It must not republish a marketplace map with a fresh `stale_after` before a good hook run (that would extend stale data). Marketplace providers are published `stale: true` until their first good run. Pinned by `TestStartPublishesMarketplaceProvidersStale` (Task 4).
4. **A device's `expires` passes while the Hub is stopped.** `wg` must drop the peer and group-gate must deny it by their own clocks, without a new `vpn.json`. Pinned by `TestExpiredPeerDroppedByClock` (Task 12) and `test_expired_device_denied_by_clock` (Task 16).
5. **A Portcullis name that is a CNAME** (`app.<d>` CNAME `<d>`, and `docs.<d>` CNAME to a foreign host). The resolver rewrites the final A that points at this server, strips the RRSIGs and leaves foreign chains untouched. Pinned by `TestRewriteCNAMEChain` (Task 12).

## Pre-flight rulings (V1–V26)

1. **V1**: Forwarder image renamed `ghcr.io/porelli/portcullis-forwarder` (reserved prefix kept absolute; forwarder exception in validators) — Tasks 1, 2, 9, 13, 19
2. **V2**: `wg`/`wg_data` added to reserved core names — Tasks 1, 2, 9
3. **V3**: Core lint updates (46 binds, Dockerfile lists, hub_data consumers, Go cache, dependabot, fully qualified inline images) — Tasks 14, 17
4. **V4**: `vpn init` genkey fix (ct_run, user 0:0, truncate+write, secrets_fix_perms, stub tests) — Task 15
5. **V5**: `wg_data` ownership (volume_own 10006:10001, directory 2750, wg chgrps files) — Task 14
6. **V6**: vpndoc vectors path `../../../tests/vpn_json_vectors.json` — Task 11
7. **V7**: Task 4 adds no-op `vpnRangesChanged()` hook; Task 5 implements override re-render — Tasks 4, 5
8. **V8**: Fresh-auth per-host model (people → `{/signin, /vpn/}`, hub → `{/}`; deduplicated origins) — Tasks 1, 6
9. **V9**: MCP parity gaps (`assign_vpn_address` AlsoTwins DELETE; settings/DNS-ack noToolRoutes reasons) — Task 7
10. **V10**: VPN hook exclusions beside ai hooks (reload.hook, delivery.hook, with vectors) — Tasks 2, 9
11. **V11**: Forwarder also gets `PORTCULLIS_VPN_EDGE` env (set on `network_mode: service:<ingress>` services) — Tasks 1, 5, 19
12. **V12**: Forwarder `cap_add: [NET_BIND_SERVICE]` (Podman `:443` bind), test both runtimes — Task 19
13. **V13**: Prometheus `wg` via `file_sd` (written by `vpn init`/`builtin`, empty when profile off), promtool test — Task 15
14. **V14**: Headscale cleanup (backup lines 10, 328, 860–862; remove apps file services/volume, README line) — Task 15
15. **V15**: Glue script allowed per spec §4 amendment (distroless confirmed, stdlib-only in official interpreter image), doctor note API key expiry — Task 10
16. **V16**: Headscale gateway bootstrap (entrypoint wrapper, `TS_SERVE_CONFIG` generated, `--proxy-protocol` proved) — Task 10
17. **V17**: Group-gate gaps (`/portal` backend vpn_check class `core`, public guard steps 1–2 only) — Task 16
18. **V18**: `vpnAssets` serves fresh-auth scripts under `/vpn/assets/` (reachable in server mode) — Tasks 1, 6
19. **V19**: Merge-window outage confirmed real (order forced docs → Hub → templates → core) — noted
20. **V20**: `PORTCULLIS_VPN_IP_RANGE` variable, validated in network.sh; Hub derives gateways from VPNNet — Task 14
21. **V21**: WebCrypto X25519 instead of noble (generateKey, export raw public + last 32 bytes of PKCS#8 private) — Task 6
22. **V22**: Build risk spike (Step 0: build + TestTunnelRoundTrip in golang:1.27.3, allow newer gVisor if needed) — Task 11
23. **V23**: Metrics bind to `portcullis` interface address (not `:9100` on all interfaces) — Task 12
24. **V24**: Builtin default wording clarified (`vpn init --builtin` default `on`; compose default `off`; empty key = off) — Global Constraints
25. **V25**: Rootless CI coverage (small step in e2e-podman: vpn init, wg healthy, built-in handshake+GET) — Task 17
26. **V26**: Textual fixes (Task 4 lastDNSErr field, Task 6 start RunVPNExpiry, Task 19 netbird routers netbird-mgmt/netbird-signal, contract §16 multi-server spec reference, Task 15 keep netbird Keycloak client, Task 18 DNSSEC cross-link) — Tasks 1, 4, 6, 15, 18, 19

---

## File structure

**Docs (`wt-vpn1/portcullis-docs`):** `docs/guides/integration-contracts.md`; `docs/operations/vpn.md` (new) + `.nav.yml`; `hardening.md`, `auth-policies.md`, `hub.md`, `cli.md`, `backups.md`, `monitoring.md`, `testing.md`; `docs/guides/manifest-reference.md`; a person-facing VPN section in the Sign-in guide (`docs/operations/hub.md` "Sign-in page"); `includes/abbreviations.md`.

**Hub (`wt-vpn1/portcullis-hub`)**

| File | Responsibility |
|---|---|
| `internal/templates/vpn.go` (new), `testdata/vpn_vectors.json` (new) | `VPN` manifest types, `HookVPN`, `ValidateVPN`, `ResolveVPNRanges`; shared refusal vectors |
| `internal/vpn/` (new, pure: `doc.go`, `ranges.go`, `alloc.go`, `hookdoc.go`, `status.go`, `testdata/vpn_json_vectors.json`) | `vpn.json` v2 types + writer, range rules, address allocation, hook document parsing, `wg` status reader; shared reader vectors (core keeps a byte copy) |
| `internal/state/vpn.go` (new) | `Reach`, `VPNState` (settings, wired providers, built-in devices, quarantine, static assignments) |
| `internal/keycloak/usersbyid.go` (new) | `UsernamesByID` |
| `internal/hub/vpn_providers.go`, `vpn_publish.go`, `vpn_devices.go`, `vpn_reach.go`, `vpn_render.go`, `doctor_vpn.go` (new); `override.go`, `public.go`, `reconcile.go` (drift), `internal/policy/file.go` | wiring, hook runners, publishing, devices, reach, rendering, drift, policy v7 |
| `internal/doctor/vpn.go` (new) | The 14 VPN kinds |
| `internal/httpapi/vpn.go`, `vpn_people.go`, `mcptools_vpn.go`, `hostctl.go` (new); `server.go`, parity test files | admin routes, people `/vpn/` routes, MCP tools, the host control socket |
| `cmd/hub/main.go`, `cmd/hub/vpn.go` (new) | wiring, `hub vpn …` subcommands (control socket client) |
| `web/vpn.html`, `web/vpn.js`, `web/vendor/noble-x25519.js`, `web/vendor/qrcode.js` (new); `web/index.html`, `web/mysignin.js`, `web/directory.js`, `web/web.go` | device page, admin UI, Sign-in list, People → VPN devices |

**Templates (`wt-vpn1/portcullis-templates`):** `schema/manifest.schema.json`, `tests/validate.py`, `tests/test_validate.py`, `tests/vpn_vectors.json` (byte copy), `tests/e2e/app_signin.py` (policy v7), `headscale/{manifest.yaml,compose.yml,config/config.yaml,vpn/glue.py}`, `tests/apps/headscale.sh`, `CLAUDE.md`, `CONTRIBUTING.md`; on `vpn2`: `netbird/*`, `wireguard/*` (new), `tests/apps/{netbird,wireguard}.sh`, `.github/dependabot.yml`.

**Core (`wt-vpn1/portcullis`)**

| File | Responsibility |
|---|---|
| `wg/` (new Go module: `main.go`, `internal/{vpndoc,tunnel,edge,people,resolver,status}`, `Dockerfile`) | the `wg` service and its subcommands |
| `forwarder/` (new Go module + `Dockerfile`), `.github/workflows/forwarder.yml` (new) | `portcullis-forwarder` image, published to GHCR |
| `docker-compose.yml`, `docker-compose.podman.yml`, `docker-compose.podman-selinux.yml` | `wg`, networks, `vpnsecure`, entrypoint variables, `people-vpn-enrol`, `vpn-required` middleware, Hub mounts |
| `group-gate/group-gate.py`, `tests/test_group_gate.py`, `tests/vpn_json_vectors.json` (byte copy) | policy v7, `vpn.json` reader, binding, core-host classes, `/vpn-required` |
| `scripts/lib/vpn.sh` (new), `network.sh`, `common.sh`, `status.sh`, `stack.sh`, `backup.sh`, `keycloak.sh`, `portcullis` | `vpn …` commands, network validation, core.env, status, cleanup |
| `monitoring/prometheus/{prometheus.yml,alerts.yml,tests/alerts_test.yml}` | `wg` job, two alerts |
| `.github/workflows/ci.yml`, `tests/e2e/e2e_vpn.py`, `tests/e2e/vpn-client/` (new) | static checks, "Test the VPN service", `e2e-vpn` |
| `headscale/config.yaml` (deleted), `CLAUDE.md`, `.env.example`, `CHANGELOG.md` | cleanup, rules |

---

### Task 1: Contract (docs, first)

**Files:**
- Modify: `docs/guides/integration-contracts.md`:
  - §2 (reserved `PORTCULLIS_VPN_*`)
  - §3 (entrypoints, reserved names) and new §3.3
  - §4 (policy v7)
  - §5, §5.1
  - §11 (reach, wiring)
  - §13.8 (the `vpn` trigger)
  - §13.15 / §14.5 / §14.7
  - §15.10
  - new §16
- Modify (Hub): `web/docs/*` via `sync.sh`

**Interfaces — Produces (binding for Tasks 2–19):**
- §3:
  - Templates set only `entrypoints: websecure`.
  - No key or value may contain `portcullis-vpn`, except the forwarder image `ghcr.io/porelli/portcullis-forwarder` (V1).
  - No `${PORTCULLIS_VPN_*}` compose interpolation; the container-shell `$$PORTCULLIS_VPN_EDGE` is allowed.
  - Reserved core names: `wg` service, `wg_data` volume (V2).
- §3.3: the `vpn:` block exactly as spec §4, with these refusal texts (shared by the Hub and validate.py, Task 2 vectors):
  - `vpn.label: a single line of 1–64 characters`
  - `vpn.ranges: 1–8 IPv4 prefixes`
  - `vpn.ranges[<i>]: <v> is not an IPv4 prefix between /8 and /30`
  - `vpn.ranges: <a> overlaps <b>`
  - `vpn.ranges[<i>]: {{setting:<k>}} must name a cidr setting`
  - `vpn.ingress.service: <s> is not a service of compose.yml`
  - `vpn.ingress.service: <s> has network_mode`
  - `vpn.ingress.service: <s> is a job` / `is an AI companion` / `has a Traefik router`
  - `vpn.ingress.proxy_protocol: only v2`
  - `vpn.identity.hook: <h> is not a hook with exactly when: [vpn]`
  - `vpn.identity.owner: oidc_sub or username`
  - `vpn.identity: source static takes no hook or owner`
  - `vpn.identity.refresh: between 15s and 10m`
  - `vpn.dns: exactly one of hook and manual: true`
  - `vpn.control_routers: <r> is not a host router of the template`
  - `vpn.control_routers: <r> serves an admin UI`
  - `hooks[<n>]: when: [vpn] needs a vpn: block that names it`
  - `hooks[<n>]: vpn can't be combined with other triggers`
- §13.8: the `vpn` trigger.
  - Stdin `{"version":1,"trigger":"vpn","instance":"<id>","op":"devices","ranges":[…]}`, or `"op":"dns","records":[{"name","type":"A","value"}]`.
  - `devices` stdout: the spec §6.1 document, version 1. `dns` stdout: ignored, exit 0 = applied.
  - Timeout = the hook's `timeout` (default 30 s). Never run by the settings engine.
- §4:
  - Policy v7 = v6 plus the required key `vpn` (Global Constraints shape).
  - `hosts` keys are valid hostnames. `via` is `["*"]` or 1–8 provider ids (`builtin` or an instance id).
  - The binding rule (spec §8.2 steps 1–3) and the reason texts.
  - The client address is the **last** `X-Forwarded-For` entry.
  - Core-host classes (assistant's call: a fixed table in group-gate, map.conf unchanged):
    - `admin` = `traefik.`, `hub.`, `directory.`, `metrics.`, and `auth.` (console);
    - `core` = `<d>`, `people.`;
    - `enrol` = `people.` paths under `/vpn/` with `public_enrol`.
  - VPN-only core hosts require the full binding (steps 1–3).
  - `vpn.json` v2 = spec §6.4, plus `builtin.peers[].expires` (RFC 3339 or null; readers drop a peer past it by their own clock).
  - The file is 0640, group 10001. The fail-closed reader rules come from spec §6.4.
- §5:
  - `vpnsecure`.
  - Rendering per reach × mode × via: internet → `websecure,vpnsecure`; VPN-only → `vpnsecure` with `portcullis-vpnallow-<id>` (`ipallowlist.sourcerange` = the accepted providers' ranges, joined by `,`, `rejectstatuscode: 403`) first in every chain.
  - Control routers keep `websecure,vpnsecure`.
  - `portcullis-vpnonly-<id>`: rule `Host(a) || Host(b) …`, priority 1, `websecure`, the instance's TLS tier, middlewares `vpn-required-path@docker`, service `group-gate@docker`.
  - Drift compares entrypoints, the allowlist ranges and its position.
  - The gateway attachment: the ingress service's networks = the template's (or `default`) + `portcullis-vpn: {ipv4_address: <gw>}`, and env `PORTCULLIS_VPN_EDGE=<wg ip>:<9001+slot>` on that service **and** every service with `network_mode: service:<ingress>` (V11).
- §5.1, the people routes:
  - `GET /vpn/` (page), `GET /vpn/assets/<file>` (V18: `vpnAssets` serves its own copies of the fresh-auth scripts, so they stay reachable in server mode), `GET|POST /vpn/api/devices`, `PUT|DELETE /vpn/api/devices/{id}`, `POST /vpn/api/devices/{id}/renew`.
  - The fresh-auth redirect URI `https://people.<d>/vpn/` (V8: the model is per-host: people → `{/signin, /vpn/}`, hub → `{/}`; deduplicated web origins).
  - People → person: `GET|DELETE /api/people/{user}/vpn-devices[/{id}]` (admins and `manage_signin`).
- §11:
  - `state.yaml` `reach` and `vpn`.
  - The admin API: `GET /api/vpn`, `PUT /api/vpn/settings`, `PUT /api/instances/{id}/vpn-provider` `{wired, refresh}`, `PUT /api/instances/{id}/reach` `{mode, via, public_links}`, `PUT|DELETE /api/instances/{id}/vpn-static/{ip}` `{user, name}`, `POST /api/instances/{id}/vpn-dns/ack`, `GET /api/vpn/devices[?user=]`, `DELETE /api/vpn/devices/{id}`.
  - The 409s from Global Constraints.
  - Audit actions: `vpn.provider_wired|unwired`, `vpn.static_assigned|unassigned`, `instance.reach`, `vpn.public_links`, `vpn.settings`, `vpn.device_added|renamed|removed|expired`. Never key material.
- §13.15 / §14.7: Local networks never count for VPN-only access, plus the overlap rules of spec §4. §14.5: the 14 kinds of spec §12.
- §15.10 tools:
  - `get_vpn` (R, twin `GET /api/vpn`)
  - `list_vpn_devices` (R)
  - `remove_vpn_device` (D)
  - `set_vpn_provider` (D)
  - `assign_vpn_address` (D)
  - `set_instance_reach` (D)
- §16 VPN and the `wg` service:
  - Roles, the separation rules (spec §3.1) and the networks/addresses.
  - Edge ports and accept rules (spec §5).
  - Files: `secrets/wg/people.key` 0640 group 10006, `wg_data/status.json`.
  - `status.json` v1:

    ```json
    {"version":1,"written":"<rfc3339>","mode":"apps","edge":{"ok":true,"error":""},
     "people":{"ok":true,"error":"","public_key":"…","port":51820,"subnet":"10.213.0.0/22","mtu":1280,
               "peers":[{"public_key":"…","last_handshake":"<rfc3339>|null"}]}}
    ```

    `people` is null when the role is off. The Hub treats a file older than 30 s as "wg down".
  - The CLI: `vpn init|mode|builtin|add-device|devices|revoke`.
  - The host control socket: the Hub listens on `/tmp/hub-host.sock` (0600, its tmpfs). `hub vpn add-device|devices|revoke|host-info` inside the Hub container are its only clients; it has no HTTP route on any listener.
  - The forwarder image `ghcr.io/porelli/portcullis-forwarder` (listens `:443`, forwards to `$PORTCULLIS_VPN_EDGE` with PROXY v2).
  - The multi-server spec references the `link` role (V26).

- [ ] **Step 1:** Write the sections in the contract's existing style ("NEW (VPN)" markers).
- [ ] **Step 2:** Run the docs gate. Expected: exit 0.
- [ ] **Step 3:** Commit (`docs: contract for VPN-only access (vpn: block, vpn hook, policy v7, vpn.json v2, vpnsecure, wg service §16)`) and push `vpn1`.
- [ ] **Step 4:** Resync the Hub `web/docs` (Global Constraints). Check that `git diff --stat web/docs` lists only `integration-contracts.md`, then commit (`docs: sync contract`) and push.

---

### Task 2: Hub `vpn:` block validation and the `vpn` hook trigger

**Files:**
- Create: `internal/templates/vpn.go`, `internal/templates/vpn_test.go`, `internal/templates/testdata/vpn_vectors.json`
- Modify:
  - `internal/templates/manifest.go` (`Manifest.VPN`)
  - `internal/templates/settings.go` (`HookVPN`, `HookTriggers`, `(*Hook) IsVPN`, `sortedHooks` exclusion in `internal/hub/deliver_hooks.go:126`, plus V10: `reload.hook` and option `delivery.hook` exclusions, with vectors)
  - `internal/templates/coreref.go:37` (`reservedRefs` += `"portcullis-vpn"`, forwarder image exception V1; `coreServices` += `wg`, `coreVolumes` += `wg_data` V2)
  - `internal/templates/reservedvars.go` (`PORTCULLIS_VPN_*`)
  - `internal/templates/discover.go` (call `ValidateVPN` after `ValidateAI`)
  - `internal/hub/realtemplates_test.go`, `CLAUDE.md`

**Interfaces — Produces:**
- `templates.VPN{Label string; Ranges []string; Ingress VPNIngress; Identity VPNIdentity; DNS VPNDNS; ControlRouters []string}` (yaml/json snake_case, strict `UnmarshalYAML` like `AI`).
- `VPNIngress{Service, ProxyProtocol string}`, `VPNIdentity{Source, Hook, Owner string; Refresh Duration}`, `VPNDNS{Hook string; Manual bool}`.
- `const HookVPN = "vpn"`, `(*Hook) IsVPN() bool`, `const VPNReservedPrefix = "portcullis-vpn"`.
- `ValidateVPN(t *Template, compose []byte, routes *Routes) error` (the §3.3 texts). V1: accept `ghcr.io/porelli/portcullis-forwarder` in `image:` values.
- `ResolveVPNRanges(m *Manifest, values map[string]any) ([]netip.Prefix, error)` (literals, or the `{{setting:KEY}}` cidr value).
- `(VPNIdentity) EffectiveRefresh() time.Duration` (0 → 60 s).

- [ ] **Step 1: Write the failing tests.**
  - `vpn_vectors.json`: an array of `{name, manifest, compose, want_error}` where `want_error` is the exact §3.3 text or `""`. One vector per refusal in Task 1, plus:
    - "headscale-shaped ok"
    - "static ok"
    - "range via cidr setting ok"
    - "range via a string setting refused"
    - "ingress has a router refused"
    - "hook with [vpn, start] refused"
    - "vpn hook nobody names refused"
    - "control router = the admin_paths router refused"
  - `TestVPNVectors` iterates the vectors.
  - `TestTemplateMentioningPortcullisVPNRefused` (a label value `portcullis-vpnallow-x@docker` → `checkCoreRefs` error).
  - `TestReservedVPNVarRefused` (`${PORTCULLIS_VPN_EDGE}` refused, `$$PORTCULLIS_VPN_EDGE` accepted).
  - `TestVPNHooksNeverDelivered`: `sortedHooks` drops `vpn` hooks, as it drops `ai` hooks. V10: also refuse vpn as `reload.hook` and option `delivery.hook`, with vectors.
  - `TestRealTemplatesVPN` (skips without `PORTCULLIS_TEMPLATES_DIR`): every real template still loads.
- [ ] **Step 2:** Run `go test ./internal/templates/ ./internal/hub/ -run 'VPN|ReservedVPN'`. Expected: FAIL (undefined `VPN`).
- [ ] **Step 3: Implement** in `vpn.go` with `net/netip` (`ParsePrefix`, `Overlaps`, `Masked` equality), reusing `routes.HostRouters`, `kindOf` (companion), `Manifest.Jobs` and `ServiceNetworks(compose)` for the ingress checks. In Hub `CLAUDE.md`, add one sentence to the `internal/templates` row.
- [ ] **Step 4:** Run the Hub gates. Expected: PASS.
- [ ] **Step 5:** Commit (`templates: vpn: block (ValidateVPN + shared vectors), the exclusive vpn hook trigger, portcullis-vpn reserved`).

---

### Task 3: Hub `internal/vpn` (pure): `vpn.json` v2, ranges, allocation, hook documents, `wg` status

**Files:**
- Create: `internal/vpn/{doc.go,ranges.go,alloc.go,hookdoc.go,status.go}`, their `_test.go` files, `internal/vpn/testdata/vpn_json_vectors.json`
- Modify: `CLAUDE.md` (layout row)

**Interfaces — Produces:**
- Constants:
  - `DocVersion = 2`, `HookDocVersion = 1`, `StatusVersion = 1`
  - `MaxHookOutput = 4 << 20`, `MaxDevices = 10000`
  - `RefreshMin = 15*time.Second`, `RefreshMax = 10*time.Minute`, `RefreshDefault = time.Minute`, `StaleFloor = 3*time.Minute`
  - `Quarantine = 7*24*time.Hour`, `DefaultDevicesPerPerson = 10`, `DefaultExpiry = 365*24*time.Hour`, `MinExpiry = 30*24*time.Hour`
  - `EdgePortBase = 9001`, `GatewayFirst = 16`, `GatewayLast = 62`, `BuiltinMTU = 1280`, `StatusMaxAge = 30*time.Second`
- Types (JSON exactly the contract):
  - `Doc{Version int; Builtin *Builtin; Providers []Provider; Devices []Device}`
  - `Builtin{Subnet string; ServerPublicKey string; Domains []string; Peers []Peer}`
  - `Peer{IP, PublicKey, DeviceID string; Expires *time.Time}`
  - `Provider{ID, Label string; Ranges []string; EdgePort int; GatewayIP string; RefreshedAt, StaleAfter *time.Time; Stale bool}`
  - `Device{IP, Provider, User, DeviceID, Name string; Expires *time.Time}`
- Functions:
  - `Write(path string, d Doc) error`: `fsutil.WriteFileAtomic`, 0640, then `os.Chown(path, -1, 10001)`.
  - `Parse(b []byte) (*Doc, error)`: strict (`DisallowUnknownFields`); version 2 only; ranges disjoint; addresses unique. It is the reference reader the vectors drive.
  - `ParseRanges(rs []string) ([]netip.Prefix, error)`, `FirstOverlap(a, b []netip.Prefix) (netip.Prefix, netip.Prefix, bool)`.
  - `NextFree(subnet netip.Prefix, used map[netip.Addr]bool, quarantined map[netip.Addr]time.Time, now time.Time) (netip.Addr, error)`: skips network, `.1`, broadcast, used and quarantined-within-7-days; `ErrSubnetFull`.
  - `GatewayAddr(net netip.Prefix, slot int) (netip.Addr, error)` (slot 0 → `.16`, 46 → `.62`), `EdgePort(slot int) int`.
  - `StaleAfter(refreshedAt time.Time, refresh time.Duration) time.Time` (`refreshedAt + max(3*refresh, StaleFloor)`).
  - `HookInput{Version int; Trigger, Instance, Op string; Ranges []string; Records []Record}`, `Record{Name, Type, Value string}`.
  - `ParseHookDevices(out []byte, ranges []netip.Prefix) (*HookDevices, error)`.
    - `HookDevices{Gateway netip.Addr; Devices []HookDevice; Dropped []Dropped}`.
    - `HookDevice{ID, Name, Owner string; Address netip.Addr; Online bool; LastSeen, Expires *time.Time}`, `Dropped{ID, Reason string}`.
    - Refusals: over 4 MiB, over 10 000 devices, version ≠ 1, unknown keys, gateway missing or outside the ranges, an IPv6 `address` ignored (dropped, reason `ipv6`), outside the ranges (`outside_ranges`), duplicate addresses (every device with it dropped, `duplicate`), expired (`expired`). The gateway's own address is never a device (`gateway`).
  - `Status`, matching the §16 shape. `ReadStatus(path string, now time.Time) (*Status, error)`: `ErrStatusStale` when `written` is older than 30 s or in the future by more than 30 s.

- [ ] **Step 1: Write the failing tests.**
  - `vpn_json_vectors.json`: an array of `{name, doc, now, want: "ok" | "<error substring>", deny: [{ip, provider}]}`. Core's two readers run this file too (Tasks 12 and 16). Vectors:
    - "valid two providers"
    - "unknown top-level key"
    - "version 1"
    - "overlapping provider ranges"
    - "duplicate device ip"
    - "provider past stale_after denies its own"
    - "peer past expires dropped"
    - "missing builtin with a builtin provider"
  - `TestParseVectors` (the Go reference reader).
  - `TestWriteMode0640Group` (skips when not root; else checks mode and gid).
  - `TestNextFreeQuarantine`: an address removed 6 days ago is skipped, one removed 8 days ago is reused; `.1` and broadcast are never handed out; a full /30 gives `ErrSubnetFull`.
  - `TestGatewayAddrSlots` (0 → .16, 46 → .62, 47 → error).
  - `TestStaleAfterFloor` (15 s refresh → +3 min; 2 min → +6 min).
  - `TestParseHookDevices`: one subtest per refusal and drop reason above, plus "5 MiB → error", "10 001 devices → error", "the gateway listed as a device is dropped".
  - `TestReadStatusStale`.
- [ ] **Step 2:** Run `go test ./internal/vpn/`. Expected: FAIL.
- [ ] **Step 3:** Implement. Parse with `encoding/json`'s `Decoder.DisallowUnknownFields` and `netip` throughout.
- [ ] **Step 4:** Run the Hub gates. Expected: PASS.
- [ ] **Step 5:** Commit (`vpn: vpn.json v2 writer and reference reader (shared vectors), ranges, allocation with quarantine, hook documents, wg status`).

---

### Task 4: Hub providers: wiring, identity and DNS hooks, static assignments, publishing

**Files:**
- Create: `internal/state/vpn.go`, `internal/keycloak/usersbyid.go`, `internal/hub/vpn_providers.go`, `internal/hub/vpn_publish.go`, and tests (`internal/hub/vpn_providers_test.go`, `vpn_publish_test.go`, `internal/keycloak/usersbyid_test.go`)
- Modify:
  - `internal/state/state.go` (`AppState.Reach`, `AppState.VPN`)
  - `internal/hub/hub.go` (`Config.VPNStatusFile`, `Config.VPNNet`; core.env keys)
  - `cmd/hub/main.go` (`HUB_VPN_STATUS_FILE` default `/wg-data/status.json`, `go h.RunVPNMaps(ctx, 5*time.Second)`)
  - `wireDirectoryHooks` (`OnChange` → `TriggerVPNPublish`)

**Interfaces:**
- Consumes: Task 2 (`Manifest.VPN`, `ResolveVPNRanges`, `IsVPN`) and Task 3 (everything).
- Produces:
  - `state.Reach{Mode string; Via []string; PublicLinks bool}` (yaml `mode`, `via`, `public_links,omitempty`).
  - `state.VPNState{UsersGroup string; DevicesPerPerson int; Expiry string; BuiltinOff bool; Providers map[string]VPNProvider; Devices []VPNDevice; Quarantine map[string]time.Time; Static map[string][]VPNStatic}`.
  - `state.VPNProvider{Slot int; Refresh templates.Duration; WiredAt time.Time; DNSAcked bool}`.
  - `state.VPNDevice{ID, User, UUID, Name, IP, PublicKey string; Created time.Time; Expires *time.Time}`.
  - `state.VPNStatic{IP, User, Name string}`.
  - `(*keycloak.Client) UsernamesByID(ctx context.Context) (map[string]string, error)`: LDAP-federated users only (`FederationLink != ""`), username lowercased.
  - `var ErrVPNNotRunning`, `var ErrNoLiveProvider` (both `StatusError` 409 with the Global Constraints texts).
  - `(*Hub) SetVPNProvider(ctx context.Context, actor directory.Actor, id string, wired bool, refresh time.Duration) error`
  - `(*Hub) AssignVPNAddress(ctx context.Context, actor directory.Actor, id, ip, user, name string) error`, `UnassignVPNAddress(ctx, actor, id, ip string) error`, `AckVPNDNS(ctx, actor, id string) error`
  - `(*Hub) RunVPNMaps(ctx context.Context, tick time.Duration)` (runs each wired `source: hook` provider when due; never debounced)
  - `(*Hub) TriggerVPNPublish()` (coalesced), `(*Hub) publishVPNLocked() error`
  - `(*Hub) liveProviders() []string` (wired, fresh, `wg` up)
  - `(*Hub) wgStatus() (*vpn.Status, error)`
  - `type providerMap struct{refreshedAt time.Time; staleAfter time.Time; gateway netip.Addr; devices []vpn.Device; problems []vpn.Dropped; lastErr string}` (memory only, never in `state.yaml`)

- [ ] **Step 1: Write the failing tests** (fake engine, fake Keycloak `UsernamesByID`, fake directory, fake `wg` status file in `t.TempDir()`).
  - `TestWireRefusedWithoutWG`: no status file → `ErrVPNNotRunning`.
  - `TestWireAssignsSlotAndGateway`: the first provider gets slot 0 / `.16` / 9001, the second slot 1. Unwiring frees the slot, and the next wire reuses it.
  - `TestWireRefusesOverlap`: overlap with the built-in subnet (from status), another provider, a Docker network (engine `NetworkList`) or `PORTCULLIS_VPN_NET` → 409 naming both prefixes. An overlap with Local networks is accepted.
  - `TestWireAuditedAndConfirmed`: `vpn.provider_wired` / `unwired` entries carry the provider id only.
  - `TestIdentityHookStdin`: the exec'd stdin equals the contract document byte for byte.
  - `TestOwnerResolution`:
    - `oidc_sub` → via `UsernamesByID`, then the directory: enabled, and in the VPN users group when set.
    - `username` → exact lowercase match.
    - Unresolved → dropped with `not a Portcullis person`.
  - `TestHookFailureKeepsLastMapUntilStale`: a failing run keeps the map; past `StaleAfter` it is published `stale: true`; the next good run is fresh again.
  - `TestHookOutputNeverStored`: the op record and `state.yaml` hold no device name or owner from stdout (redaction like `TestOnChangeHookOutputNeverStored`).
  - `TestStartPublishesMarketplaceProvidersStale` (Review Focus 3): after `New` with wired hook providers and no run yet, `vpn.json` lists them with `stale: true` and no `refreshed_at`.
  - `TestStaticAssignments`: an address outside the ranges → 400; a disabled user → 400; assign and unassign audited `vpn.static_assigned|unassigned`; static maps are never stale.
  - `TestDNSHookRecords`: after a gateway change and after any Portcullis hostname change (instance hosts set, enable, enrolled domain), the `dns` hook gets one A record per core host (`policy.CoreHosts`) and per enabled instance host on the DNS plan, all with the gateway address. A failing hook sets `lastDNSErr` but never marks the map stale.
  - `TestPublishDoc`:
    - `vpn.json` equals a golden for builtin + headscale + static, sorted deterministically (providers by id, devices by IP).
    - It is rewritten on a map change and at least every refresh for live providers.
    - With the builtin off (`state.VPN.BuiltinOff` or status `people == null`), there is no `builtin` and no `builtin` provider.
  - `TestUsernamesByID` (Keycloak fake: only federated users).
- [ ] **Step 2:** Run `go test ./internal/hub/ ./internal/keycloak/ ./internal/state/ -run 'Wire|Identity|Owner|Hook.*Stale|HookOutput|StartPublishes|Static|DNSHook|PublishDoc|UsernamesByID'`. Expected: FAIL.
- [ ] **Step 3: Implement.**
  - Hooks run through `ExecStdinSplit` (guarded), with the hook's `timeout` and a `vpn:<name>` unit.
  - The map lives in memory (`h.vpnMaps`, own mutex). Never hold `Hub.mu` across exec.
  - `publishVPNLocked` builds the `vpn.Doc`: built-in peers come from `state.VPN.Devices` (minus expired); `server_public_key`, `subnet` from `wgStatus()`; `domains` = the main domain plus the enrolled ones. It then calls `vpn.Write(<data>/vpn.json)`.
  - V7: every change of providers, devices, statics or the directory also calls `h.vpnRangesChanged()` (a no-op hook here; Task 5 implements the override re-render).
- [ ] **Step 4:** Run the Hub gates. Expected: PASS.
- [ ] **Step 5:** Commit (`hub: VPN providers (wiring, slots, overlap guards), identity/DNS hook runners, static assignments, vpn.json v2 publishing`).

---

### Task 5: Hub rendering, reach, drift, server mode, policy v7

**Files:**
- Create: `internal/hub/vpn_reach.go`, `internal/hub/vpn_render.go`, tests `vpn_render_test.go`, `vpn_reach_test.go`, `testdata/golden/vpn_*.yml`
- Modify:
  - `internal/hub/override.go` (`hubLabels`, `renderOverrideIn`: entrypoints, allowlist, friendly router, gateway networks/env)
  - `public.go:183`, `override.go:648` and `:815` (the hard-coded `entrypoints: websecure` → `rl.entrypoints`)
  - `internal/hub/reconcile.go` (exposure drift)
  - `internal/policy/file.go` (`FileVersion = 7`, `Document.VPN`)
  - `internal/hub/portal.go` (the policy writer input)

**Interfaces:**
- Consumes: Task 4 (`liveProviders`, `state.Reach`, provider slots and ranges).
- Produces:
  - `policy.VPNPolicy{Hosts map[string]VPNHost; ServerMode, AdminOnly, PublicEnrol bool; DevicesFile string}` (json `hosts`, `server_mode`, `admin_only`, `public_enrol`, `devices_file`) and `policy.VPNHost{Via []string}`. `Document.VPN VPNPolicy` json `vpn` (required).
  - `(*Hub) SetInstanceReach(ctx context.Context, actor directory.Actor, id string, r state.Reach) error`: `ErrNoLiveProvider` for `vpn` with no live provider in `via`; `via` must be `["*"]` or wired ids; audited `instance.reach` (detail `internet -> vpn via=*`) and `vpn.public_links`.
  - `(*Hub) effectiveReachLocked(t *templates.Template) (vpnOnly bool, via []string)`. Server mode makes every instance VPN-only, except instances with `PublicLinks` (public routers only) and provider control routers.
  - `(*Hub) vpnAllowRanges(via []string) []string`.
  - Constants `VPNAllowPrefix = "portcullis-vpnallow-"`, `VPNOnlyPrefix = "portcullis-vpnonly-"`, `VPNRequiredMiddleware = "vpn-required-path@docker"`, `EntrypointsBoth = "websecure,vpnsecure"`, `EntrypointsVPN = "vpnsecure"`.
  - `routeLabels` gains `entrypoints map[string]string` (per router) and `vpnLabels map[string]string` (the allowlist + friendly router, on the first labelled service).

- [ ] **Step 1: Write the failing tests.**
  - `TestRenderReachMatrix`: goldens for {internet, vpn via *, vpn via [builtin]} × {apps, server} × an instance with public access, an extra-domain sign-in router and an MCP router. Assert per router:
    - internet: `websecure,vpnsecure`;
    - VPN-only: `vpnsecure` with `portcullis-vpnallow-<id>@docker` first in the chain, and on the public, `portcullis-oauth2-*` and MCP routers too;
    - `portcullis-vpnonly-<id>` on `websecure`, priority `1`, rule `Host(...)` over every host, the instance tier, `vpn-required-path@docker`, service `group-gate@docker`.
  - `TestControlRoutersStayPublic`: a provider instance set to `vpn` keeps `headscale` on `websecure,vpnsecure` with no allowlist, while `headplane` goes VPN-only.
  - `TestAllowlistRangesFollowProviders`: wiring a second provider re-renders `sourcerange` for `via: ["*"]` instances only.
  - `TestGatewayOverrideKeepsTemplateNetworks` (Review Focus 1): ingress services declaring nothing, `[default, portcullis-proxy]`, or a map with aliases each render their original networks plus `portcullis-vpn: {ipv4_address: 172.31.254.16}` and `PORTCULLIS_VPN_EDGE: "172.31.254.3:9001"`, and the override's top-level `networks.portcullis-vpn.external: true`. V11: also set the env on every service with `network_mode: service:<ingress>`.
  - `TestReachRefusedWithoutProvider` (409 "wire a VPN first"), `TestReachAudited`.
  - `TestDriftComparesEntrypointsAndAllowlist`: a running container with `websecure` on a VPN-only router, or the allowlist moved second, is drift.
  - `TestPolicyV7VPNSection`: version 7; `vpn.hosts` lists every host of VPN-only instances with their `via`; `server_mode` / `admin_only` / `public_enrol` from core.env (`PORTCULLIS_VPN_MODE`, `PORTCULLIS_VPN_PUBLIC_ENROL`); `devices_file` is `"vpn.json"`.
  - `TestUnwireLastViaMakesInstanceUnreachable`: the instance stays VPN-only with an empty allowlist (`sourcerange` `0.0.0.0/32`), never internet.
- [ ] **Step 2:** Run `go test ./internal/hub/ ./internal/policy/ -run 'Reach|ControlRouters|Allowlist|GatewayOverride|Drift.*Entrypoints|PolicyV7|UnwireLast'`. Expected: FAIL.
- [ ] **Step 3: Implement.**
  - Set the entrypoints label on every router the Hub knows (template host routers included).
  - An empty accepted set renders `0.0.0.0/32`: Traefik refuses an empty source range, and that range matches no client.
  - V7: implement `vpnRangesChanged()` to re-render VPN-only instance overrides whose accepted ranges changed (called by Task 4's map changes).
  - Update the existing goldens: every internet router now carries `entrypoints: websecure,vpnsecure`. Check the diff contains only that line per router.
- [ ] **Step 4:** Run the Hub gates. Expected: PASS.
- [ ] **Step 5:** Commit (`hub: VPN-only rendering (vpnsecure, portcullis-vpnallow, friendly router, control routers, gateway attachment), reach, drift, policy v7`).

---

### Task 6: Hub built-in devices: people `/vpn/` page and API, host control socket

**Files:**
- Create:
  - `internal/hub/vpn_devices.go`, `internal/httpapi/vpn_people.go`, `internal/httpapi/hostctl.go`, `cmd/hub/vpn.go`
  - `web/vpn.html`, `web/vpn.js`, `web/vendor/qrcode.js` (`qrcode-generator`, pinned version + sha256 in a header comment)
  - tests `vpn_devices_test.go`, `vpn_people_test.go`, `hostctl_test.go`, `webui_vpn_test.go`
- Modify:
  - `internal/httpapi/server.go` (people mux, `peopleStatic` unchanged: V18 `/vpn/assets/` has its own allowlist `vpnAssets` serving fresh-auth scripts)
  - `web/web.go` (`//go:embed`)
  - `cmd/hub/main.go` (fresh-auth: a `hub.ListenerPeopleVPN` verifier with redirect `https://people.<d>/vpn/`; `hub vpn` dispatched before env like `folderfix`; control socket listener; V26 `go h.RunVPNExpiry(ctx, 10*time.Second)`)
  - `internal/keycloak/freshauth.go` (V8: `checkFreshAuthURIs` per-host model: people → `{/signin, /vpn/}`, hub → `{/}`; deduplicated web origins)
  - `web/mysignin.js` (the "VPN devices" card: all-providers list, a link to `/vpn/`)
  - `web/directory.js` (People → person → VPN devices, remove only)

**Interfaces:**
- Consumes: Task 4 (`publishVPNLocked`, `wgStatus`, `state.VPNDevice`), `freshauth.Proof`.
- Produces:
  - `hub.VPNDeviceConfig{Address, ServerPublicKey, Endpoint, AllowedIPs, DNS string; MTU int}` (json snake_case).
  - `hub.VPNDeviceView{ID, Provider, ProviderLabel, Name, Address string; LastSeen, Expires *time.Time; Online, Managed bool}` (`Managed` = built-in, rename and remove possible).
  - `(*Hub) VPNDevices(ctx context.Context, user string) []VPNDeviceView` (every provider; static assignments included).
  - `(*Hub) AddVPNDevice(ctx context.Context, user, name, publicKey string, p freshauth.Proof) (*VPNDeviceConfig, error)`.
  - `RenameVPNDevice(ctx, actor, user, id, name string) error`, `RemoveVPNDevice(ctx, actor directory.Actor, id string) error`, `RenewVPNDevice(ctx, user, id, publicKey string, p freshauth.Proof) (*VPNDeviceConfig, error)`.
  - `(*Hub) HostAddVPNDevice(ctx context.Context, user, name, publicKey string) (*VPNDeviceConfig, error)` (no proof; only reachable through the control socket).
  - `(*Hub) VPNHostInfo(ctx context.Context) HostInfo`, `HostInfo{LocalNetworks, ProviderRanges []string; AdminDeviceSeen bool}` (json `local_networks`, `provider_ranges`, `admin_device_seen`). `AdminDeviceSeen` is true when an `lldap_admin` member has a device seen within 10 min on the builtin or a `source: hook` provider.
  - `(*Hub) RunVPNExpiry(ctx context.Context, every time.Duration)`: expires devices (audited `vpn.device_expired`); revokes on group leave, disable or delete.
  - Control socket: `httpapi.HostHandler(h) http.Handler` on `/tmp/hub-host.sock` (0600), routes `POST /host/vpn/devices`, `GET /host/vpn/devices`, `DELETE /host/vpn/devices/{id}`, `GET /host/vpn/info`.
  - `hub vpn add-device --user U --name N` (public key on stdin → config JSON on stdout), `hub vpn devices [--user U]`, `hub vpn revoke <id>`, `hub vpn host-info`.

- [ ] **Step 1: Write the failing tests.**
  - `TestAddDeviceNeedsFreshAuth`: no proof, an old proof (> 5 min) or another user's proof → 403. A valid one → 201 with `allowed_ips == "10.213.0.1/32"`, `dns == "10.213.0.1"`, `mtu == 1280`, `endpoint == "<d>:51820"`. The device is in `vpn.json`, and the audit entry `vpn.device_added` has no key.
  - `TestAddDeviceRefusals`:
    - a key that isn't 32 bytes of base64 → 400;
    - a key already used by any device → 409;
    - the 11th device → 409 ("at most 10 devices");
    - a person outside the VPN users group → 403;
    - the builtin off → 409.
  - `TestRemoveQuarantinesAddress` (the address isn't handed out for 7 days).
  - `TestRecreatedPersonDoesNotInheritDevices` (Review Focus 2): a device recorded with uuid A; the directory now reports the same username with uuid B → the device is dropped from `vpn.json` and audited `vpn.device_removed` (`reason=account re-created`).
  - `TestGroupLeaveRevokes`, `TestDisableRemovesDevices`, `TestExpiryAudited`.
  - `TestRenewRekeys` (same id and address, new key, fresh proof).
  - `TestPeopleVPNDevicesAdminOnly`: People → person list and delete for admins and `manage_signin`; another person → 403; marketplace devices → 409 "managed in <label>".
  - `TestHostSocketOnly`:
    - the `/host/` routes are 404 on all three TCP listeners;
    - the socket file is 0600;
    - `HostAddVPNDevice` creates a device for any enabled person in the VPN users group;
    - the audit actor is `host`.
  - `TestHubVPNSubcommand` (cmd/hub: stdin key → POST over a test socket → stdout JSON; a missing socket → exit 1 with "the Hub isn't running").
  - `TestFreshAuthVPNRedirect` (V8: `checkFreshAuthURIs` per-host model: people accepts `/signin` and `/vpn/`, hub accepts `/`, test covers host-twice rule and path set).
  - `TestVPNPageNeverPostsPrivateKey` (static, `webui_vpn_test.go`):
    - `vpn.js` posts a body built only from `name`, `public_key`, `proof`;
    - it contains no `localStorage` / `sessionStorage` / `indexedDB`;
    - the config text and QR are built in the page.
  - `TestVPNAssetsAllowlist` (only the page's own files under `/vpn/assets/`).
- [ ] **Step 2:** Run `go test ./internal/hub/ ./internal/httpapi/ ./internal/keycloak/ ./cmd/hub/ -run 'Device|Recreated|GroupLeave|Disable|Expiry|Renew|PeopleVPN|HostSocket|HubVPN|FreshAuthVPN|VPNPage|VPNAssets'`. Expected: FAIL.
- [ ] **Step 3: Implement.**
  - The page: name → fresh sign-in (`freshauth.js` with the `/vpn/` verifier) → V21 WebCrypto `generateKey({name:"X25519"})`, export raw public key and last 32 bytes of PKCS#8 private key → POST the public key → assemble `[Interface]`/`[Peer]` text and the QR in memory → show once → overwrite the key variable on close.
  - Expiry choices: 30 d, 90 d, 1 y, never (Settings bounds).
  - The Sign-in card and People → person reuse `GET /vpn/api/devices` and `/api/people/{user}/vpn-devices`.
  - Escape everything (`escapeHtml` / `esc`) and use delegated listeners.
- [ ] **Step 4:** Run the Hub gates. Expected: PASS.
- [ ] **Step 5:** Commit (`hub: built-in VPN devices (people /vpn/ with fresh sign-in and in-browser keys), all-providers lists, expiry and revocation, host control socket + hub vpn`).

---

### Task 7: Hub admin API, MCP, audit and the admin UI

**Files:**
- Create: `internal/httpapi/vpn.go`, `internal/httpapi/mcptools_vpn.go`, tests `vpn_test.go`, `webui_vpnadmin_test.go`
- Modify:
  - `internal/httpapi/server.go` (Hub mux)
  - `internal/httpapi/mcp_parity_test.go` (TestToolParity class lists and the "all registered" slice), `mcptools_admin_test.go` (`TestAdminToolsSameAsHTTP` cases), `mcptools_admin2_test.go` (`adminToolFixtures`), `auditparity_test.go`
  - `web/index.html`:
    - the instance page → Access: *Reachable from* + *Through* + the public-links opt-in;
    - the instance VPN tab: Use for Portcullis access, refresh, the map with drops and reasons, static assignments, DNS records + acknowledge;
    - Settings → VPN: VPN users group, devices per person, expiry, the providers overview, and the mode and public enrolment read-only with the CLI command.

**Interfaces:**
- Consumes: Tasks 4–6.
- Produces:
  - Routes (Hub listener only): exactly the §11 list of Task 1.
  - `(*Hub) VPNOverview(ctx) VPNView`, `VPNView{Mode string; PublicEnrol bool; WG struct{Up bool; Error string}; Builtin *struct{Subnet string; Port int; Devices, Online int}; Providers []ProviderView; Settings VPNSettingsView}`.
  - `ProviderView{ID, Label, Source string; Wired, Stale bool; Ranges []string; Devices, Online int; RefreshedAt *time.Time; LastError string; Compat *templates.Compat}` (`Compat` = the rootless status under Podman).
  - `VPNSettingsView{UsersGroup string; DevicesPerPerson int; Expiry string}` and `VPNSettingsUpdate` (the same fields as pointers; only the set ones change).
  - `(*Hub) SetVPNSettings(ctx, actor, VPNSettingsUpdate) error` (audited `vpn.settings`; `devices_per_person` 1–100, `expiry` `30d|90d|1y|never` or a duration ≥ 30 d).
  - MCP (all `admin(...)`, twins as Task 1 §15.10): `get_vpn` R, `list_vpn_devices` R, `remove_vpn_device` D, `set_vpn_provider` D, `assign_vpn_address` D (V9: takes DELETE via `AlsoTwins` for unassign), `set_instance_reach` D. V9: `PUT /api/vpn/settings`, `DELETE /api/instances/{id}/vpn-static/{ip}`, `POST /api/instances/{id}/vpn-dns/ack` get `noToolRoutes` reasons ("admin UI only").

- [ ] **Step 1: Write the failing tests.**
  - `TestVPNRoutesAdminOnly` (the people listener 404s each one).
  - `TestVPNRoutesStatus`: 409 texts; 400 for an unknown provider in `via`; 404 for an unknown instance.
  - `TestAdminToolsSameAsHTTP` gains the six tools; `TestToolParity` gets the classes R/D; `adminToolFixtures` gets one fixture each (the P3 pattern of the rootless plan).
  - `TestVPNAuditParity`: every mutating route writes its action.
  - `TestNoKeyInMCPOutput`: `list_vpn_devices` output has no `public_key` and nothing else from config text.
  - `TestHubVPNUI` (static): `index.html` has `data-reach=`, `data-vpn-provider=`, `function renderVPNTab(` and `function loadVPNSettings(`. The unwire confirm lists the instances whose `via` names only that provider first.
- [ ] **Step 2:** Run `go test ./internal/httpapi/ -run 'VPN|AdminToolsSameAsHTTP|ToolParity|NoKeyInMCP'`. Expected: FAIL.
- [ ] **Step 3: Implement**, following `set_public_access` / `list_ops` for tool shape, the confirmation flow and audit. Add a Hub `CLAUDE.md` row for the VPN files and rules (no key on any listener; host socket only; fail-closed 409s).
- [ ] **Step 4:** Run the Hub gates. Expected: PASS.
- [ ] **Step 5:** Commit (`hub: VPN admin API, MCP tools (get_vpn, list/remove devices, set_vpn_provider, assign_vpn_address, set_instance_reach), audit, admin UI`).

---

### Task 8: Hub doctor kinds

**Files:**
- Create: `internal/doctor/vpn.go`, `internal/doctor/vpn_test.go`, `internal/hub/doctor_vpn.go`, `internal/hub/doctor_vpn_test.go`
- Modify: `internal/doctor/doctor.go` (`Inputs.VPN *VPNIn`), `internal/hub/doctor.go` (fill inputs), `internal/hub/doctorfix_touches_test.go` (no new fixers)

**Interfaces — Produces:**
- `doctor.VPNIn{Mode string; WGUp bool; WGError string; VPNOnly []string; Providers []VPNProviderIn; Instances []VPNInstanceIn; LocalNetworks, DockerNets []netip.Prefix; Devices []VPNDeviceIn; AdminSeen time.Time}`
  - `VPNProviderIn{ID, Label, Source string; Stale bool; LastError string; GatewayUp, GatewayPrivileged bool; Ranges []netip.Prefix; Duplicates int; Outside, Unresolved int; DNSManual, DNSAcked bool; DNSError string}`
  - `VPNInstanceIn{ID string; Via []string; PublicLinks bool}`, `VPNDeviceIn{ID, User string; LastHandshake, Expires *time.Time}`
- Kinds (constants `KindVPN…`), severities as spec §12:
  - `vpn_down` (Problem; steps `./portcullis up`, `./portcullis logs wg`)
  - `vpn_provider_stale` (Problem)
  - `vpn_provider_invalid` (Problem for duplicates, else Info)
  - `vpn_range_overlap` (Local networks → Warning; Docker network → Problem)
  - `vpn_via_dead` (Problem)
  - `vpn_dns_failed` (Problem), `vpn_dns_manual` (Info until acknowledged)
  - `vpn_gateway_privileged` (Info), `vpn_static_mapping` (Info)
  - `vpn_single_provider` (Warning), `vpn_public_links` (Warning)
  - `vpn_no_admin_device` (Problem, 30 days)
  - `vpn_device_stale` (Info, 90 days), `vpn_expiring` (Info, 14 days, `persons: [owner]`)
- Every VPN finding's `why` ends with "Portcullis can't test UDP reachability from outside."

- [ ] **Step 1: Write the failing tests.** One `TestVPN<Kind>` per kind (fires, doesn't fire, severity), plus:
  - `TestVPNKindsSilentWithoutVPN` (no `wg`, no providers, mode apps → none);
  - `TestGatewayPrivilegedFromInspect` (a gateway container, or a service sharing its netns, with `CapAdd` NET_ADMIN / `Privileged` / `Devices` → Info naming the service);
  - `TestProviderStaleShowsRedactedError` (the hook's stderr with a stored secret → redacted, then clipped).
- [ ] **Step 2:** Run `go test ./internal/doctor/ ./internal/hub/ -run 'VPN|GatewayPrivileged|ProviderStale'`. Expected: FAIL.
- [ ] **Step 3:** Implement: register in `init()` like `dns.go`. The inputs come from Task 4/6 state, `wgStatus()` and guarded inspects, cached with the scans.
- [ ] **Step 4:** Run the Hub gates. Push `vpn1` and dispatch `gh workflow run build.yml --ref vpn1`. Expected: green.
- [ ] **Step 5:** Commit (`hub: VPN doctor kinds`).

---

### Task 9: Templates validator for `vpn:`, the trigger and policy v7 in app_signin

**Files:**
- Modify:
  - `schema/manifest.schema.json` (`vpn` def, `hooks[].when` gains `vpn`)
  - `tests/validate.py`: new `check_vpn(t, services, routers, r)` called beside `check_ai`; `RESERVED_REFS` += `"portcullis-vpn"` (V1: forwarder image exception); V2: `CORE_SERVICES` += `wg`, `CORE_VOLUMES` += `wg_data`; the reserved `PORTCULLIS_VPN_*` interpolation refusal in `check_reserved_var_refs`; V10: vpn hook exclusions in reload/delivery like ai hooks
  - `tests/test_validate.py` (`VPNTests`), `tests/e2e/app_signin.py` (`policy_doc`), `.github/workflows/lint.yml`, `CLAUDE.md`, `CONTRIBUTING.md`
- Create: `tests/vpn_vectors.json` (byte copy of the Hub's `internal/templates/testdata/vpn_vectors.json`)

**Interfaces:**
- Consumes: the Task 1 texts and the Task 2 vectors.
- Produces: `check_vpn` emitting exactly the §3.3 texts. `policy_doc(ver)` writes `"version": ver`, and for `ver >= 7` the key `vpn: {"hosts": {}, "server_mode": false, "admin_only": false, "public_enrol": true, "devices_file": "vpn.json"}`.

- [ ] **Step 1: Write the failing tests.**
  - `VPNTests.test_vectors` (each vector → the same first error, or none).
  - `test_reserved_vpn_ref`.
  - `test_policy_doc_v7` (v6 → no `vpn` key and version 6; v7 → version 7 with the exact `vpn` dict).
  - `test_schema_vpn_strict` (an unknown key in `vpn:` → schema error).
- [ ] **Step 2:** Run `python3 tests/test_validate.py`. Expected: FAIL.
- [ ] **Step 3:** Implement. Add a lint.yml step "VPN vectors match the Hub" (the pattern of "Rootless vectors match the Hub": same-named Hub branch via `git ls-remote`, else main; `cmp`; no secrets). Document the block in `CONTRIBUTING.md` ("VPN providers") and in one `CLAUDE.md` line.
- [ ] **Step 4:** Run the templates gates. Expected: PASS.
- [ ] **Step 5:** Commit (`validate: vpn: block, the vpn hook trigger, portcullis-vpn reserved (shared vectors with the Hub); app_signin writes policy v7`).

---

### Task 10: Headscale as the reference provider

**Files:**
- Modify: `headscale/manifest.yaml`, `headscale/compose.yml`, `headscale/config/config.yaml`, `tests/apps/headscale.sh`
- Create: `headscale/vpn/glue.py` (stdlib only)

**Interfaces:**
- Consumes: Tasks 2, 9 (`vpn:` rules), the Hub's override env `PORTCULLIS_VPN_EDGE`.
- Produces:
  - The template's `vpn:` block:
    - `label: Headscale tailnet`, `ranges: ["100.64.0.0/10"]`
    - `ingress: {service: gateway, proxy_protocol: v2}`
    - `identity: {source: hook, hook: vpn-devices, owner: oidc_sub, refresh: 60s}`
    - `dns: {hook: vpn-dns}`, `control_routers: [headscale]`
  - Hooks:
    - `vpn-devices` and `vpn-dns`: service `vpn-glue`, `when: [vpn]`, command `["python3", "/vpn/glue.py"]`.
    - `gateway-key`: service `vpn-glue`, `when: [start]`, command `["python3", "/vpn/glue.py", "gateway-key"]`.
  - Services:
    - `gateway`: `docker.io/tailscale/tailscale:<pinned tag@sha256>`, V16: entrypoint wrapper waits for `/run/gateway/authkey`, then runs containerboot with a generated `TS_SERVE_CONFIG` substituting `$PORTCULLIS_VPN_EDGE`; `TS_USERSPACE=true`, `TS_EXTRA_ARGS=--login-server=https://${PORTCULLIS_HOST_HEADSCALE} --advertise-tags=tag:portcullis-gateway`, state in volume `gateway-state`, no caps.
    - `vpn-glue`: `docker.io/library/python:<pinned>-alpine@sha256`, read-only, `cap_drop: ALL`, idle `sleep infinity`, env `HEADSCALE_API_KEY: ${HEADSCALE_API_KEY:-}`, `OIDC_ISSUER`; mounts `./templates/headscale/vpn:/vpn:ro` (V15: stdlib-only glue per spec §4 amendment), `headscale-dns:/dns`, `gateway-auth:/run/gateway`.
  - `config.yaml`: `dns.extra_records_path: /var/lib/headscale-dns/extra-records.json` (the `headscale-dns` volume read-only in `headscale`).

- [ ] **Step 1 (verification, Q5 and the glue's premise; record the outcome in the commit message):**
  - V15: confirm the pinned `headscale` image has no `/bin/sh` (distroless). That's why the hooks run in `vpn-glue` against Headscale's REST API with the template's existing `api_key` setting instead of `headscale nodes list | jq`.
  - V16: register a userspace `tailscale/tailscale` against it and run `tailscale serve --tcp 443 tcp://<edge> --proxy-protocol 2` (or `TS_SERVE_CONFIG` generated) against a netcat that prints the PROXY header. Expected: the v2 header's source is the client node's 100.64 address.
  - If it isn't, stop and switch to the spec's Q5 fallback: a TUN-mode tailscaled + `portcullis-forwarder` in Task 19's netbird pattern (rootless `degraded`). Report the switch before going on.
- [ ] **Step 2: Write the failing checks** in `tests/apps/headscale.sh`:
  - `validate.py` accepts the template;
  - the gateway has no `cap_add` / `devices`;
  - the glue's image is pinned;
  - **live**: boot core as test-apps does, start headscale + vpn-glue, create a node through the API, run `vpn-devices` with the contract stdin, and validate stdout against version 1 (gateway present, owner = the OIDC sub with the issuer prefix stripped, a non-OIDC user's node absent);
  - `vpn-dns` writes `extra-records.json` with the given A records, atomically (temp + rename).
- [ ] **Step 3: Implement `glue.py`.**
  - `devices`: `GET /api/v1/node` with the bearer from `HEADSCALE_API_KEY` (missing → exit 1 "set the Headscale API key setting"). Each node maps to `{id, name, address (first IPv4), owner, online, last_seen, expires}`. The owner is `user.providerId` minus `OIDC_ISSUER + "/"`; another issuer, or none, means the node is skipped. The tagged gateway node's IPv4 is `gateway`.
  - `dns`: write `/dns/extra-records.json` as `[{"name","type":"A","value"}]`.
  - `gateway-key`: create the user `portcullis-gateway` if absent, then a non-reusable 1 h pre-auth key tagged `tag:portcullis-gateway`, written to `/run/gateway/authkey` 0600, only when the gateway isn't registered yet.
  - Errors go to stderr, without tokens.
  - In `manifest.yaml` notes: what goes public in server mode (only the `headscale` router), the API key requirement, and the refresh delay. V15: note that identity depends on the Headscale API key's expiry (365 d default).
- [ ] **Step 4:** Run the templates gates and `bash tests/apps/headscale.sh` against a local core checkout. Expected: PASS. Push `vpn1`, run lint.yml and Test Apps `apps=headscale`. Expected: green.
- [ ] **Step 5:** Commit (`headscale: Portcullis VPN provider (userspace gateway with PROXY v2, identity and DNS hooks through the REST API)`).

---

### Task 11: Core `wg` tunnel and `vpn.json` reader packages

**Files:**
- Create: `wg/go.mod`, `wg/go.sum`, `wg/internal/vpndoc/{vpndoc.go,vpndoc_test.go}`, `wg/internal/tunnel/{tunnel.go,tunnel_test.go}`, `tests/vpn_json_vectors.json` (byte copy of the Hub's `internal/vpn/testdata/vpn_json_vectors.json`)

**Interfaces — Produces:**
- `vpndoc.Parse(b []byte) (*Doc, error)` (the contract rules; types mirror Task 3).
- `(*Doc) ProviderOf(a netip.Addr) *Provider`.
- `(*Doc) Device(provider string, a netip.Addr, now time.Time) *Device` (nil when stale, expired or absent).
- `(*Doc) BuiltinPeers(now time.Time) []Peer` (expired peers dropped).
- `vpndoc.Watcher{Path string; Every time.Duration}`, `(*Watcher) Run(ctx, func(*Doc, error))` (stat polling on dev/ino/mtime/size, every 2 s).
- `tunnel.Config{PrivateKey [32]byte; ListenPort int; Address netip.Addr; MTU int}`.
- `tunnel.New(cfg Config) (*Stack, error)` (`netstack.CreateNetTUN` + `device.NewDevice(..., conn.NewDefaultBind(), ...)`).
- `(*Stack) SyncPeers(peers []PeerConfig) error`: diff through `IpcSet` (`remove=true` for gone peers, add or update the rest, `allowed_ip=<ip>/32`, `replace_allowed_ips=true`). Never `replace_peers`.
- `(*Stack) ListenTCP(port uint16) (net.Listener, error)`, `ListenUDP(port uint16) (net.PacketConn, error)`.
- `(*Stack) DialTCP(ctx, addr netip.AddrPort) (net.Conn, error)` (tests only).
- `(*Stack) Handshakes() (map[string]time.Time, error)` (`IpcGet` `last_handshake_time_sec`), `(*Stack) PublicKey() string`, `Close()`.
- `tunnel.PeerConfig{PublicKey [32]byte; IP netip.Addr}`.

- [ ] **Step 0 (V22 spike):** Build + `TestTunnelRoundTrip` inside `golang:1.27.3-alpine3.24@sha256:fa48…`, allowing a newer gVisor `require` if needed. Stop and report if it fails.
- [ ] **Step 1: Write the failing tests.**
  - `TestVectors` (V6: reads `../../../tests/vpn_json_vectors.json`).
  - `TestSyncPeersDiff`: removing one of two peers keeps the other's handshake.
  - `TestTwoStacksIsolated` (the role-separation proof for the future link role): two stacks in one process with disjoint subnets; dialling stack B's address from stack A fails; a stack with no listener accepts nothing.
  - `TestTunnelRoundTrip`: a client stack peered to a server stack reaches the server's TCP listener.
- [ ] **Step 2:** Run `cd wg && go test ./...`. Expected: FAIL.
- [ ] **Step 3:** Implement with the libraries named in Tech Stack. Pin them in `go.mod`, matching the golang builder version of `mcp-gate`.
- [ ] **Step 4:** Run the `wg` gate. Expected: PASS.
- [ ] **Step 5:** Commit (`wg: vpn.json v2 reader (shared vectors), userspace WireGuard tunnel package (netstack, peer diff, isolated stacks)`).

---

### Task 12: Core `wg` service: edge, people role, resolver, status, subcommands, image

**Files:**
- Create: `wg/main.go`, `wg/main_test.go`, `wg/internal/edge/{edge.go,edge_test.go}`, `wg/internal/people/{people.go,people_test.go}`, `wg/internal/resolver/{resolver.go,resolver_test.go}`, `wg/internal/status/status.go`, `wg/Dockerfile`

**Interfaces:**
- Consumes: Task 11.
- Produces:
  - Env:
    - `WG_VPN_FILE=/hub-data/vpn.json`, `WG_STATUS_FILE=/data/status.json`, `WG_PEOPLE_KEY=/run/portcullis/wg/people.key`
    - `WG_PEOPLE=on|off`, `WG_PORT`, `WG_SUBNET`, `WG_VPN_ADDR` (its `portcullis-vpn` IP), `WG_TRAEFIK=<ip>:8443`
    - `WG_DNS_UPSTREAM`, `WG_DOMAIN`, `WG_MODE`, `WG_METRICS=:9100` (V23: bind to the `portcullis` interface's address found at start, not all interfaces)
  - Subcommands:
    - `wg run`
    - `wg genkey <path>` (writes a key 0640; the private key is never printed)
    - `wg keypair` (`{"private_key","public_key"}` on stdout, for the host CLI only)
    - `wg qr` (stdin text → terminal QR on stdout)
    - `wg healthcheck`, `wg status` (prints `status.json`)
    - Usage errors exit 2.
  - `edge.Rejection` reasons: `wrong_port`, `wrong_gateway`, `no_header`, `slow_header`, `outside_ranges`, `not_in_map`, `stale`, `no_doc`.
  - `edge.New(traefik netip.AddrPort, local netip.Addr, doc func() *vpndoc.Doc, now func() time.Time) *Edge`.
  - `(*Edge) ServeProvider(ctx, ln net.Listener, providerID string)`; `(*Edge) Handle(conn net.Conn, providerID string, client netip.Addr)` (in-process for `builtin`).
  - Metrics: `wg_edge_rejected_total{provider,reason}`, `wg_edge_accepted_total{provider}`, `wg_provider_stale{provider}`, `wg_role_up{role}`, `wg_people_peers`, `wg_mode_restricted` (1 when mode ≠ apps).
  - `resolver.Rewriter{Domains []string; Server []netip.Addr; Self netip.Addr}`, `(*Rewriter) Rewrite(q, upstream *dns.Msg) *dns.Msg`. `Server` = the apex's A records, re-resolved every 300 s.

- [ ] **Step 1: Write the failing tests.**
  - `TestEdgeAcceptRules`: a table over each rejection reason, using a fake Traefik listener that records the received PROXY v2 header (go-proxyproto) and a `vpndoc.Doc` fixture. Accepted → the header source equals the claimed client. The slow header is cut at 5 s (clock injected through `SetReadDeadline` and a short test value).
  - `TestEdgeGatewayClaimsBuiltinAddress` → `outside_ranges`.
  - `TestEdgeNoDocDeniesAll` (missing file, parse error).
  - `TestPeopleRoleSyncsPeers` (a doc change adds and removes peers; a mismatched non-empty `server_public_key` → the people role refuses to load peers, `ok:false`).
  - `TestExpiredPeerDroppedByClock` (Review Focus 4): a peer whose `expires` passes is removed at the next tick (1 s) with no new doc.
  - `TestPeopleHTTPRedirect` (`:80` → `308 https://<host><path>`).
  - Resolver:
    - `TestRewriteTable`: A for `<d>` / `app.<d>` / an enrolled domain pointing at the server → `10.213.0.1`; AAAA → NODATA; AD cleared; RRSIGs stripped; a foreign A (`nas.<d>` → another address) passes untouched; a non-Portcullis name passes through.
    - `TestRewriteCNAMEChain` (Review Focus 5).
  - `TestStatusDocument` (the contract §16 shape; `people` null when off; written every 10 s).
  - `TestMainUsage` (`--help` exit 0, unknown subcommand exit 2, `keypair` output parses, `genkey` never writes to stdout).
- [ ] **Step 2:** Run `cd wg && go test -race ./...`. Expected: FAIL.
- [ ] **Step 3: Implement.**
  - `run` wiring:
    - the edge always;
    - one listener per provider in the doc on `WG_VPN_ADDR:<edge_port>` (re-bound when the doc changes);
    - the people role when `WG_PEOPLE=on`: `tunnel.New`, TCP 443 → `edge.Handle(conn, "builtin", remote)`, TCP 80, UDP/TCP 53 (miekg `dns.Server` over the stack's `PacketConn` / `Listener`);
    - metrics on the `portcullis` address only.
  - A role that fails to load sets `ok:false` with its error, and the other keeps running.
  - `Dockerfile`: `FROM docker.io/library/golang:<the mcp-gate builder tag@sha256> AS builder`, `CGO_ENABLED=0`, then `FROM docker.io/library/alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a`, `USER 10006:10006`, `ENTRYPOINT ["/wg"]`, `CMD ["run"]`.
- [ ] **Step 4:** Run the `wg` gate. Expected: PASS.
- [ ] **Step 5:** Commit (`wg: edge (PROXY v2 accept rules), built-in people role, split-DNS resolver, status, metrics, subcommands, image`).

---

### Task 13: Core `portcullis-forwarder` image and its publishing

**Files:**
- Create: `forwarder/{go.mod,go.sum,main.go,main_test.go,Dockerfile}`, `.github/workflows/forwarder.yml`
- Modify: `.github/workflows/release.yml` (also tag the forwarder `vX.Y.Z`), `CLAUDE.md` (Key Files)

**Interfaces — Produces:**
- The forwarder:
  - listens on `${FORWARDER_LISTEN:-:443}` and forwards each connection to `$PORTCULLIS_VPN_EDGE` with a PROXY v2 header (source = the peer address it sees);
  - refuses to start without `PORTCULLIS_VPN_EDGE` (exit 2);
  - uid 65534, `ENTRYPOINT ["/forwarder"]`.
- `forwarder.yml`: on push to main touching `forwarder/**` and on dispatch, builds `linux/amd64,linux/arm64` and pushes `ghcr.io/porelli/portcullis-forwarder:edge`. `permissions: packages: write` only on that job. Actions are pinned by SHA.

- [ ] **Step 1: Write the failing tests:** `TestForwardsWithHeader`, `TestRefusesWithoutEdge`, `TestHalfCloseSplice`.
- [ ] **Step 2:** Run `cd forwarder && go test ./...`. Expected: FAIL.
- [ ] **Step 3:** Implement on go-proxyproto and `io.Copy` with half-close. Use the same builder and alpine digests as Task 12. Run `actionlint`.
- [ ] **Step 4:** Run the forwarder gate and `actionlint`. Expected: PASS.
- [ ] **Step 5:** Commit (`forwarder: PROXY v2 forwarder image for VPN apps with a real tunnel interface, published to GHCR from main`).

---

### Task 14: Core compose, networks, Traefik `vpnsecure`, overlays and static CI checks

**Files:**
- Modify:
  - `docker-compose.yml`:
    - networks `portcullis-vpn` (internal, `name: portcullis-vpn`, IPAM `${PORTCULLIS_VPN_NET:-172.31.254.0/26}`, V20 `ip_range: ${PORTCULLIS_VPN_IP_RANGE:-172.31.254.8/29}` so no dynamic address can take a pinned one) and `wg-egress`;
    - the `wg` service (profile `wg`);
    - Traefik's `vpnsecure` env and its `portcullis-vpn` address;
    - every core router's `entrypoints` → one of the three variables;
    - the `people-vpn-enrol` router; `vpn-required-path` on group-gate;
    - the Hub's `wg_data:/wg-data:ro` and `HUB_VPN_STATUS_FILE`; volume `wg_data`.
  - `docker-compose.podman.yml` (`wg: restart: always`), `docker-compose.podman-selinux.yml` (the `./secrets/wg/people.key` bind, `Z`)
  - `scripts/lib/network.sh` (`vpn_net()`, `vpn_traefik_ip()`, `vpn_wg_ip()`, `validate_vpn_network_config`, `vpn_network_state`, in `network_check`; `CORE_SERVICE_NAMES` += `wg`)
  - `.github/workflows/ci.yml` (unit-tests: wg and forwarder Go tests, the vectors cmp step, compose checks), `tests/test_cli.sh`, `tests/test_shell_libs.sh`, `.env.example`, `CLAUDE.md` (Deployment: a `wg` bullet)

**Interfaces — Produces:**
- `wg` service:
  - `build: ./wg`, `image: portcullis-wg`, `<<: *hardening`, `user: "10006:10006"`, `group_add: ["10001"]`, `read_only: true`, `profiles: [wg]`, `mem_limit: 128m`, `pids_limit: 128`.
  - Volumes: `hub_data:/hub-data:ro`, `wg_data:/data`, `./secrets/wg/people.key:/run/portcullis/wg/people.key:ro`.
  - Networks: `portcullis-vpn: {ipv4_address: ${PORTCULLIS_VPN_WG_IP:-172.31.254.3}}`, `wg-egress: {}`, `portcullis: {}`.
  - `ports: ["${PORTCULLIS_VPN_PORT:-51820}:${PORTCULLIS_VPN_PORT:-51820}/udp"]`, healthcheck `["CMD", "/wg", "healthcheck"]`, `restart: unless-stopped`.
  - Env (Task 12 names), from `.env` with defaults; `WG_PEOPLE: ${PORTCULLIS_VPN_BUILTIN:-off}`; `WG_MODE: ${PORTCULLIS_VPN_MODE:-apps}`.
- Traefik env:
  - `TRAEFIK_ENTRYPOINTS_VPNSECURE_ADDRESS: ${PORTCULLIS_VPN_TRAEFIK_IP:-172.31.254.2}:8443`
  - `TRAEFIK_ENTRYPOINTS_VPNSECURE_PROXYPROTOCOL_TRUSTEDIPS: ${PORTCULLIS_VPN_WG_IP:-172.31.254.3}/32`
  - `TRAEFIK_ENTRYPOINTS_VPNSECURE_HTTP_ALIASHEADERSSTRATEGY: delete`
  - `..._VPNSECURE_HTTP_TLS_CERTRESOLVER: letsencrypt` and the same two `TLS_DOMAINS_0_*` as websecure
  - networks: `portcullis-vpn: {ipv4_address: ${PORTCULLIS_VPN_TRAEFIK_IP:-172.31.254.2}}`
- Router classes:
  - `PORTCULLIS_EP_ADMIN`: `dashboard`, `lldap`, `keycloak-admin`, `hub`, `grafana-metrics`, `mcp`, `hub-mcp`, `people-mcp`.
  - `PORTCULLIS_EP_ENROL`: `keycloak`, `keycloak-resources`, `oauth2-callback`, `enroll-invite`, `people-vpn-enrol`.
  - `PORTCULLIS_EP_CORE`: `portal`, `people`.
  - Each defaults to `websecure,vpnsecure`.
- `people-vpn-enrol`: rule `Host(`people.<d>`) && PathPrefix(`/vpn/`)`, priority above `people`, the people router's middleware chain and service `hub-people`.
- group-gate labels: `traefik.http.middlewares.vpn-required-path.replacepath.path: /vpn-required`.

- [ ] **Step 1: Write the failing checks.**
  - In unit-tests' compose step, over `--profile '*'` configs (default and podman, with and without the SELinux overlay):
    - `wg` has no `cap_add`, `devices`, `sysctls`, `privileged`, `network_mode`, and no engine-socket mount;
    - Traefik's `VPNSECURE_PROXYPROTOCOL_TRUSTEDIPS` equals `<wg ipv4_address>/32`;
    - no `TRAEFIK_ENTRYPOINTS_VPNSECURE_FORWARDEDHEADERS_*` key exists;
    - every `traefik.http.routers.*.entrypoints` of core services equals the interpolated value of one of the three variables (also asserted in `tests/test_cli.sh` on the raw file: each label is literally one of the three `${PORTCULLIS_EP_*:-websecure,vpnsecure}` strings);
    - `portcullis-vpn` members are exactly traefik and wg, at their pinned addresses;
    - `docker-compose.podman.yml` names `wg`.
  - The existing jq checks (hardening baseline, NET_ADMIN / SYS_ADMIN, image pins, `lint_healthchecks.sh`, `lint_images.sh`, `CORE_SERVICE_NAMES` diff) now see `wg`.
  - The "Shared vpn.json vectors match the Hub" step: a copy of the sign-in vectors step comparing `tests/vpn_json_vectors.json` with the Hub's `internal/vpn/testdata/vpn_json_vectors.json`.
  - V3(a): `[ "$NBINDS" = 46 ]` (was 45).
  - V3(b): "UNPINNED base" and "one golang builder" loops add `wg/Dockerfile` and `forwarder/Dockerfile`.
  - V3(d): `hub_data` consumer check runs over `$CFG_ALL` and includes `wg`.
  - V3(e): Go cache key and dependabot add `/wg`, `/forwarder`, `/tests/e2e/vpn-client`.
  - Shell tests: "validate_vpn_network_config: wg ip outside the subnet → fail", "… traefik ip inside the ip_range → fail", "… overlap with the proxy subnet → fail".
- [ ] **Step 2:** Run `PORTCULLIS_ROOT=/tmp/pv-x ./portcullis init --env-only --runtime docker --non-interactive --domain ci.example.org --dns-provider none`, then the jq checks and the shell tests. Expected: FAIL.
- [ ] **Step 3:** Implement the compose changes. `stack_prepare` creates an empty `secrets/wg/people.key` placeholder (0640, `ct_group_read 10006`) so the bind never makes a directory and the SELinux overlay's missing-source rule holds. `wg` treats an empty key file as "people off". V5: `volume_own wg_data 10006:10001` (directory 2750); `wg` chgrps files to 10001 (allowed as a member). V20: `validate_vpn_network_config` validates `PORTCULLIS_VPN_IP_RANGE`; the Hub derives gateway addresses from `Config.VPNNet` (/26 minimum). Add `secrets/wg` to `secrets_fix_perms`.
- [ ] **Step 4:** Run `docker compose -f docker-compose.yml config -q` (also with `--profile '*'` and the overlays), the jq checks and the core gates. Expected: PASS.
- [ ] **Step 5:** Commit (`compose: wg service (profile wg, no caps), portcullis-vpn network, Traefik vpnsecure (PROXY from wg only), core entrypoint classes, people-vpn-enrol, overlays; CI static checks`).
- [ ] **Step 6 (controller):** Run `gh workflow run ci.yml --ref vpn1 -f jobs=unit-tests,build-and-test`. Expected: green (VPN off: nothing else changes).

---

### Task 15: Core CLI: `vpn …`, status, backup, alerts, cleanup

**Files:**
- Create: `scripts/lib/vpn.sh`
- Modify:
  - `portcullis` (source `vpn.sh`, `help_main`)
  - `scripts/lib/common.sh` (`HUB_ENV_VARS` += the four core.env keys)
  - `scripts/lib/status.sh` (`status_run` VPN block, `--json` `vpn{}`, `status_textfile` `portcullis_vpn_mode_restricted`)
  - `scripts/lib/backup.sh` (V14: drop `headscale-config.yaml` lines 10, 328, 860–862; `secrets/wg` is already under `secrets/`)
  - `scripts/lib/keycloak.sh:854-859,936` (V14: remove optional headscale/headplane clients and their help text; V26 keep netbird client in the same block)
  - V14: Delete `headscale/config.yaml`, remove headscale + headplane services and volume from `docker-compose.apps.yml` (lines 64–84, 199), remove README line
  - `monitoring/prometheus/prometheus.yml` (V13: `file_sd` for `wg` written by `vpn init`/`builtin`, empty when profile off), `alerts.yml` (`PortcullisVPNDown`, `PortcullisVPNProviderStale`), `tests/alerts_test.yml`
  - `tests/test_shell_libs.sh`, `tests/test_cli.sh`, `.env.example`, `CLAUDE.md` (the lib list; the Admin CLI VPN bullet)

**Interfaces — Produces (bash):**
- `vpn_entrypoints <mode> <public_enrol>` prints three lines, `PORTCULLIS_EP_CORE=…`, `PORTCULLIS_EP_ADMIN=…`, `PORTCULLIS_EP_ENROL=…`:
  - `apps` → all `websecure,vpnsecure`;
  - `admin` → ADMIN `vpnsecure`;
  - `server` → CORE and ADMIN `vpnsecure`, ENROL `websecure,vpnsecure` when public enrolment is on, else `vpnsecure`.
- `vpn init [--builtin on|off] [--port N] [--subnet CIDR]`:
  - `need_env`, Hub healthy.
  - Overlap refusal against Docker networks (`docker network inspect` of all), `portcullis-vpn`, the reserved link default `10.214.0.0/24`, and the Hub's `hub vpn host-info` (Local networks, provider ranges). It suggests the next free /22 in `10.213.0.0/16`.
  - V4: `--builtin on` → `env_set COMPOSE_PROFILES` → `runtime_build_service wg` → `ct_run --rm --network none --user 0:0 --cap-drop ALL … genkey` writing the key in place (truncate + write, no rename) → `ct_group_read 10006`. `vpn builtin on|off` recreates `wg`. Add `secrets/wg` to `secrets_fix_perms`. Stub tests assert `ct_run`.
  - Writes `PORTCULLIS_VPN_BUILTIN`, `_PORT`, `_SUBNET`, adds `wg` to `COMPOSE_PROFILES` (`env_set`), `hub_env_write`, `stack_compose_up wg traefik hub`.
- `vpn mode apps|admin|server [--force] [--public-enrol true|false]`:
  - The lock-out guard for admin/server: `hub vpn host-info` `.admin_device_seen` must be true, else exit 1 naming `--force`. `apps` never checks and works with `wg` and the Hub down.
  - Writes `PORTCULLIS_VPN_MODE`, `PORTCULLIS_VPN_PUBLIC_ENROL` and the three `PORTCULLIS_EP_*`, then `hub_env_write` and `stack_compose_up` (core recreated).
- `vpn builtin on|off`: off empties the key file and sets `PORTCULLIS_VPN_BUILTIN=off`; the edge keeps running.
- `vpn add-device <user> <name>`:
  - `kp=$(dc exec -T wg /wg keypair)`;
  - `KP="$kp" jq -rn 'env.KP | fromjson | .public_key'` piped to `dc exec -T hub hub vpn add-device --user U --name N`;
  - the config assembled by `jq -rn` reading only `env.X` (never `--arg` with a key);
  - printed, then piped to `dc exec -T wg /wg qr`;
  - `unset kp`.
- `vpn devices [--user U] [--json]`, `vpn revoke <device-id>` (through `hub vpn`).
- `vpn_status_lines` / `vpn_status_json`: from `dc exec -T wg /wg status`: mode, roles ok, the built-in port and subnet, per provider label / ranges / devices / map age.
- Status counts a Problem when mode ≠ apps and `wg` is down.

- [ ] **Step 1: Write the failing tests** (stubs answer `docker compose exec … wg /wg keypair|status|qr` and `… hub hub vpn …`).
  - "vpn_entrypoints: apps/admin/server × public_enrol" (6 cases, exact lines).
  - "vpn init: subnet overlapping a Docker network → refused with a suggestion".
  - "vpn init: overlapping a Local network from hub vpn host-info → refused".
  - "vpn init writes the keys, adds wg to COMPOSE_PROFILES once".
  - "vpn mode server without an admin device → refused naming --force", "vpn mode apps with wg and hub down → writes and recreates".
  - "vpn add-device: the private key never on argv" (the stub logs argv; grep for the stub's fixed private key → absent) and "the config has AllowedIPs = 10.213.0.1/32".
  - "status --json has vpn{}", "status textfile has portcullis_vpn_mode_restricted".
  - "keycloak.sh registers no headscale client", "backup has no headscale-config.yaml".
  - In `tests/test_cli.sh`: every `vpn` subcommand's `--help` works without `.env` or Docker; argument errors exit 2.
  - Promtool: alert tests for both alerts (firing and not), each with `exp_annotations`. V13: test "profile off → no TargetDown".
- [ ] **Step 2:** Run `bash tests/test_shell_libs.sh; bash tests/test_cli.sh`. Expected: the new cases FAIL.
- [ ] **Step 3:** Implement. Alerts:
  - `PortcullisVPNDown`: `portcullis_vpn_mode_restricted == 1 and on() (absent(up{job="wg"}) or up{job="wg"} == 0)` for 2m;
  - `PortcullisVPNProviderStale`: `wg_provider_stale == 1` for 5m.
- [ ] **Step 4:** Run the core gates and promtool as CI does. Expected: PASS.
- [ ] **Step 5:** Commit (`cli: vpn init|mode|builtin|add-device|devices|revoke (lock-out guard, break-glass), status, alerts; remove core's headscale leftovers`).

---

### Task 16: group-gate policy v7: the binding, core-host classes, `/vpn-required`

**Files:**
- Modify: `group-gate/group-gate.py`, `tests/test_group_gate.py`, `docker-compose.yml` (group-gate env `GATE_VPN_FILE: /hub-data/vpn.json`), `scripts/lib/status.sh` (`hub_policy_check` unchanged, reads v7), `CLAUDE.md` (group-gate bullet)

**Interfaces — Produces (Python):**
- `POLICY_VERSION = 7`, `PUBLIC_GUARD_VERSION = 7`, `POLICY_REQUIRED_KEYS` += `"vpn"`.
- `validate_vpn_section(v) -> Optional[str]` (unknown keys, bad hostnames, a `via` that isn't `["*"]` or 1–8 ids, `devices_file != "vpn.json"` → an error, so the doc denies everything).
- `VPN_FILE`, `parse_vpn_doc(doc) -> dict` (the contract rules; raises `ValueError`).
- `load_vpn_file(now=None) -> Optional[dict]` (cached by stamp like `load_impersonation_file`, logged once per change, never values).
- `client_address(headers) -> Optional[ipaddress.IPv4Address]` (the last `X-Forwarded-For` entry; IPv6 or garbage → None).
- `CORE_HOST_CLASSES = {"traefik": "admin", "hub": "admin", "directory": "admin", "metrics": "admin", "auth": "admin", "people": "core", "": "core"}`.
- `vpn_check(policy_doc, vpn_doc, host, kind, path, addr, username, now) -> Optional[Tuple[str, str]]` (None = allowed; else `(reason, page_text)`). Reasons are metric labels: `vpn_not_vpn`, `vpn_stale`, `vpn_via`, `vpn_unknown_device`, `vpn_expired`, `vpn_other_owner`, `vpn_no_doc`.
- `do_GET`: `/vpn-required` → 403 with the exact spec copy (no sign-in, no app content). The full checks call `vpn_check` after the identity and before the group checks.
- The opened log gains `via`, `provider`, `device`.

- [ ] **Step 1: Write the failing tests.**
  - `test_vectors_vpn_json` (reads `tests/vpn_json_vectors.json`).
  - `test_policy_v6_denies`, `test_vpn_unknown_key_denies`, `test_devices_file_other_denies`.
  - Binding cases, one test each: outside ranges, stale provider, `via` mismatch, unknown device, expired, other owner, disabled owner (the device absent from the doc), allowed.
  - `test_expired_device_denied_by_clock` (Review Focus 4).
  - `test_last_xff_wins` (`X-Forwarded-For: 10.213.0.5, 203.0.113.9` → 203.0.113.9 → `vpn_not_vpn`).
  - `test_internet_app_via_vpn_needs_no_binding` (Q3).
  - Core classes:
    - `admin_only`: `hub.<d>` from a non-VPN address → denied; with a bound device → allowed.
    - `server_mode`: `people.<d>/vpn/` from the internet with `public_enrol` → allowed; `people.<d>/signin` → denied; V17 the portal `/portal` also denied (backend call to `vpn_check` class `core`).
  - V17: `test_public_guard_vpn_steps_1_2` (public hosts enforce steps 1–2 but not 3).
  - `test_vpn_required_page` (403, the exact text, no `Set-Cookie`).
  - `test_reason_pages_hide_owner` (the page never contains the device owner's name).
  - `test_opened_log_via_fields`.
- [ ] **Step 2:** Run `python3 -m pytest -q tests/test_group_gate.py`. Expected: FAIL.
- [ ] **Step 3:** Implement with stdlib `ipaddress`. Fail closed on every exception path, cached like the impersonation file.
- [ ] **Step 4:** Run the core gates. Expected: PASS.
- [ ] **Step 5:** Commit (`group-gate: policy v7 (vpn section), vpn.json v2 reader, device ↔ person binding, core-host classes, /vpn-required`).

---

### Task 17: Core CI: "Test the VPN service" and `e2e-vpn`

**Files:**
- Create: `tests/e2e/vpn-client/{go.mod,main.go}` (a wireguard-go netstack client: `vpn-client --conf <stdin> --get https://<host>/... --resolve`, with HTTP over the tunnel through `tnet.DialContext`), `tests/e2e/e2e_vpn.py` (Playwright for sign-ins, stdlib otherwise, ops via `e2e_ops.py`)
- Modify: `.github/workflows/ci.yml` (a build-and-test step; the new job after `e2e-podman`; the `workflow_dispatch` description list), `CLAUDE.md` (Testing bullet)

**Interfaces:**
- Consumes: everything above; the headscale template (same-named templates branch, else main; the step fails without its `vpn:` block); the CI fixture `tests/e2e/apps/echo`.
- Produces: job `e2e-vpn`: `runs-on: ubuntu-latest`, `timeout-minutes: 45`, `needs: jobs-input`, the usual name-match `if`, `ACME_STAGING=true` with the CI override, `COMPOSE_PROFILES=wg`.

- [ ] **Step 1: The build-and-test step "Test the VPN service".**
  - `./portcullis vpn init` succeeds.
  - `wg` is healthy, its user is `10006`, `CapAdd` is null, `/data/status.json` is 0640 group 10001.
  - `curl` from a throwaway container on `portcullis-vpn` (the CI override joins it at `.20`) to Traefik `.2:8443` with a hand-made PROXY v2 header claiming `10.213.0.5` → the header isn't honoured (the app answers 403 from the allowlist, or the connection is refused).
  - Spoofed `X-Forwarded-For` / `X-Real-Ip` on `websecure` → group-gate logs the real address.
- [ ] **Step 2: The `e2e-vpn` job setup.**
  - Clone the templates (the e2e-folders pattern).
  - `init` with the CI override; seed the Hub with echo + headscale.
  - Create alice and bob (setup links, as in e2e).
  - `./portcullis vpn init`; create `echo-vpn` (echo) and a headscale instance; set its API key through `PUT /api/instances/{id}/settings` after `headscale apikeys create` via `docker exec`.
  - Wire headscale through the Hub API.
  - Build `tests/e2e/vpn-client` and a userspace `tailscaled` (V3: fully qualified `docker.io/tailscale/tailscale:tag@sha256`, no caps, on the runner's default network).
  - Register a node through Keycloak OIDC with Playwright as alice, and a second node from a pre-auth key of a non-OIDC Headscale user.
  - Built-in device for alice through the `/vpn/` API with a fresh-auth proof (the e2e-signin helper), and one for bob.
- [ ] **Step 3: Assertions**, each failing with `FAIL: <what>`, for the built-in and for headscale:
  - `echo-vpn` set to `vpn` → `websecure` answers only `/vpn-required`.
  - Through the tunnel:
    - sign-in still demanded (302 to `auth.`);
    - with alice's session it opens;
    - bob's device with alice's session → 403 "this device isn't yours";
    - `via: ["builtin"]` → the tailnet device gets 403.
  - Revocation: a built-in device revoked → its handshake fails within 5 s; a headscale node deleted → denied within `refresh` + 10 s.
  - `docker stop portcullis-wg-1` → `echo-vpn` unreachable on both paths, with no internet fallback.
  - Stopping the headscale gateway → only tailnet devices fail.
  - A broken identity hook (API key setting cleared) → tailnet devices denied once stale (refresh set to 15 s → within 3 min 15 s), the built-in unaffected.
  - The non-OIDC node → denied ("not a Portcullis person" on the VPN tab).
  - A gateway claiming a built-in address (a raw PROXY header to the headscale edge port from the gateway's address) → closed; `wg_edge_rejected_total{reason="outside_ranges"}` increments.
  - `vpn mode server --force`:
    - on `websecure` only the public set answers (headscale's control router, `auth.` sign-in pages, `enroll.`, `people.<d>/vpn/`);
    - `keycloak-admin` and `hub.` don't;
    - `vpn mode apps` with `wg` stopped restores them.
  - DNS: the built-in resolver answers `echo-vpn.<d>` A `10.213.0.1` and AAAA NODATA; the tailnet resolves it to the gateway address (MagicDNS through `tailscale status` / `nslookup` inside the tailscaled container).
  - Failure artifacts: logs only (never `.env`, `secrets/`, configs or keys).
  - V25: Add a small step to `e2e-podman`: `vpn init`, `wg` healthy as 10006 with `CapAdd` null, one built-in `vpn-client` handshake + GET through the tunnel. The SELinux overlay check is already static.
- [ ] **Step 4:** Run `actionlint` and `bash tests/test_cli.sh`. Expected: PASS. Add `e2e-vpn` to the description list, then commit (`ci: Test the VPN service step, e2e-vpn (built-in + headscale end to end)`).
- [ ] **Step 5 (controller):** Run `gh workflow run ci.yml --ref vpn1 -f jobs=build-and-test,e2e-vpn`. Expected: green. If the Q5 premise failed in Task 10, the headscale half follows the fallback chosen there.

---

### Task 18: Docs pages

**Files:**
- Create: `docs/operations/vpn.md`
- Modify:
  - `docs/operations/.nav.yml` (`- VPN: vpn.md` after Rootless Podman)
  - `hardening.md`: the `wg` row (no caps, roles, PROXY trust only from `wg`, the gateway trust note of spec §5, the runtime matrix)
  - `auth-policies.md` ("a VPN never replaces sign-in"; the binding)
  - `hub.md`: Access → Reachable from, VPN tab, Settings → VPN, the doctor kinds, and the person-facing "VPN devices" (`/vpn/`, client apps per OS, V26 DNSSEC-validating clients cross-link `docs/setup/dns.md`, browser DoH)
  - `cli.md` (`vpn …`, restating `--help`), `backups.md` (`secrets/wg`; `wg_data` is status only), `monitoring.md` (job `wg`, both alerts), `testing.md` (`e2e-vpn`, the step, the static checks)
  - `docs/guides/manifest-reference.md` (`vpn:`, the `vpn` trigger), `rootless-podman.md` (TUN gateways `degraded`, `modprobe tun`), `includes/abbreviations.md` (VPN provider, edge, device binding, VPN-only)
- Regenerate the app catalog: `python3 scripts/generate-app-docs.py --source /Volumes/workspace/portcullis/wt-vpn1/portcullis-templates`.

- [ ] **Step 1:** Write `vpn.md`. Sections:
  - the model (five gates);
  - built-in setup;
  - wiring a marketplace VPN;
  - several VPNs and *Through*;
  - modes and the public set;
  - enrolment and `public_enrol`;
  - revocation delay per provider;
  - DNS caveats;
  - break-glass (`vpn mode apps`) and the lock-out guard;
  - what isn't covered (spec non-goals).
- [ ] **Step 2:** Run the docs gate. Expected: exit 0. Commit (`docs: VPN-only access (operations page, hardening, CLI, Hub, manifest reference, testing)`), push, resync the Hub `web/docs` and commit there (`docs: sync`).

---

### Task 19: Templates `vpn2`: NetBird and plain WireGuard providers (after the core merge)

**Files:**
- Modify: `netbird/manifest.yaml`, `netbird/compose.yml`, `tests/apps/netbird.sh`, `tests/rootless.txt` (regenerated)
- Create: `wireguard/{manifest.yaml,compose.yml}`, `tests/apps/wireguard.sh`, `.github/dependabot.yml` entry

**Interfaces:**
- Consumes: `ghcr.io/porelli/portcullis-forwarder:edge` digest, published by core main (get it with `docker buildx imagetools inspect`).
- Produces:
  - **netbird**:
    - service `gateway`: the pinned `netbirdio/netbird` client, `cap_add: [NET_ADMIN]`, `devices: [/dev/net/tun]`, setup key from a `secret` setting;
    - service `forwarder`: V11 `network_mode: service:gateway`, V12 `cap_add: [NET_BIND_SERVICE]`, the forwarder image pinned by digest.
    - V26: `vpn: {label: NetBird, ranges: ["{{setting:netbird_range}}"], ingress: {service: gateway, proxy_protocol: v2}, identity: {source: hook, hook: vpn-devices, owner: oidc_sub, refresh: 60s}, dns: {manual: true}, control_routers: [netbird-mgmt, netbird-signal]}` (+ netbird-api if needed; there is no relay router).
    - `vpn-devices` runs in a `vpn-glue` python service: `/api/peers` + `/api/users`, with a service-user token `secret` setting.
    - Rootless: `degraded` with rule 6's reason.
  - **wireguard**:
    - `wg-easy` pinned, its UI behind `portcullis-auth`/`portcullis-groups`;
    - `identity: {source: static}`, `dns: {manual: true}`;
    - V11 V12: the forwarder in its netns with `cap_add: [NET_BIND_SERVICE]`;
    - NET_ADMIN + `/dev/net/tun`; `degraded` under rootless.

- [ ] **Step 1:** Create `vpn2` from templates main after Task 20 Step 3. Write the failing checks:
  - each `tests/apps/*.sh` validates the block;
  - the forwarder image pinned by digest;
  - `network_mode: service:gateway` on the forwarder;
  - `tests/rootless.txt` lists both as `degraded` with the TUN reason.
- [ ] **Step 2:** Run the templates gates. Expected: FAIL.
- [ ] **Step 3:** Implement. Regenerate `tests/rootless.txt` with `python3 tests/validate.py --rootless > tests/rootless.txt`. Review its diff: only these two lines change.
- [ ] **Step 4:** Run the templates gates, then lint.yml and Test Apps `apps=netbird,wireguard` on `vpn2`. Expected: green.
- [ ] **Step 5:** Commit (`netbird, wireguard: Portcullis VPN providers through portcullis-forwarder`), merge `vpn2` through a detached worktree, and regenerate the docs catalog on docs main (`docs: app catalog (VPN providers)`).

---

### Task 20: Full CI, merge, deploy, client checks, cleanup

**Files:** none new (merges and the test server).

- [ ] **Step 1 (controller):** Run a full core CI `gh workflow run ci.yml --ref vpn1`, plus Hub `build.yml`, templates lint and Test Apps on `vpn1`. Expected: all green.
- [ ] **Step 2: Merge docs**, then the Hub (Global Constraints). Run `gh workflow run build.yml --ref main -f compare_ref=vpn1` and wait for `edge`.
- [ ] **Step 3: Merge templates `vpn1`, then core, without a pause** (the policy v7 window). Wait for `forwarder.yml` to publish `edge` on core main, re-run templates Test Apps on main, then do Task 19.
- [ ] **Step 4: Deploy to the test server** (`ACME_STAGING=true` stays):
  1. **Before**, record `./portcullis status --json` and every app host's answer.
  2. Run `git pull --ff-only && ./portcullis upgrade`.
  3. **After the upgrade (VPN still off):**
     - status is clean, with no `wg` container;
     - the policy file is version 7 (`hub_policy_check`);
     - every app answers as before;
     - the routers carry `websecure,vpnsecure`.
  4. Run `./portcullis vpn init`. The user opens UDP 51820 in the server's cloud firewall.
  5. **The user's client checks (Mac and iPhone, official WireGuard app):**
     - add a device on `people.<d>/vpn/` and import it by QR or file;
     - set one test instance to VPN only;
     - from the internet it shows `/vpn-required`;
     - over the tunnel it asks for sign-in and opens;
     - a second person's session on that device → 403;
     - DNS resolves through the tunnel.
  6. **Headscale (the user):**
     - install it from the Marketplace, set its API key, wire it;
     - register the Mac and the iPhone with the Tailscale app (custom login server, OIDC through Portcullis);
     - repeat the instance checks with *Through* = all, then = built-in only (tailnet refused);
     - check MagicDNS resolution (Q7: A only).
  7. `vpn mode admin`: the guard passes with the admin's device online; `hub.<d>` from the internet is refused, through a VPN it's allowed. Then `vpn mode apps`.
  8. Leave mode `apps`, the built-in on and the test instance back on `internet`. Never touch LLDAP `admin`.
- [ ] **Step 5: Clean up.**
  - Delete the `vpn1` and `vpn2` branches (local + `git push origin --delete`) in every repo.
  - `git worktree remove` every `wt-vpn1/*` and `/tmp/merge-*`, then `git worktree prune`.
  - Remove `/tmp/pv-*`.
