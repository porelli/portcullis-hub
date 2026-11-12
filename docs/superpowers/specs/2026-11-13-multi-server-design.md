# Multiple servers management (design)

Status: written by the assistant for the roadmap item "multiple servers management" (the user's words). No interruptions were wanted, so the assistant made every decision. Each one is the **assistant's call** unless it says otherwise. Open questions are in §14, each with a default. This design builds on `2026-11-13-vpn-only-access-design.md` (userspace WireGuard, `vpnsecure`), `2026-11-13-rootless-podman-design.md` (runtime selection, socket proxies on the engine socket) and `2026-11-13-dns-hardening-design.md` (the DNS plan). There is no Kubernetes spec yet; §12 says how one would fit.

## 1. Where things stand (2026-11-12)

- **One server is one stack.** Traefik, Keycloak (realm `portcullis`, sign-in methods and templates), LLDAP, Vault PKI (`pki_int` for YubiKey certificates, `pki_file` for browser certificates), oauth2-proxy ×2 + the `sessions` store, group-gate (policy v6 from `hub_data`), enroll, domains, mcp-gate and the Hub all run on one Docker (or, later, rootless Podman) host.
- **The Hub drives one engine.** `DOCKER_HOST=tcp://socket-proxy-hub:2375`. It uses `internal/docker` (moby client: containers, exec, logs, events, volumes, helper create + archive, `RunHelper` for the folder fixer) and `internal/compose` (`docker compose -p portcullis-<id>` with `PROJECT_HOST_DIR` so relative binds such as `./templates/<app>/setup.py` and `./certs/ca-bundle.crt` resolve to host paths).
- **Routing is labels.** Instance containers join the external `portcullis-proxy` network and carry Traefik labels that the Hub's override rewrites (TLS tier, public routers, `portcullis-oauth2-*` routers, extra-domain auth, and later the VPN entrypoints). Traefik's docker provider only sees local containers. Its single HTTP provider is taken by the domains service.
- **The session cookie is domain-wide.** `forward-auth` sets its ticket cookie for `.<d>`, so every `*.<d>` backend receives it. On one server all backends are equally trusted, so this is fine today. A ticket can be replayed until the session ends.
- **Header trust.** Header-auth apps trust identity headers only from `PORTCULLIS_TRAEFIK_IP` (contract §2).
- **Backups.** Instance backups (§11.5) are archives in `hub_data/backups/<id>/`, made with never-started helpers through the archive endpoints. Core `backup` archives `hub_data`, and restic ships it offsite.

## 2. What "multiple servers" means: one primary, worker servers, primary ingress (assistant's call)

| Option | Verdict |
|---|---|
| (a) One control plane (the primary's Hub) places app instances on several worker servers | **Chosen** |
| (b) Several independent Portcullis servers seen from one Hub | Rejected. Each would have its own people, sign-in methods and policy. "Sign-in strength identical everywhere" would then be a sync problem, and a person would have N accounts |
| (c) Identity shared across servers | **Included, by construction**: there is exactly one LLDAP, one Keycloak and one group-gate, on the primary |
| (d) HA / failover | Non-goal (§3). The primary is restorable onto a new host, and workers re-attach by themselves (§9) |

**Ingress stays on the primary** (assistant's call, the central decision). DNS (`<d>`, `*.<d>`, enrolled domains) keeps pointing only at the primary. The primary's Traefik terminates TLS and runs forward-auth, group-gate and the TLS tier for every host, including the hosts of instances on workers. It then forwards the request through a WireGuard tunnel that the worker dials out to the primary. Why:
- Sign-in strength and group rules are identical **structurally**, not by synchronisation. A worker has no Traefik, oauth2-proxy or group-gate that could drift, so the policy file stays v6/v7 unchanged.
- Workers hold no ACME account, no DNS credentials, no certificates and no cookie secret.
- Workers need **no inbound port and no public address**. A NAS behind home NAT can be a worker for a VPS primary (the same outbound-only model as Portainer's Edge Agent).
- Fail closed is structural: if the primary is down, nothing routes to a worker app.

The cost is that all app traffic crosses the primary (bandwidth, one extra hop). That's fine for home and small-office use. Direct ingress on a worker is parked (§13).

## 3. Goals, non-goals, anti-goals

**Goals**
1. Add a server from the Hub with one copy-paste command. See its health, runtime, capacity and instances.
2. Choose a server when creating an instance, and later **move** the instance between servers. Hostnames, groups, Keycloak clients and policy don't change.
3. Every instance feature works on a worker unless it's listed as primary-only in §7: backups and restores, logs, exec hooks, drift, operation progress + Stop, public exceptions, VPN-only, shared folders.
4. Revoke a lost or compromised server in one action, without its cooperation.
5. Doctor, status, monitoring, CI and docs cover all of it.

**Non-goals (v1)**
- HA, failover, a second primary, or workers taking over the primary's role.
- Running core services (Keycloak, LLDAP, Vault, Hub) on workers.
- Direct ingress to workers. Non-HTTP Traefik routers (`traefik.tcp/udp`) on workers.
- File-sharing apps (Samba, Time Machine: `hub_secrets`, per-person secrets) on workers. This is part 2 (§13).
- Automatic placement or scheduling (bin-packing). Placement is always an admin choice.
- Remote agent upgrades from the Hub.

**Anti-goals (never)**
- **Never expose a Docker/Podman socket, or the Engine API, over the network.** The worker's engine socket is mounted only into its local socket proxy (contract §6, word for word on the worker). The network carries only the agent's operation API (§5), which is narrower than `socket-proxy-hub`.
- **A compromised worker never gains control of the primary or of another worker.**
  - It never receives: session cookies; the proxy secret; Keycloak, LLDAP, Vault or DNS credentials; the cookie secret; or another server's bundles.
  - The primary's end of the tunnel **listens on nothing**: every connection is opened by the primary.
  - Everything an agent returns is untrusted input: size-capped, schema-checked, and never executed or used as a path.
  - Worker identities are per server and pinned (§6).
- **Sign-in strength and group rules are the same on every server.** No setting, placement or server state can weaken or skip `portcullis-auth`/`portcullis-groups` for an instance.
- **Fail closed when the primary is unreachable.** Worker apps become unreachable through Portcullis. The agent makes no change on its own.
  - What keeps working: worker containers keep running (restart policies), and their data is safe. `lan_only` ports published on the worker's LAN stay up, because by definition they are outside sign-in today too. Host break-glass also works (§9).
  - What stops: every routed app, cert renewal (it is driven by the Hub), and backups.
- Never weaken a rootless/hardening property on a worker. The worker's agent and socket proxy follow `hardening.md`, and the rootless spec applies per server.

## 4. Topology and new components

```
browser ─TLS─▶ primary Traefik ─(forward-auth, group-gate, tier)─▶ relay ─▶ link ══WireGuard══▶ worker agent ─▶ app container
                                                                Hub ─▶ link ══(mTLS inside WG)══▶ agent ─▶ socket-proxy-agent ─▶ engine
```

- **`link` (core, Go, profile `workers`, off by default).** A userspace WireGuard endpoint: wireguard-go + gVisor netstack, sharing a small `wgnet` package with the VPN spec's `vpn` service. It has no capabilities, runs read-only as uid 10007 with `no-new-privileges`, and needs no TUN.
  - Publishes `${PORTCULLIS_LINK_PORT:-51821}/udp` (the endpoint is the apex `<d>`, already in the DNS plan).
  - Tunnel subnet `${PORTCULLIS_LINK_SUBNET:-10.214.0.0/24}`: link `.1`, workers `.10`–`.250`, MTU 1380. Each peer's AllowedIPs is its /32. Keepalive 25 s, set on the worker side so NAT works.
  - **The netstack has zero listeners.** link only *dials* into the tunnel, for two internal clients:
    - the Hub, on internal network `portcullis-link` (members: hub, link). It sends HTTP `CONNECT <worker-ip>:7443` (control) and nothing else;
    - relays, on internal network `portcullis-link-data` (members: link and relays only). They send `CONNECT <worker-ip>:7000` with a per-instance bearer, and link checks bearer → worker.
  - Config: `hub_data/link.json` v1, written by the Hub (public keys, IPs, states, relay token hashes), reloaded through UAPI on change, so a removed peer is dropped at once. Server key `secrets/link/server.key` (`./portcullis link init`).
  - `/metrics` on `monitoring`: per-peer handshake age and rx/tx, plus each agent's metrics scraped over the tunnel and re-labelled `server=`.
- **Relays (primary, per placed instance).** When an instance runs on a worker, its compose project **on the primary** (`portcullis-<id>`) contains only relay services, one per routed template service. Each relay has the same service name and **the same Traefik labels the Hub renders today**. So the TLS tier, public, `portcullis-oauth2-*`, extra-domain, VPN entrypoints and exposure-drift code all apply unchanged. The relay (`portcullis-relay` image, a few MB, Go `httputil.ReverseProxy` with upgrade/WebSocket support) listens on each `loadbalancer.server.port` and forwards over link to the agent. It also filters cookies (assistant's call):
  - **request:** it deletes the Portcullis cookies (`_oauth2_proxy*`, `__Host-portcullis_ext*`, and the CSRF cookies);
  - **response:** it drops any `Set-Cookie` with a reserved name, or with a `Domain` attribute other than the request host. Worker apps can only set host-only cookies, so there's no cookie tossing onto `.<d>`.

  When the worker is offline it answers 503 with a static page: "<app> runs on <server>, which is offline".
- **`portcullis-agent` (worker).** Go, in the Hub repo (`cmd/portcullis-agent`), so it shares `internal/compose`, `internal/templates` checks, `folderfix` and the helper specs. Image `ghcr.io/porelli/portcullis-agent`, pinned like `HUB_IMAGE`. It runs as uid 10008, read-only, with no capabilities, and uses its own userspace WireGuard client.
  - It listens **only inside its netstack**: `:7443` control (mTLS), `:7000` data (accepted only from `10.214.0.1`).
  - It drives the engine through **`socket-proxy-agent`**: the same image and environment as `socket-proxy-hub`, on its own internal network, the only container that mounts the engine socket.
  - It creates the worker's internal `portcullis-proxy` network with the primary's `PORTCULLIS_PROXY_SUBNET` and pins **itself at `PORTCULLIS_TRAEFIK_IP`**. Header-auth templates therefore work unchanged: on a worker the only peer at that address is the agent.
- **Worker install** uses the same core CLI (assistant's call): `./portcullis worker join <code>` writes `.env` with `PORTCULLIS_ROLE=worker` and starts only `agent` + `socket-proxy-agent` (`docker-compose.worker.yml`). It supports Docker or rootless Podman (`CONTAINER_RUNTIME`, as in the rootless spec), amd64/arm64. Other commands: `worker status|upgrade|leave|stop <instance>|start <instance>`.

## 5. The agent API (control, `https://<worker-ip>:7443/v1`, mTLS)

Callers: the Hub's control certificate (§6). The `link` certificate may call only `GET /v1/metrics`. Every request and response is JSON, or a tar/ndjson stream with a size cap. The agent **re-validates** every bundle with the same rules the Hub applies (`useroverride.go`/`coreref.go`: no `privileged`, `devices`, `userns_mode`, `network_mode` other than allowed, bind roots inside the bundle or the server's folder roots) and refuses anything outside the projects it was given.

| Agent operation | `socket-proxy-hub` section it uses | Scope the agent enforces |
|---|---|---|
| `GET /info` (engine version, runtime, rootless map, arch, CPU/mem, disk of `DockerRootDir` and data dir, SecurityOptions, agent version, API range, published port binds) | INFO, VERSION, PING | — |
| `PUT /projects/{id}/bundle` (tar: compose, env, override, user override, `templates/<app>/`, the instance's `appfiles/`, `certs/ca-bundle.crt`; sha256 manifest) | — | `id` matches the instance pattern; stored 0600 under the agent's data dir, mounted at the same host path (as `PROJECT_HOST_DIR`) |
| `POST /projects/{id}/up\|down` (ndjson progress; `DELETE /ops/{op}` = Stop, as `stop_op`) | CONTAINERS, IMAGES, NETWORKS, VOLUMES, POST | only projects with a bundle; `docker compose -p portcullis-<id>` |
| `GET /projects/{id}/ps`, `GET /containers/{cid}` (inspect/state), `/logs?tail=`, `POST /exec`, `POST /kill` | CONTAINERS, LOGS, EXEC, POST | only containers labelled `com.docker.compose.project=portcullis-<id>` of a bundled project |
| `GET /events` (stream) | EVENTS | filtered to bundled projects |
| `POST /images/pull` | IMAGES, POST | only refs in a bundle, or the pinned helper/fixer image |
| `GET/POST/DELETE /volumes` | VOLUMES, POST | only volumes compose labelled with a bundled project, or the §11.2 names of a placed instance |
| `POST /helpers` `{kind: volume_io\|folder_fix, …}`, `GET/PUT /helpers/{h}/archive`, `DELETE /helpers/{h}` | CONTAINERS, ARCHIVE, POST | fixed specs only (the Hub's current helper and fixer specs, byte for byte); `folder_fix` only under the server's folder roots |
| `POST /identity/csr`, `PUT /identity/cert`, `PUT /identity/wg` | — | key rotation (§6); private keys never leave the worker |
| `GET /metrics` | — | Prometheus (node + container states) |
| **Data `:7000`** | — | first line `{"instance","service","port"}`; allowed only for routed services of bundled, enabled instances. The agent dials the container on its `portcullis-proxy` |

Not offered, ever: arbitrary container create, `build`, `commit`, system/df/prune, plugins, swarm, secrets/configs, `/libpod/…`, a raw Engine API passthrough. The API is versioned. The Hub accepts an agent in the same or the previous minor version and refuses others (`server_agent_incompatible`).

**In the Hub:** `internal/docker` and `internal/compose` sit behind one `Engine` interface with two implementations: `local` (as today) and `agent` (this API). Instance code asks `engineFor(instance)`. Backups, restores, drift, deliver hooks and the doctor work through the interface unchanged.

## 6. Identity, enrolment, revocation

- **PKI.** A new Vault intermediate `pki_node` under the existing root. It is never trusted by Traefik, Keycloak or group-gate, so a node certificate can never sign anyone in, and a person's certificate can never act as a node. Roles:
  - `node-worker`: CN/SAN `<server-id>.node.portcullis.internal`, client+server, TTL 30 d;
  - `node-control`: CN `hub.control`, client;
  - `node-link`: CN `link.control`, client.

  **enroll** signs CSRs through a new internal endpoint `POST /internal/nodes/sign`, called by the Hub (Vault policy `enroll.hcl` + `pki_node/sign/node-*` only). The Hub never holds a Vault token. Renewal happens at ⅓ remaining life: the Hub asks for a CSR, has it signed, and pushes the cert. The Hub pins each worker's SPKI and current serial in state, so a worker can't present another worker's identity. The agent pins `hub.control` / `link.control` and the `pki_node` CA it learned at join.
- **Enrolment** (admin, fresh sign-in, audited `server.add` / `server.enrolled`). Every connection is opened by the primary:
  1. Hub → Servers → *Add server* (name, id `^[a-z][a-z0-9-]{0,30}$`). The Hub allocates a tunnel IP and a **bootstrap** WireGuard key pair, adds the bootstrap peer to `link.json` as `enrolling`, and shows a one-time **join code**, valid 15 min, single use: endpoint, link public key, server id, tunnel IP, bootstrap private key, `pki_node` CA fingerprint, and a 256-bit secret (only its hash is stored).
  2. On the worker: `./portcullis worker join <code>`. The agent brings the tunnel up with the bootstrap key and serves `:7443` with a self-signed certificate in *enrolling* mode.
  3. When link reports a handshake, the Hub connects with its `hub.control` cert and proves the secret (HMAC over a nonce from the agent). The agent checks the Hub cert against the CA fingerprint. It then generates its **own** WireGuard key and TLS key and returns the public key + CSR. The Hub has enroll sign the CSR, pushes the cert, and swaps the peer's public key in `link.json`. The bootstrap key is dead from then on.
  4. The server is `ready`. An expired code, a reused code or a wrong HMAC → `server.enrol_refused`, and the bootstrap peer is removed.
- **Revocation** (*Revoke now*, admin, fresh sign-in, typed id; works on an offline server):
  1. remove the peer from `link.json` (the tunnel drops at once);
  2. revoke the cert serial in `pki_node`;
  3. unpin it;
  4. stop the instance's relays;
  5. **rotate** what the worker held: each placed instance's Keycloak client secrets and relay tokens.

  Its instances become `orphaned`: they can be restored from their last backup onto another server, or *forgotten*. *Remove server* is the clean path: the server must have no instances, and it then runs revocation plus `worker leave` remotely. Audited `server.revoked` / `server.removed`.

## 7. Placement and moves

- **State.** `Instance.Server` (`""` = primary). `state.yaml` `servers: {<id>: {name, tunnel_ip, wg_public_key, cert_serial, spki, state: enrolling|ready|offline|revoked, local_networks, folder_roots, backup_schedule}}`. The primary is always listed, as `primary` (the local engine).
- **Choosing a server.** The setup form gets *Runs on* (default primary). Each choice shows free disk/memory, runtime and arch. The Hub refuses (`409`, before anything is created) when:
  - the server isn't `ready`;
  - the template is **primary-only**: it mounts core volumes (`hub_secrets`, `hub_data`, …), has `traefik.tcp/udp` routers, or has a `person_secret` option. The Hub detects this; the optional manifest field `placement: primary_only` exists for anything detection misses;
  - the rootless compatibility gate of that server says `refused`;
  - a pre-pull of the images on that server fails (arch).

  Everything that isn't containers stays where it is: hostnames, Keycloak clients, groups, policy and portal entry.
- **Shared folders** are per server. A folder records its server, the folder roots are a per-server setting, and the fixer runs through `folder_fix`. Only folders on the instance's server can be bound to it.
- **Move** (`POST /api/instances/{id}/move {server}`, admin, op-progress + Stop, audited `instance.move`):
  1. **check**: the target is ready and the placement rules pass. No bound shared folders (`409` "unbind folders first; folder contents aren't moved");
  2. **backup** on the source (§11.5, reason `move`), which stops the instance;
  3. **restore** into the same id on the target (§11.6 machinery, new volumes);
  4. **switch**: the relays point at the target (or are removed when the target is the primary, where the real project takes the routes), then the instance starts;
  5. **keep** the source volumes, stopped, for 7 days (*Undo move* restores routing to the source). After that a doctor Info offers the guarded removal.

  Downtime equals the backup + restore time, and the confirm dialog shows the size. A failure before step 4 restarts the source. It never leaves two copies routed.

## 8. DNS, networking, VPN

- **No new DNS records** (with the DNS spec). Worker hosts are ordinary instance hosts under the wildcard or an enrolled domain. The link endpoint is the apex. The DNS plan's CAA/DNSSEC are unaffected, and workers never get DNS credentials (anti-goal).
  - A foreign `A` record someone points at a worker (`nas.<d>`) is already reported by the DNS plan as *shadowing the wildcard*. The Servers page links it.
  - Workers reach `auth.<d>` (native-OIDC back channel) over the public internet, like any client.
- **VPN-only (VPN spec)** works unchanged: the relays carry the rendered `vpnsecure` entrypoints and `vpn-only@file`. The `link` subnet must not overlap the VPN subnet or Local networks; `link init` refuses an overlap. link and vpn are separate services, ports and keys (separate blast radius), but they share `wgnet`.
- **`lan_only` ports and Local networks** are per server: a worker's LAN is not the primary's. The doctor's `lan_only_exposed` reads the agent's port binds.

## 9. Backups, disaster recovery, failure handling

- **Instance backups** of worker instances stream through the agent's helper archive into the primary's `hub_data/backups/<id>/`, so core `backup` and restic offsite cover them like primary instances (one backup story; free-space checks as §11.5). New per-server *Scheduled backups* setting: off / daily / weekly at a chosen hour, default off. It stops each instance briefly, the existing consistency rule. It keeps the last 3 scheduled archives per instance; manual ones are never pruned. The schedule applies to the primary too.
- **Worker state isn't backed up.** Its identity is re-created by re-joining, and its bundles are rendered again by the Hub. A dead worker = restore its instances onto another server from their last backups (`orphaned` flow).
- **Primary DR.** Restoring the primary onto a new host restores `link.json`, `secrets/link`, `pki_node` (Vault raft) and state. Workers reconnect by themselves once `<d>` points at the new host: their peer key and certificates are still valid.
- **Server offline** (3 missed 30 s polls or no handshake for 3 min): instances show `unreachable`. Their relays serve the 503 page, and lifecycle operations answer `409` "server offline". Drift and doctor reconcile on return.
- **Worker break-glass** (host operator, who is root on that host anyway): `./portcullis worker stop|start <instance>` and `worker leave`. They never change what the primary routes.

## 10. Hub UI, MCP, doctor, monitoring

- **Settings → Servers.** A list with name, state, runtime (docker / podman rootless), arch, CPU/memory/disk, instance count, last contact, agent version and cert expiry, plus *Add server*. A server page shows details, its instances, Local networks, folder roots, scheduled backups, *Revoke now* and *Remove*. Enrol and move run in the operation progress panel.
- **Apps / instance page.** A *Runs on* badge, *Move…* on Instance → Manage, and *Runs on* in the setup form. Shared Folders gains a server column.
- **MCP** (admin, per-call confirmation): `list_servers`, `get_server`, `move_instance`, `set_backup_schedule`. Nothing that creates a join code or revokes a server: a join code must never land in a transcript, and revocation stays a human action.
- **Doctor:**
  - `server_offline` (Problem);
  - `server_cert_expiring` (Warning ≤ 7 d);
  - `server_agent_incompatible` (Problem) / `server_agent_outdated` (Info);
  - `server_disk_low` (Warning < 10 %);
  - `server_no_recent_backup` (Warning: an instance on a worker without a backup in 14 d);
  - `server_move_leftover` (Info, 7 d after a move, offers removal);
  - `link_subnet_overlap` (Problem);
  - `instance_orphaned` (Problem).
- **Monitoring** (profile `monitoring`): a Prometheus job `link`. Alerts `PortcullisServerDown` (no handshake for 5 min), `PortcullisServerDiskLow` and `PortcullisServerContainerUnhealthy`. `./portcullis status` gets a "Servers" block (peers, handshake age), and `--json` gets `servers{}`.

## 11. Contract changes

- **§6 Docker access:** on workers the socket rule holds for `socket-proxy-agent`. The agent API (§5) is the only remote access to an engine. No Engine API on the network.
- **§11:** instance `server`, placement refusals, primary-only detection + `placement: primary_only`, move (op `move`, `instance.move`), states `unreachable` / `orphaned`. §11.5: reason `move`, archives of worker instances. §11.7: the new audit kinds.
- **§3 templates:** a worker-placeable template must not use `host-gateway`, `traefik.tcp/udp`, or host paths outside its bundle and the folder roots. Its cookies must be host-only (the relay strips the rest).
- **§5:** relays carry the rendered labels. Cookie filtering on relays. The 503 page.
- **§14.5:** the doctor kinds above. **§15:** the MCP tools.
- **New §17 Servers:** link (networks, `link.json` v1, CONNECT rules, zero listeners), relays, the agent API v1, `pki_node` roles and enroll's `/internal/nodes/sign`, the join code, renewal, revocation, version skew.
- The policy file is **unchanged** (no group-gate change), so Hub and core don't have to upgrade in lockstep for policy. They do for `link.json` v1.

## 12. CI strategy, docs, Kubernetes

- **Unit tests:**
  - Hub: the `Engine` interface fakes; placement rules; the move state machine with failure at every step; join-code and HMAC; `link.json` writer; relay label rendering = today's goldens; doctor kinds.
  - Agent: bundle re-validation (privileged/devices/bind escape refused), the scope table of §5 (foreign project, foreign volume, unlisted image, non-fixed helper spec → 403), data preamble checks, response caps.
  - Relay: cookie filter vectors.
  - link (core): CONNECT authorisation, zero netstack listeners, reload drops peers.
- **Two stacks in one CI job, `e2e-servers` (core):** the primary is the full stack + Hub + link, `ACME_STAGING`-style Pebble as in `e2e-instances`. The worker is a pinned `docker:dind` container (privileged in CI only, the one reviewed exception), with its own daemon and the worker compose, reaching the primary only over UDP to the runner's published link port. Asserts:
  - join works; a reused or expired code is refused;
  - an `echo` instance placed on the worker answers through the primary after sign-in and is refused without it, with the same tier and factors as on the primary;
  - the echo shows **no Portcullis cookie** in the request, and a `Set-Cookie; Domain=.<d>` is stripped;
  - backup / move worker → primary → worker keeps the data;
  - `docker stop link` → the worker app is unreachable (fail closed) and the containers are still running;
  - **rogue worker:** from the worker's netns, every port on `10.214.0.1` is closed; the agent cert of server B is refused for server A; a forged data preamble for an unplaced instance is refused; an oversized `/info` is cut off;
  - revoke → handshake gone within the reload, client secrets rotated;
  - the socket rule on both stacks.

  When the rootless job lands, a matrix leg runs the worker on rootless Podman instead of dind.
- **Docs:** new `operations/servers.md` (model, join, placement, move, revoke, DR, break-glass, what works when the primary is down); `hardening.md` (agent, socket-proxy-agent, link, relays, `pki_node`, the threat model of §3); `backups.md`; `monitoring.md`; `cli.md` (`link`, `worker …`); `hub.md`; contract; core `CLAUDE.md` (socket rule incl. the worker).
- **Kubernetes:** if that design lands, a cluster becomes one more `Engine` implementation behind the same agent API (the agent runs in the cluster, with namespaced RBAC instead of a socket proxy). Nothing here assumes Docker beyond the agent.

## 13. Task outline (for the plan)

1. Core: `wgnet` package (shared with vpn), `link` service + profile `workers`, networks, `link init`, `link.json` reader, CONNECT rules, metrics; `pki_node` mount/roles in `pki setup`, enroll `/internal/nodes/sign` + policy; status block, alerts; CLI tests.
2. Hub: the `Engine` interface (local + agent client), `engineFor`, compose-over-agent.
3. Hub repo: `cmd/portcullis-agent` (netstack, mTLS, §5 API and scope table, bundle store, data listener) + `cmd/portcullis-relay`; images, pins, release flow.
4. Core: `docker-compose.worker.yml`, `worker join|status|upgrade|leave|stop|start`, `PORTCULLIS_ROLE`.
5. Hub: servers state, enrolment and renewal, revocation + secret rotation, relay projects + tokens, placement rules, move/undo, scheduled backups, per-server Local networks and folder roots.
6. Hub UI + MCP + doctor.
7. CI `e2e-servers` (dind worker, rogue-worker asserts).
8. Contract §17 and the other sections, docs, CLAUDE.md files.
9. Test server: a second VM as worker (and one behind NAT), `ACME_STAGING=true`. Merge order: docs → hub → templates → core. Mainline all branches.

**Parked:** file-sharing apps on workers (per-instance secrets volume pushed by the Hub; part 2); direct ingress on a worker (its own Traefik, delegated certs, needs the cookie scope reworked); TCP/UDP routers; cookie filtering for primary-local apps too; automatic placement; HA primary; remote agent upgrades; worker-to-worker traffic.

## 14. Open questions (each has a default; work proceeds on the default)

1. **Data path without TLS inside WireGuard.** *Default:* WireGuard alone protects data (peer-authenticated, encrypted, and the agent accepts data only from `10.214.0.1`). Control uses mTLS on top. Revisit if a threat review asks for mTLS on data too.
2. **Bandwidth through the primary.** *Default:* accept it. If test-server throughput through relay + userspace WireGuard is under 200 Mbit/s, try a kernel-WireGuard opt-in for `link` (NET_ADMIN, doctor Info) before direct ingress.
3. **Undo-move window of 7 days.** *Default:* 7 days. It's a setting if disk pressure on workers makes it a problem.
4. **Cookie filter breaking an app** that relies on a parent-domain cookie. *Default:* filter always, and mark the template primary-only if one turns up.
