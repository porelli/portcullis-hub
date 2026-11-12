# Rootless Podman support (design)

Status: written by the assistant for the roadmap item "rootless support using Podman" (the user's words). The user asked not to be interrupted, so the assistant made every decision. Each decision is the **assistant's call** unless marked otherwise. Open questions are in §12, and each one has a default.

## 1. Where things stand (2026-11-12)

- **Core** (`portcullis/docker-compose.yml`) assumes rootful Docker. The two socket proxies (`socket-proxy-traefik` with `POST=0`, `socket-proxy-hub` with the compose subset plus `ALLOW_ARCHIVE`) are linuxserver/socket-proxy, i.e. HAProxy running as root with `SYS_CHROOT`. Both bind-mount `/var/run/docker.sock:ro`, and no other service touches the socket (contract §6, enforced by CI).
- **Traefik** runs as root with only `NET_BIND_SERVICE` and publishes `80:80` and `443:443`. It is pinned on `portcullis-proxy` (`.2`) and `portcullis-auth` (`.2`). `portcullis-mcp` pins Keycloak and the Hub. `portcullis-domains` has a fixed subnet. Six networks are `internal: true`. `network_state` compares `IPAM.Config[0].Subnet/IPRange` from `docker network inspect`.
- **Fixed uids/gids** (`CT_*` in `scripts/lib/common.sh`): vault 100:1000, hub 10001, enroll 10002, group-gate 10003, domains 10004, mcp-gate 10005, valkey 999:1000, lldap 1000, Traefik root/group 0. File-sharing person uids come from 20000–59999.
- **How ownership is set:**
  - `ct_own` calls `chown` directly when the operator is root. Otherwise it runs a throwaway `alpine` with `--user 0:0 --cap-add CHOWN`.
  - `volume_own` and `_ensure_secrets_volume` work the same way on named volumes.
  - `ct_group_read` and the per-area `*_fix_perms` call `ct_own "$(id -u):<gid>"`.
  - The restic helper runs as `--user "$(id -u):$(id -g)"`.
  - Every command goes through `dc() { docker compose --project-directory … }` and plain `docker run/inspect/volume/network`.
- **Hub** (`internal/docker`, moby client) uses `DOCKER_HOST=tcp://socket-proxy-hub:2375`. It needs containers (list/inspect/logs/exec/kill/create/rm/wait), images (pull/inspect), volumes, networks, events, info, version, `_ping`, archive GET/PUT on never-started helpers, and one started helper: the shared-folder fixer (`RunHelper`, `--user 0:0`, caps limited to CHOWN/DAC_OVERRIDE/DAC_READ_SEARCH/FOWNER/FSETID). It runs `docker compose -p portcullis-<instance>` per instance.
- **Shared-folder fixer under translated ids.** `runFixer` refuses when Info `SecurityOptions` contains `name=userns` or `name=rootless` (`docker.RemappedIDs`). `folderfix` refuses inside a non-identity `/proc/self/uid_map`.
- **What the Hub refuses in templates.** The doctor reads `DockerRootDir`. Custom overrides may not use `userns_mode`, `privileged`, `devices`, `network_mode`, etc. (`useroverride.go`, `coreref.go`).
- **Templates** that need host features:
  - `scrutiny`: `devices` (raw disks) and `cap_add: SYS_RAWIO`.
  - `netbird` coturn: `network_mode: host`.
  - `pihole` / `adguard`: host port 53 tcp+udp.
  - The Samba and Time Machine templates: host port 445.
  - `guacamole` init: `cap_add: [CHOWN, DAC_OVERRIDE, FOWNER]`.
  - Everything else publishes nothing and routes through Traefik.
- **Rootless Podman 5.x facts this design rests on** (checked against podman docs and source):
  - The Docker-compatible API listens on the user socket `$XDG_RUNTIME_DIR/podman/podman.sock` (`systemctl --user enable --now podman.socket`).
  - `podman compose` is only a wrapper around an external provider, and it prefers `docker-compose`.
  - The compat network create maps `Internal` and `IPAM.IPRange` (→ netavark `LeaseRange`, round-tripped by inspect when the range is a full CIDR). Static `ipv4_address` works. aardvark-dns resolves only container names on internal networks.
  - Rootless bridge networks live in a rootless netns. Pasta is the default since 5.0. Host-port forwarding uses `rootlessport`, which keeps the client source IP for remote TCP when nft or iptables is present. UDP and loopback connections see a rewritten source.
  - Host ports below `net.ipv4.ip_unprivileged_port_start` (a per-netns sysctl, default 1024) can't be published.
  - In the default user namespace, container uid 0 = the operator, and container uid n = `subuid_start + n − 1` (65536 ids by default). Unmapped host ids appear as 65534.
  - The `idmap` mount option is rootful only.
  - Resource limits need cgroups v2 with the `memory` and `pids` controllers delegated to `user@<uid>.service` (systemd delegates both by default).
  - Healthchecks run on systemd transient timers, and `restart: unless-stopped` survives a reboot only with `podman-restart.service` (user unit) and lingering enabled.
  - `:z` / `:Z` relabel bind mounts on SELinux hosts.
  - Device nodes and raw device access are impossible.

## 2. Goals, non-goals, anti-goals

**Goals**
1. The whole stack (core, the Hub and the app instances) runs as **one dedicated unprivileged host user** under rootless Podman ≥ 5.4. The operator never needs root after a one-time host preparation (§4).
2. **Same security properties as rootful Docker, or stronger.** Every hardening item holds: socket proxies with the same allowlists, internal networks, fixed IPAM with pinned Traefik/Keycloak/Hub/mcp-gate addresses, `no-new-privileges`, `cap_drop: ALL`, read-only roots, mem/pids limits, pinned digests. On top of that, a container escape (including an escape from the Hub's "can create any container") lands as the unprivileged operator, not host root.
3. **One compose file and one CLI.** The difference between runtimes is a few variables and code paths behind `CONTAINER_RUNTIME`. There is no second stack definition.
4. **Backups are runtime-neutral.** A backup taken on Docker restores on Podman and the other way round. Ids inside tarballs are container ids. This is also the supported way to move from one runtime to the other.
5. Every template is classified as works / degraded / refused under rootless (§9), and the Hub explains a refusal before anything is deployed.

**Non-goals** (assistant's call)
- **Rootful Podman.** It brings no security gain over Docker and doubles the test matrix. Rootless Docker is also out: it is mostly the same work, but nobody asked for it, and the fixer refusal stays in place for it.
- **Quadlet / systemd units per service, and podman-compose.** The Hub drives arbitrary per-instance compose projects through the Engine API, and `docker compose` against the Podman socket keeps a single implementation. Quadlet fits better with the later Kubernetes item (`podman kube`), not here.
- `--userns=auto` per container and idmapped mounts. Shared volumes (`hub_data` is read by four services) need one stable mapping, and idmap is rootful only.
- Live migration of an existing install between runtimes, beyond backup → `init` → `restore`.
- macOS / Windows Podman machine.

**Anti-goals** (never)
- Never mount the Podman socket into anything except the two socket proxies. Never widen an allowlist, and never expose the libpod API (`/libpod/…`, which includes `play kube`, `generate`, `machine`). The contract §6 rule stays word for word, with "the engine socket" in place of `docker.sock`.
- Never drop a hardening item silently. If mem/pids limits can't be enforced (no delegation, cgroups v1), `init`, `up` and `upgrade` **refuse**. They don't warn and carry on.
- Never relabel user data with `:Z`/`:z` (shared folders under `/srv`, `/mnt`, `/media`, home directories). Never set `label=disable` on anything but the two proxies.
- Never let the runtime change under an existing install. Never write host ids computed from guesses: every translation comes from the live `uid_map`.

## 3. Runtime selection

- **`.env` key `CONTAINER_RUNTIME=docker|podman`**, written by `init`, and never changed afterwards (switching is backup → fresh `init` → `restore`).
- **Detection at `init`**, in this order:
  1. `--runtime` flag or the `CONTAINER_RUNTIME` environment variable.
  2. A reachable `/var/run/docker.sock` (or `DOCKER_HOST`) whose `/version` has no `Podman Engine` component → `docker`.
  3. `podman` installed, the operator not root, and `$XDG_RUNTIME_DIR/podman/podman.sock` answering `/_ping` → `podman`.
  4. Otherwise fail with the host-prep hints from §4.
  
  When both runtimes are present, Docker wins unless podman is chosen explicitly. Running as root with podman → refused (rootful is a non-goal).
- **Every later run checks the engine.** `env_load` → `runtime_check` asks the engine's `/version`. The run fails if the answer contradicts `CONTAINER_RUNTIME`, for example a `DOCKER_HOST` that points at Podman on a Docker install.
- **One mechanism: the Docker CLI against the engine socket.** For podman, `common.sh` exports `DOCKER_HOST=unix://$XDG_RUNTIME_DIR/podman/podman.sock` once, so `dc` and every existing `docker …` call keep working unchanged through the compat API. The Docker CLI and the compose plugin are required, but no Docker daemon is. Only the call sites listed in §5 change.
- **Socket path in compose.** `.env` key `PORTCULLIS_ENGINE_SOCKET` holds the host path (default `/var/run/docker.sock`; `init` writes the rootless path; `up` re-validates it). Both proxies mount `${PORTCULLIS_ENGINE_SOCKET:-/var/run/docker.sock}:/var/run/docker.sock:ro`. CI's socket rule matches that exact source string.
- **Local images** (enroll, group-gate, domains, mcp-gate). Under podman the CLI builds them with `podman build` (same tags) before `up`, and compose runs with `--no-build`. This avoids depending on buildx/bake against the compat `/build` endpoint. The Hub's proxy keeps denying `BUILD`.
- **The Hub learns the runtime from `HUB_CONTAINER_RUNTIME`** (from compose) and verifies it at start through `/version` (`Components[].Name`). On a mismatch it **fails closed**: it logs, and every engine operation answers 503.

## 4. Host preparation (one-time, root) and the checks for it

Docs page plus `./portcullis status` checks. `init` and `up` refuse when an item marked † is missing.

| Item | Requirement | Check |
|---|---|---|
| Dedicated user | e.g. `portcullis`, no sudo, owns the checkout | `id -u` ≠ 0 |
| subuid/subgid † | ≥ 65536 ids each (container ids up to 65534 are used) | `podman unshare cat /proc/self/uid_map` (and `gid_map`) |
| Global userns † | `containers.conf` `userns` empty/`host` (no `auto`, no `keep-id`) | `podman info` / a probe container's `uid_map` = the expected shape |
| cgroups v2 delegation † | `memory`, `pids` in `user@<uid>.service`'s `cgroup.controllers` | read the file; probe that a container gets `Memory`/`PidsLimit` set |
| Linger † | `loginctl enable-linger <user>` (timers for healthchecks, start at boot) | `loginctl show-user -p Linger` |
| User units † | `podman.socket` and `podman-restart.service` enabled | `systemctl --user is-enabled` |
| Low ports † | `net.ipv4.ip_unprivileged_port_start=80` (sysctl.d) | `/proc/sys/net/ipv4/ip_unprivileged_port_start` ≤ 80 |
| Source IP | `nft` or `iptables` present (rootlessport keeps TCP client IPs) | `command -v` |
| Podman ≥ 5.4, passt, Docker CLI + compose plugin † | versions | `podman version`, `docker compose version` |
| SELinux | enforcing is supported (§5, §7) | `getenforce` when present |

Assistant's call: **80**, not 0 or 53. 80 covers Traefik and 445 (SMB). It means any local user can bind 80–1023, which is acceptable on a dedicated server and documented. DNS apps (53) are refused unless the operator lowers the sysctl further (§9). The CLI writes the current value into `secrets/hub/core.env` as `PORTCULLIS_UNPRIVILEGED_PORT_START` (the sysctl is per-netns, so the Hub can't read the host's value itself).

## 5. uid/gid model and the ownership helpers

**Model.** All containers share the user's default namespace. Container id `c` maps as follows (from the live `uid_map` and `gid_map`):

| Container id | Host id |
|---|---|
| `c = 0` | the operator |
| `1 ≤ c < 65536` | `subuid_start + c − 1` |

Because every container uses the same mapping, ids are consistent between containers: hub 10001 in the Hub and in group-gate is the same host id. All `CT_*` values stay as they are. Only the host-side view changes.

**Changes** (assistant's call). `common.sh` gets three helpers:
- `ct_operator_id`: `$(id -u)` on docker, `0` on podman.
- `ct_host_id <c>`: translates through the cached map.
- `_owner_of_ct <path>`: host owner translated back to container ids; an unmapped owner is `unmapped`.

| Helper | Docker (unchanged) | Podman |
|---|---|---|
| `ct_own` | root: `chown`; else alpine `--user 0:0 CAP_CHOWN` | always the alpine helper (it runs in the namespace, so `chown 10001` writes host `subuid+10000`). The no-op test compares `_owner_of_ct`. The root fast path is never taken |
| `ct_group_read` / `*_fix_perms` (`ct_own "$(id -u):gid"`) | operator : gid | **`ct_own "$(ct_operator_id):gid"`**: container 0 = the operator, so the operator still owns its secrets. Passing `$(id -u)` there would hand them to a subuid. All six call sites (common, domains, mcpgate) change |
| `volume_own`, `_ensure_secrets_volume` | helper | unchanged (helpers already run in the namespace) |
| restic (`backup.sh` `--user $(id -u):$(id -g)`) | operator | `--user 0:0` with `--cap-drop ALL` (root in the namespace without caps = the operator, so it reads by owner and mode only) |
| `stack_prepare` hints (`sudo chown -R …`) | `sudo chown` | `podman unshare chown …` |
| Traefik `CT_GID_TRAEFIK=0` | host group 0 | container group 0 = the operator's group. No change |

**What this means for security.** Container root now equals the operator, so Traefik and the proxies own operator-owned files *that are mounted into them*. They no longer read by mode alone (in rootful Docker, root without `DAC_OVERRIDE` was limited to modes). The blast radius is still set by the mounts, and those don't change. This is documented in hardening.md. **Assistant's call:** Traefik keeps running as root inside the container. Making it non-root would change the ACME volume and certs ownership on both runtimes, so it is parked (§12 Q4).

**Shared folders / ACL fixer.** Ruling 28 refused translated ids because owners would be "wrong". Under rootless Podman with one shared mapping, the ids the fixer writes inside the namespace are exactly what the app containers see, including ACL entries (the kernel translates POSIX ACL xattrs). So:
- `runFixer` allows `name=rootless` when `HUB_CONTAINER_RUNTIME=podman` and the fixer reports a mapping of the expected shape (`0 → operator, 1…65535 → one subuid range`). `name=userns`, rootless Docker and any other shape stay refused.
- `folderfix` swaps `idMapsIdentity` for `idMapsConsistent`, which checks that shape. The report carries `host_uid`/`host_gid` next to container ids, so the UI can show both.
- A folder (or a child) owned by an **unmapped** id (shown as 65534, e.g. host root or another real user) is refused per path: "owned by a host account outside Portcullis' id range; run `sudo chown -R <operator> <path>` once, then re-check". The fixer never tries to work around it.
- Per-person file-share uids (20000–59999) fit inside 65536.

## 6. Networking

- **Fixed IPAM and pinned addresses** are unchanged. Netavark accepts `subnet`, `ip_range` (as a lease range) and `ipv4_address`, and `internal: true` gives no default route. `network_state` keeps comparing subnet and range: the podman inspect round-trip gives back the CIDR range for our full-CIDR ranges. CI asserts this round-trip and the pinned addresses on every pinned network.
- **The gateway is never trusted.** In rootless mode, forwarded host ports arrive inside the namespace through `rootlessport`. Loopback publishes (`127.0.0.1:8080` Keycloak, `:8200` Vault) and UDP may show a gateway or rootless-netns source. All trust anchors are the pinned `.2/.3` addresses, which `network.sh` already keeps off the gateway and broadcast. CI checks that Keycloak refuses proxy headers on a request that comes in through the loopback publish.
- **80/443.** Published by Traefik as `80:80`/`443:443` (allowed by the sysctl). Inside its netns Traefik keeps `NET_BIND_SERVICE` (it is meaningful in its own namespace).
- **Client IPs.** Remote TCP keeps the real source (rootlessport with nft/iptables), so rate limits, Public IP detection and access logs behave as on Docker. UDP sources are rewritten: the DNS apps' per-client data is degraded (§9). Pasta port forwarding (`rootless_port_forwarder="pasta"`) is experimental and stays off (§12 Q2).
- **`extra_hosts: auth.<d>:host-gateway`** (forward-auth, forward-auth-ext, blackbox) reaches the host's published 443. Podman ≥ 5.3 maps `host-gateway` to a pasta-mapped host address, and CI tests it. Fallback (assistant's call, applied on both runtimes if CI shows a problem): point these entries at `${PORTCULLIS_TRAEFIK_IP}` and add those three services to `portcullis-proxy`. That would be a contract-visible change and needs its own review, so it is §12 Q3.
- **DNS shadowing guard** (`proxy_dns_shadows`) and member checks rely on `network inspect .Containers` and `compose ps -aq`, which the compat API provides. No change.

## 7. Socket proxies on the Podman API

- Same image, same environment, same networks. The only change is the socket source (§3).
- **Path filtering.** linuxserver/socket-proxy allows `^(/v[0-9.]+)?/<section>`, so `/libpod/…` and `/v5.x/libpod/…` never match an allowed section and get 403. CI adds denial checks for `/libpod/info`, `/libpod/play/kube`, `/v5.0.0/libpod/containers/json` and `/build` on **both** proxies.
- **Root inside the proxy** = the operator, who owns the socket. HAProxy keeps `SYS_CHROOT`. This still sits behind `no-new-privileges`, `cap_drop: ALL`, a read-only root, and the 64m/64 limits.
- **SELinux enforcing.** `container_t` cannot `connectto` the user's Podman socket. Under `CONTAINER_RUNTIME=podman` with SELinux enforcing, **only** the two proxies get `security_opt: label=disable`. A tiny overlay `docker-compose.podman-selinux.yml` is added to `COMPOSE_FILE` by the CLI (assistant's call; listed as a hardening exception and CI-gated to those two services). Core binds get the long-syntax `bind.selinux: z` on read-only shared sources (`certs/`, `traefik/dynamic`, `secrets/*` files, `keycloak/` files, `.`→`/project`, `templates/`, `appfiles/`). On non-SELinux hosts this is a no-op on both runtimes.

## 8. The Hub

- **Engine client.** No change for moby negotiation (Podman 5.x compat answers `/_ping` and `/version`). `DockerRootDir` maps to Podman's graph root (doctor disk checks, the "no shared folder inside the engine root" rule).
- **Instances.** `docker compose -p portcullis-<instance> up/down` through the proxy as today. Template bind mounts under `./templates/` and `./appfiles/` get `selinux: z` added by the Hub's renderer on SELinux hosts (Info `SecurityOptions` `name=selinux`). Shared-folder binds never get it: the doctor reports `selinux_label_missing` with the `semanage fcontext … container_file_t` + `restorecon` commands.
- **Backups and restores** (archive endpoints on never-started helpers) work unchanged, and tar ids stay container ids. Covered by the CI job.
- **Events, logs, exec, kill** use the compat endpoints. The Hub must tolerate Podman's extra event actions (it ignores unknown ones) and `health_status` without a suffix.
- **Compatibility gate (new, in `internal/templates`).** Before deploying an instance, `RootlessCompat(compose, manifest, portStart)` returns `ok`, `degraded:[reasons]` or `refused:[reasons]` from the rules in §9. The instance page and the Marketplace show it, refused instances can't be created, and `/api/runtime` exposes the runtime, the mapping and `portStart`. Under Docker it always returns `ok`.
- **Doctor (new checks, podman only):** `runtime_mismatch`, `limits_not_enforced` (an instance container whose inspect shows no `Memory`/`PidsLimit` although the compose sets them), `unmapped_owner` (a shared folder), `selinux_label_missing`, `udp_source_rewritten` (info, on DNS apps).

## 9. Per-feature compatibility under rootless Podman

| Feature | Status | Why / what happens |
|---|---|---|
| Core stack, sign-in methods, people, sessions, domains/ACME, mcp-gate, monitoring | works | pinned IPs, internal networks, limits and healthchecks all hold |
| Socket proxies, Traefik docker provider | works | compat API; libpod denied |
| Instance backup/restore, core `backup`/`restore` | works | runtime-neutral tarballs |
| Shared folders + fixer + ACLs | works with conditions | allowed for the consistent mapping (§5). Unmapped owners are refused per path. SELinux needs labels set by the operator |
| File sharing (Samba 445, Time Machine) | works | 445 ≥ 80. TCP client IPs kept. Avahi/mDNS discovery is unverified (§12 Q5) |
| Header-auth apps (grafana, firefly-iii, …) | works | trust Traefik's pinned IP |
| `network_mode: host` (netbird coturn) | degraded | allowed (it shares the host netns), but host ports must be ≥ the sysctl. The relay range is fine |
| Apps publishing UDP (pihole/adguard DNS, STUN) | degraded | the client source is rewritten (UDP) |
| Host ports < `ip_unprivileged_port_start` (pihole/adguard 53 at the default 80) | refused | message names the sysctl and the risk. Allowed when the host value ≤ the port |
| `devices:` (scrutiny raw disks), raw-I/O caps (`SYS_RAWIO`, `SYS_ADMIN` on host devices) | refused | impossible without host root |
| Templates with ids > 65535 | refused | outside the mapping |
| Other `cap_add` within the namespace (guacamole CHOWN/DAC_OVERRIDE/FOWNER) | works | caps in the namespace act only on mapped ids |
| Custom override `userns_mode` | refused | unchanged (already refused) |

## 10. CLI, status, CI, docs

**CLI**
- `init --runtime docker|podman` and the `runtime_check` behind `env_load`.
- The host-prep checks (§4) run in `init`, `up`, `upgrade` and `restore`.
- `status` prints `runtime: podman 5.x rootless, uid 1001, subuid 100000+65536, ports ≥ 80` and adds `runtime{}` to `--json`. A failed † item is a `fail` line.
- `version` and `MANIFEST.json` record the runtime and its version.
- `tests/test_cli.sh` covers the detection matrix (stubbed `docker`/`podman` binaries), every `ct_operator_id` call site (a grep test: no `ct_own "$(id -u)` left), and `--help` working without an engine.

**CI** (assistant's call)
- **Core:** one new job `e2e-podman` on `ubuntu-26.04` (its archive has Podman 5.x; see §12 Q1).
  - **Setup:** stop and disable `docker.service`/`docker.socket` so nothing silently uses Docker; install podman, passt and uidmap; set `ip_unprivileged_port_start=80`; enable linger and the user `podman.socket`/`podman-restart.service`; `ACME_STAGING=true`; `init --runtime podman`.
  - **Asserts:**
    - status is green;
    - IPAM round-trips and the pinned IPs are right;
    - `Memory` and `PidsLimit` are set on every core container;
    - the socket rule and the proxy denials pass (including libpod);
    - Traefik sees the docker provider's routers;
    - secrets are operator-owned on the host (`stat`) and `0:gid` inside the namespace (`podman unshare stat`);
    - a sign-in via curl and the portal work;
    - forward-auth reaches `auth.<d>` through `host-gateway`;
    - a Hub instance goes up/down and through backup/restore;
    - the fixer runs on a `/srv` folder (operator-owned → ok, root-owned child → refused per path);
    - a scrutiny instance is refused with the device reason;
    - containers are back after `systemctl --user restart podman-restart`;
    - a Docker → Podman backup/restore round-trip uses an artifact from the existing `e2e` job.
  - Static checks (pins, hardening baseline, socket rule, proxy-network members) run once against the compose file and the overlay.
- **Hub:** unit tests for runtime verification, the `uid_map` shape parser (`idMapsConsistent`), the fixer gate (podman+rootless ok; userns/rootless-docker refused), `RootlessCompat` vectors, and the SELinux renderer.
- **Templates:** `tests/validate.py` emits each template's rootless classification, so a change in that classification shows up in review. No manifest field: the Hub computes it.

**Docs**
- **New page `operations/rootless-podman.md`:** why to use it, host prep (§4) as copy-paste blocks for Debian/Ubuntu and Fedora/RHEL, migration (backup → init → restore), and the compatibility table (§9).
- **hardening.md**
  - "Rootless Podman" section covering container root = operator, the Hub becoming operator-equivalent instead of host-root-equivalent, and the proxies' `label=disable` exception.
  - The socket-proxy table gets a "socket source" row.
- **Contract §6:** "the engine socket (`PORTCULLIS_ENGINE_SOCKET`)", libpod paths always denied, and `HUB_CONTAINER_RUNTIME`.
- **Core CLAUDE.md** "Deployment" / "Admin CLI": the `ct_operator_id` rule and the runtime check.

## 11. Task outline (for the plan)

1. **Core runtime plumbing:** `CONTAINER_RUNTIME`, `PORTCULLIS_ENGINE_SOCKET`, detection, `runtime_check`, the `DOCKER_HOST` export, the host-prep checks, and `podman build` for local images.
2. **Core ownership:** `ct_operator_id` / `ct_host_id` / `_owner_of_ct`, the six `ct_own "$(id -u):…"` call sites, the restic `--user`, the hints; CLI tests.
3. **Core compose:** socket source variable, `selinux: z` binds, the SELinux overlay for the proxies, `HUB_CONTAINER_RUNTIME`, and `PORTCULLIS_UNPRIVILEGED_PORT_START` in `core.env`; CI static checks extended.
4. **Hub:** runtime verification; the `idMapsConsistent` fixer gate + host ids in reports + per-path unmapped refusal; the SELinux renderer; `RootlessCompat` + UI badges + `/api/runtime`; doctor checks; unit tests.
5. **Templates:** classification output in `validate.py`; refusal messages reviewed for scrutiny, pihole and adguard.
6. **Core CI `e2e-podman`** (§10), including the Docker → Podman restore round-trip.
7. **Docs:** the new page, hardening, contract §6, CLAUDE.md files.
8. **Test server:** a second VM with a `portcullis` user and Podman (`ACME_STAGING=true`), a full live check. Mainline all branches.

Merge order as for file sharing: docs → hub (wait for the main `build.yml`) → templates → core.

## 12. Open questions (each has a default; work proceeds on the default)

1. **CI runner image.** If `ubuntu-26.04` isn't available on GitHub-hosted runners yet → *default:* `ubuntu-24.04` with Podman 5.x from the upstream static build (`mgoltzsch/podman-static`, pinned by checksum) plus passt from the archive.
2. **Pasta port forwarder** (keeps UDP source IPs) → *default:* off until it is no longer experimental. The DNS apps stay "degraded".
3. **`host-gateway` fallback** (§6) → *default:* keep `host-gateway`. Switch to Traefik's pinned IP on both runtimes only if CI shows it fails on Podman.
4. **Non-root Traefik** on both runtimes (ACME volume and certs group change) → *default:* parked follow-up, not part of this feature.
5. **Avahi/mDNS for Time Machine** under rootless → *default:* verify on the test server. If it fails, mark Time Machine discovery "degraded (connect by address)".
6. **Minimum Podman version** → *default:* 5.4. If a needed fix turns out to be newer, CI pins the floor and `init` enforces it.
