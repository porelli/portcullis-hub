# Instance networks: each instance alone with Traefik

Status: draft for approval (2026-11-02)

Replaces the shared `portcullis-proxy` app network with one network per app
instance, shared only with Traefik. Touches all four repos: core (compose,
CLI, CI), Hub (override, lifecycle, validator, reconcile), templates (CI
emulation, variable form) and docs (contract §2, §3, §3.1, §5, §6, §11).

## Intent

Today every routed service of every app instance sits on one network,
`portcullis-proxy`, together with Traefik. So any container of any app can:

- connect to any other app's frontend directly, bypassing Traefik,
  forward-auth and group-gate;
- spoof identity headers (`X-Forwarded-User`, …) or client IPs to apps that
  trust them from the wrong peer. This was found on Mattermost.
- with `CAP_NET_RAW` (in Docker's default capability set), ARP-spoof
  Traefik's address on the shared L2 segment. That would defeat even an
  exact `PORTCULLIS_TRAEFIK_IP` allowlist.

The stop-gap was nginx "Traefik-only gates" in front of ESPHome,
Zigbee2MQTT, motionEye and (on branch `mm-gate`) Mattermost. The user chose
the structural fix (2026-11-02, option B): **give each instance its own
network, shared only with Traefik.**

## Goals

1. **No app-to-app path.** No container of instance A can open a connection
   to any container of instance B, or to a core service, over any Docker
   network.
2. **Only Traefik reaches an instance's frontends.** The only foreign peer on
   an instance's routing network is Traefik, at a fixed address.
3. **Exact, per-instance trust.** Header-auth apps and gates keep trusting
   one address, `PORTCULLIS_TRAEFIK_IP`. The Hub sets it per instance, and
   only Traefik can hold it on that network. So identity headers that arrive
   from that address came through Traefik.
4. **Self-healing plumbing.** Traefik rejoins every instance network after
   any recreate (core `up`/`upgrade`, a manual `docker compose up`), with no
   operator step. While it isn't attached, routing fails closed.
5. **No template churn for the network itself.** Existing templates keep
   their compose files. The Hub maps the network they already declare.
6. **The test server upgrades cleanly**, with no migration code.

## Non-goals

- Isolating containers **inside** one instance from each other (same app,
  same trust domain): headscale and headplane both stay on their instance's
  routing network.
- Paths that are meant to be open:
  - an app reaching another app's **public hostname** (through Traefik, with
    full sign-in, like any browser);
  - an app reaching another app's **host-published ports** (MQTT, DNS, SSH:
    they listen on the host for everyone);
  - containers with `network_mode: host`.
- IPv6 on instance networks (all core networks are IPv4-only today).
- Protecting apps from the host or from the Hub. The Hub's socket proxy can
  already exec into any container.
- Re-routing native-OIDC back-channel calls (`https://auth.<domain>`):
  they stay on public DNS (hairpin), as today.

## Anti-goals

- **Failing open.** A missing network, a detached Traefik, a wrong address
  or an unexpected attachment must give an unreachable app (502/504, or an
  instance that doesn't start), never a route around the gateway.
- **A second allocator.** Exactly one component (the Hub) chooses instance
  subnets. Core validates the pool only.
- **New Docker powers.** No new socket-proxy permission, and no change to
  Traefik's read-only proxy.
- **Breaking `reconcile never fixes`.** App state (enable, stop, recreate)
  stays the admin's explicit action. Only the Hub's own plumbing (Traefik's
  attachments, orphan networks) is maintained automatically.

## Constraints and facts (verified in the code)

- **Core compose** (`portcullis/docker-compose.yml`):
  - `portcullis-proxy` has fixed IPAM: `PORTCULLIS_PROXY_SUBNET`
    172.31.250.0/24, dynamic range `/25` at .128. Traefik is pinned at
    `PORTCULLIS_TRAEFIK_IP` 172.31.250.2 (lines 14–21, 241–247).
  - `TRAEFIK_PROVIDERS_DOCKER_NETWORK: portcullis-proxy` (line 192).
  - Every core service sets its own `traefik.docker.network`.
  - The only other core member of `portcullis-proxy` is **core Grafana**
    (profile `monitoring`, `GF_AUTH_PROXY_WHITELIST=${PORTCULLIS_TRAEFIK_IP}`,
    lines 1111, 1132–1145).
  - `socket-proxy-hub` already has `NETWORKS=1` and `POST=1`. That covers
    network create, inspect, connect, disconnect and remove (lines 107–134).
  - `socket-proxy-traefik` is read-only, with `CONTAINERS`, `NETWORKS` and
    `EVENTS`.
- **Core CLI:**
  - `scripts/lib/network.sh` validates the proxy, auth and domains IPAM and
    refuses a mismatched existing network.
  - `common.sh` `HUB_ENV_VARS` (line 350) passes `PORTCULLIS_TRAEFIK_IP`,
    `PORTCULLIS_PROXY_SUBNET` and `PORTCULLIS_PROXY_IP_RANGE` to the Hub's
    `core.env`.
  - `upgrade_run` runs `dc up -d`, which recreates Traefik when its
    definition changes; `dc restart` does not.
- **The Hub override** (`internal/hub/override.go`
  `renderOverrideLocked`):
  - It writes volumes, ports, per-router labels, the public and sign-in
    routers, and volume names. It writes **no networks** today.
  - For non-default instances it replaces labels with `!override`.
- **Env** (`internal/hub/env.go`):
  - `generateAppEnvLocked` copies a referenced variable from `core.env`
    **only if it isn't already set**.
  - The instance variables (`t.InstanceEnv`) are always rewritten, also by
    `refreshInstanceEnvLocked` before every up.
- **Lifecycle** (`internal/hub/lifecycle.go`):
  - `composeUp` = regenerate the override + env → custom override check →
    template file sync → `compose up --no-start` → image-label check →
    `up`.
  - Restart = down + up. Disable = down, then state.
  - A failed enable runs `rollbackUp` (down, volumes kept).
  - Backups stop the instance with down/up (`backup.go`).
- **Reconcile** (`internal/hub/reconcile.go`):
  - `watchEvents` watches container events that carry
    `com.docker.compose.project`, and acts only on projects that start with
    `portcullis-`. So core's project (`portcullis`) is ignored today.
  - The reconcile interval defaults to 60 s.
  - Drift is reported and resolved by explicit actions (`apply` = regenerate
    + up).
- **The validator** (`internal/templates/coreref.go`):
  - `coreNetworks` has no `portcullis-proxy`: templates may join it, and
    nothing else that is shared.
  - No `ipv4_address`/`ipv6_address`/`link_local_ips` on a shared network
    (lines 439–446).
  - `traefik.docker.network` is an allowed label key (line 753).
  - Core DNS names are reserved (`reservedDNSName`).
  - The custom override may not touch networks (`useroverride.go` lines 53,
    237).
- **Templates** (`portcullis-templates` `origin/main`, 48 templates):
  - All 48 declare the top-level network exactly as
    `portcullis-proxy: {external: true}`. None declares any other external or
    `name:`d network.
  - Every Traefik-enabled service is on both `default` and
    `portcullis-proxy`. No service is on `portcullis-proxy` without Traefik
    labels or without `default`.
  - None sets `traefik.docker.network`, none uses compose `ports:` (host
    ports come from manifest `ports`), and no Traefik-enabled service uses
    `network_mode`.
  - None calls a core service directly: no `extra_hosts`, no `http://keycloak`
    and the like.
  - Cross-app integration (Home Assistant ↔ Zigbee2MQTT's broker) goes
    through a host-published port.
  - 33 compose files use `${PORTCULLIS_TRAEFIK_IP:-172.31.250.2}` (allowlists,
    the gates' `gate.sh`, `ACTUAL_TRUSTED_PROXIES`, Grafana's
    `GF_AUTH_PROXY_WHITELIST`, `TRUSTED_PROXIES`, dokuwiki's and Home
    Assistant's init scripts). The gates sit in front of esphome,
    zigbee2mqtt and motioneye, plus mattermost on `mm-gate`.
  - None of the templates' `ports` maps the container port Traefik routes to.
- **Templates CI runs templates without the Hub.**
  - It boots core without the Hub, runs each template's compose directly on
    `portcullis-proxy`, and adds hostnames as Traefik aliases there
    (`CLAUDE.md`).
  - Core CI likewise runs ad-hoc test apps on `portcullis-proxy`
    (`ci.yml` ~870, ~1267, ~2006), and checks that Grafana refuses a spoofed
    header from `portcullis-proxy` (~2153).
- **Docker behaviour this design relies on (the builder verifies each in
  CI):**
  - `network connect --ip` needs a user-defined subnet.
  - Attachments made with `network connect` survive container restarts and
    daemon restarts, but not a recreate.
  - Since Engine API 1.44, network names are unique.
  - Different bridge networks are isolated from each other (the
    DOCKER-ISOLATION chains).
  - `internal: true` networks get no egress and no default route.
  - Traefik's Docker provider dials the container's address on the network
    named by `traefik.docker.network`. If the container isn't on that
    network, it falls back to the container's first network. It never checks
    that Traefik itself is attached.

## Decided by the user

- Option B: each instance gets its own network, shared only with Traefik.
  This replaces the shared `portcullis-proxy` app network (2026-11-02).
- Goal: apps can't reach each other at all, only Traefik reaches each
  instance, and identity headers become trustworthy because only Traefik can
  connect.
- Standing rules: no migration or back-compat code (only the test server
  must upgrade cleanly); prefer mature libraries; main-only; four public
  repos.

## Calls made while drafting (check these)

1. **One routing network per instance, owned by the Hub (Controller's
   call).**
   - **Name:** `portcullis-app.<instance-id>`, for the default instance too
     (`portcullis-app.grafana`).
   - **Why the dot:**
     - Ids never contain `.`, so the name can't equal a compose project
       network (`portcullis-<id>_<key>`), a core network or another
       instance's.
     - Template ids may contain `_`, so a `-`-only scheme could equal
       another project's `portcullis-<x>_<key>`.
   - **Labels:** `io.portcullis.hub.network=<instance-id>` (like
     `io.portcullis.hub.helper`).
   - **Options:**
     - `internal: true`: no egress and no default route. Egress stays on the
       instance's `default` network, as today. So Traefik's default route
       never moves onto an instance bridge.
     - IPv4 only, bridge driver.
   - **Not a compose network.** Compose creates and removes project networks
     on its own schedule. It would fail `down` while Traefik is attached, and
     it can't recreate IPAM in place. A Hub-made external network keeps the
     Hub the single owner of its lifecycle.
2. **Address plan (Controller's call).**
   - **Pool:** `PORTCULLIS_APP_NETWORK_POOL` in core `.env`, default
     **172.31.0.0/17**. Core passes it to the Hub as `HUB_APP_NETWORK_POOL`.
     The same default is built into the Hub, so a new Hub on an old core
     works.
   - **Why that default:**
     - It lies in the 172.31.0.0/16 that core's fixed networks
       (172.31.250–252) already keep Docker's default address pools from
       handing out.
     - It overlaps none of core's subnets.
   - **Blocks:** fixed **/27** blocks, 1024 instances in the default pool.
     In each block:
     - .1 is the gateway (reserved by Docker);
     - **.2 is Traefik** (`PORTCULLIS_TRAEFIK_IP` for that instance);
     - the dynamic `ip_range` is the upper /28 (.16–.30, 15 addresses);
     - .3–.15 are never used.
     Templates put only frontends on this network (at most 3 today:
     netbird), so /27 leaves room.
   - **Allocation:**
     - The Hub allocates under `h.mu`: the lowest block that is in no other
       instance's allocation and overlaps no existing Docker network's
       subnet.
     - It records the block in a new `state.yaml` map `networks:
       {<instance-id>: <subnet>}`. The map is empty on upgrade, so no
       migration is needed.
     - The allocation is kept across disable and restart, so an instance
       keeps its Traefik address. It is freed by a guarded delete.
     - If Docker refuses the create because the pool overlaps a network
       created meanwhile, the Hub tries the next block (bounded).
     - When the pool is exhausted, the answer is `507` with a hint to widen
       the pool.
   - **Validation:**
     - The Hub refuses to start with a pool that isn't an IPv4 CIDR of
       prefix ≤ 27.
     - Core's `network_check` refuses a pool that overlaps
       `portcullis-auth`, `portcullis-domains` or `portcullis-grafana`
       (call 9).
3. **`PORTCULLIS_TRAEFIK_IP` becomes a derived instance variable
   (Controller's call).**
   - The Hub writes the instance's .2 into its `.env` with the other
     instance variables (§3.1 table). It is rewritten before every up and
     reserved, so manifests can't declare it.
   - Core drops `PORTCULLIS_TRAEFIK_IP`, `PORTCULLIS_PROXY_SUBNET` and
     `PORTCULLIS_PROXY_IP_RANGE` from `HUB_ENV_VARS`. No template uses the
     latter two.
   - Templates switch `${PORTCULLIS_TRAEFIK_IP:-172.31.250.2}` to
     `${PORTCULLIS_TRAEFIK_IP:?set by the Hub}`, a mechanical change that
     `validate.py` enforces. A missing value is then a compose error, never
     a stale address.
   - Either order works: an old Hub copies the value from the old core's
     `core.env`, and a new Hub sets it itself.
4. **The template keeps `portcullis-proxy` as a placeholder key; the Hub
   maps it (Controller's call).**
   - **The override's network part.** The Hub override always contains:

     ```yaml
     networks:
       portcullis-proxy:
         external: true
         name: portcullis-app.<instance-id>
     ```

   - **The label.** On every service with `traefik.enable: "true"` it also
     sets `traefik.docker.network: portcullis-app.<instance-id>`. For
     non-default instances the label goes inside the `!override` label set
     (`hubLabels`).
   - **Why keep the key:**
     - Zero edits to 48 compose files.
     - No ordering hazard between the Hub and template releases.
     - The template validator's "templates join only `portcullis-proxy`"
       rule stays as it is.
   - **Fail closed.** Core removes the real `portcullis-proxy` (call 9). A
     template run without the override then finds no such network and
     doesn't start.
   - **Docs.** Contract §3 documents `portcullis-proxy` as "the key for the
     instance's routing network; the Hub names it".
5. **The validator closes the shared-network class (Controller's call;
   `coreref.go`, the same rules in `validate.py`).**
   - **Top-level networks:**
     - `portcullis-proxy` must be exactly `{external: true}`, with no
       `name:` and nothing else.
     - Every other network must be project-scoped: no `name:`, no
       `external`.
     - `portcullis-proxy` and `portcullis-grafana` join `coreNetworks`, so
       neither may be used as a `name:` or external name under another key.
     - A name starting with `portcullis-app.` is refused.
     - All 48 templates already comply.
   - **Labels:**
     - `traefik.docker.network` is refused in templates; the Hub sets it.
     - The custom override already can't set `traefik.*` labels or networks.
   - **Routed services:**
     - A service with `traefik.enable: "true"` must join `portcullis-proxy`.
     - It must not set `network_mode` (host, none, `service:` and
       `container:` alike).
     - All templates comply.
   - **DNS names on `portcullis-proxy`:**
     - Traefik resolves `domains`, `socket-proxy-traefik`, `forward-auth`,
       … through Docker's DNS on every network it joins. So the
       reserved-core-name rule stays.
     - New: a service on `portcullis-proxy` may have no dotted DNS name
       (service name, `container_name` or alias). A dotted alias could
       shadow a public name Traefik resolves (the ACME CA, DNS provider
       APIs). TLS would catch it, but it would still deny service.
     - Today the same exposure exists on the shared network; none of the
       templates has such a name.
   - **Tests.** Every new refusal goes into `TestDiscoverRefusesBypasses`.
6. **Runtime network check (Controller's call, defence in depth like the
   image-label check).**
   - **When:** after `compose up --no-start` and again after `up`,
     `networkProblem` inspects every container of the project.
   - **What is allowed:**
     - Attachments only to `portcullis-app.<id>` and to networks compose
       labelled with this project (`com.docker.compose.project=portcullis-<id>`).
     - `network_mode` `none`, `host` or `service:` only on containers with
       no `traefik.*` labels.
     - Every Traefik-enabled container is on `portcullis-app.<id>` and
       carries `traefik.docker.network` equal to it.
   - **Failure:** anything else means down (volumes kept) and a `409` naming
     the container and network. Nothing starts.
   - **Reconcile:** it runs the same check on running containers. A
     difference is the new drift kind **`network_mismatch`** (actions
     `apply`, `disable`).
     - Example: a container still on the old `portcullis-proxy` after the
       upgrade, or attached by hand to another network.
     - `traefik.docker.network` is also an exposure label (§5 exposure drift,
       `exposureLabel`).
7. **Traefik joins through the Hub's socket proxy, not core (Controller's
   call).**
   - **How:** `NetworkConnect(portcullis-app.<id>, <traefik>,
     IPv4Address=<.2>)` through `socket-proxy-hub`, which already allows it.
     Traefik's own proxy stays read-only.
   - **Finding Traefik:**
     - It is the one container with `com.docker.compose.project=portcullis`
       (core's fixed project name, a Hub constant) and
       `com.docker.compose.service=traefik`.
     - Compose sets these labels itself and overrides image LABELs. App
       projects are always `portcullis-<id>`.
     - Zero or several matches means nothing is attached and an error is
       logged (fail closed).
   - **Verification:** after connecting, the Hub reads Traefik's endpoint
     back. A different address (say, connected earlier without the fixed
     IP) is disconnected and connected again. If that fails, the instance
     doesn't start.
   - **When it runs:**
     1. In `composeUp`, before `up --no-start`: ensure the network exists,
        then attach Traefik.
     2. At Hub start.
     3. On Docker events:
        - core Traefik's container `start` (the event filter widens from
          `portcullis-` projects to core project `portcullis`, service
          `traefik`);
        - a network `disconnect` event of Traefik from a
          `portcullis-app.*` network.
     4. In every reconcile pass (60 s), as a safety net.
     Attaching is idempotent and additive, so it doesn't need the
     instance's lock.
   - **Why not core:**
     - Core's CLI isn't running when Docker or an operator recreates
       Traefik, and a manual `docker compose up -d` bypasses it.
     - Core would also have to trust network labels that a template's own
       project network could copy.
     - The Hub is the only component that knows which instances exist.
   - **The residual:** while the Hub is down, a recreated Traefik can't
     reach apps until the Hub returns (it restarts `unless-stopped`).
8. **The gap fails closed (Controller's call).**
   - **During a gap** (Traefik just recreated, or the Hub still attaching),
     Traefik's provider already knows the routers and dials the app's
     address on `portcullis-app.<id>`. Traefik isn't on that subnet, so the
     packet takes Traefik's default route (`portcullis`). The host drops it:
     the instance network is internal and the bridges are isolated. The
     client gets 502/504 for a few seconds.
   - **No wrong backend.** Subnets never overlap, and app containers can
     only get dynamic addresses outside .2 (call 5 keeps `ipv4_address` off
     shared networks; the instance network counts as shared). So no
     container can answer at Traefik's address, and none can be mistaken
     for another app's backend.
   - **No forwarding.** Traefik's container sets
     `sysctls: net.ipv4.ip_forward=0` and `net.ipv4.conf.all.forwarding=0`,
     so it never routes packets between instance networks, even if an app
     with `NET_ADMIN` points a route at it. CI asserts both.
9. **Core: `portcullis-proxy` goes away; core Grafana gets its own network
   (Controller's call).**
   - **Removed:**
     - the `portcullis-proxy` network;
     - Traefik's attachment to it;
     - `TRAEFIK_PROVIDERS_DOCKER_NETWORK`. Every core service and every Hub
       container sets the label. A container without it gets Traefik's
       first-network fallback, which is unreachable (call 8).
   - **New network `portcullis-grafana`:**
     - `internal: true`;
     - fixed IPAM `PORTCULLIS_GRAFANA_SUBNET` (default 172.31.253.0/28),
       `PORTCULLIS_GRAFANA_IP_RANGE` (172.31.253.8/29) and
       `PORTCULLIS_GRAFANA_TRAEFIK_IP` (172.31.253.2);
     - members: Traefik and Grafana only.
     - Grafana sets `GF_AUTH_PROXY_WHITELIST=${PORTCULLIS_GRAFANA_TRAEFIK_IP}`
       and `traefik.docker.network: portcullis-grafana`.
     - Grafana needs no egress: update checks, plugin installs and gravatar
       are already off.
   - **`network.sh`:** the proxy helpers become `grafana_*`. Validation
     covers it and the app pool (call 2), with the same mismatch guard.
   - **`.env.example`:**
     - drop `PORTCULLIS_PROXY_*` and `PORTCULLIS_TRAEFIK_IP`;
     - add `PORTCULLIS_GRAFANA_*` and `PORTCULLIS_APP_NETWORK_POOL`.
   - **CI:** the "each proxy network has exactly its two members" check
     extends to `portcullis-grafana`.
   - **No core file references a network called `portcullis-proxy`.**
     `docker-compose.test.yml`, `docker-compose.apps.yml` and the ad-hoc CI
     apps join a CI-made network created the Hub's way (call 15).
10. **Network lifecycle (Controller's call).**
    - **Enable / restart / drift apply / start / restore** (all through
      `composeUp`): allocate if needed, create the network if missing, then
      attach Traefik, then compose.
      - **An existing network of that name:**
        - Hub-labelled for this instance with the right IPAM: reused.
        - Hub-labelled but different (IPAM or `internal`): disconnected and
          removed if it has no endpoints but Traefik, then recreated.
          Otherwise `409`.
        - Unlabelled: `409` naming it. The Hub never adopts a network it
          didn't make.
      - **Traefik not found or not attachable:** a `503` before compose, so
        nothing is created.
    - **A template without `portcullis-proxy`** (no routed service) gets no
      network and no allocation.
    - **Restart and backup stops** (down/up) keep the network.
    - **Disable:** compose down → disconnect Traefik → remove the network.
      If the remove fails (endpoints left), it's a warning and the orphan
      sweep retries.
    - **Failed enable:** `rollbackUp` also removes the network it created.
      The allocation stays.
    - **Guarded delete (§11.4 step 3):** after `down`, the network is
      removed and the allocation freed, before the volumes.
    - **Restore:**
      - into the same id: keeps the allocation;
      - into a new id: allocates fresh.
      - The allocation is never in the archive, and `config/env` is
        rewritten with the derived variables, `PORTCULLIS_TRAEFIK_IP`
        included.
    - **Create / restore-as collision checks (§11.1)** add: an unlabelled
      Docker network named `portcullis-app.<new-id>` is a `409`. A
      Hub-labelled leftover holds no data, so it is removed and recreated.
    - **Hostname changes, extra domains, sign-in routers and public routers**
      don't touch the network. It is per instance, not per host.
      `forward-auth-ext@docker` is a core service on core's network.
    - **Orphan sweep:**
      - **When:** at start and in every reconcile pass.
      - **What:** a Hub-labelled network whose instance is not enabled.
        Unknown instances count, and deleted ones too.
      - **How:** the Hub takes the instance's lock non-blockingly (a busy
        instance is skipped, so the sweep can't race an enable). Then it
        disconnects Traefik and removes the network, but only if no
        endpoint except Traefik is left.
      - **Leftovers:** a network that still has app containers stays; the
        existing leftovers drift covers those containers.
11. **Core services apps reach (Controller's call: none directly, as
    today).**
    - Apps reach Keycloak and every other core host only by public URL,
      through Traefik (forward-auth apps never call core; native-OIDC
      back-channels use public DNS).
    - On its instance network, an app can also reach Traefik itself at .2,
      which is the same gateway as from the internet.
    - No `auth`, `keycloak`, `group-gate` or `hub` name resolves on an
      instance network. The DNS names of core services are reserved, and
      only Traefik is attached.
    - Nothing in the templates needs more.
12. **The nginx gates stay (Controller's call).**
    - Gated backends (esphome, zigbee2mqtt, motioneye, mattermost on
      `mm-gate`) keep their `gate.sh` front.
    - **Why they stay:**
      - They do something isolation doesn't: they never forward the
        Portcullis session (Authorization, access-token headers,
        `_oauth2_proxy*` / `__Host-portcullis_ext*` cookies) to apps with
        no access control of their own.
      - They are the only defence against a compromised sidecar of the same
        instance.
      - They cost nothing to keep.
    - **What changes:** their `PORTCULLIS_TRAEFIK_IP` is now per instance
      (call 3). `mm-gate` should merge as planned.
    - Simplifying them away would be a separate decision, after this change
      has run for a while.
13. **Socket proxies: no change (Controller's call).**
    - The Hub already has `NETWORKS` + `POST`, which already let it create
      networks and connect any container to them. This design uses that
      power, and the contract now says so.
    - Contract §6 lists the network operations: list, inspect, create,
      remove, connect, disconnect.
    - Traefik's proxy stays `POST=0`.
14. **Upgrade of the test server: release order, no migration code
    (Controller's call; see call 23 for how this maps onto `edge`).**
    1. **Hub first.**
       - The Hub has the pool default built in, so it works on today's core.
       - Each enabled instance shows `network_mismatch` drift ("on
         portcullis-proxy, not on portcullis-app.<id>").
       - Until the admin applies it, the instance keeps routing over the old
         shared network. Traefik is still there, so there is no outage.
       - Apply recreates the containers on `portcullis-app.<id>`, with
         Traefik attached at .2 and `PORTCULLIS_TRAEFIK_IP` set.
    2. **Templates** (the `:?` form and the CI emulation). Either Hub works
       with them (call 3).
    3. **Core.**
       - `./portcullis upgrade` recreates Traefik without
         `portcullis-proxy`, with `portcullis-grafana`, and recreates
         Grafana.
       - The Hub re-attaches Traefik to every instance network on Traefik's
         start event.
       - Instances still not applied then answer 502 (fail closed) until
         applied.
    4. **Cleanup.** The upgrade note says: `docker network rm
       portcullis-proxy` once `docker network inspect portcullis-proxy`
       lists no containers. Compose leaves a network it no longer declares.
       This is a documented step, not code.
    - There is no automatic re-apply. The drift banner lists every instance
      that needs it.
15. **Tests (Controller's call).**
    - **Hub unit tests** (fake engine):
      - allocation: lowest free block, existing subnets skipped, exhaustion
        `507`, kept across disable, freed by delete, fresh for restore-as;
      - the override golden files: the networks block, the
        `traefik.docker.network` label (default and `!override`
        instances), the env value;
      - every validator refusal of call 5;
      - `networkProblem`: an attachment to `portcullis-proxy` or a foreign
        network gives `409` + down, and so does a Traefik-labelled
        `network_mode` service;
      - Traefik attach:
        - happens before compose;
        - a wrong address leads to a reconnect;
        - Traefik missing gives `503` with nothing created, and so do two
          Traefiks;
      - re-attach on a Traefik `start` event and on a `disconnect` event;
      - the orphan sweep skips busy instances and networks with app
        endpoints;
      - disable and delete remove the network;
      - `network_mismatch` drift and apply.
    - **Core `e2e-instances`** (real daemon, Hub, echo template). The echo
      template gains a `probe` service: curl, on `default` +
      `portcullis-proxy`, no Traefik labels. Two instances A and B are
      enabled, and the test runs `docker run --network container:<A's web>`
      (exactly an app's view). It asserts:
      1. A cannot connect to any address of any of B's containers (every
         network), and cannot reach core services by name (`keycloak`,
         `group-gate`, `hub`, `lldap`, `socket-proxy-hub`, `domains`) or by
         address.
      2. Over A's network, A reaches Traefik at A's `PORTCULLIS_TRAEFIK_IP`.
         That value equals Traefik's endpoint address on
         `portcullis-app.A`.
      3. Through Traefik, both hosts route (302 to sign-in, 200 after the
         existing sign-in steps). whoami's `RemoteAddr` is the instance's
         Traefik address.
      4. **Header spoofing:**
         - `X-Forwarded-User: admin` sent from A straight to B's address
           can't connect;
         - sent from A through Traefik to B's host, the spoofed value never
           reaches B (stripped by forward-auth).
      5. Traefik has `ip_forward=0` and `conf.all.forwarding=0`.
      6. **Recreate:** after `docker compose up -d --force-recreate
         traefik`, Traefik is back on both networks at the same addresses
         within 30 s. Requests in the gap are non-2xx and are never served
         by another backend.
      7. Disabling B removes `portcullis-app.B`, and A still routes. A
         Hub-labelled network made by hand for an unknown instance is gone
         after the next reconcile.
    - **Core `ci.yml`:**
      - The Traefik/IPAM checks move to `portcullis-grafana`.
      - The Grafana spoof check runs from the `monitoring` network (still
        refused).
      - The ad-hoc test apps use the CI helper network.
    - **Templates CI** (`tests/lib.sh`) emulates the Hub:
      - create `portcullis-app.ci-<app>` (internal, a /27 from the pool),
        connect Traefik at .2 (with the hostname aliases the current CI
        adds), and set `PORTCULLIS_TRAEFIK_IP`;
      - pass a generated override with the networks block and labels.
      `assert_traefik_only_trust` / `assert_spoofed_identity_rejected` run
      their spoofer on the instance network, as a same-instance peer: that
      still proves the allowlist is exact. A new
      `assert_unreachable_from_other_instance` runs the spoofer on a second
      CI network and expects no connection.

### Settled in the builder check

16. **What counts as the instance's own project networks (Controller's
    call).** Networks with label
    `com.docker.compose.project=portcullis-<id>`, in practice
    `portcullis-<id>_default` and the template's other project-scoped
    networks. Names alone are not enough: ownership is the compose label,
    as for volumes (§11.4).
17. **Where the network work sits in `composeUp` (Controller's call).**
    - `ensureInstanceNetwork(t)` runs after the override and env are
      rendered and before `syncTemplateFiles`. It runs without `h.mu`;
      only the allocation itself takes `h.mu`, and the state is saved
      there.
    - The derived `PORTCULLIS_TRAEFIK_IP` comes from the allocation. So a
      first enable allocates in phase 1 of `enableInner` (under `mu`, with
      the other files), and phase 2 creates the network and attaches
      Traefik.
18. **Missing template (Controller's call).** An enabled instance whose
    template is missing keeps running with whatever it has. Its override
    can't be regenerated, and the policy denies its hosts anyway. The sync
    still attaches Traefik to its network if one exists. The sweep doesn't
    remove it, because the instance is enabled.
19. **The core project name is a constant (Controller's call).** `portcullis`
    is core's fixed compose `name:`, and `coreContainerRe` already assumes
    it. It is not configurable.
20. **Drift wording and UI (Controller's call).**
    - `network_mismatch` items say what is wrong ("service web is on
      portcullis-proxy", "Traefik is not on portcullis-app.<id>: <error>")
      and offer `apply` / `disable`.
    - The instance overview's facts gain "Network `portcullis-app.<id>`,
      Traefik at <ip>" (read-only). It helps when debugging a header-auth
      allowlist.
21. **Core `status` (Controller's call).** `./portcullis status` warns, read
    only, about every `io.portcullis.hub.network` network Traefik isn't
    attached to. It changes nothing.
22. **Scale (Controller's call).** Traefik gets one interface per enabled
    instance. The builder checks Traefik and Docker with 50 attached
    networks on the test server (start time, provider refresh) and records
    the figure in the docs. No hard cap besides the pool.
23. **What "Hub first" means in practice (Controller's call; refines call
    14).**
    - Core `main` pins `HUB_IMAGE` to `edge`, so any `./portcullis upgrade`
      also pulls the newest Hub.
    - So on the test server, step 1 is: merge the Hub, then run
      `./portcullis upgrade` from the **current** core checkout (the new Hub
      on the old core compose). Then apply every instance in the drift
      banner.
    - Steps 2–3 follow: merge the templates and core, `git pull` in the core
      checkout, then `./portcullis upgrade`.
    - Core's change merges only after the Hub change is on `edge`. The core
      PR description says so, and core CI's `e2e-instances` already needs
      the new Hub to pass.
24. **Referencing the Traefik address needs the network (Controller's
    call).**
    - A template whose `compose.yml` (or a support file it passes the value
      to through `environment:`) references `PORTCULLIS_TRAEFIK_IP` must
      declare `portcullis-proxy`. Without it the Hub allocates nothing and
      sets no value. The validator refuses the reference, and so does
      `validate.py`.
    - All 33 users declare it today.
25. **The address may change, so apps apply it at every start (Controller's
    call).**
    - The allocation is stable, but a re-allocation (call 2: a block taken
      by another network while the instance was disabled, or a restore into
      a new id) changes the instance's Traefik address.
    - So templates must apply `PORTCULLIS_TRAEFIK_IP` at every start, never
      only at first init. That is the existing pattern: the gates'
      `gate.sh`, Home Assistant's `init.py` and dokuwiki's `init.sh` rewrite
      it each start, and the other templates pass it through the
      environment.
    - CONTRIBUTING.md states the rule. The templates CI starts each app
      twice with different addresses and runs `assert_traefik_only_trust`
      after the second start.

## Example: what the Hub writes for `grafana-team-b`

The allocation is `172.31.0.96/27`, so Traefik is at 172.31.0.98.

```yaml
# <data>/overrides/grafana-team-b.override.yml (excerpt)
services:
  dashboards:
    labels: !override
      "traefik.enable": "true"
      "traefik.docker.network": "portcullis-app.grafana-team-b"
      "traefik.http.routers.grafana-team-b_grafana.rule": "Host(`${PORTCULLIS_HOST_GRAFANA:-grafana.portcullis.local}`)"
      # … the rest of the renamed labels, as today
networks:
  portcullis-proxy:
    external: true
    name: portcullis-app.grafana-team-b
volumes:
  "grafana-data":
    name: "portcullis_grafana-team-b-grafana-data"
```

```text
# <data>/env/grafana-team-b.env (excerpt)
PORTCULLIS_INSTANCE=grafana-team-b
PORTCULLIS_TRAEFIK_IP=172.31.0.98
```

The Docker network looks like this:

```text
portcullis-app.grafana-team-b
  internal: true, subnet 172.31.0.96/27, ip_range 172.31.0.112/28
  labels: io.portcullis.hub.network=grafana-team-b
  endpoints: portcullis-traefik-1 172.31.0.98, portcullis-grafana-team-b-dashboards-1 172.31.0.11x
```

The template (`GF_AUTH_PROXY_WHITELIST: ${PORTCULLIS_TRAEFIK_IP:?set by the
Hub}`) is untouched apart from that variable form.

## Interfaces with the other repos

- **Contract** (`portcullis-docs/docs/guides/integration-contracts.md`;
  change it first):
  - §2: drop `PORTCULLIS_PROXY_SUBNET` / `_IP_RANGE` and move
    `PORTCULLIS_TRAEFIK_IP` to the instance variables.
  - §3 Networks bullet and core names: `portcullis-proxy` is the routing
    placeholder; `portcullis-grafana` and `portcullis-app.*` are reserved;
    the new validator rules of call 5; the runtime network check (call 6).
  - §3.1: the instance-variable table gains `PORTCULLIS_TRAEFIK_IP`
    (reserved).
  - §5: exposure drift includes `traefik.docker.network`.
  - §6: the Hub's network operations.
  - §11.1: network collision.
  - §11.2: the derived-names table gains "Routing network
    `portcullis-app.<id>`".
  - §11.4 step 3: network removal.
  - §11.6: restore.
  - No release tags exist yet, so there is no MAJOR bump (§1).
- **Docs pages:** `operations/hardening.md` (network table, threat table
  row "Identity headers", diagram), `architecture.md`, `operations/hub.md`,
  `operations/upgrading.md` (call 14), `guides/header-auth-app.md`,
  `guides/saml-app.md`, `guides/adding-an-app.md`,
  `guides/manifest-reference.md`, `guides/third-party-apps.md` (open
  question 1), and the app pages that mention the network.
- **Core:** see call 9, plus `CLAUDE.md`, `README.md`, `CHANGELOG.md`,
  `tests/test_shell_libs.sh` (pool and grafana validation) and Dependabot's
  file list if example files change.
- **Templates:**
  - the `:?` form (33 files);
  - `validate.py` (call 5 and the `:?` rule);
  - `tests/lib.sh` (call 15);
  - `CLAUDE.md` / `CONTRIBUTING.md` network text;
  - `.core-ref` stays `main`.
- **Hub:**
  - `override.go`: networks block, label;
  - `env.go`: derived variable;
  - new `networks.go`: allocation, ensure, attach, sweep, `networkProblem`;
  - `lifecycle.go`, `delete.go`, `restore.go`, `create.go`: collision
    check;
  - `reconcile.go`: events, drift kind;
  - `templates/coreref.go`;
  - `state`: the `networks` map;
  - `internal/docker`: network list / inspect / create / remove / connect /
    disconnect, and container networks in `ListContainers`;
  - `Engine` interface and fakes;
  - `CLAUDE.md`.

## Residuals (accepted, documented)

- **Same-instance peers** share the routing network with Traefik. A
  compromised sidecar could ARP-spoof Traefik's address inside its own
  instance. Gates (call 12) and per-service allowlists narrow this. It is
  the same trust domain.
- **Traefik's internal entrypoints** (`:8082` metrics, `:8080` ping) answer
  on every interface, so an app can read router and host names and request
  counts of all apps. This is pre-existing (it was open on
  `portcullis-proxy` too). Follow-up: bind them to Traefik's `portcullis`
  address (that needs fixed IPAM on `portcullis`).
- **Requests an app sends to Traefik come from a private address**, so a
  template `ipallowlist` on private ranges admits other apps. This is
  pre-existing. Follow-up: a validator warning for private ranges in
  `ipallowlist.sourcerange`.
- **Host-published ports and `network_mode: host`** services are
  reachable from every container through the host's addresses, by design
  (non-goals; open question 2 covers the routed port).
- **Hub down:** a Traefik recreated while the Hub is down can't reach apps
  until the Hub is back (call 7).

## Left to the builder

- Exact Go names, the moby SDK calls (the
  `network.CreateOptions` / `EndpointSettings` shapes), and how
  `ListContainers` exposes networks.
- Confirming that Docker accepts `.` in network names. If it doesn't, use
  `portcullis-app--<id>` and add a validator refusal of ids/keys that could
  form it.
- Confirming that the `sysctls` are allowed on Traefik's container and
  effective (CI asserts them).
- Debounce and backoff for the attach loop. Wording of errors, drift
  messages and the upgrade note.
- What happens to `docker-compose.apps.yml`: rewritten onto the CI helper
  network, or dropped in favour of the templates. Pick whichever keeps
  `ci.yml`'s host-less-router check meaningful.

## Open questions

1. **Hand-run ("third-party") apps outside the Hub.** The docs
   (`guides/third-party-apps.md`, `saml-app.md`, `header-auth-app.md`) tell
   operators to put any container on `portcullis-proxy` with labels. That
   network is gone, and nothing re-attaches Traefik to networks the Hub
   didn't make. Options:
   - (a) Drop the path: such apps become a template in the operator's own
     git source (the Hub then isolates them like any instance).
   - (b) Keep a core-managed shared `portcullis-proxy` only for hand-run
     apps (Hub apps never on it). That brings back app-to-app exposure
     among those apps.
   - (c) A new Hub feature: "external app networks" that the Hub creates and
     attaches Traefik to, for operator containers.

   **Recommendation: (a)** now, with (c) as a later follow-up if anyone
   needs it. (b) brings back exactly the problem this design removes.
2. **Publishing the routed port on the host.** A manifest `ports` entry or
   an Expert override `ports:` that maps the container port Traefik routes
   to bypasses Traefik entirely, from every container and from the LAN or
   the internet. No template does this today. Should the Hub refuse it?
   - **Recommendation:**
     - Refuse it (manifest at discovery, custom override on save and before
       up) for `forward-auth` and `header-auth` apps, where the gateway is
       the only sign-in and identity headers would be spoofable.
     - Allow it, with a warning in the Expert tab, for `native-oidc`,
       `custom` and `public` apps: LAN clients such as TV apps talking to a
       media server directly are a real use case, and the app does its own
       sign-in there.
