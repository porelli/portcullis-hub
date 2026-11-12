# VPN-only access, per app or for the whole server (design)

Status: written by the assistant for the roadmap item "VPN only access per app, or for the whole server" (the user's words). No interruptions were wanted, so the assistant made every decision. Each one is the **assistant's call** unless it says otherwise. Open questions are in §16, each with a default. Order on the roadmap: after DNS hardening (`2026-11-13-dns-hardening-design.md`), rootless Podman and Kubernetes. This design has to work on all three runtimes.

**Revision 2 (2026-11-12), two user rulings:**
- **User ruling 1:** "for the VPN, let's allow using any of the VPN apps installed from the marketplace." The first version had a single core WireGuard VPN. Now any marketplace app whose template declares a `vpn:` block (§4) can be a **people-VPN provider**: Headscale, NetBird, a plain WireGuard app, or a future one. Core enforcement stays VPN-agnostic.
- **User ruling 2:** "The built-in WireGuard service might be helpful to handle the kubernetes cluster and/or multiple servers (aka: deploy on another machine)." The built-in userspace WireGuard stays as core infrastructure, one implementation with separate roles (§3): **link** (server-to-server tunnels: the multi-server spec's worker ↔ primary tunnel and a Kubernetes cluster on another machine) and **people** (the default people-VPN provider when no marketplace VPN is wired). Each role has its own keys, peers, address range and policy.

## 1. Where things stand (2026-11-12)

- **Traefik** (core `docker-compose.yml`) has `web` (:80, redirects to https), `websecure` (:443, `asDefault`, ACME **DNS-01 only**: nothing on :80 has to stay public), plus the internal `traefik` (:8080 ping) and `metrics` (:8082). `websecure` never trusts forwarded headers, so client copies of `X-Forwarded-*` / `X-Forwarded-Tls-Client-Cert*` are deleted (CLAUDE.md rule). There is no `ipAllowList` anywhere and no notion of where a client connects from.
- **Routers.** Core routers (portal, auth/keycloak, keycloak-admin, oauth2-callback, hub, people, enroll-invite, traefik dashboard, lldap, mcp, grafana-metrics) are compose labels with `entrypoints: websecure`. The Hub renders instance routers through its override (`internal/hub/override.go`, `public.go`): the TLS tier per host (contract §5), public routers `portcullis-public-<id>` (public guard, no sign-in), extra-domain sign-in routers `portcullis-oauth2-<id>_<r>`, the MCP routers. The Hub has no rw mount under `traefik/`.
- **group-gate** reads `group-gate-policy.json` (**v6**, `POLICY_VERSION = 6`) from `hub_data` on every request, fails closed on unknown keys/versions, and gets core hosts from `group-gate-map.conf`.
- **Local networks** (Hub Settings, contract §14.7) are CIDRs for `lan_only` ports and file sharing (defaults include `100.64.0.0/10`, "the tailnet"). The doctor's `lan_only_exposed` judges port binds. §14.7 records a residual: with Docker's userland proxy on, connections to published ports can arrive from the bridge gateway. So **a source address seen through a published port is not trustworthy enough to grant access.**
- **Template capabilities.** A manifest declares optional capability blocks that the Hub validates strictly (unknown keys refused) and the templates repo's `schema/manifest.schema.json` + `tests/validate.py` mirror: `auth:` (method, groups, `public_access`, `native_login`), `ports:` (incl. `lan_only`, `network_mode_host`), `settings:`, `hooks:` (§13.8, Docker exec with a JSON stdin; triggers `start|settings_change|membership_change|credential_change`, plus the exclusive `ai` trigger), `jobs:` and the required `ai:` block (§3.2, `internal/templates/ai.go`, "exactly one of two forms"). Category `vpn` is only a catalog label today.
- **VPN apps in the marketplace:** `headscale` (Headscale + Headplane, native OIDC through Keycloak, users keyed on the OIDC subject and named after `preferred_username`, default host `vpn.<d>`, `ai.unsupported`) and `netbird` (management/signal/dashboard on Traefik, coturn with host networking; management keys users on the token's `sub`). There is no plain-WireGuard template (wg-easy or similar) yet. Neither app is wired into Portcullis access. Core still has leftovers from the initial release: `headscale/config.yaml` and the optional `headscale`/`headplane` Keycloak clients in `scripts/lib/keycloak.sh` (the template now owns those clients).
- **Other specs** that lean on this one: multi-server (its `link` tunnel, userspace WireGuard), Kubernetes (PROXY trust on the vpn pod), rootless Podman (no NET_ADMIN anywhere in core).

## 2. Goals, non-goals, anti-goals

**Goals**
1. **Per app:** an instance can be set to *Reachable from: the internet (default) / VPN only*. A VPN-only instance answers only through a Portcullis-wired VPN, after the normal Portcullis sign-in, and only from a device that belongs to the person who signed in.
2. **Any marketplace VPN (user ruling 1):** every installed app whose template declares a `vpn:` block can be wired as a people-VPN provider. Several can be wired at once (§8.3). Core knows nothing about Headscale or NetBird: the template says which addresses it hands out, how its traffic reaches Traefik and how Portcullis learns who owns each address.
3. **A built-in default:** with no marketplace VPN wired, the built-in userspace WireGuard provider works on Docker, rootless Podman and Kubernetes without NET_ADMIN (§3.2).
4. **One WireGuard implementation for server tunnels too (user ruling 2):** the multi-server worker tunnel and a Kubernetes cluster on another machine use the same core service, in a separate role (§3.1).
5. **Whole server:** one switch makes everything VPN-only except the short list that has to stay public (§9), with a recovery path that doesn't depend on any VPN.
6. **Devices:** built-in devices are added and removed by their owners on the Sign-in page (people.<d>); private keys never reach the server. Marketplace devices are managed in their app; Portcullis shows them (read-only) next to the built-in ones.
7. **Split DNS:** on a wired VPN, Portcullis names resolve to that VPN's entry point (§11).
8. The doctor, status, CI and docs cover all of it.

**Non-goals (v1)**
- A general-purpose VPN from core: the built-in provider gives no LAN access, no exit node, no mesh. Peers reach exactly one thing, Traefik's VPN entrypoint. Marketplace apps keep doing what they do for people (mesh, exit nodes); Portcullis only uses their path to the gateway.
- Non-HTTP ports over the VPN (e.g. Samba/Time Machine from outside). Parked (§15).
- IPv6 inside tunnels: Portcullis access is matched on IPv4 tunnel addresses only (AAAA for Portcullis names is NODATA on the built-in resolver, §11; marketplace devices' IPv6 addresses are ignored).
- Treating the LAN (Local networks) as equal to the VPN. The source-address residual in §1 is the reason. Parked.
- Shared devices (a family tablet that several people use). Parked.
- Marketplace VPN instances placed on a worker (multi-server): a provider's gateway must sit on the primary (§5).

**Anti-goals (never)**
- **Never bypass sign-in.** The VPN is an extra condition, never a credential. A VPN-only app still runs `portcullis-auth` + `portcullis-groups` with its usual factors, groups and path groups. Being on any VPN never skips or weakens a factor, never counts as `mtls`/`webauthn`, and never makes a step-up silent. A marketplace VPN's own sign-in (e.g. Headscale's OIDC) never stands in for the Portcullis sign-in.
- **Never expose anything wider.** Every switch here only narrows reachability. No admin surface (Hub, Keycloak admin, LLDAP, Traefik dashboard, metrics) ever gains a route because a VPN exists. Wiring a VPN app never opens a public path that wasn't public.
- **Fail closed.** If the `wg` service is down, a provider's gateway is down, `vpn.json` can't be parsed, a provider's device map is stale or unreadable, or the policy's `vpn` section is malformed, then the affected VPN-only hosts are **unreachable** and never fall back to the internet. The enforcement is structural: a VPN-only router doesn't exist on `websecure` at all.
- **Roles never mix (user ruling 2):** a server tunnel (link) never carries people traffic into worker apps around the primary's sign-in, and a people device is never a server peer.
- Never store a client private key, and never let one reach the Hub, logs, audit or an MCP transcript.

## 3. Architecture

```
built-in device ═WG═▶ wg [people] ─┐
Headscale device ═tailnet═▶ gateway (template) ─PROXY v2─▶ wg [edge] ─PROXY v2─▶ Traefik vpnsecure ─▶ forward-auth, group-gate ─▶ app
NetBird device ═netbird═▶ gateway (template) ─PROXY v2─┘
worker agent ═WG═▶ wg [link]  (multi-server; separate key, port, range; zero listeners)
```

### 3.1 The core `wg` service and its roles (user ruling 2; shape is the assistant's call)

One Go binary and one compose service, `wg` (`wg/` in the core repo, built locally like group-gate; it replaces both the first version's `vpn` service and the multi-server spec's `link` service). wireguard-go + gVisor netstack (`golang.zx2c4.com/wireguard`, `tun/netstack`), `github.com/pires/go-proxyproto`, `github.com/miekg/dns`. uid 10006, read_only, `cap_drop: ALL`, `no-new-privileges`, no `/dev/net/tun`, no kernel module. Compose profile `wg`, off by default; `config apply` turns it on when any role is on. Roles are switched on independently:

| Role | Switched on by | What it is |
|---|---|---|
| **edge** | any VPN-only host, a non-`apps` mode, or a wired provider | The single PROXY-protocol client of Traefik's `vpnsecure`. Accepts connections from the built-in people stack (in-process) and from wired marketplace gateways (§5), checks each claimed client address against that provider's ranges, and re-originates PROXY v2 to Traefik. Needs no key and no UDP port |
| **people** | `./portcullis vpn init` (host) | The built-in people-VPN provider: one WireGuard device, key `secrets/wg/people.key`, `${PORTCULLIS_VPN_PORT:-51820}/udp`, tunnel `${PORTCULLIS_VPN_SUBNET:-10.213.0.0/22}` (server `.1`, MTU 1280), peers from `hub_data/vpn.json`. Netstack listeners: TCP 443 (handed to edge), TCP 80 (`308` to https), UDP/TCP 53 (§11) |
| **link** | `./portcullis link init` (host; multi-server and remote Kubernetes) | Server-to-server tunnels: a second, independent WireGuard device, key `secrets/wg/link.key`, `${PORTCULLIS_LINK_PORT:-51821}/udp`, tunnel `${PORTCULLIS_LINK_SUBNET:-10.214.0.0/24}`, peers from `hub_data/link.json`. **Zero netstack listeners**: it only dials out (Hub control CONNECT, relay data CONNECT), exactly as the multi-server spec §4 describes |

**Separation of the roles** (the code is shared, nothing else is):
- Two WireGuard devices, two gVisor stacks, two private keys, two UDP ports, two config files, two disjoint subnets (`link init` and `vpn init` refuse overlaps with each other, Local networks, Docker networks and every wired provider range). There is **no forwarding code between the stacks**: the people stack's only outbound path is the edge → Traefik `vpnsecure`; the link stack's only callers are the Hub and relays on `portcullis-link` / `portcullis-link-data`, and its only targets are worker tunnel addresses. A unit test proves the people stack can't dial a link address and the link stack accepts nothing inbound.
- A public key can't be in both `vpn.json` and `link.json`; the Hub refuses it and the service refuses to load a config that has one (fail closed for that role).
- Worker apps are reached only through relays on the primary, behind the primary's Traefik, sign-in and group-gate (multi-server §4). A link peer has no route to `vpnsecure`, so a worker can never present itself as a people device.
- Per-role metrics, health and status lines; one role failing to load its config disables that role only.

The outer UDP source address doesn't matter for either role (WireGuard authenticates by key), so rootless port forwarding that rewrites it is harmless. On Kubernetes both UDP ports are LoadBalancer Services of the one `wg` pod.

### 3.2 Built-in provider stays the default (assistant's call)

Kept, because it is the only provider that is guaranteed on every runtime: no NET_ADMIN, no TUN, no host networking, no control plane, stock WireGuard apps on every OS, and the tunnel source address *is* the device identity (cryptokey routing), assigned by Portcullis with no external API. It is the default whenever no marketplace provider is wired, and the recommended recovery provider in `server` mode (§9). An admin can leave it off (`vpn init` never run) or turn it off later (`./portcullis vpn builtin off`) once a marketplace provider is wired; the edge keeps running either way.

Marketplace providers trade that for their own features (OIDC enrolment, ACLs, mesh, MagicDNS, polished clients). Their runtime fit is decided by the existing compatibility gate (rootless spec §9 / Kubernetes §8): a gateway that needs TUN or NET_ADMIN is `degraded` on rootless Podman and refused on Kubernetes unless it has a userspace mode.

### 3.3 Providers

A **provider** is the built-in people role or a wired marketplace instance. Each has: an id (`builtin` or the instance id), IPv4 client ranges, an ingress into the edge, a device map (address → device → Portcullis person, §6) and a freshness state. Installing a template with a `vpn:` block does **not** make it a provider: the admin turns on *Use for Portcullis access* on the instance's VPN tab (audited `vpn.provider_wired|unwired`, API/MCP `set_vpn_provider`, admin, per-call confirmation like other exposure changes; assistant's call: a mesh installed for its own sake shouldn't silently become an access path).

## 4. The `vpn:` manifest block (template capability)

Optional. Strict like `ai:` (unknown keys refused); the templates repo's schema + `validate.py` and a new Hub `ValidateVPN` (`internal/templates/vpn.go`) implement the same refusals, and the Hub skips a template that fails them.

```yaml
vpn:
  label: Headscale tailnet            # single line, 1–64; shown on Settings → VPN, the instance and device lists
  ranges: ["100.64.0.0/10"]           # IPv4 CIDRs the app hands to clients; literals or exactly "{{setting:KEY}}" (a cidr setting)
  ingress:
    service: gateway                  # compose service the Hub joins to portcullis-vpn
    proxy_protocol: v2                # the only value in v1
  identity:
    source: hook                      # hook | static
    hook: vpn-devices                 # a hook with when: [vpn] (§6.1); source: hook only
    owner: oidc_sub                   # oidc_sub | username; source: hook only
    refresh: 60s                      # 15s–10m, default 60s
  dns:
    hook: vpn-dns                     # a `vpn` hook that receives the records (§11) — or `manual: true`
  control_routers: [headscale]        # host routers that stay on websecure in server mode (§9)
```

**Rules:**
- `ranges`: 1–8 IPv4 prefixes, each /8–/30, no overlaps within the block. At wiring time (not template load) the Hub also refuses overlap with another provider's ranges, the built-in and link subnets, Docker networks and `portcullis-vpn`. Overlap with Local networks is allowed with a doctor Warning (§12): those ranges then reach `lan_only` ports, as the tailnet default does today, but never count for VPN-only access.
- `ingress.service`: a service of `compose.yml` with no `network_mode` (it must be able to join a network), not a job, not a `kind: companion` AI service, with no Traefik router. The template must not mention `portcullis-vpn` anywhere (the network is Hub-only, like `portcullis-oauth2-`). The Hub's override adds the network with a fixed address and sets `PORTCULLIS_VPN_EDGE=<edge ip>:<port>` on that service (§5). `proxy_protocol: none` (a gateway that routes real source addresses) is parked: it needs routes in Traefik's netns, which core won't take (NET_ADMIN).
- `identity.source: hook`: `hook` names a hook with exactly `when: [vpn]` (any service of the template), and `owner` is required. `source: static`: no `hook`/`owner`; the admin assigns addresses to people (§6.2). A hook with `vpn` that no `vpn:` field names is refused, and `vpn` can't combine with other triggers (like `ai`).
- `dns`: exactly one of `hook` (a `vpn` hook) and `manual: true`.
- `control_routers`: host routers of the template (§3.1 of the contract), optional. They must not be the routers of an admin UI the template marks `admin_paths`/`group_admin`; review rule: only what clients need to connect (coordination, signal, relay).
- Templates never ship Portcullis code for this: hooks call the app's own CLI or API (the §3.2 "companions are never Portcullis code" rule, applied to VPN glue). The one exception is core's published `portcullis-vpn-forwarder` image (§5), which a template may use as its gateway, pinned like any image.

**Reference templates** (templates repo):
- **headscale** (CI reference): gains a `gateway` service, the official `tailscale/tailscale` image in userspace mode (`TS_USERSPACE=true`, no TUN, no caps), registered with a tagged pre-auth key created by a `start` hook, running `tailscale serve --tcp 443 tcp://$PORTCULLIS_VPN_EDGE --proxy-protocol 2` (open question 5). `identity.hook` runs `headscale nodes list -o json` in the headscale container and maps it with `jq` (no API key needed); `owner: oidc_sub` (Headscale keys OIDC users on iss+sub). `dns.hook` writes Headscale's `dns.extra_records_path` file (reloaded on change). `control_routers: [headscale]`; Headplane is an admin UI and goes VPN-only in server mode.
- **netbird** (second): a gateway service running the NetBird client plus `portcullis-vpn-forwarder` in its netns (`network_mode: service:`), so the forwarder sees real peer addresses; the client needs TUN + NET_ADMIN (rootless `degraded`, Kubernetes refused unless its netstack mode proves to keep source addresses). `identity.hook` calls the management API `/api/peers` + `/api/users` with a service-user token (a `settings` secret); `owner: oidc_sub` (management keys users on `sub`). `dns: manual` until NetBird's custom-zone API is evaluated. `control_routers`: the management, signal and relay routers, not the dashboard.
- **wireguard** (new, plain WireGuard UI such as wg-easy, after the two): `identity.source: static`, `dns: manual`, the forwarder in the WireGuard container's netns.

## 5. How a provider's traffic reaches Traefik (the edge)

- **Networks.** `portcullis-vpn` (internal, fixed IPAM `${PORTCULLIS_VPN_NET:-172.31.254.0/26}`): Traefik `.2`, `wg` `.3`, provider gateways `.16`–`.62` (the Hub assigns each wired provider one address, written as `ipv4_address` in that instance's override). `wg-egress`: publishes the role UDP ports and carries the built-in resolver's upstream queries. The link role's `portcullis-link` / `portcullis-link-data` networks are as in the multi-server spec; `wg` binds each listener to the address of its own network only.
- **Edge listeners.** One TCP port per wired provider on `wg`'s `portcullis-vpn` address (`9001 + slot`, slots held in `vpn.json`). A connection is accepted only if it arrives on the provider's port **from the provider's assigned gateway address**, starts with a valid PROXY v2 header within 5 s, and the header's source address lies in that provider's ranges and is an address in its current, fresh device map (§6). Anything else is closed and counted (`wg_edge_rejected_total{provider,reason}`). Accepted connections are re-originated to Traefik `vpnsecure` with a new PROXY v2 header carrying the same client address. The built-in people stack hands its TCP 443 connections to the edge in-process under provider `builtin`.
- **Why one edge** (assistant's call): Traefik's `vpnsecure` trusts PROXY protocol from exactly one address (`wg`'s), as before. Traefik can't bind a PROXY sender to the ranges it may claim; the edge can, so one provider can't claim another provider's addresses (a buggy or misconfigured gateway is contained). A *malicious* template is outside this model: a template source is trusted with the host (contract §3 trust model), and one with NET_ADMIN on `portcullis-vpn` could spoof another gateway's address; the doctor shows which wired gateways have NET_ADMIN (§12).
- **`portcullis-vpn-forwarder`** (core-published image, Go, a few hundred lines on go-proxyproto): listens on `:443` in the netns it shares with a VPN client that has a real tunnel interface, and forwards each connection to `$PORTCULLIS_VPN_EDGE` with a PROXY v2 header carrying the peer's tunnel address. It is for apps whose node can't emit PROXY itself (NetBird, plain WireGuard).
- **Primary only.** A wired provider's instance is placed on the primary (multi-server placement refuses a worker), because its gateway joins `portcullis-vpn`.
- **Kubernetes.** `portcullis-vpn` maps to a NetworkPolicy: each edge port accepts ingress only from pods labelled with that provider's instance; the gateway-address check uses the pod CIDR there (Kubernetes §5 pattern), and the per-port policy carries the per-provider binding.

## 6. Identity: device maps

Every provider yields a **device map**: `{address → device {id, name, owner, online, last_seen, expires}}`, where `owner` is a Portcullis username. The Hub builds them, validates them and publishes them in `vpn.json`; group-gate and the edge read them.

### 6.1 `source: hook` (Headscale, NetBird, any app with an API or CLI)

- The Hub runs the identity hook every `refresh` (Docker exec, like every hook; never debounced, never from the settings engine). Stdin `{"version":1,"trigger":"vpn","instance":"<id>","op":"devices","ranges":[...]}`. Stdout (≤ 4 MiB, ≤ 10 000 devices, never stored raw, redacted in op records):
  ```json
  {"version": 1, "gateway": "100.64.0.1",
   "devices": [{"id": "12", "name": "laptop", "address": "100.64.0.7", "owner": "<sub or username>",
                "online": true, "last_seen": "2026-11-12T10:00:00Z", "expires": null}]}
  ```
- **Validation per device:** address an IPv4 inside `ranges` (IPv6 ignored); addresses unique (a duplicate drops every device with it + doctor Problem); `owner` resolves to an enabled person who is in the *VPN users* group: `oidc_sub` through Keycloak (user id → LLDAP username, the federation link keyed on entryUUID), `username` by exact lowercase match. Unresolved owners are dropped (shown on the instance's VPN tab as "not a Portcullis person"). `expires` in the past drops the device. `gateway` (the gateway node's tunnel address, required) is the DNS target (§11) and is never itself a device.
- A hook failure, timeout or invalid document keeps the last good map until it is **stale** (`3 × refresh`, at least 3 min). A stale map is published as stale: the edge refuses its connections and group-gate denies its addresses. Recovery is automatic on the next good run.
- Address reuse: a mesh may reassign a removed node's address to someone else's node within one refresh. The binding then fails (owner ≠ the signed-in person) until the next refresh, so it fails closed, never open. The docs say removing a node takes up to `refresh` to be reflected.

### 6.2 `source: static` (plain WireGuard apps)

The instance's VPN tab lists addresses in the ranges; an admin assigns each to a person and a device name (audited `vpn.static_assigned|unassigned`, MCP `assign_vpn_address`, admin, per-call confirmation). The owner sees them on their Sign-in page (read-only). The map never goes stale, but the device's existence isn't proven (the app owns peers and keys), so the doctor shows an Info: "static mapping: devices are assigned by an admin". A static provider never counts for the lock-out guard (§9).

### 6.3 Built-in

The built-in map is the Hub's own device list (§10); `online`/`last_seen` come from the `wg` service's `wg_data/status.json` (last handshake).

### 6.4 `vpn.json` v2 (Hub → wg, group-gate)

Written atomically to `hub_data/vpn.json`, 0640 group 10006 (group-gate's group also reads it), public data only:

```json
{"version": 2,
 "builtin": {"subnet": "10.213.0.0/22", "server_public_key": "…", "domains": ["…"],
             "peers": [{"ip": "10.213.0.5", "public_key": "…", "device_id": "…"}]},
 "providers": [{"id": "builtin", "ranges": ["10.213.0.0/22"], "edge_port": 0, "gateway_ip": "", "stale": false},
               {"id": "headscale", "label": "Headscale tailnet", "ranges": ["100.64.0.0/10"], "edge_port": 9001,
                "gateway_ip": "172.31.254.16", "refreshed_at": "…", "stale_after": "…", "stale": false}],
 "devices": [{"ip": "100.64.0.7", "provider": "headscale", "user": "alice", "device_id": "headscale:12",
              "name": "laptop", "expires": null}]}
```

Readers fail closed: an unknown version or key, a parse error, overlapping provider ranges, or a missing file while anything needs it denies every VPN request; a provider whose `stale_after` has passed (readers compare with their own clock, so a stopped Hub also ends in deny) denies its own addresses only. The Hub rewrites it on every map change and at least every `refresh` for live providers.

## 7. Traefik: the VPN entrypoint

- Static entrypoint **`vpnsecure`**: `TRAEFIK_ENTRYPOINTS_VPNSECURE_ADDRESS=${PORTCULLIS_VPN_TRAEFIK_IP:-172.31.254.2}:8443`, bound to Traefik's fixed address on `portcullis-vpn`. `PROXYPROTOCOL_TRUSTEDIPS` is `wg`'s fixed IP **only** (gateways are on the same network but never trusted directly). `aliasHeadersStrategy: delete`, the same TLS resolver/domains as `websecure`, and **no `forwardedHeaders.trustedIPs`/`insecure`** (the CLAUDE.md rule extends to it). Always defined, even with the profile off, so labels that name it never break. With no `wg`, nothing connects to it: fail closed.
- **Allowlist (Hub-rendered).** The provider ranges change at runtime, and the Hub can't write under `traefik/`, so there is no static `vpn-only@file`. For every VPN-only instance the override renders a middleware `portcullis-vpnallow-<id>` (`ipallowlist.sourcerange` = the ranges of the providers the instance accepts, §8.3, no `ipstrategy`, so the remote address is the PROXY one; `rejectstatuscode: 403`) and prepends it. The name prefix `portcullis-vpn` is reserved for the Hub (template refusal like `portcullis-public-`). Core routers in `admin`/`server` mode rely on the structural entrypoint and group-gate's host classes (§9). A change in the ranges re-renders the affected overrides (one recreate per VPN-only instance; rare).
- TLS tiers apply per host on both entrypoints unchanged. `mtls` apps work over the VPN as on the internet.

## 8. Per-app "VPN only"

### 8.1 Setting and rendering

- On the instance page → Access, *Reachable from*: `internet` (default) / `vpn`, plus *Through* (§8.3). Stored as `state.yaml` `reach: {<instance>: {mode: "vpn", via: ["*"]}}` (no entry = internet), audited `instance.reach`, Hub API/MCP `set_instance_reach` (admin, per-call confirmation). Switching to `vpn` with no live provider is refused with "wire a VPN first" (`409`).
- **Rendering** (Hub override), for every router of every instance:
  - internet instances: `websecure,vpnsecure` (split DNS sends every Portcullis name to the VPN entry, so normal apps answer there too);
  - VPN-only instances: `vpnsecure` **only**, with `portcullis-vpnallow-<id>` prepended: the app's routers, its `portcullis-oauth2-*` sign-in routers, its MCP routers and its public exceptions (`portcullis-public-<id>`). A provider instance's own `control_routers` are the exception: they always keep `websecure` (otherwise its clients couldn't connect), and setting a provider instance to `vpn` applies to its other routers;
  - a low-priority friendly router `portcullis-vpnonly-<id>` on `websecure` per host → group-gate `/vpn-required` (static 403: "This app is only reachable over a Portcullis VPN. Connect your device and reload." No app content, no sign-in). It covers browsers whose DoH bypasses the VPN's DNS.
- Templates keep writing `entrypoints: websecure`; the override sets the final value, and contract §3 refuses any other entrypoint in a template.
- Exposure drift also compares `entrypoints`, the allowlist ranges and its position.

### 8.2 group-gate (second, identity layer): policy v7

```json
"vpn": {"hosts": {"<hostname>": {"via": ["*"]}}, "server_mode": false, "admin_only": false,
        "public_enrol": true, "devices_file": "vpn.json"}
```

For a host in `vpn.hosts`, on `/` (portcullis-groups) the gate requires, in order:
1. the client address lies in a provider's ranges, that provider is not stale and is accepted by the host's `via`;
2. `vpn.json` has a device with that address under that provider (not expired, owner enabled);
3. the device's owner equals the signed-in `X-Auth-Request-Preferred-Username`.

Otherwise 403 with a reason page ("this device isn't yours; sign in on your own device", "your VPN's device list is out of date; try again in a minute"; the owner's name isn't shown). The client address is the **last** `X-Forwarded-For` entry, which Traefik appends from the PROXY remote address; client-sent copies are discarded on both entrypoints and CI proves it (§13). Requests via a VPN to *internet* apps need no binding. The opened log gains `via: "vpn"`, `provider` and `device`. Unknown keys deny everything, as for every policy key today. **Hub and core upgrade together** (v6 → v7, `vpn.json` v2).

So a VPN-only app has five gates: no `websecure` router; the edge's range + map check; the Traefik allowlist; Portcullis sign-in (unchanged); the device ↔ person binding.

### 8.3 Several VPN apps at once (assistant's call)

- **Union by default.** Every wired, fresh provider is a path to every VPN-only app (`via: ["*"]`). People use whichever VPN they have; the binding is per device whatever the provider.
- **Narrowing per app.** *Through* can restrict an instance to a subset (`via: ["builtin"]`, `["headscale"]`); only narrowing, never wider. Unwiring a provider that an instance names alone makes that instance unreachable (fail closed) and raises `vpn_via_dead` (§12); the Hub's unwire dialog lists such instances first.
- Ranges are disjoint by construction (§4), so an address names exactly one provider.
- Whole-server mode uses the union (core hosts have no `via`).

## 9. Whole-server mode, core surfaces and recovery

Core routers are core compose labels, so their reachability is a **core `.env` setting, owned by the operator on the host**: consistent with "the Hub has no rw under `traefik/`", and the break-glass is on the host anyway. The Hub shows it read-only and passes it into the policy.

- `./portcullis vpn mode apps|admin|server`, which writes `PORTCULLIS_VPN_MODE` and recreates core:
  - `apps` (default): core as today, on `websecure,vpnsecure`.
  - `admin`: Hub, Keycloak admin console, LLDAP, Traefik dashboard, grafana-metrics and `mcp`/`hub-mcp`/`people-mcp` go `vpnsecure`-only.
  - `server`: everything goes `vpnsecure`-only except the **public set**.
- **Public set in `server` mode.** Nothing for ACME (DNS-01 only); the `web` redirect; the built-in people UDP port (if on) and the link UDP port (if on); every wired provider's `control_routers` and its own UDP/STUN ports (manifest `ports`); and with `PORTCULLIS_VPN_PUBLIC_ENROL=true` (default) the enrolment surfaces:
  - `auth.<d>`: Keycloak sign-in pages and `oauth2-callback`, never `keycloak-admin` (also what Headscale/NetBird OIDC enrolment needs);
  - invite redemption on `enroll.<d>`;
  - people.<d> limited to `PathPrefix(/vpn/)` + its static assets (compose router `people-vpn-enrol`); the full `people` router goes VPN-only.

  With `public_enrol=false`, only the UDP ports and provider control routers are public. New built-in devices then come from an existing device or the host CLI (§10); marketplace providers then need their own non-OIDC enrolment (e.g. pre-auth keys), which the docs describe per template.
- **Instances in `server` mode** render as VPN-only whatever their own setting is, except provider `control_routers` and the per-instance opt-in *"Public links stay on the internet"* (only for instances with public exceptions; audited; doctor Warning).
- **Labels:** core routers use `entrypoints: ${PORTCULLIS_EP_CORE:-websecure,vpnsecure}`, `${PORTCULLIS_EP_ADMIN:-…}` and `${PORTCULLIS_EP_ENROL:-…}`; `config apply` derives them from the mode. `tests/test_cli.sh` checks every core router uses one of the three.
- **Second layer:** the policy's `server_mode`/`admin_only` make the gate deny core hosts from non-VPN addresses too (map.conf gains a `class` per core host: `admin` / `enrol` / `core`). This is also what stands in for the allowlist on core routers (§7).
- **Recovery path (never depends on any VPN):**
  - **Break-glass:** `./portcullis vpn mode apps` on the host works with `wg`, every provider and the Hub down.
  - **Lock-out guard:** `vpn mode admin|server` refuses unless a device owned by an `lldap_admin` member was online in the last 10 minutes on a built-in or `source: hook` provider (handshake / `last_seen`); `--force` overrides it.
  - **Provider control stays public**, so marketplace clients can always reconnect; stale maps recover on their own.
  - **Backup provider:** in `admin|server` mode with only one wired provider, the doctor raises `vpn_single_provider` (Warning) recommending the built-in as a second path; `./portcullis vpn add-device` on the host can always mint a built-in device for an admin.

## 10. Built-in devices: enrolment, revocation, keys

- **Who:** the Hub setting *VPN users* (a group, default every person; it gates every provider's device map, §6) and *Devices per person* (default 10, built-in only). A person outside the group sees no VPN section, their built-in devices are revoked when they leave it, and their marketplace devices drop out of the maps.
- **Add (Sign-in page, people.<d>/vpn/):** the person names the device, passes a **fresh sign-in** (the same max-age step-up the Sign-in page uses for adding a security key; default 5 min), and the browser generates an x25519 key pair (`@noble/curves`, vendored). Only the **public key** is POSTed. The Hub allocates the next free address (a removed address is quarantined for 7 days) and returns the server's public key, endpoint `<d>:<port>` (the apex, already in the DNS plan), `AllowedIPs = 10.213.0.1/32` (split tunnel), `DNS = 10.213.0.1` and the MTU. The page assembles the `.conf` and a QR **in the browser**, shows them once, and drops the private key from memory. Expiry defaults to 1 year (Settings: 30 d–never). Renewal re-keys.
- **List/rename/remove:** the Sign-in page shows the person's devices from **every** provider (name, provider label, address, last seen, expiry); built-in ones can be renamed/removed there, marketplace ones link to their app. People → person → *VPN devices* (admins and the delegated `manage_signin` permission; remove only, built-in only). Disabling or deleting a person removes their built-in devices. Every change rewrites `vpn.json` atomically and `wg` drops the peer at once. Audit: `vpn.device_added|renamed|removed|expired` (never key material).
- **Admins can't create a config for someone else in the UI.** The host operator can: `./portcullis vpn add-device <user> <name>` generates the key pair in the `wg` container and prints the config + terminal QR to stdout only.
- **MCP:** `list_vpn_devices` (all providers), `remove_vpn_device` (built-in, admin, per-call confirmation), `set_vpn_provider`, `assign_vpn_address`. Nothing creates configs, so no key lands in a transcript.

## 11. DNS

- **Built-in:** `wg` runs a forwarding resolver at `10.213.0.1:53` (miekg/dns). WireGuard's `DNS =` is system-wide on most clients, so it forwards everything (upstream `${PORTCULLIS_VPN_DNS_UPSTREAM:-1.1.1.1,9.9.9.9}`). For names under `<d>` and the enrolled domains it **rewrites only answers that point at this server**: A → `10.213.0.1`, AAAA → NODATA. Foreign records the DNS plan reports pass through. It never sets AD on a rewritten answer and strips its RRSIGs.
- **Marketplace providers, `dns.hook`:** after every map refresh that changes the gateway address, and on any change of Portcullis hostnames, the Hub runs the hook with `{"op":"dns","records":[{"name":"<host>","type":"A","value":"<gateway>"}]}`: one record per core and instance host the DNS plan serves from this server (explicit names, no wildcard). The template applies them its own way (Headscale `extra_records_path`). A failed DNS hook is a doctor Problem for that provider (`vpn_dns_failed`), not a map failure: names then resolve publicly and VPN-only apps show `/vpn-required`.
- **`dns: manual`:** the provider page shows the records to configure by hand; the doctor Info `vpn_dns_manual` stays until the admin acknowledges it.
- **DNS hardening interplay:** nothing new is published; CAA/DNSSEC untouched. A client that validates DNSSEC locally fails on rewritten built-in names; the docs give the per-OS fix. Browser DoH bypasses tunnel resolvers; `/vpn-required` explains.

## 12. Doctor and status

- **Doctor (Hub):**
  - `vpn_down`: VPN-only hosts or mode ≠ apps while `wg` (edge) is unhealthy. Problem; steps: `./portcullis up`, logs.
  - `vpn_provider_stale`: a wired provider's map is stale, or its gateway container is down. Problem; shows the hook's last error (redacted).
  - `vpn_provider_invalid`: duplicate addresses, devices outside ranges, owners that don't resolve. Problem for duplicates, Info otherwise.
  - `vpn_range_overlap`: a provider range overlaps Local networks (Warning: also reaches `lan_only` ports) or a Docker network (Problem; the provider can't be wired).
  - `vpn_via_dead`: an instance's *Through* names only unwired or stale providers. Problem.
  - `vpn_dns_failed` (Problem) / `vpn_dns_manual` (Info).
  - `vpn_gateway_privileged`: a wired gateway service (or a service sharing its netns) has NET_ADMIN, `privileged` or host devices. Info, explaining §5's trust note.
  - `vpn_static_mapping`: a `source: static` provider is wired. Info.
  - `vpn_single_provider`: mode `admin|server` with one provider. Warning.
  - `vpn_public_links`: a "public links stay on the internet" opt-in. Warning.
  - `vpn_no_admin_device`: mode `admin|server` and no admin device seen in 30 days on any non-static provider. Problem.
  - `vpn_device_stale` (no handshake in 90 days, built-in; offers remove) and `vpn_expiring` (within 14 days, to the owner). Info.

  The Hub can't probe UDP reachability from outside, and says so.
- **`./portcullis status`:** `wg` health per role (edge, people, link), mode, per provider: label, ranges, devices / online, map age; built-in port and subnet; link peers (multi-server block). **Subcommands:** `vpn init|mode|builtin|add-device|devices|revoke`, `link init` (multi-server). Monitoring: alerts when `wg` is down while mode ≠ apps, and `PortcullisVPNProviderStale`.

## 13. CI strategy

- **wg service (Go, core):** `vpn.json` v2 parser (fail closed on version/key/overlap/missing), stale handling by clock, PROXY v2 framing, the edge's accept rules (wrong port, wrong gateway IP, address outside ranges, address not in map, slow header), the DNS rewrite table, peer removal on reload; role isolation (people stack can't dial link addresses, link stack has no listeners, one key in both configs refused).
- **group-gate:** v7 parser (unknown key → deny), the binding decisions per provider (outside ranges, stale provider, `via` mismatch, unknown device, expired, other owner, disabled owner), the last-XFF rule, core-host classes per mode.
- **Hub (Go):** `ValidateVPN` table tests mirroring `validate.py` (each refusal of §4); hook output validation (owners via a fake Keycloak, duplicates, size caps, timeouts → stale); override goldens for entrypoints/allowlist per reach × mode × via (incl. public, oauth2, MCP, friendly and control routers); drift; address allocation + quarantine; wiring guards (overlaps, primary-only); API/MCP/audit; doctor checks. A CI-only fixture template in `testdata` with `source: static`.
- **Templates repo:** schema + `validate.py` for the `vpn:` block (and the `vpn` hook trigger); `tests/apps/headscale.sh` gains the gateway and the identity hook against a real Headscale (its output validated against the v1 document).
- **e2e `e2e-vpn` (core, like e2e-folders):** the whole stack with profile `wg`, plus CI-only clients without privileges: `tests/e2e/vpn-client` (wireguard-go netstack) for the built-in, and a userspace `tailscaled` registered with the **headscale template** (pinned templates ref; node registered through Keycloak OIDC by Playwright, so its owner is a real `oidc_sub`; a second node from a pre-auth key of a non-OIDC Headscale user proves "not a Portcullis person" is denied). Asserts, for both providers:
  - a VPN-only app on `websecure` gets only `/vpn-required`;
  - via the tunnel: sign-in still demanded; with sign-in it opens; another person's device → 403; `via: ["builtin"]` refuses the tailnet device;
  - built-in device revoked → handshake fails within the reload; Headscale node deleted → denied within `refresh`;
  - **`docker stop wg` → VPN-only apps unreachable everywhere**; stopping the headscale gateway → only tailnet devices fail; a broken identity hook → tailnet devices denied once stale, built-in unaffected;
  - spoofed `X-Forwarded-For`/`X-Real-Ip` on both entrypoints ignored; a PROXY header sent straight to `vpnsecure` from a gateway is not honoured; a gateway claiming a built-in address is refused by the edge;
  - mode `server`: only the public set (incl. headscale's control router) answers on `websecure`, and `keycloak-admin` doesn't; break-glass `vpn mode apps` works with `wg` stopped;
  - DNS answers through both tunnels (built-in rewrite, Headscale extra records).

  It runs on the Docker runner now and joins the rootless/Kubernetes jobs when those land (built-in and headscale's userspace gateway both need no privileges). The multi-server `e2e-servers` job exercises the link role of the same image.
- `test_cli.sh`: entrypoint variables on every core router, no `forwardedHeaders` trust on `vpnsecure`, the trusted PROXY IP is exactly `wg`'s address.

## 14. Contract and docs changes

- **Contract:**
  - §3: templates must not set entrypoints other than `websecure`, mention `portcullis-vpn`, or use names starting `portcullis-vpn`; new **§3.3 VPN providers: the `vpn:` block** (§4 of this spec, with the refusal texts); §13.8: the `vpn` hook trigger (exclusive, like `ai`), its stdin/stdout documents (`op: devices|dns`).
  - §4: policy v7 `vpn` section, `vpn.json` v2, the binding rule, staleness, fail-closed rules.
  - §5: `vpnsecure`, `portcullis-vpnallow-<id>`, rendering per reach/mode/via, control routers, the friendly router, drift, the gateway network attachment in the override.
  - §5.1: the people `/vpn/` routes and the all-providers device list.
  - §11: instance `reach` (`mode`, `via`), provider wiring state, primary-only placement of providers.
  - §13.15/§14.5/§14.7: the new checks; Local networks never count for VPN-only access, overlap rules.
  - §15: the MCP tools.
  - New **§16 VPN and the `wg` service**: roles, separation rules, networks, edge ports and accept rules, files, CLI, the forwarder image. The multi-server §17 points at it for the link role.
- **Docs site:** new `operations/vpn.md` (built-in setup, wiring a marketplace VPN, coexistence and *Through*, modes, enrolment, revocation delay per provider, DNS caveats, DoH, break-glass); per-template pages for headscale/netbird (gateway, identity hook, what goes public in server mode); `hardening.md` (the `wg` row: no caps, roles, PROXY trust, gateway trust note); `auth-policies.md` ("a VPN never replaces sign-in"); the Hub page; the person-facing Sign-in page guide (client apps per OS); backups (`secrets/wg`; `wg_data` is status only); the manifest reference (`vpn:`).
- **Core cleanup:** remove `headscale/config.yaml` and the optional headscale/headplane clients in `keycloak.sh` (the template owns them).

## 15. Task outline (for the plan)

1. Core: `wg` service (shared WireGuard device/netstack package, roles edge + people; link lands with the multi-server plan on the same binary), PROXY v2, edge accept rules, resolver, UAPI reload, status, metrics, Dockerfile, profile `wg`, networks, `secrets/wg`, `vpn init`, `vpn builtin`; `portcullis-vpn-forwarder` image + release.
2. Core: `vpnsecure`, core router entrypoint variables, `vpn mode` + lock-out guard, `add-device`/`devices`/`revoke`, status, backup, alerts, CLI tests.
3. group-gate: policy v7, `vpn.json` v2 reader (staleness by clock), binding per provider, `via`, core-host classes, `/vpn-required`, opened-log fields.
4. Hub: `ValidateVPN` + `vpn` hook trigger; provider wiring (slots, gateway addresses, overlap guards, primary-only); identity hook runner + map validation (Keycloak sub → person) + static assignments; `vpn.json` v2 writer; DNS hook runner; state (`reach`, devices, settings); address allocator; override rendering (entrypoints, allowlist, control routers, gateway network) + drift; API/audit/MCP.
5. Hub UI: instance Access → Reachable from + Through; instance VPN tab (wire/unwire, map, static assignments, DNS records); Settings → VPN (users group, devices per person, expiry, providers overview; mode read-only); Sign-in page device flow + all-providers list; People → VPN devices.
6. Doctor checks.
7. Templates repo: schema/`validate.py` for `vpn:` and the trigger; headscale gateway + hooks (CI reference); then netbird; then a plain WireGuard template.
8. e2e `e2e-vpn` (built-in + headscale) + CI clients.
9. Contract + docs + core cleanup; resync the Hub's docs copies.
10. Merge to main in the usual order (docs → hub → templates → core; core + Hub together for policy v7 / `vpn.json` v2), deploy on the test server, `ACME_STAGING=true`, Mac/iPhone client check by the user with the built-in and with Headscale.

**Parked follow-ups:**
- non-HTTP `lan_only` ports over the VPN (the edge can forward chosen TCP ports per instance, e.g. Samba);
- `proxy_protocol: none` gateways (routed source addresses);
- NetBird DNS through its API; NetBird netstack-mode gateway for Kubernetes;
- "Local networks also count" (needs a source-address fidelity probe);
- IPv6 in tunnels;
- shared/group devices;
- per-peer preshared keys for the built-in (post-quantum hardening);
- per-domain client split DNS;
- device posture (could come from a provider's map);
- push-based maps (webhooks) instead of polling.

## 16. Open questions (each has a default; work proceeds on the default)

1. **Default built-in subnet `10.213.0.0/22`** may collide with someone's LAN. *Default:* keep it; `vpn init` refuses an overlap with Local networks, Docker networks, link and wired providers, and suggests a free /22.
2. **`public_enrol` default in `server` mode.** *Default:* on. Strict sites turn it off and bootstrap with `vpn add-device`.
3. **Binding for internet apps reached over a VPN.** *Default:* not required.
4. **Userspace throughput** (built-in and link). *Default:* accept it. Under 200 Mbit/s on the test server, revisit with a kernel/TUN mode behind an opt-in that adds NET_ADMIN (doctor Info). A marketplace provider with a kernel datapath is the other answer for people traffic.
5. **`tailscale serve --tcp … --proxy-protocol 2` in userspace mode** is assumed to carry the tailnet source address. *Default:* verify first in the plan; if it doesn't, the headscale gateway uses a TUN-mode tailscaled + `portcullis-vpn-forwarder` (NET_ADMIN, rootless `degraded`, Kubernetes refused) like NetBird.
6. **Refresh 60 s** as the revocation delay for marketplace devices. *Default:* 60 s, admin-tunable per provider (15 s–10 m); the binding to the signed-in person bounds the damage meanwhile.
7. **Headscale MagicDNS and AAAA** for names in `extra_records`. *Default:* A records only, checked on the test server. A client that still reaches a public AAAA lands on `/vpn-required` (fail closed); IPv6 matching joins the parked IPv6 item.
