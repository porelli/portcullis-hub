# VPN-only access, per app or for the whole server (design)

Status: written by the assistant for the roadmap item "VPN only access per app, or for the whole server" (the user's words). No interruptions were wanted, so the assistant made every decision. Each one is the **assistant's call** unless it says otherwise. Open questions are in §13, each with a default. Order on the roadmap: after DNS hardening (`2026-11-13-dns-hardening-design.md`), rootless Podman and Kubernetes. This design has to work on all three runtimes.

## 1. Where things stand (2026-11-12)

- **Traefik** (core `docker-compose.yml`) has `web` (:80, redirects to https), `websecure` (:443, `asDefault`, ACME **DNS-01 only**: nothing on :80 has to stay public), plus the internal `traefik` (:8080 ping) and `metrics` (:8082). `websecure` never trusts forwarded headers, so client copies of `X-Forwarded-*` / `X-Forwarded-Tls-Client-Cert*` are deleted (CLAUDE.md rule). There is no `ipAllowList` anywhere and no notion of where a client connects from.
- **Routers.** Core routers (portal, auth/keycloak, keycloak-admin, oauth2-callback, hub, people, enroll-invite, traefik dashboard, lldap, mcp, grafana-metrics) are compose labels with `entrypoints: websecure`. The Hub renders instance routers through its override (`internal/hub/override.go`, `public.go`): the TLS tier per host (contract §5), public routers `portcullis-public-<id>` (public guard, no sign-in), extra-domain sign-in routers `portcullis-oauth2-<id>_<r>`, the MCP routers. The Hub has no rw mount under `traefik/`.
- **group-gate** reads `group-gate-policy.json` (**v6**, `POLICY_VERSION = 6`) from `hub_data` on every request, fails closed on unknown keys/versions, and gets core hosts from `group-gate-map.conf`.
- **Local networks** (Hub Settings, contract §14.7) are CIDRs for `lan_only` ports and file sharing (defaults include `100.64.0.0/10`, "the tailnet"). The doctor's `lan_only_exposed` judges port binds. §14.7 records a residual: with Docker's userland proxy on, connections to published ports can arrive from the bridge gateway. So **a source address seen through a published port is not trustworthy enough to grant access.**
- **VPN pieces that exist:** templates `headscale` (Headscale + Headplane, native OIDC, default host `vpn.<d>`) and `netbird` (management/signal/relay, host networking for TURN). Both are apps that give people a mesh between their own devices. Neither is wired into Portcullis access. Core still has leftovers from the initial release: `headscale/config.yaml` and the optional `headscale`/`headplane` Keycloak clients in `scripts/lib/keycloak.sh` (the template now owns those clients).

## 2. Goals, non-goals, anti-goals

**Goals**
1. **Per app:** an instance can be set to *Reachable from: the internet (default) / VPN only*. A VPN-only instance answers only through the Portcullis VPN, after the normal Portcullis sign-in, and only from a device that belongs to the person who signed in.
2. **Whole server:** one switch makes everything VPN-only except the short list that has to stay public (§6).
3. **Devices:** people add and remove their own VPN devices on the Sign-in page (people.<d>). Admins see and revoke them on People. Private keys never reach the server.
4. **Split DNS:** on the VPN, Portcullis names resolve to the tunnel and the device's other names resolve as before.
5. The doctor, status, CI and docs cover all of it.

**Non-goals (v1)**
- A general-purpose VPN: no LAN access, no exit node, no site-to-site, no mesh between devices (the headscale/netbird templates still do that). Peers reach exactly one thing, Traefik's VPN entrypoint.
- Non-HTTP ports over the VPN (e.g. Samba/Time Machine from outside). This is parked (§12) and the design keeps room for it.
- IPv6 inside the tunnel (it carries IPv4; AAAA for Portcullis names is answered NODATA on the VPN, §8).
- Treating the LAN (Local networks) as equal to the VPN. The source-address residual in §1 is the reason. Parked (§12).
- Shared devices (a family tablet that several people use). Parked.

**Anti-goals (never)**
- **Never bypass sign-in.** The VPN is an extra condition, never a credential. A VPN-only app still runs `portcullis-auth` + `portcullis-groups` with its usual factors, groups and path groups. Being on the VPN never skips or weakens a factor, never counts as `mtls`/`webauthn`, and never makes a step-up silent.
- **Never expose anything wider.** Every switch here only narrows reachability. No admin surface (Hub, Keycloak admin, LLDAP, Traefik dashboard, metrics) ever gains a route because the VPN exists. The VPN never opens a public path that wasn't public.
- **Fail closed.** If the VPN service is down, its config is missing, `vpn.json` can't be parsed, or the policy's `vpn` section is malformed, then VPN-only hosts are **unreachable** and never fall back to the internet. The enforcement is structural: a VPN-only router doesn't exist on `websecure` at all.
- Never store a client private key, and never let one reach the Hub, logs, audit or an MCP transcript.

## 3. The VPN choice: a core-managed, userspace WireGuard service (assistant's call)

| Option | For | Against |
|---|---|---|
| **A. Core `vpn` service: wireguard-go + gVisor netstack (userspace)** | One UDP port. No control plane, no relays. Stock WireGuard apps on every OS (config file / QR). The tunnel source IP *is* the device identity (WireGuard's cryptokey routing drops inbound packets whose source isn't the peer's AllowedIPs), and Portcullis assigns it. **No NET_ADMIN, no `/dev/net/tun`, no kernel module**, so it runs read-only, `cap_drop: ALL`, rootless Podman and Kubernetes unchanged. The netstack listens only on what we bind, so peers physically can't reach anything else | Userspace throughput is lower than kernel WireGuard (fine for a home/small-office gateway). We maintain about 1–2 kLoC of Go around mature libraries |
| B. Kernel WireGuard / wireguard-go with a TUN | Fastest | NET_ADMIN + `/dev/net/tun` (or the host module and host-side config). Routing/iptables in a netns gives peers an IP stack that can reach more than Traefik. Rootless needs extra setup |
| C. Headscale (+ tailscaled on the server) | OIDC enrolment through Keycloak, ACLs, MagicDNS split DNS, polished clients | Control plane + DERP/STUN (UDP 3478). The server node needs tailscaled with a TUN (NET_ADMIN) or userspace mode, which delivers inbound connections from loopback and so **loses the source address** needed for binding. Identity has to be cross-referenced through Headscale's API (node → user). Its upgrade cadence (one minor at a time) becomes core's |
| D. NetBird | Similar to C, with a dashboard | Most components (management, signal, relay, TURN with host networking). Same identity indirection |

**Choice: A.** The server is publicly reachable already (it serves :443), so NAT traversal, relays and coordination buy nothing. The smallest trusted base and the cleanest identity binding win. Libraries (prefer-libraries rule): `golang.zx2c4.com/wireguard` (device + `tun/netstack`, whose `Net` gives `ListenTCP`/`ListenUDP`/`DialContext`), `github.com/pires/go-proxyproto`, `github.com/miekg/dns`, and `@noble/curves` (x25519) in the browser. The headscale/netbird templates stay as apps and are unrelated to Portcullis access.

**Service shape.** New core service `vpn` (`vpn/` in the core repo, Go, built locally like group-gate). It sits in compose profile `vpn`, is off by default, and runs as uid 10006, read_only, no capabilities, `no-new-privileges`. Networks:
- `vpn-egress`: publishes `${PORTCULLIS_VPN_PORT:-51820}/udp` and is used for upstream DNS forwarding.
- `portcullis-vpn` (internal, fixed IPAM `${PORTCULLIS_VPN_NET:-172.31.254.0/28}`): Traefik `.2`, vpn `.3`, nothing else.

Inside the netstack the server's tunnel address is `.1` of `${PORTCULLIS_VPN_SUBNET:-10.213.0.0/22}` (≈1000 devices, MTU 1280). The service listens there on **TCP 443** (proxied), **TCP 80** (answers `308` to https itself), and **UDP/TCP 53** (§8). Every accepted TCP 443 connection is dialled to Traefik's VPN entrypoint with a **PROXY protocol v2** header that carries the peer's tunnel address. The outer UDP source address doesn't matter (WireGuard authenticates by key), so rootless port forwarding that rewrites it is harmless.

**Keys.** The server key is `secrets/vpn/server.key` (`./portcullis vpn init`, 0640, group 10006). It's never in `hub_data` and is backed up only inside the restic-encrypted snapshot, like every core secret. Peers come from `hub_data/vpn.json` (public keys only, §7). The service reloads it on change through wireguard-go's UAPI, so a removed peer stops working at once. It writes `vpn_data/status.json` (per peer: last handshake, rx/tx; group 10001, read by the Hub) and Prometheus metrics on an internal port.

## 4. Traefik: a dedicated VPN entrypoint

- New static entrypoint **`vpnsecure`**: `TRAEFIK_ENTRYPOINTS_VPNSECURE_ADDRESS=${PORTCULLIS_VPN_TRAEFIK_IP:-172.31.254.2}:8443` is bound to Traefik's fixed address on `portcullis-vpn`, so no app network can reach it. `PROXYPROTOCOL_TRUSTEDIPS` is the vpn service's fixed IP **only**. Its `aliasHeadersStrategy` is `delete`, the same TLS resolver/domains as `websecure`, and **no `forwardedHeaders.trustedIPs`/`insecure`** (the CLAUDE.md rule extends to it). The entrypoint is always defined, even with the profile off, so labels that name it never break. With no vpn service, nothing connects to it: fail closed.
- Middleware **`vpn-only@file`** (`traefik/dynamic/middlewares.yml`): `ipAllowList.sourceRange` = the VPN subnet (Traefik's file-provider `env` template), no `ipStrategy` (so the remote address is the one PROXY protocol supplies), `rejectStatusCode: 403`.
- TLS tiers (§5) apply per host on both entrypoints unchanged. `mtls` apps work over the VPN as they do on the internet.

## 5. Per-app "VPN only"

**Setting.** On the instance page → Access, *Reachable from*: `internet` (default) / `vpn`. It's stored as `state.yaml` `reach: {<instance>: "vpn"}` (no entry = internet), audited `instance.reach`, and changed through the Hub API/MCP (`set_instance_reach`, admin, per-call confirmation like other exposure changes). Switching to `vpn` while the VPN profile is off is refused with "turn on the VPN first" (`409`).

**Rendering** (Hub override). Every router of every instance gets `entrypoints`:
- internet instances: `websecure,vpnsecure`. On the VPN, split DNS sends every Portcullis name to the tunnel, so normal apps must answer there too.
- VPN-only instances: `vpnsecure` **only**, with `vpn-only@file` prepended to the middlewares. This applies to the app's routers, its `portcullis-oauth2-*` sign-in routers and its MCP routers. **Public exceptions** (`portcullis-public-<id>`) of a VPN-only instance also become `vpnsecure`-only. Being reachable from the internet is the thing the admin turned off.
- A low-priority friendly router `portcullis-vpnonly-<id>` on `websecure` for each host of a VPN-only instance → group-gate `/vpn-required` (a static 403 page: "This app is only reachable over the Portcullis VPN. Connect your device and reload." No app content, no sign-in). This covers browsers whose DoH bypasses the VPN's DNS.
- Templates keep writing `entrypoints: websecure`. The override sets the final value, and contract §3 says templates must not name any other entrypoint (rejected at load).
- Exposure drift (§5 "Exposure drift") also compares `entrypoints` and the `vpn-only@file` position.

**group-gate (second, identity layer).** Policy **v7** adds:
```json
"vpn": {"subnet": "10.213.0.0/22", "hosts": ["<hostname>", "..."], "server_mode": false,
        "admin_only": false, "public_enrol": true, "peers_file": "vpn.json"}
```
For a host in `vpn.hosts`, on `/` (portcullis-groups) the gate requires, in order:
1. the client address is in `subnet`;
2. `vpn.json` (version 1, re-read on mtime change) has a live peer with that address (not expired, owner enabled);
3. the peer's owner equals the signed-in `X-Auth-Request-Preferred-Username`.

Otherwise it returns 403 with a reason page ("this device isn't yours; sign in on your own device"; the owner's name isn't shown). The client address is the **last** `X-Forwarded-For` entry, which Traefik appends from the (PROXY-protocol) remote address. On these entrypoints client-sent copies are discarded; CI proves it with spoofed headers on both entrypoints (§10). Requests via the VPN to *internet* apps need no binding (the VPN is just a path there). The opened log gains `via: "vpn"` + `device` for VPN requests. Fail closed: a missing or unparseable `vpn.json` while `vpn.hosts` is non-empty denies those hosts. Unknown keys deny everything, as for every policy key today. **Hub and core upgrade together** (v6 → v7, as before).

So a VPN-only app has four gates: no `websecure` router; the allowlist; Portcullis sign-in (unchanged); the device ↔ person binding.

## 6. Whole-server mode and core surfaces

Core routers are core compose labels, so their reachability is a **core `.env` setting, owned by the operator on the host** (assistant's call). It's consistent with "the Hub has no rw under `traefik/`", and the break-glass is on the host anyway. The Hub shows it read-only and passes it into the policy.

- `./portcullis vpn mode apps|admin|server`, which writes `PORTCULLIS_VPN_MODE` and recreates core:
  - `apps` (default): core as today, on `websecure,vpnsecure`.
  - `admin`: Hub, Keycloak admin console, LLDAP, Traefik dashboard, grafana-metrics and `mcp`/`hub-mcp`/`people-mcp` go `vpnsecure`-only.
  - `server`: everything goes `vpnsecure`-only except the **public set**.
- **Public set in `server` mode.** Nothing is needed for ACME (DNS-01 only, both Traefik and the domains service); the `web` redirect stays. The WireGuard UDP port. With `PORTCULLIS_VPN_PUBLIC_ENROL=true` (default), also the enrolment surfaces:
  - `auth.<d>`: Keycloak sign-in pages and `oauth2-callback`, never `keycloak-admin`.
  - invite redemption on `enroll.<d>`.
  - people.<d> limited to `PathPrefix(/vpn/)` + its static assets. This is a new compose router `people-vpn-enrol`; the full `people` router goes VPN-only.

  With `public_enrol=false`, nothing but the UDP port is public. New devices then come from an existing device or the host CLI (§7).
- **Instances in `server` mode** render as VPN-only whatever their own setting is. The one exception is a per-instance opt-in *"Public links stay on the internet"* (only for instances with public exceptions; audited; a doctor Warning).
- **Labels:** core routers use `entrypoints: ${PORTCULLIS_EP_CORE:-websecure,vpnsecure}`, `${PORTCULLIS_EP_ADMIN:-…}` and `${PORTCULLIS_EP_ENROL:-…}`. `config apply` derives these from the mode. `vpn-only@file` is prepended when the value is `vpnsecure`. `tests/test_cli.sh` checks every core router uses one of the three variables.
- **Second layer:** the policy's `server_mode`/`admin_only` make the gate deny core hosts from non-VPN addresses as well (map.conf gains a `class` per core host: `admin` / `enrol` / `core`).
- **Lock-out guard:** `vpn mode admin|server` refuses unless a device owned by an `lldap_admin` member has had a handshake in the last 10 minutes (read from `status.json`); `--force` overrides it. `vpn mode apps` on the host is the break-glass and works with the VPN down.

## 7. Devices: enrolment, revocation, keys

- **Who:** the Hub setting *VPN users* (a group, default every person) and *Devices per person* (default 10). A person outside the group sees no VPN section, and their existing devices are revoked when they leave it.
- **Add (Sign-in page, people.<d>/vpn/):** the person names the device, passes a **fresh sign-in** (the same max-age step-up the Sign-in page uses for adding a security key; default 5 min), and the browser generates an x25519 key pair (`@noble/curves`, vendored). Only the **public key** is POSTed. The Hub allocates the next free address (a removed address is quarantined for 7 days, never reused sooner) and returns the server's public key, endpoint `<d>:<port>` (covered by the DNS plan's apex record; no new name), `AllowedIPs = 10.213.0.1/32` (split tunnel: only Portcullis traffic enters the tunnel), `DNS = 10.213.0.1` and the MTU. The page assembles the `.conf` and a QR **in the browser**, shows them once, and drops the private key from memory. Expiry defaults to 1 year (Settings: 30 d–never). Renewal re-keys rather than extending.
- **List/rename/remove:** on the Sign-in page (own devices: name, address, last handshake, expiry) and People → person → *VPN devices* (admins and the delegated `manage_signin` permission; remove only). Disabling or deleting a person removes their devices. Every change rewrites `vpn.json` atomically, and the service drops the peer at once. Audit: `vpn.device_added|renamed|removed|expired` (never key material).
- **Admins can't create a config for someone else in the UI** (the private key would pass through the admin's browser). The host operator can: `./portcullis vpn add-device <user> <name>` generates the key pair in the vpn container and prints the config + terminal QR to stdout only (never to disk). This is the bootstrap for the first device under `public_enrol=false`.
- **MCP:** `list_vpn_devices`, `remove_vpn_device` (admin, per-call confirmation). Nothing creates configs, so no key ever lands in a transcript.
- `vpn.json` (Hub → vpn, gate), version 1: `{subnet, server_public_key, domains: [...], peers: [{ip, public_key, user, device_id, name, expires}]}` with public data only, written 0640 group 10006.

## 8. DNS

- **Split DNS on the tunnel:** the vpn service runs a forwarding resolver at `10.213.0.1:53` (miekg/dns). WireGuard's `DNS =` is system-wide on most clients, so it forwards everything (upstream `${PORTCULLIS_VPN_DNS_UPSTREAM:-1.1.1.1,9.9.9.9}`, the same resolvers the DNS plan checks through). For names under `<d>` and the enrolled domains (`vpn.json` `domains`), it **rewrites only answers that point at this server**: A records → `10.213.0.1`, AAAA records → NODATA (IPv4 tunnel). The server's addresses are the DNS plan's wanted A/AAAA. Foreign records the DNS plan reports (e.g. `mail.<d>` hosted elsewhere) pass through unchanged. It never sets AD on a rewritten answer and strips its RRSIGs.
- **DNS hardening interplay:** nothing new is published (the endpoint is the apex). CAA/DNSSEC are untouched. A client that validates DNSSEC locally (rare; e.g. systemd-resolved `DNSSEC=yes`) fails on rewritten names; the docs give the per-OS fix. Browser DoH bypasses the tunnel resolver; the friendly `/vpn-required` page (§5) tells the person what happened.
- Parked: per-domain split DNS on clients that support it (would avoid sending all DNS through the server).

## 9. Doctor and status

- **Doctor (Hub):**
  - `vpn_down`: VPN-only hosts or mode ≠ apps while the service is unhealthy. Problem; steps: `./portcullis up`, logs.
  - `vpn_subnet_overlap`: the subnet overlaps Local networks, a Docker network, or the tailnet range. Problem; explain-only (`.env`).
  - `vpn_public_links`: a "public links stay on the internet" opt-in. Warning.
  - `vpn_no_admin_device`: mode `admin|server` and no admin device handshake in 30 days. Problem.
  - `vpn_device_stale`: no handshake in 90 days. Info; offers remove.
  - `vpn_expiring`: expires within 14 days. Info, to the owner.

  The Hub can't probe UDP reachability from outside, and says so.
- **`./portcullis status`:** service health, mode, peers (total / handshake < 3 min), port and subnet. **`vpn` subcommands:** `init`, `mode`, `add-device`, `devices`, `revoke`. Monitoring: alert when the service is down while mode ≠ apps.

## 10. CI strategy

- **vpn service (Go, core):** unit tests for the `vpn.json` parser (fail closed), PROXY v2 framing, the DNS rewrite table (server address → tunnel, foreign → pass, AAAA → NODATA, no AD), and the reload removing peers.
- **group-gate:** a v7 parser (unknown key → deny), the binding decisions (outside subnet, unknown peer, expired, other owner, disabled owner), the last-XFF rule, and core-host classes per mode.
- **Hub (Go):** override goldens for entrypoints/middlewares per reach × mode (incl. public, oauth2, MCP and friendly routers), drift on entrypoints, address allocation + quarantine, API/MCP/audit, doctor checks.
- **e2e `e2e-vpn` (core, like e2e-folders):** the whole stack with profile `vpn`, plus a CI-only client `tests/e2e/vpn-client` (wireguard-go netstack as a client, no privileges). Asserts:
  - a VPN-only app on `websecure` gets only `/vpn-required`;
  - via the tunnel: sign-in still demanded; with sign-in it opens; another person's device → 403;
  - revoked device → handshake fails within the reload;
  - **`docker stop vpn` → VPN-only app unreachable everywhere** (fail closed);
  - spoofed `X-Forwarded-For`/`X-Real-Ip` on both entrypoints is ignored;
  - a PROXY header from an untrusted container is not honoured;
  - mode `server`: only the public set answers on `websecure`, and `keycloak-admin` doesn't;
  - DNS answers through the tunnel.

  It runs on the Docker runner now and joins the rootless/Kubernetes jobs when those land.
- `test_cli.sh`: entrypoint variables on every core router, no `forwardedHeaders` trust on `vpnsecure`, the trusted PROXY IP is exactly the vpn address.

## 11. Contract and docs changes

- **Contract:**
  - §3: templates must not set entrypoints other than `websecure`.
  - §4: policy v7 `vpn` section, `vpn.json` v1, the binding rule, fail-closed rules.
  - §5: the `vpnsecure` entrypoint, `vpn-only@file`, rendering per reach/mode, the friendly router, drift.
  - §5.1: the people `/vpn/` routes.
  - §11: instance `reach`.
  - §14.5/§14.7: the new checks; Local networks doesn't include the VPN subnet and the VPN never counts as LAN.
  - §15: the MCP tools.
  - New **§16 VPN**: service, networks, files, CLI.
- **Docs site:**
  - new `operations/vpn.md` (setup, modes, enrolment, revocation, DNS caveats, DoH, break-glass);
  - `hardening.md` (the vpn row: no caps, PROXY trust);
  - `auth-policies.md` ("VPN never replaces sign-in");
  - the Hub page;
  - the person-facing Sign-in page guide (client apps per OS);
  - backups (`secrets/vpn`, `vpn_data` is status only).
- **Core cleanup:** remove `headscale/config.yaml` and the optional headscale/headplane clients in `keycloak.sh`. The template owns them (§1).

## 12. Task outline (for the plan)

1. Core: `vpn` service (wireguard-go netstack, PROXY v2, resolver, UAPI reload, status, metrics), Dockerfile, profile, networks, `secrets/vpn`, `vpn init`.
2. Core: `vpnsecure` entrypoint, `vpn-only@file`, core router entrypoint variables, `vpn mode` + lock-out guard, `add-device`/`devices`/`revoke`, status, backup, monitoring alert, CLI tests.
3. group-gate: policy v7, `vpn.json` reader, binding, core-host classes, `/vpn-required`, opened-log fields.
4. Hub: state (`reach`, devices, settings), address allocator, `vpn.json` writer, override rendering + drift, API/audit/MCP.
5. Hub UI: instance Access → Reachable from; Settings → VPN (users group, devices per person, expiry; mode read-only); Sign-in page device flow (noble x25519, `.conf` + QR in the browser); People → VPN devices.
6. Doctor checks.
7. e2e `e2e-vpn` + CI client.
8. Contract + docs + core cleanup; resync the Hub's docs copies.
9. Merge to main in the usual order (core + Hub together for policy v7), deploy on the test server, `ACME_STAGING=true`, Mac/iPhone client check by the user.

**Parked follow-ups:**
- non-HTTP `lan_only` ports over the VPN (the netstack can forward chosen TCP ports per instance, e.g. Samba);
- "Local networks also count" (needs a source-address fidelity probe);
- IPv6 in the tunnel;
- shared/group devices;
- per-peer preshared keys (post-quantum hardening);
- per-domain client split DNS;
- device posture.

## 13. Open questions (each has a default; work proceeds on the default)

1. **Default subnet `10.213.0.0/22`** may collide with someone's LAN. *Default:* keep it; `vpn init` refuses an overlap with Local networks/Docker networks and suggests a free /22.
2. **`public_enrol` default in `server` mode.** *Default:* on (sign-in + invite + device enrolment stay public; every admin surface goes VPN-only). Strict sites turn it off and bootstrap with `vpn add-device`.
3. **Binding for internet apps reached over the VPN.** *Default:* not required (the VPN is only a path there). Revisit if users want "the VPN counts only for my own devices" everywhere.
4. **Userspace throughput.** *Default:* accept it. If measured throughput on the test server is under 200 Mbit/s, revisit with a kernel/TUN mode behind an opt-in that adds NET_ADMIN (doctor Info).
