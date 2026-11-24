# Multiple Servers

One Portcullis server, the **primary**, can run app instances on other
machines, the **worker servers**: a NAS at home, a Raspberry Pi, a second
VPS. People, groups, sign-in, certificates and the Hub stay on the primary;
only the apps' containers run on the worker. The interfaces are in
[contracts §17](../guides/integration-contracts.md#17-servers-new-multiple-servers).

## The model

- **Every request enters through the primary.** DNS keeps pointing at the
  primary only. Its Traefik terminates TLS and runs forward-auth, group-gate
  and the TLS tier for every host, including the hosts of instances on a
  worker, then hands the request to a small **relay** that carries it to the
  worker over a WireGuard tunnel. So sign-in strength, group rules, public
  exceptions and VPN-only access are the same on every server: there is
  nothing on a worker that could drift.
- **Workers dial out.** A worker needs no inbound port and no public
  address: its **agent** connects out to the primary's link port (UDP 51821
  by default), so a NAS behind home NAT can be a worker of a VPS. Every
  connection inside the tunnel is still opened by the primary; the primary's
  end of the tunnel listens on nothing.
- **A worker holds no keys to the kingdom.** It has no ACME account, no DNS
  credentials, no certificate of a person, no cookie secret, no proxy secret
  and no core credential, and it never sees a Portcullis session cookie.
- **The worker runs two containers** of its own: the agent and
  `socket-proxy-agent`, the only thing that mounts the worker's engine
  socket. The Hub never talks to a worker's engine directly: it calls the
  agent's narrow API, and the agent checks everything again.
- **Fail closed.** When the primary (or its link) is down, nothing routes to
  a worker app. The worker's containers keep running.

```text
browser ─TLS─▶ primary Traefik ─(sign-in, groups, tier)─▶ relay ─▶ link ══WireGuard══▶ worker agent ─▶ app
                                                      Hub ─▶ link ══mTLS in WireGuard══▶ worker agent ─▶ socket-proxy-agent ─▶ engine
```

**What it isn't:** high availability, failover or a second primary; core
services (Keycloak, LLDAP, Vault, the Hub) on a worker; direct ingress on a
worker; automatic placement. Placement is always an admin's choice.
Kubernetes is not supported on either side (a Kubernetes primary shows
"servers need a Docker or Podman primary").

## Setting up

### 1. The link role on the primary

```bash
./portcullis link init            # --port N for another UDP port
```

`link init` turns on the third role of the VPN service `wg`, **link**: the
WireGuard server workers connect out to, on UDP 51821 and the fixed tunnel
subnet `10.214.0.0/24` (link is `10.214.0.1`, workers get `.10`–`.250`). It
generates the link's keys in place (never printed), has Vault sign its
`link.control` certificate, and starts `wg`, Traefik and the Hub. The Hub
must already be running. It refuses when `10.214.0.0/24` overlaps the
built-in VPN's subnet, a core network, a Docker network, a Local network
you entered in the Hub or a wired VPN provider's range.

Open **UDP 51821** in the primary's firewall. The workers dial the main
domain's apex (`example.com:51821`): no new DNS record is needed.

Until `link init` has run, **Settings → Servers** answers "run
./portcullis link init on the primary", and the primary's own apps are
unaffected.

### 2. Add the server in the Hub

In **Settings → Servers**, type an id (lowercase, e.g. `nas`; `primary` is
reserved) and a name (e.g. "Attic NAS"), then **+ Add server…**. This needs
a [fresh sign-in](#fresh-sign-in-and-typed-ids). The Hub shows a **join
code**:

- it is a secret: shown **once**, in that dialog only. **Copy code**
  copies it; closing the dialog forgets it. The Hub keeps only a hash of
  its secret, never the code: not in the audit, a log, the operation record
  or an AI transcript (no MCP tool can create one);
- it works **once** and expires after **15 minutes**.

The enrolment runs in the operation progress panel as `server_enrol`, in
three steps: **join** (waiting for the worker), **handshake** (the worker
checks the primary's certificate, the primary checks the worker's clock)
and **verify** (the proof, the worker's certificate, the key swap). **Stop
enrolment** during *join* leaves nothing behind; from *handshake* on it
revokes the server.

### 3. Join on the worker

The worker needs Docker, or [rootless Podman](rootless-podman.md), and a
checkout of core:

```bash
sudo mkdir -p /opt/portcullis && sudo chown "$USER" /opt/portcullis
git clone https://github.com/porelli/portcullis.git /opt/portcullis
cd /opt/portcullis
./portcullis worker join          # paste the code when asked
```

Or pipe it in: `./portcullis worker join < code.txt`. The code is never
accepted as an argument (it would land in the shell history and the process
list): `worker join <code>` refuses with "the join code is a secret: paste
it when asked, or pipe it in".

`worker join` writes `.env` (`PORTCULLIS_ROLE=worker`), starts the agent and
its socket proxy (compose project `portcullis-worker`) and waits up to five
minutes for the primary to enrol it. Then the server shows **ready** in
Settings → Servers.

!!! warning "Not under /root"
    The agent runs as uid 10008 and must read the checkout. `worker join`
    refuses an install under `/root`, also through a symlink ("…/root, which
    the agent (uid 10008) can't traverse"): put the checkout elsewhere, e.g.
    `/opt/portcullis`.

Before anything is written, `join` also refuses:

- a host that is a Portcullis primary (a worker needs a host, or at least a
  checkout, of its own);
- Kubernetes (`--runtime kubernetes`, or `CONTAINER_RUNTIME=kubernetes`);
- a worker that already has an identity (`--force` joins again over it);
- a missing **folder root**, or a folder root that contains the install, its
  `worker-data/`, the engine socket or the engine's data root (every path
  resolved first: `/var/run` is usually a link to `/run`,
  [below](#folder-roots)).

**The clock.** The worker's clock must be within **5 minutes** of the
primary's. Otherwise the enrolment fails with "the worker's clock is <n>
off; fix its time (NTP)". Keep NTP on both machines: the agent checks the
primary's certificates against its own clock too.

On a worker, every `./portcullis` command except `worker …`, `help`,
`version` and `status` refuses: "this host is a Portcullis worker: use
./portcullis worker …". The commands are in the
[CLI reference](cli.md#servers).

### Folder roots

A worker app may bind host paths only under the worker's **folder roots**,
`PORTCULLIS_WORKER_BIND_ROOTS` in the worker's `.env` (default
`/srv:/mnt:/media`). Each root must exist when you join. The agent mounts
every root **read-only at the same path** to check binds, and refuses to
start if it can't see one. A template that binds an absolute path outside
them can't be placed there.

Shared folders work on workers: a folder records its server (**Shared
Folders** has a Server column, and the server is chosen when you define the
folder), and only folders on the instance's own server can be bound to it.
The fixer runs on the worker, through its agent.

The agent also sees the install directory and the engine's data root
read-only at their host paths, and refuses any bind that equals, contains or
sits inside them, the worker's data directory, the engine socket or `/`.

!!! warning "Aliases the agent can't see"
    The agent compares directories by path and, for each folder in a bind
    source's path, by device and inode. Two kinds of alias escape that:

    - **FUSE union filesystems** such as Unraid's `/mnt/user` (a union of
      `/mnt/disk*` and the cache) or mergerfs show the same files under
      another device number;
    - **`mount --bind`** copies you make of a protected directory into a
      folder root.

    Keep the checkout, its `worker-data/` and the engine's data root out of
    every folder root under any name. On Unraid, narrow
    `PORTCULLIS_WORKER_BIND_ROOTS` to the shares apps need (e.g.
    `/mnt/user/media`), and keep the checkout and Docker's data root out of
    them.

## Placing apps

**Runs on** in an instance's setup form chooses the server (the primary by
default), and shows each server's runtime, architecture, free data space and
memory. Only the containers go to the worker: hostnames, Keycloak clients,
groups, policy and the portal entry stay where they are.

The Hub refuses, before anything is created, when the server isn't ready
("server NAS is offline"), its rootless compatibility gate says refused, a
pre-pull of the images fails there ("<image> has no <arch> image"), a host
port is taken by another instance **of that server** (each server has its
own ports), or the template is **primary-only**.

### Primary-only apps

A template is primary-only when it needs something only the primary has.
The Hub detects it, and refuses with "<app> can't run on a worker:
<reason>", where the reason is one of:

| Reason | Why |
|--------|-----|
| mounts the core volume `<v>` | Core volumes (`hub_data`, `hub_secrets`, the mail volumes, …) are on the primary. This covers the file-sharing apps (Samba, Time Machine) |
| has a Traefik TCP/UDP router | A relay carries HTTP only |
| has a per-person secret option | Per-person secrets live in the primary's `hub_secrets` |
| has AI companions | `mcp-gate` reaches companions on the primary's networks |
| is an AI page | The model providers' secrets stay on the primary |
| is a VPN provider | Its gateway joins the primary's `portcullis-vpn` |
| uses host-gateway | The host would be the worker, not what the app expects |
| binds `<path>` outside the server's folder roots | See [Folder roots](#folder-roots) |
| uses a non-HTTP backend scheme | A relay carries plain HTTP |
| passes a host device | A device of the worker's host (anything but `/dev/null`) |
| adds the capability `<cap>` | A capability beyond the Kubernetes baseline (`CHOWN`, `SETUID`, `NET_BIND_SERVICE`, …), `ALL` or an unknown one |
| delivers a settings secrets file | Only the primary can hand a `<name>.secrets.json` to the app's reader (uid 10001, `0600`); a worker's agent refuses one too (`400`) |
| is marked `placement: primary_only` | The template says so ([manifest reference](../guides/manifest-reference.md#placement)) |

A worker also refuses an image that isn't pinned by digest: "image <ref>
isn't pinned by digest: templates must pin images to run on a worker". The
Hub checks it on create and at every start, also for an image an admin
overrides in Settings.

So **AI** (`ai.mcp` companions and the AI chat page) and **mail** are
primary-only, as are VPN providers and file sharing. An app that declares
only `ai.unsupported` can run anywhere.

The rule is checked again whenever the Hub renders the instance (create,
enable, restart, a template update, a move). If a template update makes a
placed instance primary-only, the Hub stops it on the worker and the doctor
shows `server_placement_invalid`: move it to the primary.

### The cookie rule

The relay changes cookies in both directions, so a worker app never sees a
Portcullis session and its cookies never leave its own host:

- **Requests:** every Portcullis cookie (`_oauth2_proxy…`,
  `__Host-portcullis_ext…`) is removed before the request reaches the app;
- **Responses:** every `Set-Cookie` of the app is made **host-only** (its
  `Domain` attribute removed).

An app that needs a cookie for a parent or sibling host (single sign-on
across its own subdomains, for example) must stay on the primary: its
template sets `placement: primary_only`.

### Bandwidth

All traffic of a worker app goes through the primary: browser → primary →
worker and back. The primary's uplink carries it twice (in and out), plus
one more hop. Streaming from a NAS at home to a phone at home, with a VPS
primary, leaves the house and comes back. That is fine for home and
small-office use; keep heavy media apps on the server people are closest
to, or on the primary.

## Moving an instance

**Move…** on the instance page (Server section) moves an instance to another
server. Type the instance id to confirm. The app is **down while it moves**:

1. **check**: the target is ready and the placement rules pass. Bound shared
   folders are refused ("unbind folders first; folder contents aren't
   moved");
2. **backup** on the source (an instance backup, reason `move`), which
   stops the app;
3. **restore** into the same id on the target;
4. **switch**: the routes go to the target (the relays get a new token, or
   are removed when the target is the primary), and the app starts there;
5. **keep**: the old copy's volumes stay on the source, stopped.

It runs in the operation progress panel and can be stopped. A failure or a
Stop before *switch* starts the app on the source again: two routed copies
never exist. If the Hub restarts mid-move, it routes back to the source and
starts it there. If the target's copy can't be taken down, the app runs
nowhere until it can: doctor `server_move_stuck`, retried every 30 s.

**Undo move.** For **7 days** the instance page shows "Moved from <server>"
with **Undo move…**: routing goes back to the old copy and the app starts
there; the copy on the other server is stopped. **Changes made since the
move are lost.** After 7 days *Undo move* is gone and the doctor shows
`server_move_leftover` (Info): **Remove the old copy…** on the instance page
deletes the old copy's volumes, after which no undo is possible. Both need a
fresh sign-in and the typed instance id.

**Earlier copies on a worker.** Creating an instance on a worker, or moving
one there, is refused while that worker still holds a copy of the same
instance id — its bundle or its volumes, for example from a failed move — and
also when the worker can't be asked. Remove the old copy first. A kept copy
on a server that was revoked or removed can't be reached any more: deleting
or forgetting the instance drops it from the record and audits it
(`instance.copy_dropped`), and whatever is left on that machine is yours to
wipe.

## Backups

An instance on a worker is backed up like any other: the archive streams
through the agent into the primary's `<hub data>/backups/<instance-id>/`, so
the core backup and `--offsite` include it ([Backups](backups.md)). Restore
works the same way.

**Scheduled backups** are a per-server setting (the primary's too), in each
server's **Settings** in Settings → Servers: **off** (the default),
**daily** at an hour or **weekly** on a weekday at an hour, in the Hub's
time zone. Each enabled instance of that server is backed up in turn (it
stops briefly, as any instance backup). The 3 newest scheduled archives per
instance are kept; manual, move and pre-delete archives are never pruned. A
server that isn't ready is skipped, with a note in each instance's last
operation ("scheduled backup skipped: server NAS is offline"). The doctor
warns (`server_no_recent_backup`) about an enabled worker instance without a
backup in 14 days.

## Revoking and removing

**Revoke…** (fresh sign-in, typed server id) is for a lost, stolen or
compromised worker. It needs nothing from the worker and works while it is
offline:

1. the worker's peer and relays leave the tunnel's peer list: the tunnel and
   every open connection drop at once;
2. its certificate is revoked;
3. its instances' relays come down;
4. what the worker held is rotated: each placed instance's Keycloak client
   secrets and relay token.

Each step is retried every 30 seconds until it succeeds; a rotation that
can't finish shows `server_secrets_not_rotated`. The server stays listed as
revoked, and its instances become **orphaned** (doctor `instance_orphaned`):
restore an orphaned instance's last backup into a new instance (Backups tab;
it lands on the primary, move it afterwards), or forget it
(`DELETE /api/instances/<id>?forget=1` with `{"confirm": "<id>"}`: its
state, clients and groups go, nothing on the worker is touched, its
archives are kept).

**Remove…** (fresh sign-in, typed id) retires a worker you still have: it is
refused while instances remain ("move, restore or forget them first"); it
tells the worker to take its apps down and wipe its identity, then revokes
it. On the worker, `./portcullis worker leave` does the same from that side
(and removes `worker-data/`); it fails, keeping the identity and
`worker-data/`, while any app container is still there. Revoke or remove the
server in the Hub too.

### Fresh sign-in and typed ids

Adding, revoking and removing a server, *Undo move*, *Remove the old copy*
and *Lift quarantine* each need a **fresh sign-in** on the Hub (a popup
opened from the Confirm click), and all but adding need the id typed in an
inline confirmation row. They are never MCP tools, and the doctor never
offers a one-click fix for them: its finding explains and points at the
button. *Move…* needs the typed id but no fresh sign-in.

### Quarantine

The agent watches every container it starts. If one runs with a bind
source that fails its check (a symlink someone planted, a directory swapped
under a folder root), it kills the container, takes the instance down and
**quarantines** it: it refuses to start it again, also after a restart and
after a new bundle. The doctor shows `server_instance_quarantined`. Fix the
cause on the worker, then **Lift quarantine…** on the instance page (fresh
sign-in): the agent checks the bind sources again before it lifts it.

## When something is down

**The primary or its link is down:**

- nothing routes to worker apps (fail closed); their containers keep
  running, and their data is safe;
- `lan_only` ports a worker app publishes on the worker's LAN keep working,
  as they are outside sign-in anyway;
- the break-glass on the worker still works:
  `./portcullis worker stop <instance>` and `worker start <instance>`, as the
  worker's operator (no root needed; they find the instance through the
  engine). They never change what the primary routes;
- what stops: every routed app, scheduled backups, and the renewal of the
  worker's certificate (30 days, renewed with a third of its life left).

**A worker is offline** (three missed 30-second polls, or no tunnel
handshake for 3 minutes): its instances show `unreachable`, their pages
answer "<app> runs on <server>, which is offline", and lifecycle operations
are refused ("server NAS is offline"). When it comes back, the Hub
reconciles and runs the doctor.

**Restoring the primary** onto a new host ([Backups → On a new
host](backups.md#on-a-new-host)) restores the link's keys, the node CA in
Vault and the Hub's state. The workers reconnect by themselves once the
domain's apex points at the new host.

**A dead worker:** revoke it, then restore its instances' last backups.
Worker state isn't backed up: a re-join creates a new identity, and the Hub
renders the apps again.

## Monitoring and status

- `./portcullis status` on the primary has a **Servers** block (each
  worker's last handshake; a worker silent for more than 3 minutes is a
  problem), and `./portcullis link status` shows the same. On a worker,
  `./portcullis worker status`.
- The monitoring profile scrapes job `link` and alerts
  `PortcullisServerDown`, `PortcullisServerDiskLow` and
  `PortcullisServerContainerUnhealthy` ([Monitoring](monitoring.md)).
- The doctor's server checks are listed on
  [Hub → Server checks](hub.md#server-checks).
- **Usage** on the Hub covers the workers too ([Hub → Usage](hub.md#usage)):
  each ready worker's apps and containers are sampled in the primary's 15 s
  sweep through its agent, its volumes measured with the rest of the
  storage, and **Usage → Share** has a **Server** picker for each worker's
  CPU, memory, disk IO, network and disks ([Share](hub.md#share)). A worker
  that doesn't answer in time, or whose agent is older than the Hub, shows
  its apps as "not measured" with that reason; the primary's figures are
  never held up by a worker.
- **Not yet for workers:** the doctor's usage checks (memory, OOM, process
  limits, a nearly full disk) and the Hub's usage metrics in Grafana cover
  the primary only. They carry no server label yet, so watch a worker's
  apps on the Usage tab.

## Security

The threat model, the agent's checks, the tunnel's rules and the per-service
settings are on [Security & Hardening → Multiple
servers](hardening.md#multiple-servers).
