# High availability on Kubernetes (design)

Status: written by the assistant from a design conversation with the user on 2026-11-16. The user set the goal, the model and the main directions; those are listed in §2 as **the user's**, in their words where they gave words. Every other decision is the **assistant's call** unless it says otherwise. What the builder verifies in spikes is in §19.

**Revision 2 (2026-11-16): the user answered the open questions** (§20).
- Q1 (main-domain credentials) and Q2 (cross-site start only when fully synced) are **user rulings**, folded into §2, §11.3 and §11.5.
- Q3–Q5 were accepted as the assistant recommended.

**Timing (user):** HA starts **after the current queue**: multi-server → the mail-provider rework → resource usage → CLI login. HA is framed as **multi-server's next stage**. It reuses multi-server's enrolment, join codes, the link and the Servers page (§6.2, §16).

This spec builds on:
- `2026-11-13-kubernetes-design.md` (Helm chart on k3s, the Hub's compose → Kubernetes translator, one namespaced Role, the admission policies);
- `2026-11-13-multi-server-design.md` (worker agent, the `wg` link role, `pki_node`, join codes, placement, move, per-server backups);
- `2026-11-13-dns-hardening-design.md` (the DNS plan, CAA pinning, the fail-safe TTL waits);
- `2026-11-16-mail-provider-design.md` (mail as a Marketplace provider slot);
- `2026-11-14-resource-usage-design.md` (usage sampling, limits).

**Baseline.** The local `main` checkouts under `/Volumes/workspace/portcullis/` are behind `origin/main` (core by 168 commits, Hub by 36), so the recon read `origin/main`, plus the `ms1` worktrees at `/Volumes/workspace/portcullis/wt-ms1/` for multi-server. Paths are repo-relative.

## 1. Where things stand (2026-11-16)

### 1.1 Kubernetes (EXPERIMENTAL, on main)

- **Core** ships `charts/portcullis/` (one Deployment per core service, `charts/portcullis/templates/*.yaml`), `kube/admission/` (the six ValidatingAdmissionPolicies plus bindings and params), `kube/storage/` (a pinned local-path provisioner `portcullis.io/local-path`, StorageClasses `portcullis-core` with reclaim `Retain` and `portcullis-apps` with reclaim `Delete`, ownership from PVC annotations) and `kube/probe/` (the NetworkPolicy enforcement probe). The CLI side is `scripts/lib/kube.sh` (2320 lines): the 1.33 floor (`KUBE_MIN_VERSION`), the k3s flag checks (`--secrets-encryption`, `--disable=traefik`, the network policy controller, ServiceLB, `pod-max-pids=1024`), the AppArmor stacking check (`_kube_apparmor_check`, containerd#14485) and the kube-check timer.
- **It is single-node by construction.** `kube_detect_cidrs` refuses a cluster with more than one node ("Portcullis runs on a single-node k3s"). Every core Deployment is `replicas: 1`, strategy `Recreate`. Volumes are hostPath PVs on the one node. The `hub-data` PVC is mounted by the Hub, group-gate, mcp-gate and Keycloak, which only works because they share a node.
- **The Hub** (`internal/runtime/kube/`) translates each instance into Deployments (replicas 1, `Recreate`), PVCs, Services, Secrets, ConfigMaps and NetworkPolicies in `portcullis-apps`, and IngressRoutes, Middlewares and pinned ExternalName Services in `portcullis-edge`, the only namespace Traefik watches. The admission policies refuse `replicas > 1` (`kube/admission/policies.yaml`, mirrored in the Hub's `internal/runtime/kube/testdata/admission/policies.yaml`), and the contract's Kubernetes refusal list (§3.4 "Refused on Kubernetes", §11.10) has `service <s> sets replicas above 1 (not on Kubernetes)`.
- **Templates:** about 5 work on Kubernetes today (docs, firefox-sync, mealie, paperless, vikunja). Most of the others need a numeric `user:`, which is a parked follow-up.
- **Not on Kubernetes yet:** mail (contract §19.12; the mail-provider spec refuses Kubernetes too), the `link` role (contract §16.1), and multi-server (contract §17.1 on `ms1`: "a primary on `CONTAINER_RUNTIME=kubernetes` … Kubernetes workers … HA or a second primary" are not supported).

### 1.2 Multi-server (branch `ms1`, nearly done)

- The primary's Hub places instances per server. Workers (Docker or rootless Podman) run `portcullis-agent` + `socket-proxy-agent` (`cmd/portcullis-agent`, `docker-compose.worker.yml`, `./portcullis worker join|status|upgrade|leave|stop|start`).
- They are linked by the `wg` service's link role: userspace WireGuard, subnet `10.214.0.0/24` fixed, zero listeners on the primary's netstack. Identities come from the `pki_node` Vault mount, which has its own root (contract §17.5 on `ms1`).
- Relays on the primary carry each placed instance's Traefik labels. Ingress stays on the primary.
- Join codes are single use and valid 15 min, with an HMAC proof and a bootstrap key swapped for the worker's own.
- Move is backup → restore → switch, and *Undo move* works for 7 days. Scheduled backups are set per server (off, daily or weekly, last 3 kept).
- Its non-goals include HA and failover: a dead worker's instances become `orphaned` and are restored from their last backup by hand.

### 1.3 Core services and their state today

| Service | State | Today |
|---|---|---|
| Traefik | `acme.json` (main-domain certificates via its built-in resolver) | 1 replica; the domains service feeds it added-domain certificates over the mTLS HTTP provider (contract §12.4) |
| Keycloak | Postgres (`postgres-data`), themes from `hub-data` | 1 replica |
| Postgres | `postgres-data` | 1 instance, `pg_dump` backups |
| LLDAP | SQLite in `lldap-data` | 1 replica |
| Vault | raft storage in `vault-data`, auto-unseal from `secrets/vault-unseal` | 1 raft peer |
| sessions (Valkey) | memory only | 1 replica |
| forward-auth ×2 (oauth2-proxy), group-gate, enroll, mcp-gate | sessions in Valkey, policy and attributes from `hub-data`, `mcp-gate-data` | 1 replica each |
| Hub | `hub-data` (state.yaml, overrides, appfiles, backups, folder snapshots, published documents), `hub-secrets` | 1 replica |
| domains | `domains-data` (age-encrypted credentials, its ACME account) | 1 replica |
| wg | `wg-data`, `vpn-doc` | 1 replica |
| monitoring | Prometheus, Alertmanager, Grafana | profile, 1 replica each |

### 1.4 DNS and mail

- The main domain's records are handled by `./portcullis dns setup`, and its certificates by Traefik's resolver. **Traefik is already a long-running holder of the main domain's DNS-provider credentials**: core `docker-compose.yml` passes `TRAEFIK_CERTIFICATESRESOLVERS_LETSENCRYPT_ACME_DNSCHALLENGE_*` plus the provider's token (`CF_DNS_API_TOKEN`, `PORKBUN_API_KEY`, …) for DNS-01 renewals. The domains service holds the added domains' credentials. The DNS spec's rule keeps those credentials away from the domains service and the Hub, not away from every long-running service.
- `address` records have TTL 300, but Porkbun forces 600. Public resolvers (8.8.8.8) re-serve old answers long after one TTL. CAA is pinned to one ACME account per name, and account switches go through the fail-safe relax → wait → flip → re-pin sequence.
- Mail is merged as a core profile. It is being reworked into a Marketplace provider slot after multi-server ships (user's sequencing). It needs public port 25 and a PTR record, and it is refused on Kubernetes.

## 2. What the user decided

These are the user's decisions from the conversation (their words in quotes):

1. **Goal:** when something fails, "have down the least amount of things", without overwhelming nodes that can't sustain the load.
2. **Nodes are very diverse:** a Raspberry Pi that runs only critical services such as DNS filtering, local machines and cloud machines.
3. **Priorities are the admin's:** which services matter more is up to the admin, "by priority for HA services". The user expects Kubernetes to handle this already, through priority classes, requests and limits, preemption and affinity.
4. **Stateful apps:** ideally zero data loss, plus protection against divergence (split brain).
5. **Storage tiers, chosen per volume:**
   - shared single-copy NFS served by one or more Portcullis nodes, for non-critical big data;
   - replicated storage (Longhorn-like) for important data;
   - both at once, e.g. one Nextcloud instance with an NFS single-copy external storage (a movie library) plus replicated personal data. The user said "this is just an example".
6. **Native snapshots (ZFS / btrfs), integrated**, used for quick undo before risky changes **and** as history and offsite-backup sources ("both").
7. **Docker multi-server vs Kubernetes** (the assistant recommended, the user accepted):
   - automatic HA is **Kubernetes-only**;
   - Docker multi-server gets **assisted recovery**: alerts, one-click "bring the app up elsewhere from its latest snapshot or backup" with a data-loss warning, and an upgrade path that turns Docker servers into a k3s cluster.
8. **The core must be HA:** "if we lose the sign-in services we lose everything anyway. We should not lose them." The accepted direction:
   - Keycloak with 2+ replicas sharing sessions;
   - Postgres replicated, with fenced automatic failover through a mature operator;
   - LLDAP on that Postgres;
   - Valkey with a replica and promotion;
   - the stateless gates replicated;
   - the Hub as active + standby with leader election (a short Hub pause is acceptable);
   - DNS filtering and similar shared services replicated;
   - at least 3 nodes for quorum, where a Pi may be the light tie-breaker.
9. **The front door:** DNS failover is enough. Portcullis rewrites the public A/AAAA to healthy nodes with short TTLs. No floating IP or cloud load balancer is required.
10. **Anti-goal: setup must be super simple.**
    - A one-line start on the main machine.
    - Every other machine is provisioned from inside Portcullis (Hub UI and/or CLI).
    - Portcullis installs and joins k3s, the storage, the snapshot integration and the operators itself. The user never assembles a cluster by hand.
    - Single-server installs must not get harder.
11. **Main-domain DNS credentials (ruling on Q1).** The user pointed out that Traefik already holds them for ACME DNS-01 renewals, so the front-door role is **a second consumer, not a reversal of a rule**. Allowed, with these conditions:
    - they are held by the front-door role;
    - they are limited to the main domain's records;
    - they use the narrowest token the provider offers;
    - the offsite-backup prerequisite for HA mode stays.
12. **Cross-site (ruling on Q2):** asynchronous replication across sites, but "do not start unless the volumes were fully synced". This is defined precisely in §11.5.
13. **Kernel WireGuard mesh, a 1–3 min Hub pause in phase 1, and `git clone && ./portcullis init` as the one line** (Q3–Q5): the assistant's recommendations, accepted.

## 3. Goals, non-goals, anti-goals

**Goals**
1. **Survive the loss of any one node** in a cluster of 3 or more nodes at one site. Sign-in keeps working (with seconds of disruption for stateless parts and under a minute for Postgres). Every app the admin marked HA comes back on its own, without data loss and without two live copies.
2. **Degrade by priority, not at random.** When capacity is short after a failure, lower-priority apps are the ones that stop. A small node never receives work it wasn't allowed to take. Before anything fails, the admin can see whether the cluster can absorb the loss of each node (§10.4).
3. **Per-volume storage tiers** (local, replicated, shared NFS), chosen by the admin per volume within what the template allows, with native snapshots behind one Snapshot model (§9).
4. **Setup stays a one-liner plus clicks.** Nodes are added from the Hub or the CLI with a join code. Portcullis installs k3s, Longhorn, the snapshot controller, CloudNativePG and the fencing components.
5. **DNS failover for the front door**, consistent with the DNS-hardening rules (TTL, CAA, append-then-delete).
6. **Assisted recovery on Docker multi-server**, and a guided upgrade path from Docker (single or multi-server) and from experimental single-node Kubernetes to an HA cluster.

**Non-goals**
- Multi-region or multi-site **active-active**. A cluster spans at most one site in phases 1–3. A second site is a disaster-recovery target with asynchronous replication (phase 4, §11.5).
- Floating IPs, VRRP/keepalived, BGP, or a cloud load balancer as a requirement. They may be documented as optional, but nothing depends on them.
- Automatic failover on Docker or Podman, single or multi-server.
- 2-node HA. Quorum needs 3 voters (§4). A 2-node cluster is refused for HA, and a Pi is enough as the third voter.
- Guaranteed zero data loss across sites. Cross-site copies are asynchronous: "confirmed caught up" bounds the loss but can't eliminate it (§11.5).
- Live migration, and HA for apps bound to host devices (USB sticks, GPUs). They are pinned to their node and marked "not HA".
- Kubernetes distributions other than k3s for HA, and an external etcd or SQL datastore.
- Mixing Docker workers and Kubernetes nodes in one install (v1, §16).

**Anti-goals (never)**
- **Never two writers.** Prefer downtime over divergence: a stateful workload never runs in two places at once, even during a network partition (§8.4). Every automatic failover of state is fenced.
- **Never make single-server harder.** A Docker single-server install gains no new prompt, dependency, flag or service. Nothing in this spec runs unless the admin turns HA on.
- **Never hand-assemble a cluster.** No step asks the user to run `k3s`, `kubectl`, `helm`, Longhorn or operator commands themselves.
- **Never overload a small node.** Small nodes are tainted. Only pods that tolerate the taint (quorum pieces, and apps the admin pinned there explicitly) ever land on one.
- **Never weaken the security model** of the Kubernetes spec:
  - the Hub has no cluster-scoped verb and holds no join token;
  - every namespace is default-deny;
  - the admission policies judge every identity except the CLI;
  - etcd, the kubelet and the API server are never reachable from the internet.

## 4. Constraints that shape the design

- **Quorum.** etcd (k3s embedded), Vault raft and Valkey Sentinel each need a majority of voters: 3 tolerates 1 failure, and 2 tolerates none. So HA starts at 3 nodes, and each quorum system puts one voter on each of 3 distinct nodes. The Pi can carry all three voters (etcd member, raft voter, sentinel) without carrying data. It does need a USB SSD rather than an SD card, because etcd is fsync-bound (§19, spike).
- **Synchronous replication and latency.** Longhorn writes every block to every replica before it acknowledges the write. CloudNativePG in synchronous mode waits for a standby before it acknowledges a commit. Across home ↔ cloud (typically 15–60 ms RTT, variable) that makes every write wait at least one round trip, and an uplink saturated by backup traffic can stall the apps. So zero-loss replicas stay within one site (one LAN or one cloud region), and cross-site copies are asynchronous (§11.5). This is the one place where "ideally zero data loss" can't be guaranteed. The user's rule ("do not start unless the volumes were fully synced", §11.5) bounds the loss to the last few seconds before the primary site went silent, and when even that can't be confirmed, nothing starts on its own.
- **etcd across sites** works with tuned heartbeat and election timeouts up to about 100 ms RTT. But with 2 sites, the site that holds 2 of the 3 voters is the only one that can survive on its own. Real site tolerance needs a third location for the tie-breaker (§11.5).
- **Kubernetes doesn't fence by itself.** A partitioned node's kubelet keeps running its pods. The control plane only marks the node `NotReady`/`Unreachable`, and pods with RWO volumes stay stuck until something proves the node is dead (§8.4).
- **Default failover timings are slow:** about 40–50 s to mark a node unreachable, plus the default 300 s `tolerationSeconds` before eviction. HA pods get shorter tolerations (§8.4).
- **DNS caching.** Provider minimum TTLs vary (Porkbun 600 s), and public resolvers keep old answers beyond the TTL. So a single-address DNS failover can take 10+ minutes on some providers. Multi-address answers (§11.1) are what make it fast.
- **Diverse nodes.** arm64 and amd64, 2 GB to 64+ GB of RAM, SD cards to NVMe. Home nodes sit behind NAT, ISPs block port 25, and cloud nodes have public addresses and PTR records.
- **The Hub's and core's existing guarantees** (kube spec §2 anti-goals, contract §6 "On Kubernetes") stay in force. Any change to them is listed in §17.

## 5. The model: one cluster, node roles, failure matrix

**One k3s cluster with embedded etcd** (assistant's call). Every Portcullis node is a k3s node. Kubernetes does the scheduling, priorities, preemption and rescheduling, and Portcullis supplies the policy (classes, priorities, tiers) and the guard rails (admission, the N−1 check, fencing).

**Node roles** (k3s): the first 3 nodes are **servers** (etcd members and API servers); later nodes are **agents**. The Hub picks the role at join time: a server while fewer than 3 healthy servers exist, otherwise an agent. The admin can override this, for example "this cloud VM should be the third server instead of the Pi" (assistant's call). A 4th or 5th server is allowed for 2-failure tolerance, but never an even number on purpose: the Hub warns about 4.

**Node labels** (set by Portcullis at join, editable on the server page, never by apps):

| Label | Values | Meaning |
|---|---|---|
| `portcullis.io/class` | `small`, `home`, `cloud` | Suggested from the detected RAM/CPU (`small` < 4 GB RAM or a Pi model string) and from whether a public address answers. Shown to the admin, who confirms or changes it |
| `portcullis.io/site` | free text, default `main` | Failure domain for spreading and for keeping sync replication within one site |
| `portcullis.io/ingress` | `true` | Runs Traefik and takes public traffic. Needs a reachable 80/443 (checked from the other nodes and by the public check, §11.1) |
| `portcullis.io/storage` | `true` | Holds Longhorn replicas. Off by default on `small` nodes |
| `portcullis.io/nfs` | `true` | Serves shared-tier folders (§8.3) |
| `portcullis.io/mail` | `true` | May run the mail provider (static IP, PTR, port 25 open, §13.1) |
| `topology.kubernetes.io/zone` | = `site` | So standard spreading and the operators' anti-affinity work unchanged |

**Taint:** `small` nodes get `portcullis.io/small=true:NoSchedule`. Core quorum pieces tolerate it. An app instance tolerates it only when the admin pins it there ("Runs on: Pi"), which is how the Pi runs DNS filtering and nothing else.

**What a single failure does** (3 nodes at one site, the phase 1 target):

| Failure | Sign-in | HA apps (replicated tier) | Non-HA apps | Data |
|---|---|---|---|---|
| A cloud/home node dies | Keycloak and the gates keep serving from the other replicas. A Postgres primary there → the sync standby is promoted in ~10–30 s. A Valkey primary → Sentinel promotes in ~10 s (some users sign in again). The Hub on that node → paused 1–3 min (§7.3) | Fenced, then rescheduled with their volume on a surviving replica: ~2–4 min | Down until the node returns (local tier), or rescheduled if their volume is shared/NFS on another node | No loss |
| The Pi (tie-breaker) dies | Unaffected. Quorum 2/3 still holds | Unaffected | DNS filtering moves to its other replica (§12.3) | No loss |
| A partition isolates one node | The minority node fences itself (§8.4). The majority side behaves as if it died | As above | As above | No loss, no divergence |
| Two of three nodes die | Down: no quorum. Portcullis refuses to guess. The surviving node keeps its data and reports "quorum lost" | Down | Down | No loss (fenced). Recovery = bring a node back, or the guided restore (§15.4) |
| The NFS node dies | Unaffected | Unaffected, unless they mount a shared-tier volume, which then waits (single copy, by the user's choice) | Same | No loss |

## 6. Setup and provisioning

### 6.1 The main machine (one line)

- **Docker single-server stays exactly as today** (`git clone … && ./portcullis init`). It never gets k3s, and nothing in §6 runs for it.
- **Kubernetes:** `./portcullis init --runtime kubernetes` **installs k3s itself** when no cluster is configured (assistant's call). The user no longer runs the k3s install line from `operations/kubernetes.md`.
  - The k3s version and the sha256 of the install script and binary are pinned, as `e2e-k3s` already pins them.
  - The k3s flags are the ones `kube.sh` checks today, plus `--cluster-init`, so that the datastore is embedded etcd from the first boot and the later step to 3 servers needs no reinstall.
  - The host checks (AppArmor stacking, the sysctls, Longhorn's prerequisites `open-iscsi` and `nfs-common`, ZFS/btrfs detection) run before the install. Packages are installed only after one confirmation that lists them.
  - Existing single-node k3s installs on SQLite are converted to etcd by k3s's own restart with `--cluster-init` when HA is turned on (§15.2).
- A curl-to-shell installer (`curl -fsSL https://…/install.sh | sh -s -- --runtime kubernetes`) that clones and runs `init` is **not** published. `git clone && ./portcullis init` stays the one line, because it is already one line and it is auditable (Q5, accepted). The Hub-served, checksum-pinned `join.sh` is used only for adding nodes, where the join code authenticates it.
- **HA is off until the admin turns it on.** A fresh Kubernetes install is a 1-node cluster that is HA-ready but runs the single-replica chart, so it costs no more RAM than today plus etcd (about 100–200 MB).

### 6.2 Adding a node (from the Hub or the CLI)

This reuses the multi-server enrolment model (`ms1`: contract §17.5) with a new server kind, **cluster node** (assistant's call).

1. **Hub → Settings → Servers → Add server**, kind **Cluster node** (fresh sign-in, audited `server.add`). The CLI twin is `./portcullis node add <id>`. The Hub suggests the role (server or agent) and the class. It shows a single-use **join code**, valid 15 min, holding:
   - the cluster's enrol endpoint (`<d>`, plus each current server's address);
   - the server id;
   - the `pki_node` CA fingerprint;
   - a 256-bit secret, of which only the hash is stored.

   The code carries **no k3s token** (below).
2. **On the new machine:** a one-liner the Hub shows (`curl -fsSL https://<d>/node/join.sh | sh -s -- <code>`; the script is served by core, its sha256 is inside the code, and the script checks itself against it). The script:
   - runs the host checks;
   - proves the secret to **`nodeadm`** (below) with the same HMAC-over-nonce exchange as multi-server enrolment;
   - gets a `pki_node` certificate (role `node-cluster`);
   - only then receives the k3s join material for its role over that mTLS channel;
   - installs pinned k3s with the cluster's flags and the node's labels and taints, and installs the mesh key (§16.2).
3. **The Hub follows progress** in the operation panel (`server_enrol` op, as on `ms1`): enrolled → k3s joined → node Ready → storage ready (Longhorn node, disks found, ZFS pool found) → done.
4. **Removal** (`DELETE /api/servers/{id}`, typed id): cordon → drain, which respects PodDisruptionBudgets and refuses if a quorum or a replica count would drop below its minimum → Longhorn evicts the node's replicas → etcd member removal → certificate revocation → `k3s-uninstall.sh` over the channel. **Revoke now** (the node is lost or stolen) skips the cooperative steps: it deletes the node object, removes its etcd member, revokes its `pki_node` certificate and its mesh peer, and rotates the cluster's server token.

**`nodeadm`** (new core component, assistant's call). It is the only holder of the k3s server token and the only identity that can create agent bootstrap tokens.
- It runs in the core namespace on server nodes only. Its own ServiceAccount may create Secrets of type `bootstrap.kubernetes.io/token` in `kube-system`, guarded by a ValidatingAdmissionPolicy: a TTL of 15 min or less, usage `authentication` only, and the k3s bootstrap group only.
- It reads the server token from a Secret that only it can read.
- It serves the enrol endpoint behind Traefik on a dedicated path that requires a `pki_node` client certificate after the HMAC step.

So the Hub asks `nodeadm` to issue a code but never holds a token. A compromised Hub can let a machine join only through a code an admin created with a fresh sign-in, which is the same bar as multi-server's *Add server*. Joining as a **server** grants that machine cluster-admin equivalence, and the Add-server dialog says so in those words. Server joins are never offered over MCP.

### 6.3 Turning HA on

**Settings → High availability** (admin, fresh sign-in) shows a checklist:
- at least 3 nodes, with at least 3 servers;
- at least 2 storage nodes (3 recommended);
- at least 1 ingress node (2 recommended);
- the backup destination is set (§9.3);
- the N−1 check is green (§10.4).

**Make Portcullis highly available** then runs the conversion as one operation (§15.2): core components scale out, core volumes move to their HA storage, and LLDAP moves to Postgres. It costs one announced sign-in downtime of a few minutes. The CLI twin is `./portcullis ha enable`.

## 7. Core HA, service by service

### 7.1 Summary

| Component | Mode | Replicas / voters | Storage | Failover | Pick (alternatives in §18) |
|---|---|---|---|---|---|
| Traefik | active-active | DaemonSet on `ingress` nodes | none (§11.2) | DNS failover + client multi-address fallback | as today |
| Keycloak | active-active | 2 (3 with ≥ 3 non-small nodes) | Postgres | other replicas keep serving; sessions are in Postgres and the Infinispan cluster | the custom image (portcullis-keycloak), embedded Infinispan, JDBC_PING discovery |
| Postgres | primary + sync standby | 2 instances (3 with ≥ 3 capable nodes) | local tier per instance (the database replicates itself) | CloudNativePG promotes the most advanced standby; the isolated primary shuts itself down | CloudNativePG |
| LLDAP | active-active (to verify) or active + reschedule | 2 | its database in the CNPG cluster | stateless app on HA Postgres | LLDAP's Postgres backend |
| sessions (Valkey) | primary + replica + 3 sentinels | 2 data + 3 sentinels | memory (as today) | Sentinel promotion ~10 s; oauth2-proxy follows Sentinel | Valkey Sentinel |
| Vault | raft | 3 voters (one may be the Pi) | local tier per voter | raft leader election in seconds; auto-unseal as today | Vault raft `retry_join` |
| forward-auth ×2, group-gate, enroll, mcp-gate | active-active | 2 each, spread across nodes, PDB `minAvailable: 1` | none (published documents, §7.2) | none needed | as today |
| Hub | single writer, Lease-guarded | 1 active (+ a warm standby in phase 4) | `hub-state` replicated tier | fenced reschedule, 1–3 min (§7.3) | client-go leader election |
| domains | single writer, Lease-guarded | 1 active | `domains-data` replicated tier | fenced reschedule; Traefik keeps the last certificates meanwhile | as today, plus the front-door role (§11) |
| nodeadm | single writer, Lease-guarded | 1 on a server node | Secrets only | reschedule | new |
| wg | single | 1 | `wg-data` replicated tier | reschedule; VPN clients reconnect (§13.2) | as today |
| monitoring | Prometheus 1 (low priority); Alertmanager 2, meshed | — | Prometheus replicated tier (or local, the admin's choice) | Alertmanager survives any one node | as today |

**Placement rules** for every replicated core component: `topologySpreadConstraints` on `kubernetes.io/hostname` with `whenUnsatisfiable: DoNotSchedule` for the quorum and data pieces, and `ScheduleAnyway` for the stateless gates. Every core pod uses PriorityClass `portcullis-core` (§10.1). Sentinels and the third Vault voter tolerate `portcullis.io/small`, and nothing else in core does (assistant's call).

### 7.2 Published documents instead of a shared `hub-data`

Today group-gate, mcp-gate, Keycloak and the Hub share the RWO `hub-data` PVC on one node. In HA that can't hold. The Hub's outputs for other services are split off (assistant's call):
- the policy file and user attributes (contract §4, §4.1);
- `vpn.json` and `link.json`;
- the mcp-gate files (§15.4);
- the Keycloak theme and map inputs.

Each becomes a **ConfigMap or Secret in the core namespace** with a fixed name, written by the Hub through a new Role in the core namespace limited to `get`/`update`/`patch` on exactly those `resourceNames`, with no `create`, `delete`, `list` or other names (core creates the empty objects). Readers mount them as today; the kubelet syncs them, and the Hub bumps a pod annotation for the prompt deliveries the contract already requires (kube spec §4, "`.rev`").

This **narrows** the kube spec's anti-goal "nothing in the core namespace" to "nothing but those named documents" (§17). The alternative, an RWX Longhorn volume, adds an NFS share-manager to the sign-in path, and a hung NFS mount fails sign-in closed. It is rejected for that reason.

### 7.3 The Hub: single writer, fast reschedule, warm standby later

- **The user accepted active + standby with leader election and a short pause.** The Hub's state is a set of files in `hub-data` (`state.yaml`, overrides, appfiles, audit, folder snapshots, backups). A true hot standby needs that state in a store two pods can share safely.
- **Phase 1** (assistant's call):
  - Instance backups and folder snapshots move out of `hub-data` to the backup tier (§9.3), so the volume stays small.
  - `hub-state` becomes a replicated-tier (Longhorn) RWO volume.
  - The Hub runs 1 replica and takes a Kubernetes **Lease** before it writes anything. A Hub that can't renew its Lease within 10 s stops writing and answers 503. That is the software fence; the node-level fence is §8.4.
  - A dead node means a fenced reschedule: the pause is the node-failure detection plus the volume reattach, 1–3 min, during which sign-in and apps are unaffected and only administration waits.
- **Phase 4:** the Hub's state moves into the HA Postgres (one database, with optimistic concurrency on a versioned `state` document plus tables for the audit). A second Hub pod then waits on the Lease as a hot standby, and the pause drops to the Lease duration (about 15 s). The 1–3 min pause in phase 1 was accepted (Q4).

### 7.4 Core details worth stating

- **Keycloak.**
  - Persistent user sessions (on by default in Keycloak 26) keep sessions in Postgres, so a lost replica loses no session.
  - The embedded Infinispan caches cluster through `JDBC_PING` over the same database, so no extra discovery service is needed.
  - `--proxy-trusted-addresses` stays the pod CIDR, with the Traefik-only ingress policy (kube spec §5).
  - Keycloak's start time (start_period 300 s, memory note) means the second replica comes up after the first. The PDB keeps one Ready during upgrades.
- **Postgres (CloudNativePG).**
  - One `Cluster` (`portcullis-pg`), with databases `keycloak` and `lldap` (and `hub` in phase 4).
  - `synchronous: {method: any, number: 1, dataDurability: preferred}` with 2 instances, so a lone standby failing doesn't stop writes; `required` with 3 instances (assistant's call; why: §8.2).
  - Anti-affinity on hostname, and instances never on `small` nodes.
  - WAL archiving and base backups go to the backup destination (§9.3).
  - The operator runs in its own namespace `cnpg-system`, installed and upgraded by the CLI (pinned chart and digest), with no rights in `portcullis-apps`.
- **Valkey.** Its config gains `replicaof` / Sentinel. oauth2-proxy uses its Sentinel mode (`--redis-use-sentinel`, master name, the three sentinel addresses). Replication is asynchronous: a promotion can lose the last second of session writes, so a few people sign in again. Sessions are tickets, not user data, so this is accepted (assistant's call).
- **Vault.**
  - The raft storage gets 3 voters with `retry_join` on the headless Service.
  - Each pod auto-unseals from the same `secrets-vault-unseal` Secret, as today.
  - The core `backup` takes the raft snapshot from the leader.
  - Vault's own replication means its volumes are on the **local tier**, not Longhorn (the "replicate once" rule, §8.1).
- **LLDAP.** It moves from SQLite to Postgres when HA is turned on, with a one-time conversion in the `ha enable` operation (§15.2). Whether two LLDAP replicas can share one database safely is a spike (§19). If not, it runs as 1 replica that reschedules in seconds (stateless on HA Postgres).

## 8. Storage

### 8.1 Three tiers, and "replicate once"

| Tier | What it is | Copies | Survives a node loss | Snapshots | For |
|---|---|---|---|---|---|
| **local** | a PV on one node: `portcullis.io/local-path` today, or **OpenEBS ZFS LocalPV** on ZFS nodes | 1 | no (the pod waits for its node) | ZFS native on ZFS nodes; none on other filesystems (§9.1) | databases and stores that replicate themselves (CNPG, Vault raft), caches, scratch data, apps the admin doesn't need HA |
| **replicated** | **Longhorn** volume, block-replicated across storage nodes of one site | 2 (default) or 3 | yes, fenced (§8.4) | Longhorn native (block-level, instant) | important app data: Nextcloud user files, Vaultwarden, Paperless, the Hub's state |
| **shared** | an NFS export served by a Portcullis node with the `nfs` label, mounted through **csi-driver-nfs** | 1 (by the user's choice) | only if the NFS node isn't the one lost | native ZFS/btrfs on the NFS node's dataset (§9.1) | big, non-critical data shared across apps and nodes: media libraries, shared folders (contract §14) |

**Replicate once** (assistant's call): data that replicates itself at the application level (CNPG, Vault raft, a future Valkey AOF) sits on the **local** tier. Layering Longhorn under it would multiply writes and latency for no extra safety. The Hub enforces this for core, and templates mark it for their own databases (`replicated_by_app`, §12.1).

### 8.2 Zero data loss: what it means here

- **Within one site, any single failure loses no committed data:**
  - Longhorn acknowledges a write only once every healthy replica has it.
  - CNPG in synchronous mode acknowledges a commit only once a standby has it.
  - Vault raft commits on a majority.
- **`dataDurability: preferred` vs `required`** (CNPG): with 2 instances, `required` would stop every write when the standby is gone, which takes down sign-in on a single failure. `preferred` keeps writing alone, so data is lost only if the primary then dies too before the standby is back (a **double** failure). With 3 instances, `required` has no availability cost. The Hub shows the current guarantee on the HA page: "Zero loss on one failure" / "Degraded: one more failure may lose the last writes".
- **Longhorn with 2 replicas** behaves the same way: after one failure it rebuilds a new replica on another storage node when one exists. Until the rebuild finishes, the volume is "degraded" and shown that way.
- **Across sites, nothing is synchronous** (§4). DR copies lag by seconds to minutes (§11.5).

### 8.3 The shared NFS tier

- **Server:** the kernel NFS server (`nfsd`, NFSv4.2 only) on nodes labelled `nfs`. It is configured by the node install script and kept in sync by a small node-side Portcullis agent (`portcullis-nodeagent`, §16.1) from Hub state. Exports are restricted to the mesh addresses of cluster nodes, with `sec=sys` (assistant's call: every node is a trusted cluster member, and root on any node is already cluster compromise). Rejected: an in-cluster NFS-Ganesha pod, because it is one more pod on the data path and its volume would itself need a tier.
- **Client:** `csi-driver-nfs` with **static PVs**, one per shared folder (the contract §14 folders keep their identity, groups, ACL rules and fixer), and a StorageClass `portcullis-shared-<node>` for dynamic subdirectories. Rejected: `nfs-subdir-external-provisioner`, which offers less (no CSI, no snapshot hooks) and is maintained less.
- **Ownership and ACLs:** the folder fixer (`folderfix`) runs **on the NFS node** through `portcullis-nodeagent`, not over NFS. ACL semantics over NFSv4 differ from POSIX ACLs on the server, and the fixer needs the real filesystem.
- **Failure:** single copy, by the user's choice. While the NFS node is down, pods that mount its exports wait (`hard` mounts, so no silent write loss), and the Hub shows "waiting for <node> (shared storage)". Optional asynchronous replication of a dataset to a second NFS node (ZFS send, §9.2) offers a manual "serve from <node2>" switch with the data-loss warning (phase 4).

### 8.4 Fencing and split-brain protection

This is the core of "protection against divergence". There are three layers (assistant's call):

1. **Quorum or nothing.** The control plane acts only with etcd quorum. A node on the minority side of a partition can't schedule, promote or move anything.
2. **Self-fencing of isolated nodes.** **medik8s Self Node Remediation (SNR)** runs on every node, driven by the **Node Healthcheck Operator**:
   - A node that loses the API server **and** can't reach a majority of its peers reboots itself through its watchdog (the hardware watchdog on the Pi, `softdog` elsewhere) within a bounded time `T_fence`.
   - The healthy side waits `T_fence` plus a margin before it treats the node as fenced. It then applies the Kubernetes `node.kubernetes.io/out-of-service` taint (non-graceful node shutdown), which force-deletes the node's pods and detaches their volumes.
   - Only then do Longhorn volumes attach elsewhere and replicated-tier pods start elsewhere.
   - Defaults: `T_fence` = 60 s, toleration for not-ready/unreachable = 30 s on HA pods. That gives about 2–4 min from failure to a running stateful app.
3. **Application fences.**
   - CNPG's primary isolation check makes a primary that can reach neither the API server nor its standbys shut itself down. A failover promotes only a standby that has every synchronously confirmed commit.
   - Longhorn attaches an RWO volume to one node at a time, and after a split it rebuilds stale replicas from the active one rather than merging.
   - The Hub and domains stop writing when their Lease lapses (§7.3).
   - Valkey replicas refuse writes (`replica-read-only`), and Sentinel needs its quorum of 2 to promote.

**What is never done:** a force-delete of a pod or a volume attachment on an unreachable node without the out-of-service step that follows a fence. **Fail stopped, not split:** if fencing can't be confirmed (no watchdog, SNR unhealthy), stateful failover does not happen. The app stays down and the doctor raises `ha_fencing_unavailable` (Problem). The HA checklist (§6.3) requires a working watchdog on every node that holds replicated-tier pods.

## 9. Snapshots, history, backups and offsite

### 9.1 One Snapshot model, native mechanisms underneath

The Hub's model has a single concept, the **snapshot**: a point-in-time copy of every volume of an instance, crash-consistent by default and app-consistent when the template declares a quiesce hook (§12.1). It is backed by each tier's native mechanism, all through **external-snapshotter** (the CSI `VolumeSnapshot` CRDs and controller, installed by Portcullis):

| Tier | Backing | Where the copies live |
|---|---|---|
| replicated | Longhorn snapshots (`VolumeSnapshotClass` `type: snap`) | in the volume's replicas |
| local on ZFS | OpenEBS ZFS LocalPV snapshots (`zfs snapshot`) | the node's pool |
| local without ZFS | none. The Hub says "no snapshots on this volume (not on ZFS)" and offers the backup instead | — |
| shared on ZFS / btrfs | `zfs snapshot` / `btrfs subvolume snapshot -r` of the folder's dataset or subvolume, by `portcullis-nodeagent` | the NFS node |
| CNPG | not a snapshot: continuous WAL archive + base backups = point-in-time recovery | backup destination |

- **btrfs:** no mature btrfs CSI driver exists, so **btrfs is supported on the shared tier** (host-level snapshots), **ZFS on both local and shared**, and btrfs PVCs are parked (assistant's call, accepted with Q3).
- **Consistency group:** an instance's snapshot covers all its volumes. Across tiers it is "taken within the same few seconds", not atomic. For app consistency the template's quiesce hook (for example `nextcloud occ maintenance:mode --on`, or a database `CHECKPOINT`) runs before the snapshot and is undone after it, under the existing ops/progress model.

### 9.2 Both uses the user asked for

- **Quick undo before risky changes.** Before an app update, a settings apply that the template marks risky, a restore into an existing instance, a move, or a template-declared migration job, the Hub takes an **undo snapshot** of every volume that supports one (assistant's call: automatic, kept 7 days, matching the multi-server undo window). **Undo** on the instance page stops the instance, rolls each volume back (Longhorn revert, `zfs rollback` after an undo-of-the-undo snapshot, btrfs subvolume swap), restores the previous template version and settings, and starts it. The confirm dialog names the time and says that everything written since is lost.
- **History and offsite.**
  - *Scheduled snapshots* per instance: off, hourly, daily or weekly, keeping the last N of each (default for HA instances: hourly ×24, daily ×7).
  - A snapshot is also the **consistent source** for the offsite backup. The backup job reads from the snapshot, never from the live volume, so app downtime for backups drops to the quiesce window. Today's instance backups stop the instance (multi-server spec §9).

### 9.3 Backup destination and offsite

- **One backup destination** per install, set on Settings → Backups: an S3-compatible URL plus credentials (any provider, or a MinIO/Garage instance **outside** the cluster). Every mechanism writes there:
  - Longhorn backups (incremental, block-level, restorable into a new volume on any cluster);
  - CNPG WAL and base backups (barman-cloud plugin);
  - restic for shared-tier and local-tier snapshots (file-level, deduplicated);
  - the core `backup` archive (restic, as today).

  **HA can't be turned on without a destination outside the cluster** (user ruling with Q1): offsite copies are what make losing two nodes, or a site, survivable.
- **ZFS replication between nodes** (`zfs send -i`, a syncoid-style job run by `portcullis-nodeagent` over the mesh) is offered for the shared tier as a second local copy. It is the source of "serve from the other NFS node" (§8.3) and of the Docker assisted recovery (§14).
- **Restore** stays runtime-neutral: an instance backup restores into Docker, Podman or a cluster (the kube spec's format), and a Longhorn backup restores only into a cluster.

## 10. Priorities, resources, placement, admission

### 10.1 Priority classes (installed by core)

| PriorityClass | Value | Preemption | Who |
|---|---|---|---|
| `portcullis-core` | 1 000 000 | yes | core only (admission refuses it on app pods) |
| `portcullis-critical` | 100 000 | yes | apps the admin marks Critical (DNS filtering, password manager) |
| `portcullis-high` | 10 000 | yes | High |
| `portcullis-normal` | 1 000 (global default for apps) | yes | Normal |
| `portcullis-low` | 100 | `Never` (it never preempts anything) | Low: first to stop when capacity is short (media transcoders, AI chat) |

- **The admin chooses** the priority per instance (Instance → Manage → Availability). The template may suggest a default (`ha.priority`, §12.1), but the admin's choice wins (user's decision 3).
- **Preemption** does the rest: after a failure, pending higher-priority pods evict lower-priority ones when capacity is short. The Hub explains it on the instance page ("stopped to make room for <higher> after <node> failed").

### 10.2 Requests and limits

- **Memory:** compose `mem_limit` becomes request = limit (as today; Guaranteed-style memory). Templates without a `mem_limit` get the default 512 Mi request and limit on Kubernetes (assistant's call), with a doctor Info `template_no_memory_limit`.
- **CPU:** a request from the new optional manifest field `resources.cpu` (default 50m), and **no CPU limit** (throttling hurts latency more than it protects). The admin can override both in the Expert view, as `mem_limit` today.
- **The resource-usage page** (`2026-11-14-resource-usage-design.md`) gains a "request vs used" column on Kubernetes. That makes overstated and understated requests visible, and the doctor suggests corrections (Info).

### 10.3 Placement

- **Per instance**, *Runs on*:
  - **Anywhere** (default; never `small` nodes);
  - **Prefer** a class, site or node (preferred node affinity);
  - **Only** chosen nodes (required affinity, plus the `small` toleration when a small node is chosen).
- **Spreading:** replicas of `replicated` / `independent` services are spread across hostnames. For CNPG-backed apps, the template's database goes on the instance's local tier and follows the same anti-affinity.
- **Admission** (new ValidatingAdmissionPolicy rules, guarding what the Hub's Role can create):
  - app pods may use only `portcullis-critical|high|normal|low`;
  - the `small` toleration only together with a required node affinity naming small nodes;
  - no `nodeName`;
  - `topologySpreadConstraints` and affinity only on Portcullis labels;
  - `replicas` above 1 only on a Deployment or StatefulSet of a service its template declares `replicated` or `independent` (the `replicas > 1` refusal of the kube spec becomes conditional).

### 10.4 The N−1 check ("don't overwhelm the nodes that can't sustain it")

- For each node, the Hub simulates its loss. Every pod on it at `portcullis-core`, `critical` or `high` must fit (by requests, taints and affinity) into the remaining allocatable, after evicting `normal` and `low` pods.
- **Results:**
  - green: everything fits;
  - yellow: high priority fits only by evicting normal;
  - red: critical or core doesn't fit.

  It is shown per node on the HA page, and the doctor raises `ha_n_minus_1_insufficient` (Problem when red).
- **When it runs:** on every placement change, and **before** an admin raises an instance to Critical or High. The dialog says "if <node> fails, <x> won't have room".
- **Implementation:** a scheduler-faithful simplification (resource fit, taints/tolerations, required affinity, anti-affinity), not a full scheduler. Its limits are documented, and the builder compares it with the real scheduler in the chaos tests (§18).

## 11. The front door: DNS failover, certificates, CAA

### 11.1 DNS failover (user's decision 9; the design is the assistant's call)

- **Multi-address answers, with health-based removal.** The `address` set of the main domain and of every added domain (`<d>`, `*.<d>`) holds **one A (and AAAA) per healthy ingress node**, not just one. Browsers and most HTTP clients try the next address when a connection fails, so a dead node costs a few seconds of retry rather than a TTL. Removal of the dead address is the second step. This is what keeps failover fast even with Porkbun's 600 s TTL.
- **Who decides:** the **front-door role** of the domains service. It is one Lease-guarded writer, so a minority partition can't flip DNS.
- **Health of an ingress node** = all of:
  - the node is Ready;
  - its Traefik pod is Ready;
  - an HTTPS probe of `https://auth.<d>/healthz` **sent to that node's public address**, run from every other node's `portcullis-nodeagent`, passes for a majority of probers. That catches broken NAT and port forwarding, which in-cluster checks don't see;
  - when there are 2 sites, probers from at least 2 sites.
- **Hysteresis:**
  - remove after 3 failed rounds 10 s apart (~30 s);
  - add back after 2 min of passing;
  - at most one change per name per 60 s.
- **Fail static:** never remove the last address. If every node looks unhealthy, the set stays as it is: the problem is more likely the probers' side than all ingress nodes at once (the same rule as Route 53's "all unhealthy = all healthy").
- **Record writes** follow the DNS spec rules: append the new values first, then delete only the exact stale values by record ID (Porkbun, legacy Hetzner). The A/AAAA TTL is 60 s where the provider allows it, otherwise the provider's minimum (Porkbun: 600). The HA page shows the resulting worst-case failover time for each name ("worst case ~10 min for clients that hit the dead address first, on Porkbun").
- **Other names follow their service, not the ingress set.** `MAIL_HOSTNAME` (§13.1) and the VPN endpoint (§13.2) are separate record sets that point at the node running that service. The apex stays in the ingress set.
- **DNSSEC** is unaffected: the provider signs, and the record changes are ordinary updates.

### 11.2 Certificates with several Traefik replicas

Traefik's built-in ACME resolver can't be shared by several replicas: each would register its own account, and the CAA `accounturi` pin would break. In HA mode (assistant's call):
- **The domains service issues the main domain's certificate too,** through the front-door role, with its **own** ACME account, separate from the added-domains account, so the DNS spec's "one account per name" pin and least privilege hold.
- Every Traefik replica fetches certificates from the domains service's existing mTLS HTTP provider endpoint (contract §12.4). The "only added-domain names" rule becomes "only Portcullis names: the main domain and added domains", and the type that can carry only `tls.certificates` stays.
- Traefik keeps the last fetched configuration while domains is down, so a domains failover doesn't interrupt TLS. `acme.json` and Traefik's resolver are not used in HA mode.
- **CAA:** the main domain is pinned to the front-door account URI. Turning HA on is an **account switch** for the main domain, so it runs the DNS spec's fail-safe sequence: relax to CA-only → wait the real TTL (settle file) → issue with the new account → re-pin. The same applies to `ACME_STAGING` flips in HA mode.
- **Staging on the test server:** the test server is always `ACME_STAGING=true` (memory note). The HA test cluster uses staging too, and the front-door account is a staging account. The public would-issue check runs before every flip, as today.

### 11.3 The credentials question

DNS failover and HA certificates both need a **long-running** component that holds the **main domain's** DNS credentials. That is not new: Traefik already holds them today for ACME DNS-01 renewals (core `docker-compose.yml`, `TRAEFIK_CERTIFICATESRESOLVERS_LETSENCRYPT_ACME_DNSCHALLENGE_*` and the provider token). The DNS spec's rule is that the domains service and the Hub never hold them. So the front-door role is **a second consumer, not a reversal of a rule** (user ruling, Q1).

In HA mode, Traefik's resolver is off (§11.2), so the front-door role becomes the **only** holder. The count stays at one. It is contained as follows:
- a separate process and Secret, with no API besides health; the domains service's added-domain code and the Hub never see the credentials;
- only the main domain's records: `address`, `caa` and `_acme-challenge` (plus `MAIL_HOSTNAME` and the VPN endpoint name when those follow their service, §11.1);
- the narrowest token the provider allows (a zone-scoped Cloudflare token; Porkbun has only account-wide API keys, and the HA page says so);
- HA mode requires the offsite backup destination (§9.3, kept as a prerequisite by the user).

### 11.4 Ingress nodes and ServiceLB

- Traefik runs as a **DaemonSet on `ingress` nodes**.
- k3s ServiceLB publishes 80/443 only on nodes labelled `svccontroller.k3s.cattle.io/enablelb=true`, which Portcullis sets together with `portcullis.io/ingress`.
- `externalTrafficPolicy: Local` keeps the client IP, as the kube spec requires.
- Home nodes behind NAT are ingress nodes only if the public probe passes (port forwarding is the user's router setting, and the HA page shows how).

### 11.5 Two sites (phase 4)

- The site with the tie-breaker (or a third location, such as a small cloud VM or a Pi at a friend's house) keeps quorum.
- Within the primary site everything is synchronous. Toward the other site:
  - a CNPG **replica cluster** (asynchronous streaming);
  - Longhorn **DR volumes** (continuously restored from the backup destination);
  - ZFS send for the shared tier.
- **The rule (user ruling, Q2): asynchronous across sites, but "do not start unless the volumes were fully synced".**
  - Within a site, replication is synchronous and loses nothing (§8.2).
  - Across sites it is asynchronous, so it **can't guarantee the last ~seconds of writes**. "Confirmed caught up" **bounds** the loss; it doesn't eliminate it. Writes acknowledged at the primary site after the last heartbeat could still be lost.
- **Sync heartbeat.** A `portcullis-nodeagent` on the primary site publishes, at least every second and per instance (core counts as one instance), the replication position of each of its volumes. The DR site records its own applied position for each:

  | Mechanism | Primary-site position | DR-site position | Caught up when |
  |---|---|---|---|
  | CNPG replica cluster | current WAL LSN | replayed LSN | equal |
  | ZFS send (shared tier) | latest snapshot and a "written since" flag (`written@<snap>` = 0) | latest received snapshot | the same snapshot, and nothing written since it |
  | Longhorn DR volume | the last backup id and whether the volume was written since | the last restored backup id | the same id, and no write since |

  A volume that is busy and backed up periodically is therefore rarely caught up. That is honest, and it pushes the decision to the admin, as the rule wants.
- **Automatic promotion at the DR site happens only when all three hold for every volume of the instance:**
  1. **Zero lag:** caught up at the last heartbeat received.
  2. **Freshness:** that heartbeat came at most **5 s** before the primary site went silent (`T_sync`, a setting, at most 30 s).
  3. **Fencing holds:** the DR site has quorum, with the tie-breaker at the third location. The primary site is the minority, so its nodes have self-fenced (§8.4), and the healthy side has waited `T_fence` plus the margin before it acts.

  Core is judged like any instance, so sign-in comes up at the DR site on its own only when Postgres and Vault were caught up.
- **Otherwise nothing starts on its own.** The instance stays down, and the Hub raises an **admin decision** on the HA page and the instance page:
  - **Wait for <primary site>:** no loss. The instance comes back when the site returns.
  - **Promote at <DR site>:** accept the reported window: "writes after <time of the last confirmed position> (up to <lag>) are lost". This needs a fresh sign-in and the typed instance id, is audited as `ha.site_promote` with the lag shown, and is never offered over MCP.
  - Without quorum at the DR site (no tie-breaker reachable), promotion goes through `./portcullis ha recover` (§15.4) on the DR site, with the same warning.
- **When the old site returns** after a promotion, its copies are superseded and never merged. The returning site rejoins as the new DR target and resyncs from the promoted side. Its diverged data is kept 7 days, stopped, as in §14.

## 12. Apps: what templates declare, what the admin chooses

### 12.1 Manifest fields (contract §3, new `ha:` block; assistant's call on the shape)

```yaml
# manifest.yaml (excerpt)
ha:
  mode: failover          # single | failover | replicated | independent
  priority: normal        # suggestion only; the admin chooses (§10.1)
  services:               # only for replicated / independent
    web: {replicas: {min: 2, max: 3}}
  quiesce:                # optional, app-consistent snapshots (§9.1)
    service: nextcloud
    before: ["php", "occ", "maintenance:mode", "--on"]
    after:  ["php", "occ", "maintenance:mode", "--off"]
volumes:
  data:
    tiers: [replicated, local, shared]   # allowed, first = default
    size: 20Gi                           # default request; the admin may change it
  db:
    tiers: [local]
    replicated_by_app: false
  media:
    tiers: [shared]                       # the "movie library" kind
    optional: true
resources:
  cpu: 100m
```

- **`mode`:**
  - `single`: never moves on its own (device apps, anything not declared);
  - `failover`: one copy, fenced reschedule (the default for templates with volumes, once they declare tiers);
  - `replicated`: several stateless replicas behind the routed Service (the template certifies that the app supports it);
  - `independent`: several **independent** instances with their own volumes, each answering on its own address. This is DNS filtering (§12.3).
- **`volumes`:** per compose named volume, which tiers the template supports (for example SQLite on NFS is unsafe, so such a volume lists no `shared`). An undeclared volume defaults to `[local]` (on Kubernetes non-HA, exactly as today).
- **Validation:** `validate.py` and the Hub share vectors, as for `RuntimeCompat`. A `replicated` service must have no named volume, and a `shared` tier must not be the only tier of a volume that a database writes (a template marks such volumes `db: true`).

### 12.2 What the admin chooses (setup form and Instance → Manage → Availability)

- **Per instance:**
  - the priority (§10.1);
  - *Runs on* (§10.3);
  - the HA mode within what the template allows (for example a `replicated` template can still run as `failover`);
  - the replica count within `min..max`;
  - the snapshot schedule (§9.2).
- **Per volume:**
  - the tier from `tiers`;
  - its size;
  - for replicated, the copy count (2 or 3, limited by the number of storage nodes);
  - for shared, which shared folder or NFS node.

  **Example (the user's):** Nextcloud's `data` on replicated ×2 and the external storage `media` bound to the shared folder "Movies" on the NFS node, while its MariaDB `db` sits on local next to the Nextcloud pod. Only the movie library is single-copy.
- **Changing a tier later** is a guarded operation:
  1. stop;
  2. snapshot;
  3. copy into a new volume of the new tier (the existing `hub volcopy` helper pods);
  4. swap;
  5. start.

  The old volume is kept 7 days, like *Undo move*.

### 12.3 DNS filtering as the reference "shared service"

Pi-hole / AdGuard Home run `independent` with 2 instances, one pinned to the Pi and one to another node. Each publishes port 53 through a LoadBalancer Service on its own node (`lan_only`), and both are given out as DNS servers (the admin's DHCP setting, which the Hub shows). The Hub renders the same settings into both (contract §13 settings with `scope: instance` applied to both). There's no shared state to diverge, because the block lists come from the same settings and each copy keeps its own query log.

### 12.4 Prerequisite: templates that run on Kubernetes

HA apps are Kubernetes apps, and only about 5 templates run there today. The numeric-user follow-up for the remaining templates (memory: about 40) is therefore a **prerequisite** of app HA and is scheduled as part of phase 2 (§19). The core HA of phase 1 doesn't depend on it.

## 13. Mail, VPN, monitoring

### 13.1 Mail

- **Order:** mail on Kubernetes comes after the mail-provider rework (user's sequencing: after multi-server) and after the provider slot allows Kubernetes (the mail-provider spec refuses it). It is phase 4.
- **The model then** (assistant's call):
  - The wired mail provider runs `failover` (one copy, replicated-tier volumes) on nodes labelled `mail`: a static public IP with PTR, port 25 open in both directions, which in practice means cloud nodes.
  - Port 25 is published on the node running the pod (`externalTrafficPolicy: Local`, because SMTP checks need the client IP).
  - `MAIL_HOSTNAME`'s A/AAAA follows the pod through the front-door role (§11.1). The SPF `ip4:`/`ip6:` lists every `mail` node, and each `mail` node needs its own PTR. The HA page lists any missing ones, because the user has to set PTR at the hosting provider.
  - Outbound SMTP leaves from the node running the pod. Its address is in SPF, and the HELO name matches that node's PTR.
  - One `mail` node means mail is `single` (no failover), and the page says so.
- **Testing** follows the user's rule: no outbound port-25 connections. Delivery is tested in-cluster only (§18).

### 13.2 VPN

- The `wg` people role and the VPN-only modes work as on single-node Kubernetes (contract §16.1).
- **Endpoint:** `wg-people` is a LoadBalancer on the ingress nodes. With `externalTrafficPolicy: Cluster`, any ingress node forwards to the `wg` pod. The client's source address is SNATed, which WireGuard tolerates (replies go back the same way), and VPN identity comes from keys, not addresses (assistant's call).
- **Client caveat:** WireGuard clients resolve the endpoint name once, when the tunnel is brought up, and most don't fall back to another address. After an ingress node failure, devices pointed at the dead address must reconnect (toggle the tunnel) to pick up a healthy one. With `PORTCULLIS_VPN_MODE` set so that everything is VPN-only, this is the main remaining user-visible failover cost, and the docs say so plainly. A `wg` pod reschedule (its node died) is the same disruption.
- **The `link` role** (multi-server) isn't used inside a cluster (§16).

### 13.3 Monitoring and alerts

New alerts (Alertmanager has 2 meshed replicas, so it survives any one node), doctor kinds and HA-page tiles:

| Alert / doctor kind | Severity | When |
|---|---|---|
| `PortcullisNodeDown` / `node_down` | Problem | node NotReady > 1 min |
| `PortcullisQuorumAtRisk` / `ha_quorum_at_risk` | Problem | etcd, Vault raft or Sentinel has exactly a bare majority |
| `PortcullisQuorumLost` | Critical | no majority (sent from the surviving nodes' Alertmanager) |
| `PortcullisVolumeDegraded` / `volume_degraded` | Warning | a Longhorn volume below its copy count > 10 min |
| `PortcullisPostgresNotSynchronous` / `pg_not_synchronous` | Warning | no synchronous standby (degraded to async) |
| `PortcullisFailover` | Info | a CNPG, Sentinel, DNS or app failover happened (what, where, how long) |
| `ha_fencing_unavailable` | Problem | SNR or watchdog unhealthy on a node with stateful pods |
| `ha_n_minus_1_insufficient` | Problem / Warning | §10.4 |
| `PortcullisDNSFailoverStuck` | Warning | an unhealthy address still published after 5 min (write failing) |
| `PortcullisBackupStale` / `backup_stale` | Warning | no successful offsite backup for 26 h (any mechanism) |
| `PortcullisSmallNodePressure` | Warning | memory pressure on a `small` node |

- **External dead-man's switch** (opt-in, assistant's call): the existing Watchdog alert can ping a URL the admin provides (healthchecks.io or their own). It is never on by default (the user's rule against unprompted outbound connections). Without it, "the whole cluster is down" can only be noticed from outside.
- **Grafana** gets a dashboard for the cluster: nodes, quorum, failovers, volume health, replication lag.

## 14. Docker multi-server: assisted recovery (user's decision 7)

This builds on `ms1`, and none of it is automatic.

- **Alerts:** `server_offline` (existing) plus a new *Recovery* card on each affected instance after 5 min offline.
- **"Bring it up elsewhere"** (admin, fresh sign-in, typed instance id):
  - It lists the **latest restorable copy** with its age: the newest of the per-server scheduled backup (on the primary), the newest offsite backup, and, when the dead server replicated its ZFS datasets to another server (§9.3, opt-in), the newest replicated snapshot.
  - It warns "changes after <time> on <server> are lost unless that server comes back".
  - It restores into the same instance id on the chosen server (`ms1` restore machinery) and switches the relays. The old placement is marked **superseded**.
- **Return of the dead server** (the divergence guard): when it reconnects, the Hub sends `down` for every superseded project **before** the server returns to `ready`. Its volumes are kept, stopped and labelled "diverged copy from <date>", for 7 days, with a doctor Info. They are never routed and never merged. The agent refuses `up` for a superseded project until the Hub clears it.
- **Native snapshots on Docker servers** (ZFS/btrfs) are taken by the agent through a new fixed-spec helper. They give the same quick undo before updates as §9.2, and they feed the optional ZFS replication between servers.
- **The primary itself** has no assisted recovery beyond today's primary DR (restore onto a new host). That is the main reason to move to Kubernetes, and the Servers page says so.
- **The upgrade path** is §15.3.

## 15. Migration paths

All of them run as Hub operations with progress and Stop, plus a CLI twin. Each step is resumable, and each announces its downtime first. Following the no-back-compat rule, there is no long-lived compatibility mode: old data is converted once.

1. **Docker single-server → HA cluster:**
   - `./portcullis backup` (runtime-neutral);
   - `init --runtime kubernetes` on the same or a new machine (installs k3s with `--cluster-init`);
   - `restore`;
   - add 2+ nodes from the Hub (§6.2);
   - **Make HA** (§6.3).

   On the same machine this is the kube spec's backup → init → restore, plus the new steps.
2. **Single-node Kubernetes (experimental) → HA:**
   - k3s is restarted with `--cluster-init` (SQLite → etcd, k3s's own conversion) when it isn't already on etcd;
   - nodes are added;
   - **Make HA** then:
     - converts LLDAP's SQLite into the CNPG database (LLDAP's documented migration path);
     - moves Postgres into CNPG (`pg_dump` → import, or CNPG's `import` bootstrap);
     - moves `hub-data` into `hub-state` plus the published documents (§7.2);
     - moves `domains-data` and `wg-data` to the replicated tier;
     - joins Vault voters;
     - switches Traefik to the DaemonSet and the front-door certificates (with the CAA flip, §11.2);
     - scales out the gates.

   Expected sign-in downtime is a few minutes, plus the CAA wait (which doesn't stop sign-in, since the old certificate stays valid).
3. **Docker multi-server → HA cluster:** the primary converts as in path 1. Then, server by server, "Convert to a cluster node":
   - back up its instances (per-server backups);
   - `worker leave`;
   - join as a cluster node with the same machine (§6.2);
   - restore the instances into the cluster, placed on that node (*Runs on: Only <node>*) so data locality is kept, then relax placement once the volumes are replicated.

   Per-instance downtime is its backup + restore time, the same as an `ms1` move.
4. **Quorum-lost recovery** (not a migration, but the same machinery): when two of three nodes are gone for good, `./portcullis ha recover` on the survivor resets etcd to a single member (k3s `--cluster-reset`), shrinks Vault raft to its own peer, promotes the local CNPG instance if it is the most advanced (otherwise it restores from the backup destination), and shows exactly what may be lost before it acts.

## 16. Relation to the multi-server agent and the WireGuard link

### 16.1 Agent and enrolment

- **Reused:** the join-code shape, the HMAC enrolment, `pki_node` (new role `node-cluster`), the Servers page, the `server_enrol` op, revocation, and the "fresh sign-in, typed id, never over MCP" rules (§6.2).
- **Not reused:** the worker agent's engine API. On cluster nodes the Kubernetes API replaces it. The small host-side pieces that Kubernetes can't do run in **`portcullis-nodeagent`**, a fixed-function host service on each node (systemd unit, Go, in the Hub repo next to `portcullis-agent`, sharing its mTLS and enrolment code). Its jobs:
  - NFS exports;
  - host-level ZFS/btrfs snapshots and ZFS send for the shared tier;
  - the fixer on NFS nodes;
  - the public ingress probes (§11.1);
  - host checks.

  It answers only to the Hub's `hub.control` certificate over the mesh, and it accepts only fixed operations (the same "no arbitrary exec" rule as the worker agent).

### 16.2 One network?

- **Node traffic** (API server 6443, etcd 2379/2380, kubelet 10250, Longhorn, NFS, pod traffic) runs over a **dedicated node mesh**: kernel WireGuard via k3s's `--flannel-backend=wireguard-native` for pods, and a Portcullis-managed WireGuard interface `pcmesh` for node addresses (assistant's call).
  - Subnet: `10.215.0.0/24`, fixed. It is separate from link (`10.214.0.0/24`) and from the people VPN, and checked against both.
  - Keys come from enrolment.
  - Every node holds the full peer list (static, no coordinator needed at runtime).
  - k3s uses `--node-ip` on the mesh address.
- **Why not the `link` role:** link is a star through the primary with zero listeners on the primary side, and every connection is opened by the primary. A cluster needs a full mesh that survives the loss of any node, including the "primary". The VPN spec's user ruling (one WireGuard implementation for server tunnels) is about the userspace link role. The mesh is kernel WireGuard because Longhorn and etcd traffic needs kernel throughput. The link role stays for Docker workers, and the cluster mesh is kernel WireGuard (Q3, accepted).
- **Phase 1 (one LAN):** the mesh still runs, so that the addresses are stable and encrypted. Phase 4 adds NAT traversal across sites: every site needs at least one node that is reachable (a cloud node always is; a home node needs one UDP port forwarded), and peers behind NAT keep their tunnel up with a 25 s keepalive.

## 17. Security deltas (for `hardening.md`)

- **New privileged components:**
  - `nodeadm`: holds the server token, and can create only short-TTL bootstrap tokens (VAP-guarded);
  - SNR / Node Healthcheck: can reboot nodes and taint them `out-of-service`;
  - the Longhorn manager (privileged DaemonSet, host iSCSI);
  - CNPG (manages Postgres pods in its namespaces);
  - csi-driver-nfs and zfs-localpv node plugins (privileged).

  All of them are third-party operators or drivers in their own namespaces (except `nodeadm`). They are installed and upgraded only by the CLI, pinned by digest (`images.yaml`), have no rights in `portcullis-apps` beyond what their CSI role requires, and are judged by the admission policies like any identity except the CLI.
- **The Hub gains:**
  - the named-documents Role in the core namespace (§7.2);
  - `create`/`get`/`list`/`delete` on `volumesnapshots` in `portcullis-apps`;
  - the right to request codes from `nodeadm`.

  It still has no cluster-scoped verb and no token.
- **Main-domain credentials** in the front-door role (§11.3). This is a second consumer of credentials Traefik already holds (user ruling, Q1). In HA mode it is the only holder, because Traefik's resolver is off there.
- **Joining a server node** = cluster-admin on that machine. That is stated in the dialog, and it requires a fresh sign-in.
- **The mesh:** etcd, kubelet and Longhorn ports listen only on mesh addresses. `status` and the doctor (`kube_api_public`, extended per node) check every node's public address.

## 18. Technology picks (assistant's calls)

| Need | Pick | Considered | Why |
|---|---|---|---|
| Cluster datastore | **k3s embedded etcd**, 3 servers | k3s + external Postgres/MySQL (kine); dqlite | no extra database to make HA; native to k3s; `--cluster-init` from the start |
| Replicated block storage | **Longhorn** (v1 data engine), 2–3 replicas | OpenEBS Mayastor; Rook/Ceph | Longhorn runs on arm64 and modest nodes, has snapshots, backups to S3, DR volumes, node/disk tags and a UI. Mayastor needs hugepages, dedicated cores per io-engine and NVMe-oF. Ceph wants ~4 GB per OSD plus monitors: too heavy for a home cluster with a Pi |
| Postgres | **CloudNativePG** + barman-cloud plugin | Zalando operator (Patroni); Crunchy PGO | Kubernetes-native (no external DCS), synchronous replication controls, a primary isolation check, fencing annotations, volume-snapshot and PITR backups, CNCF project, arm64 images. Zalando is solid but slower-moving with a Patroni-in-pod model. Crunchy is heavier, and its image licensing terms need a separate review |
| Sessions | **Valkey + Sentinel** (3 sentinels, primary + replica), rendered by the core chart | Valkey Cluster; a Valkey operator | oauth2-proxy speaks Sentinel; sharding isn't needed; no mature operator |
| Keycloak clustering | **embedded Infinispan, JDBC_PING**, persistent user sessions | Keycloak Operator; external Infinispan | no extra discovery or service, using Keycloak 26 defaults; the operator adds a CRD for little gain here |
| Shared tier | **kernel nfsd on nodes + csi-driver-nfs** (static PVs) | nfs-subdir-external-provisioner; NFS-Ganesha in-cluster | a maintained CSI driver; the server stays outside the pod data path |
| Local tier with snapshots | **OpenEBS ZFS LocalPV**; the existing local-path elsewhere | LVM LocalPV (thin snapshots); btrfs CSI (no mature driver) | ZFS is native and mature, with send/receive for replication |
| Snapshot API | **external-snapshotter** (CRDs + controller) | — | required by Longhorn, ZFS LocalPV and CNPG volume snapshots |
| Fencing | **medik8s Self Node Remediation + Node Healthcheck Operator**, Kubernetes out-of-service taint | Longhorn's node-down pod deletion alone; a home-made watchdog | watchdog-backed self-fencing with peer checks; a library rather than our own cluster logic (user preference: mature libraries) |
| Front door | **domains service front-door role** (lego + the libdns providers incl. our Porkbun v3 client) | cert-manager + external-dns | reuses the providers, CAA, TTL waits and the HTTP certificate provider we already have; cert-manager has no Porkbun support without a third-party webhook |
| Leader election | **client-go `leaderelection` Leases** | — | standard |
| Node mesh | **kernel WireGuard** (`wireguard-native` flannel + `pcmesh`) | the userspace link role; Tailscale/Headscale integration | throughput, no coordinator at runtime, no dependency on an app hosted on the cluster itself |

## 19. Phases, effort, testing, and what the builder verifies

### 19.1 Phases (MVP first)

Effort is in working days for the assistant's build loop (plan → build → review → CI → test server). It is estimated from this design, not from memory (an earlier estimate was badly low), so treat each upper bound as the realistic one.

| Phase | Scope | Effort |
|---|---|---|
| **0. Spikes** | 3 VMs + a Pi-class arm64 VM: k3s `--cluster-init` join and leave; Longhorn on arm64 with a USB SSD; SNR fencing under a real partition (iptables drop) and power-off; CNPG sync failover with the isolation check; Keycloak JDBC_PING ×2; LLDAP ×2 on one Postgres; oauth2-proxy over Sentinel; etcd on the Pi | 4–6 |
| **1. Core HA + replicated storage, 3 nodes, one site (MVP)** | k3s install from `init`; `nodeadm` + join from Hub/CLI; node labels and taints; mesh (LAN); Longhorn, external-snapshotter, CNPG, SNR installed by the CLI; core chart HA (§7); published documents (§7.2); the Hub single-writer on `hub-state`; priority classes, admission changes; N−1 check; front-door DNS failover + HA certificates + CAA flip; HA page, alerts, doctor; `ha enable`; migration path 2 (single-node Kubernetes → HA); CI and chaos tests; docs and contract | 18–25 |
| **2. App HA and storage tiers** | Templates runnable on Kubernetes (numeric users, the ~40-template follow-up; 6–8 of the days); manifest `ha:` / `volumes:` / `resources:`; setup form and Availability tab; replicated / independent modes; tier changes; the shared NFS tier + `portcullis-nodeagent` + fixer on NFS; ZFS LocalPV; snapshots (undo + schedules + app quiesce); backup destination with Longhorn, CNPG and restic offsite | 18–24 |
| **3. Migration + Docker assisted recovery** | Migration paths 1 and 3; Docker recovery card, superseded/diverged guard, agent snapshots, ZFS replication between servers; `ha recover` | 8–12 |
| **4. Multi-site and the rest** | Mesh across NAT; tie-breaker at a third location; CNPG replica cluster, Longhorn DR volumes, assisted site failover; NFS second copy and switch; Hub state in Postgres + hot standby; mail on Kubernetes + `mail` nodes (after the mail-provider rework) | 18–25 |

Total: about 65–90 working days. Phase 3's assisted recovery doesn't depend on Kubernetes and can run in parallel with phase 1 once `ms1` is merged.

### 19.2 Testing

- **Unit and envtest (Hub):**
  - translator goldens for replicas, affinity, tolerations, PriorityClasses and tiers;
  - the new admission vectors (shared fixtures with core, as today);
  - N−1 simulator vectors;
  - front-door hysteresis and fail-static vectors;
  - the Lease single-writer test (a second Hub never writes).
- **Core CI, `e2e-ha-k3d` (new, GitHub runner):**
  - k3d with 3 servers + 1 agent (an agent labelled `small`);
  - Longhorn doesn't run in k3d (it needs host iSCSI), so this job uses local-path for apps and covers the **logic**: CNPG failover (delete the primary pod and its node container), Keycloak and gate continuity (a Playwright sign-in loop during the failover asserts at most N failed requests), Sentinel promotion, Vault raft leader loss, Hub Lease handover, the DNS failover against the `testprovider` fake + Pebble (the domains CI pattern), and the N−1 check;
  - the k3d nodes are pinned images and the job is time-boxed.
- **Builder `e2e-ha-vm` (self-hosted, real VMs):**
  - 3–4 fresh VMs created per run, never the builder host itself (memory: never reboot or wipe the shared builder), one of them arm64 small;
  - Longhorn, SNR and CNPG for real;
  - chaos scenarios: power off a node, partition a node (the minority must self-fence; a writer on it must fail; checksums of a test app's data afterwards must match the majority's), kill a disk, fill a disk, lose the Pi, a rolling upgrade under load;
  - mail delivery in-cluster only (no outbound port 25).
- **Test server:** a 3-VM cluster with `ACME_STAGING=true` (config apply + up after init, memory note), the full HA conversion from a Docker backup, and one live failover per component, run by the assistant. The user's own end-to-end check from their laptop is prepared as steps (as for mail).
- **Local first:** run one local cluster at a time on the Mac or the builder, and run full e2e flows locally before pushing, so CI only confirms (memory notes).

### 19.3 What the builder verifies (spikes and facts, not user decisions)

- CNPG: the primary isolation check's version and its defaults; `dataDurability` behaviour with 2 instances.
- LLDAP: multi-replica safety on one Postgres (otherwise 1 replica, §7.4).
- Keycloak 26: JDBC_PING + persistent sessions with the portcullis-keycloak image; behaviour during a rolling upgrade.
- Longhorn on arm64 Pi-class nodes and on nodes whose root is ZFS/btrfs (Longhorn wants ext4/XFS for its data path; a ZFS node gets a zvol or a separate disk for Longhorn).
- SNR on k3s: the watchdog on cloud VMs (softdog), `T_fence` timing, and the interaction with the out-of-service taint and Longhorn's detach.
- etcd on a Pi with a USB SSD: fsync latency under Longhorn rebuild load.
- Client multi-address fallback in current browsers and in the iOS/Android WireGuard apps.
- k3s ServiceLB with `enablelb` labels plus `externalTrafficPolicy: Local` on multiple nodes.
- Porkbun's and Cloudflare's behaviour for multi-value A record sets through our client.

## 20. Answered questions (2026-11-16)

1. **Main-domain DNS credentials in a long-running service** (§11.3). **User ruling: allowed.**
   - It is a second consumer, not a reversal of a rule: Traefik already holds those credentials for DNS-01 renewals.
   - They are held by the front-door role, limited to the main domain's records, with the narrowest token the provider allows.
   - HA mode still requires the offsite backup destination (§9.3).
2. **Cross-site replication** (§11.5). **User ruling:** asynchronous, but "do not start unless the volumes were fully synced".
   - Automatic promotion only when the DR copy was confirmed caught up (zero lag) at a heartbeat no more than 5 s before the primary site went silent, and fencing holds.
   - Otherwise an admin decides: wait (no loss) or promote and accept the reported window (fresh sign-in, audited).
   - Within a site, replication stays synchronous and zero-loss.
3. **The cluster mesh is kernel WireGuard, separate from the userspace `wg` link role** (§16.2), and btrfs is supported for shared-tier snapshots only: accepted as recommended.
4. **A 1–3 min Hub pause after a node failure in phase 1** (§7.3), with the hot standby in phase 4: accepted as recommended.
5. **The one line stays `git clone && ./portcullis init`** (§6.1). No `curl | sh` for the main machine, and the checksum-pinned `join.sh` only for adding nodes: accepted as recommended.

No open questions remain. The spikes in §19.3 are the builder's.
