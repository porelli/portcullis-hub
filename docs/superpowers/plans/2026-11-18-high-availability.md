# High availability on Kubernetes (phases 0 + 1, plus DNS failover across sites) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Portcullis Kubernetes install of 3 or more nodes at one site survives the loss of any one node. Sign-in keeps working, no committed data is lost and nothing ever has two writers.

The cluster may also span **several sites**: nodes at other locations, behind NAT or not, join the same cluster over the node mesh. The public front door then fails over **across sites** by DNS.

Nodes are added from the Hub or the CLI with a join code, and Portcullis installs k3s, the storage, the operators and the fencing itself. Docker single-server doesn't change at all.

**Architecture:**
- **One k3s cluster with embedded etcd**, joined over a kernel WireGuard node mesh `pcmesh`. The mesh spans sites and NAT: a node behind NAT reaches other sites through reachable nodes, and NATed pairs at different sites go through one site gateway.
- **Core** gains:
  - `nodeadm`, the only holder of the k3s token and the only cluster-scoped actor besides the CLI;
  - an HA mode of the chart (replicas, PDBs, spreading, PriorityClasses, CloudNativePG, Valkey Sentinel, Vault raft ×3, a Traefik DaemonSet on ingress nodes at every site). Data and sign-in pieces stay at the primary site;
  - the **front-door** role of the domains service: DNS failover with probes from every site, plus main-domain certificates;
  - `./portcullis ha enable`, which converts a cluster as one resumable operation.
- **The Hub**:
  - is a Lease-fenced single writer on a replicated volume;
  - publishes its documents for other services as named ConfigMaps and Secrets instead of files on a shared `hub-data`;
  - adds cluster nodes through `nodeadm`;
  - computes the N−1 check, the site-aware server layout and the mesh peer plan.
- **`portcullis-nodeagent`** (Hub repo) is the small fixed-function host service on every node: enrolment, mesh peers (across NAT and sites), RTT, host checks and the public ingress probes.

**Tech Stack:**
- **Hub:** Go 1.27, `k8s.io/client-go` v0.37.2 (now also `tools/leaderelection`), `sigs.k8s.io/controller-runtime/pkg/envtest` (tests only), cel-go v0.29.2, `golang.zx2c4.com/wireguard/wgctrl`, vanilla JS.
- **Core:**
  - bash 3.2 + jq 1.8, `kubectl`, `helm`;
  - k3s with `--cluster-init`;
  - Go 1.27 for `nodeadm/` (new) and `domains/` (lego v4.35.2, libdns);
  - Python 3 (`tests/k8s_*.py`, Playwright e2e), promtool;
  - k3d for `e2e-ha-k3d`.
- **Third-party (pinned by the Task 3 report):** Longhorn (v1 data engine), external-snapshotter, CloudNativePG with the barman-cloud plugin, medik8s Self Node Remediation with the Node Healthcheck Operator.
- **Templates:** Python 3. **Docs:** Zensical.

**Spec:** `docs/superpowers/specs/2026-11-16-high-availability-design.md` in portcullis-hub (Revision 2, binding). Its user rulings (§2, §20) are restated in Global Constraints. User rulings in memory: `ha_kubernetes.md`.

**Scope (user, D1):** phases 0 and 1 of spec §19.1, plus the **DNS-failover-across-sites slice of phase 4**:
- multi-site membership;
- the mesh across NAT (§16.2);
- the tie-breaker at a third location, for quorum;
- per-site probes and the multi-site front door (§11.1);
- their tests.

What the slice gives:
- the front door keeps answering when one site's ingress fails (its uplink's inbound path, its port forwarding, its Traefik nodes, or the whole site when the site holding sign-in survives);
- an ingress-only site needs no data of its own.

What it doesn't give: sign-in and the data stay at the **primary site** (`main`). Surviving the loss of the primary site needs cross-site data replication and site promotion (spec §11.5: CNPG replica cluster, Longhorn DR volumes, the sync heartbeat, user ruling Q2). That is the rest of phase 4, a later plan, together with phases 2 and 3.

**Size, from the code (not from memory).**
- **The base this plan starts from:**
  - `scripts/lib/kube.sh` is 2,326 lines and hard-codes a single node (`kube_detect_cidrs`). `charts/portcullis/templates/_helpers.tpl:93` writes `replicas: 1` / `Recreate` for every core service. No PriorityClass, Lease or leader logic exists anywhere.
  - Five RWO volumes are shared across pods today, and the spec's §7.2 covers only two of them (D6).
  - Node addresses and API endpoints are frozen into chart values and admission params by the CLI (D10).
  - The Hub's `RulesExact` rejects `resourceNames` rules and requires defaults only in the core namespace.
  - The Hub has no single write funnel: 78 `saveLocked` callers, 23 direct `Save`s and 59 `WriteFileAtomic` sites.
  - Nothing site-aware exists. The link role is a star through the primary, with no NAT traversal between workers.
- **The work:** 36 tasks.
  - Stream A: 4, Tasks 1–4 (contract, vectors, 2 spikes).
  - Stream H: 12, Tasks 5–16.
  - Stream C: 17, Tasks 17–33.
  - Stream T: 1, Task 34.
  - Stream D: 1, Task 35.
  - Final: 1, Task 36.

  The cross-site slice adds 4 tasks:
  - Task 10, the mesh across sites and NAT;
  - Task 11, sites and the server layout;
  - Task 20, primary-site pinning;
  - Task 28, the front door across sites.

  It also widens Tasks 1–3, 8, 9, 15–17, 21, 27, 32, 33, 35 and 36.
- **Effort:** about **11–16 working days** of the build loop (plan → build → review → CI → test cluster).
  - The calibration is the last four plans of 19–29 tasks, each of which took 1.5–2.5 days.
  - This plan is slower:
    - the spikes need the VMs (1.5–2 days);
    - it pulls in four third-party operators;
    - its chaos tests run only on real machines;
    - the cross-site slice adds about 3–4 days: NAT relaying, the cross-region spike and the site scenarios.
  - The spec's own figures are 22–31 days for phases 0 + 1, plus part of phase 4's 18–25. They are upper bounds from the design. Above 16 days, look first at the VM spikes, Longhorn/SNR on arm64, and flannel inside `pcmesh` across regions.

## Decisions (resolved)

**Answered by the user (2026-11-17, through the coordinator):**
- **D1. Scope.** A bigger first slice: phases 0 + 1 plus DNS failover across sites, with everything it needs (multi-site membership, the mesh across NAT, per-site probes, the multi-site front door, its tests). Phases 2, 3 and the rest of phase 4 are later plans.
- **D2. Delivery of published documents: about 10 s.**
  - k3s `--kubelet-arg=sync-frequency=10s` on every node.
  - After every publish, the Hub confirms the new `.rev` on every reader pod through the existing `hub rev` exec. It raises `published_doc_stale` after 120 s.
  - The Hub's core Role gains `pods/exec` `create` and `pods` `list` there.

  [6, 17, 19, 21]
- **D8. The HA shape always.**
  - Every Kubernetes install runs k3s `--cluster-init` on `pcmesh`, CloudNativePG (1 instance), LLDAP on Postgres, Vault as a StatefulSet and the published documents.
  - `ha enable` only installs Longhorn and fencing, moves volumes and scales out.
  - Migration path 2 isn't built (no back-compat).
  - The LLDAP SQLite → Postgres conversion exists only as a restore step for Docker or old backups.

  [4, 17, 23, 26, 31]
- **D9. Machines.**
  - Four Lightsail VMs, created only when the HA build starts (Task 3) and deleted at the end (Task 36).
  - Never name the account, the profile or the VM names in any repo, commit or doc.
  - Layout (assistant's call):
    - site `main` in one region: `vm1`, `vm2` (amd64, servers, storage, ingress) and `vm3` (arm64, class `small`, the third server and the third Vault voter);
    - site `edge` in another region: `vm4` (amd64, agent, ingress).

    That is the "two sites, majority at `main`" case. The three-site tie-breaker case is tested in k3d (Task 33).
  - The VMs are reused across runs, reset by `k3s-uninstall.sh` and a wipe of the test disks, never recreated per run. The builder host itself is never used as a node.

  [3, 33, 36]

**Ruled by the coordinator, as recommended:**
- **D3.** Leases `portcullis-hub`, `portcullis-frontdoor` and `portcullis-nodeadm` in the core namespace, pre-created by the chart. The Hub's core Role has `leases` `get`/`update` on `portcullis-hub` only. [5, 6, 19]
- **D4.** `nodeadm` does every cluster-scoped read and write (snapshot, labels, taints, cordon/drain, etcd members) for the Hub's `hub.control` certificate. The Hub keeps no cluster-scoped verb. [8, 12, 15, 21]
- **D5.** The HA conversion is CLI-only (`./portcullis ha enable`). The Hub's HA page shows the checklist, the live state and the command. [15, 31]
- **D6.** group-gate, mcp-gate and wg serve their logs/status on read-only ports that only the Hub may reach, with one local PVC per gate replica. The Hub merges them, and an unreadable replica means "incomplete". [7, 22]
- **D7.** A minimal `portcullis-nodeagent` in this plan: enrol, mesh (now across sites and NAT), RTT, host checks, probes. NFS, ZFS and the fixer stay in phase 2. [9, 10]
- **D10.** `nodeadm` keeps `portcullis-cluster-addresses` and rewrites the admission params generation after each join or removal, with the CLI's create-before-delete swap. `PORTCULLIS_POD_CIDR` becomes the cluster CIDR. [17, 21]
- **D11.** Per-instance priority and *Runs on* ship here. HA mode, replicas, tiers and schedules stay in phase 2. [13, 14, 18]
- **D12.**
  - Without hairpin NAT, same-site probes don't count.
  - With another site present, that site's probers are the outside vantage.
  - A single-site cluster without hairpin uses in-cluster health only, with doctor `frontdoor_probes_internal_only` (Warning).

  [3, 9, 16, 27, 28]
- **D13.** HA ships **EXPERIMENTAL**: the docs, the HA page banner and `ha enable`'s confirmation say so. [15, 35]
- **D14.** The backup destination is built for core only: CNPG WAL and base backups, the core `backup` archive and Longhorn backups of the core volumes. Instance backups move to a replicated `hub-backups` PVC. [26, 31]

## Global Constraints

- **Base, branches, worktrees.**
  - Branch `ha` in all four repos at `/Volumes/workspace/portcullis/wt-ha/{portcullis,portcullis-hub,portcullis-templates,portcullis-docs}`. The Hub worktree exists already: it holds this plan.
  - Create the others with `git -C /Volumes/workspace/portcullis/<repo> worktree add /Volumes/workspace/portcullis/wt-ha/<repo> -b ha origin/main`, and check each one lands at that absolute path, not nested inside the repo.
  - Bases: core `674ac34`, Hub `ab3cd7c`, templates `d61915b`, docs `9996fff` (ms1, usage and cli are merged).
  - **`mailprov` is in flight.** When it merges into a repo's main, merge `origin/main` into `ha` there before that repo's next task (a merge commit, never a rebase). Expect conflicts in the doctor registry, MCP tools, routes, the contract §1/§14.5 and `ci.yml`.
  - Never edit, stash or commit in the main checkouts. Never detach a shared worktree.
- **Project rules (hard constraints):**
  - **No back-compat or migrations until a public release.** There is no compat mode, legacy hint or shim, and migration path 2 is not built (D8). Old test-server data is fixed by hand.
  - **Secrets never on argv, in logs or in errors.** Secrets travel through files and stdin only:
    - `kubectl create secret … --from-file`, `kubectl apply -f -`, `kubectl exec -i`;
    - the k3s token, bootstrap tokens, join secrets, mesh private keys, S3 credentials and main-domain DNS credentials go nowhere else;
    - `tests/test_cli.sh`'s argv grep covers the new `scripts/lib/{kube_install,ha,node}.sh`.

    The rules on what they may reach:
    - `nodeadm` logs and errors carry a token's id at most, never the token;
    - the Hub's `servers` redaction (`JoinCode.String`) covers the v2 code;
    - error texts never echo instance values (kube rule).
  - **Fail closed.** Each of these has a test in the task named:
    - no Lease → no write [5];
    - a Lease lost → writes stop within 10 s [5];
    - a published document over the object limit → the last good one kept and a doctor Problem [6];
    - fencing unconfirmed → no stateful failover [24];
    - quorum lost → nothing promoted, moved or flipped [27, 31];
    - every probe failing → no DNS change (fail static) [27];
    - a join without a verified HMAC proof and certificate → no k3s material [21];
    - an `ha enable` checklist item red → nothing changed [31];
    - unparseable cluster addresses → no params rewrite [21];
    - a node at a site with no reachable node, or a server more than 100 ms away → no k3s material [10, 11, 21];
    - a blind prober, or one site's failures alone when ≥ 2 sites can probe → no DNS change [28].
  - **Identity = the LLDAP username.** Leases, audit actors and op records name usernames. The LLDAP conversion (Task 26) keeps every user's username **and uuid** (Keycloak's federation links depend on it).
  - **Prefer mature libraries.**
    - Leader election uses client-go `leaderelection`.
    - Storage, Postgres and fencing use their operators.
    - DNS and ACME go through the domains service's existing lego/libdns providers.
    - No hand-rolled YAML, CEL, WireGuard or Raft.
  - **Main-only merges.** See Final, Task 36.
  - **No private identifiers in public repos.** No cloud profile, account id, VM name, test-server hostname or private repo name in code, docs or commits.
  - **ACME staging on the test server.** The test cluster always runs `ACME_STAGING=true`: `config apply` + `up` after `init`. The front-door account is a staging account there. The public would-issue check runs before every CAA flip.
  - **Never touch the LLDAP `admin` user.**
  - **Never weaken the kube security model** (spec §3 anti-goals):
    - the Hub has no cluster-scoped verb and holds no token;
    - every namespace is default-deny;
    - the admission policies judge every identity except the CLI;
    - etcd, the kubelet and the API server listen only on mesh addresses.
- **Single-server stays the same.** A Docker install gains no prompt, dependency, flag, service or `.env` key. `tests/test_cli.sh` keeps `test_docker_init_unchanged`, which diffs the Docker `init` transcript and `.env` key set against a fixture committed in Task 17.
- **Core lints stay green:** `NBINDS`, `lint_healthchecks.sh`, `lint_images.sh` (now also over `kube/ha/**`), the Podman overlays, `tests/lint_ci_size.sh` (`ci.yml` ≤ 450 000 bytes), and `tests/lint_builder_cache.sh`. A new CI step longer than 20 lines goes in `.github/ci/<job>-<step>.sh`. A compose change needs its chart change in the same commit. This plan adds no compose service.
- **TDD everywhere.** Write the failing test, see it fail, implement, see it pass, commit. Gates:
  - **Core:**
    - `bash tests/test_shell_libs.sh && bash tests/test_cli.sh && shellcheck -S warning portcullis scripts/lib/*.sh tests/*.sh .github/ci/*.sh && actionlint && bash tests/lint_ci_size.sh && bash tests/lint_images.sh && bash tests/lint_builder_cache.sh`;
    - `helm lint charts/portcullis && python3 tests/k8s_parity.py && python3 tests/k8s_netpol_matrix.py && python3 tests/k8s_hardening.py`;
    - for each Go module touched (`domains`, `nodeadm`, `wg`, `mcp-gate`, `enroll`): `test -z "$(gofmt -l .)" && go vet ./... && go test -race ./...`.
  - **Hub:** `go vet ./... && go test -race ./... && test -z "$(gofmt -l .)"`, plus `go test -tags envtest ./internal/runtime/kube/... ./internal/leader/...` with `KUBEBUILDER_ASSETS` from `setup-envtest use 1.33.x`.
  - **Templates:** `python3 tests/validate.py && python3 tests/test_validate.py`.
  - **Docs:** `python3 scripts/check-lists.py && bash scripts/check-branding.sh && zensical build --strict --clean`.
  - Run the Go race suites and every k3s/k3d job **on the builder**, never on the Mac. Run one local cluster at a time.
- **CI:**
  - **Core:** `gh workflow run ci.yml --ref ha -f jobs=<names> [-f scenarios=…] [-f runner=builder]`.
    - Only the controller dispatches core CI on `ha` (the concurrency group cancels).
    - Iterate locally first with `.github/ci/local/run-job.sh` (it can't run e2e-k3s or e2e-ha-k3d: use `.github/ci/e2e-k3s-local.sh` and the new `e2e-ha-k3d-local.sh`).
    - Every new e2e check starts with the `scenarios.skip(name)` gate.
  - **Hub:** `gh workflow run build.yml --ref ha`. **Templates:** `lint.yml` and `test-apps.yml`.
  - The controller runs its **own background watcher** on every dispatched run (memory: own watcher).
- **Byte copies and vectors** (the authoring repo is first; every copy is compared in the other repo's CI):

  | File | Authored in | Copies |
  |---|---|---|
  | `kube/admission/{policies,bindings,params}.yaml` | core | Hub `internal/runtime/kube/testdata/admission/` |
  | `charts/portcullis/files/hub-role{,-edge,-core}.yaml` | Hub `internal/runtime/kube/testdata/role{,-edge,-core}.yaml` | core chart |
  | `admission_vectors.json` (HA cases appended) | Hub `internal/runtime/kube/testdata/` | (envtest in Hub; core `e2e-k3s-*-admission.sh` runs the subset tagged `ha`) |
  | `published_docs.json` | Hub `internal/publish/testdata/` | core `tests/published_docs.json` |
  | `nodeadm_api_vectors.json` | core `nodeadm/testdata/` | Hub `internal/nodeadm/testdata/` |
  | `joincode_v2_vectors.json` | Hub `internal/servers/testdata/` | core `nodeadm/testdata/`, Hub `internal/nodeagent/testdata/` |
  | `frontdoor_vectors.json` | core `domains/testdata/` | Hub `internal/hub/testdata/` (HA page worst-case texts) |
  | `nminus1_vectors.json` | Hub `internal/nminus1/testdata/` | none |
  | `meshplan_vectors.json` | Hub `internal/meshplan/testdata/` | none (nodeagent is in the same repo) |
  | `site_roles_vectors.json` | Hub `internal/servers/testdata/` | none |
  | `nodeclass_vectors.json` | Hub `internal/nodeagent/testdata/` | none |
  | `core_names.txt` additions (`nodeadm`, `frontdoor`, `sessions-sentinel`, `portcullis-pg`) | core | templates `tests/` (`TestCoreNamesComplete`) |

- **Merges** (contract order): docs → Hub (wait for `edge`) → templates → core.
  - Each merge goes through a detached worktree: `git worktree add --detach /tmp/merge-<repo> origin/main` → `git merge --no-ff origin/ha -m "Merge ha: …"` → push → `git worktree remove`.
  - After the Hub merge, run `gh workflow run build.yml --ref main -f compare_ref=ha` and wait for `edge`, and for `portcullis-nodeagent` to publish.
- **Values from the spec (verbatim, binding):**
  - **Quorum and roles:**
    - HA needs ≥ 3 nodes and ≥ 3 servers; 2-node HA is refused;
    - the first 3 nodes are k3s servers, later nodes are agents;
    - the admin may override the role, and the Hub warns about an even server count (4).
  - **Node labels:**

    | Label | Values |
    |---|---|
    | `portcullis.io/class` | `small` \| `home` \| `cloud` |
    | `portcullis.io/site` | default `main` |
    | `portcullis.io/ingress` | `true` |
    | `portcullis.io/storage` | `true` (off by default on `small`) |
    | `portcullis.io/nfs` | `true` (phase 2) |
    | `portcullis.io/mail` | `true` (phase 4) |
    | `topology.kubernetes.io/zone` | = site |

    The class suggestion: `small` below 4 GB RAM or on a Pi model string; `cloud` when a public address answers.
  - **Taint:** `portcullis.io/small=true:NoSchedule`. Sentinels and the third Vault voter tolerate it; nothing else in core does.
  - **PriorityClasses:**

    | Class | Value | Preemption |
    |---|---|---|
    | `portcullis-core` | 1 000 000 | preempts |
    | `portcullis-critical` | 100 000 | preempts |
    | `portcullis-high` | 10 000 | preempts |
    | `portcullis-normal` | 1 000 | preempts (global default for apps) |
    | `portcullis-low` | 100 | `preemptionPolicy: Never` |

  - **Requests:** compose `mem_limit` → request = limit. With no `mem_limit`, 512 Mi request and limit, plus doctor Info `template_no_memory_limit`. CPU request default `50m`, no CPU limit.
  - **Placement:** `topologySpreadConstraints` on `kubernetes.io/hostname`, `DoNotSchedule` for quorum and data pieces, `ScheduleAnyway` for the stateless gates. Gates: 2 replicas, PDB `minAvailable: 1`.
  - **Keycloak:** 2 replicas, 3 with ≥ 3 non-small nodes; embedded Infinispan, `JDBC_PING`, persistent user sessions; `--proxy-trusted-addresses` = the pod CIDR.
  - **Postgres:**
    - CNPG `Cluster` `portcullis-pg`, databases `keycloak` and `lldap`, in its own namespace `cnpg-system` with no rights in `portcullis-apps`;
    - `synchronous: {method: any, number: 1, dataDurability: preferred}` with 2 instances, `required` with 3;
    - hostname anti-affinity, never on `small`;
    - the HA page texts are "Zero loss on one failure" / "Degraded: one more failure may lose the last writes".
  - **Valkey:** primary + replica + 3 sentinels, quorum 2, `replica-read-only`. oauth2-proxy uses `--redis-use-sentinel`.
  - **Vault:** 3 raft voters with `retry_join` on the headless Service, auto-unseal from `secrets-vault-unseal`, local tier. The backup takes the raft snapshot from the leader.
  - **The Hub:** 1 replica on the `hub-state` replicated-tier RWO volume. It takes a Lease before any write, and if it can't renew within **10 s** it stops writing and answers 503. Expected pause after a node failure: 1–3 min. Instance backups and folder snapshots leave `hub-data`.
  - **Fencing:**
    - medik8s SNR + NHC, with the `node.kubernetes.io/out-of-service` taint after `T_fence` + margin;
    - `T_fence` = 60 s;
    - not-ready/unreachable toleration = 30 s on HA pods;
    - never a force-delete without the out-of-service step;
    - no watchdog or SNR unhealthy → no stateful failover, doctor `ha_fencing_unavailable` (Problem);
    - the checklist needs a working watchdog on every node holding replicated-tier pods.
  - **Turning HA on (checklist):** ≥ 3 nodes with ≥ 3 servers, ≥ 2 storage nodes (3 recommended), ≥ 1 ingress node (2 recommended), the backup destination set, the N−1 check green.
  - **N−1:**
    - for each node, the `portcullis-core`/`critical`/`high` pods on it must fit into the rest after evicting `normal` and `low`;
    - green = fits; yellow = high fits only by evicting normal; red = critical or core doesn't fit;
    - it runs on every placement change and **before** raising an instance to Critical or High, and the dialog says "if <node> fails, <x> won't have room";
    - doctor `ha_n_minus_1_insufficient` (Problem when red).
  - **DNS failover:**
    - one A/AAAA per healthy ingress node in the `address` set of `<d>` and `*.<d>`, for the main domain and every added domain;
    - health = node Ready + Traefik Ready + an HTTPS probe of `https://auth.<d>/healthz` sent to the node's public address, passing for a majority of probers (from ≥ 2 sites when there are 2);
    - remove after 3 failed rounds 10 s apart; add back after 2 min passing; at most one change per name per 60 s;
    - never remove the last address (fail static);
    - append first, then delete the exact stale values by record id;
    - TTL 60 s, or the provider minimum (Porkbun 600);
    - the HA page shows each name's worst case ("worst case ~10 min for clients that hit the dead address first, on Porkbun").
  - **HA certificates:**
    - the front-door role issues the main domain's certificate with its own ACME account;
    - every Traefik replica fetches certificates from the domains HTTP provider, whose rule becomes "only Portcullis names: the main domain and added domains";
    - `acme.json` and Traefik's resolver are off in HA mode;
    - turning HA on is a CAA account switch: relax → wait the real TTL (settle file) → issue → re-pin.
  - **Credentials (user ruling Q1):**
    - the front-door role holds the main domain's DNS credentials, in a separate process and Secret with no API besides health;
    - only the main domain's `address`, `caa` and `_acme-challenge` records;
    - the narrowest token (zone-scoped Cloudflare; Porkbun is account-wide, and the HA page says so);
    - HA requires the offsite backup destination.
  - **Ingress:** Traefik is a DaemonSet on `ingress` nodes. ServiceLB is on nodes labelled `svccontroller.k3s.cattle.io/enablelb=true` (set with `portcullis.io/ingress`), with `externalTrafficPolicy: Local`.
  - **VPN:** `wg-people` is a LoadBalancer on ingress nodes with `externalTrafficPolicy: Cluster`. The docs state the reconnect caveat.
  - **Mesh:** `pcmesh` kernel WireGuard, `10.215.0.0/24` fixed (checked against link `10.214.0.0/24` and the people VPN), full static peer list, k3s `--node-ip` on the mesh address, `--flannel-backend=wireguard-native`. **Across sites (§16.2, phase 4 slice):** every site needs at least one node that is reachable (a cloud node, or one forwarded UDP port), and peers behind NAT keep their tunnel up with a 25 s keepalive.
  - **Sites and quorum (§4, §11.5):**
    - etcd across sites works with tuned heartbeat and election timeouts, up to about 100 ms RTT;
    - with 2 sites, the site holding 2 of the 3 voters is the only one that survives on its own;
    - real site tolerance needs a tie-breaker at a third location (a small cloud VM, or a Pi at a friend's house);
    - zero-loss replicas stay within one site.
  - **Probes across sites (§11.1):** with 2 sites, probers from at least 2 sites.
  - **Join codes:** single use, 15 min, carrying the enrol endpoint + server addresses, the server id, the `pki_node` CA fingerprint and a 256-bit secret (hash stored), never a k3s token. The one-liner is `curl -fsSL https://<d>/node/join.sh | sh -s -- <code>` (script sha256 inside the code). `pki_node` role `node-cluster`.
  - **Adding a node:** fresh sign-in, audited `server.add`, `server_enrol` op with steps enrolled → k3s joined → node Ready → storage ready → done. A server join is "cluster-admin on that machine", stated in the dialog. Never over MCP.
  - **Removing a node:** cordon → drain (respects PDBs, refuses below a quorum or replica minimum) → Longhorn evicts → etcd member removal → certificate revocation → `k3s-uninstall.sh`. **Revoke now**: node object deleted, etcd member removed, certificate and mesh peer revoked, server token rotated.
  - **`nodeadm`:**
    - the only holder of the k3s server token;
    - creates `bootstrap.kubernetes.io/token` Secrets in `kube-system` only, guarded by a VAP: TTL ≤ 15 min, usage `authentication` only, the k3s bootstrap group only;
    - Lease-guarded, on server nodes only.
  - **Alerts and doctor kinds:**

    | Alert / doctor kind | Severity |
    |---|---|
    | `PortcullisNodeDown` / `node_down` | Problem, NotReady > 1 min |
    | `PortcullisQuorumAtRisk` / `ha_quorum_at_risk` | Problem |
    | `PortcullisQuorumLost` | Critical |
    | `PortcullisVolumeDegraded` / `volume_degraded` | Warning, > 10 min |
    | `PortcullisPostgresNotSynchronous` / `pg_not_synchronous` | Warning |
    | `PortcullisFailover` | Info |
    | `ha_fencing_unavailable` | Problem |
    | `ha_n_minus_1_insufficient` | Problem / Warning |
    | `PortcullisDNSFailoverStuck` | Warning, 5 min |
    | `PortcullisBackupStale` / `backup_stale` | Warning, 26 h |
    | `PortcullisSmallNodePressure` | Warning |

    The external dead-man's switch is opt-in, never on by default.
- **Values this plan adds (assistant's calls, binding unless a D-answer changes them):**
  - **Namespaces:** `longhorn-system`, `cnpg-system`, `portcullis-fencing` (SNR + NHC); external-snapshotter's controller in `kube-system`. PSA `privileged` on the first and third, `restricted` on `cnpg-system`. Each is default-deny plus the operator's documented flows.
  - **StorageClasses:** `portcullis-core` (unchanged, local, Retain) and new `portcullis-core-replicated` (Longhorn, `numberOfReplicas: "2"`, reclaim Retain, `dataLocality: best-effort`). The apps tiers are phase 2.
  - **Core PVCs on `portcullis-core-replicated` in HA:** `hub-state` (was `hub-data`), `hub-secrets`, `hub-backups` (new), `domains-data`, `wg-data`, `traefik-acme` (deleted in HA), `prometheus-data` (Prometheus at `portcullis-low`).
  - **Published documents** (names in `published_docs.json`, Task 2):

    | Kind | Object | Key | Mounted at |
    |---|---|---|---|
    | ConfigMap | `pub-group-gate-policy` | `group-gate-policy.json` | `/hub-data` |
    | ConfigMap | `pub-user-attributes` | `user-attributes.json` | `/hub-data` |
    | ConfigMap | `pub-portal-apps` | `portal-apps.json` | `/hub-data` |
    | ConfigMap | `pub-signin-keycloak` | `signin-keycloak.json` | `/hub-data` |
    | ConfigMap | `pub-impersonation` | `impersonation.json` | `/hub-data` |
    | ConfigMap | `pub-mcp-gate` | `mcp-gate.json` | `/hub-data` |
    | ConfigMap | `pub-vpn` | `vpn.json` | `/vpn-doc` |
    | Secret | `pub-mcp-credentials` | `mcp-credentials.json` | `/hub-data` |

    - Readers keep their paths through a **projected volume** (never `subPath`, which the kubelet never refreshes).
    - Each object carries `.rev` too. The size limit is **1 000 000 bytes** per document.
  - **Leases** (D3): `portcullis-hub`, `portcullis-frontdoor` and `portcullis-nodeadm`, timed at LeaseDuration 15 s, RenewDeadline 10 s and RetryPeriod 2 s, with identity = the pod name.
  - **The Hub's core-namespace Role `portcullis-hub-core`** (`role-core.yaml`):

    | Group | Resource | Verbs | `resourceNames` |
    |---|---|---|---|
    | core | `configmaps` | `get`, `update`, `patch` | the seven `pub-*` ConfigMaps |
    | core | `configmaps` | `get` | `frontdoor-status`, `portcullis-cluster-addresses` |
    | core | `secrets` | `get`, `update`, `patch` | `pub-mcp-credentials` |
    | `coordination.k8s.io` | `leases` | `get`, `update` | `portcullis-hub` |
    | core | `pods/exec` | `create` | none (D2: `hub rev` on readers) |
    | core | `pods` | `list` | none (needed to find readers) |

  - **`nodeadm`:**
    - Go module `nodeadm/`, image `ghcr.io/porelli/portcullis-nodeadm`, uid **10010**;
    - the internal API on `:8443`, mTLS with `pki_node` clients `hub.control` (all operations) and `frontdoor.control` (none);
    - public paths behind Traefik `https://<d>/node/{join.sh,nodeagent-amd64,nodeagent-arm64,v1/nonce,v1/enrol,v1/join}` on router `portcullis-node`, `rate-limit@file`;
    - metrics on `:9105`.
  - **Join code v2:** `pcj2.` + base64url(JSON) `{"v":2,"kind":"cluster","endpoint":"https://<d>/node","servers":["<mesh-ip>",…],"server_id","role":"server"|"agent","class","site","ca_sha256","script_sha256","agent_sha256":{"amd64","arm64"},"mesh_ip","secret"}`, ≤ 4 KiB.
  - **`pki_node` roles:**
    - `node-cluster`: CN `<id>.cluster.portcullis.internal`, 720 h;
    - `node-frontdoor`: CN `frontdoor.control`, 720 h, signed by enroll for `nodeadm`'s request only.
  - **`pcmesh`:** UDP **51830**, interface `pcmesh`, `PersistentKeepalive = 25`, keys generated on the node (the private key never leaves it), the first node `10.215.0.1`.
  - **The mesh peer plan** (`internal/meshplan`, Task 10; vectors `meshplan_vectors.json`):
    - *reachable* = a public UDP endpoint answering on 51830;
    - two nodes peer **directly** when either is reachable or both are at the same site (the LAN endpoint);
    - a NATed pair at different sites goes **through the target's site gateway**: the lowest-id reachable node of that site, with the target's `/32` added to that peer's AllowedIPs;
    - only gateways forward, and only `pcmesh` ↔ `pcmesh` (iptables `-i pcmesh -o pcmesh -j ACCEPT`; everything else to and from `pcmesh` stays dropped);
    - keepalive 25 only on NATed nodes;
    - the refusal text: `site <s> needs one node reachable on UDP 51830 first (a cloud node, or one forwarded port)`.
  - **Sites (assistant's calls):**
    - the **primary site is `main`**, the first node's site, which can't be changed in this plan;
    - CNPG, Vault, Sentinel and sessions, the Hub, domains, Keycloak, the gates, enroll, mcp-gate, wg and Longhorn disks are pinned to it (required `portcullis.io/site In [main]`);
    - unpinned: the Traefik DaemonSet (ingress nodes at every site), `frontdoor` (any site: it must be able to write DNS when the primary's uplink is down) and `nodeadm` (any server);
    - storage nodes only at `main`: the label `node.longhorn.io/create-default-disk=true` is set by `nodeadm` only on `main` storage nodes, and the Hub refuses `storage` elsewhere with "storage nodes must be at the primary site (main) in this version".
  - **etcd timing:** `--etcd-arg=heartbeat-interval=200 --etcd-arg=election-timeout=2000` on **every** server from `init` on, single site included, so a second site needs no rolling restart.
  - **RTT limits** (measured over `pcmesh` by nodeagent, p95 of 20 pings):
    - a server needs ≤ **100 ms** to every server: `too far for one cluster: <n> ms (servers need 100 ms or less)`;
    - an agent needs ≤ **250 ms**;
    - doctor `mesh_rtt_high` at 80 % of the limit.
  - **Server layout across sites** (vectors `site_roles_vectors.json`):
    - one site: the first 3 nodes are servers;
    - with 3 or more sites, a new server is suggested only where it keeps **no site at a majority** of servers;
    - with exactly 2 sites, servers stay at `main`, and the HA page and doctor `ha_two_sites_no_tiebreaker` (Warning) say "Only main can survive on its own: add a tie-breaker at a third location (a small cloud VM or a Pi elsewhere)."
  - **`portcullis-nodeagent`:**
    - systemd unit `portcullis-nodeagent.service`, uid 0 (it manages `pcmesh` and runs host checks), listening only on its mesh address `:7443`;
    - mTLS clients `hub.control` (every operation) and `frontdoor.control` (`GET /v1/probes` only);
    - binary at `/usr/local/lib/portcullis/nodeagent`.
  - **Front door:** `domains frontdoor`, a separate Deployment `frontdoor` (1 replica, Lease `portcullis-frontdoor`), Secret `frontdoor-env` (the main domain's DNS credentials, which only it mounts), its status in ConfigMap `frontdoor-status` (writable only by its own Role), health on `:8090`, metrics on `:9106`.
  - **`.env` (Kubernetes only):**
    - `PORTCULLIS_HA=on` (written by `ha enable`; absent = off);
    - `PORTCULLIS_BACKUP_S3_URL`, with credentials in `secrets/backup-destination.env` (mode 0600), synced to Secret `backup-destination`;
    - `PORTCULLIS_K3S_VERSION` (pinned; written by `init`).
  - **CLI commands:**
    - `./portcullis ha status|enable`;
    - `./portcullis node add <id> [--role server|agent] [--class small|home|cloud] [--site <s>]`, `node list`, `node remove <id>` (typed id), `node revoke <id>` (typed id);
    - `./portcullis backup destination set|show|test`.
  - **Doctor kinds added beyond the spec:**
    - `frontdoor_probes_internal_only` (Warning, D12);
    - `published_doc_too_large` (Problem);
    - `published_doc_stale` (Problem: a reader's `.rev` is behind for more than 120 s);
    - `ha_lease_lost` (Problem);
    - `mesh_site_no_gateway` (Problem: a site whose only reachable node is gone);
    - `mesh_peer_stale` (Warning: a nodeagent missed the last peer plan for more than 5 min);
    - `mesh_rtt_high` (Warning);
    - `ha_two_sites_no_tiebreaker` (Warning).
  - **Op keys:** `_ha` (the HA page's refreshes) and `server_enrol` (reused); `node_remove`.

## Plan rulings (assistant's calls; spec gaps and defects)

- **R1.** The spec's "Keycloak theme and map inputs" from `hub-data` (§7.2) don't exist: the Hub writes no theme. Keycloak reads only `signin-keycloak.json` and `impersonation.json` there.
- **R2.** The small-node admission rule (§10.3: "the `small` toleration only together with a required node affinity naming small nodes") is checked without a node list. The pod's `requiredDuringScheduling…` must contain a term with `portcullis.io/class In [small]`. A VAP can't read Node objects.
- **R3.** The first node runs `pcmesh` from `init` and k3s `--node-ip=10.215.0.1`, so a later join changes no etcd peer URL. A single-node Kubernetes install therefore has a one-peer WireGuard interface (Kubernetes is experimental; Docker is unaffected).
- **R4.** There is no `ha disable` (the spec has none). Leaving HA = `backup` → `init` → `restore`.
- **R5.** Phase 1's backup destination (D14; spec §9.3) covers core only:
  - CNPG WAL and base backups (barman-cloud plugin);
  - the core `backup` archive (restic, as today);
  - Longhorn backups of the core replicated volumes.

  Instance backups move from `hub-data/backups` to the `hub-backups` PVC (replicated tier). Instance backups to S3 are phase 2.
- **R6.** The front door pulls probe results from each `portcullis-nodeagent` (`GET /v1/probes`, client `frontdoor.control`). The Hub is never in the DNS decision path.
- **R7.** `nodeadm` exports the cluster gauges Prometheus needs: `portcullis_node_ready{node}`, `portcullis_quorum_voters{system,state}`, `portcullis_volume_robustness{volume}`, `portcullis_pg_sync_standbys`, `portcullis_fencing_ready{node}` and `portcullis_failover_total{kind}`. There is no kube-state-metrics, so Prometheus gets no cluster-scoped rights.
- **R8.** `kube.sh` is not grown. The new CLI code goes in `scripts/lib/kube_install.sh`, `ha.sh` and `node.sh` (the parked kube.sh split, started here).
- **R9.** On Kubernetes the `servers` feature changes meaning. `serversOn()` answers true with kind `cluster-node` only, and Docker workers stay refused there (spec non-goal: no mixing).
- **R10.** A **blind prober**, one that fails every target at every site in a round (its own uplink is down), is discarded for that round. Otherwise one site's broken uplink would look like every other site failing. An address is removed only when:
  - a majority of the non-blind, eligible probers fail it for 3 rounds; and
  - with ≥ 2 sites holding eligible probers, the failing probers span ≥ 2 sites.

  When only one site can probe a target (2 sites, no hairpin), that site's probers alone decide, and only while they aren't blind.
- **R11.** A site with no ingress node Ready (the whole site down) loses all its addresses through the same rule, one name at a time, at most one change per name per 60 s. The last address overall is never removed.
- **R12.** flannel `wireguard-native` runs inside `pcmesh` (WireGuard in WireGuard). The MTU and the cross-region throughput are spiked in Task 3. If they fail, the plan stops for a user decision; it never switches the flannel backend quietly.

## Review Focus

1. **The Hub on a node that a partition isolates.** Its pod keeps running until SNR reboots the node, and background ops, op records and audit appends are in flight. Every write must stop within 10 s of the last renewal, including those already running, and the new Hub on the majority side must never see a write from the old one land after its own first write. Pinned by `TestLeaseLostStopsInflightWrites` and `TestNoFileWritesOutsideFsutil` (Task 5).
2. **A published document grows past the object limit** (a big `user-attributes.json`, many apps in the policy file). The Hub must keep the last good document, never truncate it, never publish an empty one, and raise `published_doc_too_large`. Readers keep enforcing the old document. Pinned by `TestPublishTooLargeKeepsLast` (Task 6).
3. **Restoring a Docker backup into the HA shape converts LLDAP from SQLite to Postgres.** Every user's username, uuid, groups and password hash must survive, otherwise Keycloak's federation links break and people lose their passkeys. Any difference in counts or uuids aborts the restore with nothing switched. Pinned by `test_lldap_convert_keeps_uuids` (Task 26).
4. **`ha enable` interrupted** by Stop, a CLI crash or a node lost half-way. A re-run resumes from the recorded step. Two Postgres writers or two Hubs must never be up at once: the old single Postgres stays scaled to 0 once CNPG has the data, and the old Hub stays scaled to 0 before the new volume attaches. Pinned by `test_ha_enable_resumes_each_step` and `test_ha_enable_never_two_writers` (Task 31).
5. **One site's uplink fails** while the front door runs at that site or elsewhere. That site's probers see every target fail, and its nodes stay Ready inside the cluster.
   - The other sites' addresses must stay published.
   - The front door must keep its Lease only on the quorum side.
   - A front door at the cut-off site must not be able to write DNS, and must stop trying once the Lease lapses.
   - Pinned by `TestOneSiteUplinkDownNoRemovalElsewhere` and `TestBlindProberDiscarded` (Task 28) and the VM scenario `ha_vm_site_uplink_down` (Task 33). (The provider's half-written change is pinned in Task 27 by `TestFrontDoorPartialWriteNeverEmpty`.)

---

## File structure

**Docs (`wt-ha/portcullis-docs`):**
- `docs/guides/integration-contracts.md`:
  - §1 (an "High availability (NEW, HA)" entry);
  - §2 (the `.env` keys);
  - §3.4 (PriorityClass, requests, tolerations in the translation table);
  - §4 and §8.1 (published documents on Kubernetes);
  - §6 "On Kubernetes" (the core-namespace Role, the admission additions);
  - §12.4 (the HTTP provider rule in HA);
  - §14.5 (the kinds);
  - §16.1 (`wg-people` in HA);
  - §17 (cluster nodes);
  - new **§20 High availability** (`nodeadm` API, join code v2, nodeagent API, Leases, front door, N−1, HA state);
  - also fix the misnumbered "16.2 The Hub's usage metrics" heading after §17.7, renumbered to §17.8.
- `docs/operations/high-availability.md` (new), `kubernetes.md`, `servers.md`, `hardening.md`, `backups.md`, `monitoring.md`, `cli.md`, `hub.md`, `testing.md`, `architecture.md`, `includes/abbreviations.md`, `docs/operations/.nav.yml`.

**Hub (`wt-ha/portcullis-hub`)**

| File | Responsibility |
|---|---|
| `internal/runtime/kube/guard.go`, `testdata/role-core.yaml` (new) | `RulesExact` with `resourceNames`, the core Role check |
| `internal/leader/` (new) | Lease fence (`Fence`) |
| `internal/fsutil/gate.go` (new), `fsutil.go`, `internal/state/state.go` | write gate on every writer |
| `internal/httpapi/leader.go` (new) | 503 for writes while standing by |
| `internal/publish/` (new) + `internal/runtime/kube/publish.go` (new) | published-document sinks |
| `internal/hub/{hub.go,signin_publish.go,impersonation_file.go,portal.go,ai_gatefile.go,vpn_publish.go}` | writers through `h.publish` |
| `internal/gatelogs/` (new), `internal/hub/{signin_history.go,impersonation_apps.go,ai_accesslog.go,vpn.go}` | per-replica logs and status (D6) |
| `cmd/portcullis-nodeagent/`, `internal/nodeagent/` (new), `Dockerfile.nodeagent` (new) | host agent |
| `internal/runtime/kube/{translate.go,names.go}` + `testdata/translate/ha-*` | priority, tolerations, affinity, requests |
| `internal/state/availability.go` (new), `internal/hub/availability.go` (new), `internal/httpapi/availability.go` (new), `web/availability.js` (new) | priority + *Runs on* |
| `internal/nodeadm/` (new client), `internal/nminus1/` (new) | cluster snapshot, N−1 |
| `internal/meshplan/` (new), `internal/hub/servers_mesh.go` (new) | mesh peer plan across sites and NAT, pushed to nodeagents |
| `internal/servers/siteroles.go` (new), `internal/hub/sites.go` (new) | sites, site-aware server layout, RTT limits |
| `internal/servers/joincode.go`, `internal/hub/{servers.go,servers_enrol.go,servers_revoke.go,servers_cluster.go (new)}`, `internal/httpapi/servers.go`, `web/servers.js` | cluster nodes |
| `internal/hub/ha.go` (new), `internal/httpapi/ha.go` (new), `web/ha.js` (new) | HA page |
| `internal/doctor/ha.go` (new), `internal/hub/doctor_ha.go` (new), `internal/httpapi/mcptools_ha.go` (new) | kinds, MCP read tools |
| `cmd/hub/{main.go,kube.go}` | wiring |
| `.github/workflows/build.yml` | nodeagent image + binaries, envtest list |

**Core (`wt-ha/portcullis`)**

| File | Responsibility |
|---|---|
| `scripts/lib/kube_install.sh` (new), `stack.sh` `cmd_init` | k3s + `pcmesh` install at `init` |
| `scripts/lib/kube.sh` | multi-node detection, cluster addresses, params from `portcullis-cluster-addresses` |
| `kube/ha/{longhorn,snapshotter,cnpg,fencing}/` (new) + `scripts/lib/ha.sh` (new) | third-party installs |
| `kube/admission/{policies,bindings}.yaml`, `kube/admission/nodeadm-tokens.yaml` (new), `charts/portcullis/templates/priorityclasses.yaml` (new) | priorities, admission |
| `nodeadm/` (new Go module), `nodeadm/join.sh`, `charts/portcullis/templates/nodeadm.yaml` (new) | enrolment, cluster API |
| `enroll/nodes.go`, `scripts/lib/pki.sh` | `node-cluster`, `node-frontdoor` |
| `charts/portcullis/templates/*.yaml`, `_helpers.tpl`, `values.yaml` | the HA chart |
| `charts/portcullis/templates/{postgres-cnpg,sessions,vault,published}.yaml` | CNPG, Sentinel, raft, documents |
| `group-gate/group-gate.py`, `mcp-gate/`, `wg/` | log ports (D6) |
| `domains/frontdoor/` (new package, incl. `sites.go`), `domains/traefik.go`, `domains/main.go` | front door, across sites |
| `charts/portcullis/templates/_helpers.tpl` (`portcullis.sitePin`), `values.yaml` (`ha.primarySite`) | primary-site pinning |
| `scripts/lib/{backup.sh,config.sh,dns.sh}` | destination, CNPG backups, CAA flip in HA |
| `scripts/lib/node.sh` (new) | `node …` |
| `monitoring/prometheus/{alerts.yml,prometheus.yml,tests/alerts_test.yml}`, `monitoring/grafana/dashboards/cluster.json` (new) | alerts, dashboard |
| `.github/workflows/ci.yml`, `.github/ci/e2e-ha-k3d-*.sh` (new), `.github/ci/e2e-ha-vm-*.sh` (new), `.github/workflows/images.yml` | CI |
| `tests/{test_shell_libs.sh,test_cli.sh,k8s_parity.py,k8s_parity_deltas.yaml,k8s_netpol_matrix.py,k8s_hardening.py,published_docs.json}`, `tests/e2e/e2e_ha.py` (new) | tests |

**Templates (`wt-ha/portcullis-templates`):** `tests/validate.py` (reserved core names), `tests/test_validate.py`, `tests/core_names.txt`.

---

## Stream A — Contract, vectors, spikes (first)

### Task 1: Contract (docs)

**Files:**
- Modify: `docs/guides/integration-contracts.md` (the sections in File structure).
- Modify (Hub): `web/docs/*` via `PORTCULLIS_DOCS_DIR=/Volumes/workspace/portcullis/wt-ha/portcullis-docs web/docs/sync.sh`.

**Interfaces — Produces (binding for every later task):**
- **§1:** "High availability (NEW, HA)". A MINOR bump. It names the breaking change for core + Hub on Kubernetes only (published documents replace `hub-data` files there) and the merge order.
- **§6 "On Kubernetes":**
  - the core-namespace Role table (Global Constraints) replaces "There is **nothing in the core namespace**", whose new text is "nothing in the core namespace but the named documents, its Lease and the `hub rev` exec on readers";
  - the line "Each Role object must equal these rules exactly" also covers `role-core.yaml`;
  - the admission additions:
    - `app pods may use only portcullis-critical|high|normal|low`;
    - `the portcullis.io/small toleration needs a required node affinity on portcullis.io/class In [small]`;
    - `nodeName is refused`;
    - `topologySpreadConstraints and affinity may use only portcullis.io/* and kubernetes.io/hostname keys`.

    These are the exact refusal texts, also used in `admission_vectors.json`.
  - The replicas rule stays "replicas above 1 are refused" (phase 2 makes it conditional).
- **§3.4 translation table:**
  - `priorityClassName` = the instance's priority (default `portcullis-normal`);
  - tolerations `node.kubernetes.io/not-ready` and `unreachable` with `tolerationSeconds: 30` on every app pod in HA mode;
  - `resources.requests.cpu` = `50m`, no CPU limit;
  - no `mem_limit` → 512 Mi;
  - *Runs on* affinity (§20.6).
- **§4 / §8.1:** "On Kubernetes" each published file is the object in the table. The `.rev` key and the ≤ 1 000 000 bytes rule; over it, the Hub keeps the last good one.
- **§12.4:** with `PORTCULLIS_HA=on`, "Only Portcullis names": the main domain + `*.<main>` from the front door, plus added domains. Without it, unchanged.
- **§14.5:** the spec kinds plus the four added ones, each with its severity and its condition (copy from Global Constraints).
- **§17:**
  - "Not supported: a primary on Kubernetes" becomes "On Kubernetes, Servers manages **cluster nodes** only (§20)";
  - add the `node-cluster` and `node-frontdoor` roles to §17.5;
  - renumber the stray §16.2 to §17.8.
- **§20 High availability** (new):
  - **20.1 Model and roles.**
  - **20.2 `nodeadm` API:**
    - internal `POST /v1/codes`, `GET /v1/cluster`, `PUT /v1/nodes/{id}/labels`, `POST /v1/nodes/{id}/cordon|uncordon|drain`, `DELETE /v1/nodes/{id}?mode=cooperative|revoke`;
    - public `GET /node/join.sh`, `GET /node/nodeagent-{arch}`, `POST /node/v1/nonce`, `POST /node/v1/enrol`, `POST /node/v1/join`.

    Each comes with strict JSON shapes, the error kinds `quorum_minimum`, `replica_minimum`, `unknown_node`, `code_expired`, `code_used`, `proof_invalid` and `not_leader`, and status codes.
  - **20.3 Join code v2** (the shape in Global Constraints).
  - **20.4 nodeagent API:** `GET /v1/health`, `GET /v1/checks`, `PUT /v1/mesh/peers` (the full list, idempotent), `GET /v1/probes`, `POST /v1/k3s/uninstall`, and `GET /v1/mesh/rtt` (`{<peer-id>: p95_ms}`). `PUT /v1/mesh/peers` carries `{peers:[{id, pub, endpoint|null, allowed_ips:[…], keepalive}], forward: bool}`.
  - **20.5 Leases and the write fence.**
  - **20.6 Priority and *Runs on*:** state, API and the affinity each choice renders.
  - **20.7 N−1:** the input snapshot and the algorithm, as in Task 12.
  - **20.8 Front door:** health inputs, hysteresis, fail static, the `frontdoor-status` document `{v:1, names:{<name>:{addresses:[…], ttl, worst_case_s, last_change, pending}}, probes:{<node>:{ok, internal_only, blind}}, sites:{<site>:{healthy, ingress:[…]}}}`. The multi-site rules: R10 and R11 (blind probers, the 2-site span, whole-site removal).
  - **20.9 Cluster addresses document** `portcullis-cluster-addresses` `{v:1, mesh_cidr, cluster_cidr, service_cidr, api:[…], nodes:{<id>:{mesh, lan:[…], public:[…]}}}`.
  - **20.10 Per-replica logs** (D6): ports `group-gate :8091` and `mcp-gate :8092`, `GET /v1/log?from=<ts>&limit=` (JSONL, ≤ 4 MiB per answer), and `wg :8093` `GET /v1/status`, each admitted only from the Hub pod.
  - **20.11 Sites and the mesh across sites:**
    - the primary site `main` and the pinned/unpinned component list;
    - the mesh peer plan rules and refusal text;
    - the RTT limits and refusal texts;
    - the server layout across sites, with the 2-site warning text;
    - storage only at `main`;
    - the `etcd` timing flags.

    Every value is copied from Global Constraints.

- [ ] **Step 1:** Write the sections above in the docs worktree. Every refusal text appears exactly once in the contract, together with the vector file that carries it.
- [ ] **Step 2:** Run the docs gates. Expected: all pass, `zensical build --strict` clean.
- [ ] **Step 3:** Sync the Hub copy (`web/docs/sync.sh`), then run `go test ./web/ -run TestDocsCopies`. Expected: PASS.
- [ ] **Step 4:** Commit docs (`contract: high availability §20, cluster nodes, published documents`) and Hub (`web/docs: sync contract (HA)`).

### Task 2: Shared vectors (Hub authors the Hub-owned ones, core the core-owned ones)

**Files:**
- Create (Hub): `internal/publish/testdata/published_docs.json`, `internal/servers/testdata/joincode_v2_vectors.json`, `internal/nminus1/testdata/nminus1_vectors.json`, `internal/nodeagent/testdata/nodeclass_vectors.json`, `internal/meshplan/testdata/meshplan_vectors.json`, `internal/servers/testdata/site_roles_vectors.json`.
- Create (core): `nodeadm/testdata/nodeadm_api_vectors.json`, `domains/testdata/frontdoor_vectors.json`; copies `tests/published_docs.json`, `nodeadm/testdata/joincode_v2_vectors.json`.
- Modify (Hub): `internal/runtime/kube/testdata/admission_vectors.json` (≥ 24 new cases tagged `"ha": true`).
- Copy (Hub): `internal/nodeadm/testdata/nodeadm_api_vectors.json`, `internal/hub/testdata/frontdoor_vectors.json`.

**Interfaces — Produces:**
- **`published_docs.json`:** `[{"doc","object","kind":"configmap"|"secret","key","mount","readers":["group-gate","keycloak","mcp-gate","wg"],"gid"}]`, exactly the eight rows of Global Constraints.
- **`joincode_v2_vectors.json`:** `{valid:[{code, decoded}], invalid:[{code, error}]}`. The errors:
  - `join code: not a pcj2 code`;
  - `join code: too long`;
  - `join code: field <f> missing`;
  - `join code: role must be server or agent`;
  - `join code: mesh_ip outside 10.215.0.0/24`;
  - `join code: secret must be 32 bytes`;
  - `join code: script_sha256 must be 64 hex`.
- **`nodeadm_api_vectors.json`:** request/response pairs for each §20.2 route, including every error kind.
- **`frontdoor_vectors.json`:** `[{name, provider_min_ttl, rounds:[{t, probes:{node:ok}, ready:{node:bool}}], want:{addresses, changes:[{t, op, value}]}, want_worst_case_text}]`. It covers:
  - removal after 3 rounds;
  - re-add after 120 s;
  - one change per 60 s;
  - all failing → no change;
  - last address kept;
  - 2-site majority;
  - Porkbun 600 s text;
  - internal-only (D12);
  - **across sites** (R10, R11): a blind prober discarded; the 2-site span required; one site's uplink down leaves the other sites' addresses; a whole site down removes its addresses one name per 60 s and keeps the last address overall; a front door without the Lease changes nothing.
- **`nminus1_vectors.json`:** `[{name, snapshot, want:[{node, level, unplaced, evicted}]}]`, ≥ 12 cases: taints, the `small` taint, required affinity, anti-affinity/spread, preemption of normal/low only, `preemptionPolicy: Never` on low, DaemonSet pods ignored, a node already NotReady.
- **`meshplan_vectors.json`:** `[{name, nodes:[{id, site, mesh_ip, lan, public|null, pub}], want:{<id>:{peers:[{id, endpoint|null, allowed_ips, keepalive}], forward}} | want_error}]`, ≥ 14 cases:
  - one site, all on the LAN;
  - one site, one node public;
  - two sites, both with gateways;
  - a NATed node per site (relayed through the target's gateway);
  - two gateways at one site (the lowest id wins);
  - a site with no reachable node (`want_error` with the refusal text);
  - a duplicate mesh ip;
  - an ip outside `10.215.0.0/24`;
  - a gateway removed (the next lowest id takes over).
- **`site_roles_vectors.json`:** `[{name, cluster:[{id, site, role, healthy}], new:{site, rtt_ms:{<server>:ms}}, want:{role, warnings} | want_error}]`, covering:
  - one site, servers 1–3, then agents;
  - an even-count warning;
  - 2 sites (servers stay at `main`, plus the tie-breaker warning);
  - 3 sites (no site at a majority: `main` 2, `edge` 2, `tb` 1);
  - a server at 101 ms (refused with the exact text);
  - an agent at 251 ms (refused);
  - 80 % warnings.
- **`nodeclass_vectors.json`:** `[{mem_bytes, cpu, model, public_answers, want}]`, covering < 4 GB → small, "Raspberry Pi" → small, public → cloud, else home.

- [ ] **Step 1: Write the failing loaders.**
  - Hub: `TestPublishedDocsVectorsShape`, `TestJoinCodeV2VectorsShape`, `TestNMinus1VectorsShape`, `TestNodeClassVectorsShape`, `TestMeshPlanVectorsShape`, `TestSiteRolesVectorsShape` (each asserts its file parses strictly and has its minimum case count).
  - Core: `nodeadm` `TestAPIVectorsShape` and `domains` `TestFrontdoorVectorsShape`.
  - Byte-copy checks: Hub `TestNodeadmVectorsCopy` and `TestFrontdoorVectorsCopy` (`PORTCULLIS_CORE_DIR`); core `unit-tests-kube-static.sh` compares `tests/published_docs.json` and `joincode_v2_vectors.json` against the Hub's same-named branch.
- [ ] **Step 2:** Run them. Expected: FAIL (files missing).
- [ ] **Step 3:** Write the vector files, values from Task 1. The new admission cases: each of the four refusal texts, and the accepted forms (`portcullis-low` with no toleration; small toleration + the class term; hostname spread).
- [ ] **Step 4:** Run them. Expected: PASS. The envtest admission cases tagged `ha` stay **skipped** until Task 18 (`t.Skip("ha admission lands in Task 18")` keyed on the tag, removed there).
- [ ] **Step 5:** Commit in each repo (`vectors: HA (published docs, join code v2, nodeadm API, front door, N−1, node class, mesh plan, site roles)`).

### Task 3: Spike — cluster, storage, fencing on real machines (builder + VMs, D9)

**Files:** Create (Hub): `.superpowers/sdd/2026-11-18-high-availability/spike-cluster.md`. No product code.

**Interfaces — Produces:** pins (version + sha256/digest) for k3s, Longhorn, external-snapshotter, CNPG + barman-cloud plugin, SNR, NHC and k3d. They are written into this plan's Global Constraints as an amendment commit, as the kube plan's Task 0 did. Each answer below is recorded as **works / works with X / doesn't**.

- [ ] **Step 1:** The four VMs in the D9 layout (`vm1`–`vm3` at `main`, `vm4` at `edge`), linked by a hand-made `pcmesh` (spike only). Bring up k3s `--cluster-init` on `vm1` at `10.215.0.1`, join `vm2`/`vm3` as servers and `vm4` as an agent over `pcmesh` with `--flannel-backend=wireguard-native`, then remove one server (etcd member removal). Record: works, and the steps that worked.
- [ ] **Step 2:** Longhorn v1 on the arm64 node with a USB SSD (or a separate block device), plus on a node whose root is ZFS or btrfs. Record whether Longhorn needs a separate disk.
- [ ] **Step 3:** SNR + NHC, with `softdog` on cloud VMs.
  - Partition one node (`iptables -I INPUT -j DROP` on mesh + API) and record `T_fence` to reboot.
  - Power one off, apply the out-of-service taint after `T_fence` + margin, and record the detach time and the stateful pod start time elsewhere.
  - Target 2–4 min.
- [ ] **Step 4:** etcd fsync p99 on the arm64 node during a Longhorn rebuild.
- [ ] **Step 5:** ServiceLB with `enablelb` labels and `externalTrafficPolicy: Local` on 2 ingress nodes: the client IP is kept and both answer.
- [ ] **Step 6:** Hairpin probe (D12): from each node, `curl --resolve auth.<d>:443:<public ip of another node>`. Record per network.
- [ ] **Step 7:** Multi-value A records through the domains providers: Porkbun (our v3 client) and Cloudflare. Append a second A, delete one by id, and confirm what the public resolvers serve.
- [ ] **Step 8: Across sites** (D9 layout: `vm4` in a second region as site `edge`).
  - Measure the `pcmesh` RTT p95 `vm4` ↔ `main`.
  - Join `vm4` as an agent with the etcd timings of Global Constraints on the servers, and record that a server leader election under the cross-region link stays ≤ 3 s.
  - flannel `wireguard-native` inside `pcmesh` (R12): record the working MTU, and `iperf3` pod-to-pod `main` ↔ `edge`.
  - Block inbound UDP 51830 on `vm2` (NATed at `main`, while `vm1` stays the gateway), and record that `vm2` ↔ `vm4` traffic relays through `vm1` with forwarding limited to `pcmesh`.
  - Cross-site probes: `vm4` probing `main`'s public addresses and back, and a blind prober (`vm4`'s egress dropped).
- [ ] **Step 9:** Commit the report and the pins amendment (`plan: HA spike 1 results and pins`). **Any "doesn't" answer stops the plan for a user decision.**

### Task 4: Spike — the components inside the cluster (builder, k3d + one VM run)

**Files:** Create (Hub): `.superpowers/sdd/2026-11-18-high-availability/spike-components.md`. Throwaway manifests under `/tmp/pk-ha-spike/`, never committed.

- [ ] **Step 1:** CNPG 2 instances with `dataDurability: preferred`.
  - Delete the primary pod, then its k3d node container. Record the promotion time.
  - Record that the isolation check (`.spec.probes`/primary isolation, version-specific) shuts down an isolated primary.
  - Record 3 instances with `required`.
- [ ] **Step 2:** Keycloak 26 (the `portcullis-keycloak` image at its current digest) × 2 on CNPG.
  - Use `KC_CACHE=ispn` with the default `jdbc-ping` stack. JGroups ports 7800/57800 need the NetworkPolicy flow.
  - Sign in, kill the replica holding the session, and refresh: the session survives.
  - Do a rolling restart under a sign-in loop.
- [ ] **Step 3:** LLDAP × 2 on one Postgres. Run concurrent user creates and group changes: record any error or duplicate. If unsafe → 1 replica (spec §7.4).
- [ ] **Step 4:** LLDAP SQLite → Postgres conversion, following LLDAP's documented database migration. Record the exact steps, and that `users.uuid`, `password_hash` and memberships survive (a diff query).
- [ ] **Step 5:** Valkey primary + replica + 3 sentinels. oauth2-proxy (the core's pinned version) with `--redis-use-sentinel`, the master name and the sentinel URLs. Kill the primary: record the promotion time and the sessions lost.
- [ ] **Step 6:** Vault raft, 3 voters through `retry_join` on the headless Service, with auto-unseal from one Secret. Kill the leader: record the election time. Take a snapshot from the leader through `vault-active`.
- [ ] **Step 7:** ConfigMap propagation (D2): measure the time to mounted update with the default kubelet and with `sync-frequency=10s`, over 20 runs (p50/p99).
- [ ] **Step 8:** Commit the report (`plan: HA spike 2 results`). A "doesn't" answer stops the plan for a user decision.

---

## Stream H — Hub

### Task 5: The write fence — `internal/leader`, the fsutil gate, 503 while standing by (Hub)

**Files:**
- Create: `internal/leader/leader.go`, `internal/leader/leader_test.go`, `internal/leader/envtest_test.go` (`//go:build envtest`).
- Create: `internal/fsutil/gate.go`, `internal/fsutil/gate_test.go`, `internal/fsutil/nowrites_test.go`.
- Modify: `internal/fsutil/fsutil.go` (each writer calls `gate()` first), `internal/state/state.go` (`Save`), `internal/hub/ops.go`, the audit appender (the file that holds `auditOp`'s append), `internal/runtime/kube/backend.go` (`apply` checks the gate).
- Create: `internal/httpapi/leader.go`. Modify `internal/httpapi/server.go` (the middleware chain).
- Modify: `cmd/hub/main.go`, `cmd/hub/kube.go`.

**Interfaces:**
- Consumes: the client-go `kubernetes.Interface` from `kubeRuntime`.
- Produces:
  - `package leader`:
    - `type Config struct{ Client kubernetes.Interface; Namespace, Name, Identity string; LeaseDuration, RenewDeadline, RetryPeriod time.Duration }`;
    - `func New(cfg Config) *Fence`;
    - `func Always() *Fence` (Docker: always leading);
    - `func (f *Fence) Run(ctx context.Context)`;
    - `func (f *Fence) WaitLeading(ctx context.Context) error`;
    - `func (f *Fence) Check() error` (nil, or `ErrStandingBy`);
    - `var ErrStandingBy = errors.New("this Hub is standing by: another Hub is the active writer")`.

    `Check` answers `ErrStandingBy` once the last successful renew is older than `RenewDeadline` (10 s), measured locally with a monotonic clock, **before** client-go's own callback fires.
  - `fsutil.SetWriteGate(func() error)`: every `WriteFileAtomic*`, `AppendFile`, `MkdirAll*` and `Remove*` wrapper returns the gate's error first.
  - httpapi `leaderGate(next)`: every non-`GET`/`HEAD` request → 503 with `ErrStandingBy`'s text while `Check() != nil`; `GET /healthz` reports `{"leading": bool}`.

- [ ] **Step 1: Write the failing tests.**

```go
func TestCheckStandsByAfterRenewDeadline(t *testing.T)   // fake clock: renew at t0; Check()==nil at t0+9.9s; ErrStandingBy at t0+10s
func TestAlwaysLeads(t *testing.T)                        // Always().Check()==nil
func TestWriteGateRefusesEveryWriter(t *testing.T)        // gate returns ErrStandingBy → WriteFileAtomic, WriteFileAtomicGroup, AppendFile, state.Save all return it and the file is unchanged (sha256 before == after)
func TestNoFileWritesOutsideFsutil(t *testing.T)          // go/ast over ./internal ./cmd (non-test): no os.WriteFile, os.Create, os.OpenFile with O_WRONLY|O_RDWR|O_CREATE|O_APPEND, os.Rename, os.Remove* outside internal/fsutil, except allowlist entries with reasons (folderfix runs in helpers; cmd/hub helper subcommands)
func TestLeaseLostStopsInflightWrites(t *testing.T)       // a background op writing every 100 ms; renewals stop at t0; no write lands after t0+10s (file mtime/sha), op ends with ErrStandingBy recorded in memory only
func TestStandbyAnswers503(t *testing.T)                  // POST /api/... → 503 body {"error":"this Hub is standing by: another Hub is the active writer"}; GET /api/... → 200
// envtest:
func TestSecondHubNeverWrites(t *testing.T)               // two Fences on one Lease; only one Check()==nil at any sampled instant over 60 s with the leader's client cut at 20 s; the second leads only after LeaseDuration from the last renew
```

- [ ] **Step 2:** Run `go test ./internal/leader/ ./internal/fsutil/ ./internal/httpapi/ -run 'Check|Always|WriteGate|NoFileWrites|LeaseLost|Standby'` and `-tags envtest ./internal/leader/`. Expected: FAIL (package missing).
- [ ] **Step 3: Implement.**
  - The `Fence` wraps `leaderelection.LeaderElector` with a `resourcelock.LeaseLock`, and `ReleaseOnCancel: false`.
  - `cmd/hub/kube.go`: `leader.New{Namespace: core ns, Name: "portcullis-hub", Identity: $POD_NAME}`; `main` calls `fsutil.SetWriteGate(f.Check)` and waits `WaitLeading` before `hub.New`.
  - Docker uses `leader.Always()`.
  - The start-time sweeps (`afterEngineVerified`) run only after leading.
  - Fix the call sites `TestNoFileWritesOutsideFsutil` finds by moving them to fsutil.
- [ ] **Step 4:** Run the tests again. Expected: PASS. Then the full Hub gate.
- [ ] **Step 5:** Commit (`hub: Lease write fence, fsutil write gate, 503 while standing by`).

### Task 6: Published documents (Hub)

**Files:**
- Create: `internal/publish/{publish.go,file.go,publish_test.go}`, `internal/runtime/kube/publish.go`, `internal/runtime/kube/publish_test.go`.
- Modify: `internal/hub/hub.go` (`writePolicy`), `signin_publish.go`, `impersonation_file.go`, `portal.go`, `ai_gatefile.go`, `vpn_publish.go`, `internal/policy/file.go`, `attributes.go`, `internal/aigate` writers, `deliver_headers.go:461`.
- Create: `internal/doctor/publish.go`.
- Modify (D3/D2): `internal/runtime/kube/guard.go` + `testdata/role-core.yaml` (new); the envtest `TestRoleIsEnough` covers it.

**Interfaces:**
- Consumes: `published_docs.json` (Task 2); `leader.Fence.Check` (Task 5, via fsutil and its own check).
- Produces:
  - `package publish`:
    - `type Doc string` with consts `GroupGatePolicy`, `UserAttributes`, `PortalApps`, `SignInKeycloak`, `Impersonation`, `MCPGate`, `MCPCredentials`, `VPN`;
    - `type Sink interface { Publish(ctx context.Context, d Doc, data []byte) (rev string, err error); Confirmed(ctx context.Context, d Doc, rev string) (bool, error) }`;
    - `FileSink{Dirs map[Doc]string; GID map[Doc]int}` (Docker: today's paths and modes, byte for byte);
    - `const MaxDoc = 1_000_000`;
    - `var ErrTooLarge`.
  - kube `(*Backend).DocSink() publish.Sink`: `update` on the named ConfigMap/Secret (data key + `.rev`); `Confirmed` runs `/portcullis-bin/hub rev /hub-data` (or `/vpn-doc`) in each reader pod found by label `portcullis.io/component in (readers)`.
  - `Hub.publish(d publish.Doc, data []byte) error`. Over `MaxDoc` → `ErrTooLarge`: the last document stays and `published_doc_too_large` is raised with the doc name and size.
  - `RulesExact` / `expand` accept `ResourceNames`, keyed `group/resource/verb/name`, and the core namespace must equal `role-core.yaml`.

- [ ] **Step 1: Write the failing tests.**

```go
func TestFileSinkByteCompatible(t *testing.T)      // FileSink writes the same bytes, mode and gid as today's writers for every Doc (golden from current code)
func TestPublishTooLargeKeepsLast(t *testing.T)    // 1_000_001 bytes → ErrTooLarge; object still holds the previous data and .rev; doctor kind published_doc_too_large with doc name; nothing written partially
func TestDocSinkUpdatesNamedObjectOnly(t *testing.T) // fake clientset: only update/patch on the published_docs.json object names; any other name → test fails via reactor
func TestDocSinkConfirmedReadsRev(t *testing.T)    // exec fake returns old rev then new; Confirmed false then true
func TestPublishedStaleAfter120s(t *testing.T)     // Confirmed false for 120 s → published_doc_stale (Problem) naming reader pod
func TestPublishedDocsVectorsMatchCode(t *testing.T) // every Doc const ↔ one vector row; object/key/mount equal
func TestExpandResourceNames(t *testing.T)         // a rule with resourceNames expands per name; a wildcard name still refused
func TestRoleExactCore(t *testing.T)               // core ns review == role-core.yaml; one extra name → refused "more than the Role"
```

- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement. Every writer in `writePolicy` and the others goes through `h.publish`. The kube backend picks `DocSink()` when `kubeOn()`, otherwise `FileSink`. With Kubernetes, `hub-data` is the Hub's own volume (`hub-state`), and no reader mounts it.
- [ ] **Step 4:** Run the tests again, plus `-tags envtest -run 'RoleIsEnough|Admission'`. Expected: PASS.
- [ ] **Step 5:** Commit (`hub: published documents as named ConfigMaps/Secrets on Kubernetes; core-namespace Role`).

### Task 7: Per-replica gate logs and wg status (Hub, D6)

**Files:**
- Create: `internal/gatelogs/{client.go,merge.go,gatelogs_test.go}`.
- Modify: `internal/hub/signin_history.go`, `impersonation_apps.go`, `ai_accesslog.go`, the VPN status reader (`internal/hub/vpn*.go`, which reads `HUB_VPN_STATUS_FILE`), `cmd/hub/main.go` (`HUB_GATE_LOG_SOURCES`).
- Modify: `internal/signinhistory` (`OpenedLog` gets a `Source` interface).

**Interfaces:**
- Consumes: §20.10 (Task 1).
- Produces:
  - `gatelogs.Source interface{ Read(ctx, gatelogs.Query{From, To time.Time; Keep func([]byte) bool; Budget *gatelogs.Budget}) ([]byte, error) }` (as shipped: a time window, a line filter and one byte budget, 64 MiB, over every replica; the opened log reads it day by day, newest first, answering `*Partial` when the budget runs out);
  - `gatelogs.Replicas{Service string; Port int; Lister func(ctx) ([]gatelogs.Replica{Name, Addr}, error); Client; MaxPages}`, where the lister is kube `(*Backend).CoreReplicas(component, ReplicaOptions{StatefulSet, Expected})`: the Hub's `pods list` in the core namespace (Task 6 Role), pods owned by the component's own controller; pending, terminating, failed pods and expected ordinals without a pod are listed without an address (unread → incomplete). `gatelogs.Tail` follows mcp-gate's access log (newest 4 MiB per replica, first fill from 1 h back widened ×4, incomplete until caught up);
  - `gatelogs.Merge(parts [][]byte) []byte` (stable by timestamp, then replica);
  - an unreadable replica → `Incomplete = true`.

  On Docker, the file sources are unchanged (`Dir`). `HUB_GATE_LOG_SOURCES=http` (set by the chart) selects HTTP.

- [ ] **Step 1: Write the failing tests.**

```go
func TestMergeTwoReplicasOrdered(t *testing.T)        // interleaved timestamps → one ordered stream, duplicates (same line, same replica) kept once
func TestReplicaDownMarksIncomplete(t *testing.T)     // one source errors → entries from the other + Incomplete true; impersonation apps marked incomplete (existing behaviour)
func TestOpenedLogFileSourceUnchanged(t *testing.T)   // Docker: Dir source byte-equal results to today's tests
func TestAnswerCappedAt4MiB(t *testing.T)             // a source answering 4 MiB + 1 → error, Incomplete
func TestWGStatusFromHTTP(t *testing.T)               // status JSON via http source equals file parse
```

- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement. The pruning to `history_days` (today a write to `group-gate-data`) is now each gate's own job (Task 22). The Hub no longer writes there on Kubernetes.
- [ ] **Step 4:** Run them. Expected: PASS.
- [ ] **Step 5:** Commit (`hub: per-replica gate logs and wg status over the core namespace (HA)`).

### Task 8: Join code v2 and cluster-node enrolment (Hub)

**Files:**
- Modify: `internal/servers/joincode.go` (+ `joincode_v2.go`), `internal/state/servers.go` (`Server.Kind`, `"worker"` | `"cluster-node"`; `Role`, `Class`, `Site`, `Labels`).
- Create: `internal/hub/servers_cluster.go`.
- Modify: `servers.go` (`serversOn` per R9), `servers_enrol.go` (cluster steps), `servers_revoke.go`.
- Create: `internal/nodeadm/{client.go,types.go,client_test.go}`.
- Modify: `internal/httpapi/servers.go`, `mcp_parity_test.go` (`serverNoToolRoutes`), `web/servers.js`.

**Interfaces:**
- Consumes: `nodeadm_api_vectors.json`, `joincode_v2_vectors.json` (Task 2); `controlCert` (`nodecerts.go`).
- Produces:
  - the code: `servers.JoinCodeV2` + `EncodeV2`/`DecodeJoinCodeV2` (redacting `String`);
  - the client: `nodeadm.Client{BaseURL string; TLS *tls.Config}` with:
    - `IssueCode(ctx, CodeRequest) (CodeAnswer, error)`;
    - `Cluster(ctx) (Snapshot, error)`;
    - `SetLabels(ctx, id string, l Labels) error`;
    - `Cordon` / `Uncordon` / `Drain(ctx, id) error`;
    - `Remove(ctx, id string, mode RemoveMode) error`;
    - `type APIError{Kind string}`.
  - `Hub.AddClusterNode(ctx, actor, AddClusterNodeRequest{ID, Role, Class, Site, Labels}) (op OpRef, code string, err error)`: role suggestion = server while there are < 3 healthy servers; refused on Docker.
  - The `server_enrol` steps are `enrolled`, `mesh_ready` (Task 10), `k3s_joined`, `node_ready`, `storage_ready` and `done`, each read from `Cluster()` and the nodeagent.
  - `Hub.RemoveClusterNode(ctx, actor, id, typed, mode)`.

- [ ] **Step 1: Write the failing tests.**

```go
func TestJoinCodeV2Vectors(t *testing.T)            // every valid decodes to decoded; every invalid → its exact error
func TestJoinCodeV2NeverPrintsSecret(t *testing.T)  // fmt %v / %#v / json of JoinCodeV2 contain no secret bytes (hex, base64, base64url)
func TestNodeadmClientVectors(t *testing.T)         // httptest server replays nodeadm_api_vectors.json; every error kind → APIError{Kind}
func TestAddClusterNodeSuggestsRole(t *testing.T)   // 1 server → server; 3 healthy servers → agent; override kept; 4th server → warning "an even number of servers doesn't add failure tolerance"
func TestAddClusterNodeNeedsFreshSignIn(t *testing.T) // POST /api/servers kind cluster-node without fresh auth → 401 fresh_auth_required; audit server.add only on success
func TestServerJoinDialogText(t *testing.T)         // the answer for role server carries "Joining as a server gives this machine full control of the cluster (cluster-admin)."
func TestClusterNodeRoutesNeverOverMCP(t *testing.T) // POST /api/servers, DELETE, revoke in serverNoToolRoutes; TestToolParity passes
func TestEnrolStepsFromSnapshot(t *testing.T)       // snapshots in order → op steps enrolled→mesh_ready→k3s_joined→node_ready→storage_ready→done; Stop during → op stopped, nodeadm Remove(cooperative) called
func TestRemoveRefusedBelowQuorum(t *testing.T)     // nodeadm 409 quorum_minimum → 409 "removing <id> would leave fewer than 3 servers"
func TestWorkersRefusedOnKube(t *testing.T)         // kind worker on kube → 409 "Docker workers can't join a Kubernetes cluster: add it as a cluster node"
```

- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement. The UI's Add server dialog gets the kind choice (Kubernetes only), role, class, site, the one-liner, the cluster-admin warning for servers and the progress panel. The Revoke now dialog needs the typed id.
- [ ] **Step 4:** Run them. Expected: PASS.
- [ ] **Step 5:** Commit (`hub: cluster nodes — join code v2, nodeadm client, enrol op, removal`).

### Task 9: `portcullis-nodeagent` (Hub, D7)

**Files:**
- Create: `cmd/portcullis-nodeagent/main.go`, `internal/nodeagent/{server.go,mesh.go,checks.go,probes.go,class.go,enrol.go}` + tests, `Dockerfile.nodeagent`.
- Modify: `.github/workflows/build.yml`: the matrix gains `nodeagent`, which also uploads `nodeagent-linux-{amd64,arm64}` with their sha256 as release and `edge` artifacts. The `nodeadm` image (Task 21) copies them from `ghcr.io/porelli/portcullis-nodeagent@sha256:…`.

**Interfaces:**
- Consumes: §20.4 and the join code v2 (Tasks 1, 2); the mTLS peer checks of `internal/agent/server.go` (shared through a new `internal/pkinode` package extracted from it).
- Produces: the `portcullis-nodeagent` subcommands:
  - `join <code-on-stdin>`: the host checks, the HMAC proof to `/node/v1/enrol`, the CSR, the `pcmesh` key, and `/node/v1/join` → k3s install with the material over the mTLS channel;
  - `serve`;
  - `checks`.

  The API is §20.4. Probes run every 10 s against each other ingress node's public address with SNI `auth.<d>`, and `GET /v1/probes` answers the last 3 rounds, each round `{prober, site, reached_any, results:{<target>:{ok, class}}}` (the blind bit of R10 is `reached_any == false`). `join` sends the mesh RTT to every server (`GET /v1/mesh/rtt` on itself, Task 10) in the `/node/v1/join` request after `mesh_ready`. `class.Suggest(mem, cpu, model, publicAnswers) string`.

- [ ] **Step 1: Write the failing tests.**

```go
func TestNodeClassVectors(t *testing.T)           // nodeclass_vectors.json
func TestPeersIdempotent(t *testing.T)            // PUT same list twice → one wg set call; a removed peer is removed; own key never in list → 400
func TestOnlyFixedOperations(t *testing.T)        // routing table == §20.4 list; any other path 404
func TestFrontdoorCertOnlyProbes(t *testing.T)    // frontdoor.control client: GET /v1/probes 200, PUT /v1/mesh/peers 403
func TestJoinRefusesBadProof(t *testing.T)        // fake nodeadm answers proof_invalid → exit 1 "the join code was refused", k3s never installed (fake installer untouched)
func TestJoinNeverLogsSecrets(t *testing.T)       // captured stdout/stderr/log contain neither the code secret nor the k3s token nor the wg private key
func TestHostChecksList(t *testing.T)             // checks: kernel wireguard, open-iscsi, nfs-common, watchdog device, AppArmor stacking sysctl, ports 6443/2379/2380/10250 free, mesh subnet unused
func TestProbeHairpinFallback(t *testing.T)       // all public probes fail with a connect error class "no route from inside" → internal_only true (D12)
```

- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement. WireGuard goes through `golang.zx2c4.com/wireguard/wgctrl` (a mature library). k3s is installed from the pinned script and binary (sha256 checked) with the flags in Task 17, and the `--token-file` comes from the channel (never argv, never logged).
- [ ] **Step 4:** Run them. Expected: PASS. Build both arches.
- [ ] **Step 5:** Commit (`nodeagent: host agent for cluster nodes (enrol, mesh, checks, probes)`).

### Task 10: The mesh across sites and NAT — `internal/meshplan`, the nodeagent's side, the Hub's push (Hub)

**Files:**
- Create: `internal/meshplan/{plan.go,plan_test.go}`, `internal/hub/servers_mesh.go`, `internal/hub/servers_mesh_test.go`, `internal/nodeagent/netns_test.go` (`//go:build netns`).
- Modify: `internal/nodeagent/mesh.go` (endpoints, keepalive, gateway forwarding, RTT), `internal/hub/servers_poll.go` (a node that missed the plan gets it at its next poll), `.github/workflows/build.yml` (step "mesh netns (root)": `sudo -E go test -tags netns ./internal/nodeagent/ -run TestMeshNetns`).

**Interfaces:**
- Consumes: `meshplan_vectors.json` (Task 2); the nodeagent API (Task 9); §20.11 (Task 1).
- Produces:
  - `package meshplan`:
    - `type Node struct{ ID, Site string; MeshIP netip.Addr; LAN netip.AddrPort; Public netip.AddrPort /* zero = behind NAT */; Pub string }`;
    - `type Peer struct{ ID, Pub string; Endpoint netip.AddrPort /* zero = none */; AllowedIPs []netip.Prefix; Keepalive int }`;
    - `type NodePlan struct{ Peers []Peer; Forward bool }`;
    - `func Plan(nodes []Node) (map[string]NodePlan, error)`;
    - `func Gateway(nodes []Node, site string) (string, bool)`.
  - `Hub.pushMesh(ctx context.Context) error`: computes `Plan` from the servers state plus the snapshot, then `PUT /v1/mesh/peers` on every nodeagent. It runs on every join, removal and public-endpoint change. One unreachable agent doesn't block the others; that node gets `mesh_peer_stale` after 5 min.
  - In the nodeagent:
    - `mesh.Apply(plan NodePlan) error` uses wgctrl, plus the iptables rules from Global Constraints when `Forward`;
    - `GET /v1/mesh/rtt` answers the p95 of 20 ICMP-less UDP echo rounds to each peer's mesh address on `:7444` (the nodeagent's own echo listener, mesh-only).

- [ ] **Step 1: Write the failing tests.**

```go
func TestMeshPlanVectors(t *testing.T)            // every vector: Plan(nodes) == want, or the exact want_error
func TestNATedPairRelaysViaGateway(t *testing.T)  // a@main NAT, b@edge NAT, gw(edge)=e1: a's peer e1 AllowedIPs ⊇ b/32; b's peer gw(main) ⊇ a/32; a has no direct peer b
func TestForwardOnlyOnGateways(t *testing.T)      // Forward true exactly for each site's gateway when that site has a NATed node and another site exists
func TestKeepaliveOnlyBehindNAT(t *testing.T)     // Keepalive 25 iff the node itself has no public endpoint
func TestPushMeshOnJoin(t *testing.T)             // join completes → every fake nodeagent got the new plan; the new node's plan first
func TestPushMeshPartialFailure(t *testing.T)     // one agent down → others updated, op not failed; after 5 min doctor mesh_peer_stale names it
func TestForwardRulesPcmeshOnly(t *testing.T)     // the rule set applied with Forward == exactly ["-A FORWARD -i pcmesh -o pcmesh -j ACCEPT"] plus the chain's default DROP for pcmesh; removed when Forward false
func TestRTTEndpoint(t *testing.T)                // echo peer with 30 ms injected delay → p95 within [30, 40] ms
// netns (root, builder and Hub CI):
func TestMeshNetns(t *testing.T)                  // 4 netns as nodes, 2 "sites", NAT by nftables masquerade; Apply each plan; ping every mesh ip from every node; a NATed↔NATed cross-site pair answers through the gateway; dropping the gateway's forward rule breaks exactly that pair
```

- [ ] **Step 2:** Run `go test ./internal/meshplan/ ./internal/hub/ ./internal/nodeagent/ -run 'MeshPlan|NATed|Forward|Keepalive|PushMesh|RTT'`. Expected: FAIL.
- [ ] **Step 3:** Implement `Plan`. Peers are sorted by id, so the output is deterministic. Pick the gateway with `Gateway` (the lowest id among reachable nodes of the site). The Hub's enrol op (Task 8) gains the step `mesh_ready` between `enrolled` and `k3s_joined`: the new node's plan is applied, and so is every existing node's plan with the new peer.
- [ ] **Step 4:** Run them again, plus the netns test on the builder (`sudo`). Expected: PASS.
- [ ] **Step 5:** Commit (`hub, nodeagent: the node mesh across sites and NAT`).

### Task 11: Sites, the server layout across sites, RTT limits (Hub)

**Files:**
- Create: `internal/servers/siteroles.go`, `internal/servers/siteroles_test.go`, `internal/hub/sites.go`, `internal/hub/sites_test.go`.
- Modify: `internal/hub/servers_cluster.go` (the role suggestion goes through `SuggestRole`; storage outside `main` refused), `internal/httpapi/servers.go` (site in the add request, already there; the answer gains `warnings`), `web/servers.js` (site field with existing sites offered; the warnings shown).

**Interfaces:**
- Consumes: `site_roles_vectors.json` (Task 2); the RTT from the joining node's nodeagent (Task 10), reported in the enrol op before `k3s_joined`; `nodeadm.Snapshot` (Task 8).
- Produces:
  - `servers.SuggestRole(cluster []ClusterNode, new NewNode) (role string, warnings []string, err error)`, with `ClusterNode{ID, Site, Role string; Healthy bool}` and `NewNode{Site string; RTTms map[string]int; Override string}`;
  - `servers.CheckRTT(role string, rttms map[string]int) error`, with the exact texts of Global Constraints;
  - `Hub.Sites(ctx) ([]SiteView, error)`, with `SiteView{Name string; Primary bool; Nodes, Servers []string; Gateway string; Ingress []string; RTTms map[string]int}`;
  - the enrol op refuses a node whose RTT fails `CheckRTT` **after** `mesh_ready` and **before** `k3s_joined`, then removes its peer from every plan.

- [ ] **Step 1: Write the failing tests.**

```go
func TestSiteRolesVectors(t *testing.T)          // every vector → want role + warnings, or the exact error
func TestTwoSitesWarnTiebreaker(t *testing.T)    // second site's first node → agent + "Only main can survive on its own: add a tie-breaker at a third location (a small cloud VM or a Pi elsewhere)."
func TestThreeSitesNoMajority(t *testing.T)      // main 2, edge 1, tb 0 servers; new at tb → server; new at main → agent
func TestServerTooFarRefusedBeforeJoin(t *testing.T) // RTT 120 ms → op failed "too far for one cluster: 120 ms (servers need 100 ms or less)"; nodeadm never asked for join material; peer removed from plans
func TestStorageOnlyAtPrimary(t *testing.T)      // labels storage=true at site edge → 400 "storage nodes must be at the primary site (main) in this version"
func TestSitesView(t *testing.T)                 // snapshot + plans → SiteView per site, gateway named, primary only main
```

- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement. `SuggestRole` keeps the one-site behaviour of Task 8 (`TestAddClusterNodeSuggestsRole` still passes unchanged).
- [ ] **Step 4:** Run them, plus Task 8's tests. Expected: PASS.
- [ ] **Step 5:** Commit (`hub: sites, server layout across sites, RTT limits`).

### Task 12: The N−1 simulator (Hub)

**Files:** Create `internal/nminus1/{nminus1.go,nminus1_test.go}`.

**Interfaces:**
- Consumes: `nodeadm.Snapshot{Nodes []Node{Name, Ready, Allocatable{CPU, Mem}, Labels, Taints}; Pods []Pod{Name, NS, Node, Priority, PriorityClass, PreemptionPolicy, Requests{CPU, Mem}, Tolerations, RequiredAffinity, AntiAffinityHost, SpreadHost bool, DaemonSet bool}}` (Task 8 types).
- Produces: `func Check(s nodeadm.Snapshot) []Result`, with `Result{Node string; Level Level /*Green|Yellow|Red*/; Unplaced, Evicted []string}`; `func Explain(r Result) string` ("if <node> fails, <x> won't have room").

The algorithm the tests don't fully fix:
- For each node N, remove N.
- Sort its non-DaemonSet pods by priority (descending), then by requests (descending).
- First-fit each pod onto the remaining Ready nodes that pass taints, required affinity and hostname anti-affinity/spread. Free capacity there may come from evicting `normal`/`low` pods, lowest priority first, but never pods with priority ≥ the pod's own. A `low` pod never evicts.
- Red if any core or critical pod is unplaced; yellow if a high pod needed a `normal` eviction; else green.

- [ ] **Step 1: Write the failing test.** `func TestNMinus1Vectors(t *testing.T)` iterates `nminus1_vectors.json` and asserts `Check(snapshot)` equals `want` (level, unplaced, evicted, order-insensitive).
- [ ] **Step 2:** Run it. Expected: FAIL.
- [ ] **Step 3:** Implement as above.
- [ ] **Step 4:** Run it. Expected: PASS.
- [ ] **Step 5:** Commit (`hub: N−1 simulator`).

### Task 13: Translator — priority, tolerations, *Runs on*, requests (Hub)

**Files:**
- Modify: `internal/runtime/kube/translate.go` (`workload()`, the container resources around :1163), `names.go` (priority class names), `internal/runtime/types.go` (`Input.Availability`).
- Create: `testdata/translate/ha-priority/`, `ha-runs-on-only-small/`, `ha-no-memlimit/`.

**Interfaces:**
- Consumes: `state.Availability` (Task 14).
- Produces:
  - `runtime.Availability{Priority string /*critical|high|normal|low*/; RunsOn RunsOn{Mode "anywhere"|"prefer"|"only"; Class, Site string; Nodes []string}; HA bool}`;
  - priority class `portcullis-<priority>`;
  - with `HA`, tolerations for not-ready/unreachable at 30 s;
  - `anywhere` → required `portcullis.io/class NotIn [small]`;
  - `prefer` → preferred terms;
  - `only` → required `kubernetes.io/hostname In nodes`, plus a `portcullis.io/class In [small]` term and the small toleration when any chosen node is small (R2);
  - CPU request `50m` (or the manifest's, phase 2), no CPU limit;
  - no memory → 512Mi request = limit;
  - `templateNoMemoryLimit(id) bool` for the doctor.

- [ ] **Step 1:** Write the goldens: the three new cases' `case.json`, with the expected `want.yaml` written by hand from the rules above. Also `TestTranslateNoCPULimit` and `TestTranslateDefaultMemory`.
- [ ] **Step 2:** Run `go test ./internal/runtime/kube/ -run 'TranslateGoldens|NoCPULimit|DefaultMemory'`. Expected: FAIL.
- [ ] **Step 3:** Implement. Existing goldens change only by `priorityClassName: portcullis-normal`, the class `NotIn [small]` term and the CPU request: re-generate with `-update` and review the diff line by line.
- [ ] **Step 4:** Run the test again, plus `-tags envtest -run TranslatedObjectsAdmitted` (it passes after Task 18's policies are copied; until then it runs against the current copy and must still pass, because the current policies don't refuse these fields). Expected: PASS.
- [ ] **Step 5:** Commit (`hub: translator renders priority, HA tolerations, Runs on, CPU/memory requests`).

### Task 14: Instance availability — priority and *Runs on* (Hub, D11)

**Files:** Create `internal/state/availability.go`, `internal/hub/availability.go`, `internal/httpapi/availability.go`, `internal/httpapi/mcptools_availability.go`, `web/availability.js` (add to `//go:embed`). Modify `web/index.html` (Instance → Manage → Availability) and the setup form (priority only).

**Interfaces:**
- Consumes: `nminus1.Check` / `Explain` (Task 12), `nodeadm.Client.Cluster` (Task 8).
- Produces:
  - `state.Instance.Availability *Availability` (nil = defaults);
  - `GET /api/instances/{id}/availability` → `{priority, runs_on, nodes:[{name, class, site, small}], n_minus_1:[…]}`;
  - `PUT …/availability` `{priority, runs_on, confirm_n_minus_1?}`: a raise to `critical`/`high` that makes any node red or yellow → 409 `{error:"if <node> fails, <x> won't have room", n_minus_1}` unless `confirm_n_minus_1: true`; audited `instance.availability`; a restart of the instance;
  - MCP tool `instance_availability_get` (R). The PUT is MCP class W with the confirmation.

- [ ] **Step 1: Write the failing tests.**

```go
func TestAvailabilityDefaults(t *testing.T)            // nil → normal / anywhere
func TestRaiseToCriticalRunsNMinus1First(t *testing.T) // fake snapshot red → 409 with the exact text; nothing saved; with confirm → saved + audited
func TestOnlySmallNodeNeedsSmallNode(t *testing.T)     // runs_on only [pi] where pi class != small → 400 "pi isn't a small node"; unknown node → 400 "unknown node pi"
func TestAvailabilityRefusedOnDocker(t *testing.T)     // Docker → 409 "availability needs Kubernetes"
func TestAvailabilityAPIStrict(t *testing.T)           // unknown key, priority "core" → 400
```

- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement. The UI goes in `web/availability.js`: a priority select, *Runs on* radios with a node picker, and the N−1 result. Escape everything (`escapeHtml`).
- [ ] **Step 4:** Run them, plus `TestToolParity`. Expected: PASS.
- [ ] **Step 5:** Commit (`hub: instance priority and Runs on (Kubernetes)`).

### Task 15: The HA page (Hub, D4, D5, D13)

**Files:** Create `internal/hub/ha.go`, `internal/httpapi/ha.go`, `internal/httpapi/mcptools_ha.go`, `web/ha.js`. Modify `web/index.html` (Settings → High availability).

**Interfaces:**
- Consumes:
  - `nodeadm.Snapshot` (nodes, quorum per system, CNPG sync state, Longhorn robustness, fencing per node);
  - `frontdoor-status` (via the Role's `get`);
  - `nminus1.Check`;
  - the backup destination state (`state.BackupDestination`, read from `core.env`'s `PORTCULLIS_BACKUP_S3_URL` presence — never the credentials);
  - `frontdoor_vectors.json` worst-case texts.
- Produces:
  - `GET /api/ha` → `{experimental: true, enabled, checklist:[{id, ok, text}], guarantee, nodes:[{name, role, class, site, ready, fencing, n_minus_1}], quorum:{etcd, vault, sentinel}, sites:[SiteView…] (Task 11), dns:[{name, addresses, worst_case_text, per_site:[{site, healthy}]}], credentials_note, command:"./portcullis ha enable"}`;
  - the checklist ids `nodes`, `servers`, `storage`, `ingress`, `backup_destination`, `n_minus_1`, `watchdog`, plus with ≥ 2 sites `site_gateway` (every site has a reachable node) and `site_rtt` (every server within 100 ms). The 2-site tie-breaker warning is shown, but it isn't a blocker;
  - the guarantee texts from the spec (verbatim);
  - for Porkbun, `credentials_note` = "Porkbun API keys can change every domain in the account: Portcullis can't narrow them";
  - MCP `ha_status` (R).

- [ ] **Step 1: Write the failing tests.**

```go
func TestHAChecklistFromSnapshot(t *testing.T)  // 2 nodes → nodes false "at least 3 nodes"; a site without a gateway → site_gateway false "site <s> needs one node reachable on UDP 51830"; no destination → backup_destination false "set an offsite backup destination first"
func TestGuaranteeText(t *testing.T)            // 2 instances + preferred + 1 sync standby → "Zero loss on one failure"; 0 sync standbys → "Degraded: one more failure may lose the last writes"
func TestWorstCaseTextVectors(t *testing.T)     // frontdoor_vectors.json want_worst_case_text
func TestHAPageNeverShowsCredentials(t *testing.T) // response JSON has no key or value from frontdoor-env / backup-destination fixtures
func TestHAEnableIsNotAnAPI(t *testing.T)       // POST /api/ha/enable → 404 (D5); the page shows the command
```

- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement. The banner reads "High availability is experimental".
- [ ] **Step 4:** Run them, plus `TestToolParity`. Expected: PASS.
- [ ] **Step 5:** Commit (`hub: Settings → High availability page`).

### Task 16: Doctor kinds and MCP read tools (Hub)

**Files:** Create `internal/doctor/ha.go`, `internal/hub/doctor_ha.go`, `internal/doctor/ha_test.go`. Modify `internal/hub/doctor_runtime.go`.

**Interfaces:**
- Consumes: Tasks 6, 8, 12, 13, 15. (Task 13 review M4: `template_no_memory_limit` calls `kube.NoMemoryLimit(model *types.Project) []string`, the services without a memory limit, once per enabled instance; Task 13's brief named `templateNoMemoryLimit(id) bool`, which does not exist.)
- Produces: `doctor.HAKinds` = `node_down`, `ha_quorum_at_risk`, `volume_degraded`, `pg_not_synchronous`, `ha_fencing_unavailable`, `ha_n_minus_1_insufficient`, `backup_stale`, `template_no_memory_limit`, `frontdoor_probes_internal_only`, `published_doc_too_large`, `published_doc_stale`, `ha_lease_lost`, `mesh_site_no_gateway`, `mesh_peer_stale`, `mesh_rtt_high`, `ha_two_sites_no_tiebreaker`, each with the severity of Global Constraints. The input `HAIn{Snapshot, FrontdoorStatus, Published, LastBackup, Lease}`. The existing `kube_api_public` is checked for **every** node's public address from the snapshot (spec §17), with `TestKubeAPIPublicPerNode` (one exposed node of three → the kind names that node).

- [ ] **Step 1:** Write the failing `TestHAKinds` (every kind registered once, severities exact) and one `TestHAKind_<kind>` per kind (the input that raises it, and the one that clears it; `node_down` only after > 1 min NotReady; `volume_degraded` only after > 10 min; `backup_stale` after 26 h).
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement. The kinds register only when `kubeOn()`.
- [ ] **Step 4:** Run them. Expected: PASS. Check the contract §14.5 copy (`TestDocsCopiesInSync`).
- [ ] **Step 5:** Commit (`hub: HA doctor kinds`).

---

## Stream C — Core

### Task 17: `init --runtime kubernetes` installs k3s on `pcmesh` (core, D8, R3)

**Files:**
- Create: `scripts/lib/kube_install.sh`.
- Modify: `scripts/lib/stack.sh` (`cmd_init` 720–746), `scripts/lib/runtime.sh` (source it), `scripts/lib/kube.sh` (`kube_detect_cidrs`: multi-node, cluster CIDR from the k3s `--cluster-cidr` node arg or `10.42.0.0/16`; `kube_runtime_check` reads `portcullis-cluster-addresses` once it exists).
- Modify: `tests/test_shell_libs.sh`, `tests/test_cli.sh` (`test_docker_init_unchanged` + fixture `tests/fixtures/docker-init-transcript.txt`, `tests/fixtures/docker-env-keys.txt`).
- Modify: `.github/ci/e2e-k3s-install.sh` (uses `kube_install_k3s` instead of its own line).

**Interfaces:**
- Consumes: the Task 3 pins.
- Produces:
  - `kube_install_k3s` installs the pinned script and binary (sha256 checked) with:
    - `--cluster-init`;
    - `--secrets-encryption`;
    - `--disable=traefik`;
    - `--kubelet-arg=pod-max-pids=1024`;
    - `--kubelet-arg=sync-frequency=10s` (D2);
    - `--flannel-backend=wireguard-native`;
    - `--node-ip=10.215.0.1`;
    - `--advertise-address=10.215.0.1`;
    - `--node-label` for class/site/ingress/storage plus `svccontroller.k3s.cattle.io/enablelb=true`;
    - `--etcd-arg=listen-client-urls=https://10.215.0.1:2379,https://127.0.0.1:2379`;
    - `--etcd-arg=heartbeat-interval=200`, `--etcd-arg=election-timeout=2000`;
    - `--kubelet-arg=address=10.215.0.1`.
  - It runs only when no `PORTCULLIS_KUBE_CONTEXT` cluster answers.
  - `kube_install_mesh` writes `/etc/wireguard/pcmesh.conf` (private key generated on the host, mode 0600) and enables `wg-quick@pcmesh`.
  - `kube_host_checks` gains `open-iscsi`, `nfs-common`, the watchdog device and ZFS/btrfs detection (reported only). It runs before the install, followed by **one** confirmation that lists the packages to install.

- [ ] **Step 1: Write the failing shell tests** (`expect_eq` style, a fake `curl`/`sha256sum`/`systemctl` on PATH).
  - "kube_install_k3s: refuses a script whose sha256 differs" (rc=1, nothing executed).
  - "kube_install_k3s: flags exactly" (the recorded argv of the fake installer equals `tests/fixtures/k3s-server-flags.txt`, the list above, sorted; nodeadm's `TestJoinFlagsEqualInitFlags` reads the same fixture).
  - "kube_install_k3s: token never on argv" (grep the recorded argv and the log for the fixture token: none).
  - "kube_install_mesh: private key mode 0600 and never printed".
  - "kube_detect_cidrs: three nodes accepted, cluster CIDR 10.42.0.0/16".
  - "kube_host_checks: one confirmation lists open-iscsi nfs-common".
  - "init docker: transcript and .env keys unchanged" (`test_docker_init_unchanged`).
- [ ] **Step 2:** Run `bash tests/test_shell_libs.sh` and `bash tests/test_cli.sh`. Expected: FAIL on the new cases.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run them again, plus shellcheck. Expected: PASS. Then `gh workflow run ci.yml --ref ha -f jobs=unit-tests,e2e-k3s` (e2e-k3s now installs through `kube_install_k3s`).
- [ ] **Step 5:** Commit (`cli: init installs pinned k3s with embedded etcd on the pcmesh node mesh`).

### Task 18: PriorityClasses and the admission additions (core; Hub byte copies)

**Files:**
- Create: `charts/portcullis/templates/priorityclasses.yaml`, `kube/admission/nodeadm-tokens.yaml` (a VAP + binding for `nodeadm`'s ServiceAccount on `kube-system` Secrets).
- Modify: `kube/admission/policies.yaml` (pods: the four rules; `params.maxAppPriority` stays 1000 for routes — unrelated), `bindings.yaml`, `scripts/lib/kube.sh` (`KUBE_BINDINGS` + the new binding).
- Copy to Hub: `internal/runtime/kube/testdata/admission/*` (remove Task 2's `t.Skip`).
- Modify: `charts/portcullis/templates/_helpers.tpl` (`priorityClassName: portcullis-core` on every core pod).

**Interfaces:**
- Consumes: the Task 1 texts; the Task 2 vectors.
- Produces: the five PriorityClasses (Global Constraints values; `globalDefault: true` only on `portcullis-normal`). The pod rules use the exact texts. The token VAP refuses a bootstrap-token Secret unless `expiration` ≤ now + 15 min, `usage-bootstrap-authentication: "true"` is the only usage, and `auth-extra-groups` = `system:bootstrappers:k3s:default-node-token`.

- [ ] **Step 1:** Write the failing tests:
  - core `.github/ci/e2e-k3s-apps-admission.sh` runs the `ha`-tagged vectors;
  - core `tests/test_shell_libs.sh` "KUBE_BINDINGS lists portcullis-nodeadm-tokens";
  - Hub envtest `TestAdmissionVectors` with the `ha` cases unskipped;
  - Hub `TestNodeadmTokenPolicy`, which dry-runs as `nodeadm`'s SA: a 16 min TTL is refused "bootstrap tokens must expire within 15 minutes"; usage signing is refused; 10 min + authentication is admitted.
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement the CEL. Bound every list walk (`size(...) <= 32` guards as in the existing policies).
- [ ] **Step 4:** Run the Hub `-tags envtest`, `TestAdmissionCELCompiles` and core `unit-tests-kube-static.sh` (byte copies equal). Expected: PASS. Then `gh workflow run ci.yml --ref ha -f jobs=unit-tests,e2e-k3s`.
- [ ] **Step 5:** Commit both repos (`admission: priorities, small-node toleration, nodeName, placement keys, nodeadm token guard`).

### Task 19: The chart's HA mode and the published documents (core)

**Files:**
- Modify: `charts/portcullis/templates/_helpers.tpl` (`portcullis.deployment` gains `replicas`, `strategy`, `spread`, `pdb`, `tolerations`, `priorityClass`; a `portcullis.statefulset` helper), `values.yaml` (`ha.enabled`, `ha.replicas.*`), `keycloak.yaml`, `forward-auth*.yaml`, `group-gate.yaml`, `enroll.yaml`, `mcp-gate.yaml`, `hub.yaml`, `traefik.yaml` (DaemonSet when `ha.enabled`), `monitoring.yaml` (Alertmanager ×2 meshed, `--cluster.peer`), `services.yaml`, `netpol-networks.yaml` (Keycloak 7800/57800 between Keycloak pods; Alertmanager 9094; the D6 log ports from the Hub only).
- Create: `charts/portcullis/templates/published.yaml` (the eight empty objects, `helm.sh/resource-policy: keep`, plus the three Leases), `pdb.yaml`.
- Modify: `charts/portcullis/files/hub-role-core.yaml` (copy of the Hub's), `hub-rbac.yaml`.
- Modify: `tests/k8s_parity.py`, `tests/k8s_parity_deltas.yaml`, `tests/k8s_netpol_matrix.py`, `tests/k8s_hardening.py`, `tests/k8s-ci-values.yaml` (+ `tests/k8s-ci-values-ha.yaml`).

**Interfaces:**
- Consumes: `published_docs.json`, `role-core.yaml` (Hub Task 6).
- Produces:
  - values `ha.enabled` (bool, from `PORTCULLIS_HA`);
  - Keycloak replicas = 2, or 3 when `ha.nonSmallNodes >= 3`; gates 2; PDB `minAvailable: 1`;
  - readers mount a projected volume `hub-data` of their `published_docs.json` objects at the same paths;
  - no reader mounts the `hub-state` PVC;
  - HA pods get tolerations at 30 s;
  - Traefik DaemonSet `nodeSelector: portcullis.io/ingress: "true"`;
  - `wg-people` with `externalTrafficPolicy: Cluster` when `ha.enabled` (`Local` otherwise, as today); test row "ha: wg-people externalTrafficPolicy Cluster" in `k8s_parity.py`;
  - `hub-state` / `hub-secrets` / `hub-backups` / `domains-data` / `wg-data` on `portcullis-core-replicated` when `ha.enabled`, else `portcullis-core`.

- [ ] **Step 1: Write the failing tests:**
  - `k8s_parity.py` case "ha: every reader mounts its published documents through a projected volume, never subPath";
  - `k8s_hardening.py` "ha: no pod but hub mounts hub-state";
  - `k8s_netpol_matrix.py` rows: keycloak↔keycloak 7800 allow, group-gate:8091 only from hub, any app → keycloak 7800 deny;
  - `helm template` with `k8s-ci-values-ha.yaml`, asserting with a yq/jq script that the replica counts, PDBs and `priorityClassName` match the values above;
  - the shell test "chart ha: role-core.yaml byte-equal to the Hub's".
- [ ] **Step 2:** Run the core kube static gates. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the gates again. Expected: PASS. Then `-f jobs=unit-tests,e2e-k3s`: single node, `ha.enabled=false`, the published documents in use.
- [ ] **Step 5:** Commit (`chart: HA mode (replicas, PDBs, spread, priorities, Traefik DaemonSet) and published documents`).

### Task 20: Primary-site pinning and storage at `main` (core)

**Files:** Modify `charts/portcullis/templates/_helpers.tpl` (new `portcullis.sitePin`; the deployment and statefulset helpers include it when `pin: true`), `values.yaml` (`ha.primarySite: main`), every core template listed as pinned in Global Constraints, `postgres-cnpg.yaml` (`affinity.nodeSelector`), `kube/storage/storageclass-replicated.yaml` (Longhorn creates disks only where `node.longhorn.io/create-default-disk=true`), `tests/k8s_parity.py`, `tests/k8s_hardening.py`, `tests/k8s-ci-values-ha.yaml` (+ `tests/k8s-ci-values-ha-sites.yaml`).

**Interfaces:**
- Consumes: Task 19's helpers; §20.11.
- Produces:
  - `portcullis.sitePin` renders a required node affinity term `portcullis.io/site In [<ha.primarySite>]`, merged with the class term of R2 (never replacing it);
  - the pinned set exactly as in Global Constraints;
  - `frontdoor`, `nodeadm` and the Traefik DaemonSet carry no site term;
  - the values key `ha.primarySite` is fixed to `main` by `kube_render_values` (no CLI option).

- [ ] **Step 1: Write the failing tests:**
  - `k8s_parity.py` "sites: every pinned component requires portcullis.io/site In [main]";
  - "sites: frontdoor, nodeadm, traefik carry no site term";
  - "sites: CNPG instances pinned to main and NotIn small";
  - `k8s_hardening.py` "sites: no pod but the pinned set's may mount portcullis-core-replicated";
  - shell "kube_render_values: ha.primarySite is main".
- [ ] **Step 2:** Run the core kube static gates. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the gates again. Expected: PASS.
- [ ] **Step 5:** Commit (`chart: pin sign-in and data to the primary site; storage only at main`).

### Task 21: `nodeadm` (core, D4, D10)

**Files:**
- Create: `nodeadm/{go.mod,main.go,api.go,enrol.go,tokens.go,nodes.go,snapshot.go,addresses.go,params.go,metrics.go,join.sh,Dockerfile}` + `*_test.go`, `nodeadm/testdata/`.
- Create: `charts/portcullis/templates/nodeadm.yaml` (Deployment on `node-role.kubernetes.io/control-plane`, its ClusterRole and Role, NetworkPolicy, router `portcullis-node`).
- Modify: `enroll/nodes.go` (sign `node-cluster`, `node-frontdoor` for `nodeadm`'s own identity only), `scripts/lib/pki.sh` (`_pki_write_node_role` adds both), `.github/workflows/images.yml` (`portcullis-nodeadm`).
- Modify: `scripts/lib/kube.sh` (`kube_sync_secrets` puts the k3s server token into Secret `nodeadm-k3s-token`, from `/var/lib/rancher/k3s/server/token` via `--from-file`).

**Interfaces:**
- Consumes: `nodeadm_api_vectors.json`, `joincode_v2_vectors.json`, §20.2 and §20.9 (Tasks 1–2); the nodeagent binaries (Task 9).
- Produces:
  - the §20.2 API;
  - `Snapshot` exactly as the Hub's `nodeadm.Snapshot` (Task 8 type, same JSON);
  - ConfigMap `portcullis-cluster-addresses` (§20.9);
  - after each join or removal, a params generation rewrite: create `portcullis-admission-params-<gen>` → new bindings → admission probe → delete old (the CLI's algorithm ported, CLI and `nodeadm` share the generation function through vector `params_generation_vectors.json`, added here to `kube/admission/` and tested by both);
  - the R7 metrics;
  - the `/node/v1/join` answer `{role, server_url, token_file, flags:[…]}`, whose `flags` equal Task 17's list for a server (minus `--cluster-init`, plus `--server https://<server-mesh-ip>:6443`, and the node's own `--node-ip`/labels/taints) or the agent subset. It refuses with `CheckRTT`'s text when the request's RTT report fails (Task 11), and with the site-gateway text when the node's site has no reachable node;
  - the label `node.longhorn.io/create-default-disk=true` only on `main` storage nodes (Task 20).
- `nodeadm`'s **ClusterRole** is exactly:

  | Resources | Verbs |
  |---|---|
  | `nodes` | `get`, `list`, `watch`, `patch` (labels, taints, unschedulable) |
  | `pods` | `list`, `watch` |
  | `pods/eviction` | `create` |
  | CNPG/Longhorn/SNR status CRs | `get`, `list` |
  | `validatingadmissionpolicybindings` | `create`, `delete` (label `portcullis.io/admission`) |

  Its Roles are `secrets` `create` in `kube-system` (type bootstrap only, VAP Task 18), `get` on `nodeadm-k3s-token`, `configmaps` `create`/`delete` on `portcullis-admission-params-*` and `update` on `portcullis-cluster-addresses`, and `leases` `get`/`update` on `portcullis-nodeadm`. etcd member removal goes through the k3s server's etcd client using the node's etcd client certificate mounted read-only (hostPath `/var/lib/rancher/k3s/server/tls/etcd/` on server nodes, in its own namespace `portcullis-nodeadm`, PSA privileged). **This is a security delta for `hardening.md`**: `nodeadm` is privileged.

- [ ] **Step 1: Write the failing tests** (Go, envtest for the Kubernetes parts, fake etcd).

```go
func TestAPIVectors(t *testing.T)                  // every vector request → vector response
func TestEnrolNeedsProofThenCert(t *testing.T)     // join without prior enrol → 403; wrong HMAC → proof_invalid; replay of a used code → code_used; > 15 min → code_expired
func TestJoinFlagsEqualInitFlags(t *testing.T)     // server join flags == kube_install_k3s's list (shared fixture tests/fixtures/k3s-server-flags.txt) with the documented substitutions; etcd timing flags present
func TestJoinRefusesFarServer(t *testing.T)        // RTT report 101 ms for role server → 409 "too far for one cluster: 101 ms (servers need 100 ms or less)"; no token minted
func TestJoinMaterialOnlyOverMTLS(t *testing.T)    // /node/v1/join without the node-cluster client cert → 403; with → agent role gets a bootstrap token (TTL ≤ 15 min), server role gets the server token
func TestTokenNeverLogged(t *testing.T)            // logs/errors over the whole flow contain neither token
func TestDrainRefusesBelowMinimum(t *testing.T)    // removing a server with 3 servers → quorum_minimum; a PDB-blocked eviction → replica_minimum
func TestRevokeRotatesServerToken(t *testing.T)    // mode=revoke: node deleted, etcd member removed, cert revoked via enroll, token rotated (k3s token rotate fake)
func TestParamsRewriteAfterJoin(t *testing.T)      // new node addresses → new generation, bindings swapped create-before-delete, probe passes, old deleted; probe failure → new bindings removed, old kept, join op fails "admission params couldn't be proven"
func TestParamsGenerationVectors(t *testing.T)     // same as the CLI's (shared vectors)
func TestNotLeaderAnswers503(t *testing.T)         // without the Lease every write → 503 not_leader
func TestUnparseableAddressesNoRewrite(t *testing.T) // a node with no mesh address → no params change, doctor-visible error in snapshot
```

  Core shell: "params generation: vectors equal nodeadm's".
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement. `join.sh` checks its own sha256 against the code's `script_sha256` (passed in as an argument), downloads `nodeagent-<arch>`, checks it against `agent_sha256`, and runs `nodeagent join` with the code on stdin.
- [ ] **Step 4:** Run them, plus the nodeadm Go gate and the chart gates. Expected: PASS.
- [ ] **Step 5:** Commit (`nodeadm: cluster enrolment, bootstrap tokens, node operations, cluster snapshot, addresses and params`).

### Task 22: Gates and wg serve their logs; group-gate prunes its own (core, D6)

**Files:** Modify `group-gate/group-gate.py` (log port `:8091`, `GATE_OPENED_PRUNE_DAYS`), `tests/test_group_gate.py`, `mcp-gate/main.go` + `internal/…` (`:8092`), `wg/main.go` (`:8093` `GET /v1/status`), the chart's StatefulSets for group-gate and mcp-gate in HA (one local PVC each per replica).

**Interfaces:**
- Consumes: §20.10.
- Produces: the read-only endpoints. Each:
  - binds its own port;
  - refuses every method but GET;
  - answers ≤ 4 MiB JSONL with `from` / `limit`;
  - has no auth beyond the NetworkPolicy (Hub pod only, Task 19), as with every other internal port bound to how traffic arrived.

- [ ] **Step 1: Write the failing tests:**
  - `test_group_gate.py` `test_log_endpoint_get_only`, `test_log_endpoint_from_limit` and `test_prune_days` (entries older than N days removed at start and daily);
  - mcp-gate `TestAccessLogEndpoint`;
  - wg `TestStatusEndpoint`;
  - `k8s_netpol_matrix.py` rows (already in Task 19).
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run them. Expected: PASS.
- [ ] **Step 5:** Commit (`gates, wg: read-only log and status ports for the Hub (HA)`).

### Task 23: Postgres on CloudNativePG, LLDAP on Postgres (core, D8)

**Files:**
- Create: `kube/ha/cnpg/` (operator manifests at the Task 3 pin, plus the barman-cloud plugin), `charts/portcullis/templates/postgres-cnpg.yaml` (the `Cluster`, `ObjectStore` when a destination is set).
- Delete: `charts/portcullis/templates/postgres.yaml`.
- Modify: `keycloak.yaml` (`KC_DB_URL` → `portcullis-pg-rw`), `lldap.yaml` (`LLDAP_DATABASE_URL` from Secret `portcullis-pg-lldap`, no `lldap-data` PVC on Kubernetes), `scripts/lib/ha.sh` (`ha_install_cnpg`), `scripts/lib/backup.sh` + `kube.sh` (`_backup_pg_dump` against the CNPG primary via `portcullis-pg-rw`; restore = `pg_restore` into the new cluster), `charts/portcullis/images.yaml` (via `gen-images-yaml.py`), `tests/k8s_parity_deltas.yaml` ("postgres: CNPG on Kubernetes").

**Interfaces:**
- Produces:
  - `Cluster portcullis-pg`: `instances` = 1 (non-HA) or 2/3 (HA); synchronous settings per Global Constraints;
  - anti-affinity on hostname, `nodeAffinity` class NotIn [small];
  - storage class `portcullis-core`, `priorityClassName: portcullis-core`;
  - Services `portcullis-pg-rw` / `-ro`, Secrets `portcullis-pg-keycloak` / `-lldap`;
  - `ha_install_cnpg` (idempotent, pinned).

- [ ] **Step 1: Write the failing tests:**
  - shell "ha_install_cnpg: applies pinned manifests only (digest check), never helm --set with a secret";
  - `k8s_parity.py` "postgres: CNPG cluster, LLDAP DATABASE_URL from Secret";
  - e2e-k3s phase `restore` extended in `tests/e2e/e2e_k3s.py`: `test_restore_into_cnpg`, which restores a backup containing `pg_dump`, after which Keycloak signs in.
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the static gates, then `-f jobs=e2e-k3s`. Expected: PASS.
- [ ] **Step 5:** Commit (`chart: Postgres on CloudNativePG, LLDAP on Postgres (Kubernetes)`).

### Task 24: Longhorn, external-snapshotter, fencing (core)

**Files:**
- Create: `kube/ha/{longhorn,snapshotter,fencing}/` (pinned manifests), `kube/storage/storageclass-replicated.yaml`.
- Modify: `scripts/lib/ha.sh` (`ha_install_longhorn`, `ha_install_snapshotter`, `ha_install_fencing`), `kube/admission/` (these namespaces are judged like any identity; they carry no app-namespace rights), `tests/test_shell_libs.sh`, `tests/lint_images.sh` (scan `kube/ha/**`).

**Interfaces:**
- Produces:
  - StorageClass `portcullis-core-replicated`;
  - the Longhorn settings `node-down-pod-deletion-policy: do-nothing` (fencing decides, not Longhorn) and `replica-soft-anti-affinity: false`, with node tags from `portcullis.io/storage`;
  - SNR config `watchdogFilePath: /dev/watchdog`, `safeTimeToAssumeNodeRebootedSeconds` = 60 + margin 30;
  - NHC selector: every node; remediation = SNR with the `OutOfServiceTaint` strategy;
  - `ha_fencing_ready` (the jq over SNR status → per-node ready).

- [ ] **Step 1: Write the failing shell tests:**
  - "ha_install_longhorn: refuses without open-iscsi on every storage node";
  - "ha_install_fencing: refuses a node without /dev/watchdog: 'node <n> has no watchdog: fencing can't be confirmed'";
  - "ha manifests: every image pinned by digest";
  - "longhorn settings: node-down-pod-deletion-policy do-nothing".
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run them. Expected: PASS. (Live behaviour is checked in Task 33.)
- [ ] **Step 5:** Commit (`ha: Longhorn, snapshotter and medik8s fencing installs (pinned)`).

### Task 25: Valkey Sentinel and Vault raft ×3 (core)

**Files:** Modify `charts/portcullis/templates/sessions.yaml` (StatefulSet `sessions` ×2 + StatefulSet `sessions-sentinel` ×3 in HA), `forward-auth*.yaml` (sentinel flags in HA), `vault.yaml` (StatefulSet `vault` ×1/×3, headless `vault-internal`, Service `vault-active` by the `vault-active=true` label), `vault/vault.hcl` → `vault/vault.hcl.tmpl` (`node_id` = the pod name, `retry_join` for each peer), `vault/entrypoint.sh`, `scripts/lib/kube.sh` (`_backup_vault_snapshot` via `vault-active`), `tests/k8s_parity*.{py,yaml}`.

**Interfaces:**
- Produces:
  - Sentinel master name `portcullis-sessions`, quorum 2;
  - oauth2-proxy `--redis-use-sentinel=true --redis-sentinel-master-name=portcullis-sessions --redis-sentinel-connection-urls=redis://sessions-sentinel-0.sessions-sentinel:26379,…`, password from the existing Secret through env (never argv: the env var `OAUTH2_PROXY_REDIS_SENTINEL_PASSWORD` from `secretKeyRef`);
  - Vault voters spread `DoNotSchedule`, and the third voter tolerates `small`.

- [ ] **Step 1: Write the failing tests:**
  - `k8s_parity.py` "ha: sentinel quorum 2, three sentinels, tolerate small";
  - "ha: vault 3 voters, retry_join lists the other two";
  - "non-ha: vault 1 voter, node_id vault-0";
  - shell "backup: vault snapshot taken through vault-active".
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the gates again. Expected: PASS. Then e2e-k3s (single node, `vault-0`).
- [ ] **Step 5:** Commit (`chart: Valkey Sentinel and Vault raft voters (HA)`).

### Task 26: The backup destination, CNPG archives, and the LLDAP conversion on restore (core, D8, R5)

**Files:** Modify `scripts/lib/backup.sh` (`cmd_backup destination set|show|test`; restic repository = the destination when set; Longhorn backup target = the destination), `scripts/lib/kube.sh` (sync `secrets/backup-destination.env` → Secret `backup-destination`), `charts/portcullis/templates/postgres-cnpg.yaml` (`ObjectStore` + plugin), and the restore path (`_backup_restore_kube`: an archive with `lldap_data` → `lldap_convert_sqlite_to_pg`). Create `scripts/lib/lldap_convert.sh` and `tests/fixtures/lldap/users.db` (3 users, 2 groups, generated by LLDAP itself in the test).

**Interfaces:**
- Produces:
  - `backup destination set` reads the URL as an argument and the credentials **from stdin only** (`AWS_ACCESS_KEY_ID=…` lines), writes `secrets/backup-destination.env` 0600 and syncs it;
  - `test` writes and deletes one object;
  - `lldap_convert_sqlite_to_pg <db> <pg-url-file>` (Task 4's steps): it compares user count, the uuid set, group memberships and password-hash count before switching, and refuses on any difference with "LLDAP conversion changed <what>: nothing was switched".

- [ ] **Step 1: Write the failing tests:**
  - shell "backup destination set: credentials never on argv (stdin only)";
  - "backup destination show: no secret in output";
  - e2e-k3s `test_lldap_convert_keeps_uuids` (restore a Docker archive: the uuids and hashes equal the source, Keycloak sign-in works for the fixture user);
  - `test_lldap_convert_refuses_on_diff` (a fault injected into one row → refused, the old Deployment untouched).
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run them. Expected: PASS.
- [ ] **Step 5:** Commit (`backup: offsite destination, CNPG WAL/base backups, LLDAP SQLite→Postgres on restore`).

### Task 27: The front-door role — DNS failover (core `domains/`)

**Files:** Create `domains/frontdoor/{engine.go,health.go,writer.go,status.go,engine_test.go}`, `charts/portcullis/templates/frontdoor.yaml` (Deployment, Secret `frontdoor-env` mount, Role, NetworkPolicy: egress to the DNS provider API and nodeagents' `:7443` only). Modify `domains/main.go` (`domains frontdoor` subcommand).

**Interfaces:**
- Consumes:
  - `frontdoor_vectors.json`;
  - the existing providers (`provider_porkbun.go`, `provider_byid.go`, libdns) and their by-id deletes;
  - nodeagent `/v1/probes` (client cert `frontdoor.control`, Task 21);
  - the node and Traefik readiness from `nodeadm`'s snapshot (`GET /v1/cluster`; `frontdoor.control` gets read-only access to that one route, added to §20.2 by Task 1).
- Produces:
  - `frontdoor.Engine.Step(now time.Time, in Inputs) []Change` (pure, vector-tested);
  - `Writer.Apply(ctx, Change) error` (append, then delete the exact stale value by id);
  - the `frontdoor-status` ConfigMap;
  - metrics `portcullis_frontdoor_addresses{name}` and `portcullis_frontdoor_unhealthy_published_seconds{name,address}`.
  - The cross-site cases of `frontdoor_vectors.json` are skipped here (`t.Skip("cross-site rules land in Task 28")`) and run from Task 28.

- [ ] **Step 1: Write the failing tests.**

```go
func TestFrontdoorVectors(t *testing.T)               // Engine.Step over every vector → want.changes
func TestFrontDoorNeverRemovesLast(t *testing.T)      // all nodes failing → no Change
func TestFrontDoorPartialWriteNeverEmpty(t *testing.T) // append ok, delete fails → set has old+new; retry after 60 s; never a state with 0 addresses (fake provider asserts on every call)
func TestFrontDoorMinorityNoWrites(t *testing.T)      // without the Lease → Step runs, Apply never called
func TestFrontDoorOnlyMainRecords(t *testing.T)       // a Change for any name outside <d>, *.<d>, _acme-challenge.<d>, caa → refused before the provider call
func TestFrontDoorCredentialsNeverLogged(t *testing.T)
```

- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement. The engine is the vector table's semantics; nothing beyond it.
- [ ] **Step 4:** Run them (`go test -race ./...` and `-tags testprovider`). Expected: PASS.
- [ ] **Step 5:** Commit (`domains: front-door role — DNS failover with hysteresis and fail-static`).

### Task 28: The front door across sites (core `domains/`)

**Files:** Create `domains/frontdoor/sites.go`, `domains/frontdoor/sites_test.go`. Modify `domains/frontdoor/{engine.go,health.go,status.go}`, `charts/portcullis/templates/frontdoor.yaml` (no site term, Task 20; `topologySpreadConstraints` none; tolerates nothing small), `domains/testdata/frontdoor_vectors.json` (the cross-site cases already written in Task 2 now run, no longer skipped).

**Interfaces:**
- Consumes:
  - Task 27's `Engine`;
  - the per-node site from `nodeadm`'s snapshot;
  - the nodeagent probes, now including each prober's own site and its "reached any target" bit;
  - R10, R11 and D12.
- Produces:
  - `frontdoor.Eligible(prober, target Site, hairpin bool) bool`;
  - `frontdoor.Blind(round ProbeRound) bool`;
  - `frontdoor.Unhealthy(target string, rounds []ProbeRound, sites SiteSet) bool`;
  - `frontdoor-status.sites` (§20.8);
  - metrics `portcullis_frontdoor_site_healthy{site}` and `portcullis_frontdoor_blind_probers{site}`.

  The HA page's worst-case text per name now names the site ("if site <s> fails: worst case ~<n> min on <provider>").

- [ ] **Step 1: Write the failing tests.**

```go
func TestBlindProberDiscarded(t *testing.T)               // prober at edge fails every target at every site → its results ignored for that round; main's addresses unchanged
func TestOneSiteUplinkDownNoRemovalElsewhere(t *testing.T) // edge's uplink down: edge's probers blind, main's probers fail edge's addresses → only edge's addresses removed after 3 rounds; main's never
func TestTwoSiteSpanRequired(t *testing.T)                // 3 sites with probers; failures for target t only from one site → no removal
func TestOnlyOneSiteCanProbe(t *testing.T)                // 2 sites, no hairpin at main: edge's non-blind probers alone decide main's addresses
func TestWholeSiteDownOneNamePer60s(t *testing.T)         // site edge NotReady + Traefik not Ready → its addresses removed, one change per name per 60 s, last address overall kept
func TestFrontdoorCrossSiteVectors(t *testing.T)          // the cross-site cases of frontdoor_vectors.json
func TestCutOffSiteFrontdoorStops(t *testing.T)           // Lease renew fails → Apply never called after RenewDeadline; status shows "standing by"
```

- [ ] **Step 2:** Run `go test ./frontdoor/ -run 'Blind|Uplink|Span|OnlyOneSite|WholeSite|CrossSite|CutOff'` in `domains/`. Expected: FAIL.
- [ ] **Step 3:** Implement R10/R11 as pure functions that Task 27's `Engine.Step` calls. Don't touch its single-site rules: the single-site vectors still pass.
- [ ] **Step 4:** Run all of `domains`' tests (`-race`, `-tags testprovider`). Expected: PASS.
- [ ] **Step 5:** Commit (`domains: front door across sites (blind probers, two-site span, whole-site removal)`).

### Task 29: The front-door role — HA certificates and the CAA flip (core)

**Files:** Modify `domains/frontdoor/` (+ `cert.go`), `domains/traefik.go` (`servable()`: with `PORTCULLIS_HA=on`, the main domain + `*.<main>` from the front door's store are servable), `domains/acme.go` (a second account, store key `frontdoor`), `charts/portcullis/templates/traefik.yaml` (no resolver, no `traefik-acme` in HA), `scripts/lib/dns.sh` (`dns_flip_main_account <uri>`: relax → settle → issue → re-pin, reusing `_dns_relax_file` / `settlePoint`), `scripts/lib/config.sh` (`ACME_STAGING` flips in HA go through it).

**Interfaces:**
- Produces:
  - `frontdoor.IssueMain(ctx) error` (DNS-01 through its own credentials);
  - `servableHA(cert, main string) bool`;
  - `dns_flip_main_account` (shell);
  - `domains frontdoor account-uri` prints the front-door account URI.

- [ ] **Step 1: Write the failing tests:**
  - Go `TestServableHAIncludesMain` / `TestServableNonHAUnchanged`;
  - `TestFrontdoorAccountSeparate` (its account URI ≠ the added-domains account);
  - shell "dns_flip_main_account: order relax, settle, issue, re-pin" (fake `domains`, recorded calls);
  - "dns_flip_main_account: settle not reached → stops before issue";
  - Pebble test `TestIssueMainPebble` (`-tags testprovider`).
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run them. Expected: PASS.
- [ ] **Step 5:** Commit (`domains: main-domain certificates from the front door in HA; CAA account flip`).

### Task 30: `./portcullis node …` (core)

**Files:** Create `scripts/lib/node.sh`. Modify `portcullis` (dispatcher whitelist, `help_main`), `tests/test_cli.sh`, `tests/test_shell_libs.sh`. Hub: `cmd/hub` gains `hub servers add-cluster-node` (reads its JSON request on stdin, prints the code to stdout only; audited `server.add` with actor `cli`).

**Interfaces:**
- Consumes: `Hub.AddClusterNode` (Task 8).
- Produces:
  - `node add <id> [--role] [--class] [--site]`: `kubectl exec -i` into the Hub pod; prints the one-liner;
  - `node list`;
  - `node remove <id>` / `node revoke <id>`, which ask for the typed id.

- [ ] **Step 1: Write the failing tests:**
  - "node add: request on stdin, nothing on argv but the subcommand";
  - "node remove: typed id mismatch → refused";
  - "help lists node and ha";
  - every new command's `--help` runs (CI rule);
  - Hub `TestCLIAddClusterNodeStdinOnly`.
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run them. Expected: PASS.
- [ ] **Step 5:** Commit core + Hub (`cli: node add|list|remove|revoke`).

### Task 31: `./portcullis ha status|enable` (core, D5)

**Files:** Modify `scripts/lib/ha.sh` (`cmd_ha`, `ha_enable_step_<n>`, state file `secrets/kube/ha-enable.json`), `scripts/lib/kube.sh` (render `ha.enabled` from `PORTCULLIS_HA`), `tests/test_shell_libs.sh`, `tests/test_cli.sh`.

**Interfaces:**
- Consumes: Tasks 19–29; `GET /api/ha` checklist via `kubectl exec hub -- hub ha checklist`.
- Produces: the resumable steps, each recorded in `ha-enable.json` after success (commit only after success):
  1. checklist (all green or refuse, naming each red item);
  2. one confirmation, naming the sign-in downtime, "experimental" and the CAA wait;
  3. `ha_install_snapshotter`, `ha_install_longhorn`, `ha_install_fencing`, `ha_fencing_ready` (all nodes ready or stop);
  4. scale the Hub to 0 → copy `hub-data` → `hub-state` (Longhorn), and `hub-secrets`, `domains-data`, `wg-data` the same way (helper pods, checksums equal) → instance backups to `hub-backups`;
  5. CNPG `instances` 2 or 3, wait for sync;
  6. Vault StatefulSet 3, wait for raft peers = 3;
  7. Sentinel + replica;
  8. `PORTCULLIS_HA=on` + `helm upgrade` (gates ×2, Keycloak ×2/3, Traefik DaemonSet, the front door);
  9. `dns_flip_main_account` (front door), then delete `traefik-acme`;
  10. `ha status` all green.

  `ha status` prints the checklist, quorum, nodes and guarantee.

- [ ] **Step 1: Write the failing shell tests:**
  - "ha enable: a red checklist changes nothing" (no kubectl write recorded);
  - `test_ha_enable_resumes_each_step` (a fault injected after step n → a re-run starts at n+1, steps 1..n not repeated);
  - `test_ha_enable_never_two_writers` (step 4: the Hub replicas are 0 before the copy and stay 0 until the copy checksums match; a fault in the copy → the old PVC is still bound to the scaled-0 Hub, never two PVCs attached);
  - "ha enable: Stop (SIGINT) between steps leaves a resumable record";
  - "ha enable: refuses on docker: 'high availability needs Kubernetes'";
  - carried from Task 30 (review M6): Task 30's "help lists node and ha" tests `node` only (a help line for a missing `ha` would fail the every-`--help` rule): add `ha` to that test here, with `ha`'s help line in `help_main`.
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run them. Expected: PASS.
- [ ] **Step 5:** Commit (`cli: ha status and ha enable (resumable conversion)`).

### Task 32: Monitoring — alerts and the cluster dashboard (core, R7)

**Files:** Modify `monitoring/prometheus/prometheus.yml` (the `nodeadm` and `frontdoor` jobs), `alerts.yml`, `tests/alerts_test.yml`, `charts/portcullis/templates/monitoring.yaml`. Create `monitoring/grafana/dashboards/cluster.json`. Modify `alertmanager` config (`watchdog_url` opt-in, empty by default).

**Interfaces:** the alert names of Global Constraints, over the R7 gauges and the front-door metrics. Plus `portcullis_mesh_rtt_ms{from,to}` (nodeadm, from the nodeagents' RTT) for the dashboard; there is no new alert for sites, the doctor kinds of Task 16 cover them.
- `PortcullisNodeDown`: `portcullis_node_ready == 0` for 1m.
- `PortcullisQuorumAtRisk`: `portcullis_quorum_voters{state="up"} == floor(total/2)+1`.
- `PortcullisQuorumLost`: below the majority, or `up{job="nodeadm"} == 0` for 2m.
- `PortcullisVolumeDegraded`: for 10m.
- `PortcullisDNSFailoverStuck`: `portcullis_frontdoor_unhealthy_published_seconds > 300`.
- `PortcullisBackupStale`: 26h.

- [ ] **Step 1:** Write the failing promtool unit tests in `tests/alerts_test.yml`, one per alert: the firing series and the not-yet-firing boundary (59 s, 9 m 59 s, 4 m 59 s, 25 h 59 m).
- [ ] **Step 2:** Run `promtool test rules tests/alerts_test.yml`. Expected: FAIL.
- [ ] **Step 3:** Implement. The dashboard covers nodes, quorum, failovers, volume health, replication lag, and a **Sites** row (healthy per site, blind probers, mesh RTT).
- [ ] **Step 4:** Run promtool again, plus `lint_images.sh`. Expected: PASS.
- [ ] **Step 5:** Commit (`monitoring: HA alerts and cluster dashboard`).

### Task 33: CI — `e2e-ha-k3d` and `e2e-ha-vm` (core, D9)

**Files:** Modify `.github/workflows/ci.yml` (two jobs; `e2e-ha-k3d` on `ubuntu-26.04`; `e2e-ha-vm` only with `-f runner=builder`, `workflow_dispatch` only). Create `.github/ci/e2e-ha-k3d-{install,phases,chaos}.sh`, `.github/ci/e2e-ha-k3d-local.sh`, `.github/ci/e2e-ha-vm-{setup,chaos,collect}.sh` and `tests/e2e/e2e_ha.py` (scenarios with `scenarios.skip`).

**Interfaces:** the scenario names.
- `e2e-ha-k3d` (k3d pinned, 3 servers + 1 agent labelled `small`, local-path for apps, no Longhorn):
  - `ha_cnpg_failover`: delete the primary pod, then its node container; writes resume within 60 s and no committed row is lost;
  - `ha_signin_continuity`: a Playwright sign-in loop during a Keycloak and a gate replica kill; at most **5** failed requests out of 300;
  - `ha_sentinel_promotion`;
  - `ha_vault_leader_loss`;
  - `ha_hub_lease_handover`: a second Hub pod never writes; the handover is within LeaseDuration + start;
  - `ha_dns_failover`: `testprovider` + Pebble; a dead ingress node's address is removed after ~30 s and the last one is never removed;
  - `ha_n_minus_1`: the N−1 page agrees with the scheduler: cordon + drain the node, every pod marked placeable starts;
  - `ha_published_docs`: a group removal reaches group-gate within 20 s with `sync-frequency=10s`;
  - `ha_dns_failover_sites`: k3d nodes labelled across 3 sites (`main` ×2 + agent, `edge` ×1, `tb` ×1 server `small`), with `portcullis-nodeagent serve --probes-only` as a test-only DaemonSet (`tests/e2e/ha/nodeagent-probes.yaml`).
    - `iptables` drops on a site's node containers simulate an uplink loss: only that site's addresses go, and the others stay.
    - A blind site changes nothing.
    - Stopping the `tb` server keeps quorum.
    - Stopping `edge` + `tb` loses quorum, and nothing is changed.
- `e2e-ha-vm` (the D9 VMs, reused, reset by `k3s-uninstall.sh` + wipe of the test disks, **never the builder host**):
  - `ha_vm_partition`: the minority self-fences within `T_fence`; a writer on it fails; a test app's data checksums equal the majority's afterwards;
  - `ha_vm_power_off`: the stateful app runs elsewhere within 4 min;
  - `ha_vm_disk_kill`, `ha_vm_disk_full`;
  - `ha_vm_lose_small`;
  - `ha_vm_rolling_upgrade`: a rolling upgrade under the sign-in loop;
  - `ha_vm_site_uplink_down`: drop `vm4`'s public ingress (443 inbound) while its mesh stays up. Its address leaves the set after about 30 s, and `main` keeps serving. Then drop `main`'s ingress nodes' 443: their addresses go and `vm4` serves sign-in through Traefik → `main` over `pcmesh`;
  - `ha_vm_site_down`: power `vm4` off. Quorum holds (servers at `main`), and `edge`'s address is removed but never the last one;
  - `ha_vm_nat_relay`: block inbound UDP 51830 on `vm2`. `vm2` ↔ `vm4` traffic keeps working through `vm1`, and sign-in is unaffected.
  - `ha_vm_revoke_restarts` (the agent-token fix, 2026-11-22; replaces the bare "agent-token rotation" VM proof): three servers + one agent. Revoke the agent, then a server (two rotations). After each revoke:
    - restart every surviving k3s server one at a time, then all together, then reboot one host: each comes back (no `cred/passwd newer than datastore`, no `encrypted with different token`) and the cluster is healthy (every Node Ready, etcd 3/3 or 2/2 healthy, core pods Running);
    - on every server `/var/lib/rancher/k3s/server/cred/passwd` is byte-equal across servers, has `node` = `server`, and no server's unit or config names `--agent-token-file`;
    - the old server token and the node credential derived from it answer 401 on `/v1-k3s/server-bootstrap` / `/v1-k3s/client-kube-proxy.crt` (credentials in a 0600 curl config, never argv), the new ones 200;
    - the revoked agent can't come back with what it holds: `systemctl restart k3s-agent` there stays out (no Node re-registered, no `<id>.node-password.k3s` Secret re-created), and its bootstrap token, Node and node-password Secret are gone;
    - a surviving agent restarts on its node identity (its bootstrap token long expired) and a new node joins with a fresh code.

- [ ] **Step 1:** Write `tests/e2e/e2e_ha.py` with every scenario, plus the `tests/test_e2e_scenarios.py` cases (each scenario starts with its `skip` gate).
- [ ] **Step 2:** Run `python3 tests/test_e2e_scenarios.py`. Expected: FAIL until the jobs exist and are listed.
- [ ] **Step 3:** Implement the scripts. Each CI step over 20 lines goes in `.github/ci/`. Check `lint_ci_size.sh`.
- [ ] **Step 4:** Run `.github/ci/e2e-ha-k3d-local.sh` on the builder, then `gh workflow run ci.yml --ref ha -f jobs=e2e-ha-k3d`, then `-f jobs=e2e-ha-vm -f runner=builder`. Expected: green, every scenario passing. Start a background watcher on each run.
- [ ] **Step 5:** Commit (`ci: e2e-ha-k3d and e2e-ha-vm`).

---

## Stream T — Templates

### Task 34: Reserved core names (templates)

**Files:** Modify `tests/core_names.txt` (`nodeadm`, `frontdoor`, `sessions-sentinel`, `portcullis-pg`, `portcullis-pg-rw`, `portcullis-pg-ro`, `vault-internal`, `vault-active`), `tests/validate.py` (reserved-name check reads the file), `tests/test_validate.py` (`TestCoreNamesComplete` against core's same-named branch).

- [ ] **Step 1:** Write the failing `test_reserved_ha_names` (a service named `nodeadm` → "service name nodeadm is reserved by core").
- [ ] **Step 2:** Run `python3 tests/test_validate.py`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `python3 tests/validate.py && python3 tests/test_validate.py`. Expected: PASS. Then run `lint.yml` on `ha`.
- [ ] **Step 5:** Commit (`validate: core names reserved by HA`).

---

## Stream D — Docs pages

### Task 35: Docs pages (docs)

**Files:**
- Create: `docs/operations/high-availability.md`, covering:
  - the model;
  - EXPERIMENTAL;
  - requirements (3 nodes, watchdog, open-iscsi, the backup destination);
  - adding nodes (the one-liner, server vs agent, the cluster-admin warning);
  - `ha enable`;
  - the HA page;
  - what each failure does (spec §5 table);
  - DNS failover and the worst case per provider;
  - the VPN reconnect caveat;
  - limits (one site, no 2-node HA, no `ha disable`, phases 2–4).
- Modify:
  - `kubernetes.md` (k3s installed by `init`, `pcmesh`, multi-node);
  - in `high-availability.md`, a **Sites** section:
    - what the cross-site slice does and doesn't do (the front door survives one site's ingress failure; sign-in and data stay at `main`);
    - a reachable node per site (one forwarded UDP port);
    - the RTT limits;
    - the 2-site rule and the tie-breaker;
    - storage only at `main`;
    - the worst case per provider;
    - the blind-prober rule in plain words;
  - `servers.md` (cluster nodes);
  - `hardening.md` (`nodeadm` privileged; the Hub's core Role; front-door credentials; the mesh-only listeners; the new namespaces);
  - `backups.md` (the destination, CNPG archives, the LLDAP conversion on restore);
  - `monitoring.md` (alerts, dashboard, dead-man's switch);
  - `cli.md` (`ha`, `node`, `backup destination`, restating real `--help`);
  - `hub.md` (HA page, Availability, doctor kinds);
  - `testing.md` (`e2e-ha-k3d`, `e2e-ha-vm`, envtest additions);
  - `architecture.md`;
  - `includes/abbreviations.md` (CNPG, SNR, NHC, PDB, N−1);
  - `.nav.yml`.

- [ ] **Step 1:** Write the pages, checking each statement against the code on `ha` (CLAUDE.md rule).
- [ ] **Step 2:** Run the docs gates. Expected: PASS.
- [ ] **Step 3:** Resync the Hub copies (`web/docs/sync.sh`), then run `go test ./web/`. Expected: PASS.
- [ ] **Step 4:** Commit docs + Hub (`docs: high availability`).

---

## Final

### Task 36: Full CI, reviews, merges, the test cluster, cleanup (all repos)

- [ ] **Step 1:** Run full CI on `ha` in every repo:
  - core: `ci.yml`, all jobs, plus `e2e-ha-vm` on the builder;
  - Hub: `build.yml`;
  - templates: `lint.yml` + `test-apps.yml`;
  - docs: the build.

  Start a background watcher on each run.
- [ ] **Step 2:** Run the whole-branch review on the most capable model, per repo. Fix findings in their owning task's style (test first).
- [ ] **Step 3:** Merge in the order docs → Hub (wait for `edge` and the `portcullis-nodeagent` artifacts) → templates → core, through detached worktrees (Global Constraints). Then core `images.yml` publishes `portcullis-nodeadm`.
- [ ] **Step 4: The test cluster** (the D9 VMs, `ACME_STAGING=true`).
  - Run `init --runtime kubernetes` on VM1, then `config apply` + `up`.
  - Restore a backup of the Docker test server (the LLDAP conversion runs, and Keycloak sign-in works for real accounts).
  - Add `vm2`/`vm3` (servers at `main`, `vm3` class `small`) and `vm4` (agent, ingress, site `edge`, another region) from the Hub, then run `ha enable`.
  - Do one live failover per component: a node power-off, the CNPG primary, the Valkey primary, the Vault leader, the Hub node, an ingress node (DNS), `edge`'s ingress (DNS across sites), `main`'s ingress while `edge` serves, the NAT relay.
  - Record each outcome in the ledger.
- [ ] **Step 5:** Write the user's laptop check as steps (sign in during a power-off; the HA page; a node add) for the user to run.
- [ ] **Step 6: Cleanup** (memory: branches mainlined).
  - Delete every `ha` branch (local and remote) in the four repos, every `wt-ha/*` worktree, `/tmp/merge-*`, `/tmp/pk-ha-*` and `/tmp/ha-read`.
  - Delete the four D9 VMs (user ruling: deleted at the end).
  - Update memory: a `ha_phase1` note with the rulings, gotchas and parked items.

---

## Out of scope (later plans)

- **Phase 2:**
  - the resource-usage page's "request vs used" column and the doctor's request suggestions (§10.2);
  - the manifest `ha:` / `volumes:` / `resources:` blocks (schema, `validate.py`, shared vectors);
  - the setup form and the full Availability tab (mode, replicas, tiers, snapshot schedule);
  - `replicated` / `independent` modes and conditional `replicas > 1`;
  - tier changes;
  - the shared NFS tier;
  - the nodeagent's NFS, ZFS and fixer jobs;
  - ZFS LocalPV;
  - snapshots (undo, schedules, quiesce);
  - instance backups to the destination;
  - the numeric-user follow-up for ~46 templates (the prerequisite of app HA).
- **Phase 3:** migration paths 1 and 3 as guided operations, Docker assisted recovery (Recovery card, superseded/diverged guard, agent snapshots, ZFS replication), `ha recover`.
- **The rest of phase 4:** the CNPG replica cluster, Longhorn DR volumes, the sync heartbeat and site promotion (user ruling Q2), the NFS second copy, Hub state in Postgres + hot standby, mail on Kubernetes, storage nodes outside `main`, and changing the primary site.

## Amendment 1 (2026-11-19): spike 1 results, rulings and pins

Spike 1 (Task 3) ran on the four test VMs (amd64 only: no arm64 cloud VMs, so every arm64 step is "not verified on hardware: arm64"; arm64 builds + a qemu smoke stay). These rulings amend Global Constraints and bind every later task:

- **S5 Ingress (replaces ServiceLB for Traefik).** k3s ServiceLB (klipper-lb) masquerades, so the client IP is lost even with `externalTrafficPolicy: Local`. Traefik runs as a DaemonSet on `portcullis.io/ingress` nodes with `hostNetwork: true`, binding 80/443 on the node; no LoadBalancer Service for Traefik. It runs as uid 0 with `capabilities: drop ALL, add NET_BIND_SERVICE`, `allowPrivilegeEscalation: false`, read-only root. Because PodSecurity `baseline` refuses hostNetwork, Traefik moves to its own namespace `portcullis-ingress` (PSA `privileged`, default-deny plus its flows), and a ValidatingAdmissionPolicy admits in that namespace only the Traefik DaemonSet's pod shape (its image digest, its single capability, no other hostPath/hostPID/privileged). The core namespace stays `restricted`. `hardening.md` states the delta. The `svccontroller.k3s.cattle.io/enablelb` label is set only for `wg-people`.
- **wg-people** stays a UDP LoadBalancer through ServiceLB, `externalTrafficPolicy: Cluster` (verified: handshake through another node).
- **S6 Probes.** Same-site probes never count (in-cluster networking answers a node's own public address). Only probers at another site are the outside vantage. A single-site cluster is always internal-only (`frontdoor_probes_internal_only`). Verified: cross-site probes take the real public path; a blind prober fails every target including its own address (R10 holds).
- **S3 Fencing.** SNR v0.13.0 refuses a safe time below 90 s (API check 10 s, timeout 5 s, 2 errors). Its watchdog timeout reads 0 (upstream bug), so `safeTimeToAssumeNodeRebootedSeconds` is set to **150** (90 + 60 s margin) and `T_fence` = 150 s. Power-off stateful failover measured 3.6 min at 90 s. The target becomes **≤ 5 min**. The SNR DaemonSet tolerates `portcullis.io/small`.
- **S8 etcd.** Leader election across sites measured 2–3 s (worst case ~4 s from etcd's randomised timeout). The target is ≤ 5 s.
- **S2 Longhorn** needs no separate disk (ext4 root, an ext4 loop file and btrfs all work). A ZFS dataset doesn't work; a zvol or a separate disk does. A ZFS dataset as the Longhorn path is refused by the node checks and doctor. Nodes need `open-iscsi` (iscsid running), the `iscsi_tcp` module, `nfs-common` and a multipathd blacklist for Longhorn devices; nodeagent's host checks report each.
- **Mesh gateway rules.** k3s's network-policy chain sits first in FORWARD and accepts pod traffic, so the gateway rule set is: accept `-i pcmesh -o pcmesh`, then drop anything else arriving on `pcmesh` for forwarding. Relay verified (MTU 1420 on pcmesh, pods 1340, 206–447 Mbit/s across sites).
- **flannel on 51840.** No k3s flag exists. Every node gets a `--flannel-conf` file (used verbatim, so it carries the cluster network too) with `"Backend": {"Type": "wireguard", "ListenPort": 51840, …}`.
- **Token rotation without argv.** `k3s token rotate` takes the new token on argv only. nodeagent calls the same k3s supervisor rotation API itself, reading both tokens from 0600 files, then updates each node's token file and restarts the nodes one at a time (verified: old 401, new 200). Pinned to the k3s version below; an e2e step covers it.
- **barman-cloud needs cert-manager.** Task 4 rules on it.

**Pins** (from the spike):


| Component | Version | Artifact | sha256 / digest |
|---|---|---|---|
| k3s | v1.37.2+k3s1 (stable channel) | `k3s` (amd64) | `265b3ee6a3198ef14033c63ef46cbb32370d83795199fb6d1b01f21575eddbda` |
| k3s | v1.37.2+k3s1 | `k3s-arm64` | `a779ccf1e5e2e33a62f5a29c2f1c0bbf99431e100579d4c10f0aa0742a6aa84b` |
| k3s | v1.37.2+k3s1 | `k3s-airgap-images-amd64.tar.zst` | `35a5af1e69b57b8b627a4f6b1c29ea104209b661067b8c97fd40dc3f860bfcd2` |
| k3s (k3d node image) | v1.37.2-k3s1 | `docker.io/rancher/k3s:v1.37.2-k3s1` | `sha256:21ea6e0fac4e3930c2ce8aa40ddd41a8b18cb3e9a0222c030dc005e7e88c4332` |
| Longhorn | v1.13.0 | chart `longhorn-1.13.0.tgz` (longhorn/charts release) | `e57f010d2a8bcf0da5b8b03ffecf49c5bc35ddc2663588ce8f22b7567b6133ed` |
| Longhorn | v1.13.0 | `longhorn.yaml` (release asset) | `d0f99488e7b2789312d45b0127ce7388df71a971e6fca2085e88635303cc0a1f` |
| Longhorn | v1.13.0 | `longhorn-images.txt` (release asset) | `2fa3f49f28a285c136fced55e9a510cb14f847fd7acc20f8baa5956cc5edd760` |
| Longhorn | v1.13.0 | `longhornio/longhorn-manager:v1.13.0` | `sha256:7372f3c59239e9a67c0017b3af32fabdf08c4dcc0631140161da9a47e3b142f0` |
| Longhorn | v1.13.0 | `longhornio/longhorn-engine:v1.13.0` | `sha256:b0cc5090889d57705acd69c5106492992e84560170ac3bec4a1cc8dd3fe83ca6` |
| Longhorn | v1.13.0 | `longhornio/longhorn-instance-manager:v1.13.0` | `sha256:fc9e1c15e81988b04c146866ce7010b6df3a70f88302809bf53e19b27d1658a3` |
| Longhorn | v1.13.0 | `longhornio/longhorn-share-manager:v1.13.0` | `sha256:53950f78b7af38b8a943c298cd3020622191a4661a13036f69d83c154cc8690d` |
| Longhorn | v1.13.0 | `longhornio/longhorn-ui:v1.13.0` | `sha256:f22fb0254ae50195c1635ce428dfae26375956b3d7bd39640fae8fe33a236023` |
| external-snapshotter | v8.7.0 | git tag commit (CRDs `client/config/crd`, `deploy/kubernetes/snapshot-controller`) | `9cc6050ab00a0c56d84ba0279e518a00367363e7` |
| external-snapshotter | v8.7.0 | `kubectl kustomize client/config/crd` output | `9942127fab40ddd5b991745c3aa9127f883df96639b538e3103e51a227a463d5` |
| external-snapshotter | v8.7.0 | `registry.k8s.io/sig-storage/snapshot-controller:v8.7.0` | `sha256:8511f417d0072efcd937aedd7cc79a937d5066e64ee17beb6097301c92742f19` |
| CloudNativePG | v1.30.2 | `cnpg-1.30.2.yaml` (release asset) | `ea4cc355b394e10661d30c6b409cefb19029dd973bccb76b1ed8c789985bc68c` |
| CloudNativePG | v1.30.2 | `ghcr.io/cloudnative-pg/cloudnative-pg:1.30.2` | `sha256:f96f6be3d81ec93819b443c665c575c609342fca840df90d4d87dae314a5b913` |
| barman-cloud plugin | v0.16.0 | `manifest.yaml` (release asset; needs cert-manager) | `aee614683892dd4b44ff9f7afaca55254f1c28de17abbaa0552bf2e1228f7155` |
| barman-cloud plugin | v0.16.0 | `ghcr.io/cloudnative-pg/plugin-barman-cloud:v0.16.0` | `sha256:6404a416718bd7aad943c67a25a7bb20d0558b43edfeab0bf167f013ca435882` |
| barman-cloud plugin | v0.16.0 | `ghcr.io/cloudnative-pg/plugin-barman-cloud-sidecar:v0.16.0` | `sha256:c669259e20ed1e11fad821f735c396c19d929985aa05b9544b13ecc8b5a386d0` |
| SNR | v0.13.0 | `bundle.tar.gz` (OLM bundle, release asset) | `c7d58af594390e5a544a4f0d51579e55462669bd8d5dfe37822dc833efd300c2` |
| SNR | v0.13.0 | `quay.io/medik8s/self-node-remediation-operator:v0.13.0` (manager + agent DS) | `sha256:9ad002dca9ea183c72e350f72e47aff7020397fd476b4a3ac4ebc3627412a5b0` |
| NHC | v0.12.0 | `bundle.tar.gz` (OLM bundle, release asset) | `b12c9eb3bcc22136b8527974700f72260c2f19b141122ea6fe2dfa170f495597` |
| NHC | v0.12.0 | `quay.io/medik8s/node-healthcheck-operator:v0.12.0` | `sha256:5b048ad5d2b8578d2120989a5a822a041d65c985f9ac88d50b000427b32b5391` |
| k3d | v5.9.0 | `k3d-linux-amd64` | `06d8f25bc3a971c4eb29e0ff08429b180402db0f4dec838c9eac427e296800a0` |
| k3d | v5.9.0 | `k3d-linux-arm64` | `03cde5cf23e6e8e67de5a039ecf26e5b85aca82fba3e5d13dadf904cd218a250` |

Notes on the pins:
- **Tested on hardware**: k3s, Longhorn, external-snapshotter, SNR and NHC. **Pinned only, not exercised** (outside Steps 1–8): CNPG, barman-cloud and k3d.
- kubernetes-csi's v8.7.0 snapshot-controller deploy manifest still references image v8.6.0. The pin overrides it with v8.7.0, which ran fine.
- The k3s ServiceLB image in that release is `rancher/klipper-lb:v0.4.17` (STOP 1).
- `get.k3s.io` is unversioned. The copy used had sha256 `c2a2643dd7c259121a876d16538844c60928de3d38ae98f22f7b95a7ffcfab9d`. Pin the binary instead (it is checked against `sha256sum-<arch>.txt`).
- Image digests are manifest-list digests read from each registry's v2 API. Asset sha256s are GitHub release asset digests.
- etcd inside k3s is 3.7.1. The spike used `etcdctl` v3.7.1 for checks only.


## Amendment 2 (2026-11-19): spike 2 results and rulings

Spike 2 (Task 4) ran in k3d; no "doesn't". Node-loss timings, real partitions and 3-server etcd are confirmed on the VMs by `e2e-ha-vm` (Task 33). These rulings bind the owning tasks:

- **CNPG** (Task 23): measured promotion 2.6 s (pod), 67–73 s (node, mostly NotReady detection); an isolated primary shuts down before a promotion; `required` blocks writes with no standby. Pins: CloudNativePG v1.30.2 (Amendment 1).
- **barman-cloud plugin needs cert-manager** (Task 26). Ruling: install cert-manager (pinned by the Task 24 implementer: version + manifest sha256 + image digests) in namespace `cert-manager`, default-deny plus its webhook flow, used only for the plugin's certificates. CNPG's in-tree barman object store is deprecated, so it is not used.
- **Keycloak ×2** (Task 23): `KC_CACHE=ispn`, jdbc-ping, `-Djgroups.bind.address=<pod IP>` (downward API), NetworkPolicy flows 7800/57800 between Keycloak pods. Measured: session survives pod and node loss; 0/328 failures over a rolling restart.
- **Endpoints after a node loss stay for ~40–50 s** (Tasks 19, 26). Traefik's Keycloak and Hub routes get `retry` (attempts 3) and a passive health check; the Vault raft snapshot in the backup retries (5 × 15 s) and asks every voter for the leader rather than trusting `vault-active` alone.
- **LLDAP ×2 is safe** (Task 23) with: a `lldap create_schema` Job before the Deployment (no replica creates the schema), one server key as a Secret mounted on every replica (`LLDAP_SERVER_KEY_FILE`; the generated `/data/private_key` doesn't exist in the HA shape), `enableServiceLinks: false`. The key-file-from-Secret path is untested: Task 23 tests it first.
- **LLDAP conversion** (Task 26): the measured steps in spike-components.md Step 4 (create_schema on the target with the full env and a writable cwd, then the documented data migration). The server key moves with the data into the Secret. uuid, password_hash, groups, memberships and attributes are diffed; any difference aborts.
- **Valkey** (Task 25): measured 7.6 s promotion, 0/50 sessions lost on node loss. Without a guard, a primary that crash-restarts fast comes back empty as master and the replica copies the emptiness (48/48 lost; a `rollout restart` too). Ruling: the sessions chart ships the spike's init guard (never self-elect; when sentinel still names this pod as master, force a failover first) and its readiness probe; `TestSessionsSurviveRolloutRestart` in the e2e pins it.
- **Vault raft** (Task 25): `retry_join { leader_api_addr = "http://vault-internal:8200" }` on the headless Service; auto-unseal from one Secret with core's entrypoint; election 1.4 s (pod), 16 s (node).
- **Published documents** (D2, Tasks 6, 17, 19): measured p50 10.4 s / p99 14.4 s with `sync-frequency=10s` (default kubelet p50 72 s). D2 holds.
- **Memory (user ruling 2026-11-19, Task 19):** core requests = the measured working sets in spike-cluster.md (test-server `docker stats`) and spike-components.md (`kubectl top`), peak × 1.25 rounded up to 16 Mi; limits unchanged.

## Amendment 3 (2026-11-19): spike 1 round 3 — Traefik on hostPort, gateway rules

Supersedes the hostNetwork part of Amendment 1 (S5):
- **Traefik** is a DaemonSet on `portcullis.io/ingress` nodes **in the pod network** with `hostPort` 80/443 (k3s portmap). Measured: the real client IP is kept, it runs as non-root with every capability dropped (no `NET_BIND_SERVICE`), and NetworkPolicy peers `namespaceSelector: portcullis-ingress` + `podSelector app.kubernetes.io/name=traefik` match it under default-deny. hostNetwork is rejected: its traffic carries `cni0`/`flannel-wg` addresses that no selector matches, and kube-router admits same-node traffic from any hostNetwork pod.
- Namespace `portcullis-ingress`: PSA `privileged` (baseline forbids hostPort). The admission policy `portcullis-ingress-pods` admits there only the Traefik pod shape: the `restricted` profile in every field except `hostPort` 80 and 443 on its one container, with no hostNetwork, hostPID, hostIPC, hostPath or added capability.
- **App `ports:`** through ServiceLB keep `loadBalancerSourceRanges` for `lan_only`. Measured: klipper filters on the real client IP before it masquerades, and kube-proxy applies the same ranges inside the cluster. The app sees the svclb address, which is stated in the docs.
- **Mesh gateway rules** (Task 10, nodeagent): its own chain `PORTCULLIS-MESH`, jumped from FORWARD, so kube-router's re-insertion can't reorder it:
  `-i pcmesh -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT`, then (gateways only) `-i pcmesh -o pcmesh -j ACCEPT`, then `-i pcmesh -j DROP`. Without the conntrack rule, replies to pods on the gateway break.

## Amendment 4 (2026-11-21, Task 24): fencing time

T_fence is Self Node Remediation's safe time, 150 s (SNR v0.13.0 with our namespace-scoped patch; nodeadm replaces Node Healthcheck and opens a remediation after 30 s NotReady). Task 33's 5-minute failover budget is NotReady detection (≤ 40 s) + 30 s + T_fence 150 s + volume reattach and pod start. The live Task 24 run measured 3 min 02 s.
