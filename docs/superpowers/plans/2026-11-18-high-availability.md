# High availability on Kubernetes (phases 0 + 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Portcullis Kubernetes install of 3 or more nodes at one site survives the loss of any one node. Sign-in keeps working, no committed data is lost and nothing ever has two writers. Nodes are added from the Hub or the CLI with a join code, and Portcullis installs k3s, the storage, the operators and the fencing itself. Docker single-server doesn't change at all.

**Architecture:**
- **One k3s cluster with embedded etcd**, joined over a kernel WireGuard node mesh `pcmesh`.
- **Core** gains:
  - `nodeadm`, the only holder of the k3s token and the only cluster-scoped actor besides the CLI;
  - an HA mode of the chart (replicas, PDBs, spreading, PriorityClasses, CloudNativePG, Valkey Sentinel, Vault raft ×3, Traefik DaemonSet);
  - the **front-door** role of the domains service (DNS failover plus main-domain certificates);
  - `./portcullis ha enable`, which converts a cluster as one resumable operation.
- **The Hub** becomes a Lease-fenced single writer on a replicated volume. It publishes its documents for other services as named ConfigMaps and Secrets instead of files on a shared `hub-data`. It adds cluster nodes through `nodeadm` and computes the N−1 check.
- **`portcullis-nodeagent`** (Hub repo) is the small fixed-function host service on every node: enrolment, mesh peers, host checks and the public ingress probes.

**Tech Stack:**
- **Hub:** Go 1.27, `k8s.io/client-go` v0.37.2 (now also `tools/leaderelection`), `sigs.k8s.io/controller-runtime/pkg/envtest` (tests only), cel-go v0.29.2, vanilla JS.
- **Core:**
  - bash 3.2 + jq 1.8, `kubectl`, `helm`;
  - k3s with `--cluster-init`;
  - Go 1.27 for `nodeadm/` (new) and `domains/` (lego v4.35.2, libdns);
  - Python 3 (`tests/k8s_*.py`, Playwright e2e), promtool;
  - k3d for `e2e-ha-k3d`.
- **Third-party (pinned by the Task 3 report):** Longhorn (v1 data engine), external-snapshotter, CloudNativePG with the barman-cloud plugin, medik8s Self Node Remediation with the Node Healthcheck Operator.
- **Templates:** Python 3. **Docs:** Zensical.

**Spec:** `docs/superpowers/specs/2026-11-16-high-availability-design.md` in portcullis-hub (Revision 2, binding). Its user rulings (§2, §20) are restated in Global Constraints. User rulings in memory: `ha_kubernetes.md`.

**Scope: phases 0 and 1 of spec §19.1 only** (the spikes, plus core HA and replicated storage on 3 nodes at one site). Phases 2–4 are listed at the end of this plan as out of scope. Each one gets its own plan, because each produces software that works and can be tested on its own (writing-plans "Scope Check"). See Decision D1.

**Size, from the code (not from memory).**
- **The base this plan starts from:**
  - `scripts/lib/kube.sh` is 2,326 lines and hard-codes a single node (`kube_detect_cidrs`). `charts/portcullis/templates/_helpers.tpl:93` writes `replicas: 1` / `Recreate` for every core service. No PriorityClass, Lease or leader logic exists anywhere.
  - Five RWO volumes are shared across pods today, and the spec's §7.2 covers only two of them (D6).
  - Node addresses and API endpoints are frozen into chart values and admission params by the CLI (D10).
  - The Hub's `RulesExact` rejects `resourceNames` rules and requires defaults only in the core namespace.
  - The Hub has no single write funnel: 78 `saveLocked` callers, 23 direct `Save`s and 59 `WriteFileAtomic` sites.
- **The work:** 32 tasks.
  - Stream A: 4, Tasks 1–4 (contract, vectors, 2 spikes).
  - Stream H: 10, Tasks 5–14.
  - Stream C: 15, Tasks 15–29.
  - Stream T: 1, Task 30.
  - Stream D: 1, Task 31.
  - Final: 1, Task 32.
- **Effort:** about **8–12 working days** of the build loop (plan → build → review → CI → test cluster).
  - The calibration is the last four plans of 19–29 tasks, each of which took 1.5–2.5 days.
  - This plan is slower: the spikes need real VMs (1.5–2 days, blocked on D9), it pulls in four third-party operators, and its chaos tests can only be checked on real machines.
  - The spec's own figure for phases 0 + 1 is 22–31 days. It is an upper bound from the design, and the spec says to treat the upper end as realistic. Above 12 days, look first at the VM spikes and the Longhorn/SNR behaviour on arm64.

## Decisions for the user (before Task 1)

The spec leaves each of these open, or contradicts itself on them, and each one changes what gets built. The plan is written assuming the **recommendation** each line gives. The tasks a different answer would change are named in brackets.

- **D1. Scope of this plan.** Phases 0 + 1 only, with phases 2 (app HA, tiers, NFS, snapshots), 3 (Docker assisted recovery, migration paths 1/3, `ha recover`) and 4 (multi-site, Hub hot standby, mail) as later plans. *Recommend: yes.* [all]
- **D2. How fast published documents reach readers.**
  - Today the policy file, `signin-keycloak.json`, `impersonation.json` and the rest are instant on a shared PVC. As ConfigMaps or Secrets (§7.2), the kubelet delivers them in up to about 60–90 s.
  - The spec says "the Hub bumps a pod annotation". That needs `patch` on pods in the core namespace, which can't be limited by name and which §17 doesn't grant.
  - Options:
    - (a) accept ≤ 90 s for group removals and impersonation stops in HA;
    - (b) k3s `--kubelet-arg=sync-frequency=10s` on every node, at some kubelet CPU cost;
    - (c) give the Hub pod `patch` in the core namespace.
  - *Recommend (b), with readers' `.rev` confirmed by the Hub through the existing `hub rev` exec (Hub Role: `pods/exec create` on core pods, by label).* [6, 15, 17]
- **D3. Where the Hub's Lease lives, and the Role delta for it.**
  - §17 lists what the Hub gains and has no Lease. *Recommend:*
    - Leases `portcullis-hub`, `portcullis-frontdoor` and `portcullis-nodeadm` in the core namespace, pre-created by the chart;
    - the Hub's Role there: `coordination.k8s.io/leases` `get`/`update` on `resourceNames: [portcullis-hub]`.

  [5, 6, 17]
- **D4. Cluster-scoped reads and writes.**
  - The N−1 check, the HA page, node labels and taints, cordon/drain and etcd member removal all need cluster-scoped access (nodes, pods in every namespace, CRs). The spec keeps the Hub with "no cluster-scoped verb".
  - *Recommend: `nodeadm` does all of it.* It serves a read-only cluster snapshot and five fixed write operations to the Hub's `hub.control` certificate. This makes `nodeadm` broader than §6.2 says ("only the token holder"). [8, 10, 13, 18]
- **D5. "Make Portcullis highly available" from the Hub.**
  - The Hub can't run Helm or install operators, and §6.3 has the button run the whole conversion.
  - *Recommend for phase 1:*
    - the conversion is CLI-only (`./portcullis ha enable`);
    - the Hub's HA page shows the checklist, the live state, and the command to run;
    - the alternative, an in-cluster executor with cluster-admin rights, is parked.

  [13, 27]
- **D6. The shared volumes that §7.2 doesn't cover.**
  - The volumes:
    - `group-gate-data` holds the opened log. The Hub mounts it read-write and reads it for the sign-in history and for the impersonation "apps opened" audit.
    - `mcp-gate-data` holds the AI access log, which the Hub reads.
    - `wg-data` holds `status.json`, which the Hub reads.

    With 2 gate replicas on different nodes, one RWO volume can't serve them.
  - *Recommend:*
    - each gate replica keeps its log on its own `emptyDir`-backed local PVC (a StatefulSet, one PVC per replica) and serves it on a new internal read-only port that only the Hub may reach (NetworkPolicy);
    - the Hub merges the replicas' logs;
    - a replica that can't be read marks the history "incomplete", as today's read failure does;
    - `wg` publishes `status.json` the same way.
  - Alternatives: pin the gates to the Hub's node, which kills gate HA, or put an RWX Longhorn volume in the sign-in path, which the spec rejects in §7.2. [7, 19]
- **D7. A host-side agent in phase 1.**
  - Joining, the `pcmesh` peer list (every node holds all peers and must learn each new one), host checks and the public probes (§11.1) all need a host process. §19.1 puts `portcullis-nodeagent` in phase 2.
  - *Recommend: a minimal `portcullis-nodeagent` in phase 1* (enrol, mesh, checks, probes). NFS, ZFS and the fixer stay in phase 2. [9]
- **D8. What a fresh Kubernetes install looks like, and whether migration path 2 is built.**
  - *Recommend the HA shape from day one, on every Kubernetes install:*
    - k3s `--cluster-init` on `pcmesh`;
    - CloudNativePG with 1 instance;
    - LLDAP on Postgres;
    - Vault as a 1-voter StatefulSet;
    - published documents as ConfigMaps/Secrets.

    `ha enable` then installs Longhorn and the fencing pieces, moves volumes and scales out. It needs no data conversion.
  - *Recommend also:* following the no-back-compat rule, **don't build migration path 2**. Existing experimental single-node installs re-install through `backup` → `init` → `restore`, which is the kube spec's path. LLDAP's SQLite → Postgres conversion is still needed for that restore of a Docker or old-Kubernetes backup into the new shape, so Task 4 spikes it and Task 23 builds it as a restore step, not as a migration. [4, 15, 20, 23, 27]
- **D9. Real machines.**
  - The spikes (Task 3), the builder chaos job `e2e-ha-vm` (Task 29) and the 3-VM test cluster (Task 32) need 3–4 VMs, one of them arm64 and small.
  - The builder (Lightsail) has no nested virtualisation. The plan never creates cloud resources by itself.
  - *Recommend:* the user approves creating 4 Lightsail instances (3 × 2 vCPU/4 GB amd64 plus one arm64 small-class stand-in, about $60/mo) with the existing profile, deleted after Task 32. They are reused across runs, never recreated per run (spec §19.2 asks for a fresh VM per run). Alternatively the user provides their own machines, a Pi included. [3, 29, 32]
- **D10. Node addresses, API endpoints and the pod CIDR when nodes join.**
  - Today the CLI freezes them into `.env`, chart values and the admission params. They are used by `PORTCULLIS_KUBE_NODE_ADDRESSES`, `apiEndpoints`, the netpol egress denies and the `nodeAddresses` param. `kube_runtime_check` refuses any drift.
  - A Hub-driven join changes all three. *Recommend:*
    - `nodeadm` keeps a ConfigMap `portcullis-cluster-addresses` (mesh, LAN and public address per node, and the API endpoints);
    - the admission params and the chart read **the mesh subnet `10.215.0.0/24` plus that list**;
    - a join finishes only after `nodeadm` has rewritten the params generation through the same create-before-delete binding swap the CLI uses.

    That gives `nodeadm` write access to the admission params and bindings (the alternative is "run `./portcullis ha sync` on the main machine after each join").
  - `PORTCULLIS_POD_CIDR` becomes the cluster CIDR (`10.42.0.0/16`), no longer the first node's `/24`. [15, 18]
- **D11. Per-instance priority and *Runs on* in phase 1.**
  - §19.1 puts the Availability tab in phase 2, but the admission rules and the N−1 check in phase 1. Without an admin priority, N−1 judges only core.
  - *Recommend:* phase 1 ships priority and *Runs on*. HA mode, replicas, tiers and snapshot schedules stay in phase 2. [11, 12, 16]
- **D12. Public probes from a home site without hairpin NAT.**
  - Probing a node's public address from the other nodes at the same site needs the router to support hairpin NAT, and many home routers don't.
  - *Recommend:*
    - Task 3 tests it on the user's network;
    - a cluster whose probes can't reach a public address from inside counts an ingress node healthy on in-cluster health alone (node Ready + Traefik Ready);
    - the HA page and the doctor (`frontdoor_probes_internal_only`, Warning) say that broken port forwarding won't be detected without an off-site node.

  [3, 9, 14, 24]
- **D13. Label.** HA ships **EXPERIMENTAL**, like Kubernetes support: the docs, the HA page banner and `ha enable`'s confirmation say so. *Recommend: yes.* [13, 31]

- **D14. The backup destination in phase 1.**
  - §19.1 puts the backup destination in phase 2. But turning HA on requires it (user ruling with Q1, §6.3 checklist), and CNPG's WAL archive needs it (§7.4).
  - *Recommend:* phase 1 builds the destination for **core only**: CNPG WAL and base backups, the core `backup` archive and Longhorn backups of the core volumes. Instance backups move from `hub-data` to a replicated `hub-backups` PVC and go to the destination in phase 2. [23, 27]

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
    - fencing unconfirmed → no stateful failover [21];
    - quorum lost → nothing promoted, moved or flipped [24, 27];
    - every probe failing → no DNS change (fail static) [24];
    - a join without a verified HMAC proof and certificate → no k3s material [18];
    - an `ha enable` checklist item red → nothing changed [27];
    - unparseable cluster addresses → no params rewrite [18].
  - **Identity = the LLDAP username.** Leases, audit actors and op records name usernames. The LLDAP conversion (Task 23) keeps every user's username **and uuid** (Keycloak's federation links depend on it).
  - **Prefer mature libraries.**
    - Leader election uses client-go `leaderelection`.
    - Storage, Postgres and fencing use their operators.
    - DNS and ACME go through the domains service's existing lego/libdns providers.
    - No hand-rolled YAML, CEL, WireGuard or Raft.
  - **Main-only merges.** See Final, Task 32.
  - **No private identifiers in public repos.** No cloud profile, account id, VM name, test-server hostname or private repo name in code, docs or commits.
  - **ACME staging on the test server.** The test cluster always runs `ACME_STAGING=true`: `config apply` + `up` after `init`. The front-door account is a staging account there. The public would-issue check runs before every CAA flip.
  - **Never touch the LLDAP `admin` user.**
  - **Never weaken the kube security model** (spec §3 anti-goals):
    - the Hub has no cluster-scoped verb and holds no token;
    - every namespace is default-deny;
    - the admission policies judge every identity except the CLI;
    - etcd, the kubelet and the API server listen only on mesh addresses.
- **Single-server stays the same.** A Docker install gains no prompt, dependency, flag, service or `.env` key. `tests/test_cli.sh` keeps `test_docker_init_unchanged`, which diffs the Docker `init` transcript and `.env` key set against a fixture committed in Task 15.
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
  - **Mesh:** `pcmesh` kernel WireGuard, `10.215.0.0/24` fixed (checked against link `10.214.0.0/24` and the people VPN), full static peer list, k3s `--node-ip` on the mesh address, `--flannel-backend=wireguard-native`.
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
    - `ha_lease_lost` (Problem).
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

## Review Focus

1. **The Hub on a node that a partition isolates.** Its pod keeps running until SNR reboots the node, and background ops, op records and audit appends are in flight. Every write must stop within 10 s of the last renewal, including those already running, and the new Hub on the majority side must never see a write from the old one land after its own first write. Pinned by `TestLeaseLostStopsInflightWrites` and `TestNoFileWritesOutsideFsutil` (Task 5).
2. **A published document grows past the object limit** (a big `user-attributes.json`, many apps in the policy file). The Hub must keep the last good document, never truncate it, never publish an empty one, and raise `published_doc_too_large`. Readers keep enforcing the old document. Pinned by `TestPublishTooLargeKeepsLast` (Task 6).
3. **Restoring a Docker backup into the HA shape converts LLDAP from SQLite to Postgres.** Every user's username, uuid, groups and password hash must survive, otherwise Keycloak's federation links break and people lose their passkeys. Any difference in counts or uuids aborts the restore with nothing switched. Pinned by `test_lldap_convert_keeps_uuids` (Task 23).
4. **`ha enable` interrupted** by Stop, a CLI crash or a node lost half-way. A re-run resumes from the recorded step. Two Postgres writers or two Hubs must never be up at once: the old single Postgres stays scaled to 0 once CNPG has the data, and the old Hub stays scaled to 0 before the new volume attaches. Pinned by `test_ha_enable_resumes_each_step` and `test_ha_enable_never_two_writers` (Task 27).
5. **The DNS provider fails half-way through a change**: the new address is appended, then the delete of the stale one fails, or the API rate-limits. The set must never drop to zero addresses, retries must stay within one change per name per 60 s, and `PortcullisDNSFailoverStuck` must fire after 5 min. Pinned by `TestFrontDoorPartialWriteNeverEmpty` (Task 24).

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
| `domains/frontdoor/` (new package), `domains/traefik.go`, `domains/main.go` | front door |
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
  - **20.4 nodeagent API:** `GET /v1/health`, `GET /v1/checks`, `PUT /v1/mesh/peers` (the full list, idempotent), `GET /v1/probes`, `POST /v1/k3s/uninstall`.
  - **20.5 Leases and the write fence.**
  - **20.6 Priority and *Runs on*:** state, API and the affinity each choice renders.
  - **20.7 N−1:** the input snapshot and the algorithm, as in Task 10.
  - **20.8 Front door:** health inputs, hysteresis, fail static, the `frontdoor-status` document `{v:1, names:{<name>:{addresses:[…], ttl, worst_case_s, last_change, pending}}, probes:{<node>:{ok, internal_only}}}`.
  - **20.9 Cluster addresses document** `portcullis-cluster-addresses` `{v:1, mesh_cidr, cluster_cidr, service_cidr, api:[…], nodes:{<id>:{mesh, lan:[…], public:[…]}}}`.
  - **20.10 Per-replica logs** (D6): ports `group-gate :8091` and `mcp-gate :8092`, `GET /v1/log?from=<ts>&limit=` (JSONL, ≤ 4 MiB per answer), and `wg :8093` `GET /v1/status`, each admitted only from the Hub pod.

- [ ] **Step 1:** Write the sections above in the docs worktree. Every refusal text appears exactly once in the contract, together with the vector file that carries it.
- [ ] **Step 2:** Run the docs gates. Expected: all pass, `zensical build --strict` clean.
- [ ] **Step 3:** Sync the Hub copy (`web/docs/sync.sh`), then run `go test ./web/ -run TestDocsCopies`. Expected: PASS.
- [ ] **Step 4:** Commit docs (`contract: high availability §20, cluster nodes, published documents`) and Hub (`web/docs: sync contract (HA)`).

### Task 2: Shared vectors (Hub authors the Hub-owned ones, core the core-owned ones)

**Files:**
- Create (Hub): `internal/publish/testdata/published_docs.json`, `internal/servers/testdata/joincode_v2_vectors.json`, `internal/nminus1/testdata/nminus1_vectors.json`, `internal/nodeagent/testdata/nodeclass_vectors.json`.
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
  - internal-only (D12).
- **`nminus1_vectors.json`:** `[{name, snapshot, want:[{node, level, unplaced, evicted}]}]`, ≥ 12 cases: taints, the `small` taint, required affinity, anti-affinity/spread, preemption of normal/low only, `preemptionPolicy: Never` on low, DaemonSet pods ignored, a node already NotReady.
- **`nodeclass_vectors.json`:** `[{mem_bytes, cpu, model, public_answers, want}]`, covering < 4 GB → small, "Raspberry Pi" → small, public → cloud, else home.

- [ ] **Step 1: Write the failing loaders.**
  - Hub: `TestPublishedDocsVectorsShape`, `TestJoinCodeV2VectorsShape`, `TestNMinus1VectorsShape`, `TestNodeClassVectorsShape` (each asserts its file parses strictly and has its minimum case count).
  - Core: `nodeadm` `TestAPIVectorsShape` and `domains` `TestFrontdoorVectorsShape`.
  - Byte-copy checks: Hub `TestNodeadmVectorsCopy` and `TestFrontdoorVectorsCopy` (`PORTCULLIS_CORE_DIR`); core `unit-tests-kube-static.sh` compares `tests/published_docs.json` and `joincode_v2_vectors.json` against the Hub's same-named branch.
- [ ] **Step 2:** Run them. Expected: FAIL (files missing).
- [ ] **Step 3:** Write the vector files, values from Task 1. The new admission cases: each of the four refusal texts, and the accepted forms (`portcullis-low` with no toleration; small toleration + the class term; hostname spread).
- [ ] **Step 4:** Run them. Expected: PASS. The envtest admission cases tagged `ha` stay **skipped** until Task 16 (`t.Skip("ha admission lands in Task 16")` keyed on the tag, removed there).
- [ ] **Step 5:** Commit in each repo (`vectors: HA (published docs, join code v2, nodeadm API, front door, N−1, node class)`).

### Task 3: Spike — cluster, storage, fencing on real machines (builder + VMs, D9)

**Files:** Create (Hub): `.superpowers/sdd/2026-11-18-high-availability/spike-cluster.md`. No product code.

**Interfaces — Produces:** pins (version + sha256/digest) for k3s, Longhorn, external-snapshotter, CNPG + barman-cloud plugin, SNR, NHC and k3d. They are written into this plan's Global Constraints as an amendment commit, as the kube plan's Task 0 did. Each answer below is recorded as **works / works with X / doesn't**.

- [ ] **Step 1:** Three amd64 VMs and one arm64 small VM, linked by a hand-made `pcmesh` (spike only). Bring up k3s `--cluster-init` on `10.215.0.1`, join 2 servers + 1 agent over `pcmesh` with `--flannel-backend=wireguard-native`, then remove one server (etcd member removal). Record: works, and the steps that worked.
- [ ] **Step 2:** Longhorn v1 on the arm64 node with a USB SSD (or a separate block device), plus on a node whose root is ZFS or btrfs. Record whether Longhorn needs a separate disk.
- [ ] **Step 3:** SNR + NHC, with `softdog` on cloud VMs.
  - Partition one node (`iptables -I INPUT -j DROP` on mesh + API) and record `T_fence` to reboot.
  - Power one off, apply the out-of-service taint after `T_fence` + margin, and record the detach time and the stateful pod start time elsewhere.
  - Target 2–4 min.
- [ ] **Step 4:** etcd fsync p99 on the arm64 node during a Longhorn rebuild.
- [ ] **Step 5:** ServiceLB with `enablelb` labels and `externalTrafficPolicy: Local` on 2 ingress nodes: the client IP is kept and both answer.
- [ ] **Step 6:** Hairpin probe (D12): from each node, `curl --resolve auth.<d>:443:<public ip of another node>`. Record per network.
- [ ] **Step 7:** Multi-value A records through the domains providers: Porkbun (our v3 client) and Cloudflare. Append a second A, delete one by id, and confirm what the public resolvers serve.
- [ ] **Step 8:** Commit the report and the pins amendment (`plan: HA spike 1 results and pins`). **Any "doesn't" answer stops the plan for a user decision.**

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
  - `gatelogs.Source interface{ Read(ctx, from time.Time, limit int) ([]byte, error) }`;
  - `gatelogs.Replicas{Service string; Port int; Lister func(ctx) ([]string, error)}`, where the lister uses the Hub's `pods list` in the core namespace (Task 6 Role);
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
- [ ] **Step 3:** Implement. The pruning to `history_days` (today a write to `group-gate-data`) is now each gate's own job (Task 19). The Hub no longer writes there on Kubernetes.
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
  - The `server_enrol` steps are `enrolled`, `k3s_joined`, `node_ready`, `storage_ready` and `done`, each read from `Cluster()`.
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
func TestEnrolStepsFromSnapshot(t *testing.T)       // snapshots in order → op steps enrolled→k3s_joined→node_ready→storage_ready→done; Stop during → op stopped, nodeadm Remove(cooperative) called
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
- Modify: `.github/workflows/build.yml`: the matrix gains `nodeagent`, which also uploads `nodeagent-linux-{amd64,arm64}` with their sha256 as release and `edge` artifacts. The `nodeadm` image (Task 18) copies them from `ghcr.io/porelli/portcullis-nodeagent@sha256:…`.

**Interfaces:**
- Consumes: §20.4 and the join code v2 (Tasks 1, 2); the mTLS peer checks of `internal/agent/server.go` (shared through a new `internal/pkinode` package extracted from it).
- Produces: the `portcullis-nodeagent` subcommands:
  - `join <code-on-stdin>`: the host checks, the HMAC proof to `/node/v1/enrol`, the CSR, the `pcmesh` key, and `/node/v1/join` → k3s install with the material over the mTLS channel;
  - `serve`;
  - `checks`.

  The API is §20.4. Probes run every 10 s against each other ingress node's public address with SNI `auth.<d>`, and `GET /v1/probes` answers the last 3 rounds. `class.Suggest(mem, cpu, model, publicAnswers) string`.

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
- [ ] **Step 3:** Implement. WireGuard goes through `golang.zx2c4.com/wireguard/wgctrl` (a mature library). k3s is installed from the pinned script and binary (sha256 checked) with the flags in Task 15, and the `--token-file` comes from the channel (never argv, never logged).
- [ ] **Step 4:** Run them. Expected: PASS. Build both arches.
- [ ] **Step 5:** Commit (`nodeagent: host agent for cluster nodes (enrol, mesh, checks, probes)`).

### Task 10: The N−1 simulator (Hub)

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

### Task 11: Translator — priority, tolerations, *Runs on*, requests (Hub)

**Files:**
- Modify: `internal/runtime/kube/translate.go` (`workload()`, the container resources around :1163), `names.go` (priority class names), `internal/runtime/types.go` (`Input.Availability`).
- Create: `testdata/translate/ha-priority/`, `ha-runs-on-only-small/`, `ha-no-memlimit/`.

**Interfaces:**
- Consumes: `state.Availability` (Task 12).
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
- [ ] **Step 4:** Run the test again, plus `-tags envtest -run TranslatedObjectsAdmitted` (it passes after Task 16's policies are copied; until then it runs against the current copy and must still pass, because the current policies don't refuse these fields). Expected: PASS.
- [ ] **Step 5:** Commit (`hub: translator renders priority, HA tolerations, Runs on, CPU/memory requests`).

### Task 12: Instance availability — priority and *Runs on* (Hub, D11)

**Files:** Create `internal/state/availability.go`, `internal/hub/availability.go`, `internal/httpapi/availability.go`, `internal/httpapi/mcptools_availability.go`, `web/availability.js` (add to `//go:embed`). Modify `web/index.html` (Instance → Manage → Availability) and the setup form (priority only).

**Interfaces:**
- Consumes: `nminus1.Check` / `Explain` (Task 10), `nodeadm.Client.Cluster` (Task 8).
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

### Task 13: The HA page (Hub, D4, D5, D13)

**Files:** Create `internal/hub/ha.go`, `internal/httpapi/ha.go`, `internal/httpapi/mcptools_ha.go`, `web/ha.js`. Modify `web/index.html` (Settings → High availability).

**Interfaces:**
- Consumes:
  - `nodeadm.Snapshot` (nodes, quorum per system, CNPG sync state, Longhorn robustness, fencing per node);
  - `frontdoor-status` (via the Role's `get`);
  - `nminus1.Check`;
  - the backup destination state (`state.BackupDestination`, read from `core.env`'s `PORTCULLIS_BACKUP_S3_URL` presence — never the credentials);
  - `frontdoor_vectors.json` worst-case texts.
- Produces:
  - `GET /api/ha` → `{experimental: true, enabled, checklist:[{id, ok, text}], guarantee, nodes:[{name, role, class, site, ready, fencing, n_minus_1}], quorum:{etcd, vault, sentinel}, dns:[{name, addresses, worst_case_text}], credentials_note, command:"./portcullis ha enable"}`;
  - the checklist ids `nodes`, `servers`, `storage`, `ingress`, `backup_destination`, `n_minus_1`, `watchdog`;
  - the guarantee texts from the spec (verbatim);
  - for Porkbun, `credentials_note` = "Porkbun API keys can change every domain in the account: Portcullis can't narrow them";
  - MCP `ha_status` (R).

- [ ] **Step 1: Write the failing tests.**

```go
func TestHAChecklistFromSnapshot(t *testing.T)  // 2 nodes → nodes false "at least 3 nodes"; no destination → backup_destination false "set an offsite backup destination first"
func TestGuaranteeText(t *testing.T)            // 2 instances + preferred + 1 sync standby → "Zero loss on one failure"; 0 sync standbys → "Degraded: one more failure may lose the last writes"
func TestWorstCaseTextVectors(t *testing.T)     // frontdoor_vectors.json want_worst_case_text
func TestHAPageNeverShowsCredentials(t *testing.T) // response JSON has no key or value from frontdoor-env / backup-destination fixtures
func TestHAEnableIsNotAnAPI(t *testing.T)       // POST /api/ha/enable → 404 (D5); the page shows the command
```

- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement. The banner reads "High availability is experimental".
- [ ] **Step 4:** Run them, plus `TestToolParity`. Expected: PASS.
- [ ] **Step 5:** Commit (`hub: Settings → High availability page`).

### Task 14: Doctor kinds and MCP read tools (Hub)

**Files:** Create `internal/doctor/ha.go`, `internal/hub/doctor_ha.go`, `internal/doctor/ha_test.go`. Modify `internal/hub/doctor_runtime.go`.

**Interfaces:**
- Consumes: Tasks 6, 8, 10, 13.
- Produces: `doctor.HAKinds` = `node_down`, `ha_quorum_at_risk`, `volume_degraded`, `pg_not_synchronous`, `ha_fencing_unavailable`, `ha_n_minus_1_insufficient`, `backup_stale`, `template_no_memory_limit`, `frontdoor_probes_internal_only`, `published_doc_too_large`, `published_doc_stale`, `ha_lease_lost`, each with the severity of Global Constraints. The input `HAIn{Snapshot, FrontdoorStatus, Published, LastBackup, Lease}`. The existing `kube_api_public` is checked for **every** node's public address from the snapshot (spec §17), with `TestKubeAPIPublicPerNode` (one exposed node of three → the kind names that node).

- [ ] **Step 1:** Write the failing `TestHAKinds` (every kind registered once, severities exact) and one `TestHAKind_<kind>` per kind (the input that raises it, and the one that clears it; `node_down` only after > 1 min NotReady; `volume_degraded` only after > 10 min; `backup_stale` after 26 h).
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement. The kinds register only when `kubeOn()`.
- [ ] **Step 4:** Run them. Expected: PASS. Check the contract §14.5 copy (`TestDocsCopiesInSync`).
- [ ] **Step 5:** Commit (`hub: HA doctor kinds`).

---

## Stream C — Core

### Task 15: `init --runtime kubernetes` installs k3s on `pcmesh` (core, D8, R3)

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
    - `--kubelet-arg=address=10.215.0.1`.
  - It runs only when no `PORTCULLIS_KUBE_CONTEXT` cluster answers.
  - `kube_install_mesh` writes `/etc/wireguard/pcmesh.conf` (private key generated on the host, mode 0600) and enables `wg-quick@pcmesh`.
  - `kube_host_checks` gains `open-iscsi`, `nfs-common`, the watchdog device and ZFS/btrfs detection (reported only). It runs before the install, followed by **one** confirmation that lists the packages to install.

- [ ] **Step 1: Write the failing shell tests** (`expect_eq` style, a fake `curl`/`sha256sum`/`systemctl` on PATH).
  - "kube_install_k3s: refuses a script whose sha256 differs" (rc=1, nothing executed).
  - "kube_install_k3s: flags exactly" (the recorded argv of the fake installer equals the list above, sorted).
  - "kube_install_k3s: token never on argv" (grep the recorded argv and the log for the fixture token: none).
  - "kube_install_mesh: private key mode 0600 and never printed".
  - "kube_detect_cidrs: three nodes accepted, cluster CIDR 10.42.0.0/16".
  - "kube_host_checks: one confirmation lists open-iscsi nfs-common".
  - "init docker: transcript and .env keys unchanged" (`test_docker_init_unchanged`).
- [ ] **Step 2:** Run `bash tests/test_shell_libs.sh` and `bash tests/test_cli.sh`. Expected: FAIL on the new cases.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run them again, plus shellcheck. Expected: PASS. Then `gh workflow run ci.yml --ref ha -f jobs=unit-tests,e2e-k3s` (e2e-k3s now installs through `kube_install_k3s`).
- [ ] **Step 5:** Commit (`cli: init installs pinned k3s with embedded etcd on the pcmesh node mesh`).

### Task 16: PriorityClasses and the admission additions (core; Hub byte copies)

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

### Task 17: The chart's HA mode and the published documents (core)

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

### Task 18: `nodeadm` (core, D4, D10)

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
  - the R7 metrics.
- `nodeadm`'s **ClusterRole** is exactly:

  | Resources | Verbs |
  |---|---|
  | `nodes` | `get`, `list`, `watch`, `patch` (labels, taints, unschedulable) |
  | `pods` | `list`, `watch` |
  | `pods/eviction` | `create` |
  | CNPG/Longhorn/SNR status CRs | `get`, `list` |
  | `validatingadmissionpolicybindings` | `create`, `delete` (label `portcullis.io/admission`) |

  Its Roles are `secrets` `create` in `kube-system` (type bootstrap only, VAP Task 16), `get` on `nodeadm-k3s-token`, `configmaps` `create`/`delete` on `portcullis-admission-params-*` and `update` on `portcullis-cluster-addresses`, and `leases` `get`/`update` on `portcullis-nodeadm`. etcd member removal goes through the k3s server's etcd client using the node's etcd client certificate mounted read-only (hostPath `/var/lib/rancher/k3s/server/tls/etcd/` on server nodes, in its own namespace `portcullis-nodeadm`, PSA privileged). **This is a security delta for `hardening.md`**: `nodeadm` is privileged.

- [ ] **Step 1: Write the failing tests** (Go, envtest for the Kubernetes parts, fake etcd).

```go
func TestAPIVectors(t *testing.T)                  // every vector request → vector response
func TestEnrolNeedsProofThenCert(t *testing.T)     // join without prior enrol → 403; wrong HMAC → proof_invalid; replay of a used code → code_used; > 15 min → code_expired
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

### Task 19: Gates and wg serve their logs; group-gate prunes its own (core, D6)

**Files:** Modify `group-gate/group-gate.py` (log port `:8091`, `GATE_OPENED_PRUNE_DAYS`), `tests/test_group_gate.py`, `mcp-gate/main.go` + `internal/…` (`:8092`), `wg/main.go` (`:8093` `GET /v1/status`), the chart's StatefulSets for group-gate and mcp-gate in HA (one local PVC each per replica).

**Interfaces:**
- Consumes: §20.10.
- Produces: the read-only endpoints. Each:
  - binds its own port;
  - refuses every method but GET;
  - answers ≤ 4 MiB JSONL with `from` / `limit`;
  - has no auth beyond the NetworkPolicy (Hub pod only, Task 17), as with every other internal port bound to how traffic arrived.

- [ ] **Step 1: Write the failing tests:**
  - `test_group_gate.py` `test_log_endpoint_get_only`, `test_log_endpoint_from_limit` and `test_prune_days` (entries older than N days removed at start and daily);
  - mcp-gate `TestAccessLogEndpoint`;
  - wg `TestStatusEndpoint`;
  - `k8s_netpol_matrix.py` rows (already in Task 17).
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run them. Expected: PASS.
- [ ] **Step 5:** Commit (`gates, wg: read-only log and status ports for the Hub (HA)`).

### Task 20: Postgres on CloudNativePG, LLDAP on Postgres (core, D8)

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

### Task 21: Longhorn, external-snapshotter, fencing (core)

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
- [ ] **Step 4:** Run them. Expected: PASS. (Live behaviour is checked in Task 29.)
- [ ] **Step 5:** Commit (`ha: Longhorn, snapshotter and medik8s fencing installs (pinned)`).

### Task 22: Valkey Sentinel and Vault raft ×3 (core)

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

### Task 23: The backup destination, CNPG archives, and the LLDAP conversion on restore (core, D8, R5)

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

### Task 24: The front-door role — DNS failover (core `domains/`)

**Files:** Create `domains/frontdoor/{engine.go,health.go,writer.go,status.go,engine_test.go}`, `charts/portcullis/templates/frontdoor.yaml` (Deployment, Secret `frontdoor-env` mount, Role, NetworkPolicy: egress to the DNS provider API and nodeagents' `:7443` only). Modify `domains/main.go` (`domains frontdoor` subcommand).

**Interfaces:**
- Consumes:
  - `frontdoor_vectors.json`;
  - the existing providers (`provider_porkbun.go`, `provider_byid.go`, libdns) and their by-id deletes;
  - nodeagent `/v1/probes` (client cert `frontdoor.control`, Task 18);
  - the node and Traefik readiness from `nodeadm`'s snapshot (`GET /v1/cluster`; `frontdoor.control` gets read-only access to that one route, added to §20.2 by Task 1).
- Produces:
  - `frontdoor.Engine.Step(now time.Time, in Inputs) []Change` (pure, vector-tested);
  - `Writer.Apply(ctx, Change) error` (append, then delete the exact stale value by id);
  - the `frontdoor-status` ConfigMap;
  - metrics `portcullis_frontdoor_addresses{name}` and `portcullis_frontdoor_unhealthy_published_seconds{name,address}`.

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

### Task 25: The front-door role — HA certificates and the CAA flip (core)

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

### Task 26: `./portcullis node …` (core)

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

### Task 27: `./portcullis ha status|enable` (core, D5)

**Files:** Modify `scripts/lib/ha.sh` (`cmd_ha`, `ha_enable_step_<n>`, state file `secrets/kube/ha-enable.json`), `scripts/lib/kube.sh` (render `ha.enabled` from `PORTCULLIS_HA`), `tests/test_shell_libs.sh`, `tests/test_cli.sh`.

**Interfaces:**
- Consumes: Tasks 17–25; `GET /api/ha` checklist via `kubectl exec hub -- hub ha checklist`.
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
  - "ha enable: refuses on docker: 'high availability needs Kubernetes'".
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run them. Expected: PASS.
- [ ] **Step 5:** Commit (`cli: ha status and ha enable (resumable conversion)`).

### Task 28: Monitoring — alerts and the cluster dashboard (core, R7)

**Files:** Modify `monitoring/prometheus/prometheus.yml` (the `nodeadm` and `frontdoor` jobs), `alerts.yml`, `tests/alerts_test.yml`, `charts/portcullis/templates/monitoring.yaml`. Create `monitoring/grafana/dashboards/cluster.json`. Modify `alertmanager` config (`watchdog_url` opt-in, empty by default).

**Interfaces:** the alert names of Global Constraints, over the R7 gauges and the front-door metrics.
- `PortcullisNodeDown`: `portcullis_node_ready == 0` for 1m.
- `PortcullisQuorumAtRisk`: `portcullis_quorum_voters{state="up"} == floor(total/2)+1`.
- `PortcullisQuorumLost`: below the majority, or `up{job="nodeadm"} == 0` for 2m.
- `PortcullisVolumeDegraded`: for 10m.
- `PortcullisDNSFailoverStuck`: `portcullis_frontdoor_unhealthy_published_seconds > 300`.
- `PortcullisBackupStale`: 26h.

- [ ] **Step 1:** Write the failing promtool unit tests in `tests/alerts_test.yml`, one per alert: the firing series and the not-yet-firing boundary (59 s, 9 m 59 s, 4 m 59 s, 25 h 59 m).
- [ ] **Step 2:** Run `promtool test rules tests/alerts_test.yml`. Expected: FAIL.
- [ ] **Step 3:** Implement. The dashboard covers nodes, quorum, failovers, volume health and replication lag.
- [ ] **Step 4:** Run promtool again, plus `lint_images.sh`. Expected: PASS.
- [ ] **Step 5:** Commit (`monitoring: HA alerts and cluster dashboard`).

### Task 29: CI — `e2e-ha-k3d` and `e2e-ha-vm` (core, D9)

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
  - `ha_published_docs`: a group removal reaches group-gate within 20 s with `sync-frequency=10s`.
- `e2e-ha-vm` (the D9 VMs, reused, reset by `k3s-uninstall.sh` + wipe of the test disks, **never the builder host**):
  - `ha_vm_partition`: the minority self-fences within `T_fence`; a writer on it fails; a test app's data checksums equal the majority's afterwards;
  - `ha_vm_power_off`: the stateful app runs elsewhere within 4 min;
  - `ha_vm_disk_kill`, `ha_vm_disk_full`;
  - `ha_vm_lose_small`;
  - `ha_vm_rolling_upgrade`: a rolling upgrade under the sign-in loop.

- [ ] **Step 1:** Write `tests/e2e/e2e_ha.py` with every scenario, plus the `tests/test_e2e_scenarios.py` cases (each scenario starts with its `skip` gate).
- [ ] **Step 2:** Run `python3 tests/test_e2e_scenarios.py`. Expected: FAIL until the jobs exist and are listed.
- [ ] **Step 3:** Implement the scripts. Each CI step over 20 lines goes in `.github/ci/`. Check `lint_ci_size.sh`.
- [ ] **Step 4:** Run `.github/ci/e2e-ha-k3d-local.sh` on the builder, then `gh workflow run ci.yml --ref ha -f jobs=e2e-ha-k3d`, then `-f jobs=e2e-ha-vm -f runner=builder`. Expected: green, every scenario passing. Start a background watcher on each run.
- [ ] **Step 5:** Commit (`ci: e2e-ha-k3d and e2e-ha-vm`).

---

## Stream T — Templates

### Task 30: Reserved core names (templates)

**Files:** Modify `tests/core_names.txt` (`nodeadm`, `frontdoor`, `sessions-sentinel`, `portcullis-pg`, `portcullis-pg-rw`, `portcullis-pg-ro`, `vault-internal`, `vault-active`), `tests/validate.py` (reserved-name check reads the file), `tests/test_validate.py` (`TestCoreNamesComplete` against core's same-named branch).

- [ ] **Step 1:** Write the failing `test_reserved_ha_names` (a service named `nodeadm` → "service name nodeadm is reserved by core").
- [ ] **Step 2:** Run `python3 tests/test_validate.py`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `python3 tests/validate.py && python3 tests/test_validate.py`. Expected: PASS. Then run `lint.yml` on `ha`.
- [ ] **Step 5:** Commit (`validate: core names reserved by HA`).

---

## Stream D — Docs pages

### Task 31: Docs pages (docs)

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

### Task 32: Full CI, reviews, merges, the test cluster, cleanup (all repos)

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
  - Add VM2/VM3 (servers) and VM4 (agent, small) from the Hub, then run `ha enable`.
  - Do one live failover per component: a node power-off, the CNPG primary, the Valkey primary, the Vault leader, the Hub node, an ingress node (DNS).
  - Record each outcome in the ledger.
- [ ] **Step 5:** Write the user's laptop check as steps (sign in during a power-off; the HA page; a node add) for the user to run.
- [ ] **Step 6: Cleanup** (memory: branches mainlined).
  - Delete every `ha` branch (local and remote) in the four repos, every `wt-ha/*` worktree, `/tmp/merge-*`, `/tmp/pk-ha-*` and `/tmp/ha-read`.
  - Delete the D9 VMs unless the user says otherwise.
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
- **Phase 4:** the mesh across NAT, a tie-breaker at a third location, the CNPG replica cluster, Longhorn DR volumes, the sync heartbeat and site promotion (user ruling Q2), the NFS second copy, Hub state in Postgres + hot standby, mail on Kubernetes.
