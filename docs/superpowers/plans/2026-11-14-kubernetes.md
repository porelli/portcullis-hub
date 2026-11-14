# Kubernetes support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run Portcullis core as a hand-written Helm chart on a single-node k3s, driven by the same `./portcullis` CLI against a named kube context. The Hub translates each app instance's rendered compose project into a small fixed set of Kubernetes objects. Every Docker trust anchor gets a mechanism that is at least as strict, and backups stay runtime-neutral.

**Architecture:** The core CLI gains an `rt_*` runtime layer. Its docker/podman branch is today's `dc` code, and its kubernetes branch is `kubectl` + `helm`, with Secrets and ConfigMaps synced from the operator's `secrets/` and host files, never generated in the chart. Isolation moves from compose networks and pinned IPs to these mechanisms:
- pod labels plus default-deny NetworkPolicies;
- trust bound to the port a connection arrived on (Traefik's `kcinternal` and `vpnsecure` entrypoints, routed app ports open only to Traefik, `wg` edge ports open only to their own gateway's pods);
- PSA `restricted` for core;
- ValidatingAdmissionPolicies that guard the Hub's one namespaced Role in `portcullis-apps`.

The Hub gets an `internal/runtime` interface. The existing compose CLI + Engine become its `docker` backend (Docker and rootless Podman, unchanged). A new `kube` backend (client-go, server-side apply) has its own translator, helper pods running the Hub's own image, an admission self-test and NetworkPolicy rendering. The core `wg` service (VPN contract §16) runs as one pod with its edge and people roles. Its UDP port is a LoadBalancer Service. The `link` role, which is how a cluster on another machine will join (VPN spec user ruling 2, multi-server spec §12), stays with the multi-server plan.

**Tech Stack:**
- **Core:** bash 3.2 + jq 1.8, `kubectl`, `helm`, k3s (pinned, sha256-checked), kubeconform (pinned schemas plus the Traefik CRDs), Python 3 + PyYAML (`tests/k8s_parity.py`, `tests/k8s_netpol_matrix.py`), and the pinned upstream `rancher/local-path-provisioner`.
- **Hub:** Go 1.27 with `k8s.io/client-go`, `k8s.io/api`, `k8s.io/apimachinery` (server-side apply, `fake` clientset), `sigs.k8s.io/controller-runtime/pkg/envtest` (tests only, kube-apiserver 1.32), `github.com/google/go-containerregistry` (digest resolution, image config) and `github.com/compose-spec/compose-go/v2` (already used). Traefik CRD objects are `unstructured`, so the Traefik module isn't pulled in.
- **Templates:** Python 3.
- **CI:** GitHub Actions. **Docs:** Zensical.

**Spec:** `/Volumes/workspace/portcullis/portcullis-hub/docs/superpowers/specs/2026-11-13-kubernetes-design.md` (binding). §13 open questions, settled by Task 0 (done, see Task 0):
- Q1: ServiceLB with `externalTrafficPolicy: Local` keeps the client IP for an address in the Service's `status.loadBalancer.ingress`. **No hostNetwork fallback.**
- Q2: a pinned upstream provisioner `portcullis.io/local-path` (v0.0.37) with the native `userPattern`/`groupPattern`/`permPattern` (ruling K3, mechanism (a) native).
- Q3: routed ports stay Traefik-only.
- Q4: "degraded: connect by address".
- Q5: the floor stays Kubernetes 1.32 (every CEL function Task 8 needs works there).

Related plans: `2026-11-13-rootless-podman.md` (`CONTAINER_RUNTIME`, the guard, the compat gate) and `2026-11-13-vpn-only-access.md` (the `wg` service, `vpnsecure`, `vpn.json` v2). Their structure is copied here.

**Amended 2026-11-13** (before Task 1): the Task 0 spike results are folded into the tasks; the plan is updated for VPN-only access (`vpn1`), DNS hardening, Rootless Podman and `kcwait` on main (§ "VPN, kcwait and Podman on Kubernetes" below); the pre-flight scan is `.superpowers/sdd/2026-11-14-kubernetes/preflight.md` (findings K-P1…K-P30), and its rulings are written into the tasks they bind. Mains at amendment: core `791a7436d9a7`, Hub `398361dfc33d`, templates `37350f43277b`, docs `0dbf043769da`.

## Global Constraints

- **Base.** VPN-only access (`vpn1`) is merged to `main` in all four repos (core `6babe04`, Hub `398361d`, docs `0dbf043`, templates `37350f4`), and so are DNS hardening, Rootless Podman and `kcwait` (core `791a743`). Never base on a feature branch. `vpn2` (Hub + templates: the VPN gateway allowlist, pid/ipc/`volumes_from` rules) is still open: if it merges before Task 3 or Task 9, merge `origin/main` into `kube1` (a merge commit, never a rebase) before that task, and the Kubernetes compat rules never restate vpn2's gateway rules (K-P24).
- **Branches and worktrees:**
  - Branch `kube1` in core, Hub, templates and docs, at `/Volumes/workspace/portcullis/wt-kube1/{portcullis,portcullis-hub,portcullis-templates,portcullis-docs}`. Create each one with `git -C <main checkout> worktree add -b kube1 <path> origin/main`, and record the base SHAs in the Task 1 commit message.
  - Templates `kube2` (Task 10) is cut from main after the core merge.
  - Main checkouts may hold other people's work: never edit, stash or commit there.
- **Contract first.** Task 1 lands on docs `kube1` before any code task. After Task 1 and Task 17, resync the Hub copies with `PORTCULLIS_DOCS_DIR=/Volumes/workspace/portcullis/wt-kube1/portcullis-docs web/docs/sync.sh`, then commit `web/docs`.
- **Project rules:**
  - No back-compat or migration code. `PORTCULLIS_TRAEFIK_IP` / `PORTCULLIS_MCP_GATE_IP` stop being template variables: templates switch to `_SOURCE`, nothing reads both, and `RootlessCompat` is renamed (no alias).
  - Prefer the libraries in Tech Stack. Never hand-roll a YAML, CEL or kube wire format.
  - Identity is the LLDAP username.
  - Never name private repos, cloud profiles or account ids in code, docs or commits.
- **Secrets never on argv.** Secrets go through files and stdin only: `kubectl create secret … --from-file`, `kubectl apply -f -` and `kubectl exec -i` with stdin. `--from-literal`, `helm --set`/`--set-string` with any secret, and secrets in `kubectl exec -- sh -c '<text>'` are banned. The `tests/test_cli.sh` argv grep gains `--from-literal` and `--set` patterns (Task 11). The Hub puts instance env in a Secret (`envFrom`), never in pod specs.
- **Fail closed (each item gets a test in its task):**
  - `CONTAINER_RUNTIME=kubernetes` without `PORTCULLIS_KUBE_CONTEXT`, a context that doesn't exist, or a cluster that fails a † check (spec §6) → refused.
  - The NetworkPolicy probe not proven → no deploy (CLI) and every instance deploy refused (Hub, doctor `netpol_not_enforced`).
  - The admission self-test is not rejected **by the Portcullis policy** (ruling K6) → 503 on every runtime operation, doctor `admission_guard_missing`.
  - In-cluster config, namespace or Role verification fails → every runtime operation answers `503 the cluster is not verified: <why>`.
  - A detected pod/service CIDR or API endpoint differs from `.env` → refused, naming both values.
  - Dual-stack or IPv6-only cluster → refused (ruling K10).
  - A translation that can't be represented (name collision, object > 1 MiB, refused compose feature) → nothing is applied for that instance.
  - A VPN gateway pod with no observed IP (not Running+Ready) → its provider is left out of `vpn.json`, so the edge has no listener for its port and refuses until the Hub has seen the pod (K5; never an empty `gateway_ip`, which voids the document).
- **Trust is bound to how traffic arrived, never to an address or header alone.** Each of these is a dedicated container port whose NetworkPolicy admits exactly one peer:
  - Keycloak :8080 accepts only from Traefik pods, and internal clients reach it only through Traefik's `kcinternal` entrypoint, which strips the headers;
  - `vpnsecure` accepts only from the `wg` pod;
  - each `wg` edge port `9001+n` accepts only from pods labelled `portcullis.io/vpn-slot: "<n>"`;
  - a routed app port accepts only from Traefik;
  - a companion port accepts only from mcp-gate.

  CIDR settings (`--proxy-trusted-addresses`, `PROXYPROTOCOL_TRUSTEDIPS`, `_SOURCE`) are only the second layer.
- **Least privilege for anything internet-facing.** Traefik and `wg` each have their own NetworkPolicy and their own PVC (`traefik-acme`, `wg-data`), with `vpn-doc` mounted read-only in `wg`. Neither mounts `hub-data`. App pods get `automountServiceAccountToken: false` and the namespace's `default` ServiceAccount.
- **Applied-state caches commit only after success:**
  - the CLI's `secrets/kube/applied.json` (hashes of the synced Secrets/ConfigMaps and the VAP params) is written after `kubectl apply` **and** `helm upgrade --wait` succeed;
  - the Hub's per-instance applied render key is written after every object is applied **and** ready;
  - a delivered `.rev` counts only after the mounted copy matches;
  - a resolved digest is cached only after a successful deploy;
  - the probe "proven" flag lasts only for the process.
- **jq 1.8 precedence.** Every jq filter that binds `as $x` after a binary operator is parenthesised (`(A and B) as $x` written out). The kubernetes status and parse filters get a shell test on a fixture where the unparenthesised form would differ (Task 11).
- **Core compose lints stay green and are built in, not discovered.** This plan adds no compose service and no project bind, so `NBINDS` stays **46** (if a task adds one, it updates `docker-compose.podman-selinux.yml` and the count in the same commit). It keeps `lint_healthchecks.sh` (CMD-SHELL / tmpfs allowlist), `lint_images.sh` (fully qualified, pinned, now also over `charts/portcullis/images.yaml`), the `docker-compose.podman.yml` restart overlay and `tests/lint_ci_size.sh` (ci.yml ≤ **450 000** bytes). Every new CI step longer than 20 lines lives in `.github/ci/<job>-<step>.sh`.
- **The Podman quirks stay handled where they live** (Tasks 2 and 11 move code, not behaviour):
  - Hub docker backend: `ListNetworks` doesn't rely on `IPRange` in inspect; archive copies treat the tar root as `/`;
  - core `rt_*` docker branch: `runtime_build_local` keeps `--format docker` (HEALTHCHECK), also for K1 `local` builds; `stack_compose_up` (kcwait: every local image built first, one `up -d --no-build`, one more up after waiting `STACK_UP_WAIT` for a still-starting dependency) is the docker/podman `rt_up`, unchanged;
  - lessons that carry to Kubernetes: backup/restore helpers mount volumes at `/vol` (never at an image path, so no image content or owner leaks onto an empty volume, the `domains_data` incident) and **core PVCs never get K4 seed init containers**; timestamps from the API are UTC; every image ref (chart, `images.yaml`, `kube/**/*.yaml`, CLI constants) is fully qualified and pinned (`lint_images.sh` scans them).
- **TDD everywhere.** Write the failing test, see it fail, implement, see it pass, commit. Gates:
  - Core: `bash tests/test_shell_libs.sh && bash tests/test_cli.sh && shellcheck -S warning portcullis scripts/lib/*.sh tests/*.sh .github/ci/*.sh && actionlint && bash tests/lint_ci_size.sh`, plus `helm lint charts/portcullis && python3 tests/k8s_parity.py && python3 tests/k8s_netpol_matrix.py` from Task 13 on.
  - Hub: `go vet ./... && go test -race ./... && gofmt -l .` (gofmt prints nothing), plus `go test -tags envtest ./internal/runtime/kube/...` with `KUBEBUILDER_ASSETS` from `setup-envtest use 1.32.x` from Task 8 on.
  - Templates: `python3 tests/validate.py && python3 tests/test_validate.py`.
  - Docs: `python3 scripts/check-lists.py && bash scripts/check-branding.sh && zensical build --strict --clean`.
- **CI:**
  - Core: `gh workflow run ci.yml --ref kube1 -f jobs=<names>`, then one full run. Only the controller dispatches core CI on `kube1` (the concurrency group cancels). Task 16 adds `e2e-k3s` to the `workflow_dispatch` description list.
  - Hub: `gh workflow run build.yml --ref kube1`. Templates: lint.yml and Test Apps.
- **Merges** (spec order docs → Hub (Task 2 alone first) → templates → core):
  - Merge each repo through a detached worktree: `git worktree add --detach /tmp/merge-<repo> origin/main` → `git merge --no-ff <ref> -m "merge kube1: …"` → push → `git worktree remove`.
  - After each Hub merge, run `gh workflow run build.yml --ref main -f compare_ref=kube1` and wait for `edge`.
  - **The window.** After the second Hub merge, `edge` no longer copies `PORTCULLIS_TRAEFIK_IP` to instances. Templates main falls back to the Docker default form until templates `kube1` lands. So merge templates, then core, without a pause. Don't dispatch core CI on main and don't upgrade any server in that window.
  - After core main publishes the five core images (Task 12's `images.yml`) as `:edge`, do Task 10 (templates `kube2`).
  - At the end, delete every `kube1`/`kube2` branch (local and remote), every worktree, `/tmp/merge-*` and `/tmp/pk-*` (memory: branches mainlined).
- **Test servers:**
  - The Docker test server is upgraded in place: connect with the SSH command and install directory in `2026-11-13-rootless-podman.md` Global Constraints, then `git pull --ff-only && ./portcullis upgrade`.
  - The Kubernetes check runs on a **separate VM the user provides** (ruling K12). The plan never creates or edits cloud resources or firewalls.
  - `ACME_STAGING=true` on both servers (memory). Never touch the LLDAP `admin` user.
- **Values from the spec (verbatim):**
  - `.env`: `CONTAINER_RUNTIME=kubernetes` (set at `init`, never changed), `PORTCULLIS_KUBE_CONTEXT` (required, never the current context), `PORTCULLIS_NAMESPACE` (default `portcullis`), `PORTCULLIS_APPS_NAMESPACE` (default `portcullis-apps`), `PORTCULLIS_POD_CIDR` and `PORTCULLIS_SERVICE_CIDR` (detected at `init`, re-checked by `runtime_check`).
  - k3s ≥ **Kubernetes 1.32**, installed with `--disable=traefik --secrets-encryption --kubelet-arg=pod-max-pids=1024`, the network policy controller on and ServiceLB on. When the public IPv4 is a secondary local address of the node (not its InternalIP), the install line adds `--node-external-ip=<public IPv4>`, so that ServiceLB publishes it (Task 0 Q1).
  - Helm: `helm upgrade --install --wait --timeout 10m`. Down = scale every Deployment to 0, never `helm uninstall`. PVCs carry `helm.sh/resource-policy: keep`.
  - Labels `portcullis.io/instance`, `portcullis.io/service`, `portcullis.io/net-<network>`, `portcullis.io/egress`, `portcullis.io/helper` (set by the translator only; compose labels become annotations).
  - Names `<instance>-<service>`, truncated with `-<hash8>` past 63 characters. PVC `<instance>-<key>`. ConfigMap `tpl-<id>-<hash>`. Secret `<instance>-<key>-pw`.
  - StorageClasses `portcullis-core` (local-path, reclaim `Retain`) and `portcullis-apps` (RWO, reclaim `Delete`).
  - Traefik non-root uid **65532** on **:8000/:8443**, `LoadBalancer`, `externalTrafficPolicy: Local`. `kubernetesCRD` provider `namespaces: [portcullis, portcullis-apps]`, `allowCrossNamespace: false`, `allowExternalNameServices: false`, Ingress and Gateway providers off.
  - Keycloak `--proxy-trusted-addresses=$PORTCULLIS_POD_CIDR`. Internal clients use `http://keycloak-internal:8081` (entrypoint `kcinternal`, router middleware `strip-forwarded@file`).
  - `PORTCULLIS_TRAEFIK_SOURCE` / `PORTCULLIS_MCP_GATE_SOURCE`: `<ip>/32` on Docker/Podman, the pod CIDR on k8s.
  - `PORTCULLIS_TRAEFIK_SERVICE_IP` (the `traefik` Service's fixed `clusterIP`, used for `hostAliases`).
  - `HUB_CONTAINER_RUNTIME=kubernetes`, `HUB_SELF_IMAGE`, `PORTCULLIS_RUNTIME_ROOTS` (core.env).
  - Revocation is enforced within **10 s**. Kubelet `podPidsLimit` 1024 is the only hardening delta (hardening.md).
  - PSA: `portcullis` is `restricted` (enforce). `portcullis-apps` is `enforce: privileged`, `warn/audit: baseline`.
- **Values this plan adds (assistant's calls, binding):**
  - `.env` `PORTCULLIS_KUBE_API_ENDPOINTS`: the `default/kubernetes` EndpointSlice addresses:port, detected and re-checked like the CIDRs. Only the Hub and Traefik may reach them (egress `ipBlock` /32 per address).
  - `PORTCULLIS_TRAEFIK_SERVICE_IP` default: the service CIDR's network address + 20 (k3s default `10.43.0.20`). It must lie in the static band, the first `min(max(16, size/16), 256)` addresses.
  - The `kcinternal` entrypoint is `:8081`. `vpnsecure` on k8s is `:8444` (a container port of its own, separate from websecure's 8443).
  - Label `portcullis.io/component: <core service>` on core pods (the chart's selectors). Label `portcullis.io/vpn-slot: "<0–46>"` on a wired provider's ingress pod (Hub-set).
  - Every namespace selector uses `kubernetes.io/metadata.name` (set by the API server, can't be forged), never a custom namespace label.
  - Core-built images on k8s: `ghcr.io/porelli/portcullis-{group-gate,enroll,domains,mcp-gate,wg}` (ruling K1).
  - **Pins (Task 0, binding):**
    - k3s `v1.37.2+k3s1`, sha256 `265b3ee6a3198ef14033c63ef46cbb32370d83795199fb6d1b01f21575eddbda` (CI and the documented install); the floor `v1.32.13+k3s1`, sha256 `4aaf9825a92dc885856baab578f18e1881e8d381d42578bcbdabd5d7b7285865` (`init`/`runtime_check` refuse a server older than 1.32);
    - kubectl `v1.37.2`, sha256 `c04487523e7aa7d1493f7808174c899db93d7a9cf57531420cd76b9bd415f8f4` (CI);
    - `docker.io/rancher/local-path-provisioner:v0.0.37@sha256:e757967a5ec338f6a9b371c5a9688bedaa8c3578ea3dd4db329ea0084be0a86f`;
    - Traefik CRDs at the compose Traefik version (`v3.7.17`, K14).
  - **Fixed ClusterIPs** in the service CIDR's static band (network address + n; k3s defaults in brackets; `init` checks each is free and in the band):
    - `PORTCULLIS_TRAEFIK_SERVICE_IP` +20 (`10.43.0.20`): the `traefik` LoadBalancer, ports 80→8000 and 443→8443 **only** (hostAliases target);
    - `PORTCULLIS_TRAEFIK_VPN_SERVICE_IP` +21 (`10.43.0.21`): ClusterIP `traefik-vpn`, port 8444 → `vpnsecure` (wg's `WG_TRAEFIK`);
    - `PORTCULLIS_WG_EDGE_SERVICE_IP` +22 (`10.43.0.22`): ClusterIP `wg-edge`, ports 9001–9047 → the `wg` pod (the gateways' `PORTCULLIS_VPN_EDGE`).

    `kcinternal` (8081), `vpnsecure` (8444) and the edge ports are never ports of a LoadBalancer Service: ServiceLB publishes every port of one on the node (K-P26).
  - **The third namespace `portcullis-storage`** (K3): the provisioner and its helper pods only. PSA `enforce: baseline`, default-deny with egress to the API endpoints only, K11's label and annotation. Nothing else runs there.
  - **VPN reserved ranges on k8s:** `PORTCULLIS_VPN_RUNTIME_POOLS="$PORTCULLIS_POD_CIDR $PORTCULLIS_SERVICE_CIDR"` (K-P11).
  - **Entrypoint classes on k8s:** the six `.env` keys `PORTCULLIS_EP_{CORE,ADMIN,ENROL}` and `PORTCULLIS_WEB_{CORE,ADMIN,ENROL}` (written by `vpn mode`) become chart values `entrypoints.ep.{core,admin,enrol}` / `entrypoints.web.{core,admin,enrol}`, and Traefik keeps the `parked` entrypoint `127.0.0.1:8441` (K-P9).

## Plan rulings (assistant's calls beyond the spec, binding)

- **K1 — core-built images on k8s.**
  - The five images built locally on Docker (`group-gate`, `enroll`, `domains`/`dns-tool`, `mcp-gate`, `wg`) are published by core CI like the forwarder: new `.github/workflows/images.yml`, `:edge` from main, `:X.Y.Z` at release, cosign keyless, no `latest`.
  - The CLI resolves every tag (these five, Hub, Keycloak) to a digest at `up`/`upgrade`, and the chart only ever sees `name@sha256:…`.
  - `.env` `PORTCULLIS_KUBE_IMAGES=registry|local` (default `registry`). `local` builds them from the checkout with `docker build` or `podman build --format docker` and imports them with `sudo k3s ctr -n k8s.io images import` under `localhost/portcullis-<svc>@sha256` with `imagePullPolicy: Never`. CI and development use it; `status` shows it.
  - Why: k3s has no builder, and a pinned registry digest keeps "fully qualified pinned images" true.
- **K2 — the Hub's Role.** The spec's list plus `create` on `pods`, which helper pods need. Exec: **`create` on `pods/exec` only, never `get`** (Task 0 Q3: `create` alone works on 1.32 and 1.37, kubectl and client-go, WebSocket and SPDY; on 1.32 `get` alone even opens a WebSocket exec, so granting it would widen the Role). `TestRoleExact` treats `get` on `pods/exec` as an extra verb. Nothing cluster-scoped. Core keeps the Role YAML in the chart, and the Hub keeps a byte copy in `internal/runtime/kube/testdata/role.yaml`, compared in core CI.
- **K3 — volume ownership: mechanism (a) native (decided by Task 0 Q2).**
  - Both StorageClasses (`portcullis-core`, `portcullis-apps`) use provisioner `portcullis.io/local-path` with the v0.0.37 parameters `userPattern: '{{ index .PVC.Annotations "portcullis.io/uid" }}'`, `groupPattern: '{{ index .PVC.Annotations "portcullis.io/gid" }}'` and `permPattern: '{{ index .PVC.Annotations "portcullis.io/mode" }}'`. The `setup` script reads `VOL_USER`/`VOL_GROUP`/`VOL_PERM`, checks each (uid/gid 1–65535 integers, mode 3–4 octal digits), runs `mkdir -m` + `chown`, and **refuses** (non-zero exit, `portcullis-setup REFUSED: <why>` in the log) on any missing or bad value, so the PVC stays `Pending` (fail closed; the provisioner retries until its 120 s create timeout, then `ProvisioningFailed`).
  - Core PVCs carry the `CT_*` values as those three annotations (chart); the Hub's translator sets them on app PVCs from the service's numeric `user:` (mode `0750`; the K4 CI leg records where Docker's copy-up gives another owner or mode).
  - The provisioner runs in `portcullis-storage` with `--service-account-name <its SA>` (required when the SA isn't upstream's name). Its helper pod template runs the pinned `PORTCULLIS_HELPER_IMAGE` as uid 0 with `CapEff` = CHOWN, DAC_OVERRIDE, FOWNER only: the provisioner refuses `capabilities.add` without `--allow-unsafe-helper-pod-template`, so the template drops the other 11 default caps by name, with no-new-privileges, `RuntimeDefault` seccomp and a read-only root.
  - Not proven by the spike, so pinned by tests: 4-digit setgid modes (`2750` on `vpn-doc` and `wg-data`, from `volume_own`) — a Task 14 shell test on `setup.sh` and an e2e-k3s `stat` assertion.
  - No fallback is taken: no chown init container in `portcullis-apps`, no chown helper in `portcullis`. `fsGroup` is no substitute (the spike measured `0:10001:2775`).
- **K4 — Docker volume copy-up.** Docker copies image content into a new named volume, and PVCs don't. For each named volume, the translator adds two init containers:
  - `portcullis-bin`: the Hub image by digest; it copies the static `/usr/local/bin/hub` into an `emptyDir`;
  - `portcullis-seed`: the service's own image and user; it runs `/portcullis-bin/hub seed <target> /portcullis-seed`, which copies the image's directory into the PVC only when the PVC is empty and writes `.portcullis-seeded` last.

  No shell is needed in the app image. Ownership is the service's uid, and the CI leg flags any template where Docker's copy-up gives a different owner. `portcullis-bin` is also added to every app pod that mounts a ConfigMap/Secret delivery, so the `.rev` poll runs `/portcullis-bin/hub rev <mount>` without needing `cat` in the image (Task 5). Core PVCs never get either init container.
- **K5 — the VPN gateway address on k8s.** `vpn.json` v2 is unchanged (format, bounds and readers). The Hub watches the ingress pod of each wired provider and writes its current pod IP as `gateway_ip`. Until it has seen a Running+Ready pod with an IP, the provider is **not published** at all, so the edge refuses its port (pre-flight K-P7: the original "write an empty `gateway_ip`" would void the whole document, because `vpn.Parse` and wg's and group-gate's readers refuse a non-IPv4 `gateway_ip`). The gateway dials the edge at `PORTCULLIS_VPN_EDGE` = `<PORTCULLIS_WG_EDGE_SERVICE_IP>:<9001+n>` (ClusterIP `wg-edge`; pod → ClusterIP keeps the pod source address, asserted live in e2e-k3s). `vpn.GatewayAddr` (the `.16 + n` pins) and the `PORTCULLIS_VPN_WG_IP` check (`vpnWGIPOK`) are docker/podman only. The chart has one static ingress rule per edge port `9001+n` on the `wg` pod, from `portcullis-apps` pods labelled `portcullis.io/vpn-slot: "<n>"`. The VAP admits that label only as an integer 0–46 (the spike's `matches` rule refuses `"47"`), and only on a pod that also carries `portcullis.io/instance`. The per-pod binding is the edge's `gateway_ip` match: the Hub can't write in `portcullis`, so there is no per-slot params object.
- **K6 — admission self-test.** The Hub dry-runs (`dryRun=All`, server side) a forbidden Pod **and** a forbidden Deployment in `portcullis-apps`. A `ValidatingAdmissionPolicyBinding` binds exactly one policy (Task 0 Q4), so **each of the five policies has its own binding `portcullis-apps-guard-<policy>`** (`-pods`, `-workloads`, `-services`, `-traefik`, `-netpol`), each with `paramRef` → ConfigMap `portcullis-admission-params` (`parameterNotFoundAction: Deny`), `validationActions: [Deny]`, `failurePolicy: Fail`. The test passes only when each dry-run is rejected with an `Invalid`/`Forbidden` **Status whose `message`** contains `with binding 'portcullis-apps-guard-` (the API server's form: `ValidatingAdmissionPolicy '<p>' with binding '<b>' denied request: …`). The Hub reads the Status, never the response's `Warning:` headers: on `portcullis-apps` PSA `warn: baseline` adds `would violate PodSecurity…` warnings before the denial. A rejection by RBAC, quota or another webhook counts as "guard missing". The `pods` and `workloads` policies match `pods` and `deployments`/`jobs` (pod templates at `spec.template.spec` through `variables`, as in the spike), so the Deployment dry-run reaches them.
- **K7 — `wg` on k8s.**
  - One Deployment, `Recreate`, uid 10006 (+ supplemental group 10007), PSA restricted, netstack (no caps). Rendered only when `wg.enabled` (= `wg` in `COMPOSE_PROFILES`, as on Docker).
  - **One pod IP for every role:** wg today refuses `WG_EDGE_ADDR == WG_VPN_ADDR` and metrics on either, because on Docker each sits on its own network. On k8s isolation is the NetworkPolicy, so Task 13 adds `WG_ADDR_MODE=pod` to wg: `WG_VPN_ADDR` = `WG_EDGE_ADDR` = the pod IP (Downward API `status.podIP`), metrics on `<pod IP>:9100`; `docker` (the default) keeps today's checks byte for byte.
  - `WG_TRAEFIK` = `<PORTCULLIS_TRAEFIK_VPN_SERVICE_IP>:8444` (ClusterIP `traefik-vpn`).
  - The people UDP port is a LoadBalancer Service `wg-people` (ETP `Local`, `${PORTCULLIS_VPN_PORT:-51820}/udp`).
  - Edge ports are on the pod IP behind `wg-edge`: its own policy, its own `wg-data` PVC, `vpn-doc` read-only, no `hub-data`, the people key as a Secret file.
  - `portcullis-vpn-edge` becomes the policy "`wg` → Traefik :8444 only", and `vpnsecure`'s `PROXYPROTOCOL_TRUSTEDIPS` = the pod CIDR (second layer). `portcullis-metrics-wg` becomes "Prometheus → `wg` :9100 only" (Service `wg-metrics`). `wg-egress` becomes the label `portcullis.io/egress` on `wg` (resolver upstreams) plus `wg-people`.
  - Edge caps: the chart passes the five `WG_EDGE_*` from the `.env` keys `PORTCULLIS_VPN_EDGE_MAX_PER_PROVIDER`/`_PER_USER`/`_PER_CLIENT`/`_PRESSURE_PERCENT`/`_PRESSURE_IDLE` with the contract §16 defaults (1024/128/32/90/`2m`); wg's own start check (client ≤ person ≤ provider) is unchanged, and the parity test compares the env keys.
  - **No link objects:** the multi-server plan adds the `wg-link` Service and its policy.
  - The kube API is never reachable through `wg`.
- **K8 — `:6443`/`:10250` on the public address.** `status` warns when either answers on the node's external address ("restrict it in the firewall"). It is never a refusal: firewalls are the user's.
- **K9 — `_SOURCE` consumers.** Task 9 Step 1 lists every one of the 84 template files and the setting each one feeds. A setting that can't take a CIDR gets the existing nginx gate pattern (esphome `gate.sh`) in front, never a wider rule.
- **K10 — IPv4 single-stack only.** `init`/`runtime_check` refuse a cluster whose pod or service CIDR list has an IPv6 entry.
- **K11 — ownership.** `init --runtime kubernetes` refuses to adopt an existing `portcullis`, `portcullis-apps` or `portcullis-storage` namespace unless it has the label `app.kubernetes.io/managed-by: portcullis` and the annotation `portcullis.io/install: <uuid>` equal to `.env` `PORTCULLIS_KUBE_INSTALL_ID` (generated at init).
- **K12 — the Kubernetes test VM** is provided by the user (SSH details given at Task 18). The Docker test server is not converted. Its fresh backup is copied to the VM by the operator (scp, 0600) for the cross-runtime restore.
- **K13 — VAP and Role vectors are authored in the Hub** (`internal/runtime/kube/testdata/admission/*.yaml`, `role.yaml`, `admission_vectors.json`). Core keeps byte copies under `kube/admission/` and checks them in unit-tests against the same-named Hub branch, like the `vpn.json` vectors.
- **K14 — Traefik CRDs.** The pinned Traefik CRD bundle (`charts/portcullis/crds/traefik-<version>.yaml`) is applied by `init`/`upgrade` with `kubectl apply --server-side`, never by Helm. Its version follows the compose Traefik image, and the parity test checks it.
- **K15 — core services and middlewares that app routers name.** The Hub renders app routers whose *service* is core's (`group-gate@docker` for `/vpn-required`, `forward-auth-ext@docker` for sign-in routers, `mcp-gate@docker` for MCP routers) and whose chains name core `@docker` middlewares (`portcullis-auth`, `portcullis-auth-ext`, `portcullis-groups`, `portcullis-groups-vpn`, `portcullis-public-guard`, `portcullis-public-guard-vpn`, `vpn-required-path`). With `allowCrossNamespace: false` an IngressRoute in `portcullis-apps` can't reach a Service in `portcullis`, so on k8s these live in the **file provider** (ConfigMap `traefik-dynamic`): the middlewares as `<name>@file`, and the three services as file-provider services `group-gate@file`, `forward-auth-ext@file`, `mcp-gate@file` whose servers are the core Services' cluster DNS names. The translator maps exactly these `@docker` names to `@file` (services as `kind: TraefikService` refs), the VAP allows exactly these names plus the six `middlewares.yml` ones (the `fileMiddlewares` param), and anything else `@docker` that isn't the instance's own is refused. `hub-proxy-secret` and `portcullis-auth-console` stay core-only CRDs in `portcullis` (never on the app list). `strip-forwarded` (kcinternal) is chart-only and never on the app list.
- **K16 — CLI one-shots on k8s** (core uses more than the spec's `rt_*` list: `dc run` one-shots, `dc stop/start`, `container_health`, `ct_run` throwaways, `docker volume …`, restic, the lldap-ui forwarder). On kubernetes:
  - `rt_run <svc> [-i] -- <argv…>` = a one-shot pod built from the chart's spec for `<svc>` (`helm template --show-only` of a `oneshot` template: same image digest, user, caps, labels and volumes, `restartPolicy: Never`), attached with `kubectl run --rm -i --overrides=-` or create + `exec -i` + delete; secrets only on stdin. Users: `dns-tool` (credentials on stdin), `hub signin reset-core` (Hub scaled to 0 first, as `dc stop hub` today).
  - `rt_stop <svc>` / `rt_start <svc>` = scale to 0 / 1 and wait. `rt_health <svc>` = `healthy|unhealthy|starting|running|exited|missing` from the pod's Ready/started/restart state (the `container_health` vocabulary).
  - `vpn_genkey`: no throwaway container; with `wg.enabled` and an empty key Secret the edge role runs alone, so `vpn init` runs `rt_exec wg -- /wg keypair`, keeps the pair in shell variables, writes only the private key (jq from a variable, never argv) to `secrets/wg/people.key` (0640), then syncs and `rt_restart wg`.
  - Restore throwaways (`docker run` of postgres for the federation-count guard, volume loads, the `acme.json` reset in `config.sh`) become owner-uid helper pods in `portcullis` (restricted: no hostPath, data over exec stdin/stdout).
  - Offsite `restic` uses the **host `restic` binary** on kubernetes (version ≥ the pinned image's 0.19.1, checked by `kube_host_checks` only when offsite is configured); `lldap-ui` uses `kube_port_forward lldap 17170`.
- **K17 — probe start periods.** compose `start_period` maps to a **`startupProbe`** (the same exec, `periodSeconds` = interval, `failureThreshold` = ceil(start_period / interval) + retries), and readiness/liveness get no `initialDelaySeconds`. Mapping it to `initialDelaySeconds` would hold every pod unready for its whole start period (Keycloak's is 300 s since kcwait). Chart and translator use the same mapping (parity).

## VPN, kcwait and Podman on Kubernetes (what changed on main, and its k8s form)

| On main (Docker/Podman) | Kubernetes | Where |
|---|---|---|
| `wg` service (compose profile `wg`, uid 10006 + group 10007, read-only, no caps) | Deployment `wg` when `wg.enabled` (from `COMPOSE_PROFILES`), K7; `WG_ADDR_MODE=pod` | Tasks 13, 15 |
| `vpn_doc` volume (Hub rw, `wg` + group-gate ro, `10001:10007` 2750) | PVC `vpn-doc` (`portcullis-core`, annotations uid 10001 / gid 10007 / mode 2750), same mounts | Tasks 13, 14 |
| `wg_data` (`10006:10001` 2750, Hub ro) | PVC `wg-data`, same | Task 13 |
| `portcullis-vpn` network, gateways pinned `.16`–`.62`, `PORTCULLIS_VPN_EDGE=<wg ip>:<port>` | ClusterIP `wg-edge` (fixed IP), per-slot ingress rules on 9001+n, `gateway_ip` = live pod IP (K5) | Tasks 7, 13 |
| `portcullis-vpn-edge` (wg ⇄ Traefik only, PROXY trusted from wg's `.67`) | policy `wg` → Traefik :8444 only; ClusterIP `traefik-vpn`; `PROXYPROTOCOL_TRUSTEDIPS` = pod CIDR (second layer) | Task 13 |
| `wg-egress`, `portcullis-metrics-wg` | `portcullis.io/egress` on `wg` + `wg-people` LB; policy Prometheus → wg :9100 | Task 13 |
| `strip-client-forwarded@file` on websecure and vpnsecure (entrypoint middlewares) | the same entrypoint middlewares on `websecure`, `vpnsecure` **and** `kcinternal`, plus `aliasHeadersStrategy: delete` on each | Task 13 |
| policy file v7, `vpn.json` v2 | unchanged (no format change on k8s) | — |
| `-vpn` core routers, `PORTCULLIS_EP_*`/`PORTCULLIS_WEB_*`, `parked` entrypoint | chart IngressRoutes per router with entrypoints from `entrypoints.*` values; `parked` = `127.0.0.1:8441`; `vpn mode` = write `.env` + `rt_up` | Tasks 13, 15 |
| Hub-rendered app `-vpn`/VPN-only routers (`portcullis-vpnallow-<id>`, `vpn-required-path`, `group-gate@docker`) | IngressRoutes + own Middlewares; core names through `@file` (K15) | Task 7 |
| reserved ranges (`WG_CORE_SUBNETS`, `GATE_CORE_SUBNETS`, `PORTCULLIS_VPN_RESERVED_RANGES`, + Podman pools) | `PORTCULLIS_VPN_RUNTIME_POOLS` = pod + service CIDR; `vpn init`'s overlap check uses them and the node IPs instead of the Docker subnets; the Hub's overlap guard gets them as `Info.Networks` | Tasks 2, 7, 11, 15 |
| edge caps `PORTCULLIS_VPN_EDGE_*` → `WG_EDGE_*` | chart env, same keys and defaults | Task 13 |
| `hub vpn …` over `/tmp/hub-host.sock` (`dc exec -u 10001 hub hub vpn`) | `rt_exec hub -- hub vpn …` (the container already runs as 10001; k8s exec has no `-u`) | Task 11 |
| `vpn init` key generation (throwaway `wg genkey` container) | `rt_exec wg -- /wg keypair` (K16) | Task 15 |
| headscale-style marketplace providers (gateway allowlist, `vpn2`) | unchanged rules; the gateway pod gets `portcullis.io/vpn-slot` and the egress rule to `wg-edge` | Tasks 3, 7 |
| `link` role (multi-server) | **not on Kubernetes yet** (multi-server plan) | — |
| VPN-only access to the **Kubernetes API** | **not on Kubernetes yet**: K8 warns only | — |
| `vpn_down` steps / break-glass `vpn mode apps` with the Hub down | the same: group-gate's mode is its env (chart value from `PORTCULLIS_VPN_MODE`), so `vpn mode apps` + `rt_up` works with the Hub at 0 | Task 15 |
| kcwait `stack_compose_up` (build first, `up --no-build`, `STACK_UP_WAIT` retry, `compose_health_report`) | docker branch unchanged; k8s `rt_up` builds+imports K1 `local` images first, then `helm --wait --timeout 10m`, and on failure `kube_health_report` (unready pods, restart counts, last 3 events each; never a secret) | Tasks 11, 15 |
| kcwait Keycloak `start_period: 300s` | `startupProbe` (K17) | Tasks 4, 13 |
| Podman lessons (see Global Constraints) | `/vol` mounts, no seeding of core PVCs, UTC, qualified images | Tasks 6, 12, 15 |

## Review Focus

1. **The admission guard passes its self-test for the wrong reason.** On a cluster where the VAPs are missing but RBAC, a quota or a foreign webhook rejects the probe, the Hub must still report `admission_guard_missing` and refuse deploys. Pinned by `TestSelfTestRequiresPolicyRejection` (Task 8, envtest with the VAPs absent and a deny-all webhook).
2. **Compose names that aren't DNS-1123.** Service names like `my_db` and `my-db` (or `My-DB`), or an instance + service longer than 63 characters, must not collide after normalisation or truncation. The instance is refused with both names, and no object is applied. Pinned by `TestTranslateNameCollisionRefused` (Task 4).
3. **An object over the 1 MiB API limit.** A template directory, an appfile or a `*-pw` Secret for a large group past 1 MiB must be refused with a named reason before anything is applied. Pinned by `TestTranslateObjectTooLargeRefused` (Task 4) and `TestPersonSecretTooLargeRefuses` (Task 5).
4. **A wired VPN gateway pod is rescheduled and gets a new IP.** The edge must refuse the old IP at once and admit only after the Hub has published the new one, with no window where any address is accepted. While no Ready pod is seen the provider is left out of `vpn.json` (an empty `gateway_ip` would invalidate the whole document: `vpn.Parse` refuses it). Pinned by `TestGatewayIPFollowsPod` (Task 7) and the live e2e-k3s check (Task 16).
5. **The kube context points at a cluster with leftover or foreign Portcullis namespaces** (an old install, another operator's). `init` must refuse to adopt them unless the install id matches. Pinned by the shell test "init kubernetes: foreign portcullis namespace → refused" (Task 11).
6. **One pod IP for every `wg` role** (K7 `WG_ADDR_MODE=pod`). On Docker, edge, metrics and Traefik-side addresses are separate networks; on k8s only NetworkPolicies separate them. An app pod must not reach `wg` :9100 or any edge port but its own slot's, and nothing but `wg` may reach Traefik :8444. Pinned by `k8s_netpol_matrix.py` (Task 13) and e2e-k3s (Task 16).

---

## File structure

**Docs (`wt-kube1/portcullis-docs`):** `docs/guides/integration-contracts.md`; `docs/operations/kubernetes.md` (new) + `.nav.yml`; `hardening.md`, `backups.md`, `cli.md`, `testing.md`, `hub.md`, `vpn.md`, `rootless-podman.md` (cross-links); `includes/abbreviations.md`.

**Hub (`wt-kube1/portcullis-hub`)**

| File | Responsibility |
|---|---|
| `internal/runtime/runtime.go`, `types.go` (new) | `Instances`, `Kind`, neutral types |
| `internal/runtime/docker/backend.go` (new; wraps `compose.Runner` + `docker` client) | the docker backend (Docker and Podman), moved code |
| `internal/runtime/kube/{translate.go,names.go,objects.go,apply.go,backend.go,status.go,exec.go,deliver.go,helpers.go,ingress.go,netpol.go,guard.go,digest.go}` + `testdata/` (new) | the kube backend |
| `internal/templates/runtimecompat.go` (renamed from `rootless.go`), `testdata/runtime_vectors.json` | `RuntimeCompat` |
| `internal/hub/*.go` (24 files using `h.engine` / `h.compose`) | switch to `h.rt runtime.Instances` |
| `internal/hub/vpn_publish.go`, `doctor_runtime.go` (new) | K5 gateway IPs; the k8s doctor kinds |
| `cmd/hub/main.go`, `cmd/hub/helper.go` (new: `hub helper idle`, `hub volcopy`, `hub seed`) | wiring, helper subcommands |
| `web/index.html`, `web/apps.js` | runtime badge, compat column |

**Templates (`wt-kube1/portcullis-templates`):** the 84 `_SOURCE` files, `*/gate.sh` CIDR checks, `tests/validate.py`, `tests/test_validate.py`, `tests/runtime_vectors.json` (byte copy), `CONTRIBUTING.md`, `CLAUDE.md`; on `kube2`: `.github/workflows/test-apps.yml`, `tests/apps/lib-k3s.sh`.

**Core (`wt-kube1/portcullis`)**

| File | Responsibility |
|---|---|
| `scripts/lib/runtime.sh`, `scripts/lib/kube.sh` (new), every `scripts/lib/*.sh` with `dc`/`docker` | `rt_*` verbs, the kubernetes runtime, checks, probe |
| `charts/portcullis/` (new: `Chart.yaml`, `values.yaml`, `images.yaml`, `crds/`, `templates/*.yaml`) | the chart |
| `kube/admission/*.yaml`, `kube/storage/*.yaml`, `kube/probe/*.yaml` (new) | VAPs + params, StorageClasses + provisioner, probe pods |
| `tests/k8s_parity.py`, `tests/k8s_netpol_matrix.py`, `tests/k8s_hardening.py`, `scripts/gen-images-yaml.py` (new) | static checks |
| `.github/workflows/{ci.yml,images.yml (new),release.yml}`, `.github/ci/e2e-k3s-*.sh`, `.github/ci/unit-tests-kube-static.sh` (new) | CI |
| `tests/e2e/e2e_k3s.py` (new) | the e2e assertions |

---

### Task 0: Spike (done 2026-11-13)

**Status: done.** Run on a throwaway core branch `kspike` (deleted) with one push-triggered workflow on `ubuntu-26.04` (kernel 7.0, k3s's containerd 2.1), no actions, every download pinned. Legs: `v1.32.13+k3s1`, `v1.37.2+k3s1`, and `v1.37.2+k3s1` with `--node-external-ip=198.51.100.1`, all with the Global Constraints k3s flags. Final all-green run: https://github.com/porelli/portcullis/actions/runs/43463450694 (earlier runs 43460777928 — coredns wait — and 43460959847 — the provisioner needed `--service-account-name`, and two Q4 vectors were misjudged because the PSA warning pushed the message past the cut). Full report: `.superpowers/sdd/2026-11-14-kubernetes/k8s-spike-report.md`. No spike file is left on any branch, so no cleanup commit is owed.

**Evidence → where it is folded in:**
- **Q1 source IP (→ Global Constraints k3s values, Tasks 11, 16, 17):** ServiceLB ETP `Local` keeps the client IP (`ClientHost` = `198.51.100.2`) when the client targets an address in `status.loadBalancer.ingress`. A second local address that isn't one goes through klipper's hostPort DNAT and is SNATed to the svclb pod (`10.42.0.x`); the ETP `Cluster` control is SNATed too. With `--node-external-ip=198.51.100.1` that address becomes an ingress address and keeps the IP. **No hostNetwork fallback, no `portcullis-edge` namespace.**
- **Q2 volume ownership (→ K3, Tasks 13, 14):** (a) pathPattern-encoded, (a) native `userPattern`/`groupPattern`/`permPattern` and (b) a name table all gave `10001:10001:750` on both versions; `fsGroup` gave `0:10001:2775` (not a substitute). Missing or partial annotations and a missing table row leave the PVC `Pending` (`portcullis-setup REFUSED: …`). The only root process is the provisioner's helper pod in its own namespace (`CapEff 0xb` = CHOWN, DAC_OVERRIDE, FOWNER). **Chosen: (a) native.**
- **Q3 exec verbs (→ K2, Task 8):** `create` on `pods/exec` is enough on 1.32 and 1.37 for kubectl and client-go, WebSocket and SPDY. `get` alone opens a WebSocket exec on 1.32. **`create` only, never `get`.**
- **Q4 CEL on 1.32 (→ K6, Tasks 8, 14):** `in`, `matches`, `all`, `exists`, `startsWith`, `params`, `split`, `string()`, `size`, `messageExpression` and the IP/CIDR library (`isCIDR`, `cidr().containsCIDR`) all type-check (`status.typeChecking: {}`) and deny on 1.32 and 1.37, for Pods, Deployments and Jobs. **Floor stays 1.32.** Corrections: one binding per policy (K6); read the Status message, not the PSA warnings.
- **Pins (→ Global Constraints "Pins"):** k3s `v1.37.2+k3s1` sha256 `265b3ee6…eddbda`, floor `v1.32.13+k3s1` sha256 `4aaf9825…7285865`, kubectl `v1.37.2`, local-path-provisioner `v0.0.37@sha256:e757967a…be0a86f`.

---

### Task 1: Contract (docs, first)

**Files:**
- Modify: `docs/guides/integration-contracts.md`: §1, §2, §3, §5, §6, §11 (incl. §11.10), §13.6–§13.8, §13.15, §14.5, §16
- Modify (Hub): `web/docs/*` via `sync.sh`

Setup first: create the four `kube1` worktrees (Global Constraints "Branches and worktrees") from `origin/main`; the mains at amendment are core `791a7436d9a7`, Hub `398361dfc33d`, templates `37350f43277b`, docs `0dbf043769da` (record the actual base SHAs in the commit message).

**Interfaces — Produces (binding for Tasks 2–17):**
- **§1:** a "Kubernetes (NEW)" entry in the style of the VPN one: no policy-file or `vpn.json` version change (policy file stays **v7**, `vpn.json` **v2**); the `_SOURCE` switch is breaking for templates together with the Hub (merge order docs → Hub → templates → core, the window in Global Constraints).
- **§2:**
  - `PORTCULLIS_TRAEFIK_SOURCE` is the CIDR of the only peers that may send identity headers. Default form `${PORTCULLIS_TRAEFIK_SOURCE:-172.31.250.2/32}`, always combined with "only that peer can connect".
  - `PORTCULLIS_MCP_GATE_SOURCE` uses the default form `${PORTCULLIS_MCP_GATE_SOURCE:-172.31.250.3/32}`.
  - Both reach instances like every core variable a template references: core writes them into the Hub's `core.env` (`HUB_ENV_VARS`, `hub_env_write`: `<PORTCULLIS_TRAEFIK_IP>/32` and `<PORTCULLIS_MCP_GATE_IP>/32` on Docker/Podman, `PORTCULLIS_POD_CIDR` on k8s), and the Hub copies them (its `aiEnvLocked` writes `PORTCULLIS_MCP_GATE_SOURCE` instead of today's `_IP`).
  - `PORTCULLIS_TRAEFIK_IP` and `PORTCULLIS_MCP_GATE_IP` leave the template table (still core variables, refused in templates; the Hub stops copying them, like `PORTCULLIS_UNPRIVILEGED_PORT_START`).
  - `PORTCULLIS_RUNTIME_ROOTS` and `PORTCULLIS_KUBE_*` are core.env-only, not template variables.
- **§3 "Compose on Kubernetes":** the refused features with their reasons (the Task 3 strings); `…@docker` middleware names are translated to `…@file`; replicas > 1, `deploy:` and non-numeric `user:` are refused; the K4 seed init containers.
- **§5:**
  - IngressRoutes, one per router; the `@file` names apps may use on k8s (K15): `middlewares.yml`'s six (`client-headers`, `client-cert-pem`, `rate-limit`, `rate-limit-auth`, `security-headers`, `strip-client-forwarded`) plus core's `portcullis-auth`, `portcullis-auth-ext`, `portcullis-groups`, `portcullis-groups-vpn`, `portcullis-public-guard`, `portcullis-public-guard-vpn`, `vpn-required-path`, and the services `group-gate@file`, `forward-auth-ext@file`, `mcp-gate@file`;
  - entrypoints on k8s: `web :8000`, `websecure :8443`, `kcinternal :8081`, `vpnsecure :8444`, `parked 127.0.0.1:8441`; `strip-client-forwarded@file` and `aliasHeadersStrategy: delete` on websecure, vpnsecure and kcinternal; the core routers' entrypoints follow the six `PORTCULLIS_EP_*`/`PORTCULLIS_WEB_*` classes as on Docker;
  - `kcinternal` (`:8081`, router middleware `strip-forwarded@file`, chart-only, removes `X-Forwarded-*`, `Forwarded`, `X-Real-Ip`, `X-Forwarded-Tls-Client-Cert*`);
  - routed ports open only to Traefik.
- **§6 "Engine access":** a Kubernetes subsection containing:
  - the Role table (K2; `create` on `pods/exec`, never `get`);
  - "nothing in `portcullis`";
  - helper pods (`hub helper idle`, `hub volcopy out|in <path>`, `hub folderfix <mode>` over exec; label `portcullis.io/helper`; image = `HUB_SELF_IMAGE`; caps per mode unchanged);
  - `*-pw` Secrets replace the `hub_secrets` subpath (exactly one instance+option's `<user>.nt` keys, mounted read-only);
  - the admission self-test (K6: five bindings `portcullis-apps-guard-<policy>`, the Status message names the binding) and its 503.
- **§11:**
  - object naming (Global Constraints) and PVCs;
  - the backup format is unchanged (container ids in tarballs);
  - §11.10 becomes "Runtime compatibility". `GET /api/runtime` keeps its fields: `runtime` = `kubernetes`, `engine` = `Kubernetes`, `engine_version` = the server's `gitVersion`, `verified`/`mismatch` from the guard; it adds `context`, `admission` (`ok|missing|unknown`) and `netpol` (`proven|unproven`); `uid_map`/`gid_map`/`unprivileged_port_start` are `null` on k8s. The views' `rootless: {status, reasons}` becomes `compat: {runtime, status, reasons}` on podman **and** kubernetes (absent under Docker; no alias).
- **§13.6–13.8:**
  - ConfigMap/Secret deliveries carry a `.rev` key;
  - the Hub bumps the pod annotation `portcullis.io/rev` and waits for the mounted `.rev` before running hooks;
  - reload = exec `kill -s <SIG> 1`, and with no `kill` in the image a pod restart (state `reload_degraded`).
- **§13.15:** `lan_only` → `loadBalancerSourceRanges` = Local networks.
- **§14.5:** new kinds `netpol_not_enforced` (Problem), `admission_guard_missing` (Problem), `cluster_unverified` (Problem), `reload_degraded` (Info) and `kube_api_public` (Warning, K8). Forbidden roots come from `PORTCULLIS_RUNTIME_ROOTS`.
- **§16 "On Kubernetes":** K5 (`gateway_ip` = the live pod IP; a provider whose gateway pod isn't Ready with an IP is not published), K7 (one pod IP, `WG_ADDR_MODE=pod`, `wg-edge`/`traefik-vpn`/`wg-people`/`wg-metrics` Services, the edge caps unchanged), the per-slot edge policy and the label `portcullis.io/vpn-slot`, the reserved ranges on k8s (pod + service CIDR), `PORTCULLIS_VPN_EDGE` = `<wg-edge IP>:<port>`, `vpn init` key generation through `wg keypair`. The `link` role and VPN-only access to the Kubernetes API: **not on Kubernetes yet**. `vpn.json` stays v2.

- [ ] **Step 1:** Write the sections in the contract's style ("NEW (Kubernetes)" markers).
- [ ] **Step 2:** Run the docs gate. Expected: exit 0.
- [ ] **Step 3:** Commit (`docs: contract for Kubernetes (_SOURCE variables, compose on k8s, IngressRoutes + kcinternal, the Hub's Role and helper pods, *-pw Secrets, .rev deliveries, runtime compat, doctor kinds, wg on k8s)`) with the base SHAs, then push `kube1`.
- [ ] **Step 4:** Resync Hub `web/docs` (only `integration-contracts.md` changes), commit (`docs: sync contract`) and push.

---

### Task 2: Hub `internal/runtime` and the docker backend (no behaviour change, merged alone)

**Files:**
- Create: `internal/runtime/runtime.go`, `internal/runtime/types.go`, `internal/runtime/docker/backend.go`, `internal/runtime/docker/backend_test.go`, `internal/runtime/runtimetest/fake.go`
- Modify: `internal/hub/hub.go` (`New(cfg, rt runtime.Instances, idp)`; drop `Engine` and the `compose`/`engine` fields), the **26** non-test `internal/hub` files with `h.engine.*` / `h.compose.*` at Hub `398361d` (`grep -lE 'h\.(engine|compose)\.' internal/hub/*.go | grep -v _test`; VPN added `doctor_vpn.go`, `vpn_admin.go`, `vpn_providers.go`, `vpn_reach.go`), every `internal/hub/*_test.go` fake (to `runtimetest.Fake`), `cmd/hub/main.go`, `CLAUDE.md`

**Interfaces — Produces:**

```go
package runtime
type Kind string // "docker" | "podman" | "kubernetes"
type Project struct{ Name, Instance string; Files compose.Project; Model *types.Project } // Model: interpolated, profiles applied (the Hub's existing loader)
type Filter struct{ Instance, Service string; Helper bool; All bool }
type Instances interface {
	Kind() Kind
	Env() []string // the environment the project is interpolated with (today compose.Runner.Env: PassedEnv only)
	Info(ctx context.Context) (Info, error) // Info{Kind; Verified bool; Why string; ForbiddenRoots []string; APIVersion string; SELinux bool; IDMapped bool; Networks []Network}
	Create(ctx context.Context, p Project) error
	Up(ctx context.Context, p Project, onPull func(svc string, done, total int64, sized bool)) error
	Down(ctx context.Context, p Project) error
	DownByName(ctx context.Context, name string) error
	List(ctx context.Context, f Filter) ([]Unit, error) // Unit{ID, Instance, Service, Image string; State State; Labels map[string]string}
	Logs(ctx context.Context, id string, tail int, ts bool) ([]byte, error)
	Exec(ctx context.Context, id string, in ExecInput) (*ExecResult, error)
	ExecSplit(ctx context.Context, id string, in ExecInput) (*ExecSplitResult, error)
	ExecRunning(ctx context.Context, execID string) (bool, error)
	Signal(ctx context.Context, id, sig string) error
	State(ctx context.Context, id string) (State, error)
	Events(ctx context.Context, f Filter, fn func(Event)) error
	ListVolumes(ctx context.Context, f Filter) ([]Volume, error)
	InspectVolume(ctx context.Context, name string) (Volume, error)
	CreateVolume(ctx context.Context, v Volume) error
	RemoveVolume(ctx context.Context, name string) error
	VolumeOut(ctx context.Context, volume, path string) (io.ReadCloser, error)
	VolumeIn(ctx context.Context, volume, path string, r io.Reader) error
	RunFixer(ctx context.Context, s FixerSpec, out func(tar io.Reader) error) (*RunResult, error)
	EnsureImage(ctx context.Context, ref string) error
}
```

  - The neutral types in `types.go` are type aliases of today's `docker.*` structs (`ExecInput`, `ExecResult`, `ExecSplitResult`, `State`, `Event`, `Volume`, `RunResult`, `Network`). `FixerSpec` = today's `docker.RunSpec` minus the image (the backend picks the image).
  - `VolumeOut`/`VolumeIn` wrap today's helper create + archive copy + remove. `Info` folds `SecurityOptions`, `DockerRootDir`, `APIVersion` and `ListNetworks` (the VPN wiring's overlap guard, contract §3.3: on docker the engine's networks; on kube Task 8 returns the pod and service CIDRs as two synthetic networks) together with the guard state. `Up` keeps `PullWithProgress` behind `onPull` on docker.
  - `runtime.Kind` replaces `docker.Runtime` (the docker package and `RuntimeView` use it), so there is one runtime enum, not two.
  - `runtimetest.Fake`: an in-memory `Instances` with call recording.

- [ ] **Step 1:** Write `TestDockerBackendMatchesEngine` (the backend fed by today's fake engine/runner gives the same calls in the same order for create/up/down/backup/restore/fixer) and `TestDockerBackendPodmanQuirks` (ListNetworks without `IPRange`, an archive whose root entry is `/`).
- [ ] **Step 2:** Run `go test ./internal/runtime/...`. Expected: FAIL (package missing).
- [ ] **Step 3:** Implement the backend by moving code. Convert `internal/hub` call sites mechanically; the guard (`docker.Guard`) stays inside the backend.
- [ ] **Step 4:** Run the Hub gate. Expected: PASS with **no test assertion changed** (only fakes swapped). `git diff --stat origin/main -- '*_test.go'` shows fake plumbing only.
- [ ] **Step 5:** Commit (`hub: internal/runtime Instances; docker backend = compose CLI + engine (no behaviour change)`).
- [ ] **Step 6 (controller):** Run Hub `build.yml` on `kube1`, then core `gh workflow run ci.yml --ref kube1 -f jobs=build-and-test,e2e-instances,e2e-podman` (core `kube1` = main at this point, so it builds Hub `kube1`). Expected: green. Merge Hub `kube1` **at this commit** to main (`git merge --no-ff <sha>`) and wait for `edge`.

---

### Task 3: Hub `RuntimeCompat` (kubernetes table), `/api/runtime`, UI badge

**Files:**
- Rename: `internal/templates/rootless.go` → `runtimecompat.go`, `rootless_test.go` → `runtimecompat_test.go`, `testdata/rootless_vectors.json` → `testdata/runtime_vectors.json`
- Modify: `internal/hub/rootless.go` → `internal/hub/compat.go`, `internal/hub/runtime_engine.go` (`RuntimeView`), `internal/httpapi/instances.go` (`handleRuntime`; there is no `runtime.go`), `internal/httpapi/runtime_test.go`, `internal/httpapi/mcptools_admin.go` (`get_runtime`), `web/index.html` (the apps UI is inline there: `data-rootless`, `rootlessBadge`; there is no `web/apps.js`), `CLAUDE.md`

**Interfaces — Produces:**
- `templates.RuntimeCompat(rt runtime.Kind, compose []byte, m Manifest, env map[string]string, portStart int) Compat`. `docker` → `ok` always; `podman` → today's rules, unchanged; `kubernetes` → the table below.
- Kubernetes reasons (exact, shared with validate.py through `runtime_vectors.json`, which gains `"runtime"` per vector):
  - refused:
    - `service <s> uses network_mode: host (not on Kubernetes)`
    - `service <s> passes host devices (not on Kubernetes)`
    - `service <s> is privileged (not on Kubernetes)`
    - `service <s> shares the host's <pid|ipc> namespace (not on Kubernetes)`
    - `service <s> adds <CAP>, outside the Kubernetes baseline`
    - `service <s> binds <path>, outside the shared-folder roots (not on Kubernetes)`
    - `service <s> runs as user <u>: Kubernetes needs a numeric uid`
    - `service <s> sets deploy or replicas (not on Kubernetes)`
    - `service <s> publishes port <p>, a core port`
    - `service <s> uses TUN/NET_ADMIN (not on Kubernetes; prefer a userspace mode)`
  - degraded: `the Avahi services directory binds a host path outside the shared-folder roots: leave it empty and connect by address` (timemachine's `avahi_services_dir` set). The device-slot rule mirrors rootless P1: a `/dev/null` slot is degraded, a real device refused.
  - Baseline caps: `AUDIT_WRITE CHOWN DAC_OVERRIDE FOWNER FSETID KILL MKNOD NET_BIND_SERVICE SETFCAP SETGID SETPCAP SETUID SYS_CHROOT`.
- `GET /api/runtime` keeps `runtime` (= `kubernetes` on k8s; no new `kind` field), `engine` (`Kubernetes`), `engine_version` (server `gitVersion`), `verified`, `mismatch`, and adds `context`, `admission` (`ok|missing|unknown`) and `netpol` (`proven|unproven`) (Task 1 §11.10). No new MCP tool (the `get_runtime` twin covers it).
- Template and instance views: `rootless` → `compat: {runtime, status, reasons}` (podman and kubernetes; absent under Docker; no alias); the UI's `data-rootless*` → `data-compat*`, `rootlessBadge` → `compatBadge` with the runtime's own text (`Rootless: …` / `Kubernetes: …`).
- Reason order and the "names a device source only when it looks like `/dev/…`" rule are §11.10's, unchanged; vpn2's gateway allowlist reasons (if merged) stay the VPN rules' own and are not repeated here.

- [ ] **Step 1:** Write vectors: netbird refused (host); scrutiny refused (devices + SYS_RAWIO); zigbee2mqtt with an empty slot degraded; guacamole ok (its `cap_add` CHOWN, DAC_OVERRIDE, FOWNER is inside the baseline; a vector with `SYS_ADMIN` added is refused); timemachine with `avahi_services_dir` set degraded, empty ok; echo ok; `user: "app"` refused. Write `TestRuntimeCompatKubernetes` reading them, and extend `TestRuntimeRoute` (`internal/httpapi/runtime_test.go`) for the new fields.
- [ ] **Step 2:** Run `go test ./internal/templates/ ./internal/httpapi/`. Expected: FAIL.
- [ ] **Step 3:** Implement. The create/enable gates (`createEntry`, `prepareUp`) call `RuntimeCompat(h.rt.Kind(), …)`. The UI shows the column for the active runtime and a header badge `Docker | Podman | Kubernetes`.
- [ ] **Step 4:** Run the Hub gate. Expected: PASS.
- [ ] **Step 5:** Commit (`hub: RuntimeCompat with the Kubernetes table (shared vectors), /api/runtime kind/context/admission/netpol, runtime badge`).

---

### Task 4: Hub translator (pure, golden-tested)

**Files:**
- Create: `internal/runtime/kube/{translate.go,names.go,objects.go}`, `translate_test.go`, `testdata/translate/<case>/{compose.yml,env,want.yaml}`
- Test: one case per row of spec §4's table, plus the Review Focus cases

**Interfaces:**
- Consumes: `runtime.Project.Model`, Task 3's refusal rules (the translator refuses exactly what `RuntimeCompat` refuses, so the two can't drift: `TestTranslatorRefusesWhatCompatRefuses` runs every vector through both).
- Produces:
  - `func Translate(in Input) (Plan, error)`, with `Input{Instance, Template, Namespace string; Model *types.Project; Digests map[string]string; TemplateFiles map[string][]byte; AppFiles map[string]AppFile; PersonSecrets map[string]map[string][]byte; BindRoots []string; HubImage string; VPNSlot *int; IngressService string; Settings Settings}` and `Settings{PodCIDR, TraefikServiceIP, WGEdgeServiceIP, Domain string; CorePorts []int; LocalNetworks []string}`.
  - `Plan{Steps []Step}`, `Step{Objects []*unstructured.Unstructured; Wait WaitKind}`, with `WaitKind` one of `WaitNone | WaitReady | WaitComplete`. The order follows `depends_on` (healthy → `WaitReady`, completed → `WaitComplete`).
  - `func ObjectName(instance, service string) string`: lowercase, `_`/`.` → `-`, `-<hash8>` (sha256 of the original pair) past 63.
  - `ErrRefused{Reason string}`.
- Mapping (spec §4, exact):
  - `CMD-SHELL x` → exec probe `["sh","-c",x]`, and `CMD a b` → `["a","b"]`;
  - `interval`/`timeout`/`retries` → `periodSeconds`/`timeoutSeconds`/`failureThreshold` for readiness, liveness gets `failureThreshold × 2`; `start_period` → a `startupProbe` (same exec, `periodSeconds` = interval, `failureThreshold` = ceil(start_period / interval) + retries); **no `initialDelaySeconds`** anywhere (K17; core's chart uses the same mapping, Task 13);
  - `tmpfs: path:size=N,mode=M` → `emptyDir{medium: Memory, sizeLimit: N}` (mode is a reviewed delta: unshared, per container);
  - `mem_limit` → limits = requests;
  - `environment` → Secret `<instance>-env` (`envFrom`);
  - images → `Digests[ref]` (unresolved = refuse);
  - `seccompProfile: RuntimeDefault` and `automountServiceAccountToken: false` always;
  - `stop_signal` → `preStop` exec `kill -s <sig> 1`;
  - K4's two init containers per named volume;
  - `network_mode: service:x` → an extra container in `x`'s pod;
  - `ports:` → Service `LoadBalancer` with `externalTrafficPolicy: Local`, and `lan_only` → `loadBalancerSourceRanges`;
  - named volumes → PVC with the K3 annotations `portcullis.io/uid`, `portcullis.io/gid` (the service's numeric `user:`) and `portcullis.io/mode: "0750"`;
  - a wired VPN provider's ingress pod (`VPNSlot` set) → label `portcullis.io/vpn-slot: "<n>"` and `PORTCULLIS_VPN_EDGE=<WGEdgeServiceIP>:<9001+n>` in its `<instance>-env` Secret (and its namespace members'); no `portcullis-vpn` network on k8s.

- [ ] **Step 1:** Write the goldens and these tests:
  - `TestTranslateGoldens`;
  - `TestTranslateNameCollisionRefused` (`my_db` + `my-db` → `ErrRefused` naming both; an instance id of 40 chars + a service of 30 → hashed, distinct, ≤ 63);
  - `TestTranslateObjectTooLargeRefused` (a template file set of 1 MiB + 1 byte → refused `template files for <id> exceed 1 MiB`);
  - `TestTranslateLabelsOnlyFromTranslator` (a compose label `portcullis.io/net-portcullis: "true"` stays an annotation, never a pod label);
  - `TestTranslateNoSecretInPodSpec` (no env value appears in any Deployment);
  - `TestTranslateStartPeriodIsStartupProbe` (`start_period: 300s`, `interval: 10s`, `retries: 3` → startupProbe `failureThreshold: 33`, no `initialDelaySeconds`);
  - `TestTranslatorRefusesWhatCompatRefuses`.
- [ ] **Step 2:** Run `go test ./internal/runtime/kube/ -run Translate`. Expected: FAIL.
- [ ] **Step 3:** Implement with `unstructured` builders in `objects.go` (typed `k8s.io/api` structs converted with `runtime.DefaultUnstructuredConverter`).
- [ ] **Step 4:** Run the Hub gate. Expected: PASS.
- [ ] **Step 5:** Commit (`hub: compose → Kubernetes translator (goldens, ordered plan, K4 volume seeding, refusals in lockstep with RuntimeCompat)`).

---

### Task 5: Hub kube backend: apply, status, exec, signals, events, deliveries

**Files:**
- Create: `internal/runtime/kube/{backend.go,apply.go,status.go,exec.go,deliver.go,digest.go}` + tests (`fake.NewSimpleClientset` and a dynamic fake)
- Modify: `internal/hub/deliver_files.go`, `deliver_reload.go`, `secretsmount.go`, `stop.go`, `progress.go` (kube-specific branches only where the mechanism differs)

**Interfaces:**
- Consumes: `Translate`, `runtime.Instances`.
- Produces:
  - `kube.New(cfg Config) (*Backend, error)`, with `Config{Client kubernetes.Interface; Dynamic dynamic.Interface; Namespace string; Settings Settings; HubImage string; Resolver DigestResolver; Clock func() time.Time}`.
  - `DigestResolver interface{ Resolve(ctx context.Context, ref string) (string, error) }` (go-containerregistry `remote.Head`, anonymous, fully qualified refs only).
  - The apply uses server-side apply, field manager `portcullis-hub`, `force: true` only on objects carrying `portcullis.io/instance=<id>`.
  - `Create` = apply with replicas 0. `Up` = replicas 1 through the plan's steps. `Down` = delete by label every object of the instance **except PVCs** (as `compose down` keeps volumes; PVCs go only through `RemoveVolume`, the §11.4 guarded delete). `DownByName` works from labels alone.
  - `Unit.ID` = `<pod name>/<container>`.
  - `Signal` = exec `kill -s <SIG> 1`. On `executable file not found`, it falls back to deleting the pod (Deployment recreates it) and returns `ErrReloadDegraded`, which the Hub records as `reload_degraded`.
  - `onPull` gets `sized=false` from `Pulling`/`Pulled` events.
  - `deliver.go`: `func (b *Backend) Deliver(ctx, instance string, obj DeliveryObject, rev string) error` updates the ConfigMap/Secret with key `.rev`, patches the pod annotation `portcullis.io/rev: <rev>`, then polls `exec /portcullis-bin/hub rev <mount>` every 250 ms up to **10 s** (no `cat` needed in the app image: the K4 `portcullis-bin` init container is added to every pod that mounts a delivery, not only to pods with named volumes; `hub rev <dir>` prints `<dir>/.rev`, Task 6). It returns only when the copy matches; the caller records `rev` only then.

- [ ] **Step 1:** Write these tests:
  - `TestUpAppliesStepsInOrder` (a Job dependency is applied and completes before its dependents);
  - `TestApplyNeverTouchesForeignObjects` (an object without the instance label is never force-applied);
  - `TestDeliverWaitsForRev` (mounted `.rev` stale for 3 polls → not recorded; matching → recorded);
  - `TestDeliverTimeoutLeavesRevUnrecorded` (10 s with no match → error, rev not recorded);
  - `TestSignalFallsBackToRestart`;
  - `TestPersonSecretTooLargeRefuses` (`*-pw` over 1 MiB → refused, nothing applied);
  - `TestDownKeepsPVCs` (Down deletes the instance's Deployments, Services, routes, policies, ConfigMaps and Secrets, never a PVC);
  - `TestDigestCachedOnlyAfterDeploy` (a resolve followed by a failed `Up` leaves no cached digest).
- [ ] **Step 2:** Run `go test ./internal/runtime/kube/`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the Hub gate. Expected: PASS.
- [ ] **Step 5:** Commit (`hub: kube backend (server-side apply, ordered steps, status/logs/exec/signal/events, digest pinning, .rev deliveries within 10 s)`).

---

### Task 6: Hub helper pods, instance backups and restore, folder fixer

**Files:**
- Create: `cmd/hub/helper.go` (`hub helper idle|listen <addr>|dial <ip:port>`, `hub volcopy out|in <path>`, `hub seed <src> <dst>`, `hub rev <dir>` — prints `<dir>/.rev`, exit 1 when missing; Task 5's delivery poll runs it), `internal/runtime/kube/helpers.go` + tests
- Modify: `cmd/hub/main.go` (dispatch these before any env read, like `folderfix`), `internal/hub/fixer.go` (self image from `HUB_SELF_IMAGE` under kubernetes), `internal/hub/backup.go`, `restore.go` (no change to the format)

**Interfaces:**
- Produces:
  - Helper pod `hub-helper-<rand8>` in `portcullis-apps`:
    - image `HUB_SELF_IMAGE` (digest), main process `hub helper idle`, labels `portcullis.io/helper: "true"` + `portcullis.io/instance`;
    - no network label (deny-all), `automountServiceAccountToken: false`, read-only root, caps per contract §6 mode, run as `0:0` only for the fixer modes;
    - mounts exactly one PVC or one `hostPath` (`Directory`) under the bind roots.
  - `VolumeOut`/`VolumeIn` exec `hub volcopy out|in /vol` (the volume is always mounted at `/vol`, never at an image path: the Podman `domains_data` lesson) and stream the tar on stdout/stdin (cap: the existing backup limits). `RunFixer` execs `hub folderfix <mode> …` and parses the same report.
  - Task 8's probe pods are the one exception to deny-all. They carry `portcullis.io/probe: "deny"|"allow"`, no `portcullis.io/instance` and no volume. Their policies select only that label, and the VAP admits the label only on pods running `HUB_SELF_IMAGE` with command `hub helper listen|idle`.
  - Helpers are deleted always (`defer`, background context) and swept at Hub start by label.
  - `hub seed` copies `src/.` into `dst` only when `dst` has no entries but `lost+found`, preserving modes and symlinks. It writes `.portcullis-seeded` last and exits 0 if that file already exists.

- [ ] **Step 1:** Write these tests:
  - `TestVolcopyRoundTrip` (out → in on temp dirs; ownership as the caller);
  - `TestSeedOnlyWhenEmpty`;
  - `TestRevPrintsMountedRev`;
  - `TestHelperSpecMinimal` (golden of the helper pod per mode: caps exactly contract §6's; no SA token; no network label);
  - `TestHelperRemovedOnFailure`;
  - `TestHelperSweepAtStart`;
  - `TestInstanceBackupFormatUnchanged` (a kube-backend backup of the echo fixture equals a docker-backend one byte for byte modulo timestamps).
- [ ] **Step 2:** Run `go test ./cmd/hub/ ./internal/runtime/kube/ -run 'Volcopy|Seed|Helper|Backup'`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the Hub gate. Expected: PASS.
- [ ] **Step 5:** Commit (`hub: helper pods from the Hub's own image (volcopy, folderfix over exec, seed), instance backups/restore unchanged`).

---

### Task 7: Hub exposure on k8s: IngressRoutes, Middlewares, NetworkPolicies, VPN gateways, drift

**Files:**
- Create: `internal/runtime/kube/{ingress.go,netpol.go}` + goldens
- Modify: `internal/hub/override.go` (render labels as today; the kube backend converts them), `internal/hub/reconcile.go` (exposure drift via `Backend.LiveExposure`), `internal/hub/vpn_publish.go` (K5), `internal/hub/vpn_reach.go` (the VPN labels and `vpnAttachLocked`; there is no `vpn_render.go`, its tests are `vpn_render_test.go`), `internal/hub/vpn_providers.go` (`PORTCULLIS_VPN_EDGE` and the reserved ranges under kubernetes)

**Interfaces:**
- Produces:
  - `func IngressObjects(instance string, labels map[string]map[string]string) ([]*unstructured.Unstructured, error)`:
    - one `IngressRoute` per `traefik.http.routers.<r>` with its entrypoints, rule, priority, `tls.options` and middlewares;
    - a `Middleware` per `traefik.http.middlewares.<m>`, which may not be `forwardAuth` or set `X-Portcullis-*`;
    - middlewares: `…@docker` → `…@file` when on the K15 list (Task 1 §5), the instance's own (`portcullis-vpnallow-<id>`, the template's) → own-namespace refs, anything else refused;
    - services: `group-gate@docker`, `forward-auth-ext@docker`, `mcp-gate@docker` → `kind: TraefikService` refs `group-gate@file` / `forward-auth-ext@file` / `mcp-gate@file` (K15); the instance's own services stay in-namespace; anything else (e.g. `hub@docker`, `api@internal`) refused.
  - `func InstancePolicies(instance string, p Plan, vpnSlot *int) []*unstructured.Unstructured`:
    - per compose network `N`: same-label ingress/egress;
    - routed ports: ingress only from `namespaceSelector{kubernetes.io/metadata.name: portcullis}` + `podSelector{portcullis.io/component: traefik}`;
    - companion ports: the same with `mcp-gate`;
    - `internal: false` → the egress rule `0.0.0.0/0` except pod/service CIDRs, `169.254.0.0/16` and the node IPs, plus a node-IP rule for 80/443 only;
    - DNS egress to kube-dns :53;
    - a wired gateway: egress to the `wg` pod (`namespaceSelector` `portcullis` + `podSelector{portcullis.io/component: wg}`) on `9001+slot` only (reached through ClusterIP `wg-edge`).
  - `func (b *Backend) LiveExposure(ctx, instance string) (Exposure, error)`, compared with the desired set by the existing drift code.
  - K5: `vpnGatewayIPs(ctx) map[string]string` from a pod watch on `portcullis.io/vpn-slot`, feeding `vpn.json` `gateway_ip`. Republish when it changes. A provider whose gateway pod isn't Running+Ready with an IP is **left out** of `vpn.json` (never `gateway_ip: ""`: `vpn.Parse`, wg's and group-gate's readers refuse a non-IPv4 `gateway_ip`, which would void the whole document). Under kubernetes `vpnGatewayLocked` returns the pod IP and `PORTCULLIS_VPN_EDGE` = `<PORTCULLIS_WG_EDGE_SERVICE_IP>:<9001+slot>` (core.env); `vpn.GatewayAddr` and `vpnWGIPOK` are docker/podman only.
  - Reserved ranges: under kubernetes `core.Reserved` also holds `PORTCULLIS_POD_CIDR` and `PORTCULLIS_SERVICE_CIDR` (from core.env, and in `PORTCULLIS_VPN_RESERVED_RANGES` via core's `PORTCULLIS_VPN_RUNTIME_POOLS`), and the §3.3 overlap guard reads `Info.Networks`.

- [ ] **Step 1:** Write these tests:
  - `TestIngressGoldens` (forward-auth, oauth2, public link, MCP, extra domain, `vpnsecure` + `portcullis-vpnallow-<id>` first in the chain);
  - `TestCrossNamespaceMiddlewareRefused`;
  - `TestForwardAuthMiddlewareRefused`;
  - `TestPolicyRoutedPortTraefikOnly`;
  - `TestPolicyEgressExcludesClusterAndNode`;
  - `TestGatewayIPFollowsPod` (pod IP A published; pod rescheduled → the provider is unpublished before B is seen, and the written `vpn.json` still parses; then B; A is never republished);
  - `TestCoreServiceRefsAreFile` (a sign-in, MCP and `/vpn-required` router → `TraefikService` `forward-auth-ext@file` / `mcp-gate@file` / `group-gate@file`; `hub@docker` refused);
  - `TestKubeReservedIncludesClusterCIDRs` (a provider range inside the pod CIDR is not wired).
- [ ] **Step 2:** Run `go test ./internal/runtime/kube/ ./internal/hub/ -run 'Ingress|Policy|Gateway|Middleware'`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the Hub gate. Expected: PASS.
- [ ] **Step 5:** Commit (`hub: IngressRoutes/Middlewares from rendered labels (@docker → @file), per-instance NetworkPolicies, live VPN gateway IPs, exposure drift on k8s`).

---

### Task 8: Hub cluster guard, wiring, doctor kinds, envtest RBAC and VAP vectors

**Files:**
- Create: `internal/runtime/kube/guard.go`, `guard_test.go`, `envtest_test.go` (`//go:build envtest`), `testdata/role.yaml`, `testdata/admission/{policies.yaml,bindings.yaml,params.yaml}`, `testdata/admission_vectors.json`, `internal/hub/doctor_runtime.go`
- Modify: `cmd/hub/main.go` (`runtimeFromEnv` accepts `kubernetes` → `rest.InClusterConfig`; `HUB_SELF_IMAGE` required under kubernetes), `.github/workflows/build.yml` (the envtest step, `setup-envtest` pinned), `internal/doctor/doctor.go`, `CLAUDE.md` ("the Hub has one Role" rule)

**Interfaces:**
- Produces:
  - `kube.Guard` with `Run(ctx, every 60s)` and `Verified() <-chan struct{}`. It checks, in order:
    - (1) in-cluster config and namespace = `HUB_APPS_NAMESPACE`;
    - (2) `SelfSubjectRulesReview` equals K2's Role exactly (no more, no less; `pods/exec` is `create` only, so a `get` there is an extra verb);
    - (3) the admission self-test (K6) passes: a forbidden Pod and a forbidden Deployment, `dryRun=All`, each rejected `Invalid`/`Forbidden` with a Status `message` containing `with binding 'portcullis-apps-guard-`; `Warning:` headers (PSA `warn: baseline`) are ignored;
    - (4) its own NetworkPolicy probe: two helper pods (`hub helper listen :8080`), one behind a deny policy and one behind an allow policy, with `hub helper dial <ip:port>` exec'd from a third pod. It passes only when the denied dial fails and the allowed one succeeds. ConfigMap `portcullis-netpol-probe` (the CLI's result) is shown in `/api/runtime` but is never enough by itself.

    Until all four hold, every `Instances` method but `Kind`/`Info` returns `ErrClusterUnverified` (503 `the cluster is not verified: <why>`).
  - `admission_vectors.json` entries `{name, object, as: "hub", want: "allow"|"deny", reason_contains}`, covering spec §7's list, one or more each, plus the K5 slot label range (`"46"` allowed, `"47"` and `"-1"` denied), the Task 6 probe exception (a NetworkPolicy selecting `portcullis.io/probe` whose peers are probe pods only: allowed; any other non-instance selector: denied) and the K15 `@file` names (allowed) vs any other `@file`/`@internal` (denied). `reason_contains` is matched against the Status message only. The spike's vectors (Task 0 Q4 table) are the starting set.
  - Doctor kinds from Task 1 §14.5.

- [ ] **Step 1:** Write these tests:
  - `TestGuardFailsClosed` (each check failing alone → 503 with its why);
  - `TestRoleExact` (an extra verb in a fake rules review → unverified; `get` on `pods/exec` → unverified);
  - `TestSelfTestRequiresPolicyRejection` (envtest: VAPs absent + a deny-all validating webhook → `admission_guard_missing`; VAPs present → ok; a fake whose denial message names another binding, or carries the binding only in a warning → `admission_guard_missing`);
  - `TestAdmissionVectors` (envtest, each vector as the Hub's ServiceAccount through impersonation);
  - `TestRoleIsEnough` (envtest: the full echo deploy, helper, delete with exactly `role.yaml`; envtest has no kubelet, so for exec and logs the test asserts the request passes authorization — any error but `Forbidden` — rather than success).
- [ ] **Step 2:** Run `go test -tags envtest ./internal/runtime/kube/` with `KUBEBUILDER_ASSETS`. Expected: FAIL.
- [ ] **Step 3:** Implement the guard, the wiring, the CEL policies (`ValidatingAdmissionPolicy` `portcullis-apps-{pods,workloads,services,traefik,netpol}`, one binding per policy `portcullis-apps-guard-{pods,workloads,services,traefik,netpol}`, each with `paramRef` to ConfigMap `portcullis-admission-params` and `parameterNotFoundAction: Deny`, `validationActions: [Deny]`, `failurePolicy: Fail`; `status.typeChecking` must come back empty in envtest) and the doctor kinds.
- [ ] **Step 4:** Run the Hub gate plus envtest, then `gh workflow run build.yml --ref kube1`. Expected: PASS / green.
- [ ] **Step 5:** Commit (`hub: kubernetes runtime (in-cluster guard: namespace, exact Role, admission self-test, netpol probe; fail closed), doctor kinds, envtest RBAC + VAP vectors`).

---

### Task 9: Templates: `_SOURCE` switch, gate CIDR checks, validator kubernetes column

**Files:**
- Modify: the 84 files that reference `PORTCULLIS_TRAEFIK_IP` at templates `37350f4` (35 `compose.yml`, 15 `nginx.conf`, 5 `manifest.yaml`, the 4 `gate.sh` — esphome, mattermost, motioneye, zigbee2mqtt —, `grafana/portcullis/trust.sh`, `dokuwiki/init.sh`, 16 `tests/apps/*.sh`, `tests/lib.sh`, `test-apps.yml`, the validator and its tests, `CONTRIBUTING.md`, `CLAUDE.md`, `.github/pull_request_template.md`); `PORTCULLIS_MCP_GATE_IP` appears in 4 files only — `CLAUDE.md`, `CONTRIBUTING.md`, `tests/validate.py`, `tests/test_validate.py`, no template — and reaches AI companions through the Hub's instance env (Task 1 §2); `tests/trust/test_grafana_trust.sh`; `tests/validate.py`, `tests/test_validate.py`, `tests/rootless_vectors.json` → `tests/runtime_vectors.json` (renamed byte copy), `tests/rootless.txt` → `tests/runtime.txt`, **`.github/workflows/lint.yml`** (the "Rootless vectors match the Hub" step becomes "Runtime vectors match the Hub", fetching `internal/templates/testdata/runtime_vectors.json` from the same-named Hub branch, else main), `CONTRIBUTING.md`, `CLAUDE.md`

**Interfaces:**
- Consumes: Task 1 §2, Task 3 vectors.
- Produces:
  - Every reference is exactly `${PORTCULLIS_TRAEFIK_SOURCE:-172.31.250.2/32}` / `${PORTCULLIS_MCP_GATE_SOURCE:-172.31.250.3/32}`.
  - `validate.py` refuses any `PORTCULLIS_TRAEFIK_IP`/`PORTCULLIS_MCP_GATE_IP` reference, and refuses a `_SOURCE` in any form other than the default form.
  - Gates accept `a.b.c.d/n` (0 ≤ n ≤ 32, `ipaddress.IPv4Network(strict=True)` semantics in shell via the existing parse helpers) and nothing else.
  - `runtime_compat(t, rt, env, port_start)` matches the Hub's vectors. `tests/runtime.txt` lists both columns.

- [ ] **Step 1 (K9 survey):** Produce `tests/source_consumers.txt` (committed): one line per file with the app setting it feeds and "CIDR ok" (with the upstream doc reference) or "single IP → gate". Expected: every "single IP" line names the gate added in Step 4.
- [ ] **Step 2:** Write the failing tests:
  - "`_IP` reference refused";
  - "`_SOURCE` non-default form refused";
  - "gate.sh accepts 10.42.0.0/16 and 172.31.250.2/32, refuses 10.42.0.0/33, `any`, empty";
  - the vectors comparison with the Hub (`kube1`, else main), in `test_validate.py` and the renamed lint.yml step (templates main's lint fetches the old `rootless_vectors.json` path and goes red from the second Hub merge until templates `kube1` merges: that is inside the merge window, accepted);
  - `test_grafana_trust.sh` with a CIDR.
- [ ] **Step 3:** Run the templates gate. Expected: FAIL.
- [ ] **Step 4:** Implement the switch, the gates and the classifier.
- [ ] **Step 5:** Run the templates gate. Expected: PASS. Commit (`templates: PORTCULLIS_TRAEFIK_SOURCE / _MCP_GATE_SOURCE (CIDR), gate CIDR checks, kubernetes compat column`) and push. Run lint.yml and Test Apps (Docker) on `kube1`. Expected: green.

---

### Task 10: Templates `kube2`: the k3s Test Apps leg (after the core merge)

**Files:**
- Modify: `.github/workflows/test-apps.yml` (matrix `runtime: [docker, kubernetes]`; the kubernetes leg skips templates whose compat is `refused`), `tests/apps/lib.sh` (runtime-neutral `app_exec`, `app_logs`)
- Create: `tests/apps/lib-k3s.sh` (installs k3s through core's `.github/ci/e2e-k3s-install.sh` from the core checkout the workflow already makes at `.core-ref` — `main` — and runs `./portcullis init --runtime kubernetes`; images `PORTCULLIS_KUBE_IMAGES=registry`, the five `:edge` images; the runner job uses `ubuntu-26.04` like core's e2e-k3s)

**Interfaces:**
- Consumes: core main (chart, `e2e-k3s-install.sh`, `:edge` images), Hub `edge`.
- Produces: one job per template per runtime; failures name the template and the first unready pod's events.

- [ ] **Step 1:** Add the leg for `echo`-class templates first (grafana, vaultwarden, gitea), then all `ok`/`degraded` templates.
- [ ] **Step 2 (controller):** Run Test Apps on `kube2`. Expected: green. Each failure is fixed in the template, or (Q3) gets a manifest-declared internal port, never a wider rule. Record every K4 owner mismatch in `tests/runtime.txt`.
- [ ] **Step 3:** Commit (`ci: Test Apps on k3s (one template per job)`), then merge `kube2` like the others.

---

### Task 11: Core CLI runtime layer: `rt_*`, the kubernetes runtime, checks and probe

**Files:**
- Create: `scripts/lib/kube.sh`, `kube/probe/{namespace.yaml,deny.yaml,allow.yaml}`
- Modify: `scripts/lib/runtime.sh` (`runtime_name` accepts `kubernetes`; `runtime_export` sets `PORTCULLIS_VPN_RUNTIME_POOLS="$PORTCULLIS_POD_CIDR $PORTCULLIS_SERVICE_CIDR"` under kubernetes; `runtime_check` dispatches to the kube checks), `common.sh` (`rt_*`; `HUB_ENV_VARS` + `hub_env_write`: `PORTCULLIS_TRAEFIK_SOURCE`, `PORTCULLIS_MCP_GATE_SOURCE`, and under kubernetes `PORTCULLIS_POD_CIDR`, `PORTCULLIS_SERVICE_CIDR`, `PORTCULLIS_WG_EDGE_SERVICE_IP`, `PORTCULLIS_RUNTIME_ROOTS`), every `scripts/lib/*.sh` + `portcullis` call site of `dc`/`docker` (about 270 lines at core `791a743`, including `vpn.sh`'s `dc exec … hub hub vpn` and `wg` execs), `tests/test_shell_libs.sh`, `tests/test_cli.sh`, `.env.example`, `CLAUDE.md` (the `rt_*` rule)

**Interfaces — Produces (bash):**
- `rt_up [svc…]`, `rt_down`, `rt_exec [-i] <svc> -- <argv…>`, `rt_logs <svc> [--tail N]`, `rt_ps [--json]`, `rt_volume_out <volume> <path>` (tar on stdout), `rt_volume_in <volume> <path>` (tar on stdin), `rt_restart <svc>`, plus (K16) `rt_run <svc> [-i] -- <argv…>`, `rt_stop <svc>`, `rt_start <svc>`, `rt_health <svc>` (`container_health`'s vocabulary). On docker/podman these are today's `dc`/`docker` code, moved:
  - `rt_up` on docker/podman **is** kcwait's `stack_compose_up` (build every local image first, one `dc up -d --no-build`, the `STACK_UP_WAIT` retry, `compose_health_report`), unchanged; its callers (`stack.sh`, `backup.sh` restore, `vpn.sh` `stack_compose_up wg traefik hub`) call `rt_up`. On kubernetes `rt_up` ignores the service list (a Helm release is whole) — Task 15.
  - `rt_exec` has no `-u`: the one `dc exec -u` today (`vpn.sh`, the Hub as `10001:10001`) is the container's own user, so dropping it changes nothing on docker.
  - `rt_run` on docker is `dc run --rm --no-deps -T …` (dns-tool, `signin reset-core`), `rt_stop`/`rt_start` are `dc stop`/`dc start`.
  - `ct_run` throwaways, `ct_own`/`volume_own` on named volumes and `docker volume …` stay docker-branch code; their kubernetes forms are Task 15's (K16; `volume_own` is a no-op there: K3 annotations own the PVCs).
- `kube_ctl …` = `kubectl --context "$PORTCULLIS_KUBE_CONTEXT" …` (never without `--context`), `kube_helm …` the same for `helm --kube-context`.
- `kube_detect_cidrs` sets `_K_POD_CIDR` (the node's `spec.podCIDRs`), `_K_SVC_CIDR` and `_K_API_EP` (the `default/kubernetes` EndpointSlice). `_K_SVC_CIDR` comes from a server dry-run Service with `clusterIP: 0.0.0.1`, whose rejection names the valid range; an unparsable answer is refused.
- `kube_host_checks` prints `_rt_chk` rows for the † items of spec §6, K8, K10 and K11, and:
  - the server version ≥ `v1.32` (the floor; refuse) — CI pins `v1.37.2+k3s1`;
  - the source-IP row (warning, spec §6): when the public IPv4 (`PORTCULLIS_PUBLIC_IPV4` or detected) is a local address of the node but not in the `traefik` Service's `status.loadBalancer.ingress`, warn `client IPs will be rewritten: reinstall k3s with --node-external-ip=<ip>` (Task 0 Q1; `init` can't change k3s flags itself);
  - the three fixed ClusterIPs (Global Constraints) inside the static band and free (refuse);
  - the `portcullis-storage` namespace under K11 like the other two.
- `kube_netpol_probe` applies `kube/probe/*`. It passes only when the denied dial fails **and** the allowed dial succeeds; then it writes ConfigMap `portcullis-netpol-probe` (`proven_at`) in `portcullis-apps` and deletes the probe namespace.
- `kube_port_forward <svc> <port>` is a background port-forward on a random local port; it prints the port and the trap kills it.
- `init --runtime kubernetes --kube-context <ctx>` writes the keys from Global Constraints plus `PORTCULLIS_KUBE_INSTALL_ID` (`uuidgen`), `PORTCULLIS_KUBE_IMAGES=registry` and the three fixed ClusterIPs.
- Shape: Step 3 lands as **two commits**: (a) the `rt_*` verbs with only the docker branch and every call site converted (docker/podman CI green on its own: Step 6's run), then (b) the kubernetes branch, checks and probe. Same task, same review.

- [ ] **Step 1:** Write shell tests (kubectl/helm stubs in the style of the docker stubs):
  - "need_env: kubernetes without PORTCULLIS_KUBE_CONTEXT → refused naming it";
  - "kube_ctl always passes --context";
  - "runtime_check: detected pod CIDR differs from .env → refused naming both";
  - "kube_host_checks: an IPv6 pod CIDR → refused";
  - "init kubernetes: foreign portcullis namespace → refused" (Review Focus 5) and "… matching install id → adopted";
  - "kube_netpol_probe: allowed dial fails → not proven, ConfigMap not written";
  - "status jq: (A and B) as $x fixture" (jq 1.8);
  - "no dc/docker outside the rt_* docker branch" (grep);
  - argv grep: no `--from-literal`, no `--set` with a `secrets/` value;
  - "runtime_export kubernetes: PORTCULLIS_VPN_RUNTIME_POOLS = pod + service CIDR";
  - "hub_env_write: PORTCULLIS_TRAEFIK_SOURCE = <ip>/32 on docker, the pod CIDR on kubernetes";
  - "kube_host_checks: public IP local but not an LB ingress address → warning naming --node-external-ip";
  - "kube_host_checks: server v1.31 → refused";
  - "rt_up docker = stack_compose_up" (the existing kcwait tests pass unchanged through `rt_up`).
- [ ] **Step 2:** Run the core gate. Expected: FAIL.
- [ ] **Step 3:** Implement. Convert call sites mechanically (docker behaviour unchanged).
- [ ] **Step 4:** Run the core gate. Expected: PASS.
- [ ] **Step 5:** Commit (`cli: rt_* runtime layer (docker/podman unchanged), CONTAINER_RUNTIME=kubernetes, context/namespace/CIDR/API keys, § 6 checks, NetworkPolicy probe`).
- [ ] **Step 6 (controller):** Run `gh workflow run ci.yml --ref kube1 -f jobs=unit-tests,build-and-test,e2e,e2e-podman`. Expected: green (no Docker/Podman change).

---

### Task 12: Core image publishing (`images.yml`) and `images.yaml`

**Files:**
- Create: `.github/workflows/images.yml`, `scripts/gen-images-yaml.py`, `charts/portcullis/images.yaml`
- Modify: `.github/workflows/release.yml` (tag the five images `X.Y.Z` and sign them), `tests/lint_images.sh` (scan `charts/portcullis/images.yaml`, `charts/portcullis/templates/*.yaml` and `kube/**/*.yaml`: the provisioner image `docker.io/rancher/local-path-provisioner:v0.0.37@sha256:e757967a5ec338f6a9b371c5a9688bedaa8c3578ea3dd4db329ea0084be0a86f` and `PORTCULLIS_HELPER_IMAGE` for its helper pod), `.github/dependabot.yml` (the `wg` Dockerfile if it isn't covered yet)

**Interfaces — Produces:**
- `images.yml`:
  - matrix `svc: [group-gate, enroll, domains, mcp-gate, wg]`, context `./<svc>`;
  - pushes `ghcr.io/porelli/portcullis-<svc>:edge` from main (only when the context changed, or on dispatch), cosign signs the digest, and writes the summary line `pushed <ref>@<digest>`; `runs-on: ubuntu-latest`, actions pinned by full SHA copied from `forwarder.yml`;
  - on other branches it only builds.
- `images.yaml`: `images: {<service>: "<fully qualified ref>@sha256:<64 hex>" | {tag_ref: "<ref>:edge"}}`, generated from `docker-compose.yml` (third-party images by digest; the five + Hub + Keycloak as tag refs the CLI resolves, K1).
- A unit-tests step fails when `gen-images-yaml.py --check` differs.

- [ ] **Step 1:** Write the failing check (`gen-images-yaml.py --check` on a stale file → exit 1) and the `lint_images.sh` test (an unqualified entry → flagged).
- [ ] **Step 2:** Run `bash tests/test_cli.sh`. Expected: FAIL.
- [ ] **Step 3:** Implement. Copy the forwarder workflow's pinned actions.
- [ ] **Step 4:** Run `actionlint` and the core gate. Expected: PASS. Commit (`ci: publish the five core-built images to GHCR (edge, release tags, cosign); images.yaml generated from compose`).

---

### Task 13: Core chart

**Files:**
- Create: `charts/portcullis/{Chart.yaml,values.yaml,crds/traefik-<v>.yaml}`, plus `templates/`:
  - `_helpers.tpl`, `namespaces.yaml` (rendered for kubeconform; `init` applies them);
  - one file per core service;
  - `netpol-default-deny.yaml`, `netpol-networks.yaml` (from the compose network map), `netpol-wg-edge.yaml` (47 per-slot rules, K5);
  - `traefik-rbac.yaml`, `hub-rbac.yaml` (K2), `ingressroutes-core.yaml`, `traefik-file-middlewares.yaml`, `configmap-hashes.yaml`;
  - `services.yaml`: `traefik` LoadBalancer (ETP `Local`, fixed clusterIP `traefikServiceIP`, ports 80→8000 and 443→8443 **only**), `keycloak-internal` ClusterIP (8081 → Traefik `kcinternal`), `traefik-vpn` ClusterIP (fixed `traefikVPNServiceIP`, 8444 → `vpnsecure`), and with `wg.enabled`: `wg-edge` ClusterIP (fixed `wgEdgeServiceIP`, 9001–9047), `wg-people` LoadBalancer (UDP, ETP `Local`), `wg-metrics` ClusterIP (9100). Never `kcinternal`, `vpnsecure`, edge or metrics ports on a LoadBalancer (ServiceLB publishes every LB port on the node).
  - `oneshot.yaml`: the `rt_run` pod specs (dns-tool, hub `signin reset-core`), rendered only with `--show-only` (K16).
- Create: `tests/k8s_parity.py`, `tests/k8s_netpol_matrix.py`, `tests/k8s_hardening.py`, `.github/ci/unit-tests-kube-static.sh`
- Modify: `.github/workflows/ci.yml` (one unit-tests step calling the script), `CLAUDE.md` (parity rule), **`wg/main.go`** + `wg/main_test.go` (K7 `WG_ADDR_MODE=pod`: `WG_VPN_ADDR` = `WG_EDGE_ADDR` allowed, metrics on that address allowed; any other value of `WG_ADDR_MODE` refuses to start; `docker`, the default, keeps every current check)

**Interfaces:**
- Consumes: `images.yaml` (CLI-resolved digests in `secrets/kube/values.yaml`), the Hub's `role.yaml` (byte copy, K13), `wg` per VPN contract §16.
- Produces:
  - `values.yaml` keys: `domain`, `podCIDR`, `serviceCIDR`, `apiEndpoints`, `traefikServiceIP`, `traefikVPNServiceIP`, `wgEdgeServiceIP`, `images.<svc>` (digests only; `required`), `uids.<svc>` (= `CT_*`), `monitoring.enabled` and `wg.enabled` (both from `COMPOSE_PROFILES`, as compose profiles on Docker), `wg.people.port`, `wg.subnet`, `wg.builtin`, `wg.edge.{maxPerProvider,maxPerUser,maxPerClient,pressurePercent,pressureIdle}`, `vpn.mode`, `vpn.publicEnrol`, `vpn.reservedPools` (pod + service CIDR), `entrypoints.ep.{core,admin,enrol}`, `entrypoints.web.{core,admin,enrol}` (the six `.env` classes).
  - `randAlphaNum`/`randAscii`/`genPrivateKey` banned, and `required` replaces `${VAR:?}`.
  - Every pod has: `portcullis.io/component`, its `portcullis.io/net-*` labels from compose membership, `automountServiceAccountToken: false` (except traefik, hub), drop ALL, `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem`, `seccompProfile: RuntimeDefault`, `runAsNonRoot`, limits = requests = compose `mem_limit`, the probes = compose healthcheck (Task 4's mapping) and the annotation `portcullis.io/config-hash`.
  - Traefik:
    - `kubernetesCRD` as Global Constraints, file provider from ConfigMap `traefik-dynamic` (shared middlewares + `strip-forwarded`);
    - entrypoints `web :8000`, `websecure :8443` (asDefault), `kcinternal :8081`, `vpnsecure :8444` (`proxyProtocol.trustedIPs` = podCIDR), `parked 127.0.0.1:8441`, plus today's internal `traefik :8080` (ping) and `metrics :8082`; **`http.middlewares: strip-client-forwarded@file` and `http.aliasHeadersStrategy: delete` on websecure, vpnsecure and kcinternal** (as compose has on websecure and vpnsecure);
    - the file provider ConfigMap `traefik-dynamic` = core's `traefik/dynamic/*.yml` plus the K15 core middlewares and services (`portcullis-auth`, `-auth-ext`, `-groups`, `-groups-vpn`, `-public-guard`, `-public-guard-vpn`, `vpn-required-path`; `group-gate@file`, `forward-auth-ext@file`, `mcp-gate@file` pointing at the core Services' cluster DNS names) and the chart-only `strip-forwarded`;
    - core IngressRoutes: one per compose router (the `-vpn` twins on `vpnsecure` with `portcullis-groups-vpn`; the rest with `entrypoints.*`), `hub-proxy-secret` and `portcullis-auth-console` as Middleware CRDs in `portcullis`;
    - ACME on PVC `traefik-acme`; the URI helper as a pod with Traefik's uid.
  - Keycloak: `--proxy-trusted-addresses={{ .Values.podCIDR }}`. Ingress :8080 only from Traefik.
  - `kcinternal` router: `PathPrefix(/)` on `kcinternal` → Keycloak :8080, middleware `strip-forwarded@file`. Ingress :8081 from `hub`, `enroll`, `forward-auth`, `forward-auth-ext`, `mcp-gate` only.
  - `hostAliases` `auth.<d>` → `traefikServiceIP` on the services compose gives `auth.<d>:host-gateway`: `forward-auth`, `forward-auth-ext` and `blackbox` (not grafana). mcp-gate's `extra_hosts` pins become Service FQDNs (spec §5).
  - Probes: Task 4's mapping, `start_period` → `startupProbe` (K17; Keycloak's 300 s gives `failureThreshold` = 300/interval + retries).
  - PVCs: K3 annotations `portcullis.io/uid|gid|mode` from the `CT_*` values and `volume_own` modes (e.g. `wg-data` 10006/10001/2750, `vpn-doc` 10001/10007/2750); no seed init containers on core PVCs.
  - The Hub: env `HUB_CONTAINER_RUNTIME=kubernetes`, `HUB_SELF_IMAGE`, `HUB_APPS_NAMESPACE`; egress to `apiEndpoints` :6443 only, besides its compose networks.
  - `wg` (K7): `WG_ADDR_MODE=pod`, `WG_VPN_ADDR`/`WG_EDGE_ADDR` from `status.podIP`, `WG_TRAEFIK=<traefikVPNServiceIP>:8444`, `WG_METRICS=<pod IP>:9100`, `WG_CORE_SUBNETS` (and group-gate's `GATE_CORE_SUBNETS`) = the compose list + `vpn.reservedPools`, the five `WG_EDGE_*`, the people key Secret, `vpn-doc` read-only, `wg-data`.
  - group-gate: `GATE_VPN_MODE` / `GATE_VPN_PUBLIC_ENROL` from `vpn.mode` / `vpn.publicEnrol` (its own env: break-glass with the Hub down), `vpn-doc` read-only.
- `k8s_parity.py`: for every compose service it compares `helm template` (CI values) on image digest, uid/gid, caps, read-only root, memory, env keys, mount targets, probes and network labels. It also maps every one of the **46** project binds to a ConfigMap/Secret mount target. Reviewed deltas live in `tests/k8s_parity_deltas.yaml` (each with a reason; pids is one, `tmpfs` `mode=` → `emptyDir` without a mode — e.g. the Hub's `/home/hub` `mode=1777` — is another).
- `k8s_netpol_matrix.py`: from compose networks it derives the allowed (pod, pod) pairs and asserts the rendered policies allow exactly those, plus the Global Constraints port-bound rules. The VPN networks become port-bound rules: `portcullis-vpn-edge` = `wg` → Traefik :8444 only; `portcullis-vpn` = slot-`n` gateway pods → `wg` :`9001+n` only; `portcullis-metrics-wg` = Prometheus → `wg` :9100 only; no other pod reaches `wg` on any port (Review Focus 6).
- `k8s_parity.py` also compares every core router's entrypoints for each of `vpn mode apps|admin|server` (the six classes from `vpn_entrypoints`), and the entrypoint middlewares.
- `k8s_hardening.py` asserts the per-pod list above on every rendered pod, and that no workload in `portcullis` violates `restricted`.

- [ ] **Step 1:** Write the three Python checks against an empty chart, plus kubeconform (pinned, `-strict`, the Traefik CRD schemas) and `helm lint` in `unit-tests-kube-static.sh`. Add "Hub Role byte copy matches the Hub (`kube1`, else main)".
- [ ] **Step 2:** Run `bash .github/ci/unit-tests-kube-static.sh`. Expected: FAIL (every service missing).
- [ ] **Step 3:** Write the chart service by service until parity and the matrix pass.
- [ ] **Step 4:** Run the core gate, `(cd wg && go test ./...)` and the static script. Expected: PASS. `bash tests/lint_ci_size.sh` passes (ci.yml is 315 249 bytes at core `791a743`; the limit is 450 000).
- [ ] **Step 5:** Commit (`chart: core on Kubernetes (PSA restricted, default-deny + network-derived policies, Traefik CRD provider + file middlewares + kcinternal + vpnsecure on its own port, wg edge/people, Hub Role); parity, netpol matrix, hardening checks`).

---

### Task 14: Core admission policies, StorageClasses, `init` cluster setup

**Files:**
- Create: `kube/admission/{policies.yaml,bindings.yaml,params.yaml}` (byte copies, K13; `bindings.yaml` holds the five `portcullis-apps-guard-<policy>` bindings), `kube/admission/params.tmpl.yaml`, `kube/storage/{namespace.yaml,provisioner.yaml,storageclasses.yaml,setup.sh}`
- Modify: `scripts/lib/kube.sh` (`kube_cluster_setup`), `.github/ci/unit-tests-kube-static.sh` (the byte-copy comparison)

**Interfaces:**
- Produces:
  - `kube_cluster_setup` is idempotent and server-side; each step commits to `applied.json` only after success. It:
    - creates the namespaces with PSA labels and K11's label/annotation: `portcullis` (restricted), `portcullis-apps` (enforce privileged, warn/audit baseline), `portcullis-storage` (enforce baseline);
    - installs the provisioner `portcullis.io/local-path` (`docker.io/rancher/local-path-provisioner:v0.0.37@sha256:e757967a5ec338f6a9b371c5a9688bedaa8c3578ea3dd4db329ea0084be0a86f`) in `portcullis-storage` with its own ServiceAccount and `--service-account-name <that SA>` (required: Task 0 run 2 failed without it), a ClusterRole limited to what upstream's needs, default-deny + egress to the API endpoints only; its helper pod template runs `PORTCULLIS_HELPER_IMAGE` as uid 0, drops the 11 default caps other than CHOWN/DAC_OVERRIDE/FOWNER by name (no `capabilities.add`, never `--allow-unsafe-helper-pod-template`), no-new-privileges, `RuntimeDefault`, read-only root;
    - both StorageClasses with K3's native patterns (`userPattern`/`groupPattern`/`permPattern` from the PVC annotations `portcullis.io/uid|gid|mode`), `portcullis-core` reclaim `Retain`, `portcullis-apps` reclaim `Delete`; `setup.sh` validates `VOL_USER`/`VOL_GROUP`/`VOL_PERM` and refuses (`portcullis-setup REFUSED: <why>`) a missing or bad value;
    - applies the Traefik CRDs (K14) and the five VAPs + their five bindings (K6);
    - renders the params ConfigMap `portcullis-admission-params` in `portcullis-apps`: `hubImage`, `bindRoots`, `corePorts` (80, 443, the VPN port, 8000, 8081, 8443, 8444), `podCIDR` and `fileMiddlewares` (K15's names: middlewares and the three services).
  - Used by `init` and `upgrade`.

- [ ] **Step 1:** Write the shell tests: "cluster setup: params ConfigMap carries the resolved Hub digest", "a failed VAP apply leaves applied.json unchanged", "setup.sh: 10001/10001/0750 and 10006/10001/2750 → mkdir -m + chown; '' or 'x' or 65536 → REFUSED, nothing created", "the provisioner Deployment carries --service-account-name", and the byte-copy CI check.
- [ ] **Step 2:** Run the core gate. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the core gate. Expected: PASS. Commit (`kube: admission policies + params (from the Hub vectors), local-path provisioner + StorageClasses with owner patterns, idempotent cluster setup`).

---

### Task 15: Core sync, up/down/status, backup/restore and revocation on kubernetes

**Files:**
- Modify: `scripts/lib/kube.sh`, `stack.sh` (`up`, `upgrade`, `down`), `status.sh`, `backup.sh`, `vault.sh`, `keycloak.sh`, `certs.sh` (`cert revoke|sync`), `vpn.sh` (`vpn init|mode|builtin|add-device` on kubernetes), `signin.sh` (`signin reset-core`), `dns.sh` (`_dns_tool`), `users.sh` (`lldap-ui`), `config.sh` (the `acme.json` reset), `tests/test_shell_libs.sh`, `tests/test_cli.sh`

**Interfaces — Produces (bash):**
- `kube_sync_secrets`: every file under `secrets/` (except `secrets/kube/`) plus the core secret variables become Secrets via `--from-file` (variables written to a 0600 temp dir first, removed by trap). The host config directories become ConfigMaps. Each is applied only when its hash differs from `applied.json`.
- `kube_render_values` writes `secrets/kube/values.yaml` with no secret: every key of Task 13's `values.yaml` list, from `.env` (the six entrypoint classes, `PORTCULLIS_VPN_*`, the edge caps, `COMPOSE_PROFILES` → `monitoring.enabled`/`wg.enabled`, the three fixed ClusterIPs, the CIDRs) and the resolved digests (K1); a key Task 13 marks `required` and `.env` lacks → refused naming it.
- `rt_up` on kubernetes = (K1 `local`: build every core image first — `docker build` or `podman build --format docker` — and import it, kcwait's "build before up") → sync → `kube_cluster_setup` → `helm upgrade --install --wait --timeout 10m -f secrets/kube/values.yaml` → `applied.json`. A service list (`rt_up wg traefik hub` from `vpn init`) is accepted and ignored: the release is whole. On a failed or timed-out helm run, `kube_health_report` prints each unready pod with its restart count and its last 3 events (never env or a Secret), the `compose_health_report` equivalent, and `applied.json` is not written.
- `rt_down` scales every Deployment in both namespaces to 0. It never calls `helm uninstall`.
- `status`: the same lines from pods. `--json`'s existing `runtime` object (`runtime_status_json`: `{name, version, rootless, uid, …, checks}`) gets `name: "kubernetes"`, `version` (server `gitVersion`), `context`, `checks` = the `kube_host_checks` rows (spec §3's `runtime{kind, …}` is this object; no second `kind` key), and the top level gains `netpol`, `admission`, `dns_shadows` (no app Service name equals a core one) and `kube_api_public` (K8). The VPN lines (mode, roles, per-provider maps from `/wg status` and `/wg providers` via `rt_exec wg`) are unchanged.
- VPN on kubernetes (K16): `vpn init` writes the `.env` keys as today, adds `wg` to `COMPOSE_PROFILES` (→ `wg.enabled`), checks the subnet against `PORTCULLIS_POD_CIDR`, `PORTCULLIS_SERVICE_CIDR`, the node IPs, the reserved link subnet and `hub vpn host-info` (instead of `_vpn_docker_subnets`), runs `rt_up`, then generates the people key with `rt_exec wg -- /wg keypair` (private key from a shell variable into `secrets/wg/people.key`, 0640, never argv or a temp file), syncs and `rt_restart wg`. `vpn mode` writes the six entrypoint classes + `PORTCULLIS_VPN_MODE` and runs `rt_up` (break-glass `vpn mode apps` works with the Hub at 0). `vpn add-device` keeps `wg keypair` / `hub vpn add-device` / `wg qr` through `rt_exec`.
- One-shots (K16): `_dns_tool` → `rt_run dns-tool -i` (credentials on stdin); `signin reset-core` → `rt_stop hub`, `rt_run hub -- hub signin reset-core`, `rt_start hub` (same trap); `lldap-ui` → `kube_port_forward lldap 17170`; the `acme.json` reset → a helper pod as Traefik's uid 65532 on `traefik-acme`.
- `backup` (same layout and `MANIFEST.json`):
  - Vault snapshot through `kube_port_forward vault 8200`;
  - `pg_dump -Fc` via `rt_exec`;
  - volumes via an owner-uid helper pod in `portcullis` (restricted-compliant, `PORTCULLIS_HELPER_IMAGE`, the PVC mounted read-only at `/vol`), streaming the tar over exec;
  - plus `secrets/kube/values.yaml`;
  - offsite: the host `restic` binary on kubernetes (≥ 0.19.1, the pinned image's version; refused naming it when missing), never a container (K16).
- `restore`:
  - scale the Hub to 0, and the instances mounting `*-pw` Secrets to 0 (the label `portcullis.io/person-secrets`);
  - empty every `*-pw` Secret;
  - volumes in through the helper (at `/vol`), then the existing guards (LLDAP empty; the Keycloak federation counts from a throwaway postgres pod in `portcullis` — uid 999, `emptyDir` data, the dump on exec stdin — instead of today's `docker run` postgres), then `helm upgrade`;
  - it keeps the host's `CONTAINER_RUNTIME` and `PORTCULLIS_KUBE_*` keys (rootless P6 pattern).
- `cert revoke|sync`: update ConfigMap `certs`, then patch the group-gate pod annotation `portcullis.io/rev`.

- [ ] **Step 1:** Write shell tests:
  - "sync: no secret on argv (stub records argv)";
  - "sync: unchanged hash → no apply";
  - "helm failure → applied.json unchanged";
  - "down never runs helm uninstall";
  - "restore keeps PORTCULLIS_KUBE_* from the host";
  - "restore empties *-pw Secrets before scaling up";
  - "status --json runtime.name = kubernetes, runtime.context set";
  - "rt_up kubernetes: K1 local builds before helm; helm timeout → kube_health_report, applied.json unchanged";
  - "vpn init kubernetes: people key from wg keypair via stdin/variables, never argv (stub records argv)";
  - "vpn init kubernetes: a subnet inside the pod CIDR → refused";
  - "signin reset-core kubernetes: Hub scaled to 0, one-shot run, Hub scaled to 1 (also on failure)";
  - "cert revoke bumps portcullis.io/rev".
- [ ] **Step 2:** Run the core gate. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the core gate. Expected: PASS. Commit (`cli: kubernetes up/upgrade/down/status, secrets + config sync (files only), backup/restore with owner-uid helpers, prompt revocation`).

---

### Task 16: Core CI job `e2e-k3s`

**Files:**
- Create: `.github/ci/e2e-k3s-install.sh` (usable by templates' Test Apps, Task 10: the netns client and `--node-external-ip` only with `--netns-client`; k3s `v1.37.2+k3s1`, binary sha256 `265b3ee6a3198ef14033c63ef46cbb32370d83795199fb6d1b01f21575eddbda`; kubectl `v1.37.2`, sha256 `c04487523e7aa7d1493f7808174c899db93d7a9cf57531420cd76b9bd415f8f4`; the § 6 flags plus `--node-external-ip=198.51.100.1`; the netns `ext` client `198.51.100.2` ⇄ node `198.51.100.1` over a veth, as the spike; wait for the coredns Deployment to exist before waiting on it — spike run 1; the K1 `local` image import), `.github/ci/e2e-k3s-assert.sh`, `tests/e2e/e2e_k3s.py`
- Modify: `.github/workflows/ci.yml` (job `e2e-k3s` after `e2e-vpn`: `runs-on: ubuntu-26.04` (as `e2e-podman`), `timeout-minutes: 90`, `needs: jobs-input`, the name-match `if` copied from `e2e-vpn`, `ACME_STAGING: "true"`, Pebble (`PEBBLE_IMG`) as build-and-test's domains service step; add `e2e-k3s` to the `workflow_dispatch` description list), `CLAUDE.md` (Testing)
- One leg, on the pin. The 1.32 floor is covered by envtest 1.32 (Task 8), `init`'s version refusal and the spike; no floor leg in CI (K-P5).

**Interfaces:**
- Consumes: everything above; the Hub from the same-named branch (built, imported as `localhost/`); templates from the same-named branch, else main; the `tests/e2e/apps/echo` fixture.

- [ ] **Step 1:** Write the job with spec §10's assertions, each failing as `FAIL: <what>`:
  - the probe; PSA restricted in `portcullis` (a privileged pod is rejected);
  - a pod sending `X-Forwarded-Tls-Client-Cert` to `keycloak-internal:8081` gets no X.509 login;
  - spoofed `X-Forwarded-For`/`X-Real-Ip` on websecure are dropped;
  - an app pod can't reach Keycloak :8080, Vault, Postgres, :6443 or :10250;
  - the client IP shows in the access log: `curl -k https://198.51.100.1/` from netns `ext` → `ClientHost` `198.51.100.2` (an address in the `traefik` Service's `status.loadBalancer.ingress`, thanks to `--node-external-ip`); and `status` warns when the public IP is local but not an ingress address (a second, unpublished local address);
  - PVC ownership on the node (`stat -c '%u:%g:%a'` under the local-path root): `postgres-data` = the `CT_*` owner, `wg-data` = `10006:10001:2750`, `vpn-doc` = `10001:10007:2750`, an echo PVC = the service uid; a PVC without the annotations stays `Pending`;
  - sign-in plus the Playwright portal subset;
  - echo deploy/backup/restore/delete through the Hub API;
  - with the Hub's ServiceAccount token: hostPath outside roots, NodePort, a cross-namespace middleware, a foreign helper image, a `vpn-slot` of 47 → all denied, each Status message naming `portcullis-apps-guard-<policy>`; `get` on `pods/exec` → `Forbidden` (`kubectl auth can-i`);
  - the fixer on `/srv`;
  - revocation ≤ 10 s;
  - the Docker → k8s restore round trip inside the job (phase 1 on Docker, as rootless P11, no artifact with secrets);
  - VPN:
    - `vpn init`; a built-in device handshake + GET through `wg-people`;
    - a raw PROXY v2 header to Traefik :8444 (pod IP and `traefik-vpn`) from a non-`wg` pod → refused by policy;
    - an app pod → `wg` :9100 and → another slot's edge port → refused (Review Focus 6);
    - the headscale provider wired as in e2e-vpn (reuse `.github/ci/e2e-vpn-instances-users-headscale-provider-setup.sh`'s steps, kubernetes branch): wg sees the gateway pod's own IP through `wg-edge` (`wg_edge_accepted_total{provider}` rises, no `wrong_gateway`); the gateway pod rescheduled → the provider leaves `vpn.json` and old-IP connections are refused (`wrong_gateway`) until the new IP is published (Review Focus 4, live);
    - `vpn mode admin` then `vpn mode apps` (break-glass with the Hub scaled to 0) move the core routers' entrypoints as on Docker.
  - Failure artifacts: logs and `kubectl get events` only.
- [ ] **Step 2:** Run `actionlint`, `bash tests/lint_ci_size.sh` and `bash tests/test_cli.sh`. Expected: PASS. Commit (`ci: e2e-k3s (real k3s, the § 6 flags; isolation, trust, Hub instances, admission, fixer, revocation, cross-runtime restore, VPN)`).
- [ ] **Step 3 (controller):** Run `gh workflow run ci.yml --ref kube1 -f jobs=unit-tests,e2e-k3s`. Expected: green.

---

### Task 17: Docs pages

**Files:**
- Create: `docs/operations/kubernetes.md`
- Modify: `docs/operations/.nav.yml`, `hardening.md` (Kubernetes section: RBAC tables replacing the socket-proxy table there — the Hub's Role with `create`-only `pods/exec` —, the five VAPs and their bindings, the NetworkPolicy map incl. the VPN port rules, PSA levels incl. `portcullis-storage` baseline, the provisioner helper's three caps, Traefik non-root, the pids delta; no K3 fallback was taken), `backups.md` (host `restic` on k8s), `cli.md`, `testing.md` (`e2e-k3s`, envtest, the k3s Test Apps leg), `hub.md` (runtime badge, compat column, the new doctor kinds), `vpn.md` (`wg` on k8s: one pod, `wg-edge`/`wg-people`, the reserved ranges, `vpn init` key via `wg keypair`; link role and VPN-only API access not on Kubernetes yet), `rootless-podman.md` (a link), `includes/abbreviations.md` (PSA, VAP, CRD)

- [ ] **Step 1:** Write `kubernetes.md`:
  - why to use it;
  - the k3s install line with the flags, pinned `v1.37.2+k3s1` (floor 1.32) and its sha256, and `--node-external-ip=<public IPv4>` when the public IP is a secondary local address (otherwise client IPs are SNATed to the svclb pod: Task 0 Q1);
  - prerequisites (§6, K8, K10);
  - `init --runtime kubernetes --kube-context`;
  - migration (backup → init → restore);
  - the compatibility table;
  - images (K1);
  - troubleshooting (probe, admission — the Status message names `portcullis-apps-guard-<policy>` —, CIDR drift, source IP and `--node-external-ip`, a PVC `Pending` with `portcullis-setup REFUSED`).
- [ ] **Step 2:** Run the docs gate. Expected: PASS. Commit (`docs: Kubernetes operations page, hardening/backups/cli/testing/hub/vpn updates`), then resync Hub `web/docs` and commit.

---

### Task 18: Full CI, merges, deploys, cleanup

**Files:** none new.

- [ ] **Step 1 (controller):** Run full core CI on `kube1`, Hub `build.yml` (with envtest), and templates lint + Test Apps on `kube1`. Expected: all green.
- [ ] **Step 2:** Merge docs, then the Hub (the rest of `kube1`). Wait for `edge`. Then merge templates `kube1` and core **without a pause** (the window in Global Constraints). Wait for `images.yml` to publish the five `:edge` images, then re-run core CI on main (`e2e-k3s` with `PORTCULLIS_KUBE_IMAGES=registry`) and templates Test Apps on main.
- [ ] **Step 3:** Do Task 10 (templates `kube2`) and merge it.
- [ ] **Step 4: The Docker test server** (`ACME_STAGING=true` stays):
  - record `./portcullis status --json` and every app host's answer;
  - `git pull --ff-only && ./portcullis upgrade`;
  - check that status is clean, the instances were recreated with `_SOURCE` in their env, header-auth apps still sign in (grafana, a craft app), and the VPN setup kept since vpn1 still holds (built-in VPN on; oxicloud `drive.<domain>` opens only over the VPN);
  - take a fresh `./portcullis backup`.
- [ ] **Step 5: The Kubernetes VM** (K12; the user provides SSH access and opens 80/443/51820 in its firewall):
  - install k3s with the documented line;
  - clone core, then `./portcullis init --runtime kubernetes --kube-context default`, set `ACME_STAGING=true` and run `config apply` + `up` (memory: staging certs on test servers);
  - restore the Docker backup (it carries the VPN key and `COMPOSE_PROFILES` with `wg`; restore keeps the VM's `CONTAINER_RUNTIME`/`PORTCULLIS_KUBE_*`);
  - live checks: sign-in by passkey and by certificate, the portal, two instances (one header-auth), a public link, a VPN device from the user's phone (a new device config: the endpoint is the VM's address) opening the VPN-only app, `status` clean apart from the K8 Warning if the API is public and the source-IP warning if `--node-external-ip` was needed and not set;
  - `cert revoke` of a test cert takes effect within 10 s.

  Never touch LLDAP `admin`.
- [ ] **Step 6: Clean up:**
  - delete the `kube1`/`kube2` branches (local + `git push origin --delete`) in every repo;
  - `git worktree remove` every `wt-kube1/*` and `/tmp/merge-*`, then `git worktree prune`;
  - remove `/tmp/pk-*`.

---

## Self-review (done while writing)

- **Spec coverage:**
  - §3 → Tasks 11, 15;
  - §4 → Tasks 2, 4–8;
  - §5 → Tasks 7, 13;
  - §6 → Tasks 11, 14;
  - §7 → Tasks 8, 14;
  - §8 → Tasks 3, 9;
  - §9 → Tasks 6, 15;
  - §10 → Tasks 8, 10, 13, 16;
  - §11 → Tasks 1, 17;
  - §12 item 10 → Task 18;
  - §13 Q1/Q2 → Task 0, Q3 → Task 10, Q4 → Task 3, Q5 → Task 0.

  Gaps the spec left open are settled in K1 (no builder on k3s), K4 (copy-up), K5 (gateway addresses) and K6 (the self-test cause); the 2026-11-13 amendment adds K15 (core names from app routers), K16 (CLI one-shots) and K17 (start periods), and the pre-flight rulings K-P1…K-P30 (`.superpowers/sdd/2026-11-14-kubernetes/preflight.md`).
- **Types:**
  - `runtime.Instances` (Task 2) is used unchanged by Tasks 5–8.
  - `Translate`/`Plan`/`ErrRefused` (Task 4) by Tasks 5 and 7.
  - `kube.Guard` (Task 8) gates the Task 5 backend.
  - `RuntimeCompat(rt, …)` (Task 3) by Tasks 4 and 9.
  - `portcullis-admission-params` is written by Task 14 and read by Task 8's policies.
  - `portcullis-netpol-probe` is written by Task 11 and read by Task 8.
  - `hub rev <dir>` (Task 6) is the argv Task 5's delivery poll execs (Task 5's tests fake the exec).
  - The three fixed ClusterIPs and `PORTCULLIS_WG_EDGE_SERVICE_IP` in core.env are written by Task 11, rendered by Task 13, read by Tasks 4/7 (`Settings.WGEdgeServiceIP`).
- **Proportion:** there are no function bodies, only signatures, values and test names.
