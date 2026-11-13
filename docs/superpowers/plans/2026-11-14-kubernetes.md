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

**Spec:** `/Volumes/workspace/portcullis/portcullis-hub/docs/superpowers/specs/2026-11-13-kubernetes-design.md` (binding). §13 open questions take their defaults: Q1 is ServiceLB with `externalTrafficPolicy: Local`, proven in Task 0 (if it fails, the hostNetwork fallback the spec names); Q2 is a pinned upstream provisioner (the mechanism is fixed in Task 0, ruling K3); Q3 keeps routed ports Traefik-only; Q4 is "degraded: connect by address"; Q5 is floor 1.32. Related plans: `2026-11-13-rootless-podman.md` (`CONTAINER_RUNTIME`, the guard, the compat gate) and `2026-11-13-vpn-only-access.md` (the `wg` service, `vpnsecure`, `vpn.json` v2). Their structure is copied here.

## Global Constraints

- **Base.** VPN-only access (`vpn1`) must be merged to `main` in all four repos first. If it isn't, stop and wait. Never base on `vpn1`.
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
  - A VPN gateway pod with no observed IP → its provider is published with no `gateway_ip` match, so the edge refuses (`wrong_gateway`) until the Hub has seen it.
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
- **The Podman quirks stay handled in the docker backend** (Task 2 moves code, not behaviour):
  - `ListNetworks` doesn't rely on `IPRange` in inspect;
  - archive copies treat the tar root as `/`;
  - `runtime_build_local` keeps `--format docker` (HEALTHCHECK).
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
  - k3s ≥ **Kubernetes 1.32**, installed with `--disable=traefik --secrets-encryption --kubelet-arg=pod-max-pids=1024`, the network policy controller on and ServiceLB on.
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

## Plan rulings (assistant's calls beyond the spec, binding)

- **K1 — core-built images on k8s.**
  - The five images built locally on Docker (`group-gate`, `enroll`, `domains`/`dns-tool`, `mcp-gate`, `wg`) are published by core CI like the forwarder: new `.github/workflows/images.yml`, `:edge` from main, `:X.Y.Z` at release, cosign keyless, no `latest`.
  - The CLI resolves every tag (these five, Hub, Keycloak) to a digest at `up`/`upgrade`, and the chart only ever sees `name@sha256:…`.
  - `.env` `PORTCULLIS_KUBE_IMAGES=registry|local` (default `registry`). `local` builds them from the checkout with `docker build` or `podman build --format docker` and imports them with `sudo k3s ctr -n k8s.io images import` under `localhost/portcullis-<svc>@sha256` with `imagePullPolicy: Never`. CI and development use it; `status` shows it.
  - Why: k3s has no builder, and a pinned registry digest keeps "fully qualified pinned images" true.
- **K2 — the Hub's Role.** The spec's list plus `create` on `pods`, which helper pods need. Exec verbs are the minimum envtest proves for client-go's executor (WebSocket with SPDY fallback): `create` on `pods/exec`, plus `get` only if envtest shows it is needed. Nothing cluster-scoped. Core keeps the Role YAML in the chart, and the Hub keeps a byte copy in `internal/runtime/kube/testdata/role.yaml`, compared in core CI.
- **K3 — volume ownership.** Task 0 decides between two mechanisms and records the result here:
  - **(a)** the StorageClass `pathPattern` carries the PVC annotation `portcullis.io/owner: "<uid>-<gid>-<mode>"`, and the provisioner's `setup` script parses it from `VOL_DIR` and runs `mkdir -m <mode>` + `chown`;
  - **(b)** for `portcullis-core` only, a name table the CLI renders from the `CT_*` values, keyed by `{{.PVC.Namespace}}_{{.PVC.Name}}`.

  Apps PVCs need (a). If (a) fails, apps PVCs get a root `CHOWN`-only init container (baseline caps, allowed in `portcullis-apps`), and hardening.md lists it. No chown helper runs in `portcullis`.
- **K4 — Docker volume copy-up.** Docker copies image content into a new named volume, and PVCs don't. For each named volume, the translator adds two init containers:
  - `portcullis-bin`: the Hub image by digest; it copies the static `/usr/local/bin/hub` into an `emptyDir`;
  - `portcullis-seed`: the service's own image and user; it runs `/portcullis-bin/hub seed <target> /portcullis-seed`, which copies the image's directory into the PVC only when the PVC is empty and writes `.portcullis-seeded` last.

  No shell is needed in the app image. Ownership is the service's uid, and the CI leg flags any template where Docker's copy-up gives a different owner.
- **K5 — the VPN gateway address on k8s.** `vpn.json` v2 is unchanged. The Hub watches the ingress pod of each wired provider and writes its current pod IP as `gateway_ip`. Until it has seen one, it writes `""`, which the edge rejects (`wrong_gateway`). The chart has one static ingress rule per edge port `9001+n` on the `wg` pod, from `portcullis-apps` pods labelled `portcullis.io/vpn-slot: "<n>"`. The VAP admits that label only as an integer 0–46, and only on a pod that also carries `portcullis.io/instance`. The per-pod binding is the edge's `gateway_ip` match: the Hub can't write in `portcullis`, so there is no per-slot params object.
- **K6 — admission self-test.** The Hub dry-runs (`dryRun=All`, server side) a forbidden Pod **and** a forbidden Deployment in `portcullis-apps`. The test passes only when each is rejected with an `Invalid`/`Forbidden` status whose message names the binding `portcullis-apps-guard`. A rejection by RBAC, quota or another webhook counts as "guard missing". The VAPs match `pods`, `deployments` and `jobs` (pod templates at `spec.template.spec`), so the Deployment dry-run reaches them.
- **K7 — `wg` on k8s.**
  - One Deployment, `Recreate`, uid 10006, PSA restricted, netstack (no caps).
  - The people UDP port is a LoadBalancer Service `wg-people` (ETP `Local`).
  - Edge ports are on the pod IP: its own policy, its own `wg-data` PVC, `vpn-doc` read-only, no `hub-data`.
  - `portcullis-vpn-edge` becomes the policy "`wg` → Traefik :8444 only", and `vpnsecure`'s `PROXYPROTOCOL_TRUSTEDIPS` = the pod CIDR (second layer).
  - **No link objects:** the multi-server plan adds the `wg-link` Service and its policy.
  - The kube API is never reachable through `wg`.
- **K8 — `:6443`/`:10250` on the public address.** `status` warns when either answers on the node's external address ("restrict it in the firewall"). It is never a refusal: firewalls are the user's.
- **K9 — `_SOURCE` consumers.** Task 9 Step 1 lists every one of the 84 template files and the setting each one feeds. A setting that can't take a CIDR gets the existing nginx gate pattern (esphome `gate.sh`) in front, never a wider rule.
- **K10 — IPv4 single-stack only.** `init`/`runtime_check` refuse a cluster whose pod or service CIDR list has an IPv6 entry.
- **K11 — ownership.** `init --runtime kubernetes` refuses to adopt an existing `portcullis` or `portcullis-apps` namespace unless it has the label `app.kubernetes.io/managed-by: portcullis` and the annotation `portcullis.io/install: <uuid>` equal to `.env` `PORTCULLIS_KUBE_INSTALL_ID` (generated at init).
- **K12 — the Kubernetes test VM** is provided by the user (SSH details given at Task 18). The Docker test server is not converted. Its fresh backup is copied to the VM by the operator (scp, 0600) for the cross-runtime restore.
- **K13 — VAP and Role vectors are authored in the Hub** (`internal/runtime/kube/testdata/admission/*.yaml`, `role.yaml`, `admission_vectors.json`). Core keeps byte copies under `kube/admission/` and checks them in unit-tests against the same-named Hub branch, like the `vpn.json` vectors.
- **K14 — Traefik CRDs.** The pinned Traefik CRD bundle (`charts/portcullis/crds/traefik-<version>.yaml`) is applied by `init`/`upgrade` with `kubectl apply --server-side`, never by Helm. Its version follows the compose Traefik image, and the parity test checks it.

## Review Focus

1. **The admission guard passes its self-test for the wrong reason.** On a cluster where the VAPs are missing but RBAC, a quota or a foreign webhook rejects the probe, the Hub must still report `admission_guard_missing` and refuse deploys. Pinned by `TestSelfTestRequiresPolicyRejection` (Task 8, envtest with the VAPs absent and a deny-all webhook).
2. **Compose names that aren't DNS-1123.** Service names like `my_db` and `my-db` (or `My-DB`), or an instance + service longer than 63 characters, must not collide after normalisation or truncation. The instance is refused with both names, and no object is applied. Pinned by `TestTranslateNameCollisionRefused` (Task 4).
3. **An object over the 1 MiB API limit.** A template directory, an appfile or a `*-pw` Secret for a large group past 1 MiB must be refused with a named reason before anything is applied. Pinned by `TestTranslateObjectTooLargeRefused` (Task 4) and `TestPersonSecretTooLargeRefuses` (Task 5).
4. **A wired VPN gateway pod is rescheduled and gets a new IP.** The edge must refuse the old IP at once and admit only after the Hub has published the new one, with no window where any address is accepted. Pinned by `TestGatewayIPFollowsPod` (Task 7).
5. **The kube context points at a cluster with leftover or foreign Portcullis namespaces** (an old install, another operator's). `init` must refuse to adopt them unless the install id matches. Pinned by the shell test "init kubernetes: foreign portcullis namespace → refused" (Task 11).

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

### Task 0: Spike (core `kube1`, throwaway)

**Files:** Create and later delete `.github/workflows/spike-k3s.yml` and `.github/ci/spike-k3s.sh`. Results go into this plan's rulings K3 and Q1 (one commit on Hub `kube1`).

**Interfaces — Produces:** the pinned k3s version and its sha256 (the newest 1.3x patch ≥ 1.32), the pinned local-path-provisioner version, K3's chosen mechanism, the Q1 outcome, and the minimal exec verbs (K2).

- [ ] **Step 1:** Write `spike-k3s.sh`. It runs on `ubuntu-26.04`:
  - install k3s with the § Global Constraints flags (binary sha256 checked);
  - create netns `ext` with a veth, client `198.51.100.2`, node side `198.51.100.1`;
  - deploy a non-root Traefik on `:8443` behind `LoadBalancer` ETP `Local`, then `curl -k https://198.51.100.1/` from `ext`;
  - grep the access log for `198.51.100.2`;
  - with the pinned provisioner: create a PVC with `portcullis.io/owner: "10001-10001-0750"` and check `stat -c '%u:%g:%a'` on the node = `10001:10001:750` (mechanism a); then the same through mechanism b;
  - create a ServiceAccount with K2's Role, run client-go's executor via `kubectl --as=system:serviceaccount:…` exec, and record the verbs it needs;
  - apply one VAP using every CEL function Task 8 needs (`matches`, `all`, `exists`, `startsWith`, `params`) and record whether 1.32 accepts it.
- [ ] **Step 2 (controller):** Run `gh workflow run spike-k3s.yml --ref kube1`. Expected: one summary line per item, each `OK` or `FAIL <why>`.
- [ ] **Step 3:** Record the results in K2/K3/Q1:
  - if the source IP isn't preserved, switch Traefik to `hostNetwork` on :80/:443 (non-root, `NET_BIND_SERVICE` only), the spec's fallback. PSA is per namespace and even `baseline` forbids `hostNetwork`, so Traefik moves to its own namespace `portcullis-edge` (`enforce: privileged`). A VAP there admits exactly the Traefik pod spec, and `portcullis` stays `restricted`. Tasks 1, 13 and 14 follow;
  - if 1.32 lacks a CEL function, raise the floor.

  Delete both spike files, then commit on core (`spike: k3s source IP, PVC ownership, exec verbs, CEL on 1.32 (results in the plan)`) and on Hub (`plan: kubernetes — Task 0 results`).

---

### Task 1: Contract (docs, first)

**Files:**
- Modify: `docs/guides/integration-contracts.md`: §2, §3, §5, §6, §11 (incl. §11.10), §13.6–§13.8, §13.15, §14.5, §16
- Modify (Hub): `web/docs/*` via `sync.sh`

**Interfaces — Produces (binding for Tasks 2–17):**
- **§2:**
  - `PORTCULLIS_TRAEFIK_SOURCE` is the CIDR of the only peers that may send identity headers. Default form `${PORTCULLIS_TRAEFIK_SOURCE:-172.31.250.2/32}`, always combined with "only that peer can connect".
  - `PORTCULLIS_MCP_GATE_SOURCE` uses the default form `${PORTCULLIS_MCP_GATE_SOURCE:-172.31.250.3/32}`.
  - `PORTCULLIS_TRAEFIK_IP` and `PORTCULLIS_MCP_GATE_IP` leave the template table (still core variables, refused in templates).
  - `PORTCULLIS_RUNTIME_ROOTS` and `PORTCULLIS_KUBE_*` are core.env-only, not template variables.
- **§3 "Compose on Kubernetes":** the refused features with their reasons (the Task 3 strings); `…@docker` middleware names are translated to `…@file`; replicas > 1, `deploy:` and non-numeric `user:` are refused; the K4 seed init containers.
- **§5:**
  - IngressRoutes, one per router; the `@file` shared middleware list (`portcullis-auth`, `portcullis-auth-ext`, `portcullis-groups`, `client-headers`, `client-cert-pem`, `security-headers`, `rate-limit`, `rate-limit-*`, plus the VPN `-vpn` twins);
  - `kcinternal` (`:8081`, `strip-forwarded@file` removes `X-Forwarded-*`, `Forwarded`, `X-Real-Ip`, `X-Forwarded-Tls-Client-Cert*`);
  - routed ports open only to Traefik.
- **§6 "Engine access":** a Kubernetes subsection containing:
  - the Role table (K2);
  - "nothing in `portcullis`";
  - helper pods (`hub helper idle`, `hub volcopy out|in <path>`, `hub folderfix <mode>` over exec; label `portcullis.io/helper`; image = `HUB_SELF_IMAGE`; caps per mode unchanged);
  - `*-pw` Secrets replace the `hub_secrets` subpath (exactly one instance+option's `<user>.nt` keys, mounted read-only);
  - the admission self-test (K6) and its 503.
- **§11:**
  - object naming (Global Constraints) and PVCs;
  - the backup format is unchanged (container ids in tarballs);
  - §11.10 becomes "Runtime compatibility", with `GET /api/runtime` gaining `kind: kubernetes`, `context`, `version`, `admission`, `netpol`.
- **§13.6–13.8:**
  - ConfigMap/Secret deliveries carry a `.rev` key;
  - the Hub bumps the pod annotation `portcullis.io/rev` and waits for the mounted `.rev` before running hooks;
  - reload = exec `kill -s <SIG> 1`, and with no `kill` in the image a pod restart (state `reload_degraded`).
- **§13.15:** `lan_only` → `loadBalancerSourceRanges` = Local networks.
- **§14.5:** new kinds `netpol_not_enforced` (Problem), `admission_guard_missing` (Problem), `cluster_unverified` (Problem), `reload_degraded` (Info) and `kube_api_public` (Warning, K8). Forbidden roots come from `PORTCULLIS_RUNTIME_ROOTS`.
- **§16 "On Kubernetes":** K5 (`gateway_ip` = the live pod IP, `""` until seen), K7, the per-slot edge policy and the label `portcullis.io/vpn-slot`. `vpn.json` stays v2.

- [ ] **Step 1:** Write the sections in the contract's style ("NEW (Kubernetes)" markers).
- [ ] **Step 2:** Run the docs gate. Expected: exit 0.
- [ ] **Step 3:** Commit (`docs: contract for Kubernetes (_SOURCE variables, compose on k8s, IngressRoutes + kcinternal, the Hub's Role and helper pods, *-pw Secrets, .rev deliveries, runtime compat, doctor kinds, wg on k8s)`) with the base SHAs, then push `kube1`.
- [ ] **Step 4:** Resync Hub `web/docs` (only `integration-contracts.md` changes), commit (`docs: sync contract`) and push.

---

### Task 2: Hub `internal/runtime` and the docker backend (no behaviour change, merged alone)

**Files:**
- Create: `internal/runtime/runtime.go`, `internal/runtime/types.go`, `internal/runtime/docker/backend.go`, `internal/runtime/docker/backend_test.go`, `internal/runtime/runtimetest/fake.go`
- Modify: `internal/hub/hub.go` (`New(cfg, rt runtime.Instances, idp)`; drop `Engine` and the `compose`/`engine` fields), the 24 `internal/hub` files with `h.engine.*` / `h.compose.*`, every `internal/hub/*_test.go` fake (to `runtimetest.Fake`), `cmd/hub/main.go`, `CLAUDE.md`

**Interfaces — Produces:**

```go
package runtime
type Kind string // "docker" | "podman" | "kubernetes"
type Project struct{ Name, Instance string; Files compose.Project; Model *types.Project } // Model: interpolated, profiles applied (the Hub's existing loader)
type Filter struct{ Instance, Service string; Helper bool; All bool }
type Instances interface {
	Kind() Kind
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
  - `VolumeOut`/`VolumeIn` wrap today's helper create + archive copy + remove. `Info` folds `SecurityOptions`, `DockerRootDir` and `APIVersion` together with the guard state.
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
- Modify: `internal/hub/rootless.go` → `internal/hub/compat.go`, `internal/httpapi/runtime.go`, `web/apps.js`, `web/index.html`, `CLAUDE.md`

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
- `GET /api/runtime` adds `kind`, `context`, `version`, `admission` (`ok|missing|unknown`) and `netpol` (`proven|unproven`). No new MCP tool (the `get_runtime` twin covers it).

- [ ] **Step 1:** Write vectors: netbird refused (host); scrutiny refused (devices + SYS_RAWIO); zigbee2mqtt with an empty slot degraded; guacamole refused if its caps are outside the baseline, else ok; timemachine with `avahi_services_dir` set degraded, empty ok; echo ok; `user: "app"` refused. Write `TestRuntimeCompatKubernetes` reading them, and extend `TestRuntimeAPI` for the new fields.
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
  - `func Translate(in Input) (Plan, error)`, with `Input{Instance, Template, Namespace string; Model *types.Project; Digests map[string]string; TemplateFiles map[string][]byte; AppFiles map[string]AppFile; PersonSecrets map[string]map[string][]byte; BindRoots []string; HubImage string; VPNSlot *int; IngressService string; Settings Settings}` and `Settings{PodCIDR, TraefikServiceIP, Domain string; CorePorts []int; LocalNetworks []string}`.
  - `Plan{Steps []Step}`, `Step{Objects []*unstructured.Unstructured; Wait WaitKind}`, with `WaitKind` one of `WaitNone | WaitReady | WaitComplete`. The order follows `depends_on` (healthy → `WaitReady`, completed → `WaitComplete`).
  - `func ObjectName(instance, service string) string`: lowercase, `_`/`.` → `-`, `-<hash8>` (sha256 of the original pair) past 63.
  - `ErrRefused{Reason string}`.
- Mapping (spec §4, exact):
  - `CMD-SHELL x` → exec probe `["sh","-c",x]`, and `CMD a b` → `["a","b"]`;
  - `interval`/`timeout`/`retries`/`start_period` → `periodSeconds`/`timeoutSeconds`/`failureThreshold`/`initialDelaySeconds` for readiness; liveness gets `failureThreshold × 2`;
  - `tmpfs: path:size=N,mode=M` → `emptyDir{medium: Memory, sizeLimit: N}` (mode is a reviewed delta: unshared, per container);
  - `mem_limit` → limits = requests;
  - `environment` → Secret `<instance>-env` (`envFrom`);
  - images → `Digests[ref]` (unresolved = refuse);
  - `seccompProfile: RuntimeDefault` and `automountServiceAccountToken: false` always;
  - `stop_signal` → `preStop` exec `kill -s <sig> 1`;
  - K4's two init containers per named volume;
  - `network_mode: service:x` → an extra container in `x`'s pod;
  - `ports:` → Service `LoadBalancer` with `externalTrafficPolicy: Local`, and `lan_only` → `loadBalancerSourceRanges`.

- [ ] **Step 1:** Write the goldens and these tests:
  - `TestTranslateGoldens`;
  - `TestTranslateNameCollisionRefused` (`my_db` + `my-db` → `ErrRefused` naming both; an instance id of 40 chars + a service of 30 → hashed, distinct, ≤ 63);
  - `TestTranslateObjectTooLargeRefused` (a template file set of 1 MiB + 1 byte → refused `template files for <id> exceed 1 MiB`);
  - `TestTranslateLabelsOnlyFromTranslator` (a compose label `portcullis.io/net-portcullis: "true"` stays an annotation, never a pod label);
  - `TestTranslateNoSecretInPodSpec` (no env value appears in any Deployment);
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
  - `Create` = apply with replicas 0. `Up` = replicas 1 through the plan's steps. `Down` = delete by label. `DownByName` works from labels alone.
  - `Unit.ID` = `<pod name>/<container>`.
  - `Signal` = exec `kill -s <SIG> 1`. On `executable file not found`, it falls back to deleting the pod (Deployment recreates it) and returns `ErrReloadDegraded`, which the Hub records as `reload_degraded`.
  - `onPull` gets `sized=false` from `Pulling`/`Pulled` events.
  - `deliver.go`: `func (b *Backend) Deliver(ctx, instance string, obj DeliveryObject, rev string) error` updates the ConfigMap/Secret with key `.rev`, patches the pod annotation `portcullis.io/rev: <rev>`, then polls `exec cat <mount>/.rev` every 250 ms up to **10 s**. It returns only when the copy matches; the caller records `rev` only then.

- [ ] **Step 1:** Write these tests:
  - `TestUpAppliesStepsInOrder` (a Job dependency is applied and completes before its dependents);
  - `TestApplyNeverTouchesForeignObjects` (an object without the instance label is never force-applied);
  - `TestDeliverWaitsForRev` (mounted `.rev` stale for 3 polls → not recorded; matching → recorded);
  - `TestDeliverTimeoutLeavesRevUnrecorded` (10 s with no match → error, rev not recorded);
  - `TestSignalFallsBackToRestart`;
  - `TestPersonSecretTooLargeRefuses` (`*-pw` over 1 MiB → refused, nothing applied);
  - `TestDigestCachedOnlyAfterDeploy` (a resolve followed by a failed `Up` leaves no cached digest).
- [ ] **Step 2:** Run `go test ./internal/runtime/kube/`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the Hub gate. Expected: PASS.
- [ ] **Step 5:** Commit (`hub: kube backend (server-side apply, ordered steps, status/logs/exec/signal/events, digest pinning, .rev deliveries within 10 s)`).

---

### Task 6: Hub helper pods, instance backups and restore, folder fixer

**Files:**
- Create: `cmd/hub/helper.go` (`hub helper idle|listen <addr>|dial <ip:port>`, `hub volcopy out|in <path>`, `hub seed <src> <dst>`), `internal/runtime/kube/helpers.go` + tests
- Modify: `cmd/hub/main.go` (dispatch these before any env read, like `folderfix`), `internal/hub/fixer.go` (self image from `HUB_SELF_IMAGE` under kubernetes), `internal/hub/backup.go`, `restore.go` (no change to the format)

**Interfaces:**
- Produces:
  - Helper pod `hub-helper-<rand8>` in `portcullis-apps`:
    - image `HUB_SELF_IMAGE` (digest), main process `hub helper idle`, labels `portcullis.io/helper: "true"` + `portcullis.io/instance`;
    - no network label (deny-all), `automountServiceAccountToken: false`, read-only root, caps per contract §6 mode, run as `0:0` only for the fixer modes;
    - mounts exactly one PVC or one `hostPath` (`Directory`) under the bind roots.
  - `VolumeOut`/`VolumeIn` exec `hub volcopy out|in /v` and stream the tar on stdout/stdin (cap: the existing backup limits). `RunFixer` execs `hub folderfix <mode> …` and parses the same report.
  - Task 8's probe pods are the one exception to deny-all. They carry `portcullis.io/probe: "deny"|"allow"`, no `portcullis.io/instance` and no volume. Their policies select only that label, and the VAP admits the label only on pods running `HUB_SELF_IMAGE` with command `hub helper listen|idle`.
  - Helpers are deleted always (`defer`, background context) and swept at Hub start by label.
  - `hub seed` copies `src/.` into `dst` only when `dst` has no entries but `lost+found`, preserving modes and symlinks. It writes `.portcullis-seeded` last and exits 0 if that file already exists.

- [ ] **Step 1:** Write these tests:
  - `TestVolcopyRoundTrip` (out → in on temp dirs; ownership as the caller);
  - `TestSeedOnlyWhenEmpty`;
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
- Modify: `internal/hub/override.go` (render labels as today; the kube backend converts them), `internal/hub/reconcile.go` (exposure drift via `Backend.LiveExposure`), `internal/hub/vpn_publish.go` (K5), `internal/hub/vpn_render.go`

**Interfaces:**
- Produces:
  - `func IngressObjects(instance string, labels map[string]map[string]string) ([]*unstructured.Unstructured, error)`:
    - one `IngressRoute` per `traefik.http.routers.<r>` with its entrypoints, rule, priority, `tls.options` and middlewares;
    - a `Middleware` per `traefik.http.middlewares.<m>`, which may not be `forwardAuth` or set `X-Portcullis-*`;
    - `…@docker` → `…@file` when on the Task 1 allowlist, own-namespace refs otherwise, anything else refused;
    - `Service` refs stay in-namespace.
  - `func InstancePolicies(instance string, p Plan, vpnSlot *int) []*unstructured.Unstructured`:
    - per compose network `N`: same-label ingress/egress;
    - routed ports: ingress only from `namespaceSelector{kubernetes.io/metadata.name: portcullis}` + `podSelector{portcullis.io/component: traefik}`;
    - companion ports: the same with `mcp-gate`;
    - `internal: false` → the egress rule `0.0.0.0/0` except pod/service CIDRs, `169.254.0.0/16` and the node IPs, plus a node-IP rule for 80/443 only;
    - DNS egress to kube-dns :53;
    - a wired gateway: egress to `wg` on `9001+slot` only.
  - `func (b *Backend) LiveExposure(ctx, instance string) (Exposure, error)`, compared with the desired set by the existing drift code.
  - K5: `vpnGatewayIPs(ctx) map[string]string` from a pod watch on `portcullis.io/vpn-slot`, feeding `vpn.json` `gateway_ip`. Republish when it changes; `""` until a Running+Ready pod has an IP.

- [ ] **Step 1:** Write these tests:
  - `TestIngressGoldens` (forward-auth, oauth2, public link, MCP, extra domain, `vpnsecure` + `portcullis-vpnallow-<id>` first in the chain);
  - `TestCrossNamespaceMiddlewareRefused`;
  - `TestForwardAuthMiddlewareRefused`;
  - `TestPolicyRoutedPortTraefikOnly`;
  - `TestPolicyEgressExcludesClusterAndNode`;
  - `TestGatewayIPFollowsPod` (pod IP A published; pod rescheduled → `""` published before B is seen; then B; A is never republished).
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
    - (2) `SelfSubjectRulesReview` equals K2's Role exactly (no more, no less);
    - (3) the admission self-test (K6) passes;
    - (4) its own NetworkPolicy probe: two helper pods (`hub helper listen :8080`), one behind a deny policy and one behind an allow policy, with `hub helper dial <ip:port>` exec'd from a third pod. It passes only when the denied dial fails and the allowed one succeeds. ConfigMap `portcullis-netpol-probe` (the CLI's result) is shown in `/api/runtime` but is never enough by itself.

    Until all four hold, every `Instances` method but `Kind`/`Info` returns `ErrClusterUnverified` (503 `the cluster is not verified: <why>`).
  - `admission_vectors.json` entries `{name, object, as: "hub", want: "allow"|"deny", reason_contains}`, covering spec §7's list, one or more each, plus the K5 slot label range.
  - Doctor kinds from Task 1 §14.5.

- [ ] **Step 1:** Write these tests:
  - `TestGuardFailsClosed` (each check failing alone → 503 with its why);
  - `TestRoleExact` (an extra verb in a fake rules review → unverified);
  - `TestSelfTestRequiresPolicyRejection` (envtest: VAPs absent + a deny-all validating webhook → `admission_guard_missing`; VAPs present → ok);
  - `TestAdmissionVectors` (envtest, each vector as the Hub's ServiceAccount through impersonation);
  - `TestRoleIsEnough` (envtest: the full echo deploy, exec, logs, helper, delete with exactly `role.yaml`).
- [ ] **Step 2:** Run `go test -tags envtest ./internal/runtime/kube/` with `KUBEBUILDER_ASSETS`. Expected: FAIL.
- [ ] **Step 3:** Implement the guard, the wiring, the CEL policies (`ValidatingAdmissionPolicy` `portcullis-apps-{pods,workloads,services,traefik,netpol}`, binding `portcullis-apps-guard` with `paramRef` to ConfigMap `portcullis-admission-params`, `validationActions: [Deny]`, `failurePolicy: Fail`) and the doctor kinds.
- [ ] **Step 4:** Run the Hub gate plus envtest, then `gh workflow run build.yml --ref kube1`. Expected: PASS / green.
- [ ] **Step 5:** Commit (`hub: kubernetes runtime (in-cluster guard: namespace, exact Role, admission self-test, netpol probe; fail closed), doctor kinds, envtest RBAC + VAP vectors`).

---

### Task 9: Templates: `_SOURCE` switch, gate CIDR checks, validator kubernetes column

**Files:**
- Modify: the 84 files that reference `PORTCULLIS_TRAEFIK_IP` and the 4 that reference `PORTCULLIS_MCP_GATE_IP`; every `*/gate.sh` and the craft `nginx.conf`s; `grafana/portcullis/trust.sh`, `tests/trust/test_grafana_trust.sh`; `tests/validate.py`, `tests/test_validate.py`, `tests/runtime_vectors.json` (renamed byte copy), `tests/rootless.txt` → `tests/runtime.txt`, `CONTRIBUTING.md`, `CLAUDE.md`

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
  - the vectors comparison with the Hub (`kube1`, else main);
  - `test_grafana_trust.sh` with a CIDR.
- [ ] **Step 3:** Run the templates gate. Expected: FAIL.
- [ ] **Step 4:** Implement the switch, the gates and the classifier.
- [ ] **Step 5:** Run the templates gate. Expected: PASS. Commit (`templates: PORTCULLIS_TRAEFIK_SOURCE / _MCP_GATE_SOURCE (CIDR), gate CIDR checks, kubernetes compat column`) and push. Run lint.yml and Test Apps (Docker) on `kube1`. Expected: green.

---

### Task 10: Templates `kube2`: the k3s Test Apps leg (after the core merge)

**Files:**
- Modify: `.github/workflows/test-apps.yml` (matrix `runtime: [docker, kubernetes]`; the kubernetes leg skips templates whose compat is `refused`), `tests/apps/lib.sh` (runtime-neutral `app_exec`, `app_logs`)
- Create: `tests/apps/lib-k3s.sh` (installs k3s through core's `.github/ci/e2e-k3s-install.sh` from core main and runs `./portcullis init --runtime kubernetes`)

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
- Modify: `scripts/lib/runtime.sh` (`runtime_name` accepts `kubernetes`), `common.sh` (`rt_*`), every `scripts/lib/*.sh` + `portcullis` call site of `dc`/`docker`, `tests/test_shell_libs.sh`, `tests/test_cli.sh`, `.env.example`, `CLAUDE.md` (the `rt_*` rule)

**Interfaces — Produces (bash):**
- `rt_up [svc…]`, `rt_down`, `rt_exec [-i] <svc> -- <argv…>`, `rt_logs <svc> [--tail N]`, `rt_ps [--json]`, `rt_volume_out <volume> <path>` (tar on stdout), `rt_volume_in <volume> <path>` (tar on stdin), `rt_restart <svc>`. On docker/podman these are today's `dc`/`docker` code, moved.
- `kube_ctl …` = `kubectl --context "$PORTCULLIS_KUBE_CONTEXT" …` (never without `--context`), `kube_helm …` the same for `helm --kube-context`.
- `kube_detect_cidrs` sets `_K_POD_CIDR` (the node's `spec.podCIDRs`), `_K_SVC_CIDR` and `_K_API_EP` (the `default/kubernetes` EndpointSlice). `_K_SVC_CIDR` comes from a server dry-run Service with `clusterIP: 0.0.0.1`, whose rejection names the valid range; an unparsable answer is refused.
- `kube_host_checks` prints `_rt_chk` rows for the † items of spec §6, K8, K10 and K11.
- `kube_netpol_probe` applies `kube/probe/*`. It passes only when the denied dial fails **and** the allowed dial succeeds; then it writes ConfigMap `portcullis-netpol-probe` (`proven_at`) in `portcullis-apps` and deletes the probe namespace.
- `kube_port_forward <svc> <port>` is a background port-forward on a random local port; it prints the port and the trap kills it.
- `init --runtime kubernetes --kube-context <ctx>` writes the keys from Global Constraints plus `PORTCULLIS_KUBE_INSTALL_ID` (`uuidgen`) and `PORTCULLIS_KUBE_IMAGES=registry`.

- [ ] **Step 1:** Write shell tests (kubectl/helm stubs in the style of the docker stubs):
  - "need_env: kubernetes without PORTCULLIS_KUBE_CONTEXT → refused naming it";
  - "kube_ctl always passes --context";
  - "runtime_check: detected pod CIDR differs from .env → refused naming both";
  - "kube_host_checks: an IPv6 pod CIDR → refused";
  - "init kubernetes: foreign portcullis namespace → refused" (Review Focus 5) and "… matching install id → adopted";
  - "kube_netpol_probe: allowed dial fails → not proven, ConfigMap not written";
  - "status jq: (A and B) as $x fixture" (jq 1.8);
  - "no dc/docker outside the rt_* docker branch" (grep);
  - argv grep: no `--from-literal`, no `--set` with a `secrets/` value.
- [ ] **Step 2:** Run the core gate. Expected: FAIL.
- [ ] **Step 3:** Implement. Convert call sites mechanically (docker behaviour unchanged).
- [ ] **Step 4:** Run the core gate. Expected: PASS.
- [ ] **Step 5:** Commit (`cli: rt_* runtime layer (docker/podman unchanged), CONTAINER_RUNTIME=kubernetes, context/namespace/CIDR/API keys, § 6 checks, NetworkPolicy probe`).
- [ ] **Step 6 (controller):** Run `gh workflow run ci.yml --ref kube1 -f jobs=unit-tests,build-and-test,e2e,e2e-podman`. Expected: green (no Docker/Podman change).

---

### Task 12: Core image publishing (`images.yml`) and `images.yaml`

**Files:**
- Create: `.github/workflows/images.yml`, `scripts/gen-images-yaml.py`, `charts/portcullis/images.yaml`
- Modify: `.github/workflows/release.yml` (tag the five images `X.Y.Z` and sign them), `tests/lint_images.sh` (scan `images.yaml`), `.github/dependabot.yml`

**Interfaces — Produces:**
- `images.yml`:
  - matrix `svc: [group-gate, enroll, domains, mcp-gate, wg]`, context `./<svc>`;
  - pushes `ghcr.io/porelli/portcullis-<svc>:edge` from main (only when the context changed, or on dispatch), cosign signs the digest, and writes the summary line `pushed <ref>@<digest>`;
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
  - `services.yaml` (`traefik` LB with fixed clusterIP, `keycloak-internal`, `wg-people` LB).
- Create: `tests/k8s_parity.py`, `tests/k8s_netpol_matrix.py`, `tests/k8s_hardening.py`, `.github/ci/unit-tests-kube-static.sh`
- Modify: `.github/workflows/ci.yml` (one unit-tests step calling the script), `CLAUDE.md` (parity rule)

**Interfaces:**
- Consumes: `images.yaml` (CLI-resolved digests in `secrets/kube/values.yaml`), the Hub's `role.yaml` (byte copy, K13), `wg` per VPN contract §16.
- Produces:
  - `values.yaml` keys: `domain`, `podCIDR`, `serviceCIDR`, `apiEndpoints`, `traefikServiceIP`, `images.<svc>` (digests only; `required`), `uids.<svc>` (= `CT_*`), `monitoring.enabled`, `wg.enabled`, `wg.people.port`, `vpn.mode`.
  - `randAlphaNum`/`randAscii`/`genPrivateKey` banned, and `required` replaces `${VAR:?}`.
  - Every pod has: `portcullis.io/component`, its `portcullis.io/net-*` labels from compose membership, `automountServiceAccountToken: false` (except traefik, hub), drop ALL, `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem`, `seccompProfile: RuntimeDefault`, `runAsNonRoot`, limits = requests = compose `mem_limit`, the probes = compose healthcheck (Task 4's mapping) and the annotation `portcullis.io/config-hash`.
  - Traefik:
    - `kubernetesCRD` as Global Constraints, file provider from ConfigMap `traefik-dynamic` (shared middlewares + `strip-forwarded`);
    - entrypoints `web :8000`, `websecure :8443`, `kcinternal :8081`, `vpnsecure :8444` (`proxyProtocol.trustedIPs` = podCIDR, `http.aliasHeadersStrategy: delete`);
    - ACME on PVC `traefik-acme`; the URI helper as a pod with Traefik's uid.
  - Keycloak: `--proxy-trusted-addresses={{ .Values.podCIDR }}`. Ingress :8080 only from Traefik.
  - `kcinternal` router: `PathPrefix(/)` on `kcinternal` → Keycloak :8080, middleware `strip-forwarded@file`. Ingress :8081 from `hub`, `enroll`, `forward-auth`, `forward-auth-ext`, `mcp-gate` only.
  - `hostAliases` `auth.<d>` → `traefikServiceIP` on oauth2-proxy/grafana.
  - The Hub: env `HUB_CONTAINER_RUNTIME=kubernetes`, `HUB_SELF_IMAGE`, `HUB_APPS_NAMESPACE`; egress to `apiEndpoints` :6443 only, besides its compose networks.
  - `wg` (K7).
- `k8s_parity.py`: for every compose service it compares `helm template` (CI values) on image digest, uid/gid, caps, read-only root, memory, env keys, mount targets, probes and network labels. It also maps every one of the **46** project binds to a ConfigMap/Secret mount target. Reviewed deltas live in `tests/k8s_parity_deltas.yaml` (each with a reason; pids is one).
- `k8s_netpol_matrix.py`: from compose networks it derives the allowed (pod, pod) pairs and asserts the rendered policies allow exactly those, plus the Global Constraints port-bound rules.
- `k8s_hardening.py` asserts the per-pod list above on every rendered pod, and that no workload in `portcullis` violates `restricted`.

- [ ] **Step 1:** Write the three Python checks against an empty chart, plus kubeconform (pinned, `-strict`, the Traefik CRD schemas) and `helm lint` in `unit-tests-kube-static.sh`. Add "Hub Role byte copy matches the Hub (`kube1`, else main)".
- [ ] **Step 2:** Run `bash .github/ci/unit-tests-kube-static.sh`. Expected: FAIL (every service missing).
- [ ] **Step 3:** Write the chart service by service until parity and the matrix pass.
- [ ] **Step 4:** Run the core gate and the static script. Expected: PASS. `bash tests/lint_ci_size.sh` passes.
- [ ] **Step 5:** Commit (`chart: core on Kubernetes (PSA restricted, default-deny + network-derived policies, Traefik CRD provider + file middlewares + kcinternal + vpnsecure on its own port, wg edge/people, Hub Role); parity, netpol matrix, hardening checks`).

---

### Task 14: Core admission policies, StorageClasses, `init` cluster setup

**Files:**
- Create: `kube/admission/{policies.yaml,bindings.yaml,params.yaml}` (byte copies, K13), `kube/admission/params.tmpl.yaml`, `kube/storage/{provisioner.yaml,storageclasses.yaml,setup.sh}`
- Modify: `scripts/lib/kube.sh` (`kube_cluster_setup`), `.github/ci/unit-tests-kube-static.sh` (the byte-copy comparison)

**Interfaces:**
- Produces:
  - `kube_cluster_setup` is idempotent and server-side; each step commits to `applied.json` only after success. It:
    - creates the namespaces with PSA labels and K11's label/annotation;
    - installs the provisioner `portcullis.io/local-path` (pinned) and both StorageClasses (K3 mechanism);
    - applies the Traefik CRDs (K14) and the VAPs + binding;
    - renders the params ConfigMap `portcullis-admission-params` in `portcullis-apps`: `hubImage`, `bindRoots`, `corePorts` (80, 443, the VPN port, 8000, 8081, 8443, 8444), `podCIDR` and `fileMiddlewares`.
  - Used by `init` and `upgrade`.

- [ ] **Step 1:** Write the shell tests: "cluster setup: params ConfigMap carries the resolved Hub digest", "a failed VAP apply leaves applied.json unchanged", and the byte-copy CI check.
- [ ] **Step 2:** Run the core gate. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the core gate. Expected: PASS. Commit (`kube: admission policies + params (from the Hub vectors), local-path provisioner + StorageClasses with owner patterns, idempotent cluster setup`).

---

### Task 15: Core sync, up/down/status, backup/restore and revocation on kubernetes

**Files:**
- Modify: `scripts/lib/kube.sh`, `stack.sh` (`up`, `upgrade`, `down`), `status.sh`, `backup.sh`, `vault.sh`, `keycloak.sh`, `certs.sh` (`cert revoke|sync`), `tests/test_shell_libs.sh`, `tests/test_cli.sh`

**Interfaces — Produces (bash):**
- `kube_sync_secrets`: every file under `secrets/` (except `secrets/kube/`) plus the core secret variables become Secrets via `--from-file` (variables written to a 0600 temp dir first, removed by trap). The host config directories become ConfigMaps. Each is applied only when its hash differs from `applied.json`.
- `kube_render_values` writes `secrets/kube/values.yaml` with no secret, holding the resolved digests (K1).
- `rt_up` on kubernetes = sync → `kube_cluster_setup` → `helm upgrade --install --wait --timeout 10m -f secrets/kube/values.yaml` → `applied.json`.
- `rt_down` scales every Deployment in both namespaces to 0. It never calls `helm uninstall`.
- `status`: the same lines from pods. `--json` gains `runtime{kind: "kubernetes", context, version}`, `netpol`, `admission`, `dns_shadows` (no app Service name equals a core one) and `kube_api_public` (K8).
- `backup` (same layout and `MANIFEST.json`):
  - Vault snapshot through `kube_port_forward vault 8200`;
  - `pg_dump -Fc` via `rt_exec`;
  - volumes via an owner-uid helper pod in `portcullis` (restricted-compliant), streaming the tar over exec;
  - plus `secrets/kube/values.yaml`.
- `restore`:
  - scale the Hub to 0, and the instances mounting `*-pw` Secrets to 0 (the label `portcullis.io/person-secrets`);
  - empty every `*-pw` Secret;
  - volumes in through the helper, then the existing guards (LLDAP empty, federation counts), then `helm upgrade`;
  - it keeps the host's `CONTAINER_RUNTIME` and `PORTCULLIS_KUBE_*` keys (rootless P6 pattern).
- `cert revoke|sync`: update ConfigMap `certs`, then patch the group-gate pod annotation `portcullis.io/rev`.

- [ ] **Step 1:** Write shell tests:
  - "sync: no secret on argv (stub records argv)";
  - "sync: unchanged hash → no apply";
  - "helm failure → applied.json unchanged";
  - "down never runs helm uninstall";
  - "restore keeps PORTCULLIS_KUBE_* from the host";
  - "restore empties *-pw Secrets before scaling up";
  - "status --json runtime.kind = kubernetes";
  - "cert revoke bumps portcullis.io/rev".
- [ ] **Step 2:** Run the core gate. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the core gate. Expected: PASS. Commit (`cli: kubernetes up/upgrade/down/status, secrets + config sync (files only), backup/restore with owner-uid helpers, prompt revocation`).

---

### Task 16: Core CI job `e2e-k3s`

**Files:**
- Create: `.github/ci/e2e-k3s-install.sh` (pinned k3s + sha256, the § 6 flags, the K1 `local` image import), `.github/ci/e2e-k3s-assert.sh`, `tests/e2e/e2e_k3s.py`
- Modify: `.github/workflows/ci.yml` (job `e2e-k3s` after `e2e-vpn`: `runs-on: ubuntu-26.04`, `timeout-minutes: 90`, `needs: jobs-input`, the name-match `if`, `ACME_STAGING: "true"`, Pebble as in the domains job; the description list), `CLAUDE.md` (Testing)

**Interfaces:**
- Consumes: everything above; the Hub from the same-named branch (built, imported as `localhost/`); templates from the same-named branch, else main; the `tests/e2e/apps/echo` fixture.

- [ ] **Step 1:** Write the job with spec §10's assertions, each failing as `FAIL: <what>`:
  - the probe; PSA restricted in `portcullis` (a privileged pod is rejected);
  - a pod sending `X-Forwarded-Tls-Client-Cert` to `keycloak-internal:8081` gets no X.509 login;
  - spoofed `X-Forwarded-For`/`X-Real-Ip` on websecure are dropped;
  - an app pod can't reach Keycloak :8080, Vault, Postgres, :6443 or :10250;
  - the client IP shows in the access log (the Task 0 netns client);
  - sign-in plus the Playwright portal subset;
  - echo deploy/backup/restore/delete through the Hub API;
  - with the Hub's ServiceAccount token: hostPath outside roots, NodePort, a cross-namespace middleware, a foreign helper image, a `vpn-slot` of 47 → all denied;
  - the fixer on `/srv`;
  - revocation ≤ 10 s;
  - the Docker → k8s restore round trip inside the job (phase 1 on Docker, as rootless P11, no artifact with secrets);
  - VPN:
    - `vpn init`; a built-in device handshake + GET through `wg-people`;
    - a raw PROXY v2 header to Traefik :8444 from a non-`wg` pod → refused by policy;
    - a gateway pod rescheduled → refused until republished (Review Focus 4, live).
  - Failure artifacts: logs and `kubectl get events` only.
- [ ] **Step 2:** Run `actionlint`, `bash tests/lint_ci_size.sh` and `bash tests/test_cli.sh`. Expected: PASS. Commit (`ci: e2e-k3s (real k3s, the § 6 flags; isolation, trust, Hub instances, admission, fixer, revocation, cross-runtime restore, VPN)`).
- [ ] **Step 3 (controller):** Run `gh workflow run ci.yml --ref kube1 -f jobs=unit-tests,e2e-k3s`. Expected: green.

---

### Task 17: Docs pages

**Files:**
- Create: `docs/operations/kubernetes.md`
- Modify: `.nav.yml`, `hardening.md` (Kubernetes section: RBAC tables replacing the socket-proxy table there, VAPs, the NetworkPolicy map, PSA levels, Traefik non-root, pids delta, K3's fallback if taken), `backups.md`, `cli.md`, `testing.md` (`e2e-k3s`, envtest, the k3s Test Apps leg), `hub.md` (runtime badge, compat column, the new doctor kinds), `vpn.md` (`wg` on k8s), `rootless-podman.md` (a link), `includes/abbreviations.md` (PSA, VAP, CRD)

- [ ] **Step 1:** Write `kubernetes.md`:
  - why to use it;
  - the k3s install line with the flags;
  - prerequisites (§6, K8, K10);
  - `init --runtime kubernetes --kube-context`;
  - migration (backup → init → restore);
  - the compatibility table;
  - images (K1);
  - troubleshooting (probe, admission, CIDR drift, source IP).
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
  - check that status is clean, the instances were recreated with `_SOURCE` in their env, and header-auth apps still sign in (grafana, a craft app);
  - take a fresh `./portcullis backup`.
- [ ] **Step 5: The Kubernetes VM** (K12; the user provides SSH access and opens 80/443/51820 in its firewall):
  - install k3s with the documented line;
  - clone core, then `ACME_STAGING=true ./portcullis init --runtime kubernetes --kube-context default`;
  - restore the Docker backup;
  - live checks: sign-in by passkey and by certificate, the portal, two instances (one header-auth), a public link, a VPN device from the user's phone, `status` clean apart from the K8 Warning if the API is public;
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

  Gaps the spec left open are settled in K1 (no builder on k3s), K4 (copy-up), K5 (gateway addresses) and K6 (the self-test cause).
- **Types:**
  - `runtime.Instances` (Task 2) is used unchanged by Tasks 5–8.
  - `Translate`/`Plan`/`ErrRefused` (Task 4) by Tasks 5 and 7.
  - `kube.Guard` (Task 8) gates the Task 5 backend.
  - `RuntimeCompat(rt, …)` (Task 3) by Tasks 4 and 9.
  - `portcullis-admission-params` is written by Task 14 and read by Task 8's policies.
  - `portcullis-netpol-probe` is written by Task 11 and read by Task 8.
- **Proportion:** there are no function bodies, only signatures, values and test names.
