# Kubernetes support (design)

Status: written by the assistant for the roadmap item "kubernetes support" (the user's words). The user asked not to be interrupted, so the assistant made every decision. Each decision is the **assistant's call** unless it says otherwise. Open questions are in §13, and each one has a default. This spec builds on `2026-11-13-rootless-podman-design.md` (`CONTAINER_RUNTIME`, runtime-neutral backups, the compatibility gate), `2026-11-13-vpn-only-access-design.md` (the core userspace WireGuard `wg` service, `vpnsecure`) and `2026-11-13-dns-hardening-design.md` (the CAA pin on Traefik's ACME account).

## 1. Where things stand (2026-11-12)

- **Core** is one compose project (`portcullis/docker-compose.yml`, about 20 services). The isolation model is built from Docker features:
  - **Networks.** Six `internal: true` networks (`portcullis-auth`, `socket-proxy-*`, `monitoring`, `portcullis-domains`, `portcullis-certs`, `portcullis-mcp`, `portcullis-sessions`), plus non-internal `portcullis`, `portcullis-proxy`, `domains-egress` and `alerting`.
  - **Fixed IPAM.** It anchors the trust relationships:
    - Keycloak `--proxy-trusted-addresses` = Traefik's `.2` on `portcullis-auth`.
    - Header-auth apps trust `PORTCULLIS_TRAEFIK_IP`. 84 template files read it; 18 nginx gates reject anything that isn't an IPv4 address.
    - mcp-gate pins Keycloak and the Hub through `extra_hosts`.
    - The VPN spec trusts PROXY protocol only from the `wg` service's fixed IP (its edge role fronts every VPN provider, built-in or marketplace).
  - **Two socket proxies** are the only holders of the engine socket (contract §6).
  - `network.sh` adds a DNS shadowing guard.
- **The CLI** (`scripts/lib/*.sh`) drives everything through `dc` (= `docker compose`) and plain `docker run/exec/volume`. Backups are logical and online: a Vault raft snapshot over `127.0.0.1:8200`, `pg_dump` via exec, SQLite backups inside volume tars made by helpers that run as the volume owner, plus `.env`, `secrets/` and `certs/`. Ownership comes from `ct_own` / `ct_group_read` with the `CT_*` uids.
- **The Hub** runs one compose project per instance through `compose.Runner` (`up --no-start`, image-label check, `up -d --pull never`, `down`) and the Docker-shaped `hub.Engine` interface (`internal/hub/hub.go`: containers, logs, exec with stdin, kill, events, volumes, archive copy through never-started helpers, the started fixer helper, `DockerRootDir`, `APIVersion`). It renders its override (`override.go`: routers, middlewares, tiers, public/oauth2/MCP routers) as compose labels and bind-mounts `./templates/<id>/` and `./appfiles/<id>/`. Per-person hashes sit on `hub_secrets` behind subpath mounts.
- **Templates** (`portcullis-templates`, about 45) are `manifest.yaml` + `compose.yml`, loaded with `compose-go`. Host features in use:
  - `devices` / `/dev` (scrutiny, zigbee2mqtt, esphome, motioneye);
  - `network_mode: host` (netbird coturn);
  - published `ports:` (pihole/adguard 53, samba/timemachine 445, gitea ssh, netbird);
  - extra caps (guacamole).

## 2. Goals, non-goals, anti-goals

**Goals**
1. **Core as a Helm chart on a single-node k3s** (`charts/portcullis` in the core repo). `./portcullis` stays the only operator interface, driven against a named kube context.
2. **Same security properties as on Docker.** Each pinned-IP trust anchor, internal network and socket-proxy allowlist gets a k8s mechanism that is at least as strict (§5). Every hardening item holds, and the single unavoidable delta is documented (§5, pids).
3. **App instances work unchanged.** Templates stay compose-based. The Hub translates the rendered project into a fixed, small set of k8s objects (§4). There is no Helm chart per template.
4. **Backups are runtime-neutral** (extends podman goal 4). Docker ⇄ Podman ⇄ k8s goes through backup → `init` → `restore`, with the same archive format, the same instance backup format and container ids in tarballs.
5. **One compatibility gate.** The podman spec's `RootlessCompat` becomes `RuntimeCompat(runtime, …)` with a Kubernetes table (§8).

**Non-goals (v1)**
- Multi-node, HA or replicas > 1. Single-replica Vault, Postgres, LLDAP and Traefik ACME depend on this, and `hub_data` is RWO and shared by four pods. Namespaces and labels are chosen so that a later "all core pinned to one node" step stays possible. Apps on another machine (a remote node or a second cluster) instead join as multi-server workers over the core `wg` service's link role (user ruling, VPN spec §3.1; multi-server spec).
- Clusters other than k3s as a *supported* target. Any conformant cluster with the §6 prerequisites is documented as "should work, not CI-tested".
- Operators for Postgres, Keycloak, Vault or cert-manager. Also External Secrets, Sealed Secrets, the Vault Agent injector and GitOps (Argo/Flux) workflows. Gateway API. `podman kube play`. Rootless k3s. Per-instance namespaces. USB/raw devices through device plugins. Parked (§12).

**Anti-goals (never)**
- **No cluster-admin for the Hub, and no cluster-scoped verb at all.** The Hub's ServiceAccount has exactly one Role in exactly one namespace (`portcullis-apps`). It holds no RBAC verbs (no `roles`, `rolebindings`, `serviceaccounts`, `namespaces`, `nodes`, `pods/ephemeralcontainers`, `escalate`, `bind` or `impersonate`) and nothing in the core namespace.
- **Never weaken network isolation.** Every namespace is default-deny for ingress and egress. Every allowed path is a NetworkPolicy derived from today's compose networks. `up` refuses to run if NetworkPolicy enforcement isn't proven (§6).
- **Never weaken the hardening baseline** (pinned digests, no-new-privileges, drop ALL, read-only roots, limits, non-root where possible). Core is PSA `restricted`. Nothing the Hub creates bypasses admission (§7).
- **Never let an app reach a core secret, a core object or the API server.** App pods get no ServiceAccount token, and the Hub's Role can't read core Secrets.

## 3. Runtime selection and the CLI

- **`CONTAINER_RUNTIME=kubernetes`** (podman spec §3; it is set once at `init` and never changed). New `.env` keys:
  - `PORTCULLIS_KUBE_CONTEXT`: required. The CLI never uses the current context implicitly, so a wrong `kubectl config use-context` can't hit another cluster.
  - `PORTCULLIS_NAMESPACE` (default `portcullis`) and `PORTCULLIS_APPS_NAMESPACE` (default `portcullis-apps`).
  - `PORTCULLIS_POD_CIDR` and `PORTCULLIS_SERVICE_CIDR`: detected at `init` and re-checked by `runtime_check`.
- **Tools:** host `kubectl` and `helm` (version floors checked like `docker compose` today). The kubeconfig is the operator's copy of `/etc/rancher/k3s/k3s.yaml` (0600). It holds cluster-admin and is the host-root equivalent, as the Docker socket is today.
- **The CLI's runtime layer.** `common.sh` gains `rt_*` verbs: `rt_up`, `rt_down`, `rt_exec <svc>`, `rt_logs`, `rt_ps`, `rt_volume_out/in`, `rt_restart`. On docker/podman they keep today's `dc` code. On kubernetes:
  - `rt_up` = sync Secrets/ConfigMaps (below), then `helm upgrade --install --wait --timeout 10m`.
  - `rt_down` = scale every Deployment to 0. It is never `helm uninstall`; PVCs carry `helm.sh/resource-policy: keep`.
  - `rt_exec` = `kubectl exec deploy/<svc>`.
  - Vault and Keycloak API calls keep their curl code against a temporary `kubectl port-forward` (it arrives on 127.0.0.1 inside the pod, so Keycloak never treats it as a trusted proxy).
  - `tests/test_cli.sh` greps that no `dc`/`docker` call is left outside the `rt_*` docker branch.
- **Values and secrets.**
  - The CLI renders the chart's values from `.env` into `secrets/kube/values.yaml`, which holds no secrets.
  - Every file under `secrets/` and every core secret variable becomes a k8s Secret in the core namespace, applied with `kubectl create secret --from-file … --dry-run=client -o yaml | kubectl apply -f -`. That keeps secrets off argv (CLAUDE.md rule; files and stdin only).
  - Host files (`traefik/dynamic`, `certs/`, `keycloak/realm-export.json` and themes, `vault/`, `group-gate-map.conf`, `monitoring/`) become ConfigMaps. Pods carry a content-hash annotation, so a change rolls them.
  - The chart never generates secrets (`randAlphaNum` is banned; `required` replaces `${VAR:?}`).
  - Secrets stay sourced from the operator's `secrets/` directory. Backups don't change, and k3s `--secrets-encryption` is required (§6).
- **Prompt delivery for revocation data.** `cert revoke` / `cert sync` update the `certs` ConfigMap, then bump an annotation on the running group-gate pod. That makes the kubelet resync the volume at once, and CI asserts the serial is enforced within 10 s.
- **Commands.**
  - `init --runtime kubernetes` runs the §6 checks, creates the namespaces (with PSA labels), StorageClasses, Traefik CRDs and the admission policies (§7), then continues as today.
  - `up`, `upgrade` (`helm upgrade` + the idempotent steps), `down`, `status` (pods → the same status lines and `--json` with `runtime{kind: kubernetes, context, version}`), `backup` and `restore` (§9).
  - `backup schedule --systemd` stays a host timer. A CronJob would need cluster credentials in a pod, for the same reason as the "no scheduler container" rule.
- **Hand-written chart plus a parity test, not a generated chart.** `tests/k8s_parity.py` renders `helm template` and compares it with `docker-compose.yml`, service by service: image digest, uid/gid, caps, read-only root, memory limit, env keys, mount targets and network membership (→ the policy labels). A short reviewed list holds the intentional deltas. Image digests are generated into `charts/portcullis/images.yaml` from compose, and CI fails when that file is stale, so Dependabot changes stay single-source.

## 4. The Hub on Kubernetes: a translator behind a runtime interface

**Choice.** The Hub translates compose into k8s objects itself (it keeps the compose-go model and every existing check). It does not run a separate controller with a CRD, and templates don't ship k8s manifests.

| Option | For | Against |
|---|---|---|
| **A. In-Hub translator + scoped ServiceAccount** | All validation stays on the compose model (contract §3, overrides, setup profiles, secrets mount rules). The ops/progress/Stop model is unchanged. One binary | The Hub holds the namespaced write Role |
| B. `PortcullisInstance` CRD + controller | GitOps-friendly | Same privilege total (now on the controller), a second component, CRD versioning, and every Hub check duplicated or moved |
| C. Helm chart per template | Native | Rewrites about 45 templates, two formats forever |

**Interface.** New package `internal/runtime` with `Instances`. Its verbs:
- `Deploy(project)`, `Stop`, `Down`, `Status`;
- `Logs`, `Exec(stdin)`, `Signal`, `Events`;
- `Volumes` (list/create/remove), `VolumeOut/In`;
- `RunHelper`;
- `Info` (runtime, id mapping, forbidden roots).

The existing `compose.Runner` + `hub.Engine` become the `docker` backend, which serves Docker and Podman unchanged. `kube` is the new backend (client-go, server-side apply, field manager `portcullis-hub`). `HUB_CONTAINER_RUNTIME=kubernetes` selects it. The Hub verifies the choice at start (in-cluster config, its namespace, a self-test of the admission guard, §7) and **fails closed**: if verification fails, every runtime operation answers 503.

**Translation** (`internal/runtime/kube/translate.go`, golden-tested):

| Compose | Kubernetes |
|---|---|
| service | Deployment, replicas 1, strategy `Recreate`. Names are `<instance>-<service>`, truncated with `-<hash8>` past 63 characters. Labels `portcullis.io/instance`, `portcullis.io/service` and `portcullis.io/net-*` (§5) are set by the translator only. Compose labels become annotations, never pod labels |
| job (contract §3 "one-off jobs"), `restart: "no"` | Job, `backoffLimit: 0`. Dependents are applied after it succeeds |
| `depends_on` (healthy / completed) | Ordered apply: the Hub waits for readiness or completion between steps |
| `healthcheck` | Readiness + liveness exec probes (`CMD-SHELL` → `sh -c`) |
| `user`, `cap_add`/`cap_drop`, `read_only`, `security_opt: no-new-privileges` | `runAsUser/Group` (numeric only), capabilities, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`. `seccompProfile: RuntimeDefault` is always set |
| `tmpfs`, `shm_size` | `emptyDir {medium: Memory, sizeLimit}`; `/dev/shm` the same |
| `mem_limit` / `pids_limit` | `resources.limits.memory` (= request). Pids: §5 |
| `environment`, `--env-file` | One Secret per instance (`envFrom`), so values never appear in pod specs |
| `image` | Resolved by the Hub to `name@sha256` (go-containerregistry) at create, then deployed by digest. This replaces `--pull never`. Docker's image-label merge doesn't exist here, so the image-label check becomes moot (Traefik reads only IngressRoutes) |
| named volume | PVC `<instance>-<key>`, StorageClass `portcullis-apps` (RWO, reclaim `Delete`; guarded delete, §11.4) |
| bind `./templates/<id>/…` | ConfigMap `tpl-<id>-<hash>` (≤ 1 MiB, nested paths via `items`), read-only |
| `./appfiles/<id>/<name>` data files (§13.7) | ConfigMap (`.json`) + Secret (`.secrets.json`) per instance and file |
| `hub_secrets` subpath (§6) | A Secret `<instance>-<key>-pw` holding exactly that instance's/option's `<user>.nt` keys, mounted read-only at `mount.path`. Cross-namespace mounts are impossible, so isolation stays structural |
| bind under `HUB_OVERRIDE_BIND_ROOTS` (shared folders) | `hostPath` (type `Directory`), allowed only under the bind roots (§7) |
| `ports:` (manifest ports) | Service `LoadBalancer` (k3s ServiceLB). `lan_only` → `loadBalancerSourceRanges` = Local networks. Core ports (80, 443, the VPN port) are refused |
| Traefik labels | One IngressRoute per router (TLS options are per IngressRoute) + Middlewares in `portcullis-apps` (§5) |
| `network_mode: service:<x>` | Co-located as an extra container in `<x>`'s pod |
| `stop_grace_period` / `stop_signal` | `terminationGracePeriodSeconds` / a `preStop` exec `kill -s <sig> 1` |

**Operations that change mechanism.**
- **Reload signals (§13.8):** exec `kill -s <SIG> 1`. If the image has no `kill`, the reload falls back to a pod restart. The template is then "degraded" (shown in the panel).
- **Secret/ConfigMap deliveries:** after an update the Hub bumps a pod annotation (immediate kubelet resync) and waits until the mounted copy's `.rev` key matches before it runs hooks. This keeps the file-sharing revocation SLAs, and CI tests it.
- **Pull progress:** read from pod events (bytes aren't available, so the bar shows "pulling").
- **Exposure drift:** compares the live IngressRoutes/Middlewares with the desired ones.
- **Helpers (volume copy, fixer):** pods running the Hub's own image by digest. `hub helper idle` is the main process. The Hub execs `hub volcopy out|in` or `hub folderfix <mode>` and streams the tar or the report over the exec stream (this replaces the archive endpoints and logs). They carry the label `portcullis.io/helper` (deny-all NetworkPolicy), have no token, and are removed always and at Hub start. Their caps per mode are the contract §6 minimums. The image digest is the `HUB_SELF_IMAGE` that the CLI resolves from the running Hub pod. The admission policy pins helpers to exactly that digest (§7), which preserves ruling 37: the Hub can't pick another root-capable image. The `uid_map` is the identity on k8s (`hostUsers` stays true, §12), so the fixer runs as on rootful Docker.
- **Forbidden roots** (the doctor's Docker-root rule): `PORTCULLIS_RUNTIME_ROOTS` in `core.env` = the containerd root and the local-path storage directory.

**The Hub's Role** (`portcullis-apps` only):
- create/update/patch/delete/get/list/watch on deployments, jobs, services, persistentvolumeclaims, configmaps, secrets, networkpolicies, `traefik.io` ingressroutes/middlewares;
- get/list/watch/delete on pods;
- get on `pods/log`, create on `pods/exec`;
- list/watch on events.

That is the k8s form of `socket-proxy-hub`. Everything else is denied, and there is nothing in `portcullis`. The Hub reads its own inputs (core.env, LLDAP/invite/domains/mcp-gate secrets) as mounted Secrets, as today.

## 5. What maps how (core and apps)

| Docker concept | Kubernetes mechanism |
|---|---|
| Compose network `N` | Pod label `portcullis.io/net-N: "true"` on members. One NetworkPolicy per network: ingress from and egress to pods with the same label. Namespace default-deny for both directions. Egress to kube-dns :53 for all pods |
| `internal: false` (`portcullis`, `domains-egress`, `alerting`, app `default`) | Label `portcullis.io/egress`: egress to `0.0.0.0/0` **except** the pod/service CIDRs, link-local and the node IPs. Node IPs get a separate rule allowing only 80/443 (hairpin to `auth.<d>`), so pods never reach :6443/:10250. LAN reachability for apps stays as on Docker |
| `portcullis-proxy` (apps ⇄ Traefik) | App frontends' routed ports accept ingress **only from Traefik pods** (namespaceSelector + podSelector). Other same-instance ports stay open within the instance |
| Pinned Traefik IP trusted by Keycloak | Keycloak :8080 accepts ingress **from Traefik only**, with `--proxy-trusted-addresses=$PORTCULLIS_POD_CIDR`. Internal Keycloak clients (Hub, enroll, forward-auth*, mcp-gate) call `http://keycloak-internal:8081`. That is a Traefik entrypoint `kcinternal` (ClusterIP Service on Traefik pods, ingress allowed from exactly those clients) whose single router strips every `X-Forwarded-*` / client-cert header (`strip-forwarded@file`). So Keycloak still hears only from Traefik, and nobody can inject a client certificate |
| `PORTCULLIS_TRAEFIK_IP` / `PORTCULLIS_MCP_GATE_IP` in templates | New contract §2 variables `PORTCULLIS_TRAEFIK_SOURCE` / `PORTCULLIS_MCP_GATE_SOURCE` (CIDR): `<ip>/32` on Docker/Podman, the pod CIDR on k8s, always combined with the "only that peer can connect" policy above. Templates switch to them (no back-compat, CLAUDE.md), and the nginx gates' check accepts a CIDR |
| mcp-gate `extra_hosts` pins | Service FQDNs (`keycloak.portcullis.svc.cluster.local`). Apps can't create Services in the core namespace, so names can't be shadowed. The DNS shadowing guard becomes structural, and `status` asserts it (no app Service name matches a core one) |
| VPN PROXY trust (`vpnsecure`) | Traefik's vpnsecure port accepts ingress only from the `wg` pod. `PROXYPROTOCOL_TRUSTEDIPS` = pod CIDR. Each edge port of the `wg` pod accepts ingress only from its marketplace provider's gateway pods (VPN spec §5). The people and link WireGuard UDP ports are LoadBalancer Services of the `wg` pod (userspace netstack, no NET_ADMIN, as the VPN spec intended) |
| Fixed IPs needed as literals (`extra_hosts: auth.<d>:host-gateway`) | `hostAliases` → the `traefik` Service's fixed `clusterIP` (`PORTCULLIS_TRAEFIK_SERVICE_IP`, picked from the service CIDR's static band) |
| `socket-proxy-traefik` (read-only) | Traefik's ServiceAccount gets read-only Roles (get/list/watch services, endpointslices, `traefik.io` CRDs) in the two namespaces. The proxy services disappear |
| `socket-proxy-hub` | The Hub's Role (§4) |
| Traefik docker provider + labels | `kubernetesCRD` provider: `namespaces: [portcullis, portcullis-apps]`, `allowCrossNamespace: false`, `allowExternalNameServices: false`; the Ingress and Gateway providers are off. Core routers become chart IngressRoutes. Shared middlewares (`portcullis-auth`, `-auth-ext`, `-groups`, `client-headers`, `client-cert-pem`, `security-headers`, `rate-limit*`) move to the file provider (ConfigMap) so apps can name them `@file`. The translator maps `…@docker` → `…@file`; templates don't change. Secret-bearing `hub-proxy-secret` is a CRD in `portcullis`, unreachable from apps. File provider, HTTP provider (domains certs) and ACME keep their config |
| Ports 80/443 | Traefik runs **non-root** (uid 65532) on :8000/:8443 behind a `LoadBalancer` Service with `externalTrafficPolicy: Local` (source IP kept; CI asserts the client IP in the access log). This solves podman Q4 on k8s only |
| ACME | **Traefik's resolver stays** (not cert-manager): `acme.json` on a PVC, the same DNS-01 providers and CAA pin as in the DNS spec. Its URI helper becomes a pod (Traefik's uid, PVC read-only, deny-all policy) |
| Volumes + `ct_own` | PVCs, StorageClass `portcullis-core` (local-path, reclaim `Retain`). The provisioner's `userPattern`/`groupPattern`/`permPattern` read PVC annotations `portcullis.io/{uid,gid,mode}` = the `CT_*` values, so no chown helper runs. Every core volume is single-owner (CI) |
| Secrets files 0640 group gid | Secret volumes, `defaultMode: 0440` + pod `fsGroup` = the gid |
| Hardening baseline | Core namespace PSA `restricted` (enforce). Every container: drop ALL, no escalation, read-only root, `RuntimeDefault` seccomp, memory limit, digest, `automountServiceAccountToken: false` (except Traefik, Hub) |
| `pids_limit` per service | **The only delta.** k8s has no per-container pids limit. The kubelet's `podPidsLimit` (k3s `--kubelet-arg=pod-max-pids=1024`) is required and checked, and caps every pod at Keycloak's 1024. hardening.md lists this |
| Loopback publishes (Keycloak 8080, Vault 8200) | None. The CLI uses port-forward (§3) |

## 6. Host / cluster prerequisites (checked by `init`, `up`, `upgrade`, `status`; † = refuse)

- † k3s ≥ the floor (Kubernetes 1.32; VAP is GA), installed with:
  - `--disable=traefik` (core ships its own);
  - `--secrets-encryption`;
  - `--kubelet-arg=pod-max-pids=1024`;
  - the network policy controller **on** (not `--disable-network-policy`);
  - ServiceLB on.
- † **NetworkPolicy enforcement probe.** Two probe pods in a scratch namespace: a denied connection must fail and an allowed one must succeed. If it isn't proven, nothing is deployed. The Hub repeats it (doctor `netpol_not_enforced`, Problem; instance deploys refused).
- † A local-path provisioner version with the ownership patterns (§13 Q2), and the `portcullis-core`/`portcullis-apps` StorageClasses.
- † Source-IP preservation: Traefik sees the real client IP for a curl to the node's address. If it can't be proven (e.g. no external request possible), it is a warning only.
- Ports 80/443 (+ VPN UDP, app ports) free on the node.

## 7. Admission: the guard behind the Hub's Role

RBAC can't constrain *what* the Hub puts in a pod spec. So `init` installs **ValidatingAdmissionPolicies** (CEL, cluster-scoped, installed by the operator) bound to `portcullis-apps`, with a params ConfigMap written by the CLI: the Hub image digest, bind roots, core ports, the pod CIDR. The policies:
- **Pods:**
  - Baseline-equivalent rules (no `privileged`, host namespaces, `hostPort`, caps beyond the baseline list, unconfined seccomp, `procMount`, sysctls).
  - `hostPath` only under the bind roots.
  - `automountServiceAccountToken: false` on the namespace `default` SA.
  - A `portcullis.io/instance` label is required, and every Secret/ConfigMap/PVC a pod references starts with its instance's prefix (or `tpl-<template>-`).
  - No `cni.projectcalico.org/*` or other CNI annotations.
  - Helper pods: image must equal the param digest, caps ⊆ the fixer set, no network label.
- **Services:** no `NodePort`/`ExternalName`, no LoadBalancer on core ports, no `externalIPs`.
- **IngressRoutes/Middlewares:**
  - Middleware refs must be own-namespace or on the `@file` allowlist; no `@internal` services; services in their own namespace.
  - TLS options on the tier allowlist; no `IngressRouteTCP/UDP`, `TraefikService` or `ServersTransport` with `insecureSkipVerify`.
  - Middlewares in apps may not be `forwardAuth` pointing at core or carry `X-Portcullis-*` headers.
- **NetworkPolicies:** the Hub may only create policies whose `podSelector` targets one instance and whose peers are that instance, Traefik or mcp-gate.

PSA on `portcullis-apps` is `enforce: privileged`, `warn/audit: baseline`. Built-in PSA can't allow hostPath under a prefix, so the VAPs enforce the baseline instead. The Hub **self-tests** at start and before every deploy with a server-side dry-run of a forbidden pod. If it is not rejected, the guard is missing → fail closed (503 on deploys, doctor `admission_guard_missing`).

Templates are still trusted with what they declare (contract §3 trust model), but on k8s host access is narrower than on Docker: no host paths outside the bind roots, no host network, no devices.

## 8. Compatibility table (`RuntimeCompat`, Kubernetes)

| Feature | Status |
|---|---|
| Core, sign-in methods, people, domains/ACME, mcp-gate, monitoring (chart value `monitoring.enabled`), VPN | works |
| Forward-auth, native OIDC, header-auth apps (via `_SOURCE`), public links, extra domains, MCP companions | works |
| Instance backup/restore, settings files, hooks, jobs, setup profiles | works |
| Reload by signal without `kill` in the image | degraded (pod restart) |
| Shared folders + fixer + ACLs, file sharing (445 via ServiceLB, `lan_only` via source ranges) | works. mDNS/Avahi for Time Machine: degraded (connect by address), §13 Q4 |
| Published UDP (pihole/adguard 53) | works (port 53 has no unprivileged limit here). Client IP kept with `Local` |
| `network_mode: host` (netbird coturn), `devices` / `/dev/*` (scrutiny, zigbee2mqtt, esphome, motioneye), `privileged`, `pid/ipc: host`, caps outside baseline, host binds outside the bind roots, non-numeric `user:` | refused, with the reason named |

`validate.py` in the templates repo prints the k8s column next to the rootless one.

## 9. Backups and restore

- **Core `backup`** has the same archive layout and `MANIFEST.json`:
  - The Vault raft snapshot goes through the port-forward with the existing curl code.
  - `pg_dump -Fc` via `rt_exec`.
  - SQLite/volume archives via a one-shot helper pod in `portcullis` that mounts the PVC read-only and runs **as the volume owner's uid**. It is restricted-compliant (no root needed, thanks to the single-owner rule) and streams the tar over exec.
  - Then `.env`, `secrets/`, `certs/`, `config/`, plus `secrets/kube/values.yaml`. Offsite restic is unchanged on the host.
- **`restore`** stops the Hub (scale 0) and scales app instances that mount person secrets to 0 (they replace today's `compose down` set). It empties the `*-pw` Secrets (the contract §6 "voided" rule). Volume data is streamed in through the same owner-uid helper (`hub volcopy in`-equivalent in alpine). Then the existing guards (LLDAP empty, Keycloak federation counts) run, and `helm upgrade`.
- **Cross-runtime:** a Docker or Podman backup restores on k8s and the other way round. CI runs the round-trip with an artifact from the `e2e` job.
- **Instance backups** use the §4 helper pods and keep the same format, so a Docker instance backup restores into a k8s instance.

## 10. CI

- **Core, static (unit-tests job):**
  - `helm lint`;
  - `helm template` → kubeconform (pinned schemas, Traefik CRDs);
  - `k8s_parity.py` and the `images.yaml` freshness check;
  - a rendered-manifest hardening check (§5 row);
  - a NetworkPolicy matrix generated from compose networks, compared with the rendered one;
  - a `test_cli.sh` grep for `rt_*`.
- **Core, `e2e-k3s` (new job):** real k3s on the runner VM (pinned version, binary sha256 checked, the §6 flags), **not** kind or k3d, because it has to be the supported target. `ACME_STAGING`-style Pebble as in the domains job; `init --runtime kubernetes`. Asserts:
  - the §6 probe;
  - PSA restricted holds in `portcullis`;
  - the Keycloak-only-from-Traefik rule (a pod sending `X-Forwarded-Tls-Client-Cert` to `keycloak-internal` gets no X.509 login);
  - spoofed headers on websecure are dropped;
  - an app pod can't reach Keycloak, Vault, Postgres, :6443 or :10250;
  - the client IP shows in the log;
  - sign-in plus the portal (the existing Playwright subset);
  - a Hub instance (`tests/e2e/apps/echo`) goes through deploy/backup/restore/delete;
  - the guard rejects a hostPath outside the roots, a NodePort, a cross-namespace middleware and a foreign helper image (via the Hub's ServiceAccount token);
  - the fixer on `/srv`;
  - revocation within 10 s;
  - the Docker → k8s restore round-trip.

  The `e2e-vpn` assertions join this job when the VPN lands.
- **Hub:**
  - translator goldens per compose feature;
  - `RuntimeCompat` vectors;
  - client-go fake tests for ops/progress;
  - **envtest** (a real kube-apiserver) for the RBAC Role and every VAP vector, run as the Hub's ServiceAccount;
  - `HUB_SELF_IMAGE` and fail-closed tests.
- **Templates:** `test-apps.yml` gains a k3s matrix leg (one template per job, as now). `validate.py` classification.

## 11. Docs and contract

- New `operations/kubernetes.md`: why to use it, the k3s install line, prerequisites (§6), `init`, migration (backup → init → restore), the compatibility table, troubleshooting.
- `hardening.md`: a Kubernetes section with the RBAC tables (replacing the socket-proxy table there), VAPs, the NetworkPolicy map, the PSA levels, Traefik non-root, and the pids delta.
- `backups.md`, `cli.md`, `testing.md`, and the Hub page (runtime badge).
- **Contract:**
  - §2: `_SOURCE` variables.
  - §3: the compose features refused on k8s; `@docker` middleware names are translated.
  - §5: IngressRoutes, the `@file` shared middlewares, `kcinternal`.
  - §6: "Engine access" with the Kubernetes Role, the helper pods, and per-instance `*-pw` Secrets replacing the `hub_secrets` subpath.
  - §11: object naming, PVCs, the backup format unchanged.
  - §13.7/§13.8: ConfigMap/Secret deliveries, `.rev`, exec-kill reloads.
  - §14: forbidden roots.
- Core and Hub `CLAUDE.md` files: the `rt_*` rule, the parity test, the "Hub has one Role" rule.

## 12. Task outline (for the plan)

1. **Core CLI runtime layer:** `rt_*` verbs (docker branch = today's code), `CONTAINER_RUNTIME=kubernetes`, context/namespace/CIDR keys, the §6 checks and probe; tests.
2. **Core chart:** namespaces + PSA, StorageClasses, every core service as Deployment/PVC/Service/ConfigMap/Secret refs, NetworkPolicies from the network map, Traefik CRD provider + file-provider middlewares + `kcinternal` + non-root ports, the `_SOURCE` values, IngressRoutes for core routers; `images.yaml` generator; parity and static checks.
3. **Core secrets/config sync, backup/restore/status** on kubernetes; revocation annotation bump.
4. **Admission policies + params** (core repo, installed by `init`); envtest vectors (shared fixtures with the Hub).
5. **Hub `internal/runtime`:** extract the docker backend behind `Instances` (no behaviour change, its own merge).
6. **Hub kube backend:** translator, digest resolution, ordered apply, Secret/ConfigMap deliveries with `.rev`, helper pods (`hub helper idle`, `hub volcopy`), exec-kill reload, IngressRoute rendering + drift, the admission self-test, doctor checks, `RuntimeCompat` k8s table + UI badges.
7. **Templates:** `_SOURCE` switch across the 84 files + nginx gate CIDR check; `validate.py` column; k3s CI leg.
8. **Core CI `e2e-k3s`** (§10).
9. **Docs + contract;** resync the Hub's docs copies.
10. **Test server:** a k3s VM (`ACME_STAGING=true`), full live check, restore of a Docker backup. Mainline all branches.

Merge order: docs → hub (task 5 first, then 6, wait for `build.yml`) → templates → core.

**Parked:**
- multi-node / HA (RWX or a split `hub_data`, cert-manager for multi-replica Traefik, CloudNativePG, Vault raft peers);
- per-instance namespaces with ResourceQuota;
- `hostUsers: false` (user namespaces) for app pods;
- External Secrets for GitOps installs;
- Gateway API once per-route client-cert tiers are standard;
- device plugins for USB apps;
- private-registry `imagePullSecrets`;
- rootless k3s.

## 13. Open questions (each has a default; work proceeds on the default)

1. **ServiceLB source-IP preservation** with `externalTrafficPolicy: Local` is assumed, not documented by k3s for every NAT setup. *Default:* rely on it, with CI and `status` proving it. If it fails, Traefik moves to `hostNetwork` on :80/:443 as a documented PSA exception for that one pod (still non-root, `NET_BIND_SERVICE` only).
2. **The local-path ownership patterns** may be missing from k3s's bundled provisioner. *Default:* `init` installs a pinned upstream local-path-provisioner as a second provisioner `portcullis.io/local-path` used by both StorageClasses.
3. **Header-auth frontends that get calls from their own sidecars on the routed port.** *Default:* the routed port stays Traefik-only. Any template that breaks is found by the k3s CI leg and gets a manifest-declared internal port, not a wider rule.
4. **mDNS for Time Machine** on k8s. *Default:* "degraded: connect by address", verified on the test server.
5. **Kubernetes floor.** *Default:* 1.32. If a needed feature (e.g. a VAP CEL function) turns out to be newer, CI pins the floor and `init` enforces it.
