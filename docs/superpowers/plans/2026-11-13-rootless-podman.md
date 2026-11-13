# Rootless Podman support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run the whole stack (core, the Hub, app instances) as one unprivileged host user under rootless Podman ≥ 5.4, with the same hardening as rootful Docker. One compose file and one CLI; the runtime is chosen once by `init` (`CONTAINER_RUNTIME`) and never switched.

**Architecture:** The CLI keeps driving everything through the Docker CLI and the compose plugin. Under podman it exports `DOCKER_HOST=unix://$XDG_RUNTIME_DIR/podman/podman.sock`, and a new `scripts/lib/runtime.sh` does the detection, the engine check and the host-preparation checks. Ownership helpers translate container ids through the live `uid_map`. The two socket proxies mount `${PORTCULLIS_ENGINE_SOCKET}`, and libpod paths stay denied. The Hub verifies its engine at start (`HUB_CONTAINER_RUNTIME`) and fails closed on a mismatch (503). It also gains a consistent-mapping gate for the folder fixer, a template compatibility gate `RootlessCompat` (shared vectors with the templates validator), SELinux relabels for its own binds, and five doctor kinds. A new core CI job `e2e-podman` proves the Podman path. The Docker test server keeps Docker.

**Tech Stack:** bash 3.2-compatible + jq (core CLI), Go 1.27 + moby client + vanilla JS (Hub), Python 3 (templates validator), GitHub Actions (`ubuntu-26.04`, podman 5.x + passt + uidmap from the archive), Zensical (docs).

**Spec:** `/Volumes/workspace/portcullis/portcullis-hub/docs/superpowers/specs/2026-11-13-rootless-podman-design.md` (binding). Every §12 open question takes its default: Q1 `ubuntu-26.04` (the `e2e-instances` job already runs on it as `ubuntu-latest`; only if the label is missing, `ubuntu-24.04` + `mgoltzsch/podman-static` pinned by checksum), Q2 pasta forwarder off, Q3 keep `host-gateway`, Q4 Traefik stays root (parked), Q5 Avahi/mDNS unverified (see ruling R10), Q6 floor 5.4. Cross-reference: VPN spec `2026-11-13-vpn-only-access-design.md` (§3.2: core's future `wg` service is userspace with no NET_ADMIN; a marketplace gateway that needs TUN or NET_ADMIN is `degraded` here).

## Global Constraints

- **Branch `podman1`** in core, Hub, templates and docs. Worktrees: `/Volumes/workspace/portcullis/wt-podman1/{portcullis,portcullis-hub,portcullis-templates,portcullis-docs}`, each made with `git -C <main checkout> worktree add -b podman1 <path> origin/main` (bases: core d4d40ac, Hub f21a90e, templates 311827d, docs e451041). Main checkouts may hold others' uncommitted work: never edit, stash or commit there; read `origin/main` with `git show origin/main:<path>`.
- **Contract first.** Task 1 (docs `podman1`) lands before any code task. After Task 1 and again after Task 11, resync the Hub copies: `PORTCULLIS_DOCS_DIR=/Volumes/workspace/portcullis/wt-podman1/portcullis-docs web/docs/sync.sh` in the Hub worktree, then commit `web/docs`.
- **No back-compat or migration code** (user rule). An absent `CONTAINER_RUNTIME` means `docker`, the documented default like every other `.env` default (ruling R1). Nothing rewrites an existing `.env`, and `upgrade` never writes the key.
- **Secrets never on argv** (the `tests/test_cli.sh` grep stays green). No new secret is introduced.
- **Fail closed:**
  - An engine that contradicts `CONTAINER_RUNTIME` stops the CLI and makes the Hub answer 503.
  - A failed † host check refuses `init`, `up`, `upgrade` and `restore`.
  - An unreadable `uid_map` refuses.
  - An unknown or missing `PORTCULLIS_UNPRIVILEGED_PORT_START` is treated as 1024.
  - An unmapped owner refuses the fixer for that folder.
- **Unchanged:** the socket rule (contract §6, now "the engine socket") and the hardening baseline: `no-new-privileges`, `cap_drop: ALL`, mem/pids limits, read-only roots, pinned digests, the proxies' allowlists. `label=disable` only on the two proxies, only through `docker-compose.podman-selinux.yml`. Never relabel user data (`/srv`, `/mnt`, `/media`, homes) or the engine socket.
- **Prefer mature libraries** (memory): the moby client, `golang.org/x/sys/unix` (xattrs), PyYAML. No hand-rolled protocol code.
- **TDD everywhere:** write the failing test, see it fail, implement, see it pass, commit. Gates:
  - Core: `bash tests/test_shell_libs.sh && bash tests/test_cli.sh && shellcheck -S warning portcullis scripts/lib/*.sh tests/*.sh && actionlint`.
  - Hub: `go vet ./... && go test -race ./... && gofmt -l .` (gofmt prints nothing).
  - Templates: `python3 tests/validate.py && python3 tests/test_validate.py`.
- **Core CI:**
  - Run targeted jobs with `gh workflow run ci.yml --ref podman1 -f jobs=<names>`, then one full run.
  - `jobs-input` reads job names from ci.yml with `yq`. Task 10 still adds `e2e-podman` to the `workflow_dispatch` `jobs` description list.
  - **Only the controller dispatches core CI on `podman1`**, because the concurrency group cancels. Subagents never run `gh workflow run ci.yml`.
  - Hub branch CI: `gh workflow run build.yml --ref podman1`.
- **Merges** (spec order: docs → Hub → templates → core):
  - Merge each repo through a temporary detached worktree: `git worktree add --detach /tmp/merge-<repo> origin/main` → `git merge --no-ff origin/podman1 -m "merge podman1: …"` → push → `git worktree remove`.
  - After the Hub merge, dispatch `gh workflow run build.yml --ref main -f compare_ref=podman1` and wait for it to publish `edge` before merging core. Keycloak is unchanged: publish nothing there.
  - After the core merge, re-run the templates "Test Apps" workflow on main.
  - Finally delete every `podman1` branch (local and remote), every worktree, and `/tmp/pp-*` and `/tmp/merge-*` (memory: branches mainlined).
- **Deploy (Docker test server only):**
  - The server keeps running Docker. There is no runtime switch on it: `CONTAINER_RUNTIME` is chosen by init and never switched.
  - Connect with `ssh -o BatchMode=yes -o ConnectTimeout=10 -o IdentitiesOnly=yes -i /Volumes/Michele/Michele/Keys/AWS/PDX/PDX-lightsail.pem admin@44.244.208.227`, then run `git pull --ff-only && ./portcullis upgrade` in `~/portcullis`. `ACME_STAGING=true` stays.
  - Then check that nothing changed for a Docker install (Task 12).
  - Never touch the LLDAP `admin` user. The Podman path is proven in CI only (spec §11 item 8 is replaced by this user instruction, ruling R10).
- **Values from the spec (verbatim):**
  - Container id `c=0` → the operator; `1 ≤ c < 65536` → `subuid_start + c − 1`. Subuid/subgid ≥ 65536 ids each.
  - `net.ipv4.ip_unprivileged_port_start=80`.
  - Podman ≥ 5.4.
  - `.env` keys `CONTAINER_RUNTIME=docker|podman` and `PORTCULLIS_ENGINE_SOCKET` (default `/var/run/docker.sock`).
  - Hub env `HUB_CONTAINER_RUNTIME`; core.env `PORTCULLIS_UNPRIVILEGED_PORT_START`.
  - Proxy mount `${PORTCULLIS_ENGINE_SOCKET:-/var/run/docker.sock}:/var/run/docker.sock:ro`.
  - Version component name `Podman Engine`.

## Plan rulings (assistant's calls beyond the spec)

- **R1:** an absent `CONTAINER_RUNTIME` means `docker` (`runtime_name`). `init` always writes it.
- **R2:** `runtime_check` runs in `need_env`, and in `init_run` after the `--env-only` return. It is cached per process. `--help` paths never reach it.
- **R3 (spec gap):** under Podman, the Hub's `selfContainerID` must accept Podman's mountinfo roots `…/overlay-containers/<64 hex>/userdata/{hostname,hosts,resolv.conf}`. Without that the fixer can't find its own image.
- **R4 (devices):** a `devices:` entry whose source resolves to `/dev/null` (the empty-slot default of esphome, motioneye, zigbee2mqtt) makes the template `degraded` ("device slots can't pass host devices"). Any other source is `refused`. `/dev/net/tun` and `cap_add: NET_ADMIN` are `degraded` (VPN spec §3.2 cross-reference).
- **R5:** `RootlessCompat(compose, m, env, portStart)` gains `env` (the instance's effective values; nil = defaults), so an instance check sees its own ports, devices and caps.
- **R6:** `restore` keeps the host's runtime keys. `CONTAINER_RUNTIME` and `PORTCULLIS_ENGINE_SOCKET` come from the `.env` being replaced (else `runtime_detect`), never from the backup.
- **R7:** under podman, `backup schedule --systemd` writes **user** units (`~/.config/systemd/user`, `After=/Requires=podman.socket`, `WantedBy=default.target`, no `User=`).
- **R8 (CI):** the runner user is the operator. The reboot check restarts `user@<uid>.service` (all containers die with the user manager), and `podman-restart.service` must bring them back.
- **R9 (CI):** the `e2e` job uploads one backup as artifact `e2e-docker-backup` (`retention-days: 1`; the ephemeral CI stack's secrets only). `e2e-podman` `needs` it and fails, never skips, when it is missing.
- **R10:** there is no Podman test server. Time Machine discovery is documented as "unverified under rootless Podman; connect by address if it isn't found" (the Q5 fallback wording).
- **R11:** every core bind whose source is inside the checkout gets long syntax with `bind: {selinux: z}`. The engine socket bind never does. CI checks both directions.
- **R12:** RootlessCompat reasons are exact strings, shared byte-for-byte through `rootless_vectors.json` (Hub ↔ templates), like the sign-in vectors.

## Review Focus

1. **`COMPOSE_FILE` unset with a `docker-compose.override.yml` present, on an SELinux host.** Adding the overlay must not drop the override: compose auto-loads it only while `COMPOSE_FILE` is unset. Pinned by the shell test "runtime_export keeps docker-compose.override.yml beside the SELinux overlay" (Task 7).
2. **Restoring a Docker backup onto a fresh Podman install.** The backup's `.env` says nothing or says `docker`, but the host must stay `podman` with its rootless socket. Pinned by the shell test "restore keeps the host's runtime keys" (Task 7) and the CI round-trip (Task 10).
3. **A folder entry owned by `65534`:** under a consistent map that is either container uid 65534 or a host account outside the range. Both must be refused per path, with the `sudo chown` hint. Pinned by `TestApplyRefusesUnmapped` and `TestScanCountsUnmapped` (Task 3).
4. **`XDG_RUNTIME_DIR` unset** (sudo -u, cron, a systemd unit). The socket must be derived from `/run/user/$(id -u)`, not `//podman/podman.sock`. Pinned by the shell test "runtime_podman_socket falls back to /run/user/<uid>" (Task 7).
5. **The Hub starting before `socket-proxy-hub` answers.** The guard must stay "unverified" (503) and then become "ok" once `/version` answers. Only a contradicting answer is permanent. Pinned by `TestGuardRetriesUntilVerified` (Task 2).

---

## File structure

**Core (`wt-podman1/portcullis`)**

| File | Responsibility |
|---|---|
| `scripts/lib/runtime.sh` (new; sourced right after `common`) | `runtime_name`, `runtime_detect`, `runtime_podman_socket`, `runtime_export`, `runtime_check`, `runtime_id_maps`, `runtime_port_start`, `runtime_host_checks`, `runtime_require_host`, `runtime_build_local`, `runtime_status_json`, `_ver_ge` |
| `scripts/lib/common.sh` | `ct_operator_id`, `ct_host_id`, `_owner_of_ct`; `ct_own` podman path; `ct_group_read`; `need_env` → `runtime_check`; `hub_env_write` port start; podman hints |
| `scripts/lib/stack.sh` | `init --runtime`, the `.env` keys, `stack_compose_up`, host checks in init/up/upgrade |
| `scripts/lib/domains.sh`, `scripts/lib/mcpgate.sh` | The five `ct_own "$(id -u):…"` sites → `ct_operator_id` |
| `scripts/lib/backup.sh` | restic `--user`, restore keeps runtime keys, host checks in restore, MANIFEST runtime, podman user units |
| `scripts/lib/status.sh` | `runtime:` line, `runtime{}` in `--json`, `version` runtime |
| `docker-compose.yml`, `docker-compose.podman-selinux.yml` (new) | Socket variable, `selinux: z` binds, `HUB_CONTAINER_RUNTIME`; proxies' `label=disable` |
| `portcullis`, `.env.example`, `CLAUDE.md`, `tests/test_shell_libs.sh`, `tests/test_cli.sh` | Sourcing, docs of keys, rules, tests |
| `.github/workflows/ci.yml`, `tests/e2e/e2e_podman.py` (new) | Static checks, libpod denials, `e2e-podman`, the `e2e` backup artifact |

**Hub (`wt-podman1/portcullis-hub`)**

| File | Responsibility |
|---|---|
| `internal/idmap/idmap.go` (new) | `uid_map` / `gid_map` parser and shapes |
| `internal/docker/runtime.go` (new), `client.go`, `run.go` | `Runtime`, `Guard`, guarded transport, `Components`, `ContainerInfo.Memory/PidsLimit` |
| `internal/compose/*.go` | `NewCLI(host, guard)`: refuses while the guard does |
| `cmd/hub/main.go` | `runtimeFromEnv` (`HUB_CONTAINER_RUNTIME` required), guard loop |
| `internal/hub/runtime_engine.go` (new), `fixer.go`, `override.go`, `instances.go`, `lifecycle.go` | `RuntimeView`, fixer gate, `selfContainerID` podman, SELinux renderer, compat gate |
| `internal/folderfix/{walk,apply,childfix,scan,fs_linux,fs_other}.go` | `idMapsAllowed`, `IDMap` / host ids / `Unmapped` / `SELinux` in reports |
| `internal/templates/rootless.go` (new), `testdata/rootless_vectors.json` (new) | `RootlessCompat` and its vectors |
| `internal/doctor/engine.go` (new), `internal/hub/doctor_engine.go` (new) | Five kinds and their inputs |
| `internal/httpapi/{server,instances,mcptools_admin}.go`, `web/index.html` | `GET /api/runtime`, `get_runtime`, 503 mapping, badges |
| `CLAUDE.md` | Runtime guard and gate rules |

**Templates (`wt-podman1/portcullis-templates`):** `tests/validate.py` (`rootless_compat`, `--rootless`), `tests/rootless_vectors.json` (byte copy), `tests/rootless.txt` (committed classification), `tests/test_validate.py`, `.github/workflows/lint.yml`, `CLAUDE.md`.

**Docs (`wt-podman1/portcullis-docs`):** `docs/guides/integration-contracts.md`, `docs/operations/rootless-podman.md` (new), `docs/operations/.nav.yml`, `hardening.md`, `cli.md`, `testing.md`, `hub.md`, `backups.md`, `docs/setup/quickstart.md` (one pointer line).

---

### Task 1: Contract (docs, first)

**Files:**
- Modify: `docs/guides/integration-contracts.md`:
  - §2 (core env, about line 35)
  - §6 "Docker access" (about 715–772; retitle it "Engine access")
  - §11 (instance create/enable refusals)
  - §14.2 (fixer report) and §14.5 (doctor kinds)
  - §15.10 (admin tools)
- Modify (Hub): `web/docs/*` via `sync.sh`

**Interfaces — Produces (binding for Tasks 2–10):**
- §2: `PORTCULLIS_UNPRIVILEGED_PORT_START` in `secrets/hub/core.env`, written only when `CONTAINER_RUNTIME=podman`. It is an integer 1–65535 and is not a template variable.
- §6:
  - Each proxy mounts "the engine socket" `${PORTCULLIS_ENGINE_SOCKET:-/var/run/docker.sock}`, read-only, and no other service does.
  - `/libpod/…` and `/v*/libpod/…` are always denied, and so is `/build`.
  - The Hub env `HUB_CONTAINER_RUNTIME=docker|podman` is required. At start the Hub compares it with `/version` `Components[].Name` (`Podman Engine` → podman, `Engine` → docker). Until they agree, and permanently once they contradict, every engine operation and every compose run answers **503** `the container engine is not verified: <why>`.
  - Fixer "Refusals before any run" now reads: `userns`, or `rootless` unless `HUB_CONTAINER_RUNTIME=podman`, → 503. Under podman the fixer also refuses any map that is neither identity nor the consistent shape.
  - Fixer image lookup: the Docker mountinfo root as today, and under podman `…/overlay-containers/<64 hex>/userdata/<file>`.
- §11: under podman, `POST /api/instances` and enable refuse **409** `<id> can't run under rootless Podman: <reasons joined "; ">` for a `refused` compat. Template and instance views carry `rootless: {status: ok|degraded|refused, reasons: [...]}` (podman only; absent under Docker).
  - `GET /api/runtime` (Hub listener) answers `{runtime, verified, engine, engine_version, mismatch, rootless, uid_map, gid_map, unprivileged_port_start, selinux}`, where each map is `[{container, host, size}]` (null under Docker) and `unprivileged_port_start` is null under Docker.
- §14.2: report fields `id_map: {uid: [...], gid: [...]}` (omitted for identity), `owners[].host_uid` / `host_gid` and `children[].host_uid` / `host_gid` (omitted for identity), `unmapped: Count` (entries whose uid or gid reads 65534 under a non-identity map), `selinux_label` (the root's `security.selinux`, omitted when there is none).
  - Under a non-identity map, `apply`, `restore` and `childfix` refuse while `unmapped.n > 0` with `<rel> is owned by a host account outside Portcullis' id range`.
  - The Hub appends `; run sudo chown -R <operator uid> <host path> once, then re-check`.
- §14.5 kinds (podman only, explain-only):
  - `runtime_mismatch` (problem)
  - `limits_not_enforced` (warning)
  - `unmapped_owner` (warning)
  - `selinux_label_missing` (warning; steps `semanage fcontext -a -t container_file_t '<path>(/.*)?'` and `restorecon -R <path>`)
  - `udp_source_rewritten` (info)
- §15.10: the admin tool `get_runtime` (class R), whose twin is `GET /api/runtime`.

- [ ] **Step 1:** Write the sections above in the contract's existing style (NEW (rootless) markers, as earlier features did). Keep §6's socket sentence word for word, with "the engine socket (`PORTCULLIS_ENGINE_SOCKET`)" in place of `/var/run/docker.sock`.
- [ ] **Step 2:** Run `python3 scripts/check-lists.py && bash scripts/check-branding.sh`. Expected: no output, exit 0.
- [ ] **Step 3:** Commit (`docs: contract for rootless Podman (engine socket, runtime guard, compat gate, fixer maps, doctor kinds)`) and push `podman1`.
- [ ] **Step 4:** In the Hub worktree, run `sync.sh` (Global Constraints), check that `git diff --stat web/docs` lists only `integration-contracts.md`, commit (`docs: sync contract`) and push.

---

### Task 2: Hub engine runtime guard, id maps, `/api/runtime`

**Files:**
- Create: `internal/idmap/idmap.go`, `internal/idmap/idmap_test.go`, `internal/docker/runtime.go`, `internal/docker/runtime_test.go`, `internal/hub/runtime_engine.go`, `internal/hub/runtime_engine_test.go`
- Modify: `internal/docker/client.go` (`New`), `internal/compose/*.go` (`NewCLI`), `cmd/hub/main.go` (around 299–315), `cmd/hub/main_test.go`, `internal/hub/fixer.go:529-560` (`selfMountRe`, `selfContainerID`), `internal/httpapi/server.go` (`errStatus`, hub mux), `internal/httpapi/mcptools_admin.go`, `internal/httpapi/mcp_parity_test.go` (tool list near line 389), `internal/hub/reconcile_test.go`, `CLAUDE.md`

**Interfaces:**
- Produces:
  - `idmap.Range{Container, Host, Size uint32}` with JSON keys `container`, `host`, `size`.
  - `idmap.Map []Range`:
    - `idmap.Parse(s string) (Map, error)`: strict, 1–340 lines of three decimals.
    - `(Map) Identity() bool` (`0 0 4294967295`).
    - `(Map) Consistent() bool`: exactly `[{0, op, 1}, {1, start, n}]` with `op != 0` and `n >= 65536`.
    - `(Map) ToHost(c uint32) (uint32, bool)`.
    - `const idmap.Overflow = 65534`.
  - `docker.Runtime` (`RuntimeDocker = "docker"`, `RuntimePodman = "podman"`) and `docker.ParseRuntime(string) (Runtime, error)`.
  - `docker.ErrEngineRefused` (sentinel; every refusal wraps it).
  - `docker.NewGuard(want Runtime) *Guard`, with methods:
    - `(*Guard) Err() error`
    - `(*Guard) Verify(ctx, VersionReader) error`
    - `(*Guard) Run(ctx, VersionReader, every time.Duration)`
    - `(*Guard) Info() EngineInfo`
  - `docker.EngineInfo{Runtime Runtime; Verified bool; Engine, Version, Mismatch string}`.
  - `docker.VersionReader` (has `Components(ctx) ([]Component, error)`), `docker.Component{Name, Version string}`, and `docker.RuntimeOf([]Component) Runtime` ("" for neither).
  - `docker.New(host string, g *Guard) (*Client, error)`. Its transport passes `GET /_ping`, `/version` and `/v*/version` always; every other request returns `g.Err()` while it is non-nil.
  - `compose.NewCLI(host string, g *docker.Guard)`: every command returns `g.Err()` first.
  - `hub.RuntimeView` (the contract §11 JSON) and `(*Hub) Runtime(ctx) RuntimeView`. `hub.Config` gains `Runtime docker.Runtime` and `Guard *docker.Guard`.
  - `selfContainerID(mountinfo []byte, rt docker.Runtime) (string, error)`.

- [ ] **Step 1: Write the failing tests.**
  - `TestParseShapes`: table cases:
    - `"0 0 4294967295"` → Identity.
    - `"0 1001 1\n1 100000 65536"` → Consistent, `ToHost(10001) == 110000`.
    - `"0 100000 65536"` → neither.
    - `n=65535` → not Consistent.
    - `op=0` → not Consistent.
    - Three ranges → not Consistent.
    - Garbage or empty → error.
  - `TestRuntimeOf`: `[{Name:"Podman Engine"}]` → podman, `[{Name:"Engine"},{Name:"containerd"}]` → docker, `[]` → "".
  - `TestGuardRetriesUntilVerified`: a fake reader fails twice, then answers docker for a docker guard. `Err()` wraps `ErrEngineRefused` until then, then nil.
  - `TestGuardMismatchIsPermanent`: a podman answer to a docker guard gives `Err()` containing `HUB_CONTAINER_RUNTIME=docker but the engine is Podman Engine`, and a later docker answer does not clear it.
  - `TestGuardedTransport`: `/v1.47/containers/json` is refused before verification; `/_ping` and `/v1.47/version` reach an `httptest` server.
  - `TestComposeRefusesUnverified`.
  - `TestSelfContainerIDPodman`: `/home/p/.local/share/containers/storage/overlay-containers/<64 hex>/userdata/hostname` mounted at `/etc/hostname` → the id under podman, and an error under docker. Docker lines are unchanged.
  - `TestRuntimeFromEnv` (cmd/hub): "" or "rkt" → refuse to start, docker and podman are accepted.
  - `TestRuntimeView`: under docker the maps and port are null. Under podman with a fake `/proc/self/uid_map` (seam `readIDMaps`) and core env `PORTCULLIS_UNPRIVILEGED_PORT_START=80` the maps are filled and the port is 80. `abc` gives 1024.
  - `TestRuntimeRoute`: `GET /api/runtime` is 200 with that JSON, and a guard refusal on another route is 503 (`errStatus`).
  - `TestAdminToolsSameAsHTTP` gains `get_runtime`.
  - `TestWatchEventsIgnoresPodmanActions` (`init`, `cleanup`, `health_status` trigger nothing).
- [ ] **Step 2:** Run `go test ./internal/idmap/ ./internal/docker/ ./internal/compose/ ./internal/hub/ ./internal/httpapi/ ./cmd/hub/`. Expected: FAIL (undefined `idmap`, `NewGuard`, …).
- [ ] **Step 3: Implement.**
  - `Components` uses the moby client's `ServerVersion` (`res.Components`).
  - In `main`: `runtimeFromEnv(os.Getenv)` → `docker.NewGuard`, then `docker.New(dockerHost, guard)` and `compose.NewCLI(dockerHost, guard)`. Then `go guard.Run(ctx, engine, 10*time.Second)`, which logs once per state change and stops after verification or a mismatch.
  - `errStatus`: `errors.Is(err, docker.ErrEngineRefused)` → 503.
  - Register `GET /api/runtime` on the Hub listener only.
  - `get_runtime` is `admin(..., ClassRead, Twin: "GET /api/runtime")`, following `list_ops`.
  - Hub `CLAUDE.md`: one row for `internal/idmap` and the guard sentence in `cmd/hub`.
- [ ] **Step 4:** Run the Hub gates (Global Constraints). Expected: PASS, gofmt prints nothing.
- [ ] **Step 5:** Commit (`hub: engine runtime guard (HUB_CONTAINER_RUNTIME, 503 until verified), id maps, /api/runtime, get_runtime`).

---

### Task 3: Hub folder fixer under the consistent mapping

**Files:**
- Modify:
  - `internal/folderfix/fs_linux.go:280-292`, `fs_other.go:98` (replace `idMapsIdentity`)
  - `walk.go:137-141` (`identityMap` → `idmap`), walk tally and `finish` (about 367–390)
  - `apply.go:92-104` (`mayChange`), `childfix.go:185-198`, `restore.go` (`checkHeader`)
  - `scan.go` (`Report`, `OwnerCount`, `ChildOwner`)
  - `internal/hub/fixer.go:270-335` (`execFixer` gate, the unmapped message)
- Test: `internal/folderfix/plan_test.go`, `internal/folderfix/scan_test.go`, `internal/hub/fixer_test.go`

**Interfaces:**
- Consumes: `idmap.Map` (Task 2), `Hub.cfg.Runtime`.
- Produces:
  - `folderfix.IDMaps{UID, GID idmap.Map}` (JSON `uid`, `gid`).
  - `Report.IDMap *IDMaps` (`id_map,omitempty`), `Report.Unmapped Count` (`unmapped`), `Report.SELinux string` (`selinux_label,omitempty`).
  - `OwnerCount.HostUID, HostGID *uint32` and `ChildOwner.HostUID, HostGID *uint32` (`host_uid,omitempty`, `host_gid,omitempty`).
  - Seam `var readIDMaps func() (uid, gid idmap.Map, err error)`.
  - `idMapsAllowed(uid, gid idmap.Map) error` (nil for identity or both Consistent, else a `refuse(...)`). The message keeps today's text for the non-consistent case.
  - `const UnmappedMsg = "%s is owned by a host account outside Portcullis' id range"`.
  - Hub `fixerIDsAllowed(rt docker.Runtime, opts []string) error`.

- [ ] **Step 1: Write the failing tests.**
  - `TestIDMapsAllowed`: identity → ok; consistent uid+gid → ok; consistent uid with a userns-remap gid → refused; single remap → refused.
  - `TestScanCountsUnmapped` (seam: a consistent map; tree via the existing fake walk helpers with one file at uid 65534): `unmapped.n == 1`, sample = its rel, `id_map` set, `owners[0].host_uid == ToHost(uid)`.
  - `TestScanIdentityNoUnmapped` (65534 under identity → `unmapped.n == 0`, `id_map` absent).
  - `TestApplyRefusesUnmapped`: an apply with `unmapped.n > 0` → `*Refused` whose text equals `fmt.Sprintf(UnmappedMsg, "<rel>")`, and nothing changed.
  - `TestChildfixRefusesUnmapped`, same for childfix.
  - `TestScanSELinuxLabel` (fake `Fgetxattr` seam returning `system_u:object_r:container_file_t:s0`) → `selinux_label`.
  - Hub `TestRunFixerRootlessPodman`: SecurityOptions `name=rootless` + runtime podman → the run happens; + runtime docker → 503 with today's message; `name=userns` + podman → 503.
  - `TestFixerUnmappedMessage`: a 409 from a report whose error is `UnmappedMsg` gets `; run sudo chown -R 1001 /srv/media/x once, then re-check` (operator uid from the report's `id_map.uid[0].host`, host path = folder host path + rel).
- [ ] **Step 2:** Run `go test ./internal/folderfix/ ./internal/hub/ -run 'IDMaps|Unmapped|SELinux|RootlessPodman|UnmappedMessage'`. Expected: FAIL.
- [ ] **Step 3: Implement.**
  - The walker reads the maps once per run. It counts `Unmapped` where `st.UID == idmap.Overflow || st.GID == idmap.Overflow` under a non-identity map.
  - `mayChange`, `childfix` and `restore` call `idMapsAllowed`, then refuse on `Unmapped.N > 0`.
  - The label is read with `unix.Fgetxattr(fd, "security.selinux", …)`; ENODATA/ENOTSUP → "".
  - In the Hub `execFixer`, replace the `RemappedIDs` refusal with `fixerIDsAllowed` and add the message suffix.
- [ ] **Step 4:** Run the Hub gates, then `sudo -E env "PATH=$PATH" go test -tags fixerroot -count=1 ./internal/folderfix/` on a Linux box if available (CI build.yml runs it). Expected: PASS.
- [ ] **Step 5:** Commit (`hub: folder fixer allows the rootless Podman mapping; host ids, unmapped owners refused per path, SELinux label`).

---

### Task 4: Hub compatibility gate `RootlessCompat` + UI

**Files:**
- Create: `internal/templates/rootless.go`, `internal/templates/rootless_test.go`, `internal/templates/testdata/rootless_vectors.json`
- Modify:
  - `internal/hub/instances.go:275` (`CreateInstance`), `internal/hub/lifecycle.go:95` (`prepareUp`)
  - The template/instance views (`internal/templates/manifest.go` `Template`: `Rootless *Compat` with `json:"rootless,omitempty"`)
  - `internal/hub/realtemplates_test.go`, `web/index.html`, `internal/httpapi/webui_apps_test.go`, `CLAUDE.md`

**Interfaces:**
- Consumes: `Hub.Runtime` / `unprivilegedPortStart()` (Task 2).
- Produces:
  - `templates.Compat{Status string; Reasons []string}` (JSON `status`, `reasons`), with `CompatOK = "ok"`, `CompatDegraded = "degraded"`, `CompatRefused = "refused"`.
  - `templates.RootlessCompat(compose []byte, m Manifest, env map[string]string, portStart int) Compat` (ruling R5).
  - `(*Hub) instanceCompat(t *templates.Template, s state.InstanceSettings) templates.Compat` (podman only).
- Rules (reasons are the exact strings, in the order the rules are listed). Any refused reason makes the result `refused` with every refused reason. Otherwise any degraded reason makes it `degraded`. Otherwise `ok`. `${VAR:-d}` is resolved from `env`, then the default.
  1. A device whose source isn't `/dev/null` and isn't `/dev/net/tun` → refused `service <s> passes the host device <src>: device access needs host root`.
  2. `cap_add` `SYS_RAWIO` or `SYS_ADMIN` → refused `service <s> needs <CAP> (raw device access needs host root)`.
  3. Any `user:` / `group_add` / folder `runs_as` id > 65535 → refused `service <s> runs as id <n>, outside the rootless id range (0–65535)`.
  4. A host port (tcp/udp, incl. a `range` start and `network_mode_host` ports) below `portStart` → refused `host port <p>/<proto> is below net.ipv4.ip_unprivileged_port_start (<portStart>): lower it to <p> on the host to allow it (any local user can then bind ports from <p>)`.
  5. A device source `/dev/null` → degraded `service <s> has device slots: host devices can't be passed under rootless Podman`.
  6. `/dev/net/tun` or `NET_ADMIN` → degraded `service <s> uses TUN/NET_ADMIN inside the rootless network namespace (prefer a userspace mode)`.
  7. A udp port → degraded `UDP clients on port <p> appear with a rewritten source address`.
  8. `network_mode_host` → degraded `host networking: published ports must stay at or above <portStart>`.

- [ ] **Step 1: Write the failing tests.**
  - Write `rootless_vectors.json`: an array of `{name, compose, ports, env, port_start, want: {status, reasons}}`. Vectors:
    - "plain web app ok"
    - "dns 53 refused at 80", and the same at 53 → degraded (udp)
    - "samba 445 ok"
    - "scrutiny SYS_RAWIO refused" (its real compose with `${SCRUTINY_NVME_CAPABILITY:-SYS_RAWIO}`)
    - "device slot unset → degraded", and "device slot set → refused" (env `ESPHOME_SERIAL_DEVICE=/dev/ttyUSB0`)
    - "tun degraded"
    - "uid 70000 refused"
    - "coturn host network + udp degraded"
  - `TestRootlessVectors` iterates over the vectors.
  - `TestCreateRefusedUnderPodman`: a fake runtime podman, port start 80, pihole-like template → 409 with the contract text. Under docker → created.
  - `TestEnableRefusedUnderPodman` (prepareUp, instance env sets a device).
  - `TestTemplateViewRootless`: field present under podman, absent under docker.
  - `TestRealTemplatesRootlessClassification`: needs `PORTCULLIS_TEMPLATES_DIR`, else skips like its siblings. It compares `<id>\t<status>\t<reasons joined "; ">` over every template, sorted, with `$PORTCULLIS_TEMPLATES_DIR/tests/rootless.txt` (made in Task 6) at port start 80.
  - `TestHubAppsPageRootless` (static): `web/index.html` has `function rootlessBadge(` and `data-rootless=`, and the create button is disabled for `refused`.
- [ ] **Step 2:** Run `go test ./internal/templates/ ./internal/hub/ ./internal/httpapi/ -run 'Rootless|RefusedUnderPodman'`. Expected: FAIL.
- [ ] **Step 3: Implement.**
  - Parse with the package's existing compose YAML decoding.
  - `instanceCompat` takes the instance's ports (`s.Ports` over the manifest defaults) and its `.env`.
  - The gate runs only when `h.cfg.Runtime == docker.RuntimePodman`.
  - UI: the Marketplace card badge "Rootless: works / limited / not available" with the reasons in its title. On the instance page, the reasons list. Fetch `/api/runtime` once at page load and show nothing under Docker.
  - Hub CLAUDE.md: describe `RootlessCompat` in the `internal/templates` row.
- [ ] **Step 4:** Run the Hub gates. Expected: PASS (`TestRealTemplatesRootlessClassification` skips locally).
- [ ] **Step 5:** Commit (`hub: rootless compatibility gate (RootlessCompat + shared vectors), refusals at create/enable, Marketplace badges`).

---

### Task 5: Hub SELinux renderer and the five doctor kinds

**Files:**
- Create: `internal/doctor/engine.go`, `internal/doctor/engine_test.go`, `internal/hub/doctor_engine.go`, `internal/hub/doctor_engine_test.go`
- Modify: `internal/doctor/doctor.go` (`Inputs`: `Engine *EngineIn`; `RuntimeIn`: `Memory, PidsLimit int64; WantMemory, WantPids bool`), `internal/docker/run.go:305` (`ContainerInfo.Memory`, `PidsLimit` from `HostConfig`), `internal/hub/override.go` (`renderOverrideIn`, about 73–260), `internal/hub/folders_render_test.go` or `golden_test.go`

**Interfaces:**
- Consumes: `RuntimeView` (Task 2), `Report.Unmapped` / `SELinux` (Task 3).
- Produces:
  - `doctor.EngineIn{Runtime string; Mismatch string; SELinux bool}`.
  - The kind constants `KindRuntimeMismatch = "runtime_mismatch"`, `KindLimitsNotEnforced = "limits_not_enforced"`, `KindUnmappedOwner = "unmapped_owner"`, `KindSELinuxLabelMissing = "selinux_label_missing"`, `KindUDPSourceRewritten = "udp_source_rewritten"`, and `doctor.EngineKinds`.
  - `selinuxRelabels(compose []byte) map[string][]string`: per service, the long-syntax entries for the binds under `./templates/`, plus the Hub's appfiles mounts.

- [ ] **Step 1: Write the failing tests.**
  - `TestEngineKindsDockerSilent` (`Engine.Runtime == "docker"` → no findings).
  - `TestRuntimeMismatchProblem`.
  - `TestLimitsNotEnforced` (`WantMemory && Memory == 0` → warning naming instance/service).
  - `TestUnmappedOwnerWarning` (a ScanIn report with `unmapped.n = 2` → warning with samples).
  - `TestSELinuxLabelMissing` (SELinux on, label `user_home_t` or a scan error containing `permission denied` → warning with the two contract steps; `container_file_t` → none).
  - `TestUDPSourceRewritten` (a PortIn `Protocol: "udp"` → info).
  - `TestOverrideSELinuxRelabel`: on SELinux, a template bind `./templates/x/gate.sh:/gate.sh:ro` is re-declared as `{type: bind, source: ./templates/x/gate.sh, target: /gate.sh, read_only: true, bind: {selinux: z}}`. A shared-folder mount never gets `selinux`. Without SELinux the rendered output is byte-identical to today's golden.
- [ ] **Step 2:** Run `go test ./internal/doctor/ ./internal/hub/ -run 'Engine|Limits|Unmapped|SELinux|UDP|Relabel'`. Expected: FAIL.
- [ ] **Step 3: Implement.**
  - Register the checks in `init()` as `dns.go` does.
  - `doctor_engine.go` fills `Inputs.Engine` from `h.cfg.Guard.Info()` and SecurityOptions (`name=selinux`), cached with the scans.
  - `WantMemory` / `WantPids` come from the instance's rendered compose (`mem_limit` / `pids_limit` set).
  - The renderer emits the relabel entries only when SELinux is reported.
- [ ] **Step 4:** Run the Hub gates. Expected: PASS.
- [ ] **Step 5:** Commit (`hub: SELinux relabel of the Hub's own binds, doctor kinds for rootless Podman`). Push `podman1` and dispatch `gh workflow run build.yml --ref podman1`. Expected: green except `TestRealTemplatesRootlessClassification` until Task 6 is pushed. Re-run after Task 6: green.

---

### Task 6: Templates classification

**Files:**
- Modify: `tests/validate.py` (new `rootless_compat(t, env=None, port_start=80) -> Tuple[str, List[str]]` and a `--rootless` flag in `main`), `tests/test_validate.py` (`RootlessTests`), `.github/workflows/lint.yml`, `CLAUDE.md`
- Create: `tests/rootless_vectors.json` (byte copy of the Hub's `internal/templates/testdata/rootless_vectors.json`), `tests/rootless.txt`

**Interfaces:**
- Consumes: the rules and reason strings of Task 4 (R12).
- Produces: `tests/rootless.txt` (`<id>\t<status>\t<reasons>` per template, sorted, port start 80). Hub Task 4's real-templates test reads it.

- [ ] **Step 1: Write the failing tests.**
  - `RootlessTests.test_vectors`: each vector through `rootless_compat` equals `want`.
  - `test_committed_classification`: `validate.py --rootless` output == `tests/rootless.txt`.
  - `test_expected_refusals`: pihole and adguard are `refused` with the `53/tcp` reason; scrutiny is `refused` naming `SYS_RAWIO`; esphome, motioneye and zigbee2mqtt are `degraded`; samba and timemachine are `ok`.
- [ ] **Step 2:** Run `python3 tests/test_validate.py`. Expected: FAIL (no `rootless_compat`).
- [ ] **Step 3: Implement** a rule-for-rule port of `RootlessCompat` (the same order and strings). Then generate `tests/rootless.txt` with `python3 tests/validate.py --rootless > tests/rootless.txt` and review it: no other template is `refused`.
- [ ] **Step 4: Add a lint.yml step** "Rootless vectors match the Hub". It fetches `https://raw.githubusercontent.com/porelli/portcullis-hub/<ref>/internal/templates/testdata/rootless_vectors.json`, where ref = the same-named Hub branch if `git ls-remote` finds it, else main. The step runs `cmp` against `tests/rootless_vectors.json` (the pattern of core's sign-in vectors step). No secrets.
- [ ] **Step 5:** Run `python3 tests/validate.py && python3 tests/test_validate.py`. Expected: PASS. Then update `CLAUDE.md` (the "Layout & tooling" line for `--rootless`, the vectors and `rootless.txt`: "a change to the classification shows in review"), commit (`tests: rootless Podman classification (shared vectors with the Hub)`) and push. Expected: lint.yml green on `podman1`.

---

### Task 7: Core runtime plumbing

**Files:**
- Create: `scripts/lib/runtime.sh`
- Modify:
  - `portcullis` (the source list: `common runtime network …`)
  - `scripts/lib/common.sh:140-145` (`need_env` → `runtime_check`), `common.sh` `hub_env_write`
  - `scripts/lib/stack.sh`: `init_write_env`, `init_run` (about 124–200), `stack_up` (416), `upgrade_run` (444), `help_init`, `cmd_init`; new `stack_compose_up`
  - `scripts/lib/backup.sh`: `backup_restore` (714 onwards: runtime keys and host checks), `_backup_manifest` (176: `runtime`)
  - `scripts/lib/status.sh`: `status_run` (100), `version_run` (465)
  - `.env.example`
- Test: `tests/test_shell_libs.sh`, `tests/test_cli.sh`

**Interfaces:**
- Produces (bash):
  - `runtime_name` → `docker|podman` (`${CONTAINER_RUNTIME:-docker}`).
  - `runtime_podman_socket` → `${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/podman/podman.sock`.
  - `runtime_detect [flag]` → prints docker|podman. Order: the flag or `CONTAINER_RUNTIME`; then `/var/run/docker.sock` or `DOCKER_HOST` without `Podman Engine`; then podman installed, not root, and the user socket's `_ping`. Otherwise exit 1 with the §4 hints. As root with podman, exit 1 "rootless only".
  - `runtime_export`:
    - Under podman, exports `DOCKER_HOST=unix://<socket>`.
    - With SELinux enforcing (`getenforce`), exports `COMPOSE_FILE` = (current, or `docker-compose.yml` plus `docker-compose.override.yml` if it exists) + `:docker-compose.podman-selinux.yml`, without duplicates.
  - `runtime_check`:
    - Runs once (`_RT_CHECKED`) and calls `runtime_export`.
    - Gets `docker version --format '{{json .Server.Components}}'`. An unreachable engine or a contradiction (`CONTAINER_RUNTIME=docker but the engine is Podman Engine`, or the reverse) → `fail`.
    - Under podman, `PORTCULLIS_ENGINE_SOCKET` must be `-S` and equal `runtime_podman_socket`.
  - `runtime_id_maps`: sets `_RT_UID_OP _RT_UID_START _RT_UID_N _RT_GID_OP _RT_GID_START _RT_GID_N` from `podman unshare cat /proc/self/uid_map` / `gid_map`. A non-consistent shape or `n < 65536` → returns 1.
  - `runtime_port_start` (reads `${RT_PROC_PORT_START:-/proc/sys/net/ipv4/ip_unprivileged_port_start}`).
  - `runtime_host_checks`: prints `ok|warn|fail<TAB><text>` lines; † items are `fail`. Overridable paths: `RT_PROC_PORT_START`, `RT_CGROUP_ROOT`. The checks:
    - uid ≠ 0
    - subuid/subgid shape
    - a probe container's uid_map equals the unshare map (global userns)
    - `memory` and `pids` in `$RT_CGROUP_ROOT/user.slice/user-<uid>.slice/user@<uid>.service/cgroup.controllers`, plus a probe container created with `--memory 16m --pids-limit 8` whose inspect shows both
    - `loginctl show-user -p Linger --value` = yes
    - `systemctl --user is-enabled podman.socket podman-restart.service`
    - port start ≤ 80
    - nft or iptables (warn)
    - podman ≥ 5.4 (`_ver_ge`)
    - `docker compose version`
    - SELinux mode (ok line)
  - `runtime_require_host`: under podman, fails on any `fail` line, listing them all. Under docker it is a no-op.
  - `runtime_build_local`: for each service with a `build` section in `dc config --format json`, runs `podman build -t <image> -f <dockerfile> [--build-arg K=V…] <context>`.
  - `stack_compose_up [svc…]`: docker → `dc up -d --build "$@"`; podman → `runtime_build_local && dc up -d --no-build "$@"`.
  - `runtime_status_json` → `{name, version, rootless, uid, subuid_start, subuid_count, subgid_start, subgid_count, port_start, checks: [{status, text}]}`.
  - `init --runtime docker|podman`: an existing `.env` with a different `CONTAINER_RUNTIME` → exit 1 `CONTAINER_RUNTIME is docker in .env and is never switched (backup → fresh init → restore)`.

- [ ] **Step 1: Write the failing tests** (in `tests/test_shell_libs.sh`). A `docker` stub answers `version --format …` by `$DOCKER_HOST` (`STUB_DOCKER_SOCK_ENGINE`, `STUB_PODMAN_SOCK_ENGINE` = `Engine`|`Podman Engine`|`down`). A `podman` stub answers `unshare cat …`, `version` and `build` (logging argv). Tests, by name:
  - "runtime_detect: docker socket without Podman component → docker"
  - "runtime_detect: both present → docker"
  - "runtime_detect: --runtime podman → podman"
  - "runtime_detect: podman as root → refused"
  - "runtime_detect: nothing answers → fails with the host-prep hints"
  - "runtime_check: CONTAINER_RUNTIME=docker but the engine is Podman → fails"
  - "runtime_check: podman exports DOCKER_HOST=unix://<XDG>/podman/podman.sock"
  - "runtime_podman_socket falls back to /run/user/<uid>" (Review Focus 4)
  - "runtime_export keeps docker-compose.override.yml beside the SELinux overlay" (Review Focus 1; `getenforce` stub prints Enforcing)
  - "runtime_id_maps: 65535 subuids → refused"
  - "runtime_host_checks: port start 1024 → fail line naming ip_unprivileged_port_start"
  - "runtime_host_checks: no pids in cgroup.controllers → fail"
  - "stack_compose_up on podman builds with podman build and runs up --no-build"
  - "init: CONTAINER_RUNTIME=docker in .env, --runtime podman → refused"
  - "init --env-only writes CONTAINER_RUNTIME=podman and the rootless PORTCULLIS_ENGINE_SOCKET with --runtime podman"
  - "hub_env_write: PORTCULLIS_UNPRIVILEGED_PORT_START only under podman"
  - "restore keeps the host's runtime keys" (Review Focus 2: the backup's `.env` without the keys over a podman `.env`)
  - "MANIFEST.json records runtime {name, version}"
  - "status --json has runtime{}"

  In `tests/test_cli.sh`: the stub answers the version call, and add "init --help documents --runtime" and "every --help works with no engine" (the stub exits 99 on any call, and `STUB_CALLS` stays empty).
- [ ] **Step 2:** Run `bash tests/test_shell_libs.sh; bash tests/test_cli.sh`. Expected: the new cases FAIL.
- [ ] **Step 3: Implement.**
  - `init_write_env` writes `CONTAINER_RUNTIME=<detected>`, plus `PORTCULLIS_ENGINE_SOCKET=<socket>` under podman, with a comment block saying "chosen by init, never switched". `--env-only` without a flag and no engine writes `docker` with an info line (later runs verify it).
  - `init_run`, `stack_up` and `upgrade_run` call `runtime_check` and `runtime_require_host` before `network_check`, and replace each `dc up -d --build` with `stack_compose_up`.
  - `backup_restore` saves the two keys from the current `.env` (`env_get`) before the copy, then writes them back with `env_set`, or deletes them when they were absent and `runtime_detect` says docker. It calls `runtime_require_host` before stopping anything.
  - `hub_env_write` appends `PORTCULLIS_UNPRIVILEGED_PORT_START=$(runtime_port_start)` under podman only.
  - Status prints `runtime: podman <ver> rootless, uid <u>, subuid <s>+<n>, ports ≥ <p>` or `runtime: docker <ver>`, and every `fail` line counts as a problem. `version` and `--json` add `runtime` and `runtime_version`. `.env.example` documents both keys.
- [ ] **Step 4:** Run the core gates. Expected: PASS, shellcheck clean.
- [ ] **Step 5:** Commit (`cli: CONTAINER_RUNTIME (init --runtime, runtime_check, host-prep checks, podman build), restore keeps the host's runtime`).

---

### Task 8: Core ownership under the user namespace

**Files:**
- Modify:
  - `scripts/lib/common.sh:278-340` (`_owner_of`, `ct_own`, `ct_group_read`), `common.sh:427` and `452-455` (hints, owner checks)
  - `scripts/lib/domains.sh:237-242`, `scripts/lib/mcpgate.sh:81-82`
  - `scripts/lib/backup.sh:383` (`_restic`), `backup.sh:873-931` (`backup_schedule_systemd`)
  - `scripts/lib/certs.sh:77` (hint), `CLAUDE.md` ("Admin CLI" ownership bullet)
- Test: `tests/test_shell_libs.sh`, `tests/test_cli.sh`

**Interfaces:**
- Consumes: `runtime_name`, `runtime_id_maps` (Task 7).
- Produces:
  - `ct_operator_id` → `$(id -u)` on docker, `0` on podman.
  - `ct_host_id <c>` → the host id (`c=0` → `_RT_UID_OP`, else `_RT_UID_START + c − 1`; out of range → exit 1). The gid side is `ct_host_gid <c>`.
  - `_owner_of_ct <path>` → `uid:gid` in container ids (the identity on docker), `unmapped` for any side outside the map.
  - `ct_hint_chown <spec> <paths…>` → `sudo chown …` (docker) or `podman unshare chown …` (podman).

- [ ] **Step 1: Write the failing tests.**
  - "ct_host_id: 0 → operator, 10001 → subuid+10000, 70000 → error"
  - "_owner_of_ct: host operator → 0, subuid+10000 → 10001, host root → unmapped" (stub `stat`)
  - "ct_own on podman always runs the helper (never chown directly, even as uid 0 stub) and is a no-op when _owner_of_ct matches"
  - "ct_group_read on podman passes 0:<gid>"
  - "_restic on podman runs --user 0:0 --cap-drop ALL"
  - "backup schedule --systemd on podman writes user units (Requires=podman.socket, no User=, WantedBy=default.target)"
  - The grep test in `tests/test_cli.sh`: `grep -rn 'ct_own "$(id -u)' scripts/lib portcullis` prints nothing.
- [ ] **Step 2:** Run `bash tests/test_shell_libs.sh; bash tests/test_cli.sh`. Expected: FAIL.
- [ ] **Step 3: Implement.**
  - On docker, `ct_own` keeps its current behaviour.
  - Change the six call sites (`ct_group_read`, three in `domains_fix_perms`, two in `mcpgate_fix_perms`) to `"$(ct_operator_id):…"`.
  - The failure messages use `ct_hint_chown`.
  - On podman, the `stack_prepare` writability hint becomes `podman unshare chown -R 0:0 "<path>"`.
  - In `CLAUDE.md`, add the rule "never `ct_own "$(id -u):…"` — use `ct_operator_id`; container root is the operator under Podman".
- [ ] **Step 4:** Run the core gates. Expected: PASS.
- [ ] **Step 5:** Commit (`cli: ownership through the rootless id map (ct_operator_id, ct_host_id, _owner_of_ct), restic and backup timer under podman`).

---

### Task 9: Core compose, overlay and static CI checks

**Files:**
- Modify: `docker-compose.yml` (proxies lines 101 and 148, every `./…` bind (45 entries), the Hub `environment` about line 869)
- Create: `docker-compose.podman-selinux.yml`
- Modify: `.github/workflows/ci.yml` (unit-tests "compose files are valid…" step about 200–300, build-and-test "Test the socket proxies" about 1795), `tests/test_cli.sh`, `CLAUDE.md` (the socket-rule sentence in Deployment, Key Files)

**Interfaces:**
- Produces:
  - Compose `HUB_CONTAINER_RUNTIME: ${CONTAINER_RUNTIME:-docker}`.
  - Both proxies mount `- ${PORTCULLIS_ENGINE_SOCKET:-/var/run/docker.sock}:/var/run/docker.sock:ro`.
  - Each project bind becomes `{type: bind, source: ./…, target: …, read_only: <as before>, bind: {selinux: z}}` (R11).
  - The overlay sets `security_opt: ["no-new-privileges:true", "label=disable"]` on `socket-proxy-traefik` and `socket-proxy-hub` only.

- [ ] **Step 1: Write the failing checks** (they fail on the current compose).
  - In the unit-tests step, run the existing socket jq both on the default config and on `CONTAINER_RUNTIME=podman PORTCULLIS_ENGINE_SOCKET=/run/user/1001/podman/podman.sock docker compose -f docker-compose.yml config --format json`. The source compared is `env.PORTCULLIS_ENGINE_SOCKET // "/var/run/docker.sock"`.
  - `.services.hub.environment.HUB_CONTAINER_RUNTIME` equals the runtime given.
  - Every bind with a source under the project dir has `.bind.selinux == "z"`, and the engine-socket bind has none.
  - With `-f docker-compose.podman-selinux.yml` merged, `label=disable` appears exactly on the two proxies, and each keeps `no-new-privileges:true`.
  - No core service has `cap_add` `NET_ADMIN` or `SYS_ADMIN` (VPN cross-reference: core stays userspace).
  - The hardening baseline jq also runs on the overlay-merged config.
  - In "Test the socket proxies", add 403 checks on both proxies for `/libpod/info`, `/libpod/play/kube`, `/v5.0.0/libpod/containers/json` and `/build`. Use `tp` for Traefik's proxy and the Hub-side helper the step already uses.
  - In `tests/test_cli.sh`, check that the literal mount string appears exactly twice and `/var/run/docker.sock:/var/run/docker.sock` nowhere else.
- [ ] **Step 2:** Run the step's commands locally: `PORTCULLIS_ROOT=/tmp/pp-x ./portcullis init --env-only --non-interactive --domain ci.example.org --dns-provider none`, then the jq checks. Expected: FAIL.
- [ ] **Step 3: Implement** the compose changes. Then `stack_prepare` must still make every bind source before `up`, because long syntax keeps compose's `create_host_path` but a missing file would become a directory. Check that every file-bind source already exists after `stack_prepare`.
- [ ] **Step 4:** Run `docker compose -f docker-compose.yml config -q`, the same with `--profile '*'` and with the overlay, then the jq checks and the core gates. Expected: PASS.
- [ ] **Step 5:** Commit (`compose: engine socket variable, SELinux z on project binds, podman SELinux overlay for the proxies, HUB_CONTAINER_RUNTIME; CI static checks and libpod denials`).
- [ ] **Step 6 (controller):** run `gh workflow run ci.yml --ref podman1 -f jobs=unit-tests,build-and-test`. Expected: green (Docker path unchanged).

---

### Task 10: Core CI job `e2e-podman`

**Files:**
- Create: `tests/e2e/e2e_podman.py` (stdlib only; it polls ops with `tests/e2e/e2e_ops.py`)
- Modify: `.github/workflows/ci.yml` (the `workflow_dispatch` description list; the `e2e` job's final steps; the new job after `e2e-ai`), `CLAUDE.md` (Testing bullet)

**Interfaces:**
- Consumes: everything above; the CI templates `tests/e2e/apps/echo` and `tests/e2e/apps/folder-writer`; the templates repo's `scrutiny` (same-named templates branch, else main).
- Produces: job `e2e-podman`: `runs-on: ubuntu-26.04`, `timeout-minutes: 60`, `needs: [jobs-input, e2e]`. Its `if` is `always() && needs.jobs-input.result == 'success'` plus the usual name match for `e2e-podman`.

- [ ] **Step 1: Make the `e2e` job publish its backup.** After the job's tests it runs `./portcullis backup` and uploads `backups/<newest>` as `e2e-docker-backup` with `retention-days: 1` (R9).
- [ ] **Step 2: Build the job's setup steps.**
  - **Images.** Build the local images and the Hub/Keycloak images with the existing actions (`hub-image`, `keycloak-image`, build-push for enroll, group-gate, domains (`GO_TAGS=testprovider`) and mcp-gate) while Docker still runs. Then `docker save … | podman load`.
  - **Stop Docker.** `sudo systemctl disable --now docker.service docker.socket`, and assert that `/var/run/docker.sock` doesn't answer.
  - **Install.** `sudo apt-get install -y podman passt uidmap`. Make sure `/etc/subuid` and `/etc/subgid` give `runner` 65536 ids (`usermod --add-subuids 100000-165535 --add-subgids 100000-165535`).
  - **Sysctl.** `sudo sysctl -w net.ipv4.ip_unprivileged_port_start=80`.
  - **User services.** `sudo loginctl enable-linger runner`, then `XDG_RUNTIME_DIR=/run/user/$(id -u)` into `GITHUB_ENV`, then `systemctl --user enable --now podman.socket podman-restart.service`, then `DOCKER_HOST=unix://$XDG_RUNTIME_DIR/podman/podman.sock` into `GITHUB_ENV`.
  - **Init.** `ACME_STAGING=true ./portcullis init --runtime podman --non-interactive --domain portcullis.local --email ci@portcullis.local --dns-provider none --no-config-repo`, with the CI override as in `e2e`.
  - **Template sources.** Seed the Hub's local template sources as `e2e-folders` does (echo, folder-writer, scrutiny), and make `/srv/e2e-pod` as `e2e-folders` makes `/srv/e2e-media` (operator-owned, plus one `sudo chown root` child).
- [ ] **Step 3: Write the assertion steps**, each failing with `FAIL: <what>`.
  - `./portcullis status --json`: `.problems == 0`, `.runtime.name == "podman"`, `.runtime.port_start <= 80`.
  - Every pinned network: `docker network inspect` subnet and range equal `.env`, and Traefik, Keycloak, Hub and mcp-gate sit at their pinned IPs.
  - Every core container: `HostConfig.Memory > 0` and `PidsLimit > 0`.
  - The socket checks: copy the bodies of build-and-test's "Test the socket proxies" step, including the libpod denials from Task 9.
  - Traefik's API lists the docker provider's `hub@docker` and `people@docker` routers.
  - Secrets: `stat -c %u secrets/hub/core.env` = `$(id -u)`, and `podman unshare stat -c %u:%g` = `0:10001`.
  - Sign-in: the curl mTLS sign-in and the portal, copied from build-and-test's "Test mTLS authentication with client cert".
  - Forward-auth reaches `auth.portcullis.local` through `host-gateway` (a 302 to Keycloak from an app host).
  - `python3 tests/e2e/e2e_podman.py` covers the Hub side:
    - `/api/runtime` (`runtime == "podman"`, `verified`, `uid_map[0].host == os.getuid()`)
    - an echo instance through create, enable, disable, backup and restore (op polling via `e2e_ops`)
    - the fixer on `/srv/e2e-pod`: the operator-owned folder applies ok, and the root-owned child's apply answers 409 with `is owned by a host account outside Portcullis' id range` and its path
    - creating scrutiny answers 409 naming `SYS_RAWIO`
  - **Reboot simulation (R8).** `sudo systemctl restart user@$(id -u).service`, then wait ≤ 180 s for `status` to have no problems.
  - **Docker → Podman round trip.** Fail when `needs.e2e.result != 'success'` with `FAIL: run with jobs=e2e,e2e-podman`. Download `e2e-docker-backup`, wipe (`./portcullis down`, `docker volume rm` of the project's volumes, remove `.env`, `secrets/` and `certs/`), `init --runtime podman`, `./portcullis restore --yes <dir>`. Then assert:
    - `.env` keeps `CONTAINER_RUNTIME=podman` and the rootless socket
    - status is clean
    - the sha256 of `certs/ca-chain.crt` equals the backup's
    - the e2e job's LLDAP users exist
    - secrets are operator-owned on the host
  - **Failure artifacts.** Upload the logs on failure (`docker compose logs`), never `.env` or `secrets/`.
- [ ] **Step 4:** Run `actionlint` and `bash tests/test_cli.sh`. Expected: PASS. Add `e2e-podman` to the `jobs` description list. Write the `CLAUDE.md` Testing bullet for `e2e-podman` and `e2e_podman.py`. Commit (`ci: e2e-podman (rootless Podman end to end, Docker → Podman restore)`).
- [ ] **Step 5 (controller):** run `gh workflow run ci.yml --ref podman1 -f jobs=e2e,e2e-podman`. Expected: green. If `host-gateway` fails on Podman, stop and report: Q3's fallback is a contract change that needs its own review.

---

### Task 11: Docs

**Files:**
- Create: `docs/operations/rootless-podman.md`
- Modify: `docs/operations/.nav.yml` (`- Rootless Podman: rootless-podman.md` after Upgrading), `hardening.md` ("Docker socket proxies" table about line 185: a "socket source" row; a new "Rootless Podman" section after "Shared folders and the fixer helper"), `cli.md` (`init --runtime`, the status `runtime:` line, the restore runtime keys, the backup schedule user units), `testing.md` (`e2e-podman`, the static checks), `hub.md` (badges, `/api/runtime`, doctor kinds), `backups.md` ("moving between runtimes"), `docs/setup/quickstart.md` (one line pointing to the page)

- [ ] **Step 1:** Write `rootless-podman.md`. Sections: why; host preparation as copy-paste blocks for Debian/Ubuntu and for Fedora/RHEL (useradd without sudo, subuid/subgid, linger, user units, sysctl.d `80`, passt + Docker CLI + compose plugin, SELinux `semanage` for shared folders); `init --runtime podman`; migration (backup → init → restore, R6); the §9 table with each template's status taken from `tests/rootless.txt`; Time Machine discovery per R10; the limits (no devices, UDP sources, ports below the sysctl).
- [ ] **Step 2:** In `hardening.md` say:
  - Container root is the operator.
  - The Hub is operator-equivalent instead of host-root-equivalent.
  - The proxies' `label=disable` is the only SELinux exception.
  - Traefik and the proxies own the operator-owned files mounted into them.
- [ ] **Step 3:** Run `python3 scripts/check-lists.py && bash scripts/check-branding.sh`. Expected: exit 0. Commit (`docs: rootless Podman page, hardening, CLI, testing, Hub`), push, and resync the Hub `web/docs` (Global Constraints). Commit that in the Hub (`docs: sync`).

---

### Task 12: Full CI, merge, deploy, cleanup

**Files:** none new (merges and the test server).

- [ ] **Step 1 (controller):** Run a full core CI `gh workflow run ci.yml --ref podman1`, and on the same branch Hub `build.yml` and templates lint plus Test Apps. Expected: all green.
- [ ] **Step 2: Merge docs**, then the Hub through detached worktrees (Global Constraints). Run `gh workflow run build.yml --ref main -f compare_ref=podman1` in the Hub and wait for `edge` to be published. Then merge templates, then core.
- [ ] **Step 3:** Re-run templates "Test Apps" on main. Expected: green.
- [ ] **Step 4: Deploy the Docker test server and check that nothing changed.**
  1. **Before**, on the server: `docker compose config --format json > /tmp/cfg-before.json`, and for each core container record `docker inspect` `{Config.User, HostConfig.CapAdd, HostConfig.Memory, HostConfig.PidsLimit, HostConfig.SecurityOpt, [.Mounts[] | {Source, Destination, RW}], NetworkSettings.Networks[].IPAddress}` into `/tmp/inspect-before.json`.
  2. Run `git pull --ff-only && ./portcullis upgrade`.
  3. **After**, compare:
     - The config diff is only `hub.environment.HUB_CONTAINER_RUNTIME = "docker"` and the binds' long syntax with `selinux: z`.
     - The inspect diff is empty.
     - `grep -cE '^(CONTAINER_RUNTIME|PORTCULLIS_ENGINE_SOCKET)=' .env` = 0.
     - `secrets/hub/core.env` has no `PORTCULLIS_UNPRIVILEGED_PORT_START`.
     - `./portcullis status` has no problems and prints `runtime: docker <ver>`.
     - The Hub's `GET /api/runtime` says `docker`, `verified: true`.
     - The Marketplace shows no rootless badges.
     - A doctor scan of a defined shared folder (if any) still runs.
  4. Keep `ACME_STAGING=true`. Never touch LLDAP `admin`.
- [ ] **Step 5: Clean up.**
  - Delete the `podman1` branches (local + `git push origin --delete podman1` in all four repos).
  - Run `git worktree remove` for every `wt-podman1/*` and `/tmp/merge-*`, then `git worktree prune`.
  - Remove `/tmp/pp-*`.
