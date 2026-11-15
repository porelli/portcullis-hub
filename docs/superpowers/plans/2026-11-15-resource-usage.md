# Resource usage (storage, memory and CPU per app and per container) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a **Usage** page to the Hub, plus a Usage tab on each instance page. They show live CPU, memory, network, block IO and PIDs per app (aggregated) and per container, the core services as their own group, and storage per app, per shared folder and per core volume with each filesystem's free space. A JSON API, a CSV export, five read-only-ish MCP tools, six doctor kinds and optional Prometheus history come with it. The page works on Docker and rootless Podman first, then on Kubernetes. No socket-proxy flag changes and no new container.

**Architecture:**
- **Live data.** A Hub goroutine, the **usage sampler**, runs every 15 s. Through the existing `socket-proxy-hub` it lists containers, takes one-shot stats (4 at a time) and inspects limits every 5 min, field by field. It keeps a 240-point ring per container in memory. Page views, CSV and MCP read only that cache: no read ever reaches the engine.
- **Storage.** The **storage measurer** runs daily and on demand as op `_usage`. It runs a new read-only fixer mode, `hub folderfix usage`, one target after the other: named volumes (a new read-only `FixerSpec.Volumes` mount), hand-typed binds and core volumes. It adds writable layers (`size=true` inspect) and image sizes, and caches it all in `<data>/usage/storage.json`. Shared folders reuse the doctor's scans, which gain `alloc_bytes`.
- **Doctor.** Six kinds judge those two caches and never run anything.
- **History (Part 3).** A metrics listener on a new internal network `portcullis-metrics-hub` exposes the sampler's cache to core's Prometheus (`client_golang`, its own registry). Core adds a dashboard and three alerts.
- **Kubernetes (Part 4).** `metrics.k8s.io` `PodMetrics` through the kube backend, one read-only namespaced Role rule, and the PVC read-only volume helper running `hub folderfix usage`. The core group shows "not measured on Kubernetes yet".

**Tech Stack:**
- Go 1.27 (Hub):
  - `github.com/moby/moby/client` v0.6.2 (`ContainerStats`, `ContainerInspect{Size}`, `ImageInspect`, `Info`);
  - `github.com/prometheus/client_golang` v1.24.0 (already in `go.sum` as indirect, becomes direct);
  - `k8s.io/client-go` dynamic client v0.37.2 with `k8s.io/metrics` v0.37.2 types (new, same release train);
  - `encoding/csv`;
  - `golang.org/x/sys/unix` (`statx` `STATX_BLOCKS|STATX_SIZE`, `SYS_IOPRIO_SET`).
- Vanilla JS (Hub UI, inline SVG sparklines).
- bash + jq (core CI), Python 3 (core e2e).
- Prometheus v3.16 `promtool`, Grafana JSON.
- Zensical (docs).

**Spec:** `docs/superpowers/specs/2026-11-14-resource-usage-design.md` (Hub repo, `origin/main`, binding). Its §15 open questions take their defaults: Q1 no app-admin view; Q2 a fixed 15 s; Q3 constants; Q4 count only; Q5 core not measured on Kubernetes; Q6 no per-person usage. Related plans whose structure and rules carry over:
- `2026-11-14-kubernetes.md` (`internal/runtime.Instances`, the kube backend, K2's Role);
- `2026-11-02-shared-folders-doctor.md` (the fixer, scans, the doctor);
- `2026-11-07-operation-progress.md` (op records, Stop).

## Global Constraints

Process:
- **Precondition: Kubernetes (`kube1`) is merged to `main` in docs, Hub, core and templates.** This plan is written against Hub `origin/kube1` `c73d2ce` and core/docs `origin/kube1`. Every file and name below is from there: `internal/runtime/{runtime.go,types.go}`, `internal/runtime/docker/backend.go`, `internal/runtime/kube/{backend.go,helpers.go,guard_test.go,envtest_test.go,testdata/role.yaml}`, `internal/runtime/runtimetest/fake.go`. If `kube1` isn't on `main` when execution starts, stop and wait. Never base on `kube1`. At execution, re-read every file named here on the merged `main`, follow any rename, and note it in the task's commit.
- **Branches (U1):**
  - Branch `usage1` in docs, Hub and core, at `/Volumes/workspace/portcullis/wt-usage1/{portcullis-docs,portcullis-hub,portcullis}`. Create each with `git -C <main checkout> worktree add -b usage1 <path> origin/main`.
  - Never edit, stash or commit in the main checkouts.
  - Templates don't change (U21). Their CI is re-run in Task 20.
  - Every commit step is `git add -A && git commit -m "…"`.
- **Contract first.** Task 1 lands on docs `usage1` before any code. After Tasks 1 and 7, resync the Hub copies with `PORTCULLIS_DOCS_DIR=/Volumes/workspace/portcullis/wt-usage1/portcullis-docs go generate ./web` in the Hub worktree, and commit `web: docs copies resynced (usage)`.
- **Parts.** Part 1 = Tasks 1–7 and 14; Part 2 = 8–12 and 15; Part 3 = 13 and 16; Part 4 = 17 and 18. Each part leaves every CI green on `usage1`, so execution can stop after any part and mainline what is there (spec §14). The default is one mainline at the end (Task 20).
- **Gates (every task):**
  - Hub: `gofmt -l .` prints nothing; `go vet ./...`, `go vet -tags docker ./internal/hub/` and `go test -race ./...` pass (with `PORTCULLIS_DOCS_DIR` set to the docs worktree).
  - Core: `shellcheck -S warning portcullis scripts/lib/*.sh tests/*.sh .github/ci/*.sh`, `bash tests/test_cli.sh`, `bash tests/test_shell_libs.sh`, `bash tests/lint_ci_size.sh`, `actionlint`.
  - Docs: `python3 scripts/check-lists.py && bash scripts/check-branding.sh && zensical build --strict --clean`.
- **Heavy Docker tests run on the Linux builder** (`/Volumes/workspace/portcullis/.builder/b.sh '<cmd>'`), inside an **isolated, pinned `docker:dind` container** started for the run and removed after it. This covers `go test -tags docker`, `-tags fixerroot` (inside a privileged throwaway container on the builder) and any local e2e. Never run them on the Mac or against the builder's own daemon. CI only confirms.
- **CI:** `gh workflow run build.yml -R porelli/portcullis-hub --ref usage1`, and `gh workflow run ci.yml -R porelli/portcullis --ref usage1 -f jobs=<names>`. Always run your own background watcher on every dispatched run (memory).

Project rules (binding):
- **Secrets never on argv or in logs.** Container inspect answers carry `Config.Env`. The engine client copies only the named fields of `runtime.UnitInfo` (Task 2), and the sampler never logs, stores or returns a raw engine body. Engine errors are logged without their body, and API errors are fixed text ("stats unavailable"). The fixer argv carries only paths and caps, never a value from a container. `TestUsageNeverKeepsEnv` (Task 4) and `TestStatsErrorNeverEchoesBody` (Task 2) pin this.
- **Fail closed.**
  - Missing data is `null`, never 0. The page says "not measured" with the reason.
  - No doctor finding is ever raised from a `null`. Missing data is `usage_not_measured`, never "OK".
  - A corrupt or oversized cache file is dropped and means "never measured".
  - A fixer report that doesn't decode strictly is an error.
  - A bind source at or under an engine root is refused.
  - A writable named-volume mount in a started helper is refused (`checkRunSpec`).
- **Never weaken access control, and never widen socket-proxy access.**
  - No `socket-proxy-hub` flag changes: never `SYSTEM`, `ALLOW_TOP` or any `LIBPOD_*`. Only `GET /containers/json`, `/containers/{id}/stats`, `/containers/{id}/json[?size=true]`, `/images/{id}/json` and `/info`, plus the fixer's existing create/start/wait/logs/remove.
  - No new socket mount and no third proxy: no cAdvisor, no node-exporter host mounts.
  - Every route is on the Hub listener (admins), none on the people listener or the people MCP scope.
  - The only RBAC change is a read-only, namespaced `metrics.k8s.io` `pods` `get`/`list` rule (Part 4): no `nodes*`, nothing in `portcullis`, nothing cluster-scoped.
- **Identity is the LLDAP username** in the `usage.measure` audit entry, the op record's actor and every log line naming a person.
- **No back-compat before the release.** `storage.json` v1 is new. Scan reports gain fields without a version bump, and an old cached scan without `alloc_bytes` just shows "not measured yet". No migration code. Fix test-server data by hand.
- **Prefer mature libraries:** moby SDK calls, `client_golang`, `k8s.io/metrics` types, `encoding/csv` and `docker/go-units`-style binary units on the page (KiB/MiB/GiB). No hand-rolled Prometheus text format, CSV quoting or quantity parsing (`resource.Quantity`).
- **No private identifiers in public repos:** example.com names, the CI people, no test-server host, no builder address.
- **Core `ci.yml` stays ≤ 450 KB** (`tests/lint_ci_size.sh`; ~322 KB on `kube1`). New CI logic goes in `.github/ci/*.sh` or `tests/e2e/*.py`, and no CI job is added.
- **The test server stays `ACME_STAGING=true`** (`config apply` + `up` after init) for Task 19.
- **No suspicious outbound connections in tests.** Every test fakes the engine, the Kubernetes API and Prometheus, or uses the local runner/DinD daemon and k3s. The e2e never contacts third-party hosts. Pinned images only.

Values pinned by the spec (copy exactly):
- Sampler: interval **15 s**; per container **5 s** timeout; **4** at once; sweep budget **12 s**; inspect every **5 min** and on first sight; `/info` at start and hourly. Ring **240** samples (1 h). Cap **256** containers, the rest counted "not measured: over the 256-container limit".
- Working set: `memory_stats.usage − stats.inactive_file` (cgroup v2) or `− stats.total_inactive_file` (v1). CPU `cores = Δcpu_usage.total_usage (ns) / Δwall (ns)`, never `precpu_stats`.
- Display: "0.35 CPU", with the percentage of the CPU limit, else of host `NCPU`. Memory bar coloured at **80 %** and **90 %**. Lower bounds are shown as "≥ 1.2 GiB" (`partial: true`). Figures older than **48 h** are dimmed.
- Storage: per target `--max-entries 2000000 --max-time 2m`, helper wall timeout `max-time + 30 s`, run budget **1 h**, targets one after the other. Daily: first run **10 min** after start when the cache is older than **24 h**. Hard-link set cap **1,000,000**, else `partial` reason `hard_links`. `size=true` inspect **10 s** each. Cache **0600**, ≤ **4 MiB**, ≤ **2,048** entries.
- Helper isolation: `User 0:0`, `NetworkMode none`, read-only rootfs, `no-new-privileges`, `CapDrop ALL` + `CapAdd DAC_READ_SEARCH`, pids **16**, memory **256 MiB**, `Healthcheck NONE`, `LogConfig json-file`, label `io.portcullis.hub.helper=usage:<target>`, removed always. Exactly one mount, at `/vol`, read-only, a volume with `NoCopy: true` or a `Type: bind` (never `Binds`, never `CreateMountpoint`). IO priority idle class, best effort, else `io_idle: false`.
- Doctor:
  - `disk_nearly_full`: Warning < 10 % or < 5 GiB free; Problem < 3 % or < 1 GiB.
  - `memory_near_limit`: ≥ 90 % of a non-zero limit in every sample of the last 10 min (≥ 30 samples).
  - `oom_killed`: OOMKilled on the current start, or restarts +≥ 3 in 1 h with an OOM seen.
  - `pids_near_limit`: ≥ 90 % for 10 min.
  - `usage_not_measured`: no successful sweep for 5 min while verified, or no metrics API (Kubernetes).
  - `storage_measure_partial`: a target hit a cap in the last run.
- Routes, MCP tools, CSV headers, filename `portcullis-usage-<view>-<UTC timestamp>.csv`, formula prefixes `=`, `+`, `-`, `@`, tab, CR → `'`. Op key `_usage`, audit `usage.measure`.
- Prometheus: `HUB_METRICS_ADDR` (core `hub-metrics:9100`), network `portcullis-metrics-hub` (members: Hub alias `hub-metrics`, Prometheus), job `hub-usage`, the §11 series names, alerts `PortcullisAppMemoryNearLimit` (> 0.9 for 10m), `PortcullisDiskNearlyFull` (< 0.10 for 30m), `PortcullisUsageSamplerStale` (no success for 10m while the Hub is up).
- Copy:
  - "not measured";
  - "stats unavailable";
  - "3 other containers on this engine are not shown";
  - "Hub helpers (transient)";
  - "History in Grafana ↗";
  - "Measure now" / "Measure";
  - "measured 3 h ago";
  - "≥ 120 GiB (stopped after 2 min)";
  - "the cluster has no metrics API (metrics-server)";
  - "not measured on Kubernetes yet";
  - "Hub-managed files";
  - "shared, not in total";
  - "the figure is a lower bound";
  - "free space or move the data".

## Rulings made here (assistant's call)

- **U1 One branch `usage1`** in docs, Hub and core, with all four parts. Each part leaves CI green, and the branch is mainlined once in Task 20.
- **U2 No `Usage(ctx, UsageSpec)` runtime method.** The started helper stays `RunFixer`, which gets `FixerSpec.Volumes []VolumeMount` (a named volume or PVC, always read-only). `runtime.Instances` gains `Stats`, `LayerSize` and `ImageSize`. `runtime.Info` gains `CPUs` / `MemoryBytes`, and `runtime.UnitInfo` gains the limit, OOM, restart, start and mount fields. One started-helper path, one strict report decoder (`execFixer`). This deviates from spec §3's method name; the behaviour is the same.
- **U3 Stats are decoded into the Hub's own struct with `*uint64` fields** (`internal/docker/stats.go`), not `container.StatsResponse`. Its `omitempty` `uint64`s can't tell "absent" from 0 (spec: `null` when absent). The body is capped at 1 MiB.
- **U4 Δt is the engine's `read` timestamps.** A rate is `null` when Δt < 1 s or ≤ 0, a counter went down, or `started_at` changed.
- **U5 `network_mode` `none`** gives `null` network rates, like `host`, `container:` and `service:`.
- **U6 A pure package `internal/usage`** holds the maths, rings, totals and CSV escaping. `internal/hub` holds the goroutines, scope and caches.
- **U7 Rings are keyed by container ID.** A container gone from the list is dropped at the next sweep. History in the API is keyed `"<service>.<number>"`, so a recreated container's line continues after a gap.
- **U8 The kube backend's `Stats`** is served from one `pods.metrics.k8s.io` list cached for 10 s, so a sweep makes 1 API call (spec §10's engine load). Decoding uses the dynamic client with `k8s.io/metrics/pkg/apis/metrics/v1beta1` types (`DefaultUnstructuredConverter`). `runtime.UnitStats` carries `CPUCores` / `MemWorkingSet` as gauges there.
- **U9 Kubernetes CPU is a gauge.** `portcullis_container_cpu_seconds_total` is omitted on Kubernetes (no counter exists).
- **U10 Op `_usage` (`OpUsageMeasure = "usage_measure"`)** has steps `[measure]` and is stoppable, with no undo: figures measured so far are kept. Stop: `POST /api/usage/storage/op/stop` `{"op_id"?}`, which runs `StopUsageMeasure`, cancels the op's ctx and ends between targets. Audit `usage.measure.stop`.
- **U11 Two routes have no tool:** `GET /api/usage/export.csv` and `POST /api/usage/storage/op/stop`. They go in a new `usageNoToolRoutes` map in `mcp_parity_test.go`, wired like `vpnNoToolRoutes`, because `noToolRoutes` is pinned to exactly G15's list.
- **U12 Doctor scans and the measurer share `Hub.diskMu`,** held per target around each fixer run, never across a run. The two daily loops interleave and never run two walks at once.
- **U13 A bind host path or volume used by several instances** is measured once. It is listed on each with `shared: [...]`, `in_total: false`, so it is in no app total (like shared folders).
- **U14 A per-person tree** (`TopOnly` doctor scan) has no byte figure: "not measured (checked at the top level only)".
- **U15 `usage` mode** exits 0 when entries couldn't be read, with `partial: true`, `partial_reason: "failed"` and `failed.n`. Exit 2 is a refusal, exit 1 a crash. `scan` keeps exiting 1 on failed entries (R55).
- **U16 The usage report is `folderfix.Report` with `mode: "usage"`.** It gains `alloc_bytes`, `apparent_bytes` (both modes) and `io_idle` (usage only, `*bool`, omitempty). The other fields stay as they are (zero values for usage).
- **U17 Kubernetes storage uses the existing volume-kind helper pod** (the PVC read-only, `/vol`, read-only root). It has only `DAC_OVERRIDE` of the volume kind's admitted caps. The admission policy allows `DAC_READ_SEARCH` only for the fixer kind, and no admission change is made. Binds use the fixer kind (hostPath) as today.
- **U18 Core's e2e fixture `tests/e2e/apps/echo`** gets `mem_limit: 32m` and `pids_limit: 32` on `hold`. The spec's e2e asserts "a limit", and the fixture has none. `hold` (`network_mode: none`) also proves null network rates.
- **U19 The contract section is §11.11 "Usage"** (spec §13 says §11.12; §11.10 is the last on `kube1`).
- **U20 On Kubernetes `HUB_METRICS_ADDR` stays unset** (chart): no listener in v1. Parked.
- **U21 Templates don't change.**
- **U22 CSV columns** (header row exactly):
  - `apps`: `instance,template,name,status,cpu_cores,mem_bytes,mem_limit_bytes,cpu_limit_cores,pids,pids_limit,net_rx_bps,net_tx_bps,blk_read_bps,blk_write_bps,partial,measured_at`
  - `containers`: `instance,service,number,id12,state,cpu_cores,mem_bytes,mem_limit_bytes,cpu_limit_cores,pids,pids_limit,net_rx_bps,net_tx_bps,blk_read_bps,blk_write_bps,oom_killed,restarts,measured_at`
  - `storage`: `owner,kind,target,alloc_bytes,apparent_bytes,partial,in_total,shared_with,measured_at`

  Core rows have `instance` = `core`. The timestamp is `20060102T150405Z`.
- **U23 Hub helpers** are listed in the core group as one row, "Hub helpers (transient)", with their count and summed sample. Their labels are never shown.
- **U24 "Other containers"** = `List(Filter{})` minus every compose-labelled unit and every helper. They are counted only and never sampled.
- **U25 The Grafana link** shows when `/metrics` was scraped within 5 min (`Hub.MetricsScrapedRecently`). The URL is `https://metrics.<domain>/d/portcullis-usage`.

## Review Focus

1. **Containers recreated on every enable / restart / settings reload.** A person expects the instance's 1 h sparkline to continue across the recreate (with a gap), and no ghost containers filling the 256 cap or memory. Pinned by Task 4 `TestUsageRingsFollowRecreatedContainers`: a container replaced 300 times keeps ≤ 1 ring per live ID, and the history key `web.1` holds points from both IDs.
2. **Many admins with the page open, plus an AI polling `usage_overview`.** A person expects the engine load to stay the sampler's alone. Pinned by Task 5 `TestUsageReadsNeverReachEngine`: 100 `GET /api/usage`, 50 instance GETs, 20 CSV exports and 20 MCP calls between two sweeps add zero calls to the fake runtime.
3. **Samples that land close together or out of order** (a slow sweep then a fast one, a clock step, Podman's `read` equal to the previous one). A person expects "—" for that interval, never "4000 CPU" or a negative rate. Pinned by Task 3 `TestRateNullOnTinyOrNegativeInterval` (Δt 0, 200 ms, −5 s → `nil`; 15 s → value).
4. **One host path or volume used by two apps.** A person expects it measured once and listed on both as shared, never counted twice in totals or the Disks strip. Pinned by Task 9 `TestStorageSharedTargetMeasuredOnce` (one fixer run; both groups list it with `in_total: false`; the disk's owners name both).
5. **An instance deleted, or the Hub's disk full, during a storage run.** A person expects the run to finish the others, the deleted instance to vanish from the cache, and a failed cache write to keep the previous file and say so in the op's warnings. Pinned by Task 9 `TestStorageInstanceDeletedMidRun` and `TestStorageCacheWriteFailureKeepsPrevious`.

---

## File structure

**Docs (`wt-usage1/portcullis-docs`):**
- `docs/guides/integration-contracts.md`: §6, the new §11.11, §11.7 (op key, audit), §14.5, §15.10, §16 neighbourhood (`HUB_METRICS_ADDR`), §6 "On Kubernetes" Role table;
- `docs/operations/{hub,hardening,monitoring,kubernetes,rootless-podman}.md`.

**Hub (`wt-usage1/portcullis-hub`)**

| File | Responsibility |
|---|---|
| `internal/runtime/types.go`, `runtime.go` | `UnitStats`, `NotMeasuredError`, `VolumeMount`, `UnitMount`, new `UnitInfo` / `Info` fields, `FixerSpec.Volumes`, `Stats` / `LayerSize` / `ImageSize` |
| `internal/docker/stats.go` (new), `run.go`, `volumes.go` | stats decode, size, image size, host resources, field-by-field inspect, the volume mount in `RunHelper` |
| `internal/runtime/docker/backend.go`, `internal/runtime/runtimetest/fake.go` | backend wiring, fakes |
| `internal/runtime/kube/backend.go`, `metrics.go` (new, Part 4), `helpers.go`, `testdata/role.yaml` | kube stubs (Part 1), metrics, inspect fields, the volume usage helper |
| `internal/usage/` (new: `sample.go`, `ring.go`, `total.go`, `csv.go`) | pure maths, rings, totals, CSV |
| `internal/hub/usage.go`, `usage_scope.go`, `usage_view.go` (new) | the sampler, scope, views |
| `internal/hub/usage_storage.go`, `usage_storage_cache.go` (new); `doctorscan.go` (`diskMu`); `ops.go` (`validOpKey`) | the measurer, cache, op `_usage` |
| `internal/hub/usage_metrics.go` (new, Part 3) | the Prometheus collector |
| `internal/folderfix/usage.go` (new), `walk.go`, `scan.go`, `cli.go`, `fs_linux.go`, `fs_other.go` | `usage` mode, `alloc_bytes` |
| `internal/doctor/usage.go` (new), `doctor.go` (`Inputs.Usage`, `Inputs.Storage`) | six kinds |
| `internal/hub/doctor_usage.go` (new), `doctor.go` | doctor inputs |
| `internal/httpapi/usage.go`, `mcptools_usage.go`, `metricslistener.go` (new); `server.go`, `mcp.go`, `mcp_parity_test.go` | routes, tools, parity, metrics listener |
| `web/usage.js` (new), `web/index.html`, `web/web.go` | the Usage tab and the instance Usage tab |
| `cmd/hub/main.go`, `cmd/hub/metrics.go` (new) | wiring, `HUB_METRICS_ADDR` |
| `CLAUDE.md`, `go.mod` | rules, deps |

**Core (`wt-usage1/portcullis`):**
- `.github/workflows/ci.yml` (two steps extended, by calls only);
- `.github/ci/usage-proxy-asserts.sh` (new), `.github/ci/unit-tests-compose-files-are-valid-generated.sh`, `.github/ci/e2e-k3s-assert.sh`;
- `tests/e2e/e2e_usage.py` (new), `tests/e2e/apps/echo/compose.yml`;
- `docker-compose.yml`, `docker-compose.podman*.yml` (if they restate networks);
- `monitoring/prometheus/{prometheus.yml,alerts.yml,tests/alerts_test.yml}`, `monitoring/grafana/dashboards/usage.json`;
- `charts/portcullis/files/hub-role.yaml`;
- `docs/{monitoring,hardening}.md`, `CLAUDE.md`, `CHANGELOG.md`.

---

## Docs stream

### Task 1: Contract and guides (docs, first)

**Files:**
- Modify: `docs/guides/integration-contracts.md`:
  - **§6 "Engine access":**
    - the stats call (`GET /containers/{id}/stats?stream=false&one-shot=true`), the `size=true` inspect and `GET /images/{id}/json`, under the existing `CONTAINERS` / `IMAGES` / `INFO` sections, with "no flag of `socket-proxy-hub` changes; `SYSTEM`, `ALLOW_TOP` and `LIBPOD_*` stay off";
    - the fixer's `usage` mode (one read-only mount at `/vol`, a volume with `NoCopy` or a `Type: bind`, `DAC_READ_SEARCH` only, idle IO);
    - `alloc_bytes` / `apparent_bytes` in `scan` and `usage` reports, `io_idle`;
    - the `usage` exit codes (U15).
  - **§6 "On Kubernetes":** the Role table gains `metrics.k8s.io` `pods` `get`, `list` ("read-only pod metrics; never `nodes`, `nodes/stats`, `nodes/proxy`"). The usage helper is the read-only volume-kind pod (U17).
  - **New §11.11 "Usage":**
    - every route of spec §8.1 plus the Stop route (U10), with exact JSON field names;
    - `null` semantics; `no-store`; 200 with `engine.verified: false` on refusal;
    - the CSV headers (U22) and escaping;
    - the cache-only rule.
  - **§11.7:** op key `_usage`, op `usage_measure`, steps `[measure]`, audit `usage.measure` (target `storage`, detail `scope=all|<instance>`) and `usage.measure.stop`.
  - **§14.5:** the six kinds, with thresholds, severities, fingerprints and the band-digest rule.
  - **§15.10:** the five tools (name, class, twin, description) and the two routes without a tool (U11).
  - **After §16's intro:** `HUB_METRICS_ADDR`, `portcullis-metrics-hub`, `GET /metrics` + `GET /healthz` only, the series list, "null values are omitted". Kubernetes: unset (U20).
- Modify: `docs/operations/hub.md`: a new "## Usage" section (the three views, the instance tab, Measure now, what "≥" and dimmed mean, who can see it), and the Navigation list with Usage between Doctor and Settings.
- Modify: `docs/operations/hardening.md`: under the proxy table, "stats are read through `CONTAINERS`; `SYSTEM` and `ALLOW_TOP` stay off"; the `portcullis-metrics-hub` row in the networks table and its diagram.
- Modify: `docs/operations/monitoring.md`: the `hub-usage` job, the series, the `usage` dashboard, the three alerts and the retention estimate ("30 containers × 10 series × 2 samples/min × 30 d ≈ 26 M samples, about 40 MB").
- Modify: `docs/operations/kubernetes.md`: what the Usage page shows on Kubernetes (metrics-server, null cells, core not measured).
- Modify: `docs/operations/rootless-podman.md`: CPU is null without the `cpu` controller, block IO usually null without `io`.

- [ ] **Step 1:** Write every section above. Copy the values from Global Constraints verbatim, and every U-ruling that touches an interface (U2, U5, U10, U11, U13, U14, U15, U16, U17, U19, U20, U22, U25). No version bump: the scan report only gains fields (rule "no back-compat").
- [ ] **Step 2:** Run `python3 scripts/check-lists.py && bash scripts/check-branding.sh && zensical build --strict --clean`. Expected: no warnings.
- [ ] **Step 3:** Commit `docs: resource usage page in the contract and guides`.

---

## Hub stream: Part 1, live usage (Tasks 2–7)

### Task 2: Runtime interface, engine calls, fakes (hub)

**Files:**
- Modify: `internal/runtime/types.go`, `internal/runtime/runtime.go`.
- Create: `internal/docker/stats.go`, `internal/docker/stats_test.go` with fixtures `internal/docker/testdata/stats/{docker-v2.json,docker-v1.json,podman-v2.json,podman-nocpu.json}`.
- Modify: `internal/docker/run.go` (`InspectContainer`, `checkRunSpec`, `RunHelper`), `internal/docker/run_test.go`.
- Modify: `internal/runtime/docker/backend.go` (the `Engine` interface + the three methods + `Info`), `backend_test.go`.
- Modify: `internal/runtime/kube/backend.go`: `Stats`, `LayerSize` and `ImageSize` answer `&runtime.NotMeasuredError{Why: "not measured on Kubernetes yet"}` until Task 17. `RunFixer` refuses `len(s.Volumes) > 0` until Task 17.
- Modify: `internal/runtime/runtimetest/fake.go`.

**Interfaces:**
- Produces:
  - in `runtime`:
    ```go
    type UnitStats struct {
        Read            time.Time // the engine's sample time
        CPUUsageNS      *uint64   // cpu_stats.cpu_usage.total_usage
        CPUCores        *float64  // a rate the runtime gives directly (Kubernetes)
        MemUsage        *uint64   // memory_stats.usage
        MemInactiveFile *uint64   // stats.inactive_file (v2) or stats.total_inactive_file (v1)
        MemWorkingSet   *uint64   // given directly (Kubernetes)
        Pids            *uint64
        NetRx, NetTx    *uint64   // Σ networks{}; nil: no networks object
        BlkRead, BlkWrite *uint64 // Σ io_service_bytes_recursive op read / write (case-insensitive)
    }
    type NotMeasuredError struct{ Why string } // Error() = "not measured: " + Why
    type VolumeMount struct{ Name, Target, Instance string } // always read-only, NoCopy
    type UnitMount struct{ Type, Name, Source, Destination string; RW bool }
    ```
  - `UnitInfo` gains `NanoCPUs, CPUQuota, CPUPeriod int64; NetworkMode string; OOMKilled bool; RestartCount int; StartedAt time.Time; Mounts []UnitMount`.
  - `Info` gains `CPUs int; MemoryBytes int64` (0 = unknown).
  - `FixerSpec` gains `Volumes []VolumeMount`.
  - `Instances` gains `Stats(ctx context.Context, id string) (UnitStats, error)`, `LayerSize(ctx context.Context, id string) (int64, error)` and `ImageSize(ctx context.Context, ref string) (int64, error)`.
  - In `internal/docker`:
    - `(*Client) ContainerStats(ctx, id string) (runtime.UnitStats, error)`: `client.ContainerStatsOptions{Stream: false}`, which sends `stream=false&one-shot=true` in SDK v0.6.2; the spec's `OneShot` field doesn't exist;
    - `(*Client) ContainerSizeRw(ctx, id string) (int64, error)` (`ContainerInspectOptions{Size: true}`, 10 s, `SizeRw` nil → `NotMeasuredError{"the engine didn't report a size"}`);
    - `(*Client) ImageSize(ctx, ref string) (int64, error)`;
    - `(*Client) HostResources(ctx) (cpus int, mem int64, err error)`.
  - Fake: `StatsVal map[string]runtime.UnitStats`, `StatsErr map[string]error`, `StatsBlock chan struct{}` (when set, `Stats` waits on it), `LayerSizes`, `ImageSizes map[string]int64`. It records `stats <id>`, `layer-size <id>` and `image-size <ref>`.

- [ ] **Step 1: Write the failing tests** (`internal/docker/stats_test.go`):
  - `TestStatsDecodeV2`: the docker-v2 fixture. `MemUsage` = usage, `MemInactiveFile` = `stats.inactive_file`, `Pids`, `NetRx` = Σ two networks, `BlkRead` from op `read`, and `Read` parsed.
  - `TestStatsDecodeV1`: `total_inactive_file`, op `Read` / `Write`.
  - `TestStatsAbsentIsNil`: podman-nocpu (no `cpu_usage.total_usage`, no `networks`, empty `io_service_bytes_recursive`). `CPUUsageNS`, `NetRx` and `BlkRead` are `nil`, while a present `0` decodes as a non-nil 0.
  - `TestStatsRequestIsOneShot`: the fake server sees `GET /containers/c1/stats?one-shot=true&stream=false`.
  - `TestStatsBodyCapped`: a 2 MiB body is an error.
  - `TestStatsErrorNeverEchoesBody`: a 500 whose body is `SECRET=hunter2`. The error text lacks `hunter2`.
- [ ] **Step 2: More failing tests:**
  - `run_test.go` `TestInspectCopiesNamedFieldsOnly`: an inspect answer with `Config.Env: ["DB_PASSWORD=s3cret"]`, `HostConfig.NanoCpus: 500000000`, `State.OOMKilled: true`, `RestartCount: 4`, `State.StartedAt`, two `Mounts` and `HostConfig.NetworkMode: "none"`. The `UnitInfo` holds exactly those, and `fmt.Sprintf("%+v")` of it lacks `s3cret`.
  - `TestRunHelperVolumeMount`: a `RunSpec` with `Volumes: [{Name: "portcullis-x_data", Target: "/vol"}]`. The create body's `HostConfig.Mounts` = `[{Type: volume, Source: portcullis-x_data, Target: /vol, ReadOnly: true, VolumeOptions: {NoCopy: true}}]`, and `Binds` is empty.
  - `TestRunHelperRefusesBadSpec` gains: a volume target equal to a bind target, an empty volume name, a target `/` → refused.
  - `TestHostResources`: `/info` with `NCPU 8`, `MemTotal` → (8, n).
  - `backend_test.go` `TestBackendInfoHostResources`: `Info().CPUs == 8`. `TestBackendStatsPassThrough` passes.
  - `runtimetest` `TestFakeStatsBlock`.
- [ ] **Step 3:** Run `go test ./internal/docker/ ./internal/runtime/...`. Expected: FAIL (undefined fields and methods).
- [ ] **Step 4: Implement:**
  - the types;
  - `stats.go` (a private `statsBody` struct of pointers; `io.LimitReader` 1 MiB + 1; `json.Decoder`; the error is `fmt.Errorf("stats %s: %s", shortID(id), http.StatusText(code))` with no body);
  - `InspectContainer`'s new fields copied one by one;
  - `checkRunSpec` / `RunHelper` volume mounts (`ReadOnly: true` always);
  - the backend's `Engine` interface + pass-throughs, with `Info` filling `CPUs` / `MemoryBytes` from `HostResources`;
  - the kube stubs;
  - the fake.
- [ ] **Step 5:** Run `go test -race ./internal/docker/ ./internal/runtime/... && go vet ./...`. Expected: PASS.
- [ ] **Step 6:** Commit `runtime: stats, layer and image sizes, host resources, limit fields, read-only volume mounts for started helpers`.

### Task 3: `internal/usage`: samples, rates, rings, totals, CSV (hub)

**Files:**
- Create: `internal/usage/sample.go`, `ring.go`, `total.go`, `csv.go` and their `_test.go`.

**Interfaces:**
- Consumes: `runtime.UnitStats`, `runtime.UnitInfo` (Task 2).
- Produces:
  ```go
  type Sample struct {
      CPUCores      *float64 `json:"cpu_cores"`
      MemBytes      *int64   `json:"mem_bytes"`
      MemLimitBytes *int64   `json:"mem_limit_bytes"`  // 0 = no limit
      CPULimitCores *float64 `json:"cpu_limit_cores"`  // nil = no limit
      Pids          *int64   `json:"pids"`
      PidsLimit     *int64   `json:"pids_limit"`
      NetRxBps, NetTxBps     *float64 `json:"net_rx_bps"` / `json:"net_tx_bps"`
      BlkReadBps, BlkWriteBps *float64 `json:"blk_read_bps"` / `json:"blk_write_bps"`
  }
  type Limits struct { MemBytes int64; CPUCores *float64; Pids int64; NetworkMode string;
                       StartedAt time.Time; OOMKilled bool; Restarts int }
  func LimitsOf(i runtime.UnitInfo) Limits
  func WorkingSet(s runtime.UnitStats) *int64
  func Derive(prev *runtime.UnitStats, prevStart time.Time, cur runtime.UnitStats, l Limits) Sample
  type Point struct { T time.Time; S Sample }
  type Ring struct { /* fixed 240 */ }
  func NewRing(n int) *Ring
  func (r *Ring) Add(p Point)
  func (r *Ring) Points() []Point // oldest first, a copy
  func (r *Ring) Since(t time.Time) []Point
  func Total(ss []Sample) (Sample, bool) // bool: partial (some member nil)
  func CSVCell(s string) string
  func WriteCSV(w io.Writer, header []string, rows [][]string) error
  const ( Interval = 15 * time.Second; RingSize = 240; MaxContainers = 256; Parallel = 4
          StatsTimeout = 5 * time.Second; SweepBudget = 12 * time.Second
          InspectEvery = 5 * time.Minute; InfoEvery = time.Hour; MinInterval = time.Second )
  ```

- [ ] **Step 1: Write the failing tests:**
  - `TestDeriveCPU`: Δ`CPUUsageNS` 3e9 over Δ`Read` 15 s → 0.2.
  - `TestDeriveCPURestart`: the counter went down → `nil`; `StartedAt` changed → `nil`; `prev == nil` → `nil`.
  - `TestDeriveCPUGauge`: `CPUCores` set (Kubernetes) → used as is.
  - `TestRateNullOnTinyOrNegativeInterval`: Δt 0, 200 ms, −5 s → every rate `nil`; 15 s → values.
  - `TestWorkingSet`: v2 usage 100 MiB, inactive 30 MiB → 70 MiB. Inactive > usage → 0, never negative. Usage nil → nil. `MemWorkingSet` set → it.
  - `TestDeriveNetworkModes`: `none`, `host`, `container:x`, `service:y` → net `nil` even with counters.
  - `TestLimitsOf`: `NanoCPUs 5e8` → 0.5; else `CPUQuota 50000 / CPUPeriod 100000` → 0.5; neither → nil; Memory 0 → `MemLimitBytes` 0.
  - `TestRingWraps`: 300 adds → 240 points, oldest first; `Since` filters.
  - `TestTotalPartial`: `[{mem 1}, {mem nil}]` → mem 1, partial true. `MemLimitBytes` sums only when every member has a non-zero one, else nil (partly unlimited). All nil → nil, partial false.
  - `TestCSVCellEscapes`: `=1+1`, `+x`, `-x`, `@x`, `"\tx"`, `"\rx"` → prefixed `'`; `a,b"c` round-trips through `encoding/csv`.
- [ ] **Step 2:** Run `go test ./internal/usage/`. Expected: FAIL (package missing).
- [ ] **Step 3:** Implement. `Derive` takes Δt from `cur.Read.Sub(prev.Read)`, and every rate is `nil` under `MinInterval` (U4). Byte rates are `Δ / Δt.Seconds()`. `WriteCSV` uses `csv.NewWriter` with every cell through `CSVCell`.
- [ ] **Step 4:** Run `go test -race ./internal/usage/`. Expected: PASS.
- [ ] **Step 5:** Commit `usage: samples, rates, rings, totals and CSV escaping`.

### Task 4: The sampler, scope and views (hub)

**Files:**
- Create: `internal/hub/usage.go` (state, `RunUsageSampler`, sweep), `usage_scope.go` (grouping), `usage_view.go` (views, `UsageOverview`, `UsageInstance`), and `usage_test.go`.
- Modify: `internal/hub/hub.go` (field `usage *usageState`, initialised in `New`), `cmd/hub/main.go` (`go h.RunUsageSampler(ctx, usage.Interval)` beside `RunDoctorScans`), `CLAUDE.md` (Layout rows for `internal/usage` and `usage*.go`; the sampler rules: cache-only reads, field-by-field inspect copy, no `mu` across engine calls, never `SYSTEM`).

**Interfaces:**
- Consumes: Task 2's runtime calls, Task 3's package.
- Produces:
  ```go
  func (h *Hub) RunUsageSampler(ctx context.Context, every time.Duration)
  func (h *Hub) UsageOverview() UsageView
  func (h *Hub) UsageInstance(id string) (*UsageGroup, error) // statusErr 404 "app instance not found: <id>"
  type UsageView struct {
      SampledAt *time.Time `json:"sampled_at"`; IntervalS int `json:"interval_s"`; Stale bool `json:"stale"`
      Engine UsageEngine `json:"engine"`; Host UsageHost `json:"host"`
      Apps []UsageGroup `json:"apps"`; Core UsageGroup `json:"core"`
      UnknownProjects []UsageGroup `json:"unknown_projects"`
      NotShown int `json:"not_shown"`; OverLimit int `json:"over_limit"`
  }
  type UsageEngine struct { Runtime string `json:"runtime"`; Verified bool `json:"verified"`; Why string `json:"why,omitempty"` }
  type UsageHost struct { CPUs *int `json:"cpus"`; MemoryBytes *int64 `json:"memory_bytes"` }
  type UsageGroup struct {
      Instance, Template, Name, Status string // json snake_case; Status running|stopped|restarting|partly running|not_measured
      Why string `json:"why,omitempty"`        // Status not_measured: the reason
      Totals usage.Sample `json:"totals"`; Partial bool `json:"partial"`
      Containers []UsageContainer `json:"containers"`
      History *UsageHistory `json:"history,omitempty"`  // UsageInstance only
      Storage *StorageGroup `json:"storage,omitempty"`  // UsageInstance only (Task 9 fills it)
  }
  type UsageContainer struct {
      ID12, Service string; Number int; State string
      Sample usage.Sample `json:"sample"`; Limits UsageLimits `json:"limits"`
      OOMKilled bool `json:"oom_killed"`; Restarts int `json:"restarts"`
      Helper bool `json:"helper,omitempty"`; Error string `json:"error,omitempty"` // "stats unavailable"
  }
  type UsageLimits struct { MemBytes int64 `json:"mem_bytes"`; CPUCores *float64 `json:"cpu_cores"`; Pids int64 `json:"pids"` }
  type UsageHistory struct { T []time.Time `json:"t"`; CPUCores map[string][]*float64 `json:"cpu_cores"`; MemBytes map[string][]*int64 `json:"mem_bytes"` }
  func (h *Hub) usageSnapshot() usageSnap // for the doctor (Task 6) and metrics (Task 13): a deep copy under the sampler's RWMutex
  ```
  `StorageGroup` is declared here with its fields commented as "Task 9" so the type exists. Grouping: `portcullis-<id>` with a known instance → app; with no instance → `unknown_projects` (by project name); project `portcullis` → core (U23 helpers row); everything else → `not_shown` count only (U24).

- [ ] **Step 1: Write the failing tests** (`usage_test.go`, `runtimetest.Fake`, a fake clock, `sweep(ctx)` called directly):
  - `TestUsageGroupsAppsCoreUnknownOther`: units of `portcullis-a` (2), `portcullis` (hub, traefik), `portcullis-gone` (no instance) and 3 unlabelled. Apps = [a], core has 2 + 0 helpers, `unknown_projects` = [portcullis-gone], `not_shown` 3. The fake recorded no `stats` for the 3 others.
  - `TestUsageAggregatesAndPartial`: two containers, one `StatsErr`. Totals mem = the other's, `partial` true, the failed container's `error` "stats unavailable", its sample all `null`.
  - `TestUsageCPUOnSecondSweep`: first sweep `cpu_cores` null, second 0.2.
  - `TestUsageCapAt256`: 300 app units → 256 sampled, `over_limit` 44.
  - `TestUsageInspectEvery5Min`: inspect on first sight, not at +15 s, again at +5 min.
  - `TestUsageNeverKeepsEnv`: the fake `Infos` carry a `Labels` value and the fake's raw inspect stand-in holds `SECRET_TOKEN=abc`. `json.Marshal` of `UsageOverview()`, `UsageInstance("a")` and `usageSnapshot()` lacks `abc`, and so does a captured `log` output.
  - `TestUsageSweepReleasesMuDuringEngineCalls`: `StatsBlock` holds a sweep inside `Stats`. Then `h.mu.Lock()` succeeds within 1 s, and the sweep finishes after `close(StatsBlock)`.
  - `TestUsageRefusedEngine`: `Fake.Err = &engine.RefusedError{…}`. `Engine.Verified` false, `Why` = `RefusedError.Message()`, the last good numbers kept, `stale` true after 2 intervals.
  - `TestUsageRingsFollowRecreatedContainers` (Review Focus 1).
  - `TestUsageStoppedAppShowsStopped`: exited containers → group status `stopped`, totals all null (never zeros).
  - `TestUsageSweepBudget`: with 40 units each taking 1 s (fake delay), the sweep ends by 12 s. The rest keep their previous sample, and the sweep's `budget_skipped` count is logged once.
  - `TestUsageHistoryKeyedByServiceNumber`: `UsageInstance` history keys `web.1`, `db.1`; `T` length = ring length.
- [ ] **Step 2:** Run `go test ./internal/hub/ -run Usage`. Expected: FAIL.
- [ ] **Step 3:** Implement. Each sweep:
  1. copy the instance list under `h.mu.RLock()` and release it;
  2. `rt.List(Filter{})`;
  3. group;
  4. a worker pool of `usage.Parallel` with `context.WithTimeout(usage.StatsTimeout)` each, inside `context.WithTimeout(usage.SweepBudget)`;
  5. inspect due containers;
  6. store under the sampler's own `sync.RWMutex`.

  `Info` runs at start and every `InfoEvery`. On `errors.Is(err, engine.ErrEngineRefused)` the sweep stops and records the refusal. Views compute `Totals` with `usage.Total`, `Status` from unit states, and `Name` from the instance's label (else the template's name, else the id).
- [ ] **Step 4:** Run `go test -race ./internal/hub/ -run Usage`. Expected: PASS. Then the full gates.
- [ ] **Step 5:** Commit `hub: the usage sampler (15 s, cache-only reads), app/core/unknown grouping and views`.

### Task 5: Routes, CSV export, MCP `usage_overview` / `usage_instance` (hub)

**Files:**
- Create: `internal/httpapi/usage.go` (`registerUsage(mux routeMux)`, handlers), `usage_test.go`, `mcptools_usage.go` (`registerUsageTools()`), `mcptools_usage_test.go`.
- Modify: `internal/httpapi/server.go` (`s.registerUsage(mux)` in `hubMux` after `registerDoctor`), `mcp.go` (`s.registerUsageTools()`), `mcp_parity_test.go` (`adminUsage`, `usageNoToolRoutes`).

**Interfaces:**
- Consumes: `Hub.UsageOverview`, `Hub.UsageInstance` (Task 4), `usage.WriteCSV` (Task 3).
- Produces:
  - routes `GET /api/usage`, `GET /api/usage/instances/{id}`, `GET /api/usage/export.csv?view=apps|containers` (`storage` from Task 10);
  - `(s *Server) usageOverview() hub.UsageView`, `(s *Server) usageInstance(id string) (*hub.UsageGroup, error)`, shared by route and tool;
  - `var adminUsage = []string{"usage_overview", "usage_instance", "usage_storage", "usage_storage_measure", "usage_storage_op"}` (Task 10 registers the last three);
  - `var usageNoToolRoutes = map[string]string{"GET /api/usage/export.csv": "a file download; usage_overview and usage_storage answer the same data", "POST /api/usage/storage/op/stop": "stops a read-only measurement in the admin UI's progress panel; the figures measured so far are kept"}`. The stop entry is added in Task 9 together with its route.

- [ ] **Step 1: Write the failing tests:**
  - `TestUsageRoutesHubListenerOnly`: each route on `e.people` → 404, and on the Hub listener as a non-admin → 401/403 (the `folderAdmin` rule).
  - `TestUsageOverviewJSON`: field names exactly as §11.11 (`sampled_at`, `interval_s`, `stale`, `engine.runtime`, `host.cpus`, `apps[0].totals.mem_bytes`, `not_shown`, `over_limit`), `Cache-Control: no-store`, and a `null` stays `null`.
  - `TestUsageInstance404`: unknown id and a bad id (`../x`) → 404 "app instance not found".
  - `TestUsageCSV`: `view=apps` header = U22's, a `null` → empty cell, a label `=HYPERLINK(…)` → `'=HYPERLINK(…)`. `Content-Type: text/csv; charset=utf-8`, the `Content-Disposition` filename matches `^portcullis-usage-apps-\d{8}T\d{6}Z\.csv$`, `no-store`. `view=bogus` → 400.
  - `TestUsageReadsNeverReachEngine` (Review Focus 2).
  - `mcptools_usage_test.go` `TestUsageToolsParity`: `usage_overview` and `usage_instance` are R, their twins are the routes, and the answers equal the routes' JSON. `usage_instance {"id":"../x"}` → the 404 text. Answers pass the redactor (a redact literal planted in a label is masked).
  - `mcp_parity_test.go`: `TestToolParity` reads `usageNoToolRoutes` like `vpnNoToolRoutes`, and the all-tools check includes `adminUsage[:2]`.
- [ ] **Step 2:** Run `go test ./internal/httpapi/ -run 'Usage|Parity'`. Expected: FAIL.
- [ ] **Step 3:** Implement. Handlers run `folderAdmin` → `noStore(w)` → `writeJSON`. CSV rows come from the same view (one container row per container, core rows with `instance` `core`). Tools use `admin("usage_overview", "<spec §8.2 description>", ClassRead, "GET /api/usage", "", …)`.
- [ ] **Step 4:** Run `go test -race ./internal/httpapi/`. Expected: PASS.
- [ ] **Step 5:** Commit `httpapi: usage routes, CSV export and the usage_overview / usage_instance tools`.

### Task 6: Doctor `memory_near_limit`, `oom_killed`, `pids_near_limit`, `usage_not_measured` (hub)

**Files:**
- Create: `internal/doctor/usage.go`, `usage_test.go`, `internal/hub/doctor_usage.go`, `doctor_usage_test.go`.
- Modify: `internal/doctor/doctor.go` (`Inputs.Usage *UsageIn`, `Inputs.Storage *StorageIn`), `internal/hub/doctor.go` (`doctorInputs` gathers `h.usageDoctorIn()` before `mu`).

**Interfaces:**
- Consumes: `Hub.usageSnapshot()` (Task 4).
- Produces (in `doctor`):
  ```go
  const ( KindDiskNearlyFull = "disk_nearly_full"; KindMemoryNearLimit = "memory_near_limit"
          KindOOMKilled = "oom_killed"; KindPidsNearLimit = "pids_near_limit"
          KindUsageNotMeasured = "usage_not_measured"; KindStorageMeasurePartial = "storage_measure_partial"
          TabUsage = "usage" )
  var UsageKinds = []string{KindMemoryNearLimit, KindOOMKilled, KindPidsNearLimit, KindUsageNotMeasured}
  type UsageIn struct { Runtime string; Verified bool; LastSuccess time.Time; NotMeasured string; Containers []ContainerUsageIn }
  type ContainerUsageIn struct { Instance, Service string /* Instance "" = core */; Number int
      MemLimit, PidsLimit int64; OOMKilled bool; Restarts, RestartsHourAgo int; OOMSeenHour bool
      Points []UsagePointIn /* the last 10 min */ }
  type UsagePointIn struct { At time.Time; Mem, Pids *int64 }
  type StorageIn struct { Filesystems []FilesystemIn; Partial []StoragePartialIn } // Task 11 fills and judges it
  type FilesystemIn struct { Dev uint64; Path string; Free, Total uint64; Owners []string }
  type StoragePartialIn struct { Target, Owner, Reason string }
  func (h *Hub) usageDoctorIn() *doctor.UsageIn
  ```
  Fingerprints are `Fingerprint(kind, instance, service, strconv.Itoa(number))`, with core as instance `core`. `Inputs` digests use the band: `"warning"`, plus the service for core. Links are `&Link{Instance: id, Tab: TabUsage}` for apps. Core findings name the service and point to `docs/operations/hardening.md`.

- [ ] **Step 1: Write the failing tests** (`internal/doctor/usage_test.go`):
  - `TestMemoryNearLimitTenMinutes`: 40 points at 95 % → Warning. One point at 85 % → none. 29 points → none (< 30). Limit 0 → none. Any `Mem` nil in the window → none.
  - `TestOOMKilled`: `OOMKilled` true → Warning. Restarts 7 vs 3 an hour ago with `OOMSeenHour` → Warning. Restarts +3 without OOM → none.
  - `TestPidsNearLimit`: ≥ 90 % for 10 min → Warning; `PidsLimit` 0 → none.
  - `TestUsageNotMeasured`: `LastSuccess` 6 min ago while verified → Info with the fixed reason. Not verified → none (the engine kinds speak). `NotMeasured` "the cluster has no metrics API (metrics-server)" → Info with that text.
  - `TestUsageFindingTokenStableAcrossSamples`: two runs whose memory differs inside the band → the same `Token`.
  - `TestUsageCoreServiceFinding`: a core `traefik` near its limit → Warning naming `traefik`, `Fix` mentioning `docs/operations/hardening.md`, no `Link`.
  - `TestUsageNilInputsNoFindings`: `Inputs.Usage == nil` → none of the four kinds.
  - `internal/hub/doctor_usage_test.go` `TestUsageDoctorInFromSnapshot`: the window holds only the last 10 min, and `RestartsHourAgo` comes from the ring's oldest point within 1 h.
- [ ] **Step 2:** Run `go test ./internal/doctor/ ./internal/hub/ -run Usage`. Expected: FAIL.
- [ ] **Step 3:** Implement and register the four checks in `init()` (`usageCheck{kind}` like `engineCheck`). All four are `FixExplain`, with the Steps text from spec §9.
- [ ] **Step 4:** Run `go test -race ./internal/doctor/ ./internal/hub/`. Expected: PASS.
- [ ] **Step 5:** Commit `doctor: memory_near_limit, oom_killed, pids_near_limit, usage_not_measured`.

### Task 7: UI: the Usage tab (By app, By container) and the instance Usage tab (hub)

**Files:**
- Create: `web/usage.js` (`window.PortcullisUsage.render(el, view)`, `.renderInstance(el, id)`), `internal/httpapi/webui_usage_test.go`.
- Modify:
  - `web/index.html`:
    - the tab `<div class="tab" data-tab="usage">Usage</div>` between Doctor and Settings;
    - `<div class="tab-content" id="tab-usage"><div id="usage-root"></div></div>`;
    - `<script src="/static/usage.js">`;
    - `PAGE_TABS` gains `['usage', 'Usage']` after `logs`;
    - the hash routes `#usage`, `#usage/apps`, `#usage/containers`, `#usage/storage` (Storage view from Task 12);
    - CSS for bars, sparklines and dimmed figures.
  - `web/web.go`: `usage.js` in the `//go:embed` line.
  - `web/docs/*`: resync after Task 1 (Global Constraints).

**Interfaces:**
- Consumes: `GET /api/usage`, `GET /api/usage/instances/{id}`, `GET /api/usage/export.csv` (Task 5).
- Produces: `window.PortcullisUsage` with `render`, `renderInstance` and `stop()` (clears the poll timer; called by `showTab` when leaving).

- [ ] **Step 1: Write the failing tests** (`webui_usage_test.go`, static checks over the embedded files, as `webui_vpn_test.go`):
  - `TestUsageJSEscapesAndDelegates`:
    - every `innerHTML +=` / `'…' + x + '…'` interpolation in `usage.js` goes through `esc(` (a regexp over `+ [a-z]` that isn't `esc(`, a number formatter `fmtBytes(` / `fmtCores(` / `fmtRate(` or a numeric `.toFixed(`);
    - no `onclick=` / `on[a-z]+="`, no `localStorage`, no `console.log`.
  - `TestUsageJSPollsOnlyWhenVisible`: contains `document.visibilityState`, `visibilitychange`, `15000`, and a `clearTimeout` / `clearInterval` in `stop`.
  - `TestUsageJSBinaryUnits`: the formatter table contains `'KiB'`, `'MiB'`, `'GiB'`, `'TiB'` and no `'MB'`. A `null` renders as `not measured`, never as `0`.
  - `TestUsageSparklineNumbersOnly`: the SVG builder only interpolates through `Number(` / `.toFixed(`.
  - `TestUsageTabPlacement`: in `index.html` the `data-tab="usage"` div sits after `data-tab="doctor"` and before `data-tab="settings"`. `PAGE_TABS` contains `['logs', 'Logs'], ['usage', 'Usage']`, and `web.go`'s embed line names `usage.js`.
  - `TestUsageCSVLinks`: the page links `/api/usage/export.csv?view=apps` and `…containers`.
- [ ] **Step 2:** Run `go test ./internal/httpapi/ -run 'UsageJS|UsageTab|UsageCSV|Sparkline'`. Expected: FAIL.
- [ ] **Step 3: Implement:**
  - **By app** (default): sortable columns per spec §6.2; rows expand in place to containers; the Core group last and collapsible; the header strip with host CPUs/memory, sums, "sampled 4 s ago" and "N other containers on this engine are not shown"; the refusal message from `engine.why`.
  - **By container:** a flat table with a filter box (app, service) and limits as numbers.
  - **Instance tab:** that group's containers and 1 h sparklines (inline SVG polylines from numbers). Its Storage block is filled in Task 12.
  - **Display rules:** CPU "0.35 CPU" + percentage; memory bars coloured at 80/90 %; "≥ " prefix when `partial`; "no limit" when `mem_limit_bytes` is 0.
- [ ] **Step 4:** Run `go test ./internal/httpapi/ ./web/`. Expected: PASS. Open the page against a local Hub with fake data (`go test -tags harness` harness or `go run ./cmd/hub` in dev mode) and check both views by eye. This needs no Docker.
- [ ] **Step 5:** Commit `web: Usage tab (by app, by container) and the instance Usage tab`. Then the docs resync commit.

---

## Hub stream: Part 2, storage (Tasks 8–12)

### Task 8: Fixer `usage` mode and `alloc_bytes` in `scan` (hub)

**Files:**
- Create: `internal/folderfix/usage.go`, `usage_test.go`; `internal/hub/usage_docker_test.go` (`//go:build docker`).
- Modify:
  - `internal/folderfix/fs_linux.go`: `statxWant` adds `STATX_BLOCKS|STATX_SIZE`, and `fileStat` gains `Blocks`, `Size`; the `Fstatat` fallback fills them too.
  - `fs_other.go` (the same fields).
  - `walk.go`: per-entry `alloc` / `apparent` sums, and a `(dev, ino)` set for `Nlink > 1` capped at 1,000,000, past which the report is `partial` with reason `hard_links`.
  - `scan.go`: `Report` gains `AllocBytes uint64 json:"alloc_bytes"`, `ApparentBytes uint64 json:"apparent_bytes"`, `IOIdle *bool json:"io_idle,omitempty"`.
  - `cli.go`: `modeFlags["usage"] = {"root", "max-entries", "max-time"}`, `Args`, `Main` (U15 exit codes).
  - `root_test.go` (fixerroot cases).
- Modify: `internal/hub/fixer.go`:
  - `fixerRun.Mode` accepts `"usage"`;
  - `validate`: usage takes `Folder` "", no target, principals or children, and the caps, with exactly one of `Source` (a bind) or `Volume` (new field `fixerRun.Volume runtime.VolumeMount`);
  - `fixerTimeout`: usage = `MaxTime + 30 s`;
  - `spec`: usage mounts at `/vol` (`fixerUsageRoot = "/vol"`), read-only, `CapAdd` `fixerReadCaps`, label `usage:<target>` with the target clipped to 200 runes.

**Interfaces:**
- Produces:
  - `folderfix.Usage(o Options) (*Report, error)`;
  - `folderfix.Args("usage", Options{Root: "/vol", MaxEntries, MaxTime}, ArgsExtra{})` = `["usage", "--root=/vol", "--max-entries=2000000", "--max-time=2m0s"]`;
  - `(h *Hub) runUsageFixer(ctx context.Context, r fixerRun) (*folderfix.Report, error)` (through `execFixer`, mode `usage`).

- [ ] **Step 1: Write the failing tests** (`internal/folderfix/usage_test.go`, no root needed, `t.TempDir()`):
  - `TestUsageAllocMatchesBlocks`: files of 1 B, 4 KiB and 1 MiB. `alloc_bytes` = Σ `st_blocks*512` from `syscall.Stat`, `apparent_bytes` = Σ sizes.
  - `TestUsageHardLinksOnce`: a 1 MiB file with 3 links → counted once, `hard_links.n` 3.
  - `TestUsageSparse`: a file truncated to 1 GiB with 4 KiB written → alloc ≈ 4 KiB, apparent 1 GiB.
  - `TestUsageSymlinkLoopNotFollowed`: `a → .` and `b → a` → counted as symlinks, the walk ends.
  - `TestUsageMaxTimePartial`: `MaxTime` 1 ns → `partial` true, reason `time`.
  - `TestUsageHardLinkCapPartial`: the cap lowered through a test var to 2, with 3 multi-link inodes → `partial`, reason `hard_links`.
  - `TestUsageFailedEntriesExitZero`: `Main` on a tree whose dir is mode 0000 (as non-root) → exit 0, `partial_reason` `failed`, `failed.n` 1.
  - `TestScanGainsAlloc`: `Scan` reports the same `alloc_bytes` as `Usage` on the same tree.
  - `TestUsageArgsRoundTrip` and `TestUsageRejectsScanFlags` (`--gid`, `--principal` → error).
  - `TestUsageIOIdle`: `IOIdle` non-nil on Linux.
- [ ] **Step 2: More failing tests:**
  - `root_test.go` (`fixerroot`): `TestRootUsageMatchesDu` compares a tree with hard links, a sparse file, a bind-mounted subdir (counted as a mount point, not crossed) and a 0700 dir owned by uid 2001 against `du -s --block-size=1 -x`. As root with `DAC_READ_SEARCH` they are equal. With the capability dropped (`capsh --drop=cap_dac_read_search,cap_dac_override --`) the 0700 dir counts as `failed`.
  - `internal/hub/usage_docker_test.go` `TestDockerUsageHelper`: the real Hub-shaped image (as `fixer_docker_test.go`) on a named volume. The report decodes and `alloc_bytes > 0`. Inside the helper, a write to `/vol/x` fails (read-only) and `/proc/self/status` `CapEff` holds only `DAC_READ_SEARCH`. The container is gone after the run.
  - `fixer_test.go` `TestFixerUsageSpec`: the `RunSpec` for a volume target has one `Volumes` mount at `/vol`, no `Binds`, `CapAdd [DAC_READ_SEARCH]`, label `usage:portcullis-a_data`, `Timeout` 2m30s. A bind target has one read-only bind at `/vol`. Both, or neither, → `validate` error.
- [ ] **Step 3:** Run `go test ./internal/folderfix/ ./internal/hub/ -run 'Usage|FixerUsage'`. Expected: FAIL.
- [ ] **Step 4:** Implement:
  - `Usage` = `openWalker(o, "usage")`, `w.run(w.tallySize)`, `finish`;
  - IO priority: `unix.Syscall(unix.SYS_IOPRIO_SET, 1 /*IOPRIO_WHO_PROCESS*/, 0, 3<<13 /*IOPRIO_CLASS_IDLE*/)` once at start, with `IOIdle` from its result;
  - in `walk.go`, the size sums run in `handle` for every mode (one add per entry).
- [ ] **Step 5:** Run `go test -race ./internal/folderfix/ ./internal/hub/`. Then, on the builder in DinD: `go test -tags fixerroot -run Usage ./internal/folderfix/` (as root) and `PORTCULLIS_DOCKER_TEST=require go test -tags docker -run 'TestDockerUsage' ./internal/hub/`. Expected: PASS.
- [ ] **Step 6:** Commit `folderfix: usage mode (du-equal alloc bytes, hard links once, idle IO), alloc_bytes in scan reports`.

### Task 9: The storage measurer, cache, schedule, op `_usage`, routes and Stop (hub)

**Files:**
- Create: `internal/hub/usage_storage.go` (targets, run, `StartUsageMeasure`, `StopUsageMeasure`, `RunUsageStorage`, `UsageStorage`), `usage_storage_cache.go` (`storage.json` read/write), `usage_storage_test.go`.
- Modify:
  - `internal/hub/hub.go` (`diskMu sync.Mutex`, `storeMu`, `measureMu`);
  - `doctorscan.go` (`scanOne` holds `h.diskMu` around its fixer run, U12);
  - `ops.go` (`validOpKey` accepts `opKeyUsage = "_usage"`);
  - `cmd/hub/main.go` (`go h.RunUsageStorage(ctx, 24*time.Hour)`);
  - `internal/hub/usage_view.go` (`UsageInstance` fills `Storage`);
  - `internal/httpapi/usage.go` (`POST /api/usage/storage/measure`, `GET /api/usage/storage`, `GET /api/usage/storage/op`, `POST /api/usage/storage/op/stop`), `mcp_parity_test.go` (`usageNoToolRoutes` stop entry).

**Interfaces:**
- Consumes:
  - `runUsageFixer` (Task 8);
  - `rt.ListVolumes(Filter{Instance})`, `rt.LayerSize`, `rt.ImageSize`, `rt.Info().ForbiddenRoots` (Task 2);
  - the sampler's cached `UnitInfo.Mounts` (Task 4);
  - `h.scanEntries()` for folders.
- Produces:
  ```go
  const OpUsageMeasure = "usage_measure"; const opKeyUsage = "_usage"
  func (h *Hub) StartUsageMeasure(actor directory.Actor, instance string) (*AsyncOp, error) // 401 no user, 404 unknown instance, 409 "a storage measurement is already running", 503 no engine
  func (h *Hub) StopUsageMeasure(actor directory.Actor, expectedOpID string) (*OpRecord, error) // 404 none, 409 not running / changed
  func (h *Hub) RunUsageStorage(ctx context.Context, every time.Duration)
  func (h *Hub) UsageStorage() StorageView
  type StorageView struct { MeasuredAt *time.Time `json:"measured_at"`; RunningOp *AsyncOp `json:"running_op"`
      Disks []DiskView `json:"disks"`; Apps []StorageGroup `json:"apps"`; Folders []FolderStorage `json:"folders"`; Core []StorageItem `json:"core"` }
  type StorageGroup struct { Instance, Name string; Items []StorageItem; TotalAlloc *int64 `json:"total_alloc_bytes"`; Partial bool }
  type StorageItem struct { Target, Kind string /* volume|bind|folder|layer|image|hub_files */; Owner string
      AllocBytes, ApparentBytes *int64; Partial bool; PartialReason string; InTotal bool `json:"in_total"`
      Shared []string `json:"shared_with,omitempty"`; Dev uint64 `json:"-"`; Path string `json:"-"`
      MeasuredAt *time.Time; DurationMS int64; Error string `json:"error,omitempty"` }
  type FolderStorage struct { ID, Name string; AllocBytes *int64; Partial bool; UsedBy []string; MeasuredAt *time.Time; Note string `json:"note,omitempty"` }
  type DiskView struct { Dev uint64 `json:"dev"`; FreeBytes, TotalBytes uint64; UsedPercent float64; Owners []string }
  func (h *Hub) storageDoctorIn() *doctor.StorageIn // Task 11
  ```
  - Cache: `<data>/usage/storage.json` = `{"version":1,"last_run":…,"entries":{"<kind>:<target>":storageEntry}}`. It is written atomically (temp file + rename, 0600). A file > 4 MiB or > 2048 entries, a bad version or invalid JSON is dropped with one log line.
  - Bind targets: the sampler's `Mounts` with `Type bind`, source `underBindRoots` and not `inFolderLocked`, and not under `ForbiddenRoots`. A path refused for the engine root is listed with error "refused: under the engine's data root".
  - Core volumes: `ListVolumes(Filter{})` where the label `com.docker.compose.project` = `portcullis`. On Kubernetes core is skipped with "not measured on Kubernetes yet".
  - `HubFiles`: one item per app, kind `hub_files`, sizes `nil`.

- [ ] **Step 1: Write the failing tests** (Fake runtime; `runUsageFixer` stubbed through a `h.usageFixer` func field for unit tests):
  - `TestStorageTargets`: one app with 2 volumes and a bind under a bind root, a bind inside a shared folder (→ folder row, not measured again), a core volume `portcullis_postgres_data`. Targets = [2 volumes, 1 bind, 1 core], in that order (apps by id, then core).
  - `TestStorageSequentialAndDiskMu`: a stub fixer that records overlap. Never two at once, and a doctor `scanOne` holding `diskMu` delays the next target.
  - `TestStorageCapsAndBudget`: a stub returns `partial` reason `time` → item `partial`. With a fake clock past 1 h, the remaining targets keep their old figure and date, plus a warning "not measured: the run's time budget (1h0m0s) is spent".
  - `TestStorageLayerAndImageSizes`: `LayerSizes` / `ImageSizes` → `layer` items in the total, `image` items `in_total: false`. A `NotMeasuredError` → `null` with the reason.
  - `TestStorageSharedTargetMeasuredOnce` (Review Focus 4).
  - `TestStorageInstanceDeletedMidRun` and `TestStorageCacheWriteFailureKeepsPrevious` (Review Focus 5; the data dir made read-only after the first write).
  - `TestStorageCacheCorruptDropped`: a 5 MiB file, garbage, version 2 → `UsageStorage().MeasuredAt == nil`.
  - `TestStorageOp409WhileRunning`: a second `StartUsageMeasure` → 409. The op record key `_usage` is `running` and then `ok` with result `{targets, measured, failed, skipped}`. The audit has `usage.measure`, actor `alice`, detail `scope=all`.
  - `TestStorageStopBetweenTargets`: Stop during target 1 of 3 → target 1 finishes, 2 and 3 are skipped (old figures kept), the record is `stopped`, and the audit has `usage.measure.stop`.
  - `TestStorageScheduleFirstRun`: cache 25 h old → first run 10 min after start; 2 h old → at `last_run + 24 h`.
  - `TestStorageFoldersFromScans`: a doctor scan entry with `alloc_bytes` → `FolderStorage.AllocBytes`. A `TopOnly` tree → `nil` with the U14 note. An old entry without the field (`alloc_bytes` 0 and `entries > 0`) → `nil` "not measured yet".
  - httpapi `TestUsageStorageRoutes`: `POST /api/usage/storage/measure` body `{}` → 202 `{op_id, op, instance, poll}`; `{"instance":"nope"}` → 404; an unknown field → 400; a body > 1 KiB → 413; `GET /api/usage/storage/op` with none → 404; `POST …/op/stop` → 202 or 409; all on the Hub listener only.
- [ ] **Step 2:** Run `go test ./internal/hub/ ./internal/httpapi/ -run 'Storage'`. Expected: FAIL.
- [ ] **Step 3:** Implement. Use `startAsync(opKeyUsage, OpUsageMeasure, actor, []Step{{Key: "measure", Label: "Measure storage"}}, fn)`. Inside `fn`, `measureMu.TryLock()` gives the 409. Each target checks `ctx.Err()` (Stop) and the run's `context.WithoutCancel` budget. Progress detail is "<n>/<total>: <target>". The scheduled run uses the same function with actor `{User: "hub", Via: "schedule"}`, not audited (like `RunDoctorScans`). `StopUsageMeasure` reuses `cancelOpExpect(opKeyUsage, …)`.
- [ ] **Step 4:** Run `go test -race ./internal/hub/ ./internal/httpapi/`. Expected: PASS.
- [ ] **Step 5:** Commit `hub: storage measurer (daily + on demand, op _usage, Stop between targets), storage.json cache, storage routes`.

### Task 10: MCP storage tools and the storage CSV (hub)

**Files:**
- Modify: `internal/httpapi/mcptools_usage.go`, `mcptools_usage_test.go`, `usage.go` (`view=storage`), `usage_test.go`.

**Interfaces:**
- Consumes: `StartUsageMeasure`, `UsageStorage`, `LastOp("_usage")` (Task 9).
- Produces:
  - tools `usage_storage` (R, `GET /api/usage/storage`), `usage_storage_measure` (W, `POST /api/usage/storage/measure`, audit `usage.measure`, args `{instance?}` with `templates.InstanceIDRe` else 404) and `usage_storage_op` (R, `GET /api/usage/storage/op`), with the descriptions from spec §8.2;
  - `(s *Server) usageMeasure(a directory.Actor, instance string) (*hub.AsyncOp, error)`, shared by route and tool.

- [ ] **Step 1: Write the failing tests:**
  - `TestUsageStorageToolsParity`: the three tools' classes (R, W, R) and twins, and answers equal to the routes'. `usage_storage_measure` via ai → the audit entry's `via: ai` and client.
  - `TestUsageNoDTool`: no usage tool is `ClassDestructive`.
  - `TestUsageCSVStorage`: header = U22 storage, a shared item's `shared_with` = `a;b`, `null` → empty.
  - `TestToolParity` / the all-tools check now include all of `adminUsage`.
- [ ] **Step 2:** Run `go test ./internal/httpapi/ -run 'Usage|Parity'`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `go test -race ./internal/httpapi/`. Expected: PASS.
- [ ] **Step 5:** Commit `httpapi: usage_storage, usage_storage_measure, usage_storage_op; storage CSV`.

### Task 11: Doctor `disk_nearly_full`, `storage_measure_partial` (hub)

**Files:**
- Modify: `internal/doctor/usage.go`, `usage_test.go`, `internal/hub/doctor_usage.go` (`storageDoctorIn`), `internal/hub/doctor.go`.

**Interfaces:**
- Consumes: `StorageIn` (Task 6 type), `storageDoctorIn` (Task 9 signature). Filesystems = every storage item's report `dev` / `free` / `total`, every doctor scan's, and a direct `unix.Statfs` of `h.cfg.DataDir` (dev from `Stat`). They are deduplicated by `dev`. Owners are sorted by `alloc_bytes`, largest first.
- Produces: the two checks registered. Fingerprint `Fingerprint(KindDiskNearlyFull, strconv.FormatUint(dev, 10), path)` with the band as `Inputs`. `storage_measure_partial` is `Fingerprint(kind, owner, target)`, Info, "the figure is a lower bound".

- [ ] **Step 1: Write the failing tests:**
  - `TestDiskNearlyFullBands`: on a 100 GiB disk, 12 GiB free → none, 9 GiB → Warning, 2.5 GiB → Problem. On a 20 GiB disk, 4 GiB free (20 %) → Warning (< 5 GiB), 0.9 GiB → Problem (< 1 GiB).
  - `TestDiskNearlyFullDedupByDev`: three items on one `dev` → one finding listing the owners largest first, with the Explain text "free space or move the data" and a link to Storage (`Link{Tab: TabUsage}` for the largest app, `Paths` the mount path).
  - `TestDiskNearlyFullNoNumbers`: `Total == 0` → none.
  - `TestStorageMeasurePartial`: one partial item → Info.
  - `TestDiskTokenStableInBand`: free changes 9.0 → 8.5 GiB → the same token; 2.9 % → a new token.
- [ ] **Step 2:** Run `go test ./internal/doctor/ -run 'Disk|StorageMeasure'`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `go test -race ./internal/doctor/ ./internal/hub/`. Expected: PASS.
- [ ] **Step 5:** Commit `doctor: disk_nearly_full and storage_measure_partial`.

### Task 12: UI: the Storage view (hub)

**Files:**
- Modify: `web/usage.js` (`renderStorage(el)`, the instance tab's storage block), `web/index.html` (`#usage/storage`), `internal/httpapi/webui_usage_test.go`.

**Interfaces:**
- Consumes: `GET /api/usage/storage`, `POST /api/usage/storage/measure`, `GET /api/usage/storage/op`, `POST /api/usage/storage/op/stop` (Task 9), and the existing operation-progress panel.
- Produces: the panel's `OP_WORDS` gains `usage_measure: { ing: 'Measuring storage', ed: 'measured', short: 'Measuring', stopped: 'stopped: the figures measured so far are kept' }`. `oppStop` posts to `/api/usage/storage/op/stop` when the panel's key is `_usage` (else the instance route as today).

- [ ] **Step 1: Write the failing tests:**
  - `TestUsageStorageView`:
    - `usage.js` contains the Disks strip thresholds `90` / `97`;
    - "Measure now" and `data-usage-measure` (per app, sending `{instance}`);
    - `shared, not in total`, `Hub-managed files`, `measured ` + age, the dim class at 48 h (`172800`);
    - the "≥ … (stopped after …)" form;
    - the Grafana link only when `metrics_scraped` is true (Task 13 adds the field; until then it is false).
  - `TestOppStopUsageKey`: `index.html` routes `_usage` to `/api/usage/storage/op/stop`.
  - The escaping test of Task 7 covers `renderStorage` too.
- [ ] **Step 2:** Run `go test ./internal/httpapi/ -run 'UsageStorageView|OppStopUsage'`. Expected: FAIL.
- [ ] **Step 3:** Implement. The Disks strip shows used / total, free, the colour and the apps there. Then per app (volumes, binds, layers, images "shared, not in total"), shared folders (size, users, last scan, "partial"), core volumes.
- [ ] **Step 4:** Run `go test ./internal/httpapi/ ./web/`. Expected: PASS. Check the view by eye against a harness Hub with a fake cache.
- [ ] **Step 5:** Commit `web: Usage → Storage (disks, apps, shared folders, core), Measure now, Stop through the progress panel`.

---

## Hub stream: Part 3, history (Task 13)

### Task 13: Metrics listener and collector (hub)

**Files:**
- Create: `internal/hub/usage_metrics.go` (`usageCollector`), `usage_metrics_test.go`; `internal/httpapi/metricslistener.go` (`MetricsHandler(c prometheus.Collector, onScrape func()) http.Handler`), `metricslistener_test.go`; `cmd/hub/metrics.go` (`metricsBindAddr`), `metrics_test.go`.
- Modify: `cmd/hub/main.go` (`HUB_METRICS_ADDR`: unset = no listener; else bind and serve), `go.mod` (`client_golang` direct), `internal/hub/usage_storage.go` (`StorageView.MetricsScraped bool json:"metrics_scraped"`), `internal/hub/usage_view.go`.

**Interfaces:**
- Consumes: `usageSnapshot()` (Task 4), the storage cache (Task 9).
- Produces:
  - `func (h *Hub) UsageCollector() prometheus.Collector`;
  - `func (h *Hub) NoteMetricsScrape()`;
  - `func (h *Hub) MetricsScrapedRecently() bool` (5 min);
  - `func metricsBindAddr(addr string, lookup func(host string) ([]netip.Addr, error), own func() ([]netip.Addr, error)) (string, error)`. It refuses a wildcard (`""`, `0.0.0.0`, `::`), a loopback, a host that resolves to 0 or > 1 address, and an address not among `own()`.
  - Series per spec §11, labels `instance` (id or `core`), `service`, `number`:
    - `portcullis_storage_alloc_bytes{instance,kind,target}`, where `target` is a volume name or folder id, never a host path: binds are `target="bind:<n>"`, numbered per instance in path order;
    - `portcullis_filesystem_{free,total}_bytes{dev}`;
    - `portcullis_usage_sampler_last_success_timestamp_seconds`.
  - The registry is `prometheus.NewRegistry()` with only this collector: no Go or process collectors. The handler is `promhttp.HandlerFor(reg, promhttp.HandlerOpts{})` on `GET /metrics`, plus `GET /healthz`. Anything else → 404.

- [ ] **Step 1: Write the failing tests:**
  - `TestUsageCollectorSeries`: run a fake snapshot through `testutil.CollectAndCompare` against an expected text, with a `null` memory value absent (not 0). On a Kubernetes snapshot (`CPUCores` gauge) there is no `portcullis_container_cpu_seconds_total` (U9).
  - `TestUsageCollectorNoHostPath`: a bind under `/srv/media/x` → `target="bind:1"`, and the text lacks `/srv`.
  - `TestUsageCollectorCardinality`: 256 containers → ≤ 2,600 series.
  - `TestMetricsHandlerOnly`: `/metrics` 200, `/healthz` 200, `/api/usage` 404, `POST /metrics` 405. `onScrape` is called once per scrape, and `MetricsScrapedRecently` is true, then false 6 min later (fake clock).
  - `TestMetricsBindAddr`: `hub-metrics:9100` resolving to `172.18.0.5` with own {`172.18.0.5`} → `172.18.0.5:9100`. `:9100`, `0.0.0.0:9100`, `127.0.0.1:9100`, two addresses, or an address not own → error.
- [ ] **Step 2:** Run `go test ./internal/hub/ ./internal/httpapi/ ./cmd/hub/ -run 'Metrics|Collector'`. Expected: FAIL.
- [ ] **Step 3:** Implement, then wire it in `main`. A bind failure is `log.Fatalf` (fail closed: a configured listener that can't bind its own address stops the start).
- [ ] **Step 4:** Run the full Hub gates. Expected: PASS.
- [ ] **Step 5:** Commit `hub: Prometheus listener for usage (HUB_METRICS_ADDR, own registry, no host paths) and the Grafana-link signal`.

---

## Core stream (Tasks 14–16)

### Task 14: Core CI proxy assertions and the live-usage e2e (core, Part 1)

**Files:**
- Create: `.github/ci/usage-proxy-asserts.sh <net> <cid>`; `tests/e2e/e2e_usage.py`.
- Modify:
  - `.github/workflows/ci.yml`: one line calling the script at the end of "Test the socket proxies" and of "The socket proxies on the Podman API", before `compose down -v`; one line in `e2e-instances` and in the Podman leg calling `python3 tests/e2e/e2e_usage.py live`.
  - `tests/e2e/apps/echo/compose.yml` (U18).
  - `CLAUDE.md` (the "never `SYSTEM` / `ALLOW_TOP`" anti-goal and the usage page in the Hub row), `CHANGELOG.md`.

**Interfaces:**
- Consumes: the Hub's `GET /api/usage` (Task 5), through the existing e2e Hub client helpers (`hubop.sh` / the `hubc` pattern).

- [ ] **Step 1: Write `usage-proxy-asserts.sh`** (uses the `hp` wget helper shape). Through `socket-proxy-hub`:
  - `GET /containers/<cid>/stats?stream=false&one-shot=true` → 200 and the body has `memory_stats`;
  - `GET /containers/<cid>/json?size=true` → 200 with `SizeRw`;
  - `GET /images/<image id>/json` → 200;
  - `/system/df`, `/containers/<cid>/top` and `/libpod/containers/stats` → 403.

  It echoes `PASS: stats and size through CONTAINERS; system/df, top and libpod stats stay denied`.
- [ ] **Step 2: Write `e2e_usage.py live`** (`check(name, fn)` cases, pinned clients only, no outside hosts):
  - `usage_lists_echo`: enable the echo fixture, then wait 2 sweeps (≤ 45 s). `GET /api/usage` has the echo group. `web`'s `mem_bytes` > 0 with `limits.mem_bytes` 0; `hold`'s `limits.mem_bytes` 33554432 with `net_rx_bps` `null`.
  - `usage_cpu_second_sample`: `cpu_cores` is a number after the second sweep (Docker, and Podman on the runner).
  - `usage_core_group`: the core group lists `hub` and `traefik`.
  - `usage_csv`: `export.csv?view=apps` header = U22 apps.
  - `usage_people_404`: `people.<domain>/api/usage` → 404.
  - `usage_podman_nulls` (Podman leg only): `blk_read_bps` is a number or `null`, never missing.
- [ ] **Step 3:** Run on the builder in DinD, e.g. `.github/ci/usage-proxy-asserts.sh` against a local compose. Then `bash tests/lint_ci_size.sh && actionlint && shellcheck -S warning .github/ci/usage-proxy-asserts.sh`. Expected: PASS, ci.yml ≤ 450,000 bytes.
- [ ] **Step 4:** Run `gh workflow run ci.yml --ref usage1 -f jobs=build-and-test,e2e-instances,e2e-podman` with your own watcher. Expected: green.
- [ ] **Step 5:** Commit `ci: usage through socket-proxy-hub (no widening) and the live-usage e2e`.

### Task 15: Core storage e2e (core, Part 2)

**Files:**
- Modify: `tests/e2e/e2e_usage.py` (mode `storage`), and `.github/workflows/ci.yml` (one call line in each of the same two jobs).

- [ ] **Step 1: Write `e2e_usage.py storage`:**
  - `measure_instance`: `POST /api/usage/storage/measure {"instance":"echo"}` → 202. Poll `…/storage/op` until `ok` (≤ 3 min). Echo's `data` volume has `alloc_bytes > 0`, and a `layer` item exists for `web` (Docker; Podman: number or `null`).
  - `measure_conflict`: a second POST while running → 409.
  - `measure_all_core`: `{}` → the core list holds `portcullis_hub_data`, and the Disks strip has ≥ 1 filesystem with `total_bytes > 0`.
  - `stop_between_targets`: start `{}`, Stop at once → the record is `stopped` or `ok` (a fast run), and never an error.
  - `audit_actor`: the audit has `usage.measure` with the CI admin's LLDAP username.
  - `no_helper_left`: no container labelled `io.portcullis.hub.helper` remains after 30 s.
- [ ] **Step 2:** Run locally on the builder in DinD. Expected: PASS.
- [ ] **Step 3:** Run `gh workflow run ci.yml --ref usage1 -f jobs=e2e-instances,e2e-podman` with your watcher. Expected: green.
- [ ] **Step 4:** Commit `e2e: storage measurement (volumes, layers, core, stop, audit)`.

### Task 16: Core network, scrape job, dashboard, alerts (core, Part 3)

**Files:**
- Modify:
  - `docker-compose.yml`: network `portcullis-metrics-hub: {internal: true}`; the Hub joins with `aliases: [hub-metrics]` and gets `HUB_METRICS_ADDR: hub-metrics:9100`; Prometheus joins it with the comment "the Hub's usage metrics, the only other member".
  - `docker-compose.podman*.yml`, only if they restate the networks.
  - `monitoring/prometheus/prometheus.yml`: the static job `hub-usage` → `hub-metrics:9100`.
  - `alerts.yml` (three alerts) and `tests/alerts_test.yml` (each fires and each stays quiet).
  - `.github/ci/unit-tests-compose-files-are-valid-generated.sh`: `members("portcullis-metrics-hub") == ["hub", "prometheus"]`, `.networks["portcullis-metrics-hub"].internal == true`, the Hub's alias and `HUB_METRICS_ADDR`, and the Hub's network key set gains it.
  - the monitoring step's `jq` check (dashboard uid `portcullis-usage`).
  - `docs/monitoring.md`, `docs/hardening.md`.
- Create: `monitoring/grafana/dashboards/usage.json` (uid `portcullis-usage`, title "Portcullis usage"). Panels:
  - per-app CPU (`sum by (instance) (rate(portcullis_container_cpu_seconds_total[5m]))`);
  - per-app working set;
  - per-container memory / limit;
  - storage `portcullis_storage_alloc_bytes`;
  - disks `1 - free/total`.

- [ ] **Step 1: Write the failing rule tests** in `tests/alerts_test.yml`:
  - `PortcullisAppMemoryNearLimit` fires after 10 m at 0.95, not at 0.85;
  - `PortcullisDiskNearlyFull` fires after 30 m at 0.08 free;
  - `PortcullisUsageSamplerStale` fires when `time() - portcullis_usage_sampler_last_success_timestamp_seconds > 600` while `up{job="hub-usage"} == 1`.
- [ ] **Step 2:** Run the monitoring step locally (`promtool test rules`). Expected: FAIL (no rules).
- [ ] **Step 3:** Implement the compose, rules, dashboard and checks.
- [ ] **Step 4:** Run `promtool check config`, `check rules`, `test rules`, the compose check script, `bash tests/lint_ci_size.sh` and `actionlint`. Expected: PASS. Then on the builder in DinD, with `--profile monitoring`: `curl` from a container on `portcullis_portcullis-metrics-hub` gets `hub-metrics:9100/metrics` 200 with `portcullis_container_memory_working_set_bytes`, and the same URL from the `portcullis` network fails to connect.
- [ ] **Step 5:** Run `gh workflow run ci.yml --ref usage1 -f jobs=unit-tests,build-and-test` with your watcher. Expected: green.
- [ ] **Step 6:** Commit `monitoring: hub-usage scrape over portcullis-metrics-hub, usage dashboard, three alerts with rule tests`.

---

## Part 4: Kubernetes (Tasks 17–18)

### Task 17: Hub kube backend: pod metrics, inspect fields, Role rule, PVC usage helper (hub)

**Files:**
- Create: `internal/runtime/kube/metrics.go`, `metrics_test.go`.
- Modify:
  - `internal/runtime/kube/backend.go`: `Inspect` gains `OOMKilled` (`lastState.terminated.reason == "OOMKilled"` or the current state's), `RestartCount`, `StartedAt`, `NanoCPUs` (`limits.cpu.MilliValue() * 1e6`) and `NetworkMode` "pod". `LayerSize` and `ImageSize` → `NotMeasuredError{"not measured on Kubernetes"}`.
  - `helpers.go`: `RunFixer` with `Volumes` → `helperPod(HelperVolume, v.Instance, v.Name, true, nil)` with caps exactly `[DAC_OVERRIDE]` (U17), exec `s.Cmd`. `Binds` together with `Volumes` → refused.
  - `testdata/role.yaml`: add `- apiGroups: ["metrics.k8s.io"] resources: ["pods"] verbs: ["get", "list"]`.
  - `guard_test.go` (`TestRoleExact`), `envtest_test.go` (`TestRoleIsEnough` adds a `SelfSubjectAccessReview` for `list pods.metrics.k8s.io` in `portcullis-apps` = allowed, and `list nodes/stats` = denied).
  - `go.mod` (`k8s.io/metrics v0.37.2`).
  - `internal/hub/usage.go`: on `KindKubernetes`, the core group is `Status "not_measured"`, `Why "not measured on Kubernetes yet"`, and `NotShown` is not computed (the Hub sees only its namespace). `UsageIn.NotMeasured` is set from a `NotMeasuredError` of `Stats`.
  - `docs/superpowers/specs/2026-11-13-kubernetes-design.md` §4 Role list (the one added rule).

**Interfaces:**
- Consumes: `runtime.UnitStats.CPUCores` / `MemWorkingSet`, `NotMeasuredError` (Task 2).
- Produces: `(b *Backend) Stats(ctx, id string) (runtime.UnitStats, error)`, reading `b.metricsList(ctx)` (GVR `metrics.k8s.io/v1beta1 pods`, namespace `b.cfg.Namespace`, cached 10 s, U8). 404/503 → `NotMeasuredError{"the cluster has no metrics API (metrics-server)"}`; 403 → `NotMeasuredError{"the Hub's Role can't read pod metrics"}`; a pod/container not in the list → `NotMeasuredError{"no metrics yet"}`. `Read` = the item's `timestamp`. PIDs, network and block IO are `nil`.

- [ ] **Step 1: Write the failing tests** (dynamic fake client):
  - `TestKubeStatsFromPodMetrics`: `cpu: 250m`, `memory: 64Mi` → `CPUCores` 0.25, `MemWorkingSet` 67108864, `Pids` nil.
  - `TestKubeStatsOneListPerSweep`: 10 `Stats` calls within 10 s → 1 list action.
  - `TestKubeStatsNoMetricsAPI`: 404 → `NotMeasuredError` with the exact text; 503 too.
  - `TestKubeInspectOOMAndLimits`: `lastState.terminated.reason OOMKilled`, `restartCount 2`, `limits.cpu 500m` → `OOMKilled`, 2, `NanoCPUs 5e8`.
  - `TestKubeRunFixerVolume`: the created pod has label `portcullis.io/helper=volume`, PVC `ReadOnly: true` at `/vol`, caps `[DAC_OVERRIDE]`, `ReadOnlyRootFilesystem`, and the exec argv = `s.Cmd`. Binds + Volumes → error.
  - `TestRoleExact`: updated to the new rule; one verb more or less fails.
  - `internal/hub` `TestUsageKubeCoreNotMeasured`.
- [ ] **Step 2:** Run `go test ./internal/runtime/kube/ ./internal/hub/ -run 'Kube|RoleExact'`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `go test -race ./...`. Then on the builder: `KUBEBUILDER_ASSETS=… go test -tags envtest -run 'RoleIsEnough|Admission' ./internal/runtime/kube/`. Expected: PASS. That includes the existing admission vectors: the volume helper pod with `DAC_OVERRIDE` only and a read-only PVC is admitted.
- [ ] **Step 5:** Commit `kube: pod metrics (metrics.k8s.io, cached list), OOM/restart/limit inspect fields, read-only PVC usage helper, Role rule`.

### Task 18: Core chart Role copy and e2e-k3s usage asserts (core)

**Files:**
- Modify: `charts/portcullis/files/hub-role.yaml` (a byte copy of Task 17's `role.yaml`; `.github/ci/unit-tests-kube-static.sh` already compares them), `.github/ci/e2e-k3s-assert.sh` (or `tests/e2e/e2e_k3s.py`, whichever holds the instance checks on main).

- [ ] **Step 1:** Copy the Role, then run `bash .github/ci/unit-tests-kube-static.sh`. Expected: PASS (byte-equal).
- [ ] **Step 2: Add e2e-k3s checks:**
  - `usage_overview` (through the MCP client already used there, or `GET /api/usage`) lists the echo pods with `cpu_cores` and `mem_bytes` numbers within 2 min (k3s bundles metrics-server);
  - `pids` is `null`;
  - the core group `status` is `not_measured` with "not measured on Kubernetes yet";
  - `POST …/storage/measure {"instance":"echo"}` → `ok` and `alloc_bytes > 0` on its PVC;
  - `kubectl auth can-i list nodes/stats --as=system:serviceaccount:portcullis:portcullis-hub` → `no`.
- [ ] **Step 3:** Run `.github/ci/e2e-k3s-local.sh` on the builder (one cluster at a time). Expected: PASS.
- [ ] **Step 4:** Run `gh workflow run ci.yml --ref usage1 -f jobs=unit-tests,e2e-k3s` with your watcher. Expected: green.
- [ ] **Step 5:** Commit `k3s: Hub Role reads pod metrics; e2e-k3s usage and storage asserts`.

---

## Live check and mainline (Tasks 19–20)

### Task 19: Test server (operational)

- [ ] **Step 1:** On the test server (always `ACME_STAGING=true`: `config apply` + `up` after init), deploy the `usage1` images built by CI and run `./portcullis status`. Expected: healthy.
- [ ] **Step 2:** As a test admin (never the LLDAP `admin` user), open Usage:
  - By app / By container show every instance and the core group, the instance tab shows its sparklines, and the CSV downloads;
  - Measure now finishes within the budget, and Stop works mid-run;
  - with `--profile monitoring`, Grafana's "Portcullis usage" dashboard has data after 5 min and the "History in Grafana ↗" link appears.

  Record the numbers in the ledger only (no host names in repos).

### Task 20: Mainline (all repos)

- [ ] **Step 1:** Run the full CI on `usage1`: Hub `build.yml`; core `ci.yml` (all jobs). Expected: green.
- [ ] **Step 2:** Merge in order docs → Hub (wait for `edge`) → core, each through a detached worktree:

  ```bash
  git worktree add --detach /tmp/merge-<repo> origin/main
  git merge --no-ff origin/usage1 -m "merge usage1: resource usage page"
  git push origin HEAD:main
  git worktree remove /tmp/merge-<repo>
  ```

  Before core's merge, dispatch Hub `build.yml` on `main` with `-f compare_ref=usage1`.
- [ ] **Step 3:** Re-run the templates repo's CI on `main`. Expected: green with no change (U21).
- [ ] **Step 4:** Delete every `usage1` branch (local and remote) and the `wt-usage1` worktrees (memory: branches mainlined).

## Self-review

- **Spec coverage:**

  | Spec | Task |
  |---|---|
  | §2 goals 1, 3 | 4, 5, 7 |
  | §2 goal 2 | 8, 9, 12 |
  | §2 goal 4 | 2, 14 |
  | §2 goal 5 | 8, 9 |
  | §2 goal 6 | 6, 11 |
  | §2 goal 7 | 5, 10 |
  | §2 goal 8 | 13, 16 |
  | §2 goal 9 | 2, 14, 17, 18 |
  | §2 anti-goals | 2 (`checkRunSpec`, env), 4 (`NeverKeepsEnv`), 5 (`ReadsNeverReachEngine`), 8 (read-only `/vol`), 14 (proxy 403s), 17 (`can-i nodes/stats`) |
  | §3 | U2, 2, 4, 9, 13 |
  | §4.1–4.4 | 2, 3, 4 |
  | §5.1–5.3 | 8, 9 |
  | §6 | 7, 12 |
  | §7 | 5 (`HubListenerOnly`), 9 (audit) |
  | §8.1 | 5, 9, 10 |
  | §8.2 | 5, 10 |
  | §9 | 6, 11 |
  | §10 | 2, 17, 18 |
  | §11 | 13, 16 |
  | §12 | 2–18 |
  | §13 | 1, 4 (CLAUDE.md), 14 (core CLAUDE.md), 16 (core docs), 17 (kube spec) |
  | §14 | the task order |
  | §15 | defaults (header) |

- **Type consistency:** these names are used identically across tasks:
  - `runtime.UnitStats`, `NotMeasuredError`, `VolumeMount`, `FixerSpec.Volumes`;
  - `usage.Sample`, `usage.Total`, `usage.CSVCell`;
  - `UsageView`, `UsageGroup`, `UsageContainer`, `StorageGroup`, `StorageItem`, `StorageView`;
  - `OpUsageMeasure`, `opKeyUsage`, `StartUsageMeasure`, `StopUsageMeasure`;
  - `usageSnapshot`, `usageDoctorIn`, `storageDoctorIn`;
  - `UsageIn`, `StorageIn`, `TabUsage`;
  - `adminUsage`, `usageNoToolRoutes`;
  - `metricsBindAddr`, `UsageCollector`, `MetricsScrapedRecently`.
- **Proportion:** tasks give signatures, values and test names. Bodies are left to the implementer, except the CSV headers and copy the spec fixes.
- **Spec defects found (fixed by the rulings above):**
  - §4.1 `ContainerStatsOptions{OneShot: true}` doesn't exist in SDK v0.6.2 (Task 2);
  - §4.1 decoding into `container.StatsResponse` loses "absent" (U3);
  - §3 a `Usage(UsageSpec)` method while `FixerSpec` can't mount a named volume (U2);
  - §8.2 `export.csv` in `noToolRoutes`, which a test pins to G15 (U11);
  - §5.3 a Stop for `_usage` with no route (the existing Stop is instance-only) (U10);
  - §13 "§11.12" (U19);
  - §12 the e2e "a limit" on a fixture without one (U18);
  - §10 a Kubernetes helper with `DAC_READ_SEARCH` on a PVC, which the admission policy refuses for the volume kind (U17);
  - §11 the CPU counter series, which can't exist on Kubernetes (U9).
