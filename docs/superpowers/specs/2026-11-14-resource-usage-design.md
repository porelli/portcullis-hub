# Resource usage: storage, memory and CPU per app and per container (design)

Status: written by the assistant for the user's request "we should also have a page that show how much storage, memory and CPU each app is using, possibly allowing both aggregated and per-container" (the user's words). No interruptions were wanted, so the assistant made every open decision. Each one is marked **(assistant's call)**. Open questions are in §15, each with a default that work proceeds on.

Read against Hub `origin/main` `1cfc276`, core `origin/main` `225d078`, and the Kubernetes plan on `kube1` (`docs/superpowers/plans/2026-11-14-kubernetes.md`).

## 1. Where things stand (2026-11-14)

- **Engine access.** The Hub talks to the engine only through `socket-proxy-hub` (`DOCKER_HOST=tcp://socket-proxy-hub:2375`, linuxserver/socket-proxy 3.4.7 pinned by digest). Its sections are `CONTAINERS`, `IMAGES`, `NETWORKS`, `VOLUMES`, `EXEC`, `EVENTS`, `INFO`, `VERSION`, `PING`, `ALLOW_LOGS`, `ALLOW_ARCHIVE`, with `POST=1`. `SYSTEM` (`/system/df`, prune) is denied, and so are `/libpod/…` and `/build`. Core CI ("Test the socket proxies") checks the denials on both runtimes.
- **The stats endpoint is already allowed.** In the proxy's `haproxy.cfg`, `GET /containers/{id}/stats` matches the generic `^(/v[\d.]+)?/containers` rule (`CONTAINERS=1`). The only per-subpath denials are `archive`, `change`, `export`, `logs`, `top`, `pause` and `exec`, each with its own `ALLOW_*`. So `GET /containers/{id}/stats` and `GET /containers/{id}/json?size=true` work today without any flag change. The Hub never calls them yet.
- **The Hub's engine client** (`internal/docker`, moby SDK) covers list, inspect, logs, exec, events, volumes, the never-started volume helper (archive endpoints) and the one started helper, the folder fixer (`hub folderfix <mode>`: the Hub's own image by image ID, `NetworkMode none`, read-only rootfs, `CapDrop ALL` plus per-mode caps, pids 16, 256 MiB).
- **The doctor** (`internal/doctor`, `internal/hub/doctorscan.go`) runs read-only fixer scans of every shared folder and every multi-use or written hand-typed host path: on demand, after each folder apply, and daily (`RunDoctorScans`, 24 h; caps `scanMaxEntries` 2,000,000, `scanMaxTime` 10 min, run budget 3 h). Results are cached in `<data>/doctor/scans.json`. The scan report already has `free_bytes` and `total_bytes` (statfs) and entry counts, but no byte total. `free_space` judges a template's declared `checks: free_space` minimum. Nothing judges memory, CPU or a near-full disk in general.
- **Rootless Podman** (`HUB_CONTAINER_RUNTIME=podman`) serves the same Docker-compatible API through the same proxies. `init` requires cgroups v2 with `memory` and `pids` delegated to `user@<uid>.service`. `cpu` is delegated by systemd's default too, `io` usually isn't.
- **Monitoring** (core, compose profile `monitoring`): Prometheus v3.16 (`--storage.tsdb.retention.time=${PROMETHEUS_RETENTION:-30d}`, scrape 30 s) scrapes Traefik, Vault, group-gate, Keycloak, Grafana, `wg` (over its own internal network `portcullis-metrics-wg`), the textfile exporter (backup age and size, cert expiry, `portcullis status`), plus blackbox probes. Nothing scrapes container resources: there is no cAdvisor and no node-exporter host collector (the textfile exporter runs `--collector.disable-defaults` with no host mounts). Grafana is at `metrics.<domain>`, `lldap_admin` only.
- **Backups**: core's `backup.sh` measures its own archives with `du -sk`, and the Hub's instance backups check free space on the data volume (`needFree`) and sum staged files (`dirSize`). Neither measures live volumes.
- **UI**: top-level tabs Apps · Marketplace · Audit log · Doctor · Settings · People ↗. An instance page (`#apps/<id>/<tab>`) has Overview, Settings, Groups, File sharing, Logs, Backups, AI, VPN, Expert, Delete.
- **Kubernetes** (`kube1`, in progress): `internal/runtime.Instances` (Task 2) abstracts the engine. The Hub's ServiceAccount has exactly one Role in `portcullis-apps` (K2, pinned by `TestRoleExact` and a byte copy in core), with nothing cluster-scoped and nothing in the core namespace `portcullis`. Helper pods run the Hub's own image (`hub volcopy`, `hub folderfix` through exec), with volumes mounted at `/vol`. k3s is installed with `--disable=traefik` only, so its bundled metrics-server is on.

## 2. Goals, non-goals, anti-goals

**Goals**
1. A **Usage** page in the Hub that shows CPU, memory, network, block IO and PIDs for each app instance aggregated, and for each container on its own, plus the core services as a separate group.
2. **Storage** per app: its named volumes, its bind mounts and its containers' writable layers, plus shared folders (once, not per app) and the core volumes, with the free space of each filesystem underneath.
3. A **Usage** tab on each instance page, showing the same data for that instance alone.
4. Live numbers from the engine with no new container, and **no change to the socket proxy's flags**.
5. Bounded, cached, scheduled storage measurement that can never stall the Hub or the disk.
6. Doctor checks for a near-full disk, an app near its memory limit, OOM kills and a sampler that has stopped.
7. A JSON API, a CSV export and read-only MCP tools.
8. Optional history in the existing Prometheus/Grafana when the monitoring profile is on.
9. The same page on Docker and rootless Podman first, then Kubernetes (§10).

**Non-goals (v1)**
- Per-app admins seeing their own app's usage (§7). Parked.
- Setting or changing limits from this page. Limits stay in templates, settings and the Expert override.
- Per-process detail inside a container (`/top` stays denied by the proxy).
- Billing, quotas, per-person usage, or usage inside a shared folder per person.
- Growth forecasts ("full in 12 days"). Parked.
- Host-wide metrics beyond what `/info` gives (core count, total memory): no host load, swap or per-disk IO.
- Containers that don't belong to Portcullis. They're counted, never listed (§4.4).
- Image storage totals. Images are listed per app, but not added to app totals, because instances share them.
- Long history inside the Hub. The Hub keeps one hour in memory. Longer history is Prometheus's job.
- Multi-server workers (multi-server spec). Each worker would report its own usage later.

**Anti-goals (never)**
- **Never widen `socket-proxy-hub`.** No new flag, and in particular never `SYSTEM` (`/system/df`), `ALLOW_TOP` or any `LIBPOD_*`. The page uses only `GET` endpoints that `CONTAINERS`, `VOLUMES`, `IMAGES` and `INFO` already allow.
- **Never mount the engine socket anywhere new.** No cAdvisor, no node-exporter with host mounts, no third socket proxy.
- **Never let a page view or an MCP call reach the engine.** Reads come from the sampler's cache only, so the engine load is the sampler's, whoever is looking.
- **Never show a missing number as zero.** An unknown value is `null` in the API and "not measured" on the page, with the reason.
- **Never copy secrets out of an inspect.** Container inspect answers carry `Config.Env`. The sampler copies only named fields (§4.2) and never logs, stores or returns a raw engine body.
- **Never read file contents to measure storage.** The measuring helper only calls `fstatat` and `getdents`.

## 3. Architecture

```
               socket-proxy-hub (unchanged flags)
                        │  GET /containers/json, /containers/{id}/stats?stream=false&one-shot=true,
                        │      /containers/{id}/json[?size=true], /volumes, /images/{id}/json, /info
                        ▼
   ┌────────────── Hub ──────────────────────────────────────────────┐
   │ usage sampler (15 s) ──► in-memory rings (1 h) ──► /api/usage…  │──► Usage page, instance Usage tab, MCP, CSV
   │ storage measurer (daily + on demand) ──► <data>/usage/storage.json │
   │        └─ hub folderfix usage  (helper, network none, ro mounts)    │
   │ doctor checks judge the caches (never run anything)            │
   │ metrics listener (optional, Part 3) ── portcullis-metrics-hub ──┼──► Prometheus ──► Grafana
   └─────────────────────────────────────────────────────────────────┘
```

Three pieces, all inside the Hub binary (**assistant's call**: no new container):

1. **The usage sampler** (`internal/hub/usage.go`). A goroutine started by `main` beside `RunDoctorScans`. It samples live stats every 15 s and keeps a ring per container.
2. **The storage measurer** (`internal/hub/usage_storage.go`). Scheduled and on-demand runs of a new read-only fixer mode, `hub folderfix usage`, cached on disk.
3. **The metrics listener** (`internal/httpapi/metricslistener.go`, Part 3). Prometheus exposition of the sampler's cache, on a dedicated internal network.

**Why not cAdvisor** (**assistant's call**). cAdvisor needs the engine socket or `/var/lib/docker`, `/sys`, `/dev/disk` and usually `privileged`. That breaks the core rule that only the two proxies mount the socket, and it would be the most privileged container in the stack. Under rootless Podman it also needs the operator's user cgroup tree. The engine's stats API already gives everything the page needs through the existing proxy.

**Why not the textfile exporter** (**assistant's call**). It would need the Hub to write into `./monitoring/textfile`, which the Hub only sees through the read-only `/project` mount. A new writable bind for it would be a second path into core's tree. The Hub's own metrics listener follows the existing `wg` pattern instead (its own network, its own address).

**Engine interface.** If `internal/runtime.Instances` (kube plan Task 2) is on main when this is built, add `Stats(ctx, id string) (UnitStats, error)` and `Usage(ctx, spec UsageSpec) (*UsageReport, error)` to it, the docker backend wrapping the SDK calls. Otherwise add them to `internal/docker`, and the kube rebase moves them (**assistant's call**). `runtimetest.Fake` gets both.

## 4. Live data: the sampler

### 4.1 Endpoints and calls

Every interval (15 s, **assistant's call**: cheap at home-lab scale, and smooth enough for CPU rates):

1. `GET /containers/json?all=1` (the existing `ListContainers` wrapper).
2. For each running container in scope (§4.4), up to 4 at once, with a 5 s timeout each and a 12 s budget for the sweep: `GET /containers/{id}/stats?stream=false&one-shot=true` (`client.ContainerStats(ctx, id, ContainerStatsOptions{Stream: false, OneShot: true})`). The response is decoded into `container.StatsResponse`, and only the fields in §4.2 are kept.
3. Every 5 min, and once when a container is first seen: `GET /containers/{id}/json` (inspect) for limits and OOM state, copied field by field into `limitsOf` (`HostConfig.Memory`, `NanoCpus`, `CpuQuota`/`CpuPeriod`, `PidsLimit`, `NetworkMode`, `State.OOMKilled`, `RestartCount`, `State.StartedAt`, `Mounts[]` type/name/source/destination/RW). Everything else in the answer is dropped at once.
4. Once at start and every hour: `GET /info` for `NCPU` and `MemTotal`.

CPU is never taken from `precpu_stats` (**assistant's call**). With `one-shot` Docker leaves it empty, and Podman fills it differently. The Hub computes CPU from its own two consecutive samples instead: `cores = Δcpu_usage.total_usage (ns) / Δwall (ns)`. That works identically on both runtimes, and the call never waits the ~1 s that `stream=false` without `one-shot` costs on Docker. Podman's compat handler ignores `one-shot` where unsupported and still answers one sample. Core CI covers both runtimes (§12).

When the engine guard refuses (`ErrEngineRefused`, contract §6), the sampler sleeps and the page shows the guard's message (`RefusedError.Message()`), never an engine error text.

### 4.2 What is kept per container and sample

| Field | Source | Notes |
|---|---|---|
| `cpu_cores` | Δ`cpu_stats.cpu_usage.total_usage` / Δt | `null` on the first sample, after a restart (the counter went down), or when the counter is absent (cpu controller not delegated, rootless) |
| `mem_bytes` | `memory_stats.usage` − `stats.inactive_file` (cgroup v2; `total_inactive_file` v1) | The docker CLI's "working set" formula. `null` if `usage` is absent |
| `mem_limit_bytes` | inspect `HostConfig.Memory` | `0` = no limit: shown against host `MemTotal` and flagged "no limit" |
| `cpu_limit_cores` | inspect `NanoCpus/1e9`, else `CpuQuota/CpuPeriod` | `null` = no limit: shown against host `NCPU` |
| `pids` / `pids_limit` | `pids_stats.current` / inspect `PidsLimit` | Core sets `pids_limit` on every service |
| `net_rx_bps` / `net_tx_bps` | Δ sum over `networks{}` | `null` for `network_mode: container:`/`service:` (it shares another's netns, so it would double count) and for `host` |
| `blk_read_bps` / `blk_write_bps` | Δ sum of `blkio_stats.io_service_bytes_recursive` Read/Write | Often `null` on rootless Podman (`io` not delegated) |
| `oom_killed`, `restarts`, `started_at` | inspect | For the doctor |

Rates are computed between consecutive samples of the same container start (`started_at` unchanged). The ring holds 240 samples (1 h at 15 s) per container, in memory only, and is lost at Hub restart (**assistant's call**: history beyond the hour is Prometheus's job). Bound: at most 256 containers in scope (like `maxRuntimeContainers`). Above that, the rest are counted as "not measured: over the 256-container limit". About 4 MiB at worst.

Concurrency: the sampler has its own `sync.RWMutex`. It never takes `Hub.mu` across engine calls (CLAUDE.md rule). It reads the instance list under `mu`, copies it, and releases `mu` before calling the engine.

### 4.3 Aggregation

- **Per app instance**: the containers of compose project `portcullis-<id>` (label `com.docker.compose.project`), keyed by instance id, named with the instance's display name, the template id alongside. One-off containers (`com.docker.compose.oneoff=True`) are included while they run.
- **Totals**: `cpu_cores`, `mem_bytes`, `pids`, net and block rates are sums. Limits are summed only when every container has one, else the total limit is "partly unlimited". A sum that includes a `null` is shown as a lower bound ("≥ 1.2 GiB") with `partial: true`, never as an exact figure.
- **CPU display** (**assistant's call**): cores used ("0.35 CPU"), with the percentage of the CPU limit when there is one, else of the host's `NCPU`. That avoids the "350 %" of `docker stats`, which people misread.
- **Memory display**: working set / limit as a bar and a percentage, coloured at 80 % and 90 %.
- **Status**: running / stopped / restarting from the list, so a stopped app shows "stopped" rather than zeros.

### 4.4 Scope: what is shown

- **Apps**: every container of a `portcullis-<id>` project with a known instance id. A project without an instance (a leftover) is listed under "Unknown projects" by project name, since reconcile already reports it as drift.
- **Core**: compose project `portcullis` (`com.docker.compose.service` = the service name), the Hub included. It is a separate group, always listed last, with its own total (**assistant's call**). Hub helper containers (`io.portcullis.hub.helper`) are shown in the core group as "Hub helpers (transient)" when running, never in an app total.
- **Other containers** on the same engine: only their count ("3 other containers on this engine are not shown"), never names, images or numbers (**assistant's call**: they may be unrelated to Portcullis and to this admin's remit). They are also never sampled, so they cost nothing.

## 5. Storage

### 5.1 What is measured

| Item | Belongs to | How |
|---|---|---|
| Named volumes of `portcullis-<id>` (volume label `com.docker.compose.project`) | the app | `hub folderfix usage` with the volume mounted read-only at `/vol` |
| Bind mounts of the app's containers whose source is a hand-typed path under `HUB_OVERRIDE_BIND_ROOTS` and not inside a shared folder | the app | the same mode, with a read-only bind at `/vol` |
| Bind mounts into a **shared folder** | listed on the app with the folder's name, its size **not** added to the app's total | the folder's own figure (below) |
| Template support files (`./templates/<id>/`) and `appfiles` | the app | not measured: they are small and Hub-written. Shown as "Hub-managed files" with no size |
| Container writable layers | the app | `GET /containers/{id}/json?size=true` → `SizeRw`, once per storage run, 10 s per container |
| Images | the app (listed) | `GET /images/{id}/json` → `Size`, listed per app with "shared, not in total" |
| **Shared folders** | their own section, with the apps that use them | the doctor's existing scans, which gain `alloc_bytes` (§5.2) |
| Core named volumes (`postgres_data`, `vault_data`, `lldap_data`, `hub_data`, `prometheus_data`, …) | the core group | `hub folderfix usage`, read-only |
| Filesystems underneath all of them | a "Disks" strip at the top of the Storage view | `free_bytes`/`total_bytes` from every report, grouped by `dev`, plus a direct `statfs` of the Hub's `/data` |

Measuring core volumes adds no new kind of access (**assistant's call**). The Hub's proxy already allows the archive and exec endpoints on every container (contract §6 says the same of `ALLOW_ARCHIVE`), and the usage mode reads metadata only. `hub_secrets` is measured too: it is the Hub's own volume, and the figure holds no hashes.

### 5.2 The `usage` fixer mode (**assistant's call**: reuse the fixer, not a new helper)

`hub folderfix usage --root /vol --max-entries N --max-time D`, added to `internal/folderfix` beside `scan`. It reuses the fixer's walk: `O_PATH|O_NOFOLLOW|O_DIRECTORY` directory fds, no symlink following, mount points counted and not crossed, no file ever opened for reading. Report (one JSON line, decoded strictly like today's):

```json
{"version":1,"mode":"usage","root":"/vol","fs_type":"ext4","alloc_bytes":0,"apparent_bytes":0,
 "entries":0,"dirs":0,"files":0,"hard_links":{"n":0},"mount_points":{"n":0},"failed":{"n":0},
 "free_bytes":0,"total_bytes":0,"partial":false,"partial_reason":""}
```

- `alloc_bytes` = Σ `st_blocks × 512`, which is what `du` reports and what fills the disk. Hard-linked inodes (`nlink > 1`) are counted once, using a `(dev, ino)` set capped at 1,000,000 entries; past the cap the report is `partial` with reason `hard_links`. `apparent_bytes` = Σ `st_size`, shown on hover.
- `scan` gains the same `alloc_bytes`/`apparent_bytes` (one extra add per entry), so shared folders and doctor-scanned paths need no second walk (**assistant's call**).
- Isolation: as the fixer's `scan` today. `User 0:0`, `NetworkMode none`, read-only rootfs, `no-new-privileges`, `CapDrop ALL` + `CapAdd DAC_READ_SEARCH` only, pids 16, memory 256 MiB, `Healthcheck NONE`, `LogConfig json-file`, label `io.portcullis.hub.helper=usage:<target>`, removed always. Mounts: exactly one, at `/vol` (never at an image path, the Podman `domains_data` lesson), `ReadOnly: true`. A named volume is mounted `Type: volume` with `VolumeOptions.NoCopy: true` (never copy-up), and a bind `Type: bind` (never the `Binds` string, never `CreateMountpoint`). The doctor's Docker-root rule applies to binds: a source at or under the engine's root dirs is refused.
- The helper lowers its own IO priority to the idle class (`ioprio_set(IOPRIO_WHO_PROCESS, 0, IOPRIO_CLASS_IDLE)`, allowed without a capability), best effort. A failure is ignored and noted as `io_idle: false` in the report.
- The existing refusals apply unchanged (`userns` daemons, rootless Docker, a Podman `uid_map` of the wrong shape → 503, explain-only). The measurement reads only `st_blocks`, so owners don't matter, but one code path is simpler and stricter than two.
- Proxy flags: none change. Create, start, wait, logs and remove are what the fixer already uses.

### 5.3 Schedule, caching, timeouts (**assistant's call** for every number)

- **Cache**: `<data>/usage/storage.json`, 0600, at most 4 MiB and 2,048 entries. A corrupt or oversized file is dropped and means "never measured". Each entry: target (volume name or host path), kind, owner (instance id / `core` / folder id), report summary, `measured_at`, `duration_ms`, `error` (fixed text).
- **Schedule**: one run 10 min after Hub start when the cache is older than 24 h, then every 24 h (`RunUsageStorage(ctx, 24*time.Hour)`, started by `main` like `RunDoctorScans`). The two daily loops never overlap: the measurer waits while a doctor scan run holds the disk (a shared `diskRunMu`, held per target, not across the run).
- **On demand**: "Measure now" (whole run) and "Measure" on a single app (its targets only). `POST /api/usage/storage/measure` `{"instance": "<id>"}` or `{}` → 202 `{op_id, op, instance, poll}` under op key `_usage`, one run at a time (409 while running), audited `usage.measure` with the actor (LLDAP username) and the scope. The Stop button of the operation-progress panel ends a run between targets (`stopCtx`).
- **Caps**: per target `--max-entries 2,000,000` and `--max-time 2m`. The run budget is 1 h. Targets are measured one after the other, never in parallel. A target that hits a cap shows "≥ 120 GiB (stopped after 2 min)". A target left when the budget runs out keeps its previous figure with its old date. Helper wall timeout: `max-time + 30 s`, after which it is killed and the run records "timed out".
- **Freshness**: every figure on the page carries its age ("measured 3 h ago"). A figure older than 48 h is dimmed.
- **Writable layers and images**: in the same run, after the volumes, each `size=true` inspect bounded by 10 s.

## 6. The page

### 6.1 Where (**assistant's call**)

- A new top-level tab **Usage** between Doctor and Settings (`data-tab="usage"`, `web/usage.js`, added to `web/web.go`'s embed line). Hash routes: `#usage` (= `#usage/apps`), `#usage/containers`, `#usage/storage`.
- A new instance page tab **Usage** (`PAGE_TABS` after Logs: `['usage', 'Usage']`, `#apps/<id>/usage`) that shows that instance's containers, its storage rows and the 1 h sparklines.
- The Apps cards are unchanged. No numbers there, so the grid stays light.

### 6.2 Views

**By app** (the default, aggregated): one row per instance, sortable by any column. Columns: App (name, template, status), CPU, Memory (bar against limit), Net ↓/↑, Disk IO r/w, PIDs, Storage (cached total + age), a 1 h sparkline of memory. A row expands in place to its containers (service, container number, the same columns). The **Core** group sits below as one collapsible row with its own total, expanded to its services. Header strip: host CPUs and memory, the summed app and core usage, "sampled 4 s ago", and the not-shown count (§4.4).

**By container** (flat): every in-scope container in one table, with a filter box (app, service) and the same columns plus limits as numbers. This is the per-container view the user asked for.

**Storage**: a "Disks" strip (each filesystem: used / total, free, coloured at 90 % and 97 %, which apps' data lives there), then per app (volumes, binds, writable layers, images listed with "shared"), then shared folders (size, the apps using them, last scan date, "partial" if capped), then core volumes. Buttons "Measure now" and per-app "Measure" (§5.3). A link "History in Grafana ↗" to `metrics.<domain>` when the monitoring profile is on (Part 3). The Hub knows it is on because its metrics listener was scraped in the last 5 min. Otherwise there is no link (**assistant's call**: observed, not configured, so the link never points at a Grafana that isn't running).

**Rendering rules** (Hub CLAUDE.md): vanilla JS, `escapeHtml` on every value, `data-*` attributes plus delegated listeners, no inline handlers. Sparklines are inline SVG built from numbers only. The page polls `GET /api/usage` every 15 s while visible (`document.visibilityState`) and stops when hidden. Units via binary sizes (KiB, MiB, GiB) to match `docker/go-units` on the server.

## 7. Who may see it (**assistant's call**: the strictest that's still useful)

- **Hub administrators only.** Every route is on the Hub listener (`HUB_LISTEN_ADDR`, `hub.<domain>`, which core already restricts to `lldap_admin`). None is on the people listener or the people MCP scope. `TestUsageRoutesHubListenerOnly` checks that the people listener answers 404.
- **App admins (`admin_<id>`) don't get it in v1.** They have no Hub access today, and adding a people-side view would be a new exposure (container names, limits, host totals) on the listener every signed-in person reaches. Parked (§15 Q1): a later delegated permission `view_usage` in `directory.yaml`, scoped to the instances whose admin group the person is in, on `people.<domain>`, showing their app only and never the host totals or other apps.
- Reads are not audited (like every other Hub GET). "Measure now" is audited (§5.3).

## 8. API, export, MCP

### 8.1 Routes (Hub listener, admins)

| Route | Answer |
|---|---|
| `GET /api/usage` | `{sampled_at, interval_s, stale, engine: {runtime, verified, why}, host: {cpus, memory_bytes}, apps: [Group], core: Group, unknown_projects: [Group], not_shown: n, over_limit: n}`. `Group` = `{instance, template, name, status, totals: Sample, partial, containers: [Container]}`. `Container` = `{id12, service, number, state, sample: Sample, limits: {mem_bytes, cpu_cores, pids}, oom_killed, restarts}`. `Sample` = §4.2 fields, each a number or `null`. No history. |
| `GET /api/usage/instances/{id}` | One `Group` with `history: {t: [...], cpu_cores: {...per container}, mem_bytes: {...}}` (the 1 h ring) and that instance's `storage`. 404 for an unknown instance. |
| `GET /api/usage/storage` | `{measured_at, running_op, disks: [...], apps: [...], folders: [...], core: [...]}` from the cache. |
| `POST /api/usage/storage/measure` | 202 op (§5.3). Body strict, ≤ 1 KiB, optional `instance`. |
| `GET /api/usage/storage/op` | The `_usage` op record (404 when none). |
| `GET /api/usage/export.csv?view=apps\|containers\|storage` | `text/csv; charset=utf-8`, `Content-Disposition: attachment; filename="portcullis-usage-<view>-<UTC timestamp>.csv"`, `Cache-Control: no-store`. Raw numbers (bytes, cores, bytes/s), an empty cell for `null`, a `measured_at` column. Every text cell starting with `=`, `+`, `-`, `@`, tab or CR is prefixed with `'` (formula injection). Written with `encoding/csv`. |

All answers are `no-store` and computed from the caches only (anti-goal 3). Errors are fixed text: a stats failure is `"stats unavailable"` per container, with the detail in the Hub log without any engine body. Engine refusal is a 200 with `engine.verified: false` and `why`, so the page can say why. The data routes don't answer 503, because a stale cache is still worth showing with its age (**assistant's call**).

The JSON routes are the API (**assistant's call**: no separate "JSON export" route; the CSV is the file export). Field names are part of the contract (§13).

### 8.2 MCP tools (admin scope, contract §15.10 conventions, `internal/httpapi/mcptools_usage.go`, `registerUsageTools`)

| Tool | Class | Twin | Description (short form) |
|---|---|---|---|
| `usage_overview` | R | `GET /api/usage` | Every app's CPU, memory, network, disk IO and PIDs, aggregated per app with its containers, plus the core group. Live, from the Hub's last sample. |
| `usage_instance` | R | `GET /api/usage/instances/{id}` | One instance's containers, last hour and storage. Args `{id}` (the `{id}` rule of the instance routes, else 404). |
| `usage_storage` | R | `GET /api/usage/storage` | Disk use per app volume, bind, shared folder and core volume, and each filesystem's free space, as last measured (with dates). |
| `usage_storage_measure` | W | `POST /api/usage/storage/measure` | Measure storage now (all, or `instance`) in the background: answers `{op_id, op, instance, poll}`; see `usage_storage_op`. Audited `usage.measure`, attributed via ai and the client. |
| `usage_storage_op` | R | `GET /api/usage/storage/op` | The last storage measurement's op record. |

- Each Run calls the same Server method as its HTTP twin (never an HTTP loopback). Answers go through the global redactor, then clip at 1 MiB (G40).
- `GET /api/usage/export.csv` goes in `noToolRoutes` with the reason "a file download; usage_overview and usage_storage answer the same data". The parity test (`mcp_parity_test.go`) enforces both.
- No D-class tool: nothing here changes data or access. `usage_storage_measure` is W, not D (**assistant's call**): it is read-only on disk and bounded, like `doctor_scan`, which is W.

## 9. Doctor checks (contract §14.5; `internal/doctor/checks_usage.go`)

They judge `Inputs.Usage` (a snapshot of the sampler's rings and limits) and `Inputs.Storage` (the storage cache plus the scan reports' `free_bytes`/`total_bytes`). They are cheap and never run anything, like the disk checks. Thresholds are constants (**assistant's call**; §15 Q3 parks making them settings).

| Kind | Severity | When | Fix |
|---|---|---|---|
| `disk_nearly_full` | Warning at < 10 % free or < 5 GiB free; Problem at < 3 % or < 1 GiB | Per filesystem (dedup by `dev`): the Hub's `/data`, each measured volume's and bind's filesystem, each shared folder's | Explain: which apps and folders have data there (largest first), "free space or move the data". Link to Storage |
| `memory_near_limit` | Warning | An app container's working set ≥ 90 % of a non-zero limit in every sample of the last 10 min (≥ 30 samples) | Explain: raise the limit (the instance's setting if the template has one, else the Expert override), or look at the app's Logs. Link to the instance's Usage tab |
| `oom_killed` | Warning | `State.OOMKilled` is true for the container's current start, or `restarts` rose by ≥ 3 in the last hour with an OOM kill seen | Explain, as above |
| `pids_near_limit` | Warning | `pids` ≥ 90 % of `pids_limit` for 10 min | Explain |
| `usage_not_measured` | Info | The sampler has had no successful sweep for 5 min while the engine is verified, or (Kubernetes) the metrics API is missing | Explain: the reason (fixed text) |
| `storage_measure_partial` | Info | A target hit a cap in the last run | Explain: "the figure is a lower bound" |

- The core group is judged too: a core service near its memory limit is a Warning that names the service and points to `docs/operations/hardening.md` (limits are core compose values).
- Fingerprints: `Fingerprint(kind, instance, service, number)`, or the filesystem's `dev` + a mount path for disks. `Inputs` digests use the threshold band (warning/problem), not the raw number, so a finding's token doesn't change every 15 s, and mutes survive small changes but come back when the band changes.
- `free_space` (a template's declared minimum) stays as it is. `disk_nearly_full` is the general check.
- No finding is ever raised from a `null` value. Missing data is `usage_not_measured`, never "OK" and never a false alarm (fail closed in both directions).

## 10. Runtimes

| | Docker (rootful) | Rootless Podman | Kubernetes (after `kube1` merges) |
|---|---|---|---|
| CPU, memory, PIDs | stats API | stats API (compat). CPU `null` when the `cpu` controller isn't delegated | `metrics.k8s.io/v1beta1` `PodMetrics` (`containers[].usage.cpu/memory`, metrics-server; k3s bundles it). PIDs `null` |
| Limits | inspect | inspect | pod spec (`resources.limits`, = compose `mem_limit`), already readable (`get` on pods) |
| Network, block IO | stats API | stats API. Block IO usually `null` (`io` not delegated) | `null` ("not measured on Kubernetes"): kubelet stats need `nodes/proxy` or `nodes/stats`, which are cluster-scoped and exec-equivalent, so never granted |
| OOM, restarts | inspect | inspect | pod status `lastState.terminated.reason == OOMKilled`, `restartCount` |
| App storage | fixer `usage` helper | the same (`/vol`) | helper pod (kube plan Task 6 form), `hub folderfix usage --root /vol` through exec, the PVC mounted read-only. Writable layers and images: `null` (the CRI isn't reachable) |
| Core group | project `portcullis` | the same | "not measured on Kubernetes yet": the Hub's Role has nothing in `portcullis` (K2), and this feature doesn't change that |
| Engine load | 1 list + N one-shot stats / 15 s | the same | 1 `list pods.metrics.k8s.io` / 15 s (metrics-server's own resolution is ~15–60 s; repeated values give no rate, which is fine for gauges) |

**Kubernetes Role change** (the only access change in this spec, read-only and namespaced): add to the Hub's Role in `portcullis-apps` `apiGroups: ["metrics.k8s.io"], resources: ["pods"], verbs: ["get", "list"]`. Update the Role YAML in core's chart, the byte copy `internal/runtime/kube/testdata/role.yaml`, `TestRoleExact`, and the kube spec §4 Role list. It stays namespaced: no `nodes`, no `nodes/stats`, no `nodes/proxy`, nothing in `portcullis`. Without metrics-server the API answers 404 or 503, so the values are `null` and the doctor reports `usage_not_measured` "the cluster has no metrics API (metrics-server)". The Hub never installs it.

**Order** (**assistant's call**): Docker and rootless Podman ship together (Parts 1–3). Kubernetes is Part 4, built on the kube backend once `kube1` is on main, not inside `kube1` (it is already large).

## 11. History: Prometheus (Part 3)

- **Listener**: `HUB_METRICS_ADDR` (core sets `hub-metrics:9100`). The Hub resolves the host part at start and binds only the address it gets on network `portcullis-metrics-hub` (as `wg` does with `WG_METRICS`). It refuses to start on a wildcard or loopback address or on a name that doesn't resolve to exactly one of its own addresses. Unset = no listener (the default for development). It serves `GET /metrics` and `GET /healthz` only, with no proxy secret, no CSRF, never a Traefik target. The network is the protection, as for `wg`.
- **Core**: a new internal network `portcullis-metrics-hub` (members: the Hub with alias `hub-metrics`, and Prometheus), a static scrape job `hub-usage` → `hub-metrics:9100`. Core CI's "each proxy network has exactly its members" style check is extended to this network (exactly two members).
- **Library**: `github.com/prometheus/client_golang` (`prometheus.Collector` reading the sampler's cache on scrape; no global registry, its own `prometheus.NewRegistry()`, no Go runtime or process collectors by default) (**assistant's call**: mature, Dependabot-tracked).
- **Series** (gauges unless noted; labels `instance` (instance id or `core`), `service`, `number`): `portcullis_container_cpu_seconds_total` (counter, from `total_usage`), `portcullis_container_memory_working_set_bytes`, `portcullis_container_memory_limit_bytes`, `portcullis_container_pids`, `portcullis_container_network_receive_bytes_total` / `_transmit_` (counters), `portcullis_container_blkio_read_bytes_total` / `_write_` (counters), `portcullis_container_oom_killed`, `portcullis_storage_alloc_bytes{instance, kind, target}` (`target` = volume name or a shared folder id, never a host path), `portcullis_storage_measured_timestamp_seconds`, `portcullis_filesystem_free_bytes{dev}` / `_total_bytes`, `portcullis_usage_sampler_last_success_timestamp_seconds`. `null` values are omitted, never exported as 0. Cardinality is bounded by the 256-container cap: about 10 series per container, ~2,600 at most.
- **Retention**: the existing `PROMETHEUS_RETENTION` (default 30d), no change. Rough cost: 30 containers × 10 series × 2 samples/min × 30 d ≈ 26 M samples, about 40 MB of TSDB. `docs/monitoring.md` gets the estimate.
- **Grafana**: a provisioned dashboard `monitoring/grafana/dashboards/usage.json` (per app and per container CPU/memory over time, storage over time, disks).
- **Alerts** (`alerts.yml`, with `tests/alerts_test.yml`): `PortcullisAppMemoryNearLimit` (working set / limit > 0.9 for 10m), `PortcullisDiskNearlyFull` (free / total < 0.10 for 30m), `PortcullisUsageSamplerStale` (no success for 10m while the Hub is up). The same thresholds as the doctor, so Alertmanager notifies what the doctor shows.

## 12. Tests and CI

- **Hub unit** (`go test -race`): CPU/rate maths across restarts and counter resets; working-set formula on v1 and v2 stats fixtures; `null` propagation and partial totals; the 256 cap; inspect copying only named fields (`TestUsageNeverKeepsEnv`: a fake inspect with `Config.Env` secrets, then marshal every cache and API answer and assert none appears); the sampler never under `Hub.mu` (a `mu` held during a sweep doesn't block it); routes Hub-listener only; CSV formula escaping; MCP parity and redaction; doctor kinds with each threshold band and with `null` inputs (no finding); storage cache corrupt/oversized → dropped; op 409 while running; Stop between targets.
- **Fixer** (`internal/folderfix`, docker-tagged CI test like the existing caps test): `usage` on a tree with hard links, sparse files, a mount point and a symlink loop gives the expected `alloc_bytes` against `du -s --block-size=1 -x` (hard links once); drop `DAC_READ_SEARCH` → a 0700 dir counts as `failed`; `--max-time` → `partial`; the mount is read-only (a write attempt fails).
- **Core CI** ("Test the socket proxies", both runtimes): through `socket-proxy-hub`, `GET /containers/<id>/stats?stream=false&one-shot=true` → 200 with `memory_stats`, `GET /containers/<id>/json?size=true` → 200, while `/system/df`, `/containers/<id>/top`, `/libpod/containers/stats` stay 403. That pins "no widening": a future flag change would break the test.
- **Core CI e2e** (`e2e-instances` and the Podman leg): enable the whoami fixture, wait two sweeps, `GET /api/usage` lists it with non-null memory and a limit. `POST …/storage/measure` → ok, its volume has `alloc_bytes > 0`. On Podman, CPU is non-null on the runner (cpu delegated) and block IO may be null.
- **Kubernetes** (Part 4, e2e-k3s): `usage_overview` shows app pods with CPU/memory from metrics-server, the core group "not measured", and `TestRoleExact` with the added rule.

## 13. Contract and docs changes (docs repo first, per Hub CLAUDE.md)

- `integration-contracts.md` §6: the stats, `size=true` inspect and image inspect calls, under the existing `CONTAINERS`/`IMAGES` sections, "no flag of `socket-proxy-hub` changes"; the fixer's `usage` mode (one read-only mount at `/vol`, `NoCopy`, `DAC_READ_SEARCH` only); `alloc_bytes`/`apparent_bytes` in `scan` reports.
- §11 (new §11.12 "Usage"): the routes and JSON fields of §8.1, the `_usage` op key, `usage.measure` audit.
- §14.5: the six doctor kinds.
- §15.10: the five tools.
- New §16-adjacent paragraph for `HUB_METRICS_ADDR` and `portcullis-metrics-hub` (Part 3).
- `docs/operations/hardening.md`: the proxy table gains a note "stats are read through `CONTAINERS`; `SYSTEM` and `ALLOW_TOP` stay off"; the new metrics network.
- `docs/monitoring.md` (core + docs site): the `hub-usage` job, the series, the dashboard, the alerts, the retention estimate.
- `docs/operations/hub.md`: the Usage page.
- Hub and core `CLAUDE.md`: the sampler rules (cache-only reads, field-by-field inspect copy, no `mu` across engine calls) and the "never `SYSTEM`" anti-goal.
- Kube spec §4 / plan K2: the `metrics.k8s.io` rule (Part 4).

## 14. Task outline (for the plan)

**Part 1: live usage (Docker + Podman)**
1. Contract §6, §11.12, §14.5, §15.10 (docs).
2. Engine `Stats` + field-by-field inspect (`internal/docker` or `runtime`), fakes.
3. Sampler, rings, aggregation, `GET /api/usage`, `GET /api/usage/instances/{id}`, CSV export.
4. MCP `usage_overview`, `usage_instance` + parity.
5. Doctor `memory_near_limit`, `oom_killed`, `pids_near_limit`, `usage_not_measured`.
6. UI: Usage tab (By app, By container), instance Usage tab.
7. Core CI proxy assertions + e2e checks.

**Part 2: storage**
8. Fixer `usage` mode + `alloc_bytes` in `scan`, docker-tagged tests.
9. Measurer, schedule, cache, op `_usage`, `POST …/measure`, `GET …/storage[/op]`, Stop.
10. MCP `usage_storage`, `usage_storage_measure`, `usage_storage_op`.
11. Doctor `disk_nearly_full`, `storage_measure_partial`.
12. UI Storage view.

**Part 3: history**
13. Metrics listener (`client_golang`), core network, scrape job, dashboard, alerts + rule tests.

**Part 4: Kubernetes** (after `kube1` is on main)
14. `metrics.k8s.io` client in the kube backend, Role rule (chart + byte copy + `TestRoleExact`), helper-pod `usage`, the "not measured" cells, e2e-k3s.

Each part is mergeable on its own, and the branches are mainlined at the end (merge, delete branches and worktrees).

## 15. Open questions (each has a default; work proceeds on the default)

1. **App admins' own view?** Default: no (§7). Later: delegated permission `view_usage`, people.<domain>, own app only.
2. **Sample interval.** Default 15 s fixed. Alternative: 15 s while the page is open, 60 s otherwise. Revisit only if engine load shows up on small hosts.
3. **Thresholds as settings?** Default: constants (90 % memory for 10 min; disk 10 % / 3 %, 5 GiB / 1 GiB). Settings → Doctor later if people ask.
4. **Show non-Portcullis containers?** Default: count only (§4.4).
5. **Core group on Kubernetes.** Default: "not measured" until a separate, reviewed read-only Role in `portcullis` is wanted. This spec doesn't add it.
6. **Per-person usage in file-sharing trees.** Default: not in v1 (the tree is measured as one folder).
