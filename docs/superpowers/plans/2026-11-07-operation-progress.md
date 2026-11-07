# Operation progress and Stop — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every long app operation shows a resumable step list with percentages and can be stopped, putting things back as they were.

**Architecture:** The per-instance op record (`<data>/ops/<id>.json`) gains a step list, a `created` ledger and stop state, written as they change by a small progress reporter passed down the existing lifecycle paths. Each long operation runs in the background (`startAsync`) under a cancellable context; Stop cancels it and runs the operation's undo from the `created` ledger. The UI polls the op record and renders a progress panel; the Portcullis MCP reads the same record and gains `stop_op`.

**Tech Stack:** Go (Hub), Engine API via `moby/moby/client` (image pulls with progress), docker compose CLI (unchanged), vanilla JS (`web/index.html`), Python e2e (core), Zensical docs.

**Spec:** `docs/superpowers/specs/2026-11-07-operation-progress-design.md` (hub repo).

## Global Constraints

- Work on branch `progress` in each repo touched (cross-repo CI picks the same-named branch), mainlined and deleted at the end; no PRs; no migration or back-compat code (there are no installs to upgrade).
- Contract first: `portcullis-docs/docs/guides/integration-contracts.md` §11.4–11.7 (op record, async ops) and §15.10/§15.11 (MCP tools, AI routes) change before code.
- Fail closed; never weaken access control or a test to make it pass.
- Secrets never in op records, logs, the audit or answers (op records stay redacted with `secretRedactor`).
- Never hold `Hub.mu` across Docker, network or hook calls; lifecycle ops keep `lockApp` → `aiLock` (G35).
- Stop is admins only on the Hub listener (CSRF guard); audited `<op>.stop` with the actor (and `via`/`client` from the AI).
- Frontend: vanilla JS, every value through `escapeHtml`, data-* attributes + delegated listeners, no inline handlers with data.
- Hub CLAUDE.md, docs pages (`operations/hub.md`, contract) and `web/docs/` copies are updated in the same task as the behaviour.
- Checks before every push: gofmt (go1.27.3), `go vet ./...`, `go vet -tags harness ./internal/httpapi/...`, `go test -race ./...` with `PORTCULLIS_TEMPLATES_DIR`. GitHub-hosted runners only.
- Merge order at the end: docs → hub (wait for `build.yml` push run on main → edge) → templates → core; deploy only with the user's OK.

## Review Focus

1. Stop pressed at every step of an enable leaves nothing this enable created (containers, new volumes, Keycloak clients, groups), and keeps pre-existing groups/volumes.
2. A Hub restart mid-operation: the record shows "interrupted", Stop undoes from the persisted ledger, and nothing runs twice.
3. Two admins / two tabs: a second Start answers 409 with the running op; both see the same progress; a Stop from either works once.
4. Delete past its point of no return refuses Stop (409) and finishes.
5. A failed undo is shown with what's left; Stop again retries only the remaining undo steps.

---

### Task 1: Contract (docs)

**Files:**
- Modify: `portcullis-docs/docs/guides/integration-contracts.md` (§11.4–11.7 op record and async ops; §15.10 tool table; §15.11 AI routes), `docs/operations/hub.md`.

- [ ] **Step 1:** Op record shape: add `steps: [{key, label, state: "waiting"|"running"|"done"|"failed"|"stopped"|"undone", percent?, detail?, started_at?, ended_at?}]`, `created: {volumes: [], keycloak_clients: [], groups: []}`, `stopping: bool`, `stopped_by`, `stopped_at`, `stoppable: bool`, `point_of_no_return: bool`, `interrupted: bool`. Written whenever a step changes (at most every 500 ms for percent updates).
- [ ] **Step 2:** Every lifecycle route answers `202 {op_id, op, instance, poll}` after validation and the lock: `POST /api/templates/enable`, `/api/templates/disable`, `/api/templates/restart/{id}`, `PUT /api/instances/{id}/ai` (when it restarts or runs hooks), `POST /api/instances` (create), plus the existing backup/restore/delete. A second request while one runs: `409` with the running record.
- [ ] **Step 3:** `POST /api/instances/{id}/op/stop` → `202` with the record (`stopping: true`); `409` when nothing runs, when `point_of_no_return`, or when already stopping. Audited `<op>.stop` (detail: the step key).
- [ ] **Step 4:** Per-operation Stop semantics: copy the spec's table verbatim; enable's undo removes only `created` entries; downloaded images kept.
- [ ] **Step 5:** §15.10: `get_op` / `wait_for_op` return steps; new `stop_op` (W, twin `POST /api/instances/{id}/op/stop`).
- [ ] **Step 6:** `zensical build --strict --clean`; commit `contracts: operation progress and Stop`.

### Task 2: Progress model and reporter (hub)

**Files:**
- Create: `internal/hub/progress.go`, `internal/hub/progress_test.go`.
- Modify: `internal/hub/ops.go` (OpRecord fields), `internal/hub/async.go` (startAsync gets a cancellable context and a reporter).

**Interfaces:**
- Produces:
```go
type Step struct{ Key, Label, State string; Percent *int; Detail string; StartedAt, EndedAt *time.Time }
type Created struct{ Volumes, KeycloakClients, Groups []string }
type Progress struct{ /* id, op, mu, throttle */ }
func (h *Hub) newProgress(id, op string, steps []Step) *Progress
func (p *Progress) Start(key string)
func (p *Progress) Percent(key string, pct int, detail string) // throttled 500 ms
func (p *Progress) Done(key string)
func (p *Progress) Fail(key string, err error)
func (p *Progress) Created(kind, name string) // persisted at once
func (p *Progress) NoReturn()                  // point_of_no_return = true, stoppable = false
func progressFrom(ctx context.Context) *Progress // nil-safe: methods are no-ops on nil
```
- `startAsync(id, op, actor, steps, fn func(ctx context.Context, ready func()) …)`: ctx is cancelled by Stop; the reporter is in ctx.

- [ ] **Step 1: tests:** `TestProgressPersisted` (each Start/Done/Created writes the record; Percent writes at most every 500 ms; the file survives a reload), `TestProgressNilSafe`, `TestStartAsyncCancellable` (a Stop cancels ctx; fn sees `ctx.Err()`), `TestInterruptedKeepsLedger` (a running record at load becomes `interrupted: true, stoppable: true` with steps and `created` intact).
- [ ] **Step 2:** run → FAIL. **Step 3:** implement. **Step 4:** run → PASS. **Step 5:** commit `hub: op progress model and cancellable background ops`.

### Task 3: Image downloads with progress and service readiness (hub)

**Files:**
- Modify: `internal/docker/volumes.go` (or a new `internal/docker/pull.go`), `internal/hub/lifecycle.go` (`startUp`), fake engine in tests.

**Interfaces:**
- Produces: `func (e *Engine) PullWithProgress(ctx context.Context, ref string, onBytes func(done, total int64)) error` (Engine API `ImagePull` JSON stream; byte counts summed over layers; already-present image = immediate 100 %). `ContainerState` polling for "Starting services (n of m)" and "Waiting until healthy (n of m)".
- `startUp` pulls every image of the project (the pinned refs compose would pull) before `compose.Create`; Create then finds them present.

- [ ] **Step 1: tests:** `TestPullProgressSumsLayers` (fake stream → monotonic percent, 100 at end), `TestStartUpReportsSteps` (steps `images`, `create`, `start`, `healthy` in order with percents), `TestPullCancelled` (ctx cancel stops the pull, step `stopped`).
- [ ] **Step 2–4:** fail → implement → pass. **Step 5:** commit `hub: image downloads and service readiness as progress steps`.

### Task 4: Enable — async, steps, created ledger, Stop (hub)

**Files:**
- Modify: `internal/hub/instancegroups.go` (`EnableAs` → `StartEnable`), `internal/hub/lifecycle.go` (`enableInner` reports steps and `Created`), `internal/hub/stop.go` (new: `StopOp(id string, actor directory.Actor) (*OpRecord, error)` and per-op undo), tests `internal/hub/stop_test.go`.

**Interfaces:**
- Produces: `func (h *Hub) StartEnable(id string, actor directory.Actor) (*AsyncOp, error)`; `func (h *Hub) StopOp(id string, actor directory.Actor) (*OpRecord, error)`.
- Enable steps: `groups`, `keycloak`, `images`, `create`, `start`, `healthy`, `settings`. `Created` gets each group from `ensureGroups`' created list, each client `RegisterClient` created (not one that existed), each volume compose created (volumes listed by project label before vs after create).
- Undo (in order, idempotent, each an undo step): compose down; remove `created.volumes`; delete `created.keycloak_clients` (owner-tagged only); delete `created.groups` (via `Groups.DeleteInstanceGroup` as the stopping admin); state left disabled; images kept.

- [ ] **Step 1: tests:** `TestStopEnableAtEveryStep` (table: stop at each step key → afterwards none of `created` exists, pre-existing group/volume kept, state disabled), `TestStopEnableUndoFailsThenRetries` (one undo step fails → record shows it, Stop again runs only the remaining ones), `TestStopInterruptedEnable` (record from a "crashed" Hub → Stop undoes from the ledger), `TestEnableSecondRequest409`, `TestStopAudited`.
- [ ] **Step 2–4:** fail → implement → pass. **Step 5:** commit `hub: enable runs in the background with steps and can be stopped`.

### Task 5: Disable, restart, AI switches (hub)

**Files:** `internal/hub/lifecycle.go`, `internal/hub/ai_instance.go`, `internal/hub/stop.go`, tests.

- [ ] **Step 1: tests:** disable steps (`stop`, `keycloak callbacks`) and Stop → re-enabled as before; restart steps (`down`, `images`, `start`, `healthy`, `settings`) and Stop → running as before; AI on/off/mode steps (`revoke`, `scopes`, `restart`, `hooks`) and Stop → the switch back with credentials/scopes as before (reuse 12a's switch-off/switch-on paths; owed flags still hold).
- [ ] **Step 2–4:** fail → implement → pass. **Step 5:** commit `hub: disable, restart and AI switches report steps and can be stopped`.

### Task 6: Backup, restore, restore-as, create, delete (hub)

**Files:** `internal/hub/backup.go`, `restore.go`, `delete.go`, `instances.go` (create), `stop.go`, tests.

- [ ] **Step 1: tests:**
  - backup: steps (`stop`, one `volume:<name>` per volume with %, `archive`, `start`); Stop → partial archive deleted, app restarted if it ran.
  - restore: steps (`verify` %, `pre_backup`, `volumes` %, `config`, `start`); Stop → rolled back from the pre-restore backup (existing failure path).
  - restore-as and create: Stop → the new instance removed completely.
  - delete: steps (`backup`, `stop`, `volumes`, `keycloak`, `groups`, `files`); `NoReturn()` at the first volume removal; Stop before → app back as before; Stop after → 409 "past the point of no return — finishing".
- [ ] **Step 2–4:** fail → implement → pass. **Step 5:** commit `hub: backups, restores, creates and deletes report steps and can be stopped`.

### Task 7: Routes, MCP tools, audit (hub)

**Files:** `internal/httpapi/server.go`, `instances.go`, `ai.go`, `mcptools_admin.go`, `mcp_parity_test.go`, tests.

- [ ] **Step 1: tests:** each route answers 202 then the op record polls to done; `POST /api/instances/{id}/op/stop` (admins only, 401/403/404 on people listener, CSRF); MCP `stop_op` W with twin; `get_op`/`wait_for_op` include steps; `TestToolParity` green; `TestAdminToolsSameAsHTTP` covers `stop_op`.
- [ ] **Step 2–4:** fail → implement → pass. **Step 5:** commit `hub: async lifecycle routes, Stop route and stop_op tool`.

### Task 8: Progress panel (hub UI)

**Files:** `web/index.html` (and `web/settings.js` only if the settings save path uses `runInstanceOp`), harness.

- [ ] **Step 1:** panel per spec option B: title "<Verb>ing <App>", "Started by <user> at <time>", steps with ✓/◐/○/■/✗, percent bar and detail, durations, **Stop** button with confirm "Stop <verb>ing <App> and undo what it did?", Close; stopping and stopped states; "past the point of no return — finishing"; "interrupted" with Stop. Reopen from the card ("Enabling… show progress"); open automatically for an app whose op is running on page load. Poll every 1 s while open.
- [ ] **Step 2:** harness: seed a slow fake pull; Playwright screenshots of running, stopping, stopped, failed-undo, interrupted, delete past no return. Save into the workspace.
- [ ] **Step 3:** commit `ui: progress panel with Stop for every app operation`.

### Task 9: Firefly III groups (templates)

**Files:** `firefly-iii/manifest.yaml` (and compose/env references to the group names).

- [ ] **Step 1:** rename `users_firefly` → `users_firefly-iii`, `admin_firefly` → `admin_firefly-iii` everywhere in the template; `validate.py` and Test Apps (firefly-iii) green.
- [ ] **Step 2:** commit `firefly-iii: derived group names (created on enable)`.

### Task 10: Callers and e2e (core, templates tests)

**Files:** core `tests/e2e/e2e_ai.py`, `e2e_folders.py`, `e2e_filesharing.py`, `.github/workflows/ci.yml` (lines calling `/api/templates/enable`), a shared poll helper; templates `tests/e2e/app_signin.py` / `tests/lib.sh` if they enable through the Hub API.

- [ ] **Step 1:** every enable/disable/restart caller polls the op record to done (one helper per language).
- [ ] **Step 2:** new core e2e scenario `stop_enable_mid_pull` (e2e-instances): start an enable of a fixture with a large image, Stop during `images`, assert no containers, no new volumes, no Keycloak client, no groups created by it; the panel's op record ends `stopped`.
- [ ] **Step 3:** CI green on the branch; commit `ci: lifecycle routes are asynchronous; Stop mid-enable e2e`.

### Task 11: Docs pages

- [ ] **Step 1:** `operations/hub.md` (the panel, Stop table), testing.md (the new e2e), CLAUDE.md rows in hub/core; regenerate the firefly app page; re-sync the Hub's `web/docs/`.
- [ ] **Step 2:** commit `docs: operation progress and Stop`.
