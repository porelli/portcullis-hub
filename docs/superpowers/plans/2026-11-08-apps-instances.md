# Apps and instances — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The Hub shows what runs on the server (Apps, instances as "<App> · <label>", one page per instance) apart from what can be added (Marketplace with "in use · N instances"), with a setup form before the first start (label, address picker, new or existing groups, template setup choices locked after start), one-off jobs counted as fine, per-container logs and environment variables that show default vs override.

**Architecture:** Backend first: the template model gains `jobs`, setup options and profile mapping; the instance gains a label, a group binding and an env-override store; status learns jobs. Then the UI is rebuilt around two pages (Apps, Marketplace), one instance page with tabs, and the setup form. The default instance stays the default instance underneath (id = template id) but looks like every other one.

**Tech Stack:** Go (Hub `internal/templates`, `internal/hub`, `internal/httpapi`), vanilla JS (`web/index.html`, `web/settings.js`), Python (templates `tests/validate.py`), Zensical docs.

**Spec:** `docs/superpowers/specs/2026-11-08-apps-instances-design.md` (hub repo). Mockup: `.superpowers/brainstorm/13936-1794174081/content/apps-redesign.html`. UI inventory: `.superpowers/ui-inventory/inventory.md`.

## Global Constraints

- Branch `apps` in hub, docs, templates and core (core only for e2e callers); mainlined and deleted at the end; no PRs; no migration / back-compat code.
- Contract first: `portcullis-docs/docs/guides/integration-contracts.md` §3 (manifest: `jobs`, setup options), §10 (portal name), §11 (instance label, group binding, create body, env overrides, job status), §13 (setup options / profiles), §15.10 (MCP twins); `docs/guides/manifest-reference.md` and `schema/manifest.schema.json` (templates) in the task that changes them.
- The label is display only: ids, volumes, groups, Keycloak clients, hostnames and the policy file use the instance id. Label 1–64 characters, one line (`templates.HasControlChars` refused).
- The users group may never be a built-in or administrator group; the admins group may be (e.g. `lldap_admin`). Delete never deletes a group the instance didn't create.
- A `fixed_after_start` value can't change after the instance's first successful start (409 with the reason).
- Hub-set variables (`PORTCULLIS_*`, `HubPublicVar`, option-owned, secret env names) are never overridable; overrides never reveal secrets (masks as today).
- Never weaken access control; fail closed; vanilla JS, everything escaped, data-* + delegated listeners.
- Checks before every push: gofmt (go1.27.3) on changed files, `go vet ./...`, `go vet -tags harness ./internal/httpapi/...`, `go test -race ./...` with `PORTCULLIS_TEMPLATES_DIR` (the templates `apps` branch); implementers push and start CI without waiting.
- Merge order: docs → hub (wait for edge) → templates → core; deploy only with the user's OK (test server uses ACME staging).

## Review Focus

1. Renaming an instance's label changes only what people read; enable, restart, backup/restore, delete, AI scopes and the portal still work, and the AI consent text follows — pinned in Task 3.
2. Hooking an instance to an existing group grants exactly that group's members; picking a built-in/administrator group as the users group is refused; deleting the instance leaves that group alone — pinned in Task 3.
3. A restore or restore-as of an instance keeps its setup choices and profiles; the lock still holds afterwards — pinned in Task 4.
4. A job that exits non-zero is shown as failed (not "done") and an app whose job never ran is not "fine" — pinned in Task 2.
5. An env override of a Hub-set or secret variable is refused, and the Expert table never shows a secret value — pinned in Task 5.

---

### Task 1: Contract and template model (docs + hub `internal/templates` + templates repo)

**Files:** contract §3/§10/§11/§13/§15.10, `manifest-reference.md`; hub `internal/templates/manifest.go`, `settings.go`, a new `internal/templates/setup.go`, tests; templates `schema/manifest.schema.json`, `tests/validate.py`, `tests/test_validate.py`.

**Interfaces:**
- Produces: `Manifest.Jobs []string` (yaml `jobs`, compose service names); `Option.Setup bool` (`setup`), `Option.FixedAfterStart bool` (`fixed_after_start`), `Option.Profiles map[string][]string` (`profiles`: option value → compose profiles; enum options only); `templates.JobServices(m, compose) map[string]bool` (= `jobs` ∪ services another service depends on with `condition: service_completed_successfully`); `templates.ProfilesFor(t, values) []string`.

- [ ] **Step 1:** Write the contract text (all **NEW (apps)**): manifest `jobs`; setup options (`setup`, `fixed_after_start`, `profiles`; `profiles` only on `enum` instance options whose values are all keys; every profile named exists on ≥ 1 service; a service with `profiles:` must be covered by some option's mapping); instance `label`, group binding, create body, env overrides, job status, logs per container (existing `service` param); portal `name` = "<App> · <label>".
- [ ] **Step 2: tests (hub):** `TestJobServicesFromDependsOn` (guacamole-shaped compose → `guacamole-init`), `TestJobsListed`, `TestSetupOptionValidation` (profiles on a non-enum 400-style refusal, unknown profile, uncovered profiled service, `fixed_after_start` without `setup` refused), `TestProfilesFor`.
- [ ] **Step 3:** implement; templates `validate.py` mirrors every rule with the Hub's messages; schema updated.
- [ ] **Step 4:** commit docs `contracts: apps & instances (NEW)`, hub `templates: jobs and setup options`, templates `validate: jobs and setup options`.

### Task 2: One-off jobs in status, drift and readiness (hub)

**Files:** `internal/hub/runtime.go` (`Status`), drift/reconcile, `startprogress.go` (`countContainers`), card/list counts source, tests.

**Interfaces:** `ContainerStatus.Job bool`, `ContainerStatus.JobState string` (`done` | `failed` | `running` | `pending`); counts "n of m" count a job as up when `done`.

- [ ] **Step 1: tests:** `TestStatusJobDone` (exited 0 job → Job true, done, not counted as down), `TestStatusJobFailed` (exit 1 → failed, instance flagged), `TestDriftIgnoresFinishedJob`, `TestHealthyStepJobDone`, `TestJobNeverRan` (job missing → not fine).
- [ ] **Step 2–4:** fail → implement → pass; commit `hub: one-off jobs count as done when they exit 0`.

### Task 3: Instance label and group binding (hub)

**Files:** `internal/state` (instance `Label`, `UsersGroup`, `AdminsGroup`), `internal/hub/instances.go`, `create.go`, `portal.go` (`instanceName`), the places that derive the access/admin group (policy, population, settings placeholders, access role, delete cleanup, `NamesFor` users), `ai_instance.go`/`ai_lifecycle.go` (consent text), `internal/httpapi/instances.go`, `mcptools_*.go`, tests.

**Interfaces:**
- Produces: `CreateRequest{Template, ID, Label string; Hosts map[string]string; Groups GroupChoice}` with `GroupChoice{Mode string /* "new" | "existing" */; Users, Admins string}`; `func (h *Hub) SetLabel(ctx, id, label string, actor) error` (`PUT /api/instances/{id}/label {"label"}`, audited `instance.update` `label a -> b`); `instanceName(t)` = `<Manifest.Name> · <label>` (label defaults to the template name for the first instance, the id otherwise, until set); `func (h *Hub) instanceGroupsLocked(t) (users, admins string)` — the one place that answers an instance's groups.
- The first instance of a template is created with `ID = template id` (the form pre-fills it); `CreateInstance` must accept that when no default instance exists yet.

- [ ] **Step 1: tests:** `TestCreateWithLabelAndNewGroups`, `TestCreateWithExistingGroups` (population = that group; delete keeps it), `TestCreateRefusesBuiltinUsersGroup`, `TestCreateAllowsLldapAdminAsAdmins`, `TestSetLabelChangesOnlyNames` (enable/restart/backup/restore/delete unaffected; portal + My apps names), `TestSetLabelReassertsConsentText`, `TestFirstInstanceIDIsTemplateID`, `TestInstanceNameEverywhere` (the 10 `instanceName` call sites).
- [ ] **Step 2–4:** fail → implement → pass; contract text from Task 1 matches; MCP `create_instance` takes `label` / `groups`, new `set_instance_label` (class W) with its twin; parity tests.
- [ ] **Step 5:** commit `hub: instance labels and group binding`.

### Task 4: Setup choices and profiles (hub)

**Files:** `internal/hub/create.go` (setup values in the create body), `settings.go` (save lock), env/override generation (`COMPOSE_PROFILES`), `startprogress.go` `pullRefs`, status/drift/backup project loading (`loadRendered` with the instance's profiles), restore/restore-as, tests.

**Interfaces:** `CreateRequest.Setup map[string]json.RawMessage` (setup option values, parsed like settings); `InstanceSettings.FirstStartedAt *time.Time` (set at the first successful start); `COMPOSE_PROFILES` written in the instance `.env` from `templates.ProfilesFor`.

- [ ] **Step 1: tests:** `TestCreateWithSetupChoice` (Nextcloud-shaped template: postgres → profile `db-postgres`, only that DB service runs), `TestFixedAfterStartLocked` (409 after first start, allowed before), `TestRestoreKeepsChoiceAndLock`, `TestRestoreAsKeepsChoice`, `TestPullRefsFollowProfiles`, `TestStatusFollowsProfiles`.
- [ ] **Step 2–4:** fail → implement → pass; commit `hub: setup choices select compose profiles, locked after the first start`.

### Task 5: Environment overrides (hub)

**Files:** a new `internal/hub/envoverrides.go`, `settings.go` (`Env` → rows), env writer (overrides last), `internal/httpapi` routes, tests.

**Interfaces:** `type EnvRow struct{ Name, Default, Source /* "template" | "hub" | "option" */, Value string; Overridden, HubSet, Secret bool }`; `func (h *Hub) EnvRows(id) ([]EnvRow, error)`; `func (h *Hub) SetEnvOverride(id, name, value string, actor) error` / `ClearEnvOverride(id, name, actor) error` (`PUT|DELETE /api/instances/{id}/env/{name}`, audited `settings.env` `name: overridden|reset|added`); overrides stored per instance in `state.yaml` (no secrets: a variable whose value looks secret or is a secret name is refused); written after the template/Hub values in `.env`; an enabled instance restarts on change (effect restart, through the delivery engine). Today's `SaveEnv` (whole-file post) is replaced by these routes.

- [ ] **Step 1: tests:** `TestEnvRowsSources`, `TestEnvOverrideWins`, `TestEnvOverrideHubSetRefused`, `TestEnvOverrideSecretRefused`, `TestEnvRowsMaskSecrets`, `TestEnvReset`, `TestEnvAddOwnVariable`.
- [ ] **Step 2–4:** fail → implement → pass; MCP `save_env` becomes `set_env_override` / `clear_env_override` (parity); commit `hub: per-variable env overrides with defaults shown`.

### Task 6: Apps, Marketplace and the instance page (UI)

**Files:** `web/index.html`, `web/settings.js` (only where Settings mounts into the new page), harness.

- [ ] **Step 1:** Top tabs: Apps · Marketplace · Audit log · Doctor · Settings · People ↗. **Apps**: installed apps, each with its instances (status dot, "running · n of m" with "setup job done", address, users group + member count, Enable/Disable), "+ Add instance" on the app, "+ Add an app" → Marketplace; drift / missing-group banners stay above. **Marketplace**: every template card with "in use · N instances" + "Show in Apps" (filters Apps) + "+ Add instance", or "Install…".
- [ ] **Step 2:** **Instance page** (one for every instance, default included; route `#apps/<id>`): header "<App> · <label>" + status + Enable/Disable; tabs Overview (label editable, addresses / hostname editor, containers with job state), Settings, **Groups** (users / admins: kind, count, first names + "+N", "Manage on People ↗"), Logs (All containers / one container), Backups, AI, **Expert** (env table: variable, default + source tag, your value, state, Reset / Override… / "+ Add your own variable"; compose template + Hub override read-only, custom override editable), Delete. Remove the card's inline detail panel and the instance modal; old deep links (`#app/<id>/settings[/<option>]`, `#app/<id>/ai`) route to the new page.
- [ ] **Step 3:** Harness screenshots of Apps, Marketplace, an instance page per tab, a job "done" and a job "failed", a default instance and an extra instance looking alike; console clean. Commit `ui: Apps and Marketplace; one page per instance`.

### Task 7: Setup form (UI)

**Files:** `web/index.html`, harness.

- [ ] **Step 1:** Install… / + Add instance open the form: Label (required), id preview (editable before Start; the first instance pre-fills the template id and keeps it), Address (subdomain + domain picker from `GET /api/instances/defaults` / ready enrolled domains), Who can use it (new groups from the label, or pick existing users / admins groups — built-in groups not offered for users), the template's setup options with defaults (🔒 "fixed after the first start" on `fixed_after_start`), Start / Save without starting / Cancel. Start = create + enable through the progress panel.
- [ ] **Step 2:** Harness screenshots (Nextcloud-shaped fixture with a DB choice, existing groups, a refused built-in users group); commit `ui: setup before the first start`.

### Task 8: Templates and core callers

**Files:** templates `nextcloud/` (a PostgreSQL choice: `setup` + `fixed_after_start` + `profiles`), `guacamole/` (no change if detection covers it; check), Test Apps for nextcloud; core `tests/e2e/*` and `ci.yml` callers of `POST /api/instances` (now needs `label`) and `SaveEnv` / Expert env.

- [ ] **Step 1:** Nextcloud DB choice; validate.py + Test Apps green for both engines.
- [ ] **Step 2:** core callers updated; core CI on `apps` green (it builds the Hub from `apps`).
- [ ] **Step 3:** commit templates `nextcloud: database choice at setup`, core `ci: create takes a label; env overrides`.

### Task 9: Docs

- [ ] **Step 1:** `operations/hub.md` (Apps / Marketplace / instance page / setup form / Expert), `guides/adding-an-app.md` + `manifest-reference.md` (jobs, setup options), `operations/testing.md`; regenerate app pages; re-sync the Hub's `web/docs/`. Commit `docs: apps & instances`.
