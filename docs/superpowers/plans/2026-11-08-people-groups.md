# People & groups (one place, group pages, person pages) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** People and groups are managed in one place (people.<domain>) where every route — from a person, an app or the group list — lands on the group's own page, rule overrides are plain "added by hand" / "kept out" entries applied in about a second, and a person's page shows their groups, apps and per-app values.

**Architecture:** The directory backend already has everything but four pieces: a unified add (`AddMember` takes a reason/end and turns into an include exception on rule groups), a synchronous evaluation after each membership mutation (`Settle`), per-group/person audit filtering, and two admin reads served from the Hub (a person's apps/values, a group's setting uses). The UI is `web/directory.js` (shared by both listeners): expanding group cards and the person dialog become hash-routed pages; the Hub's Users & Groups tab becomes a link to people.<domain> and the audit log moves to its own Hub tab.

**Tech Stack:** Go (Hub, `internal/directory`, `internal/httpapi`), vanilla JS (`web/directory.js`, `web/index.html`, `web/settings.js`), Zensical docs.

**Spec:** `docs/superpowers/specs/2026-11-08-people-groups-design.md` (hub repo). UI inventory: `.superpowers/ui-inventory/inventory.md` in the hub's main checkout. Mockups: `.superpowers/brainstorm/53873-1794151333/content/people-pages.html`.

## Global Constraints

- Branch `people` in hub, docs (and core only if a caller needs it), mainlined and deleted at the end; no PRs; no migration / back-compat code (existing direct adds to rule groups are not migrated).
- Contract first: `portcullis-docs/docs/guides/integration-contracts.md` §9 (directory API), §5.1 (people listener routes), §15.10 (MCP tools) change before code; `operations/groups.md`, `operations/hub.md` and the Hub's `web/docs/` copies in the task that changes the behaviour.
- The people listener never carries app / Docker / settings-write routes (`TestPeopleListenerHasNoAppRoutes`); the two new reads live in the directory route set, admins only, read-only.
- Admin-only stays admin-only on both listeners; non-admins see group members read-only, without entry reasons, without "Used by" and without History. Delegates keep exactly their powers.
- Frontend: vanilla JS, no build step, every value through `esc` / `escapeHtml`, data-* attributes + delegated listeners, no inline handlers with data; `directory.js` stays the one implementation for both listeners.
- Never weaken access control or a test; fail closed.
- Checks before every push: gofmt (go1.27.3), `go vet ./...`, `go vet -tags harness ./internal/httpapi/...`, `go test -race ./...` with `PORTCULLIS_TEMPLATES_DIR`; implementers push and start `build.yml` without waiting; GitHub-hosted runners only.
- Merge order at the end: docs → hub (wait for `build.yml` push run on main → edge) → core if touched; deploy only with the user's OK.

## Review Focus

1. Adding someone who already matches a rule group stores an entry and shows "also matches the rule"; when the rule stops matching them they stay in (the evaluator keeps include exceptions) — pinned in Task 2.
2. A save while LLDAP is down stores the entry and answers `applied: false` with the reason; the page shows "saved, not applied yet: <why>" and Remove still works — pinned in Task 3.
3. A non-admin (delegate) on people.<domain> opens a group page: members visible, no reasons, no Used by, no History, no controls — pinned in Task 5.
4. Old deep links (`hub.<domain>/#users/<name>?password|?invite`, `#users?create&…`, the MCP's links) still open the right place — pinned in Task 7.
5. Deleting a group from its page states exactly what its Used by lists (apps, setting rows, permission) before the typed confirmation — pinned in Task 5.

---

### Task 1: Contract (docs)

**Files:** `portcullis-docs/docs/guides/integration-contracts.md` (§9, §5.1, §15.10).

- [ ] **Step 1:** §9, mark **NEW (people & groups)**:
  - `POST /api/directory/groups/{g}/members` body `{"username", "reason"?, "until"?}`: manual group = member (+ expiry when `until`); rule group = an "added by hand" entry (include exception, `reason` required → 400 "a reason is required: <g> is rule-based"), also when the person already matches.
  - `PUT …/members/{u}/expiry` on a rule group sets the person's added-by-hand entry's end (409 as today when they have none).
  - `GroupView.matches` (rule groups: usernames matching the rule now; admins only).
  - Every membership / exception / rule mutation answers with `{"applied": bool, "why"?: string}` merged into its body: the evaluator ran synchronously (≤ 5 s); `applied: false` = stored, not applied (LLDAP down, timeout).
  - `POST /api/directory/users` `groups` may name rule groups; `reasons: {"<group>": "<reason>"}` required for each rule group the new person won't match (400 naming it); stored as added-by-hand entries.
  - `GET /api/directory/audit?group=<g>` / `?user=<u>` (admins): entries for that group (target `<g>` or `<g>:<user>`) / user (target suffix or `user=` in detail), newest first, ≤ 100, scanning ≤ 8 MiB of the tail.
  - New admin reads (both listeners, directory route set): `GET /api/directory/users/{u}/apps` → `{apps: [{instance, name, via: [group], until?}], values: [{instance, app, key, label, value, from}]}`; `GET /api/directory/groups/{g}/uses` → `{apps: [{instance, name, role: access|admin}], settings: [{instance, app, key, label, value}], permissions: [perm]}`.
- [ ] **Step 2:** §5.1: the people listener's directory set includes the two reads; still no app routes.
- [ ] **Step 3:** §15.10: `add_member` takes `reason` / `until` (class unchanged); new read tools twin the two reads (class R); `get_audit` (or the existing audit tool) takes `group` / `user`.
- [ ] **Step 4:** `zensical build --strict --clean && rm -rf site`; commit `contracts: people & groups (NEW)`.

### Task 2: Unified add, ends and matches (directory)

**Files:** `internal/directory/service.go` (AddMember, GroupView), `internal/directory/groups.go` (SetMemberExpiry), `internal/directory/store.go` if needed, `internal/httpapi/directory.go` (handler bodies), `internal/httpapi/mcptools_directory.go` (`add_member` args), tests.

**Interfaces:**
- Produces: `type MemberAdd struct{ Username, Reason string; Until *time.Time }`; `func (s *Service) AddMember(ctx context.Context, c *Caller, group string, m MemberAdd) error`; `GroupView.Matches []string` (json `matches`, nil for non-admins and manual groups); `CreateRequest.Reasons map[string]string` (json `reasons`).
- Rule group path = `AddException(Include: true, Reason, Until)` inside the same audited run (action `group.exception`, detail as AddException's); manual group = today's add + `SetMemberExpiry` when `Until`.

- [ ] **Step 1: tests** (`internal/directory/people_groups_test.go`): `TestAddMemberRuleGroupNeedsReason` (400 text "a reason is required: milan is rule-based"), `TestAddMemberRuleGroupStoresInclude` (non-matching dave → include exception with reason/until), `TestAddMemberRuleGroupAlreadyMatching` (alice matches → entry stored; after the rule changes so she no longer matches, Evaluate keeps her), `TestAddMemberManualUntil` (expiry set), `TestSetMemberExpiryRuleHandAdded` (sets the entry's Until; 409 for a rule match without entry), `TestGroupViewMatches` (admin sees matches; non-admin Overview has nil), `TestCreateUserRuleGroups` (rule group without reason 400 naming it; with reason → include entry; a rule the new person matches on username/email/display name needs none).
- [ ] **Step 2–4:** fail → implement → pass. Update `add_member` MCP args + parity; the HTTP handler decodes the new body strictly.
- [ ] **Step 5:** commit `directory: one add for manual and rule groups, ends on hand-added entries, matches`.

### Task 3: Apply at once (Settle)

**Files:** `internal/directory/evaluate.go`, `internal/httpapi/directory.go`, `internal/httpapi/mcptools_directory.go`, tests.

**Interfaces:**
- Produces: `func (s *Service) Settle(ctx context.Context) (applied bool, why string)` — runs `Evaluate(ctx, now)` once, bounded by `settleTimeout = 5 * time.Second`; any error or timeout = `false` with the error's text (never a secret); the background loop is unchanged.
- Every membership / exception / rule / convert / expiry handler and MCP tool calls it after a successful mutation and merges `applied` / `why` into its answer.

- [ ] **Step 1: tests:** `TestSettleAppliesAtOnce` (add dave by hand → LLDAP membership present when the handler returns), `TestSettleLLDAPDown` (`applied:false`, `why` names LLDAP, entry stored, a following RemoveException works), `TestSettleTimeout` (blocking fake → false within ~5 s, handler still 200), `TestMCPAddMemberApplied`.
- [ ] **Step 2–4:** fail → implement → pass. **Step 5:** commit `directory: apply membership changes at once`.

### Task 4: History filters and the two admin reads

**Files:** `internal/directory/audit.go`, `internal/httpapi/directory.go`, `internal/hub/` (a small `people_reads.go`: `PersonApps`, `GroupUses`), `internal/httpapi/mcptools_directory.go`, `mcp_parity_test.go`, tests.

**Interfaces:**
- Produces: `func (l *AuditLog) RecentMatching(n int, maxScan int64, keep func(AuditEntry) bool) ([]AuditEntry, error)`; `func (h *Hub) PersonApps(ctx context.Context, user string) (*PersonAppsView, error)` (from `MyApps` without credentials / AI; `via` = the person's groups that grant each app, with their end); `func (h *Hub) GroupUses(group string) (*GroupUsesView, error)` (apps whose access/admin group it is; every instance setting row / group record naming it — the same matching `PurgeGroupSettings` uses; permissions from the directory).
- The two routes are registered by the directory route set on both listeners, admins only (403 otherwise), 503 when the Hub side isn't wired.

- [ ] **Step 1: tests:** `TestAuditGroupFilter` (group.rule, group.exception and `group.sync` `<g>:<id>` entries returned; another group's not), `TestAuditUserFilter`, `TestPersonAppsRoute` (values with `from`, via groups; delegate 403), `TestGroupUsesRoute` (access group + a settings row + a permission; matches what `PurgeGroupSettings` would drop), `TestPeopleListenerHasNoAppRoutes` still green, `TestToolParity` covers the two read tools.
- [ ] **Step 2–4:** fail → implement → pass. **Step 5:** commit `directory: history by group/person; person apps and group uses`.

### Task 5: Groups list and group page (UI)

**Files:** `web/directory.js`, `web/directory.css`, harness.

**Interfaces:**
- Consumes: Tasks 2–4 APIs. Produces: hash routes `#groups` (list) and `#groups/<name>` (page); `PortcullisDirectory.openGroup(name, {preselect: [user]})`.

- [ ] **Step 1:** Groups list = a table (group, kind rule-based / manual / built-in, people, gives access to); search, New group; each row opens the page. Remove the expanding cards and the Groups-tab "Missing groups" card.
- [ ] **Step 2:** Group page per the mockup: header (gives access to, rule + Edit rule… / Make manual, or Make rule-based…), People rows with their state ("matches the rule" + Keep out…; "added by hand · until · reason" + Change end / Remove, plus "also matches the rule" with the warning "keeps access if they stop matching"; "kept out · reason" + Let back in; "member · until" + Change end / Remove), Add people (multi-pick, until, reason required on rule groups, "already matches" shown while picking via `matches`), result from `applied` ("saved, not applied yet: <why>"), Used by (Task 4) with Delete group… stating what it removes, History (Task 4, plain words: map `group.sync` causes and `group.exception` / `group.rule` / `group.add_member` / `group.remove_member` details to sentences).
- [ ] **Step 3:** Non-admins: members read-only, no reasons, no Used by, no History, no controls.
- [ ] **Step 4:** Harness: Playwright screenshots of list, rule group page (all row states), manual group page, delegate view, LLDAP-down save; save to `.superpowers/sdd/2026-11-08-people-groups/screens/`. Console clean.
- [ ] **Step 5:** commit `ui: group pages`.

### Task 6: Person page and invite (UI)

**Files:** `web/directory.js`, `web/directory.css`, harness.

- [ ] **Step 1:** `#people/<name>` replaces `openUser`'s dialog: header + Edit details, Groups (state per group, links to the group page; Add to group… → pick → `openGroup(g, {preselect:[name]})`), Apps and Values (Task 4's read), Sign-in (today's key actions, unchanged permissions), History (`?user=`). Keep `#users/<name>[?password|?invite]` working on people.<domain> (route to the new page and open the prompt).
- [ ] **Step 2:** Invite: the groups pick offers rule groups too; for each picked rule group the new person won't match (username / email / display name only), a reason field (`reasons`).
- [ ] **Step 3:** Harness screenshots (person page admin + delegate, invite with a rule group). **Step 4:** commit `ui: person pages; invite with rule groups`.

### Task 7: Hub: one place, links, audit tab

**Files:** `web/index.html`, `web/settings.js`, `internal/httpapi/mcptools_directory.go` (deep links), docs pages.

- [ ] **Step 1:** Hub's Users & Groups tab → a link to `https://people.<main domain>/` (the Hub's main domain as the UI already knows it); `hub.<domain>/#users/<name>[?…]` and `#users?create&…` redirect to the matching `people.<domain>/#people/<name>[?…]` / invite.
- [ ] **Step 2:** MCP deep links (`mcptools_directory.go` `#users/…`) point to people.<domain>.
- [ ] **Step 3:** New Hub tab **Audit log** (today's audit view, all / via AI / with access log), removed from Setup on both listeners.
- [ ] **Step 4:** Every group name the Hub shows links to `people.<domain>/#groups/<g>`: settings "Who gets what" (and the "N members of <g> have no access" warning), instance overview access/admin group, AI tab and file-sharing "people with access" lines.
- [ ] **Step 5:** Docs: `operations/groups.md`, `operations/hub.md` (pages, added by hand / kept out, history, where things live); re-sync `web/docs/`. Build strict.
- [ ] **Step 6: tests:** a harness/browser check that each old deep link lands on the right page; `TestDocsCopiesInSync`. **Step 7:** commit `hub: people & groups live on people.<domain>; audit tab; group links`.

### Task 8: Core callers (if needed)

- [ ] **Step 1:** grep core `tests/e2e` and `ci.yml` for `/api/directory/groups/*/members` on rule groups and for removed UI paths; adapt bodies (manual groups need no change). If nothing needs changing, record that in the ledger and skip.
- [ ] **Step 2:** core CI on `people` green (builds the Hub from `people`).
