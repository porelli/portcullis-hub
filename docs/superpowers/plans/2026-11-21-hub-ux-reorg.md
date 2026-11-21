# Hub UX Reorganisation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reorganise the Hub into six top tabs (Apps · Doctor · Usage · Access · Settings · Audit), give Settings eight deep-linked subtabs, rebuild the Marketplace as a searchable, filterable "+ Add app" view backed by richer manifests, and add a Usage "Share" view of donuts fed by new host-wide, per-volume and worker collection.

**Architecture:**
- **Contract first.** Docs get the changes before any code: the new manifest fields, the catalog routes, the usage JSON additions, the agent's new routes and the Hub's deep links.
- **Data before UI.** Templates schema and validator, then the Hub's manifest parsing and serving. Then usage collection on the primary, then the agent and workers.
- **Then the UI tasks**, each over an API that already exists by then: navigation, Settings, Marketplace, Usage Share.
- **The UI stays vanilla JS.** Donuts are inline SVG built from numbers only. Logos are `<img>` elements pointing at a Hub route that serves sanitised SVG bytes with a strict Content-Type and a sandboxing CSP.

**Tech Stack:**
- Hub: Go and vanilla JS. New direct dependency `github.com/prometheus/procfs` (already indirect at v0.21.1). goldmark + bluemonday stay the Markdown pipeline. `encoding/xml` for the SVG allowlist. `image/png` and `image/jpeg` for screenshots.
- Templates: Python 3 (`tests/validate.py`, jsonschema, markdown-it-py) plus the new pinned `defusedxml`.
- Docs: Zensical, `scripts/generate-app-docs.py`.
- Browser checks: Playwright MCP against a local Hub harness.

**Spec:** `/Volumes/workspace/portcullis/.superpowers-ux3-triage.md` items 3, 4, 6 and 7 (current state and proposals), together with the user's rulings restated in Global Constraints (binding; they override the triage wherever the two differ).

## Global Constraints

- **Branch and worktrees.** Branch `ux2` in all four repos, at `/Volumes/workspace/portcullis/wt-ux2/{portcullis-hub,portcullis-templates,portcullis-docs,portcullis}`. Commit path-only (`git commit -- <paths>`). Other agents have uncommitted files in these worktrees: never stage, stash or revert them. No push until the user asks.
- **Work in flight in the same worktrees.** Each task's **Overlaps** line names the files these two agents also touch. A task with an overlap starts only after that agent's commits are on `ux2` and `git status --short -- <file>` is clean. If the file is still dirty, wait; don't merge by hand.
  - **Stalwart admin view:** `web/mail.js`, `web/mailprovider.js`, the mail badges in `web/index.html`'s Marketplace cards (`data-managed-by-portcullis`), `internal/httpapi/mail_provider.go`, `internal/hub/mail_*.go`, contract §19.13 and `web/docs/`.
  - **ux3 bug fixes:** the CSS for Settings and SSH in `web/index.html`, `web/ssh.js`, `web/servers.js` (the Server card), `web/folders.js` (shared-folder slots), `internal/hub/usage_view.go` (the "running" rule), `internal/hub/override.go` (alias drift).
- **User rulings (binding):**
  - **Top tabs, in order:** `Apps · Doctor · Usage · Access · Settings · Audit`.
    - The Marketplace is the "+ Add app" entry inside Apps, and its deep link `#marketplace` (and `#marketplace?filter=mail`) keeps working.
    - Access holds SSH access and VPN devices, plus sign-in history.
    - The `People ↗` tab is removed (the site bar has People).
  - **Settings has 8 subtabs, each at `#settings/<section>`:**
    | Section | Slug | Contents |
    |---|---|---|
    | Sign-in | `signin` | |
    | Network | `network` | Domains + DNS, Local networks, VPN |
    | Storage | `storage` | Shared folders |
    | Mail | `mail` | |
    | AI | `ai` | |
    | Servers | `servers` | |
    | SSH | `ssh` | the SSH *settings*, moved out of SSH access |
    | Template sources | `sources` | moved out of the Marketplace |
  - **Marketplace:**
    - Search over name, description and tags.
    - Category chips with readable names, in a fixed order.
    - Filters: works here (compat), SSO, AI, multi-instance, no web page, installed.
    - A detail drawer: `notes_html`, the settings summary, capabilities and compat reasons.
    - New optional manifest fields: `homepage`, `long_description` (Markdown, the same pipeline and limits as notes), `logo` (an SVG file in the template folder), `resources` (minimum RAM and disk) and `screenshots`. They are filled for all 52 templates where known.
  - **Usage:** a "Share" view of donuts:
    - CPU (of the host's cores), memory (of host RAM), storage (per app plus core, folders, shared images and free), network and disk IO.
    - Click an app slice for that app's per-container donut.
    - A toggle between the last sample and the 1 h average. The slices include a host-wide "other/free".
    - Inline SVG only, CSP-friendly, no chart library.
    - Workers too: each worker's totals and per-app shares, and per-container volume sizes.
- **Project rules:**
  - Contract first.
  - No back-compat code before a release. No redirects for the removed `#ssh` and `#sources` hashes. Fix the links the Hub itself emits instead.
  - Secrets never reach the UI or the logs.
  - Prefer mature libraries, except for charts.
  - XSS-safe everywhere: `escapeHtml` / `esc()` or `textContent`, `data-*` attributes with delegated listeners, no inline handlers, no `${` template interpolation in Hub scripts.
  - Docker, Podman and Kubernetes parity wherever the data exists. Where it doesn't, the figure is `null`, shown with its reason.
- **SVG logos:**
  - Sanitised by an allowlist at template load. The Hub serves the **re-serialised sanitised bytes**, never the file, from its own route with these headers:
    - `Content-Type: image/svg+xml`
    - `X-Content-Type-Options: nosniff`
    - `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; sandbox`
    - `Cross-Origin-Resource-Policy: same-origin`
  - Logos are only ever used as `<img src>`, never inlined, never put in `innerHTML`, never `<object>` / `<embed>` / `<iframe>`.
- **Values pinned by this plan** (the decisions the rulings leave open; see the commit report):
  | Field / setting | Value |
  |---|---|
  | `long_description` | ≤ 16 KiB, nesting ≤ 16, no hidden characters (the `auth.notes` limits); rendered to `long_description_html` |
  | `logo` | file name `^[a-z0-9][a-z0-9_-]{0,62}\.svg$`, in the template folder itself, ≤ 64 KiB |
  | `screenshots` | ≤ 6 entries `{file, caption}`; `file` `^[a-z0-9][a-z0-9_-]{0,62}\.(png|jpg)$`, ≤ 1 MiB, ≤ 4096×4096; `caption` single line, ≤ 120 characters |
  | `resources` | `{min_memory_mib: 16..1048576, min_disk_gib: 1..65536}`, both optional |
  | Homepage | the existing required `links.website` (all 52 templates have one); no second `homepage` key |
  | Catalog asset routes | `GET /api/catalog/{id}/logo.svg` and `GET /api/catalog/{id}/screenshots/{n}`; `/api/templates/{id}/…` would collide with the method-less `/api/templates/status/` prefix patterns in Go's mux |
  | Usage window | `GET /api/usage?window=last|1h` (default `last`) |
- **Category slugs, labels and order** (Hub `templates.Categories`; the schema's `category` becomes this enum; a community slug outside the list is labelled from the slug and sorted last):
  1. `productivity` Productivity
  2. `communication` Communication
  3. `mail` Mail
  4. `storage` Files & storage
  5. `media` Media
  6. `creative` Creative tools
  7. `home-automation` Home automation
  8. `ai` AI
  9. `finance` Finance
  10. `devops` Developer tools
  11. `monitoring` Monitoring
  12. `networking` Networking
  13. `vpn` VPN
  14. `remote-access` Remote access
  15. `security` Security
  16. `public` Public sites

## Review Focus

1. **A hostile SVG logo** (`<script>`, `<foreignObject>`, `on*=`, `href="javascript:…"`, an external `href`, `<!DOCTYPE>` / `<!ENTITY>`, a `style` element or attribute with `url(http…)`, 10 MiB of nested `<g>`, a UTF-16 file). Expected: the validator and the Hub both refuse the template with the reason, and the Hub never serves bytes that weren't re-serialised from the allowlist. Pinned by Task 4 `TestSanitizeRefuses` and Task 5 `TestCatalogLogoHeaders`.
2. **Links the Hub itself emits after the move.** These must land on the right view and never fall back silently to Apps:
   - MCP hints (`#settings/ai?…`, `#settings/domains?…`, `#sources`);
   - `mail.js`'s `#marketplace?filter=mail`;
   - the Usage CSV links;
   - `#usage/storage`.

   Pinned by Task 11 `TestEmittedHashesRoute`.
3. **Donuts on missing, idle or skewed data.** Expected: "not measured" with the reason, never `NaN` in a path, never a fake 0 slice, and "other" clamped at 0. The cases:
   - every figure `null` (Kubernetes core, a worker with an older agent);
   - every app at 0 CPU (an idle host);
   - apps summing above the host total (samples taken at different instants);
   - a single slice at 100 %, which needs two arcs, because an SVG arc from a point to itself draws nothing.

   Pinned by Task 14 `TestDonutGeometry` (node).
4. **Marketplace search input** with regex metacharacters, `<img onerror>`, a leading or trailing space, uppercase, or no match. Expected:
   - a plain case-insensitive substring match, with no `RegExp` built from the input;
   - the input echoed only through `textContent`;
   - an empty state with a "Clear filters" button;
   - chips and filters combine with AND.

   Pinned by Task 13 `TestMarketplaceSearchNode`.
5. **A worker that is unreachable, or whose agent is one minor version behind** (the new routes answer `404`). Expected:
   - the primary's sweep finishes on time;
   - that worker's apps show `not_measured` "not measured: <server>'s agent is older than the Hub" (or "<server> is unreachable");
   - its host donut is "not measured";
   - nothing blocks for longer than the 12 s sweep budget.

   Pinned by Task 10 `TestWorkerSweepOldAgent` / `TestWorkerSweepUnreachable`.

---

## File structure

**portcullis-docs**
- Modify: `docs/guides/integration-contracts.md`:
  - §3: the new fields, `links.website` as the homepage, the category enum;
  - §6: host procfs reads;
  - §11.7: the catalog fields and asset routes;
  - §11.11: `hosts`, `server`, `window`, `dev`, `services`, workers;
  - §17.4: the agent's usage routes and the usage fixer.
- Modify: `docs/operations/hub.md` (the tabs, Settings sections, Access, Marketplace and Share view) and `scripts/generate-app-docs.py` (renders `long_description`).

**portcullis-templates**
- Modify: `schema/manifest.schema.json`, `tests/validate.py`, `tests/test_validate.py`, `tests/requirements.txt` (`defusedxml`).
- Create: `tests/svgsafe.py` (the same allowlist as the Hub's, as data). `tests/svg_vectors.json`, shared byte for byte with the Hub.
- Modify: the 52 `*/manifest.yaml` files. Create: `<template>/logo.svg` where an upstream SVG logo exists.

**portcullis-hub**
- Create:
  - `internal/svgsafe/svgsafe.go`: `Sanitize([]byte) ([]byte, error)`, the allowlist.
  - `internal/templates/catalog.go`: categories, assets, `Resources`, `Screenshot`, `Links`.
  - `internal/httpapi/catalog.go`: the asset routes.
  - `internal/usage/host.go`: host counters through procfs.
  - `internal/usage/mean.go`: the window averages.
  - `internal/hub/usage_workers.go`: the worker sweep and measurement.
  - `internal/agent/usage.go`: the agent's usage routes.
  - Web: `web/donut.js` (the SVG donut), `web/share.js` (the Share view), `web/marketplace.js` (the client-rendered Marketplace), `web/access.js` (the Access tab), `web/settingsnav.js` (the Settings subtabs).
- Modify:
  - Templates: `internal/templates/manifest.go`, `discover.go`, `validate.go`.
  - Notes: `internal/notes/notes.go` (a field name in errors).
  - HTTP: `internal/httpapi/server.go` (index data, `/api/templates`, `handleStatic` untouched), `internal/httpapi/usage.go` (`window`), `internal/httpapi/mcptools_admin.go` and `mcptools_admin2.go` (emitted hashes).
  - Usage: `internal/hub/usage.go`, `usage_view.go`, `usage_storage.go`, `usage_storage_cache.go`.
  - Agent: `internal/agentapi/routes.go` and `types.go`, `internal/fixerspec/rebuild.go`, `internal/runtime/agent/backend.go`, `internal/agent/projects.go`.
  - Web: `web/index.html` (tabs, Settings markup, routing, the Marketplace block removed), `web/ssh.js` (exports `renderSettings`), `web/usage.js` (the Share view entry and `hosts[server]`), `web/web.go`.
  - Docs: `web/docs/*` (resynced), `CLAUDE.md`.
- Tests:
  - Templates: `internal/templates/catalog_test.go`, `internal/svgsafe/svgsafe_test.go` and `internal/svgsafe/testdata/vectors.json` (the shared copy).
  - HTTP: `internal/httpapi/catalog_test.go`, `internal/httpapi/webui_nav_test.go`, `webui_settingsnav_test.go`, `webui_marketplace_test.go`, `webui_share_test.go`, `webui_access_test.go`.
  - Usage: `internal/usage/host_test.go`, `mean_test.go`, `internal/hub/usage_share_test.go`, `internal/hub/usage_workers_test.go`.
  - Agent: `internal/agent/usage_test.go`, `internal/fixerspec/fixerspec_test.go`.

---

### Task 1: Contract

**Overlaps:** Stalwart admin view (`integration-contracts.md` §19.13 and `web/docs/`). Start after its docs commit lands.

**Files:**
- Modify: `portcullis-docs/docs/guides/integration-contracts.md` (§1 changelog entry, §3, §6 "Resource usage", §11.7 routes table, §11.11, §17.4)
- Modify: `portcullis-hub/web/docs/integration-contracts.md` (resync)

**Interfaces:**
- Produces, for every later task, the field names, routes and texts below (exactly these):
  - **Manifest (§3):**
    - `long_description` (string), `logo` (string), `resources` (`{min_memory_mib, min_disk_gib}`), `screenshots` (`[{file, caption}]`);
    - `links.website` is "the homepage the Marketplace links";
    - `category` is one of the 16 slugs in Global Constraints.
  - **Catalog views** (`GET /api/templates` and the MCP template tools), per template:
    - `manifest.long_description_html`, `manifest.links`;
    - `category_label`, `category_rank` (int, 1-based; unknown = 1000);
    - `routerless` (bool);
    - `logo_url` (`/api/catalog/<id>/logo.svg`, absent without a logo);
    - `screenshot_urls` (list).
  - **Asset routes:** `GET /api/catalog/{id}/logo.svg` and `GET /api/catalog/{id}/screenshots/{n}` (`n` from 0). Hub listener only. `404` for an unknown id, no logo or `n` out of range. The headers are the ones in Global Constraints; screenshots are `image/png` or `image/jpeg`.
  - **Usage (§11.11):**
    - `UsageView.host` is replaced by `hosts`: server id → `UsageHost` (`"primary"` always present).
    - `UsageHost` = `{name, cpus, memory_bytes, cpu_used_cores, mem_used_bytes, blk_read_bps, blk_write_bps, why?}`. Every figure is a number or `null`.
    - Every `Group` gains `server`.
    - `GET /api/usage?window=last|1h` (`400` "window must be last or 1h" for anything else); `window` is echoed in the view.
    - `StorageItem` gains `dev` (number, omitted when unknown) and `services` (`["<service>.<number>"]`, volume and bind items only).
    - `StorageView.disks[]` gains `server`.
    - Network has no host-wide figure: the Hub's `/proc/net/dev` is its own network namespace.
  - **Agent (§17.4)**, rows for `Stats`, `LayerSize`, `ImageSize` and the extra route `HostUsage`:
    | Route | Body |
    |---|---|
    | `GET /v1/containers/{cid}/stats` | `agentapi.UnitStats` |
    | `GET /v1/containers/{cid}/size` | `{"bytes"}` |
    | `GET /v1/images/size?ref=` | `{"bytes"}` |
    | `GET /v1/host/usage` | `agentapi.HostCounters` |

    The fixer's `usage` mode is admitted with label `usage:<target>` for a bundled project's volume or a bind under the bind roots. A Hub that gets `404` from these routes treats the worker as "older than the Hub".
  - **§6:** the Hub (and the agent) read `/proc/stat`, `/proc/meminfo` and `/proc/diskstats` of their own procfs. That is no host collector and no new mount. On Kubernetes, `hosts.primary` figures are `null` "not measured on Kubernetes".

- [ ] **Step 1:** Write the contract text for each bullet above, in each section's existing style. Use **NEW (ux3)** markers and add a §1 changelog line. Merge order: docs → templates → Hub; no version bump (the fields are optional, and the routes and usage fields are new).
- [ ] **Step 2:** In §3 also describe the SVG allowlist:
  - **Elements:** `svg g path circle ellipse rect line polyline polygon defs linearGradient radialGradient stop clipPath mask use symbol title desc`.
  - **Attributes:** geometry, presentation (`fill stroke stroke-* opacity fill-opacity fill-rule clip-rule transform viewBox width height x y x1 y1 x2 y2 cx cy r rx ry d points offset stop-color stop-opacity gradientUnits gradientTransform id clip-path mask preserveAspectRatio xmlns xmlns:xlink`) and `href` / `xlink:href` only as `#<id>`.
  - **Paint values:** `url(#<id>)` is allowed in paint values; any other `url(` is refused.
  - **Refused outright:** a DOCTYPE, an entity, a processing instruction other than the XML declaration, CDATA, `style`, `on*`, and any namespace other than SVG and XLink.
  - **Root:** must be `svg` with a `viewBox`. Encoding UTF-8 only.
- [ ] **Step 3:** Run `cd /Volumes/workspace/portcullis/wt-ux2/portcullis-docs && zensical build --strict 2>&1 | tail -3` → no warnings. Run `python3 scripts/check-lists.py` → OK.
- [ ] **Step 4:** Commit the docs (`contract §3/§6/§11.7/§11.11/§17.4 (ux3): …`). Then in the Hub run `PORTCULLIS_DOCS_DIR=/Volumes/workspace/portcullis/wt-ux2/portcullis-docs sh web/docs/sync.sh`, then `PORTCULLIS_DOCS_DIR=… go test ./web -run TestDocsCopiesInSync` → PASS. Commit `web/docs/integration-contracts.md` path-only.

### Task 2: Templates schema and validator

**Overlaps:** none (templates repo; the Stalwart agent's templates commit 14513d3 is already in).

**Files:**
- Modify: `portcullis-templates/schema/manifest.schema.json`, `tests/validate.py`, `tests/requirements.txt` (add `defusedxml==0.7.1`)
- Create: `tests/svgsafe.py`, `tests/svg_vectors.json`
- Test: `tests/test_validate.py`

**Interfaces:**
- Consumes: Task 1 §3.
- Produces:
  - `svgsafe.check(data: bytes) -> Optional[str]` (None = OK, else the reason);
  - `tests/svg_vectors.json`, a list of `{"name", "svg", "ok", "reason"?}` that Task 4 copies byte for byte;
  - the validator codes below.

- [ ] **Step 1: Write the failing tests** in `test_validate.py`. Their names, and what each asserts:
  - `TestLongDescription`: shares the `auth.notes` cases (html_block, image, a `javascript:` link, 16 KiB + 1, depth 17, U+200B). Each error names `long_description`.
  - `TestLogo`:
    - accepted: `logo: logo.svg` with a clean file;
    - refused with "logo: file not found": `logo: ../x.svg`, `logo: sub/logo.svg`, `logo: logo.png`, a missing file;
    - refused with "logo: over 64 KiB": a file over 64 KiB;
    - every entry of `svg_vectors.json` with `ok: false` is refused with its `reason`, and every `ok: true` entry is accepted.
  - `TestScreenshots`:
    - 7 entries refused;
    - a `.gif` refused;
    - a PNG over 1 MiB refused;
    - a file whose magic bytes don't match its extension refused with "screenshots[0]: not a PNG";
    - a caption with a newline refused.
  - `TestResources`: `min_memory_mib: 0` refused, `min_disk_gib: 70000` refused, `{}` accepted, an unknown key refused (schema `additionalProperties: false`).
  - `TestCategoryEnum`: `category: other` is refused, listing the 16 slugs.
- [ ] **Step 2:** Run `cd /Volumes/workspace/portcullis/wt-ux2/portcullis-templates && python3 -m pytest tests/test_validate.py -k "LongDescription or Logo or Screenshots or Resources or CategoryEnum" -q` → FAIL.
- [ ] **Step 3: Implement.**
  - Schema: the four properties, and `category.enum`.
  - `validate.py`:
    - `check_long_description(t, r)` reuses the notes checks with a `field` parameter (refactor `check_notes` → `check_markdown(t, r, field, text)`).
    - `check_logo(t, r)` → `svgsafe.check`.
    - `check_screenshots(t, r)` checks the magic bytes and reads the dimensions from the PNG IHDR / JPEG SOF headers (stdlib only; no Pillow).
  - `svgsafe.py`: parse with `defusedxml.ElementTree.fromstring(data, forbid_dtd=True)` and walk it against the Task 1 allowlist.
  - `svg_vectors.json`: at least 20 vectors, one per Review Focus 1 item, plus the clean cases (a gradient, `use href="#a"`, `url(#g)`).
- [ ] **Step 4:** Run the same pytest command, then `python3 tests/validate.py` over the repo → PASS. No existing template fails yet: all fields are optional, and every current category is in the enum.
- [ ] **Step 5:** Commit `schema/ tests/` path-only (`validate.py: long_description, logo, screenshots, resources, the category enum (contract §3, ux3)`).

### Task 3: Fill the 52 manifests

**Overlaps:** `stalwart/manifest.yaml` was last changed by the Stalwart agent; take it as committed.

**Files:**
- Modify: `*/manifest.yaml` (52)
- Create: `<template>/logo.svg` (where an upstream SVG exists)

**Interfaces:**
- Consumes: Task 2's validator.

- [ ] **Step 1:** For each template, add `long_description`. Write it as a YAML literal block, 2–5 short paragraphs: what the app is, what it's good for, what Portcullis wires (SSO, groups, AI, VPN, mail). Never copy `auth.notes`; the drawer shows both.
- [ ] **Step 2:** Add `resources` from the upstream documented minimums only. Leave the key out when upstream doesn't document one, and list those templates in the commit message.
- [ ] **Step 3:** Add `logo: logo.svg` where the project publishes an SVG logo in its own repository or press kit. Take the file from the URL under `links.website` / `links.source`, run it through `svgsafe.check`, and simplify it by hand if it is refused (strip `style`, inline the paint). Record each logo's source URL in `CHANGELOG.md` under the ux3 entry. Logos stay the projects' trademarks, used to identify them. Emoji `icon` stays for templates without one.
- [ ] **Step 4:** Leave `screenshots` out everywhere: the repo has no screenshots and none are taken in this plan. Say so in the commit message.
- [ ] **Step 5:** Run `python3 tests/validate.py && python3 -m pytest tests -q` → PASS. Check that `grep -L '^long_description:' */manifest.yaml` prints nothing.
- [ ] **Step 6:** Commit path-only (`templates: long_description for all 52, resources and logo.svg where upstream documents them (ux3)`).

### Task 4: Hub SVG sanitiser

**Overlaps:** none.

**Files:**
- Create: `internal/svgsafe/svgsafe.go`, `internal/svgsafe/svgsafe_test.go`, `internal/svgsafe/testdata/vectors.json` (a byte copy of templates `tests/svg_vectors.json`)

**Interfaces:**
- Produces: `func Sanitize(data []byte) ([]byte, error)`. It returns re-serialised bytes containing only allowlisted elements and attributes, or an error whose text is the vector's `reason`. `const MaxBytes = 64 << 10`.

- [ ] **Step 1: Write the failing tests:**
  - `TestSanitizeVectors` iterates `testdata/vectors.json`: `ok` vectors pass; for `!ok`, the error text equals `reason`.
  - `TestSanitizeRefuses` adds the Review Focus 1 inputs: a UTF-16 BOM, a `<!ENTITY` bomb, 10 000 nested `<g>` (depth cap 64), `xlink:href="data:…"`, `fill="url(https://x)"`.
  - `TestSanitizeOutputReparses`: the output parses again to the same output (idempotent) and contains no `<script`, `on` attributes or `href` other than `#…`.
  - `TestVectorsInSync` (only when `PORTCULLIS_TEMPLATES_DIR` is set) compares the testdata copy with the templates repo's file.
- [ ] **Step 2:** Run `go test ./internal/svgsafe/` → FAIL (package missing).
- [ ] **Step 3:** Implement `Sanitize` with an `encoding/xml` `Decoder` (`Strict = true`, `CharsetReader` nil, so non-UTF-8 is refused) and an `Encoder` writing only the allowed tokens:
  - refuse any `xml.Directive`, any `xml.ProcInst` other than the leading `xml` declaration, and any element or attribute outside the lists;
  - cap the depth at 64;
  - text is kept only inside `title` and `desc`.

  No suitable mature Go SVG sanitiser exists (bluemonday is HTML-only), so the allowlist is data in this file and in the shared vectors.
- [ ] **Step 4:** Run `go test ./internal/svgsafe/ && PORTCULLIS_TEMPLATES_DIR=/Volumes/workspace/portcullis/wt-ux2/portcullis-templates go test ./internal/svgsafe/ -run TestVectorsInSync` → PASS.
- [ ] **Step 5:** Commit path-only (`svgsafe: allowlist SVG sanitiser for template logos, shared vectors (contract §3, ux3)`).

### Task 5: Hub manifest parsing and catalog serving

**Overlaps:** Stalwart admin view (`internal/httpapi/server.go` is not theirs, but `mcptools_admin*.go` may be: check `git status`).

**Files:**
- Create: `internal/templates/catalog.go`, `internal/templates/catalog_test.go`, `internal/httpapi/catalog.go`, `internal/httpapi/catalog_test.go`
- Modify: `internal/templates/manifest.go` (Manifest, Template), `internal/templates/discover.go` (`build`), `internal/templates/validate.go` (`ValidateManifest`), `internal/notes/notes.go` (`CheckField`), `internal/httpapi/server.go` (route registration)

**Interfaces:**
- Consumes: `svgsafe.Sanitize` (Task 4), `notes.Render` / `notes.Check`.
- Produces:
  - Manifest fields:
    - `Links *Links` (`yaml:"links" json:"links,omitempty"`), where `Links{Website string; Source *string; SourceNote string}` (`json:"website"`, `"source"`, `"source_note,omitempty"`);
    - `LongDescription string` (`json:"long_description,omitempty"`), `LongDescriptionHTML string` (`yaml:"-" json:"long_description_html,omitempty"`);
    - `Logo string`, `Resources *Resources{MinMemoryMiB int; MinDiskGiB int}` (`json:"min_memory_mib,omitempty"`, `"min_disk_gib,omitempty"`), `Screenshots []Screenshot{File, Caption string}`.
  - Template fields: `CategoryLabel string json:"category_label"`, `CategoryRank int json:"category_rank"`, `Routerless bool json:"routerless"`, `LogoURL string json:"logo_url,omitempty"`, `ScreenshotURLs []string json:"screenshot_urls,omitempty"`, and the unexported `logoSVG []byte`, `shots [][]byte`, `shotTypes []string`.
  - `func (t *Template) LogoSVG() []byte` and `func (t *Template) Screenshot(n int) (data []byte, contentType string, ok bool)`.
  - `var Categories = []Category{{Slug, Label}}` (the 16, in order); `func CategoryOf(slug string) (label string, rank int)`.
  - `func notes.CheckField(field, text string) error`; `notes.Check` becomes `CheckField("auth.notes", …)`.
  - `func (h *hub.Hub) CatalogTemplate(id string) (templates.Template, bool)`. If no lookup exists, use `Templates()` filtered by id.

- [ ] **Step 1: Write the failing tests:**
  - `TestCategoryOf`: `("home-automation")` → `("Home automation", 7)`; `("weird-thing")` → `("Weird thing", 1000)`.
  - `TestBuildLongDescription`: a manifest with `long_description` carrying a `<script>` line → the template is refused with "long_description: …raw HTML…". A clean one → `LongDescriptionHTML` contains `<p>` and links carry `rel="noopener noreferrer nofollow"`.
  - `TestBuildLogo`:
    - a valid `logo.svg` → `LogoURL == "/api/catalog/<id>/logo.svg"`, and `LogoSVG()` equals `svgsafe.Sanitize(file)`;
    - `logo: ../etc/passwd` → refused "logo: …";
    - a symlinked `logo.svg` → refused "logo: not a regular file" (`os.Lstat`);
    - a file over 64 KiB → refused.
  - `TestBuildScreenshots`: PNG and JPEG accepted with the right content types; a PNG named `.jpg` → refused; 7 entries → refused.
  - `TestTemplatesJSONFields`: `GET /api/templates` includes `category_label`, `category_rank`, `routerless`, `links`, `long_description_html`, and **never** the raw bytes.
  - `TestCatalogLogoHeaders`:
    - `GET /api/catalog/<id>/logo.svg` → 200 with exactly the Global Constraints headers (plus `Cache-Control: no-cache`), and the body equals the sanitised bytes;
    - an unknown id, a template without a logo and `/api/catalog/<id>/logo.svg/x` → 404;
    - on the people listener → 404.
  - `TestCatalogScreenshot`: `n=0` → 200 `image/png`; `n=1` with one entry → 404; `n=-1` or `n=abc` → 404.
- [ ] **Step 2:** Run `go test ./internal/templates/ ./internal/httpapi/ -run 'CategoryOf|BuildLongDescription|BuildLogo|BuildScreenshots|TemplatesJSONFields|CatalogLogo|CatalogScreenshot'` → FAIL.
- [ ] **Step 3: Implement:**
  - In `build`, after `ValidateManifest`:
    - render `long_description` like the notes;
    - load the logo and screenshots with `os.Lstat` (regular file), size-capped reads and `svgsafe.Sanitize` / `image.DecodeConfig`;
    - set the category label and rank, `Routerless` from `m.Routerless()`, and the URLs.
  - `ValidateManifest` checks the field shapes (the regexes and bounds from Global Constraints) before any file read.
  - `internal/httpapi/catalog.go` registers `GET /api/catalog/{id}/logo.svg` and `GET /api/catalog/{id}/screenshots/{n}` on the Hub mux only.
- [ ] **Step 4:** Run the same tests, then `go test ./internal/templates/ ./internal/httpapi/ ./internal/hub/ -run 'RealTemplates|Golden'` with `PORTCULLIS_TEMPLATES_DIR` pointing at the templates worktree → PASS. The 52 real templates load with their new fields.
- [ ] **Step 5:** Commit path-only (`templates: links, long_description(_html), logo, screenshots, resources, category labels; /api/catalog/{id}/logo.svg and screenshots with a sandboxing CSP (contract §3, §11.7, ux3)`).

### Task 6: Host-wide usage sample on the primary

**Overlaps:** ux3 bug fixes (`internal/hub/usage_view.go`, the "running" rule). Start after it lands.

**Files:**
- Create: `internal/usage/host.go`, `internal/usage/host_test.go`, `internal/usage/testdata/proc/` (fixture `stat`, `meminfo`, `diskstats`)
- Modify: `go.mod` (`github.com/prometheus/procfs` direct), `internal/hub/usage.go` (`usageState`: `host *usage.HostCounters`, `hostRing *usage.HostRing`), `internal/hub/usage_view.go` (`UsageView.Hosts`, `UsageHost`, `UsageGroup.Server`), `internal/httpapi/mcptools_*.go` if a usage tool reads `Host` (compile errors will point)
- Test: `internal/hub/usage_share_test.go`

**Interfaces:**
- Produces:
  - `type HostCounters struct{ At time.Time; CPUTotal, CPUIdle uint64 /* USER_HZ ticks */; MemTotal, MemAvailable int64; DiskRead, DiskWrite uint64 /* bytes */ }`;
  - `func ReadHost(fs procfs.FS, bfs blockdevice.FS) (HostCounters, error)`;
  - `type HostSample struct{ CPUUsedCores *float64; MemUsedBytes *int64; BlkReadBps, BlkWriteBps *float64 }`;
  - `func DeriveHost(prev *HostCounters, cur HostCounters, cpus int) HostSample`;
  - `type HostRing` (`RingSize` points of `{T, HostSample}`).
  - `UsageView.Hosts map[string]UsageHost` (the `host` field is removed), with `UsageHost{Name string; CPUs *int; MemoryBytes *int64; CPUUsedCores *float64; MemUsedBytes *int64; BlkReadBps, BlkWriteBps *float64; Why string}`. `UsageGroup.Server string` is `"primary"` here (Task 10 fills workers).

- [ ] **Step 1: Write the failing tests:**
  - `TestReadHostFixture` reads `testdata/proc` → the exact counters from the fixture.
  - `TestDeriveHost`:
    - two counters 15 s apart with 1500 idle of 3000 ticks on 2 CPUs → `CPUUsedCores == 1.0`;
    - MemUsed = Total − Available;
    - disk bytes over 15 s → Bps;
    - a nil prev, a counter that goes down, or dt < `MinInterval` → rates `nil`, MemUsed still set.
  - `TestUsageHostsPrimary`: after two fake sweeps, `UsageOverview().Hosts["primary"]` has `cpu_used_cores` and `mem_used_bytes`, and each app has `server: "primary"`.
  - `TestUsageHostsKubernetes`: with a kube kind every host figure is `nil` and `Why == "not measured on Kubernetes"`.
- [ ] **Step 2:** Run `go test ./internal/usage/ ./internal/hub/ -run 'ReadHost|DeriveHost|UsageHosts'` → FAIL.
- [ ] **Step 3: Implement.**
  - `ReadHost` reads with `procfs.NewFS("/proc")`: `Stat().CPUTotal`, `Meminfo()`, and diskstats through `blockdevice` (whole disks only, no partitions, sectors × 512).
  - `usageSweep` reads the host once per sweep through a `usageState.readHost` hook (tests inject one), keeps the previous counters, derives, and adds the result to `hostRing`.
  - `UsageOverview` fills `Hosts["primary"]`, `Name` = the primary's server name.
  - Update `web/usage.js`'s `v.host` reads to `v.hosts[g.server || 'primary']`. That is the one-line consumer change; the UI tests must stay green.
- [ ] **Step 4:** Run `go test ./internal/usage/ ./internal/hub/ ./internal/httpapi/` → PASS.
- [ ] **Step 5:** Commit path-only (`usage: host-wide CPU, memory and disk IO from procfs; UsageView.hosts keyed by server, Group.server (contract §11.11, ux3)`).

### Task 7: The 1 h window

**Overlaps:** as Task 6 (`usage_view.go`).

**Files:**
- Create: `internal/usage/mean.go`, `internal/usage/mean_test.go`
- Modify: `internal/hub/usage_view.go` (`UsageOverview(window string)`), `internal/httpapi/usage.go` (`handleUsage` parses `window`), the usage MCP tool (passes `last`)

**Interfaces:**
- Consumes: `Ring.Since`, `HostRing` (Task 6).
- Produces:
  - `func Mean(ps []Point) (Sample, bool /*partial*/)`;
  - `func MeanHost(ps []HostPoint) (HostSample, bool)`;
  - `func (h *Hub) UsageOverview(window string) UsageView` (`"last"` or `"1h"`), with `UsageView.Window string json:"window"`.

- [ ] **Step 1: Write the failing tests:**
  - `TestMeanSkipsNulls`: points `[1, nil, 3]` → mean 2, partial true; all nil → nil, partial true; empty → nil.
  - `TestMeanLimitsFromLast`: the limits come from the newest point, never averaged.
  - `TestUsageWindow1h`: four sweeps → each container's `sample` and the group totals are the means; `hosts.primary` is the host mean.
  - `TestUsageWindowParam`: `GET /api/usage?window=1h` → 200 `window: "1h"`; `?window=5m` → 400 "window must be last or 1h"; `?window=1h&window=last` → 400.
- [ ] **Step 2:** Run `go test ./internal/usage/ ./internal/hub/ ./internal/httpapi/ -run 'Mean|UsageWindow'` → FAIL.
- [ ] **Step 3:** Implement. In 1h mode, each container's sample is `Mean(ring.Since(now-1h))`, and the totals sum those means with the existing `Total`.
- [ ] **Step 4:** Run the same tests → PASS.
- [ ] **Step 5:** Commit path-only (`usage: ?window=1h averages from the rings (contract §11.11, ux3)`).

### Task 8: Storage per container and per disk

**Overlaps:** ux3 bug fixes, if it touches `usage_storage.go`; check `git status`.

**Files:**
- Modify: `internal/hub/usage_storage.go` (`storageModel`, `storageTargets`), `internal/hub/usage_storage_cache.go`, `internal/hub/usage_view.go` (`StorageItem.Dev`, `StorageItem.Services`)
- Test: `internal/hub/usage_storage_test.go`

**Interfaces:**
- Consumes: `usageCont.Mounts` (the sampler's inspects).
- Produces:
  - `StorageItem.Dev *uint64 json:"dev,omitempty"`;
  - `StorageItem.Services []string json:"services,omitempty"` (sorted `"<service>.<number>"`);
  - `DiskView.Server string json:"server"`.

- [ ] **Step 1: Write the failing tests:**
  - `TestStorageItemServices`: two containers of one instance mount volume `portcullis-paperless_data`, one of them also binds `/srv/x` → the volume item's `services == ["web.1", "worker.1"]` and the bind item's `== ["web.1"]`. Layers keep `target` = service with no `services`.
  - `TestStorageItemDev`: a measured item carries its report's `dev`; never-measured items omit it.
  - `TestStorageDisksServer`: every disk has `server: "primary"`.
- [ ] **Step 2:** Run `go test ./internal/hub/ -run 'StorageItemServices|StorageItemDev|StorageDisksServer'` → FAIL.
- [ ] **Step 3:** Implement. In `storageModel`, build the volume/bind → services map from the sampler's `usageCont` snapshot under `usage.mu` (read lock). Copy `Dev` from the cache entry.
- [ ] **Step 4:** Run `go test ./internal/hub/ -run 'Storage'` → PASS.
- [ ] **Step 5:** Commit path-only (`usage: storage items name the containers that mount them, carry their filesystem; disks name their server (contract §11.11, ux3)`).

### Task 9: Agent usage routes

**Overlaps:** none (`internal/agent*`, `internal/fixerspec`).

**Files:**
- Create: `internal/agent/usage.go`, `internal/agent/usage_test.go`
- Modify: `internal/agentapi/routes.go` (the `Stats`, `LayerSize`, `ImageSize` entries; `ExtraRoutes["HostUsage"]`), `internal/agentapi/types.go` (`UnitStats`, `SizeBody{Bytes int64}`, `HostCounters`), `internal/agent/projects.go` (registration), `internal/fixerspec/rebuild.go` (admit `usage:`), `internal/runtime/agent/backend.go` (`Stats`, `LayerSize`, `ImageSize` call the routes, plus `HostUsage`)
- Test: `internal/agentapi/routes_test.go` (`TestRoutesCoverInstances` stays green), `internal/fixerspec/fixerspec_test.go`

**Interfaces:**
- Consumes: `usage.ReadHost` (Task 6), `runtime.UnitStats`.
- Produces:
  - `func (b *agentrt.Backend) HostUsage(ctx) (usage.HostCounters, error)`.
  - `agentrt.ErrOlderAgent`: returned when a usage route answers 404. Its `Error()` is "the worker's agent is older than the Hub".
  - The agent backend's `Stats`, `LayerSize` and `ImageSize` now return real figures.

- [ ] **Step 1: Write the failing tests:**
  - `TestAgentStatsScope`: `GET /v1/containers/{cid}/stats` for a bundled project's container → 200 `UnitStats`; for a container outside scope → 403; with a `link.control` cert → 403.
  - `TestAgentLayerAndImageSize`: an image ref not in any bundle's model → 403; the container size → `{"bytes": n}`.
  - `TestAgentHostUsage`: returns the counters from an injected procfs fixture.
  - `TestRebuildUsage`:
    - a `usage:` spec for a bundled project's volume → accepted;
    - a bind outside the roots → refused;
    - the volume of a project the agent doesn't hold → refused "volume … is not a bundled project's";
    - label `usage:` with mode `scan` → refused.
  - `TestBackendStatsOldAgent`: a fake agent answering 404 → `errors.Is(err, agentrt.ErrOlderAgent)`.
  - Caps: JSON bodies ≤ `MaxJSON`, decoded strictly (`TestAgentUsageStrictDecode`: an unknown field in the response → error).
- [ ] **Step 2:** Run `go test ./internal/agent/ ./internal/agentapi/ ./internal/fixerspec/ ./internal/runtime/agent/` → FAIL.
- [ ] **Step 3: Implement:**
  - The handlers use the existing scope checks (the `List` row's scope for containers, the `Pull` row's for image refs).
  - `Rebuild` gains a `usage:` label branch. Its volume check is a hook `volumeInScope func(name string) bool`, which the agent passes.
  - The agent reads procfs with `procfs.NewFS("/proc")` (the agent container's own, as for the Hub).
- [ ] **Step 4:** Run the same packages, then `go vet ./...` → PASS.
- [ ] **Step 5:** Commit path-only (`agent: stats, layer and image sizes, host usage, the usage fixer on workers (contract §17.4, ux3)`).

### Task 10: Sampling and measuring workers

**Overlaps:** ux3 bug fixes (`usage.go`, `usage_view.go`); `web/servers.js` is untouched here.

**Files:**
- Create: `internal/hub/usage_workers.go`, `internal/hub/usage_workers_test.go`
- Modify: `internal/hub/usage.go` (`usageSweep` calls `sweepWorkers`), `internal/hub/usage_view.go` (worker hosts and groups), `internal/hub/usage_storage.go` (`measureStorage` per server; worker disks from `/v1/info`)

**Interfaces:**
- Consumes:
  - `rtForServer` and the servers registry (`h.reg()`);
  - from Task 9: `agentrt.Backend.HostUsage`, `Stats`, `LayerSize`, `ImageSize`, `ErrOlderAgent`;
  - `rtFor(id)`, which gives each instance's server.
- Produces:
  - `Hosts[<server id>]` for every ready worker, and `UsageGroup.Server` = the instance's server;
  - for a failing worker, its groups get `status: "not_measured"` with `why` "not measured: <name>'s agent is older than the Hub" or "not measured: <name> is unreachable";
  - worker volumes in `StorageView.apps[].items` with `dev` and `services`, and `disks[]` with `server: <id>`.

- [ ] **Step 1: Write the failing tests** (fake servers with `runtimetest.Fake` behind a fake agent backend):
  - `TestWorkerSweepTotals`: two apps on worker `w1` → `Hosts["w1"]` has `cpus`, `memory_bytes`, `cpu_used_cores`; both groups have `server: "w1"` and summed totals.
  - `TestWorkerSweepOldAgent`: `w1` answers `ErrOlderAgent` → its groups are `not_measured` with the "older" text, its host figures are `nil` with that `why`, and the primary's groups are unaffected.
  - `TestWorkerSweepUnreachable`: a backend that blocks → the sweep still returns within `usage.SweepBudget` plus 1 s (fake clock), with the "unreachable" text.
  - `TestWorkerMeasureVolumes`: `measureStorage` measures `w1`'s volumes through `RunFixer` on `w1`'s backend, never the primary's.
  - `TestWorkerSweepMaxContainers`: the 256 cap counts primary + workers together.
- [ ] **Step 2:** Run `go test ./internal/hub/ -run 'WorkerSweep|WorkerMeasure'` → FAIL.
- [ ] **Step 3:** Implement. Each ready worker is swept in parallel with the primary's stats (one goroutine per server, each under the `Parallel` = 4 limit and `StatsTimeout`), all within the sweep's budget. Rings are keyed `<server>/<group>/<service>.<number>`.
- [ ] **Step 4:** Run `go test -race ./internal/hub/ -run 'Usage|Storage|Worker'` → PASS.
- [ ] **Step 5:** Commit path-only (`usage: workers sampled and measured through the agent; per-server hosts and disks (contract §11.11, §17.4, ux3)`).

### Task 11: Top tabs, routing and the Access tab

**Overlaps:**
- ux3 bug fixes: the Settings/SSH CSS in `web/index.html`, and `web/ssh.js`.
- Stalwart admin view: `web/index.html`.

Start after both land.

**Files:**
- Create: `web/access.js`, `internal/httpapi/webui_nav_test.go`, `internal/httpapi/webui_access_test.go`
- Modify: `web/index.html` (the tabs markup, `showTab`, `routeHash`, the `#tab-access` container; the `data-people-link` tab removed), `web/ssh.js` (`SECTIONS` without `settings`; exports `renderSettings(box)`), `web/web.go` (embed `access.js`), `internal/httpapi/mcptools_admin2.go` (`#sources` → `#settings/sources`, `#settings/domains?` → `#settings/network?`)

**Interfaces:**
- Consumes: `GET /api/vpn/devices`, `DELETE /api/vpn/devices/{id}`, `GET /api/directory/users/{u}/signin/history`, `PortcullisSSH`.
- Produces:
  - `window.PortcullisAccess.render(root, section)`, with `section` ∈ `ssh` (default), `vpn`, `signins`.
  - Hashes:
    - `#access[/ssh[/<ssh-section>]]`, `#access/vpn`, `#access/signins[?user=<name>]`;
    - `#apps`, `#doctor`, `#usage[/<view>]`, `#settings[/<section>]`, `#audit`;
    - `#marketplace[?filter=mail]` and `#marketplace/<template-id>` (Task 13 renders these; here they route to `showTab('apps')` plus `PortcullisMarketplace.open(...)` once it exists).
  - `window.PortcullisSSH.renderSettings(box)`, for Task 12.

- [ ] **Step 1: Write the failing tests:**
  - `TestTopTabsOrder`: the `.tab[data-tab]` values in `index.html`, in order, are exactly `apps doctor usage access settings audit`. No `data-people-link`, and no `data-tab="marketplace"` or `data-tab="ssh"`.
  - `TestAccessJSSafe`: the `usage.js`-style scan (no `innerHTML` with data, no inline handlers, no `${`). Device names and owners are set with `textContent`. There is no key material field name (`private`, `public_key`, `config`) anywhere in `access.js`.
  - `TestAccessVPNRemoveConfirms`: Remove asks `confirm()` with the device's name, then sends `DELETE`.
  - `TestEmittedHashesRoute`: collect every `#…` hash literal from `internal/**/*.go` (non-test) and `web/*.js` / `web/index.html` with a regex. Each one must match a pattern in `routeHash`'s table, which becomes a `const ROUTES = [...]` array of regexes so the test can read it.
  - `TestRouteHashNode` (node, skipped without it) loads `routeHash` with stubbed `showTab` and asserts:
    - `#access/vpn` → `showTab('access')` with section `vpn`;
    - `#ssh` → Apps (no redirect, per the no-back-compat rule);
    - `#marketplace?filter=mail` → apps + marketplace(mail).
- [ ] **Step 2:** Run `go test ./internal/httpapi/ -run 'TopTabsOrder|AccessJS|AccessVPN|EmittedHashes|RouteHashNode'` → FAIL.
- [ ] **Step 3: Implement:**
  - **Access** gets three subtabs: SSH (the existing `PortcullisSSH.render`, minus Settings), VPN devices, and Sign-in history.
  - **VPN devices** is a table: person (a `PortcullisPeople` link), device, provider label, address, last seen, expires, online. Remove appears only when `managed`.
  - **Sign-in history** is a username picker using the people picker in `directory.js` (`PortcullisDirectory.pickUser` if present; otherwise a text input validated `^[a-z0-9._-]{1,64}$`). The picker loads the per-person endpoint, renders its rows with `textContent`, and pages with "Older". A server-wide feed is out of scope: no such API exists.
  - **SSH access** shows a link "SSH settings → `#settings/ssh`".
  - **Routing:** `routeHash` becomes table-driven (`ROUTES`).
- [ ] **Step 4:** Run `go test ./internal/httpapi/ ./web/` → PASS.
- [ ] **Step 5: Browser check.** Use the Playwright MCP against the local harness (the `run` skill or the previous plans' `/tmp/pwcheck` harness). Take 1400×900 screenshots of `#apps`, `#access/ssh`, `#access/vpn` (with two fake devices) and `#access/signins?user=alice`. The console must be clean. Save them to `/Volumes/workspace/portcullis/.superpowers/sdd/2026-11-21-hub-ux-reorg/screens/`.
- [ ] **Step 6:** Commit path-only (`ui: top tabs Apps · Doctor · Usage · Access · Settings · Audit; Access (SSH, VPN devices, sign-in history); People tab removed; table-driven routes (ux3)`).

### Task 12: Settings subtabs

**Overlaps:**
- ux3 bug fixes: the Settings CSS, `web/folders.js`, `web/servers.js`.
- Stalwart admin view: `web/mail.js`, `web/mailprovider.js` (only mounted here, not edited).

Start after both land.

**Files:**
- Create: `web/settingsnav.js`, `internal/httpapi/webui_settingsnav_test.go`
- Modify: `web/index.html` (the `#tab-settings` markup becomes a subtab bar plus one `<section data-settings-section="<slug>">` per section; `showTab('settings')` loads only the visible one; the template-sources markup moves here from `#tab-marketplace`), `web/web.go`

**Interfaces:**
- Consumes: `PortcullisSignIn.mount`, `loadDomains`, `PortcullisFolders.render` / `renderLocalNetworks`, `loadVPNSettings`, `PortcullisMail.render`, `PortcullisServers.render`, `loadAISettings`, `PortcullisSSH.renderSettings` (Task 11), `loadSourceSync` and the source handlers (`data-src-add`, `data-src-remove`, `data-src-sync`).
- Produces:
  - `window.PortcullisSettingsNav.show(section, query)`. `section` ∈ `signin network storage mail ai servers ssh sources`; an unknown section → `signin`.
  - `openSettingsForm(kind, q)` accepts `network` (the domains forms) and `ai`.

- [ ] **Step 1: Write the failing tests:**
  - `TestSettingsSectionsOrder`: the subtab buttons read, in order, `Sign-in, Network, Storage, Mail, AI, Servers, SSH, Template sources`, with `data-settings-tab` slugs as in Global Constraints.
  - `TestSettingsNetworkHolds`: the `network` section contains `#domains-root`, `#localnets-root` and `#vpn-settings-root`, in that order. `storage` contains `#folders-root`. `sources` contains `#sources-list`. `#tab-marketplace` no longer exists in `index.html`.
  - `TestSettingsLazyLoadNode` (node): `show('mail')` calls only `PortcullisMail.render`; a second `show('mail')` re-renders (each visit loads fresh, as today); `show('ai')` doesn't call `loadDomains`.
  - `TestSettingsDeepLinksNode`:
    - `#settings/network?add=example.org` opens the add-domain form pre-filled;
    - `#settings/ai?provider=openai&field=api_key` opens the provider secret form;
    - `#settings/bogus` → `signin`, with the hash replaced by `#settings/signin`.
  - `TestSourcesFormsStillWork`: the delegated handlers for `data-src-add`, `data-src-remove` and `data-src-sync` are bound on `document`, not on `#tab-marketplace`.
- [ ] **Step 2:** Run `go test ./internal/httpapi/ -run 'Settings|SourcesForms'` → FAIL.
- [ ] **Step 3:** Implement. Template sources become client-rendered from the existing `GET /api/sources` (every name and URL through `esc`), and `handleIndex` drops `Sources`. The subtab bar is `role="tablist"` with arrow-key navigation, and each change does `history.replaceState(…'#settings/'+slug)`. Leaving a section with unsaved fields keeps the existing `leavePageOK` behaviour only for instance pages: Settings sections save per form today, so there is no new guard.
- [ ] **Step 4:** Run `go test ./internal/httpapi/ ./web/` → PASS.
- [ ] **Step 5: Browser check.** Screenshots of each of the 8 sections at 1400×900 and one at 390×844 (mobile). The page height of `#settings/network` is under 2,500 px. The console is clean. Save to the screens folder.
- [ ] **Step 6:** Commit path-only (`ui: Settings in 8 subtabs with #settings/<section> deep links, only the shown one loads; SSH settings and template sources moved in (ux3)`).

### Task 13: Marketplace as "+ Add app"

**Overlaps:**
- Stalwart admin view: the mail badges (`data-managed-by-portcullis`) are rebuilt here in JS. Keep their text and title verbatim from the landed version.
- ux3 bug fixes: `web/index.html`.

Start after both land.

**Files:**
- Create: `web/marketplace.js`, `internal/httpapi/webui_marketplace_test.go`
- Modify:
  - `web/index.html`: the server-rendered `{{range $category, $apps := .Categories}}` block is deleted, and so are `filterMarketplace` and `fillMarketplace`, whose logic moves to `marketplace.js`. The Apps header gains a "+ Add app" button (`data-add-app`). Add `<div id="mkt-root" hidden>` inside `#tab-apps`, and a `<dialog id="mkt-drawer">`.
  - `internal/httpapi/server.go`: `handleIndex` drops `Categories`.
  - `web/web.go`.

**Interfaces:**
- Consumes:
  - `GET /api/templates` with Task 5's fields;
  - `instancesCache`, `compatBadge`, `compatWhere`;
  - the existing `data-install` / `data-add-instance` / `data-apps-filter` handlers.
- Produces: `window.PortcullisMarketplace`:
  - `render(root, {filter, open})`;
  - `open(templateId)`, which opens the drawer and sets `#marketplace/<id>`;
  - `close()`.

- [ ] **Step 1: Write the failing tests:**
  - `TestMarketplaceJSSafe`: the `usage.js`-style escaping scan. The logo is an `<img>` element created with `document.createElement('img')`, `img.src = t.logo_url` (and only when it starts with `/api/catalog/`), and `alt=""`. `long_description_html` and `notes_html` are the only values assigned to `innerHTML` without `esc`, and they sit in containers with `class="md"`. No `new RegExp(` in the file.
  - `TestMarketplaceSearchNode` (node) over a fixture catalog of 6 templates:
    - `"  NEXT "` matches Nextcloud (trim, case-insensitive, over name, description and tags);
    - `"(.*"` matches nothing and doesn't throw;
    - `"<img onerror=x>"` matches nothing, and the empty state echoes it via `textContent`;
    - the "Clear filters" button resets the search, chips and filters.
  - `TestMarketplaceFiltersNode`, one assertion per filter:
    - **works here:** hides `compat.status == "refused"`;
    - **SSO:** `auth.sso` is `true` or `"partial"`;
    - **AI:** `manifest.ai.mcp` is non-empty;
    - **multi-instance:** `instances == "multi"`;
    - **no web page:** `routerless`;
    - **installed:** at least one instance in `instancesCache`;
    - combinations are ANDed with the category chip.
  - `TestMarketplaceCategoryOrderNode`: the chips follow `category_rank`, then label; the labels are `category_label`; a chip shows its count.
  - `TestMarketplaceDrawerNode`: `open('nextcloud')` shows:
    - the name, logo or icon, the `links.website` link ("Homepage ↗", `rel="noopener noreferrer"`, `target="_blank"`, only `https:`) and the source link;
    - `long_description_html`, then "Sign-in notes" with `notes_html`;
    - the settings summary (count of `settings.options`, the names of the required ones);
    - capabilities (SSO / AI companions / VPN provider / mail provider / multi-instance / no web page / placement primary-only);
    - resources ("needs ≥ 2 GiB RAM", with a warning pill when `hosts.primary.memory_bytes` is lower);
    - compat reasons (every reason as a list item);
    - screenshots as `<img>` elements (when present);
    - Install / + Add instance buttons with the same disabling rule as today.

    Esc closes the drawer and restores the hash.
  - `TestMarketplaceDeepLinksNode`:
    - `#marketplace` shows the Marketplace in Apps, with the Apps tab active;
    - `#marketplace?filter=mail` pre-selects the Mail chip;
    - `#marketplace/stalwart` opens its drawer;
    - an unknown id → the list and a toast "No template stalwartx".
- [ ] **Step 2:** Run `go test ./internal/httpapi/ -run 'Marketplace'` → FAIL.
- [ ] **Step 3:** Implement. Cards keep today's content (icon or logo, name, mail pill, source badge, description, auth badges, tags, footer). The badges are rebuilt with `el()`-style DOM creation. Search is debounced at 150 ms. The filters are toggle buttons with `aria-pressed`. "+ Add app" toggles `#apps-root` and `#mkt-root` and sets `#marketplace`; "← Apps" goes back.
- [ ] **Step 4:** Run `go test ./internal/httpapi/ ./web/` → PASS. Also run `go test ./internal/httpapi/ -run 'Mail'`: the Stalwart agent's mail badge tests must still pass against the JS badges. Update their selectors only, never their assertions.
- [ ] **Step 5: Browser check.** Screenshots of: the Marketplace (all), search "photo", the Mail chip, "works here" with a Podman compat fixture, the Nextcloud drawer, a drawer with a logo, and a 390 px wide view. The console is clean. Also check that `document.querySelectorAll('svg')` in the page has no logo content: logos are `<img>` elements only.
- [ ] **Step 6:** Commit path-only (`ui: the Marketplace is Apps' + Add app: client-rendered, search, category chips, filters, a detail drawer; #marketplace links kept (ux3)`).

### Task 14: Usage Share view

**Overlaps:** ux3 bug fixes (`web/usage.js`, if the "running" rule touches the UI). Start after it lands.

**Files:**
- Create: `web/donut.js`, `web/share.js`, `internal/httpapi/webui_share_test.go`
- Modify: `web/usage.js` (a new view `share` in the subview nav, before By app; `#usage/share`), `web/index.html` (load the two scripts; the `ROUTES` entry for `usage/(share|apps|containers|storage)`), `web/web.go`

**Interfaces:**
- Consumes: `GET /api/usage?window=`, `GET /api/usage/storage` (Tasks 6–10).
- Produces:
  - `PortcullisDonut.svg(slices, opts) → string`, where `slices` is `[{key, label, value}]` (numbers ≥ 0) and `opts` is `{size, hole, total?}`. A non-number value is dropped.
  - `PortcullisDonut.slices(view, metric, server, window)`, with `metric` ∈ `cpu mem net io storage` → slices including `other` / `free`.
  - `PortcullisShare.render(el, {server, window, app?})`.

- [ ] **Step 1: Write the failing tests:**
  - `TestDonutGeometry` (node):
    - one slice of 100 % → two arc commands and no `NaN`;
    - `[0, 0]` → the empty ring plus "nothing measured";
    - all nil → "not measured" with the reason;
    - values summing above `total` → "other" = 0, never negative;
    - every number in the output passes `/^-?\d+(\.\d+)?$/`;
    - labels are only in `<title>` via `esc()`.
  - `TestShareSlicesNode`:
    - **cpu:** per-app `totals.cpu_cores` on the server, core as one slice, other = `hosts[s].cpu_used_cores − Σ`, free = `cpus − cpu_used_cores`.
    - **mem:** the same with bytes.
    - **io:** the apps plus other from the host's `blk_*`.
    - **net:** the apps only, with the caption "of measured app traffic (no host-wide figure)".
    - **storage**, per disk:
      - apps by the items' `dev` (`in_total`);
      - core;
      - folders;
      - "shared images": images deduplicated by target, on the engine root's disk;
      - other used = `total − free − Σ` (clamped);
      - free.
    - **1h:** `window=1h` uses the same view fields.
  - `TestShareDrillNode`: clicking an app slice (`data-share-app`) shows that app's per-container donut, `"<service>.<number>"` keys, including its volumes' sizes split by `services` (a volume shared by two containers is its own slice "shared by web.1, worker.1"). "← All apps" goes back. Each slice is keyboard focusable (`tabindex="0"`, Enter opens it).
  - `TestShareServersNode`: with `hosts` = `{primary, w1}`, a server picker shows both, and switching filters the groups by `server`. A server whose host has a `why` shows that text instead of the donuts.
  - `TestShareCSPFriendly`: `share.js` and `donut.js` contain no `style=` attribute strings with data (colours come from CSS classes `.share-c0` … `.share-c9` and `.share-other`, `.share-free`), no `eval`, no `new Function`, no `innerHTML` of anything but strings built through `esc` / number formatters. A legend table repeats every slice with its value and percentage, for screen readers and colour-blind users.
- [ ] **Step 2:** Run `go test ./internal/httpapi/ -run 'Donut|Share'` → FAIL.
- [ ] **Step 3: Implement.** Before choosing the 10-colour categorical palette and the other/free greys, read the dataviz skill (`Skill dataviz`); run its validator against the Hub's dark background `#0f172a`. Slices beyond 9 apps fold into "N more apps". The view polls with `usage.js`'s existing timer (15 s, visible only), and the window toggle is "Last sample · 1 h average".
- [ ] **Step 4:** Run `go test ./internal/httpapi/ ./web/` → PASS.
- [ ] **Step 5: Browser check.** Screenshots of `#usage/share`:
  - the CPU, memory, IO, network and storage donuts on a harness with 6 apps, core and 2 folders;
  - the 1 h toggle;
  - an app drill-down;
  - the worker `w1`;
  - a Kubernetes fixture showing "not measured".

  The console is clean and no CSP violation is reported (run the harness with `Content-Security-Policy-Report-Only: default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self'` to prove the view needs nothing more).
- [ ] **Step 6:** Commit path-only (`ui: Usage Share view: inline-SVG donuts for CPU, memory, storage, network and disk IO with other/free, per-app drill-down, 1 h average, per server (ux3)`).

### Task 15: Docs, CLAUDE.md and the final pass

**Overlaps:** Stalwart admin view (`web/docs/`, `docs/operations/hub.md` if it edits mail sections). Start after it lands.

**Files:**
- Modify: `portcullis-docs/docs/operations/hub.md`, `portcullis-docs/docs/operations/servers.md` (worker usage), `portcullis-docs/scripts/generate-app-docs.py`, `portcullis-hub/web/docs/{hub.md,servers.md}` (resync), `portcullis-hub/CLAUDE.md`, `portcullis-templates/CLAUDE.md` (the new fields and the logo rule)

**Interfaces:**
- Consumes: everything above.

- [ ] **Step 1:** Update `hub.md`. It describes: the six tabs; the Access subtabs; the Settings sections and their hashes; the Marketplace's search, filters and drawer; the Share view, its "other/free" and its window; and that network has no host-wide figure.
- [ ] **Step 2:** In `generate-app-docs.py`, render `long_description` with the same `NOTES_MD` as the notes, above the sign-in notes. Show `resources` as one line. Copy `logo.svg` into the app page only if the docs site's CSP allows `img-src 'self'` (check `zensical.toml`); otherwise skip the logo and note why in the commit message. Run `python3 scripts/generate-app-docs.py && zensical build --strict` → no warnings.
- [ ] **Step 3:** Resync the Hub's `web/docs` (Task 1 Step 4 command), then run `TestDocsCopiesInSync` → PASS. Update `CLAUDE.md` rows for `web/`, `internal/usage`, `internal/svgsafe`, `internal/agent` and `internal/templates`, in the file's existing style.
- [ ] **Step 4: Full gates:**
  - Hub: `go vet ./... && go test -race -count=1 ./...`;
  - templates: `python3 tests/validate.py && python3 -m pytest tests -q`;
  - docs: `zensical build --strict`.

  All must pass.
- [ ] **Step 5: Whole-UI Playwright pass.** Open every top tab and every subtab at 1400×900, plus three at 390 px. Check: no console errors; no element wider than the viewport; and keyboard navigation reaches the tab bar, the Settings subtabs, the Marketplace chips and the donut slices. Save the screenshots and send them with the final review.
- [ ] **Step 6:** Commit each repo path-only (`docs: Hub reorganisation (ux3)`, `CLAUDE.md: …`). Request the whole-branch review (`superpowers:requesting-code-review`) with Review Focus 1–5 as its checklist.

## Controller rulings (2026-11-21)

- **Logos: no hand-rolled SVG sanitiser.** Logos (and screenshots) are only ever shown through `<img>` (never inline, never `<object>`/`<embed>`), served from `/api/catalog/{id}/…` with `Content-Type: image/svg+xml` (or png/webp for screenshots), `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; sandbox`, and `Content-Disposition: inline; filename=…`. Browsers never run script in an SVG loaded as an image; the CSP+sandbox covers direct navigation. The validators (Hub + `validate.py` with `defusedxml`) still refuse obvious script/event/foreign-object content and external references as a lint, and cap size (64 KiB logo, 512 KiB screenshot), but they are not the security boundary. Task 4 is rewritten accordingly.
- Homepage = `links.website` ACCEPTED; screenshots built but empty ACCEPTED; host figures from `/proc` ACCEPTED; no host-wide network "other" ACCEPTED; `UsageView.hosts` replaces `host` (no back-compat) ACCEPTED; no redirects for `#ssh`/`#sources` but every internal link updated ACCEPTED.
