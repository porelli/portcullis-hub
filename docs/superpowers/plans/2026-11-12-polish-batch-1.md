# Polish batch 1 (logo, security-key names and rename, part 3 follow-ups) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Put the chosen Raised-gate logo on every Portcullis surface. Give passkeys plain section names, a model and a name the person can change (Keycloak's `userLabel`). Close part 3's four follow-ups: the flaky Stop tests, step-up returning to the page that was asked for, a read-only Sign-in page while impersonated, and the introspection smoke check.

**Architecture:**
- **Logo.** Each repo gets its own byte copies of the branding files, and a test in that repo pins each copy's sha256.
  - The Hub serves its copies from `/static/` on both listeners.
  - The Keycloak login theme in core shows the mark with one CSS rule and overrides `img/favicon.ico`.
  - group-gate inlines the mark and a `data:` favicon (it serves no files).
  - The docs site sets `logo` and `favicon`.
- **Passkeys.** The Hub reads each credential's AAGUID from Keycloak's `credentialData` and looks the model up in the FIDO MDS BLOB it already holds (shown only, never stored). A new people-listener route renames a passkey through Keycloak's `PUT …/credentials/{id}/userLabel`.
- **Step-up.** group-gate builds `rd` from the request's `X-Forwarded-Uri` (GET only, same host, at most 2048 bytes; otherwise the root).

**Tech Stack:**
- Go 1.27 (Hub, gocloak v14 `UpdateCredentialUserLabel`, go-webauthn `metadata`);
- vanilla JS run by node tests;
- Python 3 (group-gate, the Keycloak smoke run's `signin.py`, core e2e with Playwright);
- Keycloak 26.8.1 `keycloak.v2` login theme (FreeMarker, CSS);
- Zensical.

**Spec:** `docs/superpowers/specs/2026-11-12-polish-batch-1-design.md` (Hub repo). It is binding.

## Global Constraints

- **Branches and worktrees.** Use branch `polish1` in every repo this batch touches: docs, keycloak, hub and core. Templates is untouched, but its CI is re-run in Task 11.
  - The worktrees are `/Volumes/workspace/portcullis/wt-polish1/<repo>` (`portcullis-docs`, `portcullis-keycloak`, `portcullis-hub`, `portcullis`).
  - Create each from a fresh `origin/main` (`git fetch && git worktree add -b polish1 /Volumes/workspace/portcullis/wt-polish1/<repo> origin/main`). The main checkouts are behind and may hold someone else's work: the docs checkout has uncommitted changes. **Never edit, stage or commit in a main checkout.**
- **Contract first.** `portcullis-docs/docs/guides/integration-contracts.md` changes in Task 1, before any code.
- **No back-compat code** (a user rule). No new dependencies.
- **Secrets never on argv**, never in logs, never in the audit. The smoke run's introspection client secret is generated in-process and sent in a form body.
- **Fail closed.** An unreadable `credentialData` means "unknown model", never an error. An unexpected step-up path means `rd` = the root. An unknown or foreign credential id means `404`.
- **TDD:** a failing test first, in every task.
- **Copy the branding bytes verbatim** from `/Volumes/workspace/portcullis/branding/` (`cp`, never retyped). The pinned sha256 values are recorded in the tests:
  - `favicon.svg` `8c07f90ac5371f5742ca1837b45ff450f56674c8773ddbcd0b4b03fa17fd2352`
  - `favicon.ico` `d709cb96a8d612fc471fa02914d674f03972146a1680db98f97f93e46bcea7a1`
  - `apple-touch-icon.png` `21b185a5c8c9ea6b234aa73d6d7f334cdb2f6713d4ea9d953f909a040b5d1cc3`
  - `icon-192.png` `becb41dbda1990e14c8fca7cf4540cf2596f2aa489e72b5b94e56e390aa1267c`
  - `icon-512.png` `c846a24046bc57a60ae4db0af83f5c2b0317c646ca4a14b702ef512f977bc709`
  - `maskable-512.png` `50372605937f18f310076ac04d818ea39993b07fe270c62e4d73e68f81a93a03`
  - `site.webmanifest` `cc025a34c1c48cb9fe21c9ff6ca8706ce4f46fceaf310b023cad91c483fde1c0`
  - `concept-1-mark-dark.svg` `a63ddab1ce0eac394cdbc7547f9fcbc9bf6947060601dd5202527222cef97bfa`

  Every surface here is dark (the Hub, group-gate, Keycloak's header, Material's coloured header), so the inlined or `<img>` mark is always the **dark** variant. The wordmark is live text in the existing font stack. No font file and no outlined lockup goes in any repo.
- **Method names (one table):** `signin.methodInfo` `Label`. The Sign-in page and the person's Sign-in tab both render `m.label`.

  | Method id | Label |
  |---|---|
  | `password` | Password |
  | `passkey_synced` | Synced passkey |
  | `browser_cert` | Browser certificate |
  | `passkey_device` | Device-bound passkey |
  | `security_key` | Security key |
  | `yubikey_cert` | YubiKey certificate |
- **Hub checks** (with `PORTCULLIS_DOCS_DIR=/Volumes/workspace/portcullis/wt-polish1/portcullis-docs`):
  - gofmt (go1.27.3) prints nothing;
  - `go vet ./...` and `go vet -tags harness ./internal/httpapi/...` pass;
  - `go test -race ./...` ends `ok` for every package (node is required for the JS tests).
- **Hub docs copies.** `web/docs/*.md` must equal the docs worktree's pages. Any Hub task that follows a docs change runs `PORTCULLIS_DOCS_DIR=… go generate ./web` and commits "web: docs copies resynced (polish1 contract)".
- **Core checks:**
  - `shellcheck -S warning portcullis scripts/lib/*.sh tests/*.sh`;
  - `bash tests/test_cli.sh`, `bash tests/test_shell_libs.sh`;
  - `python3 tests/test_group_gate.py`, `python3 tests/test_branding.py`.
- **Keycloak checks:** `docker build --target test .` (ends `BUILD SUCCESSFUL`), `docker build .`, and the smoke job.
- **Docs checks:** `bash scripts/check-branding.sh` and `zensical build --strict` in the docs venv.
- **CI:**
  - The Hub runs `build.yml`, Keycloak `build.yml`, core `ci.yml` and docs `deploy.yml`.
  - Core's targeted runs: `gh workflow run ci.yml -R porelli/portcullis --ref polish1 -f jobs="<names>"`, with names from `unit-tests build-and-test e2e e2e-instances e2e-signin e2e-settings e2e-folders e2e-filesharing e2e-ai`. The first job, `jobs-input`, refuses unknown names.
  - This batch adds **no** core CI job, only steps, so the validator's list is unchanged.
  - Core CI on `polish1` builds the Hub and Keycloak images from their same-named `polish1` branches, so push those first.
- **Commits** stage new files: `git add -A && git commit -m "…"`, run inside the task's worktree.
- **CLAUDE.md** layout tables in the Hub, Keycloak and core: a task that adds a file, a route or an asset updates its repo's row in the same commit.

## Review Focus

1. **Recasing your own passkey's name** ("yubikey" → "YubiKey") is not a duplicate of itself. It succeeds, and only *other* credentials count for the 409. Pinned in Task 4 by `TestSetPasskeyLabelRecase`.
2. **Step-up `rd` on an extra domain with a path that a browser reads as another host**: `//evil.example/x`, `/\evil.example`, `/%5Cevil`, or a tab or newline. These fall back to `rd=/`, and the main-domain form falls back to `https://<host>/`. Pinned in Task 8 by `test_stepup_return_rejects_offhost_paths`.
3. **A passkey with no, garbled or zero `credentialData` AAGUID** (stock `webauthn` and older registrations): the view still answers, with model `""`, and the page says "unknown model". Pinned in Task 3 by `TestSignInCredentialsAAGUID` and `TestMySignInPasskeyModel`.
4. **The name shows after a rename.** The inventory is cached for 30 s, but the reload right after a rename shows the new name (the rename calls `MarkInventoryStale`). Pinned in Task 4 by `TestRenameOwnPasskeyFreshView`.
5. **Renaming while impersonated** is refused 403 by `RefuseWhileImpersonated`: Keycloak isn't called and nothing is audited as `ok`. The page also doesn't offer Rename (Task 5). Pinned in Task 4 by `TestRenameOwnPasskeyRoute`'s impersonated case.

---

### Task 1: Contract, operator docs and the docs-site logo (docs)

**Files** (`wt-polish1/portcullis-docs`):
- Modify: `docs/guides/integration-contracts.md`
- Modify: `docs/operations/auth-policies.md`, `docs/operations/hub.md`, `docs/setup/certificates.md`, `docs/operations/testing.md`
- Create: `docs/assets/favicon.svg` (a copy of `favicon.svg`), `docs/assets/logo.svg` (a copy of `concept-1-mark-dark.svg`)
- Create: `scripts/check-branding.sh`
- Modify: `zensical.toml`, `.github/workflows/deploy.yml`

**Interfaces:**
- Produces: the contract text that every later task implements, with these exact names:
  - the route `PUT /api/me/signin/passkeys/{credentialId}/label`;
  - the JSON fields `passkeys[].id` and `passkeys[].model`;
  - the audit action `signin.passkey.label`;
  - the `rd` rule.

- [ ] **Step 1: Write the failing check.** `scripts/check-branding.sh` (`set -euo pipefail`) uses `sha256sum` if it exists, else `shasum -a 256`. It checks `docs/assets/favicon.svg` against the `favicon.svg` value and `docs/assets/logo.svg` against the `concept-1-mark-dark.svg` value (Global Constraints), and exits 1 naming the file on a mismatch. Run `bash scripts/check-branding.sh`. Expected: FAIL (the files are missing).
- [ ] **Step 2: Add the assets and the site config.**
  - Copy both files.
  - Add `logo = "assets/logo.svg"` and `favicon = "assets/favicon.svg"` under `[project.theme]` in `zensical.toml`.
  - Add a step `Branding copies` (`run: bash scripts/check-branding.sh`) to `deploy.yml` before `Build`.

  Run the script and `zensical build --strict`. Expected: PASS, no warnings.
- [ ] **Step 3: Edit the contract.**
  - **§5 "Step-up URL"** and the step-up page bullet: `rd` is the requested page. The main domain uses `rd=https://<host><path>?<query>` and extra domains use `rd=<path>?<query>`, where `<path>?<query>` is `X-Forwarded-Uri` exactly as Traefik passed it. It is used only when all of these hold:
    - `X-Forwarded-Method` is `GET`;
    - the value starts with `/` but not `//` or `/\`;
    - every byte is in `0x21–0x7e`;
    - it contains no `\` and no `%5c` or `%5C`;
    - it is at most 2048 bytes.

    Otherwise `rd` keeps today's root (`https://<host>/` or `/`). oauth2-proxy's `.<domain>` whitelist accepts any path on the main domain's hosts. The extra-domain `rd` stays relative.
  - **§5.1:**
    - the people listener registers "exactly **twenty-one**" app routes; add `PUT /api/me/signin/passkeys/{credentialId}/label` to the Sign-in page routes (nine) and to the "only these D25 routes under `/api/me/signin/`" sentence;
    - in the `MySignIn` example, the labels change to the Global Constraints table and the passkeys become `{"id": "<Keycloak credential id>", "label", "kind", "model", "created_at"}`;
    - the `methods` bullet says `model` is the FIDO MDS v3 `description` for the credential's AAGUID: shown only, never stored, `""` when the AAGUID is zero, missing or not in the list (the page shows "unknown model").
  - **§5.1, the new route:** `PUT /api/me/signin/passkeys/{credentialId}/label` with `{"label": "…"}` (≤ 8 KiB) → `204`.
    - The label is trimmed, 1–64 runes, valid UTF-8, with no control or bidi character; otherwise `400` "a passkey name is 1–64 characters on one line".
    - Only the caller's own passkey, by Keycloak credential id. Anything else (another person's, not a passkey, not a UUID) is `404` "no such passkey".
    - The label must be unique among the caller's other credentials, case-insensitively; otherwise `409` "you already have a sign-in method named “<label>”". This is because Keycloak refuses duplicate labels.
    - The Hub calls Keycloak's `PUT /admin/realms/portcullis/users/{id}/credentials/{credentialId}/userLabel` (`text/plain`).
    - It is refused while impersonated (the existing read-only rule), counts toward the refusal limit, and is audited `signin.passkey.label`: detail `<old> → <new>` when it succeeds, `credential <id>` when it is refused.
    - It has no MCP tool: add it to §15.10's "Never tools" with the reason "naming your passkeys: on the Sign-in page, where you can see which key is which (`my_sign_in` lists names and models)".
    - Add to §5.1: "While the browser is signed in as you, the Sign-in page offers no action and says 'Changes are off while <admin> is signed in as you.'"
  - **§8.1 Methods table:** the Label column becomes the Global Constraints table.
  - **§8.1 "Impersonation":** the smoke run checks that the introspection of an impersonated access token carries `act` and `pc_imp`, and that its `exp` is at most `until`.
  - **§1:** no version bump. The changes are additive inside released v6 / part 3.
- [ ] **Step 4: Update the operator pages.**
  - **`auth-policies.md`:**
    - the method table's names;
    - "The Sign-in page": names, model, Rename, the impersonated line;
    - "Step-up for one method": you land back on the page you asked for.
  - **`certificates.md`:** the `hwk` row reads "Security key".
  - **`hub.md`:** the person's Sign-in tab shows name and model read-only.
  - **`testing.md`:** the Keycloak smoke run's new introspection check, core e2e's `stepup_returns_to_page`, `passkey_rename`, `imp_signin_page_read_only` and `login_theme_brand` checks, and the Hub's and core's branding pin tests.

  Run `zensical build --strict`. Expected: PASS.
- [ ] **Step 5: Commit and push.** `git add -A && git commit -m "contract: passkey names, models and rename; step-up returns to the requested page; impersonated Sign-in page read-only; introspection smoke; docs-site logo" && git push -u origin polish1`

---

### Task 2: Hub — the logo on both listeners (hub)

**Files** (`wt-polish1/portcullis-hub`):
- Create (copies): `web/favicon.svg`, `web/favicon.ico`, `web/apple-touch-icon.png`, `web/icon-192.png`, `web/icon-512.png`, `web/maskable-512.png`, `web/site.webmanifest`, `web/mark.svg` (= `concept-1-mark-dark.svg`)
- Modify: `web/web.go` (the `//go:embed` list and its comment), `web/web_test.go`
- Modify: `web/index.html`, `web/people.html`, `web/mysignin.html`, `web/confirm.html`, `web/impersonation-stop.html`
- Modify: `internal/httpapi/server.go` (`peopleStatic`, `handleStatic`), `internal/httpapi/confirm.go` (`confirmCSP`), `internal/httpapi/impersonation.go` (`impStopCSP`)
- Test: `web/web_test.go`, `internal/httpapi/people_test.go` (`TestSettingsAssetHubOnly`), new `internal/httpapi/branding_test.go`
- Modify: `web/docs/*.md` (resync after Task 1)

**Interfaces:**
- Produces: `brandingFiles` (in `web/web_test.go`): file → sha256, for the eight files above.

- [ ] **Step 1: Resync the docs copies.** Run `PORTCULLIS_DOCS_DIR=/Volumes/workspace/portcullis/wt-polish1/portcullis-docs go generate ./web`, then commit "web: docs copies resynced (polish1 contract)".
- [ ] **Step 2: Write the failing tests.**
  - **`TestBrandingCopies`** (`web/web_test.go`): for every entry of `brandingFiles`, `fs.ReadFile(FS, name)` has that sha256. `mark.svg` maps to the `concept-1-mark-dark.svg` value.
  - **`TestPagesCarryBranding`:** each of the five HTML files, read from `FS`:
    - contains `<link rel="icon" href="/static/favicon.ico" sizes="48x48">`, `<link rel="icon" href="/static/favicon.svg" type="image/svg+xml">`, `<link rel="apple-touch-icon" href="/static/apple-touch-icon.png">` and `<link rel="manifest" href="/static/site.webmanifest">`;
    - has `<img class="brand-mark" src="/static/mark.svg" alt="" width="28" height="28">` inside its `<h1>`;
    - no longer contains `&#9906;`.
  - **`TestStaticContentTypes`** (`branding_test.go`, with `newPeopleEnv`):
    - on both listeners, `GET /static/<f>` answers 200 with `.svg` `image/svg+xml`, `.png` `image/png`, `.ico` `image/x-icon`, `.webmanifest` `application/manifest+json`, and `X-Content-Type-Options: nosniff`;
    - the people listener still 404s `/static/settings.js`;
    - `confirmCSP` and `impStopCSP` contain `manifest-src 'self'`.
  - **`TestSettingsAssetHubOnly`:** the expected allowlist string gains the eight files, sorted.

  Run `go test ./web ./internal/httpapi -run 'TestBranding|TestPagesCarryBranding|TestStaticContentTypes|TestSettingsAssetHubOnly'`. Expected: FAIL.
- [ ] **Step 3: Implement.**
  - Copy the files and extend the embed list.
  - `handleStatic` gets four more `case strings.HasSuffix(path, …)` content types; nosniff stays.
  - `peopleStatic` gains exactly the eight file names.
  - Each page gets the four `<link>` tags in `<head>` (after `<title>`), and the `<img>` replaces `<span>&#9906;</span>`. The Stop page's `<h1>` gains it before the text.
  - CSS `.brand-mark{vertical-align:-4px;margin-right:.35rem}` goes in each page's existing style block. `directory.css` covers people.html and mysignin.html.
  - Both CSPs gain `manifest-src 'self'`.
  - **No** root `/favicon.ico` route: every page links its icons, and a new route would widen `TestPeopleListenerHasNoAppRoutes`.
  - Update the `web/web.go` comment and the Hub `CLAUDE.md` web row.
- [ ] **Step 4: Run the Hub checks** (Global Constraints). Expected: all `ok`.
- [ ] **Step 5: Commit and push.** `git add -A && git commit -m "web: Raised-gate logo and favicon set on both listeners (static types, people allowlist, manifest-src)" && git push -u origin polish1`

---

### Task 3: Hub — method names and passkey models (hub)

**Files:**
- Modify: `internal/signin/methods.go` (`methodInfo` labels)
- Modify: `internal/keycloak/keycloak.go` (`PasskeyCredential`, `credential`, `credentials()`, `SignInCredentials`), `internal/keycloak/kctest/fake.go` (`Credential.CredentialData`)
- Modify: `internal/fidomds/trust.go` (new `Models`)
- Modify: `internal/hub/signin_mds.go` (`mdsState.models`, `setMDS`, new `mdsModels`), `internal/hub/mysignin.go` (`PasskeyRow`, `MySignInView`)
- Modify: `web/mysignin.js` (`methodRow`'s passkey branch)
- Test: `internal/keycloak/keycloak_test.go`, `internal/fidomds/fidomds_test.go`, `internal/hub/mysignin_test.go`, `internal/httpapi/webui_mysignin_test.go` (update `mySignInView` and `TestMySignInPageRendersMockupRows`)

**Interfaces:**
- Produces:
  - `keycloak.PasskeyCredential{ID, Type, Label string; Created time.Time; AAGUID string}`. `AAGUID` is lowercase and hyphenated; `""` means unknown or zero.
  - `fidomds.Models(m *metadata.Metadata) map[string]string`
  - `(h *Hub) mdsModels() map[string]string`. It is read-only, and replaced as a whole on each `setMDS`.
  - `hub.PasskeyRow{ID string "id"; Label string "label"; Kind signin.Method "kind"; Model string "model"; CreatedAt time.Time "created_at"}`
- Consumes: the Task 1 contract.

- [ ] **Step 1: Write the failing tests.**
  - **`TestSignInCredentialsAAGUID`** (keycloak). In the fake, alice has three credentials:
    - `portcullis-security-key` with `credentialData` `{"aaguid":"CB69481E-8FF7-4039-93EC-0A2729A154A8","credentialId":"x"}`;
    - `webauthn-passwordless` with `{"aaguid":"00000000-0000-0000-0000-000000000000"}`;
    - `portcullis-device-passkey` with `credentialData` `"not json"`.

    The AAGUIDs come back as `cb69481e-8ff7-4039-93ec-0a2729a154a8`, `""` and `""`, and the call does not fail.
  - **`TestModels`** (fidomds): the BLOB is built with `fidomdstest.Payload` and `Entry`, and the descriptions are `"test <aaguid>"`.
    - Every entry with an AAGUID maps lowercase AAGUID → description, whatever its status, kind or roots, and also for a stale BLOB (a model name is shown only).
    - A description with a newline or U+202E has those characters dropped. One over 128 runes is clipped to 128.
    - `Models(nil)` is an empty map.
  - **`TestMySignInPasskeyModel`** (hub): the source has a security key whose AAGUID is in a BLOB set through `setMDS`, plus a synced key with `AAGUID ""`. `MySignInView` gives `Passkeys[0].Model == "test <aaguid>"`, `ID` = the credential id, and `""` for the synced key. The labels of all six rows equal the Global Constraints table.
  - **JS: update `mySignInView`'s fixture** so each passkey gains `"id"` and `"model"`: `"YubiKey 5 Series"` for the hostile-label key, `""` for the iPhone. In `TestMySignInPageRendersMockupRows`:
    - the synced row has `iPhone · unknown model · added`;
    - the security-key row has `YubiKey 5 Nano · unknown model · added` and `· YubiKey 5 Series · added`;
    - each key is its own `<li data-msi-key="<id>">`;
    - `TestMySignInEscapes` still holds for the label **and** a hostile model.

  Run `go test ./internal/keycloak ./internal/fidomds ./internal/hub ./internal/httpapi -run 'AAGUID|TestModels|PasskeyModel|MySignInPage|MySignInEscapes'`. Expected: FAIL.
- [ ] **Step 2: Implement.**
  - **`credentials()`:** decode `CredentialData` with `encoding/json` into `struct{ AAGUID string "aaguid" }`, lowercase it, check it with `uuid.Parse`, and turn `uuid.Nil` into `""`. Any error leaves it `""`, with no log of the data.
  - **`Models`:** iterate over `m.Parsed.Entries`, skipping `uuid.Nil`. Clean the description like `impAppName`: drop `controlOrBidi` and invalid UTF-8, trim, clip to 128. Duplicate that small predicate in `fidomds` rather than importing `hub`.
  - **`setMDS`:** set `h.mds.models = fidomds.Models(m)` when `m != nil`.
  - **`MySignInView`:** take `models := h.mdsModels()` **before** `h.mu.RLock()`, and fill `ID`, `Model`.
  - **`methodRow`:** the passkey branch renders `<ul class="msi-keys">` with one `<li data-msi-key="<id>">` per key. Its escaped text is `name · (model || 'unknown model')` plus ` · added <date>` when there is one; `name` falls back to `'unnamed'`.
  - Change the `methodInfo` labels. The Hub's Settings list follows automatically. `signin.js`'s own rule-editor `METHODS` stays as it is (not in the spec).
- [ ] **Step 3: Run the Hub checks.** Expected: all `ok`.
- [ ] **Step 4: Commit.** `git add -A && git commit -m "sign-in page: plain method names, each passkey's model from the FIDO list and its credential id"`

---

### Task 4: Hub — rename a passkey (hub)

**Files:**
- Modify: `internal/keycloak/keycloak.go` (new `SetPasskeyLabel`, `ErrPasskeyNotFound`, `ErrPasskeyLabelTaken`), `internal/keycloak/kctest/fake.go` (`PUT /users/{id}/credentials/{cid}/userLabel`)
- Modify: `internal/hub/signin_people.go` (`SignInSources.PasskeyLabel`), `internal/hub/mysignin.go` (new `RenameOwnPasskey`, `passkeyLabel`)
- Modify: `cmd/hub/main.go:396` (wire `PasskeyLabel: kc.SetPasskeyLabel`)
- Modify: `internal/httpapi/mysignin.go` (route + `handleRenameOwnPasskey`), `internal/httpapi/people.go` (comment: the route count)
- Modify: `internal/httpapi/people_test.go` (`peopleAppRoutes`: add the route, count 21), `internal/httpapi/mcp_parity_test.go` (`signInNoToolRoutes`)
- Modify: `web/mysignin.js` (Rename)
- Test: `internal/keycloak/keycloak_test.go`, `internal/hub/mysignin_test.go`, `internal/httpapi/mysignin_test.go`, `internal/httpapi/webui_mysignin_test.go`

**Interfaces:**
- Consumes: `PasskeyRow.ID` and `keycloak.PasskeyCredential` (Task 3).
- Produces:
  - `func (c *Client) SetPasskeyLabel(ctx context.Context, username, credentialID, label string) (old string, err error)`
  - `SignInSources.PasskeyLabel func(ctx context.Context, username, credentialID, label string) (string, error)`
  - `func (h *Hub) RenameOwnPasskey(ctx context.Context, user, credentialID, label string) error`
  - `func passkeyLabel(raw string) (string, error)`: the trimmed label, or the 400.

- [ ] **Step 1: Write the failing tests.**
  - **`TestSetPasskeyLabel`** (keycloak fake; alice has security key `K1` "YubiKey", synced `K2` "iPhone" and a `password` credential labelled "Laptop"):
    - `("alice","K1","Office key")` gives old `"YubiKey"` and the fake's label becomes `"Office key"` (the body was sent `text/plain`);
    - `"K9"` gives `ErrPasskeyNotFound`, and so does the password credential's id (not a passkey);
    - bob's credential id with alice's name gives `ErrPasskeyNotFound`;
    - `"iphone"` and `"laptop"` give `ErrPasskeyLabelTaken`;
    - an unknown user gives `ErrUserNotFound`;
    - the fake answering 409 to the PUT gives `ErrPasskeyLabelTaken`.
  - **`TestSetPasskeyLabelRecase`:** `("alice","K1","yubikey")` succeeds and the stored label is `"yubikey"`.
  - **`TestRenameOwnPasskey`** (hub, a fake `PasskeyLabel` source that records its calls):
    - `"  Office key  "` reaches the source as `"Office key"`;
    - the audit has `signin.passkey.label`, target `alice`, detail `YubiKey → Office key`, result `ok`;
    - `""`, 65 runes, `"a\nb"` and `"a‮b"` are 400 with the contract text, the source isn't called, and the result is `refused`;
    - the source's `ErrPasskeyNotFound` or `ErrUserNotFound` is 404 "no such passkey";
    - `ErrPasskeyLabelTaken` is 409 "you already have a sign-in method named “iPhone”";
    - any other error is 503;
    - a non-UUID id is 404 without a call;
    - a nil source is 503;
    - ten refusals in a minute trip `errEntryLimited`.
  - **`TestRenameOwnPasskeyFreshView`:** after a rename, `MySignInView` (whose source now lists the new label) shows it at once, because `MarkInventoryStale` ran and the 30 s cache didn't serve the old one.
  - **`TestRenameOwnPasskeyRoute`** (httpapi, `signInEnv` with alice's key id a UUID):
    - `PUT /api/me/signin/passkeys/<id>/label` `{"label":"Office key"}` on the people listener (with CSRF) gives 204;
    - an unknown field gives 400; a body over 8 KiB gives 413;
    - the Hub listener gives 404;
    - with `X-Forwarded-Impersonation: <any>` it gives 403 "not while you are signed in as someone else: Stop first", the source isn't called, and there is no `ok` audit entry.
  - **`TestPeopleListenerHasNoAppRoutes`:** expects 21 routes.
  - **`TestPeopleToolParity`:** passes with `signInNoToolRoutes["PUT /api/me/signin/passkeys/{credentialId}/label"]` = the contract's reason.
  - **JS `TestMySignInRename`:**
    - in self mode each key `<li>` has `data-msi-act="pk-rename" data-cred="<id>"`, and person mode has none;
    - `S.labelProblem` gives `''` for `'Office key'` and `'A passkey name is 1–64 characters on one line.'` for `''`, 65 characters and `'a b'`;
    - a mounted page's Rename → Save sends `PUT /api/me/signin/passkeys/<enc(id)>/label` with `{label}` and reloads (use the existing fetch stub pattern of `TestMySignInFixRound1`).

  Run the five packages' new tests. Expected: FAIL.
- [ ] **Step 2: Implement.**
  - **`SetPasskeyLabel`:**
    - `c.token`, then `importUser`;
    - `credentials` (fresh): the id must be one of the user's credentials **and** in `passkeyTypes`;
    - duplicate if any **other** credential's label `strings.EqualFold`s the new one;
    - an equal label (byte-equal) returns at once;
    - `c.api().UpdateCredentialUserLabel(ctx, tok, Realm, userID, credentialID, label)`;
    - an HTTP 409 from it becomes `ErrPasskeyLabelTaken`, anything else goes through `opErr("set credential label", err)`.
  - **The fake:** handles `PUT` on `parts[1]=="credentials" && parts[3]=="userLabel"`: 404 for an unknown id, 409 for a case-insensitive duplicate (mirroring Keycloak), else it stores the label and answers 204.
  - **`RenameOwnPasskey`:** follows `SetOwnPassword`'s shape:
    - `myUser`, then `entryLimit.reserve`/`release(isRefusal)`;
    - `passkeyLabel`, then `keycloak.ValidUserID(credentialID)` (404 otherwise);
    - the source;
    - `h.MarkInventoryStale()` on success;
    - `auditSignIn(directory.Human(u), "signin.passkey.label", u, detail, err)` with `<old> → <new>`, or `credential <id>` when refused.
    - `passkeyLabel` uses `strings.TrimSpace`, `utf8.ValidString`, a rune count of 1–64 and `controlOrBidi`.
  - **The handler:** `mySignInUser`, then `readMySignInBody(… &struct{Label string "label"}, `{"label": "..."}`)`, then `mySignInErr`, then 204.
  - **The page:** a Rename button per key in self mode opens an inline form in the method's `data-msi-panel`: input `maxlength=64`, prefilled, with Save and Cancel. It validates with `labelProblem`, then `call('PUT', …)` and `load(st)`. Export `labelProblem`.
  - Update the comments in `registerMySignIn` and `registerPeopleApps`, and the Hub `CLAUDE.md` route row.
- [ ] **Step 3: Run the Hub checks.** Expected: all `ok`.
- [ ] **Step 4: Commit.** `git add -A && git commit -m "sign-in page: rename your own passkey (Keycloak userLabel; 404 foreign, 409 duplicate; audited signin.passkey.label; no MCP tool)"`

---

### Task 5: Hub — the own Sign-in page is read-only while impersonated (hub)

**Files:**
- Modify: `web/mysignin.js` (`load`, `ctxOf`, `offers`, `methodRow`, `methodsHtml`)
- Test: `internal/httpapi/webui_mysignin_test.go`

**Interfaces:**
- Consumes: `GET /api/me/impersonation` → `{"active": null | {person, admin, reason, until, stop_url}}` (it exists, contract §5.1).
- Produces: `ctx.readOnly`: the administrator's username, or `''`.

- [ ] **Step 1: Write the failing test.** `TestMySignInReadOnlyWhileImpersonated`:
  - `S.methodsHtml(view, {mode: 'self', readOnly: 'root'})` contains `<p class="pd-warn msi-readonly" data-msi-readonly role="note">Changes are off while root is signed in as you.</p>`;
  - it contains no `data-msi-act=` at all (Set, Change, Remove, Create, Revoke, Renew, Rename) and no `+ Add`;
  - `readOnly: '<b>x</b>'` comes out escaped;
  - `{mode: 'self'}` (no readOnly) still has the actions.
  - A mount with a fetch stub answering `/api/me/impersonation` `{"active": {"admin": "root", …}}` renders the line. When the impersonation read fails, it renders the actions: the Hub refuses them anyway (`RefuseWhileImpersonated`), and the page must not break.

  Run `go test ./internal/httpapi -run TestMySignInReadOnlyWhileImpersonated`. Expected: FAIL.
- [ ] **Step 2: Implement.**
  - In self mode, `load(st)` fetches `/api/me/impersonation` next to the view (`Promise.allSettled`) and sets `st.readOnlyBy = active ? active.admin : ''`. `ctxOf(st)` passes it on.
  - When `ctx.readOnly` is set, `offers()` returns everything false: no `accountURL` link and no Rename. `methodsHtml` puts the line first.
- [ ] **Step 3: Run the Hub checks.** Expected: all `ok`.
- [ ] **Step 4: Commit.** `git add -A && git commit -m "sign-in page: no actions while someone is signed in as you"`

---

### Task 6: Hub — the two flaky Stop tests (hub)

**Files:**
- Modify: `internal/hub/stop.go` (`resumeStop`), `internal/hub/async.go` (`startOp`) and/or `internal/hub/stop_test.go`, as the evidence decides
- Test: `internal/hub/stop_test.go` (`TestStopInterruptedEnable` line 285, `TestStopResumeConcurrent` line 543) and a new `TestStopEndedRecordMeansUnlocked`

**Interfaces:** none new.

Evidence already found (REQUIRED SUB-SKILL: superpowers:systematic-debugging; confirm it before any fix):
- **`resumeStop`'s goroutine** runs `finishAsync`, which writes the record with `Running=false`, then `unregisterOp`, and only then its deferred `unlock()`. `waitOp` returns as soon as `LastOp` reads not running, so `TestStopInterruptedEnable`'s `f.h.appBusy("other")` can still see the lock ("lock still held").
- **In `TestStopResumeConcurrent`,** dave's `StopOp` → `resumeStop` → `lockApp` can find a lock still held by the previous operation. That is the undo-failed enable from `undoFailed`/`enableStopped`, or a background holder triggered by the undo (`SyncClientAccess`, which locks every enabled app, via the group deletion; `TriggerReconcile`). The result is a `BusyError` "another operation on other is in progress".
- **`startOp`** has the opposite order: `fn` (`runEnable`) releases the lock in its `defer`, *then* `finishAsync` ends the record. So a record still shows running while the lock is already free.

- [ ] **Step 1: Reproduce.** `go test -race -count=200 -run 'TestStopInterruptedEnable|TestStopResumeConcurrent' ./internal/hub/` until it fails. Record which holder had the lock: add a temporary `testHookLock` log with the caller, and remove it before committing.
- [ ] **Step 2: Write the failing test.** `TestStopEndedRecordMeansUnlocked`: for a resumed Stop (`f.undoFailed`, then `StopOp`), poll `LastOp` in a tight loop. The first time it reads `!Running`, `appBusy("other")` must already be false. Run it with `-count=100`. Expected: FAIL while the order is the cause.
- [ ] **Step 3: Fix.**
  - If the order is the cause (a real race: a client that sees "stopped" can get a 409), fix it in the code. The rule: *an op record that reads ended means its instance lock is free.*
    - In `resumeStop`, release the lock before `finishAsync`, as `startOp` does.
    - Keep the stale-record guard: `finishAsync`'s `heldHook`/`cur.OpID == opID` check, and `p.finish`'s own record. A new operation that started in the gap must not be overwritten. Add that case to the test (an enable started between unlock and finish keeps its record).
  - If the holder is a background job (access-role sync, reconcile), that is expected behaviour. Fix the **tests**: wait with a helper `waitUnlocked(t, h, id)` (poll `appBusy`, 20 s deadline) before the assertion or the next `StopOp`, and say why in the test comment.
- [ ] **Step 4: Prove it.** Run `go test -race -count=50 -run 'TestStopInterruptedEnable|TestStopResumeConcurrent|TestStopEndedRecordMeansUnlocked' ./internal/hub/`. Expected: `ok`. Then run the full Hub checks.
- [ ] **Step 5: Commit and push.** `git add -A && git commit -m "ops: <the cause, in one line>; Stop tests no longer flaky (-race -count=50)" && git push`

---

### Task 7: Keycloak smoke — introspection of an impersonated token (keycloak)

**Files** (`wt-polish1/portcullis-keycloak`):
- Modify: `.github/smoke/signin.py` (`tokens_of`, new `token_response`, `introspector`, `impersonation_main`, and the module docstring's "impersonation" paragraph)
- Modify: `CLAUDE.md` (the smoke row)

**Interfaces:**
- Produces:
  - `token_response(code, client=CLIENT) -> dict` (the raw token answer). `tokens_of` becomes `claims_of` over it, with the same signature.
  - `introspector(token) -> (client_id, secret)`.

- [ ] **Step 1: Write the failing check.** In `impersonation_main`, right after the `"impersonation: the authorize after the start signs in without a form"` check, keep the raw access token. Create the introspection client with `introspector(admin_token())`: `POST {base}/clients` `{"clientId": "smoke-introspect", "publicClient": false, "standardFlowEnabled": false, "directAccessGrantsEnabled": false, "serviceAccountsEnabled": false, "secret": <secrets.token_urlsafe(32)>}`. It is created at runtime so `smoke-realm.json` keeps matching core's realm export. Then `POST {KC}/realms/{REALM}/protocol/openid-connect/token/introspect` with the form `{token, client_id, client_secret}` (the secret only in the body). Checks:
  - `active is True`;
  - `act == {"sub": "root"}`;
  - `pc_imp.id == imp_id`;
  - `isinstance(pc_imp.until, int)`;
  - `exp <= pc_imp["until"]`;
  - `exp <= created + 1800` (the record's until);
  - `IMP_REASON` is not in the JSON.

  If Keycloak answers `active: false` for a token issued to `smoke`, first confirm it is an audience restriction (Keycloak's log at debug). Only then add an `oidc-audience-mapper` (`included.client.audience=smoke-introspect`, access token only) to `smoke` at runtime, inside this phase, and say so in the docstring.
- [ ] **Step 2: Run it locally.** `docker build -t pc-kc-smoke .`, then `.github/smoke/run.sh impersonation` as `build.yml`'s smoke job does (same environment variables, with the admin password from the environment). Expected: every `check` passes and the log has no error naming portcullis.
- [ ] **Step 3: Run the repo checks.** Run `docker build --target test .` (expected: `BUILD SUCCESSFUL`) and `docker build .`.
- [ ] **Step 4: Commit and push.** `git add -A && git commit -m "smoke: introspection of an impersonated access token carries act and pc_imp, exp at most until" && git push -u origin polish1`. Wait for `build.yml` on `polish1`. Expected: green.

---

### Task 8: group-gate — step-up returns to the requested page (core)

**Files** (`wt-polish1/portcullis`):
- Modify: `group-gate/group-gate.py` (`stepup_url`, new `return_path`, `Handler._signin_check`'s step-up branch)
- Test: `tests/test_group_gate.py` (`SigninV6Test`, `PolicyHostsTest`)

**Interfaces:**
- Produces:
  - `return_path(raw_uri: str, method: str) -> str`: the path+query to return to, or `"/"`.
  - `stepup_url(host: str, method: str, extra: bool, path: str = "/") -> str`.

- [ ] **Step 1: Write the failing tests.**
  - **`test_stepup_returns_to_page`:** `self.page("grafana.example.com", ["spk"], uri="/d/abc?orgId=1&x=%20y", extra={"X-Forwarded-Method": "GET"})` with `write_policy({"hosts": {"grafana.example.com": "strong"}, "people": {"bob": ["passkey_synced", "security_key"]}})` gives:
    - `parse_qs(urlsplit(X-Stepup-URL).query)["rd"] == ["https://grafana.example.com/d/abc?orgId=1&x=%20y"]`;
    - the page's `href` is the same URL, escaped.

    On an extra-domain host the result is `rd == ["/d/abc?orgId=1&x=%20y"]`.
  - **`test_stepup_return_rejects_offhost_paths`:** `rd` is the root (`https://<host>/`, or `/` on an extra domain) for:
    - `X-Forwarded-Method` `POST`, `HEAD` or missing;
    - the URIs `//evil.example/x`, `/\evil.example`, `/%5Cevil`, `/%5cevil`, `/a\tb`, `/a b`, `/é`, `"/" + "a"*2048`, `""` and `"x"`.

    `return_path("/" + "a"*2047, "GET")` is kept (2048 bytes).
  - **The existing tests** (`test_stepup_one_method`, `test_stepup_url_on_extra_domain`) keep passing unchanged: they send no `X-Forwarded-Uri`, so `rd` is the root.

  Run `python3 tests/test_group_gate.py SigninV6Test PolicyHostsTest`. Expected: FAIL.
- [ ] **Step 2: Implement.**
  - **`return_path`:** applies the contract's rule: GET only; starts with `/`; not `//`; no `\`; no `%5c` in any case; every byte in `0x21–0x7e`; `len(raw_uri.encode()) <= 2048`; otherwise `"/"`.
  - **`stepup_url`:** the main domain gives `rd=f"https://{host}{path}"`, an extra domain `rd=path`, both through `urllib.parse.urlencode`.
  - **`_signin_check`:** passes `path=return_path(raw_uri, self.headers.get("X-Forwarded-Method", ""))`.
  - Update `stepup_url`'s docstring: the main domain relies on oauth2-proxy's `.<domain>` whitelist, and an extra domain's `rd` stays relative.
- [ ] **Step 3: Run the core checks.** Expected: all pass.
- [ ] **Step 4: Commit.** `git add -A && git commit -m "group-gate: step-up returns to the requested page (GET, same host, ≤ 2048 bytes; else the root)"`

---

### Task 9: core — the logo on group-gate's pages and the Keycloak login theme (core)

**Files:**
- Modify: `group-gate/group-gate.py`: new `MARK_SVG`, `FAVICON_SVG`, `FAVICON_LINK`, `MARK_HTML`; `PORTAL_CSS`, `PORTAL_CSP`, `SIGNIN_CSP`; `render_portal`, `_signin_page`, `Handler._deny`
- Create (copies): `keycloak/themes/portcullis/login/resources/img/favicon.ico`, `keycloak/themes/portcullis/login/resources/img/portcullis-mark.svg` (= `concept-1-mark-dark.svg`)
- Create: `keycloak/themes/portcullis/login/resources/css/portcullis.css`
- Modify: `keycloak/themes/portcullis/login/theme.properties`
- Create: `tests/test_branding.py`
- Modify: `.github/workflows/ci.yml` (`unit-tests`: one step `branding copies` → `python3 tests/test_branding.py`, after the group-gate unit tests)
- Test: `tests/test_group_gate.py` (new `BrandingTest`)

**Interfaces:**
- Produces:
  - `MARK_SVG: str`: exactly `concept-1-mark-dark.svg`'s bytes, decoded.
  - `FAVICON_SVG: str`: exactly `favicon.svg`'s bytes.
  - `FAVICON_LINK = '<link rel="icon" type="image/svg+xml" href="data:image/svg+xml;base64,<b64 of FAVICON_SVG>">'`
  - `MARK_HTML = '<span class="pc-mark" aria-hidden="true">' + MARK_SVG.strip() + '</span>'`

- [ ] **Step 1: Write the failing tests.**
  - **`BrandingTest`** (test_group_gate.py):
    - `sha256(gg.MARK_SVG.encode())` and `sha256(gg.FAVICON_SVG.encode())` equal the pinned values;
    - `FAVICON_LINK` and `MARK_HTML` are each in `render_portal(…)`, in `render_stepup_page`, `render_certificate_page`, `render_needs_page` (its plain and impersonated forms), `render_ended_page`, and in a live `_deny` answer (`self.req("hub.example.com", groups="users_grafana")` read with the body);
    - both `PORTAL_CSP` and `SIGNIN_CSP` contain `img-src data:`;
    - no page has `src="http`, `href="http` outside `<a`, or `url(`.
  - **`tests/test_branding.py`** (stdlib `unittest` + `hashlib`): the two theme copies have the `favicon.ico` and `concept-1-mark-dark.svg` sha256 values. `theme.properties` has the line `styles=css/styles.css css/portcullis.css`. `portcullis.css` names `../img/portcullis-mark.svg` and `#kc-header-wrapper::before`.

  Run `python3 tests/test_group_gate.py BrandingTest` and `python3 tests/test_branding.py`. Expected: FAIL.
- [ ] **Step 2: Implement group-gate.**
  - Paste the two files' exact text as triple-quoted constants (the tests prove the bytes).
  - **`PORTAL_CSS`** gains `.pc-mark{display:inline-block;width:1.75rem;height:1.75rem;vertical-align:-.3rem;margin-right:.5rem}.pc-mark svg{width:100%;height:100%}`. `SIGNIN_CSS` inherits it. The CSP hashes recompute themselves.
  - **Both CSPs** gain `img-src data:`.
  - **`render_portal`** and **`_signin_page`:** `FAVICON_LINK` goes after `<title>`, and `MARK_HTML` starts the `<h1>`.
  - **`_deny`:** writes `FAVICON_LINK` before the banner and `MARK_HTML` in its `<h1>`.
- [ ] **Step 3: Implement the theme.**
  - Copy the two files.
  - `portcullis.css`: `#kc-header-wrapper::before{content:"";display:block;width:64px;height:64px;margin:0 auto 12px;background:url("../img/portcullis-mark.svg") center/contain no-repeat}`.
  - `theme.properties` gets `styles=css/styles.css css/portcullis.css` (the parent's sheet first; Keycloak resolves it through `keycloak.v2`). Update its comment.
  - `img/favicon.ico` overrides the parent's because `keycloak.v2/login/template.ftl` links `${url.resourcesPath}/img/favicon.ico`.
  - The extension's own pages (`portcullis-needs-stronger.ftl`, `portcullis-impersonating.ftl`, the notice) use this layout, so they get the mark too.
- [ ] **Step 4: Run the core checks.** Expected: all pass.
- [ ] **Step 5: Commit.** `git add -A && git commit -m "branding: Raised-gate mark and favicon on group-gate's pages (inline, data: icon, img-src data:) and the Keycloak login theme"`

---

### Task 10: core e2e and CI (core)

**Files:**
- Modify: `tests/e2e/e2e_login.py` (a new `check("login_theme_brand", …)`)
- Modify: `tests/e2e/e2e_signin.py` (new cases `stepup_returns_to_page`, `passkey_rename`, `imp_signin_page_read_only`, and the docstring's case list)

**Interfaces:**
- Consumes:
  - Task 4's route;
  - Task 5's line;
  - Task 8's `rd`;
  - Task 9's theme files;
  - the existing helpers `hub_as(user, method, path, body, base_url=PEOPLE_API, headers=…)`, `kc(path)`, `kc_user_id`, `goto`, `body`, `needs`, `state["imp1"]`.

- [ ] **Step 1: Add the checks.**
  - **`login_theme_brand`:** on the first Keycloak sign-in page, `link[href$="/css/portcullis.css"]` exists, and `getComputedStyle(document.querySelector('#kc-header-wrapper'), '::before').backgroundImage` contains `portcullis-mark.svg`. A GET of the page's `link[rel=icon]` href answers 200, and its body's sha256 is the `favicon.ico` value.
  - **`stepup_returns_to_page`:** sam's synced session opens `HUB + "/?from=stepup#x"` (Strong). The `#stepup-continue` href's `rd` is `https://hub.<d>/?from=stepup`. After Continue and the security-key touch (`drive_kc`), `page.url` starts with `https://hub.<d>/?from=stepup`.
  - **`passkey_rename`:** sam's security-key credential id comes from `GET /api/me/signin` (people listener, `hub_as("sam", …, base_url=PEOPLE_API)`). Then:
    - `PUT …/passkeys/<id>/label` `{"label": "CI key"}` gives 204, and Keycloak's `GET /admin/realms/portcullis/users/<uid>/credentials` shows `userLabel` "CI key";
    - repeating it with the synced key's id and `"ci KEY"` gives 409;
    - root's credential id gives 404;
    - the audit (`hub_ok("GET", "/api/directory/audit")`, filtered to `action == "signin.passkey.label"` as the existing audit helper near line 841 does) has an entry whose detail ends `→ CI key`.
  - **`imp_signin_page_read_only`** (`needs("imp1")`, after `imp_people_read_only`): the impersonating browser opens `PEOPLE + "/signin"`. The body has "Changes are off while root is signed in as you." and `page.locator("[data-msi-act]").count() == 0`.
- [ ] **Step 2: Push and run the targeted CI.** Do this once the Hub's (Tasks 2–6) and Keycloak's (Task 7) `polish1` branches are pushed. `git push -u origin polish1`, then `gh workflow run ci.yml -R porelli/portcullis --ref polish1 -f jobs="unit-tests build-and-test e2e e2e-signin"`. Expected: all four green. On a failure, fix it in the owning task's repo, push, and re-run only the failed jobs.
- [ ] **Step 3: Run the full core CI on `polish1`.** Run `gh workflow run ci.yml -R porelli/portcullis --ref polish1` (no `jobs`). Expected: green.
- [ ] **Step 4: Commit any fixes.** `git add -A && git commit -m "e2e: login theme brand, step-up returns to the page, passkey rename, Sign-in page read-only while impersonated"` (if Step 1's commit wasn't made before the push).

---

### Task 11: Mainline and deploy (all repos)

Merge each repo through a **temporary detached worktree**: `git worktree add --detach /tmp/merge-<repo> origin/main`, `git merge --no-ff origin/polish1`, `git push origin HEAD:main`, then `git worktree remove /tmp/merge-<repo>`. Never merge in a main checkout. No PRs.

- [ ] **Step 1: Docs.** Merge `polish1` → main and push. Expected: `deploy.yml` green (the branding check, then the build).
- [ ] **Step 2: Keycloak.** Merge `polish1` → main and push. While the Hub's and core's `polish1` still exist, run `gh workflow run build.yml -R porelli/portcullis-keycloak --ref main -f compare_ref=polish1`, and wait for that run's `:edge` publish (`gh run list -R porelli/portcullis-keycloak --branch main --workflow build.yml`: success).
- [ ] **Step 3: Hub.** Merge `polish1` → main. Re-check the docs copies against the merged docs `main`: `PORTCULLIS_DOCS_DIR=<temporary detached docs worktree at origin/main> go generate ./web`, and commit if anything changed. Push.
  - Run `gh workflow run build.yml -R porelli/portcullis-hub --ref main -f compare_ref=polish1`, and wait for `ghcr.io/porelli/portcullis-hub:edge` from that run.
  - **No other pushes to Hub main meanwhile.**
- [ ] **Step 4: Core.** Merge `polish1` → main and push. Expected: `ci.yml` green on main.
- [ ] **Step 5: Templates.** Re-run the templates CI "Test Apps" on main (`gh workflow run test-apps.yml -R porelli/portcullis-templates --ref main`). Expected: green.
- [ ] **Step 6: Deploy to the test server** (under the standing OK). Run `ssh -o BatchMode=yes -o ConnectTimeout=10 -o IdentitiesOnly=yes -i /Volumes/Michele/Michele/Keys/AWS/PDX/PDX-lightsail.pem admin@44.244.208.227 'cd ~/portcullis && git pull --ff-only && ./portcullis upgrade'`.
  - `ACME_STAGING` stays `true`: check it with `grep ^ACME_STAGING= .env`, read only.
  - Never touch the LLDAP `admin` user.
  - Then, from the server, `curl -sk https://people.<domain>/static/favicon.svg -o /dev/null -w '%{http_code}'`: expected `302`/`401` (behind sign-in) or `200`, never `404` from the Hub. The Hub's logs show no start error.
  - The user's own checks need their YubiKey: the logo, the names and models, Rename, and the step-up return.
- [ ] **Step 7: Clean up.** Only now, after the `compare_ref` dispatches: delete `polish1` locally and on the remote in docs, keycloak, hub and core (`git log origin/main..origin/polish1` empty first). Remove the worktrees under `/Volumes/workspace/portcullis/wt-polish1/` and every `/tmp/merge-*`. Confirm with `git branch -a` and `git worktree list` in each repo.

---

## Self-review

1. **Spec coverage.**
   - §1 logo:
     - (a) the Hub, both listeners: Task 2;
     - (b) the Keycloak theme: Task 9, with e2e in Task 10;
     - (c) group-gate's portal, sign-in, ended and deny pages: Task 9;
     - (d) the docs site: Task 1;
     - the sha256 pins, one test per repo: Tasks 1, 2 and 9. Keycloak has no branding copy, because the theme lives in core.
   - §2 names: Task 3. Model, name and "added": Task 3. Rename: Task 4 (route, rules, 404 / 409, CSRF, refused while impersonated, audit, the MCP parity exemption). The person's tab is read-only: Task 3, through the embedded `MySignIn`; person mode offers no Rename (Task 4's test).
   - §3:
     - the flaky tests: Task 6;
     - step-up `rd`: Task 8, with e2e in Task 10 and the contract in Task 1;
     - the impersonated page: Task 5, with e2e in Task 10;
     - the introspection smoke: Task 7.
2. **Step scan.** Every step names its files, signatures, test names with assertions, commands and expected output. Task 6 is evidence-led on purpose: the spec says "find the race … in the code if real, else in the test". It names both outcomes and the proof.
3. **Type consistency.**
   - `PasskeyRow.ID` / `Model`, `keycloak.PasskeyCredential.AAGUID`, `SignInSources.PasskeyLabel` and `SetPasskeyLabel` share one signature across Tasks 3 and 4.
   - `ctx.readOnly` is used only in Task 5.
   - `stepup_url(…, path)` and `return_path` are Task 8's only.
   - The route string is identical in Tasks 1, 4 and 10.
4. **Review Focus:** each of the five lines names a test in its owning task.
5. **Proportion:** the code blocks are limited to fixed copy (CSS, link tags, contract texts) and the pinned hashes.
