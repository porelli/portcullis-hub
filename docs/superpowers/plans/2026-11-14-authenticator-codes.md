# Authenticator-app codes (TOTP) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a seventh sign-in method, `totp` ("Authenticator app", amr `otp`, strength 1.5). It is never a sole factor and it is enrolled only through Keycloak required actions. People see and manage it on the Sign-in page, and every reader evaluates it from the one method table and the shared vectors.

**Architecture:**
- **Keycloak** owns the secret end to end. The realm OTP policy is HmacSHA1, 6 digits, 30 s, look-ahead 1 and no reuse.
- The extension adds a `portcullis-otp` execution. It wraps the stock `OTPFormAuthenticator`, runs only once the user is known, and writes the note `portcullis.otp.method`.
- The extension also overrides `CONFIGURE_TOTP`. The override applies the switch, the reserved accounts, impersonation, the add-stronger cap, the limit of 3 and `replace:<id>` before anything is stored.
- **The Hub** gets the table row, the code-only grammar rule, the built-in `password-and-code`, the inventory rows, the rename route, the help route, the history entries and the doctor checks.
- **The Hub UI** opens the required action (`kc_action=CONFIGURE_TOTP[:replace:<id>]`, `delete_credential:<id>`) in the existing fresh-auth popup.
- **Core** gets the reader rows (group-gate, mcp-gate, oauth2-proxy), the realm flow and policy, `keycloak configure` and `status`, the theme copy, the setup-link option, `--replace-keys`, the restore line and the e2e.

**Tech Stack:**
- Java 21 + Gradle with dependency verification (Keycloak 26.8.1 SPI: `AuthenticatorFactory`, `RequiredActionFactory`, the stock `OTPFormAuthenticator`, `UpdateTotp` / `ConfigureTotp`).
- Go 1.27 (the Hub, mcp-gate and enroll).
- Python 3 (group-gate, and the e2e with Playwright + `pyotp`).
- Vanilla JS (the Hub UI) and bash (the core CLI).

**Spec:** `docs/superpowers/specs/2026-11-14-authenticator-codes-design.md` (Hub repo, binding). It builds on `docs/superpowers/specs/2026-11-09-sign-in-methods-design.md` and on the plans `docs/superpowers/plans/2026-11-09-sign-in-methods-part1.md`, `…-11-11-…-part2.md` and `…-11-12-…-part3.md`. Their decisions D1–D46 and ledger lessons stay in force. This plan continues with T1–T30, each marked **(assistant's call)** where the spec left it open.

## Global Constraints

Process (the sign-in parts' rules, restated):
- **Precondition:** every repo's `main` at or after the `vpn2` merges (core 166633c, hub 9cc40ff, keycloak 2632f34, docs 1900fb6, templates df900fc).
- **Branches:** branch `totp1` in docs, keycloak, hub and core, with worktrees `/Volumes/workspace/portcullis/wt-totp1/{portcullis-docs,portcullis-keycloak,portcullis-hub,portcullis}`. There are no PRs, and everything is mainlined in Task 15. The templates repo isn't changed; its CI is re-run in Task 15. Every commit step is `git add -A && git commit -m "…"`.
- **Contract first:** Task 1 changes `docs/guides/integration-contracts.md` before any code.
- **Merge order:** docs → keycloak (wait for `edge`) → hub (wait for `edge`) → core, then re-run the templates CI. Before core's merge, dispatch both `build.yml` on `main` with `-f compare_ref=totp1`. After the keycloak merge, run `gh workflow run build.yml -R porelli/portcullis-keycloak --ref main -f compare_ref=totp1`.
- **Checks:**
  - Hub (with `PORTCULLIS_DOCS_DIR=/Volumes/workspace/portcullis/wt-totp1/portcullis-docs`): gofmt go1.27.3 prints nothing; `go vet ./...` and `go vet -tags harness ./internal/httpapi/...` pass; `go test -race ./...` passes.
  - Keycloak: `docker build --target test .` ends `BUILD SUCCESSFUL`, `docker build .` builds, and the vectors and smoke jobs pass.
  - Core: `shellcheck -S warning portcullis scripts/lib/*.sh tests/*.sh .github/ci/*.sh`, `bash tests/test_cli.sh`, `bash tests/test_shell_libs.sh`, `python3 tests/test_group_gate.py`, `cd mcp-gate && go vet ./... && go test -race ./...`, `cd enroll && go test ./...` and `actionlint`.
  - Docs: `zensical build --strict`.
- **Hub docs copies:** `web/docs/{integration-contracts,auth-policies,hub}.md` must equal the docs worktree's pages. Each Hub task that follows a docs change re-runs `go generate ./web` and commits "web: docs copies resynced (totp)".

Project rules (binding):
- **Secrets stay out of argv, logs, the audit, errors, environment variables, e2e artifacts and Playwright traces.** This covers the TOTP seed in every form: base32, lowercase, unpadded and the QR's `otpauth://` URI. The seed is made by Keycloak, shown only on Keycloak's page and stored only in Keycloak's database. The Hub never asks for `secretData`, and never logs a credential's `credentialData`.
- **Fail closed.** A switched-off `totp` is never offered, accepted, set up or counted. Any of these refuses or denies, never allows:
  - an unreadable session, note or credential;
  - an unknown `replace` id;
  - an invalid compiled rule, including one with a code-only alternative.
- **Never weaken access control.**
  - `totp` never lowers an app's required strength.
  - It never replaces a security key or certificate a template requires: no family contains it (spec §5.1), and it is never a sole factor (§5.2).
  - It never approves a certificate (`cert_fresh`), never adds a first password, never starts an impersonation, and never counts for `admin` or `portcullis-hub`.
- **Identity is the LLDAP username** in every log line, audit entry, history entry and override decision.
- **Never touch the LLDAP `admin` user** on the test server in tests. The e2e uses the CI people (root, sam, alice, bob, pat, rita, carol). The `admin` case ("no code step, no CONFIGURE_TOTP") runs in CI only, never against the test server.
- **No migration or back-compat code before the first public release.** No version bump is needed: the method switch starts off, and a stored state without a `totp` entry has it off (`EnsureSignIn`'s fail-closed completion). Fix old test-server data by hand.
- **Prefer mature libraries:** Keycloak's own OTP code (secret, QR, verification, single-use store, brute force) and `pyotp` in the e2e (pinned with hashes). Never hand-roll HMAC, base32 or QR code.
- **No private identifiers in public repos.** Use example.com names, the CI people, no test-server host and no personal data.
- **Core `ci.yml` stays at or under 450 KB** (`tests/lint_ci_size.sh`; it is 315 KB today). New long scripts go in `.github/ci/` or `tests/e2e/`, and no CI job is added (T27).
- **Shared vectors:** the Hub's `internal/signin/testdata/vectors.json` has three byte copies: core `tests/signin_vectors.json`, core `mcp-gate/internal/signin/testdata/signin_vectors.json` and keycloak `src/test/resources/signin_vectors.json`. Every copy changes in the same commit set as the Hub's.

Values pinned by the spec (copy exactly):
- **Row:** `totp` · "Authenticator app" · 15 tenths · amr `otp` · canonical order `password, totp, passkey_synced, browser_cert, passkey_device, security_key, yubikey_cert`.
- **Strength order:** `yubikey_cert` > `security_key` > `passkey_device` > `browser_cert` > `passkey_synced` > `totp` > `password`.
- **Policy:**

  | Setting | Value |
  |---|---|
  | `otpPolicyType` | `totp` |
  | `otpPolicyAlgorithm` | `HmacSHA1` |
  | `otpPolicyDigits` | 6 |
  | `otpPolicyPeriod` | 30 |
  | `otpPolicyLookAheadWindow` | 1 |
  | `otpPolicyCodeReusable` | false |
  | `otpPolicyInitialCounter` | 0 |

  `max_auth_age` is 300 s for both `CONFIGURE_TOTP` and `delete_credential`.
- **Limit:** at most 3 `otp` credentials per person.
- **Copy:**
  - code-only refusal: "an authenticator code can't be the only way in: combine it with another method (all of)";
  - history: "wrong authenticator code";
  - limit: "you already have 3 authenticator apps: remove one first";
  - score reason suffix: "codes can be typed into a fake site";
  - core warning: "The Hub can be opened with a password and a code: both can be phished".

## Rulings made here (assistant's call)

- **T1 One plan, one branch `totp1`.** It covers contract → keycloak → hub → core, then a templates CI re-run (spec §14's suggested split).
- **T2 The code-only check sits in `signin.Validate`.** Every source-rule path gets it: save, preview, state load and the built-ins. It compiles the rule with every method on. A failure is `*signin.CodeOnlyError{At signin.Path}`, whose `At` is the deepest group with a `{totp}` alternative. `SaveTemplate` answers 400 with "rule: " + the spec's text. `PreviewTemplate` answers 200 with `problem` set to that text and `code_only: [path]`, so the editor can mark the offending group live (spec §5.2). `signin.ValidateCompiled` and every reader refuse a compiled rule with a `{totp}` alternative.
- **T3 Score reason.** `ScoreOf`'s reason gains "; codes can be typed into a fake site" when `totp` is the strongest switched-on method of at least one alternative of the compiled rule.
- **T4 Inventory.**
  - `keycloak.SignInCredentials` also returns a person's `otp` credentials, in the same list, with `Type` `"totp"`.
  - `passkeyKinds` and `passkeyTypes` don't change, so nothing passkey-specific sees them.
  - The Hub drops `totp` for `admin`, `portcullis-hub` and every `portcullis-*` name in `loadInventory`.
  - Switched-off credentials are kept and not counted (`meets` and `methodPeopleLocked` already filter by `on`).
- **T5 `?refresh=1`.** On `GET /api/me/signin` it calls `MarkInventoryStale` at most once per 10 s per caller (a per-user timestamp map in the Hub). Otherwise it is ignored, never an error.
- **T6 Rename has its own route.** `PUT /api/me/signin/authenticators/{credentialId}/label` follows the passkey rules: 400 "an authenticator name is 1–64 characters on one line", 404 "no such authenticator app", 409 duplicate, audit `signin.authenticator.label`. `keycloak.SetAuthenticatorLabel` refuses a non-`otp` id with `ErrAuthenticatorNotFound`.
- **T7 Remove impact.** When the caller has exactly one authenticator, `MethodRow.RemoveImpact` lists the names of the caller's apps whose ✓ turns ✗ without `totp`. The page shows that list before it opens `delete_credential`.
- **T8 Setup links.**
  - `invite.Client.Create(ctx, username, invite.Options{Authenticator bool})`.
  - The body of enroll's `POST /internal/invites` gains `"authenticator": true|false` (strict; absent = false).
  - On redeem, enroll adds `CONFIGURE_TOTP` after `webauthn-register-passwordless`.
  - The Hub's `POST /api/directory/users/{u}/invite` takes `{"authenticator": bool}` and refuses `true` while `totp` is off (409 "authenticator apps are off on this server").
  - Today every setup link registers a passkey (enroll has no password-only link), so "after the password step" (spec §6.5) is "after the passkey step".
- **T9 Fresh popup asks for the code.** `freshauth.AuthorizeInfo` gains `PcMethod string json:"pc_method,omitempty"`, set to `"totp"` only when `FreshAccepted(governing rule)` is exactly `{totp}`. It is set on the three views that start a popup: MySignIn, the confirmation page and My apps. `freshauth.js` then adds `pc_method=totp` to the authorize URL. Any other value is never sent.
- **T10 Fresh `totp` never adds a first password.** In `SetOwnPassword` it is refused like a fresh `password` when there is no password yet. It never approves a certificate (`certFreshAllowed` drops it).
- **T11 History.**
  - A new kind `method`.
  - `keycloak.ConfigEventTypes` and `HistoryEventTypes` gain `UPDATE_CREDENTIAL` and `REMOVE_CREDENTIAL`, and only `credential_type=otp` events are kept.
  - The override puts `pc_replaced=<old label>` on its `UPDATE_CREDENTIAL`, giving "authenticator app replaced: <label>".
  - Other entries are "added: <label>" / "removed: <label>".
  - Removals through the Hub's help route come from the audit (`user.remove_authenticators` → `help`).
- **T12 Doctor inputs.**
  - `keycloak.Client.OTPPolicy(ctx)` (realm GET + the two required-action configs) feeds `signin_totp_policy_drift`.
  - The history's Keycloak event reader (`LOGIN_ERROR` in the last 24 h whose `pc_method` is `totp`, per user) feeds `signin_totp_guessing` (≥ 20). The fingerprint is `Fingerprint(kind, user, yyyy-mm-dd)`.
- **T13 Impersonated session.** `portcullis-otp` answers `attempted` and never challenges, so the person's code is never asked for. `portcullis-template` then shows its impersonation "needs" page, as for any method the admin's session lacks.
- **T14 Theme copy.** Core's `portcullis` login theme gets a copy of keycloak.v2's `login-config-totp.ftl`. It is needed for the unique label "Authenticator <yyyy-MM-dd HH:mm>": Keycloak refuses a second credential with the same label, which is the passkey lesson.
- **T15 Message keys** in `messages_en.properties`: `portcullisTotpOff`, `portcullisTotpNotAvailable`, `portcullisTotpStrongerThanSession`, `portcullisTotpLimit`, `portcullisTotpReplaceUnknown`, `portcullisMethod_totp=code from an authenticator app`, `portcullisArticle_totp=a`, `portcullisSetUpAuthenticator=Set up an authenticator app`.
- **T16 The needs-stronger pages** (`NeedsStronger.of`, group-gate's `render_needs_page`) get a third set-up link, `portcullis-set-up-authenticator`. It appears when `totp` is missing, not set up, and `add_stronger` is on or 15 ≤ the session's strongest tenths. Otherwise the page says "or ask your admin".
- **T17 Settings warning** = `SignInView.CoreWarnings map[string]string` (key `hub` / `people`), shown next to the pick.
- **T18 `MaxAuthenticators = 3`** in Java (`TotpRegister.MAX`) and Go (`hub.MaxAuthenticators`). The Go value hides "+ Add" at 3. The Java value is the enforcement.
- **T19 Replace parameter.** It is read from the authentication session's client note `kc_action_parameter` (Keycloak's parameterised AIA). Anything but `replace:<uuid of an own otp credential>` refuses before the QR is shown. The builder confirms the note name on 26.8.1 (spec §14) and pins it in a unit test.
- **T20 Vector fix.** The existing case "strong: unknown amr values count as nothing" holds `"otp"`, which this plan makes a known amr. It becomes `"sms"`, so the case keeps testing unknown values.
- **T21 `methodSet` stays `uint8`** (7 of 8 bits). A test pins `len(Methods) <= 8` with a message that names the type to widen.
- **T22 mcp-gate counts `totp`.** The browser sign-in behind the token typed the code, and the gate has no certificate-style binding to check.
- **T23 `status`:**
  - `keycloak.otp_policy {ok, problems}` and textfile `portcullis_keycloak_otp_policy_ok`, from `kc_otp_policy_drift` (policy + the two `max_auth_age`).
  - `system.clock_synced` (`true` | `false` | `"unknown"`) and textfile `portcullis_system_clock_synced` (absent when unknown).
- **T24 Restore warning.** `cmd_restore` prints, as its last line: "Authenticator apps removed after this backup's date work again: remove the ones reported lost since then (People → person → Sign-in)."
- **T25 `otp-config`** is the authenticator config of the new execution: `default.reference.value` `otp`, `default.reference.maxAge` `36000`. It is placed after `portcullis-password-form`, priority 50.
- **T26 Event builder detail names.** `portcullis-otp` writes `pc_method=totp` and `pc_ua` through `History.onFailure(context, "totp")`. The override writes `credential_type` (Keycloak's) and `pc_replaced` (T11).
- **T27 e2e.** A new module, `tests/e2e/e2e_totp.py`, runs inside the existing `e2e-signin` job after `e2e_signin.py`, with its own `check` cases. No new job (ci.yml size), and `e2e_signin.py` (3334 lines) isn't grown.
- **T28 `invite --replace-keys`** also deletes `otp` credentials (`INVITE_PASSKEY_TYPES_JQ` gains `"otp"`; the help text says "passkeys, security keys and authenticator apps").
- **T29 Brute force is shared.** Wrong codes count in the same realm counter as wrong passwords. That is accepted and documented: one counter, never permanent.
- **T30 `delete_credential`'s `max_auth_age` 300 applies to every credential type.** Deleting a passkey from the account console now needs a sign-in within 5 minutes too. That is accepted as stricter.

## Review Focus

1. **A code-only way in hidden by nesting or redundancy.** Examples: `any[totp, all[totp, password]]`, `all[totp, any[totp]]`, and a `family:*` next to `totp` in an `any`. A person expects every save to be refused and every reader to refuse the compiled form. Pinned by Task 6 (`TestValidateCodeOnlyNested`, a property test over random rules) and by the vector `reject` cases checked in Tasks 2 and 11.
2. **A password-only session adding an authenticator outside the Sign-in page.** This covers the account console's "Set up authenticator application" and a hand-made `kc_action=CONFIGURE_TOTP` URL. A person expects the same refusal as the page: the override is the only gate. Pinned by Task 4 (`TotpRegisterTest.capRefusesPasswordOnly`, `…accountConsoleUsesOverride` through the factory id) and by Task 13 (`pat_cap_refused`).
3. **A fresh confirmation inside a live session under `all[password, totp]`.** A person expects one typed code to confirm, and a fresh password alone to be refused (403). Pinned by Task 9 (`TestFreshPcMethodTOTPOnly`, `TestCheckFreshAuthPasswordUnderPasswordAndCode`) and Task 13 (`fresh_one_code`).
4. **Replace naming the wrong credential.** This covers a passkey id, another person's `otp` id, garbage, and an id removed between the click and the post. A person expects a refusal before any QR code, with nothing stored, and the old authenticator untouched. Pinned by Task 4 (`TotpRegisterTest.replaceForeignRefused`, `…replaceGoneBetweenChallengeAndPost`).
5. **The seed escaping into logs or artifacts.** Candidates are Keycloak's log at DEBUG, the Hub's credential listing, a failure screenshot, or a Playwright trace. A person expects it to appear nowhere. Pinned by Task 7 (`TestSignInCredentialsNeverKeepsCredentialData`: the struct has no field for it and `credentialData` of an `otp` row is dropped), by Task 4 (`TotpRegisterTest.logsNoSecret`, a captured JBoss log) and by Task 13 (`no_secret_anywhere`, plus the QR / key element hidden before every screenshot).

---

### Task 1: Contract and docs (docs repo)

**Files:**
- Modify: `docs/guides/integration-contracts.md`:
  - §8.1 "Sign-in methods" (line 1231 on main): the table row, starting state, families, grammar rule, built-in, provider table + flow, OTP policy, `pc_method`, `pc_fresh`, the certificate fresh-auth exclusion, inventory, MaxAuthenticators.
  - §8.2 (1601): the error-by-method map, kind `method`, the credential events and `pc_replaced`.
  - §5 / §5.1 (740 / 889): the needs-stronger link, the Sign-in page row, the rename route, the route count, `refresh=1`, `fresh_auth.pc_method`.
  - §9.4 (1721): `authenticator` on invites.
  - §9.6 / §9.7 (1788 / 1936): `remove-authenticators`, `can.remove_authenticators`, and `authenticator` on the Hub's invite route.
  - §14.5 (3946): the two doctor kinds.
  - §15.10 (4645): the MCP twin `remove_authenticators`.
  - §4: group-gate's `AMR_TO_METHOD` / `STEPUP_METHODS` and the reject rule.
- Modify: `docs/operations/auth-policies.md`: "Authenticator app" section covering what codes are good and bad for, the supported apps (Google Authenticator, Microsoft Authenticator, Authy, 1Password, Bitwarden, FreeOTP, Aegis, Raivo), a lost phone, the "Password + authenticator code" template, and shared brute force (T29).
- Modify: `docs/operations/backups.md`:
  - backups: "it also holds every authenticator app's secret: whoever has it can generate codes";
  - restore checklist: re-remove authenticators reported lost after the backup's date (T24).
- Modify: `docs/operations/hub.md` (Sign-in page row, help action, invite option, Settings warning).
- Modify: `docs/operations/cli.md` (`invite --replace-keys` wording, `status` lines).
- Modify: `docs/operations/testing.md` (`e2e_totp.py` in e2e-signin).

- [ ] **Step 1:** Write every section above, with the values from Global Constraints copied verbatim and every T-ruling that touches an interface (T2, T5, T6, T8, T9, T11, T15, T16, T19, T23). Do not add a version bump; state why (spec §8 "Versions").
- [ ] **Step 2:** Run `zensical build --strict`. Expected: no warnings.
- [ ] **Step 3:** Commit `docs: authenticator-app codes (totp) in the contract and guides`.

### Task 2: Extension — the method table, `PcMethod`, rules, vectors (keycloak)

**Files:**
- Modify: `src/main/java/eu/portcullis/signin/Methods.java`. Add `new Info("totp", "otp", 15)` after password in `TABLE`. The `tenths` javadoc gains 15. `IDS` gains it automatically.
- Modify: `src/main/java/eu/portcullis/signin/Rule.java`. `parse` refuses a rule with an alternative equal to `{totp}`: `IllegalArgumentException("compiled rule: an authenticator code alone is a way in")`.
- Modify: `src/test/resources/signin_vectors.json` (the Hub's new file from Task 6, byte copy). Test: `src/test/java/eu/portcullis/signin/{RuleTest,PcMethodTest,SigninConfigTest}.java`, and a new `MethodsTest.java` (`forAmr("otp")`, `tenths("totp") == 15`, `IDS` order).
- Modify: `CLAUDE.md` (Layout rows for `Methods`, `Rule`, `PcMethod`: seven ids).

**Interfaces:**
- Produces: `Methods.IDS` (7 ids, canonical order), `Methods.forAmr("otp") == Optional.of("totp")`, `Methods.tenths("totp") == 15`, `PcMethod.parse("totp")` present, `Rule.parse` refusing code-only alternatives.

- [ ] **Step 1: Write the failing tests:**
  - `RuleTest.codeOnlyAlternativeRefused`: `parse({"op":"any","items":["totp","security_key"]})` throws; `parse({"op":"all","items":["password","totp"]})` has alternatives `[[password, totp]]`.
  - `PcMethodTest.totpParsed`: `parse("totp")` = `totp`; `allows(Optional.of("totp"), "password")` false.
  - `SigninConfigTest.methodsTotpSortedLast`: `["passkey_synced","totp"]` loads and `["totp","passkey_synced"]` is DENY_ALL.
  - `RuleTest.sharedVectors` runs on the new file.
- [ ] **Step 2:** Run `docker build --target test .`. Expected: FAIL (`totp` unknown).
- [ ] **Step 3:** Implement the two Java changes, then copy the vectors file from the Hub's `totp1` branch (Task 6 Step 4 produces it; land Task 6 Step 4 first, or write the same bytes here and let the vectors job confirm).
- [ ] **Step 4:** Run `docker build --target test .`. Expected: `BUILD SUCCESSFUL`.
- [ ] **Step 5:** Commit `signin: totp in the method table, pc_method and the readers' code-only refusal`.

### Task 3: Extension — `portcullis-otp`, the template and the pages (keycloak)

**Files:**
- Create: `src/main/java/eu/portcullis/signin/OtpAuthenticator.java`, `OtpAuthenticatorFactory.java`.
- Modify: `TemplateAuthenticator.java`:
  - `KEPT_NOTES` + `OtpAuthenticator.METHOD_NOTE`;
  - `ranMethods` reads it (value `totp` only);
  - `completable` adds `case "totp" -> OtpAuthenticator.usable(user, cfg)`;
  - `setUp` adds `totp` when on and an `otp` credential exists;
  - the `freshMethod` javadoc gives the new order.
- Modify: `Offer.java` (`usable`: the `portcullis-otp` execution only while `cfg.on("totp")`, `PcMethod.allows(requested, "totp")`, `known != null`, `!PasswordForm.refused(known.getUsername())`, and `known` has an `otp` credential).
- Modify: `NeedsStronger.java` (field `setUpAuthenticator`, T16), `src/main/resources/theme-resources/templates/portcullis-needs-stronger.ftl` (the link `id="portcullis-set-up-authenticator"`) and `messages_en.properties` (T15).
- Modify: `src/main/resources/META-INF/services/org.keycloak.authentication.AuthenticatorFactory` (+ `eu.portcullis.signin.OtpAuthenticatorFactory`).
- Test: `OtpAuthenticatorTest.java`, `TemplateAuthenticatorTest.java`, `OfferTest.java`, `NeedsStrongerTemplateTest.java` (uses `Fake`, `Flow`, `Configs`).

**Interfaces:**
- Consumes: Task 2's table.
- Produces:
  - `OtpAuthenticatorFactory.PROVIDER_ID = "portcullis-otp"`;
  - `OtpAuthenticator.METHOD_NOTE = "portcullis.otp.method"`, `OtpAuthenticator.TOTP = "totp"`, `OtpAuthenticator.OTP_TYPE = "otp"` (Keycloak's `OTPCredentialModel.TYPE`);
  - `static boolean usable(UserModel user, SigninConfig cfg)`: `totp` on, not `PasswordForm.NO_PASSWORD`, at least one `otp` credential;
  - `static boolean steps(AuthenticationFlowContext c, SigninConfig cfg)`: false = `attempted`.

- [ ] **Step 1: Write the failing tests** (`OtpAuthenticatorTest`):
  - `offWhenSwitchedOff`, `attemptedWithoutUser` (no username field is ever rendered: `Flow.form()` untouched), `attemptedWithoutCredential`, `attemptedForAdminAndHub`, `attemptedWhenPcMethodOther` (`pc_method=password`), `attemptedWhenImpersonated` (T13; `ImpersonationGuard.impersonated` stand-in present).
  - `successWritesNote`: a stock success → auth note `portcullis.otp.method` = `totp`.
  - `failureAddsHistory`: a wrong code → event details `pc_method=totp`, `pc_ua` set, error `invalid_user_credentials`, `Flow.countedByBruteForce()` true.
- [ ] **Step 2: More failing tests:**
  - `TemplateAuthenticatorTest.passwordAndCodeStepByStep`: rule `all[password, totp]`; after the password the step asks `totp` (`PcMethod.STEP_NOTE` = `totp`); after the code it succeeds with LOGIN details `pc_methods=password,totp`.
  - `TemplateAuthenticatorTest.freshOrderTotpAbovePassword`: `freshMethod` with both notes = `totp`; with `passkey_synced` too = `passkey_synced`.
  - `TemplateAuthenticatorTest.totpNotCandidateWithoutCredential`.
  - `OfferTest.otpOnlyWithKnownUserAndCredential`.
  - `NeedsStrongerTemplateTest.authenticatorLink`: password session, rule `all[password, totp]`, no credential, `add_stronger` false → askAdmin true, `setUpAuthenticator` false. Session `spk` → `setUpAuthenticator` true. The rendered HTML has `id="portcullis-set-up-authenticator"` and "a code from an authenticator app".
- [ ] **Step 3:** Run `docker build --target test .`. Expected: FAIL.
- [ ] **Step 4: Implement `OtpAuthenticator`**. It wraps (holds, never extends) a stock `OTPFormAuthenticator` and is not a `CredentialValidator` (spec §7.1, the part-1 lesson).
  - `authenticate` / `action`: `steps()` false → `context.attempted()`. Otherwise delegate.
  - Before the stock `action`, call `History.onFailure(context, "totp")`.
  - After a stock success, set the auth note.
  - `requiresUser()` false; `configuredFor` = `usable`; `setRequiredActions` does nothing (setup is only through the AIA).
  - The factory: `getReferenceCategory()` `otp`, display text "Authenticator app code (Portcullis)", requirement choices ALTERNATIVE / DISABLED, `isUserSetupAllowed()` false.
- [ ] **Step 5:** Implement the `TemplateAuthenticator`, `Offer`, `NeedsStronger`, ftl and messages changes listed under Files.
- [ ] **Step 6:** Run `docker build --target test .`. Expected: `BUILD SUCCESSFUL`.
- [ ] **Step 7:** Commit `signin: portcullis-otp execution, template steps, Try another way and the needs-stronger link`.

### Task 4: Extension — the `CONFIGURE_TOTP` override (keycloak)

**Files:**
- Create: `src/main/java/eu/portcullis/signin/TotpRegister.java` (extends the stock `org.keycloak.authentication.requiredactions.UpdateTotp`), `TotpRegisterFactory.java` (extends the stock `UpdateTotpFactory`; the same provider id `CONFIGURE_TOTP`, `order()` 1, `getOperationalInfo()` = `Map.of("portcullis", "totp")`, `ServerInfoAwareProviderFactory`).
- Modify: `META-INF/services/org.keycloak.authentication.RequiredActionFactory` (+ `eu.portcullis.signin.TotpRegisterFactory`), `messages_en.properties` (T15 keys, the limit text verbatim).
- Test: `TotpRegisterTest.java`.

**Interfaces:**
- Consumes: `PasskeyRegister.sessionAmr(realm, auth, userSession)`, `PasskeyRegister.SETUP_LINK_AMR`, `ImpersonationGuard.impersonated(...)`, `PasswordForm.refused`, `SigninConfig.current()`, `History.reapply`.
- Produces:
  - `static Decision decide(Set<String> sessionAmr, boolean addStronger, SigninConfig cfg, String username, int existing, Optional<String> replaceParam, Set<String> ownOtpIds)`;
  - `record Decision(boolean allowed, String messageKey, String replaceId)`;
  - `static final int MAX = 3`;
  - `static final String REPLACE_PREFIX = "replace:"`.

- [ ] **Step 1: Write the failing tests** (`TotpRegisterTest`, pure `decide` first, in this order):
  - `offRefused` → `portcullisTotpOff`;
  - `reservedRefused` (admin, portcullis-hub) → `portcullisTotpNotAvailable`;
  - `capRefusesPasswordOnly` (`pwd`, add_stronger false) → `portcullisTotpStrongerThanSession`;
  - `capAllowsPasswordAndCode` (`pwd`+`otp`);
  - `capAllowsSyncedPasskey` (`spk`);
  - `setupLinkNoCap` (`inv`);
  - `addStrongerOnNoCap`;
  - `fourthRefused` (existing 3, no replace) → `portcullisTotpLimit`;
  - `replaceAtLimitAllowed` (existing 3, own id);
  - `replaceForeignRefused` (an id not in `ownOtpIds`, a passkey's id, garbage, `replace:` empty) → `portcullisTotpReplaceUnknown`;
  - `unknownParameterRefused` (`foo`).
- [ ] **Step 2: More failing tests** (the action, over `Fake` contexts):
  - `impersonatedRefusedPage`: 403, `portcullis-impersonating.ftl` mode refused, nothing stored, an `UPDATE_CREDENTIAL` error event.
  - `challengeRefusesBeforeQr`: a refused `decide` → error page with a link to `PORTCULLIS_SIGNIN_URL`, and the stock challenge never called (no secret generated).
  - `replaceDeletesOldInSameTransaction`: after a stock success, the named credential is removed through `user.credentialManager().removeStoredCredentialById` and the event detail is `pc_replaced=<old label>`.
  - `replaceGoneBetweenChallengeAndPost`: the id vanishes before `processAction` → refusal, the new credential not kept (throw → rollback, as `PasskeyRegister`).
  - `logsNoSecret`: a JBoss log capture over a full success has no `secret`, `totpSecret`, base32 run ≥ 16 chars, or `otpauth:`.
  - `factoryMarker`: the operational info is `portcullis: totp` and the factory id is `CONFIGURE_TOTP`.
- [ ] **Step 3:** Run `docker build --target test .`. Expected: FAIL.
- [ ] **Step 4: Implement the override.**
  - `requiredActionChallenge` and `processAction` call `decide` with:
    - `cfg.addStronger()`;
    - `existing` = the user's `otp` credential count;
    - the replace parameter from the client note (T19);
    - the user's `otp` ids.
  - A refusal answers the error page, logging only the username, the credential id and the outcome. Success delegates to the stock code.
  - On replace, after a stock `SUCCESS`, delete the named credential and then call `History.reapply(context)`.
- [ ] **Step 5:** Run `docker build --target test .`. Expected: `BUILD SUCCESSFUL`.
- [ ] **Step 6:** Commit `signin: CONFIGURE_TOTP override: switch, reserved accounts, impersonation, cap, limit of 3, replace`.

### Task 5: Extension — smoke realm, live smoke, provider list (keycloak)

**Files:**
- Modify: `src/test/resources/smoke-realm.json`:
  - the `portcullis-signin` executions, `otp-config` and the `requiredActions` `CONFIGURE_TOTP` / `delete_credential` (with `config.max_auth_age` `"300"`), exactly as core's export after Task 12;
  - the `otpPolicy*` fields;
  - `enabledEventTypes` + `UPDATE_CREDENTIAL`, `REMOVE_CREDENTIAL`.
- Modify: `.github/workflows/build.yml` (`PROVIDER_IDS` + `portcullis-otp CONFIGURE_TOTP`), `.github/smoke/signin.py`, `.github/smoke/requirements.txt` (+ `pyotp==2.9.0` with `--hash` lines, the same pin as core's e2e).
- Modify: `CLAUDE.md` (provider ids, Layout rows for `OtpAuthenticator*`, `TotpRegister*`).

- [ ] **Step 1: Write the smoke cases** in `signin.py`:
  - `totp_override_marker` (serverinfo `portcullis: totp`);
  - `totp_signin` (an admin-API-free path: `kc_action=CONFIGURE_TOTP` on the smoke user after a password sign-in with `add_stronger` on in the smoke file, read the manual key from the page, compute with `pyotp`, then a new sign-in password → code; amr `pwd`+`otp`);
  - `totp_replay_refused` (the same code on a second sign-in within its step → refused);
  - `totp_pc_method_only_code` (`pc_method=totp` on an SSO session shows only the code form).

  Mask the key with `::add-mask::`, never print it, and take no screenshot while it is shown.
- [ ] **Step 2:** Push `totp1` and watch the `smoke` job (your own `gh run watch` in the background). Expected: green, with every `PROVIDER_IDS` entry listed.
- [ ] **Step 3:** Commit `ci: smoke realm and live smoke for authenticator codes`.

### Task 6: Hub — `internal/signin`: table, code-only rule, score, built-in, vectors, default off (hub)

**Files:**
- Modify: `internal/signin/methods.go`:
  - `TOTP Method = "totp"`;
  - `Methods` with TOTP second;
  - `methodInfo[TOTP] = {TOTP, "Authenticator app", "authenticator app", "a code from an authenticator app", "otp", 15, true}`;
  - `families` unchanged.
- Modify: `internal/signin/rule.go`:
  - `Validate` calls `checkCodeOnly`;
  - `ValidateCompiled` refuses a `{totp}` alternative with "compiled rule: an authenticator code alone is a way in";
  - `type CodeOnlyError struct{ At Path }` with `Error()` = "an authenticator code can't be the only way in: combine it with another method (all of)".
- Modify: `internal/signin/score.go` (T3 suffix), `internal/signin/builtin.go` (fifth built-in: `{ID: "password-and-code", Name: "Password + authenticator code", Rule: g(OpAll, "password", "totp"), BuiltIn: true}`, disabled; the doc comment says five).
- Modify: `internal/signin/testdata/vectors.json` (T20 and the spec §8 vectors).
- Modify: `internal/state/signin.go` (`defaultMethodOn`: also false for `signin.TOTP`).
- Modify: `internal/freshauth/freshauth.go` (`FreshMethods` + `"totp"` in second place).
- Test: `internal/signin/signin_test.go`, `implies_prop_test.go`, `vectors_test.go`, `internal/state/state_test.go`, `internal/freshauth/freshauth_test.go`.

**Interfaces:**
- Produces:
  - `signin.TOTP`;
  - `signin.CodeOnlyError`;
  - `func CodeOnly(n Node) (Path, bool)` (the deepest offending group of a source rule, computed with every method on);
  - `Builtins()` returning five.

- [ ] **Step 1: Write the failing tests:**
  - `TestTOTPRow`: `InfoOf(TOTP).Tenths == 15`; `MethodForAMR("otp") == TOTP`; `rank(TOTP) == 1`.
  - `TestScoresWithTOTP`: `ScoreOf(all[password,totp], allOn).Tenths == 19`, `all[passkey_synced,totp]` 29, `all[security_key,totp]` 39. The first reason ends "; codes can be typed into a fake site" and the third doesn't.
  - `TestValidateCodeOnlyNested`: `any[totp, security_key]`, `any[totp, all[totp, password]]`, `all[totp, any[totp]]` and `all[any[totp, password], any[totp, security_key]]` all return `*CodeOnlyError`, with `At` = `Path{}`, `Path{}`, `Path{1}` and `Path{0}` (the deepest group with a `{totp}` alternative, the first in rule order on a tie). `all[password, totp]` passes.
  - `TestCodeOnlyIgnoresSwitches`: `any[totp, security_key]` is refused even with `security_key` on and `totp` off.
  - `TestValidateCompiledRejectsCodeOnly`.
  - `TestBuiltinsFive`: `password-and-code` disabled, rule `all[password, totp]`.
  - `TestFreshAcceptedPasswordAndCode`: = `{totp}`.
  - `TestMethodSetFits`: `len(Methods) <= 8` (T21).
  - `TestEnsureSignInTOTPOff` (state): fresh → `Methods["totp"] == false`; stored without the key → false.
- [ ] **Step 2: Extend the property test** (`implies_prop_test.go`): for random valid rules and random switch sets, `Compile(n, on)` never yields an alternative `{totp}` (the argument from T2: an alternative under fewer switches is a pre-minimal alternative under all switches).
- [ ] **Step 3:** Run `go test ./internal/signin/ ./internal/state/ ./internal/freshauth/`. Expected: FAIL.
- [ ] **Step 4: Implement**, then write the vectors:
  - T20's `"otp"` → `"sms"`;
  - `password and code: both` (`all[password,totp]`, on [password,totp], have `["pwd","otp"]` → true, alternatives `[["password","totp"]]`);
  - `password and code: password alone` (`["pwd"]` → false);
  - `password and code: code alone` (`["otp"]` → false);
  - `code only: refused` (`any[totp, security_key]` → `"error"`: the CodeOnlyError text);
  - `reject: a code-only alternative` (compiled `{"op":"any","items":["totp","security_key"]}`);
  - `password and code: totp off` → `error` = ErrUnmeetable's text;
  - `setup link plus code counts the code only` (`all[password,totp]`, have `["inv","otp"]` → false).

  `TestSharedVectors`' error comparison for an `error` case uses the error's text.
- [ ] **Step 5:** Run `go test -race ./internal/...`. Expected: PASS. Fix every package test that counts methods, built-ins or `FreshMethods`, such as Settings view fixtures and `signinreset`.
- [ ] **Step 6:** Commit `signin: totp row, code-only rule, score reason, password-and-code built-in, vectors`.

### Task 7: Hub — Keycloak client, inventory, Sign-in page view, rename route, refresh (hub)

**Files:**
- Modify: `internal/keycloak/keycloak.go`:
  - `const OTPType = "otp"`;
  - `SignInCredentials` appends `PasskeyCredential{ID, Type: "totp", Label, Created}` for `cr.Type == OTPType` (no AAGUID; `credentialData` never read for it);
  - `var ErrAuthenticatorNotFound = errors.New("no such authenticator app")`;
  - `func (c *Client) SetAuthenticatorLabel(ctx, username, credentialID, label string) (old string, err error)`;
  - `func (c *Client) RemoveAuthenticators(ctx, username string) (int, error)` (deletes `otp` only, then `logout`);
  - `type OTPPolicy struct{ Type, Algorithm string; Digits, Period, LookAhead, InitialCounter int; CodeReusable bool; ConfigureMaxAge, DeleteMaxAge int }`;
  - `func (c *Client) OTPPolicy(ctx) (*OTPPolicy, error)`.

  `SetPasskeyLabel` and `SetAuthenticatorLabel` share one unexported `setCredentialLabel(ctx, username, id, label string, types map[string]bool, notFound error)`.
- Modify: `internal/hub/signin_people.go`:
  - `SignInSources.AuthenticatorLabel func(ctx, username, credentialID, label string) (string, error)`;
  - `loadInventory` drops `totp` for `ownPasswordRefused(u)` accounts.
- Modify: `internal/hub/mysignin.go`:
  - `MethodRow.Authenticators []AuthenticatorRow json:"authenticators,omitempty"`;
  - `MethodRow.RemoveImpact []string json:"remove_impact,omitempty"`;
  - `type AuthenticatorRow struct{ ID, Label string; CreatedAt time.Time }` (json `id`, `label`, `created_at`);
  - `MySignIn.MaxAuthenticators int json:"max_authenticators"`;
  - `const MaxAuthenticators = 3`;
  - a `case meth == signin.TOTP` branch before `default`;
  - `func (h *Hub) RenameOwnAuthenticator(ctx, user, credentialID, label string) error` (audit `signin.authenticator.label`);
  - `func (h *Hub) RefreshMySignIn(user string)` (T5).
- Modify: `internal/httpapi/mysignin.go` (`PUT /api/me/signin/authenticators/{credentialId}/label` → `handleRenameOwnAuthenticator`; `handleMySignIn` honours `refresh=1`; the register comment's route count).
- Modify: `cmd/hub/main.go` (`AuthenticatorLabel: kc.SetAuthenticatorLabel` in `SetSignInSources`).
- Test: `internal/keycloak/users_test.go`, `internal/hub/mysignin_test.go`, `internal/hub/signin_people_test.go`, `internal/httpapi/mysignin_test.go`, `internal/httpapi/webui_mysignin_test.go` (route list).

**Interfaces:**
- Consumes: Task 6 (`signin.TOTP`).
- Produces: the JSON shape `methods[].authenticators[] {id,label,created_at}`, `methods[].remove_impact[]` and `max_authenticators`, which Task 10's UI reads. Also `keycloak.Client.RemoveAuthenticators` and `OTPPolicy`, which Tasks 8 and 9 use.

- [ ] **Step 1: Write the failing tests:**
  - `TestSignInCredentialsOTP` (fake admin API): an `otp` row becomes Type `totp`, Label and Created set.
  - `TestSignInCredentialsNeverKeepsCredentialData`: the `otp` row's `credentialData` (`{"subType":"totp","digits":6,…}`) is in no field and no log line (capture `log.SetOutput`).
  - `TestSetAuthenticatorLabelRefusesPasskey` → `ErrAuthenticatorNotFound`.
  - `TestSetPasskeyLabelRefusesOTP` → `ErrPasskeyNotFound`.
  - `TestRemoveAuthenticatorsOnlyOTP` (passkeys kept, logout called).
  - `TestOTPPolicyReadsRealmAndActions`.
- [ ] **Step 2: More failing tests:**
  - `TestMySignInTOTPRow`: two authenticators → State `set`, rows sorted by `created_at`, `max_authenticators` 3. Off → `off`, rows omitted. `admin` → `none` even with a credential.
  - `TestRemoveImpactLastAuthenticator`: an instance on `password-and-code` → `remove_impact` = its name with one authenticator, empty with two.
  - `TestInventoryTOTPReservedNeverCounted`.
  - `TestRenameOwnAuthenticator` (204; 404 for a passkey id; 409 case-folded duplicate; 400 a 65-rune name; audited).
  - `TestRefreshMySignInThrottle` (two calls in 10 s → one `MarkInventoryStale`).
  - `TestRefuseWhileImpersonatedCoversAuthenticatorRename` (httpapi).
- [ ] **Step 3:** Run `go test ./internal/keycloak/ ./internal/hub/ ./internal/httpapi/`. Expected: FAIL.
- [ ] **Step 4:** Implement. The `totp` branch of `MySignInView`: `unknown` while `!keysKnown`, `set` with rows when `has[TOTP]`, else `none`.
- [ ] **Step 5:** Run `go test -race ./...`. Expected: PASS.
- [ ] **Step 6:** Commit `signin: authenticator apps in the inventory, the Sign-in page view and the rename route`.

### Task 8: Hub — help route, MCP twin, `can`, setup-link option, history (hub)

**Files:**
- Modify: `internal/directory/service.go`:
  - `Keycloak` interface + `RemoveAuthenticators(ctx, username string) (int, error)`;
  - `Inviter.Create(ctx, username string, o invite.Options) (*invite.Invite, error)`;
  - `func (s *Service) RemoveAuthenticators(ctx, c *Caller, username, confirm string) (*Result, error)` (audit `user.remove_authenticators`, detail `"<n> removed"` + `asHelp`, the same `helpPerm` / `isAdministrator` / `checkAdminTakeover` / typed-name rules as `RemovePasskeys`; `Result.Count`);
  - `SendInvite(ctx, c, username string, authenticator bool)`;
  - `newInvite(ctx, username string, o invite.Options)`.
- Modify: `internal/invite/invite.go` (`type Options struct{ Authenticator bool }`; the body `{"username", "authenticator"}`).
- Modify: `internal/httpapi/directory.go`:
  - `POST /api/directory/users/{username}/remove-authenticators` → `handleRemoveAuthenticators` (`{"confirm"}`);
  - `handleInvite` body `{"authenticator": bool}`;
  - the `rec` wrappers.
- Modify: `internal/httpapi/mcptools_signin_help.go` (twin `remove_authenticators`, class D, `ScopePeople` + `PermSignInHelp`, `helpPrecheck`, consequence "Removes every authenticator app of <u> and signs them out everywhere.") and `mcp_parity_test.go` (both lists).
- Modify: `internal/hub/signin_help.go` (`HelpCan.RemoveAuthenticators bool json:"remove_authenticators"`, true where `RemovePasskeys` is and only while `totp` is on).
- Modify: `internal/hub/` invite path: refuse `authenticator: true` while `totp` is off (T8 text, 409).
- Modify: `internal/signinhistory/entry.go` (`KindMethod Kind = "method"`), `internal/signinhistory/keycloak.go`:
  - `FailureTextFor(kcErr, method string) string`: `invalid_user_credentials` + `totp` → "wrong authenticator code"; `FromEvent` uses it;
  - `UPDATE_CREDENTIAL` / `REMOVE_CREDENTIAL` with `credential_type=otp` → `method`, detail per T11, everything else dropped.
- Modify: `internal/signinhistory/audit.go` (`user.remove_authenticators` → "authenticator apps removed").
- Modify: `internal/keycloak/events.go` (`ConfigEventTypes`, `HistoryEventTypes` + the two types).
- Test: `internal/directory/service_test.go`, `internal/httpapi/signin_help_test.go`, `directory_test.go`, `mcptools_directory_test.go`, `internal/signinhistory/signinhistory_test.go`, `internal/keycloak/events_test.go`, `internal/invite/invite_test.go`.

**Interfaces:**
- Consumes: Task 7's `keycloak.Client.RemoveAuthenticators`.
- Produces: `POST /api/directory/users/{u}/remove-authenticators` → 200 `Result` (`count`); `can.remove_authenticators`; `invite.Options`; history kind `method`.

- [ ] **Step 1: Write the failing tests:**
  - `TestRemoveAuthenticatorsTargets`: holder on alice ok, detail `"2 removed; as sign_in_help"`; holder on root 403; admin on another admin without the typed name 400; `portcullis-hub` 409.
  - `TestRemoveAuthenticatorsMCPTwin` (confirmation consequence text; parity lists).
  - `TestHelpCanRemoveAuthenticatorsOnlyWhenOn`.
  - `TestInviteBodyAuthenticator` (`{"username":"alice","authenticator":true}`).
  - `TestHubInviteAuthenticatorOff409`.
  - `TestFromEventWrongCode` (`LOGIN_ERROR`, `pc_method=totp` → "wrong authenticator code"; `password` keeps "wrong password").
  - `TestFromEventCredentialEvents` (added / replaced via `pc_replaced` / removed; `credential_type=password` dropped).
  - `TestFromAuditRemoveAuthenticators` (by carol → help).
  - `TestConfigEventTypesHasCredentialEvents`.
- [ ] **Step 2:** Run the packages' tests. Expected: FAIL.
- [ ] **Step 3:** Implement, then update every `Inviter` fake and the harness.
- [ ] **Step 4:** Run `go test -race ./...` and `go vet -tags harness ./internal/httpapi/...`. Expected: PASS.
- [ ] **Step 5:** Commit `signin: remove authenticator apps (help + MCP), setup links with an authenticator, history entries`.

### Task 9: Hub — fresh auth, certificates, Settings warning, preview, doctor (hub)

**Files:**
- Modify: `internal/freshauth/freshauth.go` (`AuthorizeInfo.PcMethod`, T9).
- Modify: `internal/hub/freshauth.go` (`func freshPcMethod(compiled signin.Node, on map[signin.Method]bool) string`), `mysignin.go`, `confirm.go:380`, `myapps.go:107` (fill `PcMethod` from each view's governing rule).
- Modify: `internal/hub/certificates.go:215` (`certFreshAllowed` also drops `signin.TOTP`).
- Modify: `internal/hub/mysignin.go` `SetOwnPassword` (T10: `m == signin.TOTP` treated like `signin.Password` in the "no password yet" refusal, text "pc_fresh names totp, but there is no password yet: …").
- Modify: `internal/hub/signin.go`:
  - `SignInView.CoreWarnings` (T17);
  - `PreviewTemplate`: a `*signin.CodeOnlyError` from `Validate` → 200 with `Problem` = its text and `TemplatePreview.CodeOnly []signin.Path json:"code_only"`;
  - `checkTemplateInput` keeps the 400.
- Create: `internal/doctor/signin_totp.go`:
  - `KindSignInTOTPPolicyDrift = "signin_totp_policy_drift"` (Problem, FixExplain, step "run `./portcullis keycloak configure`");
  - `KindSignInTOTPGuessing = "signin_totp_guessing"` (Warning, explain "change <user>'s password; the password was right and the code was wrong <n> times");
  - `type SignInTOTPIn struct{ PolicyDrift []string; Wrong map[string]int; Day string }`;
  - `Inputs.SignInTOTP *SignInTOTPIn`.
- Modify: `internal/hub/doctor.go` (gather with a 10 s timeout; nil on any error, which means no findings and the Keycloak error logged).
- Test: `internal/hub/freshauth_test.go`, `certificates_test.go`, `mysignin_test.go`, `signin_test.go`, `internal/doctor/signin_totp_test.go`.

**Interfaces:**
- Consumes: Task 7's `keycloak.Client.OTPPolicy`, the history's event reader (`hub/signin_history.go`).
- Produces: `fresh_auth.pc_method` (Task 10), `templates/preview` `code_only` (Task 10), `core_warnings` (Task 10).

- [ ] **Step 1: Write the failing tests:**
  - `TestFreshPcMethodTOTPOnly`: `all[password,totp]` → `"totp"`; `any[security_key, all[password,totp]]` → `""`.
  - `TestCheckFreshAuthPasswordUnderPasswordAndCode`: a proof with `pc_fresh=password` under that template → 403.
  - `TestCertFreshNeverTOTP`.
  - `TestSetOwnPasswordFreshTOTPNoPasswordYet` → 403 + audit reason.
  - `TestCoreWarningPasswordAndCode` (hub pick `password-and-code` → the warning text verbatim; Strong → none).
  - `TestPreviewCodeOnlyPath`: 200 with `code_only` `[[1]]` for `any[security_key, any[totp, passkey_synced]]`.
  - `TestSaveTemplateCodeOnly400` (text "rule: an authenticator code can't be the only way in: combine it with another method (all of)").
  - `TestDoctorTOTPDrift` (digits 8 → Problem naming `otpPolicyDigits`).
  - `TestDoctorTOTPGuessing` (19 → none, 20 → Warning, fingerprint per user and day).
  - `TestLockoutGuardCountsTOTP` (the only `lldap_admin` member has password + totp, hub pick `password-and-code`: the save passes; remove the totp from the inventory → 409).
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `go test -race ./...`. Expected: PASS.
- [ ] **Step 5:** Commit `signin: fresh auth asks for the code, no certificate or first password by code, core warning, code-only preview, doctor`.

### Task 10: Hub UI and docs copies (hub)

**Files:**
- Modify: `web/mysignin.js`:
  - `methodRow`'s `totp` branch: the list "<label> · added <date>" with Rename / Replace / Remove, then "+ Add authenticator app". "+ Add" is hidden at `max_authenticators` or when off. With `add_stronger` off and no set-up method ≥ 15, it shows "ask your admin for a setup link".
  - `ABOUT.totp`.
  - `labelProblem` gets a kind parameter.
  - `offers` gains `authenticators` (false while `readOnly`).
  - `onClick` gains `totp-add`, `totp-replace`, `totp-remove`, `totp-rename`.
  - After a popup ends, `load(st)` with `?refresh=1`.
  - After the first add, a hint recommends a second app (spec §6.5).
- Modify: `web/freshauth.js`:
  - `start(fa, h)` takes `h.kcAction` (`/^(CONFIGURE_TOTP(:replace:[0-9a-f-]{36})?|delete_credential:[0-9a-f-]{36})$/`, else refuse) → `kc_action`;
  - `fa.pc_method === 'totp'` → `pc_method=totp`.
- Modify: `web/freshauth-callback.js` (`msg.kc_action_status = q.get('kc_action_status') || ''`; the guard also accepts a callback with only `kc_action_status`).
- Modify: `web/signin.js` (`marksFor` marks `preview.code_only` paths `si-codeonly` with the preview's problem text; Settings shows `core_warnings[key]` next to the core pick).
- Modify: `web/directory.js`:
  - the person's Sign-in tab: "Remove authenticator apps" (`data-act="reset-authenticators"`, typed name, `can.remove_authenticators`; add it to `SIGNIN_TAB_ACTS`);
  - the invite dialog's "Also set up an authenticator app" checkbox (only while `totp` is on) → `{"authenticator": true}`.
- Modify: `web/docs/*.md` (`go generate ./web`).
- Test: `internal/httpapi/webui_mysignin_test.go`, `webui_signin_test.go` (the repo's existing static-JS checks: escaping, `data-*` + delegated listeners, the `kc_action` allowlist), `web/web_test.go`.

- [ ] **Step 1: Write the failing tests:**
  - `TestWebUIMySignInTOTPActions` (the four `data-msi-act` values, `esc()` on every label, no `innerHTML` with unescaped data);
  - `TestFreshAuthKcActionAllowlist` (the regex literal present; no other `kc_action` assignment);
  - `TestCallbackForwardsKcActionStatus`;
  - `TestSignInEditorMarksCodeOnly`.
- [ ] **Step 2:** Run `go test ./internal/httpapi/ ./web/`. Expected: FAIL.
- [ ] **Step 3:** Implement. Resync the docs copies with `PORTCULLIS_DOCS_DIR=… go generate ./web`.
- [ ] **Step 4:** Run `go test -race ./...`. Expected: PASS. Then check by hand on the local harness (`run` skill, `HUB_DEV=1`): the totp row, the editor's live refusal on `any[totp, security_key]` and the Settings warning, with screenshots in the task report.
- [ ] **Step 5:** Commit `web: authenticator apps on the Sign-in page, help, invite option, editor and Settings`, plus `web: docs copies resynced (totp)`.

### Task 11: group-gate, mcp-gate, oauth2-proxy, vector copies (core)

**Files:**
- Modify: `group-gate/group-gate.py`:
  - `METHOD_IDS` (totp second);
  - `AMR_TO_METHOD["otp"] = "totp"`, `METHOD_TENTHS["totp"] = 15`, `METHOD_WORDS["totp"] = "code from an authenticator app"`;
  - `STEPUP_METHODS` follows `METHOD_IDS`;
  - `validate_rule` (depth 1: any alternative `== frozenset({"totp"})` → "an authenticator code alone is a way in");
  - `render_needs_page` (T16: `authenticator` flag, `<a id="portcullis-set-up-authenticator" class="btn" href="{acct}">Set up an authenticator app</a>`; `totp` no longer falls into the "passwords and certificates" ask-admin branch);
  - the module docstring.
- Modify: `mcp-gate/internal/signin/rule.go` (`TOTP = "totp"`, `Methods`, `amrOf[TOTP] = "otp"`, `Validate` refuses a `{totp}` alternative; `TokenMethods` counts it, T22).
- Modify: `oauth2-proxy/alpha.yaml` (`pc_method` allow + `- value: totp` after `password`).
- Modify: `tests/signin_vectors.json`, `mcp-gate/internal/signin/testdata/signin_vectors.json` (byte copies).
- Modify: `CLAUDE.md` ("Sign-in methods" bullet: seven methods, `totp` (`otp`), `portcullis-otp`, the `CONFIGURE_TOTP` override).
- Test: `tests/test_group_gate.py`, `mcp-gate/internal/signin/rule_test.go`, `mcp-gate/internal/authz/authz_test.go`, and `tests/test_cli.sh` (a check that `alpha.yaml`'s allow list equals `STEPUP_METHODS`; add it if absent).

- [ ] **Step 1: Write the failing tests:**
  - `test_totp_amr_and_tenths`;
  - `test_validate_rule_code_only` (the reject vector; `all[password,totp]` fine);
  - `test_stepup_totp` (`choose_stepup(all[password,totp], {"password"}, {"password","totp"})` → `"totp"`; `stepup_url(...)` carries `pc_method=totp`);
  - `test_needs_page_authenticator_link` (password session, no totp set up, `add_stronger` false → "or ask your admin" and no link; a `passkey_synced` session → the link);
  - `TestTokenMethodsCountsTOTP`;
  - `TestValidateRejectsCodeOnly`;
  - `test_cli`: the allowlist equality.
- [ ] **Step 2:** Run `python3 tests/test_group_gate.py`, `cd mcp-gate && go test ./...` and `bash tests/test_cli.sh`. Expected: FAIL.
- [ ] **Step 3:** Implement and copy the vectors (`cmp` against the Hub's `totp1` file).
- [ ] **Step 4:** Rerun the Step 2 checks. Expected: PASS.
- [ ] **Step 5:** Commit `gate: totp in group-gate, mcp-gate and the step-up allowlist`.

### Task 12: Realm, `keycloak configure`, `status`, theme, enroll, CLI (core)

**Files:**
- Modify: `keycloak/realm-export.json`:
  - `portcullis-signin` + `{authenticator: "portcullis-otp", requirement: ALTERNATIVE, priority: 50, authenticatorConfig: "otp-config"}`;
  - `authenticatorConfig` + `{alias: "otp-config", config: {"default.reference.value": "otp", "default.reference.maxAge": "36000"}}`;
  - `requiredActions` + `CONFIGURE_TOTP` (enabled, priority 90, `config.max_auth_age` `"300"`) and `delete_credential` (enabled, priority 100, the same config);
  - the seven `otpPolicy*` values;
  - `enabledEventTypes` + `UPDATE_CREDENTIAL`, `REMOVE_CREDENTIAL`.
- Modify: `scripts/lib/keycloak.sh`:
  - `KC_REALM_OTP_SETTINGS` (the seven values as JSON), merged into the realm PUT next to `KC_REALM_SIGNIN_SETTINGS`;
  - `_kc_otp_actions` (registers / enables both actions and PUTs `/authentication/required-actions/{alias}/config` `{"config":{"max_auth_age":"300"}}`);
  - `kc_otp_policy_drift` (one line per differing setting, named; empty when equal);
  - `configure` fails on drift after the PUT (read back).
- Modify: `scripts/lib/status.sh` (T23: the `otp_policy` JSON next to `passkey_policy`; the line "authenticator codes: HmacSHA1, 6 digits, 30 s, one step of drift, no reuse; 5-minute sign-in to add or remove" / fail with the problems; `system.clock_synced` from `timedatectl show -p NTPSynchronized --value` else `chronyc tracking` offset < 5 s else unknown, Warning when false; the textfile metrics).
- Create: `keycloak/themes/portcullis/login/login-config-totp.ftl` (a copy of keycloak.v2's for 26.8.1, with the device-name input prefilled `Authenticator <yyyy-MM-dd HH:mm>` and the paragraph naming the apps (spec §6.1); the QR / manual-key elements keep their stock ids so the e2e can hide them).
- Modify: `enroll/invite.go` (`invite.Authenticator bool`, `redemption.Authenticator`; the API body strict `{"username","authenticator"}`; on redeem `requireTotp` (a new injected `func(string) error` adding `CONFIGURE_TOTP` through the `portcullis-enroll` service account) after `requirePasskey`; the CLI path never sets it) and `enroll/main.go` (the wiring).
- Modify: `scripts/lib/users.sh` (T28).
- Modify: `scripts/lib/backup.sh` `cmd_restore` (T24 line).
- Test: `tests/test_cli.sh` (stub admin API: the OTP PUT body, read-back failure exits 1, the drift lines, `INVITE_PASSKEY_TYPES_JQ` selects `otp`, the restore line), `tests/test_shell_libs.sh` (the clock helper with stubbed `timedatectl` / `chronyc`), `enroll/invite_test.go` (`TestCreateAuthenticatorStrictBody`, `TestRedeemAddsTotpAfterPasskey`, `TestCLINeverAuthenticator`).

- [ ] **Step 1:** Write the failing tests above.
- [ ] **Step 2:** Run `bash tests/test_cli.sh`, `bash tests/test_shell_libs.sh` and `cd enroll && go test ./...`. Expected: FAIL.
- [ ] **Step 3:** Implement. Copy the export's `authenticationFlows` / `authenticatorConfig` / `requiredActions` into the keycloak repo's `smoke-realm.json`; that is Task 5's file, and its compare job must stay green.
- [ ] **Step 4:** Rerun the Step 2 checks and shellcheck. Expected: PASS.
- [ ] **Step 5:** Commit `keycloak: portcullis-otp flow, OTP policy, required actions, status, theme, setup links, restore note`.

### Task 13: Browser e2e (core)

**Files:**
- Create: `tests/e2e/e2e_totp.py`. It imports `e2e_signin`'s helpers (`check`, `hub_ok`, `kc`, `invite`, `fresh_auth`, `people_json`, `mask`, `until`) and `e2e_login as base`.
- Modify: `tests/e2e/requirements.txt` (+ `pyotp==2.9.0` with its `--hash=sha256:` lines; `pip install --require-hashes`).
- Modify: `.github/workflows/ci.yml` job `e2e-signin` (one step "Authenticator codes": `python tests/e2e/e2e_totp.py`; artifacts as e2e-signin's; no traces). Re-run `bash tests/lint_ci_size.sh`.
- Create: `tests/e2e/apps/echo` instance `echo-otp` on template `e2e-otp` = `all[password, totp]`, made by the test through the Hub API (no new fixture dir).

- [ ] **Step 1: Write the cases**, each a `check(name, fn)`, the spec §12 list:
  - `pat_cap_refused`;
  - `pat_setup_link_authenticator`;
  - `password_then_code` (amr `pwd`+`otp`, LOGIN `pc_methods` `password,totp`);
  - `sso_stepup_only_code`;
  - `wrong_code_failed` (history "wrong authenticator code", brute-force count 1);
  - `replay_refused`;
  - `window` (`at(now-30)` ok, `at(now-90)` refused);
  - `fresh_one_code` (the confirmation popup with `pc_method=totp`; a password-only fresh sign-in 403);
  - `cert_fresh_totp_409`;
  - `replace_rename_remove`;
  - `fourth_refused`;
  - `carol_removes_alice`;
  - `root_impersonating_pat` (can't open `echo-otp`, Add refused);
  - `editor_refuses_code_only` (400 text);
  - `admin_no_code_step` (CI only);
  - `policy_read_back`;
  - `no_secret_anywhere` (the secret, its lowercase and unpadded forms absent from `docker compose logs`, the Hub's audit file and every history answer);
  - `finally` (method off, template and instance removed, authenticators removed).

  Read the secret from Keycloak's manual-key element, `mask()` it, and hide the QR / key elements with injected CSS before any screenshot. Never print or write it.
- [ ] **Step 2:** Run `gh workflow run ci.yml --ref totp1 -f jobs=e2e-signin` with your own background watcher. Expected: green; the job summary lists every case.
- [ ] **Step 3:** Run the full `ci.yml` on `totp1`. Expected: every job green.
- [ ] **Step 4:** Commit `e2e: authenticator codes`.

### Task 14: Test server (operational)

- [ ] **Step 1:** On the test server (`ACME_STAGING=true`; `config apply` + `up` after init), upgrade to the `totp1` images built by CI, run `./portcullis keycloak configure`, then `./portcullis status`. Expected: the otp policy line ok and the clock synced.
- [ ] **Step 2:** As a test person (never LLDAP `admin`), switch `totp` on, add an authenticator from a password + passkey session, sign in to an instance on `password-and-code` with a real phone app, then remove it. Switch `totp` off again unless the user asks otherwise.

### Task 15: Mainline (all repos)

- [ ] **Step 1:** Merge in order: docs → keycloak (wait for `edge`) → hub (wait for `edge`) → core. Do the `compare_ref=totp1` dispatches first, as listed under Global Constraints.
- [ ] **Step 2:** Re-run the templates repo's CI on `main`. Expected: green with no change (its harness's `methods` list doesn't name `totp`).
- [ ] **Step 3:** Delete every `totp1` branch (local and remote) and the `wt-totp1` worktrees (memory "branches mainlined").

## Self-review

- **Spec coverage:** every spec section maps to a task:

  | Spec | Task |
  |---|---|
  | §2 goals 1–6 | 6, 7, 8, 10 |
  | §4 anti-goals | 2, 3, 4, 6, 9, 13 |
  | §5.1–5.4 | 6, 9, 2, 11 |
  | §6.1–6.5 | 4, 7, 8, 10, 12 |
  | §7.1 | 3 |
  | §7.2 | 12 |
  | §7.3 | 5, 12 |
  | §8 | 6, 8, 11 |
  | §9 | 7, 8 |
  | §10 | 1, 12, 13 |
  | §11 | 9, 12 |
  | §12 | 2–13 |
  | §13 | 1, 11 |

  The spec §14 builder items are T19 (AIA parameter), Task 5 (slot, smoke-verified), T11 (event names), T14 (theme) and Task 5 (issuer string, asserted in `totp_signin` from the manual-key page).
- **Type consistency:** these names are used identically across tasks: `signin.TOTP`, `MaxAuthenticators`, `AuthenticatorRow`, `RemoveAuthenticators`, `invite.Options`, `freshauth.AuthorizeInfo.PcMethod`, `CodeOnlyError`, `OtpAuthenticator.METHOD_NOTE`, `TotpRegister.MAX`, `KindMethod`.
- **Proportion:** tasks give signatures, values and test names; bodies are left to the implementer, except the copy the spec fixes.
