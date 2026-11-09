# Sign-in methods, part 1 of 3 (methods, templates, scores, default and per app, warnings, password) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the two-checkbox auth policy (`mtls` / `webauthn`, all-of / any-of) with six server-wide sign-in methods, admin-editable templates (nested all-of / any-of rules with a /5 score), one default plus a per-app and per-core-page pick, and warnings for people who can't meet a template. Every enforcement point (group-gate, Keycloak, native-OIDC apps, mcp-gate, fresh auth) must accept exactly the switched-on methods a template names.

**Architecture:** The Hub owns methods, templates and picks (`state.yaml`). It compiles each template against the switched-on methods and publishes the compiled rules to three readers. group-gate reads them from policy file v6. A Portcullis Keycloak extension, in the new repo `porelli/portcullis-keycloak` (image `ghcr.io/porelli/portcullis-keycloak`), reads them from `signin-keycloak.json`. mcp-gate reads them from gate file v2. Keycloak records one amr value per method, and the stock `oidc-amr-mapper` accumulates them over the SSO session. The extension tells passkey kinds apart at registration by checking the attestation against Hub-published FIDO MDS roots with `webauthn4j`. It keeps the attestation in its own table, mirrors the current kind as the credential type, and reclassifies upward when a newer MDS list verifies it. It also asks for one specific method on step-up (`pc_method`) and checks native-OIDC clients' templates inside the browser flow. TLS client-certificate requests follow the switches through the per-app TLS option the Hub renders into router labels.

**Tech Stack:** Go 1.27 (Hub, mcp-gate, enroll), `github.com/go-webauthn/webauthn` (`metadata` package, BSD-3) for FIDO MDS, Python 3 (group-gate), Java 21 + Gradle with dependency verification (Keycloak 26.8.1 SPI, `webauthn4j` as Keycloak ships it, Keycloak's `JpaEntityProvider` + Liquibase for the extension's table), vanilla JS (Hub UI), bash (core CLI).

**Spec:** `docs/superpowers/specs/2026-11-09-sign-in-methods-design.md` (Hub repo). Mockups: `.superpowers/brainstorm/98502-1794260205/content/signin-settings.html`, `signin-nested-rule.html`, `signin-people.html` (only its section 2, "needs a stronger sign-in").

## Global Constraints

Process and checks (rules, verbatim):
- Branch `signin` in every repo touched (docs, keycloak, hub, templates, core), mainlined at the end, no PRs. The new repo `porelli/portcullis-keycloak` (local checkout `/Volumes/workspace/portcullis/portcullis-keycloak`) starts with `main` holding only the scaffolding, then `signin` on top of it. Docs: the main checkout is dirty with someone else's work, so work in a worktree: `git -C /Volumes/workspace/portcullis/portcullis-docs worktree add ../wt-docs-signin -b signin origin/main`. Core's local `main` is behind; branch from `origin/main`.
- No migration / back-compat code. There are no installs: policy file v5, gate file v1, `AuthPolicy` and `factors` disappear without readers for the old shapes.
- Contract first: Task 1 changes `docs/guides/integration-contracts.md` before any code.
- Never weaken access control, fail closed. An unknown method, rule shape or file version, or an unreadable file, denies. A method or template that is switched off is never accepted.
- Secrets never on argv or in logs or audit. Passwords go to LLDAP only through the existing `SetPassword` path, and are never audited or logged.
- Vanilla JS, everything escaped, data-* attributes plus delegated listeners.
- Go checks: gofmt go1.27.3 (`$(GOTOOLCHAIN=go1.27.3 go env GOROOT)/bin/gofmt -l .` prints nothing), `go vet ./...`, `go vet -tags harness ./internal/httpapi/...`, and the full `PORTCULLIS_TEMPLATES_DIR=/Volumes/workspace/portcullis/portcullis-templates go test -race ./...` (Hub; ends `ok` for every package).
- Core checks: `shellcheck -S warning portcullis scripts/lib/*.sh tests/*.sh`, `bash tests/test_cli.sh`, `bash tests/test_shell_libs.sh`, `python3 tests/test_group_gate.py`, plus `cd mcp-gate && go vet ./... && go test -race ./...` and `cd enroll && go test ./...`.
- Keycloak repo checks: `docker build --target test .` (Gradle `test` with `--dependency-verification strict`; ends `BUILD SUCCESSFUL`), `docker build .` (the image), and the CI vectors check.
- Core CI on the same-named branch builds the Hub from that branch, and likewise the Keycloak image (`.github/actions/keycloak-image`, mirroring `.github/actions/hub-image`).
- Implementers push and start CI without waiting.
- Never reformat outside the task.
- Merge order docs → portcullis-keycloak (wait for its `edge` image) → hub (wait for the edge image) → templates → core.
- Deploy only with the user's OK; the test server uses ACME staging (`ACME_STAGING=true`).
- Keycloak repo and supply chain (user-approved, user-ruled repo split):
  - The extension lives in `porelli/portcullis-keycloak` (public), next to portcullis-hub, with its Dockerfile (the pinned official Keycloak plus the jar), README.md, CLAUDE.md, `.github/automerge/` + `dependabot-automerge.yml` (the other repos' pattern), and a `build.yml` like the Hub's: test, build, publish `ghcr.io/porelli/portcullis-keycloak` (`edge` from main, semver tags for releases).
  - Every image is `tag@sha256` (the Gradle builder and the Keycloak base). Gradle dependency verification: `gradle/verification-metadata.xml` with sha256 for every artifact, `--dependency-verification strict`, and the wrapper's `distributionSha256Sum`. Dependabot covers `gradle`, `docker` and `github-actions`.
  - The repo keeps a copy of the shared test vectors, with a CI check that it matches the Hub's.
  - Core references the image like the Hub's: `${KEYCLOAK_IMAGE:-ghcr.io/porelli/portcullis-keycloak:edge}`; a release pins tag@digest.
  - Prefer mature libraries: Keycloak's own SPI and the `webauthn4j` Keycloak already ships, for attestation parsing and cert-path validation; no hand-rolled X.509 or CBOR code.
  - Creating the repo is the controller's step (`gh repo create porelli/portcullis-keycloak --public`). **Ask the user before the very first push.**
- Mockups (`.superpowers/brainstorm/98502-1794260205/content/`, not committed) were corrected on 2026-11-09: `signin-settings.html` "YubiKey + certificate" 4.4 / 5 and a "Device-bound passkey" row at 3.0; `signin-nested-rule.html` top score 4.4 (part 1: browser certificate off). Task 9's UI follows the corrected mockups.

Decisions (made here; the spec leaves them to the builder):
- **D1 Methods** (one table: Hub `internal/signin`, the contract, group-gate, mcp-gate, the extension):

  | id | label | strength | amr | where it comes from |
  |---|---|---|---|---|
  | `password` | Password | 1.0 | `pwd` | the person's LLDAP password, checked by Keycloak's LDAP bind |
  | `passkey_synced` | Passkey (phone / laptop, synced) | 2.5 | `spk` | Keycloak credential type `webauthn-passwordless` |
  | `browser_cert` | Browser certificate | 2.5 | `file` | **not available in part 1**: listed, always off, can't be switched on (409 "browser certificates aren't available yet") |
  | `passkey_device` | Device-bound passkey | 3.0 | `dpk` | credential type `portcullis-device-passkey` |
  | `security_key` | Security key passkey (YubiKey touch) | 3.5 | `hwk` | credential type `portcullis-security-key` |
  | `yubikey_cert` | YubiKey certificate | 4.0 | `mtls` | a `pki_int` client certificate (x509 authenticator) |

  `inv` is the amr of a setup-link session. It is not a method and satisfies no template. Methods start as: password off, browser_cert off, the other four on. `browser_cert` stays in the model because Standard and the `certificate` family name it; templates may reference it, and families skip it while it is off. Strengths are kept in tenths (10, 25, 25, 30, 35, 40) to avoid float error.
- **D2 Rules.** A rule is a group `{"op":"all"|"any","items":[…]}`. Each item is a method id, a family `family:passkey` (= passkey_synced, passkey_device, security_key), `family:yubikey` (= security_key, yubikey_cert) or `family:certificate` (= yubikey_cert, browser_cert), or a nested group. Groups nest up to 3 levels (the top group is level 1) and hold 1–8 items, with at most 16 leaves per rule. **Compiling** against the switched-on methods turns each family into `{"op":"any","items":[its switched-on members]}`. It fails (`ErrUnmeetable`) when a direct leaf is off or a family has no member on. Readers get compiled rules only, and validate compiled depth ≤ 4.
- **D3 "Needs".** An enabled template needs method m if m is a direct leaf, or the only switched-on member of a family it names. Switching m off is refused (409) while an enabled template needs it. The refusal lists the templates and what uses them.
- **D4 Score** (spec call 1): a method scores its strength; a family scores its weakest switched-on member; an "any of" group its weakest part; an "all of" group its strongest part + 0.4 per extra part, capped at 5. It is shown as `2.9 / 5` with a one-line reason.
- **D5 Keycloak 26.8.1 can't do this stock, so the extension repo ships one.** Stock Keycloak has three gaps: (a) a token doesn't say which passkey signed in; (b) registration stores only the attestation *format*, accepts `none`/self attestation for any AAGUID, and the realm truststore would reject FIDO attestation chains; (c) LoA levels are cumulative, so one specific method can't be asked for. The extension lives in `porelli/portcullis-keycloak` (Gradle, dependency verification) and is published as `ghcr.io/porelli/portcullis-keycloak` (FROM the pinned Keycloak, plus the jar). Its theme template `portcullis-needs-stronger.ftl` ships inside the jar (`theme-resources/templates/`), so core's mounted `portcullis` theme needs no copy. Its provider ids:
  - `webauthn-register-passwordless`: overrides the stock required action, so enroll, the account console and the Hub's "Require passkey" keep working. It uses a `NullCertPathTrustworthinessValidator` (the realm truststore would reject FIDO chains), then classifies the new credential (D14), stores the attestation in the extension's table and the credential under the type of its kind. It refuses a stronger kind from a weaker session while add-stronger is off.
  - `portcullis-security-key`, `portcullis-device-passkey`: WebAuthn credential providers with their own types and account-console metadata.
  - `portcullis-passkey-store`: a `JpaEntityProvider` with a Liquibase changelog for the table `PORTCULLIS_PASSKEY` (credential id PK, realm id, user id, AAGUID, attestation format, attestation statement as base64url CBOR, x5c chain, backup-eligible flag, current kind, MDS serial it was classified against, classified at). The stored statement, its AAGUID and the authData flags are kept for the credential's whole life and deleted with it (a `CredentialModel` removal listener plus a sweep for orphans).
  - `portcullis-reclassify`: a scheduled task (Keycloak `TimerProvider`, every 5 min) that runs when `signin-keycloak.json`'s `mds.serial` is newer than the last serial it applied (D14 rules).
  - `portcullis-passkey`: a passkey login that accepts all three types and puts the kind used in the auth note `portcullis.passkey.kind`.
  - `portcullis-condition-passkey-kind` (config `kind`).
  - `portcullis-method` (config `method` + `default.reference.value`): succeeds only while that method is on.
  - `portcullis-password-form` and `portcullis-x509` (config with the reference value): skipped (`attempted`) while their method is off, or when `pc_method` asks for another method. `portcullis-password-form` always refuses the bootstrap `admin` and `portcullis-hub` (a fixed list in code, compared after lowercasing; failure "Password sign-in isn't available for this account", counted by brute-force protection like a wrong password).
  - `auth-cookie`: overrides the stock provider. It returns `attempted`, with the user set, when `pc_method` names a method the session lacks.
  - `portcullis-template`: the client's template must be met, or it shows `portcullis-needs-stronger.ftl`.
- **D6 Flows** (core `realm-export.json`; LoA conditionals and `acr.loa.map` removed, map `{}`):
  - `portcullis-universal` = REQUIRED `portcullis-authenticate` {ALT `auth-cookie`, ALT `identity-provider-redirector`, ALT `portcullis-signin`} + REQUIRED `portcullis-template`.
  - `portcullis-signin` = ALT `portcullis-x509` (ref `mtls`), ALT sub-flow `portcullis-signin-passkey`, ALT `portcullis-password-form` (ref `pwd`).
  - `portcullis-signin-passkey` = REQUIRED `portcullis-passkey`, then one CONDITIONAL sub-flow per kind (`portcullis-condition-passkey-kind`), each holding REQUIRED `portcullis-method` (refs `hwk` / `dpk` / `spk`).
  - Every reference execution has `default.reference.maxAge` 36000, so the amr mapper keeps a method for 10 h.
  - The invite post-broker flow keeps its shape, with its amr config value renamed `inv`.
  - Realm `bruteForceProtected: true` (failureFactor 10, waitIncrementSeconds 60, maxFailureWaitSeconds 900, permanentLockout false). The passwordless WebAuthn policy is attestation `direct`, no attachment restriction, resident key and UV required.
- **D7 Step-up asks for one method.** group-gate's step-up URL is `…/oauth2/start?pc_method=<method id or "passkey">&rd=…`. oauth2-proxy's `loginURLParameters` drops `acr_values` and allows `pc_method` with exactly the six ids plus `passkey`; `kc_idp_hint` and `prompt` are unchanged. Keycloak keeps an unknown authorize parameter as the client note `client_request_param_pc_method`, which the extension reads. Task 15 pins this with a live test.
- **D8 Session methods.** The session's methods are the stock amr (Keycloak's completed executions within max age) mapped through D1 and kept only while the method is on. group-gate counts `yubikey_cert` only when the current request presents a non-revoked certificate whose CN is the session user (today's mTLS binding, generalised). mcp-gate never counts `yubikey_cert` or `browser_cert`, because MCP clients present no certificate (stricter).
- **D9 Native-OIDC: exact, never weaker.** `signin-keycloak.json` maps the client id of every Keycloak client of an enabled `native-oidc` instance (not `ai_client`s) to its template. `portcullis-template` at the end of the realm browser flow, and of the Hub's access-flow copies, enforces it at every login. A missing or invalid file denies every listed client. The Hub stops pushing `default.acr.values`: `UpdateClientACR`, `ClientSpec.ACR` and `AIDefaultACR` go. The TLS tier follows D18.
- **D10 Policy file v6** (contract §4) replaces `default` / `policies` with:
  - `methods`: the switched-on ids, sorted;
  - `templates`: id → compiled rule, enabled templates only;
  - `default`: a template id;
  - `hosts`: app hostname → template id, only for instances with their own pick;
  - `core`: core hostname → template id, for every gated core host;
  - `people`: lowercase user → ids of the switched-on methods they have set up (page text only, never an access decision).

  `groups`, `path_groups`, `public_paths`, `expiring` and `extra_domains` are unchanged. On a hostname collision the Hub publishes the stricter template, or, when neither implies the other, a synthetic template `collision.<n>` = all of both (never weaker).
- **D11 Core pages.** `state.SignIn.Core` maps a core subdomain key (`portal` = the apex, `hub`, `people`, `directory`, `enroll`, `metrics`, `traefik`) to a template id; `""` means the default. It starts with `hub` and `people` on `strong` and the rest on the default. `auth` and `mcp` are not gated by group-gate and take no template.
- **D12 Hub storage.** `state.yaml` gets `sign_in` (methods, templates, default, core, add_stronger, passwords) and `instances.<id>.sign_in_template` (`""` = default). Built-ins `basic` (any of `family:passkey`, `family:certificate`, `password`), `standard` (any of `family:passkey`, `family:certificate`; the default), `strong` (any of `security_key`, `yubikey_cert`) and `yubikey-and-certificate` (all of `yubikey_cert`, `security_key`; disabled) can be edited and disabled, never deleted. Template ids match `^[a-z][a-z0-9-]{0,31}$` and names are 1–48 visible runes. Changes are admin only, audited (`signin.method`, `signin.template`, `signin.template_enabled`, `signin.template_delete`, `signin.default`, `signin.core`, `signin.add_stronger`, `signin.reset_core`; the per-app pick is `settings.change` with scope `sign_in_template`; refusals `refused`). MCP twins have classes (Task 6).
- **D13 Passwords.** The sign-in password *is* the LLDAP password (one password). Keycloak checks it by LDAP bind (federation stays READ_ONLY). The Hub records `sign_in.passwords.<user> = {set_at, set_by}` whenever it sets one (People page, password onboarding), and only Hub-recorded passwords count in the counts, warnings and the lockout guard. Hub-set passwords must be 12–128 characters, not the username, and not in the embedded common-password list (SecLists 10k, MIT, `internal/signin/common-passwords.txt`). Setting a password is allowed while the method is off (LDAP-bind apps use it); password *onboarding* is refused (409) while it is off. Password sign-in is always refused for the bootstrap `admin` and for `portcullis-hub` (D5's `portcullis-password-form`); the Hub never counts a password for them in counts, warnings or the lockout guard, and its password view for them says "Password sign-in isn't available for this account".
- **D14 Passkey kinds** are decided by the extension at registration, from the attestation it keeps (D5's table). It uses `webauthn4j`'s parsed `AttestationObject` and its `TrustAnchorCertPathTrustworthinessValidator` over a trust-anchor repository built from the published roots of that one AAGUID.
  - **security_key** = a packed / tpm / android-key / fido-u2f attestation whose x5c chains to that AAGUID's roots, the leaf's AAGUID extension (1.3.6.1.4.1.45724.1.1.4) equal to the authData AAGUID when present, backup-eligible flag 0, and the published entry `{kind: security_key, status: certified}`.
  - **passkey_device** = the same checks with kind `passkey_device`.
  - **passkey_synced** = everything else (`none`, self attestation, an unknown AAGUID, BE = 1, a chain that doesn't verify).
  - **Reclassification** (`portcullis-reclassify`, when `mds.serial` grows): each stored row is classified again against the new list. A stronger result is applied (row and credential type updated, `PasskeyReclassified` logged). A weaker result is applied only when the AAGUID's published entry has `status: revoked` (D15), which sets synced. A missing entry, or a chain that no longer verifies for any other reason, never downgrades. Reclassification never upgrades past the add-stronger cap recorded at registration (D5's row keeps `capped_at`, the strongest kind allowed by the registering session; null = no cap).
  - With add-stronger off, a kind stronger than the session's strongest method is refused unless the session is a setup link (`inv`); a weaker or equal kind is stored with `capped_at` = the session's strongest passkey-equivalent kind.
  - Registration hints put the security key first for `lldap_admin` members (spec call 7).
- **D15 FIDO MDS.** The Hub fetches `https://mds3.fidoalliance.org/` (`HUB_FIDO_MDS_URL`) with `go-webauthn/webauthn/metadata`, which verifies the BLOB's JWS chain to the embedded FIDO root and checks revocation. It caches the BLOB at `<data>/signin/mds.jwt` (0600), refreshes daily and whenever `nextUpdate` has passed, and keeps the last good BLOB on failure. From it the Hub derives `authenticators`: AAGUID → `{kind, status, roots}`. `status: certified` for entries whose latest status is FIDO_CERTIFIED* with no compromise or revoked report; `status: revoked` (kind and roots still listed) for entries with REVOKED, USER_VERIFICATION_BYPASS, ATTESTATION_KEY_COMPROMISE, USER_KEY_REMOTE_COMPROMISE or USER_KEY_PHYSICAL_COMPROMISE; anything else is left out. The kind is `security_key` when `attachmentHint` ∋ `external` and `keyProtection` ∋ `secure_element`, and `passkey_device` when `attachmentHint` ∋ `internal` and `keyProtection` ∋ `hardware`|`tee`|`secure_element`. A BLOB more than 30 days past `nextUpdate` publishes no authenticators (new registrations fall to synced, stored ones keep their kind) and shows a Settings warning. `mds.serial` is the BLOB's `no`. Extra entries for CI's virtual authenticator come only with `HUB_DEV=1` (`HUB_SIGNIN_EXTRA_AUTHENTICATORS`).
- **D16 Inventory.** The Hub learns each person's methods from:
  - Keycloak `GET /users/{id}/credentials` (credential type → passkey kind; the stock `webauthn` type counts as synced);
  - the Hub's password records;
  - enroll's new `GET :8444/internal/certificates` (bearer = the invite secret) for valid, unrevoked YubiKey certificates. A 404 or an error leaves certificates unknown, and unknown never counts.

  The inventory is refreshed by the directory sync and on demand (at most once per 30 s). Keycloak unreachable means the lockout guard answers 503.
- **D17 Lockout guard** (spec call 7). A save that changes methods, templates, the default or the `hub` core pick is refused (409, naming why) when it would take the count of unexpired `lldap_admin` members who can meet the Hub's compiled template from > 0 to 0. When the count is already 0 the save goes through with the warning "No administrator can meet the Hub's template". The CLI recovery is `./portcullis signin reset-core`. It stops the Hub and runs `hub signin reset-core` against `/data`, which puts `hub` and `people` on `standard`, restores and enables the built-in Standard rule, switches its methods back on and audits `signin.reset_core` (actor `cli`). Then it starts the Hub.
- **D18 TLS follows the switches through labels.** `MTLS_ENABLED` goes, and the Hub gets no write access to `traefik/dynamic`. Core's tracked, static `traefik/dynamic/tls.yml` defines three options, keeping today's names so templates' literal labels stay valid:
  - `protected@file`: `RequireAndVerifyClientCert` (`/certs/ca-chain.crt`);
  - `authaware@file`: the client-cert-optional option, `VerifyClientCertIfGiven`;
  - `public@file`: the no-client-cert option, no `clientAuth`.

  `config apply` no longer writes the file. For each app, the Hub's override picks the option from the instance's compiled template, where "cert" means a certificate method that is switched on (`policy.Tier`):
  - every alternative has a cert → `protected@file`;
  - some alternative has a cert → `authaware@file`;
  - none has one, or the app has no Portcullis sign-in → `public@file`.

  Public exceptions turn protected into authaware (today's `HostTier`). All routers of one host share the option. Switching a certificate method on or off, or a template change that moves an app's option, re-renders the override and restarts the affected enabled instances (`SignInChange.Restarts`). Core routers (Keycloak `auth`, Hub, people, portal, the consoles) stay on `authaware@file`: they always offer an optional certificate request.
- **D19 mcp-gate and fresh auth.** Gate file v2: each resource's `min_loa` becomes `rule` (compiled; a companion takes its instance's template, the people resource the `people` core template, admin and aggregate the `hub` core template), `acr_loa` goes, and `methods` is added. AI support for an instance is refused (409) when every alternative of its rule needs a certificate (`signin.NeedsCertificate`; this replaces "LoA 3"). Fresh auth (file-share password creation, confirmations) accepts amr `spk`, `dpk`, `hwk` (any passkey kind) or `mtls`, each only while its method is on; never `pwd`, `file` or `inv`. The popup drops `acr_values` and keeps `prompt=login max_age=0`.
- **D20 Hub-written Keycloak config.** `<data>/signin-keycloak.json` (0644, atomic, mounted into Keycloak as `hub_data:/hub-data:ro`) holds version 1, `methods`, `add_stronger`, `templates` (compiled), `clients` (client id → `{template, name}`), `authenticators` (D15: AAGUID → `{kind, status, roots}`) and `mds` (`{serial, next_update}`). The extension caches it by mtime and decodes it strictly. Missing, unreadable or invalid means every method is off: nobody signs in until the Hub writes a good one (fail closed; recovery is `signin reset-core` plus a Hub start).

## Review Focus

1. **A switched-off method or template still accepted** (group-gate, Keycloak, a native app, AI, fresh auth). A person whose SSO session holds `pwd` keeps opening an app after password is switched off. Expected: the next request is judged without it. Pinned by `test_switched_off_method_amr_ignored` (Task 15), `MethodAuthenticatorTest.refusesSwitchedOffMethod` (Task 12), `TestFreshAuthRefusesSwitchedOffSecurityKey` (Task 7) and `TestCompileRefusesSwitchedOffLeaf` (Task 2).
2. **A synced or device-bound passkey passing a security-key rule**, e.g. a software authenticator claiming a YubiKey AAGUID with `none` attestation, or a backup-eligible key. Expected: the credential is synced. Pinned by `PasskeyClassifierTest` (Task 11) and `TestSecurityKeyRuleRefusesDeviceBound` (Task 2).
3. **A password satisfying a template that doesn't list it**, through a family, a collision merge or a setup-link session. Expected: no `passkey` / `yubikey` / `certificate` family ever contains password, and `inv` meets nothing. Pinned by `TestFamiliesNeverContainPassword` and the shared vectors (Task 2), and `test_inv_session_meets_nothing` (Task 15).
4. **An admin locking everyone out of the Hub** by switching off the method all admins use, editing Strong, or moving the Hub to a template no admin meets. Expected: 409 naming who. Recovery is the CLI. Pinned by `TestSignInLockoutGuard` (Task 5) and `TestSignInResetCore` (Task 5).
5. **A native-OIDC app enforcing less than its template**: its client missing from `signin-keycloak.json`, or a stale file. Expected: every native-oidc client is listed with its exact template, and an unlisted, missing or invalid file denies. Pinned by `TestSignInKeycloakFileListsEveryNativeClient` (Task 4) and `TemplateAuthenticatorTest.deniesWhenConfigInvalid` (Task 12).

---

### Task 1: Contract and docs (docs repo)

**Files:**
- Modify: `docs/guides/integration-contracts.md`:
  - §4: policy file v6 per D10, with full example JSON and the validation rules;
  - §4.2 / §15.4: gate file v2 per D19;
  - §5 / §5.1: step-up URL with `pc_method`, the needs-stronger page, fresh-auth popup parameters;
  - §8: new "Sign-in methods" subsection with D1 table, D2 rule grammar, D5 provider ids, D6 flows, D7, D9, D14, D20 `signin-keycloak.json` schema, the `inv` amr, the `mtls` invariant restated with `file` = browser_cert;
  - §8 AI clients: no `default.acr.values`;
  - §15.2: rule check replaces `acr` / `min_loa`;
  - §9.4: enroll `GET /internal/certificates`.
  - §1 (versions and releases) and the repo list (the contract's introduction and the docs' repo table): the new repo `porelli/portcullis-keycloak`, its image `ghcr.io/porelli/portcullis-keycloak` (`edge` / semver tags; core's `${KEYCLOAK_IMAGE:-…:edge}`, a release pins tag@digest), the merge order docs → keycloak → hub → templates → core.
  - §8: the Keycloak image's config file `signin-keycloak.json` (path `<hub_data>/signin-keycloak.json`, written by the Hub 0644 atomically, mounted into Keycloak as `hub_data:/hub-data:ro`, read at `/hub-data/signin-keycloak.json`).
- Modify: `docs/operations/auth-policies.md` (becomes "Sign-in methods and templates": methods, templates, score, default / per app / core pages, warnings, add-stronger, lockout and `signin reset-core`).
- Modify: `docs/index.md` ("Repositories": five repositories, a portcullis-keycloak row), the contract's opening line ("split across five repositories"), `docs/operations/upgrading.md` (the Keycloak image follows the Hub's release pattern), `docs/operations/hub.md` (Settings → Sign-in; instance Settings drop-down), `docs/operations/cli.md` (`signin reset-core`, `config apply` without MTLS_ENABLED), `docs/setup/certificates.md` (client-certificate requests follow the switches; MTLS_ENABLED removed).

**Interfaces:**
- Produces: the exact JSON shapes every later task implements. Policy v6:
  ```json
  {"version": 6, "methods": ["passkey_device","passkey_synced","security_key","yubikey_cert"],
   "templates": {"standard": {"op":"any","items":[{"op":"any","items":["passkey_synced","passkey_device","security_key"]},{"op":"any","items":["yubikey_cert"]}]}},
   "default": "standard", "hosts": {"git.example.com": "strong"},
   "core": {"hub.example.com": "strong", "people.example.com": "strong", "example.com": "standard"},
   "people": {"alice": ["passkey_synced","security_key"]},
   "extra_domains": [], "groups": {}, "path_groups": {}, "public_paths": {}, "expiring": []}
  ```
  Gate file v2 resource: `"rule": {…compiled…}` instead of `"min_loa"`, plus top-level `"methods": […]`, with no `acr_loa`. Also the `signin-keycloak.json` schema of D20.

- [ ] **Step 1:** In the worktree `/Volumes/workspace/portcullis/wt-docs-signin` (branch `signin`), write the sections above. Every value is copied from D1–D20, and the score example is `all[any[all[password, security_key], all[family:yubikey, family:passkey]], family:certificate]` = 4.4 / 5 with browser_cert off. Say in the operator page and in §9.4:
  - after a setup link the person touches their new passkey once more to open apps, because a setup-link session (`inv`) meets no template;
  - fresh auth accepts any passkey kind or a YubiKey certificate, never a password, a browser certificate or a setup link;
  - password sign-in is never available for `admin` and `portcullis-hub`;
  - passkey kinds are reclassified upward when a newer FIDO list verifies the stored attestation, and downward only on a revoked or compromised MDS status;
  - client-certificate requests follow the switches per app (D18), while core pages always offer an optional one.
- [ ] **Step 2:** Build the site. Run `zensical build --strict` in the worktree. Expected: exit 0, no warnings.
- [ ] **Step 3:** Commit and push: `git add -A docs && git commit -m "contract: sign-in methods, templates, policy v6, gate file v2 (part 1)" && git push -u origin signin`.

---

### Task 2: `internal/signin` — methods, rules, compile, evaluate, score, sentence (hub)

**Files:**
- Create: `internal/signin/methods.go`, `rule.go`, `score.go`, `sentence.go`, `builtin.go`, `password.go`, `common-passwords.txt`
- Create: `internal/signin/testdata/vectors.json` (shared with core: group-gate, mcp-gate and the extension copy it byte for byte)
- Test: `internal/signin/signin_test.go`, `internal/signin/vectors_test.go`

**Interfaces:**
- Produces:
  ```go
  type Method string // "password","passkey_synced","browser_cert","passkey_device","security_key","yubikey_cert"
  var Methods []Method // canonical order, as listed
  type Info struct{ ID Method; Label, Short, Phrase, AMR string; Tenths int; Available bool }
  func InfoOf(m Method) (Info, bool)
  func MethodForAMR(amr string) (Method, bool) // "inv" and unknown → false
  type Node struct{ Op string; Items []Node; Leaf string } // JSON: a leaf is a string, a group {"op","items"}
  func (n Node) MarshalJSON() ([]byte, error); func (n *Node) UnmarshalJSON(b []byte) error // strict
  func Validate(n Node) error                                   // D2 limits; top must be a group
  var ErrUnmeetable error
  func Compile(n Node, on map[Method]bool) (Node, error)        // D2
  func Satisfied(compiled Node, have map[Method]bool) bool
  func Alternatives(compiled Node) ([][]Method, error)          // minimal DNF, each sorted canonically, ≤ 256 (else error)
  func Implies(a, b Node) bool                                  // compiled; every alternative of a satisfies b
  func NeedsCertificate(compiled Node) bool                     // every alternative has yubikey_cert or browser_cert
  func Needs(n Node, on map[Method]bool) []Method               // D3
  type Score struct{ Tenths int; Reason string }
  func ScoreOf(n Node, on map[Method]bool) Score; func (s Score) String() string // "2.9 / 5"
  func Sentence(n Node) string
  type Template struct{ ID, Name string; Rule Node; Enabled, BuiltIn bool }
  func Builtins() []Template // D12
  func CheckPassword(user, pw string) error // D13
  ```

Algorithms not fixed by the signatures:
```
score(leaf m)       = tenths(m)
score(family f)     = min tenths over f's switched-on members
score(any items)    = min score(item)
score(all items)    = min(50, max score(item) + 4*(len-1))
Reason (top group):  any → "its weakest way in: <Sentence(weakest item)>"
                     all → "its strongest part (<Sentence(strongest)>) + 0.4 for each of <n-1> more" [+ ", capped at 5"]
Sentence: leaf → Phrase; all → items joined " and "; any → joined ", or " when an item is a multi-item
          group, else " or "; a multi-item any inside an all is wrapped in "( … )".
Phrases: "a password","a synced passkey","a browser certificate","a device-bound passkey","a YubiKey touch",
         "a YubiKey certificate"; family:passkey "a passkey", family:yubikey "a YubiKey", family:certificate "a certificate".
Satisfied: leaf → have[m]; any → some item; all → every item.
```

- [ ] **Step 1: Write the failing tests**
  ```go
  func TestScoreSpecExamples(t *testing.T) // on = all but password and browser_cert, except where a case switches them on
  //  basic (password on) "1.0 / 5"; standard "2.5 / 5"; strong "3.5 / 5"; yubikey-and-certificate "4.4 / 5"
  //  family example any[all[password, family:passkey], security_key] (password on) == "2.9 / 5",
  //    Reason == "its weakest way in: a password and a passkey"
  //  nested all[any[all[password,security_key], all[family:yubikey,family:passkey]], family:certificate]
  //    == "4.4 / 5" (browser_cert off), "4.3 / 5" with browser_cert on; all of 9 leaves capped: Tenths == 50
  func TestSentenceNested(t *testing.T) // the nested rule above ==
  //  "(a password and a YubiKey touch, or a YubiKey and a passkey) and a certificate"
  func TestValidateLimits(t *testing.T)        // depth 4 error; 9 items error; 17 leaves error; unknown leaf error; leaf top error
  func TestCompileRefusesSwitchedOffLeaf(t *testing.T) // all[password] with password off → errors.Is(err, ErrUnmeetable)
  func TestCompileFamilySkipsOffMembers(t *testing.T)  // family:certificate, browser_cert off → any[yubikey_cert]
  func TestFamiliesNeverContainPassword(t *testing.T)  // for every family and every on-set: password ∉ compiled leaves
  func TestSecurityKeyRuleRefusesDeviceBound(t *testing.T) // Satisfied(strong, {passkey_device,passkey_synced}) == false
  func TestImpliesAndNeeds(t *testing.T) // Implies(strong, standard) true; Implies(standard, strong) false;
  //  Needs(standard, browser_cert off) == []; Needs(strong) == [security_key, yubikey_cert]
  func TestNeedsCertificate(t *testing.T) // all[yubikey_cert,security_key] true; strong false
  func TestCheckPassword(t *testing.T)    // "short" error; username error; "password1234" (listed) error; 12 random OK
  func TestSharedVectors(t *testing.T)    // every case in testdata/vectors.json: Compile, Satisfied, Alternatives match
  ```
  `vectors.json` = `{"version":1,"cases":[{"name","rule","on","have","satisfied","alternatives"}…]}`, with at least 25 cases, including every Review Focus line 1–3 input and `"have": ["inv"]`, which `MethodForAMR` drops.
- [ ] **Step 2: Run them to see them fail.** Run `go test ./internal/signin/...`. Expected: FAIL (package doesn't exist).
- [ ] **Step 3: Implement** the files with the interfaces above. `common-passwords.txt` is SecLists' 10k most common passwords (MIT), embedded with `//go:embed`.
- [ ] **Step 4: Run them to see them pass.** Run `go test -race ./internal/signin/...`. Expected: `ok`.
- [ ] **Step 5: Commit and push.** `git add internal/signin && git commit -m "signin: methods, rules, compile, score, sentence" && git push -u origin signin`.

---

### Task 3: State, built-ins and the sign-in service (hub)

**Files:**
- Modify: `internal/state/state.go`: add `SignIn` and `Instance.SignInTemplate`; remove `AuthPolicies`, `DefaultPolicy`, `ResolvePolicy`, `Default`, `SetDefault`, `Instance.Policy`.
- Create: `internal/hub/signin.go`, `internal/hub/signin_audit.go`
- Test: `internal/state/state_test.go`, `internal/hub/signin_test.go`

**Interfaces:**
- Consumes: Task 2.
- Produces:
  ```go
  // state
  type SignIn struct {
    Methods     map[string]bool           `yaml:"methods"`
    Templates   map[string]SignInTemplate `yaml:"templates"`
    Default     string                    `yaml:"default"`
    Core        map[string]string         `yaml:"core"`
    AddStronger bool                      `yaml:"add_stronger"`
    Passwords   map[string]PasswordRecord `yaml:"passwords"`
  }
  type SignInTemplate struct{ Name string; Rule signin.Node; Enabled, BuiltIn bool }
  type PasswordRecord struct{ SetAt time.Time; SetBy string }
  func (s *AppState) EnsureSignIn() // fills D1 / D11 / D12 defaults on a fresh state
  // hub
  func (h *Hub) SignInView(ctx context.Context) (*SignInView, error)
  func (h *Hub) SetMethod(ctx context.Context, m signin.Method, on bool, actor directory.Actor) (*SignInChange, error)
  func (h *Hub) SaveTemplate(ctx context.Context, id string, in TemplateInput, create bool, actor directory.Actor) (*SignInChange, error)
  func (h *Hub) SetTemplateEnabled(ctx context.Context, id string, on bool, actor directory.Actor) (*SignInChange, error)
  func (h *Hub) DeleteTemplate(ctx context.Context, id string, actor directory.Actor) error
  func (h *Hub) SetDefaultTemplate(ctx context.Context, id string, actor directory.Actor) (*SignInChange, error)
  func (h *Hub) SetCoreTemplate(ctx context.Context, key, id string, actor directory.Actor) (*SignInChange, error) // id "" = default
  func (h *Hub) SetAddStronger(on bool, actor directory.Actor) error
  func (h *Hub) PreviewTemplate(ctx context.Context, id string, in TemplateInput) (*TemplatePreview, error) // nothing stored
  func (h *Hub) compiledLocked(id string) (signin.Node, bool)    // enabled + compiled, for every writer
  func (h *Hub) templateForInstanceLocked(t *templates.Template) string // the pick, else Default
  type TemplateInput struct{ Name string; Rule signin.Node }
  type SignInChange struct{ View *SignInView; Restarts []string; Warnings []string }
  type TemplatePreview struct{ Sentence string; Score signin.Score; Affected []AffectedApp; Problem string }
  type AffectedApp struct{ Instance, Name string; Blocked []Blocked } // Blocked from Task 5
  type UseRef struct{ Kind string /* default|core|instance */; ID, Name string }
  ```
  `SignInView` holds methods `[{id,label,tenths,on,available,people}]` (`people` from Task 5, -1 while unknown), templates `[{id,name,rule,sentence,score,enabled,built_in,used_by []UseRef}]`, `default`, `core` (key → id), `add_stronger` and `mds` (Task 8).

Refusals:
- `SetMethod`: 404 unknown method, 409 `browser_cert` ("browser certificates aren't available yet"), 409 needed (D3; lists templates and their `used_by`).
- `SaveTemplate`: 400 `Validate` / name / id rule, 409 duplicate id on create, 409 `ErrUnmeetable` while enabled.
- `SetTemplateEnabled` off: 409 when `used_by` is non-empty; on: 409 when unmeetable.
- `DeleteTemplate`: 409 for a built-in or a template in use, 404 unknown.
- `SetDefaultTemplate` / `SetCoreTemplate`: 404 unknown, 409 disabled; `SetCoreTemplate` 400 for an unknown key.
- Every save then runs the lockout guard (Task 5).

Effects: one `saveStateLocked`, then `WritePolicy` (Task 4). Instances whose TLS tier changed restart in the background (as `SetDefaultPolicyAs` does today), listed in `Restarts`. Every change is audited after `mu` (D12).

- [ ] **Step 1: Write the failing tests**
  ```go
  func TestEnsureSignInDefaults(t *testing.T) // methods per D1; 4 built-ins; Default "standard"; Core hub/people "strong";
  //  yubikey-and-certificate disabled
  func TestSetMethodRefusals(t *testing.T) // browser_cert on → 409; security_key off while strong enabled → 409 whose
  //  text names "Strong" and "Hub"; password on → OK, audit signin.method "password" "off -> on"
  func TestTemplateEnableDisableInUse(t *testing.T) // disable standard (default) → 409; disable unused basic → OK;
  //  enable a template needing password while password off → 409
  func TestDeleteTemplate(t *testing.T) // built-in → 409; custom unused → OK, audited; custom picked by an instance → 409
  func TestSaveTemplateValidates(t *testing.T) // depth 4 → 400; id "Bad" → 400; create existing → 409
  func TestPreviewTemplateStoresNothing(t *testing.T) // state.yaml bytes unchanged; Sentence/Score as Task 2
  func TestSignInChangeRewritesPolicy(t *testing.T) // SetDefaultTemplate("strong") → policy file "default" == "strong"
  ```
- [ ] **Step 2: Run them to see them fail.** Run `go test ./internal/hub/ -run 'SignIn|Template|SetMethod'`. Expected: FAIL (undefined).
- [ ] **Step 3: Implement** the state types, `EnsureSignIn` (called by `Init`) and the service, with the refusals and effects above. Delete the `AuthPolicy` state fields and every caller (the compiler lists them; Task 4 replaces the policy package).
- [ ] **Step 4: Run them to see them pass.** Same command. Expected: `ok`.
- [ ] **Step 5: Commit and push.** `git commit -am "hub: sign-in state, built-in templates, method and template service" && git push`.

---

### Task 4: Policy file v6, TLS tier, native clients and `signin-keycloak.json` (hub)

**Files:**
- Rewrite: `internal/policy/policy.go`, `capability.go`, `file.go` (remove `AuthPolicy`, `Factors`, `LoA`, `ACR`, `Normalize`, `SafetyScore`, `Stricter`)
- Create: `internal/hub/signin_publish.go` (`signin-keycloak.json` writer)
- Modify: `internal/hub/access.go`, `override.go`, `settings.go` (`SettingsUpdate.SignInTemplate *string` replaces `Policy` / `Inherit`; preview, effects, audit `settings.change` scope `sign_in_template`), `lifecycle.go` / `keycloak/keycloak.go` (drop `ACR`, `UpdateClientACR`), `keycloak/ai.go` (drop `AIDefaultACR`), `hub.go` (`writePolicy`), `backup.go` / `restore.go` (archive `sign_in_template`), `httpapi/settings.go` (`sign_in_template` in the body)
- Test: `internal/policy/file_test.go` (rewritten), `internal/hub/signin_publish_test.go`, `internal/hub/settings_test.go`, `internal/hub/override_test.go` (golden overrides updated: `testdata/golden/*.override.yml`)

**Interfaces:**
- Consumes: Task 3's `compiledLocked`, `templateForInstanceLocked`, Task 5's `peopleMethodsLocked() map[string][]signin.Method` (Task 4 ships a stub returning nil; Task 5 fills it).
- Produces:
  ```go
  // policy
  const FileVersion = 6
  type Capability struct{ Templates bool; Enforcement string } // request|login|tls|none
  func CapabilityFor(method string) Capability                // forward-auth, header-auth: request; native-oidc: login; mtls: tls; else none
  func Tier(rule *signin.Node, on map[signin.Method]bool, publicExceptions bool) string // D18; nil rule = "public@file"
  type App struct{ /* existing fields */ Template string }     // "" = default
  type Document struct{ Version int; Methods []string; Templates map[string]signin.Node; Default string;
    Hosts, Core map[string]string; People map[string][]string; ExtraDomains []string; Groups map[string]string;
    PathGroups map[string][]PathGroup; PublicPaths map[string]PublicEntry; Expiring []Expiring }
  type BuildInput struct{ Apps []App; Default string; Core map[string]string; Templates map[string]signin.Node;
    Methods []signin.Method; People map[string][]signin.Method; MainDomain string; ExtraDomains []string }
  func Build(in BuildInput) Document // D10, collisions per D10
  // hub
  type KeycloakSignIn struct{ Version int; Methods []string; AddStronger bool; Templates map[string]signin.Node;
    Clients map[string]KeycloakClientTemplate; Authenticators map[string]AuthenticatorTrust } // JSON per D20
  type KeycloakClientTemplate struct{ Template, Name string }
  type AuthenticatorTrust struct{ Kind, Status string; Roots [][]byte } // DER, JSON base64; Status certified|revoked
  func (h *Hub) keycloakSignInLocked() KeycloakSignIn
  func (h *Hub) tierChangesLocked(before, after state.SignIn) []string // enabled instances whose Tier moves (restart)
  ```
  `writePolicy` writes, in order: `signin-keycloak.json`, the policy file, then the existing attribute, portal and gate files. The override's per-router `tls.options` label comes from `policy.Tier` (existing `HostTier` path).

- [ ] **Step 1: Write the failing tests**
  ```go
  func TestBuildV6(t *testing.T) // Version 6; inheriting app absent from Hosts; picked app Hosts[host]=="strong";
  //  core keys are full hostnames for portal/hub/people/directory/enroll/metrics/traefik; no "auth"/"mcp" key
  func TestBuildCollisionNeverWeaker(t *testing.T) // two apps on one host with basic + strong → Hosts[host]=="strong";
  //  incomparable templates → synthetic "collision.1" == all of both
  func TestTier(t *testing.T) // all[yubikey_cert,security_key] "protected@file"; strong "authaware@file";
  //  protected + publicExceptions "authaware@file"; nil "public@file"; standard with yubikey_cert and
  //  browser_cert off "public@file" (no certificate method switched on)
  func TestSignInKeycloakFileListsEveryNativeClient(t *testing.T) // every keycloak_clients entry of every enabled
  //  native-oidc instance (not ai_client) in Clients with the instance's exact template; a disabled instance absent;
  //  a forward-auth instance absent
  func TestTierFollowsCertificateSwitch(t *testing.T) // instance on standard: SetMethod(yubikey_cert, off) → its
  //  override's routers carry tls.options public@file and Restarts lists it; on again → authaware@file, restart;
  //  an instance on basic with password off and no cert method on → public@file; the Hub writes nothing under
  //  /project/traefik
  func TestSaveSettingsSignInTemplate(t *testing.T) // "" inherits; "basic" disabled → 409; tier change → restart effect;
  //  audit settings.change "scope=sign_in_template: standard -> strong"; app with method public → 400
  func TestNoACRPushed(t *testing.T) // RegisterClient spec carries no default.acr.values
  ```
- [ ] **Step 2: Run them to see them fail.** Run `go test ./internal/policy/ ./internal/hub/ -run 'BuildV6|Collision|Tier|SignInKeycloak|SignInTemplate|NoACR'`. Expected: FAIL.
- [ ] **Step 3: Implement.** The policy rewrite, publishing and settings wiring. Every former `policy.*` caller listed by `grep -rn 'policy\.\(AuthPolicy\|LoA\|ACR\|Normalize\|Resolve\|SafetyScore\|Stricter\)'` moves to templates; `describePolicy` / `policyNotes` become `signin.Sentence` + score lines.
- [ ] **Step 4: Run them to see them pass.** Run the same tests, then the full Go checks. Expected: `ok`.
- [ ] **Step 5: Commit and push.** `git commit -am "hub: policy file v6, template-driven TLS tier, signin-keycloak.json, no acr push" && git push`.

---

### Task 5: Inventory, warnings, lockout guard, password records and `hub signin reset-core` (hub)

**Files:**
- Create: `internal/hub/signin_people.go`, `internal/hub/signin_guard.go`, `internal/signinreset/reset.go`
- Modify: `internal/keycloak/keycloak.go` (`passkeyTypes` += `portcullis-security-key`, `portcullis-device-passkey`; new `SignInCredentials`), `internal/invite/invite.go` (`Certificates`), `internal/directory/service.go` (`SetPassword` and password onboarding: `signin.CheckPassword`, record via hook, onboarding 409 while password is off), `internal/hub/directory.go` (refresh after sync), `cmd/hub/main.go` (dispatch `signin reset-core` before env, like `folderfix`)
- Test: `internal/hub/signin_people_test.go`, `internal/hub/signin_guard_test.go`, `internal/signinreset/reset_test.go`, `internal/keycloak/users_test.go`, `internal/directory/service_test.go`

**Interfaces:**
- Consumes: Tasks 2–4.
- Produces:
  ```go
  // keycloak
  type PasskeyCredential struct{ ID, Type, Label string; Created time.Time }
  func (c *Client) SignInCredentials(ctx context.Context) (map[string][]PasskeyCredential, error) // username → passkeys
  // invite
  type CertRecord struct{ User, Serial string; NotAfter time.Time; Revoked bool }
  var ErrNoCertAPI error
  func (c *Client) Certificates(ctx context.Context) ([]CertRecord, error)
  // hub
  type PersonMethods struct{ User string; Methods []signin.Method; CertsKnown bool }
  type Inventory struct{ At time.Time; People map[string]PersonMethods }
  func (h *Hub) SignInInventory(ctx context.Context, fresh bool) (*Inventory, error) // fresh: ≤ 1 refresh / 30 s
  type Blocked struct{ User, Why string } // Why: "no method yet" | "<Short> + <Short> only"
  func blockedFor(inv *Inventory, users []string, compiled signin.Node, on map[signin.Method]bool) []Blocked
  func (h *Hub) InstanceSignIn(ctx context.Context, id string) (*InstanceSignInView, error) // template, inherits, choices, blocked
  func (h *Hub) peopleMethodsLocked() map[string][]signin.Method
  func (h *Hub) lockoutCheck(ctx context.Context, before, after state.SignIn) (warning string, err error) // D17
  func (h *Hub) RecordPassword(user, actor string) error // directory hook after a successful SetPassword
  // signinreset
  func Main(args []string, dataDir string, out io.Writer) int // "reset-core": D17; exit 0, prints what changed
  ```
  Blocked lists cover members (unexpired) of the instance's access and admin groups, `lldap_admin` for the `hub` and `directory` / `traefik` / `metrics` / `enroll` core picks, and every user for `people` and `portal`. `TemplatePreview.Affected` and the `people` counts in `SignInView` come from here.

- [ ] **Step 1: Write the failing tests**
  ```go
  func TestSignInCredentialsTypes(t *testing.T) // kctest server: webauthn-passwordless→passkey_synced,
  //  portcullis-device-passkey→passkey_device, portcullis-security-key→security_key, webauthn→passkey_synced
  func TestRemovePasskeysRemovesEveryKind(t *testing.T) // all three types deleted by remove-passkeys
  func TestBlockedWhy(t *testing.T) // strong vs bob{password} "password only"; dave{} "no method yet";
  //  carol{passkey_synced,password} "password + synced passkey only"
  func TestCertsUnknownNeverCount(t *testing.T) // Certificates → ErrNoCertAPI: a ykc-only admin is Blocked
  func TestSignInLockoutGuard(t *testing.T) // 1 admin with only security_key: SetMethod(security_key,off) 409;
  //  SaveTemplate("strong", all[yubikey_cert]) 409; SetCoreTemplate("hub","yubikey-and-certificate") 409;
  //  each 409 text names the admin; with 0 admins able before: allowed + warning; Keycloak down: 503
  func TestPasswordRules(t *testing.T) // SetPassword "password1234" 400; good one → state.sign_in.passwords[user].SetBy ==
  //  actor; never in audit detail; onboarding=password while password off → 409; a recorded password for
  //  "admin" or "portcullis-hub" never appears in PersonMethods (counts, warnings, lockout guard)
  func TestSignInResetCore(t *testing.T) // a state with hub on a custom template and security_key off:
  //  Main(["reset-core"]) == 0; Core hub/people "standard"; standard rule == built-in; passkey kinds +
  //  yubikey_cert on; audit line action signin.reset_core actor cli
  ```
- [ ] **Step 2: Run them to see them fail.** Run `go test ./internal/hub/ ./internal/keycloak/ ./internal/signinreset/ ./internal/directory/ -run 'SignIn|Passkeys|Blocked|Certs|Lockout|Password|ResetCore'`. Expected: FAIL.
- [ ] **Step 3: Implement.** Wire `lockoutCheck` into every Task 3 save and into `SaveSettings` for no instance, since the Hub's own pick is the `hub` core key.
- [ ] **Step 4: Run them to see them pass.** Run the same tests, then the full Go checks. Expected: `ok`.
- [ ] **Step 5: Commit and push.** `git commit -am "hub: sign-in inventory, warnings, admin lockout guard, password records, reset-core" && git push`.

---

### Task 6: HTTP API and MCP twins (hub)

**Files:**
- Create: `internal/httpapi/signin.go`, `internal/httpapi/mcptools_signin.go`
- Modify: `internal/httpapi/server.go` (routes; remove `default_auth_policy` from `/api/settings` and `setDefaultPolicy`), `mcptools_admin.go` / `mcptools_admin2.go` (remove `set_policy`, `set_default_policy`, `preview_default_policy`), `mcp_parity_test.go` (tables)
- Test: `internal/httpapi/signin_test.go`, `internal/httpapi/mcptools_signin_test.go`, `mcp_parity_test.go`

**Interfaces:**
- Consumes: Tasks 3–5.
- Produces routes (admin only, Hub listener; JSON):
  - `GET /api/signin`
  - `PUT /api/signin/methods/{method}` `{on}`
  - `POST /api/signin/templates` `{id,name,rule}`
  - `PUT /api/signin/templates/{id}` `{name,rule}`
  - `PUT /api/signin/templates/{id}/enabled` `{on}`
  - `DELETE /api/signin/templates/{id}`
  - `POST /api/signin/templates/preview` `{id?,name,rule}`
  - `PUT /api/signin/default` `{template}`
  - `PUT /api/signin/core/{key}` `{template}`
  - `PUT /api/signin/add-stronger` `{on}`
  - `GET /api/instances/{id}/signin`

  Errors map to the statuses Task 3 / Task 5 define.

  MCP tools (twins of the routes) and classes:

  | tool | class |
  |---|---|
  | `get_sign_in`, `preview_sign_in_template` | R |
  | `set_sign_in_method` | D when on, W when off |
  | `save_sign_in_template` | D unless creating, or the new compiled rule `Implies` the old |
  | `set_sign_in_template_enabled`, `delete_sign_in_template` | W |
  | `set_default_template`, `set_core_template`, `set_sign_in_template` (instance) | D unless the new template `Implies` the current one |
  | `set_add_stronger` | D when on, W when off |

- [ ] **Step 1: Write the failing tests**
  ```go
  func TestSignInRoutesAdminOnly(t *testing.T) // non-admin 403 on every route; people listener 404
  func TestSignInRoutesStatuses(t *testing.T)   // PUT methods/browser_cert {on:true} 409; unknown 404; preview 200 no write
  func TestSignInToolClasses(t *testing.T)      // set_default_template strong→standard needs confirmation (D);
  //  standard→strong doesn't; set_sign_in_method on → D; off → W
  func TestMCPParity(t *testing.T)              // existing test, tables updated: every route has its twin
  ```
- [ ] **Step 2: Run them to see them fail.** Run `go test ./internal/httpapi/ -run 'SignIn|MCPParity'`. Expected: FAIL.
- [ ] **Step 3: Implement** the handlers and tools. Classes go through the existing `ClassFor` per-call mechanism (`perCall`), `accessWidening` entries as in the table.
- [ ] **Step 4: Run them to see them pass.** Run the same tests, then `go vet -tags harness ./internal/httpapi/...`. Expected: `ok`, no vet output.
- [ ] **Step 5: Commit and push.** `git commit -am "httpapi: sign-in routes and MCP tools with classes" && git push`.

---

### Task 7: AI gate file v2 and fresh auth (hub)

**Files:**
- Modify: `internal/aigate/files.go`, `validate.go`, `testdata/mcp-gate.json` (v2: `rule`, `methods`, no `acr_loa` / `min_loa`)
- Modify: `internal/hub/ai_gatefile.go`, `ai_instance.go` (`aiRefusalLocked`: `NeedsCertificate`), `ai_revoke.go` (`aiOffForLoA3` → `aiOffForCertOnly`), `settings.go` / `signin.go` (switch companions off before a change that makes an instance's rule certificate-only, as G43 does today), `doctor_ai.go`
- Modify: `internal/freshauth/freshauth.go` (`Config.Accepted func() []string`), `internal/hub/credentials.go` / `confirm.go` callers, `web/freshauth.js` (no `acr_values`)
- Test: `internal/aigate/aigate_test.go`, `internal/hub/ai_gatefile_test.go`, `internal/freshauth/freshauth_test.go`

**Interfaces:**
- Consumes: Tasks 3–4.
- Produces: `aigate.File{Version: 2, Methods []string, …}` and `aigate.Resource{Rule signin.Node \`json:"rule"\`, …}`. `func (h *Hub) freshAuthAccepted() []string` returns, in order, `spk` / `dpk` / `hwk` / `mtls` for each of passkey_synced / passkey_device / security_key / yubikey_cert that is on (D19). `freshauth` refuses `pwd`, `file` and `inv` in amr whatever `Accepted` returns.

- [ ] **Step 1: Write the failing tests**
  ```go
  func TestGateFileV2Vector(t *testing.T) // testdata/mcp-gate.json decodes strictly; re-encode is byte-identical
  func TestGateRulePerResource(t *testing.T) // companion rule == instance's compiled template; people == core "people";
  //  admin/aggregate == core "hub"
  func TestAIRefusedCertificateOnly(t *testing.T) // instance on yubikey-and-certificate: SetAISupport → 409
  //  "needs a client certificate on every sign-in"
  func TestFreshAuthRefusesSwitchedOffSecurityKey(t *testing.T) // amr [hwk] with security_key off → refused;
  //  amr [spk], [dpk], [hwk], [mtls] each accepted while its method is on; [pwd] refused; [inv] refused;
  //  [mtls,file] refused; [spk] with passkey_synced off → refused
  ```
- [ ] **Step 2: Run them to see them fail.** Run `go test ./internal/aigate/ ./internal/freshauth/ ./internal/hub/ -run 'GateFileV2|GateRule|CertificateOnly|FreshAuth'`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them to see them pass.** Run the same tests, then the full Go checks. Expected: `ok`.
- [ ] **Step 5: Commit and push.** `git commit -am "ai: gate file v2 with sign-in rules; fresh auth follows the method switches" && git push`.

---

### Task 8: FIDO MDS fetch and the authenticator trust list (hub)

**Files:**
- Create: `internal/fidomds/fidomds.go`, `internal/fidomds/trust.go`
- Modify: `go.mod` / `go.sum` (`github.com/go-webauthn/webauthn` latest stable), `internal/hub/signin_publish.go` (`Authenticators` from the cache), `cmd/hub/main.go` (`HUB_FIDO_MDS_URL`; `HUB_SIGNIN_EXTRA_AUTHENTICATORS` only with `HUB_DEV=1`, else the Hub refuses to start; `go h.RunMDS(ctx, 24*time.Hour)`)
- Test: `internal/fidomds/fidomds_test.go` (synthetic BLOB signed by a test root built in the test)

**Interfaces:**
- Produces:
  ```go
  type Fetcher struct{ URL string; CacheFile string; Roots *x509.CertPool /* nil = FIDO production root */; HTTP *http.Client; Now func() time.Time }
  func (f *Fetcher) Refresh(ctx context.Context) (*Status, error) // fetch, verify, cache; failure keeps the cache
  func (f *Fetcher) Load() (*metadata.Metadata, *Status, error)   // from the cache
  type Status struct{ Serial int; NextUpdate, FetchedAt time.Time; Stale bool; Err string }
  func Trust(m *metadata.Metadata, now time.Time) map[string]AuthenticatorTrust // D15
  func (h *Hub) RunMDS(ctx context.Context, every time.Duration)
  ```
  `SignInView.MDS` is the `Status`; `Stale` shows "The FIDO list is out of date: new passkeys count as synced until it refreshes".

- [ ] **Step 1: Write the failing tests**
  ```go
  func TestRefreshVerifiesSignature(t *testing.T) // BLOB signed by another key → error, cache untouched
  func TestRefreshKeepsLastGood(t *testing.T)     // server 500 → Load returns the previous BLOB
  func TestTrustKinds(t *testing.T) // external+secure_element → security_key; internal+tee → passkey_device;
  //  external+software → absent; status REVOKED / USER_KEY_PHYSICAL_COMPROMISE → present with Status "revoked" and
  //  its kind and roots; not certified → absent
  func TestTrustStaleIsEmpty(t *testing.T) // now = NextUpdate + 31 days → empty map, Status.Stale
  func TestExtraAuthenticatorsNeedDev(t *testing.T) // cmd/hub: env set without HUB_DEV=1 → exit with error
  ```
- [ ] **Step 2: Run them to see them fail.** Run `go test ./internal/fidomds/ ./cmd/hub/`. Expected: FAIL.
- [ ] **Step 3: Implement** with `go-webauthn/webauthn/metadata` (its decoder verifies the JWS x5c chain to `Roots` and the CRLs). The cache is 0600 in a 0700 dir.
- [ ] **Step 4: Run them to see them pass.** Run the same tests, then the full Go checks. Expected: `ok`.
- [ ] **Step 5: Commit and push.** `git commit -am "fidomds: fetch, verify and cache FIDO MDS; publish the authenticator trust list" && git push`.

---

### Task 9: Hub UI — Settings → Sign-in, template editor, instance drop-down, People password (hub)

**Files:**
- Create: `web/signin.js`
- Modify: `web/index.html`: a Settings → Sign-in section after the Settings tab's first block; script tag; the instance Settings tab replaces `.policy-section` with the sign-in drop-down and blocked list.
- Modify: `web/settings.js` (`accessParts` sends `sign_in_template`; the policy form goes), `web/directory.js` (password action copy D13; onboarding radio hidden while password is off), `internal/httpapi/server.go` (`/api/settings` view adds `sign_in`).
- Test: `internal/httpapi/webui_signin_test.go` (runs `signin.js` helpers like `webui_setup_test.go`'s `setupJS`), harness entries in `harness_test.go`

**Interfaces:**
- Consumes: Task 6 routes. The `PortcullisSignIn` global exposes `render(view)`, `editorHtml(template)`, `ruleFromEditor(root) signin rule JSON` and `blockedHtml(blocked)`.
- Layout follows `signin-settings.html` sections 1, 2 and 4, and `signin-nested-rule.html`. The methods table (all six, browser_cert shown "not available yet"), the templates table (rule sentence, score bar, used by, toggle, Edit), "+ New template", "Default for everything" and the add-stronger switch are all part of it. A "Core pages" table lists portal, hub, people, directory, enroll, metrics and traefik with drop-downs. In the editor, groups show as nested boxes with an "all of / any of" select, "+ method" (methods and the three families), "+ group" (hidden at level 3) and × buttons. Each change sends a 300 ms debounced `POST /api/signin/templates/preview`, which updates the score, the reason, the sentence and "who it affects". A refused save shows the Hub's text next to Save.
- Every value goes through `escapeHtml`; actions are `data-signin-action` attributes handled by one delegated listener on the section.

- [ ] **Step 1: Write the failing tests**
  ```go
  func TestSignInRenderEscapes(t *testing.T)     // template name `<img onerror>` rendered escaped in table and editor
  func TestSignInEditorRoundTrip(t *testing.T)   // editorHtml(nested example) → ruleFromEditor == the same JSON
  func TestSignInEditorDepthLimit(t *testing.T)  // a level-3 group has no "+ group" button
  func TestSignInNoInlineHandlers(t *testing.T)  // signin.js output has no "onclick=" / "javascript:"
  func TestInstanceSignInBody(t *testing.T)      // picking "Default (Standard · 2.5 / 5)" sends sign_in_template ""
  func TestPasswordActionCopy(t *testing.T)      // directory.js shows "Signs in to Portcullis only while Password is on"
  ```
- [ ] **Step 2: Run them to see them fail.** Run `go test ./internal/httpapi/ -run 'SignIn|PasswordActionCopy'`. Expected: FAIL.
- [ ] **Step 3: Implement.** Then check in a browser against the harness: `go test -tags harness -run TestHarness -timeout 0 ./internal/httpapi/` and open the printed URL. Edit the nested example, see 4.4 / 5 and the sentence, and see a 409 for disabling Standard.
- [ ] **Step 4: Run them to see them pass.** Run the same tests, then the full Go checks. Expected: `ok`.
- [ ] **Step 5: Commit and push.** `git commit -am "web: Settings → Sign-in, template editor, per-app template, password copy" && git push`. Wait for Hub CI green; the `edge` image comes with the merge (Task 19's merge order).

---

### Task 10: New repo `porelli/portcullis-keycloak`: scaffolding, CI, image, config file, rules (keycloak)

**Files** (all new, repo root `/Volumes/workspace/portcullis/portcullis-keycloak`):
- `Dockerfile`. Stages: `build` = a pinned `gradle:<ver>-jdk21@sha256:…` running `gradle --no-daemon --dependency-verification strict jar`; `test` = the same base running `gradle --no-daemon --dependency-verification strict test`; final `FROM quay.io/keycloak/keycloak:26.8.1@sha256:3f3c5f8e03c614774b4bd9173b88391fefa4153bfc010d8012d59ad825377332` + `COPY --from=build …/portcullis-signin.jar /opt/keycloak/providers/`.
- `settings.gradle.kts`, `build.gradle.kts`, `gradle/verification-metadata.xml` (sha256 for every artifact, generated with `gradle --write-verification-metadata sha256`, then reviewed), `gradle/wrapper/gradle-wrapper.properties` (with `distributionSha256Sum`). Keycloak 26.8.1 SPI artifacts (`keycloak-server-spi`, `-spi-private`, `keycloak-services`, `keycloak-model-jpa`) and `webauthn4j-core` are `compileOnly`, at exactly the versions Keycloak 26.8.1 ships. Tests use JUnit 5 and `webauthn4j-test` at the same webauthn4j version.
- `src/main/java/eu/portcullis/signin/{SigninConfig.java, Rule.java, Methods.java}`, `src/main/resources/META-INF/services/` (empty for now)
- `src/test/java/eu/portcullis/signin/{SigninConfigTest.java, RuleTest.java}`, `src/test/resources/signin_vectors.json` (byte copy of the Hub's `internal/signin/testdata/vectors.json`, Task 2)
- `.github/workflows/build.yml`, modelled on the Hub's:
  - test job: `docker buildx build --target test .`;
  - vectors job: `cmp src/test/resources/signin_vectors.json` against `porelli/portcullis-hub`'s same-named branch, else main. When the Hub ref has no such file yet (Hub main before the merge), the job prints a notice and passes;
  - image job: buildx build, then a smoke run of the image (`start-dev`, admin API `GET /admin/serverinfo` lists every provider id of D5 that exists so far);
  - publish to `ghcr.io/porelli/portcullis-keycloak`: `edge` on main pushes, semver on `v*` tags;
  - actions pinned by full SHA with `# vX.Y.Z`.
- `.github/dependabot.yml` (`gradle` /, `docker` /, `github-actions` /), `.github/automerge/automerge.sh` + `test.sh` and `.github/workflows/dependabot-automerge.yml` (copied from the Hub, names adapted), `README.md` (one paragraph + link to the docs site, like the Hub's), `CLAUDE.md` (layout table, commands, rules: contract first, supply chain, no migration code, the D5 provider ids).

**Interfaces:**
- Consumes: the D20 file (`/hub-data/signin-keycloak.json`) and the Hub's `vectors.json`.
- Produces:
  ```java
  final class SigninConfig { static SigninConfig current();               // mtime cache of /hub-data/signin-keycloak.json
    static SigninConfig load(Path p);                                     // strict Jackson, FAIL_ON_UNKNOWN_PROPERTIES
    static final SigninConfig DENY_ALL; boolean on(String method); boolean addStronger(); long mdsSerial();
    Optional<Rule> templateForClient(String clientId); Optional<String> clientName(String clientId);
    Optional<Trust> authenticator(UUID aaguid); }
  record Trust(String kind, String status, List<X509Certificate> roots) {}  // status "certified" | "revoked"
  final class Rule { static Rule parse(JsonNode n); boolean satisfiedBy(Set<String> methods);
    List<Set<String>> alternatives(); }
  final class Methods { static Optional<String> forAmr(String amr); static int tenths(String m);
    static Set<String> ofSession(KeycloakSession s, RealmModel r, UserSessionModel u); } // AmrUtils + forAmr + on()
  ```

- [ ] **Step 1: Create the repo (controller).** Run `gh repo create porelli/portcullis-keycloak --public` and clone it to `/Volumes/workspace/portcullis/portcullis-keycloak`. **Ask the user before the very first push**; until then commit locally only.
- [ ] **Step 2: Write the failing tests.**
  ```java
  @Test void SigninConfigTest.invalidOrMissingFileIsDenyAll()   // unknown key, version 2, bad JSON, absent → DENY_ALL
  @Test void SigninConfigTest.reloadsOnMtimeChange()
  @Test void RuleTest.sharedVectors()                           // every signin_vectors.json case: satisfiedBy, alternatives
  @Test void RuleTest.rejectsUnknownLeafAndDepth()              // leaf "webauthn", compiled depth 5 → IllegalArgumentException
  ```
  Run `docker build --target test .`. Expected: FAIL (classes missing).
- [ ] **Step 3: Implement** the three classes and the scaffolding above. `README.md` and `CLAUDE.md` follow the Hub's shape.
- [ ] **Step 4: Run them to see them pass.** Run `docker build --target test . && docker build -t portcullis-keycloak:dev .`. Expected: `BUILD SUCCESSFUL`, then the image builds.
- [ ] **Step 5: Commit and push.** Commit the scaffolding on `main` (README, CLAUDE.md, dependabot, automerge, workflows, Gradle files without sources). Commit the rest on `signin`. After the user's OK, run `git push -u origin main signin` and check CI starts on both.

---

### Task 11: Passkey kinds, attestation store, reclassification (keycloak)

**Files:**
- Create in `src/main/java/eu/portcullis/signin/`: `PasskeyClassifier.java`, `PasskeyCredentialProviders.java`, `PasskeyRegister.java`, `PasskeyRegisterFactory.java`, `store/PasskeyEntity.java`, `store/PasskeyStore.java`, `store/PasskeyStoreProviderFactory.java` (`JpaEntityProvider`), `Reclassify.java` (the scheduled task).
- Create: `src/main/resources/META-INF/portcullis-passkey-changelog.xml` (Liquibase), `META-INF/services/*` entries.
- Test: `src/test/java/eu/portcullis/signin/{PasskeyClassifierTest, ReclassifyTest, PasskeyStoreTest, PasskeyRegisterTest}.java`

**Interfaces:**
- Consumes: Task 10, D14.
- Produces:
  ```java
  record StoredAttestation(String fmt, byte[] attStmtCbor, byte[] authenticatorData, UUID aaguid, boolean backupEligible) {}
  final class PasskeyClassifier {                                   // webauthn4j AttestationObjectConverter +
    static String kind(StoredAttestation a, SigninConfig cfg, Instant now); //  TrustAnchorCertPathTrustworthinessValidator
    static String reclassify(String current, String cappedAt, StoredAttestation a, SigninConfig cfg, Instant now); } // D14
  // kinds: "passkey_synced" | "passkey_device" | "security_key"; type for each:
  //   "webauthn-passwordless", "portcullis-device-passkey", "portcullis-security-key"
  final class PasskeyStore { void put(RealmModel r, UserModel u, CredentialModel c, StoredAttestation a, String kind, String cappedAt);
    Optional<PasskeyEntity> get(String credentialId); Stream<PasskeyEntity> all(RealmModel r);
    void setKind(PasskeyEntity e, String kind, long serial); void removeOrphans(RealmModel r); }
  final class Reclassify implements ScheduledTask { public void run(KeycloakSession s); } // every 5 min; acts when
  //  SigninConfig.mdsSerial() > the last applied serial (kept in the table PORTCULLIS_SIGNIN_STATE)
  // PasskeyRegisterFactory id "webauthn-register-passwordless", order() above the stock one
  ```
  `reclassify` follows D14:
  ```
  next := kind(a, cfg, now)
  if cfg.authenticator(a.aaguid) is present with status "revoked": return passkey_synced
  if rank(next) > rank(current): return min(next, cappedAt)      // upward only, never past the registration cap
  return current                                                 // missing entry or failed chain: no downgrade
  ```
  When the kind changes, the credential's type is set to the new kind's type through `user.credentialManager().updateStoredCredential`. Task 18's live case pins that Keycloak updates the type.

- [ ] **Step 1: Write the failing tests**
  ```java
  @Test void PasskeyClassifierTest.packedChainToTrustedRootIsSecurityKey()
  @Test void PasskeyClassifierTest.noneAttestationWithYubiKeyAaguidIsSynced()
  @Test void PasskeyClassifierTest.selfAttestationIsSynced()
  @Test void PasskeyClassifierTest.backupEligibleIsSynced()
  @Test void PasskeyClassifierTest.chainToAnotherAaguidsRootIsSynced()
  @Test void PasskeyClassifierTest.leafAaguidExtensionMismatchIsSynced()
  @Test void PasskeyClassifierTest.platformTrustIsDeviceBound()        // trust kind passkey_device → passkey_device
  @Test void PasskeyClassifierTest.revokedStatusIsSynced()             // entry status revoked → passkey_synced
  @Test void ReclassifyTest.upwardWhenNewListVerifies()   // stored packed attestation, first list lacks the AAGUID →
  //  synced; list serial+1 has it as security_key → security_key, credential type portcullis-security-key
  @Test void ReclassifyTest.missingEntryNeverDowngrades() // security_key, next list lacks the AAGUID → stays security_key
  @Test void ReclassifyTest.revokedStatusDowngrades()     // security_key, next list status revoked → passkey_synced
  @Test void ReclassifyTest.neverPastRegistrationCap()    // cappedAt passkey_synced, list now verifies → stays synced
  @Test void ReclassifyTest.sameSerialDoesNothing()       // no row touched when mdsSerial == last applied
  @Test void PasskeyStoreTest.attestationKeptWithCredential() // put, then get returns the same fmt / attStmt / AAGUID;
  //  removing the credential removes the row
  @Test void PasskeyRegisterTest.strongerFromWeakerRefusedWhenOff()    // session {spk}, new kind security_key, addStronger false → error
  @Test void PasskeyRegisterTest.setupLinkSessionMayAddStronger()      // session {inv} → allowed, cappedAt null
  @Test void PasskeyRegisterTest.adminsGetSecurityKeyFirstHints()      // lldap_admin member → hints ["security-key","client-device","hybrid"]
  ```
- [ ] **Step 2: Run them to see them fail.** Run `docker build --target test .`. Expected: FAIL.
- [ ] **Step 3: Implement.** Attestation objects for the tests come from `webauthn4j-test`'s emulators with test CAs; the store tests use an in-memory H2 `EntityManager` with the Liquibase changelog applied. The register action reads the raw `attestationObject` after Keycloak's own validation. It keeps `fmt`, the attStmt CBOR, the authenticator data and the BE flag, classifies them, and creates the credential through the provider of the classified type. It then writes the store row in the same transaction.
- [ ] **Step 4: Run them to see them pass.** Run the same command. Expected: `BUILD SUCCESSFUL`. The image smoke run lists `webauthn-register-passwordless`, `portcullis-security-key`, `portcullis-device-passkey`.
- [ ] **Step 5: Commit and push.** `git add -A && git commit -m "passkey kinds at registration, attestation store, reclassification" && git push`.

---

### Task 12: Authenticators, conditions, template check (keycloak)

**Files:**
- Create in `src/main/java/eu/portcullis/signin/`: `CookieAuthenticator*.java` (id `auth-cookie`, override), `PasskeyAuthenticator*.java`, `PasskeyKindCondition*.java`, `MethodAuthenticator*.java`, `PasswordForm*.java`, `X509Authenticator*.java`, `TemplateAuthenticator*.java`, `PcMethod.java`
- Create: `src/main/resources/theme-resources/templates/portcullis-needs-stronger.ftl` (Task 15's page copy, every value `?html`), `theme-resources/messages/messages_en.properties`
- Test: `src/test/java/eu/portcullis/signin/*Test.java`

**Interfaces:**
- Consumes: Tasks 10–11.
- Produces provider ids per D5 and `PcMethod.requested(AuthenticationFlowContext) Optional<String>` (reads the client note `client_request_param_pc_method`; only the six ids and `passkey`, anything else empty). The deny list is `PasswordForm.NO_PASSWORD = Set.of("admin", "portcullis-hub")`.

- [ ] **Step 1: Write the failing tests**
  ```java
  @Test void MethodAuthenticatorTest.refusesSwitchedOffMethod()        // method password, config off → failure ACCESS_DENIED
  @Test void CookieAuthenticatorTest.attemptsWhenRequestedMethodMissing() // pc_method security_key, session {spk} → attempted, user set
  @Test void CookieAuthenticatorTest.succeedsWhenRequestedMethodPresent()
  @Test void PasskeyAuthenticatorTest.allowCredentialsFollowRequestedKind() // pc_method security_key → only that type's ids
  @Test void PasskeyAuthenticatorTest.acceptsAllThreeTypes()           // discoverable login finds each type's credential
  @Test void PasswordFormTest.skippedWhenOffOrOtherMethodRequested()   // attempted
  @Test void PasswordFormTest.refusesAdminAndHubAccount()              // "admin", "Admin", "portcullis-hub" with the right
  //  LDAP password → failure, brute-force counter incremented; "alice" → success
  @Test void PcMethodTest.ignoresUnknownValues()                       // "webauthn", "" → empty
  @Test void TemplateAuthenticatorTest.unlistedClientPasses()
  @Test void TemplateAuthenticatorTest.listedClientUnmetShowsNeedsStronger() // challenge form portcullis-needs-stronger.ftl
  @Test void TemplateAuthenticatorTest.deniesWhenConfigInvalid()       // DENY_ALL + a client that would be listed → failure
  @Test void NeedsStrongerTemplateTest.escapesValues()                 // client name "<b>" rendered as &lt;b&gt;
  ```
- [ ] **Step 2: Run them to see them fail.** Run `docker build --target test .`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them to see them pass.** Run the same command, then `docker build .`. Expected: `BUILD SUCCESSFUL`; the smoke run lists every D5 provider id.
- [ ] **Step 5: Commit and push.** `git commit -am "method authenticators, pc_method step-up, template check" && git push`.

---

### Task 13: Templates e2e on policy v6 (templates repo)

**Files:**
- Modify: `tests/e2e/app_signin.py` (`policy_doc()` writes v6 per D10 with built-in `standard` compiled; the sign-in walk handles the setup-link session's step-up page: click `#stepup-continue`, touch the virtual authenticator)

**Interfaces:**
- Consumes: Task 1's v6 shape; core's group-gate page ids `#stepup-continue` and `#needs-stronger` (Task 15).

- [ ] **Step 1:** Change `policy_doc()` and the sign-in walk. A unit check (`python3 -c "import tests.e2e.app_signin as a; a.selftest()"`, with the new `selftest()` asserting `policy_doc()["version"] == 6` and `"standard" in templates`) fails first.
- [ ] **Step 2: Run it to see it fail.** Expected: AssertionError.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run it to see it pass.** Run the same command. Expected: exit 0. Then push; `test-apps.yml` runs against core's `signin` branch once Task 18 exists (same-named branch).
- [ ] **Step 5: Commit and push.** `git commit -am "e2e: policy file v6 and the setup-link step-up" && git push -u origin signin`.

---

### Task 14: Core uses the Keycloak image; flows and `keycloak configure` (core)

**Files:**
- Modify: `docker-compose.yml` (keycloak `image: ${KEYCLOAK_IMAGE:-ghcr.io/porelli/portcullis-keycloak:edge}`, volume `hub_data:/hub-data:ro`)
- Create: `.github/actions/keycloak-image/action.yml`, mirroring `hub-image`: a same-named portcullis-keycloak branch (not main, not `v*`) is cloned and built as `portcullis-keycloak:ci`, then `KEYCLOAK_IMAGE=portcullis-keycloak:ci` and `KEYCLOAK_LOCAL=1` are set; otherwise the published edge image is used and named in the step summary.
- Modify: `.github/workflows/ci.yml` (every job that uses `hub-image` also uses `keycloak-image`; the pin checks and the pulled-image list treat `KEYCLOAK_IMAGE` exactly like `HUB_IMAGE`), the release tooling (wherever a release pins `HUB_IMAGE` to tag@digest, pin `KEYCLOAK_IMAGE` the same way), `scripts/lib/stack.sh` / `status.sh` (`portcullis upgrade` pulls it like the Hub's)
- Modify: `keycloak/realm-export.json` (D6 flows, `acr.loa.map` `{}`, brute force, the passwordless policy, the invite config `amr-hwk-invite*` value `inv`, forward-auth client `default.acr.values` removed), `scripts/lib/keycloak.sh` (`keycloak configure`: the realm PUT without the LoA map but with brute force; the AMR-config check walks the new flows; `_kc_sync_flow` rebuilds them), `keycloak/themes/portcullis/login/resources/js/webauthnRegister.js` (attestation `direct`, `hints` from the form attribute `portcullisHints`)
- Modify: core `CLAUDE.md`: the Hub-image row gets a sibling for the Keycloak image (`KEYCLOAK_IMAGE`, edge = main, releases semver; CI's `keycloak-image` action), the sign-in paragraph (passkey-only, LoA 1–3) is rewritten per D1/D6/D7, and the supply-chain line names the image.
- Test: `tests/test_cli.sh`

**Interfaces:**
- Consumes: Task 12's provider ids and Task 10's image.

- [ ] **Step 1: Write the failing tests** in `tests/test_cli.sh`:
  - `realm export: portcullis-universal is REQUIRED portcullis-authenticate + REQUIRED portcullis-template`
  - `no conditional-level-of-authentication anywhere`
  - `every reference config has maxAge 36000`
  - `invite amr configs say inv`
  - `bruteForceProtected true`
  - `compose keycloak image is ${KEYCLOAK_IMAGE:-ghcr.io/porelli/portcullis-keycloak:edge}`
  - `keycloak mounts hub_data read-only at /hub-data`
- [ ] **Step 2: Run them to see them fail.** Run `bash tests/test_cli.sh`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them to see them pass.** Run `bash tests/test_cli.sh && shellcheck -S warning portcullis scripts/lib/*.sh tests/*.sh`. Expected: `all passed`, no shellcheck output.
- [ ] **Step 5: Commit and push.** `git commit -am "keycloak: the portcullis-keycloak image, method flows, pc_method, configure" && git push -u origin signin`.

---

### Task 15: group-gate on policy v6 (core)

**Files:**
- Modify: `group-gate/group-gate.py` (remove `FACTOR_TO_AMR`, `FACTOR_TO_LOA`, `ACR_TO_LOA`, `evaluate_policy`, `policy_relies_on_mtls`, the old `stepup_url`; v6 validation; the core host map), `oauth2-proxy/alpha.yaml` (D7)
- Create: `tests/signin_vectors.json` (copy of the Hub's `internal/signin/testdata/vectors.json`)
- Test: `tests/test_group_gate.py`

**Interfaces:**
- Consumes: the D10 file, D1, D7, D8.
- Produces:
  ```python
  AMR_TO_METHOD = {"pwd": "password", "spk": "passkey_synced", "file": "browser_cert",
                   "dpk": "passkey_device", "hwk": "security_key", "mtls": "yubikey_cert"}
  def validate_rule(node, methods: set, depth: int = 1) -> Optional[str]
  def rule_for_host(doc: dict, host: str) -> Optional[dict]          # hosts/default; core[] for core hosts
  def session_methods(amr: list, enabled: set, cert_bound: bool) -> set  # D8
  def rule_satisfied(node, have: set) -> bool
  def alternatives(node) -> List[FrozenSet[str]]
  def choose_stepup(node, have: set, set_up: Optional[set]) -> Optional[str] # a method id, "passkey", or None
  def stepup_url(host: str, method: str, extra: bool) -> str
  def render_needs_page(app: str, have: set, node, set_up: Optional[set], domain: str) -> bytes
  ```
  Behaviour on an unmet rule (no auto-redirect, 403):
  - **Step-up page.** When one missing method is completable (the method is in `set_up`, or `set_up` is unknown, or the session is `inv` and the method is a passkey kind, in which case it asks for `passkey`), the page reads "<App> needs <phrase>" with `#stepup-continue` → `stepup_url`.
  - **Needs-stronger page.** Otherwise the page `#needs-stronger` copies mockup section 2: "<App> needs a stronger sign-in — You signed in with <phrases>. <App> accepts any one of: • <alternative> — you don't have one yet …". "Set up a passkey" / "Set up a security key" link to `https://auth.<domain>/realms/portcullis/account/account-security/signing-in`, except when add-stronger is off and the session is weaker, which shows "ask your admin". "Sign-in methods" links to the same account page. Certificates and passwords: "ask your admin".

  The app name comes from portal-apps.json by host, else the host. Every value goes through `html.escape`.

- [ ] **Step 1: Write the failing tests**
  ```python
  def test_v6_only(self)                          # version 5 → deny; missing "methods" → deny
  def test_unknown_leaf_denies(self)              # leaf "webauthn" → policy_error deny
  def test_shared_vectors(self)                   # every tests/signin_vectors.json case
  def test_switched_off_method_amr_ignored(self)  # amr [pwd], methods without password, basic → stepup/needs, not allow
  def test_inv_session_meets_nothing(self)        # amr [inv] on basic → not allowed, step-up asks pc_method=passkey
  def test_yubikey_cert_needs_bound_cert(self)    # strong, amr [mtls], no cert header → not allowed; CN=user → allow
  def test_core_host_uses_core_map(self)          # hub.<d> with core strong, default basic → strong applies
  def test_stepup_one_method(self)                # strong, have {spk}, set_up {hwk} → X-Stepup-URL has pc_method=security_key
  def test_needs_page_escapes(self)               # app name "<b>" escaped; #needs-stronger present; no auto refresh
  def test_alpha_pc_method_allowlist(self)        # alpha.yaml allows exactly the 6 ids + passkey, no acr_values
  ```
- [ ] **Step 2: Run them to see them fail.** Run `python3 tests/test_group_gate.py`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them to see them pass.** Run the same command. Expected: `OK`.
- [ ] **Step 5: Commit and push.** `git commit -am "group-gate: policy file v6, method rules, one-method step-up, needs-stronger page" && git push`.

---

### Task 16: mcp-gate on gate file v2 (core)

**Files:**
- Modify: `mcp-gate/internal/config/config.go`, `testdata/mcp-gate.json` (the Hub's v2 vector bytes), `mcp-gate/internal/authz/authz.go`, `mcp-gate/internal/aggregate/aggregate.go`
- Create: `mcp-gate/internal/authz/rule.go`, `testdata/signin_vectors.json` (copy)
- Test: `mcp-gate/internal/config/config_test.go`, `mcp-gate/internal/authz/rule_test.go`, `aggregate_test.go`

**Interfaces:**
- Produces: `type Rule struct{Op string; Items []Rule; Leaf string}` (strict JSON), `func (r Rule) Satisfied(have map[string]bool) bool`, `func TokenMethods(amr []string, enabled []string) map[string]bool` (drops `yubikey_cert`, `browser_cert`, `inv`, unknown).

- [ ] **Step 1: Write the failing tests**
  ```go
  func TestConfigV2Strict(t *testing.T)        // version 1 refused; "min_loa" key refused; leaf not in methods refused
  func TestRuleSharedVectors(t *testing.T)
  func TestTokenNeverCountsCertificates(t *testing.T) // amr [mtls] on rule any[yubikey_cert, security_key] → 403
  func TestAggregatePerUpstreamRule(t *testing.T)     // upstream rule unmet → that upstream's tools absent
  ```
- [ ] **Step 2: Run them to see them fail.** Run `cd mcp-gate && go test ./...`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them to see them pass.** Run `cd mcp-gate && go vet ./... && go test -race ./...`. Expected: `ok`.
- [ ] **Step 5: Commit and push.** `git commit -am "mcp-gate: gate file v2, sign-in rules instead of min_loa" && git push`.

---

### Task 17: Static TLS options, enroll certificates API, `signin reset-core` CLI (core)

**Files:**
- Modify: `scripts/lib/config.sh`. `config apply` handles only `ACME_STAGING` and no longer writes `traefik/dynamic/tls.yml`; the help text loses MTLS_ENABLED.
- Modify: `scripts/lib/stack.sh` (no `MTLS_ENABLED=true` in the default `.env`).
- Modify: `traefik/dynamic/tls.yml` (tracked, static): exactly `protected` (RequireAndVerifyClientCert), `authaware` (VerifyClientCertIfGiven) and `public` (no clientAuth), each `minVersion: VersionTLS12`, `sniStrict: false`. Its header comment says the Hub picks per app router and core routers use `authaware`.
- Modify: `portcullis` (help: `signin reset-core`; `config apply` text).
- Create: `scripts/lib/signin.sh` (`cmd_signin`: `reset-core` per D17, typed confirmation `reset`, `--yes` for CI)
- Modify: `enroll/main.go` (`GET /internal/certificates` on :8444, the invite bearer), `enroll/main_test.go`
- Test: `tests/test_cli.sh`, `tests/test_shell_libs.sh`

**Interfaces:**
- Produces: `GET /internal/certificates` → `{"certificates":[{"user","serial","not_after","revoked"}]}` (401 without the bearer); `./portcullis signin reset-core [--yes]`.

- [ ] **Step 1: Write the failing tests**
  - `test_cli.sh`:
    - `MTLS_ENABLED appears nowhere in portcullis scripts/lib docker-compose.yml`
    - `traefik/dynamic/tls.yml defines exactly protected, authaware, public with those clientAuth types`
    - `config apply leaves tls.yml byte-identical`
    - `every core router in docker-compose.yml uses authaware@file`
    - `the hub service mounts nothing under traefik/ read-write`
    - `signin reset-core without --yes and no tty refuses`
    - `signin reset-core --yes runs dc stop hub, dc run --rm --no-deps --entrypoint /usr/local/bin/hub hub signin reset-core, dc start hub (stubbed dc)`
  - `test_shell_libs.sh`: `config_apply with ACME_STAGING=true writes ACME_CA_SERVER staging and touches no traefik file`.
  - Go: `TestInternalCertificatesNeedsBearer`, `TestInternalCertificatesLists`.
- [ ] **Step 2: Run them to see them fail.** Run `bash tests/test_cli.sh; bash tests/test_shell_libs.sh; (cd enroll && go test ./...)`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them to see them pass.** Run the same commands plus `shellcheck -S warning portcullis scripts/lib/*.sh tests/*.sh`. Expected: all pass, no shellcheck output.
- [ ] **Step 5: Commit and push.** `git commit -am "core: static TLS options (the Hub picks per app), enroll certificates API, signin reset-core" && git push`.

---

### Task 18: Core CI and browser e2e (core)

**Files:**
- Modify: `.github/workflows/ci.yml`. A new step "Shared sign-in vectors match the Hub": `cmp` core's two copies (`tests/signin_vectors.json`, `mcp-gate/internal/authz/testdata/signin_vectors.json`) against the checked-out Hub branch's `internal/signin/testdata/vectors.json`. The e2e jobs start the Hub with `HUB_DEV=1` and `HUB_SIGNIN_EXTRA_AUTHENTICATORS=tests/e2e/fixtures/virtual-authenticators.json`.
- Create: `tests/e2e/fixtures/virtual-authenticators.json` (Chromium's virtual CTAP2 AAGUID → `security_key` with its attestation root; a second virtual authenticator without attestation = synced)
- Modify: `tests/e2e/e2e_login.py` (cases below), `tests/e2e/e2e_ai.py` / `e2e_filesharing.py` (sign in with a virtual passkey; fresh auth accepts any passkey kind)

**Interfaces:**
- Consumes: everything above.

- [ ] **Step 1: Write the failing e2e cases** in `e2e_login.py`:
  - `setup_link_then_stepup`: the setup link lands on the step-up page; Continue + touch → the app.
  - `synced_passkey_refused_on_strong`: a synced virtual key reaches `#needs-stronger` on `hub.<d>`.
  - `security_key_on_strong`: allowed.
  - `amr_accumulates`: after a step-up the token amr has both `spk` and `hwk`.
  - `pc_method_reaches_keycloak`: the step-up shows the passkey prompt only.
  - `reclassify_updates_type`: register with the fixture's security-key entry missing (→ synced); publish it (Hub API dev hook bumps `mds.serial`); within 6 min Keycloak's credential type is `portcullis-security-key`.
  - `password_off_not_offered`: no password field.
  - `password_on_basic_app`: with password on via the Hub API and an app on basic, a password sign-in opens it, and `hub.<d>` then shows `#needs-stronger`.
  - `admin_password_refused`: with password on, `admin` + `LLDAP_ADMIN_PASSWORD` shows "Password sign-in isn't available for this account".
  - `native_oidc_template_enforced`: a native-oidc app on strong with a synced session gets Keycloak's needs-stronger page.
  - `tls_follows_switch`: an app on standard. With yubikey_cert on, `openssl s_client -servername <app host>` shows "Acceptable client certificate CA names". After switching it off, the Hub restarts the app with `public@file` and the list is gone. `auth.<d>` still shows it either way (core routers stay on `authaware`).
  - `reset_core`: after `./portcullis signin reset-core --yes`, `/api/signin` core hub == standard.
- [ ] **Step 2: Run to see it fail.** Push and let CI run (or run locally with the stack): `python3 tests/e2e/e2e_login.py`. Expected: the new cases FAIL before the CI wiring.
- [ ] **Step 3: Implement** the CI wiring and the fixture.
- [ ] **Step 4: Run to see it pass.** CI on `signin` (core) is green, including `e2e`, `e2e-instances`, `e2e-settings`, `e2e-filesharing` and `e2e-ai`, with the Hub and the Keycloak image both built from their `signin` branches.
- [ ] **Step 5: Commit and push.** `git commit -am "ci: sign-in methods e2e, shared vectors check" && git push`.

---

### Task 19: Mainline (all repos)

- [ ] **Step 1:** Merge docs `signin` → main, push, delete the branch and the worktree `wt-docs-signin`.
- [ ] **Step 2:** Merge portcullis-keycloak `signin` → main and push. Wait for `build.yml` to publish `ghcr.io/porelli/portcullis-keycloak:edge` (`gh run list -R porelli/portcullis-keycloak --branch main --workflow build.yml` shows success). Its vectors job passes with a notice until the Hub merges, and is re-run after Step 3.
- [ ] **Step 3:** Merge hub `signin` → main and push. Wait for `ghcr.io/porelli/portcullis-hub:edge` (`gh run list --branch main --workflow build.yml` shows success). Re-run the keycloak repo's vectors job: it passes with no notice.
- [ ] **Step 4:** Merge templates `signin` → main and push; check `test-apps.yml` is green.
- [ ] **Step 5:** Merge core `signin` → main and push; check CI is green on main. Delete every `signin` branch (local and remote, all five repos) and any worktree.
- [ ] **Step 6:** Deploy only with the user's OK. On the test server: `ACME_STAGING=true`, `./portcullis config apply && ./portcullis up`.

---

## Self-review

1. **Spec coverage.**
   - Six methods with on/off, strengths and counts: Tasks 2, 3, 5, 9.
   - Passkey kinds via attestation and MDS, with stored attestation and upward reclassification: Tasks 8, 11.
   - Password as a real method, never for `admin` / `portcullis-hub`: D13, Tasks 5, 12, 15.
   - Templates (nesting, families, built-ins, edit/new, enable/disable locks, method switch-off locks): Tasks 2, 3, 9.
   - Score: Task 2; mockups corrected (Global Constraints).
   - Default, per-instance pick and core pages on Strong: Tasks 3, 4.
   - Admin warnings: Task 5.
   - "Needs a stronger sign-in" page with "Set up" links: Tasks 12, 15.
   - Add-stronger switch: Tasks 3, 11.
   - Lockout guard and CLI recovery: Tasks 5, 17.
   - Native-OIDC: Tasks 4, 12, 14.
   - Certificate requests follow the switches through Hub-rendered labels, with static core options: Tasks 4, 17.
   - Fresh auth (any passkey kind or a YubiKey certificate): Task 7.
   - The new repo, its image and core's use of it: Tasks 1, 10, 14, 19.
   - `pwd` naming: D1/D6; `pwd` now means password and the LoA map is gone.
   - People password fallback: Tasks 5, 9.
   - Out of scope (part 2/3): browser `.p12`, `pki_file`, history, the people Sign-in page, retiring enroll, the naming sweep, impersonation. The "always reachable" Sign-in page is part 2; part 1's needs-stronger page is rendered by group-gate and the extension, so it is always reachable.
2. **Step scan.** Each step names its files, signatures, test names with assertions and commands. Bodies appear only for the score, sentence, evaluation and reclassification rules.
3. **Type consistency.** These names match across tasks:
   - `signin.Node` / `Compile` / `Satisfied` / `Implies` / `NeedsCertificate` (Tasks 2, 4, 6, 7);
   - `compiledLocked` / `templateForInstanceLocked` (3 → 4); `peopleMethodsLocked` (stub 4, real 5); `Blocked` (5 → 3's `AffectedApp`, 9);
   - `AuthenticatorTrust{Kind, Status, Roots}` (4, 8) ↔ Java `Trust(kind, status, roots)` (10, 11);
   - the credential types (5, 11);
   - `pc_method` (12, 14, 15, alpha.yaml);
   - page ids `#stepup-continue` / `#needs-stronger` (13, 15, 18);
   - `KEYCLOAK_IMAGE` (14, 19).
4. **Review Focus.** Each of the five lines names a test in its owning task. group-gate's tests are now Task 15; the extension's are Tasks 11–12.
5. **Proportion.** The plan is roughly 3.5× the spec's length because of the extra repo. Code blocks are signatures and test names; the only bodies are the score / sentence / reclassification rules.
