# Sign-in methods, part 2 of 3 (Sign-in page, browser certificates, history, help to reset, enroll retired, clear names) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give every person one Sign-in page on `people.<domain>` that lists their switched-on methods, lets them create, download and revoke browser certificates, renew a YubiKey certificate and set their password, shows which of their apps they can open and their sign-in history, and lets admins and sign-in helpers help them reset. The goal also covers retiring `enroll.<domain>` as a site, making browser certificates (`browser_cert`, amr `file`, CA `pki_file`) a real method, and using the clear certificate names everywhere.

**Architecture:** Core's Vault gets a second issuing CA, `pki_file`, under the existing root. enroll is the only service that holds Vault access, and it gains internal, bearer-protected endpoints for browser certificates and for issuing, renewing and revoking YubiKey certificates. For a browser certificate enroll generates the key, has `pki_file` sign it, and returns a PKCS#12 file and its generated password once. enroll's own pages go away; only `/invite/*` stays routed. The Hub serves the Sign-in page and its API on the people listener and relays to enroll. group-gate lets any switched-on method reach that page. The Keycloak extension, group-gate and the Hub's inventory tell the two CAs apart by issuer, so `mtls` means a YubiKey certificate only. The sign-in history is merged at read time from three sources: Keycloak's stored LOGIN / LOGIN_ERROR events, whose details the extension fills in; a daily "app opened" log that group-gate writes; and the Hub's audit log.

**Tech Stack:** Go 1.27 (Hub, enroll), `software.sslmate.com/src/go-pkcs12` (BSD-3, enroll), `github.com/mileusna/useragent` (MIT, Hub), Python 3 + `cryptography` (group-gate), Java 21 + Gradle with dependency verification (Keycloak 26.8.1 SPI), vanilla JS (Hub UI), bash (core CLI), Vault PKI.

**Spec:** `docs/superpowers/specs/2026-11-09-sign-in-methods-design.md` (Hub repo), call 8 part (2), with the rulings it keeps from `docs/superpowers/specs/2026-11-02-certificates-selfservice-design.md` (goals 1–4, call 8). Mockups: `.superpowers/brainstorm/98502-1794260205/content/signin-people.html` sections 1 and 3 (section 4 and the "Sign in as" row are part 3). Model and conventions: `docs/superpowers/plans/2026-11-09-sign-in-methods-part1.md` (its D1–D20 stay in force; part 2 continues with D21–D34).

## Global Constraints

Process and checks (part 1's rules, restated for part 2):
- **Precondition (met 2026-11-11):** branch `fresh-template` (hub, keycloak, docs, core: fresh auth by the governing template, `signin.FreshAccepted`, `freshGov`) is mainlined before part 2 starts. Every part-2 branch starts from that `main`.
- Branch `signin2` in every repo touched (docs, keycloak, hub, core), mainlined at the end, no PRs. Before Task 1 the controller creates the worktrees `/Volumes/workspace/portcullis/wt-signin2/{portcullis-docs,portcullis-keycloak,portcullis-hub,portcullis}` on `signin2`. Each task works in its repo's worktree. The templates repo isn't changed; its CI is re-run in Task 14.
- No migration / back-compat code (there are no installs). `GATE_CRL_URL` / `GATE_DELTA_CRL_URL` and the core page key `enroll` go away, and nothing reads their old shapes. The idempotent `pki setup` creating a CA piece that is missing is setup, not migration.
- Contract first: Task 1 changes `docs/guides/integration-contracts.md` before any code.
- Never weaken access control, fail closed. An unknown CA, an unreadable CA file, an unreadable CRL list or an unknown certificate kind never counts as a method. A switched-off method is never accepted.
- Secrets never on argv or in logs, the audit, errors or the Hub's state. That covers the `.p12`, its password, private keys, setup links, fresh-auth codes and tokens. The `.p12` and its password appear in exactly one HTTP answer (`Cache-Control: no-store`, `Pragma: no-cache`). The private key is never stored and can't be downloaded again.
- Identity is the LLDAP username: a certificate's CN is always the username the Hub forwards for the signed-in caller, never a CSR's subject or a value from the client.
- Prefer mature libraries: `go-pkcs12` for PKCS#12, Go's `crypto/x509` / `crypto/ecdsa`, the JDK's `CertificateFactory` / `X509Certificate.verify`, Python `cryptography`, Vault's PKI. No hand-rolled X.509, ASN.1 or user-agent parsing.
- Vanilla JS, everything escaped, data-* attributes plus delegated listeners.
- Go checks (Hub): gofmt go1.27.3 (`$(GOTOOLCHAIN=go1.27.3 go env GOROOT)/bin/gofmt -l .` prints nothing), `go vet ./...`, `go vet -tags harness ./internal/httpapi/...`, and `PORTCULLIS_TEMPLATES_DIR=/Volumes/workspace/portcullis/portcullis-templates go test -race ./...`, which ends `ok` for every package.
- Core checks: `shellcheck -S warning portcullis scripts/lib/*.sh tests/*.sh`, `bash tests/test_cli.sh`, `bash tests/test_shell_libs.sh`, `python3 tests/test_group_gate.py`, `cd enroll && go vet ./... && go test -race ./...`, `cd mcp-gate && go test -race ./...`.
- Keycloak repo checks: `docker build --target test .` (ends `BUILD SUCCESSFUL`), `docker build .`, the vectors check, and the smoke job.
- Core CI on the same-named branch builds the Hub and the Keycloak image from `signin2` (`.github/actions/hub-image`, `.github/actions/keycloak-image`).
- Implementers push and start CI without waiting. Never reformat outside the task.
- Merge order: docs → portcullis-keycloak (wait for `edge`) → hub (wait for `edge`) → core. After that, re-run templates CI.
- Standing OK (2026-11-11): merge each piece to main and upgrade the test server (`ACME_STAGING=true`) once reviews are clean and every CI is green. Still stop for destructive or out-of-plan security-sensitive actions and for EC2 runners.

User rulings for part 2 (binding, 2026-11-11):
- The browser `.p12` password is generated by Portcullis and shown once next to the download, never stored. The private key is never kept.
- Defaults: browser certificate lifetime 30 days (never more than core's `CLIENT_CERT_TTL`), at most 3 active browser certificates per person, sign-in history kept 1 year. The admin can change all three in Hub Settings.
- Help to reset: managers may send a setup link, remove passkeys and revoke certificates, but may NOT reset passwords. Admins may do all of these. Nobody acts on an administrator. Everything is recorded in the person's history and the audit log.
- `browser_cert` can be switched on once part 2 lands and stays off by default.
- `portcullis-x509` tells `pki_int` (YubiKey) certificates from `pki_file` (browser) ones and emits `mtls` or `file` accordingly. `mtls` is only ever emitted for a YubiKey certificate, and a test pins this invariant.
- `enroll.<domain>` stops being a site. Setup links (`/invite/*`) and certificate issuing stay as back-end services. The renewal page moves to the Sign-in page, and the step-up and needs-stronger pages link there.
- Clear names: "Website certificate (HTTPS)", "YubiKey certificate", "Browser certificate", "Internal certificate authority" (admin and troubleshooting only). "Enrol" is used only for adding a sign-in method, and the Hub's "Enroll domain" is renamed.
- Fresh auth (part 1 ruling): `pc_fresh` must be the strongest method of one alternative of the governing compiled rule. On the people listener the governing rule is the `people` core template.

Decisions (made here; the spec leaves them to the builder):
- **D21 Internal certificate authority: `pki_file`.** `pki setup` adds a second intermediate, `pki_file`, signed by the existing `pki` root, with CN `<domain> Browser Certificate CA`, a 43800 h TTL and the same URL and CRL config as `pki_int` (`expiry=72h auto_rebuild=true auto_rebuild_grace_period=12h enable_delta=true delta_rebuild_interval=1m`). Its role `browser-cert` is the `client-cert` role's settings (`allow_any_name`, `enforce_hostnames=false`, `use_csr_common_name=false`, `use_csr_sans=false`, client flag only, `key_type=ec key_bits=256`, `max_ttl=$CLIENT_CERT_TTL`, `no_store=false`), rewritten on every run. Exports:
  - `certs/yubikey-ca.crt` (= `pki_int`'s certificate, a copy of `intermediate-ca.crt`) and `certs/browser-ca.crt`;
  - `certs/ca-chain.crt` = root + `pki_int` + `pki_file`, so Traefik's `protected` / `authaware` options accept both kinds;
  - the truststore gets `portcullis-ca-chain.pem` plus `portcullis-yubikey-ca.pem` and `portcullis-browser-ca.pem`.

  `pki setup` refuses (exit 1) when the two intermediates' CNs are equal: every reader tells the kinds apart by issuer. It creates `pki_file` when it is missing, even while `pki_int` exists (a missing piece, as today). `--force` destroys both CAs. enroll's policy (`vault/policies/enroll.hcl`) adds `pki_file/sign/browser-cert` (update), `pki_file/certs` (list), `pki_file/cert/*` (read), `pki_int/revoke` and `pki_file/revoke` (update), and `pki_int/crl/rotate` and `pki_file/crl/rotate` (read).
- **D22 Issuing a browser certificate (enroll, inside the Vault boundary).** enroll generates an ECDSA P-256 key (`ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`) and builds the CSR itself. It signs through `pki_file/sign/browser-cert` with `common_name=<user>` and `ttl=<days×24>h`, so Vault never sees the key. It encodes the result with `pkcs12.Modern2023.Encode(key, leaf, []*x509.Certificate{browserCA, root}, password)` (AES-256-CBC, PBKDF2-SHA256, SHA-256 MAC). The password is 20 characters from the Crockford base32 alphabet (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`, 100 bits from `crypto/rand`), written as 4 groups of 5 joined by `-`. The answer is returned once. Afterwards enroll clears the DER key, the `.p12` and the password buffers (`clear`), drops the key and logs only `browser certificate <serial> for <user>`. Checks, in this order, serialised by one process-wide mutex:
  - `1 ≤ days ≤ max_days`, and `days × 24 h` ≤ enroll's `CERT_TTL` (else 400);
  - the user exists in LLDAP (else 404);
  - fewer than `max_active` unrevoked, unexpired `pki_file` certificates with that CN (else 409 "you already have <n> browser certificates, the most allowed: revoke one first").

  Filename `<user>-browser-certificate-<YYYYMMDD>.p12`.
- **D23 enroll's internal API** (`:8444`, the invite bearer, JSON, bodies ≤ 64 KiB, `DisallowUnknownFields`; contract §9.4):
  - `POST /internal/browser-certificates` `{"user","days","max_days","max_active"}` → 201 `{"p12": "<std base64>", "password", "serial", "not_after", "filename"}`.
  - `POST /internal/yubikey-certificates` `{"user","csr"}` → 201 `{"certificate": "<PEM>", "serial", "not_after"}`, after `validateCSR` (400 with its text). This is the admin CSR path that replaces `/api/sign`.
  - `POST /internal/yubikey-certificates/renew` `{"user","presented": "<PEM>","csr"}` → 201 (same shape), after `checkRenewal` (403 with its text). It replaces `/api/self/renew`.
  - `POST /internal/certificates/revoke` `{"user","serial"}` → 204. enroll looks the serial up in `pki_int`, then in `pki_file`. When it isn't found, or the certificate's CN isn't `user`: 404. Already revoked: 204. Otherwise it revokes, then rotates that mount's CRL. A failed rotate is still 204: the delta CRL catches up within 2 min, and the failure is logged.
  - `GET /internal/certificates` keeps its fail-closed rules and covers both mounts. Each record gains `"kind": "yubikey" | "browser"` and `"not_before"`, and revoked ones are listed with `revoked: true`.
- **D24 Where the Sign-in page lives.** The page is `GET /signin` on the people listener, served as its own HTML (`web/mysignin.html` + `web/mysignin.js`). It calls only the `/api/me/signin*` routes below, so it works for a session the `people` template wouldn't admit. The people SPA's top nav gets "Sign-in" (→ `/signin`). The people listener's fresh-auth redirect URI becomes `https://people.<domain>/signin`: the page runs the popup callback, and My apps uses the same URI. The `portcullis-fresh-auth` client's redirect URIs are exactly `[https://people.<domain>/signin, https://hub.<domain>/]`, web origins unchanged. **group-gate's Sign-in paths:** on `people.<main domain>` only, when the normalised path (the `path_groups` normaliser) is exactly `/signin`, exactly `/api/me/signin`, under `/api/me/signin/` or under `/static/`, the rule is `{"op":"any","items":[every id in methods]}` (no methods → deny) instead of the `people` template. A path with an encoded `/` or `\`, or one the normaliser refuses, gets the `people` template. Membership checks still run first (`people=*`). The `/api/me/signin*` routes are safe for weaker sessions: anything that adds a method needs a fresh sign-in under the `people` template (D26) or the presented YubiKey certificate. Everything else only reads or removes the caller's own data.
- **D25 The caller's routes** (people listener, caller only, `X-Forwarded-User`, CSRF, the §5.1 common rules and refusal limit):
  - `GET /api/me/signin` → `MySignIn`.
  - `GET /api/me/signin/history?before=<RFC 3339>&limit=<1–100, default 50>` → `HistoryPage`.
  - `POST /api/me/signin/browser-certificates` `{days, code, code_verifier, nonce}` (≤ 8 KiB) → 200 `{p12, password, filename, certificate}`, `no-store`.
  - `DELETE /api/me/signin/certificates/{serial}` → 204. Own browser certificates only; a YubiKey certificate or someone else's serial is 404. No fresh auth: it only removes access.
  - `POST /api/me/signin/yubikey-certificate/renew` `{csr}` → 200 `{certificate, serial, not_after}`. The presented certificate is the `X-Forwarded-Tls-Client-Cert` PEM, which the people router passes (`client-cert-pem@file`). No fresh auth: the TLS session and the CSR's signature both prove possession of the key.
  - `PUT /api/me/signin/password` `{password, code, code_verifier, nonce}` → 204, refused (409) while the password method is off.
  - `DELETE /api/me/signin/password` → 204. LLDAP can't clear a password, so this sets a random 32-byte one nobody sees and drops the Hub's record.

  Own password changes and removals sign the person out of Keycloak, like every password change (§4). They are refused for `admin` and `portcullis-hub` (409, D13's text). Audit actions: `cert.create`, `cert.revoke`, `cert.renew`, `signin.password` (detail `self set` / `self removed`).
- **D26 Fresh auth for adding a certificate.** Creating a browser certificate (self) and issuing a YubiKey certificate (admin) need a proof under the `people` core template (`freshGov` for the people listener). `pc_fresh` must be in `signin.FreshAccepted(peopleRule)` **and** must not be `password` or `browser_cert`: a password or a copied certificate file never mints a new certificate. When that set is empty the answer is 409 "creating a certificate needs a passkey or YubiKey sign-in that people.<domain> accepts". A refused proof is the standard 403 "a fresh sign-in is required", with the reason audited only. Setting your own password needs a proof under the plain `FreshAccepted(peopleRule)`. Add-stronger (D14) doesn't apply separately: the fresh method is already at least as strong as a browser certificate.
- **D27 Limits.** `state.yaml` `sign_in.limits` = `{browser_cert_days: 30, browser_cert_max_active: 3, history_days: 365}`. Bounds:
  - `browser_cert_days`: 1 … the ceiling, where the ceiling is `HUB_CLIENT_CERT_TTL` in whole days (core sets `${CLIENT_CERT_TTL:-720h}`; Vault durations `<n>h|m|s|d`; unset or unparsable means the Hub refuses to start). A stored value above the ceiling applies as the ceiling and Settings shows a warning;
  - `browser_cert_max_active`: 1–20;
  - `history_days`: 30–3650.

  Route `PUT /api/signin/limits` `{browser_cert_days, browser_cert_max_active, history_days}` (Hub listener, admins), shown in `GET /api/signin` as `limits` + `ceiling_days`, audited `signin.limits` with an `old -> new` detail per field. The person picks a lifetime from 1 day up to `browser_cert_days`, and the default is the maximum. Switching `browser_cert` on is no longer refused (`Info.Available` true). Part 1's "aren't available yet" 409 is removed everywhere.
- **D28 Sign-in history.** It is merged at read time from three sources. Nothing new is stored in the Hub.
  - **Keycloak events.** The Hub owns the realm's events config: `PUT /admin/realms/portcullis/events/config` with `eventsEnabled: true`, `enabledEventTypes: ["LOGIN","LOGIN_ERROR"]`, `eventsExpiration: history_days × 86400`, and the existing `eventsListeners` kept. It is re-asserted in the directory sync loop and on a limits change. Core's realm-export sets the same values (365 days), and `keycloak configure` never touches the events config. The extension adds details to the LOGIN event in `portcullis-template`:
    - `pc_kind`: `sign_in`, `step_up` (an SSO session that gained a method in this authentication) or `sso` (cookie only);
    - `pc_methods`: this authentication's new method ids, comma-joined in canonical order;
    - `pc_session`: all of the session's methods;
    - `pc_ua`: the User-Agent, ≤ 256 characters, control characters removed.

    Its password form, `portcullis-x509` and `portcullis-passkey` add `pc_method` (the method tried) and `pc_ua` before a failure. Mapping to history kinds:
    - `LOGIN` with client `portcullis-fresh-auth` → `confirmed`;
    - `LOGIN` with `pc_kind` `sign_in` → `sign_in`; `step_up` → `step_up`;
    - `LOGIN` with `pc_kind` `sso` → `opened <client name>` for clients in `signin-keycloak.json` `clients`, otherwise dropped (group-gate's log covers the gateway's apps);
    - `LOGIN_ERROR` → `failed`, with Keycloak's error mapped to plain text (an unknown error shows as "sign-in failed").
  - **group-gate's "opened" log.** The first allowed request per `(session, host)` seen by a group-gate process appends a line to `group_gate_data/opened/<YYYY-MM-DD>.jsonl` (UTC day, files 0640 group 10001, directory 0750). The line is `{"time","user","session","host","app","methods":[…],"ip","ua","act"}`. `session` is the token's `sid`, else `<user>@<auth_time>`; `ip` is `X-Real-Ip`; `ua` is ≤ 256 characters; `act` is `""` in part 2 (part 3 fills it). Remembered sessions sit in an in-memory LRU of 10 000; a restart may log one more line, and readers dedupe on `(session, host, day)`. A write failure never denies a request: it is logged and counted (`group_gate_opened_log_failures_total`). The Hub mounts the volume read-write only to delete day files older than `history_days`, once a day and after a limits change. It never deletes today's file.
  - **The Hub's audit**, `ForUser(user)`, keeping only `cert.*`, `signin.password`, `user.invite`, `user.remove_passkeys`, `signin.help.*` → `certificate` / `help` entries (`by` = the actor, `detail` without secrets).

  **Entry** `{time, kind, methods, score, app, ip, browser, by, reason, detail}`. `kind` is one of `sign_in`, `step_up`, `failed`, `confirmed`, `opened`, `help`, `certificate` and `impersonation`; the last is reserved for part 3. `score` = `signin.ScoreOfSet(methods)` (an `all` of the methods, D4) or null. `browser` = `useragent.Parse(ua)`'s `Name` + `OS` ("Firefox · macOS"), or "" when unknown. Entries outside `history_days` are never returned. A source that fails is named in `unknown` and the others are still shown.

  **Part-3 hooks:** the `impersonation` kind; the `by` / `reason` fields; the opened log's `act`; the reserved event detail `pc_act`; and `Hub.AddHistorySource(name, signinhistory.Source)`.
- **D29 Telling the certificates apart.**
  - **Keycloak:** `portcullis-signin` holds two ALTERNATIVE `portcullis-x509` executions, first `x509-config` (`portcullis.method=yubikey_cert`, reference `mtls`, `portcullis.ca=/opt/keycloak/conf/truststores/portcullis/portcullis-yubikey-ca.pem`, CRLs `pki_int/crl##pki_int/crl/delta`), then `x509-browser-config` (`browser_cert`, `file`, the browser CA, `pki_file`'s CRLs). An execution steps aside (`attempted`) unless its method is on, `pc_method` allows it, and the presented leaf was issued by its CA: `leaf.getIssuerX500Principal().equals(ca.getSubjectX500Principal())` and `leaf.verify(ca.getPublicKey())`. A missing, unreadable or non-CA `portcullis.ca` file steps aside and is logged at ERROR. On success the execution writes its own method to `portcullis.x509.method`. `keycloak configure` pushes each config by alias.
  - **group-gate:** the leaf's issuer CN in `X-Forwarded-Tls-Client-Cert-Info` is compared with the subject CN of `GATE_YUBIKEY_CA_FILE` and of `GATE_BROWSER_CA_FILE` (read with `cryptography`, cached by mtime). Equal CNs, or a file that is missing or unreadable, means no certificate counts. `yubikey_cert` counts only when `mtls` ∈ amr and a non-revoked `pki_int` leaf with CN = the user is presented on this request. `browser_cert` counts the same way, with `file` and a `pki_file` leaf. The present-certificate page covers both ("<App> needs your <YubiKey|browser> certificate — …"), and a step-up never asks for a certificate method whose amr the session already holds.
  - **Hub:** the inventory maps `kind: yubikey` → `yubikey_cert` and `browser` → `browser_cert`, counting only unexpired, unrevoked records.
- **D30 Revocation.** group-gate reads `GATE_CRL_URLS` and `GATE_DELTA_CRL_URLS` (space-separated; the `pki_int` and `pki_file` full / delta CRLs), and its revoked set is the union of every CRL and the serial file. Keycloak's two x509 configs each check their own CA's CRLs (`crl-abort-if-non-updated` true). `cert sync` writes the union of both mounts' revoked serials. A web revocation rotates the full CRL, so it is enforced within 60 s (group-gate's refresh, Keycloak's `cache-time`). **Revoked shows as revoked everywhere:** the Sign-in page, the person's Sign-in tab, `cert list --all` and the MCP views read `revoked` from D23, and the status is one of `valid`, `expiring` (< `CERT_EXPIRY_WARN_DAYS`, default 7), `expired` or `revoked`. enroll's old certificate list, which showed revoked certificates as "Valid", goes with its site (D31).
- **D31 enroll stops being a site.**
  - **Removed:** the routers `enroll` and `enroll-self`, the `portcullis-self` middleware and group-gate's `/authenticated`, enroll's `/`, `/users`, `/certs`, `/enroll/{u}`, `/api/sign`, `/api/users`, `/self` and `/api/self/renew`, its pages other than `invite.html`, the core page key `enroll` (Hub `CoreSignInKeys`, policy `core`, `group-gate-map.conf`), and the portal links "My client certificate" / "Certificates".
  - **Kept:** `enroll-invite` (`Host(enroll.<d>) && PathPrefix(/invite/)`) and the invite issuer `https://enroll.<d>/invite`. Any other path on that host gets Traefik's 404.
  - **Pointing at the Sign-in page:** the portal's "Sign-in methods" link (`https://people.<d>/signin`), every "Set up …" and "Sign-in methods" link on group-gate's needs-stronger page, and the extension's page (the Keycloak env `PORTCULLIS_SIGNIN_URL`, set by core to `https://people.${PORTCULLIS_DOMAIN}/signin`; unset falls back to the account console).
  - **CLI:** `cert enroll|renew|revoke|list|sync` stay, covering both mounts, with `cert list` showing a KIND column (`YubiKey` / `Browser`). `cert enroll` prints the Sign-in page for renewals.
- **D32 Help to reset** (the spec's "delegated managers of a group the person is in"). Sign-in helpers are configured per group, which makes this scoped delegation:
  - **Setting:** `directory.yaml` `groups.<g>.signin_helpers: <group>`, set by admins on the group page with `PUT /api/directory/groups/{group}/signin-helpers` `{"helpers": "<group>" | ""}` and audited `group.signin_helpers`.
  - **Who is a helper:** a helper of P is a member of `groups[g].signin_helpers` for some group g that P belongs to. A helper group counts as a permission group for §9.6's rules: delegates never target its members, its rules may only use admin-only fields, and it can't be built-in.
  - **What helpers may do:** send a setup link, remove passkeys, revoke certificates. A helper never sets a password or issues a YubiKey certificate.
  - **Who may be helped:** never the helper themselves, a protected account, an administrator (the Hub's administrator set, §9.4) or a member of a permission or helper group (403, the delegate texts). The check runs against a fresh snapshot inside `gate`, like delegated permissions.
  - **Admins:** they keep every action, but the new certificate routes (issue, revoke) refuse administrator targets for everyone (409 "administrators are recovered from the server: ./portcullis cert …"). The existing setup-link, passkey and password routes keep their current rules for administrators.
  - **Setup links:** a helper's setup link skips `checkKeyless` / `created_by` (that is the point of a reset). Core's invite API still refuses protected targets.
  - **Audit:** actions keep their names (`user.invite`, `user.remove_passkeys`, `cert.revoke`), with detail `as signin helper (via <g>)` for a helper.
  - **Person routes** (directory route set, both listeners): `GET /api/directory/users/{u}/signin` → `PersonSignIn` (admins and helpers; anyone else 403), `GET …/{u}/signin/history`, `DELETE …/{u}/certificates/{serial}` (admin or helper; 404 when the serial isn't u's), `POST …/{u}/certificates` `{csr, code, code_verifier, nonce}` (admins only, D26). `POST …/invite` and `…/remove-passkeys` accept helpers.
- **D33 MCP twins and classes.**

  | tool | resource | class |
  |---|---|---|
  | `my_sign_in` (view + the last 20 history entries) | people | R |
  | `my_browser_certificate`, `my_password` (handoffs: "create it on the Sign-in page, `https://people.<d>/signin`"; never a file or password) | people | R |
  | `revoke_my_certificate` `{serial}` | people | W |
  | `person_sign_in` `{user}` | people + admin | R |
  | `revoke_person_certificate` `{user, serial}`, `remove_passkeys` `{user}` | people + admin | D |
  | `issue_yubikey_certificate` (handoff to the person's Sign-in tab) | admin | R |
  | `set_sign_in_helpers` `{group, helpers}` | admin | D when setting / changing, W when clearing |
  | `set_sign_in_limits` | admin | D when `browser_cert_days` or `max_active` go up or `history_days` goes down, else W |

  The YubiKey renewal and both history routes have no twin; `mcp_parity_test.go` lists them with that reason.
- **D34 Clear names.**
  - **"Website certificate (HTTPS)":** Let's Encrypt / the domains service's certificates, Settings → Domains and the docs.
  - **"YubiKey certificate" / "Browser certificate":** every UI, page, CLI and docs mention of a client certificate. "mTLS" stays only in contract internals (amr `mtls`, `auth.method: mtls`).
  - **"Internal certificate authority":** `pki setup` help, `cert` help, the doctor / troubleshooting and docs.
  - **"Enrol":** used only for adding a sign-in method. The Hub's "Enroll domain" button becomes "Add domain", its toasts say "Adding …", MCP `enroll_domain` → `add_domain` and audit `domain.enroll` → `domain.add`. Docs prose "enrolled domain" → "added domain", while the field and term `extra_domains` / "extra-domain host" stay. Go identifiers, the domains API path and core service names stay.

## Review Focus

1. **A browser certificate counting as a YubiKey certificate:** a session with amr `mtls` that presents a `pki_file` leaf with the right CN, the Keycloak YubiKey execution handed a browser leaf, or an inventory record of the wrong kind. Expected: never `yubikey_cert`, never amr `mtls`. Pinned by `test_browser_leaf_never_binds_yubikey` (Task 11), `X509AuthenticatorTest.browserLeafNeverMtls` (Task 2), `TestInventoryCertKinds` (Task 4) and e2e `browser_cert_not_yubikey` (Task 13).
2. **A revoked certificate still working or shown as valid:** a live session with amr `file` keeps opening an app after its certificate is revoked, or the page still says "valid". Expected: 403 within 60 s, and the status reads "revoked" everywhere. Pinned by `test_revoked_browser_cert_denied_by_pki_file_crl` (Task 11), `TestMySignInShowsRevoked` (Task 6) and e2e `browser_cert_revoked` (Task 13).
3. **The `.p12`, its password or the key leaking:** into logs, the audit, an error, a cached answer, or a second download. Expected: only the one 200 answer, with `no-store`. Pinned by `TestBrowserCertSecretsNeverLogged` (Task 10), `TestCreateBrowserCertAnswerNoStore` and `TestCertAuditHasNoSecrets` (Task 6).
4. **A helper acting outside their scope:** on an administrator, on themselves, on a person in none of their groups, resetting a password, issuing a certificate, or right after leaving the helper group. Expected: 403 with nothing changed. Pinned by `TestHelpScope` (Task 7).
5. **A weak session reaching more of people.<domain> than the Sign-in page:** `/signin/../api/directory`, `/api/me/signin%2F..%2Fapps`, `/static/../api/directory`, or the same path on `hub.<d>` or an app host. Expected: the `people` template (or the host's) applies. Pinned by `test_signin_paths_exact_after_normalising` (Task 11) and e2e `signin_page_reachable_weak` (Task 13).

---

### Task 1: Contract and docs (docs repo)

**Files:**
- Modify: `docs/guides/integration-contracts.md`:
  - §1: a "Sign-in methods part 2" bullet (breaking for core, Hub and Keycloak image together; merge order docs → keycloak → hub → core);
  - §4: core host list without `enroll`; group-gate's Sign-in paths (D24); `browser_cert` binding (D29); revocation lists (D30); the opened log (D28);
  - §5: present-certificate page for both kinds; links to the Sign-in page; core routers (no `enroll` / `enroll-self`, the people router on `client-cert-pem@file`);
  - §5.1: the `/signin` page and the D25 routes (the "exactly nine" count updated), fresh-auth redirect `…/signin`;
  - §8: fresh-auth client redirect URIs (D24); the `mtls` invariant rewritten (both CAs exist; D29; its tests named); the Hub's events config ownership (D28);
  - §8.1: the methods table (`browser_cert`: a `pki_file` client certificate, the x509 authenticator, no "not available"); flows (two x509 executions, their configs); the extension's history details and `PORTCULLIS_SIGNIN_URL`; Hub API `PUT /api/signin/limits` and `signin.limits`; D26;
  - §9.4: D23 (endpoints, shapes, errors, `kind`, `not_before`); setup-link URL unchanged;
  - §9.6: sign-in helpers (D32);
  - §9.7: the person routes (D32);
  - §12 prose: "added domain" (D34);
  - a new §8.2 "Sign-in history" (D28 entry schema, sources, retention, part-3 hooks).
- Modify: `docs/operations/auth-policies.md` (sections "The Sign-in page", "Browser certificates", "Help to reset", "Sign-in history", "Limits"), `docs/setup/certificates.md` (three parts by D34 name; `pki_file`; the macOS note below), `docs/operations/cli.md` (`cert` both kinds, `pki setup`), `docs/operations/hub.md` (Settings → Sign-in limits, Add domain, person Sign-in tab, group helpers), `docs/operations/groups.md` (helpers), `docs/architecture.md`, `docs/operations/hardening.md`, `docs/operations/testing.md` (new e2e cases, Task 13), `docs/setup/quickstart.md`, `docs/setup/dns.md`, and every other page `git grep -il 'enroll\|client cert\|mtls'` lists, swept per D34.

**Interfaces:**
- Produces: every shape later tasks implement (D23, D25, D27, D28, D32, D33).

- [ ] **Step 1:** In `wt-signin2/portcullis-docs`, write the sections above, copying every value from D21–D34. Say in the operator pages:
  - a `.p12` imports into Firefox, Chrome / Edge (Windows 10+) and macOS Keychain Access (macOS 14 or newer; the encryption is AES-256);
  - the password is shown once, and Portcullis can't show it again;
  - a revoked certificate stops working within a minute;
  - a helper's setup link hands the account to whoever holds it, so give helper rights only to people you'd trust with the account (the residual risk the ruling accepts).
- [ ] **Step 2:** Check the sweep: `git grep -n -i -E 'enroll\.<|/self\b|client certificate|enroll domain|enrolled domain' docs` prints only setup-link URLs (`enroll.<domain>/invite`) and the `cert enroll` CLI.
- [ ] **Step 3:** Build: `zensical build --strict`. Expected: exit 0, no warnings.
- [ ] **Step 4:** Commit and push: `git add -A docs && git commit -m "contract: sign-in methods part 2 — Sign-in page, browser certificates (pki_file), history, help to reset, enroll retired, clear names" && git push -u origin signin2`.

---

### Task 2: Extension — certificate kinds, history details, Sign-in page links (keycloak)

**Files:**
- Modify: `src/main/java/eu/portcullis/signin/X509Authenticator.java`, `X509AuthenticatorFactory.java` (config properties `portcullis.method`, `portcullis.ca`), `Methods.java` (`UNAVAILABLE` empty), `TemplateAuthenticator.java` (history details; `certificateUser` uses the execution matching the leaf's CA; the needs-stronger links), `CookieAuthenticator.java` (auth note `portcullis.sso`), `PasswordForm.java`, `PasskeyAuthenticator.java` (failure details), `src/main/resources/theme-resources/templates/portcullis-needs-stronger.ftl`, `messages_en.properties` (D34 names)
- Create: `src/main/java/eu/portcullis/signin/CaFile.java`, `History.java`
- Modify: `src/test/resources/smoke-realm.json` (core's new flow, Task 12), `.github/workflows/build.yml` (smoke step "x509 kinds")
- Test: `X509AuthenticatorTest.java`, `X509StepTest.java`, `TemplateAuthenticatorTest.java`, `NeedsStrongerTemplateTest.java`, `CaFileTest.java`, `HistoryTest.java`

**Interfaces:**
- Produces:
  ```java
  final class CaFile { static Optional<X509Certificate> load(String path); } // cached by mtime; a non-CA cert or unreadable = empty
  static boolean X509Authenticator.issuedBy(X509Certificate leaf, X509Certificate ca)
  String X509Authenticator.method(AuthenticatorConfigModel cfg) // "yubikey_cert" | "browser_cert"; anything else → the execution steps aside
  final class History {
    static void onSuccess(AuthenticationFlowContext c, Set<String> thisAuth, Set<String> session, String kind); // pc_kind, pc_methods, pc_session, pc_ua
    static void onFailure(AuthenticationFlowContext c, String method);  // pc_method, pc_ua
    static String ua(AuthenticationFlowContext c);                       // ≤ 256, controls stripped
  }
  String TemplateAuthenticator.signinPage(KeycloakSession s) // PORTCULLIS_SIGNIN_URL, else the account console page
  ```

- [ ] **Step 1: Write the failing tests**
  ```java
  @Test void browserLeafNeverMtls()      // yubikey execution + pki_file leaf → attempted, no note, no amr mtls
  @Test void yubikeyLeafNeverFile()      // browser execution + pki_int leaf → attempted
  @Test void browserLeafSignsInAsFile()  // browser execution, browser_cert on → success, note portcullis.x509.method = browser_cert
  @Test void caFileMissingStepsAside()   // portcullis.ca unreadable → attempted, ERROR logged naming portcullis
  @Test void unknownMethodConfigStepsAside() // portcullis.method "mtls" → attempted
  @Test void issuedByChecksSignatureNotJustName() // a leaf whose issuer DN equals the CA's but signed by another key → false
  // TemplateAuthenticatorTest
  @Test void loginEventCarriesHistoryDetails() // pc_kind sign_in, pc_methods "security_key", pc_session, pc_ua
  @Test void ssoReuseIsSso()                   // auth-cookie only → pc_kind sso, pc_methods ""
  @Test void stepUpKind()                      // SSO session + new method → step_up, pc_methods = the new one
  @Test void uaTruncatedAndCleaned()           // 300 chars with \n → 256, no control chars
  @Test void needsStrongerLinksToSigninPage()  // env set → every "Set up …" and "Sign-in methods" href == it
  // PasswordFormTest: wrongPasswordEventHasMethodAndUa()   // LOGIN_ERROR details pc_method=password, pc_ua
  // FreshMapperTest: browserCertFreshIsBrowserCert()        // pc_fresh browser_cert (the Hub refuses it for certificates, D26)
  ```
- [ ] **Step 2: Run them to see them fail.** Run `docker build --target test .`. Expected: FAIL (compile errors / assertions).
- [ ] **Step 3: Implement** the classes with the interfaces above. `issuedBy` uses only the JDK (`getIssuerX500Principal().equals`, `verify`). Remove `browser_cert` from `UNAVAILABLE`. The page copy uses the D34 names.
- [ ] **Step 3b:** The "Compare the smoke realm with core's flows" job compares against core's `signin2` realm-export, which Task 12 writes: it fails until Task 12 is pushed, then re-run it.
- [ ] **Step 4: Smoke step "x509 kinds"** in `build.yml`: issue one leaf from a test "YubiKey CA" and one from a test "Browser CA" (openssl in the job), mount both CA PEMs at the `portcullis.ca` paths and post each through the `traefik` lookup header on the smoke realm's browser flow. Expected: the YubiKey leaf's token amr ∋ `mtls` ∌ `file`; the browser leaf's ∋ `file` ∌ `mtls`; with `browser_cert` off the browser leaf doesn't sign in.
- [ ] **Step 5: Run them to see them pass.** Run `docker build --target test . && docker build .`, push, and check the smoke job. Expected: `BUILD SUCCESSFUL`, smoke green.
- [ ] **Step 6: Commit and push.** `git commit -am "x509: tell YubiKey (pki_int) from browser (pki_file) certificates — mtls vs file; history event details; links to the Sign-in page" && git push -u origin signin2`.

---

### Task 3: Limits, the browser-certificate switch, Keycloak events config, core keys (hub)

**Files:**
- Modify: `internal/state/signin.go` (`SignIn.Limits`, `CoreSignInKeys` without `enroll`, `EnsureSignIn` defaults), `internal/signin/methods.go` (`browser_cert` `Available: true`), `internal/signin/score.go` (`ScoreOfSet`), `internal/hub/signin.go` / `signin_class.go` (the 409 gone; `SetSignInLimits`), `internal/keycloak/events.go` (create), `internal/hub/directory.go` (`RunDirectorySync` re-asserts the events config), `cmd/hub/main.go` (`HUB_CLIENT_CERT_TTL`), `internal/httpapi/signin.go` + `mcptools_signin.go` (`PUT /api/signin/limits`, `set_sign_in_limits`), `mcp_parity_test.go`, `internal/signinreset` (`browser_cert` still off on reset)
- Test: `internal/state/state_test.go`, `internal/signin/signin_test.go`, `internal/hub/signin_limits_test.go`, `internal/keycloak/events_test.go`, `internal/httpapi/signin_test.go`, `cmd/hub/main_test.go`

**Interfaces:**
- Produces:
  ```go
  type SignInLimits struct{ BrowserCertDays, BrowserCertMaxActive, HistoryDays int } // yaml browser_cert_days, browser_cert_max_active, history_days
  func signin.ScoreOfSet(ms []Method) *Score            // nil for none; all[ms…] by D4
  type LimitsView struct{ Limits state.SignInLimits; CeilingDays int; Effective state.SignInLimits; Warning string }
  func (h *Hub) SignInLimits() LimitsView
  func (h *Hub) SetSignInLimits(ctx context.Context, in state.SignInLimits, actor directory.Actor) (*LimitsView, error)
  func (c *keycloak.Client) EnsureEventsConfig(ctx context.Context, historyDays int) error
  func (h *Hub) SetEventsConfig(ensure func(ctx context.Context, days int) error) // wired in main; run by the sync loop
  Config.ClientCertTTL time.Duration // HUB_CLIENT_CERT_TTL
  ```

- [ ] **Step 1: Write the failing tests**
  ```go
  func TestEnsureSignInLimitsDefaults(t *testing.T) // 30, 3, 365; CoreSignInKeys has no "enroll"
  func TestBrowserCertCanBeSwitchedOn(t *testing.T) // SetMethod(browser_cert, true) OK, audited signin.method; Standard compiles with it
  func TestScoreOfSet(t *testing.T)                 // [security_key] "3.5 / 5"; [browser_cert, security_key] "3.9 / 5"; [] nil
  func TestSetSignInLimitsBounds(t *testing.T)      // days 0 / ceiling+1 → 400; max 21 → 400; history 29 / 3651 → 400; audit "browser_cert_days 30 -> 10"
  func TestLimitsAboveCeilingApplyAsCeiling(t *testing.T) // stored 60, ceiling 30 → Effective 30, Warning non-empty
  func TestSetLimitsReassertsEvents(t *testing.T)   // history_days 90 → ensure called with 90
  func TestEnsureEventsConfigKeepsListeners(t *testing.T) // GET listeners [jboss-logging,x] → PUT same listeners, types [LOGIN LOGIN_ERROR], expiration 90*86400
  func TestHubRefusesBadClientCertTTL(t *testing.T) // unset / "abc" → start refused
  func TestSignInLimitsToolClass(t *testing.T)      // days up → D; history down → D; max down → W
  func TestAccessFlowCopiesBothX509Executions(t *testing.T) // the realm flow with two portcullis-x509 executions is copied with both configs
  ```
- [ ] **Step 2: Run them to see them fail.** Run `go test ./internal/state/ ./internal/signin/ ./internal/hub/ ./internal/keycloak/ ./internal/httpapi/ ./cmd/hub/ -run 'Limits|BrowserCert|ScoreOfSet|Events|ClientCertTTL|BothX509'`. Expected: FAIL.
- [ ] **Step 3: Implement** per D27 and D28 (events config) with the interfaces above.
- [ ] **Step 4: Run them to see them pass.** Run the same command, then the full Go checks. Expected: `ok`.
- [ ] **Step 5: Commit and push.** `git commit -am "signin: browser certificates can be switched on; limits; the Hub owns Keycloak's events config; no enroll core page" && git push -u origin signin2`.

---

### Task 4: enroll client and inventory — certificate kinds and actions (hub)

**Files:**
- Modify: `internal/invite/invite.go` (+ `certs.go`), `internal/hub/signin_people.go` (kinds)
- Test: `internal/invite/invite_test.go`, `internal/hub/signin_people_test.go`

**Interfaces:**
- Produces:
  ```go
  type CertKind string // "yubikey" | "browser"; anything else drops the record (logged)
  type CertRecord struct{ User, Serial string; Kind CertKind; NotBefore, NotAfter time.Time; Revoked bool }
  type BrowserCertRequest struct{ User string; Days, MaxDays, MaxActive int }
  type BrowserCert struct{ D32 []byte; Password, Serial, Filename string; NotAfter time.Time }
  type IssuedCert struct{ PEM, Serial string; NotAfter time.Time }
  func (c *Client) CreateBrowserCertificate(ctx context.Context, r BrowserCertRequest) (*BrowserCert, error)
  func (c *Client) IssueYubiKeyCertificate(ctx context.Context, user, csrPEM string) (*IssuedCert, error)
  func (c *Client) RenewYubiKeyCertificate(ctx context.Context, user, presentedPEM, csrPEM string) (*IssuedCert, error)
  func (c *Client) RevokeCertificate(ctx context.Context, user, serial string) error
  ```
  Non-2xx answers are `*APIError{Status, Msg}` (Msg ≤ 200 characters, never echoing a request body). Bodies ≤ 1 MiB. `D32` and `Password` are never in an error or a `String()`.

- [ ] **Step 1: Write the failing tests**
  ```go
  func TestCreateBrowserCertificateShape(t *testing.T) // fake enroll: request JSON exact, bearer; 201 decoded, D32 = base64-decoded bytes
  func TestCertificateActionsPassStatus(t *testing.T)  // 400/403/404/409 → APIError with that status and text; 503 → error
  func TestCertificatesKinds(t *testing.T)            // kind yubikey/browser kept, "other" dropped, not_before parsed
  func TestInventoryCertKinds(t *testing.T)           // yubikey → yubikey_cert, browser → browser_cert, revoked / expired → neither
  func TestBrowserCertNoSecretInErrors(t *testing.T)  // a decode failure after 201 never quotes the body
  ```
- [ ] **Step 2: Run them to see them fail.** Run `go test ./internal/invite/ ./internal/hub/ -run 'BrowserCert|CertificateActions|CertificatesKinds|InventoryCertKinds'`. Expected: FAIL.
- [ ] **Step 3: Implement.** The action URLs derive from the invites URL's directory, like `certificatesURL`.
- [ ] **Step 4: Run them to see them pass.** Same command. Expected: `ok`.
- [ ] **Step 5: Commit and push.** `git commit -am "invite: enroll's certificate actions and kinds; inventory counts browser certificates" && git push`.

---

### Task 5: Sign-in history (hub)

**Files:**
- Create: `internal/signinhistory/entry.go`, `keycloak.go`, `opened.go`, `audit.go`, `merge.go`, `internal/hub/signin_history.go`
- Modify: `internal/keycloak/events.go` (`LoginEvents`), `go.mod` / `go.sum` (`github.com/mileusna/useragent`, latest stable), `cmd/hub/main.go` (`HUB_GROUP_GATE_DATA_DIR`, default `/group-gate-data`; `go h.RunHistoryPrune(ctx, 24*time.Hour)`)
- Test: `internal/signinhistory/*_test.go`, `internal/hub/signin_history_test.go`, `internal/keycloak/events_test.go`

**Interfaces:**
- Consumes: Task 3 (`ScoreOfSet`, `HistoryDays`).
- Produces:
  ```go
  type Kind string // sign_in step_up failed confirmed opened help certificate impersonation
  type Entry struct {
    Time time.Time `json:"time"`; Kind Kind `json:"kind"`; Methods []signin.Method `json:"methods"`
    Score *signin.Score `json:"score"`; App, IP, Browser, By, Reason, Detail string // json snake_case
  }
  type Source interface{ Entries(ctx context.Context, user string, since, before time.Time, limit int) ([]Entry, error) }
  func FromEvent(ev keycloak.Event, clientNames map[string]string) (Entry, bool)
  func FromAudit(e directory.AuditEntry) (Entry, bool)
  type OpenedLog struct{ Dir string; Now func() time.Time }
  func (l OpenedLog) Entries(ctx context.Context, user string, since, before time.Time, limit int) ([]Entry, error)
  func (l OpenedLog) Prune(days int) (removed int, err error) // day files only, never today's
  func Merge(limit int, lists ...[]Entry) []Entry             // newest first, stable
  func Browser(ua string) string
  // keycloak
  type Event struct{ Time time.Time; Type, ClientID, UserID, IP, Error string; Details map[string]string }
  func (c *Client) LoginEvents(ctx context.Context, userID string, from, to time.Time, max int) ([]Event, error)
  // hub
  type HistoryPage struct{ Entries []signinhistory.Entry `json:"entries"`; Next string `json:"next"`; Unknown []string `json:"unknown"` }
  func (h *Hub) SignInHistory(ctx context.Context, user string, before time.Time, limit int) (*HistoryPage, error)
  func (h *Hub) AddHistorySource(name string, s signinhistory.Source) // part 3 hook
  func (h *Hub) RunHistoryPrune(ctx context.Context, every time.Duration)
  ```
  `Next` is the oldest returned entry's time (RFC 3339 nano), or `""` at the end. A source's own read is capped at `limit+1`. The opened log reads at most the newest 8 MiB per day file and skips torn lines.

- [ ] **Step 1: Write the failing tests**
  ```go
  func TestFromEventKinds(t *testing.T) // LOGIN pc_kind sign_in pc_methods "security_key" → sign_in, [security_key], score 3.5;
  //  step_up; sso for a listed native client → opened "Nextcloud"; sso for portcullis-forward-auth → dropped;
  //  client portcullis-fresh-auth → confirmed; LOGIN_ERROR invalid_user_credentials pc_method password →
  //  failed "wrong password", [password]; unknown error → "sign-in failed"; unknown pc_methods value → dropped from Methods
  func TestOpenedLogDedupeAndUser(t *testing.T) // two lines same (session, host, day) → one; other users' lines never returned
  func TestOpenedLogPruneKeepsToday(t *testing.T) // days 30: a 31-day-old file removed, today's kept even with days 0 passed in
  func TestFromAuditOnlyListedActions(t *testing.T) // cert.create → certificate; user.remove_passkeys by bob → help By "bob"; group.add → dropped
  func TestMergeOrderAndLimit(t *testing.T)
  func TestHistoryRetention(t *testing.T)   // an entry older than history_days from any source is never returned
  func TestHistoryUnknownSource(t *testing.T) // Keycloak 500 → Unknown ["keycloak"], opened + audit still shown
  func TestBrowserName(t *testing.T)        // Firefox UA on macOS → "Firefox · macOS"; "" → ""
  func TestAddHistorySource(t *testing.T)   // an added source's entries merged; its failure named in Unknown
  ```
- [ ] **Step 2: Run them to see them fail.** Run `go test ./internal/signinhistory/ ./internal/hub/ ./internal/keycloak/ -run 'Event|Opened|Audit|Merge|History|Browser'`. Expected: FAIL.
- [ ] **Step 3: Implement** per D28. Keycloak's error → text table: `invalid_user_credentials` "wrong password", `user_not_found` "unknown account", `user_disabled` "account disabled", `user_temporarily_disabled` "too many attempts: wait", `invalid_user_certificate`/`certificate_*` "certificate refused", `different_user_authenticated` "another person's certificate", `access_denied` "access denied".
- [ ] **Step 4: Run them to see them pass.** Same command, then the full Go checks. Expected: `ok`.
- [ ] **Step 5: Commit and push.** `git commit -am "history: Keycloak sign-in events, group-gate's opened log and the audit, merged per person; retention; part-3 source hook" && git push`.

---

### Task 6: The Sign-in page service, the caller's routes and MCP twins (hub)

**Files:**
- Create: `internal/hub/mysignin.go`, `internal/hub/certificates.go`, `internal/httpapi/mysignin.go`, `internal/httpapi/mcptools_mysignin.go`
- Modify: `internal/httpapi/server.go` (`peopleMux`: `GET /signin` + D25 routes), `people_test.go` (the people listener allowlist), `mcp_parity_test.go`, `internal/directory/service.go` (`SetOwnPassword`, `RemoveOwnPassword`)
- Test: `internal/hub/mysignin_test.go`, `internal/hub/certificates_test.go`, `internal/httpapi/mysignin_test.go`, `internal/httpapi/mcptools_mysignin_test.go`

**Interfaces:**
- Consumes: Tasks 3–5; `checkFreshAuthOn` + `freshGov` from `fresh-template`.
- Produces:
  ```go
  type MySignIn struct {
    User string; Methods []MethodRow; Certificates []CertRow; Apps []AppNeed
    Limits LimitsView; ActiveBrowserCerts int; AddStronger bool; FreshAuth *freshauth.AuthorizeInfo
  }
  type MethodRow struct{ ID signin.Method; Label string; On bool; State string /* set|none|unknown|off */; Passkeys []PasskeyRow; PasswordSetAt *time.Time }
  type PasskeyRow struct{ Label string; Kind signin.Method; CreatedAt time.Time }
  type CertRow struct{ Serial, Kind, Status string /* valid|expiring|expired|revoked */; NotBefore, NotAfter time.Time }
  type AppNeed struct{ Kind /* instance|core */, ID, Name, Template, TemplateName string; Score signin.Score; OK *bool }
  func (h *Hub) MySignInView(ctx context.Context, user string) (*MySignIn, error)
  func (h *Hub) CreateBrowserCertificate(ctx context.Context, user string, days int, p freshauth.Proof) (*invite.BrowserCert, error)
  func (h *Hub) RevokeOwnBrowserCertificate(ctx context.Context, user, serial string) error
  func (h *Hub) RenewYubiKeyCertificate(ctx context.Context, user, presentedPEM, csrPEM string) (*invite.IssuedCert, error)
  func (h *Hub) SetOwnPassword(ctx context.Context, user, password string, p freshauth.Proof) error
  func (h *Hub) RemoveOwnPassword(ctx context.Context, user string) error
  func certFreshAllowed(peopleRule signin.Node, on map[signin.Method]bool) []signin.Method // D26: FreshAccepted minus password, browser_cert
  ```
  The rules each piece follows:
  - **Methods:** only switched-on methods are listed with their state, and a switched-off one is `State: "off"` ("off on this server").
  - **Apps:** every enabled instance whose population includes the user, plus the core pages `people` (everyone) and `hub` (admins). `OK` is nil while the inventory doesn't know the person.
  - **Certificate status:** `expiring` when fewer than 7 days are left.
  - **One create at a time:** `CreateBrowserCertificate` takes a per-user lock and passes `Days`, `MaxDays` = effective `browser_cert_days` and `MaxActive` to enroll.

- [ ] **Step 1: Write the failing tests**
  ```go
  func TestMySignInListsOnlyOnMethods(t *testing.T) // password off → its row State "off"; browser_cert on → listed with certs
  func TestMySignInShowsRevoked(t *testing.T)       // enroll record revoked → CertRow.Status "revoked"; expired → "expired"; 5 days left → "expiring"
  func TestMySignInApps(t *testing.T)               // gitea on standard, person has security_key → OK true; strong core hub only for admins
  func TestCreateBrowserCertFreshRules(t *testing.T) // people on strong: pc_fresh security_key OK; passkey_synced 403;
  //  password 403; browser_cert 403 even when people's template is any[browser_cert, security_key];
  //  people on any[password] → 409 "creating a certificate needs …" before any proof is spent
  func TestCreateBrowserCertPassesLimits(t *testing.T) // days 0 / > effective → 400 before enroll; enroll gets MaxDays/MaxActive
  func TestCreateBrowserCertOffRefused(t *testing.T)   // browser_cert off → 409, enroll not called
  func TestCertAuditHasNoSecrets(t *testing.T)         // cert.create detail "browser <serial> until <date>", no password / base64
  func TestRevokeOwnOnlyBrowser(t *testing.T)          // own yubikey serial → 404; another's serial → 404; own browser → enroll revoke, audit cert.revoke
  func TestRenewUsesPresentedCert(t *testing.T)        // no X-Forwarded-Tls-Client-Cert → 403 "present your current YubiKey certificate"
  func TestOwnPasswordRules(t *testing.T)              // method off → 409; CheckPassword failures → 400; admin → 409; record set_by self; sign-out called
  // httpapi
  func TestCreateBrowserCertAnswerNoStore(t *testing.T) // 200 headers Cache-Control no-store, Pragma no-cache; body has p12, password, filename
  func TestMySignInRoutesCallerOnly(t *testing.T)       // no X-Forwarded-User 401; no username in any path; Hub listener 404
  func TestPeopleListenerHasNoAppRoutes(t *testing.T)   // existing test, allowlist updated with the D25 routes and GET /signin
  func TestMySignInToolClasses(t *testing.T)            // my_sign_in R, revoke_my_certificate W, handoffs R and carry no secret
  ```
- [ ] **Step 2: Run them to see them fail.** Run `go test ./internal/hub/ ./internal/httpapi/ ./internal/directory/ -run 'MySignIn|BrowserCert|CertAudit|RevokeOwn|Renew|OwnPassword|PeopleListener|ToolClasses'`. Expected: FAIL.
- [ ] **Step 3: Implement** per D24–D26. `GET /signin` serves `mysignin.html` (Task 8 adds the file; an embedded placeholder is enough to pass Task 6's route tests).
- [ ] **Step 4: Run them to see them pass.** Same command, then `go vet -tags harness ./internal/httpapi/...` and the full Go checks. Expected: `ok`.
- [ ] **Step 5: Commit and push.** `git commit -am "people: the Sign-in page's API — methods, certificates, apps and what they need; browser certificates; renewal; own password" && git push`.

---

### Task 7: Help to reset — sign-in helpers and the person's Sign-in routes (hub)

**Files:**
- Modify: `internal/directory/store.go` (`GroupConfig.SigninHelpers`), `authz.go` (`permHelp`, `CheckHelp`, helper groups count as permission groups), `service.go` (`SetSigninHelpers`; `SendInvite` / `RemovePasskeys` accept helpers), `groups.go` (rule restrictions), `view.go` (group view shows helpers to admins)
- Create: `internal/hub/signin_help.go`, `internal/httpapi/signin_help.go`, `internal/httpapi/mcptools_signin_help.go`
- Modify: `internal/httpapi/directory.go` (routes), `mcp_parity_test.go`
- Test: `internal/directory/help_test.go`, `internal/hub/signin_help_test.go`, `internal/httpapi/signin_help_test.go`

**Interfaces:**
- Consumes: Tasks 4–6.
- Produces:
  ```go
  func (s *Service) SetSigninHelpers(ctx context.Context, c *Caller, group, helpers string) (*Result, error) // admins; audit group.signin_helpers
  func (s *Service) CheckHelp(ctx context.Context, c *Caller, target string) (via string, err error)        // "" for admins, else the group g
  type PersonSignIn struct{ MySignIn; Can HelpCan }
  type HelpCan struct{ SetupLink, RemovePasskeys, Revoke, Issue, Password bool }
  func (h *Hub) PersonSignInView(ctx context.Context, c *directory.Caller, user string) (*PersonSignIn, error)
  func (h *Hub) RevokePersonCertificate(ctx context.Context, c *directory.Caller, user, serial string) error
  func (h *Hub) IssueYubiKeyCertificate(ctx context.Context, c *directory.Caller, user, csrPEM string, p freshauth.Proof) (*invite.IssuedCert, error)
  ```

- [ ] **Step 1: Write the failing tests**
  ```go
  func TestHelpScope(t *testing.T) // helpers group "hr" on group "milan"; bob ∈ hr, alice ∈ milan:
  //  bob → alice: invite OK (alice has passkeys: no keyless refusal), remove passkeys OK, revoke OK (detail "as signin helper (via milan)");
  //  bob → alice password 403; bob → alice issue 403; bob → carol (not in milan) 403; bob → bob 403;
  //  bob → root (lldap_admin ∈ milan) 403; bob → a member of hr 403; bob removed from hr → next call 403 (fresh snapshot)
  func TestAdminCertificateTargets(t *testing.T) // admin revoke / issue on another administrator → 409; on alice OK
  func TestHelperGroupRules(t *testing.T)   // a helper group can't be built-in; its rule on a non-admin-only field → 409
  func TestPersonSignInView(t *testing.T)   // admin: Can all true for alice, Issue false for an administrator;
  //  helper: Password false, Issue false; anyone else 403; history route the same rule
  func TestIssueYubiKeyFresh(t *testing.T)  // D26 rules as for browser certificates; enroll 400 CSR text passed through
  func TestHelpToolClasses(t *testing.T)    // revoke_person_certificate D, remove_passkeys D, set_sign_in_helpers set → D / clear → W
  ```
- [ ] **Step 2: Run them to see them fail.** Run `go test ./internal/directory/ ./internal/hub/ ./internal/httpapi/ -run 'Help|AdminCertificateTargets|HelperGroup|PersonSignIn|IssueYubiKey'`. Expected: FAIL.
- [ ] **Step 3: Implement** per D32. `permHelp` is never grantable through `Permissions`. `gate` resolves it against the snapshot: an admin, or a member of `signin_helpers` of one of the target's groups, then `checkDelegateTarget`, with helper groups added to its permission-group check.
- [ ] **Step 4: Run them to see them pass.** Same command, then the full Go checks. Expected: `ok`.
- [ ] **Step 5: Commit and push.** `git commit -am "people: help to reset — sign-in helpers per group, the person's Sign-in tab API, certificate issue and revoke" && git push`.

---

### Task 8: Hub UI — the Sign-in page, the person's Sign-in tab, limits, helpers, clear names (hub)

**Files:**
- Create: `web/mysignin.html`, `web/mysignin.js`
- Modify: `web/people.html` / `web/directory.js` (top nav "Sign-in" → `/signin`; person page tab "Sign-in"; group page "Sign-in helpers" picker, admins), `web/signin.js` (Settings → Sign-in: browser certificates and history limits; "available" note gone), `web/index.html` (Add domain, D34 copy), `web/freshauth.js` / `web/freshauth-callback.js` (people redirect `…/signin`), `internal/keycloak/freshauth.go` (`EnsureFreshAuthClient`: redirect URIs per D24), `internal/httpapi/mcptools_admin2.go` (`add_domain`), `internal/hub/domains.go` (audit `domain.add`), `web/docs/*` (`PORTCULLIS_DOCS_DIR=/Volumes/workspace/portcullis/wt-signin2/portcullis-docs go generate ./web`)
- Test: `internal/httpapi/webui_mysignin_test.go`, `webui_signin_test.go`, `webui_people_links_test.go`, `internal/keycloak/freshauth_test.go`, `web/web_test.go`

**Interfaces:**
- Consumes: the routes of Tasks 3, 5–7.

The page follows mockup sections 1 and 3:
- **Each method row:** password (set / Change / Remove); passkeys and security keys (list with kind and date, "+ Add" → the account console's signing-in page); YubiKey certificate (validity, Renew: the `ykman` CSR commands from enroll's old page, then paste); browser certificate (list, Create → days field (default and max = the limit) → fresh-auth popup → the download button and the password side by side, with "This password is shown only now" and Copy); "off on this server" for switched-off methods.
- **Below the methods:** "Apps and what they need" (✓ / ✗ / ?), and Sign-in history (newest first, "Show older" via `next`, a line naming any `unknown` source).
- **Person tab (admin / helper):** the same rows, with only the actions `Can` allows.
- **Downloading:** the `.p12` downloads through a `Blob` URL that is revoked right after the click. The password and the bytes live only in that dialog's closure and are dropped when it closes. Nothing goes to `localStorage` / `sessionStorage` other than the fresh-auth state.

- [ ] **Step 1: Write the failing tests** (node, from the served pages)
  ```go
  func TestMySignInPageRendersMockupRows(t *testing.T) // fixture MySignIn → rows in method order, "off on this server", ✓/✗/?
  func TestMySignInDownloadDialog(t *testing.T)        // after a create: one download link (blob:), password shown once, gone after close
  func TestMySignInEscapes(t *testing.T)               // a passkey label "<img onerror>" and a history UA rendered as text
  func TestPersonSignInTabActions(t *testing.T)        // Can{Revoke:true} → Revoke buttons only; no "Reset password" for helpers
  func TestSettingsLimitsForm(t *testing.T)            // ceiling shown; out-of-range refused client-side with the server's bounds
  func TestNoEnrollWording(t *testing.T)               // served Hub and people pages contain no "Enroll domain", "enroll.", "/self", "client certificate"
  func TestFreshAuthClientRedirects(t *testing.T)      // exactly [https://people.<d>/signin, https://hub.<d>/]
  func TestDocsCopiesInSync(t *testing.T)              // existing, with PORTCULLIS_DOCS_DIR set to the docs worktree
  ```
- [ ] **Step 2: Run them to see them fail.** Run `go test ./internal/httpapi/ ./internal/keycloak/ ./web/ -run 'MySignIn|PersonSignInTab|SettingsLimits|NoEnrollWording|FreshAuthClientRedirects|DocsCopies'`. Expected: FAIL.
- [ ] **Step 3: Implement** the pages and the D34 sweep in the Hub's UI and MCP texts. Regenerate `web/docs`.
- [ ] **Step 4: Run them to see them pass.** Same command, then the full Go checks. Expected: `ok`.
- [ ] **Step 5: Commit and push.** `git commit -am "web: the Sign-in page and the person's Sign-in tab; limits and helpers; Add domain and the clear certificate names" && git push`.

---

### Task 9: Internal certificate authority — `pki_file`, Vault policy, `cert` CLI (core)

**Files:**
- Modify: `scripts/lib/pki.sh` (D21), `vault/policies/enroll.hcl` (D21), `scripts/lib/certs.sh` (both mounts: `_cert_info <mount> <serial>`, `cert list` KIND, `cert revoke` finds the mount and rotates its CRL, `write_revoked_serials` union of `pki_int/certs/revoked` and `pki_file/certs/revoked`, each failure leaves the file unchanged; the help texts use D34 names), `portcullis` (help)
- Test: `tests/test_cli.sh`, `tests/test_shell_libs.sh`

**Interfaces:**
- Produces: `certs/browser-ca.crt`, `certs/yubikey-ca.crt`, the truststore files of D21, role `pki_file/roles/browser-cert`, the enroll policy paths.

- [ ] **Step 1: Write the failing tests** (stubbed `vault`, as the existing pki tests do)
  - `test_shell_libs.sh`:
    - `pki_setup on a fresh Vault enables pki, pki_int, pki_file; ca-chain.crt has 3 certificates in order root, pki_int, pki_file`
    - `pki_setup with pki_int present but no pki_file creates pki_file only and keeps pki_int`
    - `pki_setup refuses when the two intermediates' CNs are equal`
    - `browser-cert role written with client_flag=true server_flag=false use_csr_common_name=false max_ttl=$CLIENT_CERT_TTL`
    - `pki_file CRL configured auto_rebuild=true enable_delta=true delta_rebuild_interval=1m`
    - `truststore has portcullis-yubikey-ca.pem and portcullis-browser-ca.pem`
    - `write_revoked_serials writes the union of both mounts; a failing pki_file list leaves the file unchanged`
  - `test_cli.sh`:
    - `enroll.hcl grants exactly the D21 paths (sign/client-cert, sign/browser-cert, certs list, cert read, revoke, crl/rotate on both mounts) and nothing else`
    - `cert list --all prints KIND YubiKey / Browser and revoked rows`
    - `cert revoke <pki_file serial> revokes on pki_file and rotates pki_file's CRL`
    - `cert enroll's renewal hint names https://people.<domain>/signin`
- [ ] **Step 2: Run them to see them fail.** Run `bash tests/test_shell_libs.sh; bash tests/test_cli.sh`. Expected: FAIL on the new cases.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them to see them pass.** Run the same commands plus `shellcheck -S warning portcullis scripts/lib/*.sh tests/*.sh`. Expected: all pass, no shellcheck output.
- [ ] **Step 5: Commit and push.** `git commit -am "pki: a separate CA for browser certificates (pki_file); cert CLI covers both kinds" && git push -u origin signin2`.

---

### Task 10: enroll — browser certificates, YubiKey issue / renew / revoke, site retired (core)

**Files:**
- Create: `enroll/browsercert.go`, `enroll/certapi.go`
- Modify: `enroll/main.go` (routes: the public mux keeps only `/invite/*` and `/healthz`; `issuedCertsWith` over both mounts with `kind`, `not_before`), `enroll/self.go` (`checkRenewal` and `lookupIssued` kept, handlers gone), `enroll/invite.go` (`apiHandler` registers D23), `enroll/go.mod` / `go.sum` (`software.sslmate.com/src/go-pkcs12` latest stable)
- Delete: `enroll/web/index.html`, `users.html`, `certs.html`, `enroll.html`, `self.html`
- Test: `enroll/browsercert_test.go`, `enroll/certapi_test.go`, `enroll/main_test.go`, `enroll/self_test.go`

**Interfaces:**
- Consumes: Task 9's role and policy.
- Produces: D23's endpoints;
  ```go
  func newBrowserPassword() (string, error) // "XXXXX-XXXXX-XXXXX-XXXXX", Crockford base32
  func (cfg *Config) issueBrowserCert(ctx context.Context, user string, days, maxDays, maxActive int) (*browserCertResult, error)
  type browserCertResult struct{ D32 []byte; Password, Serial, Filename string; NotAfter time.Time }
  func (cfg *Config) revokeCert(ctx context.Context, user, serial string) error
  func certKind(mount string) string // "pki_int" → "yubikey", "pki_file" → "browser"
  ```

- [ ] **Step 1: Write the failing tests** (a fake Vault `httptest` server, as `vault_auth_test.go` does)
  ```go
  func TestBrowserCertP12Decodes(t *testing.T) // pkcs12.DecodeChain(p12, password) → EC P-256 key matching the leaf;
  //  leaf CN == user, issuer == the browser CA, chain [browser CA, root]; signed via pki_file/sign/browser-cert, ttl "720h" for 30 days
  func TestBrowserCertPasswordShape(t *testing.T)  // matches ^[0-9A-HJKMNP-TV-Z]{5}(-[0-9A-HJKMNP-TV-Z]{5}){3}$; 1000 draws distinct
  func TestBrowserCertTTLCeiling(t *testing.T)     // days 31 with max_days 30 → 400; days 31 with CERT_TTL 720h → 400; days 0 → 400
  func TestBrowserCertMaxActive(t *testing.T)      // 3 active (1 revoked + 1 expired not counted) → 4th 409 with the D22 text
  func TestBrowserCertMaxActiveConcurrent(t *testing.T) // 10 parallel creates with max 3 → exactly 3 succeed
  func TestBrowserCertSecretsNeverLogged(t *testing.T)  // log output holds the serial and user, never the password or any base64 of the p12/key
  func TestCertAPINeedsBearer(t *testing.T)        // every D23 route 401 without / with a wrong bearer
  func TestCertAPIStrictBodies(t *testing.T)       // unknown field, trailing data, > 64 KiB → 400 / 413
  func TestYubiKeyIssueValidatesCSR(t *testing.T)  // CSR CN ≠ user → 400; good CSR → signed on pki_int/sign/client-cert with common_name user
  func TestRenewChecksPresented(t *testing.T)      // checkRenewal cases moved from self_test; the presented PEM comes from the body
  func TestRevokeFindsMountAndOwner(t *testing.T)  // pki_file serial of alice by user alice → revoke + pki_file/crl/rotate;
  //  by user bob → 404; unknown → 404; already revoked → 204, no second revoke
  func TestCertificatesBothMountsKinds(t *testing.T) // yubikey + browser records, revoked listed, one unreadable cert → 503 for all
  func TestPublicMuxOnlyInvite(t *testing.T)       // GET / , /users, /certs, /self, POST /api/sign, /api/self/renew → 404; /invite/x → invite page
  ```
- [ ] **Step 2: Run them to see them fail.** Run `cd enroll && go test -race ./...`. Expected: FAIL.
- [ ] **Step 3: Implement** per D22, D23 and D31.
- [ ] **Step 4: Run them to see them pass.** Run `cd enroll && go vet ./... && go test -race ./...`. Expected: `ok`.
- [ ] **Step 5: Commit and push.** `git commit -am "enroll: browser certificates (.p12, generated password, never kept), YubiKey issue / renew / revoke on the internal API; its pages go" && git push`.

---

### Task 11: group-gate — two CAs, binding by issuer, Sign-in paths, opened log, links (core)

**Files:**
- Modify: `group-gate/group-gate.py`
- Test: `tests/test_group_gate.py`

**Interfaces:**
- Produces:
  ```python
  CRL_URLS: list[str]; DELTA_CRL_URLS: list[str]          # GATE_CRL_URLS / GATE_DELTA_CRL_URLS, space-separated
  def leaf_cert_issuer_cn(raw: str) -> Optional[str]
  def ca_subject_cn(path: str) -> Optional[str]            # cached by (inode, mtime, size)
  def cert_method(cert_info: str) -> Optional[str]          # "yubikey_cert" | "browser_cert" | None (D29)
  def session_methods(amr: list, enabled: set, bound: set) -> set  # bound: the cert methods this request binds
  def signin_path(host: str, raw_path: str) -> bool         # D24
  class OpenedLog:
      def __init__(self, directory: str, capacity: int = 10000): ...
      def record(self, user, session, host, app, methods, ip, ua, act="") -> None  # never raises
  def render_certificate_page(app: str, method: str) -> str
  ```
  Also: `/authenticated` goes. The needs-stronger and step-up pages link to `https://people.<domain>/signin`. The portal's own links are People, Sign-in methods (`/signin`) and, for admins, the Hub, Keycloak and Traefik.

- [ ] **Step 1: Write the failing tests**
  ```python
  def test_browser_leaf_never_binds_yubikey(): # amr [mtls], info issuer CN = browser CA, CN alice → have ∌ yubikey_cert
  def test_yubikey_leaf_binds_only_yubikey():  # amr [mtls, file], pki_int leaf → {yubikey_cert}, not browser_cert
  def test_browser_cert_binds_with_file():     # amr [file], pki_file leaf CN alice, browser_cert on → {browser_cert}; off → set()
  def test_equal_or_missing_ca_files_count_nothing(): # same CN in both files, or a missing file → neither method
  def test_revoked_browser_cert_denied_by_pki_file_crl(): # serial only in the pki_file delta CRL → 403 on any host
  def test_crl_lists_union(): # serials from both full and both delta CRLs and the file are all revoked
  def test_signin_paths_exact_after_normalising():
      # people host: "/signin", "/api/me/signin", "/api/me/signin/history", "/static/a.js" → True
      # "/signin/../api/directory", "/static/../api/directory", "/api/me/signinx", "/api/me/signin%2F..%2Fapps",
      # "/Signin", the same paths on hub.<d> and on an app host → False
  def test_signin_paths_any_switched_on_method(): # password-only session on /signin with password on → allowed;
      # password off → needs-stronger; on "/" → the people template applies
  def test_step_up_never_asks_held_cert_method(): # amr [file], no cert presented, rule any[browser_cert] → present-certificate page (browser)
  def test_opened_log_first_request_per_session_host(): # 3 requests same sid+host → 1 line; other host → 2nd line;
      # fields exact, act "", ua ≤ 256; unwritable directory → request still allowed, failure counter + 1
  def test_pages_link_to_signin_page(): # needs-stronger "Set up …" and "Sign-in methods" hrefs == https://people.<d>/signin
  def test_no_enroll_links(): # portal HTML has no "enroll." and no "/self"
  ```
- [ ] **Step 2: Run them to see them fail.** Run `python3 tests/test_group_gate.py`. Expected: FAIL.
- [ ] **Step 3: Implement** per D24, D28, D29, D30 and D31. Pin Traefik's `Issuer="…"` format with a fixture copied from a real header (as `leaf_cert_cn`'s tests do).
- [ ] **Step 4: Run them to see them pass.** Same command. Expected: `OK`.
- [ ] **Step 5: Commit and push.** `git commit -am "group-gate: YubiKey vs browser certificates by issuer; both CAs' CRLs; the Sign-in page reachable with any method; the opened log; links to the Sign-in page" && git push`.

---

### Task 12: Compose, realm and `keycloak configure` (core)

**Files:**
- Modify: `docker-compose.yml`:
  - **enroll:** drop the `enroll` and `enroll-self` routers and the `portcullis-self` middleware;
  - **people router:** `client-cert-pem@file` replaces `client-headers@file`;
  - **group-gate:** volume `group_gate_data:/data`, `./certs/yubikey-ca.crt` and `./certs/browser-ca.crt` mounted read-only under `/etc/group-gate/ca/`, `GATE_CRL_URLS`, `GATE_DELTA_CRL_URLS`, `GATE_YUBIKEY_CA_FILE`, `GATE_BROWSER_CA_FILE`, `GATE_OPENED_DIR=/data/opened`;
  - **hub:** `group_gate_data:/group-gate-data` (read-write, D28), `HUB_CLIENT_CERT_TTL: ${CLIENT_CERT_TTL:-720h}`, `HUB_GROUP_GATE_DATA_DIR`;
  - **keycloak:** `PORTCULLIS_SIGNIN_URL: https://people.${PORTCULLIS_DOMAIN:-portcullis.local}/signin`;
  - the volume `group_gate_data` itself.
- Modify: `keycloak/realm-export.json`:
  - the second x509 execution in `portcullis-signin` with `x509-browser-config`;
  - `portcullis.method` / `portcullis.ca` on both configs;
  - `x509-config`'s CRLs stay `pki_int`'s, `x509-browser-config`'s are `pki_file`'s;
  - `eventsEnabled`, `enabledEventTypes`, `eventsExpiration` 31536000.
- Modify: `scripts/lib/keycloak.sh` (push each x509 config by its alias; never touch the events config), `group-gate/group-gate-map.conf` (no `enroll=`), `scripts/lib/stack.sh` (the `group_gate_data` directory owner and modes as for `mcp_gate_data`), `README.md` / `CLAUDE.md` (D31, D34)
- Test: `tests/test_cli.sh`

**Interfaces:**
- Consumes: Tasks 9–11; the extension's config keys (Task 2).

- [ ] **Step 1: Write the failing tests** (`test_cli.sh`)
  - `no router in docker-compose.yml routes enroll.<domain> except enroll-invite (PathPrefix /invite/)`
  - `no portcullis-self middleware and no "/authenticated" anywhere`
  - `the people router uses client-cert-pem@file, before portcullis-groups@docker`
  - `group-gate mounts group_gate_data read-write and both CA files read-only; GATE_CRL_URLS lists pki_int and pki_file`
  - `hub mounts group_gate_data; HUB_CLIENT_CERT_TTL follows CLIENT_CERT_TTL`
  - `realm-export: portcullis-signin = x509 (x509-config, mtls, yubikey CA), x509 (x509-browser-config, file, browser CA), passkey sub-flow, password form, in that order`
  - `realm-export: each x509 config's CRL paths name only its own mount`
  - `realm-export: events LOGIN, LOGIN_ERROR, expiration 31536000`
  - `keycloak configure pushes x509-browser-config onto the browser execution and x509-config onto the YubiKey one (stubbed kc_get / kc_put)`
  - `group-gate-map.conf has no enroll entry`
  - `the core-names list in the Hub CI check includes group_gate_data`
- [ ] **Step 2: Run them to see them fail.** Run `bash tests/test_cli.sh`. Expected: FAIL.
- [ ] **Step 3: Implement.** Copy the new `portcullis-signin` flow into the extension repo's `src/test/resources/smoke-realm.json` on its `signin2` branch (Task 2's smoke compares them).
- [ ] **Step 4: Run them to see them pass.** Run `bash tests/test_cli.sh` and `shellcheck -S warning portcullis scripts/lib/*.sh tests/*.sh`. Expected: pass, no output.
- [ ] **Step 5: Commit and push.** `git commit -am "core: enroll.<domain> serves only setup links; browser-certificate flow and CRLs; group-gate data and CA files; Keycloak events kept a year" && git push`.

---

### Task 13: Core CI and browser e2e (core)

**Files:**
- Modify: `tests/e2e/e2e_signin.py` (the cases below), `.github/workflows/ci.yml` (e2e-signin: Playwright `clientCertificates` support pinned; `python3 -m pip` `cryptography` already present)

**Interfaces:**
- Consumes: everything above.

- [ ] **Step 1: Write the failing e2e cases** in `e2e_signin.py`:
  - `browser_cert_create_download`: switch `browser_cert` on (Hub API). Alice does a fresh auth with her virtual security key, then `POST https://people.<d>/api/me/signin/browser-certificates {days: 30}`. Expect 200 with `no-store`; `pkcs12.load_key_and_certificates(p12, password)` gives an EC key and a leaf with CN `alice`, issuer the browser CA and `not_after` ≈ now + 30 d. The audit `cert.create` contains neither the password nor base64.
  - `browser_cert_fresh_refused_weak`: a fresh auth with a synced passkey under Strong gets 403 "a fresh sign-in is required".
  - `browser_cert_max_active`: two more creates succeed and the fourth gets 409.
  - `browser_cert_signin_file`: Alice has no other session, an app sits on `any[browser_cert]`, and her browser context carries `clientCertificates` from the `.p12`. She signs in with the certificate only: the app opens, the token amr ∋ `file` ∌ `mtls`, and `kc_log` has no `mtls` for her.
  - `browser_cert_not_yubikey`: the same session on an app on `any[yubikey_cert]` gets `#needs-stronger` (or `#present-certificate` for the YubiKey). Keycloak with `pc_method=yubikey_cert` and that certificate doesn't sign her in.
  - `yubikey_cert_still_mtls`: a `pki_int` certificate issued by CI through Vault signs in with amr ∋ `mtls`.
  - `browser_cert_revoked`: `DELETE /api/me/signin/certificates/<serial>`. Within 70 s the app answers 403, `GET /api/me/signin` shows `revoked`, and `published()` people no longer lists `browser_cert` for alice.
  - `signin_page_reachable_weak`: with password on and bob signed in with a password only, `/signin` and `/api/me/signin` answer 200, while `/api/directory` and `/signin/../api/directory` get `#needs-stronger`.
  - `helper_actions`: `PUT …/groups/milan/signin-helpers {helpers: "hr"}`. Then hr-member carol sends alice a setup link (201), removes her passkeys and revokes her certificate (204), and gets 403 for setting alice's password, for acting on root, and for acting on herself.
  - `history_entries`: alice's `/api/me/signin/history` has a `sign_in` with methods `[browser_cert]` and a non-empty browser, a `step_up`, a `failed` (bob's wrong password, in bob's history), `opened` for the app's host, `help` by carol and `certificate` entries.
  - `enroll_site_gone`: `https://enroll.<d>/` and `/self` answer 404, while `/invite/<bad token>` shows the invite page's "no longer usable".
- [ ] **Step 2: Run to see it fail.** Push and let CI run e2e-signin. Expected: the new cases FAIL before the CI wiring.
- [ ] **Step 3: Implement** the CI wiring.
- [ ] **Step 4: Run to see it pass.** CI on `signin2` (core) is green: `unit-tests`, `build-and-test`, `e2e`, `e2e-instances`, `e2e-signin`, `e2e-settings`, `e2e-folders`, `e2e-filesharing` and `e2e-ai`, with the Hub and the Keycloak image built from `signin2`.
- [ ] **Step 5: Commit and push.** `git commit -am "ci: browser certificates, the mtls / file invariant, revocation, help to reset, history e2e" && git push`.

---

### Task 14: Mainline (all repos)

- [ ] **Step 1:** Merge docs `signin2` → main and push.
- [ ] **Step 2:** Merge portcullis-keycloak `signin2` → main and push. Wait for `build.yml` to publish `:edge` (`gh run list -R porelli/portcullis-keycloak --branch main --workflow build.yml` shows success).
- [ ] **Step 3:** Merge hub `signin2` → main and push. Wait for `ghcr.io/porelli/portcullis-hub:edge` (`gh run list --branch main --workflow build.yml` shows success). Re-run the keycloak repo's vectors job.
- [ ] **Step 4:** Merge core `signin2` → main and push. Check CI is green on main.
- [ ] **Step 5:** Re-run templates `test-apps.yml` on main. Expected: green, with no templates change.
- [ ] **Step 6:** Delete every `signin2` branch (local and remote, four repos) and the worktrees under `/Volumes/workspace/portcullis/wt-signin2/`.
- [ ] **Step 7:** Upgrade the test server under the standing OK: `ACME_STAGING=true`, `./portcullis pki setup && ./portcullis config apply && ./portcullis up`. `pki setup` creates `pki_file`, and `vault init` (in `up`) rewrites the enroll policy.

---

## Self-review

1. **Spec coverage.**
   - Sign-in page (always reachable, only switched-on methods with state and actions, "off on this server", apps and what they need): D24, D25, Tasks 6, 8, 11.
   - Adding a stronger method: D14 unchanged (passkeys on Keycloak); certificates follow D26.
   - Help to reset (admins and managers; setup link, remove passkeys, revoke; no password; nobody acts on an admin; history and audit): D32, Tasks 7, 5.
   - Admin-only actions on someone else's page (issue YubiKey certificate via CSR, revoke any, setup link, remove passkeys, reset password): D32, Task 7. "Sign in as" is part 3.
   - Browser certificates (fresh touch, server-generated key, `pki_file`, `.p12` once, key never kept, limits, revocation, revoked shown everywhere): D21, D22, D26, D27, D30, Tasks 9, 10, 6.
   - Telling the methods apart by issuing CA, and the `mtls` invariant with its test: D29, Tasks 2, 11, 13.
   - History (successes, failures, step-ups, every method, score, app, IP, browser; impersonation hooks): D28, Task 5.
   - enroll retired (user list and pages gone; setup links and issuing kept; the step-up page links to the Sign-in page): D31, Tasks 10–12.
   - Clear names (including "Enroll domain"): D34, Tasks 1, 2, 8, 9, 11, 12.
   - Anti-goals: a browser certificate passing a YubiKey rule (Review Focus 1); private keys stored or re-downloadable (D22, Review Focus 3).
   - Out of scope: impersonation and its banner (part 3; hooks in D28).
2. **Step scan.** Every step names its files, signatures, tests with their assertions and the commands to run. Bodies appear only for fixed copy (the error texts). Things the steps leave to the implementer: Keycloak's error-text table (given), the page layout within the mockup, and the Traefik issuer fixture (to be pinned from a real header).
3. **Type consistency.**
   - `invite.CertRecord{Kind}` / `BrowserCert` / `IssuedCert` are declared in Task 4 and used in Tasks 6–7.
   - `LimitsView` (Task 3) is used in Task 6. `signin.ScoreOfSet` (Task 3) is used in Task 5.
   - `MySignIn` (Task 6) is embedded in `PersonSignIn` (Task 7).
   - `HistoryPage` and `AddHistorySource` belong to Task 5.
   - The config keys `portcullis.method` / `portcullis.ca` and the aliases `x509-config` / `x509-browser-config` are shared by Tasks 2 and 12.
   - The environment variables match across tasks: `GATE_CRL_URLS`, `GATE_DELTA_CRL_URLS`, `GATE_YUBIKEY_CA_FILE`, `GATE_BROWSER_CA_FILE` and `GATE_OPENED_DIR` (Tasks 11–12); `HUB_CLIENT_CERT_TTL` and `HUB_GROUP_GATE_DATA_DIR` (Tasks 3, 5, 12); `PORTCULLIS_SIGNIN_URL` (Tasks 2, 12).
   - The routes of D25 and D32 are used in Tasks 6–8 and 13.
4. **Review Focus.** Each of its five lines names a test in its owning task. Max-active races, TTL ceilings and strict bodies are pinned in Task 10 too.
5. **Proportion.** The plan is about four-fifths of part 1's size (82 KB vs 102 KB). Its code blocks are signatures and test names.
