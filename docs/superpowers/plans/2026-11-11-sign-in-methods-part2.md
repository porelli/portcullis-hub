# Sign-in methods, part 2 of 3 (Sign-in page, browser certificates, history, help to reset, enroll retired, clear names) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give every person one Sign-in page on `people.<domain>` that:
- lists their switched-on methods;
- lets them create, download and revoke browser certificates, renew a YubiKey certificate and set their password;
- shows which of their apps they can open, and their sign-in history.

Admins and holders of the new delegated permission `sign_in_help` can help a person reset. The plan also:
- retires `enroll.<domain>` as a site;
- makes browser certificates (`browser_cert`, amr `file`, CA `pki_file`) a real method;
- uses the clear certificate names everywhere.

**Architecture:**
- **Second CA.** Core's Vault gets a second issuing CA, `pki_file`, under the existing root.
- **enroll.** enroll is the only service that holds Vault access. It gains internal, bearer-protected endpoints for browser certificates and for issuing, renewing and revoking YubiKey certificates. For a browser certificate it generates the key, has `pki_file` sign it, and returns a PKCS#12 file and its generated password once. enroll's own pages go away; only `/invite/*` stays routed.
- **Hub.** It serves the Sign-in page and its API on the people listener and relays requests to enroll.
- **group-gate.** It lets any switched-on method reach that page.
- **Telling certificates apart.** The Keycloak extension, group-gate and the Hub's inventory tell the two CAs apart by issuer, so `mtls` means a YubiKey certificate only.
- **History.** It is merged at read time from three sources:
  - Keycloak's stored LOGIN / LOGIN_ERROR events, whose details the extension fills in;
  - a daily "app opened" log written by group-gate;
  - the Hub's audit log.

**Tech Stack:** Go 1.27 (Hub, enroll), `software.sslmate.com/src/go-pkcs12` (BSD-3, enroll), `github.com/mileusna/useragent` (MIT, Hub), Python 3 + `cryptography` (group-gate), Java 21 + Gradle with dependency verification (Keycloak 26.8.1 SPI), vanilla JS (Hub UI), bash (core CLI), Vault PKI.

**Spec:** `docs/superpowers/specs/2026-11-09-sign-in-methods-design.md` (Hub repo), call 8 part (2). It keeps rulings from `docs/superpowers/specs/2026-11-02-certificates-selfservice-design.md` (goals 1–4, call 8).

**Mockups:** `.superpowers/brainstorm/98502-1794260205/content/signin-people.html` sections 1 and 3. Section 4 and the "Sign in as" row are part 3.

**Model and conventions:** `docs/superpowers/plans/2026-11-09-sign-in-methods-part1.md`. Its D1–D20 stay in force; part 2 continues with D21–D34.

## Global Constraints

Process and checks (part 1's rules, restated for part 2):
- **Precondition (met 2026-11-11):** branch `fresh-template` (hub, keycloak, docs, core: fresh auth by the governing template, `signin.FreshAccepted`, `freshGov`) is mainlined. Every part-2 branch starts from that `main`.
- **Branches and worktrees.** Branch `signin2` in every repo touched (docs, keycloak, hub, core), mainlined at the end, no PRs. The worktrees are `/Volumes/workspace/portcullis/wt-signin2/{portcullis-docs,portcullis-keycloak,portcullis-hub,portcullis}`, on `signin2`. Each task works in its repo's worktree. The templates repo isn't changed; its CI is re-run in Task 14.
- **Every commit step stages new files:** `git add -A && git commit -m "…"`. Never use `commit -am` alone, because it drops new files.
- **No migration / back-compat code** (there are no installs). `GATE_CRL_URL` / `GATE_DELTA_CRL_URL` and the core page key `enroll` go away, and nothing reads their old shapes. The idempotent `pki setup` creating a missing CA piece is setup, not migration.
- **Contract first:** Task 1 changes `docs/guides/integration-contracts.md` before any code.
- **Never weaken access control; fail closed.** An unknown CA, an unreadable CA file, an unreadable CRL list or an unknown certificate kind never counts as a method. A switched-off method is never accepted.
- **Secrets stay out** of argv, logs, the audit, errors and the Hub's state. That covers the `.p12`, its password, private keys, setup links, fresh-auth codes and tokens.
  - The `.p12` and its password cross exactly two answers: the internal enroll → Hub answer, and the one answer to the browser (`Cache-Control: no-store`, `Pragma: no-cache`). Neither is logged or cached.
  - The private key is never stored and can't be downloaded again.
- **Identity is the LLDAP username.** A certificate's CN is always the username the Hub forwards for the signed-in caller (or for the target the caller may act on), never a CSR's subject or a value from the client.
- **Prefer mature libraries:** `go-pkcs12` for PKCS#12, Go's `crypto/x509` / `crypto/ecdsa`, the JDK's `CertificateFactory` / `X509Certificate.verify`, Python `cryptography`, Vault's PKI. No hand-rolled X.509, ASN.1 or user-agent parsing.
- **Shared sign-in vectors stay byte-identical.** The four copies are:
  - Hub `internal/signin/testdata/vectors.json`;
  - core `tests/signin_vectors.json`;
  - core `mcp-gate/internal/signin/testdata/signin_vectors.json`;
  - keycloak `src/test/resources/signin_vectors.json`.

  Task 3 changes the Hub's copy, Task 2 copies it to keycloak, and Task 11 copies it to core.
- **Web UI:** vanilla JS, everything escaped, data-* attributes plus delegated listeners.
- **Go checks (Hub):**
  - gofmt go1.27.3: `$(GOTOOLCHAIN=go1.27.3 go env GOROOT)/bin/gofmt -l .` prints nothing;
  - `go vet ./...` and `go vet -tags harness ./internal/httpapi/...`;
  - `PORTCULLIS_TEMPLATES_DIR=/Volumes/workspace/portcullis/portcullis-templates PORTCULLIS_DOCS_DIR=/Volumes/workspace/portcullis/wt-signin2/portcullis-docs go test -race ./...` ends `ok` for every package.
- **Core checks:** `shellcheck -S warning portcullis scripts/lib/*.sh tests/*.sh`, `bash tests/test_cli.sh`, `bash tests/test_shell_libs.sh`, `python3 tests/test_group_gate.py`, `cd enroll && go vet ./... && go test -race ./...`, `cd mcp-gate && go test -race ./...`.
- **Keycloak repo checks:** `docker build --target test .` (ends `BUILD SUCCESSFUL`), `docker build .`, the vectors check and the smoke job.
- **Docs build:** inside the docs venv per the docs `CLAUDE.md` (Python ≥ 3.10, `pip install -r requirements.txt`), run `zensical build --strict`.
- **Core CI** on the same-named branch builds the Hub and the Keycloak image from `signin2` (`.github/actions/hub-image`, `.github/actions/keycloak-image`).
- **Working style:** implementers push and start CI without waiting. Never reformat outside the task.
- **Merge order:** docs → portcullis-keycloak (wait for `edge`) → hub (wait for `edge`) → core. Then re-run templates CI.
- **Standing OK (2026-11-11):** merge each piece to main and upgrade the test server (`ACME_STAGING=true`) once reviews are clean and every CI is green. Still stop for destructive or out-of-plan security-sensitive actions, and for EC2 runners.

User rulings for part 2 (binding, 2026-11-11):
- **The `.p12` password** is generated by Portcullis and shown once next to the download, never stored. The private key is never kept.
- **Defaults:** browser certificate lifetime 30 days (never more than core's `CLIENT_CERT_TTL`), at most 3 active browser certificates per person, sign-in history kept 1 year. The admin can change all three in Hub Settings.
- **Help to reset:**
  - Delegated helpers may send a setup link, remove passkeys and revoke certificates, but may NOT reset passwords. Admins may do all of these.
  - Help uses the existing People delegation (`directory.yaml` `permissions`), with one new permission, `sign_in_help`. Its scope is today's delegation scope: any non-admin person (controller ruling F13).
  - Delegates never act on an administrator. Admins keep today's typed-confirmation rule (`checkAdminTakeover`) for another administrator's passkeys and password. The new certificate routes (issue, revoke) refuse administrator targets for everyone; the CLI `cert revoke` recovers (controller ruling F14).
  - Everything is recorded in the person's history and the audit log.
- **`browser_cert`** can be switched on once part 2 lands, and stays off by default.
- **`portcullis-x509`** tells `pki_int` (YubiKey) certificates from `pki_file` (browser) ones and emits `mtls` or `file` accordingly. `mtls` is only ever emitted for a YubiKey certificate, and a test pins this.
- **`enroll.<domain>` stops being a site.** Setup links (`/invite/*`) and certificate issuing stay as back-end services. The renewal page moves to the Sign-in page, and the step-up and needs-stronger pages link there.
- **Clear names:**
  - "Website certificate (HTTPS)", "YubiKey certificate", "Browser certificate";
  - "Internal certificate authority" (admin and troubleshooting only);
  - "Enrol" is used only for adding a sign-in method, and the Hub's "Enroll domain" is renamed.
- **Fresh auth (part 1 ruling):** `pc_fresh` must be the strongest method of one alternative of the governing compiled rule. On the people listener the governing rule is the `people` core template.

Decisions (made here; the spec leaves them to the builder):
- **D21 Internal certificate authority: `pki_file`.** `pki setup` adds a second intermediate, `pki_file`, signed by the existing `pki` root:
  - CN `<domain> Browser Certificate CA`, a 43800 h TTL;
  - the same URL and CRL config as `pki_int` (`expiry=72h auto_rebuild=true auto_rebuild_grace_period=12h enable_delta=true delta_rebuild_interval=1m`).

  Its role `browser-cert` copies the `client-cert` role's settings, and is rewritten on every run: `allow_any_name`, `enforce_hostnames=false`, `use_csr_common_name=false`, `use_csr_sans=false`, client flag only, `key_type=ec key_bits=256`, `max_ttl=$CLIENT_CERT_TTL`, `no_store=false`.

  Exports:
  - `certs/yubikey-ca.crt` (`pki_int`'s certificate) and `certs/browser-ca.crt`;
  - `certs/ca-chain.crt` = root + `pki_int` + `pki_file` (Traefik's `protected-any` and `authaware` options: both kinds);
  - `certs/ca-chain-yubikey.crt` = root + `pki_int` only (Traefik's `protected` option: a browser certificate can never pass that handshake);
  - the truststore gets `portcullis-ca-chain.pem` plus `portcullis-yubikey-ca.pem` and `portcullis-browser-ca.pem`.

  Rules:
  - `pki setup` refuses (exit 1) when the two intermediates' CNs are equal: every reader tells the kinds apart by issuer.
  - It creates `pki_file` when it is missing, even while `pki_int` exists (a missing piece, as today).
  - Whenever `pki_file` is created, or either chain on disk differs from what it should be (`ca-chain.crt` = root + `pki_int` + `pki_file`, `ca-chain-yubikey.crt` = root + `pki_int`), it rewrites both chain files and the truststore and sets `PKI_TRUSTSTORE_CHANGED=true`. That flag is what makes `stack.sh` restart Traefik and Keycloak.

  **TLS options (controller ruling, Task 1 fix round 1).** Core's static `traefik/dynamic/tls.yml` has exactly four options (each `minVersion: VersionTLS12`, `sniStrict: false`; Traefik already mounts `./certs:/certs:ro`):

  | Option | Client auth | `caFiles` | Used for |
  |---|---|---|---|
  | `protected@file` | `RequireAndVerifyClientCert` | `/certs/ca-chain-yubikey.crt` | `auth.method: mtls` apps; templates where **every** alternative has `yubikey_cert` |
  | `protected-any@file` (new) | `RequireAndVerifyClientCert` | `/certs/ca-chain.crt` | templates where every alternative has a certificate method and at least one accepts `browser_cert` |
  | `authaware@file` | `VerifyClientCertIfGiven` | `/certs/ca-chain.crt` | templates where some alternative has a certificate; every core router |
  | `public@file` | none | — | everything else |

  Public exceptions keep turning `protected*` into `authaware` (`policy.HostTier`, today's rule).
  - `--force` destroys both CAs.

  enroll's policy (`vault/policies/enroll.hcl`) adds:
  - `pki_file/sign/browser-cert` (update);
  - `pki_file/certs` (list) and `pki_file/cert/*` (read);
  - `pki_int/revoke` and `pki_file/revoke` (update);
  - `pki_int/crl/rotate` and `pki_file/crl/rotate` (read).
- **D22 Issuing a browser certificate (enroll, inside the Vault boundary).**
  - **Key:** enroll generates an ECDSA P-256 key (`ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`) and builds the CSR itself.
  - **Signing:** through `pki_file/sign/browser-cert` with `common_name=<user>` and `ttl=<days×24>h`. Vault never sees the key.
  - **Encoding:** `pkcs12.Modern2023.Encode(key, leaf, []*x509.Certificate{browserCA, root}, password)` (AES-256-CBC, PBKDF2-SHA256, SHA-256 MAC).
  - **Password:** 20 characters from the Crockford base32 alphabet (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`, 100 bits from `crypto/rand`), written as 4 groups of 5 joined by `-`.
  - **After answering:** the answer is returned once. enroll then clears the DER key, the `.p12` and the password buffers (`clear`), drops the key, and logs only `browser certificate <serial> for <user>`.
  - **Checks**, in this order, serialised by one process-wide mutex:
    - `1 ≤ days ≤ max_days`, and `days × 24 h` ≤ enroll's `CERT_TTL` (else 400);
    - the user exists in LLDAP (else 404);
    - fewer than `max_active` unrevoked, unexpired `pki_file` certificates with that CN (else 409 "you already have <n> browser certificates, the most allowed: revoke one first").
  - **Filename:** `<user>-browser-certificate-<YYYYMMDD>.p12`.
- **D23 enroll's internal API.** It runs on `:8444` with the invite bearer, JSON bodies ≤ 64 KiB and `DisallowUnknownFields` (contract §9.4).
  - **Wiring:** the operations need Vault (`*Config`), while `apiHandler` lives on `*inviteService`. `main` injects them as function fields on `inviteService`, like `listCertificates`.
  - `POST /internal/browser-certificates` `{"user","days","max_days","max_active"}` → 201 `{"p12": "<std base64>", "password", "serial", "not_after", "filename"}`.
  - `POST /internal/yubikey-certificates` `{"user","csr"}` → 201 `{"certificate": "<PEM>", "serial", "not_after"}`. It runs `validateCSR` first (400 with its text). This is the admin CSR path that replaces `/api/sign`.
  - `POST /internal/yubikey-certificates/renew` `{"user","presented","csr"}` → 201 (same shape). `presented` is a real PEM `CERTIFICATE` block (the Hub converts it, D25). **Only a `pki_int` leaf renews (review I1):** enroll first checks that `presented` was issued by `pki_int` (issuer DN equal to `pki_int`'s CA subject and its signature verifying against that CA's key; else 403), then runs `checkRenewal` (403 with its text); `lookupIssued` stays on `pki_int` only. It replaces `/api/self/renew`.
  - **Protected names (review I3):** every certificate action refuses `user` = `admin`, `portcullis-hub` or any `portcullis-*` name (lowercased) with 409 `{"error": "protected account"}`, before Vault is called.
  - `POST /internal/certificates/revoke` `{"user","serial"}` → 204.
    - enroll looks the serial up in `pki_int`, then in `pki_file`. Not found, or a CN other than `user`: 404. Already revoked: 204.
    - Otherwise it revokes, then rotates that mount's CRL. A failed rotate still answers 204 and is logged: the delta CRL catches up within 2 min.
  - `GET /internal/certificates` keeps its fail-closed rules and covers both mounts. Each record gains `"kind": "yubikey" | "browser"` and `"not_before"`. Revoked records are listed with `revoked: true`.
- **D24 Where the Sign-in page lives.**
  - **The page:** `GET /signin` on the people listener, served as its own HTML (`web/mysignin.html` + `web/mysignin.js`, both in `web/web.go`'s `//go:embed` list; `mysignin.js` is in `peopleStatic`). It calls only the `/api/me/signin*` routes below, so it works for a session the `people` template wouldn't admit.
  - **Navigation:** the people SPA's top nav gets "Sign-in" (→ `/signin`).
  - **Fresh-auth redirect:** the people listener's redirect URI becomes `https://people.<domain>/signin`:
    - `cmd/hub/main.go`'s people `RedirectURI` feeds both the verifier and `EnsureFreshAuthClient`;
    - `mysignin.html` loads `freshauth-callback.js` first in `<head>`, and My apps uses the same URI;
    - the `portcullis-fresh-auth` client's redirect URIs are exactly `[https://people.<domain>/signin, https://hub.<domain>/]`, with web origins unchanged;
    - `checkFreshAuthURIs` accepts the path `/signin` on the people host and `/` on the hub host.
  - **group-gate's Sign-in paths.** On `people.<main domain>` only, the rule is `{"op":"any","items":[every id in methods]}` instead of the `people` template (no methods → deny) when:
    - `normalize_path_candidates(raw)` doesn't raise, and
    - every candidate it returns is exactly `/signin`, exactly `/api/me/signin`, under `/api/me/signin/`, or under `/static/`.

    Anything else, including an encoded `/` or `\`, gets the `people` template. Membership checks still run first (`people=*`).
  - **Why the exception is safe:** anything on `/api/me/signin*` that adds a method needs a fresh sign-in under the `people` template (D26) or the presented YubiKey certificate. Everything else only reads or removes the caller's own data.
- **D25 The caller's routes.** People listener, caller only (`X-Forwarded-User`), CSRF, and the §5.1 common rules and refusal limit:
  - `GET /api/me/signin` → `MySignIn`.
  - `GET /api/me/signin/history?before=<RFC 3339>&limit=<1–100, default 50>` → `HistoryPage`.
  - `POST /api/me/signin/browser-certificates` `{days, code, code_verifier, nonce}` (≤ 8 KiB) → 200 `{p12, password, filename, certificate}`, `no-store`.
  - `DELETE /api/me/signin/certificates/{serial}` → 204. Own browser certificates only; a YubiKey certificate or someone else's serial is 404. No fresh auth: it only removes access.
  - `POST /api/me/signin/yubikey-certificate/renew` `{csr}` → 200 `{certificate, serial, not_after}`.
    - The people router passes the presented certificate (`client-cert-pem@file`) in `X-Forwarded-Tls-Client-Cert`: base64 DER without BEGIN/END lines, possibly URL-escaped, comma-separated, leaf first.
    - The Hub (`presentedCertPEM`) takes the first entry, decodes it to DER, checks that it parses as X.509, and sends real PEM to enroll. **Only a YubiKey leaf renews (review I1):** the Hub also checks that the leaf's serial is one of the caller's unexpired, unrevoked `kind: yubikey` records in enroll's `GET /internal/certificates`, and enroll checks the issuer again (D23). A missing or unparsable header, or any other leaf (a browser certificate included), is 403 "present your current YubiKey certificate".
    - No fresh auth: the TLS session and the CSR's signature both prove possession of the key.
  - `PUT /api/me/signin/password` `{password, code, code_verifier, nonce}` → 204, refused (409) while the password method is off.
  - `DELETE /api/me/signin/password` → 204. LLDAP can't clear a password, so this sets a random 32-byte one nobody sees and drops the Hub's record.

  Own password changes and removals sign the person out of Keycloak, like every password change (§4). They are refused for `admin` and `portcullis-hub` (409, D13's text). Audit actions: `cert.create`, `cert.revoke`, `cert.renew`, `signin.password` (detail `self set` / `self removed`).

  JSON names are snake_case, as the Interfaces blocks' tags give them.
- **D26 Fresh auth for adding a certificate.** Creating a browser certificate (self) and issuing a YubiKey certificate (admin) need a proof under the `people` core template (`freshGov` for the people listener).
  - `pc_fresh` must be in `signin.FreshAccepted(peopleRule)` **and** must not be `password` or `browser_cert`: a password or a copied certificate file never mints a new certificate.
  - When that set is empty, the answer is 409 "creating a certificate needs a passkey or YubiKey sign-in that people.<domain> accepts".
  - A refused proof is the standard 403 "a fresh sign-in is required", with the reason audited only.
  - Setting your own password needs a proof under the plain `FreshAccepted(peopleRule)`.
  - Add-stronger (D14) doesn't apply separately: the fresh method is already at least as strong as a browser certificate.
- **D27 Limits.** `state.yaml` `sign_in.limits` = `{browser_cert_days: 30, browser_cert_max_active: 3, history_days: 365}`.
  - **`browser_cert_days`:** 1 to the ceiling.
    - The ceiling is `HUB_CLIENT_CERT_TTL` in whole days. Core sets `${CLIENT_CERT_TTL:-720h}`, and the Hub parses it with core's grammar `^[0-9]+[smhd]?$` (a bare number means seconds).
    - The Hub refuses to start when the variable is unset or unparsable, or when the ceiling is under 1 day.
    - A stored value above the ceiling applies as the ceiling, and Settings shows a warning.
  - **`browser_cert_max_active`:** 1–20.
  - **`history_days`:** 30–3650.
  - **Route:** `PUT /api/signin/limits` `{browser_cert_days, browser_cert_max_active, history_days}` (Hub listener, admins). `GET /api/signin` shows it as `limits` + `ceiling_days`. Audited `signin.limits`, with an `old -> new` detail per field.
  - **Lifetime picker:** the person picks a lifetime from 1 day up to `browser_cert_days`; the default is the maximum.
  - **The switch:** switching `browser_cert` on is no longer refused (`Info.Available` true). Part 1's "aren't available yet" 409, its vector and `TestBrowserCertUnavailable` are removed.
- **D28 Sign-in history.** It is merged at read time from three sources. Nothing new is stored in the Hub.
  - **Source 1: Keycloak events.**
    - The Hub owns the realm's events config: `PUT /admin/realms/portcullis/events/config` with `eventsEnabled: true`, `enabledEventTypes: ["LOGIN","LOGIN_ERROR"]`, `eventsExpiration: history_days × 86400`, and the existing `eventsListeners` kept.
    - It is re-asserted in the directory sync loop and on a limits change. Core's realm-export sets the same values (365 days); `keycloak configure` never touches the events config.
    - The extension adds details to the LOGIN event in `portcullis-template`:
      - `pc_kind`: `sign_in`, `step_up` (an SSO session that gained a method in this authentication) or `sso` (cookie only);
      - `pc_methods`: this authentication's new method ids, comma-joined in canonical order;
      - `pc_session`: all of the session's methods;
      - `pc_ua`: the User-Agent, ≤ 256 characters, control characters removed.
    - Before a failure, its password form, `portcullis-x509` and `portcullis-passkey` add `pc_method` (the method tried) and `pc_ua`.
    - Mapping to history kinds:
      - `LOGIN` with client `portcullis-fresh-auth` → `confirmed`;
      - `LOGIN` with `pc_kind` `sign_in` → `sign_in`; `step_up` → `step_up`;
      - `LOGIN` with `pc_kind` `sso` → `opened <client name>` for clients in `signin-keycloak.json` `clients`, otherwise dropped (group-gate's log covers the gateway's apps);
      - `LOGIN_ERROR` → `failed`, with Keycloak's error mapped to plain text (an unknown error shows as "sign-in failed").
  - **Source 2: group-gate's "opened" log.**
    - **What is written:** the first allowed request per `(session, host)` that a group-gate process sees appends a line to `group_gate_data/opened/<YYYY-MM-DD>.jsonl` (UTC day). The line is `{"time","user","session","host","app","methods":[…],"ip","ua","act"}`:
      - `session` is the token's `sid`, else `<user>@<auth_time>`;
      - `ip` is `X-Real-Ip`, and `ua` is ≤ 256 characters;
      - `act` is `""` in part 2; part 3 fills it.
    - **Deduping:** remembered sessions sit in an in-memory LRU of 10 000. A restart may log one more line, and readers dedupe on `(session, host, day)`.
    - **Failures:** a write failure never denies a request. It is logged and counted (`group_gate_opened_log_failures_total`).
    - **Ownership:** the volume is owned `10003:10001`. group-gate runs as 10003 with `group_add: ["10001"]`. The `opened/` directory is mode 2770 with group 10001, and files are 0640.
    - **Pruning:** the Hub (uid 10001) mounts the volume read-write only to delete day files older than `history_days`, once a day and after any change of `history_days`. It never deletes today's file.
    - **Backup:** `group_gate_data` is in `BACKUP_FILE_VOLUMES`, because the history is kept a year.
  - **Source 3: the Hub's audit**, `ForUser(user)`, keeping only `cert.*`, `signin.password`, `user.password`, `user.invite` and `user.remove_passkeys`. An entry whose actor isn't the person becomes `help` (`by` = the actor); one by the person becomes `certificate` (for `cert.*`) or is dropped (for anything else). `detail` never holds secrets.

  **Entry** `{time, kind, methods, score, app, ip, browser, by, reason, detail}`:
  - `kind` is one of `sign_in`, `step_up`, `failed`, `confirmed`, `opened`, `help`, `certificate`, `impersonation` (reserved for part 3);
  - `score` = `signin.ScoreOfSet(methods)` (an `all` of the methods, D4) or null;
  - `browser` = `useragent.Parse(ua)`'s `Name` + `OS` ("Firefox · macOS"), or "" when unknown.

  Entries outside `history_days` are never returned. A source that fails is named in `unknown`, and the others are still shown.

  **Part-3 hooks:**
  - the `impersonation` kind;
  - the `by` / `reason` fields;
  - the opened log's `act`;
  - the reserved event detail `pc_act`;
  - `Hub.AddHistorySource(name, signinhistory.Source)`.
- **D29 Telling the certificates apart.**
  - **Keycloak:**
    - `portcullis-signin` holds two ALTERNATIVE `portcullis-x509` executions:
      - first `x509-config`: `portcullis.method=yubikey_cert`, reference `mtls`, `portcullis.ca=/opt/keycloak/conf/truststores/portcullis/portcullis-yubikey-ca.pem`, CRLs `pki_int/crl##pki_int/crl/delta`;
      - then `x509-browser-config`: `browser_cert`, `file`, the browser CA, `pki_file`'s CRLs.
    - **When an execution runs:** it steps aside (`attempted`) unless all three hold:
      - its method is on;
      - `pc_method` allows it;
      - the presented leaf was issued by its CA: `leaf.getIssuerX500Principal().equals(ca.getSubjectX500Principal())` and `leaf.verify(ca.getPublicKey())`.
    - **The CA file** is loaded lazily, only when a leaf is presented and the method is on. A missing, unreadable or non-CA file steps aside and is logged at ERROR. A flow with no certificate never logs it.
    - On success the execution writes its own method to `portcullis.x509.method`.
    - `Offer` and `TemplateAuthenticator`'s `completable` step use each execution's `portcullis.method`.
    - `FreshMapper` accepts `browser_cert` as a `pc_fresh` value; the Hub refuses it for certificates (D26). When one authentication ran several methods, the strongest wins in the order `yubikey_cert > security_key > passkey_device > browser_cert > passkey_synced > password` (review I2: the certificate wins the 2.5 tie).
    - `keycloak configure` pushes each config by alias.
  - **group-gate:**
    - The leaf's issuer CN in `X-Forwarded-Tls-Client-Cert-Info` is compared with the subject CNs of `GATE_YUBIKEY_CA_FILE` and `GATE_BROWSER_CA_FILE` (read with `cryptography`, cached by mtime). Equal CNs, or a missing or unreadable file, means no certificate counts.
    - `yubikey_cert` counts only when `mtls` ∈ amr and a non-revoked `pki_int` leaf with CN = the user is presented on this request.
    - `browser_cert` counts the same way, with `file` and a `pki_file` leaf.
    - The present-certificate page covers both kinds ("<App> needs your <YubiKey|browser> certificate — …").
    - A step-up never asks for a certificate method whose amr the session already holds.
    - `GATED_CORE_SUBDOMAINS` loses `enroll`. `CORE_SUBDOMAINS` keeps it, so the name stays reserved against apps.
  - **Hub:** the inventory maps `kind: yubikey` → `yubikey_cert` and `browser` → `browser_cert`, counting only unexpired, unrevoked records.
- **D30 Revocation.**
  - **group-gate** reads `GATE_CRL_URLS` and `GATE_DELTA_CRL_URLS` (space-separated; the `pki_int` and `pki_file` full and delta CRLs). Its revoked set is the union of every CRL and the serial file.
  - **Keycloak:** each of the two x509 configs checks its own CA's CRLs (`crl-abort-if-non-updated` true).
  - **`cert sync`** writes the union of both mounts' revoked serials.
  - **Timing:** a web revocation rotates the full CRL, so it is enforced within 60 s (group-gate's refresh, Keycloak's `cache-time`).
  - **Revoked shows as revoked everywhere.** The Sign-in page, the person's Sign-in tab, `cert list --all` and the MCP views read `revoked` from D23. The status is one of `valid`, `expiring` (< `CERT_EXPIRY_WARN_DAYS`, default 7), `expired` or `revoked`.
  - enroll's old certificate list, which showed revoked certificates as "Valid", goes with its site (D31).
- **D31 enroll stops being a site.**
  - **Removed:**
    - the routers `enroll` and `enroll-self`, the `portcullis-self` middleware and group-gate's `/authenticated`;
    - enroll's `/`, `/users`, `/certs`, `/enroll/{u}`, `/api/sign`, `/api/users`, `/self` and `/api/self/renew`, and its pages other than `invite.html`;
    - the core page key `enroll` (Hub `CoreSignInKeys`, policy `core`, `group-gate-map.conf`, group-gate's `GATED_CORE_SUBDOMAINS`);
    - the portal links "My client certificate" / "Certificates".
  - **Kept:** `enroll-invite` (`Host(enroll.<d>) && PathPrefix(/invite/)`) and the invite issuer `https://enroll.<d>/invite`. Any other path on that host gets Traefik's 404. enroll's public mux is built by `publicMux(srv, inv)`.
  - **Links that now point at the Sign-in page:**
    - the portal's "Sign-in methods" link (`https://people.<d>/signin`);
    - every "Set up …" and "Sign-in methods" link on group-gate's needs-stronger page;
    - the extension's page: the Keycloak env `PORTCULLIS_SIGNIN_URL`, set by core to `https://people.${PORTCULLIS_DOMAIN}/signin`; unset falls back to the account console;
    - core's leftover texts: `.env.example`, `monitoring/prometheus/alerts.yml`, `scripts/lib/status.sh`, the core Keycloak theme's messages, and core `docs/`.
  - **CLI:** `cert enroll|renew|revoke|list|sync` stay, covering both mounts. `cert list` shows a KIND column (`YubiKey` / `Browser`), and `cert enroll` prints the Sign-in page for renewals.
- **D32 Help to reset** (People delegation, controller rulings F13 / F14).
  - **The permission:** the new delegated permission `sign_in_help` joins `edit_details`, `invite` and `remove` in `delegatedPerms`. It is granted to one group through the existing `directory.yaml` `permissions` and the existing route `PUT /api/directory/permissions/sign_in_help` and its MCP twin `set_permission`. Its scope is the existing delegation scope.
  - **What holders may do:**
    - send a setup link — this skips `checkKeyless` / `created_by` (that is the point of a reset); core's invite API still refuses protected targets;
    - remove passkeys;
    - revoke certificates.

    A holder never sets a password and never issues a YubiKey certificate.
  - **Targets:** `checkDelegateTarget` is unchanged. It is never the holder themselves, a protected account, an administrator or a member of a permission group (403, the existing texts). It is checked against a fresh snapshot inside `gate`, like every delegated permission. Holding `sign_in_help` makes its group a permission group, so its members can't be targeted by other delegates.
  - **Admins:** they keep every action.
    - On another administrator, the setup-link, passkey and password routes keep today's rules: core refuses invites for administrators, and `checkAdminTakeover` asks for the typed confirmation for passkeys and password.
    - The new certificate routes (issue, revoke) refuse administrator targets for everyone (409 "administrators' certificates are managed from the server: ./portcullis cert revoke <serial>"). The CLI recovers.
    - They also refuse `admin`, `portcullis-hub` and every `portcullis-*` name for everyone (409 "this account's certificates are managed from the server: ./portcullis cert revoke <serial>"), as enroll does (D23; review I3). On the Sign-in page those accounts can't create, renew or revoke their own certificates either; every other administrator creates and revokes their own browser certificates there like anyone else.
    - `PersonSignIn.can.setup_link` is false for an administrator target (core refuses the invite).
  - **Audit:** actions keep their names (`user.invite`, `user.remove_passkeys`, `cert.revoke`), with detail `as sign_in_help` for a delegate. These are the `help` entries in the person's history (D28).
  - **Person routes** (directory route set, both listeners):
    - `GET /api/directory/users/{u}/signin` → `PersonSignIn` (admins and `sign_in_help` holders who may target u; anyone else 403);
    - `GET …/{u}/signin/history`, under the same rule;
    - `DELETE …/{u}/certificates/{serial}` → 204 (admin or holder; 404 when the serial isn't u's);
    - `POST …/{u}/certificates` `{csr, code, code_verifier, nonce}` → 200 (admins only, D26);
    - `POST …/invite` and `…/remove-passkeys` accept holders and keep their 200 JSON answers.
- **D33 MCP twins and classes.**

  | tool | resource | class |
  |---|---|---|
  | `my_sign_in` (view + the last 20 history entries) | people | R |
  | `my_browser_certificate`, `my_password` (handoffs: "create it on the Sign-in page, `https://people.<d>/signin`"; never a file or password) | people | R |
  | `revoke_my_certificate` `{serial}` | people | W |
  | `person_sign_in` `{user}` | people + admin | R |
  | `revoke_person_certificate` `{user, serial}`, `remove_passkeys` `{user}` | people + admin | D |
  | `issue_yubikey_certificate` (handoff to the person's Sign-in tab) | admin | R |
  | `set_permission` (existing; its description and enum gain `sign_in_help`) | admin | D (unchanged) |
  | `set_sign_in_limits` | admin | D when `browser_cert_days` or `max_active` go up or `history_days` goes down, else W |

  The YubiKey renewal and both history routes have no twin; `mcp_parity_test.go` lists them with that reason.
- **D34 Clear names.**
  - **"Website certificate (HTTPS)":** Let's Encrypt / the domains service's certificates, Settings → Domains and the docs.
  - **"YubiKey certificate" / "Browser certificate":** every UI, page, CLI and docs mention of a client certificate. "mTLS" stays only in contract internals (amr `mtls`, `auth.method: mtls`).
  - **"Internal certificate authority":** `pki setup` help, `cert` help, the doctor / troubleshooting and the docs.
  - **"Enrol":** used only for adding a sign-in method.
    - The Hub's "Enroll domain" becomes "Add domain", and its toasts say "Adding …".
    - MCP `enroll_domain` → `add_domain`; audit `domain.enroll` → `domain.add`.
    - Docs prose "enrolled domain" → "added domain". The field and term `extra_domains` / "extra-domain host" stay.
    - Go identifiers, the domains API path and core service names stay.

## Review Focus

1. **A browser certificate counting as a YubiKey certificate.** For example: a session with amr `mtls` that presents a `pki_file` leaf with the right CN; the Keycloak YubiKey execution handed a browser leaf; or an inventory record of the wrong kind. Expected: never `yubikey_cert`, never amr `mtls`. Pinned by:
   - `test_browser_leaf_never_binds_yubikey` (Task 11);
   - `X509AuthenticatorTest.browserLeafNeverMtls` (Task 2);
   - `TestInventoryCertKinds` (Task 4);
   - e2e `browser_cert_not_yubikey` (Task 13).
2. **A revoked certificate still working, or shown as valid.** For example: a live session with amr `file` keeps opening an app after its certificate is revoked, or the page still says "valid". Expected: 403 within 60 s, and the status reads "revoked" everywhere. Pinned by:
   - `test_revoked_browser_cert_denied_by_pki_file_crl` (Task 11);
   - `TestMySignInShowsRevoked` (Task 6);
   - e2e `browser_cert_revoked` (Task 13).
3. **The `.p12`, its password or the key leaking** into logs, the audit, an error, a cached answer or a second download. Expected: only the enroll → Hub answer and the one `no-store` answer to the browser. Pinned by:
   - `TestBrowserCertSecretsNeverLogged` (Task 10);
   - `TestCreateBrowserCertAnswerNoStore` and `TestCertAuditHasNoSecrets` (Task 6).
4. **A `sign_in_help` delegate acting outside their scope.** For example: on an administrator, on themselves, on a member of a permission group, resetting a password, issuing a certificate, or right after losing the permission. Expected: 403, with nothing changed. Pinned by `TestHelpScope` (Task 7).
5. **A weak session reaching more of people.<domain> than the Sign-in page.** For example: `/signin/../api/directory`, `/api/me/signin%2F..%2Fapps`, `/static/../api/directory`, or the same paths on `hub.<d>` or an app host. Expected: the `people` template (or the host's) applies. Pinned by:
   - `test_signin_paths_exact_after_normalising` (Task 11);
   - e2e `signin_page_reachable_weak` (Task 13), which sends the raw, unnormalised path.

---

### Task 1: Contract and docs (docs repo)

**Files:**
- Modify: `docs/guides/integration-contracts.md`:
  - §1: a "Sign-in methods part 2" bullet (breaking for core, the Hub and the Keycloak image together; merge order docs → keycloak → hub → core);
  - §4: core hosts without `enroll` (gated hosts; `enroll` stays a reserved core name); group-gate's Sign-in paths (D24); `browser_cert` binding (D29); revocation lists (D30); the opened log (D28);
  - §5: the present-certificate page for both kinds; links to the Sign-in page; core routers (no `enroll` / `enroll-self`; the people router on `client-cert-pem@file`);
  - §5.1: the `/signin` page and the D25 routes (the "exactly nine" count updated); fresh-auth redirect `…/signin`;
  - §8: fresh-auth client redirect URIs (D24); the `mtls` invariant rewritten (both CAs exist; D29; its tests named); the Hub owns the events config (D28);
  - §8.1: the methods table (`browser_cert`: a `pki_file` client certificate through the x509 authenticator, no "not available"); flows (two x509 executions and their configs, lazy CA load); the extension's history details and `PORTCULLIS_SIGNIN_URL`; Hub API `PUT /api/signin/limits` and `signin.limits`; D26;
  - §9.4: D23 (endpoints, shapes, errors, `kind`, `not_before`, `presented` as PEM); setup-link URL unchanged;
  - §9.6: "Four permissions can be granted", adding `sign_in_help` with D32's actions, targets and the administrator rules, in exactly D32's words;
  - §9.7: the person routes (D32);
  - §12 prose: "added domain" (D34);
  - a new §8.2 "Sign-in history" (D28: entry schema, sources, retention, ownership and modes, backup, part-3 hooks).
- Modify:
  - `docs/operations/auth-policies.md`: sections "The Sign-in page", "Browser certificates", "Help to reset", "Sign-in history", "Limits";
  - `docs/setup/certificates.md`: three parts by D34 name, `pki_file`, and the macOS note below;
  - `docs/operations/cli.md`: `cert` for both kinds, `pki setup`;
  - `docs/operations/hub.md`: Settings → Sign-in limits, Add domain, the person Sign-in tab;
  - `docs/operations/groups.md`: the `sign_in_help` permission;
  - `docs/operations/testing.md`: the new e2e cases (Task 13);
  - `docs/architecture.md`, `docs/operations/hardening.md`, `docs/operations/backups.md` (`group_gate_data`), `docs/setup/quickstart.md`, `docs/setup/dns.md`;
  - every other page that `git grep -il 'enroll\|client cert\|mtls' -- docs ':!docs/apps'` lists, swept per D34.

**Interfaces:**
- Produces: every shape later tasks implement (D23, D25, D27, D28, D32, D33).

- [ ] **Step 1:** In `wt-signin2/portcullis-docs`, write the sections above, copying every value from D21–D34. The operator pages also say:
  - a `.p12` imports into Firefox, Chrome / Edge (Windows 10+) and macOS Keychain Access (macOS 14 or newer; the encryption is AES-256);
  - the password is shown once, and Portcullis can't show it again;
  - a revoked certificate stops working within a minute;
  - a `sign_in_help` setup link hands the account to whoever holds it, so grant the permission only to people you'd trust with those accounts (the residual risk the ruling accepts).
- [ ] **Step 2:** Check the sweep. Run `git grep -n -i -E 'enroll\.<|/self\b|client certificate|enroll domain|enrolled domain' -- docs ':!docs/apps'`. Expected: it prints only setup-link URLs (`enroll.<domain>/invite`) and the `cert enroll` CLI. `docs/apps/*` are generated from templates and aren't part of this sweep.
- [ ] **Step 3:** Build in the docs venv: `zensical build --strict`. Expected: exit 0, no warnings.
- [ ] **Step 4:** Commit and push: `git add -A && git commit -m "contract: sign-in methods part 2 — Sign-in page, browser certificates (pki_file), history, sign_in_help, enroll retired, clear names" && git push -u origin signin2`.

---

### Task 2: Extension — certificate kinds, history details, Sign-in page links (keycloak)

**Files:**
- Modify:
  - `src/main/java/eu/portcullis/signin/X509Authenticator.java`;
  - `X509AuthenticatorFactory.java`: config properties `portcullis.method`, `portcullis.ca`;
  - `Methods.java`: `UNAVAILABLE` empty;
  - `TemplateAuthenticator.java`: history details; `certificateUser` uses the execution matching the leaf's CA; the `completable` case `browser_cert`; the needs-stronger links;
  - `Offer.java`: filters by each execution's `portcullis.method`;
  - `FreshMapper.java`: `isFreshMethod` includes `browser_cert`, and `getHelpText` says so; the strongest-method order of several methods is `yubikey_cert > security_key > passkey_device > browser_cert > passkey_synced > password` (review I2; `FreshMapperTest.browserCertBeatsSyncedPasskey`);
  - `CookieAuthenticator.java`: auth note `portcullis.sso`;
  - `PasswordForm.java`, `PasskeyAuthenticator.java`: failure details;
  - `src/main/resources/theme-resources/templates/portcullis-needs-stronger.ftl` and `messages_en.properties`: D34 names.
- Create: `src/main/java/eu/portcullis/signin/CaFile.java`, `History.java`.
- Modify, test resources and workflow:
  - `src/test/resources/smoke-realm.json`: this task writes D29's `portcullis-signin` flow by hand, and Task 12 makes core's `realm-export.json` match it;
  - `src/test/resources/signin_vectors.json`: a byte copy of the Hub's `vectors.json` after Task 3 is pushed;
  - `.github/smoke/run.sh`, `.github/smoke/signin.py` and `.github/workflows/build.yml`: the smoke step "x509 kinds".
- Test: `X509AuthenticatorTest.java`, `X509StepTest.java`, `TemplateAuthenticatorTest.java`, `NeedsStrongerTemplateTest.java`, `OfferTest.java`, `FreshMapperTest.java`, `PasswordFormTest.java`, `PasskeyAuthenticatorTest.java`, `CaFileTest.java` (new), `HistoryTest.java` (new).

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
  static String TemplateAuthenticator.signinPage(AuthenticationFlowContext c) // PORTCULLIS_SIGNIN_URL, else accountUrl(c)
  ```

- [ ] **Step 1: Write the failing tests**
  ```java
  @Test void browserLeafNeverMtls()      // yubikey execution + pki_file leaf → attempted, no note, no amr mtls
  @Test void yubikeyLeafNeverFile()      // browser execution + pki_int leaf → attempted
  @Test void browserLeafSignsInAsFile()  // browser execution, browser_cert on → success, note portcullis.x509.method = browser_cert
  @Test void caFileMissingStepsAside()   // portcullis.ca unreadable + a leaf presented → attempted, ERROR naming portcullis
  @Test void noLeafNeverReadsCaFile()    // no certificate → attempted, CaFile.load never called, no ERROR
  @Test void unknownMethodConfigStepsAside() // portcullis.method "mtls" → attempted
  @Test void issuedByChecksSignatureNotJustName() // a leaf whose issuer DN equals the CA's but signed by another key → false
  @Test void failureHasMethodAndUa()     // X509AuthenticatorTest: a refused browser leaf → LOGIN_ERROR details pc_method=browser_cert, pc_ua
  // PasskeyAuthenticatorTest: failureHasMethodAndUa()       // pc_method = the kind tried, pc_ua
  // PasswordFormTest: wrongPasswordEventHasMethodAndUa()    // pc_method=password, pc_ua
  // OfferTest: browserExecutionOfferedOnlyWhenBrowserCertOn()
  // FreshMapperTest: browserCertFreshIsBrowserCert()        // pc_fresh browser_cert (the Hub refuses it for certificates, D26)
  // TemplateAuthenticatorTest
  @Test void browserCertCompletableWithOwnLeaf() // rule any[browser_cert], the person's pki_file leaf presented → asks for browser_cert
  @Test void loginEventCarriesHistoryDetails()   // pc_kind sign_in, pc_methods "security_key", pc_session, pc_ua
  @Test void ssoReuseIsSso()                     // auth-cookie only → pc_kind sso, pc_methods ""
  @Test void stepUpKind()                        // SSO session + new method → step_up, pc_methods = the new one
  @Test void uaTruncatedAndCleaned()             // 300 chars with \n → 256, no control chars
  @Test void needsStrongerLinksToSigninPage()    // env set → every "Set up …" and "Sign-in methods" href == it; unset → accountUrl
  ```
- [ ] **Step 2: Run them to see them fail.** Run `docker build --target test .`. Expected: FAIL (compile errors / assertions).
- [ ] **Step 3: Implement** the classes with the interfaces above.
  - `issuedBy` uses only the JDK (`getIssuerX500Principal().equals`, `verify`).
  - Remove `browser_cert` from `UNAVAILABLE`.
  - The page copy uses the D34 names.
  - Write D29's flow into `smoke-realm.json`.
  - Copy the Hub's `internal/signin/testdata/vectors.json` from `wt-signin2/portcullis-hub` (after Task 3) byte for byte to `src/test/resources/signin_vectors.json`.
- [ ] **Step 4: Add the smoke step "x509 kinds"** to `.github/smoke/` and call it from `build.yml`.
  - Setup:
    - openssl in the job issues one leaf from a test "YubiKey CA" and one from a test "Browser CA";
    - mount both CA PEMs at the `portcullis.ca` paths under `--truststore-paths`;
    - start Keycloak with `--spi-x509cert-lookup--provider=traefik` and the proxy settings core uses (`docker-compose.yml` keycloak `command`);
    - post each leaf through the `traefik` lookup header on the smoke realm's browser flow.
  - Expected:
    - the YubiKey leaf's token amr ∋ `mtls` ∌ `file`;
    - the browser leaf's amr ∋ `file` ∌ `mtls`;
    - with `browser_cert` off, the browser leaf doesn't sign in;
    - the log grep for `portcullis.*ERROR` stays empty.
- [ ] **Step 5: Run them to see them pass.** Run `docker build --target test . && docker build .`, push, and check the smoke and vectors jobs. Expected: `BUILD SUCCESSFUL` and a green smoke job. "Compare the smoke realm with core's flows" passes once Task 12 is pushed; re-run it then. The vectors job passes once the Hub's `signin2` holds Task 3.
- [ ] **Step 6: Commit and push.** `git add -A && git commit -m "x509: tell YubiKey (pki_int) from browser (pki_file) certificates — mtls vs file; history event details; links to the Sign-in page" && git push -u origin signin2`.

---

### Task 3: Limits, the browser-certificate switch, Keycloak events config, core keys (hub)

**Files:**
- Modify:
  - `internal/state/signin.go`: `SignIn.Limits`, `CoreSignInKeys` without `enroll`, `EnsureSignIn` defaults;
  - `internal/signin/methods.go`: `browser_cert` `Available: true`;
  - `internal/signin/score.go`: `ScoreOfSet`;
  - `internal/signin/testdata/vectors.json`: rewrite the case "standard: browser certificate switched on but not available yet counts as off" so that a switched-on `browser_cert` counts;
  - `internal/signin/signin_test.go`: remove `TestBrowserCertUnavailable`;
  - `internal/hub/signin.go` / `signin_class.go`: the 409 gone; `SetSignInLimits`;
  - `internal/keycloak/events.go` (new);
  - `internal/hub/directory.go`: `RunDirectorySync` re-asserts the events config;
  - `cmd/hub/main.go`: `HUB_CLIENT_CERT_TTL`;
  - `internal/httpapi/signin.go` + `mcptools_signin.go`: `PUT /api/signin/limits`, `set_sign_in_limits`;
  - `mcp_parity_test.go`;
  - `internal/signinreset`: `browser_cert` still off on reset;
  - `internal/policy/policy.go`: `Tier` per D21's four TLS options, in this order — an `mtls` app → `protected@file`; every alternative of the compiled rule contains `yubikey_cert` → `protected@file`; every alternative has a switched-on certificate method → `TierProtectedAny = "protected-any@file"`; some alternative has one → `authaware@file`; else `public@file`. `HostTier` turns both `protected*` into `authaware@file` while the public router exists. `internal/hub` (exposure drift, the instance settings preview text) and `web/index.html`'s public warning name both options.
- Test: `internal/state/state_test.go`, `internal/signin/signin_test.go`, `internal/hub/signin_limits_test.go` (new), `internal/keycloak/events_test.go` (new), `internal/keycloak/access_test.go`, `internal/httpapi/signin_test.go`, `cmd/hub/main_test.go`.

**Interfaces:**
- Produces:
  ```go
  type SignInLimits struct {
    BrowserCertDays      int `json:"browser_cert_days" yaml:"browser_cert_days"`
    BrowserCertMaxActive int `json:"browser_cert_max_active" yaml:"browser_cert_max_active"`
    HistoryDays          int `json:"history_days" yaml:"history_days"`
  }
  func signin.ScoreOfSet(ms []Method) *Score // nil for none; all[ms…] by D4
  type LimitsView struct {
    Limits      state.SignInLimits `json:"limits"`
    CeilingDays int                `json:"ceiling_days"`
    Effective   state.SignInLimits `json:"effective"`
    Warning     string             `json:"warning,omitempty"`
  }
  func (h *Hub) SignInLimits() LimitsView
  func (h *Hub) SetSignInLimits(ctx context.Context, in state.SignInLimits, actor directory.Actor) (*LimitsView, error)
  func (c *keycloak.Client) EnsureEventsConfig(ctx context.Context, historyDays int) error
  func (h *Hub) SetEventsConfig(ensure func(ctx context.Context, days int) error) // wired in main; run by the sync loop
  func parseVaultDuration(s string) (time.Duration, error)                        // ^[0-9]+[smhd]?$, bare = seconds
  Config.ClientCertTTL time.Duration                                              // HUB_CLIENT_CERT_TTL
  ```

- [ ] **Step 1: Write the failing tests**
  ```go
  func TestEnsureSignInLimitsDefaults(t *testing.T) // 30, 3, 365; CoreSignInKeys has no "enroll"
  func TestBrowserCertCanBeSwitchedOn(t *testing.T) // SetMethod(browser_cert, true) OK, audited signin.method; Standard compiles with it
  func TestSharedVectors(t *testing.T)              // existing: the rewritten browser_cert case passes
  func TestScoreOfSet(t *testing.T)                 // [security_key] "3.5 / 5"; [browser_cert, security_key] "3.9 / 5"; [] nil
  func TestSetSignInLimitsBounds(t *testing.T)      // days 0 / ceiling+1 → 400; max 21 → 400; history 29 / 3651 → 400; audit "browser_cert_days 30 -> 10"
  func TestLimitsAboveCeilingApplyAsCeiling(t *testing.T) // stored 60, ceiling 30 → Effective 30, Warning non-empty
  func TestSetLimitsReassertsEvents(t *testing.T)   // history_days 90 → ensure called with 90
  func TestEnsureEventsConfigKeepsListeners(t *testing.T) // GET listeners [jboss-logging,x] → PUT same listeners, types [LOGIN LOGIN_ERROR], expiration 90*86400
  func TestHubRefusesBadClientCertTTL(t *testing.T) // unset / "abc" / "3600" (1 h → ceiling 0) → start refused; "2592000" and "720h" → 30 days
  func TestSignInLimitsToolClass(t *testing.T)      // days up → D; history down → D; max down → W
  func TestTierFourOptions(t *testing.T)            // internal/policy: any[yubikey_cert] and all[yubikey_cert, security_key] → protected; any[browser_cert], any[yubikey_cert, browser_cert] → protected-any; Standard → authaware; any[family:passkey] → public; mtls app → protected; public exceptions on → authaware for both protected options
  func TestAccessFlowCopiesBothX509Executions(t *testing.T) // internal/keycloak/access_test.go: both portcullis-x509 executions copied with their configs
  ```
- [ ] **Step 2: Run them to see them fail.** Run `go test ./internal/state/ ./internal/signin/ ./internal/hub/ ./internal/keycloak/ ./internal/httpapi/ ./cmd/hub/ -run 'Limits|BrowserCert|SharedVectors|ScoreOfSet|Events|ClientCertTTL|BothX509'`. Expected: FAIL.
- [ ] **Step 3: Implement** per D27 and D28 (events config), with the interfaces above.
- [ ] **Step 4: Run them to see them pass.** Run the same command, then the full Go checks. Expected: `ok`.
- [ ] **Step 5: Commit and push.** `git add -A && git commit -m "signin: browser certificates can be switched on (vector updated); limits; the Hub owns Keycloak's events config; no enroll core page" && git push -u origin signin2`.

---

### Task 4: enroll client and inventory — certificate kinds and actions (hub)

**Files:**
- Modify: `internal/invite/invite.go`, `internal/hub/signin_people.go` (kinds).
- Create: `internal/invite/certs.go`.
- Test: `internal/invite/invite_test.go`, `internal/invite/certs_test.go` (new), `internal/hub/signin_people_test.go`.

**Interfaces:**
- Produces:
  ```go
  type CertKind string // "yubikey" | "browser"; anything else drops the record (logged)
  type CertRecord struct{ User, Serial string; Kind CertKind; NotBefore, NotAfter time.Time; Revoked bool }
  type BrowserCertRequest struct{ User string; Days, MaxDays, MaxActive int }
  type BrowserCert struct{ P12 []byte; Password, Serial, Filename string; NotAfter time.Time }
  type IssuedCert struct{ PEM, Serial string; NotAfter time.Time }
  func (c *Client) CreateBrowserCertificate(ctx context.Context, r BrowserCertRequest) (*BrowserCert, error)
  func (c *Client) IssueYubiKeyCertificate(ctx context.Context, user, csrPEM string) (*IssuedCert, error)
  func (c *Client) RenewYubiKeyCertificate(ctx context.Context, user, presentedPEM, csrPEM string) (*IssuedCert, error)
  func (c *Client) RevokeCertificate(ctx context.Context, user, serial string) error
  ```
  Answer rules:
  - Non-2xx answers are the existing `*APIError{Status, Message}`, with `Message` ≤ 200 characters and never echoing a request body.
  - Bodies are ≤ 1 MiB.
  - `P12` and `Password` never appear in an error or a `String()`.

- [ ] **Step 1: Write the failing tests**
  ```go
  func TestCreateBrowserCertificateShape(t *testing.T) // fake enroll: request JSON exact, bearer; 201 decoded, P12 = base64-decoded bytes
  func TestCertificateActionsPassStatus(t *testing.T)  // 400/403/404/409 → APIError{Status, Message}; 503 → error
  func TestCertificatesKinds(t *testing.T)            // kind yubikey/browser kept, "other" dropped, not_before parsed
  func TestInventoryCertKinds(t *testing.T)           // yubikey → yubikey_cert, browser → browser_cert, revoked / expired → neither
  func TestBrowserCertNoSecretInErrors(t *testing.T)  // a decode failure after 201 never quotes the body
  ```
- [ ] **Step 2: Run them to see them fail.** Run `go test ./internal/invite/ ./internal/hub/ -run 'BrowserCert|CertificateActions|CertificatesKinds|InventoryCertKinds'`. Expected: FAIL.
- [ ] **Step 3: Implement.** The action URLs derive from the invites URL's directory, like `certificatesURL`.
- [ ] **Step 4: Run them to see them pass.** Same command. Expected: `ok`.
- [ ] **Step 5: Commit and push.** `git add -A && git commit -m "invite: enroll's certificate actions and kinds; inventory counts browser certificates" && git push`.

---

### Task 5: Sign-in history (hub)

**Files:**
- Create: `internal/signinhistory/entry.go`, `keycloak.go`, `opened.go`, `audit.go`, `merge.go`, `internal/hub/signin_history.go`.
- Modify:
  - `internal/keycloak/events.go`: `LoginEvents`;
  - `internal/hub/signin.go`: `SetSignInLimits` calls the prune when `history_days` changes;
  - `internal/templates/coreref.go`: `coreVolumes` gains `group_gate_data`;
  - `go.mod` / `go.sum`: `github.com/mileusna/useragent`, latest stable;
  - `cmd/hub/main.go`: `HUB_GROUP_GATE_DATA_DIR` (default `/group-gate-data`; the log is `<dir>/opened`) and `go h.RunHistoryPrune(ctx, 24*time.Hour)`.
- Test: `internal/signinhistory/*_test.go`, `internal/hub/signin_history_test.go`, `internal/keycloak/events_test.go`, `internal/templates/coreref_test.go`.

**Interfaces:**
- Consumes: Task 3 (`ScoreOfSet`, `HistoryDays`, `SetSignInLimits`).
- Produces:
  ```go
  type Kind string // sign_in step_up failed confirmed opened help certificate impersonation
  type Entry struct {
    Time    time.Time       `json:"time"`
    Kind    Kind            `json:"kind"`
    Methods []signin.Method `json:"methods"`
    Score   *signin.Score   `json:"score"`
    App     string          `json:"app"`
    IP      string          `json:"ip"`
    Browser string          `json:"browser"`
    By      string          `json:"by"`
    Reason  string          `json:"reason"`
    Detail  string          `json:"detail"`
  }
  type Source interface{ Entries(ctx context.Context, user string, since, before time.Time, limit int) ([]Entry, error) }
  func FromEvent(ev keycloak.Event, clientNames map[string]string) (Entry, bool)
  func FromAudit(e directory.AuditEntry, user string) (Entry, bool) // D28: help when actor ≠ user
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
  Reading rules:
  - `Next` is the oldest returned entry's time (RFC 3339 nano), or `""` at the end.
  - Each source's own read is capped at `limit+1`.
  - The opened log reads at most the newest 8 MiB of each day file and skips torn lines.

- [ ] **Step 1: Write the failing tests**
  ```go
  func TestFromEventKinds(t *testing.T) // LOGIN pc_kind sign_in pc_methods "security_key" → sign_in, [security_key], score 3.5;
  //  step_up; sso for a listed native client → opened "Nextcloud"; sso for portcullis-forward-auth → dropped;
  //  client portcullis-fresh-auth → confirmed; LOGIN_ERROR invalid_user_credentials pc_method password →
  //  failed "wrong password", [password]; unknown error → "sign-in failed"; unknown pc_methods value → dropped from Methods
  func TestLoginEventsQuery(t *testing.T) // GET /admin/realms/portcullis/events?user=<id>&type=LOGIN&type=LOGIN_ERROR&dateFrom=&dateTo=&max=; details decoded
  func TestOpenedLogDedupeAndUser(t *testing.T) // two lines same (session, host, day) → one; other users' lines never returned
  func TestOpenedLogPruneKeepsToday(t *testing.T) // days 30: a 31-day-old file removed, today's kept even with days 0 passed in
  func TestFromAuditOnlyListedActions(t *testing.T) // cert.create by alice → certificate; cert.revoke of alice by root → help By "root";
  //  user.remove_passkeys by bob → help By "bob"; user.password by root → help; user.invite by alice for herself → dropped;
  //  group.add → dropped; signin.password self → dropped
  func TestLimitsChangePrunes(t *testing.T) // SetSignInLimits history 365 → 30 calls Prune(30); unchanged history → no prune
  func TestMergeOrderAndLimit(t *testing.T)
  func TestHistoryRetention(t *testing.T)   // an entry older than history_days from any source is never returned
  func TestHistoryUnknownSource(t *testing.T) // Keycloak 500 → Unknown ["keycloak"], opened + audit still shown
  func TestBrowserName(t *testing.T)        // Firefox UA on macOS → "Firefox · macOS"; "" → ""
  func TestAddHistorySource(t *testing.T)   // an added source's entries merged; its failure named in Unknown
  func TestCoreNamesComplete(t *testing.T)  // existing; with core's signin2 checkout, group_gate_data is a reserved core volume
  ```
- [ ] **Step 2: Run them to see them fail.** Run `go test ./internal/signinhistory/ ./internal/hub/ ./internal/keycloak/ ./internal/templates/ -run 'Event|Opened|Audit|Merge|History|Browser|LimitsChangePrunes|CoreNames'`. Expected: FAIL.
- [ ] **Step 3: Implement** per D28. Keycloak's error → text table:

  | Keycloak error | Text |
  |---|---|
  | `invalid_user_credentials` | "wrong password" |
  | `user_not_found` | "unknown account" |
  | `user_disabled` | "account disabled" |
  | `user_temporarily_disabled` | "too many attempts: wait" |
  | `invalid_user_certificate` / `certificate_*` | "certificate refused" |
  | `different_user_authenticated` | "another person's certificate" |
  | `access_denied` | "access denied" |
- [ ] **Step 4: Run them to see them pass.** Same command, then the full Go checks. Expected: `ok`.
- [ ] **Step 5: Commit and push.** `git add -A && git commit -m "history: Keycloak sign-in events, group-gate's opened log and the audit, merged per person; retention and pruning; part-3 source hook" && git push`.

---

### Task 6: The Sign-in page service, the caller's routes and MCP twins (hub)

**Files:**
- Create: `internal/hub/mysignin.go`, `internal/hub/certificates.go` (incl. `presentedCertPEM`), `internal/httpapi/mysignin.go`, `internal/httpapi/mcptools_mysignin.go`, `web/mysignin.html` (a placeholder that Task 8 fills).
- Modify:
  - `web/web.go`: `mysignin.html` in the `//go:embed` list;
  - `internal/httpapi/server.go`: `peopleMux` gets `GET /signin` and the D25 routes;
  - `people_test.go`: the people listener allowlist;
  - `mcp_parity_test.go`;
  - `internal/directory/service.go`: `SetOwnPassword`, `RemoveOwnPassword`.
- Test: `internal/hub/mysignin_test.go`, `internal/hub/certificates_test.go` (with a `X-Forwarded-Tls-Client-Cert` fixture copied from a real Traefik header), `internal/httpapi/mysignin_test.go`, `internal/httpapi/mcptools_mysignin_test.go`.

**Interfaces:**
- Consumes: Tasks 3–5; `checkFreshAuthOn` + `freshGov` from `fresh-template`.
- Produces:
  ```go
  type MySignIn struct {
    User               string                   `json:"user"`
    Methods            []MethodRow              `json:"methods"`
    Certificates       []CertRow                `json:"certificates"`
    Apps               []AppNeed                `json:"apps"`
    Limits             LimitsView               `json:"limits"`
    ActiveBrowserCerts int                      `json:"active_browser_certs"`
    AddStronger        bool                     `json:"add_stronger"`
    FreshAuth          *freshauth.AuthorizeInfo `json:"fresh_auth"`
  }
  type MethodRow struct {
    ID signin.Method `json:"id"`; Label string `json:"label"`; On bool `json:"on"`
    State string `json:"state"` // set | none | unknown | off
    Passkeys []PasskeyRow `json:"passkeys,omitempty"`; PasswordSetAt *time.Time `json:"password_set_at,omitempty"`
  }
  type PasskeyRow struct{ Label string `json:"label"`; Kind signin.Method `json:"kind"`; CreatedAt time.Time `json:"created_at"` }
  type CertRow struct {
    Serial string `json:"serial"`; Kind string `json:"kind"`; Status string `json:"status"` // valid|expiring|expired|revoked
    NotBefore time.Time `json:"not_before"`; NotAfter time.Time `json:"not_after"`
  }
  type AppNeed struct {
    Kind string `json:"kind"` /* instance|core */; ID string `json:"id"`; Name string `json:"name"`
    Template string `json:"template"`; TemplateName string `json:"template_name"`; Score signin.Score `json:"score"`; OK *bool `json:"ok"`
  }
  func (h *Hub) MySignInView(ctx context.Context, user string) (*MySignIn, error)
  func (h *Hub) CreateBrowserCertificate(ctx context.Context, user string, days int, p freshauth.Proof) (*invite.BrowserCert, error)
  func (h *Hub) RevokeOwnBrowserCertificate(ctx context.Context, user, serial string) error
  func (h *Hub) RenewYubiKeyCertificate(ctx context.Context, user, headerValue, csrPEM string) (*invite.IssuedCert, error)
  func presentedCertPEM(headerValue string) (string, error) // D25: first entry → DER → parsed X.509 → PEM
  func (h *Hub) SetOwnPassword(ctx context.Context, user, password string, p freshauth.Proof) error
  func (h *Hub) RemoveOwnPassword(ctx context.Context, user string) error
  func certFreshAllowed(peopleRule signin.Node, on map[signin.Method]bool) []signin.Method // D26: FreshAccepted minus password, browser_cert
  ```
  The rules each piece follows:
  - **Methods:** all six methods are listed in canonical order. A switched-off one has `State: "off"`, which the page shows as "off on this server".
  - **Apps:** every enabled instance whose population includes the user, plus the core pages `people` (everyone) and `hub` (admins). `OK` is nil while the inventory doesn't know the person.
  - **Certificate status:** `expiring` when fewer than `CERT_EXPIRY_WARN_DAYS` days are left (the Hub reads `HUB_CERT_EXPIRY_WARN_DAYS`, core sets `${CERT_EXPIRY_WARN_DAYS:-7}`; unset → 7; not a positive integer → the Hub refuses to start).
  - **Own certificates:** administrators create, renew and revoke their own certificates on the Sign-in page like anyone else; `admin`, `portcullis-hub` and `portcullis-*` get 409 (D32, review I3).
  - **Routes under `/api/me/signin/`:** the people listener registers only the D25 routes there; any later route there that adds a method needs D26's proof (group-gate lets any switched-on method reach these paths, D24).
  - **One create at a time:** `CreateBrowserCertificate` takes a per-user lock and passes `Days`, `MaxDays` (= the effective `browser_cert_days`) and `MaxActive` to enroll.

- [ ] **Step 1: Write the failing tests**
  ```go
  func TestMySignInMethodStates(t *testing.T)       // six rows in canonical order; password off → State "off"; browser_cert on → listed with certs
  func TestMySignInShowsRevoked(t *testing.T)       // enroll record revoked → CertRow.Status "revoked"; expired → "expired"; 5 days left → "expiring"
  func TestMySignInJSONNames(t *testing.T)          // marshalled keys: active_browser_certs, add_stronger, fresh_auth, password_set_at, not_before, ceiling_days
  func TestMySignInApps(t *testing.T)               // gitea on standard, person has security_key → OK true; strong core hub only for admins
  func TestCreateBrowserCertFreshRules(t *testing.T) // people on strong: pc_fresh security_key OK; passkey_synced 403;
  //  password 403; browser_cert 403 even when people's template is any[browser_cert, security_key];
  //  people on any[password] → 409 "creating a certificate needs …" before any proof is spent
  func TestCreateBrowserCertPassesLimits(t *testing.T) // days 0 / > effective → 400 before enroll; enroll gets MaxDays/MaxActive
  func TestCreateBrowserCertOffRefused(t *testing.T)   // browser_cert off → 409, enroll not called
  func TestCertAuditHasNoSecrets(t *testing.T)         // cert.create detail "browser <serial> until <date>", no password / base64
  func TestRevokeOwnOnlyBrowser(t *testing.T)          // own yubikey serial → 404; another's serial → 404; own browser → enroll revoke, audit cert.revoke
  func TestPresentedCertPEM(t *testing.T)              // Traefik fixture (URL-escaped, two entries) → PEM of the first; garbage → error
  func TestRenewUsesPresentedCert(t *testing.T)        // no header → 403 "present your current YubiKey certificate"; enroll gets real PEM;
  //  the caller's browser leaf, or another person's YubiKey leaf → 403, enroll not called (review I1)
  func TestOwnCertificatesProtectedNames(t *testing.T) // admin / portcullis-hub / portcullis-x create, renew or revoke → 409; an lldap_admin member creates a browser cert → 200
  func TestExpiringFollowsWarnDays(t *testing.T)       // HUB_CERT_EXPIRY_WARN_DAYS 10 → 9 days left is "expiring"; unset → 7
  func TestOwnPasswordRules(t *testing.T)              // method off → 409; CheckPassword failures → 400; admin → 409; record set_by self; sign-out called
  // httpapi
  func TestCreateBrowserCertAnswerNoStore(t *testing.T) // 200 headers Cache-Control no-store, Pragma no-cache; body has p12, password, filename
  func TestMySignInRoutesCallerOnly(t *testing.T)       // no X-Forwarded-User 401; no username in any path; Hub listener 404
  func TestPeopleListenerHasNoAppRoutes(t *testing.T)   // existing test, allowlist updated with the D25 routes and GET /signin
  func TestMySignInToolClasses(t *testing.T)            // my_sign_in R, revoke_my_certificate W, handoffs R and carry no secret
  ```
- [ ] **Step 2: Run them to see them fail.** Run `go test ./internal/hub/ ./internal/httpapi/ ./internal/directory/ -run 'MySignIn|BrowserCert|CertAudit|RevokeOwn|PresentedCert|Renew|OwnPassword|PeopleListener|ToolClasses'`. Expected: FAIL.
- [ ] **Step 3: Implement** per D24–D26. `GET /signin` serves the embedded `mysignin.html`.
- [ ] **Step 4: Run them to see them pass.** Same command, then `go vet -tags harness ./internal/httpapi/...` and the full Go checks. Expected: `ok`.
- [ ] **Step 5: Commit and push.** `git add -A && git commit -m "people: the Sign-in page's API — methods, certificates, apps and what they need; browser certificates; renewal; own password" && git push`.

---

### Task 7: Help to reset — `sign_in_help` and the person's Sign-in routes (hub)

**Files:**
- Modify:
  - `internal/directory/authz.go`: `PermSignInHelp = "sign_in_help"` in `delegatedPerms`;
  - `internal/directory/service.go`: `SendInvite` / `RemovePasskeys` accept `PermSignInHelp`; a `sign_in_help` invite skips `checkKeyless` / `created_by`; detail `as sign_in_help`;
  - `internal/httpapi/directory.go`: the D32 person routes;
  - `internal/httpapi/mcptools_directory.go`: the `set_permission` description and enum gain `sign_in_help`;
  - `mcp_parity_test.go`.
- Create: `internal/hub/signin_help.go`, `internal/httpapi/signin_help.go`, `internal/httpapi/mcptools_signin_help.go`.
- Test: `internal/directory/help_test.go` (new), `internal/directory/authz_test.go`, `internal/hub/signin_help_test.go` (new), `internal/httpapi/signin_help_test.go` (new).

**Interfaces:**
- Consumes: Tasks 4–6.
- Produces:
  ```go
  const PermSignInHelp = "sign_in_help"
  func (s *Service) CheckHelp(ctx context.Context, c *Caller, target string) error // admin, or holder + checkDelegateTarget (fresh snapshot)
  type PersonSignIn struct{ MySignIn; Can HelpCan `json:"can"` }
  type HelpCan struct {
    SetupLink      bool `json:"setup_link"`
    RemovePasskeys bool `json:"remove_passkeys"`
    Revoke         bool `json:"revoke"`
    Issue          bool `json:"issue"`
    Password       bool `json:"password"`
  }
  func (h *Hub) PersonSignInView(ctx context.Context, c *directory.Caller, user string) (*PersonSignIn, error)
  func (h *Hub) RevokePersonCertificate(ctx context.Context, c *directory.Caller, user, serial string) error
  func (h *Hub) IssueYubiKeyCertificate(ctx context.Context, c *directory.Caller, user, csrPEM string, p freshauth.Proof) (*invite.IssuedCert, error)
  ```

- [ ] **Step 1: Write the failing tests**
  ```go
  func TestHelpScope(t *testing.T) // permissions.sign_in_help = "hr"; bob ∈ hr; alice ordinary, with passkeys:
  //  bob → alice: invite 200 (no keyless refusal), remove passkeys 200, revoke 204 (audit detail "as sign_in_help");
  //  bob → alice password 403; bob → alice issue 403; bob → bob 403; bob → root (lldap_admin) 403;
  //  bob → a member of another permission group 403; bob removed from hr → next call 403 (fresh snapshot);
  //  carol holding only invite → remove passkeys 403
  func TestSignInHelpIsGrantable(t *testing.T)   // PUT /api/directory/permissions/sign_in_help {group: "hr"} OK; hr members are permission-group members
  func TestAdminCertificateTargets(t *testing.T) // admin revoke / issue on another administrator → 409 with D32's text; on admin, portcullis-hub,
  //  portcullis-breakglass → 409 "this account's certificates are managed from the server: …" (review I3); on alice OK
  func TestAdminTakeoverUnchanged(t *testing.T)  // admin removes another admin's passkeys / sets their password: typed confirmation still required, then OK
  func TestPersonSignInView(t *testing.T)        // admin: Can all true for alice, SetupLink/Issue/Revoke false for an administrator;
  //  holder: Password false, Issue false; anyone else 403; history route the same rule
  func TestIssueYubiKeyFresh(t *testing.T)       // D26 rules as for browser certificates; enroll 400 CSR text passed through
  func TestHelpToolClasses(t *testing.T)         // revoke_person_certificate D, remove_passkeys D; set_permission accepts sign_in_help
  ```
- [ ] **Step 2: Run them to see them fail.** Run `go test ./internal/directory/ ./internal/hub/ ./internal/httpapi/ -run 'Help|SignInHelp|AdminCertificateTargets|AdminTakeover|PersonSignIn|IssueYubiKey'`. Expected: FAIL.
- [ ] **Step 3: Implement** per D32. `gate` treats `PermSignInHelp` like every delegated permission, re-confirming it against the snapshot and then running `checkDelegateTarget`. The admin path is untouched.
- [ ] **Step 4: Run them to see them pass.** Same command, then the full Go checks. Expected: `ok`.
- [ ] **Step 5: Commit and push.** `git add -A && git commit -m "people: help to reset — the sign_in_help permission, the person's Sign-in tab API, certificate issue and revoke" && git push`.

---

### Task 8: Hub UI — the Sign-in page, the person's Sign-in tab, limits, clear names (hub)

**Files:**
- Modify (filling Task 6's placeholder): `web/mysignin.html`.
- Create: `web/mysignin.js`.
- Modify:
  - `web/web.go`: `mysignin.js` in the embed list;
  - `internal/httpapi/server.go`: `mysignin.js` in `peopleStatic`;
  - `web/people.html` / `web/directory.js`: top nav "Sign-in" → `/signin`; the person page tab "Sign-in"; the Permissions table lists `sign_in_help` "Help with sign-in (setup link, remove passkeys, revoke certificates)";
  - `web/signin.js`: Settings → Sign-in gains browser certificate and history limits; the "available" note goes;
  - `web/index.html`: Add domain and D34 copy, including `:894`'s comment;
  - the Hub's domain error texts lose "enroll" (contract §12, Task 1 fix round 1, choice 10): `internal/hub/domains.go` "is already enrolled" → "is already added", "re-enroll it" → "add it again" (also the `missing` `last_error` and its log line), `internal/hub/hosts.go` "re-enroll it before giving it new hostnames" → "add it again before giving it new hostnames", "can't be enrolled" → "can't be added", "under / above the enrolled domain … (enrolled domains never nest)" → "added domain … (added domains never nest)";
  - the AI certificate texts (contract §15.11): `internal/hub/ai_instance.go` `certRefusal` = "needs a YubiKey or browser certificate on every sign-in; AI clients can't present one", `aiCertOffDetail` = "sign-in needs a YubiKey or browser certificate", and the matching `internal/doctor/ai.go` texts;
  - `web/freshauth.js` / `web/freshauth-callback.js`: the people redirect `…/signin`; the callback header says so;
  - `cmd/hub/main.go`: the people `RedirectURI` `https://people.<d>/signin`;
  - `internal/keycloak/freshauth.go`: `checkFreshAuthURIs` (people path `/signin`, hub path `/`);
  - the `enroll_domain` → `add_domain` and `domain.enroll` → `domain.add` rename: `internal/httpapi/mcptools_admin2.go`, `mcptools_admin2_test.go`, `mcp_parity_test.go`, `internal/httpapi/domains.go` (comment), `domains_test.go`, `internal/hub/domains.go`, `internal/hub/domains_test.go`;
  - `web/docs/*`: `PORTCULLIS_DOCS_DIR=/Volumes/workspace/portcullis/wt-signin2/portcullis-docs go generate ./web`.
- Test: `internal/httpapi/webui_mysignin_test.go` (new), `webui_signin_test.go`, `webui_people_links_test.go`, `internal/httpapi/server_test.go` (`TestDirectoryAssetsServed`), `internal/keycloak/freshauth_test.go`, `cmd/hub/main_test.go`, `web/web_test.go`.

**Interfaces:**
- Consumes: the routes of Tasks 3, 5–7, and their JSON names.

The page follows mockup sections 1 and 3:
- **Method rows:**
  - password: set / Change / Remove;
  - passkeys and security keys: a list with kind and date; "+ Add" → the account console's signing-in page;
  - YubiKey certificate: validity; Renew shows the `ykman` CSR commands from enroll's old page, then a field to paste the CSR;
  - browser certificate: a list; Create → a days field (default and max = the limit) → the fresh-auth popup → the download button and the password side by side, with "This password is shown only now" and Copy;
  - a switched-off method shows "off on this server".
- **Below the methods:**
  - "Apps and what they need" (✓ / ✗ / ?);
  - Sign-in history: newest first, "Show older" via `next`, and a line naming any `unknown` source.
- **Person tab (admin / `sign_in_help` holder):** the same rows, with only the actions `can` allows.
- **Downloading:**
  - the `.p12` downloads through a `Blob` URL that is revoked right after the click;
  - the password and the bytes live only in that dialog's closure and are dropped when it closes;
  - nothing goes to `localStorage` / `sessionStorage` except the fresh-auth state.

- [ ] **Step 1: Write the failing tests** (node tests run against the served pages, plus Go tests)
  ```go
  func TestMySignInPageRendersMockupRows(t *testing.T) // fixture MySignIn (JSON names) → rows in method order, "off on this server", ✓/✗/?
  func TestMySignInDownloadDialog(t *testing.T)        // after a create: one download link (blob:), password shown once, gone after close
  func TestMySignInEscapes(t *testing.T)               // a passkey label "<img onerror>" and a history UA rendered as text
  func TestMySignInLoadsCallbackFirst(t *testing.T)    // freshauth-callback.js is the first script in <head>
  func TestPersonSignInTabActions(t *testing.T)        // can{revoke:true} → Revoke buttons only; no "Reset password" for a holder
  func TestPermissionsTableListsSignInHelp(t *testing.T)
  func TestSettingsLimitsForm(t *testing.T)            // ceiling shown; out-of-range refused client-side with the server's bounds
  func TestNoEnrollWording(t *testing.T)               // served Hub and people pages contain no "Enroll domain", "enroll.", "/self", "client certificate"
  func TestFreshAuthClientRedirects(t *testing.T)      // exactly [https://people.<d>/signin, https://hub.<d>/]; checkFreshAuthURIs refuses people "/"
  func TestPeopleVerifierRedirect(t *testing.T)        // cmd/hub: the people verifier's RedirectURI is https://people.<d>/signin
  func TestDirectoryAssetsServed(t *testing.T)         // existing, extended: /static/mysignin.js served on the people listener
  func TestDocsCopiesInSync(t *testing.T)              // existing; runs (not skipped) with PORTCULLIS_DOCS_DIR set
  ```
- [ ] **Step 2: Run them to see them fail.** Run `PORTCULLIS_DOCS_DIR=/Volumes/workspace/portcullis/wt-signin2/portcullis-docs go test ./internal/httpapi/ ./internal/keycloak/ ./cmd/hub/ ./web/ -run 'MySignIn|PersonSignInTab|PermissionsTable|SettingsLimits|NoEnrollWording|FreshAuthClientRedirects|PeopleVerifier|DirectoryAssets|DocsCopies'`. Expected: FAIL.
- [ ] **Step 3: Implement** the pages and the D34 sweep in the Hub's UI and MCP texts, then regenerate `web/docs`.
- [ ] **Step 4: Run them to see them pass.** Same command (with `PORTCULLIS_DOCS_DIR`), then the full Go checks. Expected: `ok`, with `TestDocsCopiesInSync` run, not skipped.
- [ ] **Step 5: Commit and push.** `git add -A && git commit -m "web: the Sign-in page and the person's Sign-in tab; limits; sign_in_help; Add domain and the clear certificate names" && git push`.

---

### Task 9: Internal certificate authority — `pki_file`, Vault policy, `cert` CLI (core)

**Files:**
- Modify:
  - `scripts/lib/pki.sh` and `vault/policies/enroll.hcl`: D21;
  - `scripts/lib/certs.sh`, covering both mounts:
    - `_cert_info <mount> <serial>`;
    - `cert list` gains the KIND column;
    - `cert revoke` finds the mount and rotates its CRL;
    - `write_revoked_serials` writes the union of `pki_int/certs/revoked` and `pki_file/certs/revoked`, and any failure leaves the file unchanged;
    - the help texts use D34 names;
  - `portcullis`: help.
- Test: `tests/test_cli.sh`, `tests/test_shell_libs.sh`.

**Interfaces:**
- Produces: `certs/browser-ca.crt`, `certs/yubikey-ca.crt`, the truststore files of D21, the role `pki_file/roles/browser-cert`, and the enroll policy paths.

- [ ] **Step 1: Write the failing tests** (with a stubbed `vault`, as the existing pki tests do)
  - `test_shell_libs.sh`:
    - `pki_setup on a fresh Vault enables pki, pki_int, pki_file; ca-chain.crt has 3 certificates in order root, pki_int, pki_file; ca-chain-yubikey.crt has exactly root, pki_int`
    - `pki_setup with pki_int present but no pki_file creates pki_file only, keeps pki_int, rewrites ca-chain.crt to 3 certificates, ca-chain-yubikey.crt and the truststore, and sets PKI_TRUSTSTORE_CHANGED=true`
    - `pki_setup with all three present and the chain current but ca-chain-yubikey.crt missing (or holding pki_file) rewrites it and sets PKI_TRUSTSTORE_CHANGED=true`
    - `pki_setup with all three present and both chains current leaves PKI_TRUSTSTORE_CHANGED unset`
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
- [ ] **Step 5: Commit and push.** `git add -A && git commit -m "pki: a separate CA for browser certificates (pki_file); cert CLI covers both kinds" && git push -u origin signin2`.

---

### Task 10: enroll — browser certificates, YubiKey issue / renew / revoke, site retired (core)

**Files:**
- Create: `enroll/browsercert.go`, `enroll/certapi.go`.
- Modify:
  - `enroll/main.go`:
    - `publicMux(srv, inv)` keeps only `/invite/*` and `/healthz`;
    - `issuedCertsWith` covers both mounts, with `kind` and `not_before`;
    - `main` injects the D23 operations into `inviteService` as function fields, like `listCertificates`;
  - `enroll/self.go`: `checkRenewal` and `lookupIssued` stay (the lookup takes a mount); the handlers and `presentedCert` go;
  - `enroll/invite.go`: `apiHandler` registers D23;
  - `enroll/go.mod` / `go.sum`: `software.sslmate.com/src/go-pkcs12`, latest stable.
- Delete: `enroll/web/index.html`, `users.html`, `certs.html`, `enroll.html`, `self.html`.
- Test: `enroll/browsercert_test.go` (new), `enroll/certapi_test.go` (new), `enroll/main_test.go`, `enroll/self_test.go`.

**Interfaces:**
- Consumes: Task 9's role and policy.
- Produces: D23's endpoints, and:
  ```go
  func newBrowserPassword() (string, error) // "XXXXX-XXXXX-XXXXX-XXXXX", Crockford base32
  func (cfg *Config) issueBrowserCert(ctx context.Context, user string, days, maxDays, maxActive int) (*browserCertResult, error)
  type browserCertResult struct{ P12 []byte; Password, Serial, Filename string; NotAfter time.Time }
  func (cfg *Config) revokeCert(ctx context.Context, user, serial string) error
  func certKind(mount string) string // "pki_int" → "yubikey", "pki_file" → "browser"
  func publicMux(srv *Server, inv *inviteService) *http.ServeMux
  // inviteService gains: issueBrowser, issueYubiKey, renewYubiKey, revoke (func fields, nil = 503)
  ```

- [ ] **Step 1: Write the failing tests** (with a fake Vault `httptest` server, as `vault_auth_test.go` does)
  ```go
  func TestBrowserCertP12Decodes(t *testing.T) // pkcs12.DecodeChain(P12, password) → EC P-256 key matching the leaf;
  //  leaf CN == user, issuer == the browser CA, chain [browser CA, root]; signed via pki_file/sign/browser-cert, ttl "720h" for 30 days
  func TestBrowserCertPasswordShape(t *testing.T)  // matches ^[0-9A-HJKMNP-TV-Z]{5}(-[0-9A-HJKMNP-TV-Z]{5}){3}$; 1000 draws distinct
  func TestBrowserCertTTLCeiling(t *testing.T)     // days 31 with max_days 30 → 400; days 31 with CERT_TTL 720h → 400; days 0 → 400
  func TestBrowserCertMaxActive(t *testing.T)      // 3 active (1 revoked + 1 expired not counted) → 4th 409 with the D22 text
  func TestBrowserCertMaxActiveConcurrent(t *testing.T) // 10 parallel creates with max 3 → exactly 3 succeed
  func TestBrowserCertSecretsNeverLogged(t *testing.T)  // log output holds the serial and user, never the password or any base64 of the p12/key
  func TestCertAPINeedsBearer(t *testing.T)        // every D23 route 401 without / with a wrong bearer
  func TestCertAPIStrictBodies(t *testing.T)       // unknown field, trailing data, > 64 KiB → 400 / 413
  func TestCertAPIUnwired503(t *testing.T)         // a nil operation field → 503
  func TestCertAPIProtectedNames(t *testing.T)     // every D23 action with user admin, portcullis-hub, Portcullis-X → 409 "protected account", Vault not called (review I3)
  func TestRenewRefusesBrowserLeaf(t *testing.T)   // presented = a pki_file leaf with CN = user (or a leaf whose issuer DN matches pki_int but signed by another key) → 403, nothing signed (review I1)
  func TestYubiKeyIssueValidatesCSR(t *testing.T)  // CSR CN ≠ user → 400; good CSR → signed on pki_int/sign/client-cert with common_name user
  func TestRenewChecksPresented(t *testing.T)      // checkRenewal cases moved from self_test; "presented" must be a PEM CERTIFICATE (else 400)
  func TestRevokeFindsMountAndOwner(t *testing.T)  // pki_file serial of alice by user alice → revoke + pki_file/crl/rotate;
  //  by user bob → 404; unknown → 404; already revoked → 204, no second revoke
  func TestCertificatesBothMountsKinds(t *testing.T) // yubikey + browser records, revoked listed, one unreadable cert → 503 for all
  func TestPublicMuxOnlyInvite(t *testing.T)       // publicMux: GET / , /users, /certs, /self, POST /api/sign, /api/self/renew → 404; /invite/x → invite page
  ```
- [ ] **Step 2: Run them to see them fail.** Run `cd enroll && go test -race ./...`. Expected: FAIL.
- [ ] **Step 3: Implement** per D22, D23 and D31.
- [ ] **Step 4: Run them to see them pass.** Run `cd enroll && go vet ./... && go test -race ./...`. Expected: `ok`.
- [ ] **Step 5: Commit and push.** `git add -A && git commit -m "enroll: browser certificates (.p12, generated password, never kept), YubiKey issue / renew / revoke on the internal API; its pages go" && git push`.

---

### Task 11: group-gate — two CAs, binding by issuer, Sign-in paths, opened log, links (core)

**Files:**
- Modify:
  - `group-gate/group-gate.py`;
  - `tests/signin_vectors.json` and `mcp-gate/internal/signin/testdata/signin_vectors.json`: byte copies of the Hub's `signin2` `internal/signin/testdata/vectors.json` (after Task 3).
- Test: `tests/test_group_gate.py`, `cd mcp-gate && go test ./...` (the vectors).

**Interfaces:**
- Produces:
  ```python
  CRL_URLS: list[str]; DELTA_CRL_URLS: list[str]          # GATE_CRL_URLS / GATE_DELTA_CRL_URLS, space-separated
  GATED_CORE_SUBDOMAINS = ("traefik", "hub", "directory", "people", "metrics")  # no "enroll"; CORE_SUBDOMAINS unchanged
  def leaf_cert_issuer_cn(raw: str) -> Optional[str]
  def ca_subject_cn(path: str) -> Optional[str]            # cached by (inode, mtime, size)
  def cert_method(cert_info: str) -> Optional[str]          # "yubikey_cert" | "browser_cert" | None (D29)
  def session_methods(amr: list, enabled: set, bound: set) -> set  # bound: the cert methods this request binds
  def signin_path(host: str, raw_path: str) -> bool         # D24: people host, normalize_path_candidates ok, every candidate in the set
  class OpenedLog:
      def __init__(self, directory: str, capacity: int = 10000): ...
      def record(self, user, session, host, app, methods, ip, ua, act="") -> None  # never raises; files 0640, dir 2770 group 10001
  def render_certificate_page(app: str, method: str) -> bytes
  ```
  Also:
  - `/authenticated` goes.
  - The needs-stronger and step-up pages link to `https://people.<domain>/signin`.
  - The portal's own links are People and Sign-in methods (`/signin`), plus the Hub, Keycloak and Traefik for admins.

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
  def test_enroll_not_gated_but_reserved(): # "enroll" ∉ GATED_CORE_SUBDOMAINS, ∈ CORE_SUBDOMAINS; core_hosts() has no enroll.<d>
  def test_opened_log_first_request_per_session_host(): # 3 requests same sid+host → 1 line; other host → 2nd line;
      # fields exact, act "", ua ≤ 256; file mode 0640; unwritable directory → request still allowed, failure counter + 1
  def test_pages_link_to_signin_page(): # needs-stronger "Set up …" and "Sign-in methods" hrefs == https://people.<d>/signin
  def test_no_enroll_links(): # portal HTML has no "enroll." and no "/self"
  def test_shared_vectors(): # existing, against the copied vectors
  ```
- [ ] **Step 2: Run them to see them fail.** Run `python3 tests/test_group_gate.py`. Expected: FAIL.
- [ ] **Step 3: Implement** per D24 and D28–D31. Pin Traefik's `Issuer="…"` format with a fixture copied from a real header (as `leaf_cert_cn`'s tests do). Copy the vectors.
- [ ] **Step 4: Run them to see them pass.** Run `python3 tests/test_group_gate.py && (cd mcp-gate && go test ./...)`. Expected: `OK` and `ok`.
- [ ] **Step 5: Commit and push.** `git add -A && git commit -m "group-gate: YubiKey vs browser certificates by issuer; both CAs' CRLs; the Sign-in page reachable with any method; the opened log; links to the Sign-in page; vectors" && git push`.

---

### Task 12: Compose, realm, `keycloak configure`, CI checks, leftover texts (core)

**Files:**
- Modify: `docker-compose.yml`:
  - **enroll:** drop the `enroll` and `enroll-self` routers and the `portcullis-self` middleware;
  - **people router:** `client-cert-pem@file` replaces `client-headers@file`;
  - **group-gate:**
    - `group_add: ["10001"]`;
    - volume `group_gate_data:/data`;
    - `./certs/yubikey-ca.crt` and `./certs/browser-ca.crt` mounted read-only under `/etc/group-gate/ca/`;
    - `GATE_CRL_URLS`, `GATE_DELTA_CRL_URLS`, `GATE_YUBIKEY_CA_FILE`, `GATE_BROWSER_CA_FILE`, `GATE_OPENED_DIR=/data/opened`;
  - **hub:** `group_gate_data:/group-gate-data` (read-write, D28), `HUB_CLIENT_CERT_TTL: ${CLIENT_CERT_TTL:-720h}`, `HUB_GROUP_GATE_DATA_DIR: /group-gate-data`;
  - **keycloak:** `PORTCULLIS_SIGNIN_URL: https://people.${PORTCULLIS_DOMAIN:-portcullis.local}/signin`;
  - the volume `group_gate_data` itself.
- Modify: `keycloak/realm-export.json`, matching the keycloak repo's `smoke-realm.json` (Task 2):
  - the second x509 execution in `portcullis-signin`, with `x509-browser-config`;
  - `portcullis.method` / `portcullis.ca` on both configs;
  - `x509-config`'s CRLs stay `pki_int`'s, and `x509-browser-config`'s are `pki_file`'s;
  - `eventsEnabled`, `enabledEventTypes`, `eventsExpiration` 31536000.
- Modify, core scripts and checks:
  - `scripts/lib/keycloak.sh`: push each x509 config by its alias; never touch the events config;
  - `group-gate/group-gate-map.conf`: no `enroll=`;
  - `scripts/lib/common.sh`: `CT_UID_GROUP_GATE=10003`, `volume_own group_gate_data "$CT_UID_GROUP_GATE:$CT_UID_HUB"`;
  - `scripts/lib/backup.sh`: `group_gate_data:$CT_UID_GROUP_GATE:$CT_UID_HUB` in `BACKUP_FILE_VOLUMES`;
  - `.github/workflows/ci.yml`: drop the `portcullis-self` assertions (lines 217, 245, 368) and `"enroll."` from the core policy keys (1275, 2617); add a compose check pinning `group_gate_data` to exactly group-gate (rw) and hub (rw), like the `mcp_gate_data` check (352–353); the static TLS check expects exactly the four D21 options (`protected` → `caFiles: [/certs/ca-chain-yubikey.crt]`, `protected-any` and `authaware` → `[/certs/ca-chain.crt]`, `public` none); `build-and-test` checks both chain files (`ca-chain.crt` root + `pki_int` + `pki_file`, `ca-chain-yubikey.crt` root + `pki_int`, no `pki_file`).
  - `traefik/dynamic/tls.yml`: the four options of D21 (`protected` on `/certs/ca-chain-yubikey.crt`, new `protected-any`); the header comment says which uses which. Traefik's existing `./certs:/certs:ro` mount carries both chain files.
  - `docker-compose.yml` hub: `HUB_CERT_EXPIRY_WARN_DAYS: ${CERT_EXPIRY_WARN_DAYS:-7}`.
- Modify, leftover texts (D31 / D34): `.env.example`, `monitoring/prometheus/alerts.yml`, `scripts/lib/status.sh`, `keycloak/themes/portcullis/login/messages/messages_en.properties`, core `docs/*.md`, `README.md`, `CLAUDE.md`.
- Test: `tests/test_cli.sh`, `tests/test_shell_libs.sh`.

**Interfaces:**
- Consumes: Tasks 9–11; the extension's config keys and smoke flow (Task 2).

- [ ] **Step 1: Write the failing tests** (`test_cli.sh` unless named)
  - `no router in docker-compose.yml routes enroll.<domain> except enroll-invite (PathPrefix /invite/)`
  - `no portcullis-self middleware and no "/authenticated" anywhere`
  - `the people router uses client-cert-pem@file, before portcullis-groups@docker`
  - `group-gate mounts group_gate_data read-write, has group_add 10001, and both CA files read-only; GATE_CRL_URLS lists pki_int and pki_file`
  - `hub mounts group_gate_data; HUB_CLIENT_CERT_TTL follows CLIENT_CERT_TTL`
  - `realm-export: portcullis-signin = x509 (x509-config, mtls, yubikey CA), x509 (x509-browser-config, file, browser CA), passkey sub-flow, password form, in that order`
  - `realm-export: each x509 config's CRL paths name only its own mount`
  - `realm-export: events LOGIN, LOGIN_ERROR, expiration 31536000`
  - `keycloak configure pushes x509-browser-config onto the browser execution and x509-config onto the YubiKey one (stubbed kc_get / kc_put)`
  - `group-gate-map.conf has no enroll entry`
  - `no file in the repo matches enroll\.[^ ]*/self, and none outside contract internals says "client certificate"`
  - `test_shell_libs.sh`: `the stack's volume setup owns group_gate_data 10003:10001; BACKUP_FILE_VOLUMES lists group_gate_data`
- [ ] **Step 2: Run them to see them fail.** Run `bash tests/test_cli.sh; bash tests/test_shell_libs.sh`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them to see them pass.** Run `bash tests/test_cli.sh && bash tests/test_shell_libs.sh` and `shellcheck -S warning portcullis scripts/lib/*.sh tests/*.sh`. Expected: pass, no output. Push, then re-run the keycloak repo's "Compare the smoke realm with core's flows" job.
- [ ] **Step 5: Commit and push.** `git add -A && git commit -m "core: enroll.<domain> serves only setup links; browser-certificate flow and CRLs; group-gate data and CA files; Keycloak events kept a year; leftover enroll texts" && git push`.

---

### Task 13: Core CI and browser e2e (core)

**Files:**
- Modify:
  - `tests/e2e/e2e_signin.py`: the cases below; the fresh-auth redirect at `:506` → `PEOPLE + "/signin"`;
  - `tests/e2e/e2e_filesharing.py`: the fresh-auth redirect at `:904` → `PEOPLE + "/signin"`;
  - `tests/e2e/e2e_login.py`: the renewal case at `:532-538` moves to `POST https://people.<d>/api/me/signin/yubikey-certificate/renew`;
  - `.github/workflows/ci.yml`: e2e-signin wiring, if any is needed.

**Interfaces:**
- Consumes: everything above.

- [ ] **Step 1: Write the failing e2e cases** in `e2e_signin.py`:
  - `browser_cert_create_download`:
    - Setup: switch `browser_cert` on (Hub API). Alice does a fresh auth with her virtual security key, then `POST https://people.<d>/api/me/signin/browser-certificates {days: 30}`.
    - Expected: 200 with `no-store`. `pkcs12.load_key_and_certificates(p12, password)` gives an EC key and a leaf with CN `alice`, issuer the browser CA and `not_after` ≈ now + 30 d. The `cert.create` audit entry contains neither the password nor base64.
  - `browser_cert_fresh_refused_weak`: a fresh auth with a synced passkey under Strong gets 403 "a fresh sign-in is required".
  - `browser_cert_max_active`: two more creates succeed and the fourth gets 409.
  - `browser_cert_signin_file`:
    - Setup: alice has no other session, an app sits on `any[browser_cert]`, and her browser context carries `client_certificates` from the `.p12`.
    - Expected: she signs in with the certificate only, the app opens, the token amr ∋ `file` ∌ `mtls`, and `kc_log` has no `mtls` for her.
  - `browser_cert_not_yubikey`: the same session on an app on `any[yubikey_cert]` gets `#needs-stronger` (or `#present-certificate` for the YubiKey). Keycloak with `pc_method=yubikey_cert` and that certificate doesn't sign her in.
  - `yubikey_cert_still_mtls`: a `pki_int` certificate that CI issues through Vault signs in with amr ∋ `mtls`.
  - `browser_cert_revoked`: `DELETE /api/me/signin/certificates/<serial>`. Expected within 70 s: the app answers 403, `GET /api/me/signin` shows `revoked`, and `published()` people no longer lists `browser_cert` for alice.
  - `signin_page_reachable_weak`: password on, bob signed in with a password only. `/signin` and `/api/me/signin` answer 200. `/api/directory`, and `/signin/../api/directory` sent as a raw, unnormalised path (`http.client` with the path written as-is), get `#needs-stronger`.
  - `sign_in_help_actions`: `PUT …/permissions/sign_in_help {group: "hr"}`. Then hr-member carol:
    - sends alice a setup link (200), removes her passkeys (200), and revokes her certificate (204);
    - gets 403 for setting alice's password, for acting on root, and for acting on herself;
    - gets 409 from the admin issue / revoke routes on root (as an admin).
  - `history_entries`: alice's `/api/me/signin/history` has a `sign_in` with methods `[browser_cert]` and a non-empty browser, a `step_up`, `opened` for the app's host, `help` by carol, and `certificate` entries. bob's history has a `failed` entry (his wrong password).
  - `browser_cert_cannot_renew` (review I1): alice's browser certificate presented on `POST /api/me/signin/yubikey-certificate/renew` with a CSR for its key → 403 "present your current YubiKey certificate", nothing issued.
  - `tls_protected_yubikey_ca_only`: `echo-cert` (`e2e-cert` = any[`yubikey_cert`] → `protected@file`, the option `mtls` apps get): `openssl s_client`'s "Acceptable client certificate CA names" lists only the root and the YubiKey CA.
  - `tls_mtls_refuses_browser_cert`: a handshake to that host with alice's browser certificate fails; with root's YubiKey certificate it succeeds.
  - `tls_protected_any`: an instance `echo-anycert` on `e2e-anycert` = any[`yubikey_cert`, `browser_cert`] is on `protected-any@file`; its CA names list the root and both CAs; a handshake with alice's browser certificate succeeds and one without a certificate fails.
  - `enroll_site_gone`: `https://enroll.<d>/` and `/self` answer 404, while `/invite/<bad token>` shows the invite page's "no longer usable".
- [ ] **Step 2: Run to see it fail.** Push and let CI run e2e-signin. Expected: the new cases FAIL before the CI wiring.
- [ ] **Step 3: Implement** the CI wiring and the moved cases in `e2e_login.py` / `e2e_filesharing.py`.
- [ ] **Step 4: Run to see it pass.** CI on `signin2` (core) is green: `unit-tests`, `build-and-test`, `e2e`, `e2e-instances`, `e2e-signin`, `e2e-settings`, `e2e-folders`, `e2e-filesharing` and `e2e-ai`, with the Hub and the Keycloak image built from `signin2`.
- [ ] **Step 5: Commit and push.** `git add -A && git commit -m "ci: browser certificates, the mtls / file invariant, revocation, sign_in_help, history e2e" && git push`.

---

### Task 14: Mainline (all repos)

- [ ] **Step 1:** Merge docs `signin2` → main and push.
- [ ] **Step 2:** Merge portcullis-keycloak `signin2` → main and push. Wait for `build.yml` to publish `:edge` (`gh run list -R porelli/portcullis-keycloak --branch main --workflow build.yml` shows success). Its vectors job compares against the Hub's `main`: it passes with a notice until Step 3.
- [ ] **Step 3:** Merge hub `signin2` → main and push. Wait for `ghcr.io/porelli/portcullis-hub:edge` (`gh run list --branch main --workflow build.yml` shows success). Then re-run the keycloak repo's vectors job: it passes with no notice (all four copies match the Hub's).
- [ ] **Step 4:** Merge core `signin2` → main and push. Check that CI is green on main, including "Shared sign-in vectors match the Hub".
- [ ] **Step 5:** Re-run templates `test-apps.yml` on main. Expected: green, with no templates change.
- [ ] **Step 6:** Delete every `signin2` branch (local and remote, four repos) and the worktrees under `/Volumes/workspace/portcullis/wt-signin2/`.
- [ ] **Step 7:** Upgrade the test server under the standing OK: `ACME_STAGING=true`, `./portcullis pki setup && ./portcullis config apply && ./portcullis up`.
  - `pki setup` creates `pki_file`, rewrites the chain and flags the truststore change, which restarts Traefik and Keycloak.
  - `vault init`, run by `up`, rewrites the enroll policy.

---

## Self-review

1. **Spec coverage.**
   - **Sign-in page** (always reachable; every method with its state and actions; "off on this server"; apps and what they need): D24, D25, Tasks 6, 8 and 11.
   - **Adding a stronger method:** D14 is unchanged (passkeys on Keycloak); certificates follow D26.
   - **Help to reset** (admins and the delegated `sign_in_help` holders; setup link, remove passkeys, revoke; no password; delegates never act on an administrator; history and audit): D32 (rulings F13, F14), Tasks 7 and 5.
   - **Admin-only actions on someone else's page** (issue a YubiKey certificate via CSR, revoke any, setup link, remove passkeys, reset password): D32, Task 7. "Sign in as" is part 3.
   - **Browser certificates** (fresh touch, server-generated key, `pki_file`, `.p12` once, key never kept, limits, revocation, revoked shown everywhere): D21, D22, D26, D27 and D30, Tasks 9, 10 and 6.
   - **Telling the methods apart by issuing CA, and the `mtls` invariant with its tests:** D29, Tasks 2, 11 and 13.
   - **History** (successes, failures, step-ups, every method, score, app, IP, browser; impersonation hooks; help shown as help): D28, Task 5.
   - **enroll retired** (user list and pages gone; setup links and issuing kept; the step-up page links to the Sign-in page; leftover texts): D31, Tasks 10–12.
   - **Clear names** (including "Enroll domain"): D34, Tasks 1, 2, 8, 9, 11 and 12.
   - **Anti-goals:** a browser certificate passing a YubiKey rule (Review Focus 1); private keys stored or re-downloadable (D22, Review Focus 3).
   - **Out of scope:** impersonation and its banner (part 3; hooks in D28).
2. **Step scan.**
   - Every step names its files, signatures, tests with their assertions, and the command to run.
   - Every commit step uses `git add -A`.
   - Bodies appear only for fixed copy (error texts, the Keycloak error table).
   - Left to the implementer: the page layout within the mockup, and the two Traefik fixtures (the issuer info header and the PEM header), pinned from real headers.
3. **Type consistency.**
   - `invite.CertRecord{Kind}`, `BrowserCert{P12}`, `IssuedCert` and `APIError{Status, Message}` come from Task 4 and are used in Tasks 6–7. enroll's `browserCertResult{P12}` comes from Task 10.
   - `LimitsView` (Task 3) is used in Task 6. `signin.ScoreOfSet` and `SetSignInLimits` (Task 3) are used in Task 5.
   - `MySignIn` (Task 6) is embedded in `PersonSignIn` (Task 7). Their JSON names are fixed in the Interfaces blocks and used by Task 8.
   - `PermSignInHelp` / `sign_in_help` is the same name in Task 7, Task 8 (the Permissions table), Task 13 and the contract (Task 1).
   - `presentedCertPEM` (Task 6) produces the PEM that D23 / Task 10 expect.
   - The config keys `portcullis.method` / `portcullis.ca` and the aliases `x509-config` / `x509-browser-config` match across Tasks 2 and 12. `smoke-realm.json` is written only in Task 2.
   - The environment variables match: `GATE_CRL_URLS`, `GATE_DELTA_CRL_URLS`, `GATE_YUBIKEY_CA_FILE`, `GATE_BROWSER_CA_FILE` and `GATE_OPENED_DIR` (Tasks 11–12); `HUB_CLIENT_CERT_TTL` and `HUB_GROUP_GATE_DATA_DIR` (Tasks 3, 5 and 12); `PORTCULLIS_SIGNIN_URL` (Tasks 2 and 12).
   - The ownership rule `10003:10001` and the modes 2770 / 0640 are the same in D28 and Tasks 11–12.
   - The redirect `https://people.<d>/signin` is the same in D24 and Tasks 8 and 13.
4. **Review Focus.** Each of its five lines names a test in its owning task. Max-active races, TTL ceilings and strict bodies are pinned in Task 10 too.
5. **Proportion.** About 100 KB, the same as part 1's 102 KB. Its code blocks are signatures and test names.
