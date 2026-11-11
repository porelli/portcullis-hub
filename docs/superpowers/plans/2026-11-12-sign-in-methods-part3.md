# Sign-in methods, part 3 of 3 (admin impersonation) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An administrator can sign in as another person and act in their apps:
- it needs a fresh YubiKey touch and a typed reason;
- it ends after 30 minutes or on Stop;
- every Portcullis page shows it while it runs;
- the person's history and the admin audit record it, and the person is told at their next sign-in.

**Architecture:**
- **Start.** The Hub checks the rules and the admin's fresh touch. It then publishes a one-time *pending* record in `hub_data/impersonation.json`, bound to the admin's Keycloak session id, and sends the admin's browser to a Portcullis endpoint inside Keycloak (`/realms/portcullis/portcullis-impersonate/start`). That endpoint is a realm resource of the extension, written along the lines of Keycloak's own `UserResource.impersonate`. It:
  - checks the record against the browser's identity cookie;
  - ends the admin's own session;
  - creates the person's session, carrying the admin's methods plus the fresh touch and the impersonation notes;
  - sets the cookie and sends the browser through oauth2-proxy to the portal.
- **Claims.** A protocol mapper on the `acr` scope puts `act` and `pc_imp` into every token of such a session.
- **Enforcement.** group-gate checks those claims against the file on every request, binds certificates to the admin, never steps up, adds the banner and passes the impersonator to the Hub. mcp-gate refuses such tokens. The extension refuses every client except the apps and every new method.
- **End.** It happens at 30 minutes, on Stop or when the switch goes off:
  - group-gate denies at once;
  - the extension's task removes the Keycloak session within 15 s;
  - oauth2-proxy's 1-minute refresh then fails, and Stop in the impersonating browser also signs out of oauth2-proxy.
- **Record.** The audit holds the durable record. The history is a fourth source (`AddHistorySource("impersonation", …)`). The notice is a Keycloak required action the Hub adds at the end.

**Tech Stack:** Go 1.27 (Hub, mcp-gate), Python 3 + PyJWT (group-gate), Java 21 + Gradle with dependency verification (Keycloak 26.8.1 SPI: `RealmResourceProviderFactory`, `RequiredActionFactory`, `ProtocolMapper`, `TimerProvider`, JPA entity), vanilla JS (Hub UI), bash (core CLI).

**Spec:** `docs/superpowers/specs/2026-11-09-sign-in-methods-design.md` (Hub repo): "Impersonation (full)", anti-goal "Impersonation without a fresh hardware touch, a reason and a record the person can see", call 5, and call 8 part (3).

**Mockup:** `.superpowers/brainstorm/98502-1794260205/content/signin-people.html` section 3 (the "Sign in as alice…" row) and section 4 (the banner).

**Model and conventions:** `docs/superpowers/plans/2026-11-11-sign-in-methods-part2.md`. D1–D34 stay in force, and part 3 continues with D35–D46. Part 2's ledger lessons also hold:
- the fresh-auth governing-template rule;
- the four TLS options;
- the Valkey session store;
- the history hook.

## Global Constraints

Process and checks (parts 1–2's rules, restated):
- **Precondition:** `signin2` (hub, keycloak, docs, core, including the session store, core 088d571 and later) is mainlined. Every part-3 branch starts from that `main`.
- **Branches and worktrees.** Branch `signin3` in docs, keycloak, hub and core, mainlined at the end, with no PRs. The worktrees are `/Volumes/workspace/portcullis/wt-signin3/{portcullis-docs,portcullis-keycloak,portcullis-hub,portcullis}`, and each task works in its repo's worktree. The templates repo isn't changed; its CI is re-run in Task 12.
- **Every commit step stages new files:** `git add -A && git commit -m "…"`.
- **No migration / back-compat code.** The new state field defaults to "on" by its zero value (D36). The extension's new table is a new changeSet, which is setup, not migration.
- **Contract first:** Task 1 changes `docs/guides/integration-contracts.md` before any code.
- **Never weaken access control; fail closed.** Any of these means "not impersonating, deny":
  - an unreadable or invalid `impersonation.json`;
  - a malformed `act` / `pc_imp` claim;
  - an unknown or ended impersonation id;
  - a claim whose admin or person disagrees with the file;
  - a past `until`.

  An impersonated session never adds a method, never confirms a fresh sign-in, never completes a required action and never reaches an AI tool.
- **Secrets stay out of argv, logs, the audit, errors and URLs.** Nothing secret travels in the start URL: the pending id is not a bearer, because only the browser holding the admin's own Keycloak session can use it (D38). The reason is not a secret, but it never goes into a token, a URL or a log line. It lives in the audit, the file and the user-session note only.
- **Identity is the LLDAP username** throughout: `act.sub`, the file, the headers and the audit.
- **Shared sign-in vectors** don't change in part 3, because template evaluation is unchanged. Task 9 checks that the four copies are still byte-identical.
- **Web UI:** vanilla JS, everything escaped, data-* attributes plus delegated listeners.
- **Go checks (Hub):** the same as part 2, with `PORTCULLIS_DOCS_DIR=/Volumes/workspace/portcullis/wt-signin3/portcullis-docs`:
  - gofmt go1.27.3 prints nothing;
  - `go vet ./...` and `go vet -tags harness ./internal/httpapi/...` pass;
  - `go test -race ./...` ends `ok` for every package.
- **Core checks:** `shellcheck -S warning portcullis scripts/lib/*.sh tests/*.sh`, `bash tests/test_cli.sh`, `bash tests/test_shell_libs.sh`, `python3 tests/test_group_gate.py`, `cd mcp-gate && go test -race ./...`.
- **Keycloak repo checks:** `docker build --target test .` (ends `BUILD SUCCESSFUL`), `docker build .`, the vectors check and the smoke job.
- **Docs build:** `zensical build --strict` in the docs venv.
- **Core CI** on `signin3` builds the Hub and the Keycloak image from `signin3`.
- **Merge order:** docs → portcullis-keycloak (wait for `edge`) → hub (wait for `edge`) → core. Then re-run templates CI.
- **Standing OK (2026-11-11):** merge each piece to main and upgrade the test server (`ACME_STAGING=true`) once reviews are clean and every CI is green. Still stop for destructive or out-of-plan security-sensitive actions, and for EC2 runners.

User rulings for part 3 (binding):
- **What it is:** full impersonation. An admin signs in as another person and acts in their apps. There is no approval step.
- **Who:**
  - only `lldap_admin` members may do it;
  - never on another administrator or the Hub's service account;
  - a Settings switch turns the feature off, and it is on by default.
- **To start:** a fresh YubiKey touch by the admin (`security_key` or `yubikey_cert`, never a synced passkey, a password or a browser certificate) and a typed reason.
- **To end:** after 30 minutes or on Stop.
- **The banner:** on every Portcullis page (the portal, My apps, People and the sign-in pages), "You are signed in as <person> (by <admin>) · reason · N min left · Stop". Apps can't show it, and that is accepted.
- **Apps with their own sessions** may outlast it. That is accepted, and the person's history says so.
- **The record:** the history and the admin audit show who, when, the reason and the apps opened. The person sees it at their next sign-in ("<admin> signed in as you on …: reason").
- **Call 5:** an impersonated session meets a template only if the admin's own current session methods would, the fresh touch included. Certificate checks (the mTLS binding) use the ADMIN's certificate.

Decisions (made here; the spec leaves the mechanics to the builder):
- **D35 Mechanism: Portcullis's own start inside Keycloak, never Keycloak's impersonation.**
  - **Recon (Keycloak 26.8.1 `keycloak-services`, `UserResource.impersonate`, disassembled).** What the endpoint does:
    - it requires the `IMPERSONATION` feature and the `impersonation` admin role;
    - in the same realm it backchannel-logs-out the caller's own session and expires the identity, remember-me and auth-session cookies;
    - it creates the session with `UserSessionManager.createUserSession(realm, user, username, ip, "impersonate", false, null, null)`;
    - it sets the session notes `IMPERSONATOR_ID` / `IMPERSONATOR_USERNAME` (`ImpersonationSessionNote`);
    - it sets the login cookie in **its own response** and returns `{redirect: <account console>, sameRealm}`.

    The notes reach no token without a mapper. The endpoint has no time limit, no reason and no step-up. Because its cookies go to whoever calls it, the Hub (on `hub.<d>`) can't hand them to a browser on `auth.<d>`. Standard token exchange (V2) can't impersonate, and legacy V1 isn't enabled. **The endpoint is unusable for this.**
  - **Our endpoint.** The extension adds the realm resource `portcullis-impersonate` (`GET /realms/portcullis/portcullis-impersonate/start?id=<id>`). It follows the same steps as Keycloak's endpoint (D38), but runs in the admin's browser and uses that browser's own identity cookie.
  - **The stock path is closed.** Core starts Keycloak with `--features-disabled=impersonation`, so the stock endpoint answers "feature disabled" even for a Keycloak console admin, and no impersonation can skip the touch, the reason or the record. A CI check pins this, and nothing else uses the feature.
  - **No authenticator in the flows.** Setting a different user inside the browser flow would trip Keycloak's `attachSession` "different user" check against the admin's root session, so the switch happens only in the resource. The flows don't change, apart from the checks in D39 / D42.
- **D36 Rules for starting.** The Hub checks them in this order. Each refusal is audited `impersonation.start` with result `refused`, and the reason text is written only for the admin's own refusals.
  1. **The switch** `state.yaml` `sign_in.impersonation_off` (bool, zero = on) is off → 409 "signing in as someone else is switched off (Settings → Sign-in)".
  2. **The caller** isn't an administrator in a fresh directory snapshot → 403 (the directory's standard text).
  3. **The target:**
     - unknown → 404;
     - the caller → 409 "you can't sign in as yourself";
     - `invite.ProtectedName` (admin, portcullis-hub, every portcullis-*) → 409 "this account can't be signed in as";
     - an administrator → 409 "administrators can't be signed in as";
     - disabled in Keycloak → 409 "this account is disabled".
  4. **The reason:** trimmed, 3–200 runes, one line, no control or bidi characters → else 400 "type a reason (3–200 characters, one line)".
  5. **One at a time:**
     - the caller already runs one → 409 "you are signed in as <x> until <hh:mm>: Stop it first";
     - the target is already impersonated → 409 "<admin> is signed in as <target> right now".
  6. **Unfinished steps:** the target's Keycloak required actions are anything other than `portcullis-impersonation-notice` (a setup link in progress, for example) → 409 "<target> has an unfinished sign-in step (a setup link?): finish or cancel it first". Otherwise the admin would register their own key on the person's account.
  7. **No touch method:** neither `security_key` nor `yubikey_cert` is on → 409 "signing in as someone needs security keys or YubiKey certificates switched on". This is checked before the proof is exchanged.
  8. **The admin's session id:** the `sid` of the caller's `X-Forwarded-Access-Token`. Its payload is decoded without verifying, inside the trust boundary, as group-gate does: oauth2-proxy verified it, Traefik strips client copies, and the proxy secret holds. Missing → 403 "your sign-in can't be read: sign in again".
  9. **The fresh touch:** `freshauth.Verifier.Verify(proof, caller)` on the request's listener. `Method` must be in `{security_key, yubikey_cert}` and on, else the standard 403 "a fresh sign-in is required". Templates don't govern this proof, and `checkFreshAuthOn`'s outage answers (503) apply.

  The lengths are fixed:
  - the pending record lives 120 s;
  - `until = started + max_minutes`, where `max_minutes` = `HUB_IMPERSONATION_MAX_MINUTES` (an integer 1–30, default 30). An unset variable means 30, and anything else refuses to start the Hub. The variable can only shorten. CI sets 2 for the expiry case.
- **D37 The published file `hub_data/impersonation.json`** (mode 0644, written atomically, version 1). The Hub writes it at start, at end, on the switch, on any instance or client change, and every 60 s. Keycloak and group-gate read it, cached by (inode, mtime, size). The shape:
  ```json
  {"version": 1, "allowed": true, "written": "<RFC 3339>",
   "clients": ["portcullis-forward-auth", "<every enabled instance's signInClientIDs>"],
   "pending": [{"id","admin","admin_sid","target","reason","fresh","fresh_at","created","until"}],
   "sessions": [{"id","admin","target","reason","started","until","ended"}],
   "notices": {"<target>": [{"id","admin","started","ended","reason","apps":[{"name","own_session"}]}]}}
  ```
  - **`id`:** 32 lowercase hex characters (16 bytes from `crypto/rand`).
  - **`sessions`:** the running ones, plus those ended in the last hour (`ended` is null while running).
  - **`notices`:** used impersonations (D44) that ended within `history_days`.
  - **`clients`:** never the fresh-auth client or `isHubAIClient` ids.
  - **Readers fail closed:**
    - a missing, unreadable, invalid or newer-version file means `allowed: false`, nothing pending and nothing live;
    - group-gate also treats a file older than 300 s (`written`) as unreadable, so a Hub that stopped writing ends every impersonation within 5 minutes;
    - every reader logs the failure once per change.
- **D38 Starting, end to end.**
  1. On the person's page, the admin chooses "Sign in as alice…", types a reason and does the fresh sign-in, as the D26 certificate dialog does.
  2. The browser sends `POST /api/directory/users/{username}/impersonation {reason, code, code_verifier, nonce}`, which is allowed on both listeners.
  3. The Hub checks D36, records `state.SignIn.Impersonations` (status pending), writes the file and audits `impersonation.start`. The detail is `"<id> · <fresh method> · <reason>"`, with actor the admin and target the person. The answer is 200 `{id, next, until}`, where `next = https://auth.<d>/realms/portcullis/portcullis-impersonate/start?id=<id>`.
  4. The page navigates the top window to `next`.
  5. The resource (`ImpersonationResource.start`) runs, in this order. Every refusal is the page `portcullis-impersonating.ftl` (mode `refused`, 403) and logs `portcullis: impersonation <id> refused: <why>`.
     - `ImpersonationFile.allowed()`;
     - the pending record with this id exists, `created` is under 120 s old, and it is used for the first time: `session.singleUseObjects().putIfAbsent("pc_imp:" + id, 300)`;
     - `AuthenticationManager.authenticateIdentityCookie(session, realm, true)` gives a session whose id equals `admin_sid` and whose user's username equals `admin`;
     - the admin is in the Keycloak group `lldap_admin`;
     - the target exists and is enabled. It has no service-account link, isn't `admin` or `portcullis-*`, isn't in `lldap_admin`, isn't the admin, and has no required action other than the notice;
     - the methods are computed, as described below;
     - `AuthenticationManager.backchannelLogout(…, adminSession, …)` and `expireIdentityCookie` / `expireRememberMeCookie` / `expireAuthSessionCookie`;
     - `new UserSessionManager(session).createUserSession(realm, target, target.getUsername(), ip, "portcullis-impersonate", false, null, null)`, and on the new session:
       - `IMPERSONATOR_ID` / `IMPERSONATOR_USERNAME` (Keycloak's names, so the admin console shows them);
       - `portcullis.imp.id`, `portcullis.imp.until` (epoch seconds), `portcullis.imp.reason`;
       - `AUTHENTICATORS_COMPLETED` = the computed methods;
     - `AuthenticationManager.createLoginCookie(…)`;
     - the event `IMPERSONATE` (user = target) with details `pc_imp` = id and `pc_act` = admin;
     - 302 to `<auth base>/oauth2/start?rd=<PORTCULLIS_PORTAL_URL>`. The env is set by core to `https://${PORTCULLIS_DOMAIN}/`; unset or not http(s) means the refused page.
  6. oauth2-proxy runs the authorize, and `auth-cookie` reuses the new session (D42), so the person's portal opens with the banner.

  **The methods (call 5):** the admin session's `AUTHENTICATORS_COMPLETED` entries are copied with their own times. If the `fresh` method's amr isn't among them, the extension adds the realm execution whose authenticator config's `default.reference.value` is `Methods.amrOf(fresh)`, with time `fresh_at`. If no such execution exists, the start is refused. The admin loses their own session at start (Keycloak's same-realm behaviour) and signs in again after Stop.
- **D39 Call 5: whose methods and whose certificate.**
  - **The session's methods** are exactly the admin's (D38), so the amr, `Methods.ofSession` and every template check see the admin's methods, the touch included.
  - **group-gate:**
    - for an impersonated request, `bound_cert_method(leaf, username)` is called with the admin's username (`act.sub`): the presented certificate must be the admin's (CN = admin, unrevoked), and a certificate of the person's never counts;
    - `claims.preferred_username` must still equal the forward-auth username (the person);
    - there is never a step-up, because the person's session can't gain the admin's methods. An unmet template shows `render_needs_page` in its impersonation form: "<App> needs <methods>. <admin>'s sign-in didn't use them, and a session as <person> can't add one: Stop, sign in with them, and start again." It has a Stop link and no "Set up" links.
  - **Keycloak (native-OIDC apps):** `TemplateAuthenticator` evaluates the session's methods as today. In an impersonated session it never asks for a method (no `ask`, no x509 completion) and shows `portcullis-impersonating.ftl` (mode `needs`) instead of the needs-stronger page.
  - **mcp-gate** refuses every token with `act` or `pc_imp` (D42), which is stricter than call 5.
  - **The Hub** has no template check of its own; group-gate's applies.
- **D40 Claims and headers.**
  - **Mapper `portcullis-impersonation`** (`ImpersonationMapper`, an OIDC access, ID and userinfo mapper with a fixed claim name). When the user session has `portcullis.imp.id` it emits:
    - `act` = `{"sub": "<admin username>"}` (RFC 8693's actor claim);
    - `pc_imp` = `{"id": "<id>", "until": <epoch seconds>}`.

    The reason is never emitted. Core puts the mapper `impersonation` on the `acr` client scope, next to the amr mapper (realm-export and `keycloak configure`), so every client with amr (forward-auth, Hub app clients, AI clients) carries it.
  - **group-gate headers.** On allow, group-gate adds `X-Forwarded-Impersonator: <admin>` and `X-Forwarded-Impersonation: <id>`. Both names are added to the `authResponseHeaders` of `portcullis-groups`, `portcullis-auth`, `portcullis-auth-ext` and `portcullis-auth-console`, so a client-sent copy is always deleted. Apps receive them too, which is documented (§5).
  - **The opened log's `act`** = the admin's username.
  - **The extension's LOGIN events** in an impersonated session carry `pc_act` = admin.
- **D41 Ending: what kills what.** An impersonation ends on Stop, at `until`, or when the switch goes off. The Hub's `RunImpersonationExpiry` checks every 5 s.
  - **The Hub:**
    - sets `ended` and `how`: `stopped` (by whom), `expired` or `switched_off`;
    - writes the file;
    - audits `impersonation.end` (actor = who stopped it, or `portcullis` for expiry and the switch). The detail is `"<id> · <how> · <n> min · apps opened: A, B"` (or `"none"`; `not used` when D44 finds no `IMPERSONATE` event);
    - adds the notice required action when it was used (D45).

    A pending record that was never used ends `not used` after 120 s, with no notice.
  - **group-gate:** the next request with that `pc_imp.id` (claim not live, D37) gets the "ended" page (403) on every host: "Your session as <person> has ended." with a link to sign out (`https://auth.<d>/oauth2/sign_out?rd=https%3A%2F%2F<d>%2F`).
  - **Keycloak:** `ImpersonationExpiry` (portcullis-task, `ClusterAwareScheduledTaskRunner`, every 15 s) walks the user sessions of every target the file names, and of the last good file's targets when the file can't be read. It backchannel-logs-out any session whose `portcullis.imp.id` isn't live or whose `until` has passed. That also sends Keycloak's backchannel logout to apps that registered one. The cookie and template checks (D42) do the same at once for a browser that comes back.
  - **oauth2-proxy (Valkey store):**
    - Stop in the impersonating browser ends with `oauth2-proxy /oauth2/sign_out`, which deletes the ticket's Valkey key and clears the cookie, and the backend logout runs.
    - Any other end (another admin's Stop, expiry, the switch) leaves the ticket until oauth2-proxy's `cookie_refresh` (1 min) fails against the removed Keycloak session; group-gate has already denied it.
    - The Hub gets no Valkey access: ticket ids are only in cookies, and the ACLs stay per service.
  - **Accepted:**
    - a native-OIDC app that keeps its own session may outlast the end (D44 says so);
    - an extra-domain host's existing forward-auth-ext cookie of the admin's own (now logged-out) session can act as the admin for up to 1 minute after the start. That is the admin's own identity, which is today's behaviour after any sign-out.
- **D42 What an impersonated session may do.**
  - **Apps:** every gateway app and every native-OIDC app the person may open.
  - **Keycloak:**
    - in a browser whose identity cookie is an impersonated session, every authentication must be for a client in the file's `clients`, use only the SSO cookie (no authenticator ran a method in it), have no `pc_method` and no `prompt=login`, and its session must be live;
    - otherwise it gets `portcullis-impersonating.ftl` (mode `refused`: "Not while you are signed in as <person>", with Stop);
    - a session that is no longer live is logged out, and the page shows mode `ended`;
    - this covers fresh-auth, AI clients, the account console and step-ups. `CookieAuthenticator` and `TemplateAuthenticator` both check it;
    - `PasskeyRegister` refuses in an impersonated session, and the notice action ignores it (D45).
  - **The Hub:** both listeners refuse every request that isn't GET or HEAD while `X-Forwarded-Impersonation` is set, except `POST /api/me/impersonation/stop`. The answer is 403 "not while you are signed in as someone else: Stop first". That covers My apps values, credentials, AI connections, passwords, certificates, confirmations and delegated directory actions. Reads work.
  - **AI:**
    - mcp-gate answers 403 (reason `impersonated`, message "a session as someone else can't use AI tools") for any token with an `act` or `pc_imp` claim, before membership;
    - Keycloak never issues such a token to an AI client (above);
    - there's no MCP tool that starts it (D46).
- **D43 The banner.** The text is fixed:
  `You are signed in as <person> (by <admin>) · reason “<reason>” · <n> min left` plus a **Stop** button, where `n = ceil(remaining / 60 s)` (at least 1).
  - **group-gate** pages (the portal, needs-stronger, step-up, present-certificate, ended and every deny page) render it server-side from the file record (`render_banner`), escaped, with Stop → `https://people.<d>/impersonation/stop`.
  - **Hub people listener** pages (`people.html`: My apps and People; `mysignin.html`; the Stop page) load `web/impersonation.js`. It fetches `GET /api/me/impersonation`, shows the banner, counts down once a minute, and on Stop POSTs `/api/me/impersonation/stop` and then navigates to `sign_out`. When the time runs out it reloads.
  - **The extension's pages** (`portcullis-impersonating.ftl`, `portcullis-needs-stronger.ftl`) render it from the session's notes.
  - **group-gate's Sign-in paths** (D24) gain exactly `/impersonation/stop`, `/api/me/impersonation` and `/api/me/impersonation/stop`, so Stop is always reachable.
  - **Apps** show nothing (accepted).
- **D44 Audit and history.**
  - **The audit:** `impersonation.start` (ok or refused), `impersonation.end` and `signin.impersonation` (the switch; detail `on` / `off`).
  - **Apps opened** (`Hub.impersonationApps`), for the person between `started` and `ended` (or now):
    - the opened log's lines with `act` = admin (gateway apps, `own_session: false`);
    - plus Keycloak LOGIN events with `pc_act` = admin for clients in `signin-keycloak.json` `clients` (native apps, `own_session: true`).
    - `used` = an `IMPERSONATE` event with `pc_imp` = id exists. An unreadable event source counts as used (fail toward telling).
    - The Hub's events config (D28) adds `IMPERSONATE` to `enabledEventTypes`, and realm-export does the same.
  - **The history source `impersonation`** (`signinhistory.ImpersonationSource`, added with `AddHistorySource`) gives one entry per id from the person's audit (`impersonation.start` with result ok, joined with its `.end`):
    - `kind` `impersonation`, `time` = start, `by` = admin, `reason`;
    - `detail` = `"<n> min · <how> · apps opened: Gitea, Nextcloud"`, plus " · Nextcloud keeps its own session and may have stayed signed in longer" for each `own_session` app, or `"not used"`;
    - a running one shows "running · ends hh:mm".

    part 2's `FromAudit` keeps dropping `impersonation.*`.
  - **Part 2's sources:** an `opened` line or a native LOGIN with `act` / `pc_act` gets `by` = admin.
  - **The admin audit** (Hub → Audit) shows the same start and end entries.
- **D45 The next-sign-in notice.**
  - **When:** at a used end, the Hub calls `keycloak.Client.RequireImpersonationNotice(person)`, which adds the required action `portcullis-impersonation-notice` like `RequirePasskey`.
  - **The action** (`ImpersonationNotice`):
    - shows `portcullis-impersonation-notice.ftl` with every notice in the file for this user whose `ended` is after the user's `seen` time (the new table `PORTCULLIS_IMP_NOTICE_SEEN`: `USER_ID` pk, `SEEN_UNTIL` bigint);
    - each line reads "<admin> signed in as you on <d MMM yyyy HH:mm> UTC for <n> min: <reason>. Apps opened: …", plus the own-session sentence;
    - Continue stores `SEEN_UNTIL` = the latest `ended` shown and completes the action.
  - **Edge cases:**
    - the file can't be read → it shows "An administrator signed in as you. Your Sign-in page's history has the details." and completes without moving `SEEN_UNTIL`;
    - nothing unseen → it completes silently;
    - in an impersonated session → `context.ignore()` (kept for the person; never shown to the admin).
  - **Setup:** core registers and enables the action (realm-export `requiredActions`, `keycloak configure`).
- **D46 MCP twins and classes.**

  | tool | resource | class |
  |---|---|---|
  | `impersonations` (the switch, the running ones, the last 20 ended) | admin | R |
  | `stop_impersonation` `{user}` | admin | W |
  | `turn_off_impersonation` | admin | W |

  `mcp_parity_test.go` lists the routes without a tool, each with its reason:
  - `POST …/impersonation` — "needs the admin's fresh YubiKey touch and a typed reason; never by an AI";
  - `PUT /api/signin/impersonation` with `allowed: true` — "switched on in Hub Settings only";
  - every `/api/me/impersonation*` route — "the impersonating browser only".

## Review Focus

1. **An impersonated session meeting a template the admin's own session wouldn't**, or the person's certificate counting. For example: alice's YubiKey certificate presented during root's session, root's session without a certificate on an `any[yubikey_cert]` app, a step-up redirect as alice, or a native app's Keycloak flow asking for a method. Expected: the admin's methods only, the admin's certificate only, never a step-up. Pinned by:
   - `test_imp_cert_binds_admin_only` and `test_imp_never_steps_up` (Task 9);
   - `TemplateAuthenticatorTest.impersonatedNeverAsks` (Task 3);
   - `ImpersonationResourceTest.methodsAreAdminsPlusFresh` (Task 2);
   - e2e `imp_call5` (Task 11).
2. **An impersonation outliving Stop, 30 minutes or the switch** on gateway apps or Portcullis pages: a stale file, a Hub that is down, a token refreshed after `until`, or the ext host. Expected: group-gate denies on the next request (claims or file), and the Keycloak session is gone within 15 s. Pinned by:
   - `test_imp_ended_denied_at_once`, `test_imp_until_claim_wins` and `test_imp_stale_file_denies` (Task 9);
   - `ImpersonationExpiryTest` (Task 3);
   - e2e `imp_stop` and `imp_expiry` (Task 11).
3. **Starting without the admin's own fresh hardware touch, or from another browser.** For example: a synced passkey, password or browser-certificate proof; another person's proof; the `next` URL opened in a browser without the admin's session, opened twice, or opened after 120 s. Expected: refused, nothing created. Pinned by:
   - `TestStartImpersonationFreshTouch` (Task 5);
   - `ImpersonationResourceTest.refusals` (Task 2);
   - e2e `imp_refused_proofs` and `imp_next_bound` (Task 11).
4. **The person's account acted on through Portcullis or AI during impersonation.** For example: a password change, creating a certificate, an AI connection, an AI client's authorize, a delegated directory action, or a passkey registration from a pending setup link. Expected: refused, nothing changed. Pinned by:
   - `TestRefuseWhileImpersonated` (Task 6);
   - `TestImpersonatedTokenRefused` (Task 10);
   - `CookieAuthenticatorTest.impersonatedOnlyListedClients` and `PasskeyRegisterTest.refusedWhileImpersonated` (Task 3);
   - e2e `imp_people_read_only` and `imp_ai_refused` (Task 11).
5. **The person not told, or told wrongly.** For example: no notice at the next sign-in, the notice shown to the admin during a later impersonation, shown twice, a reason with HTML or control characters, or a history without the reason or apps. Expected: shown once at the person's own next sign-in, escaped, with reason, apps and the own-session sentence. Pinned by:
   - `ImpersonationNoticeTest` (Task 4);
   - `TestImpersonationHistoryEntry` (Task 7);
   - `test_banner_escapes` (Task 9);
   - e2e `imp_notice_next_signin` (Task 11).

---

### Task 1: Contract and docs (docs repo)

**Files:**
- Modify: `docs/guides/integration-contracts.md`:
  - §1: a "Sign-in methods part 3" bullet (breaking for core, the Hub and the Keycloak image together; merge order);
  - §4: group-gate's impersonated requests (D39, D41, D42: claims, file, binding to the admin, no step-up, the ended page, the stale-file rule); `GATE_IMPERSONATION_FILE`; the opened log's `act` filled;
  - §5: the two headers and the four middlewares' lists (D40); the banner on group-gate pages (D43);
  - §5.1: the people routes (Task 6's route list, under D42's refusal), the Stop page, the Sign-in path additions, and the updated route count;
  - §8: `--features-disabled=impersonation` (D35); the `impersonation` mapper on `acr`; the required action; `PORTCULLIS_PORTAL_URL`; the events config adds `IMPERSONATE`;
  - §8.1: a new "Impersonation" subsection: D35–D38, D42 (Keycloak side), D45, the file (D37), the resource's checks in order, and the session notes;
  - §8.2: the `impersonation` kind is now live; the source; `by` on opened entries; the "Part-3 hooks" paragraph is replaced by D44;
  - §9.7: the person routes (Task 6's route list); `PersonSignIn.can.impersonate`, `impersonation`, `impersonate_refusal`;
  - §15.2: mcp-gate's `impersonated` refusal; §15.10: D46's tools; §15.11: the switch.
- Modify:
  - `docs/operations/auth-policies.md`: a section "Signing in as someone else" (who, the touch, the reason, 30 minutes, Stop, what is refused, what apps may keep, the person's notice);
  - `docs/operations/hub.md`: Settings → Sign-in "Signing in as someone else" switch and running list; the person's Sign-in tab button;
  - `docs/operations/hardening.md`: the stock Keycloak impersonation is disabled, and why;
  - `docs/operations/testing.md`: the new e2e cases (Task 11);
  - `docs/architecture.md`: one paragraph.

**Interfaces:**
- Produces: every shape later tasks implement (D37, D38, D40, D44, D46, and the routes listed in Task 6).

- [ ] **Step 1:** In `wt-signin3/portcullis-docs`, write the sections above, copying every value from D35–D46 and the Task 6 routes. The operator page also says:
  - your own session ends when you start;
  - apps that keep their own sessions (Nextcloud, …) may stay signed in after the end, so sign the person out there when it matters;
  - the stock Keycloak "Impersonate" button is gone on purpose.
- [ ] **Step 2:** Build in the docs venv: `zensical build --strict`. Expected: exit 0, no warnings.
- [ ] **Step 3:** Commit and push: `git add -A && git commit -m "contract: sign-in methods part 3 — admin impersonation (start in Keycloak, claims, call 5, end, banner, history, notice, MCP)" && git push -u origin signin3`.

---

### Task 2: Extension — the start resource, the file, the claims (keycloak)

**Files:**
- Create in `src/main/java/eu/portcullis/signin/`:
  - `ImpersonationFile.java`;
  - `Impersonation.java` (notes and the live check);
  - `ImpersonationResource.java` + `ImpersonationResourceFactory.java` (`RealmResourceProviderFactory`, id `portcullis-impersonate`);
  - `ImpersonationMapper.java`.
- Create: `src/main/resources/theme-resources/templates/portcullis-impersonating.ftl`.
- Modify:
  - `META-INF/services/org.keycloak.services.resource.RealmResourceProviderFactory` (new) and `org.keycloak.protocol.ProtocolMapper`;
  - `messages_en.properties`;
  - `History.java` (`pc_act`).
- Modify, test resources and workflow: `src/test/resources/smoke-realm.json` (the mapper on `acr`, `IMPERSONATE` among the event types), `.github/smoke/run.sh` and `signin.py` (the smoke step "impersonation"), `.github/workflows/build.yml`.
- Test: `ImpersonationFileTest.java`, `ImpersonationResourceTest.java`, `ImpersonationMapperTest.java`.

**Interfaces:**
- Produces:
  ```java
  final class ImpersonationFile {
    static final Path PATH = Path.of("/hub-data/impersonation.json");
    static final ImpersonationFile DENY;                      // allowed false, nothing
    static ImpersonationFile current();                       // cached by (inode, mtime, size); invalid → DENY, logged once
    static ImpersonationFile parse(byte[] raw) throws IOException; // strict: unknown fields, bad ids/names/times → IOException
    boolean allowed();
    Set<String> clients();
    Optional<Pending> pending(String id);
    Optional<SessionRec> session(String id);
    List<Notice> notices(String user);
    Set<String> targets();
    record Pending(String id, String admin, String adminSid, String target, String reason, String fresh, Instant freshAt, Instant created, Instant until) {}
    record SessionRec(String id, String admin, String target, String reason, Instant started, Instant until, Instant ended) {}
    record Notice(String id, String admin, Instant started, Instant ended, String reason, List<App> apps) {}
    record App(String name, boolean ownSession) {}
  }
  final class Impersonation {
    static final String ID = "portcullis.imp.id", UNTIL = "portcullis.imp.until", REASON = "portcullis.imp.reason";
    record Info(String id, String admin, String reason, Instant until) {}
    static Optional<Info> of(UserSessionModel s);             // from the notes; partial notes → Info with id only (never live)
    static boolean live(Info i, String target, ImpersonationFile f, Instant now); // allowed, session(id) not ended, admin/target equal, now < min(i.until, rec.until)
  }
  final class ImpersonationResource implements RealmResourceProvider {
    @GET @Path("start") Response start(@QueryParam("id") String id);
    static String computeExecutions(RealmModel r, UserSessionModel admin, String fresh, Instant freshAt); // AUTHENTICATORS_COMPLETED JSON, or null (refuse)
  }
  final class ImpersonationMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {
    static final String PROVIDER_ID = "portcullis-impersonation";
  }
  // History
  static void History.onSuccess(...) // adds pc_act when the authentication's SSO session is impersonated
  ```
  The `portcullis-impersonating.ftl` modes are `refused`, `ended` and `needs`. Every mode shows the banner when the attribute `impersonation` (an `Info`, plus the person's username) is set, and every mode links Stop to `https://people.<d>/impersonation/stop`, derived from `PORTCULLIS_SIGNIN_URL`'s origin.

- [ ] **Step 1: Write the failing tests**
  ```java
  // ImpersonationFileTest
  @Test void parsesShape()                 // D37 example → pending/session/notice/clients as given
  @Test void invalidIsDeny()               // missing file, bad JSON, version 2, unknown field, id "ABC", reason with \u0007 → DENY
  @Test void liveNeedsEverything()         // ended set / admin differs / target differs / now ≥ until (either) / allowed false → false
  // ImpersonationResourceTest (mocked KeycloakSession, as TemplateAuthenticatorTest does)
  @Test void startsSessionWithNotes()      // happy path → new session for alice: IMPERSONATOR_USERNAME root, portcullis.imp.id/until/reason;
                                           //  admin session backchannel-logged-out; login cookie set; 302 to <auth>/oauth2/start?rd=<portal>
  @Test void methodsAreAdminsPlusFresh()   // admin executions {x509 mtls @t1}, fresh security_key @t2 → {x509 @t1, method-security-key @t2};
                                           //  fresh already present → copied unchanged; no execution with that reference → refused
  @Test void refusals()                    // each → 403 page, no session created, admin session untouched:
      // not allowed; unknown id; created 121 s ago; second use (singleUseObjects says used); no identity cookie;
      // cookie session id ≠ admin_sid; cookie user ≠ admin; admin not in lldap_admin; target disabled / service account /
      // "portcullis-x" / in lldap_admin / == admin / has required action webauthn-register-passwordless; PORTCULLIS_PORTAL_URL unset
  @Test void impersonateEventHasIdAndActor() // IMPERSONATE, user alice, details pc_imp, pc_act=root; no reason in the event
  @Test void logNeverHasReason()           // captured log lines on success and refusal contain no reason text
  // ImpersonationMapperTest
  @Test void claimsWhenImpersonated()      // notes → act {"sub":"root"}, pc_imp {"id","until"}; no reason claim anywhere
  @Test void nothingOtherwise()            // no portcullis.imp.id → neither claim; config claim.name ignored
  ```
- [ ] **Step 2: Run them to see them fail.** Run `docker build --target test .`. Expected: FAIL (compile errors / assertions).
- [ ] **Step 3: Implement** per D35, D37, D38 and D40.
  - Use Keycloak's own calls named in D38 (`UserSessionManager`, `AuthenticationManager`, `AuthenticatorUtils.parseCompletedExecutions`, `session.singleUseObjects()`) and Jackson's strict mapper, as `SigninConfig` does.
  - Usernames match `^[a-z0-9][a-z0-9._-]{0,63}$`, ids `^[0-9a-f]{32}$`, and reasons 3–200 runes with no control or bidi characters.
- [ ] **Step 4: Add the smoke step "impersonation"** to `.github/smoke/`.
  - Setup:
    - the smoke realm has users root (in `lldap_admin`) and alice;
    - root signs in with the smoke's password method;
    - the step writes `impersonation.json` with a pending record bound to root's session id (read from the admin API's user sessions);
    - it calls `start?id=` with root's cookies, then follows to an authorize for a test client listed in `clients`.
  - Expected:
    - the token's `preferred_username` is alice, `act.sub` is root, `pc_imp.id` is the id, and its amr equals root's;
    - root's session is gone;
    - a second `start?id=` gets 403;
    - `POST /admin/realms/<r>/users/<alice>/impersonation` with the smoke admin token is refused (the smoke Keycloak runs with `--features-disabled=impersonation`, as core does);
    - the `portcullis.*ERROR` grep stays empty.
- [ ] **Step 5: Run them to see them pass.** Run `docker build --target test . && docker build .`, push, and check the smoke job. Expected: `BUILD SUCCESSFUL` and green. "Compare the smoke realm with core's flows" passes once Task 10 is pushed; re-run it then.
- [ ] **Step 6: Commit and push.** `git add -A && git commit -m "impersonation: Portcullis's own start inside Keycloak (bound to the admin's session, one use, 120 s), the admin's methods plus the touch, act / pc_imp claims" && git push -u origin signin3`.

---

### Task 3: Extension — impersonated sessions in the flows, expiry (keycloak)

**Files:**
- Modify: `CookieAuthenticator.java`, `TemplateAuthenticator.java`, `PasskeyRegister.java`, `NeedsStronger.java` (banner attribute), `portcullis-needs-stronger.ftl`.
- Create: `ImpersonationGuard.java`, `ImpersonationExpiry.java`, `ImpersonationExpiryFactory.java` (portcullis-task SPI, registered in `META-INF/services/eu.portcullis.signin.PortcullisTaskSpi$Factory`).
- Test: `CookieAuthenticatorTest.java`, `TemplateAuthenticatorTest.java`, `PasskeyRegisterTest.java`, `ImpersonationGuardTest.java`, `ImpersonationExpiryTest.java`.

**Interfaces:**
- Consumes: Task 2 (`ImpersonationFile`, `Impersonation`, the FTL).
- Produces:
  ```java
  final class ImpersonationGuard {
    enum Verdict { NOT_IMPERSONATED, ALLOW, REFUSE, ENDED }
    // D42: the identity cookie's session; ALLOW only for a live session, a listed client, SSO only (no method ran),
    // no pc_method, no prompt=login. ENDED logs the session out (backchannelLogout) before answering.
    static Verdict check(AuthenticationFlowContext c, ImpersonationFile f, Instant now);
    static Response page(AuthenticationFlowContext c, Verdict v, Impersonation.Info i); // portcullis-impersonating.ftl
  }
  final class ImpersonationExpiry implements ScheduledTask {
    static final long INTERVAL_MS = 15_000; static final String TASK_NAME = "portcullis-impersonation-expiry";
    void run(KeycloakSession s); // D41: targets of the file (or the last good one); logs out every non-live impersonated session
  }
  ```

- [ ] **Step 1: Write the failing tests**
  ```java
  // CookieAuthenticatorTest
  @Test void impersonatedOnlyListedClients()  // live imp cookie: client portcullis-forward-auth → stock SSO; client portcullis-ai-x,
                                              //  portcullis-fresh-auth, account-console → challenge page mode refused
  @Test void impersonatedPcMethodRefused()    // pc_method=security_key on a live imp session → refused, never handed to the sign-in flow
  @Test void endedSessionLoggedOut()          // file says ended → backchannelLogout called, page mode ended
  // TemplateAuthenticatorTest
  @Test void impersonatedNeverAsks()          // native client on all[yubikey_cert] and a session lacking it → page mode needs, no resetFlow
  @Test void impersonatedPromptLoginRefused() // prompt=login (cookie skipped) with an imp identity cookie → refused, nothing issued
  @Test void impersonatedMetSucceedsWithAct() // met → success; LOGIN details pc_kind sso, pc_act root
  @Test void otherRequiredActionRefused()     // live imp, the user has UPDATE_PASSWORD → refused page
  // PasskeyRegisterTest
  @Test void refusedWhileImpersonated()       // registration challenge in an imp session → refused, nothing stored
  // ImpersonationGuardTest
  @Test void notImpersonatedUntouched()       // a normal cookie → NOT_IMPERSONATED for every client
  @Test void unreadableFileEnds()             // DENY file + imp cookie → ENDED
  // ImpersonationExpiryTest
  @Test void removesEndedAndOverdue()         // sessions: live, ended, until past, no note → only the two removed
  @Test void unreadableFileUsesLastTargets()  // good file then DENY → the last good targets' imp sessions all removed
  ```
- [ ] **Step 2: Run them to see them fail.** Run `docker build --target test .`. Expected: FAIL.
- [ ] **Step 3: Implement** per D39, D41 and D42.
  - `CookieAuthenticator.authenticate` and `TemplateAuthenticator.authenticate` call `ImpersonationGuard.check` first.
  - Schedule the task like `ReclassifyFactory` does (on `PostMigrationEvent`, `ClusterAwareScheduledTaskRunner`).
  - The needs-stronger page shows the banner when the session is impersonated.
- [ ] **Step 4: Run them to see them pass.** Run `docker build --target test . && docker build .` and push. Expected: `BUILD SUCCESSFUL`, smoke green.
- [ ] **Step 5: Commit and push.** `git add -A && git commit -m "impersonation: listed clients and SSO only, never a new method or a required action, ended sessions logged out within 15 s" && git push`.

---

### Task 4: Extension — the next-sign-in notice (keycloak)

**Files:**
- Create:
  - `ImpersonationNotice.java` + `ImpersonationNoticeFactory.java` (`RequiredActionFactory`, id `portcullis-impersonation-notice`);
  - `store/NoticeSeenEntity.java`;
  - `theme-resources/templates/portcullis-impersonation-notice.ftl`.
- Modify:
  - `store/PasskeyStoreProviderFactory.java` (entity list);
  - `META-INF/portcullis-passkey-changelog.xml` (a new changeSet `portcullis-imp-notice-seen-1`: table `PORTCULLIS_IMP_NOTICE_SEEN`, `USER_ID` varchar(36) pk, `SEEN_UNTIL` bigint not null);
  - `META-INF/services/org.keycloak.authentication.RequiredActionFactory`;
  - `messages_en.properties`;
  - `smoke-realm.json` (the action registered and enabled);
  - the smoke step "impersonation" (Task 2) gains the notice check.
- Test: `ImpersonationNoticeTest.java`, `PasskeyStoreTest.java` (the entity).

**Interfaces:**
- Consumes: Task 2 (`ImpersonationFile.notices`, `Impersonation.of`).
- Produces:
  ```java
  final class ImpersonationNotice implements RequiredActionProvider {
    static final String ID = "portcullis-impersonation-notice";
    void requiredActionChallenge(RequiredActionContext c); // D45: unseen notices, generic text, silent success, or ignore()
    void processAction(RequiredActionContext c);           // Continue → SEEN_UNTIL = latest ended shown; success()
    static String line(Notice n);                           // "root signed in as you on 12 Nov 2026 14:02 UTC for 26 min: <reason>. Apps opened: Gitea, Nextcloud." (+ own-session sentence)
  }
  ```

- [ ] **Step 1: Write the failing tests**
  ```java
  @Test void showsUnseenOnly()           // two notices ended t1 < t2, SEEN_UNTIL t1 → only the t2 line
  @Test void continueStoresSeen()        // processAction → SEEN_UNTIL t2, success
  @Test void nothingUnseenSilent()       // SEEN_UNTIL ≥ every ended → success, no form
  @Test void unreadableFileGeneric()     // DENY file → the generic text; Continue → success, SEEN_UNTIL unchanged
  @Test void ignoredWhileImpersonated()  // auth session's SSO session impersonated → ignore(), no form, action kept
  @Test void lineExact()                 // line(n) equals the D45 text; own_session app adds "Nextcloud keeps its own session and may have stayed signed in longer."
  @Test void reasonEscapedInPage()       // reason "<b>x</b>" → rendered escaped (FreeMarker auto-escaping on)
  ```
- [ ] **Step 2: Run them to see them fail.** Run `docker build --target test .`. Expected: FAIL.
- [ ] **Step 3: Implement** per D45. Read and write the table through `PasskeyStore`'s `EntityManager` (`JpaConnectionProvider`), like `SigninStateEntity`.
- [ ] **Step 4: Extend the smoke step.**
  - Setup: give alice the action, write a notice into the file, and sign alice in with her password.
  - Expected: the notice page has the line, Continue reaches the client, and a second sign-in shows no notice.
- [ ] **Step 5: Run them to see them pass.** Run `docker build --target test . && docker build .` and push. Expected: `BUILD SUCCESSFUL`, smoke green.
- [ ] **Step 6: Commit and push.** `git add -A && git commit -m "impersonation: the person's notice at their next sign-in (once, never to the admin)" && git push`.

---

### Task 5: Hub — state, switch, start / stop / expiry, the published file (hub)

**Files:**
- Modify: `internal/state/signin.go` (`ImpersonationOff`, `Impersonations`, `state.Impersonation`), `internal/hub/signin.go` (`IMPERSONATE` in the events config types, D44), `internal/keycloak/events.go`, `cmd/hub/main.go` (`HUB_IMPERSONATION_MAX_MINUTES`, `go h.RunImpersonationExpiry(ctx, 5*time.Second)`).
- Create:
  - `internal/hub/impersonation.go`, `internal/hub/impersonation_file.go`;
  - `internal/keycloak/notice.go` (`RequireImpersonationNotice`, `RequiredActions`, `UserEnabled`).
- Test: `internal/hub/impersonation_test.go`, `internal/hub/impersonation_file_test.go`, `internal/keycloak/notice_test.go`, `internal/keycloak/events_test.go`, `cmd/hub/main_test.go`, `internal/state/state_test.go`.

**Interfaces:**
- Produces:
  ```go
  // state
  type Impersonation struct {
    ID       string    `yaml:"id"`
    Admin    string    `yaml:"admin"`
    Target   string    `yaml:"target"`
    AdminSID string    `yaml:"admin_sid"`
    Reason   string    `yaml:"reason"`
    Fresh    string    `yaml:"fresh"`
    FreshAt  time.Time `yaml:"fresh_at"`
    Started  time.Time `yaml:"started"`
    Until    time.Time `yaml:"until"`
    Ended    time.Time `yaml:"ended,omitempty"`
    How      string    `yaml:"how,omitempty"`      // stopped | expired | switched_off | not_used
    EndedBy  string    `yaml:"ended_by,omitempty"`
    Used     bool      `yaml:"used,omitempty"`     // D44, set at end
  }
  SignIn.ImpersonationOff bool                      `yaml:"impersonation_off"`
  SignIn.Impersonations   []Impersonation           `yaml:"impersonations"` // running + ended < 1 h
  // hub
  const ImpersonationFileName = "impersonation.json"
  type StartImpersonation struct{ Target, Reason, AdminSID, Listener string; Proof freshauth.Proof }
  type StartedImpersonation struct{ ID, Next string; Until time.Time }
  type ImpersonationView struct {
    ID      string    `json:"id"`
    Admin   string    `json:"admin"`
    Person  string    `json:"person"`
    Reason  string    `json:"reason"`
    Started time.Time `json:"started"`
    Until   time.Time `json:"until"`
    Ended   *time.Time `json:"ended"`
    How     string    `json:"how"`
  }
  type ImpersonationsView struct{ Allowed bool `json:"allowed"`; MaxMinutes int `json:"max_minutes"`; Running, Recent []ImpersonationView }
  func (h *Hub) StartImpersonation(ctx context.Context, in StartImpersonation, actor directory.Actor) (*StartedImpersonation, error) // D36, D38
  func (h *Hub) StopImpersonation(ctx context.Context, target string, actor directory.Actor) error                                // admins; 404 when none
  func (h *Hub) StopOwnImpersonation(ctx context.Context, id, person string) (signOut string, err error)                          // the impersonating browser
  func (h *Hub) ImpersonationOf(person, id string) *ImpersonationView                                                            // nil unless running and matching
  func (h *Hub) Impersonations() ImpersonationsView
  func (h *Hub) SetImpersonationAllowed(ctx context.Context, allowed bool, actor directory.Actor) (*ImpersonationsView, error)   // off ends every running one
  func (h *Hub) RunImpersonationExpiry(ctx context.Context, every time.Duration)
  func (h *Hub) SetImpersonationApps(f func(ctx context.Context, rec state.Impersonation) (apps []signinhistory.OpenedApp, used bool)) // Task 7
  func (h *Hub) writeImpersonationFileLocked() error
  // keycloak
  const ImpersonationNoticeAction = "portcullis-impersonation-notice"
  func (c *Client) RequireImpersonationNotice(ctx context.Context, username string) error
  func (c *Client) RequiredActions(ctx context.Context, username string) ([]string, error)
  func (c *Client) UserEnabled(ctx context.Context, username string) (bool, error)
  Config.ImpersonationMaxMinutes int // HUB_IMPERSONATION_MAX_MINUTES
  ```
  `signinhistory.OpenedApp{Name string; OwnSession bool}` is declared in Task 7's package. This task adds the type with its JSON tags `name` and `own_session`, so Task 7 only adds behaviour.

- [ ] **Step 1: Write the failing tests**
  ```go
  func TestImpersonationOnByZeroValue(t *testing.T)     // empty state → allowed; ImpersonationOff true → 409 text of D36.1
  func TestStartImpersonationRules(t *testing.T)         // D36 order, each case's status and exact text: non-admin 403; unknown 404; self;
  //  "admin", "portcullis-hub", "portcullis-x"; another admin; disabled; reason "" / "ab" / 201 runes / "a\nb" → 400;
  //  caller already running; target taken; target RequiredActions [webauthn-register-passwordless] → 409; no sid → 403;
  //  security_key and yubikey_cert both off → 409 before Verify is called
  func TestStartImpersonationFreshTouch(t *testing.T)    // fake verifier: security_key ✓, yubikey_cert ✓; passkey_synced, passkey_device,
  //  password, browser_cert → 403 "a fresh sign-in is required"; proof for another user → 403; security_key switched off → 403;
  //  every refusal audited impersonation.start refused, with no code/verifier/nonce in the detail
  func TestStartImpersonationRecord(t *testing.T)        // ok → state pending, file pending {admin_sid, fresh, until = started+30m},
  //  next = https://auth.<d>/realms/portcullis/portcullis-impersonate/start?id=<32 hex>; audit detail "<id> · security_key · <reason>"
  func TestMaxMinutes(t *testing.T)                       // unset → 30; "2" → 2; "0", "31", "x" → the Hub refuses to start
  func TestImpersonationFileShape(t *testing.T)          // golden D37: clients = forward-auth + enabled instances' ids, no AI or fresh-auth
  //  client; sessions keep ended < 1 h; notices only used, within history_days; mode 0644; atomic
  func TestExpiryEnds(t *testing.T)                      // fake clock: until passed → How expired, audit impersonation.end by "portcullis",
  //  file ended; pending unused after 120 s → not_used, no notice
  func TestStopEnds(t *testing.T)                        // StopImpersonation by admin2 → How stopped, EndedBy admin2; StopOwnImpersonation
  //  wrong id or person → 404; right → sign_out "https://auth.<d>/oauth2/sign_out?rd=https%3A%2F%2F<d>%2F"
  func TestSwitchOffEndsAll(t *testing.T)                // two running → both switched_off; start then 409; audit signin.impersonation off
  func TestNoticeOnlyWhenUsed(t *testing.T)              // apps func used=true → RequireImpersonationNotice(alice); used=false → not called
  func TestEndDetailApps(t *testing.T)                   // apps [Gitea, Nextcloud(own)] → detail "<id> · stopped · 12 min · apps opened: Gitea, Nextcloud"
  func TestFileRewrittenEveryMinute(t *testing.T)        // written refreshes with no change (group-gate's 300 s staleness, D37)
  func TestEventsConfigHasImpersonate(t *testing.T)      // EnsureEventsConfig types = {LOGIN, LOGIN_ERROR, IMPERSONATE} (compared as a set)
  func TestRequireImpersonationNotice(t *testing.T)      // keycloak fake: adds the action once, keeps the others
  ```
- [ ] **Step 2: Run them to see them fail.** Run `go test ./internal/state/ ./internal/hub/ ./internal/keycloak/ ./cmd/hub/ -run 'Impersonat|MaxMinutes|Expiry|Stop|SwitchOff|Notice|EndDetail|FileRewritten|EventsConfig'`. Expected: FAIL.
- [ ] **Step 3: Implement** per D36–D38, D41 and D44.
  - The Keycloak calls (required actions, enabled) and the fresh-touch exchange happen outside `h.mu`. The state is re-read under the lock before the record is written, so a concurrent start for the same target or admin loses with 409.
  - The id comes from `crypto/rand`.
- [ ] **Step 4: Run them to see them pass.** Run the same command, then the full Go checks. Expected: `ok`.
- [ ] **Step 5: Commit and push.** `git add -A && git commit -m "impersonation: rules, fresh YubiKey touch, the published file, stop / expiry / switch, audit, notice" && git push -u origin signin3`.

---

### Task 6: Hub — routes, the refusal while impersonated, MCP twins (hub)

**Files:**
- Create: `internal/httpapi/impersonation.go`, `internal/httpapi/mcptools_impersonation.go`, `web/impersonation-stop.html` (a placeholder that Task 8 fills).
- Modify:
  - `internal/httpapi/server.go`: the people and Hub muxes; `RefuseWhileImpersonated` wraps both listeners after `ProxySecret`; `GET /impersonation/stop`;
  - `internal/httpapi/middleware.go`: `RefuseWhileImpersonated`;
  - `internal/httpapi/signin_help.go`: `PersonSignIn`'s new fields;
  - `internal/hub/signin_help.go`: `can.impersonate`, `impersonation` and `impersonate_refusal` (the first D36 refusal that applies without a proof);
  - `people_test.go` (allowlist), `mcp_parity_test.go`, `auditparity_test.go`;
  - `web/web.go`: `impersonation-stop.html` in the embed list.
- Test: `internal/httpapi/impersonation_test.go`, `internal/httpapi/mcptools_impersonation_test.go`, `internal/httpapi/middleware_test.go`.

**Interfaces:**
- Consumes: Task 5.
- Produces — the routes (JSON in snake_case):
  - `POST /api/directory/users/{username}/impersonation` `{reason, code, code_verifier, nonce}` (≤ 8 KiB, both listeners, CSRF) → 200 `{id, next, until}`;
  - `POST /api/directory/users/{username}/impersonation/stop` → 204 (admins, both listeners);
  - `GET /api/impersonations` (Hub listener, admins) → `ImpersonationsView`;
  - `PUT /api/signin/impersonation` `{allowed}` (Hub listener, admins) → `ImpersonationsView`;
  - `GET /api/me/impersonation` (people) → `{"active": null | {person, admin, reason, until, stop_url}}`, answered only when `X-Forwarded-Impersonation` names the caller's running one;
  - `POST /api/me/impersonation/stop` (people, CSRF) → 200 `{"sign_out": "<url>"}`, Cache-Control `no-store`;
  - `GET /impersonation/stop` (people) → the Stop page.
  ```go
  func RefuseWhileImpersonated(next http.Handler) http.Handler // D42: non-GET/HEAD + X-Forwarded-Impersonation → 403, except POST /api/me/impersonation/stop
  func callerSID(r *http.Request) string                       // sid of X-Forwarded-Access-Token's payload (unverified decode), "" when absent/malformed
  type PersonSignInImpersonation struct {
    Can     bool               `json:"impersonate"`          // inside PersonSignIn.Can
    Running *hub.ImpersonationView `json:"impersonation"`
    Refusal string             `json:"impersonate_refusal"`
  }
  // MCP (D46)
  tool impersonations (R), stop_impersonation {user} (W), turn_off_impersonation (W)
  ```

- [ ] **Step 1: Write the failing tests**
  ```go
  func TestImpersonationRoutesAdminsOnly(t *testing.T) // non-admin 403 on start/stop/list/switch; people listener has no /api/impersonations
  func TestStartRouteShape(t *testing.T)               // body > 8 KiB 413; unknown field 400; ok → {id,next,until}; sid read from the token header
  func TestRefuseWhileImpersonated(t *testing.T)       // with X-Forwarded-Impersonation: PUT /api/me/signin/password, POST …/browser-certificates,
  //  DELETE /api/me/ai/connections/x, PUT /api/me/apps/i/values/k, POST /api/directory/users/bob/invite → 403 exact text;
  //  GET /api/me/apps 200; POST /api/me/impersonation/stop passes; without the header nothing changes
  func TestMeImpersonation(t *testing.T)               // header names the running id for this caller → active; other id / other person / ended → null
  func TestStopOwnRoute(t *testing.T)                  // → 200 sign_out, no-store; then GET /api/me/impersonation → null
  func TestPersonSignInCanImpersonate(t *testing.T)    // admin viewing alice: can true; viewing an admin: false + "administrators can't be signed in as";
  //  switch off: false + D36.1 text; delegate (sign_in_help) viewing alice: can false, no running record shown
  func TestImpersonationTools(t *testing.T)            // classes R / W / W; stop_impersonation by AI audited via ai; no start tool in tools/list
  func TestParityImpersonation(t *testing.T)           // mcp_parity lists the start route, switch-on and /api/me/impersonation* with D46's reasons
  func TestStopPageReachable(t *testing.T)             // GET /impersonation/stop on people → 200 html; on the Hub listener 404
  ```
- [ ] **Step 2: Run them to see them fail.** Run `go test ./internal/httpapi/ -run 'Impersonat|RefuseWhile|MeImpersonation|StopOwn|PersonSignInCan|StopPage'`. Expected: FAIL.
- [ ] **Step 3: Implement** per D42, D46 and the routes above. `callerSID` uses `github.com/golang-jwt/jwt/v5`'s `ParseUnverified` (already in the Hub's module graph; otherwise base64url + `encoding/json` of the payload only).
- [ ] **Step 4: Run them to see them pass.** Run the same command, then the full Go checks. Expected: `ok`.
- [ ] **Step 5: Commit and push.** `git add -A && git commit -m "impersonation: Hub routes, read-only while impersonated, MCP stop / list / turn off (no start)" && git push`.

---

### Task 7: Hub — apps opened and the history source (hub)

**Files:**
- Create: `internal/signinhistory/impersonation.go`, `internal/hub/impersonation_apps.go`.
- Modify:
  - `internal/signinhistory/opened.go` and `keycloak.go`: `By` from `act` / `pc_act`; a reader of `act` lines in a window;
  - `internal/keycloak/events.go`: `ImpersonateEvents`;
  - `cmd/hub/main.go`: `AddHistorySource("impersonation", …)` and `SetImpersonationApps(…)`.
- Test: `internal/signinhistory/impersonation_test.go`, `signinhistory_test.go`, `internal/hub/impersonation_apps_test.go`, `internal/keycloak/events_test.go`.

**Interfaces:**
- Consumes: Task 5 (`state.Impersonation`, `SetImpersonationApps`, `OpenedApp`); part 2's `OpenedLog`, `LoginEvents`, `AuditLog.RecentMatching`.
- Produces:
  ```go
  type OpenedApp struct{ Name string `json:"name"`; OwnSession bool `json:"own_session"` }
  type ImpersonationSource struct {
    Audit func(ctx context.Context, user string, since, before time.Time, limit int) ([]directory.AuditEntry, error) // impersonation.* for user
    Apps  func(ctx context.Context, user, admin string, from, to time.Time) ([]OpenedApp, bool, error)            // apps, used
    Now   func() time.Time
  }
  func (s ImpersonationSource) Entries(ctx context.Context, user string, since, before time.Time, limit int) ([]Entry, error)
  func ImpersonationDetail(minutes int, how, endedBy string, apps []OpenedApp, used bool) string // D44 text
  func (l OpenedLog) ActApps(user, act string, from, to time.Time) ([]string, error)
  func (c *keycloak.Client) ImpersonateEvents(ctx context.Context, userID string, from, to time.Time) ([]Event, error) // type=IMPERSONATE
  func (h *Hub) impersonationApps(ctx context.Context, rec state.Impersonation) ([]signinhistory.OpenedApp, bool)
  ```

- [ ] **Step 1: Write the failing tests**
  ```go
  func TestImpersonationHistoryEntry(t *testing.T) // start ok + end (stopped by root, 12 min, Gitea, Nextcloud own) → one entry: kind impersonation,
  //  time = start, by root, reason as typed, detail "12 min · stopped by root · apps opened: Gitea, Nextcloud · Nextcloud keeps its own
  //  session and may have stayed signed in longer"; refused starts → no entry; a running one → "running · ends 14:32"; unused → "not used"
  func TestImpersonationSourceWindowAndLimit(t *testing.T) // since/before and limit respected; newest first; failure → Unknown ["impersonation"]
  func TestOpenedAndEventsByActor(t *testing.T)    // opened line act "root" → opened entry By "root"; LOGIN sso with pc_act → opened By "root"
  func TestImpersonationApps(t *testing.T)         // opened act lines in the window + native LOGINs with pc_act → apps, deduped, gateway first;
  //  lines outside the window or with another act ignored; IMPERSONATE event with pc_imp = id → used; events unreadable → used true
  func TestFromAuditStillDropsImpersonation(t *testing.T) // part 2's audit source never emits impersonation.*
  ```
- [ ] **Step 2: Run them to see them fail.** Run `go test ./internal/signinhistory/ ./internal/hub/ ./internal/keycloak/ -run 'Impersonat|ByActor|FromAuditStill'`. Expected: FAIL.
- [ ] **Step 3: Implement** per D44. The source parses the audit detail's leading `<id> · `. Its fields are separated by ` · `, and the reason is the rest of the start detail, so a reason containing " · " is kept whole.
- [ ] **Step 4: Run them to see them pass.** Run the same command, then the full Go checks. Expected: `ok`.
- [ ] **Step 5: Commit and push.** `git add -A && git commit -m "history: impersonation entries with reason and apps opened; opened / native entries by the admin" && git push`.

---

### Task 8: Hub UI — Sign in as…, the banner, the Stop page, the switch (hub)

**Files:**
- Create: `web/impersonation.js`.
- Modify:
  - `web/impersonation-stop.html`;
  - `web/people.html`, `web/mysignin.html`: load `impersonation.js` first in `<body>`;
  - `web/directory.js`: the person's Sign-in tab gets the row "Sign in as <person>…" (mockup section 3), the dialog (reason field, the fresh sign-in, then `location.assign(next)`), and a running line "root is signed in as alice since 14:02 · reason · 26 min left · Stop" for admins;
  - `web/signin.js`: Settings → Sign-in gets the "Signing in as someone else" switch (on by default) and the running list with Stop;
  - `web/web.go` and `internal/httpapi/server.go` `peopleStatic`: `impersonation.js`.
- Test: `internal/httpapi/webui_impersonation_test.go` (the existing headless-page harness, as `webui_mysignin_test.go` does).

**Interfaces:**
- Consumes: the Task 6 routes.
- Produces: `impersonation.js` exposes nothing global. It renders into `<div id="pc-imp-banner">`, which it inserts as the body's first child.

- [ ] **Step 1: Write the failing tests**
  ```go
  func TestBannerText(t *testing.T)        // /api/me/impersonation active (alice, root, "checking quota", until now+25m30s) →
  //  banner text exactly "You are signed in as alice (by root) · reason “checking quota” · 26 min left" + a Stop button
  func TestBannerEscapes(t *testing.T)     // reason "<img src=x onerror=alert(1)>" → shown as text, no element created
  func TestBannerStop(t *testing.T)        // Stop → POST /api/me/impersonation/stop, then location = sign_out
  func TestNoBannerWhenNull(t *testing.T)  // active null → no #pc-imp-banner
  func TestSignInAsDialog(t *testing.T)    // admin, can.impersonate → button; reason < 3 chars disables Continue; ok → fresh popup →
  //  POST with {reason, code, code_verifier, nonce} → location.assign(next); can false → refusal text shown, no button
  func TestSettingsSwitch(t *testing.T)    // switch off → PUT {allowed:false} after a confirm naming the running ones
  func TestStopPage(t *testing.T)          // /impersonation/stop: a "Stop signing in as alice" button; when not impersonating "Nothing to stop"
  ```
- [ ] **Step 2: Run them to see them fail.** Run `go test ./internal/httpapi/ -run 'Banner|SignInAs|SettingsSwitch|StopPage'`. Expected: FAIL.
- [ ] **Step 3: Implement** per D43 and the mockup. The banner sits above everything, with a warning style and `role="alert"`. It counts down once a minute and reloads at 0.
- [ ] **Step 4: Run them to see them pass.** Run the same command, then the full Go checks. Expected: `ok`.
- [ ] **Step 5: Commit and push.** `git add -A && git commit -m "web: Sign in as…, the impersonation banner on people pages, the Stop page, the Settings switch" && git push`.

---

### Task 9: group-gate — impersonated requests (core)

**Files:**
- Modify: `group-gate/group-gate.py`.
- Test: `tests/test_group_gate.py`; the vectors check (byte-identical, unchanged).

**Interfaces:**
- Produces:
  ```python
  IMPERSONATION_FILE = os.environ.get("GATE_IMPERSONATION_FILE", "/hub-data/impersonation.json")
  IMPERSONATION_STALE = 300.0
  IMPERSONATION_HEADERS = ("X-Forwarded-Impersonator", "X-Forwarded-Impersonation")
  class Impersonation(NamedTuple): id: str; admin: str; until: float
  def impersonation_claims(claims: dict) -> Tuple[bool, Optional[Impersonation]]  # (present, parsed); present+malformed → (True, None)
  def load_impersonation_file() -> Optional[dict]          # cached (inode, mtime, size); invalid / version ≠ 1 / stale → None
  def live_impersonation(imp: Impersonation, username: str, now: float) -> Optional[dict]  # the file's session record (D37, Impersonation.live rules)
  def render_banner(rec: dict, now: float, domain: str) -> str   # D43 text, escaped, Stop → https://people.<d>/impersonation/stop
  def render_ended_page(person: str, domain: str) -> bytes
  def render_needs_page(app, have, node, set_up, add_stronger, domain, impersonated: Optional[dict] = None) -> bytes
  def render_portal(user, groups, apps, domain, domains=(), banner: str = "") -> bytes
  def _signin_page(title: str, body: str, banner: str = "") -> bytes
  SIGNIN_EXACT = ("/signin", "/api/me/signin", "/impersonation/stop", "/api/me/impersonation", "/api/me/impersonation/stop")
  ```
  Order in `do_GET`, after the username checks and before membership:
  1. If claims are present but malformed, or `live_impersonation` is None → `render_ended_page` (403, log `DENIED … reason=impersonation_ended`).
  2. Membership as today.
  3. `_signin_check`, using `rec["admin"]` as the certificate binding user and the impersonation needs-page with no step-up.
  4. On allow: the two headers, and `OPENED_LOG.record(…, act=rec["admin"])`.

  The portal and every page get `banner`.

- [ ] **Step 1: Write the failing tests**
  ```python
  def test_imp_claims_parse():          # act {"sub":"root"} + pc_imp {"id":32hex,"until":n} → parsed; act only / pc_imp only / act "root" /
                                        # id "XYZ" / until "x" → (True, None); neither → (False, None)
  def test_imp_live_allows_with_headers(): # live record, member host → 200, X-Forwarded-Impersonator root, X-Forwarded-Impersonation id,
                                        # X-Forwarded-User alice
  def test_imp_ended_denied_at_once():  # record ended (file rewritten) → next request 403 ended page with the sign-out link, on app, people, portal
  def test_imp_until_claim_wins():      # file until later but claim until passed → ended page; and the reverse
  def test_imp_stale_file_denies():     # written 301 s ago / unreadable / allowed false → ended page; non-impersonated requests unaffected
  def test_imp_admin_or_person_mismatch(): # act.sub bob vs file admin root, or file target carol → ended page
  def test_imp_cert_binds_admin_only(): # app any[yubikey_cert], amr [mtls]: root's pki_int leaf → allowed; alice's leaf → needs page;
                                        # no leaf → needs page; root's revoked leaf → needs page
  def test_imp_never_steps_up():        # unmet rule with a completable step-up → 403 impersonation needs page, no X-Stepup-URL, Stop link
  def test_imp_signin_paths():          # people host: /impersonation/stop, /api/me/impersonation, /api/me/impersonation/stop → signin_path True;
                                        # /impersonation/stop/../api/directory → False
  def test_banner_text_and_escape():    # exact D43 text with 26 min; reason "<script>" escaped; on portal, needs, step-up, certificate pages
  def test_banner_escapes():            # admin/person names validated by the username grammar, else the page has no banner and denies
  def test_imp_opened_log_act():        # first allowed request → line with act "root"
  def test_client_sent_imp_headers_ignored(): # request carries X-Forwarded-Impersonator without claims → not impersonated, header not echoed
  ```
- [ ] **Step 2: Run them to see them fail.** Run `python3 tests/test_group_gate.py`. Expected: FAIL.
- [ ] **Step 3: Implement** per D39–D43. Read the file with the stdlib `json`, and parse times with the module's existing `_parse_rfc3339`.
- [ ] **Step 4: Run them to see them pass.** Run `python3 tests/test_group_gate.py && (cd mcp-gate && go test ./...)`. Expected: `OK` and `ok`.
- [ ] **Step 5: Commit and push.** `git add -A && git commit -m "group-gate: impersonated requests — live by claims and the Hub's file, the admin's certificate, no step-up, banner, headers, opened act" && git push -u origin signin3`.

---

### Task 10: mcp-gate, compose, realm, `keycloak configure`, CI checks (core)

**Files:**
- Modify:
  - `mcp-gate/internal/authz/authz.go`: claims `Act`, `PcImp` (`json.RawMessage`); refusal before membership;
  - `docker-compose.yml`:
    - keycloak: `--features-disabled=impersonation` in `command`, `PORTCULLIS_PORTAL_URL: https://${PORTCULLIS_DOMAIN:-portcullis.local}/`;
    - the two headers in the `authResponseHeaders` of `portcullis-auth`, `portcullis-auth-console`, `portcullis-auth-ext` and `portcullis-groups`;
    - group-gate: `GATE_IMPERSONATION_FILE: /hub-data/impersonation.json`;
    - hub: `HUB_IMPERSONATION_MAX_MINUTES: ${IMPERSONATION_MAX_MINUTES:-30}`;
  - `.env.example`: `IMPERSONATION_MAX_MINUTES` (commented: 1–30, shortens only);
  - `keycloak/realm-export.json`: the `acr` scope's mapper `impersonation` (`portcullis-impersonation`, access + ID + userinfo); `requiredActions` gains `portcullis-impersonation-notice` (enabled, not default); `enabledEventTypes` gains `IMPERSONATE`;
  - `scripts/lib/keycloak.sh` (`keycloak configure`): ensure the mapper on `acr`; register and enable the required action (`POST /authentication/register-required-action`, then `PUT …/required-actions/portcullis-impersonation-notice`); never touch the events config (the Hub owns it);
  - `.github/workflows/ci.yml`: the checks below;
  - core `docs/`, `README.md`, `CLAUDE.md`: one paragraph each.
- Test: `mcp-gate/internal/authz/authz_test.go`, `tests/test_cli.sh`.

**Interfaces:**
- Consumes: the extension's ids (Tasks 2–4) and the D37 file path.
- Produces: `authz.Decision{Status: 403, Reason: "impersonated", Message: "a session as someone else can't use AI tools"}`.

- [ ] **Step 1: Write the failing tests**
  ```go
  func TestImpersonatedTokenRefused(t *testing.T) // valid token + act {"sub":"root"} → 403 impersonated; + pc_imp only → 403; act null → 403;
  //  a non-member with act → impersonated (before population); no act/pc_imp → unchanged
  ```
  `tests/test_cli.sh`:
  - `keycloak command disables the impersonation feature`
  - `every forward-auth middleware's authResponseHeaders lists X-Forwarded-Impersonator and X-Forwarded-Impersonation`
  - `group-gate has GATE_IMPERSONATION_FILE under /hub-data; hub has HUB_IMPERSONATION_MAX_MINUTES`
  - `realm-export: the acr scope has mappers amr and impersonation (portcullis-impersonation); requiredActions has portcullis-impersonation-notice enabled; enabledEventTypes ⊇ LOGIN, LOGIN_ERROR, IMPERSONATE`
  - `keycloak configure ensures the impersonation mapper and the required action (stubbed kc_get / kc_put / kc_post)`
- [ ] **Step 2: Run them to see them fail.** Run `(cd mcp-gate && go test ./internal/authz/) ; bash tests/test_cli.sh`. Expected: FAIL.
- [ ] **Step 3: Implement.** In `ci.yml` `build-and-test`, add the step "Stock impersonation is off": `POST /admin/realms/portcullis/users/<id>/impersonation` with the CLI's admin token (read from a file, never argv) answers non-2xx with a body naming the feature.
- [ ] **Step 4: Run them to see them pass.** Run `bash tests/test_cli.sh && bash tests/test_shell_libs.sh && (cd mcp-gate && go test -race ./...)` and `shellcheck -S warning portcullis scripts/lib/*.sh tests/*.sh`. Expected: pass, no output. Push, then re-run the keycloak repo's "Compare the smoke realm with core's flows" job.
- [ ] **Step 5: Commit and push.** `git add -A && git commit -m "core: impersonation wiring — stock Keycloak impersonation off, claims mapper, notice action, headers stripped, mcp-gate refuses impersonated tokens" && git push`.

---

### Task 11: Core CI and browser e2e (core)

**Files:**
- Modify:
  - `tests/e2e/e2e_signin.py`: the cases below;
  - `.github/workflows/ci.yml`: the e2e-signin job's `.env` sets `IMPERSONATION_MAX_MINUTES=2`.

**Interfaces:**
- Consumes: everything above. Root is the CI admin with a virtual security key (`Key`), and alice and bob are the existing users.

- [ ] **Step 1: Write the failing e2e cases** in `e2e_signin.py`. Each starts with `fresh_auth(page, …)` as root with his security key, then POSTs the start route on the Hub listener:
  - `imp_start`:
    - Setup: start with reason "checking quota", then follow `next`.
    - Expected:
      - root's browser lands on the portal as alice;
      - `token_claims` has `preferred_username` alice, `act.sub` root, `pc_imp.id` = id, and amr = root's amr before the start (plus `hwk`);
      - `kc_sessions(root)` is empty;
      - `kc_sessions(alice)` has one session with the impersonator.
  - `imp_banner_everywhere`: each of these contains `You are signed in as alice (by root) · reason “checking quota” ·` with `min left` and a Stop control:
    - the portal HTML;
    - `people.<d>/` (My apps) and `/signin` after `impersonation.js` ran;
    - a group-gate needs-stronger page (an app on a template root's session can't meet);
    - the extension's page (an AI client's authorize, which also checks `imp_ai_refused`).
  - `imp_call5`:
    - an app on `e2e-cert` (`any[yubikey_cert]`) opens only while the context presents root's YubiKey certificate (`vault_issue("root")`). With alice's certificate it shows the impersonation needs page with no `X-Stepup-URL`.
    - an app on Strong opens although alice has only a password.
  - `imp_people_read_only`: `PUT /api/me/signin/password`, `POST /api/me/signin/browser-certificates` and `DELETE /api/me/ai/connections/x` are 403 with the D42 text. `GET /api/me/apps` is 200.
  - `imp_ai_refused`:
    - the authorize for the CI AI client in this browser shows `#portcullis-impersonating`, and no code is issued;
    - `mcpclient` with a token minted for alice before the start still works, so only impersonated tokens are refused.
  - `imp_stop`:
    - Setup: press Stop on the portal.
    - Expected:
      - the Stop page POSTs, and the browser goes through `/oauth2/sign_out` to the sign-in page;
      - within 20 s `kc_sessions(alice)` has no impersonated session;
      - replaying the old `_oauth2_proxy` cookie on the app gets 403 or a sign-in redirect, never 200;
      - the audit has `impersonation.start` with the reason and `impersonation.end` "stopped" with the apps opened;
      - alice's `/api/me/signin/history` has the `impersonation` entry by root with the reason and the apps.
  - `imp_stop_elsewhere`: a second admin's (CI's `admin2`) `stop_impersonation` MCP call, through `hub_mcp_admin`, ends it. Root's impersonating browser then gets group-gate's ended page on its next request, within 5 s.
  - `imp_expiry`: started with max 2 minutes. After 2 min 10 s, a request gets the ended page, and within a further 20 s Keycloak has no impersonated session. The audit has "expired" by `portcullis`.
  - `imp_notice_next_signin`:
    - Setup: after `imp_stop`, alice signs in herself in a new context.
    - Expected: the notice page shows "root signed in as you on … UTC for … min: checking quota." Continue reaches her app, and her next sign-in shows no notice.
  - `imp_refused_proofs`: fresh proofs with a synced passkey (bob's), a password (password on) and a browser certificate → 403. Another person's proof → 403. Reason "ab" → 400.
  - `imp_refused_targets`: on root (self), on `admin2` (an administrator), on `portcullis-hub` and `admin` → 409. A `sign_in_help` delegate as the caller → 403. Switch off → 409, and a running one ends.
  - `imp_next_bound`:
    - `next` opened in bob's signed-in context → 403 page, and bob's session is intact;
    - `next` opened again in root's context after a successful use → 403;
    - a fresh start whose `next` is opened after 125 s → 403;
    - in each case nothing appears in `kc_sessions(alice)`.
  - `imp_stock_endpoint_off`: the stock admin impersonation endpoint answers non-2xx.
- [ ] **Step 2: Run to see it fail.** Push and let CI run e2e-signin. Expected: the new cases FAIL before the wiring.
- [ ] **Step 3: Implement** the CI wiring (the 2-minute env, the `admin2` fixture if it's missing) and anything the cases expose.
- [ ] **Step 4: Run to see it pass.** CI on `signin3` (core) is green: `unit-tests`, `build-and-test`, `e2e`, `e2e-instances`, `e2e-signin`, `e2e-settings`, `e2e-folders`, `e2e-filesharing` and `e2e-ai`, with the Hub and the Keycloak image built from `signin3`.
- [ ] **Step 5: Commit and push.** `git add -A && git commit -m "ci: impersonation e2e — start, banner, call 5, read-only, AI refused, stop, expiry, notice, refusals" && git push`.

---

### Task 12: Mainline (all repos)

- [ ] **Step 1:** Merge docs `signin3` → main and push.
- [ ] **Step 2:** Merge portcullis-keycloak `signin3` → main and push. Wait for `build.yml` to publish `:edge` (`gh run list -R porelli/portcullis-keycloak --branch main --workflow build.yml` shows success).
- [ ] **Step 3:** Merge hub `signin3` → main and push. Wait for `ghcr.io/porelli/portcullis-hub:edge`, then re-run the keycloak repo's vectors job.
- [ ] **Step 4:** Merge core `signin3` → main and push. Check that CI is green on main.
- [ ] **Step 5:** Re-run templates `test-apps.yml` on main. Expected: green.
- [ ] **Step 6:** Delete every `signin3` branch (local and remote, four repos) and the worktrees under `/Volumes/workspace/portcullis/wt-signin3/`.
- [ ] **Step 7:** Upgrade the test server under the standing OK: `ACME_STAGING=true`, `./portcullis config apply && ./portcullis up`, then `./portcullis keycloak configure`.
  - Check that the stock endpoint is off, and that Settings → Sign-in shows the switch on.
  - Starting an impersonation on the test server is the user's own check (it needs their YubiKey).

---

## Self-review

1. **Spec coverage.**
   - **Who** (`lldap_admin` only; never another admin or the Hub's service account): D36.2–3, checked again in Keycloak (D38). Tasks 5 and 2.
   - **The Settings switch, on by default:** D36.1 (zero value), D41. Tasks 5 and 8.
   - **The fresh touch** (security key or YubiKey certificate only) **and the reason:** D36.4 and D36.9, Task 5. The touch is carried into the session's methods in D38, Task 2.
   - **The 30-minute end and Stop**, killing the Keycloak and oauth2-proxy sessions: D41. Tasks 3, 5, 9 and 11.
   - **The banner on the portal, My apps, People and the sign-in pages:** D43. Tasks 8, 9, 2 and 3.
   - **Apps that keep their own sessions** (accepted, and said in the history): D41, D44. Task 7.
   - **History, admin audit, and the notice at the next sign-in:** D44, D45. Tasks 5, 7 and 4.
   - **No approval step:** none is built.
   - **Call 5** (the admin's methods with the touch, the admin's certificate): D38, D39. Tasks 2, 3 and 9.
   - **MCP twins** (never startable by an AI): D42, D46. Tasks 6 and 10.
   - **The e2e cases:** Task 11.
   - **The anti-goal** "without a fresh hardware touch, a reason and a record the person can see": D35 also closes the stock path.
2. **Step scan.**
   - Every task names its files, its signatures, its tests with assertions, and its commands.
   - Bodies appear only for fixed copy (the banner, the notice line, the refusal texts) and for the D37 file shape.
   - Left to the implementer: page layout within the mockup.
3. **Type consistency.**
   - `state.Impersonation` (Task 5) is used in Tasks 6 and 7. `signinhistory.OpenedApp` is declared in Task 5 and used in Task 7 and the D37 `apps` field.
   - `ImpersonationFile` / `Impersonation.Info` (Task 2) are used in Tasks 3 and 4.
   - The file's field names are identical in D37, `ImpersonationFile.parse`, `writeImpersonationFileLocked` and `load_impersonation_file`.
   - The note names `portcullis.imp.id` / `.until` / `.reason` match across Tasks 2–4.
   - The ids match across tasks:
     - `portcullis-impersonate` (Tasks 2 and 5's `next`);
     - `portcullis-impersonation` (Tasks 2 and 10);
     - `portcullis-impersonation-notice` (Tasks 4, 5 and 10).
   - The env names match: `GATE_IMPERSONATION_FILE`, `HUB_IMPERSONATION_MAX_MINUTES` / `IMPERSONATION_MAX_MINUTES` and `PORTCULLIS_PORTAL_URL` (Tasks 2, 5, 9, 10 and 11).
   - The header names match in D40 and Tasks 6, 9 and 10.
4. **Review Focus.** Each of its five lines names tests in their owning tasks.
5. **Proportion.** Smaller than part 2's plan. Its code blocks are signatures, test names and the file shape.
