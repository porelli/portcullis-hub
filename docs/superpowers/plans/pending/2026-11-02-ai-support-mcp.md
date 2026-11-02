# AI Support (MCP) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** People use their Portcullis apps from Claude (or any MCP
client) and from an AI page, as themselves. Admins switch AI support on
per instance; every template declares `ai.mcp` (an upstream or vetted
community companion) or `ai.unsupported` (with the reason). One "all my
apps" endpoint covers everything a person can use, and the Hub serves its
own Portcullis MCP that can do whatever the signed-in admin can do in the
Hub, with destructive actions needing a fresh passkey touch.

**Architecture:**
- **Core `mcp-gate`** (new Go service, official MCP Go SDK) terminates
  every MCP request:
  - per-app endpoints on app hosts (`https://gitea.<d>/mcp`);
  - the aggregate on `https://mcp.<d>/mcp`;
  - the Portcullis MCP on `https://hub.<d>/mcp` and `https://people.<d>/mcp`.
  It validates the Keycloak token for exactly that resource, checks the
  person's population on every request, applies tool policy, rate limits
  and confirmations, writes the access log and talks to the upstream with
  the identity the template's identity mode defines. It never forwards the
  person's token.
- **Hub** owns everything around it:
  - Keycloak AI clients and `mcp:*` scopes;
  - `mcp-gate.json` (written with the policy file) and
    `mcp-credentials.json` (per-person app credentials, age-encrypted to
    the gate; the Hub can't read them back);
  - companion containers (override `scale`, alias, `portcullis-mcp-…`
    router);
  - the confirmation pages (fresh passkey);
  - the Portcullis MCP on a third listener `:8890` that only the gate
    reaches;
  - the People-page "Connect your AI" card;
  - Settings → AI with pluggable model providers.
- **Templates** declare `ai:` (validator requires it). Pilots: gitea
  (`app_token`), grafana (`identity_headers`), homeassistant
  (`app_oauth`). The AI page is a new `ai-chat` template (LibreChat).
  Everything app-specific is template glue (hooks), never Hub code.

**Tech Stack:**
- Hub: Go; new pinned modules:
  - `github.com/modelcontextprotocol/go-sdk` (v1.7.x; MCP server);
  - `filippo.io/age` (encrypt credentials to the gate's recipient);
  - `github.com/gowebpki/jcs` (RFC 8785 canonical JSON for argument
    digests);
  - `github.com/coreos/go-oidc/v3` and `golang.org/x/oauth2` (fresh auth;
    from file sharing Task 7, or added here, see "Bases and order").
- Core `mcp-gate`: Go; `github.com/modelcontextprotocol/go-sdk` (server
  and client), `github.com/coreos/go-oidc/v3` (JWKS/JWT),
  `filippo.io/age`, `golang.org/x/time/rate`, `github.com/gowebpki/jcs`;
  base images pinned by digest like `domains/Dockerfile`.
- Core e2e: Python Playwright (existing `tests/e2e` venv) plus a small Go
  MCP client (`tests/e2e/mcpclient`, Go SDK client).
- Templates: JSON Schema + `tests/validate.py`; LibreChat, MongoDB,
  Meilisearch, `gitea-mcp`, `mcp-grafana` images pinned `tag@sha256`.
- Docs: zensical.

**Spec:** `docs/superpowers/specs/2026-11-02-ai-support-mcp-design.md` (hub repo).
Read it together with:
- project 1's plan `docs/superpowers/plans/pending/2026-11-02-app-settings-panel.md`
  ("Interfaces for later plans": every name used here comes from it);
- project 2's plan `docs/superpowers/plans/pending/2026-11-02-shared-folders-doctor.md`
  (doctor API, `doctor.Check`, `Register`, `doctor.Inputs`);
- project 3's plan `docs/superpowers/plans/pending/2026-11-02-file-sharing.md`
  (Task 7: `internal/freshauth`).

**Bases and order.**

| Repo | Base when this plan was written |
|---|---|
| hub | `main` `0aab28d` |
| core | `main` `80dd54e` |
| docs | `main` `84ff201` |
| templates | `new-apps` `330bc59` |

- **This project starts only after project 1 (`settings`) has merged into
  `main` in every repo** (templates: into `new-apps`, or `main` once
  `new-apps` has landed). It needs hooks with stdin (`ExecStdin`,
  `runHook`), `HookTriggers`, data files, the delivery units, the secret
  store, `populationLocked` / `InPopulation`, `People.Membership`,
  `MyApp` and `peopleAppRoutes`. Re-read project 1's "Interfaces for
  later plans" first; line numbers quoted from today's code may have
  moved, so find code by name.
- **Branch:** every repo works on a branch named **`ai`**, cut from the
  bases above after project 1 has merged.
  - Hub CI clones the same-named templates and core branches
    (`TestRealTemplates*`, `TestCore*Complete`).
  - Core CI builds the Hub from its same-named branch
    (`.github/actions/hub-image`).
  - Templates `.core-ref` is set to `ai` on the branch and back to `main`
    before merging.
- **Work order:** contract (T1) → core gate (T2–T6) → Hub (T7–T23) →
  templates (T24–T29) → core e2e (T30) → docs (T31) → deploy (T32). This
  follows the spec's order: the Gitea pilot (T25) is exercised by the e2e
  before the aggregate and the other pilots are trusted.
  - Hub `TestRealTemplates*` is red from T8 (the validator requires
    `ai:`) until templates T24 is pushed. Push hub, core and templates
    `ai` together at the end of T24, then keep pushing all three per
    task.
- **Merge order:** docs → core → Hub → templates (core first: the Hub's
  `TestCoreNamesComplete` needs `mcp-gate` / `mcp_gate_data`).

**Running alongside projects 2 (folders) and 3 (file sharing).**
- Independent of both, and can run in parallel with them: T1–T19 and
  T21–T32, except the two items below.
- **Needs project 2 merged:** T20 (doctor and folder tools of the
  Portcullis MCP, and the four AI doctor checks). If the rest of `ai` is
  ready first, it merges without T20; T20 then lands on a branch
  `ai-doctor` cut from the `main` that contains both.
- **Fresh passkey touch (T14):**
  - if file sharing's Task 7 has merged, T14 consumes `internal/freshauth`
    and `EnsureFreshAuthClient` as they are;
  - otherwise T14 builds `internal/freshauth` **to file sharing Task 7's
    interface exactly** (same package, constants, types and tests), and
    file sharing then skips its Task 7 and consumes this one.
  - Either way T14 widens one signature, because AI confirmations run on
    two hosts: `EnsureFreshAuthClient(ctx, redirectURIs, webOrigins []string)`
    (was one string each) and one `freshauth.Verifier` per listener
    (`Config.RedirectURI` stays a single string per verifier). Whichever
    project lands second updates the other's caller.
- **`my_file_share_password`** (people tool): built in T19 only if file
  sharing has merged; otherwise file sharing's plan adds it (the tool
  returns the People-page link only, never the password).
- **Merge conflict hotspots** (whoever lands second resolves):
  - `peopleAppRoutes` in `internal/httpapi/people_test.go` (file sharing
    appends 2 routes, this plan 4);
  - contract section numbers (this plan's new section is **§15**, after
    project 1's §13 and project 2's §14);
  - `templates.HookTriggers` (file sharing adds `credential_change`, this
    plan `ai`);
  - `MyApp` (this plan adds `AI`);
  - every Hub method with an `actor string` parameter (T7 turns them into
    `directory.Actor`; projects 2/3 add more).

## Global Constraints

- **No migration or back-compat code.** There are no installs. Every
  template gets its `ai:` block in the same change that makes the
  validator require it.
- **Contract first:** `portcullis-docs/docs/guides/integration-contracts.md`
  (T1) before code in the other repos. Template contract v3 (with project
  1's §13).
- **Portcullis writes no app MCP server.** Companions are the app's
  built-in server, the upstream's official image, or a vetted community
  image, pinned `tag@sha256`, never built for Portcullis. `mcp-gate` and
  the aggregate only proxy tools upstreams define. Mint/revoke hooks call
  the app's own CLI/API and never see tool traffic.
- **No app-specific Hub code.** No template id appears in Hub or gate
  code (a test greps for the pilot ids, T12).
- **Resources** (canonical URL = audience; scope):

  | Resource | URL | Scope | Population |
  |---|---|---|---|
  | companion | `https://<host of router><public_path>` | `mcp:<instance-id>.<companion>` | the instance's settings population (project 1 call 27), instance enabled |
  | all my apps | `https://mcp.<d>/mcp` | `mcp:all` | every LLDAP user except the service account |
  | Portcullis admin | `https://hub.<d>/mcp` | `mcp:portcullis.admin` | `lldap_admin` members |
  | Portcullis people | `https://people.<d>/mcp` | `mcp:portcullis.people` | every LLDAP user except the service account |

  Metadata at `/.well-known/oauth-protected-resource<path>` on the same
  host. Authorization server `https://auth.<main d>/realms/portcullis`.
- **Token rules (gate):** `Authorization: Bearer` only; RS256/ES256 per
  JWKS (never `none`/HS*); `iss` exact; `exp`/`nbf`/`iat` ±60 s; `typ`
  `Bearer`; `azp` ∈ the file's `clients`; `aud` contains this resource's
  URL **and no other MCP resource URL**; `scope` contains this resource's
  scope; `acr` LoA ≥ the resource's `min_loa` (realm map
  `{"public":0,"pwd":1,"hwk":2,"mtls":3}`); lowercase
  `preferred_username` ∈ population and not past its `expiring` time; an
  `Origin` header, if present, ∈ `allowed_origins` (default empty).
  `401` bad/missing token; `403` valid but not allowed; `403
  error="insufficient_scope"`; `429` + `Retry-After` over a limit; `503`
  "AI support is off on this Portcullis" when the master switch is off or
  `mcp-gate.json` is missing; every request refused (`503`) while the file
  exists but doesn't parse.
- **Protocol versions:** `2025-06-18`, `2025-11-25`, `2026-07-28` (client
  side and Hub listener); anything else `400` "unsupported protocol
  version". 2026-07-28: `Mcp-Method` / `Mcp-Name` must match the body,
  else `400` JSON-RPC `-32020`; decisions always use the parsed body.
- **Keycloak AI clients** (public, standard flow only, PKCE S256 required,
  consent required, default ACR `hwk`; direct access, implicit, device,
  CIBA, service accounts, token exchange off; owner-tagged
  `portcullis.hub.template` = `portcullis-ai`):
  - `portcullis-ai-claude`: redirect exactly `https://claude.ai/api/mcp/auth_callback`;
  - `portcullis-ai-claude-code`: `http://localhost:33418/callback`,
    `http://127.0.0.1:33418/callback`;
  - `portcullis-ai-generic`: the same loopback redirects;
  - one confidential client per `ai-chat` instance (manifest
    `ai_client: true`).
  - DCR and CIMD stay off; resource indicators not enabled.
- **Scopes:** one optional client scope per resource, named as above, one
  Audience mapper (included custom audience = the resource URL, access
  token only), "include in token scope" on, consent text:
  - companion: `Use <label> (<host>) as you`;
  - `mcp:all`: `Use all your Portcullis apps as you`;
  - `mcp:portcullis.admin`: `Manage Portcullis as you — administrator`;
  - `mcp:portcullis.people`: `Use your Portcullis account as you`.
  - Attached only as **optional** scopes of AI clients (the admin scope
    only to clients the admin enabled it for), never to app clients,
    `portcullis-forward-auth` or realm defaults; no group/attribute
    mappers.
- **Connection length** (Settings → AI): offline session idle default 7 d
  (bounds 1–30), max default 30 d (bounds 1–90); access tokens 5 min
  (realm); refresh tokens rotate (revoke refresh token on, reuse 0).
- **mTLS rule:** an instance whose effective policy has LoA 3
  (`policy.ACR(...) == "mtls"`, tier `protected@file`) can't get AI
  support (`409`); saving such a policy switches AI off first. Same for
  the admin resource if the hub host is moved to mTLS-only. No exception.
- **Identity modes:** `app_token` (Hub-minted per-person credential,
  injected by the gate), `identity_headers` (gate sends
  `X-Forwarded-User`, `X-Forwarded-Email`, `X-Auth-Request-Groups`,
  `X-Forwarded-Attr-*` plus the template's `caller_secret`), `app_oauth`
  (gate not in the path; never aggregated; `revoke` hook required; modes
  `[read_write]` only). No shared-admin mode exists.
- **Gate → upstream headers:** only what the identity mode defines plus
  `MCP-Protocol-Version` / `Mcp-Method` / `Mcp-Name` / `Content-Type` /
  `Accept` / the upstream session id. Never `Cookie`, the person's token,
  `X-Forwarded-*` (other than the identity mode's), `X-Auth-Request-*`,
  `Remote-*` or `X-Portcullis-*` from the client. Nothing on an MCP route
  sets or reads a cookie.
- **Credentials:** name in the app `portcullis-ai-<12 random [a-z0-9]>`;
  mint stdin `{"action":"mint","user","instance","companion","name","mode","scopes"}`,
  stdout `{"credential","id"}`; exit `3` = person has no app account yet;
  revoke stdin `{"action":"revoke","user","ids":[…]}` or
  `{"action":"revoke_all","prefix":"portcullis-ai-"}`. Hook stdout is
  parsed and dropped, never logged, stored, audited or put in an op
  record; failures keep exit code + redacted, clipped stderr only. Hooks
  an `ai:` block names must be `when: [ai]`.
- **Confirmations:** destructive tools (class **D**) and companion
  `confirm` tools. Id = 128 random bits (base32 `XXXX-XXXX-…` display);
  bound to (person, resource, tool, SHA-256 of RFC 8785 canonical JSON
  arguments); single use; valid 10 min; consumed by the first matching
  retry; any argument change → a new confirmation. The page is on
  `hub.<d>/confirm/<id>` (admin tools) or `people.<d>/confirm/<id>`
  (people tools, companions); it refuses any browser user but the
  person, shows the Hub-rendered action, asks for the existing typed
  check, then a fresh Keycloak sign-in through `portcullis-fresh-auth`
  (`auth_time` ≤ 5 min, `amr` `hwk` or `mtls`, never `file`). Form-mode
  elicitation is never a confirmation. Text without URL elicitation:
  `This needs your confirmation in your browser: open <url>, then ask me to try again.`
  Never HTTP 401/403 for this.
- **Rate limits** (defaults, editable; per person):
  - 120 req/min per person and resource (burst 30); 600 req/min per
    person across resources;
  - 60 `tools/call`/min per person and resource;
  - 10 confirmations started per person per hour; 10 mints per person
    per minute;
  - aggregate fan-out ≤ 4 parallel upstream calls per request;
  - request body ≤ 8 MiB, tool result ≤ 16 MiB, upstream timeout 120 s.
- **Aggregate tool names:** `<instance-id>__<tool>`; Portcullis people
  tools `portcullis__<tool>`; longer than 64 → first 55 chars + `_` +
  first 8 hex of sha256(full name). Descriptions prefixed
  `[<label> · <host>] `. List cached 60 s per person.
- **Access log** (`mcp_gate_data/access.jsonl`, gate-owned, 90 days): one
  line per MCP request `{time, user, client, resource, instance,
  companion, via, method, tool, args_sha256, decision, upstream_status,
  duration_ms}`; `via` ∈ `direct|aggregate`; `decision` ∈ `allow`,
  `deny:<reason>`, `confirm:<id>`, `rate_limited`. Never arguments,
  results, tokens or credentials.
- **Audit (`audit.jsonl`):** `AuditEntry` gains `Via` (`"ai"` or empty)
  and `Client` (the `azp`). Portcullis MCP actions use exactly the HTTP
  handlers' action names (today: `instance.create|update|delete|backup|restore`,
  `domain.enroll|token|delete`, `group.*`, `user.*`, `field.*`,
  `permission.set`, `app.sign_in`, `app.compose_override`, plus project
  1–2 actions). The spec's examples `directory.set_rule` /
  `directory.add_member` are `group.rule` / `group.add_member` in code.
  New actions: `ai.enable`, `ai.disable`, `ai.mode`, `ai.providers`,
  `ai.credential.mint`, `ai.credential.revoke`, `ai.connection.revoke`,
  `ai.confirm`, `settings.ai`, `ai.provider.add|update|secret|delete`,
  and (T7, for parity) `instance.enable|disable|restart|exec`, `app.env`,
  `drift.resolve`, `source.add|remove|sync`.
- **Secrets never reach the model:** tools needing a secret (class **U**)
  have no argument for it and return a URL elicitation to the Hub's
  existing form; arguments whose names match `*token*`, `*password*`,
  `*secret*`, `*key*` (case-insensitive) are refused on every tool.
  Results: secret settings `{set, updated_at}`, env/logs redacted then
  clipped, no invite links, file-share passwords, share tokens (`•••`
  with the path) or `HUB_*` secrets.
- **Model provider secrets:** write-only (`{set, updated_at}`),
  `type=password`, cleared on submit; stored only in
  `<data>/ai/provider-secrets.json` (0600) and the env files of the
  `ai-chat` instances that selected the provider, as
  `PORTCULLIS_AI_PROVIDER_<NAME>_<FIELD>` (`<NAME>` upper, `-`→`_`).
- **Reserved names:** Traefik routers and network aliases with prefix
  `portcullis-mcp-`; variables `PORTCULLIS_AI_ENABLED`,
  `PORTCULLIS_AI_READONLY_<COMPANION>`, `PORTCULLIS_MCP_GATE_IP`,
  `PORTCULLIS_AI_PROVIDER_*`; core service `mcp-gate`, volume
  `mcp_gate_data`, core subdomain `mcp`.
- **Pinned values:** `PORTCULLIS_MCP_GATE_IP` default `172.31.250.3`
  (inside `PORTCULLIS_PROXY_SUBNET`, outside `PORTCULLIS_PROXY_IP_RANGE`,
  never Traefik's); Hub `HUB_MCP_ADDR` `:8890`; header
  `X-Portcullis-MCP-Secret` = `HUB_MCP_GATE_SECRET` (file, ≥ 32 chars);
  Claude Code callback port `33418`; mint wait 20 s.
- **Hub hygiene:** `go vet ./... && go test -race ./... && gofmt -l .`
  after every task; update the CLAUDE.md rows a task changes. Core Go:
  the same inside `mcp-gate/`. Frontend vanilla JS, `escapeHtml`/`esc`,
  no inline handlers with data, new assets on the `//go:embed` line.
- **Locks:** never hold `Hub.mu` across docker, Keycloak, LLDAP, hook or
  gate calls; AI lifecycle ops take the per-instance lock (`lockApp`).
- Pin GitHub Actions by full SHA, images and base images by digest.

## Review Focus

1. **A person removed from the access group while their AI is mid-session**
   (valid token, a pooled upstream session in the gate, a cached
   aggregate tool list).
   - Expected: the very next request on every resource that depended on
     the group is refused (`403`); the pooled upstream session is closed;
     the aggregate list drops that app on the next request (no 60 s
     wait); the credential is deleted and revoked in the app at the next
     reconcile.
   - Pinned in Task 3 (`TestLeaverPooledSessionClosed`), Task 5
     (`TestAggregateDropsAppOnPopulationChange`), Task 13
     (`TestLeaverCredentialRevoked`).
2. **A new person's first requests arrive in parallel** (the aggregate
   fans out 4 calls to Gitea; Claude retries).
   - Expected: exactly one mint hook run and one app token; every waiting
     request gets the same entry or the "Preparing your access" error;
     never two tokens.
   - Pinned in Task 13 (`TestConcurrentMintSingleFlight`) and Task 3
     (`TestMintWaitSharedPerPerson`).
3. **The model retries a confirmed call with the same arguments spelled
   differently** (key order, `1` vs `1.0`, `é` vs `é`), or with one
   value changed.
   - Expected: the canonical form matches (RFC 8785) and the confirmation
     is consumed once; a changed value or a second retry gets a new
     confirmation.
   - Pinned in Task 4 (`TestArgsDigestCanonical`, `TestConfirmBinding`).
4. **An AI-enabled instance's hostname changes** while people are
   connected.
   - Expected: tokens for the old URL are refused everywhere; the new
     URL's metadata answers; the scope's audience and consent text name
     the new host; the People card shows the new URL; no router remains on
     the old host.
   - Pinned in Task 15 (`TestSetHostsMovesMCPResource`).
5. **`mcp-gate.json` missing, half-written, or naming an instance
   `mcp-credentials.json` doesn't know (or the reverse)** at gate start or
   during reload.
   - Expected: missing → `503` AI off; unparsable → every request
     refused, the last good config is **not** kept; a credential entry
     for a resource not in the config is never used; a resource with
     `app_token` and no entry for the person mints, never falls back to
     no identity.
   - Pinned in Task 2 (`TestConfigMissingVsCorrupt`) and Task 3
     (`TestNoCredentialNeverAnonymous`).

---

## Phase 1 — contract

### Task 1: Contract (docs repo)

**Files:**
- Modify: `portcullis-docs/docs/guides/integration-contracts.md`: §1, §3 /
  §3.1, §4, §5, §5.1, §8, §9.5, §11, project 1's §13 (hooks), and a new
  **§15 AI support (MCP)**.
- Modify: `portcullis-docs/docs/guides/manifest-reference.md` (the `ai:`
  section, `keycloak_clients[].ai_client`, `when: ai`).

**Interfaces:**
- Produces: the formats every later task implements. The JSON shapes
  below are this plan's decisions (the spec left them to the builder);
  T2–T23 use these field names exactly.

- [ ] **Step 1: §3 / §3.1 / §13 template changes.**
  - The `ai:` block, required in every template, exactly one of
    `ai.mcp[]` and `ai.unsupported` (non-empty, ≤ 200 chars); optional
    `ai.alternative {name, source, note}` only with `unsupported`;
    `ai.on_change` only with `mcp`; `ai.chat` only with `unsupported`.
  - `ai.mcp[]` fields (spec call 11): `name`
    (`^[a-z][a-z0-9-]{0,30}$`, unique), `label`, `kind`
    (`companion|builtin`), `service`, `port`, `path` (default `/mcp`),
    `router` (a host router), `public_path` (default `/mcp`; never under
    `/.well-known/`, `/oauth2/` or a public-access path; unique per
    host), `identity` (`mode` + its parameters), `modes`, `default_mode`,
    `tools {writes, confirm, never}` (names, `*` globs, or `tool:method`
    for consolidated tools), `aggregate` (default true; false for
    `app_oauth`), `upstream` (`official|community`; `builtin` ⇒
    `official`), `source` (URL, required), `protocol` (list of MCP
    versions).
  - `identity` parameters: `app_token {header (default Authorization),
    format ("token {credential}" | "Bearer {credential}"), basic {user,
    password} (placeholders {username}, {credential}), mint, revoke,
    scopes {read_only: [...], read_write: [...]}}`;
    `identity_headers {caller_secret {env, header, format ("Bearer {secret}")}}`;
    `app_oauth {revoke}`.
  - `ai.chat {provider_kinds {<kind>: one|many}, file {service, mount}}`.
  - `keycloak_clients[].ai_client: true`: an AI client (consent, ACR
    `hwk`, optional scope `mcp:all` only).
  - `when: [ai]` hooks (project 1 §13 `HookTriggers` gains `ai`): run only
    by the AI machinery, get the AI stdin of §15.5, stdout never stored.
  - Reserved names and variables from Global Constraints; companion
    services get `scale: 0` from the Hub while AI is off and must not set
    Traefik labels or join `portcullis-proxy`.
  - The `ai-providers.json` data file (`<appfiles>/<id>/ai-providers/ai-providers.json`,
    mounted read-only at `ai.chat.file.mount`):
    `{"version":1,"instance","providers":[{"name","label","kind","base_url","region","instance_name","api_version","deployments":{…},"models":{"fetch":bool,"list":[…]},"credentials":"admin|per_person","env":{"<field>":"PORTCULLIS_AI_PROVIDER_<NAME>_<FIELD>"}}]}`
    (never a secret value; `env` names the variables that hold them).
  - Companions are upstream or vetted community images pinned by digest;
    templates never build images or ship MCP server code.
- [ ] **Step 2: §4 and §5.**
  - §4: `mcp` is a core host (`mcp=*` in `group-gate-map.conf`). Next to
    the policy file the Hub writes `mcp-gate.json` and
    `mcp-credentials.json` (§15.4). Fail-closed rules: missing = AI off;
    unparsable = every MCP request refused.
  - §5: the Hub-rendered router `portcullis-mcp-<instance-id>_<companion>`
    (rule `Host(<router's hosts>) && (Path(<public_path>) ||
    Path(/.well-known/oauth-protected-resource<public_path>))`, the
    host's TLS tier, priority above every router of the instance and its
    public and sign-in routers, service `mcp-gate@docker`, middlewares
    `rate-limit@file,security-headers@file`); core routers on `mcp.<d>`
    (all paths) and on `hub.<d>` / `people.<d>` (`Path(/mcp) ||
    Path(/.well-known/oauth-protected-resource/mcp)`, priority above
    `hub`/`people`); MCP routes carry no forward-auth; browser routes
    never accept bearer tokens (`skip_jwt_bearer_tokens` stays off).
- [ ] **Step 3: §5.1, §8, §9.5, §11.**
  - §5.1 people listener gains exactly: `GET /api/me/ai`,
    `DELETE /api/me/ai/connections/{client}`, `GET /confirm/{id}`,
    `POST /api/me/confirmations/{id}`; `GET /api/me/apps` gains `ai`.
  - §8: AI clients, `mcp:*` scopes, audience mappers, consent, per-client
    offline-session attributes; the Hub attaches `mcp:*` nowhere else.
  - §9.5: `via`, `client` in audit entries; the new actions (Global
    Constraints).
  - §11: AI state per instance in `state.yaml` and in backups (no
    credentials); same-instance restore and restore-as run `revoke_all`
    before AI traffic is allowed; restore-as starts with AI off; delete
    step 4 removes the instance's `mcp:*` scopes, step 6 its credential
    entries and AI state.
- [ ] **Step 4: §15 AI support (MCP).** Subsections:
  - **15.1 Resources** (table from Global Constraints), RFC 9728
    document `{"resource","authorization_servers":["https://auth.<d>/realms/portcullis"],"scopes_supported":["<scope>"],"bearer_methods_supported":["header"],"resource_name":"<label> on Portcullis"}`,
    the `401` `WWW-Authenticate: Bearer resource_metadata="<url>", scope="<scope>"`.
  - **15.2 Token rules** and **15.3 protocol versions** (Global
    Constraints, verbatim).
  - **15.4 Hub → gate files** (both in `hub_data`, 0640, group 10001,
    atomic):
    - `mcp-gate.json` `{"version":1,"enabled":bool,"issuer","clients":[…],"allowed_origins":[…],"acr_loa":{…},"limits":{"resource_rpm":120,"resource_burst":30,"person_rpm":600,"tool_calls_rpm":60,"confirmations_per_hour":10,"mints_per_minute":10,"fanout":4,"max_request_bytes":8388608,"max_result_bytes":16777216,"upstream_timeout_s":120},"core_hosts":[…],"resources":[Resource]}`;
    - `Resource` `{"url","scope","kind":"companion|aggregate|portcullis_admin|portcullis_people","instance","companion","label","host","app_url","min_loa","upstream","protocol":[…],"mode":"read_only|read_write","identity":{"mode":"app_token|identity_headers|none","header","format","basic_user","secret_ref"},"tools":{"writes","confirm","never"},"aggregate":bool,"population":["user",…],"expiring":{"user":"RFC3339"},"people":{"user":{"email","groups":[…]}}}`
      (`people` only for `identity_headers`; `app_oauth` companions are
      never listed);
    - `mcp-credentials.json` `{"version":1,"credentials":[{"instance","companion","user","id","minted_at","state":"active|revoking","age"}],"caller_secrets":[{"ref":"<instance>/<companion>","age"}]}`
      (`age` = ASCII-armored age ciphertext to the gate's recipient;
      `revoking` entries are never used).
  - **15.5 Identity modes and hook I/O** (Global Constraints, the exit-3
    rule, `on_change` stdin `{"action":"on_change","enabled","mode","companion"}`).
  - **15.6 Confirmations** (Global Constraints), the URL-elicitation /
    text fallback.
  - **15.7 Gate ⇄ Hub internal API** (`http://hub:8890`, header
    `X-Portcullis-MCP-Secret`; identity headers `X-Forwarded-User`,
    `X-Portcullis-AI-Client`, `X-Portcullis-AI-Resource`, trusted only
    there):
    - `POST /internal/credentials` `{resource, user}` → `200 {id}` (entry
      written) | `409 {code:"no_account", app_url}` | `403` (not in
      population) | `502 {code:"mint_failed"}`;
    - `POST /internal/confirmations` `{user, client, resource, tool,
      args_sha256, args_preview}` → `201 {id, url, expires_at}`;
    - `POST /internal/confirmations/consume` `{user, resource, tool,
      args_sha256}` → `200 {id}` | `404` | `409 {state:"pending|declined"}`;
    - `/mcp/admin`, `/mcp/people` (Streamable HTTP).
  - **15.8 Access log** format (Global Constraints).
  - **15.9 Rate limits** and the aggregate naming rule.
- [ ] **Step 5:** update `manifest-reference.md`; run
  `zensical build --strict --clean` → no warnings.
- [ ] **Step 6: commit.** `contracts: AI support (MCP) — ai block, mcp-gate, scopes, confirmations (§15)`.

## Phase 2 — core: `mcp-gate`

### Task 2: Gate module, configuration, token verification

**Files:**
- Create: `portcullis/mcp-gate/go.mod`, `main.go` (flags: `serve`,
  `healthcheck`, `keygen`), `internal/config/{config.go,config_test.go}`,
  `internal/authz/{authz.go,authz_test.go}`,
  `internal/meta/{meta.go,meta_test.go}`.

**Interfaces:**
- Consumes: contract §15.1–15.4.
- Produces:
```go
// internal/config
type File struct{ /* §15.4 mcp-gate.json, json tags as in the contract */ }
type Resource struct{ /* §15.4 */ }
type CredFile struct{ /* §15.4 mcp-credentials.json */ }
type Store struct{ /* atomic.Pointer to the current snapshot */ }
func Open(dir string, ident age.Identity) (*Store, error) // watches <dir>/mcp-gate.json, mcp-credentials.json, user-attributes.json (fsnotify-free: stat poll every 2 s)
func (s *Store) Snapshot() *Snapshot
type Snapshot struct{ Err error; Off bool; File *File; Creds map[CredKey]Cred; Attrs map[string]map[string]string }
type CredKey struct{ Instance, Companion, User string }
func (sn *Snapshot) Resource(host, path string) (*Resource, bool)
// internal/authz
type Request struct{ Host, Path, Authorization, Origin string; Now time.Time }
type Decision struct{ Status int; WWWAuthenticate, Reason string; User, Client string; Resource *config.Resource }
type Verifier struct{ /* go-oidc RemoteKeySet on MCP_GATE_JWKS_URL */ }
func NewVerifier(issuer, jwksURL string, hc *http.Client) *Verifier
func (v *Verifier) Check(ctx context.Context, sn *config.Snapshot, r Request) Decision
func CheckProtocol(h http.Header, body []byte) (version string, err *ProtocolError) // ProtocolError{Status, Code (-32020), Msg}
// internal/meta
func Handler(sn func() *config.Snapshot) http.Handler // GET /.well-known/oauth-protected-resource<path>
```
- Env: `MCP_GATE_LISTEN` (`:8080`), `MCP_GATE_HUB_DATA` (`/hub-data`),
  `MCP_GATE_DATA` (`/data`), `MCP_GATE_AGE_KEY_FILE`,
  `MCP_GATE_HUB_SECRET_FILE`, `MCP_GATE_JWKS_URL`
  (`http://keycloak:8080/realms/portcullis/protocol/openid-connect/certs`),
  `MCP_GATE_HUB_URL` (`http://hub:8890`).

- [ ] **Step 1: tests.**
  - `config_test.go`:
    - `TestConfigMissingVsCorrupt` (Review Focus 5): no
      `mcp-gate.json` → `Snapshot().Off == true`, `Err == nil`; a
      truncated file after a good one → `Err != nil` and `File == nil`
      (last good config dropped); a valid file again → served.
    - `TestCredentialsDecrypted`: entries age-encrypted to a test
      identity decrypt; an entry encrypted to another recipient →
      `Err` naming the entry index (never the ciphertext); `revoking`
      entries are absent from `Creds`.
    - `TestCredentialForUnknownResourceIgnored`: an entry whose
      `(instance, companion)` has no resource is dropped.
    - `TestResourceLookupNormalised`: Host `Gitea.Example.COM.:443`,
      path `/mcp` → the gitea resource; `/mcp/` and `/MCP` → none.
  - `authz_test.go` (`TestTokenMatrix`, an RSA test key + JWKS server;
    each row → status and reason):
    - valid → 200, `User` lowercased (`Alice` → `alice`);
    - no header / `Bearer` with a query-string token → 401 with
      `resource_metadata` and `scope`;
    - wrong `aud`; `aud` containing this URL **and** another resource's
      URL → 401; `aud` with a non-MCP extra audience (e.g. `account`) →
      200;
    - `azp` `portcullis-forward-auth`, or an app's client → 401;
    - expired; `nbf` +120 s; `alg: none`; HS256 signed with the JWKS
      modulus; unknown `kid` (JWKS refreshed once, then 401);
    - `typ` `Refresh` → 401;
    - missing scope → 403 `error="insufficient_scope", scope="mcp:gitea.gitea"`;
    - `acr` `pwd` for `min_loa` 2 → 403; `acr` unknown → 403;
    - user not in population → 403; in population but `expiring` in the
      past → 403, in the future → 200;
    - `Origin: https://evil.example` → 403; listed origin → 200;
    - file `enabled: false` → 503 with the off message; corrupt file →
      503.
  - `TestProtocolVersions`: `MCP-Protocol-Version` `2025-03-26` → 400
    "unsupported protocol version"; the three supported → ok; an
    `initialize` body with `protocolVersion: 2024-11-05` → 400.
  - `TestHeaderBodyMismatch`: 2026-07-28 `Mcp-Method: tools/list` with a
    `tools/call` body → 400 code `-32020`; `Mcp-Name: a` vs body name `b`
    → -32020.
  - `meta_test.go` `TestProtectedResourceMetadata`: the exact JSON of
    contract §15.1 for gitea; unknown path → 404; no cookie set.
- [ ] **Step 2: run.** `cd mcp-gate && go test -race ./internal/...` → FAIL.
- [ ] **Step 3: implement.** JWKS through `oidc.NewRemoteKeySet`; claims
  parsed with `go-oidc`'s verifier configured `SkipClientIDCheck: true`
  (audience checked by our own rule above); `acr` → LoA through the
  file's `acr_loa`. `main.go keygen` writes an age X25519 identity and
  prints its recipient (used by `portcullis init`, Task 6).
- [ ] **Step 4: verify.** `cd mcp-gate && go vet ./... && go test -race ./... && test -z "$(gofmt -l .)"` → PASS.
- [ ] **Step 5: commit.** `mcp-gate: configuration, token and audience checks, resource metadata`.

### Task 3: Per-app bridge, identity, tool policy, limits, access log

**Files:**
- Create: `mcp-gate/internal/bridge/{bridge.go,upstream.go,identity.go,policy.go,bridge_test.go}`,
  `mcp-gate/internal/limits/{limits.go,limits_test.go}`,
  `mcp-gate/internal/accesslog/{log.go,log_test.go}`,
  `mcp-gate/internal/hubapi/{client.go,client_test.go}`.

**Interfaces:**
- Consumes: Task 2 `Snapshot`, `Decision`, `Resource`.
- Produces:
```go
// internal/bridge — an SDK server facing the client, an SDK client per (person, resource) upstream
type Bridge struct{ /* sessions, pool, policy, log, limits, hub */ }
func New(cfg Config) *Bridge
func (b *Bridge) ServeResource(w http.ResponseWriter, r *http.Request, d authz.Decision) // per-app endpoint
func (b *Bridge) Upstream(ctx context.Context, user, client string, res *config.Resource) (*mcp.ClientSession, error) // pooled, idle 10 min
func (b *Bridge) DropUser(user string) // closes the user's pooled sessions (called on every snapshot change for leavers)
func FilterTools(res *config.Resource, tools []*mcp.Tool) []*mcp.Tool
func CallDecision(res *config.Resource, tool string, args json.RawMessage, ann *mcp.ToolAnnotations) (allow, confirm bool, reason string)
func Match(pattern, tool, method string) bool // "*" globs; "repo_write:delete" matches tool repo_write with arguments.method == "delete"
// internal/bridge (identity.go)
func Transport(base http.RoundTripper, sn func() *config.Snapshot, res *config.Resource, user string, mint Minter) http.RoundTripper
type Minter interface{ Mint(ctx context.Context, resource, user string) error }
// internal/limits
type Limiter struct{}
func (l *Limiter) Allow(user, resource string, toolCall bool) (ok bool, retryAfter time.Duration)
func (l *Limiter) AllowConfirm(user string) bool
func (l *Limiter) AllowMint(user string) bool
// internal/accesslog
type Line struct{ Time time.Time; User, Client, Resource, Instance, Companion, Via, Method, Tool, ArgsSHA256, Decision string; UpstreamStatus int; DurationMS int64 }
func Open(path string, retention time.Duration) (*Log, error)
func (l *Log) Write(Line) error // never blocks a request > 50 ms; errors counted and logged
// internal/hubapi
func (c *Client) Mint(ctx context.Context, resource, user string) (*MintAnswer, error)
func (c *Client) CreateConfirmation(ctx, req ConfirmRequest) (*Confirmation, error)
func (c *Client) ConsumeConfirmation(ctx, req ConsumeRequest) (id string, state string, err error)
```

- [ ] **Step 1: tests** (fake companion = an SDK server in `httptest`
  recording headers and calls; fake Hub API).
  - `TestIdentityAppToken`: format `token {credential}` → upstream gets
    `Authorization: token s3cr3t`, nothing else identity-related;
    `basic {user: "{username}", password: "{credential}"}` → Basic
    `alice:s3cr3t`.
  - `TestIdentityHeaders`: `X-Forwarded-User: alice`, `X-Forwarded-Email`,
    `X-Auth-Request-Groups` from `people`, `X-Forwarded-Attr-Team` from
    `user-attributes.json` for the resource's host, and the caller
    secret header; a person missing from `people` → no email/groups
    header (never a stale one).
  - `TestClientHeadersNeverForwarded`: client sends `Cookie`,
    `Authorization` (its token), `X-Forwarded-User: root`,
    `X-Auth-Request-User`, `Remote-User`, `X-Portcullis-Proxy-Secret` →
    none reach the upstream; the response sets no cookie.
  - `TestNoCredentialNeverAnonymous` (Review Focus 5): `app_token`, no
    entry → `Mint` called, request waits; after the entry appears (≤ 20
    s) the call proceeds with it; no entry by then → JSON-RPC error
    `Preparing your access to Gitea, try again in a moment`; the upstream
    is never called without the header.
  - `TestMintNoAccount`: Hub answers 409 `no_account` → error text
    `Open Gitea (https://gitea.example.com) in your browser once, then try again`.
  - `TestMintWaitSharedPerPerson` (Review Focus 2): 4 concurrent calls by
    a new person → one `Mint` call (singleflight per (resource, user)).
  - `TestToolFilter`: `never` hidden in every mode; read-only hides
    `writes` globs (`create_*`, `*_write`); `tools/call` on a hidden tool
    → JSON-RPC error, access log `deny:never` / `deny:read_only`;
    `repo_write` with `method: delete` matches `repo_write:delete`.
  - `TestAnnotationAddsConfirmNeverRemoves`: a tool annotated
    `destructiveHint: true` not in `confirm` → confirm (template warning
    logged); `readOnlyHint: true` on a `writes` tool → still hidden in
    read-only.
  - `TestServerToClientRequests`: the upstream's sampling request →
    declined, the person's client never sees it; roots → declined; form
    elicitation → passed through and answered; URL elicitation to
    `https://gitea.example.com/x` or a core host → passed; to
    `https://evil.example` → declined, logged `deny:url_elicitation`.
  - `TestSessionsBoundToPerson`: a 2025-11-25 client gets the gate's own
    session id; bob presenting alice's session id → 404 (unknown
    session); the upstream session id is never shown to the client.
  - `TestUpstreamProtocolNegotiation`: client 2026-07-28, companion
    `protocol: ["2025-11-25"]` → works (the SDK client speaks 2025-11-25
    upstream).
  - `TestLeaverPooledSessionClosed` (Review Focus 1): alice has a pooled
    session; a snapshot without alice in the population → `DropUser`
    closes it; her next request → 403.
  - `TestLimits`: 121st request in a minute → 429 with `Retry-After`;
    61st tool call → 429; 601st across resources → 429; a 9 MiB body →
    413; a 17 MiB result → JSON-RPC error "result too large"; upstream
    sleeping 121 s (fake clock) → timeout error.
  - `TestAccessLogLine`: every field of §15.8 present; no argument value,
    token or credential appears in the file (marker strings); retention:
    lines older than 90 days are removed by `Prune` (rewritten
    atomically).
- [ ] **Step 2: run.** `cd mcp-gate && go test -race ./internal/bridge/ ./internal/limits/ ./internal/accesslog/ ./internal/hubapi/` → FAIL.
- [ ] **Step 3: implement.**
  - The per-app endpoint is an SDK `StreamableHTTPHandler` whose server
    for a request is built per (person, resource), forwarding `tools/*`,
    `resources/*`, `prompts/*` to the pooled upstream `ClientSession`
    (SDK client, `StreamableClientTransport` with `identity.Transport`).
  - The upstream client declares no `sampling` or `roots` capability; its
    elicitation handler forwards form requests to the person's session and
    checks URL hosts against the resource host + `core_hosts`.
  - Every snapshot change: users who left a resource's population →
    `DropUser`.
- [ ] **Step 4: verify** as in Task 2 → PASS.
- [ ] **Step 5: commit.** `mcp-gate: per-app bridge, identity modes, tool policy, limits, access log`.

### Task 4: Confirmations at the gate

**Files:**
- Create: `mcp-gate/internal/confirm/{confirm.go,digest.go,confirm_test.go}`.
- Modify: `mcp-gate/internal/bridge/bridge.go` (call path).

**Interfaces:**
- Consumes: Task 3 `CallDecision`, `hubapi.Client`, `limits.AllowConfirm`.
- Produces:
```go
func ArgsDigest(args json.RawMessage) (string, error) // hex sha256 of RFC 8785 canonical JSON (gowebpki/jcs); null/absent args = "{}"
func Preview(args json.RawMessage) string             // ≤ 4 KiB, canonical, clipped on a rune boundary
type Gate struct{}
func (g *Gate) Before(ctx context.Context, sess *mcp.ServerSession, user, client string, res *config.Resource, tool string, args json.RawMessage) (proceed bool, result *mcp.CallToolResult, err error)
```

- [ ] **Step 1: tests.**
  - `TestArgsDigestCanonical` (Review Focus 3): `{"b":1,"a":"é"}` and
    `{"a":"é","b":1.0}` → same digest; `{"a":"é","b":2}` → different;
    `null` = `{}`.
  - `TestConfirmBinding`: first call of a `confirm` tool → the Hub gets
    `{user, client, resource, tool, args_sha256, args_preview}`, the
    upstream is not called; consume answers `200` on the retry → the
    upstream is called once; a second retry → a new confirmation; a
    retry with changed arguments → new confirmation; consume `409
    pending` → `isError` text "Still waiting for your confirmation in
    your browser"; `409 declined` → `isError` "You declined this in your
    browser".
  - `TestConfirmationShape`: a 2026-07-28 client that declared
    `elicitation.url` → `InputRequiredResult` with a URL elicitation
    (`mode: url`, the Hub's URL, message `<Tool> on <label> needs your
    confirmation in your browser.`); a 2025-11-25 client with
    `elicitation.url` → a URL-mode `elicitation/create` request, then the
    `isError` text; no URL capability → only the exact text of Global
    Constraints; never a 401/403; never form mode.
  - `TestConfirmRateLimit`: the 11th confirmation in an hour → `isError`
    "Too many confirmations requested; try again later", logged
    `rate_limited`.
  - Access log: `confirm:<id>` on creation, `allow` on the consumed retry.
- [ ] **Step 2: run.** `cd mcp-gate && go test -race ./internal/confirm/ ./internal/bridge/` → FAIL.
- [ ] **Step 3: implement** as the signatures say.
- [ ] **Step 4: verify** → PASS.
- [ ] **Step 5: commit.** `mcp-gate: confirmations for companion tools (URL elicitation, canonical argument digests)`.

### Task 5: Aggregate endpoint and the Portcullis upstreams

**Files:**
- Create: `mcp-gate/internal/aggregate/{aggregate.go,names.go,aggregate_test.go}`,
  `mcp-gate/internal/portcullis/{proxy.go,proxy_test.go}`.
- Modify: `mcp-gate/main.go` (routing by resource kind).

**Interfaces:**
- Consumes: Tasks 2–4.
- Produces:
```go
func ToolName(instance, tool string) string // "<instance>__<tool>", >64 → name[:55]+"_"+hex8(sha256(name))
type Aggregate struct{}
func (a *Aggregate) ServeHTTP(w http.ResponseWriter, r *http.Request, d authz.Decision)
func (a *Aggregate) Invalidate(user string) // on population / config change
// internal/portcullis: kinds portcullis_admin / portcullis_people
func Proxy(hubURL, secret string) func(w http.ResponseWriter, r *http.Request, d authz.Decision)
```

- [ ] **Step 1: tests.**
  - `TestToolNames`: `gitea` + `list_issues` → `gitea__list_issues`; a
    70-char result → 64 chars, stable across runs, distinct for two
    names that share 55 chars.
  - `TestAggregateList`: alice in gitea + grafana populations → both
    apps' filtered tools + `portcullis__my_apps`, descriptions prefixed
    `[Gitea · gitea.example.com] `; bob in gitea only → no grafana tool;
    `aggregate: false` companions absent.
  - `TestAggregateDropsAppOnPopulationChange` (Review Focus 1): a new
    snapshot without alice in grafana → her next `tools/list` has no
    grafana tool even within the 60 s cache; with
    `subscriptions/listen` she gets `notifications/tools/list_changed`.
  - `TestAggregateLoAPerUpstream`: a token with `acr: hwk` and grafana
    `min_loa: 3` → grafana absent and its calls refused.
  - `TestAggregateUpstreamDown`: grafana unreachable → list has gitea and
    a line in `instructions` "Grafana is unavailable right now"; the
    endpoint answers.
  - `TestAggregateCallRouting`: `gitea__list_issues` → the gitea upstream
    with alice's identity; access log `resource` = gitea's URL, `via`
    `aggregate`; a `confirm` tool → the same confirmation as Task 4.
  - `TestAggregateFanout`: at most 4 concurrent upstream list calls per
    request (fake upstreams count).
  - `TestPortcullisProxy`: `hub.example.com/mcp` → hub `/mcp/admin` with
    exactly `X-Portcullis-MCP-Secret`, `X-Forwarded-User: alice`,
    `X-Portcullis-AI-Client`, `X-Portcullis-AI-Resource` and the MCP
    headers; a client-sent `X-Portcullis-MCP-Secret` / `X-Forwarded-User`
    is replaced, never passed; `people.example.com/mcp` → `/mcp/people`.
  - `TestAggregateNeverHasAdminTools`: the aggregate's Portcullis
    upstream is `/mcp/people`, never `/mcp/admin`, even for root.
- [ ] **Step 2: run.** `cd mcp-gate && go test -race ./internal/aggregate/ ./internal/portcullis/` → FAIL.
- [ ] **Step 3: implement.** The aggregate is an SDK server whose tool
  handlers call per-upstream `ClientSession`s from `Bridge.Upstream`
  (same identity, policy, confirmation and log path); the Portcullis
  people tools come from an SDK client to `/mcp/people` with the same
  headers as `Proxy`. Resources and prompts get the same prefix.
- [ ] **Step 4: verify** → PASS.
- [ ] **Step 5: commit.** `mcp-gate: "all my apps" aggregate and Portcullis MCP forwarding`.

### Task 6: Core wiring (compose, secrets, routes, Keycloak realm, CI)

**Files (core):**
- Create: `mcp-gate/Dockerfile` (builder `golang:1.27.3-alpine3.24@sha256:…`,
  runtime `alpine:3.24.3@sha256:…` as in `domains/Dockerfile`; uid/gid
  10005; `HEALTHCHECK mcp-gate healthcheck`), `scripts/lib/mcpgate.sh`.
- Modify: `docker-compose.yml`, `group-gate/group-gate-map.conf`
  (`mcp=*`, with a comment that the router has no forward-auth),
  `scripts/lib/common.sh` (secrets dirs), `scripts/lib/network.sh`
  (`PORTCULLIS_MCP_GATE_IP` checks), `scripts/lib/backup.sh`
  (`mcp_gate_data`), `keycloak/realm-export.json`,
  `scripts/lib/keycloak.sh`, `.github/workflows/ci.yml`, `CLAUDE.md`,
  `CHANGELOG.md`.

**Interfaces:**
- Consumes: Tasks 2–5.
- Produces (Hub side relies on these):
  - Secrets: `secrets/mcp-gate/age.key` (gate only, group 10005, 0640),
    `secrets/mcp-gate/age.pub` (recipient, group 10001, 0640),
    `secrets/mcp-gate/hub-secret` (48 random chars, group 10001, 0640),
    generated by `portcullis init` / `up` when missing
    (`mcpgate_ensure_secrets`).
  - Hub env: `HUB_MCP_ADDR: ":8890"`,
    `HUB_MCP_GATE_SECRET_FILE: /run/portcullis/mcp-gate/hub-secret`,
    `HUB_MCP_GATE_RECIPIENT_FILE: /run/portcullis/mcp-gate/age.pub`,
    `HUB_MCP_GATE_DATA_DIR: /mcp-gate-data`; mounts of those two files
    `:ro` and `mcp_gate_data:/mcp-gate-data:ro`.
  - Service `mcp-gate`: networks `portcullis` and `portcullis-proxy`
    (`ipv4_address: ${PORTCULLIS_MCP_GATE_IP:-172.31.250.3}`), `group_add:
    ["10001"]`, volumes `hub_data:/hub-data:ro`, `mcp_gate_data:/data`,
    the two secret files `:ro`; hardening anchor, `read_only`, tmpfs
    `/tmp`; labels: Traefik service `mcp-gate` (port 8080,
    `traefik.docker.network: portcullis-proxy`), routers `mcp`
    (`Host(mcp.<d>)`), `hub-mcp` and `people-mcp` (`Host(hub|people.<d>)
    && (Path(/mcp) || Path(/.well-known/oauth-protected-resource/mcp))`,
    priority `200`), all `authaware@file`, middlewares
    `rate-limit@file,security-headers@file`.
  - Realm: `offlineSessionIdleTimeout: 2592000`,
    `offlineSessionMaxLifespanEnabled: true`,
    `offlineSessionMaxLifespan: 7776000` (the upper bounds; the Hub sets
    shorter per-client values), `revokeRefreshToken: true`,
    `refreshTokenMaxReuse: 0`.
  - `keycloak configure` never deletes or rewrites clients tagged
    `portcullis.hub.template=portcullis-ai` or client scopes named
    `mcp:*`.

- [ ] **Step 1: tests.**
  - `tests/test_shell_libs.sh`: `mcpgate_ensure_secrets` creates the
    three files with the modes/groups above, is idempotent, never prints
    a secret; `network_check` refuses a gate IP inside the dynamic range,
    outside the subnet, or equal to `PORTCULLIS_TRAEFIK_IP`.
  - `ci.yml` wiring check (jq over `docker compose config`, like the
    domains check): the gate's networks are exactly `portcullis` and
    `portcullis-proxy` with the pinned address; only `mcp-gate` mounts
    `age.key`; `hub_data` is read-only in the gate; `mcp_gate_data` is
    written only by the gate and mounted read-only in the Hub; no
    `mcp-gate` router has `portcullis-auth`; the `hub-mcp` /
    `people-mcp` priorities exceed `hub` / `people`;
    `oauth2-proxy/alpha.yaml` has no `skipJwtBearerTokens: true` (and no
    `--skip-jwt-bearer-tokens` flag anywhere).
  - The pinned-images step covers `mcp-gate/Dockerfile`; the Go unit-test
    step runs `mcp-gate` (`go mod verify`, vet, gofmt, `go test -race`).
  - `tests/test_cli.sh`: `portcullis keycloak configure` on a realm with
    a `portcullis-ai`-tagged client and an `mcp:gitea.gitea` scope leaves
    both untouched.
  - e2e-login job (existing) still passes with rotating refresh tokens:
    a forward-auth session survives two cookie refreshes (1 min each) and
    two concurrent tabs (add `refresh_rotation` to `e2e_login.py`).
- [ ] **Step 2: run.** `bash tests/test_shell_libs.sh` and the CI wiring
  check locally (`docker compose config --format json | jq …`) → FAIL.
- [ ] **Step 3: implement.** Add `mcp` to `CORE_SUBDOMAINS` lists the CI
  checks enumerate; document the gate in `CLAUDE.md` (layout row,
  network/secrets rules) and `CHANGELOG.md`.
- [ ] **Step 4: verify.** All core suites (`bash tests/test_cli.sh`,
  `bash tests/test_shell_libs.sh`, `python3 tests/test_group_gate.py`,
  `cd mcp-gate && go test -race ./...`) → PASS.
- [ ] **Step 5: commit.** `core: mcp-gate service, secrets, routes, realm offline sessions, CI checks`.

## Phase 3 — Hub foundations

### Task 7: Audit attribution ("via AI") and audit parity

**Files:**
- Modify: `internal/directory/audit.go`, `internal/directory/authz.go`,
  `internal/directory/service.go` (`run`), `internal/directory/instancegroups.go`,
  `internal/hub/hosts.go` (`Auditor`, `auditOp`), `internal/hub/hub.go`
  (`Groups`), every `internal/hub` method with an `actor string`
  parameter (today: `CreateInstanceAs`, `SetHosts`, `BackupInstance`,
  `RestoreInstance*`, `DeleteInstance`, `Start*`, `EnrollDomain`,
  `ReplaceDomainToken`, `DeleteDomain`, plus those projects 1–3 added),
  `internal/httpapi/*.go` (callers; `s.audit`), tests in each package.

**Interfaces:**
- Produces:
```go
// internal/directory
type AuditEntry struct{ /* + */ Via string `json:"via,omitempty"`; Client string `json:"client,omitempty"` }
type Actor struct{ User, Via, Client string }
func Human(user string) Actor                       // Via "", Client ""
const ViaAI = "ai"
type Caller struct{ User string; Admin bool; Perms map[string]bool; Via, Client string }
func (c *Caller) Actor() Actor
// internal/hub: every `actor string` parameter becomes `actor directory.Actor`;
// Groups.ResolveActor / CreateInstanceGroup / DeleteInstanceGroup take directory.Actor.
// Stored or displayed actors (ops records, created_by, logs) use actor.User only.
// internal/httpapi
func (s *Server) auditAs(a directory.Actor, e directory.AuditEntry, err error) // fills Actor/Via/Client, Result from err
```

- [ ] **Step 1: tests.**
  - `TestAuditViaFields` (directory): a `run` with `Caller{User: "root",
    Admin: true, Via: "ai", Client: "portcullis-ai-claude-code"}` writes
    `"via":"ai","client":"portcullis-ai-claude-code"`; a refusal carries
    them too; a human call has neither key.
  - `TestHubAuditCarriesActor` (hub): `DeleteInstance(…, directory.Actor{User:
    "root", Via: "ai", Client: "c"})` → the `instance.delete` entry has
    via/client; the groups it deletes are audited with the same via/client;
    the op record's actor is `root`.
  - `TestCreatedByIsUserOnly`: a delegate's `CreateUser` with Via `ai`
    stores `created_by` `bob`, not a struct.
  - `TestUnauditedMutationsNowAudited` (httpapi): enable, disable,
    restart, exec, env save, drift resolve, source add/remove/sync each
    write `instance.enable|disable|restart|exec`, `app.env`,
    `drift.resolve`, `source.add|remove|sync` with actor and result; exec
    detail is the service name only (never the command output).
- [ ] **Step 2: run.** `go test -race ./internal/directory/ ./internal/hub/ ./internal/httpapi/ -run 'TestAuditVia|TestHubAuditCarries|TestCreatedByIsUserOnly|TestUnauditedMutations'` → FAIL.
- [ ] **Step 3: implement** (mechanical signature change, then the new
  audit lines through `auditAs`).
- [ ] **Step 4: verify.** `go vet ./... && go test -race ./... && gofmt -l .` → PASS.
- [ ] **Step 5: commit.** `audit: via/client attribution, directory.Actor, audit every admin mutation`.

### Task 8: Manifest `ai:` block and validation

**Files:**
- Create: `internal/templates/ai.go`, `internal/templates/ai_test.go`,
  fixtures `internal/templates/testdata/ai/{companion,headers,oauth,chat,unsupported}/`.
- Modify: `internal/templates/manifest.go` (`Manifest.AI`,
  `KeycloakClient.AIClient`), `internal/templates/settings.go`
  (`HookAI`, `HookTriggers`), `internal/templates/validate.go`,
  `internal/templates/coreref.go` (`reservedRefs` gains
  `portcullis-mcp-`; `coreServices` gains `mcp-gate`; `coreVolumes`
  gains `mcp_gate_data`), `internal/templates/instance.go` (instance
  variables), `internal/policy/file.go` (`coreSubdomains` gains `mcp`),
  every fixture template under `internal/*/testdata` (gets
  `ai.unsupported: "test fixture"`), `CLAUDE.md`.

**Interfaces:**
- Produces:
```go
type AI struct {
    MCP         []Companion  `yaml:"mcp" json:"mcp,omitempty"`
    Unsupported string       `yaml:"unsupported" json:"unsupported,omitempty"`
    Alternative *Alternative `yaml:"alternative" json:"alternative,omitempty"`
    OnChange    string       `yaml:"on_change" json:"on_change,omitempty"`
    Chat        *Chat        `yaml:"chat" json:"chat,omitempty"`
}
type Companion struct {
    Name, Label, Kind, Service string; Port int; Path, Router, PublicPath string
    Identity Identity; Modes []string; DefaultMode string; Tools ToolClasses
    Aggregate *bool; Upstream, Source string; Protocol []string
} // yaml/json snake_case as in contract §3
type Identity struct{ Mode, Header, Format string; Basic *BasicFormat; Mint, Revoke string; Scopes map[string][]string; CallerSecret *CallerSecret }
type BasicFormat struct{ User, Password string }
type CallerSecret struct{ Env, Header, Format string }
type ToolClasses struct{ Writes, Confirm, Never []string }
type Alternative struct{ Name, Source, Note string }
type Chat struct{ ProviderKinds map[string]string; File ChatFile }
type ChatFile struct{ Service, Mount string }
const (
    AIReadOnly = "read_only"; AIReadWrite = "read_write"
    IdentityAppToken = "app_token"; IdentityHeaders = "identity_headers"; IdentityAppOAuth = "app_oauth"
    CompanionKind = "companion"; BuiltinKind = "builtin"
    HookAI = "ai"
    MCPNamePrefix = "portcullis-mcp-"
)
func (c Companion) Aggregated() bool // false for app_oauth, else *Aggregate (default true)
func (c Companion) EffectivePublicPath() string
func ReadOnlyVar(companion string) string // PORTCULLIS_AI_READONLY_<UPPER, - → _>
const VarAIEnabled = "PORTCULLIS_AI_ENABLED"; const VarMCPGateIP = "PORTCULLIS_MCP_GATE_IP"
func ValidateAI(t *Template, compose []byte, routes *Routes) error
// KeycloakClient.AIClient bool `yaml:"ai_client" json:"ai_client,omitempty"`
// HookTriggers gains HookAI.
```

- [ ] **Step 1: tests** (`ai_test.go`, one fixture per row, each error
  naming the field):
  - `TestAIRequired`: no `ai:` → error `ai: required (ai.mcp or ai.unsupported)`;
    both forms → error; empty `unsupported` → error; 201 chars → error.
  - `TestAIAlternativeRules`: `alternative` next to `mcp` → error;
    `alternative` without `source` URL → error; `on_change` with
    `unsupported` → error; `chat` with `mcp` → error.
  - `TestCompanionRules`:
    - `source` missing → error; `name` `Gitea` → error; duplicate name →
      error;
    - `service` not in compose → error; a `companion` service with any
      `traefik.*` label, or joining `portcullis-proxy` → error;
    - `router` not a host router → error; `public_path` `/.well-known/x`,
      `/oauth2/x`, or under a public-access path → error; two companions
      on the same host with the same `public_path` → error;
    - a hook it names missing, or present without `when: [ai]`, or with
      `ai` plus another trigger → error;
    - `app_oauth` + `kind: companion` → error; `app_oauth` without
      `revoke` → error; `app_oauth` with `read_only` in `modes` → error;
    - `identity_headers` without `caller_secret`, or whose `env` is not a
      `generate: random` env entry → error;
    - `app_token` without `mint`/`revoke` → error; `modes` empty →
      error; `default_mode` not in `modes` (when both) → error;
    - `upstream: community` + `kind: builtin` → error.
  - `TestReservedMCPNames`: a template router, middleware, service or
    network alias starting `portcullis-mcp-` → refused at discover; a
    template setting `PORTCULLIS_AI_ENABLED` or `PORTCULLIS_AI_PROVIDER_X`
    → refused (`ReservedVar`); `mcp` as a default subdomain → refused.
  - `TestAIClientFlag`: `ai_client: true` only with `ai.chat` → else error.
  - `TestHookAITrigger`: `when: [ai]` accepted; `HookTriggers["ai"]`.
  - `TestRealTemplates*` (CI) loads every real template's block (red
    until T24).
- [ ] **Step 2: run.** `go test -race ./internal/templates/ -run 'TestAI|TestCompanion|TestReservedMCP|TestHookAI'` → FAIL.
- [ ] **Step 3: implement** `ValidateAI` and call it from discover after
  `ValidateSettingsSpec`; add `mcp-gate` / `mcp_gate_data` to the core
  lists (`TestCoreNamesComplete` passes against core `ai`).
- [ ] **Step 4: verify** → PASS except `TestRealTemplates*` (expected
  until T24).
- [ ] **Step 5: commit.** `templates: ai block (companions, identity modes, unsupported), reserved MCP names`.

### Task 9: AI settings and model providers

**Files:**
- Create: `internal/hub/ai_settings.go`, `internal/hub/ai_providers.go`,
  `internal/hub/ai_settings_test.go`, `internal/hub/ai_providers_test.go`,
  `internal/httpapi/ai.go`, `internal/httpapi/ai_test.go`.
- Modify: `internal/state/state.go`, `internal/httpapi/server.go`
  (`registerAI`, Hub listener only).

**Interfaces:**
- Consumes: project 1's secret store helper (atomic 0600 JSON) and
  `envQuote`; Task 7 `directory.Actor`.
- Produces:
```go
// internal/state
type AISettings struct {
    Enabled bool; Clients AIClients; PortcullisAdmin, PortcullisPeople bool
    OfflineIdleDays, OfflineMaxDays int; Limits AILimits; AllowedOrigins []string
    Providers []ModelProvider; ProviderSecrets map[string]SecretMeta // "<name>.<field>"
}
type AIClients struct{ Claude, ClaudeCode, Generic bool }
type AILimits struct{ ResourceRPM, ResourceBurst, PersonRPM, ToolCallsRPM, ConfirmationsPerHour, MintsPerMinute, Fanout int }
type ModelProvider struct{ Name, Label, Kind, Instance, BaseURL, Region, InstanceName, APIVersion, Credentials string; Deployments map[string]string; Models ProviderModels }
type ProviderModels struct{ Fetch bool; List []string }
// AppState.AI AISettings `yaml:"ai"`
// internal/hub
var ProviderKinds = map[string]ProviderKind{ /* litellm, openai_compatible, anthropic, openai, google, bedrock, azure_openai */ }
type ProviderKind struct{ Fields []string; Required []string; Secrets []string; OptionalSecrets []string; Fetch bool }
func (h *Hub) AISettings() AISettingsView
func (h *Hub) SaveAISettings(u AISettingsUpdate, actor directory.Actor) error
func (h *Hub) ModelProviders() []ProviderView // secrets as {set, updated_at}; used_by [{instance, group, people}]
func (h *Hub) SaveModelProvider(p state.ModelProvider, actor directory.Actor) error
func (h *Hub) SetProviderSecret(name, field string, value []byte, actor directory.Actor) error // value zeroed after write
func (h *Hub) DeleteModelProvider(name string, actor directory.Actor) error // 409 while selected anywhere
func (h *Hub) providerSecrets() (map[string]string, error) // internal; never logged
```
- Kinds (spec call 28): `litellm {instance; secret key}` (base URL filled
  from the installed LiteLLM instance's API host), `openai_compatible
  {base_url required; optional secret key}`, `anthropic|openai|google
  {base_url optional; secret key}`, `bedrock {region; secrets
  access_key_id, secret_access_key}`, `azure_openai {instance_name or
  base_url, api_version, deployments; secret key}`. Fetch allowed for
  `litellm`, `openai_compatible`, `openai`.
- Routes (admins only, bodies `DisallowUnknownFields`, 64 KiB):
  `GET|PUT /api/ai/settings`, `GET|POST /api/ai/providers`,
  `PUT|DELETE /api/ai/providers/{name}`,
  `PUT /api/ai/providers/{name}/secrets/{field}` (`{value}`; answer
  `{set, updated_at}`).
- Defaults on a new install: `Enabled false`, all three clients true,
  `PortcullisAdmin true`, `PortcullisPeople true`, 7 / 30 days, limits
  of Global Constraints, no providers.

- [ ] **Step 1: tests.**
  - `TestAISettingsDefaultsAndBounds`: defaults as above; idle 0 or 31,
    max 0 or 91, idle > max → 400; an origin that isn't `https://host` →
    400; audited `settings.ai` with the changed keys.
  - `TestProviderValidation`: name `Ollama` → 400; duplicate → 409;
    unknown kind → 400; `openai_compatible` without `base_url` → 400;
    `litellm` naming a non-litellm or missing instance → 400; a kind no
    installed chat template declares → 400 "no installed AI page supports
    kind bedrock"; audited `ai.provider.add|update`.
  - `TestProviderSecretsNeverEchoed`: set marker `sk-MARKER-123` →
    absent from every API answer, `state.yaml`, `audit.jsonl`, op
    records, logs (capture), and errors; answer `{set: true,
    updated_at}`; audited `ai.provider.secret` with detail `key replaced`.
  - `TestDeleteProviderInUse`: selected by `ai-chat` → 409 listing
    `ai-chat`; deselected → 204, its secrets deleted from the store,
    audited `ai.provider.delete`.
  - `TestAIRoutesAdminOnly`: delegate → 403; no user → 401; the routes →
    404 on the people listener.
- [ ] **Step 2: run.** `go test -race ./internal/hub/ ./internal/httpapi/ -run 'TestAISettings|TestProvider|TestDeleteProviderInUse|TestAIRoutesAdminOnly'` → FAIL.
- [ ] **Step 3: implement.**
- [ ] **Step 4: verify** → PASS.
- [ ] **Step 5: commit.** `hub: AI settings and write-only model providers`.

### Task 10: Keycloak AI clients, `mcp:*` scopes, connections

**Files:**
- Create: `internal/keycloak/ai.go`, `internal/keycloak/ai_test.go`.
- Modify: `internal/keycloak/kctest` (client scopes with protocol
  mappers, optional-scope attachment, consents, offline sessions),
  `internal/keycloak/live_test.go` (AI cases), `CLAUDE.md`.

**Interfaces:**
- Produces:
```go
const AIOwner = "portcullis-ai"
var AIClientIDs = struct{ Claude, ClaudeCode, Generic string }{"portcullis-ai-claude", "portcullis-ai-claude-code", "portcullis-ai-generic"}
type AIClientSpec struct{ ClientID, Name string; Public bool; Secret string; RedirectURIs []string; OptionalScopes []string; OfflineIdle, OfflineMax time.Duration; Owner string }
func (c *Client) EnsureAIClient(ctx context.Context, s AIClientSpec) error
func (c *Client) DeleteAIClient(ctx context.Context, clientID, owner string) error
type MCPScope struct{ Name, Audience, ConsentText string }
func (c *Client) EnsureMCPScope(ctx context.Context, s MCPScope) error   // creates/updates; Audience mapper "portcullis-mcp-audience"
func (c *Client) DeleteMCPScope(ctx context.Context, name string) error   // detaches everywhere first; missing = nil
func (c *Client) SetOptionalScopes(ctx context.Context, clientID string, scopes []string) error // exactly this set of mcp:* optional scopes; others untouched
type AIConnection struct{ Client string; Consented, LastUsed, Expires *time.Time }
func (c *Client) AIConnections(ctx context.Context, username string, clients []string) ([]AIConnection, error)
func (c *Client) RevokeAIConnection(ctx context.Context, username, clientID string) error // deletes consent + offline sessions for that client
```
- Client attributes: `pkce.code.challenge.method=S256`,
  `client.offline.session.idle.timeout`, `client.offline.session.max.lifespan`,
  `default.acr.values=hwk`, `consentRequired: true`,
  `standardFlowEnabled: true`, all other grants false,
  `oauth2.device.authorization.grant.enabled=false`,
  `oidc.ciba.grant.enabled=false`, `standard.token.exchange.enabled=false`;
  offline_access stays an optional scope.

- [ ] **Step 1: tests (kctest).**
  - `TestEnsureAIClient`: the three public clients exactly as Global
    Constraints (redirects, flags, owner tag, offline attributes in
    seconds); idempotent; an untagged existing `portcullis-ai-claude` →
    `*ConflictError`.
  - `TestEnsureMCPScope`: the scope has `include.in.token.scope=true`,
    `consent.screen.text`, one audience mapper with
    `included.custom.audience` = the URL, access token only; updating the
    audience rewrites the mapper (hostname change); `DeleteMCPScope`
    detaches it from every client first.
  - `TestOptionalScopesExact`: `SetOptionalScopes(c, [mcp:all])` after
    `[mcp:all, mcp:gitea.gitea]` removes only the gitea scope; never
    touches `offline_access` or default scopes; refused for
    `portcullis-forward-auth` and app clients (error).
  - `TestAIConnectionsAndRevoke`: consent + offline session listed;
    revoke deletes both, leaves other clients' sessions.
  - `TestLiveAIObjects` (live, gated by the existing env vars): the same
    objects on Keycloak 26.8.1, plus the builder verifications of spec
    "Left to the builder": loopback redirect port matching (record the
    result in the test's comment and in contract §8; if port-agnostic,
    keep the fixed port anyway for the card), a request for a scope the
    client lacks fails, `amr`/`acr` `hwk` after a passkey sign-in with
    default ACR `hwk`.
- [ ] **Step 2: run.** `go test -race ./internal/keycloak/ -run 'TestEnsureAIClient|TestEnsureMCPScope|TestOptionalScopesExact|TestAIConnections'` → FAIL.
- [ ] **Step 3: implement** on gocloak; raw requests only for consents /
  offline sessions (`/users/{id}/consents/{client}`,
  `/users/{id}/offline-sessions/{clientUuid}`).
- [ ] **Step 4: verify** → PASS.
- [ ] **Step 5: commit.** `keycloak: AI clients, mcp scopes with audience mappers, AI connections`.

### Task 11: Gate files (`mcp-gate.json`, `mcp-credentials.json`)

**Files:**
- Create: `internal/aigate/{files.go,crypt.go,names.go,aigate_test.go}`
  (no Hub import), `internal/hub/ai_gatefile.go`, `internal/hub/ai_gatefile_test.go`.
- Modify: `internal/hub/hub.go` (`WritePolicy` writes the gate file in the
  same pass), `cmd/hub/main.go` (`HUB_MCP_GATE_RECIPIENT_FILE`), `go.mod`
  (`filippo.io/age`).

**Interfaces:**
- Consumes: Task 8 `templates.AI`; Task 9 `state.AISettings`; project 1
  `populationLocked`, `People.Membership`; `policy.Resolve`, `policy.LoA`;
  `user-attributes.json` (unchanged, the gate reads it).
- Produces:
```go
// internal/aigate (JSON = contract §15.4)
type File struct{ /* … */ }; type Resource struct{ /* … */ }; type CredFile struct{ /* … */ }
type Credential struct{ Instance, Companion, User, ID string; MintedAt time.Time; State, Age string }
const StateActive, StateRevoking = "active", "revoking"
func Encrypt(r age.Recipient, plaintext []byte) (string, error) // armored; caller zeroes plaintext
func WriteJSON(path string, v any) error                          // atomic, 0640
func CompanionScope(instance, companion string) string             // "mcp:<instance>.<companion>"
func Alias(instance, companion string) string                      // "portcullis-mcp-<instance>-<companion>"
func Router(instance, companion string) string                     // "portcullis-mcp-<instance>_<companion>"
func CompanionURL(host, publicPath string) string
// internal/hub
func (h *Hub) gateFileLocked() (*aigate.File, error)   // built from state + directory; called by WritePolicy
func (h *Hub) creds() *credStore                        // <data>/mcp-credentials.json, own mutex
```

- [ ] **Step 1: tests.**
  - `TestGateFileResources`: gitea AI on (read_write) → one companion
    resource with URL `https://gitea.example.com/mcp`, scope
    `mcp:gitea.gitea`, upstream
    `http://portcullis-mcp-gitea-gitea:8080/mcp`, `min_loa` from the
    effective policy, tools from the manifest, population = settings
    population; plus `mcp:all`, `mcp:portcullis.admin` (population =
    `lldap_admin` members), `mcp:portcullis.people`; the admin resource
    absent when `PortcullisAdmin` is off; the master switch off →
    `enabled: false`.
  - `TestGateFilePopulationRules`: instance disabled → companion absent;
    `sign_in: native` → empty population; expired-but-not-removed member
    absent; a future expiry → in `expiring`; `app_oauth` companions never
    listed; an `unsupported` template never listed.
  - `TestGateFileIdentityPeople`: `identity_headers` → `people` holds
    each member's email and the groups group-gate would forward (same
    filtering as the policy file); `app_token` → no `people`.
  - `TestGateFileWrittenWithPolicy`: a membership change through
    `TriggerDirectorySync` rewrites both files in one `WritePolicy`; the
    directory failing keeps the last gate file (fail closed, like
    `expiring`).
  - `TestCredentialsEncryptedHubCantRead`: `creds().Put` of `s3cr3t` →
    the file holds armored age text decryptable only by the test
    identity; no Hub API returns it; the Hub process holds no identity
    (there's no code path that loads one: grep test over `internal/hub`
    for `age.ParseX25519Identity`).
  - `TestGateFileFollowsSettings`: `clients` = the offered AI clients
    plus every `ai_client` client of an `ai-chat` instance; `limits` and
    `allowed_origins` = Settings → AI; `acr_loa` = the realm map; the
    admin and people resources have `min_loa` 2.
  - `TestGateFileHasNoTemplateIDs` (Global Constraints): non-test files
    under `internal/hub/ai*.go`, `internal/aigate` contain none of
    `gitea`, `grafana`, `homeassistant`, `librechat`.
- [ ] **Step 2: run.** `go test -race ./internal/aigate/ ./internal/hub/ -run 'TestGateFile|TestCredentialsEncrypted'` → FAIL.
- [ ] **Step 3: implement.** Without a recipient file the Hub writes
  `enabled: false` and Settings → AI says "This core has no mcp-gate".
- [ ] **Step 4: verify** → PASS.
- [ ] **Step 5: commit.** `hub: mcp-gate.json and age-encrypted mcp-credentials.json`.

### Task 12: Per-instance AI support (switch, mode, companion, router)

**Files:**
- Create: `internal/hub/ai_instance.go`, `internal/hub/ai_instance_test.go`,
  fixture `internal/hub/testdata/ai/aiapp/` (a `companion` with
  `app_token`, a second with `identity_headers`, an `on_change` hook).
- Modify: `internal/state/state.go`, `internal/hub/override.go`
  (companion `scale`, alias, `portcullis-mcp-*` router; `exposureLabel`),
  `internal/hub/env.go` (AI variables), `internal/hub/imagelabels.go`
  (the router is a Hub label), `internal/hub/settings.go` (policy save
  vs mTLS), `internal/hub/ai_settings.go` (master switch ensures/removes
  AI clients and scopes), `internal/httpapi/ai.go`, tests.

**Interfaces:**
- Consumes: Tasks 8–11; project 1 `runHook` plumbing (`ExecStdin`).
- Produces:
```go
// internal/state
type AIInstance struct{ Companions map[string]AICompanion; Providers []string }
type AICompanion struct{ Enabled bool; Mode string }
// AppState.AIInstances map[string]AIInstance `yaml:"ai_instances"` (keyed by instance id)
// internal/hub
func (h *Hub) InstanceAI(id string) (*InstanceAIView, error)
func (h *Hub) SetAISupport(ctx context.Context, id, companion string, on bool, actor directory.Actor) error
func (h *Hub) SetAIMode(ctx context.Context, id, companion, mode string, actor directory.Actor) error
func (h *Hub) runAIHook(ctx context.Context, t *templates.Template, name string, stdin []byte) (stdout []byte, res UnitResult)
// stdout returned to the caller only; never logged, stored or put in UnitResult
type InstanceAIView struct{ Unsupported string; Alternative *templates.Alternative; Companions []CompanionView; MasterOff bool }
type CompanionView struct{ Name, Label, URL, Mode, Upstream, Source, IdentityMode, Status, LastError string
    Modes []string; Enabled bool; Population, Credentials, Connections int; Confirm, Never []string; OwnRules bool }
```
- Routes: `GET|PUT /api/instances/{id}/ai` (`{companions: {<name>:
  {enabled, mode}}}`), admins only.
- Override per companion with AI on: `services.<service>.scale: 1`
  (`0` while off, `kind: companion` only), `networks: {portcullis-proxy:
  {aliases: [<Alias>]}}`; router labels (contract §5) on the instance's
  first `traefik.enable` service; env `PORTCULLIS_AI_ENABLED`,
  `PORTCULLIS_AI_READONLY_<C>`, `PORTCULLIS_MCP_GATE_IP` (from core env).

- [ ] **Step 1: tests.**
  - `TestSetAISupportOn`: → state saved, scope ensured
    (`mcp:aiapp.tok`, audience = URL, consent `Use AI App (aiapp.example.com) as you`),
    scope added to the three clients' optional scopes, override has
    `scale: 1`, the alias and the router (exact rule, `authaware@file`,
    priority above every instance router, service `mcp-gate@docker`,
    middlewares `rate-limit@file,security-headers@file`), env
    `PORTCULLIS_AI_READONLY_TOK=false` for read_write, compose up ran,
    `on_change` hook got `{"action":"on_change","enabled":true,"mode":"read_write","companion":"tok"}`,
    gate file lists it, audited `ai.enable`.
  - `TestSetAISupportOff`: router and alias gone, `scale: 0`, scope
    deleted, `revoke_all` hook ran, credential entries gone, `on_change`
    `enabled: false`, audited `ai.disable`.
  - `TestSetAIModeRevokesFirst`: read_write → read_only: `revoke_all`
    before the restart; entries gone; env flag `true`; audited `ai.mode
    read_write -> read_only`.
  - `TestAIRefusals`: master switch off → 409; instance `deleting` /
    `restoring` → 409; effective policy `mtls` (or `all` of mtls +
    webauthn) → 409 "needs a client certificate on every request; AI
    clients can't present one"; `unsupported` template → 409; unknown
    companion → 404; mode not in `modes` → 400.
  - `TestPolicySaveTurnsAIOff`: saving an mtls-only policy on an
    AI-enabled instance switches AI off first (audited `ai.disable` with
    detail `policy needs mTLS`) and the save preview lists the warning.
  - `TestMCPRouterIsExposureLabel`: a running container whose
    `portcullis-mcp-*` labels differ from the override → exposure drift;
    an image label defining a `portcullis-mcp-*` router → refused like
    any image-label router.
  - `TestOnChangeHookOutputNeverStored`: the hook prints `TOKEN-MARKER`
    and exits 1 → op record and `CompanionView.LastError` hold exit code
    and redacted stderr only; `TOKEN-MARKER` nowhere on disk.
  - `TestMasterSwitchManagesClients`: master on → the clients offered
    exist, their offline idle / max attributes follow Settings → AI
    connection length (changing it updates them); Claude Code unticked →
    `portcullis-ai-claude-code` deleted (only when owner-tagged); the
    admin scope is attached only while `PortcullisAdmin` is on; master
    off → scopes and clients kept, gate file `enabled: false`.
  - `TestAppOAuthCompanion`: an `app_oauth` companion switched on → no
    router, alias, scope or gate-file entry; only `on_change` runs and
    the state is saved; off → `on_change` `enabled: false` (app-side
    token revocation on off is Task 13's `TestAppOAuthLeaverRevoked`).
- [ ] **Step 2: run.** `go test -race ./internal/hub/ ./internal/httpapi/ -run 'TestSetAI|TestAIRefusals|TestPolicySaveTurnsAIOff|TestMCPRouterIsExposure|TestOnChangeHook|TestMasterSwitch|TestAppOAuthCompanion'` → FAIL.
- [ ] **Step 3: implement.** Keycloak calls happen outside `mu`; a failure
  after the state save is an `OpError` (op `ai`) and the same request
  re-applies everything.
- [ ] **Step 4: verify** → PASS.
- [ ] **Step 5: commit.** `hub: per-instance AI support (companions, routers, scopes, modes)`.

### Task 13: Hub MCP listener, internal API, credential lifecycle

**Files:**
- Create: `internal/hub/ai_credentials.go`, `internal/hub/ai_credentials_test.go`,
  `internal/hub/ai_accesslog.go` (`AccessLog`, `MyAI`, `DisconnectAI`),
  `internal/httpapi/mcplistener.go` (handler chain of the third
  listener), `internal/httpapi/internal_api.go`, `internal/httpapi/internal_api_test.go`.
- Modify: `internal/httpapi/middleware.go` (`MCPSecret`),
  `cmd/hub/main.go` (`HUB_MCP_ADDR`, `HUB_MCP_GATE_SECRET_FILE`, third
  `http.Server`), `internal/hub/reconcile.go` (credential reconcile),
  `internal/hub/directory.go` (after each `WritePolicy`), `CLAUDE.md`
  (three listeners).

**Interfaces:**
- Produces:
```go
func MCPSecret(secret string, next http.Handler) http.Handler // constant time; /healthz exempt; strips X-Portcullis-MCP-Secret before next
func (s *Server) MCPHandler() (http.Handler, error)          // /healthz, /mcp/admin, /mcp/people, /internal/*; no CSRF; strict JSON
func (h *Hub) MintCredential(ctx context.Context, resource, user string) (*MintResult, error) // singleflight per (resource,user)
type MintResult struct{ ID string; NoAccount bool; AppURL string }
func (h *Hub) RevokeAICredentials(ctx context.Context, instance, companion, user string, actor directory.Actor) error // user "" = everyone (revoke_all)
func (h *Hub) ReconcileAICredentials(ctx context.Context) // leavers, disabled instances, revoking retries, app_oauth leavers, connections cleanup
func (h *Hub) MyAI(ctx context.Context, user string) (*MyAIView, error) // the caller's AI connections + their last 50 access-log lines
func (h *Hub) DisconnectAI(ctx context.Context, user, client string, actor directory.Actor) error // AI client ids only; audited ai.connection.revoke
type AccessLine struct{ /* contract §15.8 */ }
func (h *Hub) AccessLog(filter func(AccessLine) bool, n int) ([]AccessLine, error) // HUB_MCP_GATE_DATA_DIR/access.jsonl, tail 4 MiB, newest first
```
- `<data>/ai/oauth-seen.json`: per `app_oauth` companion, the people who
  were in its population while AI was on (who may hold app-side tokens).

- [ ] **Step 1: tests.**
  - `TestMCPListenerSecret`: no / wrong secret → 401 on every path but
    `/healthz`; the secret never reaches handlers; `X-Forwarded-User` on
    the hub and people listeners never reaches MCP code (the MCP routes →
    404 there); `HUB_MCP_GATE_SECRET_FILE` under 32 chars → the Hub
    refuses to start; missing file → listener not started, AI off.
  - `TestMintCredential`: in population → hook stdin exactly
    `{"action":"mint","user":"alice","instance":"aiapp","companion":"tok","name":"portcullis-ai-<12>","mode":"read_write","scopes":[…]}`;
    stdout `{"credential":"c","id":"7"}` → entry written encrypted
    (`state: active`), answer `200 {id: "7"}`, audited
    `ai.credential.mint` (target `aiapp/tok/alice`, detail `id 7`, never
    the credential); exit 3 → `409 no_account` with `app_url`; exit 1 →
    `502`, `CompanionView.LastError` updated; not in population → 403.
  - `TestConcurrentMintSingleFlight` (Review Focus 2): 4 concurrent
    `/internal/credentials` for alice → one hook run, four `200` with the
    same id.
  - `TestLeaverCredentialRevoked` (Review Focus 1): alice removed from
    the access group → after `WritePolicy` her entry is gone, then the
    revoke hook gets `{"action":"revoke","user":"alice","ids":["7"]}`,
    audited `ai.credential.revoke`; hook fails → entry kept as `revoking`
    (gate ignores it), retried every reconcile, shown on the AI tab; never
    reported as done.
  - `TestAppOAuthLeaverRevoked`: an `app_oauth` companion: bob in the
    population is recorded in `oauth-seen.json`; bob leaves → `revoke`
    hook `{"action":"revoke","user":"bob","ids":[]}`; success removes
    him; switching the companion off runs `revoke` for everyone recorded.
  - `TestConnectionsCleanupWhenNoAIResource`: a deleted user, or one in
    no AI population (people MCP off, no companion) → `RevokeAIConnection`
    for every AI client.
  - `TestInternalAPIStrictJSON`: unknown fields → 400; 64 KiB + 1 → 413.
  - `TestAccessLogReader`: a torn last line is skipped; `MyAI("alice")`
    holds only alice's lines (newest first, ≤ 50) and her connections;
    `DisconnectAI` with a non-AI client id → `StatusError` 404.
- [ ] **Step 2: run.** `go test -race ./internal/hub/ ./internal/httpapi/ ./cmd/hub/ -run 'TestMCPListener|TestMint|TestConcurrentMint|TestLeaver|TestAppOAuth|TestConnectionsCleanup|TestInternalAPI|TestAccessLogReader'` → FAIL.
- [ ] **Step 3: implement.**
- [ ] **Step 4: verify** → PASS.
- [ ] **Step 5: commit.** `hub: MCP listener, internal API, lazy minting and revocation on leave`.

### Task 14: Confirmations (store, pages, fresh passkey)

**Files:**
- Create: `internal/confirm/{confirm.go,confirm_test.go}`,
  `internal/httpapi/confirm.go`, `internal/httpapi/confirm_test.go`,
  `web/confirm.js`, `web/confirm.html`.
- Reuse or build: `internal/freshauth` and
  `internal/keycloak/freshauth.go` (file sharing Task 7, see "Bases and
  order").
- Modify: `internal/httpapi/server.go` (`/confirm/{id}` and the API on
  both listeners, scoped by listener), `internal/httpapi/internal_api.go`,
  `internal/httpapi/people_test.go`, `web/web.go`, `cmd/hub/main.go`
  (two verifiers: redirect `https://people.<d>/` and `https://hub.<d>/`),
  `go.mod`.

**Interfaces:**
- Consumes: `freshauth.Verifier.Verify(ctx, Proof, user)`,
  `Info()`; `hub.FreshAuth`.
- Produces:
```go
// internal/confirm (in memory; lost on restart = expired)
type Request struct{ User, Client, Resource, Tool, ArgsSHA256, ArgsPreview, Listener string; Typed string; Consequences []string; Label string }
type Confirmation struct{ ID string; Request; State string; Created, Expires time.Time }
const Pending, Approved, Declined, Consumed = "pending", "approved", "declined", "consumed"
const TTL = 10 * time.Minute
func New(now func() time.Time) *Store
func (s *Store) Create(r Request) (*Confirmation, error)           // id: 16 random bytes, base32 no padding, grouped by 4 with "-"
func (s *Store) Get(id, user string) (*Confirmation, error)        // another user → ErrNotFound (no oracle)
func (s *Store) Decide(id, user string, approve bool) error         // pending only
func (s *Store) Consume(user, resource, tool, digest string) (*Confirmation, error) // first approved match; ErrPending / ErrDeclined / ErrNotFound
// keycloak (widened, see Bases): EnsureFreshAuthClient(ctx, redirectURIs, webOrigins []string) error
```
- Routes: `GET /confirm/{id}` (page) and `POST /api/me/confirmations/{id}`
  `{decision: "approve"|"decline", typed, code, code_verifier, nonce}`
  on both listeners; a confirmation created for the admin listener is
  404 on people and vice versa.

- [ ] **Step 1: tests.**
  - `TestConfirmStore`: TTL 10 min (fake clock: 9:59 ok, 10:01
    expired); single use; another user's id → not found; ids unique and
    16 bytes of entropy.
  - `TestConfirmPage`: alice's id opened by bob → 404; by alice → page
    shows tool, target, consequences and arguments (escaped; a
    `<script>` argument renders as text); unauthenticated → normal
    forward-auth sign-in (no special handling, test on the handler: no
    `X-Forwarded-User` → 401).
  - `TestConfirmApprove`: typed check wrong → 409 nothing recorded; fake
    verifier fresh (`auth_time` now−10 s, `amr: ["hwk"]`) → approved,
    audited `ai.confirm` (detail `approved`, the digest, never
    arguments); `auth_time` 301 s ago or `amr: ["file"]` → 403 "a fresh
    passkey sign-in is required"; decline needs no passkey, audited
    `declined`; expiry audited `expired` by the sweeper.
  - `TestInternalConfirmations`: create → `201 {id, url:
    "https://people.example.com/confirm/<id>", expires_at}`; consume
    before approval → `409 pending`; after → `200`; again → `404`.
  - `TestPeopleListenerHasNoAppRoutes` (updated): `peopleAppRoutes` gains
    `GET /confirm/{id}` and `POST /api/me/confirmations/{id}` (plus Task
    21's two).
  - `TestEnsureFreshAuthClientTwoHosts` (kctest): both redirect URIs and
    web origins, idempotent; file sharing's existing caller passes one.
- [ ] **Step 2: run.** `go test -race ./internal/confirm/ ./internal/httpapi/ ./internal/keycloak/ -run 'TestConfirm|TestInternalConfirmations|TestPeopleListener|TestEnsureFreshAuth'` → FAIL.
- [ ] **Step 3: implement.** The page's JS starts the authorization request
  to `portcullis-fresh-auth` with `prompt=login`, `max_age=0`, PKCE and a
  nonce kept in `sessionStorage`, comes back to `/` and returns to
  `/confirm/<id>` (the redirect URI file sharing pinned).
- [ ] **Step 4: verify** → PASS; check the page in the harness
  (`go test -tags harness -run TestHarness -timeout 0 ./internal/httpapi`)
  with a seeded confirmation; screenshot approve and decline.
- [ ] **Step 5: commit.** `hub: confirmations with a fresh passkey touch (hub and people)`.

### Task 15: Instances: hostnames, backups, restore, delete

**Files:**
- Modify: `internal/hub/hosts.go` (`SetHosts`), `internal/hub/backup.go`,
  `internal/hub/restore.go`, `internal/hub/delete.go`, tests
  `internal/hub/ai_lifecycle_test.go`.

**Interfaces:**
- Consumes: Tasks 10–13.
- Produces: archive member `config/ai.json` (`state.AIInstance`; never
  credentials).

- [ ] **Step 1: tests.**
  - `TestSetHostsMovesMCPResource` (Review Focus 4): an AI-enabled
    instance moves `aiapp.example.com` → `tools.example.com` → scope
    audience and consent text name the new host in the same step as the
    redirect URIs (undo restores both on a later failure); the router
    rule has only the new host; the gate file's resource URL is new;
    `MyApps` shows the new URL.
  - `TestBackupCarriesAIConfig`: archive has `config/ai.json`, no
    credential (marker grep over the tar).
  - `TestRestoreRevokesAllFirst`: same-instance restore → `revoke_all`
    runs in the restored app before the instance appears in the gate file
    again; entries for the instance deleted; a failing `revoke_all` keeps
    the companion out of the gate file and shows the error.
  - `TestRestoreAsStartsAIOff`: new id → every companion `Enabled:
    false`; no scope created.
  - `TestDeleteRemovesAI`: step 4 deletes `mcp:<id>.<c>` scopes; step 6
    removes credential entries, `oauth-seen` and `AIInstances[id]`.
- [ ] **Step 2: run.** `go test -race ./internal/hub/ -run 'TestSetHostsMovesMCP|TestBackupCarriesAI|TestRestoreRevokesAll|TestRestoreAsStartsAIOff|TestDeleteRemovesAI'` → FAIL.
- [ ] **Step 3: implement.**
- [ ] **Step 4: verify** → PASS.
- [ ] **Step 5: commit.** `hub: AI across hostname changes, backups, restore and delete`.

## Phase 4 — the Portcullis MCP

### Task 16: MCP server core (`/mcp/admin`, `/mcp/people`)

**Files:**
- Create: `internal/httpapi/mcp.go` (server, registry, call path),
  `internal/httpapi/mcp_test.go`, `internal/httpapi/mcp_resources.go`
  (docs, manifests, doctor catalogue, prompts).
- Modify: `internal/httpapi/mcplistener.go`, `go.mod`
  (`github.com/modelcontextprotocol/go-sdk`, `github.com/gowebpki/jcs`),
  `web/web.go` (embed the docs pages the Hub ships: contract and
  operations guides copied at build time into `web/docs/`), `Dockerfile`
  if it needs the copy step.

**Interfaces:**
- Consumes: Task 7 `Caller.Via/Client`, Task 13 listener, Task 14
  `confirm.Store`.
- Produces:
```go
type ToolClass string // "R", "W", "D", "U"
type Tool struct {
    Name, Description string
    Class             ToolClass
    Scope             string   // "admin" | "people"
    Twin              string   // the HTTP route it mirrors, exactly as registered ("DELETE /api/directory/users/{username}", "/api/templates/enable")
    Perm              string   // people tools: "" or a directory.Perm* the caller must hold
    In                any      // argument struct (JSON schema derived by the SDK)
    Typed             func(args json.RawMessage) string // D tools: the typed check the page asks for ("" = none)
    Consequences      func(args json.RawMessage) []string
    SecretForm        func(args json.RawMessage) string // U tools: Hub URL of the form
    Run               func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error)
}
func (s *Server) registerTool(t Tool)
func (s *Server) tools(scope string) []Tool
type mcpIdentity struct{ User, Client, Resource string } // from the gate headers on :8890 only
func callerFrom(ctx context.Context) *directory.Caller    // CallerFor + Via "ai" + Client
var secretArgRe = regexp.MustCompile(`(?i)token|password|secret|key`)
func toolResult(v any, redact func(string) string) *mcp.CallToolResult // JSON text, redacted then clipped (≤ 1 MiB)
```
- Call path for every tool: `callerFrom` (CallerFor; `/mcp/admin` →
  `!Admin` is a tool error "admins only") → argument names checked
  against `secretArgRe` → class D: `Consume(user, resource, tool,
  digest)` or `Create` + URL elicitation / text → class U: URL
  elicitation to `SecretForm` → `Run` → `toolResult`. Errors map as the
  HTTP handlers do (`writeErr` statuses): a 409 busy is an `isError`
  result with the reason, never a protocol error. Long operations return
  `{op_id, op, instance, poll}` and progress notifications when the
  client asked for a stream.
- Annotations: R → `readOnlyHint`; D → `destructiveHint`; W/U →
  `destructiveHint: false`; idempotent where the twin is a PUT.

- [ ] **Step 1: tests** (a test tool table of four tools, one per class).
  - `TestMCPServesBothScopes`: `/mcp/admin` lists only admin tools;
    `/mcp/people` only people tools; root through `/mcp/people` gets no
    admin tool.
  - `TestMCPAdminRefusesNonAdmin`: alice on `/mcp/admin` → every tool
    `isError` "admins only", audited `refused` for W/D with via/client.
  - `TestMCPDestructiveNeedsConfirmation`: first call → URL elicitation
    (2026-07-28 `InputRequiredResult`; 2025-11-25 `elicitation/create`
    mode url) to `https://hub.example.com/confirm/<id>`; the text
    fallback without the capability; `Run` not called; after `Decide
    approve` the identical retry runs once; a third call → a new
    confirmation.
  - `TestMCPSecretArgsRefused`: an argument named `apiKey` or
    `db_password` → `isError` "secrets are never passed through the AI;
    use <url>".
  - `TestMCPSecretFormElicitation`: a U tool returns the URL of its form,
    never a form-mode elicitation.
  - `TestMCPOutputRedacted`: a `Run` returning a known secret value and
    an invite link → redacted; results over 1 MiB clipped after
    redaction.
  - `TestMCPProtocolVersions`: `2025-03-26` → 400; the three supported →
    ok; header/body mismatch → -32020.
  - `TestMCPIdentityOnlyFromGate`: missing `X-Forwarded-User` → 401; the
    request's `X-Portcullis-AI-Client` becomes `Caller.Client` and the
    audit `client`.
  - `TestMCPResourcesAndPrompts`: `portcullis://docs/integration-contracts`
    readable; `portcullis://templates/<id>` returns the manifest (env
    defaults of `generate: random` entries never included); prompts
    "Diagnose this app", "Set up an app for a team", "Why can't <person>
    open <app>?" listed with their arguments.
- [ ] **Step 2: run.** `go test -race ./internal/httpapi/ -run 'TestMCP'` → FAIL.
- [ ] **Step 3: implement** on the SDK's `StreamableHTTPHandler`
  (stateless, 2026-07-28 with the 2025-11-25 fallback).
- [ ] **Step 4: verify** → PASS.
- [ ] **Step 5: commit.** `hub: Portcullis MCP server (classes, confirmations, secret rules, redaction)`.

### Task 17: Admin tools — catalog, instances, settings, runtime, drift, backups, domains, AI, Hub settings

**Files:**
- Create: `internal/httpapi/mcptools_admin.go`, `internal/httpapi/mcptools_admin_test.go`,
  `internal/httpapi/mcp_parity_test.go`.
- Modify: `internal/httpapi/server.go` (route recorder: `Handler()`
  registers through a small wrapper that records every pattern into
  `s.hubRoutes`).

**Interfaces:**
- Consumes: Task 16 registry; the Hub methods the HTTP handlers call
  today (the tool's `Run` calls the same method with the same checks; no
  HTTP loopback).
- Produces: the admin tools of spec call 25 for these areas, with these
  names, classes and twins (twin = the route the handler is registered
  under):
  - Overview: `hub_status` R (`GET /api/status` + drift + doctor summary
    when present), `explain_policy` R (`GET /api/templates/settings/{id}` policy part).
  - Catalog: `list_templates` R, `get_template` R, `list_sources` R,
    `sync_sources` W, `add_source` W, `remove_source` D.
  - Instances: `list_instances` R, `get_instance` R, `instance_defaults`
    R, `create_instance` W, `enable_instance` W, `disable_instance` W,
    `restart_instance` W, `set_hosts` W, `get_op` R, `wait_for_op` R
    (polls the op record every 2 s, returns at done or 60 s),
    `delete_instance` D (typed check = instance id; consequences from
    `DeleteInstance`'s plan).
  - Settings: `get_settings` R, `preview_settings` R, `save_settings` W
    (requires the preview's `plan_hash`), `set_secret_setting` U,
    `set_policy` W, `set_sign_in_mode` W, `set_public_access` W.
  - Runtime: `get_logs` R (≤ 500 lines, op-record redaction),
    `get_status` R, `exec` D (consequences: the command, service), 
    `get_compose` R, `get_env` R (secret-looking values redacted),
    `save_env` D, `get_custom_override` R, `save_custom_override` D.
  - Drift: `list_drift` R, `resolve_drift` D.
  - Backups: `list_backups` R, `backup_instance` W, `restore_instance` D
    (typed check = instance id), `restore_as` W.
  - Domains: `list_domains` R, `enroll_domain` U (form
    `https://hub.<d>/#settings/domains?enroll=<name>`),
    `replace_domain_token` U, `delete_domain` D (typed = domain).
  - AI: `ai_status` R, `set_ai_support` W, `set_ai_mode` W,
    `revoke_ai_access` D, `ai_activity` R, `list_model_providers` R,
    `save_model_provider` W (no secret fields in its schema),
    `set_model_provider_secret` U, `delete_model_provider` D.
  - Hub settings: `get_hub_settings` R, `save_hub_settings` W (refuses
    turning `PortcullisAdmin` **on**; turning it off is allowed).
- `var noToolRoutes = map[string]string{…}`: Hub-listener routes with no
  tool and the reason (the page, `/static/`, `/healthz`, the CSV upload
  of `import/review` is mirrored by a JSON tool instead, …).

- [ ] **Step 1: tests.**
  - `TestToolParity` (`mcp_parity_test.go`): every recorded Hub-listener
    route is some tool's `Twin` or in `noToolRoutes`; every admin tool's
    `Twin` is a recorded route; every class-D tool's twin is a route
    whose handler has a typed confirmation today or deletes, restores,
    revokes or runs code (the list of spec call 25 hard-coded in the
    test); `exec`, `save_env`, `save_custom_override`, `resolve_drift`
    are D.
  - `TestAdminToolsSameAsHTTP`: for each W/D tool, the fake Hub records
    the method call and arguments; the HTTP twin with the same input
    records the same call; the audit entry has the same action, with
    `via: ai` and the client only for the tool.
  - `TestDeleteInstanceTool`: confirmation page consequences list "takes
    a backup, then permanently removes its containers, volumes, Keycloak
    client and groups users_x, admin_x"; typed check `x`; after approval
    the retry answers `202 {op_id, op: "delete", instance, poll}`;
    audited `instance.delete` with via/client and `confirmation <id>` in
    detail.
  - `TestBusyIsToolError`: an instance mid-backup → `enable_instance` →
    `isError` with the 409 reason.
  - `TestEnrollDomainNoToken`: the tool's schema has no credential
    field; calling it returns the URL elicitation; `TestTokenNotEchoed`
    extended over every admin tool result.
  - `TestSaveHubSettingsCantEnableAdminMCP`.
- [ ] **Step 2: run.** `go test -race ./internal/httpapi/ -run 'TestToolParity|TestAdminTools|TestDeleteInstanceTool|TestBusyIsToolError|TestEnrollDomainNoToken|TestSaveHubSettingsCant'` → FAIL.
- [ ] **Step 3: implement.**
- [ ] **Step 4: verify** → PASS.
- [ ] **Step 5: commit.** `hub: Portcullis MCP admin tools (instances, settings, runtime, backups, domains, AI)`.

### Task 18: Admin tools — users and groups

**Files:**
- Create: `internal/httpapi/mcptools_directory.go`,
  `internal/httpapi/mcptools_directory_test.go`.

**Interfaces:**
- Consumes: Task 16; `directory.Service` methods with the tool's
  `*Caller` (Via `ai`).
- Produces (spec call 25, twin = the `/api/directory/*` route):
  `directory_overview` R (`OverviewFor`), `get_person` R, `create_person`
  W (invite by email; the link is never returned), `update_person` W,
  `set_details` W, `require_passkey` D, `remove_passkeys` D,
  `set_password` U (form `https://hub.<d>/#users/<name>?password`),
  `delete_person` D (typed = the name), `create_group` W,
  `delete_group` D (typed = the group), `add_member` W, `remove_member`
  W, `set_member_expiry` W, `set_group_rule` W, `preview_rule` R,
  `add_exception` W, `remove_exception` W, `convert_group` W (preview +
  apply), `create_field` W, `update_field` W, `delete_field` D,
  `set_permission` W, `import_review` R (JSON rows instead of the CSV
  upload), `import_apply` W, `audit_recent` R (entries carry via/client).
  Another administrator as target: the typed check is that person's name
  (as the HTTP flow does) **and** the passkey touch.

- [ ] **Step 1: tests.**
  - `TestDirectoryToolsGuardrails`: `delete_person admin` and
    `portcullis-hub` → refused exactly like HTTP (`checkTarget`), audited
    `refused` with via/client; `TestProtectedAccountsParity` still passes
    (no new `Service` method).
  - `TestCreatePersonNoInviteLink`: result has no `url`/`link`/token
    field (marker invite URL from the fake absent from the result).
  - `TestSetGroupRuleSameAsHTTP`: tool and HTTP produce the same
    `group.rule` audit, the tool's with `via: ai`.
  - `TestOtherAdminNeedsTypedName`: `remove_passkeys` on admin `ops` →
    confirmation page asks for `ops`.
- [ ] **Step 2: run.** `go test -race ./internal/httpapi/ -run 'TestDirectoryTools|TestCreatePersonNoInviteLink|TestSetGroupRuleSameAsHTTP|TestOtherAdminNeedsTypedName|TestToolParity'` → FAIL.
- [ ] **Step 3: implement.**
- [ ] **Step 4: verify** → PASS.
- [ ] **Step 5: commit.** `hub: Portcullis MCP users and groups tools`.

### Task 19: People tools

**Files:**
- Create: `internal/httpapi/mcptools_people.go`, `internal/httpapi/mcptools_people_test.go`.

**Interfaces:**
- Consumes: Task 16; project 1 `MyApps`; Task 13 `MyAI`, `DisconnectAI`.
- Produces (scope `people`, also in the aggregate as `portcullis__…`):
  `my_apps` R (= `GET /api/me/apps`), `my_profile` R, `directory` R
  (`OverviewFor`), `my_ai_connections` R, `disconnect_ai` W
  (own connections only), delegates only: `update_person` W
  (`edit_details`), `invite_person` W (`invite`), `delete_person` D
  (`remove`, typed = the name). `my_certificates` and
  `my_file_share_password` only when their projects have landed
  ("Bases and order").

- [ ] **Step 1: tests.**
  - `TestPeopleToolsCallerOnly`: alice's `my_apps` = her
    `GET /api/me/apps`; no tool takes another username except the
    delegate tools; delegate tools absent from `tools/list` for a caller
    without the permission, and refused if called anyway (403 reason).
  - `TestPeopleToolsNoAppScope`: no tool name or twin under
    `/api/templates`, `/api/settings`, `/api/drift`, `/api/instances`.
  - `TestDelegateDeleteNeedsConfirmation`: `delete_person` by a holder
    of `remove` → confirmation on `people.<d>/confirm/<id>`.
- [ ] **Step 2: run.** `go test -race ./internal/httpapi/ -run 'TestPeopleTools|TestDelegateDelete'` → FAIL.
- [ ] **Step 3: implement.**
- [ ] **Step 4: verify** → PASS.
- [ ] **Step 5: commit.** `hub: Portcullis MCP people tools`.

### Task 20: Doctor and folder tools, AI doctor checks (needs project 2)

Runs only on a base that contains project 2 (see "Bases and order").

**Files:**
- Create: `internal/doctor/ai.go`, `internal/doctor/ai_test.go`,
  `internal/httpapi/mcptools_doctor.go`, `internal/httpapi/mcptools_doctor_test.go`.
- Modify: `internal/doctor` `Inputs` (gains `AI []AIIn`),
  `internal/hub` `doctorInputs`.

**Interfaces:**
- Consumes: project 2 `doctor.Check`, `doctor.Register`, `Inputs`,
  `Fingerprint`, `(*Hub).Doctor`, `PreviewFix`, `ApplyFix`, `StartDoctorScan`,
  `MuteFinding`, `Folders`, `PreviewAssign`, `StartAssign`.
- Produces:
```go
type AIIn struct{ Instance, Companion, Status, Policy string; LoA int; Revoking int; ImagePinned, ImageRunning string }
// kinds: ai_companion_unhealthy (problem), ai_policy_needs_mtls (problem), ai_credentials_revoking (warning), ai_companion_image_old (warning)
```
  Tools: `doctor_findings` R, `doctor_scan` W, `doctor_preview_fix` R,
  `doctor_apply_fix` W — D when the plan's `FixPlan` touches data
  (folder apply / ownership change), `doctor_mute` W, `list_folders` R,
  `folder_preview` R, `folder_apply` W (requires the preview's
  `plan_hash`).

- [ ] **Step 1: tests.**
  - `TestAIDoctorChecks`: AI on + companion not running → problem with
    a `link` fix to the AI tab; AI on + LoA 3 policy → problem; a
    `revoking` entry → warning naming the instance; running image digest
    ≠ the template's pin → warning.
  - `TestDoctorToolsMirror`: `doctor_apply_fix` on a data-touching plan
    → confirmation first; on a config-only plan → runs, audited
    `doctor.fix` with via/client; `TestToolParity` covers the new routes.
- [ ] **Step 2: run.** `go test -race ./internal/doctor/ ./internal/httpapi/ -run 'TestAIDoctor|TestDoctorTools|TestToolParity'` → FAIL.
- [ ] **Step 3: implement.**
- [ ] **Step 4: verify** → PASS.
- [ ] **Step 5: commit.** `hub: AI doctor checks; Portcullis MCP doctor and folder tools`.

## Phase 5 — Hub API and UI

### Task 21: People page — "Connect your AI"

**Files:**
- Create: `internal/hub/ai_people.go` (`MyAppAI`, the top-level `ai`),
  `internal/hub/ai_people_test.go`, `web/myai.js`.
- Modify: `internal/hub/myapps.go` (`MyApp.AI`, top-level `ai`),
  `internal/httpapi/people.go`, `internal/httpapi/server.go`
  (`PeopleHandler` registers the routes), `internal/httpapi/people_test.go`,
  `web/myapps.js`,
  `web/people.html`, `web/web.go`.

**Interfaces:**
- Consumes: Task 13 `MyAI`, `DisconnectAI`.
- Produces:
```go
type MyAppAI struct{ Companions []MyCompanion `json:"companions"` }
type MyCompanion struct{ Name, Label, URL, IdentityMode, Mode string; Official bool } // json snake_case
// MyApp gains AI *MyAppAI `json:"ai,omitempty"` (only when on and the caller is in the population)
type MyAITop struct{ AggregateURL string; Clients MyAIClients; AdminURL string `json:"admin_url,omitempty"` }
type MyAIClients struct{ Claude *struct{ClientID string}; ClaudeCode *struct{ClientID string; CallbackPort int}; Generic *struct{ClientID string; RedirectURIs []string} }
// GET /api/me/apps → {"apps": [...], "ai": MyAITop} ("ai" absent when the master switch is off or the caller has no AI resource)
```
- Routes (people listener; caller only): `GET /api/me/ai`,
  `DELETE /api/me/ai/connections/{client}` (only an AI client id → else
  404; audited `ai.connection.revoke`).

- [ ] **Step 1: tests.**
  - `TestMyAppsAI`: alice in gitea and grafana (AI on), not in ha →
    gitea/grafana carry `ai.companions` with URL, mode, `official`; the
    top-level `ai` has `aggregate_url: https://mcp.example.com/mcp`,
    client ids `portcullis-ai-claude`, `portcullis-ai-claude-code` +
    `callback_port: 33418`, generic redirect URIs; no `admin_url` for
    alice, `https://hub.example.com/mcp` for root; master off → no `ai`
    anywhere; an instance with AI off → no `ai` on it.
  - `TestMyAICallerOnly`: alice sees only her access-log lines and her
    connections; `ALICE` header → alice's (case-folded).
  - `TestDisconnectAI`: revokes only alice's consent and offline sessions
    for that client; a non-AI client id → 404; audited.
  - `TestPeopleListenerHasNoAppRoutes`: `peopleAppRoutes` now project
    1's three + `GET /api/me/ai`, `DELETE /api/me/ai/connections/{client}`,
    `GET /confirm/{id}`, `POST /api/me/confirmations/{id}` (+ file
    sharing's two if merged); those four → 404 on the Hub listener.
- [ ] **Step 2: run.** `go test -race ./internal/hub/ ./internal/httpapi/ -run 'TestMyAppsAI|TestMyAICallerOnly|TestDisconnectAI|TestPeopleListener'` → FAIL.
- [ ] **Step 3: implement the card** in `web/myai.js`, rendered from
  `GET /api/me/apps` + `GET /api/me/ai`, every value escaped, copy
  buttons, tabs Claude desktop / Claude Code / Other MCP clients, with
  the spec's card text ("Example: the People page card"): the intro
  paragraph (incl. "What it reads is sent to the AI provider you use.
  Deleting things always asks for your passkey in this browser."), the
  Team/Enterprise note, the reachability note, the Claude Code command
  `claude mcp add --transport http --scope user --client-id portcullis-ai-claude-code --callback-port 33418 <name> <url>`
  (name = label lowercased, reduced to `[a-z0-9-]`; `portcullis-apps`
  for the aggregate), "One app only" rows, `app_oauth` rows with "Home
  Assistant applies its own rules; Portcullis doesn't log or confirm its
  AI actions" (from the companion's label, not a template id), the
  disconnect note "Disconnect ends all your Claude connectors at once",
  and "Recent AI activity". No card when no AI app and no aggregate.
- [ ] **Step 4: verify** → PASS; harness screenshots for alice (two apps)
  and a person with none (no card).
- [ ] **Step 5: commit.** `people: Connect your AI card, AI connections and activity`.

### Task 22: Admin UI — Settings → AI, instance AI tab, audit filter

**Files:**
- Modify: `web/index.html` (Settings → AI; the instance detail's **AI
  support** tab; audit view filter "via AI"), `internal/httpapi/ai.go`
  (`GET /api/ai/activity?instance=&user=`), tests
  `internal/httpapi/ai_test.go`.

**Interfaces:**
- Consumes: Tasks 9, 12, 13, 21 views.
- Produces: no new Go API beyond the activity route (admins only).

- [ ] **Step 1: tests.**
  - `TestAIActivityAdminOnly` and filters (instance, user, n ≤ 200).
  - `TestAuditViaFilter`: `GET /api/directory/audit?via=ai` returns only
    entries with `via: ai`, merged with access-log lines when
    `include=access`.
- [ ] **Step 2: run.** `go test -race ./internal/httpapi/ -run 'TestAIActivity|TestAuditViaFilter'` → FAIL.
- [ ] **Step 3: implement the UI.**
  - Settings → AI: master switch; clients offered; Portcullis MCP for
    admins / for people; connection length (idle, max); rate limits;
    allowed origins; the reachability note (exact text of spec call 28);
    providers table (label, kind, models, credentials mode, used by
    `instance (group, N people)`), add/edit dialog per kind's fields,
    secret inputs `type=password` cleared on submit and never rendered
    back (`set · updated <date>` / `not set`), the data-egress note per
    provider.
  - Instance → AI support tab: `unsupported` → the reason and the
    alternative labelled "not vetted by Portcullis" (link escaped), no
    switch. Otherwise per companion: switch, mode picker when both, the
    official/community label and `source`, status + last error,
    population count, active credentials and connections, `confirm` and
    `never` lists, recent activity, the `app_oauth` notice, greyed out
    with the reason while the master switch is off or the policy needs
    mTLS. Errors show the status meaning (409 refused).
- [ ] **Step 4: verify** → PASS; harness screenshots of Settings → AI
  (with a provider whose secret is set) and the tab in its four states
  (unsupported, off, on, refused for mTLS).
- [ ] **Step 5: commit.** `ui: Settings → AI, instance AI support tab, via-AI audit filter`.

### Task 23: AI page delivery (providers per `ai-chat` instance)

**Files:**
- Create: `internal/hub/ai_chat.go`, `internal/hub/ai_chat_test.go`,
  fixture `internal/hub/testdata/ai/chatapp/` (`ai.chat` with
  `provider_kinds {openai_compatible: many, litellm: many, anthropic: one}`,
  a second Keycloak client `ai_client: true`).
- Modify: project 1's delivery engine (`internal/hub/deliver*.go`: unit
  `file:ai-providers`), `internal/hub/env.go` (provider variables),
  `internal/hub/accessrole.go` / client registration (AI-client
  semantics for `ai_client` entries), `internal/httpapi/ai.go`.

**Interfaces:**
- Consumes: Task 9 providers, Task 10 `EnsureAIClient`, project 1
  `Deliver`, `TriggerDelivery(id, TriggerSave, true)`, data-file layout.
- Produces:
```go
func (h *Hub) SetAIProviders(ctx context.Context, id string, names []string, actor directory.Actor) error // audited ai.providers
func (h *Hub) providersFileLocked(t *templates.Template) (*ProvidersDoc, error)                          // contract §3 shape
func ProviderVar(name, field string) string // PORTCULLIS_AI_PROVIDER_<NAME>_<FIELD>
```
- `PUT /api/instances/{id}/ai` accepts `providers` for templates with
  `ai.chat`; default selection = every provider whose kind the template
  supports.

- [ ] **Step 1: tests.**
  - `TestProvidersFile`: `ai-chat` with `litellm` + `ollama-gpu` →
    `<appfiles>/ai-chat/ai-providers/ai-providers.json` holds both
    (labels, base URLs, models, `env` names), mounted read-only at
    `ai.chat.file.mount` in `ai.chat.file.service`; the env file holds
    `PORTCULLIS_AI_PROVIDER_OLLAMA_GPU_KEY='…'` (single-quoted) and no
    other instance's env does.
  - `TestProviderSecretsNeverEchoed` (extended): the marker secret is
    absent from `ai-providers.json`, the override, op records, and the
    gate file.
  - `TestTwoOneKindProviders`: two `anthropic` providers selected → 400;
    a kind the template doesn't declare → 400.
  - `TestProviderChangeRestartsSelected`: updating `ollama-gpu`'s models
    re-delivers and restarts `ai-chat` only (not `ai-research`, which
    didn't select it); the AI settings save preview lists the restarts.
  - `TestPerPersonCredentials`: `credentials: per_person` → no env
    variable, file entry says `per_person`.
  - `TestAIClientSemantics`: the `ai_client` entry becomes a confidential
    AI client (consent, ACR `hwk`, optional `mcp:all` only; no access-role
    flow, no other scope); the master switch off leaves it registered
    but the gate file doesn't list it in `clients`.
  - `TestUsedBy`: `ModelProviders()` lists `{instance: ai-chat, group:
    users_ai-chat, people: 41}`.
- [ ] **Step 2: run.** `go test -race ./internal/hub/ -run 'TestProvidersFile|TestProviderSecretsNeverEchoed|TestTwoOneKind|TestProviderChange|TestPerPerson|TestAIClientSemantics|TestUsedBy'` → FAIL.
- [ ] **Step 3: implement.**
- [ ] **Step 4: verify** → PASS.
- [ ] **Step 5: commit.** `hub: AI page providers (data file, env secrets, AI client)`.

## Phase 6 — templates

Templates work on branch `ai` of the templates repo (base `new-apps`).
Templates that live on other branches today (`apps-ha-oxi`:
homeassistant, mattermost, oxicloud, vault-ui; `apps-sync-vikunja`:
vikunja, firefox-sync; `apps-home`: esphome, zigbee2mqtt, motioneye) get
their `ai:` block in whichever change lands second: if they merge into
`new-apps` before `ai` is cut, T24 covers them; otherwise the branch that
merges after `ai` adds them (the validator makes that unavoidable). T27
(Home Assistant) needs `apps-ha-oxi` merged first.

### Task 24: Schema, validator, an `ai:` block in every template

**Files:**
- Modify: `schema/manifest.schema.json` (`ai`, `keycloak_clients[].ai_client`,
  `hooks[].when` gains `ai`), `tests/validate.py` (`check_ai`,
  `CORE_SUBDOMAINS` gains `mcp`, reserved `portcullis-mcp-` names and
  `PORTCULLIS_AI_*` / `PORTCULLIS_MCP_GATE_IP` variables, core service
  `mcp-gate`), `tests/test_validate.py`, `CONTRIBUTING.md` (the vetting
  checklist), every `*/manifest.yaml`, `.core-ref` (`ai`), `CLAUDE.md`.

**Interfaces:**
- Consumes: contract §3 (T1); mirrors Hub `ValidateAI` (T8) rule for
  rule.

- [ ] **Step 1: validator tests** (`test_validate.py`, class `AITests`):
  no `ai:`; both forms; empty reason; 201 chars; `alternative` with
  `mcp`; companion without `source`; `upstream: community` with
  `builtin`; a `companion` service with Traefik labels or on
  `portcullis-proxy`; `router` not a host router; `public_path`
  `/.well-known/x`; a hook without `when: [ai]`; `app_oauth` without
  `revoke` or with `read_only`; `identity_headers` without
  `caller_secret`; `ai_client` without `ai.chat`; a `portcullis-mcp-x`
  router or alias; `PORTCULLIS_AI_ENABLED` set by the template; `mcp` as
  a subdomain → each an error naming the field. A companion image without
  `@sha256` → error (existing image rule, asserted for the companion).
- [ ] **Step 2: run.** `python3 -m unittest discover -s tests -p 'test_*.py' -k AITests` → FAIL.
- [ ] **Step 3: implement `check_ai`.**
- [ ] **Step 4: write every block** (spec call 31; re-check the "no
  server known" rows and record the date in the reason's docs note):
  - `ai.unsupported` + `alternative`: paperless, immich, vikunja,
    jellyfin, firefly-iii (reasons and alternatives verbatim from call
    31).
  - `ai.unsupported` without alternative: the 15 ArtCraft templates,
    vaultwarden, litellm, docs, plex, adguard, pihole, headscale,
    netbird, actual-budget, cloudbeaver, dokuwiki, guacamole, kanboard,
    matrix, mealie, oxicloud, scrutiny, wiki (reasons verbatim).
  - Templates the spec doesn't list: firefox-sync `Signs people in with
    Mozilla accounts, not Portcullis identities; no MCP server known`;
    vault-ui `A placeholder demo route that needs a client certificate on
    every request, which AI clients can't present`; esphome,
    zigbee2mqtt, motioneye `No official or vetted community MCP server
    known (surveyed <date>)` after the builder's survey (if one is
    official and per-person, record it for a later `ai.mcp` change).
  - Interim, replaced before the branch is pushed: gitea, grafana (T25,
    T26), homeassistant (T27), nextcloud, mattermost, gitlab (T29):
    `ai.unsupported: "AI support is being added"`.
  - `CONTRIBUTING.md`: the vetting checklist (maintained, licence,
    multi-user identity fitting an identity mode, no shared admin
    identity, pinned release, the docs note why), and the rule that a
    template never ships MCP server code or an image built for
    Portcullis.
- [ ] **Step 5: verify.** `python3 tests/validate.py` and the unit tests →
  PASS; Hub `TestRealTemplates*` against this branch → PASS
  (`PORTCULLIS_TEMPLATES_DIR=… go test ./internal/hub -run TestRealTemplates`).
- [ ] **Step 6: commit, then push hub, core and templates `ai` together.**
  `templates: ai block required; every template classified`.

### Task 25: Gitea pilot (`app_token`)

**Files:**
- Modify: `gitea/compose.yml` (service `gitea-mcp`), `gitea/manifest.yaml`
  (`ai.mcp`, `hooks` `mcp-mint` / `mcp-revoke`), `.github/dependabot.yml`
  (the image), `tests/apps/gitea.sh`.
- Create: `gitea/portcullis/mcp-token.sh` (mounted read-only into
  `gitea` at `/portcullis/`).

**Interfaces:**
- Consumes: contract §15.5 hook I/O.
- Produces: the manifest block of the spec's "Example: template
  declaration (Gitea)", with the companion image
  `docker.gitea.com/gitea-mcp-server:1.12.0@sha256:<digest>`, command
  `["-t", "http", "--port", "8080", "-H", "http://gitea:3000"]`,
  `GITEA_READONLY: ${PORTCULLIS_AI_READONLY_GITEA:-true}`,
  `read_only: true`, tmpfs `/tmp`, no labels, default network only.
- `mcp-token.sh mint`: reads stdin JSON; unknown person (`gitea admin
  user list` has no such login) → exit 3; else `gitea admin user
  generate-access-token --username <user> --token-name <name> --scopes
  <csv> --raw` as the `git` user, prints `{"credential","id"}` (the id
  looked up by token name). `revoke` / `revoke_all`: deletes the person's
  `portcullis-ai-*` tokens (by id, or all with the prefix) through
  Gitea's API with a hook-local admin token that the hook creates and
  deletes in the same run. Secrets never on argv of a process whose argv
  other containers can see: the token is passed to `curl` via
  `--config -` on stdin.

- [ ] **Step 1: tests** (`tests/apps/gitea.sh`, on the CI core stack):
  - mint for alice → the credential authorizes as alice
    (`/api/v1/user` → `alice`) with only the read scopes in read_only;
    mint for `nobody` → exit 3;
  - `gitea-mcp` with that token lists alice's repos only (bob's private
    repo absent);
  - `revoke` → the token is refused; `revoke_all` → no `portcullis-ai-*`
    token left for any user; the hook-local admin token is gone too;
  - tool classes: start the companion, list its tools: every `writes`
    and `confirm` pattern matches at least one real tool, and every tool
    (or `tool:method`) whose name contains `delete` is in `confirm`;
  - `GITEA_READONLY=true` hides the write tools.
- [ ] **Step 2: run.** `bash tests/apps/gitea.sh` → FAIL.
- [ ] **Step 3: implement.**
- [ ] **Step 4: verify.** `python3 tests/validate.py` and `bash tests/apps/gitea.sh` → PASS.
- [ ] **Step 5: commit.** `gitea: AI support through the official gitea-mcp (per-person tokens)`.

### Task 26: Grafana pilot (`identity_headers`)

**Files:**
- Modify: `grafana/compose.yml` (service `grafana-mcp`; Grafana's
  auth-proxy whitelist), `grafana/manifest.yaml` (`env`
  `MCP_GRAFANA_SERVER_TOKEN` `generate: random`, `ai.mcp` as in the
  spec's Grafana example), `.github/dependabot.yml`, `tests/apps/grafana.sh`.

**Interfaces:**
- Produces: companion `grafana/mcp-grafana:<release>@sha256:<digest>`,
  `-t streamable-http`, `--server-auth-token` from
  `MCP_GRAFANA_SERVER_TOKEN`, `GRAFANA_FORWARD_HEADERS=X-Forwarded-User`,
  `--disable-write=${PORTCULLIS_AI_READONLY_GRAFANA:-true}`, never
  `--allow-grafana-url-override`, no service-account token; `tools.confirm`
  on its delete tools.
- Grafana trusts `X-Forwarded-User` only from Traefik and the companion:
  the companion gets a pinned address on the template's own network and
  `GF_AUTH_PROXY_WHITELIST` lists exactly Traefik's IP and that address.

- [ ] **Step 1: tests** (`tests/apps/grafana.sh`):
  - a request to Grafana from another container on the project network
    with `X-Forwarded-User: admin` → not signed in as admin; from the
    companion's address → signed in as the header's user;
  - the companion without the server token → 401; with it and
    `X-Forwarded-User: alice` → alice's dashboards only (a dashboard in a
    folder alice can't see is absent);
  - read-only → write tools absent;
  - tool classes check as in T25.
- [ ] **Step 2: run.** `bash tests/apps/grafana.sh` → FAIL.
- [ ] **Step 3: implement.** If Grafana can't be made to trust the header
  from the companion only without weakening Traefik's trust, set
  `ai.unsupported` with that reason instead and record why on the docs
  page; T30 then uses a second Gitea instance for the cross-resource
  checks.
- [ ] **Step 4: verify** → PASS.
- [ ] **Step 5: commit.** `grafana: AI support through the official mcp-grafana (identity headers)`.

### Task 27: Home Assistant pilot (`app_oauth`)

**Files:**
- Modify: `homeassistant/manifest.yaml` (`ai.mcp` as in the spec's Home
  Assistant example; hooks `mcp-integration` (`on_change`) and
  `mcp-revoke`), `homeassistant/portcullis/` scripts, `tests/apps/homeassistant.sh`.

**Interfaces:**
- Produces: `kind: builtin`, `service: homeassistant`, `port: 8123`,
  `path: /api/mcp`, `router: homeassistant`, `identity.mode: app_oauth`,
  `modes: [read_write]`, `aggregate: false`, `upstream: official`.
- `mcp-integration`: `enabled: true` → adds the MCP Server config entry
  (if missing) and turns its administrators-only option off;
  `enabled: false` → removes the entry. `mcp-revoke`: ends the person's
  Home Assistant refresh tokens (the exact call verified by the builder:
  delete their refresh tokens through the websocket API as the hook's
  local admin context, or deactivate; record the choice in the script
  header).

- [ ] **Step 1: tests:** on → `/api/mcp` answers the MCP initialize with
  a valid HA token; a non-admin person's token works; off → 404/disabled;
  `revoke` for alice → her refresh tokens gone, another person's kept.
- [ ] **Step 2: run.** `bash tests/apps/homeassistant.sh` → FAIL.
- [ ] **Step 3: implement.**
- [ ] **Step 4: verify** → PASS.
- [ ] **Step 5: commit.** `homeassistant: AI support through its built-in MCP server (own OAuth)`.

### Task 28: `ai-chat` template (LibreChat)

**Files:**
- Create: `ai-chat/{compose.yml,manifest.yaml,portcullis/render-config.mjs,portcullis/librechat.base.yaml}`,
  `tests/apps/ai-chat.sh`, `tests/apps/fixtures/ai-providers.json`.
- Modify: `.github/dependabot.yml`.

**Interfaces:**
- Consumes: contract §3 `ai.chat`, `ai-providers.json`, `ai_client`.
- Produces:
  - `instances: multi`, router `ai` (default host `ai.<d>`),
    `access_group: users_ai-chat` with the access role, native-oidc
    (OpenID login keyed on `preferred_username`);
  - services `api` (LibreChat, pinned), `mongodb`, `meilisearch`
    (pinned), and `config` (an init job, same image, `depends_on`
    `service_completed_successfully` for `api`) that runs
    `render-config.mjs`: reads the mounted `ai-providers.json`, writes
    `librechat.yaml` into a volume `api` mounts read-only. LibreChat reads
    its config only at start, so rendering happens before `api` starts
    (the spec's "start hook"); a provider change re-delivers the file
    (`applies: restart`) and the restart re-renders;
  - `keycloak_clients`: `ai-chat` (login) and `ai-chat-mcp`
    (`ai_client: true`, redirect
    `https://{{HOST_AI}}/api/mcp/portcullis/oauth/callback`, secret env
    `AI_CHAT_MCP_SECRET`);
  - `librechat.yaml`: one MCP server `portcullis` =
    `https://mcp.${PORTCULLIS_DOMAIN}/mcp`, `type: streamable-http`,
    `oauth {client_id: ${PORTCULLIS_CLIENT_ID_AI_CHAT_MCP}, client_secret: ${AI_CHAT_MCP_SECRET}, scope: mcp:all}`,
    `oauthPrompt: on_start`; `litellm` / `openai_compatible` →
    `endpoints.custom[]` (`name` = label, `baseURL`, `apiKey:
    "${PORTCULLIS_AI_PROVIDER_<NAME>_KEY}"` or `user_provided`, `models`);
    `azure_openai` → `endpoints.azureOpenAI.groups[]`; `anthropic`,
    `openai`, `google`, `bedrock` → LibreChat's native endpoint
    variables, each an env reference. No provider → the welcome text "No
    model provider configured; ask your administrator";
  - `ai: {unsupported: "The AI page itself: it is an MCP client, not an app the AI drives", chat: {provider_kinds: {openai_compatible: many, litellm: many, azure_openai: many, anthropic: one, openai: one, google: one, bedrock: one}, file: {service: config, mount: /portcullis/ai-providers}}}`;
    a kind is declared only if the builder verified LibreChat takes its
    secret from an env reference (spec "Left to the builder"); drop any
    that can't.
  - `tests.signin` block (templates contract), `urls`.

- [ ] **Step 1: tests** (`tests/apps/ai-chat.sh`):
  - render the fixture (one provider of every declared kind, a marker
    secret in the env) → `librechat.yaml` parses, has only `${…}`
    references for secrets, the marker is absent, two `openai_compatible`
    providers become two custom endpoints with their labels;
  - empty provider list → the welcome text, no endpoint;
  - the stack starts; signing in as a member works and an outsider is
    refused (sign-in e2e); `/api/mcp/portcullis/oauth/callback` exists.
- [ ] **Step 2: run.** `bash tests/apps/ai-chat.sh` → FAIL.
- [ ] **Step 3: implement.**
- [ ] **Step 4: verify.** `python3 tests/validate.py` and the test → PASS.
- [ ] **Step 5: commit.** `ai-chat: the AI page (LibreChat) with admin-configured model providers`.

### Task 29: Post-pilot companions (nextcloud, mattermost, gitlab)

**Files:** `nextcloud/`, `mattermost/`, `gitlab/` (compose, manifest,
`portcullis/` scripts), `tests/apps/{nextcloud,mattermost,gitlab}.sh`.

- [ ] **Step 1: nextcloud.** Companion `cbcoutinho/nextcloud-mcp-server`
  (`upstream: community`, pinned release, docs note: AGPL-3.0, ~5k
  commits, multi-user Basic pass-through); `app_token` with
  `basic {user: "{username}", password: "{credential}"}`; mint `occ
  user:auth-tokens:add <user>` (name `portcullis-ai-…`; exit 3 when the
  user doesn't exist), revoke `occ user:auth-tokens:delete`. Test as in
  T25 (alice's files only; revoke refuses the app password).
- [ ] **Step 2: mattermost.** If the template doesn't ship
  `mattermost-plugin-agents`: `ai.unsupported: "Needs the Mattermost
  Agents plugin, which this template doesn't install"`. If it does:
  `kind: builtin`, path `/plugins/mattermost-ai/mcp-server/mcp`,
  `app_token` with a personal access token through `mmctl`; test as T25.
- [ ] **Step 3: gitlab.** Verify the built-in MCP server on the edition
  the template runs with per-person identity; `ai.mcp` only if the test
  proves it, else `ai.unsupported` naming the missing tier or auth.
- [ ] **Step 4: verify.** `grep -rn 'AI support is being added' */manifest.yaml`
  → no match; `python3 tests/validate.py` and the three app tests → PASS.
- [ ] **Step 5: commit.** `nextcloud, mattermost, gitlab: AI support classified after the pilots`.

## Phase 7 — e2e, docs, deploy

### Task 30: CI e2e `e2e-ai` (core repo)

**Files:**
- Create: `tests/e2e/mcpclient/{go.mod,main.go}` (Go SDK client + OAuth
  PKCE with `resource`, loopback callback on `--callback-port`),
  `tests/e2e/e2e_ai.py`.
- Modify: `.github/workflows/ci.yml` (job `e2e-ai`, modelled on
  `e2e-instances`; the Hub from the same-named branch; a Hub template
  source = a clone of `porelli/portcullis-templates` on the same-named
  branch, else `main`), `tests/e2e/requirements.txt` if needed.

**Interfaces:**
- `mcpclient login --client-id portcullis-ai-claude-code --callback-port 33418 --resource <url> --scope <scope>`
  prints the authorize URL on stdout and the token JSON to a file when
  the callback arrives; `mcpclient call --url <url> --token-file <f>
  --method tools/list|tools/call [--tool n --args json]` prints the
  JSON-RPC result; exit 0 on any JSON-RPC answer.
- `e2e_ai.py` opens the authorize URL in Playwright with the CDP virtual
  WebAuthn authenticator (as `e2e_login.py`), signs in, approves consent.

- [ ] **Step 1: scenarios** (each a named function, failures keep
  screenshots/traces):
  1. `gitea_as_alice`: alice signs in for `https://gitea.portcullis.local/mcp`
     (`mcp:gitea.gitea`), lists tools, calls the repo-list tool → only
     alice's repos.
  2. `leaver_refused_and_revoked`: remove alice from `users_gitea`
     through the Hub API → her next call `403`; within one reconcile her
     Gitea token is gone (Gitea API).
  3. `audience_separation`: alice's Gitea token at Grafana's resource,
     at `https://mcp.portcullis.local/mcp` and at `hub.portcullis.local/mcp`
     → `401`; a token minted with both scopes → refused everywhere.
  4. `no_token_crossing`: alice's MCP token as `Authorization: Bearer` on
     `https://gitea.portcullis.local/` and `https://people.portcullis.local/`
     → the sign-in redirect, never a page; a browser session cookie on
     `/mcp` → `401`.
  5. `destructive_confirmation`: root signs in for `hub.portcullis.local/mcp`;
     `delete_instance` of a throwaway echo instance → URL elicitation /
     text with `https://hub.portcullis.local/confirm/<id>`; bob opening
     it → 404; root opens it, types the id, touches the virtual
     authenticator → approved; the retry answers `202`; a second retry →
     a new confirmation; `audit.jsonl` has `instance.delete` with
     `via: ai`, `client: portcullis-ai-claude-code`.
  6. `aggregate_lists`: carol in gitea + grafana sees `gitea__*` and
     `grafana__*` tools and `portcullis__my_apps`; bob (gitea only) sees
     no `grafana__*`; no admin tool for root on the aggregate.
  7. `ai_off`: master switch off → every MCP resource `503`.
- [ ] **Step 2: run** the job on the `ai` branch via `workflow_dispatch` →
  FAIL until wired.
- [ ] **Step 3: implement**, pin every image and the Go module.
- [ ] **Step 4: verify** → green on `ai` in core, Hub and templates CI.
- [ ] **Step 5: commit.** `ci: e2e-ai (MCP client through mcp-gate with Keycloak OAuth)`.

### Task 31: Docs (docs repo)

**Files:**
- Create: `docs/guides/connect-your-ai.md` (user guide: the card's
  content, screenshots from T21's harness), `docs/operations/ai.md`
  (admin guide: switches, modes, identity modes, what is logged, the
  reachability note, prompt-injection guidance of spec call 20, model
  providers and one `ai-chat` instance per audience, the manual
  checklist).
- Modify: `docs/guides/adding-an-app.md` and `manifest-reference.md`
  (`ai:` — `mcp`, `unsupported`, `alternative`, `chat` — and `when: ai`
  hooks), `docs/operations/hardening.md` (gate, token rules, no token
  passthrough, secrets never reach the model), `docs/architecture.md`,
  `docs/operations/testing.md` (`e2e-ai`, the manual checklist: Claude
  desktop custom connector with "Use your own OAuth client" — verify spec
  call 40, public client; Claude Code `claude mcp add` + `/mcp`; the AI
  page with an OpenAI-compatible Ollama and the Anthropic API, and with a
  LiteLLM instance), `scripts/generate-app-docs.py` (an "AI support"
  section per app: companion, upstream, source, identity mode, or the
  reason and the alternative labelled "not vetted by Portcullis"),
  regenerated `docs/apps/*`, `mkdocs.yml`/nav.

- [ ] **Step 1:** write the pages and the generator change; run
  `python scripts/generate-app-docs.py --source <templates ai checkout>`.
- [ ] **Step 2:** `zensical build --strict --clean` → no warnings.
- [ ] **Step 3: commit.** `docs: AI support (Connect your AI, admin guide, template ai block)`.

### Task 32: Deploy and live check

- [ ] **Step 1:** merge in order docs → core → Hub → templates; deploy to
  the test server (`./portcullis upgrade`); confirm `mcp-gate` healthy
  and `./portcullis status` clean.
- [ ] **Step 2: live checks** (throwaway users and instances, cleaned up
  afterwards):
  1. Settings → AI on; Gitea AI support on (read_write); the People card
     for a test user shows the URLs.
  2. Claude Code on the operator's machine: the card's `claude mcp add`
     command, `/mcp` sign-in with the passkey; list the test user's
     issues; create one (write) and ask to delete a repo → confirmation
     page with passkey; remove the user from `users_gitea` → refused.
  3. claude.ai custom connector with "Use your own OAuth client"
     (`portcullis-ai-claude`, no secret): connects (spec call 40; if it
     demands a secret, apply call 40's fallback and note it).
  4. `hub.<d>/mcp` as an admin: `get_instance`, `doctor_findings` (if
     T20 landed), delete a throwaway instance through the confirmation.
  5. An `ai-chat` instance with an OpenAI-compatible provider: a chat
     that lists the person's Gitea repos through the aggregate.
  6. The access log and `audit.jsonl` show the calls with `via: ai`; no
     secret in either (grep the markers used).
- [ ] **Step 3:** report (what passed, the builder verifications' results,
  anything deferred).

## Not in this plan

- **CIMD / "Use Claude's published identity"** for the Portcullis clients:
  waits until Keycloak's `cimd` feature is no longer experimental (spec
  call 3).
- **Certificate tools** (`list_certificates`, `revoke_certificate`,
  `sign_in_history`, `my_certificates`, `my_sign_ins`): added by the
  certificates self-service project when it lands (spec call 25), with
  the same registry and parity test.
- **App update preview** of `ai:` changes: the Hub has no template update
  preview yet; the app-updates project shows new tools, changed `confirm`
  lists and identity-mode changes there.
- **Per-tool allowlists edited by admins**, MCPB desktop extensions,
  agents without a person (spec non-goals).
