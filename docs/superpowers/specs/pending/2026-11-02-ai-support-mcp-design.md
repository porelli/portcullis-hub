# AI support: MCP companions, "Connect your AI", the AI page, one "all my apps" endpoint, and the Portcullis MCP

Status: draft for approval (2026-11-02)

Evidence base: `.superpowers/sdd/ai-brainstorm-context.md` (the user's
decisions) and `settings-brainstorm-context.md` (standing constraints).
Related specs:
[app settings panel](2026-11-02-app-settings-panel-design.md) (this design
reuses its declaration and delivery model: hooks, data files, population,
`GET /api/me/apps`),
[app instances and domains](2026-11-02-app-instances-domains-design.md),
[certificates self-service](2026-11-02-certificates-selfservice-design.md)
(the fresh-passkey pattern),
[shared folders + doctor](2026-11-02-shared-folders-doctor-design.md) (the
doctor the Portcullis MCP drives),
[directory rework](2026-11-01-directory-rework-design.md).

## Intent

People install many apps on Portcullis. They should be able to use those
apps from an AI assistant, as themselves, without a support call.

- An admin switches **AI support** on per app. The Hub then runs that app's
  MCP companion (an MCP server for the app, declared by its template) and
  publishes it at the app's own address, e.g.
  `https://gitea.example.com/mcp`, behind the Portcullis gateway. There is
  no app-specific Hub code: everything an app needs is in its template.
- Every person who can use that app sees a **"Connect your AI"** card on
  `people.<domain>` with the URL to copy and step-by-step instructions for
  Claude desktop, Claude Code and other MCP clients.
- One **"all my apps"** URL covers every app the person can use, so one
  setup is enough.
- An **AI page** (`ai.<domain>`, a chat app template) lets people chat with
  all their apps from the browser, using models from LiteLLM.
- The Hub serves its own **Portcullis MCP**. For an admin it can do
  everything the admin can do in the Hub: explain, diagnose with the doctor,
  propose changes and apply them. For anyone else it covers only their own
  apps and settings, like the People page.

The AI signs in through Keycloak with the person's passkey. It acts as that
person: only apps they can access, with their own rights in each app. It
loses access when they lose access.

## Goals

1. **Per-app AI support, declared by templates.** A template's `ai:` block
   declares one or more MCP companions:
   - which service runs it (a companion container, or the app itself when
     the MCP server is built in);
   - where it is published (a path on one of the instance's hostnames);
   - how the person's identity reaches it (identity mode, call 12);
   - which tools are writes and which need confirmation.

   An admin switches AI support on or off per instance and picks read-only
   or read-write where the template supports it. Off means the companion
   doesn't run, its route doesn't exist and every credential it used is
   revoked.
2. **The AI acts as the person.** Each request carries the person's
   identity to the companion. The person sees and changes only what they
   could see and change in the app's own UI. Nothing runs under a shared
   admin identity unless the template's identity mode says so and the
   admin can see that it does (call 12).
3. **People-page instructions.** On `people.<domain>` → My apps, every app
   with AI support on that the person can use shows a "Connect your AI"
   card: the URL with a copy button, and concrete steps for Claude desktop
   (Customize → Connectors → Add custom connector), Claude Code (a
   `claude mcp add` command to paste) and other MCP clients. A card at the
   top gives the "all my apps" URL. The person can see and disconnect their
   AI connections.
4. **One "all my apps" endpoint.** `https://mcp.<domain>/mcp` merges every
   companion the person can use (plus their own Portcullis tools) into one
   MCP server. The tool list is computed per person.
5. **The AI page.** A chat template (LibreChat, call 23) on `ai.<domain>`
   signs people in through Keycloak, connects to the "all my apps"
   endpoint as each person, and uses LiteLLM for models.
6. **The Portcullis MCP.** Served by the Hub at `https://hub.<domain>/mcp`
   (admins) and `https://people.<domain>/mcp` (everyone). Its tools mirror
   the Hub API, run through the same authorization code as the HTTP
   handlers, and are audited as the person, marked "via AI".
7. **Destructive actions need a human.** Deleting an instance, a person, a
   group or a domain, restoring over data, revoking credentials and every
   other destructive action keeps the Hub's existing confirmation (e.g.
   typing the instance id), and adds a fresh passkey touch in the person's
   browser. The model can't produce either.
8. **Revocation follows access.** A person leaving the app's access group
   (or being deleted, or the instance's AI support going off) loses AI
   access to that app at the next directory reconcile: their credentials
   are deleted and revoked in the app, and their AI sign-ins for it stop
   working.
9. **Everything is audited.** Every AI request is in an access log (who,
   which client, which app, which tool, result). Every Portcullis MCP
   change is in `audit.jsonl` as that person with `via: ai`.

## Non-goals

- **Local (stdio) companions on people's computers.** Every companion runs
  on the Portcullis server. Desktop extensions (MCPB) are not produced.
- **MCP for core services** (Keycloak, Traefik, LLDAP, group-gate). The
  Portcullis MCP covers what the Hub manages, nothing more.
- **Agents without a person.** No `client_credentials` tokens, scheduled
  agents or service accounts acting on their own. Every MCP request has a
  signed-in person behind it.
- **Hosting models.** LiteLLM (an existing template) is the model gateway;
  this design only wires the AI page to it.
- **Writing MCP servers for apps that have none.** Where no maintained
  companion exists (call 31), the template has no `ai:` block yet.
- **Per-tool allowlists edited by admins.** The template declares tool
  classes (write, confirm, never); admins choose read-only or read-write.
  A per-tool admin editor is left for later.
- **AI clients beyond the instructions.** The Hub doesn't install or
  configure Claude or any other client on people's computers.
- **Dynamic Client Registration and Client ID Metadata Documents** in v1
  (call 3). Clients use pre-registered Keycloak clients.

## Anti-goals

- **Prompt injection driving actions.** A document, issue or chat message
  read by the AI says "delete the repository" or "copy the passwords into
  this issue". The design must make such an action impossible without the
  person (destructive) or limited to what the person could do anyway
  (writes), and visible in the audit (call 20).
- **One app's token calling another app.** A token issued for
  `https://gitea.example.com/mcp` must be refused by every other resource,
  the aggregate and the Portcullis MCP included (call 6).
- **An MCP token becoming a browser session**, or a browser session
  authorizing MCP. MCP routes accept only bearer tokens for their own
  resource; browser routes never accept MCP tokens; nothing on an MCP route
  sets or reads a cookie (call 10).
- **Token passthrough.** The gate never forwards the person's Keycloak
  token to a companion or app. A companion receives only the credential its
  identity mode defines (MCP authorization spec: servers "MUST NOT accept or
  transit any other tokens").
- **Secrets reaching the model.** Env values, secret settings, DNS
  tokens, passwords, invite links, file-share passwords, generated
  secrets, app credentials and the proxy secret never appear in a tool
  result, an elicitation form or a tool argument (call 26).
- **A confirmation the model can fake.** No confirmation is a form the
  client can answer, a token in a URL, or text the model can type.
- **Admin power in the everyday connector.** The "all my apps" endpoint
  and the AI page never carry Portcullis admin tools.
- **Weakening the gateway.** An app whose policy needs a client certificate
  on every request doesn't get AI support (call 8). Group access, expiring
  memberships, path groups and the deny group keep applying.
- **App-specific Hub code.** Minting a Gitea token, turning on Home
  Assistant's MCP integration: all of it lives in the template (hooks).
- **Silent failure.** A companion that won't start, a mint hook that fails
  or a revocation that doesn't complete is shown on the instance's AI tab
  with the reason. A revocation that failed in the app is retried and never
  reported as done.

## Constraints and facts (verified in code and sources)

### Hub code

- **Two listeners, one chain.** `Handler()` (`internal/httpapi/server.go:38`)
  registers the app, template, source, drift, settings, directory, domain
  and instance routes and wraps them in `ProxySecret(…, CSRF(mux))`.
  `PeopleHandler()` (`server.go:80`) registers only `/healthz`, the people
  page, static files and the directory API (`TestPeopleListenerHasNoAppRoutes`,
  `internal/httpapi/people_test.go:85`). Addresses come from
  `HUB_LISTEN_ADDR` (`:8888`) and `HUB_PEOPLE_ADDR` (`:8889`)
  (`cmd/hub/main.go:185-186`).
- **Proxy secret and CSRF.** `ProxySecret` (`middleware.go:40`) requires
  `X-Portcullis-Proxy-Secret` (constant time, hashed) on everything but
  `GET /healthz`. `CSRF` (`middleware.go:70`) uses
  `http.NewCrossOriginProtection` and refuses non-JSON mutations.
- **Identity.** `actor(r)` is `X-Forwarded-User` (`directory.go:50`);
  `s.caller` (`directory.go:54`) builds a `directory.Caller{User, Admin,
  Perms}` (`internal/directory/authz.go:32`) once per request through
  `CallerFor` (`authz.go:59`). Every mutating `Service` method re-checks it
  inside the lock (`gate`, `authz.go:95`) and audits refusals.
  `adminOnly` (`internal/httpapi/domains.go:28`) guards domain and instance
  routes.
- **Audit.** `AuditEntry{Time, Actor, Action, Target, Detail, Result,
  Error}` (`internal/directory/audit.go:13`), appended as JSON lines (0600)
  to `audit.jsonl`. There is no field that says how a change was made.
- **Exec.** `Hub.Exec` (`internal/hub/runtime.go:104`) runs `/bin/sh -c`
  in a service container with no stdin. The settings spec (call 16) adds
  argv hooks with JSON on stdin; this design reuses them.
- **Policy write.** `WritePolicy` (`internal/hub/hub.go:548`) writes the
  group-gate policy, `portal-apps.json` and `user-attributes.json`
  together; the directory feeds it through `OnChange` (coalesced). The
  gate's file (call 4) is written in the same place.
- **Long operations** answer `202` and are polled at
  `/api/instances/{id}/op` (contract §11.7).

### Core

- **Traefik v3.7.17, Keycloak 26.8.1** (`portcullis/docker-compose.yml:146`,
  `:392`).
- **Forward-auth is cookie-based.** oauth2-proxy (`forward-auth`) uses the
  Keycloak client `portcullis-forward-auth`, a `.<domain>` cookie, 1 min
  cookie refresh, and injects `Authorization: Bearer <its access token>`,
  `X-Forwarded-User` (= `preferred_username`) and
  `X-Forwarded-Access-Token` into backends
  (`portcullis/oauth2-proxy/alpha.yaml`). It isn't configured to accept
  bearer tokens (`skip_jwt_bearer_tokens` is not set) and must stay that
  way (call 10).
- **group-gate does not verify JWT signatures** ("already verified upstream
  by oauth2-proxy", `group-gate/group-gate.py` docstring). It reads acr,
  amr, `preferred_username` and groups from the forwarded token. So it
  can't be the validator for bearer tokens that never passed oauth2-proxy.
- **Router tiers.** The hub and people routers use `authaware@file`
  (`docker-compose.yml:836`, `:848`); an app whose policy needs mTLS on
  every request gets `protected@file` (contract §5), which makes the TLS
  handshake itself demand a client certificate.
- **Shared routing plane.** `portcullis-proxy` has fixed IPAM
  (`172.31.250.0/24`, dynamic range `.128/25`) and Traefik pinned at
  `PORTCULLIS_TRAEFIK_IP` (`.2`); header-auth apps trust identity headers
  only from that address (Grafana: `GF_AUTH_PROXY_WHITELIST`,
  `tpl-new/grafana/compose.yml:22`; Firefly III: an nginx check on
  `$realip_remote_addr`).
- **Core Go services exist** (`enroll`, `domains`), so a new Go core
  service fits the repo.
- **ForwardAuth can forward the body** (`forwardBody`, `maxBodySize`) but
  "this breaks streaming", and a non-2xx answer is returned to the client
  as is (Traefik v3.7 docs). So forwardAuth can't answer a tool call with a
  proper JSON-RPC result (it can only allow or fail the HTTP request);
  call 4 uses a proxy instead.

### Templates

- `tpl-new` has 40 templates plus `tpl-ha-oxi` (homeassistant, oxicloud,
  mattermost). Auth methods relevant here: gitea, immich, nextcloud,
  paperless, jellyfin, homeassistant, oxicloud are `native-oidc`; grafana
  and firefly-iii `header-auth`; mattermost `forward-auth`.
- `litellm` exists (`instances: multi`, native-oidc admin UI; its
  OpenAI-compatible API has no forward-auth and is keyed by virtual keys,
  `tpl-new/litellm/manifest.yaml`).
- The compose allowlist refuses `profiles`, `deploy` and others in
  templates (contract §3). The Hub's own override isn't bound by that
  list.

### MCP specification (current revision 2026-07-28)

Sources: modelcontextprotocol.io/specification/2026-07-28 (authorization,
client registration, Streamable HTTP, elicitation), fetched 2026-11-02.

- **Authorization.** The MCP server is an OAuth 2.1 resource server. It
  "MUST implement OAuth 2.0 Protected Resource Metadata (RFC 9728)"; the
  client finds the authorization server from it, then uses RFC 8414 or
  OpenID Connect discovery (clients must support both). Clients "MUST
  implement Resource Indicators (RFC 8707)" and send `resource` (the
  canonical server URI, e.g. `https://gitea.example.com/mcp`) on both the
  authorization and the token request. Servers "MUST validate that access
  tokens were issued specifically for them as the intended audience",
  "MUST only accept tokens that are valid for use with their own
  resources" and "MUST NOT accept or transit any other tokens". Invalid or
  expired tokens get `401`; insufficient scope gets `403` with
  `error="insufficient_scope"`. Tokens only in the `Authorization` header,
  never in the query string. PKCE S256.
- **Client registration** (priority): pre-registered client, then Client
  ID Metadata Documents (CIMD, "SHOULD"), then Dynamic Client
  Registration, which "is deprecated and retained for backwards
  compatibility".
- **Streamable HTTP in 2026-07-28**: one POST endpoint, JSON or a
  request-scoped SSE stream; **no protocol sessions and no GET stream**;
  server-to-client requests (elicitation, sampling, roots) are embedded in
  results as `InputRequiredResult` (MRTR) and the client retries with
  `inputResponses`. Every POST carries `MCP-Protocol-Version`, `Mcp-Method`
  and (for `tools/call`, `resources/read`, `prompts/get`) `Mcp-Name`;
  servers "MUST reject requests where the values specified in the headers
  do not match the corresponding values in the request body" (`-32020
  HeaderMismatch`), and intermediaries that enforce policy on headers
  "SHOULD" reject older versions rather than trust them. Servers "MUST
  validate the `Origin` header" and answer `403` to an invalid one.
  Versions 2025-03-26 to 2025-11-25 had `Mcp-Session-Id` sessions and
  server-sent requests; servers that support them implement those
  revisions too.
- **Elicitation.** Form mode collects structured data through the client;
  servers "MUST NOT use form mode elicitation to request sensitive
  information such as passwords, API keys, access tokens" and "MUST use
  URL mode" for those. URL mode sends the user to a URL out of band; the
  client "MUST NOT open the URL without explicit consent", "MUST show the
  full URL", must open it so "the client or LLM" can't inspect it. Servers
  "MUST NOT provide a URL which is pre-authenticated" and "MUST verify the
  identity of the user who opens the URL" (phishing). `accept` on a URL
  elicitation only means the user agreed to open it, not that the
  interaction finished.

### Claude clients

Sources: claude.com/docs/connectors/building/authentication.md,
claude.com/docs/connectors/custom/add-unlisted.md,
code.claude.com/docs/en/mcp (fetched 2026-11-02).

- **One OAuth stack** backs claude.ai, Claude Desktop, mobile, Claude Code
  and Cowork. Supported: DCR, CIMD (only when the authorization server
  advertises `client_id_metadata_document_supported: true` **and** `none`
  in `token_endpoint_auth_methods_supported`), a client the user enters,
  and no auth. PKCE S256 always. `401` with a `resource_metadata` pointer
  starts sign-in (a `WWW-Authenticate` on `200` is ignored). Claude uses
  only the first `authorization_servers` entry. Discovery, registration and
  token endpoints get 10 s, refresh 30 s. Refresh tokens should rotate;
  errors must be `invalid_grant`. `offline_access` is appended when the
  authorization server lists it.
- **Claude desktop and claude.ai connect from Anthropic's cloud**:
  "Anthropic's outbound traffic to your server originates from
  `160.79.104.0/21`", and the authorization server must be reachable from
  there too. Hosted apps use the redirect URI
  `https://claude.ai/api/mcp/auth_callback`.
- **Adding a custom connector** (Free, Pro, Max, Ultra): Customize →
  Connectors → "Add custom connector" → server URL → optionally OAuth
  credentials (under "Advanced settings", or a two-step dialog with
  "Authentication: Sign in now / Sign in when needed / No sign-in" and
  "OAuth client: Use Claude's published identity / Register automatically /
  Use your own OAuth client") → Add. Team and Enterprise: an Owner adds it
  in Organization settings → Connectors → Add → Custom → Web; members then
  click Connect under Customize → Connectors. Authentication settings
  can't be changed after adding (remove and re-add). Tools can be set to
  "Blocked" per connector.
- **Claude Code**: `claude mcp add --transport http <name> <url>`,
  `--scope local|project|user`, `--client-id`, `--client-secret` (prompts),
  `--callback-port` ("fixes the port to match a pre-registered redirect URI
  of the form `http://localhost:PORT/callback`"); sign in with `/mcp` or
  `claude mcp login <name>`; tokens in the keychain, refreshed
  automatically; `claude mcp logout <name>` revokes. Claude Code treats a
  `401` **or `403`** as "needs authentication". Claude Code connects from
  the person's own computer, not from Anthropic's cloud.

### Keycloak 26.8.1 as an MCP authorization server

Sources: keycloak.org/securing-apps/mcp-authz-server,
keycloak.org/securing-apps/token-exchange (fetched 2026-11-02).

- MCP 2025-03-26 "Supported"; 2025-06-18, 2025-11-25 and 2026-07-28
  "Experimental". OAuth 2.1, RFC 8414, RFC 9207 and RFC 7591 (DCR)
  supported; **RFC 8707 resource indicators and CIMD are experimental**
  (`--features=resource-indicators`, `--features=cimd`, "may introduce
  breaking changes"). RFC 9728 is the MCP server's job, not Keycloak's.
- Without the resource-indicators feature Keycloak "does not recognize the
  `resource` parameter"; the documented workaround is **optional client
  scopes with an Audience mapper whose custom audience is the MCP server
  URL**.
- CIMD with Claude needs a client profile with trusted domains `claude.ai`,
  `localhost`, `127.0.0.1`, "Restrict same domain" off and "Accept Public
  Client with Confidential-only Grant Types" on.
- Standard token exchange (V2) is on by default for confidential clients
  that enable it; it doesn't support `resource` yet. Contract §8 already
  names token exchange as a residual risk for access-role clients.

### Companions for our templates (surveyed 2026-11-02)

| App | Companion | Maintainer | Transport | How it authenticates to the app |
|---|---|---|---|---|
| Gitea | `gitea-mcp` (`docker.gitea.com/gitea-mcp-server`, v1.12.0) | official (gitea.com/gitea) | Streamable HTTP, stateless, up to 2026-07-28 | Per-request `Authorization: token <gitea token>` passthrough; `-r`/`GITEA_READONLY` hides write tools; `GITEA_TOOLS`/`GITEA_SCOPES` filters; optional own OAuth with Gitea as AS (no DCR) |
| Grafana | `mcp-grafana` (github.com/grafana/mcp-grafana) | Grafana org | stdio / SSE / streamable-http | Service account token, or per-request headers; `GRAFANA_FORWARD_HEADERS` copies listed incoming headers to Grafana (streamable-http only); `--server-auth-token` for callers; `--disable-write` |
| Home Assistant | built-in "MCP Server" integration, `/api/mcp` | official | HTTP | Home Assistant is its own OAuth AS (PKCE, CIMD-style client ids via IndieAuth, no DCR, no client secret); admin-only by default, an option allows non-admins; only Assist-exposed entities; Claude connects from the cloud |
| Mattermost | built-in to `mattermost-plugin-agents`, `/plugins/mattermost-ai/mcp-server/mcp` | official | Streamable HTTP | OAuth with DCR, or a personal access token; tools run with the user's permissions |
| Nextcloud | `cbcoutinho/nextcloud-mcp-server` (AGPL-3.0, ~5k commits) | community | streamable-http, stdio | App passwords over Basic auth; multi-user "BasicAuth pass-through: clients send credentials via Authorization header"; OAuth-to-Nextcloud dropped |
| GitLab | built-in MCP server | official | builder verifies (docs moved to docs.gitlab.com/user/model_context_protocol/mcp_server/) | builder verifies tier and auth |
| Paperless-ngx | `nloui/paperless-mcp` (248★, last change Nov 2025), others smaller | community | builder verifies | API token |
| Immich | `drolosoft/immich-photo-manager` (62★), `barryw/ImmichMCP` (55★) | community, small | — | API key (Immich has no admin path to mint keys for another user) |
| Vikunja | `democratize-technology/vikunja-mcp` (114★) | community | — | API token |
| Jellyfin | `jaredtrent/jellyfin-mcp` (46★) | community | — | API key |
| Firefly III | `etnperlong/firefly-iii-mcp` (91★), `daften/fireflyiii-mcp` | community | stdio (PAT) / HTTP (OAuth) | PAT |

Sources: gitea.com/gitea/gitea-mcp, github.com/grafana/mcp-grafana,
home-assistant.io/integrations/mcp_server, github.com/mattermost/mattermost-plugin-agents,
github.com/cbcoutinho/nextcloud-mcp-server, GitHub repository searches
(stars and dates as shown on 2026-11-02).

"Acts as that person" therefore comes in three shapes in the wild:
**a per-person app credential** the caller supplies (Gitea, Nextcloud,
Mattermost PATs, most community servers), **identity headers** forwarded to
an app that trusts an auth proxy (Grafana), and **the app as its own OAuth
server** (Home Assistant; Mattermost and GitLab also offer it). Token
exchange into an app-audience Keycloak token would need the app to accept
Keycloak bearer tokens; none of the surveyed companions relies on that
(Nextcloud's OIDC route was dropped upstream).

### Chat front-ends

Sources: docs.openwebui.com/features/extensibility/mcp,
librechat.ai/docs/configuration/librechat_yaml/object_structure/mcp_servers.

- **Open WebUI** (≥ 0.6.31): native MCP over Streamable HTTP only (works
  with 2026-07-28); auth modes None, Bearer, Session, OAuth (reuse the SSO
  token), OAuth 2.1 (DCR) and OAuth 2.1 Static (pre-created client);
  OAuth grants are per user. "MCP servers can only be added by
  administrators" (in the UI); OAuth 2.1 tools "must not be set as model
  defaults"; "expect occasional breaking changes"; OpenAPI is still "the
  preferred integration path".
- **LibreChat**: MCP servers declared in `librechat.yaml`
  (`type: streamable-http`), an `oauth` block (`client_id`,
  `client_secret`, `scope`, PKCE; DCR when no client is given), per-user
  OAuth tokens ("Each user is prompted to authenticate"), callback
  `${DOMAIN_SERVER}/api/mcp/<server-name>/oauth/callback`, `oauthPrompt:
  on_use`, OpenID login, custom OpenAI-compatible endpoints (LiteLLM).

### MCP gateways

- **agentgateway** (agentgateway.dev, standalone 1.7.x): MCP resource
  server (JWT validation, serves protected resource metadata), multiplexes
  targets into one endpoint with per-target tool prefixes, CEL tool
  authorization on JWT claims that also filters `tools/list`, per-target
  static `backendAuth` keys, token exchange, rate limits, access logs. It
  has no notion of a per-person credential minted by someone else, and its
  docs advise against multiplexing servers whose users authenticate
  themselves ("One federated endpoint can't run a separate authorization
  flow for each upstream server").
- **Official MCP Go SDK** (`github.com/modelcontextprotocol/go-sdk`,
  v1.7.0+): supports 2026-07-28 down to 2024-11-05, has `auth` and
  `oauthex` (protected resource metadata) packages.

### Standing rules

Prefer mature pinned libraries; no migration code (no installs); fail
closed; never weaken access control; secrets never on argv, in logs, the
audit, op records or API answers; identity is the LLDAP username, never
email; admin-only and audited management; the people listener exposes only
what each person may see; contract changes in `integration-contracts.md`
first; templates stay declarative; images pinned by digest.

## Decided by the user

- "Be AI-ready providing MCP support for the apps users are installing."
- Admins enable "AI support" so that the app's MCP companion is installed,
  and people get concrete instructions to configure the MCP on their
  computers (e.g. the Claude GUI).
- "An interface users can open to actually interface with all their apps
  through the MCPs."
- The approved playback:
  - (a) a per-app "AI support" toggle by an admin; the template declares
    the app's MCP companion (e.g. Gitea MCP server, Grafana MCP, Home
    Assistant's built-in MCP server), installed by the Hub, reachable at
    the app's address (e.g. `https://gitea.<domain>/mcp`) behind the
    gateway; no app-specific Hub code;
  - (b) a People page "Connect your AI" card per app the person can access
    with AI support on: URL to copy, steps for Claude desktop (Settings →
    Connectors → Add custom connector), Claude Code (`claude mcp add`
    command), other MCP clients;
  - (c) an AI page (e.g. `ai.<domain>`) to chat with all their apps through
    those companions.
- Accepted ("it looks all good"): the person's AI signs in through Keycloak
  (passkey) and acts as that person, only apps they can access, their own
  rights in each app; the AI page is a chat app template (Open WebUI or
  LibreChat) wired to the person's companions and to LiteLLM for models; a
  single "all my apps" connector URL so one setup covers everything.
- "We should also have our own MCP so that admins can get help configuring
  the app": a Portcullis MCP served by the Hub. "It should be fully
  featured": it can do everything the signed-in admin can do in the Hub
  (explain, diagnose via the doctor, propose AND apply changes), not just
  suggest. Ordinary users get only their own apps and settings (People-page
  scope).

## Calls made while drafting (check these)

Items marked **Controller's call** were made by the controller during the
brainstorm. The others were made while drafting this spec.

### The shape in one paragraph

A new core service, **`mcp-gate`** (Go, on the official MCP Go SDK),
terminates every MCP request: per-app endpoints on app hostnames, the
aggregate on `mcp.<domain>`, and the Portcullis MCP on `hub.<domain>` and
`people.<domain>`. It validates the Keycloak access token for exactly that
resource, checks the person is in the resource's population right now,
applies tool policy, rate limits and confirmations, writes the access log,
and forwards the request to the companion with the person's identity in the
form the companion understands (a per-person app credential the Hub minted
through a template hook, identity headers, or nothing for apps that are
their own OAuth server). The Hub manages everything around it: Keycloak
clients and scopes, the gate's configuration and per-person credentials,
the companion containers, the People-page cards and the Portcullis MCP
itself.

```
Claude desktop ──(Anthropic cloud)──┐
Claude Code ────────────────────────┤  Bearer <Keycloak token, aud = that URL>
AI page (LibreChat) ────────────────┤
                                    ▼
             Traefik ── Hub-rendered router /mcp ──► mcp-gate (core)
                                                     │  validate · population · policy
                                                     │  rate limit · confirm · log
              ┌──────────────────────────────────────┼─────────────────────┐
              ▼                                      ▼                     ▼
   companion (template service)            Hub MCP listener :8890    (aggregate fans out
   + per-person app credential             X-Forwarded-User + gate    to the same upstreams)
   or identity headers                     secret; Caller + audit
```

### Controller's calls, made concrete

1. **Audited as that person, marked "via AI".** *(Controller's call.)*
   - `directory.AuditEntry` gains `Via string` (`"ai"` or empty) and
     `Client string` (the Keycloak `azp`, e.g. `portcullis-ai-claude`).
     Every Portcullis MCP action is written with `Actor` = the person,
     `Via: "ai"`, `Client`, the same `Action` names the HTTP handlers use
     (`instance.delete`, `settings.change`, `directory.add_member`, …), and
     the same `Result` values. Refusals are audited too.
   - Actions on app companions are not Hub actions; they go to the gate's
     access log (call 19), which the Hub shows on the instance's AI tab and
     the person's People page.
2. **Destructive actions keep their confirmations, and add a fresh passkey
   touch the model can't fake.** *(Controller's call, made concrete.)*
   - A tool is **destructive** when its HTTP twin has a confirmation today
     (typed instance id, typed name for another administrator) or deletes,
     restores over, revokes or runs code: see the tool tables (call 25).
   - Calling it without a confirmation returns, instead of acting:
     - an `InputRequiredResult` with a **URL-mode elicitation** when the
       client declared `elicitation.url` (2026-07-28 MRTR; on 2025-11-25
       the equivalent server request);
     - otherwise a tool result with `isError: true` and the text "This
       needs your confirmation in your browser: open
       https://hub.example.com/confirm/7Q2M-K9WX, then ask me to try
       again." (Never an HTTP 401/403: Claude Code would treat it as a
       sign-in problem.)
   - The **confirmation page** is on the listener the tool belongs to
     (`hub.<domain>/confirm/<id>` for admin tools, `people.<domain>/confirm/<id>`
     for people tools and app companions). It is a normal browser page
     behind forward-auth, and it:
     1. refuses unless the browser session's user is the person the
        confirmation was created for (the MCP spec's phishing rule);
     2. shows the exact action from the stored request, rendered by the
        Hub (not text the model wrote): tool, target, arguments,
        consequences ("takes a backup, then permanently removes …");
     3. asks for the existing typed confirmation where one exists (the
        instance id, the person's name);
     4. asks for a **fresh passkey touch**: a fresh Keycloak sign-in
        through the Hub's own confirmation client, verified on a new ID
        token (`auth_time` within 5 minutes, `amr` passkey or a `pki_int`
        certificate, never a file certificate) — the certificates spec's
        fresh-authentication pattern (its call 8);
     5. records approve or decline.
   - A confirmation is bound to (person, resource, tool, SHA-256 of the
     canonical JSON arguments), single use, valid 10 minutes, and
     consumed by the first matching retry. A retry with any other argument
     gets a new confirmation. The URL holds only an unguessable id (128
     bits), never a credential; opening it unauthenticated just leads to
     sign-in.
   - Form-mode elicitation is never accepted as a confirmation: a client
     (or a scripted client such as `claude -p`) can answer it without the
     person.
3. **OAuth 2.1 with Keycloak, pre-registered clients.** *(Controller's
   call: "DCR or pre-registered clients — builder to decide, verify what
   Claude desktop/Claude Code support". Drafting resolves it.)*
   - **Pre-registered public clients**, created and reconciled by the Hub
     (owner-tagged like app clients), one per client kind the admin offers
     (Hub Settings → AI, call 28):
     - `portcullis-ai-claude`: public, standard flow only, PKCE S256
       required, redirect URI exactly `https://claude.ai/api/mcp/auth_callback`
       (claude.ai, Claude desktop, mobile, Cowork);
     - `portcullis-ai-claude-code`: public, PKCE S256, redirect URIs
       `http://localhost:33418/callback` and `http://127.0.0.1:33418/callback`
       (used with `--callback-port 33418`; the builder verifies whether
       Keycloak 26.8 matches loopback redirects port-agnostically, and if
       so drops the fixed port);
     - `portcullis-ai-generic`: public, PKCE S256, the same loopback
       redirects, for other MCP clients that accept a client id;
     - one confidential client per AI page instance (call 23).
   - On all of them: direct access grants, implicit, device, CIBA, service
     accounts and token exchange off; "Consent required" on, with the
     consent text of each scope (call 7); default ACR `hwk` (call 8).
   - **DCR stays off.** Keycloak's anonymous registration would let anyone
     on the internet create clients (Claude registers from Anthropic's
     range, Claude Code from any address), and the MCP spec deprecates it.
   - **CIMD later.** It is the spec's preferred mechanism and Claude
     supports it, but it is experimental in Keycloak 26.8 (`--features=cimd`).
     When it is no longer experimental, a later change can switch the
     Claude clients to "Use Claude's published identity" with a client
     profile that trusts only `claude.ai`, `localhost` and `127.0.0.1`. The
     gate and the scopes don't change.
   - Authorization server = `https://auth.<domain>/realms/portcullis`
     (Keycloak's own discovery; the `keycloak` router already has no
     forward-auth). It must be reachable from Anthropic's egress range for
     Claude desktop; the AI settings page says so.

### Architecture

4. **A core service `mcp-gate` terminates every MCP request.**
   - Why not the existing pieces: oauth2-proxy is cookie-based and must
     never accept bearer tokens (call 10); group-gate doesn't verify
     signatures and, as forwardAuth, can't answer a tool call with a
     JSON-RPC result or a URL elicitation; agentgateway can't inject a
     per-person credential minted elsewhere and advises against
     aggregating self-authenticating servers; the Hub holds Docker and
     admin power and shouldn't parse untrusted tool traffic for every app.
   - `mcp-gate` lives in the core repo (Go, like `enroll` and `domains`),
     image pinned by digest. Libraries: the official MCP Go SDK
     (client and server, Streamable HTTP, both 2026-07-28 and 2025-11-25),
     a maintained JOSE/OIDC library for JWKS and JWT validation (e.g.
     `github.com/coreos/go-oidc/v3`), `filippo.io/age` (call 13),
     `golang.org/x/time/rate` (call 18). The builder may replace any of
     them with an equally mature one.
   - Networks: `portcullis` (Keycloak JWKS at `http://keycloak:8080`, the
     Hub at `http://hub:8890`) and `portcullis-proxy` with a pinned address
     **`PORTCULLIS_MCP_GATE_IP`** (default `172.31.250.3`, outside the
     dynamic range, never equal to Traefik's). It has no Docker access,
     no LLDAP or Keycloak admin credentials.
   - It reads (never writes) `mcp-gate.json` and `mcp-credentials.json`
     from `hub_data` (read-only mount, like group-gate), re-reading on
     change; a file that exists but can't be parsed means every MCP
     request is refused (fail closed). It writes only its own volume
     `mcp_gate_data` (the access log, call 19), which core mounts read-only
     into the Hub.
   - Core reserves the service name `mcp-gate` and the volume key
     `mcp_gate_data` (the Hub's `reservedDNSName` / `coreVolumes` lists
     follow, checked by `TestCoreNamesComplete`).
5. **Resources and URLs.** Each MCP endpoint is its own OAuth protected
   resource, identified by its canonical URL:

   | Resource | URL | Who | Upstream |
   |---|---|---|---|
   | App companion | `https://<host of the declared router><path>`, e.g. `https://gitea.example.com/mcp` | the instance's AI population (call 14) | the companion |
   | All my apps | `https://mcp.<domain>/mcp` | any signed-in person | every companion the person may use + their people-scope Portcullis tools |
   | Portcullis (admin) | `https://hub.<domain>/mcp` | `lldap_admin` | Hub `:8890/mcp/admin` |
   | Portcullis (people) | `https://people.<domain>/mcp` | any signed-in person | Hub `:8890/mcp/people` |

   - `mcp` becomes a **core subdomain** (contract §4 core hosts,
     `policy.CoreHosts`, group-gate, the templates validator), never on an
     extra domain.
   - For each resource the gate serves its RFC 9728 document at
     `/.well-known/oauth-protected-resource<path>` on the same host
     (e.g. `https://gitea.example.com/.well-known/oauth-protected-resource/mcp`):
     `{"resource": "<url>", "authorization_servers": ["https://auth.<domain>/realms/portcullis"],
     "scopes_supported": ["<the resource's scope>"], "bearer_methods_supported": ["header"],
     "resource_name": "<app label> on Portcullis"}`. Unauthenticated
     requests get `401` with `WWW-Authenticate: Bearer resource_metadata="…",
     scope="<the resource's scope>"`.
   - **Routing.** For app companions the Hub's override renders a router
     per companion, like the extra-domain sign-in router does for
     `forward-auth-ext@docker`: `portcullis-mcp-<instance-id>_<companion>`,
     rule `Host(<the router's hosts>) && (Path(<path>) ||
     Path(/.well-known/oauth-protected-resource<path>))`, the host's TLS
     tier, a priority above every router of the instance and its public
     and sign-in routers, service `mcp-gate@docker`, middlewares
     `rate-limit@file,security-headers@file` only (no forward-auth). The
     name prefix `portcullis-mcp-` is reserved for the Hub (templates may
     not use it). Its labels are exposure labels (drift). The template's
     own routers never see `/mcp` requests on that host.
   - Core adds routers for `mcp.<domain>` (all paths → `mcp-gate`) and for
     `hub.<domain>` / `people.<domain>` with `Path(/mcp) ||
     Path(/.well-known/oauth-protected-resource/mcp)` → `mcp-gate`, at a
     priority above the `hub` and `people` routers, `authaware@file`.
   - Extra-domain instances work the same: the resource is on the extra
     domain, the authorization server stays `auth.<main domain>`.
6. **What the gate accepts (audience separation).** A request is served
   only if all of these hold, otherwise `401` (bad or missing token) or
   `403` (valid token, not allowed):
   - `Authorization: Bearer <JWT>` only; no token in the query; no cookie
     is read.
   - Signature valid against the realm's JWKS (cached, refreshed on an
     unknown `kid`); `iss` exactly the realm issuer; `exp`, `nbf`, `iat`
     with 60 s skew; `typ` `Bearer`.
   - `azp` is one of the Hub's AI clients (from `mcp-gate.json`), never
     `portcullis-forward-auth` or an app's client.
   - **`aud` contains this resource's URL and no other MCP resource URL**
     (a token minted for several companions at once is refused
     everywhere), and `scope` contains this resource's scope.
   - `acr` meets the resource's minimum level (call 8).
   - `preferred_username` (lowercased) is in the resource's current
     population in `mcp-gate.json`, minus anyone in an active `expiring`
     entry for the group that grants it; for the admin resource, in
     `lldap_admin` (and the Hub re-checks through `CallerFor`).
   - If an `Origin` header is present it must be in the admin's allowed
     origins (empty by default): `403` otherwise (the spec's DNS-rebinding
     rule).
   - For 2026-07-28 requests the gate checks `Mcp-Method` / `Mcp-Name`
     against the body (`400 -32020` on mismatch) and always decides on the
     parsed body, never the headers alone.

   Insufficient-scope failures follow the spec (`403`,
   `error="insufficient_scope"`, `scope=…`, `resource_metadata=…`).
7. **Scopes and Keycloak objects the Hub manages.**
   - One **optional client scope per resource**, named
     `mcp:<instance-id>.<companion>` for app companions, `mcp:all`,
     `mcp:portcullis.admin`, `mcp:portcullis.people`; each with one
     Audience mapper whose included custom audience is the resource URL
     (access token only), "include in token scope" on, and a consent
     screen text ("Use Gitea (gitea.example.com) as you", "Use all your
     Portcullis apps as you", "Manage Portcullis as you — administrator").
     This is Keycloak's documented workaround for `resource`; the
     experimental resource-indicators feature is not needed and not
     enabled.
   - The scopes are attached as **optional** scopes to every AI client
     (the admin scope only to the clients the admin enabled it for, call
     28), never to app clients or `portcullis-forward-auth`, never as
     realm defaults. They carry no group or attribute mappers: the
     token has `preferred_username`, `acr` and `amr`, nothing else
     Portcullis-specific.
   - A hostname change (contract §11.3) renames the resource: the Hub
     updates the audience mapper and consent text in the same step as the
     redirect URIs; old tokens stop matching. A deleted instance or AI
     support switched off removes its scope (and with it every consent
     that named it).
   - Contract §8 gets these objects, and the rule that the Hub never
     attaches an `mcp:*` scope anywhere else.
8. **Sign-in strength, and apps that need a certificate.**
   - The AI clients' default ACR is `hwk`, so an AI sign-in is a passkey
     (or hardware certificate) touch, like a browser sign-in. The gate
     requires the resource's LoA from its effective policy (default
     policy or the app's override, `policy.Resolve`).
   - An instance whose effective policy needs `mtls` on every request
     (`mtls` alone, or `all` of `mtls` and `webauthn`; TLS tier
     `protected@file`) **can't get AI support**: no MCP client can present
     the person's certificate (Claude desktop's requests come from
     Anthropic's cloud). Switching AI on is a `409` with that reason, and
     changing such an instance's policy to need mTLS switches AI support
     off first (with a warning in the save preview).
   - **No exception.** An admin can't let AI use such an app with a passkey
     sign-in only: that would serve the app's data at a lower level than its
     policy demands, which the standing rule "never weaken access control"
     and the anti-goal "Weakening the gateway" rule out. An admin who wants
     AI on the app lowers its policy deliberately, in the policy editor,
     where the change is visible and audited like any other.
   - The same rule applies to the Portcullis admin resource if an admin
     moves the hub host to mTLS-only.
9. **How long an AI connection stays signed in.** *(Controller's call,
   call 33.)* AI clients may request `offline_access` (Claude asks for
   it when listed), so a connection survives the browser session:
   offline session idle 7 days, max 30 days, then the person touches their
   passkey again. Access tokens live 5 minutes (realm default). Refresh
   tokens rotate (Keycloak "Revoke refresh token", reuse 0), so a stolen
   refresh token is detected at the next use.
10. **No crossing between MCP tokens and browser sessions.**
    - MCP routers have no forward-auth; browser routers keep
      oauth2-proxy, which never accepts bearer tokens (core keeps
      `skip_jwt_bearer_tokens` off; core CI asserts it). An MCP token's
      `azp` and `aud` are not `portcullis-forward-auth`'s, so it would be
      refused there anyway.
    - The gate ignores `Cookie`, never sets cookies, strips `Cookie`,
      `Authorization`, `Proxy-Authorization`, every `X-Forwarded-*`,
      `X-Auth-Request-*`, `Remote-*` and `X-Portcullis-*` header the client
      sent before forwarding, and adds only what the identity mode defines.
      A browser session cookie can't authorize an MCP route; an MCP token
      can't open any page.
    - Only `<path>` and its metadata path are routed to the gate on an app
      host; the companion's other paths are not reachable through it.
    - Confirmation pages (call 2) are browser pages with their own
      sign-in; a confirmation id is not a credential.
11. **How templates declare companions (`ai:` block, contract v3).**
    Generic, no per-app Hub code; reuses the settings spec's `hooks:` and
    `applies`:
    - `ai.companions[]`:
      - `name` (`^[a-z][a-z0-9-]{0,30}$`, unique in the template), `label`;
      - `service`: the compose service that serves MCP. Either a companion
        service only for AI (`kind: companion`), which the Hub's override
        sets to `scale: 0` while AI support is off, or the app's own
        service (`kind: builtin`) for built-in MCP servers;
      - `port` (container port), `path` (upstream path, default `/mcp`);
      - `router`: the host router whose hostnames carry the endpoint;
        `public_path` (default `/mcp`), which must not be
        `/.well-known/…`, `/oauth2/…` or a public-access path;
      - `identity`: the identity mode (call 12) and its parameters;
      - `modes`: `[read_only]`, `[read_write]` or both (the admin picks
        when both); `default_mode`;
      - `tools`: `confirm` (names or `*` globs that always need a human,
        call 17), `never` (names the gate refuses and hides), and
        `writes` (names or globs that are write tools; used for read-only
        enforcement and the UI). Patterns are matched on the companion's
        own tool names;
      - `aggregate` (default true; forced false for `app_oauth`);
      - `upstream: official|community` and `source` (URL), shown in the
        Hub ("community-maintained companion");
      - `protocol`: MCP versions the companion speaks (informational; the
        gate negotiates).
    - `ai.on_change`: an optional hook run with `{enabled, mode}` on stdin
      when AI support or the mode changes (e.g. turn Home Assistant's MCP
      integration on, set a companion's read-only flag), `applies` as in
      the settings spec.
    - New reserved instance variables (contract §3.1):
      `PORTCULLIS_AI_ENABLED` (`true|false`), `PORTCULLIS_AI_READONLY_<COMPANION>`
      (`true|false`; `<COMPANION>` upper-cased, `-` → `_`),
      `PORTCULLIS_MCP_GATE_IP` (core's value),
      so a companion's flags can come from env with no hook.
    - Validator (Hub and `validate.py`): the service exists; a
      `companion` service has no Traefik labels and doesn't join
      `portcullis-proxy` itself (the override adds it, with the alias
      `portcullis-mcp-<instance-id>-<companion>`; aliases with that prefix
      are reserved); `router` is a host router; `public_path` doesn't
      collide with another companion's; hooks named exist; an
      `app_oauth` companion is `builtin` and has a `revoke` hook; an
      `identity_headers` companion declares a `caller_secret` (call 12).
12. **How the person's identity reaches each companion (identity modes).**
    The template picks one per companion:
    - **`app_token`** — a per-person app credential, minted by the Hub
      through the template's `mint` hook, injected by the gate on every
      request. Parameters: `header` (default `Authorization`) and `format`
      with `{credential}` / `{username}` placeholders (`"token
      {credential}"` for Gitea, `"Bearer {credential}"`, or
      `basic: {user: "{username}", password: "{credential}"}` for
      Nextcloud app passwords), `scopes` per mode (passed to the hook),
      and `revoke` hook. The credential exists only for this purpose
      (named `portcullis-ai-…` in the app), only for people who used AI on
      that app, and never leaves Portcullis. Used by: Gitea, Nextcloud,
      Mattermost, most community companions.
    - **`identity_headers`** — the gate sends `X-Forwarded-User`,
      `X-Forwarded-Email`, `X-Auth-Request-Groups` and the person's
      `X-Forwarded-Attr-*` headers (same values group-gate would send) and
      the companion passes them to an app that trusts an auth proxy. The
      companion must refuse callers other than the gate: the template
      declares `caller_secret: {env: <VAR>, header: Authorization, format:
      "Bearer {secret}"}` (a `generate: random` env entry the Hub shares
      with the gate; mcp-grafana's `--server-auth-token` is exactly this),
      and the app must trust the header only from the companion (template
      responsibility, see "Left to the builder"). Used by: Grafana.
    - **`app_oauth`** — the app is its own MCP authorization server and
      signs people in through its own login, which on Portcullis is
      Keycloak (native-oidc). The gate is not in the path: the endpoint is
      the app's own route (e.g. `https://ha.example.com/api/mcp`), the
      People card says which client settings the app expects, the
      companion is never aggregated, and the template must have a `revoke`
      hook that ends the person's app-side tokens (e.g. Home Assistant:
      deactivate or remove the person's refresh tokens; builder verifies
      the exact call). Used by: Home Assistant.

    A mode that would run every request as one shared admin identity is
    not offered. Gitea's `Sudo`-style impersonation and mcp-grafana's
    service-account token are not used.
13. **Per-person credentials: lazy minting, encrypted at rest, revoked on
    leave.**
    - **Lazy.** The first request of a person to an `app_token` companion
      makes the gate ask the Hub (`POST http://hub:8890/internal/credentials
      {resource, user}`, authenticated with the gate secret, call 24). The
      Hub checks the population, runs the `mint` hook with
      `{"action": "mint", "user", "instance", "companion", "name":
      "portcullis-ai-<12 random>", "mode", "scopes"}` on stdin and reads
      `{"credential", "id"}` from stdout, then answers. The gate retries
      the original request once the new entry is in the file (bounded
      wait 20 s; meanwhile the client gets a JSON-RPC error "Preparing
      your access to Gitea, try again in a moment").
    - **Encrypted to the gate.** `portcullis init` generates an age X25519
      key pair: the identity file only `mcp-gate` mounts, the recipient
      (public key) the Hub reads. The Hub encrypts each credential and
      each `caller_secret` to that recipient immediately and keeps no
      plaintext: `mcp-credentials.json` holds `{instance, companion, user,
      id, minted_at, age_ciphertext}` entries. The Hub can replace or
      delete an entry but can't read one back. The hook's stdout is never
      logged, put in an op record or audited (redact, then clip).
    - **Revoked.** Deleting an entry stops its use at the gate's next
      reload (seconds). The Hub then runs the `revoke` hook with
      `{"action": "revoke", "user", "ids": [...]}`; a failure keeps the
      entry as `revoking` (the gate already refuses it), retries on every
      reconcile and shows on the AI tab. `{"action": "revoke_all",
      "prefix": "portcullis-ai-"}` is used when AI support goes off, after
      a restore (call 29) and on a mode change.
    - Audited `ai.credential.mint` / `ai.credential.revoke` (instance,
      companion, person, app-side id; never the credential).
14. **Who may use a companion, and what happens when someone leaves.**
    - There is **no separate AI group**: everyone who can use the app can
      use it through AI. The approved playback gives a "Connect your AI"
      card to every person who can access an app with AI support on, and
      the accepted model is "only apps they can access, their own rights in
      each app". An admin who wants fewer people on AI keeps the companion
      read-only or AI support off.
    - A companion's **population** is the instance's settings population
      (settings spec call 27): the access group's members minus expired
      entries, everyone when group access is off, nobody for `sign_in:
      native` instances (no identity) — and the instance must be enabled.
    - The Hub writes the populations into `mcp-gate.json` on every
      `WritePolicy`, so a membership change reaches the gate as fast as it
      reaches group-gate. The gate checks the population on **every**
      request, so a person who leaves is refused from the next request,
      without waiting for token expiry.
    - On leaving (rule evaluator, admin removal, expiry, user delete,
      group delete, instance disabled or deleted, AI support off) the Hub
      also: revokes that person's credentials for the instance (call 13);
      for `app_oauth` companions runs the `revoke` hook; and, when the
      person can no longer use **any** AI resource, deletes their consents
      and offline sessions for the AI clients (Keycloak admin API). The
      existing sign-out on group removal (contract §4) already sets the
      person's not-before, which every refresh checks, offline tokens
      included.
15. **The admin's per-app switch, modes and companion lifecycle.**
    - Hub → Apps → instance → **AI support** tab (admins only): the
      switch per companion, the mode (when the template offers both), the
      companion's official/community label and source, status (running,
      health, last error), the population count, active credentials and
      connections, the tools the template marks `confirm` and `never`,
      and recent AI activity on this instance (call 19).
    - Switching on: the Hub creates the scope (call 7), adds the
      companion to `mcp-gate.json`, renders the override (companion
      `scale: 1`, its `portcullis-proxy` alias, the `portcullis-mcp-…`
      router), and starts it (`compose up` of the instance, which
      recreates only changed services), then runs `on_change`. Refused
      (`409`) while the instance is `deleting`/`restoring`, for mTLS
      policies (call 8), and when the global AI switch is off (call 28).
    - Switching off reverses it: router and scope removed, `scale: 0`,
      `revoke_all`, entries deleted. A mode change re-mints lazily
      (`revoke_all` first), because the app-side scopes of a credential
      encode the mode.
    - Audited `ai.enable`, `ai.disable`, `ai.mode` (instance, companion,
      before → after). Delegates have no access.
16. **Tool-level authorization at the gate.**
    - The gate knows each companion's tool classes from `mcp-gate.json`
      (the template's `writes`, `confirm`, `never`, plus the admin's
      mode). For every `tools/list` it removes `never` tools, and in
      read-only mode every `writes` tool; for every `tools/call` it
      refuses those (JSON-RPC error, logged) and starts a confirmation
      for `confirm` tools (call 17). Read-only is enforced twice: by the
      gate and by the companion's own read-only flag / the credential's
      scopes.
    - Tool annotations from the companion (`destructiveHint`,
      `readOnlyHint`) are hints only; the gate never relaxes a template
      rule because of them. It may add a `confirm` for a tool annotated
      destructive that the template forgot (logged as a template
      warning), never remove one.
    - Server-to-client requests from companions: **sampling** and
      **roots** requests are declined by the gate (a companion must not
      drive the person's model or see their files); **form elicitation**
      passes through; **URL elicitation** passes only when the URL's host
      is the companion's own instance host or a core host, otherwise it
      is declined and logged.
    - Sessions of 2025-xx companions (`Mcp-Session-Id`) are bound to the
      person: the gate hands clients its own opaque session ids mapped to
      (person, resource, upstream id), so one person can't use another's
      session.
17. **Confirmations for app companions.** Same page and rules as call 2,
    on `people.<domain>/confirm/<id>`, created by the gate through the
    Hub's internal API (`POST /internal/confirmations {user, resource,
    tool, args_digest, args_preview}`), checked and consumed on the retry.
    The page shows the app, the tool and the arguments as JSON (clipped,
    escaped), and the typed check is the app's name. Rate-limited (call
    18). Audited `ai.confirm` (approved/declined/expired; no arguments,
    only the digest).
18. **Rate limits** (defaults, editable in Hub Settings → AI; per person,
    not per IP, because Claude desktop traffic comes from one Anthropic
    range):
    - 120 requests per minute per person and resource (burst 30), 600 per
      minute per person across all resources;
    - 60 `tools/call` per minute per person and resource;
    - 10 confirmations started per person per hour; 10 mint requests per
      person per minute;
    - aggregate fan-out at most 4 upstream calls in parallel per request;
    - request bodies ≤ 8 MiB, tool results passed through ≤ 16 MiB;
      upstream timeout 120 s.

    Over the limit: HTTP `429` with `Retry-After` (not 401/403). Core's
    `rate-limit@file` stays in front as the per-IP backstop.
19. **The access log ("via AI" for apps).** The gate appends one JSON line
    per MCP request to `mcp_gate_data/access.jsonl`: time, person, `azp`,
    resource, instance, companion, method, tool name, SHA-256 of the
    arguments, decision (`allow`, `deny:<reason>`, `confirm:<id>`,
    `rate_limited`), upstream status, duration. Never the arguments, the
    result, a token or a credential. The Hub reads it (read-only mount)
    for the AI tab, the admin's audit view (merged with `audit.jsonl`,
    filtered by `via: ai`) and the person's own "Recent AI activity" on
    the People page (their lines only). Retention: 90 days (the sign-in
    history's default), pruned by the gate.
20. **Prompt injection: what limits the damage.** Content the AI reads
    (issues, documents, dashboards, chat messages, entity names) can
    instruct it. The design doesn't try to detect that; it limits what
    such instructions can achieve:
    - the AI has exactly the person's rights in each app and nothing in
      apps they can't use (calls 12, 14);
    - destructive tools need the person's passkey in their browser (calls
      2, 17); `never` tools don't exist for the AI;
    - admins can make any companion read-only (call 15);
    - Portcullis admin tools are only on `hub.<domain>/mcp`, a separate
      connector the admin adds deliberately, never in the aggregate or
      the AI page, so data from an app can't reach admin tools in the
      same conversation unless the admin connected both;
    - secrets never enter the model's context (call 26), so injected text
      can't exfiltrate them;
    - companions can't redirect the person to arbitrary URLs or use the
      person's model (call 16);
    - every call is logged with tool and argument digest (call 19);
    - the People card tells people that what the AI reads is sent to the
      AI provider they use, and Claude's own controls apply (per-tool
      "Blocked", approval prompts).

    Residual: within a person's rights and outside the `confirm` lists, an
    injected instruction can still make writes (e.g. comment on an issue,
    create a task). That is the read-write mode the admin chose. The
    aggregate and the AI page apply the **same** per-app mode as the per-app
    endpoints, not a stricter default: the person accepted "their own rights
    in each app" and "one setup covers everything", which a read-only
    aggregate (writes only on per-app connectors) would break. The admin's
    lever is the per-app read-only mode; the person's lever is Claude's
    per-tool "Blocked" and approval prompts.
21. **The "all my apps" endpoint.**
    - Resource `https://mcp.<domain>/mcp`, scope `mcp:all`, served by the
      gate itself (an MCP server built on the Go SDK that is a client of
      each upstream).
    - `tools/list` for a person = the union, over enabled companions with
      `aggregate: true` whose population includes them, of the tools the
      per-app endpoint would show them (same filtering, call 16), plus the
      people-scope Portcullis tools. Tool names are
      `<instance-id>__<tool>` (`gitea__list_issues`,
      `grafana-team-a__search_dashboards`, `portcullis__my_apps`); names
      over 64 characters (Anthropic's tool-name limit, also Open WebUI's)
      are shortened with a stable 8-character hash suffix. Descriptions
      are prefixed with the app's label and host ("[Gitea ·
      gitea.example.com] …"). Resources and prompts get the same prefix.
    - Calls are routed to the upstream with the person's identity exactly
      as on the per-app route (lazy minting included), and every rule of
      calls 6–19 applies per upstream: an aggregate call to Gitea is
      logged as resource Gitea with `via` the aggregate.
    - The per-person list is cached 60 s and invalidated on population or
      AI configuration changes; with `subscriptions/listen` the gate sends
      `notifications/tools/list_changed` when it changes.
    - An upstream that is down drops out of the list with a one-line
      notice in the server's `instructions`; it never fails the whole
      endpoint.
    - `app_oauth` companions are never in the aggregate (the gate holds
      no credential for them); the People card lists them separately.
22. **The People page.**
    - `GET /api/me/apps` (settings spec call 15) gains an `ai` object per
      instance with AI support on and the caller in the population:
      `{"companions": [{"name", "label", "url", "identity_mode",
      "mode", "official"}]}`; and a top-level `ai` object: `{"aggregate_url",
      "clients": {"claude": {"client_id"}, "claude_code": {"client_id",
      "callback_port"}, "generic": {"client_id", "redirect_uris"}},
      "admin_url"` (only for admins)`}`. Nothing for instances the caller
      can't use.
    - New people-listener routes (contract §5.1, the allowlist test):
      `GET /api/me/ai` (the caller's AI connections: per AI client, when
      consented, last used, offline session expiry; and their last 50
      access-log lines), `DELETE /api/me/ai/connections/{client}`
      (revokes the caller's consent and offline sessions for that
      client; audited `ai.connection.revoke`), `GET /confirm/{id}` and
      `POST /api/me/confirmations/{id}` (call 2). Each answers only for
      the caller.
    - The card's content per client is in the example below. Commands and
      URLs are rendered from `GET /api/me/apps`, escaped, with copy
      buttons; the connector name is the instance label, lowercased and
      reduced to `[a-z0-9-]` for the Claude Code command.
23. **The AI page: a LibreChat template, models from LiteLLM.**
    - Template `ai-chat` (`instances: multi`, default host `ai.<domain>`),
      LibreChat pinned by digest, with its MongoDB and Meilisearch
      services, native-oidc sign-in through a Keycloak client keyed on
      `preferred_username`, group access `users_ai-chat`.
    - Why LibreChat over Open WebUI: its MCP servers, OAuth clients and
      model endpoints are declared in `librechat.yaml`, which the template
      renders from Hub settings (declarative, no Hub code); Open WebUI
      adds MCP servers only through the admin UI and its OAuth tools can't
      be model defaults. The builder may switch to Open WebUI if its
      declarative configuration covers the same, with the same contract.
    - It declares a second Keycloak client entry with `ai_client: true`
      (new manifest flag): confidential, redirect
      `https://{{HOST_AI}}/api/mcp/portcullis/oauth/callback`, which the
      Hub treats as an AI client (call 3: consent, ACR, `mcp:all` optional
      scope, nothing else). `librechat.yaml` has exactly one MCP server,
      `portcullis` = `https://mcp.<domain>/mcp`, `type: streamable-http`,
      `oauth` with that client and `scope: mcp:all`, `oauthPrompt:
      on_start`. Each person connects once (consent), then it is silent
      while their Keycloak session or offline session lasts.
    - Models: settings `litellm_url` (`string`, `format: url`) and
      `litellm_key` (`secret`; a LiteLLM virtual key the admin creates in
      LiteLLM with the models and budget they want) render a custom
      OpenAI-compatible endpoint. LibreChat sends the person's id as
      `user`, so LiteLLM's spend tracking is per person.
    - The page shows, under the model picker, the provider LiteLLM routes
      the chosen model to (from the model name; the admin's choice), so
      people know where their app data goes.
24. **The Portcullis MCP in the Hub.**
    - A third listener, `HUB_MCP_ADDR` (`:8890`), reachable only on the
      `portcullis` network (no Traefik router points at it). It requires
      `X-Portcullis-MCP-Secret` = `HUB_MCP_GATE_SECRET` (a file secret ≥ 32
      chars from `portcullis init`, shared only with `mcp-gate`; constant
      time, like `ProxySecret`), and serves only `/mcp/admin`,
      `/mcp/people` and `/internal/*` (credentials, confirmations).
      `/healthz` as today.
    - The gate forwards with `X-Forwarded-User` (the validated
      `preferred_username`), `X-Portcullis-AI-Client` (`azp`) and
      `X-Portcullis-AI-Resource`; the Hub trusts them only on this
      listener. No CSRF guard there (no browser can reach it), strict
      JSON-RPC bodies.
    - Built on the official MCP Go SDK server (Streamable HTTP, stateless,
      2026-07-28 with 2025-11-25 fallback). Each tool is a thin adapter
      that resolves the `directory.Caller` with `CallerFor` and calls the
      **same Hub / directory methods** the HTTP handlers call (not HTTP
      loopback), so authorization, guardrails, locks, errors and audit are
      identical. A tool's annotations (`readOnlyHint`, `destructiveHint`,
      `idempotentHint`) follow the tables in call 25.
    - `/mcp/admin` answers only admins (`Caller.Admin`, re-checked per
      mutation by `gate`). `/mcp/people` answers anyone, with exactly the
      people listener's view (`OverviewFor(caller)`, `/api/me/*`), and
      delegated operations only through the delegate's permissions.
    - The Hub also exposes MCP **resources** read-only: the docs pages it
      ships with (contract, operations guides, as `portcullis://docs/…`),
      each loaded template's manifest (`portcullis://templates/<id>`), and
      the doctor's check catalogue; plus **prompts**: "Diagnose this app",
      "Set up an app for a team", "Why can't <person> open <app>?".
25. **The Portcullis MCP tool surface.** It mirrors the Hub API. Classes:
    **R** read, **W** write (audited), **D** destructive (call 2), **U**
    needs a secret from the person, done by URL elicitation (call 26).

    Admin (`hub.<domain>/mcp`):

    | Area | Tools |
    |---|---|
    | Overview | `hub_status` R (status, drift summary, doctor summary, versions), `explain_policy` R (effective policy and score of an instance, why) |
    | Catalog and sources | `list_templates` R, `get_template` R (manifest, settings definition, AI block), `list_sources` R, `sync_sources` W, `add_source` W, `remove_source` D |
    | Instances | `list_instances` R, `get_instance` R (state, hosts, groups, clients, policy, sign-in mode, public access, last op, newest backup, AI), `instance_defaults` R, `create_instance` W, `enable_instance` W, `disable_instance` W, `restart_instance` W, `set_hosts` W, `get_op` R, `wait_for_op` R (polls until done or 60 s), `delete_instance` D |
    | Settings | `get_settings` R (secrets as `{set, updated_at}`), `preview_settings` R (who gets what, effect, restart), `save_settings` W (requires the preview's plan hash), `set_secret_setting` U, `set_policy` W, `set_sign_in_mode` W, `set_public_access` W |
    | Logs and runtime | `get_logs` R (tail ≤ 500 lines, the op-record redaction applied), `get_status` R, `exec` D, `get_compose` R, `get_env` R (secret-looking values redacted), `save_env` D, `get_custom_override` R, `save_custom_override` D |
    | Drift | `list_drift` R, `resolve_drift` D |
    | Backups | `list_backups` R, `backup_instance` W, `restore_instance` D, `restore_as` W |
    | Domains | `list_domains` R, `enroll_domain` U (the DNS token is entered on the Hub's page, never in the chat), `replace_domain_token` U, `delete_domain` D |
    | Users and groups | `directory_overview` R, `get_person` R, `create_person` W (invite by email; the link is never returned), `update_person` W, `set_details` W, `require_passkey` D, `remove_passkeys` D, `set_password` U, `delete_person` D, `create_group` W, `delete_group` D, `add_member` W, `remove_member` W, `set_member_expiry` W, `set_group_rule` W, `preview_rule` R, `add_exception` W, `remove_exception` W, `convert_group` W (preview + apply), `create_field` W, `update_field` W, `delete_field` D, `set_permission` W, `import_review` R, `import_apply` W, `audit_recent` R |
    | Doctor and folders (project 2) | `doctor_findings` R, `doctor_scan` W, `doctor_preview_fix` R, `doctor_apply_fix` W (D when the plan touches data), `doctor_mute` W, `list_folders` R, `folder_preview` R, `folder_apply` W |
    | Certificates (certificates spec) | `list_certificates` R, `revoke_certificate` D, `sign_in_history` R |
    | AI | `ai_status` R, `set_ai_support` W, `set_ai_mode` W, `revoke_ai_access` D (one person or everyone, one instance), `ai_activity` R |
    | Hub settings | `get_hub_settings` R, `save_hub_settings` W (AI settings included; turning the Portcullis admin MCP off is allowed, turning it on from MCP is not, since it would already be on) |

    People (`people.<domain>/mcp`, also in the aggregate as
    `portcullis__…`):

    | Tools |
    |---|
    | `my_apps` R (= `GET /api/me/apps`), `my_profile` R, `directory` R (`OverviewFor`: what the People page shows), `my_certificates` R, `my_sign_ins` R, `my_ai_connections` R, `disconnect_ai` W (own connections), `my_file_share_password` U (project 3: generated on the People page after a fresh touch; the tool only returns the link), delegates only: `update_person` W (`edit_details`), `invite_person` W (`invite`), `delete_person` D (`remove`) |

    Exactly the people listener's limits apply: no app, settings, policy,
    drift or template tool, and nothing about apps the caller can't use.
    "Fully featured" is honoured on the admin side: everything the admin
    UI can do is a tool. The riskiest ones (`exec`, `save_env`,
    `save_custom_override`, `resolve_drift`) are in, as **D**, so each use
    needs the admin's passkey in their browser; they are never batched.
26. **Secrets never pass through the model.**
    - Inputs: a tool that needs a secret (DNS token, secret setting value,
      a password) doesn't take it as an argument. It returns a URL-mode
      elicitation (or the same link as text) to the Hub's existing form
      for it, pre-filled with the non-secret context; the admin types the
      secret there. The tool's schema has no field for it, and the Hub
      refuses tool arguments whose names look like secrets (`*token*`,
      `*password*`, `*secret*`, `*key*`) on those tools.
    - Outputs: every tool result goes through the same rules as the API
      (secret settings as `{set, updated_at}`, credentials never echoed,
      env and logs redacted, then clipped) plus: no invite links, no
      file-share passwords, no share tokens (public access shows `listed`
      tokens as `•••` with their path), no `HUB_*` secret.
27. **Long operations.** Tools whose HTTP twin answers `202` return
    `{op_id, op, instance, poll}` immediately, plus progress notifications
    on the request's SSE stream when the client asked for a stream; the
    model calls `wait_for_op` / `get_op` to see the outcome. Busy instances
    are `isError` results with the `409` reason, not protocol errors.
28. **Hub Settings → AI (admins).**
    - Master switch "AI support" (off on a new install). Off: the gate
      refuses everything (`503` with "AI support is off on this
      Portcullis"), per-app switches are greyed out, People cards hidden.
    - Clients offered: Claude (hosted), Claude Code, other MCP clients
      (each creates or removes its Keycloak client).
    - Portcullis MCP: for admins on/off (default on when the master switch
      is on), for people on/off (default on).
    - Connection length (call 9), rate limits (call 18), allowed origins
      (call 6).
    - A reachability note: "Claude desktop and claude.ai connect from
      Anthropic's servers (160.79.104.0/21): `auth.<domain>` and every app
      host must be reachable from the internet."
    - Audited `settings.ai`.
29. **Instances, backups, restore, delete** (contract §11).
    - AI configuration (switch, mode per companion) is per instance, in
      `state.yaml`, and part of an instance backup like its settings.
      Credentials are **not** in backups: they live in the Hub's data,
      encrypted to the gate, and are re-minted lazily.
    - A same-instance restore and a restore into a new id run
      `revoke_all` in the restored app before AI traffic is allowed again
      (the restored app database may hold credentials the gate no longer
      knows). A restore into a new id starts with AI support **off**.
    - Delete: step 4 also removes the instance's `mcp:*` scopes; step 6
      its credential entries and AI state (the app's tokens die with its
      volumes).
    - The default instance and other instances get distinct resources
      (their own hosts) and scopes (`mcp:<instance-id>.<companion>`).
30. **Contract changes (integration-contracts.md first).**
    - §3 / §3.1: the `ai:` block, reserved variables, reserved names
      (`portcullis-mcp-*` routers and aliases), the `scale: 0` rule for
      companion services, `ai_client` on `keycloak_clients[]`. Template
      contract v3 (with the settings spec's §13).
    - §4: `mcp` is a core host. `mcp-gate.json` (format, fail-closed
      rules) next to the policy file; `mcp-credentials.json`.
    - §5: the `portcullis-mcp-…` router, MCP routes on `hub`, `people`,
      `mcp`; the rule that MCP routes carry no forward-auth and browser
      routes accept no bearer tokens.
    - §5.1: the new people-listener routes (call 22).
    - §8: AI clients, `mcp:*` scopes, audience mappers, consent,
      offline-session settings; the Hub attaches `mcp:*` nowhere else.
    - §9.5: `via` and `client` in audit entries; the new actions
      (`ai.enable`, `ai.disable`, `ai.mode`, `ai.credential.mint`,
      `ai.credential.revoke`, `ai.connection.revoke`, `ai.confirm`,
      `settings.ai`).
    - §11: AI state per instance, backups without credentials, restore and
      delete steps above.
    - New section "AI support (MCP)" (numbered when written, after the
      sections projects 1–3 add): resources, token rules (call 6), identity
      modes and hook stdin/stdout formats, confirmation semantics, the
      gate ⇄ Hub internal API, the access-log format.
31. **Companion conversions and pilots.**

    | Template | Companion | Mode | Notes |
    |---|---|---|---|
    | gitea | `gitea-mcp` (official) | `app_token`, `token {credential}`, minted with `gitea admin user generate-access-token --raw` (read: `read:*` scopes; read-write: `write:*`), revoked through the API | **Pilot 1.** `confirm: [delete_*, "*:delete"]` per its consolidated `method` tools (builder maps names), read-only via `GITEA_READONLY` too |
    | grafana | `mcp-grafana` (Grafana) | `identity_headers` + `caller_secret` (`--server-auth-token`), `GRAFANA_FORWARD_HEADERS=X-Forwarded-User` | **Pilot 2.** `--disable-write` in read-only; never `--allow-grafana-url-override`; `confirm` on delete tools |
    | homeassistant | built-in MCP Server | `app_oauth` | **Pilot 3.** `on_change` hook turns the integration on/off and its "administrators only" option off; `revoke` hook per person |
    | mattermost | built-in (agents plugin) | `app_token` (personal access token via `mmctl`) | after the pilots, if the plugin is in the template |
    | nextcloud | `nextcloud-mcp-server` (community) | `app_token`, Basic with an app password (`occ user:auth-tokens:add`) | after the pilots |
    | gitlab | built-in | builder verifies tier and auth first | later |
    | paperless, immich, vikunja, jellyfin, firefly-iii | community only, small or stale | — | no `ai:` block until a maintained companion exists |
    | ai-chat (new) | — | AI client | call 23 |

    Community companions are allowed only pinned by digest, with
    `upstream: community` shown to the admin.
32. **Testing.**
    - Unit: token validation matrix (wrong `aud`, two MCP audiences, wrong
      `azp`, expired, `none` alg, unknown `kid`, low `acr`, person not in
      population, expiring entry, `Origin`), header/body mismatch, tool
      filtering per mode, confirmation binding (argument change, reuse,
      expiry, other person), rate limits, credential file encryption
      (Hub can't decrypt), aggregate naming and truncation, redaction of
      tool outputs.
    - Hub: every MCP tool runs through `CallerFor` + the same method as
      its HTTP twin (a test reflects over the tool table and the handler
      list, like `TestProtectedAccountsParity`); non-admins get no admin
      tool; `TestPeopleListenerHasNoAppRoutes` gains exactly the call-22
      routes; audit entries carry `via` and `client`.
    - e2e (CI, real Keycloak 26.8.1, Traefik, gate): an MCP client
      (Go SDK) signs in with PKCE against `portcullis-ai-claude-code`,
      lists and calls Gitea tools as alice and sees only alice's repos;
      removing alice from `users_gitea` fails her next call and revokes
      her Gitea token; a Gitea token is refused at Grafana's resource and
      the aggregate; a bearer MCP token gets no page on
      `gitea.<domain>/`; a destructive Portcullis tool returns a
      confirmation, the browser page with a WebAuthn virtual
      authenticator approves it, the retry succeeds once; the aggregate
      lists Gitea and Grafana tools for a member of both and only Gitea's
      for a member of one.
    - Manual (documented checklist): Claude desktop custom connector with
      "Use your own OAuth client", Claude Code `claude mcp add` +
      `/mcp`, the AI page.

### Builder-check rulings

Questions a builder raised on the draft, settled without changing what
gets built. All are **Controller's call**.

33. **Connection lifetime.** *(Controller's call; was open question 1.)*
    The draft defaults stand: offline session idle 7 days, max 30 days,
    access tokens 5 minutes, rotating refresh tokens. They are defaults of
    the admin-editable "Connection length" in Hub Settings → AI (call 28),
    bounded to idle 1–30 days and max 1–90 days, so an admin who wants
    shorter or longer sets it there; nothing else in the design depends on
    the value.
34. **Hook `when: ai`.** The settings spec's `when` list (`start`,
    `settings_change`, `membership_change`) gains `ai`: a hook marked
    `ai` runs only when the AI machinery calls it (`mint`, `revoke`,
    `revoke_all`, `on_change`), never on the settings triggers, and the
    validator requires it for every hook an `ai:` block names. These hooks
    get the AI stdin of calls 13/11 instead of the settings spec's full
    desired state. Their **stdout is never stored**: on success it is
    parsed and dropped; on failure the op record and the AI tab get the
    exit code and the redacted, clipped stderr only.
35. **Identity headers without groups in the token.** MCP tokens carry no
    group or attribute claims (call 7) and the gate has no LLDAP access, so
    for `identity_headers` companions the Hub writes, per population
    member, the email and the groups group-gate would forward
    (`X-Auth-Request-Groups`, same filtering) into `mcp-gate.json` on every
    `WritePolicy`; the gate reads attribute headers from the existing
    `user-attributes.json` (contract §4.1), the same file group-gate
    reads. A person missing from either file gets no header for it, never
    a stale one.
36. **`app_oauth` companions are outside the gate's guarantees, and say
    so.** For Home Assistant the gate isn't in the path, so the gate's
    per-request population check, tool filtering, confirmations, rate
    limits and access log don't apply; the app enforces its own rules
    (Home Assistant: only Assist-exposed entities, the person's own
    account). What still holds: sign-in through Keycloak (auth_oidc, with
    the client's access role), revocation on leaving through the `revoke`
    hook at the next reconcile (call 14), AI support off turns the
    integration off. The AI tab and the People card state this ("Home
    Assistant applies its own rules; Portcullis doesn't log or confirm
    its AI actions"), and the template validator requires `modes:
    [read_write]` only for `app_oauth` (no read-only mode it can't
    enforce).
37. **Minting for a person with no app account yet.** The `mint` hook
    never creates accounts. If the person has never signed in to the app
    it exits with code 3 and the gate answers a JSON-RPC error "Open Gitea
    (https://gitea.example.com) in your browser once, then try again";
    the next request retries the mint (the 10/min limit applies). Other
    non-zero codes are failures shown on the AI tab.
38. **Client protocol versions.** The gate and the Hub's MCP listener
    accept every revision the Go SDK supports from 2025-06-18 on (the first
    with RFC 8707 resource indicators and RFC 9728 metadata), i.e.
    2025-06-18, 2025-11-25 and 2026-07-28; older versions get `400`
    "unsupported protocol version". Toward companions the gate speaks what
    each declares in `protocol` (newest common).
39. **Sign-in strength on the aggregate.** The `mcp:all` resource itself
    needs `hwk`. Each upstream keeps its own minimum (call 8): an upstream
    whose LoA the token's `acr` doesn't meet is left out of that person's
    `tools/list` and refuses calls, like an upstream they can't use.
40. **The hosted Claude client is public.** The People card's "leave the
    client secret empty" is the design. The builder verifies on the manual
    checklist that Claude's "Use your own OAuth client" completes with a
    public client and PKCE; if it requires a secret, `portcullis-ai-claude`
    becomes confidential with a Hub-generated secret shown on the card,
    documented as not a secret (every person sees it); the gate and
    scopes don't change.
41. **One hosted Claude client for all connectors.** Every connector a
    person adds in Claude uses `portcullis-ai-claude`, so "Disconnect" on
    the People page (per client) ends all of that person's Claude
    connectors at once; the card says so. Per-connector revocation is
    Claude's own "Remove" (or `claude mcp logout`).

## Example: template declaration (Gitea, abridged)

```yaml
# gitea/manifest.yaml (excerpt)
ai:
  on_change: ai-apply              # optional; here the env variables suffice
  companions:
    - name: gitea
      label: Gitea
      kind: companion
      service: gitea-mcp
      port: 8080
      path: /mcp
      router: gitea                # https://gitea.example.com/mcp
      public_path: /mcp
      upstream: official
      source: https://gitea.com/gitea/gitea-mcp
      protocol: ["2026-07-28", "2025-11-25"]
      modes: [read_only, read_write]
      default_mode: read_write
      identity:
        mode: app_token
        header: Authorization
        format: "token {credential}"
        mint: mcp-mint             # hook names (settings spec §13 hooks)
        revoke: mcp-revoke
        scopes:
          read_only:  [read:repository, read:issue, read:user, read:organization, read:notification]
          read_write: [write:repository, write:issue, read:user, read:organization, write:notification]
      tools:
        writes:  ["*_write", create_*, update_*, merge_*, delete_*]
        confirm: [delete_*, "repo_write:delete"]   # consolidated tools: tool:method
        never:   []
hooks:
  - name: mcp-mint                 # stdin: {"action":"mint","user","name","scopes",...}
    service: gitea                 # stdout: {"credential":"…","id":"…"}  (never logged)
    command: [/portcullis/mcp-token.sh, mint]
    when: [ai]
    timeout: 30s
  - name: mcp-revoke               # stdin: {"action":"revoke","user","ids":[…]} or revoke_all
    service: gitea
    command: [/portcullis/mcp-token.sh, revoke]
    when: [ai]
    timeout: 60s
```

```yaml
# gitea/compose.yml (excerpt)
services:
  gitea-mcp:
    image: docker.gitea.com/gitea-mcp-server:1.12.0@sha256:<digest>
    command: ["-t", "http", "--port", "8080", "-H", "http://gitea:3000"]
    environment:
      GITEA_READONLY: ${PORTCULLIS_AI_READONLY_GITEA:-true}
    read_only: true
    tmpfs: [/tmp]
    networks: [default]            # the Hub's override adds portcullis-proxy + alias
    # no Traefik labels: the Hub renders portcullis-mcp-gitea_gitea → mcp-gate@docker
```

The Hub's override for the default instance with AI support on adds
(abridged):

```yaml
services:
  gitea-mcp:
    scale: 1                       # 0 while AI support is off
    networks:
      portcullis-proxy:
        aliases: [portcullis-mcp-gitea-gitea]
  gitea:
    labels:                        # merged with the template's labels (default instance)
      traefik.http.routers.portcullis-mcp-gitea_gitea.rule: Host(`gitea.example.com`) && (Path(`/mcp`) || Path(`/.well-known/oauth-protected-resource/mcp`))
      traefik.http.routers.portcullis-mcp-gitea_gitea.entrypoints: websecure
      traefik.http.routers.portcullis-mcp-gitea_gitea.tls.options: authaware@file
      traefik.http.routers.portcullis-mcp-gitea_gitea.priority: "<above every router of the instance>"
      traefik.http.routers.portcullis-mcp-gitea_gitea.service: mcp-gate@docker
      traefik.http.routers.portcullis-mcp-gitea_gitea.middlewares: rate-limit@file,security-headers@file
```

Grafana (identity headers, abridged):

```yaml
env:
  - key: MCP_GRAFANA_SERVER_TOKEN
    generate: random
ai:
  companions:
    - name: grafana
      label: Grafana
      kind: companion
      service: grafana-mcp
      port: 8000
      router: grafana
      upstream: official
      modes: [read_only, read_write]
      default_mode: read_only
      identity:
        mode: identity_headers
        caller_secret: {env: MCP_GRAFANA_SERVER_TOKEN, header: Authorization, format: "Bearer {secret}"}
      tools:
        writes: [create_*, update_*, delete_*, "*_write"]
        confirm: [delete_*]
```

Home Assistant (its own OAuth server, abridged):

```yaml
ai:
  on_change: mcp-integration       # turns HA's MCP Server integration on/off
  companions:
    - name: homeassistant
      label: Home Assistant
      kind: builtin
      service: homeassistant
      port: 8123
      path: /api/mcp
      router: homeassistant        # people connect to https://ha.example.com/api/mcp
      upstream: official
      modes: [read_write]
      identity:
        mode: app_oauth
        revoke: mcp-revoke         # ends the person's HA tokens
      aggregate: false
```

## Example: the People page card

`people.example.com` → My apps, for alice (member of `users_gitea` and
`users_grafana`, not an admin), with Claude, Claude Code and other clients
offered:

```
Connect your AI                                                     ⓘ What's this?
  Use your apps from Claude or another AI assistant, as yourself. The AI can
  see and change only what you can. What it reads is sent to the AI provider
  you use. Deleting things always asks for your passkey in this browser.

  ── All my apps ─────────────────────────────────────────────────────────────
  https://mcp.example.com/mcp                                        [ Copy ]
  Covers Gitea and Grafana (and anything added later). Home Assistant is
  connected separately (below).

  [ Claude desktop / claude.ai ]  [ Claude Code ]  [ Other MCP clients ]

  Claude desktop / claude.ai
    1. Open Claude → Customize → Connectors → Add custom connector.
       (Team or Enterprise plan: ask an Owner to add it in Organization
       settings → Connectors → Add → Custom → Web, then click Connect.)
    2. Name: Portcullis apps        URL: https://mcp.example.com/mcp  [ Copy ]
    3. Open Advanced settings (or choose "Use your own OAuth client"):
       OAuth Client ID: portcullis-ai-claude                           [ Copy ]
       Leave the client secret empty.
    4. Click Add, then Connect. Sign in with your passkey and allow access.
    Claude connects from Anthropic's servers, so this works only while
    example.com is reachable from the internet.

  Claude Code
    Paste in a terminal:
      claude mcp add --transport http --scope user \
        --client-id portcullis-ai-claude-code --callback-port 33418 \
        portcullis-apps https://mcp.example.com/mcp                    [ Copy ]
    Then start Claude Code, type /mcp, choose portcullis-apps and sign in
    with your passkey in the browser that opens.

  Other MCP clients
    Server URL: https://mcp.example.com/mcp · Transport: Streamable HTTP
    OAuth: authorization server discovered automatically (Keycloak at
    auth.example.com) · Client ID: portcullis-ai-generic · no secret ·
    PKCE S256 · redirect http://localhost:33418/callback · scope mcp:all

  ── One app only ────────────────────────────────────────────────────────────
  Gitea         https://gitea.example.com/mcp      read and write   [ Copy ] [ Steps ▾ ]
  Grafana       https://grafana.example.com/mcp    read only        [ Copy ] [ Steps ▾ ]
  Home Assistant https://ha.example.com/api/mcp    signs in with Home Assistant
                 Claude: add it as a custom connector with "Use Claude's published
                 identity"; Home Assistant asks you to sign in (passkey).   [ Steps ▾ ]

  ── Your AI connections ─────────────────────────────────────────────────────
  Claude (claude.ai)   connected 3 Nov · last used 2 min ago · until 3 Dec  [ Disconnect ]
  Recent AI activity   gitea__list_issues ✓ · grafana__search_dashboards ✓ ·
                       gitea__delete_repository ⏸ waiting for your confirmation   [ All ▾ ]
```

Apps alice can't use, and instances whose AI support is off, don't appear.
A person with no AI-enabled app sees no card.

## Example: a Portcullis MCP session

Admin `root` has added `https://hub.example.com/mcp` to Claude Code and
signed in with a passkey (token `aud` `https://hub.example.com/mcp`,
scope `mcp:portcullis.admin`, `azp` `portcullis-ai-claude-code`).

```
root: The design team says Grafana is slow and some of them can't open it.

→ get_instance {"id": "grafana"}
← state enabled · host grafana.example.com · access group users_grafana (14) ·
  policy: passkey · last op restart ok 2026-11-02T09:12Z · AI: on, read only
→ doctor_findings {"instance": "grafana"}
← 1 problem: "grafana-data volume 96 % full" · 1 warning: "3 members of
  design_team are not in users_grafana"
→ get_logs {"id": "grafana", "service": "dashboards", "lines": 200}
← … "database is locked" (×41) …

Claude: Two things. The data volume is almost full, which explains the
"database is locked" errors and the slowness. Separately, three designers
(dana, eli, fay) aren't in users_grafana. Shall I (1) add design_team's
members by making users_grafana include the group, and (2) take a backup
and then restart Grafana after you free space?

root: Add them, and back it up first.

→ preview_rule {"group": "users_grafana", "rule": "member of design_team or member of ops"}
← +3 people (dana, eli, fay), −0
→ set_group_rule {"group": "users_grafana", "rule": "member of design_team or member of ops"}
← ok · audited directory.set_rule (actor root, via ai, client portcullis-ai-claude-code)
→ backup_instance {"id": "grafana"}
← 202 {op_id: "a41f…", poll: "/api/instances/grafana/op"}
→ wait_for_op {"id": "grafana"}
← ok · archive grafana/20261102T101500Z.tar

root: That old grafana-test instance is unused, delete it.

→ delete_instance {"id": "grafana-test", "confirm": "grafana-test"}
← InputRequiredResult: elicitation/create {mode: "url",
    url: "https://hub.example.com/confirm/7Q2M-K9WX",
    message: "Deleting grafana-test needs your confirmation in your browser."}
   (Claude Code shows the full URL and asks root before opening it.)

   Browser, hub.example.com/confirm/7Q2M-K9WX:
     Delete instance grafana-test (Grafana) — requested by your AI
     (Claude Code) at 10:16. Takes a backup, then permanently removes its
     containers, volumes, Keycloak client and groups users_grafana-test,
     admin_grafana-test.
     Type the instance id: [ grafana-test ]   [ Confirm with passkey ]  [ Decline ]
   → passkey touch → "Approved. Go back to your AI."

→ delete_instance {"id": "grafana-test", "confirm": "grafana-test"}   (retry, same arguments)
← 202 {op_id: "c07d…"} · audited instance.delete (actor root, via ai,
  client portcullis-ai-claude-code, confirmation 7Q2M-K9WX)

root: And give me the Cloudflare token field for team-b.example.org.

→ enroll_domain {"name": "team-b.example.org", "provider": "cloudflare"}
← URL elicitation: https://hub.example.com/#settings/domains?enroll=team-b.example.org
   "Enter the DNS token on the Hub's page; it never passes through the chat."
```

Had root asked the same questions through the "all my apps" endpoint, none
of the admin tools would have been there: only `portcullis__my_apps` and
the other people-scope tools.

## Interfaces with the other projects

- **Core (`porelli/portcullis`).**
  - New service `mcp-gate` (Go, pinned), networks `portcullis` and
    `portcullis-proxy` at `PORTCULLIS_MCP_GATE_IP`, read-only `hub_data`
    mount, own volume `mcp_gate_data` (mounted read-only into the Hub).
  - `portcullis init`: the age key pair for credentials, `HUB_MCP_GATE_SECRET`.
  - Routers: `mcp.<domain>`, and `/mcp` + metadata on `hub` and `people`
    to `mcp-gate`. `mcp` added to core subdomains (group-gate map: `mcp=*`,
    `policy.CoreHosts`, CI lists).
  - oauth2-proxy stays bearer-blind (`skip_jwt_bearer_tokens` off; CI
    check).
  - `keycloak configure` keeps Hub-owned AI clients and `mcp:*` scopes,
    and the realm's offline-session settings the Hub sets per AI client.
  - Hub env: `HUB_MCP_ADDR`, the gate secret file, the age recipient.
- **Templates (`porelli/portcullis-templates`).** Schema and `validate.py`
  for the `ai:` block, reserved names and variables, `ai_client`; the
  conversions in call 31; the new `ai-chat` template; companion images
  pinned by digest; template docs pages show "AI support" with the
  companion and its upstream.
- **Docs (`porelli/portcullis-docs`).** The contract changes (call 30)
  first; a user guide "Connect your AI" (the card's content, with
  screenshots); an admin guide "AI support" (switches, modes, identity
  modes, what is logged, the reachability note, prompt-injection
  guidance); the template author guide for `ai:` and hooks.
- **App settings panel (project 1).** Reused: hooks with stdin and the
  `applies` levels, data files, the population rule (call 27 there),
  `GET /api/me/apps` (gains `ai`), secret handling. This project needs
  hooks with stdin from project 1; if this is built first, it builds that
  part of project 1 to project 1's spec.
- **Shared folders + doctor (project 2).** The Portcullis MCP drives the
  doctor's API (findings, preview with plan hash, apply). New doctor
  checks: AI on but companion unhealthy; AI on for an instance whose
  policy now needs mTLS; credentials stuck in `revoking`; a companion
  image older than the template's pin.
- **File sharing (project 3).** No interaction beyond the rule that
  file-share passwords never go through MCP (`my_file_share_password`
  returns the People-page link).
- **Certificates self-service.** Reused: the fresh-authentication pattern
  (its call 8) for confirmations; if this project is built first, it
  builds that component. Sign-in history shows AI sign-ins with the AI
  client's name.
- **App updates.** A template update that changes the `ai:` block or a
  companion's image shows in the update preview (new tools, changed
  `confirm` lists, identity-mode changes as a warning that re-mints
  credentials).
- **App instances and domains.** Resources follow hostnames (call 7);
  backup, restore and delete steps (call 29).

## Left to the builder

- Exact JSON shapes of `mcp-gate.json`, `mcp-credentials.json`, the
  access log and the gate ⇄ Hub internal API (within call 6/13/17/19
  rules), and the Hub admin API for AI (`GET/PUT /api/instances/{id}/ai`,
  `GET/PUT /api/ai/settings`, activity and revoke routes).
- Library picks inside the stated constraints (Go SDK version, JOSE
  library), and whether the aggregate reuses the SDK's client per
  upstream or a pooled transport.
- Keycloak verifications on 26.8.1: whether loopback redirect URIs match
  port-agnostically (then drop `--callback-port`); that requesting a scope
  a client lacks fails as expected; refresh-token rotation with offline
  tokens; the exact consent-screen rendering; per-client offline session
  limits; "Default ACR" producing `hwk` on a passkey sign-in for these
  clients.
- Grafana: how Grafana trusts `X-Forwarded-User` from the companion only
  (a pinned address on the project's own network and
  `GF_AUTH_PROXY_WHITELIST`, or another way the template author proves);
  if none works without weakening Traefik's trust, Grafana waits.
- Home Assistant: the exact revoke call (deactivate the person, or delete
  their refresh tokens) and the hook that toggles the integration and its
  admin-only option.
- Gitea: mapping consolidated tool names (`repo_write` with `method`) to
  `writes`/`confirm`; the gate matches `tool:method` for such tools.
- Port 33418 (any free port is fine; it appears in the client's redirect
  URIs and the People card).
- UI layout of the AI tab, the People card and the confirmation page
  within the existing styles; wording.
- Order of work: contract → core gate + routes → Hub (Keycloak objects,
  gate files, credentials, AI tab, People card) → Gitea pilot e2e →
  Portcullis MCP → aggregate → Grafana, Home Assistant → `ai-chat`.

## Open questions

None. The four questions of the draft were settled: connection lifetime
(call 33, a default the admin edits), certificate-only apps (call 8: no
exception, standing rule), a separate AI group (call 14: no, approved
playback), writes through "all my apps" (call 20: the same per-app mode,
accepted "one setup covers everything").
