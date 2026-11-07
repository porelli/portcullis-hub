# Authentication Policies

Portcullis lets you require either or both of two hardware-backed factors (a passkey, a client certificate) for each app, with AND or OR semantics, plus a global default. Each app enforces only what its auth method can (see [What each app can enforce](#what-each-app-can-enforce)). This page explains the model and how to use it.

## Factors

| Factor | How the user proves it | Keycloak executor | `amr` value | LoA |
|--------|------------------------|-------------------|-------------|-----|
| **WebAuthn** | Taps a hardware security key (YubiKey, platform authenticator) | `webauthn-authenticator-passwordless` | `hwk` | 2 |
| **mTLS** | Presents a client certificate over TLS (PIV / YubiKey cert) | `auth-x509-client-username-form` | `mtls` | 3 |

LoA = Level of Authentication, a number Keycloak uses for step-up. Every
sign-in is a passkey or a client cert and reaches LoA 2 in one touch
(oauth2-proxy asks for `hwk` by default); LoA 3 needs the cert. First passkeys
come from one-time setup links (`./portcullis invite`, the Hub's Users & Groups).

!!! note "There is no password factor"
    The realm's browser flow has no password: its LoA 1 (`pwd`) subflow is a
    client cert or a passkey, the same as LoA 2. The Hub never offers or
    writes `password`, and its API refuses it (`400`). A stored policy that
    still names it is normalised when the Hub loads `state.yaml`, never into
    something weaker: in an `all` policy it is redundant and dropped; as an
    alternative (`any`, or alone) it accepted every session, so it becomes
    `any of [mtls, webauthn]`. The app's settings (or the Settings tab) show
    a note until the policy is saved. group-gate still parses `password`
    (met by every `hwk`/`mtls` session) but the Hub no longer publishes it.

## Policy model

A policy has two parts:

1. **Factors** — zero or more of `mtls`, `webauthn`.
2. **Op** — `any` (any selected factor satisfies the policy) or `all` (every selected factor must have fired in the current session).

Special cases:

- Zero factors → **public** (no authentication required).
- One factor → the single factor is required; `op` is ignored.

Examples:

| Policy | Meaning |
|--------|---------|
| `{factors: [], op: ""}` | Public |
| `{factors: ["webauthn"]}` | A passkey |
| `{factors: ["mtls", "webauthn"], op: "any"}` | Either mTLS **or** WebAuthn |
| `{factors: ["mtls", "webauthn"], op: "all"}` | mTLS **and** WebAuthn (both must fire) |

## Configuring policies

### In the Hub UI

**Per-app** — open an app in the catalog and use the *Access policy* block above the settings form:

- Every app starts with *Inherit global default* ticked. While it inherits, the factor boxes are disabled and show the app's **effective** policy: the global default intersected with what the app can enforce, with a note when the two differ (e.g. "The global default allows mTLS or WebAuthn; this app can't enforce WebAuthn, so it enforces mTLS").
- Untick *Inherit* to set an override. Only factors the app can enforce are selectable; the others are greyed out ("this app can't enforce it"), and the Hub refuses them with a `400` too.
- If two or more are ticked, pick *Require all checked* (AND) or *Any of checked* (OR).
- Apps that handle their own sign-in (`custom`, `public`, or an app switched to its own login only) show the block disabled: "This app handles its own sign-in".

**Global default** — the *Settings* tab exposes the default policy that every app without an override uses. Changing it affects all apps whose per-app policy is unset.

!!! note "Fresh installs require a YubiKey"
    Until an admin saves a global default, the Hub uses
    **`any of [mtls, webauthn]`** (`{"factors": ["mtls", "webauthn"], "op": "any"}`).
    Every app without its own policy then requires the YubiKey, by either
    method: its client certificate (`mtls`, LoA 3) or a passkey (`webauthn`,
    LoA 2).

    - Routers get `authaware@file`: the certificate is optional at the
      handshake.
    - Keycloak steps up to at least LoA 2 (`hwk`).
    - group-gate accepts `mtls` or `hwk` in `amr`, so a certificate sign-in
      passes too (including `enroll.<domain>/self` renewal).
    - A password-only session gets the step-up page.

    A WebAuthn-only default would send certificate users to the step-up page
    on every app. An explicitly saved public default is stored and honoured.
    It is not the same as "never set".

The **safety score** next to each policy is a cosmetic sum: 0 for public, LoA for a single factor, LoA + 0.5 per extra required factor for AND policies.

## What each app can enforce

| Auth method | Factors | Where |
|-------------|---------|-------|
| `forward-auth`, `header-auth`, `custom` behind Portcullis sign-in | `mtls`, `webauthn` | group-gate, on every request; a certificate is bound to the user ([mTLS binding](#mtls-binding)) |
| `native-oidc` | `mtls`, `webauthn` | Keycloak, when the user signs in to the app (`acr` of its client). mTLS is checked per connection only when the policy selects the `protected@file` tier (mTLS alone, or `all` including it) |
| `mtls` | `mtls` | The TLS handshake (`protected@file`), always: the certificate stays required even under a public or WebAuthn-only default, and an override can only be `[mtls]` |
| `custom`, `public`, own login only | none | The app handles its own sign-in; no policy, tier `public@file` |

The **effective policy** is the configured one (override or global default)
with the unsupported factors left out. For `any` that removes an alternative;
for `all` it removes a requirement the app can't check, which the app's
settings say. If nothing of the configured policy is enforceable (a
WebAuthn-only default on an mTLS-only app), the app's own floor applies (the
certificate) and the settings say so. The TLS tier and the Keycloak `acr`
come from the effective policy. The policy file is unchanged: overrides are
published as stored (they only name supported factors), inheriting apps
publish nothing.

## Apps with their own login

A `custom` template whose app has its own login and no SSO declares
[`auth.native_login`](../guides/manifest-reference.md#authnative_login). Its
settings then have a **Sign-in** choice:

- **Portcullis sign-in, then the app's own login** (default). The Hub's
  override puts `portcullis-auth@docker,portcullis-groups@docker` in front of
  every router's own middlewares; group-gate requires the template's
  `access_group` and the policy applies per request, as for `forward-auth`.
- **App's own login only (no Portcullis)**, only if the template sets
  `allow_without_gateway: true`. The routers keep the template's middlewares
  without the gateway pair, the tier is `public@file` and no group is
  published: anyone on the internet reaches the app's login page. The UI
  shows a red warning, the switch is audited (`app.sign_in`) and the Hub logs
  it.

The template is never edited; both modes are compose-override labels, which
the drift check compares with the running containers. If a template stops
allowing the own-login-only mode, the Hub falls back to Portcullis sign-in.

## What happens when a user hits an app

### Same-LoA SSO (no step-up)

User signs in to Grafana with a passkey (policy: `any of [mtls, webauthn]`, session `acr=hwk`). Opens Immich (policy: `webauthn`). The Keycloak session already satisfies the required LoA, so Immich gets a token with no further prompt. Same for any other apps with policies their session already satisfies.

### Step-up on a stricter app

User signed in with a passkey (`amr=[hwk]`, LoA 2). Opens Jellyfin with policy `mtls-required`. Keycloak sees the session's current LoA is 2, but Jellyfin's client requested `acr_values=mtls` (LoA 3). The `Condition - Level of Authentication` executor in the universal flow fires only the mTLS subflow — the certificate is asked for, nothing else. On success the session's LoA is upgraded to 3 and `amr` becomes `[hwk, mtls]`. No full re-login.

### Step-up on forward-auth apps

oauth2-proxy ≥ 7.10 accepts per-request `acr_values` via the `loginURLParameters` alpha-config setting, which is what Portcullis runs (allowed values `pwd`, `hwk`, `mtls`; default `hwk`; `kc_idp_hint=portcullis-invite` and `prompt=login` exist only for setup links). When `group-gate` detects a session that doesn't satisfy the app's policy, it returns a 403 "Additional authentication required" page with the URL in an `X-Stepup-URL` header: `https://auth.<domain>/oauth2/start?acr_values=<needed>&rd=https://<app>/`. The step-up always goes through `auth.<domain>`; there is no `/oauth2/` router on app hosts. There is no sign-out and no `prompt=login`: Keycloak's cookie authenticator runs the flow when the requested LoA is above the session's and asks only for the missing level. The new token reflects the step-up. When the missing factor is a hardware one (passkey / cert) the page does not auto-redirect: a **Continue** button, and links to register a passkey in the account console or enrol a certificate at `enroll.<domain>`. Other step-ups redirect after 2 seconds.

### Public policy

A policy with no factors means group-gate requires **no particular factor**, and the Hub sets the router's tier to `public@file`. The Hub only changes `tls.options`. The template's middlewares stay as they are, so a forward-auth app still requires a Keycloak login and its group. An app is only reachable without logging in if its routers have no forward-auth middleware (`auth.method: public`, a `custom` app, or one switched to [its own login only](#apps-with-their-own-login)). An `mtls` app never becomes public: it keeps requiring the certificate.

## Traefik TLS tier

The effective policy also drives the TLS tier on each router via a Hub-generated compose override:

| Policy | Tier | Behaviour |
|--------|------|-----------|
| Public, or the app handles its own sign-in | `public@file` | No client cert |
| mTLS-only, or `all of [..., mtls]` | `protected@file` | Requires client cert at TLS handshake |
| Everything else | `authaware@file` | Client cert tolerated but not required |

The tier change is emitted as a per-router `traefik.http.routers.<name>.tls.options` label in `${HUB_DATA_DIR}/overrides/<app>.override.yml`, for every router of the app. Base `compose.yml` files in templates are untouched. Changing the global default restarts only the inheriting apps whose tier actually changed.

**One tier per host.** Traefik selects TLS options per SNI host, before it
knows the path, so every router of a host must share one tier. If two routers
of a host disagree, Traefik falls back to its default TLS options and answers
`421 Misdirected Request`. The Hub therefore always writes the same tier for
all of an app's routers, including its [public router](#public-exceptions).

## Public exceptions

Templates can declare share-link paths in
[`auth.public_access`](../guides/manifest-reference.md#authpublic_access);
an admin turns them on per app in the [Hub](hub.md#public-exceptions). While
on, the Hub adds a router `portcullis-public-<app>` for those paths only:

- higher priority than every router of the app, so it wins for its paths;
- middlewares `portcullis-public-strip-<app>@docker,rate-limit@file,security-headers@file`
  only: **no forward-auth, no group-gate**, so no login, no group, no
  hardware key, no step-up and no access policy apply on these paths;
- the strip middleware deletes client-supplied identity headers (core's
  `X-Forwarded-User`, `X-Forwarded-Email`, `X-Forwarded-*`, `X-Auth-Request-*`,
  `Remote-*`, plus the template's `identity_headers`, each also in its
  `_` form), so a header-auth app can't be told who the visitor is;
- its first middleware, `portcullis-public-guard@docker` (group-gate
  `/public-guard`), re-checks the path against the published patterns and
  answers 403 to requests carrying `Authorization`, `Proxy-Authorization` or
  the template's credential headers, cookies or query parameters (names
  normalised the way PHP does), so a stolen password, API key or session
  can't get past the hardware key there;
- supporting paths serve static files only (by extension), plus single
  `exact` routes the template justifies;
- in mode `listed`, only the share tokens an admin listed are routed; any
  other token on the same prefix still goes through forward-auth.

**Exceptions vs mTLS.** A policy of `mtls` alone, or `all` including `mtls`,
normally gives the host `protected@file`: no client cert, no TLS handshake.
Anonymous visitors can't present one, so while the public router exists the
Hub uses `authaware@file` for **all** of the app's routers instead
(`policy.HostTier`). What still enforces mTLS:

| App type | Gated paths after the downgrade |
|----------|---------------------------------|
| `forward-auth` / `header-auth` | group-gate's [mTLS binding](#mtls-binding) requires a valid, unrevoked client certificate matching the user on **every** request, so mTLS stays enforced per request |
| `native-oidc` (no group-gate on the host-wide router) | mTLS is only enforced **at login**, through the Keycloak `acr` (`mtls`). An existing app session works from a browser without the key |
| any router without group-gate | loses the handshake check; the Hub lists such routers in the warning |

In mode `listed` with no listed share there is no public router and no
downgrade. Policies that already give `authaware@file` or `public@file` are
unchanged.

## Where policies are published

The Hub writes per-app policies into `group-gate-policy.json` (version 5) **keyed by every full hostname the instance routes** (never by template or instance ID); apps that inherit the default publish nothing and group-gate uses the file's `default`. A policy with an unknown factor or op makes group-gate deny the request (fail closed). Format: [Integration Contracts §4](../guides/integration-contracts.md#4-policy-file-hub-group-gate).

For native-OIDC apps the policy also sets the Keycloak client's `default.acr.values`, so Keycloak prompts for the right level at login.

## Identity

Policies decide *how* a user signed in; *who* the user is always comes from the immutable LLDAP username (`preferred_username`, `X-Forwarded-User`), never from the email. LLDAP users can edit their own email, so Keycloak does not trust it (`trustEmail=false`) and nothing in Portcullis authorises or links accounts by it. See [Security & Hardening](hardening.md#header-spoofing-protections).

## mTLS binding

`amr=mtls` in a token only proves a certificate was used at login. When a policy is satisfied **only** through `mtls` (`mtls` alone, `all` including `mtls`, or `any` where `mtls` is the only factor in the token), group-gate additionally requires the current request to present an unrevoked client certificate whose CN equals the token's `preferred_username`. Otherwise the user gets the step-up page. A session opened with a since-revoked certificate, or replayed from a browser without the key, stops working at once. See [TLS & mTLS](../setup/certificates.md#mtls-binding-group-gate).

## Enforcement map

| Layer | Public | WebAuthn | mTLS | AND combinations | OR combinations |
|-------|--------|----------|------|------------------|-----------------|
| Traefik | `public` | `authaware` | `protected` | `protected` if `mtls` in set | `authaware` unless mTLS-only |
| Keycloak | none | LoA 2 flow | LoA 3 flow | highest LoA + step-up | lowest LoA (any satisfies) |
| group-gate | no factor check | require `hwk ∈ amr` | require `mtls ∈ amr` + mTLS binding | require all factors in `amr` (+ binding if `mtls`) | require `amr ∩ factors ≠ ∅` (+ binding if only `mtls` matched) |

The table is per factor of the **effective** policy; which layers apply
depends on the auth method ([above](#what-each-app-can-enforce)).

## LLDAP passwords

The browser flow never asks for an LLDAP password. LLDAP passwords remain for LLDAP's own web UI and for apps that bind to LDAP themselves. They are no policy factor.

## Caveats

- **`acr_values` is advisory at Keycloak.** The OIDC spec treats it as a hint; Keycloak only hard-rejects when a client requests via the `claims` parameter with `essential: true`. Portcullis uses the LoA conditional executors instead, which hard-fail when the user can't satisfy the level (e.g. asking for `mtls` without a certificate). `group-gate` *also* verifies `acr`/`amr` from the issued token as a belt-and-braces check — trust doesn't depend on Keycloak honoring the request.
- **Session LoA accumulates.** Once a user steps up to LoA 3 via mTLS, every subsequent app within the same session sees `acr=mtls` and `amr ⊇ [mtls, ...]`. Stricter apps pass without additional prompts. Loosening policies mid-session doesn't downgrade the session.
- **`max_age` in the LoA conditions** is 10 hours (matching the session lifespan). Lower this in `realm-export.json` if you want the re-prompt window to be shorter.

## Troubleshooting

**"Step up required" page from group-gate**
Your session is missing the factor(s) the app requires. Click the link in the page body to re-authenticate at the right level.

**Client cert prompt loops indefinitely**
Your browser may not be sending the client certificate. Check that the cert is imported into your OS/keychain and that the origin matches the Traefik wildcard (`*.<your-domain>`).

**Keycloak login form appears when you expected SSO**
The session cookie expired (8 hours idle / 12 hours max by default). Re-authenticate.

**AND policy keeps failing even after a WebAuthn step-up**
Check that the `acr` client scope is attached to the app's Keycloak client and that the `acr loa level` protocol mapper has `Add to access token = true`. `./portcullis keycloak configure` does this for `portcullis-forward-auth`, and the Hub attaches the `acr` and `groups` scopes to every client it registers; a manually-created client may be missing them.
