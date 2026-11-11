# Sign-in Methods and Templates

Portcullis decides how people sign in with two things, both set in the Hub
under **Settings → Sign-in**:

- **Sign-in methods**: six ways to sign in, each switched on or off for the
  whole server.
- **Templates**: named rules over those methods ("a security key, or a
  YubiKey certificate"). One template is the default; each app and each core
  page can pick another.

Every place that checks a sign-in (group-gate, Keycloak, apps that sign in
with OIDC themselves, AI access, fresh sign-ins for sensitive actions) accepts
exactly the methods a template names, and only while they are switched on.
The exact formats are in
[Integration Contracts §8.1](../guides/integration-contracts.md#81-sign-in-methods-new-sign-in).

## Methods

| Method | Strength | Where it comes from | Starts |
|--------|----------|---------------------|--------|
| **Password** | 1.0 | The person's LLDAP password | off |
| **Passkey (phone / laptop, synced)** | 2.5 | A passkey synced by iCloud, Google, 1Password and the like, or any passkey whose model Portcullis can't verify | on |
| **Browser certificate** | 2.5 | A certificate file installed in a browser. Not available yet: listed, always off | off |
| **Device-bound passkey** | 3.0 | Windows Hello, a TPM: the key can't leave the computer or phone | on |
| **Security key passkey** | 3.5 | A touch on a certified hardware key, e.g. a YubiKey | on |
| **YubiKey certificate** | 4.0 | The client certificate stored on a YubiKey ([TLS & mTLS](../setup/certificates.md)) | on |

Settings → Sign-in shows each method with its strength and how many people
have it set up. A method that is off is never offered and never accepted, and
people can't set it up. You can't switch off a method an enabled template
needs, i.e. one without which the template would have no way in left: the
dialog lists the templates and what uses them (the default, apps, core
pages). Change those first.

Some template entries name a **family** of methods: *Passkey (any kind)*,
*YubiKey (touch or certificate)* and *Certificate (YubiKey or browser)*. A
family accepts any of its methods that is switched on. No family contains the
password: a password satisfies only templates that name it.

### Passkey kinds

Keycloak decides a new passkey's kind when it is registered, from the
attestation the authenticator sends, checked against the FIDO Alliance's
signed list of certified authenticators (the Hub fetches and verifies it
daily):

- **Security key**: a FIDO-certified roaming authenticator whose key is in a
  secure element, with an attestation that verifies.
- **Device-bound**: a certified platform authenticator (Windows Hello, a TPM)
  whose key can't leave the device.
- **Synced**: everything else, including passkeys without attestation
  (iCloud, Google, 1Password) and models the list doesn't know yet.

Keycloak keeps each passkey's attestation. Passkey kinds are reclassified
**upward** when a newer FIDO list verifies the stored attestation, and
**downward** only when the list marks that model revoked or compromised. A
model that simply drops off the list keeps its kind. If the Hub can't get a
current list for more than 30 days past its due date, new passkeys register as
synced (stored ones keep their kind) and Settings → Sign-in shows a warning.

### Password

The sign-in password **is** the person's LLDAP password: one password for
Portcullis sign-in, LLDAP's own UI and apps that bind to LDAP. Keycloak checks
it against LLDAP. Passwords set in the Hub must be 12–128 characters, not the
username, and not a common password. Only passwords set through the Hub count
in the method counts, the warnings and the lockout guard.

- You can set a password while the method is off (LDAP-binding apps use it),
  but onboarding a new person with a password is refused while it is off.
- **Password sign-in is never available for `admin` and `portcullis-hub`**,
  whatever the switch says. Keycloak answers "Password sign-in isn't
  available for this account" without checking the password, and the attempt
  doesn't count towards Keycloak's brute-force lockout (so nobody can lock
  these accounts out by trying passwords).

## Templates

A template is a rule: a tree of groups, each **all of** or **any of**,
holding methods, families and other groups, nested up to 3 levels. For
example, *((password and a security key) or (a YubiKey and a passkey)) and a
certificate*. The editor shows the rule as nested boxes and as one sentence,
both updated as you type.

Four templates are built in. You can edit them and switch them on and off, but
not delete them, and you can add your own (**+ New template**):

| Template | Rule | Score | Starts |
|----------|------|-------|--------|
| **Basic** | any passkey, any certificate, or a password | 1.0 / 5 (2.5 while password is off) | disabled |
| **Standard** | any passkey or any certificate | 2.5 / 5 | enabled, the default |
| **Strong** | a security key or a YubiKey certificate | 3.5 / 5 | enabled; the Hub and people pages |
| **YubiKey + certificate** | a YubiKey certificate and a security key | 4.4 / 5 | disabled |

Only enabled templates appear in the drop-downs. A template in use (by the
default, an app or a core page) can't be switched off or deleted.

A part of a template that names a method that is off (or a family with none
on) can't be met. In an **any of** group that part is simply dropped: Basic
with the password off works like Standard, and the editor greys the dropped
part out. In an **all of** group it makes the whole group impossible. A
template left with no way in at all can't be enabled.

### Score

Each template shows a score out of 5, such as `2.9 / 5`, with a one-line
reason. It is computed over the tree, leaving out the parts the switches
drop:

- a method scores its strength;
- a family scores its weakest method that is on;
- an **any of** group scores its **weakest** part (anyone can pick it);
- an **all of** group scores its strongest part + 0.4 per extra part, at
  most 5.

Example, with the browser certificate off:
`all of [any of [all of [password, security key], all of [YubiKey, passkey]], certificate]`
scores **4.4 / 5**. The two inner *all of* groups score 3.5 + 0.4 = 3.9 each,
their *any of* 3.9; *certificate* (only the YubiKey certificate is on) 4.0;
the top *all of* 4.0 + 0.4. With the password off, its *password and security
key* alternative is dropped and the rest still scores 4.4.

## Default, per app and core pages

- **Default.** Settings → Sign-in → *Default template*. Every app and core
  page without its own pick uses it. It starts as Standard.
- **Per app.** An instance's Settings tab has one drop-down: *Default
  (Standard · 2.5 / 5)* or any enabled template (see
  [Hub → Settings](hub.md#settings)). Saving another template restarts the app
  only when its client-certificate request changes ([below](#traefik-tls-tier)).
- **Core pages.** Settings → Sign-in → *Core pages* gives the portal, the Hub,
  people.&lt;domain&gt;, directory, enroll, metrics and the Traefik dashboard
  each the default or a template. The Hub and people.&lt;domain&gt; start on
  **Strong**: they control everything else. `auth.<domain>` (Keycloak itself)
  and `mcp.<domain>` take no template of their own: the Keycloak admin
  console's router (`auth.<domain>/admin`, which also runs group-gate) follows
  the Hub's template (the console is as powerful as the Hub; without one it is
  denied), and `mcp.<domain>` never reaches group-gate (mcp-gate
  checks it). The portal checks its own template (its router has no group
  check). A core page the policy file doesn't list is denied.

### What each app can enforce

| Auth method | Where the template is checked |
|-------------|-------------------------------|
| `forward-auth`, `header-auth`, `custom` behind Portcullis sign-in | group-gate, on every request. A YubiKey certificate counts only while the request presents it ([mTLS binding](#mtls-binding)) |
| `native-oidc` | Keycloak, at every sign-in to the app: the app's Keycloak clients are listed with their exact template, and Keycloak shows the needs-stronger page when the session doesn't meet it. Never weaker than the template |
| `mtls` | The TLS handshake: the client certificate is the app's authentication. It takes no template and always requires the certificate |
| `custom`, `public`, own login only | None: the app handles its own sign-in. No template, no client-certificate request |

### AI support

AI clients sign in with the template of the app they reach (the Hub's and
people pages' templates for the Portcullis MCP and "all my apps"), but they
never present a client certificate, so certificate methods never count for
them. An app whose template needs a certificate in every alternative can't
get AI support, and a sign-in change that would make it so switches its AI
support off first, after asking. See [AI support](ai.md).

## Apps with their own login

A `custom` template whose app has its own login and no SSO declares
[`auth.native_login`](../guides/manifest-reference.md#authnative_login). Its
settings then have a **Sign-in** choice:

- **Portcullis sign-in, then the app's own login** (default). The Hub's
  override puts `portcullis-auth@docker,portcullis-groups@docker` in front of
  every router's own middlewares; group-gate requires the template's
  `access_group` and the app's sign-in template applies per request, as for
  `forward-auth`.
- **App's own login only (no Portcullis)**, only if the template sets
  `allow_without_gateway: true`. The routers keep the template's middlewares
  without the gateway pair, no client certificate is requested and no group
  is published: anyone on the internet reaches the app's login page. The UI
  shows a red warning, the switch is audited (`app.sign_in`) and the Hub logs
  it.

The template is never edited; both modes are compose-override labels, which
the drift check compares with the running containers. If a template stops
allowing the own-login-only mode, the Hub falls back to Portcullis sign-in.

## Warnings

- **For admins.** Wherever a template is applied (an app's Settings, the
  template editor, Settings → Sign-in), the Hub lists the members of the
  app's users and admins groups who have no method set up that meets it, for
  example "2 people can't sign in to Nextcloud · family with it: bob (password
  only), dave (no method yet)". The Hub learns each person's methods from
  Keycloak (passkeys), its own password records and enroll (YubiKey
  certificates). A source it can't read counts as nothing set up.
- **For people.** Opening an app whose template the session doesn't meet
  shows a page instead of a failed sign-in ([below](#what-happens-when-someone-opens-an-app)).

## Adding a stronger method

Settings → Sign-in → *Add a stronger method from a weaker sign-in* is **off**
at the start. While it is off, a person can add only methods as strong as the
one they signed in with: a password-only session can't register any passkey,
and someone who signed in with a synced passkey can add
another synced passkey, but registering a security key needs help from an admin
(a setup link). The needs-stronger page then
says "ask your admin" instead of "Set up …". A passkey added this way can't be
reclassified above that cap later. A setup link is the exception: the passkey
registered there may be of any kind. Passkey registration offers the security
key first to administrators.

## Locked out of the Hub

The Hub refuses (`409`, saying why) a save that changes methods, templates,
the default or the Hub's template when it would leave **no** administrator
(an unexpired `lldap_admin` member) able to meet the Hub's template. If none
can already, the save goes through with the warning "No administrator can meet
the Hub's template". Only a save that can lower the number of administrators
able to meet it reads Keycloak, enroll and LLDAP; when Keycloak or LLDAP
can't be reached, such a save answers `503`.

If you are locked out anyway, recover on the server:

```bash
./portcullis signin reset-core
```

It stops the Hub, puts the Hub and people.&lt;domain&gt; back on Standard,
restores and enables the built-in Standard rule, switches its methods back on
(audited `signin.reset_core`, actor `cli`) and starts the Hub. See the
[CLI reference](cli.md#signin-reset-core).

## What happens when someone opens an app

### Single sign-on

A person who signed in with a security key opens an app on Standard. The
Keycloak session already holds a method Standard accepts, so the app opens
with no prompt. Keycloak remembers every method used in the session (for 10
hours), so templates with *all of* can be met step by step.

### Not in the app's groups

group-gate checks the app's groups (and its admin paths' groups) before its
template. Someone who isn't in them gets a plain "not authorized" page, never
a step-up or needs-stronger page that would name the app's rule.

### Step-up for one method

When the session is missing exactly one method the person can complete (one
they have set up, or one the Hub doesn't know about), group-gate shows
"&lt;App&gt; needs &lt;method&gt;" with a **Continue** button. It leads to Keycloak with
`pc_method=<method>`, and Keycloak asks for that method only: a security-key
step-up offers only security keys, a certificate step-up only the
certificate. The page never redirects on its own. When the Hub doesn't know
which passkeys the person has and several passkey kinds would do, it asks for
any passkey. Apps that sign in with OIDC themselves do the same inside
Keycloak: an *all of* template is met step by step.

### Present your YubiKey certificate

When the session already holds the YubiKey certificate but the browser didn't
present it on this request (the key isn't inserted, or the browser offered no
certificate), signing in again can't help: group-gate shows "&lt;App&gt; needs
your YubiKey certificate — insert your YubiKey and reload this page", with no
Continue button. A revoked certificate or another person's doesn't count.

### Needs a stronger sign-in

Otherwise the page reads "&lt;App&gt; needs a stronger sign-in — You signed in with
a password. &lt;App&gt; accepts any one of: a passkey (you don't have one yet) · a
YubiKey certificate …", with **Set up a passkey** / **Set up a security key**
links to Keycloak's account page and a **Sign-in methods** link. When adding a
stronger method from this sign-in isn't allowed, or the missing method is a
certificate or a password, it says "ask your admin". Apps that sign in with
OIDC themselves get the same page from Keycloak. These pages come from
group-gate and Keycloak, not from the app or the Hub, so they are always
reachable.

### After a setup link

A setup link signs the person in with a session that meets **no** template.
Right after it they touch their new passkey once more to open apps. The
step-up asks for any passkey when the app's template accepts several passkey
kinds, else for the first method the template can complete: the list of who has which method may not show the new passkey yet, so
it isn't consulted for a setup-link session (no "needs a stronger sign-in"
page just because it is behind).

### Fresh sign-in for sensitive actions

Creating a file-share password and approving an AI confirmation need a fresh
sign-in in a popup, with a method the governing template accepts: the
strongest method of at least one of the template's ways in (its
alternatives, counting only the methods switched on now; a tie lets either
through; a password too). What counts is the method that actually ran in that
popup sign-in (Keycloak records it in the token's `pc_fresh` claim), never
the methods the session used earlier; an SSO session reused or a setup link
never counts.

| Action | Governing template |
|---|---|
| Creating or regenerating a file-share password | the app's template (its own pick, else the default) |
| Approving a companion's confirmation (people.&lt;domain&gt;) | the companion's app's template |
| Approving a Portcullis people tool's confirmation (people.&lt;domain&gt;) | the `people` core page's template |
| Approving an admin tool's confirmation (hub.&lt;domain&gt;) | the `hub` core page's template |
| Anything else that asks for a fresh sign-in | the `hub` core page's template (fail closed) |

So with the core pages on Strong an admin confirmation needs the security key
or the YubiKey certificate, a synced passkey isn't enough; under Standard any
passkey or the YubiKey certificate approves; an app on a password-only
template is confirmed by typing the password again; a template that needs a
security key and a password (`all[security_key, password]`) is confirmed with
the security key — the password alone never is. A template that is
disabled, gone or can't be met refuses.

## Traefik TLS tier

Whether browsers are asked for a client certificate follows the method
switches and the app's template. Core's `traefik/dynamic/tls.yml` is static
and defines three options; the Hub picks one per app and writes it as a
`tls.options` label on every router of the app, in
`${HUB_DATA_DIR}/overrides/<app>.override.yml`:

| The app's template | Tier | Behaviour |
|--------------------|------|-----------|
| Every alternative needs a certificate method that is on (e.g. YubiKey + certificate) | `protected@file` | Client certificate required at the TLS handshake |
| Some alternative has one (e.g. Standard, Strong) | `authaware@file` | Client certificate asked for, optional |
| None has one, or the app has no Portcullis sign-in | `public@file` | No client certificate requested |
| An `mtls` app | `protected@file` | Always |

Core pages (Keycloak, the Hub, people.&lt;domain&gt;, the portal, the
consoles) always use `authaware@file`: they always offer an optional
certificate (a browser without one shows nothing). Switching a certificate
method on or off, or a template change that moves an app to another tier,
restarts only the apps whose tier changed. Base `compose.yml` files in
templates are untouched.

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
  hardware key, no step-up and no sign-in template apply on these paths;
- the strip middleware deletes client-supplied identity headers (core's
  `X-Forwarded-User`, `X-Forwarded-Email`, `X-Forwarded-*`, `X-Auth-Request-*`,
  `Remote-*`, plus the template's `identity_headers`, each also in its
  `_` form), so a header-auth app can't be told who the visitor is;
- its first middleware, `portcullis-public-guard@docker` (group-gate
  `/public-guard`), re-checks the path against the published patterns and
  answers 403 to requests carrying `Authorization`, `Proxy-Authorization` or
  the template's credential headers, cookies or query parameters (names
  normalised the way PHP does), so a stolen password, API key or session
  can't get past the sign-in there;
- supporting paths serve static files only (by extension), plus single
  `exact` routes the template justifies;
- in mode `listed`, only the share tokens an admin listed are routed; any
  other token on the same prefix still goes through forward-auth.

**Exceptions vs a required certificate.** A template that needs a
certificate in every alternative normally gives the host `protected@file`.
Anonymous visitors can't present a certificate, so while the public router
exists the Hub uses `authaware@file` for **all** of the app's routers instead
(`policy.HostTier`). What still enforces the certificate:

| App type | Gated paths after the downgrade |
|----------|---------------------------------|
| `forward-auth` / `header-auth` | group-gate's [mTLS binding](#mtls-binding) requires a valid, unrevoked client certificate matching the user on **every** request, so the certificate stays enforced per request |
| `native-oidc` (no group-gate on the host-wide router) | The certificate is only enforced **at sign-in**, by Keycloak's template check. An existing app session works from a browser without the key |
| any router without group-gate | loses the handshake check; the Hub lists such routers in the warning |

In mode `listed` with no listed share there is no public router and no
downgrade. Templates that already give `authaware@file` or `public@file` are
unchanged.

## Where templates are published

The Hub compiles each enabled template against the methods that are on and
publishes it three times, rewritten after every change:

- **group-gate**: `group-gate-policy.json` (version 6), with the methods,
  the templates, the default, each app's own pick keyed by every full
  hostname it routes, and each core page's template, plus each person's
  set-up methods and the add-stronger switch (these two only word
  group-gate's pages, they never decide access). A missing file, one
  group-gate can't read, another version, an unknown key, an unknown method
  or rule shape, a method in a rule that isn't on, or a template a host names
  but the file lacks makes it deny (fail closed). Format: [Integration Contracts §4](../guides/integration-contracts.md#4-policy-file-hub-group-gate).
- **Keycloak**: `signin-keycloak.json`, with the methods, the templates, the
  native-OIDC clients and their templates, and the FIDO list's verdicts. If
  it is missing or invalid every method counts as off and nobody signs in
  until the Hub writes a good one.
- **mcp-gate**: `mcp-gate.json` (version 2), each AI resource with its rule
  ([AI support](ai.md)).

## Sign-in flows in Keycloak

Keycloak runs Portcullis's own image, `ghcr.io/porelli/portcullis-keycloak`
(`KEYCLOAK_IMAGE`, see [Upgrading](upgrading.md)): the official Keycloak plus
the sign-in extension that enforces the methods and templates. It reads the
Hub's `signin-keycloak.json` from the `hub_data` volume, mounted read-only at
`/hub-data`. The realm's flows (`keycloak/realm-export.json`, rebuilt by
[`./portcullis keycloak configure`](cli.md#keycloak-configure) whenever they
change) have no Level-of-Authentication steps any more:

- **Browser flow `portcullis-universal`**: the SSO cookie, the hidden setup-link
  identity provider, or one sign-in method, then the **template check**
  (`portcullis-template`) for the app that asked. The methods, tried in this
  order:
    - the **YubiKey certificate** (automatic when the browser presents one;
      amr `mtls`),
    - a **passkey**: Keycloak offers only the kinds that are on, and the kind
      that signed in gives the amr (`hwk` security key, `dpk` device-bound,
      `spk` synced),
    - a **password** (amr `pwd`), only while the method is on, never for
      `admin` and `portcullis-hub`.

    Each method stays in the session's amr for 10 hours. A step-up
    (`pc_method=<method>`) makes the other methods step aside, and the SSO
    cookie hands a session that lacks the method back to the sign-in.
- **Setup links** (`portcullis-invite-session`, the setup-link identity
  provider's post-login flow): only for `portcullis-forward-auth`, then the
  session gets amr `inv` (not a method, it meets no template) and the
  template check.
- **Brute-force protection** is on for the realm: after 10 failed sign-ins an
  account waits 60 s more per further failure, at most 15 minutes, and is
  never locked for good. Refused passwords of `admin` / `portcullis-hub` don't
  count.
- **Passkey registration** asks the authenticator for a direct attestation
  (the extension decides the kind from it; a passkey without one registers as
  synced), allows any authenticator attachment and requires a resident key and
  user verification. The browser is given hints in the extension's order: the
  security key first for `lldap_admin` members, the device first for everyone
  else. Keycloak's stock two-factor WebAuthn registration is disabled.
- `portcullis-forward-auth` has no default acr: group-gate asks for a method
  with `pc_method`, never with `acr_values`.

## Identity

Templates decide *how* a person signed in; *who* they are always comes from
the immutable LLDAP username (`preferred_username`, `X-Forwarded-User`), never
from the email. LLDAP users can edit their own email, so Keycloak does not
trust it (`trustEmail=false`) and nothing in Portcullis authorises or links
accounts by it. See [Security & Hardening](hardening.md#header-spoofing-protections).

## mTLS binding

A YubiKey certificate in the session (`amr=mtls`) only proves a certificate
was used at sign-in. group-gate counts the **YubiKey certificate** method
only while the current request presents an unrevoked client certificate whose
CN equals the session's `preferred_username` (and the token's
`preferred_username` is the same user). Without it the method is missing: a
template the certificate would meet shows the present-certificate page
([above](#present-your-yubikey-certificate)), any other the step-up or
needs-stronger page. A session opened with a since-revoked certificate, or replayed from a
browser without the key, stops meeting such a template at once. See
[TLS & mTLS](../setup/certificates.md#mtls-binding-group-gate).

## Troubleshooting

**"&lt;App&gt; needs …" page from group-gate**
Your session is missing a method the app's template needs. Press
**Continue**, or set the method up from the page's links.

**Client certificate prompt loops indefinitely**
Your browser may not be sending the client certificate. Check that the
certificate is imported into your OS/keychain and that the origin matches the
Traefik wildcard (`*.<your-domain>`).

**Keycloak sign-in page appears when you expected single sign-on**
The session cookie expired (8 hours idle / 12 hours max by default), or the
app's template needs a method your session doesn't have yet.

**Nobody can sign in at all**
Keycloak couldn't read `signin-keycloak.json`: every method counts as off.
Check the Hub is running (it writes the file at start); if the Hub itself is
unreachable because of its template, run `./portcullis signin reset-core`.
