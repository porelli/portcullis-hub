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
| **Browser certificate** | 2.5 | A certificate file (`.p12`) the person creates on the [Sign-in page](#the-sign-in-page) and installs in a browser ([below](#browser-certificates)) | off |
| **Device-bound passkey** | 3.0 | Windows Hello, a TPM: the key can't leave the computer or phone | on |
| **Security key passkey** | 3.5 | A touch on a certified hardware key, e.g. a YubiKey | on |
| **YubiKey certificate** | 4.0 | The certificate stored on a YubiKey ([Certificates](../setup/certificates.md)) | on |

Settings → Sign-in shows each method with its strength and how many people
have it set up. A method that is off is never offered and never accepted, and
people can't set it up. You can't switch off a method an enabled template
needs, i.e. one without which the template would have no way in left: the
dialog lists the templates and what uses them (the default, apps, core
pages). Change those first. The browser certificate starts off; switch it on
when you want people to be able to create one.

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
  only when its certificate request changes ([below](#traefik-tls-tier)).
- **Core pages.** Settings → Sign-in → *Core pages* gives the portal, the Hub,
  people.&lt;domain&gt;, directory, metrics and the Traefik dashboard
  each the default or a template. `enroll.<domain>` only serves setup links
  and takes no template. The Hub and people.&lt;domain&gt; start on
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
| `forward-auth`, `header-auth`, `custom` behind Portcullis sign-in | group-gate, on every request. A YubiKey or browser certificate counts only while the request presents it ([certificate binding](#certificate-binding)) |
| `native-oidc` | Keycloak, at every sign-in to the app: the app's Keycloak clients are listed with their exact template, and Keycloak shows the needs-stronger page when the session doesn't meet it. Never weaker than the template |
| `mtls` | The TLS handshake: the certificate is the app's authentication. It takes no template and always requires one |
| `custom`, `public`, own login only | None: the app handles its own sign-in. No template, no certificate request |

### AI support

AI clients sign in with the template of the app they reach (the Hub's and
people pages' templates for the Portcullis MCP and "all my apps"), but they
never present a YubiKey or browser certificate, so certificate methods never
count for them. An app whose template needs a certificate in every alternative can't
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
  without the gateway pair, no certificate is requested and no group
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
  Keycloak (passkeys), its own password records and enroll (YubiKey and
  browser certificates). A source it can't read counts as nothing set up.
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

## The Sign-in page

Every person has one place for their sign-in methods: the **Sign-in page**,
`https://people.<domain>/signin` (the **Sign-in** link in the people page's
top bar, **Sign-in methods** on the portal, and every "Set up …" and
"Sign-in methods" link on the needs-stronger pages). It shows:

- **Each sign-in method**, in strength order, with its state (set up, not set
  up, unknown) and what the person can do with it. A method switched off on
  the server shows "off on this server".
    - **Password:** set, change or remove your own password. Setting one needs
      a fresh sign-in; it is refused while the password method is off, and for
      `admin` and `portcullis-hub`. Changing or removing it signs you out of
      Keycloak.
    - **Passkeys and security keys:** the list with each one's kind and date;
      **+ Add** opens Keycloak's account page to register one.
    - **YubiKey certificate:** its validity and **Renew**: the page shows the
      `ykman` commands that make a new request (CSR) for the key already on
      the YubiKey; you paste it, and the browser must present your current
      YubiKey certificate on that request (only a YubiKey certificate
      renews; a browser certificate is refused). No fresh sign-in is needed:
      the certificate and the request both prove you hold the key.
    - **Browser certificate:** the list and **Create**
      ([below](#browser-certificates)); each one can be revoked.
- **Apps and what they need:** every app you can use, plus the people page
  (and the Hub for administrators), with its template and whether one of
  your methods meets it (✓ / ✗, or ? while Portcullis doesn't know your
  methods).
- **Sign-in history** ([below](#sign-in-history)).

The page works with **any** switched-on method, even one the people page's
own template wouldn't accept: group-gate lets a session with any method in
to exactly `/signin`, its `/api/me/signin…` routes and the page's static
files on people.&lt;domain&gt;, and nothing else. Everything there that adds a
method needs a fresh sign-in the people page's template accepts (or, for a
renewal, the YubiKey certificate itself); the rest only shows or removes your
own data. See
[Integration Contracts §5.1](../guides/integration-contracts.md#51-people-subdomain-new).

## Browser certificates

A **browser certificate** is a certificate file (`.p12`) that a person
creates on the Sign-in page and installs in a browser or the OS. It is a
sign-in method of its own (strength 2.5, like a synced passkey: it is a
file, and a file can be copied). It is issued by its own certificate
authority, `pki_file` (the **Internal certificate authority** of
[Certificates](../setup/certificates.md)), so it never counts as a YubiKey
certificate, and signing in with it gives amr `file`, never `mtls`.

1. An admin switches **Browser certificate** on in Settings → Sign-in (it
   starts off).
2. On the Sign-in page the person picks **Create**, chooses a lifetime (from
   1 day up to the limit, 30 days by default; the default is the limit) and
   confirms with a fresh sign-in in a popup. That sign-in must be a passkey
   or YubiKey method the people page's template accepts: a password or
   another browser certificate never creates a certificate. If the template
   accepts nothing else, the page says "creating a certificate needs a
   passkey or YubiKey sign-in that people.&lt;domain&gt; accepts".
3. The page offers the download (`<user>-browser-certificate-<YYYYMMDD>.p12`)
   and, next to it, its password. **The password is shown once: Portcullis
   doesn't keep it and can't show it again**, and the private key is never
   kept either, so the file can't be downloaded again. A lost file or
   password means creating a new certificate (and revoking the old one).
4. The person imports the file:
    - **Firefox:** Settings → Privacy & Security → Certificates → View
      Certificates → Your Certificates → Import.
    - **Chrome / Edge on Windows 10 or newer:** open the `.p12` (Windows
      certificate import wizard, Current User).
    - **macOS:** open it in **Keychain Access** (macOS 14 or newer: the file
      is encrypted with AES-256, which older versions can't open); Safari and
      Chrome use the login keychain.

Administrators create and revoke their own browser certificates here like
anyone else; only `admin`, `portcullis-hub` and `portcullis-*` accounts
can't (their certificates are managed from the server).

A person can have at most 3 active browser certificates (the limit), and
each one lasts at most the lifetime limit. A certificate **revoked** on the
Sign-in page (or by an admin or helper, or with
`./portcullis cert revoke`) **normally stops working within a minute** everywhere,
and shows as revoked on the Sign-in page, the person's Sign-in tab and
`./portcullis cert list --all`.

## Help to reset

Someone who lost their passkeys or certificates can get help from an
administrator or from a **sign-in helper**: a member of the group that holds
the delegated permission `sign_in_help` ([People & groups](groups.md#delegated-permissions)).
Both open the person's **Sign-in** tab on their page on people.&lt;domain&gt;:

| Action | Administrators | Holders of `sign_in_help` |
|--------|----------------|---------------------------|
| Send a setup link | yes (not to another administrator: `./portcullis invite <user>`) | yes, also for accounts they didn't create |
| Remove passkeys | yes (another administrator's needs their username typed again) | yes |
| Revoke a certificate | yes, except an administrator's, `admin`'s, `portcullis-hub`'s or any `portcullis-*` account's (`./portcullis cert revoke <serial>`) | yes |
| Reset the password | yes (another administrator's needs their username typed again) | **no** |
| Issue a YubiKey certificate (from a CSR) | yes, after a fresh sign-in; not for an administrator, `admin`, `portcullis-hub` or any `portcullis-*` account (`./portcullis cert enroll`) | **no** |

A helper can never act on themselves, on `admin` or `portcullis-hub`, on an
administrator, or on a member of any delegated-permission group; the check
uses the current group memberships on every request. Every action is in the
audit log (as `as sign_in_help` for a helper) and in the person's sign-in
history.

!!! warning "Grant `sign_in_help` only to people you'd trust with those accounts"
    A setup link hands the account to whoever holds it. A `sign_in_help`
    holder can send one to anyone in their reach, so grant the permission
    only to people you would trust with those accounts. Administrators are
    never in reach.

## Signing in as someone else

An administrator can sign in as another person to see what they see and act
in their apps, for example to check a problem the person reports. There is
no approval step, so every impersonation is limited, visible and recorded.

**Who.** Only members of `lldap_admin`, and never on another administrator,
on yourself, on `admin`, on `portcullis-hub` or on any `portcullis-*`
account. One at a time: you can't run two, and nobody can be impersonated
by two administrators at once. Settings → Sign-in → **Signing in as someone
else** switches the feature off for everyone (it is on at the start), and
switching it off ends every impersonation that is running.

**Starting.** On the person's page on people.&lt;domain&gt;, open the
**Sign-in** tab and choose **Sign in as &lt;person&gt;…**:

1. Type a reason (3–200 characters, one line). The person will read it.
2. Do a fresh sign-in with a **YubiKey touch**: a security key passkey or a
   YubiKey certificate. A synced passkey, a device-bound passkey, a
   password or a browser certificate is refused. At least one of the two
   YubiKey methods must be switched on.
3. Your browser opens the person's portal, signed in as them.

**Your own session ends when you start.** Keycloak signs you out of your
own account in that browser. After Stop you sign in again as yourself.

**30 minutes at most.** An impersonation ends after 30 minutes (core's
`IMPERSONATION_MAX_MINUTES` in `.env` can only make it shorter), when you
press **Stop**, when another administrator stops it, or when the switch
goes off. Every Portcullis page (the portal, My apps, People, the Sign-in
page and the sign-in pages) shows:

> You are signed in as alice (by root) · reason “checking quota” · 26 min left · **Stop**

Apps can't show this line. Stop is also at
`https://people.<domain>/impersonation/stop`. When it ends, the next
request shows "Your session as alice has ended." with a link to sign out.

**What it can do.** You open the apps the person may open, as them. Your
own sign-in counts, not theirs: an app opens only when **your** session's
methods (the fresh touch included) meet its template, and a certificate
method counts only with **your** YubiKey or browser certificate. A session
as someone else can never add a method, so there is no step-up: when your
sign-in doesn't meet an app's template, the page says so; press Stop, sign
in with the methods it needs and start again.

**What is refused.** Everything on Portcullis's own pages that changes
something is refused while you are signed in as someone else ("not while
you are signed in as someone else: Stop first"): app values, file-share
passwords, AI connections, passwords, certificates, passkeys, confirmations
and anything you may do in the directory. Reading works. AI tools refuse a
session as someone else, Keycloak's account console and fresh sign-ins are
refused, and so is any app sign-in that would need a method. A person with
an unfinished sign-in step (an unused setup link, for example) can't be
signed in as until it is finished or cancelled.

**Apps that keep their own sessions.** A gateway app loses access at once
when the impersonation ends. An app that signs in through Keycloak itself
and keeps its own session (Nextcloud, for example) may stay signed in as the
person after the end, unless it supports Keycloak's backchannel logout.
When that matters, sign the person out inside that app. The person's
history and notice say which apps may have stayed signed in.

**The record.** The audit log has `impersonation.start` (who, whom, the
method of the touch and the reason; refused starts too) and
`impersonation.end` (how it ended, how long it ran and the apps opened).
The person's [sign-in history](#sign-in-history) has an entry with who,
when, the reason and the apps opened. At their next sign-in the person
sees, once:

> root signed in as you on 12 Nov 2026 14:02 UTC for 26 min: checking
> quota. Apps opened: Gitea, Nextcloud. Nextcloud keeps its own session and
> may have stayed signed in longer.

An impersonation that was started but never opened (the browser didn't
follow through within 2 minutes) ends as "not used", and the person gets no
notice.

AI tools can list impersonations, stop one and switch the feature off,
never start one or switch it on ([AI support](ai.md)).

Keycloak's own **Impersonate** button is gone on purpose: core switches the
stock feature off, because it has no fresh touch, no reason, no time limit
and no record ([Hardening](hardening.md#keycloak-impersonation)).

## Sign-in history

The Sign-in page (and, for admins and helpers, the person's Sign-in tab)
shows the person's sign-in history, newest first, with **Show older**:

| Entry | What it is |
|-------|------------|
| Signed in | a new sign-in, with its methods and their score |
| Stepped up | an existing session that added a method |
| Failed | a sign-in that failed, with the method tried and why ("wrong password", "certificate refused", …) |
| Confirmed | a fresh sign-in for a sensitive action |
| Opened | the first time a session opened an app (per app); "by root" when an administrator opened it while signed in as the person |
| Help | an action someone else took on the account (by whom) |
| Certificate | a certificate the person created, renewed or revoked |
| Signed in as you | an administrator signed in as the person ([above](#signing-in-as-someone-else)): who, the reason, how long, how it ended and the apps opened |

Each entry shows the IP address and the browser ("Firefox · macOS"). The
history is put together when it is shown, from Keycloak's sign-in events,
group-gate's log of opened apps (the `group_gate_data` volume, in
[backups](backups.md)) and the Hub's audit log. When one of them can't be
read, the page says which, and shows the rest. Entries older than the
history limit (1 year by default) are never shown and are deleted.

## Limits

Settings → Sign-in → **Limits** (admins):

| Limit | Default | Range |
|-------|---------|-------|
| Browser certificate lifetime | 30 days | 1 day to the server's ceiling |
| Active browser certificates per person | 3 | 1–20 |
| Sign-in history kept | 365 days | 30–3650 days |

The ceiling is core's `CLIENT_CERT_TTL` (default `720h`, 30 days) in whole
days: no certificate lives longer. If you lower `CLIENT_CERT_TTL` below the
stored lifetime, the ceiling applies and Settings shows a warning. Changing
the history limit also changes how long Keycloak keeps sign-in events. The
change is audited (`signin.limits`).

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

### Present your certificate

When the session already holds a YubiKey or browser certificate but the
browser didn't present it on this request (the key isn't inserted, the
certificate is installed in another browser, or the browser offered none),
signing in again can't help: group-gate shows "&lt;App&gt; needs your YubiKey
certificate — insert your YubiKey and reload this page" (or "&lt;App&gt; needs
your browser certificate — use the browser it is installed in and reload
this page"), with no Continue button. A revoked certificate or another
person's doesn't count, and neither does a certificate of the other kind.

### Needs a stronger sign-in

Otherwise the page reads "&lt;App&gt; needs a stronger sign-in — You signed in with
a password. &lt;App&gt; accepts any one of: a passkey (you don't have one yet) · a
YubiKey certificate …", with **Set up a passkey** / **Set up a security key**
links and a **Sign-in methods** link, all to the person's
[Sign-in page](#the-sign-in-page) (`https://people.<domain>/signin`). When adding a
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

Creating a file-share password, approving an AI confirmation, creating a
browser certificate, issuing a YubiKey certificate and setting your own
password need a fresh sign-in in a popup, with a method the governing template accepts: the
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
| Creating a browser certificate, issuing a YubiKey certificate | the `people` core page's template, but never with a password or a browser certificate ([below](#browser-certificates)) |
| Setting your own password on the Sign-in page | the `people` core page's template |
| Anything else that asks for a fresh sign-in | the `hub` core page's template (fail closed) |

So with the core pages on Strong an admin confirmation needs the security key
or the YubiKey certificate, a synced passkey isn't enough; under Standard any
passkey or the YubiKey certificate approves; an app on a password-only
template is confirmed by typing the password again; a template that needs a
security key and a password (`all[security_key, password]`) is confirmed with
the security key — the password alone never is. A template that is
disabled, gone or can't be met refuses.

## Traefik TLS tier

Whether browsers are asked for a certificate (YubiKey or browser) follows the
method switches and the app's template. Core's `traefik/dynamic/tls.yml` is static
and defines four options; the Hub picks one per app and writes it as a
`tls.options` label on every router of the app, in
`${HUB_DATA_DIR}/overrides/<app>.override.yml`:

| The app's template | Tier | Behaviour |
|--------------------|------|-----------|
| An `mtls` app | `protected@file` | Always: a **YubiKey** certificate required at the TLS handshake |
| Every alternative needs the YubiKey certificate (e.g. YubiKey + certificate) | `protected@file` | A **YubiKey** certificate required at the TLS handshake; a browser certificate never passes it |
| Every alternative needs a certificate method that is on, and at least one accepts the browser certificate | `protected-any@file` | A YubiKey or browser certificate required at the TLS handshake |
| Some alternative has one (e.g. Standard, Strong) | `authaware@file` | A certificate asked for, optional |
| None has one, or the app has no Portcullis sign-in | `public@file` | No certificate requested |

`protected` trusts only the YubiKey certificate authority
(`certs/ca-chain-yubikey.crt`); `protected-any` and `authaware` trust both
(`certs/ca-chain.crt`). Core pages (Keycloak, the Hub, people.&lt;domain&gt;,
the portal, the consoles) always use `authaware@file`: they always offer an
optional certificate (a browser without one shows nothing). Which method a
certificate counts as is decided by its issuer
([certificate binding](#certificate-binding)). Switching a certificate
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
certificate in every alternative normally gives the host `protected@file` or
`protected-any@file`.
Anonymous visitors can't present a certificate, so while the public router
exists the Hub uses `authaware@file` for **all** of the app's routers instead
(`policy.HostTier`). What still enforces the certificate:

| App type | Gated paths after the downgrade |
|----------|---------------------------------|
| `forward-auth` / `header-auth` | group-gate's [certificate binding](#certificate-binding) requires a valid, unrevoked certificate of the right kind matching the user on **every** request, so the certificate stays enforced per request |
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
    - the **YubiKey certificate** (automatic when the browser presents one
      issued by the YubiKey certificate authority, `pki_int`; amr `mtls`),
    - the **browser certificate** (automatic when the browser presents one
      issued by the browser certificate authority, `pki_file`, while the
      method is on; amr `file`). Each of the two certificate steps checks the
      certificate's issuer and signature against its own authority and its
      own revocation lists, so a browser certificate never counts as a
      YubiKey certificate,
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

## Certificate binding

A certificate in the session (`amr=mtls` for a YubiKey certificate, `file`
for a browser certificate) only proves a certificate was used at sign-in.
group-gate counts a certificate method only while the current request
presents an unrevoked certificate **of that kind** whose CN equals the
session's `preferred_username` (and the token's `preferred_username` is the
same user). It tells the kinds apart by the certificate's issuer: the YubiKey
certificate authority (`pki_int`) or the browser certificate authority
(`pki_file`). If the two authorities' names were equal, or group-gate can't
read either file, no certificate counts at all. Without a bound certificate
the method is missing: a template the certificate would meet shows the
present-certificate page ([above](#present-your-certificate)), any other the
step-up or needs-stronger page. A session opened with a since-revoked
certificate, or replayed from a browser without it, stops meeting such a
template at once. See
[Certificates](../setup/certificates.md#certificate-binding-group-gate).

## Troubleshooting

**"&lt;App&gt; needs …" page from group-gate**
Your session is missing a method the app's template needs. Press
**Continue**, or set the method up from the page's links.

**Certificate prompt loops indefinitely**
Your browser may not be sending the YubiKey or browser certificate. Check
that the certificate is imported into your OS/keychain (or the browser's own
store, for Firefox) and that the origin matches the Traefik wildcard
(`*.<your-domain>`).

**"&lt;App&gt; needs your browser certificate" although it is installed**
The certificate may be revoked or expired: open the
[Sign-in page](#the-sign-in-page) and check its status. A revoked
certificate normally stops working within a minute.

**Keycloak sign-in page appears when you expected single sign-on**
The session cookie expired (8 hours idle / 12 hours max by default), or the
app's template needs a method your session doesn't have yet.

**Nobody can sign in at all**
Keycloak couldn't read `signin-keycloak.json`: every method counts as off.
Check the Hub is running (it writes the file at start); if the Hub itself is
unreachable because of its template, run `./portcullis signin reset-core`.
