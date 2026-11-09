# Sign-in methods, templates, certificates and impersonation — design

Status: agreed in conversation 2026-11-09 (brainstorming, two mockups approved);
written for the builder check. Supersedes the draft
`2026-11-02-certificates-selfservice-design.md` (its builder-check rulings are
kept below; its 0–100 score is replaced by the /5 score).

## Why

Today sign-in is passkey-only and policies are two checkboxes ("mTLS" /
"WebAuthn", all-of / any-of). The admin found:

- no way to allow a username + password, although some people/apps need it
  (it is the weakest method, but it is the admin's call);
- no way to tell a YubiKey from a synced phone/laptop passkey, or a YubiKey
  certificate from one installed in a browser, so an app can't require
  "a YubiKey";
- rules can't combine methods ("this AND that, or the other");
- the pages confuse certificates: HTTPS website certificates, client
  certificates on a YubiKey, client certificates in a browser, the internal
  CA — and there is no way to download a certificate for a browser;
- `enroll.<domain>/users` duplicates `people.<domain>`; certificate issuing,
  listing and renewal live on a separate admin-only site the step-up page
  links people to (non-admins can't open it); revoked certificates show as
  "Valid"; revocation is CLI-only;
- left-overs: the People page can set an LLDAP password nothing accepts; the
  LoA 1 name is still `pwd` although it means "certificate or passkey".

## Goals

### Sign-in methods (server-wide)

Six methods, each switched on or off for the whole server in Hub Settings →
Sign-in (with its strength, and how many people have it set up):

| Method | Strength |
|---|---|
| Password | 1.0 |
| Passkey (phone / laptop, synced) | 2.5 |
| Browser certificate (a file installed in a browser / OS) | 2.5 |
| Device-bound passkey (Windows Hello, a TPM: stays on one computer/phone) | 3.0 |
| Security key passkey (certified hardware key, e.g. a YubiKey touch) | 3.5 |
| YubiKey certificate | 4.0 |

People can set up and use only methods that are on. A method that is off is
neither offered nor accepted. A method an enabled template needs can't be
switched off (the dialog lists the templates and apps; change them first),
the same rule as for templates in use. Whether browsers are asked
for a client certificate at all follows the switches (no certificate method on
→ no certificate request); today's `.env`-only `MTLS_ENABLED` goes away.

### Templates

- A template is a named rule: a tree of groups, each **"all of"** or **"any
  of"**, holding methods and other groups — any combination, e.g.
  ((password AND YubiKey touch) OR (YubiKey AND passkey)) AND a certificate.
  Groups nest up to 3 levels. The editor shows the rule as nested boxes and
  as one plain-English sentence, both updated live (mockup
  `signin-nested-rule.html`). A method entry may itself be a family
  ("YubiKey (touch or certificate)", "Certificate (YubiKey or browser)",
  "Passkey (any kind)") = an "any of" of those methods.
- Built-in templates ship (Basic, Standard, Strong, YubiKey + certificate);
  admins can edit them and add their own ("+ New template").
- Each template can be switched on or off; only enabled ones appear in the
  drop-downs. A template in use (by the default or any app) can't be switched
  off.
- **Score**, per template, shown everywhere as "2.9 / 5" with a one-line
  reason, computed over the tree: an "all of" group scores its strongest part
  + 0.4 per extra part (max 5); an "any of" group scores its **weakest** part;
  a method scores its strength. Updated live in the editor.
- The editor shows who it would affect ("2 people can't sign in to
  Nextcloud · family with it: bob (password only), dave (no method yet)").

### Default and per app

- One Portcullis-wide default template (Settings → Sign-in).
- Every app instance picks "Default (Standard · 2.5 / 5)" or another enabled
  template — one drop-down on the instance page (Settings tab).
- Core pages (Hub, people.<domain>, portal, …) are governed the same way
  (default unless assigned).

### Warnings

- **Admins**: wherever a template is applied (instance page, template editor,
  Settings), members of the app's users/admins groups who have no method set
  that satisfies it are listed.
- **People**: opening an app they can't meet shows a page instead of a failed
  sign-in: "Gitea needs a stronger sign-in — you signed in with a password;
  Gitea accepts any one of: a passkey (you don't have one yet) · a YubiKey
  certificate …" with "Set up …" buttons and a link to Sign-in methods.

### Sign-in methods page (people.<domain> → Sign-in)

For every person (admins see the same page for anyone, from People → person):

- **Always reachable**: the Sign-in page and the "needs a stronger sign-in"
  page open with any enabled method, whatever template governs
  people.<domain>.
- **Adding a stronger method from a weaker sign-in** (e.g. a password-only
  session registering a security key) is a Settings switch the admin decides
  (off = a person can only add methods as strong as the one they signed in
  with; anything stronger needs help from an admin or manager).
- **Help to reset**: admins, and the delegated managers of a group the person
  is in (People delegation), can send a setup link and remove the person's
  methods; recorded in the person's history and the audit log.
- Only enabled methods are listed, each with its state and actions:
  password (set / change / remove), passkeys and security keys (list, + Add),
  YubiKey certificate (validity, renew), browser certificate (create/download
  `.p12`, list, revoke own). A method off on the server shows "off on this
  server".
- "Apps and what they need": each of the person's apps with its template and
  ✓ / ✗.
- **Sign-in history** (from the draft: successes, failures, step-ups, every
  method used, score, app, IP, browser; impersonation entries included).
- Admin-only actions on someone else's page: issue a certificate for a
  YubiKey (CSR), revoke any certificate, send a setup link, remove passkeys,
  reset password, "Sign in as <person>…".
- `enroll.<domain>` stops being a site of its own: its user list and pages go
  away; setup links (`/invite/*`) and certificate issuing stay as back-end
  services behind this page. The step-up page links here.

### Browser certificates

As the draft's goals 1–3 and rulings: a person creates a certificate for
themselves after a fresh passkey/YubiKey touch; the server generates the key,
a **separate issuing CA** (`pki_file`) signs it, the person downloads a
password-protected `.p12` once (the key is never kept). Admin-set limits:
maximum lifetime (≤ core's `CLIENT_CERT_TTL`), active certificates per person,
history retention. Revocation (own, or any for admins) is enforced as today
(CRL / delta CRL). Revoked certificates show as revoked everywhere.

### Telling the methods apart

- Browser certificate vs YubiKey certificate: by issuing CA (`pki_file` vs
  `pki_int`), as the draft ruled.
- Passkeys, at registration, by attestation checked against the FIDO
  Alliance's signed metadata (MDS) the Hub fetches and verifies regularly:
  **security key** = a FIDO-certified roaming authenticator whose key is in
  hardware (secure element); **device-bound** = a platform authenticator
  (Windows Hello, TPM, …) whose key can't leave the device; **synced** =
  everything else, including passkeys without attestation (iCloud, Google,
  1Password). A model missing from the metadata counts as the weaker kind
  until the list knows it (fail toward weaker). The kind is fixed at
  registration and shown on the person's Sign-in page.
- The session records **every** method used (not just the strongest), so
  templates with "and" can be evaluated.

### Password

- A real method: set by the person on Sign-in methods (or at a setup link
  when the server allows passwords), reset by an admin. LLDAP passwords stay
  separate only where the docs already say so (LLDAP's own UI, LDAP-bind
  apps) — the builder decides whether the sign-in password and the LLDAP
  password are one.
- A password alone satisfies only templates that include it.

### Impersonation (full)

An admin can sign in as another person and act in their apps.

- Only `lldap_admin` members; never on another admin or the Hub's service
  account. A Settings switch turns the feature off (on by default).
- Starting it needs a fresh YubiKey touch by the admin and a typed reason.
  It ends after 30 minutes or on Stop.
- While it runs, every Portcullis page (portal, My apps, People, sign-in
  pages) shows "You are signed in as alice (by root) · reason · N min left ·
  Stop". Apps themselves can't show it (accepted).
- Apps that keep their own sessions (e.g. Nextcloud) may outlast the 30
  minutes / Stop and aren't fully tracked under "apps opened" — accepted;
  the person's history says so.
- The person's sign-in history shows who, when, the reason and the apps
  opened; the admin audit log the same; the person sees it at their next
  sign-in ("root signed in as you on … : reason"). No approval step.

### Clear names (everywhere: Hub, people, sign-in pages, docs)

- **Website certificate (HTTPS)** — the padlock; Let's Encrypt (staging while
  testing). People never handle it.
- **YubiKey certificate** — a sign-in certificate stored on a YubiKey.
- **Browser certificate** — a sign-in certificate installed in a browser/OS
  (a downloaded file).
- **Internal certificate authority** — admin / troubleshooting pages only.
- "Enrol" is used only for adding a sign-in method (the Hub's "Enroll domain"
  is renamed).

## Non-goals

- Writing a certificate to a YubiKey from the browser (browsers can't write
  PIV; the CLI stays for that, plus the admin CSR action).
- An impersonation banner inside apps.
- Migration of existing policies or certificates (no installs).

## Anti-goals

- A method or template the admin switched off still being accepted.
- A browser certificate or synced passkey passing a rule that needs a
  YubiKey.
- A password satisfying a template that doesn't list it.
- Impersonation without a fresh hardware touch, a reason and a record the
  person can see.
- Private keys stored, logged or re-downloadable after the `.p12` download.
- Disabling a template still in use.

## Calls I made (check these)

1. **Scoring weights** as in the table; "any of" = weakest part, "all of" =
   strongest part + 0.4 per extra part, max 5. One table in the Hub and the
   docs.
2. **Built-in templates**: Basic (any method), Standard (any passkey or any
   certificate — default), Strong (YubiKey touch or YubiKey certificate),
   YubiKey + certificate (both, off until switched on). Editable. Core pages
   (Hub, people.<domain>) start on **Strong**, not the server default: they
   control everything else.
3. **Rule depth**: groups nest up to 3 levels (any rule a person can still read at a glance).
4. **Synced vs hardware passkey** decided at registration by attestation /
   AAGUID; unknown = synced (fail toward weaker).
5. **Impersonated sessions** meet a template only if the admin's own current
   session methods (incl. the fresh YubiKey touch) would; certificate checks
   (the mTLS binding) use the admin's certificate, not the person's.
6. **Native-OIDC apps** (enforced at login through `acr` only): where
   Keycloak can enforce the template exactly (per-client flow), it does;
   otherwise the Hub asks for a **stricter** level, never a weaker one, and
   lists who that locks out.
7. **No admin lock-out**: the Hub refuses a save (template edit, method
   switch, Hub/People template change) that would leave no `lldap_admin`
   member able to meet the Hub's template; the admin setup link offers a
   security key first; a CLI recovery (`./portcullis signin reset-core`,
   name the builder's) puts the Hub and people.<domain> back on Standard.
8. **Build in three parts**: (1) methods, templates, scores, default/per app,
   warnings, password; (2) Sign-in methods page, browser certificates,
   history, enroll retired, clear names; (3) impersonation.

## Left to the builder

- How methods are encoded end to end (Keycloak flows / required actions /
  acr–amr values, group-gate evaluation of templates against a session's
  methods, step-up for a missing method, oauth2-proxy allow-lists, mcp-gate
  `min_loa`, fresh-auth rules) — contract first.
- Keycloak mechanics for impersonation and its time limit; how the banner
  reaches core pages.
- Password policy (length, breach list) within Keycloak's options.
- Policy file / contract versioning (no back-compat needed).
- UI layout within the two mockups
  (`.superpowers/brainstorm/98502-1794260205/content/signin-settings.html`,
  `signin-people.html`).
