# Authenticator-app codes (TOTP) as a sign-in method — design

Status: queued at the user's request ("sign-in with authenticator-app codes:
Google Authenticator, Authy, 1Password and the like"). Written by the
assistant without a brainstorming round. Every decision marked
**(assistant's call)** is for the user to review; everything else follows
from rulings already in the sign-in methods spec
(`2026-11-09-sign-in-methods-design.md`), contract §8.1 / §8.2 and the
memory `signin_methods_2026_11`. Open questions are in §15, each with a
default.

## 1. Why

Today the only method that needs no special hardware and works on any phone
is the password (1.0), and the next step up is a passkey. Some people (and
some apps' audiences) have a phone with an authenticator app but no passkey
support they trust, or share a computer where a synced passkey isn't wanted.
For them "password **and** a 6-digit code" is a real improvement over a
password alone, and it is what they already know from other sites.

Keycloak 26.8.1 ships everything needed for the codes themselves: the `otp`
credential type, the realm OTP policy, the `CONFIGURE_TOTP` required action
(QR code + manual key), the OTP form authenticator, single-use code
protection and brute-force counting. What it can't do stock is fit our
model: the methods file, `pc_method`, templates, the add-stronger cap, the
history details and the fresh-auth claim. That is the extension's job, the
same way it wraps the stock passkey and X.509 authenticators.

## 2. Goals

1. A seventh method, **`totp`** ("Authenticator app"), switched on or off in
   Hub Settings → Sign-in like the others, **off at the start**.
2. Templates can use it, but only **next to another method** (`all of`): it
   never identifies a person and never is a way in on its own.
3. People add, replace, rename and remove their authenticator apps from the
   Sign-in page on `people.<d>`; the secret lives only in Keycloak and the
   person's app.
4. Admins and `sign_in_help` holders can remove a person's authenticators
   and send a setup link that sets one up (lost phone).
5. Every reader (group-gate, mcp-gate, the extension, the Hub) knows the
   method from one table and one set of shared vectors.
6. The Sign-in page lists the authenticators; history shows code sign-ins,
   wrong codes, and adds/removals.

## 3. Non-goals (assistant's call)

- **HOTP** (counter-based codes), SMS or e-mail codes, push approval
  (Authy/Duo-style "approve on your phone"). Only time-based codes.
- **Recovery codes** (Keycloak's `recovery-authn-codes`). They would be an
  eighth method with its own score and enrolment; recovery stays "another
  authenticator, another method, or a setup link" (§6.5). Parked.
- **Per-template or per-person code parameters** (digits, period,
  algorithm). One realm policy (§7.2).
- **Importing existing secrets** from another system (no installs to
  migrate, and a secret that was ever outside Keycloak is a weaker secret).
- **Codes on MCP device or CLI flows** beyond what the browser sign-in
  already gives (an MCP client's token carries `otp` in `amr` when the
  person typed a code in the browser; nothing else).

## 4. Anti-goals (never)

- The TOTP secret in the Hub, enroll, group-gate, a log line, the audit,
  an error, argv, an environment variable, an e2e artifact or a Playwright
  trace. It is created by Keycloak, shown once as a QR code and manual key on
  Keycloak's own page, and stored only in Keycloak's database.
- A code alone signing anyone in, or a rule with a code-only way in being
  saved or accepted by any reader.
- A code accepted twice, or a code from outside the look-ahead window.
- A switched-off `totp` being offered, accepted or set up.
- A password-only session adding an authenticator while `add_stronger` is
  off (that is how a stolen password becomes a stolen second factor).
- An administrator, while signed in as someone else, adding or removing that
  person's authenticator, or being asked for that person's code.
- Code sign-in for `admin` or `portcullis-hub`.

## 5. The method

### 5.1 Table row

| id | Label | Strength | amr | Where it comes from |
|---|---|---|---|---|
| `totp` | Authenticator app | 1.5 | `otp` | Keycloak credential type `otp` (the realm OTP policy, §7.2), checked by the extension's `portcullis-otp` execution |

- **id `totp`, label "Authenticator app"** (assistant's call). People-facing
  copy says "a code from your authenticator app"; "TOTP" appears only on
  admin/troubleshooting pages and the docs.
- **amr `otp`** (assistant's call): RFC 8176's registered value for a
  one-time password, and what other IdPs use for it. Unique in the table.
- **Strength 1.5, tenths 15** (assistant's call). Above a password alone (a
  second, possession factor; online guessing is rate-limited), well below a
  synced passkey (2.5): a code is **phishable** (a fake page relays it within
  30 s), the secret is a shared secret the server stores, and authenticator
  apps can sync and export it. Ordered in the table between `password` and
  `passkey_synced`, which also fixes the canonical order of `pc_methods` /
  `pc_session` and the Sign-in page:
  `password, totp, passkey_synced, browser_cert, passkey_device,
  security_key, yubikey_cert`.
- **Score effects:** `all[password, totp]` = 1.5 + 0.4 = **1.9 / 5**;
  `all[passkey_synced, totp]` = 2.9; `all[security_key, totp]` = 3.9. The
  one-line reason for a rule whose best part is `totp` names the weakness:
  "codes can be typed into a fake site".
- **No family contains `totp`** (assistant's call): `family:passkey`,
  `family:yubikey`, `family:certificate` stay as they are, so no existing
  template starts accepting codes.

### 5.2 Never a sole factor (assistant's call)

A code proves possession of a phone, not who the person is: the OTP form
needs a known user, and a 6-digit code space is small. So:

- **Grammar rule:** every alternative of a rule (its any-of-all-of form,
  §8.1 "Alternatives") must contain at least one method other than `totp`.
  The Hub checks it on the **uncompiled** rule with every method counted as
  on (so a later switch can't create a code-only way in) and refuses a save
  with `400` "an authenticator code can't be the only way in: combine it with
  another method (all of)". The editor shows the error on the offending
  group live.
- **Readers refuse it too:** a compiled rule with a `{totp}` alternative is
  refused by group-gate, mcp-gate and the extension (fail closed, the same
  as any other invalid rule), pinned by a `reject` vector.
- **In Keycloak** `portcullis-otp` never identifies: it steps aside
  (`attempted`) unless this authentication already has its user (a step-up,
  a `portcullis-template` step, a re-authentication) — §7.1.

### 5.3 Core consoles and administrators

- **Defaults never accept it alone** (follows from §5.2 and the built-ins):
  `hub` and `people` start on Strong (security key or YubiKey certificate),
  the other core pages on the default (Standard, passkeys or certificates).
  Neither names `totp`.
- **Warning, not refusal** (assistant's call): when the `hub` or `people`
  core pick has an alternative made only of `password` and `totp`, Settings
  → Sign-in shows "The Hub can be opened with a password and a code: both
  can be phished" next to the pick. The admin's call stays the admin's, as
  for passwords; the lockout guard counts `totp` like any method.
- **`admin` and `portcullis-hub`** can't set up or use codes (assistant's
  call): the same fixed list as the password form, in `portcullis-otp` and
  the `CONFIGURE_TOTP` override, not counted by brute force, and the Hub
  never counts `totp` for them.

### 5.4 Built-in template (assistant's call)

A fifth built-in, `password-and-code` "Password + authenticator code"
(`all` of `password`, `totp`; score 1.9), **disabled** at the start like
Basic. It can't be enabled while either method is off (the existing
"doesn't compile" rule). No other built-in changes.

## 6. Enrolment and recovery

### 6.1 Where the secret is made (assistant's call)

All enrolment runs in **Keycloak**, as an application-initiated action
(AIA) of the people listener's fresh-auth client (`portcullis-fresh-auth`,
redirect back to `https://people.<d>/signin`), never through the Hub's API.
Keycloak generates the secret (`HmacOTP.generateSecret`, 20 random bytes =
160 bits, RFC 4226's recommended length), renders the QR code
(`otpauth://totp/…?secret=…&issuer=…` as a server-side PNG) and the manual
key on its own page, and stores the credential. The Hub only links to it and
reads the inventory afterwards. This keeps the secret out of the Hub's
process, logs, audit and answers by construction, the same way passkey
registration already runs in Keycloak.

- **Issuer and account label** (assistant's call): issuer = the main domain
  (`portcullis.example.com`), account = the username, so the app's entry
  reads "portcullis.example.com: alice". Set through the realm's display
  name / OTP policy as Keycloak allows; the builder checks what 26.8.1 puts
  in the `issuer` parameter and the label.
- **Theme:** the `portcullis` login theme gets a copy of keycloak.v2's
  `login-config-totp.ftl` only if needed to (a) prefill a unique device name
  "Authenticator <date time>" (the passkey lesson: Keycloak refuses a second
  credential with the same label) and (b) name the apps that work with the
  policy (Google Authenticator, Microsoft Authenticator, Authy, 1Password,
  Bitwarden, FreeOTP, Aegis, Raivo). Keep the copy in sync with the image's
  Keycloak version, as for `webauthn-register.ftl`.

### 6.2 The `CONFIGURE_TOTP` override (extension)

The extension overrides the stock `CONFIGURE_TOTP` required action
(`order()` 1, server-info operational info `portcullis: totp`, smoke-checked;
the same pattern as `webauthn-register`), wrapping the stock action and
adding, before the stock code stores anything:

1. refused while `totp` is off (message key `portcullisTotpOff`);
2. refused for `admin` / `portcullis-hub`;
3. refused in an impersonated session (`ImpersonationGuard`);
4. the **add-stronger cap**: with `add_stronger` off and no `inv` in the
   session, refused unless the session's strongest switched-on method
   (user session + this authentication, as for passkeys) is at least 1.5.
   A password-only session therefore can't add an authenticator; a
   password + code session can replace one; any passkey or certificate
   session can add one (assistant's call: the existing cap rule, applied
   unchanged);
5. **at most 3** `otp` credentials per person (assistant's call: a phone, a
   spare phone, a password manager); the fourth is refused with "you already
   have 3 authenticator apps: remove one first";
6. **replace**: the AIA parameter `CONFIGURE_TOTP:replace:<credentialId>`
   (Keycloak's parameterised AIA, as `delete_credential:<id>`) names one of
   the person's own `otp` credentials; when the new code verifies, the stock
   action stores the new credential and the override deletes the named one
   in the same transaction. A foreign or unknown id refuses before the QR is
   shown.

Every refusal is a page with the message and a link back to the Sign-in
page; nothing is stored. The override logs only the username, the
credential id and the outcome.

### 6.3 Freshness (assistant's call)

Add, replace and remove need a **sign-in within the last 300 s in this
authentication**: the AIA's `max_auth_age` is 300 s for `CONFIGURE_TOTP`
and `delete_credential` (pushed by `keycloak configure`), so Keycloak
re-authenticates the person first. The re-authentication may use any method
the person has (`portcullis-template` passes the unlisted fresh-auth
client); what stops abuse is the cap (adding) and that removing only removes
access. This is the passkey model, not the certificate model: certificates
need the `people` template because the Hub issues them; codes are created by
Keycloak under the same cap as passkeys.

### 6.4 The Sign-in page (people.<d> → Sign-in)

- The `totp` row lists each authenticator: label, added date
  (Keycloak `createdDate`), and **Rename**, **Replace**, **Remove**; with
  **+ Add authenticator app** below (hidden when 3 exist or `totp` is off;
  "off on this server" when off). With the cap in force and a session too
  weak, + Add shows "ask your admin for a setup link" instead, the same
  copy as for passkeys.
- **Add / Replace** open the AIA (`kc_action=CONFIGURE_TOTP[:replace:<id>]`)
  in the fresh-auth popup; on return the page refreshes the inventory
  (`refresh=1`, bypassing the 30 s throttle once for the caller).
- **Remove** opens the stock `delete_credential:<id>` AIA (Keycloak's own
  confirmation and re-authentication); before opening it the page lists the
  caller's apps that would then need a stronger sign-in ("Nextcloud needs a
  password and an authenticator code").
- **Rename** is a Hub route, as for passkeys (§9).
- Read-only while impersonated (`RefuseWhileImpersonated`; the AIA override
  refuses too).
- The account console's own "Authenticator application" section stays
  reachable and runs through the same override and `delete_credential`, so it
  can't bypass any rule.

### 6.5 Lost phone and help

- **Self-service:** a second authenticator (the page recommends one after
  the first is added), or any other method at least as strong (a passkey or
  certificate session can add a new one and remove the lost one).
- **Help** (admins, and `sign_in_help` holders on people they may target):
  **Remove authenticator apps** (all of the person's `otp` credentials,
  through the Keycloak admin API, then signs the person out of Keycloak, as
  `remove-passkeys` does), and the existing **Send a setup link**. Audited
  `user.remove_authenticators` (detail `<n> removed`, `as sign_in_help` for
  a holder); in the person's history as `help`. Never on an administrator
  for a holder; an administrator on another administrator needs the typed
  confirmation, as for passkeys (assistant's call: the same targets and
  rules as `remove-passkeys`).
- **Setup links** (assistant's call): an invite may ask for an authenticator
  (`authenticator: true` on `POST /internal/invites` and the Hub's invite
  dialog, offered only while `totp` is on). Redeeming then adds
  `CONFIGURE_TOTP` next to (or, for a password onboarding, after) the
  password / passkey step. A setup-link session (`inv`) has no cap, so a
  password-only person can be given their first authenticator this way.
  `./portcullis invite <user> --replace-keys` ("lost devices") also deletes
  the person's `otp` credentials.

## 7. Keycloak

### 7.1 The `portcullis-otp` execution

- A new provider `portcullis-otp` that **wraps** (not extends) the stock
  `OTPFormAuthenticator` and is not a `CredentialValidator` (assistant's
  call; the part-1 lesson: Keycloak's selection runs credential
  authenticators after plain ones, so a credential validator lands in an
  unpredictable place in "Try another way").
- **Flow:** `portcullis-signin` gains ALTERNATIVE `portcullis-otp` (config
  `otp-config`, `default.reference.value` `otp`, `default.reference.maxAge`
  36000) after the password form. The builder confirms the position with
  the smoke run; the rule is what matters, not the slot.
- **Steps aside** (`attempted`) unless all hold: `totp` is on; the user is
  already known in this authentication; the user has an `otp` credential;
  the user isn't `admin` / `portcullis-hub`; `pc_method` is absent or
  `totp`. It never shows a username field.
- **When it runs:** a `portcullis-template` step asking for `totp`
  (`all[password, totp]` met step by step: password, then the code); a
  group-gate step-up with `pc_method=totp` (`auth-cookie` hands the SSO
  session over with its user set); a re-authentication (AIA, fresh auth).
  "Try another way" lists it only in those cases.
- **On success** it writes `totp` to the authentication note
  `portcullis.otp.method` (read by `portcullis-fresh`, below) and the
  reference `otp` lands in `amr` through the stock amr mapper.
- **On failure** it adds `pc_method=totp` and `pc_ua` (`History.onFailure`)
  before the stock `invalid_user_credentials` error, which Keycloak's brute
  force counts.
- **Step-up candidates:** `portcullis-template` treats `totp` as completable
  when the person has an `otp` credential (from Keycloak, so it is known,
  unlike a password).
- **`pc_method`:** `totp` joins the ids `PcMethod`, group-gate's
  `STEPUP_METHODS` and oauth2-proxy's `loginURLParameters` allowlist accept.
- **`pc_fresh`:** `totp` is a valid value (from `portcullis.otp.method`).
  Strength order for "several methods in one authentication":
  `yubikey_cert` > `security_key` > `passkey_device` > `browser_cert` >
  `passkey_synced` > `totp` > `password`. The fresh-auth popup may pass
  `pc_method=totp` when the governing template's accepted fresh methods are
  `totp` alone. Under `all[password, totp]` the accepted fresh method is
  `totp` (the strongest of the one alternative), so a confirmation inside a
  live session is one typed code (assistant's call: the existing
  "strongest method of an alternative" ruling, unchanged).
- **Certificates:** `totp` never approves a new certificate (§5.1 "Fresh
  auth for adding a certificate" gains `totp` next to `password` and
  `browser_cert`; `cert_fresh` never lists it) (assistant's call: phishable).

### 7.2 Realm OTP policy (assistant's call)

`keycloak configure` pushes, reads back and fails on a difference (the
passkey-policy lesson: check the PUT actually took):

| Setting | Value | Why |
|---|---|---|
| `otpPolicyType` | `totp` | time-based only |
| `otpPolicyAlgorithm` | `HmacSHA1` | the only algorithm every common app honours (below) |
| `otpPolicyDigits` | 6 | the same |
| `otpPolicyPeriod` | 30 | the same |
| `otpPolicyLookAheadWindow` | 1 | ±1 step (±30 s) of clock drift, Keycloak checks both sides |
| `otpPolicyCodeReusable` | `false` | replay protection (below) |
| `otpPolicyInitialCounter` | 0 | unused for TOTP, pinned so the read-back is exact |

- **Why SHA-1 / 6 / 30.** Google Authenticator (Android) and Microsoft
  Authenticator ignore or reject `algorithm`, `digits` and `period` in the
  QR code and always compute HMAC-SHA1, 6 digits, 30 s; other apps support
  more but not uniformly. A policy any app gets wrong produces codes that
  never match, with no error at enrolment until the verify step. HMAC-SHA1
  is not weakened by SHA-1's collision attacks: HOTP/TOTP security rests on
  HMAC being a PRF, which collisions don't break (RFC 4226 §A, RFC 6238).
  The weak point of TOTP is phishing and the 10⁶ code space, not the hash.
- **Look-ahead 1.** Three codes are valid at a time (previous, current,
  next): ±30 s of phone clock drift, a minimal guessing surface. Server
  clock drift is checked by `status` (§11).
- **Replay.** With `otpPolicyCodeReusable: false` Keycloak records each
  accepted code in its single-use object store for the code's lifetime and
  refuses it again, across the cluster. Pinned by an e2e case (§12).
- **Brute force.** The realm's existing protection counts wrong codes
  (failureFactor 10, waitIncrementSeconds 60, maxFailureWaitSeconds 900,
  never permanent). A guesser must already have the password (a code never
  stands alone) and gets at most about 96 tries an hour once the wait is at
  its cap: with 3 valid codes in 10⁶, about 0.03 % an hour, 0.7 % a day. Not
  enough on its own, so wrong codes are surfaced (history "wrong
  authenticator code", the doctor's `signin_totp_guessing`, §11) and the
  advice there is to change the password. No permanent lockout (assistant's
  call: it would let anyone who knows a password lock the person out of
  every method).
- **AIA `max_auth_age`:** 300 s for `CONFIGURE_TOTP` and `delete_credential`
  (§6.3).

### 7.3 Status and smoke

- `./portcullis status` checks the OTP policy and the two AIA settings
  (`keycloak.otp_policy` in `--json`, `portcullis_keycloak_otp_policy_ok`
  in `--textfile`), next to the passkey policy line.
- The extension's smoke run: `CONFIGURE_TOTP` override present (operational
  info), a code sign-in with a TOTP library on `smoke-realm.json` (copied
  from core's `realm-export.json`, as always), replay refused,
  `pc_method=totp` asks only for the code.
- `PROVIDER_IDS` gains `portcullis-otp` and `CONFIGURE_TOTP`.

## 8. Policy

- **Method switch:** Settings → Sign-in lists "Authenticator app · 1.5 · N
  of M people set up", off at the start, switchable like any method
  (`Info.Available` true). Switching it off is refused while an enabled
  template needs it (existing rule). Switched off, existing `otp`
  credentials are **kept** (assistant's call): they stop being offered and
  counted, and work again when it is switched back on.
- **Templates:** the editor offers "Authenticator app" as a method; the
  sentence says "a password and a code from an authenticator app"; §5.2's
  refusal is shown live.
- **Needs-stronger copy** (group-gate's page and `portcullis-needs-stronger
  .ftl`, one wording): "Nextcloud needs a stronger sign-in — You signed in
  with a password. Nextcloud accepts: • a password and a code from an
  authenticator app — you don't have an authenticator app yet [Set up an
  authenticator app]". The button links to the Sign-in page, or reads "ask
  your admin" when the cap would refuse (§6.2 step 4). A session that has
  the password and an authenticator set up gets the step-up (`pc_method=
  totp`), not this page.
- **Readers** (one table, §5.1):
  - group-gate: `AMR_TO_METHOD["otp"] = "totp"`, `METHOD_TENTHS["totp"] = 15`,
    `METHOD_IDS`, `STEPUP_METHODS`, the §5.2 `reject`. No certificate
    binding (it isn't a certificate).
  - mcp-gate: the same row; `totp` **counts** on MCP (the browser sign-in
    behind the token typed the code; unlike certificates there is nothing
    the MCP request would have to present).
  - the extension: `Methods`, `PcMethod`, `Rule.parse` (seven leaf ids).
  - the Hub: `internal/signin` (table, families unchanged, scores, the
    §5.2 check, sentences).
- **Shared vectors** (`internal/signin/testdata/vectors.json`, byte-copied
  to core `tests/signin_vectors.json` and the extension): `all[password,
  totp]` met by `["pwd","otp"]`, not by `["pwd"]` or `["otp"]`; its
  alternatives `[["password","totp"]]`; score 19; `any[totp,
  security_key]` → `error` (code-only way in); a compiled
  `{"op":"any","items":["totp","security_key"]}` → `reject`; with `totp` off
  `all[password, totp]` → `ErrUnmeetable`; `inv` + `otp` → `totp` only.
- **Versions** (assistant's call): no version bump of the policy file, the
  gate file or `signin-keycloak.json`. A reader that doesn't know `totp`
  already refuses it (unknown method → deny), and the Hub writes `totp` only
  once it is switched on, which is after everything is upgraded. Merge order
  as usual: docs → keycloak (edge) → hub (edge) → templates → core.

## 9. Inventory, history, API

- **Inventory:** Keycloak credential type `otp` → `totp` set (one or more
  credentials, not a reserved account, method on). `MySignIn`'s `totp` row
  carries `authenticators: [{"id", "label", "created_at"}]` (Keycloak
  credential id, `userLabel`, `createdDate`), omitted when empty, like
  `passkeys`. Counts, warnings, impact and the lockout guard count it like
  any method.
- **Rename:** `PUT /api/me/signin/authenticators/{credentialId}/label`
  (same rules, texts and audit shape as the passkey rename, audited
  `signin.authenticator.label`) (assistant's call: its own route rather than
  widening the passkey one, so a passkey id can't be renamed through it and
  vice versa). The people listener's route count and §4 "Sign-in paths"
  list grow by one; it changes a name only, so no fresh auth.
- **Help route:** `POST /api/directory/users/{u}/remove-authenticators`
  (admins, `sign_in_help`), MCP twin `remove_authenticators` (D), `can`
  gains `remove_authenticators`.
- **History** (§8.2):
  - `LOGIN` with `pc_methods` containing `totp` → `sign_in` / `step_up`
    with the method listed, scored as usual.
  - `LOGIN_ERROR` with `pc_method=totp` and `invalid_user_credentials` →
    `failed`, reason **"wrong authenticator code"** (the error table maps
    by error *and* method; a password keeps "wrong password").
  - Adds, replacements and removals: the Hub's events config also keeps
    Keycloak's credential events for `otp` (`UPDATE_CREDENTIAL` /
    `REMOVE_CREDENTIAL` with `credential_type=otp`; the builder checks the
    26.8.1 names, the older `UPDATE_TOTP` / `REMOVE_TOTP` are deprecated)
    → a new kind **`method`** with detail "authenticator app added: <label>"
    / "replaced" / "removed" (assistant's call: a new kind rather than
    stretching `certificate`). By the person → `method`; by an admin or
    holder → `help` (from the audit, as now).
  - No entry holds a code or a secret.

## 10. Backups, restore, impersonation

- **Backups:** the secrets are in Keycloak's PostgreSQL database
  (`pg_dump` in core's backup), stored as Keycloak stores them (in clear in
  the credential row, because the server must compute codes). A backup was
  already as sensitive as the host; the docs' backup page adds "it also
  holds every authenticator app's secret: whoever has it can generate
  codes" (assistant's call: no extra encryption layer; restic's off-host
  encryption stays the protection).
- **Restore:** restoring an older backup brings back authenticators removed
  since (a lost phone works again). `./portcullis restore` prints that line,
  and the docs' restore checklist says: re-remove authenticators reported
  lost after the backup's date (assistant's call: a warning, not
  automation; the Hub's audit is restored to the same point and can't tell).
- **Instance backups** (§11.5) are unaffected (no secrets of Keycloak's in
  them).
- **Impersonation:** an impersonated session meets a template only if the
  administrator's own session methods would (part 3 ruling): an app needing
  `all[password, totp]` stays closed unless the administrator's own session
  has both, and the person's code is never asked for. While impersonated,
  `CONFIGURE_TOTP`, `delete_credential` on an `otp` credential, the rename
  and the help route on oneself are refused. Starting an impersonation still
  needs the administrator's fresh YubiKey touch (a code never qualifies).

## 11. Doctor and status (assistant's call)

- `signin_totp_policy_drift` (Problem, explain: "run `./portcullis keycloak
  configure`"): the realm OTP policy or the AIA ages differ from §7.2.
- `signin_totp_guessing` (Warning, explain: "change <user>'s password; the
  password was right and the code was wrong <n> times"): 20 or more
  `LOGIN_ERROR` with `pc_method=totp` for one person in 24 h, read from the
  Keycloak events the history already reads. Fingerprint per person per day.
- `signin_totp_reserved` is not needed: the override and the execution
  refuse reserved accounts.
- **Clock:** core `status` adds `system.clock_synced` (the host's
  `timedatectl show -p NTPSynchronized`, or `chronyc tracking` offset
  under 5 s; "unknown" when neither is available), a Warning when not
  synced, since codes fail when the server is more than about 30 s off.
  Always checked, whether `totp` is on or not (other features need a sane
  clock too).

## 12. Tests

- **Hub (Go):** the table, scores (19, 29, 39), the §5.2 check on
  uncompiled rules (nested, through every switch combination), the
  built-in `password-and-code`, inventory mapping (`otp` → `totp`,
  reserved accounts never), the rename route (404 for a passkey id, 409
  duplicate), the help route (targets, audit), history mapping (wrong code,
  `method` kind), impact, the lockout guard with `totp`, the needs-stronger
  copy, the vectors.
- **group-gate / mcp-gate:** the vectors, `otp` mapping, `pc_method=totp`
  step-up URL, the `reject` case, mcp-gate counting `totp`.
- **Extension (unit):** `portcullis-otp` skip rules (off, no user, no
  credential, reserved, `pc_method` other), the note, the failure details,
  `CONFIGURE_TOTP` override (off, reserved, impersonated, cap with
  `pwd` / `pwd+otp` / `spk` / `inv`, the fourth refused, replace own /
  foreign id), `pc_fresh` ordering, template candidates.
- **Core e2e (`e2e-signin`, Python Playwright + `pyotp`** pinned with
  hashes in the e2e requirements; assistant's call: a mature RFC 6238
  library, never a hand-rolled HMAC): `totp` switched on in setup, an
  instance `echo-otp` on template `e2e-otp` = `all[password, totp]`. The
  test reads the secret from Keycloak's manual-key element, `::add-mask::`s
  it, and hides the QR / key element (CSS) before any screenshot; it never
  prints or stores it. Cases:
  - pat's password-only session: + Add refused by the cap (`add_stronger`
    off); with a setup link (`authenticator: true`) the authenticator is
    set up;
  - pat opens `echo-otp`: password, then the code step (`pyotp.TOTP(secret)
    .now()`), amr `pwd`+`otp`, `LOGIN` `pc_methods` `password,totp`;
  - SSO step-up: pat's password session on another app, then `echo-otp`
    → step-up `pc_method=totp` asks only for the code;
  - wrong code → `failed` "wrong authenticator code", brute-force count 1;
  - replay: the same accepted code on a second sign-in in the same step
    → refused;
  - window: `totp.at(now − 30)` accepted, `totp.at(now − 90)` refused;
  - fresh auth under `e2e-otp` (a file-share password on `echo-otp`, if the
    echo template has one, else a companion confirmation) with one code
    → approved; certificate creation with `pc_fresh=totp` → 409;
  - replace (new secret works, old one refused), rename, remove via
    `delete_credential`; the fourth add refused;
  - carol (`sign_in_help`) removes alice's authenticators; root impersonating
    pat can't open `echo-otp` and gets a refusal on Add;
  - the template editor refuses `any[totp, security_key]` (400 text);
  - `admin` gets no code step and can't open `CONFIGURE_TOTP`;
  - the realm OTP policy read back equals §7.2;
  - **no secret anywhere:** after the run, the secret (and its
    lowercase/no-padding forms) is absent from `docker compose logs`, the
    Hub's audit file and the history answers;
  - everything restored in a `finally` (method off, template and instance
    removed).
- **Templates repo:** CI re-run after core (policy harness unchanged
  unless it lists method ids; then it gains `totp`).

## 13. Contract and docs changes

- §8.1: the table row, starting state, families note, §5.2 grammar rule,
  the built-in, `portcullis-otp` and the `CONFIGURE_TOTP` override in the
  provider table and flows, the OTP policy, `pc_method` ids, `pc_fresh`
  values and order, the certificate fresh-auth exclusion, the inventory.
- §8.2: the error-by-method mapping, the `method` kind, the credential
  events.
- §5 / §5.1: the needs-stronger copy, the Sign-in page row, the rename
  route, the route count.
- §9.4 invites (`authenticator`), §9.6/§9.7 the help route and `can`,
  §14.5 the doctor kinds, §15.10 the MCP twins.
- Docs site: Sign-in methods page (what codes are good and bad for, the
  supported apps, lost phone), backups/restore notes, the admin guide's
  "Password + authenticator code" template. Core `CLAUDE.md` "Sign-in
  methods" bullet, the extension's `CLAUDE.md` provider list.

## 14. Left to the builder

- The exact AIA mechanics in 26.8.1: the parameterised `CONFIGURE_TOTP`
  action, `max_auth_age` per action, and that a re-authentication keeps the
  user so `portcullis-otp` can run without a password first.
- The slot of `portcullis-otp` in `portcullis-signin` (smoke-verified).
- Keycloak 26.8.1's credential event names and details.
- Whether the theme copy of `login-config-totp.ftl` is needed at all.
- The issuer string Keycloak puts in the QR code.
- Plan split (suggested: one part; contract first, then extension → Hub →
  core → templates CI).

## 15. Open questions (each has a default)

1. **Strength 1.5 vs 1.0.** At 1.0 (equal to a password) a password-only
   session could add an authenticator with the cap on. *Default:* 1.5 and
   the cap applies; the setup link is the way to a first authenticator.
2. **Allow codes for `lldap_admin` members?** *Default:* yes, as an extra
   factor (`all[security_key, totp]` is legitimate); the core templates'
   defaults don't name it, and §5.3 warns.
3. **Recovery codes.** *Default:* parked (§3).
4. **Limit of 3 authenticators.** *Default:* 3, not admin-changeable (add
   it to `sign_in.limits` if asked).
