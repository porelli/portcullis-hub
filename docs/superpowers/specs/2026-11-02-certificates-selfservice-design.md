# Client certificates in the web app, login history, policy scoring

Status: draft for approval (2026-11-02)

## Intent

mTLS today is CLI-only:
- `./portcullis cert enroll|renew|revoke` on the server, onto a YubiKey's
  PIV slot;
- self-renewal at `enroll.<domain>/self`.

Users should manage their own certificates from the web app, see their
sign-in history, and admins should be able to revoke any certificate from the
Hub. Also, the policy "level" (LoA 0–3) should become a meaningful score of
how strong an app's setup is.

## Goals

1. **Downloadable client certificates (`.p12`).**
   - From `people.<domain>`, a signed-in user can create a client
     certificate for themselves.
   - The server generates the key, Vault's PKI issues the certificate, and the
     user downloads a PKCS#12 file protected by a password they choose, to
     install in their browser or OS.
   - They can list their certificates (YubiKey and file, with serial, issued
     and expires) and revoke their own.
2. **One mTLS factor, two key-protection levels.**
   - A `.p12` certificate is still mTLS, but its key is a file, protected only
     by its password. A YubiKey (PIV) certificate's key can't be copied.
   - A policy factor "client certificate" accepts both. The option
     **"hardware key only"** accepts only YubiKey certificates.
   - Whether a file certificate is required, enough or not allowed is up to
     whoever sets the policy (per app, or the default).
3. **Admins manage certificates.**
   - In the Hub, admins see every certificate (user, kind, serial,
     issued/expires, revoked) and can revoke any of them.
   - Revocation is enforced within a minute (CRL/delta CRL, as today).
4. **Login history.**
   - Everyone sees their own sign-ins on `people.<domain>`.
   - Admins see everyone's.
   - Failed attempts are included.
   - Each entry shows: time, result (success/failure + reason), the app or
     page, **every method used** in that sign-in (passkey, client certificate
     with its key protection — YubiKey or file — or several together, e.g.
     passkey + YubiKey certificate), the resulting strength score, IP address,
     and browser.
   - Step-ups (a later prompt for a stronger method during the same session,
     e.g. an app that needs a certificate) are recorded as their own entries,
     showing the method added.
5. **Policy score (0–100).** Every app's effective policy, and the default
   policy, shows a strength score with a one-line explanation, replacing the
   bare LoA level in the UI. Examples of the ordering:
   - public = 0;
   - "passkey or file certificate" < "passkey" < "client certificate
     (hardware)";
   - "passkey and hardware certificate" is highest.

## Non-goals

- Writing certificates to a YubiKey from the browser (browsers can't write
  PIV). The CLI `cert enroll` stays for that.
- Device management beyond certificates (e.g. passkey listing — already in
  Users & Groups for admins).
- Per-app sign-in analytics or alerting.

## Anti-goals

- A downloaded certificate must never pass a "hardware key only" policy.
- Issuing a certificate must not be possible with a stolen session alone.
- Private keys must never be stored server-side after download, logged, or
  re-downloadable.
- Login history must not expose other users' data to non-admins.

## Decided by the user

- `.p12` download (not YubiKey-from-browser).
- One mTLS factor with a key-protection level; the policy owner decides.
- Scoring on a scale, more meaningful than LoA.
- Login history: own for everyone, all for admins, failures included.

## Calls made while drafting (check these)

1. **Fresh authentication to issue a certificate.** Creating or revoking a
   certificate requires a passkey touch right before (Keycloak step-up with
   `max_age`), so a stolen session cookie can't mint a certificate.
2. **Issuing is done by `enroll`.**
   - It already holds the Vault AppRole and owns certificate issuance.
   - It gets a new API for file certificates: generate key → issue → build
     the PKCS#12 with the user's password (a mature library, e.g.
     `software.sslmate.com/src/go-pkcs12`) → return it once → forget the key.
   - The people UI calls it through the Hub, which forwards the signed-in
     user (never a user-chosen subject: the certificate CN is always the
     caller's username).
3. **Marking the key protection.**
   - File certificates are issued from a separate Vault role
     (`client-file`), with a marker in the certificate (OU
     `portcullis-file`, plus a certificate-policy OID).
   - YubiKey certificates keep the existing role, marked OU `portcullis-piv`.
   - group-gate reads the marker from Traefik's forwarded cert info and
     reports the factor as `mtls` with `key=hardware|file`.
   - Keycloak's X.509 login maps a file certificate to a lower level than a
     hardware one, so acr-based apps can also require hardware.
   - Existing certificates have no marker and count as hardware: they were
     issued only via the YubiKey CLI.
4. **Limits.**
   - A file certificate is valid for `CLIENT_CERT_TTL` (default 720 h). Admin specifies the limit, user can select anything up to the limit
   - At most X active file certificates per user. As per admin configured
   - Revoking your own needs the same fresh touch; admins revoke anyone's.
   - Where these are set (controller's call): Hub Settings → Certificates & sign-ins, admins only, audited. Defaults: maximum lifetime 720 h, at most 5 active file certificates per person, sign-in history kept 90 days. The maximum lifetime can't exceed core's `CLIENT_CERT_TTL` (the server-side ceiling enforced by `enroll`); the Hub passes the configured limits with each issuing request and `enroll` re-checks them. The retention applies to both sources: the Hub sets Keycloak's event expiration through the admin API and prunes the group-gate sign-in log to the same window.
5. **Login history source: Keycloak events.**
   - Enable stored login events (`LOGIN`, `LOGIN_ERROR`, `CODE_TO_TOKEN`,
     `LOGOUT`), with X days' retention, configured by `keycloak configure`. As per admin configured
   - The Hub reads them through the admin API (gocloak).
   - The methods come from the session's full amr list (all factors, not just
     the last) plus the cert marker for certificates; step-up events are LOGIN
     events on an existing session and are shown as "step-up".
   - Failures show Keycloak's error code mapped to plain text.
   - Gateway-only denials (group-gate 403s) are not "sign-ins" and are not
     shown in v1.
6. **Score model (deterministic, explained).**
   - Each factor has a strength:
     - passkey 60;
     - file certificate 45;
     - hardware certificate 80.
   - Combinations:
     - "any of" scores the weakest allowed factor;
     - "all of" scores the strongest plus 20 for each additional distinct
       factor, capped at 100.
   - Adjustments:
     - per-request enforcement (forward-auth) +0, at-login-only enforcement
       (native-oidc without protected@file) −10;
     - a public exception −5;
     - a native sign-in (app's own login) shows "app's own sign-in — not
       scored".
   - The UI shows the score and the reason ("weakest accepted: file
     certificate").
   - The exact weights live in one table in the Hub and the docs.
7. **Where it lives in the UI.**
   - `people.<domain>` gets "My certificates" and "My sign-ins".
   - The Hub gets a Certificates tab (admins) and a Sign-ins view per
     person.
   - Policy editors show the score live as the policy changes.

8. **Builder-check rulings (supersede call 3 where they differ).**
   - **Separate issuing CA for file certificates** (`pki_file` intermediate under the same root); YubiKey certificates stay on `pki_int`. "Hardware key only" = trust only `pki_int` — a new Traefik TLS option for mtls-capability apps, Keycloak's X.509 step checks the issuer, group-gate derives `key=hardware|file` from the issuer. No marker/back-compat logic: existing certificates are `pki_int` = hardware. Both CAs' CRLs/delta CRLs are enforced as today.
   - **File certificates never reach `hwk` on their own**: Keycloak maps a `pki_file` X.509 login to a new acr `file` at LoA 1 (below `hwk`); the default policy therefore asks for a passkey on top; only policies that explicitly accept file certificates request LoA 1 for them. `acr.loa.map`, group-gate's `ACR_TO_LOA`, step-up and the oauth2-proxy acr allow-list are updated together (contract change).
   - **Fresh authentication** = a fresh Keycloak sign-in with a passkey or a `pki_int` certificate (never a file certificate), verified by the issuing service on a new ID token (`auth_time` within 5 minutes, `amr`), through its own Keycloak client — not the shared forward-auth session.
   - **Login history**: successes are recorded by group-gate the first time it sees a session (`sid`): user, time, every factor (amr + certificate kind), resulting score, app host, IP, user agent → an append-only log the Hub reads (90 days); failures come from Keycloak `LOGIN_ERROR` events (IP, error; browser shown as unknown). Step-ups appear when an existing session gains a factor.
   - **Renewal keeps the kind**: `enroll /self` renews a certificate on the CA that issued it. Admin `/api/sign` (CLI path) issues hardware certificates without attestation (trusted path; attestation is a possible later addition).

## Left to the builder

- The enroll API shape (bearer secret like the invite API), the PKCS#12
  encryption algorithm (modern AES, compatible with current browsers and
  macOS/Windows import).
- Event-to-row mapping and pagination.
- UI layout within the existing styles.

## Open questions

- None known; the builder check may raise some.
