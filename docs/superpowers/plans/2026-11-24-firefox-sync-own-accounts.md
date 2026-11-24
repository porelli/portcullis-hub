# Firefox Sync + own accounts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A new multi-instance template, `firefox-sync-fxa` ("Firefox Sync + own accounts"), that runs Mozilla's accounts service, Sync storage and the admin UI on the server. Who may have an account follows the template's access group, matched by each person's **verified** Portcullis email.

**Architecture:** Most of the work is the template in `portcullis-templates`. Its services sit on the instance's private `default` network. Isolation uses the existing **Traefik-only nginx gate pattern** of `esphome/gate.sh`: one gate, `fxa-gate`, is the only service on `portcullis-proxy`, and it answers `${PORTCULLIS_TRAEFIK_SOURCE}` only. A long-running `fxa-access-sync` service applies the Hub's data file of verified emails to upstream's `ffs_access` functions, through a `membership_change` hook. The Hub gains six capabilities the design needs and that don't exist yet:
- app mail senders, with Portcullis's own sender among them;
- verified emails on People;
- a `verified_email` option type (verified emails in data files);
- a TLS tier per host for routers without sign-in;
- a reason per host on bypass badges;
- free-disk and setup-form resource warnings.

Core's `mailctl` implements the senders. Core's CI gets the end-to-end test with real mail.

**Tech Stack:** Docker Compose templates (YAML, POSIX sh, nginx, MySQL client, psql), Python 3 validators and tests (PyFxA for the accounts protocol), Go (Hub, mailctl; `github.com/wneessen/go-mail` for the Hub's SMTP submission, a new dependency), vanilla JS (Hub UI), Markdown (contract).

**Spec:** `docs/superpowers/specs/2026-11-24-firefox-sync-own-accounts-design.md` (Hub repo, branch `fxa-design`), including its "Decided after planning" section. Upstream facts: `/Volumes/workspace/firefox-sync-drafts/plans/open-items/portcullis-own-accounts-facts.md`; upstream docs at `porelli/firefox-sync` 7216405.

**Repos and merge order:** docs → Hub (wait for the `edge` image) → core `mailctl` only (its image must exist before the Stalwart pin moves) → templates → core e2e. Every repo works on a branch named `fxa-own-accounts`.

## Rulings (2026-11-24, recorded in the design)

- **D1:** isolation through the existing Traefik-only nginx gate pattern (`esphome/gate.sh`), not per-instance networks.
- **D2 (the user's):** verified emails only. A code proves an email, and an email an admin set counts as verified. This is generic: any email-keyed app can use it (Tasks 1, 2, 3, 4).
- **D3:** the Hub's existing per-instance host naming (§11.3, `<sub>-<suffix>`).
- **D4:** no `admin_paths`. The admin UI is protected by its own host, forward-auth and its OIDC sign-in with the admin group.
- **D5:** `on_membership_change: hook`, never a data-file restart, so Redis isn't wiped.
- **D6:** upstream's figures: `min_memory_mib: 4096`, and `min_disk_gib: 18` (upstream's chart PVCs: accounts DB 8, keys 1, avatars 1, one Sync database 8).
- **D7:** a reason per host on the bypass badges, as a Hub feature (Task 6).

## Global Constraints

- Template id `firefox-sync-fxa`, `name: Firefox Sync + own accounts`, `instances: multi`, `auth.method: forward-auth`, `group_access: true`, `group_admin: true`, `access_group: users_firefox-sync-fxa`, `admin_group: admin_firefox-sync-fxa`. No `admin_paths`.
- Host routers and their default subdomains. Each is one DNS label, never `accounts.<x>`. Other instances get `<sub>-<suffix>` from the Hub (§11.3).
  - `firefox-sync-fxa` → `firefox-sync` (Sync);
  - `firefox-sync-fxa-accounts` → `firefox-sync-accounts`;
  - `firefox-sync-fxa-api` → `firefox-sync-api`;
  - `firefox-sync-fxa-profile` → `firefox-sync-profile`;
  - `firefox-sync-fxa-admin` → `firefox-sync-admin`;
  - `firefox-sync-fxa-pairing` → `firefox-sync-pairing`.
- Open without sign-in:
  - the API, profile, Sync and pairing hosts (whole host);
  - on the accounts host, only `/.well-known/fxa-client-configuration`, `/.well-known/openid-configuration`, `/__heartbeat__` and `/__lbheartbeat__` (exact paths);
  - on the API host, `POST /v1/account/create` → `ffs-admin:8081`.

  Everything else on the accounts host, and the whole admin host, sits behind `portcullis-auth@docker,portcullis-groups@docker`.
- Images, all pinned `tag@sha256:`. The builder resolves the versioned tag of each digest with `docker buildx imagetools inspect` and must find exactly this digest.
  - `ghcr.io/porelli/firefox-sync:fxa-mono-v1.350.0@sha256:0ec0804fe9a021496faffd78d64ae90c014ee4fa1b0ed228451e84df30a77d73` (fxa-keys-owner, fxa-migrations, fxa-auth, fxa-content, fxa-profile, fxa-profile-worker, fxa-profile-static);
  - `ghcr.io/porelli/firefox-sync:admin-721640567d61@sha256:0db8bcf937d9fc4f2271620951f98f0ba0bf2296eabfacfa26bf1912cf131a17` (fxa-policy, ffs-admin);
  - `ghcr.io/porelli/firefox-sync:syncstorage-rs-postgres-0.25.1@sha256:e67e05fab539e94c81ce6991d01309c2996db1178dcad8c5cd7640eca48c7e95`;
  - `ghcr.io/porelli/firefox-sync:syncstorage-rs-postgres-init-0.25.1-20261124T034155@sha256:19566723433882b1e1214da8ee987a9cdf3d453713979f2696d8e6307fa98558`;
  - `ghcr.io/porelli/firefox-sync:fxa-channelserver-<release>@sha256:cfc3319d79ba46bdc7b32922170bbfa5ea5eec3cb6549519ac0996309f320f74` (1.6.0);
  - `mysql:<lts version>@sha256:1f2ca53a9e94ff9f1f313099fa7dc7fb2f72e180ca5b2ef83574031e451bbbf1`;
  - `redis:<version>-alpine@sha256:61d65002475565ac459faee56be20007561fe3cb6209a09cf967d25d3f3499cb` (no volume);
  - `postgres:17.11-alpine@sha256:3540c0362c809df084ffac0ae69fe794515f9de92692f02178bcdce0ef0302ac` (the Sync database, as in `firefox-sync/`);
  - `nginx:1.31.8-alpine@sha256:fed7e14be83cbd2661a75cdc5b872d936cf155d46c327084d30b8df19ae88d72` (fxa-gate, as in `esphome/`).
- `ADMIN_ACCESS_EXTERNAL: "1"` on fxa-policy and ffs-admin. `FXA_ACCESS_DB_PASSWORD` is generated, so `FXA_SIGNUPS` is forced to `allowlist`. `FXA_SIGNUP_ALLOWLIST` is never set.
- `ADMIN_PASSWORD: ""`, `ADMIN_OIDC_GROUPS_CLAIM: groups`, `ADMIN_ALLOWED_GROUPS: ${PORTCULLIS_ADMIN_GROUP:-admin_firefox-sync-fxa}`, `ADMIN_OIDC_TRUST_UNVERIFIED_EMAIL: "false"`, `ADMIN_ALLOWED_USERS: ""`.
- `FXA_ACCOUNT_EVENTS: "false"` (`ACCOUNT_EVENTS_ENABLED` on fxa-auth). `IP_PROFILING_RECENCY: 0`. `CUSTOMS_SERVER_URL: none`. `FXA_EXPIRATION_ACCESS_TOKEN: 60 minutes`.
- `CLIENT_ADDRESS_DEPTH` / `FXA_CLIENT_ADDRESS_DEPTH: "2"` (Traefik alone; the gate forwards Traefik's `X-Forwarded-For` unchanged and adds nothing).
- No account cap by default: `FXA_MAX_ACCOUNTS` = the optional `max_accounts` setting, else `unlimited`.
- Mail: `FXA_SMTP_PORT` 587, and `SMTP_SECURE` `false` (STARTTLS on 587) or `true` (implicit TLS on 465). The template refuses to start with neither the mail provider nor an external SMTP host.
- Resources: `min_memory_mib: 4096`, `min_disk_gib: 18`. They warn and never block.
- Email verification:
  - the code is 8 digits, valid **15 min**, with **5** wrong entries per code;
  - sends are limited to **3 per hour** and **10 per day** per person;
  - only an HMAC-SHA256 hash of the code is kept, in memory;
  - the code is bound to the email it was sent to.
- Volumes (keys unique across templates): `fxa-keys`, `fxa-db-data`, `fxa-profile-images`, `fxa-access-state`, `firefox-sync-fxa-db-data`. All are in the instance backup (`backup.go projectVolumes` archives every project volume).
- Upstream config files are vendored from `porelli/firefox-sync` 7216405 into `firefox-sync-fxa/fxa-config/` and mounted `./templates/firefox-sync-fxa/fxa-config:/fxa-config:ro`. `env_file` is forbidden, so the settings in `no-telemetry.env` are written inline.
- Support scripts (`gate.sh`, `access-sync.sh`, `mail-check.sh`, `mail-select.sh`, the SQL files) are mounted `./templates/firefox-sync-fxa/<file>:/portcullis-bin/<file>:ro`. The data file's directory is `/portcullis`.
- Template rules (CONTRIBUTING): no `ports:`, `container_name:`, `env_file:` or `build:`. `cap_drop: [ALL]`, `no-new-privileges:true`, a sized `tmpfs` and `mem_limit` on every service. Router, service and middleware names contain no `_`.

## Review Focus

1. **Variants of the sign-up path.** `/v1/account/create/`, `//v1/account/create`, `/v1//account/create` and `/v1/account/create?keys=true` must never create an account for an email that isn't listed. The database policy refuses even when nginx's normalisation and the auth server's router disagree. Pinned in Task 12, `signup_path_variants_refused`.
2. **An email changed outside the Hub.** A person edits their email in LLDAP's own UI. The old verification no longer counts: the new email isn't delivered, the old one leaves the list, and its account is disabled. A code sent before the change can't verify the new email. Pinned in Task 3, `TestVerificationClearedByLLDAPEdit` and `TestCodeBoundToEmail`, and Task 13, `email_change_and_duplicates`.
3. **Lost or stale sync state.** After a restore, or after `fxa-access-state` was recreated empty, the next run still deletes and disables every listed email that is no longer in the file. Leaves come from the database rows, not only from the state file. Pinned in Task 13, `state_lost_still_disables`.
4. **Bodies and websockets through the gate.** A 2.5 MB Sync `POST` is not refused with 413, and the pairing websocket upgrade passes. Pinned in Task 12, `sync_body_2_5mb` and `pairing_websocket`.
5. **A sign-in template that asks for a YubiKey certificate.** Firefox presents no client certificate, so the open hosts must not request one, and Firefox must still reach the accounts host's open paths. Pinned in Task 5, `TestOpenOnlyHostGetsPublicTier` and `TestMixedHostDowngradedToDefault`.

---

## File Structure

**docs (`/Volumes/workspace/portcullis/.m-docs`):**
- `docs/guides/integration-contracts.md`:
  - §3: catalog `resources` wording, `mail_sender`, `hosts.reasons`;
  - §5: tier per host;
  - §5.1 / §9: new §9.8 "Verified emails";
  - §11.7: resource warnings and badge notes;
  - §13.2 / §13.7: `verified_email`;
  - new §19.14: app mail senders.
- `docs/guides/manifest-reference.md`: `mail_sender`, `hosts.reasons`, `verified_email`.
- `docs/operations/hub.md` (People: verified emails).

**Hub (`.m-hub`):**
- `internal/templates/mailsender.go`, `internal/mailprovider/types.go`, `internal/hub/mail_senders.go`, `internal/hub/mailsend.go`, `internal/hub/env.go`, `internal/hub/doctor_mail.go`, `internal/state/state.go`
- `internal/directory/store.go`, `internal/directory/emailverify.go`, `internal/directory/membership.go`, `internal/directory/service.go`, `internal/hub/emailverify.go`, `internal/httpapi/emailverify.go`, `internal/httpapi/directory.go`, `web/people.html`, `web/directory.js`
- `internal/templates/settings.go`, `internal/templates/verifiedemail.go`, `internal/settings/kinds_person.go`, `internal/hub/verifiedemail.go`, `internal/hub/deliver_files.go`, `internal/hub/panel.go`, `web/settings.js`
- `internal/hub/tlstier.go`, `internal/hub/override.go`, `internal/hub/bypass.go`, `internal/templates/manifest.go` (`hosts.reasons`)
- `internal/hub/usage_view.go`, `web/marketplace.js`, `web/index.html`
- `web/docs/integration-contracts.md` (the contract copy)

**core (`.m-core`):** `mailctl/internal/state/`, `mailctl/internal/reconcile/senders.go`, `tests/mail-conformance/`, `tests/e2e/e2e_fxa.py`, `.github/workflows/ci.yml` (job `e2e-fxa`).

**templates (worktree off `origin/main`, after `firefox-sync-admin` lands):**
- `schema/manifest.schema.json`, `tests/validate.py`, `tests/test_validate.py`, `stalwart/compose.yml` (mailctl pin)
- `firefox-sync-fxa/{manifest.yaml, compose.yml, gate.sh, access-sync.sh, mail-check.sh, mail-select.sh, guard.sql, revoke.sql, admin-db.sql, fxa-config/}`
- `tests/apps/firefox-sync-fxa.sh`, `tests/fxa_client.py` (PyFxA helper), `tests/requirements.txt` (PyFxA, hashed)

---

### Task 1: Contract first (docs)

**Files:**
- Modify: `/Volumes/workspace/portcullis/.m-docs/docs/guides/integration-contracts.md`, `docs/guides/manifest-reference.md`, `docs/operations/hub.md`
- Copy to: `.m-hub/web/docs/integration-contracts.md` (in Task 2's branch)

**Interfaces** (produces the contract every later task implements; each section is marked **NEW (Firefox own accounts)**):
- **§19.14 App mail senders.**
  - MailState gains `senders: [{username, uuid, address}]`, for every enabled instance whose template has `mail_sender: {label}` (≤ 64 characters, one line). For those, `username` = `portcullis-app-<instance>` and `address` = `<username>@<primary_domain>`.
  - The list also holds **Portcullis's own sender**, `portcullis-hub-mail` / `portcullis-hub-mail@<primary_domain>` (label `Portcullis`), whenever a provider is wired and mail is on.
  - The provider MUST create a submission-only account with no mailbox and no IMAP, allow `MAIL FROM` / `From:` = `address` only, refuse RCPT to it with `550 5.1.1`, and apply `limits`.
  - The credential comes from the existing `POST /v1/credentials`, with `allowed_ips: []`.
  - Instance env `PORTCULLIS_MAIL_SENDER_HOST` (= `MAIL_HOSTNAME`), `_PORT` (`587`), `_USER` (= address), `_PASSWORD` (in the 0600 `.env`) and `_FROM` (`"<label> <address>"`). All are empty while no provider is wired or mail is off.
  - Wiring, switching or a restore voids the credentials. New ones are created at the next sync, and the instances restart.
  - Doctor kind `mail_sender_unwired` (Warning).
- **§9.8 Verified emails.**
  - A person's email is **verified** when `directory.yaml` `email_verified.<lldap uuid>` = `{email, at, by}` holds the person's current LLDAP email (compared trimmed and lowercased). `by` is `code` or `admin:<username>`.
  - Any change of the LLDAP email, through the Hub or LLDAP's own UI, makes it unverified, since the stored email no longer matches.
  - An email set by someone other than the person, with `edit_details` (create, invite, CSV import, `PUT /api/directory/users/{u}`), is stored verified with `by: admin:<caller>`. So is `POST /api/directory/users/{u}/email/verified` (an admin re-confirms an existing email; `204`, audited `user.email_verified`).
  - Self-service routes, refused while impersonating (`RefuseWhileImpersonated`):
    - `POST /api/me/email/verify` → `202 {"expires_at"}`, `409` "mail isn't set up on this server" (no Portcullis sender), `429` "too many codes: try again later";
    - `POST /api/me/email/verify/confirm {"code"}` → `200 {"verified": true}`, `400 {"attempts_left"}`, `410` "this code has expired: ask for a new one" (expired, used up, or the email changed since it was sent).
  - Code rules: Global Constraints.
  - Mail text (exact): subject `Your Portcullis email code`, body `Your code is <8 digits>. It expires in 15 minutes. If you didn't ask for it, you can ignore this email.`
  - Audit: `email.code_sent` and `email.verified`, never the code.
  - Person views gain `email_verified: bool`.
- **§13.2 / §13.7 `verified_email` type.**
  - Effective scope `person`. The Hub sets it, and any admin input is refused "set by the Hub". `self_visible: false`. Only `{file: {name, field}}` deliveries. Only on templates with `group_access: true` and an `access_group`.
  - The value is the person's verified email. A person without one is left out of the file.
  - The panel's `population.no_verified_email` lists them, and the instance page shows their count.
- **§5 TLS option per host.**
  - A host whose routers all lack `portcullis-auth` gets `public@file`.
  - A host that mixes open and gated routers gets `HostTier(tier, true)`.
  - A host with only gated routers keeps the instance tier.
- **§3 `hosts.reasons: {<host router>: "<reason>"}`** (one line, ≤ 200 runes). For an `open_router` badge on that host, `Note` = the reason. It falls back to the first paragraph of `auth.notes`.
- **§3 / §11.7 Resource warnings.**
  - The Marketplace card and the setup form warn when `memory_bytes < min_memory_mib·2^20` or the `docker_data` disk's free bytes are below `min_disk_gib·2^30`. They warn and never block.
  - `GET /api/usage` `hosts.<id>.disk_free_bytes` (int64 or null).
  - §3 keeps "the figures the project's own documentation states". A figure may be summed from upstream's documented sizes (PVCs), and `long_description` says so.

- [ ] **Step 1:** Write the sections above, with exactly these names, values and texts.
- [ ] **Step 2:** Run `zensical build --strict --clean && python scripts/check-lists.py site` in the docs repo. Expected: exit 0.
- [ ] **Step 3:** Commit `contract: app mail senders, verified emails, verified_email, TLS per host, badge reasons, resource warnings`.

---

### Task 2: Hub: app mail senders and Portcullis's own sender

**Files:**
- Create: `internal/templates/mailsender.go` (+ `_test.go`): `Manifest.MailSender *MailSender{Label string}`
- Modify: `internal/mailprovider/types.go:16-35`: `MailState.Senders []Sender`, and `type Sender struct{Username, UUID, Address string}` with JSON tags `username`, `uuid`, `address`
- Create: `internal/hub/mail_senders.go` (+ `_test.go`), `internal/hub/mailsend.go` (+ `_test.go`; go-mail, STARTTLS required on 587, trusting core's CA bundle)
- Modify:
  - `internal/hub/mail.go:274` (`mailBuild` adds the senders);
  - `internal/hub/env.go` (the five `PORTCULLIS_MAIL_SENDER_*`, rewritten before every up like `t.InstanceEnv`);
  - `internal/state/state.go` (`MailSenders map[string]state.MailSender{UUID, CredentialID, CreatedAt}`, keyed by instance id or `"hub"`; passwords on `hub_secrets`, never in `state.yaml`);
  - `internal/hub/doctor_mail.go`;
  - `internal/hub/restore.go`.

**Interfaces:**
- Consumes: `mailprovider.Client.CreateCredential(ctx, user, uuid, label string, expires *time.Time) (Created, error)`, `RevokeCredential`, `mailWaitApplied`, `h.mailCore()`, `credstore`.
- Produces:
  - `func (h *Hub) mailSendersLocked() []mailprovider.Sender`;
  - `func (h *Hub) ensureSenderCredential(ctx context.Context, key string) (changed bool, err error)`;
  - `func senderEnv(key string, s *storedSender, mc mailCoreEnv, label string) map[string]string`;
  - `func (h *Hub) SendHubMail(ctx context.Context, to, subject, body string) error`, returning `ErrNoHubSender` while unwired;
  - doctor kind `mail_sender_unwired`.

- [ ] **Step 1: Write the failing tests**

```go
func TestSenderInMailState(t *testing.T)    // enabled firefox-sync-fxa + wired -> Senders == [{portcullis-app-firefox-sync-fxa,…},
//   {portcullis-hub-mail, <uuid>, portcullis-hub-mail@ci.example.org}] sorted; a disabled instance absent
func TestSenderEnvWired(t *testing.T)       // HOST == MAIL_HOSTNAME, PORT "587", USER == address,
//   FROM == "Firefox accounts <portcullis-app-firefox-sync-fxa@ci.example.org>", PASSWORD == created secret, .env 0600
func TestSenderEnvUnwired(t *testing.T)     // all five keys present and ""; finding mail_sender_unwired (warning)
func TestSenderVoidedOnSwitch(t *testing.T) // old credentials gone, new CreateCredential, instance restart queued
func TestSenderVoidedOnRestore(t *testing.T)
func TestSenderLabelValidation(t *testing.T) // "" / > 64 runes / "\n" refused
func TestSenderNoMailboxLeak(t *testing.T)   // never in Accounts, mail_users or MyMail
func TestSendHubMailUnwired(t *testing.T)    // ErrNoHubSender
func TestSendHubMailStartTLS(t *testing.T)   // against a test SMTP server: STARTTLS required (plain refused), AUTH with the stored password,
//   From == "Portcullis <portcullis-hub-mail@ci.example.org>"
```

- [ ] **Step 2:** Run `go test ./internal/... -run 'Sender|SendHubMail'`. Expected: FAIL.
- [ ] **Step 3:** Implement. Passwords are never logged or audited. The audit entry is `mail_sender.created` with the key only.
- [ ] **Step 4:** Run `go test ./... && go vet ./...`. Expected: PASS. Copy the contract to `web/docs/`.
- [ ] **Step 5:** Commit `mail: app senders and Portcullis's own sender`.

---

### Task 3: Hub: verified emails on People

**Files:**
- Modify: `internal/directory/store.go:60-80` (`Meta.EmailVerified map[string]EmailVerification` with tag `email_verified,omitempty`; `type EmailVerification struct{Email string; At time.Time; By string}`)
- Create: `internal/directory/emailverify.go` (+ `_test.go`)
- Modify:
  - `internal/directory/membership.go:28-53`: `Membership.VerifiedEmails map[string]string`, lowercase user → verified email, only when it matches;
  - `internal/directory/service.go`: `CreateUser` and `UpdateUser:1593` record `by: admin:<caller>` when the caller isn't the target; the person view gains `EmailVerified`.
- Create: `internal/hub/emailverify.go` (+ `_test.go`), `internal/httpapi/emailverify.go` (+ `_test.go`)
- Modify: `internal/httpapi/directory.go` (the admin route), `web/people.html` + `web/directory.js` (badge "Verified" / "Not verified" on the person page and the People list; on your own page "Verify email" → send → code field)
- Test: `internal/httpapi/webui_people_links_test.go` or a new `webui_emailverify_test.go`

**Interfaces:**
- Consumes: `SendHubMail` (Task 2), `RefuseWhileImpersonated`, the audit writer.
- Produces:
  - `func (s *Service) MarkEmailVerified(ctx context.Context, c *Caller, username string) error`;
  - `func verifiedEmail(meta *Meta, uuid, current string) (string, bool)`;
  - `func (h *Hub) StartEmailVerification(ctx context.Context, user string) (expires time.Time, err error)`;
  - `func (h *Hub) ConfirmEmailVerification(ctx context.Context, user, code string) (attemptsLeft int, err error)`;
  - routes as in Task 1.

- [ ] **Step 1: Write the failing tests**

```go
func TestAdminSetEmailVerified(t *testing.T)            // UpdateUser by root on alice -> email_verified{email, by:"admin:root"}
func TestSelfSetEmailNotVerified(t *testing.T)          // UpdateUser by alice on alice -> no record
func TestVerificationClearedByLLDAPEdit(t *testing.T)   // LLDAP email changed outside -> VerifiedEmails has no alice
func TestCodeFlow(t *testing.T)                         // start -> mail with 8 digits, 15 min expiry; confirm right code -> verified, by "code"
func TestCodeBoundToEmail(t *testing.T)                 // email changed after start -> confirm 410
func TestCodeAttempts(t *testing.T)                     // 5 wrong -> 410 for the right code too; attempts_left 4,3,2,1,0
func TestCodeExpiry(t *testing.T)                       // clock + 15m01s -> 410
func TestSendLimits(t *testing.T)                       // 4th send within 1 h -> 429; 11th within 24 h -> 429
func TestCodeNeverStoredOrAudited(t *testing.T)         // the code is not in state, directory.yaml, audit or logs
func TestVerifyRefusedImpersonating(t *testing.T)       // 403 read-only text
func TestVerifyNoSender(t *testing.T)                   // 409 "mail isn't set up on this server"
func TestPeoplePageBadges(t *testing.T)                 // UI: badge text per state; own page shows the Verify button
```

- [ ] **Step 2:** Run `go test ./internal/directory/ ./internal/hub/ ./internal/httpapi/ -run 'Email|Code|Verify|Badges'`. Expected: FAIL.
- [ ] **Step 3:** Implement. The code comes from `crypto/rand`, is compared in constant time, and pending codes live in memory (a Hub restart drops them). The record is keyed by LLDAP uuid, so a re-created username starts unverified.
- [ ] **Step 4:** Run `go test ./...`. Expected: PASS.
- [ ] **Step 5:** Commit `people: verified emails (code by mail, admin-set)`.

---

### Task 4: Hub: `verified_email` option type

**Files:**
- Modify: `internal/templates/settings.go:463-472` (`TypeVerifiedEmail = "verified_email"`)
- Create: `internal/templates/verifiedemail.go` (+ `_test.go`), `internal/hub/verifiedemail.go` (+ `_test.go`)
- Modify:
  - `internal/settings/kinds_person.go`: `Parse` refuses "set by the Hub";
  - `internal/hub/deliver_files.go`: `fileNeedsPeople`, and the people section in `renderDocLocked`;
  - `internal/hub/panel.go:61` (`PopulationView.NoVerifiedEmail []string` with JSON tag `no_verified_email,omitempty`);
  - `web/settings.js` (copy: `<n> members have no verified email and can't have an account.` plus a "Show" list).

**Interfaces:**
- Consumes: `Membership.VerifiedEmails` (Task 3), `populationLocked`.
- Produces:
  - `func validateVerifiedEmail(o *Option, m *Manifest) error`;
  - `func verifiedEmailOptions(t *templates.Template) []*templates.Option`;
  - `func (h *Hub) noVerifiedEmailLocked(t *templates.Template, m *directory.Membership) []string`.

- [ ] **Step 1: Write the failing tests**

```go
func TestVerifiedEmailValidation(t *testing.T) // refused: scope, default, env/claim/hook delivery, self_visible true,
//   no group_access/access_group; accepted: {file:{name:access, field:email}}
func TestVerifiedEmailInDataFile(t *testing.T)  // alice verified, bob unverified, carol none:
//   doc.People == {"alice":{"email":"alice@example.org"}}
func TestVerifiedEmailPanelList(t *testing.T)   // population.no_verified_email == ["bob","carol"]
func TestVerifiedEmailRedelivers(t *testing.T)  // alice verifies -> the next membership run's file differs
func TestVerifiedEmailNotParsedFromAdmin(t *testing.T) // PUT …/settings with the key -> 400 "set by the Hub"
```

- [ ] **Step 2:** Run `go test ./internal/... -run VerifiedEmail`. Expected: FAIL.
- [ ] **Step 3:** Implement. A verification or a cleared one marks the directory changed (`wireDirectoryHooks` `OnChange`), so the membership delivery runs.
- [ ] **Step 4:** Run `go test ./...`. Expected: PASS.
- [ ] **Step 5:** Commit `settings: verified_email type`.

---

### Task 5: Hub: TLS tier per host for routers without sign-in

**Files:**
- Create: `internal/hub/tlstier.go`, `internal/hub/tlstier_test.go`
- Modify:
  - `internal/hub/override.go:687-730`: `routeLabels.routerTier map[string]string`, written by the label loop at `:419`;
  - `internal/hub/bypass.go:91`: each badge's `Tier` comes from its hosts;
  - the Kubernetes translator input (the same `routeLabels`).

**Interfaces:**
- Consumes: `templateChains`, `chainSignsIn`, `routerHosts`, `policy.HostTier`.
- Produces: `func (h *Hub) routerTiersLocked(t *templates.Template, rl *routeLabels) map[string]string`. All routers of one host get the same value.

- [ ] **Step 1: Write the failing tests** (a fixture shaped like `firefox-sync-fxa`; the default sign-in template requires `yubikey_cert`, so the instance tier is `protected@file`)

```go
func TestOpenOnlyHostGetsPublicTier(t *testing.T)   // api/profile/sync/pairing -> "public@file"
func TestMixedHostDowngradedToDefault(t *testing.T) // both accounts routers -> "default"
func TestGatedOnlyHostKeepsTier(t *testing.T)       // admin -> "protected@file"
func TestCustomAppUnchanged(t *testing.T)           // method: custom: every router "public@file"
```

- [ ] **Step 2:** Run `go test ./internal/hub/ -run Tier`. Expected: FAIL.
- [ ] **Step 3:** Implement. Keep `rl.tier` as the instance tier for `weak_tls`.
- [ ] **Step 4:** Run `go test ./...` (`TestRealTemplatesInstances` and the golden tests: existing templates' overrides must be byte-identical). Expected: PASS.
- [ ] **Step 5:** Commit `override: TLS option per host; hosts without sign-in get public@file`.

---

### Task 6: Hub: a reason per host on bypass badges

**Files:**
- Modify: `internal/templates/manifest.go` (`Hosts.Reasons map[string]string` with tag `reasons,omitempty`; validation in `internal/templates/validate.go`: keys are host routers, values one line of ≤ 200 runes, no control characters), `internal/hub/bypass.go:135-150` (`Note` = the reason of the badge's host router, else `templateNote(t)`)
- Test: `internal/hub/bypass_test.go`, `internal/templates/validate_test.go`

**Interfaces:**
- Consumes: Task 5's badge tiers.
- Produces: `func hostReason(t *templates.Template, router string) string`.

- [ ] **Step 1: Write the failing tests**

```go
func TestBypassHostReason(t *testing.T)     // api router with reason "Firefox calls the accounts API in the background, without cookies."
//   -> its badge Note is exactly that; a host router without one -> templateNote(t)
func TestBypassBadgesFxaShape(t *testing.T) // 4 whole-host open_router badges (Tier public@file, Note = their reasons);
//   1 accounts badge with the 4 exact paths, Tier default
func TestHostReasonsValidation(t *testing.T) // unknown router, "\n", 201 runes -> refused
```

- [ ] **Step 2:** Run `go test ./internal/... -run 'Bypass|HostReasons'`. Expected: FAIL.
- [ ] **Step 3:** Implement. `web/index.html`'s badge details already show `note`, so they need no change; check that in `webui_bypass_test.go`.
- [ ] **Step 4:** Run `go test ./...`. Expected: PASS.
- [ ] **Step 5:** Commit `bypass: a reason per host (manifest hosts.reasons)`.

---

### Task 7: Hub: resource warnings (disk free, setup form)

**Files:**
- Modify: `internal/hub/usage_view.go:44-51` (`UsageHost.DiskFreeBytes *int64` with JSON tag `disk_free_bytes`, from the cached `docker_data` disk), `web/marketplace.js:384-447` (`loadHostRes`; the disk line gets the warn pill), `web/index.html:4449` (`setupFormHtml`, one `setup-warn` line per figure)
- Test: `internal/hub/usage_test.go`, `internal/httpapi/webui_marketplace_test.go`, `internal/httpapi/webui_setup_test.go`

**Interfaces:**
- Consumes: `Manifest.Resources{MinMemoryMiB, MinDiskGiB}`.
- Produces:
  - card copy `needs ≥ 18 GiB free disk` plus pill `more than this server has free (<n> GiB)`;
  - setup copy (exact): `This app needs about <m> of RAM; this server has <n>. It may not start or may slow other apps.` and `This app needs about <d> GiB of free disk; this server has <n> GiB free.`

- [ ] **Step 1: Write the failing tests:**
  - `TestUsageHostDiskFree`: a cached disk with 12 GiB free → `disk_free_bytes == 12<<30`; no cache → `null`;
  - marketplace and setup form with `{min_memory_mib: 4096, min_disk_gib: 18}`: 2 GiB RAM / 12 GiB free → both warnings; 8 GiB / 40 GiB → none;
  - in every case the Install button stays enabled.
- [ ] **Step 2:** Run `go test ./internal/hub/ ./internal/httpapi/ -run 'DiskFree|Marketplace|Setup'`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `go test ./...`. Expected: PASS.
- [ ] **Step 5:** Commit `marketplace, setup form: warn on low RAM or free disk`. Wait for the `edge` image before Task 9.

---

### Task 8: core mailctl: senders on Stalwart

**Files:**
- Modify: `/Volumes/workspace/portcullis/.m-core/mailctl/internal/state/` (parse `senders` strictly), `tests/mail-conformance/` vectors
- Create: `mailctl/internal/reconcile/senders.go` (+ `_test.go`)
- Then, in templates: `stalwart/compose.yml` (mailctl pin `main-<sha7>@sha256:<digest>`, copied from tool output)

**Interfaces:**
- Consumes: MailState `senders`.
- Produces: in Stalwart, one account per sender with the send permission only (no IMAP, JMAP or mailbox), a sending-address restriction to `address`, and `550 5.1.1` at RCPT for `address`.

- [ ] **Step 1: Write the failing tests:**
  - `TestSenderAccountCreated`;
  - `TestSenderFromRestricted` (another `From` is refused at DATA);
  - `TestSenderInboundRefused`;
  - `TestSenderRemovedWithInstance`;
  - `TestSenderNotMassRemoval`.
- [ ] **Step 2:** Run `cd mailctl && go test ./...`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `cd mailctl && go test ./...` and the conformance suite. Expected: PASS.
- [ ] **Step 5:** Commit `mailctl: app senders`, merge, and wait for `main-<sha7>`. Then bump the Stalwart pin (`python3 tests/validate.py` passes) and commit `stalwart: mailctl main-<sha7> (app senders)`.

---

### Task 9: templates validator: `verified_email`, `mail_sender`, `hosts.reasons`, sender variables

**Files:**
- Modify: `schema/manifest.schema.json` (type list at `:616`; `mail_sender {label}`; `hosts.reasons`), `tests/validate.py` (type handling next to `PERSON_TYPES` `:3204-3205` / `:5832`; `INSTANCE_VAR_TEXT_RE` `:1625` accepts `PORTCULLIS_MAIL_SENDER_(HOST|PORT|USER|PASSWORD|FROM)` only with `mail_sender`; `check_immutable_hosts`' neighbour checks `hosts.reasons` keys)
- Test: `tests/test_validate.py`

- [ ] **Step 1: Write the failing tests:**
  - `test_verified_email_needs_group_access`;
  - `test_verified_email_file_delivery_only`;
  - `test_verified_email_self_visible_false`;
  - `test_mail_sender_vars_need_block`;
  - `test_mail_sender_label_bounds`;
  - `test_hosts_reasons_known_routers`;
  - `test_hosts_reasons_one_line_200`.
- [ ] **Step 2:** Run `python3 -m pytest tests/test_validate.py -k 'verified_email or mail_sender or hosts_reasons'`. Expected: FAIL.
- [ ] **Step 3:** Implement, with the Hub's refusal texts word for word.
- [ ] **Step 4:** Run `python3 -m pytest tests/test_validate.py && python3 tests/validate.py`. Expected: PASS.
- [ ] **Step 5:** Commit `validate: verified_email, mail_sender, hosts.reasons`.

---

### Task 10: `firefox-sync-fxa` skeleton: services, start order, volumes, static checks

**Files:**
- Create: `firefox-sync-fxa/manifest.yaml`, `firefox-sync-fxa/compose.yml`, `firefox-sync-fxa/fxa-config/{oauth-clients.js,content-server.js}` (vendored from 7216405, unmodified, with a header comment naming the commit)
- Create: `tests/apps/firefox-sync-fxa.sh` (section "static")

**Interfaces:**
- Produces:
  - service names: `fxa-keys-owner`, `fxa-db`, `fxa-redis`, `fxa-migrations`, `fxa-policy`, `fxa-mail-check`, `fxa-auth`, `fxa-content`, `fxa-profile`, `fxa-profile-worker`, `fxa-profile-static`, `fxa-pairing`, `ffs-admin`, `fxa-access-sync`, `firefox-sync-fxa-db`, `firefox-sync-fxa-migrate`, `firefox-sync-fxa-db-init`, `firefox-sync-fxa-init`, `firefox-sync-fxa` (syncstorage), `fxa-gate`;
  - generated env: `FXA_MYSQL_PASSWORD`, `FXA_ADMIN_DB_PASSWORD`, `FXA_ACCESS_DB_PASSWORD`, `FXA_OAUTH_SECRET`, `FXA_AUTH_SECRET`, `FXA_PROFILE_SECRET`, `FXA_FLOW_ID_KEY`, `FXA_SESSION_TOKEN_HANDLE_KEY`, `FXA_CONTENT_SESSION_SECRET`, the MFA JWT secret upstream's `.env-example` names, `FIREFOX_SYNC_FXA_DB_PASSWORD`, `FIREFOX_SYNC_FXA_APP_DB_PASSWORD`, `FIREFOX_SYNC_FXA_MASTER_SECRET`, `FIREFOX_SYNC_FXA_METRICS_SECRET`, `FIREFOX_SYNC_FXA_ADMIN_OIDC_SECRET`.

- [ ] **Step 1: Write the failing static checks** (yq; `pass` / `fail` from `tests/lib.sh`):
  - `six_host_routers`: exactly the six, each with its default subdomain;
  - `start_order`:
    - `fxa-auth` depends on `fxa-keys-owner` and `fxa-policy` (completed) and `fxa-redis` (healthy);
    - `fxa-policy` depends on `fxa-migrations` (completed), which depends on `fxa-db` (healthy);
    - `fxa-content` depends on `fxa-auth` and `fxa-profile` (healthy);
    - `firefox-sync-fxa` depends on `firefox-sync-fxa-init`, which depends on `firefox-sync-fxa-db-init`, which depends on `firefox-sync-fxa-migrate` (all completed);
  - `only_gate_on_proxy`: `fxa-gate` is the only service on `portcullis-proxy`, and every other service is on `default` only;
  - `images_pinned`: every image equals Global Constraints' digests;
  - `env_values`: `ADMIN_ACCESS_EXTERNAL` = `"1"` (fxa-policy, ffs-admin), `ADMIN_PASSWORD` = `""`, `ACCOUNT_EVENTS_ENABLED` = `"false"`, `IP_PROFILING_RECENCY` = `0`, `CLIENT_ADDRESS_DEPTH` = `"2"`, `CUSTOMS_SERVER_URL` = `none`, `FXA_SIGNUP_ALLOWLIST` absent;
  - `tokenserver_internal`: `SYNC_TOKENSERVER__FXA_OAUTH_SERVER_URL` = `http://fxa-auth:9000/v1`, `SYNC_TOKENSERVER__FXA_EMAIL_DOMAIN` = `${PORTCULLIS_HOST_FIREFOX_SYNC_FXA_API:-firefox-sync-api.portcullis.local}`;
  - `volumes`: exactly `fxa-keys`, `fxa-db-data`, `fxa-profile-images`, `fxa-access-state`, `firefox-sync-fxa-db-data`; `fxa-redis` has none;
  - `resources`: `min_memory_mib == 4096`, `min_disk_gib == 18`;
  - `node_trusts_ca`: every Node service sets `NODE_EXTRA_CA_CERTS` to the mounted `./certs/ca-bundle.crt`.
- [ ] **Step 2:** Run `STATIC_ONLY=1 bash tests/apps/firefox-sync-fxa.sh` and `python3 tests/validate.py firefox-sync-fxa`. Expected: FAIL.
- [ ] **Step 3:** Write the manifest and compose. They follow upstream's `compose/fxa.yml` without `ports:` or `env_file:`, with the `no-telemetry.env` values inline and upstream's healthchecks (`start_period: 300s`). The Sync side mirrors `firefox-sync/compose.yml`, and Task 15 fills in its SQL.
- [ ] **Step 4:** Run the same commands and `python3 tests/validate.py --placement`. Expected: PASS.
- [ ] **Step 5:** Commit `firefox-sync-fxa: services, start order, volumes`.

---

### Task 11: Traefik routers and badge reasons

**Files:**
- Modify: `firefox-sync-fxa/compose.yml` (labels on `fxa-gate` only; every router `.service: firefox-sync-fxa-gate`, port 8080), `firefox-sync-fxa/manifest.yaml` (`hosts.reasons`)
- Test: `tests/apps/firefox-sync-fxa.sh` (section "routers")

**Interfaces:**
- Produces these routers:
  - host routers: `firefox-sync-fxa`, `-api`, `-profile` and `-pairing` carry `rate-limit@file,security-headers@file`; `-accounts` and `-admin` carry `client-headers@file,portcullis-auth@docker,portcullis-groups@docker,security-headers@file`;
  - path routers: `firefox-sync-fxa-accounts-open` (the four exact `Path()`s, priority 1000, `rate-limit@file,security-headers@file`), `firefox-sync-fxa-signup` (API host `&& Path(/v1/account/create)`, priority 1000, `rate-limit-auth@file,security-headers@file`), `firefox-sync-fxa-token` (Sync host `&& PathPrefix(/1.0/)`, `rate-limit-auth@file`).
- `hosts.reasons` (exact):
  - api: `Firefox and the account pages call the accounts API in the background, without cookies; the sign-up list decides who may create an account.`;
  - profile: `Firefox loads account profiles and avatars in the background, without cookies.`;
  - Sync: `Firefox syncs in the background, without cookies; each request is signed with the account's own keys.`;
  - pairing: `An encrypted relay for pairing a phone by QR code; it can't read what it relays.`

- [ ] **Step 1: Write the failing checks:**
  - `routers_exact`;
  - `open_routers_no_gateway`;
  - `gated_routers_gateway`;
  - `accounts_open_paths`;
  - `manifest_auth` (`method: forward-auth`, `group_access: true`, no `admin_paths`);
  - `host_reasons` (the four texts above).
- [ ] **Step 2:** Run the router section. Expected: FAIL.
- [ ] **Step 3:** Add the labels and the reasons.
- [ ] **Step 4:** Run the router section and `python3 tests/validate.py firefox-sync-fxa`. Expected: PASS.
- [ ] **Step 5:** Commit `firefox-sync-fxa: routers and badge reasons`.

---

### Task 12: `fxa-gate`, the Traefik-only nginx gate (the `esphome/gate.sh` pattern)

**Files:**
- Create: `firefox-sync-fxa/gate.sh`. It copies `esphome/gate.sh`'s checks (`cidr_ok`, fail closed, stripping forward-auth cookies and tokens), then writes one `server` block per host.
- Modify: `firefox-sync-fxa/compose.yml` (`fxa-gate`: `PORTCULLIS_TRAEFIK_SOURCE: ${PORTCULLIS_TRAEFIK_SOURCE:-172.31.250.2/32}`, and six `GATE_HOST_*` from the host variables)
- Test: `tests/apps/firefox-sync-fxa.sh` (section "gate", runtime)

**Interfaces:**
- Produces: nginx `server_name` per host:
  - accounts → `fxa-content:3030`;
  - api → `fxa-auth:9000`, with `location = /v1/account/create` → `ffs-admin:8081`;
  - profile → `fxa-profile:1111`, with `/img/` → `fxa-profile-static:1112` (prefix stripped);
  - Sync → `firefox-sync-fxa-internal:8000`;
  - admin → `ffs-admin:8080`;
  - pairing → `fxa-pairing:8000` (websocket);
  - unknown host → 421.
- Rules: `client_max_body_size 10m` on the Sync host; `proxy_set_header X-Forwarded-For $http_x_forwarded_for`; `Host` kept; a peer outside `PORTCULLIS_TRAEFIK_SOURCE` → 403.

- [ ] **Step 1: Write the failing runtime checks** (`compose_up`, core Traefik in front, `via_traefik`):
  - `open_paths_anonymous`: the four paths → 200 without a cookie; accounts `/` → Keycloak (`assert_redirect_to_keycloak`);
  - `admin_gated`: the admin host `/` → Keycloak;
  - `another_app_cannot_reach_auth`: a pinned `curlimages/curl` on `portcullis-proxy` runs `curl --max-time 5 http://fxa-auth:9000/__heartbeat__`, which fails (exit 6, 7 or 28); `curl -H "Host: <api host>" http://<fxa-gate ip>:8080/v1/account/create` → 403;
  - `spoofed_xff_same_key`: 6 failed `POST /v1/account/login` for one email through Traefik, each with `X-Forwarded-For: 203.0.113.<n>` → the 6th answers 429 with errno 114; `redis-cli --scan --pattern '*203.0.113*'` → empty;
  - `sync_body_2_5mb`: a 2.5 MB `POST` to `/1.5/x/storage/bookmarks` → 401 (Hawk), never 413;
  - `pairing_websocket`: the upgrade → 101;
  - `signup_path_variants_refused`: `nobody@example.org` on `/v1/account/create/`, `//v1/account/create`, `/v1//account/create` and `/v1/account/create?keys=true` → never 200, and `fxa.accounts` has no row with `normalizedEmail='nobody@example.org'`.
- [ ] **Step 2:** Run `bash tests/apps/firefox-sync-fxa.sh`. Expected: FAIL.
- [ ] **Step 3:** Write `gate.sh` and the compose entries.
- [ ] **Step 4:** Run the same command. Expected: PASS.
- [ ] **Step 5:** Commit `firefox-sync-fxa: fxa-gate (Traefik-only nginx gate)`.

---

### Task 13: `fxa-access-sync`: verified emails of the access group to the sign-up allowlist

**Files:**
- Create: `firefox-sync-fxa/access-sync.sh`
- Modify: `firefox-sync-fxa/manifest.yaml`:
  - `files: [{name: access, service: fxa-access-sync, mount: /portcullis, on_membership_change: hook}]`;
  - option `access_email` (`type: verified_email`, `self_visible: false`, `delivery: [{file: {name: access, field: email}}]`);
  - `hooks: [{name: access-sync, service: fxa-access-sync, command: [/bin/sh, /portcullis-bin/access-sync.sh], when: [start, membership_change], timeout: 120s}]`
- Modify: `firefox-sync-fxa/compose.yml` (`fxa-access-sync`: the `mysql` image digest, `user: "10001:10001"`, `group_add: ["10001"]`, `fxa-access-state:/state`, `command: [sleep, infinity]`; depends on `fxa-policy` completed with `restart: true`)
- Test: `tests/apps/firefox-sync-fxa.sh` (section "access"), `tests/fxa_client.py`

**Interfaces:**
- Consumes: `/portcullis/access.json` (`people.<user>.email`, verified only); `ffs_access` with `FXA_ACCESS_DB_PASSWORD` (`MYSQL_PWD`, never argv).
- Produces: `/state/applied.json` = `{"version":1,"listed":[…],"removed":[…]}`. Exit 0 = applied; exit 1 = nothing changed.
- Algorithm (the design decides it; how leaves are found is spelled out here because Review Focus 3 depends on it):

```text
new      = sorted unique lowercase people.*.email   (missing / unparsable / version != 1 -> exit 1, no SQL)
db       = SELECT email FROM ffs.signup_allowlist
joins    = new - db                                 -> INSERT
leaves   = (db ∪ state.listed) - new                -> DELETE, then CALL ffs.disable_account_by_email(e)
rejoins  = joins ∩ state.removed                    -> INSERT, then CALL ffs.enable_account_by_email(e)
"no such account" from disable/enable               -> ignored
state    = {listed: new, removed: (state.removed ∪ leaves) - new}   written atomically after COMMIT
```

- [ ] **Step 1: Write the failing runtime checks** (data file from `write_appfiles_override firefox-sync-fxa access …`; sign-ups through `tests/fxa_client.py signup <email> <password>` (PyFxA `fxa.core.Client`) against a mail catcher set as the external SMTP of Task 14):
  - `nonmember_refused`: an empty list → signing up `alice@example.org` → 400 and no row;
  - `join_allows`: alice listed → sign-up plus the code → a verified account;
  - `leave_disables`: alice removed, hook run → `disabledAt` is set, and her session token answers 401;
  - `rejoin_enables`: alice listed again → `disabledAt` is NULL;
  - `admin_disable_survives`: `CALL ffs.disable_account_by_email('bob@example.org')` while bob stays listed, then a routine run with an unchanged file → bob is still disabled;
  - `missing_file_keeps_list` / `unparsable_file_keeps_list`: the hook exits 1 and `ffs.signup_allowlist` is unchanged;
  - `email_change_and_duplicates`: alice's email changes → the old one is disabled and the new one listed; two entries with `shared@example.org` → one row, kept while one of them remains;
  - `state_lost_still_disables`: `fxa-access-state` is recreated empty, and carol is in the DB but not in the file → carol is deleted and disabled.
- [ ] **Step 2:** Run `bash tests/apps/firefox-sync-fxa.sh`. Expected: FAIL.
- [ ] **Step 3:** Write `access-sync.sh` (POSIX sh + `mysql --batch`). An email becomes an SQL literal only after it passes `^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+$`, with quotes doubled.
- [ ] **Step 4:** Run the same command. Expected: PASS.
- [ ] **Step 5:** Commit `firefox-sync-fxa: fxa-access-sync (verified emails to the sign-up allowlist)`.

---

### Task 14: Mail: the provider by default, or an external SMTP server

**Files:**
- Create: `firefox-sync-fxa/mail-check.sh`, `firefox-sync-fxa/mail-select.sh` (sourced by both)
- Modify: `firefox-sync-fxa/manifest.yaml`:
  - `mail_sender: {label: Firefox accounts}`;
  - section `Mail` with `mail_source` (enum `provider` "The server's mail provider" / `external` "Another SMTP server", default `provider`), `smtp_host` (string, format hostname), `smtp_port` (int 1–65535, default 587), `smtp_security` (enum `starttls` "STARTTLS (587)" / `tls` "TLS (465)", default `starttls`), `smtp_user` (string), `smtp_password` (secret), `smtp_sender` (string, format email);
  - `max_accounts` (int, min 1, optional, section `Accounts`);
  - `requires: [smtp_host, smtp_sender]` on `smtp_user`;
  - every option `applies: restart`.
- Modify: `firefox-sync-fxa/compose.yml`:
  - `fxa-mail-check` is a one-shot that validates only, and `fxa-auth` depends on it completed;
  - `fxa-auth`'s `sh -c` command first runs `. /portcullis-bin/mail-select.sh`, which exports `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_SECURE` and `SMTP_SENDER` from `PORTCULLIS_MAIL_SENDER_*` (provider) or `EXT_SMTP_*` (external);
  - `ffs-admin` (no shell) keeps `SMTP_HOST: ""`, as in `firefox-sync/`.

**Interfaces:**
- Consumes: `PORTCULLIS_MAIL_SENDER_*` (Task 2); env `MAIL_SOURCE`, `EXT_SMTP_HOST`, `EXT_SMTP_PORT`, `EXT_SMTP_SECURITY`, `EXT_SMTP_USER`, `EXT_SMTP_PASSWORD`, `EXT_SMTP_SENDER`, `MAX_ACCOUNTS`.
- Produces: the auth server's `SMTP_*`. `FXA_MAX_ACCOUNTS: ${MAX_ACCOUNTS:-unlimited}` on `fxa-policy`.

- [ ] **Step 1: Write the failing checks:**
  - `refuses_without_mail`: provider mode with an empty sender env → `fxa-mail-check` exits 1 and logs exactly `portcullis: no mail: wire a mail provider or set an external SMTP server`, and `fxa-auth` isn't started;
  - `external_used`: the catcher with `starttls` → `SMTP_SECURE=false`, port 587, and the code arrives;
  - `provider_used`: in `fxa-auth`'s `/proc/1/environ`, `SMTP_HOST` = `PORTCULLIS_MAIL_SENDER_HOST`, `SMTP_SECURE=false`, `SMTP_PORT=587`, and `SMTP_SENDER` = `_FROM`;
  - `secret_not_in_argv`: `docker inspect` `Args` and `Cmd` hold no SMTP password;
  - `no_cap_default`: `FXA_MAX_ACCOUNTS` is `unlimited` without the setting and `5` with it.
- [ ] **Step 2:** Run `bash tests/apps/firefox-sync-fxa.sh`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the same command and `python3 tests/validate.py firefox-sync-fxa`. Expected: PASS.
- [ ] **Step 5:** Commit `firefox-sync-fxa: mail (provider or external SMTP), optional account cap`.

---

### Task 15: Sync side: our guard on the Sync database (**depends on `firefox-sync-admin` landing**)

**Files:**
- Create: `firefox-sync-fxa/guard.sql`, `revoke.sql`, `admin-db.sql`, from the branch's `firefox-sync/` versions without the uid allowlist table and its trigger
- Modify: `firefox-sync-fxa/compose.yml` (the `firefox-sync-fxa-*` services as in the branch; `-db-init` with `ADMIN_ACCESS_EXTERNAL: "1"`, `MAX_USERS: unlimited`, `SYNC_ALLOWED_ACCOUNTS: ""`)
- Test: `tests/apps/firefox-sync-fxa.sh` (section "sync")

**Interfaces:**
- Produces: roles `firefoxsync_app` (owns nothing, no superuser), `firefoxsync_admin`, `firefoxsync_admin_sync`. The node is `https://${PORTCULLIS_HOST_FIREFOX_SYNC_FXA:-firefox-sync.portcullis.local}`.

- [ ] **Step 1: Write the failing checks:**
  - `app_role_owns_nothing`;
  - `only_three_roles_connect`;
  - `node_url`;
  - `first_sync`: `tests/fxa_client.py sync <email>` (OAuth token with the Sync scope → tokenserver 200 with an `api_endpoint` on the Sync host → a BSO PUT/GET round trip);
  - `foreign_token_refused`: 401.
- [ ] **Step 2:** Run the sync section. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the same. Expected: PASS.
- [ ] **Step 5:** Commit `firefox-sync-fxa: Sync database roles and node`.

---

### Task 16: Admin UI with OIDC, access managed elsewhere (**depends on `firefox-sync-admin` landing**)

**Files:**
- Modify: `firefox-sync-fxa/compose.yml` (`ffs-admin`), `firefox-sync-fxa/manifest.yaml` (`keycloak_clients: [{client_id: firefox-sync-fxa-admin, secret_env: FIREFOX_SYNC_FXA_ADMIN_OIDC_SECRET, redirect_uri: "https://{{HOST_FIREFOX_SYNC_FXA_ADMIN}}/auth/callback", name: Firefox Sync + own accounts admin UI}]`; `tests.signin` with host `{{HOST_FIREFOX_SYNC_FXA_ACCOUNTS}}` and path `/settings`)
- Test: `tests/apps/firefox-sync-fxa.sh` (section "admin", reusing the branch's Keycloak acceptance checks)

**Interfaces:**
- Consumes: the branch's `firefox-sync-admin` env block, plus `FXA_DB_HOST: fxa-db`, `FXA_DB_PASSWORD: ${FXA_ADMIN_DB_PASSWORD}`, `FXA_AUTH_UPSTREAM: http://fxa-auth:9000`, `FXA_CONTENT_URL` / `FXA_AUTH_URL` / `FXA_PROFILE_URL` from the host variables, `FXA_PAIRING_URL: wss://${PORTCULLIS_HOST_FIREFOX_SYNC_FXA_PAIRING:-firefox-sync-pairing.portcullis.local}`, `FXA_ACCOUNT_EVENTS: "false"`, `FXA_CLIENT_ADDRESS_DEPTH: "2"`.

- [ ] **Step 1: Write the failing checks:**
  - `admin_env`: `ADMIN_ACCESS_EXTERNAL=1`, `ADMIN_PASSWORD=""`, `ADMIN_ALLOWED_GROUPS=${PORTCULLIS_ADMIN_GROUP:-admin_firefox-sync-fxa}`, `ADMIN_OIDC_GROUPS_CLAIM=groups`, `ADMIN_OIDC_TRUST_UNVERIFIED_EMAIL=false`;
  - `post_login_403`;
  - `redirect_uri_matches`;
  - `allowlist_read_only`: the sign-up and allowlist forms → 403;
  - `oidc_member_not_admin_refused`;
  - `connect_page_values`: `identity.fxaccounts.autoconfig.uri` = the accounts URL.
- [ ] **Step 2:** Run the admin section. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the admin section and `python3 tests/e2e/app_signin.py firefox-sync-fxa` (the member is signed in on the accounts pages; the outsider gets 403). Expected: PASS.
- [ ] **Step 5:** Commit `firefox-sync-fxa: admin UI (OIDC, admin group, access managed elsewhere)`.

---

### Task 17: Notes, Firefox setup, docs page

**Files:**
- Modify: `firefox-sync-fxa/manifest.yaml`:
  - `description`;
  - `long_description` with the exact sentence `Needs about 4 GB of RAM and 18 GB of disk (upstream's sizes), plus about 5 GB for Mozilla's accounts image.`;
  - `auth.notes`, covering: what runs; access by group and **verified** email ("verify it on your People page"); no verified email = no account; the token lifetime of about 1 h after a disable; mail; backups (`fxa-keys`); Firefox setup for desktop (`identity.fxaccounts.autoconfig.uri`), Android and iOS;
  - `urls`, `ai.unsupported`.
- Modify: `firefox-sync/manifest.yaml:79` (point "A separate template may add them later" to `firefox-sync-fxa`)
- Run: the docs repo's `scripts/generate-app-docs.py --source <templates>`

- [ ] **Step 1: Write the failing checks:**
  - `notes_render` (the validate.py notes lint);
  - `long_description_resources` (the exact sentence);
  - `notes_verified_email` (contains "verified").
- [ ] **Step 2:** Run `python3 tests/validate.py firefox-sync-fxa && bash tests/apps/firefox-sync-fxa.sh`. Expected: FAIL.
- [ ] **Step 3:** Write the texts. Regenerate the docs, then build them with `zensical build --strict --clean`.
- [ ] **Step 4:** Run the same commands and the docs build. Expected: PASS.
- [ ] **Step 5:** Commit `firefox-sync-fxa: notes, Firefox setup` (templates) and `apps: firefox-sync-fxa` (docs).

---

### Task 18: core e2e: real mail, real Hub (`e2e-fxa`)

**Files:**
- Create: `/Volumes/workspace/portcullis/.m-core/tests/e2e/e2e_fxa.py` (reuses `e2e_mail.py`'s `hub_ok`, `member`, `imap_login`, `wait_mail`)
- Modify: `.github/workflows/ci.yml` (job `e2e-fxa`, modelled on `e2e-mail` at `:4050`; templates branch `fxa-own-accounts`; PyFxA, hashed, in `tests/e2e/requirements.txt`)

- [ ] **Step 1: Write the scenarios:**
  - `email_verify_by_code`: alice (in `mail_users` and the access group) asks for a code on her People page. A message from `portcullis-hub-mail@ci.example.org` reaches her INBOX; she enters the code → `email_verified: true`;
  - `unverified_not_listed`: bob is in the group with an unverified email → the instance page counts 1 without a verified email, and `create_account(bob…)` is refused;
  - `signup_code_via_provider`: alice's `create_account` → within 120 s a message from `portcullis-app-firefox-sync-fxa@ci.example.org` with `dkim=pass` reaches her INBOX, and its code verifies the account;
  - `nonmember_refused`: carol (`mail_users`, not in the group, admin-verified) → refused, and no code is sent;
  - `leave_disables_via_hub`: alice is removed from the group → within 180 s her session token answers 401;
  - `rejoin_enables_via_hub`: alice is added again → within 180 s she can sign in again;
  - `email_change_disables`: alice changes her email in LLDAP → within 10 min (the periodic membership run) her account is disabled and the new email isn't listed until she verifies it;
  - `admin_disable_survives_routine_run`: bob is admin-verified and signed up; the admin UI disables him, then `POST /api/apps/firefox-sync-fxa/settings/retry` → bob is still disabled;
  - `bypass_badges`: 4 whole-host badges (`public@file`, notes = the Task 11 reasons) and the accounts host's 4 paths;
  - `mail_unwired_refuses`: the provider is unwired → `fxa-mail-check` exits 1, `mail_sender_unwired` is listed, and `POST /api/me/email/verify` → 409.
- [ ] **Step 2:** Run `python3 tests/e2e/e2e_fxa.py` against the stack, or push. Expected: FAIL before Tasks 2–16 are merged.
- [ ] **Step 3:** Wire the CI job (runner with ≥ 8 GB of RAM; the accounts image is cached).
- [ ] **Step 4:** Watch the CI with your own background watcher until `e2e-fxa` is green. Expected: PASS.
- [ ] **Step 5:** Commit `e2e: Firefox Sync + own accounts (real mail, real Hub)`. Mainline every branch and delete the worktrees at goal end.

---

## Self-review

- **Spec coverage:**
  - two templates: Task 17;
  - full stack: Task 10;
  - group by **verified** email: Tasks 3, 4 and 13;
  - join / leave / rejoin: Task 13, and Task 18 through the Hub;
  - mail through the provider: Tasks 2, 8, 14 and 18;
  - pages behind sign-in, open paths: Tasks 11 and 12;
  - bypass badges with a reason per host: Tasks 5, 6, 11 and 18;
  - MySQL `mysql:lts`, PostgreSQL for Sync, digests: Task 10;
  - resources 4 GB / 18 GB, warn not block: Tasks 7 and 10;
  - hosts (§11.3 naming): Global Constraints;
  - admin UI with its own host, forward-auth and OIDC, `ADMIN_PASSWORD` empty, no `admin_paths`: Tasks 11 and 16;
  - rate limits, XFF depth and the spoof test: Tasks 10 and 12;
  - backups: Global Constraints and Task 10;
  - `FXA_ACCOUNT_EVENTS` off: Tasks 10 and 16;
  - isolation with the gate pattern, and the other-app test: Task 12;
  - pairing: Tasks 11 and 12;
  - no cap by default: Task 14;
  - unverified members counted on the instance page: Task 4;
  - errors keep the list: Task 13;
  - verification code expiry, attempts, cleared on change, admin-set, People badges: Task 3;
  - membership hook (D5): Task 13;
  - Firefox desktop end to end "if feasible": Task 15's `first_sync` is the protocol-level stand-in; a real Firefox isn't covered.
- **Types:** `verified_email`, `Membership.VerifiedEmails`, `email_verified`, `PopulationView.NoVerifiedEmail` / `no_verified_email`, `MailState.Senders` / `senders`, `portcullis-hub-mail`, `PORTCULLIS_MAIL_SENDER_*`, `SendHubMail` / `ErrNoHubSender`, `hosts.reasons`, `mail_sender_unwired` are spelled the same in every task that names them.
- **Unverified here:**
  - whether the versioned image tags carry exactly the facts' digests (Task 10 checks);
  - the MFA JWT secret's variable name (upstream `.env-example`);
  - the auth server's mailer with STARTTLS and AUTH against Stalwart (upstream never tested it; Task 18 proves it);
  - whether Stalwart's permissions can express "send only, one From" (Task 8);
  - whether `github.com/wneessen/go-mail` is acceptable as a new Hub dependency;
  - how the People page reaches a person's own page on `people.<domain>` (Task 3 follows `web/people.html`'s existing routes).
