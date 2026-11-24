# Firefox Sync + own accounts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A new multi-instance template, `firefox-sync-fxa` ("Firefox Sync + own accounts"), that runs Mozilla's accounts service, Sync storage and the admin UI on the server. Who may have an account follows the template's access group, matched by each person's Portcullis email.

**Architecture:** Most of the work is the template in `portcullis-templates`. Its services sit on the instance's private `default` network. A Traefik-only nginx gate, `fxa-gate`, is the one service on `portcullis-proxy` (see Open decision D1). A long-running `fxa-access-sync` service applies the Hub's email data file to upstream's `ffs_access` functions, through a `membership_change` hook. The Hub gains four capabilities the design needs and that don't exist yet:
- a `person_email` option type (emails in data files);
- a TLS tier per host for routers without sign-in;
- a disk-free and setup-form resource warning;
- app mail senders: a submission-only account per instance on the wired mail provider.

Core's `mailctl` implements the senders. Core's CI gets the end-to-end test with real mail.

**Tech Stack:** Docker Compose templates (YAML, POSIX sh, nginx, MySQL client, psql), Python 3 validators and tests (PyFxA for the accounts protocol), Go (Hub, mailctl), vanilla JS (Hub UI), Markdown (contract).

**Spec:** `docs/superpowers/specs/2026-11-24-firefox-sync-own-accounts-design.md` (Hub repo, branch `fxa-design`). Upstream facts: `/Volumes/workspace/firefox-sync-drafts/plans/open-items/portcullis-own-accounts-facts.md`; upstream docs at `porelli/firefox-sync` 7216405.

**Repos and merge order:** docs → Hub (wait for the `edge` image) → core `mailctl` only (its image must exist before the Stalwart pin moves) → templates → core e2e. Every repo works on a branch named `fxa-own-accounts`.

## Open decisions (flagged, not decided by this plan)

The tasks below take the **default** named in each line. The user confirms or overrides each one before Task 1 merges.

- **D1 Network isolation.** The design relies on "the Hub's per-instance networks". Those exist only as a pending spec (`docs/superpowers/specs/pending/2026-11-02-instance-networks-design.md`), and the Hub's override writes no networks. *Default:* the existing Traefik-only gate pattern (`esphome/gate.sh`). Only `fxa-gate` joins `portcullis-proxy` and answers only `${PORTCULLIS_TRAEFIK_SOURCE}`, so no other app can reach `fxa-auth:9000`. The ARP-spoofing residual is the same as every gate's. When instance networks ship, the gate's proxy role goes and its routing stays.
- **D2 Unverified email.** The LLDAP email is user-editable and unverified (contract §5, §8 `email-unverified`). A member can set their email to an outsider's address and so admit that outsider to sign up. Changing an email also disables the account under the old address. *Default:* accept this and document it in `auth.notes`. The alternatives are making `email` admin-only for this template's population, or an email-verification feature in the Hub.
- **D3 Hostnames of non-default instances.** The Hub pre-fills `<sub>-<suffix>` for each host router (§11.3, `internal/hub/hosts.go defaultHost`). So instance `firefox-sync-fxa-team` gets `firefox-sync-accounts-team`, not `firefox-sync-team-accounts`. *Default:* no Hub change. The default instance gets exactly `<host>-accounts` and so on. The admin can edit every host on the setup form. The default instance's `firefox-sync` / `firefox-sync-admin` also collide with the existing template's default instance. The Hub refuses the second one with its usual collision error.
- **D4 The admin host's gate.** `auth.admin_paths` applies to every host of an instance (`internal/policy/file.go` builds `PathGroups` per host). With `group_access: true`, `admin_paths: ["/"]` would make the accounts pages admin-only too. *Default:* no `admin_paths`. On the admin host, group-gate requires the access group, and the admin UI's OIDC admits only `ADMIN_ALLOWED_GROUPS` = the admin group. So admins must also be in the access group. The alternative is a Hub "admin host" field.
- **D5 Trigger of `fxa-access-sync`.** `on_membership_change: restart` restarts the **whole** instance (§13.9). That would wipe Redis, which holds revoked tokens and rate-limit counters, on every membership change. *Default:* `on_membership_change: hook` and a long-running `fxa-access-sync` container that the hook execs. The design's "restarts the one-shot" becomes "re-runs the sync".
- **D6 Resource figures.** Contract §3 says `resources` are "the minimum the project's own documentation states". Upstream states 3–4 GB RAM and no disk figure. The design's 6 GB / 20 GB are our call. *Default:* `min_memory_mib: 6144`, `min_disk_gib: 20`. Task 1 widens §3's wording to "or the template's own sizing, explained in `long_description`".
- **D7 Bypass reason per host.** Badges carry the Hub's reason plus the first paragraph of `auth.notes` (`bypass.go templateNote`), not a reason per host. *Default:* the first paragraph of `auth.notes` names the open hosts and why.

## Global Constraints

- Template id `firefox-sync-fxa`, `name: Firefox Sync + own accounts`, `instances: multi`, `auth.method: forward-auth`, `group_access: true`, `group_admin: true`, `access_group: users_firefox-sync-fxa`, `admin_group: admin_firefox-sync-fxa`.
- Host routers and their default subdomains (one DNS label each, never `accounts.<x>`):
  - `firefox-sync-fxa` → `firefox-sync` (Sync);
  - `firefox-sync-fxa-accounts` → `firefox-sync-accounts`;
  - `firefox-sync-fxa-api` → `firefox-sync-api`;
  - `firefox-sync-fxa-profile` → `firefox-sync-profile`;
  - `firefox-sync-fxa-admin` → `firefox-sync-admin`;
  - `firefox-sync-fxa-pairing` → `firefox-sync-pairing`.
- Open without sign-in: the API, profile, Sync and pairing hosts (whole host). On the accounts host, only `/.well-known/fxa-client-configuration`, `/.well-known/openid-configuration`, `/__heartbeat__` and `/__lbheartbeat__` (exact paths). On the API host, `POST /v1/account/create` → `ffs-admin:8081`, also open. Everything else on the accounts host, and the whole admin host, sits behind `portcullis-auth@docker,portcullis-groups@docker`.
- Images, all pinned `tag@sha256:` (the builder resolves the versioned tag of each digest with `docker buildx imagetools inspect` and must find exactly this digest):
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
- Mail: `FXA_SMTP_PORT` 587, and `FXA_SMTP_SECURE` `false` (STARTTLS on 587) or `true` (implicit TLS on 465). The template refuses to start with neither the mail provider nor an external SMTP host.
- Resources: `min_memory_mib: 6144`, `min_disk_gib: 20`. They warn and never block.
- Volumes (keys unique across templates): `fxa-keys`, `fxa-db-data`, `fxa-profile-images`, `fxa-access-state`, `firefox-sync-fxa-db-data`. All are in the instance backup (the Hub archives every project volume, `backup.go projectVolumes`).
- Upstream config files are vendored from `porelli/firefox-sync` 7216405 into `firefox-sync-fxa/fxa-config/` and mounted `./templates/firefox-sync-fxa/fxa-config:/fxa-config:ro`. `env_file` is forbidden, so the settings in `no-telemetry.env` are written inline.
- Support scripts (`gate.sh`, `access-sync.sh`, `mail-check.sh`, `mail-select.sh`, the SQL files) are mounted `./templates/firefox-sync-fxa/<file>:/portcullis-bin/<file>:ro`. The data file's directory is `/portcullis`.
- Template rules (CONTRIBUTING): no `ports:`, `container_name:`, `env_file:` or `build:`. `cap_drop: [ALL]`, `no-new-privileges:true`, a sized `tmpfs` and `mem_limit` on every service. Router, service and middleware names contain no `_`.

## Review Focus

1. **Variants of the sign-up path.** `/v1/account/create/`, `//v1/account/create`, `/v1//account/create` and `/v1/account/create?keys=true` must never create an account for an email that isn't listed. The database policy refuses even when nginx's normalisation and the auth server's router disagree. Pinned in Task 10, `signup_path_variants_refused`.
2. **Email edge cases.** An email in mixed case or with spaces is listed lowercased and trimmed. Two members with one email give one row. Leaving keeps that row while the other member is still in the group. A changed email disables the old one and lists the new one. Pinned in Task 2, `TestPersonEmailNormalised`, and Task 11, `email_change_and_duplicates`.
3. **Lost or stale sync state.** After a restore, or after `fxa-access-state` was recreated empty, the next run still deletes and disables every listed email that is no longer in the file. Leaves come from the database rows, not only from the state file. Pinned in Task 11, `state_lost_still_disables`.
4. **Bodies and websockets through the gate.** A 2.5 MB Sync `POST` is not refused with 413, and the pairing websocket upgrade passes. Pinned in Task 10, `sync_body_2_5mb` and `pairing_websocket`.
5. **A sign-in template that asks for a YubiKey certificate.** Firefox presents no client certificate, so the open hosts must not request one, and Firefox must still reach the accounts host's open paths. Pinned in Task 3, `TestOpenOnlyHostGetsPublicTier` and `TestMixedHostDowngradedToDefault`.

---

## File Structure

**docs (`/Volumes/workspace/portcullis/.m-docs`):**
- `docs/guides/integration-contracts.md`: §3 (catalog `resources` wording, `mail_sender` block), §5 (tier per host), §11.7 (resource warnings), §13.2/§13.7 (`person_email`), new §19.14 (app mail senders).
- `docs/guides/manifest-reference.md`: `mail_sender` and `person_email`.

**Hub (`.m-hub`):**
- `internal/templates/settings.go` (type constant), `internal/templates/personemail.go` (new: rules), `internal/settings/kinds_person.go` (kind).
- `internal/hub/personemail.go` (new: data-file rendering and the no-email list), `internal/hub/deliver_files.go`, `internal/hub/panel.go`, `web/settings.js`.
- `internal/hub/tlstier.go` (new), `internal/hub/override.go`, `internal/hub/bypass.go`.
- `internal/hub/usage_view.go`, `web/marketplace.js`, `web/index.html` (setup form).
- `internal/templates/mailsender.go` (new), `internal/mailprovider/types.go`, `internal/hub/mail_senders.go` (new), `internal/hub/env.go`, `internal/hub/doctor_mail.go`, `internal/state/state.go`.
- `web/docs/integration-contracts.md`: the copy of the contract.

**core (`.m-core`):** `mailctl/internal/state/`, `mailctl/internal/reconcile/senders.go` (new), `tests/mail-conformance/`, `tests/e2e/e2e_fxa.py` (new), `.github/workflows/ci.yml` (job `e2e-fxa`).

**templates (worktree off `origin/main`, after `firefox-sync-admin` lands):**
- `schema/manifest.schema.json`, `tests/validate.py`, `tests/test_validate.py`, `stalwart/compose.yml` (mailctl pin).
- `firefox-sync-fxa/manifest.yaml`, `compose.yml`, `gate.sh`, `access-sync.sh`, `mail-check.sh`, `guard.sql`, `revoke.sql`, `admin-db.sql`, `fxa-config/{oauth-clients.js,content-server.js}`.
- `tests/apps/firefox-sync-fxa.sh`, `tests/fxa_client.py` (PyFxA helper), `tests/requirements.txt` (PyFxA, hashed).

---

### Task 1: Contract first (docs)

**Files:**
- Modify: `/Volumes/workspace/portcullis/.m-docs/docs/guides/integration-contracts.md` (§3 catalog fields line ~153, §3 new "`mail_sender`", §5 TLS tier, §11.7, §13.2, §13.7, new §19.14)
- Modify: `/Volumes/workspace/portcullis/.m-docs/docs/guides/manifest-reference.md`
- Copy to: `/Volumes/workspace/portcullis/.m-hub/web/docs/integration-contracts.md` (in Task 2's branch)

**Interfaces:**
- Produces (the contract every later task implements):
  - `person_email` type (§13.2). Effective scope `person`. The Hub sets it, and any admin input is refused "set by the Hub". `self_visible: false`. Only `{file: {name, field}}` deliveries. Only on templates with `group_access: true` and an `access_group`. The value is the person's LLDAP email, trimmed and lowercased, and must pass `lldap.ValidEmail`. A person without one is left out of the file and listed in the panel's `population.no_email`.
  - §13.7: the people section carries `"<user>": {"<field>": "<email>"}`.
  - §5: each host gets its own TLS option. A host whose routers all lack `portcullis-auth` gets `public@file`. A host that mixes open and gated routers gets `HostTier(tier, true)`. A host with only gated routers keeps the instance tier.
  - §11.7 / §3: the Marketplace card and the setup form warn when `memory_bytes < min_memory_mib·2^20` or the `docker_data` disk's free bytes are below `min_disk_gib·2^30`. They warn and never block. `GET /api/usage` `hosts.<id>.disk_free_bytes` (int64 or null).
  - §3 `mail_sender: {label}` (≤ 64 characters, one line) and §19.14 app senders:
    - MailState `senders: [{username, uuid, address}]`, with `username` = `portcullis-app-<instance>` and `address` = `portcullis-app-<instance>@<primary_domain>`;
    - the provider MUST create a submission-only account with no mailbox and no IMAP, allow `MAIL FROM` / `From:` = `address` only, refuse inbound mail to it with `550 5.1.1`, and apply `limits`;
    - the credential comes from the existing `POST /v1/credentials` with `allowed_ips: []`;
    - instance env `PORTCULLIS_MAIL_SENDER_HOST` (= `MAIL_HOSTNAME`), `_PORT` (`587`), `_USER` (= address), `_PASSWORD` (in the 0600 `.env`), `_FROM` (`"<label> <address>"`). All are empty while no provider is wired or mail is off;
    - wiring, switching or a restore voids the credential. The Hub creates a new one at its next sync and restarts the instance;
    - doctor kind `mail_sender_unwired` (Warning).
  - §3 `resources` wording: "…or the template's own sizing, explained in `long_description`" (D6).

- [ ] **Step 1:** Write the sections above, with the exact names and values given here. Mark each one **NEW (Firefox own accounts)**, like the other NEW markers.
- [ ] **Step 2:** Run `zensical build --strict --clean && python scripts/check-lists.py site` in the docs repo. Expected: exit 0.
- [ ] **Step 3:** Commit `contract: person_email, TLS tier per host, resource warnings, app mail senders (Firefox own accounts)`.

---

### Task 2: Hub: `person_email` option type

**Files:**
- Modify: `internal/templates/settings.go:463-472` (add `TypePersonEmail = "person_email"` to the builtin types)
- Create: `internal/templates/personemail.go`, `internal/templates/personemail_test.go`
- Modify: `internal/settings/kinds_person.go` (kind: `Parse` refuses "set by the Hub"; `Display` = the email)
- Create: `internal/hub/personemail.go`, `internal/hub/personemail_test.go`
- Modify: `internal/hub/deliver_files.go` (`fileNeedsPeople` true for it; `renderDocLocked` people section), `internal/hub/panel.go:61` (`PopulationView`), `web/settings.js` (the note)

**Interfaces:**
- Consumes: `directory.Membership.Emails` (`internal/directory/membership.go:50`), `populationLocked`, `lldap.ValidEmail`.
- Produces:
  - `func validatePersonEmail(o *Option, m *Manifest) error` (called from the type switch where `TypePersonID` is checked, `settings.go:1298`);
  - `func personEmailOptions(t *templates.Template) []*templates.Option`;
  - `func emailOf(m *directory.Membership, user string) (string, bool)`: trimmed, lowercased, valid;
  - `func (h *Hub) noEmailLocked(t *templates.Template, m *directory.Membership) []string`: sorted population members without an email;
  - `PopulationView.NoEmail []string` with JSON tag `no_email,omitempty`.

- [ ] **Step 1: Write the failing tests**

```go
func TestPersonEmailValidation(t *testing.T) // refused: scope set, default set, env/claim/hook delivery,
//   self_visible true, a template without group_access or access_group; accepted: {file:{name:access,field:email}}
func TestPersonEmailInDataFile(t *testing.T) // members alice (Alice@Example.org ), bob (bob@example.org), carol (none):
//   doc.People == {"alice":{"email":"alice@example.org"},"bob":{"email":"bob@example.org"}}; "carol" absent
func TestPersonEmailNormalised(t *testing.T) // " Bob@EXAMPLE.org" -> "bob@example.org"; "not-an-email" left out
func TestPersonEmailNoEmailListed(t *testing.T) // panel population.no_email == ["carol"]
func TestPersonEmailNotParsedFromAdmin(t *testing.T) // PUT …/settings with the key -> 400 "set by the Hub"
func TestPersonEmailChangeRedelivers(t *testing.T) // alice's email changes in m -> buildFilesLocked output differs (membership run)
```

- [ ] **Step 2:** Run `go test ./internal/templates/ ./internal/settings/ ./internal/hub/ -run 'PersonEmail'`. Expected: FAIL (unknown type `person_email`).
- [ ] **Step 3:** Implement the signatures above. `renderDocLocked` writes the field for each carried member that has an email. `logIdless`'s pattern logs the members it left out. The settings panel shows "N people have no email in Portcullis and can't have an account: <names>" when `no_email` isn't empty.
- [ ] **Step 4:** Run `go test ./...`. Expected: PASS. Then copy the contract (Task 1) to `web/docs/integration-contracts.md`.
- [ ] **Step 5:** Commit `settings: person_email type (emails in data files)`.

---

### Task 3: Hub: TLS tier per host for routers without sign-in

**Files:**
- Create: `internal/hub/tlstier.go`, `internal/hub/tlstier_test.go`
- Modify: `internal/hub/override.go:687-730` (`routeLabels` gains `routerTier map[string]string`; the label loop at `:419` writes `routerTier[r]`), `internal/hub/bypass.go:91` (`Bypass.Tier` per badge from its hosts), the Kubernetes translator input (it takes the same `routeLabels`)
- Test: `internal/hub/bypass_test.go`

**Interfaces:**
- Consumes: `templateChains`, `chainSignsIn`, `routerHosts`, `policy.HostTier`.
- Produces:
  - `func (h *Hub) routerTiersLocked(t *templates.Template, rl *routeLabels) map[string]string`: router → tier. All routers of one host get the same value, because Traefik picks the options per SNI host.

- [ ] **Step 1: Write the failing tests** (a fixture template shaped like `firefox-sync-fxa`: forward-auth; open routers on the api, profile, sync and pairing hosts; an accounts host with an open router `Path(/.well-known/fxa-client-configuration) || …` plus a gated host router; a gated admin host; the default sign-in template requires `yubikey_cert`, so the instance tier is `protected@file`)

```go
func TestOpenOnlyHostGetsPublicTier(t *testing.T)    // api/profile/sync/pairing routers -> "public@file"
func TestMixedHostDowngradedToDefault(t *testing.T)  // both accounts routers -> "default" (policy.TierDefault)
func TestGatedOnlyHostKeepsTier(t *testing.T)        // admin router -> "protected@file"
func TestCustomAppUnchanged(t *testing.T)            // a method: custom fixture: every router "public@file", as before
func TestBypassBadgesFxaShape(t *testing.T)          // 4 open_router badges with Paths [] (whole host) and Tier public@file;
//   1 open_router on the accounts host with Paths = the 4 exact paths and Tier default; no weak_tls badge for them
```

- [ ] **Step 2:** Run `go test ./internal/hub/ -run 'Tier|Bypass'`. Expected: FAIL.
- [ ] **Step 3:** Implement `routerTiersLocked`. Group the routers by host; a host is open-only when no router on it signs in. Keep `rl.tier` as the instance tier used for `weak_tls`.
- [ ] **Step 4:** Run `go test ./...` (including `TestRealTemplatesInstances` and the golden tests: existing templates must produce byte-identical overrides). Expected: PASS.
- [ ] **Step 5:** Commit `override: TLS option per host; hosts without sign-in get public@file`.

---

### Task 4: Hub: resource warnings (disk free, setup form)

**Files:**
- Modify: `internal/hub/usage_view.go:44-51` (`UsageHost.DiskFreeBytes *int64` with JSON tag `disk_free_bytes`, from the cached `docker_data` disk of that server, `usage_storage_cache.go`)
- Modify: `web/marketplace.js:384-447` (`loadHostMem` → `loadHostRes` reads both; the disk line gets the same warn pill), `web/index.html:4449` (`setupFormHtml`: a `setup-warn` line per figure)
- Test: `internal/hub/usage_test.go`, `internal/httpapi/webui_marketplace_test.go`, `internal/httpapi/webui_setup_test.go`

**Interfaces:**
- Consumes: `Manifest.Resources{MinMemoryMiB, MinDiskGiB}` (`internal/templates/catalog.go`).
- Produces: `GET /api/usage` `hosts.primary.disk_free_bytes`. Card copy: `needs ≥ 20 GiB free disk` + pill `more than this server has free (<n> GiB)`. Setup form copy (exact): `This app needs about 6 GiB of RAM; this server has <n> GiB. It may not start or may slow other apps.` and `This app needs about 20 GiB of free disk; this server has <n> GiB free.`

- [ ] **Step 1: Write the failing tests:**
  - `TestUsageHostDiskFree` (a cached `docker_data` disk with free 12 GiB → `disk_free_bytes == 12<<30`; no cache → `null`);
  - marketplace: with `resources {min_memory_mib: 6144, min_disk_gib: 20}`, `memory_bytes` 4 GiB and `disk_free_bytes` 12 GiB → both pills present; with 8 GiB / 40 GiB → no pill;
  - setup form: the same two cases. The Install button stays enabled in both (warn, never block).
- [ ] **Step 2:** Run `go test ./internal/hub/ ./internal/httpapi/ -run 'DiskFree|Marketplace|Setup'`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `go test ./...`. Expected: PASS.
- [ ] **Step 5:** Commit `marketplace, setup form: warn on low RAM or free disk`.

---

### Task 5: Hub: app mail senders

**Files:**
- Create: `internal/templates/mailsender.go` (+ `_test.go`): `Manifest.MailSender *MailSender{Label string}`
- Modify: `internal/mailprovider/types.go:16-35` (`MailState.Senders []Sender`; `type Sender struct{Username, UUID, Address string}` with JSON tags `username`, `uuid`, `address`)
- Create: `internal/hub/mail_senders.go`, `internal/hub/mail_senders_test.go`
- Modify: `internal/hub/mail.go:274` (`mailBuild` adds the senders), `internal/hub/env.go` (the five `PORTCULLIS_MAIL_SENDER_*` instance variables, rewritten before every up like `t.InstanceEnv`), `internal/state/state.go` (`MailSenders map[string]state.MailSender{UUID, CredentialID, CreatedAt}`; the password lives on `hub_secrets`, never in `state.yaml`), `internal/hub/doctor_mail.go` (`mail_sender_unwired`), `internal/hub/restore.go` (a restore voids the credential)

**Interfaces:**
- Consumes: `mailprovider.Client.CreateCredential(ctx, user, uuid, label string, expires *time.Time) (Created, error)`, `RevokeCredential`, `h.mailCore()` (`MAIL_HOSTNAME`, primary domain), `credstore` (the secret store used for `person_secret`).
- Produces:
  - `func (h *Hub) mailSendersLocked() []mailprovider.Sender`: enabled instances whose template has `mail_sender`, sorted by username;
  - `func (h *Hub) ensureSenderCredential(ctx context.Context, instance string) (changed bool, err error)`;
  - `func senderEnv(instance string, s *storedSender, mc mailCoreEnv, label string) map[string]string`;
  - doctor kind `mail_sender_unwired`.

- [ ] **Step 1: Write the failing tests**

```go
func TestSenderInMailState(t *testing.T)        // enabled firefox-sync-fxa -> Senders == [{portcullis-app-firefox-sync-fxa, <uuid>,
//   portcullis-app-firefox-sync-fxa@ci.example.org}]; a disabled instance is absent
func TestSenderEnvWired(t *testing.T)           // HOST == MAIL_HOSTNAME, PORT "587", USER == address,
//   FROM == "Firefox accounts <portcullis-app-firefox-sync-fxa@ci.example.org>", PASSWORD == the created secret, .env 0600
func TestSenderEnvUnwired(t *testing.T)         // no provider: all five keys present and "" ; doctor finding mail_sender_unwired (warning)
func TestSenderVoidedOnSwitch(t *testing.T)     // provider switch -> old credential gone, new CreateCredential, instance restart queued
func TestSenderVoidedOnRestore(t *testing.T)
func TestSenderLabelValidation(t *testing.T)    // label "" / > 64 runes / with "\n" refused
func TestSenderNoMailboxLeak(t *testing.T)      // the sender is never in Accounts, mail_users or MyMail
```

- [ ] **Step 2:** Run `go test ./internal/... -run 'Sender'`. Expected: FAIL.
- [ ] **Step 3:** Implement. A new credential is created after the provider has applied the generation that adds the sender (`mailWaitApplied`). The password is never logged or audited; the audit entry is `mail_sender.created` with the instance id only.
- [ ] **Step 4:** Run `go test ./...` and `go vet ./...`. Expected: PASS.
- [ ] **Step 5:** Commit `mail: app senders (submission-only account per instance)`. Wait for the `edge` image before Task 7.

---

### Task 6: core mailctl: senders on Stalwart

**Files:**
- Modify: `/Volumes/workspace/portcullis/.m-core/mailctl/internal/state/` (parse `senders`, strict like the rest)
- Create: `mailctl/internal/reconcile/senders.go`, `senders_test.go`
- Modify: `tests/mail-conformance/` vectors (MailState with `senders`)
- Then, in templates: `stalwart/compose.yml` (the mailctl pin `main-<sha7>@sha256:<digest>` from the published image, copied from tool output)

**Interfaces:**
- Consumes: MailState `senders` (Task 1 / Task 5 shape).
- Produces: in Stalwart, an account per sender with the `email-send` permission only (no IMAP, JMAP or mailbox), a sending-address restriction to `address`, and `550 5.1.1` at RCPT for `address`. Credentials go through the existing `/v1/credentials`.

- [ ] **Step 1: Write the failing tests:**
  - `TestSenderAccountCreated` (permissions exactly send);
  - `TestSenderFromRestricted` (a `From` other than `address` → refused at DATA);
  - `TestSenderInboundRefused` (RCPT `address` → 550 5.1.1);
  - `TestSenderRemovedWithInstance` (absent from the next document → account and credentials destroyed);
  - `TestSenderNotMassRemoval` (removing senders never counts toward `mass_removal`).
- [ ] **Step 2:** Run `cd mailctl && go test ./...`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `cd mailctl && go test ./...` and the conformance suite. Expected: PASS.
- [ ] **Step 5:** Commit `mailctl: app senders`, merge, wait for `mailctl.yml` to publish `main-<sha7>`. Then bump the Stalwart pin in templates (`python3 tests/validate.py` passes) and commit `stalwart: mailctl main-<sha7> (app senders)`.

---

### Task 7: templates validator: `person_email`, `mail_sender`, sender variables

**Files:**
- Modify: `schema/manifest.schema.json` (type list at `:616`; top-level `mail_sender {label}`), `tests/validate.py` (`PERSON_TYPES`-like handling at `:3204-3205` and `:5832`; `INSTANCE_VAR_TEXT_RE` at `:1625` accepts `PORTCULLIS_MAIL_SENDER_(HOST|PORT|USER|PASSWORD|FROM)` only when the manifest has `mail_sender`)
- Test: `tests/test_validate.py`

**Interfaces:**
- Consumes: Task 1's rules.
- Produces: the validator Tasks 8–14 run.

- [ ] **Step 1: Write the failing tests:**
  - `test_person_email_needs_group_access`;
  - `test_person_email_file_delivery_only`;
  - `test_person_email_self_visible_false`;
  - `test_mail_sender_vars_need_block` (`${PORTCULLIS_MAIL_SENDER_HOST:-}` without `mail_sender` → error);
  - `test_mail_sender_label_bounds`.
- [ ] **Step 2:** Run `python3 -m pytest tests/test_validate.py -k 'person_email or mail_sender'`. Expected: FAIL.
- [ ] **Step 3:** Implement, with the Hub's refusal texts word for word (parity).
- [ ] **Step 4:** Run `python3 -m pytest tests/test_validate.py && python3 tests/validate.py`. Expected: PASS.
- [ ] **Step 5:** Commit `validate: person_email, mail_sender`.

---

### Task 8: `firefox-sync-fxa` skeleton: services, start order, volumes, static checks

**Files:**
- Create: `firefox-sync-fxa/manifest.yaml`, `firefox-sync-fxa/compose.yml`, `firefox-sync-fxa/fxa-config/{oauth-clients.js,content-server.js}` (vendored from 7216405, unmodified, with a header comment naming the source commit)
- Create: `tests/apps/firefox-sync-fxa.sh` (section "static")

**Interfaces:**
- Consumes: Global Constraints (images, hosts, volumes).
- Produces:
  - service names: `fxa-keys-owner`, `fxa-db`, `fxa-redis`, `fxa-migrations`, `fxa-policy`, `fxa-mail-check`, `fxa-auth`, `fxa-content`, `fxa-profile`, `fxa-profile-worker`, `fxa-profile-static`, `fxa-pairing`, `ffs-admin`, `fxa-access-sync`, `firefox-sync-fxa-db`, `firefox-sync-fxa-migrate`, `firefox-sync-fxa-db-init`, `firefox-sync-fxa-init`, `firefox-sync-fxa` (syncstorage), `fxa-gate`;
  - generated env (`generate: random`): `FXA_MYSQL_PASSWORD`, `FXA_ADMIN_DB_PASSWORD`, `FXA_ACCESS_DB_PASSWORD`, `FXA_OAUTH_SECRET`, `FXA_AUTH_SECRET`, `FXA_PROFILE_SECRET`, `FXA_FLOW_ID_KEY`, `FXA_SESSION_TOKEN_HANDLE_KEY`, `FXA_CONTENT_SESSION_SECRET`, the MFA JWT secret upstream's `.env-example` names, `FIREFOX_SYNC_FXA_DB_PASSWORD`, `FIREFOX_SYNC_FXA_APP_DB_PASSWORD`, `FIREFOX_SYNC_FXA_MASTER_SECRET`, `FIREFOX_SYNC_FXA_METRICS_SECRET`, `FIREFOX_SYNC_FXA_ADMIN_OIDC_SECRET`.

- [ ] **Step 1: Write the failing static checks** in `tests/apps/firefox-sync-fxa.sh` (yq over compose and manifest, `pass`/`fail` from `tests/lib.sh`):
  - `six_host_routers`: the host routers are exactly the six of Global Constraints, each with its default subdomain;
  - `start_order`:
    - `fxa-auth.depends_on` has `fxa-keys-owner` and `fxa-policy` with `service_completed_successfully` and `fxa-redis` with `service_healthy`;
    - `fxa-policy` depends on `fxa-migrations` (completed), which depends on `fxa-db` (healthy);
    - `fxa-content` depends on `fxa-auth` and `fxa-profile` (healthy);
    - `firefox-sync-fxa` depends on `firefox-sync-fxa-init` (completed), which depends on `firefox-sync-fxa-db-init` (completed), which depends on `firefox-sync-fxa-migrate` (completed);
  - `only_gate_on_proxy`: `fxa-gate` is the only service whose networks include `portcullis-proxy`, and every other service is on `default` only;
  - `images_pinned`: every `image:` matches `@sha256:` and equals Global Constraints' digests;
  - `env_values`: `ADMIN_ACCESS_EXTERNAL` = `"1"` on `fxa-policy` and `ffs-admin`, `ADMIN_PASSWORD` = `""`, `ACCOUNT_EVENTS_ENABLED` = `"false"`, `IP_PROFILING_RECENCY` = `0`, `CLIENT_ADDRESS_DEPTH` = `"2"`, `CUSTOMS_SERVER_URL` = `none`, `FXA_SIGNUP_ALLOWLIST` absent everywhere;
  - `tokenserver_internal`: `SYNC_TOKENSERVER__FXA_OAUTH_SERVER_URL` = `http://fxa-auth:9000/v1` and `SYNC_TOKENSERVER__FXA_EMAIL_DOMAIN` = `${PORTCULLIS_HOST_FIREFOX_SYNC_FXA_API:-firefox-sync-api.portcullis.local}`;
  - `volumes`: exactly `fxa-keys`, `fxa-db-data`, `fxa-profile-images`, `fxa-access-state`, `firefox-sync-fxa-db-data`; `fxa-redis` has none;
  - `resources`: `min_memory_mib == 6144`, `min_disk_gib == 20`;
  - `node_trusts_ca`: every Node service sets `NODE_EXTRA_CA_CERTS` to the mounted `./certs/ca-bundle.crt` (they call the public URLs, staging certificates included).
- [ ] **Step 2:** Run `bash tests/apps/firefox-sync-fxa.sh` (static part, `STATIC_ONLY=1`) and `python3 tests/validate.py firefox-sync-fxa`. Expected: FAIL (no template).
- [ ] **Step 3:** Write the manifest and compose. The services follow upstream's `compose/fxa.yml`, with `ports:` and `env_file:` removed and the `no-telemetry.env` values inline. Healthchecks are the upstream ones (`node -e fetch(.../__heartbeat__)`, `start_period: 300s`). The Sync side mirrors `firefox-sync/compose.yml` (Task 13 fills in its SQL).
- [ ] **Step 4:** Run the same two commands, plus `python3 tests/validate.py --placement`. Expected: PASS.
- [ ] **Step 5:** Commit `firefox-sync-fxa: services, start order, volumes`.

---

### Task 9: Traefik routers: open and gated paths

**Files:**
- Modify: `firefox-sync-fxa/compose.yml` (labels on `fxa-gate` only; every router `.service: firefox-sync-fxa-gate`, port 8080)
- Test: `tests/apps/firefox-sync-fxa.sh` (section "routers")

**Interfaces:**
- Produces these routers:
  - host routers: `firefox-sync-fxa`, `firefox-sync-fxa-api`, `firefox-sync-fxa-profile` and `firefox-sync-fxa-pairing` carry `rate-limit@file,security-headers@file`; `firefox-sync-fxa-accounts` and `firefox-sync-fxa-admin` carry `client-headers@file,portcullis-auth@docker,portcullis-groups@docker,security-headers@file`;
  - path routers: `firefox-sync-fxa-accounts-open` (the four exact `Path()`s, priority 1000, `rate-limit@file,security-headers@file`), `firefox-sync-fxa-signup` (API host `&& Path(/v1/account/create)`, priority 1000, `rate-limit-auth@file,security-headers@file`), and `firefox-sync-fxa-token` (Sync host `&& PathPrefix(/1.0/)`, `rate-limit-auth@file`), as in `firefox-sync`.

- [ ] **Step 1: Write the failing checks:**
  - `routers_exact`: the set of router names equals the list above;
  - `open_routers_no_gateway`: no `portcullis-` middleware on the open routers;
  - `gated_routers_gateway`: the exact middleware string on the accounts and admin host routers;
  - `accounts_open_paths`: the open router's rule is exactly the four `Path()` alternatives;
  - `manifest_auth`: `method: forward-auth`, `group_access: true`, no `admin_paths` (D4).
- [ ] **Step 2:** Run the router section. Expected: FAIL.
- [ ] **Step 3:** Add the labels.
- [ ] **Step 4:** Run the router section and `python3 tests/validate.py firefox-sync-fxa`. Expected: PASS.
- [ ] **Step 5:** Commit `firefox-sync-fxa: routers (open hosts, open paths, gated pages)`.

---

### Task 10: `fxa-gate`: Traefik-only nginx router

**Files:**
- Create: `firefox-sync-fxa/gate.sh` (the `esphome/gate.sh` pattern: `cidr_ok`, fail closed, credential stripping; then one `server` block per host)
- Modify: `firefox-sync-fxa/compose.yml` (`fxa-gate` env: `PORTCULLIS_TRAEFIK_SOURCE: ${PORTCULLIS_TRAEFIK_SOURCE:-172.31.250.2/32}` and the six `GATE_HOST_*` from the host variables)
- Test: `tests/apps/firefox-sync-fxa.sh` (section "gate", runtime)

**Interfaces:**
- Consumes: Task 9's routers (all to port 8080).
- Produces: nginx `server_name` per host:
  - accounts → `fxa-content:3030`;
  - api → `fxa-auth:9000`, with `location = /v1/account/create` → `ffs-admin:8081`;
  - profile → `fxa-profile:1111`, with `/img/` → `fxa-profile-static:1112` (prefix stripped);
  - Sync → `firefox-sync-fxa-internal:8000`;
  - admin → `ffs-admin:8080`;
  - pairing → `fxa-pairing:8000` (websocket `Upgrade`/`Connection`);
  - unknown host → 421.
- Rules: `client_max_body_size 10m` on the Sync host; `proxy_set_header X-Forwarded-For $http_x_forwarded_for` (passed through, never appended); `Host` kept; peer not in `PORTCULLIS_TRAEFIK_SOURCE` → 403.

- [ ] **Step 1: Write the failing runtime checks** (the stack up with `compose_up`, core Traefik in front; `via_traefik` from `tests/lib.sh`):
  - `open_paths_anonymous`: the four accounts paths answer 200 without a cookie, and `/` on the accounts host redirects to Keycloak (`assert_redirect_to_keycloak`);
  - `admin_gated`: the admin host `/` redirects to Keycloak;
  - `another_app_cannot_reach_auth`: a pinned `curlimages/curl` container on `portcullis-proxy` runs `curl --max-time 5 http://fxa-auth:9000/__heartbeat__`, which fails with exit 6 or 7 or 28; `curl -H "Host: <api host>" http://<fxa-gate ip>:8080/v1/account/create` → 403;
  - `spoofed_xff_same_key`: 6 failed `POST /v1/account/login` for one email through Traefik, each with `X-Forwarded-For: 203.0.113.<n>`. The 6th answers 429 with errno 114. `redis-cli --scan --pattern '*203.0.113*'` in `fxa-redis` returns nothing;
  - `sync_body_2_5mb`: a 2.5 MB `POST` to the Sync host's `/1.5/x/storage/bookmarks` answers 401 (Hawk), never 413;
  - `pairing_websocket`: a websocket upgrade to the pairing host answers 101;
  - `signup_path_variants_refused`: `POST` create for `nobody@example.org` on `/v1/account/create/`, `//v1/account/create`, `/v1//account/create` and `/v1/account/create?keys=true` → never 200, and `SELECT COUNT(*) FROM fxa.accounts WHERE normalizedEmail='nobody@example.org'` = 0.
- [ ] **Step 2:** Run `bash tests/apps/firefox-sync-fxa.sh`. Expected: FAIL.
- [ ] **Step 3:** Write `gate.sh` and the compose entries.
- [ ] **Step 4:** Run the same command. Expected: PASS.
- [ ] **Step 5:** Commit `firefox-sync-fxa: fxa-gate (Traefik only, one server per host)`.

---

### Task 11: `fxa-access-sync`: the access group to the sign-up allowlist

**Files:**
- Create: `firefox-sync-fxa/access-sync.sh`
- Modify: `firefox-sync-fxa/manifest.yaml`:
  - `files: [{name: access, service: fxa-access-sync, mount: /portcullis, on_membership_change: hook}]`;
  - option `access_email` (`type: person_email`, `self_visible: false`, `delivery: [{file: {name: access, field: email}}]`);
  - `hooks: [{name: access-sync, service: fxa-access-sync, command: [/bin/sh, /portcullis-bin/access-sync.sh], when: [start, membership_change], timeout: 120s}]`
- Modify: `firefox-sync-fxa/compose.yml` (`fxa-access-sync`: mysql client image = the `mysql` digest, `user: "10001:10001"`, `group_add: ["10001"]`, volume `fxa-access-state:/state`, command `sleep infinity`; depends on `fxa-policy` completed with `restart: true`)
- Test: `tests/apps/firefox-sync-fxa.sh` (section "access"), `tests/fxa_client.py`

**Interfaces:**
- Consumes: data file `/portcullis/access.json` (`people.<user>.email`); DB user `ffs_access` / `FXA_ACCESS_DB_PASSWORD` (env only, never argv; `MYSQL_PWD`).
- Produces: `/state/applied.json` = `{"version":1,"listed":[…],"removed":[…]}` (sorted, lowercase); exit 0 = applied; exit 1 = nothing changed.
- Algorithm (the design decides it; how leaves are found is spelled out here because Review Focus 3 depends on it):

```text
new      = sorted unique lowercase emails of people.*.email     (missing / unparsable / version != 1 -> exit 1, no SQL)
db       = SELECT email FROM ffs.signup_allowlist
joins    = new - db                                     -> INSERT
leaves   = (db ∪ state.listed) - new                    -> DELETE, then CALL ffs.disable_account_by_email(e)
rejoins  = joins ∩ state.removed                        -> INSERT, then CALL ffs.enable_account_by_email(e)
"no such account" from disable/enable                   -> ignored
state    = {listed: new, removed: (state.removed ∪ leaves) - new}   written atomically after COMMIT
```

- [ ] **Step 1: Write the failing runtime checks** (the data file comes from `write_appfiles_override firefox-sync-fxa access …`; sign-ups go through `tests/fxa_client.py signup <email> <password>` (PyFxA `fxa.core.Client`) against a mail catcher set as the external SMTP of Task 12):
  - `nonmember_refused`: an empty list → signing up `alice@example.org` is refused (HTTP 400) and no `fxa.accounts` row exists;
  - `join_allows`: alice listed → sign-up plus the catcher's code → a verified account;
  - `leave_disables`: alice removed, hook run → `fxa.accounts.disabledAt` is set and her session token answers 401;
  - `rejoin_enables`: alice listed again → `disabledAt` is NULL;
  - `admin_disable_survives`: `CALL ffs.disable_account_by_email('bob@example.org')` (as the admin UI's Disable does) while bob stays listed, then the hook runs (a routine run with an unchanged file) → bob is still disabled;
  - `missing_file_keeps_list`: the file is deleted, the hook exits 1, and `ffs.signup_allowlist` is unchanged;
  - `unparsable_file_keeps_list`: same, with `{`;
  - `email_change_and_duplicates`: alice's email changes → the old one is disabled and the new one listed; two people with `shared@example.org` → one row, still there after one of them leaves;
  - `state_lost_still_disables`: `fxa-access-state` is recreated empty, carol is in the DB but not in the file → the next run deletes and disables carol.
- [ ] **Step 2:** Run `bash tests/apps/firefox-sync-fxa.sh`. Expected: FAIL.
- [ ] **Step 3:** Write `access-sync.sh` (POSIX sh + `mysql --batch`; emails are passed as SQL string literals only after a strict `^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+$` check, quotes doubled) and the manifest entries.
- [ ] **Step 4:** Run the same command. Expected: PASS.
- [ ] **Step 5:** Commit `firefox-sync-fxa: fxa-access-sync (group to sign-up allowlist)`.

---

### Task 12: Mail: the provider by default, or an external SMTP server

**Files:**
- Create: `firefox-sync-fxa/mail-check.sh`
- Modify: `firefox-sync-fxa/manifest.yaml`:
  - `mail_sender: {label: Firefox accounts}`;
  - section `Mail` with instance options `mail_source` (enum `provider` "The server's mail provider" / `external` "Another SMTP server", default `provider`), `smtp_host` (string, format hostname), `smtp_port` (int 1–65535, default 587), `smtp_security` (enum `starttls` "STARTTLS (587)" / `tls` "TLS (465)", default `starttls`), `smtp_user` (string), `smtp_password` (secret), `smtp_sender` (string, format email), `max_accounts` (int, min 1, optional, section `Accounts`);
  - `requires: [smtp_host, smtp_sender]` on `smtp_user`;
  - every option `applies: restart`
- Modify: `firefox-sync-fxa/compose.yml`:
  - `fxa-mail-check` is a one-shot that validates only (the same env as `fxa-auth`), and `fxa-auth` depends on it completed;
  - `fxa-auth`'s existing `sh -c` command first runs `. /portcullis-bin/mail-select.sh`. It exports `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_SECURE` and `SMTP_SENDER` from `PORTCULLIS_MAIL_SENDER_*` (`mail_source=provider`) or from the external settings, then `exec`s the key server;
  - `ffs-admin` (distroless, no shell) keeps `SMTP_HOST: ""` as in `firefox-sync/`: no admin mail.
- Create: `firefox-sync-fxa/mail-select.sh` (sourced; shared by `mail-check.sh`)

**Interfaces:**
- Consumes: `PORTCULLIS_MAIL_SENDER_*` (Task 5); the settings above as env (`MAIL_SOURCE`, `EXT_SMTP_HOST`, `EXT_SMTP_PORT`, `EXT_SMTP_SECURITY`, `EXT_SMTP_USER`, `EXT_SMTP_PASSWORD`, `EXT_SMTP_SENDER`).
- Produces: the auth server's `SMTP_*`, with `SMTP_SECURE` `false` for starttls and `true` for tls, and port 587 for the provider. `FXA_MAX_ACCOUNTS: ${MAX_ACCOUNTS:-unlimited}` on `fxa-policy`.

- [ ] **Step 1: Write the failing checks:**
  - `refuses_without_mail`: `mail_source=provider` with empty sender env → `fxa-mail-check` exits 1 and logs exactly `portcullis: no mail: wire a mail provider or set an external SMTP server`, and `fxa-auth` isn't started;
  - `external_used`: `mail_source=external`, host = the CI mail catcher, `starttls` → `FXA_SMTP_SECURE=false`, port 587 → the sign-up code arrives at the catcher;
  - `provider_used`: the sender env is set → in `fxa-auth`'s process environment (`/proc/1/environ`), `SMTP_HOST` equals `PORTCULLIS_MAIL_SENDER_HOST`, `SMTP_SECURE=false`, `SMTP_PORT=587`, and `SMTP_SENDER` is the `_FROM` value;
  - `secret_not_in_argv`: `docker inspect` of every container shows no SMTP password in `Args` or `Cmd`;
  - `no_cap_default`: `FXA_MAX_ACCOUNTS` is `unlimited` without the setting and `5` with `max_accounts=5`.
- [ ] **Step 2:** Run `bash tests/apps/firefox-sync-fxa.sh`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the same command and `python3 tests/validate.py firefox-sync-fxa`. Expected: PASS.
- [ ] **Step 5:** Commit `firefox-sync-fxa: mail (provider or external SMTP), optional account cap`.

---

### Task 13: Sync side: our guard on the Sync database (**depends on `firefox-sync-admin` landing**)

**Files:**
- Create: `firefox-sync-fxa/guard.sql`, `revoke.sql`, `admin-db.sql` (from the branch's `firefox-sync/` versions, without the uid allowlist table and its trigger: own accounts are already gated)
- Modify: `firefox-sync-fxa/compose.yml` (the `firefox-sync-fxa-*` services as in the branch: `firefox-sync-fxa-db-init` with `ADMIN_ACCESS_EXTERNAL: "1"`, `MAX_USERS: unlimited`, `SYNC_ALLOWED_ACCOUNTS: ""`; `firefox-sync-fxa-init` runs the three SQL files in the branch's order)
- Test: `tests/apps/firefox-sync-fxa.sh` (section "sync")

**Interfaces:**
- Consumes: the branch's `revoke.sql` / `admin-db.sql` patterns and its `firefox-sync-db-init` env.
- Produces: roles `firefoxsync_app` (owns nothing, no superuser), `firefoxsync_admin`, `firefoxsync_admin_sync`; the node = `https://${PORTCULLIS_HOST_FIREFOX_SYNC_FXA:-firefox-sync.portcullis.local}`.

- [ ] **Step 1: Write the failing checks:**
  - `app_role_owns_nothing`;
  - `only_three_roles_connect`;
  - `node_url`;
  - `first_sync`: `tests/fxa_client.py sync <email>` (sign in, OAuth token with the Sync scope, tokenserver `GET /1.0/sync/1.5`) → 200 with an `api_endpoint` on the Sync host, then a BSO PUT/GET round trip;
  - `foreign_token_refused`: a token signed by another key → 401.
- [ ] **Step 2:** Run the sync section. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the same. Expected: PASS.
- [ ] **Step 5:** Commit `firefox-sync-fxa: Sync database roles and node`.

---

### Task 14: Admin UI with OIDC, access managed elsewhere (**depends on `firefox-sync-admin` landing**)

**Files:**
- Modify: `firefox-sync-fxa/compose.yml` (`ffs-admin`), `firefox-sync-fxa/manifest.yaml` (`keycloak_clients: [{client_id: firefox-sync-fxa-admin, secret_env: FIREFOX_SYNC_FXA_ADMIN_OIDC_SECRET, redirect_uri: "https://{{HOST_FIREFOX_SYNC_FXA_ADMIN}}/auth/callback", name: Firefox Sync + own accounts admin UI}]`)
- Test: `tests/apps/firefox-sync-fxa.sh` (section "admin", reusing the branch's Keycloak acceptance checks)

**Interfaces:**
- Consumes: the branch's `firefox-sync-admin` env block. Additions for accounts: `FXA_DB_HOST: fxa-db`, `FXA_DB_PASSWORD: ${FXA_ADMIN_DB_PASSWORD}`, `FXA_AUTH_UPSTREAM: http://fxa-auth:9000`, `FXA_CONTENT_URL`, `FXA_AUTH_URL` and `FXA_PROFILE_URL` from the host variables, `FXA_PAIRING_URL: wss://${PORTCULLIS_HOST_FIREFOX_SYNC_FXA_PAIRING:-firefox-sync-pairing.portcullis.local}`, `FXA_ACCOUNT_EVENTS: "false"`, `FXA_CLIENT_ADDRESS_DEPTH: "2"`.
- Produces: the admin UI on the admin host, and the sign-up gate on `:8081`.

- [ ] **Step 1: Write the failing checks:**
  - `admin_env`: `ADMIN_ACCESS_EXTERNAL=1`, `ADMIN_PASSWORD=""`, `ADMIN_ALLOWED_GROUPS=${PORTCULLIS_ADMIN_GROUP:-admin_firefox-sync-fxa}`, `ADMIN_OIDC_GROUPS_CLAIM=groups`, `ADMIN_OIDC_TRUST_UNVERIFIED_EMAIL=false`;
  - `post_login_403`;
  - `redirect_uri_matches`;
  - `allowlist_read_only`: the admin UI's sign-up and allowlist forms refuse changes (403);
  - `oidc_member_not_admin_refused`: a member of the access group who isn't an admin is refused by the admin UI's OIDC;
  - `connect_page_values`: the Connect page shows `identity.fxaccounts.autoconfig.uri` = the accounts URL.
- [ ] **Step 2:** Run the admin section. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the admin section and `python3 tests/e2e/app_signin.py firefox-sync-fxa` (manifest `tests.signin`: host `{{HOST_FIREFOX_SYNC_FXA_ACCOUNTS}}`, path `/settings`; the member is signed in, the outsider gets 403). Expected: PASS.
- [ ] **Step 5:** Commit `firefox-sync-fxa: admin UI (OIDC, admin group, access managed elsewhere)`.

---

### Task 15: Notes, Firefox setup, docs page

**Files:**
- Modify: `firefox-sync-fxa/manifest.yaml`:
  - `description`, `long_description` with the resource sentence: "Needs about 6 GB of RAM and 20 GB of free disk (Mozilla's accounts image alone is about 5 GB).";
  - `auth.notes`. Its first paragraph names the open API, profile, Sync and pairing hosts and why (D7). The body covers what runs, access by group, no email = no account, D2's caveat, the token lifetime of about 1 h after a disable, mail, backups (`fxa-keys`), and the Firefox setup for desktop (`identity.fxaccounts.autoconfig.uri`), Android and iOS;
  - `urls` (Accounts, Admin UI);
  - `ai.unsupported`.
- Modify: `firefox-sync/manifest.yaml:79` (point "A separate template may add them later" to `firefox-sync-fxa`)
- Run: `/Volumes/workspace/portcullis/.m-docs/scripts/generate-app-docs.py --source <templates>` (adds `docs/apps/firefox-sync-fxa.md`, index, `.nav.yml`)

- [ ] **Step 1: Write the failing checks:**
  - `notes_first_paragraph` (≤ 300 runes and names the four open hosts);
  - `notes_render` (`python3 tests/validate.py` notes lint);
  - `long_description_resources` (contains `6 GB` and `20 GB`).
- [ ] **Step 2:** Run `python3 tests/validate.py firefox-sync-fxa && bash tests/apps/firefox-sync-fxa.sh`. Expected: FAIL.
- [ ] **Step 3:** Write the texts. Regenerate the docs, then build them with `zensical build --strict --clean`.
- [ ] **Step 4:** Run the same commands and the docs build. Expected: PASS.
- [ ] **Step 5:** Commit `firefox-sync-fxa: notes, Firefox setup` (templates) and `apps: firefox-sync-fxa` (docs).

---

### Task 16: core e2e: real mail, real Hub (`e2e-fxa`)

**Files:**
- Create: `/Volumes/workspace/portcullis/.m-core/tests/e2e/e2e_fxa.py` (imports the setup helpers of `e2e_mail.py`: `hub_ok`, `member`, `imap_login`, `wait_mail`)
- Modify: `.github/workflows/ci.yml` (job `e2e-fxa`, modelled on `e2e-mail` at `:4050`, with templates branch `fxa-own-accounts`; `tests/e2e/requirements.txt` gains PyFxA, hashed)

**Interfaces:**
- Consumes: everything above; Stalwart wired; mail on for `ci.example.org`; nothing leaves the runner.

- [ ] **Step 1: Write the scenarios:**
  - `signup_code_via_provider`: alice is in `users_firefox-sync-fxa` and `mail_users`. PyFxA `create_account("alice@ci.example.org")`. Within 120 s a message from `portcullis-app-firefox-sync-fxa@ci.example.org` with a `dkim=pass` header reaches alice's INBOX (IMAP 993). Its code verifies the account;
  - `nonmember_refused`: carol is in `mail_users` and not in the access group → `create_account` is refused and no code is sent;
  - `leave_disables_via_hub`: `member("remove", "users_firefox-sync-fxa", "alice")` → within 180 s (60 s debounce + hook) alice's session token answers 401;
  - `rejoin_enables_via_hub`: alice is added again → within 180 s she can sign in again (with a new code);
  - `admin_disable_survives_routine_run`: bob is disabled through the admin UI's API, then `POST /api/apps/firefox-sync-fxa/settings/retry` runs (a routine run) → bob is still disabled;
  - `no_email_listed`: dave has no email → `GET /api/apps/firefox-sync-fxa/settings` `population.no_email == ["dave"]`;
  - `bypass_badges`: `GET /api/apps` gives 4 whole-host `open_router` badges (tier `public@file`) and the accounts host's 4 exact paths;
  - `mail_unwired_refuses`: the provider is unwired → after the restart `fxa-mail-check` exits 1 and the doctor lists `mail_sender_unwired`.
- [ ] **Step 2:** Run `python3 tests/e2e/e2e_fxa.py` locally against the stack, or push. Expected: FAIL before Tasks 5–14 are merged.
- [ ] **Step 3:** Wire the CI job (runner with ≥ 8 GB of RAM; the accounts image is pulled once and cached).
- [ ] **Step 4:** Watch the CI with your own background watcher until `e2e-fxa` is green. Expected: PASS.
- [ ] **Step 5:** Commit `e2e: Firefox Sync + own accounts (real mail, real Hub)`. Mainline every branch and delete the worktrees at goal end.

---

## Self-review

- **Spec coverage:**
  - two templates: Task 15 updates the old note;
  - full stack: Task 8;
  - group by email: Tasks 2 and 11;
  - join / leave / rejoin: Task 11, and Task 16 through the Hub;
  - mail through the provider: Tasks 5, 6, 12 and 16;
  - pages behind sign-in, open paths: Tasks 9 and 10;
  - bypass badges: Tasks 3 and 16;
  - MySQL `mysql:lts`, PostgreSQL for Sync, digests: Task 8;
  - resources 6 GB / 20 GB, warn not block: Tasks 4 and 8;
  - hosts and suffixes: Global Constraints and D3;
  - admin UI OIDC, `ADMIN_PASSWORD` empty: Task 14;
  - rate limits, XFF depth and spoof test: Tasks 8 and 10;
  - backups (`fxa-keys`, accounts DB): Global Constraints; automatic for all project volumes, asserted in Task 8;
  - `FXA_ACCOUNT_EVENTS` off: Tasks 8 and 14;
  - isolation and the other-app test: Task 10 (D1);
  - pairing on `<host>-pairing`: Tasks 9 and 10;
  - no cap by default: Task 12;
  - no email → instance page: Task 2;
  - errors keep the list: Task 11;
  - Firefox desktop end to end "if feasible": Task 13's `first_sync` is the protocol-level stand-in. A real Firefox is left out: upstream's `tests/browser` image could be added later.
- **Types:** `person_email`, `PopulationView.NoEmail` / `no_email`, `MailState.Senders` / `senders`, `PORTCULLIS_MAIL_SENDER_{HOST,PORT,USER,PASSWORD,FROM}` and `mail_sender_unwired` are spelled the same in Tasks 1, 2, 5, 7, 12 and 16.
- **Unverified here:** whether the versioned image tags carry exactly the facts' digests (Task 8 checks); the MFA JWT secret's variable name (upstream `.env-example`); how the auth server's mailer handles STARTTLS against Stalwart with AUTH (upstream never tested it; Task 16 proves it); whether Stalwart's permission model can express "send only, one From" (Task 6).
