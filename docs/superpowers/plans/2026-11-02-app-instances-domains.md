# App Instances and Extra Domains Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run any template as several fully separate instances with
admin-chosen, changeable hostnames on the main domain or on enrolled extra
domains/subdomains (their own DNS records + wildcard certs), with silent
cross-domain sign-in, guarded delete with backups, and restore.

**Architecture:**
- **Instances.** The Hub's state moves from "app id" to "instance id". The
  default instance's id is the template id, so today's state is the default
  instance as-is.
- **Templates (contract v2).** Templates use per-router hostname variables
  `PORTCULLIS_HOST_<ROUTER>` and declare `instances: multi|single`. The Hub
  namespaces volumes per instance.
- **Policy file v5.** Keyed by full hostname; group-gate matches the Host
  exactly.
- **New core service `domains`.** Go, using lego and libdns. It owns DNS
  tokens (encrypted at rest), records and certificates for enrolled domains,
  and Traefik reads the certificates through its file provider.
- **Sign-in on extra domains.** It uses per-host `/oauth2/*` routers and a
  relative oauth2-proxy callback.

**Tech Stack:**
- Hub: Go, gopkg.in/yaml.v3, gocloak, moby client.
- Core: Python group-gate, Traefik v3 labels and file provider; new
  `domains` service in Go with `github.com/go-acme/lego/v4`, `libdns`
  providers and `filippo.io/age` (at-rest encryption).
- Templates: compose + manifest schema + `tests/validate.py`.

**Spec:** `docs/superpowers/specs/2026-11-02-app-instances-domains-design.md` (hub repo)

## Global Constraints

- **Dependencies:** prefer mature, pinned libraries over hand-rolled code.
  Images are pinned `tag@sha256`; Go modules pinned; Python with hashes.
- **Workflow:** work on `main` in every repo; commit per task; push at phase
  ends. Hub v5 and core v5 ship together.
- **No migration code.** The default instance id = template id makes
  today's state valid as-is.
- **Instance id:** `^[a-z][a-z0-9-]{0,30}$`. The default instance id = the
  template id.
- **Instance-derived names:**
  - compose project `portcullis-<id>`;
  - Keycloak client id `<id>`;
  - groups `users_<id>` / `admin_<id>` (the default instance keeps the
    manifest's groups);
  - volumes `portcullis_<id>-<volume key>`.
- **Hostname variables:** `PORTCULLIS_HOST_<ROUTER>`, where `<ROUTER>` is
  the Traefik router name upper-cased with `-` and `.` turned into `_`. Its
  value is the full hostname.
- **Policy file `version: 5`:** `policies`, `groups`, `path_groups` and
  `public_paths` are keyed by full lowercase hostname; `expiring` is
  unchanged.
- **Core hostnames:** group-gate expands map-file `<sub>` entries to
  `<sub>.<main domain>`.
- **Extra domains never route core services.** A hostname may belong to at
  most one instance or core service.
- **DNS tokens:**
  - never logged, audited or returned by any API;
  - stored only in the `domains` service's volume, age-encrypted, with the
    key under core `secrets/domains/`;
  - the Hub forwards them once and forgets them.
- **Delete** needs the instance id typed, takes a backup first, then removes
  everything.
- **Admin-only and audited:** every instance and domain operation. Actions:
  - `instance.create|update|delete|backup|restore`;
  - `domain.enroll|token|delete`.
- **Contract first:** `portcullis-docs/docs/guides/integration-contracts.md`.

## Review Focus

1. **A hostname edited to collide** with another instance, a core hostname
   (`auth.<main>`, …), or a hostname on a domain that isn't enrolled.
   - Expected: refused before anything changes.
   - Pinned in Task 4 (`TestHostCollisions`).
2. **Request Host spelling:** a request with an uppercase Host, a trailing
   dot, or a port (`Grafana-A.team-a.com.:443`).
   - Expected: group-gate normalises it and applies the right policy, or
     denies. It must never fall back to a subdomain-only match.
   - Pinned in Task 6 (`test_host_normalisation_v5`).
3. **A failed restore or delete halfway:**
   - Delete: the backup is written before anything is removed, and a failure
     after that leaves a consistent "partially deleted" state that can be
     retried.
   - Restore: on failure, the instance's previous data is kept.
   - Pinned in Task 9 (`TestDeleteBackupFirst`, `TestRestoreFailureKeepsData`).
4. **Domain enrollment with a wrong or under-privileged token, or a slow DNS
   provider:**
   - The status shows the error.
   - No instance can be assigned until the certificate is valid.
   - Retries back off.
   - Pinned in Task 7 (`TestEnrollBadToken`, `TestAssignRequiresValidCert`).
5. **Cross-domain sign-in loops:** a stale or foreign oauth2-proxy cookie on
   an extra-domain host, or a step-up redirect.
   - Expected: no redirect loop, no prompt when the session already
     satisfies the policy.
   - Pinned in Task 11 (e2e `cross_domain_sso`).

---

## Phase 1 — contract and templates

### Task 1: Contract v2/v5 (docs repo)

**Files:** `portcullis-docs/docs/guides/integration-contracts.md`
(§3 template layout, §4 policy file, §5 routing, a new §11 instances, a new
§12 domains service API), `docs/guides/manifest-reference.md`.

- [ ] **Step 1: Write the contract.**
  - **§3, template contract v2:**
    - `PORTCULLIS_HOST_<ROUTER>`, with the naming rule from Global
      Constraints;
    - manifest `instances: multi|single` (default `single`);
    - no hard-coded volume `name:` in multi templates; the Hub sets
      `portcullis_<id>-<key>`;
    - instance-scoped variables `PORTCULLIS_INSTANCE` (the id),
      `PORTCULLIS_OIDC_CLIENT_ID`, `PORTCULLIS_ACCESS_GROUP` and
      `PORTCULLIS_ADMIN_GROUP`, so templates stop hard-coding these.
  - **§4, policy v5:** keyed by full hostname, as in Global Constraints.
    Show an example with two Grafana instances on two domains.
  - **§5:**
    - extra-domain routers carry the same middlewares as main-domain ones;
    - the `/oauth2/*` router on each extra-domain instance host goes to
      `forward-auth`;
    - the step-up URL is built from the request host on extra domains.
  - **§11:**
    - the instance id rules and derived names;
    - the default instance;
    - hostname changes (immediate, no redirects);
    - guarded delete with backup;
    - the backup archive layout `<data>/backups/<id>/<UTC ts>.tar` with a
      `MANIFEST.json` of sha256 sums;
    - restore semantics.
  - **§12:** the internal `domains` API (bearer secret file
    `secrets/domains/api-secret`, mounted for the Hub):
    - `PUT /domains/{name}` with body `{provider, credentials{...}}`;
    - `GET /domains`, returning `[{name, provider, records_ok, cert_not_after, last_error, state}]`;
    - `POST /domains/{name}/token`;
    - `DELETE /domains/{name}`;
    - certificates are written to the shared `domains_certs` volume and
      listed in a Traefik dynamic file `certs.yml`;
    - providers: `cloudflare`, `porkbun`, `route53`, `digitalocean`,
      `hetzner`.
- [ ] **Step 2:** update the manifest reference (`instances`, the hostname
  variables).
- [ ] **Step 3:** commit
  `contracts: instances, hostname variables, policy v5, domains service`.

### Task 2: Templates contract v2 (templates repo)

**Files:** `schema/manifest.schema.json`, `tests/validate.py`,
`CONTRIBUTING.md`, all 22 `*/compose.yml` and `*/manifest.yaml`, templates
CI if it asserts hostnames.

- [ ] **Step 1: Validator tests first.**
  - The validator refuses a multi template that has
    `${PORTCULLIS_DOMAIN}` in a router rule.
  - It refuses a multi template with a volume `name:`.
  - It requires every router rule to be exactly
    `Host(\`${PORTCULLIS_HOST_<ROUTER>}\`)`, optionally `&& PathPrefix(...)`.
  - It requires every env URL that names the app's own host to use the
    variable. Check `https://<sub>.${PORTCULLIS_DOMAIN` patterns.
  - It accepts `instances: single` templates that still use the old form.
- [ ] **Step 2:** convert all 22 templates to the hostname variables. Mark
  each one `multi`, unless it needs host-level uniqueness, which must be
  justified in the manifest notes (e.g. one that binds fixed host devices).
  Templates with host ports stay multi; ports are per-instance settings.
  Replace hard-coded client ids and group names with the instance
  variables.
- [ ] **Step 3:** run `python3 tests/validate.py` and the templates unit
  tests → pass. Commit `templates: contract v2 (hostname variables, instances)`.

### Task 2b: Best upstream sign-in for every template (user request 2026-11-02)

**Files:** `nextcloud/`, `wiki/`, `dokuwiki/`, `pihole/`, `adguard/` (compose, manifest, init/config files), `tests/apps/*.sh`; docs: regenerate `docs/apps/*` with `scripts/generate-app-docs.py`.

**Input:** the audit at `.superpowers/sdd/2026-11-02-app-instances-domains/templates-auth-audit.md` (hub repo workspace), plus the controller's additions in the ledger.

- [ ] **Step 1:** switch Nextcloud to `native-oidc` (user_oidc: preferred_username identity, group mapping, admin group, auto-provisioning; disable password login except a break-glass admin) and Wiki.js to `native-oidc`.
- [ ] **Step 2:** DokuWiki: `header-auth` through a maintained plugin trusting `X-Forwarded-User` only from Traefik's IP, or OIDC if no safe plugin exists. Justify the choice with upstream links.
- [ ] **Step 3:** Pi-hole and AdGuard Home: remove the second login behind the gateway where upstream allows it safely (check API access, DNS-over-HTTPS and admin endpoints); otherwise document why the app password stays.
- [ ] **Step 4:** update the per-app tests (`tests/apps/<app>.sh`) and the validator expectations, run the templates CI checks locally, regenerate the docs app pages, and commit to both repos.

### Task 2c: Full per-app sign-in tests in templates CI (user request 2026-11-02)

**Why:** today's `tests/apps/<app>.sh` mostly check config, start the app and probe its own login page. They don't prove that a real person can sign in through Portcullis and gets the right role. The user wants a full test per integrated app, run by GitHub Actions on every change, especially image version bumps (Dependabot PRs).

**Files (templates):**
- `tests/e2e/app_signin.py` (new; Playwright + a CDP virtual WebAuthn authenticator, like core's `tests/e2e`);
- `tests/e2e/requirements.txt` (pinned with hashes);
- a manifest `tests.signin` block in every template;
- `schema/manifest.schema.json`, `tests/validate.py` (require the block for every template except `public`/`custom` ones, which declare why);
- `.github/workflows/test-apps.yml` (run the e2e for every changed app after its existing test; also on Dependabot PRs; a `workflow_dispatch` input "all apps");
- `CONTRIBUTING.md`;
- docs `operations/testing.md` and `guides/adding-an-app.md`.

**Manifest block (contract):**
```yaml
tests:
  signin:
    path: /                    # page to open on the app's main host
    signed_in:                 # how to recognise a signed-in user (one of)
      text: "{username}"       # visible text containing the username, or
      json: {url: /api/user, field: login}   # an API returning the username
    admin:                     # optional: how to recognise admin rights
      json: {url: /api/user, field: isGrafanaAdmin, equals: true}
```

- [ ] **Step 1: Write the driver.** For each changed app, on the core stack the templates CI already boots, `app_signin.py`:
  1. creates three LLDAP users, `member` (in the access group), `admin` (in the admin group) and `outsider` (in neither), through core's CLI, with setup links;
  2. registers a passkey for each with the virtual authenticator;
  3. opens the app host and completes the app's real sign-in (forward-auth / header-auth / native-oidc / saml);
  4. asserts `signed_in` shows the right username for `member`, `admin` rights for `admin`, and that `outsider` is refused (403 from group-gate, or the app's own denial for native-oidc apps once Task 4b lands; until then mark it `expected_fail` with the reason);
  5. checks there is no password field on the way, except the break-glass flows the manifest documents.
  - Screenshots and traces are kept on failure.
- [ ] **Step 2:** add `tests.signin` to all 22 templates and make the validator require it.
- [ ] **Step 3:** wire it into `test-apps.yml` (changed apps; Dependabot PRs; dispatch "all"). Keep the existing per-app shell tests. Pin Playwright and its browser through the existing pip/Playwright cache.
- [ ] **Step 4:** run it on the `contract-v2` branch via `workflow_dispatch` for every app. Fix what fails, or record a documented `expected_fail`, then commit.

## Phase 2 — Hub instances

### Task 3: Instance model + lifecycle

**Files:** `internal/state/state.go`, `internal/hub/{hub,lifecycle,env,override,access,public,portal,reconcile}.go`, `internal/templates/routes.go`, tests.

**Interfaces (produced):**
```go
type Instance struct {
    ID, Template string
    Hosts map[string]string // router -> full hostname
}
// state.AppState.Instances map[string]Instance (yaml `instances`).
// The default instance is implicit for every enabled template id with no
// entry: ID = Template = template id, Hosts = the template's hosts on the
// main domain.
func (h *Hub) Instances() []InstanceView
func (h *Hub) CreateInstance(templateID, id string, hosts map[string]string) error
func (h *Hub) Enable(instanceID string) error // and Disable, RestartApp keyed by instance id
```
- Settings, auth policies, public access, sign-in mode, published, ops
  records and overrides all stay keyed by instance id.
- `routes.ParseRoutes` accepts the `PORTCULLIS_HOST_<ROUTER>` rule form and
  resolves it with the instance's Hosts.
- Compose project: `portcullis-<id>`. The override sets volume names
  `portcullis_<id>-<key>` and the env adds the instance variables.

- [ ] **Step 1: Tests.**
  - `TestTwoInstancesSeparate`: two grafana instances get different
    projects, volumes, env and groups, and enabling one doesn't touch the
    other.
  - `TestDefaultInstanceUnchanged`: an existing state.yaml with `grafana`
    enabled produces exactly today's project, hostnames, groups and policy
    keys.
  - `TestInstanceIDRules`.
  - `TestSingleTemplateRefusesSecondInstance`.
- [ ] **Step 2:** implement.
- [ ] **Step 3:** run vet/race/gofmt and commit
  `hub: app instances (state, lifecycle, env, override, routes)`.

### Task 4: Hostnames: choose, validate, change

**Files:** `internal/hub/hosts.go` (new), `internal/hub/lifecycle.go`,
`internal/keycloak` (client redirect URIs update), tests.

**Interfaces:**
- `func (h *Hub) DefaultHosts(templateID, instanceID, domain string) map[string]string`
  - the router's subdomain, plus `-<suffix>` where the suffix is the
    instance id minus a leading `<template>-`, on `domain`.
- `func (h *Hub) SetHosts(instanceID string, hosts map[string]string) error`
  - validates;
  - collision check against all instances, core hostnames and Domains
    (Task 7 provides `Domains()`; until then, only the main domain);
  - regenerates env/override;
  - updates the Keycloak client's redirect URIs and web origins for OIDC
    templates;
  - rewrites the policy and restarts. Old names vanish.

- [ ] **Step 1: Tests.**
  - `TestDefaultHosts`.
  - `TestHostCollisions`: Review Focus 1, plus a host on a domain that isn't
    enrolled.
  - `TestSetHostsUpdatesKeycloakRedirects` (kctest).
  - `TestSetHostsRewritesPublicShareHosts`.
- [ ] **Step 2:** implement. Steps 3–4: verify and commit
  `hub: instance hostnames (defaults, collisions, live change)`.

### Task 4b: Group enforcement for native-OIDC apps without app-side groups (security review 2026-11-02)

**Why:** templates with `auth.method: native-oidc` and `group_access: false` (netbird, actual-budget, others — grep the manifests) let ANY Portcullis user sign in. With several instances that breaks "fully separate" (team B can open team A's instance).

**Files:** `internal/keycloak` (per-client access role + authentication-flow binding), `internal/hub/lifecycle.go` (create/update/delete with the instance), contract §8 (docs), templates: the affected manifests declare `group_access: true` once the Hub enforces it, tests.

- [ ] **Step 1: Tests (kctest).**
  - `TestClientAccessRoleEnforced`: the instance's client gets a client role `access`. The instance's access group gets that role. The client's browser flow override is a Hub-managed flow `portcullis-client-access` that denies sign-in without the role, and also denies at token refresh.
  - The role and group mapping are removed on instance delete.
  - Idempotent across reconciles.
- [ ] **Step 2:** implement with gocloak. Use Keycloak's built-in "Condition - user role" plus "Deny access" authenticators in a flow the Hub creates once. Raw calls only where gocloak lacks an endpoint. Then flip `group_access: true` on the affected templates (templates repo, local commit alongside Task 2).
- [ ] **Step 3:** verify, then commit `keycloak: per-instance access role for native-oidc apps without app-side groups`.

### Task 5: Policy file v5 (Hub side)

**Files:** `internal/policy/file.go`, `internal/hub/hub.go` (WritePolicy),
`internal/hub/portal.go` (portal entries with full URLs), tests.

- [ ] **Step 1: Tests.**
  - `TestPolicyFileV5KeyedByHost`: two instances on two domains.
  - `TestCoreHostsNeverPublished`.
  - `TestDenyGroupForUnknownRunningHosts`, keyed by host.
- [ ] **Step 2:** set `FileVersion = 5` and key everything by host.
  `CoreSubdomains` → `CoreHosts(mainDomain)`.
- [ ] **Step 3:** verify and commit `policy v5: keyed by full hostname`.
  Don't push until Task 6 is done.

## Phase 3 — core

### Task 6: group-gate v5 + extra-domain sign-in

**Files (core):** `group-gate/group-gate.py`, `tests/test_group_gate.py`,
`docker-compose.yml` (oauth2-proxy relative redirect URL for extra domains;
file-provider dynamic dir mount `domains_certs`), `traefik` file provider
config, CI checks, `CLAUDE.md`, `docs` pointers.

- [ ] **Step 1: Tests.**
  - `test_policy_v5_host_keys`.
  - `test_host_normalisation_v5`: Review Focus 2.
  - `test_core_hosts_from_map`: `<sub>` → `<sub>.<main>`.
  - `test_v4_refused`.
  - `test_stepup_url_on_extra_domain`: built from the request host.
  - `test_attribute_headers_on_extra_domain_host`.
- [ ] **Step 2:** implement.
  - oauth2-proxy:
    - keep `auth.<main>` as the main-domain callback;
    - support callbacks on extra-domain hosts, using a per-request redirect
      for non-main hosts (check oauth2-proxy v7.15 for relative
      `redirect_url`);
    - if a single process can't serve both, run a second oauth2-proxy
      instance for extra domains with host-only cookies, and document why.
  - Traefik: watch the `domains_certs` dynamic dir.
- [ ] **Step 3:** run all core suites, then commit
  `group-gate v5, extra-domain sign-in plumbing`.

### Task 7: `domains` service (core) + Hub domains API/UI

**Files (core):** `domains/` (new Go module: `main.go`, `acme.go`,
`records.go`, `store.go`, tests, `Dockerfile`), `docker-compose.yml`
(service, internal network with the Hub, volume `domains_data`, shared
`domains_certs` with Traefik read-only), `scripts/lib` (secrets:
`secrets/domains/{api-secret,age.key}` generated by init/up, backup
includes `domains_data`), CI build and Pebble, `CLAUDE.md`,
`docs/hardening.md` pointer → docs site.

**Files (hub):** `internal/domains` (new client), `internal/hub` (assign
validation uses `Domains()`), `internal/httpapi` (admin-only `/api/domains`
routes), `web/` (Settings → Domains), tests.

- [ ] **Step 1: Tests (core).**
  - `TestEnrollIssuesCert`: Pebble with a fake libdns provider.
  - `TestEnrollBadToken`: the state shows the error and backoff applies.
  - `TestRecordsCreatedAAndAAAA`.
  - `TestRenewal`: within 30 days of expiry.
  - `TestTokenNeverLogged`: capture the logs.
  - `TestStoreEncrypted`: the file on disk doesn't contain the token.
  - `TestDeleteRefusedWhileAssigned`: the Hub sends the assigned list, or
    the service asks the Hub; pick one and pin it in the contract.
- [ ] **Step 2: Tests (hub).**
  - `TestAssignRequiresValidCert`.
  - `TestDomainRoutesAdminOnly`.
  - `TestTokenNotEchoed`.
  - Audit entries.
- [ ] **Step 3:** implement both sides. The UI shows status: records OK,
  certificate valid until, last error.
- [ ] **Step 4:** verify both repos and commit them.

## Phase 4 — Hub instance UX, delete/backup/restore

### Task 8: Instances UI + API

**Files:** `internal/httpapi` (`/api/instances` create, update hosts, list,
delete, backup, restore — all admin-only), `web/index.html` (catalog "Add
instance", per-instance detail with a hostname editor pre-filled from
DefaultHosts and a domain picker of valid domains), tests.

- [ ] **Step 1: Tests.**
  - Route tests for each operation.
  - Delegates get 403.
  - `TestDeleteNeedsTypedID`.
- [ ] **Step 2:** implement, and check in a browser harness with
  screenshots, as in plan 2026-11-01 Task 12b.
- [ ] **Step 3:** commit.

### Task 9: Guarded delete, backup, restore

**Files:** `internal/hub/backup.go` (new), `internal/hub/lifecycle.go`,
`internal/keycloak`, `internal/directory` (group delete for
`users_<id>`/`admin_<id>` through the existing guarded DeleteGroup path),
tests. Core: `scripts/lib/backup.sh` includes `<hub_data>/backups/`
(already inside the hub volume archive; verify and document).

- [ ] **Step 1: Tests.**
  - `TestBackupArchiveLayout`: a tar holding the volumes, config and a
    MANIFEST of sha256 sums; volume files keep their owner uid.
  - `TestDeleteBackupFirst`: Review Focus 3.
  - `TestDeleteRemovesEverything`: project, volumes, Keycloak client,
    groups, state, secrets.
  - `TestRestoreSameInstance`.
  - `TestRestoreIntoNewID`: new hosts, client and groups.
  - `TestRestoreFailureKeepsData`.
  - `TestRestoreChecksumMismatchRefused`.
- [ ] **Step 2:** implement. Volume I/O goes through a helper container via
  the Hub's socket proxy (the image is pinned by digest). Check that the
  proxy allows what's needed (volumes, containers create/start/wait/remove);
  if not, list the core socket-proxy env change in the report, contract §6.
- [ ] **Step 3:** commit.

## Phase 5 — docs, e2e, deploy, verify

### Task 10: Docs

**Files (docs):** `operations/hub.md` (instances, hostnames, domains,
delete/backup/restore), `setup/dns.md` (enrolling extra domains),
`operations/hardening.md` (domains service, token handling, extra-domain
routing), `operations/backups.md` (instance backups), `architecture.md`,
`operations/testing.md` (Pebble e2e).

- [ ] Write the pages, run `zensical build --strict --clean`, commit and
  push.

### Task 11: CI e2e (core)

**Files (core):** `.github/workflows/ci.yml` (Pebble + challtestsrv as the
fake DNS for the `domains` service; a second domain `team-b.test`),
`tests/e2e/e2e_login.py` (or a new `e2e_instances.py`).

- [ ] **Step 1:** e2e `cross_domain_sso`:
  1. a user signs in on the main domain;
  2. they open an instance host on `team-b.test`;
  3. no WebAuthn prompt appears (count the authenticator assertions: zero
     extra);
  4. the page loads;
  5. a step-up-required instance prompts once;
  6. a stale cookie doesn't loop.
- [ ] **Step 2:** e2e `two_instances`: two whoami/header-echo instances get
  different groups, and each user only reaches theirs.
- [ ] **Step 3:** commit and push Hub + core + templates together; CI must
  be green.

### Task 12: Deploy + live check

- [ ] **Step 1:** deploy to the test server (`./portcullis upgrade`).
- [ ] **Step 2:** live checks, with throwaway resources only, cleaned up
  afterwards:
  1. enroll `team-a.portcullis.imbu.ca` with the server's existing DNS
     token: records appear and a separate wildcard certificate is issued;
  2. create `grafana-team-a` on it, enable it, and sign in silently from
     the main domain;
  3. change its hostname and confirm the old one fails;
  4. back it up, delete it with the typed id, and restore the backup into a
     new id.
- [ ] **Step 3:** report.
