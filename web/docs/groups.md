# Groups & Access Control

Portcullis uses LLDAP groups to control which users can access which apps. Groups can be **manual** (membership managed by hand) or **rule-based** (computed from custom user fields). This page explains the group model, rule-based groups, the group pages where membership is changed, how groups flow through the system, and how to manage access.

## Where things live

People and groups are managed in one place, the people page
`https://people.<your-domain>/` (**People** in the top navigation the Hub and
the people page share). Whatever you start from, you end on the same view: a
group's page is the only place membership changes.

Two accounts are special. The Hub's own service account (`portcullis-hub`) is
never listed: not among people, in group members or in suggestions (Setup
names it). The built-in `admin` can't be added to any group, so it can't use
apps: invite yourself as a regular person for that (see
[Users & Groups](hub.md#users-groups)).

| You want to… | Go to |
|--------------|-------|
| See or change who is in a group | the group's page, `people.<domain>/#groups/<group>` ([Group pages](#group-pages)) |
| Add someone to a group starting from the person | their page, `people.<domain>/#people/<name>` → **Add to group…** (opens the group's page with them picked) |
| See who has an app and why | the app's access group, linked from the Hub (instance Overview, Who gets what, Missing groups): its page |
| Create a group | people page → **Groups** → **New group** |
| Create the groups an enabled instance is missing | the Hub's Apps page banner, [Missing groups](hub.md#missing-groups) |
| Change a rule | the group's page → **Edit rule…** |
| See who changed what | the group's or the person's **History** (admins); everything: the Hub's [Audit log](hub.md#audit-log) tab |
| Define fields and delegated permissions | people page → **Setup** (admins) |

Every group name the Hub shows links to its page
([Group names link to their pages](hub.md#group-names-link-to-their-pages)).

## The Group Model

Every app in Portcullis has two associated LLDAP groups:

| Group | Pattern | Purpose |
|-------|---------|---------|
| **Access group** | `users_<app>` | Grants access to the app. Users not in this group get a 403 from group-gate. |
| **Admin group** | `admin_<app>` | Grants admin privileges within the app (if the app supports group-based admin). |

For example, Jellyfin has:

- `users_jellyfin` -- Members can access Jellyfin
- `admin_jellyfin` -- Members get Jellyfin admin privileges

These group names are defined in each app's `manifest.yaml` under `auth.access_group` and `auth.admin_group`.

### Manual vs. Rule-Based Groups

- **Manual groups**: membership is managed directly by admins (add/remove members, set end dates).
- **Rule-based groups**: membership is computed by the Hub from custom user fields (department, office, manager, etc.). Rules combine conditions (all/any blocks) and can reference any field. The Hub evaluates rules at least every 60 seconds and on every relevant change (details, rules, added-by-hand and kept-out entries, import).

Groups are ordinary LLDAP groups; apps, group-gate and Keycloak use them the same way whether manual or rule-based.

## Rule-Based Groups

Rule-based groups grant membership automatically based on who people are, not by hand-picking members. Example rules: "everyone in the Milan office gets Nextcloud", "anyone reporting to Anna can see Grafana". The Hub evaluates rules continuously and updates LLDAP membership.

### Creating a Rule

Admins make a group rule-based on its [page](#group-pages) (**Make rule-based…**) and change the rule with **Edit rule…**. Rules are edited two ways that stay in sync:

1. **Blocks** (default): point-and-click all/any blocks, nestable. Conditions: `is`, `is not`, `is one of` (list fields), `is empty`, and for person fields (e.g. manager) `reports to (directly or indirectly)`.
2. **Text rule**: a typed expression with autocomplete for field names and list values, plus inline errors. A toggle switches between them; a parse error refuses the toggle.

A **preview** shows who matches (count and names, live-updated while editing).

**Converting a manual group to rule-based**: opens a review. Current members who don't match the rule are pre-ticked to stay as added by hand (reason: "member before the rule (set by X on date)"). Untick whoever should leave. Nothing changes until confirmed. The Hub compares the review with a fresh preview inside its lock and refuses with 409 if they differ (someone added/removed in between) — convert again.

### Added by hand and kept out

On a rule-based group, admins can:

- **Add** someone whatever the rule says: an **added by hand** entry. They
  stay even if the rule changes or they stop matching.
- **Keep out** someone the rule matches: a **kept out** entry. The evaluator
  leaves them out.

Both are done on the [group's page](#group-pages): **Add people** and
**Keep out…**. Each entry needs a written **reason** (≤ 500 characters) and
may have an [end](#end-dates). Reasons can be sensitive: only administrators
see them (and who set the entry, and when); everyone else sees the members
only. The API and the AI's `add_member` refuse an add to a rule-based group
without a reason (400) instead of adding a member the evaluator would remove.

**Also matches the rule.** Someone who already matches can still be added by
hand (a reason is still required). Their row reads "added by hand · also
matches the rule", with "⚠ keeps access if they stop matching": the entry
keeps them in whatever their details become. The same note appears when an
existing hand-added person starts matching (the rule or their details
changed). While you pick people in **Add people**, each says "already matches
the rule" or "doesn't match the rule".

### End dates

- **Manual groups**: any membership may have an end (date/time, browser local
  time; **No end** clears it). The membership is removed automatically when it
  ends.
- **Added by hand**: the entry's end. After it the rule decides alone: they
  stay if they match by then, else they leave.
- **Kept out**: the entry may end too. After it they're back in if they still
  match.
- **Matches the rule only**: no end date (the page offers **Keep out…**, not
  **Change end**, on those rows). To limit them, keep them out from a date
  with an end, or change the details the rule reads.
- **Built-in groups** (`lldap_admin`): end dates are refused (409).

An ended entry is kept (a kept-out entry still keeps the person out; an
added-by-hand one does nothing once the person left the group) until the
person's membership changes or an admin removes it. Its row then shows the
rule's own state with "added-by-hand entry ended <date>" or "kept-out entry
ended <date>".

When a membership ends, the Hub removes it from LLDAP, revokes the user's Keycloak sessions (OIDC apps lose access at their next token refresh, within ~1 minute), and keeps the end in the policy file's `expiring` array (plus a 10-minute grace period) so enforcement is strict even while the Hub is down. When group-gate withholds an ended membership for a request, it also withholds `Authorization` and `X-Forwarded-Access-Token`.

### The Evaluator

The Hub runs the rule evaluator:

- at least every **60 seconds** (cadence),
- about a second after every detail change, rule change, entry change and CSV import that affects membership, and on ends.

For each rule-based group (skipping administrator and built-in groups):

1. Computes who matches the rule (handles cycles in the manager field: `reports to` stops at the first repeat).
2. Applies the entries (adds the added-by-hand people, leaves the kept-out people out).
3. Compares with LLDAP membership and updates it (adds/removes members).
4. Audits every change (`group.rule_add`, `group.rule_remove`, `group.expired`) with the cause.

**The Hub owns rule-group membership.** A manual change made in LLDAP to a rule-based group (e.g. in `portcullis lldap-ui`) is reverted at the next evaluation and audited as `group.manual_change_reverted`.

### Guarding Groups

Rules of **protected groups** may only reference **admin-only fields**:

- **Administrator groups**: `lldap_admin`, `lldap_password_manager`, core-subdomain groups (`auth`, `traefik`, `hub`, `directory`, `people`, `metrics`, `mcp`), `INVITE_PROTECTED_GROUPS`
- **Permission groups**: the groups holding a delegated permission (`edit_details`, `invite`, `remove`, `sign_in_help`)
- **App admin groups**: any group used as an app's `admin_group` or in `path_groups`
- **Privileged setting groups**: any group with a row in an app's [privileged option](hub.md#per-group-values) (a role or admin flag, e.g. Grafana's or Immich's role). The Hub works these out from the apps' current settings; the reason shown is "a privileged value of app <id>"

This prevents delegates (who can edit non-admin-only fields) from granting themselves admin rights, delegated permissions or a privileged app value by editing data. The settings panel enforces the same rule from the other side: a privileged option takes rows only from manual groups and rule-based groups over admin-only fields, and a row whose group later stops qualifying grants only the option's lowest value and is removed at the next check. A field used by such a rule cannot lose its admin-only flag (409 until the rule is changed or the group stops being protected).

**Built-in groups** (`lldap_admin`, `lldap_password_manager`, core-subdomain groups) and permission groups cannot be rule-based (409). `INVITE_PROTECTED_GROUPS` can be rule-based, but only over admin-only fields.

### Delegated permissions

Four permissions can each be granted to one group (Hub → People → Setup →
Permissions; `PUT /api/directory/permissions/<permission>`): **edit details**
(`edit_details`), **invite** (`invite`), **remove** (`remove`) and **help
with sign-in** (`sign_in_help`: send a setup link, remove passkeys, revoke
certificates). Their members are delegates for that permission, everywhere
(delegation isn't scoped to groups). Delegates never act on themselves,
`admin`, `portcullis-hub`, administrators or members of any permission
group, and every check uses the memberships as they are at that moment.

`sign_in_help` holders help people who lost a passkey or a certificate
([Help to reset](auth-policies.md#help-to-reset)). They never set a password
or issue a certificate. Holding it makes the group a permission group, so
its rule may use only admin-only fields and other delegates can't act on its
members.

!!! warning "Grant `sign_in_help` only to people you'd trust with those accounts"
    A setup link hands the account to whoever holds it. Anyone in the
    `sign_in_help` group can send one to anyone they may help (any
    non-administrator outside the permission groups), so grant it
    only to people you would trust with those accounts.

Details: [Hub → Delegated permissions](hub.md#delegated-permissions).

### Membership Flow for Rule-Based Groups

1. **Fields**: admins define custom fields (department, office, manager) under **Setup** on the people page. Admins and delegates (with `edit_details` permission) fill in values.
2. **Rules**: admins write a rule that combines conditions over those fields.
3. **Evaluator**: the Hub runs the rule every ≤ 60 s and on changes, computes who matches, applies the added-by-hand and kept-out entries, updates LLDAP membership.
4. **Sync**: Keycloak syncs groups from LLDAP periodically (and can be triggered manually).
5. **Access**: apps enforce group membership the same way as manual groups (group-gate for the subdomain's `access_group`, the app's own group-admin mapping for `admin_group`).

## Group pages

`people.<domain>/#groups/<group>`: one page per group, reached from the
groups list, a person's page, or any group name on the Hub. Admins see and
use all of it; delegates and everyone else see the members read-only (names,
and a manual group's end dates), without reasons, Used by or History.

- **Header**: the name, its kind (rule-based, manual, built-in) and what it
  gives access to (app links). A rule-based group shows its rule with
  **Edit rule…** and **Make manual**; a manual group **Make rule-based…**.
- **People**: one row per person, linking to their page, with how they're in
  it and what you can do:

    | Row | Actions |
    |-----|---------|
    | matches the rule | **Keep out…** (reason required, optional end) |
    | added by hand · until … · "reason" (· also matches the rule) | **Change end**, **Remove** |
    | kept out · "reason" | **Let back in** |
    | member · until … (manual groups) | **Change end**, **Remove** |
    | protected account — the rules leave it as it is | none |
    | not explained by the rule — leaves at the next sync | none |

  Notes say where LLDAP hasn't caught up yet: "not in the group yet", "joins
  at the next sync", "still in until the next sync". Locked members (the
  Hub's account, `admin`, yourself in `lldap_admin`) have no actions.

- **Add people**: pick one or more people, an optional end and, on a
  rule-based group, a reason. Each save waits for the evaluator's run (about
  a second), so the rows show the result when it finishes. If the run fails
  or LLDAP is down, the page says "saved, not applied yet: <why>": the entry
  is stored and applies at the next evaluation, and Remove / Change end work
  on it as on any other.
- **Used by** (admins): the apps it grants (access group, admin group,
  privileged values), every app setting row that names it ("Immich › storage
  quota: 50 GiB"), and the delegated permissions it holds, each a link.
  **Delete group…** is here: the page lists what goes, and you type the name
  to confirm ([Groups deleted outside the Hub](#groups-deleted-outside-the-hub)
  covers the setting rows).

### History

The group page's **History** (admins) lists the audit entries for the group,
newest first, in words:

- the rule's own changes: "bob joined — matches the rule", "erin left — no
  longer matches the rule", "x left — their added-by-hand entry ended",
  "carol left — kept out" (actor: the rules);
- the entries: "added dave by hand until 30 Nov — "covers for Anna"", "kept
  carol out — "on leave"", "removed the entry of x";
- the rule: "changed the rule to office = "Milan"", "made the group
  rule-based: …", "made the group manual";
- members added and removed, end dates, the group's creation.

Each line has the time and who did it ("via AI (client)" when made through
the Portcullis MCP), and a pill when the change was refused or failed. A
person's page has the same list for that person. The whole log is the Hub's
[Audit log](hub.md#audit-log) tab.

## How Groups Flow

Groups originate in LLDAP and flow through the system:

```
LLDAP (source of truth)
  |
  v  LDAP federation (periodic sync)
Keycloak (identity provider)
  |
  v  OIDC groups claim
oauth2-proxy (forward auth)
  |
  v  X-Auth-Request-Groups header
group-gate (access check)
  |
  v  hostname -> required group mapping
App (allowed or denied)
```

### Step by step:

1. **LLDAP** stores users and groups. An admin creates groups and assigns users to them.
2. **Keycloak** federates from LLDAP via its LDAP user storage provider. Groups are synced periodically (and can be triggered manually).
3. **oauth2-proxy** authenticates users via Keycloak's OIDC endpoint. The ID token includes a `groups` claim with the user's LLDAP groups.
4. **group-gate** receives the `X-Auth-Request-Groups` header (set by oauth2-proxy) and checks whether the user belongs to the required group for the requested hostname.

## group-gate and the Subdomain Map

group-gate is the forward-auth service behind the `portcullis-groups@docker`
middleware. It maps **hostnames** to required groups. Two sources are merged,
and both are re-read on every request:

1. **`group-gate/group-gate-map.conf`** in the core repo (mounted read-only
   into group-gate) holds static entries, mainly for the core services:

    ```
    # subdomain=required_group
    auth=lldap_admin
    hub=lldap_admin
    grafana=users_grafana
    ```

    Each `<sub>` means `<sub>.<main domain>` (group-gate expands it with
    `PORTCULLIS_DOMAIN`). Edits take effect on the next request; no restart is
    needed.

2. **The Hub's `group-gate-policy.json`** (version 6, on the `hub_data` volume)
   has a `groups` map keyed by **full lowercase hostname**. The Hub rewrites it
   whenever an instance is enabled, disabled or reconfigured. For every
   **enabled** instance with `auth.group_access: true`, each hostname it
   routes maps to the instance's access group. For example, Nextcloud's
   default instance routes `cloud.<main domain>` and declares
   `users_nextcloud`, so it yields `"cloud.<main domain>": "users_nextcloud"`;
   an instance `nextcloud-team-b` on `cloud.team-b.example.org` yields
   `"cloud.team-b.example.org": "users_nextcloud-team-b"`. Hub entries add to
   or override the map file's expanded entries.

**Keys are full hostnames only.** Policies, groups and path rules are never
keyed by template or instance ID. A hostname belongs to at most one instance:
the Hub refuses a hostname another instance uses, and rejects templates whose
`Host()` rules it can't fully resolve (see
[Hub → Template rules](hub.md#template-rules-enforced-by-the-hub)).

**Core subdomains** (`auth`, `traefik`, `hub`, `directory`, `enroll`, `people`, `metrics`, `mcp`, on the main domain) always
come from the map file. The Hub never publishes them, and group-gate ignores
them in the policy file. If they are missing from the map file they default to
`lldap_admin`. `enroll` stays reserved (no app can take the name) but has no
map entry and isn't gated: `enroll.<domain>` serves only setup links
(`/invite/…`), without forward-auth.

### What group-gate checks

When a request for `grafana.<domain>` arrives, group-gate runs these checks in
order and stops at the first failure:

1. **Host.** It takes the host from `X-Forwarded-Host`, lowercases it, and
   strips any port and trailing dot, and looks it up exactly (no
   parent-domain fallback). The host must be a core host,
   `<label>.<PORTCULLIS_DOMAIN>`, or an added domain `<d>` / `<label>.<d>`
   that the policy file lists in `extra_domains`; anything else gets a 403.
   Traefik matches hosts case-insensitively, so without normalisation
   `HUB.<domain>` would miss the `hub.<domain>` entry.
2. **Reserved group.** A user whose groups include `__portcullis_deny__` is
   denied.
3. **Revocation.** If the request carries a YubiKey or browser certificate
   (via `client-headers@file` or `client-cert-pem@file`, which must come
   before `portcullis-groups@docker`), its serial must not be revoked by
   either certificate authority. See [Certificates](../setup/certificates.md#revocation).
4. **Group.** It looks up the hostname's required group (`users_grafana`) and
   compares it with `X-Auth-Request-Groups` (set by oauth2-proxy). The header
   is split on commas only, and the match must be exact.
5. **Path rules.** If the hostname has `path_groups`, the group of the matching
   path rule is required **in addition** (see below).
6. **Sign-in template.** Only after the group and path checks (someone outside
   the app's groups gets the plain 403, never a page naming the app's rule):
   the session's sign-in methods must meet the template the app (or core page)
   uses. Otherwise group-gate returns the step-up or needs-stronger page. A
   YubiKey or browser certificate counts only when the current request
   presents a certificate of that kind whose CN is the user
   ([certificate binding](auth-policies.md#certificate-binding)). On
   people.&lt;domain&gt;, the Sign-in page (`/signin`, `/api/me/signin…`,
   `/static/…`) accepts any switched-on method instead of the template. See
   [Sign-in methods](auth-policies.md).
7. **Allow.** It returns `200 OK` and sets `X-Forwarded-User` /
   `X-Auth-Request-User` (the LLDAP username), `X-Forwarded-Email` /
   `X-Auth-Request-Email` and `X-Auth-Request-Groups` for the backend.
   Identity is always the immutable LLDAP username, never the user-editable
   email. Apps must never create, match or link accounts by email.
   Otherwise it returns `403 Forbidden`.

**Fail closed.** These all deny the request instead of falling back to
"public":

- a policy file that exists but can't be parsed
- a `version` other than 6 (older files are denied too)
- an unknown method, template or rule shape

If a hostname has no mapping at all, group-gate allows any authenticated user
and logs `ALLOW-UNMAPPED`. This is the passthrough for apps without group-based
access.

### The reserved group `__portcullis_deny__`

The Hub publishes `groups[host] = "__portcullis_deny__"` for hostnames it knows
are routed but can't attribute a config to. That happens when:

- an enabled app has neither a template nor a stored snapshot
- a `portcullis-<id>` project runs without being enabled

Nobody is a member of that group, so every request to those hostnames is
denied ("The configuration of … is unavailable"). A user who *claims*
membership is denied everywhere.

!!! danger "Never create an LLDAP group named `__portcullis_deny__`"
    Membership would be treated as tampering and deny that user on every app.

See [Hub → Fail-closed behaviour](hub.md#fail-closed-behaviour).

### Path rules (`path_groups` and `admin_paths`)

Some apps keep an admin area on a path of the same hostname, e.g.
Vaultwarden's `/admin`. A template lists such prefixes in its manifest:

```yaml
auth:
  admin_group: admin_vaultwarden
  admin_paths: ["/admin"]
```

For every hostname of an enabled instance, the Hub publishes
`path_groups[host] = [{"prefix": "/admin", "group": "admin_vaultwarden"}]` (the
instance's admin group: `admin_<id>` for instances other than the default). On
requests under that prefix, group-gate then requires the admin group **in
addition** to the hostname's group.

Matching:

- **What is matched.** The path from `X-Forwarded-Uri` with the query and
  fragment stripped. It is percent-decoded **once**, `//` is collapsed, and dot
  segments (`/./`, `/../`) are resolved.
- **Ambiguous paths are denied.** If an encoded slash, backslash or NUL
  (`%2F`, `%5C`, `%00`) is still present after that one decode, or the path has
  control characters, the request is denied outright. Different backends read
  such paths differently.
- **Deny-biased variants.** A rule applies if it matches **any** of: the
  primary form, the fully decoded form, `\` read as `/`, `;` path parameters
  stripped. Each is compared both case-sensitively and case-insensitively. So
  `/%61dmin`, `//admin`, `/x/../admin` and `/ADMIN` all hit the `/admin` rule
  (CI's browser test checks exactly these).
- **Segment-boundary prefixes.** `/admin` matches `/admin` and `/admin/x`, but
  not `/administrator`. The longest matching prefix wins. If different variants
  hit rules with different groups, all of those groups are required.

!!! note "Only routers with group-gate are covered"
    Path rules only work on routers whose middlewares include
    `portcullis-auth@docker,portcullis-groups@docker`. For a native-OIDC app,
    the template routes the admin path through its own higher-priority
    `PathPrefix` router with forward-auth (`validate.py` in the templates repo
    checks that such a router exists).

## Per-App Enforcement

How group access is enforced depends on the auth method:

### Forward-Auth and Header-Auth Apps

The Traefik middleware chain handles everything:

```
client-headers@file --> portcullis-auth@docker --> portcullis-groups@docker --> App
(certificate info)      (oauth2-proxy)             (group-gate)
```

Both oauth2-proxy and group-gate run as Traefik forward-auth middleware. The app itself is unaware of groups (header-auth apps receive them in `X-Auth-Request-Groups`).

### Native OIDC Apps

Native OIDC apps receive the user's groups in the `groups` claim (the Hub attaches the `groups` client scope to every client it registers). Some apps enforce group-based access themselves, e.g. Jellyfin's SSO plugin requires `users_jellyfin` and maps `admin_jellyfin` to admin. Each app page in the [App Catalog](../apps/index.md) says what it does.

Apps that can't restrict OIDC logins by group (GitLab, LiteLLM, Vaultwarden) put only their interactive login paths behind forward-auth + group-gate on a higher-priority `PathPrefix` router, and keep their API router without forward-auth. Never put `portcullis-auth@docker` on the host-wide router of a native-OIDC app: it would break API clients and mobile apps.

### Public Apps

No group enforcement. Anyone can access the app.

## Managing Groups

### Creating Groups

Groups are created on the people page, `https://people.<your-domain>` →
**Groups** → **New group** (admins; everyone else sees the groups
read-only). Enter the group name (e.g. `users_grafana`); its page opens. New
groups are manual.

Groups an enabled app needs but that don't exist yet are listed in the Hub's
Apps page [Missing groups](hub.md#missing-groups) banner, each with a
one-click **Create**.

`https://directory.<your-domain>` redirects to `https://people.<your-domain>`. LLDAP has no single sign-on, so its own web UI isn't published; for recovery, open it from the server with [`portcullis lldap-ui`](cli.md#lldap-ui).

### Adding Users to Groups

On the group's page (admins), **Add people**:

- **Manual groups**: pick the people and an optional end. Adding someone to an administrator group asks for confirmation. **Remove** takes them out.
- **Rule-based groups**: membership is computed. Change the rule, or add them by hand (with a reason); keep out someone the rule matches with **Keep out…** ([Added by hand and kept out](#added-by-hand-and-kept-out)).

From a person's page, **Add to group…** picks the group and opens its page with them already picked.

### Syncing Groups to Keycloak

Keycloak syncs groups from LLDAP periodically. To trigger an immediate sync:

1. Open Keycloak admin at `https://auth.<your-domain>/admin/`
2. Go to **User Federation**
3. Click on the LLDAP provider
4. Click **Synchronize all users**

Or via API:

```bash
# Get admin token
KC_TOKEN=$(curl -s http://localhost:8080/realms/master/protocol/openid-connect/token \
  -d "client_id=admin-cli" \
  -d "username=admin" \
  -d "password=YOUR_KC_ADMIN_PASSWORD" \
  -d "grant_type=password" | jq -r '.access_token')

# Find LDAP provider ID
LDAP_ID=$(curl -s http://localhost:8080/admin/realms/portcullis/components \
  -H "Authorization: Bearer $KC_TOKEN" | jq -r '.[] | select(.providerId=="ldap") | .id')

# Trigger full sync
curl -s -X POST \
  "http://localhost:8080/admin/realms/portcullis/user-storage/$LDAP_ID/sync?action=triggerFullSync" \
  -H "Authorization: Bearer $KC_TOKEN"
```

### Groups deleted outside the Hub

[App settings](hub.md#per-group-values) can give values per group (a quota for `office_milan`, an admin role for `admin_immich`). Each such row stores the group's LLDAP id, not only its name, so a group's settings never pass to a different group:

- **Deleted through the Hub** (the group page's **Delete group…**): the group's rows are removed from every app at once, audited as `settings.purge` with you as the actor, and the affected apps get a new delivery.
- **Deleted in LLDAP's own UI** (`portcullis lldap-ui`) or by anything else: the rows stop granting anything immediately, because the group is missing. The Hub's next check removes them (audited `settings.purge`, actor `hub`). It removes them only while LLDAP looks healthy: the bootstrap `admin` and the Hub's account exist, and the user count hasn't dropped by more than 20 % and more than 2 accounts (the same check as the [stale-record cleanup](hub.md#stale-keycloak-records-admins-only)). Otherwise it only logs a warning and keeps filtering.
- **Re-created with the same name**: it is a new group with a new id and inherits nothing: no rows, no records. Add its rows again in the app's settings. The only exception is a template's own preset row for the instance's access or admin group (`admin_<id>`): it comes back when the Hub re-creates that group itself, on enable or with **Create missing groups**.

Values people enter for themselves work the same way with accounts: each remembers the LLDAP account it was entered for, so an account deleted and re-created outside the Hub doesn't get the old value (see [Values people enter](hub.md#values-people-enter)).

## Example: Giving a User Access to an App

To give user `alice` access to Grafana:

1. Enabling Grafana in the Hub creates the `users_grafana` and `admin_grafana` groups if they are missing (or use the Apps page banner, see [Missing groups](hub.md#missing-groups))
2. Open `users_grafana`'s page (the Hub's Grafana Overview links to it) and add `alice` with **Add people**
3. `alice` can now access `https://grafana.<your-domain>` (Keycloak reads groups from LLDAP at her next sign-in or token refresh)

To also give `alice` admin privileges in Grafana, add her to `admin_grafana`.

## Example: Revoking Access

To revoke `alice`'s access to Grafana:

1. On `users_grafana`'s page, **Remove** `alice` (or, on a rule-based group, **Keep out…**)
2. The Hub revokes her Keycloak sessions: she gets a 403 within about a minute (at her next oauth2-proxy refresh)

!!! tip
    oauth2-proxy sessions have a configurable expiry. For immediate revocation, you can also revoke the user's Keycloak sessions from the Keycloak admin panel.
