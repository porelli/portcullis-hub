# Users & Groups rework: custom fields, rule-based groups, delegated permissions

Status: for approval (2026-11-01)

## Intent

Portcullis is moving from "a handful of homelab accounts" to "a small
organisation". Admins need to describe people (city, department, manager…),
grant app access by **who people are** rather than by hand-picked lists, and
hand day-to-day people management (new hires, detail changes, leavers) to
trusted non-admins such as HR, without giving them control of apps or
security policy.

Typical rules, in the user's words: "everyone in the Milan office gets
Nextcloud", "anyone reporting to Anna can see Grafana", combined with
and/or over several fields.

## Goals

1. **Custom user fields**, defined by admins.
   - Field types: **free text**, **list** (values the admin maintains), and
     **person** (a reference to another user; "manager" is the canonical
     one and drives the org chart).
   - Per field: **share with apps** (default **on**) and **admin-only**
     (only admins may edit it; see Security).
   - Everyone signed in can see everyone's field values and the org chart.
2. **Rule-based groups.**
   - A group is either *manual* (today's behaviour) or *rule-based*.
   - A rule combines conditions with all/any blocks, nestable. Conditions
     are `is`, `is not`, `is one of`, `is empty`, and, for person fields,
     `reports to (directly or indirectly)`.
   - Rules are editable two ways that stay in sync: **point-and-click
     blocks** (default) and a **typed text rule** with autocomplete for
     field names and list values, plus inline errors. A toggle switches
     between them.
   - A live preview shows the number and names of the people who match
     while editing.
   - Rule-based groups are ordinary LLDAP groups. Apps, group-gate and
     Keycloak use them exactly like today's groups; only their membership
     is computed.
3. **Exceptions and temporary membership.**
   - On a rule-based group, a person can be **added** although they don't
     match, or **kept out** although they match.
   - Every exception needs a written **reason** (stored and shown).
   - Any membership can have an **expiry date/time**: exceptions, and
     members of manual groups too ("contractor until 2027-03-31").
   - When a membership expires, the person is removed automatically.
4. **Delegated permissions.**
   - Three permissions: **edit details** (single edits and bulk import),
     **invite people**, **remove people**.
   - Each is granted to a group the admin picks, manual or rule-based.
   - Everything else stays admin-only: apps, policies, field definitions,
     rules, permissions, and the administrator groups.
5. **Bulk import (CSV) with a review step.**
   - Uploading a file never changes anything by itself. It opens an
     editable review table: one row per person and one column per field,
     with a status (new / changed / not in file / unchanged).
   - Unchanged rows are hidden by default, and there are filters plus a
     search box.
   - Changed cells show the current value struck through, plus the file
     value.
   - Any cell can be edited; ↺ keeps the current value.
   - Problems block Apply until they are fixed. Example: a manager who
     isn't a known user, with a picker to fix it.
   - New people are ticked and get a setup link on Apply.
   - "Not in file" people are unticked, and ticking means remove (this
     needs the remove permission).
   - The table shows the effect on rule-based groups (+n / −n per group)
     before Apply.
   - Rows can also be added by hand, and the edited table can be
     downloaded as CSV.
6. **Fields reach apps.**
   - Shared fields go out as OIDC claims for native-OIDC apps, and as
     identity headers for forward-auth/header-auth apps.
   - This is on by default per field.
7. **Page layout (option A, tabs):** People | Groups | Org chart | Setup ⚙.
   - **People:** a searchable table with the field columns, groups (⚡
     marks membership via a rule) and key status, plus Invite and Import
     CSV buttons. Clicking a row opens details, groups and keys.
   - **Groups:** the list of groups, the *missing groups* card with
     Create, members, rule editor, exceptions and expiries, and the apps
     each group grants.
   - **Org chart:** a tree from the manager field.
   - **Setup** (admins only): field definitions and permission
     assignments.

## Non-goals (for now)

- **Scoped delegation.** Example: "HR Milan edits only Milan people". The
  permission is global ("everyone") for now; the data model shouldn't
  preclude scopes later.
- **Self-service editing** of one's own details.
- **Syncing from an external HR system.** Only manual edits and CSV
  import are supported.
- **Per-viewer field visibility.** Everyone sees all fields; only "share
  with apps" is per field.

## Anti-goals: failure even if it "works"

- **Privilege escalation through data.** Someone who can edit details must
  never be able to grant themselves or others admin rights or a delegated
  permission by editing a field.
- **Weakened access control.** group-gate, Keycloak and the policy file
  must keep working on plain groups, and the auth path must not depend on
  the Hub being up.
- **Silent changes.** Every membership change from rules, expiry or
  import is audited with its cause.
- **Manual end-user steps** beyond registering a key: there must be none
  (standing project rule).

## Security rules (decided)

- Rules of **protected groups** (administrator groups, as today's
  `ProtectedGroups`) and of **permission groups** may only reference
  **admin-only** fields. A field used by such a rule cannot lose its
  admin-only flag.
- **Edit details** never applies to one's own record, and never to
  protected accounts (service account, bootstrap `admin`, administrators).
  That matches today's `checkTarget` parity rules.
- Invite and remove respect the existing guardrails: no Hub invites for
  administrators, no self-delete, and the last `lldap_admin` member stays.
- Exceptions and expiries on protected and permission groups: admins only.
- Every mutation is audited with the actor (`X-Forwarded-User`), cause and
  reason. Field values are not sensitive by design, but secrets never go
  in the audit log.
- LLDAP's own UI must not become a back door. All custom attributes are
  created non-user-editable in LLDAP, so users can't change their own
  department there.

## Constraints

- **Hub rules (see the Hub `CLAUDE.md`):**
  - stdlib plus yaml.v3 only, and vanilla JS with no build step;
  - escape everything;
  - no migration code;
  - users-and-groups guardrails live in `internal/directory`, and
    `TestProtectedAccountsParity` must cover every new user-targeting
    operation.
- **LLDAP 0.6.3 is the source of truth for people and groups.** Custom
  fields are LLDAP user attributes (schema API: `addUserAttribute`, with
  type and list / visible / editable flags).
- **Rule definitions, exceptions, expiries, field metadata LLDAP can't
  hold, and permission assignments** live in Hub state under `/data`.
  They are atomic and corrupt-file-refuses-to-start, like `state.yaml`.
- **The Hub writes computed membership into the real LLDAP groups.** A
  manual change made in LLDAP to a rule-based group is reverted at the next
  evaluation and audited as such. (My call: the Hub owns these groups.
  This differs from app drift, which is only reported, because the rule
  *is* the declared state.)
- **Re-evaluation** happens on every detail change, rule change, import
  and exception change, and periodically (at least every minute) for
  expiries.
- **Cross-repo interfaces** go into `integration-contracts.md` first:
  - the claim and header names for shared fields;
  - any core change (Keycloak LDAP attribute mappers and client-scope
    protocol mappers; oauth2-proxy alpha-config
    `injectRequestHeaders`/`injectResponseHeaders` from claims; Traefik
    header pass-through).
- **Header names for shared fields:** `X-Forwarded-Attr-<Field>` (my
  call). The header-hardening rules in hardening.md (strip
  client-supplied identity headers) must cover the new prefix.

## Decided by the user

- Field types free text **and** list, chosen per field; a person type for
  manager.
- Rule editing: both blocks and text, switchable.
- Delegation: permission ↔ group, and that group may itself be
  rule-based. The permissions are edit details, invite and remove.
  Delegation is global for now.
- Everyone can see everyone's details and the org chart.
- Fields are shared with apps by default.
- Import goes through an editable review table (layout B, v2 mockup).
- Page layout A (tabs).
- Exceptions both ways, with a required reason. Expiry on exceptions and
  temporary memberships.
- Rules of protected and permission groups only use admin-only fields;
  nobody edits their own details through the permission.

## Left to the builder

- The exact text-rule grammar. It must round-trip losslessly with the
  block view; when the text doesn't parse, the toggle refuses rather than
  dropping parts.
- Storage layout under `/data` and the evaluation algorithm.
  Requirements:
  - expected scale is up to a few thousand people;
  - "reports to" must handle cycles in the manager field (and the UI
    should flag them);
  - the evaluation must be idempotent.
- CSV column mapping: header names match field names; `username` is
  required; unknown columns are reported in the review.
- Org chart rendering (vanilla JS/SVG or nested lists).
- How a deleted list value or a deleted field affects rules. It should be
  refused while in use, with the referencing rules listed.

## Calls made while reviewing (check these)

1. **Where non-admins go: `people.<domain>`.**
   - The user wants everyone to inspect the org chart and other people's
     details. The Hub binary gets a second listener, which core routes as
     a new core subdomain `people`.
   - The listener serves only the directory UI and API (People, Groups,
     Org chart, Import) to every signed-in user, with per-person
     permission checks. App, policy, drift, compose and Docker endpoints
     are not registered on it at all.
   - `hub.<domain>` stays admin-only, unchanged.
   - Core: the new subdomain in the gate map (any signed-in user), its
     Traefik router with the proxy-secret middleware, and the contract
     §4/§5 entries.
2. **Delegates can't touch manual groups.**
   - Membership of manual groups, exceptions and expiries stays
     admin-only.
   - A delegate's invite creates a person with no groups. With "edit
     details" they can fill in fields, and so make the person match
     rules built on non-admin-only fields.
   - That trust is accepted (delegates are trusted staff), and it is
     visible: the audit records the inviter, and a new account's rule
     memberships show "via rule, account created by X".
3. **Protected targets for delegates.**
   - Delegates may not edit, remove, re-invite or reset keys of:
     administrators, the service account, `admin`, or members of any
     permission group. Only admins may.
   - These checks go into `checkTarget`, and
     `TestProtectedAccountsParity` covers every new operation.
   - The Hub is the only caller of core's invite API for delegates, so
     core's check is unchanged.
4. **App admin groups count as protected for rules.** Rules of any group
   used as an app's `admin_group` (or `path_groups` admin access) may only
   use admin-only fields, like protected and permission groups.
5. **Built-in groups can't be rule-based.** `lldap_admin`,
   `lldap_password_manager`, `INVITE_PROTECTED_GROUPS` and core-subdomain
   groups stay manual. That avoids fights with core re-adding the service
   account and with the last-admin guardrail.
6. **How fields reach apps, without per-field core changes.**
   - **Native-OIDC apps:** the Hub creates the Keycloak LDAP attribute
     mapper and the protocol mapper on a `portcullis-attributes` client
     scope through the admin API it already uses. Each shared field
     becomes claim `attr_<field>`.
   - **Forward-auth and header-auth apps:** the Hub writes
     `user-attributes.json` next to the policy file. group-gate (already
     in the chain) returns `X-Forwarded-Attr-<Field>` headers, and the
     `portcullis-groups` middleware forwards them with
     `authResponseHeadersRegex: ^X-Forwarded-Attr-`.
   - oauth2-proxy is not involved. The client-header stripping rule
     covers the new prefix.
   - All of this goes into the contract (core: group-gate and middleware
     changes).
7. **Expiry and removal are strict even while the Hub is down.**
   - The Hub writes every pending expiry (user, group, timestamp) into
     the policy file ahead of time. group-gate treats a membership past
     its expiry as absent, whatever the token says.
   - On every removal, whether by rule, expiry or a person, the Hub
     revokes that person's Keycloak sessions. OIDC apps then lose access
     at their next token refresh.
8. **Turning a manual group into a rule-based one** opens a review step.
   - Current members who don't match the rule are listed, pre-ticked to
     stay as "added" exceptions, with the reason "member before the rule
     (set by X on date)".
   - The admin unticks whoever should go, and nothing changes until they
     confirm.
