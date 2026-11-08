# Apps and instances: what runs on the server vs the Marketplace — design

Status: agreed in conversation 2026-11-08 (brainstorming, mockups approved with changes); written for the plan.

## Why

The Hub opens on an "App Catalog" that mixes what could be installed with what
is running. "+ Add instance" sits next to Enable/Disable on one card that is
both a shop item and a running app. The default instance has its settings in
the card while other instances use a separate window (hostnames, backups and
delete only there); "Settings" means three things. The admin also found:

- an app is flagged when not all its containers run, although a one-off setup
  job (Guacamole's `guacamole-init`, exited 0, `restart: no`, the others wait
  for it with `service_completed_successfully`) is meant to stop;
- no way to see one container's logs;
- Expert's environment variables don't say what is the default and what the
  admin overrode, and there is no clean way to add one's own;
- no per-instance view of its groups and who is in them;
- no setup before the first start (a name, the database engine, …).

The admin thinks of "one app with two instances", and people using the portal
must see that too.

## Goals

- **Apps** (the Hub's main page): what runs on this server. One entry per
  installed app; its instances listed under it as "<App> · <label>" with
  status, address, access group and member count. Enable/Disable on each
  instance; "+ Add instance" on the app; "+ Add an app" opens the Marketplace.
- **Marketplace**: what can be added. Each template shows whether it is in use
  and by how many instances, with "Show in Apps" (filters Apps to it) and
  "+ Add instance"; templates not in use show "Install…".
- **Setup before the first start** (Install… and + Add instance): nothing
  starts until the admin presses **Start** ("Save without starting" and Cancel
  too):
  - **Label** — mandatory; shown everywhere ("Gitea · team", portal, My apps)
    and used to derive the instance id and the default group names.
  - **Address** — a picker: a subdomain plus a domain chosen from the main
    domain and the enrolled domains that are ready (today's host rules).
  - **Who can use it** — either create new groups from the label
    (`users_<id>` / `admin_<id>`, today's derived names) or hook it to existing
    groups (pick any existing group for users and for admins).
  - **The template's setup choices** (e.g. Nextcloud's database: MySQL or
    PostgreSQL) with defaults; each says whether it can change later in
    Settings or is fixed after the first start (🔒, "changing it would mean
    moving the data"). Fixed choices are locked afterwards and say why; moving
    to another choice = a new instance + restore of a backup.
- **One page per instance, the same for every instance** (no special default
  instance in the UI). Tabs: Overview (status, addresses, containers), Settings,
  **Groups**, Logs, Backups, AI, Expert, Delete.
  - **Groups**: the instance's users and admins groups, kind (rule-based /
    manual), how many people and who (first names, "+N"), and "Manage on
    People ↗" (the group page on people.<domain>).
  - **Logs**: all containers or one container, picked from the instance's
    containers.
  - **Expert → environment variables**: one table — variable, default and where
    it comes from (template / set by the Hub), the admin's value, and a state
    ("default", "overridden" + Reset to default, "set by the Hub — can't be
    overridden"); "+ Add your own variable". Compose: template and Hub override
    read-only, the admin's custom override editable (as today).
- **One-off jobs**: a container of a service that others wait for with
  `condition: service_completed_successfully` (or declared as a job by the
  template) counts as fine when it exited 0 ("setup job done"), as failed when
  it exited non-zero; it never makes the app "not all running". This applies to
  status, drift and the card/row counts ("3 of 3").
- **Clear names for people**: portal and My apps show "<App> · <label>".

## Non-goals

- No change to what an instance is underneath (compose project per instance,
  contract §11), to backups/restore semantics, or to Settings' content.
- No migration (no installs to upgrade).
- No change to people & groups pages (they are on people.<domain>).

## Anti-goals

- Two places to manage one instance.
- A setup form that starts the app before the admin presses Start.
- A fixed choice that can be changed after the first start.

## Template change (setup choices)

Templates declare setup choices so the form can offer them. Shape left to the
builder (contract §3 / §13 first), with these rules agreed:
- a choice has a label, options with labels, a default, and whether it is
  `fixed_after_start`;
- a choice may switch which services the template runs (e.g. a database
  service per engine — compose profiles or a per-choice service set) and/or set
  values;
- the templates repo's `validate.py` mirrors the Hub's rules; at least
  Nextcloud gets a database choice as the first user.

## Calls I made (check these)

- **Label → id**: the instance id is derived from the label (`CheckIDShape`
  slug), shown and editable in the form before Start, immutable after creation
  (ids name compose projects and volumes). The label itself can change later.
- **First instance of a template**: created through the same form (no
  implicit create from an Enable button). Under the hood it stays today's
  default instance — the form pre-fills its id with the template id, so the
  existing default-instance machinery (names, volumes, manifest groups) keeps
  working; the UI shows it like any other instance, with its label. Further
  instances get an id derived from their label. The manifest's groups
  (`access_group` / `admin_group`) are the form's suggestion for the first
  instance.
- **"Save without starting"** keeps the instance created but disabled
  (today's `created` state).
- **One-off job detection** from compose (`service_completed_successfully`
  dependants, `restart: no`) plus an optional explicit template flag.
- **Logs per container** uses the existing logs endpoint with a container
  filter.
- **Env overrides**: the admin's own variables live in a Hub-managed per-
  instance store, written after the template/Hub values (so they win), never
  for Hub-set variables; the custom compose override stays for everything else.

## Settled details (from the builder check)

- **Label**: a new per-instance field in `state.yaml` (also the default
  instance's), 1–64 characters, one line; changeable in Overview; carried into
  `portal-apps.json` and My apps ("<App> · <label>"); the contract §10/§11
  entries change first.
- **Changing a label later is safe** because nothing keys on it: ids,
  volumes, groups, Keycloak clients, hostnames and the policy file use the
  instance id. Today's `instanceName(t)` (10 call sites: portal, My apps,
  directory app list, people reads, entries' refusal text, AI consent text,
  companion confirmations, AI activity) becomes "<App> · <label>". A label
  change re-asserts the AI companion scopes' consent text (as `SetHosts`
  does, `moveAIScopes`), and a confirmation keeps the typed check it was
  created with. Audited `instance.update` (label a -> b).
- **Existing groups**: the choice is stored per instance (users group, admins
  group) and replaces the derived / manifest names wherever the instance's
  groups are used (policy, population, settings placeholders, Keycloak access
  role, delete's group cleanup — which never deletes a group the instance
  didn't create). New groups are created as today. Built-in groups may be
  picked for admins only (e.g. `lldap_admin`), never as the users group.
- **Setup choices**: a template option with `setup: true` (shown in the form)
  and optional `fixed_after_start: true`; choices that switch services map
  option values to compose profiles (`profiles: {postgres: [db-postgres]}`),
  written as the instance's `COMPOSE_PROFILES`; values are stored like any
  instance setting. The Hub enforces the lock: a save changing a fixed value
  after the first successful start is 409 with the reason (a custom compose
  override stays the admin's own responsibility). The Hub's image pre-pull,
  status, drift and backup paths follow the selected profiles.
- **One-off jobs**: a service is a job when another service depends on it with
  `condition: service_completed_successfully`, or the manifest lists it under
  `jobs:`; a job container exited 0 = done, non-zero = failed; restart policy
  doesn't matter.

## Left to the builder

- Exact routes and API shapes (contract first), the setup-choice schema,
  how choices map to services, layout details within the mockups
  (`.superpowers/brainstorm/13936-1794174081/content/apps-redesign.html`).
