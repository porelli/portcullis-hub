# Hub Management

The Hub is Portcullis's web dashboard for app templates. It lists the catalog,
enables and disables apps, edits their settings and sign-in templates, and shows
status and logs. It is published as `ghcr.io/porelli/portcullis-hub` and run by
the core `docker-compose.yml` (`HUB_IMAGE`). There is nothing to build.

Open it at `https://hub.<your-domain>`. It requires a Keycloak login and
membership of `lldap_admin`.

## Navigation

The Hub has six main tabs under the shared navigation (Portal · Hub · People):

- **Apps** — installed apps and their instances (one per app, showing all its instances)
- **Marketplace** — all available templates from every [template source](#template-sources), with installation and template source management
- **Audit log** — [operation and access audit](#audit-log)
- **Doctor** — [system health checks and fixes](#doctor)
- **Settings** — [global server settings](#settings-tab-global) (shared folders, local networks, domains)
- **People ↗** — opens the People subdomain (`people.<domain>`) in the same tab

## Apps

The **Apps** page lists every installed app (an app with at least one instance: a state entry, an enabled instance, or an operation record). The page shows:

- **Drift / missing-groups / LLDAP-sweep banners** at the top (see [Drift detection](#drift-detection), [Missing groups](#missing-groups))
- **"Installed apps"** heading with:
    - **All backups** — list of every instance's backups across all apps
    - **+ Add an app** — opens the Marketplace
- One **app block** per installed app, containing:
    - App icon, name, and "N instances" count
    - **+ Add instance** button (for `instances: multi` templates) — opens the [setup form](#setup-before-the-first-start)
    - One **instance row** per instance, showing:
        - Status dot (green = all running, amber = partially running, red = stopped, gray = not started)
        - Name as **`<App> · <label>`** (or just **`<App>`** when the label equals the app name), linking to the [instance page](#instance-page)
        - First hostname (or "no web page" for router-less apps)
        - Users group name (linking to `people.<domain>`) and member count in parentheses, or "missing" in red when the group doesn't exist
        - Status pill: "running · n of m", "not started yet", "last \<operation\> failed", or the current operation ("Enabling… show progress")
        - **Enable** / **Disable** button

For an instance with duplicate names (two instances of the same app with identical labels), the row shows its id first in muted text to distinguish them.

## Marketplace

The **Marketplace** page shows every template from every [template source](#template-sources) as a card, whether installed or not:

- icon, name and one-line description
- auth badges:

| Badge | Meaning |
|-------|---------|
| **SSO** | The app supports single sign-on via Keycloak (`auth.sso`) |
| **Group Access** | group-gate restricts the instance's hostnames to its access group (`users_<app>` for the default instance; `auth.group_access`) |
| **Group Admin** | The app maps the `admin_<app>` group to its admin role (`auth.group_admin`) |
| **Method** | `forward-auth`, `native-oidc`, `header-auth`, `mtls`, `custom` or `public` |
| **No web page** | The template has no host routers (e.g., a background service) |
| **Rootless: works / limited / not available** | Only under [rootless Podman](#rootless-podman): whether the app runs there, with the reasons in its tooltip |

- tags (e.g., `productivity`, `media`)
- footer showing:
    - For installed apps: **"in use · N instances"**, **Show in Apps** (filters the Apps page to that app), and **+ Add instance** (for multi templates)
    - For not-yet-installed apps: **Install…**

Below the cards, the **Template sources** section (moved from the old Template sources section (at the bottom of the Marketplace)) shows each configured source with its URL, update interval, and management buttons.

## Setup before the first start

Clicking **Install…** (Marketplace) or **+ Add instance** (Apps, for multi templates) opens the **setup form**. Nothing starts until you press **Start**.

The form has these sections:

### Name

- **Label** (required, 1–64 characters): shown everywhere as **`<App> · <label>`** in the portal, Hub, My apps, and People. The Hub derives the instance id from the label as you type (lowercase, accents folded, punctuation removed, no `portcullis` segments, max 31 characters). For example, "Team Zürich" → `nextcloud-team-zurich`.
- **Instance id**: editable before creation, immutable afterward. The first instance (Install…, or a single template) shows the template id with 🔒 (read-only).

### Address

- **Domain picker**: choose the main domain or an added extra domain (domains not yet `ready` are disabled)
- **Subdomain per host router**: shown as `[subdomain].<domain>`. An empty subdomain means the added domain itself. Pre-filled from defaults; edits are kept.
- Templates with no web page show "No web page".

### Who can use it

Only shown when the manifest declares an `access_group` or `admin_group`. Two choices:

- **New groups from the label**: creates `users_<id>` / `admin_<id>` (or the manifest's group names for the first instance). For the first instance, groups with other names aren't created (only a warning) and must exist on People.
- **Existing groups**: pick any existing group. The Users field excludes built-in, administrator, and permission groups; Admins may be any group.

### Setup choices

The template's `setup: true` options with their defaults. Each shows whether it can change later in Settings or is **🔒 fixed after the first start** (changing it would mean moving the data). Examples: database engine (fixed), trash retention days (changeable).

### Buttons

- **Start**: creates the instance, then enables it (opens the instance page and shows the progress panel; a LAN-only confirmation may appear first)
- **Save without starting**: creates the instance but leaves it disabled (opens the instance page with "Created. Nothing runs yet")
- **Cancel**: creates nothing

Inline errors show refused values (label, id shape, hostname collisions, unknown groups, bad setup values) under their fields. The Hub is the authority: typing a built-in group in the Users field is sent and refused inline.

!!! warning "LAN-only ports (file sharing and other apps)"
    Apps with `lan_only` ports (Samba port 445, Time Machine port 445, Pi-hole DNS port 53, NetBird's STUN/TURN ports) publish those ports directly on the host, **bypassing Docker's network isolation and any firewall rules like ufw**. Anyone on your network (or the internet, if the port is exposed through your router) can reach the port. See [LAN-only ports](hardening.md#lan-only-ports-and-host-firewalls) in the hardening guide.

    File-sharing apps (Samba, Time Machine) also require [Local networks](file-sharing.md#2-configure-local-networks) to be configured: an empty Local networks list **keeps the app from starting** (its container exits at boot, and the doctor reports `local_networks_empty`). Set Local networks before enabling a file-sharing app.

### What happens when you enable

Before anything starts, the Hub refuses to enable the app if:

Before anything starts, the Hub refuses to enable an instance if:

- one of its host ports (from Settings or its [custom override](#custom-override))
  overlaps a host port of another enabled instance (HTTP 409, "port
  0.0.0.0:3300/tcp already claimed by enabled app …"), or
- one of its hostnames is already used by another instance, enabled or not, or
  is still routed by one (HTTP 409). Every hostname has exactly one owner,
  because group-gate keys groups and templates by full hostname (policy v6).
- a bound group (one chosen at setup as "Existing groups") that was a valid users group at creation is now built-in, administrator, or a permission group (HTTP 409, "can't start")

When groups mode is "new", it creates the instance's **missing access and admin groups** in LLDAP, as you
(the enabling admin, through the same audited Users & Groups operation as
creating a group): `users_<id>` / `admin_<id>` for every group the manifest declares.
Existing groups are left alone. If creating a group fails, the instance isn't enabled; a group
created before a later failure stays (empty — the instance needs it anyway). The
progress panel's groups step lists the groups it created and the ones that
already existed. When groups mode is "existing", no groups are created; the step shows "bound to \<users\>, \<admins\>".

The Hub then generates the instance's `.env` and compose override, copies the template
directory to `<core>/templates/<app-id>/` (shared by all instances), registers the instance's Keycloak
clients (a client ID owned by another template or by nobody provable aborts
the enable with HTTP 409, see [Keycloak clients](#keycloak-clients)) and runs
`docker compose up`. The instance is recorded as enabled only after
`compose up` succeeds. Then the Hub publishes its group, admin paths and template
to group-gate.

The Hub can't test host ports outside Docker from inside its container (a
service on the host, e.g. `systemd-resolved` on `127.0.0.53:53`), so those
conflicts surface as a `compose up` failure. See
[When an operation fails](#when-an-operation-fails).

## Missing groups

An enabled instance whose access or admin group isn't in LLDAP (deleted in LLDAP's
own UI, or the instance was enabled before the Hub created groups on enable) lets
**nobody** sign in: Keycloak and group-gate find no member. The **Apps** page
then shows a **Missing groups** banner listing each such instance (by id, linking to its page) and its missing
groups (checked every minute). **Create missing groups** creates every listed
`users_<id>` / `admin_<id>` group as you (audited as `group.create`); **Create**
on a row does it for one instance. Groups with other names (including bound groups) are listed with "create
on the people page". Every listed group name links to its group page on
`people.<domain>`. The new groups are empty: add the people who should have
access on their pages. The Hub log's warning `group … not found in keycloak` points to the
same button. API: `GET /api/instances/missing-groups`,
`POST /api/instances/missing-groups` with `{}` (all) or `{"ids": ["<id>"]}`.

An instance's **Groups** tab also shows a "doesn't exist" message with a **Create missing groups** button when a group is gone.

### Progress and Stop

Enable, disable, restart, AI support switches, create, back up, restore and
delete run in the background. Clicking the button opens a **progress panel**
(a modal dialog) headed "Enabling Gitea" (or the operation's equivalent) and
"Started by <user> at <time> · you can close this, it keeps going". It lists
the operation's steps:

- ✓ done, with how long the step took
- ◐ running, with a percentage (0–100), a bar and one detail line wherever
  there is something to measure (e.g. per image "gitea/gitea:1.25 — 312 of
  690 MB" while images download, "2 of 3" while services start)
- ○ waiting
- ■ stopped (at n %)
- ↺ undone (struck through: a forward step whose effect the undo reversed)
- ✗ failed, with the error and hint (see
  [When an operation fails](#when-an-operation-fails))

An enable, for example, goes through: groups (`users_<id>` / `admin_<id>`,
"created" or "already exist"), the sign-in client in Keycloak, downloading
images, starting services (n of m), waiting until healthy (n of m), and
applying settings (start hooks, data files).

**You can close the panel at any time**; the operation keeps going. The
instance row shows "Enabling… show progress" while it runs, and clicking that
or the instance name reopens the panel. Refreshing the page, opening a second
tab, or another admin opening the instance shows the same running operation with
its progress. Only one operation runs per instance at a time: a second Enable (or
any other operation) while one runs answers HTTP 409 with the running
operation, and the UI opens its panel instead.

#### Stop

**Stop** (with the confirmation "Stop enabling Gitea and undo what it did?")
undoes what the operation did. While stopping, the panel's header reads
"Stopping Gitea — undoing" and the undo steps tick off under an "Undo"
separator. It ends with "Gitea was not enabled · everything is back as
before" (or the operation's equivalent) and "Stopped by <user> at <time>".
What Stop puts back:

| Operation | Stop does | Stop unavailable |
|-----------|-----------|------------------|
| Enable | Containers removed; volumes this enable created removed (volumes that existed before are kept); the Keycloak client and groups deleted **only if this enable created them**; downloaded images kept, so a later enable resumes the download; **only what this enable created is removed** (pre-existing groups, clients and volumes are kept) | never |
| Disable | The app turned back on | never |
| Restart | The app back running as before | never |
| AI support on/off, mode | The switch back as it was; AI credentials are minted again on next use | never |
| Back up | The partial archive deleted; the app restarted if it was running | never |
| Restore | Rolled back from the pre-restore backup | never |
| Create, restore as new | The new instance removed completely | never |
| Delete | The delete cancelled and the app back as before | once data removal starts (the first volume): the panel shows "past the point of no return — finishing" and Stop is unavailable |

Stop works at every step until the operation ends, the last one included:
an app that has already started is taken down and undone. **Images already
downloaded are kept** (they don't carry instance data), so a stopped enable
followed by a new enable resumes the download where it left off.

Stop always names the operation the panel shows. If that one has ended and
another admin's operation started in the meantime, the Stop is refused ("Stop
refused: the operation changed — another one runs now (…), nothing was
stopped"). The panel always follows its own operation to its own outcome
(the Hub keeps each operation's final record by its id, the last 20 per app).
When a newer operation has started since (the Hub's queued restart, a start
hook that failed after an enable, another admin's operation), the panel adds a
short note under its outcome, "then: Restarting (running)", with a **show**
link that opens the newer operation; press Stop there to stop that one.

#### Failed undo and "Stop again"

If the undo itself fails, the panel shows the error, what is left to undo
("Not undone yet: <undo steps>. Stop again retries what is left"), and the
**Stop** button changes to **Stop again**. Press it to retry the undo, which
skips the undo steps already done. Every Stop is audited as `<op>.stop`
(e.g. `enable.stop`) with the step it was pressed at.

#### Interrupted

If the Hub restarts while an operation runs, the panel shows it as
**interrupted**, with Stop to clean up what it left. The note reads
"interrupted: the Hub stopped while this ran. Stop undoes what it did." An
interrupted restore is rolled back, and an unfinished restore as new is
removed, at the next Hub start on their own (the Stop is automatic).

#### AI support and stop_op

The Portcullis MCP sees the same progress (`get_op`, `wait_for_op`, both
with an optional `op_id` that names the operation to show or wait for;
`list_ops` for every app's current operation) and can
stop an operation with `stop_op`. When the undo re-enables or switches
something on (a disable, a delete of an enabled app, a same-instance restore,
an AI switch-off), `stop_op` needs a **confirmation** that names the
operation (its `op_id`), and the Hub refuses any other operation under that
lock. A stopped enable or an AI switch that went back on are audited
`refused` for the lifecycle action (`instance.enable`, `ai.enable`) and `ok`
for the Stop (`enable.stop`, `ai.stop`).

API: `GET /api/instances/<id>/op` (`?op_id=<op_id>`: that operation's
record), `GET /api/instances/ops` (every app's current operation, in short),
`POST /api/instances/<id>/op/stop`
([contract §11.7](../guides/integration-contracts.md#117-hub-api-and-audit)).

### When an operation fails

If enable, disable, restart or a drift action fails, the UI shows the error
(in the progress panel's failed step, or a dialog for a drift action), a hint where one is known, and the last 8 KiB of
`docker compose`'s output (scrollable). Values of secret-looking variables
(names containing `SECRET`, `PASSWORD`, `TOKEN`, `KEY`, …, and generated ones)
from the app's and core's env are replaced with `[redacted]`. For
`address already in use` / `port is already allocated` the hint names the
port and links to the app's **Settings → Host Ports**: change the host port,
bind it to one address, or clear it (optional ports) to disable the binding,
then enable again.

A failed `compose up` during **enable** is rolled back: the Hub runs
`docker compose down --remove-orphans` for the project (volumes are kept), so
no stopped containers or network stay behind. The app stays disabled, and
neither the fail-closed deny entry nor a `stopped_not_enabled` drift item is
left over. If the rollback fails too, the error says so and the leftovers show
up in [Drift detection](#drift-detection) (**Stop & remove**).

Every operation's progress and outcome is stored per app in
`${HUB_DATA_DIR}/ops/<app>.json` (operation, who started it, time, steps,
what it created, ok/failed, error, hint, output tail; mode 0600), and kept
until the next operation on that instance. An instance row whose last operation failed shows
"last enable failed" (or restart, …); its instance page shows a banner, and the
**Logs** tab, also for an instance that is not enabled, shows the record above the
container logs. The API:

```text
GET  /api/templates/lastop/<app>   {op, op_id, at, actor, running, steps, created, ok, error?, output?, hint?, rolled_back?, …} or null
```

Enable, disable and restart answer `202` at once and their outcome is the op
record above (fields:
[contract §11.7](../guides/integration-contracts.md#117-hub-api-and-audit)).
A failed `/api/drift/resolve` answers with its HTTP status and a JSON body
`{error, op, output, hint, rolled_back}`; other errors stay plain text.

### Disabling an instance

Click **Disable** on the instance row or its instance page. The Hub runs
`docker compose down` for the project. The instance is marked disabled only once
that succeeds. If stopping fails, the instance stays enabled and the error is shown,
so you can retry instead of being left with orphaned containers. If the
template is gone or its compose file is broken, the Hub falls back to
`docker compose -p portcullis-<id> down`.

Keycloak clients are not deleted when you disable an app. Volumes are kept.

Only one operation (enable, disable, restart, backup, …) runs per app at a
time. A second request while one is in progress answers HTTP 409 with the
running operation, whose progress panel the UI shows
([Progress and Stop](#progress-and-stop)).

## Instance page

Each instance has its own page (`#apps/<id>`, or `#apps/<id>/<tab>` for a specific tab). The page shows:

- **Breadcrumbs**: Apps › \<App\> ›
- **Header**: **`<App> · <label>`** (or just **`<App>`** when the label equals the app name), status pill, **Enable** / **Disable** button
- **Operation banner** (when an operation is running or failed): shows progress or error, with a **Details** link to the progress panel
- **Doctor line** (when the [doctor](#doctor) has findings): "Doctor: …" with a link to the Doctor tab
- **Tabs**: Overview · Settings · Groups · (File sharing) · Logs · Backups · AI · (VPN) · Expert · Delete

The File sharing tab appears only for templates with `person_secret` credentials (Samba, Time Machine), the VPN tab only for templates with a [`vpn:` block](../guides/manifest-reference.md#vpn) (Headscale).

Every instance, including the default instance, gets the same page structure. Deep links from the old `#app/<id>/<tab>` format redirect to `#apps/<id>/<tab>`.

### Settings

- The **Sign-in** block, only for apps whose manifest declares
  [`auth.native_login`](../guides/manifest-reference.md#authnative_login)
  (Plex): *Portcullis sign-in, then the app's own login* (default; the
  override adds `portcullis-auth@docker,portcullis-groups@docker` to every
  router, group = the template's `access_group`) or *App's own login only (no
  Portcullis)*, offered only if the template allows it. Choosing the latter
  shows a red warning; saving writes the routers without the gateway
  middlewares and with `public@file`, publishes no group for the app, logs a
  warning and adds an `app.sign_in` entry (actor, `gateway -> native`) to the
  audit log, refusals included. See
  [Apps with their own login](auth-policies.md#apps-with-their-own-login).
- The **Sign-in template** drop-down (see
  [Sign-in methods and templates](auth-policies.md#default-per-app-and-core-pages)):
  *Default (Standard · 2.5 / 5)* or any enabled template, each with its
  score. Below it: the sentence of the chosen rule, how the app enforces it
  (per request, at sign-in, at the TLS handshake), whether browsers are asked
  for a YubiKey or browser certificate, and the members of the app's users and admins
  groups who have no method set up that meets it. Apps without a Portcullis
  sign-in (`custom` without it, `public`, own login only) and `mtls` apps show
  no drop-down: "This app handles its own sign-in" / "The certificate is
  this app's sign-in". A disabled template can't be picked (`409`), and a
  pick that would switch AI support off asks first. Saved as
  `sign_in_template` (audited `settings.change`, scope `sign_in_template`).
- The app's **options**, declared by the template under `settings:`: one
  value for the instance, values per group that the Hub resolves per person,
  secrets, per-group records and values each person enters. See
  [App settings](#app-settings).
- **Host ports** declared in the manifest: rebind them, or clear optional ones
  to disable the binding.
- The **public exceptions** block, only for apps whose manifest declares
  [`auth.public_access`](../guides/manifest-reference.md#authpublic_access).
  See [Public exceptions](#public-exceptions).

One **Save** sends everything you changed in the tab. The save bar says what
saving does (for example "Saving restarts Immich" or "Takes effect at each
person's next sign-in; no restart"). A sign-in mode or public-exception
change restarts the app; a sign-in template change restarts it only when
whether it asks for a certificate at sign-in changes.

Input validation:

- A path setting is a **custom path** or a **shared folder** (picked in
  the setting, applied through the folder's preview: see
  [Shared folders](#shared-folders)). A shared-folder value can't be typed
  or saved in the panel.
- Path settings must be absolute host directories (not `/`), without `:`
  (Compose would read it as `host:container`) or newlines. Spaces, quotes and
  `#` are fine, because paths are quoted in the generated override.
- Port bind addresses must be IP addresses (e.g. `0.0.0.0`, `127.0.0.1`, `::1`).
  IPv6 is bracketed automatically.
- No setting value may contain newlines or other control characters. Values
  written to the app's `.env` may not contain `'` or `\` either: they are
  single-quoted there.

### Overview

The **Overview** tab shows:

- **Auth notes** (how the app enforces auth, from the template)
- **Addresses**: each hostname as a link, editable (see [Changing hostnames](#changing-hostnames) below)
- **Access** ([VPN-only access](vpn.md#several-vpns-and-through)):
  **Reachable from** *the internet (default)* or *only Portcullis VPNs*;
  **Through** *every VPN provider* or the live providers you tick (the
  built-in one is *Portcullis VPN (built-in)*); in server mode, for an
  instance with public exceptions, *Public links stay on the internet
  (server mode)*. **Save access** asks first ("Make &lt;id&gt; reachable
  only through … ? It restarts.") and restarts the app. With no VPN wired it
  says "No VPN is wired yet: wire a VPN first". Saved with
  `PUT /api/instances/{id}/reach`, audited `instance.reach`; the AI tool is
  `set_instance_reach` (widening needs a confirmation)
- **Containers**: one row per service with its name, state, and status. One-off jobs show as "setup job done" (green), "setup job failed" (red), "setup job running" (amber), or "setup job pending" (gray). Services with no container show "(none) · \<svc\> · no container" in red.
- **Instance**: label (editable inline), instance id, template, compose project name
- **Last operation**: most recent operation (enable, restart, backup, etc.) with its status and timestamp

**Editing the label**: click the label to edit it inline. The change is saved with **Save** and updates the instance's name everywhere (portal, My apps, People, consent texts).

### Groups

The **Groups** tab shows the instance's access and admin groups:

- Group name (linking to `people.<domain>` in a new tab)
- Kind: "New group (manual)" for groups created at setup, or "Existing group" for bound groups, plus rule details ("rule-based: \<rule\>" or "built-in LLDAP group")
- Member count and first names of up to 3 members, with "+N" for the rest
- **Manage on People ↗** button (opens the group page in a new tab)

When a group doesn't exist, the tab shows "doesn't exist" in red with a **Create missing groups** button.

### Logs

The **Logs** tab shows:

- The instance's [last operation](#when-an-operation-fails) (with compose's output if it failed)
- A container picker: **All containers** or one specific container (only the instance's services)
- Log lines (last 100, 200, or 500 lines)
- **Refresh** button to reload

### Backups

The **Backups** tab shows:

- List of this instance's backups (name, size, timestamp)
- **Back up now** button
- **Restore here** (same-instance restore) for each backup
- **Restore as new** (restore into a new instance id, with an optional label)
- **All backups** button (shows backups across all instances)

See [Instance backups](#instance-backups) and [Restoring an instance](#restoring-an-instance).

### AI

The **AI** tab (deep link `#apps/<id>/ai`) shows:

- Whether the AI can act in this instance
- Its companions (services the AI can call)
- The switch and mode (proactive, request-only, or off)
- The people who can use it (based on the instance's groups)
- A **Revoke** button to revoke all AI tokens for this instance
- Recent AI activity (last N AI actions)

For AI pages (`ai-chat`), the tab also shows the configured model providers. Templates without AI support show the reason and, when the template names one, an alternative "not vetted by Portcullis". See [AI support](ai.md#switching-an-app-on).

### VPN

The **VPN** tab (deep link `#apps/<id>/vpn`; templates with a `vpn:` block
only) makes the instance a [VPN provider](vpn.md#wiring-a-marketplace-vpn):

- **Use for Portcullis access** and, for a provider with a device hook, the
  **refresh** (`15s`–`10m`, default `60s`); **Save** asks first. Unwiring
  lists the apps that accept only this provider, which become unreachable.
  Wiring is refused while the VPN service isn't running, or when a range
  overlaps the built-in subnet, a reserved range, a Docker network or
  another provider (`PUT /api/instances/{id}/vpn-provider`, audited
  `vpn.provider_wired` / `vpn.provider_unwired`; AI tool `set_vpn_provider`).
- **Ranges, devices** (and how many are online), **Map** fresh or stale with
  the last refresh, the hook's **last error** (redacted), and a table of the
  devices **left out** with the reason.
- **Static assignments** (providers with `identity.source: static`): an
  address, a person and a device name; **Assign** asks first ("Traffic from
  &lt;ip&gt; counts as &lt;person&gt;'s device &lt;name&gt;"), **Remove** per row
  (audited `vpn.static_assigned` / `vpn.static_unassigned`; AI tool
  `assign_vpn_address`).
- **DNS**: the A records for the Portcullis hostnames, the DNS hook's error
  if it failed, and for `dns: manual` **I configured them**
  (`POST /api/instances/{id}/vpn-dns/ack`, audited `vpn.dns_acknowledged`).

### Expert

Advanced tools with direct access to the compose configuration and the
containers. Compose runs with three files, later ones winning:

```text
docker compose -p portcullis-<id> \
  -f <template>/compose.yml \
  -f ${HUB_DATA_DIR}/overrides/<id>.override.yml \
  -f ${HUB_DATA_DIR}/overrides/<id>.user.yml
```

1. **compose.yml** (read-only). The template's file as it comes from the
   template source. The Hub never writes it, so source syncs always
   fast-forward. To change routing (subdomains, routers, middlewares), change
   the template in its source (see [Template sources](#template-sources)).
2. **Hub override** (read-only). Generated from Settings and regenerated
   before every `compose up`: bind mounts, host ports, each router's
   `tls.options` derived from the sign-in template, router middlewares for instances
   with their own login, and the public-exception router with its strip
   middleware when on. Never hand-edited.
3. **Custom override** (editable). Your own additions, stored by the Hub per
   instance, outside the template clone, so template syncs and updates keep it.
   See [Custom override](#custom-override).

#### Environment variables

One table with rows for every variable in the instance's `.env`:

| Column | Content |
|--------|---------|
| **Key** | Variable name |
| **Default** | What the template, the Hub, or a setting writes (shown as `[set]` for secrets) |
| **Source** | `template`, `hub`, `option` (from a setting), or `custom` (your own variable) |
| **Your value** | Your override (empty = using the default) |
| **Actions** | **Override** / **Reset** (or **Remove** for custom variables) |

Variables you can override:

- Any variable the template uses only in `environment:` blocks (map values or list items)
- Variables you add yourself with **+ Add your own variable**

Variables you **cannot** override (shown with "set by the Hub — can't be overridden"):

- Hub-set variables: `PORTCULLIS_*`, `COMPOSE_*`, `DOCKER_*`, `BUILDKIT_*`, `BUILDX_*`
- Secrets (names in the template's `secret_env` or secret-looking names)
- Variables set by a setting (e.g., a port's `<PORT>` and `<PORT>_BIND`)
- Variables the template uses outside `environment:` (in image tags, labels, volume sources, command, etc.)

Your overrides are written single-quoted at the end of the `.env`, so they win. A value may not contain `'`, `\`, line breaks, or control characters. An enabled instance restarts after each change; a disabled one gets the value at its next start.

If a template update makes one of your variables refuse (moved outside `environment:`, became Hub-set, or became a secret), it is no longer written and shows in the Deliveries panel's "Environment values" unit. The next prune removes it.

#### Other Expert tools

- **Container shell**: Runs one command with `/bin/sh -c` in a chosen container
  through the Engine API and shows its output. The Hub stops waiting after
  15 minutes, or when the browser request is cancelled. A process that keeps
  running inside the container is not killed.
- **Restart app** (enabled instances): A full `down` + `up` of the project, so
  override and env changes take effect. It waits for the result and, if it
  fails, shows compose's output like a failed enable.

### Delete

The **Delete** tab shows:

- A warning about what will be deleted (volumes, groups, Keycloak clients)
- For bound instances (groups mode "existing"), a note that the groups won't be deleted
- A typed confirmation field (type the instance id to confirm)
- **Delete** button

See [Deleting an instance](#deleting-an-instance).

#### Custom override

Typical uses: pin a different image tag, add environment variables, resource
limits, extra bind mounts or named volumes, extra (literal) host ports, a
healthcheck. **Save override** validates and stores it; it applies on the next
restart ("restart to apply"), or when a disabled app is enabled. Saving an
empty (or comment-only) override deletes the file. Every save, removal and
refusal goes to the [audit log](#audit-log) as `app.compose_override` with the
signed-in user, the size and a SHA-256 prefix, never the content (it may hold
env values). The file is mode 0600.

The Hub refuses anything that would bypass Portcullis' routing or isolation.
group-gate keys every policy and group by the full hostnames of the
instance's Traefik routers (policy v6), and the Hub's override sets each router's TLS
options and middlewares, so the custom override may not change them:

- **Top level:** only `services`, `volumes`, `networks`. Must be a mapping;
  no YAML tags (compose's `!reset` / `!override` could strip the template's
  labels or networks).
- **Services:** only services the template defines, and only these keys:
  `image`, `command`, `entrypoint`, `environment`, `labels`, `volumes`,
  `ports`, `expose`, `restart`, `healthcheck`, `user`, `working_dir`,
  `hostname`, `domainname`, `mem_limit`, `mem_reservation`, `memswap_limit`,
  `mem_swappiness`, `cpus`, `cpu_shares`, `cpuset`, `pids_limit`,
  `shm_size`, `ulimits`, `logging`, `tmpfs`, `extra_hosts`, `dns`,
  `dns_search`, `dns_opt`, `stop_grace_period`, `stop_signal`, `init`,
  `read_only`, `cap_drop`, `tty`, `stdin_open`, `pull_policy`, `platform`,
  `depends_on` (on the template's services), `oom_score_adj`.
  Everything else is refused, in particular `privileged`, `cap_add`,
  `devices`, `security_opt`, `network_mode`, `networks`, `pid`, `ipc`, `uts`,
  `userns_mode`, `cgroup`, `cgroup_parent`, `sysctls`, `volumes_from`,
  `extends`, `env_file`, `build`, `links`, `external_links`,
  `container_name`, `profiles`, `deploy`, `configs`, `secrets`, `group_add`,
  `runtime`.
- **Labels:** no `traefik.*` (routers, rules, middlewares, TLS options,
  entrypoints, services) and no `com.docker.compose.*` (the Hub finds the
  app's containers by them).
- **Volumes:** named volumes, `./templates/<app>/…`, or bind mounts of
  absolute host paths under the **bind roots**; everything else is refused,
  including `/home`, `/var`, `/opt` and `/etc/localtime`. The bind roots are
  `HUB_OVERRIDE_BIND_ROOTS` (colon-separated absolute paths, e.g.
  `/srv:/mnt/media`), default `/srv:/mnt:/media`. The Hub refuses to start if
  a root is `/`, is or contains a system path (`/etc`, `/var/lib`, `/run`,
  `/usr`, `/tmp`, …), contains the Docker socket or state, or overlaps the
  core checkout. Sources are cleaned (`//`, `/./`); `..` segments, sockets
  (`*.sock`) and `/` itself are refused, as are shared/slave bind propagation
  and volume types other than bind, volume, tmpfs.

    !!! warning
        The Hub can't resolve symlinks on the host: a symlink under a bind
        root pointing elsewhere (e.g. `/srv/x -> /`) would be followed by the
        Docker daemon. What lives under the bind roots is the operator's
        responsibility; keep them to data directories.

- **Ports:** literal host ports only (no variables); they count in the port
  checks against other enabled apps and against the app's own Settings ports.
- **Top-level `volumes`:** only `labels` per volume (no `driver`,
  `driver_opts`, `external` or `name`: they could point at host paths or
  another app's data).
- **Top-level `networks`:** only networks the template declares and doesn't
  mark external or name (so never `portcullis-proxy`), with `labels`,
  `driver_opts`, `enable_ipv6`, `ipam`.
- **No variables anywhere.** Compose interpolates `${VAR}` / `$VAR` in keys and
  values *after* the Hub's checks, so a label key `${T}raefik.enable` would
  become `traefik.enable`. Every key and value with an unescaped `$` is
  refused; write `$$` for a literal dollar sign (compose turns it into `$`).

Because of these rules, the routes, subdomains, published snapshot and
exposure drift the Hub computes from the template stay exact with a custom
override in place. The override is checked again before every `compose up`: if
a template update dropped a service it names (or it no longer passes), enable,
restart and drift actions fail with HTTP 409 ("the custom compose override
(Expert) is not valid for this template any more") before compose runs — edit
or clear it.

!!! warning
    A custom override can still break the app (a wrong image, a bad mount).
    It can't change how Portcullis routes and guards it.

### Public exceptions

Some apps have share links meant for people without a Portcullis account
(Nextcloud public shares, Grafana shared dashboards, Immich shared links). If
the template declares them, the Settings tab shows a **Public exceptions**
block (bordered in amber):

- the template's description and every declared path with its description
  and kind: *per share* (`{token}` path), *supporting, always opened*
  (static assets) or *all shares only*;
- a red warning: requests to these paths skip Portcullis entirely (no
  forward-auth, no group-gate, no hardware key); only the app's own checks
  (share token, share password, expiry) apply;
- what is refused or stripped: core's public guard answers 403 to requests
  carrying `Authorization`, `Proxy-Authorization` or the app's login
  headers, cookies or query parameters (an app user signed in with
  "remember me" opens shares in a private window), and the Hub strips
  identity headers;
- if the app's template requires a YubiKey or browser certificate at the TLS handshake
  (`protected@file` or `protected-any@file`), an amber warning that **all** of the app's routers use
  `authaware@file` while a public path is open. For native-OIDC apps it adds
  that the certificate is then only enforced at sign-in (Keycloak's template check); for forward-auth /
  header-auth apps that group-gate still checks the certificate on
  every gated request; and it lists routers without group-gate, which lose
  the handshake check. See
  [Sign-in methods → Public exceptions](auth-policies.md#public-exceptions).

Controls:

| Control | Meaning |
|---------|---------|
| **Allow public exceptions** | On/off (an explicit admin choice) |
| **Use the template default** | Forget the choice; the template's `enabled_by_default` applies, also after it changes on a template sync |
| **Only listed shares / All shares** | Mode, if the template has `{token}` paths. *Only listed*: just the shares below. *All*: every share of the app |
| **Listed shares** | Each listed token with **Remove**; a text box takes share URLs or bare tokens, one per line |

The Hub extracts the token from a pasted URL (the `{token}` segment of the
first matching path, e.g. `https://cloud.example.org/s/AbC123/download` →
`AbC123`), checks it against the template's `token_pattern` and the alphabet
`[A-Za-z0-9._~-]`, rejects anything else (the save fails with the reason),
and removes duplicates. At most 200 shares per app (each adds two matchers
per `{token}` path to one Traefik rule). The status line shows what is open
(with `{token}`, never the tokens) and on which subdomains, or "No public
router is generated" — the case in mode *listed* with no share, which also
keeps the handshake tier.

The list is admin-managed: ordinary app users can't publish a share to the
internet themselves; they create the share in the app as usual (with its own
password and expiry) and ask a Hub admin to list it. Remove the token (or
turn the exception off) to close it again; the app's own share settings keep
applying either way.

Saving regenerates the override and restarts the app. Any public choice
(toggle, token list) also pins the mode it was made under, so a later
template change can't widen it. Fail closed:

- a stored mode the template no longer supports (e.g. *listed* after the
  template dropped its `{token}` paths) opens **nothing** and shows "public
  exception disabled … confirm a mode" in the block and as drift;
- listed tokens the template's `token_pattern` no longer accepts are not
  routed and are shown as invalid (saving removes them).

The router is generated from the manifest, not shipped in `compose.yml`: only
the Hub knows whether the exception is on, which shares are listed and which
TLS tier the host gets, and a template can't open paths by itself.

## App settings

Templates declare their options under `settings:` in the manifest
([Manifest Reference](../guides/manifest-reference.md#settings),
[contracts §13](../guides/integration-contracts.md#13-settings)). The Hub
validates every value, stores it, works out who gets what and delivers it to
the app. The template only says what the option is and how the app reads it.

The panel is the app's (or instance's) **Settings** tab on `hub.<domain>`,
for admins only. It needs Users & Groups: per-person values are worked out
from group memberships, so without the Hub's LLDAP account the settings API
answers `503` and the tab can't load. A request without a signed-in user is
`401`, and delegates get `403`.

### What the panel shows

From top to bottom:

1. The **Deliveries** strip: how each part of the last delivery went, with
   **Retry** (see [Deliveries and Retry](#deliveries-and-retry)).
2. The template's options, grouped by the template's sections. Each option
   shows its label, when a change takes effect ("applies: at the next
   sign-in", "applies: after a restart", …), its description and any
   warnings.
3. Host ports, the sign-in block, the sign-in template and public exceptions
   (see [Settings](#settings)).
4. The **save bar**.

Each option is one of four kinds, depending on its scope:

| Scope | What you set | Example |
|-------|--------------|---------|
| instance | One value for the whole instance | Immich's trash days, Jellyfin's library folders, Nextcloud's default quota |
| per person | A value for "everyone else with access" plus rows for groups; the Hub resolves one value per person | Immich's storage quota and role, Grafana's role |
| per group | One record per group you add; the app gets the records, the Hub doesn't resolve them per person | A library or room per group |
| entered by each person | Nothing: each person enters their own value on [My apps](#my-apps) | Firefox Sync's Mozilla account ID |

The editor fits the option's type: a text box (with the template's pattern
or format), a number with its unit, a size (a number plus MiB / GiB / TiB,
with an **unlimited** box where the template allows it), a duration, a
checkbox, a dropdown, a multi-select, a list, a table, a group or user
picker, or a host path (with "the app writes here as uid:gid" when the
template says which identity the app writes as). Options the template pairs
with `requires` (a Craft app's version and its SHA-256) sit side by side:
setting one without the other is refused. Leaving an instance option empty
(or resetting it) goes back to the template's default.

### Per-group values

A per-person option has a row **Everyone else with access** (the default)
and one row per group. **+ Add group** adds a row; ✕ removes it. The
**When someone is in several groups** choice says how the Hub picks one
value for a person who is in several of the listed groups:

| Choice | Rule |
|--------|------|
| largest wins / smallest wins | Numbers, sizes, durations and choices (by the template's order); unlimited beats any number under "largest" and loses under "smallest" |
| first matching group wins (in this order) | Any type. The rows get drag handles and ▲ / ▼ buttons to order them |
| everything any of their groups gives / only what all of their groups give | Lists and sets |
| on if any of their groups says on / on only if all of their groups say on | Checkboxes |

The template sets the rule; it may let you switch between a few (its
`resolve_choices`). The default row is only a fallback: it applies to people
in none of the listed groups and never takes part in "largest wins". If
nothing applies to someone (no matching row, no default), they get nothing
for that option and the app uses its own default ("unresolved: the app's own
default applies").

A template can preset rows for the instance's own groups: Immich and Grafana
give their admin group (`admin_<id>`) the administrator role. These rows are
added when the instance is created or enabled, and bound to the group the
Hub creates for it.

**Rows follow the group, not its name.** Each row stores the group's LLDAP
id. When a group is deleted, through the Hub or in LLDAP's own UI, its rows
stop granting anything at once and are removed (see
[Groups deleted outside the Hub](groups.md#groups-deleted-outside-the-hub)).
A group re-created with the same name starts with no rows. If you saved
from a panel that was loaded before such a change, the save is refused with
`409` ("re-created since its row was saved"): reload the tab.

**Privileged options.** Options the template marks `privileged` (a role or
an admin flag) take rows only from groups that delegates can't steer:
manual groups, and rule-based groups whose rules use admin-only fields. The
group picker greys out the other groups with the reason ("can't grant a
privileged value: its rule uses fields delegates can edit: office_location").
Their default is always the lowest value (Viewer, User). A group used in a
privileged row becomes a [guarding group](groups.md#guarding-groups).

### Who gets what

Under each per-person option, **Who gets what** lists everyone with access
and the value they would get with the panel as it is now, before you save:
"10 GiB from office_milan", "2 TiB largest of office_milan (10 GiB),
it_staff (2 TiB)", "500 GiB everyone else with access". It updates a moment
after each edit, has a search box and shows 50 people per page. Each group
it names links to the group's page on `people.<domain>`, in a new tab (an
unsaved draft stays where it is). The save bar adds
"Changes: N people get a new value".

"With access" means:

- with group access on (or the app's Keycloak access role enforced): the
  members of the instance's access group, minus anyone whose temporary
  membership has expired;
- otherwise every LLDAP user except the Hub's service account.

The admin group never adds anyone: a member of `admin_<id>` who isn't in
the access group can't reach the app and gets nothing. Warnings below the
list say when some members of a listed group have no access ("1 member of
office_milan has no access to Immich and gets nothing") and when people
joining or leaving restarts the app. For an app signed in with its own
login only (no Portcullis), nobody gets a per-person value: "per-person
values need Portcullis sign-in".

### Saving and when changes take effect

The save bar says what saving does before you click **Save**. Each option
declares when a change takes effect:

| Applies | What happens |
|---------|--------------|
| at once (`live`) | A hook in the running app applies it; no restart |
| after a reload (`reload`) | The Hub sends the app's reload signal (or runs its reload hook) |
| at the next request (`next_request`) | Request headers: each person's next request carries the new value |
| at the next sign-in (`next_sign_in`) | Token claims: each person gets the new value when they next sign in to the app |
| after a restart (`restart`) | The Hub restarts the app in the background |
| when an account is created (`account_creation`) | Only accounts the app creates from now on get it. The panel warns "existing accounts keep their value" |

One save does the strongest thing any changed option needs, once: a
restart covers a reload, and several reloads are one. Changing a port, a
path or an option the app reads from its `.env` restarts an enabled app. On
a disabled app the values are stored and used at the next start.

- **A save never waits for a running delivery.** If one is still running
  (a slow hook, a restart), the save is stored and answers at once; its
  delivery runs right after (the save's answer shows the `Delivery` unit
  as `busy`: "a delivery is running: this one follows it").
- **A restart owed survives a Hub restart.** The Hub records the reload or
  restart a save still owes before it starts it, and runs it again at its
  next start if it stopped first. A restart that can't start (another
  operation holds the app too long) is the app's
  [last operation](#when-an-operation-fails) `restart`, failed; it stays
  owed.
- **A restart checks before it stops the app.** The Hub writes the
  override, `.env` and data files first; if one of them is refused, the
  app keeps running and the restart fails.
- **One bad value never blocks the `.env`.** A stored value that can't be
  written into the `.env` (it holds a `'`, a `\` or a line break, e.g.
  after a template update) is written empty for that variable only, logged,
  and shown in the Deliveries strip as unit `env:values`; every other
  variable is written.

Membership changes deliver too. When people join or leave a group, the Hub
waits 60 seconds per instance before delivering, so many changes in a row
cause one restart, not one each. It also re-checks every 10 minutes.

Every changed option is audited as `settings.change` (`scope=…: before ->
after`; secrets show as replaced), refused saves as `refused`.

### Secrets

Options of type `secret` (an API key, a password the app needs) are
write-only. The panel shows **Set ✓ (updated …)** or "not set", with
**Replace**, **Generate** (when the template declares how) and **Clear**
(asks first). The input is a password field. After a save the panel is
rebuilt from the Hub, which never sends a secret back: not in the panel, not
in the save's answer, not in logs, op records or the audit (which says
`replaced`, `generated` or `cleared`). Generated values use the template's
length and character set (hex, letters and digits, or printable ASCII
without space, `'` and `\`). A secret can't contain `'` or control
characters. Clearing a secret another option `requires` is refused.

The Hub keeps secrets in `${HUB_DATA_DIR}/settings/<id>/secrets.json`
(mode 0600). They reach the app only through its `.env` (mode 0600), a
secrets file (mode 0600, see
[Security & Hardening](hardening.md#settings-data-files-and-secrets)) or a hook's
standard input. **Expert → Environment variables** shows them as `[set]`
and refuses to override a variable an option owns ("change it under
Settings") or a secret ("use Settings").
Backups carry them; a restore into a new id generates new values for the
generated ones.

A template update that renames or removes a secret option doesn't leave
the value behind: the next sync blanks every `.env` variable that still
holds it before the Hub forgets it, and **Expert → Environment variables**
shows any variable whose value equals a stored secret as `[set]`, whoever
wrote it.

### Deliveries and Retry

The **Deliveries** strip lists each part of the last delivery:

| Unit | What it is |
|------|------------|
| Environment | The option values in the app's `.env`, read when the app starts |
| Environment values (`env:values`) | Shown only while some stored value can't go in the `.env`: those variables are written empty (named, without the value), and env overrides the template now refuses are skipped |
| Data file `<name>` | A JSON file the Hub writes for the app (mounted read-only) |
| Hook `<name>` | A command the Hub ran in the app's container, with the settings on its standard input |
| Sign-in claim `<attribute>` | Per-person values in Keycloak tokens |
| Request headers | Per-person `X-Forwarded-Attr-*` headers group-gate adds |
| Reload / Restart | The effect of the save |
| Delivery | The run as a whole (shown when it didn't run) |

Each one reads **last applied**, **failed:** with the error (secrets
blanked), or a skip reason:

| Skip reason | Meaning |
|-------------|---------|
| unchanged | Nothing new to deliver |
| not running | The app isn't running; it gets the values when it starts |
| directory unavailable | Users & Groups didn't answer; the last delivery stays in place |
| busy | Another operation on the app was running; the delivery runs again shortly |
| superseded | A newer save replaced this run, which runs again |
| not supported | The app has no reload action |
| previous run still running | A hook from an earlier run is still running (it timed out but the container hasn't finished it); the Hub tries again |

**Retry** runs the delivery again, every hook included, and is audited as
`settings.retry`. A failed hook or reload is also the app's
[last operation](#when-an-operation-fails), and every failed unit is logged
by the Hub (`settings: <id>: delivery unit <unit> failed: …`). A hook runs
again on its next trigger anyway, so fix the cause, then **Retry**.

Hooks run one at a time per instance, each for at most its template's
timeout (at most 10 minutes). Nextcloud's start hook waits for Nextcloud to
finish installing, which can take up to 10 minutes on the first start; a
save made meanwhile is delivered after it.

### Values people enter

An option entered by each person shows, instead of an editor:

- "N of M people with access have entered one", with a search box;
- each value with the person, when and by whom it was set, and
  **delivered**;
- **Stored, not delivered**: values the app doesn't get, with the reason:
  *no access* (the person left the access group), *account changed* (the
  account was deleted or re-created outside the Hub) or *directory
  unavailable*;
- **Not set**: people with access who haven't entered one.

**Clear** works on every value. **Set** / **Edit** appear only when the
template allows admins to enter a value for someone (`admin_override`), and
never on a "no access" or "directory unavailable" row. These buttons act at
once (they don't go through the save bar, and your unsaved edits are kept).
Uniqueness applies to admins too. If the app restarts to pick values up, the
option warns "people entering or changing a value restarts <app>".

What happens to a value:

- **Leaving the access group:** the value is kept but no longer delivered.
  Rejoining delivers it again.
- **Account deleted through the Hub:** the person's values are deleted in
  every app (audited, the admin as actor).
- **Account deleted or re-created outside the Hub:** each value remembers
  the LLDAP account it was entered for. A re-created account with the same
  name doesn't get it; the value stops being delivered at once and is
  removed at the next check (audited, actor `hub`), only while LLDAP looks
  healthy (the same check as the
  [stale-record cleanup](#stale-keycloak-records-admins-only)).
- **Disabled app:** values are kept, nothing is delivered.
- **Template update** that removes the option, changes its type or tightens
  its rules: values that no longer fit are dropped (audited `invalidated`).
  When an option becomes unique, the earliest of two equal values stays.
- **Backups** carry the values; a restore keeps the account check.

Every change, refusal, deletion and purge is audited as
`settings.person_value` with target `<instance>/<option>/<person>`.

## App instances

A template can run as multiple fully independent **instances**. Each instance has its own:

- compose project, containers and volumes (data is never shared)
- label (shown as **`<App> · <label>`** everywhere)
- settings, environment variables and generated secrets
- Keycloak clients (one per manifest `keycloak_clients` entry)
- access and admin groups (`users_<id>`, `admin_<id>`, or bound existing groups)
- sign-in template pick, public exceptions and sign-in mode
- drift tracking and last-operation record

Templates declare `instances: multi` or `instances: single` in their manifest.
**Multi** templates show **+ Add instance** in Apps and Marketplace and can be instantiated
as many times as needed. **Single** templates run only as their default instance
(e.g., templates that bind fixed hardware).

### Default instance

Every template has a **default instance** whose id is the template id itself. For
existing enabled apps, nothing changes: they are their template's default
instance, with today's project name, hostnames, groups and volumes. No migration
is needed. The default instance gets the same [instance page](#instance-page) as any other instance.

### Creating an instance

See [Setup before the first start](#setup-before-the-first-start) for the complete setup form flow.

When you create an instance (Install… or + Add instance), the Hub:

1. Validates the label, instance id, hostnames, and groups
2. When groups mode is "new": creates the access and admin groups (`users_<id>`, `admin_<id>`, only for
   groups the manifest declares) as empty manual LLDAP groups, through the
   Users & Groups guardrails as the acting administrator (who must be an LLDAP
   administrator). For the first instance, groups with names other than `users_<template>` / `admin_<template>` aren't created (only a warning) and must exist on People.
3. When groups mode is "existing": stores the bound group names, creates nothing
4. Generates fresh values for every `generate: random` secret
5. Stores the instance's setup choice values
6. Records the instance as `state: created`, with its label, hostnames, groups mode, and binding

If you chose **Save without starting**, the instance stays created but not enabled. If you chose **Start**, the Hub then enables it (see [What happens when you enable](#what-happens-when-you-enable)).

The `.env` carries the instance variables:

- `PORTCULLIS_INSTANCE=<id>`
- `PORTCULLIS_HOST_<ROUTER>=<hostname>` (one per host router)
- `PORTCULLIS_OIDC_CLIENT_ID[_<KEY>]=<id>[-<client id>]` (per Keycloak client)
- `PORTCULLIS_ACCESS_GROUP=<users group>` (derived or bound)
- `PORTCULLIS_ADMIN_GROUP=<admins group>` (derived or bound)
- `COMPOSE_PROFILES=<profile1>,<profile2>` (for templates with profiled services, from the instance's setup choices)

The override names the volumes `portcullis_<id>-<key>` and renames the
template's routers, services and middlewares to `<id>_<name>`.

The instance appears in Apps under its app block and on its own [instance page](#instance-page).

### Changing hostnames

An instance's hostnames can be changed at any time (enabled or not) on the
**Overview** tab. Each hostname is individually editable. Hostnames must be:

- valid hostnames (at most 253 characters, `<label>.<domain>` where each label
  is `[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?`)
- either `<label>.<main domain>` or `<d>` / `<label>.<d>` for an added domain
  `<d>` that is in state `ready` (records OK, valid certificate)
- not already used by another instance, a core subdomain, or the added domain
  names themselves

Some templates mark host routers as **immutable** (`hosts.immutable` in the
manifest): their hostnames cannot be changed after the instance is created. This
is for apps that store their own URL in their database (e.g. Matrix homeserver
domain).

When you save, the Hub:

1. Validates the new hostnames (collision checks, added-domain state)
2. Updates the instance's Keycloak clients' redirect URIs and web origins, and
   the extra-domain sign-in callback URIs (see [Cross-domain sign-in](#cross-domain-sign-in))
3. Regenerates the instance's `.env` and compose override with the new hostnames
4. Saves the instance state (**commit point** — if this succeeds, the old
   hostnames are gone)
5. Publishes the new hostnames to group-gate and updates the portal
6. Restarts the instance if it is enabled

The change is audited as `instance.update` with the acting administrator. If
step 6 fails, the instance's last-operation record shows `op: hosts` and the
error; the new hostnames are already in effect, but the app is not running with
them — retrying **Save hostnames** with the same hostnames re-applies
everything (the Hub keeps the last hostname-change record apart from the other
operations, so a backup in between doesn't hide the failure).

**Changing the main domain** (`PORTCULLIS_DOMAIN` in core's `.env`) moves every
default instance's hostnames to the new domain, which **breaks apps that store
their own URL** (e.g. GitLab). Default instances of templates with
`hosts.immutable` (Matrix) are the exception: their hostnames are pinned on
their first enable and never moved; such an instance is listed as error (and
stays denied) until you add the old domain as an extra domain or fix its
hostnames. See [DNS Configuration](../setup/dns.md).

Hostnames are also refused while another instance's running project still
routes them (409, "restart or stop it first"), and a hostname set a router
can't serve is a 400 at once: one router mixing main-domain and extra-domain
hostnames, or an extra-domain router that reaches `portcullis-auth` through the
template's own chain middleware.

### Adding extra domains

The **Settings → Domains** section (Hub admins only) lists added domains and
their status. To add a domain:

1. Click **+ Add domain** (the toasts say "Adding …" while it runs)
2. Enter the domain name (e.g. `team-a.example.org` or `team-a.<main domain>`)
3. Select the DNS provider (Cloudflare, Porkbun, Route 53, DigitalOcean,
   Hetzner (legacy DNS, dns.hetzner.com) or Hetzner Cloud (a Cloud API token
   with Read & Write))
4. Paste the provider's API token or credentials

The Hub sends the credentials **once** to the domains service (see
[Domains service](#domains-service)) and never stores them in its own state,
logs, audit or errors. The domains service:

- stores them encrypted at rest with an age key
- creates `<d>` and `*.<d>` DNS records (A, and AAAA if the server has IPv6)
- writes a CAA at `<d>` pinned to its own ACME account, DNS-01 only, and
  waits until both public resolvers see it before ordering
  ([CAA](../setup/dns.md#caa))
- obtains a Let's Encrypt wildcard certificate for `*.<d>` and `<d>` via DNS-01
- renews the certificate 30 days before expiry
- publishes the certificate to Traefik via its HTTP provider

The domain is listed with:

- **Records**: OK (both public resolvers 1.1.1.1 and 8.8.8.8 answer with the
  server's addresses) or the last error
- **Certificate**: valid until (RFC 3339), or "none" / "expired"
- **State**: `pending` → `records` → `issuing` → `ready`, or `renewing` (< 30
  days left), or `error` (retried with backoff), or `missing`: the domains
  service no longer lists a domain that instances still use. The Hub keeps it
  (its hostnames stay extra-domain hosts and keep their policy and sign-in),
  refuses new hostnames on it (409) and logs it; add the same name again to
  bring it back. It is dropped once no instance uses it

A domain is **assignable** (usable for instance hostnames) only while `records_ok`
is true, the certificate is valid and the domains service is reachable. Existing
hostnames on a domain that stops being assignable are kept, but new assignments
and hostname changes to it get HTTP 503.

CAA and DNSSEC never make a domain unassignable: only the records check and
the certificate's validity do.

**Replacing the token**: click **Replace token** on the domain, paste the new
credentials and save. The domains service re-runs the records step and, if
needed, issuance.

**Removing a domain**: click **Remove** on the domain. The Hub refuses (409)
while any instance has a hostname on it. After the Hub's check, the service
removes the DNS records (and retries once on failure) and stops serving the
certificate.

Credentials reach the domains service over an internal API with a shared bearer
secret, never through the Hub's logs, state, errors or API responses. The
domains service stores them in one age-encrypted file with its ACME account and
certificates (the age key is in core's `secrets/`, so the encrypted backup must
be protected like Vault's). See [Domains service](#domains-service) and
[Security & Hardening](hardening.md#domains-service).

### The DNS panel

Each domain in **Settings → Domains** has a **DNS** button that opens its
DNS panel, built from the domain's [DNS plan](../setup/dns.md#record-sets)
(**Refresh** builds it again, at most once per 30 s per domain):

- **One row per record**: set (`address`, `caa`, `nomail`), name, type, the
  wanted and live values, and the status (`ok`, `missing`, `wrong`,
  `foreign` for a record under the domain that isn't Portcullis', or
  `unknown` when a lookup failed) coloured by severity, with the steps left
  under it.
- **Fix** on each row Portcullis can write: it applies that row's record set
  in the background (the domain goes to `records`, then back), audited
  `domain.dns_apply`. Rows that need a hand change (a CNAME in the way, a
  record of another service) list the steps instead.
- **CAA**: the issuer, the account the pin names (or CA-only) and "would
  issue: yes / no", the CA's own judgement of the live records.
- **DNSSEC**: the zone, its state (`secure`, `unsigned`, `ds_missing`,
  `ds_mismatch`, `bogus`, `insecure`, `unknown`), the steps left and the DS values to
  publish at your registrar, each with a **Copy** button.
- **Turn on DNSSEC signing**, only while the zone is `unsigned` and the
  provider can sign through its API (Cloudflare), behind the confirmation
  "Turns on signing for the whole zone <zone>. Continue?": signing is
  zone-wide and can't be undone from Portcullis. Audited
  `domain.dnssec_enable`. There is never a button to turn signing off
  ([why](../setup/dns.md#dnssec)).

The **main domain** has a read-only panel above the table: the same rows,
CAA and DNSSEC state, built from public lookups only (the Hub never holds the
main domain's credentials). It has no Fix or signing buttons; every fix reads
"Run `./portcullis dns setup` on the server".

The same plans feed the [doctor's DNS checks](#dns-checks). Through the
Portcullis MCP the panel's twins are `get_domain_dns`, `get_main_dns`,
`apply_domain_dns` and `enable_domain_dnssec` (a confirmation, like the
button), plus `domain_op` for the op record of a doctor DNS fix.

### Cross-domain sign-in

Portcullis supports single sign-on across the main domain and added domains
with **no extra key touch** (like Amazon Midway). When a signed-in user opens an
instance on an added domain:

1. The instance's Traefik router uses `portcullis-auth-ext@docker`, a second
   oauth2-proxy service (`forward-auth-ext`) that runs alongside `forward-auth`
2. `forward-auth-ext` redirects to Keycloak with a relative callback
   `/oauth2/callback` (resolved to `https://<added host>/oauth2/callback`)
3. The user's existing Keycloak session at `auth.<main domain>` satisfies the
   sign-in **silently** (no prompt) unless the instance's template needs a
   method the session lacks (then it prompts for step-up, as on the main
   domain)
4. Keycloak redirects back to `https://<added host>/oauth2/callback`
   (the Hub maintains these URIs in the `portcullis-forward-auth` client's
   redirect URIs)
5. `forward-auth-ext` sets a **host-only** session cookie `__Host-portcullis_ext`
   (the `__Host-` prefix: browsers accept it only `Secure`, without `Domain`,
   with `Path=/`, so sibling hosts can't plant or widen it)
6. The user reaches the app

**Key points**:

- The main-domain cookie (`.<main domain>`) and host-only added-domain cookies
  (`__Host-portcullis_ext`) coexist without interfering
- The Hub adds a sign-in router `portcullis-oauth2-<id>_<router>` per
  extra-domain host: `Host(<host>) && PathPrefix(/oauth2/)` → `forward-auth-ext`
- Core never routes to extra domains: the portal, Hub, people, auth, directory,
  enroll (setup links), traefik and metrics pages exist only on the main domain
- Both oauth2-proxy services use PKCE (S256) as required by the Keycloak client
- The callback URIs follow the instance: added on enable (a failed enable
  removes them again), changed with its hostnames and with its sign-in mode
  (gateway ↔ app's own login; the change waits for no other operation: 409
  busy while one runs on the instance; the Keycloak update comes first, a
  failure is a 502 and nothing changes), removed on disable and delete; the Hub's access
  sync loop re-asserts them for running instances
- The Hub swaps `portcullis-auth@docker` for `portcullis-auth-ext@docker` only
  where it is listed on the router itself: a template whose router reaches
  forward-auth through its own chain middleware can't get extra-domain
  hostnames (400)

### Instance backups

**Admin-only.** The Hub can back up any instance on demand or before a restore /
delete. Backups, restores and deletes run in the background: the API answers
`202` with an operation id, and the UI polls that operation's record
(`GET /api/instances/<id>/op?op_id=<op_id>`) until it is done
([contract §11.7](../guides/integration-contracts.md#117-hub-api-and-audit)). A backup archives:

- the instance's **Docker volumes** (using helper containers, never starting
  them, with the owner uid/gid preserved)
- its state, settings, `.env`, custom override and sign-in template pick

Backups are stored in `<data>/backups/<instance-id>/<YYYYMMDDTHHMMSSZ>.tar`
(sha256-checksummed). Core's `./portcullis backup` includes the `backups/`
directory, so `--offsite` ships instance backups too.

**To back up an instance**:

1. Open the instance detail (or the template detail for the default instance)
2. Go to the **Backups** tab
3. Click **Back up now**

A running instance is **stopped** (`docker compose down`) during the backup for
database consistency, then started again. The backup is listed with its timestamp,
size and result. A failed backup shows the error.

Backups, restores and deletes run in the background with a
[progress panel](#progress-and-stop): the Hub accepts the request at once and
the panel follows the operation step by step until it finishes, then shows its
result and warnings (also under **Last operation**). Closing the panel doesn't
stop it (**Stop** does); another operation on the same instance is refused
(busy) until it ends. On shutdown the Hub waits up to about 50 s for a running
operation; one it couldn't finish is shown as "interrupted" at the next start,
with Stop to clean it up. A running operation never shows as a failure.

**Stop** during a backup deletes the partial archive and starts the instance
again if it was running.

**Free space**: a backup needs at least 64 MiB free on the Hub's data volume
before it starts, and the copied size plus 64 MiB before the archive is
assembled; staging an archive for a restore needs its size plus 64 MiB.
Otherwise the operation fails with HTTP 507 (no archive is written, and an
instance stopped for a manual backup is started again).

### Restoring an instance

**Admin-only.** A backup can be restored into the same instance (replacing its
data and settings) or into a **new instance id** (creating a copy).

**Same instance**:

1. Go to **Backups** tab
2. Click **Restore** on a backup row
3. Confirm

The Hub:

1. Takes a **pre-restore backup** of the current state
2. Marks the instance `restoring` (while in this state, enable / settings / other
   operations are refused with HTTP 409)
3. Removes the instance's volumes and recreates them from the archive
4. Restores env, override and settings (hostnames are kept)
5. Clears `restoring` or, if any step failed, rolls back from the pre-restore
   backup

While `restoring`, if the Hub or the process crashes, the next `Init` or
`RestoreInstance` call **rolls back** from the pre-restore backup automatically.
**Stop** during a restore rolls back from the pre-restore backup the same way
(before that backup was taken, nothing has changed yet); during a restore as
new it removes the new instance completely.
A failed restore leaves an `OpError` with `op: restore` and `rolled_back: true`.

**New instance**:

1. Go to **Backups** tab
2. Click **Restore as new** on a backup row
3. Enter a new instance id
4. Confirm

The Hub:

- creates the new instance with the hostnames given in the request (the API's
  optional `hosts`); otherwise each
  `hosts.immutable` router keeps the archive's hostname and every other router
  gets the **new id's default hostname on the main domain** (change them
  afterwards on the **Overview** tab). The hostnames are validated like a new
  instance's
- shows it as `restoring` while it runs and `created` (not started) when it is
  done — **enable it by hand** afterwards (instance detail → **Enable**: the
  restored copy never starts on its own, so you can check its hostnames and
  settings first, and add members to its new, empty groups); a restore the Hub didn't finish (it stopped half-way) is removed at the
  next Hub start (its groups may remain, logged)
- creates new volumes (labelled with the new project) and fills them from the
  archive; restores the archive's settings, sign-in template pick, public exceptions and share
  tokens, sign-in mode, custom override and env, with the instance variables
  rewritten for the new id
- regenerates each Keycloak client's secret (`secret_env`)
- creates the groups `users_<new-id>` / `admin_<new-id>` as empty manual groups
  (an existing group of that name is kept, with a warning)
- creates its Keycloak clients only when it is first enabled, as for any
  instance

`type: path` settings keep the same host path: the result warns that both
instances now share that directory.

Immutable-host routers: the Hub refuses (409) a `hosts.immutable` router given a
different hostname than the archived one (you can't
restore a Matrix instance with a different homeserver domain).

Both forms are audited as `instance.restore` with the acting administrator and
the archive path.

### Deleting an instance

**Admin-only, guarded.** Deleting an instance:

1. Takes an automatic backup (stored in `backups/<id>/`)
2. Marks the instance `deleting` (other operations refused with HTTP 409)
3. Runs `docker compose down`, then removes the per-person passwords, the AI
   credentials and the volumes. The first volume removal is the **point of no
   return**: until then **Stop** cancels the delete and puts the app back as
   it was (enabled again if it was enabled; the delete's backup stays listed);
   from then on the delete finishes ("past the point of no return —
   finishing")
4. Removes the Keycloak clients (only those owned by this instance), the access
   role (if any), and extra-domain sign-in callback URIs for this instance's hosts
5. Deletes the groups named exactly `users_<id>` / `admin_<id>`, through the
   Users & Groups guardrails, **only if they are not shared** with another
   instance or template and are not built-in, administrator, permission or
   rule groups (others are kept, with a warning)
6. Removes env, override, settings, ops records and the state entry

**To delete**:

1. Open the instance detail
2. Click **Delete instance**
3. Type the instance id to confirm
4. Click **Delete**

The operation is audited as `instance.delete`. If any step fails after the
backup, the instance stays in `state: deleting` and the error is shown; a retry
continues from where it left off (it does not take another backup).

The automatic backup is listed in the **All backups** list (Apps → All backups) with a
`reason: delete` label. The Hub shows the backup path and warnings (e.g., if
some groups were kept because they're shared, or if no IdP is configured so
client deletion was skipped).

Deleting the default instance deletes the template's deployment, just like
disabling it did before instances existed.
## Settings tab (global)

- **Sign-in** ([Sign-in methods and templates](auth-policies.md)):
    - **Methods**: the six sign-in methods, each with its strength, how many
      people have it set up, and an on / off switch. Password and browser
      certificate start off.
      Switching off a method an enabled template needs is refused and lists the
      templates and their uses.
    - **Templates**: the built-in Basic, Standard, Strong and YubiKey +
      certificate, and your own (**+ New template**), each with its score
      (`2.9 / 5` and a one-line reason), its enabled switch and what uses it.
      The editor shows the rule as nested boxes and one sentence, the score
      and who it would leave out, all live; built-ins can be edited and
      disabled, never deleted.
    - **Default template** (Standard at the start) and **Core pages** (the
      portal, the Hub, people.&lt;domain&gt;, directory, metrics,
      Traefik; the Hub and people start on Strong).
    - **Add a stronger method from a weaker sign-in** (off at the start).
    - **Limits** ([Sign-in methods → Limits](auth-policies.md#limits)): the
      browser certificate lifetime (30 days at the start; 1 day up to the
      ceiling, core's `CLIENT_CERT_TTL` in whole days, which the form shows),
      the active browser certificates per person (3; 1–20) and how long
      sign-in history is kept (365 days; 30–3650). A stored lifetime above the
      ceiling applies as the ceiling, with a warning. Saved with
      `PUT /api/signin/limits`, audited `signin.limits`; raising a
      certificate limit or shortening the history asks for confirmation from
      AI tools (`set_sign_in_limits`).
    - **Signing in as someone else** ([Sign-in methods → Signing in as
      someone else](auth-policies.md#signing-in-as-someone-else)): the
      switch (on at the start; `PUT /api/signin/impersonation`, audited
      `signin.impersonation`) and the running list, each line with who,
      whom, the reason, the time left and **Stop**. Switching it off asks
      for confirmation naming the running ones, and ends them all. AI tools
      may switch it off (`turn_off_impersonation`), never on.
    - A warning when the FIDO metadata list is out of date, and "No
      administrator can meet the Hub's template" when that is the case.

    A save that would leave no administrator able to meet the Hub's template
    is refused (recovery: [`./portcullis signin reset-core`](cli.md#signin-reset-core)).
    A change that would switch AI support off somewhere (a template that
    needs a certificate in every alternative) first asks, listing the
    instances. Changing a certificate method or a template restarts only the
    apps whose certificate request changes.

**VPN** ([VPN-only access](vpn.md#settings-vpn)): the mode and public
enrolment (read-only, set on the host with `./portcullis vpn mode`), the VPN
service up or down, the built-in VPN's subnet, port and devices (or off),
instances stopped because a narrowing failed, the **VPN users group**
(empty: every person), **Devices per person** (10; 1–100) and **Device
expiry** (`30d`, `90d`, `1y`, `never`), and every provider with its source,
whether it is wired, its ranges, devices and map state, each linking to its
VPN tab. Saved with `PUT /api/vpn/settings`, audited `vpn.settings` (no AI
tool).

The tab also has **AI support** (the master switch, AI clients, the
Portcullis MCP, connection length, rate limits, allowed origins and the model
providers: [AI support → Settings → AI](ai.md#settings-ai)),
**Domains** ([Adding extra domains](#adding-extra-domains)),
**Shared folders** ([below](#shared-folders)) and **Local networks**
([below](#local-networks)).

People and groups are managed on the people page: see [Users & Groups](#users-groups).

## Shared folders

A **shared folder** is a host directory you define once in the Hub (a name
and a path) and then give to the apps that use it: say `/srv/media` for
Jellyfin, Plex and Immich, or one photo library that a writer app fills and
a viewer app reads. The Hub keeps the folder's ownership consistent so
every app can do what it needs, whatever uid it runs as and whatever umask
it creates files with:

- the folder gets its **own group** (a gid; the Hub never creates a host
  group name, an LLDAP group or a group inside a container);
- every directory is group-writable and **setgid**, so new files land in
  the folder's group;
- every directory gets a **default ACL**, so new files are group-writable
  even when the app's umask is `022`, and open to nobody else;
- apps that **write** get group read/write; apps that only **read** are
  always mounted read-only.

Nothing on disk changes except through a preview you applied, and every
apply first saves a permissions snapshot that **Undo last fix** can put
back. Find it under **Settings → Shared folders** (admins only; it needs
Users & Groups). The rules behind it are in
[Integration Contracts §14](../guides/integration-contracts.md#14-shared-folders-and-the-doctor).

### Defining a folder

**Add shared folder** asks for:

- **Name** (shown everywhere) and an **id** (lowercase letters, digits and
  dashes, at most 31 characters; filled in from the name, and never changes).
- **Host path.** It must be strictly under one of the Hub's bind roots
  (`HUB_OVERRIDE_BIND_ROOTS`, default `/srv:/mnt:/media`) and may not be:
    - a system or sensitive path (`/etc`, `/proc`, Docker's own storage, …),
      the core checkout, the settings data files' directory, or at, above or
      under Docker's data root;
    - at, above or under another shared folder. The comparison also ignores
      case and Unicode normalisation, so `/srv/Photos` and `/srv/photos`
      collide; a path that is the same directory as another folder's (one
      tree reached through a host bind mount or another spelling) is refused
      too;
    - a path with a symlink in it (give the real path), `..`, `:`, `$`,
      control characters, invisible characters or a component that starts or
      ends with a space;
    - on a network, virtual or in-memory filesystem (NFS, SMB/CIFS, FUSE
      including virtiofs, overlay, tmpfs, 9p such as WSL's `/mnt/c`, Ceph,
      ramfs, eCryptfs). The Hub can't keep ownership consistent where a
      server or another layer decides it. Fixes are written only on ext4,
      XFS, Btrfs and ZFS: a folder on another local filesystem (vfat, exFAT,
      NTFS) can be checked, never applied.
- **Check path** probes the path and scans it (at most 30 seconds) and
  answers in one line, for example
  `exists · ext4 · ACLs and xattrs supported · 12,410 files · owners 1000:1000 (all)`,
  plus any problems in plain words. A missing path offers **Create it**: an
  empty directory, nothing else.
- **Description** (optional).
- **Advanced → Adopt an existing host group.** Normally the Hub allocates
  the folder a gid from **60000–60999**, the lowest free one; a gid is never
  reused, even after the folder is deleted. To keep a group your host
  already uses, type its number: at least 1000, not 65534, outside
  60000–60999, and not 10001 or 10002 (the Hub's and enroll's). Anything
  else mounted with that gid becomes reachable by the folder's apps, and the
  Hub says so.
- **Used by**: every app instance with a path setting. Tick the ones that
  use this folder and optionally give a **subfolder** (`movies`, created by
  the apply when missing). An app whose template doesn't declare how it
  uses folders is mounted **read-only unless you tick "allow writing"**.

Saving the definition changes nothing on disk or in any app. If the **Used
by** ticks changed, Save opens the assignment preview below.

The folder table shows each folder's path, gid, the apps using it
(read-only or read/write), its last check and last operation, with
**Edit**, **Undo last fix…** (when there is something to undo) and
**Remove**. You can rename a folder or change its description at any time;
its path only while no app uses it. **Remove** asks you to type the id, is
refused while any app uses the folder, and never touches the files.

### Assigning apps (preview and apply)

Assigning, changing or removing apps is one operation with a preview. The
preview changes nothing; it says, for example:

> gid 60001 is allocated for this folder (shown as *Family photos*). 12,410
> files and 312 folders change group 1000 → 60001; group 1000 keeps
> read/write through an ACL. … Immich mounts it read-only. Samba and Immich
> are stopped for about 1 minute, then started. A permissions snapshot is
> saved first.

and lists each app's setting with its subfolder, access and whether it is
added, kept or removed, plus warnings (hard links, nested mount points and
other entries the fix leaves alone). **Apply** then:

1. stops the affected apps that are running (enabled-but-stopped ones are
   only regenerated);
2. saves the permissions snapshot, applies the ownership and verifies it
   ("verified: 0 entries differ");
3. points the apps' settings at the folder (`folder:<id>` or
   `folder:<id>/<subfolder>`), starts the apps again and runs their
   settings delivery.

Nobody loses access they had: groups and owners that had rights keep them
through ACL entries, and "others" bits are never changed. Some entries are
never touched and are reported instead: hard-linked files, other mounts,
devices, setuid/setgid files and files with file capabilities.

If anything fails before the settings are saved, the apps start again with
their old configuration and the error names the snapshot (Undo is offered
if the disk changed). If the setup changed between the preview and Apply,
Apply answers "the setup changed since the preview": preview again.

While an apply runs, the affected apps are marked busy: their settings,
Expert pages, hostnames and backups answer "shared folder <name> is being
applied". The preview estimates the downtime from the number of entries
(about 5,000 a second for each of its three passes).

!!! note "Very large folders and queued restarts"
    A restart queued for an app (by a settings save, for example) waits
    for the app's operation for at most 20 minutes. An apply of a folder
    with millions of entries can take longer; a restart that gives up stays
    owed and runs at the next Hub start (the app's last operation shows
    `restart`, failed). The apply's own start of the app already uses the
    new configuration, so normally nothing is lost.

**In an app's settings panel**, a path setting has a picker: **Custom
path** or **Shared folder: <name>**. Choosing a folder, or going back to a
custom path, opens the same preview: it never goes through the panel's
**Save**. A setting on a shared folder shows the folder and its host path,
with **Change subfolder…**.

**Moving a setting to another folder takes two steps:** remove it from the
first folder (pick **Custom path**, or untick it there), then assign it to
the second. The Hub refuses a setting that is still on another folder
("unassign it from <name> first").

Other refusals you may see in the preview:

- two settings of one app's service that would need different primary
  groups: "point both settings at the same shared folder" (Plex: keep its
  three libraries on one folder);
- two apps that must own what they write on the same folder;
- a change that would remove someone's access on a filesystem without ACLs
  (explain-only).

### Undo last fix

**Undo last fix…** (in the folder table, and on the doctor's drift finding)
puts back the permissions the last apply changed, from its snapshot. Its
preview says how many entries go back and how many **changed since the
fix** and are left alone, so an undo never takes away access granted
since. It stops and starts the apps like an apply; the settings stay
pointed at the folder. An undo **can't be undone**: it saves a safety copy
of what it rewrote, but offers no undo of itself.

## File Sharing

File-sharing apps (Samba, Time Machine) have a **File sharing** tab in
their instance's detail view on `hub.<domain>`. It is for admins only, one
instance at a time. People create their own file-share passwords on
[My apps](#my-apps). Admins list and revoke passwords, but never create
them: an admin who created one would have seen it. The Hub keeps only
each password's NT hash on the `hub_secrets` volume. See
[File Sharing](file-sharing.md) for setup.

For each file-share password option of the instance, the tab shows:

- **People with access** (the instance's access group, `users_<id>`) and
  how many of them have a password.
- **One row per person:**
    - **Person:** their username.
    - **Ids:** their Hub uid (`uid`). My apps never shows it.
    - **Values:** their person-scope values, such as Time Machine's size
      limit.
    - **Password:** one of these statuses:
        - **no password** (`none`): they never created one.
        - **password since <date>** (`active`): it works.
        - **reset by a restore on <date>** (`voided`): a restore voided it
          (see [Restores](file-sharing.md#restores)), and they have no
          password until they create a new one.
        - **revoked (<reason>) on <date>** (`revoked`). The reason is one
          of: by the person, by an administrator, left the app, or account
          deleted.
        - **unavailable** (`unavailable`): the app can't serve their
          username (the template's username rule), so they get no button
          on My apps.
    - **Revoke**, on active rows only. Revoke asks for a confirmation,
      then deletes the hash and ends the person's sessions. Revoking takes
      a few seconds and can take up to about 30 seconds. It is audited as
      `credential.revoke` with you as the actor. The person must create a
      new password to connect again.
- **Former members' folders:** top-level folders in the per-person tree
  (Samba's home folders, Time Machine's storage) owned by an account that
  is gone, with their uid and size. They are kept on disk and never
  served.
- **Last sync:** the app's last `sync` hook run (ok, skipped or failed,
  with its time). Sizes come from the hook's last report.

A banner at the top links to the [Doctor](#doctor) card when the app's
SMB port is reachable from outside your Local networks
(`lan_only_exposed`). From there you can rebind the port.

**Revocation happens on its own.** A person who leaves the access group,
or whose account is deleted, loses their password at once when the
change is made in the Hub. A change made directly in LLDAP is caught
within about a minute. Leaving a share's reader or writer group drops
that share only, and keeps the password. See
[Managing people](file-sharing.md#managing-people).

**Restores.** An instance restore voids that instance's passwords only.
A core restore (`./portcullis restore`) empties `hub_secrets` and voids
every password of every instance.

**The `hub_secrets` volume** must be owned by `10001:10001` with mode
`0700`. Core sets this on every `./portcullis init`, `up`, `upgrade` and
`restore`, so you never change it by hand, and the doctor offers no fix
for it. If the Hub finds the volume wrong at start, the credential routes
answer `503` and file-sharing apps refuse to start, naming the reason. To
fix it, run `./portcullis up` (which sets the owner and mode again), then
restart the Hub container: the Hub checks the volume only at start.

The doctor's file-sharing findings
([contracts §14.5](../guides/integration-contracts.md#145-the-doctor)) are:

- a password whose holder should have been revoked (one-click revoke);
- a former account's folder (explain-only);
- a per-person folder with the wrong group or mode (one-click fix);
- an account the Hub can't verify (no LLDAP uuid);
- Local networks saved empty;
- a share slot served to nobody;
- a refused share name or username, as reported by the app.

## Doctor

The **Doctor** tab checks the whole setup, including folders and paths you
set up by hand, and lists findings as **Problems** (broken or unsafe now),
**Warnings** (likely to break, or weaker than intended) and **Info**. The
tab's badge counts Problems and Warnings, and each instance page shows
a "Doctor: 1 problem, 2 warnings" line linking to the tab.

Each finding says what is wrong, why it matters, which apps, folders and
paths it concerns, and what a fix would do. Its buttons:

- a **one-click fix** with a preview and Apply: **Manage as shared
  folder…** (two apps using one hand-typed path), **Apply again…** (a folder
  that drifted), **Undo last fix…**, **Rebind…** (a LAN-only port, below);
- **Explain**: the steps to do by hand, for anything risky (moving data,
  nested paths, custom-override mounts, hard links, host networking);
- **Open setting**: the app's settings panel at the option;
- **Mute** with a reason. A muted finding moves to **Muted** and comes back
  by itself as soon as what it judged changes.

The doctor never changes anything by itself. The cheap checks (settings,
templates, ports, groups) run every time you open the tab. The **disk
checks** scan the folders and the shared hand-typed paths: daily, after
every apply, and when you click **Run disk checks**. A scan stops after
2,000,000 entries or 10 minutes; its findings then say "(partial scan …)".

What it finds includes: two apps using the same hand-typed path, a folder
that drifted since the last apply, an app that can't write or read where it
must, a path outside the bind roots, a template that doesn't say how it
uses folders, a folder that changed on disk under a running app, an app
container that holds a shared folder's gid without being assigned it,
missing ACL support, too little free space or the wrong filesystem for an
app's declared checks, per-person settings with no group values, and
LAN-only ports reachable from outside.

### DNS checks

The doctor also judges the [DNS plans](#the-dns-panel) of every added domain
and of the main domain (the cached plans). When the domains service can't be read there are no DNS
findings; when a lookup failed the findings it could judge still show. Either
way the Doctor tab says "DNS checks didn't run" (the report's
`dns_unavailable`). A plan that is only missing the server's addresses (no
domain added yet, no `PORTCULLIS_PUBLIC_IPV4`) or a DNSSEC state `insecure`
doesn't count: nothing failed.

| Kind | Severity | Finds | Fix |
|------|----------|-------|-----|
| `dns_records_wrong` | Problem | An A/AAAA record missing or wrong, or a CNAME at the name or its wildcard | One click: apply the `address` set; explain-only (remove the CNAME) while a CNAME is there |
| `dns_caa_missing` | Warning | No CAA where Portcullis wants one | One click: apply the `caa` set |
| `dns_caa_wrong_account` | Problem | The CA wouldn't issue: the live pin names another ACME account | One click: apply the `caa` set |
| `dns_caa_other_issuers` | Info | Other CAs may also issue for the name | — |
| `dnssec_bogus` | Problem | DNSSEC `bogus` or `ds_mismatch`: validating resolvers can't reach the name | Explain: fix or remove the DS at the registrar |
| `dnssec_ds_missing` | Warning | Signed, but no DS at the parent | Explain, with the DS values |
| `dnssec_unsigned` | Info | The zone isn't signed | One click: turn on signing (Cloudflare; the preview names the whole zone), else explain |
| `dns_dangling` | Warning | A CNAME under the name to a name that doesn't exist | Explain: remove it |
| `dns_shadowed` | Info | An address under the name that isn't the server's: that name doesn't reach Portcullis | — |
| `dns_nomail_recommended` | Info | The name sends no mail but has no null MX / SPF / DMARC | One click: apply the `nomail` set |

The one-click DNS fixes preview the records they change (`<set> <name>
<type>: <live> → <want>`, or "turns on signing for the whole zone
<zone>") and refuse with "the DNS records changed since the preview" when
the live records moved. They run in the background and are audited like the
DNS panel's buttons. For the **main domain** every DNS finding is
explain-only: "Run `./portcullis dns setup` on the server" (for
`dnssec_unsigned`: "Run `./portcullis dns setup --dnssec` on the server
(Cloudflare only)").

### Rootless Podman checks

Under [rootless Podman](rootless-podman.md) the doctor adds five checks. They
never fire under Docker, and none has a one-click fix:

| Kind | Severity | Finds | Fix |
|------|----------|-------|-----|
| `runtime_mismatch` | Problem | The engine isn't the runtime core said (`HUB_CONTAINER_RUNTIME`): every engine operation answers `503` | Explain: fix `.env` or `DOCKER_HOST`, then restart the Hub (`./portcullis up`) |
| `limits_not_enforced` | Warning | An app container runs without the memory or process limit its compose sets | Explain: delegate the `memory` and `pids` cgroup controllers to the operator's user manager |
| `unmapped_owner` | Warning | A shared folder has entries owned by a host account outside the operator's id range (they read as 65534); the fixer refuses that folder | Explain: `sudo chown -R '<uid>:<gid>' '<path>'` once, then re-check |
| `selinux_label_missing` | Warning | On an SELinux host, a shared folder without the `container_file_t` label (or a scan that got `permission denied`) | Explain: the path regex-escaped in `semanage fcontext -a -t container_file_t '<path>(/.*)?'` and `restorecon -R '<path>'`, as root |
| `udp_source_rewritten` | Info | An app publishes a UDP port: its clients appear with a rewritten source address | — |

### VPN checks

With the [VPN](vpn.md) the doctor adds eighteen checks. All are explain-only,
and none fires without the VPN service, a provider or a mode other than
`apps`:

| Kind | Severity | Finds |
|------|----------|-------|
| `vpn_down` | Problem | VPN-only apps, or a mode other than `apps`, while `wg` is down (its `status.json` missing or stale). Fix on the server: `./portcullis up`, then `./portcullis status` |
| `vpn_provider_stale` | Problem | A wired provider's device list is stale, or its gateway is down; shows the hook's last error |
| `vpn_provider_invalid` | Problem for duplicate addresses, else Info | Devices left out as duplicates, outside the ranges, or with owners that aren't Portcullis people |
| `vpn_range_overlap` | Warning (Local networks), Problem (a Docker network) | A provider range overlaps them |
| `vpn_via_dead` | Problem | A VPN-only instance's *Through* names only unwired or stale providers |
| `vpn_no_providers` | Warning | A VPN-only instance with no provider at all: it is unreachable |
| `vpn_dns_failed` | Problem | A provider's DNS hook failed: the names resolve publicly |
| `vpn_dns_manual` | Info | A `dns: manual` provider, until you acknowledge its records |
| `vpn_gateway_privileged` | Info | A wired gateway, or a service in its network namespace, has `NET_ADMIN`, `privileged` or host devices |
| `vpn_static_mapping` | Info | A `source: static` provider is wired: its devices are assigned by an admin, not proven |
| `vpn_single_provider` | Warning | Mode `admin` or `server` with one provider; add the built-in VPN as a second path |
| `vpn_public_links` | Warning | An instance's public links stay on the internet |
| `vpn_no_admin_device` | Problem | Mode `admin` or `server`, and no administrator's device seen in 30 days on a provider that isn't static |
| `vpn_device_stale` | Info | A built-in device with no handshake in 90 days (links to the person's *VPN devices*) |
| `vpn_expiring` | Info | A built-in device expiring within 14 days, shown to its owner |
| `vpn_publish_failed` | Problem | The Hub couldn't write `vpn.json`: every VPN request is denied once its `valid_until` passes |
| `vpn_reserved_defaults` | Warning | `core.env` lacks `PORTCULLIS_VPN_RESERVED_RANGES`, so the Hub uses the default reserved ranges |
| `vpn_reach_failed_closed` | Problem | A narrowing render failed, so the Hub stopped the instance; clears after the next successful render |

## Rootless Podman

When core runs on [rootless Podman](rootless-podman.md) the Hub knows it from
`HUB_CONTAINER_RUNTIME` (set by core's compose) and checks it at start
against the engine's version answer. Until the engine has answered, and for
good if it names the other runtime, every engine operation answers `503`
"the container engine is not verified". Restart the Hub against the right
engine to clear a mismatch.

- **Badges.** The Marketplace card shows **Rootless: works**, **limited** or
  **not available**, with the reasons in its tooltip; the instance page lists
  the reasons. An instance's badge uses its own ports, devices and env.
  Under Docker nothing is shown.
- **Refusals.** Creating, restoring into a new id, enabling or restarting an
  app that is not available is refused before anything starts:
  `<id> can't run under rootless Podman: <reasons>`. Limited apps run.
- **Shared folders.** The fixer runs under Podman's mapping, and its
  reports show host ids next to container ids. A folder with entries owned
  by a host account outside the operator's id range is refused for that
  folder, with the `sudo chown -R` step ([Doctor](#rootless-podman-checks)).
- **SELinux.** On an SELinux host the Hub labels the template files it
  mounts into apps (`z`). It never relabels shared folders.
- **`GET /api/runtime`** (admins, Hub listener; the admin MCP tool
  `get_runtime`) answers the runtime, whether it is verified, the engine's
  name and version, a mismatch's text, whether the engine is rootless and
  has SELinux, the Hub's own id maps and the host's
  `ip_unprivileged_port_start` (the maps and the port are `null` under
  Docker). See [contract §11.10](../guides/integration-contracts.md#1110-runtime-compatibility-new-rootless-kubernetes).

## Local networks

**Settings → Local networks** lists the networks that count as local: one
CIDR per line, at most 64. The defaults are `10.0.0.0/8`,
`172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7` and `100.64.0.0/10`
(private ranges, IPv6 unique-local and the tailnet). Loopback always counts.
An empty list means only loopback; **Reset to defaults** goes back to the
defaults. The panel warns about a range broader than **/8** (IPv4) or
**/64** (IPv6): a large share of the internet, or more than one site, would
count as local.

The doctor uses the list to judge ports a template marks **LAN only**
(Samba, for example):

- bound to all interfaces (`0.0.0.0`, the default) → Warning;
- bound to an address outside the local networks, or one your main
  domain's DNS records point at → Problem.

Both offer **Rebind…**: type the address to bind to (an IP inside the
local networks, not `0.0.0.0` or `::` and not one your main domain points
at; usually the host's LAN address, for example `192.168.1.10`); the Hub writes the port's bind address and restarts the
app (putting the old bind back if the restart fails). A port added through
a custom override is explain-only (edit the override). A LAN-only port of
an app on the **host network** is always a Problem and explain-only: Docker
publishes nothing for it, so the bind address has no effect; restrict it in
the app's own listen address and in your router or host firewall. See
[Security & Hardening](hardening.md#lan-only-ports-and-host-firewalls) for
why a host firewall such as ufw doesn't help with published ports.

## Audit log

The Hub's **Audit log** tab shows the audit log of the whole Hub: people and
groups, app settings, instances, folders, the doctor, AI. Every change,
including refused and failed attempts, is appended to `audit.jsonl` in
`$HUB_DATA_DIR` (mode 0600). Each entry records the time, actor
(`X-Forwarded-User`), action, target, optional detail, result (`ok` /
`refused` / `error`) and optional error. The log never contains passwords,
tokens or invite links.

The tab shows the newest 100 entries, with **Refresh** and a **Show** filter:

- **all changes**;
- **changes made via AI**: only those made through the Portcullis MCP
  (`?via=ai`), each with a "via AI" pill and the AI client;
- **via AI, with the AI requests (access log)**: those merged with the
  newest 100 lines of the gate's access log (`?via=ai&include=access`): who,
  through which client, what (the tool or method), on which resource, and the
  gate's decision. If the access log can't be read, the tab says so and
  shows the changes made via AI alone.

The log lives only on the Hub: the people page has no audit view of its
own. On it, administrators see a group's entries in the group page's
[History](groups.md#history) and a person's on their
[page](#a-persons-page). `GET /api/directory/audit` (with `via`, `include`,
`group` and `user` filters, [contract §9.7](../guides/integration-contracts.md#97-http-api-for-groups-and-users-new-people-groups))
answers administrators only, on both listeners (403 for everyone else).

## Users & Groups

People and groups live in **one place**: the people page,
`https://people.<domain>/`. The Hub page and the people page share one top
navigation: **Portal** (`https://<domain>/`), **Hub** (`https://hub.<domain>/`,
shown to administrators only) and **People** (`https://people.<domain>/`), with
the current site highlighted; each page's own tabs sit below it. The Hub has no
Users & Groups tab any more: use **People** in the navigation (old `#users…`
links still redirect, see below). Administrators get every admin operation on
the people page (see [Access levels](#access-levels)); the Hub itself keeps only
the [Audit log](#audit-log) tab, which covers the whole Hub.

Every field that takes a person or a group (a group's **Add people**, a
person's **Add to group…**, person fields, rule values, CSV import cells, the
settings panel's group rows and group / people lists, the AI tab's **Revoke
for**) suggests matches as you type: by username, display name or email for
people, by name for groups, at most 8, with ↑ / ↓, Enter and Esc. It only
suggests people and groups you can already see on the people page.

LLDAP has no single sign-on, so its own web UI isn't published:
`directory.<domain>` redirects to `people.<domain>`, and the LLDAP UI is
reachable only from the server for recovery
([`portcullis lldap-ui`](cli.md#lldap-ui)). The Hub uses its own LLDAP service
account, `portcullis-hub`, which core creates and mounts as files (see
[Integration Contracts §9](../guides/integration-contracts.md#9-hub-lldap-users-groups)).
Nobody can use it, so it is never listed: not among people, in the org chart,
in group members or in any suggestion. **Setup** names it in one line ("Service
account: portcullis-hub — used by the Hub to manage users and groups; it can't
sign in."). If core doesn't provide it, the people page says user management
is disabled and everything else keeps working.

**The built-in `admin` account** (LLDAP's bootstrap admin) manages Portcullis
(apps, people, settings) but can't be added to any group, so it can't use the
apps it installs. Its person page says so and its **Add to group…** is
disabled; it is never suggested where an instance's people are picked (**Revoke
for**, the settings panel's people lists). Signed in to the Hub as `admin`, the
Apps page shows "You're signed in as the built-in admin, which can't use
apps. Invite yourself as a person to use them." (linking to the invite form on
the people page), and enabling an instance adds "admin can't open it — invite
yourself to use it". To use apps, invite yourself as a regular person and add
that account to the instances' groups.

The people page has the tabs **People**, **Groups**, **Org chart**, **My
apps** (each person's own app settings, see [My apps](#my-apps)) and
**Setup** (admins only). Its views are links you can bookmark and share:

| Link | Opens |
|------|-------|
| `people.<domain>/#groups` | the groups list |
| `people.<domain>/#groups/<group>` | a [group's page](groups.md#group-pages), the only place membership changes |
| `people.<domain>/#people/<name>` | a [person's page](#a-persons-page) (any spelling of the username: `#people/Carol` opens `carol`) |
| `people.<domain>/#invite?username=&email=&display_name=&groups=` | the invite form, pre-filled (`groups` ticks only groups the directory reports as not guarding — never an administrator, permission, app admin or privileged-value group — and only for an admin) |

**Old Hub links keep working.** `hub.<domain>` sends them to the people page
(same tab, replacing the Hub's entry in the history):

| Old link on `hub.<domain>` | Lands on `people.<domain>` |
|----------------------------|----------------------------|
| `#users` | the People list |
| `#users/<name>` | `#people/<name>`, the person's page |
| `#users/<name>?password`, `#users/<name>?invite` | the person's page, then the password fallback's or the invite's prompt |
| `#users?create&<query>` | `#invite?<query>`, the invite form pre-filled |
| `#groups`, `#groups/<group>`, `#people/<name>` | the same view |

The Portcullis MCP's person forms (`create_person`, `send_invite`,
`set_password`, the invite note of `remove_passkeys`) link to the people page
in the same forms.

### Group names link to their pages

Every group name the Hub shows links to that group's page on the people
page (`https://people.<main domain>/`, from the configured domain whatever
address the Hub was opened at): the access and admin group of an instance
(Overview, the Sign-in section, the Delete summary), a model provider's
**Used by** (Settings → AI) and the names in the Apps page's
[Missing groups](#missing-groups) banner open in the same tab; the settings
panel's — the rows of [Who gets what](#who-gets-what) ("from office_milan",
"largest of …", "combined from …"), its "N members of office_milan have no
access" warnings and a privileged option's refused groups — always open in
a new tab, so following one never drops an unsaved draft. On the people page, every group a
person page or the Used by panel names links to its page too, including each
group of a combined value's "from".

### Access levels

- **Admins** (members of `lldap_admin`) see and can change everything.
- **Everyone else** (any signed-in user) can view all people, groups, fields and the org chart, with three **delegated permissions** (granted per group by admins):
    - **edit details**: edit custom field values of non-protected accounts (single edits and CSV import)
    - **invite**: create new accounts with no groups (invite links only)
    - **remove**: delete accounts

Core lets any signed-in user reach `people.<domain>`; the Hub's own `lldap_admin` check (re-checked on every change) is the gate for admin operations there.

Delegates cannot target themselves, administrators, the protected accounts (`admin`, `portcullis-hub`), or members of any permission group. Delegates cannot touch manual groups, added-by-hand or kept-out entries, or end dates; they can fill in fields that make people match rule-based groups. They see group members read-only, without the entries' reasons, the Used by panel or History. See [Delegated permissions](#delegated-permissions).

### People

The **People** table shows every LLDAP user, with the custom field columns, groups (⚡ = matches the rule, ✱ = added by hand, ⏳ = the membership ends), Keycloak status (passkey count, required actions; admins only) and a search box. Clicking a row opens the person's page.

**Invite** (admins and delegates with the `invite` permission): creates a new user. Username (lowercase letters, digits, `.`, `_`, `-`; at least 2 characters), email, display name and groups (admins only). The user gets a **one-time invite link** (shown once, expires in 72 h): they register their passkey and are signed in, no password. Administrators get no invite links; the Hub shows `./portcullis invite <user>` (server only). Under **Advanced**, admins can use a password fallback instead (generated or typed; 12 to 128 characters, not the username, not a common password; refused while the [password method](auth-policies.md#password) is off).

The groups pick lists rule-based groups too. A ticked rule-based group shows its rule and either "they match the rule: nothing else needed" or, when the new person won't match it, a required **Reason**: they join it as [added by hand](groups.md#added-by-hand-and-kept-out). After the invite the new person's page opens; if the groups couldn't be applied yet (LLDAP down), it says "saved, not applied yet: …". A delegate's new account has no groups; filling in fields can make it match rule-based groups.

**Import CSV** (admins and delegates with any permission): see [CSV import](#csv-import).

### A person's page

`#people/<name>`: everything about one person, for everyone who can see
people (admins see all of it; others the parts their permissions allow).

- **Header**: display name, username, email, custom fields (a person field
  links to that person's page), "since … · account created by …", and
  **Edit details** (admins; delegates with `edit_details` for the accounts
  they may edit).
- **Groups**: one row per group, linking to the group's page, with how they
  are in it: matches the rule, added by hand · until … · "reason", kept out ·
  "reason", member · until. **Add to group…** (admins) picks a group (rule-based
  ones too) and opens that group's page with the person already picked in
  **Add people**, where the end and the reason are set. Membership is never
  changed on the person's page itself.
- **Apps** (admins): the apps they reach and through which groups (with
  "until …" when that membership ends), each app linking to its settings on
  the Hub and each group to its page.
- **Values** (admins): their value of each app's per-person settings, with
  where it comes from ("from office_milan", a combined value's groups,
  "default", "fail-closed", "own entry"), each linking to the setting on the
  Hub.
- **Sign-in** (admins, and holders of `sign_in_help` for the people they may
  help): the person's [Sign-in page](auth-policies.md#the-sign-in-page) as
  they see it — each method with its state, their passkeys (name and model,
  read-only: only the person renames them), their YubiKey and
  browser certificates (valid, expiring, expired or revoked), the apps and
  what they need, and their [sign-in history](auth-policies.md#sign-in-history)
  — with only the actions the caller may take: **Send setup link**, **Remove
  passkeys**, **Revoke** per certificate, and for admins **Password…** and
  **Issue YubiKey certificate** (paste a CSR made with `ykman`, then a fresh
  sign-in). Administrators' certificates show no Revoke or Issue: they are
  managed from the server (`./portcullis cert revoke <serial>`,
  `./portcullis cert enroll`).
  For admins the tab also has **Sign in as &lt;person&gt;…**: type a reason,
  do a fresh sign-in with a YubiKey touch, and the browser opens the
  person's portal signed in as them ([Signing in as someone
  else](auth-policies.md#signing-in-as-someone-else)). When it can't be
  offered the tab says why (an administrator, the switch off, an
  unfinished setup link, …). While someone is signed in as the person the
  tab shows "root is signed in as alice since 14:02 UTC · reason · 26 min
  left · **Stop**".
- **History** (admins): the audit entries for this person, newest first, in
  words ("office_milan: kept carol out — "on leave"", "created the account").

#### Per-person actions

| Action | Who | What it does |
|--------|-----|--------------|
| Edit details | Admins, delegates with `edit_details` | Change email, display name and custom field values (admin-only fields need an admin) |
| Send new invite | Admins, delegates with `invite` (own keyless accounts only), holders of `sign_in_help` (any account they may help) | New one-time link; earlier unused links stop working. Not offered for administrators |
| Require passkey | Admins | Adds the passkey registration action for the next sign-in |
| Clear pending | Admins | Removes pending required actions |
| Reset passkeys | Admins, holders of `sign_in_help` | Deletes all passkeys, signs the user out, then creates a new invite (or shows `./portcullis invite <user>` for an administrator). Type the username to confirm |
| Revoke certificate | Admins, holders of `sign_in_help` (Sign-in tab) | Revokes one YubiKey or browser certificate; it normally stops working within a minute. Refused (409) for an administrator's, and for `admin`, `portcullis-hub` and any `portcullis-*` account: `./portcullis cert revoke <serial>` |
| Issue YubiKey certificate | Admins (Sign-in tab) | Signs a CSR made on the person's YubiKey, after a fresh sign-in the people page's template accepts (not a password or a browser certificate). Refused (409) for an administrator, `admin`, `portcullis-hub` and any `portcullis-*` account |
| Password… | Admins | Fallback: set or generate a password; signs the user out |
| Sign in as… | Admins (Sign-in tab) | Signs in as the person for at most 30 minutes, after a typed reason and a fresh YubiKey touch; your own session ends. Not for administrators, `admin`, `portcullis-hub` or any `portcullis-*` account. Audited, and shown to the person at their next sign-in |
| Delete | Admins, delegates with `remove` | Deletes the user from LLDAP and Keycloak. Type the username to confirm |

**Delete** deletes the user from LLDAP first (saved as a tombstone to prevent re-creation of names still in entries or end dates), then deletes the Keycloak copy. The audit entry records what happened to the copy: `keycloak_copy=removed`, `none` (never imported) or `FAILED`. Delegates can delete only non-protected, non-administrator accounts not in any permission group. If the Keycloak removal fails, the copy is listed under **Stale Keycloak records** (admins only), where it can be removed by id. (Keycloak sometimes answers HTTP 500 after it has removed a federated user's copy; the Hub then looks the user up again and treats "not found" as removed.) The result also warns when other people's person fields (e.g. `manager`) or a rule's `reports to` still name the deleted user — update those. Afterwards the page goes back to the People list.

#### Keycloak status (admins only)

For each LLDAP user except `portcullis-hub`:

- **not signed in yet**: Keycloak has no copy. LDAP users are imported at first sign-in or when the Hub needs them (not an error)
- passkey count, or **no passkey**
- pending required actions
- **Keycloak status unavailable** with the reason (per-user failure; only that row is affected)

The Hub reads each user's status separately, at most 8 calls at a time, 15 seconds total. A per-user failure marks only that user. If Keycloak itself is unreachable (sign-in, user list or federation list fails), a banner says "Keycloak status unavailable" and users/groups still load. Past 15 seconds, a banner says some statuses are missing.

YubiKey and browser certificates are on the person's **Sign-in** tab ([below](#a-persons-page)).

#### Stale Keycloak records (admins only)

Users Keycloak has (federation link = LDAP provider) but LLDAP no longer has (deleted outside the Hub, e.g. in `portcullis lldap-ui`). The Hub lists the username, Keycloak id and reason.

They rarely appear any more: Keycloak removes its copy of such a user by itself the next time the user is looked up (core sets `removeInvalidUsersEnabled` on the LDAP federation), and the Hub lists every Keycloak user every 15 minutes so each one is looked up (the **stale-record cleanup**). Keycloak decides per user by asking LLDAP; while LLDAP is unreachable nothing is removed.

The cleanup is **fail safe**: before each run the Hub checks that LLDAP answers, that the bootstrap `admin` and the Hub's service account exist, and that LLDAP's user count hasn't dropped by more than 20 % *and* more than 2 accounts since the last successful run (kept in `<data>/user-sweep.json`). LLDAP unreachable **skips** that run and retries every minute until LLDAP answers or a real problem pauses it. A skipped run (unreachable) shows no Apps page banner for the first \~5 minutes; after that: **"Removing people deleted in LLDAP is waiting: \<reason\>. It retries every minute."** A failed account or count check **pauses** the cleanup: the Hub log says so loudly at every run and the Apps page shows **"LLDAP looks wrong — stale-record cleanup paused"** with the reason. Check LLDAP — restore it from a backup if it lost users — then type `resume` in the banner and click **Resume cleanup** (admins; audited as `keycloak.sweep_resume`; LLDAP's current user count becomes the new baseline; the account checks still apply). API: `GET /api/keycloak/user-sweep`, `POST /api/keycloak/user-sweep/resume` with `{"confirm": "resume"}`. The pause covers only the Hub's cleanup: Keycloak still checks a user against LLDAP when that user tries to sign in, so restoring LLDAP before starting the stack is still required ([Backups](backups.md#restore)). Groups deleted in LLDAP leave Keycloak at its next LDAP sync (hourly). A record that still shows here (e.g. Keycloak answered with an error) can be removed by hand:

**Remove** deletes only the Keycloak copy (type the username to confirm). The federation is read-only, so LLDAP isn't touched. Logged as `keycloak.remove_stale` with the id. Refused for `admin`, `portcullis-hub`, any username LLDAP has, and Keycloak users not linked to the LDAP federation.

### Groups

The **Groups** tab is a table of every LLDAP group: name, kind (rule-based,
manual or built-in), number of people and what it gives access to (app
links), with a search box. Every row opens the group's page:
**[Group pages](groups.md#group-pages)** describes the page (People with how
each is in, Add people, Keep out…, Change end, Used by, History).

**New group** (admins): enter a group name (`[A-Za-z0-9][A-Za-z0-9_.-]{0,127}`, not starting with `lldap_`; case-insensitively unique); its page opens. New groups are manual and start clean: if the Hub still has a rule, entries, end dates or a permission grant for that name (a group deleted in LLDAP's own UI), they are removed first and a warning lists them.

**Delete group…** (admins, in the group page's Used by panel): the page states what goes (memberships — the members are signed out —, the rule and its entries, the app setting rows that name it, the permissions it holds, the apps that lose access through it); type the name to confirm. Built-in groups (`lldap_admin`, `lldap_password_manager`, core-subdomain groups) can't be deleted. The group is deleted in LLDAP first (if that fails, nothing changes); then its rule, entries, end dates and any delegated permission granted to it are removed, so a group created later with the same name inherits nothing. Its former members are signed out of Keycloak.

**Add / Remove** (admins, on the group page): adding someone to an administrator group asks for confirmation. Removing yourself from `lldap_admin` is refused, and the last human member of `lldap_admin` stays. Removing a member also drops their end date in that group (a later re-add starts without one) and signs them out of Keycloak; if the sign-out fails, the removal stands and a warning says so.

**End dates** (admins): pick a date/time (browser local time, converted to UTC); the membership is removed automatically when it ends. Clear it with **No end**. Refused for `lldap_admin`. On a rule-based group the end belongs to an added-by-hand or kept-out entry ([End dates](groups.md#end-dates)).

Groups an enabled app needs but that don't exist yet are listed (with one-click **Create**) only in the Apps page's [Missing groups](#missing-groups) banner.

#### Rule-based groups

Admins can turn a group **rule-based** (**Make rule-based…** on its page): membership is computed from custom fields. The rule is edited (**Edit rule…**) two ways that stay in sync:

1. **Blocks** (default): point-and-click all/any blocks, nestable, with conditions `is`, `is not`, `is one of` (list fields), `is empty`, and for person fields `reports to (directly or indirectly)`.
2. **Text rule**: a typed expression with autocomplete (field names, list values) and inline errors. A toggle switches between them; a parse error refuses the toggle.

A **preview** shows who matches (count and names, live-updated). The Hub evaluates rules at least every 60 seconds, and about a second after every detail change, rule change, entry change and import that affects membership. **Make manual** turns it back into a manual group.

**Convert a manual group to rule-based** (admins): opens a review. Current members who don't match are pre-ticked to stay as added by hand (reason: "member before the rule (set by X on date)"); untick whoever should leave. Nothing changes until confirmed. The review compares itself with a fresh preview inside the Hub's lock and refuses with 409 if they differ (someone was added/removed in between) — convert again.

**Added by hand and kept out** (admins, rule-based groups only): **Add people** adds someone whatever the rule says (an *added by hand* entry); **Keep out…** keeps someone the rule matches out of the group (a *kept out* entry). Each needs a written **reason** (≤ 500 characters, shown to administrators only) and may have an end. See [Added by hand and kept out](groups.md#added-by-hand-and-kept-out).

#### Protected groups

Rules of **administrator groups** (see [Administrators](#administrators)), **permission groups** (the groups holding a delegated permission) and **app admin groups** (any group used as an app's `admin_group` or in `path_groups`) may only reference **admin-only fields**. A field used by such a rule cannot lose its admin-only flag (409 until the rule is changed or the group stops being protected).

A protected group's rule also **must not match a person with no details** (e.g. `office is empty` or `not office = "HQ"`): every new account starts empty, so such a rule would hand the group to whoever creates accounts (409).

**Delegate-created accounts** (`created_by`, see [Delegated permissions](#delegated-permissions)) are never added to a protected group by the evaluator, even if they match its rule; the evaluator reports them each run. They join once an admin acts on the account (sets a password, sends an invite, removes passkeys or requires a passkey), which clears `created_by`.

Built-in groups (`lldap_admin`, `lldap_password_manager`, core-subdomain groups) and permission groups cannot be rule-based.

#### The evaluator

- Runs at least every 60 seconds, and about a second after every detail/rule/entry/import change.
- Computes membership of every rule-based group (skips admin/built-in groups).
- **The Hub owns rule-group membership.** A manual change made in LLDAP to a rule-based group (e.g. in `portcullis lldap-ui`) is reverted at the next evaluation and audited as such.
- Handles cycles in the manager field (the `reports to` condition stops at the first repeat).
- Removes ended memberships (manual groups and added-by-hand entries) from LLDAP after their end. Ended entries are kept in the policy file's `expiring` array (plus a 10-minute grace period) so enforcement is strict even while the Hub is down. When group-gate withholds an ended membership for a request, it also withholds `Authorization` and `X-Forwarded-Access-Token`.
- On every removal, the Hub revokes the user's Keycloak sessions, so OIDC apps lose access at their next token refresh (oauth2-proxy cookie refresh is 1 minute, so removals take effect within ~1 minute). The same happens for an admin's **Remove**, a group **Delete** (all former members) and a **password** change; deleting a user deletes their Keycloak copy. Keycloak's LDAP federation caches no users, so group and field changes are read from LLDAP at that refresh.
- An added-by-hand entry with an end date is not published as expiring while the person is a member and matches the rule anyway (they stay by rule after the end); manual end dates and the 10-minute grace entries are always published.

### Org chart

A tree of everyone's manager (the person field named `manager`, or the first person field if there is none). Shows cycles as a banner. If there is no person field, a message says so (admins: add one under Setup).

Everyone can see everyone's details and the org chart.

### My apps

On `people.<domain>`, every signed-in person also has a **My apps** tab
(after Org chart). While AI support is on and they can use an app (or their
Portcullis account) with AI, it starts with the **Connect your AI** card:
the addresses, the steps per AI client, their connections with Disconnect and
their recent AI activity ([Connect your AI](../guides/connect-your-ai.md)). It lists the enabled apps they can reach that have
something personal for them, sorted by id, each with its link:

- their **per-person values** with where each comes from: "from
  office_milan" (only the person's own groups, never anyone else's rows),
  "everyone with access", or a fail-closed note, and when a change applies
  ("a change applies at your next sign-in"). Options the template hides
  (`self_visible: false`) and secrets never appear, and neither does any
  other person or any instance-wide value;
- the **values they enter themselves** (for example Firefox Sync's Mozilla
  account ID): an input with the template's rules (pattern, length, range,
  choices), **Save** and **Clear**, and a status line:
    - "Not set";
    - "Saved 2 Nov 2026 · the app picks it up within about a minute (the app
      restarts)", or "applies at your next sign-in to the app";
    - "Set by an administrator on 2 Nov 2026" (the admin isn't named); the
      person can still change or clear it, and saving it makes it theirs;
    - the Hub's refusal, e.g. "this value is already registered for Firefox
      Sync by another person". It never says who.
- **file-share passwords** (Samba and Time Machine apps): the person's own
  SMB password, for connecting from macOS, Windows or Linux. There is one
  password per app instance. The card shows the address to connect to
  (for example `smb://nas.home.arpa/Home`) and the username.
    - **Create password** (when there is none): a popup asks the person to
      sign in again with a passkey or YubiKey certificate (a method that is
      switched on). This is a **fresh** sign-in,
      even if they signed in a minute ago, and the Hub accepts it only if
      it is at most 5 minutes old. The Hub then generates a 24-character
      random password and shows it **once**, as 6 groups of 4 joined by
      `-` (29 characters; the dashes are part of the password). The dialog
      has **Copy** and **I've saved it**. The password never appears
      again: the Hub keeps only its NT hash on the `hub_secrets` volume,
      never in a backup.
    - **Regenerate** (when a password is active): it asks for confirmation
      ("Your Mac will ask for the new password; running backups stop. The
      old password stops working at once."), then repeats the same fresh
      sign-in and one-time display. The Hub removes the old hash the way it
      revokes a password (see [Managing
      people](file-sharing.md#managing-people)), so the old password stops
      working even when the app's hook is busy or fails, and open sessions
      that used it end.
    - **Revoke** (when a password is active): after a confirmation, the
      password is deleted and every device using it loses access. No fresh
      sign-in is needed. To connect again, create a new password.
    - The status line shows one of:
        - "No password yet"
        - "Password active since <date>"
        - "Your password was reset by a restore on <date>; create a new
          one." Restores are covered in
          [Restores](file-sharing.md#restores): an instance restore voids
          that instance's passwords, a core restore voids them all.
        - "File sharing isn't available for the username <name>; ask an
          administrator." (the app can't serve that username; there is no
          button)

  The fresh sign-in means that someone with only the person's Portcullis
  session cookie can't create or replace a password. Revoking needs no
  fresh sign-in, because it only removes access. Refused creates count
  toward the refusal limit below.

  Only people in the app's access group (`users_<id>`) see the card, and
  only while the app is enabled. Leaving the group, or having the account
  deleted, revokes the password: at once for a change made in the Hub,
  within about a minute for one made directly in LLDAP.

A person enters a value only for apps they have access to; for anything
else the answer is the same "not found". Clearing your own value always
works, also after you lost access or while the app is disabled. After 10
refused saves in a minute, every save is refused ("too many refused
attempts: try again in a minute", `429`) until the minute is over.

With nothing to show, the tab says "No apps with personal settings." The
tab only reads the person's own data: the people listener has no other app
routes ([contracts §5.1](../guides/integration-contracts.md#51-people-subdomain-new)).

### VPN devices

Every person in the VPN users group has a **VPN page**,
`https://people.<domain>/vpn/` (linked from the Sign-in page's **VPN
devices** card): their devices on every Portcullis VPN, and for built-in
devices **Add device**, **Renew**, **Rename** and **Remove**. Adding and
renewing need a fresh sign-in, the key pair is made in the browser, and the
configuration and QR code are shown once and never stored
([VPN-only access → Devices](vpn.md#devices-on-the-built-in-vpn)). The page
uses only its own files under `/vpn/`, so in server mode with public
enrolment it works from the internet (still behind sign-in) while the rest
of people.&lt;domain&gt; is VPN-only.

- **Client apps:** the official WireGuard app on Windows, macOS, iOS and
  Android (scan the QR code or import the file), `wg-quick` or
  NetworkManager on Linux.
- **DNS:** the configuration sends DNS to the tunnel's resolver. A device
  that validates DNSSEC itself fails on Portcullis names when the zone is
  signed ([DNSSEC](../setup/dns.md#dnssec)), and a browser with its own
  DNS-over-HTTPS bypasses the tunnel and shows `/vpn-required`: see
  [DNS caveats](vpn.md#dns-caveats).

Administrators and holders of `sign_in_help` see a person's devices on
People → person → **Sign-in** → *VPN devices* and can remove built-in ones
(a marketplace device answers "managed in &lt;provider&gt;"). Nobody can create
a configuration for someone else in the Hub; the host operator can
(`./portcullis vpn add-device`).

### Setup (admins only)

Define custom fields and assign delegated permissions. (The audit log is the Hub's [Audit log](#audit-log) tab.)

#### Custom fields

**Fields** describe people: department, office, cost center, manager, etc. Three kinds:

| Kind | Meaning |
|------|---------|
| **text** | Free-form text (one or multiple values per person) |
| **list** | One of the values you maintain (e.g. "Milan", "Berlin", "Remote"). Multi-valued allowed |
| **person** | A reference to another user (e.g. manager). Single-valued only |

Per field:

- **Label** (shown in the UI, e.g. "Department")
- **Share with apps** (default on): the field becomes an OIDC claim (`attr_<field>`) for native-OIDC apps and an `X-Forwarded-Attr-<Header-Name>` header for forward-auth/header-auth apps. Attribute values are percent-encoded (`%` → `%25`, `,` → `%2C`), joined with `, `, limited to 1 KB per value (before encoding; longer values are dropped and logged). Apps must percent-decode each value after splitting on `, `. See [Integration Contracts §4.1, §5](../guides/integration-contracts.md#41-user-attributes-file-hub-group-gate-new).
- **Admin-only** (off by default): only admins may edit it, and only admin-only fields may be used in rules of protected groups (administrator, permission and app-admin groups).

**Create**: name (`^[a-z][a-z0-9]*(_[a-z0-9]+)*$`, at most 31 characters: lowercase letters and digits, starting with a letter, `_` only between two of them — not at the end, not doubled; so its header name is always valid and unique; unique, and not one of LLDAP's built-in attributes: `mail`, `uid`, `display_name`, `first_name`, `last_name`, `avatar`, `creation_date`, `uuid`, `user_id`), label, kind, multi-valued (not for person fields), share with apps, admin-only. For list fields, add the allowed values.

**Edit**: change the label, values (list fields; can't remove a value in use), share-with-apps and admin-only flags. Can't change kind or multi. Can't turn off admin-only while a protected group's rule uses the field (409).

**Delete**: type the name to confirm. Refused (409) if a rule uses it, with the groups listed.

Fields are stored in LLDAP as custom user attributes (non-user-editable, so users can't change their own department in `portcullis lldap-ui`). Rules, exceptions, expiries, field metadata LLDAP can't hold, and permission assignments live in the Hub's state (`$HUB_DATA_DIR/directory.yaml`, atomic, mode 0600; a corrupt file refuses to start).

#### Delegated permissions

Four permissions, each granted to a group (manual or rule-based; that group may itself use rules over non-admin-only fields):

| Permission | What it grants |
|------------|----------------|
| **edit details** | Update email, display name and custom field values (single edits and CSV import). Admin-only fields need an admin |
| **invite** | Create new accounts via invite link (no groups, no Keycloak credentials). Filling in fields can make them match rule-based groups. A delegate-created account shows "via rule, account created by X" for its rule memberships |
| **remove** | Delete accounts |
| **sign in help** (`sign_in_help`) | Help with sign-in (setup link, remove passkeys, revoke certificates): send a setup link to any account they may help (not only ones they created, and also when it has passkeys), remove passkeys and revoke YubiKey and browser certificates, on the person's Sign-in tab. Never set a password or issue a certificate. See [Help to reset](auth-policies.md#help-to-reset) |

!!! warning "A setup link hands the account over"
    A `sign_in_help` setup link hands the account to whoever holds it, so
    grant the permission only to people you'd trust with those accounts.
    Holders can never reach an administrator.

Delegates never target themselves, administrators (`lldap_admin` etc.), the protected accounts (`admin`, `portcullis-hub`) or members of any permission group. They can't create a tombstoned name or one still in exceptions/expiries. A delegate's **Send new invite** works only for accounts the delegate created that still have zero Keycloak credentials (Keycloak missing or unavailable → refused); admins should re-invite such accounts themselves if they gave them only a YubiKey certificate. An admin's password / invite / passkey action clears the account's `created_by`, so delegates can't re-invite it.

Permission changes (including refusals) are audited (`directory.permission`). Built-in, admin and rule groups using non-admin-only fields are refused (409). Set a permission to **(none)** to revoke it.

### CSV import

**Import CSV** (admins and delegates with any of edit_details, invite, remove) uploads a CSV file (`,` or `;` separator, optional BOM, CRLF; at most 5 MB, 10,000 rows, 64 columns) and opens an **editable review table**. Nothing changes until **Apply**. The review:

- One row per person: new, changed, missing (in LLDAP but not in the file; unticked by default) or unchanged (hidden by default, with a **Show unchanged** toggle)
- Changed cells show `current → file`; click ↺ to keep the current value
- **Edit** any cell
- **Problems** (red): block Apply until fixed. Example: a manager who isn't a known user, with a picker to fix it. Unknown columns are reported but don't block
- **Effect on rule-based groups**: +n / −n per group, ignoring missing rows
- **Download CSV**: the edited table with a formula-neutralising leading `'` for cells that start with `=`, `+`, `-`, `@` or `` ` ``, or with tab/CR. That `'` is stripped on re-import, so a downloaded review imports back unchanged
- **Re-review** (JSON of the edited `{header, rows}`): refreshes the Effect with current rules

**Columns:**

- `username` (required), `display_name`, `email` and every custom field name. Unknown columns are listed but don't block.
- Missing people (LLDAP users not in the file) show up as unticked rows. Tick to remove (needs `remove` permission).
- Can't clear email or display name (the cell must have a value).

**Apply**: processes rows one by one (no rollback). Each row is re-checked with the caller's permissions (delegates: can't create into groups, can't touch protected/admin/permission-group accounts, can't create a tombstone). New people get invite links (admins and delegates with `invite`). The result shows per-row ok/error and invite links.

The Hub writes shared fields (those with share-with-apps on) into `user-attributes.json`, which group-gate reads to populate `X-Forwarded-Attr-*` headers (§4.1). On every field or membership change, the Hub also syncs the Keycloak LDAP attribute mappers and protocol mappers on the `portcullis-attributes` client scope (each shared field → `portcullis-attr-<field>` LDAP mapper → `attr_<field>` protocol mapper).

### Administrators

Members of these groups are **administrators**:

- `lldap_admin` and `lldap_password_manager`
- the groups of the core subdomains (`auth`, `traefik`, `hub`, `directory`, `people`, `metrics`, `mcp`) in `group-gate/group-gate-map.conf` (Hub: `HUB_GATE_MAP_FILE`)
- any group listed in `INVITE_PROTECTED_GROUPS`

This is the same set core's invite API uses. An invite hands the account to whoever holds the link, so core refuses invites for administrators, and the Hub doesn't offer them. Invite or recover an administrator on the server with `./portcullis invite <user>`. If core refuses an invite for a group the Hub doesn't know about, the Hub shows "administrators are recovered from the server: `./portcullis invite <user>`".

### Guardrails

- `portcullis-hub` (the Hub's own account) and `admin` (the bootstrap LLDAP admin) are untouchable: no edits, passwords, invites, passkey actions, group changes or deletion. An invite for `admin` would hand over the root account, so recover it on the server: `./portcullis invite admin`.
- [Administrators](#administrators) get no invites from the Hub. Resetting another administrator's passkeys or setting their password lets you take over their account: you must type their username to confirm, and the audit entry is flagged (`target_is_lldap_admin=true`).
- `admin` and every name starting with `portcullis-` are reserved: `portcullis-hub` is the Hub's protected service account, and apps use the prefix for their internal accounts. The Hub won't create such a user, import one from a CSV, invite one or set a password for one, even if the account was made in the LLDAP console. `lldap_*` group names are reserved. Built-in groups can't be deleted or made rule-based.
- You can't delete yourself or remove yourself from `lldap_admin`.
- The last human member of `lldap_admin` (every member except `portcullis-hub`) can't be deleted or removed from it.
- Email addresses are unique (case-insensitive).
- Every change goes through the same proxy-secret and CSRF checks as the rest of the Hub and needs a signed-in user (`X-Forwarded-User`).

### How passwords are set

LLDAP stores passwords with OPAQUE. Its HTTP password endpoints need the client half of that protocol, so the Hub sets passwords over LDAP instead (the standard Password Modify operation, RFC 3062). LLDAP then does the OPAQUE step itself. This is the same mechanism `ldappasswd` uses. The password crosses the `portcullis` network in clear text, like Keycloak's and enroll's LDAP binds; core may switch to LDAPS with `LLDAP_LDAP_URL=ldaps://…`.

## Drift detection

The Hub keeps the desired state (enabled apps) in `state.yaml` and regularly
compares it with the compose projects Docker actually runs:

- every `HUB_RECONCILE_INTERVAL` (default `1m`, at least `5s`)
- on Docker events

Reconcile **reports** drift and never fixes it by itself. A yellow **State
drift** box at the top of the catalog lists each mismatch with a message, the
running/total container count, and buttons for the allowed actions:

| Kind (`kind` in the API) | Meaning | Actions |
|--------------------------|---------|---------|
| `enabled_not_running` | Enabled, but no container of the project runs (stopped, or none) | **Start** (`start`: compose up), **Disable** (`disable`) |
| `running_not_enabled` | Containers of `portcullis-<id>` run, but the instance is not enabled (the message adds "its public-exception router bypasses forward-auth" if they carry one) | **Stop & remove** (`stop`: compose down). **Enable** (`adopt`: mark it enabled and compose up) when a template with that ID exists |
| `stopped_not_enabled` | Stopped containers left behind by an instance that is not enabled | **Stop & remove** (`stop`) |
| `template_missing` | Enabled, but no valid template provides it any more (source removed, template deleted or now invalid) | **Disable** (`disable`) |
| `public_access_mismatch` | An exposure label of a running container (any router's `tls.options`, any label of the public router or its strip middleware, and for instances with [their own login](auth-policies.md#apps-with-their-own-login) every router's `middlewares`, e.g. after switching the Sign-in mode without a restart) differs from what the Hub renders now — a widened rule, a missing guard or other middleware, a stale or missing public router (e.g. after a failed restart or a template change) — or a stored public choice can't be applied ("confirm a mode") | **Apply settings** (`apply`: regenerate the override and compose up), **Disable** (`disable`); none for "confirm a mode" (fix it in Settings) |
| `job_failed` | A one-off job (§3 of the [integration contracts](../guides/integration-contracts.md)) exited non-zero, is dead, or ContainerState errored (fail closed). Message: "job \<svc\> failed (exit \<code\>)" or "job \<svc\> failed" (unknown code); multiple: joined with "; " | **Start** (`start`), **Disable** (`disable`) |
| `job_missing` | A one-off job never ran (no container). A job in a compose profile the instance's setup choices leave off is never missing; one of a selected profile is. Message: "job \<svc\> never ran"; multiple: "N jobs never ran: \<list\>" | **Start** (`start`), **Disable** (`disable`) |
| `inactive_service_running` | An enabled instance runs a container of a service in a compose profile its setup choices leave off (e.g. the old database after a choice changed). Exited leftovers stay hidden. Message: "service \<svc\> runs although the instance's setup choices leave it off"; several: joined with "; " | **Restart** (`restart`: compose down with every profile, then up), **Disable** (`disable`) |

Destructive actions ask for confirmation. **Re-check** runs a reconcile
immediately. Apps that are in the middle of an operation are skipped.

The same is available over the API, which also needs the proxy secret:

```text
GET  /api/drift            latest report: {checked_at, error?, items: [{id, kind, message, running, total, template_exists, actions}]}
POST /api/drift            re-check now, returns the new report
POST /api/drift/resolve    {"id": "<app>", "action": "start|disable|stop|adopt|apply"}
```

If Docker is unreachable, the report carries `error` and the UI shows
"Docker unreachable".

### Fail-closed behaviour

Drift must never open access. That is why `state.yaml` keeps a **snapshot**
(`published`) of each enabled app's last published config: hostnames, access
group, admin paths, sign-in template pick, whether it ran with its own login only
(then no group is published: its routers have no group-gate) and the public
paths it opened (with `{token}`). The containers keep the public router they were started with, so
the snapshot keeps showing it in the policy file's `public_paths`.

- **Template missing, snapshot present.** If an enabled app's template stops
  loading, the Hub keeps publishing the snapshot to group-gate, so the app
  stays protected exactly as before. The drift message says "template missing
  — still enforced from last known config", plus "configured for the app's own
  login only" for such apps.
- **No snapshot.** If an enabled app has no snapshot, or a `portcullis-<id>`
  project runs without being enabled, the Hub reads the `Host()` rules from the
  running containers' labels. It publishes the reserved group
  `__portcullis_deny__` for those hostnames. group-gate then denies every
  request to them ("The configuration of … is unavailable"), until you disable
  or adopt the app. Never create an LLDAP group with that name.
- **Corrupt `state.yaml`.** If the file can't be parsed (or is empty), the Hub
  refuses to start rather than overwrite it with empty state.

## Template rules enforced by the Hub

Templates must load cleanly, or the Hub skips them and logs why:

- The manifest must satisfy the templates repo's
  [schema](../guides/manifest-reference.md).
- The directory name must match `^[a-z0-9][a-z0-9_-]{0,63}$`.
- Port and env keys must be valid `.env` keys.
- `settings`, `files`, `hooks` and `reload` must pass the settings rules of
  [Manifest Reference → Validation](../guides/manifest-reference.md#settings-files-hooks-and-reload);
  the message names the option, e.g. `setting trash_days: …`.
- Port `bind` values must be IP addresses.
- `auth.method` must be one of the schema's methods; `auth.native_login`
  only with `method: custom`, `sso: false` and `supported: true`.

**Strict Traefik rule parsing.** group-gate keys every template, group and path
rule by full hostname (policy v6). A host the Hub doesn't see would get no
policy and no group, which fails open. So the Hub parses each
`traefik.http.routers.<name>.rule` label in `compose.yml` (template contract
v2, [contracts §3.1](../guides/integration-contracts.md#31-template-contract-v2-instances-and-hostname-variables-new-contract-v2)) and rejects the template if:

- a `Host()` argument is anything but exactly
  `` `${PORTCULLIS_HOST_<ROUTER>:-<sub>.portcullis.local}` ``, where
  `<ROUTER>` is the host router's name (the router whose rule is `Host()`
  alone) upper-cased with `-` and `.` turned into `_`, and `<sub>` a single DNS
  label (the default subdomain). That rules out literal domains, bare
  domains, and other variables. The Hub sets the variable to the instance's
  full hostname, on the main domain or an added domain. During the
  conversion period an `instances: single` template may still use
  `` `<sub>.${PORTCULLIS_DOMAIN:-portcullis.local}` `` for all its routers
  (no mixing); it runs only as its default instance on fixed hostnames
- the rule uses `HostRegexp`, `HostHeader`, `HostSNI` or `HostSNIRegexp`
- some way the rule can match is not restricted by `Host()`: a top-level `||`
  branch without `Host()`, a negation, or a path-only rule
- a hostname has no host router, two host routers map to the same variable,
  or a variable is written with different defaults
- a router has no rule, or a `traefik.enable=true` service has no HTTP router.
  Traefik would then apply its default rule
- it declares a TCP or UDP router, which would bypass forward-auth
- its default hostname is a core host (`<main domain>` itself and the core
  subdomains `auth`, `traefik`, `hub`, `directory`, `enroll`, `people`,
  `metrics`); instance hostnames that are core hosts are refused when they are
  set

## Keycloak clients

For templates with `keycloak_clients`, the Hub creates confidential OIDC
clients in the `portcullis` realm. Each client gets:

- the secret from the app's generated env
- the manifest's redirect URIs, with `{{DOMAIN}}` replaced
- the default client scopes `openid`, `profile`, `email`, plus **`acr`** (puts
  `acr`/`amr` in tokens; `amr` names the sign-in methods used) and **`groups`** (claim `groups` with
  plain group names, so apps can map `users_<app>` / `admin_<app>`)
- with `email_verified_claim: false` in the manifest, **`email-unverified`**
  instead of `email` (claim `email`, no `email_verified`; created by
  `./portcullis keycloak configure`). The Hub attaches it first, then removes
  `email` from the client's default and optional scopes, on create and on every
  reconcile; without the realm scope it logs an error and leaves `email` in
  place ([contract §8](../guides/integration-contracts.md#8-keycloak-clients-core-hub-templates))

**Ownership.** Each client the Hub creates is tagged with the attribute
`portcullis.hub.template=<template-id>`. When the client already exists, the
Hub updates its secret, redirect URIs and scopes only if:

- **the client is tagged** and the tag names this template, or
- **the client is untagged** and the Hub can prove it belongs to the template.
  That means it has at least one redirect URI, and every redirect URI and web
  origin is a plain `http(s)` URL without wildcards whose host is one of the
  template's own `<sub>.<domain>` hosts.

Anything else fails closed. The existing client is left untouched and the
enable is **refused with HTTP 409** (`client "<id>" …` belongs to someone else).
The app is not started, because it would be wired to a secret and redirect URIs
it doesn't own. Resolve the clash in Keycloak, e.g. by deleting the foreign
client or choosing another `client_id`. Other registration errors, such as
Keycloak being unreachable, are logged as warnings, and the app still starts.


Core and built-in clients are reserved and never touched:
`portcullis-forward-auth`, `admin-cli`, `account`, `account-console`,
`broker`, `realm-management` and `security-admin-console`.

## Per-app isolation

- **Separate compose project.** Each app runs as `portcullis-<app-id>`, with its
  own containers and `default` network.
- **Networks.** Frontends join the external `portcullis-proxy` network (shared
  with Traefik) and the app's `default` network. Internal services join only
  `default`. Apps can't reach each other or the core services directly.
- **Template files.** Before every `compose up`, the Hub copies the app's
  template directory to `<core>/templates/<app-id>/`. Compose resolves relative
  paths against the core checkout on the host
  (`--project-directory = PROJECT_HOST_DIR`), which is what makes bind mounts
  like `./templates/immich/setup.sh` work.
- **Separate `.env`.** The Hub writes a per-app `.env` with the app's option values (single-quoted),
  generated secrets (`generate: random` → 32 hex characters), and the core
  variables its compose file references. It takes those core variables from
  `/project/.env`, which is **not** the core `.env`: it is the generated subset
  `secrets/hub/core.env` (see [Security & Hardening](hardening.md#container-hardening)).
  Files are written atomically with mode `0600`.

## Template sources

Each source is a git repository with one directory per app (`manifest.yaml` +
`compose.yml`).

- **Default source.** On first start, the Hub clones
  [porelli/portcullis-templates](https://github.com/porelli/portcullis-templates)
  (`DEFAULT_TEMPLATES_URL`) as the source named `portcullis`. It cannot be
  removed.
- **Sync.** Runs `git pull --ff-only` on every source and reports which failed
  to fast-forward. The Hub never edits the clones (the Expert tab's custom
  override lives in the Hub's data directory), so syncs fast-forward.
    - **Automatic.** The Hub syncs at **every start**, before it writes its first
      policy file (each pull bounded to a minute; group-gate keeps serving the
      previous policy meanwhile), and when it receives `SIGHUP` —
      `./portcullis upgrade` sends it and prints the result (see
      [Upgrading](upgrading.md)). **Sync All Sources** in the Template Sources
      tab does the same on demand. `HUB_SYNC_SOURCES_AT_START=false` turns the
      start-up sync off.
    - **Fail-safe.** A failed pull (remote unreachable, or local changes block the
      fast-forward) leaves the checkout as it was: the last good copy keeps
      serving. If the new version has no valid template for an app that is
      enabled (e.g. it needs a newer Hub), the source is put back to the commit it
      had (`git reset --keep`) and the sync reports "the previous version is
      kept". A sync never opens anything: an enabled app whose template is
      missing or rejected stays **denied** (fail closed) until a template it
      accepts is there.
    - **Status.** The Template sources section (at the bottom of the Marketplace) shows the last sync (start-up, upgrade
      or button): each source up to date / updated to `<commit>` / not updated
      and why, and enabled apps still without a valid template. Also
      `GET /api/sources/sync` and `<data>/source-sync.json`.
- **Community sources.** Add more repositories in the **Template Sources** tab.
    - Source names use lowercase letters, digits, `-` and `_`.
    - URLs must be `https://…`, `http://…`, `ssh://…` or `user@host:path`.
    - Removing a source first stops every enabled app from it.

Templates from all sources are merged into one catalog. Remember that a
template runs with what is effectively host-root power (see below). Only add
sources you trust.

## Security model

- **Authentication.** The Hub has no login of its own. Traefik enforces
  forward-auth and the `lldap_admin` group (`hub=lldap_admin` in core's
  `group-gate-map.conf`) before a request reaches it.
- **Proxy secret.** Every request except `GET /healthz` must carry
  `X-Portcullis-Proxy-Secret` equal to `HUB_PROXY_SECRET`. The comparison is
  constant-time, the secret must be at least 32 characters, and the Hub won't
  start without it. Traefik's `hub-proxy-secret@docker` middleware adds the
  header after forward-auth, so a container that reaches the Hub directly on
  the `portcullis` network can't impersonate an admin by sending
  `X-Forwarded-User`. See [Security & Hardening](hardening.md#hub-proxy-secret).
- **MCP listener.** A third listener, `HUB_MCP_ADDR` (`:8890`), serves only
  the Portcullis MCP (`/mcp/admin`, `/mcp/people`) and the gate's internal
  API (credentials, confirmations) to `mcp-gate`. Every request but
  `GET /healthz` needs `X-Portcullis-MCP-Secret`
  (`HUB_MCP_GATE_SECRET_FILE`); it is bound on all the Hub's interfaces, so
  the secret is the only protection, and no Traefik router targets it.
  Without the secret file the listener doesn't start and AI support stays
  off. See [Security & Hardening → AI support](hardening.md#ai-support-mcp-gate).
- **AI files.** The Hub writes `mcp-gate.json` and `mcp-credentials.json`
  (0640, group 10001) for the gate, and keeps `<data>/ai/` (provider secrets,
  the `app_oauth` records, minted-but-unstored ids, who could use AI; 0600).
  At start it sets every other file of its data directory with a group or
  other bit to 0600 (the policy, portal, attribute and `signin-keycloak.json`
  files stay 0644 without write bits). A hostname change moves the companion scopes' audience
  with the Keycloak redirect URIs and holds the AI scope pass until it
  commits. Instance backups carry `config/ai.json` (switches, modes and the
  provider selection, never a credential or an internal flag).
- **Portal list.** Next to the policy file the Hub writes `portal-apps.json`:
  enabled apps with name, icon, URLs and required group, for core's landing
  portal ([Integration Contracts §10](../guides/integration-contracts.md#10-landing-portal-app-list-hub-core)).
- **CSRF.** Every state-changing request (POST/PUT/DELETE) must be same-origin
  (checked through `Sec-Fetch-Site`/`Origin`) and carry
  `Content-Type: application/json`. The forward-auth cookie is shared across
  all `*.<domain>` subdomains, so without this a page on any other app would
  count as "same-site".
- **Docker access.** The Hub has no Docker socket. It uses
  `DOCKER_HOST=tcp://socket-proxy-hub:2375` both for the `docker compose` CLI
  (only `up`/`down`) and for its own Engine API calls (status, logs, exec,
  events, and the container archive endpoints of the never-started helper
  containers that copy volumes for instance backups and restores:
  `ALLOW_ARCHIVE`). The socket proxy denies swarm, plugins, builds, secrets, configs and
  system prune. The Hub can still start containers with any configuration, so
  treat it as host-root-equivalent (under [rootless Podman](#rootless-podman):
  equivalent to the operator account).
- **Runtime user.** The image runs as **uid/gid 10001** with a read-only root
  filesystem. It writes only `/data` (the `hub_data` volume), `/project/templates`
  and `/project/appfiles` (both chowned to 10001 by `./portcullis up`; the
  latter holds the [settings data files](hardening.md#settings-data-files-and-secrets))
  and tmpfs. `secrets/` and `backups/`
  of the core checkout are masked with empty tmpfs mounts.
- **Outbound calls.** The Hub calls the Keycloak admin API, LLDAP (GraphQL,
  plus LDAP only to set passwords) and core's invite API, with Go's HTTP
  client: 20 s timeouts, TLS verification, no shelling out to `curl`.
  Credentials never appear in process arguments or env vars: the LLDAP
  service account and the invite secret are read-only files mounted by core.
  The signed-in user shown in the header is `X-Forwarded-User` as-is, i.e.
  the LLDAP username. The Hub never looks it up in LDAP.
- **LLDAP admin rights.** The Hub's service account is in `lldap_admin`, so
  the Hub can grant `lldap_admin`. That adds nothing to what it can already
  do: through its socket proxy it is host-root-equivalent. Every change is
  attributed to the signed-in admin and audited.
- **Domains service.** The Hub adds extra domains through core's `domains`
  service (a separate Go service). Credentials are sent to the service once over
  an internal API (bearer secret) and never appear in the Hub's state, logs,
  audit or errors. The service stores them encrypted at rest with an age key.
  The Hub reads only domain status (records OK, certificate expiry) from the
  service's API. See [Domains service](#domains-service) below.
- **Timeouts.** compose up 15 min, compose down 5 min, shell 15 min, git 5 min.
- **Policy file.** The Hub writes `group-gate-policy.json` (version 6)
  atomically to `hub_data`. It is keyed **by full hostname**:
    - `methods`, `templates` (every enabled template, compiled) and `default`
    - `hosts` for instances with their own template pick (instances on the
      default publish nothing; group-gate uses `default`)
    - `core` for every gated core page's template
    - `groups` for enabled instances with `group_access: true`
    - `path_groups` from `auth.admin_paths`
    - `extra_domains` lists added domains
    - core hosts' groups are never published (they come from `group-gate-map.conf`)

    Next to it the Hub writes `signin-keycloak.json` (0644), which Keycloak's
    sign-in extension reads (methods, templates, native-OIDC clients, FIDO list).

    The format is defined in [Integration Contracts §4](../guides/integration-contracts.md#4-policy-file-hub-group-gate).

## Image tags and verification

| Tag | Published when |
|-----|----------------|
| `X.Y.Z`, `X.Y`, `X`, `sha-<short>` | A release tag `vX.Y.Z` is pushed |
| `edge` | Every push to `main` |

There is **no `latest` tag**. On core `main`, `HUB_IMAGE` defaults to
`ghcr.io/porelli/portcullis-hub:edge`. A core release pins a released Hub tag
by digest, and `release.yml` enforces that. If you override it, pin a release
by tag **and** digest in `.env`, then run `./portcullis up`.
`./portcullis version` shows which image is configured and which one runs.

Images are multi-arch (amd64, arm64) and carry SBOM and provenance attestations.
Each one is signed with cosign (keyless, GitHub OIDC). Verify a tag before you
pin it:

```bash
cosign verify ghcr.io/porelli/portcullis-hub:<tag> \
  --certificate-identity-regexp '^https://github.com/porelli/portcullis-hub/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Common tasks
## Domains service

The Hub adds extra domains (beyond the main domain) through core's **domains**
service. See [Adding extra domains](#adding-extra-domains) above for the
operator workflow.

### How it works

The domains service is a separate Go service that:

- **Receives requests to add domains** over an internal HTTP API (bearer secret at
  `HUB_DOMAINS_SECRET_FILE`, shared with the Hub)
- **Stores DNS credentials encrypted** at rest with an age key
  (`secrets/domains/age.key`). The encrypted store (`domains_data/store.age`)
  is in core backups, so protect it like Vault's raft snapshot.
- **Creates DNS records** (`<d>` and `*.<d>`: A, and AAAA if the server has IPv6)
  and their CAA via provider APIs (Cloudflare, Porkbun, Route 53, DigitalOcean,
  Hetzner, Hetzner Cloud)
- **Obtains wildcard certificates** (website certificates, HTTPS) for each added domain via ACME DNS-01
- **Serves certificates to Traefik** via its HTTP provider (inline PEM, polled
  every 10 s), with mutual TLS authentication

Credentials are sent to the service **once** and never appear in the Hub's state,
logs, audit or errors. The service redacts provider errors (which may echo tokens)
before logging or returning them. The Hub reads only domain status from the service:

- `records_ok` (A/AAAA verified at 1.1.1.1 and 8.8.8.8)
- `cert_not_after` (RFC 3339)
- `last_error`
- `state` (pending, records, issuing, ready, renewing, error)
- `caa_ok` (the CA would issue to the service's account) and `dnssec` (the
  zone's DNSSEC state)

and, for the [DNS panel](#the-dns-panel), each domain's DNS plan and the
main domain's read-only plan.

The Hub stores this status in `state.yaml` (no credentials).

### Network isolation

The service sits on three isolated networks:

- **`portcullis-domains`**: domains + Hub (internal, fixed subnet
  `172.31.252.0/28`). The API accepts connections only addressed to this subnet
  or loopback.
- **`domains-egress`**: domains and the one-shot `dns-tool` of `./portcullis dns`. They reach ACME and DNS providers over
  this, isolated from other services.
- **`portcullis-certs`**: domains + Traefik (internal). The certificate endpoint
  (`:8443`) uses mutual TLS with a private CA.

Traefik never routes the domains service.

### Certificate endpoint

Traefik fetches certificates from `https://domains:8443/traefik/dynamic` via its
HTTP provider. The endpoint:

- **Requires and verifies** Traefik's own certificate (TLS `RequireAndVerifyClientCert`
  against a private CA generated by `./portcullis init`)
- **Returns only** `tls.certificates` with inline PEM (cert chain + key), never
  routers, services, middlewares or other Traefik config
- **Checks every certificate's SANs** before serving: they must be exactly `<d>`
  and `*.<d>` for an added domain `<d>`, never the main domain or any host at
  or under it (except added subdomains of the main domain themselves)

Certificates and keys are never on a shared volume.

See [Integration Contracts](../guides/integration-contracts.md) §12 (Domains service)
and [Security & Hardening](hardening.md#domains-service) for complete details.



### Changing an app's hostname or middlewares

Hostnames are per instance: change them in the Hub on the instance's
**Overview** tab (see [Changing hostnames](#changing-hostnames)); the default
instance's are `<sub>.<main domain>` unless edited. The router middlewares come
from the template only. Change them in a template source you control (fork the
template into your own source repository if needed), keep the rule in the
[strict form](#template-rules-enforced-by-the-hub) and keep the forward-auth
pair (`portcullis-auth@docker,portcullis-groups@docker`, in this order) and
`security-headers@file`. **Sync**, then restart the app. The Expert tab's custom
override refuses `traefik.*` labels.

### Backing up app data

App data lives in Docker volumes: `portcullis_<key>` for a default instance,
`portcullis_<instance-id>-<key>` for the others (the Hub's override names
them). Use the Hub's [instance backups](#instance-backups) (archived under
`hub_data`, so `./portcullis backup` ships them), or back up app volumes with
your usual tooling, e.g.:

```bash
docker run --rm -v portcullis_jellyfin-config:/data -v "$PWD":/backup \
  alpine tar czf /backup/jellyfin-config.tar.gz -C /data .
```
