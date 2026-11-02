# Shared folders and the doctor

Status: draft for approval (2026-11-02)

Project 2 of 3: (1) app settings panel → **(2) shared folders + doctor** →
(3) file sharing (file-share passwords, Samba and Time Machine templates).
This design depends on project 1 (its spec is being drafted alongside this
one) and serves as groundwork for project 3.

## Intent

Several apps often work on the same files: a Samba share and Nextcloud or
OxiCloud on the family documents, or Jellyfin, Immich and a Samba share on
the photos. Each app container runs as its own uid and gid (Gitea 70,
Synapse 991, Mealie 911, Paperless 1000, Mattermost 2000, Nextcloud
`www-data`, others as root or the image's own user), and each writes new
files with its own umask. Today the admin types each host path into each
app separately. Nothing makes the ownership agree, so one app can't read
or write what another app created. The fix is a host shell, which
Portcullis doesn't want people to need.

Two things solve this, and the user asked for both (decision 9):

- **Shared folders.** The admin defines a folder once (name, host path) and
  picks which app instances use it. The Hub then keeps ownership
  consistent: one shared group per folder, setgid directories, default ACLs
  so the apps' umasks don't matter. It does this through its Docker helper
  containers, never a host shell.
- **The doctor.** It checks the whole setup, including folders set up
  outside the Hub. It shows findings with a severity, offers one-click
  fixes where they are safe, and only explains the risky ones.

## Goals

1. **Define a shared folder once.**
   - Fields: name ("Family photos"), id (slug), host path, optional
     description.
   - The host path must lie under one of the Hub's bind roots, and the
     Hub checks it before saving: it exists (or is created on request),
     its filesystem type, ACL and xattr support, file count, and current
     owners.
2. **Pick the apps that use it.**
   - For each app instance and each of its folder settings (a `path`
     setting, project 1), the admin chooses either "Shared folder ▾" or
     "Custom path".
   - A folder setting can point at a subfolder of a shared folder
     (`Family media` + `movies`).
   - One folder can serve any number of instances, including several
     instances of the same template.
3. **Templates declare what each app needs on each folder setting**, as
   an extension of project 1's `path` type:
   - the access it needs (`read` or `write`);
   - the uid and gid it reads and writes as (fixed, or set through env
     such as PUID/PGID);
   - how the app joins the folder's group;
   - whether it must own the files.

   The Hub applies this generically, with no app-specific code.
4. **Consistent ownership, kept by the Hub.**
   - Each shared folder gets a Hub-allocated group (gid).
   - Directories get setgid, plus group read/write/traverse and a default
     ACL for the group. New files therefore land in the folder's group
     with group write, whatever the app's umask.
   - Every app container using the folder joins that group.
   - `read` access mounts the folder read-only, on every path setting
     that declares it (call 24).
   - All of this goes through Docker helper containers: no host shell, no
     SSH.
5. **The doctor checks the whole setup.** At minimum it finds:
   - **Disagreeing apps:** apps that share a folder (Hub-managed, or the
     same host path or nested paths typed in by hand, or bind mounts in a
     custom override) but disagree on ownership, or a writer that can't
     write.
   - **Folder owner mismatch:** what is on disk (group, setgid, default
     ACL, owner where an app must own its files) doesn't match what the
     apps need, or has drifted since the last apply.
   - **File sharing reachable from the internet:** a port the template
     marks LAN-only is bound to every interface or to a public address,
     or the app uses host networking.
   - **Per-person options no group sets** (project 1): everyone gets the
     default value, a group value names a group with nobody from the
     instance's access group in it, or the group no longer exists.
   - **Generic checks templates declare**, from a fixed catalog of check
     kinds (filesystem features, exclusive use, free space, LAN-only
     exposure, required values), so apps we don't have yet can use them
     without Hub code (decision 2: "forward-thinking").
6. **Findings with a severity and a clear explanation.**
   - Each finding says what is wrong, why it matters, which apps and
     folders are affected, and what the fix would do.
7. **One-click fixes where they are safe** (decision 8). Every fix:
   - previews exactly what will change before it is applied;
   - is audited;
   - restarts the affected apps when needed;
   - saves a backup first when it touches data.

   Risky changes are explain-only: moving data, filesystem changes, host
   firewall.
8. **Admin-only and audited.** Shared folders, doctor fixes and mutes are
   admin-only on the hub listener and audited. Delegates have no access.

## Non-goals

- Moving, copying, merging or deleting user data. A shared folder is
  only ever adopted where it already is. Removing a shared folder never
  deletes files.
- Backing up shared-folder contents. Instance backups copy volumes only
  (contract §11.5), and shared folders are host data. The doctor may warn
  that they aren't backed up, but it doesn't back them up.
- Quotas, per-person subfolders, and SMB users and passwords (project 3).
- Host firewall management, and probing reachability from outside the
  server (see Open questions).
- Changing the settings type system itself (project 1). This project adds
  fields to `path` and a value form for it.
- Folders on NFS, CIFS or FUSE mounts as Hub-managed folders. The doctor
  explains why they are refused.

## Anti-goals

- **No host shell, no new root path.** Ownership changes run only in a
  Hub-created helper container with a fixed program and fixed arguments,
  mounting only the one folder, with no network, and only the
  capabilities that step needs.
- **Never weaken access.**
  - A fix never removes permission bits or ACL entries that someone has
    today. It only adds access for the folder's group. Groups that
    currently have access keep it: they get an ACL entry for it, or the
    fix becomes explain-only (calls 7 and 8).
  - Previous owners (uids) keep their access too when `must_own` changes
    the owner (call 20), and existing named ACL entries never gain
    effective rights (call 21).
  - `group_add` stays forbidden in custom overrides (`useroverride.go:72`).
    The Hub adds only the gids of the folders that instance actually
    mounts, and never writes the custom override (call 26).
- **No chown of the world.** No folder may be a bind root itself, a system
  path, the core checkout, the Hub's data, or Docker's own storage. Two
  shared folders may not overlap. The fixer never crosses a mount point
  and never changes a hard-linked file (call 27).
- **No silent changes.** Nothing on disk changes without a preview that
  the admin applied. The doctor flags drift but never fixes it by itself.
- **No app-specific Hub code.** Everything comes from manifest
  declarations and a fixed catalog of check kinds.

## Constraints and facts (verified in the code)

- **Path settings today** (`internal/templates/manifest.go` `Setting`,
  `SettingTarget`):
  - The types are `text`, `path`, `paths`, `boolean` and `select`.
  - A `path` has a `target` `{service, mount}` and no mode.
  - The schema has the same enum (`tpl-new/schema/manifest.schema.json`
    `$defs.setting`, ~line 324).
  - `paths` is in the schema but the Hub ignores it.
  - Only immich, jellyfin and plex use `path` (both template trees).
    Nextcloud keeps its files in a named volume
    (`nextcloud-data:/var/www/html`), OxiCloud in `/app/storage` inside the
    container. So the user's own example (Samba + Nextcloud/OxiCloud)
    needs those templates to gain a folder setting (see Open questions).
- **Mounts are always read-write.**
  - `renderOverrideLocked` (`internal/hub/override.go` ~40–54) writes
    `"<host>:<mount>"` with no `:ro`.
  - Immich's setting says "mounted read-only"
    (`tpl-new/immich/manifest.yaml` ~115–120) but isn't.
  - → `access: read` must render `:ro`.
- **Path values are barely checked.**
  - `ValidatePathSetting` (`internal/templates/validate.go:203`) rejects
    only `:` and control characters.
  - The bind roots (`HUB_OVERRIDE_BIND_ROOTS`, default `/srv:/mnt:/media`)
    and the system and sensitive path lists (`internal/hub/useroverride.go`
    ~77–110, `ParseBindRoots`) apply only to custom overrides.
  - → Shared folders reuse those rules. Confining plain path settings the
    same way is project 1's validation; until then the doctor flags paths
    outside the bind roots.
- **Every settings save restarts the instance** if it is enabled
  (`internal/hub/settings.go`, end of `SaveSettings`). Project 1 introduces
  per-setting `applies`. Assigning a folder changes mounts and groups, so
  it is always a restart.
- **Helper containers are created, never started.**
  - `internal/hub/backup.go` ~39–56 and `internal/docker/volumes.go`
    `HelperSpec`/`CreateHelper` (~99–143) show the current helper:
    - volume mounts only (`mount.TypeVolume`, no bind);
    - uid 65534, every capability dropped, no network, no-new-privileges;
    - 8 pids, 32 MiB;
    - pinned `HelperImage`, alpine 3.24.3 by digest.
  - Contract §6 says "The Hub never starts a helper container".
  - The daemon's archive endpoints can't do a recursive chgrp or chmod,
    and can't set ACLs.
  - → This project needs a **started** helper kind (a contract §6
    change).
  - The Hub's socket proxy (`portcullis/docker-compose.yml`
    `socket-proxy-hub`: `CONTAINERS`, `POST`, `EXEC`, `ALLOW_ARCHIVE`)
    already lets `compose up` start containers. The builder confirms that
    starting a helper needs no new proxy flag.
- **Port exposure today** (`internal/hub/ports.go` `resolvePortBindings`):
  - the bind defaults to `0.0.0.0` unless a template sets `bind` or the
    admin sets `<KEY>_BIND`;
  - `network_mode_host` ports bind wherever the app binds;
  - the Hub can't see the host's firewall or NAT;
  - Docker-published ports bypass host firewalls such as ufw (known Docker
    behaviour [k]).
- **Reserved variables**: `templates.ReservedVar`
  (`internal/templates/instance.go:36`) covers the instance, client-id,
  group and host variables. The new folder variables must be added.
- **Patterns to reuse**:
  - background operations return 202 `{op_id, poll}` with the outcome in
    the op record (`internal/hub/ops.go` `OpRecord`; backup, restore and
    delete);
  - audit goes through `auditOp` to `audit.jsonl` (contract §9.5);
  - per-instance locks; Hub.mu is never held across Docker calls;
  - the Hub UI has tabs catalog, settings, sources and users, and the
    Settings tab has sections such as Domains (`web/index.html` ~451).
- **Standing rules**:
  - prefer mature pinned libraries;
  - no migration or back-compat code;
  - fail closed;
  - identity is the LLDAP username;
  - contract changes go into `integration-contracts.md` first;
  - templates stay declarative.

## Decided by the user

- A doctor helps configure things the right way. Example: the same
  folders shared in Samba and in Nextcloud or OxiCloud need consistent
  group and user file ownership (decision 8).
- The doctor explains **and** offers one-click fixes where safe
  (decision 8).
- Both: the Hub manages shared folders itself (define once, pick apps,
  Hub keeps ownership consistent) **and** the doctor checks folders set
  up outside it (decision 9).
- Three projects in this order: settings panel → shared folders + doctor
  → file sharing (decision 10).
- File sharing (project 3) is reachable only from LAN/VPN, with a warning
  if exposed (decision 6). This project's exposure check delivers that
  warning.
- Forward-looking: it must work for apps we don't have yet, without ad hoc
  definitions per app (decisions 2 and 5).

## Calls made while drafting (check these)

1. **Fix rules (Controller's call, from the brainstorm).** Every fix:
   - previews exactly what changes;
   - is audited;
   - restarts the affected apps if needed;
   - takes a backup first when it touches data.

   Risky changes (moving data) are explain-only. The calls below make
   this concrete.
2. **Template declaration (Controller's call).** A `path` setting gets an
   optional `folder` block:
   - `access: read|write`, required.
   - `runs_as`: the uid/gid the app's process uses on this mount, given as
     `{uid, gid}` or as `{uid_env, gid_env}`. The `_env` form names
     variables the Hub sets, e.g. PUID/PGID images, where the Hub sets
     the gid to the folder's group.
   - `joins_group`: how the app joins the folder's group, one of:
     - `group_add` (the default): the Hub adds the gid as a supplementary
       group of the target service;
     - `gid_env`: the gid becomes the app's primary group through
       `runs_as.gid_env`;
     - `template`: the template does it itself (e.g. Samba
       `force group`) from the variable in call 4.
   - `must_own: true`, for apps that refuse files they don't own. At most
     one `must_own` app per folder; the Hub then also sets the owner.
   - `checks`: template-declared checks (call 12).

   The validator enforces the following:
   - `folder` only on `path`;
   - `runs_as` required whenever `folder` is present;
   - `uid`/`gid` must match the service's `user:` in compose when that
     is set;
   - the `_env` names may not be reserved variables.
3. **Folder setting values.** A setting that uses a shared folder stores
   `folder:<id>` or `folder:<id>/<subpath>`. The Hub resolves it to the
   host path when it renders the override. The subpath is relative, has
   no `..`, and is created by the fix if it is missing.
   - A template without a `folder` block can still be pointed at a shared
     folder. The doctor then reports "this template doesn't say how it
     writes" (Info), and the Hub mounts the folder read-only unless the
     admin confirms write access.
4. **Group per folder.**
   - The Hub allocates a gid from **60000–60999**. The range stays clear
     of project 1/3 person uids (10000–59999 in the survey) and of
     65534. The gid is stable and never reused.
   - The gid is kept in Hub state, so it survives a Hub restore.
   - The group is only a number. Its display name (the folder's name) is
     kept in Hub state; nothing creates a named group on the host
     (`/etc/group`), in LLDAP or in the containers (call 22).
   - Adopting an existing host group is allowed, by number: gid ≥ 1000,
     not 65534, not used by another folder. A warning explains that anything mounted
     with that gid becomes reachable.
   - The Hub sets `PORTCULLIS_FOLDER_GID_<SETTINGKEY>` (and `_UID` when
     a `must_own` app owns the folder) in the instance's env for every
     setting that uses a folder. The `PORTCULLIS_FOLDER_` prefix becomes
     reserved.
5. **What "consistent ownership" means on disk.**
   - The group owner is the folder gid.
   - Directories get mode `g+rwx` + setgid. Files get `g+rw` where a
     writer app uses the folder, `g+r` if all apps only read.
   - On every directory: an access ACL and a default ACL for the owning
     group (`rwx`) and a mask of `rwx`, so new files inherit group write
     whatever the umask. The mask is raised without widening anyone
     else's effective rights (call 21).
   - File owners (uids) are left alone, except under `must_own`.
   - "Others" bits are never changed.
6. **The folder fixer: a started helper kind (contract §6 change).**
   - **Image**: the Hub's own image, with a hidden subcommand that walks
     the tree. It is already pinned and present, and adds no new image to
     trust. The Hub itself runs as uid 10001; only this helper runs as
     root, with the capabilities listed below.
   - **Arguments**: fixed and declarative (folder path, gid, owner, mode
     plan). No shell; paths aren't secrets.
   - **Mount**: one bind mount of the folder (`TypeBind`), confined as in
     the Anti-goals.
   - **Isolation**: `network: none`, no-new-privileges, read-only rootfs,
     pids and memory limits, label `LabelHelper`.
   - **Scan** mode runs as root with `CAP_DAC_READ_SEARCH` only, on a
     read-only mount.
   - **Apply** mode runs with `CAP_CHOWN` and `CAP_FOWNER` (plus
     `CAP_DAC_OVERRIDE`/`CAP_DAC_READ_SEARCH` to traverse), on a
     read-write mount.
   - **Output**: a JSON report (counts, a clipped sample of paths, errors)
     read from its logs.
   - **Cleanup**: helpers left behind are removed at start, like backup
     helpers.
   - **ACLs**: the Linux POSIX ACL xattrs, through a maintained library
     where one exists.
7. **The backup before a permissions fix is a permissions snapshot.**
   - Before a fix it records path, uid, gid, mode and ACL for every
     entry it will change, under `<data>/folder-snapshots/<folder>/<UTC>`
     (compressed, checksummed, the last 3 kept).
   - A full data copy of a multi-terabyte folder isn't practical, and
     the contents don't change.
   - "Undo last fix" is itself a previewed fix built from the snapshot.
   - Fixes that touch app volumes (none in v1) would use instance backups
     (§11.5).
8. **Previous group access is kept.**
   - When the fix changes the group owner, every group that had
     permissions gets a named ACL entry with the same bits, and the
     preview lists it ("group 1000 keeps rw through an ACL on 12,410
     files"). Directories also get the entry in their default ACL, so the
     previous group keeps access to files created later (call 21). Under
     `must_own`, previous owners get named-user entries the same way
     (call 20).
   - On a filesystem without ACLs, a fix that would remove someone's
     access is explain-only. Otherwise it applies group + setgid + mode,
     and the doctor recommends the template's umask variable where one is
     declared.
9. **Applying is stop → fix → start.**
   - The apps that use the folder are stopped, so nothing writes with the
     old ownership in between.
   - Then: snapshot, apply, re-scan to verify, regenerate their overrides
     (mounts, `:ro`, `group_add`, env), and start them.
   - The preview shows the downtime estimate from the scan's file count.
   - Folder, instance and coalesced restart locks are taken in a fixed
     order.
   - It is an async op (202 `{op_id, poll}`); a failure is recorded with
     the snapshot named.
10. **Severity has three levels.**
    - **Problem**: broken or unsafe now, e.g. a writer can't write, a
      LAN-only port bound to a public address.
    - **Warning**: likely to break, or weaker than intended, e.g. drift,
      `0.0.0.0` binds of `lan_only` ports (call 13; other ports' binds
      are no finding), no ACL support.
    - **Info**: worth knowing, e.g. a per-person option with no group
      values, a template that doesn't declare how it writes.

    Each finding has a stable fingerprint (check kind + subjects), so the
    admin can **mute** it with a reason. A muted finding reappears when
    its inputs change. Mutes are audited.
11. **Fix classes.**
    - **One-click** (preview → Apply):
      - manage existing hand-typed paths as a shared folder;
      - re-apply a folder's ownership;
      - rebind a LAN-only port to an address the admin types, checked
        against the declared local networks (call 25);
      - undo the last fix.

      (No "mount read-only" fix: `access: read` always renders `:ro`,
      call 24.)
    - **Explain-only**:
      - moving or merging data;
      - nested or overlapping paths;
      - disagreeing bind mounts from a custom override (call 26);
      - hard-linked files and nested mount points (call 27);
      - `must_own` on a filesystem without ACLs when previous owners
        would lose access (call 20);
      - folders outside the bind roots or on unsupported filesystems;
      - host networking exposure (firewall steps);
      - two `must_own` apps on one folder.
    - **Link-out**: per-person option findings open project 1's settings
      panel at the option. The doctor never edits settings values itself.
12. **Catalog of template-declared check kinds** (Hub-implemented,
    parameterised in the manifest, each with a one-line `reason` from the
    template):
    - `filesystem` (`needs: [xattr, acl]`, `not: [nfs, cifs, fuse]`) on a
      folder setting;
    - `exclusive` (no other app or instance may write the same folder,
      e.g. Time Machine bundles);
    - `free_space` (`min: <size>`);
    - `lan_only` on a `ports` entry;
    - `requires_group_value` on a per-person option (project 1): warn
      when no group sets it.

    Adding a check kind is Hub work and a contract change; adding a check
    is template work.
13. **Local networks for the exposure check.**
    - Hub Settings gets "Local networks": CIDRs, defaulting to RFC 1918,
      IPv6 ULA and the tailnet's `100.64.0.0/10`. Admin-only, audited.
    - Only ports a template marks `lan_only` are judged; a port without
      it bound to `0.0.0.0` is no finding (most templates publish that
      way by default).
    - A `lan_only` port bound to `0.0.0.0`/`::` is a **Warning**. It
      becomes a **Problem** when bound to an address outside the local
      networks, or to an address the main domain's A/AAAA record points
      at.
    - Host networking is a Warning (explain-only: the Hub can't see host
      firewalls; Docker bypasses ufw).
14. **When checks run.**
    - Config checks (state, manifests, overrides, ports, project 1
      values) are cheap and run on every Doctor view and after every
      relevant save.
    - Disk checks (fixer scan mode) run on demand ("Run disk checks"),
      after every folder apply, and daily. Results are cached with their
      time.
    - A scan has a time and entry cap. When it hits the cap, the result
      is marked "partial" and the finding says so.
15. **UI.**
    - **Settings → Shared folders** section (next to Domains): list
      (name, path, group, apps, last check), add/edit, "Check path",
      assign apps (a previewed apply, call 19), remove (refused with 409 while apps use it; never
      deletes files).
    - **Doctor** top-level tab with a count badge of Problems + Warnings:
      findings grouped by severity, each with explanation, affected
      apps/folders, and Fix…/Mute.
    - The **path setting** in project 1's panel gets the folder picker.
    - An app's detail shows a short "Doctor: 1 warning" line linking to
      the tab.
16. **API and audit** (admin-only, hub listener).
    - Endpoints:
      - `/api/folders` (CRUD of the definition, `/check`);
      - `POST /api/folders/{id}/assign/preview` (desired assignments →
        plan + plan hash) and `POST /api/folders/{id}/assign/apply
        {plan_hash}` (202), the same plan-hash pattern as doctor fixes
        (call 19);
      - `GET /api/doctor` (findings, last disk scan);
      - `POST /api/doctor/scan` (async);
      - `POST /api/doctor/findings/{fp}/preview`, which returns the plan
        and a plan hash;
      - `POST …/apply {plan_hash}`, which returns 202. It answers 409 when
        the state changed since the preview, so the admin re-previews;
      - `POST …/mute`, `DELETE …/mute`.
    - Audit actions: `folder.create`, `folder.update`, `folder.delete`,
      `folder.assign`, `folder.apply`, `doctor.fix`, `doctor.mute`,
      `doctor.unmute`, `settings.local_networks`.
    - Audit detail holds counts and ids, never file lists.
17. **Lifecycle.**
    - Deleting an instance drops its assignments; the folder stays.
    - Restoring an instance whose settings name a missing folder clears
      those settings, with a warning.
    - Restore as a new id keeps folder references (it's the same host
      data); the doctor then shows any `exclusive` conflict.
18. **Testing.**
    - Unit tests with fakes for planning, preview hashing, fingerprinting
      and each check kind.
    - A fixer test in CI on a filesystem with POSIX ACLs (the runner's
      ext4 temp dir) for chgrp, setgid and default ACL inheritance: a
      file created afterwards by another uid with umask 022 ends up
      group-writable.
    - One e2e: jellyfin (read) + a test writer app on one folder, through
      preview → apply → verify → undo.
    - Exposure check fixtures for binds and host networking.
    - Fixer fixtures for a hard link, a nested mount point, a symlink, an
      existing named ACL entry under a narrower mask, and `must_own` with
      several previous owners (calls 20, 21 and 27).

### Settled in the builder check

19. **Assigning is one previewed operation (Controller's call).**
    - Saving the folder *definition* (name, id, path, description) is a
      plain synchronous save. It allocates the gid in Hub state and
      changes nothing on disk or in any app.
    - Assigning or unassigning apps is a previewed async op, like a
      doctor fix: preview returns the plan and a plan hash; apply (202)
      runs call 9 and, only once the disk step verifies, writes the
      assignments, rewrites the setting values to `folder:<id>[/sub]`,
      regenerates the overrides and starts the apps.
    - Closing the preview saves no assignment and changes no setting.
      A failed apply leaves the old assignments and values in place
      (the snapshot is named in the op record).
    - So "assigned but not applied" is never a stored state. Drift after
      a successful apply is the doctor's "folder owner mismatch".
    - The UI's Save on the folder dialog saves the definition, then opens
      the assignment preview when assignments changed.
20. **`must_own` keeps previous owners' access (Controller's call, from
    the "never weaken access" anti-goal).**
    - When the fix changes an entry's owner, each previous owner uid
      gets a named-user ACL entry with the old user bits (access ACL; on
      directories also the default ACL), listed in the preview ("uid
      1000 keeps rw through an ACL on 12,410 files").
    - The snapshot records the old uid, so undo restores it.
    - On a filesystem without ACLs a `must_own` change that would drop a
      previous owner's access is explain-only. The group, setgid and mode
      part of the fix may still apply on its own.
21. **Default ACLs and the mask (Controller's call, from the anti-goals).**
    - Previous groups' (call 8) and previous owners' (call 20) entries go
      into the access ACL of existing entries and the default ACL of
      directories, so they keep access to files created afterwards.
    - Raising the mask never widens effective rights: before the mask
      goes to `rwx`, every existing named user/group entry is clamped to
      its current effective rights (entry ∧ old mask). The stored entries
      change, nobody's effective access does; the snapshot holds the
      originals and the preview lists the count ("4 existing ACL entries
      are narrowed to what they grant today").
22. **The folder group is only a gid (Controller's call).**
    - No `/etc/group` write on the host (the anti-goals forbid host
      writes), no LLDAP group (folders aren't an access-control group and
      must not touch the directory guardrails), no group created in
      containers. `group_add` and PUID/PGID take numbers.
    - The display name is the folder's name in Hub state. The preview
      says "gid 60001 is allocated for this folder", not "group photos is
      created".
    - Adopting an existing host group is by number only; the admin types
      the gid. The Hub doesn't look up host group names.
    - A template that needs a name inside its container (e.g. Samba's
      `force group`) creates it itself from `PORTCULLIS_FOLDER_GID_*`
      (`joins_group: template`, project 3).
23. **One primary gid per process (Controller's call).**
    - Validator: two folder settings of one service that name the same
      `runs_as.gid_env` (or `uid_env`) variable must declare the same
      `runs_as` and `joins_group`. Sharing the variable is normal (one
      PUID/PGID image, several folders), so it isn't refused.
    - Assignment: when two folder settings of one service would set the
      same `gid_env` (or `uid_env`) variable to different values, the
      assignment preview is refused (409) with an explanation: point both
      settings at the same shared folder (or subfolders of it). No silent
      `group_add` fallback (PUID images usually drop supplementary
      groups when they switch user).
    - Hand-typed paths that end up like this are a doctor Problem.
24. **`access: read` always renders `:ro` (answered by Goal 4 and the
    Constraints; no installs to migrate).**
    - Every `path` setting whose `folder` block says `access: read` is
      mounted `:ro`, shared folder or custom path (e.g. Immich's external
      library). No per-instance flag.
    - Templates without a `folder` block mounted on a shared folder keep
      call 3's rule (read-only unless the admin confirms write; that
      confirmation is part of the assignment, call 19).
    - The "mount read-only" one-click fix is dropped.
25. **Rebind addresses are typed (Controller's call).**
    - The admin types the address. The Hub checks that it is a valid IP
      inside the Local networks and not `0.0.0.0`/`::`. No host address
      discovery (no new helper kind, no new socket-proxy permission).
    - Apply writes `<KEY>_BIND` and restarts the instance. If the
      restart fails (e.g. the address isn't on the host), the old bind is
      put back and the instance started again; the op record says why.
26. **Custom-override bind mounts are explain-only (Controller's call).**
    - The Hub never writes the custom override and adds no `group_add`
      for its mounts.
    - The finding explains the steps: remove the mount from the custom
      override (Expert tab) and use the template's folder setting with a
      shared folder, where the template has one. Mounts that also appear
      in a folder setting still count for the disagreement check.
27. **Hard links, mount points, symlinks (Controller's call, from "no
    chown of the world").**
    - The walk stays on the folder's filesystem: a directory on another
      device is not entered or changed, and is reported.
    - Symlinks are never followed and never changed (`lchown` not used).
    - Regular files with `nlink > 1` are skipped and reported: their
      inode may also be reachable outside the folder. The preview lists
      the count; the finding explains how to fix them by hand. The apply
      still runs for everything else.
    - Devices, sockets and FIFOs are skipped and reported.
28. **Only `lan_only` ports are judged for exposure (answered by call
    13).** Call 10's "`0.0.0.0` binds" means `lan_only` ports.

## Example: template declaration

```yaml
# jellyfin/manifest.yaml (excerpt)
settings:
  - key: JELLYFIN_MOVIES_PATH
    label: Movies folder
    type: path
    target: {service: jellyfin, mount: /data/movies}
    folder:
      access: read
      runs_as: {uid: 1000, gid: 1000}
      joins_group: group_add

# samba/manifest.yaml (project 3, excerpt)
settings:
  - key: SAMBA_SHARE_PATH
    label: Shared folder
    type: path
    target: {service: samba, mount: /shares/family}
    folder:
      access: write
      runs_as: {per_person: true}           # each person's Hub-allocated uid (form: project 3, Open question 4)
      joins_group: template                 # reads PORTCULLIS_FOLDER_GID_SAMBA_SHARE_PATH
      checks:
        - kind: filesystem
          needs: [xattr, acl]
          not: [nfs, cifs, fuse]
          reason: macOS clients store metadata in extended attributes
ports:
  - key: SAMBA_SMB
    label: SMB
    container: 445
    default: 445
    protocol: tcp
    service: samba
    lan_only: true
```

(How a per-person uid is written in `runs_as` is for project 3 to define;
see Open questions.)

## Example: resulting UI behaviour

1. Settings → Shared folders → **Add**:
   - Name `Family photos`, path `/srv/photos`. The admin clicks **Check
     path** and sees: "exists · ext4 · ACLs and xattrs supported · 12,410
     files · owners 1000:1000 (all)".
   - **Used by**: the admin ticks *Immich → External photo library*
     (read) and *Samba → Shared folder* (write).
2. **Save** saves the folder definition and opens the assignment preview
   (closing it leaves the folder defined with no apps, call 19):
   - "gid 60001 is allocated for this folder (shown as *Family photos*).
     12,410 files and 312 folders change group 1000 → 60001; group 1000
     keeps read/write through an ACL.
     312 folders get setgid and a default ACL (group rwx).
     Immich mounts it read-only.
     Samba and Immich are stopped for about 1 minute, then started.
     A permissions snapshot is saved first."
   - The admin clicks **Apply**, the op runs in the background, and the
     result is "verified: 0 entries differ".
3. Doctor tab, on another install where the admin typed paths by hand:
   - **Problem**: "Jellyfin and Samba both use `/srv/media`. Samba writes
     as uid 10001 (group 10001); Jellyfin reads as uid 1000 and can't read
     412 new files." → **Manage as shared folder…** (the same preview as
     above).
   - **Warning**: "Samba's SMB port 445 listens on all interfaces
     (0.0.0.0). File sharing should only be reachable from your local
     networks." → **Rebind…** (type `192.168.1.10`; preview: "SAMBA_SMB
     bind 0.0.0.0 → 192.168.1.10, Samba restarts").
   - **Info**: "Time Machine: *Backup size limit* has no group values;
     everyone with access gets the default (500 GB)." → **Open setting**.

## Interfaces with the other projects

- **Project 1 (settings panel)** provides:
  - the `path` type this extends;
  - per-setting `applies` (folder changes are `restart`);
  - bind-root validation for plain path settings;
  - read access to per-person options, group values and the resolver,
    for the "no group sets it" check and `requires_group_value`;
  - the panel that renders the folder picker.

  This project adds the `folder` block, the `folder:<id>` value form and
  the `PORTCULLIS_FOLDER_*` variables.
- **Project 3 (file sharing)**:
  - its Samba and Time Machine templates declare `folder` (`joins_group:
    template`), `lan_only` ports, and `filesystem` and `exclusive`
    checks;
  - files created over SMB carry the person's Hub-allocated uid and the
    folder gid;
  - file-share password checks (e.g. a password still active for someone
    who left the group) can register as doctor check kinds through the
    same internal check interface.

## Left to the builder

- The ACL library (or a direct xattr encoding), the fixer's walk
  strategy, the scan caps, and the snapshot format.
- Exact API field names, finding wording, and the UI layout within the
  existing styles.
- Whether the Hub's own image is reachable by digest at runtime (else
  pin a dedicated fixer image built in Hub CI); confirming the socket
  proxy needs no new flag to start helpers.
- Contract text: §3 (`folder`, `lan_only`, `checks`), §6 (started fixer
  helper), reserved variables; schema and `validate.py` in the templates
  repo.

## Open questions

1. **Which file apps can share a human-readable folder?** Nextcloud can,
   through External storage (local) set up by its `setup.sh` hook [k].
   OxiCloud keeps its storage at `/app/storage`; whether its on-disk
   layout is the user's file tree (and safe to share) is unverified. If
   it isn't, OxiCloud can't use a shared folder and the doctor says so.
2. **Tightening.** Should the doctor ever offer to remove access
   ("others can read the family photos")? This design never removes
   access.
3. **External reachability probe.** Should we have a real "is port 445
   open from the internet" test? It would need something outside the
   server; this design only judges binds.
4. **Per-person uids in `runs_as`.** How a template says "each person's
   own uid" (project 3's `person_id`) is for project 3 to settle.
5. **Should delegates see doctor findings** (read-only)? This design says
   admins only.
