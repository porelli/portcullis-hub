# File sharing: file-share passwords, Samba and Time Machine

Status: draft for approval (2026-11-02)

Project 3 of 3: (1) [app settings panel](2026-11-02-app-settings-panel-design.md)
→ (2) [shared folders + doctor](2026-11-02-shared-folders-doctor-design.md)
→ **(3) file sharing**. It depends on both and builds on the extension points
they reserve: `person_secret` and `person_id` (project 1, call 20); the
`folder` block, `lan_only` ports, check kinds and Local networks (project 2,
calls 2, 4, 12, 13). Related specs:
[certificates self-service](2026-11-02-certificates-selfservice-design.md)
(fresh passkey touch) and
[app instances and domains](2026-11-02-app-instances-domains-design.md)
(instances, backups, restore). Evidence base: `.superpowers/sdd/settings-survey.md`
§1.3, §1.4 and §3.6.

## Intent

People want a network drive and Mac backups on the home server. SMB is the
only protocol for both: Finder, Windows Explorer and Time Machine speak it,
and Time Machine speaks nothing else. SMB can't use Portcullis sign-in:

- no browser, so no passkey and no forward-auth;
- Samba needs the NT hash of the password, and LLDAP will never store one
  (OPAQUE, by design; lldap #1168 closed "not planned", #1493 "no go");
- most Portcullis people have no password at all (passkey-only).

So the Hub issues each person a **file-share password** of their own, for one
file-sharing instance, from their People page. It is shown once and stored
only as an NT hash. It is withdrawn the moment the person loses access. Two
templates use it:

- **Samba**: personal folders and the Hub's shared folders (project 2);
- **Time Machine** (`mbentley/docker-timemachine`): one backup share per
  person, with a per-person size limit set per group (project 1, e.g.
  `office_milan` gets 10 GiB).

Everything app-specific lives in the two templates. The Hub gains only
generic parts that any future app-password app (mail, WebDAV, restic) can
reuse.

## Goals

1. **File-share passwords (generic `person_secret`).**
   - A person with access to a file-sharing instance creates their password
     on `people.<domain>` → My apps → <instance>. They must touch their
     passkey first (a fresh touch).
   - The password is random, at least 24 characters, and shown **once**, with
     a copy button. It works for that instance's file sharing only.
   - The person can regenerate it (the old one stops at once) or revoke it.
   - It is **disabled automatically** when the person leaves the instance's
     access group, or when their account is deleted.
   - It is stored only as the NT hash, in the instance's private storage.
     Never logged, never audited, never in an API answer after the first one.
   - Admins see who has a password (never the password or hash) and can
     revoke anyone's.
2. **Stable per-person uids (generic `person_id`).** The Hub gives each
   person one uid that never changes and is never reused. Files a person
   writes over SMB carry the same owner in every file-sharing instance and in
   every shared folder.
3. **Samba template.**
   - Each person gets a personal folder, and the admin can add shares on
     project 2's shared folders, with read and write groups.
   - Ownership follows project 2: the owner is the person's uid, the group is
     the folder's gid.
4. **Time Machine template** (`mbentley/docker-timemachine`).
   - Each person gets a Time Machine share.
   - The size limit is a project 1 per-person option, set per group with a
     default ("everyone else with access").
5. **Hardened SMB in both templates.**
   - SMB3 only; encryption and signing required; SMB1, NTLMv1, LANMAN and
     guest access off.
   - Enforced at every start and verified. The container refuses to start
     when the effective config differs.
6. **LAN/VPN only, with a warning.**
   - SMB ports are declared `lan_only`. Samba itself also refuses clients
     outside the Hub's Local networks.
   - Project 2's doctor warns when a port is exposed. The instance and its
     enable dialog show the same warning.
7. **Discovery (Bonjour/mDNS) that works with Docker.** Off by default;
   people connect by address. Admins can opt in to advertising through the
   host's Avahi.
8. **No restart for people changes.** New passwords, revocations, people
   joining or leaving, and quota changes are applied live by a hook the
   template ships. Restart is only the fallback.

## Non-goals

- Kerberos/PKINIT or an AD domain controller. Set aside by the user: it needs
  an AD DC, and unattended Time Machine backups would need tickets. It may
  come later as a separate template.
- Using the password for anything but that instance's SMB: no web sign-in,
  no other instance, no other app.
- Admins creating a password for someone else.
- Windows network discovery (wsdd2: needs host networking and
  `CAP_NET_ADMIN`). Windows users connect with `\\<address>\<share>`.
- macvlan or host networking for discovery (see call 15).
- Per-person quotas on Samba folders (Samba can't enforce them; open
  question 1). Time Machine size limits are in scope.
- AFP (mbentley's AFP image is deprecated), NFS, WebDAV, SFTP.
- Probing from the internet whether 445 is reachable (project 2 open
  question 3).
- Deleting a former member's data automatically.

## Anti-goals

- **A stolen session minting a credential.** Creating or regenerating needs a
  fresh passkey (or hardware certificate) touch.
- **Secret sprawl.** The plaintext exists only in the Hub's memory and in
  the one response. The NT hash is password-equivalent, so it gets the same
  treatment:
  - never in `state.yaml`, env, `docker inspect`, argv, logs, the audit, op
    records, hook stdin or backups;
  - present only in the instance's private storage and in the app's own
    passdb inside its container.
- **Access outliving membership.** A person removed from the access group
  must lose SMB access within seconds of the Hub seeing the change, open
  sessions included. A membership-change debounce must not delay removals.
  The Hub sees a change made through the Hub (or by the rule evaluator) at
  once. It sees an edit made directly in LLDAP within 60 s (call 23).
- **A default or orphan account.** No SMB account may exist other than the
  people the Hub delivers. In particular, never mbentley's
  `timemachine`/`timemachine` default.
- **Weak protocol by accident.** No setting, template update or upstream
  default may bring back SMB1/SMB2, unsigned or unencrypted sessions, NTLMv1
  or guest access.
- **Someone else's data.** A new account with a recycled username must never
  inherit a former account's folder or backups.
- **App-specific Hub code.** The Hub knows `person_secret`, `person_id`,
  hooks, files and `lan_only`. It knows nothing about Samba.

## Constraints and facts

Hub and templates (verified in the code):

- **Settings today** are instance-wide, of types text/path/paths/boolean/select
  (`internal/templates/manifest.go:122-132`, `tpl-new/schema/manifest.schema.json`
  `$defs.setting`). Every save restarts the instance (`internal/hub/settings.go:343-346`).
  Project 1 replaces this; this project uses project 1's model only.
- **Ports.**
  - The bind defaults to `0.0.0.0` (IPv4 only) unless the template sets
    `bind` or the admin sets `<KEY>_BIND`. The value must be an IP
    (`internal/hub/ports.go:25-40`, `settings.go:123`).
  - The Hub override publishes `<bind>:<host>:<container>`
    (`internal/hub/override.go:56-80`).
  - Host-port collisions are checked across instances. A second SMB instance
    needs another port or another bind address.
- **Path settings** are bind-mounted read-write and only refuse `:` and control
  characters (`internal/templates/validate.go:203`, `override.go:42-53`).
  So a host directory outside the bind roots, such as `/etc/avahi/services`,
  can be a path setting today.
- **Compose allowlist** (`internal/templates/coreref.go:831-835`) allows
  `ulimits`, `tmpfs`, `cap_add`/`cap_drop`, `entrypoint`, `user`,
  `group_add`, `network_mode` (literal). Interpolation is refused in
  `network_mode`, so a setting can't switch host networking on or off.
- **Atomic writes replace the file** (`internal/fsutil/fsutil.go:35`:
  `os.Rename`). A container that bind-mounts a single file keeps the old
  inode and never sees a rewrite. → Hub data and secret files must be
  mounted as **directories** (call 7).
- **Exec has no stdin** today (`internal/docker/exec.go`); project 1 adds it
  for hooks. `Hub.Exec` runs `/bin/sh -c` (`internal/hub/runtime.go:104`);
  project 1's hooks use argv instead.
- **Directory** signals every change through `Service.OnChange`
  (`internal/directory/service.go:105-110`). Removals already sign people out
  of Keycloak (`LogoutUser`, `service.go:1354`, `evaluate.go:287`). Rule
  groups re-evaluate at most every 60 s (contract §9.6).
- **People listener** serves only the directory API, the people page and
  `/healthz` (`TestPeopleListenerHasNoAppRoutes`). Project 1 adds exactly one
  exception, `GET /api/me/apps` (project 1 call 15, contract §5.1).
- **Instance backups** archive every volume of the project plus
  `instance.yaml`, the env and the overrides (contract §11.5). Through the
  core backup and `--offsite` they leave the host, and they "hold app
  secrets in clear" (`portcullis-docs/docs/operations/backups.md`).
- **Libraries present:** `golang.org/x/crypto` (indirect, `go.mod:45`; its
  `md4` package computes the NT hash) and `github.com/docker/go-units`
  (indirect).
- **No HTTP routers.** Neither template has a web page. Nothing in
  `internal/templates` visibly requires a router (no such check found). The
  builder confirms that Discover, policy and portal accept a router-less
  template (call 17).

Upstream images (fetched and read 2026-11-02):

- **`mbentley/docker-timemachine`** (README, `entrypoint.sh`, `Dockerfile.smb`):
  - Alpine + Samba + s6. `ENTRYPOINT /entrypoint.sh`, `CMD s6-svscan /etc/s6`;
    the entrypoint ends with `exec "$@"`.
  - Multi-user mode: `EXTERNAL_CONF` is a directory of `*.conf` files, one per
    user. Required keys: `TM_USERNAME`, `TM_GROUPNAME`, `PASSWORD`,
    `SHARE_NAME`, `VOLUME_SIZE_LIMIT` (MiB or with a unit; empty = no limit),
    `TM_UID`, `TM_GID`. Optional: `SHARE_PATH`, `TM_ENABLED`.
  - **Plaintext passwords only.** `chpasswd` and `smbpasswd -s` read
    `PASSWORD` or `PASSWORD_FILE`. There is no hash input.
  - Without `EXTERNAL_CONF` it creates the user `timemachine` with password
    `timemachine`.
  - It regenerates `smb.conf` at every start:
    - `server min protocol = ${CUSTOM_SMB_PROTO}` (default SMB2);
    - `ntlm auth = ${CUSTOM_SMB_AUTH}`;
    - nothing for encryption or signing.

    `CUSTOM_SMB_CONF=true` uses a mounted `smb.conf` instead.
  - Each user's share gets `fruit:time machine max size = <limit>`.
  - It writes an Avahi file `/etc/avahi/services/smbd.service` with
    `_adisk._tcp` entries naming every Time Machine share.
  - The storage must support xattrs (NFS likely won't); the image tests for
    them and warns. Recommended: `--tmpfs /run/samba`,
    `--ulimit nofile=65536:65536`.
  - Discovery needs host networking with no Avahi or Samba on the host, or
    macvlan, or a host Avahi reflector plus `ADVERTISED_HOSTNAME`. Without
    any of these, people connect by `smb://host/share`.
  - No reload mechanism is documented.
  - Tags: `smb` / `latest` (multi-arch) and daily `smb-YYYYMMDD` snapshots
    (kept 6 months).
- **`ghcr.io/servercontainers/samba`** (README, `scripts/entrypoint.sh`,
  `config/samba/smb.conf`):
  - Alpine + Samba + runit. `ENTRYPOINT /container/scripts/entrypoint.sh`;
    it initialises once per container (`/.initialized` marker), then
    `exec "$@"`.
  - Accounts come from `ACCOUNT_<user>` env. The value is a plaintext
    password or a **full smbpasswd line with the NT hash**, written straight
    into `passdb backend = smbpasswd`. Also `UID_<user>`, `GROUP_<name>`,
    `GROUPS_<user>`. Accounts can't be read from files.
  - Shares come from `SAMBA_VOLUME_CONFIG_<name>` (raw stanzas). Global lines
    come from `SAMBA_GLOBAL_CONFIG_*` / `SAMBA_GLOBAL_STANZA`.
  - Defaults include:
    - `map to guest = Bad User`;
    - `wide links = yes`, `follow symlinks = yes`;
    - nothing for protocol, signing or encryption.
  - Discovery: Avahi in the container needs host networking. Alternatively,
    mount the host's Avahi services directory at `/external/avahi`; the
    container writes `samba.service` there and disables its own Avahi.
  - Tags `a<alpine>-s<samba>` (pinned, not overwritten), variants
    `smbd-only` / `smbd-avahi` / `smbd-wsdd2`, cosign-signed.
- **Others.**
  - `crazy-max/samba`: `config.yml`, plaintext or `password_file`, no hash
    input.
  - `dperson/samba`: plaintext on argv; effectively unmaintained.
  - → Only ServerContainers takes a hash. That is why the Samba template
    uses it.
- **Docker and mDNS.** Multicast doesn't cross Docker's bridge, so an Avahi
  inside a bridged container advertises to nobody on the LAN. With host
  networking it collides with a host Avahi or Samba, binds every interface,
  and two instances can't both own 445.

## Decided by the user

- A Hub-generated per-person file-share password:
  - random, at least 24 characters, shown once, with a copy button;
  - for file sharing only, and per instance;
  - revocable and regenerable;
  - disabled automatically when the person leaves the access group;
  - stored only as the NT hash inside the instance's private storage, never
    logged or audited.
- SMB3 only, with encryption and signing required; SMB1 and NTLMv1 off.
- Reachable only from LAN/VPN, with a warning if exposed.
- Kerberos/PKINIT is set aside (it needs an AD DC; unattended Time Machine
  backups need tickets). Possibly a separate template later.
- People get their own file-share password on their People page
  (people.<domain> → My apps → <app>). "It works as long as these are shown
  only if relevant for the user (i.e. they have access)."
- Templates for `mbentley/docker-timemachine` and a Samba server.
- Per-person limits come from the directory and are set per LDAP group, e.g.
  people in Milan get 10 GB for Time Machine. The admin sees all of Time
  Machine's options and sets limits for a whole group.
- Order: settings panel → shared folders + doctor → file sharing.

## Calls made while drafting (check these)

Items marked **Controller's call** were made by the controller during the
brainstorm. The others were made while drafting this spec.

1. **Fresh passkey touch to create or regenerate.** *(Controller's call.)*
   - This reuses the certificates spec's fresh authentication (its call 8):
     - a fresh Keycloak sign-in with a passkey or a hardware (`pki_int`)
       certificate, never a file certificate;
     - its own Keycloak client;
     - an ID token with `auth_time` within 5 minutes and the right `amr`.
   - Here the **Hub** verifies the token, on the people listener.
   - One fresh-auth client and verifier serve both projects. Whichever
     project is built first builds it.
   - Revoking your own password needs no touch: it only removes access.
2. **The password.**
   - 24 random characters from `crypto/rand`, drawn from a 54-character
     alphabet with no look-alikes (no `0 O 1 l I`), about 138 bits.
   - Shown in groups of 4 joined by `-` (29 characters). The dashes are part
     of the password, so what people read is what they type.
   - The NT hash (MD4 of the UTF-16LE password) uses `golang.org/x/crypto/md4`.
   - The answer carries `Cache-Control: no-store`. The plaintext is
     overwritten in memory after it is sent, as far as Go allows.
3. **One credential per (person, instance, option).** A person with Samba and
   Time Machine has two passwords. Regenerating one doesn't touch the other.
4. **Self-service only. Admins revoke, never create.** An admin who created
   a password would have seen it. Admins see the list "who has a password,
   created when" on the instance's **File sharing** tab, with **Revoke**.
5. **Leaving = the credential is destroyed, not paused.** The user said
   "disabled". This draft deletes the hash when a person leaves the access
   group, is removed from LLDAP, or the instance is deleted. Coming back
   means creating a new password: fail closed, and nothing old stays
   dormant. The person's data stays (call 13). Confirm (open question 2).
6. **Revocations are immediate, additions debounced.**
   - Project 1 debounces membership-driven deliveries for 60 s (its
     call 17). For a `person_secret` with `revoke_on_leave`, a removal skips
     the debounce: the Hub deletes the hash file and runs the hook at once.
   - The hook disables the account, removes it from the passdb, and ends the
     person's open SMB sessions.
   - If the hook fails, the Hub recreates the container. The start-time
     converge (call 9) then drops the account. If that fails too, the
     instance is stopped and the op record says why: fail closed.
   - Additions (joins, quota changes) keep the debounce.
   - What counts as "the Hub seeing" a removal, including edits made
     directly in LLDAP, is call 23.
7. **Private storage = project 1's per-instance secrets file directory.**
   - "The instance's private storage" is the separate secrets location of
     project 1 call 14 (0600 files, Hub uid 10001). It is bind-mounted
     **read-only as a directory** into the one declared service and nowhere
     else. Directory, because atomic rewrites replace the file.
   - Where it lives on the host is call 25: outside the Hub's `/data`, so
     no backup holds it. How the container reads it without extra
     capabilities is call 24.
   - Layout: `<key>/<username>.nt`, one 32-hex-character NT hash per file.
   - Project 1's data files are mounted as a directory the same way, so a
     hook sees the current file without a recreate.
   - `state.yaml` keeps only metadata: credential id, created_at, created_by
     (always the person), revoked_at + reason.
8. **Not in backups; void after restore.**
   - `person_secret` hashes are left out of instance backups, the
     credential metadata included. They are also out of the core backup
     (`./portcullis backup`, `--offsite`), because the secrets volume isn't
     part of it. A core-level restore voids them as well (call 25).
   - Any restore voids every password of that instance: same instance (a
     restored hash could revive a password someone regenerated because it
     leaked) or new id (the survey's "copy on restore: false").
   - My apps then says "Your password was reset by a restore on <date>;
     create a new one."
   - Audited as `credential.void_restore` with the count only.
9. **One converge script per template, used at start and as the hook.**
   - The template ships `portcullis-sync`. It reads the people data file and
     the secrets directory and brings the container to that desired state,
     idempotently:
     - Unix users with their Hub uid;
     - passdb entries (hashes imported from files, never from argv);
     - share stanzas;
     - the hardened `[global]` section;
     - removal of every account not in the desired state.
   - It runs:
     - inside the container's start wrapper, before the image's service
       supervisor starts smbd;
     - as project 1's hook on `start`, `settings_change`,
       `membership_change` and a new trigger `credential_change`.
   - Hook stdin (project 1 call 16) carries who has a credential (id,
     version), never a hash.
   - The same script is copied into both templates. A templates-repo test
     keeps the copies identical.
10. **Hardened Samba config, verified.**
    - The script writes these `[global]` lines in both templates:
      - `server min protocol = SMB3`;
      - `server smb encrypt = required`;
      - `server signing = mandatory`;
      - `ntlm auth = ntlmv2-only`, `lanman auth = no`;
      - `map to guest = never`, `restrict anonymous = 2`, `guest ok = no`;
      - `disable netbios = yes`, `smb ports = 445`;
      - `wide links = no`;
      - `hosts allow` = Local networks (call 14), `hosts deny = 0.0.0.0/0 ::/0`.
    - Then it runs `testparm -s` and compares the effective values with the
      list. Any mismatch exits non-zero, so the container doesn't start.
    - Only 445/tcp is published (no 137-139).
    - The matching upstream knobs are pinned and locked in the manifest:
      `CUSTOM_SMB_PROTO=SMB3`, `CUSTOM_SMB_AUTH=ntlmv2-only`,
      `SAMBA_CONF_MAP_TO_GUEST=Never`, `HIDE_SHARES=yes`.
11. **Time Machine template mechanics.**
    - The template's `entrypoint:` is a Portcullis wrapper (`/portcullis/start`):
      1. it renders `EXTERNAL_CONF` from the people data file, one `.conf`
         per person with a password:
         - `TM_UID` = `TM_GID` = the person's uid (a private group);
         - `VOLUME_SIZE_LIMIT` = their resolved limit in MiB, empty =
           unlimited;
         - `SHARE_NAME` = `<share prefix>-<username>`;
         - `PASSWORD` = a throwaway random value made in the container and
           never stored;
      2. it execs mbentley's `/entrypoint.sh` with `command:`
         `/portcullis/post`;
      3. `post` runs `portcullis-sync`, which imports the real NT hashes over
         the throwaway ones (`pdbedit -i smbpasswd:<file>`, from a 0600 temp
         file in tmpfs), hardens and verifies `smb.conf`, then execs
         `s6-svscan /etc/s6`.
    - smbd starts only after the real hashes are in place, so the throwaway
      passwords never serve a request.
    - With nobody holding a password, there are no accounts and no shares,
      and the default `timemachine` account is never created. CI asserts
      both.
    - Live changes: the hook edits the share's
      `fruit:time machine max size`, adds or removes accounts and stanzas,
      then runs `smbcontrol all reload-config`.
    - The limit is cooperative: Samba reports the share's size and Time
      Machine prunes old backups to fit [k, Samba vfs_fruit]. The UI says
      "Time Machine keeps backups within this size", not "hard quota".
12. **Samba template mechanics.**
    - ServerContainers `ghcr.io/servercontainers/samba:a<alpine>-s<samba>`,
      pinned by digest.
    - No `ACCOUNT_*` env (that would put hashes in `docker inspect`). The
      image's entrypoint runs with no accounts. The template's `command:` is
      `/portcullis/post`, which runs `portcullis-sync` (accounts written into
      the smbpasswd passdb from the secrets directory, shares written to an
      included file), then execs `runsvdir -P /container/config/runit`.
    - Shares:
      - **Home**: `path = <homes>/%U`, `valid users = %U`. The folder is
        created by `portcullis-sync`, owned by the person's uid, mode 0700.
      - **Shared folders**: one per row of the `shares` table:
        - name, a project 2 folder, read groups and write groups;
        - `valid users` = readers ∪ writers, `write list` = writers,
          `read only = yes`. Nobody else can open the share, not even
          other people of the instance (call 26);
        - `force group` = the folder's gid
          (`PORTCULLIS_FOLDER_GID_<KEY>`, project 2 call 4);
        - `create mask 0660`, `directory mask 2770`.

        Files therefore land as `<person uid>:<folder gid>`, which is what
        project 2 keeps consistent.
    - Unix groups inside the container exist only for `valid users = @…`.
      Their in-container gids never reach the disk (`force group` decides).
13. **Former accounts' data is never reused.** Before serving a person's home
    or Time Machine folder, `portcullis-sync` checks its owner.
    - If the folder is owned by another uid (a deleted account whose
      username was created again), it is **not** served.
    - The hook reports it, and project 2's doctor shows a finding: "alice's
      Time Machine folder belongs to a former account (uid 10023)".
    - Moving or deleting the folder is explain-only (project 2 call 11).
    - Former members' folders stay on disk. The File sharing tab lists them
      with their size.
14. **LAN/VPN only, three layers.**
    - Both templates' SMB ports are `lan_only: true` (project 2 call 12).
      The default bind stays `0.0.0.0` (IPv4).
    - Samba's `hosts allow` comes from the Hub's **Local networks** setting
      (project 2 call 13). It reaches templates as a new reserved variable,
      `PORTCULLIS_LOCAL_NETWORKS` (comma-separated CIDRs), usable by any
      future LAN-only template. Its value when the admin hasn't configured
      anything is call 28.
    - The warning is project 2's exposure finding: Warning for `0.0.0.0`,
      Problem for a public or main-domain address. It also shows:
      - as a banner on the instance;
      - in the enable dialog, which asks the admin to confirm ("SMB will
        listen on every interface of this server. Make sure your firewall
        or router blocks port 445 from the internet; Docker-published ports
        bypass ufw.").
    - It warns and never blocks (the user asked for a warning).
    - `hosts allow` is defence in depth, not a guarantee. Where Docker's
      userland proxy forwards a connection, Samba sees the bridge gateway
      (a private address). The builder verifies source addresses are
      preserved for IPv4 published ports and documents the IPv6 case.
15. **Bonjour/mDNS: off by default, host Avahi opt-in.**
    - **Default:** no advertising. My apps shows the exact address:
      - `smb://<connect address>[:port]/<share>` and the username;
      - for Time Machine: "Finder → Go → Connect to Server, then System
        Settings → Time Machine → Add Backup Disk".
    - **Opt-in:** the admin sets the path option "Host Avahi services
      directory" (e.g. `/etc/avahi/services`; the host runs `avahi-daemon`).
      - The container's own Avahi is disabled.
      - The template writes one service file, `portcullis-<instance>.service`.
        It advertises `_smb._tcp` on the published port; for Time Machine
        also `_adisk._tcp` with the share entries and `_device-info._tcp`
        with the model.
      - The host's Avahi announces the host's own name, which is where the
        ports are published.
      - Samba uses the image's built-in `/external/avahi` mode. Time Machine
        copies mbentley's generated `smbd.service`, adjusted.
      - Disabling the option removes the file.
    - **Not used:** host networking (it collides with the host's Avahi and
      Samba, binds every interface, allows one instance per host, and
      `network_mode` can't be a setting) and macvlan (host-specific network
      config, and the host can't reach the container).
    - Advertising lists every Time Machine share name, and those contain
      usernames, to the whole LAN. The option's help says so (open
      question 3).
16. **Per-person uids: a Hub-wide pool** (settles project 2 open
    question 4; amends project 1 call 20).
    - `person_id` gains `pool:`. Every option in every instance with the same
      pool shares one allocation per person. The file-sharing templates use
      pool `posix_uid`, range 10000-59999. That is clear of project 2's
      folder gids (60000-60999) and of 65534.
    - Allocated the first time a person needs one, never reused (deleted
      people are tombstoned), kept in Hub state, carried by the Hub's own
      backup.
    - A template states "each person's uid" as
      `runs_as: {uid_from: <person_id key>, gid: folder}` in its `folder`
      block. The per-person private group form
      `runs_as: {uid_from: …, gid_from: …}` is call 29.
    - `person_id` is never shown on My apps (`self_visible: false`).
17. **Router-less templates.**
    - Both templates are `auth.method: custom` with no Traefik router and
      `access_group` = the instance's `users_<id>`.
    - The access group decides who may create a password; it has no other
      effect.
    - Portal, policy and the app detail show "No web page: file sharing over
      SMB". My apps still lists the instance (project 1's population is the
      access group).
    - If Discover or policy code needs a router today, the builder makes the
      minimal generic change (zero routers allowed for `custom`) rather than
      adding a new auth method.
18. **Two instances, two ports.** Both templates are `instances: multi`. A
    second SMB instance on the same host must take another port or another
    bind address (the existing collision check). My apps shows the port in
    the address when it isn't 445.
19. **Username rule.** A person whose LLDAP username isn't a valid Samba and
    Unix name can't create a password. My apps shows the reason instead of
    the button. The rule: `^[a-z_][a-z0-9_.-]{0,31}$`, and not a name that
    exists in the image (`root`, `nobody`, `timemachine`, …; list checked by
    the template). The template declares the rule and the Hub enforces it
    generically (call 27).
20. **New Hub routes.**
    - People listener, contract §5.1 changed first, both added to the
      `TestPeopleListenerHasNoAppRoutes` allowlist next to `GET /api/me/apps`:
      - `POST /api/me/apps/{instance}/credentials/{key}` (create or
        regenerate; body: the fresh-auth ID token; answers the password
        once);
      - `DELETE …/{key}` (revoke your own).

      Both act for `X-Forwarded-User` only. They refuse with 404 when the
      caller isn't in the instance's population.
    - Hub listener (admins): `GET /api/instances/{id}/credentials` (metadata
      only) and `DELETE /api/instances/{id}/credentials/{key}/{user}`.
    - Audit:
      - `credential.create`, `credential.regenerate`, `credential.revoke`
        (actor = self or admin), `credential.revoke_leave`,
        `credential.void_restore`;
      - fields: instance, key, username, actor, reason; never the secret or
        hash.
    - `My apps` `credentials[]` (project 1 call 20) holds for each:
      - label, status (`none` / `active since <date>` / `voided by restore`
        / `not available: <reason>`);
      - connect address, username, share names.
21. **Storage checks.**
    - Time Machine storage and Samba homes are `path` options with
      project 2 checks:
      - `filesystem` (`needs: [xattr]`, `not: [nfs, cifs, fuse]`);
      - Time Machine also `exclusive`.
    - Samba `shares` rows add `needs: [acl]` through the folder's own checks.
    - The empty default is a named volume (`portcullis_<id>-data`), where
      the Hub can't move data.
22. **Testing.**
    - Unit:
      - password alphabet and length;
      - NT hash against known vectors;
      - fresh-auth verification (stale `auth_time`, file-certificate `amr`
        refused);
      - the people routes answer only for the caller;
      - hashes absent from state, logs, op records, audit and backups (a
        `TestCredentialNotEchoed` in the style of `TestTokenNotEchoed`);
      - revoke-on-leave bypasses the debounce;
      - restore voids credentials.
    - CI e2e with `smbclient`, against both templates:
      - the password works;
      - `-m SMB2`, NT1/NTLMv1 and unencrypted sessions are refused;
      - a client outside the Local networks is refused (test CIDR);
      - the `testparm` guard stops a tampered config;
      - after a member is removed, login fails and the open session is
        dropped within 10 s;
      - a regenerated password works and the old one doesn't;
      - with no people there are no accounts (and no `timemachine` account);
      - a file written to a shared folder share is `<uid>:<folder gid>`.
    - Live, on a Mac against the test server:
      - a Time Machine backup over encrypted SMB3;
      - the 10 GiB limit is honoured;
      - discovery via the host's Avahi;
      - Finder access to Samba.

## Example: the template declaration

Time Machine (`timemachine/manifest.yaml`, abridged; project 1's settings
format, project 2's `folder`/`checks`/`lan_only`):

```yaml
name: Time Machine
description: Mac backups over SMB, one share per person
instances: multi
auth: {method: custom, access_group: "{{ACCESS_GROUP}}",
       notes: "No web page. SMB with per-person file-share passwords; LAN/VPN only."}
ports:
  - {key: TM_SMB, label: SMB, container: 445, default: 445, protocol: tcp,
     service: timemachine, lan_only: true}
files:
  - {name: people, service: timemachine, mount: /portcullis/data}        # directory mount
hooks:
  - name: sync
    service: timemachine
    command: [/portcullis/portcullis-sync]
    when: [start, settings_change, membership_change, credential_change]
    timeout: 60s
settings:
  sections: [Access, Backups, Network]
  options:
    - key: share_password
      label: File-share password
      type: person_secret
      hash: nt
      length: 24
      delivery: file                    # → <secrets>/share_password/<user>.nt, mounted ro at /portcullis/secrets
      mount: {service: timemachine, path: /portcullis/secrets}
      revoke_on_leave: true
      on_restore: void
      applies: live
      section: Access
    - key: uid
      label: File owner id
      type: person_id
      pool: posix_uid                   # Hub-wide, 10000-59999
      self_visible: false
      delivery: [{file: {name: people, field: uid}}]
    - key: size_limit
      label: Backup size limit
      type: size
      step: 1GiB
      allow_unlimited: true
      scope: person
      default: 500GiB
      resolve: max
      section: Backups
      applies: live
      delivery: [{file: {name: people, field: size_limit,
                         render: {unit: MiB, integer: true, unlimited: ""}}}]
      checks: [{kind: requires_group_value, reason: "Most people should get a deliberate limit"}]
    - key: storage
      label: Backup storage
      type: path
      target: {service: timemachine, mount: /opt}
      folder:
        access: write
        runs_as: {uid_from: uid, gid: uid}   # private group per person
        joins_group: template
        checks:
          - {kind: filesystem, needs: [xattr], not: [nfs, cifs, fuse],
             reason: "Time Machine stores metadata in extended attributes"}
          - {kind: exclusive, reason: "Backup bundles must not be written by other apps"}
    - key: share_prefix
      label: Share name prefix
      type: string
      pattern: "^[A-Za-z0-9][A-Za-z0-9 _-]{0,31}$"
      default: TimeMachine
      applies: live
    - key: connect_address
      label: Address people connect to
      type: string
      format: hostname                  # an IP address must also be accepted (project 1 format list)
      required: true
      section: Network
      self_visible: true                # shown on My apps as the server address
    - key: avahi_services_dir
      label: Host Avahi services directory (Bonjour advertising)
      description: "Empty = off. Advertising shows every share name, which contains usernames, to everyone on the local network."
      type: path
      target: {service: timemachine, mount: /external/avahi}
      section: Network
      applies: restart
    - key: model
      label: Shown in Finder as
      type: enum
      options: [{value: "TimeCapsule8,119", label: Time Capsule}, {value: "MacPro7,1", label: Mac Pro}]
      default: "TimeCapsule8,119"
      delivery: [{env: MIMIC_MODEL}]
      applies: restart
      section: Network
# locked in compose.yml (not settings): CUSTOM_SMB_PROTO=SMB3, CUSTOM_SMB_AUTH=ntlmv2-only,
# HIDE_SHARES=yes, SET_PERMISSIONS=false, EXTERNAL_CONF=/run/portcullis/conf,
# tmpfs /run/samba, ulimits nofile 65536, cap_drop ALL + the minimal cap_add set.
```

Samba (`samba/manifest.yaml`, the part that differs):

```yaml
settings:
  options:
    - key: homes
      label: Personal folders
      type: path
      target: {service: samba, mount: /homes}
      folder: {access: write, runs_as: {uid_from: uid, gid: uid}, joins_group: template}
    - key: shares
      label: Shared folders
      type: table
      key: name
      columns:
        - {key: name, type: string, pattern: "^[A-Za-z0-9][A-Za-z0-9 _-]{0,31}$"}
        - {key: folder, type: folder, mount: "/shares/{name}",
           runs_as: {uid_from: uid, gid: folder}, joins_group: template}
        - {key: readers, type: groups}
        - {key: writers, type: groups}
      applies: restart                  # new mounts; group edits alone apply live
      delivery: [{file: {name: people, field: shares, render: {expand_members: true}}}]
```

## Example: the resulting UI behaviour

**people.<domain> → My apps** for alice, who is in `users_timemachine` and
`office_milan`:

```
Time Machine                                         No web page · SMB
  Backup size limit   10 GiB   from office_milan · Time Machine keeps backups within this size
  File-share password  none yet                      [ Create password ]
  Connect: smb://nas.home.arpa/TimeMachine-alice   ·  username: alice
  How to add it on your Mac ▸
```

- **Create password** → "Touch your passkey to continue" (fresh sign-in) →
  a dialog:

  ```
  Your file-share password for Time Machine
    h7Kq-3xRm-Pd9w-Zt4c-Nb2v-Yf6s        [ Copy ]
  This is the only time it is shown. Save it in your Mac's Keychain when
  Time Machine asks. It works only for Time Machine on this server.
                                         [ I've saved it ]
  ```

  Closing the dialog clears it. The card then shows "Password active since
  2 Nov 2026 · [ Regenerate ] [ Revoke ]". Regenerate asks for a fresh touch
  and warns: "Your Mac will ask for the new password; running backups stop."
- People without access to Time Machine see no Time Machine card at all.
- After a restore: "Your password was reset by a restore on 5 Nov 2026.
  [ Create password ]".
- A username Samba can't use: "File sharing isn't available for the username
  `Alice.Smith@x`; ask an administrator." No button.

**Hub → Apps → Time Machine → File sharing tab** (admin):

```
⚠ SMB (port 445) listens on all interfaces (0.0.0.0). File sharing should only be
  reachable from your local networks or VPN.                 [ Rebind… ] (doctor)
People with access: 42 · passwords: 17
  alice   uid 10007   10 GiB   password since 2 Nov 2026     [ Revoke ]
  bob     uid 10011    2 TiB   no password
  …
Former members' folders: carol (uid 10003) 182 GiB · kept on disk
Last sync: ok, 2 Nov 2026 14:03 (live, no restart)
```

- When bob leaves `users_timemachine`, a few seconds later his row
  disappears. The audit shows `credential.revoke_leave instance=timemachine
  user=bob`, and his Mac's running backup is disconnected.
- Settings → Backups is project 1's panel (the "who gets what" preview,
  `office_milan` 10 GiB). Its apply line reads "Applies live, no restart".

## Interfaces with the other projects

- **Project 1 (settings panel)** provides, and this project needs:
  - `person_secret` and `person_id` implemented to the shapes reserved in its
    call 20, plus:
    - `pool` on `person_id` (call 16; replaces "per instance");
    - `on_restore: void`;
    - the `mount` of the secrets directory;
  - file deliveries and the secrets file mounted as **directories** (call 7);
  - the hook trigger `credential_change`, and the revoke-on-leave bypass of
    the debounce (call 6);
  - the `table` column types `folder` (project 2) and `groups`, a per-row
    mount pattern, and `render: {expand_members: true}`. That render puts the
    current members of each referenced group, limited to the instance's
    population, into the data file;
  - `GET /api/me/apps` `credentials[]`, and the people-listener allowlist that
    the two routes of call 20 join.
- **Project 2 (shared folders + doctor)** provides:
  - the `folder` block (`joins_group: template`) and
    `PORTCULLIS_FOLDER_GID_<KEY>`;
  - the `lan_only` port check with Local networks, and the `filesystem` /
    `exclusive` / `requires_group_value` check kinds;
  - the exposure finding and its Rebind fix.

  This project adds:
  - `runs_as.uid_from` (call 16);
  - `PORTCULLIS_LOCAL_NETWORKS` (call 14);
  - two doctor checks through project 2's internal check interface: "folder
    owned by a former account" (call 13) and "password active for someone
    without access" (should never fire; it is a canary for a failed
    revocation).
- **Certificates spec:** the shared fresh-auth client and verifier (call 1).
- **Contract** (`integration-contracts.md` first):
  - §3: router-less `custom` templates, `PORTCULLIS_LOCAL_NETWORKS`;
  - §5.1: the people routes;
  - §11.5: backups exclude `person_secret`;
  - §13 (project 1): `person_secret`, `person_id` `pool`,
    `credential_change`, the hook stdin `credentials` shape.

## Left to the builder

- Exact image pins (ServerContainers `a…-s…` tag and mbentley `smb-YYYYMMDD`
  snapshot, both by digest); the minimal `cap_add` set that smbd needs after
  `cap_drop: [ALL]`, verified in CI.
- How `portcullis-sync` edits each image's generated `smb.conf` (in-place
  `[global]` edit, an included file, or `CUSTOM_SMB_CONF=true` with a fully
  rendered file for Time Machine), as long as call 10's verification holds.
- How to end a revoked person's sessions (`smbstatus` + `smbcontrol <pid>
  close-share` / terminating that user's smbd), within the 10 s target.
- Fresh-auth plumbing details if the certificates project hasn't built them
  yet; route payload shapes; metadata file location.
- UI layout within the existing styles; the macOS/Windows how-to text.
- Whether mbentley's entrypoint copes with an empty `EXTERNAL_CONF` directory
  (no people yet); if not, the wrapper starts it with a placeholder that
  creates no account.

## Open questions

1. **For the user: quotas on Samba folders.** Samba can't cap a user's
   folder. `fruit:time machine max size` is cooperative and only for Time
   Machine shares. Real limits need host filesystem quotas (XFS or ext4
   project quotas), which is host setup. Accept "no Samba folder quotas" in
   v1, or plan quotas through the host?
2. **For the user: "disabled" on leaving.** This draft destroys the password
   (call 5), so a returning person creates a new one. Is that what you meant,
   or should it come back when they rejoin?
3. **For the user: Bonjour shows usernames.** With advertising on, every Time
   Machine share name (`TimeMachine-alice`) is visible to the whole LAN.
   Acceptable with the warning, or should share names be opaque (e.g. a
   per-person code people see on My apps)?
4. **For the user: former members' data.** It is kept and listed (call 13).
   Should admins get a guarded "delete this folder" (typed name, like
   instance delete), or is that left to the host?
5. **Encrypted SMB and Time Machine speed.** Required encryption is the
   user's decision. The live test measures the throughput cost on Wi-Fi, so
   nobody is surprised; no change is proposed.
6. **Projects 1 and 2 acceptance** of the interface items above, in
   particular the Hub-wide uid pool (it changes project 1 call 20) and
   `folder`/`groups` table columns. The fallback for the Samba shares table
   is a fixed number of share slots (e.g. 8), each a `path` option with a
   `folder` block.
