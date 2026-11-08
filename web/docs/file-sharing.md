# File Sharing

Portcullis provides SMB3 file sharing through the Samba and Time Machine templates. Each person creates their own file-share password after a fresh passkey sign-in, sees it once, and can regenerate or revoke it at any time.

## How It Works

- **Per-person passwords:** Each person has their own password for file sharing, separate from their Portcullis sign-in. Admins list and revoke credentials but never create them (an admin who created one would have seen it).
- **Self-service:** People create and regenerate their passwords on [My apps](hub.md#my-apps) (`https://people.<domain>`). A fresh hardware sign-in (passkey touch) is required for each create or regenerate.
- **No web page:** File-sharing apps serve only SMB3 (no HTTP), so they appear without hostnames in the app catalog.
- **Hub-allocated ids:** Each person gets a stable Unix uid (20000–59999), allocated once and never reused. Files land as `<person's uid>:<folder's gid>`.

## Apps

| App | What it serves |
|-----|----------------|
| **Samba** | Eight configurable share slots (readers/writers per slot, each pointing at a shared folder) plus a private Home share per person |
| **Time Machine** | One private backup share per person with a size limit |

Both use hardened SMB3 (encryption required, NTLMv2 only, SMB2 refused) and trust only the Local networks you configure.

## Setup

### 1. Enable Users & Groups

File sharing needs [Users & Groups](../setup/quickstart.md#step-5-create-users): who may create a password is decided by the instance's access group in LLDAP, and every password belongs to an LLDAP account.

### 2. Configure Local Networks

File sharing should only be reachable from your LAN or VPN. Go to **Hub → Settings → Local networks** and list the CIDRs that count as local:

- **Default:** RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), IPv6 ULA (`fc00::/7`) and the Tailscale range (`100.64.0.0/10`).
- **Empty list** (`[]`): loopback only. File sharing then refuses to start (the Hub writes `PORTCULLIS_LOCAL_NETWORKS` empty, and the templates fail closed).

When you save a changed list, every enabled app that reads it (the file-sharing apps) restarts.

### 3. Create an Instance

Create a Samba or Time Machine instance from the catalog and give it an id (e.g. `samba-office`). File-sharing apps have no web page, so there is no hostname to choose.

File-sharing apps have `instances: multi`, so you can run several Samba or Time Machine instances for different groups.

### 4. Configure It

Each app has settings:

**Samba:**

- **Connect address** (required): the hostname or IPv4 address people connect to (e.g. `nas.home.arpa` or `192.168.1.10`). IPv6 addresses and single-label names like `nas` are refused.
- **Home folders:** the host directory holding each person's private folder (`<username>`, owned by their uid, mode `0700`), shared as `Home`. Empty = a Docker volume.
- **Eight share slots:** for each slot, a [shared folder](hub.md#shared-folders) assignment (the host path), a share name (what people see in `smb://<address>/<name>`), and reader/writer groups (expanded to the members with access to the instance).

**Time Machine:**

- **Connect address** (required): as above.
- **Backup storage:** the host directory holding each person's backup folder. Empty = a Docker volume.
- **Backup size limit:** per person (cooperative: Time Machine prunes to fit).
- **Share name prefix:** each person's share is `<prefix>-<username>` (default `TimeMachine`).

Both apps also have:

- **Username rule:** usernames the app can serve (a pattern plus reserved names). A person whose username fails sees "File sharing isn't available for your username: …" on My apps, with no button.
- **Bonjour (optional):** advertise shares to the local network. Off by default. Enable it by mounting your host's Avahi services directory (usually `/etc/avahi/services`) and ticking "Advertise". macOS and iOS clients then see the shares in Finder → Network. **Warning:** advertising shows every share name and username to the local network. Turn it off before clearing the Avahi directory.

### 5. Add People

Add the people who should use the instance to its access group,
`users_<id>` (e.g. `users_samba-office`), in [Users & Groups](hub.md#users-groups).
Only members of that group see the instance on My apps and can create a
password. On Samba, put people in the reader and writer groups of the
shares they should open too. To share a folder with everyone who has
access, pick `users_<id>` as its reader group.

### 6. Bind the Port

Each app publishes port 445/tcp, marked `lan_only: true`. The Hub's [doctor](hub.md#doctor) warns if the bind makes it reachable from outside your local networks:

- **Bound to `0.0.0.0`:** Warning. The doctor offers a one-click rebind to a LAN address you type.
- **Bound to a public address:** Problem.

Ports on `0.0.0.0` or `::` bypass host firewalls like ufw, so rebind to a LAN address or make sure your router blocks port 445 from the internet.

## Connecting

Once the app is enabled, people visit [My apps](hub.md#my-apps) (`https://people.<domain>`) and:

1. Click [Create password] on the app's card.
2. A popup asks them to touch their passkey (a **fresh** sign-in, even if they signed in seconds ago).
3. The password is shown **once** as 6 groups of 4 characters joined by `-` (29 characters total, e.g. `a2bC-d3eF-g4hJ-…`). The dashes are part of the password.
4. After "I've saved it", the password disappears from the DOM. It is never shown again and never logged.

The card then shows two lines:

- **Connect:** `smb://<connect address>/Home` on Samba, or `smb://<connect address>/<prefix>-<username>` on Time Machine (`TimeMachine-<username>` by default). A port other than 445 is part of the address.
- **Username:** the person's username.

The card doesn't list Samba's shared folders. A share's address is `smb://<connect address>/<share name>`: tell people the share names they may use.

### macOS

1. Open **Finder → Go → Connect to Server** (`⌘K`).
2. Enter the server address: `smb://<address>`.
3. Click **Connect**.
4. Choose **Registered User**, enter your **username** (lowercase, the one shown on My apps) and the **file-share password** (not your Portcullis passkey).
5. Select the share (Home, or the share name).

macOS then mounts it in `/Volumes/<share name>`.

**Time Machine:**

1. Connect to the server as above and mount your share (`TimeMachine-<username>`).
2. Open **System Settings → General → Time Machine**.
3. Click **+** (Add Backup Disk).
4. Select your share.
5. Time Machine keeps backups within the size limit you set in the Hub.

### Windows

1. Open **File Explorer**.
2. In the address bar, type `\\<address>\<share>` (e.g. `\\nas.home.arpa\Home`).
3. Press Enter.
4. Enter your **username** (lowercase) and **file-share password**.
5. Tick **Remember my credentials** if you want Windows to save it.

Windows then shows the share in This PC → Network Locations.

**Mapping a drive letter:**

1. Right-click **This PC** → **Map network drive**.
2. Choose a drive letter.
3. Enter the folder: `\\<address>\<share>`.
4. Tick **Reconnect at sign-in**.
5. Click **Finish** and enter your credentials.

## Managing People

**People should be managed through the Hub's [Users & Groups](hub.md#users-groups), not directly in LLDAP.** Here's why:

- **Hub-made changes** (removing a member, deleting a user or group) revoke file-share passwords **at once**, with no delay.
- **LLDAP-direct changes** (e.g. removing a user from a group in LLDAP's web UI) are caught by the evaluator's 60-second tick. The worst case is **about 60 seconds plus the revocation hook**; measured: 3.4–51.8 seconds. A changed LLDAP password doesn't touch the file-share password: they are separate.
- **Leaving a share's group:** someone removed from a Samba share's reader or writer group loses **that share only**, not their password. Their sessions end, and their other shares and Home stay. A writer who is still a reader keeps the share read-only; measured: 3.5–3.6 seconds.

Revocation always:

1. Removes the hash file from the `hub_secrets` volume.
2. If the app isn't running, that's the end of it: it starts without the account.
3. Otherwise it runs the app's `credential_change` hook directly (at most 8 seconds), which removes the account and ends the person's open SMB sessions.
4. If the hook can't run, fails or times out, the Hub stops the app (`compose down`) and starts it again in the background, so no old session survives. It does the same, without trying the hook, when the hash file could not be removed. Until the Hub's secrets volume is consistent again, it then refuses to start file-sharing apps.

A regenerated password goes the same way: the old hash's removal is applied like a revocation. A backup, restore, delete, restart or disable of the app waits once, up to 10 seconds, for a revocation in flight to finish, then goes on.

### Measured revocation times

From the core `e2e-filesharing` CI job (three runs, plus one more; time from the change until the open session was gone and a new login refused):

| Change | Measured | Notes |
|---|---|---|
| Removal through the Hub (Users & Groups) | 0.8–0.9 s | applied at once by the hook |
| Removal directly in LLDAP | 3.4–51.8 s | caught by the evaluator's 60 s tick: worst case about 60 s plus the hook |
| Writer demoted to reader | 3.5–3.6 s | the share's `write list` is applied and the person's sessions end |

## Security

### Password Storage

- **Never in clear text:** The password is shown once, then zeroed in memory. The Hub stores only its **NT hash** (MD4 over the UTF-16LE encoding of the dashed password, as a 32-character hex file).
- **Never logged or backed up:** Neither the password nor the hash appears in `state.yaml`, logs, the audit, hook output, or any backup (instance or core).
- **Secrets volume:** Hashes live on their own volume (`hub_secrets`), never on `hub_data`. It is **not backed up** and is **emptied** by a core restore (`./portcullis restore`).

The passdb and Samba's state directories are on tmpfs (`/var/lib/samba`, `/var/cache/samba`, `/run/samba`, `/run/portcullis`), so no hash ever reaches a Docker volume or an instance backup.

### Hardened SMB

Both templates enforce exactly these settings in `smb.conf` (contracts §13.17):

```ini
[global]
server min protocol = SMB3
server smb encrypt = required
server signing = mandatory
ntlm auth = ntlmv2-only
lanman auth = no
map to guest = never
restrict anonymous = 2
disable netbios = yes
smb ports = 445
wide links = no
follow symlinks = no
smb3 unix extensions = no
hosts allow = <Local networks, space-separated>
hosts deny = 0.0.0.0/0 ::/0
```

And for every share:

```ini
guest ok = no
```

`testparm -s` must show exactly these values. SMB2, NTLMv1, guest access and unencrypted sessions are all refused, and the images' own config switches do nothing (their entrypoints never run).

**When the check fails (fail closed):**

- **At boot**, the converge script exits 4 before smbd starts, so the container exits and Docker restarts it (a restart loop). Its logs say why.
- **At hook time** (a setting, membership or password change), any failure after the script started changing things brings smbd down. The container stays up and turns unhealthy, and a down marker keeps smbd from starting again, whatever its supervisor does. The app's Deliveries strip shows the failed `sync` hook.

**Bringing smbd back:** fix the cause, then run the hook again: click **Retry** on the app's Deliveries strip, or make any change that runs it. smbd comes back with the first hook run that succeeds. A restart of the app also brings it back, because the boot starts with a fresh tmpfs, and its own checks still apply.

See also [Hardening](hardening.md#file-sharing) for the capabilities and container configuration.

### Hosts Allow and the Userland Proxy

**Measured on the test server** (Docker 29.9.3, default settings: `userland-proxy` on): a connection to a published Samba / Time Machine port, even one bound to `127.0.0.1`, reached smbd from the **bridge gateway of the instance's own network** (for example `192.168.64.1`), not from the client's address: Docker's `docker-proxy` relayed it. The gateway sits in Docker's default address pools (`172.17.0.0/16`–`172.31.0.0/16`, then `192.168.x.0/20` once those are used), which are inside the default Local networks (`172.16.0.0/12`, `192.168.0.0/16`). So with the userland proxy on, **`hosts allow` can't tell clients apart**: every client looks local.

What actually limits who can connect:

- **Who can reach the published port.** Publish on a LAN address only (rebind the port in the Hub), and keep the host firewall closed to anything outside your LAN. This is the real boundary.
- **Disabling the userland proxy** (`"userland-proxy": false` in `/etc/docker/daemon.json`, then restart Docker) lets Docker forward with NAT, so smbd should see the real client address and `hosts allow` works as defence in depth. This was not measured for a LAN client here (the test server can't publish SMB beyond loopback).
- Narrowing Local networks does **not** help while the proxy is on: the gateway is still in a range you probably also use for the LAN.

## Credentials

### Viewing Them

**Admins** see every credential on the instance's File sharing tab (Hub Management):

- **Status:** none, active (with the creation date), voided (by a restore), revoked (self / admin / leave / deleted), or unavailable: the username doesn't meet the template's rule (its pattern and reserved names) or the hard rules every file-sharing app applies: no `/`, no `..`, no leading `.` or `-`, and not `pfg<digits>`.
- **Person ids:** each person's Unix uid.
- **Per-person values:** their displayed person-scope settings (e.g. the Time Machine size limit).
- **Former members' folders:** top-level directories in per-person trees (Home, Time Machine storage) whose owner isn't the person's current uid, with sizes (or "size unknown").
- **Last sync:** when the app's `sync` hook last ran (ok / skipped / failed).

### Regenerating

A person regenerates their password by clicking [Regenerate] on My apps (after a fresh sign-in, like a create). The old hash's removal is applied like a revocation: the hook runs within 8 seconds, or the Hub stops and restarts the app. So the old password stops working even when the hook is busy or fails, and the sessions that used it end. macOS prompts for the new password; running Time Machine backups stop.

### Revoking

- **Self:** A person clicks [Revoke] on their own card. No fresh sign-in needed. Their hash file and metadata go, and the hook ends their sessions.
- **Admin:** An admin clicks [Revoke] on the File sharing tab. Same effect, audited with the admin as actor.
- **Automatic:** The Hub revokes when the person leaves the instance's access group or their account is deleted (reasons: `leave`, `deleted`). These are immediate (Hub-made) or caught within about 60 seconds (LLDAP-direct). Leaving a share's reader or writer group is not a revocation: it drops that share only (see [Managing People](#managing-people)).

A revoked credential is **destroyed**, not paused. Coming back means creating a new password.

### Restores

- **Instance restore** (`POST /api/instances/{id}/restore`): Every active credential of the instance is voided (`reason: restore`, audited `credential.void_restore` with the count). My apps then shows "Your password was reset by a restore on <date>; create a new one."
- **Core restore** (`./portcullis restore`): The `hub_secrets` volume is **emptied** (removed and re-created with its labels and ownership). The Hub detects it at start via the **secrets epoch** (a random 16-byte value in both `state.yaml` and `<secrets>/.epoch`). Every credential of every instance is voided, every hash file deleted, and every person-id pool's next uid advances by 1000 (so a pool restored from an older `state.yaml` never hands out a uid that files may already carry). People create new passwords on My apps.

The two restores stop the apps differently:

- **Instance restore:** the Hub stops that one instance for the restore and voids its passwords before it starts it again. If the instance was enabled, it is enabled again; other instances aren't touched.
- **Core restore:** before anything changes, it stops the Hub, then takes down every app project with a container mounting `hub_secrets` (volumes kept). If that fails, or a container is left, the restore aborts with nothing restored and starts the Hub again, so the Hub is running; if starting it fails, the message says so. The Hub starts again with the core, but the apps stay down: the restore lists them, their drift shows them not running, and you start each one again from the Hub.

## Filesystems

Per-person trees (Home, Time Machine storage) and Samba share folders need:

- **Extended attributes:** macOS clients store metadata (Finder tags, resource forks) in `com.apple.*` xattrs.
- **Not NFS, CIFS or FUSE:** The Hub can't keep ownership consistent where a server or VM host decides it, or under virtiofs.

The Hub's [doctor](hub.md#doctor) checks these when you assign a shared folder or run Check path. For Samba shares, it also checks ACL support (needed for the folder's group ownership).

If your folder is **its own filesystem** (a ZFS dataset or btrfs subvolume), the one-click fix can't touch it: the Hub refuses a different mount. **Fix it on the host:** `chown <uid>:<uid>` the folder, then `chmod 0700` it, where `<uid>` is the person's id from the File sharing tab (the one-click fix changes only the folder itself, not what is inside).

