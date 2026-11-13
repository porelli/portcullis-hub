# Backups

`./portcullis backup` makes a **consistent** backup while everything keeps
running. `--offsite` also uploads it, encrypted, to a
[restic](https://restic.net) repository on another machine or in object
storage. `./portcullis backup verify` proves that a backup can be restored, and
`./portcullis restore` puts one back, on the same host or on a new one.

!!! danger "A backup is the keys to everything"
    A backup contains `secrets/`, which holds the Vault **root token and unseal
    key**, plus `.env` with every password. Whoever has a backup can decrypt
    the CA and impersonate any user. For off-host copies, that also takes
    `BACKUP_PASSWORD`.

    - Local backups are mode `0700`.
    - Off-host copies are only as safe as `BACKUP_PASSWORD`.

!!! warning "Store `BACKUP_PASSWORD` offline"
    `./portcullis init` generates `BACKUP_PASSWORD`. Keep a copy in a password
    manager or on paper in a safe, not only in `.env`. If the host is lost,
    `.env` is lost with it, and the off-host backups are useless without the
    password. Never rotate it: existing snapshots are encrypted with it.

## What is backed up, and how

| Piece | How | Why this way |
|-------|-----|--------------|
| Vault (the internal certificate authority's keys, issued YubiKey and browser certificate records, CRLs, AppRole) | Raft snapshot (`sys/storage/raft/snapshot`, root token) → `vault.snap` | Consistent point-in-time copy without stopping Vault |
| Keycloak database | `pg_dump -Fc` → `postgres.dump` | A raw copy of a running Postgres data directory is not consistent |
| LLDAP (`lldap_data`) | Files, with every SQLite database copied through SQLite's online backup API → `lldap_data.tar.gz` | Consistent while LLDAP runs. Keeps `private_key` (password hashing) |
| Hub state (`hub_data`), ACME account and certs (`traefik_acme`), the AI access log (`mcp_gate_data`), group-gate's opened log (`group_gate_data`, part of everyone's [sign-in history](auth-policies.md#sign-in-history), kept a year by default) | Same → `hub_data.tar.gz`, `traefik_acme.tar.gz`, `mcp_gate_data.tar.gz`, `group_gate_data.tar.gz` (restored owned `10003:10001`) | `hub_data` includes the AI model provider keys in clear (`ai/provider-secrets.json`) and the AI app credentials encrypted to the gate's key, which is in `secrets/mcp-gate/` (lose that key and every AI resource answers `503` until the app credentials are dropped: [AI support residuals](ai.md#residuals)) |
| `.env`, `certs/`, `secrets/`, `config/`, `keycloak/realm-export.json`, `headscale/config.yaml`, `docker-compose.override.yml` | Copied | |
| **File-share credentials (`hub_secrets`)** | **Never backed up** | Hashes are voided by every restore ([File Sharing](file-sharing.md#restores)) |
| `MANIFEST.json` | Format, time, core version, Hub and Keycloak images, sha256 of every file | `verify` and `restore` refuse a backup whose files changed |

A backup is built in `backups/<timestamp>.partial/` and renamed to
`backups/<timestamp>/` when it is complete. The newest `BACKUP_KEEP_LOCAL`
(default 7) local backups are kept. `./portcullis upgrade` makes one first.

App data in Hub-managed apps (their own `portcullis_*` volumes) is **not** part
of the core backup.
Back those up per app instance in the Hub (**instance backups**): the Hub's
**Backups** tab (per instance) can back up, restore and delete instances
([Hub Management](hub.md#instance-backups)). An instance backup archives:

- the instance's Docker volumes (via helper containers, with owner uid/gid preserved)
- its state, settings, `.env` (including generated secrets), custom override and published policy
- its AI state (`config/ai.json`: which companions are on, their modes, an AI page's provider selection). Never an AI credential: model provider variables are blanked in the archived `.env` and rewritten from the Hub's store on restore, and every restore revokes the app's earlier AI credentials (`revoke_all`) before its companions are used again. The app's own data can still carry what the app keeps there: Home Assistant's `/config` holds the hook user's token, rotated at the next container start after a restore

**File-share credentials are never in instance backups:** the `hub_secrets` volume is external to the instance's project, so it is never archived, replaced or removed by a backup, restore or delete of the instance. An instance restore voids every active credential (`reason: restore`): people create new ones on My apps. See [File Sharing](file-sharing.md#restores).

These are stored in `<hub data>/backups/<instance-id>/<UTC timestamp>.tar`
(sha256-checksummed). The Hub also takes an automatic backup before every
instance restore and delete. Instance backups live in `hub_data`, so the **core
backup** (and `--offsite`) includes every instance backup taken so far. They are
never pruned automatically and hold app secrets in clear: protect them like the
rest of the backup.

An instance backup can be restored into the same instance (replacing its data)
or into a **new instance id** (creating a copy). See [integration contracts
§11.5](../guides/integration-contracts.md#115-backups).

### Shared folders and host paths

**Neither backup copies the files in a [shared folder](hub.md#shared-folders)
or in any host path an app mounts** (`/srv/media`, a photo library, …).
Instance backups copy Docker volumes only, and the core backup copies the
core's own volumes and files. Back those directories up with your own host
tools (restic, borg, ZFS or Btrfs snapshots, a NAS job).

What the backups do hold:

- **Folder definitions** (name, path, gid, the gids ever allocated) are in
  the Hub's `state.yaml`, so in the core backup. An instance backup keeps the
  instance's settings, `folder:<id>` values included. Restoring it where
  that folder doesn't exist clears those values with a warning ("setting <k>
  named shared folder <id>, which doesn't exist; cleared"); restoring into a
  new instance id warns about the folders the copy now uses.
- **Permissions snapshots.** Every folder apply first saves a snapshot of
  the permissions it is about to change (path, inode, owner, group, mode and
  ACLs of each entry, not the contents) in
  `<hub data>/folder-snapshots/<folder>/<UTC timestamp>.ndjson.gz` with a
  `.sha256` next to it (files `0600`); the last 3 per folder are kept, plus
  the one Undo needs. They are what **Undo last fix** restores, and they are
  in `hub_data`, so in the core backup. An undo saves a safety copy of what
  it rewrote the same way, but an undo itself can't be undone.

A permissions snapshot only undoes a permissions fix on the same folder: it
records inodes, so it doesn't apply to files restored from another backup.

!!! note "First backup on a fresh host"
    On a host without the `group-gate` image (a fresh install before the first `portcullis up`, or after `docker image rm`), `./portcullis backup` builds it first (needs network access to Docker Hub and PyPI for the pinned, hashed Python dependencies: cryptography, PyJWT).

```bash
./portcullis backup            # local backup
./portcullis backup --list     # local backups
```

## Off-host backups (restic)

Configure the repository in `.env`:

```bash
# Any restic backend the container can reach: s3:, b2:, azure:, gs:, rest:,
# or a local path (e.g. an NFS / USB mount).
BACKUP_REPOSITORY=s3:https://s3.eu-central-1.amazonaws.com/my-bucket/portcullis
# BACKUP_PASSWORD is generated by ./portcullis init: copy it somewhere offline.

# Provider credentials (restic's variable names). BACKUP_<NAME> wins over
# <NAME>, so BACKUP_AWS_* can differ from the AWS_* used for Route53 / ACME.
BACKUP_AWS_ACCESS_KEY_ID=...
BACKUP_AWS_SECRET_ACCESS_KEY=...
# B2_ACCOUNT_ID / B2_ACCOUNT_KEY, AZURE_ACCOUNT_NAME / AZURE_ACCOUNT_KEY,
# GOOGLE_PROJECT_ID, RESTIC_REST_USERNAME / RESTIC_REST_PASSWORD, ...

# Retention applied after every upload (restic forget --prune).
BACKUP_KEEP_DAILY=7
BACKUP_KEEP_WEEKLY=4
BACKUP_KEEP_MONTHLY=6
```

```bash
./portcullis backup --offsite                 # local backup, then upload + retention
./portcullis backup --list --offsite          # restic snapshots
./portcullis backup --list --offsite --json   # restic's JSON
```

How the upload runs:

- **Container.** restic runs in its pinned image (`BACKUP_RESTIC_IMAGE` in
  the core repo's `scripts/lib/backup.sh`) as your user, with a read-only
  root filesystem and no capabilities.
- **Secrets.** The repository password and the provider credentials are passed
  to the container by variable name, never on a command line.
- **Snapshots.** The first upload initialises the repository. Every snapshot
  has host `portcullis`, tag `portcullis` and path `/portcullis-backup`, so all
  runs form one deduplicated, incremental series.

`sftp:` and `rclone:` repositories are not supported: the container has
neither SSH keys nor rclone. Use `rest:` with
[rest-server](https://github.com/restic/rest-server) instead.

## Verify

```bash
./portcullis backup verify                    # off-host: latest snapshot
./portcullis backup verify --snapshot 1a2b3c4d
./portcullis backup verify --local            # newest local backup (or --local DIR)
```

Off-host verification first runs `restic check`, reading
`BACKUP_VERIFY_READ_DATA` (default `10%`) of the pack data. Then it restores
the snapshot into a temporary directory and checks it like a local backup:

- every file matches `MANIFEST.json`, and `.env`, the root token and the unseal key are present
- `vault.snap` is a raft snapshot (`meta.json`, `state.bin`, its `SHA256SUMS`)
- `postgres.dump` restores into a throwaway Postgres container (no network) and contains the Keycloak realms
- the LLDAP database opens, passes `integrity_check` and has users
- every volume archive is readable

The command exits non-zero if anything fails. Run it regularly, e.g. weekly: a
backup that was never restored is a hope, not a backup.

## Schedule (systemd timer)

The backup has to drive Docker on the host (`docker exec`, throwaway
containers), so it runs from a **systemd timer**, not from a container. A
scheduler container would need the Docker socket, which only the socket
proxies may mount ([contract §6](../guides/integration-contracts.md#6-engine-access)).

```bash
./portcullis backup schedule --systemd --output /tmp/units
sudo install -m 0644 /tmp/units/portcullis-backup.service /tmp/units/portcullis-backup.timer /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now portcullis-backup.timer
sudo systemctl start portcullis-backup.service    # once now; journalctl -u portcullis-backup
```

Under [rootless Podman](rootless-podman.md) the units are **user** units for
the operator's own systemd manager (they need `podman.socket` and run while
nobody is logged in thanks to lingering), and no `sudo` is involved:

```bash
./portcullis backup schedule --systemd --output ~/.config/systemd/user
systemctl --user daemon-reload && systemctl --user enable --now portcullis-backup.timer
systemctl --user start portcullis-backup.service  # once now; journalctl --user -u portcullis-backup
```

What the service does:

- **What it runs.** `portcullis backup --offsite` (just `backup` while
  `BACKUP_REPOSITORY` is unset), then `portcullis status --textfile`.
- **When.** Daily at 03:15, plus up to 30 minutes of random delay, catching up
  after downtime. Change it with `--on-calendar SPEC`.
- **As whom.** The user who generated the units. That user must be allowed to
  run `docker` (under Podman: the operator, through its user manager).
- **Metrics.** Both commands publish metrics for the
  [monitoring profile](monitoring.md), which alerts when the last successful
  local or off-host backup is older than 36 hours.

## Restore

```bash
./portcullis restore --list                     # local backups
./portcullis restore --list --offsite           # restic snapshots
./portcullis restore backups/20261031-031500    # a local backup
./portcullis restore --from-offsite             # latest off-host snapshot
./portcullis restore --from-offsite 1a2b3c4d    # a specific one
```

The restore first checks the backup's checksums. Before anything changes, it
stops the Hub (so nothing can start a file-sharing app again) and takes down
every app project with a container mounting `hub_secrets` (`compose down`,
volumes kept); a failure there, or a container left, aborts the restore with
nothing restored and starts the Hub again (if that start fails, the message
says so). It saves the current `.env`, `secrets/` and `certs/` to
`backups/pre-restore-<timestamp>/`. Then it stops Portcullis and:

1. Restores `.env`, `certs/` and the config files. An existing `config/` repo is left alone. `CONTAINER_RUNTIME` and `PORTCULLIS_ENGINE_SOCKET` keep the host's values, never the backup's ([below](#moving-between-runtimes)).
2. **Empties `hub_secrets`.** The file-sharing apps are already down (above). The `hub_secrets` volume is removed and re-created with its labels and ownership (`10001:10001 0700`). After the restore the Hub voids every file-share password (reason `restore`, audited `credential.void_restore` per instance with the count): people create new ones on [My apps](hub.md#my-apps). The Hub starts again with the core, but never starts the apps taken down: the restore lists them, their drift shows them not running, and an admin starts each one again from the Hub. See [File Sharing](file-sharing.md#restores).
3. Recreates the Postgres and Vault volumes, and `pg_restore`s the Keycloak database into the fresh Postgres.
4. Initialises the fresh Vault with throwaway keys, then force-restores the raft snapshot, which brings back the original keyring. It installs the backed-up `secrets/` and recreates Vault, which auto-unseals with the **original** unseal key.
5. Restores the LLDAP, Hub and ACME volumes.
6. **Checks LLDAP before Keycloak starts.** Keycloak deletes its copy of an LDAP
   user — passkeys included — as soon as a lookup (a sign-in attempt, the Hub's
   cleanup) doesn't find the user in LLDAP. If LLDAP has no users besides
   `admin` and `portcullis-hub` (or no user database at all, e.g. a backup
   without `lldap_data.tar.gz` on a new host) while the restored Keycloak
   database has users, the restore **stops here**: Postgres and Vault are up,
   nothing else is started. Restore a backup that includes LLDAP, or, if the
   users really are gone, re-run with `--allow-empty-lldap`.
7. Runs `vault init`, which refreshes the enroll AppRole secret and the metrics token. Then it starts everything and waits for Vault, Postgres, LLDAP and Keycloak.

Use `--yes` to skip the confirmation.

!!! warning "Restore LLDAP before Keycloak runs"
    Never start the stack with an empty or wrong LLDAP database over a Keycloak
    database that has users: every user's Keycloak copy and passkeys go at the
    next sign-in attempt. `restore` checks this; the Hub's stale-record cleanup
    pauses itself when LLDAP looks wrong ([Hub](hub.md#stale-keycloak-records-admins-only)).

### On a new host

```bash
git clone https://github.com/porelli/portcullis.git && cd portcullis
export BACKUP_REPOSITORY=s3:https://...  BACKUP_PASSWORD='<from your offline copy>'
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=...   # the provider credentials
./portcullis restore --from-offsite
```

`.env` comes from the backup. Then point DNS at the new host. The ACME
certificate is restored too, so Traefik doesn't have to re-issue it.

Without an `.env` the restore detects the runtime as `init` does, before its
first engine call, and writes it into the restored `.env`. On a Podman host
where a Docker engine also answers, export `CONTAINER_RUNTIME=podman` first.

### Moving between runtimes

A backup taken on Docker restores on rootless Podman, and the other way
round: the ids inside the archives are container ids, the same on both, and
`MANIFEST.json` records the runtime it was taken on. The restore always keeps
the **host's** runtime keys: it reads `CONTAINER_RUNTIME` and
`PORTCULLIS_ENGINE_SOCKET` from the `.env` it replaces and writes them back
into the restored one, and onto Docker it drops a `PORTCULLIS_ENGINE_SOCKET`
that a Podman backup carried.

1. Take a backup on the old install (`./portcullis backup`, or `--offsite`).
2. On the new host, prepare it ([Rootless Podman → Host preparation](rootless-podman.md#host-preparation)
   for Podman), clone core and run `./portcullis init --runtime podman` (or
   `--runtime docker`).
3. Copy the backup directory over and run `./portcullis restore --yes <backup-dir>`
   (or `./portcullis restore --from-offsite`).
4. App instances: their volumes aren't in the core backup, but their Hub
   backups are (they live on the Hub's volume). Restore each instance from
   the Hub's Backups list.

Under Podman, check the [per-app table](rootless-podman.md#apps-under-rootless-podman)
first: an app that isn't available there (host devices, DNS on port 53)
can't be started after the move.

See the [CLI Reference](cli.md#backups) for every option.
