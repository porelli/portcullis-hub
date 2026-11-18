# SSH Access

Portcullis can sign **SSH certificates** for the people in your directory.
A person runs `portcullis login`, signs in once in their browser with a
YubiKey, a security key or a device passkey, and gets short-lived
certificates in their ssh-agent for the hosts they may reach. Hosts trust
the Portcullis certificate authority instead of a pile of `authorized_keys`
files.

Who may log into which host, as which account, with or without sudo, is set
on one page: **Hub → SSH access**. It is off until an administrator switches
it on. Switching it off again ends access: enrolled hosts keep syncing, lock
every Portcullis account and get every certificate revoked; nothing new is
enrolled or signed. The interfaces are in
[contracts §18](../guides/integration-contracts.md#18-ssh-access-and-the-cli-new-ssh-cli-login).
The person's side is in [The Portcullis CLI](../guides/cli.md).

## The model

```
LLDAP group ──grant──▶ host group ──contains──▶ hosts
                │
                └─ accounts ({username} and/or shared names) · sudo none|full ·
                   TTL · port forwarding · agent forwarding
```

- **Host groups** collect hosts: `web`, `db`, `lab`. Their id appears in
  every certificate, so a `web` certificate is worthless on a `db` host.
  The built-in `all` holds every managed host. At most 64.
- **Grants** connect an LLDAP group to a host group. A grant names the
  accounts its members may use: `{username}` (each person logs in as
  themselves, the recommended default) and/or shared accounts such as
  `deploy`. It says whether those accounts get sudo, how long certificates
  last (default 8 hours, at most 12), and whether port or agent forwarding
  is allowed. At most 256.
- **Certificates.** One per host group per login. Its principals are
  `u:<username>@<host group>` for a person's own account and
  `s:<account>@<host group>` for a shared one (`u:alice@web`, `s:deploy@web`):
  the two never mix, so a shared account and a person with the same name can
  never stand in for each other. Its lifetime is the
  **shortest** of the grants' TTLs, the server's maximum and the end of a
  temporary membership it depends on: access never outlives the reason for it.

Example:

| LLDAP group | Grant | Result |
|---|---|---|
| `ssh_web` | → `web`, account `{username}`, no sudo | alice gets a `web` certificate with `u:alice@web`; on every `web` host the account `alice` exists |
| `ssh_admins` | → `all`, account `{username}`, sudo | alice also gets an `all` certificate; on every managed host she has sudo |
| `ssh_deploy` | → `web`, account `deploy`, no sudo | bob gets `s:deploy@web`; the host's log still names him: `ID pc:bob:web:…` |

**sudo belongs to an account on a host**, not to a certificate: on a `web`
host alice has sudo because a grant that applies there (`all`) gives it,
whichever certificate she used.

### Sign-in strength

Each host group has a governing template (default `strong`). A certificate
is issued only after a **fresh** sign-in (`prompt=login`) with a method that
template accepts **and** that is a hardware-backed or passkey method: a
password, an authenticator code or a browser certificate never signs an SSH
certificate, whatever the template says. A session as someone else
(impersonation) never gets certificates.

### Privileged grants

A grant is privileged when it gives sudo, the account `root`, agent
forwarding, a shared account with sudo, or the host group `all`. Privileged
grants:

- need an administrator, a fresh sign-in and the group's name typed again;
- default to 4 hours;
- show in the doctor as Info;
- make the group's members protected: delegates can't send them setup links;
- can never be made by an AI assistant.

### Delegation

The delegated permission **`ssh_access`** lets a group's members manage
non-privileged grants on host groups an administrator marked *delegable*,
from `people.<domain>`. They can't grant sudo, root or forwarding, can't
grant to a group they are in, and can't touch host groups, hosts or
settings. Every group used by a grant becomes a guarding group: its rule may
use only admin-only fields, so nobody can type a field value that grants SSH.

## Managed and unmanaged hosts

| | Managed host | Unmanaged host |
|---|---|---|
| Set up with | `sudo portcullis host enroll < code.txt` | `sudo portcullis host trust …` |
| Talks to Portcullis | outgoing HTTPS only, signed by its host key | never (optionally pulls the public revoked-keys list) |
| Accounts and sudo | created and locked for you | yours to manage |
| Revocation | within seconds | within 5 minutes with `--revoked-keys`, else at expiry |
| Host certificate | issued and renewed automatically | an admin runs `portcullis host certify` |
| Drift detection | yes | no |

Both need OpenSSH 8.2 or later with `Include /etc/ssh/sshd_config.d/*.conf`
in the main config (Debian, Ubuntu, Fedora, RHEL 9, macOS 13 and later).
The tools never edit the main `sshd_config`: when the `Include` is missing,
they stop and print the line to add.

### Enrolling a managed host

1. **Hub → SSH access → Hosts → Add host**: a name, its addresses and its
   host groups. This needs a fresh sign-in. The Hub shows a **one-time
   enrolment code**, valid 15 minutes. Copy it into a file on the host; it
   is never shown again and never put in a URL.
2. On the host, as root:

    ```
    sudo portcullis host enroll < code.txt
    ```

    It asks for the host's **local ceiling** (below), proves the code to
    Portcullis, pins the host's own SSH host key, writes the files, checks
    them with `sshd -t` and `sshd -T`, reloads sshd and installs the
    `portcullis-host-sync` service. Any failure puts every file back and
    leaves sshd alone.

The code is read from standard input (or typed at a hidden prompt with `-`),
never from the command line, so it never shows in `ps` or a shell history.

### The local ceiling

`/etc/portcullis/host.json` is written by the host's operator at enrolment
and **never changed by Portcullis**:

| Setting | Default |
|---|---|
| `allow_sudo` | `true` |
| `allow_root_login` | `false` |
| `uid_range` | `20000–59999` |
| `protected_accounts` | every account below uid 1000, plus the break-glass account |
| `breakglass_account` | `breakglass` |
| `max_accounts` | 500 |

Any account that can reach root on the host by other means — a
`sudo`/`wheel`/`admin` group, a root-equivalent group (`docker`, `lxd`,
`incus`, `libvirt`, `disk`), a doas rule, a sudoers rule anywhere, uid 0; the
host asks `id`, doas.conf and `sudo -l` rather than reading sudoers — gets a
certificate login there only through a privileged grant, and with
`allow_sudo: false` never. The approval is in the certificate: a privileged
grant's certificates carry `up:` / `sp:` principals, and an account with sudo
— Portcullis's own included — accepts only those, so a certificate from a
plain grant stops working there the moment the account gets sudo. Every host reports such accounts; until a managed
host has reported, every shared-account grant on its host groups counts as
privileged (typed group name and a fresh sign-in). A grant that becomes
privileged later (the host reports the account with sudo) gives that account
nothing until an administrator saves it again.

A grant that would exceed it is skipped on that host and reported. This is
what bounds a compromised Hub: it can't grant root where you said no, and it
can't touch protected accounts.

### Setting up an unmanaged host

```
sudo portcullis host trust --domain example.com --host-group web \
     --ca-key 'ssh-ed25519 AAAA…' --person alice --account deploy --revoked-keys
```

The Hub's host-group page shows this command with the right key and the
`--person` (a person's own account) and `--account` (a shared account)
lines the current grants need. `--ca-fingerprint SHA256:…`
fetches the key instead, and only accepts it when the fingerprint matches.
Without `--revoked-keys` the host never talks to Portcullis.

`host trust` checks each named account for sudo the same way a managed host
does: an account with sudo accepts only a privileged grant's certificates
(`sp:` / `up:`), and `--approved-only` makes every account do so. It prints
which form each account got. Nobody watches an unmanaged host afterwards: run
`host trust` again when an account's sudo changes.

## Accounts and sudo (managed hosts)

- Each person gets an account named after their LLDAP username, with the
  same uid on every host (from 20000), in the local group
  `portcullis-users`, created before they first log in. A username that
  can't be a local account on that host (too long, a leading digit) is
  skipped and reported; the person still reaches shared accounts.
- **Portcullis accounts are certificate-only:** no `authorized_keys`, no
  password, no keyboard-interactive login. Nobody can plant a key in them.
- An existing local account with the same name that Portcullis didn't
  create is **never adopted**: it is reported as a conflict.
- A person whose username is `root`, a shared account of a grant, a host's
  break-glass or protected account, or a system account name (`daemon`,
  `www-data`, …) gets **no** personal account at all: the doctor reports
  `ssh_username_collision`, and the previews show the skipped grant. A
  shared account can't be named after a person in the directory.
- **Losing access** (leaving the group, a deleted grant) locks the account at
  the next sync, removes its principals and ends its running sessions.
  Accounts are never deleted automatically: *Remove account* on the host's
  page deletes it and keeps the home directory under `/home/.portcullis-removed/`.
- **A deleted person's account** stays locked with its uid. If someone new
  later gets the same username, they never inherit it: the old uid is
  retired, every managed host removes the old account first (home kept as
  above), then the newcomer gets a fresh uid and an empty account.
- **sudo** comes from `/etc/sudoers.d/portcullis`, checked with `visudo -cf`
  before it replaces the old file; a candidate `visudo` refuses removes the
  file (nobody keeps Portcullis sudo) and is reported. Portcullis accounts have no password, so
  the lines are `NOPASSWD`: the proof is the fresh hardware sign-in that
  made the certificate, bounded by its lifetime.
- Shared accounts are created only when the host group says *Portcullis
  creates shared accounts*; otherwise create them yourself.

## The access preview

**Hosts → web-1 → Access** answers "who can reach web-1, and as root?":
person, account, sudo, the grant it comes from, until when, and whether the
account is in place. The same view exists per host group and per person. The
grant editor shows it for an unsaved change ("this gives sudo on 12 hosts to
4 people"). Unmanaged hosts say "accounts and sudo unknown (unmanaged)".

## Revocation

- *Revoke* on a certificate, *Revoke all SSH certificates* on a person, the
  person's own *Revoke all my SSH certificates* ("I lost a device") and
  `portcullis logout --revoke` put the key on the revoked list.
- Leaving a grant's group revokes that person's certificates for it
  automatically (losing any one account of a certificate is enough), and
  locks the account on managed hosts.
- A host key signed with *Sign a host key* is revoked from the
  certificates list by its fingerprint; it is never signed again.
- Revoking a person's own key (`login --key`, e.g. a security key) yourself
  or as an administrator is for good; *Un-revoke…* on the revoked list (the
  fingerprint typed again, a fresh sign-in) takes it off. Automatic
  revocations (leaving a group, switching SSH access off) expire 24 hours
  after the key's last certificate.
- Managed hosts get the list within seconds; unmanaged hosts with
  `--revoked-keys` within 5 minutes; others when the certificate expires
  (at most 12 hours).

## When a host can't reach Portcullis

A managed host keeps its last files **indefinitely**. Certificates are
self-contained, so people with valid certificates keep logging in. The
revoked list is as fresh as the last sync, so a key revoked during an outage
stays usable there at most until its certificate expires (≤ 12 hours). That
is deliberate: refusing every key on a partitioned host would lock out
everyone, break-glass included. Account changes and new host certificates
wait for the network. The Hub shows each host's last sync; the doctor warns
after 15 minutes and reports a problem after a day.

## Break-glass

Portcullis must never be the only way into a host.

- `host enroll` and `host trust` refuse to finish unless the host has a
  **break-glass account** with its own `authorized_keys` (recommended: an
  offline FIDO key in a safe), or you pass
  `--no-breakglass-i-have-console-access`. The account is protected, never
  certificate-only, and every apply checks that the Portcullis rules don't
  apply to it. Logins to it are reported.
- **Hub down, Vault up:** on the Portcullis server,
  `./portcullis ssh breakglass-cert --user <name> --host-group <hg> --ttl 1h --key <pub>`
  signs directly in Vault. It is recorded and shows in the Hub's audit and
  doctor at the next start ([CLI reference](cli.md#ssh-breakglass-cert)).
- **Portcullis down entirely:** certificates already issued keep working;
  after that, the host's break-glass account.

## Drift

Every sync reports the host's state. A hand-edited Portcullis file is
rewritten at the next apply and reported as fixed. Something Portcullis
can't fix, such as the main `sshd_config` setting `TrustedUserCAKeys` before
its `Include` (sshd keeps the first value it reads), is reported as a
Problem naming the keyword and the value sshd uses. Fix it in the main
config; Portcullis never edits it.

## Threat model in plain words

- **A stolen, locked laptop** holds no private key on disk and no token. A
  new certificate needs the person's YubiKey or passkey again.
- **A stolen, unlocked laptop** can use the certificates in the agent until
  they expire (8 hours by default). Revoke them from any device; managed
  hosts refuse within seconds. *Only through the Portcullis VPN* on a host
  group limits where certificates work at all.
- **A compromised host** sees certificates (public) and sessions, never
  private keys. With agent forwarding (off by default, privileged) it can use
  a connected person's agent while the session lasts. Its host key signs
  nothing; *Remove host* cuts it off.
- **A compromised Hub** could sign what Vault's policy allows and push
  accounts to managed hosts, but never over 12 hours, never host
  certificates from the user CA, never root or protected accounts where the
  host's ceiling says no, and never the break-glass account.
- **Codes and secrets** never appear on command lines, in logs or in the
  audit; the audit holds key fingerprints only.

CA rotation (new CA keys with an overlap) is coming in part 2.

## Windows hosts

Portcullis doesn't automate Windows hosts. Windows OpenSSH Server supports
the same trust by hand: copy the user CA key from the Hub into
`C:\ProgramData\ssh\portcullis_user_ca.pub`, add
`TrustedUserCAKeys __PROGRAMDATA__/ssh/portcullis_user_ca.pub` and
`AuthorizedPrincipalsFile __PROGRAMDATA__/ssh/portcullis_principals/%u` to
`C:\ProgramData\ssh\sshd_config`, write one principals file per account
(`u:alice@web` for alice's own account, `s:deploy@web` for a shared one), and restart the `sshd` service. `portcullis host …` commands
refuse on Windows with "Windows hosts: follow the manual steps in the docs".
