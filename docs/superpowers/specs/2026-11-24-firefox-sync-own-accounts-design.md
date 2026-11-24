# Firefox Sync with its own accounts — design

Status: design for the user's approval (2026-11-24); the user's four choices are recorded below. Source of upstream facts: the 🦊 firefox-sync session, `porelli/firefox-sync` main 7216405, notes in `/Volumes/workspace/firefox-sync-drafts/plans/open-items/portcullis-own-accounts-facts.md` (image digests, doc links).

## Intent

Offer two Firefox Sync templates:

1. **Firefox Sync (Mozilla accounts)**: the existing template. People sign in to Firefox with their Mozilla account. Portcullis decides who may sync by Mozilla account id. The admin UI is on its own host, with access "managed elsewhere".
2. **Firefox Sync + own accounts (new)**: the whole stack runs on the server, Mozilla's account service included, so nothing depends on Mozilla. Accounts follow Portcullis's group by email: you join the group and may sign up; you leave and your account is disabled.

Why: full self-hosting, with no Mozilla dependency. The admin UI shows real people, not bare ids, and membership is managed in Portcullis as for every other app.

## Goals

- One template installs the full stack with your own accounts: accounts, auth, profile, Sync storage, the admin UI, MySQL for the accounts and Redis.
- Who may have an account is the template's access group, matched by each person's Portcullis email:
  - join: allowed to sign up;
  - leave: the account is disabled and signed out everywhere;
  - rejoin: the account is enabled again.
- Accounts mail (sign-up and sign-in codes) goes through the server's mail provider.
- The account web pages and the admin UI sit behind Portcullis sign-in. Only what Firefox needs stays open.
- Each instance shows its bypass badges honestly: the API, profile and Sync hosts are open to the internet.

## Non-goals

- Replacing or changing the Mozilla-accounts template. Both stay.
- Signing in to the accounts service with Keycloak or LLDAP. Upstream has no federation, and Sync's keys derive from each person's own password.
- Pre-creating accounts. Each person signs up themselves, in Firefox.
- Moving existing Mozilla-account Sync data into own accounts. It can't move: the data is encrypted with keys from the Mozilla account.
- Setting up phones automatically. The steps are manual, and only desktop is tested upstream.

## Anti-goals: failure even if it works

- A sign-up path that works for people outside the group. The sign-up policy must hold even though the accounts API is open.
- An admin's emergency Disable silently undone by Portcullis. Enable only on a real rejoin, never on a routine run.
- Any account system reachable with no rate limits, or with spoofable client IPs that dodge the limits.
- The accounts' signing keys lost on a restore. They must be in the backup.

## Constraints (upstream facts)

- **Accounts database:** MySQL or MariaDB only, `mysql:lts` by default; upstream's accounts code has no PostgreSQL. Sync's own databases can stay on PostgreSQL.
- **Resources:** about 3–4 GB of RAM, and an accounts image of about 5 GB. The template must say so, and the marketplace must warn on small servers.
- **Hosts:** one name per service, no subpaths, single-label under the wildcard (`<x>-accounts`, never `accounts.<x>`):
  - accounts: the web pages; may sit behind sign-in except `/.well-known/fxa-client-configuration`, `/.well-known/openid-configuration`, `/__heartbeat__` and `/__lbheartbeat__`;
  - API: must stay anonymous; `POST /v1/account/create` goes to the sign-up gate (`ffs-admin:8081`), also anonymous;
  - profile: anonymous, with `/img/` served by profile-static;
  - Sync: anonymous;
  - admin: behind sign-in;
  - pairing: optional.
- **Mail settings:** `FXA_SMTP_HOST`, `_PORT` 587, `_USER`, `_PASS`, `_SECURE` (false = STARTTLS on 587) and `_SENDER`. Never tested upstream against a real submission server with a login.
- **Access mode:**
  - settings: `ADMIN_ACCESS_EXTERNAL=1` with `FXA_ACCESS_DB_PASSWORD`, which forces `FXA_SIGNUPS=allowlist` and creates the DB user `ffs_access`;
  - what `ffs_access` may do: `ffs.signup_allowlist` (SELECT/INSERT/DELETE), `ffs.disable_account_by_email`, `ffs.enable_account_by_email`, and `ffs.delete_account_by_email` (for disabled accounts only);
  - the list gates account creation only. An existing account keeps working until it's disabled;
  - after a disable, tokens Firefox already holds may last up to about 1 h.
- **Client IP:** the auth server reads `X-Forwarded-For` at `FXA_CLIENT_ADDRESS_DEPTH`. Traefik must pass the real client address and trust only itself, or rate limits can be dodged.
- **Network:** don't share the stack's proxy network with other apps. Sync bodies can reach about 2.5 MB.

## Decided

- **Separate template:** `firefox-sync-fxa`, display name "Firefox Sync + own accounts", and multi-instance. It's a template, not a Portcullis core feature.
- **Hostnames per instance:** one host router per service, with the default subdomains `firefox-sync` (Sync), `firefox-sync-accounts`, `firefox-sync-api`, `firefox-sync-profile`, `firefox-sync-admin` and `firefox-sync-pairing`. They follow the Hub's existing per-instance naming (contract §11.3). The default instance gets exactly these. Another instance gets `<sub>-<suffix>` for each, e.g. `firefox-sync-accounts-team` for `firefox-sync-fxa-team`, and the admin can edit every one on the setup form.
- **Sync storage** stays on PostgreSQL, the same as the other template. The accounts database is `mysql:lts`. Every image is pinned by digest.
- **Access by group** runs as a template one-shot, `fxa-access-sync`:
  - **input:** the Hub delivers a data file with the access group's emails, the same machinery as `allowlist.json`. A membership change runs the sync again through a `membership_change` hook (`on_membership_change: hook`), never a data-file restart, which would restart the whole instance and wipe Redis;
  - **state:** the one-shot keeps the last applied list on its own volume, and diffs the new list against it;
  - **joins** are INSERTed;
  - **leaves** are DELETEd, then `disable_account_by_email`;
  - **rejoins** (an email in the old removed-set that reappears): INSERT plus `enable_account_by_email`. Enable only then, never on a routine run;
  - **errors:** a missing or unparsable file stops the job and leaves the list as it was. "No such account" on disable or enable is fine (the person never signed up);
  - **verified emails only:** only an email Portcullis has verified goes on the list (see "Decided after planning"). People without one can't be listed, and the instance page counts them.
- **The admin UI** (`ffs-admin`) has `ADMIN_ACCESS_EXTERNAL=1`:
  - sign-in by OIDC with Portcullis's Keycloak, the groups claim and `ADMIN_ALLOWED_GROUPS` = the instance admin group;
  - its own host, behind Portcullis forward-auth (no `admin_paths`, which would apply to every host of the instance);
  - `ADMIN_PASSWORD` empty.
- **Rate limits and IPs:** upstream's Redis limits stay on, and `FXA_CLIENT_ADDRESS_DEPTH` is set for Traefik alone. A CI test proves that a spoofed `X-Forwarded-For` doesn't change the rate-limit key.
- **Backups:** the `fxa-keys` volume and the accounts DB go in the instance's backup set.
- **Privacy:** `FXA_ACCOUNT_EVENTS` is off, since it stores IPs.
- **Network isolation** (my call, from the builder check; mechanism ruled after planning): every service sits on the instance's own `default` network. Only a Traefik-only nginx gate, `fxa-gate`, joins `portcullis-proxy`. This is the existing gate pattern of `esphome/gate.sh`: it answers `PORTCULLIS_TRAEFIK_SOURCE` only. No per-instance networks are needed. No other app can reach `fxa-auth:9000` directly and skip the sign-up gate. A CI test checks that another app's container can't connect to it.
- **Resource warning** (my call; figures ruled after planning): upstream's own figures, per the resources contract. The RAM figure is 4 GB, the top of upstream's 3–4 GB (`min_memory_mib: 4096`). The disk figure is 18 GB, the sum of upstream's chart PVC sizes for the volumes this template has: accounts DB 8 GiB, keys 1 GiB, avatars 1 GiB, one Sync database 8 GiB (`min_disk_gib: 18`). The about 5 GB accounts image comes on top and is stated in the description. The marketplace and the setup form warn when the server has less RAM or less free disk. They warn, they don't block.
- **Bypass badges:** the API, profile, Sync and pairing hosts appear as "Open to the internet" with upstream's reason, through a new reason per host in the manifest (a Hub feature). The accounts host shows its public paths.

## Decided by the user (2026-11-24)

1. **Accounts web pages behind Portcullis sign-in.** Only signed-in members reach the sign-up and account-settings pages. The open paths Firefox needs stay open, and so do the API, profile and Sync hosts. This is defence in depth; the sign-up policy is the gate.
2. **Mail:** the server's mail provider by default. An admin may instead enter an external SMTP server (host, port, security, user, password, sender), stored as instance secrets. The template refuses to start with neither. A CI test sends a real sign-up code through the mail provider.
3. **Pairing:** run our own `fxa-channelserver`, on its own open host `<host>-pairing` (WebSocket). It shows as a bypass badge: open to the internet, an encrypted relay only.
4. **No account cap by default.** The group decides. `FXA_MAX_ACCOUNTS` is an optional instance setting.

## Decided after planning (2026-11-24)

Controller calls, recorded from the implementation plan's open decisions (D1–D7). D2 is the user's.

1. **D1, isolation:** the existing Traefik-only nginx gate pattern (`esphome/gate.sh`), not the Hub's per-instance networks (still a pending spec).
2. **D2, verified emails only (the user's decision):** only an email Portcullis has verified goes on the sign-up list.
   - It counts as verified when it was proven by a code sent to it, or set by an admin.
   - The code goes out through the server's mail provider, by Portcullis's own app sender. It has an expiry and attempt limits. The email counts as verified only after the code is entered.
   - Changing your email clears its verification.
   - The data file carries only verified emails.
   - The People page shows verified or unverified, and the instance page counts the members without a verified email.
   - The "verified email" flag is generic: any future email-keyed app can use it.
3. **D3, names:** the Hub's existing per-instance host naming (§11.3), see "Hostnames per instance".
4. **D4:** no `admin_paths`. The admin UI is protected by its own host, forward-auth and its OIDC sign-in (the admin group).
5. **D5:** a membership hook re-runs `fxa-access-sync`, not a data-file restart, so Redis isn't wiped.
6. **D6:** the warning uses upstream's figures, 4 GB of RAM and 18 GB of disk (the PVC sizes). They replace this design's earlier 6 GB / 20 GB.
7. **D7:** a reason per host on the bypass badges, as a Hub feature.

## Left to the builder

- **Startup:** service names, network layout, start order (keys-owner → migrations → policy → auth/content/profile; db-init → our guard → syncstorage) and healthchecks.
- **The Hub data file's format** for emails, and how the delivery triggers `fxa-access-sync`.
- **Tests:**
  - a real sign-up through the mail provider in CI (a sign-up code arrives, the account is created);
  - a member who isn't in the group gets refused at sign-up;
  - leave → disabled; rejoin → enabled; an admin Disable survives a routine run;
  - a spoofed IP doesn't bypass the rate limits;
  - Firefox desktop syncs end to end, if feasible in CI.
- **Docs:** the template's `auth.notes`, the Firefox setup steps (also on the admin UI's Connect page), and the resource warning.
