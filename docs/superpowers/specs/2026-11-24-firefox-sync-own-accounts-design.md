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
- **Hostnames per instance:** `<host>` (Sync), `<host>-accounts`, `<host>-api`, `<host>-profile`, `<host>-admin` and `<host>-pairing`. The instance's base host defaults to `firefox-sync`.
- **Sync storage** stays on PostgreSQL, the same as the other template. The accounts database is `mysql:lts`. Every image is pinned by digest.
- **Access by group** runs as a template one-shot, `fxa-access-sync`:
  - **input:** the Hub delivers a data file with the access group's emails, the same machinery as `allowlist.json`, and it restarts the one-shot on membership changes;
  - **state:** the one-shot keeps the last applied list on its own volume, and diffs the new list against it;
  - **joins** are INSERTed;
  - **leaves** are DELETEd, then `disable_account_by_email`;
  - **rejoins** (an email in the old removed-set that reappears): INSERT plus `enable_account_by_email`. Enable only then, never on a routine run;
  - **errors:** a missing or unparsable file stops the job and leaves the list as it was. "No such account" on disable or enable is fine (the person never signed up);
  - **no email:** people without an email in Portcullis can't be listed, and the instance page says so.
- **The admin UI** (`ffs-admin`) has `ADMIN_ACCESS_EXTERNAL=1`:
  - sign-in by OIDC with Portcullis's Keycloak, the groups claim and `ADMIN_ALLOWED_GROUPS` = the instance admin group;
  - Portcullis forward-auth in front;
  - `ADMIN_PASSWORD` empty.
- **Rate limits and IPs:** upstream's Redis limits stay on, and `FXA_CLIENT_ADDRESS_DEPTH` is set for Traefik alone. A CI test proves that a spoofed `X-Forwarded-For` doesn't change the rate-limit key.
- **Backups:** the `fxa-keys` volume and the accounts DB go in the instance's backup set.
- **Privacy:** `FXA_ACCOUNT_EVENTS` is off, since it stores IPs.
- **Network isolation** (my call, from the builder check): the stack never joins the shared `portcullis-proxy` network. It uses the Hub's per-instance networks: a private network for its services, plus one shared only with Traefik for the routed services. No other app can reach `fxa-auth:9000` directly and skip the sign-up gate. A CI test checks that another app's container can't connect to it.
- **Resource warning** (my call): the marketplace and the setup form warn when the server has less than 6 GB of RAM or less than 20 GB of free disk. They warn, they don't block. The numbers sit next to the template's description.
- **Bypass badges:** the API, profile and Sync hosts appear as "Open to the internet" with upstream's reason. The accounts host shows its public paths.

## Decided by the user (2026-11-24)

1. **Accounts web pages behind Portcullis sign-in.** Only signed-in members reach the sign-up and account-settings pages. The open paths Firefox needs stay open, and so do the API, profile and Sync hosts. This is defence in depth; the sign-up policy is the gate.
2. **Mail:** the server's mail provider by default. An admin may instead enter an external SMTP server (host, port, security, user, password, sender), stored as instance secrets. The template refuses to start with neither. A CI test sends a real sign-up code through the mail provider.
3. **Pairing:** run our own `fxa-channelserver`, on its own open host `<host>-pairing` (WebSocket). It shows as a bypass badge: open to the internet, an encrypted relay only.
4. **No account cap by default.** The group decides. `FXA_MAX_ACCOUNTS` is an optional instance setting.

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
