# Mail server: send, receive, filter, fully authoritative (design)

Status: written by the assistant for the roadmap item "a full working mail server with spam filter and correct settings to be fully authoritative" (the user's words). The user asked not to be interrupted, so the assistant made every decision. Each one is the **assistant's call** unless it says otherwise. Open questions are in §12, and each has a default. This spec builds on the DNS spec (`2026-11-13-dns-hardening-design.md`: one DNS plan, record sets, `nomail`, the DNSSEC state hook for DANE) and on file sharing's per-person credentials (contract §13.16).

## 1. Where things stand (2026-11-12)

- **No mail anywhere.** Core sends nothing except Alertmanager through an external smarthost (`ALERT_SMTP_*`). No template configures SMTP. LLDAP's `mail` attribute can be edited by the user, so by contract §5 it is never an identity key.
- **DNS.** The DNS plan (once it ships) owns the record sets `address`, `caa` and `nomail` for the main domain (written by the CLI one-shot `dns-tool` from `.env` credentials) and for enrolled domains (written by the `domains` service in the background). It reserves a defined way for mail to add sets, and `nomail` is meant to be replaced by real mail records. DNSSEC `secure` is exposed so that mail can publish DANE.
- **Ingress.** Traefik publishes only `:80` / `:443`. It has no TCP routers and no other entrypoints. It holds the main wildcard `*.<d>` key in `acme.json`. Enrolled-domain certificates come from the domains service over mTLS.
- **Credential precedent.** File sharing issues each person a password for one instance. The person creates it on `people.<domain>` after a fresh passkey touch. It is shown once, stored only as a hash, revoked within seconds when the person leaves the group (the hook within 8 s, otherwise the app is killed), voided by a restore, and audited without secrets.
- **Scheduling precedent.** Host-side periodic jobs run as systemd timers (`backup schedule --systemd`), never as a container with the Docker socket.

## 2. Goals, non-goals, anti-goals

**Goals**
1. **Send and receive** for the main domain and for every enrolled domain where an admin turns mail on (Settings → Mail).
2. **Authentication that passes and aligns**: SPF `pass` with the envelope domain = From domain, DKIM `pass` with `d=` = From domain (Ed25519 + RSA-2048 dual signatures), DMARC `pass` for every message Portcullis sends. DMARC and TLS-RPT aggregate reports are received and summarised.
3. **Transport security**: MTA-STS (policy host plus TXT), TLS-RPT, and DANE TLSA for the MX host whenever the main zone's DNSSEC state is `secure`. Outbound mail verifies DANE and MTA-STS for remote domains.
4. **Reverse DNS**: PTR is set at the hosting provider (Portcullis can't write it). A check confirms forward-confirmed rDNS for every public address, plus guidance for setting it at each provider.
5. **Spam filtering** with no external service: rules, a statistical classifier trained by people's Junk moves, DNSBLs through our own validating resolver, phishing and homograph checks, and rejection at SMTP time for clear spam.
6. **Fully authoritative**: Portcullis owns every mail record (MX, SPF, DKIM with rotation, DMARC, MTA-STS, TLS-RPT, autoconfig / autodiscover, SRV, TLSA) through the DNS plan. The doctor and `status` show any drift.
7. **People and groups map to mail**: LLDAP users become mailboxes, the admin defines aliases, and Hub groups can become lists. Removals take effect within seconds, as with file sharing.
8. Webmail stays **optional and later** (§10, phase M5).

**Non-goals** (assistant's call)
- Being an outbound relay for third parties or apps in v1 (app sender accounts are parked, §11).
- Hosting a domain's mail when Portcullis doesn't control its DNS ("records by hand" still works, but there's no rotation; see §6).
- Inbound mail through an external MX or relay for networks where inbound port 25 is blocked.
- POP3, IMAP without TLS on 143, ManageSieve, CalDAV / CardDAV / WebDAV, JMAP for clients, Stalwart's own WebUI for people, S/MIME / OpenPGP management, AI spam classification. All are off in v1.
- Clustering and multi-server mail (the roadmap's multi-server item).
- Migrating mail from other providers (Stalwart's import tools are documented only as a pointer).

**Anti-goals** (never)
- **Never an open relay.** Mail to non-local recipients is accepted only from an authenticated submission session, and its envelope sender and `From` must be addresses of the authenticated person (their own address, their aliases, or a list they may send as). No IP-based trust (`mynetworks`): the docker gateway, the LAN and localhost get no relay right. CI asserts this (§9).
- **Never a mail password in clear at rest.** The Hub never stores one. Stalwart stores only its hash. The plaintext exists only in the one create response, as with SMB.
- **Never weaker sign-in.** Mail clients can't do WebAuthn. So a mail credential (a) can only be created after a fresh touch with a method the server's policy accepts (§8 of the sign-in work), (b) works only on IMAPS and submission, never on Portcullis web sign-in, Stalwart's WebUI, its API, JMAP or DAV (Stalwart refuses app passwords at interactive sign-in since v1.0.2), (c) is revocable per device, and (d) dies when its holder leaves the mail group. An LLDAP password never opens a mailbox.
- **Never DNS credentials in the mail server**, and never the main wildcard key in it. Stalwart's ACME and automatic DNS management stay off.
- **Never backscatter.** Spam is rejected during the SMTP transaction or filed in Junk. Mail is never bounced after it was accepted, except DSNs for our own authenticated senders.
- **Never someone else's mailbox.** A username deleted and created again (new LLDAP uuid) never inherits the old mailbox or address history.
- **Never a standing full-access admin credential**: `STALWART_RECOVERY_ADMIN` exists only during bootstrap (§4).

## 3. Software choice: Stalwart (assistant's call)

| | Stalwart v1.1 | docker-mailserver | Mailcow | Maddy |
|---|---|---|---|---|
| Licence | AGPL-3.0 (+ proprietary SELv2 for ~15% enterprise features we don't use) | MIT | GPL-3.0 | GPL-3.0 |
| Shape | one Rust process: SMTP, IMAP, JMAP, spam filter, DKIM/ARC/SPF/DMARC, MTA-STS, DANE, TLS-RPT, report analysis | Postfix + Dovecot + Rspamd (+ ClamAV) under supervisord, root | ~15–20 containers, own nginx/ACME/DB/UI, ~6 GB RAM recommended, wants the host | one Go process, rspamd external for content filtering, small community |
| Directory / auth | internal, LDAP, SQL, OIDC (OAUTHBEARER/XOAUTH2); app passwords with protocol / IP / expiry scopes, hashed | LDAP (community-maintained), Dovecot OAuth2 | own DB | LDAP, PAM |
| Declarative config | `config.json` (store only) + idempotent NDJSON plans (`stalwart-cli apply`) | env + files | UI / DB | config file |
| Activity | weekly releases; v1.0 2026-10-26, v1.1.0 2026-11-09 | steady | steady | slow |

**Why Stalwart:**
- It is one hardened-able process with every feature in §2 built in, so there are no extra containers for spam, DKIM or reports.
- App passwords are a native, hashed, scoped feature: per device, `allowedIps`, `expiresAt`, permissions that narrow the account's, and refused at interactive sign-in.
- The configuration is a data model we can apply idempotently from code.
- Its documented Traefik layout matches ours.

AGPL is acceptable: we run the upstream image unmodified and link nothing. We use only AGPL features. SCIM is enterprise-only, which is one reason the Hub provisions accounts itself (§5).

**Risks and how we handle them:**
- v1 is three weeks old and had breaking changes. We pin `tag@sha256`, and an image bump needs the mail e2e to pass.
- At startup it downloads the WebUI and spam rules from GitHub. We vendor the spam-rules file (pinned by sha256, refreshed with releases) and don't serve the WebUI.

docker-mailserver is the fallback if Stalwart's 1.x churn proves unmanageable.

## 4. How it plugs in: a core profile, not a template (assistant's call)

Mail is server-wide. It spans the main domain and every enrolled domain, owns public port 25, needs DNS sets of its own and feeds the identity model. A template instance is per-app, and the contract allows `person_secret` only on router-less templates. So mail is the compose profile **`mail`** (`COMPOSE_PROFILES=…,mail`, like `monitoring`), with three services:

- **`mail`**: the Stalwart image, pinned `tag@sha256`.
  - Runs as the image's unprivileged user, with `x-hardening`, `read_only` and tmpfs `/tmp`.
  - Listens on high ports and Docker maps them, so no `NET_BIND_SERVICE` is needed: `25→10025` (STARTTLS), `465→10465` and `993→10993` (implicit TLS), `587→10587` (STARTTLS submission).
  - `ulimits.nofile 65536`, `mem_limit 1g` (the cache limits are set in the plan to fit it; §12 Q4), `pids_limit 256`.
  - Volumes: `mail_data:/var/lib/stalwart` (RocksDB), `mail_etc:/etc/stalwart` (`config.json`: the store only), and `mail_tls` read-only.
  - The 8080 management listener is bound inside the container and reachable only on `portcullis-mail`. Every HTTP access rule except `/api` from mailctl's pinned address is denied.
- **`mailctl`**: new, Go, in `mailctl/` in core (same rules as `domains`).
  - It is the **only** holder of Stalwart's API key (role `portcullis-mailctl`: principals, domains, DKIM, app passwords with `impersonate` + `sysAppPasswordCreate`, queue read, reload actions; no message read or export).
  - It applies the desired state, runs the DKIM / MTA-STS / TLSA state machines, serves the well-known files, renders DNS sets and runs the deliverability checks.
  - User `10006`, read-only, no Docker access, no LLDAP or Keycloak credentials, no DNS credentials.
- **`mail-resolver`**: Unbound, pinned. A validating, recursive resolver used only by `mail` and `mailctl`.
  - DANE needs a validating resolver.
  - Spamhaus refuses DNSBL queries that arrive through public resolvers.
  - It has no forwarders and is not reachable from outside.

**Networks:**
- `portcullis-mail`: internal, fixed IPAM. Members: mail, mailctl, mail-resolver.
- `mail-egress`: mail's outbound SMTP and the resolver's port 53.
- `portcullis-mailctl`: internal, fixed subnet. Members: the Hub and mailctl. The API answers only there, with a shared secret (the domains pattern).
- `portcullis-proxy`: mailctl, pinned, for its Traefik routers.

`network_check` validates all of them.

**Ports: direct publish, not Traefik TCP entrypoints** (assistant's call).
- SMTP on 25/587 upgrades with STARTTLS inside the protocol, which Traefik can't terminate. So Stalwart does all mail TLS anyway, and Traefik would only add a passthrough hop and PROXY-protocol trust.
- Keeping SMTP parsing out of the process that holds the main wildcard key is a plus.
- Docker's DNAT keeps the client IPv4 address. Where the userland proxy hides the source (IPv6 without Docker IPv6), mailctl's check reports "client addresses are rewritten: spam scoring degraded" (Warning). Relay safety never depends on IPs (anti-goal).
- The ports are **not** `lan_only`: 25 must be public. `MAIL_SUBMISSION_LAN_ONLY=false` can restrict 465/587/993 to the Hub's local networks (with Stalwart rules applying the same networks).

**One MX host for every domain** (assistant's call): `mail.<d>` (`MAIL_HOSTNAME`, default `mail.<main domain>`).
- Enrolled domains' MX, MTA-STS `mx:` and client settings all name it.
- So there is **one** mail certificate, one PTR, one EHLO name and one TLSA owner name (`_25._tcp.mail.<d>`).
- `mail.<d>` already resolves through the `*.<d>` wildcard. The Hub reserves the labels `mail`, `mta-sts`, `autoconfig` and `autodiscover` on every mail-enabled domain (it refuses them as instance hostnames).

**The mail certificate** (assistant's call: dedicated, key reused):
- `mail-cert`: a `dns-tool` subcommand (`domains mail-cert`, run by `./portcullis` with stdin credentials, egress-only, exactly as `dns setup`).
- It issues `mail.<d>` with **its own ACME account and a key it reuses** across renewals (lego `ObtainRequest.PrivateKey`), stored in the `mail_acme` volume.
- It writes `fullchain.pem` / `privkey.pem` (uid of `mail`, 0640) into `mail_tls`. It never uses Traefik's wildcard: a compromised mail server must not be able to impersonate `auth.<d>`.
- CAA: a `caa` entry at `mail.<d>` pins this account (the closest RRset wins, so the main pin is untouched; the DNS spec §4 rule).
- Renewal: `./portcullis mail schedule --systemd` installs `portcullis-mail.timer` (daily). It renews below 30 days, runs `mail rotate` (DKIM and TLSA publication for the main domain, §6) and then asks mailctl to send `Action/ReloadTlsCertificates`.
- `up` issues the certificate when it is missing. The timer is required for the main domain's rotation, and `status` reports a missing timer as a Warning.

**Bootstrap** (`./portcullis mail enable`, idempotent):
1. Write `config.json` (`RocksDb`).
2. Start `mail` with `STALWART_RECOVERY_MODE=1` and a one-time `STALWART_RECOVERY_ADMIN` from a 0600 env file.
3. Apply the base plan: listeners, a `none` DNS provider, ACME off, internal directory, spam settings, resolver = mail-resolver, telemetry, and the mailctl role and API key into `secrets/mail/api-key`.
4. Delete the env file, recreate the container without recovery, and check that a login with the recovery admin now fails.

`upgrade` re-applies the base plan. After a Stalwart minor update it sets `STALWART_UPDATE_ROLE_PERMISSIONS` once, as the release notes require.

## 5. Identity: people, addresses, aliases, lists

- **Who gets a mailbox**: members of the Hub-managed group **`mail_users`** (created by the Hub, like an app's access group; rules and delegation work on it).
- **Primary address**: `<lldap username>@<primary mail domain>`. The username is immutable; the editable LLDAP email is never used.
  - Per enrolled domain, an admin can grant the domain to groups. Members then also receive at `<username>@<that domain>` and may send as it.
  - The Stalwart login name is the primary address (what autoconfig fills in).
- **Desired state**: the Hub computes it with its existing membership machinery and `PUT`s it to mailctl as one document: domains, accounts `{username, uuid, display name, addresses, quota}`, aliases, lists. Then mailctl reconciles Stalwart with `upsert` plans.
  - Additions are debounced 60 s.
  - **Removals are immediate** (file sharing's rule). On leave: app passwords destroyed, account disabled, open IMAP sessions ended (Stalwart session kill; failing that, mailctl restarts `mail`, the 8 s rule of §13.16). Incoming mail to the address gets `550 5.1.1`.
  - Direct LLDAP edits are caught on the evaluator's 60 s tick.
- **Account identity** is keyed by LLDAP uuid (stored in the Stalwart principal's description). A changed uuid renames the old principal to `former-<uuid>` (disabled, no addresses), and the new person gets a fresh, empty mailbox.
  - Former mailboxes are kept **30 days** (`MAIL_FORMER_RETENTION`), then deleted.
  - Within the 30 days an admin can export one (`./portcullis mail export <former>` → mbox via Stalwart's export task) or delete it now.
- **Aliases**: defined by an admin on the person's page (address on any mail domain → that person). Each address is unique across people, lists and reserved names.
  - Reserved names: `postmaster`, `abuse`, `dmarc-reports`, `tls-reports`, `mailer-daemon`. `postmaster` and `abuse` are delivered to the members of `lldap_admin` (RFC 5321 / 2142).
- **Groups as lists**: on a group's page an admin can make the group a list at `<group>@<domain>` (opt-in for each group). Delivery goes to the expanded members.
  - Posting: `members` (default) or `anyone`. Senders outside a `members` list are rejected at RCPT.
  - Lists are Stalwart group principals with addresses: no list archive, no subscription management.
- **Quotas**: a group-scoped setting with a default (10 GiB), resolved as Hub settings do (§13.4).

## 6. Mail client authentication

**v1: mail passwords** (Stalwart app passwords, assistant's call). On `people.<domain>` → **Sign-in → Mail passwords**, a person in `mail_users` can:
- **Create** one, with a label ("iPhone", "Thunderbird laptop") and an optional expiry (none / 90 days / 1 year).
  - It needs a fresh-auth proof under the server's default sign-in template (the §8 flow, as for SMB).
  - The Hub forwards the request to mailctl, which calls `x:AppPassword/set` for that account with permissions `Replace [authenticate, imapAuthenticate…, emailSend]` (the exact permission names are pinned in T2) and `allowedIps` = everywhere, or the local networks when `MAIL_SUBMISSION_LAN_ONLY`.
  - Stalwart generates and hashes the secret. The secret passes through mailctl and the Hub in memory **once**, in a `no-store` response.
  - That response also offers a one-time Apple `.mobileconfig` (unsigned; built in memory, never stored) and the manual settings: server `mail.<d>`, IMAPS 993, submission 465 / 587, username = address.
- **List** their passwords: label, created, expiry, last used if Stalwart exposes it. Never the secret.
- **Revoke** one, without fresh auth.

Rules:
- **At most 5 per person** (Stalwart's `maxAppPasswords` default).
- Admins see who has how many and can revoke them, **never create** (the §13.16 rule).
- Metadata `{id, label, created_at, expires_at}` lives in `state.yaml` `mail_credentials`. Stalwart's object id links the two.
- Audit: `mail_credential.create|revoke|revoke_leave|void_restore`, with no secret.
- The account's own primary password is random, 64 bytes, never disclosed. Accounts have no TOTP and no passkeys: nobody signs in to Stalwart interactively.
- Stalwart's auto-ban applies to failed logins. The doctor shows repeated failures for each account as Info.

**OAuth2 (OAUTHBEARER / XOAUTH2) through Keycloak: not in v1** (assistant's call). Three reasons:
- Stalwart's OIDC directory takes over a domain's accounts and creates them only at first sign-in (no pre-provisioned mailboxes, no deprovisioning), which conflicts with §5.
- Apple Mail needs the provider to implement the Open Public Clients profile (dynamic registration), which Keycloak doesn't fully do.
- Thunderbird offers OAuth only for providers it knows.

§12 Q1 keeps it as phase M6, for webmail and capable clients, on Stalwart's `trustedProvider` path, with the acr required at least the server's default.

## 7. DNS: the `mail` record set

The `mail` set is added to the DNS plan (DNS spec §3). It replaces `nomail` on a domain when mail is turned on for it, and puts `nomail` back when mail is turned off (assistant's call: with a warning that MX removal bounces mail). mailctl renders the wanted records:

| Name | Record | TTL |
|---|---|---|
| `<e>` | `MX 10 mail.<d>.` | 3600 |
| `<e>` | `TXT "v=spf1 mx -all"` (plus `include:<relay>` when a relay is set, §8) | 3600 |
| `mail.<d>` | `TXT "v=spf1 a -all"` (HELO identity) | 3600 |
| `<sel>._domainkey.<e>` | `TXT "v=DKIM1; k=ed25519; p=…"` and `k=rsa` (2048), selectors `v1-{ed25519,rsa}-YYYYMMDD` | 3600 |
| `_dmarc.<e>` | `TXT "v=DMARC1; p=<policy>; adkim=s; aspf=s; rua=mailto:dmarc-reports@<e>"` (no `ruf`: privacy) | 3600 |
| `_mta-sts.<e>` | `TXT "v=STSv1; id=<policy hash>"` | 3600 |
| `mta-sts.<e>` | covered by `address` / wildcard; HTTPS served via Traefik | — |
| `_smtp._tls.<e>` | `TXT "v=TLSRPTv1; rua=mailto:tls-reports@<e>"` | 3600 |
| `autoconfig.<e>`, `autodiscover.<e>` | covered by `address` / wildcard (for an enrolled zone apex without a wildcard: `CNAME mail.<d>.`) | 3600 |
| `_submissions._tcp.<e>`, `_imaps._tcp.<e>` | `SRV 0 1 465/993 mail.<d>.` (RFC 6186/8314); `_submission._tcp` `SRV 0 1 587`; `_imap._tcp`, `_pop3._tcp`, `_pop3s._tcp` `SRV 0 0 0 .` | 3600 |
| `_25._tcp.mail.<d>` | `TLSA 3 1 1 <current SPKI>` (+ `<next SPKI>` during a key rollover); **only when the main zone's DNSSEC state is `secure`**, removed when it isn't | 3600 |
| `mail.<d>` | `CAA` pinning the mail-cert account (§4) | 300 |

**Policies and their schedules** (assistant's call):

- **DMARC**
  - Domains with no MX / SPF before Portcullis start at `p=reject`: Portcullis is the only sender.
  - A domain that had other mail records starts at `p=none`. The doctor proposes `quarantine` → `reject` after 14 days of aggregate reports without unaligned sources.
- **MTA-STS**
  - Starts in `mode: testing; max_age: 86400`. It becomes `enforce; max_age: 604800` after 7 days if the certificate check and TLS-RPT show no failures.
  - mailctl serves `/.well-known/mta-sts.txt` itself (Traefik public router `HostRegexp(^mta-sts\..+$)` on mail domains only, tier `public@file`). The `id` changes with every policy change.
  - Turning mail off first publishes `mode: none` for a full `max_age` before the MX goes.
- **DKIM rotation** (Portcullis-run; Stalwart's own rotation needs its DNS provider, which is an anti-goal)
  - mailctl's state machine is `pending` (key created in Stalwart, record wanted) → `active` (record visible at both public resolvers) → `retiring` (7 days) → `retired` (record removed; key deleted 30 days later).
  - Rotation every **180 days** (`MAIL_DKIM_ROTATE`). Dual algorithms, one active key each.
  - A key suspected leaked is rotated now: `./portcullis mail dkim rotate <domain>` or the doctor fix.
- **TLSA rollover**
  - The mail key is reused, so TLSA stays stable across renewals.
  - The key changes yearly or on demand: publish the next SPKI → wait 2×TTL + 1 day → switch the certificate → drop the old SPKI.

**Who writes.**
- **Enrolled domains**: the Hub passes mailctl's wanted set to the domains service (`PUT /domains/{name}/sets/mail`, new). The domains service applies it like any set and owns it in `Domain.Records`.
- **Main domain**: `./portcullis dns setup` (`--only mail`) and the daily `mail rotate` timer, with the `.env` credentials, through `dns-tool`. mailctl's wanted set reaches them via `docker compose exec -T mailctl mailctl dns --main --json`.
- **Lego-only providers**: the plan prints the records by hand. DKIM then **doesn't rotate** (the doctor shows Info with the next manual step), as Stalwart does without a DNS provider.

## 8. Deliverability, spam and outbound

**Doctor checks** (mailctl `GET /v1/checks`, every 6 h and on demand; Hub doctor kinds in §10):
- **Outbound 25**: connect to the MX of three large providers within 10 s. If all time out, Problem "outbound port 25 is blocked (common on AWS, GCP, Azure, Oracle and DigitalOcean, and on home ISPs): ask the provider to unblock it or set a relay".
- **FCrDNS** for each public IPv4 / IPv6: the PTR must resolve to a name that resolves back to the address. `mail.<d>` is recommended, and EHLO uses `MAIL_HOSTNAME`. Missing or wrong → Problem, with how to set it at hetzner / DO / AWS (EIP form) / OVH / generic "your provider's reverse DNS panel".
  - **Outbound IPv6 is used only when the v6 PTR passes** (otherwise Gmail rejects it). This is automatic (assistant's call).
- **Blocklists**: each public address against Spamhaus ZEN (PBL listing means a residential range: "use a relay"), SpamCop and Barracuda, through `mail-resolver`.
- **The certificate** served on 25 / 465 / 587 / 993 (names, expiry, and TLSA match when DANE is on).
- **Records**: the DNS plan's `mail` items. **DKIM selftest**: sign a message and verify it against the live DNS. **Reports**: DMARC / TLS-RPT aggregates with failures in the last 7 days.
- **Inbound 25 from outside** can't be probed from inside without a third party (non-goal). `./portcullis mail test --to <external address>` sends a signed message. The docs show how to read the receiver's `Authentication-Results` and suggest a manual external tester.
- **Relay** (`MAIL_RELAY_HOST`, `_PORT`, `_USERNAME`, `_PASSWORD`, `_SPF_INCLUDE` in `.env`): outbound through a smarthost (implicit TLS or STARTTLS required, authenticated). Inbound still needs 25.

**Spam** (Stalwart built-in, assistant's call):
- **Mechanisms**: rules from the vendored file; the classifier with autolearn from Junk moves; DNSBLs (Spamhaus via its free DQS key when `MAIL_SPAMHAUS_DQS_KEY` is set, otherwise direct queries through our resolver, within free-use limits); phishing and homograph checks; sender reputation; reply tracking.
- **Off**: greylisting (delays first mail) and the AI classifier (privacy).
- **Thresholds**: score ≥ 15 is rejected at DATA (`550 5.7.1`); ≥ 5 is filed in Junk with `X-Spam-*` headers.
- **Inbound authentication**: SPF / DKIM / ARC / DMARC verification. Remote domains' DMARC `reject` is honoured at SMTP time.
- **Settings → Mail → Spam**: the two thresholds, DNSBL toggles and the DQS key. Allow and block lists by domain or address.
- **Outbound limits**: 300 recipients an hour and 1000 a day for each account (settings). An account over the limit is held and the doctor shows a Warning, so a stolen mail password can't burn the IP's reputation unnoticed.
- **Auth for submission only**: 465 / 587 require AUTH and refuse the MX role; 25 refuses AUTH.
- **No virus scanner in v1** (ClamAV costs ~1 GB RAM). The risky attachment-type rules are on (§12 Q3).

## 9. Backups, monitoring, status, CI

- **Backups**
  - `mail_data` and `mail_acme` go into `portcullis backup` (online). Stalwart's own backup / snapshot task for RocksDB writes a consistent copy, which the archive picks up (§12 Q2).
  - `stalwart-cli snapshot` (the plan) is included for the configuration.
  - **Restore voids every mail password**: mailctl destroys all app passwords after a restore, and people see "reset by a restore", as with SMB.
  - DKIM keys survive a restore (they are in the store). The DNS plan reconciles.
- **Monitoring** (profile `monitoring`):
  - Stalwart's Prometheus exporter, scraped on `monitoring` (mail joins it).
  - mailctl textfile metrics: `portcullis_mail_check{check}` 0/1, `portcullis_mail_dkim_stage{domain,stage}`, `portcullis_mail_cert_expiry_seconds`.
  - Alerts: queue > 100 for 30 min, outbound deferrals > 20 % for 1 h, certificate < 14 days, a blocklist hit, DKIM stuck in `pending` > 24 h, a check failing.
- **`./portcullis status`**: a "Mail" block (services, certificate, checks, DKIM stages, queue, the timer). `--json`: `mail: {…}`.
- **CLI**: `./portcullis mail enable|disable|status|test|dkim rotate|cert|rotate|schedule --systemd|export`.
- **CI** (core `build-and-test`, profile `mail`, with Pebble for the mail certificate):
  1. **Two-server exchange.** Portcullis' `mail` plus a second Stalwart ("remote", plain config) on a CI network, and a CoreDNS container serving both zones and the DNS plan's records (written by the `fake` provider). portcullis → remote and remote → portcullis. Assert `dkim=pass` (both algorithms), `spf=pass` and `dmarc=pass` in `Authentication-Results`, and a DMARC aggregate report received and parsed.
  2. **Open relay tests**:
     - unauthenticated RCPT to a foreign domain on 25 → `554/550`;
     - AUTH on 25 refused;
     - authenticated submission with a foreign `From` or envelope sender → refused;
     - a connection from the docker gateway / localhost doesn't relay.
  3. **Spam**: GTUBE → rejected at DATA. A message scoring between the thresholds → Junk.
  4. **Credentials** (Hub e2e with the fresh-auth harness):
     - a mail password works with `imaplib` on 993 and `smtplib` on 465 / 587;
     - the LLDAP password of the same user fails;
     - the mail password fails on Stalwart's HTTP API and on Portcullis sign-in;
     - revocation → refused within 8 s;
     - a group leave → revoked and the mailbox disabled;
     - a re-created username → a fresh mailbox.
  5. **Hardening**: network membership, mailctl the only peer of the 8080 listener, no recovery admin left (a login fails), image pins.
  6. **Go unit tests** (mailctl): the plan rendering, the DKIM / MTA-STS / TLSA state machines on a fake clock and a fake resolver, the desired-state diff, the checks against fakes.
- **Live check** on the test server (staging certificates per memory): real delivery to Gmail and Outlook test accounts, `Authentication-Results` recorded, PTR, MTA-STS and TLS-RPT reports arriving within 48 h.

## 10. Hub, contract and docs

- **Hub**
  - mailctl client.
  - **Settings → Mail**: on/off per domain, primary domain, domain → groups, relay status (read-only, from `.env`), spam, limits, quotas, retention.
  - A Mail section on person and group pages (addresses, aliases, list on/off, mail passwords count, admin revoke).
  - Sign-in → Mail passwords (§6).
  - A DNS panel `mail` set (via the DNS spec's panel).
  - Hostname reservation.
  - **Doctor kinds** (`internal/doctor/mail.go`):
    - `mail_port25_blocked` (Problem, explain);
    - `mail_ptr_missing` / `mail_ptr_mismatch` (Problem, explain with provider steps);
    - `mail_blocklisted` (Problem, explain);
    - `mail_records_wrong` (Problem, one-click `dns_apply` with sets `[mail]` / main: explain);
    - `mail_dkim_stuck` (Warning);
    - `mail_dkim_manual` (Info);
    - `mail_cert_expiring` (Warning / Problem);
    - `mail_dmarc_failures` (Warning);
    - `mail_dmarc_promote` (Info, one-click);
    - `mail_mtasts_enforce` (Info, one-click);
    - `mail_ipv6_ptr` (Info);
    - `mail_client_ip_rewritten` (Warning);
    - `mail_rate_held` (Warning);
    - `mail_timer_missing` (Warning).
  - MCP: the existing doctor tools cover these. A read-only `mail_status` tool is added to the Portcullis MCP; no credential tools ever.
- **Contract**
  - New **§16 Mail** (profile, services, networks, the mailctl API `PUT /v1/state`, `GET /v1/dns/{domain}`, `GET /v1/checks`, `POST|DELETE /v1/credentials`, reserved labels, the `mail` set, removal timing, restore voiding).
  - §12.2 `PUT /domains/{name}/sets/mail`. §5.1 the mail-password routes. §14.5–14.6 the doctor kinds.
- **Docs**
  - New `setup/mail.md`: prerequisites (port 25 both ways, PTR, static IP), enable, DNS, clients, relay.
  - New `operations/mail.md`: spam, DKIM, MTA-STS / DMARC promotion, backups, troubleshooting.
  - `operations/hardening.md` rows for mail, mailctl and mail-resolver.
  - The `setup/dns.md` `mail` set. The people guide "Mail passwords".
  - Core `CLAUDE.md` and `.env.example`.

## 11. Task outline and parked follow-ups

1. **M1 mailctl skeleton + bootstrap**
   - compose profile, networks, `mail-resolver`;
   - `mail enable` recovery bootstrap, base plan, API key, recovery removal;
   - the dedicated certificate via `dns-tool mail-cert` + timer + reload;
   - hardening CI.
2. **M2 Identity + credentials**
   - the desired-state API, the reconcile loop, uuid keying, former mailboxes;
   - the Hub's computation from `mail_users`, aliases, lists, quotas;
   - Sign-in → Mail passwords; revocation timing; restore voiding;
   - CI items 2 and 4.
3. **M3 DNS + authenticity**
   - the `mail` set rendering, domains `sets/mail`, the main-domain path;
   - the DKIM / MTA-STS / TLSA state machines, DMARC policy logic, the well-known router;
   - CI item 1.
4. **M4 Deliverability + spam + ops**
   - the checks, relay, spam settings, rate limits;
   - doctor kinds, status, metrics / alerts, backups;
   - CI item 3;
   - contract §16, docs;
   - the live check;
   - then mainline every branch (memory).
5. **M5 (optional) webmail**: a `roundcube` template signing in through Keycloak, IMAP via OAUTHBEARER. Depends on M6.
6. **M6 (optional) OAuth2 for mail clients** (§12 Q1).

**Parked:**
- app sender accounts for templates and Alertmanager;
- inbound backup MX / relay for blocked 25;
- JMAP / CalDAV / CardDAV for people;
- Sieve filters and vacation replies on people.<domain>;
- ClamAV;
- the Porkbun / Route53 manual paths for DKIM;
- rootless podman's low-port publish (roadmap item);
- multi-server.

## 12. Open questions (each has a default; work proceeds on the default)

1. **OAUTHBEARER via Keycloak.** *Default:* not in v1. In M6, test Stalwart's OIDC `trustedProvider` for internal-directory accounts. Ship only if a Keycloak token with the required acr can open IMAP for a pre-provisioned account without handing the domain to the OIDC directory.
2. **Online backup of RocksDB.** *Default:* use Stalwart's documented backup task. If it can only copy offline, `backup` stops `mail` alone for the copy (remote senders retry while the port is closed) and documents it as the one exception to "never stop services".
3. **Antivirus.** *Default:* none in v1. Attachment-type rules reject executables and macros. ClamAV is an optional milter later.
4. **Memory.** *Default:* `mem_limit 1g`, with Stalwart's caches reduced in the base plan (its defaults total ~2.4 GiB on a 2 GiB host). Raise it in M4 if the live check shows pressure.
5. **The mail certificate's ACME account.** *Default:* its own account in `mail_acme`, pinned by a CAA at `mail.<d>`. If T-M1 finds that Traefik can issue `mail.<d>` with a reused key through a second resolver, still keep the separate tool: the key must stay out of Traefik's store.
