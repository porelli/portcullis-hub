# Mail provider slot: the mail server as a swappable Marketplace provider (design)

Status: written by the assistant for the user's request to make mail "swappable for another mail server later without core changes". The user agreed the model up front:

- one active mail provider at a time;
- core and the Hub grant that provider the server-wide powers normal apps can't have;
- the Hub drives it through the §19 contract;
- Stalwart + mailctl becomes the first provider, as a Marketplace template.

Every other decision is the **assistant's call** unless it says otherwise.

**Revision 2 (2026-11-16): the user approved the design.** The open questions are decided (§15):
- **User ruling:** **any** installed template with a `mail:` block may be a mail provider. There is no trusted-source restriction, so containment never relies on the template's source (§10.2).
- The other three answers are the assistant's recommendations, accepted.

This spec builds on the mail spec (`2026-11-13-mail-server-design.md`), the VPN spec (`2026-11-13-vpn-only-access-design.md`, whose provider pattern it copies), and the shipped rulings in `.superpowers/sdd/2026-11-14-mail-server/progress.md`.

**Baseline.** Mail shipped on `origin/main` as core 9408f97, Hub 75cdbfe, docs bd4668a and templates 5637458. The local `main` checkouts under `/Volumes/workspace/portcullis/` are behind `origin/main`, so the recon read `origin/main`. Paths below are repo-relative.

## 1. Where things stand (2026-11-16)

### 1.1 Mail is a core profile

- **Core** (`portcullis`):
  - `docker-compose.yml` defines the `mail` profile's services: `mail` (Stalwart v1.1.0, pinned, with a fail-closed `/bin/sh` entrypoint gate), `mailctl` (built from `mailctl/`), `mail-resolver` (Unbound) and the `tools` one-shot `mail-cert` (the `portcullis-domains` image, `domains mail-cert`).
  - It also defines four networks (`portcullis-mail`, `portcullis-mailctl`, `portcullis-metrics-mail`, `mail-egress`) and five volumes (`mail_data`, `mail_etc`, `mail_tls`, `mail_acme`, `mailctl_data`).
  - `docker-compose.mail-recovery.yml` is the recovery session's overlay. `docker-compose.podman.yml` and `docker-compose.podman-selinux.yml` carry the mail entries for Podman.
  - `scripts/lib/mail.sh` (1019 lines) holds `mail enable|disable|status|test|dkim|cert|rotate|schedule|export`, the recovery session, the void gate (`mail_void_pending`, `mail_void_restore`), the Prometheus targets (`mail_prom_targets`) and the timer.
  - `scripts/lib/backup.sh` stops mail while it copies (`_backup_mail_data`, `BACKUP_MAIL_STOPPED_VOLUMES`). On restore it writes the marker (`_restore_mail_marker`), voids (`_restore_mail_void`) and reports the outcome (`_restore_mail_outcome`).
  - `scripts/lib/dns.sh` passes the `mail` set and `mail_hostname` into `dns-tool`.
  - `scripts/lib/network.sh` checks the mail subnets.
  - `monitoring/prometheus/prometheus.yml` and `alerts.yml` hold the `mail` / `mailctl` jobs and six `Mail*` alerts. `alerts.yml:18` is a generic `up == 0` alert.
- **mailctl** (`mailctl/internal/…`) has two kinds of package:
  - Stalwart-specific: `stalwart`, `bootstrap`, `admin`, `reconcile`, `spamrules`, `export`, `creds` (JMAP AppPasswords) and `resolve`.
  - Server-neutral: `api`, `state` (MailState v1 and its vector `internal/state/testdata/mailstate_v1.json`), `dnsset`, `machines`, `dkim`, `dmarc`, `mtasts`, `tlsa`, `checks`, `wellknown`, `metrics` and `logx`.
- **Core CI** (`.github/workflows/ci.yml`):
  - `unit-tests` runs the mail wiring step (`.github/ci/unit-tests-mail-wiring.sh`), the mailctl unit tests and the MailState vector check against the Hub.
  - `build-and-test` has "Test the mail service …" (`.github/ci/build-and-test-mail-service.sh`) and the mail backup/restore steps.
  - `e2e-mail` runs nine scenarios plus the restore (`.github/ci/e2e-mail-start-stack.sh`, `e2e-mail-remote.sh`).
  - `e2e-podman` has "Mail on rootless Podman" (`.github/ci/e2e-podman-mail.sh`).
  - `.github/ci/mail-gate-entrypoint.sh` tests the entrypoint gate.
- **Hub** (`portcullis-hub`):
  - `internal/mailctl/{client,types}.go` is the client. `internal/hub/mail_core.go` defines the `MailAPI` interface, which is already a clean provider seam: `PutState`, `State`, `DNS`, `Checks`, `Status`, `Credentials`, `CreateCredential`, `RevokeCredential`, `Action`.
  - `mail.go` (sync, debounce, `mail-last.json`), `mail_state.go` (`BuildMailState`, `diffMail`), `mail_pending.go` (mass removal), `mail_creds.go` (mail passwords, reconcile, restore void), `mail_dns.go` (added domains' sets, hash poll), `mail_admin.go` (Settings → Mail, lists, aliases, host drain) and `mail_restart.go` (`RestartCoreService("mail")`).
  - `internal/hub/doctor_mail.go` and `internal/doctor/mail.go` hold the 22 kinds. `internal/hub/ports.go:160` holds the port collision check on `mailPorts`. `internal/templates/coreref.go:52–60, 842–847` holds the mail core names. `web/mail.js` is the UI.
- **Templates** (`portcullis-templates`): `tests/validate.py` reserves the mail core names (`CORE_NETWORKS`, `CORE_TRAEFIK_NAMES`) and the `PORTCULLIS_MAIL` prefix (`VAR_MAIL_PREFIX`, line 106).
- **Docs** (`portcullis-docs/docs/guides/integration-contracts.md`):
  - §19.1–19.12 is mail.
  - Mail is also referenced from §2 (core.env keys), §3 (mail core names), §5 (`mail-wellknown`, reserved labels), §6 (the Hub's one restart of core `mail`), §12.2 (`PUT/DELETE /domains/{name}/sets/mail`), §13.16, §14.5/14.6 (the kinds and fixes), §15.10 (`mail_status`) and §16 (host routes).

### 1.2 How VPN providers work

The precedent this spec copies:

- **Core infrastructure.** The `wg` service (§16) is profile `wg`, opened by `./portcullis vpn init`. It owns the edge, the built-in provider and the networks `portcullis-vpn` / `portcullis-vpn-edge`.
- **The capability is declared in the manifest.** A template declares a `vpn:` block (§3.3; Hub `internal/templates/vpn.go` `ValidateVPN`; templates `tests/validate.py` with the shared `tests/vpn_vectors.json`). Today only `headscale/manifest.yaml` has one.
- **Wiring is a separate admin act.** Installing the template doesn't make it a provider: the admin wires an instance (`PUT /api/instances/{id}/vpn-provider`, `internal/hub/vpn_providers.go` `SetVPNProvider`).
  - Wiring is refused while `wg` isn't up ("run ./portcullis vpn init on the host"), on a range overlap, or with no free slot.
  - It is audited `vpn.provider_wired` / `vpn.provider_unwired`.
- **The Hub's override attaches the provider to core infrastructure.** The ingress service joins `portcullis-vpn` at a pinned `.16 + slot` and gets `PORTCULLIS_VPN_EDGE` (`internal/hub/override.go:252–402`, `vpnAttachLocked`). The template never names a core network.
- **Containment.**
  - A template with a `vpn:` block gets stricter rules than other templates on every service (§3.3 "Mounts and volumes of every service"):
    - `./` binds only, read-only template files;
    - plain volumes;
    - no YAML anchors;
    - the gateway: `cap_drop: [ALL]`, only `NET_BIND_SERVICE`, no devices and no host namespaces.
  - Core and the Hub keep the identity rules: the device map is validated, owners resolve to Portcullis people and stale maps fail closed.
- **No source restriction.** Any installed template with a valid `vpn:` block may be wired. §3 "Trust model" says that installing a source means trusting it with the host (`docs/operations/hub.md` "Template sources": only the default source `portcullis` can't be removed).
- **Several VPN providers may be wired at once** (slots 0–46). Mail differs here: one at a time.

### 1.3 What a template may not do today

These rules are why mail was made core:

- A template may not publish 25/465/587/993 while `PORTCULLIS_MAIL=on` (§19.2; `ports.go`).
- It may not join a core network or name one (§3).
- It may not mount a core volume or any external `portcullis*` volume (§3 "Volumes").
- It may not name a core DNS name or a core router (§3).
- It may not use the `PORTCULLIS_MAIL*` variables.
- `person_secret` / `person_id` options are allowed only on router-less templates (§3 "HTTP routers").
- It may not write DNS. Only core's `dns-tool` (main domain) and the `domains` service (added domains, fed by the Hub) write records.
- It may not hold a certificate. `tls.certresolver` / `tls.domains` are refused, because certificates are core's.

## 2. Goals, non-goals, anti-goals

**Goals**
1. **Swappable.** A second mail server (Maddy, Postfix+Dovecot, Mox, …) is one more template that implements the provider API, with **no core or Hub change**.
2. **One slot.** At most one wired mail provider. The slot's powers are granted only to the wired instance and are withdrawn when it is unwired.
3. **Same guarantees.** Every security invariant of the shipped mail (§10) holds unchanged, and every CI check that guards one keeps running, now against the provider template (§12).
4. **Stalwart first.** Stalwart + mailctl ships as the template `stalwart` in `portcullis-templates`. What it does for people (sending, receiving, spam, DKIM, MTA-STS, DANE, lists, mail passwords) is unchanged.

**Non-goals**
- **Mailbox migration between providers.** A switch starts the new provider with empty mailboxes. The old instance is stopped and its data kept, and the admin moves mail with the servers' own tools if they want to. Export/import is out of scope; the one trivial path is the existing former-account mbox export, which stays a provider capability (§6.12).
- **Several active providers** (for example split by domain).
- **Mail on Kubernetes** (still refused, §19.12).
- **IPv6 mail** (still refused).
- **Webmail.**

**Anti-goals** (never)
- **No mail server code in core or the Hub.** No Stalwart name, image, JMAP call or config in core or Hub code paths. The provider-specific appendix lives with the template (§7).
- **The provider never gets** DNS credentials, the main wildcard key, LLDAP / Keycloak credentials, engine access or `hub_data`: the same "never" list as `mailctl` today.
- **The slot is no generic escalation.** It grants exactly the allowlist in §4. A template can't use the `mail:` block to get anything else (a core network for a non-API service, an arbitrary port, a core volume other than the certificate).

## 3. The model in one page

Three parts:

- **The mail slot** (core + Hub, generic): core infrastructure that is useless without a provider, plus the Hub's driver for the provider API.
- **The provider** (a template with a `mail:` block, wired by an admin): the mail server and its adapter.
- **The provider API** (contract §19, made neutral): the HTTP API the Hub speaks to the provider, plus the obligations the provider must meet.

| Piece | Today | After (assistant's call unless marked) |
|---|---|---|
| Compose profile `mail`, services `mail`, `mailctl`, `mail-resolver` | core | **template `stalwart`** (services `stalwart`, `adapter` = mailctl, `resolver` = Unbound) |
| `docker-compose.mail-recovery.yml`, recovery session, bootstrap | core CLI | **template** (a one-off job, §6.13) |
| `mail-cert` one-shot, `mail_tls`, `mail_acme`, CAA at `MAIL_HOSTNAME` | core | **stays core** (§6.4) |
| TLSA `_25._tcp.<MAIL_HOSTNAME>`, HELO SPF at `MAIL_HOSTNAME`, `MAIL_HOSTNAME` A/AAAA | mailctl renders TLSA and HELO SPF; core owns A/AAAA | **core** (dns-tool renders all three; the TLSA rollover moves from `mailctl/internal/tlsa` into core, §6.4) |
| Per-domain `mail` set (MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT, SRV, CNAMEs) | mailctl | **provider**, served on `GET /v1/dns/{domain}`, **validated by the Hub and the domains service** (§6.3) |
| Network Hub ⇄ provider | `portcullis-mailctl` (core) | **stays core**, renamed `portcullis-mail-api`; the Hub's override attaches the provider's API service at a pinned address with alias `mail-api` |
| Hub ⇄ provider bearer secret | `secrets/mail/hub-secret`, written by core | **Hub-generated on every wiring**, delivered through the reserved `portcullis-hub-secrets` mount (§6.2) |
| `portcullis-mail`, `mail-egress` networks | core | **template-internal** (the template's own networks) |
| Published 25/465/587/993 | core compose | **the Hub's override**, on the wired provider's declared listener service (§6.1) |
| Well-known router (MTA-STS, autoconfig, autodiscover) | core `mail-wellknown` on mailctl, plus the Hub's per-domain routers | **the Hub's override** renders `portcullis-mail-wellknown` onto the provider's declared service and port (§6.8) |
| Session reset after a revoke | Hub `RestartCoreService("mail")` | the Hub restarts the provider's **declared** service, through its normal instance path (§6.5) |
| Void gate (marker, entrypoint wrapper, start primitive) | core CLI + Stalwart wrapper | **the Hub's start primitive** (void mode) + the gate files on `hub_secrets` + the template's entrypoint wrapper (§6.10) |
| Mail data backup | core `backup` stops mail | **a Hub instance backup** of the provider, triggered by core `backup`, inside the `hub_data` archive (§6.10) |
| Prometheus targets and metrics secret | core-written `mail-targets.json` | **Hub-written**, into a new core volume `mail_slot` (Hub read-write, Prometheus read-only) (§6.11) |
| Mail alerts | core | **stay core**, keyed on the contract metric names; `MailCertExpiring` moves to core's own textfile metric |
| Relay, DKIM rotation, former retention | core `.env` | **Settings → Mail** (Hub), sent in MailState v2; the relay password is a Hub secret delivered as a file |
| Spamhaus DQS key | core `.env` | **a `stalwart` template setting** (provider-specific) |
| `MAIL_HOSTNAME`, LAN-only, `MAIL_ACME_CA_SERVER`, `MAIL_CAA_ISSUER` | core `.env` | **stay core** (LAN-only stays CLI-only, the shipped rule) |

The adapter pattern: every provider is **an upstream server plus a Portcullis adapter** that serves the provider API. For Stalwart the adapter is mailctl. Its server-neutral packages (`state`, `machines`, `dnsset`, `checks` framework, `wellknown`, report trust) are a Go library that future adapters can import, so DKIM, MTA-STS and DMARC behaviour doesn't drift between providers.

## 4. The `mail:` manifest block (template capability)

A template that is a mail server may declare a top-level `mail:` block. As with `vpn:`, the block alone grants nothing: only the **wired** instance gets the powers.

- The templates repo's schema, `tests/validate.py` and the Hub's new `templates.ValidateMail` implement exactly the rules below, with the same refusal texts in the same order.
- The two share `tests/mail_vectors.json` / `internal/templates/testdata/mail_vectors.json`, byte copies checked in CI the way `vpn_vectors.json` is.
- The Hub skips a template that fails them.

```yaml
# manifest.yaml (excerpt, template stalwart)
instances: single
mail:
  label: Stalwart
  api_version: 1
  api:       {service: adapter, port: 8080}
  listeners: {service: stalwart, smtp: 10025, submissions: 10465, submission: 10587, imaps: 10993}
  wellknown: {service: adapter, port: 8081}
  metrics:   {service: adapter, port: 9100}
  server_metrics: {service: stalwart, port: 9180, path: /metrics/prometheus}   # optional
  tls:       [stalwart, adapter]        # services that get the mail certificate, read-only
  gated:     [stalwart, adapter]        # services that get the gate files and must honour them
  sessions:  {restart: stalwart}        # restarted after every removal and revoke
  export:    {service: adapter, argv: ["mailctl", "export", "--former", "{former_id}"]}   # optional
```

**Fields** (unknown keys refused; only `server_metrics` and `export` are optional):

- `label`: one line, 1–64 characters.
- `api_version`: exactly `1`. The Hub refuses a version it doesn't speak (`409` at wiring, doctor `mail_provider_refused`).
- `api`, `wellknown`, `metrics`, `server_metrics`: a compose service of the template plus a port, 1024–65535.
  - Not a job, not an AI companion, no `network_mode`.
  - **No Traefik router and no `traefik.*` label on any service of a mail template.** The only router is the Hub's well-known router (§6.8). **Exception (ux2, 2026-11-20, user ruling): the mail admin view is read-only and admin-only.** An optional `admin_view: {service, port}` gets the Hub's admin view router on `mail-admin.<main domain>` (full administrators only, never the portal, MCP or AI), and the provider MUST make the mail server itself refuse every write of the view's principal and mask every secret (contract §19.13). All management stays in the Hub, so every guard below still applies.
- `listeners`: exactly the four keys, each a container port 1024–65535, all on one service. That service publishes no port itself: the template's compose has **no `ports:` on any service**, and the manifest has no `ports` list.
- `tls`, `gated`: lists of services. Every service in `listeners` and `api` must be in both. A service that serves mail or holds credentials must honour the gate.
- `sessions.restart`: one service, normally the listener service. **Required**: the Hub restarts it after every removal and every revoked mail password, whatever the server claims about sessions (§10, invariant 8).
- `export.argv`: a literal argv with exactly one `{former_id}` placeholder, run by `./portcullis mail export` as an exec in that service. Stdout is the mbox (§6.12).

**Stricter rules for every service of a mail template.** These are the VPN gateway's rules (§3.3), applied to the whole template, because a mail provider holds everyone's mailbox:

- not `privileged`;
- `cap_drop: [ALL]`, and `cap_add` only `NET_BIND_SERVICE` (Stalwart's binary needs it, §19.1);
- no `devices` or `device_cgroup_rules`;
- no `pid`, `ipc` or `network_mode: host`, and no `volumes_from` into another project;
- binds only `./templates/<id>/…`, read-only;
- plain `<project>_<key>` volumes;
- no YAML anchors or merge keys;
- no `enable_ipv6` on any network (the shipped IPv6 ruling);
- no `person_secret` / `person_id` options: mail passwords go only through the provider API;
- `instances: single` (justified in `auth.notes`: the host ports and the one slot).

The `auth` block must be `method: custom` with no routers and `group_access: false`. The mailbox population is the Hub's `mail_users` group, never the template's.

**Refusal texts** (examples; the full list goes into the contract and the vectors):

- `mail.api_version: only 1`
- `mail.listeners: exactly smtp, submissions, submission and imaps, on one service`
- `mail: service <s> publishes ports: the Hub publishes a mail provider's ports`
- `mail: service <s> has a Traefik router: a mail provider's only router is the Hub's well-known router`
- `mail.tls: <s> serves mail and must be listed`
- `mail.gated: <s> serves mail and must be listed`
- `mail.sessions.restart: required`
- `mail: <s> adds <cap>: a mail provider may add only NET_BIND_SERVICE`
- `mail: person_secret options are not allowed: mail passwords go through the provider API`

The VPN mount texts are reused with the prefix `mail:`.

## 5. The slot's lifecycle

### 5.1 Open, install, wire

1. **Open the slot (core).** `./portcullis mail enable [--hostname H] [--lan-only true|false] [--provider stalwart|none] [--yes]`.
   - Refusals as today: Kubernetes, a lego-only DNS provider, `MAIL_IPV6`, LAN-only on rootless Podman, Podman `ip_unprivileged_port_start` > 25.
   - It writes `PORTCULLIS_MAIL=on`, `MAIL_HOSTNAME` and `MAIL_SUBMISSION_LAN_ONLY`, creates `portcullis-mail-api`, `portcullis-metrics-mail` and `mail_slot`, runs `mail-cert` and refreshes `core.env`.
   - Then, unless `--provider none`, it asks the Hub through the host socket to install the default provider and wire it (`hub mail install stalwart`, below). It prints the DNS step as today.
   - No compose profile is added: the slot is infrastructure, not services. (Assistant's call, mirroring `vpn init`.)
2. **Install (Hub, Marketplace).** Like any app. A template with a `mail:` block shows a "Mail server" badge. Installing creates and enables the instance, but its override publishes no mail ports and attaches nothing (a stalled server with no inbound path). The adapter waits, with no document.
3. **Wire (Hub).** On the instance's **Mail** tab: *Use as this server's mail* (`PUT /api/instances/{id}/mail-provider {"wired": true, "confirm": "<instance id>"}`). Any installed template with a valid `mail:` block can be wired (user ruling, §15 Q1). The guards, which also apply to a re-wire after a template update (§10.2):
   - **Admin with a fresh sign-in.** Full administrators only (`lldap_admin`; delegates `403`). The call carries a fresh-auth proof (contract §8, as for creating a mail password); a missing or stale proof is `403`.
   - **Typed confirmation.** `confirm` must equal the instance id exactly, else `400` "type the instance id to confirm".
   - **An explicit warning, in the UI and in the API.**
     - The UI shows it, and the Mail tab's `GET /api/instances/{id}/mail-provider` returns the same text as `warning`.
     - The text names the powers the instance gets: "This app becomes the mail server for every person and every mail domain. It gets public ports 25, 465, 587 and 993, writes the mail DNS records of every mail domain, creates and checks the mail passwords of every person in mail_users, sends mail to the internet (outbound SMTP), and can read every mailbox."
     - The PUT answer repeats it.
   - **Never from MCP or AI.** There is no tool. A request carrying an AI or MCP token (contract §15) is refused (`403`) on this route, on switch and on the re-wire.
   - **Audited.** `mail.provider_wired`, with the instance, the template, its source and commit, the `mail:` block hash and the actor.
   - **The host path.** `./portcullis mail enable` (and `--provider`) wires through the host socket (actor `host`). There the host operator's own confirmation stands in for the fresh sign-in: the CLI prints the same warning and asks the operator to type the instance id; `--yes` accepts it. It is audited the same way (assistant's call: the host operator already holds the host).
   - **Refusals** (`409`):
     - `PORTCULLIS_MAIL` isn't `on`: "mail is off: run ./portcullis mail enable on the host";
     - another instance is wired: "<id> is this server's mail provider: switch instead";
     - the runtime is Kubernetes;
     - the rootless compatibility gate (§11.10) says `refused` for the listener ports;
     - another instance publishes 25/465/587/993;
     - `api_version` is unknown.
   - **Steps, in order.** Each later step runs only after the earlier one succeeded:
     1. Record `state.yaml` `mail.provider = {instance, wired_at, template_commit, block_hash}` and mark a void owed.
     2. Generate the API secret and the gate files (§6.2, §6.10).
     3. Render the override in **void mode** (no ports, internal networks only) and `up`.
     4. Wait for `GET /v1/state` `bootstrap: true`, then `POST /v1/void` and verify (§6.10).
     5. Render the normal override (ports, well-known router, metrics) and `up`.
     6. Send the first MailState document.
     7. Publish the DNS sets after the first accepted document (as today, §6.3).
   - **Every wiring starts with a void** (assistant's call): a provider that arrives with credentials from a restore, an older wiring or an imported store starts clean. Wiring is an op with progress and Stop (§11.7 pattern).

### 5.2 Switch

`POST /api/mail/provider/switch {"to": "<instance>", "confirm": "<instance>", "confirm_empty": "<n> mailboxes start empty"}`. The switch wires the new provider, so it has every guard of §5.1 step 3 (fresh sign-in, the typed instance id, the warning, no MCP/AI, audited), plus the typed phrase shown. Audited `mail.provider_switched`.

- **Same MX.** Every domain's MX, SRV and MTA-STS `mx:` name `MAIL_HOSTNAME`, and the certificate is core's, so **a switch changes no MX and no TLSA**. There is no drain: it is a cutover.
- **Steps:**
  1. Unwire the old provider (§5.3, *switch* variant: no drain, the DNS sets stay).
  2. Wire the new one (§5.1 step 3).
  3. The new provider's sets replace the old ones domain by domain.
- **DKIM continuity.** For 7 days the Hub keeps the old provider's DKIM TXT records (`*._domainkey.<e>`) in each domain's set, marked retiring, so messages signed just before the switch still verify. MTA-STS restarts at `testing` (a fresh id). That is a weakening, but the certificate is the same, so senders with a cached `enforce` policy keep working.
- **The DMARC floor.** MailState v2 carries each domain's current `p=` as `dmarc_floor`. The Hub refuses a set from the new provider with a lower policy (§6.3), so a switch never lowers DMARC.
- **Data.** The old instance is stopped, not deleted: its volumes stay until a guarded delete (§11.4). People's mailboxes on the new provider start empty. IMAP clients may drop their local copies; the confirmation says so.
- **Credentials.** Every active mail password row becomes `voided` with the new reason `provider_changed` ("the mail server changed on <date>: create a new mail password").

### 5.3 Unwire, disable, uninstall

- **Unwire** (`PUT …/mail-provider {"wired": false, "drain": true|false}`, audited `mail.provider_unwired`):
  - **`drain: true`** (the default): every domain goes `draining` as with `mail disable` today (§19.7: MTA-STS `mode: none` for the last `max_age`). Then the Hub removes every `mail` set (`DELETE /domains/{name}/sets/mail`, so `nomail` comes back), and the main domain's set is withdrawn by the CLI timer's next pass.
  - **`drain: false`** (`--force`): the sets go now, and senders may bounce.
  - **Then, in order:**
    1. Every mail password row is voided (reason `provider_changed`).
    2. The Hub calls `POST /v1/void` (best effort).
    3. It deletes the API secret and the gate sentinel, so the gate closes.
    4. It renders the override without ports, attachment or router, and **stops the instance**.

    The instance stays installed with its data.
- **Disable the slot** (`./portcullis mail disable [--force]`): unwires through the host socket (drain unless `--force`), waits for every domain to be `off` as today, then writes `PORTCULLIS_MAIL=off`. The networks and `mail_slot` stay, and so do `MAIL_HOSTNAME`'s A record and CAA pin (the parked ruling L6).
- **Uninstall / delete the provider instance.** The normal guarded delete (§11.4) is refused (`409`) while the instance is wired: "unwire it first (Settings → Mail)". Deleting an unwired provider is an ordinary app delete.

## 6. The capabilities and how each is gated

### 6.1 Published ports 25/465/587/993

- **Who binds.** The Hub's override, only for the wired instance, on `mail.listeners.service`: `0.0.0.0:25:<smtp>`, `0.0.0.0:465:<submissions>`, `0.0.0.0:587:<submission>`, `0.0.0.0:993:<imaps>`. IPv4 only, no `[::]` lines (the shipped ruling). The template can't publish anything (§4).
- **Collision.** While the slot is open, no instance but the wired provider may publish one of the four ports (`ports.go` keeps `mailPorts`, now keyed on "slot open" rather than "core mail on"). Wiring is refused while another instance holds one.
- **LAN-only.** It stays the core CLI's setting (`MAIL_SUBMISSION_LAN_ONLY`, `core.env` `PORTCULLIS_MAIL_SUBMISSION_LAN_ONLY`), refused on rootless Podman as today. The Hub sends `submission_lan_only` and `local_networks` in MailState v2. The provider must enforce both layers (the per-credential IP restriction and an auth rule on submission and IMAPS). **The Hub verifies the first layer:** `GET /v1/credentials` returns each credential's `allowed_ips`. A credential whose set isn't exactly the Local networks while LAN-only is on is revoked at once, and the doctor reports `mail_lan_only_unenforced` (Problem). The ports are never `lan_only` (25 must be public).
- **Podman.** The existing compatibility gate (§11.10, "below the port start") reads the listener ports as 25/465/587/993 for a mail template, so `ip_unprivileged_port_start` > 25 makes the wiring `refused`, as `mail enable` already refuses. The client-address mode (`preserved` or `rewritten`) is computed by core `up` into `core.env` `PORTCULLIS_MAIL_CLIENT_IP` (formerly `MAILCTL_CLIENT_IP`) and sent in MailState v2 `client_ip`. The provider must degrade as §19.8 says (SPF, iprev and the IP DNSBLs off; DMARC only on DKIM alignment, never rejecting).

### 6.2 The API network and secret

- **Network.** `portcullis-mail-api` (core, internal, fixed subnet `${PORTCULLIS_MAIL_API_SUBNET:-172.31.255.16/28}`, today's `portcullis-mailctl` values). The Hub is pinned at `.18`. The override attaches `mail.api.service` at `.19` with alias `mail-api`. Nothing else may join (§3 core networks). `HUB_MAIL_API_URL` defaults to `http://mail-api:8080`, and the port comes from `mail.api.port`: the override maps nothing, and the Hub dials `<alias>:<port>` from the block.
- **Secret.** On every wiring the Hub generates a 48-character bearer and writes it to `hub_secrets` `<instance>/_mail/api-secret` (0640, gid 2000, in place).
  - The override mounts `<instance>/_mail/` read-only at `/run/portcullis/mail/slot/` into the `gated` services, through the reserved `portcullis-hub-secrets` key (§6 "per-person secrets mount": only those services, that subpath, read-only, refused otherwise).
  - It replaces core's `secrets/mail/hub-secret`, which removes the in-place bind bug class (progress.md line 85) for this file.
  - Unwiring deletes it.
  - The provider must refuse requests whose source address is outside the subnet, and every request without the bearer (§19.5 as today).
- **gid 2000.** The contract's "mail provider" group (`CT_GID_MAIL_PROVIDER`, today `CT_UID_MAIL`). The override adds `group_add: ["2000"]` to the `tls` and `gated` services, so they can read the certificate, the gate and the secret whatever uid the image uses.

### 6.3 DNS: provider-supplied sets, core-written, Hub-validated

- **Unchanged contract.** The Hub reads `GET /v1/dns/{domain}[?wildcard=…]` after every accepted document, on a change of `GET /v1/status` `dns` hash (60 s poll), and every 6 h. It writes added domains with `PUT /domains/{name}/sets/mail`. The main domain is written by the CLI only.
- **Main domain.** The CLI now gets the provider's set through the Hub: `GET /host/mail/dns/main`, which `hub mail dns-main` runs. It replaces `mailctl dns --main --json` and exec. `dns-tool` adds core's own records: the HELO SPF `v=spf1 a -all` at `<h>`, `<h>` A/AAAA (already core's) and the TLSA (§6.4).
- **Set validation.** One shared rule set (`internal/mailprovider/dnsrules.go` in the Hub, mirrored in `domains/` for `PUT …/sets/mail`; a vectors file shared by both). The Hub drops a set that fails, keeps the last good one and reports `mail_records_wrong` with the reason. The domains service refuses it (`400`). Only these names under the mail domain `<e>`, these types and these values:

  | Name | Allowed |
  |---|---|
  | `<e>` | `MX <prio> <h>.` (target exactly `MAIL_HOSTNAME`); one TXT starting `v=spf1 ` whose terms are only `mx`, `-all` / `~all` and `include:<relay include>` when the admin set one in Settings → Mail |
  | `<sel>._domainkey.<e>` (`sel` a single DNS label) | TXT starting `v=DKIM1;` |
  | `_dmarc.<e>` | TXT `v=DMARC1; …` with `p=` ≥ the domain's `dmarc_floor`, `rua` only `mailto:` addresses on `<e>`, no `ruf` |
  | `_mta-sts.<e>` | TXT `v=STSv1; id=<1–32 alnum>` |
  | `_smtp._tls.<e>` | TXT `v=TLSRPTv1; rua=mailto:<addr on e>` |
  | `_submissions._tcp`, `_submission._tcp`, `_imaps._tcp` | `SRV <p> <w> 465/587/993 <h>.` |
  | `_imap._tcp`, `_pop3._tcp`, `_pop3s._tcp` | `SRV 0 0 0 .` only |
  | `mta-sts.<e>`, `autoconfig.<e>`, `autodiscover.<e>` | `CNAME <h>.`, only when the Hub asked with `wildcard=false` |

  - Never A, AAAA, CAA, NS, DS, TLSA or any other type; never a name outside the table.
  - The provider can't point mail at another host, widen SPF, receive reports elsewhere, lower DMARC, or touch the CAA (`mail-cert`'s, unchanged) or the address records.
- **MTA-STS policy check.** The Hub fetches each mail domain's `/.well-known/mta-sts.txt` through Traefik every 6 h and refuses a policy whose `mx:` isn't exactly `MAIL_HOSTNAME`: doctor `mail_records_wrong` (assistant's call: the policy is served by the provider, so the Hub checks it).
- **Ownership rules already shipped stay.**
  - The address set owns `MAIL_HOSTNAME`'s A/AAAA with the slot open, whether or not a provider has sent anything (progress.md lines 78 and 106; now "with `PORTCULLIS_MAIL=on`").
  - The CAA at `<h>` is `mail-cert`'s.
  - Former hostnames are adopted only from `secrets/mail/former-hostnames`.
  - Deleting an added domain is refused while its mail is `on` or `draining`.

### 6.4 The certificate and TLSA

- **`mail-cert` stays a core one-shot** (decision: stays). It holds DNS credentials, its own ACME account and the reused key. A provider must never get any of these. Volumes `mail_tls` and `mail_acme` and the daily timer stay core. `mail_tls` files become group 2000 (§6.2).
- **The mount.** The override mounts `portcullis_mail_tls` read-only at `/run/portcullis/mail/tls` into `mail.tls` services, only for the wired instance. Before every `up` the Hub checks the rendered project: that volume is mounted only there and only read-only, else `409` (the `hub_secrets` check pattern). The certificate's SAN is exactly `MAIL_HOSTNAME`, so a compromised provider can't impersonate `auth.<d>` (the shipped rule).
- **Reload.** After a renewal the timer calls `POST /host/mail/tls` `{"spki_sha256", "not_after"}` (`hub mail tls`). The Hub records it and calls the provider's new `POST /v1/tls/reload`. This replaces `mailctl reload-tls` and `mailctl tls-key`. The provider's `cert` check confirms what it serves.
- **TLSA moves into core** (assistant's call). It depends only on `mail-cert`'s SPKIs, which are core's, and on the main zone's DNSSEC state, which core reads.
  - `dns-tool` renders `_25._tcp.<h>` from `mail_acme`'s current and next SPKI, only while `domains report --main` says `secure`.
  - The rollover state (`--next-key` → both published → wait 2×TTL + 1 day → `--switch-key` → drop) moves from `mailctl/internal/tlsa` into a small state file `mail_acme/tlsa.json`, driven by `mail rotate`.
  - The provider's `GET /v1/dns` no longer has a `tlsa` field. The provider's `cert` check still compares what it serves with the published TLSA, which the CLI tells the Hub and the Hub sends in MailState v2 (`tls: {spki: [...]}`).

### 6.5 Per-person credentials and the session reset

- **The provider holds the credentials; the Hub holds identity and metadata.** As today: the provider creates mail passwords on `POST /v1/credentials {username, uuid, label, expires_at}`, returns the secret once, revokes by `?uuid=` only, and answers `account_mismatch` / `mass_removal` as `error_kind`. The Hub keeps the rows (`state.yaml` `mail_credentials`), the fresh-auth proof, the 5-per-person cap and the self-service-only rule.
- **"With a router."** Mail passwords aren't `person_secret` options, so the router-less rule (§3 "HTTP routers") is untouched. The provider gets per-person credentials **through the API only**, and a mail template may not declare `person_secret` at all (§4). The Hub's well-known router (§6.8) is the only router.
- **`GET /v1/credentials` keys on `?uuid=`** (rename from `?user=`, assistant's call: credentials by uuid everywhere).
- **Session reset.** After every removal and every revoked password the Hub restarts `mail.sessions.restart` through its normal instance path (a restart of one service of the provider's own project). It replaces `RestartCoreService("mail")` and the §6 exception for a core container, so the Hub no longer restarts any core container. The 8 s budget and the shared restart (`mail_restart.go` `sharedRestart`) are unchanged.

### 6.6 The egress network

- **Not a slot power.** Every template's own `default` network already reaches the internet. `mail-egress` and `portcullis-mail` become the template's own networks: `stalwart` declares `internal: {internal: true}` (Stalwart, adapter, resolver, pinned) and `egress` (Stalwart and resolver). The adapter has no egress except to the public resolvers its checks need, which go through the resolver.
- **Rules.** No `enable_ipv6` (§4). The VPN reserved-range logic sees the template's networks as Docker networks, as for any app. Core's `network.sh` mail subnet checks shrink to `portcullis-mail-api`.
- **No outbound 25 in tests** is enforced by CI's runner firewall (DOCKER-USER / OUTPUT reject, the egress probe at TEST-NET-1 only). That is per runner, not per network, so it covers the template unchanged (§12).

### 6.7 The resolver

**It moves into the template** (assistant's call). It is part of how a given server validates DANE and queries DNSBLs (Spamhaus refuses public resolvers). Another provider may bring its own or need none. Core keeps no `mail-resolver`. The `dane` check and doctor `mail_dane_off` stay neutral concepts: whether outbound DANE verification is on.

### 6.8 The well-known router

- The Hub's override puts these labels on `mail.wellknown.service` of the wired instance: `traefik.http.routers.portcullis-mail-wellknown` (rule `Host(mta-sts.<e>) || Host(autoconfig.<e>) || Host(autodiscover.<e>)` for every mail domain), `entrypoints: ${PORTCULLIS_EP_CORE}` (it follows VPN-only mode with no public exception, the user ruling of 2026-11-15) and `middlewares: rate-limit@file,security-headers@file`. Its service is `portcullis-mail-wellknown`, on `mail.wellknown.port`.
- The `portcullis-` prefix is the Hub's (§3.1), so no template can define it.
- The provider gets `PORTCULLIS_MAIL_WELLKNOWN_ENTRYPOINTS` in its env from the override (today `MAILCTL_WELLKNOWN_ENTRYPOINTS`). While `websecure` isn't in it, MTA-STS is `off` (§19.7, unchanged).
- The core router `mail-wellknown` and service `mailctl-wellknown` are removed from `docker-compose.yml`.

### 6.9 Identity and account feeds

They are unchanged in substance. The provider never reads LLDAP or Keycloak. The Hub sends MailState (v2, §7) with accounts keyed by LLDAP uuid, aliases, lists, postmasters, quotas, limits, spam settings and Local networks. Reserved addresses, the parking-domain semantics (former accounts, no bounce, `550 5.1.1`, retention) and "removals at once, additions debounced 60 s" become **obligations of every provider** in the neutral contract. The parking domain name `portcullis-former.internal` stays contract-fixed.

### 6.10 Backups, restore and the void

- **Backups.**
  - The provider's data lives in its instance volumes, so it is backed up by a **Hub instance backup** (§11.5). That backup stops the instance during the copy, as RocksDB requires and as core does today.
  - `./portcullis backup` calls `POST /host/mail/backup` (`hub mail backup`): an instance backup of the wired provider with the new reason `core`. It waits for it, records the archive name in the core backup's manifest, then archives `hub_data`, which contains it.
  - `mail_acme` and `mail_tls` stay in core's online file volumes.
  - This keeps today's guarantee that one `./portcullis backup` holds the mail store.
- **Restores.** Each path voids every mail password before any mail port listens (M7):
  - **Instance restore of the provider** (same instance, from the Hub): after the volumes are replaced and before the instance is enabled, a void is owed.
  - **Core restore** (`./portcullis restore`): `hub_secrets` is emptied as today, which removes the gate sentinel and the API secret. The Hub's secrets-epoch mismatch marks a mail void owed. When the provider's volumes are missing (a fresh host), core asks the Hub to restore the provider instance from the archive the manifest names (`POST /host/mail/restore {archive}`), which owes a void too.
  - **Wiring** owes a void (§5.1).
- **The void, while one is owed** (`state.yaml` `mail.void_owed`, saved before anything else):
  1. The Hub never renders the normal override. It renders **void mode**: no published ports, no well-known router, the template's networks forced `internal: true`, only the API attachment.
  2. It starts the instance and calls `POST /v1/void {"reason": "restore"|"wire"}`. The provider destroys every credential of every account and records `restored_at`.
  3. **The Hub then verifies:** it lists every account's credentials, and any credential created before the void starts is revoked again. If one still exists, or the void fails, the instance is stopped and the doctor reports `mail_void_pending` (Problem). The Hub retries every 5 min and on the Mail tab's *Retry*.
  4. Only on success does it write the gate sentinel and clear `void_owed`.
- **The container gate.** Its files are on `hub_secrets` `<instance>/_mail/`, mounted read-only into the `gated` services:
  - `.present` (reads `portcullis-mail-gate`);
  - `void-pending` (exists while a void is owed);
  - `void-session` (a random nonce, only while the Hub runs void mode; the override passes the same nonce as `PORTCULLIS_MAIL_VOID_SESSION`).

  The contract obliges every gated service to refuse to start unless `.present` is right, and, while `void-pending` exists, unless the env nonce equals `void-session`. That covers a raw `docker compose up` of the provider project after a core restore: the volume was emptied, so the sentinel is missing and the start fails closed. For `stalwart`, the existing one-line entrypoint wrapper moves into the template unchanged, apart from its paths.
- **The adapter's own recovery** (Stalwart bootstrap, `STALWART_RECOVERY_MODE`) is template-internal (§6.13). It isn't the void.

### 6.11 Monitoring and alerts

- **Two scrape targets, both fixed.** `mail-provider-metrics:<metrics.port>` (the contract metrics, Basic auth) and, optionally, `mail-provider-server-metrics:<port><path>` (the server's own).
  - The override attaches the declared services to `portcullis-metrics-mail` with those aliases.
  - The Hub writes `mail_slot/mail-targets.json` (file_sd) and `mail_slot/metrics-secret` (0640, gid 65534, Prometheus).
  - Prometheus mounts `mail_slot` read-only. The Hub gets the same secret to the provider through the `_mail/` mount.
  - `mail-targets.json` is `[]` whenever nothing is wired, so the generic `up == 0` alert never fires for an empty slot. That is why the Hub writes it and core doesn't (assistant's call, the `vpn_doc` pattern).
- **Contract metric names:** `portcullis_mail_check{check}`, `portcullis_mail_dkim_stage{domain,stage}`, `portcullis_mail_queue_messages`, `portcullis_mail_queue_deferred_ratio`. `portcullis_mail_cert_expiry_seconds` moves to core: `mail rotate` writes it through the textfile exporter.
- The alerts in `monitoring/prometheus/alerts.yml` keep their names and expressions.

### 6.12 Export, test, status (CLI paths)

- `./portcullis mail export <former-id>` asks the Hub for the wired instance (`GET /host/mail/provider`), then runs `mail.export.argv` as an exec in that service and writes stdout to `backups/mail-export/` (0600).
  - **Message content never passes through the Hub** (the shipped rule).
  - Without `export` in the block the command says the provider has none.
- `mail test --to` → `POST /host/mail/test` → provider `POST /v1/actions/test {"to"}`.
- `mail status` → `GET /host/mail/status` (the Hub's view: provider, document generation, checks, void state) plus core's own rows (certificate, timer, TLSA).
- The CLI no longer execs into any mail container except for export.

### 6.13 Inside the `stalwart` template (provider-specific, for the appendix)

- **Images.** Stalwart, pinned as today. The adapter: mailctl as a published image, `ghcr.io/porelli/portcullis-mailctl` (`:edge` from main, `:X.Y.Z` per release, cosign-signed, pinned by digest in the template; the `forwarder.yml` pattern). Unbound, pinned.
- **Bootstrap.** A one-off job `bootstrap`, ordered with `service_completed_successfully` before `stalwart` and `adapter`:
  - it starts Stalwart in recovery mode on the internal network only, with a random recovery password made inside the job;
  - it applies the base plan (§19.4's list, unchanged) through mailctl's bootstrap code;
  - it writes the API key into the adapter's volume (0600);
  - before it exits 0, it checks that the recovery login is refused.

  A recovery-mode start outside the job is refused by the wrapper (the job-scoped session file replaces the host boot id). This needs a short spike: two processes on one RocksDB store must never overlap, and compose's job ordering guarantees that only for `up`.
- **Updates.** `STALWART_UPDATE_ROLE_PERMISSIONS` after an image change: the adapter keeps the last digest in its state and runs the one recreate itself.
- **Spam rules.** The import, the external-lookup suppression and the vendored rules stay in the adapter. Their checks become provider checks `x-spam_rules` and `x-external_lookups` (§9).
- **Settings.** The DQS key is a `secret` template setting.

## 7. Contract changes

§19 becomes **"19. Mail provider API"**, neutral. Every Stalwart-specific statement moves to **the `stalwart` template's documentation page** (`portcullis-templates/docs/stalwart.md`, rendered on the docs site under Apps). That page is normative for that template only.

**What §19 keeps (neutral):** the slot (§19.1), the ports (§19.2), the certificate and TLSA (§19.3), the API (§19.5), people and credentials (§19.6), the per-domain sets with the validation table and the DKIM / MTA-STS / DMARC obligations (§19.7), the check catalog and report trust (§19.8), the Hub API (§19.9), the host routes and CLI (§19.10), backups and the void (§19.11) and Kubernetes (§19.12). A new **§3.5 "The `mail:` block"** joins §3.3 (`vpn:`).

**Renames and removals:**

| Before | After |
|---|---|
| §19 "Mail" | §19 "Mail provider API" + the `stalwart` app page |
| "mailctl" as the Hub's peer | "the provider" / "the provider API" |
| `HUB_MAILCTL_API_URL` (`http://mailctl:8080`) | `HUB_MAIL_API_URL` (`http://mail-api:<api.port>`, from the block) |
| `HUB_MAILCTL_SECRET_FILE`, `secrets/mail/hub-secret` | removed (Hub-generated, `hub_secrets/<instance>/_mail/api-secret`) |
| network `portcullis-mailctl`, `PORTCULLIS_MAILCTL_SUBNET` / `_IP_RANGE` / `_HUB_IP` / `_API_IP` | `portcullis-mail-api`, `PORTCULLIS_MAIL_API_SUBNET` / `_IP_RANGE` / `_HUB_IP` / `_PROVIDER_IP` |
| networks `portcullis-mail`, `mail-egress`; `PORTCULLIS_MAIL_SUBNET` / `_IP` / `_IP_RANGE`, `PORTCULLIS_MAILCTL_MAIL_IP`, `PORTCULLIS_MAIL_RESOLVER_IP`, `PORTCULLIS_MAILCTL_PROXY_IP` | removed from core (template-internal) |
| core services `mail`, `mailctl`, `mail-resolver`; volumes `mail_data`, `mail_etc`, `mailctl_data`; aliases `mail-metrics`, `mailctl-metrics`; router `mail-wellknown`, service `mailctl-wellknown` | removed from core and from the reserved names (`coreref.go`, `validate.py`); new reserved names: volume `mail_slot`, network `portcullis-mail-api`, aliases `mail-api`, `mail-provider-metrics`, `mail-provider-server-metrics` |
| compose profile `mail`; `docker-compose.mail-recovery.yml` | removed; `PORTCULLIS_MAIL=on` means "slot open" |
| `MAILCTL_CLIENT_IP` | `core.env` `PORTCULLIS_MAIL_CLIENT_IP` → MailState v2 `client_ip` |
| `MAIL_RELAY_*`, `MAIL_DKIM_ROTATE`, `MAIL_FORMER_RETENTION` (`.env`) | Settings → Mail → MailState v2 `relay`, `dkim_rotate`, `former_retention`; relay password delivered as a file |
| `MAIL_SPAMHAUS_DQS_KEY` | a `stalwart` template setting |
| MailState v1 | **MailState v2**: adds `mail_hostname`, `client_ip`, `submission_lan_only`, `dkim_rotate`, `former_retention`, `relay {host, port, username, spf_include}`, `tls {spki: [..]}`, per domain `dmarc_floor`. Vectors: Hub `internal/mailprovider/testdata/mailstate_v2.json`, adapter `…/state/testdata/mailstate_v2.json`, byte-compared in CI as today |
| Hub package `internal/mailctl` | `internal/mailprovider` (`MailAPI` stays the seam) |
| `GET /v1/credentials?user=` | `GET /v1/credentials?uuid=`; each row gains `allowed_ips` |
| `GET /v1/dns` `tlsa` field; TLSA and HELO SPF in the main set | removed (core's, §6.4) |
| MailStatus `stalwart_version`, `client_ip`, `timer_seen_at` | `provider: {name, version}`; the other two removed (the Hub and core know them) |
| — | new: `GET /v1/provider` (`{name, version, api_version, checks: [ids], actions: [names], export: bool}`), `POST /v1/void`, `POST /v1/tls/reload`, `POST /v1/actions/test` |
| §6 "Restarting core `mail`" | removed; the session reset is an instance service restart (§19.6) |
| §16 host routes `POST /host/mail/drain`, `GET /host/mail/domains` | kept; new `GET /host/mail/provider`, `GET /host/mail/status`, `GET /host/mail/dns/main`, `POST /host/mail/tls`, `POST /host/mail/test`, `POST /host/mail/backup`, `POST /host/mail/restore`, `POST /host/mail/install` |
| audit | new `mail.provider_wired`, `mail.provider_unwired`, `mail.provider_switched`, `mail_credential.void_provider` (count) |
| check ids | a fixed neutral catalog (§9); provider-specific ids start with `x-` |
| §19.4 bootstrap and recovery; §19.1 Stalwart service details; the `portcullis-mailctl` role; spam-rule import; JMAP specifics | the `stalwart` app page |

The change is breaking, which is allowed before a public release (memory: no back-compat until release). Version bumps: contract MINOR, MailState v2, policy and `vpn.json` unchanged.

**Merge order:** docs → Hub (wait for `edge`) → templates → core. Core and the Hub land together, because core removes the profile that the Hub no longer drives.

## 8. CLI and UX

- **CLI** (assistant's call: keep `mail enable` as the shortcut that opens the slot and installs the default provider; §15 Q2):
  - `mail enable [--hostname H] [--lan-only true|false] [--provider stalwart|none] [--yes]`; `mail disable [--yes] [--force]`;
  - `mail status [--json]`, `mail test --to`, `mail cert`, `mail rotate [--next-key]`, `mail schedule --systemd`, `mail export <former-id>`, all as in §6.12;
  - `mail dkim rotate <domain>` → `POST /host/mail/…` → the provider's `dkim-rotate` action;
  - **removed:** `--rotate-key` (the template's bootstrap concern), and every `mailctl` exec but export.
- **Settings → Mail:**
  - **Slot closed:** "Mail is off: run `./portcullis mail enable` on the host" (as today). Read-only on Kubernetes.
  - **Slot open, no provider:** a card "No mail server is wired", listing installed mail-provider instances with *Use as this server's mail* and a link to the Marketplace filtered on mail providers. Settings (domains, spam, limits, quotas, relay, DKIM rotation, former retention) stay editable. They are Hub state and are sent once a provider is wired.
  - **Wired:** today's page, plus a header row with the provider label and version, the instance link, *Switch…* and *Unwire…*, and the void state when one is owed.
- **Instance Mail tab** (templates with a `mail:` block, deep link `#apps/<id>/mail`): the wiring switch, the provider's `GET /v1/provider` answer, the void state with *Retry*, and why wiring is refused when it is.
- **People** pages are unchanged. A voided password says "the mail server changed" or "reset by a restore".
- **MCP:** `mail_status` stays (it adds the provider label). No tool wires, switches or unwires.

## 9. Doctor kinds

The doctor has 22 kinds today (`internal/doctor/mail.go`). After the change:

- **Neutral, unchanged in meaning (19).** Mapped from catalog check ids or computed by the Hub:
  - from provider checks: `mail_port25_blocked`, `mail_ptr_missing`, `mail_ptr_mismatch`, `mail_ipv6_ptr`, `mail_blocklisted`, `mail_dkim_stuck`, `mail_dkim_manual`, `mail_dmarc_failures`, `mail_dmarc_promote`, `mail_mtasts_enforce`, `mail_rate_held`, `mail_dane_off`;
  - Hub-judged: `mail_records_wrong` (now also the set-validation and MTA-STS-policy refusals), `mail_cert_expiring` (from the CLI-reported `not_after` plus the provider's `cert` check), `mail_timer_missing` (the timer's visits, recorded by the Hub through the host socket), `mail_client_ip_rewritten` (from `core.env`), `mail_lan_only_unenforced` (also the `allowed_ips` verification, §6.1), `mail_mass_removal_pending`, `mail_sync_blocked`.
- **Replaced:** `mail_hub_secret_invalid` → **`mail_provider_unreachable`** (Problem: wired, but the API can't be reached or authenticated, or it reports `bootstrap: false` for more than 10 min).
- **Provider-specific, as one generic kind:** `mail_spam_rules_missing` and `mail_external_lookups_on` become **`mail_provider_check`**. It covers any `x-` check, with the provider's title, detail and steps shown as plain text (clipped, no links or HTML), severity at most Problem, and never a one-click fix. Stalwart's become `x-spam_rules` and `x-external_lookups`. Their texts move to the app page.
- **New:**
  - `mail_provider_missing` (Warning: the slot is open, nothing is wired);
  - `mail_void_pending` (Problem: a void is owed and failing; the provider is stopped);
  - `mail_provider_refused` (Problem: the wired template no longer validates, its `api_version` is unknown, or its `mail:` block changed since wiring, §10.2; the provider is kept in void mode until an admin re-confirms the wiring).

That makes 24 kinds. The fixes `mail_dmarc_promote`, `mail_mtasts_enforce`, `mail_confirm_removal` and `dns_apply sets=mail` are unchanged.

## 10. Security invariants and containment

### 10.1 Invariants that survive unchanged

Each invariant comes from `progress.md` and contract §19. The middle column says where it is enforced after the move: **H** = Hub, **C** = core, **P** = provider obligation (contract MUST, tested by the conformance suite, §12).

| # | Invariant (ruling) | Enforced by | Notes |
|---|---|---|---|
| 1 | Fail closed: `PORTCULLIS_MAIL` is on only on exactly `on`; mail routes `503` while the provider is unreachable or `bootstrap: false` | H | `mail_core.go` logic, re-keyed on the wired provider |
| 2 | Secrets in place, never `mv` over a bound file; never on argv, in logs or in audit | C, H | the API secret and gate files written in place on `hub_secrets`; core's remaining single-file binds keep the sweep |
| 3 | Restore void before any mail port listens (M7); marker first; every start path voids; the start primitive and the container both gate | H (void mode, verify), P (gate wrapper), C (core restore → epoch → void owed) | §6.10; the Hub's verification makes it independent of the provider's honesty |
| 4 | No outbound 25 in tests; egress probe at TEST-NET-1 only | CI | §12 |
| 5 | Report trust: count only aligned-DKIM reports, reporters by eTLD+1, never weaken; display-only in v1.1.0 | P; H for DMARC (`dmarc_floor`) | the Hub refuses a set that lowers DMARC; MTA-STS downgrades only on two definite local certificate failures (P) |
| 6 | Credentials by uuid: create carries uuid → `account_mismatch`; revoke only `?uuid=`; one snapshot plus one live read; rows end only on the provider's word; a re-created username never inherits | H, P | list by `?uuid=` too (§6.5) |
| 7 | Mass-removal guard: > 50 % removal refused without confirmation; only full admins confirm; pending → passwords revoked and sessions reset; `error_kind`, never text | **H first**, P second | new: the Hub refuses to send such a document itself (against `mail-last.json`), so a provider without the guard can't be told to drop everyone; the provider's `409` stays as the second layer |
| 8 | Revocation effective within 8 s; sessions ended by a restart | H | `sessions.restart` is required, so the Hub restarts whatever the provider claims |
| 9 | LAN-only (CLI-only, two layers, refused on Podman) | C (setting, refusal), P (both layers), H (verifies `allowed_ips`) | §6.1 |
| 10 | Never an open relay; AUTH never on 25; From must be your own address | P | conformance suite; the core CI open-relay test stays |
| 11 | A mail password opens only IMAPS and submission; never sign-in or management | P | conformance: password on the API listener refused |
| 12 | No mail password in clear at rest; secret once, `no-store` | H, P | unchanged |
| 13 | The certificate is dedicated (SAN `MAIL_HOSTNAME`), never the wildcard key; no DNS credentials in the mail server | C | `mail-cert` stays core; the mount check (§6.4) |
| 14 | MTA-STS follows VPN-only mode (user ruling) | H | the Hub renders the router and the entrypoints env (§6.8) |
| 15 | IPv6 mail refused | C (`MAIL_IPV6`), template rule (no `enable_ipv6`), H (no `[::]` publish) | |
| 16 | Parking domain, never bounce, retention; reserved local parts; addresses unique Hub-wide | H (uniqueness), P (parking) | |
| 17 | Message content never through the Hub; export CLI-only | C | exec into the provider, stdout to file (§6.12) |
| 18 | No surprise egress from the spam filter (external lookups off, re-checked) | P (`stalwart`) | provider check `x-external_lookups` |
| 19 | `MAIL_HOSTNAME` reserved; the mail labels reserved on mail domains; a mail domain can't be deleted while `on` or `draining` | H | unchanged |

### 10.2 Containing a malicious or buggy provider

**Any** installed template with a `mail:` block may be wired (user ruling, §15 Q1), whatever its source. So containment never relies on who wrote the template. A hostile template that an admin wires gains exactly what the slot allows and nothing more:

1. **Allowlist, not blocklist.** The `mail:` block can request exactly the items in §4, and the override renders exactly those. The template's compose gets the VPN-gateway hardening on every service (§4). The provider never gets: engine access, `hub_data`, LLDAP / Keycloak / DNS credentials, the wildcard key, other instances' networks, or a core network other than `portcullis-mail-api` (one service) and `portcullis-metrics-mail` (one or two services).
2. **Wiring is a deliberate, guarded act** (§5.1 step 3): a full administrator with a fresh sign-in, the instance id typed, the powers spelled out in the UI and the API, never from MCP or AI, audited with the template's source, commit and block hash. Installing a template never wires it.
3. **Template updates hold.** The Hub stores the wired template's commit and a hash of its `mail:` block and images. A source sync that changes either keeps the instance on its current containers: no re-`up`, doctor `mail_provider_refused` "the mail provider's template changed: review and confirm on its Mail tab". The confirmation is a **re-wire** with every guard of item 2, and it includes a void. An ordinary sync of unrelated templates is unaffected.
4. **The Hub enforces every invariant itself, never trusting the provider.** The provider's own checks are only a second layer:
   - the DNS allowlist and the DMARC floor (§6.3) in the Hub and in the domains service;
   - credentials by uuid, with `uuid` echoed and compared, and rows that end only on a confirmed answer (§6.5);
   - the mass-removal guard, checked by the Hub before it sends a document (§10.1, row 7);
   - LAN-only, verified through `allowed_ips` (§6.1);
   - the void after every wiring and restore, verified by listing credentials (§6.10);
   - the session reset after every revoke (§6.5);
   - the certificate and `hub_secrets` mount checks (§6.2, §6.4);
   - strict decoding of every answer: unknown keys refused, sizes capped, ids shaped.
5. **Damage bound.** A provider that turns hostile can read and send the mail of the people in `mail_users`. That is inherent to running a mail server, and it is why the warning says so and wiring needs a fresh, typed admin confirmation. It can't affect sign-in, other apps, DNS outside the validated mail names, or the certificate of any other host.

## 11. Migration (test server, by hand)

There is no migration code (memory: no back-compat until release). The test server runs core main 9408f97 with mail on as a core profile:

- document generation 1;
- staging certificate;
- DKIM pending;
- `dns setup` failed at Porkbun MX create (progress.md line 149), so **no mail records were published**;
- the Lightsail firewall is still closed on 25/465/587/993 (user ruling 2026-11-16).

There is no real mail to keep.

1. **Before the upgrade:** `./portcullis mail status --json > ~/mail-before.json` (for the record), then `./portcullis mail disable --force --yes`. Nothing was published, so nothing is withdrawn. Stop the timer: `sudo systemctl disable --now portcullis-mail.timer`.
2. **Upgrade core and the Hub** to the merged versions (`./portcullis upgrade`, `ACME_STAGING=true` as always on the test server). `up --remove-orphans` drops the old `mail`, `mailctl` and `mail-resolver` containers.
3. **Remove the old data by hand:**
   - delete the volumes `portcullis_mail_data`, `portcullis_mail_etc` and `portcullis_mailctl_data`, and the networks `portcullis-mail`, `portcullis-mailctl` and `mail-egress`;
   - in `secrets/mail/`, delete `api-key`, `hub-secret`, `dqs-key`, `relay-password`, `mailctl-metrics-secret`, `recovery.env`, `update.env`, `.stalwart-image` and `gate/`;
   - delete `secrets/monitoring/prometheus/mail-targets.json` and the `mail*-metrics-secret` copies;
   - **keep** `mail_tls`, `mail_acme` (same ACME account, so the CAA pin stays valid), `secrets/mail/hostname` and `former-hostnames`.
4. **Hub state by hand** (Hub stopped):
   - delete `hub_data/mail-last.json`;
   - in `state.yaml`, clear `mail.pending_removal` and `mail_credentials` (expected empty), and keep the mail settings (domains, quotas, spam).
5. **`./portcullis mail enable --yes`.** It opens the slot, installs and wires `stalwart`, and voids. Check `./portcullis mail status` (provider `stalwart`, document generation 1, certificate valid (staging), DKIM pending).
6. **DNS:** `./portcullis dns setup --yes` once the Porkbun fix (branch `mailfix`) is in. Then `./portcullis mail schedule --systemd` and install the units with sudo. Keep the Lightsail firewall closed until the user opens it.
7. **Clean the worktrees:** fold `wt-mailfix` (Porkbun) into main before this work starts, and remove `wt-mail1`, `wt-mail1-dns` and `wt-mailfix` (memory: branches mainlined at goal end).

## 12. Testing: keeping every mail check

The principle: **every assertion that runs today keeps running, against the `stalwart` template**. New assertions cover the slot's gates.

- **Template source in core CI.** `e2e-mail`, `build-and-test` and `e2e-podman` clone `portcullis-templates` at the same-named branch, else `main` (the `e2e-vpn` step, `ci.yml` ~line 5241). They fail closed when `stalwart/manifest.yaml` has no `mail:` block, and install it through the Hub's API (`hub mail install` via `mail enable`).
- **`unit-tests` (core):**
  - `unit-tests-mail-wiring.sh` becomes the slot wiring check: `portcullis-mail-api`, `portcullis-metrics-mail`, `mail_slot`, `mail-cert`, gid 2000, and the absence of the old services;
  - the TLSA rollover tests move into core with the code;
  - the adapter's unit tests and the MailState vector byte comparison run wherever the adapter lives (§15 Q3);
  - `mail-gate-entrypoint.sh` moves to the templates repo's tests for `stalwart`.
- **`build-and-test`, "Test the mail service":** the same assertions on the template's containers:
  - bootstrap;
  - recovery login refused afterwards;
  - isolation (`/jmap` from another address on the template's internal network → `404`);
  - certificate SANs and SPKI;
  - open-relay refusal;
  - `mail status`;
  - the timer.

  The backup and restore steps assert that `./portcullis backup` holds the provider's instance archive, that `restore` voids (the Hub's verification included) and that `hub_secrets` emptied → the gate refuses a raw `compose up`.
- **`e2e-mail`:** all nine scenarios (exchange, alias, spam / GTUBE in the Subject, mail passwords, lists, postmaster, revocation within 8 s, leave, re-created username) plus restore and the DMARC report, unchanged, through the wired `stalwart`. New scenarios:
  - **switch:** to a second provider (the CI-only `mail-fake` template below): DNS sets replaced, the old DKIM retained for 7 days, passwords voided with `provider_changed`, ports moved, the old instance stopped with its data;
  - **containment:** `mail-fake` in hostile mode serves a set with an A record, a foreign MX, an SPF `include:` the admin didn't set, a lower DMARC and a CAA (each refused; `mail_records_wrong`); omits the mass-removal `409` (the Hub's own guard refuses); returns `allowed_ips` wider than Local networks under LAN-only (revoked; `mail_lan_only_unenforced`); fails the void (the instance stays stopped; `mail_void_pending`);
  - **wiring guards:** a wire without a fresh sign-in, with the wrong typed id, or with an AI/MCP token is refused; a template change holds the provider until a confirmed re-wire; a template from a non-default CI source can be wired with the guards.
- **`mail-fake`.** A minimal provider for CI only, in core `tests/e2e/mail-fake/` and loaded as a CI-only template source. It is a Go binary that implements the API over an in-memory store, with no SMTP. It also proves goal 1: a second provider works with no core or Hub change.
- **The conformance suite.** `tests/mail-conformance/` in core: API-level and protocol-level checks of the MUSTs in §10.1 (P rows). `e2e-mail` runs it against `stalwart`, and any future provider template must pass it in its own CI.
- **`e2e-podman`:** "Mail on rootless Podman" installs `stalwart`, checks the port-start refusal, `client_ip: rewritten` in MailState v2, the doctor, local delivery and no ban events (unchanged), and the gate wrapper on Podman.
- **Hub CI:**
  - `ValidateMail` against `mail_vectors.json`;
  - override rendering (ports, mounts, attachments, router, void mode);
  - the `mail_tls` and `hub_secrets` mount checks;
  - DNS set validation vectors;
  - the Hub-side mass-removal precheck;
  - void verification;
  - switch and unwire state machines;
  - the wiring guards (fresh sign-in, typed id, the warning text, the AI/MCP refusal, the audit record);
  - the template-change hold.
- **Templates CI:** `validate.py` against the vectors; `stalwart` compose-config and lint; the gate-wrapper test.
- **No outbound 25.** The runner firewall rules and the TEST-NET-1 egress probe stay in every mail job. The probe now runs from the provider's egress network. The remote test server (`remote.test`) stays on internal networks only.

## 13. Work breakdown and effort

| Repo | Work | Estimate (agent-days) |
|---|---|---|
| **docs** | §19 rewritten neutral; §3.5 `mail:`; §2, §3, §5, §6, §11.7, §12.2, §13.16, §14.5–14.6, §15.10, §16 updates; setup/operations mail pages; the `stalwart` app page (moved text); resync the Hub's copies | 1.5 |
| **Hub** | `internal/mailctl` → `internal/mailprovider` (v2 types, `?uuid=`, new endpoints); `templates.ValidateMail` + vectors; wiring, switch and unwire op + state; override rendering (ports, `portcullis-mail-api` attachment, metrics aliases, `mail_tls` and `_mail/` mounts, gid 2000, well-known router, void mode) and the mount checks; API secret and gate files; void-and-verify; Hub-side mass-removal precheck; DNS set validator + `dmarc_floor` + the DKIM retention on switch; MTA-STS policy fetch; `allowed_ips` check; wiring guards (fresh-auth proof, typed id, warning, AI/MCP refusal, audit) + template-change hold; `mail_slot` targets and metrics secret; session reset on the instance; host routes (`provider`, `status`, `dns/main`, `tls`, `test`, `backup`, `restore`, `install`); doctor (24 kinds); UI (Settings → Mail states, instance Mail tab, Marketplace badge); remove `RestartCoreService` | 5–6 |
| **templates** | schema + `validate.py` for `mail:` + vectors; the `stalwart` template (Stalwart, adapter, resolver, `bootstrap` job, internal and egress networks, gate wrapper, settings incl. DQS); its docs page; gate-wrapper test | 2–3 |
| **core** | remove the `mail` profile, the services, `docker-compose.mail-recovery.yml` and the Podman / SELinux entries; slot infrastructure (networks, `mail_slot`, gid 2000, `network.sh`); `mail.sh` rewritten on the host socket (enable/disable/status/test/dkim/export, `--provider`); TLSA and HELO SPF into `dns-tool` + `mail_acme/tlsa.json` rollover; `domains` set-validation rules + vectors; backup / restore through the Hub; Prometheus `mail_slot` file_sd and the textfile cert metric; the adapter image workflow (`forwarder.yml` pattern) and moving mailctl's provider wiring (env, secret path, void and TLS endpoints, no control socket but export); kube parity list | 4–5 |
| **e2e / CI** | template checkout in three jobs; rework of the mail scripts; `mail-fake` + the switch, containment and wiring-guard scenarios; `tests/mail-conformance/` | 3 |
| **test server** | §11 by hand, then a live check | 0.5 |

**Total: about 16–19 agent-days.** With the usual streams (docs first; then Hub ‖ templates ‖ core; then e2e and fix rounds), that is **about 5–7 elapsed days**, a bit less than mail1, because there's no Stalwart spike. The one new spike is the `bootstrap` job ordering (§6.13, half a day, first).

Plan order:
1. Merge `mailfix` (Porkbun) first.
2. Docs contract.
3. Spike.
4. Hub ‖ templates ‖ core.
5. e2e.
6. Final reviews.
7. Merge docs → Hub → templates → core.
8. Test server.

## 14. Parked follow-ups

- Mailbox migration between providers (IMAP-to-IMAP copy as a Hub-orchestrated job, or JMAP import).
- Including other apps in core backups (generalise `POST /host/mail/backup` into a per-instance "in core backups" flag).
- A second real provider template (Maddy or Mox) as the proof beyond `mail-fake`.
- Removing `MAIL_HOSTNAME`'s A record and CAA on `mail disable` (L6, unchanged).
- Webmail as an ordinary app on the provider's IMAP.
- Push instead of polling for the DNS hash (`/v1/status` every 60 s today).

## 15. Decisions (formerly open questions; decided 2026-11-16)

1. **Which templates may be a mail provider?** **User ruling:** any installed template with a `mail:` block, from any source. There is no trusted-source restriction and no `MAIL_PROVIDER_SOURCES`. Containment doesn't rely on the source (§10.2):
   - wiring and every re-wire need a full administrator with a fresh sign-in, the instance id typed, and the explicit warning in the UI and API;
   - they are refused from MCP/AI and audited (§5.1);
   - the Hub enforces every invariant itself;
   - the template-update hold and the VPN-gateway hardening stay.
2. **Does `./portcullis mail enable` still install the default provider?** **Assistant's call (accepted):** yes. `mail enable` opens the slot and installs and wires `stalwart` (the host operator confirms the wiring, §5.1); `--provider none` opens the slot only.
3. **Where does the Stalwart adapter (mailctl) source live?** **Assistant's call (accepted):** in the core repo (`mailctl/`), published as the pinned image `ghcr.io/porelli/portcullis-mailctl` (cosign-signed, `:edge` and `:X.Y.Z`, the forwarder pattern). Core's runtime knows nothing about Stalwart.
4. **A source rule for VPN providers.** Moot (dropped), since there is no source rule for mail either.
