# Mail server (send, receive, filter, fully authoritative) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Working mail for the main domain and every enrolled domain an admin turns it on for. The goal covers:
- sending and receiving, with a built-in spam filter;
- SPF, DKIM (Ed25519 + RSA-2048, rotated) and DMARC that pass and align, with DMARC and TLS-RPT reporting;
- MTA-STS, and DANE whenever the main zone's DNSSEC is `secure`;
- PTR / forward-confirmed rDNS checks with provider guidance;
- every mail record owned by the DNS plan, with drift in the doctor and `status`;
- LLDAP people as mailboxes, aliases and group lists;
- per-device mail passwords created after a fresh passkey touch.

**Architecture:**
- Core gets the compose profile **`mail`** with three services:
  - **`mail`**: Stalwart, pinned upstream image, unmodified;
  - **`mailctl`**: new, Go, `mailctl/`, the only holder of Stalwart's API key;
  - **`mail-resolver`**: Unbound, a validating recursive resolver for `mail` and `mailctl` only.
- mailctl turns the Hub's desired-state document into Stalwart objects over Stalwart's JMAP management API (`urn:stalwart:jmap`, `x:<Object>/get|set|query`).
- mailctl renders the `mail` record set and runs the DKIM / MTA-STS / TLSA / DMARC state machines. It serves `mta-sts.txt`, autoconfig and autodiscover behind Traefik, runs the deliverability checks and exposes metrics.
- The domains service gains the `mail` record set (enrolled domains: `PUT /domains/{name}/sets/mail`; main domain: `dns-tool`) and a one-shot `domains mail-cert` that issues `mail.<d>` with its own ACME account and a reused key.
- The Hub computes the desired state from `mail_users`, domain grants, aliases, lists and quotas. It owns Settings → Mail, the person and group Mail sections, Sign-in → Mail passwords, 14 doctor kinds and the read-only `mail_status` MCP tool.
- Templates only mirror the new reserved core names. Docs get the contract section and two new pages.

**Tech Stack:**
- **Core:**
  - `docker.io/stalwartlabs/stalwart:v1.1.0` and `docker.io/klutchell/unbound:v1.26.2` (pins in Global Constraints);
  - Go 1.27 for `mailctl` (`github.com/miekg/dns`, `github.com/emersion/go-msgauth` for the DKIM selftest, `github.com/emersion/go-imap/v2` for `mail export`, `github.com/prometheus/client_golang`) and for `domains` (lego v4 `certificate.ObtainRequest.PrivateKey`, libdns);
  - bash 3.2 + jq for the CLI;
  - Python 3 stdlib for e2e (`smtplib`, `imaplib`, `email`) and Playwright for the fresh-auth popup.
- **Hub:** Go + vanilla JS. **Templates:** Python 3. **Docs:** Zensical.

**Spec:** `/Volumes/workspace/portcullis/portcullis-hub/docs/superpowers/specs/2026-11-13-mail-server-design.md` (binding). §12 open questions take their defaults, as amended by the spec defects below:
- Q1: no OAuth for mail clients in v1.
- Q2: RocksDB has no online backup, so `backup` stops `mail` alone for the copy.
- Q3: no antivirus.
- Q4: `mem_limit 1g`, caches cut in the base plan.
- Q5: a separate `mail-cert` tool and ACME account.

Related plans:
- DNS hardening `2026-11-13-dns-hardening.md`: the DNS plan, sets, fail-safe flips, Porkbun quirks.
- Rootless Podman `2026-11-13-rootless-podman.md`: the runtime model, the SELinux overlay, the lints, the test server SSH line.
- VPN-only access `2026-11-13-vpn-only-access.md`: the `wg` service shape copied here.
- Kubernetes `2026-11-14-kubernetes.md`: the coexistence rules in Global Constraints.
- Multi-server `2026-11-14-multi-server.md`: not depended on; its reserved ids are avoided.

## Global Constraints

- **Base and branches.**
  - Branch `mail1` in core, Hub, templates and docs, at `/Volumes/workspace/portcullis/wt-mail1/{portcullis,portcullis-hub,portcullis-templates,portcullis-docs}`.
  - Create each with `git -C <main checkout> worktree add -b mail1 <path> origin/main` and record the base SHAs in the Task 1 commit message.
  - Main checkouts may hold others' work: never edit, stash or commit there.
- **Kubernetes coexistence (kube1 is in flight):**
  - Mail targets Docker and rootless Podman only. On `CONTAINER_RUNTIME=kubernetes`:
    - `mail enable` refuses with exit 1 `mail isn't available on Kubernetes yet (Docker or rootless Podman only)`;
    - `up` / `upgrade` refuse a `COMPOSE_PROFILES` containing `mail` with the same text;
    - the Hub's Settings → Mail shows that text read-only.
  - If `kube1` is merged to core main before a core task of this plan starts:
    1. Merge `origin/main` into `mail1` first (a merge commit, never a rebase).
    2. Write the mail CLI with the `rt_*` verbs of the kube plan's Task 11 (`rt_exec`, `rt_run`, `rt_stop`, `rt_start`, `rt_up`), never new `dc` / `docker` call sites.
    3. Add the three mail services to `tests/k8s_parity_deltas.yaml`, each with the reason `mail profile: Docker/Podman only (mail plan)`, so `k8s_parity.py` stays green.
  - If kube1 merges later, kube's own merge converts the mail call sites (its Task 11 converts every `dc` call site). The mail controller tells the kube controller about the three new services and their deltas.
  - Mail adds 7 project binds (Task 5), so `NBINDS` 46 → **53**. Whichever branch merges second updates the count in its merge commit.
- **Contract first.**
  - Task 1 lands on docs `mail1` before any code task.
  - After Task 1 and Task 19, resync the Hub copies: run `PORTCULLIS_DOCS_DIR=/Volumes/workspace/portcullis/wt-mail1/portcullis-docs web/docs/sync.sh` in the Hub worktree, then commit `web/docs`.
  - The mail contract section is the **next free top-level section** at Task 1: §17 if multi-server's §17 "Servers" is not on docs main, else §18. This plan calls it **§M**.
- **Project rules:**
  - **Secrets never on argv, in logs or in the audit.** The secrets here are the recovery admin password, the Stalwart API key, the Hub ⇄ mailctl secret, mail passwords, DKIM private keys, the relay password, the DQS key and the metrics secret. They travel only through files, stdin and request bodies.
    - jq reads them through `env.X` / `--rawfile`, never `--arg`.
    - `tests/test_cli.sh`'s argv grep covers `scripts/lib/mail.sh`.
    - mailctl's logger runs every line through `redact()`, which blanks every known secret value and every `API_…` token.
    - Op records and audit details never carry a secret or a hash.
  - **Fail closed.** Each item in "Fail closed" below gets a test in its task.
  - **Never weaken access control.** Mail adds no route to any admin surface. A mail password is never a Portcullis sign-in credential. Every mail switch only narrows existing rights.
  - **Identity = the LLDAP username.** The mailbox login, the primary address and the account key are built from the username and the LLDAP uuid, never from the editable LLDAP `mail` attribute.
  - **No migration or back-compat code** before the first public release. Every version below is v1, and nothing reads another version.
  - **Prefer mature libraries** (Tech Stack). The one exception, a thin hand-written JMAP request envelope in mailctl, is recorded in M12.
  - **No private identifiers in public repos.** No hostnames, IPs, account ids or key paths of the test server in code, docs or commits. Refer to the rootless plan's Global Constraints for the SSH line.
  - **`.github/workflows/ci.yml` ≤ 450 000 bytes** (`tests/lint_ci_size.sh`; 315 249 bytes at core `166633c`). Every new step longer than 20 lines lives in `.github/ci/<job>-<step>.sh`.
  - **The test server always uses `ACME_STAGING=true`** (memory). The mail certificate follows `ACME_CA_SERVER` like the main one, so it is a staging certificate there.
  - **Never touch the LLDAP `admin` user.**
- **Fail closed (each gets a test in its task):**
  - mailctl refuses to start when any of these is true:
    - the API key file is missing or empty;
    - the Hub secret file is missing or empty;
    - `MAILCTL_API_SUBNET` doesn't parse;
    - its own address on `portcullis-mailctl` is outside it.
  - mailctl's Hub API answers only on its `portcullis-mailctl` address, with the bearer secret. Anything else gets 403 and nothing else.
  - A desired-state document fails strict decoding when it has an unknown key, a duplicate address, an address on a domain that isn't in `domains`, an unknown version or a trailing byte. Such a document is refused (400) and the last applied state stays.
  - mailctl refuses to remove more than 50 % of the accounts in one document unless `"confirm_mass_removal": true` is present. The Hub sets that flag only after an admin's explicit removal of `mail_users` members, never on a directory read error.
  - The Hub sends no desired state when the directory read fails. Nothing is removed because LLDAP is unreachable.
  - A Stalwart call that fails during a removal leaves the person removed in mailctl's state, and the removal is retried every 5 s. Their app passwords are destroyed first: no window keeps a password valid after the account is removed.
  - Revocation of a mail password, or a person leaving `mail_users`, must be refused by IMAP / SMTP within **8 s**. If a session survives the permission change, the Hub restarts `mail` (M3).
  - A DKIM key becomes `active` only when both public resolvers (1.1.1.1, 8.8.8.8) serve its exact TXT. A failed lookup keeps it `pending`.
  - A TLSA record is published only while the main zone's DNSSEC state is `secure`. Any other state, or a failed check, removes it on the next apply.
  - MTA-STS `enforce` is published only after 7 days of `testing` with no certificate-check failure and no TLS-RPT failure. Any failure goes back to `testing`.
  - The mail certificate is refused when its SANs aren't exactly `{MAIL_HOSTNAME}` or its key doesn't match the reused key. The old files stay.
  - Restores: every mail password is destroyed before any mail service listens (M7). If voiding fails, `mail` stays stopped and `restore` exits 1.
  - A recovery admin is left only while `secrets/mail/recovery.env` exists. `mail enable` fails unless a login with it is refused after removal (401).
  - The Hub refuses to create a mail password while mailctl is unreachable or reports `bootstrap: false` (503 "mail isn't running right now"). It never creates one while the person isn't in `mail_users` (404, the shared answer).
- **Runtime matrix (decided):**

  | | Docker (rootful) | Rootless Podman | Kubernetes |
  |---|---|---|---|
  | `mail` / `mailctl` / `mail-resolver` | as compose | as compose plus overlays: `restart: always` (`docker-compose.podman.yml`) and the long-syntax binds (`docker-compose.podman-selinux.yml`) | refused (above) |
  | Host ports 25/465/587/993 | published on IPv4 `0.0.0.0` always; IPv6 `[::]` only with `MAIL_IPV6=on` and the daemon's `ip6tables: true` (`docker info`); otherwise IPv6 isn't published (M9) | need `net.ipv4.ip_unprivileged_port_start ≤ 25`: a new host check when `mail` is in `COMPOSE_PROFILES` (`RT_PORT_START_MAX_MAIL=25`) refuses `mail enable`, `up` and `upgrade` | — |
  | Client source address | IPv4 preserved (DNAT) | rewritten by rootlessport → `MAILCTL_CLIENT_IP=rewritten` (M9 degraded mode, doctor Warning) | — |

- **TDD everywhere.** Write the failing test, see it fail, implement, see it pass, commit. Gates:
  - **Core:** `bash tests/test_shell_libs.sh && bash tests/test_cli.sh && shellcheck -S warning portcullis scripts/lib/*.sh tests/*.sh .github/ci/*.sh && actionlint && bash tests/lint_ci_size.sh && bash tests/lint_images.sh`, plus:
    - `cd mailctl && gofmt -l . && go vet ./... && go test -race ./...` (gofmt prints nothing);
    - `cd domains && go vet ./... && go vet -tags testprovider ./... && go test -race ./...`.
  - **Hub:** `go vet ./... && go test -race ./... && gofmt -l .` (gofmt prints nothing).
  - **Templates:** `python3 tests/validate.py && python3 tests/test_validate.py`.
  - **Docs:** `python3 scripts/check-lists.py && bash scripts/check-branding.sh && zensical build --strict --clean`.
- **CI.**
  - Core: `gh workflow run ci.yml --ref mail1 -f jobs=<names>`, then one full run. Only the controller dispatches core CI on `mail1` (the concurrency group cancels). Task 12 adds `e2e-mail` to the `workflow_dispatch` description list.
  - Hub: `gh workflow run build.yml --ref mail1`. Templates: lint.yml on `mail1`.
- **Merges (docs → Hub → templates → core).** No wire format changes in lockstep: the Hub tolerates a missing mailctl, and core main pulls Hub `edge`.
  - Merge each repo through a detached worktree: `git worktree add --detach /tmp/merge-<repo> origin/main` → `git merge --no-ff origin/mail1 -m "merge mail1: …"` → push → `git worktree remove`.
  - After the Hub merge, run `gh workflow run build.yml --ref main -f compare_ref=mail1` and wait for `edge` before merging core.
  - At the end, delete every `mail1` branch (local and remote), every worktree and `/tmp/merge-*` (memory: branches mainlined).
- **Test server (Task 20).**
  - Connect with the SSH command and install directory in `2026-11-13-rootless-podman.md` Global Constraints, then `git pull --ff-only && ./portcullis upgrade`. It runs Docker; `ACME_STAGING=true` stays.
  - **No outbound port 25, ever, in testing (user rule 2026-11-14).** Nothing in this plan — tests, CI, the deploy or the live check — opens a connection to port 25 of a host outside our own test networks, and nothing asks for the provider's port-25 unblock, a PTR change or external mailboxes. Outbound connections that look like spam probing are forbidden.
  - **Test-server inbound ports:** the controller asks the user to open inbound TCP 465, 587 and 993 (IPv4) in the Lightsail firewall only if the live check needs them; inbound 25 stays closed on the test server.
- **Values from the spec (verbatim):**
  - Profile **`mail`**; services `mail`, `mailctl`, `mail-resolver`.
  - Ports `25→10025` (STARTTLS), `465→10465` and `993→10993` (implicit TLS), `587→10587` (STARTTLS submission).
  - `ulimits.nofile 65536`, `mem_limit 1g`, `pids_limit 256`.
  - Volumes `mail_data:/var/lib/stalwart`, `mail_etc:/etc/stalwart` (`config.json`: the store only), `mail_tls` (read-only in `mail`), `mail_acme`.
  - The 8080 management listener is reachable only on `portcullis-mail`. HTTP access rules deny everything but `/api` (here: `/jmap` and `/api`, M12) from mailctl's pinned address.
  - mailctl: role `portcullis-mailctl`, read-only, no Docker access, no LLDAP / Keycloak / DNS credentials. Its permissions:
    - principals, domains, DKIM;
    - app passwords with `impersonate` + `sysAppPasswordCreate`;
    - queue read and reload actions;
    - no message read or export (M5 is the one scoped exception).
  - Networks `portcullis-mail` (internal, fixed IPAM: mail, mailctl, mail-resolver), `mail-egress`, `portcullis-mailctl` (internal, fixed subnet: Hub, mailctl), `portcullis-proxy` (mailctl pinned).
  - `MAIL_HOSTNAME` (default `mail.<main domain>`). Reserved labels `mail`, `mta-sts`, `autoconfig`, `autodiscover` on every mail-enabled domain.
  - Mail certificate: `domains mail-cert`, its own ACME account, the key reused across renewals, `fullchain.pem` / `privkey.pem` 0640 in `mail_tls`. A `caa` entry at `mail.<d>` pins the account. Renewal is below **30 days**.
  - `./portcullis mail schedule --systemd` installs `portcullis-mail.timer` (daily).
  - Bootstrap: `STALWART_RECOVERY_MODE=1`, a one-time `STALWART_RECOVERY_ADMIN` from a 0600 env file, then removed. `STALWART_UPDATE_ROLE_PERMISSIONS` is set for one start after a minor update.
  - Group **`mail_users`**. Primary address `<lldap username>@<primary mail domain>`; the Stalwart login is the primary address.
  - Additions are debounced **60 s**; removals are immediate. Direct LLDAP edits are caught on the evaluator's **60 s** tick. Mail to a removed address gets `550 5.1.1`.
  - Changed uuid: the old account becomes `former-<uuid>`. Former mailboxes are kept **30 days** (`MAIL_FORMER_RETENTION`). Export via `./portcullis mail export <former>` → mbox.
  - Reserved local parts `postmaster`, `abuse`, `dmarc-reports`, `tls-reports`, `mailer-daemon`. `postmaster` and `abuse` go to the members of `lldap_admin`.
  - Lists at `<group>@<domain>`, posting `members` (default) or `anyone`; outside senders on a `members` list are rejected at RCPT.
  - Quota default **10 GiB**, group-scoped.
  - Mail passwords: label, expiry none / 90 days / 1 year, fresh auth under the server's default sign-in template, **at most 5** per person. Admins see and revoke, never create.
  - Metadata `{id, label, created_at, expires_at}` in `state.yaml` `mail_credentials`. Audit `mail_credential.create|revoke|revoke_leave|void_restore`.
  - The account's own password is random, **64 bytes**, never disclosed.
  - DNS set `mail`, TTLs as the spec §7 table (3600; CAA 300). Selectors `v1-{ed25519,rsa}-YYYYMMDD`.
  - DMARC `adkim=s; aspf=s; rua=mailto:dmarc-reports@<e>`, no `ruf`. `p=reject` for domains with no prior MX/SPF, else `p=none` → doctor proposes `quarantine` → `reject` after **14 days** clean.
  - MTA-STS `mode: testing; max_age: 86400` → `enforce; max_age: 604800` after **7 days**. Turning mail off first publishes `mode: none` for a full `max_age`.
  - DKIM `pending → active → retiring (7 days) → retired` (record removed; key deleted 30 days later). Rotation every **180 days** (`MAIL_DKIM_ROTATE`).
  - TLSA `3 1 1`, next SPKI during rollover; wait 2×TTL + 1 day.
  - Checks every **6 h** and on demand.
    - Outbound 25: three providers' MX within **10 s**.
    - FCrDNS for each public address; IPv6 outbound only when the v6 PTR passes.
    - Spamhaus ZEN / SpamCop / Barracuda through `mail-resolver`.
  - Relay: `MAIL_RELAY_HOST`, `_PORT`, `_USERNAME`, `_PASSWORD`, `_SPF_INCLUDE`.
  - Spam: score ≥ **15** rejected at DATA `550 5.7.1`; ≥ **5** to Junk with `X-Spam-*`. Greylisting and the AI classifier off. Remote DMARC `reject` honoured. Limits **300 recipients/hour, 1000/day** per account.
  - Submission 465/587 require AUTH and refuse the MX role; 25 refuses AUTH.
  - Metrics `portcullis_mail_check{check}`, `portcullis_mail_dkim_stage{domain,stage}`, `portcullis_mail_cert_expiry_seconds`.
  - Alerts:
    - queue > 100 for 30 min;
    - deferrals > 20 % for 1 h;
    - certificate < 14 days;
    - a blocklist hit;
    - DKIM `pending` > 24 h;
    - a check failing.
  - CLI `./portcullis mail enable|disable|status|test|dkim rotate|cert|rotate|schedule --systemd|export`.
  - The 14 doctor kinds of spec §10 (Task 17).
- **Values this plan adds (assistant's calls, binding):**
  - **Pins:**
    - `docker.io/stalwartlabs/stalwart:v1.1.0@sha256:f772aa6ef8cd8018969fa491640f1436b0270eb14e2c219b5f37f1a77020837e` (index digest; the image runs as `stalwart` **2000:2000**, `setcap cap_net_bind_service=+ep` on the binary);
    - `docker.io/klutchell/unbound:v1.26.2@sha256:50cbeb32b5838a829a7226b19cb151f9535bd7f9f3190f950780f452fe807478`;
    - vendored spam rules `mailctl/internal/spamrules/spam-filter-rules.json.gz` = stalwartlabs/spam-filter **v3.0.4**, sha256 `604cc4386b1574e95185d37cb9c194ac20d360cca3865960b6ed0edf70475562`.
  - **Ids:**
    - `CT_UID_MAIL=2000` (Stalwart);
    - `CT_UID_MAILCTL=10010`. **Not 10006**, which is `wg`'s; 10007 is `vpn_doc` and 10008/10009 are reserved by the multi-server plan.
    - mailctl runs `10010:10010` with `group_add ["10001"]` (the Hub secret, as domains).
  - **Addresses:**
    - `portcullis-mail` = `${PORTCULLIS_MAIL_SUBNET:-172.31.255.0/28}`, range `${PORTCULLIS_MAIL_IP_RANGE:-172.31.255.8/29}`; mail `.2` (`PORTCULLIS_MAIL_IP`), mailctl `.3` (`PORTCULLIS_MAILCTL_IP`), mail-resolver `.4` (`PORTCULLIS_MAIL_RESOLVER_IP`).
    - `portcullis-mailctl` = `${PORTCULLIS_MAILCTL_SUBNET:-172.31.255.16/28}`, range `.24/29`, Hub `.18`, mailctl `.19`.
    - `portcullis-metrics-mail` (internal, unpinned): Prometheus, mail, mailctl.
    - mailctl on `portcullis-proxy` at `${PORTCULLIS_MAILCTL_PROXY_IP:-172.31.250.4}`.
    - mailctl also joins `mail-egress` (the public resolvers and the outbound-25 probe; spec §4 omits it).
    - `network.sh` validates them all (Task 5).
  - **Files:**
    - `secrets/mail/` 0700;
    - `api-key` 0640 group 10010 (mailctl);
    - `hub-secret` 0640 group 10001 (Hub, mailctl);
    - `metrics-secret` 0640 group 2000 (mail) plus a copy `prometheus-mail` 0640 group 65534 (Prometheus);
    - `relay-password` 0640 group 2000 (mail), written by `stack_prepare` from `.env` `MAIL_RELAY_PASSWORD` (empty file = no relay auth);
    - `dqs-key` 0640 group 10010 (mailctl; from `.env` `MAIL_SPAMHAUS_DQS_KEY`; empty = none);
    - `recovery.env` 0600 (exists only during a recovery session).
  - **Volumes:**
    - `mailctl_data:/data` (10010:10010 0700: `state.json` — state machines, the applied generation, check results), backed up;
    - `mail_tls` 10004:2000 2750 (files 0640);
    - `mail_acme` 10004:10004 0700.
  - **`.env` keys:**
    - `MAIL_HOSTNAME`;
    - `MAIL_IPV6=on|off` (default `off`);
    - `MAIL_SUBMISSION_LAN_ONLY=true|false` (default `false`);
    - `MAIL_DKIM_ROTATE` (default `4320h`);
    - `MAIL_FORMER_RETENTION` (default `720h`);
    - the `MAIL_RELAY_*` keys, `MAIL_SPAMHAUS_DQS_KEY`.

    `COMPOSE_PROFILES` gains `mail` through `mail enable`. The Hub's core.env gets `PORTCULLIS_MAIL` (`on` iff `mail` is in `COMPOSE_PROFILES` and `secrets/mail/api-key` is non-empty), `PORTCULLIS_MAIL_HOSTNAME`, `PORTCULLIS_MAIL_SUBMISSION_LAN_ONLY`, `PORTCULLIS_MAIL_RELAY` (`on|off`, never the host or credentials) and `PORTCULLIS_MAILCTL_IP` (`.19`).
  - **Stalwart internal listeners** (high ports in the container):
    - `smtp` `[::]:10025`;
    - `submissions` `:10465` (`implicitTls: true`);
    - `submission` `:10587`;
    - `imaps` `:10993` (`implicitTls: true`);
    - `management` `http` `172.31.255.2:8080`;
    - `metrics` `http` on mail's `portcullis-metrics-mail` address `:9180`.

    The base plan deletes every default listener (443, 995, 4190 and 8080 on `[::]`).
  - **Parking domain** `portcullis-former.invalid` (a Stalwart Domain object, never in DNS, never in the `mail` set): removed and former accounts are renamed onto it (M4).
  - **Router:** mailctl's Traefik router `mail-wellknown`, service `mailctl` (port 8081), tier `public@file`, entrypoints `${PORTCULLIS_EP_CORE:-websecure,vpnsecure}`, middlewares `rate-limit@file,security-headers@file`. Its rule is generated per mail-enabled domain (Task 8). Exact paths only: `/.well-known/mta-sts.txt` on `mta-sts.<e>`, `/mail/config-v1.1.xml` + `/.well-known/autoconfig/mail/config-v1.1.xml` on `autoconfig.<e>`, `POST /autodiscover/autodiscover.xml` on `autodiscover.<e>`.

## Review Focus

1. **The client address is rewritten** (rootless Podman's rootlessport, or IPv6 through Docker's userland proxy). Every inbound connection then appears to come from one gateway address. A person would expect:
   - legitimate mail is not rejected: SPF / iprev would fail for everyone and the remote DMARC `reject` would bounce real mail;
   - the server does not ban itself: Stalwart's auto-ban keys on the source address;
   - the doctor says so.

   Degraded mode (M9): SPF, iprev and DNSBL verification off, DMARC only on DKIM alignment and never rejecting, an `AllowedIp` for the gateway, Warning `mail_client_ip_rewritten`. Pinned by `TestClientIPRewrittenPlanDisablesIPChecks` (Task 9) and the e2e-podman step "mail from a rewritten source is delivered, nothing banned" (Task 12).
2. **A 2048-bit RSA DKIM TXT is longer than 255 bytes.** It must be split into 255-byte character-strings when written, compared as their concatenation when read back from both resolvers, and published by Porkbun's and Cloudflare's libdns paths without truncation. Otherwise the key never leaves `pending`, or verifiers see a broken `p=`. Pinned by `TestMailSetLongTXTRoundTrip` (Task 3, fakedns splitting like Porkbun) and the live check's `dkim=pass` for `rsa-sha256` at Gmail (Task 20).
3. **A person leaves `mail_users` while their phone holds an open IMAP IDLE session.** Mail must stop within 8 s, and new mail to their address must get `550 5.1.1` at RCPT, not a later bounce. Pinned by `e2e_mail.py::leave_ends_idle_session` (Task 12) and `TestRemovalRenamesToParkingDomain` (Task 7).
4. **Mail is turned off for a domain that has MTA-STS `enforce` cached by senders.** Removing the MX at once would make remote senders defer, then fail, mail for up to `max_age`. The order is `mode: none` published for a full `max_age` → then the MX and the rest go → then `nomail`. Pinned by `TestMailOffPublishesNoneThenRemoves` (Task 8).
5. **The same username is deleted and re-created in LLDAP within the debounce window.** The new person must get a fresh empty mailbox. The old mailbox goes to `former-<old uuid>` and is never reattached, and the old person's mail passwords stop working. Pinned by `TestUUIDChangeMovesToFormer` (Task 7) and `e2e_mail.py::recreated_username_fresh_mailbox` (Task 12).

## Spec defects and plan rulings (M1–M13, assistant's calls unless marked)

- **M1 (spec defect): uid 10006 is `wg`'s.** mailctl is **10010** (10007 = `vpn_doc`; 10008/10009 are reserved by multi-server). Tasks 5, 10.
- **M2 (spec defect): contract §16 is VPN.** Mail is §M, the next free top-level section (Task 1). Kubernetes' "§16 On Kubernetes" subsection is unrelated.
- **M3 (spec defect): mailctl can't restart `mail`.** It has no engine access, by the spec's own rule. Sessions end like this:
  1. destroy the app passwords;
  2. disable `authenticate` on the account (the Account has no enabled flag; Stalwart's suspension is `permissions.disabledPermissions`);
  3. `x:Action/set` `InvalidateCaches`.

  Task 2 measures whether an authenticated IMAP IDLE / SMTP session survives steps 1–3. **If it survives**, the Hub restarts the core `mail` container through its guarded engine client within the 8 s budget. `restartCoreMail` may target only the container that `docker compose -p portcullis` lists for service `mail`, and `TestMailRestartOnlyTargetsCoreMail` pins that. Tasks 2, 14.
- **M4 (spec defect): disabling `emailReceive` bounces after acceptance** ("delivery fails permanently … the sender gets a bounce"), which is backscatter. A removed or former account is instead renamed onto the parking domain `portcullis-former.invalid`, with `authenticate`, `emailSend` and `emailReceive` disabled and no aliases. Its real address then doesn't exist, so RCPT gets `550 5.1.1 Mailbox does not exist` and the mailbox is kept. Rejoining before the uuid changes renames it back. Task 7.
- **M5 (spec defect): Stalwart has no per-account export task.** `--export` is whole-store and offline only. `mail export <former>` is done like this (audited `mail.export`):
  1. mailctl lifts `authenticate` on that former account only;
  2. creates an app password with `Replace` = `authenticate, imapAuthenticate, imapList, imapSelect, imapExamine, imapFetch, imapStatus`, `allowedIps` = mailctl's `portcullis-mail` address, `expiresAt` = now + 1 h;
  3. streams every mailbox as mbox over IMAPS to stdout (`go-imap/v2`);
  4. destroys the password and disables `authenticate` again, in a `defer` that also runs on error.

  It is the only path that reads message content, CLI-only, never over the Hub API. Task 7.
- **M6 (spec defect): app passwords also work for HTTP Basic** (JMAP, CalDAV, CardDAV, WebDAV, ManageSieve, POP3), per Stalwart's docs. The spec's "refused at interactive sign-in since v1.0.2" isn't documented. So every mail password is `permissions: {"@type":"Replace","permissions":[…]}` with the list `MailPasswordPermissions` (Task 7). It holds `authenticate`, `emailSend`, `emailReceive`, `imapAuthenticate` and the 27 `imap*` mailbox / message permissions, and nothing `jmap*`, `dav*`, `sieve*`, `pop3*`, `sys*`, `impersonate` or `interactAi`. No public HTTP listener exists at all. CI proves Basic auth on the management listener with a mail password → 401 or 403 (Task 12).
- **M7 (spec defect): voiding mail passwords on restore needs Stalwart running, which would open the ports.** `restore` runs the restored store in **recovery mode** (mail services stopped, only the management listener; the `mail enable` recovery session), and mailctl destroys every AppPassword there. Only then does `mail` start normally. Task 10.
- **M8 (spec defect): Stalwart's image sets `cap_net_bind_service=+ep` on its binary.** Under `cap_drop: ALL`, execve of a file whose effective bit asks for a capability outside the bounding set fails with EPERM. Task 2 Step 2 runs the image with `cap_drop: ALL`:
  - if it starts, no `cap_add`;
  - if it fails, `cap_add: [NET_BIND_SERVICE]` is the one exception, documented in hardening.md as "required to exec the upstream binary; it binds only ports ≥ 10025".

  The spec's "no `NET_BIND_SERVICE` is needed" holds only in the first case. Tasks 2, 5.
- **M9 (spec defect): rootless Podman can't publish ports below 80 under the existing host check, and rewrites client addresses.**
  - The mail host check needs `ip_unprivileged_port_start ≤ 25`, documented with its cost: unprivileged users may then bind 25–79.
  - `MAILCTL_CLIENT_IP` = `preserved` (Docker IPv4) | `rewritten` (Podman, or Docker IPv6 without ip6tables, which isn't published, see the runtime matrix) is set by the CLI from the runtime.
  - `rewritten` = degraded mode (Review Focus 1).
  - Outbound IPv6: `ipLookupStrategy` is `v4Only` unless `MAIL_IPV6=on` and the v6 FCrDNS check passes; then it is `v4ThenV6`.

  Tasks 5, 9, 10.
- **M10 (spec defect): Stalwart group accounts are shared mailboxes, not lists.** Lists are **`MailingList`** objects (`recipients` = the members' primary addresses). `posting: members` has no native field, so it works this way:
  - port 25 refuses RCPT to a members-only list (`550 5.7.1 only members may post`);
  - submission admits it only when `authenticated_as` is one of the list's member accounts.

  The check is an `MtaStageRcpt` expression over a mailctl-maintained `MemoryLookupKey` set `list-posters` with entries `<list address>|<member login>`. If v1.1.0's expression functions can't read it, Task 2 pins the fallback, a trusted Sieve script at RCPT. Tasks 2, 7.
- **M11 (spec defect): RocksDB has no online backup** (Stalwart docs). This is spec Q2's own fallback: `backup` runs `dc stop mail` → archives `mail_data` → `dc start mail`. It is the one documented exception to "never stop services": remote senders retry, typically < 30 s of closed ports. A failed archive still restarts `mail` (trap). `stalwart-cli snapshot` is dropped: the configuration objects live in the store, and the CLI isn't in the server image. Task 10.
- **M12: no `stalwart-cli` and no NDJSON plans.** mailctl speaks JMAP directly (`POST /jmap` with `using: ["urn:ietf:params:jmap:core","urn:stalwart:jmap"]`), as a thin envelope in `mailctl/internal/stalwart`. No maintained Go client exists for Stalwart's `x:` objects. Idempotence comes from mailctl's own diff: query, then create / update / destroy by natural key.
  - The HTTP access rule on the management listener is `allowedEndpoints`: `200` when `remote_ip == '<mailctl ip>' && (starts_with(path,'/jmap') || starts_with(path,'/api') || path == '/.well-known/jmap')`, `200` when `listener == 'metrics' && path == '/metrics/prometheus'`, else `404`.
  - Stalwart treats an expression error as `200`, so the network isolation is the real control; CI checks it.
- **M13: Stalwart objects pinned by a schema snapshot.** Task 2 saves the running v1.1.0's `/api/schema` as `mailctl/internal/stalwart/testdata/schema-v1.1.0.json`. `TestEveryUsedFieldInSchema` checks that every object, field and enum value mailctl sends exists there. An image bump must refresh it and pass the mail e2e (spec §3 risk).
- **M14: the DQS key stays in `.env`.** It is not a Hub setting: no secret in `state.yaml`. Settings → Mail → Spam shows "DQS key: set in .env" or "not set", read-only.
- **M15: lists, aliases, the parking domain and the reserved addresses are Hub-wide.** Each address is unique across accounts, aliases, lists and the reserved names. The Hub refuses a conflict with 409 naming both owners, and mailctl refuses a document with one (400).

---

## File structure

**Docs (`wt-mail1/portcullis-docs`):**
- `docs/guides/integration-contracts.md`: §M new; §2, §3, §5, §5.1, §6, §11.3, §12.2, §13.16, §14.5, §14.6, §15.10;
- `docs/setup/mail.md` (new) + `docs/setup/.nav.yml`;
- `docs/operations/mail.md` (new) + `docs/operations/.nav.yml`;
- `hardening.md`, `backups.md`, `monitoring.md`, `cli.md`, `testing.md`, `hub.md` (Settings → Mail, the people "Mail passwords" section), `rootless-podman.md`;
- `docs/setup/dns.md` (the `mail` set);
- `includes/abbreviations.md` (SPF, DKIM, DMARC, MTA-STS, TLS-RPT, DANE, PTR, FCrDNS, DQS).

**Core (`wt-mail1/portcullis`)**

| File | Responsibility |
|---|---|
| `mailctl/` (new Go module: `main.go`, `Dockerfile`, `internal/{config,stalwart,state,reconcile,creds,dnsset,dkim,mtasts,tlsa,dmarc,wellknown,checks,spamrules,api,metrics,export,bootstrap}`) | the mailctl service and its subcommands `serve`, `healthcheck`, `bootstrap`, `void`, `dns --main --json`, `rotate`, `export`, `test` |
| `mail/unbound.conf`, `mail/config.json` (new) | the resolver config; Stalwart's store-only `config.json` (copied into `mail_etc` by `mail enable`) |
| `domains/internal/dnsplan/{plan.go,mail.go}`, `domains/tool.go`, `domains/service.go`, `domains/store.go`, `domains/mailcert.go` (new), `domains/internal/fakedns/fakedns.go` | the `mail` set; `sets/mail`; `domains mail-cert` |
| `docker-compose.yml`, `docker-compose.podman.yml`, `docker-compose.podman-selinux.yml` | profile `mail`: three services, networks, volumes; the `mail-cert` tools service; Hub env + networks; Prometheus membership |
| `scripts/lib/mail.sh` (new), `common.sh`, `network.sh`, `runtime.sh`, `dns.sh`, `status.sh`, `stack.sh`, `backup.sh`, `monitoring.sh`, `portcullis` | CLI |
| `monitoring/prometheus/{prometheus.yml,alerts.yml,tests/alerts_test.yml}` | jobs `mail`, `mailctl`; six alerts |
| `.github/workflows/ci.yml`, `.github/ci/{unit-tests-mail-wiring.sh,build-and-test-mail-service.sh,e2e-mail-*.sh}`, `tests/e2e/e2e_mail.py`, `tests/e2e/mail/` (new: `remote/`, `coredns/`, `unbound-ci.conf`) | CI |
| `tests/test_cli.sh`, `tests/test_shell_libs.sh`, `tests/lint_images.sh` | shell tests, lints |
| `CLAUDE.md`, `.env.example`, `CHANGELOG.md` | rules, keys, changelog |

**Hub (`wt-mail1/portcullis-hub`)**

| File | Responsibility |
|---|---|
| `internal/mailctl/` (new: `client.go`, `types.go`) | the mailctl client (domains-client pattern) and the shared document types |
| `internal/state/mail.go` (new) | `MailSettings`, `MailCredential` |
| `internal/hub/mail.go`, `mail_state.go`, `mail_creds.go`, `mail_dns.go`, `mail_restart.go`, `doctor_mail.go` (new); `hosts.go`, `domains.go`, `revoke.go`, `freshauth.go`, `ports.go` (collisions), `cmd/hub/main.go` | desired state, sync, credentials, DNS, restart fallback, reserved labels |
| `internal/doctor/mail.go` (new) | the 14 kinds |
| `internal/httpapi/mail.go`, `mail_people.go`, `mcptools_mail.go` (new); `server.go`, parity test files | admin and people routes, MCP |
| `internal/templates/coreref.go` | reserved core names |
| `web/mail.js` (new), `web/index.html`, `web/settings.js`, `web/directory.js`, `web/mysignin.js`, `web/mysignin.html`, `web/dns.js` | UI |

**Templates (`wt-mail1/portcullis-templates`):** `tests/validate.py`, `tests/test_validate.py`, `CLAUDE.md`.

---

### Task 1: Contract (docs, first)

**Files:**
- Modify: `docs/guides/integration-contracts.md`. The sections:
  - §M new;
  - §2 (reserved `PORTCULLIS_MAIL*`);
  - §3 (reserved core names);
  - §5 (the `mail-wellknown` router; the reserved labels);
  - §5.1 (the people mail routes);
  - §6 (the Hub's one core-container restart, M3);
  - §11.3 (hostnames);
  - §12.2 (`PUT|DELETE /domains/{name}/sets/mail`);
  - §13.16 (mail passwords as a credential kind);
  - §14.5 / §14.6 (kinds, fixes);
  - §15.10 (`mail_status`).
- Modify (Hub): `web/docs/*` via `sync.sh`.

**Interfaces — Produces (binding for Tasks 2–19):**
- **§3 reserved core names** (the Hub's `coreref.go` and templates' `validate.py`, Task 18):
  - services `mail`, `mailctl`, `mail-resolver`, `mail-cert`;
  - volumes `mail_data`, `mail_etc`, `mail_tls`, `mail_acme`, `mailctl_data`;
  - networks `portcullis-mail`, `portcullis-mailctl`, `portcullis-metrics-mail`, `mail-egress`;
  - aliases `mailctl-metrics`, `mail-metrics`;
  - router `mail-wellknown`, service `mailctl`.
- **§5:** on every mail-enabled domain `<e>` the labels `mail`, `mta-sts`, `autoconfig`, `autodiscover` are reserved. The Hub refuses an instance hostname at or under `<label>.<e>` with 409 `hostname <h> is reserved for mail on <e>`. An enrolled domain whose apex has no `*.<e>` wildcard gets `CNAME mail.<d>.` at `autoconfig.<e>` / `autodiscover.<e>` and `mta-sts.<e>` in the `mail` set.
- **§12.2:**
  - `PUT /domains/{name}/sets/mail` takes the body `{"records":[{"name":"<abs, no dot>","type":"MX|TXT|SRV|TLSA|CNAME|CAA","ttl":<s>,"value":"<libdns RR Data>"}]}`, at most 200 records, every name at or under `<name>`. The response is 202 with the View.
    - The service stores the records as `Domain.MailWanted`.
    - It puts `mail` into `Sets`, removes `nomail` from `Sets`, and marks both due.
  - `DELETE /domains/{name}/sets/mail` → 202. It removes `mail` from `Sets`, makes `mail` due (its records are removed) and adds `nomail` when the domain had it before mail.
  - The plan's `mail` items show want / live per record.
  - `dnsplan.Sets` becomes `address, caa, nomail, mail`.
- **§M Mail** (structure in the spec §4 / §5 / §6 order):
  - **Services, networks, addresses, files:** Global Constraints verbatim.
  - **The mailctl API** (Hub-only on `portcullis-mailctl` `:8080`, `Authorization: Bearer <hub-secret>`, strict JSON, unknown keys refused, bodies ≤ 4 MiB):
    - `PUT /v1/state` — **MailState v1**:

      ```json
      {"version":1,"generation":12,"primary_domain":"d","confirm_mass_removal":false,
       "domains":[{"name":"d","dmarc_start":"reject","mail":"on"}],
       "accounts":[{"username":"alice","uuid":"…","display_name":"Alice A.","addresses":["alice@d","alice@e"],"quota_bytes":10737418240}],
       "aliases":[{"address":"sales@d","username":"alice"}],
       "lists":[{"address":"team@d","members":["alice","bob"],"posting":"members"}],
       "postmaster":["root"],
       "limits":{"recipients_per_hour":300,"recipients_per_day":1000},
       "spam":{"reject_score":15,"junk_score":5,"dnsbl":{"spamhaus":true,"spamcop":true,"barracuda":true},"allow":["example.org"],"block":["spam@example.net"]},
       "local_networks":["10.0.0.0/8"]}
      ```

      - `domains[].mail` is `on` | `off` | `draining` (the MTA-STS `none` phase).
      - The answer is 202 `{"generation":12}`. A `generation` not greater than the applied one is 409.
      - `GET /v1/state` → `{"generation","applied_generation","bootstrap":true,"errors":[…]}`.
    - `GET /v1/dns/{domain}` → `{"domain","records":[{"name","type","ttl","value"}],"dkim":"auto|manual","tlsa":"published|withheld: <why>"}`.
    - `GET /v1/checks[?refresh=1]` → `{"checked_at","checks":[{"id","severity":"ok|info|warning|problem","detail","steps":[…]}]}`, with ids `port25`, `fcrdns_v4`, `fcrdns_v6`, `blocklist`, `cert`, `records:<domain>`, `dkim_selftest:<domain>`, `dmarc_reports`, `tlsrpt_reports`, `client_ip`, `rate_held:<username>`, `auth_failures:<username>`.
    - `GET /v1/credentials?user=<u>` → `[{"id","label","created_at","expires_at","last_used"}]` (`last_used` null when Stalwart doesn't expose it).
    - `POST /v1/credentials` `{"username","label","expires_at"}` → 201 `{"id","secret","created_at","expires_at"}` with `Cache-Control: no-store`. 409 at 5 active; 404 for an unknown account.
    - `DELETE /v1/credentials/{id}?user=<u>` → 204.
    - `GET /v1/status` → `{"bootstrap","stalwart_version","cert":{"not_after","sans"},"dkim":[{"domain","algorithm","selector","stage","since"}],"mtasts":[{"domain","mode","since"}],"dmarc":[{"domain","policy","since"}],"queue":{"messages","deferred"},"client_ip":"preserved|rewritten","restored_at":"<rfc3339>|null","timer_seen_at":"<rfc3339>|null","former":[{"id","username","since"}]}`.
    - `POST /v1/actions/dkim-rotate|dmarc-promote|mtasts-enforce` `{"domain"}` → 202.
  - **Removal timing:** removals are applied at once (Fail closed). Additions are debounced 60 s by the Hub.
  - **Restore voiding:** M7. The Hub marks every metadata row without a Stalwart object `revoked`, with reason `void_restore`.
  - **Reserved addresses:** the reserved local parts on every mail domain, plus the parking domain.
  - **Mail passwords:** permission set M6, `allowedIps` = everywhere, or the Hub's Local networks when `MAIL_SUBMISSION_LAN_ONLY=true`.
  - **Kubernetes:** refused (Global Constraints text).
- **§5.1 people routes** (people listener, signed-in person, `mail_users` member; one 404 otherwise):
  - `GET /api/me/mail` → `{"addresses","server":"mail.<d>","imaps":993,"submissions":465,"submission":587,"username":"<primary>","passwords":[…]}`;
  - `POST /api/me/mail/passwords` `{"label","expiry":"none|90d|1y","proof":{…fresh-auth…}}` → 201 `{"id","password","mobileconfig_b64"}`, `Cache-Control: no-store`;
  - `DELETE /api/me/mail/passwords/{id}` → 204 (no fresh auth);
  - the fresh-auth redirect URI `https://people.<d>/signin`.
- **Admin routes:**
  - `GET|PUT /api/mail/settings`;
  - `GET /api/mail/status`;
  - `GET /api/mail/checks[?refresh=1]`;
  - `PUT /api/mail/domains/{name}` `{"enabled","groups"}`;
  - `GET|PUT /api/directory/users/{username}/mail` (aliases);
  - `DELETE /api/directory/users/{username}/mail/passwords/{id}`;
  - `PUT /api/directory/groups/{group}/mail-list` `{"enabled","domain","posting"}`;
  - `POST /api/mail/actions/{dkim-rotate|dmarc-promote|mtasts-enforce}` `{"domain"}`.

  Admins (`lldap_admin`) hold them all; `manage_signin` holds the password list and revoke only.
- **Audit actions:**
  - `mail.settings`, `mail.domain`, `mail.alias`, `mail.list`, `mail.export`, `mail.dkim_rotate`, `mail.dmarc_promote`, `mail.mtasts_enforce`;
  - `mail_credential.create|revoke|revoke_leave|void_restore`.

  Never a secret.
- **§6:** the Hub restarts the core `mail` container (M3) only when Task 2 found sessions survive.
- **§14.5:** the 14 kinds of Task 17. **§14.6:** fixes `dns_apply` (sets `[mail]`), `mail_dmarc_promote`, `mail_mtasts_enforce`.
- **§15.10:** `mail_status` (R, twin `GET /api/mail/status`), and no credential tool ever.

- [ ] **Step 1:** Write the sections in the contract's existing style ("NEW (mail)" markers).
- [ ] **Step 2:** Run the docs gate. Expected: exit 0.
- [ ] **Step 3:** Commit (`docs: contract for mail (mailctl API, MailState v1, sets/mail, reserved names, people mail routes)`) and push `mail1`.
- [ ] **Step 4:** Resync the Hub `web/docs` (Global Constraints). Check that `git diff --stat web/docs` lists only `integration-contracts.md`, then commit (`docs: sync contract (mail)`) on Hub `mail1`.

---

### Task 2: Spike — pin Stalwart v1.1.0's behaviour (core)

The spike pins the facts the spec and this plan assume about Stalwart but its docs don't settle. It runs on a throwaway compose project under `/tmp/mail-spike` (never committed), from the pinned image. Its outputs are committed fixtures plus a "Task 2 results" block that the controller copies into this plan's M3, M8 and M10 before Task 5.

**Files:**
- Create: `mailctl/internal/stalwart/testdata/schema-v1.1.0.json` (from `GET /api/schema`, recovery admin)
- Create: `mailctl/internal/stalwart/testdata/jmap/*.json` (real request / response pairs for: Account create / rename, AppPassword create — the secret field shape — and destroy, ApiKey create, DkimSignature create with `stage: pending`, MailingList create, MemoryLookupKey, Action/InvalidateCaches, NetworkListener destroy)

- [ ] **Step 1:** Start the image in recovery mode (`STALWART_RECOVERY_MODE=1`, `STALWART_RECOVERY_ADMIN=spike:<random>` from a 0600 env file). Fetch the schema and save it. Record the JMAP session URL, and check that Basic auth with the recovery admin works on `POST /jmap`.
- [ ] **Step 2 (M8):** Restart with `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, `read_only: true`, `user: "2000:2000"`, tmpfs `/tmp`. Record whether it starts. Repeat with `cap_add: [NET_BIND_SERVICE]`.
- [ ] **Step 3 (M3):**
  1. Create a test domain, an account and an app password. Open an IMAP IDLE session and an authenticated SMTP submission session.
  2. Destroy the app password, set `permissions` `Merge` with `authenticate`, `emailSend` and `emailReceive` disabled, then run `Action/InvalidateCaches`.
  3. Record within how many seconds each open session's next command fails, if ever: `NOOP`, `SELECT INBOX`, `MAIL FROM`.
  4. Rename the account to `x@portcullis-former.invalid` and record RCPT to the old address on 25 (expected `550 5.1.1`).
- [ ] **Step 4 (M10):** Write an `MtaStageRcpt` rule that reads a `MemoryLookupKey` set and refuses non-members, and record that it works on 25 and on submission. If it can't, write and record the Sieve fallback.
- [ ] **Step 5:** Record:
  - DKIM: with `dkimManagement: Manual`, a key created with `stage: pending` doesn't sign; updated to `active` it does; `retiring` doesn't.
  - Applications: which object or field stops the WebUI download at start, by watching the egress connections (`ss -tnp` in a debug sidecar sharing the netns).
  - Spam rules: `spamFilterRulesUrl` accepts `http://172.31.255.3:8082/…`.
  - Listeners: removing all default listeners plus creating the six of Global Constraints survives a restart (defaults aren't re-created while one listener exists).
- [ ] **Step 6:** Commit the fixtures (`mailctl: Stalwart v1.1.0 schema and JMAP fixtures (spike)`) with the results block in the commit message. The controller amends M3 / M8 / M10 in this plan on Hub `mail1` (`plan: mail spike results`).

---

### Task 3: Domains — the `mail` record set (core)

**Files:**
- Create: `domains/internal/dnsplan/mail.go`, `domains/internal/dnsplan/mail_test.go`
- Modify:
  - `domains/internal/dnsplan/plan.go`: `SetMail`, `Sets`, `Spec.Mail`, `Wanted`, `Build`, `Apply`, `rrData` for `*dns.SRV` / `*dns.TLSA` / `*dns.CNAME`; `nomailItems` is skipped when `len(Spec.Mail) > 0`.
  - `domains/tool.go` (`toolInput.Mail []MailRecord`, the `mail` set name accepted).
  - `domains/service.go` (`PUT|DELETE /domains/{name}/sets/mail`; `buildPlan` passes `MailWanted`).
  - `domains/store.go` (`Domain.MailWanted []dnsplan.MailRecord`, `Domain.NoMailBeforeMail bool`).
  - `domains/internal/fakedns/fakedns.go` (`TXTSplit255`: store a long TXT as several strings, as Porkbun serves it).
- Test: `domains/internal/dnsplan/mail_test.go`, `domains/service_test.go`, `domains/tool_test.go`

**Interfaces — Produces:**
- `const SetMail = "mail"`; `Sets = []string{SetAddress, SetCAA, SetNoMail, SetMail}`.
- `type MailRecord struct{ Name, Type string; TTL int; Value string }` (JSON `name,type,ttl,value`).
- `func ValidateMail(d string, recs []MailRecord) error`. It enforces:
  - the names at or under `d`, or exactly `MAIL_HOSTNAME`'s names for the main domain;
  - types MX / TXT / SRV / TLSA / CNAME / CAA, TTL 60–86400, ≤ 200 records;
  - no CNAME next to another type at the same name;
  - no CAA except at `mail.<d>`.
- `func mailRecords(recs []MailRecord) ([]libdns.Record, error)` turns the records into libdns types. TXT values are split into ≤ 255-byte strings by the provider path and joined for comparison. TLSA uses `libdns.RR{Type:"TLSA", Data:"3 1 1 <hex>"}`.
- `func mailItems(ctx, in Input, d string, fix Fix) []Item`: one item per (name, type).
  - Status by `judge` at both resolvers.
  - SPF TXT at `<e>` replaces only SPF strings (other TXT stays), like nomail.
  - A TLSA the provider can't write → `FixManual`, step `add TLSA _25._tcp.<host> 3 1 1 <hex> by hand: <provider> can't write TLSA records`.
- Apply order within `mail`: append every wanted record first, then delete stale entries by exact data (the existing `syncSet`). A `mail` apply never touches `address` / `caa` records.

- [ ] **Step 1: Write the failing tests:**
  - `TestWantedMailSetReplacesNoMail` (`Spec{NoMail:true, Mail:[…]}` → `Wanted` has a `mail` key and no `nomail` key).
  - `TestMailSetLongTXTRoundTrip` (Review Focus 2): a 410-byte RSA `p=` record through fakedns with `TXTSplit255` is written, read back by both resolvers, and judged `ok`. Also with Cloudflare-style unsplit storage.
  - `TestMailItemsSPFKeepsOtherTXT` (a `google-site-verification=…` TXT survives).
  - `TestMailTLSAProviderCannotWrite` (fake provider refusing type TLSA → item `FixManual` with the exact step text).
  - `TestValidateMailRefuses`: a name outside `d`; CNAME+TXT at one name; 201 records; CAA at `<e>`.
  - `TestSetsMailEndpoint` (service): `PUT /domains/team-b.test/sets/mail` → 202, `Sets` has `mail` not `nomail`, `DueSets` has both. `DELETE` → `nomail` back only when `NoMailBeforeMail`. Unknown key → 400. A non-enrolled name → 404.
  - `TestToolApplyMainMail` (tool): stdin `{"sets":["mail"],"mail":[…]}` writes the records in the fake zone.
- [ ] **Step 2:** Run `cd domains && go test -race ./...`. Expected: FAIL (undefined `SetMail`, `MailRecord`).
- [ ] **Step 3:** Implement as the Interfaces block says.
- [ ] **Step 4:** Run the domains gate (Global Constraints). Expected: PASS.
- [ ] **Step 5:** Commit (`domains: the mail record set (sets/mail, tool input, SRV/TLSA/long TXT)`).

---

### Task 4: Domains — `domains mail-cert` and the `mail-cert` tools service (core)

**Files:**
- Create: `domains/mailcert.go`, `domains/mailcert_test.go`
- Modify: `domains/main.go` (subcommand `mail-cert`), `docker-compose.yml` (service `mail-cert`, volumes `mail_tls`, `mail_acme`)

**Interfaces — Produces:**
- `domains mail-cert` reads one JSON object on stdin (≤ 64 KiB, unknown keys refused): `{"hostname","ca_server","email","provider","credentials":{…},"caa":{"enabled","issuer","iodef"},"renew_below_days":30}`. It runs these steps:
  1. Load or create the ACME account in `/acme/account.json` (EC P-256, 0600) and the certificate key `/acme/mail.key` (EC P-256, created once, **reused**).
  2. Ensure the `caa` entry at `<hostname>` pins this account (`dnsplan.CAAValue`, written through the same provider, `waitCAA`).
  3. Issue with lego `certificate.ObtainRequest{Domains:[hostname], Bundle:true, PrivateKey: <mail.key>}` (DNS-01 via the existing `challengeProvider`) when the current `/tls/fullchain.pem` expires in < `renew_below_days` or its key or SANs differ.
  4. Write `/tls/fullchain.pem` and `/tls/privkey.pem` atomically, 0640.
  5. Print one JSON line `{"renewed":bool,"not_after","spki_sha256"}`.

  Exit codes as `domains dns` (0 / 1 problem / 2 usage / 3 provider failure, redacted).
- `domains mail-cert --next-key` creates `/acme/mail.next.key` (TLSA rollover, Task 8) and prints its `spki_sha256`. `--switch-key` makes it current at the next issue.
- Compose `mail-cert`: `image: portcullis-domains`, `pull_policy: never`, `profiles: [tools]`, `<<: *hardening`, `read_only: true`, `user: "10004:2000"`, `entrypoint: ["domains","mail-cert"]`, `stdin_open: true`, healthcheck disabled, volumes `mail_acme:/acme`, `mail_tls:/tls`, networks `[domains-egress]`, `mem_limit: 128m`, `pids_limit: 64`.

- [ ] **Step 1: Write the failing tests** (in-process Pebble with `internal/fakedns`, as the service tests):
  - `TestMailCertIssuesAndReusesKey` (issue, then force a renewal: the same SPKI).
  - `TestMailCertWritesCAAAtHost` (a CAA at `mail.<d>` with `accounturi=` this account; the main `<d>` CAA untouched).
  - `TestMailCertRefusesWrongSANs` (an existing chain for another name → replaced; a fresh chain whose SAN ≠ hostname → refused, old files kept).
  - `TestMailCertNoRenewAbove30Days`.
  - `TestMailCertNextKey` (the next SPKI differs and is stable across calls).
  - `TestMailCertStdinRefusesUnknownKey`.
- [ ] **Step 2:** Run `cd domains && go test -race -run MailCert ./...`. Expected: FAIL.
- [ ] **Step 3:** Implement `runMailCert(args []string, env toolEnv) int` in `domains/mailcert.go` and the compose service.
- [ ] **Step 4:** Run the domains gate and `docker compose -f docker-compose.yml --env-file <generated .env> --profile tools config -q`. Expected: PASS.
- [ ] **Step 5:** Commit (`domains: mail-cert (own ACME account, reused key, CAA at mail.<d>)`).

---

### Task 5: mailctl skeleton, the `mail` profile and its wiring (core)

**Files:**
- Create:
  - `mailctl/{go.mod,go.sum,main.go,main_test.go,Dockerfile}`;
  - `mailctl/internal/config/config.go` (+ test);
  - `mailctl/internal/stalwart/{client.go,schema_test.go}`;
  - `mailctl/internal/api/{server.go,server_test.go}`;
  - `mailctl/internal/metrics/metrics.go`;
  - `mailctl/internal/spamrules/{rules.go,spam-filter-rules.json.gz}`;
  - `mail/unbound.conf`, `mail/config.json`.
- Modify:
  - `docker-compose.yml`: services `mail`, `mailctl`, `mail-resolver` (profile `mail`); networks; volumes; the Hub joins `portcullis-mailctl` at `.18` and gets the `HUB_MAILCTL_*` env plus the `hub-secret` bind; Prometheus joins `portcullis-metrics-mail`.
  - `docker-compose.podman.yml` (three `restart: always`), `docker-compose.podman-selinux.yml` (7 new binds; `NBINDS` 46 → 53).
  - `scripts/lib/common.sh`: `CT_UID_MAIL=2000`, `CT_UID_MAILCTL=10010`, `secrets_fix_perms` for `secrets/mail/*`, `stack_prepare` (empty placeholder files; `volume_own mailctl_data 10010:10010 0700`, `mail_tls 10004:2000 2750`, `mail_acme 10004:10004 0700`, only with `mail` in `COMPOSE_PROFILES`).
  - `scripts/lib/network.sh`: `mail_subnet`, `mail_ip_range`, `mail_ip`, `mailctl_ip`, `mail_resolver_ip`, `mailctl_subnet`, `mailctl_hub_ip`, `mailctl_api_ip`, `mailctl_proxy_ip`, `validate_mail_network_config`, `mail_network_state`, the `network_check` mismatch guard.
  - `tests/test_shell_libs.sh`, `tests/lint_images.sh` (two new pins).
  - `.github/workflows/ci.yml` (unit-tests: `cd mailctl` vet/test; one step `bash .github/ci/unit-tests-mail-wiring.sh`).
  - `.github/dependabot.yml` (`gomod` for `/mailctl`; `docker` covers the compose pins).
  - `CLAUDE.md`, `.env.example`.
- Create: `.github/ci/unit-tests-mail-wiring.sh`

**Interfaces — Produces:**
- `mailctl` subcommands: `serve` (default), `healthcheck`, `bootstrap`, `void`, `dns`, `rotate`, `reload-tls`, `status`, `export`, `test` (later tasks fill them; each talks to the running serve process's loopback admin socket `/tmp/mailctl.sock` or to Stalwart directly, as its task says). Unknown → exit 2.
- `config.Load(env func(string) string) (Config, error)` reads:
  - `MAILCTL_API_ADDR` (`:8080`), `MAILCTL_API_SUBNET`, `MAILCTL_HUB_SECRET_FILE`, `MAILCTL_API_KEY_FILE`;
  - `MAILCTL_STALWART_URL` (`http://172.31.255.2:8080`), `MAILCTL_WELLKNOWN_ADDR` (`:8081`), `MAILCTL_RULES_ADDR` (`172.31.255.3:8082`), `MAILCTL_METRICS_ADDR` (`mailctl-metrics:9100`), `MAILCTL_DATA` (`/data`);
  - `MAILCTL_CLIENT_IP` (`preserved|rewritten`, required), `MAIL_HOSTNAME`, `PORTCULLIS_DOMAIN`;
  - `MAIL_DKIM_ROTATE`, `MAIL_FORMER_RETENTION`, `MAIL_SUBMISSION_LAN_ONLY`, `MAIL_IPV6`;
  - `MAIL_RELAY_HOST`, `_PORT`, `_USERNAME`, `_SPF_INCLUDE`, `MAILCTL_DQS_KEY_FILE`;
  - `MAILCTL_PUBLIC_IPV4` / `_IPV6` (env_file `secrets/domains/public-ips.env`'s `DOMAINS_PUBLIC_IPV*` names), `MAILCTL_RESOLVERS` (`1.1.1.1:53 8.8.8.8:53`).

  Any missing required value, or a bad value, → error naming the variable.
- `stalwart.Client`: `New(url string, auth Auth) *Client`, with `Auth` = `Bearer(apiKey)` or `Basic(user, pass)`.
  - `Call(ctx, method string, args any, out any) error` sends one method call, `using` = core + `urn:stalwart:jmap`; a `["error", …]` response → `*MethodError{Type, Description}`.
  - `Set(ctx, object string, create map[string]any, update map[string]map[string]any, destroy []string) (SetResult, error)`.
  - `Query(ctx, object string, filter any) ([]string, error)`.
  - `Get(ctx, object string, ids []string, props []string, out any) error`.
  - `Action(ctx, variant string) error`.
- `api.Server`: listens on `MAILCTL_API_ADDR`. It refuses (403, empty body) a connection whose local address isn't inside `MAILCTL_API_SUBNET` or whose bearer differs (constant-time compare against the file read at each request, as domains). `GET /healthz` is open on loopback only.
- `spamrules.Handler()` serves the embedded file at `/spam-filter-rules.json.gz` on `MAILCTL_RULES_ADDR` only. `TestEmbeddedRulesDigest` pins the sha256.
- **Compose `mail`:**
  - `image:` the Stalwart pin; `<<: *hardening`; `cap_add` per M8.
  - `user: "2000:2000"`, `read_only: true`, tmpfs `/tmp`, `init: true`.
  - `ulimits: {nofile: {soft: 65536, hard: 65536}}`, `mem_limit: 1g`, `pids_limit: 256`.
  - env_file `- path: ./secrets/mail/recovery.env` (`required: false`); env `STALWART_HEALTHCHECK_URL: http://127.0.0.1:8080/healthz/live`.
  - Volumes:
    - `mail_data:/var/lib/stalwart`, `mail_etc:/etc/stalwart`, `mail_tls:/run/portcullis/mail/tls:ro`;
    - `./secrets/mail/metrics-secret:/run/portcullis/mail/metrics-secret:ro`, `./secrets/mail/relay-password:/run/portcullis/mail/relay-password:ro`.
  - Networks:
    - `portcullis-mail: {ipv4_address: ${PORTCULLIS_MAIL_IP:-172.31.255.2}}`;
    - `mail-egress: {}`;
    - `portcullis-metrics-mail: {aliases: [mail-metrics]}`.
  - Ports `"0.0.0.0:25:10025"`, `"0.0.0.0:465:10465"`, `"0.0.0.0:587:10587"`, `"0.0.0.0:993:10993"`. The `[::]` lines are added by the CLI override `secrets/mail/ipv6.override.yml` only with `MAIL_IPV6=on` (Task 10).
  - Healthcheck `CMD-SHELL` `curl -fsS http://127.0.0.1:8080/healthz/live || exit 1`, `start_period: 60s`.
  - `restart: unless-stopped`.
- **Compose `mailctl`:**
  - `build: ./mailctl`, `image: portcullis-mailctl`, `<<: *hardening`.
  - `user: "10010:10010"`, `group_add: ["10001"]`, `read_only: true`, tmpfs `/tmp`.
  - Env (above); env_file `./secrets/domains/public-ips.env` (`required: false`).
  - Volumes `mailctl_data:/data`, `./secrets/mail/api-key:/run/portcullis/mail/api-key:ro`, `./secrets/mail/hub-secret:/run/portcullis/mail/hub-secret:ro`, `./secrets/mail/dqs-key:/run/portcullis/mail/dqs-key:ro`.
  - Networks:
    - `portcullis-mail: {ipv4_address: .3}`;
    - `portcullis-mailctl: {ipv4_address: ${PORTCULLIS_MAILCTL_API_IP:-172.31.255.19}}`;
    - `portcullis-proxy: {ipv4_address: ${PORTCULLIS_MAILCTL_PROXY_IP:-172.31.250.4}}`;
    - `mail-egress: {}`;
    - `portcullis-metrics-mail: {aliases: [mailctl-metrics]}`.
  - Healthcheck `CMD-SHELL` `mailctl healthcheck`; `mem_limit: 256m`, `pids_limit: 128`.
  - Traefik labels `traefik.enable`, `traefik.docker.network: portcullis-proxy`, service `mailctl` port 8081 (the router rule comes in Task 8).
- **Compose `mail-resolver`:**
  - The Unbound pin, `<<: *hardening`, `read_only: true`, `user:` the image's `unbound` uid:gid (read from its `/etc/passwd` in Step 1; recorded as `CT_UID_MAIL_RESOLVER`), tmpfs `/tmp`.
  - `command: ["-d","-c","/etc/unbound/custom.conf"]`, volume `./mail/unbound.conf:/etc/unbound/custom.conf:ro`.
  - Networks `portcullis-mail: {ipv4_address: .4}`, `mail-egress: {}`.
  - Healthcheck `CMD-SHELL` `drill-hc @127.0.0.1 -p 5353 dnssec.works` (the image's tool; AD required).
  - `mem_limit: 128m`, `pids_limit: 64`.
- **`mail/unbound.conf`:**
  - `interface: 0.0.0.0@5353` (a non-root process can't bind 53, and no capability is added). `mail` and `mailctl` use `172.31.255.4:5353` explicitly: Stalwart through `DnsResolver Custom` (Task 6), mailctl through `MAILCTL_LOCAL_RESOLVER=172.31.255.4:5353`. No compose `dns:` key is set on any mail service.
  - `username: ""`, `do-daemonize: no`, `access-control: 172.31.255.0/28 allow`, everything else refused.
  - `trust-anchor-file: /var/unbound/root.key` (the image's, read-only: refreshed by image bumps), `harden-dnssec-stripped: yes`, `val-permissive-mode: no`.
  - No `forward-zone`; `qname-minimisation: yes`; `cache-max-ttl: 86400`.
- **`network.sh`:**
  - `validate_mail_network_config`: subnets parse, ranges inside, pinned addresses inside the subnet and outside the range, none equal to the gateway / broadcast, the two subnets disjoint from each other and from every core subnet (`_overlaps`).
  - `PORTCULLIS_MAILCTL_PROXY_IP` inside the proxy subnet, outside its range, ≠ Traefik's / mcp-gate's IP.
  - Only with `mail` in `COMPOSE_PROFILES`.
- **`unit-tests-mail-wiring.sh`** asserts over `docker compose config` with `--profile mail`:
  - membership: `portcullis-mail` = {mail, mailctl, mail-resolver}; `portcullis-mailctl` = {hub, mailctl}; `portcullis-metrics-mail` = {prometheus, mail, mailctl}; `mail-egress` = {mail, mailctl, mail-resolver};
  - internal flags;
  - the mounts: the only bind of `api-key` is mailctl's; `hub-secret` is in hub + mailctl; no service but mail mounts `mail_data` / `mail_etc`; `mail_tls` ro in mail;
  - no engine socket; no `privileged` / `devices` / `sysctls`; `cap_add` only as M8 on `mail`;
  - user ids; pins; no Traefik router other than `mail-wellknown`;
  - the same checks with the Podman and SELinux overlays.

- [ ] **Step 1: Write the failing tests:**
  - `config_test.go`: `TestLoadRefusesMissing` (each required variable named); `TestClientIPMode` (`preserved|rewritten` only).
  - `server_test.go`:
    - `TestAPIRefusesOutsideSubnet` (local address outside → 403);
    - `TestAPIRefusesBadBearer`;
    - `TestAPISecretReadPerRequest` (rotated file → the new one works);
    - `TestHealthzLoopbackOnly`.
  - `schema_test.go`: `TestEveryUsedFieldInSchema` (M13; a registry `stalwart.Used` of `{object, field}` filled by later tasks, checked against the snapshot).
  - `TestEmbeddedRulesDigest`.
  - `main_test.go`: `TestStartRefusesEmptyAPIKey`.
  - Shell (`test_shell_libs.sh`):
    - "validate_mail_network_config refuses an overlap with portcullis-vpn";
    - "… mailctl proxy IP = Traefik's";
    - "… pinned IP in the range";
    - "stack_prepare makes the mail placeholders only with the mail profile".
  - The wiring script against an empty profile (fails).
- [ ] **Step 2:** Run the core gate. Expected: FAIL.
- [ ] **Step 3:** Implement. The Dockerfile uses the same golang builder and alpine digests as `mcp-gate/Dockerfile` (unit-tests' single-builder-digest check), CGO off, `USER 10010:10010`, `HEALTHCHECK` none (compose's).
- [ ] **Step 4:** Run the core gate, `bash .github/ci/unit-tests-mail-wiring.sh`, `bash tests/lint_healthchecks.sh <env>` and `bash tests/lint_images.sh`. Expected: PASS.
- [ ] **Step 5:** Commit (`mail: profile mail (Stalwart, mailctl skeleton, Unbound), networks, ids, wiring checks`).

---

### Task 6: Bootstrap, the base plan, the certificate and the timer (core)

**Files:**
- Create: `mailctl/internal/bootstrap/{bootstrap.go,baseplan.go,bootstrap_test.go}`, `scripts/lib/mail.sh`
- Modify:
  - `portcullis` (source `mail`; dispatch `mail`);
  - `scripts/lib/common.sh` (`help_main` line);
  - `scripts/lib/stack.sh` (`stack_up` / `upgrade_run`: `mail_up_steps`);
  - `scripts/lib/runtime.sh` (`RT_PORT_START_MAX_MAIL=25`, the host check row, the kubernetes refusal);
  - `tests/test_cli.sh`, `.env.example`, `CLAUDE.md`.

**Interfaces — Produces:**
- `mailctl bootstrap` reads stdin `{"recovery_user","recovery_password","hostname","primary_domain","client_ip","lan_only","local_networks":[…],"relay":{…}|null,"metrics_user":"prometheus"}`. It authenticates with Basic (the recovery admin), applies `BasePlan(cfg) []Op` idempotently, and prints exactly one line `{"api_key":"API_…"}`, or `{"api_key":null}` when the key exists and `--rotate-key` wasn't given. The base plan:
  - **Listeners:** delete every listener that isn't one of the six (Global Constraints), then create the missing ones.
  - **`SystemSettings`:** `defaultHostname` = `MAIL_HOSTNAME`, `maxBufferedMemory` 134217728.
  - **`Cache`:** `messagesLarge` 0, `groupwareLarge` 0, `messages` 67108864.
  - **`DataStore`:** `cacheSize` 67108864. Q4: the field names are as the schema snapshot says.
  - **`Certificate`:** `certificate` `File /run/portcullis/mail/tls/fullchain.pem`, `privateKey` `File …/privkey.pem`.
  - **`AcmeProvider`:** none. Every `Domain` gets `certificateManagement: Manual`, `dnsManagement: Manual`, `dkimManagement: Manual`.
  - **`DnsResolver`:** `Custom`, servers `[{protocol: udp, address: 172.31.255.4, port: 5353}, {protocol: tcp, …}]`.
  - **`Http`:** `allowedEndpoints` per M12.
  - **`Metrics`:** `prometheus` `Enabled`, `authUsername` `prometheus`, `authSecret` `File /run/portcullis/mail/metrics-secret`.
  - **`MtaStageAuth`:** `saslMechanisms` `[plain, login]` only when `local_port != 10025 && is_tls`, else `false`. `require` is `local_port != 10025`. `mustMatchSender` is `true`.
  - **`MtaStageRcpt`:**
    - `allowRelaying` is `!is_empty(authenticated_as)`, so no IP trust;
    - the list-posting rule M10;
    - submission refuses the MX role: an unauthenticated session on 10465 / 10587 gets 503 before MAIL;
    - `maxRecipients` 100.
  - **`SenderAuth`:** `dkimVerify`, `spfEhloVerify`, `spfFromVerify`, `dmarcVerify`, `reverseIpVerify` and `arcVerify` are all `relaxed` on 10025, or M9's degraded values with `client_ip=rewritten`.
  - **`MtaTlsStrategy` `default`:** `dane: optional`, `mtaSts: optional`, `startTls: optional`, `allowInvalidCerts: false`. A strategy `relay-strict` sets `startTls: require`.
  - **`MtaOutboundStrategy`:** `route` = `'relay'` when a relay is configured, else `'mx'`, for non-local recipients. The `tls` expression never selects the `invalid-tls` fallback.
  - **`MtaRoute`:** `Relay` `relay` (host, port, `implicitTls` = port == 465, `authUsername`, `authSecret` `File /run/portcullis/mail/relay-password`), only with a relay. The `mx` route's `ipLookupStrategy` per M9.
  - **`SpamSettings`:**
    - `enable` true, `scoreSpam` 5, `scoreReject` 15, `scoreDiscard` 0;
    - `greylistFor` unset;
    - `spamFilterRulesUrl` `http://172.31.255.3:8082/spam-filter-rules.json.gz`;
    - the AI classifier objects disabled, the statistical classifier on with autolearn.
  - **`SpamDnsblSettings`:** Spamhaus ZEN, SpamCop and Barracuda zones, queried through the resolver.
  - **`Security`:** `authBanRate` default; with `client_ip=rewritten` an `AllowedIp` for the `mail-egress` gateway.
  - **`Domain` `portcullis-former.invalid`.**
  - **Role `portcullis-mailctl`:**
    - `authenticate`, `impersonate`;
    - `sysAccount{Get,Create,Update,Destroy,Query}`, `sysDomain{…}`, `sysDkimSignature{…}`, `sysAppPassword{Get,Create,Destroy,Query}`, `sysMailingList{…}`;
    - `sysQueuedMessageGet`, `sysQueuedMessageQuery`;
    - `sysActionCreate`, `actionReloadSettings`, `actionReloadTlsCertificates`, `actionInvalidateCaches`;
    - `sysDmarcExternalReportGet|Query`, `sysTlsExternalReportGet|Query`;
    - `sysSpamSettingsGet|Update`, `sysMemoryLookupKey*`.

    It holds **no** `jmapEmail*`, `imap*`, `sysApiKey*` or `sysRole*`: the key can't widen itself.
  - **Account `portcullis-mailctl@portcullis-former.invalid`:** User, role Custom `[portcullis-mailctl]`, a random 64-byte password never kept.
  - **One `ApiKey`** for that account: `permissions: Inherit`, `allowedIps` = `[172.31.255.3/32]`, no expiry.
  - **The trailing `Action/ReloadSettings`.**
- **`scripts/lib/mail.sh`:**
  - `mail_enable` takes `[--hostname H] [--lan-only true|false] [--yes]`. Its steps:
    1. Refuse on kubernetes. On podman, refuse unless `ip_unprivileged_port_start ≤ 25`, naming the sysctl line.
    2. Write `.env` `MAIL_HOSTNAME` and `COMPOSE_PROFILES += mail` once (`env_set`); copy `mail/config.json` into `mail_etc` through `ct_run` as 2000:2000.
    3. `mail_cert_ensure`.
    4. `mail_recovery_session mail_bootstrap_apply`.
    5. `hub_env_write`; `stack_compose_up mail mail-resolver mailctl traefik hub`.
    6. Prompt (or `--yes`) for `mail schedule --systemd`.
  - `mail_recovery_session <fn>`:
    1. Generate a 32-byte password (`openssl rand -base64 32` into a variable, never argv).
    2. Write `secrets/mail/recovery.env` (umask 077) with `STALWART_RECOVERY_MODE=1` and `STALWART_RECOVERY_ADMIN=portcullis-recovery:<pw>`, then `dc up -d --force-recreate --no-deps mail`.
    3. Wait for `/healthz/live` (mail healthy).
    4. Call `<fn>`, which gets the credentials on fd 3.
    5. Always, in a trap: `rm -f` the env file, `dc up -d --force-recreate --no-deps mail`.
    6. Check through `dc exec -T mailctl mailctl bootstrap --verify-gone` (credentials on stdin) that the recovery login is refused (401); else fail `the recovery admin still works: stop mail and inspect`.
  - `mail_bootstrap_apply` pipes the JSON into `dc run --rm --no-deps -T mailctl mailctl bootstrap` and writes `api_key` from stdout straight into `secrets/mail/api-key` with `jq -r .api_key > file` (umask 077, then `ct_group_read 10010`). The key never reaches a shell variable that's echoed. `null` keeps the file.
  - `mail_cert_ensure`: `_mail_cert_input` (like `_dns_tool_input`: jq `env[$var]` for the credentials) piped into `dc run --rm --no-deps -T mail-cert`. Lego-only providers (`DNS_PROVIDER` without a libdns writer) refuse with `mail needs a DNS provider Portcullis can write (see setup/mail.md)`, because the mail certificate needs DNS-01.
  - `mail_schedule_systemd` writes `portcullis-mail.service` + `.timer` (`OnCalendar=daily`, `RandomizedDelaySec=1h`, `Persistent=true`). Its ExecStart is `<checkout>/portcullis mail rotate`. Same unit shape as `backup_schedule_systemd` (podman: user units, `After/Requires=podman.socket`).
  - `mail_rotate`:
    1. `mail_cert_ensure`;
    2. on change, `dc exec -T mailctl mailctl reload-tls` (`Action/ReloadTlsCertificates`);
    3. `dc exec -T mailctl mailctl rotate --json`, which runs the state machines and prints the main domain's wanted set;
    4. `DNS_SETS=mail` and `_dns_tool apply` with the set (Task 8's input).
  - `mail_up_steps` (called from `stack_up` and `upgrade_run` when `mail` is in `COMPOSE_PROFILES`):
    - `mail_cert_ensure` when `fullchain.pem` is missing;
    - after a Stalwart image change (the stored digest `secrets/mail/.stalwart-image` differs), one recovery-less recreate with `STALWART_UPDATE_ROLE_PERMISSIONS=true` in a 0600 env file, removed after healthy;
    - `upgrade` re-runs `mail_recovery_session mail_bootstrap_apply` (the base plan is idempotent).
  - `mail_disable [--yes]`:
    1. Tell the Hub to drain every domain (`hub mail drain` through the Hub's control socket, as `hub vpn …`).
    2. Print that MX removal waits for MTA-STS `max_age`.
    3. Remove `mail` from `COMPOSE_PROFILES` only after the Hub reports every domain `off`, or with `--force`, which says the MX is removed now and senders may bounce.
- `cmd_mail` dispatches `enable|disable|status|test|dkim|cert|rotate|schedule|export`; `help_mail*` for each. `--help` works without `.env`; argument errors exit 2.

- [ ] **Step 1: Write the failing tests:**
  - Go: `TestBasePlanIsIdempotent` (a fake JMAP server: two runs; the second sends no `create`).
  - Go: `TestBasePlanRoleHasNoSelfWidening` (no `sysApiKey*` / `sysRole*` / `jmapEmail*` / `imap*`).
  - Go: `TestBasePlanDeletesDefaultListeners`.
  - Go: `TestBasePlanRelayStrictTLS` (with a relay: `relay-strict` and the route).
  - Go: `TestBootstrapPrintsKeyOnce` (second run `null`).
  - Go: `TestVerifyGoneRefusesWhenLoginWorks`.
  - Shell (`test_cli.sh`, stub `docker`):
    - "mail enable on kubernetes → exit 1 with the text";
    - "mail enable on podman with port start 80 → refused naming net.ipv4.ip_unprivileged_port_start=25";
    - "mail_recovery_session removes recovery.env when fn fails";
    - "the recovery password never on argv" (the argv grep);
    - "mail schedule --systemd writes the timer (docker and podman shapes)";
    - "every mail subcommand --help without .env".
- [ ] **Step 2:** Run the core gate. Expected: FAIL.
- [ ] **Step 3:** Implement as above.
- [ ] **Step 4:** Run the core gate. Expected: PASS.
- [ ] **Step 5:** Commit (`mail: enable/disable, recovery bootstrap, base plan, mail certificate, daily timer`).

---

### Task 7: Desired state, reconcile, credentials, void, export (core)

**Files:**
- Create:
  - `mailctl/internal/state/{doc.go,doc_test.go,store.go}`;
  - `mailctl/internal/reconcile/{reconcile.go,reconcile_test.go}`;
  - `mailctl/internal/creds/{creds.go,creds_test.go}`;
  - `mailctl/internal/export/{export.go,export_test.go}`.
- Modify: `mailctl/internal/api/server.go` (routes), `mailctl/main.go` (`void`, `export`), `mailctl/internal/stalwart/fake/` (a fake JMAP server with Account / MailingList / AppPassword / MemoryLookupKey semantics, used by every mailctl test).

**Interfaces — Produces:**
- `state.Parse(b []byte) (*Doc, error)` is strict: version 1; unknown, duplicate or missing keys refused; trailing data refused. It also refuses:
  - an address on a domain not in `domains`;
  - a duplicate address across accounts, aliases, lists and the reserved names (M15);
  - a reserved local part used by a person;
  - a username that isn't LLDAP's form;
  - a uuid that isn't a UUID;
  - `quota_bytes` < 0;
  - limits outside 1–100000;
  - scores with `junk ≥ reject`.
- `reconcile.Plan(cur Live, want *state.Doc, now time.Time) Ops` is pure. `Ops` = ordered creates, updates, renames and destroys, computed like this:
  - Account key = LLDAP uuid, stored in `description` as `portcullis:<uuid>`.
  - A wanted username whose live account carries another uuid → that account is renamed `former-<old uuid>@portcullis-former.invalid` (aliases cleared, `authenticate` / `emailSend` / `emailReceive` disabled, app passwords destroyed, `former_since` recorded in mailctl state), and a fresh account is created.
  - A live account absent from the document → the same treatment, as a **removal** (M4).
  - A removed person who comes back with the same uuid gets their account renamed back and re-enabled. App passwords are never restored.
  - Former accounts older than `MAIL_FORMER_RETENTION` → destroyed.
  - `postmaster@` and `abuse@` on every domain → a `MailingList` with recipients = the `postmaster` usernames' primary addresses. `dmarc-reports@` and `tls-reports@` → aliases of the `portcullis-mailctl` account. Stalwart analyses reports itself (`DmarcExternalReport`), and mailctl reads them.
  - Lists → `MailingList` (`recipients` = members' primary addresses) + the `list-posters` lookup entries (M10).
  - Quotas → `quotas`. Limits → one `MtaInboundThrottle` per limit, key `authenticatedAs`, `rate` `{count: 300, period: 1h}` and `{count: 1000, period: 1d}`.
  - Removal ops come first; within a removal: destroy app passwords → disable permissions → rename → `InvalidateCaches`.
  - More than 50 % of live accounts removed without `confirm_mass_removal` → `ErrMassRemoval` (409).
- `reconcile.Run(ctx, c *stalwart.Client, st *store.Store)` runs the loop: apply on every new document and every 5 s while errors remain. Removals are retried until done (Fail closed). It updates `applied_generation`.
- `creds.Create(ctx, c, username, label string, expires *time.Time, lan []netip.Prefix) (Created, error)`:
  - refuses at 5 active (`ErrLimit`);
  - `x:AppPassword/set` with the request-level `accountId` of that account, `description` = label (≤ 64, one line), `expiresAt`, `allowedIps` (`0.0.0.0/0`, `::/0`, or the Local networks), `permissions` = `{"@type":"Replace","permissions": MailPasswordPermissions}` (M6);
  - returns `{ID, Secret, CreatedAt, ExpiresAt}`. The secret is in memory once, never logged.
- `creds.List`, `creds.Revoke(ctx, c, username, id) error`. `creds.VoidAll(ctx, c) (int, error)` destroys every AppPassword of every account, and records `restored_at` = now in mailctl's state.
- `var MailPasswordPermissions = []string{…}` (M6's exact list, sorted). `TestMailPasswordPermissionsExact` pins it.
- HTTP: `PUT /v1/state`, `GET /v1/state`, `GET|POST /v1/credentials`, `DELETE /v1/credentials/{id}` (contract §M).
- `mailctl void --reason restore` (stdin: the recovery credentials; Basic auth) → `{"voided":n}`.
- `mailctl export --former <former-id>` streams mbox to stdout (M5). It refuses a non-former account (exit 2) and audits through its log line `export former=<id> messages=<n>` (no content).

- [ ] **Step 1: Write the failing tests** (fake JMAP server):
  - `TestParseRefuses` (one case per Parse rule, table-driven).
  - `TestUUIDChangeMovesToFormer` (Review Focus 5).
  - `TestRemovalRenamesToParkingDomain` (Review Focus 3: the old address unknown in the fake's RCPT lookup, app passwords gone before the rename, `InvalidateCaches` last).
  - `TestRejoinSameUUIDRenamesBack`.
  - `TestMassRemovalRefused`.
  - `TestRemovalRetriedUntilDone` (the fake fails twice).
  - `TestFormerDestroyedAfterRetention` (fake clock).
  - `TestPostmasterToAdmins`.
  - `TestListMembersOnlyLookup`.
  - `TestCreateRefusesSixth`.
  - `TestCreateLanOnlyAllowedIps`.
  - `TestMailPasswordPermissionsExact`.
  - `TestSecretNeverLogged` (capture the logger).
  - `TestVoidAll`.
  - `TestExportRefusesActiveAccount`.
  - `TestExportRestoresDisabledOnError`.
  - `TestStaleGeneration409`.
- [ ] **Step 2:** Run `cd mailctl && go test -race ./...`. Expected: FAIL.
- [ ] **Step 3:** Implement. Add every object and field used to `stalwart.Used`.
- [ ] **Step 4:** Run the mailctl gate, including `TestEveryUsedFieldInSchema`. Expected: PASS.
- [ ] **Step 5:** Commit (`mailctl: desired state v1, uuid-keyed reconcile, parking-domain removals, lists, mail passwords, void, export`).

---

### Task 8: DNS rendering, DKIM / MTA-STS / TLSA / DMARC state machines, well-known files (core)

**Files:**
- Create:
  - `mailctl/internal/dnsset/{dnsset.go,dnsset_test.go}`;
  - `mailctl/internal/dkim/{dkim.go,dkim_test.go}`;
  - `mailctl/internal/mtasts/{mtasts.go,mtasts_test.go}`;
  - `mailctl/internal/tlsa/{tlsa.go,tlsa_test.go}`;
  - `mailctl/internal/dmarc/{dmarc.go,dmarc_test.go}`;
  - `mailctl/internal/wellknown/{wellknown.go,wellknown_test.go}`.
- Modify:
  - `mailctl/internal/api/server.go` (`GET /v1/dns/{domain}`, `POST /v1/actions/*`);
  - `mailctl/main.go` (`dns --main --json`, `rotate --json`, `reload-tls`);
  - `docker-compose.yml` (mailctl's router labels: rule `Host(\`mta-sts.${PORTCULLIS_DOMAIN}\`) || Host(\`autoconfig.${PORTCULLIS_DOMAIN}\`) || Host(\`autodiscover.${PORTCULLIS_DOMAIN}\`)` for the main domain; enrolled domains' hosts come from the Hub's dynamic router `mail-wellknown-<domain>`, Task 14);
  - `scripts/lib/dns.sh` (`--only mail`, `_dns_tool_input` adds `mail` from `dc exec -T mailctl mailctl dns --main --json`).

**Interfaces — Produces:**
- `dnsset.Wanted(d Domain, main Main, st *store.Store, now time.Time) []dnsplan-shaped Record` returns exactly the spec §7 table. For an enrolled domain:
  - the main-host records (`mail.<d>` TXT / CAA, `_25._tcp.mail.<d>` TLSA) are omitted;
  - `CNAME mail.<d>.` at `autoconfig` / `autodiscover` / `mta-sts` when its zone has no wildcard (from the domain's plan: `address` items).

  Also:
  - SPF `v=spf1 mx -all`, plus ` include:<MAIL_RELAY_SPF_INCLUDE>` before `-all` when set;
  - SRV `_submissions._tcp` `0 1 465`, `_imaps._tcp` `0 1 993`, `_submission._tcp` `0 1 587`, `_imap._tcp` / `_pop3._tcp` / `_pop3s._tcp` `0 0 0 .`;
  - DMARC `v=DMARC1; p=<policy>; adkim=s; aspf=s; rua=mailto:dmarc-reports@<e>`;
  - TLS-RPT `v=TLSRPTv1; rua=mailto:tls-reports@<e>`;
  - `_mta-sts` `v=STSv1; id=<policy id>`.

  A domain in `draining` → only `_mta-sts` (new id), and the policy file says `mode: none`. A domain `off` (after draining) → nothing.
- **`dkim` machine** (per domain × {ed25519, rsa}), `Step(now, view Visible) []Action`:
  - `pending` (key created with `stage: pending`, wanted TXT published) → `active` when `view` shows the exact TXT at both resolvers;
  - the previous `active` → `retiring` at the same step;
  - `retiring` → `retired` after 7 days (record dropped);
  - `retired` → key destroyed after 30 days.
  - Rotation is due every `MAIL_DKIM_ROTATE`, or at once on `dkim-rotate`.
  - Keys come from `crypto/ed25519` and `rsa.GenerateKey(rand.Reader, 2048)`, PEM (PKCS#8), sent once in `DkimSignature.privateKey` `Text`, never stored by mailctl.
  - Selector `v1-<ed25519|rsa>-YYYYMMDD`, with `-2`… on a same-day re-rotation.
  - `pending` > 24 h → check `dkim_stuck`.
  - On a lego-only main domain (no writer): `dkim: manual`, one key per algorithm `active` at bootstrap, no rotation, check `dkim_manual` (Info).
- **`mtasts` machine** per domain: `testing` (max_age 86400) → `enforce` (604800) after 7 days with `checks.cert` ok and no TLS-RPT failure in the reports since `testing` began, or at once on `mtasts-enforce` when the same holds. Then:
  - a failure → back to `testing`;
  - `draining` → `none` for 604800 s (or 86400 when it was `testing`), then `off`.
  - Policy `version: STSv1`, `mode`, `mx: <MAIL_HOSTNAME>`, `max_age`. `id` = the first 20 hex characters of sha256(policy text) + `T<unix>`, so it changes with every policy change.
- **`tlsa`**: `Wanted(spki []string, dnssecSecure bool) []Record`:
  - with `secure`, `_25._tcp.<MAIL_HOSTNAME>` `TLSA 3 1 1 <spki>` for the current key plus the next key while a rollover runs;
  - otherwise none (`tlsa: "withheld: dnssec <state>"`).
  - Rollover:
    1. `mail-cert --next-key`;
    2. publish both;
    3. wait 2×TTL + 1 day (`7200 s + 86400 s`);
    4. `--switch-key` at the next issue;
    5. drop the old SPKI after a further 2×TTL.
  - The DNSSEC state comes from the domains plan (`dnssec.state`), passed in by the CLI for the main domain and by the Hub for enrolled ones (the Hub reads the main zone's state from `GET /api/dns/main`).
- **`dmarc`**: `Start(hadMailRecords bool) Policy` gives `reject` or `none`. `Promote(reports []Aggregate, since time.Time, now)` proposes `quarantine` after 14 clean days, then `reject` after 14 more. Clean = no source failing both SPF and DKIM alignment. It applies only on `dmarc-promote`, never by itself.
- **`wellknown.Handler(st)`** on `:8081`, exact paths only, host-checked against the mail-enabled domains, anything else 404:
  - `GET /.well-known/mta-sts.txt` (`text/plain`, `Cache-Control: max-age=300`);
  - `GET /mail/config-v1.1.xml` and `/.well-known/autoconfig/mail/config-v1.1.xml` (Thunderbird autoconfig: IMAP 993 SSL, SMTP 465 SSL, username `%EMAILADDRESS%`, server `MAIL_HOSTNAME`);
  - `POST /autodiscover/autodiscover.xml` (Outlook POX response; the request's `EMailAddress` echoed only if it parses and is on a mail domain).
- `mailctl dns --main --json` → `{"records":[…],"dkim":"auto|manual","tlsa":"…"}` for `PORTCULLIS_DOMAIN`. `mailctl rotate --json` steps the machines and prints the same.

- [ ] **Step 1: Write the failing tests** (fake clock, fake resolver views):
  - `TestWantedMatchesSpecTable` (golden: main and enrolled domain, with and without a wildcard, with relay include).
  - `TestDKIMPendingNeedsBothResolvers`.
  - `TestDKIMRetireAndDelete`.
  - `TestDKIMRotateNow`.
  - `TestDKIMStuck24h`.
  - `TestDKIMManualNoRotation`.
  - `TestMTASTSEnforceAfter7Days`.
  - `TestMTASTSFailureBackToTesting`.
  - `TestMailOffPublishesNoneThenRemoves` (Review Focus 4).
  - `TestPolicyIDChangesWithPolicy`.
  - `TestTLSAOnlyWhenSecure`.
  - `TestTLSARollover` (both published, then the switch after 2×TTL + 1 day).
  - `TestDMARCStart`.
  - `TestDMARCPromote14Days`.
  - `TestWellKnownExactPaths` (`/.well-known/mta-sts.txt.bak` → 404; a non-mail host → 404).
  - `TestAutodiscoverRefusesForeignAddress`.
  - Shell: "dns setup --only mail passes mailctl's records on stdin, never argv".
- [ ] **Step 2:** Run `cd mailctl && go test -race ./...` and `bash tests/test_cli.sh`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the core gate. Expected: PASS.
- [ ] **Step 5:** Commit (`mailctl: mail record set, DKIM/MTA-STS/TLSA/DMARC state machines, mta-sts/autoconfig/autodiscover`).

---

### Task 9: Checks, spam and outbound settings, client-IP mode, metrics (core)

**Files:**
- Create: `mailctl/internal/checks/{checks.go,port25.go,fcrdns.go,blocklist.go,cert.go,selftest.go,reports.go,checks_test.go}`
- Modify:
  - `mailctl/internal/metrics/metrics.go`;
  - `mailctl/internal/bootstrap/baseplan.go` (`DegradedSenderAuth`);
  - `mailctl/internal/reconcile/reconcile.go` (spam / allow / block / dnsbl from the document);
  - `monitoring/prometheus/{prometheus.yml,alerts.yml,tests/alerts_test.yml}`.

**Interfaces — Produces:**
- `checks.Run(ctx, deps Deps) []Check` (`Deps` = resolvers, the local resolver, a dialer, a clock, the Stalwart client, the store). Each check:
  - **`port25`:** never dials anything (no probing of third-party mail servers). It reports from the queue only: when every outbound delivery to port 25 in the last 24 h failed with a connect timeout (Stalwart's delivery events) → Problem with the spec's text and the provider guidance; no delivery attempts yet → Info `mail_port25_unknown`; otherwise ok.
  - **`fcrdns_v4` / `fcrdns_v6`:**
    - PTR of each public address through the public resolvers; the name must resolve back to the address. Missing or mismatched → Problem.
    - The steps per provider: hetzner, DigitalOcean, AWS EC2 (the EIP form), **AWS Lightsail** ("submit the 'Request to remove email sending limitations' form for the static IP with the reverse DNS name"), OVH, and generic.
    - v6 failing → Info `mail_ipv6_ptr` (outbound v4 only).
  - **`blocklist`:** each public address against `zen.spamhaus.org` (or `<key>.zen.dq.spamhaus.net` with a DQS key), `bl.spamcop.net` and `b.barracudacentral.org` through the local resolver.
    - `127.0.0.1x` answers per list.
    - A PBL hit (`127.0.0.10`/`.11`) → "residential range: use a relay".
    - A `127.255.255.x` answer (query refused, public-resolver policy) → Warning "DNSBL refused the query", never ok.
  - **`cert`:** TLS to `mail:10465` / `10993` (implicit) and STARTTLS on `10025` / `10587` from mailctl. SAN = `MAIL_HOSTNAME`, expiry, and with TLSA published the SPKI matches.
  - **`records:<d>`:** comes from the Hub (it owns the plans), not computed here. mailctl reports only the DKIM visibility it already tracks.
  - **`dkim_selftest:<d>`:** sign a fixed test message with each active key (`go-msgauth/dkim`, the same private key read back with `x:DkimSignature/get` — the key never leaves the process) and verify against the live DNS.
  - **`dmarc_reports` / `tlsrpt_reports`:** `x:DmarcExternalReport/query` / `x:TlsExternalReport/query` over the last 7 days. Failures → Warning with the sources.
  - **`client_ip`:** `MAILCTL_CLIENT_IP=rewritten` → Warning.
  - **`rate_held:<u>`:** queue entries held by the throttle → Warning.
  - **`auth_failures:<u>`:** ≥ 20 failed logins in 24 h for one account → Info.

  The run happens every 6 h and on `?refresh=1` (one at a time; a refresh within 60 s returns the last result).
- `bootstrap.DegradedSenderAuth()` (M9, Review Focus 1):
  - `spfEhloVerify`, `spfFromVerify` and `reverseIpVerify` → `disable`;
  - `dmarcVerify` `relaxed` with the reject action off (DKIM alignment still evaluated, never a rejection on DMARC);
  - the DNSBL IP lists off (domain / URL lists stay);
  - `AllowedIp` for the gateway.
- Metrics on `MAILCTL_METRICS_ADDR`: `portcullis_mail_check{check}` 0/1, `portcullis_mail_dkim_stage{domain,stage}`, `portcullis_mail_cert_expiry_seconds`, `portcullis_mail_queue_messages`, `portcullis_mail_queue_deferred_ratio`.
- Prometheus jobs:
  - `mail`: `mail-metrics:9180/metrics/prometheus`, basic auth `prometheus` + `password_file: /etc/prometheus/secrets/prometheus-mail`;
  - `mailctl`: `mailctl-metrics:9100`.

  Both only with the profile: a file_sd `monitoring/targets/mail.json` written by `mail enable` / `up`, empty otherwise (the `wg` pattern, `vpn_prom_targets`).
- Alerts (spec §9):
  - `MailQueueHigh` (`portcullis_mail_queue_messages > 100` for 30m);
  - `MailDeferralsHigh` (> 0.2 for 1h);
  - `MailCertExpiring` (< 14 d);
  - `MailBlocklisted` (`portcullis_mail_check{check="blocklist"} == 0`);
  - `MailDKIMStuck` (`portcullis_mail_check{check=~"dkim_stuck.*"} == 0`);
  - `MailCheckFailing` (any check 0 for 1h).

- [ ] **Step 1: Write the failing tests:**
  - `TestPort25AllTimeout` (a dialer that blocks).
  - `TestFCrDNSMismatch`.
  - `TestFCrDNSLightsailSteps`.
  - `TestBlocklistPBL`.
  - `TestBlocklistRefusedIsWarning`.
  - `TestCertTLSAMismatch`.
  - `TestSelftestFailsOnWrongDNSKey`.
  - `TestClientIPRewrittenPlanDisablesIPChecks` (Review Focus 1: the degraded plan values exact).
  - `TestRefreshCoalesced`.
  - Promtool tests for the six alerts in `alerts_test.yml` (with `exp_annotations`, samples every ≤ 5m).
- [ ] **Step 2:** Run the mailctl gate and `promtool test rules monitoring/prometheus/tests/alerts_test.yml`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the gates plus `promtool check config --syntax-only` and `promtool check rules`. Expected: PASS.
- [ ] **Step 5:** Commit (`mailctl: deliverability checks, degraded mode for rewritten client IPs, metrics; prometheus jobs and alerts`).

---

### Task 10: CLI integration — status, test, dkim, export, backup / restore, Podman, IPv6 (core)

**Files:**
- Modify:
  - `scripts/lib/mail.sh`;
  - `scripts/lib/status.sh` (`_st_mail_lines`, `--json` `mail`);
  - `scripts/lib/backup.sh` (`BACKUP_FILE_VOLUMES` += `mailctl_data:10010:10010`; `_backup_mail_data`; restore M7);
  - `scripts/lib/common.sh` (`HUB_ENV_VARS` += the five `PORTCULLIS_MAIL*`);
  - `scripts/lib/runtime.sh` (`mail_client_ip_mode`);
  - `scripts/lib/stack.sh`;
  - `tests/test_cli.sh`, `tests/test_shell_libs.sh`, `CLAUDE.md`, `CHANGELOG.md`.

**Interfaces — Produces:**
- `mail_status [--json]`:
  - services healthy;
  - certificate `not_after` / SANs;
  - DKIM stages, MTA-STS / DMARC per domain;
  - the queue;
  - the checks (from `GET /v1/status` and `/v1/checks` via `dc exec -T mailctl mailctl status --json`);
  - `portcullis-mail.timer` active (missing → Warning, spec §4);
  - client-IP mode.

  `status` prints a "Mail" block with the same `_st_line` vocabulary, and `--json` adds `mail: {…}` (absent with the profile off).
- `mail test --to <addr>` → `mailctl test --to` sends a signed message as `postmaster@<primary>` and prints the queue id and how to read `Authentication-Results`.
- `mail dkim rotate <domain>` → `POST /v1/actions/dkim-rotate` through `mailctl` exec. `mail cert` → `mail_cert_ensure` + reload. `mail export <former-id> [--out FILE]` → an mbox at `backups/mail-export/<former-id>-<ts>.mbox` (0600), streamed from `mailctl export`.
- `mail_client_ip_mode`: `rewritten` under podman, `preserved` under docker. It is written as `MAILCTL_CLIENT_IP` into the compose environment through `.env` `MAILCTL_CLIENT_IP` (set by `mail enable` / `up`, never by hand).
- IPv6: with `MAIL_IPV6=on`, `mail_ipv6_override` writes `secrets/mail/ipv6.override.yml` with the four `[::]` port lines and adds it to `COMPOSE_FILE` in `runtime_export`. It refuses unless `docker info` shows `ip6tables: true`, or the runtime is podman, where it is refused outright ("rootless Podman rewrites IPv6 client addresses").
- Backup (M11), `_backup_mail_data`:
  1. `trap 'dc start mail' RETURN`;
  2. `dc stop mail`;
  3. archive `mail_data` and `mail_etc` with `_backup_volume_tar` (as 2000:2000, at `/vol`);
  4. `dc start mail`.

  Added to `backup_create` only with the profile on. `mail_acme` and `mail_tls` are archived online (plain files).
- Restore (M7): after the volume restore, when the backup has `mail_data`:
  1. `mail_recovery_session mail_void_restore` (`mailctl void --reason restore` with the recovery credentials on stdin);
  2. if that fails: `dc stop mail`, then fail `mail passwords could not be voided: mail stays stopped (./portcullis mail enable to retry)`;
  3. otherwise the normal start. The Hub's metadata follows (Task 15).
- Podman host check row: with `mail` in `COMPOSE_PROFILES`, `ip_unprivileged_port_start ≤ 25`, else fail with `sysctl net.ipv4.ip_unprivileged_port_start=25 (mail publishes ports 25, 465, 587)`.

- [ ] **Step 1: Write the failing tests** (`test_cli.sh`, stub docker):
  - "status --json has mail only with the profile";
  - "mail timer missing → status warning line";
  - "backup stops and restarts mail even when the archive fails" (stub fails tar);
  - "restore voids before the normal start and leaves mail stopped on failure";
  - "MAIL_IPV6=on refused without ip6tables";
  - "MAIL_IPV6=on refused on podman";
  - "export writes 0600 under backups/mail-export";
  - "HUB core.env has PORTCULLIS_MAIL=on only with the api key non-empty";
  - "podman + mail profile + port start 80 → up refused".
- [ ] **Step 2:** Run `bash tests/test_cli.sh && bash tests/test_shell_libs.sh`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the core gate. Expected: PASS.
- [ ] **Step 5:** Commit (`mail: status, test, dkim rotate, export, backup (mail stopped for the copy), restore voiding in recovery mode, podman and IPv6 rules`).

---

### Task 11: Core CI — build-and-test "Test the mail service" (core)

**Files:**
- Create: `.github/ci/build-and-test-mail-service.sh`, `tests/e2e/mail/unbound-ci.conf`
- Modify: `.github/workflows/ci.yml` (build-and-test: one step; the CI override's `mail-cert` gets Pebble's root as `LEGO_CA_CERTIFICATES` and the fake DNS, as `dns-tool`), `docs` pointer none

**Interfaces:** consumes Tasks 3–10.

The step runs after the domains step, on Docker, with `COMPOSE_PROFILES` += `mail`, `MAIL_HOSTNAME=mail.ci.example.org`, Pebble and the fake DNS. The resolver gets `tests/e2e/mail/unbound-ci.conf` (stub zone `ci.example.org.` and `test.` → the fake DNS, `domain-insecure` for both). It asserts:
1. `./portcullis mail enable --yes` exit 0.
   - mail healthy as 2000:2000, caps per M8, read-only.
   - mailctl as 10010 with group 10001 only; resolver healthy.
2. No `recovery.env`. The recovery login is refused (401 through `mailctl bootstrap --verify-gone`).
   - `secrets/mail/api-key` 0640 group 10010.
   - The key's `allowedIps` refuse it from another `portcullis-mail` address (a throwaway container at `.9`).
3. The 8080 listener:
   - from a container on `portcullis-proxy` it is unreachable (no route);
   - from `.9` on `portcullis-mail`, `GET /jmap` → 404 (M12);
   - `/admin` → 404 from mailctl too.
4. Certificate:
   - `fullchain.pem` SAN exactly `mail.ci.example.org`;
   - the CAA at `mail.ci.example.org` names the mail-cert account;
   - a second `mail cert` keeps the SPKI;
   - STARTTLS on host `:25` / `:587` and TLS on `:465` / `:993` present it.
5. Open relay (the spec §9 item 2):
   - unauthenticated `RCPT TO:<x@foreign.test>` on 25 → `550 5.7.1`;
   - `AUTH` not offered on 25;
   - with a real account and mail password: a foreign `MAIL FROM` → refused, and a foreign `From:` header → refused at DATA (`mustMatchSender`, plus the From check Task 2 pinned);
   - a connection from the bridge gateway (`docker exec` into a container on `mail-egress` dialling 25) doesn't relay.
6. `status --json | jq .mail` has bootstrap true, the cert, the timer warning. `mail schedule --systemd` (CI has systemd) clears it.
7. `backup` → `mail` was stopped and restarted (container StartedAt changed), and `backup verify` passes.
8. After the job's restore: an app password created before the backup fails IMAP login (voided); `mail` healthy; `mailctl_data` restored (the DKIM stage file equal).

- [ ] **Step 1:** Write the script against the current branch. Run `gh workflow run ci.yml --ref mail1 -f jobs=build-and-test`. Expected: FAIL at the first assertion not yet implemented (or green if Tasks 3–10 are complete).
- [ ] **Step 2:** Fix what the run shows (in the owning task's files, with a test there first).
- [ ] **Step 3:** Run again. Expected: PASS. `bash tests/lint_ci_size.sh` passes.
- [ ] **Step 4:** Commit (`ci: test the mail service (bootstrap, recovery gone, isolation, certificate, open relay, backup/restore voiding)`).

---

### Task 12: Core CI — job `e2e-mail` (core)

**Files:**
- Create:
  - `tests/e2e/e2e_mail.py`;
  - `tests/e2e/mail/remote/plan.json` (the remote Stalwart's minimal setup: one domain `remote.test`, one account, DKIM Ed25519, applied by `e2e_mail.py` over its JMAP with a recovery admin);
  - `tests/e2e/mail/coredns/Corefile`;
  - `.github/ci/e2e-mail-start-stack.sh`, `.github/ci/e2e-mail-remote.sh`.
- Modify: `.github/workflows/ci.yml` (job `e2e-mail`, 60 min, `needs: jobs-input`, the Hub from the same-named Hub branch via `.github/actions/hub-image`, Keycloak via `.github/actions/keycloak-image`; the description list), the e2e-podman job (one step).

**Interfaces:** consumes everything above plus Hub Tasks 13–15 (same-named Hub branch).

The setup:
- the whole stack + Hub + domains (fake provider, Pebble) with the enrolled `team-b.test`;
- a CoreDNS container serving `ci.example.org`, `team-b.test` and `remote.test` from the fake provider's zone file export;
- a second Stalwart `remote` (the same pin, plain config, `remote.test`) on a CI network with a route to the host's published ports.

People `alice`, `bob` (`mail_users`), `carol` (not), `root` (`lldap_admin`). `team-b.test` mail is on with `mail_users`. `e2e_mail.py` checks:
1. `exchange_both_ways`: portcullis → remote and remote → portcullis. `Authentication-Results` at the remote shows `dkim=pass` for both `ed25519-sha256` and `rsa-sha256`, `spf=pass` and `dmarc=pass`. The remote's DMARC aggregate report (forced with its report task) arrives at `dmarc-reports@` and appears in `GET /api/mail/checks`.
2. `enrolled_domain_alias`: bob receives at `bob@team-b.test` and sends as it.
3. `gtube_rejected_at_data` (`550 5.7.1`); `between_thresholds_to_junk` (a message crafted with the vendored rules' known tags scoring 5–15 → bob's Junk, with `X-Spam-*`).
4. `mail_password_flow` (Playwright, CDP virtual authenticator, the fresh-auth popup as e2e-filesharing):
   - alice creates "e2e laptop" → the password is shown once, absent from the page, storage and every API after the dialog;
   - it works with `imaplib` on 993 and `smtplib` on 465 and 587;
   - alice's LLDAP password fails IMAP;
   - the mail password fails Basic auth on the management listener (M6), from a container on `portcullis-mail`, and fails Portcullis sign-in;
   - a sixth password → 409.
5. `revoke_within_8s` (Fail closed): an IMAP session `NOOP`-polled fails within 8 s of the revoke.
6. `leave_ends_idle_session` (Review Focus 3): bob is removed from `mail_users` through the Hub API while IDLE → the session fails within 8 s, and RCPT to `bob@ci.example.org` from remote gets `550 5.1.1` at RCPT.
7. `recreated_username_fresh_mailbox` (Review Focus 5): delete bob in LLDAP and create bob again, add him to `mail_users` → INBOX empty, the old mail passwords fail, and `former-<uuid>` is listed in `GET /api/mail/status`.
8. `members_only_list`: the `team` list members-only → remote sender `550 5.7.1`, alice (authenticated) delivered to bob.
9. `postmaster_to_admins`: mail to `postmaster@ci.example.org` reaches root.
10. `restore_voids_mail_passwords`: run in the job's backup/restore phase. The metadata rows show `void_restore`, and the people page shows "reset by a restore".

e2e-podman gets one step, "mail on rootless Podman":
- set `ip_unprivileged_port_start=25`, then `mail enable`;
- `MAILCTL_CLIENT_IP=rewritten`;
- doctor `mail_client_ip_rewritten`;
- a message from a CI container to host port 25 is delivered and no `BlockedIp` appears (Review Focus 1).

- [ ] **Step 1:** Write `e2e_mail.py` and the job. Run `gh workflow run ci.yml --ref mail1 -f jobs=e2e-mail`. Expected: FAIL first on whatever isn't done.
- [ ] **Step 2:** Fix in the owning task's files, test first.
- [ ] **Step 3:** Run `-f jobs=e2e-mail,e2e-podman`. Expected: PASS. `bash tests/lint_ci_size.sh` passes.
- [ ] **Step 4:** Commit (`ci: e2e-mail (two-server exchange, spam, mail passwords, revocation timing, re-created usernames, lists)`).

---

### Task 13: Hub — mailctl client, state, core.env, reserved labels and ports (Hub)

**Files:**
- Create: `internal/mailctl/{client.go,types.go,client_test.go}`, `internal/state/mail.go`
- Modify:
  - `internal/state/state.go` (`Mail MailSettings` `yaml:"mail,omitempty"`, `MailCredentials map[string][]MailCredential` `yaml:"mail_credentials,omitempty"`);
  - `internal/hub/hosts.go` (`checkInstanceHostsLocked`: the reserved mail labels);
  - `internal/hub/domains.go` (`domainNameProblem` unchanged; enrolled-domain mail flags);
  - `internal/hub/ports.go` `checkPortCollisionsLocked` (refuse host ports 25 / 465 / 587 / 993 while `PORTCULLIS_MAIL=on`);
  - `internal/templates/coreref.go` (Task 1 §3 names);
  - `cmd/hub/main.go` (`HUB_MAILCTL_API_URL` default `http://mailctl:8080`, `HUB_MAILCTL_SECRET_FILE` default `/run/portcullis/mail/hub-secret`).

**Interfaces — Produces:**
- `mailctl.Client`: `New(url, secretFile string) *Client`, with `Available() error`, `PutState(ctx, *MailState) (int, error)`, `State(ctx) (StateStatus, error)`, `DNS(ctx, domain string) (DNSSet, error)`, `Checks(ctx, refresh bool) (Checks, error)`, `Status(ctx) (Status, error)`, `Credentials(ctx, user string) ([]Credential, error)`, `CreateCredential(ctx, user, label string, expires *time.Time) (Created, error)`, `RevokeCredential(ctx, user, id string) error`, `Action(ctx, name, domain string) error`. Errors are `*APIError{Status, Msg}` with secrets redacted (the domains client's `redact`). The types mirror contract §M exactly; `TestTypesMatchContractVector` decodes `testdata/mailstate_v1.json`, a byte copy of the contract's example, which core's `mailctl/internal/state/testdata/` also holds.
- State:

  ```go
  type MailSettings struct {
      PrimaryDomain string                    `yaml:"primary_domain,omitempty"`
      Domains       map[string]MailDomain     `yaml:"domains,omitempty"` // name → on/off, groups
      Aliases       map[string][]string       `yaml:"aliases,omitempty"` // username → addresses
      Lists         map[string]MailList       `yaml:"lists,omitempty"`   // group → {domain, posting}
      Quotas        []MailQuotaRow            `yaml:"quotas,omitempty"`  // {group, bytes}
      Spam          MailSpam                  `yaml:"spam"`
      Limits        MailLimits                `yaml:"limits"`
      Generation    int                       `yaml:"generation"`
  }
  type MailDomain struct { Enabled bool; Draining bool; Groups []string; HadMailRecords bool }
  type MailCredential struct {
      ID, StalwartID, Label, UUID, CreatedBy, RevokedBy, Reason string
      CreatedAt time.Time; ExpiresAt, RevokedAt *time.Time
  }
  ```

  Reasons are `revoked`, `revoke_leave`, `void_restore`, `expired` (the same `CredentialReason*` naming as `state.Credential`).
- `mailReservedLabels = []string{"mail","mta-sts","autoconfig","autodiscover"}`. `(h *Hub) mailReservedLocked(host string) string` returns the 409 text of Task 1 §5 or "", and is checked in `checkInstanceHostsLocked` after the core-host checks.

- [ ] **Step 1: Write the failing tests:**
  - `TestClientRedactsSecret`.
  - `TestClientRefusesWithoutSecretFile`.
  - `TestTypesMatchContractVector`.
  - `TestInstanceHostReservedForMail` (`mail.team-b.test` refused when team-b has mail on; allowed when off).
  - `TestPortCollisionWithMail`.
  - `TestCoreNamesIncludeMail`.
- [ ] **Step 2:** Run `go test -race ./internal/mailctl/... ./internal/hub/... ./internal/templates/...`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the Hub gate. Expected: PASS.
- [ ] **Step 5:** Commit (`hub: mailctl client, mail state, reserved mail labels and ports`).

---

### Task 14: Hub — desired state, sync, enrolled-domain DNS, restart fallback (Hub)

**Files:**
- Create: `internal/hub/mail.go`, `internal/hub/mail_state.go`, `internal/hub/mail_dns.go`, `internal/hub/mail_restart.go` (+ tests)
- Modify: `internal/hub/revoke.go` (the holder-check triggers also call `TriggerMailSync`), `internal/hub/hub.go` (`RunMailSync` goroutine), `cmd/hub/main.go`, the dynamic Traefik file (`mail-wellknown-<domain>` routers for enrolled mail domains)

**Interfaces:**
- Consumes: `mailctl.Client` (Task 13), `h.membership(ctx) (*directory.Membership, error)`, `domains.Client.ApplySets` / a new `domains.Client.SetMailSet(ctx, name string, recs []MailRecord) error` and `DeleteMailSet`, and `settings.Registry.Resolve` for the quota.
- Produces:
  - `func BuildMailState(m *directory.Membership, st state.MailSettings, mainDomain string, quotaRes func(user string) int64) (*mailctl.MailState, error)`, pure:
    - accounts = members of `mail_users` (expanded; the Hub's service account and `admin` excluded);
    - addresses = `<username>@<primary>` plus `<username>@<e>` for each enrolled domain whose `groups` the person is in;
    - aliases;
    - lists = groups with `Lists[g]`, members = the group's `mail_users` members;
    - `postmaster` = `lldap_admin` members;
    - `local_networks` = the Hub's Local networks;
    - `uuid` = `m.UUIDs[user]`. A person without a uuid is left out, logged once, never sent with an empty uuid.
  - `(h *Hub) TriggerMailSync()` and `RunMailSync(ctx)`:
    - a removal (any account, address or list member gone vs the last sent document) is sent at once;
    - additions wait 60 s (`mailDebounce`);
    - a directory error sends nothing;
    - `confirm_mass_removal` only when the shrink came from Hub-made removals of `mail_users` members in this run (the directory OnChange records them);
    - the generation is `state.Mail.Generation + 1`, persisted before the PUT.
  - Revocation timing (M3):
    1. After a removal is accepted (202), `RunMailSync` polls `GET /v1/state` until `applied_generation` ≥ the sent one (≤ 4 s).
    2. If Task 2 recorded surviving sessions, it then calls `restartCoreMail(ctx)`. Total ≤ 8 s.
    3. A timeout also restarts. A failed restart is logged, op record `mail_restart`, and the doctor shows `mail_rate_held`-style Warning "mail sessions may still be open".
  - `(h *Hub) restartCoreMail(ctx) error` lists containers with labels `com.docker.compose.project=portcullis` and `com.docker.compose.service=mail` through the guarded engine client (rootless plan Task 2, or kube's `internal/runtime` docker backend if merged). It restarts exactly one, refuses anything else (0 or > 1 matches → error), and never under kubernetes.
  - `(h *Hub) syncMailDNS(ctx)`: for each enrolled domain with mail on, draining or just turned off:
    - `mailctl.DNS(domain)` → `SetMailSet`;
    - a domain whose mailctl state reached `off` → `DeleteMailSet`;
    - the main domain is not written by the Hub (CLI path), only read for the panel.
  - Runs after every accepted state and every 6 h.
  - Enrolled mail domains get a dynamic router `mail-wellknown-<domain>`: rule `Host(mta-sts.<e>) || Host(autoconfig.<e>) || Host(autodiscover.<e>)`, service `mailctl@docker`, the domain's TLS tier, middlewares `rate-limit@file,security-headers@file`.

- [ ] **Step 1: Write the failing tests:**
  - `TestBuildMailStateAddresses`.
  - `TestBuildMailStateSkipsNoUUID`.
  - `TestBuildMailStatePostmasterAdmins`.
  - `TestRemovalSentImmediately` / `TestAdditionDebounced60s` (fake clock).
  - `TestDirectoryErrorSendsNothing`.
  - `TestMassRemovalFlagOnlyForHubRemovals`.
  - `TestMailRestartOnlyTargetsCoreMail` (two candidates → refused; an app container labelled `service=mail` in another project → ignored).
  - `TestRestartWhenApplyTimesOut`.
  - `TestSyncMailDNSSetsAndDeletes`.
  - `TestWellKnownRouterPerEnrolledDomain`.
- [ ] **Step 2:** Run `go test -race ./internal/hub/...`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the Hub gate. Expected: PASS.
- [ ] **Step 5:** Commit (`hub: mail desired state and sync (removals at once, additions debounced), enrolled-domain mail sets, well-known routers, mail restart fallback`).

---

### Task 15: Hub — mail passwords (people Sign-in page, admin list and revoke) (Hub)

**Files:**
- Create: `internal/hub/mail_creds.go`, `internal/httpapi/mail_people.go` (+ tests)
- Modify:
  - `internal/hub/freshauth.go` (`govDefault()`: `freshGov{def: true}` resolves to `h.st.SignIn.Default`, never a core key; `governingLocked` handles it);
  - `internal/httpapi/server.go` (people listener routes);
  - `web/mysignin.html`, `web/mysignin.js` (section "Mail passwords");
  - `internal/httpapi/mcp_parity_test.go` (the people routes in `noToolRoutes`, reason "credentials: never through MCP").

**Interfaces — Produces:**
- `(h *Hub) CreateMailPassword(ctx, user, label, expiry string, p freshauth.Proof) (*CreatedMailPassword, error)`. The order of checks and actions, as `createCredential`:
  1. the caller's entry limit (`entryLimit`);
  2. `PORTCULLIS_MAIL=on` and mailctl `bootstrap` (else 503);
  3. the caller in `mail_users` (else the shared 404);
  4. label one line 1–64; expiry `none|90d|1y` (else 400);
  5. < 5 active (409 "at most 5 mail passwords: revoke one first");
  6. LLDAP uuid read (503 on failure);
  7. `checkFreshAuth(ctx, govDefault(), p, user)` (403);
  8. `mailctl.CreateCredential`;
  9. metadata append, audit `mail_credential.create` (`id`, label length, never the secret).
- `CreatedMailPassword{ID, Password string; MobileConfig []byte}`. `MobileConfig` is an unsigned Apple configuration profile: `com.apple.mail.managed` with `EmailAccountType=EmailTypeIMAP`, `IncomingMailServerHostName=MAIL_HOSTNAME`, port 993 SSL, `OutgoingMailServerHostName`, port 465 SSL, username = primary address, `IncomingPassword` / `OutgoingPassword` = the password. It is built in memory with `howett.net/plist` (or the Hub's existing plist dependency, if any). The caller zeroes both after writing the one answer.
- `(h *Hub) RevokeOwnMailPassword(ctx, user, id string) error`, `(h *Hub) AdminRevokeMailPassword(ctx, user, id string, actor directory.Actor) error`, `(h *Hub) MailPasswords(user string) []MailPasswordView` (label, created, expiry, last used, never a secret).
- The holder check (Task 14's removal path) marks the person's rows `revoke_leave` after mailctl applied the removal. The audit is `mail_credential.revoke_leave`.
- Reconcile on every `GET /v1/credentials` per person, and at start for everyone:
  - an active row with no Stalwart object → `void_restore` when mailctl's `GET /v1/status` reports a restore since the row was created (`restored_at`), else `revoked` (reason `missing`, logged);
  - expired rows → `expired`.
- Routes per Task 1 §5.1. The POST answer carries `Cache-Control: no-store`, and `mobileconfig_b64` is the profile base64-encoded.
- UI (`mysignin.js`): the list, Create (label, expiry), the shown-once dialog with the password, the manual settings, the `.mobileconfig` download (a Blob URL revoked on close) and Revoke. "reset by a restore" is shown for `void_restore` rows.

- [ ] **Step 1: Write the failing tests:**
  - `TestCreateMailPasswordOrder` (each refusal in order, the proof not consumed before step 7).
  - `TestCreateRequiresMailUsers` (404, the same body as unknown).
  - `TestCreateWhileMailOff503`.
  - `TestMobileConfigFields`.
  - `TestSecretNotInAuditOrState` (grep the audit log and state.yaml for the password).
  - `TestAdminCannotCreate` (no admin route exists: `TestNoAdminCreateRoute`).
  - `TestRevokeLeaveMarksRows`.
  - `TestReconcileVoidRestore`.
  - `TestNoStoreHeader`.
  - Web: `web_test.go` asserts the section exists and the dialog clears the field on close.
- [ ] **Step 2:** Run the Hub tests. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the Hub gate. Expected: PASS.
- [ ] **Step 5:** Commit (`hub: mail passwords (fresh auth under the default template, shown once, .mobileconfig, admin revoke, leave/restore voiding)`).

---

### Task 16: Hub — Settings → Mail, person and group Mail sections, DNS panel (Hub)

**Files:**
- Create: `internal/httpapi/mail.go`, `web/mail.js` (+ tests)
- Modify: `internal/httpapi/server.go`, `web/index.html` (Settings → Mail), `web/settings.js`, `web/directory.js` (person page Mail: addresses, aliases editor, password count + revoke; group page: "Make this group a list"), `web/dns.js` (the `mail` set in the DNS panel for the main and enrolled domains), `internal/hub/mail.go` (setters)

**Interfaces — Produces:**
- `(h *Hub) SetMailSettings(ctx, in MailSettingsInput, actor) error`. Validation:
  - the primary domain is the main domain or an enrolled `Assignable` domain;
  - spam scores `1 ≤ junk < reject ≤ 100`;
  - limits 1–100000;
  - allow / block entries are a domain or an address;
  - quota rows: an existing group and 0 < bytes ≤ 1 TiB, default 10 GiB.

  Audited `mail.settings`, then `TriggerMailSync`.
- `(h *Hub) SetMailDomain(ctx, name string, enabled bool, groups []string, actor) error`:
  - turning on records `HadMailRecords` from the domain's plan (an MX or SPF before Portcullis) for `dmarc_start`;
  - turning off sets `Draining` (Review Focus 4);
  - the UI warns "turning mail off removes the MX after the MTA-STS max_age (up to 7 days); mail sent meanwhile is still received".
- `(h *Hub) SetUserAliases(ctx, user string, addrs []string, actor) error` (M15: 409 naming the owner) and `(h *Hub) SetGroupList(ctx, group string, enabled bool, domain, posting string, actor) error` (posting `members|anyone`).
- The host control socket (the VPN plan's `/tmp/hub-host.sock`, `internal/httpapi/hostctl.go`, no HTTP route on any listener) gains `mail drain` (sets every mail domain `Draining`, audited `mail.domain` with actor `host`) and `mail domains` (`[{name, state: on|draining|off}]`). `cmd/hub` gets `hub mail drain|domains` as its clients; `mail disable` (Task 6) polls `hub mail domains` until every one is `off`. Test: `TestHostMailDrain`.
- Settings → Mail shows:
  - on / off per domain + groups;
  - the primary domain;
  - relay status read-only (`PORTCULLIS_MAIL_RELAY`);
  - spam, limits, quotas;
  - former retention read-only (`.env`);
  - the DQS line (M14);
  - on kubernetes, the refusal text;
  - with `PORTCULLIS_MAIL=off`: "Mail is off: run ./portcullis mail enable on the host".

- [ ] **Step 1: Write the failing tests:**
  - `TestSetMailSettingsValidation` (table).
  - `TestSetMailDomainOffDrains`.
  - `TestAliasConflict409`.
  - `TestGroupListPosting`.
  - `TestMailRoutesAdminOnly` (a `manage_signin` holder gets only the password list / revoke).
  - `TestMailRoutesMCPParity` (every admin route has a tool twin or a `noToolRoutes` reason).
  - web tests for the new sections.
- [ ] **Step 2:** Run the Hub tests. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the Hub gate. Expected: PASS.
- [ ] **Step 5:** Commit (`hub: Settings → Mail, person aliases and mail section, group lists, mail set in the DNS panel`).

---

### Task 17: Hub — doctor kinds, fixes and the `mail_status` MCP tool (Hub)

**Files:**
- Create: `internal/doctor/mail.go`, `internal/doctor/mail_test.go`, `internal/hub/doctor_mail.go`, `internal/httpapi/mcptools_mail.go` (+ tests)
- Modify: `internal/doctor/dns.go` (`DNSFixSets` maps `mail_records_wrong` → `[mail]`), the doctor kind registry tests, `internal/httpapi/mcp_parity_test.go`

**Interfaces — Produces** (kinds, severities, fixes, from mailctl `GET /v1/checks` / `/v1/status` and the domains plans):
- `mail_port25_blocked` (Problem, explain);
- `mail_ptr_missing` / `mail_ptr_mismatch` (Problem, explain with the provider steps, Lightsail included);
- `mail_blocklisted` (Problem, explain);
- `mail_records_wrong` (Problem; enrolled domain: fix `dns_apply` sets `[mail]`; main domain: explain `./portcullis dns setup --only mail`);
- `mail_dkim_stuck` (Warning);
- `mail_dkim_manual` (Info);
- `mail_cert_expiring` (Warning < 14 d, Problem < 3 d or expired);
- `mail_dmarc_failures` (Warning);
- `mail_dmarc_promote` (Info, fix `mail_dmarc_promote`, confirm);
- `mail_mtasts_enforce` (Info, fix `mail_mtasts_enforce`, confirm);
- `mail_ipv6_ptr` (Info);
- `mail_client_ip_rewritten` (Warning);
- `mail_rate_held` (Warning);
- `mail_timer_missing` (Warning, when mailctl's status `timer_seen_at` is older than 36 h; `mail rotate` updates it through `mailctl rotate`).

When mailctl is unreachable with `PORTCULLIS_MAIL=on`, no new kind is invented: the doctor shows its existing partial-scan line (the `dnsPartial` pattern) naming mailctl. `mail_status` MCP tool: Class R, twin `GET /api/mail/status`, no arguments, no credential data. No mail credential tool exists (parity test reason).

- [ ] **Step 1: Write the failing tests:**
  - one per kind from a fixture checks document (`TestMailKinds`, table);
  - `TestMailRecordsWrongFixSets`;
  - `TestDmarcPromoteFixConfirms`;
  - `TestTimerMissingAfter36h`;
  - `TestMailStatusToolTwin`;
  - `TestNoMailCredentialTool`.
- [ ] **Step 2:** Run the Hub tests. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the Hub gate. Expected: PASS.
- [ ] **Step 5:** Commit (`hub: 14 mail doctor kinds, mail fixes, mail_status MCP tool`).

---

### Task 18: Templates — reserved mail names (templates)

**Files:**
- Modify: `tests/validate.py` (`CORE_SERVICES`, `CORE_VOLUMES`, `CORE_NETWORKS`, `CORE_ALIASES`, `CORE_TRAEFIK_NAMES` routers `mail-wellknown` and services `mailctl`, all per Task 1 §3), `tests/test_validate.py`, `CLAUDE.md`

- [ ] **Step 1:** Write the failing tests:
  - "a service named mailctl → refused";
  - "a volume mail_data → refused";
  - "network portcullis-mail → refused";
  - "router mail-wellknown → refused";
  - "alias mailctl-metrics → refused".
- [ ] **Step 2:** Run `python3 tests/test_validate.py`. Expected: FAIL.
- [ ] **Step 3:** Add the names (the same sets as the Hub's `coreref.go`, Task 13). `TestCoreNamesComplete` in the Hub compares them.
- [ ] **Step 4:** Run the templates gate. Expected: PASS (no shipped template uses them).
- [ ] **Step 5:** Commit (`validate: reserve the mail core names`).

---

### Task 19: Docs pages (docs)

**Files:**
- Create: `docs/setup/mail.md`, `docs/operations/mail.md`
- Modify: `docs/setup/.nav.yml`, `docs/operations/.nav.yml`, `docs/setup/dns.md`, `docs/operations/{hardening.md,backups.md,monitoring.md,cli.md,testing.md,hub.md,rootless-podman.md}`, `includes/abbreviations.md`

Content (each page in the site's existing voice):
- **`setup/mail.md`:**
  - Prerequisites: a static public IPv4; outbound and inbound 25; PTR; a DNS provider Portcullis can write. A per-provider table:
    - AWS Lightsail: port 25 + rDNS through the "Request to remove email sending limitations" form, a static IP, no IPv6 rDNS;
    - EC2;
    - hetzner;
    - DigitalOcean;
    - OVH;
    - home ISPs (use a relay; inbound still needs 25).
  - `mail enable`; DNS (`dns setup --only mail` for the main domain, Settings → Mail for enrolled ones); clients (autoconfig, the `.mobileconfig`, the manual settings); relay keys; Podman's sysctl and degraded mode; IPv6; "not on Kubernetes yet".
- **`operations/mail.md`:**
  - spam (thresholds, Junk training, allow / block, DQS);
  - DKIM rotation and `dkim rotate`;
  - MTA-STS and DMARC promotion;
  - TLSA and the rollover;
  - backups (mail stops for the copy, M11) and restores (mail passwords voided);
  - former mailboxes and `mail export`;
  - reading `Authentication-Results`, `mail test`, and a manual external tester;
  - troubleshooting per doctor kind.
- **`hardening.md`:** rows for `mail` (2000:2000, read-only, M8's capability line, the four ports, the access rule and its fail-open caveat), `mailctl` (10010, the API key's role and `allowedIps`, no engine, the M5 export exception) and `mail-resolver`.
- **`backups.md`:** the M11 exception and the M7 restore order. **`monitoring.md`:** the two jobs and six alerts. **`cli.md`:** every `mail` subcommand. **`testing.md`:** the build-and-test step, `e2e-mail`, the e2e-podman step.
- **`hub.md`:** Settings → Mail, the person and group sections, and the people Sign-in page's "Mail passwords" (what a person sees, at most 5, shown once).
- **`dns.md`:** the `mail` set table. **`rootless-podman.md`:** the port-25 sysctl and degraded mode.

- [ ] **Step 1:** Write the pages.
- [ ] **Step 2:** Run the docs gate. Expected: exit 0.
- [ ] **Step 3:** Commit (`docs: mail setup and operations, hardening/backups/monitoring/cli/testing/hub/dns/podman updates`), push, and resync the Hub `web/docs` (Global Constraints).

---

### Task 20: Full CI, merges, the test-server deploy and the live check, cleanup (all repos)

- [ ] **Step 1:** Full runs, all green:
  - core `gh workflow run ci.yml --ref mail1` (all jobs);
  - Hub `build.yml --ref mail1`;
  - templates lint;
  - the docs build.
- [ ] **Step 2:** Merge docs → Hub → (wait for `edge` after `build.yml --ref main -f compare_ref=mail1`) → templates → core, through detached worktrees (Global Constraints). Then run core CI on main (all jobs). If kube1 merged meanwhile, apply the coexistence rules and fix `NBINDS` and the parity deltas in the merge commit.
- [ ] **Step 3:** No provider requests are made (no port-25 unblock, no PTR request, no external mailboxes; user rule 2026-11-14). If the live check needs a real client, ask the user to open inbound 465/587/993 on the test server's firewall and wait.
- [ ] **Step 4:** Upgrade the test server, then run:
  1. `./portcullis mail enable --yes` (staging certificate);
  2. `./portcullis mail schedule --systemd`;
  3. `./portcullis dns setup --only mail`;
  4. `./portcullis status`.

  Expected:
  - the Mail block is ok, apart from the checks still pending;
  - TLSA is published (the zone is DNSSEC `secure`);
  - DKIM is `active` within the TTL wait.
- [ ] **Step 5: Live check (no outbound port 25):**
  - add a test person (never the LLDAP `admin`) to `mail_users`, create a mail password, and check IMAP (993) and submission (587/465) log-in with it, and that a removed person's password is refused;
  - submit a message to a local recipient on the same server: it lands with `dkim=pass` for both algorithms (Review Focus 2) as verified by Stalwart itself; a GTUBE lands in Junk;
  - check the published DNS by lookup only: SPF, DKIM (the split TXT reassembles), DMARC, MTA-STS (`curl https://mta-sts.<d>/.well-known/mta-sts.txt`; staging certificate, note it, never switch to production), TLS-RPT, and TLSA when the zone is DNSSEC `secure`;
  - the doctor's `port25` check shows Info (no delivery attempts). Delivery to the internet isn't tested on the test server.
- [ ] **Step 6:** Delete every `mail1` branch (local and remote), every worktree, `/tmp/merge-*` and `/tmp/mail-spike` (memory: branches mainlined). Update memory with the outcome, the Lightsail state and the follow-ups:
  - parked: app sender accounts, inbound backup MX, JMAP / DAV for people, Sieve / vacation, ClamAV, webmail (M5 of the spec) and OAuth (M6 of the spec), mail on Kubernetes, a SQLite store for online backups.
