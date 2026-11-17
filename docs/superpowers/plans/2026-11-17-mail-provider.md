# Mail provider slot Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Mail becomes a swappable provider. Core and the Hub run a generic **mail slot**. Stalwart + mailctl ships as the Marketplace template `stalwart`, which an admin wires into the slot. A second mail server is then one more template, with no core or Hub change. Every shipped mail guarantee stays.

**Architecture:**
- **The slot** belongs to core and the Hub and is generic:
  - Core keeps the infrastructure: `mail-cert`, `mail_tls` / `mail_acme`, TLSA and HELO SPF in `dns-tool`, the networks `portcullis-mail-api` / `portcullis-metrics-mail`, the volume `mail_slot`, LAN-only, and the CLI on the host socket.
  - The Hub drives the provider API v1 (`internal/mailprovider`). It wires one instance (with guards), renders that instance's override (ports, attachments, mounts, the well-known router, void mode), and checks every invariant itself.
- **The provider** is a template with a `mail:` block. For `stalwart` it is Stalwart, mailctl as the adapter (a published image built from core `mailctl/`), Unbound and a `bootstrap` job.
- **The contract** (§3.5 `mail:` and the neutral §19) lands first, with three vector files shared byte for byte across repos.

**Tech Stack:**
- Hub: Go and vanilla JS.
- Core: Go 1.27 (`mailctl`, `domains`, the new `tests/e2e/mail-fake`), bash 3.2 + jq for the CLI, Python 3 stdlib + Playwright for e2e and `tests/mail-conformance/`.
- Templates: Python 3 (`tests/validate.py`, jsonschema).
- Docs: Zensical.
- Images: Stalwart `v1.1.0` and Unbound `v1.26.2`, at the pins in the 2026-11-14 mail plan's Global Constraints (unchanged). The adapter is `ghcr.io/porelli/portcullis-mailctl`, cosign-signed and pinned by digest.

**Spec:** `/Volumes/workspace/portcullis/portcullis-hub/docs/superpowers/specs/2026-11-16-mail-provider-design.md` (Revision 2, approved; §15 Decisions binding). Other inputs:
- the shipped mail plan `docs/superpowers/plans/2026-11-14-mail-server.md`, for its task style, its values and rulings M1–M15;
- its ledger `.superpowers/sdd/2026-11-14-mail-server/progress.md`, whose binding rulings are restated below.

## Global Constraints

- **Base, branches, worktrees.**
  - Branch `mailp1` in core, Hub, templates and docs, at `/Volumes/workspace/portcullis/wt-mailp1/{portcullis,portcullis-hub,portcullis-templates,portcullis-docs}`.
  - Create each from `origin/main` with `git -C <main checkout> worktree add -b mailp1 <path> origin/main`. The bases are core a298a30, Hub dbb1f2f, templates 5637458 and docs 20283be (mail itself shipped at core 9408f97 + 658a245, Hub 75cdbfe, docs bd4668a).
  - Never edit, stash or commit in the main checkouts. Never detach a shared worktree.
- **Before Task 1 (spec §11 step 7).** Delete the merged mail branches and worktrees: `wt-mail1/*`, `wt-mail1-dns` and `wt-mailfix`, and the branches `mail1` (four repos), `mail1-dns` and `mailfix` (local and remote). `mailfix` is already in core main (658a245).
- **Multi-server coexistence (`ms1` is in flight).** It reserves contract §17 / §18 and uids 10008 / 10009. If `ms1` merges into a repo's main before a task of this plan starts there, merge `origin/main` into `mailp1` first (a merge commit, never a rebase).
- **Contract first.**
  - Task 1 (contract) and Task 2 (vectors) land before any code task.
  - After Task 1 and Task 28, resync the Hub's copy of the contract: run `PORTCULLIS_DOCS_DIR=/Volumes/workspace/portcullis/wt-mailp1/portcullis-docs web/docs/sync.sh` in the Hub worktree, then commit `web/docs`.
- **Project rules:**
  - **No mail-server code in core or Hub code paths.** No Stalwart name, image, JMAP call or config there. Exception: core `mailctl/` is the adapter's *source* and image (§15 Q3). Core's runtime never builds, runs or execs it, except `mail export` running the block's argv.
  - **No back-compat or migration code** (memory). MailState v1, `?user=`, `HUB_MAILCTL_*`, the `mail` profile and every removed `.env` key are simply gone. Old test-server data is fixed by hand (Task 29).
  - **Prefer mature libraries.**
  - **No private identifiers in public repos.**
  - **The test server always uses `ACME_STAGING=true`.**
  - **Never touch the LLDAP `admin` user.**
  - **`.github/workflows/ci.yml` ≤ 450 000 bytes** (342 838 at a298a30). Any new step longer than 20 lines goes in `.github/ci/<job>-<step>.sh`.
  - **A compose change needs its chart change in the same commit** (`.github/ci/unit-tests-kube-static.sh`). New compose services, networks and volumes either go into `charts/portcullis` or get a reasoned line in `tests/k8s_parity_deltas.yaml` (`mail slot: Docker/Podman only (mail provider plan)`). Recount the project binds (CLAUDE.md, `NBINDS`).
- **Binding rulings from the shipped mail ledger.** Each must survive the rework. The task named in brackets keeps its test.
  1. **Fail closed** [4, 7, 8, 18]:
     - `PORTCULLIS_MAIL` is on only when it is exactly `on`;
     - the mail routes answer `503 "mail isn't running right now"` while the provider is unreachable, reports `bootstrap: false`, or a void is owed;
     - the Hub sends no MailState when the directory read fails;
     - strict decoding everywhere: unknown keys refused, sizes capped, ids shaped, no trailing bytes.
  2. **Credentials by uuid** (ledger lines 52–57, 118, 124) [4, 12, 18]:
     - create carries the `uuid`, and a mismatch is `409 error_kind account_mismatch`;
     - list and revoke take only `?uuid=`; revoke is idempotent, and an unknown id or uuid is `204`;
     - the Hub works from one snapshot plus one live read;
     - a row ends only on the provider's word (204, or absence from the live list), never on a missing uuid;
     - a re-created username never inherits a mailbox or a password;
     - reconcile, create and revoke share a per-person mail credential lock (sync > person > mu).
  3. **The mass-removal guard** (lines 41, 43, 66–68) [12, 18]:
     - a document that removes more than 50 % of the accounts needs `confirm_mass_removal`;
     - only `lldap_admin` removals confirm it (one predicate); delegates never do;
     - the confirmation is bound to a hash of the removed set, and pending entries clear when people return;
     - while pending, the people's passwords are revoked and sessions reset, with doctor Problem `mail_mass_removal_pending`;
     - the provider's `409` is matched on `error_kind: "mass_removal"` with `removed: [{username, uuid}]`, never on text. Absent or empty → `mail_sync_blocked`;
     - **new:** the Hub refuses to send such a document itself, judged against `mail-last.json`.
  4. **The void gate and marker** (lines 61, 65, 71–73, 117, 124) [7, 13, 17, 24]:
     - every restore voids every mail password before any mail port listens (M7);
     - the marker comes first, saved before anything else;
     - every start path voids while the marker exists, and the marker is removed only after a verified void;
     - both the start primitive and the container gate;
     - the restore marker is persisted; rows are reconciled with the reason "reset by a restore";
     - a failed void keeps the provider stopped.
  5. **LAN-only** (lines 29, 32, 34, 125) [12, 18, 23]:
     - CLI-only, as `MAIL_SUBMISSION_LAN_ONLY`;
     - two layers: per-credential `allowedIps` = the Local networks, and an auth rule requiring `remote_ip` in the Local networks;
     - enforced on its own path before the plan is applied, and re-asserted on every pass;
     - refused on rootless Podman (client IP rewritten);
     - `local_networks` IPv6 rules as ledger line 139;
     - **new:** the Hub verifies `allowed_ips`.
  6. **No outbound port 25 in tests** (lines 4, 75, 77; memory) [25, 27]:
     - DOCKER-USER / OUTPUT reject rules in every mail CI job;
     - the egress probe targets only TEST-NET-1 (`192.0.2.0/24`) and expects a local REJECT;
     - remote test servers sit on internal networks only;
     - no test, deploy or live check connects to port 25 of an outside host.
  7. **Report trust** (lines 40, 42, 45) [18]:
     - a report counts only with an aligned DKIM pass;
     - reporters are counted by eTLD+1 of the DKIM `d=` (publicsuffix), and at least 2 independent reporters are needed before any downgrade;
     - future-dated or pre-`Since` reports are dropped, and the domain must match;
     - reports never weaken MTA-STS or DMARC automatically (doctor Problem only). In v1.1.0 they are display-only.
  8. **DKIM / DANE / MTA-STS downgrade rules** (lines 40, 49, 51) [18, 11]:
     - DKIM becomes `active` only when both public resolvers serve the exact TXT, and a failed stage change rolls back atomically;
     - DANE counts only definite verdicts, and is disabled after ≥ 3 consecutive definite failures over ≥ 30 min (doctor Problem `mail_dane_off`);
     - TLSA is published only while the main zone is `secure`;
     - MTA-STS downgrades only on 2 consecutive definite local certificate failures ≥ 15 min apart. Transport or ctx errors count as unknown;
     - no root-store chain check (staging certificates);
     - **new:** the Hub refuses any set that lowers DMARC below `dmarc_floor`.
  9. **Secrets written in place** (lines 85–86) [7, 20, 23]:
     - never `mv` over a bound file;
     - never on argv, in logs, in op records or in audit; jq reads them through `env.X` / `--rawfile`;
     - the in-place sweep of core's single-file binds stays;
     - the Hub writes `_mail/*` with `O_TRUNC` on the same inode, then `fsync`.
  10. **Session reset** (lines 12, 47) [12]: the sessions survive a revocation, so the Hub restarts the provider's `sessions.restart` service after every removal and every revoke, within the **8 s** budget, with one shared restart.
  11. **No surprise egress** (lines 12, 102–103) [18, 19]: the spam filter's external lookups stay off and are re-checked forever (every 1 min for 30 min after a start or import, then every 15 min). This becomes `x-external_lookups`.
  12. **Mail well-known routes follow VPN-only mode**, with no public exception (user ruling 2026-11-15) [6].
  13. **IPv6 mail refused** (lines 60, 62) [5, 6, 23]: `MAIL_IPV6` is refused, templates may not `enable_ipv6`, and the Hub never publishes `[::]`.
  14. **Export** (lines 33, 125, 138): CLI-only, and message content never passes through the Hub. The adapter's export cleanup is guaranteed (ids recorded in its state, exact `/32` `allowedIps`, exact `ExportPermissions`).
  15. **Ownership** (lines 78, 106): with `PORTCULLIS_MAIL=on`, the address set owns `MAIL_HOSTNAME`'s A/AAAA whether or not a document exists. The CAA at `<h>` is `mail-cert`'s. Former hostnames come only from `secrets/mail/former-hostnames`. An added domain can't be deleted while its mail is `on` or `draining`.
  16. **`MAIL_ACME_CA_SERVER`** (line 73): https only, a testing knob, and the CAA pin must cover it.
  17. **Parked:** L6 (`MAIL_HOSTNAME` A + CAA left after `mail disable`); the Podman resolver healthcheck flake (line 147); `tls_mtls_refuses_browser_cert` (line 155).
- **TDD everywhere.** Write the failing test, watch it fail, implement, watch it pass, commit. The gates:
  - **Core:**
    - `bash tests/test_shell_libs.sh && bash tests/test_cli.sh && shellcheck -S warning portcullis scripts/lib/*.sh tests/*.sh .github/ci/*.sh && actionlint && bash tests/lint_ci_size.sh && bash tests/lint_images.sh && bash tests/lint_builder_cache.sh`;
    - `cd mailctl && test -z "$(gofmt -l .)" && go vet ./... && go test -race ./...`;
    - the same for `domains` (also `-tags testprovider`) and `tests/e2e/mail-fake`.
  - **Hub:** `go vet ./... && go test -race ./... && test -z "$(gofmt -l .)"`.
  - **Templates:** `python3 tests/validate.py && python3 tests/test_validate.py`.
  - **Docs:** `python3 scripts/check-lists.py && bash scripts/check-branding.sh && zensical build --strict --clean`.
- **CI.**
  - **Core:** `gh workflow run ci.yml --ref mailp1 -f jobs=<names> [-f scenarios="<names>"] [-f runner=builder]`. Only the controller dispatches core CI on `mailp1`, because the concurrency group cancels runs.
    - For a single e2e scenario use `-f scenarios=…` (names from `python3 tests/e2e/scenarios.py list`).
    - For local iteration, `.github/ci/local/run-job.sh <job> [--scenario <n>]… --local <worktree>` runs one job on the builder. It can't run e2e-podman or e2e-k3s.
    - Every new e2e check needs the `scenarios.skip(name)` gate at the start of `check()` (`tests/test_e2e_scenarios.py`).
    - A new job keeps the `runs-on` builder expression and never writes the Actions cache from the builder (`tests/lint_builder_cache.sh`).
  - **Hub:** `gh workflow run build.yml --ref mailp1`. **Templates:** `lint.yml` and `test-apps.yml` on `mailp1`.
  - **The controller runs its own background watcher** on every dispatched run (memory).
- **Merges** (spec §7): docs → Hub (wait for `edge`) → templates → core. Core lands right after the templates.
  - Merge each repo through a detached worktree: `git worktree add --detach /tmp/merge-<repo> origin/main` → `git merge --no-ff origin/mailp1 -m "merge mailp1: …"` → push → `git worktree remove`.
  - After the Hub merge, run `gh workflow run build.yml --ref main -f compare_ref=mailp1` and wait for `edge` before merging core.
  - At the end, delete every `mailp1` branch, worktree and `/tmp/merge-*` (memory: branches mainlined).
- **Values from the spec (verbatim):**
  - **The slot:**
    - `PORTCULLIS_MAIL=on` = slot open;
    - network `portcullis-mail-api` = `${PORTCULLIS_MAIL_API_SUBNET:-172.31.255.16/28}`, range `${PORTCULLIS_MAIL_API_IP_RANGE:-172.31.255.24/29}`, Hub `.18` (`PORTCULLIS_MAIL_API_HUB_IP`), provider `.19` (`PORTCULLIS_MAIL_API_PROVIDER_IP`), alias `mail-api`;
    - `HUB_MAIL_API_URL` default `http://mail-api:8080`, the port taken from `mail.api.port`;
    - `portcullis-metrics-mail` with the aliases `mail-provider-metrics` and `mail-provider-server-metrics`;
    - volume `mail_slot` (Hub rw, Prometheus ro).
  - **Gid 2000** = `CT_GID_MAIL_PROVIDER` (renamed from `CT_UID_MAIL`). The override adds `group_add: ["2000"]` to the `tls` and `gated` services.
  - **`_mail/` files:** `hub_secrets` `<instance>/_mail/{api-secret,metrics-secret,relay-password,.present,void-pending,void-session}`, mounted read-only at `/run/portcullis/mail/slot/` into the `gated` services only. The API secret is 48 characters, files are 0640 gid 2000, and `.present` reads `portcullis-mail-gate`.
  - **The certificate:** `portcullis_mail_tls`, mounted read-only at `/run/portcullis/mail/tls` into the `tls` services only, SAN exactly `MAIL_HOSTNAME`.
  - **Ports:** `0.0.0.0:25:<smtp>`, `0.0.0.0:465:<submissions>`, `0.0.0.0:587:<submission>`, `0.0.0.0:993:<imaps>`. IPv4 only, never `lan_only`.
  - **The well-known router:** `portcullis-mail-wellknown`, rule `Host(mta-sts.<e>) || Host(autoconfig.<e>) || Host(autodiscover.<e>)` for every mail domain, `entrypoints: ${PORTCULLIS_EP_CORE}`, `middlewares: rate-limit@file,security-headers@file`, service `portcullis-mail-wellknown` on `mail.wellknown.port`. The env key is `PORTCULLIS_MAIL_WELLKNOWN_ENTRYPOINTS`.
  - **Void mode:** no ports, no router, the template's networks forced `internal: true`, only the API attachment, and `PORTCULLIS_MAIL_VOID_SESSION=<nonce>`. The retry runs every **5 min** and on *Retry*.
  - **DKIM retention on switch:** **7 days**. MTA-STS restarts at `testing`.
  - **Timing:** the DNS hash poll every **60 s**, the backstop every **6 h**, the MTA-STS policy fetch every **6 h**; `mail_provider_unreachable` after **10 min** of `bootstrap: false`.
  - **The session-reset budget** is **8 s**: a restart grace of 2 s and a 30 s bound per restart (unchanged from `mail_restart.go`).
  - **The warning text** (exact): "This app becomes the mail server for every person and every mail domain. It gets public ports 25, 465, 587 and 993, writes the mail DNS records of every mail domain, creates and checks the mail passwords of every person in mail_users, sends mail to the internet (outbound SMTP), and can read every mailbox."
  - **Refusal texts:** "type the instance id to confirm"; "mail is off: run ./portcullis mail enable on the host"; "<id> is this server's mail provider: switch instead"; "unwire it first (Settings → Mail)"; "the mail provider's template changed: review and confirm on its Mail tab"; plus the `mail:` texts in spec §4.
  - **Audit:** `mail.provider_wired`, `mail.provider_unwired`, `mail.provider_switched`, `mail_credential.void_provider` (with the count). The wired record carries the instance, template, source, commit, block hash and actor.
  - **Credential void reasons:** `provider_changed` ("the mail server changed on <date>: create a new mail password") and `void_restore` ("reset by a restore").
  - **Contract metrics:** `portcullis_mail_check{check}`, `portcullis_mail_dkim_stage{domain,stage}`, `portcullis_mail_queue_messages`, `portcullis_mail_queue_deferred_ratio`. Core's own is `portcullis_mail_cert_expiry_seconds`, through the textfile exporter.
  - **The parking domain:** `portcullis-former.internal`.
- **Values this plan adds (assistant's calls, binding):**
  - **The neutral check catalog:** `port25`, `fcrdns_v4`, `fcrdns_v6`, `blocklist`, `cert`, `dane`, `client_ip`, `dmarc_reports`, `tlsrpt_reports`, `records:<d>`, `dkim_selftest:<d>`, `dkim_stuck:<d>`, `dkim_manual:<d>`, `rate_held:<u>`. Anything else must start with `x-`; any other id is refused by strict decoding. Stalwart's: `x-spam_rules`, `x-external_lookups`.
  - **`hub_data` files:**
    - `mail-relay-password` (0600, the Hub's own copy; the source for `_mail/relay-password`);
    - `mail-last.json` (as today).
  - **`state.yaml` `mail.provider`:** `{instance, template, source, commit, block_hash, wired_at, wired_by}`. Plus `mail.void_owed {reason, since}`, `mail.held {reason, since}`, `mail.retiring_dkim {<domain>: {records, until}}` and `mail.tls {spki_sha256: [..], not_after, seen_at}`.
  - **Image tags:** `ghcr.io/porelli/portcullis-mailctl:edge` (main), `:X.Y.Z` (release) and `:dev-<branch>-<sha7>` (P2).
  - **E2E scenario names:**
    - `11 switch_provider`;
    - `12 hostile_provider_contained`;
    - `13 wiring_guards`;
    - `14 template_change_holds`;
    - `15 conformance_stalwart`;
    - `16 conformance_fake_api`.

## Plan rulings (P1–P12, assistant's calls; spec gaps and defects)

- **P1 (spec defect): the app page lives in the docs repo.** `portcullis-templates/docs/` is the `docs` app template, and every app page is `portcullis-docs/docs/apps/<id>.md`. So the Stalwart page is `portcullis-docs/docs/apps/stalwart.md` (Task 28).
- **P2 (spec gap): the adapter image before core merges.** The templates merge before core, but the image is published from core main. So:
  - `.github/workflows/mailctl.yml` (forwarder pattern) pushes `:edge` from main. On `workflow_dispatch` from a non-main ref it pushes only `:dev-<branch>-<sha7>`, cosign-signed, never `edge` or a release tag.
  - The templates branch pins that digest.
  - Core CI on any branch never pulls it: it builds `mailctl/` from the checkout and rewrites the cloned template's adapter `image:` line to the local tag (Task 25). The step fails when the line isn't exactly `ghcr.io/porelli/portcullis-mailctl:<tag>@sha256:<64 hex>`.
  - After the core merge, Task 29 re-pins `stalwart` to the `:edge` digest.
- **P3 (spec ambiguity): the gate predicate, exactly.** A gated service starts only when one of these holds:
  - `void-pending` is absent and `.present` is exactly `portcullis-mail-gate` (an optional trailing newline);
  - `void-pending` exists, `void-session` is non-empty, and `$PORTCULLIS_MAIL_VOID_SESSION` equals it byte for byte.

  Anything else, including an unreadable file, exits non-zero before the server starts. During void mode the Hub writes `void-pending` and `void-session` but no `.present`. Only after a verified void does it write `.present`, then delete `void-session` and `void-pending`. So a raw `compose up` after a core restore (empty `hub_secrets`) fails closed.
- **P4 (spec inconsistency between §9 and §10.2): the hold.**
  - On a template change the Hub issues no `up`, re-render or recreate of the wired instance, and the running containers keep serving.
  - Every lifecycle path that would need an `up` (enable, a dead container, a Hub restart reconcile, an env change) renders **void mode** instead, and runs no void.
  - Mail routes answer as for an unreachable provider until an admin re-wire, which includes a void.
  - `block_hash` is the sha256 of the canonical JSON of the `mail:` block, the compose file's bytes and every file under the template directory (path-sorted). This is stricter than "block and images" and fails closed. Its cost: every image bump of `stalwart` needs a re-wire, which voids the mail passwords.
- **P5 (spec gap): host-socket wiring.** The routes are:
  - `GET /host/mail/provider` → `{slot, wired, instance, template, label, version, void_owed, held, warning}` (`warning` = the warning text, always);
  - `POST /host/mail/install {"template","source","confirm"}`: installs the template when no instance of it exists, then wires it. `confirm` is the instance id;
  - `POST /host/mail/unwire {"drain": bool}`;
  - `POST /host/mail/action {"name","domain"}`.

  Each `mail rotate` run posts `POST /host/mail/tls`, which also records the timer's visit (`mail_timer_missing`).
- **P6 (spec gap): writing gid-2000 and Prometheus files.**
  - Core adds `group_add: ["2000"]` to the `hub` service, so the Hub can create `_mail/` (directory 2750 gid 2000) and its files.
  - `mail_slot` is prepared by core as `10001:65534` mode 2750 (setgid). The Hub's 0640 files inherit gid 65534 for Prometheus.
- **P7: metrics discovery.**
  - One file, `mail_slot/mail-targets.json` (file_sd). Its entries carry the label `service: provider|server`, and the server entry has `__metrics_path__` from the block.
  - Two jobs, `mail-provider` and `mail-provider-server`, keep their own entries. Both use Basic auth, user `prometheus`, with `password_file: /mail-slot/metrics-secret`.
  - The file is `[]` when nothing is wired.
- **P8: void verification.**
  - While a void is owed, the Hub refuses to create mail passwords (503).
  - After `POST /v1/void` it lists `?uuid=` for every account in `mail-last.json` and every uuid in its `mail_credentials` rows. It revokes any credential it finds, then lists again. Any credential left, or any list error, is a failed void.
- **P9: reserved core names (contract §1 "core ⊆ Hub", one-directional).**
  - The Hub and templates add the new names in Tasks 5 and 16, and keep the removed mail core names until core has merged.
  - Task 29 removes them: `mail`, `mailctl`, `mail-resolver`, `mail_data`, `mail_etc`, `mailctl_data`, `portcullis-mail`, `portcullis-mailctl`, `mail-egress`, `mail-metrics`, `mailctl-metrics`, `mail-wellknown`, `mailctl-wellknown`.
- **P10 (spec §11 is stale): the test server's mail records are published.**
  - Ledger line 154: the Porkbun fix published the set, DKIM is active and the timer is installed.
  - So migration step 1's `mail disable --force --yes` withdraws them at once, which is acceptable: the firewall is closed on 25, so there are no real senders.
  - Step 6's `dns setup --yes` needs no further fix (658a245 is in).
- **P11: conformance levels.** `tests/mail-conformance/run.py --level api|full`:
  - `full` (API + SMTP/IMAP) runs against `stalwart`;
  - `api` runs against `mail-fake`, which has no SMTP, to prove goal 1.
- **P12: the MTA-STS policy fetch.**
  - The Hub fetches `/.well-known/mta-sts.txt` through Traefik's `websecure` entrypoint on `portcullis-proxy`, with SNI and Host `mta-sts.<e>`.
  - The check is on content only: exactly one `mx:` line equal to `MAIL_HOSTNAME`, `version: STSv1`. TLS chain verification is off (a local hop, staging certificates).
  - It is skipped while MTA-STS is `off`, for example in VPN-only mode.

## Review Focus

1. **The Hub restarts (or crashes) mid-wiring, mid-void or mid-switch.** `state.yaml` says `void_owed` and names a provider.
   - On start the Hub must resume void mode. It never renders the normal override first, and it never re-creates `.present` before the verification.
   - A switch interrupted after the unwire must not leave both instances holding ports.
   - Pinned by `TestWireResumesVoidAfterRestart` (Task 8) and `TestSwitchResumesAfterRestart` (Task 9).
2. **Core `./portcullis backup` runs while a void is owed or the provider is held.** The instance backup stops and restarts the instance. The restart must come back in void mode (or stay stopped), never normal. Pinned by `TestCoreBackupDuringVoidStaysVoid` (Task 13).
3. **An unwire, `mail disable` or switch while the provider is down or hostile.** `POST /v1/void` fails or hangs. The secret and `.present` must still be deleted, the ports closed and the rows voided. Nothing may wait forever for the provider. Pinned by `TestUnwireWithProviderDownClosesGate` (Task 9).
4. **A switch where a domain's `PUT …/sets/mail` fails half-way.** Some domains still carry the old set and some the new. Each domain must keep the old DKIM records until its own new set is written and 7 days have passed, and the doctor must name the domain. Pinned by `TestSwitchPartialDNSKeepsRetention` (Task 9).
5. **A template source sync lands while a wiring op is running.** The op has recorded `block_hash` but hasn't finished. The hold must win: no normal override for a tree that no longer matches. Pinned by `TestTemplateChangeDuringWireHolds` (Task 10).

---

## File structure

**Docs (`wt-mailp1/portcullis-docs`):**
- `docs/guides/integration-contracts.md`: §1, §2, §3, §3.5 (new), §5, §6, §11.4, §11.5, §11.7, §11.10, §12.2, §13.16, §14.5, §14.6, §15.10, §16, §19 (rewritten);
- `docs/apps/stalwart.md` (new) and `docs/apps/.nav.yml`;
- `docs/setup/mail.md`, `docs/operations/mail.md`, `hardening.md`, `backups.md`, `monitoring.md`, `cli.md`, `testing.md`, `hub.md`, `rootless-podman.md`, `docs/setup/dns.md`.

**Hub (`wt-mailp1/portcullis-hub`)**

| File | Responsibility |
|---|---|
| `internal/mailprovider/{client.go,types.go,dnsrules.go}` + `testdata/{mailstate_v2.json,mail_dns_vectors.json}` + `mailprovidertest/fake.go` (was `internal/mailctl/`) | provider API v1 client, MailState v2, DNS set rules |
| `internal/templates/mail.go` + `testdata/mail_vectors.json` | `ValidateMail`, the `Mail` manifest type |
| `internal/state/mail.go` | `MailProvider`, void / hold / retiring-DKIM / TLS state, new settings |
| `internal/hub/mail_slot.go` (new) | slot view, block hash, the wired provider's client |
| `internal/hub/mail_override.go` (new), `override.go` | normal / void / unwired rendering, mount checks |
| `internal/hub/mail_gate.go` (new) | `_mail/` files, secret, void-and-verify |
| `internal/hub/mail_wire.go` (new) | wire / unwire / switch ops, guards, hold |
| `internal/hub/mail_dns.go`, `mail_mtasts.go` (new) | validated sets, DKIM retention, MTA-STS policy fetch, main set |
| `internal/hub/mail.go`, `mail_state.go`, `mail_pending.go`, `mail_creds.go`, `mail_restart.go`, `mail_admin.go`, `mail_core.go` | sync, v2 document, Hub-side mass-removal check, `allowed_ips`, instance session reset |
| `internal/hub/mail_monitor.go` (new) | `mail_slot` targets + metrics secret |
| `internal/hub/backup.go`, `restore.go`, `delete.go`, `ports.go`, `credstore.go` | reason `core`, void owed on restore, delete refusal, slot port collisions, epoch → void |
| `internal/runtime/{runtime.go,docker/backend.go,kube/exec.go,runtimetest/fake.go}` | `RestartService` replaces `RestartCoreService` |
| `internal/doctor/mail.go`, `internal/hub/doctor_mail.go` | 24 kinds |
| `internal/httpapi/{mail.go,mail_provider.go (new),hostctl.go,mcptools_mail.go}`, `cmd/hub/{main.go,vpn.go}` | routes, host routes, `hub mail …` |
| `internal/templates/coreref.go` | reserved names (P9) |
| `web/mail.js`, `web/apps.js` / instance page, marketplace | UI |

**Templates (`wt-mailp1/portcullis-templates`):** `schema/manifest.schema.json`, `tests/validate.py`, `tests/test_validate.py`, `tests/mail_vectors.json`, `.github/workflows/lint.yml`, `stalwart/` (new: `manifest.yaml`, `compose.yml`, `gate/entrypoint.sh`, `unbound/unbound.conf`, `config/config.json`), `tests/apps/stalwart.sh`, `tests/mail/test_gate_entrypoint.sh`, `CLAUDE.md`.

**Core (`wt-mailp1/portcullis`)**

| File | Responsibility |
|---|---|
| `mailctl/internal/{api,state,config,bootstrap,dnsset,checks,metrics,tlsa→removed}`, `mailctl/main.go`, `mailctl/Dockerfile` | the adapter's provider API v1 + runtime |
| `.github/workflows/mailctl.yml` (new) | adapter image (P2) |
| `docker-compose.yml`, `docker-compose.podman*.yml`, `docker-compose.mail-recovery.yml` (deleted), `charts/portcullis`, `tests/k8s_parity_deltas.yaml` | slot infrastructure |
| `domains/internal/dnsplan/{mail.go,tlsa.go (new),mailrules.go (new)}`, `domains/tool.go`, `domains/service.go`, `domains/mailcert.go` + `testdata/mail_dns_vectors.json` | TLSA / HELO SPF, `tlsa.json` rollover, set validation |
| `scripts/lib/{mail.sh,backup.sh,dns.sh,network.sh,stack.sh,common.sh,status.sh}` | CLI |
| `monitoring/prometheus/{prometheus.yml,alerts.yml,tests/alerts_test.yml}` | jobs, alerts |
| `.github/workflows/ci.yml`, `.github/ci/{unit-tests-mail-wiring.sh,build-and-test-mail-service.sh,e2e-mail-*.sh,e2e-podman-mail.sh,mail-templates-checkout.sh (new)}` | CI |
| `tests/e2e/mail-fake/` (new Go module), `tests/e2e/apps/mail-fake/` (new template), `tests/mail-conformance/` (new), `tests/e2e/e2e_mail.py` | fake provider, conformance, e2e |

---

## Stream A — Contract and vectors (first)

### Task 1: Contract (docs)

**Files:**
- Modify: `docs/guides/integration-contracts.md` (the sections listed in File structure).
- Modify (Hub): `web/docs/*` via `sync.sh`.

**Interfaces — Produces (binding for every later task):**
- **§1:** a "Mail provider slot (NEW, mail provider)" bullet. It covers the contract MINOR bump, MailState v2, the breaking change for core + Hub together, and the merge order docs → Hub (`edge`) → templates → core.
- **§3.5 "The `mail:` block":** spec §4 verbatim, with:
  - the field rules;
  - the stricter rules for every service;
  - the `auth` rule;
  - the full ordered refusal list, the same texts as `tests/mail_vectors.json`. Each spec §4 text, plus the VPN mount texts with the prefix `mail:`, plus:
    - `mail.label: 1–64 characters, one line`;
    - `mail.<field>: service <s> is not a service of this template`;
    - `mail.<field>: port must be 1024–65535`;
    - `mail.<field>: <s> is a job` / `an AI companion` / `has network_mode`;
    - `mail.export.argv: exactly one {former_id}`;
    - `mail: instances must be single`;
    - `mail: auth must be method custom with no routers and group_access false`;
    - `mail: network <n> enables IPv6`;
    - `mail: manifest ports are not allowed`;
    - `mail: unknown key <k>`.
- **§19 "Mail provider API"** (neutral). §19.1–19.12 as spec §7 "What §19 keeps", with these exact shapes:
  - **Auth:** `Authorization: Bearer <api-secret>`. The provider refuses any source outside `PORTCULLIS_MAIL_API_SUBNET` and any request without the bearer (403, nothing else). JSON is strict, bodies ≤ 4 MiB.
  - **Endpoints:**
    - `GET /v1/provider` → `{"name","version","api_version":1,"checks":["<id>"],"actions":["dkim-rotate","dmarc-promote","mtasts-enforce","test"],"export":true}`;
    - `PUT /v1/state` (MailState v2) → `202 {"generation"}`. A non-increasing generation is `409 {"error_kind":"generation"}`; a mass removal is `409 {"error_kind":"mass_removal","removed":[{"username","uuid"}]}`;
    - `GET /v1/state` → `{"generation","applied_generation","bootstrap","errors":[…]}`;
    - `GET /v1/dns/{domain}[?wildcard=false]` → `{"domain","records":[{"name","type","ttl","value"}],"dkim":"auto|manual"}` (no `tlsa`);
    - `GET /v1/checks[?refresh=1]` → `{"checked_at","checks":[{"id","severity":"ok|info|warning|problem","title","detail","steps":[…],"reason"}]}`, ids from the catalog. `title` appears only on `x-` checks (≤ 80 characters), `detail` ≤ 500, at most 10 steps ≤ 200 each;
    - `GET /v1/status` → `{"bootstrap","provider":{"name","version"},"cert":{"not_after","sans","spki_sha256"},"dkim":[…],"mtasts":[…],"dmarc":[…],"queue":{"messages","deferred"},"restored_at","former":[…],"dns":{"<domain>":"<hash>"}}`;
    - `GET /v1/credentials?uuid=<u>` → `[{"id","uuid","label","created_at","expires_at","last_used","allowed_ips":["<cidr>"]}]`. `uuid` is echoed on every row, `allowed_ips` `[]` = anywhere;
    - `POST /v1/credentials {"username","uuid","label","expires_at"}` → `201 {"id","secret","created_at","expires_at"}` with `no-store`. `409 error_kind account_mismatch|limit`, `404` for an unknown account;
    - `DELETE /v1/credentials/{id}?uuid=<u>` → 204 (idempotent);
    - `POST /v1/void {"reason":"wire"|"restore"}` → `200 {"voided":<n>,"restored_at":"<rfc3339>"}`;
    - `POST /v1/tls/reload {"spki_sha256":["<hex>"]}` → `200 {"serving_spki_sha256":"<hex>"}`;
    - `POST /v1/actions/test {"to"}` → `202 {"queue_id"}`;
    - `POST /v1/actions/{dkim-rotate|dmarc-promote|mtasts-enforce} {"domain"}` → 202.
  - **MailState v2** (the canonical example, which is the vector of Task 2): v1's fields plus `"version":2`, `"mail_hostname":"mail.example.com"`, `"client_ip":"preserved"`, `"submission_lan_only":false`, `"dkim_rotate":"4320h"`, `"former_retention":"720h"`, `"relay":null` (or `{"host","port","username","spf_include"}`, the password in the file `relay-password`), `"tls":{"spki_sha256":["<64 hex>"]}`, and per domain `"dmarc_floor":"none|quarantine|reject"`.
  - **Gate and void:** P3 verbatim; §6.10 of the spec; the void obligations (destroy every credential of every account, record `restored_at`).
  - **The provider's environment** (set by the override): `PORTCULLIS_MAIL_API_SUBNET`, `PORTCULLIS_MAIL_API_HUB_IP`, `PORTCULLIS_MAIL_SLOT_DIR=/run/portcullis/mail/slot`, `PORTCULLIS_MAIL_TLS_DIR=/run/portcullis/mail/tls`, `PORTCULLIS_MAIL_WELLKNOWN_ENTRYPOINTS`, `PORTCULLIS_MAIL_VOID_SESSION` (void mode only).
  - **Obligations (MUST)**, one per P row of spec §10.1: 3, 5, 6, 7, 9, 10, 11, 12, 16, 18 (provider-specific). Plus the parking domain, reserved local parts, "removals at once, additions debounced 60 s", and §19.8's degraded mode.
  - **§19.7:** the DNS set validation table (spec §6.3) and "never A, AAAA, CAA, NS, DS, TLSA".
  - **§19.9:** the Hub routes:
    - `GET|PUT /api/instances/{id}/mail-provider` (PUT `{"wired","confirm","code","code_verifier","nonce","drain"}`);
    - `POST /api/mail/provider/switch {"to","confirm","confirm_empty","code","code_verifier","nonce"}`;
    - `POST /api/mail/provider/retry-void`;
    - `GET /api/mail/provider`.
  - **§19.10:** the host routes of spec §7 plus P5. **§19.12:** Kubernetes refused.
- **Other sections:**
  - **§2:** the core.env keys `PORTCULLIS_MAIL`, `PORTCULLIS_MAIL_HOSTNAME`, `PORTCULLIS_MAIL_SUBMISSION_LAN_ONLY` and `PORTCULLIS_MAIL_CLIENT_IP`. Gone: `PORTCULLIS_MAIL_RELAY`, `_DQS`, `_FORMER_RETENTION`, `PORTCULLIS_MAILCTL_IP`.
  - **§3:** the new reserved names (spec §7) and P9.
  - **§5:** `portcullis-mail-wellknown` replaces `mail-wellknown`.
  - **§6:** drop "Restarting core `mail`"; add the `RestartService` scope (the wired instance's `sessions.restart` only); the `_mail/` subpath of the `portcullis-hub-secrets` mount.
  - **§11.4:** the delete refusal while wired.
  - **§11.5:** backup reason `core`.
  - **§11.7:** the wire / unwire / switch ops.
  - **§11.10:** the listener ports in the port-start gate.
  - **§12.2:** the domains service refuses an invalid `sets/mail` body with 400 and the rule's text.
  - **§13.16:** the void reasons.
  - **§14.5 / §14.6:** the 24 kinds (Task 14's list).
  - **§15.10:** `mail_status` gains `provider`; there is no wiring tool ever.
  - **§16:** the host routes.

- [ ] **Step 1:** Write the sections in the contract's style ("NEW (mail provider)" markers). Move every Stalwart-specific paragraph of the current §19 (§19.1 service details, §19.4 bootstrap and recovery, the role, spam-rule import, JMAP) into a stub list at the end of this commit message, for Task 28's app page.
- [ ] **Step 2:** Run the docs gate. Expected: exit 0.
- [ ] **Step 3:** Commit (`docs: contract for the mail provider slot (§3.5 mail:, §19 provider API v1, MailState v2)`) and push `mailp1`.
- [ ] **Step 4:** Resync the Hub `web/docs`. `git diff --stat web/docs` must list only `integration-contracts.md`. Commit (`docs: sync contract (mail provider)`).

### Task 2: Shared vectors (Hub authors; byte copies in templates and core)

**Files:**
- Create (Hub):
  - `internal/templates/testdata/mail_vectors.json`;
  - `internal/mailprovider/testdata/mailstate_v2.json` (git-move `internal/mailctl/testdata/mailstate_v1.json`, then edit);
  - `internal/mailprovider/testdata/mail_dns_vectors.json`.
- Create (templates): `tests/mail_vectors.json`. (Core): `mailctl/internal/state/testdata/mailstate_v2.json` (delete `mailstate_v1.json`), `domains/internal/dnsplan/testdata/mail_dns_vectors.json`.
- Test (Hub): `internal/templates/mail_vectors_shape_test.go`, `internal/mailprovider/vectors_shape_test.go`.

**Interfaces — Produces:**
- **`mail_vectors.json`:** `[{"name","manifest","compose","want_error"}]` (the `vpn_vectors.json` shape; `want_error` `""` = valid).
  - At least one "stalwart-shaped ok", one `mail-fake`-shaped ok, and one vector per refusal text of §3.5, in contract order.
  - Plus: `ports:` on a non-listener service; a `traefik.enable` label; `cap_add: [NET_ADMIN]`; a `./../` bind; an external `portcullis_mail_tls` volume; YAML anchors; `enable_ipv6: true`; `instances: multi`; a `person_secret` option; `listeners` split over two services; `gated` missing the api service; `sessions` missing; `api_version: 2`.
- **`mail_dns_vectors.json`:** `{"context":{"domain","mail_hostname","relay_include","dmarc_floor","wildcard"},"cases":[{"name","records":[…],"want_error"}]}`.
  - One ok case per row of spec §6.3.
  - One refusal per forbidden shape: an A, AAAA, CAA, NS, DS or TLSA record; MX to a foreign host; SPF with `a`, `ip4:` or an unset `include:`; a DKIM selector with a dot; DMARC `p=none` under floor `reject`; `rua` off-domain; `ruf` present; an MTA-STS id of 33 characters; an SRV on a wrong port; `_imap._tcp` not `0 0 0 .`; a CNAME with `wildcard=true`; a name outside the table; a name under another domain.
  - `want_error` texts are of the form `mail set: <name> <type>: <why>`.
- **`mailstate_v2.json`:** the §19 canonical example, two domains (one floor `reject`, one `none`), `relay` set.

- [ ] **Step 1: Write the failing tests:** `TestMailVectorsShape` (every refusal text of §3.5 appears in exactly one vector; names unique), `TestDNSVectorsShape`, `TestMailStateV2VectorDecodesStrict` (decodes into the Task 4 types once they exist; until then into a `map` with the key-set assertion).
- [ ] **Step 2:** Run `go test ./internal/templates/ ./internal/mailprovider/`. Expected: FAIL (files missing).
- [ ] **Step 3:** Write the three files. Copy them byte for byte into the templates and core branches. Commit there too (`tests: shared mail vectors (copy of the Hub's)`).
- [ ] **Step 4:** Run the test again. Expected: PASS. `cmp` each copy against the Hub file. Expected: no output.
- [ ] **Step 5:** Commit on Hub (`mailprovider, templates: shared mail vectors`).

### Task 3: Spike — the `bootstrap` job ordering and the gate on Docker and rootless Podman (templates; builder)

**Files:**
- Create: a throwaway `stalwart/` prototype (`compose.yml`, `gate/entrypoint.sh`) on the builder, and the ledger file `portcullis-hub/.superpowers/sdd/2026-11-17-mail-provider/spike.md` (untracked, like every SDD ledger).

**Interfaces — Produces:** the facts Task 17 relies on, as a ruling list in `spike.md`:
1. With compose `depends_on: {bootstrap: {condition: service_completed_successfully}}` on `stalwart` and `adapter`, two RocksDB openers never overlap. This holds for `up`, for a Hub `up` of one service, and for `restart stalwart`.
2. A `restart` of `stalwart` doesn't re-run `bootstrap`.
3. A recovery-mode start outside the job is refused by the wrapper. The job-scoped session file lives in a job-only volume or tmpfs, never a shared one.
4. The P3 predicate's wrapper works as Stalwart's entrypoint under Docker and rootless Podman 6.1.3. This is the 4-element entrypoint, no re-split (ledger line 73).
5. `group_add: ["2000"]` and a volume `subpath` mount of `hub_secrets` work on Podman.

- [ ] **Step 1:** On the builder, on an internal network with egress 25/465/587 rejected (Global Constraints ruling 6), run the prototype under Docker, then under rootless Podman.
- [ ] **Step 2:** Record each fact as `ok` or `refuted + the fallback`. If fact 1 is refuted, the fallback is the adapter running bootstrap itself before it starts Stalwart's recovery session, with a flock on the volume. The controller rules on it.
- [ ] **Step 3:** Save `spike.md` and note its facts in the ledger. Nothing is committed: Task 17 builds the template from these facts.

---

## Stream H — Hub

### Task 4: `internal/mailprovider` — provider API v1 client and MailState v2 (Hub)

**Files:**
- Move: `internal/mailctl/` → `internal/mailprovider/` (`client.go`, `types.go`, `mailprovidertest/fake.go`), and update imports.
- Modify: `internal/hub/mail_core.go` (`MailAPI`), `cmd/hub/main.go` (drop `HUB_MAILCTL_*`).
- Test: `internal/mailprovider/client_test.go`.

**Interfaces — Produces:**
- `mailprovider.New(baseURL string, secretFile string) *Client`. The secret is re-read per call, and a missing or empty file is `ErrNoSecret` (the client sends nothing).
- `MailAPI` gains `Provider(ctx) (ProviderInfo, error)`, `Void(ctx, reason string) (VoidResult, error)`, `TLSReload(ctx, spki []string) (string, error)` and `Test(ctx, to string) (string, error)`.
- `Credentials(ctx, uuid string) ([]Credential, error)` (by uuid). `Credential` gains `UUID string`, `AllowedIPs []netip.Prefix`.
- `MailState` v2 fields per Task 1. `Status` per Task 1, with `Provider{Name, Version}`.
- `Check.Title`. `ValidCheckID(id string) bool` (the catalog + `x-[a-z0-9_]{1,40}`).
- Errors: `*APIError{Status int, Kind string, Removed []Removed, Msg string}`, secrets redacted.

- [ ] **Step 1: Write the failing tests:**
  - `TestMailStateV2Vector` (decode → encode round-trip equals the vector bytes after compact);
  - `TestCredentialRowsMustEchoUUID` (a row with another uuid → error, nothing returned);
  - `TestCredentialAllowedIPsStrict`;
  - `TestUnknownCheckIDRefused`;
  - `TestXCheckTextClipped`;
  - `TestResponseSizeCapped` (> 4 MiB → error);
  - `TestTrailingBytesRefused`;
  - `TestSecretReReadPerCall`;
  - `TestNoSecretNoRequest`;
  - `TestVoidAndTLSReloadShapes`.
- [ ] **Step 2:** Run `go test -race ./internal/mailprovider/...`. Expected: FAIL.
- [ ] **Step 3:** Implement. `MailAPI` keeps its seam role. Every existing `internal/hub/mail_*_test.go` keeps passing with the renamed fake.
- [ ] **Step 4:** Run the Hub gate. Expected: PASS.
- [ ] **Step 5:** Commit (`hub: internal/mailprovider (provider API v1, MailState v2, strict decoding)`).

### Task 5: `templates.ValidateMail`, the Marketplace badge, reserved names (Hub)

**Files:**
- Create: `internal/templates/mail.go`, `internal/templates/mail_test.go`.
- Modify: `internal/templates/manifest.go` (`Mail *Mail \`yaml:"mail"\``), the source loader (skip a template that fails; the same path `ValidateVPN` uses), `internal/templates/coreref.go` (add the new names, P9), the marketplace view (`mail_provider: true`).

**Interfaces — Produces:**
- `type Mail struct{ Label string; APIVersion int; API, Wellknown, Metrics Endpoint; ServerMetrics *MetricsEndpoint; Listeners Listeners; TLS, Gated []string; Sessions struct{ Restart string }; Export *Export }`.
- `type Endpoint struct{ Service string; Port int }`; `MetricsEndpoint{Endpoint; Path string}`; `Listeners{Service string; SMTP, Submissions, Submission, IMAPS int}`; `Export{Service string; Argv []string}`.
- `func ValidateMail(t *Template, compose []byte, routes *Routes) error`: the first refusal in contract order, else nil.
- `func MailBlockHash(dir string, m *Mail, compose []byte) (string, error)`: P4 (hex sha256).

- [ ] **Step 1: Write the failing tests:**
  - `TestMailVectors` (every vector of `testdata/mail_vectors.json`: `want_error` == the returned text, `""` == nil);
  - `TestMailBlockHashCoversTree` (a byte change in any file under the dir changes it; an unrelated template's change doesn't);
  - `TestTemplateWithBadMailSkipped`;
  - `TestCoreNamesIncludeMailSlot`;
  - `TestMarketplaceMailBadge`.
- [ ] **Step 2:** Run `go test ./internal/templates/`. Expected: FAIL.
- [ ] **Step 3:** Implement. Reuse `vpnMounts`, `vpnYAMLIndirection`, `vpnPlainVolumeIdentity`, `vpnBindEscapes` and `vpnNamespaceCaps` with a prefix parameter (`"vpn:"` / `"mail:"`), not copies.
- [ ] **Step 4:** Run the Hub gate. Expected: PASS.
- [ ] **Step 5:** Commit (`templates: the mail: block (ValidateMail, vectors, badge, reserved names)`).

### Task 6: Slot state, override rendering, mount checks, `RestartService` (Hub)

**Files:**
- Create: `internal/hub/mail_slot.go`, `internal/hub/mail_override.go`, `internal/hub/mail_override_test.go`, goldens `internal/hub/testdata/golden/mail_{normal,void,unwired}.override.yml`.
- Modify:
  - `internal/state/mail.go`;
  - `internal/hub/override.go` (`renderOverrideIn` calls `mailOverrideLocked`);
  - `internal/hub/ports.go` (`mailPorts` keyed on "slot open"; the wired provider exempt);
  - `internal/runtime/runtime.go` + `docker/backend.go` + `kube/exec.go` + `runtimetest/fake.go` (`RestartService` replaces `RestartCoreService`);
  - `internal/hub/mail_restart.go`.

**Interfaces — Produces:**
- `state.MailProvider{Instance, Template, Source, Commit, BlockHash string; WiredAt time.Time; WiredBy string}`; `state.MailVoid{Reason string; Since time.Time}`; `MailSettings` gains `Provider *MailProvider`, `VoidOwed *MailVoid`, `Held *MailHold`, `RetiringDKIM map[string]RetiringDKIM`, `TLS MailTLS`, `Relay *MailRelay`, `DKIMRotate`, `FormerRetention string`.
- `type mailMode int` (`mailUnwired`, `mailVoid`, `mailNormal`); `(h *Hub) mailModeLocked(id string) mailMode` (void when `VoidOwed` or `Held`, P4).
- `(h *Hub) mailOverrideLocked(t *templates.Template, id string, mode mailMode) (string, error)` renders:
  - **normal:** the ports on `listeners.service`; `portcullis-mail-api` on `api.service` at `PROVIDER_IP` with alias `mail-api`; `portcullis-metrics-mail` with the aliases; the `mail_tls` mount; the `_mail/` mount; `group_add: ["2000"]`; the well-known labels; the env keys.
  - **void:** the API attachment, the mounts and the env with `PORTCULLIS_MAIL_VOID_SESSION`; every template network overridden `internal: true`; no ports, no router, no metrics.
  - **unwired:** nothing beyond an ordinary app.
- `(h *Hub) checkMailMountsLocked(project []byte, id string) error` → `409`:
  - `portcullis_mail_tls` only in the `tls` services of the wired instance, read-only;
  - `hub_secrets` `_mail/` only in the `gated` services, read-only, subpath exactly `<id>/_mail`.
  - Run before every `up` of every instance.
- `runtime.RestartService(ctx, project, service string, timeout time.Duration) error`: exactly one non-one-off container of that project and service, else nothing. Kubernetes → `ErrUnsupported`.
- `(h *Hub) mailRestart(ctx, why string) error` targets `portcullis-<wired>` / `sessions.restart`. `sharedRestart` is unchanged.

- [ ] **Step 1: Write the failing tests:**
  - `TestMailOverrideGoldens` (three modes, `stalwart`-shaped fixture);
  - `TestVoidModeNoPortsInternalNetworks`;
  - `TestUnwiredInstancePublishesNothing`;
  - `TestNoIPv6Publish`;
  - `TestWellknownEntrypointsFollowVPNMode` (apps / server mode → `PORTCULLIS_EP_CORE`; env entrypoints match);
  - `TestMailTLSMountedOnlyIntoTLSServices`;
  - `TestHubSecretsMailSubpathOnlyGated`;
  - `TestOtherInstanceMountingMailTLSRefused` (409);
  - `TestSlotPortCollision` (another instance on 587 → refused while the slot is open);
  - `TestRestartServiceNarrow` (zero or two matches → no restart; a one-off ignored);
  - `TestMailRestartTargetsWiredProvider`;
  - `TestNoRestartCoreService` (the runtime interface has no such method: a compile-time assertion file).
- [ ] **Step 2:** Run `go test -race ./internal/hub/ ./internal/runtime/...`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the Hub gate. Expected: PASS.
- [ ] **Step 5:** Commit (`hub: mail slot state, provider override (normal/void/unwired), mount checks, RestartService`).

### Task 7: Gate files, API secret, void-and-verify (Hub)

**Files:**
- Create: `internal/hub/mail_gate.go`, `internal/hub/mail_gate_test.go`.
- Modify: `internal/hub/mail_creds.go` (refuse create while void owed), `internal/hub/credstore.go` (an epoch mismatch with the slot open → `VoidOwed{restore}`).

**Interfaces — Produces:**
- `(h *Hub) markVoidOwedLocked(reason string) error`: saves `state.yaml` first, then writes `void-pending` and a fresh `void-session` (32 random bytes, hex), then removes `.present`. A save error leaves everything untouched and returns.
- `(h *Hub) writeMailSecretLocked(id string) error` (48 characters `[A-Za-z0-9]`, in place, 0640 gid 2000); `(h *Hub) writeMailMetricsSecretLocked(id string) error`; `(h *Hub) writeRelayPasswordLocked(id string) error`.
- `(h *Hub) runVoid(ctx context.Context, id, reason string) error`:
  1. render void + `up`;
  2. wait for `bootstrap: true` (≤ 5 min);
  3. `Void`;
  4. verify (P8);
  5. on success: write `.present`, delete `void-session` and `void-pending`, clear `VoidOwed` and save;
  6. on failure: stop the instance, keep `VoidOwed`, and record the error for the doctor.
- `(h *Hub) RunMailVoidRetry(ctx, every time.Duration)`, started by main with 5 min.

- [ ] **Step 1: Write the failing tests:**
  - `TestVoidMarkerSavedFirst` (a state save failure → no gate file changes);
  - `TestVoidVerifiesByListing`;
  - `TestVoidLeftoverCredentialRevokedThenFails` (the fake keeps one → stopped, `VoidOwed` kept);
  - `TestVoidListErrorFails`;
  - `TestPresentWrittenOnlyAfterVerify`;
  - `TestGateFilesInPlace` (same inode after rewrite);
  - `TestSecretNeverLogged` (log capture);
  - `TestCreateRefusedWhileVoidOwed` (503);
  - `TestEpochMismatchOwesVoid`;
  - `TestVoidRetryEvery5Min`.
- [ ] **Step 2:** Run `go test -race ./internal/hub/ -run 'Void|Gate|Epoch|Secret'`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the Hub gate. Expected: PASS.
- [ ] **Step 5:** Commit (`hub: mail gate files, API secret, void-and-verify`).

### Task 8: Wiring op and its guards (HTTP and host) (Hub)

**Files:**
- Create: `internal/hub/mail_wire.go`, `internal/hub/mail_wire_test.go`, `internal/httpapi/mail_provider.go`, `internal/httpapi/mail_provider_test.go`.
- Modify: `internal/httpapi/server.go` (routes), `internal/httpapi/hostctl.go` (`GET /host/mail/provider`, `POST /host/mail/install`), the parity test files (no MCP tool).

**Interfaces — Consumes:** Tasks 5–7. **Produces:**
- `(h *Hub) StartWireMail(id string, in WireRequest, actor directory.Actor) (*AsyncOp, error)`, with `WireRequest{Confirm string; Proof *freshauth.Proof; Listener string; Host bool}`. The guard order:
  1. `actor.Via == directory.ViaAI` or an MCP token → 403;
  2. not `lldap_admin` → 403;
  3. `!Host` and the proof is missing, stale or invalid → 403;
  4. `Confirm != id` → 400 "type the instance id to confirm";
  5. the slot is off → 409;
  6. another instance is wired → 409;
  7. Kubernetes → 409;
  8. the port-start gate is `refused` → 409;
  9. a port collision → 409;
  10. `api_version` unknown, or the template fails `ValidateMail` → 409.
- The op steps are spec §5.1 step 3 items 1–7, each saved before the next. Item 1 records `Provider` and `markVoidOwedLocked("wire")` in one save.
- On Hub start, `resumeMailLocked()`: `VoidOwed` → `runVoid`; a recorded provider whose last op is incomplete → resume at the first unfinished step.
- `MailWarning` (the exact text) in `GET /api/instances/{id}/mail-provider` (`{wired, mode, provider info, void, held, refused_because, warning}`), in the PUT answer and in `GET /host/mail/provider`.
- Audit `mail.provider_wired` `{instance, template, source, commit, block_hash}`, actor `host` on the host path.

- [ ] **Step 1: Write the failing tests:**
  - `TestWireGuardOrder` (table: each guard's status and text);
  - `TestWireRefusedFromAI`;
  - `TestWireRefusedForDelegate`;
  - `TestWireNeedsFreshProof`;
  - `TestWireTypedID`;
  - `TestWireHostPathNoProofButConfirm`;
  - `TestWireStepsInOrder` (normal override only after a verified void; the first document after; DNS after the first accepted document);
  - `TestWireAudit`;
  - `TestWarningTextExact`;
  - `TestNoMailWiringTool` (MCP tool list has none of wire / switch / unwire);
  - `TestWireResumesVoidAfterRestart`.
- [ ] **Step 2:** Run `go test -race ./internal/hub/ ./internal/httpapi/ -run 'Wire|Warning|MailWiring|Resume'`. Expected: FAIL.
- [ ] **Step 3:** Implement. Use the fresh-auth verification the impersonation route uses, with the listener of the request.
- [ ] **Step 4:** Run the Hub gate. Expected: PASS.
- [ ] **Step 5:** Commit (`hub: wire a mail provider (guards, op, resume, host path)`).

### Task 9: Unwire, switch, delete refusal, DKIM retention (Hub)

**Files:**
- Modify: `internal/hub/mail_wire.go`, `internal/hub/delete.go`, `internal/hub/mail_dns.go`, `internal/hub/mail_creds.go`, `internal/httpapi/mail_provider.go`, `internal/httpapi/hostctl.go` (`POST /host/mail/unwire`).
- Test: `internal/hub/mail_switch_test.go`.

**Interfaces — Produces:**
- `(h *Hub) StartUnwireMail(id string, drain bool, actor) (*AsyncOp, error)`. Same actor guards as wiring (AI 403, admin only); no proof and no typed id (the act narrows rights). The steps are spec §5.3; each provider call is bounded at 30 s, and the gate is closed whatever the provider answers.
- `(h *Hub) StartSwitchMail(to string, in SwitchRequest, actor) (*AsyncOp, error)`:
  - every wiring guard;
  - `confirm_empty` == `"<n> mailboxes start empty"`, where n = accounts in `mail-last.json`;
  - unwire (switch variant: no drain, sets kept), then wire.
  - Audit `mail.provider_switched {from, to}`.
- `voidProviderRowsLocked(reason string) int`: every active row → `voided` / `provider_changed`, audit `mail_credential.void_provider {count}`.
- `RetiringDKIM{Records []mailprovider.Record; Until time.Time}`: set on switch from the old provider's last good set per domain. It is merged into that domain's set until `Until`, and cleared per domain only after its new set's PUT succeeded and `Until` has passed.
- `DeleteInstance` → 409 "unwire it first (Settings → Mail)" while wired.

- [ ] **Step 1: Write the failing tests:**
  - `TestUnwireDrainThenRemoveSets`;
  - `TestUnwireForceRemovesNow`;
  - `TestUnwireOrder` (rows voided → void best effort → secret and `.present` deleted → unwired override → stopped);
  - `TestUnwireWithProviderDownClosesGate`;
  - `TestSwitchConfirmEmptyPhrase`;
  - `TestSwitchVoidsRowsProviderChanged`;
  - `TestSwitchKeepsOldDKIM7Days`;
  - `TestSwitchPartialDNSKeepsRetention`;
  - `TestSwitchNeverLowersDMARC` (the new set below the floor is dropped);
  - `TestSwitchMovesPorts` (never both instances publishing);
  - `TestDeleteRefusedWhileWired`;
  - `TestUnwireRefusedFromAI`;
  - `TestSwitchResumesAfterRestart` (an interrupted switch resumes through Task 8's `resumeMailLocked`; never both instances on the ports).
- [ ] **Step 2:** Run `go test -race ./internal/hub/ -run 'Unwire|Switch|DeleteRefusedWhileWired'`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the Hub gate. Expected: PASS.
- [ ] **Step 5:** Commit (`hub: unwire and switch mail providers (DKIM retention, provider_changed, delete refusal)`).

### Task 10: The template-change hold and the re-wire (Hub)

**Files:**
- Modify: `internal/hub/mail_wire.go`, the source-sync path (where installed templates are reloaded), `internal/hub/lifecycle.go` (enable / restart / reconcile `up` paths consult `mailModeLocked`).
- Test: `internal/hub/mail_hold_test.go`.

**Interfaces — Produces:**
- After every source sync, `(h *Hub) checkMailHoldLocked()`:
  - recomputes `MailBlockHash` for the wired instance;
  - on a mismatch, or a template that now fails `ValidateMail`, sets `Held{reason}` and saves, with no `up` (P4);
  - re-wiring (`StartWireMail` on the wired id, every guard) clears `Held`, records the new hash and voids.

- [ ] **Step 1: Write the failing tests:**
  - `TestTemplateChangeHoldsNoUp` (runtime fake: zero `Up` calls after the sync);
  - `TestHeldUpRendersVoidOnly` (an enable or reconcile while held renders void mode, no void run);
  - `TestUnrelatedTemplateSyncNoHold`;
  - `TestRewireClearsHoldAndVoids`;
  - `TestRewireNeedsAllGuards`;
  - `TestTemplateChangeDuringWireHolds`;
  - `TestTemplateNowInvalidHolds`.
- [ ] **Step 2:** Run `go test -race ./internal/hub/ -run 'Hold|Rewire'`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the Hub gate. Expected: PASS.
- [ ] **Step 5:** Commit (`hub: hold a mail provider whose template changed until a guarded re-wire`).

### Task 11: DNS set validation, `dmarc_floor`, the MTA-STS policy check, the main-domain set (Hub)

**Files:**
- Create: `internal/mailprovider/dnsrules.go` (+ test), `internal/hub/mail_mtasts.go` (+ test).
- Modify: `internal/hub/mail_dns.go`, `internal/hub/mail_state.go` (`dmarc_floor`), `internal/httpapi/hostctl.go` (`GET /host/mail/dns/main`).

**Interfaces — Produces:**
- `type RuleContext struct{ Domain, MailHostname, RelayInclude, DMARCFloor string; Wildcard bool }`; `func ValidateSet(c RuleContext, rs []Record) error` (the first refusal, with the vector texts).
- `dmarc_floor` = the stricter of the policy currently published (from the last good set) and `dmarc_start`.
- On a refusal, the Hub keeps the last good set, records `{domain, reason}` and reports `mail_records_wrong`.
- `GET /host/mail/dns/main` → `{"records":[…]}`: the validated main set plus the retiring DKIM, or `409 "no mail provider is wired"`.
- `(h *Hub) checkMTASTSPolicy(ctx, domain string) error` per P12, every 6 h; a refusal → `mail_records_wrong`.

- [ ] **Step 1: Write the failing tests:**
  - `TestDNSRuleVectors` (every case of `testdata/mail_dns_vectors.json`);
  - `TestRefusedSetKeepsLastGood`;
  - `TestFloorFromPublished`;
  - `TestMainDNSRouteValidated`;
  - `TestMainDNSRetiringDKIMIncluded`;
  - `TestMTASTSPolicyWrongMX`;
  - `TestMTASTSPolicySkippedWhenOff`;
  - `TestNoTLSAFromProvider` (any TLSA → refused).
- [ ] **Step 2:** Run `go test -race ./internal/mailprovider/ ./internal/hub/ -run 'DNS|Floor|MTASTS|TLSA'`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the Hub gate. Expected: PASS.
- [ ] **Step 5:** Commit (`hub: validate provider mail sets (allowlist, dmarc_floor), MTA-STS policy check, main set route`).

### Task 12: Hub-side invariants and the v2 document (Hub)

**Files:**
- Modify:
  - `internal/hub/mail_pending.go` (the pre-send check);
  - `internal/hub/mail_creds.go` (`allowed_ips` check);
  - `internal/hub/mail_state.go` (`BuildMailState` v2);
  - `internal/hub/mail_admin.go` + `internal/httpapi/mail.go` (Settings → Mail: relay host / port / username / spf_include / password, `dkim_rotate`, `former_retention`);
  - `internal/hub/mail_core.go` (core.env `PORTCULLIS_MAIL_CLIENT_IP`).
- Test: `internal/hub/mail_invariants_test.go`.

**Interfaces — Produces:**
- `(h *Hub) massRemovalLocked(next *mailprovider.MailState, last *mailprovider.MailState) (removed []Removed, needs bool)`: `needs` when `len(removed)*2 > len(last.Accounts)` and the document doesn't carry a confirmation bound to `hash(removed)`. The document isn't sent; it goes pending (the existing machinery).
- `(h *Hub) checkAllowedIPsLocked(uuid string, rows []mailprovider.Credential) []string` runs after every create and every reconcile while LAN-only is on. It revokes each row whose set ≠ the Local networks (canonical, sorted) and reports `mail_lan_only_unenforced`.
- Relay: `PUT /api/mail/settings` accepts `relay {host, port, username, spf_include, password?}`. The password goes write-only to `hub_data/mail-relay-password` (0600) and is never returned (`password_set: bool`).
- Defaults: `dkim_rotate` `4320h`, `former_retention` `720h`, relay none.

- [ ] **Step 1: Write the failing tests:**
  - `TestHubRefusesMassRemovalBeforeSend` (the fake provider without a guard receives nothing);
  - `TestMassRemovalConfirmBoundToSet`;
  - `TestDelegateNeverConfirms`;
  - `TestPendingRevokesAndRestarts`;
  - `TestAllowedIPsWiderRevoked`;
  - `TestAllowedIPsIgnoredWhenLANOff`;
  - `TestBuildMailStateV2Vector` (fixture state → the vector bytes);
  - `TestRelayPasswordWriteOnly`;
  - `TestRevokeRestartsWithin8s` (fake clock: the restart is requested within the budget);
  - `TestRowEndsOnlyOnProviderWord` (kept from the shipped suite, re-pointed).
- [ ] **Step 2:** Run `go test -race ./internal/hub/ -run 'MassRemoval|AllowedIPs|MailStateV2|Relay|Restart|RowEnds'`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the Hub gate. Expected: PASS.
- [ ] **Step 5:** Commit (`hub: Hub-side mass-removal and LAN-only checks, MailState v2, mail settings`).

### Task 13: Monitoring, the remaining host routes, backups and restores (Hub)

**Files:**
- Create: `internal/hub/mail_monitor.go` (+ test).
- Modify:
  - `internal/httpapi/hostctl.go` (`GET /host/mail/status`, `POST /host/mail/tls`, `POST /host/mail/test`, `POST /host/mail/backup`, `POST /host/mail/restore`, `POST /host/mail/action`);
  - `cmd/hub/vpn.go` `mailMain` (`hub mail provider|install|unwire|status|dns-main|tls|test|backup|restore|action|drain|domains`);
  - `internal/hub/backup.go` (reason `core`), `internal/hub/restore.go` (restoring the wired provider → `markVoidOwedLocked("restore")` before the volumes are replaced);
  - `cmd/hub/main.go` (`HUB_MAIL_SLOT_DIR`, default `/mail-slot`).

**Interfaces — Produces:**
- `(h *Hub) writeMailTargetsLocked() error`, per P7, on every wire, unwire and Hub start. Written in place.
- `POST /host/mail/tls {"spki_sha256":[1–2 × 64 hex],"not_after"}` records `TLS` and `timer_seen_at`, then calls `TLSReload` when wired.
- `POST /host/mail/backup` → `{"archive":"<rel path>"}`: `BackupInstance(wired, reason core)`, waiting for it. While `VoidOwed` or `Held`, the instance comes back in void mode, or stays stopped.
- `POST /host/mail/restore {"archive"}` restores the wired instance from that archive (owes a void).
- `hub mail …` prints JSON on stdout. Exit 0 on 2xx, 1 on a refusal (the text on stderr), 2 on usage.

- [ ] **Step 1: Write the failing tests:**
  - `TestMailTargetsEmptyWhenUnwired`;
  - `TestMailTargetsLabelsAndPath`;
  - `TestMetricsSecretGid65534` (in a temp setgid dir);
  - `TestHostTLSRecordsAndReloads`;
  - `TestHostBackupReasonCore`;
  - `TestCoreBackupDuringVoidStaysVoid`;
  - `TestInstanceRestoreOwesVoidFirst`;
  - `TestHostRoutesNotOnTCP` (404 on the three listeners);
  - `TestHubMailCLIExitCodes`.
- [ ] **Step 2:** Run `go test -race ./internal/hub/ ./internal/httpapi/ ./cmd/hub/ -run 'MailTargets|MetricsSecret|HostTLS|HostBackup|Restore|HostRoutes|HubMailCLI|CoreBackup'`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the Hub gate. Expected: PASS.
- [ ] **Step 5:** Commit (`hub: mail_slot targets, host mail routes, core backup and restore of the provider`).

### Task 14: Doctor — 24 kinds (Hub)

**Files:** Modify: `internal/doctor/mail.go`, `internal/doctor/mail_test.go`, `internal/hub/doctor_mail.go`, `internal/hub/doctor_mail_test.go`.

**Interfaces — Produces:**
- `MailKinds`, in this order: `mail_port25_blocked`, `mail_ptr_missing`, `mail_ptr_mismatch`, `mail_blocklisted`, `mail_records_wrong`, `mail_dkim_stuck`, `mail_dkim_manual`, `mail_cert_expiring`, `mail_dmarc_failures`, `mail_dmarc_promote`, `mail_mtasts_enforce`, `mail_ipv6_ptr`, `mail_client_ip_rewritten`, `mail_rate_held`, `mail_timer_missing`, `mail_dane_off`, `mail_lan_only_unenforced`, `mail_mass_removal_pending`, `mail_sync_blocked`, `mail_provider_unreachable`, `mail_provider_check`, `mail_provider_missing`, `mail_void_pending`, `mail_provider_refused`.
- Gone: `mail_hub_secret_invalid`, `mail_spam_rules_missing`, `mail_external_lookups_on`, `sessions_open`, `auth_failures:`.
- `mail_provider_check`: one finding per `x-` check that isn't ok. It shows the title and detail as plain text (clipped, HTML-escaped, no links), with severity at most Problem and no fix.
- `mail_cert_expiring` comes from `TLS.not_after` (< 14 days) or the `cert` check. `mail_timer_missing` fires when `timer_seen_at` is older than 36 h with the slot open.

- [ ] **Step 1: Write the failing tests:**
  - `TestMailKinds24`;
  - `TestProviderUnreachableAfter10Min`;
  - `TestProviderMissingWhenSlotOpen`;
  - `TestVoidPendingProblem`;
  - `TestProviderRefusedOnHold`;
  - `TestXCheckPlainTextNoFix`;
  - `TestCatalogMapping` (each catalog id → its kind, as before);
  - `TestCertExpiringFromCore`.
- [ ] **Step 2:** Run `go test -race ./internal/doctor/ ./internal/hub/ -run 'Mail'`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the Hub gate. Expected: PASS.
- [ ] **Step 5:** Commit (`doctor: mail kinds for the provider slot (24)`).

### Task 15: UI and MCP (Hub)

**Files:**
- Modify: `web/mail.js`, the instance page script (the Mail tab, deep link `#apps/<id>/mail`), the marketplace script (badge + filter), `web/index.html`, `internal/httpapi/mcptools_mail.go` (`mail_status` gains `provider`), `internal/httpapi/webui_mail_test.go`.

**Interfaces — Produces:**
- **Settings → Mail states** (spec §8):
  - closed;
  - open with no provider: a card with the installed mail instances and a Marketplace link `#marketplace?filter=mail`;
  - wired: a header row with the label, version and instance link, *Switch…*, *Unwire…*, and the void state.
- **The Mail tab:**
  - the warning text shown before the switch;
  - typed id input, then the fresh-auth popup (the mail-password popup code);
  - `GET /v1/provider`'s answer;
  - *Retry* (→ `POST /api/mail/provider/retry-void`);
  - `refused_because`.
- **Switch dialog:** the two typed fields.
- **People pages:** voided rows say "the mail server changed" or "reset by a restore".

- [ ] **Step 1: Write the failing tests:**
  - `TestWebMailStates` (the static HTML/JS assertions as in `webui_mail_test.go`: the three states' ids, the warning node's text equals `MailWarning`, no `innerHTML` with provider text);
  - `TestMCPMailStatusProvider`;
  - `TestMCPHasNoMailWiring`.
- [ ] **Step 2:** Run `go test ./internal/httpapi/ -run 'WebMail|MCPMail'`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the Hub gate, then `gh workflow run build.yml --ref mailp1`. Expected: PASS, green.
- [ ] **Step 5:** Commit (`web: Settings → Mail provider states, instance Mail tab, marketplace badge`).

---

## Stream T — Templates

### Task 16: Schema, `validate.py` `mail:`, vectors lint (templates)

**Files:**
- Modify: `schema/manifest.schema.json` (`mail` object, `additionalProperties: false`), `tests/validate.py` (`mail_errors(m, compose, app_id, compose_text) -> List[str]`, called where `vpn_errors` is), `tests/test_validate.py`, `.github/workflows/lint.yml` (step "Mail vectors match the Hub": the VPN step's shape on `internal/templates/testdata/mail_vectors.json`), `CORE_NETWORKS` / `CORE_TRAEFIK_NAMES` (+ new names, P9), `CLAUDE.md`.

**Interfaces — Consumes:** Task 2's `tests/mail_vectors.json`. **Produces:** `mail_errors` returns the Hub's texts in the Hub's order.

- [ ] **Step 1: Write the failing test:** `test_mail_vectors` in `tests/test_validate.py`. For every vector, `mail_errors(...)[:1] == ([want_error] if want_error else [])`.
- [ ] **Step 2:** Run `python3 tests/test_validate.py`. Expected: FAIL.
- [ ] **Step 3:** Implement, reusing the `vpn_*` mount and privilege helpers with a prefix argument.
- [ ] **Step 4:** Run the templates gate. Expected: PASS. Push, then `lint.yml` on `mailp1`. Expected: green, including "Mail vectors match the Hub" against Hub `mailp1`.
- [ ] **Step 5:** Commit (`validate: the mail: block (schema, rules, shared vectors)`).

### Task 17: The `stalwart` template (templates)

**Files:**
- Create:
  - `stalwart/manifest.yaml` (the spec §4 excerpt verbatim; `instances: single`; `auth: {method: custom, group_access: false, notes: "…host ports and the one mail slot…"}`; setting `dqs_key` type `secret`; `category: mail`);
  - `stalwart/compose.yml`;
  - `stalwart/gate/entrypoint.sh`;
  - `stalwart/unbound/unbound.conf`;
  - `stalwart/config/config.json`;
  - `tests/apps/stalwart.sh`;
  - `tests/mail/test_gate_entrypoint.sh` (moved from core `.github/ci/mail-gate-entrypoint.sh`, paths changed).
- Modify: `.github/workflows/lint.yml` (run the gate test).

**Interfaces — Consumes:** Task 3's facts; P2's dev image digest (from Task 19). **Produces:**
- **Services:**
  - `bootstrap` (job);
  - `stalwart` (wrapper entrypoint, `cap_add: [NET_BIND_SERVICE]`, `ulimits.nofile 65536`, `mem_limit 1g`, `pids_limit 256`, listeners 10025 / 10465 / 10587 / 10993, metrics 9180);
  - `adapter` (8080 API, 8081 well-known, 9100 metrics, uid 10010);
  - `resolver` (Unbound, healthcheck `["CMD","drill-hc","-p","5353","@127.0.0.1","dnssec.works"]`).
- **Networks:** `internal` (`internal: true`, pinned IPAM: stalwart, adapter, resolver) and `egress` (stalwart, resolver).
- **Volumes:** `data`, `etc`, `adapter_data`.
- No `ports:`, no `traefik.*` label, no anchors, `cap_drop: [ALL]` everywhere.

- [ ] **Step 1: Write the failing tests:** `tests/mail/test_gate_entrypoint.sh`, which runs the wrapper with a stub server for every P3 case:
  - absent;
  - wrong `.present`;
  - unreadable;
  - `void-pending` without session;
  - wrong nonce;
  - right nonce;
  - `.present` with `void-pending`.

  Plus `tests/apps/stalwart.sh` (compose-config, `validate.py` clean).
- [ ] **Step 2:** Run `bash tests/mail/test_gate_entrypoint.sh && python3 tests/validate.py`. Expected: FAIL.
- [ ] **Step 3:** Implement. The adapter image is the P2 `:dev-mailp1-<sha7>` digest.
- [ ] **Step 4:** Run the templates gate and the gate test. Expected: PASS. Then `lint.yml` and `test-apps.yml` (`stalwart`) on `mailp1`. Expected: green.
- [ ] **Step 5:** Commit (`stalwart: the first mail provider template`).

---

## Stream C — Core

### Task 18: The adapter speaks provider API v1 (core `mailctl/`)

**Files:**
- Modify:
  - `mailctl/internal/api/` (v1 routes);
  - `mailctl/internal/state/` (v2 doc; delete the v1 vector and code);
  - `mailctl/internal/dnsset/` (no TLSA, no HELO SPF, no `<h>` A in the main set);
  - `mailctl/internal/creds/` (list by uuid, `allowed_ips`);
  - `mailctl/internal/checks/` (catalog ids; `x-spam_rules`, `x-external_lookups`);
  - `mailctl/internal/metrics/`.
- Delete: `mailctl/internal/tlsa/` (moves to core `domains`, Task 21).
- Test: the existing suites, plus `mailctl/internal/api/v1_provider_test.go`.

**Interfaces — Consumes:** Task 1 §19, Task 2 `mailstate_v2.json`. **Produces:** the provider API v1 exactly as in Task 1.
- `POST /v1/void` destroys every AppPassword of every account (live and parked), sets `restored_at`, and answers the count.
- `POST /v1/tls/reload` reloads the certificate and answers the SPKI it serves.
- The `cert` check compares what it serves with the doc's `tls.spki_sha256`.

- [ ] **Step 1: Write the failing tests:**
  - `TestMailStateV2Vector`;
  - `TestProviderInfo`;
  - `TestVoidDestroysAll`;
  - `TestCredentialsListByUUIDEchoes`;
  - `TestCredentialsAllowedIPs`;
  - `TestDNSSetHasNoTLSAOrHELO`;
  - `TestCheckIDsInCatalog`;
  - `TestTLSReloadAnswersSPKI`;
  - `TestActionsTest`.

  These keep passing unchanged: `TestMassRemoval409AtPut`, `TestCreateCredentialAccountMismatch`, `TestDeleteCredentialByUUID`, `TestDANESwitch`, `TestCertStateConfirmed`, `TestCertDowngradeOnlyConfirmed`, `TestReportsMustBeAuthenticated`, `TestReportsProblemNoPolicyChange`, `TestLANOnlySASLAndRestrict`, `TestLANOnlyEvenWhenApplyFails`, `TestMassRemovalBoundToItsSet`.
- [ ] **Step 2:** Run `cd mailctl && go test -race ./...`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the mailctl gate. Expected: PASS.
- [ ] **Step 5:** Commit (`mailctl: provider API v1 (MailState v2, void, tls reload, credentials by uuid, neutral check ids)`).

### Task 19: The adapter's runtime inside a template, and its image (core)

**Files:**
- Modify: `mailctl/internal/config/` (env `PORTCULLIS_MAIL_*`, secret `…/slot/api-secret`, metrics secret `…/slot/metrics-secret`, relay password `…/slot/relay-password`, DQS from the template setting env `STALWART_DQS_KEY_FILE`), `mailctl/internal/bootstrap/` (`mailctl bootstrap --job`), `mailctl/main.go` (subcommands `serve`, `healthcheck`, `bootstrap --job`, `export --former <id>`; the control socket removed), `mailctl/Dockerfile`.
- Create: `.github/workflows/mailctl.yml`.

**Interfaces — Produces:**
- The adapter refuses to start (exit 1, one line) when:
  - the gate predicate (P3) fails;
  - the API secret is missing or empty;
  - `PORTCULLIS_MAIL_API_SUBNET` doesn't parse;
  - its own address isn't in it.
- `bootstrap --job` runs the base plan, writes the API key (0600) into `adapter_data`, and exits 0 only after the recovery login is refused.
- `STALWART_UPDATE_ROLE_PERMISSIONS`: the adapter records the last image digest and does the one recreate.
- **The image workflow:** `push` main on `mailctl/**` → `:edge`. `workflow_dispatch` on main → `:edge`; on another ref → `:dev-<branch>-<sha7>` (P2). Each push is cosign-signed keyless, multi-arch amd64 / arm64.

- [ ] **Step 1: Write the failing tests:**
  - `TestStartRefusedWithoutPresent`;
  - `TestStartVoidSessionNonce`;
  - `TestStartRefusedOutsideSubnet`;
  - `TestBootstrapJobVerifiesRecoveryRefused`;
  - `TestNoControlSocket`;
  - `TestRelayPasswordFromSlot`.
- [ ] **Step 2:** Run the mailctl gate. Expected: FAIL.
- [ ] **Step 3:** Implement, then `actionlint`.
- [ ] **Step 4:** Run the mailctl gate. Then `gh workflow run mailctl.yml --ref mailp1` and record the `:dev-mailp1-<sha7>` digest for Task 17. Expected: PASS, image pushed and signed.
- [ ] **Step 5:** Commit (`mailctl: run as a template adapter (gate, slot files, bootstrap job); image workflow`).

### Task 20: Slot infrastructure: compose, networks, `mail_slot`, Prometheus, alerts, chart (core)

**Files:**
- Modify:
  - `docker-compose.yml` (remove `mail`, `mailctl`, `mail-resolver`, the profile, `mail_data`, `mail_etc`, `mailctl_data`, `portcullis-mail`, `portcullis-mailctl`, `mail-egress` and the router; add `portcullis-mail-api`, `mail_slot`; `hub` joins `portcullis-mail-api` at `.18`, mounts `mail_slot:/mail-slot`, `group_add` + `"2000"` (P6), env `HUB_MAIL_API_URL`; Prometheus mounts `mail_slot:/mail-slot:ro`; `mail_tls` gid 2000);
  - `docker-compose.podman.yml`, `docker-compose.podman-selinux.yml`;
  - `scripts/lib/network.sh`, `scripts/lib/stack.sh` (`mail_slot` prepared `10001:65534 2750`);
  - `scripts/lib/common.sh` (`CT_GID_MAIL_PROVIDER=2000`);
  - `monitoring/prometheus/{prometheus.yml,alerts.yml,tests/alerts_test.yml}` (P7);
  - `charts/portcullis`, `tests/k8s_parity_deltas.yaml`;
  - `.github/ci/unit-tests-mail-wiring.sh`;
  - `CLAUDE.md`.
- Delete: `docker-compose.mail-recovery.yml`, `.github/ci/mail-gate-entrypoint.sh` (moved, Task 17).

**Interfaces — Produces:** the networks, volume, gids and env of Global Constraints. Prometheus jobs `mail-provider` and `mail-provider-server`. Alert names and expressions unchanged.

- [ ] **Step 1: Write the failing tests:**
  - `unit-tests-mail-wiring.sh` asserts on `docker compose config`: `portcullis-mail-api` internal with the subnet and the Hub at `.18`; `portcullis-metrics-mail` members; `mail_slot` mounted rw only in hub and ro only in Prometheus; the hub `group_add` contains 2000; no service named `mail`, `mailctl` or `mail-resolver`; no profile `mail`; `mail-cert` unchanged;
  - `alerts_test.yml` cases for the two jobs' `up == 0` and an empty `mail-targets.json`;
  - `tests/test_shell_libs.sh` `test_mail_slot_prepared_setgid`.
- [ ] **Step 2:** Run `bash .github/ci/unit-tests-mail-wiring.sh && promtool test rules monitoring/prometheus/tests/alerts_test.yml && bash tests/test_shell_libs.sh`. Expected: FAIL.
- [ ] **Step 3:** Implement, with the chart change in the same commit.
- [ ] **Step 4:** Run the core gate and `python3 tests/k8s_parity.py`. Expected: PASS.
- [ ] **Step 5:** Commit (`core: the mail slot infrastructure (mail-api network, mail_slot, gid 2000); the mail profile removed`).

### Task 21: TLSA and HELO SPF in `dns-tool`, the `tlsa.json` rollover, the certificate metric (core `domains/`, CLI)

**Files:**
- Create: `domains/internal/dnsplan/tlsa.go` (+ test; the code and tests moved from `mailctl/internal/tlsa`).
- Modify: `domains/tool.go` (main-domain mail set = the Hub's `dns-main` records + `<h>` TXT `v=spf1 a -all` + `_25._tcp.<h>` TLSA from `mail_acme/tlsa.json`, only while `secure`), `domains/mailcert.go` (`domains mail-tlsa status|next|switch|drop`, writes `tlsa.json` 0600 10004), `scripts/lib/mail.sh` `mail_rotate` (drives it; writes `monitoring/textfile/mail_cert.prom` with `portcullis_mail_cert_expiry_seconds`).

**Interfaces — Produces:**
- `tlsa.json` = `{"version":1,"current":"<spki hex>","next":"<hex>|null","both_since":"<rfc3339>|null"}`.
- `mail rotate` posts `hub mail tls` with `[current, next?]`.
- The rollover switches after 2×TTL + 1 day.

- [ ] **Step 1: Write the failing tests:** `TestTLSARolloverStates` (moved), `TestTLSAWithheldUnlessSecure`, `TestHELOSPFAtHostname`, `TestMainSetMergesProviderRecords`, `TestTLSAJSONStrict`, plus `test_mail_rotate_textfile` in `tests/test_cli.sh`.
- [ ] **Step 2:** Run `cd domains && go test -race ./...` and `bash tests/test_cli.sh`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the core gate. Expected: PASS.
- [ ] **Step 5:** Commit (`domains: TLSA and HELO SPF for MAIL_HOSTNAME in core (tlsa.json rollover), cert expiry metric`).

### Task 22: The domains service validates `sets/mail` (core `domains/`)

**Files:**
- Create: `domains/internal/dnsplan/mailrules.go` (+ test).
- Modify: `domains/service.go` (`PUT /domains/{name}/sets/mail` → 400 with the rule text), `.github/workflows/ci.yml` unit-tests (step "Mail DNS rule vectors match the Hub", the MailState step's shape; rename that step to v2).

**Interfaces — Consumes:** Task 2 `mail_dns_vectors.json`. **Produces:** `func ValidateMailSet(c RuleContext, rs []Record) error`, with the same texts as the Hub's `ValidateSet`.

- [ ] **Step 1: Write the failing tests:** `TestMailRuleVectors`, `TestSetsMailRefused400`.
- [ ] **Step 2:** Run `cd domains && go test -race ./...`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the core gate. Expected: PASS.
- [ ] **Step 5:** Commit (`domains: validate the mail set against the shared rules`).

### Task 23: The CLI on the host socket (core `scripts/lib/mail.sh`)

**Files:**
- Modify: `scripts/lib/mail.sh` (rewritten), `scripts/lib/dns.sh` (`hub mail dns-main`), `scripts/lib/status.sh`, `portcullis` (help), `.env.example`, `tests/test_cli.sh`, `tests/test_shell_libs.sh`.

**Interfaces — Consumes:** Task 13's `hub mail …`. **Produces:**
- `mail enable [--hostname H] [--lan-only true|false] [--provider stalwart|none] [--yes]`:
  - the refusals as today;
  - writes `PORTCULLIS_MAIL=on`, `MAIL_HOSTNAME`, `MAIL_SUBMISSION_LAN_ONLY`;
  - creates the slot, runs `mail-cert`, refreshes `core.env` (with `PORTCULLIS_MAIL_CLIENT_IP`);
  - `hub mail provider` → prints the warning → reads the typed instance id from the TTY (`--yes` = the id) → `hub mail install`;
  - prints the DNS step.
- `mail disable [--yes] [--force]`, `status [--json]`, `test --to`, `dkim rotate <d>`, `cert`, `rotate [--next-key]`, `schedule --systemd` and `export <former-id>` (spec §6.12; export execs the block's argv with `{former_id}` substituted, as an argv array, never through a shell).
- Removed: `--rotate-key`, every `mailctl` exec, the recovery session, `MAIL_RELAY_*`, `MAIL_DKIM_ROTATE`, `MAIL_FORMER_RETENTION`, `MAIL_SPAMHAUS_DQS_KEY` (no legacy hint).

- [ ] **Step 1: Write the failing tests** (in `tests/test_cli.sh`, with a stubbed `rt_exec hub`):
  - `test_mail_enable_wires_after_typed_id`;
  - `test_mail_enable_provider_none`;
  - `test_mail_enable_refusals` (kube, lego-only DNS, `MAIL_IPV6`, LAN-only on rootless Podman, port start > 25);
  - `test_mail_disable_unwires_then_off`;
  - `test_mail_export_argv_no_shell` (an id with `;` stays one argv element);
  - `test_mail_status_rows`;
  - `test_no_mailctl_exec` (grep).

  The argv secret grep covers `mail.sh`.
- [ ] **Step 2:** Run `bash tests/test_cli.sh`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the core gate. Expected: PASS.
- [ ] **Step 5:** Commit (`cli: mail on the host socket (enable installs and wires the provider, status, export)`).

### Task 24: Backup and restore through the Hub (core `scripts/lib/backup.sh`)

**Files:** Modify: `scripts/lib/backup.sh` (drop `_backup_mail_data`, `BACKUP_MAIL_STOPPED_VOLUMES`, `_restore_mail_*`; add `hub mail backup` before archiving `hub_data` and the archive name in the manifest; on restore, empty `hub_secrets` as today, then `hub mail restore {archive}` when the provider's volumes are missing), `tests/test_shell_libs.sh`.

**Interfaces — Produces:** the core backup manifest key `mail_provider_archive` (a relative path or absent).

- [ ] **Step 1: Write the failing tests:** `test_backup_calls_hub_mail_backup_first`, `test_backup_manifest_names_archive`, `test_restore_empties_hub_secrets_then_restores_provider`, `test_backup_without_slot_skips` (set -e harness).
- [ ] **Step 2:** Run `bash tests/test_shell_libs.sh`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the core gate. Expected: PASS.
- [ ] **Step 5:** Commit (`backup: the mail provider through a Hub instance backup; restore owes a void`).

### Task 25: Core CI — the templates checkout and the reworked mail steps (core)

**Files:**
- Create: `.github/ci/mail-templates-checkout.sh` (the e2e-settings "Templates" step logic, plus: fail without `stalwart/manifest.yaml` `mail:`, then the P2 image rewrite to the locally built `portcullis-mailctl:ci`).
- Modify: `.github/workflows/ci.yml` (`build-and-test`, `e2e-mail`, `e2e-podman`: build `mailctl/` → `portcullis-mailctl:ci`, run the checkout script, load `$RUNNER_TEMP/templates` plus `tests/e2e/apps` as local sources), `.github/ci/build-and-test-mail-service.sh`, `.github/ci/e2e-podman-mail.sh`, the backup / restore mail steps.

**Interfaces — Consumes:** Tasks 17, 19, 20, 23, 24. **Produces:** the spec §12 assertions, now against the template's containers:
- bootstrap;
- the recovery login refused afterwards;
- `/jmap` from another address on `internal` → 404;
- the certificate SANs and SPKI;
- the open-relay refusal;
- `mail status`;
- the timer;
- backup holds the instance archive;
- restore voids, including the Hub's verification;
- after `hub_secrets` is emptied, a raw `compose up` of `portcullis-stalwart` fails at the gate;
- on Podman: the port-start refusal, `client_ip: rewritten`, the doctor, local delivery, no ban events, and the gate wrapper.

The egress REJECT rules and the TEST-NET-1 probe (now from the template's `egress` network) stay in every mail job.

- [ ] **Step 1:** Write the new assertions into the scripts first.
- [ ] **Step 2:** Run them with `.github/ci/local/run-job.sh build-and-test --local /Volumes/workspace/portcullis/wt-mailp1/portcullis`. Expected: FAIL (before Tasks 17–24 land on the branch) or PASS (after).
- [ ] **Step 3:** Fix them until `gh workflow run ci.yml --ref mailp1 -f jobs="unit-tests build-and-test e2e-podman"` is green.
- [ ] **Step 4:** Run `bash tests/lint_ci_size.sh`. Expected: PASS (≤ 450 000).
- [ ] **Step 5:** Commit (`ci: mail checks against the stalwart template (templates checkout, local adapter image)`).

### Task 26: `mail-fake` and the conformance suite (core tests)

**Files:**
- Create:
  - `tests/e2e/mail-fake/` (Go module: `main.go`, `store.go`, `hostile.go`, tests; Dockerfile `USER 10011:10011`);
  - `tests/e2e/apps/mail-fake/{manifest.yaml,compose.yml}` (a valid `mail:` block; one service `fake` in `api`, `listeners` (dummy TCP accept-and-close on the four ports), `wellknown`, `metrics`, `tls`, `gated`, `sessions.restart`; no `export`);
  - `tests/mail-conformance/{run.py,checks_api.py,checks_proto.py}`.
- Modify: `.github/workflows/ci.yml` unit-tests (`go test` for `mail-fake`; `python3 -m py_compile` for the suite).

**Interfaces — Produces:**
- **`mail-fake`:**
  - the provider API v1 over an in-memory store, honouring the gate (P3);
  - `MAIL_FAKE_MODE=honest|hostile` from a file in its own volume, switchable by `docker exec … mail-fake mode hostile`;
  - `MAIL_FAKE_NAME` (`label` / `name`) so two copies can be told apart.
  - Hostile mode serves an A record, a foreign MX, an unset `include:`, DMARC below the floor and a CAA; omits the mass-removal 409; returns `allowed_ips` `["0.0.0.0/0"]` under LAN-only; keeps one credential across `POST /v1/void`.
- **`run.py --level api|full --api-url --secret-file --smtp-host --imap-host`** (P11): one line per check, exit 1 on any failure. The checks:
  - auth refusals (no bearer, wrong source);
  - strict JSON;
  - `account_mismatch`;
  - revoke by uuid only, idempotent;
  - `mass_removal` 409 with `removed`;
  - void empties every list;
  - `uuid` echoed;
  - `allowed_ips` exact under LAN-only.

  `full` adds: no open relay; AUTH refused on 25; a foreign `From` refused; the mail password refused on the API listener; parking `550 5.1.1` at RCPT, no bounce; LAN-only SASL from outside refused.

- [ ] **Step 1: Write the failing tests:** `go test` for `mail-fake` (`TestHonestPassesOwnAPI`, `TestHostileServesForbiddenSet`, `TestGateRefusesWithoutPresent`); `tests/mail-conformance/test_run.py` (the runner against a recorded fake answer set).
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the core gate. Expected: PASS.
- [ ] **Step 5:** Commit (`tests: mail-fake provider and the mail provider conformance suite`).

### Task 27: `e2e-mail` through the wired provider, with the new scenarios (core)

**Files:** Modify: `tests/e2e/e2e_mail.py`, `.github/ci/e2e-mail-start-stack.sh`, `.github/ci/e2e-mail-remote.sh`, `.github/workflows/ci.yml` (`e2e-mail`: templates checkout, mail-fake image build, CI-only template source `tests/e2e/apps`).

**Interfaces — Consumes:** Tasks 8–15, 23–26. **Produces:**
- Scenarios 1–10, unchanged in assertion, run through `mail enable` (which wires `stalwart`).
- The new checks, each with the `scenarios.skip` gate:
  - **`11 switch_provider`:** to `mail-fake` (honest). The sets are replaced per domain; the old `*._domainkey` records are kept and marked retiring; rows `provider_changed`; ports 25/465/587/993 now reach the fake; `portcullis-stalwart` is stopped with its volumes; audit `mail.provider_switched`. Then switch back, which voids again.
  - **`12 hostile_provider_contained`:** `mail-fake` in hostile mode:
    - each forbidden record is absent from the fakedns zone, and `mail_records_wrong` names it;
    - the Hub sends no mass-removal document;
    - the wide `allowed_ips` row is revoked, with `mail_lan_only_unenforced`;
    - the void fails → the instance is stopped, with `mail_void_pending`.
  - **`13 wiring_guards`:** wiring is refused without a fresh proof (403), with a wrong typed id (400), with an AI/MCP actor token (403; a Hub API call with the e2e helper's AI-actor token) and for a delegate (403). It succeeds with all of them, for the CI-only source template.
  - **`14 template_change_holds`:** edit the local `mail-fake` template (a comment line), then SIGHUP-sync. The container ids are unchanged, `mail_provider_refused` is reported, and the mail routes are 503. A re-wire voids and clears the hold.
  - **`15 conformance_stalwart`** (`run.py --level full`) and **`16 conformance_fake_api`** (`--level api`).

- [ ] **Step 1:** Write the scenarios. Then run `python3 tests/e2e/scenarios.py list`. Expected: the six new names.
- [ ] **Step 2:** Run `.github/ci/local/run-job.sh e2e-mail --local <wt> --scenario 11 switch_provider` (and each new one). Expected: FAIL until green.
- [ ] **Step 3:** Fix, then the full `gh workflow run ci.yml --ref mailp1 -f jobs=e2e-mail`. Expected: green, 16 scenarios plus restore.
- [ ] **Step 4:** Run `bash tests/lint_ci_size.sh && python3 tests/test_e2e_scenarios.py`. Expected: PASS.
- [ ] **Step 5:** Commit (`e2e-mail: through the stalwart provider; switch, containment, wiring guards, hold, conformance`).

---

## Stream D — Docs pages

### Task 28: Docs pages and the `stalwart` app page (docs)

**Files:**
- Create: `docs/apps/stalwart.md` (P1: the Stalwart-specific text moved out of §19 in Task 1, i.e. the services, bootstrap job, role, spam rules, GTUBE-in-Subject, DQS setting, `x-` checks and their steps).
- Modify: `docs/apps/.nav.yml`, `docs/setup/mail.md`, `docs/operations/mail.md` (slot, wiring, switch, unwire, void, hold, migration note), `hardening.md` (containment, spec §10.2), `backups.md`, `monitoring.md`, `cli.md`, `testing.md` (conformance suite, `mail-fake`, `run-job.sh --scenario`), `hub.md` (Settings → Mail, the Mail tab), `rootless-podman.md`, `docs/setup/dns.md`.

- [ ] **Step 1:** Write the pages. Every Hub text (the warning, refusals, kinds) is quoted from the code.
- [ ] **Step 2:** Run the docs gate. Expected: exit 0.
- [ ] **Step 3:** Commit (`docs: mail provider pages and the Stalwart app page`). Resync the Hub `web/docs` and commit there.

---

## Final

### Task 29: Full CI, reviews, merges, re-pin, test-server migration, cleanup (all repos)

- [ ] **Step 1: Full CI on `mailp1`:**
  - core `gh workflow run ci.yml --ref mailp1 -f jobs=all` (every job);
  - Hub `build.yml`;
  - templates `lint.yml` + `test-apps.yml`;
  - the docs build.

  All green, with the controller's own watcher running.
- [ ] **Step 2: Final reviews**, from fresh reviewers given the code, not this plan's conclusions: Hub since the base, the adapter, core CLI / compose / CI, and the templates. Route every finding, and record each ruling in the ledger.
- [ ] **Step 3: Merge** docs → Hub (wait for `edge`, `compare_ref=mailp1`) → templates → core, through detached worktrees (Global Constraints). Core's push builds `mailctl:edge`.
- [ ] **Step 4: Re-pin and clean up names.**
  - Templates commit on main: `stalwart` adapter → the `:edge` digest (`stalwart: pin the adapter to edge`).
  - Hub + templates commits: remove the old mail core names (P9). Run core CI on main. Expected: green.
- [ ] **Step 5: Test-server migration by hand.** This is spec §11 with P10. Connect with the SSH line in `2026-11-13-rootless-podman.md`.
  1. `./portcullis mail status --json > ~/mail-before.json`; `./portcullis mail disable --force --yes` (withdraws the published set at once); `sudo systemctl disable --now portcullis-mail.timer`.
  2. `git pull --ff-only && ./portcullis upgrade` with `ACME_STAGING=true`. `up --remove-orphans` drops `mail`, `mailctl` and `mail-resolver`.
  3. Delete the volumes `portcullis_mail_data`, `portcullis_mail_etc`, `portcullis_mailctl_data` and the networks `portcullis-mail`, `portcullis-mailctl`, `mail-egress`.
     - In `secrets/mail/`, delete `api-key`, `hub-secret`, `dqs-key`, `relay-password`, `mailctl-metrics-secret`, `recovery.env`, `update.env`, `.stalwart-image` and `gate/`.
     - Delete `secrets/monitoring/prometheus/mail-targets.json` and the `mail*-metrics-secret` copies.
     - Remove the `.env` keys `MAIL_RELAY_*`, `MAIL_DKIM_ROTATE`, `MAIL_FORMER_RETENTION` and `MAIL_SPAMHAUS_DQS_KEY`, noting any value to re-enter.
     - **Keep** `mail_tls`, `mail_acme`, `secrets/mail/hostname` and `former-hostnames`.
  4. With the Hub stopped: delete `hub_data/mail-last.json`; in `state.yaml` clear `mail.pending_removal` and `mail_credentials` (expected empty); keep the mail settings.
  5. `./portcullis mail enable --yes`. Then `./portcullis mail status`. Expected: provider `stalwart`, document generation 1, certificate valid (staging), DKIM pending. Re-enter the relay / DQS values from step 3 if any were set.
  6. `./portcullis dns setup --yes`; `./portcullis mail schedule --systemd`, installing the units with sudo. Expected: the mail set published, DKIM `active` within the day. The Lightsail firewall stays closed (user ruling 2026-11-16). No outbound 25.
- [ ] **Step 6: Cleanup.** Delete every `mailp1` branch (local + remote), every `wt-mailp1/*` worktree and `/tmp/merge-*`. Update memory (`mail_provider_2026_11.md`) with the rulings, follow-ups (spec §14) and parked items.
