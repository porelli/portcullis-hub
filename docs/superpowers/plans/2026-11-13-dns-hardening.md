# DNS configuration and hardening (CAA, DNSSEC, one DNS plan) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give every Portcullis name (the main domain and each enrolled domain) one DNS plan: the records Portcullis wants (address, CAA, optional nomail), the live values, a status and a fix. Also add DNSSEC status and opt-in signing. All of it comes from one Go engine that the domains service, a one-shot CLI tool and the Hub share.

**Architecture:** Two new packages in core's domains module do the work. `internal/dnsplan` covers the wanted sets, live reads, the diff, the CAA merge and judgement, and apply. `internal/dnssec` runs the chain check. `internal/fakedns` grows to cover CAA, MX, TXT, CNAME and signed zones. The long-running service applies the "due sets" in its records step and serves the plans over its API. A one-shot `domains dns …` subcommand runs as the compose service `dns-tool` (profile `tools`, egress only, credentials on stdin), and `./portcullis dns plan|setup|check` drives it for the main domain, replacing the curl/aws code in `dns.sh`. The Hub reads the plans for a DNS panel and for new doctor kinds.

**Tech Stack:** Go 1.27 (domains: lego v4.35.2, libdns v1.1.1 + providers, miekg/dns v1.1.73, aws-sdk-go-v2 route53, godo; new: `libdns/hetzner/v2`), bash + jq (core CLI), Go + vanilla JS (Hub), Zensical (docs).

**Spec:** `/Volumes/workspace/portcullis/portcullis-hub/docs/superpowers/specs/2026-11-13-dns-hardening-design.md` (binding). §11 open questions take their defaults: Q1 add a separate provider `hetzner-cloud` (Task 4), Q2 `nomail` off with an Info recommendation, Q3 Porkbun-hosted zones can't sign (guidance only).

## Global Constraints

- **Branch `dns1`** in core, Hub and docs. Worktrees: `/Volumes/workspace/portcullis/wt-dns1/portcullis`, `/Volumes/workspace/portcullis/wt-dns1/portcullis-hub`, `/Volumes/workspace/portcullis/wt-dns1/portcullis-docs`. Create them from `origin/main` with `git worktree add -b dns1 <path> origin/main`.
- **Base and merge order.** Base the branches on `main`. The polish batch (`polish1`, core + Hub) **merges first**. Before the merge task, merge `origin/main` into `dns1` (it then includes polish1) and re-run CI.
- **The docs main checkout** (`/Volumes/workspace/portcullis/portcullis-docs`) holds someone else's uncommitted work. Never edit, stash or commit there; use only the `wt-dns1` worktree.
- **Templates repo:** no change. The validator and reserved names are untouched. After the merge, re-run its "Test Apps" workflow.
- **Contract first.** Task 1 (contract §12, §14.5, §14.6) lands on docs `dns1` before any code task.
- **No back-compat or migration code** (user rule). There is no store version bump and no shim for old `.env` names. Fix the test server's old data by hand.
- **Secrets never on argv.** Provider credentials reach the tool as JSON on stdin (built with jq `env.X`). They never go in the container env, `docker inspect` or logs. Every provider error goes through `redact`.
- **Fail closed.** An unknown CA means no `caa` set (Info). Failed lookups give `unknown` / `would_issue: false`, never "ok". A tool error gives a non-zero exit. Unreadable `acme.json` means CA-only CAA.
- **Never** turn DNSSEC signing off, remove a DS, or touch NS/SOA/the apex of a zone Portcullis doesn't own. Never touch records outside spec §3, except the CAA merge rule in §4.
- **Never give `.env` main-domain credentials to a long-running service.** The domains service and the Hub never hold them.
- **Prefer mature libraries** (memory): libdns, miekg/dns, godo, aws-sdk-go-v2, lego. No hand-rolled DNS wire code.
- **TDD:** write the failing test, see it fail, implement, see it pass, commit. Run `cd domains && gofmt -l . && go vet ./... && go vet -tags testprovider ./... && go test -race ./...`. For the Hub, run `go vet ./... && go test -race ./... && gofmt -l .`. For core shell, run `bash tests/test_shell_libs.sh`, `bash tests/test_cli.sh` and `shellcheck -S warning portcullis scripts/lib/*.sh tests/*.sh`.
- **Core CI:**
  - Dispatch targeted runs with `gh workflow run ci.yml --ref dns1 -f jobs=<names>`, then one full run.
  - The `jobs-input` job reads job names from ci.yml with `yq`, so a new job needs no list edit. This plan adds no job.
  - **Only one agent dispatches core CI on `dns1` at a time**, because the concurrency group cancels.
- **Merges:**
  - Merge through temporary detached worktrees: `git worktree add --detach /tmp/merge-<repo> origin/main`, then `git merge --no-ff origin/dns1`, then push. Then remove the worktree.
  - Merge the Hub before core, then dispatch Hub `build.yml` on main with `-f compare_ref=dns1` so edge is published against core's branch. Then merge core.
  - Finally delete every `dns1` branch (local and remote) and worktree (memory: branches mainlined).
- **Test server:**
  - Connect with `ssh -o BatchMode=yes -o ConnectTimeout=10 -o IdentitiesOnly=yes -i /Volumes/Michele/Michele/Keys/AWS/PDX/PDX-lightsail.pem admin@44.244.208.227`, then run `git pull --ff-only && ./portcullis upgrade` in the install directory.
  - `ACME_STAGING=true` stays. Never touch the LLDAP `admin` user.
  - The domain is `portcullis.imbu.ca`, in zone `imbu.ca`, on the server's real DNS provider. Verify CAA and DNSSEC behaviour there with staging certificates only.
  - **Never** run `--dnssec` there: signing is zone-wide for the user's `imbu.ca`.
- **Record sets** (spec §3, verbatim values):
  - `address`: TTL 300.
  - `caa`: TTL 300, at `<d>` only. Value `0 issue "letsencrypt.org; accounturi=<uri>; validationmethods=dns-01"` plus the same as `issuewild`. CA-only form: `0 issue "letsencrypt.org; validationmethods=dns-01"`. Optional `0 iodef "<DNS_CAA_IODEF>"`.
  - `nomail`: TTL 3600. Null MX `0 .`, `v=spf1 -all`, and `_dmarc.<d>` `v=DMARC1; p=reject;`.
- **`.env`:** `DNS_CAA=true`, `DNS_CAA_ISSUER=` (non-LE CAs only), `DNS_CAA_IODEF=`, `DNS_NOMAIL=false`. Let's Encrypt production and staging both map to the issuer `letsencrypt.org`.
- **Resolvers:** `1.1.1.1:53` and `8.8.8.8:53` (`DOMAINS_RESOLVERS` overrides them in CI only). The plan refresh is throttled to one per 30 s per name.
- **polish1 overlap:**
  - Hub `web/web.go` `//go:embed` line: a certain conflict (polish1 adds 8 logo files, Task 11 adds `dns.js`). Take both.
  - DNS op names (`OpDNSApply`, `OpDNSSECSign`, `opKeyDomain`) live in `internal/hub/doctor_dns.go`, never `async.go` (polish1 T6 edits it).
  - Docs edits must pass polish1's `python3 scripts/check-lists.py` (a blank line before every list that follows a paragraph) and `scripts/check-branding.sh`. Write them that way now.
  - After any docs change (Task 1, Task 13, Task 14 catch-up), resync the Hub copies: `PORTCULLIS_DOCS_DIR=/Volumes/workspace/portcullis/wt-dns1/portcullis-docs web/docs/sync.sh` in the Hub worktree, then commit `web/docs`. Never merge the copies by hand.
- **Before or after polish1 merges:**
  - May run before: Tasks 2–6, 8, 9, and the core e2e part of Task 11 (Step 5).
  - Must run after: Task 13.
  - The rest (1, 7, 10, 11 Hub, 12) may run before; their later merge is trivial (Task 14 Step 1).

## Pre-flight rulings (2026-11-13)

All accepted as written (`.superpowers/sdd/2026-11-13-dns-hardening/preflight.md` §4). The tasks below already include them.

- **F1:** 4 admin MCP twins `get_domain_dns` (R), `get_main_dns` (R), `apply_domain_dns` (W), `enable_domain_dnssec` (D). Contract §15.10 (Task 1), mcptools + `TestAdminToolsSameAsHTTP` (Task 10).
- **F2:** DNS fixes run under op key `_domain.<name>`. `opAcceptedBody` gains a `_domain.` case, poll `GET /api/domains/{name}/op` (+ tool twin `domain_op`). `GET /api/instances/ops` excludes `_domain.*` (Tasks 1, 12).
- **F3:** `_dns_tool_input` derives `ca_server` from `ACME_STAGING` (as `config_apply` does) when `ACME_CA_SERVER` is empty (Task 8).
- **F4:** `dns_plan` / `dns_setup` / `dns_check` set `DNS_ACCOUNT_URI` from `dns_traefik_account_uri` (empty = CA-only). Shell test "dns setup keeps Traefik's pin" (Tasks 8–9).
- **F5:** The status lost-account Problem fires on `main.caa.would_issue == false` or `main-domain.env` URI ≠ `dns_traefik_account_uri`. Never compare `caa.account_uri` with Traefik's URI (Task 9).
- **F6:** `work()` runs the records step whenever `caaDueLocked`, `DueSets` or `SignRequested`, even for a ready domain with a valid cert. `caa` applies even under `keepRecords` (only `address` is skipped). `caaDueLocked` also counts a stored account CAServer/Email ≠ cfg. `account()` is called whenever a cert or CAA is due (Task 5).
- **F7:** `toolInput` carries full snake_case JSON tags (Task 7).
- **F8:** `dns_tighten_main` polls only when `DNS_CAA=true` and the provider is automated; otherwise one read, writing `main-domain.env` whenever a URI is found. `init_run` calls `dns_tighten_main` at its end (Task 9).
- **F9:** Task 12 adds `doctor.FixDNSApply: false, doctor.FixDNSSECSign: false` to `fixerTouchesData` (`doctorfix_touches_test.go`).
- **F10:** `DNS_CAA_ISSUER: pebble.test` also goes in the `e2e-instances` domains override (about ci.yml:3327) (Tasks 7, 11).
- **F11:** Task 7 adds `dns-tool` to `CORE_SERVICE_NAMES` (`scripts/lib/network.sh:179`).
- **F12:** Resync Hub `web/docs` via `sync.sh` after Tasks 1 and 13 and at Task 14 catch-up.
- **F13:** Docs follow polish1's list rule. Task 14 Step 1 runs `python3 scripts/check-lists.py` in docs after merging main.
- **F14:** Task 1 adds the audit actions `domain.dns_apply` (detail `sets=…`) and `domain.dnssec_enable` to §9.5 and §12.3.
- **F15:** (a) One helper converts `RecordRef`↔`dnsplan.Ref` (Task 5). (b) The tool builds `&Domain{Provider, Credentials}` for `buildDNSSEC` (Task 7). (c) Task 7 drops the FIFO `docker inspect`; the unit-tests jq check is the proof. (d) The tool takes `mail_from`, so the CLI plan applies the `ALERT_SMTP_FROM` rule.
- **F16:** Task 3 adds `TestBuildLookupFailureUnknown`.
- **F17:** No `dns setup --check` alias (user rule: no back-compat; overrides spec §7). The usage error points to `dns check`. Update dns.sh's hint (about :175), docs dns.md:123 and quickstart.md:175 (Tasks 8, 13).
- **F18:** Traefik provider: `${ACME_DNS_PROVIDER:-${DNS_PROVIDER:-cloudflare}}`. The `hetznerv1` probe and its fallback stay (Task 9).
- **F19:** Still ten kinds. When DNS inputs are unavailable, the doctor `Report` gains `dns_unavailable: true` (a field, not a finding) (Task 12).

## Review Focus

1. **A name that already has another CA's CAA**, e.g. `0 issue "digicert.com"` only. The plan keeps DigiCert's entry, adds ours, shows the Info "other CAs may also issue for <d>: digicert.com", and says that writing `issuewild` takes wildcard issuance away from DigiCert. Pinned by `TestMergeKeepsOtherIssuers` (Task 3).
2. **CAA values formatted differently from ours.** For example `LetsEncrypt.org`, `letsencrypt.org.`, extra spaces, parameters in another order, or `validationmethods=dns-01,http-01`. Matching must still treat them as ours and judge them the way the CA would. A critical-flag unknown tag must give `would_issue: false`. Pinned by `TestWouldIssueFormatting` (Task 3).
3. **The two resolvers disagree during an account switch** (one still caches the old pin). The service must wait until **both** resolvers see the new pin before ordering. Pinned by `TestWaitCAABothResolvers` (Task 6).
4. **A CNAME at `<d>` or `*.<d>`.** The address set shows `foreign` with a manual fix, and apply refuses to write A/AAAA next to a CNAME, naming it. Pinned by `TestCNAMEBlocksAddressApply` (Task 3).
5. **Main-domain credentials missing or empty in `.env`.** `dns setup` fails before starting the tool and names the variable (never its value), while `dns check` still works without credentials. Pinned by the shell test "dns setup: missing CLOUDFLARE_API_TOKEN names the variable" (Task 9).

---

## File structure

**Core (`/Volumes/workspace/portcullis/wt-dns1/portcullis`)**

| File | Responsibility |
|---|---|
| `domains/internal/dnssec/dnssec.go` (new) | `FindZone`, `Check` (the §5 chain check), the `DS` type, the `StatusReader` / `Signer` interfaces |
| `domains/internal/dnsplan/caa.go` (new) | `IssuerFor`, `CAAValue`, `MergeCAA`, `EffectiveCAA`, `WouldIssue` |
| `domains/internal/dnsplan/plan.go` (new) | Plan types, `Wanted`, `Build` (live read, diff, foreign records, DNSSEC block), `Apply` |
| `domains/internal/fakedns/fakedns.go` | Add CAA/MX/TXT/CNAME/SOA/DNSKEY/DS answers, NXDOMAIN, signing, validating mode and a query log |
| `domains/records.go` | The providers map (+ `hetzner-cloud`, DO wrapper, `dnssec` capability), `applySets` replacing `setRecords`, `waitCAA` |
| `domains/provider_digitalocean.go` (new) | `doProvider`: CAA through godo, everything else through libdns/digitalocean |
| `domains/signer_cloudflare.go`, `domains/signer_route53.go` (new) | Cloudflare `Signer`, Route 53 `StatusReader` |
| `domains/service.go`, `acme.go`, `store.go`, `main.go` | Due sets, account-switch order, new fields, endpoints, config, subcommands |
| `domains/tool.go` (new) | `domains dns plan\|apply\|check\|dnssec-enable`, `domains traefik-account-uri`, `domains report` |
| `docker-compose.yml` | `dns-tool` service; domains `environment` + `main-domain.env`; Traefik provider mapping |
| `scripts/lib/dns.sh` | Rewritten on the tool: plan/setup/check, Traefik URI, tighten/relax, status lines |
| `scripts/lib/stack.sh`, `config.sh`, `status.sh`, `domains.sh` | Hooks into init/up/upgrade, config apply, status, `main-domain.env`, image build helper |
| `.env.example`, `tests/test_shell_libs.sh`, `tests/test_cli.sh`, `.github/workflows/ci.yml`, `tests/e2e/e2e_instances.py`, `CLAUDE.md`, `docs/*.md` pointers | Configuration, tests, CI, docs pointers |

**Hub (`/Volumes/workspace/portcullis/wt-dns1/portcullis-hub`)**

| File | Responsibility |
|---|---|
| `internal/domains/domains.go` | `Plan` types, `Plan` / `MainPlan` / `ApplySets` / `EnableDNSSEC`, new `Domain` fields |
| `internal/hub/domains.go` | `DomainsAPI` extended; `DomainPlan`, `MainDNSPlan`, `ApplyDomainDNS`, `EnableDomainDNSSEC`; `hetzner-cloud` |
| `internal/httpapi/domains.go` | `/api/domains/{name}/dns`, `/dns/apply`, `/dnssec`, `/api/dns/main` |
| `internal/doctor/dns.go` (new) | The ten DNS kinds (§14.5) |
| `internal/hub/doctor_dns.go` (new) | DNS doctor inputs, `dns_apply` / `dnssec_sign` fixers |
| `web/dns.js` (new), `web/index.html`, `web/web.go` | The DNS panel (`PortcullisDNS.mount`) and the main-domain row |
| `internal/httpapi/mcptools_admin2.go` | Provider list text (`hetzner-cloud`) |

**Docs (`/Volumes/workspace/portcullis/wt-dns1/portcullis-docs`):** `docs/guides/integration-contracts.md`, `docs/setup/dns.md`, `docs/setup/certificates.md`, `docs/setup/quickstart.md`, `docs/operations/cli.md`, `docs/operations/hardening.md`, `docs/operations/hub.md`, `docs/operations/monitoring.md`, `docs/operations/testing.md`, `includes/abbreviations.md`.

---

### Task 1: Contract §12 / §14.5 / §14.6 / §15.10 / §9.5 (docs, first)

**Files:**
- Modify: `docs/guides/integration-contracts.md` (§12 intro and §12.1–12.4 at about lines 2178–2300, §14.5 at about 3318 and §14.6 at about 3361, plus §15.10 and §9.5). polish1 shifts these lines by about +60, and the §14.5 block will meet a trivial conflict at catch-up.
- Modify (Hub): `web/docs/*` via `sync.sh` (Step 8)

**Interfaces:**
- Produces: the binding wire shapes every later task uses (copy them exactly):
  - The plan object, as spec §3 plus `dnssec.zone`: `{name, checked_at, can_write, items: [{set, name, type, want, live, status, severity, fix, steps}], caa: {issuer, account_uri, would_issue}, dnssec: {state, zone, provider_can_sign, ds: [{key_tag, algorithm, digest_type, digest}], steps}}`. `status` is one of `ok|missing|wrong|foreign|unknown`. `severity` is one of `ok|info|warning|problem`. `fix` is one of `auto|manual|none`.
  - The domain object gains `caa_ok` (bool) and `dnssec` (state string).
  - Endpoints: `GET /domains/{name}/dns[?refresh=1]` → 200 plan. `POST /domains/{name}/dns/apply` `{"sets": [...]}` → 202 domain object (400 for an unknown set). `POST /domains/{name}/dnssec` `{"enable": true}` → 202, or 409 "provider can't sign". `GET /main/dns[?refresh=1]` → 200 plan (`can_write: false`). `GET /acme/account` → `{ca_server, account_uri, caa_issuer}`.
  - `hetzner-cloud` credentials: `api_token`.
  - The doctor finding gains `domains` (the domain names it concerns). Ten kinds and two fix kinds, as spec §8 lists them. The doctor report gains `dns_unavailable` (F19).
  - §15.10 tools (F1): `get_domain_dns` (R), `get_main_dns` (R), `apply_domain_dns` (W), `enable_domain_dnssec` (D: zone-wide, not undoable from Portcullis), `domain_op` (R, F2).
  - Op key (F2): DNS fixes run under `_domain.<name>`; 202 body `poll` = `/api/domains/{name}/op`; `GET /api/instances/ops` excludes `_domain.*`.
  - Audit actions (F14): `domain.dns_apply` (detail `sets=<a,b>`) and `domain.dnssec_enable`, in §9.5 and §12.3.

- [ ] **Step 1:** In the docs worktree, edit the §12 intro to cover three points: the main domain still uses Traefik's resolver; `dns setup` runs the domains image's one-shot `dns` tool; the service builds a read-only main-domain plan.
- [ ] **Step 2: §12.1.** Add the `dns-tool` service: profile `tools`, image `portcullis-domains`, only `domains-egress`, read-only, no volumes, no env, credentials as JSON on stdin. Also add `secrets/domains/main-domain.env` (`DOMAINS_MAIN_ACME_ACCOUNT_URI`, mode 0600, written by `up` / `upgrade`), and `DNS_CAA`, `DNS_CAA_ISSUER`, `DNS_CAA_IODEF` passed to the service.
- [ ] **Step 3: §12.2.** Add the five endpoints above, the two domain-object fields, the plan object with a field table, `hetzner-cloud` in the credentials table, and the sentence "the `records` state covers every due set (address, caa, and opted-in sets)".
- [ ] **Step 4: §12.3 and §12.4.**
  - §12.3: add the DNS panel (rows, Fix for `fix: auto`, DS values to copy, the main domain read-only with "run `./portcullis dns setup` on the server"). Add "CAA and DNSSEC never block hostnames".
  - §12.4: add the record-sets table (Global Constraints values), the CAA content and merge rule (spec §4 verbatim, plus the removal signature for the main domain from Task 3), the account-switch order, "DELETE also removes the CAA entries it wrote", and "signing is never turned off".
- [ ] **Step 5: §14.5 / §14.6.**
  - §14.5: add a "DNS (NEW)" kinds block, copying spec §8's ten kinds with severity and fix class, and add `domains` to the finding field list.
  - §14.6: add `dns_apply` (param `sets`, preview = the plan's diff lines, plan hash over the live values, `touches_data: false`) and `dnssec_sign` (preview "turns on signing for the whole zone <zone>", `touches_data: false`). Add the `_domain.<name>` op key and its poll route (F2) and the report's `dns_unavailable` (F19).
- [ ] **Step 5b: §15.10 and §9.5.** Add the five tools above to §15.10 (F1, F2) and the two audit actions to §9.5 (F14). Every new list gets a blank line before it (F13).
- [ ] **Step 6: Verify:** `zensical build --strict --clean && rm -rf site` must exit 0. Use a venv with `requirements.txt`, as CLAUDE.md says. Once polish1's scripts are on main, also run `python3 scripts/check-lists.py` and `scripts/check-branding.sh`.
- [ ] **Step 7: Commit:** `git add docs/guides/integration-contracts.md && git commit -m "contract §12/§14.5–14.6/§15.10/§9.5: dns plan, caa, dnssec, dns-tool, hetzner-cloud"`, then `git push -u origin dns1`.
- [ ] **Step 8: Hub resync (F12):** in the Hub worktree, run `PORTCULLIS_DOCS_DIR=/Volumes/workspace/portcullis/wt-dns1/portcullis-docs web/docs/sync.sh`, then `git add web/docs && git commit -m "web/docs: resync contract (dns1)"` and push.

---

### Task 2: fakedns extensions + `internal/dnssec`

**Files:**
- Modify: `domains/internal/fakedns/fakedns.go`
- Create: `domains/internal/dnssec/dnssec.go`, `domains/internal/dnssec/dnssec_test.go`, `domains/internal/fakedns/fakedns_test.go`

**Interfaces:**
- Produces (`fakedns`):
  - `func (z *Zone) SetSOA(apex string)`: marks a zone apex. The SOA query answers it, and any name under it gets that SOA in Authority.
  - `func (z *Zone) Sign(apex string) (*dns.DNSKEY, error)`: generates an ECDSAP256SHA256 KSK (flags 257, `dns.DNSKEY.Generate(256)`). DNSKEY queries answer the key plus an `RRSIG` made with `RRSIG.Sign`.
  - `func (z *Zone) PublishDS(apex string, ds ...*dns.DS)`: the DS set the parent serves for `apex`.
  - `func (z *Zone) SetBogus(apex string, bogus bool)`.
  - `type Options struct{ Validating bool }` and `func ServeWith(z *Zone, addr string, o Options) (*Server, error)`. `Serve(z, addr)` stays as `ServeWith(z, addr, Options{})`.
  - `func (s *Server) Queries() []string`: `"<TYPE> <name>"` in order, for order tests.
  - Answers come from `Zone` records (libdns RR data) for the types A, AAAA, TXT, CAA, MX, CNAME, plus DNSKEY/DS/SOA as above.
  - A name with no records and no wildcard match gets `RcodeNameError` (NXDOMAIN).
  - In validating mode: AD=1 when the zone is signed, `PublishDS` holds a DS equal to `DNSKEY.ToDS(dns.SHA256)` and it isn't bogus. SERVFAIL when a DS is published but matches no key, the zone is unsigned, or it's bogus; with CD=1 those cases answer normally with AD=0. Unsigned with no DS gives AD=0.
- Produces (`dnssec`):
  - `type State string` with the constants `Secure`, `Unsigned`, `DSMissing` (`"ds_missing"`), `DSMismatch` (`"ds_mismatch"`), `Bogus`, `Unknown`.
  - `type DS struct{ KeyTag uint16 \`json:"key_tag"\`; Algorithm uint8 \`json:"algorithm"\`; DigestType uint8 \`json:"digest_type"\`; Digest string \`json:"digest"\` }`.
  - `type Result struct{ State State; Zone string; DS []DS /* computed from the KSKs, digest type 2 */; ParentDS []DS; Err string }`.
  - `func FindZone(ctx context.Context, resolvers []string, name string) (string, error)`: SOA climb.
  - `func Check(ctx context.Context, resolvers []string, name string) Result`.
  - `type StatusReader interface{ DNSSECStatus(ctx context.Context, zone string) (status string, ds []DS, err error) }` and `type Signer interface{ StatusReader; EnableDNSSEC(ctx context.Context, zone string) error }`.

- [ ] **Step 1: Write the failing tests** in `fakedns_test.go`:
  - `TestServesCAAMXTXTCNAME`: query each type and assert the RR fields.
  - `TestNXDOMAIN`.
  - `TestValidatingAD`: signed + matching DS → AD; mismatching DS → SERVFAIL, then CD → answer.
  - `TestQueriesLogged`.
- [ ] **Step 2: Write the failing tests** in `dnssec_test.go`, table-driven over a fakedns server in validating mode with both "resolvers" pointing at it:
  - `TestCheckSecure` (`State == Secure`, `DS[0] == ParentDS[0]`).
  - `TestCheckUnsigned`.
  - `TestCheckDSMissing` (signed, no DS: `State == DSMissing` and `DS` holds the computed digest-2 entry).
  - `TestCheckDSMismatch` (DS published, no key matches).
  - `TestCheckBogus` (`SetBogus`: SERVFAIL, CD answers).
  - `TestCheckUnknown` (resolver `127.0.0.1:1`: `State == Unknown`, `Err != ""`).
  - `TestFindZoneClimbs` (`a.b.team.test` → `team.test.`).
- [ ] **Step 3: Run** `cd domains && go test ./internal/... -run 'TestServes|TestNX|TestValidating|TestQueries|TestCheck|TestFindZone' -v`. Expect FAIL (undefined symbols).
- [ ] **Step 4: Implement** the fakedns additions and `dnssec`.
  - Decision table: lookup error → `Unknown`. DS present and no computed DS equal → `DSMismatch`. DS present, keys match, and SERVFAIL-then-CD-answers (or no AD) → `Bogus`. DS present without DNSKEY → `Bogus`. AD at every resolver → `Secure`. No DNSKEY and no DS → `Unsigned`. DNSKEY without DS → `DSMissing`.
  - Use `dns.Client{Timeout: 5 * time.Second}`, EDNS0 with DO set (`m.SetEdns0(4096, true)`), and retry over TCP on `Truncated`.
- [ ] **Step 5: Run** the same command. Expect PASS. Then run `go test -race ./...` (all existing service tests must still pass with the NXDOMAIN change).
- [ ] **Step 6: Commit:** `git add domains/internal && git commit -m "domains: fakedns caa/mx/txt/cname/dnssec answers, internal/dnssec chain check"`.

---

### Task 3: `internal/dnsplan` (CAA, diff, foreign records, apply)

**Files:**
- Create: `domains/internal/dnsplan/caa.go`, `domains/internal/dnsplan/plan.go`, `domains/internal/dnsplan/caa_test.go`, `domains/internal/dnsplan/plan_test.go`

**Interfaces:**
- Consumes: `dnssec.Check`, `dnssec.FindZone`, `dnssec.DS`, `dnssec.StatusReader`, `dnssec.Signer` (Task 2); `fakedns` (tests).
- Produces:
  - Set and value constants: `SetAddress = "address"`, `SetCAA = "caa"`, `SetNoMail = "nomail"`; `Status` (`StatusOK`, `StatusMissing`, `StatusWrong`, `StatusForeign`, `StatusUnknown`); `Severity` (`SevOK`, `SevInfo`, `SevWarning`, `SevProblem`); `Fix` (`FixAuto`, `FixManual`, `FixNone`), with the Task 1 strings.
  - `type Item struct{ Set, Name, Type string; Want, Live []string; Status Status; Severity Severity; Fix Fix; Steps []string }`, with JSON tags as in Task 1.
  - `type CAAInfo struct{ Issuer, AccountURI string; WouldIssue bool }` and `type DNSSECInfo struct{ State dnssec.State; Zone string; ProviderCanSign bool; DS []dnssec.DS; Steps []string }`.
  - `type Plan struct{ Name string; CheckedAt time.Time; CanWrite bool; Items []Item; CAA CAAInfo; DNSSEC DNSSECInfo }`.
  - `type Ref struct{ Name, Type, Value string }`: relative to the zone; `Value` is libdns `RR().Data`.
  - `type Spec struct{ Name string; IPv4, IPv6 netip.Addr; CAA bool; Issuer, AccountURI, IODEF string; NoMail bool; Owned []Ref; Main bool }`. `Owned` lists the CAA entries an enrolled domain wrote. `Main` switches on the main-domain removal signature.
  - `type Provider interface{ libdns.RecordGetter; libdns.RecordSetter; libdns.RecordDeleter }`.
  - `type Input struct{ Spec Spec; Zone string; Provider Provider /* nil = read-only */; DNSSEC dnssec.StatusReader /* nil = none */; CanSign bool; ProviderName string; Resolvers []string; Now time.Time }`.
  - `func IssuerFor(caServer, override string) (issuer string, ok bool)`: `override` wins; `https://acme-v02.api.letsencrypt.org/directory` and `https://acme-staging-v02.api.letsencrypt.org/directory` give `letsencrypt.org`; anything else gives `"", false`.
  - `func CAAValue(issuer, accountURI string) string`: `"<issuer>; accounturi=<uri>; validationmethods=dns-01"`, or `"<issuer>; validationmethods=dns-01"` when the URI is empty.
  - `func Wanted(s Spec) map[string][]libdns.Record`: by set. With `s.CAA` false or `s.Issuer == ""`, there is no `caa` key.
  - `func MergeCAA(live []libdns.CAA, s Spec) (next []libdns.CAA, others []string)`: the full CAA RRset to write at `<d>`.
  - `func EffectiveCAA(ctx context.Context, resolvers []string, name string) (owner string, rrs []*dns.CAA, err error)`.
  - `func WouldIssue(rrs []*dns.CAA, issuer, accountURI string, wildcard bool) bool`.
  - `func Build(ctx context.Context, in Input) Plan`.
  - `func Apply(ctx context.Context, in Input, sets []string) (written, removed []Ref, err error)`.

**Rules the tests pin (assistant decisions grounded in spec §4):**
- **Ours (merge):** tag `issue` or `issuewild` whose issuer domain equals our issuer. The comparison is case-insensitive, ignores a trailing dot and trims whitespace. These entries are replaced; all others are kept. `iodef` is replaced only when `s.IODEF != ""`.
- **Removal with `CAA` off:**
  - Enrolled (`!Main`): exactly the `Owned` refs.
  - Main: entries with our issuer **and** the parameter `validationmethods=dns-01` (the signature Portcullis writes). The user's own LE entries without it stay.
- **`EffectiveCAA`:** query CAA at `name` via the first resolver that answers. An empty NOERROR climbs one label, stopping before the TLD. NXDOMAIN climbs too.
- **`WouldIssue`** (RFC 8659 + 8657):
  - Wildcard uses `issuewild` entries if any exist, else `issue`. An empty set issues.
  - A property with the critical flag (128) and an unknown tag means false.
  - The issuer must match. If `accounturi` is present it must equal ours. If `validationmethods` is present it must contain `dns-01`.
  - An issuer value `;` (empty) never issues.
- **`Build`:**
  - For each wanted record, live comes from the provider's `GetRecords` (when `Provider` isn't nil), compared with the resolvers' answers. Statuses: equal → `ok`; absent → `missing`; different → `wrong`.
  - `fix` is `auto` with a provider, else `manual` with steps naming each record to create.
  - Foreign items (provider only): A/AAAA/CNAME records at names under `<d>` other than `<d>` / `*.<d>`, and a CNAME at `<d>` or `*.<d>`. A CNAME whose target is NXDOMAIN is `foreign`/`warning` with the step "remove the dangling CNAME <n> → <target>". An address that isn't the server's is `foreign`/`info` "<n> doesn't reach Portcullis". `_acme-challenge` TXT records are `foreign`/`info`.
  - A live address in Cloudflare's published ranges names "proxied (orange cloud)" in the step. Embed the IPv4/IPv6 range list as a Go slice, with a comment pointing to `https://www.cloudflare.com/ips/`.
  - The CAA block: `EffectiveCAA` for `<d>` and `*.<d>`, then `WouldIssue` for both. `would_issue` is the AND of the two.
  - The DNSSEC block: `dnssec.Check`. `ProviderCanSign = in.CanSign`. When `in.DNSSEC` returns DS values, use them for `ds`; otherwise use the computed ones. Steps are spec §5's guidance, with `<provider>` = `in.ProviderName`. The unsigned step for digitalocean is "digitalocean can't sign: move the zone to sign it".
  - Recommend `nomail` (an Info item, set `nomail`, status `missing`) when `!s.NoMail` and `<d>` has no MX and no SPF TXT. The service decides the `ALERT_SMTP_FROM` part.
- **`Apply`:**
  - Per set, use `SetRecords` for the wanted RRset (CAA: the `MergeCAA` result). For `address` without an IPv6, delete AAAA at both names.
  - Refuse `address` with an error naming the CNAME when a CNAME exists at `<d>` or `*.<d>`.
  - With `CAA` off, delete the removal set.
  - Never touch NS/SOA, or names other than `<d>`, `*.<d>` and `_dmarc.<d>`.

- [ ] **Step 1: Write the failing tests** in `caa_test.go`:
  - `TestIssuerFor`: LE production and staging give `letsencrypt.org`; Pebble without override gives `ok == false`; override `pebble.test` wins.
  - `TestCAAValue`: both forms, exact strings.
  - `TestMergeKeepsOtherIssuers`: live `0 issue "digicert.com"` gives next = digicert + our issue + our issuewild, and `others == ["digicert.com"]`.
  - `TestMergeReplacesOurs`: an old `accounturi` is replaced.
  - `TestRemovalSignatureMain`: `0 issue "letsencrypt.org"` without validationmethods is kept.
  - `TestWouldIssueFormatting`: `LetsEncrypt.org.` with params reordered issues; a critical unknown tag gives false; another account URI gives false; `validationmethods=http-01` gives false; issuewild-only-other-CA blocks the wildcard but not `issue`.
  - `TestEffectiveCAAClimbs`: CAA only at `example.test`, queried at `team-a.portcullis.example.test`, gives owner `example.test`.
  - `TestEnrolledChildOwnPin`: `team-a.<main>` with its own CAA is judged on its own RRset; the main domain's pin doesn't block it.
- [ ] **Step 2: Write the failing tests** in `plan_test.go`, using a `fakedns` zone + server + `fakedns.Provider`:
  - `TestBuildAllOK` (every item `ok`, `would_issue` true).
  - `TestBuildMissingAndWrong`.
  - `TestBuildReadOnlyManualSteps` (nil Provider: `can_write` false, `fix: manual`, steps name each record).
  - `TestForeignDanglingShadowedChallenge`.
  - `TestCloudflareProxiedNamed`.
  - `TestCNAMEBlocksAddressApply`.
  - `TestApplyWritesSetsTTLs` (address 300, caa 300, nomail 3600, exact values from Global Constraints).
  - `TestApplyCAAOffRemovesOwnedOnly`.
  - `TestApplyNeverTouchesOtherNames` (records at `other.<zone>` and the apex NS unchanged).
  - `TestUnknownCASkipsCAA` (no `caa` items; one Info step "CAA skipped: unknown CA").
  - `TestNoMailRecommended`.
  - `TestBuildLookupFailureUnknown` (F16): a dead resolver (`127.0.0.1:1`) gives every item `unknown`, `would_issue: false` and `dnssec.state: unknown`.
  - Foreign records also cover ALIAS where the provider returns it (spec §3).
- [ ] **Step 3: Run** `cd domains && go test ./internal/dnsplan/ -v`. Expect FAIL.
- [ ] **Step 4: Implement** `caa.go` and `plan.go` with the interfaces and rules above.
- [ ] **Step 5: Run** the same command, then `go test -race ./...`. Expect PASS.
- [ ] **Step 6: Commit:** `git add domains/internal/dnsplan && git commit -m "domains: internal/dnsplan (record sets, caa merge and judgement, foreign records, apply)"`.

---

### Task 4: Provider capabilities: Cloudflare/Route 53 DNSSEC, DigitalOcean CAA, `hetzner-cloud`

**Files:**
- Create: `domains/signer_cloudflare.go`, `domains/signer_route53.go`, `domains/provider_digitalocean.go`, `domains/providers_test.go`
- Modify: `domains/records.go` (`providerSpec`, `providers`), `domains/go.mod` / `go.sum`

**Interfaces:**
- Consumes: `dnssec.StatusReader`, `dnssec.Signer`, `dnssec.DS` (Task 2).
- Produces:
  - `providerSpec` gains `dnssec func(c map[string]string) (dnssec.StatusReader, error)` (nil = none).
  - `func buildDNSSEC(d *Domain) (dnssec.StatusReader, bool /*canSign*/, error)`: its errors are redacted like `buildProvider`'s.
  - `type cloudflareDNSSEC struct{ token string; base string; hc *http.Client }`: `base` defaults to `https://api.cloudflare.com/client/v4`. It does `GET /zones?name=<zone>`, then `GET/PATCH /zones/{id}/dnssec` (`{"status":"active"}`), mapping `ds`/`key_tag`/`algorithm`/`digest_type`/`digest`. A 403 error says "the Cloudflare token needs the Zone › DNS Settings › Edit permission to turn on DNSSEC".
  - `type route53DNSSEC struct{ ... }`: uses `route53.Client.GetDNSSEC` (aws-sdk-go-v2 `service/route53` becomes a direct dependency) and `ListHostedZonesByName` when there's no `hosted_zone_id`. It implements **only** `StatusReader`. An AccessDenied error returns a typed error the plan treats as "no provider data".
  - `type doProvider struct{ inner *digitalocean.Provider; client *godo.Client }`: implements `dnsProvider`. CAA records go through `godo.DomainsService` (`RecordsByType`, `CreateRecord` with `DomainRecordEditRequest{Type: "CAA", Name, Data: value, Flags: int(flags), Tag: tag, TTL}`, `DeleteRecord`). Everything else goes through `inner`. `client` is built with `godo.NewFromToken(token)`; tests use `godo.New(httpClient, godo.SetBaseURL(srv.URL))`.
  - The providers map gains `"hetzner-cloud": {required: {"api_token"}}`, built with `github.com/libdns/hetzner/v2`. Read the constructor and field name from the module's source after `go get`, and record the version in the commit message. `"digitalocean"` builds `doProvider`. `"cloudflare"` and `"route53"` gain `dnssec`.

- [ ] **Step 1: Write the failing tests** in `providers_test.go`, with `httptest` fakes of the provider APIs:
  - `TestCloudflareDNSSECStatus` (maps the DS fields).
  - `TestCloudflareEnableDNSSEC` (PATCH body `{"status":"active"}`, bearer = token).
  - `TestCloudflareEnable403NamesPermission`.
  - `TestCloudflareNeverDisables`: assert no request body ever contains `"disabled"`, over every exported path.
  - `TestRoute53GetDNSSEC`.
  - `TestRoute53AccessDeniedFallsBack`.
  - `TestDigitalOceanCAASendsFlagsTag`: the POST body has `"flags":0,"tag":"issue"`, and `"issuewild"` for the wildcard entry.
  - `TestDigitalOceanNonCAAPassesThrough`.
  - `TestHetznerCloudValidateCredentials` (`validateCredentials("hetzner-cloud", {"api_token": ...})` is nil; an unknown key is an error).
  - `TestDNSSECErrorsRedacted` (a fake that echoes the token gives `[redacted]`).
- [ ] **Step 2: Run** `cd domains && go test -run 'Cloudflare|Route53|DigitalOcean|HetznerCloud|DNSSECErrors' -v .`. Expect FAIL.
- [ ] **Step 3: Implement.** Run `go get github.com/libdns/hetzner/v2@latest`, then `go mod tidy`.
- [ ] **Step 4: Run** the same command, then the full domains test command from Global Constraints. Expect PASS.
- [ ] **Step 5: Upstream (prepared, not sent).** Write the `libdns/digitalocean` fix as a patch: set `Flags`/`Tag` for CAA in its record conversion. Save it to `/tmp/libdns-digitalocean-caa.patch` and list it in the final report. Opening a PR on a third-party repo is the user's call; the local wrapper is what ships.
- [ ] **Step 6: Commit:** `git add domains && git commit -m "domains: dnssec capabilities (cloudflare sign, route53 status), digitalocean caa via godo, hetzner-cloud provider"`.

---

### Task 5: Service worker: due sets, CAA ownership, account-switch order, DELETE

**Files:**
- Modify: `domains/service.go` (`Config`, `dueLocked`, `work`, `View`, `viewLocked`), `domains/acme.go` (`obtain`), `domains/records.go` (replace `setRecords` with `applySets`, add `waitCAA`), `domains/store.go` (`Domain`)
- Test: `domains/service_test.go`

**Interfaces:**
- Consumes: `dnsplan.Spec`, `dnsplan.Apply`, `dnsplan.Ref`, `dnsplan.EffectiveCAA`, `dnsplan.WouldIssue`, `dnsplan.IssuerFor` (Task 3); `buildDNSSEC` (Task 4).
- Produces:
  - `Config` gains `CAA bool; CAAIssuer string /* resolved by IssuerFor at start; "" = unknown CA */; CAAIODEF string; MainAccountURI string; MailFrom string /* ALERT_SMTP_FROM */`.
  - `Domain` gains these fields:
    - `CAAAccountURI string \`json:"caa_account_uri,omitempty"\``: the URI the live pin was written with.
    - `CAAOK bool \`json:"caa_ok"\``.
    - `DNSSEC string \`json:"dnssec"\``.
    - `Sets []string \`json:"sets,omitempty"\``: opted-in optional sets (`nomail`).
    - `DueSets []string \`json:"due_sets,omitempty"\``.
    - `SignRequested bool \`json:"sign_requested,omitempty"\``.
  - `View` gains `CAAOK bool \`json:"caa_ok"\`` and `DNSSEC string \`json:"dnssec"\``.
  - `func (s *Service) spec(d *Domain, accountURI string) dnsplan.Spec`.
  - `func (s *Service) applySets(ctx context.Context, p dnsProvider, d *Domain, sets []string, accountURI string) ([]RecordRef, []RecordRef /*removed*/, string /*zone*/, error)`.
  - `func (s *Service) waitCAA(ctx context.Context, name, accountURI string) error`: polls with `RecordsPoll` until `WouldIssue` is true for `<d>` and `*.<d>` at **every** resolver (each one queried on its own), bounded by `RecordsWait`.
  - `func (s *Service) obtain(name string, p dnsProvider, u *acmeUser) (...)`: the account is passed in, never registered inside.
  - `func (s *Service) caaDueLocked(d *Domain, uri string) bool`: CAA on, issuer known, and either `d.CAAAccountURI != uri` or the stored account's `CAServer`/`Email` differ from `cfg` (an account switch before re-registration, F6). When CAA is off but `Records` hold CAA refs, removal is due.
  - `func refsToPlan([]RecordRef) []dnsplan.Ref` and `func refsFromPlan([]dnsplan.Ref) []RecordRef`: the single conversion point (F15a).

**Order in `work` (spec §4 "Domains service"):**
1. Whenever a cert **or** CAA is due (CAA on or off): `u, err := s.account()`, so registration happens first and `obtain`'s `u` is always defined (F6).
2. Records step (under `j.lock()`). It runs whenever a cert is due, or `caaDueLocked`, `len(DueSets) > 0` or `SignRequested` holds, **including a ready domain with a valid cert** (F6). `applySets` for `address`, `caa` (with `u.reg.URI`) and `d.Sets`/`DueSets`. When `keepRecords` is set (IPv4 unknown), only `address` is skipped; `caa` and the other sets still apply. Record refs, including the CAA entries, with `updateRecords`. Removed refs leave `d.Records`.
3. `waitCAA(name, u.reg.URI)`, then set `CAAAccountURI`.
4. Only then `obtain` (skipped when no cert is due).

`dueLocked` for a ready domain also returns true for `caaDueLocked`, `len(DueSets) > 0` and `SignRequested`. `SignRequested` calls `Signer.EnableDNSSEC` in the records step, then clears the flag. A failure goes to `last_error` with backoff, like any failure. DELETE's existing `deleteRecords` removes CAA refs, deleting only the exact data, so other CAs' entries stay.

- [ ] **Step 1: Write the failing tests** in `service_test.go`. Extend `newEnv`: `cfg.CAA = true`, `cfg.CAAIssuer = "pebble.test"`, and `ServeWith(zone, ..., Options{})`; add a `zone.SetSOA` for the test domain.
  - `TestCAAWrittenAfterRegisterBeforeOrder`: a hook logs ops. At the CAA `set` call, `e.svc.doc.Account != nil` and the value contains `accounturi=` + the stored registration URI. The server's `Queries()` shows a `CAA <name>` query after that set. The first TXT `append` (DNS-01) comes after both.
  - `TestAccountSwitchRepins`: change `svc.cfg.Email` to force a new account, kick, and wait. `CAAAccountURI` equals the new URI, and the live CAA holds only the new URI.
  - `TestWaitCAABothResolvers`: two fakedns servers. The second keeps the old pin until the test updates it; no TXT append happens before both servers show the new pin.
  - `TestDeleteRemovesCAA`: a pre-existing `0 issue "digicert.com"` at the name survives; our two entries are gone.
  - `TestCAAOffRemovesOwned`: restart with `CAA=false`. Our entries are removed and `caa_ok` is false.
  - `TestUnknownCASkipsCAAWrite` (`CAAIssuer == ""`: no CAA records written, certificate still issued).
  - `TestViewHasCAAAndDNSSEC` (`caa_ok` true, `dnssec` `"unsigned"` after ready).
  - `TestReadyDomainAppliesDueCAA` (F6): a ready domain with a valid cert and no CAA gets it written on the next kick, with no new order; the same holds with `keepRecords` set (address untouched).
- [ ] **Step 2: Run** `cd domains && go test -race -run 'CAA|AccountSwitch|DeleteRemovesCAA|ViewHas' -v .`. Expect FAIL.
- [ ] **Step 3: Implement** per the interfaces and order above. `main.go` `run()` reads `DNS_CAA` (default true; `_bool` semantics: `true`/`false` only, else refuse to start), `DNS_CAA_ISSUER`, `DNS_CAA_IODEF`, `DOMAINS_MAIN_ACME_ACCOUNT_URI` and `ALERT_SMTP_FROM`. When CAA is on, it resolves the issuer with `dnsplan.IssuerFor(cfg.CAServer, DNS_CAA_ISSUER)`; with no issuer it logs "CAA skipped: unknown CA <url> (set DNS_CAA_ISSUER)".
- [ ] **Step 4: Run** the full domains test command. Expect PASS, with every existing test green (`TestRecordsCreatedAAndAAAA` and friends now go through `applySets`).
- [ ] **Step 5: Commit:** `git add domains && git commit -m "domains: due record sets, caa pinned to the service's account before ordering, delete removes caa"`.

---

### Task 6: Service API: plans, apply, DNSSEC, main-domain plan, account

**Files:**
- Modify: `domains/service.go` (`APIHandler` and handlers)
- Test: `domains/service_test.go`

**Interfaces:**
- Consumes: `dnsplan.Build`, `dnsplan.Plan` (Task 3); `Domain` fields and `spec` (Task 5); `buildDNSSEC` (Task 4).
- Produces:
  - `func (s *Service) plan(ctx context.Context, name string, refresh bool) (dnsplan.Plan, error)`: a cache `plans map[string]cachedPlan` guarded by `mu`, built outside `mu`. A refresh within 30 s returns the cache. The worker's recheck refreshes it and updates `CAAOK` and `DNSSEC`.
  - `func (s *Service) mainPlan(ctx context.Context, refresh bool) dnsplan.Plan`: `Provider` is nil and `Spec.Main` is true, with `AccountURI = cfg.MainAccountURI`.
  - Handlers on `APIHandler`: `GET /domains/{name}/dns`, `POST /domains/{name}/dns/apply`, `POST /domains/{name}/dnssec`, `GET /main/dns`, `GET /acme/account`.
  - Apply body `{"sets": [...]}`, decoded strictly. Allowed sets are `address`, `caa`, `nomail`. Applying `nomail` also adds it to `d.Sets`. The body sets `DueSets`, kicks, and answers 202 with the view.
  - DNSSEC body: exactly `{"enable": true}` (anything else is 400). Without a `Signer` → 409 `"<provider> can't sign the zone through its API"`. Otherwise it sets `SignRequested`, kicks, and answers 202.
  - `/acme/account` → `{"ca_server", "account_uri" ("" before registration), "caa_issuer" ("" = unknown)}`.
  - The `nomail` recommendation from `dnsplan.Build` is dropped (in `plan` and `mainPlan`) when `cfg.MailFrom`'s domain is `<d>` or under it (spec §3). Test: `TestNoMailNotRecommendedForAlertSender`.

- [ ] **Step 1: Write the failing tests:**
  - `TestPlanEndpoint` (200; items include the `caa` row `ok` after ready; `can_write` true; the answer holds no credential — `assertNoCredentials` already scans bodies).
  - `TestPlanRefreshThrottled` (two `?refresh=1` within 30 s on the fake clock → one build, counted with `zone.CallCount()`).
  - `TestApplyEndpoint` (`{"sets":["nomail"]}` → 202; then the MX `0 .` exists at the name; an unknown set → 400; an unknown field → 400).
  - `TestDNSSECEndpoint409` (provider `fake` has no signer → 409).
  - `TestDNSSECEndpointSigns`: register a `fake-signer` provider in the test whose `dnssec` returns a recording `Signer`. 202, then `EnableDNSSEC` is called once, and no disable call exists in the interface.
  - `TestMainPlanReadOnly` (`can_write` false; `caa.account_uri == cfg.MainAccountURI`; never calls a provider).
  - `TestAccountEndpoint`.
  - `TestNewEndpointsNeedBearer` (401 without it).
- [ ] **Step 2: Run** `cd domains && go test -race -run 'PlanEndpoint|PlanRefresh|ApplyEndpoint|DNSSECEndpoint|MainPlan|AccountEndpoint|NewEndpoints' -v .`. Expect FAIL.
- [ ] **Step 3: Implement.** `writeJSON` and `writeError` are reused. Plan builds are bounded by `context.WithTimeout(r.Context(), 60*time.Second)`.
- [ ] **Step 4: Run** the full domains test command. Expect PASS.
- [ ] **Step 5: Commit:** `git add domains && git commit -m "domains: dns plan / apply / dnssec / main plan / acme account endpoints"`.

---

### Task 7: One-shot tool, `dns-tool` compose service, CI wiring

**Files:**
- Create: `domains/tool.go`, `domains/tool_test.go`
- Modify: `domains/main.go` (subcommand switch and usage line), `docker-compose.yml`, `scripts/lib/network.sh` (`CORE_SERVICE_NAMES` at about :179 gains `dns-tool`, F11), `.github/workflows/ci.yml` (unit-tests wiring check at about lines 371–403; build-and-test "Test the domains service" at about 1370; CI override at about 755; `e2e-instances` domains override at about 3327, F10). polish1 shifts the ci.yml lines by about +4.

**Interfaces:**
- Consumes: `dnsplan.Build`/`Apply`/`IssuerFor`, `validateCredentials`, `buildProvider`, `buildDNSSEC`, `redact`.
- Produces:
  - `domains dns plan|apply [--wait <dur>]|check|dnssec-enable` reads one JSON object from stdin (at most 64 KiB, `DisallowUnknownFields`). Every field carries an explicit tag (F7):

    ```go
    type toolInput struct {
        Name        string            `json:"name"`
        Provider    string            `json:"provider"`
        Credentials map[string]string `json:"credentials"`
        IPv4        string            `json:"ipv4"`
        IPv6        string            `json:"ipv6"`
        CAServer    string            `json:"ca_server"`
        CAA         struct {
            Enabled    bool   `json:"enabled"`
            Issuer     string `json:"issuer"`
            AccountURI string `json:"account_uri"`
            IODEF      string `json:"iodef"`
        } `json:"caa"`
        NoMail   bool     `json:"nomail"`
        Sets     []string `json:"sets"`
        MailFrom string   `json:"mail_from"` // ALERT_SMTP_FROM: drops the nomail recommendation as the service does (F15d)
    }
    ```

    - For `buildDNSSEC`, the tool builds a throwaway `&Domain{Provider: in.Provider, Credentials: in.Credentials}` (F15b).
    - `check` refuses non-empty credentials, with exit 2: "check takes no credentials".
    - An empty `provider` means read-only for `plan` (manual steps).
    - `apply` without a provider exits 2.
    - It prints the plan as JSON on stdout. Exit codes: 0, 1 (`check`: some item or the DNSSEC state has severity `problem`), 2 (usage), 3 (provider or lookup failure; message redacted on stderr).
    - `apply --wait 5m` polls `Build` read-only every 10 s until the applied sets are `ok`, then prints the final plan.
    - Resolvers come from `DOMAINS_RESOLVERS`, default `1.1.1.1:53,8.8.8.8:53`. `startTestProvider` is called first, so the testprovider build serves `fake`.
  - `domains traefik-account-uri <acme.json>` prints exactly `.letsencrypt.Account.Registration.uri` and a newline. A missing key gives exit 3 with no output. Any read or parse error prints only "no Traefik ACME account in <path>". It never prints anything else from the file.
  - `domains report --main --json` calls `http://127.0.0.1:8080/main/dns`, `/domains` and each `/domains/{n}/dns` with the bearer from `DOMAINS_API_SECRET_FILE`, and prints `{"main": <plan>, "domains": {"<name>": <plan>}}`.
  - Compose service:

    ```yaml
      dns-tool:
        image: portcullis-domains
        pull_policy: never
        profiles: [tools]
        <<: *hardening
        read_only: true
        user: "10004:10004"
        entrypoint: ["domains", "dns"]
        stdin_open: true
        networks: [domains-egress]
        mem_limit: 128m
        pids_limit: 64
    ```

    The `domains` service gains `environment: DNS_CAA: ${DNS_CAA:-true}`, `DNS_CAA_ISSUER: ${DNS_CAA_ISSUER:-}`, `DNS_CAA_IODEF: ${DNS_CAA_IODEF:-}` and `ALERT_SMTP_FROM: ${ALERT_SMTP_FROM:-}`, plus a second `env_file` entry `./secrets/domains/main-domain.env` (`required: false`).

- [ ] **Step 1: Write the failing tests** in `tool_test.go`:
  - `TestToolPlanFake` (in-process fake provider + fakedns; the JSON parses as `dnsplan.Plan`).
  - `TestToolCheckRefusesCredentials`.
  - `TestToolApplyWait`.
  - `TestToolCheckExit1OnProblem` (CAA with another `accounturi`).
  - `TestToolStdinOnly` (unknown field → exit 2; more than 64 KiB → exit 2).
  - `TestToolInputKeys` (F7): a stdin object with every snake_case key (`caa.account_uri`, `ipv4`, `ipv6`, `mail_from`, …) decodes with no error and lands in the right fields; `AccountURI` as a key is an unknown field (exit 2).
  - `TestToolErrorsRedacted`.
  - `TestTraefikAccountURI` (fixture `{"letsencrypt":{"Account":{"Email":"a@b","Registration":{"body":{},"uri":"https://acme-staging-v02.api.letsencrypt.org/acme/acct/123"},"PrivateKey":"SECRETKEY"}}}`: the output is exactly the URI line and never contains `SECRETKEY`; a file without an account gives exit 3 and empty stdout).
  - `TestReportShape` (against `httptest` of `APIHandler`).
- [ ] **Step 2: Run** `cd domains && go test -race -run 'Tool|TraefikAccount|Report' -v .`. Expect FAIL.
- [ ] **Step 3: Implement** `tool.go` and the `main.go` switch. The usage line is `usage: domains [keygen|healthcheck|enrolled|dns|traefik-account-uri|report]`.
- [ ] **Step 4: Run** the full domains test command. Expect PASS.
- [ ] **Step 5: Compose and CI.** Edit `docker-compose.yml` as above.
  - In ci.yml unit-tests, extend the jq wiring check with `$CFG_ALL`:
    - `.services["dns-tool"].profiles == ["tools"]`;
    - `[.services["dns-tool"].networks | keys[]] == ["domains-egress"]`;
    - `(.services["dns-tool"].volumes // []) == []`;
    - no `environment` and no `env_file`;
    - `read_only == true`, `user == "10004:10004"`;
    - `[.services | to_entries[] | select((.value.networks // {}) | has("domains-egress")) | .key] | sort == ["dns-tool", "domains"]`.

    Keep the existing `$CFG` line-380 assertion `== ["domains"]`.
  - In the CI override, add `dns-tool: {environment: {DOMAINS_RESOLVERS: 127.0.0.1:8053}}`.
  - In build-and-test, after `$D` is ready:
    - `dapi http://domains:8080/domains/$D/dns | jq -e` that the `caa` items are `ok`, `.caa.would_issue == true` and `.caa.account_uri == (acme/account).account_uri`.
    - The tool: `jq -n '{name:"tool.ci-domains.test",provider:"fake",credentials:{api_token:"ci-fake-token-0123456789"},ipv4:"203.0.113.10",ca_server:"https://pebble:14000/dir",caa:{enabled:true,issuer:"pebble.test"},sets:["address","caa"]}' | docker compose run --rm -T dns-tool apply --wait 60s | jq -e` that every item is `ok`.
    - `check` with no credentials, exit 0.
    - No `docker inspect` step: the unit-tests jq check (no volumes, env or env_file) is the proof (F15c).
    - Add `DNS_CAA_ISSUER: pebble.test` to the CI override's `domains.environment`, in build-and-test (about :755) **and** in `e2e-instances`' domains override (about :3327) (F10).
  - In `scripts/lib/network.sh`, add `dns-tool` to `CORE_SERVICE_NAMES` (about :179). ci.yml:536 diffs it against `--profile '*'` services (F11).
- [ ] **Step 6: Run locally:** `docker compose -f docker-compose.yml --profile '*' config -q`, then `actionlint`.
- [ ] **Step 7: Commit:** `git add domains docker-compose.yml scripts/lib/network.sh .github/workflows/ci.yml && git commit -m "domains: one-shot dns tool (stdin credentials), traefik-account-uri, report; compose dns-tool (tools profile, egress only); ci wiring"`.
- [ ] **Step 8: CI:** `gh workflow run ci.yml --ref dns1 -f jobs=unit-tests,build-and-test`. Wait for it and fix failures before Task 8.

---

### Task 8: Core CLI: `dns plan / setup / check` on the tool

**Files:**
- Modify: `scripts/lib/dns.sh` (rewrite: remove `_auth_curl`, `_dns_resolve`, `_dns_split`, `_dns_porkbun`, `_dns_cloudflare`, `_dns_digitalocean`, `_dns_hetzner`, `_dns_route53`), `scripts/lib/stack.sh` (`DNS_PROVIDERS`, `_dns_cred_vars`, `init_run` call), `scripts/lib/domains.sh` (factor `domains_image_ensure` out of `domains_age_keygen`), `portcullis` (help lines about line 50)
- Test: `tests/test_shell_libs.sh`, `tests/test_cli.sh`

**Interfaces:**
- Consumes: the tool's stdin JSON and exit codes (Task 7).
- Produces (shell functions later tasks call):
  - `_dns_cred_keys <provider>` → lines `ENV_VAR:key` (`CLOUDFLARE_API_TOKEN:api_token`, `PORKBUN_API_KEY:api_key`, `PORKBUN_SECRET_API_KEY:secret_api_key`, `AWS_ACCESS_KEY_ID:access_key_id`, `AWS_SECRET_ACCESS_KEY:secret_access_key`, `AWS_HOSTED_ZONE_ID:hosted_zone_id`, `DO_AUTH_TOKEN:auth_token`, `HETZNER_API_KEY:api_token` (hetzner), `HETZNER_API_TOKEN:api_token` (hetzner-cloud)). `_dns_cred_vars` in stack.sh derives from it.
  - `_dns_automated <provider>`: true for `cloudflare porkbun route53 digitalocean hetzner hetzner-cloud`.
  - `_dns_tool_input <mode>`: prints the JSON on stdout.
    - `mode` is `write` (with credentials) or `read` (no provider, no credentials).
    - Credentials go in through jq `env[$k]` lookups over the mapped names, so values never reach argv.
    - A required variable that is empty fails with `fail "<VAR> is not set in .env (needed for DNS_PROVIDER=<p>)"`.
    - It reads `DNS_ACCOUNT_URI` (set by callers), `DNS_SETS` (space-separated), `ACME_CA_SERVER`, `DNS_CAA`, `DNS_CAA_ISSUER`, `DNS_CAA_IODEF`, `DNS_NOMAIL`, `ALERT_SMTP_FROM` (→ `mail_from`, F15d), and the IPs. `PORTCULLIS_PUBLIC_IPV4` / `_IPV6` or `public_ip_detect`, as today.
    - When `ACME_CA_SERVER` is empty (a fresh init runs before `config_apply`), `ca_server` comes from `ACME_STAGING` with the same mapping `config_apply` uses (F3).
  - `_dns_tool <subcommand> [args]`: `domains_image_ensure`, then `_dns_tool_input … | dc run --rm --no-deps -T dns-tool "$@"`.
  - `dns_traefik_account_uri` (moved here from Task 9 so F4 can use it; definition as in Task 9).
  - `dns_plan <json>`, `dns_setup <yes> <dnssec> <only>`, `dns_check <json>`. Each sets `DNS_ACCOUNT_URI="$(dns_traefik_account_uri)"` unless the caller set it; empty means CA-only (F4).
  - The table is rendered with jq: `set name type want live status`, one row per item, then the CAA line (`issuer`, `account_uri` or "CA-only", `would_issue`) and the DNSSEC line (state, DS values, steps).
  - `cmd_dns` takes the subcommands `plan [--json]`, `setup [--yes] [--dnssec] [--only address|caa|nomail]` and `check [--json]`. There is **no** `setup --check` alias (F17): it is a `usage_error` "unknown argument --check (use: ./portcullis dns check)". Update the old hint in dns.sh (about :175). `--only` is validated (otherwise `usage_error`).
  - `help_dns`, `help_dns_plan`, `help_dns_setup` and `help_dns_check` restate the flags.
- Behaviour:
  - `setup` prints the plan. It then asks "Apply these changes? [y/N]" when stdin is a TTY and `--yes` is absent; non-interactive without `--yes` fails "non-interactive: pass --yes".
  - It then runs `_dns_tool apply --wait 5m`, the plan applies its sets, and `check` runs.
  - A non-automated provider prints the manual steps and returns 0.
  - `--dnssec` runs `_dns_tool dnssec-enable` after apply. Only `cloudflare` can; others print the plan's DNSSEC steps.
  - `init_run` calls `dns_setup true false ""` (CA-only CAA, since Traefik has no account yet; the issuer comes from `ACME_STAGING`, F3). Update the `dns_setup` stub's arity in test_cli.sh (about :631).

- [ ] **Step 1: Write the failing tests.** In `tests/test_shell_libs.sh`, stub `docker` to log argv to a file and stdin to another.
  - "dns tool: credentials only on stdin": with `CLOUDFLARE_API_TOKEN=tok-SECRET-123`, the argv log never contains `tok-SECRET-123` and the stdin log's `.credentials.api_token` equals it.
  - "dns tool: route53 mapping" (three keys).
  - "dns tool: hetzner vs hetzner-cloud mapping".
  - "dns setup: missing CLOUDFLARE_API_TOKEN names the variable" (exit non-zero, message has the name, the stub was never called).
  - "dns check: runs without credentials" (stdin has no `credentials` key).
  - "dns setup: non-interactive without --yes refuses".
  - "dns setup --yes: plan then apply then check, in that order" (argv log order).
  - "dns setup: manual provider prints steps, exit 0".
  - "dns setup --only bogus: usage error".
  - "dns setup keeps Traefik's pin" (F4): with `dns_traefik_account_uri` stubbed to a URI, the apply stdin's `.caa.account_uri` equals it; stubbed empty → `""`.
  - "dns tool: ca_server from ACME_STAGING when ACME_CA_SERVER is empty" (F3): `true` → the LE staging URL, `false` → production.
- [ ] **Step 2: Write the failing tests** in `tests/test_cli.sh`: the usage-error table gains `dns plan --bogus|unknown argument`, `dns check --bogus|unknown argument`, `dns setup --only x|--only` and `dns setup --check|dns check` (F17). The help loop already covers `dns`; add `dns plan --help`, `dns check --help` and `dns setup --help`.
- [ ] **Step 3: Run** `bash tests/test_shell_libs.sh; bash tests/test_cli.sh`. Expect the new cases to FAIL.
- [ ] **Step 4: Implement** the rewrite. Remove `require_cmd curl` from the DNS path and every `aws` reference.
- [ ] **Step 5: Run** the shell tests and `shellcheck -S warning portcullis scripts/lib/*.sh tests/*.sh`. Expect PASS.
- [ ] **Step 6: Commit:** `git add scripts portcullis tests && git commit -m "cli: dns plan / setup / check on the domains dns tool (stdin credentials); curl and aws provider code removed"`.

---

### Task 9: Core lifecycle: Traefik pin, relax on flip, `main-domain.env`, status, `.env`, Hetzner Cloud for Traefik

**Files:**
- Modify: `scripts/lib/dns.sh`, `scripts/lib/stack.sh` (`stack_up`, `upgrade_run`), `scripts/lib/config.sh` (`config_apply` flip branch at about lines 66–74), `scripts/lib/status.sh` (`status_run`, `status_textfile`), `scripts/lib/domains.sh` (`domains_fix_perms`), `docker-compose.yml` (Traefik env), `.env.example`
- Test: `tests/test_shell_libs.sh`, `tests/test_cli.sh`

**Interfaces:**
- Consumes: `_dns_tool`, `_dns_automated`, `domains traefik-account-uri`, `domains report` (Tasks 7–8).
- Produces:
  - `dns_traefik_account_uri` (written in Task 8): `docker run --rm --network none --read-only --user 0:0 --cap-drop ALL --security-opt no-new-privileges:true -v portcullis_traefik_acme:/acme:ro "$DOMAINS_IMAGE_NAME" traefik-account-uri /acme/acme.json`. It prints the URI, or nothing.
  - `dns_main_env_write <uri>`: writes `secrets/domains/main-domain.env` (`umask 077`, `DOMAINS_MAIN_ACME_ACCOUNT_URI=<uri>`). When the content changed, it runs `dc up -d domains`.
  - `dns_tighten_main`: polls `dns_traefik_account_uri` up to 180 s **only when `DNS_CAA=true` and `_dns_automated`**; otherwise it reads once (F8). Whenever a URI is found it calls `dns_main_env_write`. When `DNS_CAA` is true, the provider is automated and the live pin (`_dns_tool check` with `DNS_SETS=caa`) differs, it runs `DNS_ACCOUNT_URI=<uri> DNS_SETS=caa _dns_tool apply --wait 5m`. Every failure only `warn`s; it always returns 0.
  - `dns_relax_main`: `DNS_ACCOUNT_URI= DNS_SETS=caa _dns_tool apply`. On failure it warns "issuance will fail on CAA until ./portcullis dns setup" and returns 0.
  - `dns_status_json`: `dc exec -T domains domains report --main --json`, or empty.
- Wiring:
  - `stack_up` and `upgrade_run` call `dns_tighten_main` after `wait_healthy … keycloak` (Traefik is up by then). `init_run` also calls it at its end (F8).
  - `config_apply` calls `dns_relax_main` **before** `rm -f /acme/acme.json`, inside the flip branch, only when the provider is automated and `DNS_CAA` is true.
  - `status_run`:
    - Adds a "DNS" section: address, CAA pin, DNSSEC state, and foreign-records count. The Problem "CAA allows another ACME account than Traefik's — fix: ./portcullis dns setup" fires when `main.caa.would_issue == false`, or when `main-domain.env`'s URI ≠ `dns_traefik_account_uri` (stale). Never compare `main.caa.account_uri` with Traefik's URI: it is the wanted URI, so they are always equal (F5).
    - With no report, it prints the one line "DNS checks unavailable" (not a problem).
    - `--json` gains `dns: {main: <summary>, domains: {<name>: <summary>}}`. The jq summary is `{address_ok, caa_ok, would_issue, dnssec, foreign, problems}`.
    - Any `problem`-severity item or `dnssec` `bogus`/`ds_mismatch` sets `problems=1`.
  - `status_textfile` adds `portcullis_dns_check{name,check}` (check ∈ `address`, `caa`, `dnssec`, `foreign`; 1 = no Warning or Problem) and `portcullis_dnssec_state{name,state}` (1 for the current state).
  - Traefik env:
    - `TRAEFIK_CERTIFICATESRESOLVERS_LETSENCRYPT_ACME_DNSCHALLENGE_PROVIDER: ${ACME_DNS_PROVIDER:-${DNS_PROVIDER:-cloudflare}}` (nested default, so a hand `compose up` before `config apply` keeps the right provider, F18).
    - Add `HETZNER_API_TOKEN: ${HETZNER_API_TOKEN:-}`.
    - `config_apply` writes `ACME_DNS_PROVIDER` (= `DNS_PROVIDER`, except `hetzner-cloud` → `hetzner`) next to `ACME_CA_SERVER`.
    - It fails closed when `DNS_PROVIDER=hetzner` and `HETZNER_API_TOKEN` is set, or `hetzner-cloud` and `HETZNER_API_KEY` is set, because lego prefers the token.
    - **First** confirm that Traefik v3.7.17's go.mod pins a lego whose `providers/dns/hetzner` has `internal/hetznerv1` (`gh api repos/traefik/traefik/contents/go.mod?ref=v3.7.17`). If it doesn't, drop the Traefik mapping, keep `hetzner-cloud` for enrolled domains and `dns setup` only, and make `config_apply` refuse `DNS_PROVIDER=hetzner-cloud` for the main domain's DNS-01 with the reason. Record the outcome in the commit message.
  - `.env.example`:
    - Add `DNS_CAA=true`, `#DNS_CAA_ISSUER=`, `#DNS_CAA_IODEF=` and `DNS_NOMAIL=false`, each with one comment line.
    - Trim the provider list to "Supported: cloudflare, porkbun, route53, digitalocean, hetzner, hetzner-cloud; others (gcloud, …): records by hand".
    - Add `#HETZNER_API_TOKEN=` under a "Hetzner Cloud" heading.
  - `DNS_PROVIDERS` in stack.sh gains `hetzner-cloud`. `domains_fix_perms` covers `main-domain.env` (0600).

- [ ] **Step 1: Write the failing tests** in `tests/test_shell_libs.sh`, with stubs for `docker`/`dc`:
  - "traefik uri: helper is network none, read-only volume, root" (argv has `--network none`, `portcullis_traefik_acme:/acme:ro` and `--user 0:0`).
  - "tighten: writes main-domain.env 0600 and pins when live differs".
  - "tighten: no account within the poll window warns, returns 0" (shorten the poll with `DNS_TIGHTEN_TIMEOUT=1` for the test only).
  - "config apply flip: relax runs before acme.json is removed" (order in the call log).
  - "config apply flip: relax failure warns and goes on".
  - "status: DNS checks unavailable without the report".
  - "status --json: dns.main summary from a fixture report".
  - "status: CAA would_issue false is a problem" and "status: stale main-domain.env URI is a problem" (F5); a fixture whose `main.caa.account_uri` equals Traefik's but `would_issue` is false still reports the Problem.
  - "tighten: manual provider or DNS_CAA=false reads once, no poll" (F8; the stub is called once).
  - "init: tighten runs at the end" (F8).
  - "compose: Traefik provider falls back to DNS_PROVIDER" (F18: `docker compose config` with `DNS_PROVIDER=porkbun` and no `ACME_DNS_PROVIDER` gives `porkbun`).
  - "textfile: portcullis_dns_check and portcullis_dnssec_state lines".
  - "config apply: hetzner with HETZNER_API_TOKEN refused".
- [ ] **Step 2: Run** `bash tests/test_shell_libs.sh`. Expect the new cases to FAIL.
- [ ] **Step 3: Implement** the wiring above.
- [ ] **Step 4: Run** both shell suites and shellcheck. Expect PASS. Run `docker compose -f docker-compose.yml --profile '*' config -q`.
- [ ] **Step 5: Commit:** `git add scripts docker-compose.yml .env.example tests && git commit -m "cli: traefik caa pin after up/upgrade, relax before a staging flip, main-domain.env, status dns block + metrics, hetzner-cloud"`.
- [ ] **Step 6: CI:** `gh workflow run ci.yml --ref dns1 -f jobs=unit-tests,build-and-test`. Fix failures.

---

### Task 10: Hub: domains client, Hub methods, API routes, `hetzner-cloud`

**Files:**
- Modify: `internal/domains/domains.go`, `internal/domains/domains_test.go`, `internal/hub/domains.go` (`DomainsAPI`, `knownProviders`), `internal/hub/domains_test.go` (`fakeDomainsAPI`), `internal/httpapi/domains.go` (`registerDomains`), `internal/httpapi/domains_test.go` (`newFakeDomainsService`), `internal/httpapi/mcptools_admin2.go` (provider text at about line 64; the four DNS tools, F1), the admin tools' parity test (`TestAdminToolsSameAsHTTP`), `web/index.html` (`DOMAIN_PROVIDERS` at about line 1719)

**Interfaces:**
- Consumes: the Task 1 wire shapes.
- Produces:
  - `domains.Domain` gains `CAAOK bool \`json:"caa_ok"\`` and `DNSSEC string \`json:"dnssec"\``.
  - `type PlanItem struct{ Set, Name, Type string; Want, Live []string; Status, Severity, Fix string; Steps []string }`.
  - `type DS struct{ KeyTag, Algorithm, DigestType int; Digest string }`.
  - `type Plan struct{ Name string; CheckedAt time.Time; CanWrite bool; Items []PlanItem; CAA struct{ Issuer, AccountURI string; WouldIssue bool }; DNSSEC struct{ State, Zone string; ProviderCanSign bool; DS []DS; Steps []string } }` (JSON tags per Task 1).
  - Client methods: `func (c *Client) Plan(ctx context.Context, name string, refresh bool) (Plan, error)`, `func (c *Client) MainPlan(ctx context.Context, refresh bool) (Plan, error)`, `func (c *Client) ApplySets(ctx context.Context, name string, sets []string) (Domain, error)`, `func (c *Client) EnableDNSSEC(ctx context.Context, name string) (Domain, error)`.
  - `DomainsAPI` gains those four methods.
  - Hub methods:
    - `func (h *Hub) DomainPlan(ctx context.Context, name string, refresh bool) (domains.Plan, error)` (a known domain only, else 404).
    - `func (h *Hub) MainDNSPlan(ctx context.Context, refresh bool) (domains.Plan, error)`.
    - `func (h *Hub) ApplyDomainDNS(ctx context.Context, actor directory.Actor, name string, sets []string) (domains.Domain, error)`: audited `domain.dns_apply` with detail `sets=<a,b>`.
    - `func (h *Hub) EnableDomainDNSSEC(ctx context.Context, actor directory.Actor, name string) (domains.Domain, error)`: audited `domain.dnssec_enable`; the service's 409 passes through.
  - Routes (admins only, `adminOnly`, `noStore`): `GET /api/domains/{name}/dns` (`?refresh=1` passed through), `POST /api/domains/{name}/dns/apply` `{"sets": [...]}` (strict decode, 400 fixed message), `POST /api/domains/{name}/dnssec` `{"enable": true}`, `GET /api/dns/main`.
  - MCP tools (F1, contract §15.10), each an admin twin of its route: `get_domain_dns` (ClassRead, `GET /api/domains/{name}/dns`), `get_main_dns` (ClassRead, `GET /api/dns/main`), `apply_domain_dns` (ClassWrite, `POST /api/domains/{name}/dns/apply`, audit `domain.dns_apply`), `enable_domain_dnssec` (ClassDestructive: zone-wide and not undoable from Portcullis; `POST /api/domains/{name}/dnssec`, audit `domain.dnssec_enable`). `TestToolParity` then passes with no `noToolRoutes` entry.
  - `knownProviders` gains `"hetzner-cloud": true`. `DOMAIN_PROVIDERS` gains `'hetzner-cloud': [['api_token', 'Hetzner Cloud API token (Read & Write)', true]]`, and the `hetzner` label becomes `'DNS API token (legacy dns.hetzner.com)'`. The MCP arg text lists `hetzner-cloud`.

- [ ] **Step 1: Write the failing tests:**
  - `internal/domains/domains_test.go`: `TestPlanDecodes` (a fixture of the Task 1 plan JSON round-trips every field), `TestApplySetsBody`, `TestEnableDNSSEC409IsAPIError`.
  - `internal/hub/domains_test.go`: `TestApplyDomainDNSAudited`, `TestDomainPlanUnknown404`, `TestHetznerCloudAccepted`.
  - `internal/httpapi/domains_test.go`: extend `newFakeDomainsService` with the four endpoints. `TestDomainDNSRoutesAdminOnly` (delegate 403), `TestDomainDNSApplyStrictBody`, `TestMainDNSRoute`, `TestDNSSECConflictPassesThrough` (409 with the message). The four tools join `TestAdminToolsSameAsHTTP`; `TestToolParity` must stay green (F1).
- [ ] **Step 2: Run** `go test -race ./internal/domains/ ./internal/hub/ ./internal/httpapi/ -run 'Plan|ApplySets|EnableDNSSEC|ApplyDomainDNS|DomainPlan|HetznerCloud|DomainDNS|MainDNS|DNSSECConflict|ToolParity|AdminToolsSameAsHTTP' -v`. Expect FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `go vet ./... && go test -race ./... && gofmt -l .`. Expect PASS and empty gofmt output.
- [ ] **Step 5: Commit:** `git add internal web && git commit -m "hub: domains dns plan / apply / dnssec client and routes, main-domain plan, hetzner-cloud provider"`, then `git push -u origin dns1`.

---

### Task 11: Hub: DNS panel and main-domain row (+ core e2e-instances check)

**Files:**
- Create: `web/dns.js`, `internal/httpapi/webui_dns_test.go`
- Modify: `web/web.go` (embed list), `web/index.html` (script tag next to `folders.js`; `loadDomains` gains a "DNS" button per row, a hidden `data-dns-row` panel row, and the main-domain block above the table); core `tests/e2e/e2e_instances.py`

**polish1:** Step 5 (core e2e) may run before polish1 merges. The Hub part may too, but its `web/web.go` `//go:embed` line will conflict with polish1's 8 logo files at catch-up: take both. `dns.js` is served only on the Hub listener; never add it to `peopleStatic`. Step 7 needs `DNS_CAA_ISSUER: pebble.test` in the `e2e-instances` override (Task 7, F10).

**Interfaces:**
- Consumes: the routes from Task 10.
- Produces: `PortcullisDNS.mount(el, {name, main})` in `web/dns.js`.
  - It fetches `/api/domains/<name>/dns`, or `/api/dns/main` when `main` is true.
  - It renders one `<tr data-dns-item="<set>:<name>:<type>">` per item, with the columns set, name, type, want, live, status (with severity colour) and an action.
  - A **Fix** button (`data-dns-fix="<set>"`) appears only for `fix === 'auto'` and when not `main`. It POSTs `/api/domains/<name>/dns/apply` `{"sets": [set]}` via `apiCall`, then reloads with `?refresh=1`.
  - The CAA line shows the issuer, the account URI or "CA-only", and "would issue: yes/no".
  - The DNSSEC block shows the state, the DS values (key tag, algorithm, digest type 2, digest) with copy buttons (`navigator.clipboard.writeText`), and the steps.
  - "Turn on DNSSEC signing" (`data-dnssec-sign`) appears only when `provider_can_sign && state === 'unsigned' && !main`. Its confirm text is exactly `'Turns on signing for the whole zone ' + zone + '. Continue?'`, and it POSTs `/api/domains/<name>/dnssec` `{"enable": true}`.
  - The main domain shows no buttons, and its fix line reads "Run `./portcullis dns setup` on the server".
  - Every value goes through `escapeHtml`.
  - A **Refresh** button refetches with `?refresh=1`.

- [ ] **Step 1: Write the failing tests** in `webui_dns_test.go`, with `webAsset` string assertions:
  - `TestDNSPanelAsset`: contains `"/api/domains/' + encodeURIComponent(name) + '/dns'"`, `"/api/dns/main"`, `"fix === 'auto'"`, `"'Turns on signing for the whole zone '"`, `"navigator.clipboard.writeText("`, `"escapeHtml("`, `"./portcullis dns setup"`; contains no `"enable\": false"` and no `"disable"`.
  - `TestDNSPanelEmbedded` (`index.html` has `<script src="/static/dns.js">`; web.go embeds it).
  - `TestMainDomainRowReadOnly` (`index.html` mounts with `main: true`).
- [ ] **Step 2: Run** `go test ./internal/httpapi/ -run 'DNSPanel|MainDomainRow' -v`. Expect FAIL.
- [ ] **Step 3: Implement** `web/dns.js` and the `index.html` hooks, following the existing `loadDomains` markup style.
- [ ] **Step 4: Run** the Hub test command. Expect PASS.
- [ ] **Step 5: Core e2e.** In `tests/e2e/e2e_instances.py`, add the check `domains_dns_panel`. As the admin page already used for Settings, it opens `#settings/domains`, clicks the DNS button for `E2E_EXTRA`, and waits for `[data-dns-item^="caa:"]`. It asserts that each such row contains `ok` and that the CAA line says `would issue: yes`. Commit it in core: `git add tests/e2e/e2e_instances.py && git commit -m "e2e-instances: dns panel rows for the enrolled domain"`.
- [ ] **Step 6: Commit (Hub):** `git add web internal/httpapi/webui_dns_test.go && git commit -m "hub: dns panel per domain (fix, ds values, dnssec signing) and read-only main-domain plan"`, then push.
- [ ] **Step 7: CI:** `gh workflow run ci.yml --ref dns1 -f jobs=e2e-instances` (it builds the same-named Hub branch). Fix failures.

---

### Task 12: Hub doctor: DNS kinds and fixes

**Files:**
- Create: `internal/doctor/dns.go`, `internal/doctor/dns_test.go`, `internal/hub/doctor_dns.go`, `internal/hub/doctor_dns_test.go`
- Modify: `internal/doctor/doctor.go` (`Finding.Domains`, `Inputs.DNS`, `Inputs.DNSMain`, `Report.DNSUnavailable`), `internal/hub/doctor.go` (`doctorInputs`), `internal/hub/doctorfix_touches_test.go` (`fixerTouchesData`, F9), `internal/httpapi/folders.go` (`opAcceptedBody` `_domain.` case, F2), `internal/httpapi/domains.go` (`GET /api/domains/{name}/op`), `internal/httpapi/mcptools_doctor.go` or `mcptools_admin2.go` (`domain_op` tool), the `GET /api/instances/ops` handler (exclude `_domain.*`)
- **Not** `internal/hub/async.go`: the op names live in `doctor_dns.go` (polish1 T6 edits async.go), as `OpRebind` lives in doctorfix.go.

**Interfaces:**
- Consumes: `domains.Plan` (Task 10); `RegisterFixer`, `FixPlan`, `startAsync`, `statusErr` (existing).
- Produces:
  - `Finding` gains `Domains []string \`json:"domains,omitempty"\``.
  - `Inputs` gains `DNS []domains.Plan` (enrolled; nil = unavailable) and `DNSMain *domains.Plan`.
  - Kind constants: `KindDNSRecordsWrong = "dns_records_wrong"`, `KindDNSCAAMissing = "dns_caa_missing"`, `KindDNSCAAWrongAccount = "dns_caa_wrong_account"`, `KindDNSCAAOtherIssuers = "dns_caa_other_issuers"`, `KindDNSSECBogus = "dnssec_bogus"`, `KindDNSSECDSMissing = "dnssec_ds_missing"`, `KindDNSSECUnsigned = "dnssec_unsigned"`, `KindDNSDangling = "dns_dangling"`, `KindDNSShadowed = "dns_shadowed"`, `KindDNSNoMailRecommended = "dns_nomail_recommended"`. Fix kinds: `FixDNSApply = "dns_apply"`, `FixDNSSECSign = "dnssec_sign"`.
  - The mapping from a plan, enrolled and main alike (with the main domain always explain-only, whose step is "Run `./portcullis dns setup` on the server"):
    - an `address` item `missing`/`wrong` → `dns_records_wrong`, Problem, one-click `dns_apply` (param `sets=address`);
    - a `caa` item `missing` → `dns_caa_missing`, Warning, one-click `sets=caa`;
    - `caa.would_issue == false` with a live pin naming another `accounturi` → `dns_caa_wrong_account`, Problem, one-click `sets=caa`;
    - an Info step "other CAs may also issue" → `dns_caa_other_issuers`, Info;
    - dnssec `bogus`/`ds_mismatch` → `dnssec_bogus`, Problem, explain with the steps;
    - `ds_missing` → `dnssec_ds_missing`, Warning, explain with the DS steps;
    - `unsigned` → `dnssec_unsigned`, Info, one-click `dnssec_sign` when `provider_can_sign` and not main, else explain;
    - a `foreign`/`warning` item → `dns_dangling`, Warning, explain;
    - a `foreign`/`info` item that isn't a challenge → `dns_shadowed`, Info;
    - a `nomail` `missing` item → `dns_nomail_recommended`, Info, one-click `sets=nomail` (not main).
  - Fingerprints: `Fingerprint(kind, name)`. For dangling/shadowed: `Fingerprint(kind, name, item.Name)`. `Inputs: Digest(the item's live values)`. `Domains: [name]`.
  - Fixers in `internal/hub/doctor_dns.go`:
    - `dnsApplyFixer{}`: `TouchesData() false`. Preview re-fetches `DomainPlan(refresh=true)`; its lines are `"<set> <name> <type>: <live or —> → <want>"` per differing item; `Hash = doctor.Digest(live values of those items)`. Apply recomputes and returns 409 `"the DNS records changed since the preview: preview it again"` on a mismatch, else `startAsync(opKeyDomain(name), OpDNSApply, …)` calling `ApplyDomainDNS`.
    - `dnssecSignFixer{}`: `TouchesData() false`. Its preview line is `"turns on signing for the whole zone <zone>"` and its hash is the digest of `{zone, state}`. Apply calls `EnableDomainDNSSEC` under `startAsync(opKeyDomain(name), OpDNSSECSign, …)`.
    - `func opKeyDomain(name string) string { return "_domain." + name }`, plus `OpDNSApply = "dns_apply"` and `OpDNSSECSign = "dnssec_sign"`, all in `doctor_dns.go`.
  - The op route (F2): `opAcceptedBody` gains `case strings.CutPrefix(op.Instance, "_domain.")` → `body["domain"] = name`, `body["poll"] = "/api/domains/" + name + "/op"`. `GET /api/domains/{name}/op` (admin, `noStore`) answers `writeOpRecord(w, opKeyDomain(name), "domain "+name)`. Its twin tool `domain_op` (ClassRead) returns `s.opRecordOf(opKeyDomain(name), …)`, like `folder_op`. `GET /api/instances/ops` skips `_domain.*` keys.
  - `doctorInputs` calls `h.dnsDoctorInputs(ctx)` before `mu`. It uses the cached plans (no refresh, a 10 s bound). When the service is unavailable it logs and leaves `Inputs.DNS` nil: no DNS findings, and `Run` sets `Report.DNSUnavailable` (`json:"dns_unavailable,omitempty"`), so a clean report never hides that DNS checks didn't run (F19). Still exactly ten kinds.

- [ ] **Step 1: Write the failing tests:**
  - `internal/doctor/dns_test.go`: one table test per kind (`TestDNSKinds`), asserting severity, class, fix kind, params and `Domains`. Also `TestDNSMainExplainOnly`, `TestDNSFingerprintStable` (the same plan with items reordered gives the same fps; a changed live value changes `Inputs` but not `FP`), `TestDNSUnavailableNoFindings` (no findings **and** `Report.DNSUnavailable == true`, F19) and `TestDNSKindsRegistered` (`Kinds()` contains all ten).
  - `internal/hub/doctor_dns_test.go`: `TestDNSApplyPreviewHash`, `TestDNSApplyHashMismatch409`, `TestDNSSECSignPreviewLine`, `TestDNSFixersTouchNoData`. Add `doctor.FixDNSApply: false, doctor.FixDNSSECSign: false` to `fixerTouchesData` so the existing `TestFixersDeclareTouchesData` passes (F9).
  - `internal/httpapi`: `TestDomainOpAcceptedPoll` (a DNS fix's 202 body has `poll == "/api/domains/<n>/op"` and that route answers the record), `TestInstanceOpsExcludeDomain`; `TestToolParity` stays green with `domain_op` (F2).
- [ ] **Step 2: Run** `go test -race ./internal/doctor/ ./internal/hub/ ./internal/httpapi/ -run 'DNS|FixersDeclareTouchesData|DomainOp|InstanceOpsExclude|ToolParity' -v`. Expect FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the Hub test command. Expect PASS. The MCP doctor tools need no change: verify that the `doctor_apply_fix` tests still pass and that the `portcullis://doctor/checks` resource lists the new kinds.
- [ ] **Step 5: Commit:** `git add internal && git commit -m "hub doctor: dns kinds (records, caa, dnssec, dangling, shadowed, nomail) and dns_apply / dnssec_sign fixes"`, then push.

---

### Task 13: Docs pages and CLAUDE.md files

**polish1:** run this task **after** polish1 merges. First merge `origin/main` into the docs, core and Hub `dns1` worktrees: hardening/hub/testing.md and both CLAUDE.md files overlap polish1, and its `check-lists.py` / `check-branding.sh` must then pass.

**Files:**
- Modify (docs worktree): `docs/setup/dns.md`, `docs/setup/certificates.md` ("Switching"), `docs/setup/quickstart.md` (the CAA lines at about 39 and 179), `docs/operations/cli.md`, `docs/operations/hardening.md`, `docs/operations/hub.md`, `docs/operations/monitoring.md`, `docs/operations/testing.md`, `includes/abbreviations.md`
- Modify (core): `CLAUDE.md` (the domains bullet's provider list + `hetzner-cloud`, the `dns.sh` description, Key Files rows for `internal/dnsplan` / `internal/dnssec` / `tool.go`, the CI notes for `dns-tool`). Leave `docs/*.md` pointers as one-liners; fix a pointer only if a heading it links to was renamed.
- Modify (Hub): `CLAUDE.md` (the `internal/domains`, `internal/doctor` and `web/` rows).

- [ ] **Step 1: `setup/dns.md`.** Rewrite it around `dns plan / setup / check`, with new sections:
  - "Record sets" (the table);
  - "CAA" (content, pin vs CA-only, merge rule, account switches, the `DNS_CAA*` settings, lego-only providers by hand);
  - "DNSSEC" (each state with its fix; registrar DS steps; "**Never turn signing off while a DS record is published**: validating resolvers then can't reach the domain");
  - Hetzner (legacy vs `hetzner-cloud`, and the Traefik outcome from Task 9);
  - "Other providers".

  Keep the headings that core pointers link to ("Adding extra domains", "One domain per installation").
- [ ] **Step 2: Other pages.**
  - `certificates.md` "Switching": relax before the flip, tighten after `up`, the lost-account Problem.
  - `quickstart.md`: CAA is now handled by `dns setup`. Replace `dns setup --check` with `dns check` (about :175; F17). Do the same in `dns.md` (about :123).
  - `cli.md`: restate the real `./portcullis dns --help`, `dns plan --help`, `dns setup --help` and `dns check --help` output (run them in the core worktree).
  - `hardening.md`: a `dns-tool` row (egress only, no mounts, stdin credentials) and the `traefik-account-uri` helper (network none, read-only, prints only the URI).
  - `hub.md`: the DNS panel and the doctor kinds.
  - `monitoring.md`: the two metrics.
  - `testing.md`: the new CI checks.
  - Glossary entries for "DNS plan", "CAA" and "DS record".
- [ ] **Step 3: Verify:**
  - `zensical build --strict --clean && rm -rf site` exits 0.
  - The CLAUDE.md legacy grep is empty: `grep -rnE 'bootstrap\.sh|apply-config|configure-keycloak|register-oidc|setup-vault-pki|vault-init\.sh|enroll-yubikey|renew-yubikey|revoke-cert|status\.sh|upgrade\.sh|restore\.sh|setup-dns|init-config|scripts/group-gate' docs`.
  - `grep -rn 'aws CLI\|aws route53' docs` is empty.
  - `grep -rn 'setup --check' docs` is empty (F17).
  - `python3 scripts/check-lists.py` and `scripts/check-branding.sh` exit 0 (F13).
- [ ] **Step 4: Commit:** docs: `git add docs includes && git commit -m "docs: dns plan / setup / check, caa, dnssec, dns-tool, hub dns panel and doctor kinds"`, then push. Commit and push core CLAUDE.md and Hub CLAUDE.md in their worktrees.
- [ ] **Step 5: Hub resync (F12):** in the Hub worktree, `PORTCULLIS_DOCS_DIR=/Volumes/workspace/portcullis/wt-dns1/portcullis-docs web/docs/sync.sh`, then `git add web/docs && git commit -m "web/docs: resync (dns1 docs)"` and push.

---

### Task 14: Full CI, merge, deploy, live CAA checks, cleanup

**Files:** none new. Operations only.

- [ ] **Step 1: Catch up.** Wait until `polish1` is merged to core and Hub `main` (`git log origin/main --oneline | head`). In each `dns1` worktree: `git fetch && git merge origin/main`, then resolve and re-run that repo's local test command.
  - Hub `web/web.go` embed line: keep both file lists. Hub `web/docs/*`: never resolve by hand. Take either side, then re-run `sync.sh` against the docs `dns1` worktree (which by then includes docs main) and commit (F12).
  - Docs: run `python3 scripts/check-lists.py` and `scripts/check-branding.sh` after the merge (F13).
- [ ] **Step 2: Full CI.**
  - Core: `gh workflow run ci.yml --ref dns1`; it must be all green.
  - Hub: the branch's `build.yml` push run must be green (it clones core `dns1`).
  - Docs: the build must be green.
- [ ] **Step 3: Merge**, each through a temporary detached worktree (`git worktree add --detach /tmp/merge-<repo> origin/main && cd /tmp/merge-<repo> && git merge --no-ff origin/dns1 -m "merge dns1: dns plan, caa, dnssec, dns-tool, hetzner-cloud" && git push origin HEAD:main`, then `git worktree remove /tmp/merge-<repo>`).
  1. Docs.
  2. Hub, then `gh workflow run build.yml --repo porelli/portcullis-hub --ref main -f compare_ref=dns1`, and wait for green (edge published).
  3. Core, then confirm the main push CI run is green.
- [ ] **Step 4: Templates.** Run `gh workflow run "Test Apps" --repo porelli/portcullis-templates --ref main`; it must be green.
- [ ] **Step 5: Deploy to the test server.**
  - `ssh … 'cd <install dir> && grep -E "^(DNS_PROVIDER|ACME_STAGING)=" .env && git pull --ff-only && ./portcullis upgrade'`. Confirm `ACME_STAGING=true` and that `DNS_PROVIDER` is automated.
  - Fix old data by hand (no migration code): add `DNS_CAA=true` to `.env` if absent.
  - Then run `./portcullis dns plan` and `./portcullis dns setup --yes`. `dig +short CAA portcullis.imbu.ca @1.1.1.1` must show the pinned `accounturi=https://acme-staging-v02.api.letsencrypt.org/acme/acct/…` for `issue` and `issuewild`.
- [ ] **Step 6: Scenario 1, pin present → issuance OK.**
  - Stop Traefik.
  - Drop only the certificates, keeping the account: `docker run --rm --network none -v portcullis_traefik_acme:/acme <helper> sh -c 'jq "del(.letsencrypt.Certificates)" /acme/acme.json > /acme/t && mv /acme/t /acme/acme.json && chmod 600 /acme/acme.json'`. If the helper image has no jq, use the domains image or a pinned jq image with `--network none`.
  - Run `./portcullis up`.
  - Traefik's log shows a new staging certificate obtained, and `./portcullis status` shows the DNS block OK.
- [ ] **Step 7: Scenario 2, flip → relax → re-register → tighten (staying on staging).**
  - Write `false` into `certs/.acme-staging-last` by hand, then run `./portcullis config apply`.
  - The log shows the CAA relaxed **before** "clearing Traefik's ACME storage". `dig` shows the CA-only value.
  - Run `./portcullis up`: Traefik registers a new staging account, the certificate is issued under CA-only, and the tighten step pins the **new** URI (`dig`, plus `secrets/domains/main-domain.env`).
- [ ] **Step 8: Scenario 3, wrong `accounturi` → refused + status Problem.**
  - In a subshell that sources the libs as `portcullis` does (line 23 loop) after `env_load`, run `DNS_ACCOUNT_URI=https://acme-staging-v02.api.letsencrypt.org/acme/acct/1 DNS_SETS=caa _dns_tool apply --wait 5m`.
  - `./portcullis status` shows "CAA allows another ACME account than Traefik's" and exits 1.
  - Drop the certificates as in step 6 and restart Traefik: its log shows an ACME `caa` error.
  - Run `./portcullis dns setup --yes` and restart Traefik: the certificate is issued and status is clean.
  - **Leave the server with a valid staging certificate and a correct pin.**
- [ ] **Step 9: DNSSEC status.** Run `./portcullis dns plan --json | jq .dnssec` and record the state and steps for `imbu.ca` in the report. Do **not** run `--dnssec`.
- [ ] **Step 10: Cleanup.**
  - Delete `dns1` locally and on the remote in core, Hub and docs (`git push origin --delete dns1`), and remove `/Volumes/workspace/portcullis/wt-dns1/*` with `git worktree remove`.
  - Delete the temporary branches/worktrees and `/tmp/dnsplan-read` worktrees if they still exist (`git worktree prune`).
  - Confirm with `git branch -a | grep dns1` (empty) in each repo.
- [ ] **Step 11: Report.** Include merge SHAs, CI run links, the three scenario outcomes, the DNSSEC state, the Traefik Hetzner outcome (Task 9), and the prepared `libdns/digitalocean` patch path (Task 4). The patch is for the user to send upstream.
