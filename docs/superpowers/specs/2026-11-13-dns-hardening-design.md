# DNS configuration and hardening — CAA, DNSSEC, one DNS plan (design)

Status: written by the assistant for the roadmap item "an improvement in the way we configure our DNS, and configurations to make it more secure (DNSSEC, CAA so only our ACME issues certificates, etc.)" (the user's words). No interruptions were wanted, so the assistant made every decision. Each one is the **assistant's call** unless it says otherwise. Open questions are in §11, each with a default.

## 1. Where things stand (2026-11-12)

- **Main domain.** `./portcullis dns setup [--check]` (`scripts/lib/dns.sh`) sets A/AAAA records for `<d>` and `*.<d>` (TTL 300). It is hand-rolled curl + jq code for each of cloudflare, porkbun, digitalocean and hetzner, and needs the `aws` CLI for route53. `--check` resolves only A/AAAA records, through 1.1.1.1. Certificates come from Traefik's built-in resolver `letsencrypt` (DNS-01 via lego, credentials from `.env`, account and certs in `traefik_acme:/acme/acme.json`). `ACME_STAGING` → `config apply` sets `ACME_CA_SERVER` and clears `acme.json` when the setting flips, so Traefik registers a **new account**.
- **Enrolled domains** (contract §12). The `domains` service (Go, lego v4 as a library, libdns v1.1.1 providers, age store) keeps one ACME account for every domain (`store.Account`, with lego's `registration.Resource` holding the account URI). It sets the same A/AAAA pair and runs the records check (A/AAAA at 1.1.1.1 + 8.8.8.8). The Hub's Settings → Domains shows records OK, certificate expiry, last error and state.
- **Not handled at all:** CAA, DNSSEC, records Portcullis doesn't own, and mail-related records. The docs mention CAA only once ("must allow `letsencrypt.org`", quickstart).
- **Provider facts that shape this design** (checked against module sources and provider docs):

| Provider | CAA through libdns | DNSSEC signing via API | DS read via API | Notes |
|---|---|---|---|---|
| cloudflare | yes (typed `libdns.CAA`) | yes: `PATCH /zones/{id}/dnssec` `status: active` | yes: `GET …/dnssec` (`ds`, `key_tag`, `digest`, `status`) | The DS is published automatically only when the registrar is Cloudflare Registrar |
| porkbun | yes (typed) | no (its API manages DS records at the registry, it does not sign zones; see §11 Q3) | DS at the registry: `getDnssecRecords` / `createDnssecRecord` | Registrar API, out of scope (§2) |
| route53 | yes (raw RR data passes through) | possible, but it needs a customer-managed KMS key + KSK (other permissions, costs money) | `GetDNSSEC` (when the IAM policy allows it) | Signing stays manual |
| digitalocean | **no**: `libdns/digitalocean` sends only `data`, but DO's API needs `flags` + `tag` for CAA | no DNSSEC at all | — | Needs a small fix (§9 T3) |
| hetzner | yes (raw value), but on the legacy dns.hetzner.com API | not on the legacy API | — | Hetzner moved DNS to the Cloud API (GA 2025-11-10). New zones can't be created on dns.hetzner.com. `libdns/hetzner/v2` targets the Cloud API (§11 Q1) |

## 2. Goals, non-goals, anti-goals

**Goals**
1. **One DNS plan.** For each Portcullis name (the main domain and every enrolled domain) there is one list of the records Portcullis wants. For every record it shows the wanted value, the live value (provider API and public resolvers) and a status, and it can fix the record through the provider API where possible. The CLI (`dns plan / setup / check`) and the Hub (a DNS panel for each domain plus doctor findings) show the same thing.
2. **CAA**: only the ACME CA in use may issue, and only to Portcullis' own ACME account(s), and only by DNS-01. Applied automatically wherever Portcullis can write records.
3. **DNSSEC**: a clear status for every name (secure, unsigned, DS missing, broken). Signing is turned on through the API where the provider allows it (opt-in). Each status comes with the exact manual step that is left, the DS values included.
4. Small, cheap hardening: no records under our names pointing elsewhere (dangling or shadowing records), sane TTLs, and a defined way for the later mail feature to add its records.
5. The hand-rolled provider code in `dns.sh` is replaced by the libdns code the domains service already has (memory: prefer libraries). The `aws` CLI dependency goes away.

**Non-goals** (assistant's call)
- Per-host A records instead of the wildcard. The Hub creates hosts on the fly, the wildcard points only at this server, and Traefik answers unknown hosts with 404. `*.<d>` stays.
- Registrar APIs: publishing DS records, changing NS. The only registrar-side automation is the one Cloudflare Registrar does by itself. Porkbun's DS API is a parked follow-up.
- Route 53 KSK/KMS automation. Our own authoritative DNS. DANE/TLSA, DKIM, the MX of a real mail server (the mail feature, roadmap item 6). HTTPS/SVCB records.
- Automating lego-only providers (gcloud, …). For those the plan prints the records to create by hand, and the checks still run.

**Anti-goals** (never)
- Never turn DNSSEC signing off and never remove a DS record through an API. A DS without signatures takes the whole domain offline for validating resolvers.
- Never touch NS, SOA, the zone apex of a zone Portcullis doesn't own (e.g. `example.com` when `<d>` = `portcullis.example.com`), or records other than the ones listed in §3. The only exception is the CAA merge rule in §4.
- Never give the main domain's `.env` credentials to a long-running service. The domains service and the Hub never hold them.
- Never change a main-domain record without showing the plan first (`--yes` skips the prompt). Enrolled domains keep changing in the background, as today: the Hub admin opted in when enrolling.

## 3. The DNS plan

**Record sets per name `<d>`** (assistant's call). A set is the unit of ownership. Later features (mail) add sets.

| Set | Records | TTL | Default |
|---|---|---|---|
| `address` | `<d>`, `*.<d>`: A → IPv4, AAAA → IPv6 (or no AAAA) | 300 | on (as today) |
| `caa` | at `<d>` only (it also covers `*.<d>`, RFC 8659): `issue` + `issuewild` (§4), optional `iodef` | 300 (short, so an account switch heals fast) | on (`DNS_CAA=true`) |
| `nomail` | null MX `0 .` (RFC 7505), `v=spf1 -all`, `_dmarc.<d>` `v=DMARC1; p=reject;` | 3600 | **off**. Offered as an Info recommendation when `<d>` has no MX/SPF and `ALERT_SMTP_FROM` is not under `<d>` |

**Checks** (read-only, provider-agnostic, through the public resolvers 1.1.1.1 + 8.8.8.8):
- address: the existing records check.
- caa: the *effective* CAA set for `<d>` and `*.<d>`, found the way RFC 8659 says (climb to the closest non-empty CAA RRset). It is then judged the way the CA would judge it: issuer, `accounturi`, `validationmethods`. Result: `would_issue: true/false` for our account.
- dnssec: §5.
- foreign records: with provider credentials, A/AAAA/CNAME/ALIAS records at names under `<d>` that aren't ours. A CNAME to a name that doesn't exist (NXDOMAIN) is a **dangling** Warning. An address that isn't the server's **shadows the wildcard** (Info: "app.<d> doesn't reach Portcullis"). Leftover `_acme-challenge` TXT records are Info. Without credentials (main domain seen from the Hub) this check is skipped.
- Cloudflare's proxy shows up as an address mismatch, which is already a Problem. The message names "proxied (orange cloud)" when the live address is a Cloudflare address.

**The plan object** (one shape for the CLI `--json`, the domains API and the Hub):
`{name, checked_at, can_write, items: [{set, name, type, want: [..], live: [..], status: ok|missing|wrong|foreign|unknown, severity, fix: auto|manual|none, steps: [..]}], caa: {issuer, account_uri, would_issue}, dnssec: {state, provider_can_sign, ds: [{key_tag, algorithm, digest_type, digest}], steps}}`.

## 4. CAA

- **Record content** (assistant's call):
  `0 issue "letsencrypt.org; accounturi=<uri>; validationmethods=dns-01"`, plus the same as `issuewild` (written explicitly, because every certificate we hold is a wildcard). Let's Encrypt supports both `accounturi` and `validationmethods` (RFC 8657). Optional `0 iodef "<DNS_CAA_IODEF>"` (default empty: few CAs act on iodef).
- **Which account, where** (least privilege):
  - **Main domain → Traefik's account only.** Its URI is read from `acme.json` `.letsencrypt.Account.Registration.uri`. A helper container runs as root with `--network none` and the volume mounted read-only, and prints only that string (the file holds private keys and never leaves the volume).
  - **Enrolled domain → the domains service's account only** (`registration.Resource.URI`, exposed by the service as `GET /acme/account`).
  - The domains service may never issue for the main domain (§12.4). CAA now enforces that at the CA as well.
  - An enrolled subdomain of the main domain (`team-a.<d>`) gets its own CAA at its name. The closest RRset wins, so the main domain's pin doesn't block it, and the main domain's pin isn't widened.
- **Issuer identifier**: a fixed map from the CA directory to the identifier. Let's Encrypt production **and** staging both check CAA with `letsencrypt.org`; only the account URIs differ. Any other `ACME_CA_SERVER` (Pebble in CI, a private CA) needs `DNS_CAA_ISSUER`. Without it the `caa` set isn't written, with an Info "CAA skipped: unknown CA".
- **Merge rule at a name that already has CAA** (assistant's call): Portcullis owns the `issue`/`issuewild`/`iodef` entries for *its* issuer identifier at *its* names and replaces them. Other CAs' entries are left alone, with an Info "other CAs may also issue for <d>: …". Writing `issuewild` takes wildcard issuance away from other CAs that had only `issue`, and the plan says so. On an enrolled zone apex the plan notes that the CAA covers every name in the zone that has no CAA of its own.
- **Bootstrap and account switches** (the main failure mode):
  - **Domains service** (it has the credentials, so there is never a gap): CAA isn't checked when an account registers. So on the first order, or when the account changes (`ACME_CA_SERVER` or `ACME_EMAIL` changed, see `account()`), the order is: register → write the CAA with the new URI to every enrolled domain → wait until both resolvers see it → order. The domain stores `CAAAccountURI`, and a different current URI makes its `caa` set due.
  - **Traefik** (registers and orders in one go, so it can't be sequenced): while no Traefik account exists, the main domain's CAA is **CA-only**, `issue "letsencrypt.org; validationmethods=dns-01"` (still only one CA and only DNS-01). After Traefik's resolver is healthy, `up` / `upgrade` read the URI (polling up to 3 min for a first registration) and tighten the pin, but only when the provider is automated and the live pin differs. A failure there only warns: `up` never fails because of it.
  - **`config apply` on an `ACME_STAGING` flip**: it relaxes the main domain's CAA to CA-only **before** clearing `acme.json`. If that fails it warns ("issuance will fail on CAA until `./portcullis dns setup`") and goes on: staging flips are a testing workflow, and the failure costs availability, not safety.
  - **Lost account** (`acme.json` deleted, the volume recreated): Traefik registers a new account by itself, and renewal then fails on CAA. `status` compares Traefik's URI with the live pin: Problem "CAA allows another ACME account than Traefik's", fix `./portcullis dns setup`. The existing expiry warnings back it up. Backup/restore keeps both accounts (both live in backed-up volumes), so a restore doesn't trigger this.
  - **CAA switched off** (`DNS_CAA=false`): records Portcullis created are removed on the next `dns setup` / records step, and the checks show Info.
  - **Delete** of an enrolled domain removes its CAA records too. They are tracked in `Domain.Records` like A/AAAA, and only the entries we wrote are removed.
- **Lego-only providers**: `dns plan` prints the exact CAA records to add by hand (CA-only before Traefik registers, pinned after). `status` checks them.

## 5. DNSSEC

- **Chain check** (miekg/dns, already a dependency; for every name):
  1. Find the zone (SOA).
  2. Read the zone's DNSKEY set and the parent's DS set, and compute DS from the DNSKEYs (`DNSKEY.ToDS`, digest 2) to match them.
  3. Ask 1.1.1.1 and 8.8.8.8 for the `<d>` A record with DO set: is AD set? On SERVFAIL, retry with CD set; if that answers, the chain is **bogus**.

| `dnssec.state` | Meaning | Severity | Guidance |
|---|---|---|---|
| `secure` | DS matches, AD at both resolvers | ok | — |
| `unsigned` | No DNSKEY, no DS | Info | "Turn on signing at <provider>" (one click / `--dnssec` on cloudflare), else how to do it at that provider, or "<provider> can't sign: move the zone to sign it" (digitalocean) |
| `ds_missing` | Signed, no DS at the parent | Warning | "Add this DS at your registrar: key tag …, algorithm …, digest type 2, digest …" (from the provider API when it has one, else computed) |
| `ds_mismatch` / `bogus` | DS that matches no DNSKEY, or validation fails | **Problem** | "Validating resolvers can't reach <d>. Fix the DS at the registrar to …, or remove the DS. Never turn signing off while a DS is published" |
| `unknown` | Lookups failed | Warning | Retry and the resolver error |

- **Turning signing on** (opt-in, never automatic; assistant's call): it is zone-wide (it affects the user's other names in the zone), so it's an explicit action: `./portcullis dns setup --dnssec` for the main zone, a "Turn on DNSSEC signing" button for an enrolled domain (doctor one-click fix `dnssec_sign`, preview "turns on signing for the whole zone <zone>"). Only providers with a `signer` capability can do it, and in v1 that is cloudflare. If the API answers 403, the steps name the token permission to add. Turning signing off is never offered (anti-goal).
- **Provider capabilities** in the domains module: an optional interface `signer { DNSSECStatus(ctx, zone) (state, []DS, error); EnableDNSSEC(ctx, zone) error }`. Cloudflare implements both, through its API with the same token and HTTP client. Route53 implements only `DNSSECStatus` (GetDNSSEC; an IAM refusal falls back to the chain check). The others have no capability. The chain check is always the source of truth for `state`. Provider data only supplies the DS values and says whether signing is pending.
- With DNSSEC `secure`, the plan exposes it so that the mail feature can offer DANE later (hook).

## 6. Who runs what

- **One engine** (assistant's call): a package `domains/internal/dnsplan` in the domains module (wanted sets, live read, diff, CAA judgement, merge rules) plus `domains/internal/dnssec` (the chain check). Both the long-running service and a new one-shot subcommand use them.
- **Main domain: `domains dns plan|apply|check|dnssec-enable`**, run by `./portcullis` as `docker compose run --rm` of a new profile-`tools` service `dns-tool`. It uses the `portcullis-domains` image and **only** the `domains-egress` network: read-only, no volumes, no secrets, nothing else mounted. The credentials go in as JSON on **stdin**, mapped from `.env` (`CLOUDFLARE_API_TOKEN` → `api_token`, `AWS_HOSTED_ZONE_ID` → `hosted_zone_id`, …), never in argv or the container env. The same redaction applies. The image gets built if it's missing, so `dns setup` before the first `up` still works.
- **Enrolled domains**: the worker's records step becomes "apply the due sets" (address, caa, and later others). The worker's recheck also refreshes each domain's plan. Checks run every `RecheckEvery` and on demand (refresh throttled to one per 30 s per name).
- **Main domain in the Hub, read-only**: the domains service builds the main domain's plan without credentials (public checks only, `can_write: false`). It learns Traefik's account URI from a new env file `secrets/domains/main-domain.env` (`DOMAINS_MAIN_ACME_ACCOUNT_URI`, 0600, written by `up`), alongside `public-ips.env`. The Hub's fix for the main domain is "run `./portcullis dns setup` on the server" (explain).

## 7. CLI, status, `.env`

- `./portcullis dns plan [--json]`: the plan table (set, name, type, want, live, status), changes nothing.
- `./portcullis dns setup [--yes] [--dnssec] [--only address|caa|nomail]`: shows the plan and confirms (unless `--yes` or non-interactive with `--yes`), applies, waits for propagation (existing loop), checks. `--dnssec` adds the opt-in signing step. With an unsupported provider it prints the records to create by hand and exits 0.
- `./portcullis dns check [--json]`: public checks only (no credentials needed), exits 1 on any Problem. `dns setup --check` stays as an alias.
- `init` calls `dns setup` as today (CAA CA-only at that point). `up` / `upgrade`: tighten the Traefik pin (§4) and write `main-domain.env`. `config apply`: relax on a flip (§4).
- `./portcullis status`: a "DNS" block (address, CAA pin vs Traefik's account, DNSSEC state, foreign records count) through `docker compose exec -T domains domains report --main --json` (loopback; the API already allows it). If the domains service isn't running: one line "DNS checks unavailable". `--json`: `dns: {main: <plan summary>, domains: {<name>: …}}`. Textfile metrics: `portcullis_dns_check{name,check}` 0/1 and `portcullis_dnssec_state{name,state}`.
- `.env` (documented in `.env.example`): `DNS_CAA=true`, `DNS_CAA_ISSUER=` (only for non-LE CAs), `DNS_CAA_IODEF=`, `DNS_NOMAIL=false` (main domain). The `.env.example` provider list gets trimmed to the automated five plus "others: by hand".

## 8. Contract and docs changes

- **§12 intro**: the main domain still uses Traefik's resolver. `dns setup` now runs the domains image's one-shot `dns` tool. The service builds a read-only main-domain plan.
- **§12.1**: the `dns-tool` service (profile `tools`, egress only, stdin credentials); `main-domain.env`; `DNS_CAA*` / `DNS_NOMAIL` passed to the domains service.
- **§12.2**:
  - New endpoints `GET /domains/{name}/dns` (the plan, `?refresh=1` throttled), `POST /domains/{name}/dns/apply` `{"sets": [...]}` → 202, `POST /domains/{name}/dnssec` `{"enable": true}` → 202 / `409` "provider can't sign", `GET /main/dns`, `GET /acme/account` → `{ca_server, account_uri, caa_issuer}`.
  - The domain object gains `caa_ok` (bool) and `dnssec` (state string).
  - The `records` state now covers every due set.
- **§12.3**: the DNS panel for each domain (rows of the plan, Fix buttons for `fix: auto`, the DS values to copy, the main domain read-only). Assignability is unchanged: CAA and DNSSEC never block hostnames, certificate validity does.
- **§12.4**: the record sets table, TTLs, the CAA content and merge rule, the account-switch order, DELETE also removes CAA, never disable signing.
- **§14.5 doctor kinds** (Hub, new check file `internal/doctor/dns.go`, inputs = the plans):
  - `dns_records_wrong` (Problem, one-click `dns_apply` / main: explain);
  - `dns_caa_missing` (Warning, one-click / explain);
  - `dns_caa_wrong_account` (Problem, one-click / explain);
  - `dns_caa_other_issuers` (Info);
  - `dnssec_bogus` (Problem, explain);
  - `dnssec_ds_missing` (Warning, explain with DS);
  - `dnssec_unsigned` (Info, one-click `dnssec_sign` on cloudflare, else explain);
  - `dns_dangling` (Warning, explain);
  - `dns_shadowed` (Info);
  - `dns_nomail_recommended` (Info, one-click).
- **§14.6**: the fix kinds `dns_apply` (param `sets`; preview = the plan's diff lines; plan hash over the live values) and `dnssec_sign` (`touches_data: false`). MCP parity: the existing doctor tools cover them, so no new tool.
- **Docs**:
  - `setup/dns.md` rewritten around `dns plan / setup / check`, with new sections "CAA" and "DNSSEC" (each state with its fix, registrar DS steps, "never remove signing while a DS exists");
  - `setup/certificates.md` "Switching" (CAA relax/tighten);
  - `quickstart.md` CAA line;
  - core `docs/*.md` pointers;
  - `CLAUDE.md` (domains bullet, the `dns.sh` description).

## 9. Testing

- **Go (domains, no containers)**:
  - `dnsplan`: diff, merge rule (foreign issuers kept, ours replaced), CAA rendering, RFC 8659 climbing incl. an enrolled child of the main domain, the issue judgement;
  - account switch order (fakedns call log: register → CAA → visible → order);
  - DELETE removes CAA;
  - `DNS_CAA=false` removes;
  - unknown CA skips.
- **`internal/fakedns` grows**:
  - CAA, MX, TXT, CNAME and DNSKEY/DS answers;
  - a "parent" zone for DS;
  - a resolver mode that sets AD, answers SERVFAIL for bogus, and answers with CD.
  
  Keys are generated and RRsets signed with miekg/dns (`RRSIG.Sign`), so the DS matching uses real data. There is no real validating resolver in CI (assistant's call): the decision table is tested on a simulated AD/SERVFAIL. Cloudflare and route53 `signer` code is tested against `httptest` fakes of their APIs.
- **Pebble doesn't enforce CAA**, so CI checks that the records are written and the steps run in the right order, not the CA's refusal. Real enforcement is checked on the test server with Let's Encrypt **staging** (memory: always staging there):
  1. pin present → issuance OK;
  2. flip prod/staging → relax → re-register → tighten;
  3. a hand-set wrong `accounturi` → renewal refused and `status` Problem.
- **Shell** (`tests/test_shell_libs.sh`, `tests/test_cli.sh`):
  - `acme.json` URI extraction (fixture);
  - credential mapping to stdin JSON (never in argv, checked);
  - plan/confirm/`--yes`;
  - flip relax order with a stubbed tool;
  - help texts.
- **CI build-and-test**:
  - `dns-tool` network membership is exactly `domains-egress`, with no mounts;
  - the one-shot tool runs `plan`/`apply`/`check` with provider `fake` in-process (testprovider build) and its JSON is checked;
  - for the enrolled `team-b.test`, `GET /domains/team-b.test/dns` reports `caa` ok with the domains account URI (Pebble's) via `DNS_CAA_ISSUER=pebble.test`.
- **Hub**: domains client and httpapi tests on the existing fake domains API (new endpoints); doctor check tests for every kind and fingerprint stability; the DNS panel via the existing web tests; e2e-instances asserts the panel's rows for `team-b.test`.

## 10. Task outline (for the plan)

1. **T1** `internal/dnsplan` + `internal/dnssec` + fakedns extensions (tests first).
2. **T2** Provider capabilities: `signer` (cloudflare, route53 read).
3. **T3** DigitalOcean CAA (an upstream PR to `libdns/digitalocean` setting `flags`/`tag`; until it is released, a local wrapper that handles CAA through `godo`, already an indirect dependency).
4. **T4** Service: due sets in the records step, CAA ownership and merge, account-switch order, `CAAAccountURI`, DELETE, the new API endpoints, domain object fields, main-domain plan (`main-domain.env`).
5. **T5** One-shot `domains dns …` subcommand + compose `dns-tool` (profile `tools`) + CI membership check.
6. **T6** Core CLI:
   - `dns.sh` rewritten onto the tool (curl/aws code removed);
   - `dns plan/setup/check`, `--dnssec`, `--only`;
   - Traefik URI read, `up` tighten, `config apply` relax;
   - `status` block + `--json` + metrics;
   - `.env.example`.
7. **T7** Hub: client, `/api/domains/{name}/dns` (+ apply, dnssec), `/api/dns/main`, Settings → Domains DNS panel (main domain row read-only), doctor kinds + fixes.
8. **T8** Contract §12 / §14.5–14.6, docs pages, `CLAUDE.md`.
9. **T9** Live check on the test server (staging), the three CAA scenarios + DNSSEC status for the test zone. Then mainline every branch (memory: branches mainlined).
10. **T10** (only if §11 Q1 says yes) Hetzner Cloud DNS provider.

## 11. Open questions (each has a default; work proceeds on the default)

1. **Hetzner Cloud DNS.** `libdns/hetzner` v1 and `dns setup` use the legacy API, where new zones can't be created. *Default:* add a provider `hetzner-cloud` (`libdns/hetzner/v2`, credential `api_token` = a Cloud token) for enrolled domains and `dns setup`. Keep `hetzner` as it is. For the main domain's DNS-01, use whatever Traefik's lego offers: if lego has no Cloud-API Hetzner provider yet, the main domain on Hetzner Cloud stays "records by hand", and the docs say so.
2. **`nomail` on by default?** *Default:* off. An Info finding recommends it, and the mail feature replaces the set with real MX/SPF/DKIM/DMARC/MTA-STS/TLS-RPT.
3. **Porkbun-hosted zone signing.** Porkbun's docs describe DS management at the registry only. *Default:* treat Porkbun-hosted zones as unable to sign through the API (guidance only). If T2 finds an API for it, add a `signer`.
