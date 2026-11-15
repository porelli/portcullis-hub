# `portcullis login` and SSH certificates, part 1: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship part 1 of the CLI spec. People run `portcullis login`, sign in once in their browser with a strong fresh method, and get Vault-signed SSH user certificates for their host groups in their ssh-agent. Managed hosts are enrolled with one command and kept current by `portcullis host sync`. Unmanaged hosts get a static setup with `portcullis host trust`. The mapping from LLDAP groups to grants, host groups and accounts lives on one Hub page with previews, delegation, audit and doctor checks.

**Architecture:**
- **Core.** Vault gets two SSH mounts: `ssh_user` (capped at 12 h) and `ssh_host`. There is one `ssh_user/roles/hg-<id>` per host group, written only by enroll. enroll's policy enforces the ceilings (spec §7.6). enroll gains five internal endpoints. Traefik gets a `people-cli` router (no forward-auth) to a new Hub listener, `:8891`. The server CLI gains `./portcullis ssh enroll-self | breakglass-cert` and a status block.
- **Hub.**
  - `internal/cliapi` holds the wire types and the golden vectors.
  - `internal/sshaccess` is a pure model and compiler: state → Vault roles, host bundles, certificate sets, client config and previews.
  - `internal/hub/ssh_*.go` holds state, signing, hosts, delivery and revocation.
  - `internal/httpapi` serves the CLI listener, the admin pages, the people pages and the MCP tools.
  - `freshauth` gains a configurable client and a "who signed in" mode for the Hub-owned Keycloak client `portcullis-cli`.
- **CLI.** `cmd/portcullis` in the Hub repo, one binary:
  - **person side:** PKCE loopback, an ephemeral ed25519 key, SSHSIG key proof, the agent protocol and the written SSH config;
  - **host side:** trust, enroll, a long-poll sync with the local ceiling, an atomic apply with `sshd -t` / `visudo -cf` and rollback, drift reports.
- **Docs.** Contract §18 plus the operations and guides pages, first.
- **Keycloak repo.** Unchanged. The extension is client-agnostic: `pc_method`, `portcullis-template`, `portcullis-fresh` and `portcullis-impersonation` all work on any client. Its CI is re-run at the mainline.

**Tech Stack:**
- Go 1.27 for the Hub, the CLI and enroll.
- `golang.org/x/oauth2`, `github.com/coreos/go-oidc/v3`, `golang.org/x/crypto/ssh` + `…/ssh/agent`, `github.com/hiddeco/sshsig`, `github.com/Microsoft/go-winio`, `github.com/pkg/browser`, `github.com/spf13/cobra`, `golang.org/x/term` and `golang.org/x/time/rate`.
- `github.com/hashicorp/vault/api` (enroll only). Vault 2.2.1 (core's pin) and Keycloak 26.8.1 (the `portcullis-keycloak` image).
- On hosts: OpenSSH ≥ 8.2, plus the system's `useradd`, `usermod`, `userdel`, `visudo`, `sshd -t` and `sshd -T`.
- bash (core CLI), Python 3 + Playwright (e2e), vanilla JS (Hub UI).

**Spec:** `docs/superpowers/specs/2026-11-15-cli-login-ssh-design.md` (Hub repo, binding). Part 1 = spec §15 steps 1–7. Device code (§5.4, part 2), CA rotation (§8.11, part 2), `portcullis-servers` / `worker join` (§8.13, part 2) and API tokens (§10, part 3) are later plans. The rulings C1–C44 below are this plan's.

## Global Constraints

Process:
- **Precondition:** every repo's `main` at or after: core 95089a4, hub d6b05eb, keycloak a818ddf, docs 5457bc0.
- **Branches:** branch `ssh1` in docs, hub and core, with worktrees `/Volumes/workspace/portcullis/wt-ssh1/{portcullis-docs,portcullis-hub,portcullis}`. There are no PRs, and everything is mainlined in Task 21. Every commit step is `git add -A && git commit -m "…"`.
- **Contract first:** Task 2 changes `docs/guides/integration-contracts.md` before any code.
- **Merge order:** docs → hub (wait for `edge`) → core (spec §15). Then re-run the keycloak and templates CIs on `main`. Before core's merge, dispatch the Hub's `build.yml` on `main` with `-f compare_ref=ssh1`.
- **Checks:**
  - **Hub** (with `PORTCULLIS_DOCS_DIR=/Volumes/workspace/portcullis/wt-ssh1/portcullis-docs`): gofmt go1.27.3 prints nothing; `go vet ./...` and `go vet -tags harness ./internal/httpapi/...` pass; `go test -race ./...` passes; `GOOS=windows go vet ./cmd/portcullis/...` and `GOOS=darwin go vet ./cmd/portcullis/...` pass.
  - **Core:** `shellcheck -S warning portcullis scripts/lib/*.sh tests/*.sh .github/ci/*.sh`, `bash tests/test_cli.sh`, `bash tests/test_shell_libs.sh`, `cd enroll && go vet ./... && go test -race ./...`, `actionlint` and `bash tests/lint_ci_size.sh` all pass.
  - **Docs:** `zensical build --strict`.
- **Hub docs copies:** `web/docs/*.md` must equal the docs worktree's pages, including the new `ssh-access.md` (C43). Each Hub task that follows a docs change re-runs `go generate ./web` and commits "web: docs copies resynced (ssh)".
- **Heavy tests run on the builder in isolated DinD.** Use `/Volumes/workspace/portcullis/.builder/b.sh '<cmd>'` (stdin passes through). Every container gets its own network, `--rm`, and a `ssh1-` name prefix. Nothing listens on the builder's public interfaces. The builder never reaches the test server.
- **Own watcher:** every CI wait runs your own background watcher (`gh run watch` or an until-loop under Monitor), never only a subagent's.

Project rules (binding):
- **Secrets never on argv or in logs.** This covers OAuth codes, PKCE verifiers, nonces, ID and access tokens, enrolment codes and secrets, private SSH keys (the ephemeral key, `--write-files`' `id`, host keys) and the root token used by `breakglass-cert`.
  - CLI flags never carry one. Enrolment codes come on stdin, or from a no-echo terminal prompt for `-`.
  - The CLI talks the agent protocol itself and never runs `ssh-add` or `ssh-keygen` with key material.
  - `--debug` prints redacted request lines only. The redactor is tested.
  - The Hub, enroll and the host agent log fixed reasons, never inputs.
  - The audit, the issued index, the history and error texts hold fingerprints, never keys or tokens. Public keys are allowed in the revoked-keys list only.
  - The e2e asserts that no code, token, enrolment secret or private key appears in any log or artifact.
- **Fail closed.** None of these ever signs, applies or lets anything through:
  - a missing or foreign `portcullis-cli` client (503 + `ssh_cli_client_conflict`);
  - a Vault mount, cap or role that differs from §7.6 (`ssh_ca_missing`);
  - an unreadable directory or Membership;
  - a host group whose template no allowlisted method meets;
  - a role that can't be made current;
  - an unknown key type;
  - a bundle or report that fails its strict schema, size cap or signature;
  - a host whose effective sshd config doesn't show the Portcullis values.

  The only deliberate exception is a stale revoked-keys file on a partitioned host (spec §8.12).
- **Never weaken access control.**
  - Both the template and `strongFreshMethods` apply. `password`, `totp` and `browser_cert` never sign.
  - Impersonated ID tokens (`pc_imp` or `act`) are refused.
  - No new path skips group-gate. The cookie routers are unchanged.
  - Portcullis per-person accounts are certificate-only.
  - The host tools never delete `authorized_keys` of accounts they don't manage, never edit the main `sshd_config`, and never exceed `/etc/portcullis/host.json`.
  - There is no `--insecure` and no TLS-skip.
- **Identity is the LLDAP username:** `preferred_username` from an ID token the Hub verified, checked against a fresh `directory.Membership` snapshot. Never the email.
- **No back-compat before the release.** No migrations and no version shims. Fix old test-server data by hand.
- **Prefer mature libraries** (Tech Stack). Never hand-roll PKCE, SSHSIG, the agent protocol, the OpenSSH certificate format or rate limiting.
- **No private identifiers:** `example.com`, alice / bob / carol / dave, and documentation addresses (`203.0.113.0/24`, `10.20.0.0/24`). Use no test-server names in public repos.
- **Core `ci.yml` stays at or under 450 KB** (`tests/lint_ci_size.sh`; 317,707 bytes today). Long scripts go in `.github/ci/` or `tests/e2e/`. Only the one job the spec asks for is added: `e2e-ssh` (C37).
- **Never touch the LLDAP `admin` user** on the test server. The e2e uses the CI people (root, alice, bob, carol, dave).
- **No suspicious outbound connections in tests.** Unit tests use fakes and `httptest`. Live tests talk only to local containers. The sshd test image is built from a pinned base. The CLI and the host agent connect only to their configured Portcullis: no telemetry, no update check.

Values pinned by the spec (copy exactly):
- **Ports:** loopback `127.0.0.1:38917`, then `38918`, then `38919`. Never `0.0.0.0` or `localhost`. Hub CLI listener `:8891`.
- **Keycloak client:** `portcullis-cli`.
  - Public, standard flow only, PKCE S256 required.
  - Off: implicit, direct grants, service accounts, device grant, CIBA and token exchange. `use.refresh.tokens=false`, no `offline_access`, no consent, no web origins.
  - Redirect URIs exactly `http://127.0.0.1:{38917,38918,38919}/callback`.
  - Default scopes exactly `basic`, `acr`. Mappers exactly `preferred_username` (ID token) and `portcullis-fresh`.
  - Owner tag `portcullis.hub.template` = `portcullis-cli`.
- **Authorize parameters:** `client_id=portcullis-cli`, `response_type=code`, `scope=openid`, `redirect_uri`, random `state` and `nonce`, S256 `code_challenge`, `prompt=login`, `max_age=0`, and `pc_method=<id>` only with `--method`.
- **Loopback handler:** exactly one `GET /callback` with the right `state`; anything else 404. The page says "You can close this tab", `Cache-Control: no-store`, no script. Timeout 5 minutes.
- **Discovery:** `GET https://people.<d>/api/cli/v1/config` → `{"api": 1, "domain", "issuer", "authorize_url", "client_id": "portcullis-cli", "redirect_ports": [38917, 38918, 38919], "device": false, "min_cli"}`.
- **Version header:** `Portcullis-CLI: <version>; api=1`. Answer `426` "update the Portcullis CLI to <min>".
- **Exit codes:** 0 ok · 1 error · 2 usage · 3 signed in, but no certificate was issued · 4 refused · 5 Portcullis unreachable.
- **Local files:**
  - `os.UserConfigDir()/portcullis/config.json` (0600, no secrets);
  - `~/.ssh/portcullis/<domain>/` (0700) holding `id.pub`, `<host group>-cert.pub`, `known_hosts`, `config`, and `id` (0600) only with `--write-files`;
  - the include line `Include ~/.ssh/portcullis/*/config`.
- **Agent:** comment `portcullis <domain> <host group>`. `LifetimeSecs` = until the certificate expires.
- **Key proof:** SSHSIG, namespace `portcullis-ssh-certificate@v1`, SHA-512. The message is the canonical JSON `{"domain","nonce","code_sha256","public_key"}`.
- **Key types:** accepted `ssh-ed25519`, `ecdsa-sha2-nistp256`, plus `sk-ssh-ed25519@openssh.com` and `sk-ecdsa-sha2-nistp256@openssh.com` only if spike S1 passes. Refused: RSA, DSA, ECDSA P-384/521.
- **Certificate request** `POST /api/cli/v1/ssh/certificates`, strict JSON ≤ 16 KiB: `{"code","code_verifier","nonce","redirect_uri","public_key","key_proof","host_groups"}`. The answer is spec §7.3 step 10's shape.
- **Fixed texts:**
  - "a fresh sign-in is required" (403);
  - "a session as someone else can't get SSH certificates" (403);
  - "only administrators can grant sudo, root, forwarding or server access" (403);
  - "you can't grant access to a group you're in" (403);
  - "<hg> needs a YubiKey: sign in with --method security_key" (refused entry; the method words come from `signin.InfoOf`).
- **Limits:**
  - refusals 10 a minute per address and per person (429);
  - successful signings 6 a minute per person;
  - at most 16 certificates per login, 64 host groups and 256 grants.
- **Vault:**
  - mounts `ssh_user` (`max-lease-ttl=12h`, CA ed25519) and `ssh_host` (`max-lease-ttl=2160h`, CA ed25519, role `host`);
  - user roles `ssh_user/roles/hg-<id>`;
  - the `enroll.hcl` additions as in spec §7.6, with spike S4's corrections.
- **enroll endpoints:**
  - `PUT /internal/ssh-roles/{hg}`, with ≤ 4096 principals, the four extension sets, ≤ 16 CIDRs and ≤ 43200 s;
  - `DELETE /internal/ssh-roles/{hg}`;
  - `POST /internal/ssh-certificates`, with `valid_seconds` 300–43200;
  - `POST /internal/ssh-host-certificates`;
  - `GET /internal/ssh-ca`.
- **Grammars:**
  - principal `^([a-z_][a-z0-9._-]{0,31})@([a-z][a-z0-9-]{0,30})$`;
  - host group id `^[a-z][a-z0-9-]{0,30}$` (`portcullis-*` reserved);
  - LLDAP usernames `^[a-z0-9][a-z0-9._-]{0,63}$`;
  - key id `pc:<user>:<hg>:<16 hex>`; break-glass key id `pc-breakglass:<operator note>`.
- **Extensions:** `permit-pty` always. `permit-port-forwarding` and `permit-agent-forwarding` per grant. Never `permit-X11-forwarding`, `permit-user-rc` or `force-command`. `source-address` per host group, from the role only.
- **TTLs:**
  - default 8 h, settable 1–12 h;
  - privileged grants default to 4 h;
  - host certificates 90 days, renewed at ⅓ remaining life;
  - enrolment codes 15 minutes, single use, 256-bit secret.
- **uids:** 20000–59999, never reused. The primary group has the same number. The local group is `portcullis-users`. The comment is `portcullis:<username>`.
- **Host files:**
  - `/etc/ssh/portcullis/user_ca.pub` (0644);
  - `/etc/ssh/portcullis/principals/<account>` (0644; directory 0755 root);
  - `/etc/ssh/portcullis/revoked_keys` (always exists, created empty first);
  - `/etc/ssh/sshd_config.d/50-portcullis.conf`;
  - `/etc/sudoers.d/portcullis` (0440; line `<name> ALL=(ALL:ALL) NOPASSWD: ALL`);
  - `/etc/portcullis/host.json`;
  - the host certificate `/etc/ssh/ssh_host_ed25519_key-cert.pub`.
- **Drop-in body:** spec §8.9, exact, plus spike S3's corrections.
- **Ceiling defaults:** `allow_sudo` true, `allow_root_login` false, `protected_accounts` = every account below uid 1000 plus `breakglass_account`, `breakglass_account` `breakglass`, `max_accounts` 500.
- **Bundles:** strict JSON, ≤ 4 MiB, `version` 1, long-poll `GET …/hosts/bundle?since=<serial>` held up to 55 s. Reports are strict JSON ≤ 256 KiB.
- **Host request time window** ±60 s, with replays refused.
- **Revoked-keys entries** stay until 24 h after the last certificate for that key expires.
- **Doctor `ssh_host_stale`:** Warning after 15 minutes without a sync, Problem after 24 h. `ssh_host_cert_expiring` fires at ≤ 14 days.
- **Issued index:** `hub_data/ssh/issued.jsonl`, 0600, 90 days.
- **Audit actions:**
  - `ssh.settings`, `ssh.hostgroup.create|update|delete`, `ssh.host.create|update|remove`, `ssh.host.enrol`, `ssh.grant.create|update|delete`, `ssh.account.remove`;
  - `ssh.certificate.issue|revoke|breakglass`, `ssh.host_certificate.issue`, `ssh.host.drift`, `ssh.host.stale`.

  The history kind is `ssh_certificate`.

## Rulings made here (assistant's call)

- **C1 One plan, branch `ssh1`** in docs, hub and core. Keycloak and templates are unchanged; their CIs are re-run at the mainline.
- **C2 Task 1 is a spike** on the builder.
  - It writes `docs/superpowers/spikes/2026-11-15-cli-ssh-results.md` (Hub `ssh1`), with the pinned versions and the outcome of S1–S4 and their sub-checks.
  - The scripts stay in `/Volumes/workspace/portcullis/.builder/spike-ssh/` and are not committed.
  - Later tasks name their branch as "S1 pass / S1 fail". Tasks 7 and 16 turn S1 and S4 into permanent opt-in live tests.
- **C3 Contract section number.** The new section is §18, as the spec says. Until multi-server's §17 lands, §16 ends with "§17 is reserved for multi-server."
- **C4 Enrolment proof** (spec defect: an HMAC keyed by a stored hash makes the hash the secret).
  1. The host gets a challenge from `POST /api/cli/v1/hosts/enrol/challenge {host_id}` → `{challenge}` (32 random bytes, base64url, 2 minutes, single use).
  2. It posts `POST /api/cli/v1/hosts/enrol {host_id, secret, host_key, proof, sshd_version, ceiling}`. `proof` is an SSHSIG by the host key, namespace `portcullis-host-enrol@v1`, over the canonical JSON `{"domain","host_id","challenge"}`.
  3. The Hub compares SHA-256(secret) in constant time with the stored hash, checks the proof, then pins `host_key`. The secret travels only in a TLS body.
- **C5 Enrolment code format:** `pcenrol1.` + base64url(no padding) of the strict JSON `{"d","h","g":[…],"ufp","hfp","s","exp"}`. `ufp` / `hfp` are the CA fingerprints `SHA256:…`. `s` is 32 random bytes in base64url. The Hub stores only SHA-256(s).
- **C6 Host request signing:**
  - Headers `Portcullis-Host-Id`, `Portcullis-Host-Time` (RFC 3339), `Portcullis-Host-Nonce` (16 random bytes, base64url) and `Portcullis-Host-Signature` (SSHSIG armour with its newlines encoded as `\n`; namespace `portcullis-host-request@v1`).
  - The signed message is the canonical JSON `{"host_id","method","path","query","time","nonce","body_sha256"}`.
  - Time ±60 s. A nonce is refused for 5 minutes after first use. Unknown, removed or unpinned host → 403 `removed`.
- **C7 A separate proxy secret, `HUB_CLI_PROXY_SECRET`.** It is in `CORE_SECRETS` and `ROTATABLE_SECRETS`. The middleware `hub-cli-proxy-secret` sets `X-Portcullis-Proxy-Secret` to it. The CLI listener accepts only that value, so neither listener accepts the other's secret.
- **C8 The client address on the CLI listener** is `X-Real-Ip`, which Traefik sets from the connection (no entrypoint trusts forwarded headers). Its absence counts as one shared "unknown" address for the limits.
- **C9 freshauth API.**
  - `Config.ClientID` ("" = `ClientID`, so existing callers don't change).
  - `Config.RedirectURIs []string` (when set, `RedirectURI` is ignored and `Proof.RedirectURI` must be one of them).
  - `Proof.RedirectURI`.
  - `(*Verifier).VerifyAnyUser(ctx, Proof) (*Result, error)`: every check of `Verify` except the caller comparison; `Result.User` = the lowercased `preferred_username`.
  - `Result.Impersonated bool`: the ID token has an `act` or `pc_imp` key, any value. `Verify` itself doesn't refuse it.
- **C10 No `go install` in the docs** (spec defect). The module path is `github.com/portcullis/hub`, not `github.com/porelli/portcullis-hub`, so the spec's command can't resolve. The release binaries are the install path.
- **C11 `portcullis login --no-browser`** prints the authorize URL on stderr instead of opening it. It is used by the e2e and by people on a headless session on the same machine. The URL holds no secret: state, nonce and the challenge are public.
- **C12 `portcullis host enroll --service none`** installs no service, for containers and the e2e. The operator runs `portcullis host sync` in the foreground. `--service auto` (the default) picks systemd, then launchd, and otherwise refuses with the unit text to install by hand.
- **C13 No `portcullis-servers` group in part 1.** `portcullis-*` stays reserved. `./portcullis ssh enroll-self` copies `/usr/local/bin/portcullis` out of the pinned Hub image (`docker create` + `docker cp`, no download) and runs `host enroll` with the code it reads on stdin. The admin first creates the primary as a host in any host group.
- **C14 One sshd check form.** Every `sshd -T` call is `sshd -T -C user=<u>,host=localhost,addr=127.0.0.1`. Spike S3c checks this full form on 8.7.
- **C15 enroll sends every Vault role field as a string:** booleans `"true"`/`"false"`, TTLs as decimal seconds, extensions as one canonical comma string in the order `permit-pty,permit-port-forwarding,permit-agent-forwarding`. It does so whatever S4 shows: the HCL allowed values are strings.
- **C16 `GET /internal/ssh-ca`** answers `{"user_cas","host_cas","problems"}`. `problems` names each §7.6 difference enroll can read: the mount tune, the host role, the CA key type. enroll's policy gains `read` on `sys/mounts/ssh_user/tune`, `sys/mounts/ssh_host/tune` and `ssh_host/roles/host` if S4d shows these need no `sudo`. Otherwise `problems` covers only the host role, and `./portcullis status` alone checks the caps.
- **C17 Shared vectors.** The Hub's `internal/cliapi/testdata/vectors.json` (principal and key-id grammar cases, role JSON cases, key-proof messages) has a byte copy at core `enroll/testdata/ssh_vectors.json`. core's existing vectors step in `unit-tests` compares the two, as it does for `signin_vectors.json`.
- **C18 Hub layout:**
  - `internal/cliapi` (wire types, grammars, canonical messages, vectors);
  - `internal/sshaccess` (pure: validation, privilege, merge, compile, preview, golden files);
  - `internal/state/ssh.go`;
  - `internal/hub/ssh_*.go`;
  - `internal/invite/ssh.go`;
  - `internal/keycloak/cli.go`;
  - `internal/httpapi/{cli_listener,cli_hosts,ssh_admin,ssh_people,mcptools_ssh}.go`;
  - `internal/doctor/ssh.go`;
  - `web/ssh.js` (the Hub tab) and `web/myssh.js` (the people pages).
- **C19 uids.** `state.SSH.UIDs` maps username → uid. `state.SSH.UIDsUsed` is sorted and never shrinks. Allocation takes the lowest unused number ≥ 20000. Exhaustion → 503 "no uid left in 20000–59999".
- **C20 Rate limits** use `golang.org/x/time/rate`: per address and per person for refusals (10/min, burst 10), and per person for successes (6/min, burst 6). Idle limiters are evicted after 10 minutes.
- **C21 Revoked list.** `hub_data/ssh/revoked.json` (0600, atomic write) holds `[{key, fp, reason, actor, added, until}]`. The public list and the bundles carry the keys only. Entries are pruned daily, after `until` = the last certificate's `valid_before` + 24 h, except bring-your-own keys, whose `until` is zero, meaning "until removed by an admin".
- **C22 Bundle serials.** One Hub-wide counter, `state.SSH.Serial`, is bumped when any compiled bundle's content hash changes. Each host keeps the serial of its last change. The long-poll returns as soon as the host's serial is greater than `since`, else answers `204` after 55 s.
- **C23 Host certificate renewal is the Hub's.** At compile time, a managed host whose certificate has ≤ ⅓ of its life left gets a new one from enroll in the next bundle. The agent only writes it.
- **C24 Service units.**
  - systemd: `/etc/systemd/system/portcullis-host-sync.service` (spec §8.9 hardening, `Restart=always`, `RestartSec=10`).
  - launchd: `/Library/LaunchDaemons/eu.portcullis.host-sync.plist`.
  - Windows host commands refuse with "Windows hosts: follow the manual steps in the docs".
- **C25 The CLI in the Hub image** is at `/usr/local/bin/portcullis`, matching the image's arch. There is no `portcullis-agent` image in part 1.
- **C26 Host code is testable without root.** `cmd/portcullis/internal/host` works through a `System` interface (exec, a root-prefixed file system, user lookups). Unit tests use a fake. `host_sshd_test.go` (build tag `sshd`) runs the real binary in Debian / Ubuntu / Rocky containers on the builder and in the Hub CI.
- **C27 CLI layout.**
  - `cmd/portcullis/main.go` (cobra root);
  - `cmd/portcullis/internal/{config,api,login,agentx,loopback,sshconf,host}`;
  - `cmd/portcullis/deps_test.go`: `go list -deps` shows no `github.com/portcullis/hub/internal/...` package but `internal/cliapi`.
- **C28 sshd reload:**
  - Linux: `systemctl reload ssh` when `ssh.service` exists, else `systemctl reload sshd`;
  - macOS: `launchctl kickstart -k system/com.openssh.sshd`;
  - otherwise, or under `--service none`, the PID from `/run/sshd.pid` gets SIGHUP;
  - if none of these works, refuse.
- **C29 Off by default.** `state.SSH.Settings.Enabled` starts false. While off:
  - `config` still answers;
  - `ssh/certificates` answers 409 "SSH access is off on this server";
  - host endpoints answer 503 "SSH access is off" (agents keep their files);
  - no role is written.
- **C30 `logout --revoke` and the revocation route.** `POST /api/cli/v1/ssh/revocations` takes `{code, code_verifier, nonce, redirect_uri, public_keys}`. It needs a proof that passes freshauth for `portcullis-cli` (any switched-on method). It revokes the listed keys that the issued index shows were issued to that person, and answers `{revoked: n}`. The spec names `--revoke` but no route.
- **C31 Unmanaged host certificates.** `POST /api/cli/v1/ssh/host-certificates` takes `{code, code_verifier, nonce, redirect_uri, host_group, public_key, names}`. The caller must be an administrator, and `pc_fresh` must be `security_key` or `yubikey_cert`. Each name must match the group's patterns or a managed host's names. It answers `{certificate, valid_before}`.
- **C32 `portcullis open <name>`** opens `https://<name>.<domain>/`. With no name it opens `https://<domain>/` (the portal). There is no network call.
- **C33 `portcullis status`** reads the agent and the written files only, with no network. It lists the host group, principals, expiry and key type of each certificate.
- **C34 Bundle `remove` field.** The bundle gains `"remove": [names]` for *Remove account* (the spec's example lacks it). The agent runs `userdel` after moving the home to `/home/.portcullis-removed/<name>-<yyyymmdd>`, then reports. The name stays in `locked` until the report confirms.
- **C35 Automatic revocation on leave.** It runs at every compile. Any issued, unexpired certificate whose host group no longer grants that person at least one of its principals has its key revoked. Actor `-`, reason `left <group>`.
- **C36 Doctor inputs.**
  - `ssh_ca_missing` comes from enroll's `problems` (C16) plus a Hub-side read-back of each role (`GET` through enroll's `PUT` answer, which echoes the role as Vault stores it).
  - Host kinds come from the stored reports.
- **C37 One new CI job, `e2e-ssh`** (core), as the spec asks:
  - its scripts are `.github/ci/e2e-ssh-*.sh`, `tests/e2e/e2e_ssh.py` and `tests/e2e/sshd/Dockerfile`;
  - its YAML is ≤ 15 KB.
- **C38 Release job without GoReleaser.** A `cli-release` matrix in `build.yml` runs `go build`, then `tar` / `zip`, `sha256sum`, `cosign sign-blob --yes` (bundle file per archive) and `actions/attest-build-provenance`. GoReleaser and nfpm are part 4.
- **C39 Enrol prompts.** The ceiling is asked only on a terminal. Without one, flags are required: `--allow-sudo`, `--allow-root-login`, `--breakglass-account`, `--no-breakglass-i-have-console-access`, `--max-accounts` and `--uid-range` (default `20000-59999`). Without a terminal, defaults are used and printed.
- **C40 Host reports are stored** as the last report per host in `hub_data/ssh/hosts/<id>.json` (0600). Findings are derived at read time.
- **C41 Signing reads** `Membership(ctx, now)` once per request (never the cached snapshot) and `keycloak.ListedUser` for "disabled".
- **C42 `freshGov` gains `template`** (`govTemplate(id)`), so a host group's governing template goes through `governingLocked` like core pages.
- **C43 `operations/ssh-access.md`** joins `web/docs/sync.sh`'s list, as an MCP resource.
- **C44 The spike's Keycloak result (S2) is recorded for part 3.** Part 1 doesn't branch on it: no part 1 code uses refresh tokens.

## Review Focus

1. **A person whose access ends soon.** A temporary membership ends in 20 minutes, or two grants give different TTLs. A person expects the certificate's `valid_before` to be the earliest of the three bounds (grant TTL, setting max, membership end), never the longest. Pinned by Task 5 (`TestMergeTTLEarliestBound`, `TestMergeMembershipEndsSoon`) and Task 7 (`TestSignValidSecondsFromMerge`).
2. **sshd quietly ignoring the drop-in.** Triggers: the main `sshd_config` sets `TrustedUserCAKeys` / `AuthorizedPrincipalsFile` before its `Include`; a `50-cloud-init.conf` sorts earlier; there is no `Include` line at all. A person expects `host enroll` / `host trust` to refuse (with the lines to add) and `host sync` to report a Problem, never "ready" with certificates that can't log in. Pinned by Task 14 (`TestApplyRefusesWhenEffectiveConfigDiffers`, `TestNoIncludeRefusesWithLines`) and the sshd container test.
3. **Local account names that collide or can't exist.** Cases: a local `bob` that Portcullis didn't create; LLDAP `1alice` or a 40-character name; `root` or `breakglass` as a grant account. A person expects skips with `ssh_host_account_conflict` / `_invalid` / `ssh_host_ceiling`, never an adopted or changed account. Pinned by Task 13 (`TestAccountsConflictNeverAdopted`, `TestAccountInvalidSkipped`, `TestCeilingRefusesRootAndProtected`).
4. **A bad or absent Hub answer during sync.** Cases: a 5xx, a cut long-poll, a 5 MiB bundle, a bundle with an unknown field, a bundle for another host id, a `403 removed`. A person expects the last files to stay byte-identical (except on `removed`, which removes the trust as spec §12.4 says) and sshd never reloaded. Pinned by Task 14 (`TestSyncKeepsFilesOnBadBundle`, `TestSyncRemovedUninstalls`).
5. **The loopback sign-in going sideways.** Cases: all three ports taken; a second callback; a callback with the wrong state; a `GET /callback?error=access_denied`; the browser opened on another machine (timeout). A person expects a clear message, exit 1, no post to the Hub, and the listener closed. Pinned by Task 11 (`TestLoopbackPortsTaken`, `TestLoopbackWrongStateIs404`, `TestLoopbackErrorParam`, `TestLoopbackSecondCallback404`, `TestLoopbackTimeout`).

---

### Task 1: Spike — the four unverified behaviours (builder)

**Files:**
- Create (scratch, not committed): `/Volumes/workspace/portcullis/.builder/spike-ssh/{vault.sh,keycloak.sh,sshd.sh,skkeys.go}`.
- Create: `docs/superpowers/spikes/2026-11-15-cli-ssh-results.md` (Hub `ssh1`).

**Interfaces:**
- Produces: the outcome of each check below, as pass/fail plus the observed error text. Later tasks read it as "S1 pass" and so on.

Run every container on the builder with `--rm`, a `ssh1-spike-` name and its own `docker network create --internal ssh1-spike-net`. Images are pinned by digest: core's Vault and Keycloak pins, `debian:13-slim`, `ubuntu:24.04`, `ubuntu:20.04` and `rockylinux:9`.

- [ ] **Step 1: S1, sk key types in Vault 2.2.1.** Run a dev Vault, mount `ssh_user` as in spec §7.6, and write `roles/hg-t` with `allowed_user_key_lengths` naming all four accepted types. `skkeys.go` builds `sk-ssh-ed25519@openssh.com` and `sk-ecdsa-sha2-nistp256@openssh.com` public keys in Go (wire format: type, key, application `ssh:`; parsed back with `ssh.ParsePublicKey`).
  - Sign one of each, plus an ed25519 and a P-256 key.
  - Record: does the role write accept the sk names, does each sign succeed, does `ssh-keygen -L` show the right type?
  - **S1a:** an RSA-3072 and a P-384 key are refused by the role.
- [ ] **Step 2: S2, Keycloak audience narrowing** (C44: part 3's input).
  - In the `portcullis-keycloak` image (`start-dev`, realm import of a minimal realm), make a public client with refresh tokens and two optional scopes `api:a` / `api:b`, each with an audience mapper (`https://a.example.com` and `portcullis-api`; `https://b.example.com` and `portcullis-api`).
  - Sign in with a password user, requesting both scopes.
  - Run a refresh grant with `scope=openid api:a` and record whether the new access token's `aud` holds only `https://a.example.com` and `portcullis-api`.
- [ ] **Step 3: S3, sshd `Match` scoping in included files.** Do this for each of `debian:13-slim`, `ubuntu:24.04`, `ubuntu:20.04` (OpenSSH 8.2) and `rockylinux:9` (8.7).
  - Install `openssh-server` and keep the distribution's own `sshd_config`: `Include` at the top, global keywords after it.
  - Add a user `alice` in group `portcullis-users` and a user `breakglass`.
  - Write the spec §8.9 drop-in, then record:
    - `sshd -t`;
    - `sshd -T -C user=alice,host=localhost,addr=127.0.0.1` — expect `authorizedkeysfile none`, `passwordauthentication no`, `kbdinteractiveauthentication no`;
    - the same for `breakglass` — expect the distribution's values;
    - whether the main file's keywords after the `Include` (`X11Forwarding`, `Subsystem`, `UsePAM`, `PrintMotd`) still apply globally or fell into the `Match` (the `sshd -t` error, or `-T` values for `breakglass`).
  - **S3a:** repeat with `Match all` as the drop-in's last line.
  - **S3b:** on 8.2, does `KbdInteractiveAuthentication` parse, or must it be `ChallengeResponseAuthentication`?
  - **S3c:** on 8.7, does `-T -C` accept the full `user,host,addr` form, and fail on `user=` alone?
  - **S3d:** with `TrustedUserCAKeys /x` in the main file before the `Include`, does `-T` show `/x`? This is the drift Problem case.
- [ ] **Step 4: S4, Vault `allowed_parameters`.** Dev Vault, both mounts. Apply spec §7.6's `enroll.hcl` additions as a policy on an AppRole token. As that token:
  - write `roles/hg-t` with C15's string values: expect ok;
  - write the same with JSON booleans (`true`): record whether it is refused;
  - try `allow_host_certificates="true"`, `allowed_extensions="permit-pty,permit-X11-forwarding"` and `key_type="otp"`: expect each refused;
  - sign on `ssh_user/sign/hg-t` with `critical_options`, and with `cert_type=host`: expect each refused;
  - **S4b:** sign on `ssh_host/sign/host` without `cert_type` (Vault's default is `user`), and with `cert_type=host`. Record whether a host certificate can be issued at all under `denied_parameters = {"cert_type" = []}`;
  - **S4c:** write a role with `max_ttl="86400"` and sign with `ttl="86400"`. Record the certificate's validity: is it capped at the mount's 12 h?
  - **S4d:** read `sys/mounts/ssh_user/tune` with a policy granting only `read` there.
- [ ] **Step 5: Write the results file.** It has one table: check, versions, result, observed text, and the branch later tasks take. Then the decisions, each one line:
  - **S1 fail:** part 1 ships ed25519 + P-256 only; the docs say why.
  - **S3 leak:** the drop-in ends with `Match all`.
  - **S3b fail:** the writer emits `ChallengeResponseAuthentication no` when `sshd -V` < 8.7.
  - **S4 bool refusal:** confirms C15.
  - **S4b refusal:** the host sign path uses `allowed_parameters = {"cert_type" = ["host"], "*" = []}`.
  - **S4c uncapped:** the policy pins `max_ttl` and `ttl` to the twelve values `"3600"`…`"43200"` (whole hours) and enroll rounds up to an hour.
  - **S4d needs sudo:** C16's narrow form.
- [ ] **Step 6:** Commit `spike: cli-ssh unverified behaviours (vault sk types and allowed_parameters, keycloak aud narrowing, sshd Match scoping)`.

### Task 2: Contract and docs (docs repo)

**Files:**
- Modify: `docs/guides/integration-contracts.md`:
  - new `## 18. SSH access and the CLI`, after §16. It has the spec §14 list, every value under Global Constraints, C4–C6, C9, C16, C21–C23, C29–C31, C34 and the spike's outcomes;
  - §16's last line (C3);
  - §8: the `portcullis-cli` client;
  - §8.2: the history kind `ssh_certificate`;
  - §9.4: enroll's five SSH endpoints;
  - §9.5: the audit actions;
  - §9.6: `ssh_access`, grant groups as guarding groups, privileged grants' members as protected targets;
  - §14.5: the doctor kinds of spec §9.13;
  - §15.10: the MCP tools of spec §9.12.
- Create: `docs/operations/ssh-access.md` (spec §14 "Docs site": the model, managed vs unmanaged, accounts and sudo, the preview, revocation, offline behaviour, break-glass, drift, the threat model in plain words, Windows hosts by hand). CA rotation is described as "coming in part 2" in one line.
- Create: `docs/guides/cli.md` (install from the release, `cosign verify-blob`, Gatekeeper / SmartScreen honestly, login, `ssh-config --install`, `--key` with a FIDO key, `--ca-file` for staging, the cookie FAQ of spec §11). No `go install` (C10).
- Modify: `docs/operations/.nav.yml` (+ `SSH Access: ssh-access.md` after VPN), `docs/guides/.nav.yml` (+ `The Portcullis CLI: cli.md` first).
- Modify: `docs/operations/hardening.md` (the SSH section), `docs/operations/cli.md` (`./portcullis ssh enroll-self | breakglass-cert`; the `status` block; `HUB_CLI_PROXY_SECRET` in rotate), `docs/operations/hub.md` (SSH access tab, people card), `docs/operations/testing.md` (`e2e-ssh`, the sshd container tests, the live tests), `docs/operations/groups.md` (`ssh_access`).

- [ ] **Step 1:** Write every section above, copying the values from Global Constraints verbatim.
- [ ] **Step 2:** Run `zensical build --strict`. Expected: no warnings.
- [ ] **Step 3:** Commit `docs: ssh access and the portcullis cli (contract §18, guides, operations)`.

### Task 3: Hub — `internal/cliapi`: wire types, grammars, canonical messages, vectors (hub)

**Files:**
- Create: `internal/cliapi/{doc.go,types.go,grammar.go,proof.go,strict.go}`, `internal/cliapi/testdata/vectors.json`.
- Test: `internal/cliapi/cliapi_test.go`.
- Create: `cmd/portcullis/deps_test.go` (C27; the package `cmd/portcullis` is a stub `main` until Task 11).
- Modify: `go.mod` (+ `github.com/hiddeco/sshsig`, `github.com/spf13/cobra`, `github.com/pkg/browser`, `golang.org/x/term`; promote `github.com/Microsoft/go-winio` and `golang.org/x/time` to direct), `.github/dependabot.yml` (group `cli`).

**Interfaces:**
- Produces:
  - `const APIVersion = 1`; `const HeaderCLI = "Portcullis-CLI"`; `const RedirectPorts = [3]int{38917, 38918, 38919}`.
  - Types (strict JSON tags as spec §5.2, §7.3, §8.9, §9.10): `Config`, `CertRequest`, `CertAnswer{User, Certificates []IssuedCert, Refused []Refusal, HostCAs, RevokedHostKeys []string}`, `IssuedCert`, `Refusal`, `RevocationRequest`, `HostCertRequest`, `EnrolChallenge`, `EnrolRequest`, `Bundle{Version, HostID, Serial, Generated, UserCAs, HostCertificate, Accounts []Account, Locked, Remove, RevokedKeys []string, Options BundleOptions}`, `Account{Name, Kind, UID, Principals, Sudo}`, `Report`, `Ceiling`, `EnrolCode`.
  - `func DecodeStrict(r io.Reader, max int64, v any) error`: `DisallowUnknownFields`, a single value, and a size error above `max`.
  - `func ValidPrincipal(s string) (account, hostGroup string, ok bool)`, `func ValidHostGroupID(s string) bool`, `func ValidUsername(s string) bool`, `func KeyID(user, hg, reqHex string) string`, `func ParseKeyID(s string) (user, hg, req string, ok bool)`.
  - `const NSKeyProof = "portcullis-ssh-certificate@v1"`, `NSHostRequest = "portcullis-host-request@v1"`, `NSHostEnrol = "portcullis-host-enrol@v1"`.
  - `func KeyProofMessage(domain, nonce, code, authorizedKey string) []byte`: canonical JSON with `code_sha256` = hex SHA-256 of the code. `func HostRequestMessage(...) []byte` and `func EnrolMessage(domain, hostID, challenge string) []byte`.
  - `func AcceptedKeyType(t string, sk bool) bool`: `sk` is a package var `SKKeysAccepted` = S1's outcome.
  - `func ParseEnrolCode(s string) (*EnrolCode, error)`, `func (c EnrolCode) String() string`.

- [ ] **Step 1: Write the failing tests:**
  - `TestPrincipalGrammar`: vectors `alice@web` ok; `Alice@web`, `alice@Web`, `1x@web`, `a@portcullis-servers` ok as grammar (reservation is sshaccess's), `@web`, `alice@`, 33-character account refused.
  - `TestKeyIDRoundTrip`: `pc:alice:web:0123456789abcdef`; refuses 15 hex digits and uppercase.
  - `TestKeyProofMessageCanonical`: field order and escaping, matching the vector bytes.
  - `TestDecodeStrictRefusesUnknownAndTrailing`, `TestDecodeStrictSize`.
  - `TestEnrolCodeRoundTrip`, `TestEnrolCodeRefusesBadPrefixAndPadding`.
  - `TestAcceptedKeyTypes` (S1 branch: sk accepted only when `SKKeysAccepted`).
  - `TestVectorsFile`: every case in `testdata/vectors.json` is run through the functions above.
  - `TestCLIImportGraph` (`cmd/portcullis/deps_test.go`).
- [ ] **Step 2:** Run `go test ./internal/cliapi/ ./cmd/portcullis/`. Expected: FAIL (package missing).
- [ ] **Step 3:** Implement. `vectors.json` is written by hand from the spec values. It is the file core copies (C17).
- [ ] **Step 4:** Run the same command. Expected: PASS.
- [ ] **Step 5:** Commit `cliapi: wire types, grammars, canonical proof messages and shared vectors`.

### Task 4: Hub — freshauth for the CLI client, the `portcullis-cli` Keycloak client (hub)

**Files:**
- Modify: `internal/freshauth/freshauth.go` (C9).
- Create: `internal/keycloak/cli.go`.
- Modify: `internal/keycloak/keycloak.go` (`protectedClients` + `"portcullis-cli"`), `internal/hub/impersonation_file.go` (`impFileClient` refuses it), `internal/hub/freshauth.go` (C42: `govTemplate`), `cmd/hub/main.go` (a fourth verifier `hub.VerifierCLI` with `RedirectURIs` = the three loopback URLs; `SetCLIClient(kc.EnsureCLIClient)` in the directory sync loop next to `SetFreshAuthClient`).
- Test: `internal/freshauth/freshauth_test.go`, `internal/keycloak/cli_test.go` (kctest fake), `internal/keycloak/live_test.go` (+ `TestLiveCLIObjects`).

**Interfaces:**
- Consumes: Task 3's `RedirectPorts`.
- Produces:
  - `freshauth.Config.ClientID`, `.RedirectURIs`; `freshauth.Proof.RedirectURI`; `(*Verifier).VerifyAnyUser(ctx, Proof) (*Result, error)`; `freshauth.Result.Impersonated`.
  - `keycloak.CLIClientID = "portcullis-cli"`; `(*Client).EnsureCLIClient(ctx) error` (a `*ConflictError` for a foreign or untagged holder).
  - `hub.(*Hub).CLIClientReady() bool` and the conflict flag for the doctor's `ssh_cli_client_conflict`.

- [ ] **Step 1: Write the failing tests:**
  - `TestVerifyAnyUserTakesUsernameFromToken` (fake token endpoint + JWKS as the existing tests).
  - `TestRedirectURIMustBeListed` (`http://127.0.0.1:40000/callback` refused before the exchange; the exchange's `redirect_uri` is the proof's).
  - `TestImpersonatedFlag` (`act` → true, `pc_imp: null` → true, neither → false).
  - `TestClientIDDefaults` (zero `ClientID` = `portcullis-fresh-auth`, unchanged behaviour of every existing test).
  - `TestEnsureCLIClientCreatesExact` (every attribute and flag from Global Constraints, mappers exactly two, scopes exactly `basic`, `acr`).
  - `TestEnsureCLIClientConflict` (untagged → `ConflictError`, no PUT).
  - `TestEnsureCLIClientDeletesExtraMapper`.
  - `TestProtectedCLIClient` (`RegisterClient("portcullis-cli")` refused).
- [ ] **Step 2:** Write `TestLiveCLIObjects` (gated as the existing live tests):
  - ensure twice (idempotent);
  - a real browser-less PKCE sign-in on `127.0.0.1:38917/callback` (the existing live helpers);
  - an authorize request with `redirect_uri=http://127.0.0.1:40000/callback` and one with `http://localhost:38917/callback` → Keycloak refuses both;
  - a device-authorization request → refused.
- [ ] **Step 3:** Run `go test ./internal/freshauth/ ./internal/keycloak/ ./internal/hub/`. Expected: FAIL.
- [ ] **Step 4:** Implement. `EnsureCLIClient` reuses `withFreshAuthSettings`' pattern with its own settings func (no web origins, loopback URIs) and `ensureOnlyClientMapper`.
- [ ] **Step 5:** Run the Step 3 command. Expected: PASS. Then run `TestLiveCLIObjects` on the builder against the `portcullis-keycloak` image (`b.sh`, the realm-wipe env vars, a `ssh1-kc` container). Expected: PASS.
- [ ] **Step 6:** Commit `freshauth: configurable client and VerifyAnyUser; keycloak: the Hub-owned portcullis-cli client`.

### Task 5: Hub — the mapping state and `internal/sshaccess` (hub)

**Files:**
- Create: `internal/state/ssh.go`; modify `internal/state/state.go` (`SSH SSHState \`json:"ssh" yaml:"ssh"\``).
- Create: `internal/sshaccess/{model.go,validate.go,privilege.go,merge.go,compile.go,preview.go}`, `internal/sshaccess/testdata/golden/*.json` (state → role JSON, bundle JSON, client config text: the spec §9.1–9.2 example as `example`, plus `ttl`, `ceiling`, `unmanaged`).
- Test: `internal/sshaccess/sshaccess_test.go`, `internal/state/ssh_test.go`.

**Interfaces:**
- Produces:
  - `state.SSHState{Settings SSHSettings; HostGroups map[string]SSHHostGroup; Hosts map[string]SSHHost; Grants []SSHGrant; UIDs map[string]int; UIDsUsed []int; Serial int64}`.
  - `state.SSHSettings{Enabled bool; DefaultTTLHours int}` (0 = 8).
  - `state.SSHHostGroup{Label, Description, Template string; Patterns []string; SourceCIDRs []string; VPNOnly bool; VPNVia []string; HostCerts bool; Delegable bool; CreateShared bool}`.
  - `state.SSHHost{Names, Addrs, HostGroups []string; Managed bool; KeyFP, HostKey string; EnrolHash string; EnrolExpires time.Time; Serial int64; HostCert string; HostCertUntil time.Time; Ceiling *cliapi.Ceiling; Removed bool; LastSync time.Time}`.
  - `state.SSHGrant{ID, Group string; GroupID int; HostGroup string; Accounts []string; Sudo string; TTLHours int; PortForwarding, AgentForwarding bool}`.
  - `sshaccess.Input{State state.SSHState; Members map[string]map[string]int; Pending map[string]map[string]time.Time; Expired map[string]map[string]bool; Now time.Time; VPNRanges func(via []string) []string}`.
  - `func Validate(s state.SSHState) error` (grammars, ≤ 64 host groups, ≤ 256 grants, `{username}` or a valid account, `sudo` none|full, TTL 1–12, the built-in `all` present, `portcullis-*` refused).
  - `func Privileged(g state.SSHGrant) (bool, string)` (spec §9.4; the reason text).
  - `func Compile(in Input) (*Compiled, error)`.
  - `Compiled{Roles map[string]cliapi.RoleSpec; Bundles map[string]*cliapi.Bundle; People map[string]PersonAccess}`.
  - `PersonAccess{HostGroups map[string]CertPlan}`, `CertPlan{Principals []string; Extensions []string; Until time.Time; Grants []string}`.
  - `func (c *Compiled) Preview(hostID string, rootOnly bool) []PreviewRow`; `PreviewRow{Person, Account string; Root, Sudo bool; Via []string; Until *time.Time; Status string}`.
  - `func ClientConfig(domain string, plans map[string]CertPlan, hosts map[string][]string) string` (spec §6's text, exact).
  - `func AllocUID(s *state.SSHState, user string) (int, error)` (C19).
  - `cliapi.RoleSpec{Principals []string; Extensions string; SourceAddress []string; MaxTTLSeconds int}` (add this to Task 3's `types.go` in the same commit).

- [ ] **Step 1: Write the failing tests:**
  - `TestCompileExampleGolden`: spec §9.1's three grants on web-1 / web-2 give exactly `golden/example.*`: `hg-web` principals `alice@web,bob@web,deploy@web`, extensions `permit-pty`, max 8 h; `hg-all` `alice@all` 4 h; web-1's bundle accounts as spec §9.2.
  - `TestMergeTTLEarliestBound`, `TestMergeMembershipEndsSoon` (Review Focus 1).
  - `TestExpiredMembershipGivesNothing`.
  - `TestGroupIDMismatchGrantsNothing` (a group re-created with a new id).
  - `TestPrivileged` (each of the five spec §9.4 conditions, and a plain grant false).
  - `TestPrivilegedDefaultTTL4h`.
  - `TestSudoBelongsToHostAccount` (alice's sudo on web-1 from `all`).
  - `TestRoleDeletedWithoutGrants`.
  - `TestVPNOnlySourceAddress` (the via ranges become `SourceAddress`).
  - `TestUsernameNotLocalAccountStillPrincipal` (the bundle marks it; the host skips it in Task 13).
  - `TestValidateRefusals` (65th host group, `portcullis-x`, `{user}` typo, sudo `some`).
  - `TestAllocUIDNeverReuses`.
  - `TestClientConfigExact`.
  - `TestPreviewRootFilter`.
  - `TestUnmanagedPreviewUnknown`.
  - `TestStateSSHRoundTrip` (YAML).
- [ ] **Step 2:** Run `go test ./internal/sshaccess/ ./internal/state/`. Expected: FAIL.
- [ ] **Step 3:** Implement. `Compile` is pure and deterministic: sorted maps and stable principal order, so the golden files are byte-stable.
- [ ] **Step 4:** Run the Step 2 command. Expected: PASS.
- [ ] **Step 5:** Commit `sshaccess: host groups, grants, privilege, merge and compile to roles, bundles and client config (golden)`.

### Task 6: Hub — enroll client, compile loop, role delivery (hub)

**Files:**
- Create: `internal/invite/ssh.go`, `internal/hub/ssh.go` (wiring, `TriggerSSHCompile`, the compiled snapshot), `internal/hub/ssh_deliver.go`.
- Modify: `cmd/hub/main.go` (`h.SetSSHActions(invites)`; `wireDirectoryHooks` also calls `TriggerSSHCompile`).
- Test: `internal/invite/ssh_test.go`, `internal/hub/ssh_deliver_test.go`.

**Interfaces:**
- Consumes: Task 5's `Compile`, `RoleSpec`.
- Produces:
  - `invite.(*Client).PutSSHRole(ctx, hg string, r cliapi.RoleSpec) (*cliapi.RoleSpec, error)` (answer = Vault's read-back).
  - `invite.(*Client).DeleteSSHRole(ctx, hg string) error`.
  - `invite.(*Client).SignSSHUser(ctx, r invite.SSHUserSign) (*invite.SSHSigned, error)`.
  - `invite.(*Client).SignSSHHost(ctx, r invite.SSHHostSign) (*invite.SSHSigned, error)`.
  - `invite.(*Client).SSHCA(ctx) (*invite.SSHCA, error)` with `SSHCA{UserCAs, HostCAs, Problems []string}`.
  - `hub.SSHActions` (interface of those five); `(*Hub).SetSSHActions(SSHActions)`.
  - `(*Hub).TriggerSSHCompile()`: coalesced like `TriggerVPNPublish`. It reads `Membership`, compiles, puts every changed role, deletes stale `hg-*` roles, bumps serials (C22), renews host certificates (C23) and revokes on leave (C35, Task 9's function).
  - `(*Hub).ensureRoleCurrent(ctx, hg string) error`: used before signing. A role whose read-back differs from the compiled spec is an error (fail closed).
  - `(*Hub).sshCompiled() *sshaccess.Compiled`.

- [ ] **Step 1: Write the failing tests:**
  - `TestPutSSHRoleBody` (strict body as spec §7.6's table, bearer, 15 s timeout, `APIError` mapping as `certs.go`).
  - `TestSignSSHUserNeverLogsKey` (captured `log` output holds no `AAAA`).
  - `TestCompileDeliversChangedRolesOnly`.
  - `TestCompileDeletesStaleRole`.
  - `TestEnsureRoleCurrentReadBackMismatchFails`.
  - `TestCompileMembershipUnavailableKeepsLast` (no roles touched, doctor input set).
  - `TestSerialBumpsOnBundleChangeOnly`.
  - `TestHostCertRenewedAtOneThird`.
- [ ] **Step 2:** Run `go test ./internal/invite/ ./internal/hub/ -run 'SSH|Compile|Role|Serial|HostCert'`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the Step 2 command. Expected: PASS.
- [ ] **Step 5:** Commit `hub: ssh compile loop, enroll client and Vault role delivery`.

### Task 7: Hub — the CLI listener and signing (hub)

**Files:**
- Create: `internal/httpapi/cli_listener.go` (the mux, `CLIProxySecret`, `HeaderCLI` / 426, the identity-header refusal, strict decode), `internal/hub/ssh_sign.go`, `internal/hub/ssh_limits.go`, `internal/hub/ssh_issued.go`, `internal/hub/ssh_revoked.go`.
- Modify: `cmd/hub/main.go` (`HUB_CLI_ADDR` default `:8891`, `HUB_CLI_PROXY_SECRET`; the Hub refuses to start without it, C7), `internal/signinhistory/{entry.go,audit.go}` (`KindSSHCertificate = "ssh_certificate"`; `ssh.certificate.issue` / `.revoke` → that kind), `Dockerfile` (`EXPOSE 8888 8889 8891`).
- Test: `internal/httpapi/cli_listener_test.go`, `internal/hub/ssh_sign_test.go`, `internal/signinhistory/audit_test.go`.

**Interfaces:**
- Consumes: Task 4's `VerifyAnyUser` and `Impersonated`; Task 5's `CertPlan`; Task 6's `ensureRoleCurrent` and `SignSSHUser`; `strongFreshMethods` (`certificates.go`).
- Produces:
  - `httpapi.(*Server).CLIHandler() (http.Handler, error)`, serving only `/api/cli/v1/*`: `GET config`, `POST ssh/certificates`, `POST ssh/revocations` (C30), `GET ssh/ca`, `GET ssh/revoked-keys`, plus Task 8's host routes and Task 10's `ssh/host-certificates`.
  - `hub.(*Hub).SignSSH(ctx, req cliapi.CertRequest, addr string) (*cliapi.CertAnswer, error)`.
  - `hub.(*Hub).RevokeOwnSSH(ctx, req cliapi.RevocationRequest, addr string) (int, error)`.
  - `hub.(*Hub).RevokeKeys(actor, reason string, keys []string, until time.Time) error`.
  - `hub.(*Hub).RevokedKeys() []string`.
  - `hub.(*Hub).IssuedFor(user string) []IssuedRecord`; `IssuedRecord{Time, User, HostGroup, Serial, KeyFP, Principals, ValidBefore, Flow, Addr}`.

- [ ] **Step 1: Write the failing tests** (spec §7.3's ten steps, in order):
  - `TestCLIListenerOnlyCLIRoutes` (every other Hub path 404).
  - `TestCLIListenerIgnoresIdentityHeaders` (an `X-Forwarded-User: root` changes nothing).
  - `TestCLIListenerProxySecret` (missing / the main secret → 401).
  - `TestCLI426` (`Portcullis-CLI: 0.0.1; api=0`).
  - `TestConfigShape` (exact keys, `device` false).
  - `TestSignHappyPath` (fake verifier with `security_key`, fake enroll; the answer has one certificate per host group, `hosts`, `host_cas`).
  - `TestSignRefusesPasswordTotpBrowserCert` (each → `refused` with the text, enroll never called; all refused → exit-3 shape).
  - `TestSignImpersonated403` (the fixed text).
  - `TestSignProtectedNames409` (`admin`, `portcullis-hub`, `portcullis-x`).
  - `TestSignDisabledKeycloakUser409`.
  - `TestSignNotInLLDAP409`.
  - `TestSignKeyProofWrong403` (audit reason "key proof", the answer the fixed text).
  - `TestSignKeyTypeRefused` (RSA, P-384; sk per S1).
  - `TestSignRevokedKeyRefused`.
  - `TestSignUnknownHostGroupListedNotRevealed`.
  - `TestSignValidSecondsFromMerge`.
  - `TestSignRoleNotCurrentFailsClosed` (503).
  - `TestSignTemplateUnmetListed` (`strong` group with `passkey_synced` → refused entry naming `--method security_key`).
  - `TestSignLimits` (11th refusal per address 429; 7th success per person 429).
  - `TestSignAuditAndIssuedIndex` (one `ssh.certificate.issue` per host group with principals, key type + fingerprint, serial, until, `flow=loopback`, method, address; `issued.jsonl` 0600; no key or code in either).
  - `TestSignOff409` (C29).
  - `TestSign16Max`.
  - `TestRevokedKeysPublicText`.
  - `TestRevokeOwnOnlyOwnKeys`.
  - `TestHistorySSHCertificate`.
- [ ] **Step 2:** Run `go test ./internal/httpapi/ ./internal/hub/ ./internal/signinhistory/ -run 'CLI|Sign|Revok|History'`. Expected: FAIL.
- [ ] **Step 3:** Implement.
  - The key proof uses `sshsig.Verify(message, sig, pub, sshsig.HashSHA512, cliapi.NSKeyProof)`.
  - Membership is read once per request (C41).
  - Every refusal is audited, with actor `-` when the proof failed first.
- [ ] **Step 4:** Run the Step 2 command. Expected: PASS.
- [ ] **Step 5:** Commit `hub: cli listener :8891 and ssh certificate signing (proof, strength, mapping, limits, audit, issued index, history)`.

### Task 8: Hub — managed hosts: codes, enrolment, signed requests, bundle long-poll, reports (hub)

**Files:**
- Create: `internal/hub/ssh_hosts.go`, `internal/hub/ssh_hostauth.go` (C6), `internal/hub/ssh_reports.go` (C40), `internal/httpapi/cli_hosts.go`.
- Test: `internal/hub/ssh_hosts_test.go`, `internal/httpapi/cli_hosts_test.go`.

**Interfaces:**
- Consumes: Task 3's `EnrolCode`, `EnrolMessage`, `HostRequestMessage`, `Bundle`, `Report`; Task 6's compiled bundles and `SignSSHHost`.
- Produces:
  - `(*Hub).CreateHost(ctx, actor directory.Actor, h HostInput, p freshauth.Proof) (code string, err error)`: admin, fresh under the `hub` core template, returns the C5 code once (never stored).
  - `(*Hub).NewEnrolCode(ctx, actor, hostID string, p freshauth.Proof) (string, error)`.
  - `(*Hub).EnrolChallenge(hostID string) (string, error)`.
  - `(*Hub).Enrol(ctx, req cliapi.EnrolRequest, addr string) (*cliapi.Bundle, error)`.
  - `(*Hub).HostBundle(ctx, hostID string, since int64) (*cliapi.Bundle, error)` (blocks ≤ 55 s; `nil, nil` = 204).
  - `(*Hub).HostReport(ctx, hostID string, r cliapi.Report) error`.
  - `(*Hub).RemoveHost(ctx, actor, hostID string, p freshauth.Proof) error`.
  - `(*Hub).verifyHostRequest(r *http.Request, body []byte) (hostID string, err error)`.
  - Routes: `POST hosts/enrol/challenge`, `POST hosts/enrol`, `GET hosts/bundle`, `POST hosts/report`.

- [ ] **Step 1: Write the failing tests:**
  - `TestEnrolCodeSingleUse15Min`.
  - `TestEnrolWrongSecret403` (constant-time compare; audit `ssh.host.enrol` refused with the fingerprint).
  - `TestEnrolProofOverChallenge` (a proof over another challenge refused; a challenge reused refused).
  - `TestEnrolPinsHostKey`.
  - `TestHostRequestSignature` (good; ±61 s refused; nonce replay refused; body hash mismatch refused; unpinned host 403 `removed`).
  - `TestBundleLongPollReturnsOnChange` (fake clock + a compile in a goroutine).
  - `TestBundleLongPoll204After55s`.
  - `TestBundleSizeCap4MiB` (the Hub refuses to serve an oversized bundle and reports `ssh_host_ceiling`-style doctor input).
  - `TestReportStrict256KiB` (unknown field, 257 KiB, a path in a field → stored as an opaque string, never joined to a path).
  - `TestRemoveHostUnpins`.
  - `TestHostEndpointsOff503`.
- [ ] **Step 2:** Run `go test ./internal/hub/ ./internal/httpapi/ -run 'Enrol|Host|Bundle|Report'`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the Step 2 command. Expected: PASS.
- [ ] **Step 5:** Commit `hub: managed hosts (enrolment codes, pinned host keys, signed requests, bundle long-poll, reports)`.

### Task 9: Hub — directory integration: guarding, protected targets, `ssh_access`, revocation on leave (hub)

**Files:**
- Modify: `internal/directory/authz.go` (`PermSSHAccess = "ssh_access"` in `delegatedPerms`; `checkDelegateTarget` refuses members of `Service.SSHGroups().Privileged`), `internal/directory/groups.go` (`guardingGroups` adds each grant group: "an SSH access group"), `internal/directory/service.go` (`SSHGroups func() SSHGroups`; `SSHGroups{Granting, Privileged []string}`), `internal/hub/ssh.go` (`(*Hub).SSHGroupsForDirectory()`), `internal/hub/ssh_revoked.go` (C35 `revokeOnLeave`).
- Create: `internal/hub/ssh_grants.go` (grant create/update/delete with the spec §9.4 and §9.5 checks).
- Test: `internal/directory/authz_test.go`, `internal/directory/groups_test.go`, `internal/hub/ssh_grants_test.go`.

**Interfaces:**
- Consumes: Task 5's `Privileged`, Task 6's compile.
- Produces:
  - `(*Hub).SaveGrant(ctx, c *directory.Caller, g state.SSHGrant, typedGroup string, p *freshauth.Proof) (*state.SSHGrant, error)` and `(*Hub).DeleteGrant(ctx, c, id string) error`. Admins need the proof and `typedGroup` for privileged grants. Holders need `ssh_access` and a delegable host group.
  - `(*Hub).PreviewGrant(ctx, c, g state.SSHGrant) ([]sshaccess.PreviewRow, error)` (the hypothetical preview).

- [ ] **Step 1: Write the failing tests:**
  - `TestGrantGroupIsGuarding` (its rule may use only admin-only fields; `created_by` people never added).
  - `TestPrivilegedMembersProtectedTargets` (a `sign_in_help` setup link to one → 403).
  - `TestSSHAccessHolderNonPrivilegedOnly` (sudo → the fixed 403 text).
  - `TestSSHAccessHolderOwnGroup403` (member now, or a rule would add them).
  - `TestSSHAccessHolderProtectedGroup403` (lldap_admin, a permission group, a core-subdomain group, a group with a privileged grant).
  - `TestSSHAccessHolderNonDelegableHostGroup403`.
  - `TestPrivilegedNeedsAdminFreshAndTypedName`.
  - `TestGrantAuditBeforeAfter` (`privileged=true`, `as ssh_access`).
  - `TestRevokeOnLeave` (alice leaves `ssh_web`: her unexpired `web` certificate's key is on the list, actor `-`, reason `left ssh_web`; her `all` certificate's key isn't).
  - `TestGrantNeverViaMCPPrivileged` (`directory.ViaAI` caller → 403).
- [ ] **Step 2:** Run `go test ./internal/directory/ ./internal/hub/ -run 'Grant|Guarding|Protected|SSHAccess|RevokeOnLeave'`. Expected: FAIL.
- [ ] **Step 3:** Implement. The checks run inside the directory's `gate` on a fresh snapshot, as every delegated permission does.
- [ ] **Step 4:** Run the Step 2 command. Expected: PASS.
- [ ] **Step 5:** Commit `directory: ssh_access permission, ssh grant groups guard, privileged-grant members are protected; hub: grants and revocation on leave`.

### Task 10: Hub — admin and people APIs, host certificates, MCP tools, doctor (hub)

**Files:**
- Create: `internal/httpapi/ssh_admin.go` (Hub listener `/api/ssh/...`), `internal/httpapi/ssh_people.go` (people listener `/api/me/ssh`, `/api/directory/users/{u}/ssh`, `/api/ssh/delegated/...`), `internal/httpapi/mcptools_ssh.go`, `internal/doctor/ssh.go`, `internal/hub/doctor_ssh.go`.
- Modify: `internal/httpapi/server.go` (`registerSSHAdmin` in `hubMux`; `registerSSHPeople` in `peopleMux`), `internal/httpapi/cli_listener.go` (`POST ssh/host-certificates`, C31).
- Test: `internal/httpapi/ssh_admin_test.go`, `internal/httpapi/ssh_people_test.go`, `internal/httpapi/mcptools_ssh_test.go`, `internal/doctor/ssh_test.go`, and the existing `TestPeopleListenerHasNoAppRoutes` allowlist.

**Interfaces:**
- Consumes: Tasks 5–9.
- Produces (routes; each mutation audited with spec §9.7's action):
  - Hub listener:
    - `GET|PUT /api/ssh/settings`;
    - `GET|POST /api/ssh/hostgroups`, `PUT|DELETE /api/ssh/hostgroups/{id}`;
    - `GET|POST /api/ssh/hosts`, `PUT|DELETE /api/ssh/hosts/{id}`, `POST /api/ssh/hosts/{id}/code`, `POST /api/ssh/hosts/{id}/accounts/{name}/remove`;
    - `GET /api/ssh/hosts/{id}/access?root=1`, `GET /api/ssh/hostgroups/{id}/access`, `GET /api/ssh/people/{u}/access`;
    - `GET|POST /api/ssh/grants`, `PUT|DELETE /api/ssh/grants/{id}`, `POST /api/ssh/grants/preview`;
    - `GET /api/ssh/certificates`, `POST /api/ssh/certificates/revoke`, `POST /api/ssh/host-certificates` (*Sign a host key*).
  - People listener:
    - `GET /api/me/ssh`, `POST /api/me/ssh/revoke-all`;
    - `GET /api/directory/users/{u}/ssh`, `POST /api/directory/users/{u}/ssh/revoke-all` (admins; `sign_in_help` holders via `CheckHelp`; administrators' certificates by administrators only);
    - `GET|POST /api/ssh/delegated/grants…` and `GET /api/ssh/delegated/hostgroups/{id}/access` (`ssh_access` holders).
  - MCP (spec §9.12): admin `list_ssh_access`, `ssh_access_preview`, `list_ssh_certificates`, `list_ssh_hosts`, `revoke_ssh_certificates` (confirmed), `set_ssh_grant` (non-privileged, confirmed); people `my_ssh_access`, `revoke_my_ssh_certificates` (confirmed).
  - `(*Hub).ImportBreakglass()` at `Init`: reads `secrets/ssh/breakglass.jsonl` (mounted read-only), appends each new line as `ssh.certificate.breakglass` and raises a doctor Warning `ssh_breakglass_cert`. Test `TestImportBreakglass` (once only, malformed lines skipped and counted).
  - Doctor kinds (spec §9.13): `ssh_ca_missing`, `ssh_cli_client_conflict`, `ssh_privileged_grant` (Info), `ssh_host_stale`, `ssh_host_drift`, `ssh_host_account_conflict`, `ssh_host_account_missing`, `ssh_host_account_invalid`, `ssh_host_ceiling`, `ssh_host_authorized_keys_shared` (Info), `ssh_host_cert_expiring`, `ssh_breakglass_used` (Warning), `ssh_hostgroup_unused`. Inputs: `doctor.SSHIn`.

- [ ] **Step 1: Write the failing tests:**
  - `TestSSHAdminRoutesAdminOnly`.
  - `TestCreateHostNeedsFreshHub` (the code shown once, never in the audit).
  - `TestHostGroupTemplateUnusable409`.
  - `TestAccessPreviewRootFilter`.
  - `TestHostCertificateNeedsSecurityKeyAdmin` (`passkey_device` → 403; a name outside the patterns → 409).
  - `TestPeopleMySSH` (own groups, accounts, sudo, hosts, certificates).
  - `TestRevokeAllHelperRules`.
  - `TestDelegatedRoutesHolderOnly`.
  - `TestMCPNeverSignsOrCodes` (no tool name for signing, enrolment codes, privileged grants, `source-address`, settings).
  - `TestMCPSetGrantRefusesPrivileged`.
  - One test per doctor kind (fires and stays quiet; stale at 15 min Warning and 24 h Problem; cert expiring at 14 d).
- [ ] **Step 2:** Run `go test ./internal/httpapi/ ./internal/doctor/ ./internal/hub/`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `go test -race ./...` and both `go vet` invocations. Expected: PASS.
- [ ] **Step 5:** Commit `hub: ssh access admin and people APIs, host certificates, MCP tools and doctor kinds`.

### Task 11: CLI — login, status, logout, ssh-config, open, version (hub)

**Files:**
- Create: `cmd/portcullis/main.go`, `cmd/portcullis/internal/config/config.go`, `…/api/client.go` (TLS: system pool, plus the `--ca-file` / `PORTCULLIS_CA_FILE` PEM pool; the header; exit-code mapping; the `--debug` redactor), `…/loopback/loopback.go`, `…/login/login.go`, `…/agentx/{agent.go,agent_unix.go,agent_windows.go}`, `…/sshconf/sshconf.go`, `cmd/portcullis/internal/sshconf/testdata/*.golden`.
- Test: `…/loopback/loopback_test.go`, `…/login/login_test.go` (a fake Hub `httptest.Server`), `…/agentx/agent_test.go` (in-process `agent.NewKeyring()` over a socketpair; the Windows pipe name under `GOOS=windows` build only), `…/sshconf/sshconf_test.go`, `…/api/redact_test.go`.

**Interfaces:**
- Consumes: Task 3's types and messages.
- Produces:
  - commands `login [<domain>] [--domain] [--method <id>] [--key <pub>] [--write-files] [--no-browser] [--ca-file <pem>] [--debug]`, `status`, `logout [--revoke]`, `ssh-config [--install]`, `open [<name>]`, `version`.
  - `loopback.Listen(ctx) (*Listener, error)` (38917 → 38919, `127.0.0.1` only); `(*Listener).Wait(ctx, state string) (code string, err error)`.
  - `agentx.Open() (agent.ExtendedAgent, func(), error)`; `agentx.ReplaceDomain(a, domain string, keys []agentx.Entry) (notes []string, err error)`.
  - `sshconf.Write(dir string, ans *cliapi.CertAnswer, pub string, writeKey []byte) error`; `sshconf.Install(home string, confirm func() bool) error`.

- [ ] **Step 1: Write the failing tests:**
  - Loopback (Review Focus 5): `TestLoopbackPortsTaken`, `TestLoopbackWrongStateIs404`, `TestLoopbackErrorParam`, `TestLoopbackSecondCallback404`, `TestLoopbackTimeout`, `TestLoopbackBindsLoopbackOnly`, `TestLoopbackPageNoStoreNoScript`.
  - Login:
    - `TestAuthorizeURLExact` (every parameter; `pc_method` only with `--method`; unknown method → exit 2);
    - `TestLoginPostsProofNeverCallsTokenEndpoint` (the fake Keycloak's token handler fails the test if hit);
    - `TestKeyProofVerifies` (Hub-side `sshsig.Verify` passes);
    - `TestExitCodes` (all refused → 3; 403 → 4; dial error → 5; 426 → 1 with the text);
    - `TestKeyFlagSignsThroughAgent` (BYO key in the in-process keyring);
    - `TestNoAgentRefusesWithHint`;
    - `TestWriteFiles0600`.
  - Agent:
    - `TestReplaceDomainKeepsOtherKeys`;
    - `TestLifetimeRefusedFallsBack` (an agent that refuses constraints: added without one, with the note);
    - `TestAddRefusedHintsKey`.
  - sshconf:
    - `TestConfigGolden` (spec §6);
    - `TestKnownHostsCertAuthorityScoped`;
    - `TestInstallAsksAndIsIdempotent`;
    - `TestDirModes`.
  - Redaction: `TestDebugRedacts` (code, verifier, nonce, `key_proof`, Authorization never printed).
- [ ] **Step 2:** Run `go test ./cmd/portcullis/...` and `GOOS=windows go vet ./cmd/portcullis/...`. Expected: FAIL.
- [ ] **Step 3:** Implement.
  - PKCE uses `oauth2.GenerateVerifier`, `oauth2.S256ChallengeOption`. The browser opens with `browser.OpenURL`. The y/N prompt uses `term.IsTerminal`.
  - Windows: `winio.DialPipe(`\\.\pipe\openssh-ssh-agent`, nil)`.
  - A login replaces the domain's previous Portcullis keys by comment prefix.
- [ ] **Step 4:** Run the Step 2 commands, and `GOOS=darwin go vet ./cmd/portcullis/...`. Expected: PASS.
- [ ] **Step 5:** Commit `cli: portcullis login (pkce loopback, ephemeral key, key proof, agent), status, logout, ssh-config, open`.

### Task 12: CLI — host files, the drop-in and `host trust` (hub)

**Files:**
- Create: `cmd/portcullis/internal/host/{system.go,files.go,dropin.go,sshd.go,trust.go,ceiling.go}`, `…/host/testdata/*.golden`.
- Test: `…/host/files_test.go`, `…/host/trust_test.go` (fake `System`, C26).

**Interfaces:**
- Consumes: Task 3's `Ceiling`; Task 1's S3 outcomes.
- Produces:
  - `host.System` interface (`Run(ctx, name string, args ...string) ([]byte, error)`, `ReadFile`, `WriteFileAtomic(path string, b []byte, mode fs.FileMode) error`, `Remove`, `Lookup*`).
  - `host.DropIn(domain, hostID string, hostCert bool, sshdVersion string) []byte`: spec §8.9 text, plus `Match all` last on S3 leak, and `ChallengeResponseAuthentication` below 8.7 on S3b fail.
  - `host.EffectiveCheck(sys, portcullisUser, breakglass string) error`, using the C14 form. It compares the six keywords and the `Match` values.
  - `host.Transaction` (`Stage(path, bytes, mode)`, `Commit(validate func() error) error`, `Rollback()`).
  - `host.Trust(ctx, sys, opts TrustOptions) error`.
  - commands `host trust --domain --host-group --ca-key | (--ca-fingerprint + fetch) --account … [--revoked-keys] [--breakglass-account] [--no-breakglass-i-have-console-access]`.

- [ ] **Step 1: Write the failing tests:**
  - `TestDropInGolden` (both S3 variants per the spike).
  - `TestRevokedKeysCreatedEmptyFirst` (written before the drop-in names it).
  - `TestTransactionRollsBackOnSshdT` (fake `sshd -t` exit 255 → every file restored byte for byte, no reload).
  - `TestNoIncludeRefusesWithLines` (Review Focus 2).
  - `TestApplyRefusesWhenEffectiveConfigDiffers` (the main config sets `TrustedUserCAKeys` before `Include`).
  - `TestTrustCAKeyPinnedFetch` (a fetched key that doesn't match `--ca-fingerprint` → refused; no unpinned fetch path exists).
  - `TestTrustNoConnectionWithoutRevokedKeys` (the fake HTTP transport fails the test if dialled).
  - `TestTrustRevokedKeysTimer` (systemd timer, 5 minutes; a failed fetch keeps the last file).
  - `TestTrustBreakglassRequired`.
  - `TestTrustNeverTouchesMainConfig`.
  - `TestOpenSSHFloor8_2` (refuses 8.1 with the lines).
- [ ] **Step 2:** Run `go test ./cmd/portcullis/internal/host/`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the same command. Expected: PASS.
- [ ] **Step 5:** Commit `cli: host files, the sshd drop-in with effective-config checks, atomic apply with rollback, host trust`.

### Task 13: CLI — accounts, sudo and the ceiling (hub)

**Files:**
- Create: `cmd/portcullis/internal/host/{accounts.go,sudoers.go,apply.go}`.
- Test: `…/host/accounts_test.go`, `…/host/apply_test.go`.

**Interfaces:**
- Consumes: Task 3's `Bundle`, `Account`, `Ceiling`; Task 12's `Transaction`, `EffectiveCheck`.
- Produces:
  - `host.Apply(ctx, sys, b *cliapi.Bundle, c cliapi.Ceiling, prev *State) (*State, []cliapi.Finding, error)`: writes everything, validates with `visudo -cf` and `sshd -t`, then `EffectiveCheck`, then reloads only on change. On error the previous files stay.
  - `host.State` (the last applied serial and file hashes, `/etc/portcullis/state.json` 0600).

- [ ] **Step 1: Write the failing tests:**
  - `TestCreatePersonAccount` (exact `useradd -u <uid> -U -G portcullis-users -m -s /bin/bash -c portcullis:alice alice`; `/bin/sh` when bash is absent).
  - `TestAccountsConflictNeverAdopted`, `TestAccountInvalidSkipped`, `TestCeilingRefusesRootAndProtected` (Review Focus 3).
  - `TestLockOnLoss` (`usermod -L -e 1 -s /usr/sbin/nologin`, principals file removed, `loginctl terminate-user` then `pkill -KILL -u` fallback).
  - `TestRemoveAccountKeepsHome` (C34).
  - `TestSharedAccountsOnlyWhenOptedIn` (else `ssh_host_account_missing`).
  - `TestSudoersValidatedAndKept` (`visudo -cf` failure → the old file kept).
  - `TestSudoersCeilingAllowSudoFalse`.
  - `TestMaxAccounts`.
  - `TestUIDOutsideRangeSkipped`.
  - `TestAuthorizedKeysSharedCounted`.
  - `TestReloadOnlyOnChange`.
- [ ] **Step 2:** Run `go test ./cmd/portcullis/internal/host/`. Expected: FAIL.
- [ ] **Step 3:** Implement with the system's `useradd`, `usermod`, `userdel` and `visudo`. Never edit `/etc/passwd` by hand.
- [ ] **Step 4:** Run the same command. Expected: PASS.
- [ ] **Step 5:** Commit `cli: host accounts, sudoers and the local ceiling`.

### Task 14: CLI — `host enroll`, `host sync`, `host status | remove | certify`, and the sshd container tests (hub)

**Files:**
- Create: `cmd/portcullis/internal/host/{enroll.go,sync.go,report.go,service.go,remove.go,certify.go}`, `cmd/portcullis/internal/host/host_sshd_test.go` (build tag `sshd`), `cmd/portcullis/internal/host/testdata/sshd/Dockerfile.{debian,ubuntu,rocky}` (pinned bases).
- Modify: `.github/workflows/build.yml` (`test` job: a step "host agent against real sshd" running `go test -tags sshd -count=1 -v ./cmd/portcullis/internal/host/`; `PORTCULLIS_DOCKER_TEST=require`).
- Test: `…/host/sync_test.go`, `…/host/enroll_test.go`.

**Interfaces:**
- Consumes: Tasks 8, 12 and 13; Task 11's `api` client.
- Produces:
  - `host enroll [<code>|-] [--service auto|none] [ceiling flags]`. The code comes from stdin when absent; `-` gives a no-echo prompt.
  - `host sync`: long-poll; apply; report after every apply and at least every 5 minutes; on 404 or a held-connection cut, fall back to a 60 s pull (spec §17 Q6).
  - `host status` (the bundle's age, serial, findings).
  - `host remove [--delete-accounts]`.
  - `host certify --host-group --key <pub> --name … [--method]`. It runs the loopback flow (Task 11) and posts C31's request.

- [ ] **Step 1: Write the failing tests:**
  - `TestEnrolCodeFromStdinNeverArgv` (an argv code is refused unless `-`).
  - `TestEnrolFirstCAKeyPinnedByCode` (a bundle whose `user_cas[0]` fingerprint differs from `ufp` → refused, nothing written).
  - `TestEnrolFailureRestoresEverything` (failure after files are staged → byte-identical, sshd untouched, `ssh.host.enrol error` reported).
  - `TestEnrolServiceNone`.
  - `TestSyncKeepsFilesOnBadBundle`, `TestSyncRemovedUninstalls` (Review Focus 4).
  - `TestSyncFallsBackToPull`.
  - `TestReportNeverLogLines` (counts only).
  - `TestBreakglassUsedCounted`.
  - `TestRemoveDeletesOnlyOwnFiles`.
  - `TestCertifyNeedsAdminMethod` (the Hub's 403 → exit 4).
- [ ] **Step 2: Write the sshd container test** (`host_sshd_test.go`). For each Dockerfile, with the Hub faked by an `httptest.Server` reachable from the container:
  - enrol;
  - `ssh -o CertificateFile=… alice@<container>` works with an in-test CA-signed certificate;
  - `breakglass` works with its `authorized_keys`;
  - `root` is refused;
  - a hand-edited principals file is healed at the next apply and reported `ssh_host_drift` "fixed";
  - `TrustedUserCAKeys` added to the main config before `Include` → reported Problem;
  - remove → the box's own login paths are unchanged.
- [ ] **Step 3:** Run `go test ./cmd/portcullis/...`, then on the builder `go test -tags sshd -count=1 -v ./cmd/portcullis/internal/host/` (DinD). Expected: FAIL.
- [ ] **Step 4:** Implement. The units are C24's.
- [ ] **Step 5:** Rerun Step 3. Expected: PASS on all three images.
- [ ] **Step 6:** Commit `cli: host enroll, sync (long-poll, fallback pull, reports), status, remove, certify; real-sshd container tests`.

### Task 15: Hub — UI pages and docs copies (hub)

**Files:**
- Create: `web/ssh.js` (the Hub's SSH access tab: Hosts, Host groups, Grants with the hypothetical preview, Access preview, Certificates, Settings, as spec §9.11) and `web/myssh.js` (the people card on the Sign-in page, People → person, the delegate page, the group page line "SSH: web (own account), all (own account, sudo)").
- Modify: `web/index.html`, `web/people.html`, `web/mysignin.html`, `web/web.go` (embed list and comment), `web/web_test.go`, `web/docs/sync.sh` (C43), then `go generate ./web`.

**Interfaces:**
- Consumes: Task 10's routes, `freshauth.js` for every fresh action (host create, privileged grant, *Sign a host key*).

- [ ] **Step 1:** Write the failing tests in `web/web_test.go`:
  - `TestSSHPagesEmbedded`;
  - `TestSSHScriptsNoInnerHTMLWithData` (the existing pattern check);
  - `TestDocsCopiesInSync` including `ssh-access.md`.
- [ ] **Step 2:** Run `go test ./web/`. Expected: FAIL.
- [ ] **Step 3:** Implement:
  - The enrolment code is shown once in a read-only field with *Copy* and the command `sudo portcullis host enroll < code.txt`, and is never put in a URL.
  - The privileged grant dialog asks for the group's name typed again.
  - Unmanaged entries show the `host trust` command with the `--account` hints from the compile.
- [ ] **Step 4:** Run `go test ./web/` and the Hub checks. Expected: PASS.
- [ ] **Step 5:** Commit `web: ssh access tab, people ssh card, delegate and group pages; docs copies resynced (ssh)`.

### Task 16: Hub — release job and the binary in the image (hub)

**Files:**
- Modify: `.github/workflows/build.yml`:
  - a `cli` job on every run: `go test ./cmd/portcullis/...` on `ubuntu-latest`, `macos-latest` and `windows-latest`;
  - a `cli-release` job on `v*` tags only: the six targets, `-trimpath -buildvcs=true`, the go.mod toolchain; `tar.gz` (zip for Windows); `SHA256SUMS`; `cosign sign-blob --yes --bundle <archive>.sigstore.json`; `actions/attest-build-provenance` pinned by SHA; `gh release upload`; permissions `contents: write`, `id-token: write`, `attestations: write` on that job only;
  - `edge` builds upload the archives as workflow artifacts only.
- Modify: `Dockerfile` (`go build … -o /portcullis ./cmd/portcullis`; `COPY --from=build /portcullis /usr/local/bin/portcullis`).
- Modify: `CLAUDE.md` (Layout rows for `cmd/portcullis`, `internal/cliapi`, `internal/sshaccess`; the CLI's import rule; the sshd test tag).

- [ ] **Step 1:** Run `actionlint .github/workflows/build.yml`. Expected: clean.
- [ ] **Step 2:** Push `ssh1` and run `gh workflow run build.yml --ref ssh1` with your own watcher. Expected: `test`, `cli` (3 OS) and `build` green; the image has `/usr/local/bin/portcullis version` exit 0.
- [ ] **Step 3:** Commit `ci: cli tests on three OSes, tagged cli-release (sums, cosign blobs, provenance), the cli in the hub image`.

### Task 17: Core — Vault SSH mounts, policy, enroll endpoints, vectors (core)

**Files:**
- Modify:
  - `scripts/lib/pki.sh`: `ssh_setup`, called from `pki_setup` on both paths, idempotent, the spec §7.6 commands; an existing mount with a different cap or CA key type is a `fail` naming it, never re-created silently;
  - `vault/policies/enroll.hcl`: spec §7.6 additions with the S4 corrections, and C16;
  - `scripts/lib/vault.sh`: help text.
- Create: `enroll/ssh.go` (handlers and Vault calls), `enroll/testdata/ssh_vectors.json` (byte copy, C17).
- Modify: `enroll/invite.go` (`apiHandler(false)` registers the five routes), `enroll/main.go` (wiring), `.github/workflows/ci.yml` (`unit-tests`' vector step compares `enroll/testdata/ssh_vectors.json` with the Hub's `internal/cliapi/testdata/vectors.json` exactly as the signin vectors).
- Test: `enroll/ssh_test.go`, `enroll/ssh_live_test.go` (`TestLiveSSHVault`, gated by `PORTCULLIS_VAULT_LIVE_ADDR`), `tests/test_cli.sh` (stubbed `vault`: `ssh_setup` command lines, idempotent second run, cap-mismatch failure).

**Interfaces:**
- Produces: the five endpoints with spec §7.6's checks.
  - `POST /internal/ssh-certificates` answers `201 {"certificate","serial","valid_before"}`.
  - `PUT /internal/ssh-roles/{hg}` answers `200` with the role as Vault reads it back (C36).
  - `GET /internal/ssh-ca` answers C16's shape.

- [ ] **Step 1: Write the failing tests:**
  - `TestSSHRoleBodyChecks` (id grammar, principal grammar, 4097 principals, extension set outside the four, 17 CIDRs, 43201 s → 400).
  - `TestSSHRoleStringEncoding` (C15: the Vault write map's values are all strings).
  - `TestSSHSignRefusals` (protected names 409, not in LLDAP 409, key types, principal grammar, `valid_seconds` 299 / 43201, key id form).
  - `TestSSHSignLogsNoKey`.
  - `TestSSHVectors` (the shared file).
  - `TestSSHHostSignCertType` (S4b branch: `cert_type=host` sent).
  - `TestSSHCAProblems`.
  - `TestLiveSSHVault`: S1 and S4 re-run against a real Vault 2.2.1 with the real `enroll.hcl`. It covers every refusal of Task 1 Step 4 and the sk outcome; it is permanent and opt-in.
- [ ] **Step 2:** Run `cd enroll && go test ./...` and `bash tests/test_cli.sh`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Rerun Step 2, then run `TestLiveSSHVault` on the builder (a `ssh1-vault` dev container on an internal network). Expected: PASS.
- [ ] **Step 5:** Commit `vault: ssh_user and ssh_host mounts, enroll ssh policy; enroll: ssh role, sign, host sign and CA endpoints`.

### Task 18: Core — router, secret, server CLI, status (core)

**Files:**
- Modify:
  - `docker-compose.yml` (hub service):
    - `HUB_CLI_ADDR: ":8891"` and `HUB_CLI_PROXY_SECRET: ${HUB_CLI_PROXY_SECRET:?… run ./portcullis init}`;
    - the router `people-cli` exactly as spec §7.3's table; service `hub-cli` on port 8891;
    - `traefik.http.middlewares.hub-cli-proxy-secret.headers.customrequestheaders.X-Portcullis-Proxy-Secret: ${HUB_CLI_PROXY_SECRET}`;
    - the volume `./secrets/ssh:/run/portcullis/ssh:ro` (the break-glass record Task 10 imports; `HUB_SSH_BREAKGLASS_FILE=/run/portcullis/ssh/breakglass.jsonl`).
  - `traefik/dynamic/middlewares.yml`: `strip-identity`, which empties `X-Forwarded-User`, `X-Forwarded-Email`, `X-Forwarded-Preferred-Username`, `X-Auth-Request-User`, `X-Auth-Request-Email`, `X-Auth-Request-Groups`, `X-Auth-Request-Preferred-Username`, `X-Forwarded-Access-Token`, `Authorization`, `X-Forwarded-Impersonator`, `X-Forwarded-Impersonation` and `X-Portcullis-Proxy-Secret`.
  - `scripts/lib/common.sh` (`HUB_CLI_PROXY_SECRET` in `CORE_SECRETS` and `ROTATABLE_SECRETS`; `openssl rand -hex 32`), `.env.example`.
  - `scripts/lib/status.sh` (the SSH block: mounts, caps, CA fingerprints, managed hosts with sync age from the Hub's `GET /api/ssh/hosts` over the host socket's existing client; `--json` `ssh{}`; textfile `portcullis_ssh_ca_ok`).
  - `portcullis` (dispatch `ssh`).
- Create: `scripts/lib/ssh.sh`:
  - `cmd_ssh`, `help_ssh`;
  - `enroll-self [--no-ssh]`: C13; the code is read on stdin and passed on stdin;
  - `breakglass-cert --user <name> --host-group <hg> --ttl 1h --key <pub file> [--note <text>]`: it signs with the root token from `secrets/vault-init.json`, passed to the container through an environment file, never argv. It writes `secrets/ssh/breakglass.jsonl` and prints the certificate. Key id `pc-breakglass:<note>`.
- The Hub's import of `breakglass.jsonl` is Task 10's (`ImportBreakglass`); core only writes the file in the format Task 2's contract fixes.
- Test: `tests/test_cli.sh` (the env-file path, no token on any argv in the stubbed `docker` calls, `enroll-self` stdin, help texts), `tests/test_shell_libs.sh` (status JSON shape); the compose wiring check in `unit-tests` (router rule, priority 200, middlewares order, no forward-auth, entrypoints, service port, no other router targeting 8891).

- [ ] **Step 1:** Write the failing tests above.
- [ ] **Step 2:** Run `bash tests/test_cli.sh` and `bash tests/test_shell_libs.sh`. Expected: FAIL.
- [ ] **Step 3:** Implement. Update `CLAUDE.md`'s rows (router, secret, `ssh.sh`) and `CHANGELOG.md`.
- [ ] **Step 4:** Rerun Step 2, shellcheck and `actionlint`. Expected: PASS.
- [ ] **Step 5:** Commit `core: people-cli router to the hub's cli listener, strip-identity, cli proxy secret, ./portcullis ssh enroll-self and breakglass-cert, status ssh block`.

### Task 19: Core — `e2e-ssh` (core)

**Files:**
- Create: `tests/e2e/sshd/Dockerfile` (pinned `debian:13-slim`; openssh-server, sudo, passwd, procps; `breakglass` user with a test key), `tests/e2e/e2e_ssh.py` (imports `e2e_login` / `e2e_signin` helpers: `check`, `hub_ok`, `invite`, `mask`, `until`), `.github/ci/e2e-ssh-stack.sh` (stack + Hub + the two sshd containers on `portcullis-proxy`, aliases, CI CA for `--ca-file`), `.github/ci/e2e-ssh-artifacts.sh` (the secret scan).
- Modify: `.github/workflows/ci.yml` (job `e2e-ssh`, the `jobs-input` pattern of `e2e-vpn`, timeout 45 min), then `bash tests/lint_ci_size.sh`.

- [ ] **Step 1: Write the cases** (spec §15 step 5; each a `check(name, fn)`). The CLI runs with `--no-browser` (C11). Playwright opens the printed URL with the virtual security key.
  - `setup`: SSH on, host group `web` (`strong`), managed host `web-1` enrolled with `--service none`, unmanaged `web-2` by `host trust`, grants `ssh_web` → `{username}`, `ssh_deploy` → `deploy`, `ssh_admins` → `all` sudo full.
  - `alice_reaches_both_no_sudo`.
  - `alice_sudo_after_join` (managed host, within one long-poll).
  - `bob_deploy_keyid` (`ID pc:bob:web:` in the sshd log).
  - `root_refused`.
  - `password_totp_impersonated_get_nothing` (exit 3 and 4).
  - `replayed_code_refused`.
  - `wrong_key_proof_refused`.
  - `leave_locks_and_revokes` (session ended, refused within seconds on web-1, within one pull on web-2 with `--revoked-keys`).
  - `drift_healed_and_main_override_problem`.
  - `hub_stopped_valid_certs_and_breakglass_work`.
  - `forged_report_and_oversized_bundle_refused`.
  - `cli_client_shape` (the CI Keycloak's `portcullis-cli`, spec §5.3, including `127.0.0.1:40000` and `localhost:38917` refused).
  - `no_secret_anywhere`: no code, verifier, token, enrolment secret or private key in `docker compose logs`, the Hub audit, `issued.jsonl`, the CLI's stderr or the artifacts.
  - `finally`: SSH off, hosts removed.
- [ ] **Step 2:** Run `gh workflow run ci.yml --ref ssh1 -f jobs=e2e-ssh` with your own watcher. Expected: green; the job summary lists every case.
- [ ] **Step 3:** Run the full `ci.yml` on `ssh1`. Expected: every job green; `lint_ci_size.sh` under 450 KB.
- [ ] **Step 4:** Commit `e2e: ssh access (loopback login, managed and unmanaged hosts, revocation, drift, offline, break-glass)`.

### Task 20: Test server (operational)

- [ ] **Step 1:** On the test server (`ACME_STAGING=true`; `config apply` + `up` after init), upgrade to the `ssh1` images built by CI. Run `./portcullis vault init`, `./portcullis pki setup` and `./portcullis status`. Expected: the SSH block ok, both CA fingerprints shown.
- [ ] **Step 2:** Switch SSH access on. Create the host group `web` and grant a CI-style test group (never LLDAP `admin`). Download the `edge` CLI artifact on macOS, Windows and Linux laptops. Run `portcullis login <domain> --ca-file <staging root>` with a security key, then `portcullis status`. Expected: a `web` certificate in the agent on each.
- [ ] **Step 3: Ask the user before enrolling any real host.** Name the VM or machine and say what `host enroll` / `host trust` will change on it (the files under Global Constraints, the service, accounts). Proceed only on their explicit yes, one host at a time. On a yes:
  - enrol a managed VM and set up an unmanaged one;
  - log in to both;
  - revoke from the people card and see the managed host refuse within seconds;
  - run `host remove` on both at the end unless the user says to keep them.
- [ ] **Step 4:** Leave SSH access switched off afterwards unless the user asks otherwise.

### Task 21: Mainline (all repos)

- [ ] **Step 1:** Merge in order: docs → hub (wait for `edge`) → core. Dispatch the Hub's `build.yml` on `main` with `-f compare_ref=ssh1` before core's merge.
- [ ] **Step 2:** Re-run the keycloak and templates CIs on `main`. Expected: green with no change.
- [ ] **Step 3:** Delete every `ssh1` branch (local and remote) and the `wt-ssh1` worktrees (memory "branches mainlined").

## Self-review

- **Spec coverage:**

  | Spec | Task |
  |---|---|
  | §1–§3 | context; 4, 7 |
  | §4.1–4.2 | 3, 11, 14 |
  | §4.3 | 16 (part 4 items excluded) |
  | §4.4 | 11 |
  | §5.1–5.3 | 4, 11 |
  | §5.4 | part 2 |
  | §6 | 5, 11 |
  | §7.1–7.5 | 7 (S1 for §7.5) |
  | §7.6–7.7 | 17 (S4), 5, 6 |
  | §8.1–8.10 | 8, 12, 13, 14 (S3) |
  | §8.11, §8.13 | part 2 (C13) |
  | §8.12 | 14 |
  | §9.1–9.4 | 5 |
  | §9.5 | 9 |
  | §9.6 | 7, 9, 10 |
  | §9.7 | 7, 8, 9, 10 |
  | §9.8 | 5, 10 |
  | §9.9 | 12, 14, 18 |
  | §9.10 | 8, 14 |
  | §9.11 | 10, 15 |
  | §9.12–9.13 | 10, 18 |
  | §10 | part 3 (S2 recorded, C44) |
  | §11 | 2 (docs), 11 (`open`) |
  | §12–13 | Global Constraints, 19 |
  | §14 | 2 |
  | §15 steps 1–7 | 2–20 |
  | §17 Q1–Q7 | Global Constraints (Q1, Q5, Q7), Task 1 (Q2, Q3), 7 (Q4), 14 (Q6) |

- **Task count:** 21 = 1 spike, 1 docs, 14 hub (Tasks 3–16), 3 core (Tasks 17–19), 1 test server, 1 mainline. Keycloak: 0.
- **Type consistency:** these names are used identically across tasks: `cliapi.Bundle`, `cliapi.RoleSpec`, `cliapi.Ceiling`, `freshauth.VerifyAnyUser`, `Result.Impersonated`, `sshaccess.Compile`, `CertPlan`, `TriggerSSHCompile`, `ensureRoleCurrent`, `SSHActions`, `PermSSHAccess`, `host.Transaction`, `host.EffectiveCheck`, `KindSSHCertificate`.
- **Cross-repo file:** `breakglass.jsonl` is written by core (Task 18) and read by the Hub (Task 10, `ImportBreakglass`); its format is fixed in contract §18 (Task 2). Task 18 also mounts `secrets/ssh/` read-only into the Hub.
