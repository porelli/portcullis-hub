# `portcullis login`: a CLI for sign-in, SSH certificates and API tokens (design)

Status: written by the assistant for the roadmap item "something like Amazon's internal CLI, for Mac, Linux and Windows: it authenticates with the YubiKey, gets credentials for web access and signs the person's SSH key so they can reach hosts" (the user's words). No interruptions were wanted, so the assistant made every open decision. Each one is marked **(assistant's call)**. Everything else follows from rulings already on main: the sign-in methods spec (`2026-11-09-sign-in-methods-design.md`), the authenticator codes spec (`2026-11-14-authenticator-codes-design.md`), the multi-server spec (`2026-11-13-multi-server-design.md`), the VPN spec (`2026-11-13-vpn-only-access-design.md`) and the integration contract (§4, §5, §8, §8.1, §9.4–§9.7, §15). Open questions are in §17, each with a default. Work proceeds on the default.

The agreed direction (user):
- a small `portcullis login` CLI;
- OIDC device-code and/or PKCE loopback sign-in against Keycloak, with the person's YubiKey, passkey or certificate;
- a short-lived SSH user certificate signed by Vault's SSH secrets engine, with principals and hosts derived from the person's LLDAP groups (group → host group), so hosts trust the CA instead of `authorized_keys`;
- optionally, tokens for app APIs behind Portcullis, with an honest account of what is possible for browser sessions.

**User ruling (mid-design):** two parts are first-class sections, not afterthoughts:
- **§8, configuring SSH servers** to accept Portcullis certificates end to end, for hosts Portcullis manages and hosts it doesn't;
- **§9, the authorization mapping**: who may log into which host as which account, with or without sudo.

## 1. Where things stand (origin/main, 2026-11-14)

- **Vault** (`vault/vault.hcl`):
  - server mode, raft storage, plain HTTP on the internal `portcullis` network and `127.0.0.1:8200`, auto-unseal from `secrets/vault-unseal/`;
  - mounts: `pki` (root), `pki_int` (YubiKey certificates, role `client-cert`) and `pki_file` (browser certificates, role `browser-cert`), all set up by `scripts/lib/pki.sh`. The multi-server spec adds `pki_node`;
  - there is **no SSH secrets engine** and **no Vault audit device**.
- **enroll is the only Vault signer.**
  - It logs in with the AppRole `portcullis-enroll`. Its policy, `vault/policies/enroll.hcl`, allows: signing on the two client roles with every SAN parameter denied, list/read/revoke, and CRL rotation.
  - The Hub never holds a Vault token. It calls enroll's internal listener (`:8444`, bearer, strict JSON ≤ 64 KiB, `certOpTimeout` 15 s; contract §9.4).
  - enroll refuses `admin`, `portcullis-hub` and `portcullis-*` before Vault is called, and never logs keys or CSRs.
- **Keycloak** (realm `portcullis`, `keycloak/realm-export.json`):
  - browser flow `portcullis-universal`; access tokens 5 min; SSO idle 8 h; SSO max 12 h;
  - core's client is `portcullis-forward-auth`;
  - the Hub owns `portcullis-fresh-auth` (public, PKCE, no refresh tokens; the `portcullis-fresh` mapper puts `pc_fresh` in the ID token) and the AI clients. For those, Keycloak matches loopback redirect URIs **exactly, port included** (verified on 26.8.1);
  - the device grant is off on every client;
  - stock impersonation is disabled; Portcullis impersonation marks tokens with `pc_imp` / `act`.
- **The Keycloak extension**:
  - sign-in methods and templates;
  - `portcullis-fresh`: `pc_fresh` names the method that ran in **this** authentication, and is absent when only the SSO cookie signed the person in.
- **Fresh auth** (Hub `internal/freshauth`):
  - The browser runs a PKCE flow on `portcullis-fresh-auth` with `prompt=login` and `max_age=0`, then posts `{code, code_verifier, nonce}`.
  - **The Hub exchanges the code itself** (single use). It verifies the ID token with `coreos/go-oidc/v3`, then checks `auth_time` ≤ 5 min, the nonce, `azp`, `preferred_username`, and `pc_fresh` against the governing template.
  - Certificates need `pc_fresh` in the allowlist `strongFreshMethods`: `passkey_synced`, `passkey_device`, `security_key`, `yubikey_cert`.
- **Sign-in methods** (contract §8.1), with their strengths:

  | Method | Strength |
  |---|---|
  | `password` | 1.0 |
  | `totp` | 1.5 (never a sole factor) |
  | `passkey_synced` | 2.5 |
  | `browser_cert` | 2.5 |
  | `passkey_device` | 3.0 |
  | `security_key` | 3.5 |
  | `yubikey_cert` | 4.0 |

  Templates include the built-ins `basic`, `standard` and `strong`. Core pages start on `strong`.
- **oauth2-proxy**:
  - cookie sessions only;
  - `_oauth2_proxy` is a ticket for `.<d>`, replayable while the session lives;
  - it injects `Authorization: Bearer <access token>` towards group-gate and apps.
- **group-gate** (policy v6):
  - reads the user only from `X-Auth-Request-Preferred-Username`;
  - decodes `amr` from the access token without verifying it;
  - binds certificate methods to **this** request's certificate;
  - fails closed on unknown policy shapes;
  - doesn't look at `azp` today.
- **mcp-gate** (§15.2) is the precedent for audience-restricted bearer tokens:
  - exactly one URL in `aud`, and an `azp` allowlist;
  - the resource's sign-in rule is checked over `amr` minus the certificate methods;
  - impersonated tokens are refused;
  - the population is checked on every request.
- **Hub**:
  - listeners `:8888` (hub), `:8889` (people) and `:8890` (MCP);
  - `audit.jsonl`;
  - delegated permissions `edit_details`, `invite`, `remove` and `sign_in_help`, with `checkDelegateTarget`'s protected targets;
  - guarding groups (rules on admin-only fields only);
  - one-time join codes (multi-server) as the enrolment precedent.
- **Multi-server** (planned):
  - one primary, with workers joined over the `wg` link role;
  - `portcullis-agent` is a non-root container in the Hub repo;
  - `pki_node` holds node identity;
  - workers have no inbound port and no DNS records of their own;
  - `./portcullis worker join <code>` is run by the host operator.

## 2. Goals, non-goals, anti-goals

**Goals**
1. **`portcullis login`** on macOS, Linux and Windows (amd64, arm64). One browser sign-in with a YubiKey, passkey or certificate gives SSH certificates for every host group the person may reach. The certificates are loaded into their ssh-agent and valid for hours.
2. **Hosts trust a CA, not `authorized_keys`.**
   - **Managed hosts** are enrolled with one command. A host agent then keeps their CA keys, principals, Portcullis accounts, sudo rules, revoked keys and host certificate current, and reports drift.
   - **Unmanaged hosts** get a static trust setup with no Portcullis connection at all.
3. **Authorization mapping**: LLDAP groups → grants → host groups → accounts (per-person or shared) ± sudo. It is managed on one Hub page, previewable ("who can reach web-1 as root?"), delegable within limits, audited, and compiled into Vault role ceilings and host bundles.
4. **Sign-in strength is the Portcullis model**: a fresh sign-in with a method the host group's template accepts. Never a password or a code alone, and never an impersonated session.
5. **Every signing and every mapping change is audited**, refusals included, and signings show in the person's sign-in history.
6. **Revocation**:
   - new certificates stop at once;
   - managed hosts refuse revoked keys and lock removed accounts within seconds (long-poll push);
   - unmanaged hosts within their pull interval or the certificate TTL.
7. **Offline-tolerant hosts**: a host that can't reach Portcullis keeps accepting valid certificates. The extra exposure from a stale revocation list is bounded by the certificate TTL (§8.12).
8. **Multi-server**: Portcullis servers become managed hosts automatically at `worker join`.
9. **Optional API tokens** for gateway apps (part 3).
10. Docs, CI with a real sshd, the doctor, status, and MCP read tools.

**Non-goals (v1)**
- A Portcullis-run bastion, session recording or jump host.
- Putting a session into the person's browser from the CLI, or handing browser cookies to scripts (§11).
- Tokens for native-OIDC apps (§10.2).
- Automating Windows *hosts* (the docs give the manual steps; Windows OpenSSH Server supports `TrustedUserCAKeys`).
- Per-command sudo rules, `force-command`, and certificates for automation without a person. All parked (§16).
- sssd/LDAP against LLDAP on hosts (§8.5 explains why).
- macOS notarization and Windows Authenticode in part 1.

**Anti-goals (never)**
- **A long-lived secret on the person's machine.** The default key exists in memory and in the ssh-agent only, and dies with the certificate. No refresh token in a plain file. No private key is ever sent to Portcullis.
- **A code alone as proof.**
  - The OAuth code isn't enough: it also needs the PKCE verifier, a fresh method and the key proof.
  - Neither is the device user code: device-code sign-in is a full sign-in in a browser.
  - Nor is an authenticator-app code (§8.1's rule).
- **Weakening access control.**
  - No setting lets a password-only or code-only sign-in sign an SSH certificate.
  - No path skips group-gate.
  - There is no `--insecure` / TLS-skip flag.
  - The host tools never delete existing `authorized_keys` of accounts they don't manage, never disable other login paths unless the operator asks explicitly, and never exceed the host's local ceiling (§8.9).
- **Secrets on argv or in logs.** Tokens, codes, verifiers, refresh tokens, enrolment secrets and private keys are never command-line arguments, never logged, and never in the audit, history or error texts.
- **Vault credentials outside enroll.** The Hub, the CLI and hosts never hold a Vault token.
- **Identity from the email.** Identity is the LLDAP username.
- **Silent phone-home.** No telemetry and no update checks. The CLI and hosts talk only to their own Portcullis (§13).
- **An LDAP port exposed to hosts.** LLDAP stays on Portcullis's internal network.

## 3. Architecture in one picture (assistant's call)

```
person's laptop                                          Portcullis primary
┌──────────────────────┐   1. browser: PKCE loopback    ┌──────────────────────────────┐
│ portcullis login     │ ─────────────────────────────▶ │ Keycloak (portcullis-cli)    │
│  - ed25519 key (mem) │ ◀── code to 127.0.0.1:38917 ── │  prompt=login, max_age=0     │
│  - ssh-agent         │   2. {code, verifier, nonce,   │ router people-cli            │
│                      │      public key, key proof}    │  → Hub CLI listener :8891    │
│                      │ ─────────────────────────────▶ │    code exchange, fresh +    │
│                      │ ◀── certs per host group ───── │    template, grants          │
└──────────┬───────────┘                                │    → enroll → Vault          │
           │ 3. ssh alice@web-1                         │       ssh_user/sign/hg-web   │
           ▼                                            │                              │
┌──────────────────────┐   4. long-poll (outgoing only) │ Hub: host bundles (accounts, │
│ host web-1: sshd     │ ─────────────────────────────▶ │ principals, sudo, CA keys,   │
│  portcullis host sync│ ◀── signed-in by host key ──── │ revoked keys, host cert)     │
└──────────────────────┘                                └──────────────────────────────┘
```

- **The Hub exchanges the code; the CLI never holds a token for SSH.** This is the fresh-auth model exactly, reused with a second Hub-owned client. A stolen code is useless without the verifier, and the verifier is useless once the code has been exchanged. (assistant's call)
- **Hosts only ever dial out**, authenticated by their own SSH host key, and keep working with their last bundle when they can't. (assistant's call)

## 4. The CLI

### 4.1 Language, repo, libraries

- **Go**, like the Hub. **It lives in the Hub repo as `cmd/portcullis`** (assistant's call), next to the planned `cmd/portcullis-agent`.
  - The wire types live in `internal/cliapi`, shared by the Hub handlers, the CLI and the host agent.
  - The CLI imports nothing else from Hub internals. A test pins its import graph.
- **One binary** for people and hosts. `portcullis host …` is the host side (needs root). The server operator's `./portcullis` (bash, run by path from the core checkout) keeps its name. The docs say "the Portcullis CLI" and "the server CLI".
- **Libraries** (mature, pinned, Dependabot-tracked):

  | Library | Used for |
  |---|---|
  | `golang.org/x/oauth2` | PKCE (`GenerateVerifier`, `S256ChallengeOption`); the device flow, used by the Hub |
  | `golang.org/x/crypto/ssh` and `…/ssh/agent` | keys, certificates, the agent protocol |
  | `github.com/hiddeco/sshsig` | SSHSIG, for the key proof and host requests (assistant's call) |
  | `github.com/Microsoft/go-winio` | the Windows OpenSSH agent pipe |
  | `github.com/pkg/browser` | opening the browser |
  | `github.com/spf13/cobra` | commands (assistant's call) |
  | `github.com/99designs/keyring` | part 3 only; file backend compiled out |

  On the Hub side: `coreos/go-oidc/v3` + `golang.org/x/oauth2` (already in use). `hashicorp/vault/api` stays in enroll.
- `CGO_ENABLED=0` everywhere, except the macOS build of part 3 (Keychain).

### 4.2 Commands

| Command | What it does |
|---|---|
| `portcullis login [<domain>] [--method <id>] [--key <pub>] [--write-files] [--device]` | sign in, get certificates, load the agent, write the SSH config (§6) |
| `portcullis status` | certificates in the agent (host group, principals, expiry), the person's access |
| `portcullis logout [--revoke]` | removes the Portcullis keys and certificates from the agent and deletes the written files. `--revoke` also revokes this login's certificates (needs a fresh sign-in) |
| `portcullis ssh-config [--install]` | prints, or adds after a y/N question, the `Include` line in `~/.ssh/config` |
| `portcullis open <app>` | opens the app in the default browser (§11) |
| `portcullis host enroll <code>` | **managed host**: one-command enrolment (§8.8) |
| `portcullis host trust …` | **unmanaged host**: static trust, no connection (§8.8) |
| `portcullis host sync` | the managed host's agent (systemd/launchd service) (§8.9) |
| `portcullis host status \| remove \| certify` | host state, clean removal, a host certificate for an unmanaged host |
| `portcullis token <app>`, `portcullis api <app> <method> <path>` | part 3 (§10) |
| `portcullis version` | the version and the CLI API version; no network |

- **First run**: `portcullis login example.com` reads the public `https://people.example.com/api/cli/v1/config`. It saves it in `os.UserConfigDir()/portcullis/config.json` (0600, no secrets). Several domains can be configured; `--domain` picks one.
- **TLS** uses the system trust store. A test server on staging certificates is reached with `--ca-file <pem>`, whose path is saved, or `PORTCULLIS_CA_FILE`. There is no verification-skip flag.
- **Exit codes**:

  | Code | Meaning |
  |---|---|
  | 0 | ok |
  | 1 | error |
  | 2 | usage |
  | 3 | signed in, but no certificate was issued (reasons are printed) |
  | 4 | refused |
  | 5 | Portcullis unreachable |
- **Version skew**: the CLI sends the header `Portcullis-CLI: <version>; api=1`. The Hub answers `426` "update the Portcullis CLI to <min>" when it can't serve that version. The CLI never updates itself.

### 4.3 Distribution (assistant's call)

- **Release binaries** come from a `cli-release` job on the Hub repo's `v*` tags. The CLI version is the Hub version.
  - Targets: `darwin/{amd64,arm64}`, `linux/{amd64,arm64}`, `windows/{amd64,arm64}`.
  - Built with `-trimpath -buildvcs=true` and a pinned Go toolchain.
- **Checksums and signatures**:
  - `SHA256SUMS` over every archive;
  - cosign keyless signatures (GitHub OIDC; identity `^https://github.com/porelli/portcullis-hub/`, as for the images);
  - SLSA provenance (`actions/attest-build-provenance`);
  - the docs show `cosign verify-blob`.
- **In the images**: the Hub image and the `portcullis-agent` image carry the matching Linux binary at `/usr/local/bin/portcullis`. Server hosts take it from the image they already pulled (pinned by digest), so they download nothing extra (§8.13).
- **For people**:
  - the people page links to the GitHub release of the Hub's own version;
  - `go install github.com/porelli/portcullis-hub/cmd/portcullis@<tag>` works too.
- **Part 4**:
  - a Homebrew tap (`porelli/homebrew-tap`), winget manifests, and `.deb` / `.rpm` packages (`goreleaser/nfpm`);
  - Developer ID notarization and Authenticode once the project has those accounts. Until then the docs explain Gatekeeper and SmartScreen honestly.
- `edge` builds are workflow artifacts only.

### 4.4 Where the key and certificates live (assistant's call)

- **The default is an ephemeral key in the agent.** `login` generates an **ed25519** key in memory. It adds key + certificate to the ssh-agent once per host group, with `LifetimeSecs` = until the certificate expires and the comment `portcullis <domain> <host group>`.
  - The agent is `SSH_AUTH_SOCK` on macOS/Linux and the OpenSSH named pipe on Windows.
  - Each login replaces that domain's previous Portcullis keys.
- **Only public files go on disk**, under `~/.ssh/portcullis/<domain>/` (directory 0700): `id.pub`, `<host group>-cert.pub`, `known_hosts` and `config`.
- **No agent available**:
  - `login` refuses and hints at `--write-files`, which writes the ephemeral private key (0600). The key is useless after expiry, and `logout` deletes it. Never the default.
  - An agent that refuses lifetime constraints gets the key without one, and the CLI says so. An agent that refuses adds (1Password, Secretive) gets a hint at `--key`.
- **Bring your own key**: `--key ~/.ssh/id_ed25519_sk.pub` signs an existing key, typically a **FIDO key** (`sk-ssh-ed25519@openssh.com`: one touch per SSH use). The key must be in the agent (it makes the key proof, §7.4).
- **Nothing else is stored.** No ID, access or refresh token for SSH. Part 3 keeps one refresh token, in the OS keyring only.

## 5. Sign-in flows

### 5.1 PKCE loopback, the default (assistant's call)

1. **Bind a loopback port.** The CLI binds `127.0.0.1:38917`, then `38918`, then `38919`: Keycloak matches the port exactly. It never binds `0.0.0.0` or `localhost`.
2. **Open the browser** on the realm's `auth` endpoint with:
   - `client_id=portcullis-cli`, `response_type=code`, `scope=openid`, `redirect_uri=http://127.0.0.1:<port>/callback`;
   - a random `state` and `nonce`, and an S256 `code_challenge`;
   - **`prompt=login` and `max_age=0`**;
   - `pc_method=<id>` when `--method` is given.
3. **The person signs in in their browser** with what the template allows. That browser keeps its SSO session as a side effect (§11).
4. **One callback.** The loopback handler accepts exactly one `GET /callback` with the right `state`. It answers a static "You can close this tab" page (`no-store`, no script), then closes. Anything else gets a 404. Timeout: 5 minutes.
5. **Post to the Hub.** The CLI posts `{code, code_verifier, nonce, redirect_uri, public_key, key_proof}` to the Hub (§7.3). It never calls Keycloak's token endpoint.

Phishing resistance:
- an attacker can't receive a code sent to the victim's loopback;
- passkeys and security keys are bound to the origin `auth.<d>`;
- a local process that grabs the port lacks the verifier.

### 5.2 Discovery (public)

`GET https://people.<d>/api/cli/v1/config` → `{"api": 1, "domain", "issuer", "authorize_url", "client_id": "portcullis-cli", "redirect_ports": [38917, 38918, 38919], "device": false, "min_cli"}`. No person data and no host data.

### 5.3 The Keycloak client `portcullis-cli` (Hub-owned)

- **Ownership.** The Hub ensures the client in the directory sync loop, like `portcullis-fresh-auth`, with owner tag `portcullis.hub.template` = `portcullis-cli`. If an untagged or foreign client holds that id, every CLI sign-in fails closed (`503` + doctor Problem `ssh_cli_client_conflict`).
- **Flows.**
  - Public; standard flow only; PKCE S256 required.
  - Implicit, direct grants, service accounts, device grant, CIBA and token exchange are off.
  - `use.refresh.tokens=false`; no `offline_access`; no consent screen.
- **Redirect URIs**: exactly the three loopback URLs. No web origins.
- **Default scopes**: exactly `basic` and `acr`.
- **Mappers**: exactly two, `preferred_username` (ID token) and `portcullis-fresh`.
- **Protected id**: templates may not use it.
- **Tested** by `TestLiveCLIObjects` on the live CI Keycloak, including that `127.0.0.1:40000` and `localhost:38917` are refused.

### 5.4 Device code: part 2, off by default (assistant's call)

Device code is phishable by construction: anyone can start a flow and send someone the link. So:

- **A separate client.** `portcullis-cli-device` has only the device grant on, so `azp` names the flow.
- **The Hub runs the grant.**
  - `POST /api/cli/v1/device/start` returns `{handle, user_code, verification_uri, expires_in, interval}`. It never returns `verification_uri_complete`: the person types the code.
  - The CLI polls `POST /api/cli/v1/device/poll {handle, public_key, key_proof}`. The `device_code` never leaves the Hub.
- **A fresh sign-in is forced.** The client is bound to a Hub-managed copy of the browser flow *without* `auth-cookie`, using the access-role flow-copy machinery of contract §8.
- **A network fence.** Settings → SSH → *Device-code sign-in* lists the networks a device-code login may start and poll from. The default is the Local networks plus `PORTCULLIS_VPN_SUBNET`. Anything outside gets `403`.
- **Short-lived codes**: 5 minutes, polled every 5 s.
- **A warning page.** The theme's device page warns: "Only continue if **you** just ran `portcullis login` on a computer in front of you. Someone who sent you this code can use your access."
- **Recorded.** Every device-code certificate goes into the history and the audit with `flow=device` and the polling address. The person sees a notice on their next people-page visit.

## 6. SSH client configuration written by the CLI

`~/.ssh/portcullis/<domain>/config` is regenerated at every login. It is included from `~/.ssh/config` by one line, `Include ~/.ssh/portcullis/*/config`, which the CLI offers to add (y/N, never silently) (assistant's call):

```
# Written by portcullis login for example.com. Do not edit.
Match host web-1.example.com,web-2.example.com,10.20.0.11,10.20.0.12
  IdentityFile ~/.ssh/portcullis/example.com/id.pub
  CertificateFile ~/.ssh/portcullis/example.com/web-cert.pub
  IdentitiesOnly yes
  UserKnownHostsFile ~/.ssh/known_hosts ~/.ssh/portcullis/example.com/known_hosts
```

- There is one `Match` block per host group. Its names are the managed hosts' names and addresses plus the group's patterns for unmanaged hosts.
- `known_hosts` holds the `@cert-authority` lines, scoped to the same names (§8.10), and `@revoked` lines.
- With few host groups, hosts outside every pattern still work: ssh tries each agent identity.

## 7. Signing

### 7.1 Who may get what

At every signing the Hub reads a **fresh directory snapshot** (the `gate` path used by delegated actions) and applies the mapping (§9):

- **Refused outright** (`409`): `admin`, `portcullis-hub`, every `portcullis-*` name, a disabled Keycloak user, and anyone not in LLDAP.
- **Computed per host group**: for each grant whose LLDAP group the person is in *now* (expired temporary memberships excluded), the grant's host group and accounts.
- **One certificate per host group**. Its principals are `<account>@<host group>` for each account (§8.3). Its extensions and `valid before` follow the merge rules (§9.3).

### 7.2 Strength

Each host group has a **governing template** (default `strong`). A host group's certificate is issued only when the proof's `pc_fresh` meets both conditions:

1. it is a method the host group's template **accepts**: the strongest method of at least one alternative of the compiled rule, with switched-on methods only (contract §8 "Governing template");
2. it is in `strongFreshMethods` (assistant's call: an SSH certificate is a certificate). So `password`, `totp` and `browser_cert` never sign, whatever the template says.

Other rules:
- **Unusable templates.** A template that no allowlisted method can meet can't be chosen for a host group (`409`).
- **Unmet groups are listed.** Host groups whose template the proof doesn't meet are listed in the answer with the reason ("prod needs a YubiKey: sign in with `--method security_key`"). The other groups are issued.
- **Never impersonated.** An ID token with `pc_imp` or `act` is refused (`403` "a session as someone else can't get SSH certificates"). (assistant's call; the AI rule)

### 7.3 The Hub's CLI listener and route

**The listener.** A new Hub listener, `:8891`, serves only `/api/cli/v1/*` (assistant's call). It never trusts a forward-auth identity, and no other Hub route is reachable through it.

**The router.** Core adds `people-cli` with these settings:

| Setting | Value |
|---|---|
| Rule | `` Host(`people.<d>`) && PathPrefix(`/api/cli/v1/`) `` |
| Priority | 200 |
| TLS options | `authaware@file` |
| Middlewares | `rate-limit-auth@file`, `strip-identity@file` (empties every core identity header, the public routers' list), `security-headers@file`, `hub-cli-proxy-secret@docker` |
| Service | `hub-cli` |
| Forward-auth | **none**: the proof is the authentication, as on `keycloak` and `enroll-invite` |
| Entrypoints | `${PORTCULLIS_EP_ENROL:-websecure,vpnsecure}`: wherever a person reaches Keycloak |

**`POST /api/cli/v1/ssh/certificates`** takes strict JSON, at most 16 KiB:

```json
{"code": "…", "code_verifier": "…", "nonce": "…",
 "redirect_uri": "http://127.0.0.1:38917/callback",
 "public_key": "ssh-ed25519 AAAA…",
 "key_proof": "-----BEGIN SSH SIGNATURE-----…",
 "host_groups": []}
```

An empty `host_groups` means all the person's groups. Ids that are unknown or not granted are listed as refused; the answer never reveals other groups.

**The Hub's steps**, in order:
1. **Exchange the code** with `freshauth` configured for `portcullis-cli`. The package gains a `ClientID` field, and the redirect URI must be one of the three.
2. **Run every freshauth check**, then the impersonation check.
3. **Identify the person** by `preferred_username`.
4. **Verify the key proof** (§7.4) and the key type (§7.5).
5. **Check the revoked-keys list** (§8.7).
6. **Compute** §7.1–7.2.
7. **Make sure each host group's Vault role is current** (§9.2).
8. **Have enroll sign** one certificate per host group (§7.6).
9. **Audit and record history** (§9.7).
10. **Answer**:

    ```json
    {"user": "alice",
     "certificates": [{"host_group": "web", "certificate": "ssh-ed25519-cert-v01@openssh.com AAAA…",
                       "principals": ["alice@web"], "serial": "1234567890",
                       "valid_before": "2026-11-15T18:04:05Z",
                       "hosts": ["web-1.example.com", "web-2.example.com"]}],
     "refused": [{"host_group": "prod", "reason": "prod needs a YubiKey: sign in with --method security_key"}],
     "host_cas": ["ssh-ed25519 AAAA…"], "revoked_host_keys": []}
    ```

**Refusals and limits.**
- Proof failures answer the fixed `403` "a fresh sign-in is required". The reason goes to the log and the audit only.
- Refusals are limited to 10 a minute per address and per person (`429`). Successful signings are limited to 6 a minute per person. (assistant's call)

### 7.4 Proof of possession (assistant's call)

**What is signed.** The CLI signs this canonical JSON as an **SSHSIG** (namespace `portcullis-ssh-certificate@v1`, SHA-512):

```json
{"domain": "example.com", "nonce": "<OIDC nonce>", "code_sha256": "<hex>", "public_key": "<authorized_keys line>"}
```

- For `--key`, the signature is made through the agent (a FIDO key asks for one touch). For the default key, it is made in memory.
- The Hub rebuilds the message and verifies the signature with the posted key.
- The code is single-use, so a proof can't be replayed. It binds this sign-in to this key, which is exactly what the audit claims.

### 7.5 Key types (assistant's call)

- **Accepted**: `ssh-ed25519`, `sk-ssh-ed25519@openssh.com`, `ecdsa-sha2-nistp256` and `sk-ecdsa-sha2-nistp256@openssh.com`.
- **Refused**: RSA of any size, DSA, and ECDSA P-384/521.
- **The `sk-*` types depend on Vault.** If the pinned Vault refuses them in `allowed_user_key_lengths`, part 1 ships without them (`TestLiveSSHKeyTypes`, §17 Q2).

### 7.6 Vault: mounts, per-host-group roles, policy (assistant's call on every value)

**Mounts.** `./portcullis vault init` / `pki setup` set them up (idempotent):

```
vault secrets enable -path=ssh_user ssh
vault secrets tune -max-lease-ttl=12h ssh_user          # structural cap: no user cert over 12 h
vault write ssh_user/config/ca generate_signing_key=true key_type=ed25519

vault secrets enable -path=ssh_host ssh
vault secrets tune -max-lease-ttl=2160h ssh_host
vault write ssh_host/config/ca generate_signing_key=true key_type=ed25519
vault write ssh_host/roles/host key_type=ca allow_host_certificates=true \
    allow_user_certificates=false allowed_domains="*" allow_subdomains=true \
    allow_bare_domains=true ttl=2160h max_ttl=2160h
```

**One user role per host group: `ssh_user/roles/hg-<id>`.**
- The Hub's mapping compiles into these roles (§9.2) and enroll writes them. Each holds:
  - `allowed_users`: the exact principal list for that host group;
  - `allowed_extensions`: the ceiling over all its grants;
  - `default_critical_options`: `source-address` from the host group;
  - `max_ttl`: the longest grant TTL;
  - `allowed_user_key_lengths`: §7.5.
- A signing runs on the person's host group's role. Even a bug in the Hub's merge can't exceed what the role allows, and the role's principal list is visible and diffable.

**Two CAs on two mounts.** A host-signing compromise can't mint user certificates, and the reverse.

**`vault/policies/enroll.hcl`** gains:

```hcl
path "ssh_user/sign/hg-*" {
  capabilities = ["update"]
  denied_parameters = { "cert_type" = [], "critical_options" = [] }   # source-address only from the role
}
path "ssh_user/roles/hg-*" {
  capabilities = ["create", "update", "read", "delete", "list"]
  allowed_parameters = {
    "key_type"                 = ["ca"]
    "allow_user_certificates"  = ["true"]
    "allow_host_certificates"  = ["false"]
    "allow_user_key_ids"       = ["true"]
    "allowed_users"            = []
    "allowed_extensions"       = ["permit-pty", "permit-pty,permit-port-forwarding",
                                  "permit-pty,permit-agent-forwarding",
                                  "permit-pty,permit-port-forwarding,permit-agent-forwarding"]
    "default_extensions"       = []
    "allowed_critical_options" = ["", "source-address"]
    "default_critical_options" = []
    "allowed_user_key_lengths" = []
    "ttl"                      = []
    "max_ttl"                  = []
  }
}
path "ssh_host/sign/host" {
  capabilities = ["update"]
  denied_parameters = { "cert_type" = [] }
}
```

This policy means that not even enroll can create a role that issues host certificates, X11 / user-rc / `force-command` certificates, or certificates over 12 hours (the mount cap).

**enroll's internal endpoints** follow the contract §9.4 rules and log what they sign, never keys:

| Endpoint | Body or answer | What enroll checks |
|---|---|---|
| `PUT /internal/ssh-roles/{hg}` | `{"principals", "extensions", "source_address", "max_ttl_s"}` | the role id, the principal grammar, ≤ 4096 principals, the four extension sets, ≤ 16 CIDRs, ≤ 43200 s |
| `DELETE /internal/ssh-roles/{hg}` | — | — |
| `POST /internal/ssh-certificates` | `{"user", "host_group", "public_key", "principals", "valid_seconds", "extensions", "key_id"}` → `201 {"certificate", "serial", "valid_before"}` | refuses protected names, users not in LLDAP, key types outside §7.5, principals not matching `^([a-z_][a-z0-9._-]{0,31})@([a-z][a-z0-9-]{0,30})$`, a `valid_seconds` outside 300–43200, and a key id other than `pc:<user>:<hg>:<16 hex>` |
| `POST /internal/ssh-host-certificates` | `{"public_key", "principals", "host_group"}` | — |
| `GET /internal/ssh-ca` | `{"user_cas", "host_cas"}` | — |

**The key id** `pc:<user>:<host group>:<request id>` appears in sshd's log at every login (`Accepted publickey for alice … ID pc:alice:web:…`). Host logs name the person even for shared accounts, and the request id finds the audit entry.

**No Vault audit device in v1** (assistant's call). It would log every enroll login, PKI call and metrics scrape, and tie Vault's availability to the log sink. The signing record is §9.7. Parked.

### 7.7 Extensions and critical options (assistant's call)

| Extension / option | Default | Changed by |
|---|---|---|
| `permit-pty` | on | always on |
| `permit-port-forwarding` | **off** | per grant |
| `permit-agent-forwarding` | **off** | per grant; makes the grant privileged |
| `permit-X11-forwarding`, `permit-user-rc`, `force-command` | never | not offered |
| `source-address` | none | per host group: CIDRs, or the shortcut "Only through the Portcullis VPN" (the built-in VPN subnet plus ticked marketplace VPN ranges); enforced from the Vault role |

## 8. Configuring SSH servers to accept Portcullis certificates

This section covers both kinds of host end to end. The mapping that decides *who* may log in where is §9.

### 8.1 Two kinds of host (assistant's call: managed is recommended)

| | **Managed host** | **Unmanaged host** |
|---|---|---|
| How | `sudo portcullis host enroll <code>` (§8.8) | `sudo portcullis host trust …` (§8.8) |
| Talks to Portcullis | outgoing HTTPS long-poll, authenticated by its host key | never (optionally pulls the public revoked-keys list) |
| CA keys, rotation | automatic, with overlap | operator re-runs `host trust` |
| Principals files | from the bundle, kept current | written once for the accounts given |
| Per-person accounts | created / locked by the agent | the operator's job |
| sudo | from the bundle (`/etc/sudoers.d/portcullis`) | the operator's job |
| Revoked keys | pushed within seconds (long-poll) | optional 5-minute pull, else TTL only |
| Host certificate | issued and renewed automatically | admin runs `portcullis host certify` |
| Drift detection | yes (§9.10) | no; listed as "unmanaged" in previews |
| Typical | team servers, Portcullis servers | appliances, hosts you don't own, air-gapped hosts |

Both need OpenSSH ≥ 8.2 with `Include /etc/ssh/sshd_config.d/*.conf` (Debian, Ubuntu, Fedora, RHEL 9 and macOS 13+). On other systems the tools refuse and print the lines to add by hand. They never edit the main `sshd_config` (assistant's call).

### 8.2 Trusting the CA: `TrustedUserCAKeys` and distributing the public key

- **The trust file** is `/etc/ssh/portcullis/user_ca.pub` (root 0644). It holds one or two user CA public keys (two during a rotation, §8.11).
- **Distribution, managed hosts**: the key comes inside the bundle. The very first key is pinned by the enrolment code's CA fingerprint.
- **Distribution, unmanaged hosts**: the key is passed with `--ca-key 'ssh-ed25519 AAAA…'`, the public line the Hub page shows. Alternatively it is fetched from `https://people.<d>/api/cli/v1/ssh/ca`, but **only** together with `--ca-fingerprint SHA256:…`, and only when it matches. There is no unpinned fetch.
- **Nothing on the host can sign.** It holds public keys only and never talks to Vault.

### 8.3 Principals: `AuthorizedPrincipalsFile`, not the command (assistant's call)

- **The decision**: `AuthorizedPrincipalsFile /etc/ssh/portcullis/principals/%u`, with one file per account that Portcullis may reach. Each file lists the principals that may log in as that account.
- **The alternative**, `AuthorizedPrincipalsCommand`, was rejected:
  - it puts an executable in the authentication path, run for every attempt, which is a new attack surface;
  - its output can't be compared for drift the way a file can.

  Files are static, readable, diffable and validated by `sshd -T`. The agent rewrites them whenever the bundle changes, so the main argument for the command, grants changing without touching the host, holds anyway on managed hosts.
- **The principal format** is `<account>@<host group>`, e.g. `alice@web`, `deploy@web` or `alice@all`.
  - A certificate carries the principals its host group allows.
  - A host's file for an account lists `<account>@<g>` for each host group `g` the host belongs to and that grants this account.
  - A `web` certificate is therefore worthless on a `db` host.
- **No file for an account** means no certificate login as that account. `AuthorizedPrincipalsFile` affects certificates only, so the account's existing `authorized_keys` and passwords keep working unless the host is told otherwise (§8.4).

### 8.4 From a principal to a local Unix account (assistant's call: per-person by default)

There are two kinds of account. A grant names one or both.

- **Per-person accounts**: the grant's account is `{username}`.
  - The account is named after the LLDAP username: alice logs in as `alice`.
  - **Recommended by default.** The login account *is* the person in `auth.log`, `last`, `ps`, file ownership and audit tools. Sudo is granted per person. Locking one person doesn't touch anyone else. Nobody shares a home directory.
  - LLDAP usernames match `^[a-z0-9][a-z0-9._-]{0,63}$`. The host additionally needs ≤ 32 characters and no leading digit on some systems. When a username can't be a local account on a host, the agent reports `ssh_host_account_invalid` and skips it (the person still reaches shared accounts).
- **Shared role accounts**: the grant names a fixed account, `deploy`, `backup` or `admin`.
  - Use them for a role, not a person: deploy pipelines run by people, an appliance's single admin login.
  - The key id in sshd's log still names the person.
  - Recommended **without sudo**. Shared accounts with sudo are allowed but are privileged grants (§9.4).
  - `root` is a shared account and always privileged. Recommendation: grant sudo on per-person accounts rather than `root`. It only reaches hosts whose local ceiling allows root logins (§8.9).
- **Certificate-only Portcullis accounts.** For per-person accounts created by Portcullis, the agent's drop-in sets `Match Group portcullis-users` → `AuthorizedKeysFile none`, `PasswordAuthentication no`, `KbdInteractiveAuthentication no`. Nobody can plant a backdoor key in `~alice/.ssh/authorized_keys`, and taking alice out of the group really ends her access. (assistant's call) Shared accounts keep whatever the operator set; drift reports `authorized_keys` on them (§9.10).

### 8.5 Account creation (assistant's call: the managed host's bundle)

| Option | Verdict |
|---|---|
| **Manual** (`useradd` by the operator) | The only option on **unmanaged** hosts, and for shared accounts everywhere unless the host group opts in |
| **sssd / nslcd against LLDAP** | Rejected. Hosts would need LLDAP's LDAP port, which today is on Portcullis's internal network only (an anti-goal to expose). Logins would depend on a live LDAP connection, against offline tolerance. LLDAP has no POSIX attributes (`uidNumber`, `loginShell`) without custom ones. And the agent already knows exactly who should exist, without exposing the directory |
| **Created at first login by `AuthorizedPrincipalsCommand` + `useradd`** | Rejected. It would run `useradd` as root in the authentication path on attacker-chosen input, to create an account before sshd decides. sshd runs the command as an unprivileged user anyway |
| **The managed host's bundle** | **Chosen.** The agent (`portcullis host sync`, root) creates, updates and locks per-person accounts from the bundle, before anyone logs in |

How accounts are created:
- **UIDs** are allocated by the Hub per person from `20000–59999`, stored in Hub state and never reused. The same person has the same uid on every host, which is safe for NFS. The primary gid is a per-person group with the same number. Every Portcullis account is also in the local group `portcullis-users`.
- **Creation** happens when a grant first gives the person an account on the host: `useradd -u <uid> -U -G portcullis-users -m -s <shell> -c 'portcullis:<username>' <name>`. The shell is `/bin/bash` if present, else `/bin/sh`. The home directory is created on the first apply.
- **Never touched**: an account with that name that the agent didn't create (no `portcullis:` comment, or not in `portcullis-users`) is a conflict (`ssh_host_account_conflict`) and is skipped. Accounts outside the uid range and the host's protected list (§8.9) are never touched either.
- **Losing access** (removed from the grant's group, or the grant deleted) locks the account at the next sync:
  - `usermod -L -e 1 -s /usr/sbin/nologin`;
  - the principals file is removed;
  - running sessions are ended (`loginctl terminate-user`, falling back to `pkill -KILL -u`) (assistant's call: revocation that leaves a live root shell isn't revocation).
- **Deletion** never happens automatically. *Remove account* on the host's page (admin) runs `userdel` and keeps the home directory under `/home/.portcullis-removed/<name>-<date>`.
- **Shared accounts** are created by the agent only when the host group says "Portcullis creates shared accounts" (default off). Otherwise the operator creates them, and drift reports `ssh_host_account_missing`.

### 8.6 sudo (assistant's call)

- **Per (host, account)**, from the grants. An account has sudo on a host when any grant that applies to this host and account says `sudo: full`.
- **Managed hosts** get `/etc/sudoers.d/portcullis` (0440). It is validated with `visudo -cf` before the atomic replace, and the old file is kept on failure. It holds one line per sudo account: `alice ALL=(ALL:ALL) NOPASSWD: ALL`.
- **Why `NOPASSWD`**: Portcullis accounts have no local password, by design. The proof is the fresh hardware sign-in that produced the certificate, and the certificate's TTL bounds it. "sudo needs a fresh touch" (a PAM module that checks a short-lived Portcullis assertion) is parked. Until then, sudo grants are privileged (§9.4) and default to a shorter TTL (4 h).
- **Two levels only**: `none` and `full`. Per-command sudo rules are parked.
- **Unmanaged hosts**: the operator writes sudoers. The Hub's preview marks those hosts "sudo unknown (unmanaged)".

### 8.7 Revoked keys, pushed to hosts (assistant's call)

- **Format**: the plain OpenSSH `RevokedKeys` format, one public key per line. Revoking a key revokes every certificate for it, and default keys are per login, so this is precise. No KRL library is needed. The binary KRL format is parked.
- **Managed hosts**: the list is part of the bundle. The agent holds a **long-poll** (`GET …/hosts/bundle?since=<serial>`, held up to 55 s), so a revocation reaches every connected host **within seconds**. Push semantics, with no inbound port on the host.
- **Unmanaged hosts**: `portcullis host trust --revoked-keys` installs a 5-minute timer that pulls the public `https://people.<d>/api/cli/v1/ssh/revoked-keys`. The list holds public keys only. A failed fetch keeps the last file.
- **The file always exists.** It is created empty before `RevokedKeys` is configured: sshd refuses *every* public key when that file is unreadable, which would lock out break-glass keys too.
- **When entries are added** is listed in §9.6. Entries stay until 24 h after the last certificate for that key expires. A revoked bring-your-own key stays revoked until the person removes it from their card, and the Hub won't sign it meanwhile.

### 8.8 One-command enrolment

**Managed host.**
1. **Create the host.** An administrator opens Hub → SSH access → Hosts → *Add host* and enters a name, its addresses and its host groups. This needs a fresh sign-in under the `hub` template. The Hub shows a **one-time enrolment code**, valid 15 minutes and single use. It carries the domain, host id, host groups, both CA fingerprints and a 256-bit secret, of which only the hash is stored. This is the multi-server join-code pattern.
2. **Enrol.** On the host, `sudo portcullis host enroll <code>`:
   - The code is read from **stdin** when not given, and the docs show `portcullis host enroll < code.txt`, so the secret is never on argv. A code given as an argument is accepted only from a terminal prompt (`-`) (assistant's call). The binary never passes it on.
   - It writes `/etc/portcullis/host.json`: the local ceiling (§8.9), asked interactively or given as flags.
   - It proves the secret with an HMAC over a nonce from the Hub, and sends the host's ed25519 host public key. The Hub pins that key: all later requests from the host are SSHSIGs by it.
   - It fetches the first bundle, writes every file (§8.9), runs **`sshd -t`**, and checks the effective config with `sshd -T -C user=<a portcullis account>` and `-C user=<the break-glass account>`.
   - It reloads sshd (`systemctl reload ssh|sshd`, or `launchctl kickstart -k system/com.openssh.sshd`).
   - It installs and starts the `portcullis-host-sync` service.
   - **Any failure restores every file**, leaves sshd as it was, and reports `ssh.host.enrol` `error` to the Hub.
3. The host is `ready` and shows its last sync, bundle serial and drift.

**Unmanaged host.**

```
sudo portcullis host trust --domain example.com --host-group web \
     --ca-key 'ssh-ed25519 AAAA…' --account deploy --account alice [--revoked-keys]
```

It writes the CA key, one principals file per `--account` (`<account>@web`), the drop-in and, with `--revoked-keys`, the empty revoked-keys file and the timer. Then it runs `sshd -t` and reloads, rolling back on any failure. It makes no connection unless `--revoked-keys` is given.

**Removing a host.** `sudo portcullis host remove` deletes exactly the files the tools wrote and reloads sshd. It locks Portcullis-created accounts (`--delete-accounts` deletes them, keeping home directories) and stops the service.

### 8.9 The managed host's agent, its bundle and its local ceiling

**The service.** `portcullis host sync` runs as a root systemd service (a launchd daemon on macOS), hardened with `ProtectSystem=strict` and write access only to `/etc/ssh/portcullis`, `/etc/ssh/sshd_config.d/50-portcullis.conf`, `/etc/sudoers.d/portcullis`, `/etc/passwd`, `/etc/group`, `/etc/shadow`, `/etc/gshadow` and `/home`. Plus `NoNewPrivileges`, `PrivateTmp`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`. It makes one outgoing connection, to its Portcullis, and has no listener.

**The bundle** (`internal/cliapi`, strict JSON, ≤ 4 MiB, `version` 1) is generated by the Hub for each host:

```json
{"version": 1, "host_id": "web-1", "serial": 42, "generated": "2026-11-15T09:00:00Z",
 "user_cas": ["ssh-ed25519 AAAA… portcullis-user-ca"],
 "host_certificate": "ssh-ed25519-cert-v01@openssh.com AAAA…",
 "accounts": [
   {"name": "alice", "kind": "person", "uid": 20001, "principals": ["alice@web", "alice@all"], "sudo": true},
   {"name": "bob",   "kind": "person", "uid": 20002, "principals": ["bob@web"], "sudo": false},
   {"name": "deploy","kind": "shared", "principals": ["deploy@web"], "sudo": false}],
 "locked": ["carol"],
 "revoked_keys": ["ssh-ed25519 AAAA…"],
 "options": {"create_shared_accounts": false}}
```

**What the agent writes** from it, each file atomically, owned by root:
- `/etc/ssh/portcullis/user_ca.pub`;
- `principals/<account>` (0644; the directory is 0755 root, as sshd requires);
- `revoked_keys`;
- the host certificate next to the host key;
- the sudoers file;
- the drop-in:

  ```
  # Written by portcullis host sync (example.com, host web-1). Do not edit.
  TrustedUserCAKeys /etc/ssh/portcullis/user_ca.pub
  AuthorizedPrincipalsFile /etc/ssh/portcullis/principals/%u
  RevokedKeys /etc/ssh/portcullis/revoked_keys
  HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
  Match Group portcullis-users
      AuthorizedKeysFile none
      PasswordAuthentication no
      KbdInteractiveAuthentication no
  ```

  Every time, the agent checks with `sshd -T -C …` that the `Match` block applies to a Portcullis account and *not* to the break-glass account. (sshd keeps the first value it reads for a keyword, and `Match` scoping inside included files is subtle. The check makes this concrete instead of assumed, §9.10.)

**The local ceiling** `/etc/portcullis/host.json` is written at enrolment by the host's operator and is **never changed by a bundle** (assistant's call). It holds:
- `allow_sudo` (default true);
- `allow_root_login` (default false);
- `uid_range`;
- `protected_accounts` (default: every account below uid 1000, plus `breakglass_account`);
- `breakglass_account` (default `breakglass`);
- `max_accounts` (default 500).

A bundle that would exceed the ceiling isn't partly applied. The offending entries are skipped and reported (`ssh_host_ceiling`). This bounds what a compromised Hub could do to a host: it can't grant root logins or touch protected accounts where the operator said no.

**Each apply** writes everything, validates with `visudo -cf` and `sshd -t`, then reloads sshd only if a file changed. Any validation failure keeps the previous files and reports an error. The agent never leaves sshd with a broken config.

### 8.10 Host certificates (assistant's call)

- **Per host group**: a switch "Host certificates" (on by default for managed hosts).
- **Managed hosts** get a host certificate at enrolment, with principals = the host's names and addresses as entered by the admin. The agent renews it at ⅓ remaining life. The TTL is 90 days.
- **Unmanaged hosts**: an administrator runs `portcullis host certify --host-group web --key ssh_host_ed25519_key.pub --name web-9.example.com`, or uses *Sign a host key* on the Hub page. This needs a fresh `security_key` / `yubikey_cert` sign-in, stricter than any template (as for impersonation). Each name must match the group's patterns.
- **Clients**: `login` writes `@cert-authority <the group's names> <host CA keys>` into `~/.ssh/portcullis/<d>/known_hosts`, so a host certificate is trusted only for names in its own group. Revoked host keys become `@revoked` lines.

### 8.11 CA rotation with overlap (part 2; assistant's call)

`./portcullis ssh rotate-ca user|host` (server CLI) or Hub → SSH access → Settings → *Rotate CA* (admin, fresh sign-in, typed confirm) runs these steps:

1. **New CA.** Create it on a second mount (`ssh_user_next` / `ssh_host_next`) with the same roles.
2. **Trust both.** Bundles carry both keys; `user_ca.pub` lists both. The Hub page shows which managed hosts have applied the bundle, and lists unmanaged hosts as "re-run `host trust` with both keys" (the page gives the command).
3. **Switch signing** once every managed host has confirmed (or the admin overrides, typing the number of hosts not confirmed). New certificates now come from the new CA, and the old ones keep working.
4. **Drop the old CA** after `max_ttl` (12 h): it leaves the bundles, then its mount is deleted. Unmanaged hosts that still trust it are harmless (nothing signs with it any more). The doctor lists them (`ssh_host_old_ca`).

For host CA rotation, clients get both `@cert-authority` lines at every login during the overlap, and managed hosts receive new host certificates through the agent. Every step is audited (`ssh.ca.rotate`, with a stage).

### 8.12 When the host can't reach Portcullis

**What keeps working.** A managed host keeps its last bundle **indefinitely** (assistant's call). Certificates are self-contained: sshd checks them against the local CA file, principals files and revoked-keys file, and needs no network. People with valid certificates keep logging in.

**How fresh the revocation list is.** It is as fresh as the last successful sync. The exposure is bounded:
- every user certificate expires in ≤ 12 h (the mount cap; 8 h by default);
- the Hub refuses to sign anything revoked;
- so a key revoked during an outage stays usable on that host for at most the remaining life of a certificate issued before the revocation, never more than 12 h.

That is why the agent **doesn't** fail closed on a stale list. Doing so would lock everyone out of a partitioned host, break-glass included (an unreadable `RevokedKeys` refuses every key), in exchange for at most 12 h of revocation lag.

**What waits for the network**: account changes (creations, locks, sudo) and new host certificates. A person removed during the outage keeps their account until the next sync, and can't get a new certificate meanwhile. Their current certificate ends within its TTL.

**Visibility.** The Hub shows each host's last sync. The doctor reports `ssh_host_stale` (Warning after 15 minutes without a sync, Problem after 24 h). `portcullis host status` on the host prints the bundle's age.

**Unmanaged hosts** are always "offline" from Portcullis's point of view. With `--revoked-keys` their list is at most 5 minutes old while the URL is reachable; otherwise they rely on the TTL.

### 8.13 Multi-server: worker hosts get it automatically (assistant's call)

- **A built-in host group, `portcullis-servers`.** At *Add server* (multi-server §6) the Hub also creates a managed-host entry in this group, and the join code carries a host enrolment code.
- **At `./portcullis worker join`** (as the host operator), the server CLI copies the `portcullis` binary out of the pinned `portcullis-agent` image it just pulled (`docker create` + `docker cp`; no download) and runs `portcullis host enroll` with the embedded code on stdin. The primary does the same from the Hub image (`./portcullis ssh enroll-self`). `--no-ssh` skips it.
- **The containerised `portcullis-agent` never touches sshd.** The host agent is a separate, host-level service.
- **Only `lldap_admin` may be granted `portcullis-servers`** (`409` otherwise). SSH to a Portcullis server is root over everything. The servers' ceilings default to `allow_root_login=false` and `allow_sudo=true`.
- **Server revocation** (multi-server §6) also removes the host, revokes its host certificate (`@revoked` on clients) and drops it from previews.
- **No SSH through the tunnel.** SSH never goes through the `link` tunnel (zero listeners). People reach servers directly over the LAN or the Portcullis VPN, which `source-address` can insist on.

## 9. The authorization mapping

### 9.1 The model (assistant's call)

```
LLDAP group ──grant──▶ host group ──contains──▶ hosts (managed, or patterns for unmanaged)
                │
                └─ accounts: {username} and/or shared names · sudo none|full · TTL ·
                   port forwarding · agent forwarding
```

- **Host groups**:
  - an id `^[a-z][a-z0-9-]{0,30}$` (it appears in every principal; `portcullis-*` is reserved), a label and a description;
  - members: managed hosts, plus name patterns for unmanaged hosts;
  - a governing template (default `strong`), `source-address`, host certificates on/off and "Portcullis creates shared accounts";
  - the built-ins `all` (every managed host, plus unmanaged hosts set up with `--host-group all`) and `portcullis-servers`;
  - at most 64.
- **Grants**: `{group, host_group, accounts: ["{username}", "deploy"], sudo: "none"|"full", ttl_hours, port_forwarding, agent_forwarding}`. At most 256.
- **The example from the user's request**:

  | LLDAP group | Grant | Result |
  |---|---|---|
  | `ssh_web` | → host group `web` (web-1, web-2), account `{username}`, sudo none | alice (in `ssh_web`) gets a `web` certificate with `alice@web`; on web-1 and web-2 the account `alice` exists, its principals file lists `alice@web`, no sudoers line |
  | `ssh_admins` | → host group `all`, account `{username}`, sudo full | alice (also in `ssh_admins`) also gets an `all` certificate with `alice@all`; on **every** managed host `alice` exists with `alice@all` in her file and a sudoers line; on web-1 her file lists `alice@web` and `alice@all` and she has sudo, because a grant applying to web-1 gives sudo |
  | `ssh_deploy` | → `web`, account `deploy`, sudo none | bob gets `deploy@web` in his `web` certificate; `/etc/ssh/portcullis/principals/deploy` on web-1/2 lists `deploy@web`; sshd logs `ID pc:bob:web:…` |

- **sudo belongs to (host, account), not to a certificate.** alice's sudo on web-1 comes from `ssh_admins`, whichever certificate she used. The preview (§9.8) shows it that way.

### 9.2 Where it lives, and what it compiles into (assistant's call: Hub state)

**Source of truth: Hub state** (`state.yaml` `ssh:` = settings, host groups, hosts, grants, uids), backed up with `hub_data`.

| Rejected | Why |
|---|---|
| LLDAP attributes | People may edit some custom fields themselves and delegates with `edit_details` may edit others. LLDAP has no structured types for "host group + accounts + sudo". Keycloak would copy it into tokens nobody needs |
| Vault roles as the source | Vault can't evaluate LLDAP membership (enroll uses an AppRole, not the person's identity), and Vault roles can't hold host membership or sudo |

**Compiled outputs**, regenerated on every relevant change (grant, host group, membership, rule evaluation, expiry, settings; debounced like the other deliveries) and checked again before each signing:

1. **Vault role per host group** (via enroll, §7.6). For `web` above:

   ```
   ssh_user/roles/hg-web
     allowed_users       = alice@web,bob@web,deploy@web
     allowed_extensions  = permit-pty            # no grant on web allows forwarding
     default_critical_options = {}               # no source-address on web
     max_ttl = 8h
   ```

   `hg-all` has `allowed_users = alice@all` and `max_ttl = 4h` (a sudo grant's default). A role whose group no longer has grants is deleted.
2. **Host bundles per managed host** (§8.9). For web-1: accounts alice (sudo, `alice@web`, `alice@all`), bob (`bob@web`) and deploy (`deploy@web`).
3. **The person's certificate set** at login (§7.3): one per host group, principals ⊆ the role's.
4. **The client config** (§6) and the public **unmanaged-host principal hints**, i.e. the `--account` lines the Hub page suggests for a host group's `host trust` command.

**The contract pins these compilations with shared golden test vectors** (Hub state → role JSON, bundle JSON, sshd files), committed in `internal/cliapi/testdata/`.

### 9.3 Merging (assistant's call)

For one person and one host group:
- **principals**: the union of `<account>@<group>` over the grants they hold;
- **extensions**: the union of what those grants allow;
- **TTL**: the shortest of the grants' TTLs, the setting's maximum and the earliest end of a temporary membership the set depends on.

On a host, an account has sudo if any applicable grant gives it.

### 9.4 Privileged grants

A grant is **privileged** when any of these hold:
- `sudo: full`;
- the account `root`;
- agent forwarding;
- a shared account with sudo;
- the host group `portcullis-servers` or `all`.

Privileged grants:
- **need** an administrator, a fresh sign-in under the `hub` template, and the group's name typed again, to create or widen (audited with `privileged=true`);
- **default** to a 4 h TTL;
- **make** a doctor Info `ssh_privileged_grant`;
- **make** the group's members protected targets for delegates (§9.5);
- **are never** created through MCP.

### 9.5 Delegation (assistant's call: the directory's rules, plus one new permission)

- **A fifth delegated permission, `ssh_access`**, granted to an LLDAP group through the existing `directory.yaml` `permissions` and `PUT /api/directory/permissions/ssh_access`.
  - **Holders may**: create, edit and delete **non-privileged** grants on host groups the admin marked "delegable" (default off per host group). They see the access preview for those host groups.
  - **Holders may never**:
    - create or widen a privileged grant (`403` "only administrators can grant sudo, root, forwarding or server access");
    - grant to a group they are a member of, or that a rule could put them in (`403` "you can't grant access to a group you're in"). Managers can't grant themselves anything;
    - grant to a permission group, a protected group (`lldap_admin`, `lldap_password_manager`, `INVITE_PROTECTED_GROUPS`, core-subdomain groups) or a group with a privileged grant;
    - edit host groups, hosts, settings or the CA;
    - change group memberships beyond what their existing permissions allow.
  - These checks run against a fresh snapshot inside `gate`, as for every delegated permission. Holding `ssh_access` makes its group a permission group, so its members can't be targeted by other delegates.
- **Membership is the lever, so the group rules protect it:**
  - **Guarding groups.** A group used by any grant becomes a guarding group (like `admin_<app>`): its rule may use only admin-only fields (unless `allow_any_field`), it may not match an empty person, and the evaluator never adds `created_by` accounts. A delegate with `edit_details` can't fill in a field that grants SSH.
  - **Protected targets.** Members of a group with a privileged grant are protected targets in `checkDelegateTarget`. A `sign_in_help` setup link to one of them would hand over sudo on servers, so it's refused.
  - **Manual groups.** Their memberships stay admin-only (existing rule).
- **Delegates on the Hub**: the Hub is admin-only, so `ssh_access` holders use the **SSH access** pages on `people.<d>` (§9.11).

### 9.6 Revoking

Revoked-keys entries are added by:
- *Revoke* on a certificate (admin);
- *Revoke all SSH certificates* on a person (admin, or a `sign_in_help` holder who may target the person; administrators' certificates are revocable only by administrators);
- `portcullis logout --revoke`;
- the person's own "I lost a device" on their card;
- **automatically, when a person leaves a grant's group**: their unexpired certificates whose principals came from it (assistant's call).

Leaving a group also locks the affected per-person accounts on managed hosts at the next sync, which is a long-poll and so near-immediate.

### 9.7 Audit

Every action below lands in `audit.jsonl` (refusals included, `via=ai` for MCP), never with secrets.

**Mapping changes:**

| Action | Detail |
|---|---|
| `ssh.settings` | — |
| `ssh.hostgroup.create\|update\|delete` | — |
| `ssh.host.create\|update\|remove` | — |
| `ssh.host.enrol` | ok / refused / error, the host key fingerprint |
| `ssh.grant.create\|update\|delete` | before → after, `privileged=true`, `as ssh_access` for a delegate |
| `ssh.account.remove` | — |
| `ssh.ca.rotate` | the stage |

**Certificates:**

| Action | Detail |
|---|---|
| `ssh.certificate.issue` | one entry per host group issued or refused: principals, key type + fingerprint, serial, until, `flow=loopback\|device`, method, address. Actor = the person, or `-` when the proof failed first |
| `ssh.certificate.revoke` | — |
| `ssh.host_certificate.issue` | — |

**Hosts:**

| Action | Detail |
|---|---|
| `ssh.host.drift` | each new drift finding and its resolution |
| `ssh.host.stale` | — |

**Records besides the audit:**
- the **issued index** `hub_data/ssh/issued.jsonl` (0600; 90 days): `{time, user, host_group, serial, key_fp, principals, valid_before, flow, addr}`;
- **enroll's log** line per signing, which exists even if the Hub's audit write failed;
- the person's **sign-in history** entry kind `ssh_certificate`;
- **on managed hosts**, sshd's own log with the key id: the agent reports the counts, never the log lines.

### 9.8 Access preview: "who can reach web-1 as root?"

**Hub → SSH access → Hosts → web-1 → *Access*** (and the same for a host group, and a person's view: "where can alice log in?") is computed from the same compilation as §9.2:

| Person | Account | Root? | Via | Until | Reachable now |
|---|---|---|---|---|---|
| alice | alice | **sudo** | `ssh_admins` → `all` (privileged) | — | ✓ account synced |
| dave | dave | **sudo** | `ssh_admins` → `all` | membership ends 2026-11-20 | ✓ |
| bob | deploy | no | `ssh_deploy` → `web` | — | ⚠ account `deploy` missing on web-1 |
| bob | bob | no | `ssh_web` → `web` | — | ✓ |

- **Filters**: "root or sudo only", a person, a group.
- **API**: `GET /api/ssh/hosts/{id}/access?root=1` (admins; holders for delegable host groups) and the MCP twin `ssh_access_preview`.
- **Hypothetical preview.** The grant editor shows the same table for a grant being edited ("this change gives sudo on 12 hosts to 4 people") before saving.
- **Unmanaged hosts** show "accounts and sudo unknown (unmanaged): who holds a certificate that this host would accept".

### 9.9 Break-glass (assistant's call)

Portcullis must never be the only way into a host.

1. **The host break-glass account.**
   - `host enroll` and `host trust` refuse to finish unless the host has a working non-Portcullis way in. That is the `breakglass_account` with an `authorized_keys` entry (recommended: an offline FIDO key kept in a safe), or the operator passing `--no-breakglass-i-have-console-access`.
   - The account is in `protected_accounts`, never in `portcullis-users`, and the agent verifies on every apply that the `Match` block doesn't apply to it (§8.9).
   - Logins to it are reported by the agent as `ssh_breakglass_used` (Warning, with time and source address).
2. **Hub down, Vault up**: on the primary, the server operator runs `./portcullis ssh breakglass-cert --user <name> --host-group <hg> --ttl 1h`.
   - It signs directly in Vault with the root token from `secrets/vault-init.json`, which is root on the Portcullis host anyway.
   - It writes `secrets/ssh/breakglass.jsonl`, which the Hub imports into the audit at its next start (`ssh.certificate.breakglass`) and flags with a doctor Warning.
   - The certificate's key id is `pc-breakglass:<operator note>`.
3. **Portcullis down entirely**: certificates already issued keep working (§8.12). After that, the host break-glass account.

Anti-goal: no "emergency override" in the Hub that skips the template or the fresh sign-in.

### 9.10 Drift detection (managed hosts)

Every sync reports a **state report** to the Hub (strict JSON, ≤ 256 KiB):
- the SHA-256 of each file the agent manages;
- the relevant lines of `sshd -T`: `trustedusercakeys`, `authorizedprincipalsfile`, `revokedkeys`, `pubkeyauthentication`, `authorizedkeysfile`, `hostcertificate`;
- the same for `sshd -T -C user=<a portcullis account>` and `-C user=<breakglass>`;
- Portcullis accounts present, missing or locked;
- conflicts;
- the count of `authorized_keys` entries on shared accounts;
- the sshd version;
- the counts of Portcullis and break-glass logins since the last report.

**Hand-edited managed files** are rewritten on the next apply: the agent self-heals and reports `ssh_host_drift` (Warning, "fixed"), with the file's name (never its contents).

**Overrides the agent can't fix** are reported as `ssh_host_drift` (Problem). For example, the main `sshd_config` sets `TrustedUserCAKeys`, `AuthorizedPrincipalsFile` or `RevokedKeys` *before* the `Include`: sshd keeps the first value, so the drop-in loses. The agent never edits the main config, so the fix is the operator's. The Hub page names the keyword and the effective value.

**Other findings:**

| Finding | Severity / meaning |
|---|---|
| `ssh_host_account_conflict`, `_missing`, `_invalid` | per account |
| `ssh_host_ceiling` | a bundle entry the local ceiling refused |
| `ssh_host_authorized_keys_shared` | Info: shared accounts with `authorized_keys`, i.e. a parallel way in |
| `ssh_host_old_ca` | — |
| `ssh_breakglass_used` | — |

**Untrusted input.** A report is untrusted: it is size-capped, schema-checked, never executed and never used as a path (the multi-server rule for agent answers). A host can only lie about itself.

Unmanaged hosts have no drift detection. The preview says so.

### 9.11 Hub and people pages

**Hub → SSH access** (admins), off until switched on. Tabs:

| Tab | What it holds |
|---|---|
| Hosts | managed: state, last sync, bundle serial, drift, host certificate expiry, *Access*, *Remove account*, *Remove host*; unmanaged entries: patterns and the `host trust` command |
| Host groups | members, template, `source-address`, host certificates, delegable, create shared accounts, the commands |
| Grants | with the hypothetical preview |
| Access preview | the §9.8 table |
| Certificates | the issued index, revoke, host certificates, the revoked-keys list |
| Settings | on/off, default TTL 1–12 h (default 8 h), device code and its networks, CA fingerprints, *Rotate CA* |

**people.<d>**:
- **The person's SSH access card** (Sign-in page): their host groups, accounts, sudo, hosts and certificates; *Revoke all my SSH certificates* ("I lost a device"); the CLI download and the two commands to start.
- **People → person** (admins, and `sign_in_help` holders who may target them): the same card plus *Revoke all SSH certificates*.
- **SSH access for `ssh_access` holders**: the grants and previews of delegable host groups.
- **Group pages** show "SSH: web (own account), all (own account, sudo)".

### 9.12 MCP tools (assistant's call)

- **Admin**, with per-call confirmation for mutations: `list_ssh_access`, `ssh_access_preview`, `list_ssh_certificates`, `list_ssh_hosts` (state and drift), `revoke_ssh_certificates`, and `set_ssh_grant` for **non-privileged** grants only.
- **People**: `my_ssh_access` and `revoke_my_ssh_certificates`.
- **Never through MCP**: signing user or host certificates, enrolment codes (a secret in a transcript), privileged grants, `source-address`, settings and CA rotation.

### 9.13 Doctor and status

- **Doctor kinds**: `ssh_ca_missing` (Problem: a mount, cap or role differs from §7.6), `ssh_cli_client_conflict`, `ssh_privileged_grant`, `ssh_host_stale`, `ssh_host_drift`, `ssh_host_account_*`, `ssh_host_ceiling`, `ssh_host_cert_expiring` (≤ 14 d), `ssh_host_old_ca`, `ssh_breakglass_used` and `ssh_hostgroup_unused`.
- **`./portcullis status`** gets an SSH block (mounts, caps, CA fingerprints, managed hosts with their sync age), and `--json` gets `ssh{}`.

## 10. Tokens for app APIs (part 3, optional)

### 10.1 What is possible

A token the CLI sends as `Authorization: Bearer …` to **one** app host, checked by the normal chain: oauth2-proxy verifies the signature; group-gate checks the group, the template and the audience.

- **It fits forward-auth and header-auth apps whose API trusts the gateway's identity headers on the same routes.** Candidates, to be verified per template during the build: Grafana (its auth proxy covers `/api/`), Scrutiny, Zigbee2MQTT, ESPHome, and the CI fixtures `settings-echo` and whoami.
- **Opt-in at two levels.** A template opts in with a manifest block `cli_api: {paths: ["/api/"]}`, and the admin switches it on per instance.

### 10.2 What isn't

- **Native-OIDC apps** (Gitea, GitLab, Immich, Nextcloud, Paperless, Vaultwarden, Matrix …) accept only their own client's tokens and keep their own sessions. Use their own API tokens, or their MCP companions (§15).
- **Apps whose API has its own credential** behind the gateway (Pi-hole, AdGuard, Firefly III's `/api/v1`).
- **Templates whose rule needs a certificate on every alternative** (`NeedsCertificate`): a script presents no YubiKey or browser certificate. They can't enable CLI API access (`409`), the mcp-gate rule. A CLI doing mTLS with the YubiKey's PIV certificate is parked.

### 10.3 Keycloak

**A third Hub-owned client, `portcullis-cli-api`**:
- public, standard flow + PKCE;
- loopback ports 38920–38922;
- `use.refresh.tokens=true`, no `offline_access`, no consent;
- the normal browser flow: an SSO session is reused, because API access needs a session that meets the app's template, not a fresh touch;
- `login` runs it right after the SSH flow, so it costs no second touch.

**One optional client scope per enabled instance, `api:<instance-id>`**:
- Audience mappers: `https://<host>` and the fixed `portcullis-api` (the `mcp:*` pattern);
- `login` requests the person's `api:` scopes;
- each app's token comes from a refresh grant **downscoped** to `scope=openid api:<id>`, so every token sent names one app (§17 Q3 has the fallback).

### 10.4 The gateway path

- **A third oauth2-proxy, `forward-auth-api`** (assistant's call: the cookie proxies stay exactly as they are). It runs with `skip_jwt_bearer_tokens=true`, `bearer_token_login_fallback=false` and `extra_jwt_issuers=https://auth.<d>/realms/portcullis=portcullis-api`. It has no cookie session at all, and the same injected headers as `forward-auth`. Its middleware is `portcullis-auth-api@docker`.
- **Router `portcullis-api-<id>`** (Hub override), for instances with CLI API access on:
  - rule: `` Host(…) && HeaderRegexp(`Authorization`, `^Bearer `) && (PathPrefix(…)) ``;
  - priority above the instance's routers;
  - the same tier and entrypoints (VPN-only included);
  - middlewares `portcullis-auth-api@docker,portcullis-groups@docker` + the template's;
  - covered by exposure drift.
- **group-gate, policy v7** (no v6 compatibility). It adds `api_hosts: {"<host>": {"paths": […]}}`. For a token with `azp` `portcullis-cli-api` it requires:
  - the host and path inside `api_hosts`;
  - `aud` contains `https://<host>` and no other URL;
  - no `pc_imp` / `act`;
  - the group and path-group checks;
  - the host's rule met by `amr` minus the certificate methods.

  **And a tightening on every host**: a token whose `azp` is neither `portcullis-forward-auth` nor `portcullis-cli-api` is denied.
- **Lifetimes.** Access tokens live 5 min. The refresh token lives as long as the SSO session (≤ 12 h). Leaving the group stops the next request.

### 10.5 On the laptop

- **Storage.** The refresh token is kept in the OS keyring only (Keychain, Credential Manager, Secret Service). No keyring means nothing is stored, and `token` signs in again (assistant's call).
- **`portcullis api grafana GET /api/health`** makes the request itself (body from stdin), so no token is ever on argv.
- **`portcullis token`** prints only to a non-terminal stdout, for `… | sed 's/^/Authorization: Bearer /' | curl -H @- …`. The docs never show `curl -H "Authorization: Bearer $(…)"`.

## 11. Web access and cookies: what the CLI can and can't do

**It can:**
- sign you in **in your default browser** as a side effect of `portcullis login`. The PKCE flow runs there, so that browser has its Keycloak SSO session, and opening apps afterwards is silent when the session meets their template. Certificate-bound templates still need the certificate in the browser;
- open an app for you (`portcullis open grafana`);
- give scripts a token for the APIs of gateway apps that opted in (part 3).

**It can't, by design:**
- put a session into a browser it didn't sign in with, another profile, or another machine. Browsers isolate cookie jars, and doing it anyway needs a browser extension or remote debugging, which is an attack technique;
- export `_oauth2_proxy` for scripts. It is a domain-wide, replayable ticket for every `*.<d>` app and can't be audience-restricted;
- sign you in to native-OIDC apps, which keep their own sessions;
- make a device-code login sign in your local browser: that sign-in happened on the device where you typed the code.

## 12. Threat model

### 12.1 A stolen laptop

- **Locked or off**:
  - no private key on disk (default) and no SSH token;
  - the agent's keys live in a locked session's memory;
  - signing in again needs the person's YubiKey or passkey;
  - part 3's refresh token is in the locked keyring and dies with the SSO session (≤ 12 h).
- **Unlocked**: what's in the agent works until its certificates expire (≤ 8 h by default). Mitigations:
  - *Revoke all my SSH certificates* from any device, or by an admin or helpdesk. It reaches managed hosts within seconds, unmanaged ones with `--revoked-keys` within 5 minutes, and the rest at expiry;
  - `source-address` limits use to the VPN;
  - FIDO keys need a touch per connection;
  - per-person accounts can be locked host-wide by removing the person from the group.

### 12.2 A phished device code

Device code is off by default (part 2). When on, it is limited to the listed networks (start and every poll), needs a typed code, shows a warning page, forces a fresh sign-in, lives 5 minutes, and is recorded in history and audit with a notice.

Residual: an attacker *on* an allowed network who talks someone into typing their code gets that person's certificates for ≤ 8 h. Admins who can't accept that keep device code off.

### 12.3 Token theft

- **The OAuth code** is useless without the PKCE verifier, and single-use.
- **`portcullis-cli` tokens never leave the Hub.** Signing happens only right after the Hub's own exchange, with `auth_time` ≤ 5 min.
- **Part 3 API tokens** are good for one host each and 5 minutes, and are refused everywhere else. A stolen refresh token gives API tokens until the SSO session ends, but can never sign SSH certificates.
- **Host-side**: a host's sync requests are SSHSIGs by its pinned host key, with time ±60 s and replays refused. A stolen enrolment code is single-use, valid 15 minutes, and useless once the host enrolled.

### 12.4 A compromised host

- **What it can and can't take.** It sees certificates (public) and sessions, never private keys. With **agent forwarding**, which is off by default and a privileged grant, it can use a connected person's agent while the session lasts. FIDO keys still need a touch.
- **It can't widen access elsewhere.** Its principals files only matter locally. A captured `alice@web` certificate is useless without the key and is limited by `source-address`. Its host key signs nothing, and its host certificate is valid only for its own names.
- **It can lie in its own drift reports.** Reports are untrusted input about itself only.
- **It holds no Portcullis credential beyond its own host key**: no Vault token and no LDAP access. If it's a Portcullis worker, the multi-server anti-goals hold.
- **Recovery**: *Remove host* (unpins the key; the next sync gets `403 removed`, and the agent removes the Portcullis trust), revoke its host certificate, and revoke the certificates of people who connected with forwarding.

### 12.5 A compromised Hub (new with managed hosts)

The Hub decides principals and bundles, so a compromised Hub could have enroll sign what the Vault policy allows, and push accounts and sudo to managed hosts. Limits:
- **Vault's caps**: 12 h, no host certificates on the user mount, no X11 / `force-command`;
- **each host's local ceiling**: no root logins where the operator said no, protected accounts untouched;
- **the break-glass account**, which the bundle can never touch;
- **enroll's form checks**.

This is the same trust the Hub already has over app instances. It is the reason the ceiling lives on the host.

### 12.6 Accepted residuals

- A compromised Vault CA key compromises every host that trusts it. Rotation (§8.11) and offline backups of `secrets/vault-init.json` remain the defence.
- A revoked key stays usable on hosts that can't sync for up to 12 h (§8.12).
- Unmanaged hosts without `--revoked-keys` rely on the TTL.
- `NOPASSWD` sudo: bounded by the fresh sign-in and the TTL (§8.6).

## 13. Project rules applied

- **Fail closed.** None of these sign or let anything through: a missing or foreign Keycloak client, a Vault mount or role that differs from §7.6, an unreadable directory, policy v7 with unknown keys, a host group whose template can't be met, a role that can't be made current. A bundle that fails validation is never applied. The deliberate exception is the revoked-keys file on a partitioned host, whose lag is bounded by the TTL (§8.12).
- **Never weaken access control.**
  - The template and the certificate allowlist both apply.
  - Impersonated sessions are refused.
  - There's no new path around group-gate, and the cookie routers are unchanged.
  - Part 3 adds the `azp` tightening.
  - Portcullis per-person accounts are certificate-only.
- **Secrets never on argv or in logs.**
  - CLI flags carry no secrets, and enrolment codes come on stdin.
  - The CLI talks the agent protocol itself and never runs `ssh-add`.
  - `--debug` redacts.
  - The Hub, enroll and the host agent log reasons, never inputs.
  - e2e artifacts carry no codes.
- **Identity is the LLDAP username**: `preferred_username` from an ID token the Hub verified, checked against a fresh LLDAP snapshot. Per-person accounts carry it.
- **No back-compat before the release**: policy v7 replaces v6. No migrations.
- **Prefer mature libraries** (§4.1), plus the system's own `useradd`, `usermod`, `visudo` and `sshd -t` / `sshd -T` on hosts, rather than editing `/etc/passwd` by hand.
- **No private identifiers**: `example.com`, alice / bob / carol / dave, and documentation addresses (`203.0.113.0/24`, `10.20.0.0/24`).
- **Network constraint.**
  - The CLI connects only to `auth.<d>`, `people.<d>`, the app hosts of part 3, and its own `127.0.0.1` listener.
  - Managed hosts connect only to `people.<d>`; unmanaged hosts to nothing, or the revoked-keys URL.
  - No telemetry, no update checks, no third-party endpoints. Server hosts take the binary from images they already pulled.
  - **Tests run locally**: unit tests with fakes; CI e2e on the ephemeral stack with local sshd containers and Playwright's virtual authenticator; no external service. On the test server, `ACME_STAGING=true` as always, with `--ca-file` for the staging root.

## 14. Contract and docs changes

**New contract §18, "SSH access and the CLI"**, covering:
- the CLI listener and the `people-cli` router;
- the API: `config`, `ssh/certificates`, `ssh/host-certificates`, `ssh/ca`, `ssh/revoked-keys`, `device/*`, `hosts/enrol`, `hosts/bundle`, `hosts/report`;
- the Keycloak clients;
- the proof and key-proof rules;
- the principal grammar, the key id and the merge rules;
- the Vault mounts, caps, per-host-group roles and the policy;
- enroll's endpoints (§9.4 too);
- the bundle and report formats, the local ceiling and the host file layout (golden files);
- the enrolment code;
- the revoked-keys format;
- the audit actions and the history kind.

**Other contract sections:**
- §8 (clients), §8.2 (history kind), §9.5 (audit), §9.6 (`ssh_access`, guarding and protected groups), §14.5 (doctor), §15.10 (MCP);
- multi-server's §17 (host enrolment inside the join code);
- part 3: §3 (`cli_api`), §4 (policy v7), §5 (`forward-auth-api`, `portcullis-api-<id>`), §11.7 (audit).

**Docs site:**
- new `operations/ssh-access.md`: the model, managed vs unmanaged, accounts and sudo, the preview, revocation, offline behaviour, break-glass, drift, rotation, and the threat model in plain words;
- new `guides/cli.md`: install, verify, login, ssh config, and the cookie FAQ;
- updates to `hardening.md`, `cli.md` (`./portcullis ssh enroll-self|breakglass-cert|rotate-ca`, `worker join` SSH), `hub.md`, `testing.md`, and the core and Hub `CLAUDE.md`.

## 15. Build order

**Part 1: loopback login, user certificates, managed and unmanaged hosts**
1. **Contract and docs**: contract §18 and the docs pages, first.
2. **Core**:
   - the `ssh_user` / `ssh_host` mounts, caps and the host role;
   - `enroll.hcl`;
   - enroll's role, sign and CA endpoints, with tests (form checks, the policy's refusals, no keys in logs);
   - the `people-cli` router, `strip-identity@file` and the `hub-cli` service;
   - `./portcullis ssh enroll-self` and `breakglass-cert`;
   - the status block.
3. **Hub**:
   - `internal/cliapi` with the golden vectors;
   - `freshauth.ClientID`;
   - the `portcullis-cli` client + `TestLiveCLIObjects`;
   - the `:8891` listener;
   - the mapping state, uids, compilation (roles, bundles, client hints) and role delivery;
   - signing with its limits, audit, issued index and history;
   - hosts: enrolment codes, pinned keys, bundle long-poll, reports, drift findings;
   - guarding and protected groups, and `ssh_access`;
   - the SSH access page, previews, people card and group pages;
   - automatic revocation on leave;
   - doctor and MCP.
4. **CLI** (`cmd/portcullis`): login, status, logout, ssh-config, open, and host enroll / trust / sync / status / remove / certify.
   - Unit tests on macOS, Linux and Windows runners cover the agent protocol (in-process agent), the loopback handler, the writers against the golden files, the ceiling, and rollback on `sshd -t` / `visudo -cf` failure.
   - The host agent is tested in a container with a real sshd.
5. **CI `e2e-ssh`** (core): the stack + Hub + two local sshd containers, one enrolled as managed and one set up with `host trust`. Playwright drives the browser half with a virtual security key. It asserts:
   - alice (`ssh_web`) reaches both as `alice` without sudo; after joining `ssh_admins` she has sudo on the managed one, within one long-poll;
   - bob gets `deploy@web` and the sshd log shows `pc:bob:web`;
   - `root` is refused under the default ceiling;
   - password, `totp` and impersonated sign-ins get nothing; a replayed code and a wrong key proof are refused;
   - removal from `ssh_web` locks `alice` and ends her session on the managed host, and adds her key to the revoked list (refused within seconds there, within one pull on the unmanaged host);
   - a hand-edited principals file is healed and reported, and a main-config override is reported as a Problem;
   - with the Hub stopped, logins with valid certificates still work and the break-glass key works;
   - a forged report and an oversized bundle are refused;
   - no code, token, enrolment secret or key appears in any log or artifact.
6. **Release job**: binaries, `SHA256SUMS`, cosign, provenance; the binary in the Hub and agent images.
7. **Test server**: `ACME_STAGING=true`, a VM as a managed host, an unmanaged VM, and macOS, Windows and Linux laptops. Mainline every branch.

**Part 2: device code, CA rotation, servers**
8. `portcullis-cli-device`, the flow copy without the cookie, the network fence, the device page and the notice.
9. `rotate-ca` with overlap (§8.11).
10. `portcullis-servers` and enrolment inside `worker join` (once multi-server lands).

**Part 3: API tokens**
11. `portcullis-cli-api`, the `api:<id>` scopes, `forward-auth-api`, the routers and drift, group-gate v7, the `cli_api` manifest block (templates repo: schema + `validate.py`), `token` / `api`, the keyring, and e2e.

**Part 4: distribution extras**
12. Homebrew, winget, `.deb` / `.rpm`, notarization and Authenticode.

Merge order per part: docs → hub → templates (part 3) → core.

## 16. Parked

- a Vault audit device;
- the binary KRL format;
- per-command sudo, and "sudo needs a fresh touch" (PAM);
- `force-command` certificates;
- certificates for automation (service accounts);
- per-person shell and supplementary groups chosen by the admin;
- mTLS with the YubiKey PIV certificate from the CLI;
- Windows host automation;
- session recording;
- scoped delegation (`ssh_access` limited to some host groups is in; limited to some people is not);
- automatic home-directory archiving policies.

## 17. Open questions (each has a default; work proceeds on the default)

1. **Default TTL.** *Default:* 8 h (a working day, inside the 12 h cap); 4 h for privileged grants; settable 1–12 h.
2. **FIDO key types in the pinned Vault.** *Default:* accepted if `TestLiveSSHKeyTypes` passes; otherwise part 1 ships ed25519 and P-256 only.
3. **Keycloak 26.8.1 narrowing `aud` on a downscoped refresh.** *Default:* use it if the live test shows it; otherwise `portcullis token <app>` does a silent browser round trip on the SSO session (no touch) per app and caches nothing.
4. **Synced passkeys signing SSH certificates** (they are in the certificate allowlist). *Default:* only where the host group's template accepts them; `strong`, the default, doesn't.
5. **`NOPASSWD` sudo.** *Default:* yes for `sudo: full`, since there is no local password; revisit with the parked PAM module.
6. **Long-poll vs. a 1-minute pull for managed hosts.** *Default:* long-poll (55 s), because revocations then arrive in seconds without an inbound port; falls back to a 60 s pull when a proxy in the way cuts held connections.
7. **One certificate per host group.** *Default:* yes (different TTLs and extensions per group); at most 16 per login.
