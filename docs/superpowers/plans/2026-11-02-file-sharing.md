# File Sharing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Each person with access to a file-sharing instance creates their
own file-share password on `people.<domain>` → My apps after a fresh passkey
touch. It is shown once and stored only as an NT hash outside every backup,
and destroyed within seconds when the person loses access. Two router-less
templates, Samba (ServerContainers) and Time Machine (mbentley), use it.
They serve hardened SMB3 on LAN/VPN only, with stable Hub-wide per-person
uids, and apply people changes live.

**Architecture:**
- **Hub, generic parts only.** It knows nothing about Samba:
  - the `person_secret` and `person_id` kinds (project 1's reserved
    fields);
  - a credential service with its own secrets volume `hub_secrets` and a
    `secrets_epoch` restore guard;
  - a Hub-wide uid pool keyed by LLDAP user uuid;
  - a shared fresh-auth verifier (`internal/freshauth`, its own Keycloak
    client, server-side PKCE code exchange);
  - revoke-on-leave from `OnChange` and the evaluator tick, bypassing the
    delivery debounce;
  - the hook trigger `credential_change`;
  - a line-based (`tsv`) data-file format that busybox can read;
  - hook reports for the doctor;
  - `PORTCULLIS_LOCAL_NETWORKS`;
  - table `groups` columns and `path` columns with a [P2] `folder` block
    and per-row mounts.
- **Templates.**
  - Each template ships one shared converge script, `portcullis-sync`
    (busybox sh). It runs before smbd starts and as the hook, and owns
    `smb.conf`, the passdb (on tmpfs) and the accounts.
  - It verifies the hardened `[global]` with `testparm`.
- **Core.** Core adds the `hub_secrets` volume (never backed up, emptied by
  a core restore) and url-less portal entries.

**Tech Stack:**
- Hub: Go, plus these modules:
  - `golang.org/x/crypto/md4` (already indirect; now direct);
  - `github.com/coreos/go-oidc/v3` and `golang.org/x/oauth2` (new,
    pinned) for fresh-auth verification and the PKCE code exchange.
- Core: shell CLI, Python group-gate.
- Templates:
  - `ghcr.io/servercontainers/samba` (`smbd-only` variant);
  - `mbentley/timemachine` (`smb-YYYYMMDD`);
  - busybox sh; JSON Schema + `tests/validate.py`.
- Docs: zensical.

**Spec:** `docs/superpowers/specs/2026-11-02-file-sharing-design.md` (hub repo).
Read it together with:
- project 1's plan, `docs/superpowers/plans/2026-11-02-app-settings-panel.md`
  ("Interfaces for later plans"; its exact names are used here);
- project 2's spec, `docs/superpowers/specs/2026-11-02-shared-folders-doctor-design.md`;
- the certificates spec, `docs/superpowers/specs/2026-11-02-certificates-selfservice-design.md`
  (call 8: fresh authentication).

**Bases and order.**

| Repo | Base when this plan was written |
|---|---|
| hub | `main` `bfbb3d4` |
| core | `main` `c451278` |
| docs | `main` `2c4d670` |
| templates | `new-apps` `78db191` |

- **This project starts only after projects 1 (branch `settings`) and 2
  (branch `folders`) have merged into `main` in every repo.** Re-read both
  plans' "Interfaces for later plans" first. Rebase each repo's
  `filesharing` branch on the `main` that contains them (templates: on
  `main` once `new-apps` and `settings` have landed).
- **Branch:** every repo works on a branch named **`filesharing`**.
  - Hub CI clones the same-named templates and core branches.
  - Core CI builds the Hub from its same-named branch.
  - Templates `.core-ref` is set to `filesharing` on the branch and back to
    `main` before merging.
- **Work order:** contract (T1) → core (T2) → Hub (T3–T14) → templates
  (T15–T17) → core e2e (T18) → docs (T19) → deploy (T20).
  - Hub `TestRealTemplates*` stays green throughout: the new templates
    arrive only in T16/T17.
  - Push hub, core and templates `filesharing` together at the end of
    T17.
- **Merge order:** docs → core → Hub → templates.

**Project 2 dependencies.** Every name marked **[P2]** comes from the
"Interfaces for later plans" section of project 2's plan,
`docs/superpowers/plans/2026-11-02-shared-folders-doctor.md` (its branch
is `folders`), and uses project 2's exact identifiers. The full list is at
the end ("Project 2 names this plan depends on"). Three things this plan
adds to project 2's code are also marked there:
- `FolderUse.Row`;
- `folderfix.Target.ChildOwners`;
- `doctor.Inputs.FileSharing`.

## Global Constraints

- **No migration or back-compat code.** There are no installs.
  `person_secret`/`person_id` replace project 1's reservations outright.
- **Contract first:** `portcullis-docs/docs/guides/integration-contracts.md`
  (T1) before any code in the other repos.
- **The Hub has no Samba code.** It knows only:
  - `person_secret`, `person_id`, hooks, files, `lan_only`;
  - the `tsv` data-file format;
  - hook reports;
  - `info` placeholders;
  - `PORTCULLIS_LOCAL_NETWORKS`.

  Every Samba value (username pattern, reserved names, share names) is in
  the manifests.
- **Password** (spec call 2):
  - 24 characters from `crypto/rand`, from this 54-character alphabet,
    exactly:
    `23456789ABCDEFGHJKLMNPQRSTUVWXYabcdefghjkmnpqrstuvwxyz`.
  - That is the digits minus `0 1`, upper case minus `I O Z`, lower case
    minus `i l o`. The spec's list (`0 O 1 l I`) leaves 57 characters;
    `Z`, `i` and `o` are also dropped to reach the decided 54, about
    138 bits.
  - Shown as 6 groups of 4 joined by `-` (29 characters). The dashes are
    part of the password.
- **NT hash:** the uppercase hex of MD4(UTF-16LE(the 29-character
  password)), from `golang.org/x/crypto/md4`. One file per person:
  `<secrets>/<instance>/<key>/<username>.nt`, holding 32 hex characters
  and `\n`.
  - Directories are 0700 and files 0600, owner 10001.
  - `<secrets>` is `HUB_SECRETS_DIR` (default `/secrets`), the
    `hub_secrets` volume.
- **The secret never leaves its place.** Neither the plaintext nor the
  hash may appear in:
  - `state.yaml`, env, argv, logs, the audit or op records;
  - hook stdin or hook output;
  - instance backups, core backups or any API answer other than the one
    create/regenerate response (`Cache-Control: no-store`).

  The plaintext is a `[]byte` that is zeroed after the response is
  written.
- **One credential per (person, instance, `person_secret` option).**
  Self-service only. Admins list and revoke, never create.
- **Statuses** (`MyCredential.Status`):
  - `none`;
  - `active` (`Since` = created_at);
  - `voided` (`Reason: "restore"`, `Since` = the void time);
  - `unavailable` (`Reason` = the template's username reason).
- **Revocation reasons** in metadata and audit: `self`, `admin`, `leave`,
  `deleted`, `restore`.
- **Audit actions:**
  - `credential.create`, `credential.regenerate`, `credential.revoke`
    (`actor=self|<admin>`), `credential.revoke_leave`,
    `credential.void_restore` (count only);
  - fields: instance, key, username, actor, reason. Never the secret or
    hash.
- **Fresh auth** (spec call 1; certificates spec call 8):
  - client `portcullis-fresh-auth`: public, PKCE S256, standard flow
    only;
  - redirect URI exactly `https://people.<domain>/`;
  - authorize with `prompt=login`, `max_age=0`, `acr_values=hwk`;
  - accepted when:
    - the ID token's `auth_time` is ≥ now − 300 s;
    - `amr` contains `hwk` or `mtls`;
    - `amr` and `acr` never contain `file`;
    - `nonce` matches;
    - `azp`/`aud` is `portcullis-fresh-auth`;
    - `preferred_username` (lowercased) == the caller.
  - Revoking your own needs no fresh auth.
- **Uid pool `posix_uid`:** 10000–59999.
  - It is Hub-wide and keyed by (lowercase username, LLDAP user `uuid`).
  - It is never reused. A changed uuid (account deleted and created
    again) retires the old uid and allocates a new one.
  - `person_id` is never shown on My apps.
- **Timing (spec call 23):**
  - Hub-made changes and evaluator removals revoke at once, with no
    debounce.
  - Edits made directly in LLDAP are caught by the holder check on the
    evaluator's 60 s tick.
  - LLDAP unreadable → the check does nothing.
- **Hardened SMB (spec call 10).** `[global]` has exactly:
  - `server min protocol = SMB3`;
  - `server smb encrypt = required`;
  - `server signing = mandatory`;
  - `ntlm auth = ntlmv2-only`, `lanman auth = no`;
  - `map to guest = never`, `restrict anonymous = 2`;
  - `disable netbios = yes`, `smb ports = 445`;
  - `wide links = no`;
  - `hosts allow = <PORTCULLIS_LOCAL_NETWORKS, space-separated>`,
    `hosts deny = 0.0.0.0/0 ::/0`.

  Every share has `guest ok = no`. `testparm -s` must show these values;
  otherwise the script exits non-zero. Only 445/tcp is published.
- **No share is ever rendered with an empty `valid users`.** In Samba that
  means "everyone". A share whose user list is empty is left out.
- **Passdb and the Samba state dirs are on tmpfs** in both templates:
  `/var/lib/samba`, `/var/cache/samba`, `/run/samba`, `/run/portcullis`.
  So no hash ever reaches a Docker volume, and no instance backup can
  contain one.
- **Hub hygiene:**
  - run `go vet ./... && go test -race ./... && gofmt -l .` after every
    Hub task;
  - update the CLAUDE.md rows a task changes;
  - `Hub.mu` is never held across docker, LLDAP or Keycloak calls.
    Local file I/O under `mu` is allowed (as today);
  - frontend is vanilla JS, `escapeHtml`/`esc`, no inline handlers;
    new assets go on the `//go:embed` line.
- **Images and libraries:** pinned `tag@sha256` (index digest), looked up
  at implementation time; Go modules in `go.sum`; Actions by commit SHA.

## Review Focus

1. **A share whose user list ends up empty.** Examples: a shared-folder
   row whose groups have no password holders yet, Home with nobody
   eligible, or a Time Machine share of a person whose folder is a former
   account's.
   - Samba reads `valid users =` (empty) as "no restriction".
   - Expected: the stanza is not written at all. Nobody, not even an
     authenticated other person, can open it.
   - Pinned in Task 16 (`test_no_empty_valid_users`) and Task 17
     (`samba.sh` "member in neither group → `NT_STATUS_ACCESS_DENIED`" and
     "row with no holders → share absent").
2. **A crash or core restore between writing a hash and saving
   `state.yaml`,** or a restored `state.yaml` next to a newer secrets
   volume.
   - Expected: the epoch rotates on every credential mutation (volume
     first, then state). Any mismatch at boot or before a converge voids
     every credential ("reset by a restore"). An orphan `.nt` file is
     deleted, and metadata without a file is voided. Nothing revives an
     old hash.
   - Pinned in Task 6 (`TestEpochMismatchVoidsAll`,
     `TestCrashBetweenHashAndStateFailsClosed`).
3. **The revocation hook fails or hangs** (container stopped, smbd
   wedged, exec timeout) right after a person leaves.
   - Expected: the hash file is already gone. The Hub recreates the
     container, so the start-time converge has no account for them. If
     that fails, it stops the instance (op record `credentials`, reason
     stated). It never stays running with the old account.
   - Pinned in Task 9 (`TestRevokeHookFailureRecreates`,
     `TestRevokeRecreateFailureStops`).
4. **A username that is valid in LLDAP but not for Samba**
   (`Alice.Smith@x`, `root`, `timemachine`, 33 characters), or an account
   deleted and created again under the same name.
   - Expected: My apps shows `unavailable` with the template's reason; the
     route answers 409 without consuming the fresh-auth proof.
   - The recreated account gets a new uid and none of the old
     credentials. Its old folder is reported as a former account's and
     never served.
   - Pinned in Task 8 (`TestUsernameRuleRefuses`), Task 5
     (`TestRecreatedAccountNewUID`) and Task 16
     (`test_former_account_not_served`).
5. **A fresh-auth proof that is stale, replayed, for someone else, or
   from a file certificate.** Examples: a code obtained 6 minutes ago, the
   same code posted twice, a token whose `preferred_username` is bob
   posted by alice's session, `amr: ["file"]`.
   - Expected: 403 with a generic message, nothing created, the audit says
     `refused`.
   - Pinned in Task 7 (`TestFreshAuthRefusals`) and Task 12
     (`TestCreateCredentialWrongUserProof`).

---

## Phase 1 — contract

### Task 1: Contract (docs repo)

**Files:**
- `portcullis-docs/docs/guides/integration-contracts.md`: §3, §5.1, §6,
  §8, §10, §11.5, §11.6, and project 1's §13;
- `docs/guides/manifest-reference.md`.

- [ ] **Step 1: §13 (settings), additions.**
  - **`person_secret`:**
    - `hash: nt`, `length` ≥ 24;
    - `delivery: file` (scalar form);
    - `mount{service, path}`: the read-only directory of `<username>.nt`
      files;
    - `revoke_on_leave: true`, `on_restore: void`;
    - `username{pattern, reserved[], reason}`;
    - `info[{label, value}]`, with the placeholders `{user}`,
      `{value:<instance option>}`, `{port:<PORT KEY>}`,
      `{port_suffix:<PORT KEY>:<default>}` (empty when the host port
      equals the default, else `:<port>`) and `{rows:<table option>}`
      (comma-joined key-column values of the rows whose expanded groups
      contain the caller);
    - routes, statuses, audit and fresh auth as in Global Constraints.
  - **`person_id`:**
    - `pool` (only `posix_uid`, 10000–59999, Hub-wide, never reused, keyed
      by username + LLDAP uuid);
    - `self_visible` must be false;
    - file delivery only.
  - **`credential_change`** joins the hook triggers. The `HookInput`
    field is `"credentials": {"<key>": {"<user>": {"id": "<hex>", "version": <n>}}}`.
  - **Data files** get `format: json|tsv` (default `json`). The `tsv`
    grammar is one record per line, tab-separated, UTF-8, no tab or
    newline inside a field (refused at render):
    ```text
    version	1
    instance	<id>
    value	<key>	<rendered>
    person	<user>	<field>	<rendered>
    group	<key>	<group>	<rendered>
    row	<key>	<row key>	<column>	<rendered>
    ```
    - Lists render comma-joined.
    - A `folder` column renders two columns, `<col>.mount` and
      `<col>.gid`.
    - Lines are sorted by bytes.
  - **Hook reports:** stdout lines starting with `PORTCULLIS-REPORT `,
    followed by one JSON `HookReport` (shape in Task 10). Any other output
    is log only.
  - **Tables:**
    - column type `groups`, stored with LLDAP ids and purged like rows;
    - column type `path` with a [P2] `folder` block (`FolderSpec`), whose
      cell values must be [P2] folder refs (`folder:<id>[/sub]`,
      `ParseFolderRef`);
    - project 2's `TypeFolder` stays unused;
    - such a column's `mount` pattern is `"/<…>/{<key column>}"`;
    - `render{expand_members: true}`: group cells become their members
      that are in the population;
    - the table option's `row_requires_any: [<columns>]`;
    - changing a row's folder cell goes through project 2's assignment
      (`StartAssign`, one `FolderUse` per row). Adding or removing a row
      with a folder is therefore a previewed apply. Group-cell edits apply
      as the option's `applies` says.
  - **`folder.runs_as`** [P2 `RunsAs.UIDFrom`/`GIDFrom`, yaml
    `uid_from`/`gid_from`]: both name a `person_id` option of the same
    template (spec calls 16 and 29).
    - A shared-folder use declares `{uid_from: uid}` with
      `joins_group: template` and no gid source. The group is the folder
      gid the template applies itself (`PORTCULLIS_FOLDER_GID_<KEY>`, or
      the row's `folder.gid` in the data file).
    - This replaces the spec's `gid: folder`, which project 2's numeric
      `RunsAs.GID` can't express.
    - A per-person tree declares `{uid_from: uid, gid_from: uid}`.
- [ ] **Step 2: §3.** Write these items:
  - `auth.method: custom` templates may have zero Traefik routers. They
    may then set `group_access: true` without `native_login`: the access
    group decides only who is in the population.
  - Portal, policy and the app detail show `auth.notes`.
  - The reserved variable `PORTCULLIS_LOCAL_NETWORKS`: comma-separated
    CIDRs from [P2] `LocalNetworksView()` (the saved list, or
    `DefaultLocalNetworks`), and empty only when an empty list is saved.
- [ ] **Step 3: the other sections.**
  - **§5.1:** `POST`/`DELETE /api/me/apps/{instance}/credentials/{key}`
    and their body and answer:
    - `{code, code_verifier, nonce}` → `{password, credential}`;
    - `/api/me/apps` gains `fresh_auth{authorize_url, client_id, redirect_uri}`.
  - **§6:** the Hub override mounts a `hub_secrets` subpath into app
    containers (`type: volume`, external `portcullis_hub_secrets`,
    `volume.subpath: <instance>/<key>`, read-only). This needs Engine API
    ≥ 1.45 and a compose that supports `volume.subpath`. Record the
    minimum compose version found in Task 6.
  - **§8:** the `portcullis-fresh-auth` client (Hub-owned, tagged).
  - **§10:** an entry may have `urls: []` plus `note`; the portal renders
    it without a link.
  - **§11.5 / §11.6:**
    - instance backups and core backups never contain credentials, their
      metadata or `hub_secrets`;
    - any restore voids every credential of the instance;
    - the `secrets_epoch` rule (spec call 25), and that core restore
      empties `hub_secrets`.
- [ ] **Step 4:** update the manifest reference: the two new types and the
  Time Machine example from the spec, written with project 1's field names
  (`columns[].name`, `key_column`).
- [ ] **Step 5:** run `zensical build --strict --clean`, then commit on
  `filesharing`:
  `contracts: person_secret, person_id pools, credential_change, tsv data files, hub_secrets, router-less custom`.

## Phase 2 — core

### Task 2: `hub_secrets`, restore voids, url-less portal entries (core repo)

**Files:**
- `docker-compose.yml`:
  - volume `hub_secrets: {name: portcullis_hub_secrets}`;
  - Hub mount `hub_secrets:/secrets`;
  - env `HUB_SECRETS_DIR: /secrets`,
    `HUB_SECRETS_VOLUME: portcullis_hub_secrets`,
    `HUB_KEYCLOAK_PUBLIC_URL: https://auth.${PORTCULLIS_DOMAIN:-portcullis.local}`;
- `scripts/lib/backup.sh`: `BACKUP_FILE_VOLUMES` unchanged, a comment
  saying why; restore empties `hub_secrets`;
- `group-gate/group-gate.py` (portal: entries with `urls: []`);
- `tests/test_cli.sh` / `tests/test_shell_libs.sh`,
  `tests/test_group_gate.py`;
- `CLAUDE.md`;
- `docs/` pointers.

- [ ] **Step 1: tests.**
  - `test_backup_excludes_hub_secrets` (shell lib test):
    `BACKUP_FILE_VOLUMES` and the MANIFEST `files` never name
    `hub_secrets`.
  - `test_restore_empties_hub_secrets`: with a fake `docker`, restore
    runs `volume rm portcullis_hub_secrets` and then `volume create` with
    the core project labels, before the Hub starts.
  - `test_portal_entry_without_url`: an entry with `urls: []`,
    `note: "No web page: file sharing over SMB"` renders as a card with
    the note, no `<a>`, and the content escaped.
- [ ] **Step 2: run.** `bash tests/test_shell_libs.sh` and
  `python3 -m pytest tests/test_group_gate.py -k portal` → FAIL.
- [ ] **Step 3: implement.** The Hub image provides `/secrets` owned
  10001, mode 0700 (Task 6 changes the Dockerfile). A fresh named volume
  copies that ownership up.
- [ ] **Step 4: verify.** Run all core suites → PASS.
- [ ] **Step 5: commit.**
  `core: hub_secrets volume (never backed up, emptied by restore), url-less portal entries`.

## Phase 3 — Hub

### Task 3: Manifest — person_secret, person_id, credential_change, router-less custom

**Files:**
- `internal/templates/settings.go`;
- `internal/templates/validate.go`;
- `internal/templates/routes.go` (zero routers);
- `internal/templates/settings_test.go`;
- `internal/templates/routerless_test.go` (new).

**Interfaces:**
- Consumes:
  - project 1's `Option`, `ReservedFeature`, `HookTriggers`, `DataFile`,
    `Column`, `Render`;
  - [P2] `FolderSpec`, `RunsAs{UID, GID *int; UIDEnv, GIDEnv, UIDFrom, GIDFrom string}`,
    `JoinTemplate`, `Port.LanOnly`, `Check`.
- Produces:
```go
type UsernameRule struct{ Pattern string; Reserved []string; Reason string } // yaml pattern/reserved/reason
type InfoLine struct{ Label, Value string }                               // yaml label/value
// Option: Username becomes *UsernameRule (yaml key unchanged); new fields:
//   Info           []InfoLine `yaml:"info"`
//   RowRequiresAny []string   `yaml:"row_requires_any"`
// DataFile gains Format string `yaml:"format"` ("" = json | "json" | "tsv")
// Column gains Mount string; Folder *FolderSpec `yaml:"folder"` (only on type path; cells must be folder refs)
// Render gains ExpandMembers bool `yaml:"expand_members"`
// RunsAs.UIDFrom/GIDFrom [P2]: no longer refused by ReservedFeature; they must name a person_id option
const HookCredentialChange = "credential_change" // added to HookTriggers
const HashNT = "nt"
const OnRestoreVoid = "void"
const PoolPOSIXUID = "posix_uid"
var PersonIDPools = map[string][2]int{PoolPOSIXUID: {10000, 59999}}
func (m *Manifest) Routerless() bool // custom auth and zero HTTP routers
```
- `ReservedFeature` no longer names `person_secret`/`person_id`, their
  fields or [P2] `RunsAs.UIDFrom`/`GIDFrom`. Project 1's
  `TestReservedTypesRefused` cases, and project 2's refusal test for
  `uid_from`, become acceptance cases.

- [ ] **Step 1: tests** (`settings_test.go`, table-driven, each refusal
  names the option):
  - `TestPersonSecretRules`. Refused:
    - `hash` other than `nt`;
    - `length < 24`;
    - `delivery` other than the bare `file`;
    - a missing `mount`, a `mount.service` not in compose, a relative
      `mount.path`, or one colliding with a path option or data file
      mount on that service;
    - `revoke_on_leave` not true;
    - `on_restore` other than `void`;
    - `scope` set;
    - `default` present;
    - a template without `access_group`;
    - a bad `username.pattern` regex;
    - an `info` placeholder naming an unknown option, port or table.

    The spec's Time Machine block passes.
  - `TestPersonIDRules`. Refused:
    - an unknown `pool`;
    - `self_visible` missing or true;
    - a non-file delivery;
    - `default`.
  - `TestCredentialChangeTrigger`: `when: [credential_change]` is OK.
  - `TestDataFileFormat`: `tsv` and `json` are OK; `xml` is refused.
  - `TestTableGroupsFolderColumns`. Refused:
    - a `path` column with a `folder` block but no `mount`;
    - a `mount` not containing `{<key_column>}`;
    - a `folder` block on a non-`path` column;
    - `type: folder` (project 2's reserved `TypeFolder`) as a column;
    - `row_requires_any` naming a non-`groups` column;
    - `expand_members` on an option with no `groups` column.

    The spec's Samba `shares` block, rewritten as `name`/`key_column` and
    `{name: folder, type: path, mount: "/shares/{name}", folder: {access: write, runs_as: {uid_from: uid}, joins_group: template}}`,
    passes.
  - `TestRunsAsFrom` [P2 `RunsAs`]:
    - `uid_from` must name a `person_id` option;
    - `gid_from` without `uid_from` is refused;
    - `gid_from` with a `JoinsGroup` other than `JoinTemplate` is
      refused;
    - two sources for one id (`uid` + `uid_from`) are refused (project
      2's rule, still holds).
  - `routerless_test.go`:
    - `TestRouterlessCustomDiscovered`: a custom template with no
      `traefik.enable` service and `group_access: true` plus
      `access_group` is discovered;
    - forward-auth with zero routers is still refused (today's
      behaviour);
    - `Routerless()` is true only for custom with zero routers.
- [ ] **Step 2: run.**
  `go test -race ./internal/templates/ -run 'TestPersonSecret|TestPersonID|TestCredentialChange|TestDataFileFormat|TestTableGroups|TestRunsAsFrom|TestRouterless'`
  → FAIL.
- [ ] **Step 3: implement** the fields and checks in
  `ValidateSettingsSpec`. The validator rule "custom + `group_access`
  needs `native_login`" is relaxed only when `Routerless()`.
- [ ] **Step 4: verify** with the Hub hygiene command → PASS.
- [ ] **Step 5: commit.**
  `templates: person_secret, person_id, credential_change, tsv files, table group/folder columns, router-less custom`.

### Task 4: Credential primitives and kinds (`internal/credentials`, `internal/settings`)

**Files:**
- Create: `internal/credentials/credentials.go` and its test.
- Create in `internal/settings/`: `kinds_person.go`, `tsv.go` and their
  tests.
- Modify: `internal/settings/wire.go`, `go.mod` (md4 direct).

**Interfaces:**
- Produces:
```go
// internal/credentials
const Alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYabcdefghjkmnpqrstuvwxyz"
func Generate(length int) ([]byte, error)          // length random chars, grouped by 4 with '-'; length%4 == 0
func NTHash(password []byte) string                 // 32 uppercase hex
func Zero(b []byte)
func CheckUsername(r *templates.UsernameRule, user string) (ok bool, reason string)
// internal/settings
type PersonIDKind struct{ Alloc func(ctx context.Context, pool string, people []Person) (map[string]int, error) } // Name "person_id"; PerPersonKind
type PersonSecretKind struct{ Status func(ctx context.Context, instance, key string, people []Person) (map[string]Value, error) } // Name "person_secret"; PerPersonKind; values are status strings
func EncodeTSV(doc DataFileDoc) ([]byte, error)    // grammar of contract §13; tab/newline in a field → error naming it
type HookCredential struct{ ID string `json:"id"`; Version int `json:"version"` }
// HookInput gains: Credentials map[string]map[string]HookCredential `json:"credentials"`
```

- [ ] **Step 1: tests.**
  - `TestGenerateAlphabetAndShape`:
    - `len(Alphabet) == 54`, with none of `0O1lIZio`;
    - `Generate(24)` matches `^([A-Za-z2-9]{4}-){5}[A-Za-z2-9]{4}$`, and
      every character is in `Alphabet`;
    - over 20 000 draws every symbol appears (no modulo bias: use
      `crypto/rand.Int`);
    - `Generate(10)` → error.
  - `TestNTHashVectors`:
    - `password` → `8846F7EAEE8FB117AD06BDD830B7586C`;
    - `""` → `31D6CFE0D16AE931B73C59D7E0C089C0`;
    - a 29-character dashed sample against a value computed once with
      `smbpasswd`/`pdbedit` and pinned in the test.
  - `TestCheckUsername`, with the spec's rule
    `^[a-z_][a-z0-9_.-]{0,31}$` and reserved `[root, nobody, timemachine]`:
    - `alice` OK;
    - `Alice.Smith@x`, a 33-character name and `root` → not OK, with the
      reason.
  - `TestEncodeTSV`:
    - the spec's people/shares doc gives sorted lines, a list
      comma-joined and `folder.mount`/`folder.gid`;
    - a value with `\t` → error naming the field.
  - `TestPersonKindsRegistered`:
    - `NewRegistry().Known("person_id")` is false until `Register`;
    - `Parse` of any admin input for either kind → error "set by the Hub".
- [ ] **Step 2: run.**
  `go test -race ./internal/credentials/ ./internal/settings/ -run 'TestGenerate|TestNTHash|TestCheckUsername|TestEncodeTSV|TestPersonKinds'`
  → FAIL.
- [ ] **Step 3: implement.** `Display` of `person_id` is the number. The
  kinds' closures are set by the Hub (Tasks 5 and 8).
- [ ] **Step 4: verify** with the Hub hygiene command → PASS.
- [ ] **Step 5: commit.**
  `credentials: password generator, NT hash, username rule; settings: person_id/person_secret kinds, tsv encoder`.

### Task 5: Hub-wide person-id pools

**Files:**
- `internal/state/state.go` (`PersonIDs`);
- `internal/hub/personids.go` (new) and its test;
- `internal/lldap/client.go` (`uuid` in the users query) and
  `internal/lldap/lldaptest`;
- `internal/directory/membership.go` (`UUIDs`);
- `internal/hub/hub.go` (register `PersonIDKind` before `Init`).

**Interfaces:**
- Consumes: project 1's `directory.Membership`, `People`; Task 4's
  `PersonIDKind`.
- Produces:
```go
// state
type PersonIDEntry struct {
    User string `yaml:"user"`; UUID string `yaml:"uuid"`; ID int `yaml:"id"`
    RetiredAt *time.Time `yaml:"retired_at,omitempty"`
}
type PersonIDPool struct{ Next int `yaml:"next"`; Entries []PersonIDEntry `yaml:"entries"` }
// AppState.PersonIDs map[string]PersonIDPool `yaml:"person_ids,omitempty"`
// directory.Membership gains UUIDs map[string]string // lowercase user → LLDAP uuid
// lldap.User gains UUID string `json:"uuid"`
func (h *Hub) allocPersonIDs(pool string, people []settings.Person, uuids map[string]string) (map[string]int, error) // under mu, saves once
func (h *Hub) PersonID(pool, user string) (int, bool)
```

- [ ] **Step 1: tests** (`personids_test.go`):
  - `TestPersonIDStableAcrossInstances`: two instances with pool
    `posix_uid` get the same uid for alice. The first allocation is 10000
    and later ones are increasing.
  - `TestRecreatedAccountNewUID` (Review Focus 4): alice with uuid A gets
    10000. alice with uuid B (deleted and recreated) gets 10001, and A's
    entry is retired. 10000 is never handed out again.
  - `TestPoolExhausted`: `Next` = 60000 → error "uid pool posix_uid is
    exhausted", and nothing is saved.
  - `TestPersonIDsSurviveRestore`: an instance restore into a new id
    keeps uids (the pools are not in `instance.yaml`); `state.yaml` keeps
    them.
  - `TestMembershipCarriesUUID` (directory): the fake LLDAP's uuid
    appears in `Membership.UUIDs`.
- [ ] **Step 2: run.**
  `go test -race ./internal/hub/ ./internal/directory/ -run 'TestPersonID|TestRecreated|TestPoolExhausted|TestMembershipCarriesUUID'`
  → FAIL.
- [ ] **Step 3: implement.** A missing uuid (LLDAP unavailable) means no
  allocation: the delivery is skipped "directory unavailable", as in
  project 1.
- [ ] **Step 4: verify** with the Hub hygiene command → PASS.
- [ ] **Step 5: commit.** `hub: Hub-wide person-id pools keyed by LLDAP uuid`.

### Task 6: Secrets volume, credential metadata, epoch, mount, backup and restore

**Files:**
- `internal/state/state.go` (`Credentials`, `SecretsEpoch`);
- `internal/hub/credstore.go` (new) and `credstore_test.go`;
- `internal/hub/override.go` (subpath mount, external volume);
- `internal/hub/lifecycle.go` (ensure dirs before up);
- `internal/hub/hub.go` (`Config.SecretsDir`, `SecretsVolume`; `Init`
  calls `reconcileSecrets`);
- `internal/hub/backup.go` (assert exclusion);
- `internal/hub/restore.go` (void after success);
- `internal/hub/delete.go` (remove `<secrets>/<id>/`, metadata);
- `cmd/hub/main.go` (`HUB_SECRETS_DIR`, `HUB_SECRETS_VOLUME`);
- `Dockerfile` (`mkdir -p /secrets && chown 10001:10001 /secrets && chmod 0700 /secrets`);
- the compose version check (minimum for `volume.subpath`).

**Interfaces:**
- Produces:
```go
// state
type Credential struct {
    ID string `yaml:"id"`; Version int `yaml:"version"`; UUID string `yaml:"uuid"`
    CreatedAt time.Time `yaml:"created_at"`; CreatedBy string `yaml:"created_by"`
    RevokedAt *time.Time `yaml:"revoked_at,omitempty"`; RevokedBy string `yaml:"revoked_by,omitempty"`
    Reason string `yaml:"reason,omitempty"` // self|admin|leave|deleted|restore
}
// AppState.Credentials map[string]map[string]map[string]Credential `yaml:"credentials,omitempty"` // instance → key → user
// AppState.SecretsEpoch string `yaml:"secrets_epoch,omitempty"`
func (h *Hub) secretPath(instance, key, user string) string
func (h *Hub) writeHashLocked(instance, key, user, hash string) error // rotates the epoch: volume file first, then state
func (h *Hub) removeHashLocked(instance, key, user string) error      // rotates the epoch
func (h *Hub) reconcileSecrets(reason string) (voided int, err error)  // boot + before every credentials delivery
func (h *Hub) voidCredentialsLocked(instance, reason string) int       // audits credential.void_restore count=N
```
- **Override:**
  - top-level `volumes: {portcullis_hub_secrets: {external: true, name: <SecretsVolume>}}`;
  - on `mount.service`:
    `{type: volume, source: portcullis_hub_secrets, target: <mount.path>, read_only: true, volume: {subpath: <instance>/<key>}}`.

- [ ] **Step 1: tests** (`credstore_test.go`):
  - `TestHashFileLayout`:
    - `<tmp>/secrets/immich2/share_password/alice.nt` holds 33 bytes;
    - modes 0700/0600;
    - `state.yaml` contains no 32-hex string other than ids;
    - `.epoch` equals `SecretsEpoch`.
  - `TestEpochMismatchVoidsAll` (Review Focus 2): copy `state.yaml`, make
    a credential change, put the old `state.yaml` back, then `Init`:
    - every credential has `reason: restore`;
    - the volume is empty except the new `.epoch`;
    - the audit has `credential.void_restore count=2`.
  - `TestCrashBetweenHashAndStateFailsClosed`: inject a failing state save
    after the volume epoch write → the next `Init` voids all.
  - `TestOrphansReconciled`:
    - a `.nt` file without active metadata is deleted;
    - active metadata without a file is voided.
  - `TestSecretsMountSubpath`: the override YAML has the external volume
    and the subpath mount `:ro` on the declared service only. The
    directory exists before `compose up` (the fake runner checks).
  - `TestBackupExcludesCredentials`: an instance with a credential is
    backed up. The archive's bytes don't contain the hash, and
    `config/instance.yaml` has no `credentials` key.
  - `TestRestoreVoidsCredentials`:
    - a same-instance restore leaves every credential `voided`
      (`reason: restore`) with no hash files;
    - a restore into a new id has no credentials;
    - both are audited once with the count.
  - `TestDeleteRemovesSecrets`: `<secrets>/<id>/` and the metadata are
    gone.
- [ ] **Step 2: run.**
  `go test -race ./internal/hub/ -run 'TestHashFileLayout|TestEpoch|TestCrashBetween|TestOrphans|TestSecretsMount|TestBackupExcludesCredentials|TestRestoreVoids|TestDeleteRemovesSecrets'`
  → FAIL.
- [ ] **Step 3: implement.**
  - The epoch is 16 random bytes in hex. A missing `.epoch` (new volume)
    with credentials in state → void all.
  - Check that compose supports `volume.subpath` on the version the Hub
    image ships. Raise the startup compose version check to the first
    supporting release and record it in contract §6 (Task 1 left a
    placeholder).
- [ ] **Step 4: verify** with the Hub hygiene command → PASS.
- [ ] **Step 5: commit.**
  `hub: credential store on hub_secrets (epoch guard, subpath mount, excluded from backups, voided by restore)`.

### Task 7: Fresh authentication (shared with the certificates project)

The certificates project has not built it (checked 2026-11-02: no
`fresh`/`auth_time` code in Hub, core or Keycloak config). This task is
the minimal piece both projects use.

**Files:**
- Create: `internal/freshauth/freshauth.go` and `freshauth_test.go`.
- Create: `internal/keycloak/freshauth.go`; modify `kctest` (public
  client, PKCE attribute).
- Modify: `internal/hub/hub.go` (`SetFreshAuth`), `cmd/hub/main.go`
  (config `HUB_KEYCLOAK_PUBLIC_URL`, default
  `https://auth.<PORTCULLIS_DOMAIN>`; ensure the client in the directory
  sync loop with retry), `go.mod`.

**Interfaces:**
- Produces:
```go
// internal/freshauth
const ClientID = "portcullis-fresh-auth"
const MaxAge = 5 * time.Minute
var AcceptedAMR = []string{"hwk", "mtls"} // never "file"
type Config struct {
    Issuer        string // <public>/realms/portcullis
    TokenURL      string // http://keycloak:8080/realms/portcullis/protocol/openid-connect/token
    JWKSURL       string // http://keycloak:8080/realms/portcullis/protocol/openid-connect/certs
    AuthorizeURL  string // <public>/realms/portcullis/protocol/openid-connect/auth
    RedirectURI   string // https://people.<domain>/
    HTTP          *http.Client
    Now           func() time.Time
}
type Proof struct{ Code, CodeVerifier, Nonce string }
type Result struct{ User string; AuthTime time.Time; AMR []string }
type Error struct{ Reason string } // always answered 403 "a fresh passkey sign-in is required"; Reason only in the audit
type Verifier struct{ /* oidc.IDTokenVerifier over a RemoteKeySet on JWKSURL */ }
func New(cfg Config) *Verifier
func (v *Verifier) Verify(ctx context.Context, p Proof, user string) (*Result, error)
type AuthorizeInfo struct{ AuthorizeURL, ClientID, RedirectURI string } // json authorize_url, client_id, redirect_uri
func (v *Verifier) Info() AuthorizeInfo
// internal/keycloak
func (c *Client) EnsureFreshAuthClient(ctx context.Context, redirectURI, webOrigin string) error // owner-tagged; public, PKCE S256, standard flow only, no direct/implicit/service/device grants, no refresh tokens
// internal/hub
type FreshAuth interface {
    Verify(ctx context.Context, p freshauth.Proof, user string) (*freshauth.Result, error)
    Info() freshauth.AuthorizeInfo
}
func (h *Hub) SetFreshAuth(f FreshAuth)
```
- The code exchange runs Hub → Keycloak with `oauth2.Config.Exchange(…, oauth2.VerifierOption(p.CodeVerifier))`.
- The ID token is verified by `go-oidc` against the public issuer through
  internal JWKS (`oidc.NewRemoteKeySet`).
- Keycloak's single-use codes make a replay fail.

- [ ] **Step 1: tests** (`freshauth_test.go`, an `httptest` token
  endpoint + JWKS with a generated RSA key):
  - `TestFreshAuthAccepts`: `auth_time` now − 10 s, `amr: ["hwk"]`, the
    right nonce and user → OK. The same with `amr: ["mtls"]` → OK.
  - `TestFreshAuthRefusals` (Review Focus 5), each an `*Error`:
    - `auth_time` now − 301 s;
    - `amr: ["file"]`;
    - `amr: ["hwk","file"]`;
    - `acr: "file"`;
    - no `amr`;
    - a wrong nonce;
    - `azp` another client;
    - `preferred_username: bob` for caller `alice`;
    - `ALICE` for caller `alice` → OK (case-folded);
    - a token signed by another key;
    - the token endpoint answering `invalid_grant` (replayed code).
  - `TestFreshAuthNeverLogsCode`: the log capture holds neither the code,
    the verifier nor the token.
  - keycloak `TestEnsureFreshAuthClient` (kctest):
    - created with `publicClient`, `pkce.code.challenge.method=S256`,
      exact redirect URI and web origin, no direct grant, the owner tag;
    - idempotent;
    - an untagged existing client of that id → `*ConflictError`.
- [ ] **Step 2: run.**
  `go test -race ./internal/freshauth/ ./internal/keycloak/ -run 'TestFreshAuth|TestEnsureFreshAuthClient'`
  → FAIL.
- [ ] **Step 3: implement.**
- [ ] **Step 4: verify** with the Hub hygiene command → PASS.
- [ ] **Step 5: commit.**
  `freshauth: shared fresh passkey/hardware-certificate verifier and its Keycloak client`.

### Task 8: Credential service (create, regenerate, revoke, list)

**Files:**
- `internal/hub/credentials.go` (new) and `credentials_test.go`;
- `internal/hub/deliver.go`: unit `credentials:<key>` (its hash is over
  the active metadata), and `HookInput.Credentials` filled;
- `internal/hub/hub.go`: register `PersonSecretKind`;
- `internal/hub/ops.go`: redaction of hashes and passwords;
- `internal/hub/deliver.go`: `TriggerCredential`.

**Interfaces:**
- Consumes:
  - Task 4 `credentials.*`;
  - Task 6 store;
  - Task 7 `FreshAuth`;
  - project 1's `InPopulation`, `TriggerDelivery(id, trig, immediate)`
    and `Deliver`.
- Produces:
```go
const TriggerCredential Trigger = "credential_change"
type CreatedCredential struct{ Password []byte; Credential state.Credential } // caller zeroes Password
func (h *Hub) CreateCredential(ctx context.Context, instance, key, user string, p freshauth.Proof) (*CreatedCredential, error) // create or regenerate
func (h *Hub) RevokeOwnCredential(ctx context.Context, instance, key, user string) error
func (h *Hub) AdminRevokeCredential(ctx context.Context, instance, key, user, actor string) error
type CredentialRow struct {
    User string `json:"user"`; Status string `json:"status"`; Since *time.Time `json:"since,omitempty"`
    Reason string `json:"reason,omitempty"`; IDs map[string]int `json:"ids,omitempty"` // person_id values by key
    Values map[string]string `json:"values,omitempty"` // person-scope values, displayed
}
type CredentialsView struct {
    Instance string `json:"instance"`; Key string `json:"key"`; Label string `json:"label"`
    Population int `json:"population"`; Active int `json:"active"`; Rows []CredentialRow `json:"rows"`
    Folders []settings.HookFolder `json:"folders"`; LastSync *UnitResult `json:"last_sync,omitempty"`
}
func (h *Hub) Credentials(ctx context.Context, instance string) ([]CredentialsView, error) // metadata only
```
- **Order in `CreateCredential`:**
  1. check the instance, key and `InPopulation`; refuse 404;
  2. check the username rule; refuse 409 with the reason;
  3. `FreshAuth.Verify`; refuse 403;
  4. `Generate(o.Length)` → `NTHash`;
  5. under `mu`: `writeHashLocked`, then the metadata (`Version`+1 on
     regenerate, a new `ID` each time), then save;
  6. audit `credential.create` or `credential.regenerate`;
  7. `TriggerDelivery(id, TriggerCredential, true)`.

  The username check comes before `Verify`, so the proof isn't consumed
  for a refused name.

- [ ] **Step 1: tests** (`credentials_test.go`, a fake `FreshAuth`):
  - `TestCreateCredential`:
    - the answer's password has the shape of Task 4;
    - the hash file equals `NTHash` of it;
    - metadata `{Version: 1, CreatedBy: alice}`;
    - the audit has `credential.create instance=… key=… user=alice actor=alice`;
    - one immediate `credential_change` delivery.
  - `TestRegenerateReplaces`: the hash changes, `Version: 2`, the ID
    changes, and the audit has `credential.regenerate`.
  - `TestOutsidePopulation404`: carol (not in `users_<id>`) → 404, the
    same body as an unknown instance.
  - `TestUsernameRuleRefuses` (Review Focus 4): user `root` → 409 with
    the reason, and `Verify` is not called (the fake counts).
  - `TestFreshAuthRequired`: the fake returns `*Error` → 403, nothing
    written, audit `refused`.
  - `TestRevokeOwnNeedsNoProof`: the file is gone, `reason: self`, and a
    delivery is triggered.
  - `TestAdminRevoke`: `reason: admin`, `RevokedBy: root`, the audit
    actor is root. There is no admin create method.
  - `TestCredentialNotEchoed` (style of `TestTokenNotEchoed`), with the
    password and hash from a create:
    - neither appears in `state.yaml`, the op records, `audit.jsonl`, the
      log capture, the hook stdin of a following delivery, or
      `Credentials()` JSON;
    - a hook whose output echoes the hash → `[redacted]` in the op
      record.
  - `TestHookInputCredentials`: stdin has
    `credentials.share_password.alice == {id, version: 1}` and no 32-hex
    value.
  - `TestMyAppsCredentialStatuses`: `MyApps(alice)` `credentials[]`
    shows, in turn:
    - `none` before;
    - `active` + `Since` after;
    - `voided` + `reason: restore` after a restore;
    - `unavailable` for a reserved name.

    `Info` lines render `smb://nas.home.arpa/TimeMachine-alice` (and
    `:4450` when the host port isn't 445), `{user}` and `{rows:shares}`.
    `person_id` never appears.
- [ ] **Step 2: run.**
  `go test -race ./internal/hub/ -run 'TestCreateCredential|TestRegenerate|TestOutsidePopulation|TestUsernameRule|TestFreshAuthRequired|TestRevokeOwn|TestAdminRevoke|TestCredentialNotEchoed|TestHookInputCredentials|TestMyAppsCredentialStatuses'`
  → FAIL.
- [ ] **Step 3: implement.** `MyApps` fills `Credentials` (project 1's
  `MyCredential`, `MyInfoLine`) from the metadata and the `info`
  templates. `MyApps`' answer gains `FreshAuth *freshauth.AuthorizeInfo`
  (json `fresh_auth`) when any credential is listed.
- [ ] **Step 4: verify** with the Hub hygiene command → PASS.
- [ ] **Step 5: commit.** `hub: self-service file-share credentials (create, regenerate, revoke, admin revoke, My apps)`.

### Task 9: Revoke on leave (holder check, immediate delivery, fail closed)

**Files:**
- `internal/hub/revoke.go` (new) and `revoke_test.go`;
- `internal/directory/evaluate.go` (`OnEvaluated` hook after each
  `evaluateAndLog`);
- `internal/directory/service.go` (field);
- `cmd/hub/main.go` (`OnChange` also calls `h.TriggerCredentialCheck`;
  `OnEvaluated = h.TriggerCredentialCheck`);
- `internal/hub/delete.go` (instance delete revokes with
  `reason: deleted`, no hook).

**Interfaces:**
- Consumes: project 1's `People.Membership`, `populationLocked`,
  `TriggerDelivery(…, true)`, `Deliver`, `Restart` path
  (`restartLocked`), `composeDown`; Task 6 `removeHashLocked`.
- Produces:
```go
// directory.Service gains: OnEvaluated func() // after every evaluator run (tick or kick), outside s.mu; must not block
func (h *Hub) TriggerCredentialCheck()                     // coalesced, never debounced
func (h *Hub) CheckCredentialHolders(ctx context.Context) (revoked int, err error)
func (h *Hub) RunCredentialChecks(ctx context.Context)     // started in main; serves the trigger only (no own ticker)
const OpCredentials = "credentials"
```
- **`CheckCredentialHolders`:**
  1. outside `mu`: `Membership(ctx, now)`; on error, return it and change
     nothing;
  2. for each instance with `person_secret` options and each active
     credential:
     - if the holder is not in the population, or their uuid differs from
       `Credential.UUID` (account deleted, recreated, or gone): under
       `mu`, `removeHashLocked`, metadata `reason: leave` (or `deleted`
       when the user is absent from LLDAP), and audit
       `credential.revoke_leave`;
  3. per affected instance: `Deliver(ctx, id, TriggerCredential)`
     directly (not debounced);
  4. if the hook unit fails or times out: `restartLocked` (recreate). If
     that fails: `composeDown`, an op record `credentials` with the error
     "revocation could not be applied; the instance was stopped", and the
     instance left enabled (drift shows it).

- [ ] **Step 1: tests** (`revoke_test.go`, fake clock and fake engine):
  - `TestRemoveMemberRevokesAtOnce`:
    - `RemoveMember(users_tm, bob)` through the directory service fires
      `OnChange` → within the test's 2 s: bob's hash is gone,
      `reason: leave` is in the audit, and one hook exec with trigger
      `credential_change`;
    - the project 1 debounce timer did not delay it (fake clock not
      advanced).
  - `TestLLDAPDirectRemovalCaughtOnTick`: bob is removed in the fake
    LLDAP without `OnChange`, then `OnEvaluated` fires → revoked.
  - `TestDeletedAccountRevoked`: bob is absent from LLDAP →
    `reason: deleted`. bob recreated with a new uuid and in the group →
    still revoked (uuid mismatch).
  - `TestLLDAPDownDoesNothing`: `Membership` fails → no change, no hook,
    no op record.
  - `TestRevokeHookFailureRecreates` (Review Focus 3): the hook exits 1
    → one compose down + up, and the op record `restart` is OK.
  - `TestRevokeRecreateFailureStops`: the hook times out and up fails →
    compose down is called, the op record `credentials` has the message,
    and the instance is still enabled in state.
  - `TestAdditionsStayDebounced`: alice joining triggers no immediate
    delivery. Project 1's 60 s debounce applies (fake clock).
  - `TestInstanceDeleteRevokes`: delete → metadata gone, no hook.
- [ ] **Step 2: run.**
  `go test -race ./internal/hub/ ./internal/directory/ -run 'TestRemoveMemberRevokes|TestLLDAPDirect|TestDeletedAccount|TestLLDAPDown|TestRevokeHook|TestRevokeRecreate|TestAdditionsStay|TestInstanceDeleteRevokes|TestOnEvaluated'`
  → FAIL.
- [ ] **Step 3: implement.** Add `TestOnEvaluated` (directory): the hook
  is called after a tick with no changes too.
- [ ] **Step 4: verify** with the Hub hygiene command → PASS.
- [ ] **Step 5: commit.**
  `hub: revoke on leave from OnChange and the evaluator tick (no debounce, recreate then stop on failure)`.

### Task 10: Data files and hooks for file sharing (tsv, table group/folder cells, local networks, hook reports)

**Files:**
- `internal/hub/deliver_files.go` (format `tsv`, `expand_members`);
- `internal/settings/kinds_set.go` (table cells of type `groups`, and
  `path` cells holding [P2] folder refs via `ParseFolderRef`);
- `internal/hub/groupsettings.go` (purge group ids inside table cells;
  `row_requires_any`; "members without access" warnings);
- `internal/hub/settings.go`: `SaveSettings` refuses a change to a row's
  folder cell with 409, as [P2] does for `folder:` values;
- [P2] `internal/hub` assignment code (`FolderUse` gains `Row`;
  `PreviewAssign`/`StartAssign` add, move or remove one row's folder;
  `folderUsesLocked` and `PathUsages` list one use per row);
- `internal/hub/override.go` (per-row mounts through [P2] `hubFolders`);
- `internal/hub/env.go` (`PORTCULLIS_LOCAL_NETWORKS`);
- `internal/templates/instance.go` (`ReservedVar`);
- `internal/hub/deliver_hooks.go` (parse reports into
  `<data>/settings/<id>/hook-report.json`);
- `internal/settings/wire.go` (`HookReport`);
- tests: `internal/hub/filesharing_files_test.go`;
- fixture `internal/hub/testdata/settings/smbfixture/` (Samba-shaped
  manifest: person_secret, person_id, `shares` table, tsv file, hook).

**Interfaces:**
- Consumes:
  - project 1's `DataFileDoc`, `Render`, `PurgeGroupSettings`,
    `SaveResult.Warnings`, `PathUsage`;
  - [P2] `FolderRefPrefix`, `ParseFolderRef`, `hubFolders` (the
    `FolderSource`), `state.Folder.GID`, `FolderUse`, `AssignRequest`,
    `PreviewAssign`, `StartAssign`, `PathUsage.Folder`/`Subpath`/`JoinsGroup`/`Source`;
  - [P2] `LocalNetworksView() (cidrs []string, isDefault bool)`,
    `DefaultLocalNetworks`, `SetLocalNetworks`.
- Produces:
```go
const VarLocalNetworks = "PORTCULLIS_LOCAL_NETWORKS" // reserved
// [P2] FolderUse gains: Row string `json:"row,omitempty"` // key-column value of a table row; "" = a plain path option
// PathUsage of a row: Key "<option>/<row>", Mount = the row's rendered mount
const HookReportPrefix = "PORTCULLIS-REPORT "
type HookFinding struct{ Code, Severity, Subject, Message string; UID int } // json lowercase; Severity problem|warning|info
type HookFolder struct{ Option, Name string; UID int; Former bool; Bytes *int64 } // json option,name,uid,former,bytes
type HookReport struct{ Version int; At time.Time; Findings []HookFinding; Folders []HookFolder }
func (h *Hub) HookReport(id string) (*settings.HookReport, bool)
```
- Report codes the templates use: `former_account`, `wrong_owner`,
  `name_refused`, `owner_unwritable`.
- **Local networks env.** `PORTCULLIS_LOCAL_NETWORKS` is the comma-joined
  `LocalNetworksView()` list.
  - Check how [P2] `SetLocalNetworks` treats `[]string{}`. If it refuses
    an empty list, nothing more is needed (the script still refuses an
    empty value).
  - If it accepts one, make the state keep "saved empty" apart from
    "never set": `AppState.LocalNetworks` must not be `omitempty`-dropped
    to nil. The env is then `''`.

- [ ] **Step 1: tests** (`filesharing_files_test.go`):
  - `TestTSVPeopleFile`:
    - the `people` file is `people.tsv` (0640) with `person alice uid 10000`
      and `person alice size_limit 10240`;
    - `value share_prefix TimeMachine`;
    - mounted as a directory, read-only.
  - `TestExpandMembersPopulationOnly`:
    - row `Family`, readers `[office_milan]`, writers `[users_smb]` →
      `row shares Family readers alice,bob` holds only population
      members;
    - a member of `office_milan` without access is absent;
    - the save warning reads "1 member of office_milan has no access to
      Samba and won't get this share".
  - `TestRowRequiresAny`: a row with empty readers and writers → 400
    naming the row.
  - `TestGroupCellPurged`: `DeleteGroup(office_milan)` removes it from
    every table cell (audited `settings.purge`). A recreated
    `office_milan` (new id) grants nothing.
  - `TestRowFolderGoesThroughAssign` [P2]:
    - `SaveSettings` changing writers only → `Effect "none"` and a hook
      delivery;
    - `SaveSettings` adding a row with `folder:family` → 409 "use the
      folder assignment";
    - `PreviewAssign(family, {Uses: [{Instance: smb, Key: shares, Row: Family, Write: true}]})`
      then `StartAssign` → the row exists and the override mounts
      `<folder host path>:/shares/Family` (rw);
    - `PathUsages()` has `Key "shares/Family"`, `Folder "family"`,
      `JoinsGroup "template"`, `OwnerKnown false`.
  - `TestFolderCellGID` [P2]: `row shares Family folder.gid 60001`
    (`state.Folder.GID`) and `folder.mount /shares/Family`. There is no
    `PORTCULLIS_FOLDER_GID_*` for a table.
  - `TestLocalNetworksEnv` [P2]:
    - the default → `PORTCULLIS_LOCAL_NETWORKS='10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7,100.64.0.0/10'`;
    - a saved empty list → `''`, or a 400 from `SetLocalNetworks`,
      whichever project 2 does; pin the one that holds;
    - `SetLocalNetworks` restarts enabled instances whose compose
      references `${PORTCULLIS_LOCAL_NETWORKS` (and only those);
    - a template defining the variable is refused (`ReservedVar`).
  - `TestHookReportStored`: hook stdout with a `PORTCULLIS-REPORT {…}`
    line → `HookReport(id)` has the finding and folder, and the line is
    not in the op record. A malformed report → logged, ignored, and the
    unit is still OK.
- [ ] **Step 2: run.**
  `go test -race ./internal/hub/ ./internal/settings/ -run 'TestTSV|TestExpandMembers|TestRowRequiresAny|TestGroupCellPurged|TestRowFolderGoesThroughAssign|TestFolderCellGID|TestLocalNetworksEnv|TestHookReportStored'`
  → FAIL.
- [ ] **Step 3: implement.** A row's folder use follows project 2's
  call 9 like any other use: stop, fix, start. The folder's permissions
  plan uses the row's `runs_as` (`uid_from` → `OwnerKnown false`: no
  principal uid, group access only).
- [ ] **Step 4: verify** with the Hub hygiene command → PASS.
- [ ] **Step 5: commit.**
  `hub: tsv data files, table group/folder cells (assigned per row), PORTCULLIS_LOCAL_NETWORKS, hook reports`.

### Task 11: Doctor checks and per-person trees [P2]

**Files:**
- [P2] `internal/doctor`: `Inputs` gains `FileSharing`; new checks in
  `filesharing.go`;
- [P2] `internal/folderfix`: `Target.ChildOwners` (apply: chown/chmod
  exactly those first-level children, never recursive);
- [P2] `internal/hub/doctor*.go`: `doctorInputs` fills `FileSharing`;
  `scanTargetsLocked` adds one `ScanTarget` per per-person tree with
  `Children: true`; the fixers are registered with `RegisterFixer`;
- [P2] folder code: a path option whose `runs_as` has `GIDFrom` refuses
  `folder:` values (400). It gets no `PORTCULLIS_FOLDER_GID_<KEY>`, no
  setgid/ACL/mask plan, and isn't a `shared_path`/`folder_owner` subject;
- `internal/hub/doctor_filesharing.go` (new) and its test.

**Interfaces:**
- Consumes:
  - [P2] `doctor.Check{Kind() string; Run(in *Inputs) []Finding}`,
    `doctor.Register`, `doctor.Fingerprint`;
  - `Finding{FP, Kind, Severity, Title, Why, Fix, Instances, Folders, Paths, Class, FixKind, Steps, …}`,
    `Problem`/`Warning`/`Info`, `FixClass` `one_click`/`explain`;
  - `Fixer{Kind; Preview; Apply}`, `RegisterFixer`, `FixPlan`, `runFixer`;
  - `folderfix.Options.Children`, `Report.Children []ChildOwner{Name; UID, GID int; Entries, Foreign int64}`;
  - the `lan_only_exposed` finding (unchanged; the File sharing banner
    shows it);
  - Task 9 holder logic (as a pure function of membership and metadata),
    Task 10 `HookReport`, Task 5 `PersonID`.
- Produces:
```go
// doctor (no Hub import)
type HolderIn struct{ User string; HasAccess bool }
type TreeIn struct{ Instance, Key, HostPath string; People map[string]int } // user → expected uid (= gid)
type FileSharingIn struct {
    Instance, Label string
    Holders []HolderIn            // active credentials
    Trees   []TreeIn              // gid_from path options with a value
    Report  *settings.HookReport  // last hook report, may be nil
    LocalNetworksEmpty bool       // a saved empty list while this instance references PORTCULLIS_LOCAL_NETWORKS
}
// Inputs gains FileSharing []FileSharingIn
// check kinds: credential_without_access (Problem, one_click fix "revoke_leaver"),
//   former_account_folder (Warning, explain), person_tree_owner (Warning, one_click fix "person_tree_owner"),
//   local_networks_empty (Problem, link to Settings → Local networks)
// folderfix.Target gains ChildOwners map[string]int // name → uid; apply: chown uid:uid + chmod 0700 of <root>/<name> only
```
- **Per-person tree expectations (spec call 29).** Each first-level
  `ChildOwner` of a tree is checked against the people's uids:
  - named after a person with `UID` == their uid, `GID` == uid and mode
    0700 → fine. Mode comes from the scan; add `Mode` to `ChildOwner` if
    project 2's report lacks it;
  - another uid → `former_account_folder` ("alice's Time Machine folder
    belongs to a former account (uid 10023)");
  - right uid, wrong gid or mode → `person_tree_owner`, a one-click fix;
  - anything else at the top level → Info.

  Files inside a person's tree aren't checked (`Foreign` is ignored for
  these trees).

- [ ] **Step 1: tests.**
  - `TestCanaryFindsUnrevokedHolder`: `Holders: [{bob, false}]` → one
    Problem `credential_without_access` naming instance and user. Its fix
    `revoke_leaver` previews "revoke bob's file-share password", and
    applying it calls `AdminRevokeCredential` with the admin actor.
  - `TestFormerAccountFinding`: a `ChildOwner{Name: alice, UID: 10023}`
    while alice is 10000 → Warning with the spec's text, explain-only.
    The same subject from the hook report alone (no scan yet) gives the
    same fingerprint.
  - `TestPersonTreeOwnerFix`: `{alice, UID 10000, GID 100}` → the preview
    is exactly one line, `chown 10000:10000 + chmod 0700 <tree>/alice
    (not recursive)`. The apply runs the fixer with
    `Target.ChildOwners{"alice": 10000}`. In `folderfix`,
    `TestApplyChildOwnersNotRecursive`: a file inside keeps its owner.
  - `TestGIDFromRefusesFolderValue`: `folder:photos` on a `gid_from`
    option → 400. `PathUsages` marks it `OwnerKnown false`, and no
    `folder_owner` or `shared_path` finding names it.
  - `TestLocalNetworksEmptyProblem` (only if Task 10 found that an empty
    list can be saved).
- [ ] **Step 2: run.**
  `go test -race ./internal/doctor/ ./internal/folderfix/ ./internal/hub/ -run 'TestCanary|TestFormerAccountFinding|TestPersonTreeOwnerFix|TestApplyChildOwners|TestGIDFromRefuses|TestLocalNetworksEmpty'`
  → FAIL.
- [ ] **Step 3: implement.**
- [ ] **Step 4: verify** with the Hub hygiene command → PASS.
- [ ] **Step 5: commit.**
  `doctor: file-sharing checks (credential canary + revoke fix, former account folders, per-person tree owner fix, empty local networks)`.

### Task 12: Routes (people listener and admin)

**Files:**
- `internal/httpapi/myapps.go` (or `people.go`, wherever project 1 put
  `GET /api/me/apps`);
- `internal/httpapi/instances.go` (admin credential routes);
- `internal/httpapi/server.go` (`PeopleHandler` registers the two
  routes);
- `internal/httpapi/people_test.go` (append to `peopleAppRoutes`);
- `internal/httpapi/credentials_test.go` (new).

**Interfaces:**
- Consumes: Task 8 methods.
- Produces:
  - **People listener:**
    - `POST /api/me/apps/{instance}/credentials/{key}`: body
      `{code, code_verifier, nonce}` (≤ 8 KiB) → 200
      `{password, credential: {status, since}}`, with
      `Cache-Control: no-store` and `Pragma: no-cache`; 404, 409 or 403
      as in Task 8;
    - `DELETE …/{key}` → 204.
  - `peopleAppRoutes` becomes
    `{"GET /api/me/apps", "POST /api/me/apps/{instance}/credentials/{key}", "DELETE /api/me/apps/{instance}/credentials/{key}"}`.
  - **Hub listener, `adminOnly`:**
    - `GET /api/instances/{id}/credentials` → `[]CredentialsView`;
    - `DELETE /api/instances/{id}/credentials/{key}/{user}` → 204.

- [ ] **Step 1: tests** (`credentials_test.go`):
  - `TestCreateCredentialRoute`: `X-Forwarded-User: Alice` → alice's
    credential, the right headers, and the body has `password`. The
    handler zeroes the buffer (spy).
  - `TestCreateCredentialWrongUserProof` (Review Focus 5): the fake
    verifier is bound to bob → 403, with the generic message only.
  - `TestCredentialRoutesCallerOnly`: no `X-Forwarded-User` → 401. There
    is no route taking a username on the people listener.
  - `TestAdminCredentialRoutes`: a delegate → 403; root → 200 with no
    `password` or hash field anywhere in the JSON; DELETE audited with
    actor root.
  - `TestPeopleListenerHasNoAppRoutes` (updated): exactly
    `peopleAppRoutes` beyond the directory. The credential routes → 404
    on the Hub listener; the admin routes → 404 on the people listener.
  - `TestCredentialBodyLimit`: 9 KiB → 413.
- [ ] **Step 2: run.**
  `go test -race ./internal/httpapi/ -run 'TestCreateCredential|TestCredentialRoutes|TestAdminCredential|TestPeopleListener|TestCredentialBody'`
  → FAIL.
- [ ] **Step 3: implement.**
- [ ] **Step 4: verify** with the Hub hygiene command → PASS.
- [ ] **Step 5: commit.** `httpapi: credential routes (people: own create/revoke; hub: admin list/revoke)`.

### Task 13: Router-less instances in policy, portal and app views

**Files:**
- `internal/hub/portal.go` (`urls: []`, `note`);
- `internal/hub/hub.go` (`WritePolicy`: no hosts, nothing published,
  nothing denied);
- `internal/hub/myapps.go` (`URL ""`);
- `internal/hub/accessrole.go` (never for custom);
- tests: `internal/hub/routerless_test.go`.

**Interfaces:**
- Consumes: Task 3 `Manifest.Routerless()`.
- Produces: portal entry `{…, "urls": [], "note": "<auth.notes>"}`.

- [ ] **Step 1: tests.**
  - `TestRouterlessEnableNoPolicyHosts`: enabling the fixture → the
    policy file has no host for it, the reconcile reports no exposure
    drift, and no Keycloak client or access role is made.
  - `TestRouterlessPortalEntry`: the entry has empty `urls` and `note`.
    `access_group` is `users_<id>`.
  - `TestRouterlessMyApps`: `URL == ""`, and the card is listed for
    population members only.
- [ ] **Step 2: run.**
  `go test -race ./internal/hub/ -run TestRouterless` → FAIL.
- [ ] **Step 3: implement.**
- [ ] **Step 4: verify** with the Hub hygiene command → PASS.
- [ ] **Step 5: commit.** `hub: router-less custom instances (policy, portal, My apps)`.

### Task 14: UI (My apps credential cards, File sharing tab, LAN warnings)

**Files:**
- `web/myapps.js` (credential card, fresh-auth popup, the shown-once
  dialog);
- `web/people.html` (popup callback: when loaded with `code` and `state`
  and `window.opener` is same-origin, `postMessage` and close);
- `web/index.html`:
  - app detail tab **File sharing**, shown when the template has a
    `person_secret` option;
  - a banner from [P2] `PortcullisDoctor.lineFor(instance)` (the
    `lan_only_exposed` finding);
  - the enable-dialog confirmation for `lan_only` ports bound to
    `0.0.0.0`;
  - "No web page" for router-less instances;
- `internal/httpapi/harness_test.go` (fixture data: a credential, a hook
  report, an exposure finding).

- [ ] **Step 1: implement My apps.**
  - **Create password:**
    1. generate `state`, `nonce` and a PKCE verifier (WebCrypto SHA-256,
       base64url) in `sessionStorage`;
    2. open a popup to `fresh_auth.authorize_url` with `client_id`,
       `redirect_uri`, `response_type=code`, `scope=openid`,
       `prompt=login`, `max_age=0`, `acr_values=hwk`, `state`, `nonce`,
       `code_challenge`, `code_challenge_method=S256`;
    3. on the `message` (origin = `location.origin`, matching `state`),
       POST `{code, code_verifier, nonce}`;
    4. show the dialog with the exact spec copy and a Copy button
       (`navigator.clipboard.writeText`);
    5. on "I've saved it" or close, clear the DOM node and drop the
       string.
  - **Regenerate:** the same flow, behind the spec's warning ("Your Mac
    will ask for the new password; running backups stop.").
  - **Revoke:** a confirm.
  - **Other states:** `voided` shows "Your password was reset by a
    restore on <date>."; `unavailable` shows the spec's message and no
    button.
  - `Info` lines are shown as returned, escaped.
- [ ] **Step 2: implement the Hub tab.**
  - The header: "People with access: N · passwords: M".
  - One row per person: user, ids, values, status, Revoke (inline
    confirm).
  - "Former members' folders" from `folders` (`former: true`), with
    sizes in binary units or "size unknown".
  - "Last sync" from `last_sync`.
  - The banner: [P2] `PortcullisDoctor.lineFor(instance)`, linking to the
    `lan_only_exposed` finding and its `rebind_port` fix.
  - The enable dialog adds, for every `lan_only` port whose bind is
    `0.0.0.0`, the spec's sentence and a required checkbox.
- [ ] **Step 3: browser check** in the harness (both listeners).
  Take screenshots of:
  - alice's card in each of the four statuses and the shown-once dialog
    (the fresh-auth popup is replaced by the harness's fake verifier);
  - the admin tab with a former-member folder;
  - the enable dialog.

  Check that no hash or password string appears in the DOM after the
  dialog is closed (`document.body.innerHTML` search).
- [ ] **Step 4: verify** with the Hub hygiene command → PASS.
- [ ] **Step 5: commit.**
  `web: file-share password cards (fresh passkey touch, shown once), File sharing tab, LAN-only warnings`.

## Phase 4 — templates

### Task 15: Schema and validator (templates repo)

**Files:**
- `schema/manifest.schema.json`: `person_secret`, `person_id`,
  `username`, `info`, `row_requires_any`, `files[].format`, table
  columns `groups` and `path` + `folder` block + `mount`,
  `render.expand_members`, `runs_as.uid_from|gid_from`,
  `credential_change`;
- `tests/validate.py` (`check_settings` additions, router-less custom,
  `check_sync_copies`);
- `tests/test_validate.py`;
- `CONTRIBUTING.md` ("File sharing templates");
- `.core-ref` (`filesharing`).

**Interfaces:**
- Consumes: contract §13 additions (Task 1). It mirrors Task 3's Hub rules
  one-for-one.
- Produces: `check_sync_copies(templates: List[Template], r: Report) -> None`.
  Every template that ships `bin/portcullis-sync` has a byte-identical
  copy, and the list of such templates is exactly `SYNC_TEMPLATES = {"samba", "timemachine"}`.

- [ ] **Step 1: tests** (`class TestFileSharing`): one test per Task 3
  rule in snake_case (`test_person_secret_rules`, `test_person_id_rules`,
  `test_credential_change_trigger`, `test_data_file_format`,
  `test_table_groups_folder_columns`, `test_runs_as_from`,
  `test_routerless_custom_group_access`), plus:
  - `test_sync_copies_identical`: a one-byte difference → error naming
    both files.
  - `test_lan_only_required_for_person_secret_ports`: a template with a
    `person_secret` must mark every published port `lan_only: true`
    ([P2] `Port.LanOnly`).
  - `test_no_proxy_network_when_routerless`: a router-less template's
    services may not join `portcullis-proxy`.
- [ ] **Step 2: run.** `python3 tests/test_validate.py` → FAIL.
- [ ] **Step 3: implement.**
- [ ] **Step 4: verify.** `python3 tests/test_validate.py` and
  `python3 tests/validate.py` → PASS.
- [ ] **Step 5: commit.** `schema+validate: file-sharing fields, router-less custom, shared sync script`.

### Task 16: `portcullis-sync` and the Time Machine template (templates repo)

**Files:**
- `timemachine/manifest.yaml`: the spec's example, with:
  - project 1's field names;
  - `files: [{name: people, service: timemachine, mount: /portcullis/data, format: tsv}]`;
  - `person_secret.mount.path: /portcullis/secrets`;
  - `info` lines:
    `{label: Connect, value: "smb://{value:connect_address}{port_suffix:TM_SMB:445}/{value:share_prefix}-{user}"}`,
    `{label: Username, value: "{user}"}`;
  - `username.reserved` covering the image's `/etc/passwd`;
  - `auth: {method: custom, group_access: true, access_group: "{{ACCESS_GROUP}}", notes: "No web page: file sharing over SMB. …"}`;
- `timemachine/compose.yml`;
- `timemachine/bin/{start,post,portcullis-sync}`;
- `timemachine/smb.conf.in` is not used: the script renders everything;
- `tests/apps/timemachine.sh`;
- `tests/sync/test_portcullis_sync.sh` (unit tests of the script with
  stubbed `testparm`/`pdbedit`/`smbcontrol`/`smbstatus`/`adduser`/`deluser`/`setpriv`
  on `PATH`);
- `tests/app-images.sh`, `.github/dependabot.yml`;
- `docs` regeneration.

**Compose (Time Machine):**
- **Image:** `mbentley/timemachine:smb-YYYYMMDD@sha256:<index digest>`.
  When this plan was written the newest was `smb-20261102@sha256:7af90ea0a7e934a3510152baddadd868adf4d9408dfaac9cdfe83abf2089ceae`.
  Look it up again at implementation time.
- `entrypoint: ["/portcullis/bin/start"]`, `command: []`.
- **Env, locked:**
  - `CUSTOM_SMB_PROTO: SMB3`, `CUSTOM_SMB_AUTH: ntlmv2-only`,
    `HIDE_SHARES: "yes"`, `SET_PERMISSIONS: "false"`;
  - `EXTERNAL_CONF: /run/portcullis/conf`;
  - `MIMIC_MODEL: ${MIMIC_MODEL:-TimeCapsule8,119}`;
  - `PORTCULLIS_LOCAL_NETWORKS: ${PORTCULLIS_LOCAL_NETWORKS}`;
  - `PORTCULLIS_INSTANCE: ${PORTCULLIS_INSTANCE:-timemachine}`;
  - `PORTCULLIS_SMB_PORT: ${TM_SMB:-445}`.
- **Volumes:**
  - `./templates/timemachine/bin:/portcullis/bin:ro`;
  - the storage path option at `/opt`, or the named volume
    `timemachine-data:/opt` when it is empty.
- `tmpfs`: `/run/samba`, `/run/portcullis`, `/var/lib/samba`,
  `/var/cache/samba`, `/var/log/samba`.
- `ulimits: {nofile: {soft: 65536, hard: 65536}}`.
- `cap_drop: [ALL]`, plus the minimal `cap_add`. Start from `CHOWN`,
  `SETUID`, `SETGID`, `NET_BIND_SERVICE`, `KILL`, `FOWNER`. Remove each
  one the e2e passes without, and record why each remaining one is
  needed in `auth.notes`. Never `DAC_OVERRIDE` or `DAC_READ_SEARCH`
  unless smbd provably needs one (record it here and in the spec, call
  24).
- `security_opt: [no-new-privileges:true]`.
- `networks: [default]` only.

**`portcullis-sync` contract (busybox sh, `set -eu`, identical in both
templates):**
- **Inputs:**
  - `/portcullis/data/people.tsv`;
  - `/portcullis/secrets/*.nt`;
  - env `PORTCULLIS_LOCAL_NETWORKS`, `PORTCULLIS_INSTANCE`,
    `PORTCULLIS_SMB_PORT`, `PORTCULLIS_FLAVOUR` (`samba`|`timemachine`,
    set in each compose).

  It reads the Hub's files as uid/gid 10001 (`setpriv --reuid=10001 --regid=10001 --clear-groups cat …`,
  or busybox `su`/`chpst` when `setpriv` is absent; check each image).
  The hashes go into a 0600 root-owned file under `/run/portcullis`,
  which `pdbedit -i smbpasswd:<file>` imports and the script then
  deletes.
- **Eligible people:** in `people.tsv`, with a `.nt` file, with a name
  that passes the rule. The rule is repeated in the script from env
  `PORTCULLIS_USERNAME_PATTERN`, set in compose to the manifest value;
  the validator checks they are equal. A failing name is reported
  `name_refused`.
- **Unix accounts:** for each eligible person, `addgroup -g <uid> <user>`
  and `adduser -D -H -u <uid> -G <user> -s /bin/false <user>`. Every
  other account with uid ≥ 10000 is removed, along with its passdb
  entry. Its sessions are ended: `smbstatus -p -u <user>` gives the
  PIDs, then `kill -TERM`, and `kill -KILL` after 2 s.
- **Folders:** each per-person directory (`/opt/<user>` or
  `/homes/<user>`) is checked:
  - missing → created `<uid>:<uid>` 0700;
  - owned by another uid → not served, reported `former_account` with
    that uid;
  - right uid, wrong gid or mode → served, reported `wrong_owner`.

  Top-level directories that aren't an eligible person's are reported in
  `folders[]` (`former: true`, `du -sk` with `timeout 20`, else no
  bytes).
- **`smb.conf`:** written completely by the script to a temp file, then
  `mv`:
  - the Global Constraints' hardened `[global]`, plus each flavour's
    compatibility lines (`vfs objects = catia fruit streams_xattr`,
    `fruit:metadata = stream`, `fruit:model = $MIMIC_MODEL`,
    `ea support = yes`, `passdb backend = smbpasswd:/var/lib/samba/private/smbpasswd`,
    `log file = /dev/stdout`);
  - Time Machine: one `[<prefix>-<user>]` per served person, with
    `path = /opt/<user>`, `valid users = <user>`,
    `fruit:time machine = yes`, `fruit:time machine max size = <MiB>M`
    (left out when unlimited), `durable handles = yes`,
    `kernel oplocks = no`, `kernel share modes = no`,
    `posix locking = no`, `guest ok = no`;
  - no stanza when its user list is empty.
- **Verification:** `PORTCULLIS_LOCAL_NETWORKS` empty → exit 3 with
  "Local networks is empty; file sharing is off" (never allow-all). Then
  `testparm -s` is compared per parameter with the expected table. Store
  testparm's normalised spellings in the table (check them against the
  pinned Samba version). Any mismatch → exit 4 naming the parameter.
- **Avahi:** when `/portcullis/avahi` is mounted, it writes
  `portcullis-$PORTCULLIS_INSTANCE.service` atomically:
  - `_smb._tcp` on `$PORTCULLIS_SMB_PORT`;
  - Time Machine adds `_adisk._tcp` with one `dk<n>=adVN=<share>,adVF=0x82`
    per share and `sys=adVF=0x100`, and `_device-info._tcp`
    `model=$MIMIC_MODEL`;
  - no `<host-name>`.

  When unmounted or disabled, it removes the file.
- **Live apply:** `smbcontrol all reload-config` when smbd runs.
- **Locking and output:** everything runs under
  `flock /run/portcullis/sync.lock`. It prints one
  `PORTCULLIS-REPORT {json}` line. Exit 0 = applied.
- **Modes:** `portcullis-sync --boot` (from `post`) and
  `portcullis-sync` (the hook; stdin ignored).

**Time Machine wrapper:**
- `start`:
  1. render `/run/portcullis/conf/<user>.conf` for each eligible person.
     It holds `TM_USERNAME`, `TM_GROUPNAME` = user, `TM_UID` = `TM_GID` =
     uid, `SHARE_NAME`, `VOLUME_SIZE_LIMIT`, `SHARE_PATH=/opt/<user>`,
     and `PASSWORD` = 32 random characters from `/dev/urandom`, never
     stored;
  2. with at least one file, `exec /entrypoint.sh /portcullis/bin/post`;
     with none, `exec /portcullis/bin/post` directly. mbentley's loop
     sources the literal `*.conf` when the directory is empty and the
     shell exits, and the default `timemachine` account must never be
     made.
- `post`:
  1. `portcullis-sync --boot`, which replaces the throwaway passwords by
     importing the real hashes before smbd exists;
  2. copy `/etc/s6` to `/run/portcullis/s6` without `avahi`, `dbus` and
     `nmbd`;
  3. `exec s6-svscan /run/portcullis/s6`.

- [ ] **Step 1: script tests** (`tests/sync/test_portcullis_sync.sh`,
  stubs record their argv):
  - `test_hardened_global`: the rendered `[global]` contains every line
    from Global Constraints. A stub `testparm` that drops
    `server smb encrypt` → exit 4.
  - `test_no_empty_valid_users` (Review Focus 1): nobody eligible → no
    share stanza; a person refused by name → no stanza for them.
  - `test_empty_local_networks_refused` → exit 3, no `smb.conf` written.
  - `test_former_account_not_served` (Review Focus 4): `/opt/alice` owned
    by 10023 while alice is 10000 → no `[TimeMachine-alice]`, and the
    report has `former_account`.
  - `test_removed_person_dropped`: an account present, then its `.nt`
    removed → `deluser`, `pdbedit -x` and the `kill` of the PIDs
    `smbstatus` lists.
  - `test_hash_never_on_argv`: no stub argv contains a 32-hex string.
  - `test_avahi_file`: the mounted dir gets
    `portcullis-tm1.service` with `_adisk._tcp` entries. Unmounted → the
    file is removed.
- [ ] **Step 2: run.** `sh tests/sync/test_portcullis_sync.sh` → FAIL.
- [ ] **Step 3: implement** the script, the wrapper, the compose and the
  manifest.
- [ ] **Step 4: integration test** `tests/apps/timemachine.sh`. There is
  no Hub in templates CI, so the test writes `appfiles/<id>/people/people.tsv`,
  `<secrets>/<id>/share_password/*.nt` (a local directory standing in for
  the volume, mounted the same way) and the env, then
  `docker compose up`. Assert:
  - with nobody: no accounts (`pdbedit -L` empty, no `timemachine` in
    `/etc/passwd`);
  - `smbclient //127.0.0.1/TimeMachine-alice -U alice --password=<pw> -m SMB3 -e` lists;
  - `-m SMB2`, `-m NT1`, `--option='client ntlmv2 auth=no'` and an
    unencrypted session are refused;
  - a client from a network outside a test `PORTCULLIS_LOCAL_NETWORKS`
    (a second Docker network) is refused;
  - an edited `/etc/samba/smb.conf` plus a restart → the container
    exits non-zero;
  - removing alice's `.nt` and running the hook (`docker exec … portcullis-sync`)
    → login fails and an open `smbclient` session is dropped within 10 s;
  - a regenerated hash works and the old one doesn't;
  - the container's effective caps (`/proc/1/status` `CapEff`) contain
    neither `DAC_OVERRIDE` nor `DAC_READ_SEARCH`;
  - `username.reserved` ⊇ every name in the image's `/etc/passwd`.
- [ ] **Step 5: commit.** `timemachine: Time Machine over hardened SMB3 with per-person file-share passwords`.

### Task 17: Samba template (templates repo)

**Files:**
- `samba/manifest.yaml`:
  - the spec's Samba options with project 1's names;
  - `homes`;
  - `shares` with `key_column: name` and these columns:
    - `name`;
    - `folder`: `type: path`, `mount: /shares/{name}`,
      `folder: {access: write, runs_as: {uid_from: uid}, joins_group: template}`;
      its cells are [P2] folder refs, assigned per row through
      `StartAssign`;
    - `readers` and `writers` (`groups`);
  - `row_requires_any: [readers, writers]`, `applies: live`,
    `render: {expand_members: true}`;
  - `info`: Connect `smb://{value:connect_address}{port_suffix:SAMBA_SMB:445}/Home`,
    Username, Shared folders `{rows:shares}`;
  - [P2] `checks` on `homes`: `CheckFilesystem` (`needs: [xattr]`,
    `not: [nfs, cifs, fuse]`); the `folder` column adds `needs: [xattr, acl]`;
- `samba/compose.yml`;
- `samba/bin/{post,portcullis-sync}` (the sync script copied
  byte-identical);
- `tests/apps/samba.sh`;
- dependabot, app-images, docs.

**Compose (Samba):**
- **Image:** `ghcr.io/servercontainers/samba:smbd-only-a<alpine>-s<samba>-r<n>@sha256:<index digest>`.
  When this plan was written the newest was
  `smbd-only-a3.24.3-s4.23.8-r0@sha256:04fb3bd3da742ddb988f621e8c38b0dcbc26e7b4c438c9836abb43d937bc27e6`.
  Look it up again, and check the cosign signature.
- `command: ["/portcullis/bin/post"]`. The image's entrypoint initialises
  with no `ACCOUNT_*` and then execs it.
- **Env:**
  - `SAMBA_CONF_MAP_TO_GUEST: Never`, `AVAHI_DISABLE: "1"`,
    `WSDD2_DISABLE: "1"`, `NETBIOS_DISABLE: "1"`;
  - `PORTCULLIS_FLAVOUR: samba`;
  - the same `PORTCULLIS_*` as Time Machine.
- The other compose keys are as Time Machine.
- The host Avahi dir mounts at `/portcullis/avahi`, **not** the image's
  `/external/avahi`. The image's external mode writes a fixed-name
  `samba.service` with mode `a+rw`: two instances would overwrite each
  other, and spec call 15 requires one `portcullis-<instance>.service`.
  This differs from call 15's "image's built-in mode" and is recorded in
  `auth.notes` and the docs.
- `post`: `portcullis-sync --boot`, then `exec runsvdir -P /container/config/runit`.

**Samba stanzas** (`PORTCULLIS_FLAVOUR=samba`):
- `[Home]`: `path = /homes/%U`, `valid users` = the explicit served list
  (people whose home passed the owner check), `read only = no`,
  `create mask = 0600`, `directory mask = 0700`.
- One `[<name>]` per `row shares`:
  - `path = /shares/<name>`;
  - `valid users` = readers ∪ writers, after the eligible filter;
  - `write list` = writers;
  - `read only = yes`;
  - `force group = pf<gid>`, from a container group created with
    `addgroup -g <gid> pf<gid>` (it is only a name for the gid);
  - `create mask = 0660`, `directory mask = 2770`.
- No stanza with an empty list. No in-container groups other than the
  per-person private groups and `pf<gid>`.

- [ ] **Step 1: script tests** (extend `test_portcullis_sync.sh` with
  `PORTCULLIS_FLAVOUR=samba`):
  - `test_shares_valid_users_and_write_list`;
  - `test_row_without_holders_absent`;
  - `test_home_former_account_excluded`;
  - `test_force_group_from_folder_gid`.
- [ ] **Step 2: run** → FAIL. **Step 3: implement.**
- [ ] **Step 4: integration test** `tests/apps/samba.sh`. It uses the same
  Hub stand-in as Task 16 and a shared-folder directory with gid 60001.
  It runs every `timemachine.sh` assertion that applies, plus:
  - a file written by alice to `//…/Family` is `10000:60001` with mode
    `0660` (`stat` inside the container);
  - a population member in neither group gets `NT_STATUS_ACCESS_DENIED`
    on `Family`;
  - `Home` is served for alice and not for a former account's directory.
- [ ] **Step 5: verify.** Run `python3 tests/validate.py`,
  `python3 tests/test_validate.py`, both `tests/apps/*.sh` and the script
  tests → PASS.
- [ ] **Step 6: commit.** `samba: Samba file sharing (home and shared-folder shares) with per-person file-share passwords`.
- [ ] **Step 7: push and run CI.** Push hub, core and templates
  `filesharing` together.
  - Hub `TestRealTemplates*` must discover both templates.
  - Core and templates CI must be green before Phase 5.

## Phase 5 — e2e, docs, deploy

### Task 18: CI e2e `e2e-filesharing` (core repo)

**Files:**
- `.github/workflows/ci.yml` (job `e2e-filesharing`, modelled on project
  1's `e2e-settings`: the Hub built from the same-named branch, templates
  `filesharing` checked out for `samba` and `timemachine`, `smbclient`
  from the runner's apt, pinned version);
- `tests/e2e/e2e_filesharing.py` (Playwright + CDP virtual
  authenticator, like `e2e_login.py`).

- [ ] **Step 1: write the scenarios.**
  1. Create LLDAP users alice, bob and carol, and the groups
     `users_timemachine`, `office_milan` and `users_samba`. Enable both
     instances through the Hub API. Set Time Machine `size_limit` to
     default 500GiB, with `office_milan` at 10GiB. Add the Samba row
     `Family` (readers `office_milan`, writers `users_samba`) on a [P2]
     shared folder.
  2. **Fresh auth and shown once:**
     - alice, signed in with a passkey, opens My apps and clicks Create
       password. The popup asks for a fresh touch (count the
       authenticator assertions: exactly one more);
     - the dialog shows the password;
     - a second POST with the same code → 403.
  3. **SMB works:** `smbclient //…/TimeMachine-alice -m SMB3 -e` with
     that password lists. `fruit:time machine max size` is 10240M
     (`testparm` in the container).
  4. **Removal through the Hub:** with alice's `smbclient` session open,
     remove alice from `users_timemachine` through the Hub API. Then:
     - within 10 s the session is dropped and a new login fails;
     - the audit has `credential.revoke_leave`.
  5. **Removal directly in LLDAP:** bob holds a Samba password. Remove
     him with LLDAP's GraphQL. Within 75 s his login fails.
  6. **Restore voids:** back up and restore Samba. Carol's password no
     longer works, and her My apps card says "reset by a restore".
  7. **Core restore:** run `./portcullis backup` and `./portcullis restore`
     → every credential is voided (the epoch is missing after the volume
     was emptied).
  8. **Secrets stay put:** the instance backup archive and the core
     backup contain no hash. `grep` both archives for each hash recorded
     during the run (the test reads them from the secrets volume before
     voiding).
  9. **No hash anywhere visible:** `docker inspect` of both containers
     and the Hub's logs contain no hash.
- [ ] **Step 2:** run in CI on `filesharing` → green. Commit
  `ci: e2e file sharing (fresh auth, SMB3 login, revocation SLAs, restore voids)`.

### Task 19: Docs (docs repo)

**Files:**
- `operations/file-sharing.md` (new): setup, Local networks, Bonjour
  opt-in with the username warning, the macOS and Windows steps, why
  people must be managed through the Hub (60 s for LLDAP-direct edits);
- `operations/backups.md`: `hub_secrets` is never backed up, and restores
  void credentials;
- `operations/hardening.md`: the SMB settings, `hosts allow` as defence
  in depth (the userland proxy and IPv6 case: verify on the test server
  whether source addresses are preserved for published IPv4 ports, and
  write down the result), the cap set;
- `operations/hub.md`: My apps passwords, the File sharing tab;
- `architecture.md`;
- `operations/testing.md`;
- generated app pages for `samba` and `timemachine`.

- [ ] Write the pages, run `zensical build --strict --clean`, and commit.

### Task 20: Deploy and live check

- [ ] **Step 1:** deploy to the test server (`./portcullis upgrade`).
- [ ] **Step 2: live checks** on a Mac, with throwaway users and
  instances, cleaned up afterwards:
  1. create a Time Machine password through people.<domain>, with a
     passkey touch;
  2. run a backup over encrypted SMB3 (check `smbstatus` shows
     encryption) and record the Wi-Fi throughput (spec open question 5);
  3. check the 10 GiB limit is honoured (Time Machine prunes);
  4. turn on discovery through the host's Avahi
     (`/etc/avahi/services`): Finder shows the server and Time Machine
     lists the disk;
  5. Samba: Finder → Connect to Server `smb://…/Home` and the Family
     share;
  6. remove the test user from the group through the Hub: the running
     backup disconnects within seconds.
- [ ] **Step 3:** report.

## Project 2 names this plan depends on

These come from project 2's "Interfaces for later plans"
(`docs/superpowers/plans/2026-11-02-shared-folders-doctor.md`).

**Used as defined:**
1. `templates.Option.Folder *FolderSpec`, `FolderSpec{Access, RunsAs *RunsAs, JoinsGroup string; MustOwn bool}`,
   `JoinTemplate`, `FolderWrite`.
2. `RunsAs{UID, GID *int; UIDEnv, GIDEnv, UIDFrom, GIDFrom string}`.
   `UIDFrom`/`GIDFrom` are reserved for this project; Task 3 removes the
   refusal and requires them to name a `person_id` option.
3. `templates.Option.Checks []Check`, `Check{Kind, Reason; Needs, Not; Min}`,
   `CheckFilesystem`, `CheckExclusive`, `CheckRequiresGroupValue`.
4. `templates.Port.LanOnly` (yaml `lan_only`).
5. `FolderGIDVar(key)` / `PORTCULLIS_FOLDER_GID_<KEY>`; `ReservedVar`
   covering `PORTCULLIS_FOLDER_`; `TypeFolder` stays reserved and unused.
6. `settings.FolderRefPrefix`, `ParseFolderRef`, `ErrFolderRef`.
7. `FolderGIDMin = 60000`, `FolderGIDMax = 60999`, `state.Folder.GID`,
   `AppState.Folders`, `hubFolders` (the `FolderSource`).
8. `FolderUse`, `AssignRequest`, `PreviewAssign`, `StartAssign`,
   `folderUsesLocked`, and the 409 `SaveSettings` gives for `folder:`
   value changes.
9. `PathUsage` with `Folder, Subpath, JoinsGroup, Source`, and
   `OwnerKnown = false` for `uid_from`.
10. Local networks: `DefaultLocalNetworks`, `(*Hub).LocalNetworks()`,
    `LocalNetworksView()`, `SetLocalNetworks(cidrs, actor)` (audited
    `settings.local_networks`), `AppState.LocalNetworks`, `IsLocal`.
11. Doctor: `doctor.Check{Kind() string; Run(in *Inputs) []Finding}`,
    `doctor.Register`, `doctor.Fingerprint`, `Inputs`,
    `Finding{FP, Kind, Severity, Title, Why, Fix, Instances, Folders, Paths, Class, FixKind, Steps, Link, …}`,
    `Problem`/`Warning`/`Info`, `FixClass` `one_click`/`explain`/`link`,
    the built-in kind `lan_only_exposed` and its `rebind_port` fixer.
12. Hub doctor plumbing: `doctorInputs`, `scanTargetsLocked`/`ScanTarget`,
    `Fixer{Kind, Preview, Apply}`, `RegisterFixer`, `FixPlan`, `runFixer`.
13. `folderfix.Options.Children`, `Report.Children []ChildOwner{Name; UID, GID int; Entries, Foreign int64}`.
14. UI: `window.PortcullisDoctor.lineFor(instance)`.

**Added by this plan to project 2's code** (the controller confirms with
project 2's owner):
- `FolderUse.Row` (Task 10): table rows as folder uses.
- `folderfix.Target.ChildOwners` (Task 11): a non-recursive chown/chmod
  of named first-level children. Also `ChildOwner.Mode`, if the report
  lacks it.
- `doctor.Inputs.FileSharing []FileSharingIn` (Task 11).
- `gid_from` options are excluded from folder refs and the
  setgid/ACL/mask planner (Task 11).
- The spec's `runs_as: {gid: folder}` is replaced by
  `{uid_from: uid}` + `joins_group: template` (Task 1). Project 2's
  numeric `RunsAs.GID` can't express it.
