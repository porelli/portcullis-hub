# Shared Folders and the Doctor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The admin defines a shared folder once and picks the app
instances that use it. The Hub keeps its ownership consistent (one gid
per folder, setgid, default ACLs) through a started helper container, and
a doctor checks the whole setup, explains findings by severity and offers
previewed, audited one-click fixes where they are safe.

**Architecture:**
- **Manifest.** Project 1's reserved `folder` block and `checks` on
  `type: path` options become typed (`templates.FolderSpec`,
  `templates.Check`). Ports gain `lan_only`. A path value may be
  `folder:<id>[/<subpath>]`.
- **Fixer.** A new pure-Go package `internal/folderfix` walks one tree
  (scan, snapshot, apply, restore), with POSIX ACLs encoded directly on
  the `system.posix_acl_*` xattrs through `golang.org/x/sys/unix`. It runs
  only as the hidden subcommand `hub folderfix …` inside a **started**
  helper container made from the Hub's own image (`docker.RunHelper`).
- **Hub.** `internal/hub/folders*.go` holds the folder definitions in
  `state.yaml`, the gid allocator, the path rules, the assignment plan
  (preview → plan hash → async apply: stop → snapshot → apply → verify →
  write values → regenerate → start) and undo.
- **Doctor.** A new pure package `internal/doctor` holds the finding
  model, fingerprints, mutes and a registry of checks. The Hub gathers the
  inputs (state, manifests, overrides, ports, project 1 values, cached disk
  scans, local networks) and registers its fixes (`internal/hub/doctor*.go`).
- **UI.** Settings → Shared folders and Local networks, a Doctor tab with
  a badge, the folder picker in project 1's path option, and a doctor line
  on each app's detail.

**Tech Stack:**
- Hub: Go, gopkg.in/yaml.v3, moby client/api, project 1's
  `internal/settings`. `golang.org/x/sys` becomes a direct dependency
  (`unix.Lgetxattr`/`Fsetxattr`, `Fstatfs`, `Openat`, `Fchownat`). No ACL
  library: none is maintained without cgo, and the xattr format is a
  4-byte header plus 8-byte entries.
- Templates: JSON Schema + `tests/validate.py`.
- Core: CI e2e (Python + the Hub API).
- Docs: zensical.

**Spec:** `docs/superpowers/specs/2026-11-02-shared-folders-doctor-design.md` (hub repo)

**Builds on:** project 1's plan
`docs/superpowers/plans/pending/2026-11-02-app-settings-panel.md`, section
"Interfaces for later plans". This plan uses its names exactly
(`templates.Option`, `templates.ReservedFeature`, `settings.Registry`,
`settings.Mounter.HostPath`, `hub.FolderSource`/`SetFolderSource`,
`(*Hub).PathUsages() []PathUsage`, `Option.Checks`, `writes_as`/`ResolveOwner`,
`state.InstanceSettings`, `populationLocked`, `People.Membership`).

**Bases and start.**
- This plan **starts after project 1 (`settings`) has landed**: hub, core
  and docs `main` contain the `settings` merge, and templates `new-apps`
  (or `main`, if `new-apps` has landed there) contains templates
  `settings`. Do not start any task before that.
- For reference, the pre-project-1 HEADs are hub `main` `bfbb3d4`, core
  `main` `c451278`, docs `main` `2c4d670`, templates `new-apps` `78db191`.
  Line numbers quoted from today's code (`override.go` ~40, `useroverride.go`
  ~72–110, `backup.go` ~39–56, `volumes.go` ~99–143) may have moved under
  project 1; find the code by name.

**Branches and CI order.**
- Every repo works on a branch named **`folders`**, cut from the bases
  above.
- Hub CI clones the same-named templates and core branches
  (`TestRealTemplates*`, `TestCore*Complete`). Core CI builds the Hub from
  its same-named branch. Templates CI reads `.core-ref`: set it to
  `folders` on the branch and back to `main` before merging.
- Work order: contract (T1) → Hub (T2–T14) → templates (T15) → core e2e
  (T16) → docs (T17) → deploy (T18).
- Hub `TestRealTemplates*` stays green until T15 (templates without a
  `folder` block stay valid). Push hub, templates and core `folders`
  together at the end of T15.
- Merge order: docs → Hub → core → templates.

## Global Constraints

- **No migration or back-compat code.** There are no installs.
- **Contract first:** `portcullis-docs/docs/guides/integration-contracts.md`
  (§3/§13 manifest, §6 Docker access, a new §14 Shared folders and the
  doctor). Template contract v3 gains optional fields: a MINOR bump.
- **Folder id:** `^[a-z][a-z0-9-]{0,30}$`, immutable. Name ≤ 64 chars,
  description ≤ 500, no control characters.
- **Path value form:** `folder:<id>` or `folder:<id>/<subpath>`. The
  subpath is relative, `path.Clean`-equal to itself, has no `..`, no `:`,
  no control characters, ≤ 255 bytes. It is created by the apply if
  missing.
- **Folder host path:**
  - absolute, `path.Clean`ed (a trailing `/` or `//` is normalised before
    any comparison), no `..`, `:`, `$` or control characters;
  - strictly under one of the Hub's bind roots (`h.bindRoots`), never a
    bind root itself;
  - not a system or sensitive path (`systemRoots`, `sensitiveHostPaths`),
    not at, above or under the core checkout (`ProjectHostDir`);
  - no symlink in any component below the bind root (the probe, Task 6);
  - no overlap with another shared folder (neither at nor under the other).
- **Filesystems:** Hub-managed folders are refused on `nfs`, `cifs`/`smb2`,
  `fuse`, `overlay`, `tmpfs` (statfs magic, Task 4).
- **Group per folder:**
  - allocated gid range **60000–60999**, lowest free first, stable,
    **never reused** (`state.FolderGIDs` keeps every gid ever used);
  - adopted gid: typed number, ≥ 1000, ≠ 65534, outside 60000–60999, not
    used by another folder; the answer carries the warning "anything
    mounted with gid N becomes reachable by this folder's apps";
  - the group is only a number: no `/etc/group`, no LLDAP group, no group
    in containers. The preview says "gid 60001 is allocated for this
    folder (shown as *Family photos*)".
- **Variables:** reserved prefix `PORTCULLIS_FOLDER_` (`templates.ReservedVar`).
  For every option whose value is a folder ref the env carries
  `PORTCULLIS_FOLDER_GID_<UPPER(key)>` = the folder gid, and
  `PORTCULLIS_FOLDER_UID_<UPPER(key)>` = the `must_own` app's uid when the
  folder has one.
- **On disk ("consistent ownership"):**
  - group owner = folder gid; directories `g+rwx` + setgid; regular files
    `g+rw` when any use writes, `g+r` when all only read (`+x` only where
    the file's user bits have `x`);
  - on every directory: access and default ACL entries for the owning
    group `rwx`, mask `rwx`;
  - previous owning groups (and under `must_own`, previous owner uids)
    keep their bits through named ACL entries, on directories in the
    default ACL too;
  - before the mask is raised, every existing named entry is clamped to
    entry ∧ old mask (nobody's effective rights change);
  - file owners are left alone except under `must_own`; "others" bits are
    never changed; nothing is ever removed.
- **Walk rules:** never leave the root's device (a directory on another
  device is not entered, not changed, reported); symlinks never followed,
  never changed; regular files with `nlink > 1` skipped and reported;
  devices, sockets, FIFOs skipped and reported. Every change goes through
  an fd opened `O_NOFOLLOW` relative to its parent's fd (`Openat`).
- **Fixer helper** (started; contract §6 change):
  - image: the Hub's own image by **image ID** (`sha256:…`), found by
    inspecting the Hub's own container; `HUB_FIXER_IMAGE` (must contain
    `@sha256:`) overrides it for development. Not found → every folder
    disk operation answers 503 "the Hub can't find its own image".
  - entrypoint `["hub", "folderfix", <mode>, <flags>…]`, built from a Go
    struct, never a shell;
  - user `0:0`, `network: none`, `no-new-privileges`, read-only rootfs,
    `CapDrop: ALL`, pids 16, memory 256 MiB, label `LabelHelper` =
    `folder:<id>`;
  - one bind mount of the folder at `/folder` (read-only for `scan` and
    `snapshot`), plus anonymous scratch volumes `/out` / `/in` only where
    the mode needs them;
  - capabilities: `scan`, `snapshot`, `probe` → `DAC_READ_SEARCH`;
    `apply`, `restore` → `CHOWN`, `FOWNER`, `FSETID`, `DAC_OVERRIDE`,
    `DAC_READ_SEARCH`. `FSETID` is beyond the spec's list: without it the
    kernel clears setgid on a `chmod` by a process outside the entry's
    group, and `chown` clears setuid/setgid bits the fix must keep;
  - the report is the single JSON line on stdout (≤ 256 KiB); the
    snapshot comes out of `/out` through the archive endpoint.
- **Snapshots:** `<data>/folder-snapshots/<folder>/<YYYYMMDDTHHMMSSZ>.ndjson.gz`
  plus `<same>.sha256`, files 0600, dirs 0700, the last **3** kept.
- **Severity:** `problem` | `warning` | `info`. Fingerprint =
  first 16 hex of sha256(kind `\x00` sorted subjects). A mute stores the
  finding's inputs digest; the finding reappears when the digest changes.
- **Local networks** default: `10.0.0.0/8`, `172.16.0.0/12`,
  `192.168.0.0/16`, `fc00::/7`, `100.64.0.0/10`. Loopback (`127.0.0.0/8`,
  `::1`) always counts as local. `/0` prefixes are refused. ≤ 64 entries.
- **Admin-only, audited, Hub listener only.** Audit actions:
  `folder.create`, `folder.update`, `folder.delete`, `folder.assign`,
  `folder.apply`, `doctor.fix`, `doctor.mute`, `doctor.unmute`,
  `settings.local_networks`. Audit detail holds counts and ids, never file
  lists. The people listener gets no new route.
- **No silent changes:** nothing on disk changes without a preview the
  admin applied; the doctor never fixes drift by itself.
- **Never** a host shell, SSH, `group_add` in the custom override, or a
  Hub write to the custom override.
- **Locks:** `Hub.mu` is never held across Docker calls. Order: folder
  lock (`folderLock(id)`, try-lock → 409 busy) → `lockApp` for each
  affected instance in sorted id order → restarts. One disk scan at a time
  (`scanMu`, try-lock → 409).
- **Async ops:** 202 `{op_id, op, poll}`, outcome in an op record.
  Folder ops use the op key `_folder.<id>`, doctor scans `_doctor`
  (instance ids can't start with `_` or contain `.`); rebind uses the
  instance's own record.
- **Hub hygiene:** `go vet ./... && go test -race ./... && gofmt -l .`
  after every task; update the CLAUDE.md layout/rules rows a task changes.
- **Frontend:** vanilla JS, `escapeHtml` everywhere, data-* attributes and
  delegated listeners, new assets on the `//go:embed` line.

## Review Focus

1. **A folder path spelled differently or reaching outside through a
   symlink:** `/srv/photos/`, `/srv//photos`, or `/srv/photos` where
   `photos` (or a component below the bind root) is a symlink to `/etc`.
   - Docker resolves bind sources on the host, so a symlink would mount
     and chown its target.
   - Expected: paths are cleaned before every comparison, overlap and
     doctor grouping; the probe refuses any symlinked component; every
     fixer run checks that `/folder`'s device and inode equal the
     probe's, or exits without changing anything.
   - Pinned in Task 6 (`TestFolderPathSymlinkRefused`,
     `TestFolderPathNormalised`) and Task 4 (`TestApplyRefusesWrongRoot`).
2. **The Hub restarted or killed in the middle of an apply.**
   - Expected: the helper is swept at start, the folder's op record is
     marked interrupted and names the snapshot, the setting values are
     unchanged, the apps the apply stopped are started again with their
     old configuration, and the doctor shows the drift with an undo.
   - Pinned in Task 8 (`TestInterruptedApplyRestartsApps`).
3. **Something else touching an affected app during an apply:** an
   enable, restart, settings save, backup or a second assignment.
   - Expected: 409 busy for the whole op; nothing writes with the old
     ownership in between.
   - Pinned in Task 8 (`TestAssignHoldsLocks`).
4. **Bind address spellings in the exposure check:** `::`, `[::]`,
   `::ffff:192.168.1.10`, `0.0.0.0`, a custom-override port `"8445:445"`
   with no address, a host-networking port.
   - Expected: addresses are unmapped (`netip.Addr.Unmap`) before every
     comparison; no address means all interfaces; host networking is a
     Warning.
   - Pinned in Task 10 (`TestExposureAddressForms`).
5. **A tree with entries the fixer must not touch, or must keep
   reachable:** an existing named ACL entry under a narrower mask, a
   file hard-linked from outside, a nested mount, a symlink to `/`, a
   setuid file, and `must_own` with several previous owners.
   - Expected: effective rights of every existing principal are the same
     or wider after apply; skipped entries are counted and listed; the
     setuid bit survives.
   - Pinned in Task 4 (`TestRootApplyKeepsAccess`, build tag `fixerroot`).

---

## Phase 1 — contract

### Task 1: Contract (docs repo)

**Files:** `portcullis-docs/docs/guides/integration-contracts.md`
(§1, §3/§13, §6, §11.5–11.6, new §14), `docs/guides/manifest-reference.md`
(the `folder`, `checks` and `lan_only` fields only).

- [ ] **Step 1: §13 (project 1's Settings section), `path` type.**
  - The `folder` block: `access` (required, `read|write`), `runs_as`
    (required: `{uid, gid}` numbers, or `{uid_env, gid_env}` naming the
    env of an instance `int` option, or the reserved `uid_from`/`gid_from`
    of project 3; one source per id), `joins_group` (`group_add` default |
    `gid_env` | `template`), `must_own` (bool, writers only).
  - A `folder` block replaces `mode`, `needs` and `writes_as` on that
    option (they are refused together).
  - `access: read` always mounts `:ro` (shared folder or custom path).
  - The value form `folder:<id>[/<subpath>]` and its rules (Global
    Constraints).
  - `checks`: the catalog `filesystem` (`needs: [xattr, acl]`, `not:
    [nfs, cifs, fuse]`), `exclusive`, `free_space` (`min: <size>`),
    `requires_group_value`, each with a required one-line `reason`. Which
    option kinds take which check (Task 2).
  - `ports[].lan_only: true`.
  - Reserved variables: the `PORTCULLIS_FOLDER_` prefix and the two
    names from Global Constraints.
  - Copy the spec's jellyfin and samba examples (samba with
    `runs_as: {uid_from: <person_id option>, gid: …}` marked "project 3").
- [ ] **Step 2: §6.** Replace "The Hub never starts a helper container"
  with two helper kinds: the never-started volume helper (unchanged) and
  the started **folder fixer** (Global Constraints, every field). State
  that the proxy's `CONTAINERS` + `POST` already cover
  create/start/wait/kill/logs and no flag changes.
- [ ] **Step 3: §14 Shared folders and the doctor.**
  - 14.1 Definitions and gids; 14.2 the on-disk model and walk rules;
    14.3 assignment (call 19) and apply (call 9) with lock order and
    downtime; 14.4 snapshots and undo; 14.5 the doctor: severities,
    fingerprints, mutes, config vs disk checks and their schedule, scan
    caps and "partial"; 14.6 fix classes (call 11); 14.7 local networks
    and the exposure rules (call 13); 14.8 API routes and audit actions
    (Task 13's list, verbatim).
- [ ] **Step 4: §11.5/§11.6.** Backups never include shared-folder
  contents (host data). Restore clears setting values that name a missing
  folder, with a warning; restore into a new id keeps folder refs.
- [ ] **Step 5: manifest reference.** Add the three fields with the
  jellyfin example.
- [ ] **Step 6: verify and commit.** `zensical build --strict --clean` →
  no warnings. Commit on `folders`:
  `contracts: shared folders, folder fixer helper, doctor (§14)`.

## Phase 2 — Hub foundations

### Task 2: Manifest: folder block, checks, lan_only, folder refs

**Files:**
- Modify: `internal/templates/settings.go` (types, `ReservedFeature`,
  `ValidateSettingsSpec`), `internal/templates/manifest.go` (`Port`),
  `internal/templates/instance.go` (`ReservedVar`),
  `internal/settings/kinds_path.go` (folder refs).
- Create: `internal/templates/folders.go`, `internal/templates/folders_test.go`,
  `internal/settings/folderref_test.go`.

**Interfaces:**
- Consumes: project 1 `templates.Option`, `ValidateSettingsSpec`,
  `ReservedFeature`, `Option.EnvName`, `settings.Kind`/`Mounter`.
- Produces:
```go
// templates
type FolderSpec struct {
    Access     string  `yaml:"access" json:"access"`           // FolderRead | FolderWrite
    RunsAs     *RunsAs `yaml:"runs_as" json:"runs_as"`
    JoinsGroup string  `yaml:"joins_group" json:"joins_group"` // "" = JoinGroupAdd
    MustOwn    bool    `yaml:"must_own" json:"must_own"`
}
type RunsAs struct {
    UID     *int   `yaml:"uid" json:"uid,omitempty"`
    GID     *int   `yaml:"gid" json:"gid,omitempty"`
    UIDEnv  string `yaml:"uid_env" json:"uid_env,omitempty"`
    GIDEnv  string `yaml:"gid_env" json:"gid_env,omitempty"`
    UIDFrom string `yaml:"uid_from" json:"uid_from,omitempty"` // reserved: project 3
    GIDFrom string `yaml:"gid_from" json:"gid_from,omitempty"` // reserved: project 3
}
type Check struct {
    Kind   string   `yaml:"kind" json:"kind"`
    Reason string   `yaml:"reason" json:"reason"`
    Needs  []string `yaml:"needs" json:"needs,omitempty"` // filesystem: xattr, acl
    Not    []string `yaml:"not" json:"not,omitempty"`     // filesystem: nfs, cifs, fuse
    Min    string   `yaml:"min" json:"min,omitempty"`     // free_space: a size ("500GiB")
}
const (FolderRead = "read"; FolderWrite = "write"
    JoinGroupAdd = "group_add"; JoinGIDEnv = "gid_env"; JoinTemplate = "template"
    CheckFilesystem = "filesystem"; CheckExclusive = "exclusive"; CheckFreeSpace = "free_space"
    CheckRequiresGroupValue = "requires_group_value"; CheckLANOnly = "lan_only")
var CheckKinds = map[string]bool{ /* the five above */ }
func (o *Option) FolderAccess() string // o.Folder.Access, or "" without a block
func (f *FolderSpec) Join() string     // JoinsGroup or JoinGroupAdd
func FolderGIDVar(key string) string   // "PORTCULLIS_FOLDER_GID_" + strings.ToUpper(key)
func FolderUIDVar(key string) string   // "PORTCULLIS_FOLDER_UID_" + strings.ToUpper(key)
// Option.Folder becomes *FolderSpec (yaml "folder"), Option.Checks []Check (yaml "checks").
// Port gains LanOnly bool `yaml:"lan_only" json:"lan_only"`.
// settings
const FolderRefPrefix = "folder:"
var FolderIDRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)
// ParseFolderRef: ok=false for a value without the prefix; err for a malformed ref.
func ParseFolderRef(v string) (id, sub string, ok bool, err error)
var ErrFolderRef = errors.New("a shared folder value is resolved by the Hub")
```
- `TypeFolder` stays reserved and refused (this project adds no type:
  shared folders are `path` values). `ReservedFeature` stops refusing
  `folder` and `checks`, and refuses `runs_as.uid_from`/`gid_from` with
  "file sharing (project 3)".

- [ ] **Step 1: tests** in `folders_test.go`, each fixture refused with a
  message naming the option:
  - `TestFolderOnlyOnInstancePath`: `folder` on a `string` option, or on
    a `path` with `scope: person` → refused.
  - `TestFolderAccessAndRunsAsRequired`: missing `access`, `access: rw`,
    missing `runs_as` → refused; `{access: read, runs_as: {uid: 1000, gid: 1000}}` → OK.
  - `TestRunsAsOneSourcePerID`: `{uid: 1, uid_env: PUID}` and `{gid: 1}`
    (no uid source) → refused.
  - `TestRunsAsEnvNamesOption`: `uid_env: PUID` with no instance `int`
    option whose `EnvName()` is `PUID` → refused; `uid_env: PORTCULLIS_X`
    → refused (reserved).
  - `TestRunsAsMatchesComposeUser`: compose `user: "1000:1000"` with
    `runs_as: {uid: 1000, gid: 100}` → refused; `user: "${PUID:-1000}:${PGID:-1000}"`
    with `{uid_env: PUID, gid_env: PGID}` → OK, with `{uid: 1000, gid: 1000}`
    → refused; `user: www-data` next to a folder block → refused ("give
    numbers in compose `user:`").
  - `TestJoinsGroup`: `gid_env` without `runs_as.gid_env` → refused;
    `joins_group: sudo` → refused.
  - `TestMustOwnWritersOnly`: `must_own` with `access: read` → refused.
  - `TestFolderReplacesModeNeedsWritesAs`: `folder` together with any of
    `mode`, `needs`, `writes_as` → refused with the hint "folder.access
    and folder.runs_as replace them".
  - `TestSameEnvSameRunsAs` (call 23): two folder options on one service
    naming `gid_env: PGID`, one `joins_group: gid_env` and one
    `group_add` → refused; identical blocks → OK.
  - `TestUIDFromReserved`: `runs_as: {uid_from: person_uid, gid: 0}` →
    refused "file sharing (project 3)".
  - `TestChecksCatalog`:
    - unknown kind `quota` → refused, listing the catalog;
    - missing `reason`, or one over 200 chars or with a newline → refused;
    - `filesystem` with `needs: [acl, xattr]`, `not: [nfs]` on a folder
      option → OK; `needs: [posix]` → refused; `filesystem` on a path
      option without `folder` → refused;
    - `exclusive` on `access: read` → refused;
    - `free_space` `min: "500GiB"` → OK, `"lots"` → refused;
    - `requires_group_value` on an instance option → refused, on a
      `scope: person` option → OK;
    - `kind: lan_only` in `checks` → refused, hint "set lan_only: true on
      the port".
  - `TestReservedVarFolderPrefix`: `ReservedVar("PORTCULLIS_FOLDER_GID_X")`
    is true.
  - `TestLanOnlyPort`: `lan_only: true` parses into `Port.LanOnly`.
  - In `folderref_test.go`, `TestParseFolderRef`: `folder:photos` →
    `("photos", "", true, nil)`; `folder:media/movies/hd` → sub
    `movies/hd`; `folder:Photos`, `folder:p/../x`, `folder:p//x`,
    `folder:p/`, `folder:p/a:b`, `folder:` → errors; `/srv/x` → ok false.
    `TestPathKindAcceptsFolderRef`: the path kind's `Parse` returns the
    ref unchanged; `HostPath` of a ref returns `ErrFolderRef`; a plain
    path still behaves as in project 1.
- [ ] **Step 2: run.** `go test -race ./internal/templates/ ./internal/settings/ -run 'TestFolder|TestRunsAs|TestJoinsGroup|TestMustOwn|TestSameEnv|TestUIDFrom|TestChecks|TestReservedVarFolder|TestLanOnly|TestParseFolderRef|TestPathKindAccepts'`
  → FAIL.
- [ ] **Step 3: implement** in `folders.go` (`validateFolderOption`,
  `validateChecks`, called from `ValidateSettingsSpec`). Compose `user:`
  is read from the yaml.v3-decoded compose; the `${NAME:-n}` form is
  matched with the existing `iter_var_refs`-equivalent helper in
  `templates`. `free_space.min` is parsed with
  `units.RAMInBytes`. Update project 1's `TestReservedTypesRefused`: a
  `folder:` block is no longer refused.
- [ ] **Step 4: verify.** `go vet ./... && go test -race ./... && gofmt -l .`
  → PASS.
- [ ] **Step 5: commit.** `templates: folder block, check catalog, lan_only ports, folder refs`.

### Task 3: `folderfix` — ACL codec and access evaluation

**Files:**
- Create: `internal/folderfix/acl.go`, `internal/folderfix/access.go`,
  `internal/folderfix/acl_test.go`, `internal/folderfix/access_test.go`.
- Modify: `go.mod` (`golang.org/x/sys` direct).

**Interfaces:**
- Produces:
```go
type Perm uint8 // 4=r 2=w 1=x
const (TagUserObj = 0x01; TagUser = 0x02; TagGroupObj = 0x04; TagGroup = 0x08; TagMask = 0x10; TagOther = 0x20)
type Entry struct{ Tag uint16; ID uint32; Perm Perm } // ID only for TagUser/TagGroup
type ACL []Entry // canonical order: tag, then id
const XattrAccess, XattrDefault = "system.posix_acl_access", "system.posix_acl_default"
func DecodeACL(b []byte) (ACL, error) // version 2 header, 8-byte entries
func (a ACL) Encode() []byte
func FromMode(mode uint32) ACL         // the minimal ACL a mode implies
func (a ACL) Mask() (Perm, bool)
func (a ACL) Clamp() ACL               // every TagUser/TagGroup entry ∧ mask (call 21)
func (a ACL) Set(tag uint16, id uint32, p Perm) ACL
func (a ACL) RecalcMask() ACL          // mask = union of the group class
type Principal struct{ UID int; GIDs []int; Write bool; Name string }
type Stat struct{ UID, GID int; Mode uint32; Dir bool; Access ACL } // Access nil = FromMode
func Allowed(s Stat, p Principal, want Perm) bool // the POSIX ACL check algorithm (acl(5)); uid 0 = always
```

- [ ] **Step 1: tests.**
  - `TestACLRoundTrip`: a fixed byte sample (the bytes `setfacl -m
    u:1000:rw,g:60001:rwx,m::rwx` produces, written as a Go literal)
    decodes to the expected entries and re-encodes byte-identical;
    a truncated buffer and version 1 → errors.
  - `TestFromModeAndMask`: `0640` → user_obj rw, group_obj r, other 0, no
    mask; `RecalcMask` on `{group_obj r, group 1000 rw}` → mask rw.
  - `TestClampKeepsEffective`: `{user 1000 rwx, mask r}` → after `Clamp`
    the entry is r; `Allowed` for uid 1000 is identical before and after
    for r, w, x.
  - `TestAllowed`: owner, named user, owning group, named group with
    mask, other, uid 0; a dir needs `x` with `r` for read and `w|x` for
    write (`want` is checked by the caller per entry type).
- [ ] **Step 2: run.** `go test -race ./internal/folderfix/` → FAIL.
- [ ] **Step 3: implement.** Little-endian; refuse unknown tags; sort on
  encode.
- [ ] **Step 4: verify.** `go test -race ./internal/folderfix/` → PASS,
  plus vet and gofmt.
- [ ] **Step 5: commit.** `folderfix: POSIX ACL xattr codec and access evaluation`.

### Task 4: `folderfix` — walk, scan, snapshot, apply, restore, `hub folderfix`

**Files:**
- Create: `internal/folderfix/{walk,scan,plan,apply,snapshot,restore,fs_linux,fs_other,cli}.go`,
  `internal/folderfix/scan_test.go`, `internal/folderfix/root_test.go`
  (build tag `fixerroot`, Linux only).
- Modify: `cmd/hub/main.go` (`if len(os.Args) > 1 && os.Args[1] == "folderfix" { os.Exit(folderfix.Main(os.Args[2:], os.Stdout, os.Stderr)) }`
  before anything else), `.github/workflows/build.yml` (a root fixer
  step), `CLAUDE.md` (layout row).

**Interfaces:**
- Consumes: Task 3.
- Produces:
```go
type Target struct {
    GID      int    // folder gid (0 = scan without an expected state)
    Files    string // "rw" | "r"
    OwnerUID *int   // must_own
    Mkdir    []string // relative subpaths to create (apply)
}
type Options struct {
    Root       string // "/folder"
    ExpectDev  uint64 // 0 = unchecked; else the root's st_dev and st_ino must match (Review Focus 1)
    ExpectIno  uint64
    Target     Target
    Principals []Principal
    Children   bool // per first-level child owner counts (project 3)
    MaxEntries int64
    MaxTime    time.Duration
}
type Count struct{ N int64 `json:"n"`; Sample []string `json:"sample,omitempty"` } // ≤ 20 relative paths
type OwnerCount struct{ UID, GID int; N int64 }
type PrincipalAccess struct{ Name string; UID int; CantRead, CantWrite Count }
type Conformance struct{ Group, Setgid, DefaultACL, Mode, Owner Count } // entries that differ from Target
type PlanCounts struct {
    ChangeGroup, AddSetgid, AddDefaultACL, ChangeOwner, Narrowed Count
    KeepGroup map[int]int64 `json:"keep_group"` // previous gid → entries given a named entry
    KeepUser  map[int]int64 `json:"keep_user"`
    LoseAccess Count // only without ACL support: entries whose previous group/owner would lose bits
}
type ChildOwner struct{ Name string; UID, GID int; Entries, Foreign int64 } // Foreign: entries not owned by UID
type Report struct {
    Version int; Mode string; Root string
    Dev, Ino uint64
    FSType string; ACL, Xattr bool
    Entries, Dirs, Files int64
    Partial bool; PartialReason string // "entries" | "time"
    Owners []OwnerCount // top 10 by N
    HardLinks, MountPoints, Specials, Symlinks Count
    Principals []PrincipalAccess
    Expected *Conformance // when Target.GID != 0
    Plan *PlanCounts      // when Target.GID != 0
    Children []ChildOwner
    FreeBytes, TotalBytes uint64
    Errors []string // ≤ 20, clipped to 200 runes each
    Changed int64   // apply/restore
    Elapsed time.Duration
}
func Scan(o Options) (*Report, error)
func WriteSnapshot(o Options, w io.Writer) (*Report, error) // gzip NDJSON of every entry Apply would change
func Apply(o Options, expect int64) (*Report, error)        // re-plans; a count ≠ expect → error before any change
func Restore(o Options, snapshot io.Reader) (*Report, error)
func FSName(magic int64) string // statfs magic → "ext4"|"xfs"|"btrfs"|"zfs"|"nfs"|"cifs"|"fuse"|"overlay"|"tmpfs"|"other"
var Unsupported = map[string]bool{"nfs": true, "cifs": true, "fuse": true, "overlay": true, "tmpfs": true}
func Main(args []string, stdout, stderr io.Writer) int
```
- CLI (the only argv the Hub builds, Task 5):
  `folderfix probe --root /broot --rel <path below the bind root>` →
  `{dev, ino, symlink: "<component>"|"" , exists}`;
  `folderfix scan --root /folder [--expect-dev D --expect-ino I] [--gid N --files rw|r --owner U] [--principal name:uid:gid[,gid…][:w]]… [--children] [--max-entries N --max-time D]`;
  `folderfix snapshot … --out /out` (writes `/out/snapshot.ndjson.gz`);
  `folderfix apply … --expect N [--mkdir rel]…`;
  `folderfix restore --root /folder --expect-dev D --expect-ino I --in /in/snapshot.ndjson.gz`.
  Exit 0 = done (report on stdout); 2 = refused (report + error); 1 = failed.
- Snapshot lines: header
  `{"version":1,"root_dev":D,"root_ino":I,"gid":N,"created_at":"…","entries":N}`,
  then one `{"p":"rel","t":"d|f","ino":I,"u":U,"g":G,"m":MODE,"a":"<b64 access xattr>","d":"<b64 default xattr>"}`
  per entry. Restore skips (and counts) a path whose inode or type
  differs.

- [ ] **Step 1: unprivileged tests** (`scan_test.go`, any OS where the
  syscalls exist, else skipped): in `t.TempDir()`:
  - `TestScanCounts`: 3 dirs, 4 regular files plus a second name for one
    of them (a hard link), a symlink to `/`, a FIFO → `Dirs 3`, `Files 5`
    (every regular-file name), `HardLinks.N 2` (both names),
    `Symlinks.N 1`, `Specials.N 1`; nothing
    outside the tree is read (the symlink target isn't stat'ed: assert
    via the report's `Errors` being empty with a symlink to a
    non-existent path).
  - `TestScanCap`: `MaxEntries 3` → `Partial`, `PartialReason "entries"`.
  - `TestScanPrincipals`: a file `0600` owned by the test uid →
    principal `{UID: 4242, GIDs: [4242]}` can't read it (`CantRead.N 1`,
    sample has its path).
  - `TestApplyRefusesWrongRoot`: `ExpectIno` of another directory →
    error, exit code 2 from `Main`, nothing changed (mtimes and modes
    compared).
  - `TestApplyExpectMismatch`: `expect` 1 less than the plan → error,
    nothing changed.
  - `TestCLIArgs`: `Main` with an unknown mode, a relative `--root`, or
    a `--mkdir ../x` → exit 1 and no report.
- [ ] **Step 2: root tests** (`root_test.go`, `//go:build linux && fixerroot`,
  skipped unless uid 0 and the temp dir supports ACLs):
  - `TestRootApplyInheritance` (spec Testing): a tree owned `1000:1000`
    `0640`/`0750`; `Apply` with gid 60001, files rw; then, as uid 2001
    with umask 022 (`syscall.Setfsuid` in a locked OS thread, or a
    `exec.Command` of the test binary with `SysProcAttr.Credential`), a
    new file in a subdir → its gid is 60001 and its effective group bits
    include `rw`; `getfacl` (if installed) agrees with `DecodeACL`.
  - `TestRootApplyKeepsAccess` (Review Focus 5): before/after
    `Allowed(…)` for gid 1000, uid 1000, an existing `user:3000:rwx`
    under `mask::r`, and "other" is unchanged or wider for every entry;
    the previous group gets `group:1000:r--` in access and default ACLs
    (dirs); the `user:3000` entry is stored as `r--`; `Plan.Narrowed.N`
    equals the narrowed entries.
  - `TestRootMustOwn`: three files owned by 1000, 1001, 1002 →
    `OwnerUID 2000`: owner 2000 on all, each previous uid keeps its bits
    through `user:<uid>`; `Plan.KeepUser` = `{1000:1, 1001:1, 1002:1}`.
  - `TestRootSkips`: a hard link (`nlink 2`), a bind mount of another
    tmpfs inside the tree (when `unix.Mount` is permitted), a symlink, a
    FIFO → untouched (stat before/after), counted.
  - `TestRootSetuidKept`: a `04755` file keeps setuid after the group
    change.
  - `TestRootNoACLExplainOnly`: with the package test hook
    `noACLForTest = true` (the walk then behaves as on a filesystem
    without ACL support), a group change that would drop gid 1000's
    bits → `Plan.LoseAccess.N > 0` and `Apply` refuses with nothing
    changed; with no previous group bits, `Apply` does chgrp + setgid +
    mode only and writes no ACL xattr.
  - `TestRootSnapshotRestore`: `WriteSnapshot` → `Apply` → `Restore` →
    every entry's uid, gid, mode and both ACL xattrs are byte-equal to
    before; a path replaced in between (new inode) is skipped and counted.
  - `TestRootMkdir`: `Mkdir: ["movies/hd"]` creates both levels with gid
    60001, setgid and the default ACL; a pre-existing `movies` symlink →
    refused.
- [ ] **Step 3: run.** `go test -race ./internal/folderfix/` → FAIL; on a
  Linux box `sudo -E env "PATH=$PATH" go test -tags fixerroot ./internal/folderfix/`
  → FAIL.
- [ ] **Step 4: implement.**
  - Walk: open the root `O_DIRECTORY|O_NOFOLLOW`, `Fstat` → dev/ino
    check; then a depth-first walk with `Openat(dirfd, name,
    O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC)`, `Fstat` on the fd, reading
    directories with `os.NewFile(fd).ReadDir`. Bounded open fds (close
    each dir after listing its children into a slice).
  - Per entry: compute the new ACLs with Task 3 (`Clamp`, keep previous
    group/owner, set group_obj, `RecalcMask` for files / mask rwx for
    dirs); apply in this order: `Fchown` → `Fsetxattr(access)` →
    `Fchmod` (user/other bits as before, group bits = mask, setgid on
    dirs, setuid/setgid of files as before) → `Fsetxattr(default)` on
    dirs.
  - Without ACL support: chgrp + setgid + mode only; refuse when
    `LoseAccess.N > 0`; drop `OwnerUID` changes that would cut a
    previous owner (the Hub decides from the scan; `Apply` still refuses
    as a backstop).
  - `Allowed` for principals; `Children` counts per first-level child.
  - Report JSON on stdout as one line; stderr only for crashes.
- [ ] **Step 5: CI.** In `.github/workflows/build.yml`, after `go test
  -race`: install `acl` (`sudo apt-get install -y acl`), then
  `sudo -E env "PATH=$PATH" go test -tags fixerroot -count=1 -v ./internal/folderfix/`.
  The runner's temp dir is ext4 with ACLs.
- [ ] **Step 6: verify.** `go vet ./... && go test -race ./... && gofmt -l .`
  → PASS locally; the root tests pass in CI (push the branch, check the
  run).
- [ ] **Step 7: commit.** `folderfix: scan, snapshot, apply, restore; hub folderfix subcommand; root CI test`.

### Task 5: Docker: started helper, self image

**Files:**
- Modify: `internal/docker/volumes.go` (or a new `internal/docker/run.go`),
  `internal/docker/client.go` (`InspectContainer`), `internal/hub/hub.go`
  (`Engine`, `Config.FixerImage`, `selfImage`), `cmd/hub/main.go`
  (`HUB_FIXER_IMAGE`), `internal/hub/fakes_test.go` (fake `RunHelper`),
  `internal/hub/backup.go` (`SweepBackupLeftovers` comment: it also
  removes fixers).
- Test: `internal/docker/run_test.go`, `internal/hub/fixer_test.go`.

**Interfaces:**
- Produces:
```go
// docker
type BindMount struct{ Source, Target string; ReadOnly, Create bool } // Create → BindOptions.CreateMountpoint
type RunSpec struct {
    Image    string
    Cmd      []string // Entrypoint; no shell
    User     string   // "0:0"
    Binds    []BindMount
    Scratch  []string // anonymous volume targets ("/out", "/in")
    CapAdd   []string
    Label    string   // LabelHelper value, e.g. "folder:photos"
    Pids     int64
    Memory   int64
    Timeout  time.Duration
    InPath   string    // CopyToContainer target before start ("" = none)
    In       io.Reader // tar stream
    OutPath  string    // CopyFromContainer after exit ("" = none)
}
type RunResult struct{ ExitCode int; Stdout, Stderr []byte } // stdout ≤ 256 KiB, stderr ≤ 16 KiB
// RunHelper: create → copy in → start → wait (Timeout: kill, error) → logs → copy out (out(tar)) → remove (always).
func (c *Client) RunHelper(ctx context.Context, s RunSpec, out func(tar io.Reader) error) (*RunResult, error)
type ContainerInfo struct{ ID, Image string; Labels map[string]string }
func (c *Client) InspectContainer(ctx context.Context, id string) (ContainerInfo, error)
// hub: Engine gains RunHelper and InspectContainer.
// hub internal:
type fixerRun struct {
    Mode     string // probe|scan|snapshot|apply|restore
    Folder   string // label "folder:<id>"; "" for a path check
    Source   string // host path bound at /folder (probe: the bind root at /broot)
    ReadOnly bool
    Create   bool
    Args     []string // flags after the mode
    In       []byte   // restore: the snapshot
    Out      func(io.Reader) error
}
func (h *Hub) runFixer(ctx context.Context, r fixerRun) (*folderfix.Report, error) // caps by mode, Global Constraints
func (h *Hub) selfImage(ctx context.Context) (string, error) // cached; HUB_FIXER_IMAGE, else InspectContainer(os.Hostname()).Image
```

- [ ] **Step 1: tests.**
  - `TestRunHelperSpec` (`run_test.go`, an `httptest` Docker API fake):
    the create body has `NetworkMode "none"`, `ReadonlyRootfs true`,
    `CapDrop ["ALL"]`, exactly the `CapAdd` given,
    `SecurityOpt ["no-new-privileges:true"]`, `Privileged false`, no
    `Devices`, `User "0:0"`, `PidsLimit 16`, `Memory 268435456`, the bind
    `Type bind` with `ReadOnly` and `CreateMountpoint` as given, label
    `io.portcullis.hub.helper=folder:photos`; the calls are in the order
    create, archive PUT, start, wait, logs, archive GET, delete.
  - `TestRunHelperRemovesOnFailure`: start fails → delete still called;
    wait exceeds `Timeout` → kill then delete, error.
  - `TestRunHelperClipsLogs`: 1 MiB stdout → 256 KiB kept.
  - `TestFixerCapsByMode` (`fixer_test.go`, fake engine records the
    spec): `scan` → `CapAdd [DAC_READ_SEARCH]`, read-only bind;
    `apply` → `[CHOWN FOWNER FSETID DAC_OVERRIDE DAC_READ_SEARCH]`,
    read-write; `Cmd[0:3] == ["hub","folderfix","apply"]`.
  - `TestFixerImageResolution`: `FixerImage` without `@sha256:` → `New`
    refuses; unset → `InspectContainer(hostname)` → its `Image`; inspect
    fails → `runFixer` returns a 503 `StatusError`.
  - `TestSweepRemovesFixers`: `SweepBackupLeftovers` removes a container
    labelled `folder:x`.
- [ ] **Step 2: run.** `go test -race ./internal/docker/ ./internal/hub/ -run 'TestRunHelper|TestFixer|TestSweepRemovesFixers'`
  → FAIL.
- [ ] **Step 3: implement.** `ContainerWait` with `WaitConditionNotRunning`;
  logs demuxed with `stdcopy`. The report is the last non-empty stdout
  line, decoded with `DisallowUnknownFields`; exit 2 → `StatusError` 409
  carrying the report's first error; exit 1 → 500.
- [ ] **Step 4: verify.** `go vet ./... && go test -race ./... && gofmt -l .`
  → PASS.
- [ ] **Step 5: commit.** `docker: started fixer helper (RunHelper), self image`.

## Phase 3 — Hub shared folders

### Task 6: Folder definitions, gids, path rules, check path

**Files:**
- Create: `internal/hub/folders.go`, `internal/hub/folders_test.go`.
- Modify: `internal/state/state.go` (`Folders`, `FolderGIDs`),
  `internal/hub/hub.go` (`New` calls `SetFolderSource(hubFolders{h})`,
  `folderLocks`), `CLAUDE.md`.

**Interfaces:**
- Consumes: Task 5 `runFixer`; project 1 `FolderSource`; `ParseBindRoots`
  rules (`systemRoots`, `sensitiveHostPaths`, `pathUnder`).
- Produces:
```go
// state
type Folder struct {
    Name           string          `yaml:"name"`
    Path           string          `yaml:"path"`
    Description    string          `yaml:"description,omitempty"`
    GID            int             `yaml:"gid"`
    Adopted        bool            `yaml:"adopted,omitempty"`
    CreatedAt      time.Time       `yaml:"created_at"`
    WriteConfirmed map[string]bool `yaml:"write_confirmed,omitempty"` // "<instance>/<key>": admin-confirmed write for a template without a folder block
    LastApply      *FolderApply    `yaml:"last_apply,omitempty"`
}
type FolderApply struct {
    At       time.Time `yaml:"at"`
    Files    string    `yaml:"files"` // rw|r
    OwnerUID *int      `yaml:"owner_uid,omitempty"`
    Snapshot string    `yaml:"snapshot,omitempty"` // "<folder>/<ts>.ndjson.gz"
}
// AppState.Folders map[string]Folder `yaml:"folders,omitempty"`; AppState.FolderGIDs []int `yaml:"folder_gids,omitempty"`
// hub
const FolderGIDMin, FolderGIDMax = 60000, 60999
type FolderInput struct{ ID, Name, Path, Description string; GID *int; Create bool } // GID: adopt
type PathCheck struct {
    Path string `json:"path"`; Exists bool `json:"exists"`; Created bool `json:"created"`
    FSType string `json:"fs_type"`; ACL, Xattr bool
    Files, Dirs int64; Partial bool
    Owners []folderfix.OwnerCount `json:"owners"`
    Problems []string `json:"problems,omitempty"` // refusals in plain words
    Summary string `json:"summary"` // "exists · ext4 · ACLs and xattrs supported · 12,410 files · owners 1000:1000 (all)"
}
type FolderView struct {
    ID, Name, Path, Description string; GID int; Adopted bool
    Uses []FolderUseView `json:"uses"`
    LastOp *OpRecord `json:"last_op,omitempty"`
    // Task 11 adds LastCheck *doctor.ScanSummary `json:"last_check,omitempty"`.
}
type FolderUseView struct{ Instance, Key, Label, Subpath, Access string; Declared, ReadOnly bool }
func (h *Hub) Folders() []FolderView
func (h *Hub) CheckFolderPath(ctx context.Context, path string, create bool) (*PathCheck, error)
func (h *Hub) CreateFolder(ctx context.Context, in FolderInput, actor string) (*FolderView, []string, error) // warnings
func (h *Hub) UpdateFolder(ctx context.Context, id string, in FolderInput, actor string) (*FolderView, error)
func (h *Hub) DeleteFolder(id, actor string) error
func (h *Hub) folderUsesLocked(id string) []FolderUseView // derived from InstanceSettings.Values folder refs
func cleanFolderPath(p string) (string, error)
func (h *Hub) checkFolderPathLocked(p, selfID string) error // Global Constraints path rules incl. overlap
func (h *Hub) probeFolder(ctx context.Context, p string, create bool) (dev, ino uint64, exists bool, err error)
type hubFolders struct{ h *Hub } // FolderHostPath(id, sub): caller holds h.mu (project 1 calls it from renderOverrideLocked)
```
- Assignments are **derived** from setting values (`folder:<id>…`), never
  stored separately: "assigned but not applied" can't exist (call 19).

- [ ] **Step 1: tests** (fake engine answers `probe`/`scan` with canned
  reports):
  - `TestFolderPathRules`: `/srv` (a root) → refused; `/etc/x`, `/var/lib/docker/x`,
    `<ProjectHostDir>/x`, `/home/x` (outside roots) → refused, each with
    its reason; `/srv/a/../b` → refused; `/srv/photos` → OK.
  - `TestFolderPathNormalised` (Review Focus 1): `/srv/photos/` and
    `/srv//photos` are stored as `/srv/photos`; a second folder at
    `/srv/photos/2026` or `/srv` → 409 overlap.
  - `TestFolderPathSymlinkRefused` (Review Focus 1): the probe reports
    `symlink: "photos"` → 409 "`/srv/photos` is a symlink; give the real
    path"; the probe was run with the bind root `/srv` mounted read-only
    at `/broot` and `--rel photos`.
  - `TestCreateFolderRunsCheck`: fs `nfs` → 409 naming the filesystem
    and why; `ext4` → saved, gid 60000; the next folder gets 60001;
    deleting the first and creating a third → 60002 (never reused).
  - `TestAdoptGID`: 999, 65534, 60500, and a gid another folder uses →
    400/409; 1000 → saved, `Adopted`, the warning text from Global
    Constraints.
  - `TestGIDRangeExhausted`: all 1000 gids used → 409 "no free folder
    group".
  - `TestCheckFolderPath`: missing path, `create: false` → `Exists false`,
    nothing created (the bind had `Create false`); `create: true` →
    `Created true`; the `Summary` string equals the spec's example for
    the canned report.
  - `TestDeleteFolderRefusedWhileUsed`: an instance value `folder:photos`
    → 409 listing the instance; unused → deleted; no fixer run (files
    never touched).
  - `TestUpdateFolder`: name/description change → saved; a path change
    while used → 409; id never changes.
  - `TestFolderAudit`: `folder.create` (`Target "photos"`, `Detail
    "gid=60000 path=/srv/photos"`), `folder.update`, `folder.delete`,
    and refusals audited `refused`.
  - `TestFolderHostPath`: `FolderHostPath("photos", "movies/hd")` →
    `/srv/photos/movies/hd`; unknown id → error.
- [ ] **Step 2: run.** `go test -race ./internal/hub/ -run 'TestFolder|TestCreateFolder|TestAdoptGID|TestGIDRange|TestCheckFolderPath|TestDeleteFolder|TestUpdateFolder'`
  → FAIL.
- [ ] **Step 3: implement.** The probe and check run outside `mu`; the
  save re-checks overlap under `mu` (lost race → 409). Gid allocation and
  `FolderGIDs` append happen in the same locked save.
- [ ] **Step 4: verify.** `go vet ./... && go test -race ./... && gofmt -l .`
  → PASS.
- [ ] **Step 5: commit.** `hub: shared folder definitions, gid allocation, path rules, check path`.

### Task 7: Rendering and settings integration

**Files:**
- Modify: `internal/hub/override.go` (mounts, `:ro`, `group_add`),
  `internal/hub/env.go` (folder variables, `gid_env`),
  `internal/hub/paths.go` (`PathUsage` fields), `internal/hub/settings.go`
  (`SaveSettings` refusals), `internal/hub/restore.go` (missing folder
  refs), `internal/hub/delete.go` (purge `WriteConfirmed`), `CLAUDE.md`.
- Test: `internal/hub/folders_render_test.go`.

**Interfaces:**
- Consumes: Task 2 types; Task 6 `hubFolders`; project 1
  `renderOverrideLocked`, `generateAppEnvLocked`, `PathUsages`,
  `SaveSettings`, `configProblems`.
- Produces:
```go
// PathUsage (project 1) gains:
//   Folder, Subpath, JoinsGroup, Source string // Source: "setting" | "folder" | "custom_override"
//   MustOwn, Declared bool                     // Declared: the option has a folder block
//   GIDs []int                                 // supplementary gids the container gets (folder gid under group_add)
//   Checks []templates.Check
func folderReadOnly(o *templates.Option, f *state.Folder, instance, key string) bool
func (h *Hub) folderEnvLocked(t *templates.Template) map[string]string // PORTCULLIS_FOLDER_* and gid_env overrides
func (h *Hub) customMountsLocked(t *templates.Template) []PathUsage   // bind mounts of the custom override, Source "custom_override"
func dropMissingFolderRefs(c *instanceConfig, folders map[string]state.Folder) []string // warnings
```

- [ ] **Step 1: tests.**
  - `TestFolderMountRendered`: jellyfin `movies` = `folder:media/movies`
    (folder `/srv/media`, gid 60001, `access: read`) → override volume
    `"/srv/media/movies:/data/movies:ro"` and `group_add: ["60001"]` on
    service `jellyfin`; env has `PORTCULLIS_FOLDER_GID_MOVIES='60001'`.
  - `TestReadAlwaysRO` (call 24): a custom path on an `access: read`
    option → `:ro`.
  - `TestUndeclaredTemplateRO` (call 3): an option without a folder block
    pointed at a folder → `:ro`; with `WriteConfirmed["inst/key"]` → rw;
    `group_add` present in both.
  - `TestGIDEnvOverride`: `joins_group: gid_env`, `gid_env: PGID` (option
    `pgid` = 1000) → env `PGID='60001'`, no `group_add`; the option's
    own value isn't written twice.
  - `TestMustOwnUIDVar`: a folder with a `must_own` writer uid 2000 →
    every instance using it gets `PORTCULLIS_FOLDER_UID_<KEY>='2000'`.
  - `TestTemplateJoinNoGroupAdd`: `joins_group: template` → env only.
  - `TestPathUsagesFromFolderBlock`: `Mode "ro"`, `Needs "read"`,
    `UID`/`GID` from `runs_as` (an `_env` resolved through its option),
    `Folder`, `Subpath`, `GIDs [60001]`; `uid_from` → `OwnerKnown false`;
    a custom-override bind mount appears with `Source "custom_override"`.
  - `TestSaveSettingsRefusesFolderRefs`: `PUT` a value `folder:media`, or
    replacing an existing `folder:media` value → 409 "assign through
    Settings → Shared folders"; changing option `pgid` while a folder
    sets PGID → 409 "set by shared folder Family media (gid 60001)".
  - `TestRestoreClearsMissingFolderRefs`: an archive whose settings name
    `folder:gone` → the value is cleared and the restore answers the
    warning "setting movies named shared folder gone, which doesn't exist;
    cleared"; restore into a new id keeps `folder:media` when it exists.
  - `TestDeleteInstanceDropsAssignments`: after delete, `Folders()` lists
    no use of it and `WriteConfirmed` has no `<id>/…` keys.
- [ ] **Step 2: run.** `go test -race ./internal/hub/ -run 'TestFolderMount|TestReadAlwaysRO|TestUndeclared|TestGIDEnv|TestMustOwnUID|TestTemplateJoin|TestPathUsagesFrom|TestSaveSettingsRefusesFolder|TestRestoreClearsMissing|TestDeleteInstanceDrops'`
  → FAIL.
- [ ] **Step 3: implement.** `group_add` values are strings (compose
  merges lists with the template's own). `folderEnvLocked` runs last in
  env generation so `gid_env` wins. `dropMissingFolderRefs` runs before
  `configProblems` in both restore paths.
- [ ] **Step 4: verify.** `go vet ./... && go test -race ./... && gofmt -l .`
  → PASS.
- [ ] **Step 5: commit.** `hub: render shared folders (mounts, :ro, group_add, folder variables)`.

### Task 8: Assignment preview and apply, snapshots, undo

**Files:**
- Create: `internal/hub/folderassign.go`, `internal/hub/foldersnap.go`,
  `internal/hub/folderassign_test.go`.
- Modify: `internal/hub/async.go` (`opKeyFolder`), `internal/hub/ops.go`
  (`loadOps` keeps `_folder.*` records), `internal/hub/hub.go` (`Init`:
  `RecoverFolderApplies`), `CLAUDE.md`.

**Interfaces:**
- Consumes: Tasks 4–7; `startAsync`, `lockApp`, `composeDown`/`stopProject`,
  `composeUp`, `auditOp`, `needFree`.
- Produces:
```go
type FolderUse struct {
    Instance string `json:"instance"`; Key string `json:"key"`
    Subpath string `json:"subpath,omitempty"`
    Write bool `json:"write,omitempty"` // only for options without a folder block (call 3)
}
type AssignRequest struct{ Uses []FolderUse `json:"uses"` } // the full desired set for this folder
type UsePlan struct {
    FolderUse
    Label, Access string; ReadOnly, Declared bool
    JoinsGroup string; Env map[string]string
    Change string // "add" | "remove" | "keep"
}
type DiskPlan struct {
    Files string; OwnerUID *int; Mkdir []string
    Counts *folderfix.PlanCounts; Entries int64; Partial bool
    Dev, Ino uint64
}
type AssignPlan struct {
    Folder string `json:"folder"`; GID int `json:"gid"`; Path string `json:"path"`
    Uses []UsePlan `json:"uses"`
    Disk *DiskPlan `json:"disk,omitempty"` // nil: only removals, nothing on disk
    Restarts []string `json:"restarts"`      // running instances stopped and started
    Downtime string `json:"downtime"`         // "about 1 minute"
    Lines []string `json:"lines"`             // the preview text (spec example)
    Warnings []string `json:"warnings,omitempty"`
    Hash string `json:"plan_hash"`
}
func (h *Hub) PreviewAssign(ctx context.Context, id string, req AssignRequest) (*AssignPlan, error)
func (h *Hub) StartAssign(id string, req AssignRequest, planHash, actor string) (*AsyncOp, error)
func (h *Hub) PreviewUndo(ctx context.Context, id string) (*AssignPlan, error) // from LastApply.Snapshot
func (h *Hub) StartUndo(id, planHash, actor string) (*AsyncOp, error)
func opKeyFolder(id string) string // "_folder." + id
func (h *Hub) folderLock(id string) (func(), error) // try-lock, ErrBusy
func (h *Hub) saveSnapshot(folder string, r io.Reader) (rel string, err error) // gzip passthrough, sha256 file, keep 3
func (h *Hub) openSnapshot(rel string) ([]byte, error) // checksum verified
func (h *Hub) RecoverFolderApplies() // Init: <data>/folders/<id>.applying.json → start the listed instances, mark the op interrupted
```
- Plan hash = sha256 of the canonical JSON of the plan's decisions
  (folder id, path, gid, every `UsePlan` without `Label`, `Disk` without
  `Counts`/`Entries`/`Partial`, `Restarts`) plus the current values of
  every affected option and port. Apply recomputes the plan and compares:
  a difference is 409 "the setup changed since the preview", before the
  op is accepted.
- Apply sequence (call 9), inside the op: folder lock → `lockApp` sorted
  → `ready()` → write `<data>/folders/<id>.applying.json`
  `{instances, snapshot}` → stop the running ones → (disk) free-space check
  on `<data>`, `snapshot` run → `saveSnapshot` → `apply --expect N --mkdir …`
  → verify `scan` (every `Expected` count 0, else error) → under `mu`: set
  values `folder:<id>[/sub]` (removed uses: value deleted, back to the
  default), `WriteConfirmed`, `LastApply`, save state → regenerate env and
  override → start the stopped ones → remove the marker → audit
  `folder.assign` (`Detail "add=2 remove=0 entries=12410 snapshot=<ts>"`)
  and, when disk changed, `folder.apply`. A failure before the state save
  starts the apps with the old config and fails the op with the snapshot
  named; after it, the op fails with state kept.

- [ ] **Step 1: tests** (fake engine with scripted fixer reports):
  - `TestPreviewAssignText`: the spec's UI example (12,410 files, 312
    folders, group 1000 keeps rw, Immich read-only, Samba + Immich
    stopped about 1 minute) → `Lines` contain each of those sentences;
    nothing in state, values or disk changed (no `apply` run, values
    unchanged).
  - `TestPreviewRefusals`:
    - call 23: two options of one service whose `gid_env` would get
      different gids → 409 "point both settings at the same shared folder";
    - two `must_own` uses → 409;
    - an option already using another folder → 409 "unassign it from X
      first";
    - an unknown instance/key, or a non-path option → 400;
    - no ACL support and `Counts.LoseAccess.N > 0` → 409, explain-only
      text;
    - `must_own` without ACLs and previous owners → no owner change in
      `Disk`, warning "uid 1000 would lose access: ownership stays; the
      group part still applies".
  - `TestApplyHashMismatch`: preview, change a port, apply with the old
    hash → 409, no op started.
  - `TestApplySequence`: the fake records stop, snapshot, apply
    (`--expect` = snapshot entries, `--mkdir movies`), verify, state
    save, override regeneration, start, in that order; the values become
    `folder:media/movies`; `LastApply.Snapshot` set; audit entries as
    above.
  - `TestApplyVerifyFails`: verify reports `Expected.Group.N 3` → op
    error naming the snapshot, values unchanged, apps started again.
  - `TestAssignHoldsLocks` (Review Focus 3): while the op runs (fake
    blocks the apply), `Enable`, `RestartApp`, `SaveSettings`,
    `StartBackup` on an affected instance and a second `StartAssign` on
    the folder → 409 busy.
  - `TestUnassignNoDisk`: removing the only use → `Disk nil`, the app
    restarts, the value is cleared, no fixer runs.
  - `TestSnapshotRetention`: four applies → three snapshots remain, each
    with a matching `.sha256`; a tampered snapshot → `openSnapshot` error.
  - `TestUndo`: `PreviewUndo` lines name the snapshot time and the entry
    count; apply runs `restore` with the snapshot copied in at `/in`;
    values unchanged; audited `folder.apply` `Detail "undo snapshot=<ts>"`.
    No snapshot → 404.
  - `TestInterruptedApplyRestartsApps` (Review Focus 2): a marker left
    behind + a running op record → `Init` starts the listed instances
    with their (unchanged) config and marks the record `interrupted`
    with the snapshot named.
- [ ] **Step 2: run.** `go test -race ./internal/hub/ -run 'TestPreviewAssign|TestPreviewRefusals|TestApply|TestAssignHoldsLocks|TestUnassign|TestSnapshot|TestUndo|TestInterruptedApply'`
  → FAIL.
- [ ] **Step 3: implement.** Downtime estimate = entries / 5,000 per
  second for the three runs, rounded to "under a minute" / "about N
  minutes". Every fixer run passes `--expect-dev/--expect-ino` from the
  plan's probe.
- [ ] **Step 4: verify.** `go vet ./... && go test -race ./... && gofmt -l .`
  → PASS.
- [ ] **Step 5: commit.** `hub: previewed folder assignment (stop, snapshot, apply, verify, start), undo`.

## Phase 4 — the doctor

### Task 9: Doctor engine, config checks, mutes

**Files:**
- Create: `internal/doctor/{doctor,checks_config,checks_person}.go` and
  tests; `internal/hub/doctor.go` (gather inputs, mutes),
  `internal/hub/doctor_test.go`.
- Modify: `internal/state/state.go` (`DoctorMutes`), `CLAUDE.md`.

**Interfaces:**
- Consumes: Task 7 `PathUsages` (extended), `customMountsLocked`;
  project 1 `InstanceSettings.Person`, `People.Membership`,
  `populationLocked`.
- Produces:
```go
// doctor (no hub import)
type Severity string
const (Problem Severity = "problem"; Warning Severity = "warning"; Info Severity = "info")
type FixClass string
const (FixOneClick FixClass = "one_click"; FixExplain FixClass = "explain"; FixLink FixClass = "link"; FixNone FixClass = "")
type Link struct{ Instance, Option string }
type Finding struct {
    FP string `json:"fp"`; Kind string `json:"kind"`; Severity Severity `json:"severity"`
    Title string `json:"title"`; Why string `json:"why"`; Fix string `json:"fix_text,omitempty"`
    Instances []string `json:"instances,omitempty"`; Folders []string `json:"folders,omitempty"`; Paths []string `json:"paths,omitempty"`
    Class FixClass `json:"fix_class,omitempty"`; FixKind string `json:"fix_kind,omitempty"`
    Steps []string `json:"steps,omitempty"` // explain-only instructions
    Link *Link `json:"link,omitempty"`
    Partial bool `json:"partial,omitempty"`
    Inputs string `json:"-"` // digest of what produced it
    Muted *Mute `json:"muted,omitempty"`
}
type Mute struct{ Reason, Actor string; At time.Time; Inputs string }
type PathIn struct{ /* hub.PathUsage's fields, copied */ Instance, Key, Label, HostPath, Service, Mount, Access, Source, Folder, Subpath, JoinsGroup, UIDEnv, GIDEnv string; UID, GID int; GIDs []int; OwnerKnown, Writes, ReadOnly, MustOwn, Declared bool; Checks []templates.Check }
type FolderIn struct{ ID, Name, Path string; GID int; Uses []PathIn; LastApply *time.Time }
type PortIn struct{ Instance, Key, Label, Service, Bind string; Port int; Protocol string; LanOnly, HostNetwork, Custom bool }
type RowIn struct{ Group string; GroupID int; Exists bool; Members int }
type PersonIn struct{ Instance, Key, Label, DefaultDisplay string; Rows []RowIn; Requires *templates.Check }
type ScanIn struct{ At time.Time; Report *folderfix.Report; Target string }
type Inputs struct {
    Now time.Time; BindRoots []string
    Folders []FolderIn; Paths []PathIn; Ports []PortIn; Person []PersonIn
    LocalNetworks []netip.Prefix; DomainAddrs []netip.Addr
    Scans map[string]ScanIn // by cleaned host path
}
type Check interface{ Kind() string; Run(in *Inputs) []Finding }
func Register(c Check)                // built-ins register in init(); project 3 adds its own
func Fingerprint(kind string, subjects ...string) string
func Digest(v any) string             // sha256 hex of canonical JSON
type Report struct {
    Findings []Finding `json:"findings"` // sorted: severity, then title
    Counts map[Severity]int `json:"counts"` // unmuted only
    Muted int `json:"muted"`
    Scans []ScanSummary `json:"scans"`
}
type ScanSummary struct{ Target string; At time.Time; Partial bool; Entries int64 }
func Run(in *Inputs, mutes map[string]Mute) Report
// hub
func (h *Hub) Doctor(ctx context.Context) (*doctor.Report, error)
func (h *Hub) doctorInputs(ctx context.Context) (*doctor.Inputs, error)
func (h *Hub) MuteFinding(ctx context.Context, fp, reason, actor string) error   // 404 unknown fp; audited doctor.mute
func (h *Hub) UnmuteFinding(fp, actor string) error                              // audited doctor.unmute
// state: AppState.DoctorMutes map[string]DoctorMute `yaml:"doctor_mutes,omitempty"`;
// DoctorMute{Reason, Actor string; At time.Time; Inputs string}
```
- Config check kinds registered here (kind → severity → class):
  - `shared_path`: two or more uses of the same or nested **non-folder**
    host paths (settings and custom-override mounts). Same exact path,
    all under the bind roots, no custom-override mount → Warning,
    one-click `manage_as_folder` (Task 12); nested/overlapping → Warning,
    explain; with disk data, a writer that can't write or a reader that
    can't read → Problem (Task 11 adds the disk part).
  - `path_outside_roots`: a path setting outside the bind roots →
    Warning, explain.
  - `undeclared_template` (call 3): a folder use without a folder block →
    Info "this template doesn't say how it writes".
  - `primary_gid_conflict` (call 23): hand-typed paths on one service whose
    `gid_env` would need different gids → Problem, explain.
  - `custom_override_mount` (call 26): a custom-override bind mount that
    shares or nests with another use → Warning, explain with the steps.
  - `must_own_conflict`: two `must_own` uses of one path or folder →
    Problem, explain.
  - `exclusive` (check kind): another instance (same template included)
    writes the same folder or path → Problem, explain.
  - `person_option`: per-person option with no rows → Info (Warning with
    `requires_group_value`, its `reason` shown); a row whose group has no
    population member → Warning; a row whose group id no longer exists →
    Warning; all `FixLink` to `{instance, option}`.

- [ ] **Step 1: tests** (`internal/doctor`, pure fixtures):
  - `TestFingerprintStable`: subject order doesn't matter; kind matters.
  - `TestSharedPathSameAndNested`: jellyfin `/srv/media` + writer
    `/srv/media` → one `shared_path` Warning, `FixKind
    "manage_as_folder"`; `/srv/media` + `/srv/media/tv` → explain-only;
    a custom-override mount in the set → explain-only.
  - `TestUndeclaredTemplateInfo`, `TestPrimaryGIDConflict`,
    `TestMustOwnConflict`, `TestExclusiveConflict` (two instances of one
    template writing one folder → Problem), `TestPathOutsideRoots`.
  - `TestPersonOptionFindings`: no rows → Info; with
    `requires_group_value` → Warning containing the template's reason;
    `Members 0` → Warning naming the group; `Exists false` → Warning;
    `Link` set.
  - `TestMuteReappearsOnChange`: muted with digest A → counted in
    `Muted`, not in `Counts`; same finding with digest B → unmuted.
  - `TestRegisterCustomCheck`: a registered stub kind's findings appear.
  - Hub (`doctor_test.go`): `TestDoctorInputsGather` (two instances, a
    folder, a custom override mount, a per-person option with membership
    from the fake `People`) → the expected `Inputs`;
    `TestMuteAudited` (`doctor.mute`, `Detail` = reason, never longer than
    200 runes; unknown fp → 404; empty reason → 400).
- [ ] **Step 2: run.** `go test -race ./internal/doctor/ ./internal/hub/ -run 'TestFingerprint|TestSharedPath|TestUndeclared|TestPrimaryGID|TestMustOwnConflict|TestExclusive|TestPathOutside|TestPersonOption|TestMute|TestRegisterCustom|TestDoctorInputs'`
  → FAIL.
- [ ] **Step 3: implement.** Finding copy follows the spec's examples
  ("Jellyfin and Samba both use `/srv/media`. …"). `doctorInputs` reads
  state under `mu` (a copy), then calls `Membership` and the DNS lookup
  (Task 10) outside it.
- [ ] **Step 4: verify.** `go vet ./... && go test -race ./... && gofmt -l .`
  → PASS.
- [ ] **Step 5: commit.** `doctor: findings, fingerprints, mutes, config checks`.

### Task 10: Exposure check and Local networks

**Files:**
- Create: `internal/doctor/checks_exposure.go` (+ test),
  `internal/hub/localnet.go` (+ test).
- Modify: `internal/state/state.go` (`LocalNetworks`), `internal/hub/doctor.go`
  (ports and DNS into `Inputs`), `CLAUDE.md`.

**Interfaces:**
- Produces:
```go
var DefaultLocalNetworks = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "100.64.0.0/10"}
func (h *Hub) LocalNetworks() []netip.Prefix // state, else the defaults
func (h *Hub) LocalNetworksView() (cidrs []string, isDefault bool)
func (h *Hub) SetLocalNetworks(cidrs []string, actor string) error // nil/[] semantics: nil = defaults; audited settings.local_networks
func IsLocal(a netip.Addr, nets []netip.Prefix) bool // Unmap first; loopback always local
func (h *Hub) domainAddrs(ctx context.Context) []netip.Addr // A/AAAA of the main domain, 2 s timeout, cached 5 min; h.lookupIP is swappable in tests
// state: AppState.LocalNetworks []string `yaml:"local_networks,omitempty"`
```
- Kinds: `lan_only_exposed` (a `lan_only` port, template or custom
  override, bound to `0.0.0.0`/`::`/no address → Warning, one-click
  `rebind_port`; bound outside the local networks or to a main-domain
  address → Problem, `rebind_port`); `host_network` (a `lan_only` port of
  a `network_mode_host` service → Warning, explain: "Docker publishes
  around host firewalls such as ufw; restrict the port in your router or
  host firewall"). Ports without `lan_only` produce no finding.

- [ ] **Step 1: tests.**
  - `TestExposureAddressForms` (Review Focus 4): `0.0.0.0`, `::`, `[::]`,
    a custom port `"8445:445"` → Warning; `192.168.1.10` and
    `::ffff:192.168.1.10` → none; `203.0.113.5` → Problem; `10.0.0.5`
    equal to a `DomainAddrs` entry → Problem; host networking → Warning
    explain; a port without `lan_only` on `0.0.0.0` → none.
  - `TestLocalNetworksValidate`: `0.0.0.0/0`, `::/0`, `10.0.0.1/8`
    (host bits) → 400 naming the entry; 65 entries → 400; `[]` → saved
    (only loopback local); `nil` → defaults; audited with
    `Detail "5 networks"`.
  - `TestDomainAddrsCached`: two doctor runs within 5 min → one lookup;
    a lookup error → no Problem escalation, the finding says "couldn't
    resolve <domain>".
- [ ] **Step 2: run.** `go test -race ./internal/doctor/ ./internal/hub/ -run 'TestExposure|TestLocalNetworks|TestDomainAddrs'`
  → FAIL.
- [ ] **Step 3: implement.** Port bindings come from
  `resolvePortBindings` plus `parsedOverride.ports` (matched to a
  `lan_only` port by service and container port).
- [ ] **Step 4: verify.** `go vet ./... && go test -race ./... && gofmt -l .`
  → PASS.
- [ ] **Step 5: commit.** `doctor: LAN-only exposure check, local networks setting`.

### Task 11: Disk checks and scheduled scans

**Files:**
- Create: `internal/doctor/checks_disk.go` (+ test),
  `internal/hub/doctorscan.go` (+ test).
- Modify: `cmd/hub/main.go` (`go h.RunDoctorScans(ctx, 24*time.Hour)`),
  `internal/hub/folders.go` (`FolderView.LastCheck *doctor.ScanSummary`
  from the scan cache), `CLAUDE.md`.

**Interfaces:**
- Consumes: Task 5 `runFixer`, Task 9 `Inputs.Scans`.
- Produces:
```go
type ScanTarget struct{ Path, Folder string; Principals []folderfix.Principal; Target *folderfix.Target }
func (h *Hub) scanTargetsLocked() []ScanTarget // every folder; every distinct non-folder path used by ≥ 2 uses or by a writer, under the bind roots, nested ones collapsed to the outermost
func (h *Hub) StartDoctorScan(actor string) (*AsyncOp, error) // op key "_doctor"; scanMu try-lock → 409
func (h *Hub) RunDoctorScans(ctx context.Context, every time.Duration)
func (h *Hub) scanCache() map[string]doctor.ScanIn // <data>/doctor/scans.json, 0600
const scanMaxEntries, scanMaxTime = 2_000_000, 10 * time.Minute // previews: 30 s
```
- Kinds: `folder_owner` (a folder's `Expected` counts > 0 → Warning
  "drifted since the last apply", one-click `reapply_folder`; a writer
  with `CantWrite.N > 0` or a reader with `CantRead.N > 0` → Problem);
  the disk part of `shared_path` (Problem with the principal's counts,
  e.g. "can't read 412 new files"); `filesystem` (template check: missing
  `needs` or fs in `not` → Problem, explain); `free_space` (below `min` →
  Warning); `no_acl` (Warning); `skipped_entries` (hard links, mount
  points, specials → Warning, explain, the counts and samples); every
  finding from a `Partial` scan carries `Partial` and the text "(partial
  scan: stopped after N entries)".

- [ ] **Step 1: tests.**
  - `TestScanTargets`: folder + a hand-typed path used by two apps + a
    path used by one reader only (not scanned) + a path outside the roots
    (not scanned); nested hand-typed paths → one target.
  - `TestDiskFindings`: canned reports → each kind above with the right
    severity; `Partial` propagated; principal names map back to
    instances.
  - `TestScanAfterApply`: a successful Task 8 apply stores a fresh cache
    entry for that folder.
  - `TestDoctorScanBusy`: a second `StartDoctorScan` while one runs → 409.
  - `TestScanCacheSurvivesRestart`: a new `Hub` on the same data dir
    reports the same `Scans` with their times.
- [ ] **Step 2: run.** `go test -race ./internal/doctor/ ./internal/hub/ -run 'TestScanTargets|TestDiskFindings|TestScanAfterApply|TestDoctorScanBusy|TestScanCache'`
  → FAIL.
- [ ] **Step 3: implement.** Scans run outside `mu`, one target after the
  other; a target's failure is recorded in its cache entry (finding
  `scan_failed`, Warning) and the rest continue.
- [ ] **Step 4: verify.** `go vet ./... && go test -race ./... && gofmt -l .`
  → PASS.
- [ ] **Step 5: commit.** `doctor: disk checks, scheduled and on-demand scans`.

### Task 12: Doctor fixes

**Files:**
- Create: `internal/hub/doctorfix.go`, `internal/hub/doctorfix_test.go`.

**Interfaces:**
- Consumes: Tasks 6, 8, 9, 10.
- Produces:
```go
type FixPlan struct {
    FP string `json:"fp"`; Kind string `json:"fix_kind"`
    Lines []string `json:"lines"`; Warnings []string `json:"warnings,omitempty"`
    Assign *AssignPlan `json:"assign,omitempty"`
    Hash string `json:"plan_hash"`
}
type Fixer interface {
    Kind() string
    Preview(ctx context.Context, h *Hub, f doctor.Finding, params map[string]string) (*FixPlan, error)
    Apply(h *Hub, f doctor.Finding, params map[string]string, planHash, actor string) (*AsyncOp, error)
}
func RegisterFixer(f Fixer) // built-ins: manage_as_folder, reapply_folder, rebind_port
func (h *Hub) PreviewFix(ctx context.Context, fp string, params map[string]string) (*FixPlan, error) // 404 unknown fp; 409 explain-only/link
func (h *Hub) ApplyFix(ctx context.Context, fp string, params map[string]string, planHash, actor string) (*AsyncOp, error)
```
- `manage_as_folder`: params `name`, `id` (defaults: the path's base
  name, slugged). Preview = the folder definition lines + Task 8's
  `AssignPlan` for the finding's uses. Apply = `CreateFolder`, then
  `StartAssign`. If the assign preview refuses, the definition isn't
  created.
- `reapply_folder`: `StartAssign` with the folder's current uses.
- `rebind_port`: param `address`, valid IP, not unspecified, `IsLocal`,
  not a main-domain address. Apply (instance op `rebind`, instance lock):
  set `Ports[<KEY>_BIND]`, regenerate, restart if enabled; on failure put
  the old bind back, regenerate, start again, `OpError` with
  `rolled_back` and the reason.
- Every apply is audited `doctor.fix` (`Target <fp>`,
  `Detail "fix=<kind> <ids>"`) in addition to the folder/instance actions
  its steps audit.

- [ ] **Step 1: tests.**
  - `TestRebindPreviewText`: "SAMBA_SMB bind 0.0.0.0 → 192.168.1.10,
    Samba restarts"; `0.0.0.0`, `8.8.8.8`, `not-an-ip` → 400.
  - `TestRebindRollback`: the fake runner fails the restart → old bind
    back in state and override, a second up recorded, op `rolled_back`
    with the compose output.
  - `TestManageAsFolder`: finding over jellyfin + writer on `/srv/media`
    → preview has the definition lines and an `Assign` plan; apply
    creates folder `media` and runs the assign op; values become
    `folder:media`.
  - `TestFixHashMismatch`: apply after a change → 409.
  - `TestExplainOnlyHasNoPreview`: a `custom_override_mount` fp → 409
    "explain-only" with the steps.
  - `TestFixAudited`: `doctor.fix` present with the actor.
- [ ] **Step 2: run.** `go test -race ./internal/hub/ -run 'TestRebind|TestManageAsFolder|TestFixHash|TestExplainOnly|TestFixAudited'`
  → FAIL.
- [ ] **Step 3: implement.**
- [ ] **Step 4: verify.** `go vet ./... && go test -race ./... && gofmt -l .`
  → PASS.
- [ ] **Step 5: commit.** `doctor: one-click fixes (manage as folder, re-apply, rebind)`.

## Phase 5 — API and UI

### Task 13: API

**Files:**
- Create: `internal/httpapi/folders.go`, `internal/httpapi/doctor.go`,
  tests `folders_test.go`, `doctor_test.go`.
- Modify: `internal/httpapi/server.go` (`registerFolders`, `registerDoctor`
  on the Hub listener only; `/api/settings/local-networks`),
  `internal/httpapi/people_test.go`, `CLAUDE.md` (httpapi row).

**Interfaces:**
- Consumes: Tasks 6–12.
- Produces routes (all `adminOnly`, bodies `DisallowUnknownFields`,
  64 KiB):
  - `GET /api/folders` → `{"folders": [FolderView]}`;
  - `POST /api/folders` `{id, name, path, description, gid?, create?}` →
    201 `{folder, warnings}`;
  - `PUT /api/folders/{id}` `{name, path, description}`;
  - `DELETE /api/folders/{id}` (409 while used);
  - `POST /api/folders/check` `{path, create}` → `PathCheck`;
  - `POST /api/folders/{id}/assign/preview` `AssignRequest` → `AssignPlan`;
  - `POST /api/folders/{id}/assign/apply` `{plan_hash, uses}` → 202
    `{op_id, op, folder, poll: "/api/folders/{id}/op"}`;
  - `POST /api/folders/{id}/undo/preview`, `POST /api/folders/{id}/undo/apply {plan_hash}`;
  - `GET /api/folders/{id}/op` → `OpRecord`;
  - `GET /api/doctor` → `doctor.Report`;
  - `POST /api/doctor/scan` → 202 (`poll: "/api/doctor/op"`); `GET /api/doctor/op`;
  - `POST /api/doctor/findings/{fp}/preview` `{params}` → `FixPlan`;
  - `POST /api/doctor/findings/{fp}/apply` `{plan_hash, params}` → 202;
  - `POST /api/doctor/findings/{fp}/mute` `{reason}`;
    `DELETE /api/doctor/findings/{fp}/mute`;
  - `GET|PUT /api/settings/local-networks` `{networks: [..] | null}` →
    `{networks, default}`.

- [ ] **Step 1: tests.**
  - `TestFolderRoutesAdminOnly` / `TestDoctorRoutesAdminOnly`: a delegate
    with every permission → 403 on each route; no `X-Forwarded-User` →
    401.
  - `TestPeopleListenerHasNoAppRoutes` gains `/api/folders`,
    `/api/doctor` and `/api/settings/local-networks` → 404 on people.
  - `TestAssignApplyAnswers202`: body → 202 with `poll`; hash mismatch →
    409 `{error}`; busy → 409.
  - `TestFolderBodyRejectsUnknownFields`: `{"path": "/srv/x", "owner": 0}`
    → 400.
  - `TestDoctorAnswerShape`: counts, findings with `fp`, `severity`,
    `fix_class`; muted findings present with `muted`.
  - `TestStatusMeanings`: 503 (no self image) and 507 (no space) pass
    through.
- [ ] **Step 2: run.** `go test -race ./internal/httpapi/ -run 'TestFolder|TestDoctor|TestPeopleListener|TestAssignApply|TestStatusMeanings'`
  → FAIL.
- [ ] **Step 3: implement.**
- [ ] **Step 4: verify.** `go vet ./... && go test -race ./... && gofmt -l .`
  → PASS.
- [ ] **Step 5: commit.** `httpapi: shared folders, doctor and local networks routes`.

### Task 14: UI

**Files:**
- Create: `web/folders.js` (`window.PortcullisFolders`), `web/doctor.js`
  (`window.PortcullisDoctor`).
- Modify: `web/index.html` (Doctor tab + badge; Settings → Shared folders
  and Local networks sections next to Domains; the app detail doctor
  line), `web/settings.js` (project 1's path option: the folder picker),
  `web/web.go` (embed), `internal/httpapi/harness_test.go` (fixtures:
  two folders, one drifted; findings of each severity; a `lan_only` port
  on `0.0.0.0`).

**Interfaces:**
- Consumes: Task 13 routes and JSON.
- Produces:
```js
PortcullisFolders.render(el)                              // Settings → Shared folders
PortcullisFolders.openAssign({folder, add: [{instance, key, subpath}]}) // the preview dialog
PortcullisDoctor.render(el)                               // the Doctor tab
PortcullisDoctor.badge(tabEl)                             // Problems + Warnings count
PortcullisDoctor.lineFor(instance) -> Promise<string>     // "Doctor: 1 warning" (HTML-escaped)
```
- Behaviour (spec call 15 and "resulting UI behaviour"):
  - **Shared folders:** table name, path, gid, apps, last check; Add/Edit
    dialog with **Check path** (shows `PathCheck.Summary`, "Create it"
    when missing), adopt-gid field under "Advanced", **Used by** list of
    every instance path option (ticks + subfolder input; a template
    without a folder block shows "read-only unless you allow writing"
    with a checkbox). **Save** saves the definition, then opens the
    assignment preview only when the uses changed; closing it changes
    nothing. Remove asks for confirmation and shows the 409 reason.
    "Undo last fix…" when `LastApply.Snapshot` exists.
  - **Preview dialog:** `lines`, `warnings`, downtime; **Apply** posts the
    hash, then polls the op (`runInstanceOp`-style) and shows "verified: 0
    entries differ" or the error with the snapshot name.
  - **Local networks:** a textarea of CIDRs, "Reset to defaults".
  - **Doctor tab:** groups Problem / Warning / Info (muted collapsed);
    each card: title, why, apps/folders, partial note; buttons Fix… (opens
    the fix preview with a param form: name/id or address), Explain
    (steps), Open setting (link class → the app's settings panel at the
    option), Mute (reason prompt) / Unmute; "Run disk checks" with the
    last scan time.
  - **Path option picker** (`settings.js`): "Custom path" / "Shared
    folder ▾" + subfolder; choosing or leaving a shared folder calls
    `PortcullisFolders.openAssign` instead of the panel's save.
  - **App detail:** the doctor line linking to the tab.

- [ ] **Step 1: harness.** Add the fixtures, run
  `go test -tags harness -run TestHarness -timeout 0 ./internal/httpapi`.
- [ ] **Step 2: implement** the two files and the index/settings changes.
- [ ] **Step 3: browser check** (Playwright MCP against
  `127.0.0.1:18888`), screenshots under
  `.superpowers/sdd/2026-11-02-shared-folders-doctor/`:
  1. Add folder → Check path shows the summary line;
  2. Save with two apps ticked → the preview lists gid, counts, read-only
     and downtime; closing it leaves the folder with no apps;
  3. Apply → the op ends "verified";
  4. Doctor tab badge = Problems + Warnings; Rebind… on the LAN-only port
     shows the preview line; a mute moves the card to Muted;
  5. a path option's picker opens the assignment preview;
  6. a finding title containing `<b>` renders as text (escaping).
- [ ] **Step 4: verify.** `go vet ./... && go test -race ./... && gofmt -l .`
  → PASS.
- [ ] **Step 5: commit.** `web: shared folders, doctor tab, local networks, folder picker`.

## Phase 6 — templates

### Task 15: Schema, validator, template declarations (templates repo)

**Files:** `schema/manifest.schema.json` (`$defs.option.properties.folder`,
`$defs.runsAs`, `$defs.check` (one branch per kind), `$defs.port.properties.lan_only`),
`tests/validate.py` (`check_folders`), `tests/test_validate.py`
(class `TestFolders`), `CONTRIBUTING.md` ("Shared folders and checks"),
`immich/manifest.yaml`, `jellyfin/manifest.yaml`, `plex/manifest.yaml`,
`.core-ref` (`folders`).

**Interfaces:**
- Consumes: contract (Task 1); mirrors Task 2's rules one-for-one.
- Produces: `check_folders(t: Template, services: Dict[str, Any], r: Report) -> None`.

- [ ] **Step 1: tests.** One test per Task 2 rule, same names in
  snake_case (`test_folder_only_on_instance_path`,
  `test_folder_access_and_runs_as_required`, `test_runs_as_one_source_per_id`,
  `test_runs_as_env_names_option`, `test_runs_as_matches_compose_user`,
  `test_joins_group`, `test_must_own_writers_only`,
  `test_folder_replaces_mode_needs_writes_as`, `test_same_env_same_runs_as`,
  `test_uid_from_reserved`, `test_checks_catalog`, `test_lan_only_port`).
- [ ] **Step 2: run.** `python3 tests/test_validate.py` → FAIL.
- [ ] **Step 3: implement** schema first, then `check_folders`.
- [ ] **Step 4: declarations.** Replace each path option's `mode`/`needs`/`writes_as`
  (from project 1) with a folder block:
  - immich `external_library`: `access: read`; `runs_as` from its
    `writes_as` (`{uid: 0, gid: 0}`).
  - jellyfin and plex library paths: `access: read`; `runs_as` from
    `writes_as` (a number → `uid`/`gid`; an option key → `uid_env`/`gid_env`
    = that option's env name); `joins_group: gid_env` where the image
    takes its gid from that variable, else `group_add`. Check the image's
    behaviour (entrypoint docs) and note it in the manifest `notes`.
  - No template has a `lan_only` port yet (project 3's Samba is the first).
- [ ] **Step 5: verify.** `python3 tests/validate.py` and
  `python3 tests/test_validate.py` → PASS.
- [ ] **Step 6: commit and push.**
  `schema+validate: folder block, check catalog, lan_only; immich/jellyfin/plex folders`.
  Push hub, templates and core `folders` together; Hub CI
  `TestRealTemplates*` and templates CI → green.

## Phase 7 — e2e, docs, deploy

### Task 16: CI e2e `e2e-folders` (core repo)

**Files:** `.github/workflows/ci.yml` (job `e2e-folders`, modelled on
`e2e-instances`, the Hub built from the same-named branch, templates
`folders` for jellyfin), `tests/e2e/e2e_folders.py` (new),
`tests/e2e/apps/folder-writer/` (fixture: alpine service as `user:
"2001:2001"`, umask 022, a `path` option `shared` with
`folder: {access: write, runs_as: {uid: 2001, gid: 2001}}` that writes
`/shared/new-<n>.txt` on start, and a `lan_only` tcp port).

- [ ] **Step 1: scenarios.**
  1. On the runner, create `/srv/e2e-media` with 50 files `1000:1000`
     `0640` and dirs `0750` (`sudo`); install `acl`.
  2. Hub API (admin): enable jellyfin and folder-writer; `POST
     /api/folders/check` → `exists · ext4 · ACLs and xattrs supported ·
     50 files`.
  3. Create folder `media` → gid 60000. Assign preview (jellyfin movies
     read, writer shared write) → lines name gid 60000, "group 1000 keeps
     read" and the restarts.
  4. Apply → op `ok`. Verify on the host: every entry gid 60000; dirs
     setgid; `getfacl` default `group::rwx`, `mask::rwx`, `group:1000:r-x`;
     the writer's new file is gid 60000 and group-writable; inside
     jellyfin `id -G` contains 60000 and `touch /data/movies/x` fails
     read-only.
  5. Doctor: no `folder_owner` finding. `sudo chgrp 1000` one file →
     `POST /api/doctor/scan` → a `folder_owner` Warning.
  6. Undo preview → apply → the tree is back to `1000:1000`, no ACL
     xattrs (`getfacl --skip-base` prints nothing).
  7. Exposure: the writer's `lan_only` port on `0.0.0.0` → Warning;
     rebind to `127.0.0.1` → the container port is published on
     127.0.0.1 only (`docker port`), the finding is gone.
  8. Confirm the socket proxy needed no new flag (the job uses core's
     unchanged `socket-proxy-hub`).
- [ ] **Step 2: run** the job on `folders` (`workflow_dispatch`) until
  green; keep artifacts on failure.
- [ ] **Step 3: commit and push** (core):
  `e2e: shared folders (assign, verify, drift, undo) and LAN-only exposure`.

### Task 17: Docs (docs repo)

**Files:** `docs/operations/hub.md` (Shared folders, Doctor, Local
networks), `docs/operations/hardening.md` (the fixer helper and its
capabilities, LAN-only ports and why Docker bypasses ufw),
`docs/operations/backups.md` (shared folders aren't in instance backups;
permission snapshots and undo), `docs/guides/manifest-reference.md` and
`docs/guides/adding-an-app.md` (folder block, checks, lan_only),
`docs/operations/testing.md` (`e2e-folders`, the `fixerroot` test),
`docs/architecture.md` (folders and doctor), `scripts/generate-app-docs.py`
(render folder access and checks), regenerated `docs/apps/*.md`.

- [ ] **Step 1:** write the pages, run the generator against templates
  `folders`, `zensical build --strict --clean` → no warnings.
- [ ] **Step 2:** commit `docs: shared folders, doctor, local networks` and
  push `folders`.

### Task 18: Deploy and live check

- [ ] **Step 1: merge and deploy.** Merge docs → Hub → core → templates
  (`.core-ref` back to `main`), then `./portcullis upgrade` on the test
  server.
- [ ] **Step 2: live checks** with a throwaway directory under `/srv`
  and throwaway instances, removed afterwards:
  1. Check path shows the real filesystem and owners.
  2. A folder used by jellyfin (read) and one writer: apply, then a file
     created by the writer is readable by jellyfin.
  3. The Doctor tab shows the expected findings and no false Problem on
     the existing apps; record any finding the admin would call noise.
  4. Undo restores the original ownership.
  5. `docker ps -a --filter label=io.portcullis.hub.helper` is empty
     after each op.
- [ ] **Step 3: report** the results and the noise list.

---

## Not in this plan

- Nextcloud/OxiCloud folder settings (spec Open question 1); Samba and
  Time Machine templates, per-person uids and `uid_from`/`gid_from`
  (project 3).
- Delegates seeing findings (Open question 5), access tightening (Open
  question 2), an external reachability probe (Open question 3).

## Interfaces for later plans

Project 3 (file sharing) builds on these exact names. Project 1's names
(`templates.Option`, `ReservedFeature`, `settings.Registry`,
`Mounter.HostPath`, `FolderSource`, `PathUsages`, `Option.Checks`) keep
their meaning; this list adds to them.

**Manifest (`internal/templates/folders.go`, contract §13):**
- `Option.Folder *FolderSpec` (yaml `folder`), `Option.Checks []Check`
  (yaml `checks`).
- `FolderSpec{Access, RunsAs *RunsAs, JoinsGroup string; MustOwn bool}`,
  `(*FolderSpec).Join()`, `(*Option).FolderAccess()`.
- `RunsAs{UID, GID *int; UIDEnv, GIDEnv, UIDFrom, GIDFrom string}`.
  - `UIDFrom` / `GIDFrom` (yaml `uid_from` / `gid_from`) are **parsed and
    refused** by `ReservedFeature` with "file sharing (project 3)". They
    hold an option key of the same template. Project 3 defines which
    option types they may name (its `person_id`), removes the refusal,
    and makes the Hub's ownership/doctor code treat the uid as per
    person (`PathUsage.OwnerKnown = false` today).
  - One source per id (`uid` | `uid_env` | `uid_from`, same for gid).
- `JoinGroupAdd = "group_add"`, `JoinGIDEnv = "gid_env"`,
  `JoinTemplate = "template"`. With `template` the Hub adds no
  `group_add` and only sets `PORTCULLIS_FOLDER_GID_<KEY>`.
- `FolderRead = "read"`, `FolderWrite = "write"`.
- `Check{Kind, Reason string; Needs, Not []string; Min string}`;
  `CheckKinds` = `filesystem`, `exclusive`, `free_space`,
  `requires_group_value`, `lan_only` (`CheckFilesystem`, `CheckExclusive`,
  `CheckFreeSpace`, `CheckRequiresGroupValue`, `CheckLANOnly`). Adding a
  kind = Hub code + contract change.
- `Port.LanOnly bool` (yaml `lan_only`).
- `FolderGIDVar(key)` = `PORTCULLIS_FOLDER_GID_<UPPER(key)>`,
  `FolderUIDVar(key)` = `PORTCULLIS_FOLDER_UID_<UPPER(key)>`;
  `ReservedVar` covers the `PORTCULLIS_FOLDER_` prefix.
- `TypeFolder` stays reserved and unused (shared folders are `path`
  values).

**Settings (`internal/settings`):**
- `FolderRefPrefix = "folder:"`, `FolderIDRe`,
  `ParseFolderRef(v string) (id, sub string, ok bool, err error)`,
  `ErrFolderRef` (the path kind's `HostPath` for a ref).

**Fixer (`internal/folderfix`, subcommand `hub folderfix`):**
- Modes `probe`, `scan`, `snapshot`, `apply`, `restore`; flags as in
  Task 4.
- `Options{Root; ExpectDev, ExpectIno; Target; Principals; Children; MaxEntries; MaxTime}`,
  `Target{GID; Files; OwnerUID *int; Mkdir []string}`,
  `Principal{UID int; GIDs []int; Write bool; Name string}`.
- `Report` with `FSType`, `ACL`, `Xattr`, `Owners`, `Principals
  []PrincipalAccess{CantRead, CantWrite Count}`, `Expected *Conformance`,
  `Plan *PlanCounts`, `FreeBytes`, `Partial`.
- **Per-person trees:** `Options.Children = true` (flag `--children`)
  fills `Report.Children []ChildOwner{Name; UID, GID int; Entries,
  Foreign int64}`: one entry per first-level subdirectory, `Foreign` =
  entries in it not owned by `UID`. Project 3's per-person subfolder
  checks (`<folder>/<person>` owned by that person's uid) read this.
- `Scan`, `WriteSnapshot`, `Apply`, `Restore`, `FSName`, `Unsupported`,
  `Allowed`, `ACL`/`Entry`/`DecodeACL`/`Encode`.

**Docker (`internal/docker`):**
- `RunSpec{Image; Cmd; User; Binds []BindMount; Scratch; CapAdd; Label; Pids; Memory; Timeout; InPath; In; OutPath}`,
  `BindMount{Source, Target string; ReadOnly, Create bool}`,
  `(*Client).RunHelper(ctx, s, out func(io.Reader) error) (*RunResult, error)`,
  `(*Client).InspectContainer(ctx, id) (ContainerInfo, error)`. Hub
  `Engine` has both.
- Hub internal: `runFixer(ctx, fixerRun) (*folderfix.Report, error)`,
  `selfImage(ctx)`; `Config.FixerImage` (`HUB_FIXER_IMAGE`).

**Hub (`internal/hub`):**
- State: `AppState.Folders map[string]state.Folder`,
  `AppState.FolderGIDs []int`, `AppState.DoctorMutes map[string]state.DoctorMute`,
  `AppState.LocalNetworks []string`;
  `state.Folder{Name, Path, Description; GID; Adopted; CreatedAt; WriteConfirmed map[string]bool; LastApply *FolderApply}`.
- Gids: `FolderGIDMin = 60000`, `FolderGIDMax = 60999`; project 3's
  person uids stay in 10000–59999.
- Folders: `Folders() []FolderView`, `CheckFolderPath`, `CreateFolder`,
  `UpdateFolder`, `DeleteFolder`, `hubFolders` (the `FolderSource`),
  `folderUsesLocked(id) []FolderUseView`. Assignments are derived from
  `folder:` setting values.
- Assignment: `FolderUse{Instance, Key, Subpath; Write}`,
  `AssignRequest{Uses}`, `AssignPlan{…; Hash}`, `PreviewAssign`,
  `StartAssign`, `PreviewUndo`, `StartUndo`, `opKeyFolder(id)` =
  `_folder.<id>`, `folderLock(id)`. `SaveSettings` refuses `folder:`
  value changes (409): they go through `StartAssign`.
- `PathUsage` gains `Folder, Subpath, JoinsGroup, Source string; MustOwn,
  Declared bool; GIDs []int; Checks []templates.Check`; `Source` is
  `setting` | `folder` | `custom_override`.
- **Local networks:** `DefaultLocalNetworks`, `(*Hub).LocalNetworks()
  []netip.Prefix`, `LocalNetworksView()`, `SetLocalNetworks(cidrs, actor)`
  (audited `settings.local_networks`), `IsLocal(addr, nets) bool`
  (unmapped; loopback always local), `domainAddrs(ctx)`. Project 3's
  LAN/VPN-only file sharing uses `IsLocal` and the `lan_only` port flag;
  the exposure warning is this project's `lan_only_exposed` finding.
- **Doctor:** `Doctor(ctx) (*doctor.Report, error)`, `doctorInputs(ctx)`,
  `StartDoctorScan(actor)` (op key `_doctor`), `RunDoctorScans`,
  `scanTargetsLocked() []ScanTarget{Path, Folder; Principals; Target}`,
  `MuteFinding`, `UnmuteFinding`, `PreviewFix`, `ApplyFix`,
  `FixPlan{FP, Kind, Lines, Warnings, Assign, Hash}`,
  `Fixer` interface (`Kind`, `Preview`, `Apply`) with
  `RegisterFixer(f Fixer)`. Project 3 adds per-person tree scans by
  setting `Children` on its folders' `ScanTarget`s, and adds fixers
  (e.g. revoking a leaver's file-share password) through `RegisterFixer`.

**Doctor (`internal/doctor`, no Hub import):**
- `Severity` (`Problem`, `Warning`, `Info`), `FixClass` (`one_click`,
  `explain`, `link`), `Finding{FP, Kind, Severity, Title, Why, Fix,
  Instances, Folders, Paths, Class, FixKind, Steps, Link, Partial,
  Inputs, Muted}`, `Link{Instance, Option}`, `Mute`.
- `Inputs{Now; BindRoots; Folders []FolderIn; Paths []PathIn; Ports
  []PortIn; Person []PersonIn; LocalNetworks; DomainAddrs; Scans
  map[string]ScanIn}`. Project 3 adds its own input fields (e.g.
  credentials per instance) next to these.
- `Check` interface `{Kind() string; Run(in *Inputs) []Finding}`,
  `Register(c Check)`, `Fingerprint(kind, subjects...)`, `Digest(v)`,
  `Run(in, mutes) Report`.
- Built-in kinds: `shared_path`, `path_outside_roots`,
  `undeclared_template`, `primary_gid_conflict`, `custom_override_mount`,
  `must_own_conflict`, `exclusive`, `person_option`, `lan_only_exposed`,
  `host_network`, `folder_owner`, `filesystem`, `free_space`, `no_acl`,
  `skipped_entries`, `scan_failed`.

**API (Hub listener, admins only) and audit:**
- `/api/folders` (GET, POST), `/api/folders/{id}` (PUT, DELETE),
  `/api/folders/check`, `/api/folders/{id}/assign/{preview,apply}`,
  `/api/folders/{id}/undo/{preview,apply}`, `/api/folders/{id}/op`,
  `/api/doctor`, `/api/doctor/scan`, `/api/doctor/op`,
  `/api/doctor/findings/{fp}/{preview,apply,mute}`,
  `/api/settings/local-networks`.
- Audit actions: `folder.create`, `folder.update`, `folder.delete`,
  `folder.assign`, `folder.apply`, `doctor.fix`, `doctor.mute`,
  `doctor.unmute`, `settings.local_networks`.

**UI:** `window.PortcullisFolders.render(el)`, `.openAssign({folder, add})`;
`window.PortcullisDoctor.render(el)`, `.badge(tabEl)`, `.lineFor(instance)`.
