# App Settings Panel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Templates declare typed settings (instance, per-person, per-group).
The Hub renders the panel, validates the values, resolves per-person values
from LDAP groups with a "who gets what" preview, and delivers them through
env, mounts, data files, hooks, per-client OIDC claims or per-host headers.
It restarts only when a changed option needs it. People see their own
values under My apps.

**Architecture:**
- **Pure core.** A new package `internal/settings` holds:
  - the type registry (parse to canonical, display, compare, render);
  - resolution and reasons;
  - effects and the wire formats.
  It has no I/O and no Hub state, so projects 2 and 3 register their
  types there.
- **Manifest.** `internal/templates` gets the manifest v3 model
  (`settings.options`, `files`, `hooks`, `reload`) and validates it at
  discover.
- **Hub.**
  - `state.yaml` stores typed per-instance settings. Secret values live
    only in `<data>/settings/<id>/secrets.json`.
  - A per-instance delivery engine (`internal/hub/deliver*.go`) works out
    the desired outputs from state and directory membership. It compares
    them with the last delivered hashes and applies only what changed.
    Membership-driven runs are debounced 60 s.
- **Core.** group-gate reads `user-attributes.json` v2 (per-host headers).
  Core mounts `./appfiles` into the Hub so data files are host-visible
  bind sources.

**Tech Stack:**
- Hub: Go, gopkg.in/yaml.v3, gocloak, moby client, plus these new pinned
  modules:
  - `github.com/docker/go-units` (sizes; today an indirect dependency, now
    direct);
  - `github.com/xhit/go-str2duration/v2` (durations with `d`/`w`);
  - `github.com/robfig/cron/v3`;
  - `golang.org/x/text/language`;
  - `golang.org/x/mod/semver`;
  - `time/tzdata` (embedded zone database).
- Core: Python group-gate.
- Templates: JSON Schema + `tests/validate.py`.
- Docs: zensical.

**Spec:** `docs/superpowers/specs/2026-11-02-app-settings-panel-design.md` (hub repo)

**Bases.** The plan is written against these local HEADs:

| Repo | Base |
|---|---|
| hub | `main` `bfbb3d4` |
| core | `main` `6d29200` |
| docs | `main` `12025d3` |
| templates | `new-apps` `aeac394` |

- `origin/instances` is already merged into hub and core `main`. Any
  other in-flight `instances` work is **not** assumed.
- Templates `main` (`17c0726`) lacks gitea, matrix, paperless and the 15
  Craft templates, which the conversions need. Cut the templates branch
  from `new-apps`, or from `main` once `new-apps` has landed there.

**Branches and CI order.**
- Every repo works on a branch named **`settings`**, the same pattern as
  `instances`.
- The CI pairing that follows from the name:
  - Hub CI clones the same-named templates and core branches
    (`TestRealTemplates*`, `TestCore*Complete`).
  - Core CI builds the Hub from its same-named branch
    (`.github/actions/hub-image`).
  - Templates CI reads `.core-ref`. Set it to `settings` on the branch, and
    back to `main` before merging.
- Work order: contract (T1) → core (T2) → Hub (T3–T15) → templates
  (T16–T17) → e2e (T18) → docs (T19) → deploy (T20).
- Hub `TestRealTemplates*` stays red from T3 until templates T17 is pushed.
  So push hub, templates and core `settings` together at the end of
  Phase 6.
- Merge order: docs → core → Hub → templates (spec call 26: core merges
  before the Hub).

## Global Constraints

- **No migration or back-compat code.**
  - There are no installs. Templates are converted, not shimmed.
  - `user-attributes.json` is v2 only.
  - The old types `text`/`boolean`/`select`/`paths` and
    `env[].generate: none` are refused.
- **Template contract v3** (breaking, MAJOR bump in hub, core, templates
  and docs).
  - Contract changes go into `portcullis-docs/docs/guides/integration-contracts.md`
    first.
- **Option key:** `^[a-z][a-z0-9_]{0,39}$`.
  - An env delivery names its variable.
  - An instance option without `delivery` uses env `upper(key)`.
  - The validator refuses:
    - reserved env names (`ReservedVar`, `PORTCULLIS_*`);
    - env names that compose hard-codes;
    - duplicate env names.
- **Types:** `string` `int` `size` `duration` `bool` `enum` `multi_enum`
  `list` `table` `path` `secret` `group` `groups` `user` `users`.
  - Reserved and refused by this Hub: `folder`, `person_secret`,
    `person_id`.
  - `string` formats: hostname ip cidr url email iana_tz locale cron
    semver hex.
- **Canonical values:**
  - size: bytes (int64);
  - duration: seconds (int64);
  - `unlimited` is a distinct value (`settings.Unlimited{}`, stored as
    the string `unlimited`).
  - Sizes are shown in binary units (MiB/GiB/TiB, labelled so).
- **Scopes** `instance` | `person` | `group`.
  - `person` needs a `default` and at least one per-person delivery
    (claim, header, file, hook). Per-person env is refused.
- **Resolution:**
  - `max`/`min` on int, size, duration, enum by option order;
  - `priority` on any type, the admin's row order;
  - `union`/`intersection` on list, multi_enum, groups;
  - `any`/`all` on bool.
  - The default is a fallback only, for people in no row's group. It never
    takes part in max/min/union.
  - `unlimited` beats any number under `max` and loses under `min`.
- **Applies** `live` `reload` `next_sign_in` `next_request` `restart`
  `account_creation`.
  - Effect order: none (`live`, `next_request`, `next_sign_in`,
    `account_creation`) < `reload` < `restart`.
  - One save, or one debounce window, runs at most one reload or restart.
- **Population** (call 27):
  - with an access group (group access on, or the access role enforced):
    its members, minus expired-but-not-removed `expiring` entries;
  - otherwise: every LLDAP user except the service account;
  - `sign_in: native`: empty;
  - admin, extra and core groups never widen it; public routes add nobody.
- **Privileged options** (call 9, 28):
  - per-group values only from manual groups, or from rule groups whose
    rules use admin-only fields only and don't match an empty person;
  - such groups become guarding groups ("a privileged value of app
    `<id>`");
  - the default is the lowest-ranked value.
- **`group_values`:** placeholders `{{ACCESS_GROUP}}` / `{{ADMIN_GROUP}}`
  only, stored as placeholders.
- **Group references:** every row and record stores the LLDAP group id. A
  name+id mismatch grants nothing and is purged (`settings.purge`, actor
  `hub`).
- **Secrets:** write-only.
  - GET answers `{set, updated_at}` only.
  - Never on argv, in logs, the audit, op output or API answers.
  - Redact, then clip.
  - Never in `state.yaml`.
- **Admin-only, audited.**
  - Settings routes are on the Hub listener and are `adminOnly`;
    delegates get 403.
  - Audit actions: `settings.change` (instance/key, scope, group,
    before → after; secrets: `replaced`/`generated`/`cleared`, actor) and
    `settings.purge`.
- **People listener:** exactly one app route, read-only and caller-only:
  `GET /api/me/apps` (contract §5.1).
- **Claims** (call 12):
  - one Hub-owned LLDAP attribute per (instance, option): `ps_` + the
    first 12 hex of sha256(`<instance>\x00<key>`), STRING, not visible,
    not editable;
  - an LDAP mapper plus a protocol mapper on **that instance's client
    only**, both named `portcullis-setting-<attr>`.
- **Headers** (call 13, 26):
  - names are `X-Forwarded-Attr-<Name>`;
  - only on routers with `portcullis-groups`;
  - written under every such host of the instance;
  - refused with a public router on the delivering service, and with
    `sign_in: native`.
- **Data files:**
  - written to `<appfiles>/<id>/<name>/<name>.json`, plus
    `<name>.secrets.json` for secret values;
  - atomic writes; 0640, or 0600 for the secrets file;
  - the override bind-mounts the directory `<ProjectHostDir>/appfiles/<id>/<name>`
    read-only at `mount`, never the single file.
- **Hooks:**
  - argv list, no `sh -c`;
  - full desired state as JSON on stdin;
  - exit 0 = applied;
  - serialised per instance.
- **Debounce:** membership deliveries 60 s per instance
  (`settingsDebounce`).
- **Reload:**
  - signals `HUP`/`USR1`/`USR2` through `ContainerKill`;
  - applied = 2xx, and still running (and not unhealthy) after 10 s.
- **Locks:**
  - `Hub.mu` is never held across docker, LLDAP or Keycloak calls;
  - deliveries take a per-instance delivery lock (`deliverLock`);
  - restarts go through `Restart` (its own `lockApp`).
- **Libraries:** mature and pinned (Go modules in `go.sum`; Python with
  hashes). Images pinned `tag@sha256`, Actions by commit SHA.
- **Hub hygiene:**
  - run `go vet ./... && go test -race ./... && gofmt -l .` after every
    task;
  - update the CLAUDE.md layout/rules rows a task changes.
- **Frontend:**
  - vanilla JS, `escapeHtml`/`esc` everywhere, no inline handlers with
    data;
  - new assets go on the `//go:embed` line.

## Review Focus

1. **Env values with `$`, quotes, `#` or spaces** (secrets, generated
   values, formats).
   - Compose interpolates unquoted `.env` values.
   - Expected: env-delivered values are written single-quoted. A value
     containing `'` or a newline is refused at save, naming the option.
     The generated-secret alphabet never contains `'`.
   - Pinned in Task 7 (`TestEnvValueQuotingRoundTrip`).
2. **LLDAP or the directory unavailable** during a membership or save
   delivery.
   - Expected: the delivery is skipped with status "directory
     unavailable". Last delivered claims, headers and files are kept,
     never cleared to an empty population.
   - Pinned in Task 9 (`TestDirectoryDownKeepsLastDelivery`).
3. **Mixed-case usernames.** `X-Forwarded-User: Alice`, or LLDAP returning
   `Alice`.
   - Expected: data files, claims, headers and My apps are keyed by
     lowercase username. `/api/me/apps` for `ALICE` shows alice's apps only.
   - Pinned in Task 15 (`TestMyAppsCallerCaseFolded`).
4. **A template update that makes an option `privileged`** while rows come
   from rule groups delegates can steer.
   - Expected: those rows grant nothing from that moment, and are dropped
     with a warning on the next reconcile.
   - Also: a removed or retyped option drops its stored values.
   - Pinned in Task 8 (`TestPrivilegedAfterTemplateUpdate`).
5. **A delivery that started before a newer save,** or two saves racing.
   - Expected: the older run never overwrites newer files, attributes or
     headers (generation check). The last committed save wins with no lost
     rows.
   - Pinned in Task 9 (`TestStaleDeliveryDoesNotOverwrite`).

---

## Phase 1 — contract

### Task 1: Contract v3 (docs repo)

**Files:** `portcullis-docs/docs/guides/integration-contracts.md`:
- §1 versions;
- §3 template layout (v3);
- §4.1 user attributes v2;
- §5.1 the `/api/me/apps` route;
- §6 exec stdin, kill;
- §8 per-client setting mappers;
- §9.6 the reserved `ps_` attribute prefix, privileged groups as guarding
  groups;
- §11.5 backups carry settings;
- a new §13 Settings.

Also `docs/guides/manifest-reference.md` (the `settings` section only).

- [ ] **Step 1: §13 Settings.** Write these subsections:
  - **13.1 Options:** key rule, label, description, section, type,
    scope, required, default, privileged, self_visible, applies,
    requires, delivery.
  - **13.2 Types:** constraints per type, from Global Constraints and
    spec call 6:
    - `string`: pattern, min_len/max_len, format;
    - `int`: min/max/step, unit;
    - `size`: step, allow_unlimited;
    - `duration`: min/max;
    - `enum`/`multi_enum`: `options[{value,label}]`, order = rank;
    - `list`: `items`, min_items/max_items, unique;
    - `table`: `columns[{name,label,type,…}]`, `key_column`;
    - `path`: `target{service,mount}`, `mode ro|rw`, `needs read|write`,
      `writes_as{uid,gid}` (numbers or instance option keys);
    - `secret`: `generate{length,charset}`;
    - `group(s)`, `user(s)`.

    Reserved: `folder`, `person_secret`, `person_id`, plus the option
    keys `folder`, `checks`, `hash`, `length`, `revoke_on_leave`,
    `on_restore`, `pool`, `username`, `mount`. A Hub that doesn't
    implement them refuses the template with the reason.
  - **13.3 Scopes and population:** call 27, verbatim rules.
  - **13.4 Resolution:** call 2 and call 1 (the default is a fallback).
  - **13.5 Rendering:** `render{unit, integer, unlimited, true, false,
    join, format}`.
    - A value that doesn't fit the granularity is refused at save, naming
      the app and its unit.
    - Env values are single-quoted. `'` and newlines are refused.
  - **13.6 Deliveries:**
    - `env`;
    - mounts (`path`);
    - `claim{client,name,json_type int|string|bool|json,render}`;
    - `header{name,render}`;
    - `file{name,field,render}`;
    - `hook` + `render`.

    Plus the cross-checks of call 21, and the header refusals of call 26.
  - **13.7 Data files:**
    - `files[{name, service, mount, on_membership_change restart|reload|hook|none}]`;
    - host layout and modes (Global Constraints);
    - document `DataFileDoc` / `SecretsFileDoc`:
      ```json
      {"version":1,"instance":"<id>","values":{"<key>":<rendered>},"people":{"<lowercase user>":{"<field>":<rendered>}},"groups":{"<key>":[{"group":"<name>","value":<rendered>}]}}
      ```
      The secrets file is `{"version":1,"instance":"<id>","secrets":{"<key>":"<value>"}}`.
    - The reading service runs as root, or as uid/gid 10001
      (`group_add: ["10001"]`).
  - **13.8 Hooks and reload:**
    - `hooks[{name, service, command[], user, when[start|settings_change|membership_change], timeout}]`;
    - stdin `HookInput`: the data-file shape plus `"trigger"` and
      `"secrets"`;
    - exit codes, redaction, serialisation, retry;
    - `reload{service, signal HUP|USR1|USR2}` or `reload{hook}`, with the
      10 s grace rule.
  - **13.9 Applies and effects:** call 5 and call 25 ordering.
  - **13.10 Secrets:** call 18.
  - **13.11 Groups disappearing:** calls 19 and 29.
  - **13.12 Admin API:** the routes of Task 13, and the audit actions.
- [ ] **Step 2: §4.1 v2.**
  - `"version": 2` adds
    `"hosts": {"<full lowercase host>": {"<Header-Suffix>": {"<lowercase user>": "<value>"}}}`.
  - group-gate sends `X-Forwarded-Attr-<Header-Suffix>` only for that
    host, on allow.
  - The value is sent as is after control characters are stripped. Over
    1 KB it is dropped. There is no `,` encoding: it is one value.
  - A host header replaces a same-named field header on that host.
  - v1 is refused, the same as a corrupt file (no attribute headers).
- [ ] **Step 3: the other sections.**
  - **§5.1:** `GET /api/me/apps` is the people listener's only app
    route. Show the answer shape from Task 15 `MyApp`.
  - **§6:** exec gains stdin; `POST /containers/{id}/kill?signal=` is
    used (no socket-proxy change).
  - **§8:** "Setting claims" — the attribute and mapper names from Global
    Constraints, removed on instance delete.
  - **§9.6:** fields may not start with `ps_`. Privileged-option groups
    are guarding groups.
  - **§11.5:** `instance.yaml` `settings` carries the typed settings.
    `config/settings-secrets.json` holds the secret store. Restore drops
    rows whose group id no longer matches, with a warning.
  - **§1:** template contract v3 = MAJOR.
- [ ] **Step 4: manifest reference.** Update `manifest-reference.md`
  `## settings` to the v3 shape: the Immich example from the spec, and a
  type table.
- [ ] **Step 5: verify and commit.** Run `zensical build --strict --clean`,
  then commit on `settings`:
  `contracts: template contract v3 settings (§13), user-attributes v2, /api/me/apps`.

## Phase 2 — core

### Task 2: group-gate user-attributes v2 + `appfiles` mount (core repo)

**Files:**
- `group-gate/group-gate.py` (`parse_user_attributes`,
  `user_attribute_headers`, `_allow`, the docstring around line 98);
- `tests/test_group_gate.py`;
- `docker-compose.yml` (hub volumes);
- `scripts/lib/common.sh` (mkdir/chown at `up`, around line 400);
- `tests/test_shell_libs.sh`;
- `.gitignore`;
- `scripts/lib/backup.sh` (skip `appfiles/`);
- `CLAUDE.md`.

**Interfaces:**
- Produces:
  - `parse_user_attributes(doc) -> Tuple[dict, dict]`, i.e.
    `(users: {user: [(header, value)]}, hosts: {host: {user: [(header, value)]}})`;
  - `user_attribute_headers(username: str, host: str) -> List[Tuple[str, str]]`;
  - the Hub's `/project/appfiles` (rw), host `<core>/appfiles`, owned by
    10001.

- [ ] **Step 1: tests** in `tests/test_group_gate.py`:
  - `test_attributes_v2_host_headers`: the doc has a field `department`
    and `hosts["grafana.portcullis.local"]["Grafana-Role"]["alice"]="Admin"`.
    alice on that host gets `X-Forwarded-Attr-Grafana-Role: Admin` and
    `X-Forwarded-Attr-Department`.
  - `test_host_header_only_on_its_host`: alice on
    `other.portcullis.local` gets no `Grafana-Role`.
  - `test_attributes_v1_refused`: `version: 1` gives no attribute
    headers at all; the request is still allowed.
  - `test_host_header_replaces_field_header`: a field header `Role` and a
    host header `Role` → one header, with the host value.
  - `test_host_header_invalid_name_skipped`: a suffix failing
    `_ATTR_HEADER_RE` is skipped and logged; the others are kept.
  - `test_host_header_value_limits`: control characters are stripped, a
    value over 1024 bytes is dropped, and `,` is sent verbatim.
  - `test_host_keys_normalised`: an uppercase host key in the file is
    ignored and logged (keys must be lowercase valid hostnames).
- [ ] **Step 2: run them.**
  `PYTHONDONTWRITEBYTECODE=1 python3 tests/test_group_gate.py -k attributes -k host_header`
  → FAIL.
- [ ] **Step 3: implement.**
  - Accept only `version == 2`.
  - Cache `(users, hosts)` together under the existing stat key.
  - `_allow` passes `host` (already normalised by `normalize_host`).
- [ ] **Step 4: tests** in `tests/test_shell_libs.sh`:
  `up` creates `appfiles/` with owner 10001 and mode 0750; the backup
  skips it.
- [ ] **Step 5: implement the mount.**
  - `- ./appfiles:/project/appfiles:rw` on the hub service, with the same
    comment style as `./templates`.
  - Add the mkdir/chown next to `templates`, and `appfiles/` to
    `.gitignore`.
  - The backup excludes it: the Hub regenerates it from state.
- [ ] **Step 6: run all core suites** (`tests/test_group_gate.py`,
  `tests/test_shell_libs.sh`, `tests/test_cli.sh`) → PASS. Then commit on
  `settings`:
  `group-gate: user-attributes v2 per-host headers; hub appfiles mount`.

## Phase 3 — Hub foundations

### Task 3: Manifest v3 settings model and validation

**Files:**
- Create: `internal/templates/settings.go`,
  `internal/templates/settings_test.go`.
- Modify:
  - `internal/templates/manifest.go`: remove `Setting`; `Manifest`
    gains `Settings *SettingsSpec`, `Files`, `Hooks`, `Reload`.
  - `internal/templates/validate.go`: `ValidateManifest`,
    `manifestKeys`, refuse `generate: none`.
  - `internal/templates/discover.go`: call `ValidateSettingsSpec` after
    `ParseRoutes`.
- Mechanical adaptation of the callers that iterate
  `m.Settings.Options`:
  - `internal/hub/override.go:42` (path mounts);
  - `settings.go` (env loop);
  - `restore.go:660`;
  - `httpapi`.

  Path values stay flat strings until Task 6.
- Every test manifest under `internal/*/testdata` and in the Go test
  fixtures.

**Interfaces:**
- Produces (`internal/templates/settings.go`):
```go
type SettingsSpec struct {
    Sections []string `yaml:"sections" json:"sections,omitempty"`
    Options  []Option `yaml:"options" json:"options"`
}
type Option struct {
    Key, Label, Description, Section string // yaml: key,label,description,section
    Type, Scope, Applies                 string // Scope "" = instance
    Required                             bool
    Default                              any     `yaml:"default"`
    Pattern, Format                      string
    MinLen, MaxLen, MinItems, MaxItems   *int
    Min, Max, Step                       any     // numbers, or "1GiB"/"30d" strings
    Unit                                 string
    AllowUnlimited                       bool
    Choices                              []EnumOption `yaml:"options"`
    Items                                *ItemSpec    // list
    Unique                               bool
    Columns                              []Column     // table
    KeyColumn                            string       `yaml:"key_column"`
    Target                               *SettingTarget // path
    Mode, Needs                          string         // ro|rw, read|write
    WritesAs                             *Owner         `yaml:"writes_as"`
    Generate                             *GenerateSpec  // secret
    Resolve                              string
    ResolveChoices                       []string       `yaml:"resolve_choices"`
    GroupValues                          map[string]any `yaml:"group_values"`
    Privileged                           bool
    SelfVisible                          *bool          `yaml:"self_visible"` // nil = true
    Requires                             []string
    Delivery                             Deliveries
    // Reserved for projects 2 and 3 (parse-only; ReservedFeature refuses them):
    Folder        map[string]any   `yaml:"folder"`
    Checks        []map[string]any `yaml:"checks"`
    Hash          string           `yaml:"hash"`
    Length        int              `yaml:"length"`
    RevokeOnLeave *bool            `yaml:"revoke_on_leave"`
    OnRestore     string           `yaml:"on_restore"`
    Pool          string           `yaml:"pool"`
    Username      map[string]any   `yaml:"username"`
    Mount         *OptionMount     `yaml:"mount"`
}
type EnumOption struct{ Value, Label string }
type ItemSpec struct{ Type, Pattern, Format string; Min, Max any; Choices []EnumOption `yaml:"options"` }
type Column struct{ Name, Label, Type, Pattern, Format string; Required bool; Choices []EnumOption `yaml:"options"` }
type Owner struct{ UID, GID OwnerRef }        // yaml uid/gid: a number or an option key
type OwnerRef struct{ Num *int; Key string } // UnmarshalYAML
type GenerateSpec struct{ Length int; Charset string } // charset: alnum|hex|base64url
type OptionMount struct{ Service, Path string }
type Deliveries []Delivery // UnmarshalYAML: a sequence, or the scalar file|hook → {{Bare: "file"}}
type Delivery struct {
    Env    string          `yaml:"env"`
    Claim  *ClaimDelivery  `yaml:"claim"`
    Header *HeaderDelivery `yaml:"header"`
    File   *FileDelivery   `yaml:"file"`
    Hook   string          `yaml:"hook"`
    Render *Render         `yaml:"render"` // for env and hook
    Bare   string          `yaml:"-"`      // scalar form (project 3 person_secret only)
}
type ClaimDelivery struct{ Client, Name string; JSONType string `yaml:"json_type"`; Render *Render }
type HeaderDelivery struct{ Name string; Render *Render }
type FileDelivery struct{ Name, Field string; Render *Render } // Field "" = option key
type Render struct {
    Unit      string
    Integer   bool
    Unlimited *string
    True      *string `yaml:"true"`
    False     *string `yaml:"false"`
    Join      *string
    Format    string // json|yaml|csv
}
type DataFile struct{ Name, Service, Mount string; OnMembershipChange string `yaml:"on_membership_change"` }
type Hook struct {
    Name, Service, User string
    Command             []string
    When                []string
    Timeout             Duration // "60s"; default 30s, max 10m
}
type Reload struct{ Service, Signal, Hook string }
type Duration time.Duration // UnmarshalYAML via time.ParseDuration

const (TypeString="string"; TypeInt="int"; TypeSize="size"; TypeDuration="duration"; TypeBool="bool"
    TypeEnum="enum"; TypeMultiEnum="multi_enum"; TypeList="list"; TypeTable="table"; TypePath="path"
    TypeSecret="secret"; TypeGroup="group"; TypeGroups="groups"; TypeUser="user"; TypeUsers="users"
    TypeFolder="folder"; TypePersonSecret="person_secret"; TypePersonID="person_id")
const (ScopeInstance="instance"; ScopePerson="person"; ScopeGroup="group")
const (AppliesLive="live"; AppliesReload="reload"; AppliesNextSignIn="next_sign_in"
    AppliesNextRequest="next_request"; AppliesRestart="restart"; AppliesAccountCreation="account_creation")
const (ResolveMax="max"; ResolveMin="min"; ResolvePriority="priority"; ResolveUnion="union"
    ResolveIntersection="intersection"; ResolveAny="any"; ResolveAll="all")
const (HookStart="start"; HookSettingsChange="settings_change"; HookMembershipChange="membership_change")
var HookTriggers = map[string]bool{HookStart: true, HookSettingsChange: true, HookMembershipChange: true}
var BuiltinTypes = map[string]bool{ /* the 15 implemented types above, not the 3 reserved */ }
var OptionKeyRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)
const PlaceholderAccessGroup, PlaceholderAdminGroup = "{{ACCESS_GROUP}}", "{{ADMIN_GROUP}}"

// Scope returns o.Scope or ScopeInstance.
func (o *Option) EffectiveScope() string
// EnvName is the env variable an instance option delivers to ("" = none).
func (o *Option) EnvName() string
// ReservedFeature names the project-2/3 feature o uses ("" = none).
func ReservedFeature(o *Option) string
// ValidateSettingsSpec checks t's settings against its manifest, compose
// and routes. known reports whether the Hub implements a type
// (settings.Registry.Known); a reserved or unknown type is refused with
// "type X needs <feature>".
func ValidateSettingsSpec(t *Template, compose []byte, routes *Routes, known func(typ string) bool) error
```
- `Discover(dir, source, domain string, known func(typ string) bool) []Template`
  gains the `known` parameter (today `Discover(dir, source, domain)`;
  `hub.go:336` passes `h.kinds.Known`). When `known` is nil, exactly
  `templates.BuiltinTypes` (the 15 implemented type names) count as known.
  `templates` can't import `settings`: that would be an import cycle.

- [ ] **Step 1: tests** in `settings_test.go`. Each test is a table of
  fixtures; each fixture is refused with a message naming the option:
  - `TestOptionKeyRule`: `IMMICH_X` and `1a` are refused; `trash_days`
    passes.
  - `TestOldTypesRefused`: `text`, `boolean`, `select` and `paths` are
    refused, each with a hint naming the replacement.
  - `TestReservedTypesRefused`: `folder` → "shared folders (project 2)";
    `person_secret` and `person_id` → "file sharing (project 3)". A
    `folder:` block on a path option is refused too.
  - `TestPersonScopeNeedsDefaultAndPersonDelivery`:
    - no default → refused;
    - env-only delivery → refused ("per-person env is not allowed");
    - a claim delivery → OK.
  - `TestResolveFitsType`: `max` on `string` is refused; `union` on
    `list` is OK; `resolve_choices` must each fit.
  - `TestEnvNames`:
    - `PORTCULLIS_X` is refused;
    - a duplicate between two options, or with `env[]`/`ports[]`, is
      refused;
    - an env name not referenced as `${NAME` in compose.yml is refused;
    - an env name compose hard-codes (`environment: {NAME: literal}`) is
      refused.
  - `TestClaimDeliveryNeedsNativeOIDCClient`:
    - a forward-auth template with a claim → refused;
    - `client` not in `keycloak_clients` → refused;
    - claim names `sub`, `email`, `groups`, `acr`, `amr`,
      `preferred_username`, `attr_x` and `portcullis_*` → refused.
  - `TestHeaderDeliveryRules`:
    - a name not `X-Forwarded-Attr-<Name>` → refused;
    - a template whose routers lack `portcullis-groups` → refused;
    - a delivering service with a router `public_access` marks public →
      refused.
  - `TestFileAndHookRefs`:
    - `file.name` / `hook` must name a declared file / hook;
    - the file `service` must exist;
    - `mount` must be absolute and not collide with a path option's
      target on that service;
    - a hook `command` must be non-empty argv;
    - `when` ⊆ `HookTriggers`.
  - `TestReloadRules`: `applies: reload` or
    `on_membership_change: reload` without `reload:` → refused; a signal
    other than HUP/USR1/USR2 → refused; `reload.hook` must name a hook.
  - `TestGroupValuesPlaceholdersOnly`: a literal group name is refused;
    `{{ADMIN_GROUP}}` is OK.
  - `TestPrivilegedDefaultLowest`: an enum `[user, admin]` with
    `default: admin` and `privileged` is refused.
  - `TestRequires`: an unknown key, a self reference and a person-scope
    target are each refused.
  - `TestWritesAs`: a numeric value is OK; a key reference must name an
    instance `int` or `string` option.
  - `TestGenerateNoneRefused`: `env[].generate: none` is refused with
    the hint "declare a setting".
- [ ] **Step 2: run.**
  `go test -race ./internal/templates/ -run 'TestOption|TestOld|TestReserved|TestPerson|TestResolve|TestEnvNames|TestClaim|TestHeader|TestFile|TestReload|TestGroupValues|TestPrivileged|TestRequires|TestWritesAs|TestGenerateNone'`
  → FAIL (undefined).
- [ ] **Step 3: implement** the types and `ValidateSettingsSpec`.
  - Defaults and constraints whose canonical form needs a type (`size`
    `step`, enum default) are checked through `known` and Task 4's
    parsers. Until Task 4 lands, the type check in this task covers names
    only.
  - Wire Task 4's `settings.ParseDefault` into `ValidateSettingsSpec` at
    the end of Task 4.
- [ ] **Step 4: convert the fixtures.** Convert every Hub test fixture
  manifest to v3, and adapt the callers mechanically (path options still
  mount the flat string value).
- [ ] **Step 5: verify.** `go vet ./... && go test -race ./... && gofmt -l .`
  → PASS (except `TestRealTemplates*` without the templates branch).
- [ ] **Step 6: commit.**
  `templates: manifest v3 settings model and validation (contract §13)`.

### Task 4: Setting kinds — parse, display, render (`internal/settings`)

**Files:**
- Create in `internal/settings/`:
  - `registry.go`;
  - `kinds_scalar.go` (string int size duration bool enum);
  - `kinds_set.go` (multi_enum list table group groups user users);
  - `kinds_path.go`;
  - `kinds_secret.go`;
  - `formats.go`;
  - `render.go`;
  - the tests next to each.
- Modify: `internal/templates/settings.go` (wire `ParseDefault`), `go.mod`.

**Interfaces:**
- Consumes: Task 3 `templates.Option`, `templates.Render`.
- Produces:
```go
type Value = any // canonical: string | int64 | bool | []Value | []map[string]Value | Unlimited
type Unlimited struct{}
type Kind interface {
    Name() string
    CheckOption(o *templates.Option) error           // manifest-time constraints of this type
    Parse(o *templates.Option, raw any) (Value, error) // input (JSON-decoded or YAML) → canonical, constraints enforced
    Display(o *templates.Option, v Value) string        // "10 GiB", "Administrator"
    Compare(o *templates.Option, a, b Value) (int, bool) // false = not ordered
}
// Mounter: kinds whose value is a host directory (path; folder in project 2).
type Mounter interface{ HostPath(o *templates.Option, v Value) (string, error) }
// PerPersonKind: kinds whose per-person value the Hub computes, not resolves (project 3).
type PerPersonKind interface {
    PersonValues(ctx context.Context, instance string, o *templates.Option, people []Person) (map[string]Value, error)
}
type Registry struct{ /* kinds by name */ }
func NewRegistry() *Registry                     // every built-in kind of Global Constraints
func (r *Registry) Register(k Kind)              // replaces a kind of the same name
func (r *Registry) Kind(typ string) (Kind, error) // reserved, not registered → *ErrNotImplemented
func (r *Registry) Known(typ string) bool
func (r *Registry) Parse(o *templates.Option, raw any) (Value, error)
func (r *Registry) Display(o *templates.Option, v Value) string
type ErrNotImplemented struct{ Type, Feature string } // Feature "shared folders (project 2)" | "file sharing (project 3)"
func ParseDefault(o *templates.Option) error // NewRegistry().Parse(o, o.Default) when Default != nil
type Rendered struct{ Text string; JSON any } // Text: env/header/claim attribute; JSON: files and hooks
func Render(o *templates.Option, v Value, rd *templates.Render) (Rendered, error)
func ResolveOwner(o *templates.Option, instance map[string]Value) (uid, gid int, err error)
```

- [ ] **Step 1: tests.** Each one is table-driven, with the spec's values:
  - `TestSizeParse`:
    - `"10GiB"` and `10737418240` → `int64(10737418240)`;
    - `"unlimited"` with `allow_unlimited` → `Unlimited{}`, without it →
      error;
    - `"1.5GiB"` with `step: 1GiB` → error "must be a multiple of 1 GiB";
    - `Display(10GiB)` = `"10 GiB"`.
  - `TestDurationParse`: `"30d"` → `int64(2592000)`; `"90m"` →
    `5400`; min/max enforced.
  - `TestIntParse`: `min: 0`, `max: 3650`, `step: 5`; `"3651"` →
    error.
  - `TestStringFormats`: one valid and one invalid value per format:
    - hostname `a.example.com` / `-a`;
    - ip `10.0.0.1` / `10.0.0.300`;
    - cidr;
    - url `https://x` / `x`;
    - email;
    - iana_tz `Europe/Rome` / `Mars/Base`;
    - locale `it-IT`;
    - cron `*/5 * * * *`;
    - semver `1.2.3` / `1.2`;
    - hex.

    Plus pattern and min_len/max_len. Control characters are always
    refused.
  - `TestEnumRankAndCompare`: options `[Viewer, Editor, Admin]`; the
    comparison follows option order; an unknown value → error.
  - `TestMultiEnumAndList`:
    - set semantics;
    - `unique` duplicates → error;
    - `max_items: 8`;
    - item pattern `^/dev/`.
  - `TestTableParse`: typed columns; a required column; duplicate
    `key_column` values → error.
  - `TestUserGroupNames`: LLDAP name rules. `user` refuses `@`
    (usernames, never email).
  - `TestPathKind`:
    - `ValidatePathSetting` rules;
    - `folder:abc` → error "shared folders arrive in project 2";
    - `HostPath` returns the cleaned path;
    - `mode`/`needs` checked by `CheckOption`.
  - `TestRender`:
    - size 10GiB with `{unit: GiB, integer: true}` → Text `"10"`, JSON
      `10`;
    - 1.5GiB into GiB-integer → error naming the unit;
    - `Unlimited` with `{unlimited: "-1"}` → `"-1"`;
    - bool `{true: "yes", false: "no"}`;
    - list `{join: "+"}` → `"eng+ita"`;
    - list `{format: json}` → `["eng","ita"]`;
    - table `format: csv`.
  - `TestRenderRefusesNewlinesAndOversize`:
    - a rendered Text containing `\n` → error;
    - over 1024 bytes for header, or over 4096 bytes for a claim
      attribute → error naming the delivery.
  - `TestResolveOwner`: `{uid: 1000, gid: PGID}`, where `pgid` is 100 →
    `(1000, 100)`.
  - `TestRegistryReserved`: `Kind("person_id")` → `*ErrNotImplemented`
    with `Feature = "file sharing (project 3)"`. After `Register` of a
    stub kind, `Known("person_id")` is true.
- [ ] **Step 2: run.** `go test -race ./internal/settings/` → FAIL.
- [ ] **Step 3: implement.**
  - Sizes: `go-units` `RAMInBytes` (binary); display through
    `units.BytesSize`, with labels shown as KiB/MiB/GiB/TiB.
  - Durations: `str2duration.ParseDuration`.
  - Formats: `net/netip`, `net/url`, `net/mail`, `time.LoadLocation` (with
    `import _ "time/tzdata"`), `language.Parse`, `cron.ParseStandard`, and
    `semver.IsValid("v"+s)`. Hostname uses the templates package's
    hostname validator.
  - `Display` of `Unlimited` is `"unlimited"`.
- [ ] **Step 4: wire up and verify.** Wire `ParseDefault` and `Kind.CheckOption`
  into `templates.ValidateSettingsSpec`. Add
  `TestDefaultsCanonical` (templates package): a size default `"500GiB"`
  passes, `"500 gigs"` is refused. Then run
  `go vet ./... && go test -race ./... && gofmt -l .` → PASS.
- [ ] **Step 5: commit.**
  `settings: type registry, canonical values, formats, rendering`.

### Task 5: Resolution, reasons and effects (`internal/settings`)

**Files:** create `internal/settings/resolve.go`, `effects.go`,
`requires.go`, and their tests.

**Interfaces:**
- Consumes: Task 4 `Registry`, `Value`, `Compare`.
- Produces:
```go
type Person struct{ User string; Groups map[string]int } // lowercase user; group name → LLDAP id
type Row struct{ Group string; GroupID int; Value Value } // Group: a real name (placeholders resolved by the caller)
type PersonConfig struct{ Default Value; Rule string; Rows []Row } // Rule "" = o.Resolve
type Candidate struct{ Group string; Value Value }
type Reason struct {
    Source string      `json:"source"` // ReasonGroup | ReasonDefault | ReasonCombined
    Group  string      `json:"group,omitempty"`  // the winning row (max/min/priority)
    Groups []string    `json:"groups,omitempty"` // contributing rows (union/intersection/any/all)
    Rule   string      `json:"rule"`
    Others []Candidate `json:"others,omitempty"` // losing rows: admin preview only, never My apps
}
const (ReasonGroup="group"; ReasonDefault="default"; ReasonCombined="combined")
type Resolved struct{ Value Value; Reason Reason }
func (r *Registry) Resolve(o *templates.Option, c PersonConfig, p Person) Resolved
func (r *Registry) ResolveAll(o *templates.Option, c PersonConfig, people []Person) map[string]Resolved
const (EffectNone="none"; EffectReload="reload"; EffectRestart="restart")
func EffectOf(applies string) string
func Strongest(effects ...string) string
func CheckRequires(spec *templates.SettingsSpec, values map[string]Value) error // 400 text names both options
```

- [ ] **Step 1: tests.**
  - `TestDefaultIsFallbackOnly`:
    - default 500GiB, row `office_milan` 10GiB, rule max;
    - alice in office_milan → 10GiB, `{Source: group, Group: office_milan}`;
    - carol in no row group → 500GiB, `Source: default`.

    This is the anti-goal "the default beating a group value".
  - `TestMaxMinWithUnlimited`:
    - bob in `office_milan` (10GiB) and `it_staff` (unlimited);
    - max → unlimited, `Group: it_staff`, `Others: [{office_milan, 10GiB}]`;
    - min → 10GiB.
  - `TestPriorityRowOrder`: the rows are ordered `[it_staff, office_milan]`;
    bob gets it_staff's value. Reordered, he gets office_milan's.
  - `TestUnionIntersection`: on `multi_enum` and `groups`;
    `Source: combined`; `Groups` lists exactly the person's contributing
    rows, sorted.
  - `TestAnyAll`: on bool.
  - `TestEnumRankMax`: Viewer < Editor < Admin; Editor and Admin rows →
    Admin.
  - `TestRowIDMismatchGrantsNothing`: the row is
    `{office_milan, id 7}`, but the person's `Groups["office_milan"] = 9`
    → that row is skipped (call 29).
  - `TestEffects`:
    - `Strongest(none, reload)` = reload;
    - `Strongest(reload, restart, none)` = restart;
    - `EffectOf` maps `live`/`next_request`/`next_sign_in`/`account_creation`
      → none.
  - `TestCheckRequires`: `craft_version` is set and `craft_sha256` is
    empty → an error containing both keys; both empty → OK.
- [ ] **Step 2: run.** `go test -race ./internal/settings/ -run 'TestDefault|TestMax|TestPriority|TestUnion|TestAnyAll|TestEnumRank|TestRowID|TestEffects|TestCheckRequires'`
  → FAIL.
- [ ] **Step 3: implement.** Ties under max/min go to the earlier row.
  `Others` is filled only for multi-match max/min/priority.
- [ ] **Step 4: verify.** `go test -race ./internal/settings/` → PASS,
  plus vet and gofmt.
- [ ] **Step 5: commit.**
  `settings: per-person resolution, reasons, effects, requires`.

### Task 6: Typed state, instance-scope save, env/path delivery, effects, audit, backups

**Files:**
- `internal/state/state.go` (`InstanceSettings`);
- `internal/hub/settings.go` (`SettingsUpdate`, `SaveSettings`,
  `configProblems`, the `ValidateSettings` rewrite);
- `internal/hub/env.go` (instance option env, single-quoted);
- `internal/hub/override.go` (mounts through `settings.Mounter`, `:ro`
  for `mode: ro`);
- `internal/hub/hub.go` (`kinds *settings.Registry`, `SetFolderSource`);
- `internal/hub/paths.go` (new: `PathUsages`);
- `internal/hub/backup.go`, `restore.go` (`instanceConfig.Settings`);
- `internal/hub/instances.go` / `create.go` (seed defaults);
- `internal/hub/lifecycle.go` (seed on first enable);
- `internal/hub/ports.go`, `useroverride.go`, `hosts.go`
  (`h.st.Settings[id].Ports`);
- tests: `internal/hub/settings_test.go` (new) and the existing ones.

**Interfaces:**
- Consumes:
  - Task 3: `Option.EnvName`, `ValidateSettingsSpec`;
  - Task 4: `Registry.Parse`, `Render`, `Mounter`, `ResolveOwner`;
  - Task 5: `EffectOf`, `Strongest`, `CheckRequires`.
- Produces:
```go
// state
type InstanceSettings struct {
    Ports   map[string]string        `yaml:"ports,omitempty"`   // port keys and <KEY>_BIND, as before
    Values  map[string]any           `yaml:"values,omitempty"`  // instance scope, canonical
    Types   map[string]string        `yaml:"types,omitempty"`   // key → type at save (Task 8 prune)
    Person  map[string]PersonSetting `yaml:"person,omitempty"`  // Task 8
    Groups  map[string][]GroupValue  `yaml:"groups,omitempty"`  // Task 8
    Secrets map[string]SecretMeta    `yaml:"secrets,omitempty"` // Task 7; never values
}
type PersonSetting struct{ Default any `yaml:"default"`; Resolve string `yaml:"resolve,omitempty"`; Rows []GroupValue `yaml:"rows,omitempty"` }
type GroupValue struct{ Group string `yaml:"group"`; GroupID int `yaml:"group_id"`; Value any `yaml:"value"` }
type SecretMeta struct{ UpdatedAt time.Time `yaml:"updated_at"`; Generated bool `yaml:"generated,omitempty"` }
// AppState.Settings map[string]InstanceSettings

// hub
type SettingsUpdate struct {
    Ports   map[string]string
    Values  map[string]json.RawMessage // instance options; JSON null = back to the default
    Person  map[string]PersonChange    // Task 8
    Groups  map[string][]GroupValueInput // Task 8
    Secrets map[string]SecretChange    // Task 7
    // unchanged: Policy, Inherit, PublicAccess, PublicAccessDefault, PublicMode, PublicTokens, SignIn
}
type PersonChange struct{ Default json.RawMessage; Resolve string; Rows []GroupValueInput }
type GroupValueInput struct{ Group string; Value json.RawMessage }
type SecretChange struct{ Value *string; Generate, Clear bool }
type SaveResult struct{ Effect string; Changed []string; Warnings []string; Deliveries *DeliveryReport }
func (h *Hub) SaveSettings(id string, u SettingsUpdate, actor string) (*SaveResult, error)
type FolderSource interface{ FolderHostPath(id, subpath string) (string, error) } // project 2
func (h *Hub) SetFolderSource(f FolderSource)
func (h *Hub) Kinds() *settings.Registry
type PathUsage struct {
    Instance, Key, Type, HostPath, Service, Mount, Mode, Needs string
    UID, GID   int
    OwnerKnown bool
}
func (h *Hub) PathUsages() []PathUsage // every enabled instance's path-like option with a value
```
- Effects of `SaveSettings`:
  - It computes the changed options. `Effect` = `Strongest(EffectOf(o.Applies))`
    over changed options. A port or path change is always restart.
  - It restarts **only** for `EffectRestart` on an enabled instance.
  - Reload, and Task 9's deliveries for the other effects, run through
    `h.Deliver(ctx, id, TriggerSave)`. Until Task 9 that is a no-op stub
    returning an empty report.
  - It audits one `settings.change` per changed (key, scope, group).

- [ ] **Step 1: tests** in `settings_test.go`:
  - `TestSaveRestartsOnlyWhenNeeded`:
    - fixture options `trash_days` (applies restart, env) and `motd`
      (applies live, hook stub);
    - saving `motd` only → `Effect == "none"`, and no `Restart` call
      (the fake runner records ups);
    - saving both → one restart.
  - `TestSaveValidatesTypes`:
    - `trash_days: "x"` → 400 naming `trash_days`;
    - an unknown key → 400;
    - `requires` broken → 400 naming both.
  - `TestEnvDeliveryRendered`:
    - `trash_days: 30` → `.env` has `IMMICH_TRASH_DAYS='30'`;
    - null → the default;
    - a bool rendered with `{true: "1"}`.
  - `TestPathMountReadOnly`:
    - `mode: ro` → the override volume ends `:ro`;
    - `folder:x` values → 400 (no `FolderSource`);
    - with a fake `FolderSource` the override mounts its path.
  - `TestPathUsages`: they list host path, service, mount, mode, needs,
    and uid/gid from `writes_as` (a key reference resolved).
  - `TestSettingsAudited`: `settings.change`,
    `Target "immich/trash_days"`, `Detail "scope=instance: 30 -> 60"`,
    actor set. A refused save is audited `refused`.
  - `TestSeedOnCreate`: `CreateInstance` stores no instance values (the
    defaults apply implicitly). Person options get `PersonSetting{Default}`
    plus `group_values` rows with placeholders. The rows are bound in
    Task 8.
  - `TestBackupCarriesTypedSettings`: a backup → restore round trip keeps
    `Values`, `Person`, `Groups` and `Ports`. `instance.yaml` has no
    secret values.
  - Adapt the existing tests that wrote `Settings[id]` flat maps
    (`golden_test.go`, `ports` tests, restore `configProblem` tests).
- [ ] **Step 2: run.** `go test -race ./internal/hub/ -run 'TestSave|TestEnvDelivery|TestPathMount|TestPathUsages|TestSettingsAudited|TestSeedOnCreate|TestBackupCarries'`
  → FAIL.
- [ ] **Step 3: implement the state and save path.**
  - The state type change.
  - `ValidateSettings(t, kinds, u) error` replaces the string checks:
    ports keep their current rules.
  - `configProblems(t, kinds, u, native)` keeps its order.
  - Restore calls the same.
  - `restore.go`'s path-sharing warning iterates path options via
    `Values`.
- [ ] **Step 4: implement env and override.**
  - `generateAppEnvLocked` writes the env-delivered instance values
    rendered and single-quoted (`envQuote`; values with `'`/newline are
    refused at save, Task 7 pins it). It drops the old
    `h.st.Settings[t.ID]` flat copy.
  - The override mounts use `settings.Mounter.HostPath`; a value starting
    with `folder:` goes through `h.folders` (nil → error).
- [ ] **Step 5: verify.** `go vet ./... && go test -race ./... && gofmt -l .`
  → PASS.
- [ ] **Step 6: commit.**
  `hub: typed instance settings, restart only when needed, audited changes`.

### Task 7: Secrets

**Files:**
- `internal/hub/secrets.go` (new: store `<data>/settings/<id>/secrets.json`,
  0600, atomic);
- `internal/hub/settings.go` (`SecretChange`);
- `internal/hub/env.go` (`envQuote`);
- `internal/hub/ops.go` (redaction source);
- `internal/hub/backup.go` / `restore.go`
  (`config/settings-secrets.json`);
- `internal/hub/delete.go` (remove the store);
- tests: `internal/hub/secrets_test.go`.
- Fixture template `internal/hub/testdata/settings/secretapp/`:
  - option `api_key`: `secret`, env delivery;
  - option `token`: `secret`, `generate: {length: 32, charset: alnum}`,
    hook delivery.

**Interfaces:**
- Consumes: Task 6 `SettingsUpdate.Secrets`, `state.SecretMeta`.
- Produces:
```go
func (h *Hub) secretValues(id string) (map[string]string, error) // never logged; used by env, files, hooks
func (h *Hub) knownSecrets(id string) []string                   // for redaction (ops, hook output)
func redactValues(s string, secrets []string) string             // then clip: callers clip after
func envQuote(v string) (string, error)                          // single-quoted; ' or newline → error
type SecretView struct{ Set bool `json:"set"`; UpdatedAt *time.Time `json:"updated_at,omitempty"`; Generated bool `json:"generated,omitempty"` }
```

- [ ] **Step 1: tests.**
  - `TestSecretWriteOnly`:
    - saving `api_key: "s3cr3t"` → `state.yaml` and `instance.yaml` don't
      contain it;
    - the panel view (`SettingsPanel` from Task 13, or `secretViewsLocked`
      now) shows `{set: true, updated_at}`;
    - the `.env` has `HEADSCALE_API_KEY='s3cr3t'`.
  - `TestSecretGenerateAndClear`:
    - `Generate` → 32 alnum characters, `Generated: true`;
    - `Clear` → removed from the store, the env and the meta;
    - an empty `Value` without `Clear` → 400 "clearing needs an explicit
      action".
  - `TestSecretNeverEchoed`:
    - a failing enable whose compose output contains the secret → op
      record, `OpError` JSON, audit entry and log capture all redacted
      (`[redacted]`);
    - the audit says `replaced`.
  - `TestEnvValueQuotingRoundTrip` (Review Focus 1):
    - values `a$b`, `x y#z` and `"q"` survive
      `parseEnv(writeEnv(v))` and compose-style single-quote parsing;
    - `it's` → 400 naming the option;
    - generated charsets never include `'`.
  - `TestSecretsInBackup`: the archive has `config/settings-secrets.json`
    and restore puts it back. A restore into a new id copies it, and
    regenerates `generate`-declared secrets (like client `secret_env`s).
- [ ] **Step 2: run.** `go test -race ./internal/hub/ -run 'TestSecret|TestEnvValueQuoting'`
  → FAIL.
- [ ] **Step 3: implement.**
  - `finishOp` redacts `knownSecrets(id)` as well as secret-looking env
    values, before clipping.
  - Generation uses `crypto/rand`.
- [ ] **Step 4: verify.** `go vet ./... && go test -race ./... && gofmt -l .`
  → PASS.
- [ ] **Step 5: commit.** `hub: write-only secret settings (store, generate, redaction)`.

### Task 8: Directory integration — membership, privileged groups, group ids, purge, population

**Files:**
- `internal/directory/membership.go` (new): `Membership`,
  `PrivilegeProblem`;
- `internal/directory/service.go`: `App.PrivilegedGroups`,
  `GroupDeleted` hook in `DeleteGroup`, `ReservedAttrPrefix`;
- `internal/directory/groups.go`: `guardingGroups`;
- `internal/directory/fields.go`: refuse `ps_`; lists skip `ps_*`;
- `internal/directory/view.go` / `importcsv.go`: skip `ps_*`;
- `internal/hub/population.go` (new);
- `internal/hub/groupsettings.go` (new): person/group-scope save,
  placeholder binding, purge, prune;
- `internal/hub/directory.go`: `DirectoryApps` fills `PrivilegedGroups`;
- `internal/hub/hub.go`: `People`, `SetPeople`;
- `internal/hub/restore.go`: row id check;
- `cmd/hub/main.go`: `h.SetPeople(dir)`, `dir.GroupDeleted = h.PurgeGroupSettings`;
- tests: `internal/directory/membership_test.go`,
  `internal/hub/groupsettings_test.go`.
- Fixture template `internal/hub/testdata/settings/privapp/`:
  - option `role`: enum `[user, admin]`, privileged, person, claim;
  - option `libraries`: group scope, list, file delivery.

**Interfaces:**
- Consumes:
  - Task 5: `settings.Person`, `Row`, `PersonConfig`, `ResolveAll`;
  - Task 6: `SettingsUpdate.Person/Groups`, `state.PersonSetting`,
    `GroupValue`.
- Produces:
```go
// directory
type MemberGroup struct{ ID int; Members []string } // lowercase ids
type Membership struct {
    Users   map[string]map[string]int  // lowercase user → group name → id (service account excluded)
    Groups  map[string]MemberGroup
    Expired map[string]map[string]bool // user → group: expired, not yet removed (published expiring)
}
func (s *Service) Membership(ctx context.Context, now time.Time) (*Membership, error) // 503/502 *Error when unavailable
func (s *Service) PrivilegeProblem(ctx context.Context, group string) (string, error) // "" = may hold privileged values
const ReservedAttrPrefix = "ps_"
// Service.GroupDeleted, called after a successful DeleteGroup, outside s.mu:
//   GroupDeleted func(ctx context.Context, actor, name string, id int)
// App gains: PrivilegedGroups []string

// hub
type People interface {
    Membership(ctx context.Context, now time.Time) (*directory.Membership, error)
    PrivilegeProblem(ctx context.Context, group string) (string, error)
}
func (h *Hub) SetPeople(p People)
type Population struct{ People []settings.Person; Why string } // Why: "" | "per-person values need Portcullis sign-in" | …
func (h *Hub) populationLocked(t *templates.Template, m *directory.Membership) Population
func (h *Hub) InPopulation(ctx context.Context, instance, user string) (bool, error)
func (h *Hub) personConfigLocked(t *templates.Template, key string) settings.PersonConfig // placeholders → the instance's group names
func (h *Hub) PurgeGroupSettings(ctx context.Context, actor, name string, id int) []string // audited settings.purge; triggers delivery
func (h *Hub) bindPlaceholderRows(ctx context.Context, id string) []string // sets GroupID of {{…}} rows; warnings
func SettingsIncompatibilities(old, new *templates.Template, s state.InstanceSettings) []string // for the app-updates preview
```

- [ ] **Step 1: directory tests** in `membership_test.go`:
  - `TestMembershipExcludesServiceAccountAndMarksExpired`: the service
    account is excluded, and an expired entry is marked in `Expired`.
  - `TestPrivilegeProblem`:
    - a manual group → "";
    - a rule group on `office_location` (not admin-only) → "its rule uses
      fields delegates can edit: office_location";
    - a rule matching an empty person → its reason;
    - a missing group → 404 `*Error`.
  - `TestPrivilegedGroupsAreGuarding`: an App with
    `PrivilegedGroups: [office_milan]` gives:
    - `SetRule` with a non-admin-only field → 409 with reason "a
      privileged value of app immich";
    - `addsBlocked` and the `created_by` exclusion apply;
    - turning off `admin_only` on a field its rule uses → 409.
  - `TestReservedAttrPrefix`: `CreateField("ps_x")` → 409; the
    overview, CSV export and import never show `ps_*` LLDAP attributes.
  - `TestGroupDeletedHook`: called with (actor, name, id) after the
    LLDAP delete. It is not called when the delete fails.
- [ ] **Step 2: hub tests** in `groupsettings_test.go`:
  - `TestPopulationRules` (call 27):
    - group access on: members of `users_<id>`, minus the expired one;
    - group access off: every user;
    - `sign_in: native` → empty with `Why`;
    - a member of `admin_<id>` only → excluded.
  - `TestSavePersonRows`:
    - rows store `GroupID` from `Membership`;
    - an unknown group → 400;
    - a privileged option with the row `office_milan` → 400 with the
      `PrivilegeProblem` text;
    - the default must parse.
  - `TestPlaceholderRowsBound`: after `CreateInstanceAs`, the
    `{{ADMIN_GROUP}}` row has the id of `admin_<id>`;
    `personConfigLocked` resolves the name.
  - `TestRecreatedGroupInheritsNothing` (call 29):
    - delete and re-create `office_milan` in the fake LLDAP (new id);
    - resolution gives the default;
    - the next `Deliver` purges the row;
    - the audit has `settings.purge` with actor `hub`.
  - `TestPurgeOnHubDelete` (call 19): `DeleteGroup` through the
    directory → rows and group records in every instance are removed,
    audited with the admin actor, and delivery is triggered.
  - `TestRestoreDropsMismatchedRows`: an archived row id ≠ current →
    dropped with a restore warning. A placeholder row is re-bound to the
    new id's groups.
  - `TestPrivilegedAfterTemplateUpdate` (Review Focus 4):
    - a template sync turns `quota` privileged while a row uses a rule
      group on a non-admin-only field;
    - resolution skips that row at once;
    - the next reconcile drops it with a warning;
    - an option removed or retyped → `SettingsIncompatibilities` lists it,
      and Discover drops the stored value (logged).
  - `TestGroupScopeRecords`: `Groups["libraries"]` records keep the
    admin order and their ids; a duplicate group → 400. A group-scope
    option delivered by env renders as one JSON value,
    `[{"group":…,"value":…}]` (`render.format: json`, required for env by
    the validator).
  - `TestGroupScopeNotPersonResolved`: a member of two record groups
    gets no per-person value; only the map is delivered.
- [ ] **Step 3: run.** `go test -race ./internal/directory/ ./internal/hub/ -run 'TestMembership|TestPrivilege|TestReservedAttr|TestGroupDeleted|TestPopulation|TestSavePerson|TestPlaceholder|TestRecreated|TestPurgeOn|TestRestoreDrops|TestPrivilegedAfter|TestGroupScope'`
  → FAIL.
- [ ] **Step 4: implement.**
  - `DirectoryApps` reads the rows of privileged options under `mu`
    (state only, no network).
  - The privileged and group checks call `People` **before** taking
    `mu`, then re-check the stored state under `mu`.
  - `fakes_test.go` gets a `fakePeople`.
- [ ] **Step 5: verify.** `go vet ./... && go test -race ./... && gofmt -l .`
  → PASS.
- [ ] **Step 6: commit.**
  `hub+directory: per-person and per-group values, privileged groups, group ids and purge`.

## Phase 4 — Hub deliveries

### Task 9: Delivery engine, data files, reload signal

**Files:**
- `internal/hub/deliver.go` (new): engine, generations, status;
- `internal/hub/deliver_files.go` (new);
- `internal/hub/deliver_reload.go` (new);
- `internal/hub/override.go` (data-file mounts);
- `internal/hub/hub.go` (`Config.AppFilesDir`, Engine additions);
- `internal/hub/directory.go`: `RunDirectorySync` calls
  `TriggerMembershipDelivery`; the 10-min tick resyncs;
- `internal/hub/lifecycle.go`: `Deliver(…, TriggerStart)` after a
  successful up;
- `internal/hub/delete.go`: remove `appfiles/<id>` and
  `<data>/settings/<id>`;
- `internal/docker/client.go`: `ContainerKill`, `ContainerState`;
- `internal/settings/wire.go` (new);
- `cmd/hub/main.go`: `HUB_APPFILES_DIR`, `go h.RunSettingsDelivery(ctx)`;
- tests: `internal/hub/deliver_test.go`, `internal/docker/client_test.go`.
- Fixture template `internal/hub/testdata/settings/tmfixture/`:
  - person option `size_limit`: size, max, file `people`,
    `render {unit: MiB, integer: true, unlimited: "0"}`, applies restart;
  - `files: [{name: people, service: app, mount: /portcullis, on_membership_change: restart}]`;
  - `reload: {service: app, signal: HUP}`;
  - instance option `greeting`: applies reload, file.

**Interfaces:**
- Consumes:
  - Task 6 `SaveSettings` (stub replaced);
  - Task 7 `secretValues`;
  - Task 8 `People`, `populationLocked`, `personConfigLocked`;
  - Task 4 `Render`.
- Produces:
```go
type Trigger string
const (TriggerStart Trigger="start"; TriggerSave Trigger="settings_change"; TriggerMembership Trigger="membership_change"; TriggerRetry Trigger="retry")
type UnitResult struct {
    Unit    string    `json:"unit"`    // "env" | "file:<name>" | "hook:<name>" | "claim:<attr>" | "headers" | "reload" | "restart"
    OK      bool      `json:"ok"`
    Skipped string    `json:"skipped,omitempty"` // "unchanged" | "not running" | "directory unavailable"
    Error   string    `json:"error,omitempty"`   // redacted, then clipped (2000)
    At      time.Time `json:"at"`
}
type DeliveryReport struct{ Instance string `json:"instance"`; Units []UnitResult `json:"units"` }
type DeliveryStatus struct{ Units map[string]UnitResult `json:"units"`; Pending bool `json:"pending"` } // panel
func (h *Hub) Deliver(ctx context.Context, id string, trig Trigger) (*DeliveryReport, error)
func (h *Hub) TriggerDelivery(id string, trig Trigger, immediate bool) // immediate=false: debounced settingsDebounce
func (h *Hub) TriggerMembershipDelivery()                                // every enabled instance with person/group options
func (h *Hub) RunSettingsDelivery(ctx context.Context)
func (h *Hub) DeliveryStatus(id string) DeliveryStatus
const settingsDebounce = 60 * time.Second
// Engine additions
ContainerKill(ctx context.Context, id, signal string) error
ContainerState(ctx context.Context, id string) (docker.State, error) // docker.State{Running bool; Health string}
// settings/wire.go (contract §13.7–13.8)
const DataFileVersion, HookInputVersion = 1, 1
type GroupRecordOut struct{ Group string `json:"group"`; Value any `json:"value"` }
type DataFileDoc struct {
    Version  int                       `json:"version"`
    Instance string                    `json:"instance"`
    Values   map[string]any            `json:"values"`
    People   map[string]map[string]any `json:"people"`
    Groups   map[string][]GroupRecordOut `json:"groups"`
}
type SecretsFileDoc struct{ Version int `json:"version"`; Instance string `json:"instance"`; Secrets map[string]string `json:"secrets"` }
type HookInput struct {
    DataFileDoc
    Trigger string            `json:"trigger"`
    Secrets map[string]string `json:"secrets"`
}
```
- Engine algorithm, one per instance, under `deliverLock(id)`:
  1. Under `mu`: snapshot the view, settings and generation `gen`.
  2. Outside `mu`: `People.Membership`. On error → every unit that needs
     people is `Skipped: "directory unavailable"` and nothing is cleared.
  3. Build the desired outputs per unit, and their sha256s.
  4. Compare each with `<data>/settings/<id>/delivered.json`.
  5. Apply the changed units in this order: files → claims (Task 11) →
     headers (Task 12) → hooks (Task 10) → reload/restart (only the
     strongest of the triggered effects).
  6. Before each write, re-check `gen` against the current one. If it
     changed, abort with "superseded" and re-queue.
  7. Persist hashes and status.
- With `TriggerMembership`, a file whose output changed applies its
  `on_membership_change`; `restart` is folded into one `Restart` per run.

- [ ] **Step 1: tests** in `deliver_test.go`:
  - `TestPerPersonFileDelivery` (call 14, the Time Machine case):
    - `people.json` has `people.alice.size_limit == 10240` (10 GiB in
      MiB) and `carol == 512000`;
    - mode 0640, owned by the Hub;
    - the override mounts `<host>/appfiles/<id>/people:/portcullis:ro`.
  - `TestSecretFileSeparate`: a secret file-delivery value goes only into
    `people.secrets.json` (0600); `people.json` never contains it.
  - `TestMembershipDebounced`:
    - 5 `TriggerMembershipDelivery` calls within the window (fake clock)
      → one run and one restart;
    - an unchanged output → zero restarts.
  - `TestUnchangedNotReapplied`: a second `Deliver` with no change writes
    nothing (mtime unchanged) and reports `Skipped: "unchanged"`.
  - `TestReloadSignal`:
    - saving `greeting` → one `ContainerKill(HUP)`;
    - after 10 s (fake clock) `ContainerState` running → OK, status text
      "reload signal sent, app still running";
    - exited or unhealthy → failed, with an op record (op `reload`);
    - not running → no kill, `Skipped: "not running"`.
  - `TestFilesWrittenBeforeReload`: the order of fake calls is
    file write → kill.
  - `TestDirectoryDownKeepsLastDelivery` (Review Focus 2):
    `Membership` fails → `people.json` keeps its content and the status
    says "directory unavailable".
  - `TestStaleDeliveryDoesNotOverwrite` (Review Focus 5): a run blocked
    after step 3, a `SaveSettings` committed meanwhile, then the run
    resumes → it writes nothing, and the re-queued run writes the new
    content.
  - `TestDisabledInstanceDeliversNothing`: state is kept; no files, no
    hooks.
  - `TestDeleteRemovesSettingsFiles`: delete removes `appfiles/<id>/`
    and `<data>/settings/<id>/`.
  - `internal/docker`: `TestContainerKill` and `TestContainerState`
    against the httptest daemon fake (path, signal query, health parse).
- [ ] **Step 2: run.** `go test -race ./internal/hub/ ./internal/docker/ -run 'TestPerPerson|TestSecretFile|TestMembershipDebounced|TestUnchanged|TestReload|TestFilesWritten|TestDirectoryDown|TestStale|TestDisabledInstance|TestDeleteRemovesSettings|TestContainerKill|TestContainerState'`
  → FAIL.
- [ ] **Step 3: implement.**
  - The debounce uses per-instance `time.Timer`s behind an injectable
    clock (`h.now` / `h.afterFunc`, test-settable).
  - `RunSettingsDelivery` also calls `TriggerMembershipDelivery` every
    `accessSyncInterval`, so LLDAP-direct changes and deleted groups are
    seen.
  - `TestMain`/fixtures set `AppFilesDir` to a temp dir.
- [ ] **Step 4: verify.** `go vet ./... && go test -race ./... && gofmt -l .`
  → PASS.
- [ ] **Step 5: commit.**
  `hub: settings delivery engine (data files, debounce, reload signal, generations)`.

### Task 10: Hooks (exec with stdin)

**Files:**
- `internal/docker/exec.go`: `ExecStdin`;
- `internal/hub/deliver_hooks.go` (new);
- `internal/hub/hub.go` (Engine);
- `internal/hub/runtime.go` (shared container pick);
- tests: `internal/docker/client_test.go`,
  `internal/hub/deliver_hooks_test.go`.
- Fixture template `internal/hub/testdata/settings/hookapp/`:
  - `hooks: [{name: apply, service: app, command: [/apply], when: [start, settings_change, membership_change], timeout: 5s}]`;
  - an instance option `quota`: size, live, hook, with render GB integer;
  - a secret `token` delivered by the hook;
  - `reload: {hook: apply}`.

**Interfaces:**
- Consumes:
  - Task 9 engine, `HookInput`, `UnitResult`;
  - Task 7 `secretValues`, `knownSecrets`, `redactValues`.
- Produces:
```go
type ExecInput struct{ Cmd []string; User string; Stdin []byte; Timeout time.Duration }
func (c *Client) ExecStdin(ctx context.Context, id string, in ExecInput) (*ExecResult, error) // stdin written then CloseWrite; no TTY
// Engine: ExecStdin(ctx context.Context, id string, in docker.ExecInput) (*docker.ExecResult, error)
func (h *Hub) runHook(ctx context.Context, t *templates.Template, hk templates.Hook, in settings.HookInput) UnitResult
```

- [ ] **Step 1: tests.**
  - docker `TestExecStdin`: the fake daemon records `AttachStdin: true`,
    `Cmd` as given (no `/bin/sh -c`) and `User`, and receives the
    exact stdin bytes. A timeout gives `TimedOut`.
  - `TestHookGetsFullDesiredState`:
    - stdin JSON decodes into `settings.HookInput` with `Trigger:
      "settings_change"`, `Values.quota == 10` and `Secrets.token`;
    - a second save with a different option still sends **all** values
      (never a diff).
  - `TestHookFailureRecorded`: exit 3 with output containing the token →
    `UnitResult{OK: false}`; the op record (op `hook`) has `[redacted]`
    and is clipped. The panel status shows it; it is never shown as
    applied.
  - `TestHookSerialisedAndRetried`: two concurrent triggers → runs don't
    overlap (the fake exec blocks). A failed run is retried on the next
    trigger; `Deliver(…, TriggerRetry)` re-runs it even when unchanged.
  - `TestHookOnStartAndMembership`: an enable → a hook with trigger
    `start`; a membership change → `membership_change` only if declared
    in `when`.
  - `TestReloadHookForm`: `applies: reload` with `reload.hook` → the hook
    runs once per save, folded with the other hook deliveries.
  - `TestHookNotRunningSkipped`: no running container →
    `Skipped: "not running"`; the next `start` delivers.
- [ ] **Step 2: run.** `go test -race ./internal/docker/ ./internal/hub/ -run 'TestExecStdin|TestHook|TestReloadHookForm'`
  → FAIL.
- [ ] **Step 3: implement.**
  - `ExecCreate` with `AttachStdin`, `AttachStdout`, `AttachStderr`;
    write stdin, then `att.CloseWrite()`.
  - Output cap and timeout as in `Exec`.
  - The hook container is picked the same way as `Hub.Exec` (replica 1).
- [ ] **Step 4: verify.** `go vet ./... && go test -race ./... && gofmt -l .`
  → PASS.
- [ ] **Step 5: commit.** `hub: setting hooks (argv exec with stdin, redacted op records, retry)`.

### Task 11: Claims (Hub-owned LLDAP attributes + per-client mappers)

**Files:**
- `internal/lldap/client.go`: `AddHiddenUserAttribute`;
- `internal/lldap/lldaptest` (isVisible);
- `internal/keycloak/settingclaims.go` (new);
- `internal/keycloak/kctest` (client protocol mappers, LDAP components);
- `internal/hub/deliver_claims.go` (new);
- `internal/hub/hub.go` (IdP additions, `AttrStore`, `SetAttrStore`);
- `internal/hub/delete.go` (cleanup at step 4);
- `cmd/hub/main.go` (`h.SetAttrStore(ll)`);
- tests: `internal/keycloak/settingclaims_test.go`,
  `internal/hub/deliver_claims_test.go`.

**Interfaces:**
- Consumes:
  - Task 9 engine;
  - Task 8 population;
  - Task 3 `ClaimDelivery`.
- Produces:
```go
// lldap
func (c *Client) AddHiddenUserAttribute(ctx context.Context, name string) error // STRING, isList false, isVisible false, isEditable false
// keycloak
const SettingMapperPrefix = "portcullis-setting-"
type SettingClaim struct{ Attr, Claim, JSONType string } // JSONType: int|string|bool|json → "int"|"String"|"boolean"|"JSON"
func (c *Client) EnsureSettingClaims(ctx context.Context, clientID, owner string, claims []SettingClaim) error // exact set; removes other owned mappers on that client
func (c *Client) RemoveSettingClaims(ctx context.Context, clientID, owner string, attrs []string) error   // client mappers + LDAP mappers
// hub
type AttrStore interface {
    UserAttributes(ctx context.Context) ([]lldap.Attribute, error)
    AddHiddenUserAttribute(ctx context.Context, name string) error
    DeleteUserAttribute(ctx context.Context, name string) error
    SetUserAttributes(ctx context.Context, user string, set map[string][]string, remove []string) error
}
func (h *Hub) SetAttrStore(a AttrStore)
func SettingAttr(instance, key string) string // "ps_" + first 12 hex of sha256(instance+"\x00"+key)
// IdP gains EnsureSettingClaims / RemoveSettingClaims (signatures above)
```

- [ ] **Step 1: tests.**
  - keycloak `TestEnsureSettingClaims` (kctest):
    - an LDAP mapper `portcullis-setting-ps_…` with `ldap.attribute =
      user.model.attribute = ps_…`, read-only, always read from LDAP;
    - a protocol mapper on client `immich` **only**, with `claim.name =
      immich_quota`, `jsonType.label = int`, and ID, access and userinfo
      tokens on;
    - another client has no such mapper;
    - idempotent;
    - a mapper the Hub doesn't own is kept;
    - a client not owner-tagged → `*ConflictError`.
  - `TestRemoveSettingClaims`: both mapper kinds go; a missing one is nil.
  - hub `TestClaimDeliveryPerPerson`:
    - immich fixture: `storage_quota` max, default 100GiB, row
      `office_milan` 10GiB;
    - the attribute is created hidden;
    - alice → `"10"`, carol → `"100"`;
    - dave, outside the population → the attribute is removed;
    - `role` with `{{ADMIN_GROUP}}: admin` → `admin_<id>` members who are
      in `users_<id>` get `admin`.
  - `TestClaimOnlyChangedUsersWritten`: one membership change → one
    `SetUserAttributes` call.
  - `TestClaimDeliveryNeedsKeycloak`: idp nil → the unit fails with
    "Keycloak not configured", and nothing else is skipped.
  - `TestDeleteRemovesClaims`: the instance delete removes its attributes
    (`DeleteUserAttribute`) and mappers; a shared template's other
    instance keeps its own.
  - `TestNativeSignInClearsPersonDeliveries`: `sign_in: native` (custom
    fixture with a hook) → people-dependent units are cleared, and the
    panel `Why` is set.
- [ ] **Step 2: run.** `go test -race ./internal/keycloak/ ./internal/lldap/ ./internal/hub/ -run 'TestEnsureSettingClaims|TestRemoveSettingClaims|TestClaim|TestDeleteRemovesClaims|TestNativeSignIn'`
  → FAIL.
- [ ] **Step 3: implement.**
  - gocloak `CreateClientProtocolMapper` /
    `GetClientProtocolMappers`-style calls (raw only where gocloak lacks
    one).
  - LDAP mapper creation reuses `ensureLDAPMappers`' pattern with
    `SettingMapperPrefix`.
  - Values are written per user only where the hash differs. Per-user
    hashes are stored in `delivered.json` under `claim:<attr>`.
- [ ] **Step 4: verify.** `go vet ./... && go test -race ./... && gofmt -l .`
  → PASS.
- [ ] **Step 5: commit.** `hub: per-person claim delivery (hidden LLDAP attributes, per-client mappers)`.

### Task 12: Headers (`user-attributes.json` v2, Hub side)

**Files:**
- `internal/policy/attributes.go` (v2, `Hosts`);
- `internal/policy/attributes_test.go`;
- `internal/hub/deliver_headers.go` (new);
- `internal/hub/directory.go` (`DirectoryStateOf` → hosts merged in
  `WritePolicy`);
- `internal/hub/hub.go` (`WritePolicy` merges `h.hostHeaders`);
- `internal/hub/settings.go` (refuse `sign_in: native` with a header
  delivery);
- tests: `internal/hub/deliver_headers_test.go`.

**Interfaces:**
- Consumes:
  - Task 9 engine (unit `headers`);
  - the override's `routeLabelsLocked` (rendered chains).
- Produces:
```go
const UserAttributesVersion = 2
// UserAttributesDocument gains:
//   Hosts map[string]map[string]map[string]string `json:"hosts"` // host → header suffix → user → value
func BuildUserAttributes(fields []AttrField, users map[string]map[string][]string, hosts map[string]map[string]map[string]string) UserAttributesDocument
func (h *Hub) groupsHostsLocked(t *templates.Template) ([]string, error) // every host of every router whose rendered chain has portcullis-groups (incl. portcullis-auth-ext hosts)
// h.hostHeaders map[string]map[string]map[string]map[string]string // instance → host → header → user → value; persisted in delivered.json, loaded at Init
```

- [ ] **Step 1: tests.**
  - policy `TestUserAttributesV2`: `version` is 2; `hosts` is always an
    object; host keys are lowercase; values are control-stripped, and a
    value over 1 KB is dropped.
  - hub `TestHeaderDeliveryAllGroupsHosts`:
    - a grafana fixture with role `Viewer<Editor<Admin`, privileged,
      next_request;
    - an instance with a main host and an extra-domain host → both hosts
      carry `Grafana-Role` for every population member;
    - a public router's host is absent.
  - `TestHeaderRefusedWithNativeSignIn`: switching `sign_in` to native on
    a template with a header delivery → 400.
  - `TestHeadersSurviveRestart`: a new Hub over the same data dir → the
    first `WritePolicy` still has the headers (loaded from
    `delivered.json`).
  - `TestHeadersOnlyEnabledInstances`: disable → its hosts leave the
    file at the next policy write.
  - `TestHeaderDeliveryNoRestart`: a role change → `Effect: none`, a
    policy write, no restart.
- [ ] **Step 2: run.** `go test -race ./internal/policy/ ./internal/hub/ -run 'TestUserAttributesV2|TestHeader'`
  → FAIL.
- [ ] **Step 3: implement.**
  - The header unit's apply = update `h.hostHeaders[id]` under `mu`, then
    `writePolicyLogged()`.
  - The fail-closed rule is unchanged: a failing directory keeps the last
    attributes file.
- [ ] **Step 4: verify.** `go vet ./... && go test -race ./... && gofmt -l .`
  → PASS.
- [ ] **Step 5: commit.** `hub: per-host header delivery (user-attributes.json v2)`.

## Phase 5 — Hub API and UI

### Task 13: Admin settings API

**Files:**
- `internal/httpapi/settings.go` (new): routes and body decoding;
- `internal/httpapi/server.go`: remove `/api/templates/settings/`,
  `parseSettingsUpdate`; `registerSettings(mux)` on the Hub listener only;
- `internal/hub/panel.go` (new): `SettingsPanel`, `PreviewSettings`,
  `RetryDeliveries`;
- tests: `internal/httpapi/settings_test.go`, `internal/hub/panel_test.go`;
- `CLAUDE.md` (httpapi row).

**Interfaces:**
- Consumes: Tasks 5–12.
- Produces routes (all `adminOnly`, Hub listener):
  - `GET /api/instances/{id}/settings` → `SettingsPanel`;
  - `PUT /api/instances/{id}/settings` (body `settingsBody`) → `SaveResult`;
  - `POST /api/instances/{id}/settings/preview` (same body, nothing
    stored) → `Preview`;
  - `POST /api/instances/{id}/settings/retry` → `DeliveryReport`.
```go
type settingsBody struct { // httpapi; DisallowUnknownFields, 256 KiB
    Values  map[string]json.RawMessage     `json:"values"`
    Person  map[string]hub.PersonChange    `json:"person"`  // {default, resolve, rows:[{group, value}]}
    Groups  map[string][]hub.GroupValueInput `json:"groups"`
    Secrets map[string]secretBody          `json:"secrets"` // {value?, generate?, clear?}
    Ports   map[string]string              `json:"ports"`
    Policy  *policy.AuthPolicy             `json:"auth_policy"`
    Inherit bool                           `json:"auth_policy_inherit"`
    PublicAccess *json.RawMessage          `json:"public_access"` // true|false|"default"
    PublicMode   *string                   `json:"public_mode"`
    PublicTokens *[]string                 `json:"public_tokens"`
    SignIn       *string                   `json:"sign_in"`
}
type OptionView struct {
    templates.Option
    DefaultDisplay string   `json:"default_display"`
    Effect         string   `json:"effect"`
    Warnings       []string `json:"warnings,omitempty"` // "existing accounts keep their value", "people joining or leaving restarts <app>", "per-person values need Portcullis sign-in"
    GroupChoices   []GroupChoice `json:"group_choices,omitempty"` // privileged: every group with Disabled+Reason
}
type GroupChoice struct{ Name string; Disabled bool; Reason string }
type SettingsPanel struct {
    AppSettingsView                       // policy, sign-in, public (Values field removed)
    Sections   []string                   `json:"sections"`
    Options    []OptionView               `json:"options"`
    Instance   map[string]any             `json:"instance"`  // canonical values (no secrets)
    Person     map[string]state.PersonSetting `json:"person"` // placeholders shown as the instance's group names
    Groups     map[string][]state.GroupValue  `json:"groups"`
    Secrets    map[string]SecretView      `json:"secrets"`
    Ports      map[string]string          `json:"ports"`
    Population struct{ Count int; Why string } `json:"population"`
    Deliveries DeliveryStatus             `json:"deliveries"`
}
type PersonPreview struct{ User, Display string; Reason settings.Reason }
type OptionPreview struct {
    People   []PersonPreview `json:"people"`   // all population members, sorted by user
    Changes  int             `json:"changes"`  // people whose value differs from the saved config
    NoAccess map[string]int  `json:"no_access"` // row group → members outside the population
}
type Preview struct{ Effect string `json:"effect"`; Options map[string]OptionPreview `json:"options"` }
func (h *Hub) SettingsPanel(ctx context.Context, id string) (*SettingsPanel, error)
func (h *Hub) PreviewSettings(ctx context.Context, id string, u SettingsUpdate) (*Preview, error)
func (h *Hub) RetryDeliveries(ctx context.Context, id, actor string) (*DeliveryReport, error) // audited settings.retry
```

- [ ] **Step 1: tests.**
  - `TestSettingsRoutesAdminOnly`: a delegate (has `edit_details`) →
    403 on all four routes; a non-admin → 403; no `X-Forwarded-User` →
    401.
  - `TestOldSettingsRouteGone`: `/api/templates/settings/x` → 404.
  - `TestPanelNeverReturnsSecrets`: the GET body doesn't contain the
    secret value; `secrets.api_key == {"set":true,…}`.
  - `TestPreviewOnDraft`:
    - preview with an extra row `it_staff` 2TiB, without saving →
      bob shows 2 TiB, `Reason.Group "it_staff"`, `others` has
      office_milan;
    - `Changes == 1`;
    - state is unchanged;
    - `NoAccess["office_milan"] == 1`.
  - `TestPreviewEffectText`: storage_quota only → `effect: "none"`;
    `trash_days` → `"restart"`.
  - `TestPrivilegedGroupChoices`: `office_milan` is disabled with "its
    rule uses fields delegates can edit: office_location"; `admin_<id>`
    is enabled.
  - `TestPutAnswersSaveResult`: 200 `{effect, changed, warnings, deliveries}`;
    a 400 names the option; an unknown body field → 400.
  - `TestRetryAudited`: `settings.retry` with the actor.
  - `TestPeopleListenerHasNoAppRoutes` gains
    `/api/instances/x/settings` → 404 on people.
- [ ] **Step 2: run.** `go test -race ./internal/httpapi/ ./internal/hub/ -run 'TestSettingsRoutes|TestOldSettingsRoute|TestPanel|TestPreview|TestPrivilegedGroupChoices|TestPutAnswers|TestRetryAudited|TestPeopleListener'`
  → FAIL.
- [ ] **Step 3: implement.**
  - Preview uses one `Membership` call.
  - Preview pagination is client-side, with a search box (Task 14).
- [ ] **Step 4: verify.** `go vet ./... && go test -race ./... && gofmt -l .`
  → PASS.
- [ ] **Step 5: commit.** `httpapi: instance settings API (panel, save, preview, retry)`.

### Task 14: Settings panel UI

**Files:**
- `web/settings.js` (new: the panel; `window.PortcullisSettings.render(el, id)`);
- `web/index.html`: `loadSettings`/`saveSettings` call it; policy,
  sign-in and public blocks stay in index.html and are posted through
  the same body;
- `web/web.go` (embed);
- `internal/httpapi/harness_test.go`: fixture instances with person,
  group, secret, privileged and file options.

**Interfaces:**
- Consumes: Task 13 routes and JSON shapes.
- Produces the UI behaviour of the spec's "resulting UI behaviour"
  section:
  - **Layout:** sections; an "applies" badge per option.
  - **Per-person options:**
    - an "Everyone else with access" default row;
    - group rows with ✕ and "+ Add group";
    - a resolve selector from `resolve_choices`; `priority` turns the
      rows into a drag-ordered list (keyboard up/down buttons too);
    - "Who gets what (N people with access)" with search, 50 per page;
    - the `no_access` warning;
    - the restart-on-membership warning.
  - **Previews:** debounced 400 ms after each edit. The save bar shows the
    effect text ("Saving restarts <app>" / "Takes effect at each
    person's next sign-in; no restart") and "Changes: N people get a new
    value".
  - **Privileged picker:** greyed-out groups with their reason.
  - **Secrets:** "Set ✓ (updated …)" with Replace / Generate / Clear (the
    clear asks for a confirm). Inputs are `type=password` and cleared
    after the save.
  - **Size inputs:** a number plus a GiB/TiB/MiB unit select, the
    `step` enforced, and an "unlimited" checkbox when allowed.
  - **Path options:** show "the app writes here as uid:gid" from
    `writes_as`.
  - **Craft pair:** `requires` pairs render side by side.
  - **Deliveries strip:** "last applied / failed: reason", with a Retry
    button.

- [ ] **Step 1: harness.** Add the harness fixtures, then run
  `go test -tags harness -run TestHarness -timeout 0 ./internal/httpapi`.
- [ ] **Step 2: implement** `web/settings.js`.
  - Every interpolation goes through `escapeHtml`.
  - data-* attributes and delegated listeners only.
  - No `innerHTML` with unescaped server text.
- [ ] **Step 3: browser check** (Playwright MCP against
  `127.0.0.1:18888`), with screenshots saved under
  `.superpowers/sdd/2026-11-02-app-settings-panel/`:
  1. a quota row added → the preview updates before saving;
  2. the resolve switch to priority → drag handles appear;
  3. the privileged picker greys out `office_milan` with its reason;
  4. a secret set → the value is never re-rendered (DOM check);
  5. a failed hook → the strip shows the reason, and Retry clears it.
- [ ] **Step 4: verify.** `go vet ./... && go test -race ./... && gofmt -l .`
  → PASS.
- [ ] **Step 5: commit.** `web: settings panel (per-group values, who gets what, effects, secrets)`.

### Task 15: My apps (people listener API + UI)

**Files:**
- `internal/hub/myapps.go` (new);
- `internal/httpapi/people.go` (`GET /api/me/apps`);
- `internal/httpapi/server.go` (`PeopleHandler` registers it);
- `internal/httpapi/people_test.go` (allowlist);
- `web/myapps.js` (new);
- `web/people.html` (load it, register the tab);
- `web/directory.js` (an extension hook for extra tabs:
  `PortcullisDirectory.show(el, {extraTabs: [{id, label, render}]})`);
- `web/web.go`;
- tests: `internal/hub/myapps_test.go`.

**Interfaces:**
- Consumes:
  - Task 8 `populationLocked`, `InPopulation`;
  - Task 5 `ResolveAll`;
  - Task 4 `Display`.
- Produces:
```go
type MyReason struct{ Source string `json:"source"`; Group string `json:"group,omitempty"`; Groups []string `json:"groups,omitempty"` } // the caller's own groups only; never Others
type MyValue struct{ Key, Label, Value, Applies string; Reason MyReason } // json: key,label,value,applies,reason
type MyInfoLine struct{ Label, Value string }
type MyCredential struct { // empty list in project 1; project 3 fills it
    Key, Label, Status string
    Since  *time.Time    `json:"since,omitempty"`
    Reason string        `json:"reason,omitempty"`
    Info   []MyInfoLine  `json:"info,omitempty"`
}
type MyApp struct {
    ID, Name, Icon, URL string
    Values      []MyValue      `json:"values"`
    Credentials []MyCredential `json:"credentials"` // always [] (never null)
}
func (h *Hub) MyApps(ctx context.Context, user string) ([]MyApp, error)
// people_test.go: var peopleAppRoutes = []string{"GET /api/me/apps"} // the allowlist; later plans append
```
- Answer: `GET /api/me/apps` → `{"apps": [MyApp…]}`.
  - Only enabled instances whose population contains the caller (who is
    lowercased).
  - Only person-scope options with `self_visible` ≠ false.
  - Never instance options, secrets, other people or `Others`.
  - LLDAP unavailable → 503 with a generic message.

- [ ] **Step 1: tests.**
  - `TestMyAppsOnlyCallersApps`:
    - alice sees Immich (in `users_immich`) but not Grafana (not a
      member);
    - values `storage_quota "10 GiB"` with `reason {source: group,
      group: office_milan}`;
    - `role "User"` with `source: default`;
    - no `trash_days`, no secret, `credentials == []`.
  - `TestMyAppsNeverShowsLosingGroups`: bob gets max(office_milan,
    it_staff) → the reason has only `it_staff`, and `others` is absent
    from the JSON.
  - `TestMyAppsHidesSelfInvisible`: `self_visible: false` → absent.
  - `TestMyAppsDisabledInstanceAbsent`.
  - `TestMyAppsCallerCaseFolded` (Review Focus 3): `X-Forwarded-User:
    ALICE` → alice's apps, and nothing for a different user `Alice2`.
  - httpapi `TestPeopleListenerHasNoAppRoutes`: the people mux
    registers exactly `peopleAppRoutes` beyond the directory, `/healthz`
    and the page. `GET /api/me/apps` → 200 on people and 404 on the Hub
    listener.
  - `TestMyAppsNoCaller`: no `X-Forwarded-User` → 401.
- [ ] **Step 2: run.** `go test -race ./internal/hub/ ./internal/httpapi/ -run 'TestMyApps|TestPeopleListener'`
  → FAIL.
- [ ] **Step 3: implement** the API and the UI tab "My apps":
  - one card per app with a link, value, reason ("from office_milan",
    "everyone with access") and the applies note;
  - an empty state "No apps with personal settings".
- [ ] **Step 4: browser check** in the harness (people listener):
  screenshot alice's My apps; check that another user's values never
  appear.
- [ ] **Step 5: verify.** `go vet ./... && go test -race ./... && gofmt -l .`
  → PASS.
- [ ] **Step 6: commit.** `people: My apps (GET /api/me/apps, caller-only resolved values)`.

## Phase 6 — templates

### Task 16: Schema + validator v3 (templates repo)

**Files:** `schema/manifest.schema.json` (`$defs.setting` → `$defs.option`,
`settingsSpec`, `delivery`, `render`, `dataFile`, `hook`, `reload`, and
the reserved project 2/3 shapes), `tests/validate.py`
(`check_manifest_rules` + new `check_settings`),
`tests/test_validate.py`, `CONTRIBUTING.md` ("Settings" section),
`.core-ref` (`settings`).

**Interfaces:**
- Consumes: contract §13 (Task 1). It mirrors Task 3's Hub rules
  one-for-one.
- Produces: `check_settings(t: Template, services: Dict[str, Any], routers: Dict[str, Dict[str, str]], r: Report) -> None`.

- [ ] **Step 1: tests** in `tests/test_validate.py`, class
  `TestSettingsV3`. There is one test per Task 3 rule, with the same
  names in snake_case (`test_option_key_rule`, `test_old_types_refused`,
  `test_reserved_types_refused`, …, `test_generate_none_refused`), plus:
  - `test_size_default_canonical` (`"500GiB"` passes, `"500 gigs"` is
    refused);
  - `test_header_delivery_public_router_refused`;
  - `test_env_delivery_hard_coded_refused`.
- [ ] **Step 2: run.** `python3 tests/test_validate.py` → FAIL.
- [ ] **Step 3: implement.**
  - Schema first; cross-checks in `check_settings`.
  - Size parsing in Python uses binary units by a regex over the same
    grammar `go-units` accepts. Write a table test against the Go
    examples of Task 4.
- [ ] **Step 4: verify.** `python3 tests/test_validate.py` → PASS.
  (`python3 tests/validate.py` still fails until Task 17.)
- [ ] **Step 5: commit.** `schema+validate: template contract v3 settings`.

### Task 17: Convert every template + pilots (templates repo)

**Files:** every `*/manifest.yaml` with settings or `generate: none`
(gitea, guacamole, headscale, immich, jellyfin, kanboard, matrix,
paperless, plex, scrutiny, netbird, the 15 Craft templates). Also the
pilots:
- `immich/` (manifest, `compose.yml` init, `immich-config.json.tmpl`);
- `grafana/` (manifest, compose `GF_AUTH_PROXY_HEADERS`,
  `GF_AUTH_PROXY_SYNC_TTL: 0`);
- `nextcloud/` (manifest hooks, a new `apply-settings.php` mounted from
  `./templates/nextcloud/`);
- `tests/apps/{immich,grafana,nextcloud}.sh`.

- [ ] **Step 1: conversions** (spec call 22, no shims):

  | Template | Conversion |
  |---|---|
  | scrutiny | 8 disk fields → `devices` `list`, `max_items: 8`, item pattern `^/dev/`, one env JSON or joined var as compose expects |
  | matrix | federation domains → `list` of `string` `format: hostname` |
  | paperless | OCR language → `multi_enum` with `render {join: "+"}`; time zone → `string` `format: iana_tz` |
  | headscale | API key → `secret` |
  | guacamole, kanboard | admin user → `user` |
  | gitea | SSH → `bool` |
  | immich, jellyfin, plex | paths → `path`, with `mode`, `needs` and `writes_as` (immich `{uid: 0, gid: 0}`; jellyfin/plex from their PUID/PGID options) |
  | plex | `PLEX_CLAIM` → `secret` (env) |
  | netbird | `COTURN_EXTERNAL_IP` → `string` `format: ip` |
  | 15 Craft templates | `craft_version` (`^[0-9]+\.[0-9]+\.[0-9]+$`) and `craft_sha256` (`^[0-9a-f]{64}$`), each `requires` the other, applies restart, env `CRAFT_VERSION`/`CRAFT_SHA256` |

  Every option gets a lowercase key and an explicit `applies`.
- [ ] **Step 2: Immich pilot** (spec example).
  - `storage_quota`: claim `immich_quota` int, `{unit: GiB, unlimited: "-1"}`,
    next_sign_in.
  - `role`: privileged, `{{ADMIN_GROUP}}: admin`.
  - `trash_days` and `machine_learning`: env, restart. The init `sed`
    renders them into `config.json`; extend the `.tmpl`.
  - `external_library`: path `mode: ro`.
- [ ] **Step 3: Grafana pilot.**
  - `role`: enum Viewer/Editor/Admin, privileged, default Viewer,
    `{{ADMIN_GROUP}}: Admin`, header `X-Forwarded-Attr-Grafana-Role`,
    next_request.
  - Compose maps `Role:X-Forwarded-Attr-Grafana-Role`, with
    `GF_AUTH_PROXY_SYNC_TTL: 0`.
  - Update the notes. Drop "Admin role requires manual promotion".
- [ ] **Step 4: Nextcloud pilot.**
  - Hook `apply-settings` (`user: www-data`,
    `command: [php, /portcullis/apply-settings.php]`,
    `when: [start, settings_change]`, `timeout: 60s`).
  - `default_quota`: size, live, `{unit: GB, integer: true, unlimited: none}`.
  - `trash_retention`: duration, live.
  - The script reads `HookInput` from stdin, runs `occ config:app:set`
    idempotently, and exits non-zero on any `occ` failure.
  - `tests/apps/nextcloud.sh` pipes a sample `HookInput` into it in the
    running container and asserts `occ config:app:get files default_quota`.
- [ ] **Step 5: verify.** Run `python3 tests/validate.py` (all templates)
  and `python3 tests/test_validate.py` → PASS. Run
  `tests/apps/immich.sh` (the config has `storageQuotaClaim`, `trash.days`
  rendered) and `tests/apps/grafana.sh` (the header mapping env present)
  locally where Docker is available.
- [ ] **Step 6: commit.** `templates: contract v3 settings for every template; immich claims, grafana role header, nextcloud live hook`.
- [ ] **Step 7: push and run CI.** Push hub, core and templates
  `settings` together.
  - Hub CI: `TestRealTemplates*` passes against templates `settings`.
  - Core CI and templates CI: green.
  - Fix anything red before Phase 7.

## Phase 7 — e2e, docs, deploy

### Task 18: CI e2e `e2e-settings` (core repo)

**Files:**
- `.github/workflows/ci.yml` (a new job `e2e-settings`, modelled on
  `e2e-instances`; the Hub built from the same-named branch; the
  templates repo's `settings` branch checked out for `immich` and
  `grafana`);
- `tests/e2e/e2e_settings.py` (new);
- `tests/e2e/apps/settings-file/` (fixture: per-person file + hook that
  echoes stdin to a log);
- `tests/e2e/apps/settings-echo/` (header-auth echo of request headers).

- [ ] **Step 1: write the scenarios.**
  1. Copy `immich`, `grafana` and the two fixtures into `/data/repos/ci`.
     Create LLDAP users alice, bob and carol, with groups `users_immich`,
     `admin_immich`, `office_milan`, `users_grafana`.
  2. Through the Hub API (admin), enable the instances and set Immich
     `storage_quota` default 100GiB, with `office_milan` at 10GiB.
  3. **Claims:** alice (`office_milan`) signs in with a virtual passkey.
     - Her ID token for client `immich` has `immich_quota: 10`. The token
       comes from the browser's OIDC callback; decode it via the test's
       Keycloak admin token exchange, or read Immich's
       `/api/users/me` `quotaSizeInBytes == 10737418240`.
     - Immich's UI shows 10 GiB.
     - A member of `admin_immich` gets `immich_role: admin` (`isAdmin`
       true).
     - Changing an existing account's role, then signing in again → the
       role changes (call 30).
  4. **Membership change:** remove alice from `office_milan` through the
     Hub. Within 60 s plus the evaluator interval, her next sign-in shows
     100 GiB.
  5. **Header:** bob (`admin_grafana`) → Grafana `/api/user` `isGrafanaAdmin`,
     or org role `Admin`, on his first and later requests. If an existing
     user's role doesn't update, re-declare the option
     `account_creation` (call 30) and assert on a new account.
  6. **File + hook fixture:**
     - `people.json` inside the container lists only population members;
     - the hook log has the full desired state with `trigger:
       membership_change` after a membership change;
     - joining 3 people within the window gives one restart (container
       start count).
  7. **People listener:** carol's `/api/me/apps` lists only her apps,
     with no other usernames in the body. `/api/instances/immich/settings`
     on people → 404.
- [ ] **Step 2: run the job.** Run it on the `settings` branch
  (`workflow_dispatch`) until green. Keep the artifacts (screenshots,
  traces) on failure.
- [ ] **Step 3: commit and push** (core):
  `e2e: settings panel (claims, headers, data files, hooks, My apps)`.

### Task 19: Docs (docs repo)

**Files:**
- `docs/operations/hub.md`: "App settings": panel, per-group values,
  resolution, who gets what, effects, secrets, deliveries status, retry;
- `docs/operations/groups.md`: privileged-option groups are guarding;
  groups deleted outside the Hub;
- `docs/guides/adding-an-app.md`: declaring settings, files, hooks,
  reload;
- `docs/guides/manifest-reference.md`: the full `settings`, `files`,
  `hooks`, `reload` reference and validation list;
- `docs/operations/testing.md`: `e2e-settings`;
- `docs/operations/hardening.md`: header delivery and public routes,
  secrets handling, `appfiles` permissions;
- `docs/architecture.md`: the delivery engine;
- `scripts/generate-app-docs.py`: reads `settings.options` and renders
  type, scope and applies;
- regenerated `docs/apps/*.md` from templates `settings`.

- [ ] **Step 1: write the pages and run the generator.** Write the pages,
  run `python3 scripts/generate-app-docs.py` against the templates
  `settings` checkout, then `zensical build --strict --clean` → no
  warnings.
- [ ] **Step 2: commit and push.** Commit
  `docs: app settings panel, My apps, settings reference`, then push
  `settings`.

### Task 20: Deploy + live check

- [ ] **Step 1: deploy.** Merge in this order: docs → core → Hub →
  templates, with `.core-ref` back to `main`. Deploy to the test server
  with `./portcullis upgrade`.
- [ ] **Step 2: live checks.** Use throwaway users and groups only, and
  clean them up afterwards:
  1. The Immich quota by group (`office_milan` 10 GiB vs the default) is
     visible in Immich after sign-in.
  2. The Grafana role header works.
  3. A Nextcloud default-quota change applies live, with no restart (the
     container start time is unchanged).
  4. My apps shows only the caller's apps.
  5. A secret is never in `docker logs portcullis-hub`, the audit or
     `state.yaml` (grep).
- [ ] **Step 3: report** the results, and any upstream behaviour that
  differed (Grafana role sync, call 30).

---

## Interfaces for later plans

Projects 2 (shared folders + doctor) and 3 (file sharing) build on these
exact names. "Reserved" means project 1 parses the field but refuses
templates that use it (`templates.ReservedFeature`). Implementing a
feature means registering it and removing it from that refusal.

**Manifest (`internal/templates/settings.go`, contract §13):**
- **`Option`, project 2 fields.**
  - `Target *SettingTarget`, `Mode string` (`ro|rw`), `Needs string`
    (`read|write`) and `WritesAs *Owner` are implemented and validated
    for `type: path`.
  - `Owner{UID, GID OwnerRef}`, where
    `OwnerRef{Num *int; Key string}` is a number or an instance option
    key.
  - Reserved: `Folder map[string]any` (yaml `folder`) and
    `Checks []map[string]any` (yaml `checks`). Project 2 replaces both
    with typed structs; the yaml keys stay.
  - `folder.runs_as` (`{uid, gid}` / `{uid_env, gid_env}`; project 3 adds
    `uid_from` / `gid_from`) lives inside that block.
  - Project 1's `writes_as` stays the plain-path ownership declaration.
    When a `folder` block is present, project 2 decides how the two
    relate; `ResolveOwner` covers `writes_as` only.
- **`Option`, project 3 fields** (all reserved): `Hash string`,
  `Length int`, `RevokeOnLeave *bool`, `OnRestore string`, `Pool string`,
  `Username map[string]any`, `Mount *OptionMount{Service, Path string}`.
- **`Deliveries`** (`[]Delivery`). The scalar form `delivery: file|hook`
  decodes to `Deliveries{{Bare: "file"}}`. It is refused except where a
  registered kind accepts it (project 3 `person_secret`).
- **Reserved types:** `TypeFolder = "folder"`,
  `TypePersonSecret = "person_secret"`, `TypePersonID = "person_id"`.
- **Hook triggers.** `HookTriggers` is a `map[string]bool` holding
  `start`, `settings_change` and `membership_change`. Project 3 adds
  `credential_change` there, and adds the matching `hub.Trigger`.
- `ValidateSettingsSpec(t *Template, compose []byte, routes *Routes, known func(typ string) bool) error`.
  `Discover(dir, source, domain string, known func(typ string) bool)`
  passes `known` through. `templates.BuiltinTypes` is what nil means.

**Types (`internal/settings`):**
- `type Value = any`, plus `Unlimited struct{}`.
- `Kind` interface: `Name()`, `CheckOption(o)`, `Parse(o, raw)`,
  `Display(o, v)`, `Compare(o, a, b) (int, bool)`.
- Optional kind interfaces:
  - `Mounter` → `HostPath(o *templates.Option, v Value) (string, error)`:
    host-directory values (path now; folder/`folder:<id>` in project 2);
  - `PerPersonKind` → `PersonValues(ctx context.Context, instance string, o *templates.Option, people []Person) (map[string]Value, error)`:
    values the Hub computes per person instead of resolving them
    (project 3 `person_id`, `person_secret` status).
- Registry: `NewRegistry() *Registry`, `(*Registry).Register(k Kind)`,
  `Kind(typ) (Kind, error)`, `Known(typ) bool`, `Parse`, `Display`.
  - `*ErrNotImplemented{Type, Feature string}`.
  - The Hub's registry is `(*hub.Hub).Kinds() *settings.Registry`.
    Register before `Init` / Discover.
- Resolution:
  - `Person{User string; Groups map[string]int}` (lowercase user; group
    name → LLDAP id);
  - `Row{Group string; GroupID int; Value Value}`;
  - `PersonConfig{Default Value; Rule string; Rows []Row}`;
  - `Resolved{Value; Reason}`;
  - `Reason{Source, Group string; Groups []string; Rule string; Others []Candidate}`;
  - `(*Registry).Resolve` / `ResolveAll`.
- Render: `Render(o, v, rd *templates.Render) (Rendered{Text string; JSON any}, error)`.
- Ownership: `ResolveOwner(o *templates.Option, instance map[string]Value) (uid, gid int, err error)`.
- Effects: `EffectNone|EffectReload|EffectRestart`, `EffectOf(applies)`,
  `Strongest(...)`.
- Wire formats (contract §13.7–13.8), both version 1
  (`DataFileVersion`, `HookInputVersion`):
  - `DataFileDoc{Version, Instance, Values, People, Groups}`;
  - `SecretsFileDoc{Version, Instance, Secrets}`;
  - `HookInput{DataFileDoc; Trigger; Secrets}`;
  - `GroupRecordOut{Group, Value}`.

  Project 3 adds a `Credentials` field to `HookInput`.

**State (`internal/state`):**
- `AppState.Settings map[string]InstanceSettings`.
- `InstanceSettings{Ports, Values, Types, Person, Groups, Secrets}`.
- `PersonSetting{Default, Resolve, Rows []GroupValue}`.
- `GroupValue{Group string; GroupID int; Value any}`.
- `SecretMeta{UpdatedAt, Generated}`.
- Project 3 adds its own top-level fields (e.g. the `person_id` pools).
  Per-instance hashes go under `<data>/settings/<id>/`, never in
  `state.yaml`.

**Hub (`internal/hub`):**
- Paths and files:
  - `FolderSource` interface `FolderHostPath(id, subpath string) (string, error)`,
    set with `(*Hub).SetFolderSource(f FolderSource)`. Without it,
    `folder:` path values are refused.
  - `(*Hub).PathUsages() []PathUsage`, where
    `PathUsage{Instance, Key, Type, HostPath, Service, Mount, Mode, Needs string; UID, GID int; OwnerKnown bool}`:
    the doctor's input.
  - Per-instance private storage: `<data>/settings/<id>/` (`secrets.json`,
    `delivered.json`).
  - Data files: `<Config.AppFilesDir>/<id>/<name>/` (host
    `<ProjectHostDir>/appfiles/<id>/<name>`), mounted read-only at the
    file's `mount`.
- Population:
  - `Population{People []settings.Person; Why string}`;
  - `(*Hub).populationLocked(t, m)` (internal);
  - `(*Hub).InPopulation(ctx context.Context, instance, user string) (bool, error)`:
    project 3's credential routes refuse 404 when it returns false.
- Directory hooks:
  - `People` interface: `Membership(ctx, now) (*directory.Membership, error)`
    and `PrivilegeProblem(ctx, group) (string, error)`, set with
    `SetPeople`;
  - `(*Hub).PurgeGroupSettings(ctx, actor, name string, id int) []string`.
- Delivery:
  - `type Trigger string`: `TriggerStart`, `TriggerSave`,
    `TriggerMembership`, `TriggerRetry`;
  - `(*Hub).Deliver(ctx, id string, trig Trigger) (*DeliveryReport, error)`;
  - `(*Hub).TriggerDelivery(id string, trig Trigger, immediate bool)`.
    `immediate=true` bypasses the 60 s `settingsDebounce`, which is what
    project 3's revoke-on-leave needs.
  - `(*Hub).DeliveryStatus(id) DeliveryStatus`.
  - Unit ids `env`, `file:<name>`, `hook:<name>`, `claim:<attr>`,
    `headers`, `reload`, `restart`. Project 3 adds its own units, e.g.
    `credentials:<key>`.
- Engine:
  - `ExecStdin(ctx, id string, in docker.ExecInput{Cmd []string; User string; Stdin []byte; Timeout time.Duration}) (*docker.ExecResult, error)`;
  - `ContainerKill(ctx, id, signal string) error`;
  - `ContainerState(ctx, id string) (docker.State{Running bool; Health string}, error)`.
- Secrets and redaction (internal): `secretValues(id)`,
  `knownSecrets(id)`, `redactValues(s, secrets)`. Redact, then clip.
- Claim attribute naming: `SettingAttr(instance, key string) string` gives
  `ps_` + 12 hex. The `ps_` prefix is reserved
  (`directory.ReservedAttrPrefix`).

**My apps (people listener, contract §5.1):**
- `GET /api/me/apps` returns `{"apps": [MyApp]}`.
- `MyApp{ID, Name, Icon, URL string; Values []MyValue; Credentials []MyCredential}`.
  `Credentials` is always `[]` in project 1.
- `MyValue{Key, Label, Value, Applies string; Reason MyReason}`.
- `MyReason{Source, Group string; Groups []string}`: the caller's own
  groups only.
- `MyCredential{Key, Label, Status string; Since *time.Time; Reason string; Info []MyInfoLine}`,
  with `MyInfoLine{Label, Value string}`.
- `(*Hub).MyApps(ctx, user string) ([]MyApp, error)`.
- The people-route allowlist is
  `var peopleAppRoutes = []string{"GET /api/me/apps"}` in
  `internal/httpapi/people_test.go`. Project 3 appends
  `POST /api/me/apps/{instance}/credentials/{key}` and
  `DELETE /api/me/apps/{instance}/credentials/{key}`.
- UI: `web/myapps.js` renders `credentials[]` per app. Extra tabs go
  through `PortcullisDirectory.show(el, {extraTabs: [{id, label, render}]})`.

**Directory (`internal/directory`):**
- `Membership{Users map[string]map[string]int; Groups map[string]MemberGroup{ID int; Members []string}; Expired map[string]map[string]bool}`.
- `(*Service).Membership(ctx, now)`.
- `(*Service).PrivilegeProblem(ctx, group)`.
- `App.PrivilegedGroups []string`: they become guarding groups.
- `Service.GroupDeleted func(ctx, actor, name string, id int)`.
- `ReservedAttrPrefix = "ps_"`.

**Keycloak / LLDAP:**
- `keycloak.SettingMapperPrefix = "portcullis-setting-"`.
- `keycloak.SettingClaim{Attr, Claim, JSONType string}`.
- `(*keycloak.Client).EnsureSettingClaims(ctx, clientID, owner string, claims []SettingClaim) error`.
- `(*keycloak.Client).RemoveSettingClaims(ctx, clientID, owner string, attrs []string) error`.
- `(*lldap.Client).AddHiddenUserAttribute(ctx, name string) error`.

**Admin API (Hub listener, admins only):**
- `GET|PUT /api/instances/{id}/settings`.
- `POST /api/instances/{id}/settings/preview`.
- `POST /api/instances/{id}/settings/retry`.
- Audit actions: `settings.change`, `settings.purge`, `settings.retry`.
- Project 3's admin credential routes sit beside these under
  `/api/instances/{id}/credentials`.
