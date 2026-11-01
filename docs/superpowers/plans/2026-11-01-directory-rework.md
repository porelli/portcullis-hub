# Users & Groups Rework Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Custom user fields, rule-based groups with exceptions and expiry,
delegated permissions, CSV import with an editable review, an org chart, and
fields reaching apps. All of it is served to every signed-in user on
`people.<domain>`, while `hub.<domain>` stays admin-only.

**Architecture:**
- **Data:** LLDAP stays the source of truth for people, groups and field
  values (custom user attributes). The Hub stores what LLDAP can't hold in
  `<data>/directory.yaml`: field metadata, group rules, exceptions,
  expiries and permission grants.
- **Group sync:** a deterministic evaluator writes computed membership
  into real LLDAP groups. Keycloak and group-gate therefore keep working
  on plain groups.
- **Publishing:** the Hub publishes pending expiries and shared field
  values next to the policy file. Core's group-gate drops expired
  memberships and emits `X-Forwarded-Attr-*` headers.
- **Two listeners:** a second Hub listener serves only the directory, for
  `people.<domain>`.

**Tech Stack:**
- Hub: Go (stdlib + `gopkg.in/yaml.v3`), vanilla JS.
- Core: Python 3 stdlib group-gate, Traefik v3 labels.
- LLDAP 0.6.3 GraphQL; Keycloak 26 admin API.

**Spec:** `docs/superpowers/specs/2026-11-01-directory-rework-design.md` (hub repo)

## Global Constraints

- **Hub dependencies:** stdlib + `gopkg.in/yaml.v3` only. No JS build step.
  Escape every interpolation with `escapeHtml`.
- **Checks after every Hub change:** `go vet ./... && go test -race ./...`
  and `gofmt -l .` (empty).
- **Core group-gate:** stdlib only. Run
  `python3 -m unittest discover -s group-gate -p 'test_*.py'`.
- **No migration or back-compat code.** There are no installs.
- **Never log, audit or put in errors** a password, token or invite link.
- **Identity is the LLDAP username** (lowercased for comparisons), never
  the email.
- **The cross-repo contract changes first:**
  `portcullis-docs/docs/guides/integration-contracts.md`.
- **Work on `main` in every repo.** Commit per task and push at the end of
  each phase.
- **Exact names:**
  - subdomain `people`;
  - claim `attr_<field>`;
  - header `X-Forwarded-Attr-<Field>` (`<Field>` = the field name with
    each `_`-separated word capitalised, e.g. `cost_center` →
    `Cost-Center`);
  - client scope `portcullis-attributes`;
  - files `<data>/directory.yaml` and `<policy dir>/user-attributes.json`;
  - permissions `edit_details`, `invite`, `remove`.
- **Field names:** `^[a-z][a-z0-9_]{0,30}$`. They must not be LLDAP
  built-ins (`mail`, `uid`, `display_name`, `first_name`, `last_name`,
  `avatar`, `creation_date`, `uuid`, `user_id`).
- **Every field is created in LLDAP as** `attributeType: STRING`,
  `isVisible: true`, `isEditable: false`.

## Review Focus

1. **Spreadsheet CSVs:**
   - Excel exports with a UTF-8 BOM, `;` separators (European locales),
     CRLF line endings and quoted cells with newlines must parse.
   - The username column is matched case-insensitively.
   - Pinned in Task 8 (`TestParseCSVExcelVariants`).
2. **Manager cycles and dangling managers:**
   - `a→b→a`, self-manager, and a manager who was deleted.
   - "reports to" must terminate, the org chart must still render, and
     the cycle must be flagged rather than crash.
   - Pinned in Task 3 (`TestReportsToCycle`) and Task 12 (UI renders
     flagged nodes).
3. **Edits made outside the Hub:**
   - Someone adds a member in LLDAP's own UI, or deletes a field or group
     there.
   - The evaluator must revert rule-group membership with the cause
     `reverted: outside change`, and must never crash on unknown
     attributes.
   - Pinned in Task 5 (`TestEvaluateRevertsOutsideChange`,
     `TestEvaluateIgnoresUnknownAttribute`).
4. **Expiry time zones and boundaries:**
   - Expiries are entered in the browser's local time and stored in UTC
     (RFC 3339).
   - A membership expiring "now" is gone in both the evaluator and
     group-gate.
   - Pinned in Task 5 (`TestExpiryBoundary`) and Task 11
     (`test_expired_membership_stripped`).
5. **Delegate escalation attempts:**
   - An editor changes their own fields; an editor changes another
     editor's fields; an inviter re-invites an admin.
   - All are refused with 403 and audited as `refused`.
   - Pinned in Task 6 (`TestDelegateCannotEscalate`).

---

## Phase A — Hub data model (hub repo)

### Task 1: LLDAP custom attributes

**Files:**
- Modify: `internal/lldap/client.go` (types `User`, new methods)
- Modify: `internal/lldap/lldaptest/fake.go` (schema, attributes,
  `insertAttributes`/`removeAttributes` in `updateUser`)
- Test: `internal/lldap/client_test.go`

**Interfaces:**
- Produces:
  - `type Attribute struct { Name string; IsList bool }`
  - `func (c *Client) UserAttributes(ctx) ([]Attribute, error)`: the
    schema's non-hardcoded user attributes;
  - `func (c *Client) AddUserAttribute(ctx, name string, isList bool) error`:
    STRING, visible, not editable;
  - `func (c *Client) DeleteUserAttribute(ctx, name string) error`;
  - `func (c *Client) SetUserAttributes(ctx, user string, set map[string][]string, remove []string) error`;
  - `User.Attributes map[string][]string`, filled by `ListUsers` from
    `attributes { name value }`, custom attributes only.
  - Add all four methods to `directory.Directory`.

- [ ] **Step 1: Write the failing tests.**
  - `TestUserAttributesRoundTrip`: add `city` (single) and `languages`
    (list) through the fake. Set `city=["Milan"]` and
    `languages=["it","en"]` on `anna`, and `ListUsers` returns them.
    Remove `city`, and it is gone.
  - `TestAddUserAttributeFlags`: the fake records
    `attributeType == "STRING"`, `isVisible == true` and
    `isEditable == false`.
- [ ] **Step 2:** `go test ./internal/lldap/ -run 'Attribute'` → FAIL
  (undefined).
- [ ] **Step 3: Implement.**
  - The GraphQL is `schema { userSchema { attributes { name isList isHardcoded } } }`,
    `addUserAttribute(name:, attributeType: STRING, isList:, isVisible: true, isEditable: false)`
    and `deleteUserAttribute(name:)`.
  - `updateUser(user: {id, insertAttributes: [{name, value}], removeAttributes: [..]})`.
  - Extend the fake to match.
- [ ] **Step 4:** run the tests → PASS. Run the full suite.
- [ ] **Step 5:** commit
  `lldap: custom user attributes (schema, values) + fake`.

### Task 2: Directory store (`directory.yaml`)

**Files:**
- Create: `internal/directory/store.go`,
  `internal/directory/store_test.go`

**Interfaces:**
- Produces:
```go
type FieldKind string // "text" | "list" | "person"
type Field struct {
    Name, Label string; Kind FieldKind
    Values []string   // list kind: allowed values, in order
    Multi, ShareWithApps, AdminOnly bool
}
type Exception struct {
    User, Reason, By string
    Include bool              // true = added though not matching; false = kept out
    Until *time.Time          // nil = permanent
    At time.Time
}
type GroupConfig struct {
    Rule *rules.Expr          // nil = manual group
    Exceptions []Exception    // rule groups only
    Expiry map[string]time.Time // manual groups: username -> until
}
type Config struct {
    Version int                     // 1
    Fields []Field
    Groups map[string]*GroupConfig  // by LLDAP group name
    Permissions map[string]string   // "edit_details"|"invite"|"remove" -> group name
    CreatedBy map[string]string     // username -> delegate who invited them (admins: not recorded)
}
type Store struct{ Path string }
func (s *Store) Load() (*Config, error)   // missing file = empty Config; corrupt = error
func (s *Store) Save(c *Config) error     // fsutil atomic write, 0600
```
- `rules.Expr` comes from Task 3. Write Task 3 first or stub the import.
  Tasks 2 and 3 can be implemented in either order, but Task 2's tests
  need `rules.Parse`.

- [ ] **Step 1: Write the failing tests.**
  - `TestStoreRoundTrip`: a Config with one field of each kind, one rule
    group with an exception expiring 2027-03-31T00:00:00Z, and one
    permission. Save, Load, and get the deep-equal value back.
  - `TestStoreMissingIsEmpty`.
  - `TestStoreCorruptRefuses`: garbage YAML → error mentioning the path.
  - `TestStoreUnknownVersionRefuses`: `version: 2` → error.
- [ ] **Step 2:** run → FAIL.
- [ ] **Step 3: Implement.** Use YAML with `KnownFields(true)`. A rule
  serialises as its text form (`rules.Format`) and is parsed on load. A
  parse error makes the load fail.
- [ ] **Step 4:** run → PASS.
- [ ] **Step 5:** commit `directory: directory.yaml store`.

### Task 3: Rule language (blocks ⇄ text, evaluation)

**Files:**
- Create: `internal/rules/rules.go`, `internal/rules/parse.go`,
  `internal/rules/rules_test.go`

**Interfaces:**
- Produces:
```go
type Op string // "all" | "any" | "is" | "is_not" | "in" | "empty" | "reports_to"
type Expr struct {
    Op     Op      `json:"op"`
    Field  string  `json:"field,omitempty"`
    Values []string `json:"values,omitempty"` // is/is_not: 1; in: >=1; reports_to: 1 username
    Not    bool    `json:"not,omitempty"`     // negates the node
    Items  []*Expr `json:"items,omitempty"`   // all/any
}
type Person struct { User string; Attrs map[string][]string } // attrs lowercase keys
type Directory struct { People map[string]Person; ManagerField string } // ManagerField "" = no reports_to
func Parse(text string) (*Expr, error)        // errors carry 1-based column
func Format(e *Expr) string                   // canonical text; Parse(Format(e)) deep-equals e
func Eval(e *Expr, user string, d *Directory) bool
func Fields(e *Expr) []string                 // every field referenced, sorted, unique
func Cycles(d *Directory) [][]string          // manager cycles, each sorted
```
- **Text grammar.** Keywords are case-insensitive; strings use `"…"` with
  `\"` and `\\` escapes:
  `expr := or ; or := and ("or" and)* ; and := unary ("and" unary)* ; unary := "not" unary | "(" expr ")" | cond`
  `cond := field ("=" str | "!=" str | "in" "(" str ("," str)* ")" | "is" "empty" | "reports-to" str)`
- **Semantics:**
  - `is` on a multi-valued field means "contains"; `!=` is "doesn't
    contain".
  - `empty` means no value.
  - `reports_to` walks up the manager chain from the user's manager, at
    most `len(People)` steps (so cycles terminate). It is true if it
    meets the given username. The user is never their own report.
  - Values are compared case-sensitively for list fields (exact values)
    and case-insensitively for text fields. The caller tells `Eval`
    nothing about kinds: the evaluator lowercases text-field values
    before building `Directory`.

- [ ] **Step 1: Write the failing tests.**
  - `TestParseFormatRoundTrip`: table of texts →
    `Format(Parse(x)) == canonical(x)`, including
    `city = "Milan" and (department = "Sales" or department = "Support")`,
    `not department = "HR"`, `city in ("Milan","Turin")`,
    `manager reports-to "anna"`, `languages is empty`, and a value
    containing `\"`.
  - `TestParseErrors`: `city = ` → error with column 8; `(city = "a"` →
    error; an unknown operator → error.
  - `TestEval`: the spec's example rule against 5 people, with expected
    matches.
  - `TestReportsTo`: chain `c→b→a`, so `c reports-to "a"` is true and
    `a reports-to "a"` is false.
  - `TestReportsToCycle`: `a→b→a` terminates. `a reports-to "b"` is true;
    `Cycles` returns `[[a b]]`.
  - `TestFields`.
- [ ] **Step 2:** run → FAIL.
- [ ] **Step 3: Implement** a recursive-descent parser. `Format` puts
  parentheses around `or` inside `and`, and around `not` of a compound.
- [ ] **Step 4:** run → PASS.
- [ ] **Step 5:** commit `rules: rule language (parse/format/eval)`.

### Task 4: Fields service + guardrails

**Files:**
- Create: `internal/directory/fields.go`,
  `internal/directory/fields_test.go`
- Modify: `internal/directory/service.go` (`Service` gains
  `Store *Store`; `Overview` gains `Fields []Field`, and `UserView` gains
  `Attrs map[string][]string`)

**Interfaces:**
- Consumes: Task 1 methods, the Task 2 `Store`, `rules.Fields`.
- Produces:
  - `func (s *Service) CreateField(ctx, actor string, f Field) error`.
    The API defaults `ShareWithApps` to true when it's omitted.
  - `func (s *Service) UpdateField(ctx, actor string, f Field) error`:
    `Kind` and `Multi` can't change;
  - `func (s *Service) DeleteField(ctx, actor, name, confirm string) error`;
  - `func (s *Service) guardedFields(cfg *Config) map[string]string`:
    field → the group that forces it admin-only.

- [ ] **Step 1: Write the failing tests.**
  - `TestCreateFieldCreatesLLDAPAttribute`: list kind with
    `Multi=false` → the LLDAP attribute has `isList=false`, and
    `directory.yaml` has the field.
  - `TestFieldNameRules`: refuses `Mail`, `mail`, `9x`, `a-b`.
  - `TestDeleteFieldInUseRefused`: refused with 409 while a rule
    references it, and the message lists the groups.
  - `TestAdminOnlyLockedWhileGuarding`: a field used by a permission
    group's rule → `UpdateField` with `AdminOnly=false` is refused.
  - `TestRemoveListValueInUseRefused`.
  - Every mutation is audited (`field.create`, `field.update`,
    `field.delete`).
- [ ] **Step 2:** run → FAIL.
- [ ] **Step 3: Implement** via `s.run`. Fields are admin-only operations:
  the caller check comes in Task 6, so for now note `// admin only` and
  add it to the parity list in Task 6.
- [ ] **Step 4:** run → PASS.
- [ ] **Step 5:** commit `directory: custom fields`.

### Task 5: Evaluator (rule groups, exceptions, expiry)

**Files:**
- Create: `internal/directory/evaluate.go`,
  `internal/directory/evaluate_test.go`
- Modify: `cmd/hub/main.go` (run `Evaluate` every 60 s, and after each
  mutation, through a non-blocking `s.kick()`)

**Interfaces:**
- Consumes: Task 3 (`rules.Eval`), Task 2, `Keycloak.LogoutUser`.
- Produces:
  - `func (s *Service) Evaluate(ctx context.Context, now time.Time) (*EvalReport, error)`
  - `type Change struct{ Group, User string; Add bool; Cause string }`.
    Causes: `rule`, `exception`, `exception expired`, `membership expired`,
    `reverted: outside change`.
  - `type EvalReport struct{ Changes []Change; Cycles [][]string; Errors []string }`
  - `func (s *Service) Desired(cfg *Config, sn *snapshot, now time.Time) map[string]map[string]bool`:
    pure, rule groups only.
  - `func (s *Service) Pending(cfg *Config, now time.Time) []Expiring`
    with `type Expiring struct{ User, Group string; At time.Time }`, used
    by Task 10.

- [ ] **Step 1: Write the failing tests.**
  - `TestEvaluateRuleGroup`: rule `city = "Milan"` → members match; a
    second run makes no changes (idempotent).
  - `TestExceptionIncludeExclude`.
  - `TestExpiryBoundary`: an exception until `now` → removed when
    evaluated at `now`, present at `now-1s`. The same for a manual-group
    `Expiry`, which is removed from LLDAP and dropped from the config.
  - `TestEvaluateRevertsOutsideChange`: a fake member added directly →
    removed, with cause `reverted: outside change`.
  - `TestEvaluateIgnoresUnknownAttribute`.
  - `TestRemovalLogsOut`: every removal calls `KC.LogoutUser(user)`.
  - `TestProtectedAccountsNeverRuleMembers`: the service user and `admin`
    are never added by any rule.
  - Each change appends an audit entry with action `group.sync`,
    detail = cause.
- [ ] **Step 2:** run → FAIL.
- [ ] **Step 3: Implement.**
  - Hold `s.mu` only around reading the config and snapshot and around
    applying changes, never across Keycloak calls.
  - Text-field values are lowercased into `rules.Directory`; list-field
    values are kept as-is.
  - Expired exceptions and expiries are pruned from the config and saved.
- [ ] **Step 4:** run → PASS.
- [ ] **Step 5:** commit
  `directory: evaluator (rule groups, exceptions, expiry)`.

### Task 6: Permissions and caller checks

**Files:**
- Create: `internal/directory/authz.go`, `internal/directory/authz_test.go`
- Modify: `internal/directory/service.go` (`checkTarget` gets an actor
  overload), `internal/directory/service_test.go`
  (`TestProtectedAccountsParity`)

**Interfaces:**
- Produces:
  - `type Caller struct{ User string; Admin bool; Perms map[string]bool }`
  - `func (s *Service) CallerFor(ctx, user string) (*Caller, error)`.
    `Admin` = member of `lldap_admin`; `Perms` from the
    `Config.Permissions` group memberships.
  - `func (s *Service) authorize(c *Caller, perm, target string, sn *snapshot, cfg *Config) error`.
    The `perm` value `admin` means admins only.
  - Every public mutating method gains a leading `c *Caller` parameter in
    place of `actor string`. `httpapi` builds the Caller once per request.
  - A delegate can't target:
    - themselves (`edit_details`);
    - administrators, the service user or `admin`;
    - members of any permission group.
- **Group constraints**, enforced in `SetGroupRule` (Task 7):
  - built-in or protected groups can't be rule-based;
  - rules of protected groups, permission groups and app admin groups
    (`App.AdminGroup`) may only use `AdminOnly` fields.

- [ ] **Step 1: Write the failing tests.**
  - `TestDelegateCannotEscalate`: an editor sets their own `department`
    → 403. An editor edits another editor → 403. An inviter re-invites an
    admin → 403. A remover removes an admin → 403. Each refusal is in the
    audit log as `refused`.
  - `TestDelegateAllowed`: an editor edits an ordinary user; an inviter
    creates a user (no groups allowed in the request → 400 if groups are
    given).
  - Extend `TestProtectedAccountsParity` to every new method.
- [ ] **Step 2:** run → FAIL.
- [ ] **Step 3:** implement, and thread `*Caller` through the existing
  methods. Today's behaviour must still hold for admins.
- [ ] **Step 4:** run the full suite → PASS.
- [ ] **Step 5:** commit `directory: delegated permissions and caller checks`.

### Task 7: Group config operations

**Files:**
- Create: `internal/directory/groups.go`, `internal/directory/groups_test.go`

**Interfaces:**
- Produces (all `(ctx, c *Caller, …) error` unless shown otherwise; admin
  only):
  - `SetGroupRule(group string, rule *rules.Expr)`. A nil rule makes the
    group manual again; current members stay as manual members.
  - `ConvertPreview(group string, rule *rules.Expr) (*ConvertPreview, error)`
    with
    `type ConvertPreview struct{ Matching, KeptAsException, Joining []string }`.
  - `ConvertApply(group string, rule *rules.Expr, keep []string)`. The
    kept members become `Include` exceptions with reason
    `member before the rule (set by <actor> on <YYYY-MM-DD>)`.
  - `AddException(group string, e Exception)`; `Reason` is required and
    non-blank.
  - `RemoveException(group, user string)`.
  - `SetMemberExpiry(group, user string, until *time.Time)` for manual
    groups.
  - `SetPermission(perm, group string)`; an empty group means nobody.
  - `PreviewRule(rule *rules.Expr) ([]string, error)`: live match list
    for any signed-in caller, sorted.

- [ ] **Step 1: Write the failing tests.**
  - `TestConvertKeepsAsExceptions`.
  - `TestRuleOnBuiltinRefused` (`lldap_admin` and each `ProtectedGroups`
    member).
  - `TestRuleOnPermissionGroupNeedsAdminOnlyFields`.
  - `TestRuleOnAppAdminGroupNeedsAdminOnlyFields`.
  - `TestExceptionNeedsReason`.
  - `TestPreviewRule`.
- [ ] **Step 2:** run → FAIL.
- [ ] **Step 3:** implement. Each mutation saves the store, kicks the
  evaluator and is audited (`group.rule`, `group.exception`,
  `group.expiry`, `permission.set`).
- [ ] **Step 4:** run → PASS.
- [ ] **Step 5:** commit `directory: rule groups, exceptions, expiry, permissions`.

### Task 8: Details editing + CSV import review

**Files:**
- Create: `internal/directory/details.go`, `internal/directory/importcsv.go`,
  `internal/directory/importcsv_test.go`

**Interfaces:**
- Produces:
  - `SetDetails(ctx, c *Caller, user string, attrs map[string][]string) error`,
    which needs `edit_details`. Values are validated by kind:
    - list → must be one of `Values`;
    - person → must be an existing username;
    - single-valued → at most one value;
    - `AdminOnly` fields → admins only.
  - `ParseCSV(r io.Reader) (header []string, rows [][]string, err error)`.
  - `type ReviewRow struct{ User, Status string; Cells map[string]Cell; Problems []string }`
    with Status `new|changed|missing|same`.
  - `type Cell struct{ Current, File []string }`.
  - `ImportReview(ctx, c *Caller, header []string, rows [][]string) (*Review, error)`
    with
    `type Review struct{ Rows []ReviewRow; UnknownColumns []string; Effect map[string][2]int }`.
    `Effect` is, per group, the number of members added and removed if
    the import is applied as-is.
  - `ImportApply(ctx, c *Caller, req ApplyRequest) (*ApplyResult, error)`:
    - `type ApplyRequest struct{ Rows []ApplyRow }`;
    - `type ApplyRow struct{ User string; Create, Remove bool; Attrs map[string][]string; DisplayName, Email string }`;
    - creating needs `invite` and sends an invite (returned once); setting
      `Attrs` on a created row also needs `edit_details`; a delegate's
      creation records `Config.CreatedBy[user] = actor`. Removing needs
      `remove`;
    - every row is re-validated (the review is advisory);
    - the result is per row, so a partial failure is reported, not
      rolled back.

- [ ] **Step 1: Write the failing tests.**
  - `TestParseCSVExcelVariants`: BOM + `;` + CRLF + a quoted newline
    parse to the same rows as plain `,`. The separator is detected from
    the header line.
  - `TestImportReviewStatuses`: new, changed, missing (in Portcullis but
    not in the file) and same. Username matching is case-insensitive.
  - `TestImportReviewProblems`: an unknown manager → a problem on that
    cell; a value outside the list → a problem; a duplicate username row
    → a problem.
  - `TestImportReviewEffect`: a `city` change from Rome to Milan →
    `sales-milan` gains +1.
  - `TestImportApplyRevalidates`: an `ApplyRow` with an invalid list
    value → that row fails while the others succeed.
  - Multi-valued cells use `|` as the separator.
- [ ] **Step 2:** run → FAIL.
- [ ] **Step 3:** implement with `encoding/csv`. Columns are `username`
  (required), `display_name`, `email`, then field names.
- [ ] **Step 4:** run → PASS.
- [ ] **Step 5:** commit `directory: details editing and CSV import review`.

---

## Phase B — publishing (hub + core)

### Task 9: Contract first (docs repo)

**Files:**
- Modify: `portcullis-docs/docs/guides/integration-contracts.md`:
  - §4: the policy file v4 adds `expiring`;
  - §5: the new headers;
  - §9: fields, permissions and `people`;
  - a new subsection: `user-attributes.json`.

- [ ] **Step 1: Write the contract.**
  - Policy file `version: 4` adds
    `"expiring": [{"user": "<lowercase>", "group": "<name>", "at": "<RFC3339 UTC>"}]`.
  - group-gate removes `group` from the user's groups once `now >= at`,
    and handles only version 4.
  - `user-attributes.json`:
    `{"version": 1, "fields": {"<field>": "<Header-Name>"}, "users": {"<lowercase user>": {"<field>": ["v", …]}}}`.
    It holds only fields with `ShareWithApps`, and is written atomically
    with mode 0644 beside the policy file.
  - Headers: `X-Forwarded-Attr-<Header-Name>`, values joined with `, `.
    Each value has CR, LF and other control characters removed, and is
    limited to 1 KB.
  - The client-headers middleware strips any `X-Forwarded-Attr-*` sent by
    the client.
  - `people` is a core subdomain whose map value `*` means "any signed-in
    user". `*` is valid only in the map file, never in the policy file.
  - The Hub's people listener: port `8889`, the same proxy-secret header.
- [ ] **Step 2:** commit to docs
  `contracts: user attributes, expiring memberships, people subdomain`.

### Task 10: Hub writes `expiring` + `user-attributes.json` + Keycloak mappers

**Files:**
- Modify: `internal/policy/file.go` (`FileVersion = 4`,
  `Document.Expiring []Expiring`), `internal/hub/hub.go` (`WritePolicy`
  also writes `user-attributes.json`)
- Create: `internal/keycloak/mappers.go`, `internal/keycloak/mappers_test.go`
- Test: `internal/policy/file_test.go`, `internal/hub/failclosed_test.go`

**Interfaces:**
- Consumes: Task 5 `Pending`, Task 4 fields, `rules`.
- Produces:
  - `func (c *Client) EnsureAttributeMappers(ctx, fields []AttrField) error`
    with `type AttrField struct{ Name string; Multi bool }`.
  - For each field it ensures:
    - an LDAP `user-attribute-ldap-mapper` on every LDAP provider
      (`ldap.attribute = <name>`, `user.model.attribute = attr_<name>`,
      read-only, always read from LDAP);
    - an `oidc-usermodel-attribute-mapper` on client scope
      `portcullis-attributes` (`claim.name = attr_<name>`, access + ID +
      userinfo token, `multivalued` = `Multi`).
  - It removes the mappers of fields that are no longer shared, and
    creates the scope as an optional default on every Hub-registered
    client.

- [ ] **Step 1: Write the failing tests.**
  - `TestPolicyFileV4Expiring`.
  - `TestUserAttributesFile`: only shared fields, lowercase users,
    header-name derivation (`cost_center` → `Cost-Center`).
  - `TestEnsureAttributeMappersIdempotent` (kctest fake), and removal
    when a field is unshared.
  - `WritePolicy` failure keeps the old files (atomic).
- [ ] **Step 2:** run → FAIL.
- [ ] **Step 3:** implement. The Hub triggers `WritePolicy` and
  `EnsureAttributeMappers` after every evaluator run and every field
  change.
- [ ] **Step 4:** run → PASS.
- [ ] **Step 5:** commit
  `policy v4 expiring, user-attributes.json, keycloak attribute mappers`.

### Task 11: Core: group-gate v4, attribute headers, `people` subdomain

**Files (core repo):**
- Modify:
  - `group-gate/group-gate.py`: `POLICY_VERSION = 4`;
    `PUBLIC_GUARD_VERSION = 4`; `people` in `CORE_SUBDOMAINS`; `*` map
    value; strip expired groups in `identity_headers` and in the group
    check; attribute headers;
  - `group-gate/group-gate-map.conf` (`people=*`).
- Modify `docker-compose.yml`:
  - `portcullis-groups` gets
    `authResponseHeadersRegex: ^X-Forwarded-Attr-`;
  - a Hub `people` router to port 8889 with
    `client-headers@file,portcullis-auth@docker,portcullis-groups@docker,hub-proxy-secret,security-headers@file`;
  - `HUB_PEOPLE_ADDR: ":8889"`.
- Modify: `traefik/dynamic/*` client-headers (strip `X-Forwarded-Attr-*`).
  Find the client-headers middleware with
  `grep -rn client-headers traefik/`.
- Modify: `scripts/lib/*.sh` wherever the core subdomain list or DNS
  setup is enumerated (`grep -rn '"metrics"\|metrics)' scripts/lib`).
- Test: `group-gate/test_group_gate.py` (find the actual test file name
  with `ls group-gate`; if the tests live in `tests/`, use that).

- [ ] **Step 1: Write the failing tests.**
  - `test_expired_membership_stripped`: groups header `a,b`, with
    expiring `b` at a time in the past → the group check uses `{a}`, and
    the returned `X-Auth-Request-Groups` is `a`.
  - `test_not_yet_expired_kept`.
  - `test_star_any_signed_in`: `people=*` allows any user with a session,
    and denies without one.
  - `test_star_ignored_in_policy_file`.
  - `test_attribute_headers`: the user has `city=["Milan"]` →
    `X-Forwarded-Attr-City: Milan`; a value with `\r\n` is sanitised; a
    missing or corrupt attributes file means no headers (not a deny).
  - `test_policy_v3_refused`.
- [ ] **Step 2:** run the group-gate tests → FAIL.
- [ ] **Step 3:** implement. The attributes file is loaded with the same
  mtime cache as the policy file.
- [ ] **Step 4:** run → PASS. Run the core CI-equivalent locally if one
  is available (`./portcullis` lint and shellcheck, per core's `CLAUDE.md`).
- [ ] **Step 5:** commit to core
  `group-gate v4: expiring memberships, attribute headers, people subdomain`.
  Push core and Hub together, since policy v4 needs both.

---

## Phase C — people listener + UI (hub repo)

### Task 12: People listener, API and UI

**Files:**
- Modify:
  - `internal/httpapi/server.go`: `func (s *Server) PeopleHandler() (http.Handler, error)`,
    which registers only directory routes, `/healthz` and the people page;
  - `internal/httpapi/directory.go`: new routes, Caller per request;
  - `cmd/hub/main.go`: a second `http.Server` on `HUB_PEOPLE_ADDR`
    (default `:8889`), with the same middleware chain (proxy secret,
    CSRF).
- Create:
  - `web/directory.js`: People, Groups, Org chart and Setup tabs; rule
    builder (blocks ⇄ text); import review; exceptions and expiry;
  - `web/directory.css`;
  - `web/people.html`: a shell that loads both.
- Modify: `web/index.html` (the Users & Groups tab loads `directory.js`
  instead of its inline code, which is removed), `web/web.go` (embed the
  new files).
- Test: `internal/httpapi/people_test.go`.

**Interfaces:**
- **New routes** on both listeners, all JSON:
  - `GET /api/directory/me` → `{user, admin, perms[]}`.
  - Fields: `POST /api/directory/fields`,
    `PUT /api/directory/fields/{name}`,
    `DELETE /api/directory/fields/{name}`.
  - `PUT /api/directory/users/{username}/details`.
  - Groups:
    - `POST /api/directory/rules/preview`, body `{rule: "<text>"}` or
      `{expr: Expr}`, returns `{users[], text, expr}`; this is also the
      text ⇄ blocks converter;
    - `PUT /api/directory/groups/{group}/rule`;
    - `POST /api/directory/groups/{group}/convert-preview`;
    - `POST /api/directory/groups/{group}/convert`;
    - `POST /api/directory/groups/{group}/exceptions`;
    - `DELETE /api/directory/groups/{group}/exceptions/{username}`;
    - `PUT /api/directory/groups/{group}/members/{username}/expiry`.
  - `PUT /api/directory/permissions/{perm}`.
  - Import: `POST /api/directory/import/review` (multipart `file`, max
    5 MB) and `POST /api/directory/import/apply`.
- `GET /api/directory` gains `fields`, user `attrs`, group
  `rule`/`exceptions`/`expiry`, `permissions`, `cycles`.
- **On the people listener:** non-admins see users without
  Keycloak/passkey internals, and the stale-Keycloak list and audit are
  admin-only.
- **The hub listener is unchanged:** admins only, enforced by core.

- [ ] **Step 1: Write the failing tests.**
  - `TestPeopleListenerHasNoAppRoutes`: on `PeopleHandler`,
    `/api/templates`, `/api/settings`, `/api/drift` and
    `/api/templates/compose/x` → 404.
  - `TestPeopleListenerReadForEveryone`: a plain user gets
    `/api/directory` with fields and attrs, but no `keycloak` fields and
    no audit.
  - `TestRulePreviewConverts`: text in → expr out, and back.
  - `TestImportReviewUploadLimit`: 6 MB → 413.
- [ ] **Step 2:** run → FAIL.
- [ ] **Step 3:** implement the handlers and the listener.
- [ ] **Step 4: Implement the UI**, layout A from the spec. These are the
  behaviours a reviewer will click through:
  - **People:**
    - a search box;
    - columns for the fields; ⚡ marks membership via a rule, and an
      exception shows a ✱ with its reason on hover; a rule membership of
      a delegate-created account shows "via rule, account created by X";
    - Invite and Import CSV buttons shown only with the matching
      permission;
    - a row opens details (editable by permission), groups and keys
      (admins only).
  - **Groups:**
    - a "Missing groups" card;
    - each group shows "Manual" or a ⚡ rule;
    - the rule editor has blocks by default and a "show as text" toggle.
      Converting goes through `/rules/preview`, and the toggle refuses to
      switch while the text doesn't parse, with the error column shown.
    - a live preview count (debounced to 300 ms);
    - exceptions need a reason and take an optional expiry (local
      datetime → UTC);
    - manual members can have an expiry;
    - "make rule-based" opens the convert-preview dialog.
  - **Org chart:** nested lists from the manager field, plus a list of
    people with no manager. Cycle members are shown with ⚠ "manager loop".
  - **Import review:**
    - the editable table from mockup v2;
    - filters new/changed/missing/same (same hidden by default);
    - ↺ keeps the current value;
    - problems block Apply;
    - the effect box (`Effect`) is recomputed by calling review again
      with the edited rows, debounced;
    - "missing" rows are unticked;
    - "+ add row" for a person typed by hand;
    - Download CSV.
  - **Setup** (admins only): a field list (name, label, kind, values,
    several values, share with apps, admin-only) and a permission → group
    picker.
- [ ] **Step 5:** run → PASS. Check by hand with a local demo
  (`go run ./cmd/hub` against the lldaptest fake if a demo main exists;
  otherwise use the tests plus the deploy check in Task 14).
- [ ] **Step 6:** commit `people listener, directory UI (fields, rules, import, org chart)`.

---

## Phase D — docs, deploy, verify

### Task 13: Docs

**Files (docs repo):**
- Modify:
  - `docs/operations/hub.md`: Users & Groups rewrite (tabs, fields,
    rules, exceptions, expiry, import, permissions, people page);
  - `docs/operations/groups.md`: rule-based groups, protected-group
    constraints;
  - `docs/guides/header-auth-app.md`: `X-Forwarded-Attr-*`;
  - `docs/operations/hardening.md`: header stripping, the people
    listener;
  - `docs/setup/quickstart.md`: the `people` subdomain in the DNS list,
    `HUB_PEOPLE_ADDR`;
  - `docs/architecture.md`.
- [ ] **Step 1:** write the pages.
- [ ] **Step 2:** check the links by hand (zensical isn't installed
  locally). Run the forbidden-scripts grep from the docs `CLAUDE.md` →
  empty.
- [ ] **Step 3:** commit and push.

### Task 14: Deploy and live check

- [ ] **Step 1:** wait for hub and core CI to go green (`gh run list` in
  each repo).
- [ ] **Step 2:** deploy:
  `ssh admin@<test server> 'cd ~/portcullis && git pull -q && ./portcullis upgrade'`.
  Then confirm the Hub image revision label equals the pushed SHA.
- [ ] **Step 3:** live E2E with the Playwright helpers in `/tmp/pwcheck`,
  using throwaway users only and never touching `admin`:
  1. Create the fields `city` (list: Milan, Turin) and `department` (list,
     admin-only), plus `manager` (person).
  2. Make `hr-editors` rule-based (`department = "HR"`) and grant it
     `edit_details`.
  3. A throwaway HR user signs in at `people.<domain>`, edits a user's
     city, and fails to edit their own record (403).
  4. Rule group `milan` (`city = "Milan"`) gains that user within 60 s.
  5. Grafana (header-auth) receives `X-Forwarded-Attr-City`. Check it
     with a header-echo template, or the Grafana proxy log.
  6. An exception with an expiry 2 minutes ahead: access ends after
     expiry, even with the Hub stopped.
  7. CSV import of 3 rows (1 new, 1 changed, 1 problem): Apply stays
     blocked until the problem is fixed.
  8. Delete the throwaway users and fields afterwards.
- [ ] **Step 4:** report the results to the user.
