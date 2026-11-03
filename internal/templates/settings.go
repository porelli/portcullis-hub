package templates

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/portcullis/hub/internal/policy"
)

// Settings (template contract v3, integration contracts §13): the
// manifest's typed options with their scopes, constraints and deliveries,
// plus the data files, hooks and reload action deliveries name. The types
// here are the manifest model; values, rendering and resolution live in
// internal/settings.

// SettingsSpec is the manifest's settings block.
type SettingsSpec struct {
	Sections []string `yaml:"sections" json:"sections,omitempty"`
	Options  []Option `yaml:"options" json:"options"`
}

// Option is one setting (§13.1).
type Option struct {
	Key         string `yaml:"key" json:"key"`
	Label       string `yaml:"label" json:"label"`
	Description string `yaml:"description" json:"description,omitempty"`
	Section     string `yaml:"section" json:"section,omitempty"`
	Type        string `yaml:"type" json:"type"`
	// Scope "" = ScopeInstance (EffectiveScope).
	Scope          string         `yaml:"scope" json:"scope,omitempty"`
	Applies        string         `yaml:"applies" json:"applies,omitempty"`
	Required       bool           `yaml:"required" json:"required,omitempty"`
	Default        any            `yaml:"default" json:"default,omitempty"`
	Pattern        string         `yaml:"pattern" json:"pattern,omitempty"`
	Format         string         `yaml:"format" json:"format,omitempty"`
	MinLen         *int           `yaml:"min_len" json:"min_len,omitempty"`
	MaxLen         *int           `yaml:"max_len" json:"max_len,omitempty"`
	MinItems       *int           `yaml:"min_items" json:"min_items,omitempty"`
	MaxItems       *int           `yaml:"max_items" json:"max_items,omitempty"`
	Min            any            `yaml:"min" json:"min,omitempty"` // numbers, or "1GiB" / "30d" strings
	Max            any            `yaml:"max" json:"max,omitempty"`
	Step           any            `yaml:"step" json:"step,omitempty"`
	Unit           string         `yaml:"unit" json:"unit,omitempty"`
	AllowUnlimited bool           `yaml:"allow_unlimited" json:"allow_unlimited,omitempty"`
	Choices        []EnumOption   `yaml:"options" json:"options,omitempty"`
	Items          *ItemSpec      `yaml:"items" json:"items,omitempty"` // list
	Unique         bool           `yaml:"unique" json:"unique,omitempty"`
	Columns        []Column       `yaml:"columns" json:"columns,omitempty"` // table
	KeyColumn      string         `yaml:"key_column" json:"key_column,omitempty"`
	Target         *SettingTarget `yaml:"target" json:"target,omitempty"` // path
	Mode           string         `yaml:"mode" json:"mode,omitempty"`     // ro | rw
	Needs          string         `yaml:"needs" json:"needs,omitempty"`   // read | write
	WritesAs       *Owner         `yaml:"writes_as" json:"writes_as,omitempty"`
	Generate       *GenerateSpec  `yaml:"generate" json:"generate,omitempty"` // secret
	Resolve        string         `yaml:"resolve" json:"resolve,omitempty"`
	ResolveChoices []string       `yaml:"resolve_choices" json:"resolve_choices,omitempty"`
	GroupValues    map[string]any `yaml:"group_values" json:"group_values,omitempty"`
	Privileged     bool           `yaml:"privileged" json:"privileged,omitempty"`
	// AdminOverride (person_entered only, call 32): admins may set a value.
	AdminOverride bool `yaml:"admin_override" json:"admin_override,omitempty"`
	// SelfVisible nil = true.
	SelfVisible *bool      `yaml:"self_visible" json:"self_visible,omitempty"`
	Requires    []string   `yaml:"requires" json:"requires,omitempty"`
	Delivery    Deliveries `yaml:"delivery" json:"delivery,omitempty"`

	// Shared folders (§13.15): a path option's folder block (it replaces
	// mode, needs and writes_as) and the option's doctor checks.
	Folder *FolderSpec `yaml:"folder" json:"folder,omitempty"`
	Checks []Check     `yaml:"checks" json:"checks,omitempty"`

	// Reserved for project 3: parsed, refused by ReservedFeature.
	Hash          string         `yaml:"hash" json:"hash,omitempty"`
	Length        int            `yaml:"length" json:"length,omitempty"`
	RevokeOnLeave *bool          `yaml:"revoke_on_leave" json:"revoke_on_leave,omitempty"`
	OnRestore     string         `yaml:"on_restore" json:"on_restore,omitempty"`
	Pool          string         `yaml:"pool" json:"pool,omitempty"`
	Username      map[string]any `yaml:"username" json:"username,omitempty"`
	Mount         *OptionMount   `yaml:"mount" json:"mount,omitempty"`
}

// SettingTarget is a path option's mount: the compose service and the
// container directory.
type SettingTarget struct {
	Service string `yaml:"service" json:"service"`
	Mount   string `yaml:"mount" json:"mount"`
}

// EnumOption is one enum / multi_enum choice; the list order is its rank.
type EnumOption struct {
	Value string `yaml:"value" json:"value"`
	Label string `yaml:"label" json:"label"`
}

// ItemSpec is a list's item type.
type ItemSpec struct {
	Type    string       `yaml:"type" json:"type"`
	Pattern string       `yaml:"pattern" json:"pattern,omitempty"`
	Format  string       `yaml:"format" json:"format,omitempty"`
	MinLen  *int         `yaml:"min_len" json:"min_len,omitempty"`
	MaxLen  *int         `yaml:"max_len" json:"max_len,omitempty"`
	Min     any          `yaml:"min" json:"min,omitempty"`
	Max     any          `yaml:"max" json:"max,omitempty"`
	Choices []EnumOption `yaml:"options" json:"options,omitempty"`
}

// Column is one typed table column.
type Column struct {
	Name     string       `yaml:"name" json:"name"`
	Label    string       `yaml:"label" json:"label"`
	Type     string       `yaml:"type" json:"type"`
	Pattern  string       `yaml:"pattern" json:"pattern,omitempty"`
	Format   string       `yaml:"format" json:"format,omitempty"`
	MinLen   *int         `yaml:"min_len" json:"min_len,omitempty"`
	MaxLen   *int         `yaml:"max_len" json:"max_len,omitempty"`
	Min      any          `yaml:"min" json:"min,omitempty"`
	Max      any          `yaml:"max" json:"max,omitempty"`
	Required bool         `yaml:"required" json:"required,omitempty"`
	Choices  []EnumOption `yaml:"options" json:"options,omitempty"`
}

// Owner is a path option's writes_as: the identity the app writes as.
type Owner struct {
	UID OwnerRef `yaml:"uid" json:"uid"`
	GID OwnerRef `yaml:"gid" json:"gid"`
}

// OwnerRef is a number or the key of an instance int / string option.
type OwnerRef struct {
	Num *int
	Key string
}

// UnmarshalYAML reads a number or an option key.
func (r *OwnerRef) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: writes_as: want a number or an option key", n.Line)
	}
	if n.Tag == "!!int" {
		v, err := strconv.Atoi(n.Value)
		if err != nil {
			return fmt.Errorf("line %d: writes_as: %v", n.Line, err)
		}
		r.Num = &v
		return nil
	}
	if n.Tag != "!!str" {
		return fmt.Errorf("line %d: writes_as: want a number or an option key, not %s", n.Line, n.Value)
	}
	r.Key = n.Value
	return nil
}

// MarshalJSON writes the number or the key.
func (r OwnerRef) MarshalJSON() ([]byte, error) {
	if r.Num != nil {
		return json.Marshal(*r.Num)
	}
	return json.Marshal(r.Key)
}

// GenerateSpec lets the Hub generate a secret's value (§13.2).
type GenerateSpec struct {
	Length  int    `yaml:"length" json:"length"`
	Charset string `yaml:"charset" json:"charset"`
}

// Generated-secret charsets (§13.2).
const (
	CharsetHex            = "hex"
	CharsetAlphanumeric   = "alphanumeric"
	CharsetASCIIPrintable = "ascii_printable"
)

// GenerateCharsets are the accepted generate.charset values.
var GenerateCharsets = map[string]bool{CharsetHex: true, CharsetAlphanumeric: true, CharsetASCIIPrintable: true}

// OptionMount is reserved (project 3): where a person secret is mounted.
type OptionMount struct {
	Service string `yaml:"service" json:"service"`
	Path    string `yaml:"path" json:"path"`
}

// Deliveries is an option's delivery list. The scalar form (file | hook)
// is project 3's person_secret delivery: parsed into Bare, refused by
// ReservedFeature.
type Deliveries []Delivery

// UnmarshalYAML reads a sequence of deliveries, or the bare scalar form.
func (d *Deliveries) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		if n.Value != "file" && n.Value != "hook" {
			return fmt.Errorf("line %d: delivery: want a list of deliveries", n.Line)
		}
		*d = Deliveries{{Bare: n.Value}}
		return nil
	}
	var l []Delivery
	if err := strictDecode(n, &l); err != nil {
		return err
	}
	*d = l
	return nil
}

// Delivery is one way a value reaches the app (§13.6): exactly one of
// Env, Claim, Header, File, Hook.
type Delivery struct {
	Env    string          `yaml:"env" json:"env,omitempty"`
	Claim  *ClaimDelivery  `yaml:"claim" json:"claim,omitempty"`
	Header *HeaderDelivery `yaml:"header" json:"header,omitempty"`
	File   *FileDelivery   `yaml:"file" json:"file,omitempty"`
	Hook   string          `yaml:"hook" json:"hook,omitempty"`
	Render *Render         `yaml:"render" json:"render,omitempty"` // for env and hook
	Bare   string          `yaml:"-" json:"-"`                     // scalar form (project 3 person_secret only)
}

// ClaimDelivery is a token claim on one Keycloak client of the instance.
type ClaimDelivery struct {
	Client   string  `yaml:"client" json:"client"`
	Name     string  `yaml:"name" json:"name"`
	JSONType string  `yaml:"json_type" json:"json_type,omitempty"`
	Render   *Render `yaml:"render" json:"render,omitempty"`
}

// HeaderDelivery is a per-person X-Forwarded-Attr-* header (group-gate).
type HeaderDelivery struct {
	Name   string  `yaml:"name" json:"name"`
	Render *Render `yaml:"render" json:"render,omitempty"`
}

// FileDelivery writes the value into a declared data file. Field "" = the
// option key.
type FileDelivery struct {
	Name   string  `yaml:"name" json:"name"`
	Field  string  `yaml:"field" json:"field,omitempty"`
	Render *Render `yaml:"render" json:"render,omitempty"`
}

// Render is how a delivery renders the canonical value (§13.5).
type Render struct {
	Unit      string  `yaml:"unit" json:"unit,omitempty"`
	Integer   bool    `yaml:"integer" json:"integer,omitempty"`
	Unlimited *string `yaml:"unlimited" json:"unlimited,omitempty"`
	True      *string `yaml:"true" json:"true,omitempty"`
	False     *string `yaml:"false" json:"false,omitempty"`
	Join      *string `yaml:"join" json:"join,omitempty"`
	Format    string  `yaml:"format" json:"format,omitempty"` // json | yaml | csv
}

// Render formats.
const (
	RenderJSON = "json"
	RenderYAML = "yaml"
	RenderCSV  = "csv"
)

// DataFile is a declared data file (§13.7).
type DataFile struct {
	Name               string `yaml:"name" json:"name"`
	Service            string `yaml:"service" json:"service"`
	Mount              string `yaml:"mount" json:"mount"`
	OnMembershipChange string `yaml:"on_membership_change" json:"on_membership_change,omitempty"`
}

// UnmarshalYAML decodes strictly (unknown keys are refused).
func (f *DataFile) UnmarshalYAML(n *yaml.Node) error {
	type plain DataFile
	return strictDecode(n, (*plain)(f))
}

// on_membership_change values.
const (
	MembershipRestart = "restart"
	MembershipReload  = "reload"
	MembershipHook    = "hook"
	MembershipNone    = "none"
)

// Hook is a declared hook (§13.8): argv run with Docker exec, the desired
// state on stdin.
type Hook struct {
	Name    string   `yaml:"name" json:"name"`
	Service string   `yaml:"service" json:"service"`
	User    string   `yaml:"user" json:"user,omitempty"`
	Command []string `yaml:"command" json:"command"`
	When    []string `yaml:"when" json:"when"`
	Timeout Duration `yaml:"timeout" json:"timeout,omitempty"` // 0 = HookDefaultTimeout
}

// UnmarshalYAML decodes strictly (unknown keys are refused).
func (h *Hook) UnmarshalYAML(n *yaml.Node) error {
	type plain Hook
	return strictDecode(n, (*plain)(h))
}

// Hook timeouts.
const (
	HookDefaultTimeout = 30 * time.Second
	HookMaxTimeout     = 10 * time.Minute
)

// EffectiveTimeout is the hook's timeout, or HookDefaultTimeout.
func (h *Hook) EffectiveTimeout() time.Duration {
	if h.Timeout == 0 {
		return HookDefaultTimeout
	}
	return time.Duration(h.Timeout)
}

// Reload is the template's reload action: a signal to a service, or a hook.
type Reload struct {
	Service string `yaml:"service" json:"service,omitempty"`
	Signal  string `yaml:"signal" json:"signal,omitempty"`
	Hook    string `yaml:"hook" json:"hook,omitempty"`
}

// UnmarshalYAML decodes strictly (unknown keys are refused).
func (r *Reload) UnmarshalYAML(n *yaml.Node) error {
	type plain Reload
	return strictDecode(n, (*plain)(r))
}

// ReloadSignals are the signals a reload may send.
var ReloadSignals = map[string]bool{"HUP": true, "USR1": true, "USR2": true}

// Duration is a time.Duration written as "60s".
type Duration time.Duration

// UnmarshalYAML parses a Go duration string.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: duration %q: %v", n.Line, n.Value, err)
	}
	*d = Duration(v)
	return nil
}

// MarshalJSON writes the duration string.
func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

// Types (§13.2).
const (
	TypeString       = "string"
	TypeInt          = "int"
	TypeSize         = "size"
	TypeDuration     = "duration"
	TypeBool         = "bool"
	TypeEnum         = "enum"
	TypeMultiEnum    = "multi_enum"
	TypeList         = "list"
	TypeTable        = "table"
	TypePath         = "path"
	TypeSecret       = "secret"
	TypeGroup        = "group"
	TypeGroups       = "groups"
	TypeUser         = "user"
	TypeUsers        = "users"
	TypeFolder       = "folder"        // reserved: shared folders are path values (§13.15)
	TypePersonSecret = "person_secret" // reserved: project 3
	TypePersonID     = "person_id"     // reserved: project 3
)

// BuiltinTypes are the types this Hub implements (not the reserved ones).
// Discover uses them when it is given no registry (settings.Registry.Known).
var BuiltinTypes = map[string]bool{
	TypeString: true, TypeInt: true, TypeSize: true, TypeDuration: true, TypeBool: true,
	TypeEnum: true, TypeMultiEnum: true, TypeList: true, TypeTable: true, TypePath: true,
	TypeSecret: true, TypeGroup: true, TypeGroups: true, TypeUser: true, TypeUsers: true,
}

// oldTypes are the contract v2 types, refused with their replacement.
var oldTypes = map[string]string{
	"text":    "use string",
	"boolean": "use bool",
	"select":  "use enum (options: [{value, label}])",
	"paths":   "use path (one option per directory)",
}

// Scopes (§13.3).
const (
	ScopeInstance      = "instance"
	ScopePerson        = "person"
	ScopeGroup         = "group"
	ScopePersonEntered = "person_entered"
)

// PersonEnteredTypes are the types a person_entered option may have.
var PersonEnteredTypes = map[string]bool{TypeString: true, TypeInt: true, TypeBool: true, TypeEnum: true}

// PersonEnteredMaxLen bounds a person_entered string's max_len.
const PersonEnteredMaxLen = 256

// Applies values (§13.9).
const (
	AppliesLive            = "live"
	AppliesReload          = "reload"
	AppliesNextSignIn      = "next_sign_in"
	AppliesNextRequest     = "next_request"
	AppliesRestart         = "restart"
	AppliesAccountCreation = "account_creation"
)

var appliesValues = map[string]bool{AppliesLive: true, AppliesReload: true, AppliesNextSignIn: true,
	AppliesNextRequest: true, AppliesRestart: true, AppliesAccountCreation: true}

// Resolution rules (§13.4).
const (
	ResolveMax          = "max"
	ResolveMin          = "min"
	ResolvePriority     = "priority"
	ResolveUnion        = "union"
	ResolveIntersection = "intersection"
	ResolveAny          = "any"
	ResolveAll          = "all"
)

// resolveTypes: the types each rule fits (nil = every type).
var resolveTypes = map[string]map[string]bool{
	ResolveMax:          {TypeInt: true, TypeSize: true, TypeDuration: true, TypeEnum: true},
	ResolveMin:          {TypeInt: true, TypeSize: true, TypeDuration: true, TypeEnum: true},
	ResolvePriority:     nil,
	ResolveUnion:        {TypeList: true, TypeMultiEnum: true, TypeGroups: true},
	ResolveIntersection: {TypeList: true, TypeMultiEnum: true, TypeGroups: true},
	ResolveAny:          {TypeBool: true},
	ResolveAll:          {TypeBool: true},
}

// Hook triggers (§13.8).
const (
	HookStart            = "start"
	HookSettingsChange   = "settings_change"
	HookMembershipChange = "membership_change"
)

// HookTriggers are the accepted hooks[].when values.
var HookTriggers = map[string]bool{HookStart: true, HookSettingsChange: true, HookMembershipChange: true}

// Claim JSON types.
var claimJSONTypes = map[string]bool{"int": true, "string": true, "bool": true, "json": true}

var (
	// OptionKeyRe constrains option keys (not env names).
	OptionKeyRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)
	sectionRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ]{0,31}$`)
	// fileHookNameRe constrains files[].name and hooks[].name.
	fileHookNameRe = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	fieldRe        = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)
	claimNameRe    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	// HeaderDeliveryRe is the header delivery name form (§13.6): the
	// policy package's (group-gate's suffix form after the prefix).
	HeaderDeliveryRe = policy.HeaderNameRe
)

// Group placeholders: the only group_values keys (stored as written).
const (
	PlaceholderAccessGroup = "{{ACCESS_GROUP}}"
	PlaceholderAdminGroup  = "{{ADMIN_GROUP}}"
)

// reservedClaims are claims a delivery may not name: standard OIDC / JWT
// claims, Keycloak's, Portcullis' own; attr_* and portcullis_* are
// prefixes (shared field attributes, core).
var reservedClaims = map[string]bool{
	"sub": true, "iss": true, "aud": true, "exp": true, "nbf": true, "iat": true, "jti": true,
	"azp": true, "sid": true, "nonce": true, "auth_time": true, "at_hash": true, "c_hash": true,
	"typ": true, "scope": true, "acr": true, "amr": true, "email": true, "email_verified": true,
	"name": true, "given_name": true, "family_name": true, "middle_name": true, "nickname": true,
	"preferred_username": true, "profile": true, "picture": true, "website": true, "gender": true,
	"birthdate": true, "zoneinfo": true, "locale": true, "phone_number": true,
	"phone_number_verified": true, "address": true, "updated_at": true, "groups": true,
	"realm_access": true, "resource_access": true, "allowed-origins": true, "session_state": true,
	"client_id": true, "cnf": true, "roles": true,
}

// Reserved features (ReservedFeature).
const (
	FeatureSharedFolders = "shared folders (project 2)"
	FeatureFileSharing   = "file sharing (project 3)"
)

// EffectiveScope returns o.Scope, or ScopeInstance when unset.
func (o *Option) EffectiveScope() string {
	if o.Scope == "" {
		return ScopeInstance
	}
	return o.Scope
}

// IndexSuffix marks an indexed env delivery (NAME_{n}, §13.6).
const IndexSuffix = "_{n}"

// EnvName is the env variable an instance option delivers to ("" =
// none): its first env delivery, or UPPER(key) for an option without
// deliveries (a path is mounted, never in the env). An indexed delivery
// returns its NAME_{n} form (EnvNames expands it).
func (o *Option) EnvName() string {
	if o.EffectiveScope() != ScopeInstance {
		return ""
	}
	if len(o.Delivery) == 0 {
		if o.Type == TypePath {
			return ""
		}
		return strings.ToUpper(o.Key)
	}
	for _, d := range o.Delivery {
		if d.Env != "" {
			return d.Env
		}
	}
	return ""
}

// EnvNames are every env variable o's env deliveries write (any scope),
// indexed ones expanded to NAME_1 … NAME_<max_items>.
func (o *Option) EnvNames() []string {
	var out []string
	add := func(n string) {
		if p, ok := strings.CutSuffix(n, IndexSuffix); ok {
			if o.MaxItems != nil {
				for i := 1; i <= *o.MaxItems && i <= maxIndexed; i++ {
					out = append(out, p+"_"+strconv.Itoa(i))
				}
			}
			return
		}
		out = append(out, n)
	}
	if o.EffectiveScope() == ScopeInstance && len(o.Delivery) == 0 {
		if n := o.EnvName(); n != "" {
			add(n)
		}
		return out
	}
	for _, d := range o.Delivery {
		if d.Env != "" {
			add(d.Env)
		}
	}
	return out
}

// maxIndexed caps an indexed env delivery's max_items.
const maxIndexed = 64

// ReservedFeature names the project-2/3 feature o uses ("" = none).
func ReservedFeature(o *Option) string {
	_, f := reservedUse(o)
	return f
}

// reservedUse is what of o is reserved, and for which feature.
func reservedUse(o *Option) (what, feature string) {
	switch o.Type {
	case TypeFolder:
		return "type " + o.Type, FeatureSharedFolders
	case TypePersonSecret, TypePersonID:
		return "type " + o.Type, FeatureFileSharing
	}
	if f := o.Folder; f != nil && f.RunsAs != nil {
		switch {
		case f.RunsAs.UIDFrom != "":
			return "folder.runs_as.uid_from", FeatureFileSharing
		case f.RunsAs.GIDFrom != "":
			return "folder.runs_as.gid_from", FeatureFileSharing
		}
	}
	switch {
	case o.Hash != "":
		return "hash", FeatureFileSharing
	case o.Length != 0:
		return "length", FeatureFileSharing
	case o.RevokeOnLeave != nil:
		return "revoke_on_leave", FeatureFileSharing
	case o.OnRestore != "":
		return "on_restore", FeatureFileSharing
	case o.Pool != "":
		return "pool", FeatureFileSharing
	case o.Username != nil:
		return "username", FeatureFileSharing
	case o.Mount != nil:
		return "mount", FeatureFileSharing
	}
	for _, d := range o.Delivery {
		if d.Bare != "" {
			return "delivery: " + d.Bare, FeatureFileSharing
		}
	}
	return "", ""
}

// UnmarshalYAML refuses the contract v2 list form and unknown keys
// anywhere in the block (a misspelt privileged must not pass silently).
func (s *SettingsSpec) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.SequenceNode {
		return fmt.Errorf("line %d: settings: a list of settings is template contract v2; contract v3 declares settings: {sections, options} (integration contracts §13)", n.Line)
	}
	type plain SettingsSpec
	return strictDecode(n, (*plain)(s))
}

// strictDecode decodes n into v refusing unknown keys (yaml.v3's
// Node.Decode has no KnownFields).
func strictDecode(n *yaml.Node, v any) error {
	b, err := yaml.Marshal(n)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("near line %d: %v", n.Line, err)
	}
	return nil
}

// ── validation ───────────────────────────────────────────

// Kinds is the Hub's settings type registry (settings.Registry): which
// types it implements, and each option's type-specific checks (bounds,
// patterns, choices, columns, renders, the default and group_values as
// canonical values).
type Kinds interface {
	Known(typ string) bool
	CheckOption(o *Option) error
}

// builtinKinds knows BuiltinTypes and checks nothing type-specific.
type builtinKinds struct{}

// nilKinds is what a nil Kinds means — in a test binary only. The
// package's tests set it to the real settings registry (export_test.go),
// so every fixture also passes the type-specific checks.
var nilKinds Kinds = builtinKinds{}

// inTest reports whether this is a test binary (a variable so the
// production refusal can be tested).
var inTest = testing.Testing

// ErrNoKinds: a nil Kinds outside tests (fail closed: the type-specific
// checks would be skipped).
var ErrNoKinds = errors.New("settings: no type registry (templates.Kinds is nil)")

func (builtinKinds) Known(typ string) bool     { return BuiltinTypes[typ] }
func (builtinKinds) CheckOption(*Option) error { return nil }

// ValidateSettingsSpec checks t's settings, files, hooks and reload
// against its manifest, compose file and routes (contract §13). kinds is
// the Hub's type registry (settings.Registry); nil is refused outside
// test binaries (ErrNoKinds); a reserved type or field is refused with "<what>
// needs <feature>", an unknown type as such.
func ValidateSettingsSpec(t *Template, compose []byte, routes *Routes, kinds Kinds) error {
	if kinds == nil {
		if !inTest() {
			return ErrNoKinds
		}
		kinds = nilKinds
	}
	m := &t.Manifest
	v := &specCheck{m: m, compose: compose, routes: routes, kinds: kinds}
	v.services = map[string]bool{}
	for _, s := range Services(compose) {
		v.services[s] = true
	}
	var err error
	if v.env, err = composeEnvironment(compose); err != nil {
		return err
	}
	var doc interface{}
	if err := yaml.Unmarshal(compose, &doc); err != nil {
		return fmt.Errorf("compose.yml: %v", err)
	}
	scalarValues(doc, &v.scalars)
	if err := v.files(); err != nil {
		return err
	}
	if err := v.hooks(); err != nil {
		return err
	}
	if err := v.reload(); err != nil {
		return err
	}
	v.users = composeUsers(compose)
	if err := v.composeUserGIDs(); err != nil {
		return err
	}
	if m.Settings == nil {
		return nil
	}
	if err := v.sections(); err != nil {
		return err
	}
	v.opts = map[string]*Option{}
	for i := range m.Settings.Options {
		o := &m.Settings.Options[i]
		if !OptionKeyRe.MatchString(o.Key) {
			return fmt.Errorf("setting %s: key must match %s (an identifier, not an env name)", o.Key, OptionKeyRe)
		}
		if v.opts[o.Key] != nil {
			return fmt.Errorf("setting %s: declared twice", o.Key)
		}
		if err := v.typeOf(o); err != nil {
			return fmt.Errorf("setting %s: %w", o.Key, err)
		}
		v.opts[o.Key] = o
	}
	if err := v.envNames(); err != nil {
		return err
	}
	v.claims, v.headers, v.fields = map[string]string{}, map[string]string{}, map[string]string{}
	for i := range m.Settings.Options {
		o := &m.Settings.Options[i]
		if err := v.option(o); err != nil {
			return fmt.Errorf("setting %s: %w", o.Key, err)
		}
		if err := v.kinds.CheckOption(o); err != nil {
			return fmt.Errorf("setting %s: %w", o.Key, err)
		}
	}
	return nil
}

type specCheck struct {
	m        *Manifest
	compose  []byte
	routes   *Routes
	kinds    Kinds
	services map[string]bool
	scalars  []string                      // compose.yml's decoded scalar values
	env      map[string]map[string]*string // service → environment
	users    map[string]string             // service → compose user: ("" = unset)
	files_   map[string]*DataFile
	hooks_   map[string]*Hook
	opts     map[string]*Option
	claims   map[string]string // client\x00claim → option
	headers  map[string]string // folded header → option
	fields   map[string]string // file\x00section\x00field → option
}

func (v *specCheck) sections() error {
	seen := map[string]bool{}
	for _, s := range v.m.Settings.Sections {
		if !sectionRe.MatchString(s) {
			return fmt.Errorf("settings.sections: %q must match %s", s, sectionRe)
		}
		if seen[s] {
			return fmt.Errorf("settings.sections: %q listed twice", s)
		}
		seen[s] = true
	}
	return nil
}

func validMount(p string) bool {
	return path.IsAbs(p) && path.Clean(p) == p && p != "/" && !HasControlChars(p) && !strings.Contains(p, ":")
}

// nested reports whether container paths a and b are the same or one is
// inside the other.
func nested(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

func (v *specCheck) files() error {
	v.files_ = map[string]*DataFile{}
	for i := range v.m.Files {
		f := &v.m.Files[i]
		w := fmt.Sprintf("files[%s]", f.Name)
		if !fileHookNameRe.MatchString(f.Name) {
			return fmt.Errorf("%s: name must match %s", w, fileHookNameRe)
		}
		if v.files_[f.Name] != nil {
			return fmt.Errorf("%s: declared twice", w)
		}
		if !v.services[f.Service] {
			return fmt.Errorf("%s: service %s is not in compose.yml", w, f.Service)
		}
		if !validMount(f.Mount) {
			return fmt.Errorf("%s: mount %q must be an absolute, clean container directory (no ':')", w, f.Mount)
		}
		switch f.OnMembershipChange {
		case "", MembershipNone, MembershipRestart:
		case MembershipReload:
			if v.m.Reload == nil {
				return fmt.Errorf("%s: on_membership_change: reload needs the template's reload action", w)
			}
		case MembershipHook:
			if !v.hasTrigger(HookMembershipChange) {
				return fmt.Errorf("%s: on_membership_change: hook needs a hook with when: [membership_change]", w)
			}
		default:
			return fmt.Errorf("%s: on_membership_change %q must be restart, reload, hook or none", w, f.OnMembershipChange)
		}
		for _, g := range v.m.Files[:i] {
			if g.Service == f.Service && nested(g.Mount, f.Mount) {
				return fmt.Errorf("%s: mount %s collides with files[%s] (%s) on service %s", w, f.Mount, g.Name, g.Mount, f.Service)
			}
		}
		if v.m.Settings != nil {
			for _, o := range v.m.Settings.Options {
				if o.Type == TypePath && o.Target != nil && o.Target.Service == f.Service && nested(o.Target.Mount, f.Mount) {
					return fmt.Errorf("%s: mount %s collides with setting %s's target %s on service %s", w, f.Mount, o.Key, o.Target.Mount, f.Service)
				}
			}
		}
		v.files_[f.Name] = f
	}
	return nil
}

func (v *specCheck) hasTrigger(tr string) bool {
	for _, h := range v.m.Hooks {
		for _, w := range h.When {
			if w == tr {
				return true
			}
		}
	}
	return false
}

func (v *specCheck) hooks() error {
	v.hooks_ = map[string]*Hook{}
	for i := range v.m.Hooks {
		h := &v.m.Hooks[i]
		w := fmt.Sprintf("hooks[%s]", h.Name)
		if !fileHookNameRe.MatchString(h.Name) {
			return fmt.Errorf("%s: name must match %s", w, fileHookNameRe)
		}
		if v.hooks_[h.Name] != nil {
			return fmt.Errorf("%s: declared twice", w)
		}
		if !v.services[h.Service] {
			return fmt.Errorf("%s: service %s is not in compose.yml", w, h.Service)
		}
		if len(h.Command) == 0 {
			return fmt.Errorf("%s: command must be a non-empty argv list (run directly, no sh -c)", w)
		}
		for _, a := range h.Command {
			if a == "" || HasControlChars(a) {
				return fmt.Errorf("%s: command arguments must be non-empty, without control characters", w)
			}
		}
		if HasControlChars(h.User) {
			return fmt.Errorf("%s: user contains control characters", w)
		}
		if len(h.When) == 0 {
			return fmt.Errorf("%s: when must list at least one trigger (start, settings_change, membership_change)", w)
		}
		for _, tr := range h.When {
			if !HookTriggers[tr] {
				return fmt.Errorf("%s: when %q must be start, settings_change or membership_change", w, tr)
			}
		}
		if h.Timeout < 0 || time.Duration(h.Timeout) > HookMaxTimeout {
			return fmt.Errorf("%s: timeout %s must be between 0 (default %s) and %s", w, time.Duration(h.Timeout), HookDefaultTimeout, HookMaxTimeout)
		}
		v.hooks_[h.Name] = h
	}
	return nil
}

func (v *specCheck) reload() error {
	r := v.m.Reload
	if r == nil {
		return nil
	}
	switch {
	case r.Hook != "" && (r.Service != "" || r.Signal != ""):
		return fmt.Errorf("reload: either {service, signal} or {hook}, not both")
	case r.Hook != "":
		if v.hooks_[r.Hook] == nil {
			return fmt.Errorf("reload: hook %s is not declared in hooks", r.Hook)
		}
	default:
		if !v.services[r.Service] {
			return fmt.Errorf("reload: service %q is not in compose.yml", r.Service)
		}
		if !ReloadSignals[r.Signal] {
			return fmt.Errorf("reload: signal %q must be HUP, USR1 or USR2", r.Signal)
		}
	}
	return nil
}

// composeEnvironment reads every service's environment (map or list
// form): name → value (nil = no value, passed through).
func composeEnvironment(compose []byte) (map[string]map[string]*string, error) {
	var doc struct {
		Services map[string]struct {
			Environment yaml.Node `yaml:"environment"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(compose, &doc); err != nil {
		return nil, fmt.Errorf("compose.yml: %v", err)
	}
	out := map[string]map[string]*string{}
	for svc, s := range doc.Services {
		env := map[string]*string{}
		n := &s.Environment
		switch n.Kind {
		case 0:
		case yaml.MappingNode:
			for i := 0; i+1 < len(n.Content); i += 2 {
				k, val := n.Content[i].Value, n.Content[i+1]
				if val.Tag == "!!null" {
					env[k] = nil
				} else {
					s := val.Value
					env[k] = &s
				}
			}
		case yaml.SequenceNode:
			for _, e := range n.Content {
				k, val, ok := strings.Cut(e.Value, "=")
				if ok {
					env[k] = &val
				} else {
					env[k] = nil
				}
			}
		default:
			return nil, fmt.Errorf("compose.yml: service %s: environment must be a mapping or a list", svc)
		}
		out[svc] = env
	}
	return out, nil
}

// referenced reports whether compose interpolates ${name}.
func referenced(s, name string) bool {
	re := regexp.MustCompile(`\$\{` + regexp.QuoteMeta(name) + `(\}|:?[-?+])`)
	return len(interpolations(s, re)) > 0
}

// interpolations are re's matches in s that compose interpolates: a match
// (starting at the "$" of "${") preceded by an odd run of "$" is escaped
// ("$$" is a literal "$"), so "$${X}" is literal and "$$${X}" is "$" +
// ${X}. Each result is the match's submatches.
func interpolations(s string, re *regexp.Regexp) [][]string {
	var out [][]string
	for _, idx := range re.FindAllStringSubmatchIndex(s, -1) {
		run := 0
		for i := idx[0] - 1; i >= 0 && s[i] == '$'; i-- {
			run++
		}
		if run%2 == 1 {
			continue
		}
		m := make([]string, len(idx)/2)
		for j := range m {
			if idx[2*j] >= 0 {
				m[j] = s[idx[2*j]:idx[2*j+1]]
			}
		}
		out = append(out, m)
	}
	return out
}

// interpolatedAnywhere reports whether any decoded scalar value of the
// compose file interpolates ${name} (comments and keys don't count).
func (v *specCheck) interpolatedAnywhere(name string) bool {
	for _, s := range v.scalars {
		if referenced(s, name) {
			return true
		}
	}
	return false
}

// scalarValues collects every scalar value (not mapping keys) of a
// decoded YAML document.
func scalarValues(x interface{}, out *[]string) {
	switch t := x.(type) {
	case string:
		*out = append(*out, t)
	case map[string]interface{}:
		for _, val := range t {
			scalarValues(val, out)
		}
	case map[interface{}]interface{}:
		for _, val := range t {
			scalarValues(val, out)
		}
	case []interface{}:
		for _, e := range t {
			scalarValues(e, out)
		}
	}
}

func (v *specCheck) envNames() error {
	owner := map[string]string{} // env name → what declared it
	for _, e := range v.m.Env {
		owner[e.Key] = "env[] " + e.Key
	}
	for _, p := range v.m.Ports {
		owner[p.Key] = "ports[] " + p.Key
		owner[p.Key+"_BIND"] = "ports[] " + p.Key + " (bind)"
	}
	for _, c := range v.m.Clients {
		if c.SecretEnv != "" {
			owner[c.SecretEnv] = "keycloak client " + c.ClientID + " secret_env"
		}
	}
	for i := range v.m.Settings.Options {
		o := &v.m.Settings.Options[i]
		var names []string
		for _, d := range o.Delivery {
			if d.Env == "" {
				continue
			}
			if p, ok := strings.CutSuffix(d.Env, IndexSuffix); ok {
				if err := v.indexed(o, p); err != nil {
					return fmt.Errorf("setting %s: %w", o.Key, err)
				}
			} else if strings.Contains(d.Env, "{") {
				return fmt.Errorf("setting %s: env name %q: the only indexed form is NAME_{n}", o.Key, d.Env)
			}
		}
		names = o.EnvNames()
		for _, n := range names {
			if !EnvKeyRe.MatchString(n) {
				return fmt.Errorf("setting %s: env name %q must match %s", o.Key, n, EnvKeyRe)
			}
			if ReservedVar(n) || strings.HasPrefix(n, "PORTCULLIS_") {
				return fmt.Errorf("setting %s: env name %s is reserved (PORTCULLIS_*: core and the Hub set them)", o.Key, n)
			}
			if w, ok := owner[n]; ok {
				return fmt.Errorf("setting %s: env name %s is already used by %s", o.Key, n, w)
			}
			owner[n] = "setting " + o.Key
			for svc, env := range v.env {
				if val, ok := env[n]; ok && val != nil && !referenced(*val, n) {
					return fmt.Errorf("setting %s: compose.yml hard-codes %s in service %s's environment (use ${%s})", o.Key, n, svc, n)
				}
			}
			if !v.interpolatedAnywhere(n) {
				return fmt.Errorf("setting %s: env name %s is not referenced as ${%s} in compose.yml", o.Key, n, n)
			}
		}
	}
	return nil
}

// indexed checks an indexed env delivery prefix_{n}.
func (v *specCheck) indexed(o *Option, prefix string) error {
	if o.Type != TypeList || o.EffectiveScope() != ScopeInstance {
		return fmt.Errorf("indexed env %s%s is for instance list options only", prefix, IndexSuffix)
	}
	if o.MaxItems == nil || *o.MaxItems < 1 || *o.MaxItems > maxIndexed {
		return fmt.Errorf("indexed env %s%s needs max_items (1-%d)", prefix, IndexSuffix, maxIndexed)
	}
	re := regexp.MustCompile(`\$\{` + regexp.QuoteMeta(prefix) + `_([0-9]+)(\}|:?[-?+])`)
	for _, sc := range v.scalars {
		for _, mm := range interpolations(sc, re) {
			if n, _ := strconv.Atoi(mm[1]); n < 1 || n > *o.MaxItems {
				return fmt.Errorf("compose.yml references %s_%s, beyond max_items %d", prefix, mm[1], *o.MaxItems)
			}
		}
	}
	return nil
}

// EffectiveApplies is o's applies, or its §13.9 default (claims
// next_sign_in, headers next_request, otherwise restart).
func (o *Option) EffectiveApplies() string { return appliesOf(o) }

// appliesOf is o's effective applies (§13.9 defaults).
func appliesOf(o *Option) string {
	if o.Applies != "" {
		return o.Applies
	}
	for _, d := range o.Delivery {
		switch {
		case d.Claim != nil:
			return AppliesNextSignIn
		case d.Header != nil:
			return AppliesNextRequest
		}
	}
	return AppliesRestart
}

// identityless reports whether the template's routes can run without
// Portcullis identity (method public / custom, or the app's own login
// without Portcullis).
func identityless(m *Manifest) bool {
	a := &m.Auth
	return a.Method == "public" || a.Method == "custom" || (a.NativeLogin != nil && a.NativeLogin.AllowWithoutGateway)
}

// typeOf refuses contract v2, reserved and unknown types (and reserved
// fields) before anything else looks at o.
func (v *specCheck) typeOf(o *Option) error {
	if repl, ok := oldTypes[o.Type]; ok {
		return fmt.Errorf("type %s is template contract v2: %s", o.Type, repl)
	}
	if what, f := reservedUse(o); f != "" {
		return fmt.Errorf("%s needs %s, which this Hub doesn't implement", what, f)
	}
	if o.Type == "" || !v.kinds.Known(o.Type) {
		return fmt.Errorf("unknown type %q", o.Type)
	}
	return nil
}

func (v *specCheck) option(o *Option) error {
	if o.Label == "" || utf8.RuneCountInString(o.Label) > 64 || HasControlChars(o.Label) {
		return fmt.Errorf("label must be a single non-empty line of at most 64 characters")
	}
	if len(o.Description) > 500 || strings.ContainsFunc(o.Description, func(r rune) bool { return r != '\n' && IsControlRune(r) }) {
		return fmt.Errorf("description must be at most 500 characters, without control characters")
	}
	if o.Section != "" && !contains(v.m.Settings.Sections, o.Section) {
		return fmt.Errorf("section %q is not listed in settings.sections", o.Section)
	}
	scope := o.EffectiveScope()
	switch scope {
	case ScopeInstance, ScopePerson, ScopeGroup, ScopePersonEntered:
	default:
		return fmt.Errorf("scope %q must be instance, person, group or person_entered", o.Scope)
	}
	if err := v.folderOption(o); err != nil {
		return err
	}
	if err := v.checks(o); err != nil {
		return err
	}
	if o.Applies != "" && !appliesValues[o.Applies] {
		return fmt.Errorf("applies %q must be live, reload, next_request, next_sign_in, restart or account_creation", o.Applies)
	}
	if scope == ScopePersonEntered {
		if err := v.personEntered(o); err != nil {
			return err
		}
	}
	switch {
	case o.Privileged && scope != ScopePerson:
		return fmt.Errorf("privileged needs scope: person")
	case o.SelfVisible != nil && scope != ScopePerson && !(scope == ScopePersonEntered && *o.SelfVisible):
		return fmt.Errorf("self_visible needs scope: person")
	case o.Resolve != "" && scope != ScopePerson, len(o.ResolveChoices) > 0 && scope != ScopePerson:
		return fmt.Errorf("resolve and resolve_choices need scope: person")
	case o.GroupValues != nil && scope != ScopePerson:
		return fmt.Errorf("group_values need scope: person")
	case o.AdminOverride && scope != ScopePersonEntered:
		return fmt.Errorf("admin_override needs scope: person_entered")
	case o.Type == TypeSecret && scope != ScopeInstance:
		return fmt.Errorf("a secret option needs scope instance (a secret is write-only, stored apart from the settings)")
	case scope == ScopePerson && o.Default == nil:
		return fmt.Errorf("scope person needs a default (the value for everyone else with access)")
	case o.Required && scope == ScopeGroup:
		return fmt.Errorf("required is not for scope group (its records are optional, and it has no default)")
	case o.Required && scope == ScopePerson && emptyDefault(o.Default):
		return fmt.Errorf("required on scope person needs a non-empty default (the value for everyone without a row)")
	case scope == ScopeGroup && o.Default != nil:
		return fmt.Errorf("scope group takes no default (the group records are the values)")
	case o.Unique && o.Type != TypeList && !(scope == ScopePersonEntered && (o.Type == TypeString || o.Type == TypeInt)):
		return fmt.Errorf("unique is for list options and person_entered string / int options")
	case o.Generate != nil && o.Type != TypeSecret:
		return fmt.Errorf("generate is for secret options")
	case o.WritesAs != nil && o.Type != TypePath:
		return fmt.Errorf("writes_as is for path options")
	case o.Type == TypePath && scope != ScopeInstance:
		return fmt.Errorf("a path option must have scope instance")
	}
	if o.Applies == AppliesReload && v.m.Reload == nil {
		return fmt.Errorf("applies: reload needs the template's reload action")
	}
	if err := v.resolve(o); err != nil {
		return err
	}
	if err := v.groupValues(o); err != nil {
		return err
	}
	if err := v.privileged(o); err != nil {
		return err
	}
	if err := v.requires(o); err != nil {
		return err
	}
	if err := v.pathAndSecret(o); err != nil {
		return err
	}
	if err := v.deliveries(o); err != nil {
		return err
	}
	if scope == ScopePerson && o.Resolve == "" {
		return fmt.Errorf("scope person needs resolve (how a person's rows combine: max, min, priority, union, intersection, any or all)")
	}
	return nil
}

// emptyDefault: a manifest default that holds no value (none, "", an
// empty list or map).
func emptyDefault(d any) bool {
	switch x := d.(type) {
	case nil:
		return true
	case string:
		return x == ""
	case []any:
		return len(x) == 0
	case map[string]any:
		return len(x) == 0
	}
	return false
}

func (v *specCheck) personEntered(o *Option) error {
	if !PersonEnteredTypes[o.Type] {
		if o.Type == TypeSecret {
			return fmt.Errorf("scope person_entered can't be a secret: a per-person credential is person_secret (project 3)")
		}
		return fmt.Errorf("scope person_entered is for string, int, bool or enum options, not %s", o.Type)
	}
	bad := func(field string) error { return fmt.Errorf("scope person_entered takes no %s", field) }
	switch {
	case o.Default != nil:
		return bad("default")
	case o.Required:
		return bad("required")
	case o.Resolve != "":
		return bad("resolve")
	case len(o.ResolveChoices) > 0:
		return bad("resolve_choices")
	case o.GroupValues != nil:
		return bad("group_values")
	case o.Privileged:
		return bad("privileged")
	case len(o.Requires) > 0:
		return bad("requires")
	case o.SelfVisible != nil && !*o.SelfVisible:
		return bad("self_visible: false (people always see their own value)")
	case o.Applies == AppliesAccountCreation:
		return bad("applies: account_creation")
	case o.Unique && o.Type != TypeString && o.Type != TypeInt:
		return fmt.Errorf("unique is for person_entered string / int options")
	}
	if o.Type == TypeString {
		if o.MaxLen == nil && o.Pattern == "" && o.Format == "" {
			return fmt.Errorf("a person_entered string needs max_len (at most %d), a pattern or a format", PersonEnteredMaxLen)
		}
		if o.MaxLen != nil && *o.MaxLen > PersonEnteredMaxLen {
			return fmt.Errorf("a person_entered string's max_len is at most %d", PersonEnteredMaxLen)
		}
	}
	if identityless(v.m) && v.m.Auth.AccessGroup == "" {
		return fmt.Errorf("scope person_entered on a template whose routes can run without Portcullis identity (method public / custom, or the app's own login only) needs auth.access_group (who may enter a value)")
	}
	applies := appliesOf(o)
	for _, d := range o.Delivery {
		switch {
		case d.Env != "":
			if d.Render == nil || (d.Render.Join == nil && d.Render.Format != RenderJSON) {
				return fmt.Errorf("a person_entered env delivery is the list of values: it needs render.join or render.format: json")
			}
			if applies != AppliesRestart {
				return fmt.Errorf("a person_entered env delivery needs applies: restart")
			}
		case d.File != nil:
			f := v.files_[d.File.Name]
			if f == nil {
				continue // refused in deliveries
			}
			want := map[string]string{MembershipRestart: AppliesRestart, MembershipReload: AppliesReload, MembershipHook: AppliesLive}[f.OnMembershipChange]
			if want == "" {
				return fmt.Errorf("file %s has no on_membership_change: person-entered values reach it only through the membership path", f.Name)
			}
			if applies != want {
				return fmt.Errorf("applies %s doesn't match file %s's on_membership_change %s (want applies: %s)", applies, f.Name, f.OnMembershipChange, want)
			}
		case d.Hook != "":
			h := v.hooks_[d.Hook]
			if h == nil {
				continue
			}
			if applies != AppliesLive {
				return fmt.Errorf("a person_entered hook delivery needs applies: live")
			}
			if !contains(h.When, HookMembershipChange) {
				return fmt.Errorf("hook %s needs membership_change in its when to deliver person-entered values", h.Name)
			}
		case d.Claim != nil:
			if applies != AppliesNextSignIn {
				return fmt.Errorf("a claim delivery applies at next_sign_in, not %s", applies)
			}
		case d.Header != nil:
			if applies != AppliesNextRequest {
				return fmt.Errorf("a header delivery applies at next_request, not %s", applies)
			}
		}
	}
	return nil
}

func (v *specCheck) resolve(o *Option) error {
	fits := func(r string) error {
		types, ok := resolveTypes[r]
		if !ok {
			return fmt.Errorf("resolve %s must be max, min, priority, union, intersection, any or all", r)
		}
		if types != nil && !types[o.Type] {
			return fmt.Errorf("resolve %s doesn't fit type %s", r, o.Type)
		}
		return nil
	}
	if o.Resolve != "" {
		if err := fits(o.Resolve); err != nil {
			return err
		}
	}
	for _, r := range o.ResolveChoices {
		if err := fits(r); err != nil {
			return fmt.Errorf("resolve_choices: %s: %w", r, err)
		}
	}
	return nil
}

func (v *specCheck) groupValues(o *Option) error {
	for k := range o.GroupValues {
		switch k {
		case PlaceholderAccessGroup:
			if v.m.Auth.AccessGroup == "" {
				return fmt.Errorf("group_values: %s needs auth.access_group", k)
			}
			// It would make the access group guarding (call 28): its rule
			// could then gain no member on a delegate-editable field.
			if o.Privileged {
				return fmt.Errorf("group_values: %s on a privileged option would give everyone with access a privileged value: use %s", k, PlaceholderAdminGroup)
			}
		case PlaceholderAdminGroup:
			if v.m.Auth.AdminGroup == "" {
				return fmt.Errorf("group_values: %s needs auth.admin_group", k)
			}
		default:
			return fmt.Errorf("group_values: %q: only the placeholders %s and %s (the admin picks other groups)", k, PlaceholderAccessGroup, PlaceholderAdminGroup)
		}
	}
	return nil
}

// privileged: an enum (lowest = first option) or bool (lowest = false)
// whose default is its lowest-ranked value.
func (v *specCheck) privileged(o *Option) error {
	if !o.Privileged {
		return nil
	}
	switch o.Type {
	case TypeEnum:
		if len(o.Choices) == 0 {
			return fmt.Errorf("an enum needs options")
		}
		if s, ok := o.Default.(string); !ok || s != o.Choices[0].Value {
			return fmt.Errorf("a privileged option's default must be its lowest-ranked value %q", o.Choices[0].Value)
		}
	case TypeBool:
		if b, ok := o.Default.(bool); !ok || b {
			return fmt.Errorf("a privileged option's default must be its lowest-ranked value false")
		}
	default:
		return fmt.Errorf("privileged is for enum and bool options (a role, an admin flag)")
	}
	return nil
}

func (v *specCheck) requires(o *Option) error {
	if len(o.Requires) > 0 && o.EffectiveScope() != ScopeInstance {
		return fmt.Errorf("requires is for instance options")
	}
	for _, k := range o.Requires {
		r := v.opts[k]
		switch {
		case k == o.Key:
			return fmt.Errorf("requires names itself")
		case r == nil:
			return fmt.Errorf("requires %s: no such option", k)
		case r.EffectiveScope() != ScopeInstance:
			return fmt.Errorf("requires %s: not an instance option", k)
		}
	}
	return nil
}

func (v *specCheck) pathAndSecret(o *Option) error {
	if o.Type == TypePath {
		if o.Target == nil {
			return fmt.Errorf("a path option needs a target {service, mount}")
		}
		if !v.services[o.Target.Service] {
			return fmt.Errorf("target service %q is not in compose.yml", o.Target.Service)
		}
		if !validMount(o.Target.Mount) {
			return fmt.Errorf("target mount %q must be an absolute, clean container path (no ':')", o.Target.Mount)
		}
		if len(o.Delivery) > 0 {
			return fmt.Errorf("a path option is delivered as its target mount: no delivery")
		}
	}
	if w := o.WritesAs; w != nil {
		for _, r := range []struct {
			what string
			ref  OwnerRef
		}{{"uid", w.UID}, {"gid", w.GID}} {
			switch {
			case r.ref.Num != nil:
				if *r.ref.Num < 0 {
					return fmt.Errorf("writes_as.%s must be non-negative", r.what)
				}
				if r.what == "gid" && InFolderGIDRange(int64(*r.ref.Num)) {
					return fmt.Errorf("writes_as.gid %d is in %s", *r.ref.Num, gidRangeText)
				}
			case r.ref.Key != "":
				ro := v.opts[r.ref.Key]
				if ro == nil || ro.EffectiveScope() != ScopeInstance || (ro.Type != TypeInt && ro.Type != TypeString) {
					return fmt.Errorf("writes_as.%s: %s is not an instance int or string option", r.what, r.ref.Key)
				}
			default:
				return fmt.Errorf("writes_as.%s: a number or an option key", r.what)
			}
		}
	}
	if g := o.Generate; g != nil {
		if g.Length < 8 || g.Length > 128 {
			return fmt.Errorf("generate.length %d must be 8-128", g.Length)
		}
		if !GenerateCharsets[g.Charset] {
			return fmt.Errorf("generate.charset %q must be hex, alphanumeric or ascii_printable", g.Charset)
		}
		if o.MinLen != nil && g.Length < *o.MinLen {
			return fmt.Errorf("generate.length %d is below min_len %d", g.Length, *o.MinLen)
		}
		if o.MaxLen != nil && g.Length > *o.MaxLen {
			return fmt.Errorf("generate.length %d is above max_len %d", g.Length, *o.MaxLen)
		}
	}
	return nil
}

func (v *specCheck) deliveries(o *Option) error {
	scope := o.EffectiveScope()
	if len(o.Delivery) == 0 {
		switch scope {
		case ScopePerson:
			return fmt.Errorf("scope person needs a per-person delivery (claim, header, file or hook)")
		case ScopeGroup, ScopePersonEntered:
			return fmt.Errorf("scope %s needs a delivery", scope)
		}
	}
	perPerson, hook := false, false
	for _, d := range o.Delivery {
		n := 0
		for _, set := range []bool{d.Env != "", d.Claim != nil, d.Header != nil, d.File != nil, d.Hook != ""} {
			if set {
				n++
			}
		}
		if n != 1 {
			return fmt.Errorf("each delivery is exactly one of env, claim, header, file or hook")
		}
		if d.Render != nil && d.Env == "" && d.Hook == "" {
			return fmt.Errorf("render goes inside a claim, header or file delivery")
		}
		switch {
		case d.Env != "":
			switch scope {
			case ScopePerson:
				return fmt.Errorf("per-person env is not allowed (one env for every person): deliver through a claim, header, file or hook")
			case ScopeGroup:
				if d.Render == nil || d.Render.Format != RenderJSON {
					return fmt.Errorf("a scope group env delivery is the map of records: it needs render.format: json")
				}
			}
		case d.Claim != nil:
			perPerson = true
			if err := v.claim(o, d.Claim); err != nil {
				return err
			}
		case d.Header != nil:
			perPerson = true
			if err := v.header(o, d.Header); err != nil {
				return err
			}
		case d.File != nil:
			perPerson = true
			if err := v.file(o, d.File); err != nil {
				return err
			}
			// A file whose changes run the hooks is applied live too.
			hook = hook || v.files_[d.File.Name].OnMembershipChange == MembershipHook
		case d.Hook != "":
			perPerson, hook = true, true
			if v.hooks_[d.Hook] == nil {
				return fmt.Errorf("hook %s is not declared in hooks", d.Hook)
			}
		}
	}
	if scope == ScopePerson && !perPerson {
		return fmt.Errorf("scope person needs a per-person delivery (claim, header, file or hook)")
	}
	if o.Applies == AppliesLive && !hook {
		return fmt.Errorf("applies: live means a hook applies it: add a hook delivery (or a file with on_membership_change: hook)")
	}
	return nil
}

func (v *specCheck) claim(o *Option, c *ClaimDelivery) error {
	scope := o.EffectiveScope()
	if scope != ScopePerson && scope != ScopePersonEntered {
		return fmt.Errorf("a claim delivery is for scope person or person_entered")
	}
	if v.m.Auth.Method != "native-oidc" {
		return fmt.Errorf("a claim delivery needs auth.method native-oidc (not %s)", v.m.Auth.Method)
	}
	found := false
	for _, cl := range v.m.Clients {
		found = found || cl.ClientID == c.Client
	}
	if !found {
		return fmt.Errorf("claim: client %s is not a keycloak_clients[] client_id", c.Client)
	}
	if !claimNameRe.MatchString(c.Name) {
		return fmt.Errorf("claim %q: name must match %s", c.Name, claimNameRe)
	}
	if reservedClaims[c.Name] || strings.HasPrefix(c.Name, "attr_") || strings.HasPrefix(c.Name, "portcullis_") {
		return fmt.Errorf("claim %s is reserved (standard, Keycloak, attr_* and portcullis_* claims)", c.Name)
	}
	if c.JSONType != "" && !claimJSONTypes[c.JSONType] {
		return fmt.Errorf("claim %s: json_type %q must be int, string, bool or json", c.Name, c.JSONType)
	}
	if err := claimTypeFits(o, c); err != nil {
		return fmt.Errorf("claim %s: %w", c.Name, err)
	}
	k := c.Client + "\x00" + c.Name
	if w, ok := v.claims[k]; ok {
		return fmt.Errorf("claim %s on client %s is already delivered by setting %s", c.Name, c.Client, w)
	}
	v.claims[k] = o.Key
	return nil
}

// claimTypeFits refuses a json_type the claim's render can't produce
// (what is statically known; the Hub checks every rendered value too):
// Keycloak converts the attribute to that type — int is a 32-bit integer,
// bool exactly true/false, json a JSON document.
func claimTypeFits(o *Option, c *ClaimDelivery) error {
	rd := c.Render
	if rd == nil {
		rd = &Render{}
	}
	numeric := func(int32Only bool) error {
		switch o.Type {
		case TypeInt, TypeDuration:
		case TypeSize:
			if int32Only && (rd.Unit == "" || rd.Unit == "B") {
				return fmt.Errorf("json_type %s: a size in bytes overflows the 32-bit integer Keycloak converts to: render it in a unit (render.unit: MiB, GiB, …)", c.JSONType)
			}
		default:
			return fmt.Errorf("json_type %s needs a number: type %s doesn't render as one", c.JSONType, o.Type)
		}
		if o.AllowUnlimited {
			if rd.Unlimited == nil {
				return fmt.Errorf("json_type %s: render.unlimited must be set", c.JSONType)
			}
			if int32Only {
				if _, err := strconv.ParseInt(*rd.Unlimited, 10, 32); err != nil {
					return fmt.Errorf("json_type %s: render.unlimited %q must be a 32-bit integer", c.JSONType, *rd.Unlimited)
				}
			} else if !json.Valid([]byte(*rd.Unlimited)) {
				return fmt.Errorf("json_type %s: render.unlimited %q must be JSON (a number or null)", c.JSONType, *rd.Unlimited)
			}
		}
		return nil
	}
	boolean := func() error {
		if o.Type != TypeBool {
			return fmt.Errorf("json_type %s needs type bool (not %s)", c.JSONType, o.Type)
		}
		if (rd.True != nil && *rd.True != "true") || (rd.False != nil && *rd.False != "false") {
			return fmt.Errorf("json_type %s: render.true / render.false must be exactly true / false", c.JSONType)
		}
		return nil
	}
	switch c.JSONType {
	case "int":
		return numeric(true)
	case "bool":
		return boolean()
	case "json":
		if rd.Format == RenderJSON || (o.Type == TypeTable && rd.Format == "") {
			return nil // a table renders JSON by default
		}
		switch o.Type {
		case TypeInt, TypeSize, TypeDuration:
			return numeric(false)
		case TypeBool:
			return boolean()
		}
		return fmt.Errorf("json_type %s: type %s renders plain text: add render.format: json", c.JSONType, o.Type)
	}
	return nil
}

// forwardAuthed reports whether a router runs a Portcullis forward-auth
// middleware (both strip client-sent X-Forwarded-Attr-*).
func forwardAuthed(ri *RouterInfo) bool {
	for _, m := range ri.Middlewares {
		if m == "portcullis-auth@docker" || m == "portcullis-groups@docker" {
			return true
		}
	}
	return false
}

// routerTarget is the compose service a router sends requests to: the
// service defining its explicit Traefik service (@docker trimmed), else
// the service carrying its labels.
// ok is false for an explicit service no compose service defines (a
// provider other than docker, weighted / mirroring, unknown): fail closed.
// Traefik service names are unique across compose services (ParseRoutes).
func (v *specCheck) routerTarget(ri *RouterInfo) (string, bool) {
	ts := ri.TraefikService
	if ts == "" {
		return ri.Service, true
	}
	ts, prov, _ := strings.Cut(ts, "@")
	if prov != "" && FoldKey(prov) != "docker" {
		return "", false
	}
	// Traefik folds names: compare folded, as checkCoreReferences does.
	for svc, names := range v.routes.TraefikServices {
		for _, n := range names {
			if FoldKey(n) == FoldKey(ts) {
				return svc, true
			}
		}
	}
	return "", false
}

func (v *specCheck) header(o *Option, h *HeaderDelivery) error {
	scope := o.EffectiveScope()
	if scope != ScopePerson && scope != ScopePersonEntered {
		return fmt.Errorf("a header delivery is for scope person or person_entered")
	}
	if !HeaderDeliveryRe.MatchString(h.Name) {
		return fmt.Errorf("header %q must be X-Forwarded-Attr-<Name>", h.Name)
	}
	// Identity-less routes (spec call 27, T-5): nobody is in a person
	// option's population there, and nothing strips a forged header.
	if a := &v.m.Auth; a.Method == "public" || a.Method == "custom" && !a.HasNativeLogin() {
		return fmt.Errorf("header %s: method %s routes carry no Portcullis identity (no per-person values, and clients could forge the header)", h.Name, a.Method)
	}
	if nl := v.m.Auth.NativeLogin; nl != nil && nl.AllowWithoutGateway {
		return fmt.Errorf("header %s: the app may run with its own login only (no Portcullis in front): clients could forge the header", h.Name)
	}
	// The compose services group-gate's headers reach (the backends of
	// gated routers), and every router that reaches them, wherever its
	// labels sit.
	names := make([]string, 0, len(v.routes.Info))
	for r := range v.routes.Info {
		names = append(names, r)
	}
	sort.Strings(names)
	// A service on network_mode host can reach every port of the host
	// (the delivering backend's included): no Traefik routing through it.
	svcs := make([]string, 0, len(v.routes.NetworkMode))
	for svc := range v.routes.NetworkMode {
		svcs = append(svcs, svc)
	}
	sort.Strings(svcs)
	for _, svc := range svcs {
		ns, ok := v.routes.NetNS(svc)
		if !ok {
			return fmt.Errorf("header %s: service %s's network_mode doesn't resolve to a service of the template (a cycle?): the Hub can't tell which backend its routers reach", h.Name, svc)
		}
		if ns == "host" && v.routes.TraefikLabelled[svc] {
			return fmt.Errorf("header %s: service %s has Traefik labels and runs in the host's network namespace (network_mode host): it can reach any port on the host, the delivering backend's included", h.Name, svc)
		}
	}
	// Targets are network namespaces: a service on network_mode
	// service:X shares X's, so a router to it reaches X's processes.
	gated, target := map[string]bool{}, map[string]string{}
	for _, r := range names {
		ri := v.routes.Info[r]
		t, ok := v.routerTarget(ri)
		if !ok {
			return fmt.Errorf("header %s: router %s's service %s isn't one of the template's own services: the Hub can't tell which backend it reaches", h.Name, r, ri.TraefikService)
		}
		if t, ok = v.routes.NetNS(t); !ok {
			return fmt.Errorf("header %s: router %s's backend has a network_mode the Hub can't resolve", h.Name, r)
		}
		target[r] = t
		if ri.Gated() {
			gated[t] = true
		}
	}
	if len(gated) == 0 {
		return fmt.Errorf("header %s needs routers with portcullis-groups@docker (group-gate returns the header)", h.Name)
	}
	for _, r := range names {
		ri := v.routes.Info[r]
		if t := target[r]; gated[t] && !forwardAuthed(ri) {
			return fmt.Errorf("header %s: router %s reaches service %s (its network namespace) without Portcullis forward-auth: clients could forge the header there", h.Name, r, t)
		}
	}
	k := strings.ToLower(h.Name)
	if w, ok := v.headers[k]; ok {
		return fmt.Errorf("header %s is already delivered by setting %s", h.Name, w)
	}
	v.headers[k] = o.Key
	return nil
}

func (v *specCheck) file(o *Option, fd *FileDelivery) error {
	if v.files_[fd.Name] == nil {
		return fmt.Errorf("file %s is not declared in files", fd.Name)
	}
	section := ""
	switch o.EffectiveScope() {
	case ScopeInstance, ScopeGroup:
		if fd.Field != "" {
			return fmt.Errorf("file %s: field is for person and person_entered options (this option is the file's %q entry)", fd.Name, o.Key)
		}
		return nil
	case ScopePerson:
		section = "people"
	case ScopePersonEntered:
		section = "entries"
	}
	field := fd.Field
	if field == "" {
		field = o.Key
	}
	if !fieldRe.MatchString(field) {
		return fmt.Errorf("file %s: field %q must match %s", fd.Name, field, fieldRe)
	}
	k := fd.Name + "\x00" + section + "\x00" + field
	if w, ok := v.fields[k]; ok {
		return fmt.Errorf("file %s: field %s is already written by setting %s", fd.Name, field, w)
	}
	v.fields[k] = o.Key
	return nil
}

// Options are the manifest's setting options (nil without settings).
func (m *Manifest) Options() []Option {
	if m.Settings == nil {
		return nil
	}
	return m.Settings.Options
}
