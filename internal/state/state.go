// Package state persists the Hub's own state (enabled apps, sources,
// settings, auth policies) as YAML.
package state

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"os"
	"path"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/templates"
)

// Source is a template repository.
type Source struct {
	Name string `json:"name" yaml:"name"`
	URL  string `json:"url" yaml:"url"`
	Path string `json:"path" yaml:"path"` // local path after clone
}

// PublishedApp is the last known routing/authorization config of an enabled
// instance, as published to group-gate. If the instance's template later stops
// loading (source removed, sync broke it, validation tightened) while its
// containers keep running, the Hub keeps enforcing this snapshot instead of
// silently dropping the instance's entries (which would fail open). Policy v6.
type PublishedApp struct {
	Hosts       []string `json:"hosts" yaml:"hosts"`
	GroupAccess bool     `json:"group_access" yaml:"group_access"`
	AccessGroup string   `json:"access_group,omitempty" yaml:"access_group,omitempty"`
	AdminGroup  string   `json:"admin_group,omitempty" yaml:"admin_group,omitempty"`
	AdminPaths  []string `json:"admin_paths,omitempty" yaml:"admin_paths,omitempty"`
	// SignInTemplate is the instance's own sign-in template pick at publish
	// time; "" means it inherits the (current) default.
	SignInTemplate string `json:"sign_in_template,omitempty" yaml:"sign_in_template,omitempty"`
	// SignInClients are, for a native-OIDC instance, its Keycloak client
	// ids (not ai_client) at publish time: an enabled instance whose
	// template disappears keeps them in signin-keycloak.json with
	// SignInTemplate, so Keycloak never lets an unlisted client through.
	SignInClients []string `json:"sign_in_clients,omitempty" yaml:"sign_in_clients,omitempty"`
	// NativeLoginOnly: the instance ran with its own login only (no Portcullis
	// sign-in on its routers, so GroupAccess is false) at publish time.
	NativeLoginOnly bool `json:"native_login_only,omitempty" yaml:"native_login_only,omitempty"`
	// PublicHosts / Public are the instance's public exceptions at publish time
	// ({token} kept, never the tokens); empty when no public router was generated.
	PublicHosts []string            `json:"public_hosts,omitempty" yaml:"public_hosts,omitempty"`
	Public      *policy.PublicEntry `json:"public,omitempty" yaml:"public,omitempty"`
	// Traefik, Volumes and Clients are the instance's Traefik names,
	// volume names and Keycloak client ids at publish time (contract
	// §11.1–11.2): an enabled instance whose template disappears keeps
	// claiming them, and a guarded delete still finds its clients.
	Traefik []string `json:"traefik,omitempty" yaml:"traefik,omitempty"`
	Volumes []string `json:"volumes,omitempty" yaml:"volumes,omitempty"`
	Clients []string `json:"clients,omitempty" yaml:"clients,omitempty"`
	// HeaderSuffixes are the template's header-delivery suffixes at
	// publish time: an instance whose template disappears keeps them
	// declared (no values) on its hosts, so a same-named shared-field
	// header never reaches them (fail closed).
	HeaderSuffixes []string `json:"header_suffixes,omitempty" yaml:"header_suffixes,omitempty"`
}

// KnownDomain is an enrolled domain as the domains service last reported
// it. There is deliberately no field for credentials.
type KnownDomain struct {
	Name         string     `json:"name" yaml:"name"`
	Provider     string     `json:"provider" yaml:"provider"`
	RecordsOK    bool       `json:"records_ok" yaml:"records_ok"`
	CertNotAfter *time.Time `json:"cert_not_after,omitempty" yaml:"cert_not_after,omitempty"`
	LastError    string     `json:"last_error,omitempty" yaml:"last_error,omitempty"`
	State        string     `json:"state" yaml:"state"`
}

// Instance is an app instance (contract §11): its template and hostnames
// (host router → full hostname), its label and group binding (§11.9). A
// template's default instance (ID = template id) has an entry only when
// something of this is stored (pinned or edited hosts, a label, a
// binding, a lifecycle state). Every other per-instance map of AppState
// (Enabled, Settings, Published, Public*, SignInMode) is keyed
// by its ID.
type Instance struct {
	ID       string            `json:"id" yaml:"id"`
	Template string            `json:"template" yaml:"template"`
	Hosts    map[string]string `json:"hosts" yaml:"hosts"`
	// State is InstanceCreated until the instance is first enabled
	// (InstanceDeleting during a guarded delete, InstanceRestoring while a
	// same-instance restore replaces its data); "" otherwise.
	State string `json:"state,omitempty" yaml:"state,omitempty"`
	// Backup is the archive a guarded delete took (InstanceDeleting: a
	// retry keeps it) or the pre-restore backup (InstanceRestoring: an
	// interrupted restore is rolled back from it), relative to
	// <data>/backups.
	Backup string `json:"backup,omitempty" yaml:"backup,omitempty"`
	// RestoreAs is the archive a restore into this NEW instance is filling
	// it from (state InstanceRestoring, no pre-restore backup): an
	// interrupted one is removed again at the next start.
	RestoreAs string `json:"restore_as,omitempty" yaml:"restore_as,omitempty"`
	// PreRestorePick is the sign-in template pick before a same-instance
	// restore (InstanceRestoring): a rollback puts it back, so it counts
	// as a use of its template until the restore ends.
	PreRestorePick string `json:"pre_restore_sign_in_template,omitempty" yaml:"pre_restore_sign_in_template,omitempty"`
	// Label is the instance's display label (§11.9; "" = never set: the
	// manifest's name for a default instance, the id otherwise). Display
	// only: nothing keys on it.
	Label string `json:"label,omitempty" yaml:"label,omitempty"`
	// UsersGroup / AdminsGroup bind the instance to existing groups
	// (§11.9 groups mode "existing"; "" = the derived names). Fixed after
	// create.
	UsersGroup  string `json:"users_group,omitempty" yaml:"users_group,omitempty"`
	AdminsGroup string `json:"admins_group,omitempty" yaml:"admins_group,omitempty"`
	// EnvOverrides are the admin's per-variable environment overrides
	// (§11.9 "Env overrides": name → value, never a secret), written
	// single-quoted after every other value of the instance's .env.
	EnvOverrides map[string]string `json:"env_overrides,omitempty" yaml:"env_overrides,omitempty"`
	// SignInTemplate is the instance's sign-in template pick (§8.1 "Per
	// app"; "" = the default template).
	SignInTemplate string `json:"sign_in_template,omitempty" yaml:"sign_in_template,omitempty"`
}

// HoldsIdentity reports whether the entry stores a label, a group
// binding, env overrides or a sign-in template pick: a default
// instance's entry that does is never dropped as "needs no entry".
func (e Instance) HoldsIdentity() bool {
	return e.Label != "" || e.UsersGroup != "" || e.AdminsGroup != "" || len(e.EnvOverrides) > 0 || e.SignInTemplate != ""
}

// Bound reports whether the instance is bound to existing groups.
func (e Instance) Bound() bool { return e.UsersGroup != "" || e.AdminsGroup != "" }

// Persisted instance states (Instance.State).
const (
	InstanceCreated   = "created"
	InstanceDeleting  = "deleting"
	InstanceRestoring = "restoring"
)

// AppState tracks which apps are enabled and their settings.
type AppState struct {
	// Enabled lists the enabled instance ids (a template id names its
	// default instance).
	Enabled []string `json:"enabled" yaml:"enabled"`
	// Instances are the instances by id. The default instance of a
	// template (id = template id) needs no entry unless it stores hosts,
	// a label, a binding or a state: else it uses the template's
	// hostnames on the main domain.
	Instances map[string]Instance `json:"instances,omitempty" yaml:"instances,omitempty"`
	Sources   []Source            `json:"sources" yaml:"sources"`
	// Settings are each instance's settings (contract §13), by id.
	Settings map[string]InstanceSettings `json:"settings" yaml:"settings"`
	// Published holds the last known group-gate config per enabled app.
	Published map[string]PublishedApp `json:"published" yaml:"published"`
	// PublicAccess is the admin's explicit choice for an app's public
	// exceptions (auth.public_access). No entry = the template's
	// enabled_by_default applies, including after it changes on sync.
	PublicAccess map[string]bool `json:"public_access,omitempty" yaml:"public_access,omitempty"`
	// PublicMode is the admin's explicit mode ("all" / "listed"); no entry
	// = the template's default_mode.
	PublicMode map[string]string `json:"public_mode,omitempty" yaml:"public_mode,omitempty"`
	// PublicTokens are the share tokens opened in listed mode (secrets:
	// state.yaml is 0600; the policy file only shows {token}).
	PublicTokens map[string][]string `json:"public_tokens,omitempty" yaml:"public_tokens,omitempty"`
	// SignInMode is the admin's sign-in choice for apps with their own
	// login (auth.native_login): SignInNative = the app's own login only,
	// no Portcullis in front. No entry = Portcullis sign-in, then the
	// app's own login.
	SignInMode map[string]string `json:"sign_in_mode,omitempty" yaml:"sign_in_mode,omitempty"`
	// SignIn is Settings → Sign-in (contract §8.1, D12): the methods, the
	// templates, the default, the core pages' picks, the add-stronger
	// switch and the Hub-set password records. EnsureSignIn fills a fresh
	// state's defaults.
	SignIn SignIn `json:"sign_in" yaml:"sign_in"`
	// Domains is the last known list of enrolled domains (contract §12.3)
	// with their provider and status — NEVER credentials. It keeps feeding
	// extra_domains and the portal while the domains service is down.
	Domains []KnownDomain `json:"domains,omitempty" yaml:"domains,omitempty"`
	// Folders are the shared folders by id (contract §14.1); FolderGIDs
	// every gid ever allocated from FolderGIDMin–FolderGIDMax, ascending:
	// a deleted folder's gid stays here, so it is never reused.
	Folders    map[string]Folder `json:"folders,omitempty" yaml:"folders,omitempty"`
	FolderGIDs []int             `json:"folder_gids,omitempty" yaml:"folder_gids,omitempty"`
	// FolderChanged: per instance, the folder value whose root or subpath
	// changed on disk around its last up (the doctor's folder_changed,
	// contract §14.5); kept across restarts, cleared by the instance's
	// next successful up and by its delete.
	FolderChanged map[string][]FolderChange `json:"folder_changed,omitempty" yaml:"folder_changed,omitempty"`
	// DoctorMutes: finding fingerprint → its mute (contract §14.5).
	DoctorMutes map[string]DoctorMute `json:"doctor_mutes,omitempty" yaml:"doctor_mutes,omitempty"`
	// LocalNetworks: the admin's LAN / VPN CIDRs (contract §14.7). A
	// pointer so that [] (loopback only) survives a save: nil = the
	// defaults.
	LocalNetworks *[]string `json:"local_networks,omitempty" yaml:"local_networks,omitempty"`
	// PersonIDs: pool → its Hub-wide person ids (contract §13.16, plan 3
	// Task 5). Here and never in an instance archive: an instance restore
	// keeps everyone's id.
	PersonIDs map[string]PersonIDPool `json:"person_ids,omitempty" yaml:"person_ids,omitempty"`
	// Credentials: instance → person_secret option key → lowercase user
	// → the credential's metadata (contract §13.16, plan 3 Task 6). No
	// secret: the hashes are on the secrets volume only. Not in instance
	// archives (§11.5).
	Credentials map[string]map[string]map[string]Credential `json:"credentials,omitempty" yaml:"credentials,omitempty"`
	// SecretsEpoch is the secrets epoch (§11.6): 16 random bytes, hex,
	// also in <secrets>/.epoch; rotated on every credential mutation. A
	// mismatch (a core restore, a crash between the two writes) voids
	// every credential.
	SecretsEpoch string `json:"secrets_epoch,omitempty" yaml:"secrets_epoch,omitempty"`
	// AI is Settings → AI and the model provider definitions (contract
	// §15.11–15.12; never a secret). Load starts from DefaultAISettings,
	// so keys a file lacks keep a new install's values.
	AI AISettings `json:"ai" yaml:"ai"`
	// AIInstances: instance id → its AI state (§15.11 ai_instances).
	AIInstances map[string]AIInstance `json:"ai_instances,omitempty" yaml:"ai_instances,omitempty"`
	// Impersonations are the administrators' impersonations (contract
	// §8.1 "Impersonation", top level, outside sign_in: F3): the running
	// ones, those ended less than an hour ago, and the used ones that
	// ended within history_days (with the apps opened, F1).
	Impersonations []Impersonation `json:"impersonations,omitempty" yaml:"impersonations,omitempty"`

	// signInMissing: the file Load read has no sign_in section (or there
	// was no file): the defaults EnsureSignIn filled are in memory only
	// until the next Save.
	signInMissing bool
}

// InstanceSettings are one instance's settings (contract §13). Values
// are canonical (internal/settings): sizes in bytes, durations in
// seconds, unlimited as the string "unlimited". Secret values are never
// here (Secrets holds metadata only; the values live in the Hub's 0600
// secrets store).
type InstanceSettings struct {
	// Ports are the template's port keys and their <KEY>_BIND addresses.
	Ports map[string]string `json:"ports,omitempty" yaml:"ports,omitempty"`
	// Values are the instance-scope option values (absent = the default).
	Values map[string]any `json:"values,omitempty" yaml:"values,omitempty"`
	// Types: option key → its type when it was stored (a retyped option's
	// stored value is dropped on template update).
	Types map[string]string `json:"types,omitempty" yaml:"types,omitempty"`
	// Person: per-person options (default, rule, per-group rows).
	Person map[string]PersonSetting `json:"person,omitempty" yaml:"person,omitempty"`
	// Groups: scope-group options' records, in the admin's order.
	Groups map[string][]GroupValue `json:"groups,omitempty" yaml:"groups,omitempty"`
	// Secrets: secret options' metadata only, never their values.
	Secrets map[string]SecretMeta `json:"secrets,omitempty" yaml:"secrets,omitempty"`
	// Entered: person-entered values (call 32), option key → lowercase
	// username → value.
	Entered map[string]map[string]EnteredValue `json:"entered,omitempty" yaml:"entered,omitempty"`
	// GroupIDs: instance-scope group / groups options (contract §13.2,
	// file sharing F3): option key → group name in Values → the LLDAP
	// group id it was saved against. A name whose id is missing or no
	// longer the directory's grants nothing (expand_members); a deleted or
	// re-created group is purged from the value.
	GroupIDs map[string]map[string]int `json:"group_ids,omitempty" yaml:"group_ids,omitempty"`
	// FirstStartedAt: when the instance's first start succeeded (contract
	// §13.18; nil = never started). Its fixed_after_start setup choices
	// can't change once it is set. Kept by backups and both restores.
	FirstStartedAt *time.Time `json:"first_started_at,omitempty" yaml:"first_started_at,omitempty"`
	// FixedKeys: the fixed_after_start setup options locked at the first
	// start (their values stored then), sorted. A template update never
	// drops them: an instance whose fixed choice no longer fits its
	// template is refused at start instead (§13.18).
	FixedKeys []string `json:"fixed_keys,omitempty" yaml:"fixed_keys,omitempty"`
}

// PersonSetting is a per-person option's configuration: the default
// (fallback for people in no row's group, canonical), the resolve rule
// ("" = the template's) and the per-group rows in the admin's order.
type PersonSetting struct {
	Default any          `json:"default" yaml:"default"`
	Resolve string       `json:"resolve,omitempty" yaml:"resolve,omitempty"`
	Rows    []GroupValue `json:"rows,omitempty" yaml:"rows,omitempty"`
}

// GroupValue is one per-group row or record: the LLDAP group name (or a
// {{ACCESS_GROUP}} / {{ADMIN_GROUP}} placeholder) and its id at save (0 =
// not bound yet: it grants nothing), and the canonical value.
type GroupValue struct {
	Group   string `json:"group" yaml:"group"`
	GroupID int    `json:"group_id" yaml:"group_id"`
	Value   any    `json:"value" yaml:"value"`
}

// SecretMeta is what state keeps of a secret option: when it was set and
// whether the Hub generated it. Never the value.
type SecretMeta struct {
	UpdatedAt time.Time `json:"updated_at" yaml:"updated_at"`
	Generated bool      `json:"generated,omitempty" yaml:"generated,omitempty"`
}

// EnteredValue is one person-entered value (call 32).
type EnteredValue struct {
	Value     any       `json:"value" yaml:"value"` // canonical
	UUID      string    `json:"uuid" yaml:"uuid"`   // LLDAP user uuid at save
	UpdatedAt time.Time `json:"updated_at" yaml:"updated_at"`
	SetBy     string    `json:"set_by,omitempty" yaml:"set_by,omitempty"` // "" = the person; else the admin's username
}

// instanceSettingsKeys are InstanceSettings' YAML keys.
var instanceSettingsKeys = map[string]bool{"ports": true, "values": true, "types": true, "person": true, "groups": true, "secrets": true, "entered": true, "group_ids": true, "first_started_at": true, "fixed_keys": true}

// IsLegacySettings reports whether n (one instance's settings) is not the
// InstanceSettings form: the old flat KEY: value map (contract v2), or
// anything else that isn't a mapping of its keys. Such settings are never
// read silently (a lost <KEY>_BIND would publish a port on every
// address): state.yaml and archives holding them are refused.
func IsLegacySettings(n *yaml.Node) bool {
	if n == nil || n.Kind == 0 || (n.Kind == yaml.ScalarNode && n.Tag == "!!null") {
		return false
	}
	if n.Kind != yaml.MappingNode {
		return true
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if !instanceSettingsKeys[n.Content[i].Value] {
			return true
		}
	}
	return false
}

// UnmarshalYAML decodes strictly: an unknown key (the old flat form) is
// an error, never dropped.
func (s *InstanceSettings) UnmarshalYAML(n *yaml.Node) error {
	if IsLegacySettings(n) {
		return fmt.Errorf("line %d: settings in the old flat form (before contract v3) are not read", n.Line)
	}
	type plain InstanceSettings
	return n.Decode((*plain)(s))
}

// IsZero reports whether s holds nothing.
func (s InstanceSettings) IsZero() bool {
	return len(s.Ports)+len(s.Values)+len(s.Types)+len(s.Person)+len(s.Groups)+len(s.Secrets)+len(s.Entered)+len(s.GroupIDs)+len(s.FixedKeys) == 0 && s.FirstStartedAt == nil
}

// Clone is a deep copy of s (values are copied structurally: lists and
// tables are fresh slices and maps).
func (s InstanceSettings) Clone() InstanceSettings {
	var c InstanceSettings
	if s.Ports != nil {
		c.Ports = make(map[string]string, len(s.Ports))
		for k, v := range s.Ports {
			c.Ports[k] = v
		}
	}
	if s.Values != nil {
		c.Values = make(map[string]any, len(s.Values))
		for k, v := range s.Values {
			c.Values[k] = cloneValue(v)
		}
	}
	if s.Types != nil {
		c.Types = make(map[string]string, len(s.Types))
		for k, v := range s.Types {
			c.Types[k] = v
		}
	}
	if s.Person != nil {
		c.Person = make(map[string]PersonSetting, len(s.Person))
		for k, p := range s.Person {
			c.Person[k] = PersonSetting{Default: cloneValue(p.Default), Resolve: p.Resolve, Rows: cloneRows(p.Rows)}
		}
	}
	if s.Groups != nil {
		c.Groups = make(map[string][]GroupValue, len(s.Groups))
		for k, rows := range s.Groups {
			c.Groups[k] = cloneRows(rows)
		}
	}
	if s.Secrets != nil {
		c.Secrets = make(map[string]SecretMeta, len(s.Secrets))
		for k, v := range s.Secrets {
			c.Secrets[k] = v
		}
	}
	if s.Entered != nil {
		c.Entered = make(map[string]map[string]EnteredValue, len(s.Entered))
		for k, m := range s.Entered {
			cm := make(map[string]EnteredValue, len(m))
			for u, e := range m {
				e.Value = cloneValue(e.Value)
				cm[u] = e
			}
			c.Entered[k] = cm
		}
	}
	if s.GroupIDs != nil {
		c.GroupIDs = make(map[string]map[string]int, len(s.GroupIDs))
		for k, m := range s.GroupIDs {
			cm := make(map[string]int, len(m))
			for g, id := range m {
				cm[g] = id
			}
			c.GroupIDs[k] = cm
		}
	}
	if s.FirstStartedAt != nil {
		at := *s.FirstStartedAt
		c.FirstStartedAt = &at
	}
	if s.FixedKeys != nil {
		c.FixedKeys = append([]string(nil), s.FixedKeys...)
	}
	return c
}

func cloneRows(rows []GroupValue) []GroupValue {
	if rows == nil {
		return nil
	}
	out := make([]GroupValue, len(rows))
	for i, r := range rows {
		r.Value = cloneValue(r.Value)
		out[i] = r
	}
	return out
}

// cloneValue copies a decoded value's lists and maps.
func cloneValue(v any) any {
	switch x := v.(type) {
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = cloneValue(e)
		}
		return out
	case []map[string]any:
		out := make([]map[string]any, len(x))
		for i, e := range x {
			out[i] = cloneValue(e).(map[string]any)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = cloneValue(e)
		}
		return out
	}
	return v
}

// The allocated folder gid range (contract §14.1; templates.FolderGIDMin /
// FolderGIDMax refuse it in templates).
const (
	FolderGIDMin = templates.FolderGIDMin
	FolderGIDMax = templates.FolderGIDMax
)

// Folder is a shared folder (contract §14.1). Path is the cleaned host
// path; Dev, Ino and MountRoot are the folder root's device, inode and
// exact /proc/self/mountinfo root as the fixer reported them at create or
// at the last path change (R41, R43): every later run on the folder must
// find exactly them.
type Folder struct {
	Name        string    `json:"name" yaml:"name"`
	Path        string    `json:"path" yaml:"path"`
	Description string    `json:"description,omitempty" yaml:"description,omitempty"`
	GID         int       `json:"gid" yaml:"gid"`
	Adopted     bool      `json:"adopted,omitempty" yaml:"adopted,omitempty"`
	CreatedAt   time.Time `json:"created_at" yaml:"created_at"`
	Dev         uint64    `json:"dev" yaml:"dev"`
	Ino         uint64    `json:"ino" yaml:"ino"`
	MountRoot   string    `json:"mount_root" yaml:"mount_root"`
	// WriteConfirmed: "<instance>/<key>" → an admin-confirmed write for a
	// template without a folder block.
	WriteConfirmed map[string]bool `json:"write_confirmed,omitempty" yaml:"write_confirmed,omitempty"`
	LastApply      *FolderApply    `json:"last_apply,omitempty" yaml:"last_apply,omitempty"`
}

// FolderApply is a folder's last apply (cleared by an undo).
type FolderApply struct {
	At       time.Time `json:"at" yaml:"at"`
	Files    string    `json:"files" yaml:"files"` // rw | r
	OwnerUID *int      `json:"owner_uid,omitempty" yaml:"owner_uid,omitempty"`
	Snapshot string    `json:"snapshot,omitempty" yaml:"snapshot,omitempty"` // "<folder>/<ts>.ndjson.gz"
	// RootDev / RootIno: the folder root the snapshot recorded, set when a
	// device-only identity re-check changed the stored device since (0 =
	// the folder's own dev/ino); restore expects the snapshot header to
	// name them.
	RootDev uint64 `json:"root_dev,omitempty" yaml:"root_dev,omitempty"`
	RootIno uint64 `json:"root_ino,omitempty" yaml:"root_ino,omitempty"`
	// RootMountRoot: the mount root recorded with them.
	RootMountRoot string `json:"root_mount_root,omitempty" yaml:"root_mount_root,omitempty"`
}

// FolderChange is a folder value whose root or subpath changed on disk
// while its instance started (R44; doctor finding folder_changed).
type FolderChange struct {
	Instance string    `json:"instance" yaml:"instance"`
	Key      string    `json:"key" yaml:"key"`
	Folder   string    `json:"folder" yaml:"folder"`
	Subpath  string    `json:"subpath" yaml:"subpath"`
	At       time.Time `json:"at" yaml:"at"`
	Detail   string    `json:"detail" yaml:"detail"`
}

// DoctorMute is an admin's mute of a doctor finding: the reason, who and
// when, and the finding's inputs digest (a changed digest unmutes it).
type DoctorMute struct {
	Reason string    `json:"reason" yaml:"reason"`
	Actor  string    `json:"actor" yaml:"actor"`
	At     time.Time `json:"at" yaml:"at"`
	Inputs string    `json:"inputs" yaml:"inputs"`
}

// Folder field limits (contract §14.1).
const (
	FolderNameMax        = 64
	FolderDescriptionMax = 500
)

// ValidAdoptedGID is "" when gid may be adopted for a folder (contract
// §14.1), else why not: ≥ 1000, not 65534 (nobody), outside the allocated
// range, not 10001 (the Hub, which reads the data files) or 10002
// (enroll's secrets), at most 2^31-1.
func ValidAdoptedGID(gid int) string {
	switch {
	case gid < 1000:
		return "it is a system group (below 1000)"
	case gid == 65534:
		return "65534 is the nobody group"
	case gid >= FolderGIDMin && gid <= FolderGIDMax:
		return fmt.Sprintf("%d-%d are allocated by the Hub", FolderGIDMin, FolderGIDMax)
	case gid == 10001:
		return "10001 is the Hub's own group (it reads the data files)"
	case gid == 10002:
		return "10002 is the group of enroll's secrets"
	case gid > math.MaxInt32:
		return "it is out of range"
	}
	return ""
}

// checkFolders refuses a corrupt folders / folder_gids entry: the Hub
// doesn't start on it (P24). It checks the shape only; the Hub checks the
// path rules against its configuration.
func (s *AppState) checkFolders() error {
	for i, g := range s.FolderGIDs {
		if g < FolderGIDMin || g > FolderGIDMax {
			return fmt.Errorf("folder_gids: %d is outside %d-%d", g, FolderGIDMin, FolderGIDMax)
		}
		if i > 0 && g <= s.FolderGIDs[i-1] {
			return fmt.Errorf("folder_gids: not strictly ascending at %d", g)
		}
	}
	gids := map[int]string{}
	ids := make([]string, 0, len(s.Folders))
	for id := range s.Folders {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		f := s.Folders[id]
		bad := func(format string, args ...any) error {
			return fmt.Errorf("folders: %s: %s", id, fmt.Sprintf(format, args...))
		}
		switch {
		case !settings.FolderIDRe.MatchString(id):
			return fmt.Errorf("folders: %q is not a folder id", id)
		case f.Name == "" || utf8.RuneCountInString(f.Name) > FolderNameMax || templates.HasControlChars(f.Name):
			return bad("name")
		case utf8.RuneCountInString(f.Description) > FolderDescriptionMax || templates.HasControlChars(f.Description):
			return bad("description")
		case !path.IsAbs(f.Path) || path.Clean(f.Path) != f.Path || f.Path == "/" || templates.HasControlChars(f.Path) ||
			strings.ContainsAny(f.Path, ":$"):
			return bad("path %q", f.Path)
		case f.Dev == 0 || f.Ino == 0 || !path.IsAbs(f.MountRoot) || templates.HasControlChars(f.MountRoot):
			return bad("device, inode or mount root missing")
		case f.Adopted && ValidAdoptedGID(f.GID) != "":
			return bad("adopted gid %d: %s", f.GID, ValidAdoptedGID(f.GID))
		case !f.Adopted && !slices.Contains(s.FolderGIDs, f.GID):
			return bad("gid %d is not in folder_gids", f.GID)
		case f.LastApply != nil && f.LastApply.Files != "rw" && f.LastApply.Files != "r":
			return bad("last_apply.files %q", f.LastApply.Files)
		}
		if other, dup := gids[f.GID]; dup {
			return bad("gid %d is also %s's", f.GID, other)
		}
		gids[f.GID] = id
	}
	return nil
}

// SignInNative is the SignIn value for "the app's own login only".
const SignInNative = "native"

// New returns an empty state with initialised maps.
func New() *AppState {
	s := &AppState{AI: DefaultAISettings(), signInMissing: true}
	s.init()
	s.EnsureSignIn()
	return s
}

// SignInMissing reports whether the sign-in section is in memory only:
// the loaded file had none (or there was none) and nothing has been saved
// since.
func (s *AppState) SignInMissing() bool { return s.signInMissing }

func (s *AppState) init() {
	if s.Instances == nil {
		s.Instances = make(map[string]Instance)
	}
	if s.Settings == nil {
		s.Settings = make(map[string]InstanceSettings)
	}
	if s.Published == nil {
		s.Published = make(map[string]PublishedApp)
	}
	if s.PublicAccess == nil {
		s.PublicAccess = make(map[string]bool)
	}
	if s.PublicMode == nil {
		s.PublicMode = make(map[string]string)
	}
	if s.PublicTokens == nil {
		s.PublicTokens = make(map[string][]string)
	}
	if s.SignInMode == nil {
		s.SignInMode = make(map[string]string)
	}
	if s.PersonIDs == nil {
		s.PersonIDs = make(map[string]PersonIDPool)
	}
	if s.Credentials == nil {
		s.Credentials = make(map[string]map[string]map[string]Credential)
	}
	if s.AI.AllowedOrigins == nil {
		s.AI.AllowedOrigins = []string{}
	}
}

// Load reads the state file. A missing file yields empty state. An empty or
// unparsable file is an error: continuing with empty state would overwrite
// it on the next save and lose every enabled app and source.
func Load(path string) (*AppState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return New(), nil
		}
		return nil, fmt.Errorf("cannot read %s: %w", path, err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("%s is empty (interrupted write?) — restore it from backup or delete it to start fresh", path)
	}
	var probe struct {
		Settings map[string]yaml.Node `yaml:"settings"`
		SignIn   *yaml.Node           `yaml:"sign_in"`
	}
	signInMissing := true
	if err := yaml.Unmarshal(data, &probe); err == nil {
		signInMissing = probe.SignIn == nil
		var legacy []string
		for id, n := range probe.Settings {
			if IsLegacySettings(&n) {
				legacy = append(legacy, id)
			}
		}
		if len(legacy) > 0 {
			sort.Strings(legacy)
			return nil, fmt.Errorf("%s: the settings of %s are in the old flat form (before contract v3): they are not migrated — remove them from settings: and re-enter them (ports and bind addresses included) after the upgrade", path, strings.Join(legacy, ", "))
		}
	}
	s := &AppState{AI: DefaultAISettings()}
	if err := yaml.Unmarshal(data, s); err != nil {
		return nil, fmt.Errorf("corrupt %s (%v) — fix or move it aside, then restart", path, err)
	}
	if err := s.checkFolders(); err != nil {
		return nil, fmt.Errorf("corrupt %s (%v) — fix or move it aside, then restart", path, err)
	}
	if err := s.checkPersonIDs(); err != nil {
		return nil, fmt.Errorf("corrupt %s (%v) — fix or move it aside, then restart", path, err)
	}
	if s.LocalNetworks != nil {
		if _, err := ParseLocalNetworks(*s.LocalNetworks); err != nil {
			return nil, fmt.Errorf("corrupt %s (local_networks: %v) — fix or move it aside, then restart", path, err)
		}
	}
	if err := s.AI.CheckDays(); err != nil {
		return nil, fmt.Errorf("corrupt %s (ai: %v) — fix or move it aside, then restart", path, err)
	}
	if err := s.AI.Limits.CheckLimits(); err != nil {
		return nil, fmt.Errorf("corrupt %s (ai: %v) — fix or move it aside, then restart", path, err)
	}
	s.init()
	s.signInMissing = signInMissing
	s.EnsureSignIn()
	if err := s.checkSignIn(); err != nil {
		return nil, fmt.Errorf("corrupt %s (sign_in: %v) — fix or move it aside, then restart", path, err)
	}
	return s, nil
}

// MaxLocalNetworks is the most Local networks entries (contract §14.7).
const MaxLocalNetworks = 64

// ParseLocalNetworks parses a Local networks list: at most 64 CIDRs, each
// in canonical form without host bits, no /0 prefix (it would make "LAN
// only" mean anything), no duplicates. Errors name the entry.
func ParseLocalNetworks(cidrs []string) ([]netip.Prefix, error) {
	if len(cidrs) > MaxLocalNetworks {
		return nil, fmt.Errorf("at most %d local networks (got %d)", MaxLocalNetworks, len(cidrs))
	}
	out := make([]netip.Prefix, 0, len(cidrs))
	seen := map[netip.Prefix]bool{}
	for _, c := range cidrs {
		q := clipQuote(c)
		p, err := netip.ParsePrefix(c)
		switch {
		case err != nil || p.Addr().Zone() != "":
			return nil, fmt.Errorf("%s is not a CIDR (e.g. 192.168.1.0/24)", q)
		case p.Bits() == 0:
			return nil, fmt.Errorf("%s would count every address as local", q)
		case p.Masked() != p:
			return nil, fmt.Errorf("%s has host bits set (did you mean %s?)", q, p.Masked())
		case p.Addr().Is4In6():
			return nil, fmt.Errorf("%s: write IPv4 networks in their IPv4 form", q)
		case seen[p]:
			return nil, fmt.Errorf("%s is listed twice", q)
		}
		seen[p] = true
		out = append(out, p)
	}
	return out, nil
}

// clipQuote is s quoted, at most 64 bytes of it.
func clipQuote(s string) string {
	if len(s) > 64 {
		s = s[:64] + "…"
	}
	return fmt.Sprintf("%q", s)
}

// Save writes the state atomically with mode 0600.
func (s *AppState) Save(path string) error {
	data, err := yaml.Marshal(s)
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	if err := fsutil.WriteFileAtomic(path, data, 0600); err != nil {
		return err
	}
	s.signInMissing = false
	return nil
}

// IsEnabled reports whether id is in the enabled list.
func (s *AppState) IsEnabled(id string) bool {
	for _, e := range s.Enabled {
		if e == id {
			return true
		}
	}
	return false
}

// SetEnabled adds or removes id from the enabled list.
func (s *AppState) SetEnabled(id string, on bool) {
	if on {
		if !s.IsEnabled(id) {
			s.Enabled = append(s.Enabled, id)
		}
		return
	}
	out := make([]string, 0, len(s.Enabled))
	for _, e := range s.Enabled {
		if e != id {
			out = append(out, e)
		}
	}
	s.Enabled = out
}
