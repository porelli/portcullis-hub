// Package state persists the Hub's own state (enabled apps, sources,
// settings, auth policies) as YAML.
package state

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/policy"
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
// silently dropping the instance's entries (which would fail open). Policy v5.
type PublishedApp struct {
	Hosts       []string `json:"hosts" yaml:"hosts"`
	GroupAccess bool     `json:"group_access" yaml:"group_access"`
	AccessGroup string   `json:"access_group,omitempty" yaml:"access_group,omitempty"`
	AdminGroup  string   `json:"admin_group,omitempty" yaml:"admin_group,omitempty"`
	AdminPaths  []string `json:"admin_paths,omitempty" yaml:"admin_paths,omitempty"`
	// Policy is the instance's own policy override at publish time; nil means it
	// inherits the (current) global default.
	Policy *policy.AuthPolicy `json:"policy,omitempty" yaml:"policy,omitempty"`
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

// Instance is an app instance other than a template's implicit default
// one (contract §11): its template and hostnames (host router → full
// hostname). Every other per-instance map of AppState (Enabled, Settings,
// AuthPolicies, Published, Public*, SignIn) is keyed by its ID.
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
}

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
	// Instances are the instances other than the implicit default ones,
	// by id. The default instance of a template (id = template id) needs
	// no entry: it uses the template's hostnames on the main domain.
	Instances    map[string]Instance          `json:"instances,omitempty" yaml:"instances,omitempty"`
	Sources      []Source                     `json:"sources" yaml:"sources"`
	Settings     map[string]map[string]string `json:"settings" yaml:"settings"`
	AuthPolicies map[string]policy.AuthPolicy `json:"auth_policies" yaml:"auth_policies"`
	// DefaultPolicy is the admin-chosen global default; nil = never set,
	// which means policy.InitialDefault. An explicitly saved empty policy
	// (public) is a non-nil pointer and is honoured.
	DefaultPolicy *policy.AuthPolicy `json:"default_auth_policy,omitempty" yaml:"default_auth_policy,omitempty"`
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
	// SignIn is the admin's sign-in choice for apps with their own login
	// (auth.native_login): SignInNative = the app's own login only, no
	// Portcullis in front. No entry = Portcullis sign-in, then the app's
	// own login.
	SignIn map[string]string `json:"sign_in,omitempty" yaml:"sign_in,omitempty"`
	// Domains is the last known list of enrolled domains (contract §12.3)
	// with their provider and status — NEVER credentials. It keeps feeding
	// extra_domains and the portal while the domains service is down.
	Domains []KnownDomain `json:"domains,omitempty" yaml:"domains,omitempty"`

	// LegacyPassword lists, after Load, the policies that named the removed
	// "password" factor and were normalised ("" = the global default). Not
	// persisted: the next save writes the normalised policies.
	LegacyPassword map[string]bool `json:"-" yaml:"-"`
}

// SignInNative is the SignIn value for "the app's own login only".
const SignInNative = "native"

// New returns an empty state with initialised maps.
func New() *AppState {
	s := &AppState{}
	s.init()
	return s
}

func (s *AppState) init() {
	if s.Instances == nil {
		s.Instances = make(map[string]Instance)
	}
	if s.Settings == nil {
		s.Settings = make(map[string]map[string]string)
	}
	if s.AuthPolicies == nil {
		s.AuthPolicies = make(map[string]policy.AuthPolicy)
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
	if s.SignIn == nil {
		s.SignIn = make(map[string]string)
	}
	if s.LegacyPassword == nil {
		s.LegacyPassword = make(map[string]bool)
	}
}

// normalizeLegacy rewrites stored policies that name the removed
// "password" factor (policy.Normalize: never weaker) and remembers which.
func (s *AppState) normalizeLegacy() {
	if s.DefaultPolicy != nil && policy.LegacyPassword(*s.DefaultPolicy) {
		p := policy.Normalize(*s.DefaultPolicy)
		s.DefaultPolicy = &p
		s.LegacyPassword[""] = true
	}
	for id, p := range s.AuthPolicies {
		if policy.LegacyPassword(p) {
			s.AuthPolicies[id] = policy.Normalize(p)
			s.LegacyPassword[id] = true
		}
	}
	for id, snap := range s.Published {
		if snap.Policy != nil && policy.LegacyPassword(*snap.Policy) {
			p := policy.Normalize(*snap.Policy)
			snap.Policy = &p
			s.Published[id] = snap
		}
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
	s := &AppState{}
	if err := yaml.Unmarshal(data, s); err != nil {
		return nil, fmt.Errorf("corrupt %s (%v) — fix or move it aside, then restart", path, err)
	}
	s.init()
	s.normalizeLegacy()
	return s, nil
}

// Save writes the state atomically with mode 0600.
func (s *AppState) Save(path string) error {
	data, err := yaml.Marshal(s)
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	return fsutil.WriteFileAtomic(path, data, 0600)
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

// ResolvePolicy returns the per-app override if set, else the global default.
func (s *AppState) ResolvePolicy(appID string) policy.AuthPolicy {
	if p, ok := s.AuthPolicies[appID]; ok {
		return p
	}
	return s.Default()
}

// Default returns the effective global default policy.
func (s *AppState) Default() policy.AuthPolicy {
	if s.DefaultPolicy == nil {
		return policy.InitialDefault()
	}
	p := *s.DefaultPolicy
	if p.Factors == nil {
		p.Factors = []string{} // explicit public: publish [] (public), not null
	}
	return p
}

// SetDefault stores an explicit global default (may be public).
func (s *AppState) SetDefault(p policy.AuthPolicy) {
	s.DefaultPolicy = &p
}
