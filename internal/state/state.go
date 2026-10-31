// Package state persists the Hub's own state (enabled apps, sources,
// settings, auth policies) as YAML.
package state

import (
	"bytes"
	"errors"
	"fmt"
	"os"

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
// app, as published to group-gate. If the app's template later stops
// loading (source removed, sync broke it, validation tightened) while its
// containers keep running, the Hub keeps enforcing this snapshot instead of
// silently dropping the app's entries (which would fail open).
type PublishedApp struct {
	Subdomains  []string `json:"subdomains" yaml:"subdomains"`
	GroupAccess bool     `json:"group_access" yaml:"group_access"`
	AccessGroup string   `json:"access_group,omitempty" yaml:"access_group,omitempty"`
	AdminGroup  string   `json:"admin_group,omitempty" yaml:"admin_group,omitempty"`
	AdminPaths  []string `json:"admin_paths,omitempty" yaml:"admin_paths,omitempty"`
	// Policy is the app's own policy override at publish time; nil means it
	// inherits the (current) global default.
	Policy *policy.AuthPolicy `json:"policy,omitempty" yaml:"policy,omitempty"`
}

// AppState tracks which apps are enabled and their settings.
type AppState struct {
	Enabled      []string                     `json:"enabled" yaml:"enabled"`
	Sources      []Source                     `json:"sources" yaml:"sources"`
	Settings     map[string]map[string]string `json:"settings" yaml:"settings"`
	AuthPolicies map[string]policy.AuthPolicy `json:"auth_policies" yaml:"auth_policies"`
	// DefaultPolicy is the admin-chosen global default; nil = never set,
	// which means policy.InitialDefault. An explicitly saved empty policy
	// (public) is a non-nil pointer and is honoured.
	DefaultPolicy *policy.AuthPolicy `json:"default_auth_policy,omitempty" yaml:"default_auth_policy,omitempty"`
	// Published holds the last known group-gate config per enabled app.
	Published map[string]PublishedApp `json:"published" yaml:"published"`
}

// New returns an empty state with initialised maps.
func New() *AppState {
	s := &AppState{}
	s.init()
	return s
}

func (s *AppState) init() {
	if s.Settings == nil {
		s.Settings = make(map[string]map[string]string)
	}
	if s.AuthPolicies == nil {
		s.AuthPolicies = make(map[string]policy.AuthPolicy)
	}
	if s.Published == nil {
		s.Published = make(map[string]PublishedApp)
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
