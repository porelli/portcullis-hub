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

// AppState tracks which apps are enabled and their settings.
type AppState struct {
	Enabled       []string                     `json:"enabled" yaml:"enabled"`
	Sources       []Source                     `json:"sources" yaml:"sources"`
	Settings      map[string]map[string]string `json:"settings" yaml:"settings"`
	AuthPolicies  map[string]policy.AuthPolicy `json:"auth_policies" yaml:"auth_policies"`
	DefaultPolicy policy.AuthPolicy            `json:"default_auth_policy" yaml:"default_auth_policy"`
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
	return s.DefaultPolicy
}
