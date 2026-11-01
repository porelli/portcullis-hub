package directory

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/rules"
)

// FieldKind represents the kind of a custom field.
type FieldKind string

const (
	FieldKindText   FieldKind = "text"
	FieldKindList   FieldKind = "list"
	FieldKindPerson FieldKind = "person"
)

// Field represents a custom user field.
type Field struct {
	Name          string    `yaml:"name"`
	Label         string    `yaml:"label"`
	Kind          FieldKind `yaml:"kind"`
	Values        []string  `yaml:"values,omitempty"`          // list kind: allowed values, in order
	Multi         bool      `yaml:"multi,omitempty"`           // list kind: allow multiple values
	ShareWithApps bool      `yaml:"share_with_apps,omitempty"` // expose to apps via headers/claims
	AdminOnly     bool      `yaml:"admin_only,omitempty"`      // only admins can edit
}

// Exception represents a rule exception for a user.
type Exception struct {
	User    string     `yaml:"user"`
	Reason  string     `yaml:"reason"`
	By      string     `yaml:"by"`
	Include bool       `yaml:"include"` // true = added though not matching; false = kept out
	Until   *time.Time `yaml:"until"`   // nil = permanent
	At      time.Time  `yaml:"at"`      // when the exception was created
}

// GroupConfig represents the configuration for a group.
type GroupConfig struct {
	Rule       *rules.Expr          `yaml:"-"`                    // nil = manual group
	Exceptions []Exception          `yaml:"exceptions,omitempty"` // rule groups only
	Expiry     map[string]time.Time `yaml:"expiry,omitempty"`     // manual groups: username -> until
	ruleText   string               `yaml:"rule,omitempty"`       // internal: rule as text
}

// MarshalYAML customizes YAML encoding to serialize Rule as text.
func (gc *GroupConfig) MarshalYAML() (interface{}, error) {
	type Alias GroupConfig
	aux := struct {
		*Alias
		RuleText string `yaml:"rule,omitempty"`
	}{
		Alias: (*Alias)(gc),
	}

	if gc.Rule != nil {
		text := rules.Format(gc.Rule)
		if text == "" {
			return nil, fmt.Errorf("rule failed to format")
		}
		aux.RuleText = text
	}

	return &aux, nil
}

// UnmarshalYAML customizes YAML decoding to parse Rule from text.
func (gc *GroupConfig) UnmarshalYAML(node *yaml.Node) error {
	type Alias GroupConfig
	aux := struct {
		*Alias
		RuleText string `yaml:"rule,omitempty"`
	}{
		Alias: (*Alias)(gc),
	}

	if err := node.Decode(&aux); err != nil {
		return err
	}

	if aux.RuleText != "" {
		expr, err := rules.Parse(aux.RuleText)
		if err != nil {
			return fmt.Errorf("parse rule: %w", err)
		}
		gc.Rule = expr
	}

	return nil
}

// Config represents the directory configuration.
type Config struct {
	Version     int                     `yaml:"version"`
	Fields      []Field                 `yaml:"fields"`
	Groups      map[string]*GroupConfig `yaml:"groups"`
	Permissions map[string]string       `yaml:"permissions"` // "edit_details"|"invite"|"remove" -> group name
	CreatedBy   map[string]string       `yaml:"created_by"`  // username -> delegate who invited them
}

// Store provides load/save for directory.yaml.
type Store struct {
	Path string
}

// Load reads the directory configuration from disk.
// Returns an empty Config if the file doesn't exist.
// Returns an error if the file is corrupt or has an unknown version.
func (s *Store) Load() (*Config, error) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		if os.IsNotExist(err) {
			// Missing file returns empty config
			return &Config{
				Version:     1,
				Fields:      []Field{},
				Groups:      map[string]*GroupConfig{},
				Permissions: map[string]string{},
				CreatedBy:   map[string]string{},
			}, nil
		}
		return nil, fmt.Errorf("read %s: %w", s.Path, err)
	}

	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", s.Path, err)
	}

	// Check version
	if cfg.Version != 1 {
		return nil, fmt.Errorf("unsupported version: %d", cfg.Version)
	}

	// Initialize nil maps
	if cfg.Fields == nil {
		cfg.Fields = []Field{}
	}
	if cfg.Groups == nil {
		cfg.Groups = map[string]*GroupConfig{}
	}
	if cfg.Permissions == nil {
		cfg.Permissions = map[string]string{}
	}
	if cfg.CreatedBy == nil {
		cfg.CreatedBy = map[string]string{}
	}

	// Validate parsed rules
	for groupName, gc := range cfg.Groups {
		if gc.Rule != nil {
			// Validate the parsed rule
			if err := rules.Validate(gc.Rule); err != nil {
				return nil, fmt.Errorf("invalid rule for group %q in %s: %w", groupName, s.Path, err)
			}
		}
	}

	return &cfg, nil
}

// Save writes the directory configuration to disk atomically.
func (s *Store) Save(cfg *Config) error {
	// Validate rules before saving
	for groupName, gc := range cfg.Groups {
		if gc.Rule != nil {
			if err := rules.Validate(gc.Rule); err != nil {
				return fmt.Errorf("invalid rule for group %q: %w", groupName, err)
			}
			// Check that Format produces non-empty output
			if rules.Format(gc.Rule) == "" {
				return fmt.Errorf("rule for group %q cannot be formatted", groupName)
			}
		}
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	if err := fsutil.WriteFileAtomic(s.Path, data, 0600); err != nil {
		return fmt.Errorf("write %s: %w", s.Path, err)
	}

	return nil
}
