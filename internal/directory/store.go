package directory

import (
	"bytes"
	"fmt"
	"os"
	"strings"
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
	Multi         bool      `yaml:"multi,omitempty"`           // text and list kinds: allow multiple values; person: must be false
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
}

// Config represents the directory configuration.
type Config struct {
	Version     int                     `yaml:"version"`
	Fields      []Field                 `yaml:"fields"`
	Groups      map[string]*GroupConfig `yaml:"groups"`
	Permissions map[string]string       `yaml:"permissions"` // "edit_details"|"invite"|"remove" -> group name
	CreatedBy   map[string]string       `yaml:"created_by"`  // username -> delegate who invited them
	// Deleted: tombstones of deleted users (lowercase username -> when,
	// UTC). Delegates can't re-create these names; an admin can.
	Deleted map[string]time.Time `yaml:"deleted,omitempty"`
	// Grace: memberships the evaluator removed on expiry, still published
	// in the policy file's expiring list until Until (contract §4) so a
	// token issued before the removal can't use them. Dropped when Until
	// passes or the membership is granted again.
	Grace []GraceEntry `yaml:"grace,omitempty"`
}

// GraceEntry is one removed-on-expiry membership still published.
type GraceEntry struct {
	User  string    `yaml:"user"` // lowercase
	Group string    `yaml:"group"`
	At    time.Time `yaml:"at"`    // the expiry that ended it (UTC)
	Until time.Time `yaml:"until"` // published until (UTC)
}

// GracePeriod is how long a removed-on-expiry membership stays published.
const GracePeriod = 10 * time.Minute

// addGrace records (user, group) as removed on expiry at, until now +
// GracePeriod, replacing an older entry for the same membership.
func (cfg *Config) addGrace(user, group string, at, now time.Time) {
	cfg.clearGrace(group, user)
	cfg.Grace = append(cfg.Grace, GraceEntry{User: strings.ToLower(user), Group: group, At: at.UTC(), Until: now.Add(GracePeriod).UTC()})
}

// clearGrace drops the grace entry of (user, group); reports whether
// there was one. Called whenever the membership is granted again.
func (cfg *Config) clearGrace(group, user string) bool {
	kept := cfg.Grace[:0:0]
	for _, g := range cfg.Grace {
		if g.Group != group || !strings.EqualFold(g.User, user) {
			kept = append(kept, g)
		}
	}
	found := len(kept) != len(cfg.Grace)
	cfg.Grace = kept
	return found
}

// dropEndedGrace drops grace entries whose Until is <= now.
func (cfg *Config) dropEndedGrace(now time.Time) bool {
	kept := cfg.Grace[:0:0]
	for _, g := range cfg.Grace {
		if g.Until.After(now) {
			kept = append(kept, g)
		}
	}
	found := len(kept) != len(cfg.Grace)
	cfg.Grace = kept
	return found
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
				Deleted:     map[string]time.Time{},
			}, nil
		}
		return nil, fmt.Errorf("read %s: %w", s.Path, err)
	}

	// Decode into raw intermediate structs with KnownFields(true)
	type rawGroupConfig struct {
		RuleText   string               `yaml:"rule,omitempty"`
		Exceptions []Exception          `yaml:"exceptions,omitempty"`
		Expiry     map[string]time.Time `yaml:"expiry,omitempty"`
	}
	type rawConfig struct {
		Version     int                        `yaml:"version"`
		Fields      []Field                    `yaml:"fields"`
		Groups      map[string]*rawGroupConfig `yaml:"groups"`
		Permissions map[string]string          `yaml:"permissions"`
		CreatedBy   map[string]string          `yaml:"created_by"`
		Deleted     map[string]time.Time       `yaml:"deleted,omitempty"`
		Grace       []GraceEntry               `yaml:"grace,omitempty"`
	}

	var raw rawConfig
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("parse %s: %w", s.Path, err)
	}

	// Check version
	if raw.Version != 1 {
		return nil, fmt.Errorf("unsupported version: %d", raw.Version)
	}

	// Convert raw to real config
	cfg := &Config{
		Version:     raw.Version,
		Fields:      raw.Fields,
		Groups:      make(map[string]*GroupConfig),
		Permissions: raw.Permissions,
		CreatedBy:   raw.CreatedBy,
	}

	// Initialize nil maps
	if cfg.Fields == nil {
		cfg.Fields = []Field{}
	}
	if cfg.Permissions == nil {
		cfg.Permissions = map[string]string{}
	}
	if cfg.CreatedBy == nil {
		cfg.CreatedBy = map[string]string{}
	}
	cfg.Deleted = normDeleted(raw.Deleted)
	cfg.Grace = normGrace(raw.Grace)

	// Parse rules and normalize times
	for groupName, rawGC := range raw.Groups {
		gc := &GroupConfig{
			Exceptions: rawGC.Exceptions,
			Expiry:     rawGC.Expiry,
		}

		// Parse rule if present
		if rawGC.RuleText != "" {
			expr, err := rules.Parse(rawGC.RuleText)
			if err != nil {
				return nil, fmt.Errorf("%s: group %q: rule: %w", s.Path, groupName, err)
			}
			if err := rules.Validate(expr); err != nil {
				return nil, fmt.Errorf("%s: group %q: rule: %w", s.Path, groupName, err)
			}
			gc.Rule = expr
		}

		// Normalize exception times to UTC
		for i := range gc.Exceptions {
			gc.Exceptions[i].At = gc.Exceptions[i].At.UTC()
			if gc.Exceptions[i].Until != nil {
				utc := gc.Exceptions[i].Until.UTC()
				gc.Exceptions[i].Until = &utc
			}
		}

		// Normalize expiry times to UTC
		if gc.Expiry != nil {
			for user, t := range gc.Expiry {
				gc.Expiry[user] = t.UTC()
			}
		}

		cfg.Groups[groupName] = gc
	}

	return cfg, nil
}

// Save writes the directory configuration to disk atomically.
func (s *Store) Save(cfg *Config) error {
	// Convert to raw config with normalized times and rule text
	type rawGroupConfig struct {
		RuleText   string               `yaml:"rule,omitempty"`
		Exceptions []Exception          `yaml:"exceptions,omitempty"`
		Expiry     map[string]time.Time `yaml:"expiry,omitempty"`
	}
	type rawConfig struct {
		Version     int                        `yaml:"version"`
		Fields      []Field                    `yaml:"fields"`
		Groups      map[string]*rawGroupConfig `yaml:"groups"`
		Permissions map[string]string          `yaml:"permissions"`
		CreatedBy   map[string]string          `yaml:"created_by"`
		Deleted     map[string]time.Time       `yaml:"deleted,omitempty"`
		Grace       []GraceEntry               `yaml:"grace,omitempty"`
	}

	raw := rawConfig{
		Version:     cfg.Version,
		Fields:      cfg.Fields,
		Groups:      make(map[string]*rawGroupConfig),
		Permissions: cfg.Permissions,
		CreatedBy:   cfg.CreatedBy,
		Deleted:     normDeleted(cfg.Deleted),
		Grace:       normGrace(cfg.Grace),
	}

	// Convert groups and normalize times
	for groupName, gc := range cfg.Groups {
		if gc == nil {
			continue
		}
		rawGC := &rawGroupConfig{
			Exceptions: make([]Exception, len(gc.Exceptions)),
			Expiry:     make(map[string]time.Time),
		}

		// Format rule if present
		if gc.Rule != nil {
			if err := rules.Validate(gc.Rule); err != nil {
				return fmt.Errorf("invalid rule for group %q: %w", groupName, err)
			}
			text := rules.Format(gc.Rule)
			if text == "" {
				return fmt.Errorf("rule for group %q cannot be formatted", groupName)
			}
			rawGC.RuleText = text
		}

		// Normalize exception times to UTC
		for i, exc := range gc.Exceptions {
			rawGC.Exceptions[i] = exc
			rawGC.Exceptions[i].At = exc.At.UTC()
			if exc.Until != nil {
				utc := exc.Until.UTC()
				rawGC.Exceptions[i].Until = &utc
			}
		}

		// Normalize expiry times to UTC
		for user, t := range gc.Expiry {
			rawGC.Expiry[user] = t.UTC()
		}

		raw.Groups[groupName] = rawGC
	}

	data, err := yaml.Marshal(raw)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	if err := fsutil.WriteFileAtomic(s.Path, data, 0600); err != nil {
		return fmt.Errorf("write %s: %w", s.Path, err)
	}

	return nil
}

// normGrace returns grace entries with lowercase users and UTC times.
func normGrace(in []GraceEntry) []GraceEntry {
	if len(in) == 0 {
		return nil
	}
	out := make([]GraceEntry, 0, len(in))
	for _, g := range in {
		out = append(out, GraceEntry{User: strings.ToLower(g.User), Group: g.Group, At: g.At.UTC(), Until: g.Until.UTC()})
	}
	return out
}

// normDeleted returns tombstones with lowercase keys and UTC times.
func normDeleted(in map[string]time.Time) map[string]time.Time {
	out := make(map[string]time.Time, len(in))
	for user, at := range in {
		out[strings.ToLower(user)] = at.UTC()
	}
	return out
}
