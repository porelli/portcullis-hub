// Package config is the CLI's own settings: os.UserConfigDir()/portcullis/
// config.json (0600, no secrets): each domain's discovery answer and its
// optional extra CA file.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/portcullis/hub/internal/cliapi"
)

// Domain is one configured Portcullis server.
type Domain struct {
	Config cliapi.Config `json:"config"`
	// CAFile is --ca-file's path, kept for the next runs ("" = none).
	CAFile string `json:"ca_file,omitempty"`
}

// File is config.json.
type File struct {
	Default string            `json:"default,omitempty"`
	Domains map[string]Domain `json:"domains"`
}

// Path is the file's path (dir "" = os.UserConfigDir()).
func Path(dir string) (string, error) {
	if dir == "" {
		d, err := os.UserConfigDir()
		if err != nil {
			return "", fmt.Errorf("no user config directory: %w", err)
		}
		dir = d
	}
	return filepath.Join(dir, "portcullis", "config.json"), nil
}

// Load reads the file (missing = empty).
func Load(dir string) (*File, error) {
	p, err := Path(dir)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return &File{Domains: map[string]Domain{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var f File
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("%s is corrupt: delete it and run portcullis login <domain> again", p)
	}
	if f.Domains == nil {
		f.Domains = map[string]Domain{}
	}
	return &f, nil
}

// Save writes the file (0600, its directory 0700).
func (f *File) Save(dir string) error {
	p, err := Path(dir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Pick chooses a domain: the argument, the only one, or the default.
func (f *File) Pick(arg string) (string, error) {
	if arg != "" {
		return arg, nil
	}
	if f.Default != "" {
		return f.Default, nil
	}
	if len(f.Domains) == 1 {
		for d := range f.Domains {
			return d, nil
		}
	}
	if len(f.Domains) == 0 {
		return "", errors.New("no Portcullis server configured yet: run portcullis login <domain>")
	}
	ds := make([]string, 0, len(f.Domains))
	for d := range f.Domains {
		ds = append(ds, d)
	}
	sort.Strings(ds)
	return "", fmt.Errorf("several servers are configured (%v): pick one with --domain", ds)
}
