package templates

import (
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Discover loads every valid template directly under dir. Invalid templates
// are logged and skipped. {{DOMAIN}} in app URLs is replaced by domain.
func Discover(dir, source, domain string) []Template {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []Template
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		manifestPath := filepath.Join(dir, e.Name(), "manifest.yaml")
		data, err := os.ReadFile(manifestPath)
		if err != nil {
			continue
		}
		if !IDRe.MatchString(e.Name()) {
			log.Printf("Skipping template %q: directory name must match %s", e.Name(), IDRe)
			continue
		}
		var m Manifest
		if err := yaml.Unmarshal(data, &m); err != nil {
			log.Printf("Bad manifest in %s: %v", manifestPath, err)
			continue
		}
		if err := ValidateManifest(&m); err != nil {
			log.Printf("Skipping template %s: %v", e.Name(), err)
			continue
		}
		for i := range m.URLs {
			m.URLs[i].URL = strings.ReplaceAll(m.URLs[i].URL, "{{DOMAIN}}", domain)
		}
		out = append(out, Template{
			ID:       e.Name(),
			Source:   source,
			Manifest: m,
			Path:     filepath.Join(dir, e.Name()),
		})
	}
	return out
}

// Sort orders templates by category, then name (the catalog order).
func Sort(ts []Template) {
	sort.SliceStable(ts, func(i, j int) bool {
		if ts[i].Manifest.Category != ts[j].Manifest.Category {
			return ts[i].Manifest.Category < ts[j].Manifest.Category
		}
		return ts[i].Manifest.Name < ts[j].Manifest.Name
	})
}

// ComposePath is the template's base compose file.
func (t *Template) ComposePath() string { return filepath.Join(t.Path, "compose.yml") }

// ReadCompose returns the template's compose.yml (nil if unreadable).
func (t *Template) ReadCompose() []byte {
	data, err := os.ReadFile(t.ComposePath())
	if err != nil {
		return nil
	}
	return data
}
