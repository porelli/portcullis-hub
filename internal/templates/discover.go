package templates

import (
	"log"
	"os"
	"path/filepath"
	"sort"

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
		compose, err := os.ReadFile(filepath.Join(dir, e.Name(), "compose.yml"))
		if err != nil {
			log.Printf("Skipping template %s: no compose.yml: %v", e.Name(), err)
			continue
		}
		routes, err := ParseRoutes(compose)
		if err != nil {
			log.Printf("Skipping template %s: %v", e.Name(), err)
			continue
		}
		public, err := PlanPublic(&m, routes)
		if err != nil {
			log.Printf("Skipping template %s: %v", e.Name(), err)
			continue
		}
		if err := checkVolumeNames(compose, m.Multi()); err != nil {
			log.Printf("Skipping template %s: %v", e.Name(), err)
			continue
		}
		if err := checkInstanceRules(&m, routes); err != nil {
			log.Printf("Skipping template %s: %v", e.Name(), err)
			continue
		}
		raw := m
		t := Template{
			ID:           e.Name(),
			TemplateID:   e.Name(),
			Source:       source,
			Manifest:     m,
			Path:         filepath.Join(dir, e.Name()),
			Subdomains:   routes.Subdomains,
			Public:       public,
			HostRouters:  routes.HostRouters,
			HostVars:     routes.HostVars,
			HostForm:     routes.Form,
			Volumes:      ComposeVolumes(compose),
			NamedVolumes: declaredVolumeNames(compose),
			Names:        routes.Names,
			raw:          &raw,
		}
		// The catalog entry shows the default instance.
		view, err := t.Instance(t.ID, nil, domain)
		if err != nil {
			log.Printf("Skipping template %s: %v", e.Name(), err)
			continue
		}
		out = append(out, view)
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
