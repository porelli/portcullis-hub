package templates

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

// Discover loads every valid template directly under dir. Invalid templates
// are logged and skipped. {{DOMAIN}} in app URLs is replaced by domain.
// kinds is the Hub's settings type registry (settings.Registry); nil is
// allowed only in test binaries (otherwise every template with settings
// is refused, ErrNoKinds).
func Discover(dir, source, domain string, kinds Kinds) []Template {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []Template
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, e.Name(), "manifest.yaml")); err != nil {
			continue
		}
		t, err := Load(dir, e.Name(), source, domain, kinds)
		if err != nil {
			log.Printf("Skipping template %s: %v", e.Name(), err)
			continue
		}
		out = append(out, t)
	}
	return out
}

// Load reads and validates the template in dir/name, as Discover does,
// and returns its catalog entry or why it is refused.
func Load(dir, name, source, domain string, kinds Kinds) (Template, error) {
	p := filepath.Join(dir, name)
	data, err := os.ReadFile(filepath.Join(p, "manifest.yaml"))
	if err != nil {
		return Template{}, err
	}
	compose, err := os.ReadFile(filepath.Join(p, "compose.yml"))
	if err != nil {
		compose = nil
	}
	return build(name, source, p, data, compose, domain, kinds)
}

// build validates a template from its manifest and compose file (nil =
// missing) and returns its catalog entry (the default instance's view).
func build(id, source, path string, data, compose []byte, domain string, kinds Kinds) (Template, error) {
	if !IDRe.MatchString(id) {
		return Template{}, fmt.Errorf("directory name must match %s", IDRe)
	}
	if err := CheckIDShape(id); err != nil {
		return Template{}, fmt.Errorf("directory name: %w", err)
	}
	if err := SingleDocument(data, "manifest.yaml"); err != nil {
		return Template{}, err
	}
	var mnode yaml.Node
	if err := yaml.Unmarshal(data, &mnode); err != nil {
		return Template{}, fmt.Errorf("bad manifest: %v", err)
	}
	if err := CheckTags(&mnode); err != nil {
		return Template{}, fmt.Errorf("manifest.yaml: %w", err)
	}
	var m Manifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return Template{}, fmt.Errorf("bad manifest: %v", err)
	}
	if err := ValidateManifest(&m); err != nil {
		return Template{}, err
	}
	if compose == nil {
		return Template{}, fmt.Errorf("no compose.yml")
	}
	// Before any parse: every check reads the first document only.
	if err := SingleDocument(compose, "compose.yml"); err != nil {
		return Template{}, err
	}
	routes, err := ParseRoutes(compose)
	if err != nil {
		return Template{}, err
	}
	// Only method custom may have no HTTP router (§3, F48): a gateway
	// method with none would protect nothing.
	if len(routes.Info) == 0 && m.Auth.Method != "custom" {
		return Template{}, fmt.Errorf("auth.method %s needs at least one HTTP router (only custom templates may have none)", m.Auth.Method)
	}
	m.routerless = routerlessOf(m.Auth.Method, routes)
	public, err := PlanPublic(&m, routes)
	if err != nil {
		return Template{}, err
	}
	if err := checkCoreRefs(compose, routes.HostVars); err != nil {
		return Template{}, err
	}
	if err := checkVolumeNames(compose, id, m.Multi()); err != nil {
		return Template{}, err
	}
	if err := checkInstanceRules(&m, routes); err != nil {
		return Template{}, err
	}
	services := Services(compose)
	if c := CoreContainerClash(id, services); c != "" {
		return Template{}, fmt.Errorf("its container %s would be a core service's container name", c)
	}
	raw := m
	t := Template{
		ID:           id,
		TemplateID:   id,
		Source:       source,
		Manifest:     m,
		Path:         path,
		Subdomains:   routes.Subdomains,
		Public:       public,
		HostRouters:  routes.HostRouters,
		HostVars:     routes.HostVars,
		HostForm:     routes.Form,
		Volumes:      ComposeVolumes(compose),
		NamedVolumes: declaredVolumeNames(compose),
		Services:     services,
		Names:        routes.Names,
		raw:          &raw,
	}
	if err := ValidateSettingsSpec(&t, compose, routes, kinds); err != nil {
		return Template{}, err
	}
	if err := validateSetup(&t.Manifest, compose, routes); err != nil {
		return Template{}, err
	}
	if err := ValidateAI(&t, compose, routes); err != nil {
		return Template{}, err
	}
	if t.GIDRefs, err = GIDRefs(&t.Manifest, compose); err != nil {
		return Template{}, err
	}
	if t.GIDEnvLeaks, err = GIDEnvLeaks(&t.Manifest, compose); err != nil {
		return Template{}, err
	}
	t.UsesLocalNetworks = ReferencesLocalNetworks(compose)
	// The catalog entry shows the default instance.
	return t.Instance(t.ID, nil, domain)
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
