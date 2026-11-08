package templates

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// One-off jobs (contract §3 "One-off jobs") and setup options with
// compose profiles (§13.18). The templates repo's tests/validate.py
// (check_setup) mirrors every refusal here with the same message.

// VarComposeProfiles is the .env variable the Hub writes the instance's
// profiles into (ProfilesFor); a manifest may not declare it.
const VarComposeProfiles = "COMPOSE_PROFILES"

// ProfileRe is a compose profile name (compose's own rule).
var ProfileRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

// conditionCompleted is the depends_on condition that makes the
// dependency a one-off job.
const conditionCompleted = "service_completed_successfully"

// composeServices decodes compose.yml's services as plain maps (nil
// entries for services that aren't mappings).
func composeServices(compose []byte) (map[string]map[string]any, error) {
	var doc struct {
		Services map[string]any `yaml:"services"`
	}
	if err := yaml.Unmarshal(compose, &doc); err != nil {
		return nil, fmt.Errorf("compose.yml: %v", err)
	}
	out := make(map[string]map[string]any, len(doc.Services))
	for name, raw := range doc.Services {
		s, _ := raw.(map[string]any)
		out[name] = s
	}
	return out, nil
}

// JobServices is the template's one-off jobs: the manifest's jobs plus
// every service another service depends on with condition
// service_completed_successfully (long depends_on syntax). Never nil.
func JobServices(m *Manifest, compose []byte) map[string]bool {
	out := map[string]bool{}
	for _, j := range m.Jobs {
		out[j] = true
	}
	svcs, err := composeServices(compose)
	if err != nil {
		return out
	}
	for _, s := range svcs {
		deps, _ := s["depends_on"].(map[string]any)
		for dep, raw := range deps {
			if c, _ := raw.(map[string]any); c != nil {
				if cond, _ := c["condition"].(string); cond == conditionCompleted {
					out[dep] = true
				}
			}
		}
	}
	return out
}

// ServiceProfiles is each compose service's profiles: as written (only
// services with a profiles: key; validateSetup refuses anything but a
// list of literal names).
func ServiceProfiles(compose []byte) (map[string][]string, error) {
	svcs, err := composeServices(compose)
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for name, s := range svcs {
		raw, ok := s["profiles"]
		if !ok {
			continue
		}
		list, ok := raw.([]any)
		if !ok || len(list) == 0 {
			return nil, fmt.Errorf("service %s: profiles must be a list of literal profile names", name)
		}
		for _, p := range list {
			ps, ok := p.(string)
			if !ok || !ProfileRe.MatchString(ps) {
				return nil, fmt.Errorf("service %s: profiles must be a list of literal profile names", name)
			}
			out[name] = append(out[name], ps)
		}
	}
	return out, nil
}

// ProfilesFor is the instance's compose profiles (§13.18): for every
// option with profiles, the list of its value in values (the stored
// instance values), else of its default; merged, de-duplicated, sorted.
// A stored value that isn't one of the mapping's keys counts as the
// default. Nil when the template selects no profile.
func ProfilesFor(t *Template, values map[string]any) []string {
	if t == nil || t.Manifest.Settings == nil {
		return nil
	}
	seen := map[string]bool{}
	for i := range t.Manifest.Settings.Options {
		o := &t.Manifest.Settings.Options[i]
		if o.Profiles == nil {
			continue
		}
		v, _ := values[o.Key].(string)
		ps, ok := o.Profiles[v]
		if !ok {
			d, _ := o.Default.(string)
			ps = o.Profiles[d]
		}
		for _, p := range ps {
			seen[p] = true
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// validateSetup checks jobs, setup options and compose profiles (contract
// §3, §13.18). Run after ValidateSettingsSpec (option types are known).
func validateSetup(m *Manifest, compose []byte, routes *Routes) error {
	services := map[string]bool{}
	for _, s := range Services(compose) {
		services[s] = true
	}
	listed := map[string]bool{}
	for _, j := range m.Jobs {
		switch {
		case !services[j]:
			return fmt.Errorf("jobs: %s is not a compose service", j)
		case listed[j]:
			return fmt.Errorf("jobs: %s is listed twice", j)
		case routes != nil && len(routes.Routers[j]) > 0:
			return fmt.Errorf("jobs: %s has a Traefik router: a one-off job serves nothing", j)
		}
		listed[j] = true
	}
	profiled, err := ServiceProfiles(compose)
	if err != nil {
		return err
	}
	known := map[string]bool{}
	for _, ps := range profiled {
		for _, p := range ps {
			known[p] = true
		}
	}
	started := map[string]bool{}
	if m.Settings != nil {
		for i := range m.Settings.Options {
			o := &m.Settings.Options[i]
			if err := setupOption(o, known, started); err != nil {
				return fmt.Errorf("setting %s: %w", o.Key, err)
			}
		}
	}
	names := make([]string, 0, len(profiled))
	for s := range profiled {
		names = append(names, s)
	}
	sort.Strings(names)
	for _, s := range names {
		ok := false
		for _, p := range profiled[s] {
			ok = ok || started[p]
		}
		if !ok {
			return fmt.Errorf("service %s: no setup option's profiles start it (its profiles %s)", s, strings.Join(profiled[s], ", "))
		}
	}
	return nil
}

// setupOption checks one option's setup, fixed_after_start and profiles;
// known are the profiles compose services list, started collects the
// ones the option's mapping starts.
func setupOption(o *Option, known, started map[string]bool) error {
	instance := o.EffectiveScope() == ScopeInstance
	if o.Setup && (!instance || o.Type == TypeSecret) {
		return fmt.Errorf("setup needs scope instance and a type other than secret")
	}
	if o.FixedAfterStart && !o.Setup {
		return fmt.Errorf("fixed_after_start needs setup: true")
	}
	if o.Profiles == nil {
		return nil
	}
	if !o.Setup || o.Type != TypeEnum || !instance {
		return fmt.Errorf("profiles is for setup enum options of scope instance")
	}
	if o.Default == nil {
		return fmt.Errorf("profiles needs a default")
	}
	values := map[string]bool{}
	for _, c := range o.Choices {
		values[c.Value] = true
	}
	keys := make([]string, 0, len(o.Profiles))
	for k := range o.Profiles {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !values[k] {
			return fmt.Errorf("profiles: %s is not one of the option's values", k)
		}
	}
	for _, c := range o.Choices {
		if _, ok := o.Profiles[c.Value]; !ok {
			return fmt.Errorf("profiles: value %s has no entry (write %s: [] when it starts no profile)", c.Value, c.Value)
		}
	}
	for _, k := range keys {
		for _, p := range o.Profiles[k] {
			if !ProfileRe.MatchString(p) || !known[p] {
				return fmt.Errorf("profiles.%s: profile %s is on no compose service", k, p)
			}
			started[p] = true
		}
	}
	return nil
}
