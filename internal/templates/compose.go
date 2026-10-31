package templates

import (
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// hostRuleRe matches the subdomain routed by a template:
// Host(`<sub>.${PORTCULLIS_DOMAIN...}`).
var hostRuleRe = regexp.MustCompile("Host\\(`([A-Za-z0-9-]+)\\.\\$\\{PORTCULLIS_DOMAIN")

// Subdomains returns the sorted, de-duplicated lowercase subdomains routed
// via Traefik Host() rules in a compose file.
func Subdomains(compose []byte) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range hostRuleRe.FindAllStringSubmatch(string(compose), -1) {
		sub := strings.ToLower(m[1])
		if !seen[sub] {
			seen[sub] = true
			out = append(out, sub)
		}
	}
	sort.Strings(out)
	return out
}

// Services returns the sorted service names of a compose file.
func Services(compose []byte) []string {
	var doc struct {
		Services map[string]interface{} `yaml:"services"`
	}
	if yaml.Unmarshal(compose, &doc) != nil {
		return nil
	}
	names := make([]string, 0, len(doc.Services))
	for name := range doc.Services {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// RoutersByService returns, for each service, the Traefik router names
// declared under its labels. Handles the common 2-space-per-level
// indentation used throughout the templates.
func RoutersByService(compose []byte) map[string][]string {
	out := map[string][]string{}
	seen := map[string]map[string]bool{}
	var currentService string

	for _, line := range strings.Split(string(compose), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Service header: two-space indent, ends with ":" and no further nesting.
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "   ") && strings.HasSuffix(trimmed, ":") {
			name := strings.TrimSuffix(trimmed, ":")
			if !strings.ContainsAny(name, " \t") {
				currentService = name
				if _, ok := out[name]; !ok {
					seen[name] = map[string]bool{}
				}
				continue
			}
		}
		if currentService == "" {
			continue
		}
		idx := strings.Index(line, "traefik.http.routers.")
		if idx < 0 {
			continue
		}
		rest := line[idx+len("traefik.http.routers."):]
		dot := strings.Index(rest, ".")
		if dot <= 0 {
			continue
		}
		router := rest[:dot]
		if router == "" || seen[currentService][router] {
			continue
		}
		seen[currentService][router] = true
		out[currentService] = append(out[currentService], router)
	}
	// Top-level keys like "volumes:" match the service-header heuristic; drop
	// any that didn't accumulate router labels.
	for svc, routers := range out {
		if len(routers) == 0 {
			delete(out, svc)
		}
	}
	return out
}

// EnvRefs finds all ${VAR} and ${VAR:-default} references in s.
func EnvRefs(s string) map[string]bool {
	refs := make(map[string]bool)
	for i := 0; i < len(s)-1; i++ {
		if s[i] == '$' && s[i+1] == '{' {
			end := strings.IndexByte(s[i:], '}')
			if end < 0 {
				continue
			}
			varExpr := s[i+2 : i+end]
			if idx := strings.Index(varExpr, ":-"); idx >= 0 {
				varExpr = varExpr[:idx]
			}
			refs[varExpr] = true
		}
	}
	return refs
}
