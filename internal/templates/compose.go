package templates

import (
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

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
