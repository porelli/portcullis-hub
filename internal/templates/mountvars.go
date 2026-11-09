package templates

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// ComposeMountVars are the variables compose.yml reads where they choose
// what an app mounts or shares (contract §11.9, apps Task 5 fix round
// 1): any reference in a service's volumes (short syntax: the whole
// entry; long syntax: source), env_file, build (context, dockerfile),
// network_mode, pid or ipc, and in a top-level volume's driver_opts. An
// env override of one of them is refused. Never nil.
func ComposeMountVars(compose []byte) (map[string]bool, error) {
	var doc struct {
		Services map[string]any `yaml:"services"`
		Volumes  map[string]any `yaml:"volumes"`
	}
	if err := yaml.Unmarshal(compose, &doc); err != nil {
		return nil, fmt.Errorf("compose.yml: %v", err)
	}
	out := map[string]bool{}
	add := func(v any) {
		for _, s := range scalarStrings(v) {
			for _, n := range RefNames(s) {
				out[n] = true
			}
		}
	}
	for _, raw := range doc.Services {
		s, _ := raw.(map[string]any)
		if s == nil {
			continue
		}
		if vols, ok := s["volumes"].([]any); ok {
			for _, v := range vols {
				switch e := v.(type) {
				case map[string]any:
					add(e["source"])
				default:
					add(e)
				}
			}
		}
		switch e := s["env_file"].(type) {
		case []any:
			for _, x := range e {
				if m, ok := x.(map[string]any); ok {
					add(m["path"])
				} else {
					add(x)
				}
			}
		default:
			add(e)
		}
		switch b := s["build"].(type) {
		case map[string]any:
			add(b["context"])
			add(b["dockerfile"])
		default:
			add(b)
		}
		for _, k := range []string{"network_mode", "pid", "ipc"} {
			add(s[k])
		}
	}
	for _, raw := range doc.Volumes {
		if v, ok := raw.(map[string]any); ok {
			add(v["driver_opts"])
		}
	}
	return out, nil
}

// scalarStrings are every string scalar in v (maps and lists walked).
func scalarStrings(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, e := range x {
			out = append(out, scalarStrings(e)...)
		}
		return out
	case map[string]any:
		var out []string
		for _, e := range x {
			out = append(out, scalarStrings(e)...)
		}
		return out
	}
	return nil
}

// RefNames are the variables s references as compose interpolates it:
// $NAME, ${NAME} and ${NAME<op>…} (nested references in a default
// included); $$ is an escaped $.
func RefNames(s string) []string {
	var out []string
	isStart := func(c byte) bool { return c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' }
	isName := func(c byte) bool { return isStart(c) || c >= '0' && c <= '9' }
	for i := 0; i+1 < len(s); i++ {
		if s[i] != '$' {
			continue
		}
		switch c := s[i+1]; {
		case c == '$':
			i++
		case c == '{':
			j := i + 2
			for j < len(s) && isName(s[j]) {
				j++
			}
			if j > i+2 && isStart(s[i+2]) {
				out = append(out, s[i+2:j])
			}
			i = j - 1
		case isStart(c):
			j := i + 1
			for j < len(s) && isName(s[j]) {
				j++
			}
			out = append(out, s[i+1:j])
			i = j - 1
		}
	}
	return out
}
