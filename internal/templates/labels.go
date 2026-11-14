package templates

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
	"maps"
	"slices"
)

// ServiceLabels returns each compose service's labels (map or list
// syntax), as compose reads them before interpolation.
func ServiceLabels(compose []byte) (map[string]map[string]string, error) {
	var doc struct {
		Services map[string]struct {
			Labels interface{} `yaml:"labels"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(compose, &doc); err != nil {
		return nil, fmt.Errorf("compose.yml: %w", err)
	}
	out := map[string]map[string]string{}
	for svc, s := range doc.Services {
		l, err := labelMap(s.Labels)
		if err != nil {
			return nil, fmt.Errorf("service %s: %w", svc, err)
		}
		if len(l) > 0 {
			out[svc] = l
		}
	}
	return out, nil
}

var traefikKeyRe = regexp.MustCompile(`^(traefik\.(?:http|tcp|udp)\.(?:routers|services|middlewares)\.)([^.]+)(\..+)$`)

// InstanceName is a template-defined Traefik name as instance id uses it
// (contract §3.1): "<id>_<name>".
func InstanceName(id, name string) string { return id + "_" + name }

// RenameLabels returns labels with every router, service and middleware
// the template defines (names) renamed to InstanceName(id, name), in keys
// and in the references to them: routers' service and middlewares values
// and chain middlewares (name or name@docker). Names the template doesn't
// define (portcullis-auth@docker, security-headers@file, …) are kept.
// Keys and references are matched folded (FoldKey), as Traefik's decoder
// and the validator (checkCoreReferences) read them; renamed references
// are written lowercase.
func RenameLabels(labels map[string]string, names map[string]bool, id string) map[string]string {
	ref := func(v string) string {
		v = strings.TrimSpace(v)
		base, prov, hasProv := strings.Cut(FoldKey(v), "@")
		if !names[base] || (hasProv && prov != "docker") {
			return v
		}
		if hasProv {
			return InstanceName(id, base) + "@docker"
		}
		return InstanceName(id, base)
	}
	out := make(map[string]string, len(labels))
	for k, v := range labels {
		fk := FoldKey(k)
		m := traefikKeyRe.FindStringSubmatch(fk)
		if m == nil {
			out[k] = v
			continue
		}
		kind := strings.TrimSuffix(strings.TrimPrefix(m[1][len("traefik."):], "http."), ".")
		if names[m[2]] {
			// The rest of the key keeps its case (header names); a key
			// whose folded form differs in length (non-ASCII, refused by
			// the validator) is written folded.
			rest := m[3]
			if len(fk) == len(k) {
				rest = k[len(fk)-len(m[3]):]
			}
			k = m[1] + InstanceName(id, m[2]) + rest
		}
		switch {
		case kind == "routers" && m[3] == ".service":
			v = ref(v)
		case kind == "routers" && m[3] == ".middlewares", kind == "middlewares" && strings.HasSuffix(m[3], ".chain.middlewares"):
			parts := strings.Split(v, ",")
			for i, p := range parts {
				parts[i] = ref(p)
			}
			v = strings.Join(parts, ",")
		}
		out[k] = v
	}
	return out
}

// TraefikEnable reads a service's traefik.enable label (key folded, as
// Traefik's label decoder matches it). Traefik turns a container on for any
// value strconv.ParseBool accepts ("1", "t", "TRUE", …); the Hub accepts
// only exactly true or false (a YAML bool decodes to those), and one such
// key, so every reader agrees with Traefik. Every read of traefik.enable
// goes through here.
func TraefikEnable(labels map[string]string) (bool, error) {
	key, on := "", false
	for k, v := range labels {
		if FoldKey(k) != "traefik.enable" {
			continue
		}
		if key != "" {
			a, b := key, k
			if b < a {
				a, b = b, a
			}
			return false, fmt.Errorf("traefik.enable is set twice (%q and %q)", a, b)
		}
		key = k
		switch v {
		case "true":
			on = true
		case "false":
		default:
			return false, fmt.Errorf("traefik.enable is %q: write true or false (Traefik also reads 1, t, TRUE, … as on; the Hub accepts only these two)", v)
		}
	}
	return on, nil
}

// FirstEnabledService is the first compose service, in compose.yml order,
// whose labels set traefik.enable to true (TraefikEnable; "" = none). The Hub puts its
// extra-domain sign-in routers there (contract §5).
func FirstEnabledService(compose []byte) (string, error) {
	labels, err := ServiceLabels(compose)
	if err != nil {
		return "", err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(compose, &root); err != nil {
		return "", fmt.Errorf("compose.yml: %w", err)
	}
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return "", nil
	}
	doc := root.Content[0]
	for i := 0; i+1 < len(doc.Content); i += 2 {
		if doc.Content[i].Value != "services" || doc.Content[i+1].Kind != yaml.MappingNode {
			continue
		}
		svcs := doc.Content[i+1]
		for j := 0; j+1 < len(svcs.Content); j += 2 {
			name := svcs.Content[j].Value
			on, err := TraefikEnable(labels[name])
			if err != nil {
				return "", fmt.Errorf("service %s: %w", name, err)
			}
			if on {
				return name, nil
			}
		}
	}
	return "", nil
}

// BindSource is a service's absolute bind source, as Compose would
// resolve it (the default of a whole ${VAR:-…} / ${VAR-…} source
// included; an unset variable without a default isn't resolvable here).
type BindSource struct {
	Service, Source string
}

// AbsoluteBindSources lists every service's absolute bind sources (short
// src:dst[:opts] and long {type: bind, source}), sorted by service.
func AbsoluteBindSources(compose []byte) []BindSource {
	infos := composeServiceInfos(compose)
	var out []BindSource
	for _, n := range slices.Sorted(maps.Keys(infos)) {
		l, _ := infos[n].volumes.([]interface{})
		for _, x := range l {
			var src string
			switch e := x.(type) {
			case string:
				parts := splitOutsideVars(strings.TrimSpace(e))
				if len(parts) < 2 {
					continue
				}
				src = parts[0]
			case map[string]interface{}:
				if typ, _ := e["type"].(string); typ != "bind" {
					continue
				}
				src, _ = e["source"].(string)
			}
			src = varDefault(strings.TrimSpace(src))
			if strings.HasPrefix(src, "/") {
				out = append(out, BindSource{n, src})
			}
		}
	}
	return out
}

// varDefault resolves a leading ${VAR:-def} / ${VAR-def} to def (the rest
// of the source kept); anything else is returned as is.
func varDefault(s string) string {
	if !strings.HasPrefix(s, "${") {
		return s
	}
	end := strings.Index(s, "}")
	if end < 0 {
		return s
	}
	inner := s[2:end]
	for _, sep := range []string{":-", "-"} {
		if i := strings.Index(inner, sep); i >= 0 {
			return inner[i+len(sep):] + s[end+1:]
		}
	}
	return s
}
