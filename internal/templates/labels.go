package templates

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
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
