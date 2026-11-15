package templates

import (
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Placement (contract §3 "Worker-placeable templates", §17): what keeps
// a template on the primary. It is a server property, not a runtime one,
// so it stays out of RuntimeCompat (same compose parse). The reason
// strings are shared byte for byte with the templates validator
// (testdata/placement_vectors.json; portcullis-templates
// tests/placement_vectors.json is a byte copy).

// Manifest placement values ("" = PlacementAny).
const (
	PlacementAny         = "any"
	PlacementPrimaryOnly = "primary_only"
)

// placementReasons collects reasons per rule, each once; rules are
// reported in the order of the contract's list.
type placementReasons struct {
	coreVolume, router, scheme, hostGateway, bind []string
}

// Placement reports whether compose + manifest m (with the instance's
// effective values env; nil = the defaults) must stay on the primary for
// a server whose folder roots are bindRoots, and why. Rules, in this
// order (contract §3 "Worker-placeable templates") (services in compose order within each):
//   - mounts the core volume <v>: a core volume, the Hub's secrets volume
//     or link_doc, by key, name or external name;
//   - has a Traefik TCP/UDP router (<name>): a traefik.tcp.* /
//     traefik.udp.* label (its router or service name);
//   - has a per-person secret option (<key>);
//   - has AI companions (mcp-gate reaches them on the primary): ai.mcp;
//   - is an AI page (model-provider secrets stay on the primary): ai.chat;
//   - is a VPN provider (vpn: block);
//   - uses host-gateway (<service>);
//   - binds <path> outside the server's folder roots: an absolute (or
//     ~) bind source outside every root, or a relative one other than
//     ./templates/… and ./certs/ca-bundle.crt (resolved, cleaned);
//   - uses a non-HTTP backend scheme (<label>): a
//     loadbalancer.server.scheme other than http (a relay carries HTTP
//     only; pre-flight P15);
//   - is marked placement: primary_only.
//
// An unreadable compose file is primary-only ("compose.yml can't be
// read"): fail closed. reasons is never nil.
func Placement(compose []byte, m Manifest, env map[string]string, bindRoots []string) (primaryOnly bool, reasons []string) {
	reasons = []string{}
	services, err := orderedServices(compose)
	var doc struct {
		Volumes map[string]any `yaml:"volumes"`
	}
	if err == nil {
		err = yaml.Unmarshal(compose, &doc)
	}
	if err != nil {
		return true, []string{"compose.yml can't be read"}
	}
	var r placementReasons
	// Top-level volumes: key → the core volume it is (by key or name).
	coreOf := map[string]string{}
	for k, raw := range doc.Volumes {
		if c := CoreVolumeName(k); c != "" {
			coreOf[k] = c
		}
		v, _ := raw.(map[string]any)
		names := []any{v["name"]}
		if ext, ok := v["external"].(map[string]any); ok {
			names = append(names, ext["name"])
		}
		for _, n := range names {
			if s, ok := n.(string); ok {
				if c := CoreVolumeName(resolve(s, env)); c != "" {
					coreOf[k] = c
				}
			}
		}
	}
	for _, s := range services {
		var svc map[string]any
		if err := s.node.Decode(&svc); err != nil {
			return true, []string{"compose.yml can't be read"}
		}
		r.service(s.name, svc, coreOf, env, bindRoots)
	}
	// Declared but unmounted core volumes count too.
	for _, k := range sortedKeysOf(coreOf) {
		addOnce(&r.coreVolume, "mounts the core volume "+coreOf[k])
	}
	out := r.coreVolume
	out = append(out, r.router...)
	if m.Settings != nil {
		for _, o := range m.Settings.Options {
			if o.Type == TypePersonSecret {
				addOnce(&out, "has a per-person secret option ("+o.Key+")")
			}
		}
	}
	if m.AI != nil && len(m.AI.MCP) > 0 {
		out = append(out, "has AI companions (mcp-gate reaches them on the primary)")
	}
	if m.AI != nil && m.AI.Chat != nil {
		out = append(out, "is an AI page (model-provider secrets stay on the primary)")
	}
	if m.VPN != nil {
		out = append(out, "is a VPN provider (vpn: block)")
	}
	out = append(out, r.hostGateway...)
	out = append(out, r.bind...)
	out = append(out, r.scheme...)
	if m.Placement == PlacementPrimaryOnly {
		out = append(out, "is marked placement: primary_only")
	}
	reasons = append(reasons, out...)
	return len(reasons) > 0, reasons
}

// CoreVolumeName is the core volume name n stands for ("" = none): a core
// volume key (portcullis_<key> too), link_doc, or the Hub's secrets
// volume key.
func CoreVolumeName(n string) string {
	f := FoldKey(strings.TrimSpace(n))
	if NamesSecretsVolumeKey(f) {
		return SecretsVolumeKey
	}
	if coreVolumes[f] {
		return f
	}
	if k, ok := strings.CutPrefix(f, "portcullis_"); ok && coreVolumes[k] {
		return k
	}
	return ""
}

func sortedKeysOf[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (r *placementReasons) service(name string, s map[string]any, coreOf map[string]string, env map[string]string, roots []string) {
	vols, _ := s["volumes"].([]any)
	for _, item := range vols {
		var src, typ string
		switch v := item.(type) {
		case string:
			parts := splitOutsideVars(v)
			if len(parts) < 2 {
				continue // an anonymous volume
			}
			src = resolve(parts[0], env)
			if isPathSource(src) {
				typ = "bind"
			} else {
				typ = "volume"
			}
		case map[string]any:
			typ, _ = v["type"].(string)
			src, _ = v["source"].(string)
			src = resolve(src, env)
		}
		switch typ {
		case "volume":
			if c, ok := coreOf[src]; ok {
				addOnce(&r.coreVolume, "mounts the core volume "+c)
			} else if c := CoreVolumeName(src); c != "" {
				addOnce(&r.coreVolume, "mounts the core volume "+c)
			}
		case "bind":
			if shown, outside := bindOutside(src, roots); outside {
				addOnce(&r.bind, "binds "+shown+" outside the server's folder roots")
			}
		}
	}
	labels, _ := labelPairs(name, s["labels"])
	for _, k := range sortedKeysOf(labels) {
		parts := strings.Split(FoldKey(k), ".")
		if len(parts) >= 4 && parts[0] == "traefik" && (parts[1] == "tcp" || parts[1] == "udp") {
			addOnce(&r.router, "has a Traefik TCP/UDP router ("+parts[3]+")")
		}
		if len(parts) == 7 && parts[0] == "traefik" && parts[1] == "http" && parts[2] == "services" &&
			parts[4] == "loadbalancer" && parts[5] == "server" && parts[6] == "scheme" {
			if !strings.EqualFold(strings.TrimSpace(resolve(labels[k], env)), "http") {
				addOnce(&r.scheme, "uses a non-HTTP backend scheme ("+k+")")
			}
		}
	}
	var hosts []string
	switch eh := s["extra_hosts"].(type) {
	case []any:
		for _, x := range eh {
			if v, ok := x.(string); ok {
				hosts = append(hosts, v)
			}
		}
	case map[string]any:
		for _, k := range sortedKeysOf(eh) {
			hosts = append(hosts, k+"="+strings.TrimSpace(toString(eh[k])))
		}
	}
	for _, h := range hosts {
		h = resolve(h, env)
		if strings.HasSuffix(h, ":host-gateway") || strings.HasSuffix(h, "=host-gateway") {
			addOnce(&r.hostGateway, "uses host-gateway ("+name+")")
		}
	}
}

func toString(v any) string {
	s, _ := v.(string)
	return s
}

// CABundlePath is the core checkout's CA bundle (relative to the project
// directory), which templates bind read-only and a worker bundle carries.
const CABundlePath = "certs/ca-bundle.crt"

// isPathSource: compose reads a short-syntax source as a host path when
// it starts with ".", "/" or "~" (else it is a volume name).
func isPathSource(s string) bool {
	return strings.HasPrefix(s, "/") || strings.HasPrefix(s, ".") || strings.HasPrefix(s, "~")
}

// bindOutside reports whether bind source src (resolved) lies outside
// every root (absolute) or outside ./templates/ (relative; ~ always),
// and the path as a reason shows it.
func bindOutside(src string, roots []string) (string, bool) {
	switch {
	case src == "":
		return "", false // compose itself refuses an empty source
	case strings.HasPrefix(src, "~"):
		return src, true
	case strings.HasPrefix(src, "/"):
		p := path.Clean(src)
		for _, r := range roots {
			if r != "" && pathUnderRoot(p, path.Clean(r)) {
				return p, false
			}
		}
		return p, true
	}
	p := path.Clean(src)
	if strings.HasPrefix(p, "templates/") || p == CABundlePath {
		return "./" + p, false
	}
	return "./" + p, true
}

// pathUnderRoot: clean absolute p is root or inside it (root "/" never
// counts: it would admit the whole host).
func pathUnderRoot(p, root string) bool {
	if root == "/" || !strings.HasPrefix(root, "/") {
		return false
	}
	return p == root || strings.HasPrefix(p, root+"/")
}
