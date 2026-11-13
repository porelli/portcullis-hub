package templates

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// Core-owned names a template may not use (contract §3, §5, §12): the
// extra-domain sign-in plumbing the Hub renders itself, core's networks,
// volumes and DNS names (service names, container names), and core's
// Traefik objects.
//
// The checks run on the DECODED document (yaml.v3 resolves anchors,
// aliases, merge keys, quoting and escapes), and every value that decides
// network membership or a DNS name must be a literal: compose
// interpolates `${…}` / `$VAR` after the Hub's checks, so such values are
// refused outright. compose `include` and service `extends` pull in files
// the Hub can't see and are refused too.

// proxyNetwork is the only network a template shares with core (an
// external placeholder for core's portcullis-proxy).
const proxyNetwork = "portcullis-proxy"

// reservedRefs may not appear in any key or value of a template's compose
// file: the Hub renders portcullis-auth-ext and the
// portcullis-oauth2-<id>_<router> sign-in routers to forward-auth-ext on
// extra-domain hosts itself.
// portcullis-vpn* (the VPN network, the portcullis-vpnallow-<id>
// middlewares and portcullis-vpnonly-<id> routers, contract §3.3) is the
// Hub's too, with no exception (core's forwarder image is
// ghcr.io/porelli/portcullis-forwarder, which doesn't match).
var reservedRefs = []string{"forward-auth-ext", "portcullis-auth-ext", "portcullis-oauth2-", MCPNamePrefix, VPNReservedPrefix}

// coreServices are the services of core's docker-compose.yml (all
// profiles), coreVolumes its volume keys (Docker names
// portcullis_<key>): both checked against a sibling core checkout by
// TestCoreNamesComplete.
var (
	coreServices = set("socket-proxy-traefik", "socket-proxy-hub", "traefik", "postgres", "vault", "lldap", "keycloak",
		"forward-auth", "forward-auth-ext", "group-gate", "hub", "enroll", "domains", "dns-tool", "prometheus", "alertmanager", "blackbox",
		"textfile-exporter", "grafana", "mcp-gate", "sessions", "wg")
	coreVolumes = set("postgres_data", "vault_data", "lldap_data", "hub_data", "traefik_acme", "domains_data",
		"prometheus_data", "alertmanager_data", "grafana_data", "hub_secrets", "mcp_gate_data",
		"group_gate_data", "wg_data", "vpn_doc")
	// coreAliases are core's network aliases that aren't service names
	// (wg's metrics address on portcullis): reserved DNS names too.
	coreAliases = set("wg-metrics")
	// coreContainerRe: compose's container names for core's services.
	coreContainerRe = regexp.MustCompile(`^portcullis[-_](.+)[-_][0-9]+$`)
)

// reservedDNSName: a container answering to name (service name,
// container_name, hostname, network alias) on a network it shares with a
// core service could intercept that service's traffic — every core
// service name (and its first DNS label, and compose's
// portcullis-<service>-<n> container name) is reserved.
func reservedDNSName(name string) bool {
	n := strings.TrimSuffix(FoldKey(strings.TrimSpace(name)), ".")
	first, _, _ := strings.Cut(n, ".")
	for _, c := range []string{n, first} {
		if coreServices[c] || coreAliases[c] {
			return true
		}
		if m := coreContainerRe.FindStringSubmatch(c); m != nil && coreServices[m[1]] {
			return true
		}
	}
	return false
}

// CoreContainerClash returns the container name compose would give
// service svc of project portcullis-<id> (portcullis-<id>-<svc>-<n>, or
// portcullis_<id>_<svc>_<n> with the old separator) when it is a core
// service's (portcullis-<core service>-<n>: id "forward" + service "auth"
// is forward-auth), else "". Instance ids and service names that do this
// are refused (Discover for the default instance, CreateInstance).
func CoreContainerClash(id string, services []string) string {
	for _, svc := range services {
		for _, sep := range []string{"-", "_"} {
			if coreServices[FoldKey(id+sep+svc)] {
				return "portcullis" + sep + id + sep + svc + sep + "1"
			}
		}
	}
	return ""
}

// SingleDocument refuses YAML with more than one document (empty ones
// included): compose merges every document of a file, while yaml.Unmarshal
// (and so every check here) reads only the first.
func SingleDocument(b []byte, what string) error {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	n := 0
	for {
		var node yaml.Node
		err := dec.Decode(&node)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("%s: %w", what, err)
		}
		// Any second document — even an empty one — is refused: parsers
		// differ on which document they read.
		if n++; n > 1 {
			return fmt.Errorf("%s holds more than one YAML document (compose would merge them; the Hub checks one)", what)
		}
	}
	return nil
}

// interpRe matches compose interpolations (after "$$" is removed).
var interpRe = regexp.MustCompile(`\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|\$`)

// withoutInterp removes every interpolation from s: what remains is what
// compose keeps literally, so a reserved name split by a variable
// (portcullis-auth${U}-ext) is still found.
func withoutInterp(s string) string {
	return interpRe.ReplaceAllString(strings.ReplaceAll(s, "$$", ""), "")
}

// interpolated: s would be changed by compose's variable interpolation
// (anything but `$$`, the literal dollar).
func interpolated(s string) bool {
	return strings.Contains(strings.ReplaceAll(s, "$$", ""), "$")
}

// literal refuses an interpolated value of what (a name that decides
// network membership or a DNS name).
func literal(what, v string) error {
	if interpolated(v) {
		return fmt.Errorf("%s %q uses variable interpolation: it must be a literal", what, v)
	}
	return nil
}

// walkStrings calls f on every string key and scalar value of v.
func walkStrings(v interface{}, f func(string) error) error {
	switch t := v.(type) {
	case string:
		return f(t)
	case map[string]interface{}:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if err := f(k); err != nil {
				return err
			}
			if err := walkStrings(t[k], f); err != nil {
				return err
			}
		}
	case map[interface{}]interface{}:
		for k, val := range t {
			if err := walkStrings(fmt.Sprint(k), f); err != nil {
				return err
			}
			if err := walkStrings(val, f); err != nil {
				return err
			}
		}
	case []interface{}:
		for _, x := range t {
			if err := walkStrings(x, f); err != nil {
				return err
			}
		}
	}
	return nil
}

func str(v interface{}) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

// asMap: v must be absent (nil) or a mapping with string keys; anything
// else (a list, a scalar, non-string keys) is refused — fail closed on
// shapes the checks below would otherwise skip.
func asMap(v interface{}, what string) (map[string]interface{}, error) {
	switch t := v.(type) {
	case nil:
		return nil, nil
	case map[string]interface{}:
		return t, nil
	}
	return nil, fmt.Errorf("%s must be a mapping with string keys", what)
}

// hostVarHostname: the one interpolated hostname allowed — exactly the
// contract v2 Host() argument `${PORTCULLIS_HOST_<ROUTER>:-<sub>.portcullis.local}`
// (routes.go hostVarArgRe) for a hostname variable of this template's own
// host routers (the Hub always sets it to a validated full hostname).
func hostVarHostname(v string, hostVars map[string]string) error {
	m := hostVarArgRe.FindStringSubmatch(v)
	if m == nil {
		return fmt.Errorf("hostname %q uses variable interpolation: it must be a literal or exactly ${PORTCULLIS_HOST_<ROUTER>:-<sub>.portcullis.local}", v)
	}
	own := false
	for _, hv := range hostVars {
		own = own || hv == m[1]
	}
	if !own {
		return fmt.Errorf("hostname %q: %s is not a hostname variable of this template's host routers", v, m[1])
	}
	if def := m[2] + ".portcullis.local"; reservedDNSName(m[2]) {
		return fmt.Errorf("hostname %q: the default %s is reserved", v, def)
	}
	return nil
}

// checkCoreRefs rejects a compose file that references the reserved
// sign-in names, names or externalises any network but the portcullis-proxy
// placeholder (core's, another instance's or a foreign one), sets a
// network_mode other than none / host / service:<own service>, answers to a reserved DNS name (service
// name, container_name, hostname, network alias) or to a gate upstream
// name (-internal) off the default network, uses a core volume, uses
// interpolation in any of those, or uses `include` / `extends`; plus the
// label checks (checkServiceLabels).
func checkCoreRefs(compose []byte, hostVars map[string]string) error {
	var node yaml.Node
	if err := yaml.Unmarshal(compose, &node); err != nil {
		return fmt.Errorf("compose.yml: %w", err)
	}
	if err := CheckTags(&node); err != nil {
		return fmt.Errorf("compose.yml: %w", err)
	}
	var raw interface{}
	if err := yaml.Unmarshal(compose, &raw); err != nil {
		return fmt.Errorf("compose.yml: %w", err)
	}
	doc, err := asMap(raw, "compose.yml")
	if err != nil {
		return err
	}
	if err := checkComposeKeys(doc); err != nil {
		return err
	}
	if _, ok := doc["include"]; ok {
		return fmt.Errorf("compose.yml: top-level include is not allowed (it pulls in files the Hub can't check)")
	}
	if err := walkStrings(doc, func(s string) error {
		low, bare := FoldKey(s), FoldKey(withoutInterp(s))
		for _, r := range reservedRefs {
			if strings.Contains(low, r) || strings.Contains(bare, r) {
				if r == VPNReservedPrefix {
					return fmt.Errorf("compose.yml references %q: names starting %s (the VPN network, middlewares and routers) are rendered by the Hub only (contract §3.3)", VPNReservedPrefix, VPNReservedPrefix)
				}
				if r == MCPNamePrefix {
					return fmt.Errorf("compose.yml references %q: names starting %s (routers, services, middlewares, aliases, container names, hostnames) are the Hub's AI companion routes and aliases (contract §3.2)", MCPNamePrefix, MCPNamePrefix)
				}
				return fmt.Errorf("compose.yml references %q: the extra-domain sign-in (forward-auth-ext, portcullis-auth-ext, portcullis-oauth2-*) is rendered by the Hub only", strings.TrimSuffix(r, "-"))
			}
		}
		return nil
	}); err != nil {
		return err
	}

	nets, err := asMap(doc["networks"], "top-level networks")
	if err != nil {
		return err
	}
	keys := make([]string, 0, len(nets))
	for k := range nets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	// Every top-level network is the project's own (compose scopes it to
	// portcullis-<instance>_<key>) except the portcullis-proxy placeholder:
	// name: / external: anywhere else would join a core network, another
	// instance's <project>_default (its ungated backends) or any foreign
	// network by name. shared: the networks shared with core.
	shared := map[string]bool{}
	for _, k := range keys {
		n, err := asMap(nets[k], "network "+k)
		if err != nil {
			return err
		}
		_, hasName := n["name"]
		_, hasExt := n["external"]
		if !hasName && !hasExt {
			continue
		}
		if k != proxyNetwork {
			return fmt.Errorf("network %s: name and external are allowed only on the %s placeholder (external: true) — every other network, default included, stays the project's own", k, proxyNetwork)
		}
		if ext, ok := n["external"].(bool); !ok || !ext {
			return fmt.Errorf("network %s: must be external: true (core creates it; templates only attach)", k)
		}
		if hasName {
			if nm, ok := n["name"].(string); !ok || nm != proxyNetwork {
				return fmt.Errorf("network %s: name must be %s or absent, not %v", k, proxyNetwork, n["name"])
			}
		}
		shared[k] = true
	}
	// internalNets: project networks declared exactly {internal: true}:
	// like default, only the template's own services can be on them, so
	// -internal names may live there too.
	internalNets := map[string]bool{}
	for _, k := range keys {
		n, _ := nets[k].(map[string]interface{})
		_, hasName := n["name"]
		_, hasExt := n["external"]
		if in, ok := n["internal"].(bool); ok && in && !hasName && !hasExt && len(n) == 1 {
			internalNets[k] = true
		}
	}

	if err := checkCoreVolumes(doc["volumes"]); err != nil {
		return err
	}

	svcs, err := asMap(doc["services"], "services")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(svcs))
	for s := range svcs {
		names = append(names, s)
	}
	sort.Strings(names)
	pairs := map[string]map[string]string{}
	for _, name := range names {
		s, err := asMap(svcs[name], "service "+name)
		if err != nil {
			return err
		}
		if pairs[name], err = labelPairs(name, s["labels"]); err != nil {
			return err
		}
	}
	own := collectOwnNames(pairs)
	for _, name := range names {
		s, _ := asMap(svcs[name], "service "+name)
		if _, ok := s["extends"]; ok {
			return fmt.Errorf("service %s: extends is not allowed (it pulls in configuration the Hub can't check)", name)
		}
		if err := checkServiceLabels(name, pairs[name], hostVars, own); err != nil {
			return err
		}
		for _, field := range []string{"pid", "ipc"} {
			if v, present := s[field]; present && v != nil {
				sv, ok := str(v)
				if !ok {
					return fmt.Errorf("service %s: %s must be a string", name, field)
				}
				if err := literal("service "+name+": "+field, sv); err != nil {
					return err
				}
				if strings.HasPrefix(strings.ToLower(strings.TrimSpace(sv)), "container:") {
					return fmt.Errorf("service %s: %s %s joins another container's namespace", name, field, sv)
				}
			}
		}
		if err := checkSecretsVolumeRefs(name, s["volumes"]); err != nil {
			return err
		}
		switch vf := s["volumes_from"].(type) {
		case nil:
		case []interface{}:
			for _, x := range vf {
				sv, ok := str(x)
				if !ok {
					return fmt.Errorf("service %s: volumes_from entries must be strings", name)
				}
				if NamesSecretsVolumeKey(sv) {
					return fmt.Errorf("service %s: volumes_from %s names the Hub's secrets volume", name, sv)
				}
				if err := literal("service "+name+": volumes_from", sv); err != nil {
					return err
				}
				if strings.HasPrefix(strings.ToLower(strings.TrimSpace(sv)), "container:") {
					return fmt.Errorf("service %s: volumes_from %s mounts another container's volumes", name, sv)
				}
			}
		default:
			return fmt.Errorf("service %s: volumes_from must be a list", name)
		}
		if reservedDNSName(name) {
			return fmt.Errorf("service %s: the DNS name %q is core's (reserved)", name, name)
		}
		for _, field := range []string{"container_name", "hostname", "network_mode"} {
			raw, present := s[field]
			if !present || raw == nil {
				continue
			}
			v, ok := str(raw)
			if !ok {
				return fmt.Errorf("service %s: %s must be a string", name, field)
			}
			// hostname may be exactly one Hub-set hostname variable (e.g.
			// GitLab's ${PORTCULLIS_HOST_GITLAB:-git.portcullis.local}): the
			// Hub always sets it to a validated full hostname, never a
			// single label like "domains".
			if field == "hostname" && interpolated(v) {
				if err := hostVarHostname(v, hostVars); err != nil {
					return fmt.Errorf("service %s: %w", name, err)
				}
			} else if err := literal("service "+name+": "+field, v); err != nil {
				return err
			}
			if field == "network_mode" {
				if _, both := s["networks"]; both {
					return fmt.Errorf("service %s: network_mode and networks are mutually exclusive", name)
				}
				if err := checkNetworkMode(name, v, svcs); err != nil {
					return err
				}
				continue
			}
			if reservedDNSName(v) {
				return fmt.Errorf("service %s: %s: the DNS name %q is core's (reserved)", name, field, v)
			}
		}
		if err := checkInternalNames(name, s, internalNets); err != nil {
			return err
		}
		switch sn := s["networks"].(type) {
		case []interface{}:
			for _, x := range sn {
				v, ok := str(x)
				if !ok {
					return fmt.Errorf("service %s: networks entries must be strings", name)
				}
				if err := literal("service "+name+": network", v); err != nil {
					return err
				}
			}
		case map[string]interface{}:
			for net, cfg := range sn {
				if err := literal("service "+name+": network", net); err != nil {
					return err
				}
				c, err := asMap(cfg, "service "+name+": network "+net)
				if err != nil {
					return err
				}
				// No fixed address on a network shared with core (e.g.
				// portcullis-proxy, where header-auth apps trust Traefik's IP).
				if shared[net] {
					for _, f := range []string{"ipv4_address", "ipv6_address", "link_local_ips"} {
						if _, ok := c[f]; ok {
							return fmt.Errorf("service %s: network %s: %s is not allowed on a network shared with core", name, net, f)
						}
					}
				}
				switch al := c["aliases"].(type) {
				case nil:
				case []interface{}:
					for _, x := range al {
						a, ok := str(x)
						if !ok {
							return fmt.Errorf("service %s: network %s: aliases must be strings", name, net)
						}
						if err := literal("service "+name+": network "+net+": alias", a); err != nil {
							return err
						}
						if reservedDNSName(a) {
							return fmt.Errorf("service %s: network alias %q is core's DNS name (reserved)", name, a)
						}
					}
				default:
					return fmt.Errorf("service %s: network %s: aliases must be a list", name, net)
				}
			}
		case nil:
		default:
			return fmt.Errorf("service %s: networks must be a list or a mapping", name)
		}
	}
	return nil
}

// checkNetworkMode: a template service's network_mode is exactly none,
// host or service:<another service of the same template>. Any other value
// is a network name (compose and Docker match these keywords exactly, so
// "Host" or " none" name a network too): network_mode portcullis would put
// the service on core's internal network unchecked. container: (another
// container's namespace) is refused under any spelling.
func checkNetworkMode(svc, v string, svcs map[string]interface{}) error {
	if strings.HasPrefix(FoldKey(strings.TrimSpace(v)), "container:") {
		return fmt.Errorf("service %s: network_mode %q joins another container's network namespace", svc, v)
	}
	if v == "none" || v == "host" {
		return nil
	}
	if target, ok := strings.CutPrefix(v, "service:"); ok && target != svc {
		if _, own := svcs[target]; own {
			return nil
		}
	}
	return fmt.Errorf("service %s: network_mode %q: only none, host or service:<another service of this template> (exactly, lower case) are allowed — any other value joins the network of that name", svc, v)
}

// internalSuffix: names ending in it are gate upstreams (the templates
// repo's validate.py GATED_BACKENDS: the nginx gate proxies to
// <app>-internal by Docker DNS on every network it joins, portcullis-proxy
// included). Such a name is declared on the template's own default network
// only; answering to one anywhere else could catch another app's gated
// traffic.
const internalSuffix = "-internal"

func isInternalName(n string) bool {
	return strings.HasSuffix(strings.TrimSuffix(FoldKey(strings.TrimSpace(n)), "."), internalSuffix)
}

// checkInternalNames refuses a service that answers to a name ending in
// -internal (service name, container_name, hostname — on every network it
// joins — or a network alias) on any network but the project's own
// default (top-level networks.default can't be named or external) and the
// project networks declared internal: true (internal). A
// service with network_mode (none, host, service:) has no DNS name of its
// own. Shapes and literals were checked by the caller.
func checkInternalNames(svc string, s map[string]interface{}, internal map[string]bool) error {
	if mode, _ := s["network_mode"].(string); mode != "" {
		return nil
	}
	common := []string{svc}
	for _, f := range []string{"container_name", "hostname"} {
		if v, ok := str(s[f]); ok {
			common = append(common, v)
		}
	}
	nets := map[string][]string{}
	switch sn := s["networks"].(type) {
	case []interface{}:
		for _, x := range sn {
			if v, ok := str(x); ok {
				nets[v] = nil
			}
		}
	case map[string]interface{}:
		for net, cfg := range sn {
			nets[net] = nil
			c, _ := cfg.(map[string]interface{})
			if al, ok := c["aliases"].([]interface{}); ok {
				for _, x := range al {
					if a, ok := str(x); ok {
						nets[net] = append(nets[net], a)
					}
				}
			}
		}
	}
	keys := make([]string, 0, len(nets))
	for k := range nets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, net := range keys {
		if net == "default" || internal[net] {
			continue
		}
		for _, n := range append(append([]string(nil), common...), nets[net]...) {
			if isInternalName(n) {
				return fmt.Errorf("service %s: the name %q ends in %s but is on network %s (gate upstream names are declared on the project's default network or an internal: true project network only)", svc, n, internalSuffix, net)
			}
		}
	}
	return nil
}

// labelPairs: a service's labels (mapping or KEY=VALUE list) as a map.
func labelPairs(svc string, labels interface{}) (map[string]string, error) {
	pairs := map[string]string{}
	switch l := labels.(type) {
	case nil:
	case map[string]interface{}:
		for k, v := range l {
			switch tv := v.(type) {
			case string:
				pairs[k] = tv
			case nil:
				pairs[k] = ""
			default:
				pairs[k] = fmt.Sprint(tv)
			}
		}
	case []interface{}:
		for _, x := range l {
			sv, ok := str(x)
			if !ok {
				return nil, fmt.Errorf("service %s: labels entries must be strings", svc)
			}
			k, v, _ := strings.Cut(sv, "=")
			pairs[k] = v
		}
	default:
		return nil, fmt.Errorf("service %s: labels must be a list or a mapping", svc)
	}
	return pairs, nil
}

// checkSecretsVolumeRefs: no volume entry of service svc names the Hub's
// secrets volume key (F15), in the short or long syntax, interpolated or
// not: the Hub's override declares that key for its subpath mounts.
func checkSecretsVolumeRefs(svc string, raw interface{}) error {
	list, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	for _, item := range list {
		var src string
		switch v := item.(type) {
		case string:
			src, _, _ = strings.Cut(v, ":")
			if strings.HasPrefix(strings.TrimSpace(v), "${") {
				src = v // a ${X:-…} source may hold colons
			}
		case map[string]interface{}:
			src, _ = str(v["source"])
		}
		if NamesSecretsVolumeKey(src) {
			return fmt.Errorf("service %s: volume %s names the Hub's secrets volume (%s): only the Hub mounts it", svc, src, SecretsVolumeKey)
		}
	}
	return nil
}

// checkCoreVolumes: no volume key of core's (a single template's and a
// multi template's default instance's volumes are portcullis_<key>, core's
// too: postgres_data would mount Keycloak's database), names are
// literals, and no external volume is named portcullis* (core's or another
// instance's data; an external volume without a name is its key).
func checkCoreVolumes(raw interface{}) error {
	vols, err := asMap(raw, "top-level volumes")
	if err != nil {
		return err
	}
	keys := make([]string, 0, len(vols))
	for k := range vols {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if err := literal("volume key", k); err != nil {
			return err
		}
		if NamesSecretsVolumeKey(k) {
			return fmt.Errorf("volume %s is reserved: %s is the Hub's secrets volume", k, SecretsVolumeKey)
		}
		if coreVolumes[FoldKey(strings.TrimSpace(k))] {
			return fmt.Errorf("volume %s is core's (portcullis_%s): templates may not use core's volume names", k, k)
		}
		v, err := asMap(vols[k], "volume "+k)
		if err != nil {
			return err
		}
		name, hasName := str(v["name"])
		if v["name"] != nil && !hasName {
			return fmt.Errorf("volume %s: name must be a string", k)
		}
		if err := literal("volume "+k+": name", name); err != nil {
			return err
		}
		ext := false
		switch e := v["external"].(type) {
		case nil:
		case bool:
			ext = e
		case map[string]interface{}:
			ext = true
			en, ok := str(e["name"])
			if e["name"] != nil && !ok {
				return fmt.Errorf("volume %s: external name must be a string", k)
			}
			if err := literal("volume "+k+": external name", en); err != nil {
				return err
			}
			if en != "" {
				name, hasName = en, true
			}
		default:
			return fmt.Errorf("volume %s: external must be true, false or a mapping", k)
		}
		eff := name
		if !hasName {
			eff = k
		}
		fe := FoldKey(strings.TrimSpace(eff))
		if coreVolumes[strings.TrimPrefix(fe, "portcullis_")] && strings.HasPrefix(fe, "portcullis_") {
			return fmt.Errorf("volume %s is named %s, core's volume", k, eff)
		}
		if ext && strings.HasPrefix(fe, "portcullis") {
			return fmt.Errorf("volume %s: external volume %s is core's or another instance's data (portcullis*)", k, eff)
		}
	}
	return nil
}

// checkServiceLabels: label keys and the values that name routers,
// middlewares or services must be literals (compose interpolates after
// the Hub's checks); the routing rule may use the host variables
// (checked by ParseRoutes).
func checkServiceLabels(svc string, pairs map[string]string, hostVars map[string]string, own ownNames) error {
	for k, v := range pairs {
		// Label keys are ASCII: Traefik's label decoder matches with
		// strings.EqualFold, which folds e.g. "ſ" (U+017F) to "s" and the
		// Kelvin sign to "k", so `routerſ` / `middlewareſ` / `tlſ` would be
		// Traefik routers / middlewares / TLS settings the Hub never sees.
		if !isASCII(k) {
			return fmt.Errorf("service %s: label key %q has non-ASCII characters", svc, k)
		}
		// Every label key is a literal (a key like ${X:-traefik}.http… or
		// traef${E}ik.… would dodge the prefix check below).
		if err := literal("service "+svc+": label key", k); err != nil {
			return err
		}
		lk := strings.ToLower(strings.TrimSpace(k))
		if !strings.HasPrefix(lk, "traefik") {
			continue
		}
		if err := checkTraefikKeyShape(svc, k); err != nil {
			return err
		}
		if err := checkCoreReferences(svc, k, v, own); err != nil {
			return err
		}
		// A router's entrypoints are exactly websecure: the Hub's override
		// adds vpnsecure per reach (contract §3); a template router on
		// vpnsecure would skip the VPN-only rendering.
		if m := routerLabelRe.FindStringSubmatch(lk); m != nil && m[3] == "entrypoints" && strings.TrimSpace(v) != "websecure" {
			return fmt.Errorf("service %s: router %s: entrypoints must be 'websecure' (the Hub adds vpnsecure per reach)", svc, m[2])
		}
		// Traefik label keys as ParseRoutes matches them (Traefik itself is
		// case-insensitive, so `Traefik.http…`, ` traefik.http…` or a
		// `…Rule` would route unparsed): no surrounding whitespace, the
		// structural part `traefik.<proto>.<kind>.<name>` lowercase, and
		// router keys lowercase throughout. Only middleware/service
		// configuration may carry case (header names).
		segs := strings.SplitN(k, ".", 5)
		structural := strings.Join(segs[:min(4, len(segs))], ".")
		if k != strings.TrimSpace(k) || structural != strings.ToLower(structural) ||
			(len(segs) > 2 && strings.EqualFold(segs[2], "routers") && k != lk) {
			return fmt.Errorf("service %s: Traefik label key %q must be lowercase (router keys entirely, others up to the name) without surrounding whitespace", svc, k)
		}
		// Every traefik.* value is a literal, except HTTP router rules:
		// ParseRoutes checks their host variables.
		if m := routerLabelRe.FindStringSubmatch(k); m != nil && m[1] == "http" && m[3] == "rule" {
			continue
		}
		// The template's own contract-v2 host variables may appear (e.g. a
		// redirect to its own host); anything else interpolated is refused.
		if err := literal("service "+svc+": label "+k, withoutOwnHostVars(v, hostVars)); err != nil {
			return err
		}
	}
	return nil
}

// hostVarAnyRe finds contract-v2 host-variable expressions in a string.
var hostVarAnyRe = regexp.MustCompile(`\$\{(PORTCULLIS_HOST_[A-Z0-9_]+):-([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.portcullis\.local\}`)

// withoutOwnHostVars removes the template's own host-variable expressions
// from v (whatever else is interpolated stays and is refused).
func withoutOwnHostVars(v string, hostVars map[string]string) string {
	own := map[string]bool{}
	for _, hv := range hostVars {
		own[hv] = true
	}
	return hostVarAnyRe.ReplaceAllStringFunc(v, func(m string) string {
		if own[hostVarAnyRe.FindStringSubmatch(m)[1]] {
			return "h"
		}
		return m
	})
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// FoldKey lowercases s the way Traefik compares label key segments
// (strings.EqualFold): every rune whose simple case-folding orbit holds an
// ASCII letter becomes that letter, lowercased (ſ → s, K (Kelvin) → k).
func FoldKey(s string) string {
	return strings.Map(func(r rune) rune {
		if r < utf8.RuneSelf {
			return unicode.ToLower(r)
		}
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < utf8.RuneSelf {
				return unicode.ToLower(f)
			}
		}
		return r
	}, s)
}

// Traefik label kinds and attributes the Hub understands; any other
// traefik.* key shape is refused (it could be something Traefik decodes
// that ParseRoutes and the override never see). Every comparison is on
// the folded key (FoldKey): Traefik's decoder matches with EqualFold.
var (
	// HTTP only: templates never define TCP or UDP routing (none of the
	// templates needs it, and it would bypass forward-auth, contract §4).
	// No serverstransports: a transport can present files from Traefik's
	// filesystem as client certificates and no template needs one.
	traefikKinds = map[string]map[string]bool{
		"http": {"routers": true, "services": true, "middlewares": true},
	}
	// labelSegRe: every dot-separated segment of a traefik.* key. A stray
	// "]" or "[" (or an empty segment) panics Traefik's label decoder and
	// stops its docker provider — a core-wide outage.
	labelSegRe = regexp.MustCompile(`^[A-Za-z0-9_-]+(\[[0-9]+\])?$`)
	// labelNameRe: the router / service / middleware name segment.
	labelNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
	// coreTraefikNames are the @docker routers, middlewares and services
	// core defines (core docker-compose.yml labels, all profiles; checked
	// against a sibling core checkout by TestCoreTraefikNamesComplete). A
	// template defining one would collide with core's (Traefik disables
	// both, or merges them).
	coreTraefikNames = map[string]map[string]bool{
		"routers": set("dashboard", "enroll", "enroll-invite", "enroll-self", "grafana-metrics", "hub", "keycloak", "keycloak-admin",
			"keycloak-resources", "lldap", "oauth2-callback", "people", "portal", "mcp", "hub-mcp", "people-mcp", "people-vpn-enrol",
			"core-vpn-required", "dashboard-vpn", "grafana-metrics-vpn", "hub-vpn", "keycloak-admin-vpn", "keycloak-admin-vpn-required",
			"people-vpn", "people-vpn-enrol-vpn", "portal-vpn"),
		"middlewares": set("vpn-required-path", "portcullis-groups-vpn", "portcullis-public-guard-vpn", "portal-vpn-path", "directory-redirect", "hub-proxy-secret", "portal-path", "portcullis-auth", "portcullis-auth-console",
			"portcullis-auth-ext", "portcullis-groups", "portcullis-public-guard", "portcullis-self"),
		"services": set("enroll", "forward-auth", "forward-auth-ext", "grafana-metrics", "group-gate", "hub", "hub-people", "keycloak", "lldap", "mcp-gate"),
	}
	// routerAttrRe: no tls.certresolver / tls.domains (certificates are
	// core's: a template asking ACME for names it doesn't route).
	routerAttrRe = regexp.MustCompile(`^(rule|entrypoints|middlewares|service|priority|tls|tls\.options|observability\.(accesslogs|metrics|tracing))$`)
	// serviceAttrRe: a service is a load balancer over the labelled
	// container itself (Traefik takes its address on the shared network) —
	// never server(s).url (Traefik would proxy to any address it can
	// reach: the socket proxies, the Hub, Keycloak as the trusted Traefik
	// IP), a serverstransport, or a weighted / mirroring / failover
	// service naming other services; no healthcheck either (Traefik would
	// send requests from its own address — trusted by core's header-auth
	// services — with the template's method, headers and followed
	// redirects).
	serviceAttrRe = regexp.MustCompile(`^loadbalancer\.(server\.(port|scheme)|passhostheader|responseforwarding\.flushinterval|` +
		`sticky\.cookie(\.(name|secure|httponly|samesite|maxage|path))?)$`)
	// middlewareAttrRe: the middleware types a template may define, each
	// with its attributes ("" = the type alone, e.g. compress=true).
	// Refused (not listed): forwardauth (Traefik would send requests to any
	// address it reaches), errors (its service may be api@internal or a
	// core service), plugin, basicauth / digestauth (usersfile reads
	// Traefik's filesystem), passtlsclientcert, ratelimit / inflightreq
	// redis.* (an address).
	sourceCriterion  = `sourcecriterion\.(requesthost|requestheadername|ipstrategy\.(depth|excludedips|ipv6subnet))`
	middlewareAttrRe = map[string]*regexp.Regexp{
		"addprefix":        regexp.MustCompile(`^prefix$`),
		"stripprefix":      regexp.MustCompile(`^(prefixes|forceslash)$`),
		"stripprefixregex": regexp.MustCompile(`^regex$`),
		"replacepath":      regexp.MustCompile(`^path$`),
		"replacepathregex": regexp.MustCompile(`^(regex|replacement)$`),
		"redirectregex":    regexp.MustCompile(`^(regex|replacement|permanent)$`),
		"redirectscheme":   regexp.MustCompile(`^(scheme|port|permanent)$`),
		"headers":          regexp.MustCompile(`^[a-z0-9_-]+(\[[0-9]+\])?(\.[a-z0-9_-]+)?$`),
		"compress":         regexp.MustCompile(`^(|excludedcontenttypes|includedcontenttypes|minresponsebodybytes|encodings|defaultencoding)$`),
		"contenttype":      regexp.MustCompile(`^(|autodetect)$`),
		"chain":            regexp.MustCompile(`^middlewares$`),
		"ratelimit":        regexp.MustCompile(`^(average|period|burst|` + sourceCriterion + `)$`),
		"inflightreq":      regexp.MustCompile(`^(amount|` + sourceCriterion + `)$`),
		"ipallowlist":      regexp.MustCompile(`^(sourcerange|rejectstatuscode|ipstrategy\.(depth|excludedips|ipv6subnet))$`),
		"buffering":        regexp.MustCompile(`^(maxrequestbodybytes|memrequestbodybytes|maxresponsebodybytes|memresponsebodybytes|retryexpression)$`),
		"retry":            regexp.MustCompile(`^(attempts|initialinterval)$`),
		"circuitbreaker":   regexp.MustCompile(`^(expression|checkperiod|fallbackduration|recoveryduration|responsecode)$`),
		"grpcweb":          regexp.MustCompile(`^alloworigins$`),
	}
)

// checkTraefikKeyShape: traefik.enable, traefik.docker.network, or
// traefik.http.<kind>.<name>.<attr> with an exact kind and an allowlisted
// attribute (routers, services) or middleware type + attribute — all
// compared on the folded key.
func checkTraefikKeyShape(svc, k string) error {
	fk := FoldKey(k)
	switch fk {
	case "traefik.enable", "traefik.docker.network":
		return nil
	}
	for _, seg := range strings.Split(k, ".") {
		if !labelSegRe.MatchString(seg) {
			return fmt.Errorf("service %s: Traefik label %q: segment %q is not [A-Za-z0-9_-] (with an optional [n]) — it could crash Traefik's label decoder", svc, k, seg)
		}
	}
	segs := strings.SplitN(fk, ".", 5)
	if len(segs) < 5 || segs[0] != "traefik" {
		return fmt.Errorf("service %s: Traefik label %q has an unsupported shape", svc, k)
	}
	kinds, ok := traefikKinds[segs[1]]
	if !ok || !kinds[segs[2]] {
		return fmt.Errorf("service %s: Traefik label %q: unsupported protocol or kind (only traefik.http.<routers|services|middlewares>; no TCP or UDP routing)", svc, k)
	}
	if !labelNameRe.MatchString(segs[3]) {
		return fmt.Errorf("service %s: Traefik label %q: name %q must match %s", svc, k, segs[3], labelNameRe)
	}
	if coreTraefikNames[segs[2]][segs[3]] {
		return fmt.Errorf("service %s: Traefik label %q: %s %q is core's (reserved)", svc, k, strings.TrimSuffix(segs[2], "s"), segs[3])
	}
	attr := segs[4]
	switch segs[2] {
	case "routers":
		if !routerAttrRe.MatchString(attr) {
			return fmt.Errorf("service %s: Traefik label %q: unsupported router attribute %q", svc, k, attr)
		}
	case "services":
		if !serviceAttrRe.MatchString(attr) {
			return fmt.Errorf("service %s: Traefik label %q: unsupported service attribute %q (a service balances over its own container: loadbalancer.server.port / scheme, passhostheader, sticky — never a server url or a healthcheck)", svc, k, attr)
		}
	case "middlewares":
		typ, rest, _ := strings.Cut(attr, ".")
		re, ok := middlewareAttrRe[typ]
		if !ok {
			return fmt.Errorf("service %s: Traefik label %q: middleware type %q is not allowed in templates (no forwardauth, errors, plugin, basicauth, …)", svc, k, typ)
		}
		if !re.MatchString(rest) {
			return fmt.Errorf("service %s: Traefik label %q: unsupported %s attribute %q", svc, k, typ, rest)
		}
	}
	return nil
}

// CheckTags refuses explicit YAML tags other than the core "!!" ones:
// compose's !reset / !override (and anything custom) could strip or replace
// what the checks saw.
func CheckTags(n *yaml.Node) error {
	if n.Tag != "" && strings.HasPrefix(n.Tag, "!") && !strings.HasPrefix(n.Tag, "!!") {
		return fmt.Errorf("line %d: YAML tag %s is not allowed (!reset / !override could strip labels or networks)", n.Line, n.Tag)
	}
	if n.Style&yaml.TaggedStyle != 0 && !strings.HasPrefix(n.Tag, "!!") {
		return fmt.Errorf("line %d: YAML tag %s is not allowed", n.Line, n.Tag)
	}
	if n.Tag == "!!binary" {
		return fmt.Errorf("line %d: YAML tag !!binary is not allowed (a binary scalar decodes to text no check sees)", n.Line)
	}
	for _, c := range n.Content {
		if err := CheckTags(c); err != nil {
			return err
		}
	}
	return nil
}

func set(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

// Compose keys a template may use (top level and per service). Anything
// else is refused — e.g. label_file (compose ≥ 2.32) adds labels the Hub
// never sees, deploy.labels, annotations, build, env_file, configs,
// secrets, links. Grown from what the templates use plus harmless
// runtime settings; profiles only as validateSetup allows (§13.18).
var (
	topLevelKeys = set("services", "volumes", "networks", "name")
	serviceKeys  = set("image", "volumes", "restart", "environment", "networks", "security_opt", "cap_drop", "cap_add",
		"pids_limit", "mem_limit", "mem_reservation", "memswap_limit", "cpus", "cpu_shares", "labels", "command", "read_only",
		"depends_on", "tmpfs", "entrypoint", "user", "group_add", "healthcheck", "shm_size", "network_mode", "working_dir",
		"hostname", "devices", "container_name", "ports", "expose", "ulimits", "stop_grace_period", "stop_signal", "init",
		"privileged", "sysctls", "logging", "tty", "stdin_open", "dns", "dns_search", "extra_hosts", "platform", "pull_policy",
		"pid", "ipc", "volumes_from", "domainname", "mac_address", "oom_score_adj", "storage_opt", "userns_mode",
		"device_cgroup_rules", "gpus", "runtime", "isolation", "blkio_config", "cgroup", "cgroup_parent", "cpuset", "profiles")
)

// checkComposeKeys: only allowlisted top-level and service keys (x-*
// extension keys are allowed at the top level, for anchors).
func checkComposeKeys(doc map[string]interface{}) error {
	for k := range doc {
		if !topLevelKeys[k] && !strings.HasPrefix(k, "x-") {
			return fmt.Errorf("compose.yml: top-level key %q is not allowed", k)
		}
	}
	svcs, _ := doc["services"].(map[string]interface{})
	for name, raw := range svcs {
		s, _ := raw.(map[string]interface{})
		for k := range s {
			if !serviceKeys[k] {
				return fmt.Errorf("service %s: compose key %q is not allowed in templates (the Hub can't check what it does)", name, k)
			}
		}
	}
	return nil
}

// appMiddlewares are core's @docker middlewares a template may chain
// (contract §5); fileMiddlewares the @file middlewares of core's
// traefik/dynamic/middlewares.yml (checked against a sibling core
// checkout by TestCoreFileMiddlewaresComplete) — never an admin's own
// @file objects under traefik/dynamic/local.
var (
	appMiddlewares  = set("portcullis-auth", "portcullis-groups")
	fileMiddlewares = set("client-headers", "client-cert-pem", "rate-limit", "rate-limit-auth", "security-headers")
)

// chainLabelRe: a chain middleware's member list (folded key).
var chainLabelRe = regexp.MustCompile(`^traefik\.http\.middlewares\.[^.]+\.chain\.middlewares$`)

// ownNames are the Traefik services and middlewares a template's labels
// define (folded), across all its compose services.
type ownNames struct{ services, middlewares map[string]bool }

func collectOwnNames(pairs map[string]map[string]string) ownNames {
	own := ownNames{services: map[string]bool{}, middlewares: map[string]bool{}}
	for _, l := range pairs {
		for k := range l {
			segs := strings.SplitN(FoldKey(strings.TrimSpace(k)), ".", 5)
			if len(segs) == 5 && segs[0] == "traefik" && segs[1] == "http" {
				switch segs[2] {
				case "services":
					own.services[segs[3]] = true
				case "middlewares":
					own.middlewares[segs[3]] = true
				}
			}
		}
	}
	return own
}

// checkCoreReferences: a router sends its traffic only to a Traefik
// service the template defines itself (@docker) — never to a core service
// (`hub@docker` would route the template's host to the Hub, Keycloak or
// LLDAP; `api@internal` is Traefik's dashboard), an @file one or another
// app's — and routers and chains use only the template's own middlewares,
// portcullis-auth@docker / portcullis-groups@docker and core's five @file
// middlewares (`hub-proxy-secret@docker` injects the Hub's proxy secret).
// Keys are compared folded; the keys and values of every reference
// (router service, router middlewares, chain middlewares) must be
// lowercase, so RenameLabels (which renames them per instance) and
// Traefik read the same names.
func checkCoreReferences(svc, k, v string, own ownNames) error {
	fk := FoldKey(strings.TrimSpace(k))
	m := routerLabelRe.FindStringSubmatch(fk)
	isRef := m != nil && (m[3] == "service" || m[3] == "middlewares") || chainLabelRe.MatchString(fk)
	if !isRef {
		return nil
	}
	if k != strings.ToLower(k) || !isASCII(k) {
		return fmt.Errorf("service %s: label key %q names services or middlewares: it must be lowercase", svc, k)
	}
	if v != strings.ToLower(v) || !isASCII(v) {
		return fmt.Errorf("service %s: label %s: %q must be lowercase (references are renamed per instance)", svc, k, v)
	}
	ref := func(s string) (base, provider string) {
		base, provider, _ = strings.Cut(strings.TrimSpace(s), "@")
		return base, provider
	}
	if m != nil && m[3] == "service" {
		base, prov := ref(v)
		if (prov != "" && prov != "docker") || !own.services[base] || coreTraefikNames["services"][base] {
			return fmt.Errorf("service %s: label %s: router service %q is not one this template defines (core's, @file, @internal and other apps' services are refused)", svc, k, v)
		}
		return nil
	}
	for _, mw := range strings.Split(v, ",") {
		base, prov := ref(mw)
		if base == "" && prov == "" {
			continue
		}
		ok := prov == "file" && fileMiddlewares[base] ||
			(prov == "" || prov == "docker") && (appMiddlewares[base] || own.middlewares[base] && !coreTraefikNames["middlewares"][base])
		if !ok {
			return fmt.Errorf("service %s: label %s: middleware %q is not allowed (apps use their own middlewares, portcullis-auth@docker, portcullis-groups@docker and core's @file middlewares %s)", svc, k, strings.TrimSpace(mw), strings.Join(sortedKeys(fileMiddlewares), ", "))
		}
	}
	return nil
}
