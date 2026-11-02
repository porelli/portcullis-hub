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
// and the DNS name of the domains service.
//
// The checks run on the DECODED document (yaml.v3 resolves anchors,
// aliases, merge keys, quoting and escapes), and every value that decides
// network membership or a DNS name must be a literal: compose
// interpolates `${…}` / `$VAR` after the Hub's checks, so such values are
// refused outright. compose `include` and service `extends` pull in files
// the Hub can't see and are refused too.

// coreNetworks are core's networks (compose keys; their Docker names are
// these or portcullis_<key>). Templates join only portcullis-proxy.
var coreNetworks = map[string]bool{
	"portcullis": true, "portcullis-auth": true, "portcullis-certs": true, "portcullis-domains": true,
	"domains-egress": true, "socket-proxy-traefik": true, "socket-proxy-hub": true, "monitoring": true, "alerting": true,
}

// reservedRefs may not appear in any key or value of a template's compose
// file: the Hub renders portcullis-auth-ext and the
// portcullis-oauth2-<id>_<router> sign-in routers to forward-auth-ext on
// extra-domain hosts itself.
var reservedRefs = []string{"forward-auth-ext", "portcullis-auth-ext", "portcullis-oauth2-"}

// reservedDNSNames: a container answering to one of these on a network it
// shares with a core service could intercept that service's traffic.
var reservedDNSNames = map[string]bool{"domains": true}

func isCoreNetwork(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	return coreNetworks[n] || coreNetworks[strings.TrimPrefix(n, "portcullis_")]
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
	if def := m[2] + ".portcullis.local"; reservedDNSNames[m[2]] || reservedDNSNames[def] {
		return fmt.Errorf("hostname %q: the default %s is reserved", v, def)
	}
	return nil
}

// checkCoreRefs rejects a compose file that references the reserved
// sign-in names, joins a core network (by name, external name or
// network_mode container:), answers to a reserved DNS name (service name,
// container_name, hostname, network alias), uses interpolation in any of
// those, or uses `include` / `extends`.
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
	// shared: external or explicitly named networks (not project-scoped).
	shared := map[string]bool{}
	for _, k := range keys {
		n, err := asMap(nets[k], "network "+k)
		if err != nil {
			return err
		}
		if n["name"] != nil || (n["external"] != nil && n["external"] != false) {
			shared[k] = true
		}
		name, hasName := str(n["name"])
		if hasName {
			if err := literal("network "+k+": name", name); err != nil {
				return err
			}
			if isCoreNetwork(name) {
				return fmt.Errorf("network %s is named %s, a core network", k, name)
			}
		} else if n["name"] != nil {
			return fmt.Errorf("network %s: name must be a string", k)
		}
		ext := false
		switch v := n["external"].(type) {
		case bool:
			ext = v
		case string:
			return fmt.Errorf("network %s: external must be true or false, not %q", k, v)
		case nil:
		case map[string]interface{}:
			ext = true
			en, ok := str(v["name"])
			if v["name"] != nil && !ok {
				return fmt.Errorf("network %s: external name must be a string", k)
			}
			if err := literal("network "+k+": external name", en); err != nil {
				return err
			}
			if isCoreNetwork(en) {
				return fmt.Errorf("network %s joins the core network %s", k, en)
			}
			if en != "" {
				hasName = true
			}
		default:
			return fmt.Errorf("network %s: external must be true, false or a mapping", k)
		}
		if ext && !hasName && isCoreNetwork(k) {
			return fmt.Errorf("network %s is a core network (templates join only portcullis-proxy)", k)
		}
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
	for _, name := range names {
		s, err := asMap(svcs[name], "service "+name)
		if err != nil {
			return err
		}
		if _, ok := s["extends"]; ok {
			return fmt.Errorf("service %s: extends is not allowed (it pulls in configuration the Hub can't check)", name)
		}
		if err := checkServiceLabels(name, s["labels"], hostVars); err != nil {
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
		switch vf := s["volumes_from"].(type) {
		case nil:
		case []interface{}:
			for _, x := range vf {
				sv, ok := str(x)
				if !ok {
					return fmt.Errorf("service %s: volumes_from entries must be strings", name)
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
		if reservedDNSNames[strings.ToLower(name)] {
			return fmt.Errorf("service %s: the DNS name %q is reserved for core's domains service", name, name)
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
			lv := strings.ToLower(strings.TrimSpace(v))
			if field != "network_mode" && reservedDNSNames[lv] {
				return fmt.Errorf("service %s: the DNS name %q is reserved for core's domains service", name, v)
			}
			if field == "network_mode" && strings.HasPrefix(lv, "container:") {
				return fmt.Errorf("service %s: network_mode %s joins another container's network namespace", name, v)
			}
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
						if reservedDNSNames[strings.ToLower(strings.TrimSpace(a))] {
							return fmt.Errorf("service %s: network alias %q is reserved for core's domains service", name, a)
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

// checkServiceLabels: label keys and the values that name routers,
// middlewares or services must be literals (compose interpolates after
// the Hub's checks); the routing rule may use the host variables
// (checked by ParseRoutes).
func checkServiceLabels(svc string, labels interface{}, hostVars map[string]string) error {
	pairs := map[string]string{}
	switch l := labels.(type) {
	case nil:
		return nil
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
				return fmt.Errorf("service %s: labels entries must be strings", svc)
			}
			k, v, _ := strings.Cut(sv, "=")
			pairs[k] = v
		}
	default:
		return fmt.Errorf("service %s: labels must be a list or a mapping", svc)
	}
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

// Traefik label kinds and router attributes the Hub understands; any other
// traefik.* key shape is refused (it could be something Traefik decodes
// that ParseRoutes and the override never see).
var (
	// HTTP only: templates never define TCP or UDP routing (none of the
	// templates needs it, and it would bypass forward-auth, contract §4).
	traefikKinds = map[string]map[string]bool{
		"http": {"routers": true, "services": true, "middlewares": true, "serverstransports": true},
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
			"keycloak-resources", "lldap", "oauth2-callback", "people", "portal"),
		"middlewares": set("directory-redirect", "hub-proxy-secret", "portal-path", "portcullis-auth", "portcullis-auth-console",
			"portcullis-auth-ext", "portcullis-groups", "portcullis-public-guard", "portcullis-self"),
		"services": set("enroll", "forward-auth", "forward-auth-ext", "grafana-metrics", "group-gate", "hub", "hub-people", "keycloak", "lldap"),
	}
	routerAttrRe = map[string]*regexp.Regexp{
		"http": regexp.MustCompile(`^(rule|entrypoints|middlewares|service|priority|tls|tls\.options|tls\.certresolver|tls\.domains\[[0-9]+\]\.(main|sans)|observability\.(accesslogs|metrics|tracing))$`),
		"tcp":  regexp.MustCompile(`^(rule|entrypoints|middlewares|service|priority|tls|tls\.passthrough|tls\.options|tls\.certresolver|tls\.domains\[[0-9]+\]\.(main|sans))$`),
		"udp":  regexp.MustCompile(`^(entrypoints|service)$`),
	}
)

// checkTraefikKeyShape: traefik.enable, traefik.docker.network, or
// traefik.<http|tcp|udp>.<kind>.<name>.<attr> with an exact kind and, for
// routers, an allowlisted attribute.
func checkTraefikKeyShape(svc, k string) error {
	switch k {
	case "traefik.enable", "traefik.docker.network":
		return nil
	}
	for _, seg := range strings.Split(k, ".") {
		if !labelSegRe.MatchString(seg) {
			return fmt.Errorf("service %s: Traefik label %q: segment %q is not [A-Za-z0-9_-] (with an optional [n]) — it could crash Traefik's label decoder", svc, k, seg)
		}
	}
	segs := strings.SplitN(k, ".", 5)
	if len(segs) < 5 || segs[0] != "traefik" {
		return fmt.Errorf("service %s: Traefik label %q has an unsupported shape", svc, k)
	}
	kinds, ok := traefikKinds[segs[1]]
	if !ok || !kinds[segs[2]] {
		return fmt.Errorf("service %s: Traefik label %q: unsupported protocol or kind (only traefik.http.<routers|services|middlewares|serverstransports>; no TCP or UDP routing)", svc, k)
	}
	if !labelNameRe.MatchString(segs[3]) {
		return fmt.Errorf("service %s: Traefik label %q: name %q must match %s", svc, k, segs[3], labelNameRe)
	}
	if coreTraefikNames[segs[2]][segs[3]] {
		return fmt.Errorf("service %s: Traefik label %q: %s %q is core's (reserved)", svc, k, strings.TrimSuffix(segs[2], "s"), segs[3])
	}
	if segs[2] == "routers" && !routerAttrRe[segs[1]].MatchString(segs[4]) {
		return fmt.Errorf("service %s: Traefik label %q: unsupported router attribute %q", svc, k, segs[4])
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
// secrets, profiles, links. Grown from what the templates use plus
// harmless runtime settings.
var (
	topLevelKeys = set("services", "volumes", "networks", "name")
	serviceKeys  = set("image", "volumes", "restart", "environment", "networks", "security_opt", "cap_drop", "cap_add",
		"pids_limit", "mem_limit", "mem_reservation", "memswap_limit", "cpus", "cpu_shares", "labels", "command", "read_only",
		"depends_on", "tmpfs", "entrypoint", "user", "group_add", "healthcheck", "shm_size", "network_mode", "working_dir",
		"hostname", "devices", "container_name", "ports", "expose", "ulimits", "stop_grace_period", "stop_signal", "init",
		"privileged", "sysctls", "logging", "tty", "stdin_open", "dns", "dns_search", "extra_hosts", "platform", "pull_policy",
		"pid", "ipc", "volumes_from", "domainname", "mac_address", "oom_score_adj", "storage_opt", "userns_mode",
		"device_cgroup_rules", "gpus", "runtime", "isolation", "blkio_config", "cgroup", "cgroup_parent", "cpuset")
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
