package templates

import (
	"fmt"
	"sort"
	"strings"

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
	var raw interface{}
	if err := yaml.Unmarshal(compose, &raw); err != nil {
		return fmt.Errorf("compose.yml: %w", err)
	}
	doc, err := asMap(raw, "compose.yml")
	if err != nil {
		return err
	}
	if _, ok := doc["include"]; ok {
		return fmt.Errorf("compose.yml: top-level include is not allowed (it pulls in files the Hub can't check)")
	}
	if err := walkStrings(doc, func(s string) error {
		low := strings.ToLower(s)
		for _, r := range reservedRefs {
			if strings.Contains(low, r) {
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
	for _, k := range keys {
		n, err := asMap(nets[k], "network "+k)
		if err != nil {
			return err
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
