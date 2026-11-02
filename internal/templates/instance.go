package templates

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/portcullis/hub/internal/policy"
	"gopkg.in/yaml.v3"
)

// Instances (contract §11): a template runs as its default instance (id =
// template id, today's names) and, for "multi" templates, as further
// instances with derived names (§11.2) and their own hostnames.

// InstanceIDRe constrains the ids of instances other than the default one
// (a DNS label, §11.1).
var InstanceIDRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)

// ReservedInstancePrefix may not start an instance id (§11.1).
const ReservedInstancePrefix = "portcullis"

// CheckIDShape refuses a template or instance id that would let two
// instances' automatic Traefik names collide. Traefik names a container's
// automatic service and default router Normalize("<compose service>_portcullis-<id>")
// (runs of other characters than letters and digits become "-", leading
// and trailing ones dropped), so:
//   - "portcullis" may not be a segment of the id (instance a-portcullis-b's
//     service x would be instance b's service x-portcullis-a);
//   - the id must be its own normal form, segments of [a-z0-9] joined by
//     single "-" (my_app, my--app and my-app- would all be my-app).
func CheckIDShape(id string) error {
	for _, seg := range nonAlnumRe.Split(id, -1) {
		if strings.EqualFold(seg, "portcullis") {
			return fmt.Errorf("id %q: portcullis may not be a segment of an id (Traefik's automatic names <service>-portcullis-<id> of two instances could collide)", id)
		}
	}
	if !idNormalRe.MatchString(id) {
		return fmt.Errorf("id %q: write it as letters and digits joined by single - (Traefik turns _, -- and a trailing - into the same automatic name as another id)", id)
	}
	return nil
}

var idNormalRe = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// Instance variables the Hub writes into every instance's .env (§3.1).
const (
	VarInstance       = "PORTCULLIS_INSTANCE"
	VarOIDCClientID   = "PORTCULLIS_OIDC_CLIENT_ID"
	VarAccessGroup    = "PORTCULLIS_ACCESS_GROUP"
	VarAdminGroup     = "PORTCULLIS_ADMIN_GROUP"
	varHostPrefix     = "PORTCULLIS_HOST_"
	varClientIDPrefix = VarOIDCClientID + "_"
)

// ReservedVar reports whether k is an instance variable name a manifest
// may not declare in env, settings or ports.
func ReservedVar(k string) bool {
	switch k {
	case VarInstance, VarOIDCClientID, VarAccessGroup, VarAdminGroup:
		return true
	}
	return strings.HasPrefix(k, varHostPrefix) || strings.HasPrefix(k, varClientIDPrefix)
}

// domainUseRe matches a {{DOMAIN}} with the host characters before it
// (group 1); hostCharRe is one host character.
var (
	domainUseRe = regexp.MustCompile(`([A-Za-z0-9.-]*)\{\{DOMAIN\}\}`)
	hostCharRe  = regexp.MustCompile(`[A-Za-z0-9.-]`)
)

// placeholderRe matches {{HOST_<ROUTER>}} manifest placeholders.
var placeholderRe = regexp.MustCompile(`\{\{HOST_([A-Z0-9_]+)\}\}`)

// DefaultHosts are the default instance's hostnames on domain: each host
// router's default subdomain.
func (t *Template) DefaultHosts(domain string) map[string]string {
	out := make(map[string]string, len(t.HostRouters))
	for r, sub := range t.HostRouters {
		out[r] = sub + "." + domain
	}
	return out
}

// rawManifest is the manifest as written (placeholders unexpanded).
func (t *Template) rawManifest() *Manifest {
	if t.raw != nil {
		return t.raw
	}
	return &t.Manifest
}

// InstanceNames are the names an instance derives from its id (§11.2).
type InstanceNames struct {
	Project     string
	Volumes     map[string]string // volume key → volume name
	Clients     []string          // Keycloak client ids, manifest order
	AccessGroup string            // "" if the manifest has none
	AdminGroup  string
	// Traefik are the Traefik router / service / middleware names the
	// instance defines (the template's, InstanceName-renamed for a
	// non-default instance), sorted: Traefik merges same-name objects, so
	// two instances may not share one.
	Traefik []string
}

// NamesFor returns instance id's derived names for this template.
func (t *Template) NamesFor(id string) InstanceNames {
	tid := t.TemplateID
	if tid == "" {
		tid = t.ID
	}
	def := id == tid
	m := t.rawManifest()
	n := InstanceNames{Project: "portcullis-" + id, Volumes: map[string]string{}}
	for _, k := range t.Volumes {
		if !m.Multi() {
			// A single template's volumes keep what compose names them:
			// its declared portcullis_<id>[-_…] name, else
			// <project>_<key>. The Hub's override never renames them.
			if name := t.NamedVolumes[k]; name != "" {
				n.Volumes[k] = name
			} else {
				n.Volumes[k] = n.Project + "_" + k
			}
			continue
		}
		if def {
			n.Volumes[k] = "portcullis_" + k
		} else {
			n.Volumes[k] = "portcullis_" + id + "-" + k
		}
	}
	for i, c := range m.Clients {
		switch {
		case def:
			n.Clients = append(n.Clients, c.ClientID)
		case i == 0:
			n.Clients = append(n.Clients, id)
		default:
			n.Clients = append(n.Clients, id+"-"+c.ClientID)
		}
	}
	for _, name := range sortedKeys(t.Names) {
		if !def {
			name = InstanceName(id, name)
		}
		n.Traefik = append(n.Traefik, name)
	}
	if g := m.Auth.AccessGroup; g != "" {
		n.AccessGroup = g
		if !def {
			n.AccessGroup = "users_" + id
		}
	}
	if g := m.Auth.AdminGroup; g != "" {
		n.AdminGroup = g
		if !def {
			n.AdminGroup = "admin_" + id
		}
	}
	return n
}

// HostnameRe is a valid hostname (contract §4): lowercase, at least two
// labels, no port, no trailing dot, no wildcard; also at most 253
// characters (ValidHostname).
var HostnameRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidHostname reports whether h is a valid hostname (contract §4).
func ValidHostname(h string) bool { return len(h) <= 253 && HostnameRe.MatchString(h) }

// ValidLabel reports whether s is a single DNS label.
func ValidLabel(s string) bool { return dnsLabelRe.MatchString(s) }

// Instance returns the view of instance id of this template, with hosts
// (host router → full hostname; nil = the defaults on domain) resolved:
// subdomains, public plan, URLs, Keycloak clients, groups and instance
// variables. Hostnames must be <label>.<domain>.
func (t *Template) Instance(id string, hosts map[string]string, domain string) (Template, error) {
	return t.InstanceOn(id, hosts, domain, nil)
}

// InstanceOn is Instance where extra(host) reports the hosts that lie on
// an enrolled domain (extra-domain hosts, contract §5): those need only
// be valid hostnames (the caller checks the domain rules, §11.3), are
// listed in ExtraHosts and have no subdomain. Every other host must be
// <label>.<domain>.
func (t *Template) InstanceOn(id string, hosts map[string]string, domain string, extra func(host string) bool) (Template, error) {
	tid := t.TemplateID
	if tid == "" {
		tid = t.ID
	}
	if hosts == nil {
		hosts = t.DefaultHosts(domain)
	}
	raw := t.rawManifest()
	c := *t
	c.ID, c.TemplateID, c.Instances, c.raw, c.ExtraHosts = id, tid, nil, raw, nil
	c.Hosts = make(map[string]string, len(hosts))
	subMap := map[string]string{} // default subdomain → instance's
	for r, sub := range t.HostRouters {
		h := strings.ToLower(hosts[r])
		if h == "" {
			return c, fmt.Errorf("instance %s: no hostname for host router %s", id, r)
		}
		if extra != nil && extra(h) {
			if !ValidHostname(h) {
				return c, fmt.Errorf("instance %s: hostname %s of host router %s is not a valid hostname", id, h, r)
			}
			c.Hosts[r] = h
			c.ExtraHosts = append(c.ExtraHosts, h)
			subMap[sub] = "" // no subdomain: keyed by host only
			continue
		}
		label, ok := strings.CutSuffix(h, "."+strings.ToLower(domain))
		if !ok || !dnsLabelRe.MatchString(label) {
			return c, fmt.Errorf("instance %s: hostname %s of host router %s is not <label>.%s", id, h, r, domain)
		}
		c.Hosts[r] = h
		subMap[sub] = label
	}
	for r := range hosts {
		if _, ok := t.HostRouters[r]; !ok {
			return c, fmt.Errorf("instance %s: %s is not a host router of template %s", id, r, tid)
		}
	}
	mapSub := func(s string) string {
		if v, ok := subMap[s]; ok {
			return v
		}
		return s
	}
	sort.Strings(c.ExtraHosts)
	c.Subdomains = nil
	for _, s := range t.Subdomains {
		if v := mapSub(s); v != "" {
			c.Subdomains = append(c.Subdomains, v)
		}
	}
	sort.Strings(c.Subdomains)
	if t.Public != nil {
		p := *t.Public
		p.Subdomains = nil
		p.Hosts = nil
		for _, s := range t.Public.Subdomains {
			if v := mapSub(s); v != "" {
				p.Subdomains = append(p.Subdomains, v)
			}
		}
		// Hosts: the full hostnames (extra-domain hosts included) of the
		// host routers of the public routers' subdomains only — never
		// every host of the instance (that would widen the exception).
		pubSub := map[string]bool{}
		for _, s := range t.Public.Subdomains {
			pubSub[s] = true
		}
		for r, sub := range t.HostRouters {
			if pubSub[sub] {
				p.Hosts = append(p.Hosts, c.Hosts[r])
			}
		}
		sort.Strings(p.Hosts)
		c.Public = &p
	}

	bySuffix := map[string]string{}
	for r, h := range c.Hosts {
		bySuffix[VarSuffix(r)] = h
	}
	expand := func(s string) string {
		s = strings.ReplaceAll(s, "{{DOMAIN}}", domain)
		return placeholderRe.ReplaceAllStringFunc(s, func(m string) string {
			if h, ok := bySuffix[placeholderRe.FindStringSubmatch(m)[1]]; ok {
				return h
			}
			return m
		})
	}
	names := t.NamesFor(id)
	m := *raw
	m.URLs = make([]AppURL, len(raw.URLs))
	for i, u := range raw.URLs {
		m.URLs[i] = AppURL{Label: u.Label, URL: expand(u.URL)}
	}
	m.Clients = make([]KeycloakClient, len(raw.Clients))
	for i, kc := range raw.Clients {
		kc.ClientID = names.Clients[i]
		kc.RedirectURI = expand(kc.RedirectURI)
		kc.BackchannelLogoutURL = expand(kc.BackchannelLogoutURL)
		if kc.RedirectURIs != nil {
			uris := make([]string, len(kc.RedirectURIs))
			for j, u := range kc.RedirectURIs {
				uris[j] = expand(u)
			}
			kc.RedirectURIs = uris
		}
		m.Clients[i] = kc
	}
	m.Auth.AccessGroup, m.Auth.AdminGroup = names.AccessGroup, names.AdminGroup
	c.Manifest = m

	env := map[string]string{
		VarInstance:     id,
		VarOIDCClientID: "",
		VarAccessGroup:  names.AccessGroup,
		VarAdminGroup:   names.AdminGroup,
	}
	for r, h := range c.Hosts {
		v := HostVar(r)
		if hv := t.HostVars[r]; hv != "" {
			v = hv
		}
		env[v] = h
	}
	for i, kc := range raw.Clients {
		if i == 0 {
			env[VarOIDCClientID] = names.Clients[i]
		}
		env[varClientIDPrefix+VarSuffix(kc.ClientID)] = names.Clients[i]
	}
	c.InstanceEnv = env
	return c, nil
}

// checkInstanceRules applies the contract v2 rules Discover can only check
// with the routes at hand.
func checkInstanceRules(m *Manifest, r *Routes) error {
	if m.Multi() {
		if r.Form == FormLegacy {
			return fmt.Errorf("instances: multi needs the ${PORTCULLIS_HOST_<ROUTER>:-<sub>.portcullis.local} rule form (no ${PORTCULLIS_DOMAIN} in router rules)")
		}
		for n := range r.Names {
			if strings.HasPrefix(n, "portcullis-") {
				return fmt.Errorf("Traefik name %s: names starting with portcullis- are reserved for core and the Hub", n)
			}
		}
	}
	known := map[string]bool{}
	for rt := range r.HostRouters {
		known[VarSuffix(rt)] = true
	}
	check := func(where, s string) error {
		for _, mm := range placeholderRe.FindAllStringSubmatch(s, -1) {
			if !known[mm[1]] {
				return fmt.Errorf("%s: {{HOST_%s}} names no host router", where, mm[1])
			}
		}
		return nil
	}
	// A multi template writes its own hosts only as {{HOST_<ROUTER>}}
	// (contract §3.1): {{DOMAIN}} would point every instance at the default
	// instance's hostnames. It may name a core host only: exactly
	// <core sub>.{{DOMAIN}} (never the apex, never another label).
	noDomain := func(where, s string) error {
		if !m.Multi() {
			return nil
		}
		for _, mm := range domainUseRe.FindAllStringSubmatchIndex(s, -1) {
			prefix, after := s[mm[2]:mm[3]], s[mm[1]:]
			label, ok := strings.CutSuffix(prefix, ".")
			if !ok || !policy.CoreSubdomains()[label] || (after != "" && hostCharRe.MatchString(after[:1])) {
				return fmt.Errorf("%s: a multi template names its hosts as {{HOST_<ROUTER>}}; {{DOMAIN}} only in a core host (<core subdomain>.{{DOMAIN}}), not %q", where, s[mm[2]:mm[1]])
			}
		}
		return nil
	}
	for i, u := range m.URLs {
		where := fmt.Sprintf("urls[%d]", i)
		if err := noDomain(where, u.URL); err != nil {
			return err
		}
		if err := check(where, u.URL); err != nil {
			return err
		}
	}
	if m.Hosts != nil {
		for _, h := range m.Hosts.Immutable {
			if _, ok := r.HostRouters[h]; !ok {
				return fmt.Errorf("hosts.immutable: %s is not a host router", h)
			}
		}
	}
	for _, c := range m.Clients {
		if m.Multi() && strings.Contains(c.BackchannelLogoutURL, "{{DOMAIN}}") {
			return fmt.Errorf("keycloak client %s: a multi template names its backchannel_logout_url host as {{HOST_<ROUTER>}}", c.ClientID)
		}
		for _, u := range append([]string{c.RedirectURI}, c.RedirectURIs...) {
			if err := noDomain("keycloak client "+c.ClientID+" redirect URI", u); err != nil {
				return err
			}
		}
		for _, u := range append([]string{c.RedirectURI, c.BackchannelLogoutURL}, c.RedirectURIs...) {
			if err := check("keycloak client "+c.ClientID, u); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkVolumeNames enforces contract §3 Volumes: a single template may
// name a (non-external) volume only portcullis_<template-id> or
// portcullis_<template-id>-… / portcullis_<template-id>_… (its own
// namespace: any other name could be another app's or core's data); a
// multi template names none (the Hub's override sets them, §11.2).
// Collisions inside those namespaces (template "a" naming portcullis_a-b,
// template "a-b"'s portcullis_a-b) are name claims (internal/hub).
func checkVolumeNames(compose []byte, id string, multi bool) error {
	var doc struct {
		Volumes map[string]interface{} `yaml:"volumes"`
	}
	if err := yaml.Unmarshal(compose, &doc); err != nil {
		return err
	}
	keys := make([]string, 0, len(doc.Volumes))
	for k := range doc.Volumes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		mv, _ := doc.Volumes[k].(map[string]interface{})
		if ext, ok := mv["external"]; ok && ext != nil && ext != false {
			continue
		}
		raw, has := mv["name"]
		if !has {
			continue
		}
		if multi {
			return fmt.Errorf("volume %s: an instances: multi template declares no volume name (the Hub sets it)", k)
		}
		name, ok := raw.(string)
		own := "portcullis_" + id
		if !ok || !(name == own || strings.HasPrefix(name, own+"-") || strings.HasPrefix(name, own+"_")) {
			return fmt.Errorf("volume %s: name %v must be %s or start with %s- or %s_ (the template's own namespace)", k, raw, own, own, own)
		}
	}
	return nil
}

// declaredVolumeNames returns the names non-external volumes declare
// (volume key → name).
func declaredVolumeNames(compose []byte) map[string]string {
	var doc struct {
		Volumes map[string]interface{} `yaml:"volumes"`
	}
	out := map[string]string{}
	if yaml.Unmarshal(compose, &doc) != nil {
		return out
	}
	for k, v := range doc.Volumes {
		if mv, ok := v.(map[string]interface{}); ok {
			if n, ok := mv["name"].(string); ok && n != "" {
				out[k] = n
			}
		}
	}
	return out
}

// ComposeVolumes returns the sorted top-level volume keys of a compose
// file that aren't external.
func ComposeVolumes(compose []byte) []string {
	var doc struct {
		Volumes map[string]interface{} `yaml:"volumes"`
	}
	if yaml.Unmarshal(compose, &doc) != nil {
		return nil
	}
	var out []string
	for k, v := range doc.Volumes {
		if mv, ok := v.(map[string]interface{}); ok {
			if ext, ok := mv["external"]; ok && ext != nil && ext != false {
				continue
			}
		}
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
