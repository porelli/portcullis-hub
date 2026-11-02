package templates

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

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
			// its declared portcullis_<key>, else <project>_<key>. The
			// Hub's override never renames them.
			if t.NamedVolumes[k] {
				n.Volumes[k] = "portcullis_" + k
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

// Instance returns the view of instance id of this template, with hosts
// (host router → full hostname; nil = the defaults on domain) resolved:
// subdomains, public plan, URLs, Keycloak clients, groups and instance
// variables. Hostnames must be <label>.<domain> (the policy file keys by
// subdomain).
func (t *Template) Instance(id string, hosts map[string]string, domain string) (Template, error) {
	tid := t.TemplateID
	if tid == "" {
		tid = t.ID
	}
	if hosts == nil {
		hosts = t.DefaultHosts(domain)
	}
	raw := t.rawManifest()
	c := *t
	c.ID, c.TemplateID, c.Instances, c.raw = id, tid, nil, raw
	c.Hosts = make(map[string]string, len(hosts))
	subMap := map[string]string{} // default subdomain → instance's
	for r, sub := range t.HostRouters {
		h := strings.ToLower(hosts[r])
		if h == "" {
			return c, fmt.Errorf("instance %s: no hostname for host router %s", id, r)
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
	c.Subdomains = nil
	for _, s := range t.Subdomains {
		c.Subdomains = append(c.Subdomains, mapSub(s))
	}
	sort.Strings(c.Subdomains)
	if t.Public != nil {
		p := *t.Public
		p.Subdomains = nil
		for _, s := range t.Public.Subdomains {
			p.Subdomains = append(p.Subdomains, mapSub(s))
		}
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
	for i, u := range m.URLs {
		if err := check(fmt.Sprintf("urls[%d]", i), u.URL); err != nil {
			return err
		}
	}
	for _, c := range m.Clients {
		for _, u := range append([]string{c.RedirectURI}, c.RedirectURIs...) {
			if err := check("keycloak client "+c.ClientID, u); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkVolumeNames enforces contract §3 Volumes: a single template names
// each volume portcullis_<key>, a multi template names none (the Hub's
// override sets both, §11.2, so another name would orphan its data).
func checkVolumeNames(compose []byte, multi bool) error {
	var doc struct {
		Volumes map[string]interface{} `yaml:"volumes"`
	}
	if err := yaml.Unmarshal(compose, &doc); err != nil {
		return err
	}
	for k, v := range doc.Volumes {
		mv, _ := v.(map[string]interface{})
		if ext, ok := mv["external"]; ok && ext != nil && ext != false {
			continue
		}
		name, has := mv["name"]
		switch {
		case has && multi:
			return fmt.Errorf("volume %s: an instances: multi template declares no volume name (the Hub sets it)", k)
		case has && name != "portcullis_"+k:
			return fmt.Errorf("volume %s: name must be portcullis_%s", k, k)
		}
	}
	return nil
}

// declaredVolumeNames returns the volume keys that declare a name:.
func declaredVolumeNames(compose []byte) map[string]bool {
	var doc struct {
		Volumes map[string]interface{} `yaml:"volumes"`
	}
	out := map[string]bool{}
	if yaml.Unmarshal(compose, &doc) != nil {
		return out
	}
	for k, v := range doc.Volumes {
		if mv, ok := v.(map[string]interface{}); ok && mv["name"] != nil {
			out[k] = true
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
