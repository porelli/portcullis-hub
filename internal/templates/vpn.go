package templates

import (
	"fmt"
	"maps"
	"net/netip"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// The manifest's vpn: block (contract §3.3): the template is a VPN
// provider the admin may wire for Portcullis access. ValidateVPN
// implements exactly the contract's refusals (with their texts), like the
// templates repo's tests/validate.py; testdata/vpn_vectors.json is shared
// by both.

// VPN is the manifest's vpn: block.
type VPN struct {
	Label          string      `yaml:"label" json:"label"`
	Ranges         []string    `yaml:"ranges" json:"ranges"`
	Ingress        VPNIngress  `yaml:"ingress" json:"ingress"`
	Identity       VPNIdentity `yaml:"identity" json:"identity"`
	DNS            VPNDNS      `yaml:"dns" json:"dns"`
	ControlRouters []string    `yaml:"control_routers" json:"control_routers,omitempty"`
}

// UnmarshalYAML decodes strictly (unknown keys are refused).
func (v *VPN) UnmarshalYAML(n *yaml.Node) error {
	type plain VPN
	if err := strictDecode(n, (*plain)(v)); err != nil {
		return fmt.Errorf("vpn: %v", err)
	}
	return nil
}

// VPNIngress is how the provider's traffic enters the edge: the compose
// service the Hub joins to portcullis-vpn, and the protocol it speaks.
type VPNIngress struct {
	Service       string `yaml:"service" json:"service"`
	ProxyProtocol string `yaml:"proxy_protocol" json:"proxy_protocol"`
}

// UnmarshalYAML decodes strictly.
func (i *VPNIngress) UnmarshalYAML(n *yaml.Node) error {
	type plain VPNIngress
	return strictDecode(n, (*plain)(i))
}

// VPNIdentity is where the device map comes from.
type VPNIdentity struct {
	Source  string   `yaml:"source" json:"source"`
	Hook    string   `yaml:"hook" json:"hook,omitempty"`
	Owner   string   `yaml:"owner" json:"owner,omitempty"`
	Refresh Duration `yaml:"refresh" json:"refresh,omitempty"`

	// present: the keys the block wrote (an explicit refresh: 0s or an
	// empty hook is refused, not taken for absent).
	present map[string]bool
}

// UnmarshalYAML decodes strictly and records the keys written.
func (i *VPNIdentity) UnmarshalYAML(n *yaml.Node) error {
	type plain VPNIdentity
	if err := strictDecode(n, (*plain)(i)); err != nil {
		return err
	}
	i.present = map[string]bool{}
	if n.Kind == yaml.MappingNode {
		for k := 0; k+1 < len(n.Content); k += 2 {
			i.present[n.Content[k].Value] = true
		}
	}
	return nil
}

// VPNDNS is how the provider's clients learn Portcullis names: a vpn
// hook that receives the records, or records configured by hand.
type VPNDNS struct {
	Hook   string `yaml:"hook" json:"hook,omitempty"`
	Manual bool   `yaml:"manual" json:"manual,omitempty"`
}

// UnmarshalYAML decodes strictly.
func (d *VPNDNS) UnmarshalYAML(n *yaml.Node) error {
	type plain VPNDNS
	return strictDecode(n, (*plain)(d))
}

// Contract values.
const (
	// VPNReservedPrefix starts the Hub's VPN names (the portcullis-vpn
	// network, portcullis-vpnallow-<id> middlewares, portcullis-vpnonly-<id>
	// routers); no template may mention it.
	VPNReservedPrefix = "portcullis-vpn"

	VPNSourceHook   = "hook"
	VPNSourceStatic = "static"
	VPNOwnerOIDCSub = "oidc_sub"
	VPNOwnerName    = "username"
	VPNProxyV2      = "v2"

	VPNLabelMax       = 64
	VPNMaxRanges      = 8
	VPNMinBits        = 8
	VPNMaxBits        = 30
	VPNRefreshMin     = 15 * time.Second
	VPNRefreshMax     = 10 * time.Minute
	VPNRefreshDefault = time.Minute

	// vpnSettingRef wraps a cidr setting's key in vpn.ranges.
	vpnSettingOpen  = "{{setting:"
	vpnSettingClose = "}}"
)

// EffectiveRefresh is the identity refresh, or 60 s.
func (i VPNIdentity) EffectiveRefresh() time.Duration {
	if i.Refresh == 0 {
		return VPNRefreshDefault
	}
	return time.Duration(i.Refresh)
}

// vpnSettingKey is KEY of a range written exactly "{{setting:KEY}}".
func vpnSettingKey(r string) (string, bool) {
	if !strings.HasPrefix(r, vpnSettingOpen) || !strings.HasSuffix(r, vpnSettingClose) {
		return "", false
	}
	return strings.TrimSuffix(strings.TrimPrefix(r, vpnSettingOpen), vpnSettingClose), true
}

// ParseVPNPrefix parses one client range: an IPv4 prefix, /8–/30, in
// canonical form (no host bits).
func ParseVPNPrefix(s string) (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(s)
	if err != nil || !p.Addr().Is4() || p.Bits() < VPNMinBits || p.Bits() > VPNMaxBits || p.Masked() != p || p.String() != s {
		return netip.Prefix{}, false
	}
	return p, true
}

// cidrSetting reports whether key names an instance setting of type
// string with format cidr.
func cidrSetting(m *Manifest, key string) bool {
	for _, o := range m.Options() {
		if o.Key == key {
			return o.Type == TypeString && o.Format == "cidr" && o.EffectiveScope() == ScopeInstance
		}
	}
	return false
}

// vpnHookOK: name is a declared hook with exactly when: [vpn].
func vpnHookOK(m *Manifest, name string) bool {
	for _, h := range m.Hooks {
		if h.Name == name {
			return len(h.When) == 1 && h.When[0] == HookVPN
		}
	}
	return false
}

// ValidateVPN checks the manifest's vpn: block against the manifest, the
// compose file and the routes (contract §3.3). Discover calls it after
// ValidateAI (hooks and the ai: block are validated by then).
func ValidateVPN(t *Template, compose []byte, routes *Routes) error {
	m := &t.Manifest
	v := m.VPN
	named := map[string]bool{}
	if v != nil {
		if !singleLine(v.Label, VPNLabelMax) {
			return fmt.Errorf("vpn.label: a single line of 1–%d characters", VPNLabelMax)
		}
		if len(v.Ranges) == 0 || len(v.Ranges) > VPNMaxRanges {
			return fmt.Errorf("vpn.ranges: 1–%d IPv4 prefixes", VPNMaxRanges)
		}
		var lits []netip.Prefix
		for i, r := range v.Ranges {
			if key, ok := vpnSettingKey(r); ok {
				if !cidrSetting(m, key) {
					return fmt.Errorf("vpn.ranges[%d]: {{setting:%s}} must name a cidr setting", i, key)
				}
				continue
			}
			p, ok := ParseVPNPrefix(r)
			if !ok {
				return fmt.Errorf("vpn.ranges[%d]: %s is not an IPv4 prefix between /%d and /%d", i, r, VPNMinBits, VPNMaxBits)
			}
			lits = append(lits, p)
		}
		if a, b, ok := firstOverlap(lits); ok {
			return fmt.Errorf("vpn.ranges: %s overlaps %s", a, b)
		}
		if err := checkVPNIngress(m, compose, routes); err != nil {
			return err
		}
		id := v.Identity
		switch id.Source {
		case VPNSourceHook:
			if !vpnHookOK(m, id.Hook) {
				return fmt.Errorf("vpn.identity.hook: %s is not a hook with exactly when: [vpn]", id.Hook)
			}
			named[id.Hook] = true
			if id.Owner != VPNOwnerOIDCSub && id.Owner != VPNOwnerName {
				return fmt.Errorf("vpn.identity.owner: oidc_sub or username")
			}
		case VPNSourceStatic:
			if id.Hook != "" || id.Owner != "" || id.present["hook"] || id.present["owner"] {
				return fmt.Errorf("vpn.identity: source static takes no hook or owner")
			}
		default:
			return fmt.Errorf("vpn.identity.source: hook or static")
		}
		if (id.Refresh != 0 || id.present["refresh"]) && (time.Duration(id.Refresh) < VPNRefreshMin || time.Duration(id.Refresh) > VPNRefreshMax) {
			return fmt.Errorf("vpn.identity.refresh: between 15s and 10m")
		}
		if (v.DNS.Hook != "") == v.DNS.Manual {
			return fmt.Errorf("vpn.dns: exactly one of hook and manual: true")
		}
		if v.DNS.Hook != "" {
			if !vpnHookOK(m, v.DNS.Hook) {
				return fmt.Errorf("vpn.dns.hook: %s is not a hook with exactly when: [vpn]", v.DNS.Hook)
			}
			named[v.DNS.Hook] = true
		}
		for _, r := range v.ControlRouters {
			ri := routes.Info[r]
			if ri == nil {
				return fmt.Errorf("vpn.control_routers: %s is not a host router of the template", r)
			}
			// Host(...) alone, or Host(...) && one PathPrefix(...) (Task
			// 19, the same match as templates' validate.py): a control
			// router always names its host.
			if _, host := routes.HostRouters[r]; !host && !controlRuleRe.MatchString(strings.TrimSpace(ri.Rule)) {
				return fmt.Errorf("vpn.control_routers: %s is not a host router of the template", r)
			}
			if servesAdminUI(m, routes.Info[r]) {
				return fmt.Errorf("vpn.control_routers: %s serves an admin UI", r)
			}
		}
	}
	for _, h := range m.Hooks {
		if h.IsVPN() && !named[h.Name] {
			return fmt.Errorf("hooks[%s]: when: [vpn] needs a vpn: block that names it", h.Name)
		}
	}
	return nil
}

// controlRuleRe is a control router's Host() && one PathPrefix() rule
// (validate.py's _HOST_ONLY_RULE_RE with its optional group).
var controlRuleRe = regexp.MustCompile("^Host\\(`[^`]*`\\)\\s*&&\\s*PathPrefix\\(`[^`]*`\\)$")

// sameMountSource: a and b mount the same named volume, or binds of
// the same path, one inside the other (cleaned, as written); two bind
// sources that both interpolate a variable can't be told apart and
// count as the same (fail closed).
func sameMountSource(a, b composeMount) bool {
	if a.bind != b.bind {
		return false
	}
	if !a.bind {
		return a.source == b.source
	}
	if strings.Contains(a.source, "$") && strings.Contains(b.source, "$") {
		return true
	}
	x, y := path.Clean(a.source), path.Clean(b.source)
	return x == y || strings.HasPrefix(x, y+"/") || strings.HasPrefix(y, x+"/") || x == "/" || y == "/"
}

// hostOnlyRuleRe is validate.py's _HOST_ONLY_RULE_RE without its
// optional PathPrefix group.
var hostOnlyRuleRe = regexp.MustCompile("^Host\\(`[^`]*`\\)$")

// vpnControlRulesPrecheck: a vpn.control_routers entry that is no
// router of the compose file, or whose rule (as written) is neither
// Host() alone nor Host() && one PathPrefix(). Only consulted when the
// routes don't parse, so the refusal names the control router first.
func vpnControlRulesPrecheck(m *Manifest, compose []byte) error {
	if m.VPN == nil || len(m.VPN.ControlRouters) == 0 {
		return nil
	}
	labels, err := ServiceLabels(compose)
	if err != nil {
		return nil
	}
	rules := map[string]string{}
	for _, l := range labels {
		for k, v := range l {
			if name, ok := strings.CutSuffix(strings.TrimPrefix(k, "traefik.http.routers."), ".rule"); ok && strings.HasPrefix(k, "traefik.http.routers.") && !strings.Contains(name, ".") {
				rules[name] = strings.TrimSpace(v)
			}
		}
	}
	for _, r := range m.VPN.ControlRouters {
		rule, ok := rules[r]
		if !ok || !hostOnlyRuleRe.MatchString(rule) && !controlRuleRe.MatchString(rule) {
			return fmt.Errorf("vpn.control_routers: %s is not a host router of the template", r)
		}
	}
	return nil
}

// forwarderImageRe is core's forwarder image, pinned by digest (V1):
// the only service besides the ingress allowed in its network namespace.
var forwarderImageRe = regexp.MustCompile(`^ghcr\.io/porelli/portcullis-forwarder(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?@sha256:[0-9a-f]{64}$`)

// checkVPNIngress: the ingress service exists and can join a network; no
// service of a VPN template uses the host's pid namespace, and none with
// a Traefik router or label uses host networking; every service in the ingress's network namespace (the
// ingress and the services joining it, chains followed) is no job, no AI
// companion, has no Traefik router or label and publishes no ports, and
// besides the ingress only the pinned forwarder may join it; the ingress
// and its members set no pid, ipc or volumes_from key, and no other
// service shares the pid or ipc namespace of one (service:<X>) or mounts
// its volumes (volumes_from); proxy_protocol v2.
func checkVPNIngress(m *Manifest, compose []byte, routes *Routes) error {
	s := m.VPN.Ingress.Service
	infos := composeServiceInfos(compose)
	info, ok := infos[s]
	if !ok {
		return fmt.Errorf("vpn.ingress.service: %s is not a service of compose.yml", s)
	}
	if info.networkMode {
		return fmt.Errorf("vpn.ingress.service: %s has network_mode", s)
	}
	names := slices.Sorted(maps.Keys(infos))
	// Host networking only off the VPN path (a relay may keep it): never
	// on a service with a Traefik router or label; the host's pid
	// namespace on none.
	for _, n := range names {
		if infos[n].netModeOf == "host" && (len(routes.Routers[n]) > 0 || routes.TraefikLabelled[n]) {
			return fmt.Errorf("vpn: service %s uses network_mode: host", n)
		}
		if infos[n].pidOf == "host" {
			return fmt.Errorf("vpn: service %s uses pid: host", n)
		}
	}
	members := []string{s}
	for _, n := range names {
		if n == s {
			continue
		}
		if ns, ok := routes.NetNS(n); ok && ns == s {
			members = append(members, n)
		}
	}
	jobs := JobServices(m, compose)
	for _, n := range members {
		if n != s && !forwarderImageRe.MatchString(infos[n].image) {
			return fmt.Errorf("vpn.ingress.service: %s shares %s's network namespace: only the pinned ghcr.io/porelli/portcullis-forwarder image may", n, s)
		}
		if jobs[n] {
			return fmt.Errorf("vpn.ingress.service: %s is a job", n)
		}
		if m.AI != nil {
			for _, c := range m.AI.MCP {
				if c.Service == n && kindOf(m, c.Name) == CompanionKind {
					return fmt.Errorf("vpn.ingress.service: %s is an AI companion", n)
				}
			}
		}
		if len(routes.Routers[n]) > 0 || routes.TraefikLabelled[n] {
			return fmt.Errorf("vpn.ingress.service: %s has a Traefik router", n)
		}
		if infos[n].ports {
			return fmt.Errorf("vpn.ingress.service: %s publishes ports", n)
		}
		if err := vpnNamespaceCaps(n, infos[n]); err != nil {
			return err
		}
		// No pid or ipc key at all (host, service:, container:,
		// shareable…): a member keeps its own namespaces.
		for _, k := range []struct {
			key string
			set bool
		}{{"pid", infos[n].hasPid}, {"ipc", infos[n].hasIpc}} {
			if k.set {
				return fmt.Errorf("vpn.ingress.service: %s sets %s: a VPN gateway keeps its own pid and ipc namespaces", n, k.key)
			}
		}
		if infos[n].hasVolumesFrom {
			return fmt.Errorf("vpn.ingress.service: %s uses volumes_from: a VPN gateway mounts no other service's volumes", n)
		}
	}
	// No other service shares the pid or ipc namespace of the ingress or
	// a member (it could reach the gateway's processes and, with
	// capabilities, enter its network namespace) or mounts its volumes;
	// container: targets are refused for every template already
	// (checkCoreRefs).
	inNS := map[string]bool{}
	for _, n := range members {
		inNS[n] = true
	}
	for _, n := range names {
		for _, ns := range []struct{ key, val string }{{"pid", infos[n].pidOf}, {"ipc", infos[n].ipcOf}} {
			v := strings.TrimSpace(ns.val)
			if x, ok := strings.CutPrefix(v, "service:"); ok && inNS[strings.TrimSpace(x)] {
				return fmt.Errorf("vpn.ingress.service: %s shares the %s namespace of %s", n, ns.key, strings.TrimSpace(x))
			}
		}
		// volumes_from as Compose reads it: an optional service: prefix
		// (any case), the name up to the first ':', then exactly ro or rw.
		for _, e := range infos[n].volumesFrom {
			ref := strings.TrimSpace(e)
			if len(ref) >= len("service:") && strings.EqualFold(ref[:len("service:")], "service:") {
				ref = ref[len("service:"):]
			}
			name, mode, hasMode := strings.Cut(ref, ":")
			if hasMode && mode != "ro" && mode != "rw" {
				return fmt.Errorf("vpn.ingress.service: %s: volumes_from %s: the mode must be ro or rw", n, strings.TrimSpace(e))
			}
			if inNS[name] {
				return fmt.Errorf("vpn.ingress.service: %s mounts the volumes of %s (volumes_from)", n, name)
			}
		}
	}
	// A volume or bind a member mounts read-write is the gateway's
	// state: no other service mounts it (or, for a bind, a path inside or
	// above it). One every member mounts read-only is a handover into the
	// gateway (a key file a hook writes) and may be shared.
	for _, n := range names {
		if inNS[n] {
			continue
		}
		for _, om := range infos[n].mounts {
			for _, mem := range members {
				for _, mm := range infos[mem].mounts {
					if !mm.ro && sameMountSource(mm, om) {
						why := ""
						if mm.source != om.source {
							why = " (" + mm.source + ")"
						}
						return fmt.Errorf("vpn.ingress.service: %s mounts %s, which %s mounts read-write%s", n, om.source, mem, why)
					}
				}
			}
		}
	}
	if m.VPN.Ingress.ProxyProtocol != VPNProxyV2 {
		return fmt.Errorf("vpn.ingress.proxy_protocol: only v2")
	}
	return nil
}

// vpnNamespaceCaps (Task 19, an allowlist): a service in the ingress's
// network namespace isn't privileged (absent or literally false), drops
// every capability (cap_drop includes ALL), adds none but
// NET_BIND_SERVICE (the forwarder's :443; anything else, interpolation
// included, is refused) and has no devices or device_cgroup_rules key
// at all: without NET_ADMIN or NET_RAW a gateway can't take another
// gateway's address on portcullis-vpn. Same order and texts as
// templates' validate.py.
func vpnNamespaceCaps(n string, info composeServiceInfo) error {
	capName := func(c string) string { return strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(c)), "CAP_") }
	if info.privileged {
		return fmt.Errorf("vpn.ingress.service: %s is privileged", n)
	}
	if !slices.ContainsFunc(info.capDrop, func(c string) bool { return capName(c) == "ALL" }) {
		return fmt.Errorf("vpn.ingress.service: %s must set cap_drop: [ALL]", n)
	}
	for _, c := range info.capAdd {
		if capName(c) != "NET_BIND_SERVICE" {
			return fmt.Errorf("vpn.ingress.service: %s adds %s: a VPN gateway may add only NET_BIND_SERVICE", n, strings.TrimSpace(c))
		}
	}
	if info.deviceKey != "" {
		return fmt.Errorf("vpn.ingress.service: %s has %s: a VPN gateway runs userspace (no devices)", n, info.deviceKey)
	}
	return nil
}

// servesAdminUI: the template marks an admin UI (group_admin, or
// admin_paths the router can serve). A router with no path matcher, or
// one no path reasoning applies to, serves every path (fail closed).
func servesAdminUI(m *Manifest, ri *RouterInfo) bool {
	a := &m.Auth
	if a.GroupAdmin {
		return true
	}
	if len(a.AdminPaths) == 0 {
		return false
	}
	if ri == nil || len(ri.Paths) == 0 || len(ri.Opaque) > 0 {
		return true
	}
	for _, rp := range ri.Paths {
		for _, ap := range a.AdminPaths {
			if rulePathOverlaps(rp, ap) {
				return true
			}
		}
	}
	return false
}

// firstOverlap is the first pair of overlapping prefixes in ps (in
// order), if any.
func firstOverlap(ps []netip.Prefix) (netip.Prefix, netip.Prefix, bool) {
	for i := range ps {
		for j := i + 1; j < len(ps); j++ {
			if ps[i].Overlaps(ps[j]) {
				return ps[i], ps[j], true
			}
		}
	}
	return netip.Prefix{}, netip.Prefix{}, false
}

// ResolveVPNRanges is the instance's client ranges: the literals, and for
// "{{setting:KEY}}" the instance's value of that cidr setting (values:
// key → value). Every range must be an IPv4 /8–/30 prefix and none may
// overlap another (fail closed: an unset or invalid value is an error).
func ResolveVPNRanges(m *Manifest, values map[string]any) ([]netip.Prefix, error) {
	if m.VPN == nil {
		return nil, fmt.Errorf("the template has no vpn: block")
	}
	var out []netip.Prefix
	for i, r := range m.VPN.Ranges {
		s := r
		if key, ok := vpnSettingKey(r); ok {
			if !cidrSetting(m, key) {
				return nil, fmt.Errorf("vpn.ranges[%d]: {{setting:%s}} must name a cidr setting", i, key)
			}
			val, _ := values[key].(string)
			if val == "" {
				return nil, fmt.Errorf("vpn.ranges[%d]: the setting %s has no value", i, key)
			}
			s = val
		}
		p, ok := ParseVPNPrefix(s)
		if !ok {
			return nil, fmt.Errorf("vpn.ranges[%d]: %s is not an IPv4 prefix between /%d and /%d", i, s, VPNMinBits, VPNMaxBits)
		}
		out = append(out, p)
	}
	if a, b, ok := firstOverlap(out); ok {
		return nil, fmt.Errorf("vpn.ranges: %s overlaps %s", a, b)
	}
	return out, nil
}
