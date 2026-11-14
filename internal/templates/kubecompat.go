package templates

import (
	"net/netip"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Kubernetes compatibility (contract §3.4, §11.10): what the Hub's
// translator refuses on Kubernetes, judged on the template's compose and
// manifest with the instance's values. The reasons are shared byte for
// byte with the templates validator (testdata/runtime_vectors.json) and
// with the translator (runtime/kube: TestTranslatorRefusesWhatCompatRefuses).

// KubeBaselineCaps are the capabilities a service may add on Kubernetes
// (the Pod Security baseline's list).
var KubeBaselineCaps = []string{"AUDIT_WRITE", "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "MKNOD", "NET_BIND_SERVICE", "SETFCAP", "SETGID", "SETPCAP", "SETUID", "SYS_CHROOT"}

// DefaultKubeBindRoots are the shared-folder roots when the env carries
// none (HUB_OVERRIDE_BIND_ROOTS' default).
var DefaultKubeBindRoots = []string{"/srv", "/mnt", "/media"}

// EnvBindRoots is the key under which the Hub passes its bind roots
// (colon-separated) in RuntimeCompat's env: no env file can hold it.
const EnvBindRoots = "\x00bind_roots"

// DefaultVPNPort is the VPN's UDP port when the env doesn't set
// PORTCULLIS_VPN_PORT (a core port: no app may publish it).
const DefaultVPNPort = 51820

// KubeCorePorts are the ports no app may publish on Kubernetes (the
// admission policy's corePorts): 80, 443, the VPN port (env
// PORTCULLIS_VPN_PORT, default 51820), 8000, 8081, 8443 and 8444.
func KubeCorePorts(env map[string]string) []int {
	vpn := DefaultVPNPort
	if v := strings.TrimSpace(env["PORTCULLIS_VPN_PORT"]); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			vpn = n
		}
	}
	return []int{80, 443, vpn, 8000, 8081, 8443, 8444}
}

// AvahiServicesDirKey is Time Machine's Bonjour option: a host directory
// bound outside the roots, degraded on Kubernetes.
const AvahiServicesDirKey = "avahi_services_dir"

// shownUserRe: a user value is named in a reason only when it looks like
// a user or group name (no other instance value reaches the UI).
var shownUserRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,32}(:[A-Za-z0-9._-]{1,32})?$`)

// shownPathRe: a bind source is named only when it is a plain path.
var shownPathRe = regexp.MustCompile(`^/[A-Za-z0-9._/@+-]{0,200}$`)

// kubeCompat judges compose and m for Kubernetes: per service in compose
// order its devices, cap_add, user, network_mode, privileged, pid/ipc,
// binds, replicas and extra_hosts; then each manifest port (a core port); then the
// Avahi option.
func kubeCompat(compose []byte, m Manifest, env map[string]string) Compat {
	var c compatReasons
	services, err := orderedServices(compose)
	if err != nil {
		return Compat{Status: CompatRefused, Reasons: []string{"compose.yml can't be read: " + err.Error()}}
	}
	roots := DefaultKubeBindRoots
	if v, ok := env[EnvBindRoots]; ok {
		roots = strings.Split(v, ":")
	}
	for _, s := range services {
		c.kubeService(s.name, s.node, env, roots)
	}
	first := ""
	if len(services) > 0 {
		first = services[0].name
	}
	core := KubeCorePorts(env)
	for _, p := range m.Ports {
		n := hostPort(p, env)
		if n > 0 && slices.Contains(core, n) {
			svc := p.Service
			if svc == "" {
				svc = first
			}
			c.refuse("service %s publishes port %d, a core port", svc, n)
		}
	}
	if m.Settings != nil {
		for _, o := range m.Settings.Options {
			if o.Key == AvahiServicesDirKey && strings.TrimSpace(env[o.Key]) != "" {
				c.degrade("the Avahi services directory binds a host path outside the shared-folder roots: leave it empty and connect by address")
			}
		}
	}
	return c.verdict()
}

// verdict is the result of the collected reasons.
func (c *compatReasons) verdict() Compat {
	switch {
	case len(c.refused) > 0:
		return Compat{Status: CompatRefused, Reasons: c.refused}
	case len(c.degraded) > 0:
		return Compat{Status: CompatDegraded, Reasons: c.degraded}
	}
	return Compat{Status: CompatOK, Reasons: []string{}}
}

func scalarValue(n *yaml.Node, env map[string]string) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return strings.TrimSpace(resolve(n.Value, env))
}

func (c *compatReasons) kubeService(name string, s *yaml.Node, env map[string]string, roots []string) {
	tun := "service " + name + " uses TUN/NET_ADMIN (not on Kubernetes; prefer a userspace mode)"
	devs, ok := scalars(field(s, "devices"))
	if !ok {
		c.refuse("service %s passes host devices (not on Kubernetes)", name)
	}
	for _, d := range devs {
		switch src := resolve(splitOutsideVars(d)[0], env); src {
		case "":
		case "/dev/null":
			c.degrade("service %s has device slots: host devices can't be passed on Kubernetes", name)
		case "/dev/net/tun":
			c.refuse("%s", tun)
		default:
			c.refuse("service %s passes host devices (not on Kubernetes)", name)
		}
	}
	caps, _ := scalars(field(s, "cap_add"))
	for _, cp := range caps {
		v := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(resolve(cp, env))), "CAP_")
		switch {
		case v == "":
		case v == "NET_ADMIN":
			c.refuse("%s", tun)
		case !slices.Contains(KubeBaselineCaps, v):
			if strings.Trim(v, "ABCDEFGHIJKLMNOPQRSTUVWXYZ_") != "" || len(v) > 32 {
				v = "a capability"
			}
			c.refuse("service %s adds %s, outside the Kubernetes baseline", name, v)
		}
	}
	if u := scalarValue(field(s, "user"), env); u != "" {
		uid, gid, _ := strings.Cut(u, ":")
		if !numeric(uid) || (gid != "" && !numeric(gid)) {
			shown := u
			if !shownUserRe.MatchString(u) {
				shown = "a non-numeric value"
			}
			c.refuse("service %s runs as user %s: Kubernetes needs a numeric uid", name, shown)
		}
	}
	if scalarValue(field(s, "network_mode"), env) == "host" {
		c.refuse("service %s uses network_mode: host (not on Kubernetes)", name)
	}
	if v := scalarValue(field(s, "privileged"), env); v == "true" || v == "True" || v == "yes" {
		c.refuse("service %s is privileged (not on Kubernetes)", name)
	}
	for _, ns := range []string{"pid", "ipc"} {
		if scalarValue(field(s, ns), env) == "host" {
			c.refuse("service %s shares the host's %s namespace (not on Kubernetes)", name, ns)
		}
	}
	for _, src := range bindSources(field(s, "volumes"), env) {
		if !strings.HasPrefix(src, "/") || underRoots(src, roots) {
			continue
		}
		shown := src
		if !shownPathRe.MatchString(src) {
			shown = "a host path"
		}
		c.refuse("service %s binds %s, outside the shared-folder roots (not on Kubernetes)", name, shown)
	}
	for _, hp := range publishedHostIPs(field(s, "ports"), env) {
		c.refuse("service %s publishes %s on %s (not on Kubernetes)", name, hp[1], hp[0])
	}
	if replicasAboveOne(s, env) {
		c.refuse("service %s sets replicas above 1 (not on Kubernetes)", name)
	}
	if eh := field(s, "extra_hosts"); eh != nil && eh.Tag != "!!null" && len(eh.Content) > 0 || eh != nil && eh.Kind == yaml.ScalarNode && eh.Tag != "!!null" && eh.Value != "" {
		c.refuse("service %s sets extra_hosts (not on Kubernetes)", name)
	}
}

func numeric(s string) bool { return s != "" && strings.Trim(s, "0123456789") == "" }

// underRoots: p (absolute) is at or under one of roots.
func underRoots(p string, roots []string) bool {
	p = path.Clean(p)
	for _, r := range roots {
		r = path.Clean(strings.TrimSpace(r))
		if r == "" || r == "." || !strings.HasPrefix(r, "/") {
			continue
		}
		if p == r || strings.HasPrefix(p, strings.TrimSuffix(r, "/")+"/") {
			return true
		}
	}
	return false
}

// bindSources are a service's bind sources (short syntax "src:dst…"
// with a path source, long syntax type bind), resolved; named volumes
// are not binds.
func bindSources(vols *yaml.Node, env map[string]string) []string {
	if vols == nil || vols.Kind != yaml.SequenceNode {
		return nil
	}
	var out []string
	for _, v := range vols.Content {
		switch v.Kind {
		case yaml.ScalarNode:
			parts := splitOutsideVars(v.Value)
			if len(parts) < 2 {
				continue // an anonymous volume
			}
			src := strings.TrimSpace(resolve(parts[0], env))
			if strings.HasPrefix(src, "/") || strings.HasPrefix(src, ".") || strings.HasPrefix(src, "~") {
				out = append(out, src)
			}
		case yaml.MappingNode:
			if scalarValue(field(v, "type"), env) != "bind" {
				continue
			}
			if src := scalarValue(field(v, "source"), env); src != "" {
				out = append(out, src)
			}
		}
	}
	return out
}

// replicasAboveOne: compose scale above 1 (0 and 1 map to the
// Deployment's replicas; deploy is refused on every runtime, §3).
func replicasAboveOne(s *yaml.Node, env map[string]string) bool {
	above := func(n *yaml.Node) bool {
		v := scalarValue(n, env)
		if v == "" {
			return false
		}
		k, err := strconv.Atoi(v)
		return err != nil || k > 1
	}
	return above(field(s, "scale"))
}

// publishedHostIPs are a service's published ports bound to a specific
// address other than the wildcard (0.0.0.0, ::, empty) or loopback
// (127.0.0.0/8, ::1: not published at all on Kubernetes): [ip, port]
// pairs. A LoadBalancer can't keep such a binding; widening it silently
// is never done.
func publishedHostIPs(ports *yaml.Node, env map[string]string) [][2]string {
	if ports == nil || ports.Kind != yaml.SequenceNode {
		return nil
	}
	var out [][2]string
	for _, p := range ports.Content {
		ip, port := "", ""
		switch p.Kind {
		case yaml.ScalarNode:
			v := strings.TrimSpace(resolve(p.Value, env))
			// [ip:]host:container[/proto]; an IPv6 ip is bracketed.
			if strings.HasPrefix(v, "[") {
				if i := strings.Index(v, "]:"); i > 0 {
					ip, v = v[1:i], v[i+2:]
				}
			} else if parts := strings.Split(v, ":"); len(parts) == 3 {
				ip, v = parts[0], parts[1]+":"+parts[2]
			}
			port, _, _ = strings.Cut(v, ":")
		case yaml.MappingNode:
			ip, port = scalarValue(field(p, "host_ip"), env), scalarValue(field(p, "published"), env)
		}
		if ip == "" || ip == "0.0.0.0" || ip == "::" {
			continue
		}
		if a, err := netip.ParseAddr(ip); err == nil && a.IsLoopback() {
			continue
		}
		shown := ip
		if _, err := netip.ParseAddr(ip); err != nil {
			shown = "a host address"
		}
		if port == "" {
			port = "a port"
		}
		out = append(out, [2]string{shown, port})
	}
	return out
}
