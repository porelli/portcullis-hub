package templates

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Rootless compatibility (contract §11.10, rootless Podman): how a
// template or instance fares under rootless Podman, judged before
// anything is created or started. The reason strings are shared byte for
// byte with the templates validator (testdata/rootless_vectors.json, a
// copy of portcullis-templates tests/rootless_vectors.json).

// Compat statuses.
const (
	CompatOK       = "ok"
	CompatDegraded = "degraded"
	CompatRefused  = "refused"
)

// Compat is a rootless compatibility verdict: Status and the reasons in
// rule order (only the refused ones when refused).
type Compat struct {
	Status  string   `json:"status"`
	Reasons []string `json:"reasons"`
}

// MaxRootlessID is the highest container id the rootless namespace maps.
const MaxRootlessID = 65535

// deviceSourceRe: a resolved device source is named in a reason only when
// it looks like a device path (no other instance value reaches the UI).
var deviceSourceRe = regexp.MustCompile(`^/dev/[A-Za-z0-9._/-]+$`)

// compatReasons collects reasons in order, each once.
type compatReasons struct {
	refused, degraded []string
}

func addOnce(list *[]string, s string) {
	for _, x := range *list {
		if x == s {
			return
		}
	}
	*list = append(*list, s)
}

func (c *compatReasons) refuse(format string, args ...any) {
	addOnce(&c.refused, fmt.Sprintf(format, args...))
}

func (c *compatReasons) degrade(format string, args ...any) {
	addOnce(&c.degraded, fmt.Sprintf(format, args...))
}

// RootlessCompat judges compose and manifest m with the instance's
// effective values env (nil = the defaults; port keys carry the
// instance's host ports) against the host's unprivileged port start.
//
// Rules, per service in compose order — devices (a source other than
// /dev/null and /dev/net/tun refused, /dev/null degraded, /dev/net/tun
// degraded), cap_add (SYS_RAWIO / SYS_ADMIN refused, NET_ADMIN degraded),
// user / group_add ids above 65535 refused, network_mode host degraded —
// then each manifest port (below portStart refused, UDP degraded), then
// folder runs_as ids above 65535 refused. Any refused reason makes the
// result refused with the refused reasons; else any degraded reason makes
// it degraded; else ok. An unreadable compose file is refused.
func RootlessCompat(compose []byte, m Manifest, env map[string]string, portStart int) Compat {
	var c compatReasons
	services, err := orderedServices(compose)
	if err != nil {
		return Compat{Status: CompatRefused, Reasons: []string{"compose.yml can't be read: " + err.Error()}}
	}
	for _, s := range services {
		c.service(s.name, s.node, env, portStart)
	}
	for _, p := range m.Ports {
		c.port(p, env, portStart)
	}
	c.runsAs(m)
	switch {
	case len(c.refused) > 0:
		return Compat{Status: CompatRefused, Reasons: c.refused}
	case len(c.degraded) > 0:
		return Compat{Status: CompatDegraded, Reasons: c.degraded}
	}
	return Compat{Status: CompatOK, Reasons: []string{}}
}

type namedService struct {
	name string
	node *yaml.Node
}

// orderedServices is compose's services in file order (anchors and merge
// keys resolved by decoding each service into a node of its own).
func orderedServices(compose []byte) ([]namedService, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(compose, &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) == 0 {
		return nil, nil
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("not a mapping")
	}
	var out []namedService
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value != "services" {
			continue
		}
		svcs := root.Content[i+1]
		if svcs.Kind == yaml.AliasNode {
			svcs = svcs.Alias
		}
		if svcs.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("services is not a mapping")
		}
		for j := 0; j+1 < len(svcs.Content); j += 2 {
			// Decode then re-encode: merge keys and aliases resolved.
			var v map[string]any
			if err := svcs.Content[j+1].Decode(&v); err != nil {
				return nil, fmt.Errorf("service %s: %v", svcs.Content[j].Value, err)
			}
			var n yaml.Node
			if err := n.Encode(v); err != nil {
				return nil, err
			}
			out = append(out, namedService{name: svcs.Content[j].Value, node: &n})
		}
	}
	return out, nil
}

// field is service s's value for key (nil when absent).
func field(s *yaml.Node, key string) *yaml.Node {
	if s == nil || s.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(s.Content); i += 2 {
		if s.Content[i].Value == key {
			return s.Content[i+1]
		}
	}
	return nil
}

// scalars is n's scalar items (n a sequence), else n itself as one; ok
// false for any non-scalar item.
func scalars(n *yaml.Node) ([]string, bool) {
	if n == nil || n.Tag == "!!null" {
		return nil, true
	}
	if n.Kind == yaml.ScalarNode {
		return []string{n.Value}, true
	}
	if n.Kind != yaml.SequenceNode {
		return nil, false
	}
	var out []string
	ok := true
	for _, it := range n.Content {
		if it.Kind != yaml.ScalarNode {
			ok = false
			continue
		}
		out = append(out, it.Value)
	}
	return out, ok
}

var varRe = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-?])([^}]*))?\}`)

// resolve interpolates s compose-style from env: ${V}, ${V:-d} (empty or
// unset → d), ${V-d} (unset → d), ${V:?…} / ${V?…} (the value); $$ is a
// literal dollar.
func resolve(s string, env map[string]string) string {
	const esc = "\x00"
	s = strings.ReplaceAll(s, "$$", esc)
	s = varRe.ReplaceAllStringFunc(s, func(m string) string {
		g := varRe.FindStringSubmatch(m)
		v, set := env[g[1]]
		switch g[2] {
		case ":-":
			if v == "" {
				return g[3]
			}
		case "-":
			if !set {
				return g[3]
			}
		}
		return v
	})
	return strings.ReplaceAll(s, esc, "$")
}

// splitOutsideVars splits s at ':' outside ${…}.
func splitOutsideVars(s string) []string {
	var parts []string
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '$' && i+1 < len(s) && s[i+1] == '{':
			depth++
			i++
		case s[i] == '}' && depth > 0:
			depth--
		case s[i] == ':' && depth == 0:
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	return append(parts, s[start:])
}

func (c *compatReasons) service(name string, s *yaml.Node, env map[string]string, portStart int) {
	tun := fmt.Sprintf("service %s uses TUN/NET_ADMIN inside the rootless network namespace (prefer a userspace mode)", name)
	devs, ok := scalars(field(s, "devices"))
	if !ok {
		c.refuse("service %s passes the host device a non-device source: device access needs host root", name)
	}
	for _, d := range devs {
		src := resolve(splitOutsideVars(d)[0], env)
		switch {
		case src == "":
			// An unset source: compose itself refuses the file.
		case src == "/dev/null":
			c.degrade("service %s has device slots: host devices can't be passed under rootless Podman", name)
		case src == "/dev/net/tun":
			c.degrade("%s", tun)
		default:
			shown := "a non-device source"
			if deviceSourceRe.MatchString(src) {
				shown = src
			}
			c.refuse("service %s passes the host device %s: device access needs host root", name, shown)
		}
	}
	caps, _ := scalars(field(s, "cap_add"))
	for _, cp := range caps {
		v := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(resolve(cp, env))), "CAP_")
		switch v {
		case "SYS_RAWIO", "SYS_ADMIN", "ALL":
			if v == "ALL" {
				v = "SYS_ADMIN"
			}
			c.refuse("service %s needs %s (raw device access needs host root)", name, v)
		case "NET_ADMIN":
			c.degrade("%s", tun)
		}
	}
	if u := field(s, "user"); u != nil && u.Kind == yaml.ScalarNode {
		for _, part := range strings.Split(resolve(u.Value, env), ":") {
			c.id(name, part)
		}
	}
	groups, _ := scalars(field(s, "group_add"))
	for _, g := range groups {
		c.id(name, resolve(g, env))
	}
	if nm := field(s, "network_mode"); nm != nil && nm.Kind == yaml.ScalarNode && resolve(nm.Value, env) == "host" {
		c.degrade("host networking: published ports must stay at or above %d", portStart)
	}
}

// id refuses a numeric id above MaxRootlessID.
func (c *compatReasons) id(service, v string) {
	v = strings.TrimSpace(v)
	if v == "" || strings.Trim(v, "0123456789") != "" {
		return
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil || n > MaxRootlessID {
		c.refuse("service %s runs as id %s, outside the rootless id range (0–65535)", service, strings.TrimLeft(v, "0"))
	}
}

// hostPort is a manifest port's effective host port (the range's start for
// a range): env's value for its key when set, else the default.
func hostPort(p Port, env map[string]string) int {
	v := ""
	if env != nil {
		v = strings.TrimSpace(env[p.Key])
	}
	if p.Range != "" {
		r := p.Range
		if v != "" {
			r = v
		}
		start, _, _ := strings.Cut(r, "-")
		n, err := strconv.Atoi(strings.TrimSpace(start))
		if err != nil {
			return 0
		}
		return n
	}
	if v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return p.Default
}

func (c *compatReasons) port(p Port, env map[string]string, portStart int) {
	n := hostPort(p, env)
	if n <= 0 {
		return
	}
	proto := p.Protocol
	if proto == "" {
		proto = "tcp"
	}
	if n < portStart {
		c.refuse("host port %d/%s is below net.ipv4.ip_unprivileged_port_start (%d): lower it to %d on the host to allow it (any local user can then bind ports from %d)", n, proto, portStart, n, n)
	}
	if proto == "udp" {
		c.degrade("UDP clients on port %d appear with a rewritten source address", n)
	}
}

// runsAs refuses a folder option's runs_as uid / gid above MaxRootlessID,
// naming the option's target service (else the option's key).
func (c *compatReasons) runsAs(m Manifest) {
	if m.Settings == nil {
		return
	}
	for _, o := range m.Settings.Options {
		if o.Folder == nil || o.Folder.RunsAs == nil {
			continue
		}
		svc := o.Key
		if o.Target != nil && o.Target.Service != "" {
			svc = o.Target.Service
		}
		for _, id := range []*int{o.Folder.RunsAs.UID, o.Folder.RunsAs.GID} {
			if id != nil && (*id < 0 || *id > MaxRootlessID) {
				c.refuse("service %s runs as id %d, outside the rootless id range (0–65535)", svc, *id)
			}
		}
	}
}
