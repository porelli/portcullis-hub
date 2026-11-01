package hub

import (
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/templates"
)

// The custom override (Expert mode) is the admin's own compose override for
// one app: <data>/overrides/<id>.user.yml, passed to compose last
// (-f compose.yml -f <hub override> -f <custom override>). It survives
// template syncs. It is validated on save and again before every compose
// up, and may not touch anything Portcullis' routing and access guarantees
// rest on: group-gate keys everything by subdomain from the template's
// Traefik labels, the Hub's override sets each router's TLS options and
// middlewares, and isolation relies on the container staying in its own
// namespaces on its own networks. So the routing the Hub computes from the
// template (routes, subdomains, published snapshot, exposure drift) stays
// exact by construction; its host ports count in the port checks.

// overrideServiceKeys are the service attributes a custom override may set.
var overrideServiceKeys = map[string]bool{
	"image": true, "command": true, "entrypoint": true, "environment": true, "labels": true,
	"volumes": true, "ports": true, "expose": true, "restart": true, "healthcheck": true,
	"user": true, "working_dir": true, "hostname": true, "domainname": true,
	"mem_limit": true, "mem_reservation": true, "memswap_limit": true, "mem_swappiness": true,
	"cpus": true, "cpu_shares": true, "cpuset": true, "pids_limit": true, "shm_size": true,
	"ulimits": true, "logging": true, "tmpfs": true, "extra_hosts": true,
	"dns": true, "dns_search": true, "dns_opt": true, "stop_grace_period": true, "stop_signal": true,
	"init": true, "read_only": true, "cap_drop": true, "tty": true, "stdin_open": true,
	"pull_policy": true, "platform": true, "depends_on": true, "oom_score_adj": true,
}

// overrideDenied explains the refusals that matter most.
var overrideDenied = map[string]string{
	"privileged":          "privileged containers can take over the host",
	"cap_add":             "added capabilities weaken the container's isolation",
	"devices":             "host devices weaken the container's isolation",
	"device_cgroup_rules": "host devices weaken the container's isolation",
	"security_opt":        "it can disable seccomp/AppArmor confinement",
	"network_mode":        "host/other network namespaces bypass the Traefik route group-gate guards",
	"networks":            "network attachments decide what can reach the app around Traefik (portcullis-proxy routing)",
	"pid":                 "sharing the host's (or another container's) PID namespace breaks isolation",
	"ipc":                 "sharing the host's (or another container's) IPC namespace breaks isolation",
	"uts":                 "sharing the host's UTS namespace breaks isolation",
	"userns_mode":         "it can disable user-namespace remapping",
	"cgroup":              "it can share the host's cgroup namespace",
	"cgroup_parent":       "it moves the container out of Docker's cgroup",
	"sysctls":             "kernel parameters are not the override's business",
	"volumes_from":        "it mounts another container's volumes",
	"extends":             "it pulls in configuration from other files the Hub can't check",
	"env_file":            "env files are read from the core checkout (secrets); use environment instead",
	"build":               "the Hub doesn't build images",
	"links":               "links attach the app to other services' networks",
	"external_links":      "links attach the app to other services' networks",
	"container_name":      "the Hub identifies containers by compose project",
	"profiles":            "a profile could hide the template's services from compose up",
	"deploy":              "use mem_limit / cpus for resource limits",
	"configs":             "configs are read from files the Hub can't check",
	"secrets":             "secrets are read from files the Hub can't check",
	"group_add":           "extra groups can grant access to host resources",
	"runtime":             "a different runtime changes the container's isolation",
	"isolation":           "a different isolation technology changes the container's isolation",
}

// DefaultOverrideBindRoots are the host directories a custom override may
// bind-mount from when HUB_OVERRIDE_BIND_ROOTS is unset.
var DefaultOverrideBindRoots = []string{"/srv", "/mnt", "/media"}

// systemRoots may never be (or be inside) a bind root.
var systemRoots = []string{"/proc", "/sys", "/dev", "/etc", "/boot", "/root", "/run", "/var/run", "/var/lib",
	"/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/tmp", "/var/tmp"}

// sensitiveHostPaths may not lie inside a bind root.
var sensitiveHostPaths = []string{"/var/run/docker.sock", "/run/docker.sock", "/var/lib/docker", "/run/containerd", "/var/lib/containerd"}

// ParseBindRoots validates HUB_OVERRIDE_BIND_ROOTS (colon-separated absolute
// paths; "" = the defaults). coreHostDir is the core checkout on the host:
// a root may neither contain it nor lie inside it.
func ParseBindRoots(v, coreHostDir string) ([]string, error) {
	raw := DefaultOverrideBindRoots
	if strings.TrimSpace(v) != "" {
		raw = strings.Split(v, ":")
	}
	var out []string
	for _, r := range raw {
		r = strings.TrimSpace(r)
		if !strings.HasPrefix(r, "/") || strings.Contains(r, "$") || HasDotDot(r) {
			return nil, fmt.Errorf("HUB_OVERRIDE_BIND_ROOTS: %q must be an absolute path without \"..\" or variables", r)
		}
		c := path.Clean(r)
		if c == "/" {
			return nil, fmt.Errorf("HUB_OVERRIDE_BIND_ROOTS: the host's root directory can't be a bind root")
		}
		for _, sys := range systemRoots {
			if pathUnder(c, sys) || pathUnder(sys, c) {
				return nil, fmt.Errorf("HUB_OVERRIDE_BIND_ROOTS: %s is (or contains) the system path %s", c, sys)
			}
		}
		for _, s := range sensitiveHostPaths {
			if pathUnder(s, c) {
				return nil, fmt.Errorf("HUB_OVERRIDE_BIND_ROOTS: %s contains %s", c, s)
			}
		}
		if core := path.Clean(coreHostDir); coreHostDir != "" && (pathUnder(core, c) || pathUnder(c, core)) {
			return nil, fmt.Errorf("HUB_OVERRIDE_BIND_ROOTS: %s overlaps the Portcullis core checkout %s", c, core)
		}
		out = append(out, c)
	}
	return out, nil
}

// HasDotDot reports whether p has a ".." segment.
func HasDotDot(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

var volumeNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)

// OverrideRules is the human-readable list the UI shows next to the editor.
var OverrideRules = []string{
	"Top level: only services, volumes and networks.",
	"Services: only ones the template defines; allowed keys: " + strings.Join(sortedKeys(overrideServiceKeys), ", ") + ".",
	"Refused: privileged, cap_add, devices, security_opt, network_mode, networks, pid, ipc, uts, userns_mode, sysctls, volumes_from, extends, env_file, build, links, profiles, deploy and anything else not listed.",
	"Labels: no traefik.* (routers, rules, middlewares, TLS options — group-gate and the Hub's override depend on them) and no com.docker.compose.*.",
	"Volumes: named volumes, ./templates/<app>/…, or bind mounts of absolute paths under the allowed roots (HUB_OVERRIDE_BIND_ROOTS, default /srv, /mnt, /media); everything else is refused. No \"..\", no sockets. Symlinks on the host are not resolved: what lives under the roots is the operator's responsibility.",
	"Ports: literal host ports only; they are checked against the other enabled apps' ports.",
	"Top-level volumes: only labels (no driver, driver_opts, external or name). Top-level networks: only networks the template declares and doesn't mark external, with labels, driver_opts, enable_ipv6, ipam.",
	"No YAML tags (!reset, !override): they could strip the template's labels or networks.",
	"No variables: every key and value is checked for \"$\" (compose would interpolate it after the Hub's checks); write $$ for a literal dollar sign.",
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// parsedOverride is what the Hub uses of a valid custom override.
type parsedOverride struct {
	ports []portBinding
}

// parseUserOverride validates a custom override against t's compose file.
// Empty (or comment-only) content returns (nil, nil).
func (h *Hub) parseUserOverride(t *templates.Template, data []byte) (*parsedOverride, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("invalid YAML: %v", err)
	}
	if len(root.Content) == 0 || (root.Content[0].Kind == yaml.ScalarNode && root.Content[0].Tag == "!!null") {
		return nil, nil
	}
	if err := checkTags(&root); err != nil {
		return nil, err
	}
	if err := checkNoInterpolation(&root); err != nil {
		return nil, err
	}
	var doc map[string]interface{}
	if err := root.Decode(&doc); err != nil || root.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("the override must be a mapping (services: …)")
	}

	var base struct {
		Services map[string]interface{}            `yaml:"services"`
		Networks map[string]map[string]interface{} `yaml:"networks"`
	}
	if err := yaml.Unmarshal(t.ReadCompose(), &base); err != nil {
		return nil, fmt.Errorf("the template's compose.yml does not parse: %v", err)
	}
	out := &parsedOverride{}
	for _, k := range sortedMapKeys(doc) {
		v := doc[k]
		switch k {
		case "services":
			svcs, ok := v.(map[string]interface{})
			if !ok && v != nil {
				return nil, fmt.Errorf("services must be a mapping")
			}
			for _, name := range sortedMapKeys(svcs) {
				if _, ok := base.Services[name]; !ok {
					return nil, fmt.Errorf("service %s is not defined by the template (services: %s)", name, strings.Join(templates.Services(t.ReadCompose()), ", "))
				}
				ports, err := h.checkOverrideService(t, name, svcs[name], base.Services)
				if err != nil {
					return nil, fmt.Errorf("service %s: %w", name, err)
				}
				out.ports = append(out.ports, ports...)
			}
		case "volumes":
			vols, ok := v.(map[string]interface{})
			if !ok && v != nil {
				return nil, fmt.Errorf("volumes must be a mapping")
			}
			for _, name := range sortedMapKeys(vols) {
				if !volumeNameRe.MatchString(name) {
					return nil, fmt.Errorf("volume name %q is invalid", name)
				}
				if err := onlyKeys(vols[name], "volume "+name, "labels"); err != nil {
					return nil, fmt.Errorf("%w (driver, driver_opts, external and name could point at host paths or other apps' data)", err)
				}
			}
		case "networks":
			nets, ok := v.(map[string]interface{})
			if !ok && v != nil {
				return nil, fmt.Errorf("networks must be a mapping")
			}
			for _, name := range sortedMapKeys(nets) {
				bn, declared := base.Networks[name]
				if !declared {
					return nil, fmt.Errorf("network %s is not declared by the template", name)
				}
				if ext, has := bn["external"]; (has && ext != false && ext != nil) || bn["name"] != nil {
					return nil, fmt.Errorf("network %s is external or named (e.g. portcullis-proxy): it can't be changed", name)
				}
				if err := onlyKeys(nets[name], "network "+name, "labels", "driver_opts", "enable_ipv6", "ipam"); err != nil {
					return nil, err
				}
			}
		default:
			return nil, fmt.Errorf("top-level key %q is not allowed (only services, volumes, networks)", k)
		}
	}
	return out, nil
}

// checkTags refuses YAML tags (compose's !reset / !override can remove
// what the template set, e.g. its labels or networks).
func checkTags(n *yaml.Node) error {
	if n.Tag != "" && strings.HasPrefix(n.Tag, "!") && !strings.HasPrefix(n.Tag, "!!") {
		return fmt.Errorf("line %d: YAML tag %s is not allowed (!reset / !override could strip the template's labels or networks)", n.Line, n.Tag)
	}
	if n.Style&yaml.TaggedStyle != 0 && !strings.HasPrefix(n.Tag, "!!") {
		return fmt.Errorf("line %d: YAML tag %s is not allowed", n.Line, n.Tag)
	}
	for _, c := range n.Content {
		if err := checkTags(c); err != nil {
			return err
		}
	}
	return nil
}

// checkNoInterpolation refuses any unescaped "$" in a key or value: compose
// interpolates ${VAR} everywhere, so "${T}raefik.enable" would pass the
// label check and become traefik.enable afterwards. "$$" is compose's
// literal dollar sign.
func checkNoInterpolation(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode && strings.Contains(strings.ReplaceAll(n.Value, "$$", ""), "$") {
		v := n.Value
		if len(v) > 60 {
			v = v[:60] + "…"
		}
		return fmt.Errorf("line %d: %q: variables are not allowed (compose would interpolate them after the Hub's checks); write $$ for a literal $", n.Line, v)
	}
	for _, c := range n.Content {
		if err := checkNoInterpolation(c); err != nil {
			return err
		}
	}
	return nil
}

func sortedMapKeys(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func onlyKeys(v interface{}, what string, allowed ...string) error {
	if v == nil {
		return nil
	}
	m, ok := v.(map[string]interface{})
	if !ok {
		return fmt.Errorf("%s must be a mapping", what)
	}
	ok2 := map[string]bool{}
	for _, a := range allowed {
		ok2[a] = true
	}
	for _, k := range sortedMapKeys(m) {
		if !ok2[k] {
			return fmt.Errorf("%s: %q is not allowed (allowed: %s)", what, k, strings.Join(allowed, ", "))
		}
	}
	return nil
}

// checkOverrideService validates one service's attributes and returns the
// host ports it publishes.
func (h *Hub) checkOverrideService(t *templates.Template, name string, v interface{}, baseServices map[string]interface{}) ([]portBinding, error) {
	if v == nil {
		return nil, nil
	}
	svc, ok := v.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("must be a mapping")
	}
	var ports []portBinding
	for _, k := range sortedMapKeys(svc) {
		val := svc[k]
		if why, denied := overrideDenied[k]; denied {
			return nil, fmt.Errorf("%s is not allowed: %s", k, why)
		}
		if !overrideServiceKeys[k] {
			return nil, fmt.Errorf("%s is not allowed in a custom override", k)
		}
		switch k {
		case "labels":
			if err := checkOverrideLabels(val); err != nil {
				return nil, err
			}
		case "volumes":
			list, ok := val.([]interface{})
			if !ok {
				return nil, fmt.Errorf("volumes must be a list")
			}
			for _, item := range list {
				if err := h.checkOverrideVolume(t.ID, item); err != nil {
					return nil, err
				}
			}
		case "ports":
			list, ok := val.([]interface{})
			if !ok {
				return nil, fmt.Errorf("ports must be a list")
			}
			for _, item := range list {
				pb, err := parseOverridePort(t.ID, item)
				if err != nil {
					return nil, err
				}
				if pb != nil {
					ports = append(ports, *pb)
				}
			}
		case "depends_on":
			var deps []string
			switch d := val.(type) {
			case []interface{}:
				for _, x := range d {
					deps = append(deps, fmt.Sprint(x))
				}
			case map[string]interface{}:
				deps = sortedMapKeys(d)
			default:
				return nil, fmt.Errorf("depends_on must be a list or a mapping")
			}
			for _, d := range deps {
				if _, ok := baseServices[d]; !ok {
					return nil, fmt.Errorf("depends_on: service %s is not defined by the template", d)
				}
			}
		}
	}
	return ports, nil
}

func checkOverrideLabels(v interface{}) error {
	var keys []string
	switch l := v.(type) {
	case map[string]interface{}:
		keys = sortedMapKeys(l)
	case []interface{}:
		for _, item := range l {
			s, ok := item.(string)
			if !ok {
				return fmt.Errorf("label %v is not a string", item)
			}
			k, _, _ := strings.Cut(s, "=")
			keys = append(keys, k)
		}
	case nil:
	default:
		return fmt.Errorf("labels must be a mapping or a list")
	}
	for _, k := range keys {
		lk := strings.ToLower(strings.TrimSpace(k))
		switch {
		case strings.HasPrefix(lk, "traefik."):
			return fmt.Errorf("label %s is not allowed: Traefik routing, middlewares and TLS options come from the template and the Hub (group-gate depends on them)", k)
		case strings.HasPrefix(lk, "com.docker.compose."):
			return fmt.Errorf("label %s is not allowed: the Hub identifies the app's containers by these", k)
		}
	}
	return nil
}

func (h *Hub) checkOverrideVolume(id string, item interface{}) error {
	switch v := item.(type) {
	case string:
		parts := strings.Split(v, ":")
		if len(parts) == 1 {
			return nil // anonymous volume
		}
		return h.checkMountSource(id, parts[0], "")
	case map[string]interface{}:
		if err := onlyKeys(v, "volume", "type", "source", "target", "read_only", "bind", "volume", "tmpfs", "consistency"); err != nil {
			return err
		}
		typ, _ := v["type"].(string)
		src, _ := v["source"].(string)
		if b, ok := v["bind"].(map[string]interface{}); ok {
			if p, _ := b["propagation"].(string); strings.Contains(p, "shared") || strings.Contains(p, "slave") {
				return fmt.Errorf("volume %s: bind propagation %q is not allowed", src, p)
			}
		}
		switch typ {
		case "tmpfs":
			return nil
		case "bind", "volume":
			return h.checkMountSource(id, src, typ)
		default:
			return fmt.Errorf("volume type %q is not allowed (bind, volume, tmpfs)", typ)
		}
	default:
		return fmt.Errorf("volume entry %v must be a string or a mapping", item)
	}
}

// checkMountSource checks a volume source: a named volume, or a bind mount
// of an allowed host path.
func (h *Hub) checkMountSource(id, src, typ string) error {
	if strings.Contains(src, "$") {
		return fmt.Errorf("volume source %q: variables are not allowed (the Hub must see the real path)", src)
	}
	if src == "" {
		if typ == "volume" {
			return nil // anonymous
		}
		return fmt.Errorf("bind mount without a source")
	}
	isPath := strings.HasPrefix(src, "/") || strings.HasPrefix(src, ".") || strings.HasPrefix(src, "~")
	if !isPath {
		if typ == "bind" || !volumeNameRe.MatchString(src) {
			return fmt.Errorf("volume source %q is neither a volume name nor an absolute path", src)
		}
		return nil
	}
	if typ == "volume" {
		return fmt.Errorf("volume source %q: a named volume can't be a path", src)
	}
	if strings.HasPrefix(src, "~") {
		return fmt.Errorf("volume source %q: use an absolute path", src)
	}
	if HasDotDot(src) {
		return fmt.Errorf("volume source %q: \"..\" segments are not allowed", src)
	}
	if !strings.HasPrefix(src, "/") {
		rel := path.Clean(src)
		if rel == "templates/"+id || strings.HasPrefix(rel, "templates/"+id+"/") {
			return nil
		}
		return fmt.Errorf("volume source %q: relative paths resolve in the Portcullis core checkout (secrets, .env); only ./templates/%s/… is allowed", src, id)
	}
	p := path.Clean(src) // "//", "/./" → "/"
	if p == "/" {
		return fmt.Errorf("volume source %q: the host's root directory is not allowed", src)
	}
	if strings.HasSuffix(p, ".sock") {
		return fmt.Errorf("volume source %s: sockets are not allowed", src)
	}
	for _, r := range h.bindRoots {
		if pathUnder(p, r) {
			return nil
		}
	}
	return fmt.Errorf("volume source %s: bind mounts must be under %s (HUB_OVERRIDE_BIND_ROOTS) or ./templates/%s/", src, strings.Join(h.bindRoots, ", "), id)
}

// pathUnder reports whether clean absolute path p is root or inside it.
func pathUnder(p, root string) bool {
	if root == "/" {
		return strings.HasPrefix(p, "/")
	}
	return p == root || strings.HasPrefix(p, root+"/")
}

// parseOverridePort parses a ports entry; nil means no host port is
// published (container port only).
func parseOverridePort(id string, item interface{}) (*portBinding, error) {
	pb := portBinding{AppID: id, Key: "custom override", Bind: "0.0.0.0", Protocol: "tcp", Custom: true}
	var host string
	switch v := item.(type) {
	case int:
		return nil, nil
	case string:
		if strings.Contains(v, "$") {
			return nil, fmt.Errorf("port %q: variables are not allowed (the Hub must see the real port)", v)
		}
		s := v
		if spec, proto, ok := strings.Cut(s, "/"); ok {
			s, pb.Protocol = spec, strings.ToLower(proto)
		}
		if strings.HasPrefix(s, "[") {
			end := strings.Index(s, "]:")
			if end < 0 {
				return nil, fmt.Errorf("port %q: bad IPv6 address", v)
			}
			pb.Bind, s = s[1:end], s[end+2:]
		}
		parts := strings.Split(s, ":")
		switch len(parts) {
		case 1:
			return nil, checkPortSpec(v, parts[0])
		case 2:
			host = parts[0]
		case 3:
			if pb.Bind != "0.0.0.0" {
				return nil, fmt.Errorf("port %q: bad format", v)
			}
			pb.Bind, host = parts[0], parts[1]
		default:
			return nil, fmt.Errorf("port %q: bad format", v)
		}
		if err := checkPortSpec(v, parts[len(parts)-1]); err != nil {
			return nil, err
		}
	case map[string]interface{}:
		if err := onlyKeys(v, "port", "target", "published", "host_ip", "protocol", "mode", "name", "app_protocol"); err != nil {
			return nil, err
		}
		if _, ok := v["target"].(int); !ok {
			return nil, fmt.Errorf("port: target must be a number")
		}
		if ip, ok := v["host_ip"].(string); ok {
			pb.Bind = ip
		}
		if p, ok := v["protocol"].(string); ok {
			pb.Protocol = strings.ToLower(p)
		}
		switch p := v["published"].(type) {
		case nil:
			return nil, nil
		case int:
			host = strconv.Itoa(p)
		case string:
			if strings.Contains(p, "$") {
				return nil, fmt.Errorf("port %q: variables are not allowed", p)
			}
			host = p
		default:
			return nil, fmt.Errorf("port: published must be a number or a range")
		}
	default:
		return nil, fmt.Errorf("port entry %v must be a string or a mapping", item)
	}
	if pb.Protocol != "tcp" && pb.Protocol != "udp" {
		return nil, fmt.Errorf("port protocol %q is not allowed (tcp, udp)", pb.Protocol)
	}
	if net.ParseIP(pb.Bind) == nil {
		return nil, fmt.Errorf("port host address %q is not an IP address", pb.Bind)
	}
	if host == "" {
		return nil, nil
	}
	if a, b, ok := parsePortRange(host); ok {
		if b > 65535 {
			return nil, fmt.Errorf("port range %s out of range", host)
		}
		pb.RangeStart, pb.RangeEnd = a, b
		return &pb, nil
	}
	n, err := strconv.Atoi(host)
	if err != nil || n < 1 || n > 65535 {
		return nil, fmt.Errorf("host port %q must be 1-65535 or a range", host)
	}
	pb.Port = n
	return &pb, nil
}

func checkPortSpec(entry, p string) error {
	if _, _, ok := parsePortRange(p); ok {
		return nil
	}
	if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("port %q: container port must be 1-65535 or a range", entry)
	}
	return nil
}

// userPortsLocked returns the host ports the app's stored custom override
// publishes (none if it is absent or invalid — an invalid one never
// reaches compose). Caller must hold mu.
func (h *Hub) userPortsLocked(t *templates.Template) []portBinding {
	data, err := os.ReadFile(h.userOverridePath(t.ID))
	if err != nil {
		return nil
	}
	po, err := h.parseUserOverride(t, data)
	if err != nil || po == nil {
		return nil
	}
	return po.ports
}

// checkUserOverride re-validates the stored custom override against the
// template as it is now (a sync may have dropped a service).
func (h *Hub) checkUserOverride(t *templates.Template) error {
	data, err := os.ReadFile(h.userOverridePath(t.ID))
	if err != nil {
		return nil
	}
	if _, err := h.parseUserOverride(t, data); err != nil {
		return statusErr(409, "the custom compose override (Expert) is not valid for this template any more: %v — edit or clear it", err)
	}
	return nil
}

// ComposeView is the Expert tab's three layers.
type ComposeView struct {
	// Compose is the template's compose.yml (read-only: it comes from the
	// template source).
	Compose string `json:"compose"`
	// HubOverride is what the Hub generates from Settings (read-only,
	// regenerated before every compose up).
	HubOverride      string `json:"hub_override"`
	HubOverrideError string `json:"hub_override_error,omitempty"`
	// UserOverride is the admin's custom override ("" = none).
	UserOverride string   `json:"user_override"`
	Enabled      bool     `json:"enabled"`
	Rules        []string `json:"rules"`
	// Files is the compose -f order.
	Files []string `json:"files"`
}

// ComposeFiles returns an app's compose layers.
func (h *Hub) ComposeFiles(id string) (*ComposeView, error) {
	t := h.Template(id)
	if t == nil {
		return nil, ErrNotFound
	}
	data, err := os.ReadFile(t.ComposePath())
	if err != nil {
		return nil, statusErr(404, "compose.yml not found")
	}
	v := &ComposeView{Compose: string(data), Enabled: t.Enabled, Rules: OverrideRules,
		Files: []string{"compose.yml (template)", "compose.hub-override.yml (generated)", "compose.custom-override.yml (yours)"}}
	h.mu.RLock()
	v.HubOverride, err = h.renderOverrideLocked(t, h.st.Settings[id])
	h.mu.RUnlock()
	if err != nil {
		v.HubOverrideError = err.Error()
	}
	user, _ := os.ReadFile(h.userOverridePath(id))
	v.UserOverride = string(user)
	return v, nil
}

// SaveUserOverride validates and stores an app's custom override (empty
// content removes it). It never restarts the app: restart reports whether
// the app is enabled (the change applies on its next restart). detail is a
// short, secret-free description for the audit log.
func (h *Hub) SaveUserOverride(id, content string) (restart bool, detail string, err error) {
	t := h.Template(id)
	if t == nil {
		return false, "", ErrNotFound
	}
	if len(content) > 256<<10 {
		return false, "", statusErr(400, "the override is too large (max 256 KiB)")
	}
	po, err := h.parseUserOverride(t, []byte(content))
	if err != nil {
		return false, "", statusErr(400, "%v", err)
	}
	if po == nil {
		if err := os.Remove(h.userOverridePath(id)); err != nil && !os.IsNotExist(err) {
			return false, "", statusErr(500, "remove override: %v", err)
		}
		return t.Enabled, "removed", nil
	}
	h.mu.RLock()
	enabled := h.st.IsEnabled(id)
	if enabled {
		err = h.checkPortsLocked(t, append(resolvePortBindings(t, h.st.Settings[id]), po.ports...))
	}
	h.mu.RUnlock()
	if err != nil {
		return false, "", err
	}
	if err := fsutil.WriteFileAtomic(h.userOverridePath(id), []byte(content), 0600); err != nil {
		return false, "", statusErr(500, "write override: %v", err)
	}
	sum := sha256.Sum256([]byte(content))
	return enabled, fmt.Sprintf("saved (%d bytes, sha256 %x)", len(content), sum[:6]), nil
}
