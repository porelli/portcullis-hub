package templates

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"maps"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Mail is the optional mail: block (contract §3.5): the template can be
// wired as the server's mail provider. Only the wired instance gets the
// slot's powers; the block alone grants nothing.
type Mail struct {
	Label         string           `json:"label"`
	APIVersion    int              `json:"api_version"`
	API           Endpoint         `json:"api"`
	Listeners     Listeners        `json:"listeners"`
	Wellknown     Endpoint         `json:"wellknown"`
	Metrics       Endpoint         `json:"metrics"`
	ServerMetrics *MetricsEndpoint `json:"server_metrics,omitempty"`
	TLS           []string         `json:"tls"`
	Gated         []string         `json:"gated"`
	Sessions      struct {
		Restart string `json:"restart"`
	} `json:"sessions"`
	Export *Export `json:"export,omitempty"`

	// node is the block as written: ValidateMail judges it (unknown keys,
	// shapes), so decoding the manifest never fails on it.
	node *yaml.Node
}

// Endpoint is a service of the template and a container port.
type Endpoint struct {
	Service string `json:"service"`
	Port    int    `json:"port"`
}

// MetricsEndpoint is server_metrics: an Endpoint and its URL path.
type MetricsEndpoint struct {
	Endpoint
	Path string `json:"path"`
}

// Listeners are the four container ports of one service.
type Listeners struct {
	Service     string `json:"service"`
	SMTP        int    `json:"smtp"`
	Submissions int    `json:"submissions"`
	Submission  int    `json:"submission"`
	IMAPS       int    `json:"imaps"`
}

// Export is the former-account export: an argv run in service.
type Export struct {
	Service string   `json:"service"`
	Argv    []string `json:"argv"`
}

// MailLabelMax is the longest mail.label.
const MailLabelMax = 64

// MailFormerIDArg is export.argv's one placeholder.
const MailFormerIDArg = "{former_id}"

// UnmarshalYAML keeps the node and decodes what fits; it never fails
// (ValidateMail refuses what doesn't).
func (m *Mail) UnmarshalYAML(n *yaml.Node) error {
	c := *n
	m.node = &c
	if n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i].Value, n.Content[i+1]
		switch k {
		case "label":
			m.Label = scalarString(v)
		case "api_version":
			m.APIVersion, _ = scalarInt(v)
		case "api":
			m.API = endpointOf(v)
		case "wellknown":
			m.Wellknown = endpointOf(v)
		case "metrics":
			m.Metrics = endpointOf(v)
		case "server_metrics":
			e := MetricsEndpoint{Endpoint: endpointOf(v), Path: scalarString(mapValue(v, "path"))}
			m.ServerMetrics = &e
		case "listeners":
			m.Listeners = Listeners{Service: scalarString(mapValue(v, "service"))}
			m.Listeners.SMTP, _ = scalarInt(mapValue(v, "smtp"))
			m.Listeners.Submissions, _ = scalarInt(mapValue(v, "submissions"))
			m.Listeners.Submission, _ = scalarInt(mapValue(v, "submission"))
			m.Listeners.IMAPS, _ = scalarInt(mapValue(v, "imaps"))
		case "tls":
			m.TLS, _ = stringList(v)
		case "gated":
			m.Gated, _ = stringList(v)
		case "sessions":
			m.Sessions.Restart = scalarString(mapValue(v, "restart"))
		case "export":
			argv, _ := stringList(mapValue(v, "argv"))
			m.Export = &Export{Service: scalarString(mapValue(v, "service")), Argv: argv}
		}
	}
	return nil
}

// scalarString is a scalar node's value ("" for anything else).
func scalarString(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

// scalarInt is a plain integer scalar's value.
func scalarInt(n *yaml.Node) (int, bool) {
	if n == nil || n.Kind != yaml.ScalarNode || n.Tag != "!!int" {
		return 0, false
	}
	v, err := strconv.Atoi(n.Value)
	return v, err == nil
}

// stringList is a sequence of string scalars (ok false otherwise).
func stringList(n *yaml.Node) ([]string, bool) {
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil, false
	}
	out := []string{}
	for _, c := range n.Content {
		if c.Kind != yaml.ScalarNode || c.Tag != "!!str" {
			return nil, false
		}
		out = append(out, c.Value)
	}
	return out, true
}

// mapValue is key's value in a mapping node (nil: absent).
func mapValue(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

func endpointOf(n *yaml.Node) Endpoint {
	p, _ := scalarInt(mapValue(n, "port"))
	return Endpoint{Service: scalarString(mapValue(n, "service")), Port: p}
}

// mailKeys are the block's keys, and each mapping field's own.
var (
	mailTopKeys   = []string{"label", "api_version", "api", "listeners", "wellknown", "metrics", "server_metrics", "tls", "gated", "sessions", "export"}
	mailFieldKeys = map[string][]string{
		"api": {"service", "port"}, "wellknown": {"service", "port"}, "metrics": {"service", "port"},
		"server_metrics": {"service", "port", "path"},
		"listeners":      {"service", "smtp", "submissions", "submission", "imaps"},
		"sessions":       {"restart"}, "export": {"service", "argv"},
	}
)

// mailUnknownKey is the first key (document order) outside the block's
// shape, as its path inside the block ("" = none).
func mailUnknownKey(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.MappingNode {
		return ""
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i].Value, n.Content[i+1]
		if !slices.Contains(mailTopKeys, k) {
			return k
		}
		if sub, ok := mailFieldKeys[k]; ok && v.Kind == yaml.MappingNode {
			for j := 0; j+1 < len(v.Content); j += 2 {
				if !slices.Contains(sub, v.Content[j].Value) {
					return k + "." + v.Content[j].Value
				}
			}
		}
	}
	return ""
}

// mailPathRe is an absolute URL path (server_metrics.path).
var mailPathRe = regexp.MustCompile(`^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*$`)

// mailLetterText refuses a one-letter volume name in a mail template.
const mailLetterText = "a mail template's volume names are longer than one letter"

// mailCaps are the mail template's privilege texts.
var mailCaps = capWords{"mail: ", "a mail provider", "a mail provider has no devices"}

// composeServiceOrder is compose's service names in file order.
func composeServiceOrder(compose []byte) []string {
	var doc yaml.Node
	if yaml.Unmarshal(compose, &doc) != nil || len(doc.Content) == 0 {
		return nil
	}
	svcs := mapValue(doc.Content[0], "services")
	if svcs == nil || svcs.Kind != yaml.MappingNode {
		return nil
	}
	var out []string
	for i := 0; i+1 < len(svcs.Content); i += 2 {
		out = append(out, svcs.Content[i].Value)
	}
	return out
}

// ValidateMail is contract §3.5: the first refusal in contract order, nil
// for a template without a mail: block or with a valid one. build calls
// it right after the routes parse, so a mail template's first refusal is
// always a mail one.
func ValidateMail(t *Template, compose []byte, routes *Routes) error {
	m := &t.Manifest
	b := m.Mail
	if b == nil {
		return nil
	}
	tid := t.TemplateID
	if tid == "" {
		tid = t.ID
	}
	n := b.node
	if k := mailUnknownKey(n); k != "" {
		return fmt.Errorf("mail: unknown key %s", k)
	}
	infos := composeServiceInfos(compose)
	jobs := JobServices(m, compose)
	companion := func(s string) bool {
		if m.AI == nil {
			return false
		}
		for _, c := range m.AI.MCP {
			if c.Service == s && kindOf(m, c.Name) == CompanionKind {
				return true
			}
		}
		return false
	}
	// service checks a field's service (and its port when hasPort).
	service := func(field, s string, port int, hasPort bool) error {
		if _, ok := infos[s]; !ok || s == "" {
			return fmt.Errorf("mail.%s: service %s is not a service of this template", field, s)
		}
		if hasPort && (port < 1024 || port > 65535) {
			return fmt.Errorf("mail.%s: port must be 1024–65535", field)
		}
		if jobs[s] {
			return fmt.Errorf("mail.%s: %s is a job", field, s)
		}
		if companion(s) {
			return fmt.Errorf("mail.%s: %s is an AI companion", field, s)
		}
		if infos[s].networkMode {
			return fmt.Errorf("mail.%s: %s has network_mode", field, s)
		}
		return nil
	}
	endpoint := func(field string) error {
		v := mapValue(n, field)
		if v == nil {
			return fmt.Errorf("mail.%s: required", field)
		}
		port, _ := scalarInt(mapValue(v, "port"))
		return service(field, scalarString(mapValue(v, "service")), port, true)
	}
	// label
	lv := mapValue(n, "label")
	if lv == nil {
		return fmt.Errorf("mail.label: required")
	}
	if lv.Kind != yaml.ScalarNode || !singleLine(lv.Value, MailLabelMax) {
		return fmt.Errorf("mail.label: 1–64 characters, one line")
	}
	// api_version
	av := mapValue(n, "api_version")
	if av == nil {
		return fmt.Errorf("mail.api_version: required")
	}
	if v, ok := scalarInt(av); !ok || v != 1 {
		return fmt.Errorf("mail.api_version: only 1")
	}
	if err := endpoint("api"); err != nil {
		return err
	}
	// listeners: exactly the five keys, scalar service, four int ports.
	ln := mapValue(n, "listeners")
	if ln == nil {
		return fmt.Errorf("mail.listeners: required")
	}
	const listenersText = "mail.listeners: exactly smtp, submissions, submission and imaps, on one service"
	if ln.Kind != yaml.MappingNode || len(ln.Content) != 2*len(mailFieldKeys["listeners"]) {
		return fmt.Errorf(listenersText)
	}
	ls := mapValue(ln, "service")
	if ls == nil || ls.Kind != yaml.ScalarNode {
		return fmt.Errorf(listenersText)
	}
	var lports []int
	for _, k := range []string{"smtp", "submissions", "submission", "imaps"} {
		pn := mapValue(ln, k)
		if pn == nil || pn.Kind != yaml.ScalarNode {
			return fmt.Errorf(listenersText)
		}
		p, _ := scalarInt(pn)
		lports = append(lports, p)
	}
	// The service's checks, with the first port out of range (if any).
	lp := lports[0]
	for _, p := range lports {
		if p < 1024 || p > 65535 {
			lp = p
			break
		}
	}
	if err := service("listeners", ls.Value, lp, true); err != nil {
		return err
	}
	for _, f := range []string{"wellknown", "metrics"} {
		if err := endpoint(f); err != nil {
			return err
		}
	}
	if sm := mapValue(n, "server_metrics"); sm != nil {
		if p := scalarString(mapValue(sm, "path")); !mailPathRe.MatchString(p) || slices.Contains(strings.Split(p, "/"), "..") {
			return fmt.Errorf("mail.server_metrics.path: an absolute URL path")
		}
		if err := endpoint("server_metrics"); err != nil {
			return err
		}
	}
	// tls, gated: lists of services holding listeners' and api's.
	for _, f := range []string{"tls", "gated"} {
		v := mapValue(n, f)
		if v == nil {
			return fmt.Errorf("mail.%s: required", f)
		}
		list, ok := stringList(v)
		if !ok {
			return fmt.Errorf("mail.%s: service %s is not a service of this template", f, scalarString(v))
		}
		for _, s := range list {
			if _, ok := infos[s]; !ok {
				return fmt.Errorf("mail.%s: service %s is not a service of this template", f, s)
			}
		}
		for _, s := range []string{ls.Value, b.API.Service} {
			if !slices.Contains(list, s) {
				return fmt.Errorf("mail.%s: %s serves mail and must be listed", f, s)
			}
		}
	}
	rs := scalarString(mapValue(mapValue(n, "sessions"), "restart"))
	if rs == "" {
		return fmt.Errorf("mail.sessions.restart: required")
	}
	if err := service("sessions.restart", rs, 0, false); err != nil {
		return err
	}
	if ex := mapValue(n, "export"); ex != nil {
		argv, ok := stringList(mapValue(ex, "argv"))
		if !ok || len(argv) == 0 || countOf(argv, MailFormerIDArg) != 1 || slices.ContainsFunc(argv, func(a string) bool {
			return a != MailFormerIDArg && strings.Contains(a, MailFormerIDArg)
		}) {
			return fmt.Errorf("mail.export.argv: exactly one {former_id}")
		}
		if err := service("export", scalarString(mapValue(ex, "service")), 0, false); err != nil {
			return err
		}
	}
	// The manifest.
	if m.Instances == InstancesMulti {
		return fmt.Errorf("mail: instances must be single")
	}
	if m.Auth.Method != "custom" || m.Auth.GroupAccess || len(routes.Info) > 0 {
		return fmt.Errorf("mail: auth must be method custom with no routers and group_access false")
	}
	if len(m.Ports) > 0 {
		return fmt.Errorf("mail: manifest ports are not allowed")
	}
	if m.Settings != nil {
		for _, o := range m.Settings.Options {
			if o.Type == TypePersonSecret || o.Type == TypePersonID {
				return fmt.Errorf("mail: person_secret options are not allowed: mail passwords go through the provider API")
			}
		}
	}
	// Service by service, in compose order.
	vols := topLevelVolumes(compose)
	for _, s := range composeServiceOrder(compose) {
		info := infos[s]
		if info.ports {
			return fmt.Errorf("mail: service %s publishes ports: the Hub publishes a mail provider's ports", s)
		}
		if len(routes.Routers[s]) > 0 || routes.TraefikLabelled[s] {
			return fmt.Errorf("mail: service %s has a Traefik router: a mail provider's only router is the Hub's well-known router", s)
		}
		if err := namespaceCaps(s, info, mailCaps); err != nil {
			return err
		}
		for _, k := range []struct {
			key string
			set bool
		}{{"pid", info.hasPid}, {"ipc", info.hasIpc}} {
			if k.set {
				return fmt.Errorf("mail: %s sets %s: a mail provider keeps its own pid and ipc namespaces", s, k.key)
			}
		}
		if info.netModeOf == "host" {
			return fmt.Errorf("mail: service %s uses network_mode: host", s)
		}
		if info.hasVolumesFrom {
			return fmt.Errorf("mail: %s uses volumes_from: a mail provider mounts no other service's volumes", s)
		}
		ms, bad := vpnMounts(info.volumes)
		if bad != "" {
			return fmt.Errorf("mail: %s mounts %s: unresolvable (a mail template's mounts are literal)", s, bad)
		}
		for _, mm := range ms {
			if mm.bind {
				if vpnBindOutside(mm.src) {
					return fmt.Errorf("mail: %s mounts %s: a mail template's binds start with ./ and have no .. segment", s, mm.entry)
				}
				// Case-sensitive (L12): ./templates/STALWART/ is another
				// directory on Linux.
				norm := path.Clean(mm.src)
				if !strings.HasPrefix(mm.src, "./templates/"+tid+"/") || !strings.HasPrefix(norm, "templates/"+tid+"/") || !mm.ro {
					return fmt.Errorf("mail: %s mounts %s: a mail provider binds only the template's own files (./templates/%s/…), read-only", s, mm.entry, tid)
				}
				continue
			}
			if len(mm.src) == 1 {
				return fmt.Errorf("mail: %s mounts %s: %s", s, mm.entry, mailLetterText)
			}
			if _, declared := vols[mm.src]; !declared && mm.entry != mm.src {
				return fmt.Errorf("mail: %s mounts %s: a mail template's short-syntax sources are ./ binds or declared volumes", s, mm.entry)
			}
		}
	}
	if err := bindEscapes(t.Path, tid, compose, "mail: "); err != nil {
		return err
	}
	if err := plainVolumeIdentity(compose, "mail", "a mail template's", mailLetterText); err != nil {
		return err
	}
	if err := mailNetworkRefusal(compose); err != nil {
		return err
	}
	if err := mailServiceNetworkRefusal(compose); err != nil {
		return err
	}
	if vpnYAMLIndirection(compose) {
		return fmt.Errorf("compose.yml: a mail template uses no YAML anchors, aliases or merge keys")
	}
	if s := mailInterpolatedImage(compose); s != "" {
		return fmt.Errorf("mail: %s image must be a literal reference: a mail template's images are hashed (no ${…})", s)
	}
	return nil
}

// mailInterpolatedImage is the first service (in file order) whose
// image: interpolates ($): its block hash couldn't pin it (M14).
func mailInterpolatedImage(compose []byte) string {
	var doc yaml.Node
	if yaml.Unmarshal(compose, &doc) != nil || len(doc.Content) == 0 {
		return ""
	}
	svcs := mapValue(doc.Content[0], "services")
	if svcs == nil || svcs.Kind != yaml.MappingNode {
		return ""
	}
	for i := 0; i+1 < len(svcs.Content); i += 2 {
		if img := mapValue(svcs.Content[i+1], "image"); img != nil && strings.Contains(img.Value, "$") {
			return svcs.Content[i].Value
		}
	}
	return ""
}

func countOf(l []string, s string) int {
	n := 0
	for _, x := range l {
		if x == s {
			n++
		}
	}
	return n
}

// mailCoreNetworks are core's network keys and names (core
// docker-compose.yml, folded to lower case).
var mailCoreNetworks = map[string]bool{"portcullis": true, "portcullis-proxy": true, "portcullis-auth": true, "socket-proxy-traefik": true,
	"socket-proxy-hub": true, "monitoring": true, "alerting": true, "portcullis-domains": true, "portcullis-certs": true, "domains-egress": true,
	"portcullis-mcp": true, "portcullis-sessions": true, "portcullis-vpn": true, "portcullis-vpn-edge": true, "wg-egress": true,
	"portcullis-metrics-wg": true, "portcullis-link": true, "portcullis-link-data": true, "portcullis-mail-api": true, "portcullis-metrics-mail": true,
	"portcullis-metrics-hub": true}

// mailNetworkText ends the refusal of a network key outside the
// allowlist (parity with templates' validate.py).
const mailNetworkText = "a mail template's networks are plain project networks (internal, ipam subnets and IP ranges, enable_ipv6: false)"

// mailNetworkRefusal is the networks' allowlist: per top-level network
// (file order), its keys in file order — enable_ipv6 only false
// ("enables IPv6"), internal, ipam with only config, each config entry
// only subnet and ip_range; any other key (driver, driver_opts, name,
// external, attachable, labels, ipam.driver, …) is refused.
func mailNetworkRefusal(compose []byte) error {
	var doc yaml.Node
	if yaml.Unmarshal(compose, &doc) != nil || len(doc.Content) == 0 {
		return nil
	}
	nets := mapValue(doc.Content[0], "networks")
	if nets == nil || nets.Kind != yaml.MappingNode {
		return nil
	}
	sets := func(n, key string) error {
		return fmt.Errorf("mail: network %s sets %s: %s", n, key, mailNetworkText)
	}
	for i := 0; i+1 < len(nets.Content); i += 2 {
		n, body := nets.Content[i].Value, nets.Content[i+1]
		// Never one of core's network keys or names (Ruling FH-H1): the
		// Hub's override merges its own external entries under some of
		// them (portcullis-proxy, the mail API and metrics networks).
		if mailCoreNetworks[strings.ToLower(strings.TrimSpace(n))] {
			return fmt.Errorf("mail: network %s is one of core's networks: a mail template declares only its own", n)
		}
		if body.Kind != yaml.MappingNode {
			continue // null: a plain network
		}
		for j := 0; j+1 < len(body.Content); j += 2 {
			k, v := body.Content[j].Value, body.Content[j+1]
			switch k {
			case "enable_ipv6":
				if !(v.Kind == yaml.ScalarNode && (v.Value == "false" || v.Value == "False" || v.Value == "FALSE")) {
					return fmt.Errorf("mail: network %s enables IPv6", n)
				}
			case "internal":
			case "ipam":
				if v.Kind != yaml.MappingNode {
					return sets(n, "ipam")
				}
				for a := 0; a+1 < len(v.Content); a += 2 {
					ik, iv := v.Content[a].Value, v.Content[a+1]
					if ik != "config" {
						return sets(n, "ipam."+ik)
					}
					if iv.Kind != yaml.SequenceNode {
						return sets(n, "ipam.config")
					}
					for _, c := range iv.Content {
						if c.Kind != yaml.MappingNode {
							return sets(n, "ipam.config")
						}
						for b := 0; b+1 < len(c.Content); b += 2 {
							ck, cv := c.Content[b].Value, c.Content[b+1]
							if ck != "subnet" && ck != "ip_range" {
								return sets(n, "ipam.config."+ck)
							}
							// IPv4 only (enable_ipv6 is false): an IPv6
							// or unparsable range is refused.
							if p, err := netip.ParsePrefix(cv.Value); cv.Kind != yaml.ScalarNode || err != nil || !p.Addr().Is4() {
								return sets(n, "ipam.config."+ck)
							}
						}
					}
				}
			default:
				return sets(n, k)
			}
		}
	}
	return nil
}

// MailBlockHash is the wired provider's template fingerprint (plan P4,
// contract §19.1 block_hash): hex sha256 over the canonical JSON of the
// mail: block, the bytes of compose.yml and every file under the
// template directory dir (path-sorted, symlinks by their target, never
// followed). Any change to the tree changes it: a template update holds
// the provider until an admin re-confirms.
func MailBlockHash(dir string, m *Mail, compose []byte) (string, error) {
	if m == nil {
		return "", fmt.Errorf("no mail: block")
	}
	block, err := canonicalMailJSON(m)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	part := func(tag string, b []byte) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		h.Write([]byte(tag))
		h.Write([]byte{0})
		h.Write(n[:])
		h.Write(b)
	}
	part("mail", block)
	part("compose.yml", compose)
	type entry struct {
		rel  string
		data []byte
	}
	var files []entry
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(dir, p)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			target, lerr := os.Readlink(p)
			if lerr != nil {
				return lerr
			}
			files = append(files, entry{"link:" + rel, []byte(target)})
		case d.Type().IsRegular():
			b, rerr := os.ReadFile(p)
			if rerr != nil {
				return rerr
			}
			files = append(files, entry{"file:" + rel, b})
		case d.IsDir():
		default:
			files = append(files, entry{"other:" + rel, nil})
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("hashing the template directory: %w", err)
	}
	slices.SortFunc(files, func(a, b entry) int { return strings.Compare(a.rel, b.rel) })
	for _, f := range files {
		part(f.rel, f.data)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// canonicalMailJSON is the block as written, as JSON with sorted keys.
func canonicalMailJSON(m *Mail) ([]byte, error) {
	if m.node == nil {
		return json.Marshal(m)
	}
	var v any
	if err := m.node.Decode(&v); err != nil {
		return nil, err
	}
	return json.Marshal(jsonable(v))
}

// jsonable turns yaml's map[string]any / []any tree into one
// encoding/json writes with sorted keys.
func jsonable(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for _, k := range slices.Sorted(maps.Keys(x)) {
			out[k] = jsonable(x[k])
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i := range x {
			out[i] = jsonable(x[i])
		}
		return out
	default:
		return x
	}
}

// mailServiceNetworkRefusal (Ruling RR2-H1): every network a service
// joins is one the template declares at the top level (or the implicit
// default), so no service-level reference can resolve to a network the
// Hub's override declares (core's portcullis-proxy, the mail API and
// metrics networks); and a fixed address is only an IPv4 one inside
// that network's own declared subnet (never ipv6_address or
// link_local_ips): the Hub assigns every address on a core network.
func mailServiceNetworkRefusal(compose []byte) error {
	var doc yaml.Node
	if yaml.Unmarshal(compose, &doc) != nil || len(doc.Content) == 0 {
		return nil
	}
	root := doc.Content[0]
	subnets := map[string][]netip.Prefix{"default": nil}
	if nets := mapValue(root, "networks"); nets != nil && nets.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(nets.Content); i += 2 {
			n := nets.Content[i].Value
			subnets[n] = nil
			if ipam := mapValue(nets.Content[i+1], "ipam"); ipam != nil {
				if cfg := mapValue(ipam, "config"); cfg != nil && cfg.Kind == yaml.SequenceNode {
					for _, c := range cfg.Content {
						if sn := mapValue(c, "subnet"); sn != nil {
							if p, err := netip.ParsePrefix(sn.Value); err == nil {
								subnets[n] = append(subnets[n], p)
							}
						}
					}
				}
			}
		}
	}
	svcs := mapValue(root, "services")
	if svcs == nil || svcs.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(svcs.Content); i += 2 {
		s := svcs.Content[i].Value
		nn := mapValue(svcs.Content[i+1], "networks")
		if nn == nil {
			continue
		}
		type join struct {
			name string
			cfg  *yaml.Node
		}
		var joins []join
		switch nn.Kind {
		case yaml.SequenceNode:
			for _, x := range nn.Content {
				joins = append(joins, join{x.Value, nil})
			}
		case yaml.MappingNode:
			for j := 0; j+1 < len(nn.Content); j += 2 {
				joins = append(joins, join{nn.Content[j].Value, nn.Content[j+1]})
			}
		}
		for _, jn := range joins {
			own, declared := subnets[jn.name]
			if !declared {
				return fmt.Errorf("mail: service %s joins network %s: a mail template's services join only networks it declares at the top level", s, jn.name)
			}
			if jn.cfg == nil || jn.cfg.Kind != yaml.MappingNode {
				continue
			}
			for k := 0; k+1 < len(jn.cfg.Content); k += 2 {
				key, v := jn.cfg.Content[k].Value, jn.cfg.Content[k+1]
				bad := ""
				switch key {
				case "ipv6_address", "link_local_ips":
					bad = key
				case "ipv4_address":
					a, err := netip.ParseAddr(v.Value)
					in := false
					for _, p := range own {
						in = in || (err == nil && p.Contains(a))
					}
					if !in {
						bad = key
					}
				}
				if bad != "" {
					return fmt.Errorf("mail: service %s sets %s on network %s: a mail template's fixed addresses are IPv4 inside that network's own declared subnet", s, bad, jn.name)
				}
			}
		}
	}
	return nil
}
