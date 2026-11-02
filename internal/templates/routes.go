package templates

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Traefik routing is parsed from the compose YAML rather than grepped, and
// anything the Hub cannot fully resolve is rejected: group-gate keys every
// policy and group by subdomain, so a host the Hub doesn't see would get no
// policy and no group (fail open).

var (
	routerLabelRe     = regexp.MustCompile(`^traefik\.(http|tcp|udp)\.routers\.([a-z0-9][a-z0-9_-]*)\.(.+)$`)
	middlewareLabelRe = regexp.MustCompile(`^traefik\.(?:http|tcp)\.middlewares\.([^.]+)\.`)
	serviceLabelRe    = regexp.MustCompile(`^traefik\.http\.services\.([^.]+)\.`)
	// traefikNameRe matches every label defining a router, service or
	// middleware (any protocol); group 1 is the name.
	traefikNameRe = regexp.MustCompile(`^traefik\.(?:http|tcp|udp)\.(?:routers|services|middlewares)\.([^.]+)\.`)
	// hostVarArgRe is the contract v2 Host() argument (§3.1): the host
	// router's hostname variable with the default subdomain on
	// portcullis.local, e.g. ${PORTCULLIS_HOST_GRAFANA:-grafana.portcullis.local}.
	hostVarArgRe = regexp.MustCompile(`^\$\{(PORTCULLIS_HOST_[A-Z0-9_]+):-([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.portcullis\.local\}$`)
	// hostArgRe is the conversion-period Host() argument (instances: single
	// only): a literal DNS label followed by the core domain variable
	// (optionally with a default).
	hostArgRe = regexp.MustCompile(`^(?i)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.\$\{PORTCULLIS_DOMAIN(?:(?::?[-?])[^${}]*)?\}$`)
	// Matchers that could route hosts outside the template's own hosts.
	forbiddenMatchers = map[string]bool{"hostregexp": true, "hostheader": true, "hostsni": true, "hostsniregexp": true}
)

// Routes is what a compose file exposes through Traefik.
type Routes struct {
	// Subdomains routed by HTTP routers, lowercase, sorted, de-duplicated.
	Subdomains []string
	// Routers maps service → HTTP router names (sorted).
	Routers map[string][]string
	// Info holds each HTTP router's parsed labels, by router name.
	Info map[string]*RouterInfo
	// TraefikServices maps compose service → Traefik HTTP services its
	// labels define (sorted).
	TraefikServices map[string][]string
	// Form is the rule form of every router: FormV2
	// (${PORTCULLIS_HOST_<ROUTER>:-<sub>.portcullis.local}) or FormLegacy
	// (<sub>.${PORTCULLIS_DOMAIN}); "" without HTTP routers.
	Form string
	// HostRouters maps each host router (contract §3.1: the router whose
	// rule is a Host() alone; legacy form: else the first router routing
	// the subdomain) to its default subdomain.
	HostRouters map[string]string
	// HostVars maps each host router to its hostname variable
	// (PORTCULLIS_HOST_<ROUTER>).
	HostVars map[string]string
	// Names are the Traefik router, service and middleware names the
	// template's labels define (any protocol), for per-instance renaming.
	Names map[string]bool
}

// Rule forms (Routes.Form).
const (
	FormV2     = "v2"
	FormLegacy = "legacy"
)

// HostVar is the hostname variable of host router name (contract §3.1):
// PORTCULLIS_HOST_ + the name upper-cased, "-" and "." as "_".
func HostVar(router string) string { return "PORTCULLIS_HOST_" + VarSuffix(router) }

// VarSuffix upper-cases s with "-" and "." turned into "_".
func VarSuffix(s string) string {
	return strings.NewReplacer("-", "_", ".", "_").Replace(strings.ToUpper(s))
}

// RouterInfo is what the Hub needs to know about one HTTP router.
type RouterInfo struct {
	Service string // compose service carrying the labels
	Rule    string
	// HostArgs are the Host() arguments as written, e.g.
	// "cloud.${PORTCULLIS_DOMAIN:-portcullis.local}".
	HostArgs   []string
	Subdomains []string
	// HostVars are the hostname variables of the Host() arguments
	// (parallel to HostArgs; "" in the legacy form).
	HostVars []string
	// HostOnly: the rule is a single Host() and nothing else (a host
	// router, contract §3.1).
	HostOnly bool
	// Paths are the rule's Path()/PathPrefix() matchers.
	Paths []RulePath
	// Opaque are matchers no path-overlap reasoning is possible for
	// (PathRegexp, unknown matchers, negated path/host matchers).
	Opaque      []string
	Priority    int // explicit priority label; 0 = Traefik's default
	HasPriority bool
	// TraefikService is the router's explicit service label ("" = none).
	TraefikService string
	Middlewares    []string
}

// RulePath is a Path (exact) or PathPrefix matcher argument.
type RulePath struct {
	Prefix bool
	Value  string
}

// Gated reports whether the router runs group-gate (portcullis-groups).
func (ri *RouterInfo) Gated() bool {
	for _, m := range ri.Middlewares {
		if m == "portcullis-groups@docker" {
			return true
		}
	}
	return false
}

// ReservedPrefix is reserved for Hub-generated Traefik routers and
// middlewares (public_access); templates may not define names with it.
const ReservedPrefix = "portcullis-public-"

// ParseRoutes extracts Traefik routing from a compose file and validates it:
//   - every HTTP router has a rule, and every way the rule can match is
//     restricted by Host(); there must be no top-level "||" branch, negation
//     or default rule that matches any host
//   - every Host() argument is `${PORTCULLIS_HOST_<ROUTER>:-<sub>.portcullis.local}`
//     (contract v2) or a literal `<label>.${PORTCULLIS_DOMAIN…}` (legacy),
//     one form for the whole file; every hostname variable belongs to a
//     host router named after it, with one default per variable and one
//     variable per default subdomain
//   - Traefik router, service and middleware names contain no "_" (the
//     per-instance prefix separator)
//   - HostRegexp, HostHeader, HostSNI and HostSNIRegexp are rejected, as are
//     TCP routers (they bypass forward-auth)
//   - a traefik.enable=true service must declare an HTTP router (otherwise
//     Traefik would synthesise one from its defaultRule)
func ParseRoutes(compose []byte) (*Routes, error) {
	var doc struct {
		Services map[string]struct {
			Labels interface{} `yaml:"labels"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(compose, &doc); err != nil {
		return nil, fmt.Errorf("compose.yml: %w", err)
	}
	r := &Routes{Routers: map[string][]string{}, Info: map[string]*RouterInfo{}, TraefikServices: map[string][]string{},
		HostRouters: map[string]string{}, HostVars: map[string]string{}, Names: map[string]bool{}}
	subs := map[string]bool{}
	// tsvcOwner: the compose service defining each Traefik HTTP service.
	tsvcOwner := map[string]string{}
	names := make([]string, 0, len(doc.Services))
	for name := range doc.Services {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, svc := range names {
		labels, err := labelMap(doc.Services[svc].Labels)
		if err != nil {
			return nil, fmt.Errorf("service %s: %w", svc, err)
		}
		type router struct {
			rule    string
			hasRule bool
			info    RouterInfo
		}
		httpRouters := map[string]*router{}
		tsvcs := map[string]bool{}
		for k, v := range labels {
			if m := traefikNameRe.FindStringSubmatch(k); m != nil {
				if strings.Contains(m[1], "_") {
					return nil, fmt.Errorf("service %s: Traefik name %s may not contain _ (reserved for the per-instance prefix)", svc, m[1])
				}
				r.Names[m[1]] = true
			}
			if m := middlewareLabelRe.FindStringSubmatch(k); m != nil && strings.HasPrefix(m[1], ReservedPrefix) {
				return nil, fmt.Errorf("service %s: middleware name %s is reserved for the Hub (prefix %s)", svc, m[1], ReservedPrefix)
			}
			if m := serviceLabelRe.FindStringSubmatch(k); m != nil {
				tsvcs[m[1]] = true
			}
			m := routerLabelRe.FindStringSubmatch(k)
			if m == nil {
				continue
			}
			if strings.HasPrefix(m[2], ReservedPrefix) {
				return nil, fmt.Errorf("service %s: router name %s is reserved for the Hub (prefix %s)", svc, m[2], ReservedPrefix)
			}
			proto, name, attr := m[1], m[2], m[3]
			switch proto {
			case "tcp":
				if attr == "rule" {
					return nil, fmt.Errorf("service %s: TCP router %s is not supported (it would bypass forward-auth)", svc, name)
				}
				continue
			case "udp":
				continue
			}
			rt := httpRouters[name]
			if rt == nil {
				rt = &router{}
				httpRouters[name] = rt
			}
			switch attr {
			case "rule":
				rt.rule, rt.hasRule = v, true
			case "priority":
				n, err := strconv.Atoi(strings.TrimSpace(v))
				if err != nil {
					return nil, fmt.Errorf("service %s: router %s: priority %q is not an integer", svc, name, v)
				}
				rt.info.Priority, rt.info.HasPriority = n, true
			case "service":
				rt.info.TraefikService = strings.TrimSpace(v)
			case "middlewares":
				for _, mw := range strings.Split(v, ",") {
					if mw = strings.TrimSpace(mw); mw != "" {
						rt.info.Middlewares = append(rt.info.Middlewares, mw)
					}
				}
			}
		}
		for name := range tsvcs {
			// Traefik merges same-named services of several containers into
			// one load balancer: which backend a router reaches would then
			// depend on the replica, not on the template.
			if o, ok := tsvcOwner[name]; ok {
				return nil, fmt.Errorf("Traefik service %s is defined on services %s and %s (Traefik would merge them into one load balancer): give each its own name", name, o, svc)
			}
			tsvcOwner[name] = svc
			r.TraefikServices[svc] = append(r.TraefikServices[svc], name)
		}
		sort.Strings(r.TraefikServices[svc])
		if len(r.TraefikServices[svc]) == 0 {
			delete(r.TraefikServices, svc)
		}
		if len(httpRouters) == 0 && strings.EqualFold(strings.TrimSpace(labels["traefik.enable"]), "true") {
			// Unless the service only has TCP/UDP routers.
			onlyL4 := false
			for k := range labels {
				if strings.HasPrefix(k, "traefik.tcp.") || strings.HasPrefix(k, "traefik.udp.") {
					onlyL4 = true
				}
			}
			if !onlyL4 {
				return nil, fmt.Errorf("service %s: traefik.enable=true without an HTTP router rule (Traefik would apply its default rule)", svc)
			}
		}
		rnames := make([]string, 0, len(httpRouters))
		for name := range httpRouters {
			rnames = append(rnames, name)
		}
		sort.Strings(rnames)
		for _, name := range rnames {
			rt := httpRouters[name]
			if !rt.hasRule {
				return nil, fmt.Errorf("service %s: router %s has no rule (Traefik would apply its default rule)", svc, name)
			}
			p, err := parseRule(rt.rule)
			if err != nil {
				return nil, fmt.Errorf("service %s: router %s: %w", svc, name, err)
			}
			for _, h := range p.hosts {
				subs[h] = true
			}
			info := rt.info
			info.Service, info.Rule = svc, rt.rule
			info.HostArgs, info.Subdomains, info.Paths, info.Opaque = p.hostArgs, p.hosts, p.paths, p.opaque
			info.HostVars = p.hostVars
			info.HostOnly = p.matchers == 1 && len(p.hostArgs) == 1 && p.negatedHost == 0
			r.Info[name] = &info
		}
		if len(rnames) > 0 {
			r.Routers[svc] = rnames
		}
	}
	for s := range subs {
		r.Subdomains = append(r.Subdomains, s)
	}
	sort.Strings(r.Subdomains)
	if err := r.resolveHostRouters(); err != nil {
		return nil, err
	}
	return r, nil
}

// resolveHostRouters checks the rule form and finds the host routers.
func (r *Routes) resolveHostRouters() error {
	names := make([]string, 0, len(r.Info))
	for name := range r.Info {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, v := range r.Info[name].HostVars {
			form := FormLegacy
			if v != "" {
				form = FormV2
			}
			if r.Form != "" && r.Form != form {
				return fmt.Errorf("router %s: a template uses one rule form for all its routers — ${PORTCULLIS_HOST_<ROUTER>:-<sub>.portcullis.local} or (conversion period) <sub>.${PORTCULLIS_DOMAIN}, never both", name)
			}
			r.Form = form
		}
	}
	if r.Form == FormV2 {
		varSub := map[string]string{}    // variable → default subdomain
		subVar := map[string]string{}    // default subdomain → variable
		varRouter := map[string]string{} // variable → host router
		for _, name := range names {
			ri := r.Info[name]
			for i, v := range ri.HostVars {
				sub := ri.Subdomains[i]
				if d, ok := varSub[v]; ok && d != sub {
					return fmt.Errorf("router %s: %s is written with two defaults (%s and %s.portcullis.local)", name, v, d+".portcullis.local", sub)
				}
				if o, ok := subVar[sub]; ok && o != v {
					return fmt.Errorf("router %s: hostname %s.portcullis.local has two hostname variables (%s, %s) — a hostname has one host router", name, sub, o, v)
				}
				varSub[v], subVar[sub] = sub, v
			}
			if !ri.HostOnly {
				continue
			}
			v := ri.HostVars[0]
			if want := HostVar(name); v != want {
				return fmt.Errorf("router %s: a host router uses its own hostname variable %s, not %s", name, want, v)
			}
			if o, ok := varRouter[v]; ok {
				return fmt.Errorf("routers %s and %s map to the same hostname variable %s", o, name, v)
			}
			varRouter[v] = name
			r.HostRouters[name], r.HostVars[name] = ri.Subdomains[0], v
		}
		for v, sub := range varSub {
			if varRouter[v] == "" {
				return fmt.Errorf("hostname %s.portcullis.local (%s) has no host router — add a router whose rule is Host(`${%s:-%s.portcullis.local}`) alone", sub, v, v, sub)
			}
		}
		return nil
	}
	// Legacy form: a host router per subdomain where one exists, else the
	// first router routing it.
	for _, sub := range r.Subdomains {
		pick := ""
		for _, name := range names {
			ri := r.Info[name]
			if ri.HostOnly && ri.Subdomains[0] == sub {
				pick = name
				break
			}
		}
		if pick == "" {
			for _, name := range names {
				if contains(r.Info[name].Subdomains, sub) {
					pick = name
					break
				}
			}
		}
		if prev, ok := r.HostRouters[pick]; ok && prev != sub {
			// One router routing several subdomains, none host-only: key
			// the extra ones by subdomain.
			pick = sub
		}
		r.HostRouters[pick], r.HostVars[pick] = sub, HostVar(pick)
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// labelMap normalises compose labels (map or "k=v" list syntax).
func labelMap(v interface{}) (map[string]string, error) {
	out := map[string]string{}
	switch l := v.(type) {
	case nil:
	case map[string]interface{}:
		for k, val := range l {
			if val == nil {
				out[k] = ""
			} else {
				out[k] = fmt.Sprint(val)
			}
		}
	case []interface{}:
		for _, item := range l {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("label %v is not a string", item)
			}
			k, val, _ := strings.Cut(s, "=")
			out[k] = val
		}
	default:
		return nil, fmt.Errorf("labels must be a map or a list")
	}
	return out, nil
}

// ── rule parser ──────────────────────────────────────────

type ruleParser struct {
	s        string
	pos      int
	hosts    []string
	hostArgs []string
	paths    []RulePath
	// opaque lists matchers the public-path overlap check can't reason
	// about (PathRegexp, unknown matchers, negated Path/PathPrefix/Host).
	opaque   []string
	negated  int
	hostVars []string
	// matchers counts every matcher; negatedHost the negated Host()s.
	matchers    int
	negatedHost int
}

// ParseRule validates a Traefik HTTP router rule and returns the (lowercase)
// subdomains of its Host() matchers. Grammar (Traefik v3):
//
//	expr   := term ("||" term)*
//	term   := factor ("&&" factor)*
//	factor := "!" factor | "(" expr ")" | Name "(" args ")"
//
// The rule must be host-restricted: an OR is restricted iff every branch
// is, an AND iff any operand is, a negation never is.
func ParseRule(rule string) ([]string, error) {
	p, err := parseRule(rule)
	if err != nil {
		return nil, err
	}
	return p.hosts, nil
}

func parseRule(rule string) (*ruleParser, error) {
	p := &ruleParser{s: rule}
	restricted, err := p.expr()
	if err != nil {
		return nil, err
	}
	p.skipSpace()
	if p.pos != len(p.s) {
		return nil, fmt.Errorf("rule %q: unexpected %q", rule, p.s[p.pos:])
	}
	if !restricted {
		return nil, fmt.Errorf("rule %q can match requests for any host — restrict every branch with Host(`${PORTCULLIS_HOST_<ROUTER>:-<sub>.portcullis.local}`)", rule)
	}
	return p, nil
}

func (p *ruleParser) skipSpace() {
	for p.pos < len(p.s) && (p.s[p.pos] == ' ' || p.s[p.pos] == '\t' || p.s[p.pos] == '\n' || p.s[p.pos] == '\r') {
		p.pos++
	}
}

func (p *ruleParser) consume(tok string) bool {
	p.skipSpace()
	if strings.HasPrefix(p.s[p.pos:], tok) {
		p.pos += len(tok)
		return true
	}
	return false
}

func (p *ruleParser) expr() (bool, error) {
	all := true
	for {
		r, err := p.term()
		if err != nil {
			return false, err
		}
		all = all && r
		if !p.consume("||") {
			return all, nil
		}
	}
}

func (p *ruleParser) term() (bool, error) {
	any := false
	for {
		r, err := p.factor()
		if err != nil {
			return false, err
		}
		any = any || r
		if !p.consume("&&") {
			return any, nil
		}
	}
}

func (p *ruleParser) factor() (bool, error) {
	if p.consume("!") {
		p.negated++
		_, err := p.factor()
		p.negated--
		if err != nil {
			return false, err
		}
		return false, nil
	}
	if p.consume("(") {
		r, err := p.expr()
		if err != nil {
			return false, err
		}
		if !p.consume(")") {
			return false, fmt.Errorf("rule %q: missing )", p.s)
		}
		return r, nil
	}
	p.skipSpace()
	start := p.pos
	for p.pos < len(p.s) && (isAlnum(p.s[p.pos])) {
		p.pos++
	}
	name := p.s[start:p.pos]
	if name == "" {
		return false, fmt.Errorf("rule %q: expected a matcher at %q", p.s, p.s[p.pos:])
	}
	if !p.consume("(") {
		return false, fmt.Errorf("rule %q: expected ( after %s", p.s, name)
	}
	var args []string
	for {
		p.skipSpace()
		if p.consume(")") {
			break
		}
		if len(args) > 0 && !p.consume(",") {
			return false, fmt.Errorf("rule %q: expected , or ) in %s()", p.s, name)
		}
		a, err := p.str()
		if err != nil {
			return false, err
		}
		args = append(args, a)
	}
	lname := strings.ToLower(name)
	p.matchers++
	if forbiddenMatchers[lname] {
		return false, fmt.Errorf("rule %q: %s() is not allowed — use Host(`${PORTCULLIS_HOST_<ROUTER>:-<sub>.portcullis.local}`)", p.s, name)
	}
	switch lname {
	case "path", "pathprefix":
		if p.negated > 0 {
			// A negated path matcher covers every other path: no overlap
			// reasoning is possible.
			p.opaque = append(p.opaque, "!"+name+"()")
		}
		for _, a := range args {
			p.paths = append(p.paths, RulePath{Prefix: lname == "pathprefix", Value: a})
		}
		return false, nil
	case "host":
		if p.negated > 0 {
			p.opaque = append(p.opaque, "!"+name+"()")
			p.negatedHost++
		}
	case "method", "header", "headerregexp", "query", "queryregexp", "clientip":
		// Narrow the request further; never widen which paths match.
		return false, nil
	default:
		// PathRegexp and anything unknown: the overlap check for public
		// paths can't reason about it (fail closed in PlanPublic).
		p.opaque = append(p.opaque, name+"()")
		return false, nil
	}
	if len(args) == 0 {
		return false, fmt.Errorf("rule %q: empty Host()", p.s)
	}
	for _, a := range args {
		if m := hostVarArgRe.FindStringSubmatch(a); m != nil {
			p.hosts = append(p.hosts, m[2])
			p.hostArgs = append(p.hostArgs, a)
			p.hostVars = append(p.hostVars, m[1])
			continue
		}
		m := hostArgRe.FindStringSubmatch(a)
		if m == nil {
			return false, fmt.Errorf("rule %q: host %q must be ${PORTCULLIS_HOST_<ROUTER>:-<sub>.portcullis.local}", p.s, a)
		}
		p.hosts = append(p.hosts, strings.ToLower(m[1]))
		p.hostArgs = append(p.hostArgs, a)
		p.hostVars = append(p.hostVars, "")
	}
	return true, nil
}

func (p *ruleParser) str() (string, error) {
	p.skipSpace()
	if p.pos >= len(p.s) || (p.s[p.pos] != '`' && p.s[p.pos] != '"') {
		return "", fmt.Errorf("rule %q: expected a quoted string at %q", p.s, p.s[p.pos:])
	}
	q := p.s[p.pos]
	end := strings.IndexByte(p.s[p.pos+1:], q)
	if end < 0 {
		return "", fmt.Errorf("rule %q: unterminated string", p.s)
	}
	v := p.s[p.pos+1 : p.pos+1+end]
	if q == '"' && strings.Contains(v, `\`) {
		return "", fmt.Errorf("rule %q: escapes in strings are not supported", p.s)
	}
	p.pos += end + 2
	return v, nil
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

var (
	runtimeHostRe = regexp.MustCompile(`(?i)\bHost\(([^)]*)\)`)
	// runtimeOtherHostRe: host matchers whose hosts can't be derived.
	runtimeOtherHostRe = regexp.MustCompile(`(?i)\bHost(?:Regexp|Header|SNI|SNIRegexp)\([^)]*\)`)
	quotedRe           = regexp.MustCompile("[`\"]([^`\"]*)[`\"]")
	dnsLabelRe         = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

// RuntimeHosts extracts, leniently, the full hostnames a running
// container's (already variable-substituted) Traefik rule routes: every
// Host() argument, on any domain (main, enrolled or other), lowercased
// with one trailing dot dropped. Used to fail closed for apps the Hub has
// no config for, so it errs towards finding hosts. unparsed lists what
// could not be turned into a hostname (an invalid Host() argument, a
// Host() without a quoted argument, HostRegexp/HostHeader/HostSNI
// matchers): the caller still denies the hosts it found and logs these.
func RuntimeHosts(rule string) (hosts, unparsed []string) {
	for _, m := range runtimeHostRe.FindAllStringSubmatch(rule, -1) {
		qs := quotedRe.FindAllStringSubmatch(m[1], -1)
		if len(qs) == 0 {
			unparsed = append(unparsed, m[0])
		}
		for _, q := range qs {
			h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(q[1]), "."))
			if ValidHostname(h) {
				hosts = append(hosts, h)
			} else {
				unparsed = append(unparsed, q[1])
			}
		}
	}
	unparsed = append(unparsed, runtimeOtherHostRe.FindAllString(rule, -1)...)
	return hosts, unparsed
}
