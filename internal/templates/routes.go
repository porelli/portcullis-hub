package templates

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Traefik routing is parsed from the compose YAML rather than grepped, and
// anything the Hub cannot fully resolve is rejected: group-gate keys every
// policy and group by subdomain, so a host the Hub doesn't see would get no
// policy and no group (fail open).

var (
	routerLabelRe = regexp.MustCompile(`^traefik\.(http|tcp|udp)\.routers\.([^.]+)\.(.+)$`)
	// hostArgRe is the only accepted Host() argument: a literal DNS label
	// followed by the core domain variable (optionally with a default).
	hostArgRe = regexp.MustCompile(`^(?i)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.\$\{PORTCULLIS_DOMAIN(?:(?::?[-?])[^${}]*)?\}$`)
	// Matchers that could route hosts outside "<label>.${PORTCULLIS_DOMAIN}".
	forbiddenMatchers = map[string]bool{"hostregexp": true, "hostheader": true, "hostsni": true, "hostsniregexp": true}
)

// Routes is what a compose file exposes through Traefik.
type Routes struct {
	// Subdomains routed by HTTP routers, lowercase, sorted, de-duplicated.
	Subdomains []string
	// Routers maps service → HTTP router names (sorted).
	Routers map[string][]string
}

// ParseRoutes extracts Traefik routing from a compose file and validates it:
//   - every HTTP router has a rule, and every way the rule can match is
//     restricted by Host(); there must be no top-level "||" branch, negation
//     or default rule that matches any host
//   - every Host() argument is a literal `<label>.${PORTCULLIS_DOMAIN…}`
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
	r := &Routes{Routers: map[string][]string{}}
	subs := map[string]bool{}
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
		}
		httpRouters := map[string]*router{}
		for k, v := range labels {
			m := routerLabelRe.FindStringSubmatch(k)
			if m == nil {
				continue
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
			if attr == "rule" {
				rt.rule, rt.hasRule = v, true
			}
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
			hosts, err := ParseRule(rt.rule)
			if err != nil {
				return nil, fmt.Errorf("service %s: router %s: %w", svc, name, err)
			}
			for _, h := range hosts {
				subs[h] = true
			}
		}
		if len(rnames) > 0 {
			r.Routers[svc] = rnames
		}
	}
	for s := range subs {
		r.Subdomains = append(r.Subdomains, s)
	}
	sort.Strings(r.Subdomains)
	return r, nil
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
	s     string
	pos   int
	hosts []string
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
		return nil, fmt.Errorf("rule %q can match requests for any host — restrict every branch with Host(`<sub>.${PORTCULLIS_DOMAIN}`)", rule)
	}
	return p.hosts, nil
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
		if _, err := p.factor(); err != nil {
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
	if forbiddenMatchers[lname] {
		return false, fmt.Errorf("rule %q: %s() is not allowed — use Host(`<sub>.${PORTCULLIS_DOMAIN}`)", p.s, name)
	}
	if lname != "host" {
		return false, nil
	}
	if len(args) == 0 {
		return false, fmt.Errorf("rule %q: empty Host()", p.s)
	}
	for _, a := range args {
		m := hostArgRe.FindStringSubmatch(a)
		if m == nil {
			return false, fmt.Errorf("rule %q: host %q must be a literal <sub>.${PORTCULLIS_DOMAIN}", p.s, a)
		}
		p.hosts = append(p.hosts, strings.ToLower(m[1]))
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
	quotedRe      = regexp.MustCompile("[`\"]([^`\"]*)[`\"]")
	dnsLabelRe    = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

// RuntimeSubdomains extracts, leniently, the subdomains of domain that a
// running container's (already variable-substituted) Traefik rule routes:
// every Host() argument of the form <label>.<domain>. Used to fail closed
// for apps the Hub has no config for, so it errs towards finding hosts.
func RuntimeSubdomains(rule, domain string) []string {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	var out []string
	for _, m := range runtimeHostRe.FindAllStringSubmatch(rule, -1) {
		for _, q := range quotedRe.FindAllStringSubmatch(m[1], -1) {
			h := strings.ToLower(strings.TrimSuffix(q[1], "."))
			if label, ok := strings.CutSuffix(h, "."+domain); ok && dnsLabelRe.MatchString(label) {
				out = append(out, label)
			}
		}
	}
	return out
}
