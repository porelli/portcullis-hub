package aigate

// Validation, ported rule for rule from core
// mcp-gate/internal/config/config.go (File.validate, Resource.validate,
// validateCompanion, CredFile.validate): a file these rules refuse would
// make the gate refuse every request. Keep the two in step.

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/portcullis/hub/internal/signin"
)

var (
	hostLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	idShape   = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	credID    = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	headerTok = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+.^_|~-]+$`)
	upstreamR = regexp.MustCompile(`^http://portcullis-mcp-([a-z0-9-]+)--([a-z0-9-]+):([0-9]{1,5})(/[A-Za-z0-9._~/-]*)$`)
	originR   = regexp.MustCompile(`^https://([^/:]+)(:[0-9]{1,5})?$`)
)

// ValidHostname: a lowercase DNS name without a trailing dot.
func ValidHostname(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for _, l := range strings.Split(h, ".") {
		if !hostLabel.MatchString(l) {
			return false
		}
	}
	return true
}

// NormalizeHost lowercases a request host, strips a numeric :<port> and
// trailing dots (§15.2). Anything else that isn't a hostname gives "".
func NormalizeHost(h string) string {
	h = strings.ToLower(h)
	if i := strings.LastIndexByte(h, ':'); i >= 0 {
		port := h[i+1:]
		if port == "" || len(port) > 5 || strings.Trim(port, "0123456789") != "" {
			return ""
		}
		h = h[:i]
	}
	h = strings.TrimRight(h, ".")
	if !ValidHostname(h) {
		return ""
	}
	return h
}

func sortedUnique(list []string, what string, valid func(string) bool) error {
	for i, s := range list {
		if valid != nil && !valid(s) {
			return fmt.Errorf("%s[%d]: invalid value", what, i)
		}
		if i > 0 && list[i-1] >= s {
			return fmt.Errorf("%s: not sorted or not unique", what)
		}
	}
	return nil
}

func nonEmpty(s string) bool { return s != "" && strings.TrimSpace(s) == s && !hasControl(s) }

func hasControl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

// usernameR is exactly the Hub's lldap.ValidUsername (hub
// internal/lldap/validate.go): lowercase ASCII. Matching after
// lowercasing alone isn't enough: strings.ToLower maps non-ASCII letters
// (the Kelvin sign U+212A) onto ASCII ones, so tokens are also checked
// before lowercasing (authz).
var usernameR = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ValidUsername: a lowercase ASCII username (the population's form).
func ValidUsername(s string) bool { return usernameR.MatchString(s) }

func validUser(s string) bool { return ValidUsername(s) }

// ValidCredentialID: an app-side credential id as §15.4 allows it.
func ValidCredentialID(s string) bool { return credID.MatchString(s) }

// Clients that may never use an MCP resource (§15.2).
var forbiddenClients = []string{"portcullis-forward-auth", "portcullis-fresh-auth"}

// Header names the identity mode may never set: the gate controls them,
// or they carry identity the person's client must not choose.
func forbiddenHeader(h string) bool {
	l := strings.ToLower(h)
	switch l {
	case "host", "cookie", "content-length", "transfer-encoding", "connection", "te", "upgrade", "content-type", "accept":
		return true
	}
	for _, p := range []string{"x-forwarded-", "x-auth-request-", "remote-", "x-portcullis-", "mcp-"} {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	return false
}

// Validate applies the gate's rules (core config.go File.validate).
func (f *File) Validate() error {
	if f.Version != FileVersion {
		return fmt.Errorf("version: not %d", FileVersion)
	}
	if !ValidHostname(f.MainDomain) {
		return fmt.Errorf("main_domain: invalid")
	}
	if f.Issuer != "https://auth."+f.MainDomain+"/realms/portcullis" {
		return fmt.Errorf("issuer: not https://auth.<main_domain>/realms/portcullis")
	}
	if err := sortedUnique(f.Clients, "clients", nonEmpty); err != nil {
		return err
	}
	for _, c := range forbiddenClients {
		if slices.Contains(f.Clients, c) {
			return fmt.Errorf("clients: %s may never use an MCP resource", c)
		}
	}
	if err := sortedUnique(f.AllowedOrigins, "allowed_origins", func(s string) bool {
		m := originR.FindStringSubmatch(s)
		return m != nil && ValidHostname(m[1]) && validPort(strings.TrimPrefix(m[2], ":"), m[2] == "")
	}); err != nil {
		return err
	}
	if err := sortedUnique(f.Methods, "methods", knownMethod); err != nil {
		return err
	}
	l := f.Limits
	for name, v := range map[string]int64{
		"resource_rpm": int64(l.ResourceRPM), "resource_burst": int64(l.ResourceBurst), "person_rpm": int64(l.PersonRPM),
		"tool_calls_rpm": int64(l.ToolCallsRPM), "confirmations_per_hour": int64(l.ConfirmationsPerHour),
		"mints_per_minute": int64(l.MintsPerMinute), "fanout": int64(l.Fanout),
	} {
		if v <= 0 {
			return fmt.Errorf("limits.%s: not positive", name)
		}
	}
	if l.Fanout > MaxFanout {
		return fmt.Errorf("limits.fanout: at most %d", MaxFanout)
	}
	if l.MaxRequestBytes != FixedMaxRequestBytes || l.MaxResultBytes != FixedMaxResultBytes || l.UpstreamTimeoutS != FixedUpstreamTimeoutS {
		return fmt.Errorf("limits: max_request_bytes, max_result_bytes and upstream_timeout_s are fixed in this release")
	}
	if err := sortedUnique(f.CoreHosts, "core_hosts", ValidHostname); err != nil {
		return err
	}
	index := map[string]bool{}
	kinds := map[string]int{}
	for i := range f.Resources {
		r := &f.Resources[i]
		if i > 0 && f.Resources[i-1].URL >= r.URL {
			return fmt.Errorf("resources: not sorted by url or not unique")
		}
		if err := r.validate(f); err != nil {
			return fmt.Errorf("resources[%d]: %w", i, err)
		}
		u, _ := url.Parse(r.URL) // checked by validate
		key := r.Host + u.Path
		if index[key] {
			return fmt.Errorf("resources[%d]: a second resource on %s", i, r.URL)
		}
		index[key] = true
		kinds[r.Kind]++
		if r.Kind != KindCompanion && kinds[r.Kind] > 1 {
			return fmt.Errorf("resources[%d]: a second %s resource", i, r.Kind)
		}
	}
	return nil
}

func validPort(p string, empty bool) bool {
	if empty {
		return true
	}
	n, err := strconv.Atoi(p)
	return err == nil && n >= 1 && n <= 65535 && strconv.Itoa(n) == p
}

// validate checks one resource in f (core config.go Resource.validate).
func (r *Resource) validate(f *File) error {
	if !ValidHostname(r.Host) {
		return fmt.Errorf("host: invalid")
	}
	u, err := url.Parse(r.URL)
	if err != nil || u.Scheme != "https" || u.Host != r.Host || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		u.RawPath != "" || !strings.HasPrefix(u.Path, "/") || r.URL != "https://"+r.Host+u.Path {
		return fmt.Errorf("url: not https://<host><path>")
	}
	if !nonEmpty(r.Label) {
		return fmt.Errorf("label: empty")
	}
	if err := validRule(r.Rule, f.Methods); err != nil {
		return fmt.Errorf("rule: %w", err)
	}
	if err := sortedUnique(r.Clients, "clients", func(c string) bool { return slices.Contains(f.Clients, c) }); err != nil {
		return fmt.Errorf("%w (each client must be in the top-level clients)", err)
	}
	if err := sortedUnique(r.Population, "population", validUser); err != nil {
		return err
	}
	pop := make(map[string]struct{}, len(r.Population))
	for _, p := range r.Population {
		pop[p] = struct{}{}
	}
	for u := range r.Expiring {
		if _, ok := pop[u]; !ok {
			return fmt.Errorf("expiring: a user outside the population")
		}
	}
	for _, list := range [][]string{r.Tools.Writes, r.Tools.Confirm, r.Tools.Never} {
		for _, p := range list {
			if !nonEmpty(p) {
				return fmt.Errorf("tools: an empty pattern")
			}
		}
	}
	if r.People != nil && r.Identity.Mode != "identity_headers" {
		return fmt.Errorf("people: only for identity_headers companions")
	}
	for u, p := range r.People {
		if _, ok := pop[u]; !ok {
			return fmt.Errorf("people: a user outside the population")
		}
		if hasControl(p.Email) {
			return fmt.Errorf("people: invalid email")
		}
		if err := sortedUnique(p.Groups, "people.groups", nonEmpty); err != nil {
			return err
		}
	}
	if r.Kind == KindCompanion {
		return r.validateCompanion(f)
	}
	want := map[string][3]string{
		KindAggregate: {"mcp", "mcp:all", "false"},
		KindAdmin:     {"hub", "mcp:portcullis.admin", "false"},
		KindPeople:    {"people", "mcp:portcullis.people", "true"},
	}
	w, ok := want[r.Kind]
	if !ok {
		return fmt.Errorf("kind: unknown")
	}
	if r.URL != "https://"+w[0]+"."+f.MainDomain+"/mcp" {
		return fmt.Errorf("url: not https://%s.<main_domain>/mcp", w[0])
	}
	if r.Scope != w[1] {
		return fmt.Errorf("scope: not %s", w[1])
	}
	if strconv.FormatBool(r.Aggregate) != w[2] {
		return fmt.Errorf("aggregate: must be %s", w[2])
	}
	if r.Instance != "" || r.Companion != "" || r.AppURL != "" || r.Upstream != "" || r.Mode != "" ||
		len(r.Hosts) != 0 || len(r.Protocol) != 0 || r.Identity != (Identity{Mode: "none"}) ||
		len(r.Tools.Writes)+len(r.Tools.Confirm)+len(r.Tools.Never) != 0 {
		return fmt.Errorf("companion-only fields set on a %s resource", r.Kind)
	}
	return nil
}

func (r *Resource) validateCompanion(f *File) error {
	if !idShape.MatchString(r.Instance) || !idShape.MatchString(r.Companion) {
		return fmt.Errorf("instance / companion: invalid id")
	}
	if r.Scope != "mcp:"+r.Instance+"."+r.Companion {
		return fmt.Errorf("scope: not mcp:<instance>.<companion>")
	}
	if err := sortedUnique(r.Hosts, "hosts", ValidHostname); err != nil {
		return err
	}
	if !slices.Contains(r.Hosts, r.Host) {
		return fmt.Errorf("hosts: must contain host")
	}
	for _, h := range r.Hosts {
		if slices.Contains(f.CoreHosts, h) {
			return fmt.Errorf("hosts: a core host")
		}
	}
	au, err := url.Parse(r.AppURL)
	if err != nil || au.Scheme != "https" || r.AppURL != "https://"+au.Host || !slices.Contains(r.Hosts, au.Host) {
		return fmt.Errorf("app_url: not https://<one of hosts>")
	}
	m := upstreamR.FindStringSubmatch(r.Upstream)
	if m == nil || m[1] != r.Instance || m[2] != r.Companion || !validPort(m[3], false) {
		return fmt.Errorf("upstream: not http://portcullis-mcp-<instance>--<companion>:<port><path>")
	}
	if len(r.Protocol) == 0 {
		return fmt.Errorf("protocol: empty")
	}
	seen := map[string]bool{}
	for _, p := range r.Protocol {
		if !slices.Contains(SupportedProtocols, p) || seen[p] {
			return fmt.Errorf("protocol: unsupported or repeated version")
		}
		seen[p] = true
	}
	if r.Mode != "read_only" && r.Mode != "read_write" {
		return fmt.Errorf("mode: not read_only or read_write")
	}
	if signin.NeedsCertificate(r.Rule) {
		// §15.2: no MCP client presents a certificate; such an instance
		// can't get AI support (the Hub never lists it).
		return fmt.Errorf("rule: needs a client certificate on every alternative")
	}
	id := r.Identity
	if !headerTok.MatchString(id.Header) || forbiddenHeader(id.Header) {
		return fmt.Errorf("identity.header: invalid or reserved")
	}
	if hasControl(id.Format) || hasControl(id.BasicUser) {
		return fmt.Errorf("identity: control characters")
	}
	switch id.Mode {
	case "app_token":
		basic := id.Format == "" && id.BasicUser != ""
		formatted := id.Format != "" && id.BasicUser == "" && strings.Contains(id.Format, "{credential}")
		if !(basic || formatted) || id.SecretRef != "" {
			return fmt.Errorf("identity: app_token needs format with {credential} or basic_user")
		}
	case "identity_headers":
		if !strings.Contains(id.Format, "{secret}") || id.BasicUser != "" || id.SecretRef != r.Instance+"/"+r.Companion {
			return fmt.Errorf("identity: identity_headers needs format with {secret} and secret_ref <instance>/<companion>")
		}
	default:
		return fmt.Errorf("identity.mode: not app_token or identity_headers")
	}
	return nil
}

// knownMethod: one of the six sign-in method ids (§8.1; no family, no amr
// value).
func knownMethod(s string) bool { return slices.Contains(signin.Methods, signin.Method(s)) }

// validRule is §15.4's rule check: a compiled rule (signin.ValidateCompiled:
// a group at the top, op all / any, no empty group, depth ≤ 4, ≤ 48 leaves,
// every leaf a method id), groups of at most 8 items, and every leaf among
// methods (the switched-on ones). Errors never quote values.
func validRule(n signin.Node, methods []string) error {
	if err := signin.ValidateCompiled(n); err != nil {
		return fmt.Errorf("not a compiled rule")
	}
	var walk func(n signin.Node) error
	walk = func(n signin.Node) error {
		if n.Op == "" {
			if !slices.Contains(methods, n.Leaf) {
				return fmt.Errorf("a method that isn't in methods")
			}
			return nil
		}
		if len(n.Items) > signin.MaxItems {
			return fmt.Errorf("a group of more than %d items", signin.MaxItems)
		}
		for _, it := range n.Items {
			if err := walk(it); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(n)
}

// Validate applies the gate's rules (core config.go CredFile.validate).
func (c *CredFile) Validate() error {
	if c.Version != 1 {
		return fmt.Errorf("version: not 1")
	}
	for i, e := range c.Credentials {
		if !idShape.MatchString(e.Instance) || !idShape.MatchString(e.Companion) || !validUser(e.User) {
			return fmt.Errorf("credentials[%d]: invalid instance, companion or user", i)
		}
		if !credID.MatchString(e.ID) {
			return fmt.Errorf("credentials[%d]: invalid id", i)
		}
		switch {
		case e.State == "active" && e.Age != "":
		case e.State == "revoking" && e.Age == "":
		default:
			return fmt.Errorf("credentials[%d]: state must be active (with age) or revoking (age empty)", i)
		}
		if i > 0 && cmp3(c.Credentials[i-1], e) >= 0 {
			return fmt.Errorf("credentials[%d]: not sorted by instance, companion, user or not unique", i)
		}
	}
	for i, s := range c.CallerSecrets {
		in, co, ok := strings.Cut(s.Ref, "/")
		if !ok || !idShape.MatchString(in) || !idShape.MatchString(co) || s.Age == "" {
			return fmt.Errorf("caller_secrets[%d]: invalid ref or empty age", i)
		}
		if i > 0 && c.CallerSecrets[i-1].Ref >= s.Ref {
			return fmt.Errorf("caller_secrets[%d]: not sorted by ref or not unique", i)
		}
	}
	return nil
}

func cmp3(a, b Credential) int {
	return slices.Compare([]string{a.Instance, a.Companion, a.User}, []string{b.Instance, b.Companion, b.User})
}
