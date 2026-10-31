package templates

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Public path exceptions (auth.public_access, contract §3/§4).
//
// When an app's public exceptions are on, the Hub adds one Traefik router
// for the declared prefixes that skips forward-auth and group-gate. Every
// endpoint under a prefix is then reachable by anyone, so prefixes are
// validated strictly here and against the compose routing in PlanPublic.

const (
	// MaxPublicPaths caps auth.public_access.paths.
	MaxPublicPaths = 20
	// MaxPublicTokens caps the shares listed for one app (listed mode):
	// each token adds two matchers per {token} path to one Traefik rule.
	MaxPublicTokens = 200
	// TokenPlaceholder marks the share-token segment of a public path.
	TokenPlaceholder = "{token}"
	// Public access modes.
	ModeAll    = "all"
	ModeListed = "listed"
)

var (
	// publicPrefixRe: one or more non-empty segments of unreserved URL
	// characters, optional trailing "/". No "%", "?", "#", "*", quotes,
	// backticks, "$", "(", ")": the prefix is spliced into a Traefik rule
	// inside a compose label (where "$" would be interpolated).
	publicPrefixRe = regexp.MustCompile(`^(/[A-Za-z0-9._~-]+)+/?$`)
	// tokenCharsRe is what any share token must be made of, whatever the
	// template's token_pattern says (same alphabet as prefixes).
	tokenCharsRe = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,128}$`)

	// broadPrefixes would expose a whole API, front controller or login
	// surface; they need broad: true plus a justification.
	broadPrefixes = map[string]bool{
		"/api": true, "/apps": true, "/index.php": true, "/ocs": true, "/ocs/v1.php": true, "/ocs/v2.php": true,
		"/remote.php": true, "/remote.php/dav": true, "/remote.php/webdav": true, "/public.php": true,
		"/dav": true, "/webdav": true, "/graphql": true, "/rest": true, "/v1": true, "/v2": true, "/v3": true,
		"/auth": true, "/login": true, "/user": true, "/users": true, "/account": true, "/settings": true,
		"/identity": true, "/sso": true, "/oidc": true,
	}
	// forbiddenPrefixes may never be public (and nothing under them).
	forbiddenPrefixes = []string{"/oauth2", "/admin", "/.well-known"}

	// tokenPatternProbes must never be accepted as a token.
	tokenPatternProbes = []string{"", ".", "..", "a/b", "/", "a`b", "a b", "%2F", "${X}", "a)b", "a\nb"}
)

// publicMethods are the auth methods public exceptions make sense for: the
// router skips Portcullis' gate, the app's own auth still applies. mtls
// apps have no other auth than the TLS handshake, public/custom apps no
// gate to skip.
var publicMethods = map[string]bool{"forward-auth": true, "header-auth": true, "native-oidc": true}

// StaticExtensions are the file extensions supporting paths serve by
// default; templates may add more in static_extensions (never script
// extensions). Supporting paths are matched as static files only: a
// PathRegexp of dot-free directory segments and a file name ending in one
// of these extensions, so no PATH_INFO trick (x.php/y.js) and no
// extension-less app route matches.
var StaticExtensions = []string{"avif", "css", "eot", "gif", "ico", "jpeg", "jpg", "js", "map", "mjs", "otf", "png", "svg", "ttf", "webp", "woff", "woff2"}

var (
	extRe = regexp.MustCompile(`^[a-z0-9]{1,8}$`)
	// scriptExtensions can never be static_extensions.
	scriptExtensions = map[string]bool{"php": true, "php3": true, "php4": true, "php5": true, "php7": true, "php8": true, "phtml": true,
		"phar": true, "pht": true, "phps": true, "cgi": true, "fcgi": true, "pl": true, "py": true, "rb": true, "sh": true,
		"asp": true, "aspx": true, "jsp": true, "jspx": true, "shtml": true, "htaccess": true, "exe": true, "dll": true}
	cookieNameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
)

// headerNameRe constrains auth.identity_headers (they become label keys).
var headerNameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,63}$`)

// ValidateIdentityHeaders checks auth.identity_headers.
func ValidateIdentityHeaders(hs []string) error {
	seen := map[string]bool{}
	for _, h := range hs {
		if !headerNameRe.MatchString(h) {
			return fmt.Errorf("auth.identity_headers: %q is not a header name (letters, digits, -)", h)
		}
		if seen[strings.ToLower(h)] {
			return fmt.Errorf("auth.identity_headers: duplicate %q", h)
		}
		seen[strings.ToLower(h)] = true
	}
	return nil
}

// NormalizePublicPrefix validates a public_access prefix (optionally with
// one whole-segment {token}) and returns it without its trailing "/".
func NormalizePublicPrefix(p string) (string, error) {
	if len(p) > 256 {
		return "", fmt.Errorf("prefix %q is too long", p)
	}
	check := p
	if n := strings.Count(p, TokenPlaceholder); n > 1 {
		return "", fmt.Errorf("prefix %q has more than one %s", p, TokenPlaceholder)
	} else if n == 1 {
		segs := strings.Split(strings.TrimRight(p, "/"), "/")
		ok := false
		for _, s := range segs {
			ok = ok || s == TokenPlaceholder
		}
		if !ok {
			return "", fmt.Errorf("prefix %q: %s must be a whole path segment", p, TokenPlaceholder)
		}
		check = strings.Replace(p, TokenPlaceholder, "x", 1)
	}
	if !publicPrefixRe.MatchString(check) {
		return "", fmt.Errorf("prefix %q must be /segment[/segment...] of letters, digits and . _ ~ - (not \"/\" itself, no wildcards, //, %%, ?, #)", p)
	}
	if strings.Contains(check, "..") {
		return "", fmt.Errorf("prefix %q may not contain ..", p)
	}
	for _, seg := range strings.Split(check, "/") {
		if seg == "." {
			return "", fmt.Errorf("prefix %q may not contain . segments", p)
		}
	}
	return strings.TrimRight(p, "/"), nil
}

// tokenBase is a {token} prefix cut before the token segment (what "all"
// mode opens); other prefixes are returned unchanged.
func tokenBase(p string) string {
	if i := strings.Index(p, "/"+TokenPlaceholder); i >= 0 {
		if i == 0 {
			return "/"
		}
		return p[:i]
	}
	return p
}

// IsBroadPublicPrefix reports whether a normalised prefix is on the
// broad-prefix list, or is a bare *.php front controller.
func IsBroadPublicPrefix(p string) bool {
	if broadPrefixes[strings.ToLower(p)] {
		return true
	}
	return strings.Count(p, "/") == 1 && strings.HasSuffix(strings.ToLower(p), ".php")
}

// segmentOverlap reports whether two normalised segment-boundary prefixes
// can match the same path (one equals or contains the other).
func segmentOverlap(a, b string) bool {
	if a == "/" || b == "/" {
		return true
	}
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

// HasTokenPaths reports whether any public path has a {token} segment.
func (pa *PublicAccess) HasTokenPaths() bool {
	for _, pp := range pa.Paths {
		if strings.Contains(pp.Prefix, TokenPlaceholder) {
			return true
		}
	}
	return false
}

// Mode returns DefaultMode, or its default.
func (pa *PublicAccess) Mode() string {
	if pa.DefaultMode != "" {
		return pa.DefaultMode
	}
	if pa.HasTokenPaths() {
		return ModeListed
	}
	return ModeAll
}

// ValidatePublicAccess checks auth.public_access on its own (no compose
// file) and normalises the prefixes in place.
func ValidatePublicAccess(a *Auth) error {
	pa := a.PublicAccess
	if pa == nil {
		return nil
	}
	if !publicMethods[a.Method] {
		return fmt.Errorf("auth.public_access needs auth.method forward-auth, header-auth or native-oidc (got %q)", a.Method)
	}
	if a.Method == "header-auth" && len(a.IdentityHeaders) == 0 {
		return fmt.Errorf("auth.public_access on a header-auth app needs auth.identity_headers (the headers the app trusts), so the Hub can strip them on public paths")
	}
	if HasControlChars(pa.Description) || len(pa.Description) > 500 {
		return fmt.Errorf("auth.public_access.description must be one line of at most 500 characters")
	}
	if err := ValidateIdentityHeaders(pa.CredentialHeaders); err != nil {
		return fmt.Errorf("auth.public_access.credential_headers: %w", err)
	}
	for _, c := range pa.CredentialCookies {
		if !cookieNameRe.MatchString(c) {
			return fmt.Errorf("auth.public_access.credential_cookies: %q is not a cookie name ([A-Za-z0-9_.-], max 64)", c)
		}
	}
	for _, q := range pa.CredentialQuery {
		if !cookieNameRe.MatchString(q) {
			return fmt.Errorf("auth.public_access.credential_query: %q is not a parameter name ([A-Za-z0-9_.-], max 64)", q)
		}
	}
	for _, e := range pa.StaticExtensions {
		if !extRe.MatchString(e) || scriptExtensions[e] {
			return fmt.Errorf("auth.public_access.static_extensions: %q is not allowed (lowercase [a-z0-9]{1,8}, no script extensions)", e)
		}
	}
	if pa.Service != "" && !serviceNameRe.MatchString(pa.Service) {
		return fmt.Errorf("auth.public_access.service %q is not a compose service name", pa.Service)
	}
	if len(pa.Paths) == 0 {
		return fmt.Errorf("auth.public_access.paths is empty")
	}
	if len(pa.Paths) > MaxPublicPaths {
		return fmt.Errorf("auth.public_access.paths has %d entries (max %d)", len(pa.Paths), MaxPublicPaths)
	}
	seen := map[string]bool{}
	shareable := false
	for i := range pa.Paths {
		pp := &pa.Paths[i]
		norm, err := NormalizePublicPrefix(pp.Prefix)
		if err != nil {
			return fmt.Errorf("auth.public_access.paths[%d]: %w", i, err)
		}
		if seen[norm] {
			return fmt.Errorf("auth.public_access.paths[%d]: duplicate prefix %q", i, norm)
		}
		seen[norm] = true
		pp.Prefix = norm
		tokenised := strings.Contains(norm, TokenPlaceholder)
		if tokenised && pp.Supporting {
			return fmt.Errorf("auth.public_access.paths[%d]: %s has a %s, so it can't be supporting", i, norm, TokenPlaceholder)
		}
		if pp.Exact {
			if tokenised {
				return fmt.Errorf("auth.public_access.paths[%d]: %s has a %s, so it can't be exact", i, norm, TokenPlaceholder)
			}
			if strings.TrimSpace(pp.Justification) == "" {
				return fmt.Errorf("auth.public_access.paths[%d]: exact path %s needs a justification (which app route, why the share page needs it)", i, norm)
			}
		}
		shareable = shareable || !pp.Supporting
		// Everything below is checked on what "all" mode opens: a {token}
		// prefix up to the token segment.
		base := tokenBase(norm)
		if base == "/" {
			return fmt.Errorf("auth.public_access.paths[%d]: %s would open / in mode all", i, norm)
		}
		if strings.TrimSpace(pp.Description) == "" || HasControlChars(pp.Description) || len(pp.Description) > 200 {
			return fmt.Errorf("auth.public_access.paths[%d] (%s): description is required (one line, max 200 characters)", i, norm)
		}
		for _, f := range forbiddenPrefixes {
			if segmentOverlap(strings.ToLower(base), f) {
				return fmt.Errorf("auth.public_access.paths[%d]: %s overlaps %s, which can never be public", i, norm, f)
			}
		}
		if pp.Exact {
			// One path, no subpaths: the broad list does not apply.
			if pp.Broad {
				return fmt.Errorf("auth.public_access.paths[%d]: broad: true on exact path %s", i, norm)
			}
		} else if IsBroadPublicPrefix(base) {
			if !pp.Broad || strings.TrimSpace(pp.Justification) == "" {
				return fmt.Errorf("auth.public_access.paths[%d]: %s is a broad prefix (whole API / front controller); narrow it, or set broad: true with a justification", i, base)
			}
		} else if pp.Broad {
			return fmt.Errorf("auth.public_access.paths[%d]: broad: true on %s, which is not a broad prefix", i, base)
		}
		if HasControlChars(pp.Justification) {
			return fmt.Errorf("auth.public_access.paths[%d]: justification contains control characters", i)
		}
		for _, ap := range a.AdminPaths {
			if segmentOverlap(base, ap) {
				return fmt.Errorf("auth.public_access.paths[%d]: %s overlaps admin path %s", i, norm, ap)
			}
		}
	}
	if !shareable {
		return fmt.Errorf("auth.public_access.paths has only supporting paths")
	}
	switch pa.DefaultMode {
	case "", ModeAll:
	case ModeListed:
		if !pa.HasTokenPaths() {
			return fmt.Errorf("auth.public_access.default_mode listed needs a path with %s", TokenPlaceholder)
		}
	default:
		return fmt.Errorf("auth.public_access.default_mode %q must be all or listed", pa.DefaultMode)
	}
	if pa.HasTokenPaths() {
		if _, err := compileTokenPattern(pa.TokenPattern); err != nil {
			return fmt.Errorf("auth.public_access.token_pattern: %w", err)
		}
	} else if pa.TokenPattern != "" {
		return fmt.Errorf("auth.public_access.token_pattern is set but no path has %s", TokenPlaceholder)
	}
	return nil
}

func compileTokenPattern(p string) (*regexp.Regexp, error) {
	if p == "" {
		return nil, fmt.Errorf("required when a path has %s", TokenPlaceholder)
	}
	if !strings.HasPrefix(p, "^") || !strings.HasSuffix(p, "$") || strings.HasSuffix(p, `\$`) {
		return nil, fmt.Errorf("%q must be anchored (^...$)", p)
	}
	re, err := regexp.Compile(p)
	if err != nil {
		return nil, err
	}
	for _, probe := range tokenPatternProbes {
		if re.MatchString(probe) {
			return nil, fmt.Errorf("%q accepts %q; a token may only use letters, digits and . _ ~ -", p, probe)
		}
	}
	return re, nil
}

// ExtractToken turns what an admin pastes (a share URL or a bare token)
// into a share token valid for pa: the {token} segment of the first
// tokenised path the URL's path matches, checked against token_pattern and
// the prefix alphabet.
func ExtractToken(pa *PublicAccess, input string) (string, error) {
	re, err := compileTokenPattern(pa.TokenPattern)
	if err != nil {
		return "", fmt.Errorf("this app has no per-share tokens")
	}
	in := strings.TrimSpace(input)
	tok := in
	if strings.Contains(in, "/") {
		u, err := url.Parse(in)
		if err != nil {
			return "", fmt.Errorf("%q is neither a share URL nor a token", input)
		}
		tok = ""
		segs := strings.Split(strings.Trim(u.EscapedPath(), "/"), "/")
		for _, pp := range pa.Paths {
			tpl := strings.Split(strings.Trim(pp.Prefix, "/"), "/")
			if !strings.Contains(pp.Prefix, TokenPlaceholder) || len(segs) < len(tpl) {
				continue
			}
			cand, ok := "", true
			for i, ts := range tpl {
				switch {
				case ts == TokenPlaceholder:
					cand = segs[i]
				case ts != segs[i]:
					ok = false
				}
			}
			if ok {
				tok = cand
				break
			}
		}
		if tok == "" {
			return "", fmt.Errorf("%q does not look like a share URL of this app", input)
		}
	}
	if !tokenCharsRe.MatchString(tok) || tok == "." || tok == ".." || !re.MatchString(tok) {
		return "", fmt.Errorf("%q is not a valid share token (must match %s)", tok, pa.TokenPattern)
	}
	return tok, nil
}

var serviceNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)

// PublicPlan is how the Hub routes an app's public paths.
type PublicPlan struct {
	Service string // compose service that gets the router labels
	// TraefikService is the Traefik service the router targets; "" lets
	// Traefik use the container's only (implicit) service.
	TraefikService string
	HostArgs       []string // Host() arguments as written in the template
	Subdomains     []string
	Paths          []PublicPath // normalised manifest paths
	// Priority beats every router of the app, whatever PORTCULLIS_DOMAIN
	// expands to (Traefik's default priority is the rule's length).
	Priority int
}

// maxDomainLen bounds what a ${...} in a rule expands to.
const maxDomainLen = 253

// PlanPublic resolves auth.public_access against the compose routing:
// which service and hosts the public router serves, which Traefik service
// it targets, and a priority above every router of the app. Prefixes (in
// their "all" mode extent) may not overlap any path matcher of the app's
// other routers (login gates, admin routers, API splits): those keep their
// own middlewares. Returns nil, nil when the manifest has no public_access.
func PlanPublic(m *Manifest, r *Routes) (*PublicPlan, error) {
	pa := m.Auth.PublicAccess
	if pa == nil {
		return nil, nil
	}
	svc := pa.Service
	if svc == "" {
		var withRouters []string
		for s := range r.Routers {
			withRouters = append(withRouters, s)
		}
		sort.Strings(withRouters)
		if len(withRouters) != 1 {
			return nil, fmt.Errorf("auth.public_access: %d compose services have HTTP routers (%v) — set auth.public_access.service", len(withRouters), withRouters)
		}
		svc = withRouters[0]
	}
	routers := r.Routers[svc]
	if len(routers) == 0 {
		return nil, fmt.Errorf("auth.public_access.service %q has no HTTP router", svc)
	}
	plan := &PublicPlan{Service: svc, Paths: append([]PublicPath(nil), pa.Paths...)}
	seenSub := map[string]bool{}
	hostWideSvcs := map[string]bool{}
	for _, name := range routers {
		ri := r.Info[name]
		for i, sub := range ri.Subdomains {
			if !seenSub[sub] {
				seenSub[sub] = true
				plan.Subdomains = append(plan.Subdomains, sub)
				plan.HostArgs = append(plan.HostArgs, ri.HostArgs[i])
			}
		}
		if len(ri.Paths) == 0 {
			hostWideSvcs[ri.TraefikService] = true
		}
	}
	switch defined := r.TraefikServices[svc]; len(defined) {
	case 0:
	case 1:
		plan.TraefikService = defined[0]
	default:
		if len(hostWideSvcs) != 1 || hostWideSvcs[""] {
			return nil, fmt.Errorf("auth.public_access: service %s defines several Traefik services (%v) and no single host-wide router names one", svc, defined)
		}
		for s := range hostWideSvcs {
			plan.TraefikService = s
		}
	}

	mine := map[string]bool{}
	for _, s := range plan.Subdomains {
		mine[s] = true
	}
	names := make([]string, 0, len(r.Info))
	for name := range r.Info {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		ri := r.Info[name]
		bound := ri.Priority
		if !ri.HasPriority {
			bound = len(ri.Rule) + strings.Count(ri.Rule, "${")*maxDomainLen
		}
		if bound >= plan.Priority {
			plan.Priority = bound + 1
		}
		shared := false
		for _, s := range ri.Subdomains {
			shared = shared || mine[s]
		}
		if !shared {
			continue
		}
		if len(ri.Opaque) > 0 {
			return nil, fmt.Errorf("auth.public_access: router %s uses %s; the Hub can't tell whether public paths overlap it — use Path/PathPrefix only on the app's hosts", name, strings.Join(ri.Opaque, ", "))
		}
		for _, rp := range ri.Paths {
			for _, pp := range plan.Paths {
				if base := tokenBase(pp.Prefix); rulePathOverlaps(rp, base) {
					return nil, fmt.Errorf("auth.public_access: prefix %s overlaps router %s (%s); public paths may not cover paths another router handles", pp.Prefix, name, rp.Value)
				}
			}
		}
	}
	return plan, nil
}

// rulePathOverlaps reports whether a Traefik Path/PathPrefix matcher and a
// segment-boundary public prefix (matching p and p/...) share any path.
// PathPrefix is a plain string prefix in Traefik.
func rulePathOverlaps(rp RulePath, p string) bool {
	v := rp.Value
	if !rp.Prefix {
		return v == p || strings.HasPrefix(v, p+"/")
	}
	return strings.HasPrefix(p+"/", v) || strings.HasPrefix(v, p+"/")
}

// HasTokenPaths reports whether the plan has {token} paths (listed mode
// is possible).
func (pl *PublicPlan) HasTokenPaths() bool {
	for _, pp := range pl.Paths {
		if strings.Contains(pp.Prefix, TokenPlaceholder) {
			return true
		}
	}
	return false
}

// Routed entries are encoded by kind: "p" = segment-boundary prefix
// (Path(p) || PathPrefix(p/)), "=p" = exact Path(p), "~p" = static files
// under p (PathRegexp). See Rule.
const (
	routedExact  = "="
	routedStatic = "~"
)

// Effective returns what the public router opens for a mode and the
// listed tokens: routed are the encoded entries for the Traefik rule,
// published the same with {token} kept (for the policy file and the UI:
// share tokens are secrets). Both are sorted. In listed mode without
// tokens nothing is opened (no router at all).
func (pl *PublicPlan) Effective(mode string, tokens []string) (routed, published []string) {
	rs, ps := map[string]bool{}, map[string]bool{}
	if mode == ModeListed && len(tokens) == 0 {
		return nil, nil
	}
	for _, pp := range pl.Paths {
		tokenised := strings.Contains(pp.Prefix, TokenPlaceholder)
		enc := pp.Prefix
		switch {
		case pp.Exact:
			enc = routedExact + pp.Prefix
		case pp.Supporting:
			enc = routedStatic + pp.Prefix
		}
		switch {
		case tokenised && mode != ModeListed:
			b := tokenBase(pp.Prefix)
			rs[b], ps[b] = true, true
		case tokenised:
			for _, tok := range tokens {
				rs[strings.Replace(pp.Prefix, TokenPlaceholder, tok, 1)] = true
			}
			ps[pp.Prefix] = true
		case pp.Supporting || mode != ModeListed:
			rs[enc], ps[enc] = true, true
		}
	}
	return sortedKeys(rs), sortedKeys(ps)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// staticRegexp matches static files under prefix: dot-free directory
// segments, then a file name with one of exts.
func staticRegexp(prefix string, exts []string) string {
	return "^" + regexp.QuoteMeta(prefix) + "(/[A-Za-z0-9_~@+-]+)*/[A-Za-z0-9_~@+-][A-Za-z0-9._~@+-]*\\.(" + strings.Join(exts, "|") + ")$"
}

// Extensions returns the static extensions for the app's supporting paths.
func (pa *PublicAccess) Extensions() []string {
	set := map[string]bool{}
	for _, e := range StaticExtensions {
		set[e] = true
	}
	for _, e := range pa.StaticExtensions {
		set[e] = true
	}
	return sortedKeys(set)
}

// cookieRegexp matches a Cookie header value that sets one of names,
// loosely and case-insensitively (fail closed): any character may be
// percent-encoded, and "_" also matches ".", " " and "[" (PHP turns those
// into "_" in cookie names).
func cookieRegexp(names []string) string {
	alts := make([]string, 0, len(names))
	for _, n := range names {
		var b strings.Builder
		for _, c := range n {
			if c == '_' || c == '.' {
				b.WriteString(`(?:[_. \[]|%[0-9a-f]{2})`)
			} else {
				b.WriteString(`(?:` + regexp.QuoteMeta(string(c)) + `|%[0-9a-f]{2})`)
			}
		}
		alts = append(alts, b.String())
	}
	return `(?i)(?:^|[;,])\s*(?:` + strings.Join(alts, "|") + `)\s*=`
}

// Rule is the public router's Traefik rule for the routed entries: the
// plan's hosts, and per entry Path(`p`) || PathPrefix(`p/`) (segment
// boundary), Path(`p`) (exact) or PathRegexp (static files). Requests
// carrying the app's credential cookies or query parameters are excluded:
// they fall through to the app's gated router.
func (pl *PublicPlan) Rule(routed []string, pa *PublicAccess) string {
	exts := StaticExtensions
	var excl []string
	if pa != nil {
		exts = pa.Extensions()
		if len(pa.CredentialCookies) > 0 {
			excl = append(excl, "!HeaderRegexp(`Cookie`, `"+cookieRegexp(pa.CredentialCookies)+"`)")
		}
		for _, q := range pa.CredentialQuery {
			excl = append(excl, "!QueryRegexp(`"+q+"`, `.*`)")
		}
	}
	hosts := make([]string, len(pl.HostArgs))
	for i, h := range pl.HostArgs {
		hosts[i] = "Host(`" + h + "`)"
	}
	host := hosts[0]
	if len(hosts) > 1 {
		host = "(" + strings.Join(hosts, " || ") + ")"
	}
	paths := make([]string, 0, 2*len(routed))
	for _, e := range routed {
		switch {
		case strings.HasPrefix(e, routedExact):
			paths = append(paths, "Path(`"+e[1:]+"`)")
		case strings.HasPrefix(e, routedStatic):
			paths = append(paths, "PathRegexp(`"+staticRegexp(e[1:], exts)+"`)")
		default:
			paths = append(paths, "Path(`"+e+"`)", "PathPrefix(`"+e+"/`)")
		}
	}
	rule := host + " && (" + strings.Join(paths, " || ") + ")"
	for _, e := range excl {
		rule += " && " + e
	}
	return rule
}

// RuntimePublicPrefixes decodes a running public router's rule into the
// encoded entries Effective produces, sorted.
func RuntimePublicPrefixes(rule string) []string {
	prefixes, exacts := map[string]bool{}, map[string]bool{}
	set := map[string]bool{}
	for _, m := range runtimePrefixRe.FindAllStringSubmatch(rule, -1) {
		prefixes[strings.TrimRight(m[1], "/")] = true
	}
	for _, m := range runtimePathRe.FindAllStringSubmatch(rule, -1) {
		exacts[m[1]] = true
	}
	for _, m := range runtimeRegexpRe.FindAllStringSubmatch(rule, -1) {
		set[routedStatic+strings.ReplaceAll(m[1], `\`, "")] = true
	}
	for p := range prefixes {
		set[p] = true
	}
	for p := range exacts {
		if !prefixes[p] {
			set[routedExact+p] = true
		}
	}
	return sortedKeys(set)
}

var (
	runtimePathRe   = regexp.MustCompile("(?i)\\bPath\\([`\"]([^`\"]*)[`\"]\\)")
	runtimeRegexpRe = regexp.MustCompile("(?i)PathRegexp\\([`\"]\\^([^(`\"]*)\\(")
)

var runtimePrefixRe = regexp.MustCompile("(?i)PathPrefix\\([`\"]([^`\"]*)[`\"]\\)")
