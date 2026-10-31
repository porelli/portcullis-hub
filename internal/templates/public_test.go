package templates

import (
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestNormalizePublicPrefix(t *testing.T) {
	ok := map[string]string{
		"/s/":                            "/s",
		"/s":                             "/s",
		"/public.php/dav":                "/public.php/dav",
		"/_app":                          "/_app",
		"/s/{token}":                     "/s/{token}",
		"/public.php/dav/files/{token}/": "/public.php/dav/files/{token}",
	}
	for in, want := range ok {
		if got, err := NormalizePublicPrefix(in); err != nil || got != want {
			t.Errorf("NormalizePublicPrefix(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{"", "/", "s", "//s", "/s//x", "/s/../x", "/..", "/./s", "/s/.", "/a..b", "/s*", "/s?x", "/s#x", "/%2e",
		"/a b", "/a`b", "/a$b", "/a(b", "/a'b", "/a\"b", "/a\\b", "/s/{token}/{token}", "/s/x{token}", "/{tok}", "/" + strings.Repeat("a", 300)}
	for _, in := range bad {
		if got, err := NormalizePublicPrefix(in); err == nil {
			t.Errorf("NormalizePublicPrefix(%q) accepted as %q", in, got)
		}
	}
}

func publicAuth(method string, paths ...PublicPath) *Auth {
	return &Auth{Method: method, PublicAccess: &PublicAccess{Paths: paths}}
}

func pp(prefix string) PublicPath { return PublicPath{Prefix: prefix, Description: "d"} }

func TestValidatePublicAccess(t *testing.T) {
	good := publicAuth("forward-auth", pp("/s/{token}"), PublicPath{Prefix: "/dist/", Description: "assets", Supporting: true})
	good.PublicAccess.TokenPattern = "^[A-Za-z0-9-]{1,32}$"
	if err := ValidatePublicAccess(good); err != nil {
		t.Fatalf("valid public_access rejected: %v", err)
	}
	if good.PublicAccess.Paths[1].Prefix != "/dist" || good.PublicAccess.Mode() != ModeListed {
		t.Errorf("not normalised / wrong default mode: %+v", good.PublicAccess)
	}
	if a := publicAuth("native-oidc", pp("/share")); ValidatePublicAccess(a) != nil || a.PublicAccess.Mode() != ModeAll {
		t.Errorf("token-free app: mode %q", a.PublicAccess.Mode())
	}

	cases := map[string]*Auth{
		"mtls method":                 publicAuth("mtls", pp("/s")),
		"public method":               publicAuth("public", pp("/s")),
		"custom method":               publicAuth("custom", pp("/s")),
		"no method":                   publicAuth("", pp("/s")),
		"no paths":                    publicAuth("forward-auth"),
		"broad api":                   publicAuth("forward-auth", pp("/api")),
		"broad php":                   publicAuth("forward-auth", pp("/index.php")),
		"broad ocs":                   publicAuth("forward-auth", pp("/ocs/v2.php/")),
		"broad justification missing": publicAuth("forward-auth", PublicPath{Prefix: "/api", Description: "d", Broad: true}),
		"broad on narrow":             publicAuth("forward-auth", PublicPath{Prefix: "/api/x", Description: "d", Broad: true, Justification: "j"}),
		"forbidden oauth2":            publicAuth("forward-auth", pp("/oauth2/start")),
		"forbidden admin":             publicAuth("forward-auth", pp("/admin")),
		"no description":              publicAuth("forward-auth", PublicPath{Prefix: "/s"}),
		"duplicate":                   publicAuth("forward-auth", pp("/s"), pp("/s/")),
		"only supporting":             publicAuth("forward-auth", PublicPath{Prefix: "/dist", Description: "d", Supporting: true}),
		"token without regex":         publicAuth("forward-auth", pp("/s/{token}")),
		"regex without token":         {Method: "forward-auth", PublicAccess: &PublicAccess{TokenPattern: "^[a-z]+$", Paths: []PublicPath{pp("/s")}}},
		"listed without token":        {Method: "forward-auth", PublicAccess: &PublicAccess{DefaultMode: ModeListed, Paths: []PublicPath{pp("/s")}}},
		"bad mode":                    {Method: "forward-auth", PublicAccess: &PublicAccess{DefaultMode: "some", Paths: []PublicPath{pp("/s")}}},
		"token at root":               {Method: "forward-auth", PublicAccess: &PublicAccess{TokenPattern: "^[a-z]+$", Paths: []PublicPath{pp("/{token}")}}},
		"supporting token": {Method: "forward-auth", PublicAccess: &PublicAccess{TokenPattern: "^[a-z]+$", Paths: []PublicPath{pp("/s"),
			{Prefix: "/x/{token}", Description: "d", Supporting: true}}}},
		// "all" mode opens /api for /api/{token}: broad.
		"broad token base": {Method: "forward-auth", PublicAccess: &PublicAccess{TokenPattern: "^[a-z]+$", Paths: []PublicPath{pp("/api/{token}")}}},
	}
	for name, a := range cases {
		if err := ValidatePublicAccess(a); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	admin := publicAuth("forward-auth", pp("/settings/x"))
	admin.AdminPaths = []string{"/settings"}
	if ValidatePublicAccess(admin) == nil {
		t.Error("overlap with admin_paths accepted")
	}
	many := publicAuth("forward-auth")
	for i := 0; i <= MaxPublicPaths; i++ {
		many.PublicAccess.Paths = append(many.PublicAccess.Paths, pp("/p"+strings.Repeat("x", i)))
	}
	if ValidatePublicAccess(many) == nil {
		t.Error("too many paths accepted")
	}
	for _, pat := range []string{"[a-z]+", "^[a-z]+", "[a-z]+$", "^.+$", "^[^/]*$", "^[a-z.]*$", "^(", `^[a-z]+\$`} {
		a := publicAuth("forward-auth", pp("/s/{token}"))
		a.PublicAccess.TokenPattern = pat
		if ValidatePublicAccess(a) == nil {
			t.Errorf("token_pattern %q accepted", pat)
		}
	}
	// Broad with justification is allowed.
	if err := ValidatePublicAccess(publicAuth("forward-auth", PublicPath{Prefix: "/api", Description: "d", Broad: true, Justification: "whole API is token-guarded"})); err != nil {
		t.Errorf("justified broad prefix rejected: %v", err)
	}
}

func TestValidateManifestPublicAccess(t *testing.T) {
	var m Manifest
	src := "auth:\n  method: forward-auth\n  public_access:\n    enabled_by_default: true\n    token_pattern: '^[A-Za-z0-9]{6,32}$'\n    paths:\n      - {prefix: \"/s/{token}/\", description: Share page}\n      - {prefix: /dist, description: Assets, supporting: true}\n"
	if err := yaml.Unmarshal([]byte(src), &m); err != nil {
		t.Fatal(err)
	}
	if err := ValidateManifest(&m); err != nil {
		t.Fatal(err)
	}
	if m.Auth.PublicAccess.Paths[0].Prefix != "/s/{token}" || !m.Auth.PublicAccess.EnabledByDefault {
		t.Errorf("manifest = %+v", m.Auth.PublicAccess)
	}
}

func ncAccess() *PublicAccess {
	return &PublicAccess{TokenPattern: "^[A-Za-z0-9-]{1,32}$", Paths: []PublicPath{
		pp("/s/{token}"), pp("/index.php/s/{token}"), pp("/public.php/dav/files/{token}"),
		{Prefix: "/dist", Description: "d", Supporting: true}, pp("/apps/text"),
	}}
}

func TestExtractToken(t *testing.T) {
	pa := ncAccess()
	ok := map[string]string{
		"AbCdEf123456789":                                      "AbCdEf123456789",
		"  AbCdEf123456789 \n":                                 "AbCdEf123456789",
		"https://cloud.example.org/s/AbCdEf123456789":          "AbCdEf123456789",
		"https://cloud.example.org/s/AbCdEf123456789/download": "AbCdEf123456789",
		"https://cloud.example.org/index.php/s/my-share?x=1#f": "my-share",
		"/public.php/dav/files/Tok3n/a.txt":                    "Tok3n",
	}
	for in, want := range ok {
		if got, err := ExtractToken(pa, in); err != nil || got != want {
			t.Errorf("ExtractToken(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{"", "..", ".", "a b", "a`) || Host(`evil", "a.b", strings.Repeat("a", 33), "https://cloud.example.org/apps/files/",
		"https://cloud.example.org/s/", "https://cloud.example.org/s/a%2Fb", "${PORTCULLIS_DOMAIN}", "tok/en"}
	for _, in := range bad {
		if got, err := ExtractToken(pa, in); err == nil {
			t.Errorf("ExtractToken(%q) accepted as %q", in, got)
		}
	}
	if _, err := ExtractToken(&PublicAccess{Paths: []PublicPath{pp("/share")}}, "abc"); err == nil {
		t.Error("token accepted for an app without {token} paths")
	}
}

const publicCompose = "services:\n" +
	"  app:\n    labels:\n" +
	"      traefik.http.routers.app.rule: Host(`cloud.${PORTCULLIS_DOMAIN:-portcullis.local}`)\n" +
	"      traefik.http.routers.app.middlewares: portcullis-auth@docker,portcullis-groups@docker\n" +
	"      traefik.http.routers.app-login.rule: Host(`cloud.${PORTCULLIS_DOMAIN:-portcullis.local}`) && PathPrefix(`/login`)\n" +
	"      traefik.http.routers.app-login.priority: \"5000\"\n" +
	"      traefik.http.services.app.loadbalancer.server.port: \"80\"\n" +
	"  other:\n    labels:\n" +
	"      traefik.http.routers.other.rule: Host(`other.${PORTCULLIS_DOMAIN}`)\n"

func TestPlanPublic(t *testing.T) {
	routes, err := ParseRoutes([]byte(publicCompose))
	if err != nil {
		t.Fatal(err)
	}
	m := &Manifest{Auth: Auth{Method: "forward-auth", PublicAccess: ncAccess()}}
	if err := ValidatePublicAccess(&m.Auth); err != nil {
		t.Fatal(err)
	}
	if _, err := PlanPublic(m, routes); err == nil || !strings.Contains(err.Error(), "set auth.public_access.service") {
		t.Errorf("two routed services without service: %v", err)
	}
	m.Auth.PublicAccess.Service = "app"
	plan, err := PlanPublic(m, routes)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Service != "app" || plan.TraefikService != "app" || strings.Join(plan.Subdomains, ",") != "cloud" ||
		plan.HostArgs[0] != "cloud.${PORTCULLIS_DOMAIN:-portcullis.local}" {
		t.Errorf("plan = %+v", plan)
	}
	if plan.Priority <= 5000 {
		t.Errorf("priority %d does not beat the app's routers", plan.Priority)
	}
	// Higher than any default priority (rule length) whatever the domain.
	if plan.Priority <= len(routes.Info["other"].Rule)+maxDomainLen {
		t.Errorf("priority %d below a default-priority bound", plan.Priority)
	}

	routed, published := plan.Effective(ModeAll, []string{"ignored"})
	if strings.Join(routed, ",") != "/apps/text,/index.php/s,/public.php/dav/files,/s,~/dist" || strings.Join(published, ",") != strings.Join(routed, ",") {
		t.Errorf("all: routed %v published %v", routed, published)
	}
	if r, p := plan.Effective(ModeListed, nil); r != nil || p != nil {
		t.Errorf("listed without tokens opens %v %v", r, p)
	}
	routed, published = plan.Effective(ModeListed, []string{"tokA", "tokB"})
	if strings.Join(routed, ",") != "/index.php/s/tokA,/index.php/s/tokB,/public.php/dav/files/tokA,/public.php/dav/files/tokB,/s/tokA,/s/tokB,~/dist" {
		t.Errorf("listed routed = %v", routed)
	}
	if strings.Join(published, ",") != "/index.php/s/{token},/public.php/dav/files/{token},/s/{token},~/dist" {
		t.Errorf("listed published = %v (must not leak tokens)", published)
	}
	rule := plan.Rule(routed, nil)
	hosts, err := ParseRule(rule)
	if err != nil || strings.Join(hosts, ",") != "cloud" {
		t.Errorf("rule %q: %v %v", rule, hosts, err)
	}
	if !strings.Contains(rule, "Path(`/s/tokA`) || PathPrefix(`/s/tokA/`)") {
		t.Errorf("rule lacks segment-boundary matchers: %s", rule)
	}

	// Overlap with another router's path matcher.
	m.Auth.PublicAccess.Paths = append(m.Auth.PublicAccess.Paths, pp("/login/x"))
	if _, err := PlanPublic(m, routes); err == nil || !strings.Contains(err.Error(), "app-login") {
		t.Errorf("overlap with login router: %v", err)
	}
}

func TestPlanPublicOverlapIsStringPrefix(t *testing.T) {
	routes, _ := ParseRoutes([]byte(publicCompose))
	m := &Manifest{Auth: Auth{Method: "forward-auth", PublicAccess: &PublicAccess{Service: "app", Paths: []PublicPath{pp("/logins")}}}}
	// Traefik's PathPrefix(`/login`) matches /logins: overlap.
	if _, err := PlanPublic(m, routes); err == nil {
		t.Error("/logins accepted although PathPrefix(`/login`) matches it")
	}
	m.Auth.PublicAccess.Paths = []PublicPath{pp("/log")}
	if _, err := PlanPublic(m, routes); err != nil {
		t.Errorf("/log (matches /log, /log/...) rejected: %v", err)
	}
}

func TestParseRoutesReservedNames(t *testing.T) {
	for _, c := range []string{
		"services:\n  a:\n    labels:\n      traefik.http.routers.portcullis-public-x.rule: Host(`a.${PORTCULLIS_DOMAIN}`)\n",
		"services:\n  a:\n    labels:\n      traefik.http.routers.a.rule: Host(`a.${PORTCULLIS_DOMAIN}`)\n      traefik.http.middlewares.portcullis-public-strip-a.headers.customrequestheaders.X: y\n",
		"services:\n  a:\n    labels:\n      traefik.http.routers.a.rule: Host(`a.${PORTCULLIS_DOMAIN}`)\n      traefik.http.routers.a.priority: high\n",
	} {
		if _, err := ParseRoutes([]byte(c)); err == nil {
			t.Errorf("accepted:\n%s", c)
		}
	}
}

func TestPlanPublicOpaqueMatchers(t *testing.T) {
	m := &Manifest{Auth: Auth{Method: "forward-auth", PublicAccess: &PublicAccess{Paths: []PublicPath{pp("/share")}}}}
	for _, extra := range []string{
		"PathRegexp(`^/share/.*`)",
		"!PathPrefix(`/x`)",
		"!Host(`a.${PORTCULLIS_DOMAIN}`)",
		"FutureMatcher(`x`)",
	} {
		c := "services:\n  a:\n    labels:\n" +
			"      traefik.http.routers.a.rule: Host(`a.${PORTCULLIS_DOMAIN}`)\n" +
			"      traefik.http.routers.b.rule: Host(`a.${PORTCULLIS_DOMAIN}`) && " + extra + "\n"
		routes, err := ParseRoutes([]byte(c))
		if err != nil {
			t.Fatalf("%s: %v", extra, err)
		}
		if _, err := PlanPublic(m, routes); err == nil || !strings.Contains(err.Error(), "can't tell") {
			t.Errorf("%s: public plan not refused: %v", extra, err)
		}
	}
	// Matchers that only narrow (Method, Header, Query, ClientIP) are fine.
	c := "services:\n  a:\n    labels:\n      traefik.http.routers.a.rule: Host(`a.${PORTCULLIS_DOMAIN}`) && Method(`GET`) && Header(`X`, `y`) && Query(`q`, `1`) && ClientIP(`10.0.0.0/8`)\n"
	routes, err := ParseRoutes([]byte(c))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PlanPublic(m, routes); err != nil {
		t.Errorf("narrowing matchers refused: %v", err)
	}
}

func TestIdentityHeaders(t *testing.T) {
	a := publicAuth("header-auth", pp("/share"))
	if err := ValidatePublicAccess(a); err == nil || !strings.Contains(err.Error(), "identity_headers") {
		t.Errorf("header-auth without identity_headers: %v", err)
	}
	a.IdentityHeaders = []string{"X-Forwarded-User"}
	if err := ValidatePublicAccess(a); err != nil {
		t.Error(err)
	}
	for _, hs := range [][]string{{"X_User"}, {"X User"}, {"X-A", "x-a"}, {""}, {"X:Y"}} {
		if ValidateIdentityHeaders(hs) == nil {
			t.Errorf("identity_headers %q accepted", hs)
		}
	}
}

func TestStaticRegexp(t *testing.T) {
	re := regexp.MustCompile(staticRegexp("/dist", StaticExtensions))
	for p, want := range map[string]bool{
		"/dist/a.js": true, "/dist/x/y-z.min.css": true, "/dist/core/img/a.svg": true, "/dist/f.woff2": true,
		"/dist": false, "/dist/": false, "/dist/a": false, "/dist/a.php": false, "/dist/a.php/b.js": false,
		"/dist/x.y/b.js": false, "/distx/a.js": false, "/dist/.js": false, "/dist/a.js/": false, "/dist/a.json": false,
	} {
		if got := re.MatchString(p); got != want {
			t.Errorf("static %s = %v, want %v", p, got, want)
		}
	}
}

func TestPublicExact(t *testing.T) {
	routes, _ := ParseRoutes([]byte(publicCompose))
	m := &Manifest{Auth: Auth{Method: "forward-auth", PublicAccess: &PublicAccess{Service: "app", Paths: []PublicPath{
		pp("/share"),
		{Prefix: "/core/mimeicon", Description: "d", Supporting: true, Exact: true, Justification: "public icon route"},
		{Prefix: "/core/css", Description: "d", Supporting: true},
		{Prefix: "/api/server/config", Description: "d", Exact: true, Justification: "boot config"},
	}}}}
	if err := ValidatePublicAccess(&m.Auth); err != nil {
		t.Fatal(err)
	}
	plan, err := PlanPublic(m, routes)
	if err != nil {
		t.Fatal(err)
	}
	routed, _ := plan.Effective(ModeAll, nil)
	if strings.Join(routed, ",") != "/share,=/api/server/config,=/core/mimeicon,~/core/css" {
		t.Fatalf("routed = %v", routed)
	}
	rule := plan.Rule(routed, m.Auth.PublicAccess)
	if !strings.Contains(rule, "Path(`/core/mimeicon`)") || strings.Contains(rule, "PathPrefix(`/core/mimeicon/`)") ||
		!strings.Contains(rule, "PathRegexp(`^/core/css(") {
		t.Errorf("rule = %s", rule)
	}
	if _, err := ParseRule(rule); err != nil {
		t.Errorf("rule does not parse: %v", err)
	}
	// Listed mode keeps supporting (static and exact) entries only.
	if r, _ := plan.Effective(ModeListed, []string{"x"}); strings.Join(r, ",") != "=/core/mimeicon,~/core/css" {
		t.Errorf("listed = %v", r)
	}
}

func TestPublicCredentialValidation(t *testing.T) {
	for name, a := range map[string]*Auth{
		"exact without justification": publicAuth("forward-auth", PublicPath{Prefix: "/x", Description: "d", Exact: true}),
		"exact token":                 {Method: "forward-auth", PublicAccess: &PublicAccess{TokenPattern: "^[a-z]+$", Paths: []PublicPath{{Prefix: "/s/{token}", Description: "d", Exact: true, Justification: "j"}}}},
		"php extension":               {Method: "forward-auth", PublicAccess: &PublicAccess{StaticExtensions: []string{"php"}, Paths: []PublicPath{pp("/s")}}},
		"bad extension":               {Method: "forward-auth", PublicAccess: &PublicAccess{StaticExtensions: []string{".js"}, Paths: []PublicPath{pp("/s")}}},
		"bad cookie":                  {Method: "forward-auth", PublicAccess: &PublicAccess{CredentialCookies: []string{"a b"}, Paths: []PublicPath{pp("/s")}}},
		"bad header":                  {Method: "forward-auth", PublicAccess: &PublicAccess{CredentialHeaders: []string{"x_api"}, Paths: []PublicPath{pp("/s")}}},
	} {
		if ValidatePublicAccess(a) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, p := range map[string]PublicPath{
		"exact broad unacknowledged": {Prefix: "/index.php", Description: "d", Exact: true, Justification: "j"},
		"exact api unacknowledged":   {Prefix: "/api", Description: "d", Exact: true, Justification: "j"},
		"exact broad on narrow":      {Prefix: "/x", Description: "d", Exact: true, Broad: true, Justification: "j"},
	} {
		if ValidatePublicAccess(publicAuth("forward-auth", pp("/s"), p)) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	ok := &Auth{Method: "forward-auth", PublicAccess: &PublicAccess{StaticExtensions: []string{"json", "html"}, CredentialCookies: []string{"nc_token"},
		CredentialHeaders: []string{"X-Api-Key"}, Paths: []PublicPath{pp("/s"), {Prefix: "/api", Description: "d", Exact: true, Broad: true, Justification: "single route"}}}}
	if err := ValidatePublicAccess(ok); err != nil {
		t.Errorf("valid credentials/exact rejected: %v", err)
	}
	if e := ok.PublicAccess.Extensions(); !strings.Contains(strings.Join(e, ","), "json") || !strings.Contains(strings.Join(e, ","), "woff2") {
		t.Errorf("extensions = %v", e)
	}
}

func TestCredentialExclusions(t *testing.T) {
	re := regexp.MustCompile(cookieRegexp([]string{"nc_token", "grafana_session"}))
	for c, want := range map[string]bool{
		"nc_token=x": true, "a=1; nc_token=x": true, "a=1;nc_token = x": true, "nc.token=x": true, "nc token=x": true,
		"nc[token=x": true, "nc+token=x": true, "nc%2Btoken=x": true, "nc%2btoken=x": true, "nc%20token=x": true, "NC.TOKEN=x": true,
		"Nc+ToKeN=x": true, "nc%5Ftoken=x": true, "%6Ec_token=x": true, "NC_TOKEN=x": true, "grafana_session=abc": true,
		"xnc_token=1": false, "nc_tokens=1": false, "foo=nc_token": false, "ocabc=1; nc_username=u": false,
	} {
		if got := re.MatchString(c); got != want {
			t.Errorf("cookie %q excluded = %v, want %v", c, got, want)
		}
	}
	routes, _ := ParseRoutes([]byte(publicCompose))
	pa := &PublicAccess{Service: "app", CredentialCookies: []string{"nc_token"}, CredentialQuery: []string{"apiKey"}, Paths: []PublicPath{pp("/share")}}
	m := &Manifest{Auth: Auth{Method: "forward-auth", PublicAccess: pa}}
	if err := ValidatePublicAccess(&m.Auth); err != nil {
		t.Fatal(err)
	}
	plan, _ := PlanPublic(m, routes)
	routed, _ := plan.Effective(ModeAll, nil)
	rule := plan.Rule(routed, pa)
	if !strings.Contains(rule, " && !HeaderRegexp(`Cookie`, `(?i)") || !strings.HasSuffix(rule, " && !QueryRegexp(`apiKey`, `.*`)") {
		t.Errorf("rule = %s", rule)
	}
	if got := strings.Join(queryKeyVariants("a_b.c"), "|"); strings.Count(got, "|") != 15 || !strings.Contains(got, "a b[c") || !strings.Contains(got, "a.b_c") {
		t.Errorf("query variants = %q", got)
	}
	pa.CredentialQuery = []string{"auth_token"}
	if r := plan.Rule(routed, pa); !strings.Contains(r, "!QueryRegexp(`auth token`, `.*`)") || !strings.Contains(r, "!QueryRegexp(`auth[token`, `.*`)") ||
		!strings.Contains(r, "!QueryRegexp(`auth.token`, `.*`)") || !strings.Contains(r, "!QueryRegexp(`auth_token`, `.*`)") {
		t.Errorf("rule = %s", rule)
	}
	if hosts, err := ParseRule(rule); err != nil || len(hosts) != 1 {
		t.Errorf("rule with exclusions: %v %v", hosts, err)
	}
	for _, q := range []string{"a b", "a_b_c_d_e"} {
		if ValidatePublicAccess(&Auth{Method: "forward-auth", PublicAccess: &PublicAccess{CredentialQuery: []string{q}, Paths: []PublicPath{pp("/s")}}}) == nil {
			t.Errorf("credential_query %q accepted", q)
		}
	}
}
