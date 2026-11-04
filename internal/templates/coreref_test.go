package templates

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestCheckCoreRefs(t *testing.T) {
	ok := []string{
		"services:\n  web:\n    image: x\n    networks: [portcullis-proxy, default]\nnetworks:\n  portcullis-proxy:\n    external: true\n",
		"services:\n  web:\n    networks:\n      internal:\n        aliases: [web-int]\n      default:\n        aliases: [web-internal]\nnetworks:\n  internal: {}\n",
		"services:\n  web:\n    network_mode: host\n",
		// A template's own (project-scoped) network may reuse a core key.
		"services:\n  web:\n    networks: [monitoring]\nnetworks:\n  monitoring: {}\n",
		"services:\n  web:\n    hostname: ${PORTCULLIS_HOST_GITLAB:-git.portcullis.local}\n",
		"services:\n  web:\n    networks:\n      own:\n        ipv4_address: 10.9.0.5\nnetworks:\n  own:\n    ipam:\n      config: [{subnet: 10.9.0.0/24}]\n",
		"services:\n  web:\n    volumes_from: [db]\n  db:\n    image: x\n",
		"services:\n  web:\n    labels:\n      traefik.http.routers.a.rule: Host(`${PORTCULLIS_HOST_A:-a.portcullis.local}`)\n      traefik.http.routers.a.middlewares: portcullis-auth@docker,portcullis-groups@docker\n",
		// $$ is a literal dollar; interpolation elsewhere (env) is fine.
		"services:\n  web:\n    hostname: web$$1\n    environment:\n      X: ${PORTCULLIS_DOMAIN}\n",
	}
	for _, c := range ok {
		if err := checkCoreRefs([]byte(c), map[string]string{"gitlab": "PORTCULLIS_HOST_GITLAB"}); err != nil {
			t.Errorf("refused %q: %v", c, err)
		}
	}
	bad := map[string]string{
		"forward-auth-ext":       "services:\n  web:\n    labels:\n      traefik.http.routers.x.service: forward-auth-ext@docker\n",
		"portcullis-auth-ext":    "services:\n  web:\n    labels:\n      traefik.http.routers.x.middlewares: portcullis-auth-ext@docker\n",
		"portcullis-oauth2":      "services:\n  web:\n    labels:\n      traefik.http.routers.portcullis-oauth2-x.rule: Host(`a.b`)\n",
		"external core":          "services:\n  web:\n    networks: [portcullis-certs]\nnetworks:\n  portcullis-certs:\n    external: true\n",
		"external prefixed":      "services:\n  web:\n    networks: [n]\nnetworks:\n  n:\n    external: true\n    name: portcullis_portcullis-domains\n",
		"named core":             "services:\n  web:\n    networks: [n]\nnetworks:\n  n:\n    name: portcullis-auth\n",
		"external name (legacy)": "services:\n  web:\n    networks: [n]\nnetworks:\n  n:\n    external:\n      name: portcullis\n",
		"service named domains":  "services:\n  domains:\n    image: x\n",
		"container_name domains": "services:\n  web:\n    container_name: domains\n",
		"alias domains":          "services:\n  web:\n    networks:\n      portcullis-proxy:\n        aliases: [Domains]\nnetworks:\n  portcullis-proxy:\n    external: true\n",
		"network_mode container": "services:\n  web:\n    network_mode: container:portcullis-hub-1\n",
		"internal alias own net": "services:\n  web:\n    networks:\n      internal:\n        aliases: [web-internal]\nnetworks:\n  internal: {}\n",
		"socket proxy network":   "services:\n  web:\n    networks: [s]\nnetworks:\n  s:\n    external: true\n    name: portcullis_socket-proxy-hub\n",
	}
	for what, c := range bad {
		if err := checkCoreRefs([]byte(c), map[string]string{"gitlab": "PORTCULLIS_HOST_GITLAB"}); err == nil {
			t.Errorf("%s: accepted", what)
		} else if strings.Contains(err.Error(), "\n") {
			t.Errorf("%s: multi-line error %q", what, err)
		}
	}
}

func TestSingleDocument(t *testing.T) {
	if err := SingleDocument([]byte("services:\n  web: {}\n"), "x"); err != nil {
		t.Fatal(err)
	}
	if err := SingleDocument([]byte("---\nservices:\n  web: {}\n"), "x"); err != nil {
		t.Fatalf("a leading document marker refused: %v", err)
	}
	for _, c := range []string{"---\nservices:\n  web: {}\n---\n", "---\n---\nservices:\n  web: {}\n", "~\n---\nservices:\n  web: {}\n"} {
		if err := SingleDocument([]byte(c), "x"); err == nil {
			t.Errorf("%q: a second (empty) document accepted", c)
		}
	}
	two := "services:\n  web:\n    image: x\n---\nservices:\n  web:\n    network_mode: container:portcullis-hub-1\n"
	if err := SingleDocument([]byte(two), "x"); err == nil {
		t.Fatal("two documents accepted")
	}
	// Discover skips such a template although its first document is clean.
	dir := t.TempDir()
	writeTpl(t, dir, "multi", "name: Multi\ncategory: test\nicon: x\nauth:\n  method: public\n", two)
	writeTpl(t, dir, "multiman", "name: A\ncategory: test\nicon: x\nauth:\n  method: public\n---\nname: B\n", "services:\n  web:\n    image: x\n")
	writeTpl(t, dir, "single", "name: Single\ncategory: test\nicon: x\nauth:\n  method: custom\n", "services:\n  web:\n    image: x\n")
	loaded := map[string]bool{}
	for _, tp := range Discover(dir, "local", "example.org", nil) {
		loaded[tp.ID] = true
	}
	if !loaded["single"] || loaded["multi"] || loaded["multiman"] {
		t.Errorf("loaded %v, want only single", loaded)
	}
}

func writeTpl(t *testing.T, dir, id, manifest, compose string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, id), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, id, "manifest.yaml"), []byte(manifest), 0o644)
	os.WriteFile(filepath.Join(dir, id, "compose.yml"), []byte(compose), 0o644)
}

// TestCheckCoreRefsBypasses: interpolation, escapes, anchors and merge
// keys, list-form labels, include / extends, shapes, namespaces, fixed
// addresses and label literals.
func TestCheckCoreRefsBypasses(t *testing.T) {
	hv := map[string]string{"gitlab": "PORTCULLIS_HOST_GITLAB"}
	bad := map[string]string{
		"interpolated name":       "services:\n  web:\n    networks: [n]\nnetworks:\n  n:\n    external: true\n    name: ${X:-portcullis-certs}\n",
		"interpolated ext name":   "services:\n  web:\n    networks: [n]\nnetworks:\n  n:\n    external:\n      name: $NET\n",
		"interpolated hostname":   "services:\n  web:\n    hostname: ${H:-domains}\n",
		"interpolated container":  "services:\n  web:\n    container_name: \"$${X}${Y}\"\n",
		"interpolated alias":      "services:\n  web:\n    networks:\n      portcullis-proxy:\n        aliases: [\"${A:-domains}\"]\nnetworks:\n  portcullis-proxy:\n    external: true\n",
		"interpolated netmode":    "services:\n  web:\n    network_mode: ${MODE}\n",
		"escaped ref":             "services:\n  web:\n    labels:\n      x: \"portcullis-auth\\x2dext@docker\"\n",
		"quoted escaped network":  "services:\n  web:\n    networks: [n]\nnetworks:\n  n:\n    external: true\n    name: \"portcullis\\x2dcerts\"\n",
		"anchor alias ref":        "x-mw: &mw portcullis-auth-ext@docker\nservices:\n  web:\n    labels:\n      traefik.http.routers.a.middlewares: *mw\n",
		"merge key network":       "x-net: &net\n  external: true\n  name: portcullis-domains\nservices:\n  web:\n    networks: [n]\nnetworks:\n  n:\n    <<: *net\n",
		"list labels ref":         "services:\n  web:\n    labels:\n      - traefik.http.routers.a.service=forward-auth-ext@docker\n",
		"include":                 "include:\n  - other.yml\nservices:\n  web:\n    image: x\n",
		"extends":                 "services:\n  web:\n    extends:\n      service: base\n  base:\n    image: x\n",
		"extends file":            "services:\n  web:\n    extends:\n      file: ../x/compose.yml\n      service: hub\n",
		"hostname var + suffix":   "services:\n  web:\n    hostname: ${PORTCULLIS_HOST_GITLAB}x\n",
		"hostname other var":      "services:\n  web:\n    hostname: ${OTHER:-domains}\n",
		"hostname reserved dflt":  "services:\n  web:\n    hostname: ${PORTCULLIS_HOST_GITLAB:-domains}\n",
		"hostname reserved sub":   "services:\n  web:\n    hostname: ${PORTCULLIS_HOST_GITLAB:-domains.portcullis.local}\n",
		"hostname foreign var":    "services:\n  web:\n    hostname: ${PORTCULLIS_HOST_OTHER:-git.portcullis.local}\n",
		"hostname no default":     "services:\n  web:\n    hostname: ${PORTCULLIS_HOST_GITLAB}\n",
		"services as list":        "services:\n  - web\n",
		"service as scalar":       "services:\n  web: x\n",
		"non-string keys":         "services:\n  web:\n    networks:\n      1: {}\n",
		"networks as list":        "services:\n  web:\n    image: x\nnetworks:\n  - portcullis-certs\n",
		"network cfg as list":     "services:\n  web:\n    networks:\n      n: [a]\nnetworks:\n  n: {}\n",
		"service networks scalar": "services:\n  web:\n    networks: portcullis-certs\n",
		"external as string":      "services:\n  web:\n    networks: [n]\nnetworks:\n  n:\n    external: \"yes\"\n",
		"top-level list":          "- services\n",
		"split by variable":       "services:\n  web:\n    labels:\n      traefik.http.routers.a.middlewares: portcullis-auth${U}-ext@docker\n",
		"split by bare var":       "services:\n  web:\n    environment:\n      X: forward-auth$U-ext\n",
		"middlewares var":         "services:\n  web:\n    labels:\n      traefik.http.routers.a.middlewares: ${MW}\n",
		"router service var":      "services:\n  web:\n    labels:\n      - traefik.http.routers.a.service=${SVC}@docker\n",
		"label key var":           "services:\n  web:\n    labels:\n      traefik.http.routers.${R}.rule: Host(`a.b`)\n",
		"label key prefix var":    "services:\n  web:\n    labels:\n      ${X:-traefik}.http.routers.a.middlewares: portcullis-auth@docker\n",
		"label key inner var":     "services:\n  web:\n    labels:\n      - traef${E}ik.http.routers.a.middlewares=x\n",
		"enable var":              "services:\n  web:\n    labels:\n      traefik.enable: ${ON}\n",
		"priority var":            "services:\n  web:\n    labels:\n      traefik.http.routers.a.priority: ${P}\n",
		"port var":                "services:\n  web:\n    labels:\n      traefik.http.services.a.loadbalancer.server.port: ${PORT}\n",
		"middleware config var":   "services:\n  web:\n    labels:\n      traefik.http.middlewares.m.headers.customrequestheaders.X: ${V}\n",
		"foreign host var":        "services:\n  web:\n    labels:\n      traefik.http.middlewares.m.redirectregex.replacement: https://${PORTCULLIS_HOST_OTHER:-x.portcullis.local}/\n",
		"tls options var":         "services:\n  web:\n    labels:\n      traefik.http.routers.a.tls.options: ${T}\n",
		"volumes_from container":  "services:\n  web:\n    volumes_from: [\"container:portcullis-hub-1\"]\n",
		"volumes_from var":        "services:\n  web:\n    volumes_from: [\"${C}\"]\n",
		"pid container":           "services:\n  web:\n    pid: container:portcullis-traefik-1\n",
		"ipc container":           "services:\n  web:\n    ipc: \"container:x\"\n",
		"pid var":                 "services:\n  web:\n    pid: ${P}\n",
		"static ip on proxy":      "services:\n  web:\n    networks:\n      portcullis-proxy:\n        ipv4_address: 172.31.250.2\nnetworks:\n  portcullis-proxy:\n    external: true\n",
		"uppercase key rule":      "services:\n  web:\n    labels:\n      Traefik.http.routers.a.rule: Host(`${X:-a.b}`)\n",
		"space key rule":          "services:\n  web:\n    labels:\n      - \" traefik.http.routers.a.rule=Host(`${X:-a.b}`)\"\n",
		"mixed-case key":          "services:\n  web:\n    labels:\n      traefik.HTTP.routers.a.middlewares: x\n",
		"router attr case":        "services:\n  web:\n    labels:\n      traefik.http.routers.a.Rule: Host(`${X:-a.b}`)\n",
		"tcp rule var":            "services:\n  web:\n    labels:\n      traefik.tcp.routers.a.rule: HostSNI(`${X}`)\n",
		"static ipv6 named":       "services:\n  web:\n    networks:\n      p:\n        ipv6_address: fd00::2\nnetworks:\n  p:\n    name: portcullis-proxy\n",
	}
	for what, c := range bad {
		if err := checkCoreRefs([]byte(c), hv); err == nil {
			t.Errorf("%s: accepted", what)
		}
	}
	ok := []string{
		// The template's own host variable in a redirect (headscale).
		"services:\n  web:\n    labels:\n      traefik.http.middlewares.m.redirectregex.replacement: https://${PORTCULLIS_HOST_GITLAB:-git.portcullis.local}/admin\n      traefik.http.middlewares.m.redirectregex.regex: ^https://[^/]+/?$$\n",
		"services:\n  web:\n    labels:\n      com.example.note: ${ANY}\n",
		"services:\n  web:\n    labels:\n      traefik.http.middlewares.h.headers.customresponseheaders.X-App: grafana\n",
		"services:\n  web:\n    labels:\n      traefik.http.routers.app.middlewares: client-headers@file,portcullis-auth@docker,portcullis-groups@docker,security-headers@file\n      traefik.http.routers.app.service: app\n      traefik.http.services.app.loadbalancer.server.port: \"80\"\n",
	}
	for _, c := range ok {
		if err := checkCoreRefs([]byte(c), hv); err != nil {
			t.Errorf("refused %q: %v", c, err)
		}
	}
}

// unicodeBypasses: label keys Traefik's case-insensitive (EqualFold)
// decoder reads as routers / middlewares / TLS settings, and other key
// shapes the Hub doesn't understand.
var unicodeBypasses = map[string]string{
	"routerſ":           "traefik.http.routerſ.evil.rule: Host(`auth.example.org`)",
	"middlewareſ":       "traefik.http.routers.app.middlewareſ: security-headers@file",
	"tlſ.options":       "traefik.http.routers.app.tlſ.options: public@file",
	"ſervices":          "traefik.http.ſervices.app.loadbalancer.server.port: \"80\"",
	"tcp routerſ":       "traefik.tcp.routerſ.evil.rule: HostSNI(`*`)",
	"kelvin traefik":    "traefiK.http.routers.evil.rule: Host(`auth.example.org`)",
	"unknown kind":      "traefik.http.routerz.evil.rule: Host(`a.b`)",
	"unknown attribute": "traefik.http.routers.app.foo: bar",
	"udp rule":          "traefik.udp.routers.u.rule: x",
	"short key":         "traefik.http.routers: x",
	// Fix round 3: segments that crash Traefik's decoder, TCP/UDP, core names.
	"headers ]":         "traefik.http.middlewares.m.headers.foo]: x",
	"port ]":            "traefik.http.services.s.loadbalancer.server.port]: \"80\"",
	"router name ]":     "traefik.http.routers.x].rule: Host(`a.b`)",
	"empty segment":     "traefik.http.routers.app..service: s",
	"[ without ]":       "traefik.http.middlewares.m.headers.customrequestheaders[0: x",
	"bracket mid":       "traefik.http.services.s.loadbalancer.servers[0]x.url: http://a",
	"tcp router":        "traefik.tcp.routers.t.entrypoints: websecure",
	"tcp service":       "traefik.tcp.services.t.loadbalancer.server.port: \"22\"",
	"udp service":       "traefik.udp.services.u.loadbalancer.server.port: \"53\"",
	"core middleware":   "traefik.http.middlewares.portcullis-groups.forwardauth.address: http://evil",
	"core router":       "traefik.http.routers.keycloak.rule: Host(`auth.${PORTCULLIS_DOMAIN}`)",
	"core service":      "traefik.http.services.hub.loadbalancer.server.port: \"1\"",
	"core public guard": "traefik.http.middlewares.portcullis-public-guard.forwardauth.address: http://evil",
	// References to core objects.
	"service hub":             "traefik.http.routers.app.service: hub@docker",
	"service keycloak bare":   "traefik.http.routers.app.service: keycloak",
	"service lldap":           "traefik.http.routers.app.service: lldap@docker",
	"service api@internal":    "traefik.http.routers.app.service: api@internal",
	"middleware proxy secret": "traefik.http.routers.app.middlewares: portcullis-auth@docker,portcullis-groups@docker,hub-proxy-secret@docker",
	"middleware self bare":    "traefik.http.routers.app.middlewares: portcullis-self",
	"chain proxy secret":      "traefik.http.middlewares.c.chain.middlewares: hub-proxy-secret@docker",
	"middleware console":      "traefik.http.routers.app.middlewares: portcullis-auth-console@docker",
	// Fix round 4: service and middleware attributes (allowlisted types and
	// attributes, compared folded), references to anything not the
	// template's own.
	"service url":              "traefik.http.services.s.loadbalancer.server.url: http://socket-proxy-traefik:2375",
	"servers url":              "traefik.http.services.s.loadbalancer.servers[0].url: http://hub:8888",
	"service url case":         "traefik.http.services.s.loadBalancer.Server.URL: http://keycloak:8080",
	"service url kelvin-free":  "traefik.http.services.s.LOADBALANCER.SERVER.URL: http://keycloak:8080",
	"service transport":        "traefik.http.services.s.loadbalancer.serverstransport: t@file",
	"service weighted":         "traefik.http.services.s.weighted.services[0].name: hub@docker",
	"service mirroring":        "traefik.http.services.s.mirroring.service: hub@docker",
	"service failover":         "traefik.http.services.s.failover.service: hub@docker",
	"serverstransports kind":   "traefik.http.serverstransports.t.certificates[0].certfile: /etc/traefik/acme.json",
	"chain case":               "traefik.http.middlewares.c.Chain.Middlewares: hub-proxy-secret@docker",
	"chain upper":              "traefik.http.middlewares.c.CHAIN.MIDDLEWARES: hub-proxy-secret@docker",
	"chain indexed":            "traefik.http.middlewares.c.chain.middlewares[0]: hub-proxy-secret@docker",
	"chain other app":          "traefik.http.middlewares.c.chain.middlewares: other-app-mw@docker",
	"chain internal":           "traefik.http.middlewares.c.chain.middlewares: x@internal",
	"errors api":               "traefik.http.middlewares.e.errors.service: api@internal",
	"errors hub":               "traefik.http.middlewares.e.errors.service: hub@docker",
	"errors case":              "traefik.http.middlewares.e.Errors.Service: hub@docker",
	"forwardauth":              "traefik.http.middlewares.f.forwardauth.address: http://socket-proxy-traefik:2375/containers/json",
	"forwardauth case":         "traefik.http.middlewares.f.ForwardAuth.Address: http://hub:8888/",
	"plugin":                   "traefik.http.middlewares.p.plugin.evil.url: http://hub:8888",
	"basicauth usersfile":      "traefik.http.middlewares.b.basicauth.usersfile: /etc/traefik/acme.json",
	"ratelimit redis":          "traefik.http.middlewares.r.ratelimit.redis.endpoints: hub:8888",
	"passtlsclientcert":        "traefik.http.middlewares.p.passtlsclientcert.pem: \"true\"",
	"unknown mw attribute":     "traefik.http.middlewares.r.redirectregex.foo: x",
	"router service other app": "traefik.http.routers.app.service: other-app@docker",
	"router service file":      "traefik.http.routers.app.service: app@file",
	"router service case":      "traefik.http.routers.app.service: Hub@docker",
	"router service undefined": "traefik.http.routers.app.service: nothere",
	"router mw other app":      "traefik.http.routers.app.middlewares: portcullis-auth@docker,portcullis-groups@docker,other-app-mw@docker",
	"router mw internal":       "traefik.http.routers.app.middlewares: portcullis-auth@docker,portcullis-groups@docker,x@internal",
	// Fix round 5: no healthcheck (Traefik's own requests, from the IP
	// core's header-auth services trust), no certificate resolver or
	// domains, @file only core's five middlewares, lowercase references.
	"healthcheck path":      "traefik.http.services.s.loadbalancer.healthcheck.path: /",
	"healthcheck hostname":  "traefik.http.services.s.loadbalancer.healthcheck.hostname: hub",
	"healthcheck redirects": "traefik.http.services.s.loadbalancer.healthcheck.followredirects: \"true\"",
	"healthcheck method":    "traefik.http.services.s.loadbalancer.healthcheck.method: DELETE",
	"healthcheck headers":   "traefik.http.services.s.loadbalancer.healthcheck.headers.X-Forwarded-User: admin",
	"healthcheck case":      "traefik.http.services.s.loadBalancer.HealthCheck.Path: /",
	"tls certresolver":      "traefik.http.routers.app.tls.certresolver: letsencrypt",
	"tls domains":           "traefik.http.routers.app.tls.domains[0].main: auth.example.org",
	"tls domains sans":      "traefik.http.routers.app.tls.domains[0].sans: hub.example.org",
	"file admin mw":         "traefik.http.routers.app.middlewares: portcullis-auth@docker,portcullis-groups@docker,strict-rate-limit@file",
	"file chain other":      "traefik.http.middlewares.c.chain.middlewares: protected@file",
	"file empty base":       "traefik.http.routers.app.middlewares: portcullis-auth@docker,portcullis-groups@docker,@file",
	"file case":             "traefik.http.routers.app.middlewares: portcullis-auth@docker,portcullis-groups@docker,Security-Headers@file",
	"mw case":               "traefik.http.routers.app.middlewares: Portcullis-Auth@docker,portcullis-groups@docker",
	"mw provider case":      "traefik.http.routers.app.middlewares: portcullis-auth@Docker,portcullis-groups@docker",
}

func TestCheckCoreRefsUnicodeFolding(t *testing.T) {
	base := "services:\n  web:\n    image: x\n    labels:\n      traefik.enable: \"true\"\n      traefik.http.routers.app.rule: Host(`${PORTCULLIS_HOST_APP:-app.portcullis.local}`)\n"
	hv := map[string]string{"app": "PORTCULLIS_HOST_APP"}
	if err := checkCoreRefs([]byte(base), hv); err != nil {
		t.Fatalf("control refused: %v", err)
	}
	for what, line := range unicodeBypasses {
		if err := checkCoreRefs([]byte(base+"      "+line+"\n"), hv); err == nil {
			t.Errorf("%s: accepted", what)
		}
	}
	// Folding before the reserved-name check (values).
	if err := checkCoreRefs([]byte(base+"      traefik.http.routers.app.middlewares: portculliſ-auth-ext@docker\n"), hv); err == nil {
		t.Error("a folded reserved name was accepted")
	}
	// Compose tags.
	for _, c := range []string{
		"services:\n  web:\n    labels: !reset {}\n",
		"services:\n  web:\n    networks: !override [portcullis-proxy]\n",
		"services:\n  web: !custom\n    image: x\n",
	} {
		if err := checkCoreRefs([]byte(c), hv); err == nil {
			t.Errorf("%q: tag accepted", c)
		}
	}
	if FoldKey("traefiK.http.routerſ") != "traefik.http.routers" {
		t.Errorf("FoldKey = %q", FoldKey("traefiK.http.routerſ"))
	}
}

// TestDiscoverRefusesBypasses: end to end, Discover loads none of the
// bypass forms, each refused by the check it targets (not by a YAML
// duplicate or a missing rule); the controls load.
func TestDiscoverRefusesBypasses(t *testing.T) {
	dir := t.TempDir()
	manifest := "name: App\ncategory: test\nicon: x\nauth:\n  method: forward-auth\n"
	baseLabels := [][2]string{
		{"traefik.enable", "\"true\""},
		{"traefik.http.routers.app.rule", "Host(`app.${PORTCULLIS_DOMAIN}`)"},
		{"traefik.http.routers.app.middlewares", "portcullis-auth@docker,portcullis-groups@docker"},
	}
	// build: the control compose with label lines (a key already in the
	// base replaces it), extra service keys, extra top-level YAML and the
	// service's name.
	build := func(svcName string, lines []string, svcExtra, top string) string {
		labels := append([][2]string(nil), baseLabels...)
		for _, l := range lines {
			k, v, _ := strings.Cut(l, ": ")
			replaced := false
			for i := range labels {
				if labels[i][0] == k {
					labels[i][1], replaced = v, true
				}
			}
			if !replaced {
				labels = append(labels, [2]string{k, v})
			}
		}
		var b strings.Builder
		b.WriteString("services:\n  " + svcName + ":\n    image: x\n" + svcExtra + "    labels:\n")
		for _, l := range labels {
			b.WriteString("      " + l[0] + ": " + l[1] + "\n")
		}
		if !strings.Contains(svcExtra, "    networks:") {
			b.WriteString("    networks: [portcullis-proxy]\n")
		}
		b.WriteString("networks:\n  portcullis-proxy:\n    external: true\n" + top)
		return b.String()
	}
	compose := func(extra string) string {
		if extra == "" {
			return build("web", nil, "", "")
		}
		return build("web", []string{extra}, "", "")
	}
	// Controls: everything here is allowed and must load.
	controls := map[string]string{
		"control": compose(""),
		"control-attrs": build("dash", []string{
			"traefik.http.routers.app.service: app",
			"traefik.http.routers.app.middlewares: client-headers@file,portcullis-auth@docker,portcullis-groups@docker,c@docker,security-headers@file",
			"traefik.http.services.app.loadbalancer.server.port: \"3000\"",
			"traefik.http.services.app.loadbalancer.server.scheme: https",
			"traefik.http.services.app.loadbalancer.passhostheader: \"true\"",
			"traefik.http.services.app.loadbalancer.sticky.cookie.name: s",
			"traefik.http.middlewares.c.chain.middlewares: h,z@docker,rate-limit@file",
			"traefik.http.middlewares.h.headers.customRequestHeaders.X-App: grafana",
			"traefik.http.middlewares.z.compress: \"true\"",
			"traefik.http.middlewares.r.redirectregex.regex: ^https://[^/]+/?$$",
			"traefik.http.middlewares.r.redirectregex.replacement: https://x.example.org/",
			"traefik.http.middlewares.p.stripprefix.prefixes: /api",
			"traefik.http.middlewares.i.ipallowlist.sourcerange: 10.0.0.0/8",
			"traefik.http.middlewares.l.ratelimit.average: \"10\"",
		}, "    volumes: [data:/data]\n    networks:\n      default:\n        aliases: [grafana-internal]\n      portcullis-proxy:\n        aliases: [grafana-web]\n",
			"volumes:\n  data:\n    name: portcullis_control-attrs-data\n  cache:\n    name: portcullis_control-attrs\n  shared:\n    external: true\n    name: media-library\n"),
	}
	for id, c := range controls {
		writeTpl(t, dir, id, manifest, c)
	}
	i := 0
	ids := map[string]string{}
	for what, line := range unicodeBypasses {
		id := fmt.Sprintf("bypass%d", i)
		i++
		ids[id] = what
		writeTpl(t, dir, id, manifest, compose(line))
	}
	writeTpl(t, dir, "tagged", manifest, strings.Replace(compose(""), "    labels:\n", "    labels: !override\n", 1))
	ids["tagged"] = "!override tag"
	// Compose keys outside the allowlist.
	for id, svcLine := range map[string]string{
		"labelfile":   "    label_file: ./more-labels.env\n",
		"deploylabel": "    deploy:\n      labels:\n        traefik.http.routers.x.rule: Host(`auth.example.org`)\n",
		"annotations": "    annotations:\n      a: b\n",
		"envfile":     "    env_file: ./x.env\n",
		"build":       "    build: .\n",
	} {
		writeTpl(t, dir, id, manifest, build("web", nil, svcLine, ""))
		ids[id] = svcLine
	}
	writeTpl(t, dir, "toplevelsecrets", manifest, compose("")+"secrets:\n  s:\n    file: ./s\n")
	ids["toplevelsecrets"] = "top-level secrets"
	// Core volumes (fix round 4, I1).
	for id, top := range map[string]string{
		"vol-core-key":     "volumes:\n  postgres_data:\n    name: portcullis_postgres_data\n",
		"vol-core-unnamed": "volumes:\n  hub_data: {}\n",
		"vol-core-case":    "volumes:\n  Vault_Data: {}\n",
		"vol-ext-name":     "volumes:\n  db:\n    external: true\n    name: portcullis_postgres_data\n",
		"vol-ext-key":      "volumes:\n  portcullis_lldap_data:\n    external: true\n",
		"vol-ext-legacy":   "volumes:\n  db:\n    external:\n      name: portcullis_traefik_acme\n",
		"vol-ext-instance": "volumes:\n  db:\n    external: true\n    name: portcullis_other-data\n",
		"vol-ext-var":      "volumes:\n  db:\n    external: true\n    name: ${V}\n",
		"vol-named-other":  "volumes:\n  db:\n    name: portcullis_domains_data\n",
	} {
		writeTpl(t, dir, id, manifest, build("web", nil, "    volumes: [db:/x]\n", top))
		ids[id] = top
	}
	// The Hub's secrets volume key (file sharing, F15): never a template
	// volume key, service volume source or volumes_from entry.
	for id, c := range map[string][2]string{
		"sec-key":         {"    volumes: [db:/x]\n", "volumes:\n  db: {}\n  portcullis-hub-secrets: {}\n"},
		"sec-key-case":    {"    volumes: [db:/x]\n", "volumes:\n  db: {}\n  Portcullis-Hub-Secrets: {}\n"},
		"sec-short":       {"    volumes: [\"portcullis-hub-secrets:/x:ro\"]\n", ""},
		"sec-long":        {"    volumes:\n      - {type: volume, source: portcullis-hub-secrets, target: /x}\n", ""},
		"sec-interp":      {"    volumes: [\"${S:-portcullis-hub-secrets}:/x\"]\n", ""},
		"sec-volumesfrom": {"    volumes_from: [portcullis-hub-secrets]\n", ""},
	} {
		writeTpl(t, dir, id, manifest, build("web", nil, c[0], c[1]))
		ids[id] = c[0] + c[1]
	}
	// Volume names (fix round 5, I3): a single template names a volume
	// only portcullis_<its id>[-_…]; a multi template names none.
	for id, top := range map[string]string{
		"vol-bare":       "volumes:\n  db:\n    name: portcullis_data\n",
		"vol-other-app":  "volumes:\n  db:\n    name: portcullis_gitea-data\n",
		"vol-other-pref": "volumes:\n  db:\n    name: portcullis_vol-other-prefx\n",
		"vol-project":    "volumes:\n  db:\n    name: portcullis-gitea_gitea-data\n",
		"vol-plain":      "volumes:\n  db:\n    name: mydata\n",
		"vol-case":       "volumes:\n  db:\n    name: Portcullis_vol-case\n",
		"vol-not-string": "volumes:\n  db:\n    name: [portcullis_vol-not-string]\n",
	} {
		writeTpl(t, dir, id, manifest, build("web", nil, "    volumes: [db:/x]\n", top))
		ids[id] = top
	}
	multiManifest := "name: App\ncategory: test\nicon: x\ninstances: multi\nauth:\n  method: forward-auth\n"
	multiCompose := func(lines []string, top string) string {
		return strings.Replace(build("web", lines, "", top), "Host(`app.${PORTCULLIS_DOMAIN}`)", "Host(`${PORTCULLIS_HOST_APP:-app.portcullis.local}`)", 1)
	}
	writeTpl(t, dir, "vol-multi", multiManifest, multiCompose(nil, "volumes:\n  db:\n    name: portcullis_vol-multi\n"))
	ids["vol-multi"] = "multi template volume name"
	// Mixed-case references to the template's own objects (fix round 5,
	// I4): RenameLabels renames them per instance, so they must read the
	// same to it, the validator and Traefik.
	for id, lines := range map[string][]string{
		"ref-service-case": {"traefik.http.routers.app.service: App", "traefik.http.services.app.loadbalancer.server.port: \"80\""},
		"ref-mw-case": {"traefik.http.routers.app.middlewares: portcullis-auth@docker,portcullis-groups@docker,Hdr",
			"traefik.http.middlewares.hdr.headers.customrequestheaders.X-A: b"},
		"ref-chain-case": {"traefik.http.routers.app.middlewares: portcullis-auth@docker,portcullis-groups@docker,c",
			"traefik.http.middlewares.c.chain.middlewares: HDR@docker", "traefik.http.middlewares.hdr.compress: \"true\""},
		"ref-chain-key-case": {"traefik.http.routers.app.middlewares: portcullis-auth@docker,portcullis-groups@docker,c",
			"traefik.http.middlewares.c.Chain.middlewares: hdr", "traefik.http.middlewares.hdr.compress: \"true\""},
	} {
		writeTpl(t, dir, id, multiManifest, multiCompose(lines, ""))
		ids[id] = strings.Join(lines, "; ")
	}
	// Container names (fix round 5, M6): project portcullis-forward's
	// service auth is portcullis-forward-auth-1, core's forward-auth.
	writeTpl(t, dir, "forward", manifest, build("auth", nil, "", ""))
	ids["forward"] = "container portcullis-forward-auth-1"
	writeTpl(t, dir, "socket-proxy", manifest, build("hub-x", nil, "", ""))
	writeTpl(t, dir, "socket", manifest, strings.Replace(build("web", nil, "", ""), "services:\n", "services:\n  proxy-hub:\n    image: x\n", 1))
	ids["socket"] = "container portcullis-socket-proxy-hub-1"
	controls["socket-proxy"] = "service hub-x: no core container name"
	// Core DNS names (fix round 4, I2).
	for _, n := range []string{"hub", "keycloak", "forward-auth", "forward-auth-ext", "group-gate", "lldap", "vault", "postgres",
		"socket-proxy-traefik", "socket-proxy-hub", "traefik", "domains", "enroll", "prometheus", "alertmanager"} {
		id := "dns-svc-" + n
		writeTpl(t, dir, id, manifest, build(n, nil, "", ""))
		ids[id] = "service " + n
	}
	for id, svcExtra := range map[string]string{
		"dns-alias":          "    networks:\n      portcullis-proxy:\n        aliases: [group-gate]\n",
		"dns-alias-case":     "    networks:\n      portcullis-proxy:\n        aliases: [Keycloak]\n",
		"dns-alias-dot":      "    networks:\n      portcullis-proxy:\n        aliases: [hub.]\n",
		"dns-alias-sub":      "    networks:\n      portcullis-proxy:\n        aliases: [forward-auth.portcullis-proxy]\n",
		"dns-container":      "    container_name: lldap\n",
		"dns-container-core": "    container_name: portcullis-vault-1\n",
		"dns-hostname":       "    hostname: socket-proxy-hub\n",
	} {
		writeTpl(t, dir, id, manifest, build("web", nil, svcExtra, ""))
		ids[id] = svcExtra
	}
	// network_mode: only none, host or service:<own service>; any other
	// value joins the network of that name (core's internal one included).
	sidecar := func(id, mode string) string {
		return strings.Replace(build("web", nil, "", ""), "services:\n",
			"services:\n  side:\n    image: x\n    network_mode: "+mode+"\n", 1)
	}
	for id, mode := range map[string]string{
		"nm-core":           "portcullis",
		"nm-core-prefixed":  "portcullis_portcullis-auth",
		"nm-proxy":          "portcullis-proxy",
		"nm-named":          "media-net",
		"nm-bridge":         "bridge",
		"nm-other-default":  "portcullis-esphome_default",
		"nm-container":      "container:portcullis-hub-1",
		"nm-container-case": "Container:hub",
		"nm-container-ws":   "\" container:hub\"",
		"nm-host-case":      "Host",
		"nm-none-ws":        "\" none\"",
		"nm-service-other":  "service:hub",
		"nm-service-self":   "service:side",
		"nm-service-case":   "service:Web",
		"nm-service-prefix": "Service:web",
		"nm-empty":          "\"\"",
	} {
		writeTpl(t, dir, id, manifest, sidecar(id, mode))
		ids[id] = "network_mode " + mode
	}
	writeTpl(t, dir, "nm-with-networks", manifest, strings.Replace(build("web", nil, "", ""), "services:\n",
		"services:\n  side:\n    image: x\n    network_mode: none\n    networks:\n      portcullis-proxy:\n        aliases: [esphome-internal]\n", 1))
	ids["nm-with-networks"] = "network_mode none with networks"
	for id, mode := range map[string]string{"nm-ok-none": "none", "nm-ok-host": "host", "nm-ok-service": "service:web"} {
		writeTpl(t, dir, id, manifest, sidecar(id, mode))
		controls[id] = "network_mode " + mode
	}
	// networks.default: never named or external (it would be shared with
	// portcullis-proxy or another instance's project).
	for id, top := range map[string]string{
		"def-proxy":      "  default:\n    name: portcullis-proxy\n    external: true\n",
		"def-instance":   "  default:\n    name: portcullis-esphome_default\n",
		"def-external":   "  default:\n    external: true\n",
		"def-ext-false":  "  default:\n    external: false\n",
		"def-ext-legacy": "  default:\n    external:\n      name: portcullis-gitea_default\n",
		"def-name-null":  "  default:\n    name: null\n",
	} {
		writeTpl(t, dir, id, manifest, build("web", nil, "", top))
		ids[id] = top
	}
	// Every other top-level network is project-scoped: name / external
	// only on the portcullis-proxy placeholder.
	for id, net := range map[string]string{
		"net-other-default": "  backend:\n    name: portcullis-esphome_default\n",
		"net-ext-foreign":   "  backend:\n    external: true\n    name: media-net\n",
		"net-ext-plain":     "  backend:\n    external: true\n",
		"net-ext-legacy":    "  backend:\n    external:\n      name: portcullis-gitea_default\n",
		"net-ext-false":     "  backend:\n    external: false\n",
		"net-name-null":     "  backend:\n    name: null\n",
		"net-alias-proxy":   "  proxy:\n    external: true\n    name: portcullis-proxy\n",
		"net-proxy-case":    "  Portcullis-Proxy:\n    external: true\n",
		"net-proxy-renamed": "  portcullis-proxy2:\n    external: true\n    name: portcullis_portcullis\n",
		"net-core-key":      "  monitoring:\n    external: true\n",
	} {
		writeTpl(t, dir, id, manifest, build("web", nil, "    networks: [default, portcullis-proxy, "+strings.TrimSuffix(strings.Fields(net)[0], ":")+"]\n", net))
		ids[id] = net
	}
	// portcullis-proxy itself pointing elsewhere, or not external.
	for id, proxy := range map[string]string{
		"proxy-elsewhere":  "    external: true\n    name: portcullis-esphome_default\n",
		"proxy-name-case":  "    external: true\n    name: Portcullis-Proxy\n",
		"proxy-name-ws":    "    external: true\n    name: \" portcullis-proxy\"\n",
		"proxy-ext-legacy": "    external:\n      name: portcullis\n",
		"proxy-ext-string": "    external: \"true\"\n",
		"proxy-name-only":  "    name: portcullis-proxy\n",
		"proxy-ext-false":  "    external: false\n    name: portcullis-proxy\n",
	} {
		writeTpl(t, dir, id, manifest, strings.Replace(build("web", nil, "", ""), "  portcullis-proxy:\n    external: true\n", "  portcullis-proxy:\n"+proxy, 1))
		ids[id] = proxy
	}
	for id, c := range map[string]string{
		"net-ok-internal": build("web", nil, "    networks: [default, internal, portcullis-proxy]\n", "  internal: {}\n  monitoring:\n    driver: bridge\n"),
		"net-ok-named":    strings.Replace(build("web", nil, "", ""), "    external: true\n", "    external: true\n    name: portcullis-proxy\n", 1),
	} {
		writeTpl(t, dir, id, manifest, c)
		controls[id] = c
	}
	for id, top := range map[string]string{
		"def-ok-empty":  "  default: {}\n",
		"def-ok-driver": "  default:\n    driver: bridge\n",
	} {
		writeTpl(t, dir, id, manifest, build("web", nil, "", top))
		controls[id] = top
	}
	// Gate upstream names (-internal): on the project's default network
	// only — never as a service name, container_name, hostname or alias on
	// any other network.
	for id, svcExtra := range map[string]string{
		"int-alias-proxy":    "    networks:\n      default: {}\n      portcullis-proxy:\n        aliases: [esphome-internal]\n",
		"int-alias-case":     "    networks:\n      default: {}\n      portcullis-proxy:\n        aliases: [ESPHome-Internal]\n",
		"int-alias-dot":      "    networks:\n      default: {}\n      portcullis-proxy:\n        aliases: [\"esphome-internal.\"]\n",
		"int-alias-own-net":  "    networks:\n      default: {}\n      backend:\n        aliases: [esphome-internal]\n      portcullis-proxy: {}\n",
		"int-hostname":       "    hostname: esphome-internal\n",
		"int-container":      "    container_name: mattermost-internal\n",
		"int-hostname-multi": "    hostname: x-internal\n    networks: [default, portcullis-proxy]\n",
	} {
		top := ""
		if strings.Contains(svcExtra, "backend:") {
			top = "  backend: {}\n"
		}
		writeTpl(t, dir, id, manifest, build("web", nil, svcExtra, top))
		ids[id] = svcExtra
	}
	writeTpl(t, dir, "int-svc", manifest, build("zigbee2mqtt-internal", nil, "", ""))
	ids["int-svc"] = "service zigbee2mqtt-internal on portcullis-proxy"
	writeTpl(t, dir, "int-svc-mode", manifest, strings.Replace(build("web", nil, "", ""), "services:\n",
		"services:\n  esphome-internal:\n    image: x\n    networks: [portcullis-proxy]\n", 1))
	ids["int-svc-mode"] = "unrouted service esphome-internal on portcullis-proxy"
	// Allowed: -internal names on the default network only (aliases there,
	// a default-only service or hostname), and no DNS name at all under
	// network_mode none.
	ok := strings.Replace(build("web", nil, "", ""), "services:\n",
		"services:\n  app:\n    image: x\n    networks:\n      default:\n        aliases: [app-internal]\n"+
			"  db-internal:\n    image: x\n    hostname: db-internal\n"+
			"  quiet:\n    image: x\n    hostname: esphome-internal\n    network_mode: none\n", 1)
	writeTpl(t, dir, "int-ok", manifest, ok)
	controls["int-ok"] = "-internal names on default only"
	var logs strings.Builder
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	loaded := map[string]bool{}
	for _, tp := range Discover(dir, "local", "example.org", nil) {
		loaded[tp.ID] = true
	}
	for id := range controls {
		if !loaded[id] {
			t.Errorf("control %s didn't load:\n%s", id, logs.String())
		}
	}
	for id, what := range ids {
		if loaded[id] {
			t.Errorf("%s (%s) loaded", id, what)
		}
	}
	for _, l := range strings.Split(logs.String(), "\n") {
		if strings.Contains(l, "already defined") || strings.Contains(l, "has no rule") || strings.Contains(l, "without an HTTP router") {
			t.Errorf("refused for the wrong reason: %s", l)
		}
	}
}

// TestCoreTraefikNamesComplete: coreTraefikNames lists every router,
// middleware and service core's docker-compose.yml defines (sibling core
// checkout, all profiles' services; skipped without one).
func TestCoreTraefikNamesComplete(t *testing.T) {
	core := os.Getenv("PORTCULLIS_CORE_DIR")
	if core == "" {
		core = filepath.Join("..", "..", "..", "portcullis")
	}
	b, err := os.ReadFile(filepath.Join(core, "docker-compose.yml"))
	if err != nil {
		t.Skipf("no core checkout: %v", err)
	}
	labels, err := ServiceLabels(b)
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`^traefik\.http\.(routers|middlewares|services)\.([^.]+)\.`)
	for svc, l := range labels {
		for k := range l {
			if m := re.FindStringSubmatch(k); m != nil && !coreTraefikNames[m[1]][m[2]] {
				t.Errorf("core service %s defines %s %q, missing from coreTraefikNames", svc, m[1], m[2])
			}
		}
	}
}

// TestCoreNamesComplete: coreServices and coreVolumes list every service
// and volume key of core's docker-compose.yml, and every container_name /
// network alias / hostname core sets is a reserved DNS name (sibling core
// checkout; skipped without one).
func TestCoreNamesComplete(t *testing.T) {
	core := os.Getenv("PORTCULLIS_CORE_DIR")
	if core == "" {
		core = filepath.Join("..", "..", "..", "portcullis")
	}
	b, err := os.ReadFile(filepath.Join(core, "docker-compose.yml"))
	if err != nil {
		t.Skipf("no core checkout: %v", err)
	}
	var doc struct {
		Services map[string]struct {
			ContainerName string      `yaml:"container_name"`
			Hostname      string      `yaml:"hostname"`
			Networks      interface{} `yaml:"networks"`
		} `yaml:"services"`
		Volumes map[string]interface{} `yaml:"volumes"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Services) == 0 || len(doc.Volumes) == 0 {
		t.Fatal("core compose has no services or volumes")
	}
	for name, s := range doc.Services {
		if !coreServices[name] {
			t.Errorf("core service %s missing from coreServices", name)
		}
		if !reservedDNSName(name) {
			t.Errorf("core service %s is not a reserved DNS name", name)
		}
		if !reservedDNSName("portcullis-" + name + "-1") {
			t.Errorf("core container portcullis-%s-1 is not a reserved DNS name", name)
		}
		for _, n := range []string{s.ContainerName, s.Hostname} {
			if n != "" && !reservedDNSName(n) {
				t.Errorf("core service %s: name %s is not a reserved DNS name", name, n)
			}
		}
		if nets, ok := s.Networks.(map[string]interface{}); ok {
			for net, cfg := range nets {
				c, _ := cfg.(map[string]interface{})
				al, _ := c["aliases"].([]interface{})
				for _, a := range al {
					if as, _ := a.(string); !reservedDNSName(as) {
						t.Errorf("core service %s: alias %v on %s is not a reserved DNS name", name, a, net)
					}
				}
			}
		}
	}
	for k := range doc.Volumes {
		if !coreVolumes[k] {
			t.Errorf("core volume %s missing from coreVolumes", k)
		}
	}
}

// TestCoreFileMiddlewaresComplete: fileMiddlewares are exactly the
// middlewares of core's traefik/dynamic/middlewares.yml (sibling core
// checkout; skipped without one) — the only @file objects a template may
// reference.
func TestCoreFileMiddlewaresComplete(t *testing.T) {
	core := os.Getenv("PORTCULLIS_CORE_DIR")
	if core == "" {
		core = filepath.Join("..", "..", "..", "portcullis")
	}
	b, err := os.ReadFile(filepath.Join(core, "traefik", "dynamic", "middlewares.yml"))
	if err != nil {
		t.Skipf("no core checkout: %v", err)
	}
	var doc struct {
		HTTP struct {
			Middlewares map[string]interface{} `yaml:"middlewares"`
		} `yaml:"http"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.HTTP.Middlewares) == 0 {
		t.Fatal("core's middlewares.yml defines no middlewares")
	}
	for name := range doc.HTTP.Middlewares {
		if !fileMiddlewares[name] {
			t.Errorf("core @file middleware %s missing from fileMiddlewares", name)
		}
	}
	for name := range fileMiddlewares {
		if _, ok := doc.HTTP.Middlewares[name]; !ok {
			t.Errorf("fileMiddlewares lists %s, which core's middlewares.yml doesn't define", name)
		}
	}
}
