package templates

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckCoreRefs(t *testing.T) {
	ok := []string{
		"services:\n  web:\n    image: x\n    networks: [portcullis-proxy, default]\nnetworks:\n  portcullis-proxy:\n    external: true\n",
		"services:\n  web:\n    networks:\n      internal:\n        aliases: [web-internal]\nnetworks:\n  internal: {}\n",
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
	writeTpl(t, dir, "single", "name: Single\ncategory: test\nicon: x\nauth:\n  method: public\n", "services:\n  web:\n    image: x\n")
	loaded := map[string]bool{}
	for _, tp := range Discover(dir, "local", "example.org") {
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
// bypass forms (control template loads).
func TestDiscoverRefusesBypasses(t *testing.T) {
	dir := t.TempDir()
	manifest := "name: App\ncategory: test\nicon: x\nauth:\n  method: forward-auth\n"
	compose := func(extra string) string {
		return "services:\n  web:\n    image: x\n    networks: [portcullis-proxy]\n    labels:\n      traefik.enable: \"true\"\n" +
			"      traefik.http.routers.app.rule: Host(`app.${PORTCULLIS_DOMAIN}`)\n" +
			"      traefik.http.routers.app.middlewares: portcullis-auth@docker,portcullis-groups@docker\n" + extra +
			"networks:\n  portcullis-proxy:\n    external: true\n"
	}
	writeTpl(t, dir, "control", manifest, compose(""))
	i := 0
	ids := map[string]string{}
	for what, line := range unicodeBypasses {
		id := fmt.Sprintf("bypass%d", i)
		i++
		ids[id] = what
		writeTpl(t, dir, id, manifest, compose("      "+line+"\n"))
	}
	writeTpl(t, dir, "tagged", manifest, strings.Replace(compose(""), "    labels:\n", "    labels: !override\n", 1))
	ids["tagged"] = "!override tag"
	loaded := map[string]bool{}
	for _, tp := range Discover(dir, "local", "example.org") {
		loaded[tp.ID] = true
	}
	if !loaded["control"] {
		t.Fatal("the control template didn't load")
	}
	for id, what := range ids {
		if loaded[id] {
			t.Errorf("%s (%s) loaded", id, what)
		}
	}
}
