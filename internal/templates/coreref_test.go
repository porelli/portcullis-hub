package templates

import (
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
	if err := SingleDocument([]byte("---\nservices:\n  web: {}\n---\n"), "x"); err != nil {
		t.Fatalf("empty trailing document refused: %v", err)
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
