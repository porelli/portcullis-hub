package templates

import (
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
		// $$ is a literal dollar; interpolation elsewhere (env) is fine.
		"services:\n  web:\n    hostname: web$$1\n    environment:\n      X: ${PORTCULLIS_DOMAIN}\n",
	}
	for _, c := range ok {
		if err := checkCoreRefs([]byte(c)); err != nil {
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
		if err := checkCoreRefs([]byte(c)); err == nil {
			t.Errorf("%s: accepted", what)
		} else if strings.Contains(err.Error(), "\n") {
			t.Errorf("%s: multi-line error %q", what, err)
		}
	}
}
