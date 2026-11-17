package templates

import (
	"strings"
	"testing"
)

// TestCoreServersVarsRefused (final review M4): core's multiple-servers
// settings are never template variables: a compose.yml referencing one
// and a manifest declaring one are refused; link_doc stays a core volume.
func TestCoreServersVarsRefused(t *testing.T) {
	manifest := "name: Plain\ncategory: misc\nai: {unsupported: t}\nauth: {method: forward-auth}\n"
	compose := func(v string) []byte {
		return []byte("services:\n  web:\n    image: x:1\n    environment:\n      V: " + v + "\n    labels:\n      traefik.enable: \"true\"\n" +
			"      traefik.http.routers.plain.rule: Host(`${PORTCULLIS_HOST_PLAIN:-plain.portcullis.local}`)\n" +
			"      traefik.http.routers.plain.middlewares: portcullis-auth@docker,portcullis-groups@docker\n" +
			"      traefik.http.services.plain.loadbalancer.server.port: \"8080\"\n")
	}
	if _, err := build("plain", "src", "", []byte(manifest), compose("$$PORTCULLIS_ROLE"), "example.org", nil); err != nil {
		t.Fatalf("$$ stays literal: %v", err)
	}
	for _, k := range []string{"PORTCULLIS_LINK", "PORTCULLIS_LINK_ENDPOINT", "PORTCULLIS_WORKER_TOKEN", "PORTCULLIS_ROLE", "AGENT_IMAGE", "RELAY_IMAGE"} {
		for _, ref := range []string{"${" + k + "}", "$" + k, "${" + k + ":-x}", "${" + k + ":?x}"} {
			_, err := build("plain", "src", "", []byte(manifest), compose(ref), "example.org", nil)
			if err == nil || !strings.Contains(err.Error(), "reserved for core (multiple servers)") {
				t.Errorf("compose %s: %v", ref, err)
			}
		}
		m := &Manifest{Name: "Plain", Category: "misc", Env: []EnvVar{{Key: k}}}
		if err := ValidateManifest(m); err == nil || !strings.Contains(err.Error(), "reserved for core") {
			t.Errorf("manifest env %s: %v", k, err)
		}
	}
	// N8: an environment name (set or a bare pass-through) and a key.
	for name, env := range map[string]string{
		"set":          "      AGENT_IMAGE: x\n",
		"pass-through": "    environment:\n      - RELAY_IMAGE\n",
		"list set":     "    environment:\n      - PORTCULLIS_WORKER_DATA=x\n",
	} {
		c := string(compose("x"))
		if strings.HasPrefix(env, "    environment:") {
			c = strings.Replace(c, "    environment:\n      V: x\n", env, 1)
		} else {
			c = strings.Replace(c, "      V: x\n", "      V: x\n"+env, 1)
		}
		_, err := build("plain", "src", "", []byte(manifest), []byte(c), "example.org", nil)
		if err == nil || !strings.Contains(err.Error(), "reserved for core (multiple servers)") {
			t.Errorf("environment %s: %v", name, err)
		}
	}
	keyed := string(compose("x")) + "x-notes:\n  ${AGENT_IMAGE}: \"1\"\n"
	if _, err := build("plain", "src", "", []byte(manifest), []byte(keyed), "example.org", nil); err == nil || !strings.Contains(err.Error(), "reserved for core") {
		t.Errorf("a key reference: %v", err)
	}
	for _, k := range []string{"PORTCULLIS_LINKS", "PORTCULLIS_WORKERS", "MY_AGENT_IMAGE"} {
		if CoreServersVar(k) {
			t.Errorf("%s is refused", k)
		}
	}
	if err := checkCoreRefs([]byte("services:\n  a:\n    image: x\n    volumes: [link_doc:/l]\nvolumes:\n  link_doc: {}\n"), nil); err == nil {
		t.Error("link_doc accepted")
	}
	for name, c := range map[string]string{
		"link_doc by name":  "services:\n  a:\n    image: x\n    volumes: [d:/l]\nvolumes:\n  d:\n    name: portcullis_link_doc\n",
		"link_doc external": "services:\n  a:\n    image: x\n    volumes: [d:/l]\nvolumes:\n  d:\n    name: portcullis_link_doc\n    external: true\n",
		"link-data network": "services:\n  a:\n    image: x\n    networks: [d]\nnetworks:\n  d:\n    name: portcullis-link-data\n    external: true\n",
		"link network":      "services:\n  a:\n    image: x\n    networks: [portcullis-link]\nnetworks:\n  portcullis-link: {}\n",
	} {
		if err := checkCoreRefs([]byte(c), nil); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
