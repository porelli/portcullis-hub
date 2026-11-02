package templates

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const v2Rule = "Host(`${PORTCULLIS_HOST_GRAFANA:-grafana.portcullis.local}`)"

func TestParseRoutesV2(t *testing.T) {
	c := "services:\n  g:\n    labels:\n" +
		"      traefik.http.routers.grafana.rule: " + v2Rule + "\n" +
		"      traefik.http.routers.grafana-api.rule: " + v2Rule + " && PathPrefix(`/api`)\n" +
		"      traefik.http.routers.vault-ui.rule: Host(`${PORTCULLIS_HOST_VAULT_UI:-vault.portcullis.local}`)\n"
	r, err := ParseRoutes([]byte(c))
	if err != nil {
		t.Fatal(err)
	}
	if r.Form != FormV2 || strings.Join(r.Subdomains, ",") != "grafana,vault" {
		t.Errorf("routes = %+v", r)
	}
	if len(r.HostRouters) != 2 || r.HostRouters["grafana"] != "grafana" || r.HostRouters["vault-ui"] != "vault" || r.HostVars["vault-ui"] != "PORTCULLIS_HOST_VAULT_UI" {
		t.Errorf("host routers = %v %v", r.HostRouters, r.HostVars)
	}
	if !r.Info["grafana"].HostOnly || r.Info["grafana-api"].HostOnly {
		t.Error("HostOnly")
	}

	bad := map[string]string{
		"mixed forms":    "      traefik.http.routers.grafana.rule: " + v2Rule + "\n      traefik.http.routers.b.rule: Host(`b.${PORTCULLIS_DOMAIN}`)\n",
		"wrong var":      "      traefik.http.routers.dash.rule: " + v2Rule + "\n",
		"no host router": "      traefik.http.routers.grafana-api.rule: " + v2Rule + " && PathPrefix(`/api`)\n",
		"two defaults": "      traefik.http.routers.grafana.rule: " + v2Rule + "\n" +
			"      traefik.http.routers.x.rule: Host(`${PORTCULLIS_HOST_GRAFANA:-other.portcullis.local}`) && Path(`/x`)\n",
		"two vars one host": "      traefik.http.routers.grafana.rule: " + v2Rule + "\n" +
			"      traefik.http.routers.dash.rule: Host(`${PORTCULLIS_HOST_DASH:-grafana.portcullis.local}`)\n",
		"same var": "      traefik.http.routers.a-b.rule: Host(`${PORTCULLIS_HOST_A_B:-x.portcullis.local}`)\n" +
			"      traefik.http.routers.a.b.rule: Host(`${PORTCULLIS_HOST_A_B:-x.portcullis.local}`)\n",
		"underscore":           "      traefik.http.routers.my_router.rule: Host(`${PORTCULLIS_HOST_MY_ROUTER:-x.portcullis.local}`)\n",
		"no default":           "      traefik.http.routers.grafana.rule: Host(`${PORTCULLIS_HOST_GRAFANA}`)\n",
		"other default domain": "      traefik.http.routers.grafana.rule: Host(`${PORTCULLIS_HOST_GRAFANA:-grafana.example.org}`)\n",
		"svc underscore":       "      traefik.http.routers.grafana.rule: " + v2Rule + "\n      traefik.http.services.my_svc.loadbalancer.server.port: 80\n",
	}
	for name, labels := range bad {
		if _, err := ParseRoutes([]byte("services:\n  g:\n    labels:\n" + labels)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRenameLabels(t *testing.T) {
	in := map[string]string{
		"traefik.enable":                                       "true",
		"traefik.http.routers.app.rule":                        v2Rule,
		"traefik.http.routers.app.service":                     "app",
		"traefik.http.routers.app.middlewares":                 "portcullis-auth@docker, app-hdr@docker,security-headers@file,app-hdr",
		"traefik.http.routers.app-x.service":                   "api@internal",
		"traefik.http.middlewares.app-hdr.headers.x":           "y",
		"traefik.http.middlewares.app-chain.chain.middlewares": "app-hdr@docker",
		"traefik.http.services.app.loadbalancer.server.port":   "80",
		"traefik.udp.routers.dns.entrypoints":                  "dns",
		"traefik.http.routers.portcullis-public-x.service":     "app",
		"com.example.other":                                    "app",
	}
	names := map[string]bool{"app": true, "app-x": true, "app-hdr": true, "app-chain": true, "dns": true}
	got := RenameLabels(in, names, "i1")
	want := map[string]string{
		"traefik.enable":                                          "true",
		"traefik.http.routers.i1_app.rule":                        v2Rule,
		"traefik.http.routers.i1_app.service":                     "i1_app",
		"traefik.http.routers.i1_app.middlewares":                 "portcullis-auth@docker,i1_app-hdr@docker,security-headers@file,i1_app-hdr",
		"traefik.http.routers.i1_app-x.service":                   "api@internal",
		"traefik.http.middlewares.i1_app-hdr.headers.x":           "y",
		"traefik.http.middlewares.i1_app-chain.chain.middlewares": "i1_app-hdr@docker",
		"traefik.http.services.i1_app.loadbalancer.server.port":   "80",
		"traefik.udp.routers.i1_dns.entrypoints":                  "dns",
		"traefik.http.routers.portcullis-public-x.service":        "i1_app",
		"com.example.other":                                       "app",
	}
	if len(got) != len(want) {
		t.Errorf("got %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

func TestInstanceView(t *testing.T) {
	dir := t.TempDir()
	write := func(p, s string) {
		os.MkdirAll(filepath.Dir(p), 0755)
		os.WriteFile(p, []byte(s), 0644)
	}
	write(filepath.Join(dir, "hs", "manifest.yaml"), `name: HS
instances: multi
auth:
  method: native-oidc
  group_access: true
  access_group: users_hs
  admin_group: admin_hs
urls:
  - {label: a, url: "https://{{HOST_HEADSCALE}}/x"}
  - {label: b, url: "https://{{HOST_HEADPLANE}}/admin and https://auth.{{DOMAIN}}"}
keycloak_clients:
  - {client_id: headscale, redirect_uri: "https://{{HOST_HEADSCALE}}/oidc/callback"}
  - {client_id: headplane, redirect_uris: ["https://{{HOST_HEADPLANE}}/admin/oidc/callback"]}
`)
	write(filepath.Join(dir, "hs", "compose.yml"), "services:\n  hs:\n    labels:\n"+
		"      traefik.http.routers.headscale.rule: Host(`${PORTCULLIS_HOST_HEADSCALE:-vpn.portcullis.local}`)\n"+
		"      traefik.http.routers.headplane.rule: Host(`${PORTCULLIS_HOST_HEADPLANE:-vpn-admin.portcullis.local}`)\n"+
		"    volumes: [hs-data:/d, ext:/e]\nvolumes:\n  hs-data: {}\n  ext:\n    external: true\n")
	ts := Discover(dir, "s", "example.org")
	if len(ts) != 1 {
		t.Fatalf("discovered %d", len(ts))
	}
	cat := ts[0]
	if cat.Manifest.URLs[0].URL != "https://vpn.example.org/x" || cat.Hosts["headplane"] != "vpn-admin.example.org" || strings.Join(cat.Volumes, ",") != "hs-data" {
		t.Errorf("catalog = %+v", cat)
	}
	v, err := cat.Instance("hs-b", map[string]string{"headscale": "vpn-b.example.org", "headplane": "vpn-admin-b.example.org"}, "example.org")
	if err != nil {
		t.Fatal(err)
	}
	if v.ID != "hs-b" || v.TemplateID != "hs" || v.IsDefault() || strings.Join(v.Subdomains, ",") != "vpn-admin-b,vpn-b" {
		t.Errorf("view = %+v", v)
	}
	m := v.Manifest
	if m.URLs[0].URL != "https://vpn-b.example.org/x" || m.URLs[1].URL != "https://vpn-admin-b.example.org/admin and https://auth.example.org" {
		t.Errorf("urls = %+v", m.URLs)
	}
	if m.Clients[0].ClientID != "hs-b" || m.Clients[0].RedirectURI != "https://vpn-b.example.org/oidc/callback" ||
		m.Clients[1].ClientID != "hs-b-headplane" || m.Clients[1].RedirectURIs[0] != "https://vpn-admin-b.example.org/admin/oidc/callback" {
		t.Errorf("clients = %+v", m.Clients)
	}
	if m.Auth.AccessGroup != "users_hs-b" || m.Auth.AdminGroup != "admin_hs-b" {
		t.Errorf("groups = %+v", m.Auth)
	}
	want := map[string]string{
		"PORTCULLIS_INSTANCE": "hs-b", "PORTCULLIS_HOST_HEADSCALE": "vpn-b.example.org", "PORTCULLIS_HOST_HEADPLANE": "vpn-admin-b.example.org",
		"PORTCULLIS_OIDC_CLIENT_ID": "hs-b", "PORTCULLIS_OIDC_CLIENT_ID_HEADSCALE": "hs-b", "PORTCULLIS_OIDC_CLIENT_ID_HEADPLANE": "hs-b-headplane",
		"PORTCULLIS_ACCESS_GROUP": "users_hs-b", "PORTCULLIS_ADMIN_GROUP": "admin_hs-b",
	}
	if len(v.InstanceEnv) != len(want) {
		t.Errorf("env = %v", v.InstanceEnv)
	}
	for k, val := range want {
		if v.InstanceEnv[k] != val {
			t.Errorf("%s = %q, want %q", k, v.InstanceEnv[k], val)
		}
	}
	n := cat.NamesFor("hs-b")
	if n.Project != "portcullis-hs-b" || n.Volumes["hs-data"] != "portcullis_hs-b-hs-data" || len(n.Volumes) != 1 {
		t.Errorf("names = %+v", n)
	}
	if d := cat.NamesFor("hs"); d.Volumes["hs-data"] != "portcullis_hs-data" || strings.Join(d.Clients, ",") != "headscale,headplane" || d.AccessGroup != "users_hs" {
		t.Errorf("default names = %+v", d)
	}
	// The catalog entry is unchanged by resolving an instance.
	if cat.Manifest.Clients[0].ClientID != "headscale" || cat.InstanceEnv["PORTCULLIS_INSTANCE"] != "hs" {
		t.Errorf("catalog mutated: %+v", cat.Manifest.Clients)
	}
	for _, bad := range []map[string]string{
		{"headscale": "vpn-b.example.org"},                                                 // missing headplane
		{"headscale": "vpn-b.other.org", "headplane": "x.example.org"},                     // other domain
		{"headscale": "a.b.example.org", "headplane": "x.example.org"},                     // two labels
		{"headscale": "a.example.org", "headplane": "x.example.org", "z": "z.example.org"}, // unknown router
	} {
		if _, err := cat.Instance("hs-c", bad, "example.org"); err == nil {
			t.Errorf("%v: accepted", bad)
		}
	}
}

func TestDiscoverInstanceRules(t *testing.T) {
	cases := map[string][2]string{
		"multi legacy rule": {"name: X\ninstances: multi\nauth:\n  method: forward-auth\n",
			"services:\n  s:\n    labels:\n      traefik.http.routers.x.rule: Host(`x.${PORTCULLIS_DOMAIN}`)\n"},
		"multi volume name": {"name: X\ninstances: multi\nauth:\n  method: forward-auth\n",
			"services:\n  s:\n    image: x\nvolumes:\n  d:\n    name: portcullis_d\n"},
		"single other volume name": {"name: X\ninstances: single\nauth:\n  method: forward-auth\n",
			"services:\n  s:\n    image: x\nvolumes:\n  d:\n    name: mydata\n"},
		"multi portcullis- name": {"name: X\ninstances: multi\nauth:\n  method: forward-auth\n",
			"services:\n  s:\n    labels:\n      traefik.http.routers.x.rule: Host(`${PORTCULLIS_HOST_X:-x.portcullis.local}`)\n      traefik.http.middlewares.portcullis-mine.headers.x: y\n"},
		"unknown placeholder": {"name: X\nauth:\n  method: forward-auth\nurls:\n  - {label: a, url: \"https://{{HOST_Y}}\"}\n",
			"services:\n  s:\n    labels:\n      traefik.http.routers.x.rule: Host(`${PORTCULLIS_HOST_X:-x.portcullis.local}`)\n"},
		"bad instances":    {"name: X\ninstances: many\nauth:\n  method: forward-auth\n", "services:\n  s:\n    image: x\n"},
		"reserved env":     {"name: X\nauth:\n  method: forward-auth\nenv:\n  - key: PORTCULLIS_HOST_X\n", "services:\n  s:\n    image: x\n"},
		"reserved setting": {"name: X\nauth:\n  method: forward-auth\nsettings:\n  - key: PORTCULLIS_INSTANCE\n", "services:\n  s:\n    image: x\n"},
		"reserved port":    {"name: X\nauth:\n  method: forward-auth\nports:\n  - key: PORTCULLIS_OIDC_CLIENT_ID_A\n", "services:\n  s:\n    image: x\n"},
		"client key clash": {"name: X\nauth:\n  method: native-oidc\n  group_access: true\nkeycloak_clients:\n  - client_id: a-b\n  - client_id: a.b\n", "services:\n  s:\n    image: x\n"},
	}
	for name, c := range cases {
		dir := t.TempDir()
		os.MkdirAll(filepath.Join(dir, "x"), 0755)
		os.WriteFile(filepath.Join(dir, "x", "manifest.yaml"), []byte(c[0]), 0644)
		os.WriteFile(filepath.Join(dir, "x", "compose.yml"), []byte(c[1]), 0644)
		if got := Discover(dir, "s", "example.org"); len(got) != 0 {
			t.Errorf("%s: loaded", name)
		}
	}
}
