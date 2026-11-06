package templates

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseRoutes(t *testing.T) {
	r, err := ParseRoutes([]byte(sampleCompose))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.Subdomains, []string{"api", "git"}) {
		t.Errorf("subdomains = %v", r.Subdomains)
	}
	want := map[string][]string{"web": {"web", "web-api"}, "other": {"other"}}
	if !reflect.DeepEqual(r.Routers, want) {
		t.Errorf("routers = %v, want %v", r.Routers, want)
	}
}

func TestParseRoutesListLabels(t *testing.T) {
	c := "services:\n  a:\n    labels:\n      - traefik.enable=true\n      - \"traefik.http.routers.a.rule=Host(`one.${PORTCULLIS_DOMAIN}`) || Host(`two.${PORTCULLIS_DOMAIN:-x.y}`)\"\n"
	r, err := ParseRoutes([]byte(c))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.Subdomains, []string{"one", "two"}) || !reflect.DeepEqual(r.Routers["a"], []string{"a"}) {
		t.Errorf("routes = %+v", r)
	}
}

func TestParseRule(t *testing.T) {
	ok := map[string][]string{
		"Host(`a.${PORTCULLIS_DOMAIN}`)":                                                         {"a"},
		"Host(`A-1.${PORTCULLIS_DOMAIN:-portcullis.local}`)":                                     {"a-1"},
		`Host("q.${PORTCULLIS_DOMAIN-x}")`:                                                       {"q"},
		"Host(`a.${PORTCULLIS_DOMAIN}`, `b.${PORTCULLIS_DOMAIN}`)":                               {"a", "b"},
		"Host(`a.${PORTCULLIS_DOMAIN}`) && PathPrefix(`/api`)":                                   {"a"},
		"Host(`llm.${PORTCULLIS_DOMAIN}`) && (PathPrefix(`/ui`) || PathPrefix(`/sso`))":          {"llm"},
		"(Host(`a.${PORTCULLIS_DOMAIN}`) || Host(`b.${PORTCULLIS_DOMAIN}`)) && Method(`GET`)":    {"a", "b"},
		"PathPrefix(`/x`) && Host(`a.${PORTCULLIS_DOMAIN}`) && !Header(`X-A`, `1`)":              {"a"},
		"Host(`a.${PORTCULLIS_DOMAIN}`) || (Host(`b.${PORTCULLIS_DOMAIN}`) && PathPrefix(`/p`))": {"a", "b"},
		"  Host( `a.${PORTCULLIS_DOMAIN}` )  ":                                                   {"a"},
	}
	for rule, want := range ok {
		got, err := ParseRule(rule)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("ParseRule(%q) = %v, %v; want %v", rule, got, err, want)
		}
	}
	bad := []string{
		"",
		"PathPrefix(`/api`)", // any host
		"Host(`a.${PORTCULLIS_DOMAIN}`) || PathPrefix(`/x`)",         // second branch: any host
		"Host(`a.${PORTCULLIS_DOMAIN:-x}`) || Host(`y.example.com`)", // foreign domain
		"Host(`a.${PORTCULLIS_DOMAIN}`, `evil.com`)",                 // multi-arg with foreign host
		"!Host(`a.${PORTCULLIS_DOMAIN}`)",                            // negation matches every other host
		"HostRegexp(`^.+\\.example\\.org$`)",                         // regexp
		"Host(`a.${PORTCULLIS_DOMAIN}`) && HostRegexp(`.*`)",         // regexp anywhere
		"HostSNI(`*`)",
		"HostHeader(`a.${PORTCULLIS_DOMAIN}`)",
		"Host(`${SUB}.${PORTCULLIS_DOMAIN}`)", // variable label
		"Host(`a${X}.${PORTCULLIS_DOMAIN}`)",
		"Host(`a.b.${PORTCULLIS_DOMAIN}`)", // nested label
		"Host(`a.${PORTCULLIS_DOMAIN:-${OTHER}}`)",
		"Host(`a.${OTHER_DOMAIN}`)",
		"Host(`a.${PORTCULLIS_DOMAIN}.evil.com`)",
		"Host(`-a.${PORTCULLIS_DOMAIN}`)",
		"Host(``)",
		"Host()",
		"Host(`a.${PORTCULLIS_DOMAIN}`", // unbalanced
		"Host(`a.${PORTCULLIS_DOMAIN}`) &&",
		"Host(`a.${PORTCULLIS_DOMAIN}) ",
		"Host(`a.${PORTCULLIS_DOMAIN}`) garbage",
		`Host("a.${PORTCULLIS_DOMAIN}\"")`,
		"${RULE}",
	}
	for _, rule := range bad {
		if hosts, err := ParseRule(rule); err == nil {
			t.Errorf("ParseRule(%q) accepted (hosts %v)", rule, hosts)
		}
	}
}

func TestParseRoutesRejects(t *testing.T) {
	cases := map[string]string{
		"router without rule":    "services:\n  a:\n    labels:\n      traefik.enable: true\n      traefik.http.routers.a.entrypoints: websecure\n",
		"enabled without router": "services:\n  a:\n    labels:\n      traefik.enable: \"true\"\n      traefik.http.services.a.loadbalancer.server.port: 80\n",
		"tcp router":             "services:\n  a:\n    labels:\n      traefik.tcp.routers.a.rule: HostSNI(`*`)\n",
		"rule in second service": "services:\n  a:\n    labels:\n      traefik.http.routers.a.rule: Host(`a.${PORTCULLIS_DOMAIN}`)\n  b:\n    labels:\n      traefik.http.routers.b.rule: PathPrefix(`/`)\n",
		"variable rule":          "services:\n  a:\n    labels:\n      traefik.http.routers.a.rule: ${RULE}\n",
		"bad labels type":        "services:\n  a:\n    labels: 5\n",
		"invalid yaml":           "services: [\n",
	}
	for name, c := range cases {
		if _, err := ParseRoutes([]byte(c)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// No Traefik at all is fine (internal-only apps).
	if r, err := ParseRoutes([]byte("services:\n  db:\n    image: x\n")); err != nil || len(r.Subdomains) != 0 {
		t.Errorf("plain compose: %+v %v", r, err)
	}
	// UDP-only service is fine too.
	if _, err := ParseRoutes([]byte("services:\n  a:\n    labels:\n      traefik.enable: true\n      traefik.udp.routers.a.entrypoints: dns\n")); err != nil {
		t.Errorf("udp only: %v", err)
	}
}

// TestRealTemplates runs discovery against the sibling templates checkout:
// every published template must still load.
func TestRealTemplates(t *testing.T) {
	dir := os.Getenv("PORTCULLIS_TEMPLATES_DIR")
	if dir == "" {
		dir = filepath.Join("..", "..", "..", "portcullis-templates")
	}
	if _, err := os.ReadDir(dir); err != nil {
		t.Skipf("no templates checkout at %s", dir)
	}
	dir = aiPendingDir(t, dir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, e := range entries {
		if _, err := os.Stat(filepath.Join(dir, e.Name(), "manifest.yaml")); err == nil {
			want = append(want, e.Name())
		}
	}
	got := Discover(dir, "portcullis", "example.org", nil)
	var ids []string
	for _, tpl := range got {
		ids = append(ids, tpl.ID)
		if tpl.Manifest.Routerless() {
			// A router-less custom template (file sharing, contract §3)
			// routes nothing at all.
			if len(tpl.Subdomains) != 0 || len(tpl.HostRouters) != 0 {
				t.Errorf("%s: router-less but routes %v / %v", tpl.ID, tpl.Subdomains, tpl.HostRouters)
			}
			continue
		}
		if len(tpl.Subdomains) == 0 {
			t.Errorf("%s routes no subdomain", tpl.ID)
		}
		if tpl.HostForm != FormV2 || len(tpl.HostRouters) == 0 {
			t.Errorf("%s: rule form %q, host routers %v (want contract v2)", tpl.ID, tpl.HostForm, tpl.HostRouters)
		}
		if !tpl.Manifest.Multi() {
			continue
		}
		// A second instance resolves completely.
		hosts := map[string]string{}
		for r, sub := range tpl.HostRouters {
			hosts[r] = sub + "-t.example.org"
		}
		v, err := tpl.Instance(tpl.ID+"-t", hosts, "example.org")
		if err != nil {
			t.Errorf("%s: %v", tpl.ID, err)
			continue
		}
		for _, u := range v.Manifest.URLs {
			if strings.Contains(u.URL, "{{") {
				t.Errorf("%s: url %s not expanded", tpl.ID, u.URL)
			}
		}
		for _, c := range v.Manifest.Clients {
			for _, u := range append([]string{c.RedirectURI}, c.RedirectURIs...) {
				if strings.Contains(u, "{{") || (strings.HasPrefix(u, "https://") && !strings.Contains(u, "-t.example.org")) {
					t.Errorf("%s: client %s redirect %s", tpl.ID, c.ClientID, u)
				}
			}
		}
		for r := range tpl.HostRouters {
			if v.InstanceEnv[tpl.HostVars[r]] != hosts[r] {
				t.Errorf("%s: %s not in the instance env", tpl.ID, tpl.HostVars[r])
			}
		}
	}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		// Why each missing one is refused (contract v3 settings: the
		// templates need converting until they are).
		loaded := map[string]bool{}
		for _, id := range ids {
			loaded[id] = true
		}
		var why []string
		for _, id := range want {
			if !loaded[id] {
				_, err := Load(dir, id, "portcullis", "example.org", nil)
				why = append(why, fmt.Sprintf("  %s: %v", id, err))
			}
		}
		t.Errorf("loaded %d/%d templates; refused:\n%s", len(ids), len(want), strings.Join(why, "\n"))
	}
	t.Logf("%d templates loaded", len(ids))
}

func TestRuntimeHosts(t *testing.T) {
	hosts, unparsed := RuntimeHosts("Host(`A.example.org`, `b.example.org.`) || (Host(\"c.example.org\") && PathPrefix(`/x`)) || HostRegexp(`d.example.org`) || Host(`e.other.org`) || Host(`f.g.example.org`) || Host(`bad_host`) || Host() || HostSNI(`*`)")
	if strings.Join(hosts, ",") != "a.example.org,b.example.org,c.example.org,e.other.org,f.g.example.org" {
		t.Errorf("RuntimeHosts = %v", hosts)
	}
	if strings.Join(unparsed, ",") != "bad_host,Host(),HostRegexp(`d.example.org`),HostSNI(`*`)" {
		t.Errorf("unparsed = %v", unparsed)
	}
}
