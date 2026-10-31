package templates

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

const sampleCompose = `services:
  web:
    image: x
    labels:
      traefik.http.routers.web.rule: Host(` + "`Git.${PORTCULLIS_DOMAIN:-portcullis.local}`" + `)
      traefik.http.routers.web.entrypoints: websecure
      traefik.http.routers.web-api.rule: Host(` + "`api.${PORTCULLIS_DOMAIN}`" + `) && PathPrefix(` + "`/api`" + `)
    environment:
      A: ${FOO}
      B: ${BAR:-default}
  db:
    image: postgres
  other:
    labels:
      traefik.http.routers.other.rule: Host(` + "`git.${PORTCULLIS_DOMAIN}`" + `)
volumes:
  data:
    name: portcullis_data
`

func TestSubdomains(t *testing.T) {
	got := Subdomains([]byte(sampleCompose))
	want := []string{"api", "git"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Subdomains = %v, want %v", got, want)
	}
	if Subdomains([]byte("Host(`x.example.com`)")) != nil {
		t.Error("hard-coded domains must not be picked up")
	}
}

func TestServices(t *testing.T) {
	if got := Services([]byte(sampleCompose)); !reflect.DeepEqual(got, []string{"db", "other", "web"}) {
		t.Errorf("Services = %v", got)
	}
	if got := Services([]byte("::not yaml")); got != nil {
		t.Errorf("Services(invalid) = %v", got)
	}
}

func TestRoutersByService(t *testing.T) {
	got := RoutersByService([]byte(sampleCompose))
	want := map[string][]string{"web": {"web", "web-api"}, "other": {"other"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("RoutersByService = %v, want %v", got, want)
	}
}

func TestEnvRefs(t *testing.T) {
	got := EnvRefs(sampleCompose)
	for _, k := range []string{"FOO", "BAR", "PORTCULLIS_DOMAIN"} {
		if !got[k] {
			t.Errorf("missing ref %s in %v", k, got)
		}
	}
	if len(EnvRefs("${UNTERMINATED")) != 0 {
		t.Error("unterminated reference must be ignored")
	}
}

func writeTemplate(t *testing.T, dir, id, manifest string) {
	t.Helper()
	p := filepath.Join(dir, id)
	if err := os.MkdirAll(p, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p, "manifest.yaml"), []byte(manifest), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p, "compose.yml"), []byte(sampleCompose), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestDiscover(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "good", "name: Good\ncategory: b\nurls:\n  - label: x\n    url: https://good.{{DOMAIN}}\nauth:\n  admin_group: admin_good\n  admin_paths: [/admin/]\n")
	writeTemplate(t, dir, "alpha", "name: Alpha\ncategory: a\n")
	writeTemplate(t, dir, "Bad_ID", "name: Bad\n")
	writeTemplate(t, dir, "badkey", "name: X\nsettings:\n  - key: 'A=B'\n")
	writeTemplate(t, dir, "badyaml", "name: [unclosed\n")
	writeTemplate(t, dir, "badpath", "name: X\nauth:\n  admin_group: g\n  admin_paths: [/../etc]\n")
	os.MkdirAll(filepath.Join(dir, "nomanifest"), 0755)
	os.WriteFile(filepath.Join(dir, "file.txt"), nil, 0644)

	ts := Discover(dir, "src", "example.org")
	Sort(ts)
	if len(ts) != 2 || ts[0].ID != "alpha" || ts[1].ID != "good" {
		t.Fatalf("Discover = %+v", ts)
	}
	g := ts[1]
	if g.Source != "src" || g.Path != filepath.Join(dir, "good") {
		t.Errorf("bad source/path: %+v", g)
	}
	if g.Manifest.URLs[0].URL != "https://good.example.org" {
		t.Errorf("DOMAIN not substituted: %s", g.Manifest.URLs[0].URL)
	}
	if g.Manifest.Auth.AdminPaths[0] != "/admin" {
		t.Errorf("admin path not normalised: %v", g.Manifest.Auth.AdminPaths)
	}
	if Discover(filepath.Join(dir, "missing"), "x", "d") != nil {
		t.Error("missing dir should yield nil")
	}
}
