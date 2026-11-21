package httpapi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The catalog fields and assets (contract §3 "Catalog fields", §11.7
// "Catalog views" and "Catalog assets", ux3).

const catalogManifest = `name: Demo
description: A demo
icon: "🧪"
category: home-automation
ai: {unsupported: "test fixture"}
links:
  website: https://demo.example/
  source: https://git.example/demo
long_description: |
  Demo is *small*. See [docs](https://docs.example).
logo: logo.svg
screenshots:
  - {file: one.png, caption: The start page}
auth:
  method: custom
`

const catalogCompose = "services:\n  app:\n    image: x\n"

const catalogLogo = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><!-- as written --><path d="M0 0h24v24H0z" fill="#336699"/></svg>`

var catalogPNG = []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR-demo")

// newCatalogEnv: the instEnv with template demo (a logo and one
// screenshot) and nologo (neither).
func newCatalogEnv(t *testing.T) (*instEnv, string) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "src", "demo")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "logo.svg"), []byte(catalogLogo), 0o644)
	os.WriteFile(filepath.Join(dir, "one.png"), catalogPNG, 0o644)
	plain := strings.NewReplacer("logo: logo.svg\n", "", "screenshots:\n  - {file: one.png, caption: The start page}\n", "", "name: Demo", "name: Plain").Replace(catalogManifest)
	e := newInstEnvWith(t, root, map[string][2]string{"demo": {catalogManifest, catalogCompose}, "nologo": {plain, catalogCompose}}, nil)
	return e, dir
}

func TestTemplatesJSONFields(t *testing.T) {
	e, _ := newCatalogEnv(t)
	code, body := e.do(t, "root", "GET", "/api/templates", "")
	if code != 200 {
		t.Fatalf("GET /api/templates = %d %s", code, body)
	}
	var ts []map[string]any
	if err := json.Unmarshal([]byte(body), &ts); err != nil {
		t.Fatal(err)
	}
	var demo, plain map[string]any
	for _, x := range ts {
		switch x["id"] {
		case "demo":
			demo = x
		case "nologo":
			plain = x
		}
	}
	if demo == nil || plain == nil {
		t.Fatalf("demo / nologo missing: %s", body)
	}
	if demo["category_label"] != "Home automation" || demo["category_rank"] != float64(7) || demo["routerless"] != true {
		t.Errorf("demo category / routerless = %v %v %v", demo["category_label"], demo["category_rank"], demo["routerless"])
	}
	if demo["logo_url"] != "/api/catalog/demo/logo.svg" {
		t.Errorf("logo_url = %v", demo["logo_url"])
	}
	if u, _ := demo["screenshot_urls"].([]any); len(u) != 1 || u[0] != "/api/catalog/demo/screenshots/0" {
		t.Errorf("screenshot_urls = %v", demo["screenshot_urls"])
	}
	m, _ := demo["manifest"].(map[string]any)
	if l, _ := m["links"].(map[string]any); l["website"] != "https://demo.example/" || l["source"] != "https://git.example/demo" {
		t.Errorf("manifest.links = %v", m["links"])
	}
	if h, _ := m["long_description_html"].(string); !strings.Contains(h, "<em>small</em>") || !strings.Contains(h, `rel="noopener noreferrer nofollow"`) {
		t.Errorf("long_description_html = %q", h)
	}
	if _, ok := plain["logo_url"]; ok {
		t.Errorf("nologo has a logo_url: %v", plain["logo_url"])
	}
	// Never the bytes.
	if strings.Contains(body, "336699") || strings.Contains(body, "IHDR") || strings.Contains(body, "<svg") {
		t.Errorf("the catalog carries asset bytes: %s", body)
	}
}

func TestCatalogLogoHeaders(t *testing.T) {
	e, dir := newCatalogEnv(t)
	r, body := doAs(t, e.hub, "root", "GET", "/api/catalog/demo/logo.svg", "")
	if r.StatusCode != 200 || body != catalogLogo {
		t.Fatalf("logo = %d %q", r.StatusCode, body)
	}
	for k, v := range map[string]string{
		"Content-Type":                 "image/svg+xml",
		"X-Content-Type-Options":       "nosniff",
		"Content-Security-Policy":      "default-src 'none'; style-src 'unsafe-inline'; sandbox",
		"Cross-Origin-Resource-Policy": "same-origin",
		"Content-Disposition":          `inline; filename="demo-logo.svg"`,
		"Cache-Control":                "no-cache",
	} {
		if got := r.Header.Values(k); len(got) != 1 || got[0] != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	// Served from memory: the file changing on disk changes nothing.
	os.WriteFile(filepath.Join(dir, "logo.svg"), []byte("<svg><script>alert(1)</script></svg>"), 0o644)
	if _, body := doAs(t, e.hub, "root", "GET", "/api/catalog/demo/logo.svg", ""); body != catalogLogo {
		t.Errorf("logo after the file changed = %q", body)
	}
	for _, p := range []string{"/api/catalog/nope/logo.svg", "/api/catalog/nologo/logo.svg", "/api/catalog/demo/logo.svg/x",
		"/api/catalog/demo/logo.SVG", "/api/catalog/demo/", "/api/catalog/demo"} {
		if r, b := doAs(t, e.hub, "root", "GET", p, ""); r.StatusCode != 404 {
			t.Errorf("GET %s = %d %q, want 404", p, r.StatusCode, b)
		}
	}
	// Hub listener only.
	for _, p := range []string{"/api/catalog/demo/logo.svg", "/api/catalog/demo/screenshots/0"} {
		if r, _ := doAs(t, e.ppl, "root", "GET", p, ""); r.StatusCode != 404 {
			t.Errorf("people listener GET %s = %d, want 404", p, r.StatusCode)
		}
	}
	// GET only.
	if r, _ := doAs(t, e.hub, "root", "POST", "/api/catalog/demo/logo.svg", "{}"); r.StatusCode != 405 && r.StatusCode != 404 {
		t.Errorf("POST logo = %d", r.StatusCode)
	}
}

func TestCatalogScreenshot(t *testing.T) {
	e, _ := newCatalogEnv(t)
	r, body := doAs(t, e.hub, "root", "GET", "/api/catalog/demo/screenshots/0", "")
	if r.StatusCode != 200 || body != string(catalogPNG) {
		t.Fatalf("screenshot 0 = %d %q", r.StatusCode, body)
	}
	for k, v := range map[string]string{
		"Content-Type":                 "image/png",
		"X-Content-Type-Options":       "nosniff",
		"Content-Security-Policy":      "default-src 'none'; style-src 'unsafe-inline'; sandbox",
		"Cross-Origin-Resource-Policy": "same-origin",
		"Content-Disposition":          `inline; filename="demo-0.png"`,
		"Cache-Control":                "no-cache",
	} {
		if got := r.Header.Values(k); len(got) != 1 || got[0] != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	for _, p := range []string{"/api/catalog/demo/screenshots/1", "/api/catalog/demo/screenshots/-1", "/api/catalog/demo/screenshots/abc",
		"/api/catalog/demo/screenshots/+0", "/api/catalog/demo/screenshots/0x0", "/api/catalog/demo/screenshots/99999999999999999999",
		"/api/catalog/demo/screenshots/0/x", "/api/catalog/demo/screenshots/", "/api/catalog/nologo/screenshots/0", "/api/catalog/nope/screenshots/0"} {
		if r, b := doAs(t, e.hub, "root", "GET", p, ""); r.StatusCode != 404 {
			t.Errorf("GET %s = %d %q, want 404", p, r.StatusCode, b)
		}
	}
}

// The MCP template tools carry the same catalog fields (contract §11.7).
func TestCatalogMCPTools(t *testing.T) {
	plain := strings.NewReplacer("logo: logo.svg\n", "", "screenshots:\n  - {file: one.png, caption: The start page}\n", "").Replace(catalogManifest)
	e := newToolEnv(t, map[string][2]string{"demo": {plain, catalogCompose}}, nil)
	txt, isErr, _ := e.tool(t, "list_templates", nil)
	if isErr || !strings.Contains(txt, `"category_label":"Home automation","category_rank":7`) || !strings.Contains(txt, `"routerless":true`) {
		t.Errorf("list_templates = %s", txt)
	}
	txt, isErr, _ = e.tool(t, "get_template", map[string]any{"id": "demo"})
	for _, k := range []string{`"category_label":"Home automation"`, `"category_rank":7`, `"routerless":true`, `"long_description_html":"<p>Demo is`,
		`"links":{"source":"https://git.example/demo","website":"https://demo.example/"}`} {
		if isErr || !strings.Contains(txt, k) {
			t.Errorf("get_template lacks %s: %s", k, txt)
		}
	}
}
