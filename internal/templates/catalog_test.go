package templates

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The catalog fields (contract §3 "Catalog fields", ux3).

const catHead = `name: Demo
description: A demo
icon: "🧪"
category: home-automation
ai: {unsupported: "test fixture"}
links:
  website: https://demo.example/
  source: https://git.example/demo
auth:
  method: custom
`

const catCompose = "services:\n  app:\n    image: x\n"

const catLogo = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><!-- kept as written --><path d="M0 0h24v24H0z" fill="#336699"/></svg>`

var (
	pngMagic  = []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR")
	jpegMagic = []byte("\xff\xd8\xff\xe0\x00\x10JFIF\x00")
	webpMagic = []byte("RIFF\x10\x00\x00\x00WEBPVP8 ")
)

// buildDir builds template demo from manifest in dir, with files written
// there first (name → content).
func buildDir(t *testing.T, manifest string, files map[string][]byte) (Template, error) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "demo")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return build("demo", "src", dir, []byte(manifest), []byte(catCompose), "example.org", nil)
}

func wantErr(t *testing.T, name string, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("%s: err = %v, want %q", name, err, want)
	}
}

func TestCategoryOf(t *testing.T) {
	for _, c := range []struct {
		slug, label string
		rank        int
	}{
		{"productivity", "Productivity", 1},
		{"storage", "Files & storage", 4},
		{"home-automation", "Home automation", 7},
		{"devops", "Developer tools", 10},
		{"public", "Public sites", 16},
		{"weird-thing", "Weird thing", 1000},
		{"chat", "Chat", 1000},
	} {
		if l, r := CategoryOf(c.slug); l != c.label || r != c.rank {
			t.Errorf("CategoryOf(%q) = %q, %d; want %q, %d", c.slug, l, r, c.label, c.rank)
		}
	}
	if len(Categories) != 16 {
		t.Errorf("%d categories, want 16", len(Categories))
	}
}

// long_description: the auth.notes pipeline and limits. The Hub drops raw
// HTML (contract §3: the templates validator refuses it; the Hub's
// pipeline, as for the notes, never passes it through).
func TestBuildLongDescription(t *testing.T) {
	m := catHead + "long_description: |\n  Demo is *small*. See [docs](https://docs.example).\n\n  <script>alert(1)</script>\n"
	tm, err := buildDir(t, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := tm.Manifest.LongDescriptionHTML
	if !strings.Contains(h, "<p>Demo is <em>small</em>.") || !strings.Contains(h, `rel="noopener noreferrer nofollow"`) {
		t.Errorf("long_description_html = %q", h)
	}
	if strings.Contains(h, "<script") || strings.Contains(h, "alert") {
		t.Errorf("raw HTML passed through: %q", h)
	}
	for name, c := range map[string]struct{ ld, want string }{
		"too big":     {strings.Repeat("a", 16<<10+1), "long_description is 16385 bytes"},
		"too deep":    {strings.Repeat("> ", 17) + "x", "long_description nests blocks deeper than 16"},
		"zero width":  {"a\u200bb", "long_description has the hidden character U+200B"},
		"invalid utf": {"a\xffb", "long_description is not valid UTF-8"},
	} {
		mm := &Manifest{Auth: Auth{Method: "custom"}, LongDescription: c.ld}
		wantErr(t, name, ValidateManifest(mm), c.want)
	}
	// long_description_html is never read from the manifest.
	tm, err = buildDir(t, catHead+"long_description_html: \"<script>x</script>\"\n", nil)
	if err != nil || tm.Manifest.LongDescriptionHTML != "" {
		t.Errorf("long_description_html from YAML: %q %v", tm.Manifest.LongDescriptionHTML, err)
	}
}

func TestBuildLogo(t *testing.T) {
	tm, err := buildDir(t, catHead+"logo: logo.svg\n", map[string][]byte{"logo.svg": []byte(catLogo)})
	if err != nil {
		t.Fatal(err)
	}
	if tm.LogoURL != "/api/catalog/demo/logo.svg" {
		t.Errorf("logo_url = %q", tm.LogoURL)
	}
	if !bytes.Equal(tm.LogoSVG(), []byte(catLogo)) {
		t.Errorf("LogoSVG = %q, want the file's bytes as read", tm.LogoSVG())
	}
	// Every view of the template carries it.
	in, err := tm.Instance("demo-2", nil, "example.org")
	if err != nil || !bytes.Equal(in.LogoSVG(), []byte(catLogo)) {
		t.Errorf("instance view logo = %q %v", in.LogoSVG(), err)
	}
	// Without a logo: no URL, no bytes.
	if tm, err := buildDir(t, catHead, nil); err != nil || tm.LogoURL != "" || tm.LogoSVG() != nil {
		t.Errorf("no logo: %q %q %v", tm.LogoURL, tm.LogoSVG(), err)
	}

	for name, c := range map[string]struct {
		logo  string
		files map[string][]byte
		want  string
	}{
		"traversal":    {"../etc/passwd", nil, "logo: "},
		"directory":    {"sub/logo.svg", nil, "logo: "},
		"not svg":      {"logo.png", nil, "logo: "},
		"upper case":   {"Logo.svg", nil, "logo: "},
		"missing":      {"logo.svg", nil, "logo: logo.svg: no such file"},
		"over 64 KiB":  {"logo.svg", map[string][]byte{"logo.svg": []byte(catLogo[:len(catLogo)-6] + strings.Repeat(" ", 64<<10) + "</svg>")}, "logo: over 64 KiB"},
		"hostile":      {"logo.svg", map[string][]byte{"logo.svg": []byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"><script>alert(1)</script></svg>`)}, "logo: element script refused"},
		"UTF-16":       {"logo.svg", map[string][]byte{"logo.svg": {0xff, 0xfe, '<', 0}}, "logo: not UTF-8"},
		"external ref": {"logo.svg", map[string][]byte{"logo.svg": []byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"><path d="M0 0" fill="url(https://x)"/></svg>`)}, "logo: url() must be a local #id reference"},
	} {
		_, err := buildDir(t, catHead+"logo: "+c.logo+"\n", c.files)
		wantErr(t, name, err, c.want)
	}

	// A symlinked logo (even to a good file in the folder) is refused.
	dir := filepath.Join(t.TempDir(), "demo")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "real.svg"), []byte(catLogo), 0o644)
	if err := os.Symlink("real.svg", filepath.Join(dir, "logo.svg")); err != nil {
		t.Fatal(err)
	}
	_, err = build("demo", "src", dir, []byte(catHead+"logo: logo.svg\n"), []byte(catCompose), "example.org", nil)
	wantErr(t, "symlink", err, "logo: not a regular file")
	// A directory named like the logo.
	dir2 := filepath.Join(t.TempDir(), "demo")
	os.MkdirAll(filepath.Join(dir2, "logo.svg"), 0o755)
	_, err = build("demo", "src", dir2, []byte(catHead+"logo: logo.svg\n"), []byte(catCompose), "example.org", nil)
	wantErr(t, "dir", err, "logo: not a regular file")
	// No template directory (an in-memory build) never reads the cwd.
	_, err = build("demo", "src", "", []byte(catHead+"logo: logo.svg\n"), []byte(catCompose), "example.org", nil)
	wantErr(t, "no dir", err, "logo: ")
}

func shots(entries ...string) string {
	s := "screenshots:\n"
	for _, e := range entries {
		s += "  - {file: " + e + ", caption: A view}\n"
	}
	return s
}

func TestBuildScreenshots(t *testing.T) {
	files := map[string][]byte{"a.png": pngMagic, "b.jpg": jpegMagic, "c.webp": webpMagic}
	tm, err := buildDir(t, catHead+shots("a.png", "b.jpg", "c.webp"), files)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/api/catalog/demo/screenshots/0", "/api/catalog/demo/screenshots/1", "/api/catalog/demo/screenshots/2"}
	if strings.Join(tm.ScreenshotURLs, " ") != strings.Join(want, " ") {
		t.Errorf("screenshot_urls = %v", tm.ScreenshotURLs)
	}
	for i, c := range []struct {
		data []byte
		ct   string
	}{{pngMagic, "image/png"}, {jpegMagic, "image/jpeg"}, {webpMagic, "image/webp"}} {
		b, ct, ok := tm.Screenshot(i)
		if !ok || ct != c.ct || !bytes.Equal(b, c.data) {
			t.Errorf("Screenshot(%d) = %q %q %v", i, b, ct, ok)
		}
	}
	for _, n := range []int{-1, 3, 100} {
		if _, _, ok := tm.Screenshot(n); ok {
			t.Errorf("Screenshot(%d) ok", n)
		}
	}
	if tm.Manifest.Screenshots[1].Caption != "A view" || tm.Manifest.Screenshots[1].File != "b.jpg" {
		t.Errorf("manifest screenshots = %+v", tm.Manifest.Screenshots)
	}

	big := append(append([]byte(nil), pngMagic...), make([]byte, 512<<10)...)
	for name, c := range map[string]struct {
		m     string
		files map[string][]byte
		want  string
	}{
		"png named jpg":   {shots("a.jpg"), map[string][]byte{"a.jpg": pngMagic}, "screenshots[0]: not a JPEG"},
		"jpeg named png":  {shots("b.png", "a.png"), map[string][]byte{"b.png": pngMagic, "a.png": jpegMagic}, "screenshots[1]: not a PNG"},
		"text named webp": {shots("c.webp"), map[string][]byte{"c.webp": []byte("RIFF....AVI ")}, "screenshots[0]: not a WebP"},
		"empty":           {shots("a.png"), map[string][]byte{"a.png": nil}, "screenshots[0]: not a PNG"},
		"seven":           {shots("a.png", "a.png", "a.png", "a.png", "a.png", "a.png", "a.png"), files, "screenshots: at most 6"},
		"over 512 KiB":    {shots("a.png"), map[string][]byte{"a.png": big}, "screenshots[0]: over 512 KiB"},
		"traversal":       {shots("../a.png"), files, "screenshots[0]: file"},
		"gif":             {shots("a.gif"), files, "screenshots[0]: file"},
		"missing":         {shots("z.png"), files, "screenshots[0]: z.png: no such file"},
		"no caption":      {"screenshots:\n  - {file: a.png}\n", files, "screenshots[0]: caption"},
		"long caption":    {"screenshots:\n  - {file: a.png, caption: " + strings.Repeat("é", 121) + "}\n", files, "screenshots[0]: caption"},
		"two lines":       {"screenshots:\n  - {file: a.png, caption: \"a\\nb\"}\n", files, "screenshots[0]: caption"},
	} {
		_, err := buildDir(t, catHead+c.m, c.files)
		wantErr(t, name, err, c.want)
	}
	// 120 characters (not bytes) is fine.
	if _, err := buildDir(t, catHead+"screenshots:\n  - {file: a.png, caption: "+strings.Repeat("é", 120)+"}\n", files); err != nil {
		t.Errorf("120-character caption: %v", err)
	}
}

func TestBuildCatalogFields(t *testing.T) {
	m := catHead + "resources: {min_memory_mib: 512, min_disk_gib: 2}\n"
	tm, err := buildDir(t, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	if tm.CategoryLabel != "Home automation" || tm.CategoryRank != 7 || !tm.Routerless {
		t.Errorf("category %q %d routerless %v", tm.CategoryLabel, tm.CategoryRank, tm.Routerless)
	}
	if r := tm.Manifest.Resources; r == nil || r.MinMemoryMiB != 512 || r.MinDiskGiB != 2 {
		t.Errorf("resources = %+v", r)
	}
	if l := tm.Manifest.Links; l == nil || l.Website != "https://demo.example/" || l.Source == nil || *l.Source != "https://git.example/demo" {
		t.Errorf("links = %+v", l)
	}
	// A closed-source app: source null with a note.
	closed := strings.Replace(catHead, "  source: https://git.example/demo\n", "  source: null\n  source_note: Demo is proprietary software\n", 1)
	tm, err = buildDir(t, closed, nil)
	if err != nil || tm.Manifest.Links.Source != nil || tm.Manifest.Links.SourceNote == "" {
		t.Errorf("closed source: %+v %v", tm.Manifest.Links, err)
	}
	b, _ := json.Marshal(tm)
	if !strings.Contains(string(b), `"links":{"website":"https://demo.example/","source":null,"source_note":"Demo is proprietary software"}`) {
		t.Errorf("links JSON: %s", b)
	}

	for name, c := range map[string]struct{ m, want string }{
		"memory low":       {catHead + "resources: {min_memory_mib: 8}\n", "resources.min_memory_mib"},
		"memory high":      {catHead + "resources: {min_memory_mib: 2000000}\n", "resources.min_memory_mib"},
		"disk":             {catHead + "resources: {min_disk_gib: 70000}\n", "resources.min_disk_gib"},
		"disk negative":    {catHead + "resources: {min_disk_gib: -1}\n", "resources.min_disk_gib"},
		"website http":     {strings.Replace(catHead, "https://demo.example/", "http://demo.example/", 1), "links.website"},
		"website js":       {strings.Replace(catHead, "https://demo.example/", "\"javascript:alert(1)\"", 1), "links.website"},
		"website userinfo": {strings.Replace(catHead, "https://demo.example/", "https://bank.example@evil.example/", 1), "links.website"},
		"source js":        {strings.Replace(catHead, "https://git.example/demo", "\"javascript:alert(1)\"", 1), "links.source"},
		"no website":       {strings.Replace(catHead, "  website: https://demo.example/\n", "", 1), "links.website"},
		"note two lines":   {strings.Replace(catHead, "  source: https://git.example/demo\n", "  source: null\n  source_note: \"a\\nb is closed\"\n", 1), "links.source_note"},
	} {
		_, err := buildDir(t, c.m, nil)
		wantErr(t, name, err, c.want)
	}
}

// The views carry the URLs and labels, never the bytes.
func TestCatalogJSONHasNoBytes(t *testing.T) {
	tm, err := buildDir(t, catHead+"logo: logo.svg\n"+shots("a.png"), map[string][]byte{"logo.svg": []byte(catLogo), "a.png": pngMagic})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(tm)
	s := string(b)
	for _, k := range []string{`"category_label":"Home automation"`, `"category_rank":7`, `"routerless":true`,
		`"logo_url":"/api/catalog/demo/logo.svg"`, `"screenshot_urls":["/api/catalog/demo/screenshots/0"]`, `"logo":"logo.svg"`} {
		if !strings.Contains(s, k) {
			t.Errorf("JSON lacks %s: %s", k, s)
		}
	}
	if strings.Contains(s, "336699") || strings.Contains(s, "PNG") || strings.Contains(s, "logoSVG") {
		t.Errorf("JSON carries the bytes: %s", s)
	}
}
