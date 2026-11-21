package templates

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The final review's catalog nits (contract §3 "No symlinks", the
// screenshot budget; §11.7 primary_only_reasons).

// writeCatTpl writes template name under src: manifest, compose and files.
func writeCatTpl(t *testing.T, src, name, manifest string, files map[string][]byte) string {
	t.Helper()
	d := filepath.Join(src, name)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	all := map[string][]byte{"manifest.yaml": []byte(manifest), "compose.yml": []byte(catCompose)}
	for k, v := range files {
		all[k] = v
	}
	for k, v := range all {
		if err := os.WriteFile(filepath.Join(d, k), v, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func ids(ts []Template) []string {
	var out []string
	for _, t := range ts {
		out = append(out, t.ID)
	}
	slices.Sort(out)
	return out
}

// TestDiscoverRefusesSymlinks: a symlinked template directory, manifest
// or compose file is refused, never followed.
func TestDiscoverRefusesSymlinks(t *testing.T) {
	src := t.TempDir()
	elsewhere := t.TempDir()
	writeCatTpl(t, src, "demo", catHead, nil)
	real := writeCatTpl(t, elsewhere, "real", catHead, nil)
	if err := os.Symlink(real, filepath.Join(src, "linked")); err != nil {
		t.Fatal(err)
	}
	m := writeCatTpl(t, src, "mlink", catHead, nil)
	os.Remove(filepath.Join(m, "manifest.yaml"))
	if err := os.Symlink(filepath.Join(real, "manifest.yaml"), filepath.Join(m, "manifest.yaml")); err != nil {
		t.Fatal(err)
	}
	c := writeCatTpl(t, src, "clink", catHead, nil)
	os.Remove(filepath.Join(c, "compose.yml"))
	if err := os.Symlink(filepath.Join(real, "compose.yml"), filepath.Join(c, "compose.yml")); err != nil {
		t.Fatal(err)
	}
	if got := ids(Discover(src, "src", "example.org", nil)); strings.Join(got, ",") != "demo" {
		t.Errorf("Discover = %v, want only demo", got)
	}
	for name, want := range map[string]string{"linked": "linked is a symlink", "mlink": "manifest.yaml is a symlink", "clink": "compose.yml is a symlink"} {
		_, err := Load(src, name, "src", "example.org", nil)
		wantErr(t, name, err, want)
	}
}

// TestDiscoverScreenshotBudget: past the source's budget a template
// loads without its screenshots; the ones before it keep theirs.
func TestDiscoverScreenshotBudget(t *testing.T) {
	old := maxSourceScreenshotBytes
	maxSourceScreenshotBytes = 3 * len(pngMagic)
	t.Cleanup(func() { maxSourceScreenshotBytes = old })
	src := t.TempDir()
	png := map[string][]byte{"a.png": pngMagic}
	writeCatTpl(t, src, "aa", catHead+shots("a.png", "a.png"), png)
	writeCatTpl(t, src, "bb", catHead+shots("a.png", "a.png"), png)
	writeCatTpl(t, src, "cc", catHead+shots("a.png"), png)
	got := map[string]int{}
	for _, tm := range Discover(src, "src", "example.org", nil) {
		got[tm.ID] = len(tm.ScreenshotURLs)
		if _, _, ok := tm.Screenshot(0); ok != (len(tm.ScreenshotURLs) > 0) {
			t.Errorf("%s: Screenshot(0) ok = %v with %d urls", tm.ID, ok, len(tm.ScreenshotURLs))
		}
	}
	// aa takes 2 of 3; bb's 2 don't fit (dropped); cc's 1 still does.
	if got["aa"] != 2 || got["bb"] != 0 || got["cc"] != 1 {
		t.Errorf("screenshots kept = %v", got)
	}
}

// TestCatalogPrimaryOnly: primary_only_reasons is Placement at load
// without the server-dependent bind reasons.
func TestCatalogPrimaryOnly(t *testing.T) {
	if r := catalogPrimaryOnly([]byte(catCompose), Manifest{}); r != nil {
		t.Errorf("a plain template: %v", r)
	}
	if r := catalogPrimaryOnly([]byte(catCompose), Manifest{Placement: PlacementPrimaryOnly}); !slices.Contains(r, "is marked placement: primary_only") {
		t.Errorf("placement primary_only: %v", r)
	}
	bind := []byte("services:\n  app:\n    image: x\n    volumes:\n      - /srv/media:/media\n")
	if _, all := Placement(bind, Manifest{}, nil, nil); len(all) == 0 {
		t.Fatal("the fixture's bind isn't a Placement reason")
	}
	if r := catalogPrimaryOnly(bind, Manifest{}); r != nil {
		t.Errorf("a bind outside the (unknown) roots: %v", r)
	}
	tm, err := buildDir(t, catHead+"placement: primary_only\n", nil)
	if err != nil || !slices.Contains(tm.PrimaryOnlyReasons, "is marked placement: primary_only") {
		t.Errorf("build: %v %v", tm.PrimaryOnlyReasons, err)
	}
}
