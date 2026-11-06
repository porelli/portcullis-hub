package hub

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

var aiTemplatesBlockRe = regexp.MustCompile(`(?m)^ai:`)

// aiPendingTemplatesDir bridges G3 (plan 4): until the templates repo's Task 24
// gives every template its ai: block, a checkout in which NO manifest has
// one is copied with ai.unsupported "AI support is being added" appended
// to each manifest, so TestRealTemplatesInstances still checks everything else.
// As soon as any manifest has an ai: block the checkout is used as is
// (and a template without one is refused). Remove after T24 is merged.
// internal/templates/aipending_test.go has the same copy.
func aiPendingTemplatesDir(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return dir
	}
	var manifests []string
	for _, e := range entries {
		p := filepath.Join(dir, e.Name(), "manifest.yaml")
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if aiTemplatesBlockRe.Match(b) {
			return dir
		}
		manifests = append(manifests, e.Name())
	}
	if len(manifests) == 0 {
		return dir
	}
	out := t.TempDir()
	if err := os.CopyFS(out, os.DirFS(dir)); err != nil {
		t.Fatal(err)
	}
	for _, name := range manifests {
		p := filepath.Join(out, name, "manifest.yaml")
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		b = append(b, "\nai:\n  unsupported: \"AI support is being added\"\n"...)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("G3: no template has an ai: block yet (templates Task 24 pending): checking a copy with ai.unsupported added")
	return out
}
