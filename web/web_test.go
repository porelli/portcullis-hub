package web

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// docsPages are the docs copies the Portcullis MCP serves (docs/sync.sh),
// by their place in porelli/portcullis-docs.
var docsPages = []string{
	"guides/integration-contracts.md", "operations/hub.md", "operations/auth-policies.md",
	"operations/groups.md", "operations/backups.md", "operations/file-sharing.md",
}

// TestDocsCopies: every page sync.sh copies is embedded, non-empty and a
// docs page (starts with a heading); nothing else is.
func TestDocsCopies(t *testing.T) {
	files, err := fs.Glob(Docs, "docs/*.md")
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, p := range docsPages {
		want = append(want, "docs/"+filepath.Base(p))
	}
	slices.Sort(want)
	if !slices.Equal(files, want) {
		t.Errorf("embedded docs %v, want %v", files, want)
	}
	for _, f := range files {
		b, _ := fs.ReadFile(Docs, f)
		if len(b) < 1000 || !strings.HasPrefix(string(b), "# ") {
			t.Errorf("%s: %d bytes, not a docs page", f, len(b))
		}
	}
	sh, err := os.ReadFile(filepath.Join("docs", "sync.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range docsPages {
		if !strings.Contains(string(sh), p) {
			t.Errorf("sync.sh doesn't copy %s", p)
		}
	}
}

// TestDocsCopiesInSync compares the copies with a docs checkout when
// PORTCULLIS_DOCS_DIR names one (run `go generate ./web` to refresh).
func TestDocsCopiesInSync(t *testing.T) {
	dir := os.Getenv("PORTCULLIS_DOCS_DIR")
	if dir == "" {
		t.Skip("PORTCULLIS_DOCS_DIR not set")
	}
	for _, p := range docsPages {
		src, err := os.ReadFile(filepath.Join(dir, "docs", p))
		if err != nil {
			t.Fatal(err)
		}
		got, _ := fs.ReadFile(Docs, "docs/"+filepath.Base(p))
		if !bytes.Equal(src, got) {
			t.Errorf("web/docs/%s differs from %s: run go generate ./web", filepath.Base(p), p)
		}
	}
}
