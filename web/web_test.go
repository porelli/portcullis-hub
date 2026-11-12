package web

import (
	"bytes"
	"crypto/sha256"
	"fmt"
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
	"operations/ai.md", "guides/connect-your-ai.md",
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

// brandingFiles are the logo and favicon copies (from the branding
// source, byte for byte) and their pinned sha256. mark.svg is
// concept-1-mark-dark.svg: every Hub surface is dark.
var brandingFiles = map[string]string{
	"favicon.svg":          "8c07f90ac5371f5742ca1837b45ff450f56674c8773ddbcd0b4b03fa17fd2352",
	"favicon.ico":          "d709cb96a8d612fc471fa02914d674f03972146a1680db98f97f93e46bcea7a1",
	"apple-touch-icon.png": "21b185a5c8c9ea6b234aa73d6d7f334cdb2f6713d4ea9d953f909a040b5d1cc3",
	"icon-192.png":         "becb41dbda1990e14c8fca7cf4540cf2596f2aa489e72b5b94e56e390aa1267c",
	"icon-512.png":         "c846a24046bc57a60ae4db0af83f5c2b0317c646ca4a14b702ef512f977bc709",
	"maskable-512.png":     "50372605937f18f310076ac04d818ea39993b07fe270c62e4d73e68f81a93a03",
	"site.webmanifest":     "cc025a34c1c48cb9fe21c9ff6ca8706ce4f46fceaf310b023cad91c483fde1c0",
	"mark.svg":             "a63ddab1ce0eac394cdbc7547f9fcbc9bf6947060601dd5202527222cef97bfa",
}

// TestBrandingCopies: every branding file is embedded with its pinned
// sha256.
func TestBrandingCopies(t *testing.T) {
	for name, want := range brandingFiles {
		b, err := fs.ReadFile(FS, name)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(b)); got != want {
			t.Errorf("%s sha256 = %s, want %s", name, got, want)
		}
	}
}

// TestPagesCarryBranding: each page links the favicon set and the
// manifest, and its <h1> carries the mark (the old ⚲ glyph is gone).
func TestPagesCarryBranding(t *testing.T) {
	links := []string{
		`<link rel="icon" href="/static/favicon.ico" sizes="48x48">`,
		`<link rel="icon" href="/static/favicon.svg" type="image/svg+xml">`,
		`<link rel="apple-touch-icon" href="/static/apple-touch-icon.png">`,
		`<link rel="manifest" href="/static/site.webmanifest">`,
	}
	const mark = `<img class="brand-mark" src="/static/mark.svg" alt="" width="28" height="28">`
	for _, page := range []string{"index.html", "people.html", "mysignin.html", "confirm.html", "impersonation-stop.html"} {
		b, err := fs.ReadFile(FS, page)
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		head, _, _ := strings.Cut(s, "</head>")
		for _, l := range links {
			if !strings.Contains(head, l) {
				t.Errorf("%s: <head> lacks %s", page, l)
			}
		}
		i := strings.Index(s, "<h1")
		j := strings.Index(s, "</h1>")
		if i < 0 || j < i || !strings.Contains(s[i:j], mark) {
			t.Errorf("%s: <h1> lacks the mark", page)
		}
		if strings.Contains(s, "&#9906;") {
			t.Errorf("%s still has &#9906;", page)
		}
	}
}
