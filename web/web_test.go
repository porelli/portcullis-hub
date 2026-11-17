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
	"operations/ai.md", "guides/connect-your-ai.md", "operations/ssh-access.md",
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

// TestMySignInMailSectionAndDialog: the Sign-in page has the "Mail
// passwords" section (one's own page only), and the shown-once dialog
// clears the password field, revokes the profile's Blob URL and drops
// the bytes on close.
func TestMySignInMailSectionAndDialog(t *testing.T) {
	b, err := fs.ReadFile(FS, "mysignin.js")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{"<h3 class=\"pd-h3\">Mail passwords</h3>", "if (self) h += '<div data-msi-mail hidden></div>';", "call('GET', '/api/me/mail')",
		"call('POST', '/api/me/mail/passwords', { label, expiry, code: pr.code, code_verifier: pr.code_verifier, nonce: pr.nonce })"} {
		if !strings.Contains(s, want) {
			t.Errorf("mysignin.js lacks %q", want)
		}
	}
	i := strings.Index(s, "function openMailShown(")
	j := strings.Index(s[i:], "\n  }\n") + i
	if i < 0 || j <= i {
		t.Fatal("no openMailShown")
	}
	dlg := s[i:j]
	clear := dlg[strings.Index(dlg, "const clear = () => {"):]
	for _, want := range []string{"secret = null;", "code.textContent = '';", "bytes.fill(0);", "disarm();", "dlg.remove();"} {
		if !strings.Contains(clear, want) {
			t.Errorf("the dialog's clear lacks %q", want)
		}
	}
	for _, want := range []string{"URL.revokeObjectURL(url)", "dlg.addEventListener('close', clear);", "e.preventDefault();"} {
		if !strings.Contains(dlg, want) {
			t.Errorf("openMailShown lacks %q", want)
		}
	}
}

// TestSSHPagesEmbedded: the SSH access scripts are embedded and loaded
// by their pages (the Hub's tab; the Sign-in page's card; the people
// page's person card and delegate tab), freshauth.js before ssh.js.
func TestSSHPagesEmbedded(t *testing.T) {
	for _, f := range []string{"ssh.js", "myssh.js"} {
		if b, err := fs.ReadFile(FS, f); err != nil || len(b) < 1000 {
			t.Errorf("%s not embedded: %v", f, err)
		}
	}
	read := func(f string) string {
		b, err := fs.ReadFile(FS, f)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	idx := read("index.html")
	for _, want := range []string{`data-tab="ssh"`, `id="tab-ssh"`, `id="ssh-root"`, `PortcullisSSH.render(`} {
		if !strings.Contains(idx, want) {
			t.Errorf("index.html lacks %s", want)
		}
	}
	fa, sj := strings.Index(idx, `src="/static/freshauth.js"`), strings.Index(idx, `src="/static/ssh.js"`)
	if fa < 0 || sj < 0 || fa > sj {
		t.Errorf("index.html loads freshauth.js (%d) and ssh.js (%d) out of order", fa, sj)
	}
	for f, wants := range map[string][]string{
		"mysignin.html": {`src="/static/myssh.js"`, `id="myssh-root"`, `PortcullisMySSH.mountSelf(`},
		"people.html":   {`src="/static/myssh.js"`, `PortcullisMySSH.renderDelegate`, `PortcullisMySSH.probeDelegate(`},
		"directory.js":  {`data-pp-ssh=`, `PortcullisMySSH.mountPerson(`, `data-gp-ssh>SSH: `},
	} {
		page := read(f)
		for _, w := range wants {
			if !strings.Contains(page, w) {
				t.Errorf("%s lacks %s", f, w)
			}
		}
	}
	if strings.Contains(read("people.html"), `/static/ssh.js`) || strings.Contains(read("mysignin.html"), `/static/ssh.js`) {
		t.Error("a people page loads the Hub's ssh.js")
	}
}

// TestSSHScriptsNoInnerHTMLWithData: the SSH scripts build every node
// (no innerHTML, outerHTML, insertAdjacentHTML, document.write or inline
// handlers); the enrolment code never goes near a URL or storage.
func TestSSHScriptsNoInnerHTMLWithData(t *testing.T) {
	for _, f := range []string{"ssh.js", "myssh.js"} {
		b, err := fs.ReadFile(FS, f)
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		for _, bad := range []string{".innerHTML", ".outerHTML", "insertAdjacentHTML", "document.write", "onclick=", "eval(", "new Function"} {
			if strings.Contains(src, bad) {
				t.Errorf("%s uses %s", f, bad)
			}
		}
		if f == "ssh.js" {
			for _, bad := range []string{"localStorage", "sessionStorage", "location.hash =", "history.pushState", "history.replaceState", "?code=", "&code="} {
				if strings.Contains(src, bad) {
					t.Errorf("ssh.js uses %s (the enrolment code never leaves the page)", bad)
				}
			}
			for _, want := range []string{"sudo portcullis host enroll < code.txt", "readOnly: true", "name again to confirm", "Sign a host key"} {
				if !strings.Contains(strings.ToLower(src), strings.ToLower(want)) {
					t.Errorf("ssh.js lacks %q", want)
				}
			}
		}
	}
}
