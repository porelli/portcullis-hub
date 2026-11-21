package templates

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// auth.notes is Markdown (contract §3): the built template carries it
// rendered and sanitised as notes_html, in every instance view, and a
// notes_html key in the YAML is never read.
func TestNotesHTMLBuilt(t *testing.T) {
	head := strings.Replace(smbHead, "  access_group: users_files\n",
		"  access_group: users_files\n  notes_html: \"<script>alert(1)</script>\"\n"+
			"  notes: |\n    SMB file *sharing*: `smbclient`.\n\n    <script>alert(1)</script>\n\n    - [docs](https://docs.example) [bad](javascript:alert(1))\n", 1)
	tm, err := build("files", "src", "", []byte(head), []byte(smbCompose), "example.org", nil)
	if err != nil {
		t.Fatal(err)
	}
	in, err := tm.Instance("files-office", nil, "example.org")
	if err != nil {
		t.Fatal(err)
	}
	want := "<p>SMB file <em>sharing</em>: <code>smbclient</code>.</p>\n\n<ul>\n<li>" +
		`<a href="https://docs.example" target="_blank" rel="noopener noreferrer nofollow">docs</a> bad</li>` + "\n</ul>"
	for _, v := range []Template{tm, in} {
		if v.Manifest.Auth.NotesHTML != want {
			t.Errorf("%s notes_html = %q, want %q", v.ID, v.Manifest.Auth.NotesHTML, want)
		}
		b, _ := json.Marshal(v)
		var got struct {
			Manifest struct {
				Auth struct {
					NotesHTML string `json:"notes_html"`
				} `json:"auth"`
			} `json:"manifest"`
		}
		if err := json.Unmarshal(b, &got); err != nil || got.Manifest.Auth.NotesHTML != want {
			t.Errorf("%s JSON notes_html = %q (%v)", v.ID, got.Manifest.Auth.NotesHTML, err)
		}
	}
}

// I1 / M2: ValidateManifest bounds auth.notes before anything renders it:
// a 120 KB nested input is refused fast, and so are hidden characters.
func TestNotesRefused(t *testing.T) {
	for name, c := range map[string]struct{ notes, want string }{
		"120 KB nested": {strings.Repeat("- ", 60000) + "x", "at most 16384 allowed"},
		"deep":          {strings.Repeat("> ", 17) + "x", "deeper than 16"},
		"bidi override": {"see \u202egnp.exe", "U+202E"},
		"zero width":    {"a\u200bb", "U+200B"},
		"isolate":       {"a\u2066b", "U+2066"},
		"bom":           {"\ufeffa", "U+FEFF"},
		"nul":           {"a\x00b", "U+0000"},
		"carriage ret":  {"a\r\nb", "U+000D"},
		"invalid utf-8": {"a\xffb", "not valid UTF-8"},
	} {
		start := time.Now()
		err := ValidateManifest(&Manifest{Auth: Auth{Method: "custom", Notes: c.notes}})
		if took := time.Since(start); took > 250*time.Millisecond {
			t.Errorf("%s: took %v", name, took)
		}
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	if err := validateNotes("Tabs\tand\nnewlines are fine → ✓"); err != nil {
		t.Error(err)
	}
}
