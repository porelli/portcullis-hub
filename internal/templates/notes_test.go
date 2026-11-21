package templates

import (
	"encoding/json"
	"strings"
	"testing"
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
