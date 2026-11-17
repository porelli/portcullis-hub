package templates

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
)

// mailVectorID is the template id every mail_vectors.json vector is
// built with (its binds name ./templates/mailsrv/…).
const mailVectorID = "mailsrv"

// mailVector is one entry of testdata/mail_vectors.json, shared byte for
// byte with portcullis-templates tests/mail_vectors.json: the
// vpn_vectors.json shape ("" = the template loads).
type mailVector struct {
	Name      string `json:"name"`
	Manifest  string `json:"manifest"`
	Compose   string `json:"compose"`
	WantError string `json:"want_error"`
}

func readMailVectors(t *testing.T) []mailVector {
	t.Helper()
	b, err := os.ReadFile("testdata/mail_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	var vs []mailVector
	if err := dec.Decode(&vs); err != nil {
		t.Fatal(err)
	}
	return vs
}

// contractMailRefusals are the refusal texts of contract §3.5 (the synced
// copy in web/docs), in contract order, each as a pattern: a <…>
// placeholder matches any text.
func contractMailRefusals(t *testing.T) (texts []string, pats []*regexp.Regexp) {
	t.Helper()
	doc, err := os.ReadFile("../../web/docs/integration-contracts.md")
	if err != nil {
		t.Fatal(err)
	}
	s := string(doc)
	i := strings.Index(s, "### 3.5 ")
	if i < 0 {
		t.Fatal("no §3.5 in the contract")
	}
	a := strings.Index(s[i:], "- **Validation refusals**")
	b := strings.Index(s[i:], "The mount texts are the VPN template's")
	if a < 0 || b < a {
		t.Fatal("no refusal list in §3.5")
	}
	ph := regexp.MustCompile(`<[^>]+>`)
	for _, line := range strings.Split(s[i+a:i+b], "\n") {
		if !strings.HasPrefix(line, "    - `") {
			continue
		}
		text := line[len("    - `"):]
		text = text[:strings.Index(text, "`")]
		parts := ph.Split(text, -1)
		for k := range parts {
			parts[k] = regexp.QuoteMeta(parts[k])
		}
		texts = append(texts, text)
		pats = append(pats, regexp.MustCompile("^"+strings.Join(parts, ".+")+"$"))
	}
	if len(texts) < 30 {
		t.Fatalf("only %d refusal texts in §3.5", len(texts))
	}
	return texts, pats
}

// mailRefusalNotVectored: a symlink can't be expressed in a vector (no
// template directory); ValidateMail's own tests cover it.
var mailRefusalNotVectored = map[string]bool{
	"mail: <s> mounts <entry>: it resolves outside templates/<id>/ (a symlink)": true,
}

// TestMailVectorsShape: every refusal text of §3.5 is the want_error of
// exactly one vector (the symlink text excepted), every refused vector's
// text is one of them, the refused vectors follow contract order, and the
// names are unique; the ok shapes the plan names are there.
func TestMailVectorsShape(t *testing.T) {
	vs := readMailVectors(t)
	texts, pats := contractMailRefusals(t)
	names := map[string]bool{}
	hits := make([]int, len(pats))
	last := -1
	for _, v := range vs {
		if names[v.Name] {
			t.Errorf("vector %q twice", v.Name)
		}
		names[v.Name] = true
		if v.Manifest == "" || v.Compose == "" {
			t.Errorf("%s: empty manifest or compose", v.Name)
		}
		if v.WantError == "" {
			if !strings.HasSuffix(v.Name, " ok") {
				t.Errorf("%s: a valid vector's name ends in ok", v.Name)
			}
			continue
		}
		if !strings.HasSuffix(v.Name, " refused") {
			t.Errorf("%s: a refused vector's name ends in refused", v.Name)
		}
		matched := -1
		for k, p := range pats {
			if p.MatchString(v.WantError) {
				if matched >= 0 {
					t.Errorf("%s: %q matches both %q and %q", v.Name, v.WantError, texts[matched], texts[k])
				}
				matched = k
			}
		}
		if matched < 0 {
			t.Errorf("%s: %q is no refusal text of §3.5", v.Name, v.WantError)
			continue
		}
		hits[matched]++
		if matched <= last {
			t.Errorf("%s: %q is out of contract order", v.Name, v.WantError)
		}
		last = matched
	}
	for k, n := range hits {
		if mailRefusalNotVectored[texts[k]] {
			if n != 0 {
				t.Errorf("%q has a vector but is listed as not vectored", texts[k])
			}
			continue
		}
		if n != 1 {
			t.Errorf("%q: %d vectors, want exactly 1", texts[k], n)
		}
	}
	for _, n := range []string{
		"stalwart-shaped ok", "mail-fake-shaped ok",
		"ports on a non-listener service refused", "traefik.enable false label refused", "cap_add NET_ADMIN refused",
		"./../ bind refused", "external portcullis_mail_tls volume refused", "YAML anchors refused", "enable_ipv6 refused",
		"instances multi refused", "person_secret option refused", "listeners split over two services refused",
		"gated missing the api service refused", "sessions missing refused", "api_version 2 refused",
	} {
		if !names[n] {
			t.Errorf("vector %q missing", n)
		}
	}
}

// TestMailVectorsOKShapesLoad: the valid vectors are valid templates for
// the rest of the Hub's rules too (ValidateMail itself is Task 5).
func TestMailVectorsOKShapesLoad(t *testing.T) {
	for _, v := range readMailVectors(t) {
		if v.WantError != "" {
			continue
		}
		if _, err := build(mailVectorID, "src", "", []byte(v.Manifest), []byte(v.Compose), "example.org", nil); err != nil {
			t.Errorf("%s: %v", v.Name, err)
		}
	}
}
