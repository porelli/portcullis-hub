package svgsafe

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

type vector struct {
	Name   string `json:"name"`
	SVG    string `json:"svg"`
	SVGB64 string `json:"svg_b64"`
	OK     bool   `json:"ok"`
	Reason string `json:"reason"`
}

func loadVectors(t *testing.T) []vector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vs []vector
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&vs); err != nil {
		t.Fatal(err)
	}
	if len(vs) == 0 {
		t.Fatal("no vectors")
	}
	return vs
}

func (v vector) data(t *testing.T) []byte {
	if v.SVGB64 != "" {
		b, err := base64.StdEncoding.DecodeString(v.SVGB64)
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		return b
	}
	return []byte(v.SVG)
}

// TestCheckVectors pins the Hub's lint to the templates validator's
// (tests/svgsafe.py): the same verdict and the same reason, byte for byte.
func TestCheckVectors(t *testing.T) {
	for _, v := range loadVectors(t) {
		err := Check(v.data(t))
		switch {
		case v.OK && err != nil:
			t.Errorf("%s: refused: %v", v.Name, err)
		case !v.OK && err == nil:
			t.Errorf("%s: accepted, want %q", v.Name, v.Reason)
		case !v.OK && err.Error() != v.Reason:
			t.Errorf("%s: reason %q, want %q", v.Name, err.Error(), v.Reason)
		}
	}
}

const head = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">`

// TestCheckRefuses covers the plan's Review Focus 1 inputs.
func TestCheckRefuses(t *testing.T) {
	u16 := utf16.Encode([]rune(head + `<path d="M0 0"/></svg>`))
	var le bytes.Buffer
	le.Write([]byte{0xff, 0xfe})
	for _, c := range u16 {
		le.Write([]byte{byte(c), byte(c >> 8)})
	}
	deep := head + strings.Repeat("<g>", 10000) + strings.Repeat("</g>", 10000) + "</svg>"
	cases := []struct {
		name, reason string
		data         []byte
	}{
		{"UTF-16 BOM", "not UTF-8", le.Bytes()},
		{"UTF-16 BE BOM", "not UTF-8", append([]byte{0xfe, 0xff}, []byte(head+"</svg>")...)},
		{"entity bomb", "entity refused", []byte(`<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]>` + head + `<title>&b;</title></svg>`)},
		// 10 000 nested <g> is 70 000 bytes: the size cap comes first.
		{"10000 nested g", "over 64 KiB", []byte(deep)},
		{"1000 nested g", "nested deeper than 64", []byte(head + strings.Repeat("<g>", 1000) + strings.Repeat("</g>", 1000) + "</svg>")},
		{"65 deep", "nested deeper than 64", []byte(head + strings.Repeat("<g>", 64) + strings.Repeat("</g>", 64) + "</svg>")},
		{"xlink:href data:", "href must be a local #id reference", []byte(`<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 1 1"><use xlink:href="data:image/svg+xml;base64,PHN2Zz4="/></svg>`)},
		{"fill url(https://x)", "url() must be a local #id reference", []byte(head + `<path d="M0 0" fill="url(https://x)"/></svg>`)},
		{"CSS-escaped url(", "backslash refused", []byte(head + `<path d="M0 0" fill="\75 rl(https://x)"/></svg>`)},
		{"backslash in d", "backslash refused", []byte(head + `<path d="M0\0"/></svg>`)},
		{"over 64 KiB", "over 64 KiB", []byte(head + strings.Repeat(" ", MaxBytes) + "</svg>")},
		{"two roots", "not well-formed XML", []byte(head + "</svg>" + head + "</svg>")},
		{"text after root", "not well-formed XML", []byte(head + "</svg>x")},
		{"empty", "not well-formed XML", nil},
		{"only a comment", "not well-formed XML", []byte("<!-- x -->")},
		{"unbound element prefix", "not well-formed XML", []byte(head + `<x:g/></svg>`)},
		{"unbound attribute prefix", "not well-formed XML", []byte(head + `<g x:fill="red"/></svg>`)},
		{"duplicate attribute", "not well-formed XML", []byte(head + `<g fill="red" fill="blue"/></svg>`)},
		{"duplicate expanded attribute", "not well-formed XML", []byte(`<svg xmlns="http://www.w3.org/2000/svg" xmlns:a="http://www.w3.org/1999/xlink" xmlns:b="http://www.w3.org/1999/xlink" viewBox="0 0 1 1"><use a:href="#x" b:href="#x"/></svg>`)},
		{"misplaced xml declaration", "not well-formed XML", []byte(" <?xml version=\"1.0\"?>" + head + "</svg>")},
		{"xml declaration after a comment", "not well-formed XML", []byte("<!-- c --><?xml version=\"1.0\"?>" + head + "</svg>")},
		{"pi after root", "processing instruction refused", []byte(head + "</svg><?x y?>")},
		{"undeclaring the default namespace", "namespace  refused", []byte(head + `<g xmlns=""/></svg>`)},
		{"invalid UTF-8", "not UTF-8", []byte(head + "<title>\xff</title></svg>")},
		// encoding/xml takes these, expat (tests/svgsafe.py) does not.
		{"attributes without white space", "not well-formed XML", []byte(head + `<rect width="1"ONCLICK="alert(1)"/></svg>`)},
		{"element name ending in a colon", "not well-formed XML", []byte(head + `<g:/></svg>`)},
		{"prefix starting with a digit", "not well-formed XML", []byte(`<svg xmlns="http://www.w3.org/2000/svg" xmlns:2x="http://www.w3.org/1999/xlink" viewBox="0 0 1 1"/>`)},
		{"PI target glued to its data", "not well-formed XML", []byte(`<?xmoke=l version="1.0"?>` + head + "</svg>")},
		{"PI target with a colon", "not well-formed XML", []byte(`<?xm:l version="1.0"?>` + head + "</svg>")},
		{"junk in the XML declaration", "not well-formed XML", []byte(`<?xml vers=sion="1.0"?>` + head + "</svg>")},
		{"mismatched end tag", "not well-formed XML", []byte(head + `<g></G></svg>`)},
		{"Latin-1 after a Unicode space", "encoding must be UTF-8", []byte("<?xml version=\"1.0\" encoding=\u00a0\"ISO-8859-1\"?>" + head + "</svg>")},
	}
	for _, c := range cases {
		err := Check(c.data)
		if err == nil || err.Error() != c.reason {
			t.Errorf("%s: got %v, want %q", c.name, err, c.reason)
		}
	}
}

// TestCheckAccepts: a few shapes real logos use.
func TestCheckAccepts(t *testing.T) {
	for _, s := range []string{
		head + strings.Repeat("<g>", 63) + strings.Repeat("</g>", 63) + "</svg>",
		"<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"no\"?>\n" + head + "<path d=\"M0 0\"/></svg>\n<!-- trailing -->\n",
		head + "<title><!-- c -->A</title>\n  <g stroke-width=\"2\" stroke-linecap=\"round\"/></svg>",
	} {
		if err := Check([]byte(s)); err != nil {
			t.Errorf("%q: %v", s[:min(len(s), 80)], err)
		}
	}
}

// TestCheckNeverWrites: Check reads only (the Hub serves the bytes as
// read at load).
func TestCheckNeverWrites(t *testing.T) {
	b := []byte(head + `<path d="M0 0"/></svg>`)
	c := bytes.Clone(b)
	_ = Check(b)
	if !bytes.Equal(b, c) {
		t.Fatal("Check changed its input")
	}
}

// TestVectorsInSync: testdata/vectors.json is a byte copy of the
// templates repo's tests/svg_vectors.json.
func TestVectorsInSync(t *testing.T) {
	dir := os.Getenv("PORTCULLIS_TEMPLATES_DIR")
	if dir == "" {
		t.Skip("PORTCULLIS_TEMPLATES_DIR not set")
	}
	src, err := os.ReadFile(filepath.Join(dir, "tests", "svg_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join("testdata", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(src, got) {
		t.Error("internal/svgsafe/testdata/vectors.json differs from the templates repo's tests/svg_vectors.json: copy it")
	}
}
