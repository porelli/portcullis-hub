// Package svgsafe is the logo lint of contract §3 ("Logo lint"): an
// allowlist check of a template's SVG logo, the same rules and reason
// texts as the templates validator's tests/svgsafe.py (shared vectors:
// testdata/vectors.json, a byte copy of tests/svg_vectors.json).
//
// It catches mistakes and obvious hostile content (script, event handlers,
// foreign objects, external references, DTDs and entities). It is a lint,
// not the security boundary: the Hub only ever shows a logo as <img src>
// from its catalog route with a sandboxing CSP (contract §11.7). Check
// only reads: the Hub serves the checked bytes as read, never re-serialised.
package svgsafe

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"
)

// MaxBytes caps a logo file.
const MaxBytes = 64 << 10

// MaxDepth caps element nesting.
const MaxDepth = 64

const (
	svgNS   = "http://www.w3.org/2000/svg"
	xlinkNS = "http://www.w3.org/1999/xlink"
	xmlNS   = "http://www.w3.org/XML/1998/namespace"
)

// The allowlist (contract §3; tests/svgsafe.py).
var (
	elements = set("svg g path circle ellipse rect line polyline polygon defs linearGradient radialGradient " +
		"stop clipPath mask use symbol title desc")
	// Text is kept only in these.
	textElements = set("title desc")
	attributes   = set("fill stroke opacity fill-opacity fill-rule clip-rule transform viewBox width height x y " +
		"x1 y1 x2 y2 cx cy r rx ry d points offset stop-color stop-opacity gradientUnits " +
		"gradientTransform id clip-path mask preserveAspectRatio")
	// stroke-width, stroke-linecap, stroke-dasharray, ...
	attributePrefixes = []string{"stroke-"}
	namespaces        = set(svgNS + " " + xlinkNS)
)

var (
	localRef = regexp.MustCompile(`^#[A-Za-z_][A-Za-z0-9_.:-]*$`)
	urlOpen  = regexp.MustCompile(`(?i)url\(`)
	localURL = regexp.MustCompile(`(?i)^url\(#[A-Za-z_][A-Za-z0-9_.:-]*\)`)
	// The encoding pre-check: \s is Python's Unicode \s (str.isspace), as
	// in tests/svgsafe.py.
	xmlDecl = regexp.MustCompile(strings.ReplaceAll(`^<\?xml\s[^>]*?\bencoding\s*=\s*["']([^"']*)["']`,
		`\s`, `[\t\n\v\f\r \x{1c}-\x{1f}\x{85}\p{Z}]`))
)

func set(words string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(words) {
		m[w] = true
	}
	return m
}

var errNotWellFormed = errors.New("not well-formed XML")

// xmlDeclFull is the XML declaration's grammar (XML 1.0 §2.8).
var xmlDeclFull = regexp.MustCompile(`^<\?xml[ \t\r\n]+version[ \t\r\n]*=[ \t\r\n]*("1\.[0-9]+"|'1\.[0-9]+')` +
	`([ \t\r\n]+encoding[ \t\r\n]*=[ \t\r\n]*("[A-Za-z][A-Za-z0-9._-]*"|'[A-Za-z][A-Za-z0-9._-]*'))?` +
	`([ \t\r\n]+standalone[ \t\r\n]*=[ \t\r\n]*("(yes|no)"|'(yes|no)'))?[ \t\r\n]*\?>$`)

func isSpaceByte(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }

// piTarget: the target is followed by white space or "?>" (encoding/xml
// would take "<?a=b?>" as target "a").
func piTarget(raw []byte, target string) bool {
	rest := raw[min(len(raw), 2+len(target)):]
	return bytes.Equal(rest, []byte("?>")) || (len(rest) > 0 && isSpaceByte(rest[0]))
}

// wellFormedTag catches what encoding/xml lets through in a start tag and
// expat does not: attributes not separated by white space (a="1"b="2")
// and names with a stray colon ("g:", ":svg").
func wellFormedTag(raw []byte, t xml.StartElement) bool {
	if !okName(t.Name) {
		return false
	}
	for _, a := range t.Attr {
		if !okName(a.Name) {
			return false
		}
	}
	var quote byte
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
				if i+1 < len(raw) && !isSpaceByte(raw[i+1]) && raw[i+1] != '/' && raw[i+1] != '>' {
					return false
				}
			}
		case c == '"' || c == '\'':
			quote = c
		}
	}
	return true
}

// okName: no stray colon, and the prefix and local part each start with
// a name-start character (encoding/xml also takes "2x", ".x" and "-x").
func okName(n xml.Name) bool {
	if strings.Contains(n.Local, ":") || !nameStart(n.Local) {
		return false
	}
	return n.Space == "" || nameStart(n.Space)
}

func nameStart(s string) bool {
	if s == "" {
		return false
	}
	c := s[0]
	return !(c >= '0' && c <= '9') && c != '.' && c != '-'
}

// normAttr is XML attribute-value normalisation for CDATA attributes:
// white space characters become spaces (encoding/xml keeps them).
func normAttr(v string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return ' '
		}
		return r
	}, v)
}

func attrProblem(a xml.Attr) error {
	ns, local, value := a.Name.Space, a.Name.Local, a.Value
	// A CSS escape (\75 rl(, u\rl() decodes to url( in a browser's CSS
	// tokenizer: no logo needs a backslash anywhere.
	if strings.Contains(value, `\`) {
		return errors.New("backslash refused")
	}
	if strings.HasPrefix(strings.ToLower(local), "on") {
		return fmt.Errorf("event attribute %s refused", local)
	}
	if local == "style" && ns == "" {
		return errors.New("style refused")
	}
	if local == "href" && (ns == "" || ns == xlinkNS) {
		if !localRef.MatchString(value) {
			return errors.New("href must be a local #id reference")
		}
		return nil
	}
	switch {
	case ns == xlinkNS:
		return fmt.Errorf("attribute xlink:%s refused", local)
	case ns == xmlNS:
		return fmt.Errorf("attribute xml:%s refused", local)
	case ns != "":
		return fmt.Errorf("attribute %s in namespace %s refused", local, ns)
	}
	if !attributes[local] && !hasAnyPrefix(local, attributePrefixes) {
		return fmt.Errorf("attribute %s refused", local)
	}
	for _, m := range urlOpen.FindAllStringIndex(value, -1) {
		if !localURL.MatchString(value[m[0]:]) {
			return errors.New("url() must be a local #id reference")
		}
	}
	return nil
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// isXMLSpace: the white space XML allows outside the root element.
func isXMLSpace(b []byte) bool {
	return len(bytes.Trim(b, " \t\r\n")) == 0
}

type frame struct {
	raw   xml.Name // the tag as written, for the end tag
	local string
	ns    map[string]string // prefix ("" = default) -> namespace in force
	text  bool              // non-blank text directly inside
}

// Check returns nil when data is an acceptable logo, else an error whose
// text is the reason (shared with the templates validator, byte for byte).
func Check(data []byte) error {
	if len(data) > MaxBytes {
		return errors.New("over 64 KiB")
	}
	if bytes.HasPrefix(data, []byte("\xef\xbb\xbf")) || !utf8.Valid(data) {
		return errors.New("not UTF-8")
	}
	text := string(data)
	if m := xmlDecl.FindStringSubmatch(text); m != nil {
		if e := strings.ToLower(m[1]); e != "utf-8" && e != "utf8" {
			return errors.New("encoding must be UTF-8")
		}
	}
	// Before parsing: what the parser would otherwise act on or hide.
	if strings.Contains(text, "<!ENTITY") {
		return errors.New("entity refused")
	}
	if strings.Contains(strings.ToUpper(text), "<!DOCTYPE") {
		return errors.New("DOCTYPE refused")
	}
	if strings.Contains(text, "<![CDATA[") {
		return errors.New("CDATA refused")
	}

	// Tokens only: no Encoder, nothing is ever written back. The decoder
	// converts no charset: only the "utf8" spelling (accepted above, as by
	// expat) passes through unchanged, anything else is a parse error.
	d := xml.NewDecoder(bytes.NewReader(data))
	d.Strict = true
	d.CharsetReader = func(label string, in io.Reader) (io.Reader, error) {
		if strings.EqualFold(label, "utf8") {
			return in, nil
		}
		return nil, errNotWellFormed
	}
	var stack []frame
	seenRoot, rootDone, first := false, false, true
	for {
		start := d.InputOffset()
		tok, err := d.RawToken()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errNotWellFormed
		}
		raw := data[start:d.InputOffset()]
		isFirst := first
		first = false
		switch t := tok.(type) {
		case xml.ProcInst:
			// The XML declaration only as the very first bytes and in its
			// grammar (encoding/xml checks neither). Any other processing
			// instruction is refused; a malformed one (an "xml" target in
			// another case, a colon, no white space after the target) is
			// not well-formed, as in expat.
			if t.Target == "xml" {
				if !isFirst || start != 0 || !xmlDeclFull.Match(raw) {
					return errNotWellFormed
				}
				continue
			}
			if strings.EqualFold(t.Target, "xml") || strings.Contains(t.Target, ":") || !nameStart(t.Target) || !piTarget(raw, t.Target) {
				return errNotWellFormed
			}
			return errors.New("processing instruction refused")
		case xml.Directive:
			// A DOCTYPE or entity was refused above: anything else is
			// malformed.
			return errNotWellFormed
		case xml.Comment:
			// Ignored.
		case xml.CharData:
			if len(stack) == 0 {
				if !isXMLSpace(t) {
					return errNotWellFormed
				}
				continue
			}
			if strings.TrimSpace(string(t)) != "" {
				stack[len(stack)-1].text = true
			}
		case xml.EndElement:
			if len(stack) == 0 {
				return errNotWellFormed
			}
			f := stack[len(stack)-1]
			if t.Name != f.raw {
				return errNotWellFormed
			}
			stack = stack[:len(stack)-1]
			if f.text && !textElements[f.local] {
				return errors.New("text outside title and desc refused")
			}
			if len(stack) == 0 {
				rootDone = true
			}
		case xml.StartElement:
			if rootDone || !wellFormedTag(raw, t) {
				return errNotWellFormed
			}
			var parent *frame
			if len(stack) > 0 {
				parent = &stack[len(stack)-1]
			}
			el, attrs, bind, err := resolve(t, parent)
			if err != nil {
				return err
			}
			if el.Space != svgNS {
				return fmt.Errorf("element %s is not in the SVG namespace", el.Local)
			}
			if !seenRoot {
				seenRoot = true
				if el.Local != "svg" {
					return errors.New("root must be svg")
				}
				if !hasAttr(attrs, "viewBox") {
					return errors.New("svg has no viewBox")
				}
			}
			if el.Local == "style" {
				return errors.New("style refused")
			}
			if !elements[el.Local] {
				return fmt.Errorf("element %s refused", el.Local)
			}
			stack = append(stack, frame{raw: t.Name, local: el.Local, ns: bind})
			if len(stack) > MaxDepth {
				return fmt.Errorf("nested deeper than %d", MaxDepth)
			}
			for _, a := range attrs {
				if err := attrProblem(a); err != nil {
					return err
				}
			}
		}
	}
	if !seenRoot || len(stack) != 0 {
		return errNotWellFormed
	}
	return nil
}

func hasAttr(attrs []xml.Attr, local string) bool {
	for _, a := range attrs {
		if a.Name.Space == "" && a.Name.Local == local {
			return true
		}
	}
	return false
}

// resolve checks a start tag against the namespace bindings in force
// (RawToken leaves prefixes unresolved, so the lint resolves them itself
// and refuses an unbound prefix or a duplicate attribute, as expat does).
// The tag's own namespace declarations come first, in document order, as
// tests/svgsafe.py's start-ns events. It returns the element's expanded
// name, its other attributes with expanded names, and the tag's bindings.
func resolve(t xml.StartElement, parent *frame) (xml.Name, []xml.Attr, map[string]string, error) {
	bind := map[string]string{}
	if parent != nil {
		for k, v := range parent.ns {
			bind[k] = v
		}
	}
	for i := range t.Attr {
		t.Attr[i].Value = normAttr(t.Attr[i].Value)
	}
	for _, a := range t.Attr {
		var prefix string
		switch {
		case a.Name.Space == "" && a.Name.Local == "xmlns":
			prefix = ""
		case a.Name.Space == "xmlns":
			prefix = a.Name.Local
			if prefix == "xmlns" || (prefix == "xml") != (a.Value == xmlNS) || a.Value == "" {
				return xml.Name{}, nil, nil, errNotWellFormed
			}
		default:
			continue
		}
		if !namespaces[a.Value] {
			return xml.Name{}, nil, nil, fmt.Errorf("namespace %s refused", a.Value)
		}
		bind[prefix] = a.Value
	}
	expand := func(n xml.Name, element bool) (xml.Name, bool) {
		switch {
		case n.Space == "xml":
			return xml.Name{Space: xmlNS, Local: n.Local}, true
		case n.Space != "":
			uri, ok := bind[n.Space]
			if !ok || uri == "" {
				return xml.Name{}, false
			}
			return xml.Name{Space: uri, Local: n.Local}, true
		case element:
			return xml.Name{Space: bind[""], Local: n.Local}, true
		}
		return n, true // an unprefixed attribute has no namespace
	}
	el, ok := expand(t.Name, true)
	if !ok {
		return xml.Name{}, nil, nil, errNotWellFormed
	}
	var attrs []xml.Attr
	seen := map[xml.Name]bool{}
	for _, a := range t.Attr {
		if (a.Name.Space == "" && a.Name.Local == "xmlns") || a.Name.Space == "xmlns" {
			if seen[a.Name] {
				return xml.Name{}, nil, nil, errNotWellFormed
			}
			seen[a.Name] = true
			continue
		}
		n, ok := expand(a.Name, false)
		if !ok || seen[n] {
			return xml.Name{}, nil, nil, errNotWellFormed
		}
		seen[n] = true
		attrs = append(attrs, xml.Attr{Name: n, Value: a.Value})
	}
	return el, attrs, bind, nil
}
