// Package notes renders a template's auth.notes (contract §3) from
// Markdown to sanitised HTML, server-side, for the Hub UI and the portal.
//
// Two layers, each safe on its own:
//
//   - goldmark parses CommonMark plus the GFM table and autolink
//     extensions. Raw HTML is never passed through (no html.WithUnsafe):
//     an HTML block or inline tag becomes an "omitted" comment. Before
//     rendering, an AST transformer turns images into their alt text and
//     every link or autolink whose URL isn't an absolute http/https URL
//     with a host (and no userinfo) or a mailto URL into its text; every
//     other link gets target="_blank" and rel="noopener noreferrer
//     nofollow".
//   - bluemonday then keeps only the elements and attributes that
//     subset can produce, links with an http, https or mailto URL and no
//     image at all; anything else is dropped (its text kept, escaped).
//
// Rendering is superlinear in the block nesting depth, so notes must pass
// Check (at most MaxBytes, nesting at most MaxDepth) first; the Hub checks
// them in templates.ValidateManifest and renders them once, with Render,
// when a template is built.
package notes

import (
	"bytes"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/microcosm-cc/bluemonday"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
)

// LinkRel is the rel every rendered link carries.
const LinkRel = "noopener noreferrer nofollow"

var (
	md = goldmark.New(
		goldmark.WithExtensions(
			extension.NewTable(extension.WithTableCellAlignMethod(extension.TableCellAlignAttribute)),
			extension.Linkify,
		),
		goldmark.WithParserOptions(parser.WithASTTransformers(util.Prioritized(transformer{}, 1000))),
		// No html.WithUnsafe(): raw HTML is omitted, dangerous URLs dropped.
	)

	policyOnce sync.Once
	policy     *bluemonday.Policy
)

// sanitizer is the second layer: the elements the Markdown subset makes,
// nothing else. Built once; a bluemonday Policy is safe for concurrent use
// once built.
func sanitizer() *bluemonday.Policy {
	policyOnce.Do(func() {
		p := bluemonday.NewPolicy()
		p.AllowElements("p", "br", "hr", "strong", "em", "code", "pre", "blockquote",
			"ul", "ol", "li", "h1", "h2", "h3", "h4", "h5", "h6",
			"table", "thead", "tbody", "tr", "th", "td")
		p.AllowAttrs("start").Matching(regexp.MustCompile(`^[0-9]{1,9}$`)).OnElements("ol")
		p.AllowAttrs("align").Matching(regexp.MustCompile(`^(left|center|right)$`)).OnElements("th", "td")
		p.AllowAttrs("href").OnElements("a")
		p.AllowAttrs("target").Matching(regexp.MustCompile(`^_blank$`)).OnElements("a")
		p.AllowAttrs("rel").Matching(regexp.MustCompile(`^` + LinkRel + `$`)).OnElements("a")
		p.AllowURLSchemes("http", "https", "mailto")
		p.AllowRelativeURLs(false)
		p.RequireParseableURLs(true)
		// A safety net: goldmark already sets both on every link.
		p.RequireNoFollowOnLinks(true)
		p.RequireNoReferrerOnLinks(true)
		policy = p
	})
	return policy
}

// transformer drops images (their alt text stays, as text), unwraps every
// link whose URL isn't http, https or mailto into its text, and marks the
// rest to open in a new tab without an opener or referrer.
type transformer struct{}

func (transformer) Transform(doc *ast.Document, reader text.Reader, _ parser.Context) {
	src := reader.Source()
	var unwrap []ast.Node
	var plain []*ast.AutoLink
	_ = ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch v := n.(type) {
		case *ast.Image:
			unwrap = append(unwrap, v)
		case *ast.Link:
			if !allowedURL(string(v.Destination)) {
				unwrap = append(unwrap, v)
				return ast.WalkContinue, nil
			}
			v.SetAttributeString("target", "_blank")
			v.SetAttributeString("rel", LinkRel)
		case *ast.AutoLink:
			u := string(v.URL(src))
			if v.AutoLinkType == ast.AutoLinkEmail && !strings.HasPrefix(strings.ToLower(u), "mailto:") {
				u = "mailto:" + u
			}
			if !allowedURL(u) {
				plain = append(plain, v)
				return ast.WalkContinue, nil
			}
			v.SetAttributeString("target", "_blank")
			v.SetAttributeString("rel", LinkRel)
		}
		return ast.WalkContinue, nil
	})
	for _, n := range unwrap {
		parent := n.Parent()
		for c := n.FirstChild(); c != nil; {
			next := c.NextSibling()
			parent.InsertBefore(parent, n, c)
			c = next
		}
		parent.RemoveChild(parent, n)
	}
	for _, n := range plain {
		parent := n.Parent()
		parent.ReplaceChild(parent, n, ast.NewString(append([]byte(nil), n.Label(src)...)))
	}
}

// allowedURL: an absolute http or https URL with a host, or a mailto one.
func allowedURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	if u.User != nil {
		return false // https://bank.example@evil.example
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return u.Host != ""
	case "mailto":
		return u.Opaque != ""
	}
	return false
}

// MaxBytes caps auth.notes (contract §3): the largest template's notes
// are about 6 KB.
const MaxBytes = 16 << 10

// MaxDepth caps the block nesting depth of auth.notes (block quotes and
// list items inside each other, contract §3).
const MaxDepth = 16

// Check refuses notes over MaxBytes or nested deeper than MaxDepth: the
// size first, then a line scan of the leading container markers (> - * +
// and 1. / 1)), then, on what is left (bounded), the parsed document's
// nesting (which also catches nesting by indentation).
func Check(notes string) error {
	if len(notes) > MaxBytes {
		return fmt.Errorf("auth.notes is %d bytes, at most %d allowed", len(notes), MaxBytes)
	}
	for _, line := range strings.Split(notes, "\n") {
		if markerDepth(line) > MaxDepth {
			return fmt.Errorf("auth.notes nests blocks deeper than %d", MaxDepth)
		}
	}
	src := []byte(notes)
	if d := blockDepth(md.Parser().Parse(text.NewReader(src)), 0); d > MaxDepth {
		return fmt.Errorf("auth.notes nests blocks deeper than %d", MaxDepth)
	}
	return nil
}

// markerDepth counts the block quote and list markers a line opens with.
func markerDepth(line string) int {
	d := 0
	s := line
	for {
		s = strings.TrimLeft(s, " \t")
		switch {
		case strings.HasPrefix(s, ">"):
			s = s[1:]
		case len(s) >= 2 && strings.ContainsRune("-*+", rune(s[0])) && (s[1] == ' ' || s[1] == '\t'):
			s = s[2:]
		default:
			k := 0
			for k < len(s) && k < 9 && s[k] >= '0' && s[k] <= '9' {
				k++
			}
			if k == 0 || k+1 >= len(s) || (s[k] != '.' && s[k] != ')') || (s[k+1] != ' ' && s[k+1] != '\t') {
				return d
			}
			s = s[k+2:]
		}
		d++
		if d > MaxDepth {
			return d
		}
	}
}

// blockDepth is the deepest nesting of block quotes and list items under n.
func blockDepth(n ast.Node, here int) int {
	if n.Kind() == ast.KindBlockquote || n.Kind() == ast.KindListItem {
		here++
	}
	max := here
	for c := n.FirstChild(); c != nil && max <= MaxDepth; c = c.NextSibling() {
		if c.Type() != ast.TypeBlock && c.Type() != ast.TypeDocument {
			continue
		}
		if d := blockDepth(c, here); d > max {
			max = d
		}
	}
	return max
}

// Rendered is a template's notes rendered once (templates.build): the
// whole notes and the first paragraph, as sanitised HTML and as text.
type Rendered struct {
	HTML      string // the whole notes ("" for blank notes)
	FirstHTML string // the first top-level paragraph ("" if none)
	FirstText string // its plain text (Text)
}

// Render parses notes (which must pass Check) once and renders them.
func Render(notes string) Rendered {
	if strings.TrimSpace(notes) == "" {
		return Rendered{}
	}
	src := []byte(notes)
	doc := md.Parser().Parse(text.NewReader(src))
	r := Rendered{HTML: render(src, doc)}
	var para ast.Node
	for c := doc.FirstChild(); c != nil; c = c.NextSibling() {
		if c.Kind() == ast.KindParagraph {
			para = c
			break
		}
	}
	if para == nil {
		return r
	}
	// Render the paragraph alone: a document holding only it.
	one := ast.NewDocument()
	doc.RemoveChild(doc, para)
	one.AppendChild(one, para)
	r.FirstHTML = render(src, one)
	r.FirstText = Text(r.FirstHTML)
	return r
}

// HTML renders Markdown notes to sanitised HTML ("" for blank notes).
func HTML(notes string) string { return Render(notes).HTML }

func render(src []byte, n ast.Node) string {
	var buf bytes.Buffer
	if err := md.Renderer().Render(&buf, src, n); err != nil {
		return ""
	}
	return strings.TrimSpace(sanitizer().Sanitize(buf.String()))
}

// FirstParagraph is the notes' first Markdown paragraph (the document's
// first top-level paragraph block), rendered like HTML, and its plain
// text: the rendered paragraph's text with whitespace runs collapsed to
// one space. Both are "" when the notes have no paragraph.
func FirstParagraph(notes string) (htmlOut, plain string) {
	r := Render(notes)
	return r.FirstHTML, r.FirstText
}

// textOnly strips every tag (the rendered HTML's text, still escaped).
var textOnly = bluemonday.StrictPolicy()

// Text is sanitised HTML's text content: tags removed, entities decoded,
// whitespace collapsed. For plain-text consumers, which escape it again.
func Text(h string) string {
	return strings.Join(strings.Fields(html.UnescapeString(textOnly.Sanitize(h))), " ")
}
