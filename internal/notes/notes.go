// Package notes renders a template's auth.notes (contract §3) from
// Markdown to sanitised HTML, server-side, for the Hub UI and the portal.
//
// Two layers, each safe on its own:
//
//   - goldmark parses CommonMark plus the GFM table and autolink
//     extensions. Raw HTML is never passed through (no html.WithUnsafe):
//     an HTML block or inline tag becomes an "omitted" comment, and
//     dangerous URLs (javascript:, vbscript:, file:, most data:) get an
//     empty href. Images are turned into their alt text before rendering.
//     Every link gets target="_blank" and rel="noopener noreferrer
//     nofollow".
//   - bluemonday then keeps only the elements and attributes that
//     subset can produce, links with an http, https or mailto URL and no
//     image at all; anything else is dropped (its text kept, escaped).
package notes

import (
	"bytes"
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
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return u.Host != ""
	case "mailto":
		return u.Opaque != ""
	}
	return false
}

// HTML renders Markdown notes to sanitised HTML ("" for blank notes).
func HTML(notes string) string {
	if strings.TrimSpace(notes) == "" {
		return ""
	}
	src := []byte(notes)
	return render(src, md.Parser().Parse(text.NewReader(src)))
}

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
	src := []byte(notes)
	doc := md.Parser().Parse(text.NewReader(src))
	var para ast.Node
	for c := doc.FirstChild(); c != nil; c = c.NextSibling() {
		if c.Kind() == ast.KindParagraph {
			para = c
			break
		}
	}
	if para == nil {
		return "", ""
	}
	// Render the paragraph alone: a document holding only it.
	one := ast.NewDocument()
	doc.RemoveChild(doc, para)
	one.AppendChild(one, para)
	htmlOut = render(src, one)
	return htmlOut, Text(htmlOut)
}

// textOnly strips every tag (the rendered HTML's text, still escaped).
var textOnly = bluemonday.StrictPolicy()

// Text is sanitised HTML's text content: tags removed, entities decoded,
// whitespace collapsed. For plain-text consumers, which escape it again.
func Text(h string) string {
	return strings.Join(strings.Fields(html.UnescapeString(textOnly.Sanitize(h))), " ")
}
