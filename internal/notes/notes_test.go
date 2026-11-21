package notes

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// inert fails when h holds anything that could run script or load
// content: a script/style/iframe/object/embed/img/svg/form element, an
// on* attribute, a style attribute, or a link that isn't http(s)/mailto.
func inert(t *testing.T, in, h string) {
	t.Helper()
	low := strings.ToLower(h)
	for _, bad := range []string{"<script", "<style", "<iframe", "<object", "<embed", "<img", "<svg", "<math", "<form", "<input", "<link", "<meta", "<base", "<!--", "style="} {
		if strings.Contains(low, bad) {
			t.Errorf("%q rendered %q: contains %s", in, h, bad)
		}
	}
	if regexp.MustCompile(`<[^>]*\son[a-z]+\s*=`).MatchString(low) {
		t.Errorf("%q rendered %q: an event attribute", in, h)
	}
	for _, m := range regexp.MustCompile(`href="([^"]*)"`).FindAllStringSubmatch(h, -1) {
		if !regexp.MustCompile(`^(https?://[^/\s]|mailto:)`).MatchString(m[1]) {
			t.Errorf("%q rendered %q: href %q", in, h, m[1])
		}
	}
	for _, a := range regexp.MustCompile(`<a\b[^>]*>`).FindAllString(h, -1) {
		if !strings.Contains(a, `href="`) || !strings.Contains(a, `target="_blank"`) || !strings.Contains(a, `rel="`+LinkRel+`"`) {
			t.Errorf("%q rendered %q: link %s lacks href, target or rel", in, h, a)
		}
	}
}

func TestXSSVectorsInert(t *testing.T) {
	vectors := []string{
		"<script>alert(1)</script>",
		"text <script>alert(1)</script> more",
		"<SCRIPT SRC=//x.example/x.js></SCRIPT>",
		"<img src=x onerror=alert(1)>",
		"<svg onload=alert(1)>",
		"<iframe src=\"javascript:alert(1)\"></iframe>",
		"<a href=\"https://x.example\" onclick=\"alert(1)\">x</a>",
		"<div style=\"background:url(javascript:alert(1))\">x</div>",
		"<!-- comment --><b>bold</b>",
		"[a](javascript:alert(1))",
		"[a](JaVaScRiPt:alert(1))",
		"[a]( javascript:alert(1) )",
		"[a](&#106;avascript:alert(1))",
		"[a](java&#09;script:alert(1))",
		"[a](javascript&colon;alert(1))",
		"[a](vbscript:msgbox(1))",
		"[a](data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==)",
		"[a](data:image/png;base64,iVBORw0KGgo=)",
		"[a](file:///etc/passwd)",
		"[a](//evil.example/x)",
		"[a](/relative)",
		"[a](https://ok.example/\"onmouseover=\"alert(1))",
		"[a](https://ok.example/ \"title\" onmouseover=alert(1))",
		"<javascript:alert(1)>",
		"<data:text/html,<script>alert(1)</script>>",
		"[ref]\n\n[ref]: javascript:alert(1)",
		"![x](javascript:alert(1))",
		"![x](https://tracker.example/pixel.gif)",
		"![x](data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=)",
		"[![x](https://i.example/i.png)](https://ok.example)",
		"&lt;script&gt;alert(1)&lt;/script&gt;",
		"&#60;script&#62;alert(1)&#60;/script&#62;",
		"`<script>alert(1)</script>`",
		"```html\n<script>alert(1)</script>\n```",
		"    <script>alert(1)</script>",
		"**<script>alert(1)</script>**",
		"[<img src=x onerror=alert(1)>](https://ok.example)",
		"[x](https://ok.example)<img src=x onerror=alert(1)>",
		"<a href=\"javascript:alert(1)\">[x](https://ok.example)</a>",
		"> <script>alert(1)</script>",
		"- <img src=x onerror=alert(1)>\n- [x](javascript:alert(1))",
		"| a |\n|---|\n| <script>alert(1)</script> |",
		"| a |\n|---|\n| [x](javascript:alert(1)) |",
		"<details open ontoggle=alert(1)>",
		"<math><mi xlink:href=\"javascript:alert(1)\">x</mi></math>",
		"www.example.com/\"onmouseover=\"alert(1)",
		"https://ok.example/<script>alert(1)</script>",
		"x@y.example\"onmouseover=\"alert(1)",
		"<<script>script>alert(1)<</script>/script>",
		"\x00<script>alert(1)</script>",
		"[a](https://ok.example){onclick=alert(1)}",
		"# T {onclick=alert(1)}",
	}
	for _, v := range vectors {
		h := HTML(v)
		inert(t, v, h)
		fh, _ := FirstParagraph(v)
		inert(t, v, fh)
	}
}

func TestEscapedTextStaysText(t *testing.T) {
	for in, want := range map[string]string{
		"&lt;script&gt;":                  "<p>&lt;script&gt;</p>",
		"<script>alert(1)</script>\n\nok": "<p>ok</p>",
		"`<b>`":                           "<p><code>&lt;b&gt;</code></p>",
		"a <b>bold</b> c":                 "<p>a bold c</p>",
		"[a](javascript:alert(1))":        "<p>a</p>",
		"![alt *t*](https://i.example/x)": "<p>alt <em>t</em></p>",
		"<javascript:alert(1)>":           "<p>javascript:alert(1)</p>",
	} {
		if got := HTML(in); got != want {
			t.Errorf("HTML(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLinks(t *testing.T) {
	const a = ` target="_blank" rel="noopener noreferrer nofollow"`
	for in, want := range map[string]string{
		"[x](https://a.example/p?q=1&r=2)": `<p><a href="https://a.example/p?q=1&amp;r=2"` + a + `>x</a></p>`,
		"<https://b.example>":              `<p><a href="https://b.example"` + a + `>https://b.example</a></p>`,
		"see www.c.example":                `<p>see <a href="http://www.c.example"` + a + `>www.c.example</a></p>`,
		"mail me@d.example":                `<p>mail <a href="mailto:me@d.example"` + a + `>me@d.example</a></p>`,
		"[m](mailto:x@y.example)":          `<p><a href="mailto:x@y.example"` + a + `>m</a></p>`,
		"[h](HTTP://E.EXAMPLE)":            `<p><a href="http://E.EXAMPLE"` + a + `>h</a></p>`,
	} {
		if got := HTML(in); got != want {
			t.Errorf("HTML(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSubset(t *testing.T) {
	in := "# Head\n\nA *b* **c** `d`.\nNext line.\n\n- one\n- two\n\n3. x\n\n> q\n\n---\n\n```\ncode <x>\n```\n\n| a | b |\n|:-|-:|\n| 1 | 2 |\n"
	want := "<h1>Head</h1>\n<p>A <em>b</em> <strong>c</strong> <code>d</code>.\nNext line.</p>\n<ul>\n<li>one</li>\n<li>two</li>\n</ul>\n<ol start=\"3\">\n<li>x</li>\n</ol>\n<blockquote>\n<p>q</p>\n</blockquote>\n<hr>\n<pre><code>code &lt;x&gt;\n</code></pre>\n<table>\n<thead>\n<tr>\n<th align=\"left\">a</th>\n<th align=\"right\">b</th>\n</tr>\n</thead>\n<tbody>\n<tr>\n<td align=\"left\">1</td>\n<td align=\"right\">2</td>\n</tr>\n</tbody>\n</table>"
	if got := HTML(in); got != want {
		t.Errorf("HTML subset:\n got %q\nwant %q", got, want)
	}
	if HTML("  \n\n ") != "" {
		t.Error("blank notes must render empty")
	}
}

func TestFirstParagraph(t *testing.T) {
	for _, c := range []struct{ in, html, plain string }{
		{"First *para* & `x<y`\nline two.\n\nSecond.", "<p>First <em>para</em> &amp; <code>x&lt;y</code>\nline two.</p>", "First para & x<y line two."},
		{"# Title\n\nSummary [link](https://a.example).\n\nMore.", `<p>Summary <a href="https://a.example" target="_blank" rel="noopener noreferrer nofollow">link</a>.</p>`, "Summary link."},
		{"- a list only", "", ""},
		{"", "", ""},
		{"<script>alert(1)</script>\n\nReal one.", "<p>Real one.</p>", "Real one."},
		{"&lt;b&gt; text", "<p>&lt;b&gt; text</p>", "<b> text"},
	} {
		h, p := FirstParagraph(c.in)
		if h != c.html || p != c.plain {
			t.Errorf("FirstParagraph(%q) = %q, %q; want %q, %q", c.in, h, p, c.html, c.plain)
		}
	}
}

// TestGoldenTemplate renders a real template's notes (testdata copy of
// portcullis-templates' stalwart auth.notes) against a reviewed golden
// file. Regenerate with UPDATE_GOLDEN=1 and review the diff.
func TestGoldenTemplate(t *testing.T) {
	raw, err := os.ReadFile("testdata/stalwart-manifest.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Auth struct {
			Notes string `yaml:"notes"`
		} `yaml:"auth"`
	}
	if err := yaml.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	got := HTML(m.Auth.Notes) + "\n"
	inert(t, "stalwart", got)
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile("testdata/stalwart-notes.golden.html", []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile("testdata/stalwart-notes.golden.html")
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("stalwart notes render changed:\n got %s\nwant %s", got, want)
	}
	if _, p := FirstParagraph(m.Auth.Notes); p == "" || len([]rune(p)) > 300 {
		t.Errorf("stalwart's first paragraph %q: want 1–300 runes", p)
	}
}

// I1: rendering is superlinear in the nesting depth, so Check bounds the
// size and the depth, and refuses pathological input fast.
func TestCheckRefusesFast(t *testing.T) {
	for name, in := range map[string]string{
		"120 KB nested list markers":  strings.Repeat("- ", 60000) + "x",
		"120 KB nested quotes":        strings.Repeat(">", 120000) + " x",
		"120 KB indented nested list": nestedIndented(400),
		"16 KB nested list markers":   strings.Repeat("- ", 8000) + "x",
		"16 KB nested quotes":         strings.Repeat(">", 16000) + " x",
		"17 levels by markers":        strings.Repeat("- ", MaxDepth+1) + "x",
		"17 levels mixed":             strings.Repeat("> - ", 9) + "x",
		"17 levels by indentation":    nestedIndented(MaxDepth + 1),
		"over 16 KiB of prose":        strings.Repeat("word ", MaxBytes/5+1),
	} {
		start := time.Now()
		err := Check(in)
		if took := time.Since(start); took > 250*time.Millisecond {
			t.Errorf("%s: Check took %v", name, took)
		}
		if err == nil {
			t.Errorf("%s (%d bytes): Check passed", name, len(in))
		}
	}
	for name, in := range map[string]string{
		"16 levels by markers":     strings.Repeat("- ", MaxDepth) + "x",
		"16 levels by indentation": nestedIndented(MaxDepth),
		"exactly 16 KiB":           strings.Repeat("x", MaxBytes),
		"thematic break":           "---\n\n***",
	} {
		if err := Check(in); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// nestedIndented is a list nested n levels deep by indentation alone.
func nestedIndented(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString(strings.Repeat("  ", i) + "- x\n")
	}
	return b.String()
}

// M3: a link with userinfo is a phishing shape: it stays text.
func TestUserinfoLinksAreText(t *testing.T) {
	for _, in := range []string{
		"[x](https://bank.example@evil.example/)",
		"[x](https://user:pw@evil.example/)",
		"<https://bank.example@evil.example/>",
	} {
		if h := HTML(in); strings.Contains(h, "<a") {
			t.Errorf("HTML(%q) = %q: a link", in, h)
		}
	}
}
