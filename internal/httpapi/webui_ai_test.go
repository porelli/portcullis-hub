package httpapi

import (
	"regexp"
	"strings"
	"testing"
)

// TestAdminAIUIStatic (Task 22): the admin AI UI in index.html keeps
// its rules — provider secrets only in type=password inputs, never
// pre-filled; the spec's exact texts (call 28's reachability note, the
// data-egress note, "This core has no mcp-gate", "not vetted by
// Portcullis"); a litellm provider's base_url is never posted back
// (T9); window.openAppTab exists (the doctor's "Open AI tab", T20); and
// no inline event handler anywhere in the AI block.
func TestAdminAIUIStatic(t *testing.T) {
	html := webAsset(t, "index.html")
	start := strings.Index(html, "// ── Settings → AI (contract §15.11–15.12, plan 4 Task 22) ──")
	end := strings.Index(html, "window.openAppTab = openAppTab;")
	if start < 0 || end < start {
		t.Fatal("the AI block isn't in index.html")
	}
	ai := html[start:end]
	for _, want := range []string{
		`'<input type="password" id="ai-sec-' + f + '" data-ai-secret="' + f + '" autocomplete="new-password" spellcheck="false">'`,
		`Claude desktop and claude.ai connect from Anthropic\'s servers (160.79.104.0/21): <code>auth.`,
		`</code> and every app host must be reachable from the internet.`,
		`'What people send on the AI page, and what their apps return to it, goes to ' + escapeHtml(label) + '.'`,
		`This core has no mcp-gate.`,
		`not vetted by Portcullis`,
		`if (kind === 'litellm' && f === 'base_url') continue;`,
		`i.value = '';`,
	} {
		if !strings.Contains(ai, want) {
			t.Errorf("the AI block lacks %q", want)
		}
	}
	if regexp.MustCompile(`(?i)\son[a-z]+\s*=`).MatchString(ai) {
		t.Error("the AI block generates inline event handlers")
	}
	// A secret input never gets a value attribute.
	if regexp.MustCompile(`type="password"[^>]*value=`).MatchString(ai) {
		t.Error("a password input is rendered with a value")
	}
}
