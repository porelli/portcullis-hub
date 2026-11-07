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
		// Rotation is pinned off (contract §8): the note says so exactly.
		`After that the person signs in again in their AI assistant. Access tokens last 5 minutes; refresh tokens don\'t rotate (Keycloak can\'t do it per client), so Disconnect and the limits above are what end a connection.`,
		// aiLink only links an https:// URL (an alternative's or a
		// companion's source); anything else is shown as code.
		"return /^https:\\/\\/[^\\s\"'<>]+$/.test(String(url || ''))",
		// No revoke row for identity_headers (nothing to revoke); app_oauth
		// has its own note.
		`if (c.identity_mode !== 'identity_headers') {`,
		`Revoking ends their AI access through the app\'s own sign-in; they sign in again in the app.`,
		// One decision rendering, shared with the audit view (directory.js).
		`PortcullisAI.decision(d, 'pill')`,
		`aria-label="Close"`,
	} {
		if !strings.Contains(ai, want) {
			t.Errorf("the AI block lacks %q", want)
		}
	}
	// "rotate" only ever in "don't rotate".
	if n, ok := strings.Count(ai, "rotate"), strings.Count(ai, `don\'t rotate`); n != ok || n == 0 {
		t.Errorf("the AI block says %q %d times, %d of them as \"don't rotate\"", "rotate", n, ok)
	}
	if !strings.Contains(webAsset(t, "directory.js"), "window.PortcullisAI = { decision: aiDecision };") {
		t.Error("directory.js doesn't export PortcullisAI.decision")
	}
	if regexp.MustCompile(`(?i)\son[a-z]+\s*=`).MatchString(ai) {
		t.Error("the AI block generates inline event handlers")
	}
	// A secret input never gets a value attribute.
	if regexp.MustCompile(`type="password"[^>]*value=`).MatchString(ai) {
		t.Error("a password input is rendered with a value")
	}
}
