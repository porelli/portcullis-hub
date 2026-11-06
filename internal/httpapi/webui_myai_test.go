package httpapi

import (
	"encoding/json"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// Plan 4 Task 21 (fix round 1): the "Connect your AI" card's rules a
// browser check can't prove for every path. cardHtml runs under node
// (skipped when node isn't installed; GitHub's runners have it).

// myAICard renders myai.js's cardHtml(view) under node.
func myAICard(t *testing.T, view any) string {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	v, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	script := "global.window = {};\n" + webAsset(t, "myai.js") +
		"\nprocess.stdout.write(window.PortcullisMyAI.cardHtml(" + string(v) + "));\n"
	cmd := exec.Command(node, "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("node: %v", err)
	}
	return string(out)
}

func comp(name, label, mode, identity string, aggregate bool) map[string]any {
	return map[string]any{"name": name, "label": label, "url": "https://x.example.org/" + name, "identity_mode": identity,
		"mode": mode, "official": true, "aggregate": aggregate}
}

var myAITop = map[string]any{"aggregate_url": "https://mcp.example.org/mcp", "clients": map[string]any{
	"claude":      map[string]any{"client_id": "portcullis-ai-claude", "admin": false},
	"claude_code": map[string]any{"client_id": "portcullis-ai-claude-code", "callback_port": 33418, "admin": false},
	"generic":     map[string]any{"client_id": "portcullis-ai-generic", "redirect_uris": []string{"http://localhost:33418/callback"}, "admin": false},
}}

// TestMyAICardCovers: "Covers …" names only apps with an aggregate: true
// companion; aggregate: false and app_oauth companions are "connected
// separately"; labels are escaped.
func TestMyAICardCovers(t *testing.T) {
	h := myAICard(t, map[string]any{"ai": myAITop, "apps": []any{
		map[string]any{"id": "aiapp", "name": "AI App", "ai": map[string]any{"companions": []any{
			comp("tok", "Tokens", "read_write", "app_token", true),
			comp("wiki", "Wiki <b>", "read_only", "identity_headers", false),
		}}},
		map[string]any{"id": "homeauto", "name": "Home Assistant", "ai": map[string]any{"companions": []any{
			comp("oauth", "Home Assistant", "read_write", "app_oauth", false),
		}}},
		map[string]any{"id": "notes", "name": "Notes", "ai": map[string]any{"companions": []any{
			comp("n", "Notes", "read_only", "identity_headers", false),
		}}},
	}})
	if !strings.Contains(h, "Covers AI App (and anything added later). Wiki &lt;b&gt;, Home Assistant and Notes are connected separately (below).") {
		t.Errorf("covers line wrong:\n%s", h)
	}
	if strings.Contains(h, "Wiki <b>") {
		t.Error("a label reached the markup unescaped")
	}
	// The Claude line of an app_oauth companion appears once (on its row,
	// not again in its Steps).
	if n := strings.Count(h, "Use Claude&#39;s published identity") + strings.Count(h, "Use Claude's published identity"); n != 1 {
		t.Errorf("published-identity line %d times, want 1", n)
	}
}

// TestMyAICardServerNames: Claude Code server names are unique in a card
// (-<instance id> on a clash, never portcullis-apps for an app).
func TestMyAICardServerNames(t *testing.T) {
	h := myAICard(t, map[string]any{"ai": myAITop, "apps": []any{
		map[string]any{"id": "gitea", "name": "Gitea", "ai": map[string]any{"companions": []any{comp("gitea", "Gitea", "read_write", "app_token", true)}}},
		map[string]any{"id": "gitea-b", "name": "Gitea B", "ai": map[string]any{"companions": []any{comp("gitea", "Gitea", "read_write", "app_token", true)}}},
		map[string]any{"id": "grafana", "name": "Grafana", "ai": map[string]any{"companions": []any{comp("graf", "Grafana", "read_only", "app_token", true)}}},
		map[string]any{"id": "pa", "name": "PA", "ai": map[string]any{"companions": []any{comp("pa", "Portcullis Apps", "read_only", "app_token", true)}}},
	}})
	// Each command once, in its copy button (the <code> shows it again).
	re := regexp.MustCompile(`data-mai-copy="claude mcp add [^"]*--callback-port 33418 ([a-z0-9-]+) https://`)
	seen := map[string]int{}
	for _, m := range re.FindAllStringSubmatch(h, -1) {
		seen[m[1]]++
	}
	want := map[string]int{"portcullis-apps": 1, "gitea-gitea": 1, "gitea-gitea-b": 1, "grafana": 1, "portcullis-apps-pa": 1}
	if len(seen) != len(want) {
		t.Errorf("server names = %v, want %v", seen, want)
	}
	for n, c := range want {
		if seen[n] != c {
			t.Errorf("server name %s used %d times, want %d (all: %v)", n, seen[n], c, seen)
		}
	}
	if !strings.Contains(h, "claude mcp add --transport http --scope user --client-id portcullis-ai-claude-code --callback-port 33418 portcullis-apps https://mcp.example.org/mcp") {
		t.Error("the aggregate's command is not the mandated one")
	}
}

// TestMyAICardTabs: every tab names its panel (aria-controls = the
// panel's id, the panel labelled by the tab), ids are unique, one tab
// per set is in the tab order; the arrow keys are handled.
func TestMyAICardTabs(t *testing.T) {
	h := myAICard(t, map[string]any{"ai": myAITop, "apps": []any{
		map[string]any{"id": "aiapp", "name": "AI App", "ai": map[string]any{"companions": []any{comp("tok", "Tokens", "read_write", "app_token", true)}}},
	}})
	tabs := regexp.MustCompile(`role="tab" id="([^"]+)" aria-controls="([^"]+)"`).FindAllStringSubmatch(h, -1)
	if len(tabs) != 6 {
		t.Fatalf("%d tabs, want 6 (two sets of three)", len(tabs))
	}
	ids := map[string]bool{}
	for _, m := range tabs {
		if ids[m[1]] {
			t.Errorf("tab id %s twice", m[1])
		}
		ids[m[1]] = true
		if !strings.Contains(h, `role="tabpanel" id="`+m[2]+`" aria-labelledby="`+m[1]+`"`) {
			t.Errorf("tab %s: no panel %s labelled by it", m[1], m[2])
		}
	}
	if n := strings.Count(h, `tabindex="0" data-mai-tab=`); n != 2 {
		t.Errorf("%d tabs in the tab order, want one per set", n)
	}
	js := webAsset(t, "myai.js")
	for _, want := range []string{"case 'ArrowRight':", "case 'ArrowLeft':", "selectTab(tabs[j], true)"} {
		if !strings.Contains(js, want) {
			t.Errorf("myai.js lacks %q", want)
		}
	}
	if regexp.MustCompile(`\son[a-z]+=`).MatchString(js) {
		t.Error("myai.js generates inline event handlers")
	}
}
