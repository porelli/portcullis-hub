package httpapi

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestWebAvailabilityTab: web/availability.js escapes every value of the
// Hub (node names, sites, pod names, the 409's sentence), builds the
// PUT's body from the draft, and is wired into the page (Kubernetes
// only) and the setup form (priority only).
func TestWebAvailabilityTab(t *testing.T) {
	out := nodeEval(t, `
global.window = {};
`+webAsset(t, "availability.js")+`
const A = window.PortcullisAvailability;
const v = { priority: 'high', runs_on: { mode: 'only', nodes: ['<b>n1</b>'] },
  nodes: [{ name: '<b>n1</b>', class: '<i>home</i>', site: '<s>main</s>', small: false }, { name: 'pi', class: 'small', site: 'main', small: true }],
  n_minus_1: [{ node: '<b>n1</b>', level: 'red', unplaced: ['<u>vault-0</u>'], evicted: [] }, { node: 'pi', level: '<x>', unplaced: [], evicted: [] }] };
const d = A.draftOf(v);
const html = A.tabHtml(v, d);
const prefer = A.tabHtml(v, Object.assign(A.draftOf(v), { mode: 'prefer', prefer: 'nodes' }));
const bodies = [
  A.bodyOf(d),
  A.bodyOf(Object.assign(A.draftOf(v), { mode: 'anywhere' })),
  A.bodyOf(Object.assign(A.draftOf(v), { mode: 'prefer', prefer: 'class', cls: 'cloud' }), true),
  A.bodyOf(Object.assign(A.draftOf(v), { mode: 'prefer', prefer: 'nodes', nodes: ['b', 'a'] })),
];
process.stdout.write(JSON.stringify({ html, prefer, bodies }));
`)
	var got struct {
		HTML, Prefer string
		Bodies       []json.RawMessage
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	for _, bad := range []string{"<b>", "<i>", "<s>", "<u>", "<x>"} {
		if strings.Contains(got.HTML, bad) {
			t.Errorf("unescaped %s in %s", bad, got.HTML)
		}
	}
	for _, want := range []string{"&lt;b&gt;n1&lt;/b&gt;", "&lt;u&gt;vault-0&lt;/u&gt;", `data-n1-level="red"`, `data-n1-level="unknown"`, `value="high" selected`, `value="only" data-avail-mode checked`} {
		if !strings.Contains(got.HTML, want) {
			t.Errorf("tab lacks %s", want)
		}
	}
	// Prefer never offers a small node.
	if !strings.Contains(got.Prefer, `value="pi" disabled`) {
		t.Errorf("prefer offers the small node: %s", got.Prefer)
	}
	want := []string{
		`{"priority":"high","runs_on":{"mode":"only","nodes":["<b>n1</b>"]}}`,
		`{"priority":"high","runs_on":{"mode":"anywhere"}}`,
		`{"priority":"high","runs_on":{"mode":"prefer","class":"cloud"},"confirm_n_minus_1":true}`,
		`{"priority":"high","runs_on":{"mode":"prefer","nodes":["a","b"]}}`,
	}
	for i, w := range want {
		if string(got.Bodies[i]) != w {
			t.Errorf("body %d = %s, want %s", i, got.Bodies[i], w)
		}
	}
	idx := webAsset(t, "index.html")
	for _, w := range []string{"['availability', 'Availability']", "runtimeIsKube()", "/static/availability.js", "data-setup-priority", "PortcullisAvailability.setPriority(id, v.priority)"} {
		if !strings.Contains(idx, w) {
			t.Errorf("index.html lacks %q", w)
		}
	}
}
