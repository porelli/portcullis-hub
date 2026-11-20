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

// TestWebAvailabilityRefusal (fix I4, M1): a refused raise puts the form
// back to the saved choice and says "Not changed: still High."; Raise
// anyway resends exactly the refused body with confirm_n_minus_1, not the
// form as edited since; Cancel says "Not changed" too.
func TestWebAvailabilityRefusal(t *testing.T) {
	out := nodeEval(t, `
global.window = {};
`+webAsset(t, "availability.js")+`
const v = { priority: 'high', runs_on: { mode: 'anywhere' }, nodes: [{ name: 'n1', class: 'home', site: 'main', small: false }], n_minus_1: [] };
window.apiGet = async () => v;
const sent = [];
global.fetch = async (url, o) => {
  sent.push(JSON.parse(o.body));
  return { ok: false, status: 409, headers: { get: () => 'application/json' },
    json: async () => ({ error: 'if n1 fails, <b>x</b> won\'t have room', n_minus_1: [{ node: 'n1', level: 'red', unplaced: ['x'], evicted: [] }] }) };
};
const nodes = {};
const node = sel => nodes[sel] || (nodes[sel] = { value: '', textContent: '', className: '', innerHTML: '', hidden: true });
node('[data-avail-priority]').value = 'critical';
node('[data-avail-mode]:checked').value = 'anywhere';
let html = '';
const pane = {
  set innerHTML(h) { html = h; nodes['[data-avail-confirm]'] = { innerHTML: '', hidden: true }; },
  get innerHTML() { return html; },
  querySelector: sel => (sel === '[data-avail-prefer-kind]:checked' || sel === '[data-avail-class]' || sel === '[data-avail-site]' || sel === '[data-avail-nodes]') ? null : node(sel),
  querySelectorAll: () => [],
  contains: () => true,
};
const click = act => pane.onclick({ target: { closest: () => ({ dataset: { availAct: act } }) } });
const tick = () => new Promise(r => setTimeout(r, 10));
(async () => {
  await window.PortcullisAvailability.renderTab('grafana', pane);
  click('save'); await tick();
  const afterRefusal = { html, status: node('[data-avail-status]').textContent, box: nodes['[data-avail-confirm]'].innerHTML, hidden: nodes['[data-avail-confirm]'].hidden };
  node('[data-avail-priority]').value = 'low'; // edited while the dialog is open
  click('confirm'); await tick();
  click('cancel');
  process.stdout.write(JSON.stringify({ afterRefusal, sent, cancel: node('[data-avail-status]').textContent }));
})();
`)
	var got struct {
		AfterRefusal struct {
			HTML, Status, Box string
			Hidden            bool
		}
		Sent   []json.RawMessage
		Cancel string
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	r := got.AfterRefusal
	if !strings.Contains(r.HTML, `value="high" selected`) || strings.Contains(r.HTML, `value="critical" selected`) {
		t.Errorf("the form wasn't reset to the saved choice: %s", r.HTML)
	}
	if r.Status != "Not changed: still High." || r.Hidden || !strings.Contains(r.Box, "&lt;b&gt;x&lt;/b&gt;") || !strings.Contains(r.Box, `data-avail-act="confirm"`) {
		t.Errorf("after the refusal: %+v", r)
	}
	if len(got.Sent) != 2 || string(got.Sent[0]) != `{"priority":"critical","runs_on":{"mode":"anywhere"}}` ||
		string(got.Sent[1]) != `{"priority":"critical","runs_on":{"mode":"anywhere"},"confirm_n_minus_1":true}` {
		t.Errorf("sent %s", got.Sent)
	}
	if got.Cancel != "Not changed: still High." {
		t.Errorf("cancel: %q", got.Cancel)
	}
}

// TestWebAvailabilityDisabledNodeNotSent (fix M2): a small node left
// checked from Only, disabled under Prefer, is never read into the draft.
func TestWebAvailabilityDisabledNodeNotSent(t *testing.T) {
	out := nodeEval(t, `
global.window = {};
`+webAsset(t, "availability.js")+`
const boxes = [{ value: 'n1', checked: true, disabled: false }, { value: 'pi', checked: true, disabled: true }, { value: 'n2', checked: false, disabled: false }];
const one = { '[data-avail-priority]': { value: 'normal' }, '[data-avail-mode]:checked': { value: 'prefer' }, '[data-avail-prefer-kind]:checked': { value: 'nodes' }, '[data-avail-nodes]': {} };
const pane = {
  querySelector: sel => one[sel] || null,
  querySelectorAll: sel => boxes.filter(b => (!sel.includes(':checked') || b.checked) && (!sel.includes(':not(:disabled)') || !b.disabled)),
};
const d = window.PortcullisAvailability.readDraft(pane, { priority: 'normal', mode: 'only', prefer: 'class', cls: 'home', site: '', nodes: [] });
process.stdout.write(JSON.stringify(window.PortcullisAvailability.bodyOf(d)));
`)
	if out != `{"priority":"normal","runs_on":{"mode":"prefer","nodes":["n1"]}}` {
		t.Errorf("body = %s", out)
	}
}
