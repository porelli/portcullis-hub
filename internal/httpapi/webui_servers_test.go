package httpapi

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// serversJS runs servers.js under node with body (after it).
func serversJS(t *testing.T, body string) string {
	t.Helper()
	return nodeEval(t, "global.window = {};\n"+webAsset(t, "servers.js")+"\n"+body)
}

// TestServersPanel: the list escapes names, shows the worker actions
// (never on the primary) and the add form; no code anywhere.
func TestServersPanel(t *testing.T) {
	page := map[string]any{"servers": []any{
		map[string]any{"id": "primary", "name": "Primary", "state": "ready", "instances": []string{"a"}},
		map[string]any{"id": "nas", "name": "NAS <b>", "state": "enrolling", "runtime": "docker", "arch": "arm64", "cpus": 4, "mem_bytes": 8e9,
			"disk_total": 1e12, "disk_free": 5e11, "instances": []string{}},
	}}
	b, _ := json.Marshal(page)
	h := serversJS(t, "process.stdout.write(window.PortcullisServers.listHtml("+string(b)+"));")
	for _, want := range []string{`data-server="nas"`, "NAS &lt;b&gt;", `data-srv-act="stop-enrol"`, `data-srv-act="revoke"`, `data-srv-act="remove"`, `data-srv-act="add"`, "./portcullis worker join", "500.0 GB of 1.0 TB"} {
		if !strings.Contains(h, want) {
			t.Errorf("panel lacks %q:\n%s", want, h)
		}
	}
	if strings.Contains(h, "NAS <b>") || strings.Count(h, `data-srv-act="revoke"`) != 1 {
		t.Errorf("unescaped, or a primary revoke:\n%s", h)
	}
}

// TestJoinCodeDialogForgets: the code shows only in its dialog; Copy
// copies it; Close empties and removes the dialog; nothing is stored;
// servers.js never touches localStorage or sessionStorage.
func TestJoinCodeDialogForgets(t *testing.T) {
	src := webAsset(t, "servers.js")
	if strings.Contains(src, "localStorage") || strings.Contains(src, "sessionStorage") {
		t.Fatal("servers.js uses web storage")
	}
	script := `
let stored = 0;
global.localStorage = global.sessionStorage = { setItem() { stored++; }, getItem() { return null; } };
function el(tag) {
  const e = { tag, attrs: {}, children: [], innerHTML: '', listeners: {}, parent: null, open: false,
    setAttribute(k, v) { this.attrs[k] = v; }, getAttribute(k) { return this.attrs[k]; },
    addEventListener(n, f) { (this.listeners[n] = this.listeners[n] || []).push(f); },
    appendChild(c) { c.parent = this; this.children.push(c); },
    remove() { if (this.parent) { this.parent.children = this.parent.children.filter(x => x !== this); this.parent = null; } },
    showModal() { this.open = true; }, close() { this.open = false; } };
  return e;
}
const doc = { body: el('body'), createElement: el };
let copied = '';
const clip = { writeText(s) { copied = s; return Promise.resolve(); } };
const CODE = 'pcj1.SECRET-JOIN-CODE';
window.PortcullisServers.openCodeDialog(doc, CODE, '2026-11-16T10:15:00Z', clip);
const d = doc.body.children[0];
const shown = d.innerHTML.includes(CODE) && d.open;
const cmd = d.innerHTML.includes('./portcullis worker join');
const btn = act => ({ getAttribute: k => k === 'data-srv-code-act' ? act : null });
d.listeners.click.forEach(f => f({ target: btn('copy') }));
setTimeout(() => {
  d.listeners.click.forEach(f => f({ target: btn('close') }));
  process.stdout.write(JSON.stringify({ shown, copied: copied === CODE, children: doc.body.children.length, html: d.innerHTML, open: d.open, stored,
    cmd }));
}, 0);
`
	var got struct {
		Shown, Copied, Open, Cmd bool
		Children, Stored         int
		HTML                     string
	}
	if err := json.Unmarshal([]byte(serversJS(t, script)), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Shown || !got.Copied || !got.Cmd {
		t.Errorf("dialog %+v", got)
	}
	if got.Children != 0 || got.HTML != "" || got.Open || got.Stored != 0 {
		t.Errorf("after close %+v: the code is still in the page or stored", got)
	}
}

// TestInstanceServerSection: Runs on, Move… with the other servers, the
// undo banner within 7 days only (the old copy's removal always).
func TestInstanceServerSection(t *testing.T) {
	recent := time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339)
	old := time.Now().Add(-8 * 24 * time.Hour).UTC().Format(time.RFC3339)
	run := func(inst map[string]any) string {
		b, _ := json.Marshal(inst)
		return serversJS(t, `
window.apiGet = async () => ({ servers: [{ id: 'primary', name: 'Primary', state: 'ready' }, { id: 'nas', name: 'NAS', state: 'ready' }] });
window.PortcullisServers.load().then(() => {
  const i = `+string(b)+`;
  process.stdout.write(window.PortcullisServers.runsOn(i) + '\n' + window.PortcullisServers.instanceSection(i));
});`)
	}
	h := run(map[string]any{"id": "notes", "server": "nas", "state": "enabled", "moved_from": map[string]any{"server": "", "at": recent}})
	for _, want := range []string{"<dt>Runs on</dt>", "NAS <code>nas</code>", `data-srv-iact="undo"`, `data-srv-iact="leftover"`, `data-srv-iact="move"`, `<option value="">Primary</option>`, `data-srv-iact="lift"`} {
		if !strings.Contains(h, want) {
			t.Errorf("section lacks %q:\n%s", want, h)
		}
	}
	h = run(map[string]any{"id": "notes", "server": "", "state": "enabled", "moved_from": map[string]any{"server": "nas", "at": old}})
	if strings.Contains(h, `data-srv-iact="undo"`) || !strings.Contains(h, "7 days to undo it are over") || strings.Contains(h, `data-srv-iact="lift"`) || !strings.Contains(h, `<option value="nas">NAS</option>`) {
		t.Errorf("after 7 days / on the primary:\n%s", h)
	}
}
