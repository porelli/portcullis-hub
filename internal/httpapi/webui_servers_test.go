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

// TestServersConfirmOpensPopupFromClick: typed confirmations are inline
// rows (no prompt or confirm dialog anywhere in servers.js); Confirm
// runs only when the typed id matches, and then opens the fresh sign-in
// popup synchronously, in the click itself, before any request; the
// proof's request carries the typed id.
func TestServersConfirmOpensPopupFromClick(t *testing.T) {
	src := webAsset(t, "servers.js")
	for _, bad := range []string{"prompt(", "confirm(", "alert("} {
		if strings.Contains(src, bad) {
			t.Errorf("servers.js calls %s", bad)
		}
	}
	out := serversJS(t, `
let started = [], calls = [];
window.PortcullisFreshAuth = { start(fa, h) { started.push(h.ctx); h.proof({ code: 'c', code_verifier: 'v', nonce: 'n' }); } };
window.showToast = () => {};
window.apiCall = async (url, method, body) => { calls.push([url, method, body]); return { json: async () => ({ op_id: 'o', op: 'move_undo' }) }; };
window.awaitOp = async () => ({});
window.apiGet = async () => ({ servers: [{ id: 'primary', name: 'Primary', state: 'ready' }, { id: 'nas', name: 'NAS', state: 'ready' }], fresh_auth: { authorize_url: 'x' } });
const S = window.PortcullisServers;
const listRoot = { dataset: { srvWired: '1' }, innerHTML: '' };
function row(action, expect, typed) {
  return { dataset: { srvConfirm: action, srvExpect: expect }, querySelector: q => q === '[data-srv-typed]' && expect ? { value: typed } : null };
}
S.load().then(() => {
  const res = {};
  const html = S.confirmHtml('revoke', 'nas', 'Revoke <b>?', 'Revoke');
  res.html = html.includes('data-srv-typed') && html.includes('data-srv-go disabled') && html.includes('Revoke &lt;b&gt;?');
  // A mismatch: nothing starts.
  res.mismatch = S.goConfirm(row('revoke', 'nas', 'na'), (a, t) => S.runListAction(listRoot, a, 'nas', t)) === false && started.length === 0;
  // A match: the popup opens in the same call (synchronously).
  const ok = S.goConfirm(row('revoke', 'nas', ' nas '), (a, t) => S.runListAction(listRoot, a, 'nas', t));
  res.sync = ok && started.length === 1;
  const inst = { id: 'notes', server: 'nas' };
  S.goConfirm(row('undo', 'notes', 'notes'), (a, t) => S.runInstanceAction({ querySelector: () => null }, inst, a, t, null, () => {}));
  res.undoSync = started.length === 2;
  S.goConfirm(row('lift', '', ''), (a, t) => S.runInstanceAction({ querySelector: () => null }, inst, a, t, null, () => {}));
  res.liftSync = started.length === 3;
  setTimeout(() => { res.calls = calls; process.stdout.write(JSON.stringify(res)); }, 10);
});`)
	var got struct {
		HTML, Mismatch, Sync, UndoSync, LiftSync bool
		Calls                                    [][]any
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if !got.HTML || !got.Mismatch || !got.Sync || !got.UndoSync || !got.LiftSync {
		t.Errorf("%+v", got)
	}
	want := map[string]string{"/api/servers/nas/revoke": "nas", "/api/instances/notes/move/undo": "notes"}
	seen := 0
	for _, c := range got.Calls {
		body, _ := c[2].(map[string]any)
		if w, ok := want[c[0].(string)]; ok {
			seen++
			if body["confirm"] != w || body["code"] != "c" {
				t.Errorf("%v: body %v", c[0], body)
			}
		}
	}
	if seen != 2 || len(got.Calls) != 3 {
		t.Errorf("calls %v", got.Calls)
	}
}

// TestOrphanedForget: an orphaned instance's section offers Forget
// (typed id, no fresh sign-in, DELETE …?forget=1), the restore-or-forget
// text, and neither Move nor the lift.
func TestOrphanedForget(t *testing.T) {
	out := serversJS(t, `
let started = 0, calls = [];
window.PortcullisFreshAuth = { start() { started++; } };
window.showToast = () => {};
window.apiCall = async (url, method, body) => { calls.push([url, method, body]); return { json: async () => ({ op_id: 'o', op: 'delete' }) }; };
window.awaitOp = async () => ({});
window.apiGet = async () => ({ servers: [{ id: 'primary', name: 'Primary', state: 'ready' }, { id: 'nas', name: 'NAS', state: 'revoked' }], fresh_auth: {} });
const S = window.PortcullisServers;
S.load().then(() => {
  const inst = { id: 'notes', server: 'nas', state: 'orphaned' };
  const html = S.instanceSection(inst);
  const row = { dataset: { srvConfirm: 'forget', srvExpect: 'notes' }, querySelector: q => q === '[data-srv-typed]' ? { value: 'notes' } : null };
  S.goConfirm(row, (a, t) => S.runInstanceAction({ querySelector: () => null }, inst, a, t, null, () => {}));
  setTimeout(() => process.stdout.write(JSON.stringify({ html, started, calls })), 10);
});`)
	var got struct {
		HTML    string
		Started int
		Calls   [][]any
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	for _, want := range []string{`data-srv-iact="forget"`, "Restore it from a backup (it lands on this server; move it afterwards) or Forget it."} {
		if !strings.Contains(got.HTML, want) {
			t.Errorf("section lacks %q:\n%s", want, got.HTML)
		}
	}
	if strings.Contains(got.HTML, `data-srv-iact="lift"`) || strings.Contains(got.HTML, `data-srv-iact="move"`) {
		t.Errorf("lift or move on an orphan:\n%s", got.HTML)
	}
	if got.Started != 0 || len(got.Calls) != 1 || got.Calls[0][0] != "/api/instances/notes?forget=1" || got.Calls[0][1] != "DELETE" {
		t.Fatalf("calls %v started %d", got.Calls, got.Started)
	}
	if body, _ := got.Calls[0][2].(map[string]any); body["confirm"] != "notes" {
		t.Errorf("body %v", got.Calls[0][2])
	}
}

// TestClusterNodeAddDialog: on Kubernetes the Add form adds a cluster
// node (role, class, site, labels; no worker command), carries the
// cluster-admin sentence, sends only the fields set; the dialog shows the
// one-liner (the code never in it), the code apart, the server sentence,
// the warnings and the progress panel; closing it forgets the code.
func TestClusterNodeAddDialog(t *testing.T) {
	page := map[string]any{"add_kind": "cluster-node", "servers": []any{
		map[string]any{"id": "primary", "name": "Primary", "state": "ready"},
		map[string]any{"id": "n2", "name": "N2", "state": "ready", "kind": "cluster-node", "role": "server", "class": "home", "site": "main", "storage": true},
		map[string]any{"id": "n3", "name": "N3", "state": "revoked", "kind": "cluster-node", "role": "server", "error": "revoked; waiting for quorum to remove its etcd member"},
	}}
	b, _ := json.Marshal(page)
	h := serversJS(t, "process.stdout.write(window.PortcullisServers.listHtml("+string(b)+"));")
	for _, want := range []string{`data-srv-kind="cluster-node"`, `data-srv-add-role`, `data-srv-add-class`, `data-srv-add-site`, `data-srv-add-storage`,
		"Joining as a server gives this machine full control of the cluster (cluster-admin).", "server · home · main · storage", `data-srv-act="remove"`, "revoked; waiting for quorum to remove its etcd member"} {
		if !strings.Contains(h, want) {
			t.Errorf("panel lacks %q:\n%s", want, h)
		}
	}
	if strings.Contains(h, "./portcullis worker join") {
		t.Errorf("a worker command on Kubernetes:\n%s", h)
	}
	d := serversJS(t, `process.stdout.write(window.PortcullisServers.detailHtml({id: 'n2', name: 'N2', kind: 'cluster-node', role: 'server', site: 'main'}));`)
	if !strings.Contains(d, "data-srv-cluster") || strings.Contains(d, "data-srv-nets") || strings.Contains(d, "data-srv-mode") {
		t.Errorf("a cluster node's settings are its name only:\n%s", d)
	}
	script := `
function el(tag) {
  const e = { tag, attrs: {}, children: [], innerHTML: '', listeners: {}, parent: null, open: false,
    setAttribute(k, v) { this.attrs[k] = v; }, getAttribute(k) { return this.attrs[k]; },
    addEventListener(n, f) { (this.listeners[n] = this.listeners[n] || []).push(f); },
    appendChild(c) { c.parent = this; this.children.push(c); },
    querySelector(q) { return q === '[data-srv-progress]' ? this.progress : null },
    remove() { if (this.parent) { this.parent.children = this.parent.children.filter(x => x !== this); this.parent = null; } },
    showModal() { this.open = true; }, close() { this.open = false; } };
  e.progress = { innerHTML: '' };
  return e;
}
const doc = { body: el('body'), createElement: el };
let polled = [];
window.apiGet = async url => { polled.push(url); return { running: false, ok: true, steps: [{ key: 'enrolled', label: 'Waiting', state: 'done' }, { key: 'done', label: 'Done', state: 'done' }] }; };
const CODE = 'pcj2.SECRET-JOIN-CODE';
const node = { role: 'server', notice: 'Joining as a server gives this machine full control of the cluster (cluster-admin).', warnings: ['an even number of servers doesn\'t add failure tolerance'],
  command: 'curl -fsSL https://example.org/node/join.sh | sudo sh', poll: '/api/servers/n4/op?op_id=abc' };
window.PortcullisServers.openCodeDialog(doc, CODE, '2026-11-16T10:15:00Z', null, node);
const d = doc.body.children[0];
const form = { querySelector: q => ({ '[data-srv-add-id]': { value: ' n4 ' }, '[data-srv-add-name]': { value: '' }, '[data-srv-add-role]': { value: 'server' },
  '[data-srv-add-class]': { value: '' }, '[data-srv-add-site]': { value: '' }, '[data-srv-add-ingress]': { value: '' }, '[data-srv-add-storage]': { value: 'false' } })[q] };
const body = window.PortcullisServers.addBody(form, 'cluster-node');
setTimeout(() => {
  const html = d.innerHTML, progress = d.progress.innerHTML;
  const cmdLine = html.split('<pre data-srv-cmd><code>')[1].split('</code>')[0];
  d.listeners.click.forEach(f => f({ target: { getAttribute: k => k === 'data-srv-code-act' ? 'close' : null } }));
  process.stdout.write(JSON.stringify({ html, progress, cmdLine, polled, body, after: d.innerHTML, children: doc.body.children.length }));
}, 10);
`
	var got struct {
		HTML, Progress, CmdLine, After string
		Polled                         []string
		Body                           map[string]any
		Children                       int
	}
	if err := json.Unmarshal([]byte(serversJS(t, script)), &got); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"pcj2.SECRET-JOIN-CODE", "cluster-admin", "an even number of servers", "curl -fsSL https://example.org/node/join.sh | sudo sh", "when the script asks"} {
		if !strings.Contains(got.HTML, want) {
			t.Errorf("dialog lacks %q:\n%s", want, got.HTML)
		}
	}
	if strings.Contains(got.CmdLine, "pcj2") {
		t.Errorf("the code is on the command line: %q", got.CmdLine)
	}
	if !strings.Contains(got.Progress, `data-step="enrolled"`) || len(got.Polled) != 1 || got.Polled[0] != "/api/servers/n4/op?op_id=abc" {
		t.Errorf("progress %q polled %v", got.Progress, got.Polled)
	}
	b2, _ := json.Marshal(got.Body)
	if string(b2) != `{"id":"n4","kind":"cluster-node","name":"","role":"server","storage":false}` {
		t.Errorf("body %s", b2)
	}
	if got.After != "" || got.Children != 0 {
		t.Errorf("the code survives the close")
	}
}
