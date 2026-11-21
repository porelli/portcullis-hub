package httpapi

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

// Hub UX reorganisation Task 11: the Access tab (web/access.js): SSH
// access, VPN devices, sign-in history.

// TestAccessJSSafe: no markup from strings (no innerHTML, no inline
// handlers, no template interpolation); device names and owners set as
// text; no key material field name anywhere in the file.
func TestAccessJSSafe(t *testing.T) {
	js := webAsset(t, "access.js")
	for _, banned := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "onclick=", "localStorage", "sessionStorage", "console.log", "${", "eval("} {
		if strings.Contains(js, banned) {
			t.Errorf("access.js contains %q", banned)
		}
	}
	if regexp.MustCompile(`\son[a-z]+="`).MatchString(js) {
		t.Error("access.js has an inline handler attribute")
	}
	// Access → SSH links to the SSH settings (Settings → SSH).
	if !strings.Contains(webAsset(t, "ssh.js"), "href: '#settings/ssh'") {
		t.Error("ssh.js has no link to #settings/ssh")
	}
	low := strings.ToLower(js)
	for _, key := range []string{"private", "public_key", "config"} {
		if strings.Contains(low, key) {
			t.Errorf("access.js names %q", key)
		}
	}
	for _, want := range []string{"text: d.name", "d.user", "'/api/vpn/devices'", "/signin/history", "^[a-z0-9._-]{1,64}$", "PortcullisSSH.render(", "window.PortcullisAccess = "} {
		if !strings.Contains(js, want) {
			t.Errorf("access.js lacks %q", want)
		}
	}
}

// accessFakeDOM: sshFakeDOM plus what access.js's VPN and history
// panels use (querySelector by data attribute, click dispatch).
const accessFakeDOM = sshFakeDOM + `
Node.prototype.addEventListener = function (ev, fn) { (this.on = this.on || {})[ev] = fn; };
Node.prototype.removeChild = function (c) { this.kids = this.kids.filter(k => k !== c); };
Object.defineProperty(Node.prototype, 'firstChild', { get() { return this.kids[0] || null; } });
Node.prototype.remove = function () {};
function walk(n, f) { if (!n || !n.kids) return; f(n); n.kids.forEach(k => walk(k, f)); }
function findAll(root, pred) { const out = []; walk(root, n => { if (pred(n)) out.push(n); }); return out; }
`

// TestAccessVPNRemoveConfirms: VPN devices lists every person's device
// (names as text); Remove only on a built-in (managed) device; it asks
// confirm() with the device's name, sends nothing when refused and the
// DELETE when confirmed.
func TestAccessVPNRemoveConfirms(t *testing.T) {
	out := nodeEval(t, accessFakeDOM+`
const asked = [], sent = [];
let answer = false;
global.confirm = m => { asked.push(m); return answer; };
global.window.PortcullisPeople = { href: f => 'https://people.example.org/' + f };
const devices = [
  { id: 'd1', user: 'alice', name: 'Laptop <b>', provider: 'builtin', provider_label: 'Built-in', address: '10.8.0.2', last_seen: '2026-11-20T10:00:00Z', expires: null, online: true, managed: true },
  { id: 'd2', user: 'bob', name: 'Phone', provider: 'netbird', provider_label: 'NetBird', address: '100.64.0.3', last_seen: null, expires: null, online: false, managed: false },
];
global.fetch = async (url, opts) => {
  sent.push([(opts && opts.method) || 'GET', url]);
  return { ok: true, status: url === '/api/vpn/devices' ? 200 : 204, json: async () => devices, text: async () => '' };
};
`+webAsset(t, "access.js")+`
(async () => {
  const box = new Node('div');
  await window.PortcullisAccess._test.renderVPN(box);
  const html = box.html();
  const removes = findAll(box, n => n.attrs && n.attrs['data-vpn-remove'] !== undefined);
  const r = { html, removes: removes.map(n => n.attrs['data-vpn-remove']) };
  await removes[0].on.click();
  r.refused = sent.slice();
  answer = true;
  await removes[0].on.click();
  r.asked = asked;
  r.sent = sent;
  process.stdout.write(JSON.stringify(r));
})();
`)
	var r struct {
		HTML    string
		Removes []string
		Refused [][]string
		Asked   []string
		Sent    [][]string
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	for _, want := range []string{"Laptop &lt;b&gt;", "alice", "bob", "Built-in", "NetBird", "10.8.0.2", `href="https://people.example.org/#people/alice"`, "online"} {
		if !strings.Contains(r.HTML, want) {
			t.Errorf("VPN devices lacks %q:\n%s", want, r.HTML)
		}
	}
	if strings.Contains(r.HTML, "Laptop <b>") {
		t.Error("a device name as markup")
	}
	if strings.Join(r.Removes, ",") != "d1" {
		t.Errorf("Remove on %v, want only the built-in d1", r.Removes)
	}
	if len(r.Refused) != 1 {
		t.Errorf("a refused confirm sent %v", r.Refused)
	}
	if len(r.Asked) != 2 || !strings.Contains(r.Asked[0], "Laptop <b>") || !strings.Contains(r.Asked[0], "alice") {
		t.Errorf("confirm asked %q", r.Asked)
	}
	if len(r.Sent) < 2 || r.Sent[1][0] != "DELETE" || r.Sent[1][1] != "/api/vpn/devices/d1" {
		t.Errorf("sent %v", r.Sent)
	}
}

// TestAccessSignInHistoryNode: a name outside ^[a-z0-9._-]{1,64}$ is
// refused before any request; a valid one loads the person's history
// (rows as text) and "Older" passes the cursor back as it came.
func TestAccessSignInHistoryNode(t *testing.T) {
	out := nodeEval(t, accessFakeDOM+`
const sent = [];
global.window.PortcullisPeople = { href: f => 'https://people.example.org/' + f };
global.fetch = async (url) => {
  sent.push(url);
  const older = url.indexOf('before=') >= 0;
  const page = older ? { entries: [{ time: '2026-11-01T10:00:00Z', kind: 'failed', methods: ['password'], reason: 'bad', ip: '10.0.0.9', browser: 'Safari' }], next: '', unknown: [] }
    : { entries: [{ time: '2026-11-20T10:00:00Z', kind: 'sign_in', methods: ['security_key'], app: '', ip: '10.0.0.1', browser: 'Firefox <i>' }], next: 'c/1+2', unknown: ['keycloak'] };
  return { ok: true, status: 200, json: async () => page, text: async () => '' };
};
`+webAsset(t, "access.js")+`
(async () => {
  const T = window.PortcullisAccess._test;
  const r = {};
  const box = new Node('div');
  r.bad = await T.loadHistory(box, 'Alice!', false);
  r.badSent = sent.length;
  r.badHtml = box.html();
  const box2 = new Node('div');
  await T.loadHistory(box2, 'alice', false);
  const older = findAll(box2, n => n.attrs && n.attrs['data-hist-older'] !== undefined);
  r.older = older.length;
  if (older[0]) await older[0].on.click();
  r.html = box2.html();
  r.sent = sent;
  process.stdout.write(JSON.stringify(r));
})();
`)
	var r struct {
		Bad     bool
		BadSent int
		BadHTML string
		Older   int
		HTML    string
		Sent    []string
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if r.Bad || r.BadSent != 0 || !strings.Contains(r.BadHTML, "a-z") {
		t.Errorf("an invalid name: ok=%v sent=%d %s", r.Bad, r.BadSent, r.BadHTML)
	}
	if r.Older != 1 || len(r.Sent) != 2 || r.Sent[0] != "/api/directory/users/alice/signin/history?limit=20" ||
		r.Sent[1] != "/api/directory/users/alice/signin/history?limit=20&before=c%2F1%2B2" {
		t.Errorf("older=%d sent %v", r.Older, r.Sent)
	}
	for _, want := range []string{"Signed in · security key", "Firefox &lt;i&gt;", "Sign-in failed · password: bad", "couldn"} {
		if !strings.Contains(r.HTML, want) {
			t.Errorf("history lacks %q:\n%s", want, r.HTML)
		}
	}
}
