package httpapi

import (
	"encoding/json"
	"strings"
	"testing"
)

// sshFakeDOM is a minimal document for node: createElement / createTextNode
// nodes that serialise to HTML (text escaped), enough for el().
const sshFakeDOM = `
const escT = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const escA = s => escT(s).replace(/"/g, '&quot;');
function Node(tag) { this.tag = tag; this.attrs = {}; this.kids = []; this.className = ''; this._text = null; }
Node.prototype.setAttribute = function (k, v) { this.attrs[k] = v; };
Node.prototype.addEventListener = function () {};
Node.prototype.appendChild = function (c) { this.kids.push(c); return c; };
Node.prototype.append = function (...cs) { for (const c of cs.flat()) this.kids.push(typeof c === 'string' ? new Text(c) : c); };
Object.defineProperty(Node.prototype, 'textContent', { set(v) { this.kids = [new Text(v)]; }, get() { return this.kids.map(k => k.textContent).join(''); } });
Node.prototype.html = function () {
  const a = Object.entries(this.attrs).map(([k, v]) => ' ' + k + '="' + escA(v) + '"').join('') + (this.className ? ' class="' + escA(this.className) + '"' : '') + (this.value !== undefined ? ' value="' + escA(this.value) + '"' : '');
  return '<' + this.tag + a + '>' + this.kids.map(k => k.html()).join('') + '</' + this.tag + '>';
};
function Text(t) { this.t = String(t); }
Text.prototype.html = function () { return escT(this.t); };
Object.defineProperty(Text.prototype, 'textContent', { get() { return this.t; } });
global.document = { createElement: t => new Node(t), createTextNode: t => new Text(t) };
global.window = { addEventListener() {} };
`

// TestMySSHCard: the person's card lists host groups, accounts and
// certificates as text (markup in a value stays text), the commands and
// an https download only; another person's card has no commands.
func TestMySSHCard(t *testing.T) {
	render := func(v any, self bool) string {
		vb, _ := json.Marshal(v)
		s := "false"
		if self {
			s = "true"
		}
		return nodeEval(t, sshFakeDOM+webAsset(t, "myssh.js")+"\nprocess.stdout.write(window.PortcullisMySSH._test.card("+string(vb)+","+s+",'/x',()=>{}).html());\n")
	}
	v := map[string]any{"enabled": true, "user": "alice",
		"host_groups":  []any{map[string]any{"id": "web", "label": "Web <b>", "accounts": []string{"alice"}, "sudo": true, "hosts": []string{"web-1"}, "until": "2026-11-17T18:00:00Z"}},
		"certificates": []any{map[string]any{"host_group": "web", "key_fp": "SHA256:abc", "valid_before": "2026-11-17T18:00:00Z", "flow": "pkce"}},
		"commands":     []string{"portcullis login example.com", "portcullis ssh-config --install"},
		"download":     "https://github.com/porelli/portcullis-hub/releases"}
	h := render(v, true)
	for _, want := range []string{"SSH access", "Web &lt;b&gt;", "<code>alice</code>", "SHA256:abc", "2026-11-17 18:00:00 UTC", "Revoke all my SSH certificates",
		"portcullis login example.com", `href="https://github.com/porelli/portcullis-hub/releases"`} {
		if !strings.Contains(h, want) {
			t.Errorf("card lacks %q:\n%s", want, h)
		}
	}
	if strings.Contains(h, "Web <b>") {
		t.Errorf("markup from a value:\n%s", h)
	}
	v["download"] = "javascript:alert(1)"
	if h := render(v, true); strings.Contains(h, "javascript:") || strings.Contains(h, "href=") {
		t.Errorf("a non-https download link:\n%s", h)
	}
	if h := render(v, false); strings.Contains(h, "portcullis login") || !strings.Contains(h, "Revoke all SSH certificates") {
		t.Errorf("person card:\n%s", h)
	}
}

// TestSSHTabPrivilegedCheck: the Hub tab treats sudo, root and
// forwarding as privileged (the typed group name and a fresh sign-in
// first), and keeps every editable host-group field when saving.
func TestSSHTabPrivilegedCheck(t *testing.T) {
	out := nodeEval(t, sshFakeDOM+webAsset(t, "ssh.js")+`
const T = window.PortcullisSSH._test;
process.stdout.write(JSON.stringify([
  T.looksPrivileged({ sudo: 'none', accounts: ['{username}'] }),
  T.looksPrivileged({ sudo: 'full', accounts: ['{username}'] }),
  T.looksPrivileged({ sudo: 'none', accounts: ['root'] }),
  T.looksPrivileged({ sudo: 'none', accounts: ['deploy'], port_forwarding: true }),
  T.looksPrivileged({ sudo: 'none', accounts: ['deploy'], agent_forwarding: true }),
  T.hgBody({ id: 'web', label: 'W', vpn_via: ['netbird'], hosts: ['web-1'], trust_command: 'x', host_certs: false, grants: 2 }),
]));`)
	var got []any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	for i, want := range []bool{false, true, true, true, true} {
		if got[i] != want {
			t.Errorf("looksPrivileged #%d = %v", i, got[i])
		}
	}
	body, _ := json.Marshal(got[5])
	if string(body) != `{"host_certs":false,"label":"W","vpn_via":["netbird"]}` {
		t.Errorf("hgBody %s (view-only fields must never be sent: the Hub's strict decode refuses them)", body)
	}
}
