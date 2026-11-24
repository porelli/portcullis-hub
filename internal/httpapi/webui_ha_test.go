package httpapi

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestWebHAPage: web/ha.js shows the experimental banner, the checklist
// (each failing item's text), the command and no enable button, every
// value of the Hub escaped; an unknown N−1 level is red; the front door,
// its worst-case texts and Porkbun's note are shown; the section is
// wired into Settings for Kubernetes only.
func TestWebHAPage(t *testing.T) {
	out := nodeEval(t, `
global.window = {};
`+webAsset(t, "ha.js")+`
const H = window.PortcullisHA;
const v = { experimental: true, enabled: false,
  checklist: [{ id: 'nodes', ok: false, text: 'at least 3 nodes' }, { id: 'watchdog', ok: false, text: 'node <b>n3</b> has no watchdog: fencing can\'t be confirmed' }, { id: 'ingress', ok: true, text: '' }],
  guarantee: 'Degraded: one more failure may lose the last writes',
  nodes: [{ name: '<i>n1</i>', role: 'server', class: 'home', site: 'main', ready: true, fencing: false, n_minus_1: 'unknown' },
          { name: 'n2', role: 'server', class: '<u>x</u>', site: '', ready: false, fencing: true, n_minus_1: '<x>' }],
  quorum: { etcd: { voters: 3, healthy: 2 }, vault: { voters: 3, healthy: 1 }, sentinel: { voters: 3, healthy: 3 } },
  sites: [{ name: 'main', primary: true, nodes: ['n1'], servers: ['n1'], gateway: null, ingress: [], rtt_ms: null }],
  dns: [], credentials_note: 'Porkbun API keys can change every domain in the account: Portcullis can\'t narrow them',
  command: './portcullis ha enable', frontdoor: { state: '', error: '' }, volumes: [{ name: 'hub-state-r', robustness: 'degraded', degraded_since: null }],
  warnings: ['node gone: revoked; waiting for quorum to remove its etcd member', '<b>w</b>'], known_gaps: ['Device enrolment (enroll) runs as one copy <i>g</i>'] };
const on = Object.assign({}, v, { enabled: true, guarantee: 'Zero loss on one failure',
  frontdoor: { state: 'standing by', error: '' },
  dns: [{ name: 'example.org', addresses: ['198.51.100.7'], worst_case_text: 'worst case ~10 min for clients that hit the dead address first, on Porkbun',
          per_site: [{ site: 'main', healthy: true, worst_case_text: 'if site main fails: worst case ~10 min on Porkbun', ingress: ['n1'], addresses: ['198.51.100.7'], blind_probers: 0 },
                     { site: '<b>edge</b>', healthy: false, worst_case_text: 'if site <i>edge</i> fails', ingress: ['<u>e1</u>', 'e2'], addresses: ['<script>'], blind_probers: 2 }] }] });
const stale = Object.assign({}, on, { frontdoor: { state: 'leading', error: '', snapshot_stale: true, snapshot_at: '<x>2026' } });
const broken = Object.assign({}, on, { frontdoor: { state: '', error: 'the front door\'s status isn\'t readable: <script>' }, dns: [] });
const degraded = Object.assign({}, v, { nodes: [], sites: [], checklist: [{ id: 'nodes', ok: false, text: 'nodeadm\'s snapshot isn\'t readable: <x>' }, { id: 'backup_destination', ok: true, text: '' }] });
process.stdout.write(JSON.stringify({ off: H.pageHtml(v), on: H.pageHtml(on), broken: H.pageHtml(broken), degraded: H.pageHtml(degraded), failed: H.errorHtml('<b>502</b>'), stale: H.pageHtml(stale) }));
`)
	var got struct{ Off, On, Broken, Degraded, Failed, Stale string }
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	for name, h := range map[string]string{"off": got.Off, "on": got.On, "broken": got.Broken, "degraded": got.Degraded, "failed": got.Failed, "stale": got.Stale} {
		for _, bad := range []string{"<b>", "<i>", "<u>", "<x>", "<script>"} {
			if strings.Contains(h, bad) {
				t.Errorf("%s: unescaped %s", name, bad)
			}
		}
		if !strings.Contains(h, "High availability is experimental") || strings.Contains(h, "<button") || strings.Contains(h, "/api/ha/enable") {
			t.Errorf("%s: banner or a button: %s", name, h)
		}
	}
	for _, w := range []string{`data-ha-item="nodes" data-ok="false"`, "at least 3 nodes", "node &lt;b&gt;n3&lt;/b&gt; has no watchdog", `data-ha-item="ingress" data-ok="true"`,
		"<code>./portcullis ha enable</code>", `data-n1-level="unknown"><span class="pill bad">unknown`, "&lt;i&gt;n1&lt;/i&gt;",
		"etcd 2/3", `<span class="pill bad">Vault 1/3`, "Porkbun API keys can change every domain in the account", "waiting for quorum",
		"Device enrolment (enroll) runs as one copy", "hub-state-r", "Degraded: one more failure may lose the last writes"} {
		if !strings.Contains(got.Off, w) {
			t.Errorf("off lacks %s", w)
		}
	}
	for _, w := range []string{"standing by", "worst case ~10 min for clients that hit the dead address first, on Porkbun", "if site main fails: worst case ~10 min on Porkbun", "HA is on"} {
		if !strings.Contains(got.On, w) {
			t.Errorf("on lacks %s", w)
		}
	}
	// Core Task 28 fix round 1 (review nit4): the per-site view's new
	// fields, hostile values escaped; a stale snapshot says so.
	for _, w := range []string{"publishes <code>198.51.100.7</code> (1 ingress node)", "publishes <code>&lt;script&gt;</code> (2 ingress nodes, ", "2 blind probers"} {
		if !strings.Contains(got.On, w) {
			t.Errorf("on lacks %s: %s", w, got.On)
		}
	}
	if !strings.Contains(got.Stale, "per-site view is from &lt;x&gt;2026") || strings.Contains(got.On, "data-ha-frontdoor-stale") {
		t.Errorf("stale: %s", got.Stale)
	}
	if strings.Contains(got.On, "data-ha-command") {
		t.Error("the command is offered once HA is on")
	}
	if !strings.Contains(got.Broken, "the front door&#39;s status isn&#39;t readable: &lt;script&gt;") {
		t.Errorf("broken: %s", got.Broken)
	}
	// Q2: a degraded answer and a failed one keep the banner and the command.
	if !strings.Contains(got.Degraded, "nodeadm&#39;s snapshot isn&#39;t readable: &lt;x&gt;") || !strings.Contains(got.Degraded, "<code>./portcullis ha enable</code>") {
		t.Errorf("degraded: %s", got.Degraded)
	}
	if !strings.Contains(got.Failed, "&lt;b&gt;502&lt;/b&gt;") || !strings.Contains(got.Failed, "<code>./portcullis ha enable</code>") {
		t.Errorf("failed: %s", got.Failed)
	}
	// The panel sits in Settings → Servers; its loader (settingsnav.js)
	// shows it on Kubernetes only.
	idx := webAsset(t, "index.html")
	for _, w := range []string{`<div id="ha-section" hidden>`, "High availability</div>", `<div id="ha-root"></div>`, "/static/ha.js",
		"PortcullisHA.render(document.getElementById('ha-root'))"} {
		if !strings.Contains(idx, w) {
			t.Errorf("index.html lacks %q", w)
		}
	}
	if i, j := strings.Index(idx, `id="settings-servers"`), strings.Index(idx, `<div id="ha-section" hidden>`); i < 0 || j < i || strings.Contains(idx[i:j], "</section>") {
		t.Errorf("the HA panel isn't inside Settings → Servers")
	}
	nav := webAsset(t, "settingsnav.js")
	for _, w := range []string{"byId('ha-section').hidden = !kube;", "window.PortcullisHA.render(byId('ha-root'))"} {
		if !strings.Contains(nav, w) {
			t.Errorf("settingsnav.js lacks %q", w)
		}
	}
}
