package httpapi

import (
	"encoding/json"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/portcullis/hub/web"
)

// Hub UX reorganisation Task 12: Settings in 8 subtabs
// (web/settingsnav.js), each at #settings/<section>; only the shown
// section loads; the SSH settings and the template sources moved in.

var settingsSections = []string{"signin", "network", "storage", "mail", "ai", "servers", "ssh", "sources"}

// TestSettingsSectionsOrder: the subtab buttons, in order, with their
// slugs and labels; one tablist; settingsnav.js embedded and loaded.
func TestSettingsSectionsOrder(t *testing.T) {
	src := webAsset(t, "index.html")
	var slugs, labels []string
	for _, m := range regexp.MustCompile(`<button [^>]*data-settings-tab="([a-z]+)"[^>]*>([^<]+)</button>`).FindAllStringSubmatch(src, -1) {
		slugs = append(slugs, m[1])
		labels = append(labels, m[2])
	}
	if got := strings.Join(slugs, " "); got != strings.Join(settingsSections, " ") {
		t.Errorf("subtab slugs = %q", got)
	}
	if got := strings.Join(labels, ", "); got != "Sign-in, Network, Storage, Mail, AI, Servers, SSH, Template sources" {
		t.Errorf("subtab labels = %q", got)
	}
	if !strings.Contains(src, `class="settings-nav" role="tablist"`) || !strings.Contains(src, `<script src="/static/settingsnav.js"></script>`) {
		t.Error("no settings tablist, or settingsnav.js isn't loaded")
	}
	if b, err := fs.ReadFile(web.FS, "settingsnav.js"); err != nil || len(b) < 500 {
		t.Errorf("settingsnav.js not embedded: %v", err)
	}
}

// settingsSection answers the markup of <section data-settings-section="slug">.
func settingsSection(t *testing.T, src, slug string) string {
	t.Helper()
	i := strings.Index(src, `<section data-settings-section="`+slug+`"`)
	if i < 0 {
		t.Fatalf("no section %s", slug)
	}
	j := strings.Index(src[i:], "</section>")
	if j < 0 {
		t.Fatalf("section %s isn't closed", slug)
	}
	return src[i : i+j]
}

// TestSettingsNetworkHolds: each section holds its roots (network:
// Domains, Local networks, VPN in that order); the Marketplace page and
// its sources block are gone.
func TestSettingsNetworkHolds(t *testing.T) {
	src := webAsset(t, "index.html")
	holds := map[string][]string{
		"signin":  {`id="signin-root"`},
		"network": {`id="domains-root"`, `id="localnets-root"`, `id="vpn-settings-root"`},
		"storage": {`id="folders-root"`},
		"mail":    {`id="mail-settings-root"`},
		"ai":      {`id="ai-root"`},
		"servers": {`id="servers-root"`},
		"ssh":     {`id="ssh-settings-root"`},
		"sources": {`id="sources-list"`, `id="source-name"`, `id="source-url"`, `data-src-add`, `data-src-sync`, `id="source-sync-status"`},
	}
	for slug, ids := range holds {
		sec := settingsSection(t, src, slug)
		at := -1
		for _, id := range ids {
			k := strings.Index(sec, id)
			if k < 0 || k < at {
				t.Errorf("section %s: %s missing or out of order", slug, id)
			}
			at = k
		}
	}
	for _, gone := range []string{`id="tab-marketplace"`, `id="mkt-sources"`, "{{range .Sources}}"} {
		if strings.Contains(src, gone) {
			t.Errorf("index.html still has %q", gone)
		}
	}
	if !strings.Contains(src, `<div id="mkt-root" hidden>`) || strings.Index(src, `id="tab-apps"`) > strings.Index(src, `id="mkt-root"`) {
		t.Error("the Marketplace isn't inside the Apps tab (#mkt-root)")
	}
}

// settingsNavDOM: a document for settingsnav.js: the 8 tab buttons and
// sections (hidden / aria-selected recorded), getElementById answering
// a stub per id; the loaders stubbed, each call recorded.
const settingsNavDOM = `
const calls = [];
const mk = (attrs) => ({ attrs, hidden: false, dataset: {}, setAttribute(k, v) { this.attrs[k] = v; }, getAttribute(k) { return this.attrs[k]; }, focus() { calls.push(['focus', this.dataset.settingsTab]); }, addEventListener() {} });
const SLUGS = ['signin', 'network', 'storage', 'mail', 'ai', 'servers', 'ssh', 'sources'];
const tabs = SLUGS.map(s => { const b = mk({}); b.dataset.settingsTab = s; return b; });
const secs = SLUGS.map(s => { const b = mk({}); b.dataset.settingsSection = s; return b; });
const listeners = {};
global.window = {};
global.location = { hash: '' };
global.history = { replaceState: (a, b, h) => { calls.push(['hash', h]); location.hash = h; } };
global.document = {
  querySelectorAll: sel => sel === '[data-settings-tab]' ? tabs : sel === '[data-settings-section]' ? secs : [],
  getElementById: id => ({ id }),
  addEventListener: (ev, fn) => { listeners[ev] = fn; },
};
global.PortcullisSignIn = { mount: r => calls.push(['signin', r.id]) };
global.loadDomains = () => calls.push(['loadDomains']);
global.loadAISettings = () => calls.push(['loadAISettings']);
global.loadVPNSettings = r => calls.push(['loadVPNSettings', r.id]);
global.loadSources = () => calls.push(['loadSources']);
global.loadSourceSync = () => calls.push(['loadSourceSync']);
global.PortcullisFolders = { render: r => calls.push(['folders', r.id]), renderLocalNetworks: r => calls.push(['localnets', r.id]) };
window.PortcullisMail = { render: r => calls.push(['mail', r.id]) };
window.PortcullisServers = { render: r => calls.push(['servers', r.id]) };
window.PortcullisSSH = { renderSettings: r => calls.push(['ssh', r.id]) };
`

// TestSettingsLazyLoadNode: show(section) loads that section only, every
// time it's shown; the others are hidden; the hash names the section.
func TestSettingsLazyLoadNode(t *testing.T) {
	out := nodeEval(t, settingsNavDOM+webAsset(t, "settingsnav.js")+`
const N = window.PortcullisSettingsNav;
const r = {};
const take = f => { calls.length = 0; f(); return calls.filter(c => c[0] !== 'focus'); };
r.mail = take(() => N.show('mail', ''));
r.mailHidden = secs.map(s => s.hidden);
r.mailSel = tabs.map(b => b.attrs['aria-selected']);
r.mail2 = take(() => N.show('mail', ''));
r.ai = take(() => N.show('ai', ''));
r.network = take(() => N.show('network', ''));
r.sources = take(() => N.show('sources', ''));
r.bogus = take(() => N.show('bogus', ''));
r.empty = take(() => N.show('', ''));
r.current = N.current();
process.stdout.write(JSON.stringify(r));
`)
	var r map[string]any
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	s := func(k string) string { b, _ := json.Marshal(r[k]); return string(b) }
	want := map[string]string{
		"mail":       `[["mail","mail-settings-root"],["hash","#settings/mail"]]`,
		"mailHidden": `[true,true,true,false,true,true,true,true]`,
		"mailSel":    `["false","false","false","true","false","false","false","false"]`,
		"mail2":      `[["mail","mail-settings-root"],["hash","#settings/mail"]]`,
		"ai":         `[["loadAISettings"],["hash","#settings/ai"]]`,
		"network":    `[["loadDomains"],["localnets","localnets-root"],["loadVPNSettings","vpn-settings-root"],["hash","#settings/network"]]`,
		"sources":    `[["loadSources"],["loadSourceSync"],["hash","#settings/sources"]]`,
		"bogus":      `[["signin","signin-root"],["hash","#settings/signin"]]`,
		"empty":      `[["signin","signin-root"],["hash","#settings/signin"]]`,
		"current":    `"signin"`,
	}
	for k, w := range want {
		if g := s(k); g != w {
			t.Errorf("%s: %s, want %s", k, g, w)
		}
	}
}

// TestSettingsKeyboardNode: the tablist moves with the arrow keys, Home
// and End (wrapping), each move showing that section.
func TestSettingsKeyboardNode(t *testing.T) {
	out := nodeEval(t, settingsNavDOM+webAsset(t, "settingsnav.js")+`
const N = window.PortcullisSettingsNav;
N.show('signin', '');
const key = (k, from) => { calls.length = 0; let prevented = false; listeners.keydown({ key: k, target: { closest: s => s === '[data-settings-tab]' ? tabs[SLUGS.indexOf(from)] : null }, preventDefault() { prevented = true; } }); return [N.current(), prevented]; };
const click = s => { calls.length = 0; listeners.click({ target: { closest: q => q === '[data-settings-tab]' ? tabs[SLUGS.indexOf(s)] : null } }); return calls.find(c => c[0] === 'hash'); };
process.stdout.write(JSON.stringify([key('ArrowRight', 'signin'), key('ArrowLeft', 'signin'), key('Home', 'ssh'), key('End', 'mail'), key('x', 'mail'), click('storage')]));
`)
	if want := `[["network",true],["sources",true],["signin",true],["sources",true],["sources",false],["hash","#settings/storage"]]`; strings.TrimSpace(out) != want {
		t.Errorf("keys: %s, want %s", out, want)
	}
}

// TestSettingsDeepLinksNode: routeHash with the real settingsnav.js:
// #settings/network?add=… opens the add-domain form pre-filled, ?token=
// its token row; #settings/ai?provider=…&field=… the provider secret
// form; #settings/bogus shows Sign-in at #settings/signin; showTab
// ("settings") hands the asked section to the subtabs.
func TestSettingsDeepLinksNode(t *testing.T) {
	src := webAsset(t, "index.html")
	block, _ := hubRoutes(t)
	out := nodeEval(t, settingsNavDOM+webAsset(t, "settingsnav.js")+`
let usageView = 'apps', accessView = null, settingsView = { section: '' };
const PortcullisPeople = { href: f => f };
const PortcullisSettingsNav = window.PortcullisSettingsNav;
function showTab(n) { calls.push(['showTab', n]); if (n === 'settings') PortcullisSettingsNav.show(settingsView.section, ''); return true; }
const nameInput = { value: '' };
const form = { querySelector: s => s === '.domain-provider' ? sel : { focus() { calls.push(['focus-cred']); } } };
const sel = { value: '', options: [{ value: 'hetzner' }, { value: 'porkbun' }], dispatchEvent() { calls.push(['provider-change', sel.value]); } };
global.Event = function (t) { this.type = t; };
global.CSS = { escape: s => s };
document.getElementById = id => id === 'domain-name' ? nameInput : { id };
document.querySelector = () => null;
async function waitFor(s) { calls.push(['waitFor', s]); return form; }
function flash() { calls.push(['flash']); }
function showToast(m) { calls.push(['toast', m]); }
function openProviderSecretAt(p, f) { calls.push(['secret', p, f]); }
`+hubFunc(t, src, "peopleRedirect")+hubFunc(t, src, "oldAppLink")+hubFunc(t, src, "showSettings")+hubFunc(t, src, "openSettingsForm")+block+hubFunc(t, src, "routeTo")+hubFunc(t, src, "routeHash")+`
(async () => {
  const r = {};
  const go = async h => { calls.length = 0; location.hash = h; routeHash(); await new Promise(res => setTimeout(res, 10)); return calls.filter(c => c[0] !== 'focus'); };
  r.add = await go('#settings/network?add=example.org&provider=hetzner');
  r.name = nameInput.value;
  r.ai = await go('#settings/ai?provider=openai&field=api_key');
  r.bogus = await go('#settings/bogus');
  r.ssh = await go('#settings/ssh');
  process.stdout.write(JSON.stringify(r));
})();
`)
	var r map[string]any
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	s := func(k string) string { b, _ := json.Marshal(r[k]); return string(b) }
	want := map[string]string{
		"add":   `[["showTab","settings"],["loadDomains"],["localnets","localnets-root"],["loadVPNSettings","vpn-settings-root"],["hash","#settings/network"],["waitFor","#domain-add-form"],["provider-change","hetzner"],["flash"],["focus-cred"]]`,
		"name":  `"example.org"`,
		"ai":    `[["showTab","settings"],["loadAISettings"],["hash","#settings/ai"],["secret","openai","api_key"]]`,
		"bogus": `[["showTab","settings"],["signin","signin-root"],["hash","#settings/signin"]]`,
		"ssh":   `[["showTab","settings"],["ssh","ssh-settings-root"],["hash","#settings/ssh"]]`,
	}
	for k, w := range want {
		if g := s(k); g != w {
			t.Errorf("%s: %s, want %s", k, g, w)
		}
	}
	if !strings.Contains(src, "if (name === 'settings') PortcullisSettingsNav.show(settingsView.section, '');") {
		t.Error("showTab('settings') doesn't hand the section to PortcullisSettingsNav")
	}
}

// TestSourcesFormsStillWork: the source buttons' handlers are delegated
// from document (the forms now live in Settings → Template sources); the
// list is client-rendered from GET /api/sources with every name and URL
// escaped; no template interpolation in the source code; handleIndex no
// longer passes Sources.
func TestSourcesFormsStillWork(t *testing.T) {
	src := webAsset(t, "index.html")
	lines := strings.Split(src, "\n")
	for _, h := range []string{"t.closest('[data-src-remove]')", "t.closest('[data-src-add]')", "t.closest('[data-src-sync]')"} {
		at := -1
		for i, l := range lines {
			if strings.Contains(l, h) {
				at = i
			}
		}
		if at < 0 {
			t.Fatalf("no handler %s", h)
		}
		owner := ""
		for i := at; i >= 0; i-- {
			if strings.Contains(lines[i], ".addEventListener('click'") {
				owner = strings.TrimSpace(lines[i])
				break
			}
		}
		if !strings.HasPrefix(owner, "document.addEventListener('click'") {
			t.Errorf("%s is bound by %q, not on document", h, owner)
		}
	}
	srcs := hubFunc(t, src, "sourcesHtml")
	for _, s := range []string{srcs, hubFunc(t, src, "addSource"), hubFunc(t, src, "removeSource"), hubFunc(t, src, "syncSources")} {
		if strings.Contains(s, "${") {
			t.Errorf("template interpolation in:\n%s", s)
		}
	}
	out := nodeEval(t, hubFunc(t, src, "escapeHtml")+srcs+`
process.stdout.write(JSON.stringify([
  sourcesHtml([{ name: 'portcullis', url: 'https://github.com/porelli/portcullis-templates.git', path: '/x' }, { name: 'mine<b>', url: 'https://e.org/"onx=1' }]),
  sourcesHtml([]),
]));
`)
	var got []string
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	h := got[0]
	for _, want := range []string{"portcullis", ">default<", "mine&lt;b&gt;", "https://e.org/&quot;onx=1", `data-src-remove="mine&lt;b&gt;"`} {
		if !strings.Contains(h, want) {
			t.Errorf("sources list lacks %q:\n%s", want, h)
		}
	}
	if strings.Contains(h, "mine<b>") || strings.Contains(h, `"onx`) || strings.Contains(h, `data-src-remove="portcullis"`) || strings.Contains(h, "/x") {
		t.Errorf("sources list:\n%s", h)
	}
	if !strings.Contains(got[1], "No template sources") {
		t.Errorf("empty list: %s", got[1])
	}
	srv, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(srv), `"Sources":`) {
		t.Error("handleIndex still passes Sources")
	}
}
