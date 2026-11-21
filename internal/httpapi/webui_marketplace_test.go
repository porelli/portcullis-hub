package httpapi

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

// Hub UX reorganisation Task 13: the Marketplace is Apps' "+ Add app"
// (web/marketplace.js): client-rendered from GET /api/templates, search,
// category chips, filters, a detail drawer. Every manifest field comes
// from third-party templates: text only, except the server-sanitised
// long_description_html and notes_html; logos and screenshots only as
// <img> from the catalog asset routes.

// TestMarketplaceJSSafe: the only innerHTML assignments are the two
// sanitised Markdown fields, into class="md" containers; the logo is an
// <img> created by createElement with src from logo_url (only
// /api/catalog/) and alt ""; no RegExp from input, no inline handlers,
// no template interpolation, links through safeHref (https only).
func TestMarketplaceJSSafe(t *testing.T) {
	js := webAsset(t, "marketplace.js")
	var md []string
	for i, line := range strings.Split(js, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		if strings.Contains(line, "innerHTML") {
			m := regexp.MustCompile(`(\w+)\.innerHTML = (t\.manifest\.(?:long_description_html|auth\.notes_html));`).FindStringSubmatch(line)
			if m == nil {
				t.Errorf("marketplace.js:%d innerHTML of something else: %s", i+1, strings.TrimSpace(line))
				continue
			}
			md = append(md, m[1])
		}
		if strings.Contains(line, "setAttribute('href'") || strings.Contains(line, "href:") {
			// A fragment, or home / src (themselves safeHref's answers).
			if !strings.Contains(line, "safeHref(") && !strings.Contains(line, "href: '#") && !strings.Contains(line, "{ href: home,") && !strings.Contains(line, "{ href: src,") {
				t.Errorf("marketplace.js:%d an href not through safeHref: %s", i+1, strings.TrimSpace(line))
			}
		}
	}
	if !strings.Contains(js, "const home = safeHref(links.website), src = safeHref(links.source);") {
		t.Error("the drawer's links aren't safeHref's answers")
	}
	if len(md) != 2 {
		t.Errorf("innerHTML assignments: %v, want the two Markdown fields", md)
	}
	for _, v := range md {
		if !regexp.MustCompile(`const ` + v + ` = el\('div', \{ class: 'md'`).MatchString(js) {
			t.Errorf("%s isn't a class=\"md\" container", v)
		}
	}
	for _, banned := range []string{"outerHTML", "insertAdjacentHTML", "document.write", "new RegExp(", "${", "onclick=", "localStorage", "sessionStorage", "eval(", "console.log", "<svg", "createElementNS"} {
		if strings.Contains(js, banned) {
			t.Errorf("marketplace.js contains %q", banned)
		}
	}
	if regexp.MustCompile(`\son[a-z]+="`).MatchString(js) {
		t.Error("marketplace.js has an inline handler attribute")
	}
	for _, want := range []string{"document.createElement('img')", "img.src = t.logo_url;", "img.alt = '';", "LOGO_PREFIX = '/api/catalog/'",
		"rel: 'noopener noreferrer'", "target: '_blank'", "window.PortcullisMarketplace = "} {
		if !strings.Contains(js, want) {
			t.Errorf("marketplace.js lacks %q", want)
		}
	}
	// The mail server card keeps the landed badge's text and title.
	for _, want := range []string{"'data-managed-by-portcullis': t.id", "'Managed by Portcullis'",
		"Mail is managed in Portcullis (Settings → Mail and the instance\\'s Mail tab), so Portcullis\\'s mail safeguards always apply. A full administrator can open the mail server\\'s own admin screen read-only.",
		"'data-no-web-page': t.id", "This app has no web page: people use it with its own client (see My apps)", "'data-mail-badge': ''"} {
		if !strings.Contains(js, want) {
			t.Errorf("marketplace.js lacks %q", want)
		}
	}
}

// mktFakeDOM: a document for marketplace.js (elements that serialise to
// HTML with text escaped, the raw innerHTML kept as-is), the drawer
// dialog, the page's globals (catalog, instances, runtime, compat words,
// toast) and a fixture catalog of 6 templates.
const mktFakeDOM = `
const escT = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const escA = s => escT(s).replace(/"/g, '&quot;');
function Node(tag) { this.tag = tag; this.attrs = {}; this.kids = []; this.className = ''; this.on = {}; this.hidden = false; this._html = null; }
Node.prototype.setAttribute = function (k, v) { this.attrs[k] = String(v); };
Node.prototype.getAttribute = function (k) { return k in this.attrs ? this.attrs[k] : null; };
Node.prototype.removeAttribute = function (k) { delete this.attrs[k]; };
Node.prototype.addEventListener = function (ev, fn, cap) { (this.on[ev + (cap ? '!' : '')] = this.on[ev + (cap ? '!' : '')] || []).push(fn); };
Node.prototype.appendChild = function (c) { this.kids.push(c); c.parent = this; c.parentNode = this; return c; };
Node.prototype.append = function (...cs) { for (const c of cs) this.appendChild(typeof c === 'string' ? new Text(c) : c); };
Node.prototype.replaceChildren = function (...cs) { this.kids = []; this._html = null; this.append(...cs); };
Node.prototype.focus = function () { global.focused = this; };
Object.defineProperty(Node.prototype, 'children', { get() { return this.kids.filter(k => k.tag); } });
Node.prototype.showModal = function () { this.open = true; };
Node.prototype.close = function () { this.open = false; (this.on.close || []).forEach(f => f({})); };
Object.defineProperty(Node.prototype, 'innerHTML', { set(v) { this._html = String(v); this.kids = []; }, get() { return this._html; } });
Object.defineProperty(Node.prototype, 'textContent', { set(v) { this.kids = [new Text(v)]; this._html = null; }, get() { return this._html != null ? this._html : this.kids.map(k => k.textContent).join(''); } });
Node.prototype.html = function () {
  if (this.hidden) return '';
  const props = ['src', 'alt', 'value', 'disabled', 'title'].filter(k => this[k] !== undefined && this[k] !== false).map(k => ' ' + k + '="' + escA(this[k] === true ? '' : this[k]) + '"').join('');
  const a = Object.entries(this.attrs).map(([k, v]) => ' ' + k + '="' + escA(v) + '"').join('') + (this.className ? ' class="' + escA(this.className) + '"' : '') + props;
  return '<' + this.tag + a + '>' + (this._html != null ? this._html : this.kids.map(k => k.html()).join('')) + '</' + this.tag + '>';
};
function Text(t) { this.t = String(t); this.kids = []; }
Text.prototype.html = function () { return escT(this.t); };
Object.defineProperty(Text.prototype, 'textContent', { get() { return this.t; } });
function walk(n, f) { if (!n || !n.kids) return; f(n); n.kids.forEach(k => walk(k, f)); }
function findAll(root, pred) { const out = []; walk(root, n => { if (n.tag && pred(n)) out.push(n); }); return out; }
function visibleOf(root, pred) { const out = []; (function w(n) { if (!n || !n.kids || n.hidden) return; if (n.tag && pred(n)) out.push(n); n.kids.forEach(w); })(root); return out; }
function fire(n, ev, e) {
  const evt = Object.assign({ target: n, preventDefault() { this.prevented = true; }, stopPropagation() {} }, e || {});
  const path = []; for (let p = n; p; p = p.parent) path.unshift(p);
  for (const p of path) for (const f of (p.on[ev + '!'] || [])) f(evt);
  for (let p = n; p; p = p.parent) for (const f of (p.on[ev] || [])) f(evt);
  return evt;
}
const drawer = new Node('dialog');
global.document = { createElement: t => new Node(t), createTextNode: t => new Text(t), getElementById: id => id === 'mkt-drawer' ? drawer : null, addEventListener() {},
  get activeElement() { return global.focused || null; } };
global.window = { addEventListener() {} };
global.location = { hash: '#marketplace' };
global.history = { replaceState: (a, b, h) => { location.hash = h; } };
global.CSS = { escape: s => s };
const toasts = [];
global.showToast = (m, k) => toasts.push([m, k]);
global.runtimeInfo = { runtime: 'podman', verified: true };
global.instancesCache = [{ id: 'immich', template: 'immich' }];
global.apiGet = async u => u === '/api/usage' ? { hosts: { primary: { memory_bytes: 1073741824 } } } : null;
const T = (id, o) => {
  const m = Object.assign({ name: id, description: '', icon: '', category: 'x', tags: [], instances: 'single', auth: { method: 'native-oidc', sso: false } }, o.manifest || {});
  const t = Object.assign({ id, source: 'portcullis', mail_provider: false, routerless: false, category_rank: 99, category_label: 'X', compat: null }, o);
  t.manifest = m;
  return t;
};
const CATALOG = [
  T('nextcloud', { category_rank: 4, category_label: 'Files & storage', primary_only_reasons: ['is marked placement: primary_only', '<b>x</b>'], logo_url: '/api/catalog/nextcloud/logo.svg', screenshot_urls: ['/api/catalog/nextcloud/screenshots/0'],
    compat: { runtime: 'podman', status: 'refused', reasons: ['needs a privileged port', 'uses host networking'] },
    manifest: { name: 'Nextcloud', description: 'Files, calendars and contacts', icon: '☁', category: 'storage', tags: ['files', 'sync'], instances: 'multi',
      auth: { method: 'native-oidc', sso: true, group_access: true, notes: 'Sign in with Portcullis.\n\nMore.', notes_html: '<p>Sign in <b>with</b> Portcullis.</p>' },
      links: { website: 'https://nextcloud.com/', source: 'https://github.com/nextcloud/server' }, long_description_html: '<p>The <em>long</em> one.</p>',
      resources: { min_memory_mib: 2048, min_disk_gib: 10 }, screenshots: [{ file: 'a.png', caption: 'The files view' }], placement: 'primary_only',
      settings: { options: [{ key: 'admin_email', label: 'Admin email', required: true }, { key: 'theme', label: 'Theme' }] } } }),
  T('stalwart', { category_rank: 3, category_label: 'Mail', mail_provider: true,
    manifest: { name: 'Stalwart', description: 'Mail server', icon: '✉', category: 'mail', tags: ['smtp'], auth: { method: 'native-oidc', sso: true }, ai: { mcp: [{ name: 'mail' }] } } }),
  T('immich', { category_rank: 5, category_label: 'Media',
    manifest: { name: 'Immich', description: 'Photo and video backup', icon: '📷', category: 'media', tags: ['photos'], auth: { method: 'forward-auth', sso: 'partial' } } }),
  T('smb', { category_rank: 4, category_label: 'Files & storage', routerless: true,
    manifest: { name: 'File shares', description: 'SMB shares', icon: '🗂', category: 'storage', tags: ['smb'], auth: { method: 'custom', sso: false } } }),
  T('wireguard', { category_rank: 13, category_label: 'VPN',
    manifest: { name: 'WireGuard', description: 'A VPN', icon: '🔒', category: 'vpn', tags: [], auth: { method: 'public', sso: false }, vpn: { kind: 'wireguard' } } }),
  T('evil', { source: 'community', category_rank: 1000, category_label: 'Weird thing', logo_url: 'https://evil.example/x.svg', screenshot_urls: ['javascript:alert(1)'],
    manifest: { name: '<img src=x onerror=alert(1)>', description: '<b>bold</b>', icon: '<i>', category: 'weird-thing', tags: ['<script>'],
      auth: { method: '<b>m</b>', sso: false, notes: '"onx=1' }, links: { website: 'javascript:alert(1)', source: 'http://insecure.example/' } } }),
];
global.loadCatalogInfo = async () => { const m = {}; for (const t of CATALOG) m[t.id] = t; return m; };
global.compatWhere = c => c && c.runtime === 'kubernetes' ? 'on Kubernetes' : 'under rootless Podman';
global.compatInfo = c => !c || c.runtime !== 'podman' ? null : ({ ok: { cls: 'ok', text: 'Rootless: works' }, degraded: { cls: 'warn', text: 'Rootless: limited' }, refused: { cls: 'bad', text: 'Rootless: not available' } })[c.status] || null;
const tick = () => new Promise(r => setTimeout(r, 0));
const cards = root => visibleOf(root, n => n.attrs['data-mkt-card'] !== undefined).map(n => n.attrs['data-mkt-card']);
const btn = (root, attr, v) => findAll(root, n => n.attrs[attr] === v)[0];
`

func mktEval(t *testing.T, body string) map[string]any {
	t.Helper()
	out := nodeEval(t, mktFakeDOM+webAsset(t, "marketplace.js")+`
const M = window.PortcullisMarketplace, MT = M._test;
const root = new Node('div');
(async () => {
  const r = {};
`+body+`
  process.stdout.write(JSON.stringify(r));
})().catch(e => { process.stdout.write(JSON.stringify({ error: String(e && e.stack || e) })); });
`)
	var r map[string]any
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if e, ok := r["error"]; ok {
		t.Fatalf("node: %v", e)
	}
	return r
}

func jsonOf(v any) string {
	var b strings.Builder
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	e.Encode(v)
	return strings.TrimSpace(b.String())
}

// TestMarketplaceSearchNode: a trimmed, case-insensitive substring over
// name, description and tags; regex metacharacters are plain text; the
// empty state echoes the search as text; Clear filters resets search,
// chip and filters.
func TestMarketplaceSearchNode(t *testing.T) {
	r := mktEval(t, `
  await M.render(root, { filter: '', open: '' });
  r.all = cards(root);
  MT.search('  NEXT '); r.next = cards(root);
  MT.search('PHOTO'); r.photo = cards(root);
  MT.search('smtp'); r.tag = cards(root);
  MT.search('(.*'); r.regex = cards(root);
  MT.search('<img onerror=x>'); r.xss = cards(root);
  const empty = visibleOf(root, n => n.attrs['data-mkt-empty'] !== undefined)[0];
  r.emptyHtml = empty ? empty.html() : '';
  MT.chip('storage'); MT.toggle('sso');
  const clear = visibleOf(root, n => n.attrs['data-mkt-clear'] !== undefined)[0];
  fire(clear, 'click');
  r.cleared = cards(root);
  r.state = MT.state();
  r.input = findAll(root, n => n.attrs['data-mkt-search'] !== undefined)[0].value;
  // The input is debounced (150 ms).
  const input = findAll(root, n => n.attrs['data-mkt-search'] !== undefined)[0];
  input.value = 'wire'; fire(input, 'input');
  r.before = cards(root).length;
  await new Promise(res => setTimeout(res, 200));
  r.after = cards(root);
`)
	want := map[string]string{
		"all":     `["stalwart","smb","nextcloud","immich","wireguard","evil"]`,
		"next":    `["nextcloud"]`,
		"photo":   `["immich"]`,
		"tag":     `["stalwart"]`,
		"regex":   `[]`,
		"xss":     `[]`,
		"cleared": `["stalwart","smb","nextcloud","immich","wireguard","evil"]`,
		"state":   `{"cat":"","filters":[],"q":""}`,
		"input":   `""`,
		"before":  `6`,
		"after":   `["wireguard"]`,
	}
	for k, w := range want {
		if g := jsonOf(r[k]); g != w {
			t.Errorf("%s = %s, want %s", k, g, w)
		}
	}
	if h, _ := r["emptyHtml"].(string); !strings.Contains(h, "&lt;img onerror=x&gt;") || strings.Contains(h, "<img onerror") || !strings.Contains(h, "Clear filters") {
		t.Errorf("empty state: %s", h)
	}
}

// TestMarketplaceFiltersNode: each filter alone, aria-pressed, and ANDed
// with the category chip.
func TestMarketplaceFiltersNode(t *testing.T) {
	r := mktEval(t, `
  await M.render(root, { filter: '', open: '' });
  for (const f of ['works', 'sso', 'ai', 'multi', 'noweb', 'installed']) {
    const b = btn(root, 'data-mkt-toggle', f);
    fire(b, 'click');
    r[f] = [cards(root), b.attrs['aria-pressed']];
    fire(b, 'click');
    r[f + '-off'] = b.attrs['aria-pressed'];
  }
  MT.chip('storage'); MT.toggle('noweb'); r.storageNoweb = cards(root);
  MT.toggle('noweb'); MT.toggle('sso'); r.storageSso = cards(root);
  MT.toggle('works'); r.storageSsoWorks = cards(root);
`)
	want := map[string]string{
		"works":           `[["stalwart","smb","immich","wireguard","evil"],"true"]`,
		"sso":             `[["stalwart","nextcloud","immich"],"true"]`,
		"ai":              `[["stalwart"],"true"]`,
		"multi":           `[["nextcloud"],"true"]`,
		"noweb":           `[["smb"],"true"]`,
		"installed":       `[["immich"],"true"]`,
		"works-off":       `"false"`,
		"storageNoweb":    `["smb"]`,
		"storageSso":      `["nextcloud"]`,
		"storageSsoWorks": `[]`,
	}
	for k, w := range want {
		if g := jsonOf(r[k]); g != w {
			t.Errorf("%s = %s, want %s", k, g, w)
		}
	}
}

// TestMarketplaceCategoryOrderNode: chips by category_rank then label,
// labelled category_label, each with its count; "All" first.
func TestMarketplaceCategoryOrderNode(t *testing.T) {
	r := mktEval(t, `
  await M.render(root, { filter: '', open: '' });
  const chips = findAll(root, n => n.attrs['data-mkt-cat'] !== undefined);
  r.chips = chips.map(c => [c.attrs['data-mkt-cat'], c.textContent, c.attrs['aria-pressed']]);
  fire(chips[2], 'click');
  r.after = [cards(root), chips[2].attrs['aria-pressed'], chips[0].attrs['aria-pressed']];
`)
	want := `[["","All 6","true"],["mail","Mail 1","false"],["storage","Files & storage 2","false"],["media","Media 1","false"],["vpn","VPN 1","false"],["weird-thing","Weird thing 1","false"]]`
	if g := jsonOf(r["chips"]); g != want {
		t.Errorf("chips = %s\nwant %s", g, want)
	}
	if g := jsonOf(r["after"]); g != `[["smb","nextcloud"],"true","false"]` {
		t.Errorf("after the storage chip: %s", g)
	}
}

// TestMarketplaceDrawerNode: open(id) shows the detail drawer at
// #marketplace/<id>; Esc closes it and restores the hash; a hostile
// template's fields stay text, its non-https links and off-route images
// are dropped; the create buttons follow the cards' disabling rule.
func TestMarketplaceDrawerNode(t *testing.T) {
	r := mktEval(t, `
  await M.render(root, { filter: '', open: '' });
  await M.open('nextcloud');
  r.open = drawer.open; r.hash = location.hash;
  r.html = drawer.html();
  const esc = fire(drawer, 'keydown', { key: 'Escape' });
  r.afterEsc = [drawer.open, location.hash, !!esc.prevented];
  await M.open('evil');
  r.evil = drawer.html();
  M.close();
  r.closed = [drawer.open, location.hash];
  await M.open('immich');
  r.immich = drawer.html();
  // A create button closes the drawer first (the setup dialog isn't under it).
  const show = findAll(drawer, n => n.attrs['data-apps-filter'] === 'immich')[0];
  fire(show, 'click');
  r.closedByButton = drawer.open;
  // A card's Details opens the drawer.
  fire(btn(root, 'data-mkt-open', 'stalwart'), 'click');
  await tick(); await tick();
  r.cardOpen = [drawer.open, location.hash];
`)
	if jsonOf(r["open"]) != "true" || r["hash"] != "#marketplace/nextcloud" {
		t.Errorf("open: %v %v", r["open"], r["hash"])
	}
	h, _ := r["html"].(string)
	for _, want := range []string{
		"Nextcloud", `src="/api/catalog/nextcloud/logo.svg" alt=""`,
		`href="https://nextcloud.com/"`, "Homepage ↗", `rel="noopener noreferrer"`, `target="_blank"`, `href="https://github.com/nextcloud/server"`, "Source ↗",
		`class="md"><p>The <em>long</em> one.</p>`, "Sign-in notes", `class="md"><p>Sign in <b>with</b> Portcullis.</p>`,
		"2 settings", "Required: Admin email",
		"Single sign-on", "Multi-instance", "Runs on the primary server only (is marked placement: primary_only; &lt;b&gt;x&lt;/b&gt;)",
		"needs ≥ 2 GiB RAM", "more than this server has", "needs ≥ 10 GiB disk",
		"<li>needs a privileged port</li>", "<li>uses host networking</li>", "Rootless: not available",
		`src="/api/catalog/nextcloud/screenshots/0" alt="The files view"`, "The files view",
		`data-install="nextcloud"`, `disabled=""`, "Can&#39;t run under rootless Podman", "Install…",
	} {
		if !strings.Contains(h, strings.ReplaceAll(want, "&#39;", "'")) {
			t.Errorf("drawer lacks %q:\n%s", want, h)
		}
	}
	if i, j := strings.Index(h, "The <em>long</em>"), strings.Index(h, "Sign-in notes"); i < 0 || j < i {
		t.Error("the long description isn't before the sign-in notes")
	}
	if g := jsonOf(r["afterEsc"]); g != `[false,"#marketplace",true]` {
		t.Errorf("Esc: %s", g)
	}
	ev, _ := r["evil"].(string)
	for _, bad := range []string{"<img src=x", "javascript:", "evil.example", "http://insecure", "<b>bold</b>", "<script>", "<b>m</b>"} {
		if strings.Contains(ev, bad) {
			t.Errorf("hostile drawer has %q:\n%s", bad, ev)
		}
	}
	if !strings.Contains(ev, "&lt;img src=x onerror=alert(1)&gt;") || !strings.Contains(ev, "&lt;b&gt;bold&lt;/b&gt;") || strings.Contains(ev, "Homepage") {
		t.Errorf("hostile drawer:\n%s", ev)
	}
	if g := jsonOf(r["closed"]); g != `[false,"#marketplace"]` {
		t.Errorf("close: %s", g)
	}
	im, _ := r["immich"].(string)
	if !strings.Contains(im, "in use · 1 instance") || !strings.Contains(im, `data-apps-filter="immich"`) || !strings.Contains(im, "Partial single sign-on") || strings.Contains(im, "disabled") {
		t.Errorf("immich drawer:\n%s", im)
	}
	if jsonOf(r["closedByButton"]) != "false" {
		t.Error("a create button left the drawer open")
	}
	if g := jsonOf(r["cardOpen"]); g != `[true,"#marketplace/stalwart"]` {
		t.Errorf("card Details: %s", g)
	}
}

// TestMarketplaceCardsNode: the cards keep today's content: icon or logo
// (<img>, the catalog route only), name, mail pill, source badge,
// description, auth badges (with the landed mail and no-web-page
// badges), tags, and the footer (in use / Install…, refused disabled).
func TestMarketplaceCardsNode(t *testing.T) {
	r := mktEval(t, `
  await M.render(root, { filter: '', open: '' });
  const card = id => findAll(root, n => n.attrs['data-mkt-card'] === id)[0].html();
  for (const id of ['nextcloud', 'stalwart', 'immich', 'smb', 'evil']) r[id] = card(id);
  r.imgs = findAll(root, n => n.tag === 'img').map(n => n.src);
`)
	s := func(k string) string { v, _ := r[k].(string); return v }
	checks := map[string][]string{
		"nextcloud": {`src="/api/catalog/nextcloud/logo.svg" alt=""`, "Nextcloud", "badge-builtin", "portcullis", "Files, calendars and contacts", `class="auth-badge sso"`, "Group Access", "files", "sync",
			`data-install="nextcloud"`, `disabled=""`, "Rootless: not available", `title="Sign in with Portcullis."`},
		"stalwart": {"✉", `data-mail-badge=""`, "mail server", `data-managed-by-portcullis="stalwart"`, "Managed by Portcullis", `data-install="stalwart"`},
		"immich":   {`class="auth-badge sso-partial"`, "SSO*", "in use · 1 instance", `data-apps-filter="immich"`, "Show in Apps"},
		"smb":      {`data-no-web-page="smb"`, "No web page"},
		"evil":     {"&lt;img src=x onerror=alert(1)&gt;", "&lt;b&gt;bold&lt;/b&gt;", "&lt;script&gt;", "badge-community", "&lt;i&gt;"},
	}
	for id, wants := range checks {
		for _, w := range wants {
			if !strings.Contains(s(id), w) {
				t.Errorf("%s card lacks %q:\n%s", id, w, s(id))
			}
		}
	}
	if strings.Contains(s("immich"), "disabled") || strings.Contains(s("stalwart"), "data-no-web-page") {
		t.Error("wrong badge or button state")
	}
	if g := jsonOf(r["imgs"]); g != `["/api/catalog/nextcloud/logo.svg"]` {
		t.Errorf("card images: %s", g)
	}
}

// TestMarketplaceDeepLinksNode: index.html's routes with the real
// marketplace.js: #marketplace shows it in Apps (the Apps tab active);
// ?filter=mail pre-selects the Mail chip; #marketplace/stalwart opens its
// drawer; an unknown id shows the list and a toast.
func TestMarketplaceDeepLinksNode(t *testing.T) {
	src := webAsset(t, "index.html")
	block, _ := hubRoutes(t)
	r := mktEval(t, `
  const calls = [];
  let usageView = 'apps', accessView = null, settingsView = { section: '' };
  const PortcullisPeople = { href: f => f };
  const showTab = n => { calls.push(['showTab', n]); return true; };
  const setMarketplaceShown = on => calls.push(['shown', on]);
  document.getElementById = id => id === 'mkt-drawer' ? drawer : id === 'mkt-root' ? root : null;
  `+hubFunc(t, src, "peopleRedirect")+hubFunc(t, src, "showMarketplace")+block+hubFunc(t, src, "routeTo")+hubFunc(t, src, "routeHash")+`
  const go = async h => { calls.length = 0; toasts.length = 0; location.hash = h; routeHash(); for (let i = 0; i < 5; i++) await tick(); return calls.slice(); };
  r.plain = [await go('#marketplace'), cards(root).length];
  r.mail = [await go('#marketplace?filter=mail'), findAll(root, n => n.attrs['data-mkt-cat'] === 'mail')[0].attrs['aria-pressed'], cards(root)];
  r.open = [await go('#marketplace/stalwart'), drawer.open, location.hash, drawer.html().indexOf('Stalwart') >= 0];
  M.close();
  r.unknown = [await go('#marketplace/stalwartx'), drawer.open, toasts.slice(), location.hash];
`)
	want := map[string]string{
		"plain":   `[[["showTab","apps"],["shown",true]],6]`,
		"mail":    `[[["showTab","apps"],["shown",true]],"true",["stalwart"]]`,
		"open":    `[[["showTab","apps"],["shown",true]],true,"#marketplace/stalwart",true]`,
		"unknown": `[[["showTab","apps"],["shown",true]],false,[["No template stalwartx","error"]],"#marketplace"]`,
	}
	for k, w := range want {
		if g := jsonOf(r[k]); g != w {
			t.Errorf("%s = %s\nwant %s", k, g, w)
		}
	}
}

// TestMarketplaceRefreshKeepsNodes (I1): a poll with nothing changed
// keeps every card and the open drawer (the same nodes: focus stays); a
// changed instance count rebuilds them, focus restored on the control
// with the same key; closing the drawer focuses the template's Details.
func TestMarketplaceRefreshKeepsNodes(t *testing.T) {
	r := mktEval(t, `
  await M.render(root, { filter: '', open: '' });
  const cardNode = id => findAll(root, n => n.attrs['data-mkt-card'] === id)[0];
  const before = cardNode('stalwart');
  fire(btn(root, 'data-mkt-open', 'immich'), 'click');
  for (let i = 0; i < 4; i++) await tick();
  r.initialFocus = global.focused && global.focused.attrs['data-mkt-close'] !== undefined;
  const box = drawer.kids[0];
  const show = findAll(drawer, n => n.attrs['data-apps-filter'] === 'immich')[0];
  show.focus();
  await M.refresh();
  r.same = [cardNode('stalwart') === before, drawer.kids[0] === box, global.focused === show];
  // One more immich instance: its card and the drawer change.
  instancesCache.push({ id: 'immich-2', template: 'immich' });
  await M.refresh();
  r.changed = [cardNode('stalwart') === before, drawer.kids[0] === box, global.focused !== show && global.focused.attrs['data-apps-filter'] === 'immich', drawer.html().indexOf('in use · 2 instances') >= 0];
  // Closing the drawer focuses the template's Details.
  M.close();
  r.backToDetails = !!global.focused && global.focused.attrs['data-mkt-open'] === 'immich';
  // Focus on a card's control survives that card being rebuilt (the
  // same key, a new node); the other cards stay the same nodes.
  const showBtn = () => findAll(root, n => n.attrs['data-apps-filter'] === 'immich' && n.attrs['data-mkt-open'] === undefined)[0];
  const old = showBtn();
  old.focus();
  instancesCache.push({ id: 'immich-3', template: 'immich' });
  await M.refresh();
  r.listFocus = [cardNode('stalwart') === before, showBtn() !== old, global.focused === showBtn()];
`)
	want := map[string]string{
		"initialFocus":  `true`,
		"same":          `[true,true,true]`,
		"changed":       `[true,false,true,true]`,
		"backToDetails": `true`,
		"listFocus":     `[true,true,true]`,
	}
	for k, w := range want {
		if g := jsonOf(r[k]); g != w {
			t.Errorf("%s = %s, want %s", k, g, w)
		}
	}
}

// TestMarketplaceReloadNode (M1): refresh({reload: true}) reads the
// catalog again (refreshCatalog); a template gone closes its drawer.
func TestMarketplaceReloadNode(t *testing.T) {
	r := mktEval(t, `
  let reloads = 0;
  global.refreshCatalog = async () => { reloads++; const i = CATALOG.findIndex(t => t.id === 'immich'); CATALOG.splice(i, 1); };
  await M.render(root, { filter: '', open: '' });
  await M.open('immich');
  await M.refresh();
  r.plain = [reloads, drawer.open, cards(root).indexOf('immich') >= 0];
  await M.refresh({ reload: true });
  r.reload = [reloads, drawer.open, cards(root).indexOf('immich') >= 0, location.hash];
`)
	if g := jsonOf(r["plain"]); g != `[0,true,true]` {
		t.Errorf("plain refresh: %s", g)
	}
	if g := jsonOf(r["reload"]); g != `[1,false,false,"#marketplace"]` {
		t.Errorf("reload: %s", g)
	}
}

// TestMarketplaceStaleNode (M2): an open() still waiting for /api/usage
// when the admin leaves (the Marketplace hidden) or closes it opens
// nothing and leaves the hash alone; a newer open() wins.
func TestMarketplaceStaleNode(t *testing.T) {
	r := mktEval(t, `
  let answer;
  global.apiGet = () => new Promise(res => { answer = res; });
  await M.render(root, { filter: '', open: '' });
  location.hash = '#marketplace';
  const p = M.open('nextcloud');
  await tick();
  root.hidden = true;
  location.hash = '#doctor';
  answer({ hosts: { primary: { memory_bytes: 1 } } });
  r.left = [await p, !!drawer.open, location.hash];
  root.hidden = false;
  location.hash = '#marketplace';
  r.again = [await M.open('nextcloud'), drawer.open, location.hash];
  M.close();
  // A render that's overtaken by another drops its draw.
  let slow;
  global.loadCatalogInfo = () => new Promise(res => { slow = res; });
  const r1 = M.render(root, { filter: 'mail', open: '' });
  global.loadCatalogInfo = async () => { const m = {}; for (const t of CATALOG) m[t.id] = t; return m; };
  await M.render(root, { filter: '', open: 'stalwart' });
  const m = {}; for (const t of CATALOG) m[t.id] = t; slow(m); await r1;
  r.overtaken = [drawer.open, location.hash, MT.state().cat];
`)
	want := map[string]string{
		"left":      `[false,false,"#doctor"]`,
		"again":     `[true,true,"#marketplace/nextcloud"]`,
		"overtaken": `[true,"#marketplace/stalwart","mail"]`,
	}
	for k, w := range want {
		if g := jsonOf(r[k]); g != w {
			t.Errorf("%s = %s, want %s", k, g, w)
		}
	}
}

// TestMarketplaceOtherCategoryNode (M3, nits 2–4): a template naming no
// category is under "Other", last (never a second "All"); an unknown
// ?filter= category falls back to all with a toast; a decomposed é
// matches a precomposed one; a hidden "Works here" isn't left pressed.
func TestMarketplaceOtherCategoryNode(t *testing.T) {
	r := mktEval(t, `
  CATALOG.push(T('nocat', { category_rank: 1000, category_label: '', manifest: { name: 'Caf\u00e9 board', description: 'no category', category: '' } }));
  await M.render(root, { filter: '', open: '' });
  r.chips = findAll(root, n => n.attrs['data-mkt-cat'] !== undefined).map(c => [c.attrs['data-mkt-cat'], c.textContent]);
  MT.chip('other'); r.other = cards(root); MT.chip('');
  MT.search('cafe\u0301'); r.nfd = cards(root); MT.search('');
  await M.render(root, { filter: 'nosuch', open: '' });
  r.nosuch = [MT.state().cat, toasts.slice(), cards(root).length];
  MT.toggle('works');
  for (const t of CATALOG) t.compat = null;
  MT.chip('');
  r.works = [MT.state().filters, btn(root, 'data-mkt-toggle', 'works').hidden];
`)
	want := map[string]string{
		"chips":  `[["","All 7"],["mail","Mail 1"],["storage","Files & storage 2"],["media","Media 1"],["vpn","VPN 1"],["weird-thing","Weird thing 1"],["other","Other 1"]]`,
		"other":  `["nocat"]`,
		"nfd":    `["nocat"]`,
		"nosuch": `["",[["No category nosuch","error"]],7]`,
		"works":  `[[],true]`,
	}
	for k, w := range want {
		if g := jsonOf(r[k]); g != w {
			t.Errorf("%s = %s, want %s", k, g, w)
		}
	}
}
