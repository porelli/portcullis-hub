// Portcullis Hub — the Marketplace: Apps' "+ Add app" (Hub listener only).
//
//   window.PortcullisMarketplace.render(root, {filter, open})
//       the Marketplace into root (#mkt-root): search, category chips,
//       filters and the cards; filter pre-selects a category chip
//       (#marketplace?filter=mail), open a template's drawer
//       (#marketplace/<id>). Answers a promise (the catalog read).
//   window.PortcullisMarketplace.open(id)    the detail drawer
//       (<dialog id="mkt-drawer">), at #marketplace/<id>; an unknown id:
//       a toast, the list stays
//   window.PortcullisMarketplace.close()     closes it (#marketplace)
//   window.PortcullisMarketplace.refresh()   redraws (instances changed)
//
// The catalog is GET /api/templates (index.html's loadCatalogInfo):
// third-party manifests. Rules of this file:
//   - every node is built with el(); manifest values are text or
//     attributes. The only markup inserted is the Hub's server-side
//     sanitised Markdown (long_description_html, auth.notes_html), into
//     class="md" containers;
//   - logos and screenshots are <img> elements whose src is a catalog
//     asset route (/api/catalog/…), never inline SVG;
//   - links are https only (safeHref), opened with rel="noopener
//     noreferrer";
//   - the search is a plain case-insensitive substring (no RegExp from
//     the input).
// The create buttons are the page's (data-install, data-add-instance,
// data-apps-filter: index.html's delegated handlers); a click on one in
// the drawer closes the drawer first.
(function () {
  'use strict';

  const LOGO_PREFIX = '/api/catalog/';
  const FILTERS = [['works', 'Works here'], ['sso', 'SSO'], ['ai', 'AI'], ['multi', 'Multi-instance'], ['noweb', 'No web page'], ['installed', 'Installed']];
  const MAIL_TITLE = 'Mail is managed in Portcullis (Settings → Mail and the instance\'s Mail tab), so Portcullis\'s mail safeguards always apply. A full administrator can open the mail server\'s own admin screen read-only.';
  const NOWEB_TITLE = 'This app has no web page: people use it with its own client (see My apps)';

  // OTHER: the category of a template that names none (last).
  const OTHER = { slug: 'other', label: 'Other', rank: Number.MAX_SAFE_INTEGER };
  // The keys a focused control is found again by after a redraw.
  const FOCUS_KEYS = ['data-mkt-open', 'data-install', 'data-add-instance', 'data-apps-filter', 'data-mkt-close', 'data-mkt-clear'];

  const st = { q: '', raw: '', cat: '', filters: new Set() };
  // gen: bumped by render, open and close; an async step whose
  // generation is no longer current is dropped (the admin moved on).
  // listGen: bumped when the catalog's template objects change.
  let root = null, parts = null, list = [], timer = null, opened = '', hostMem, gen = 0, listGen = 0, drawerSig = '';

  // el(tag, props, ...children): props {class, text, on: {event: fn},
  // value, disabled, hidden, …attributes}; children: nodes or strings.
  function el(tag, props, ...kids) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) {
      if (v == null || v === false) continue;
      if (k === 'class') n.className = v;
      else if (k === 'text') n.textContent = String(v);
      else if (k === 'on') for (const [ev, fn] of Object.entries(v)) n.addEventListener(ev, fn);
      else if (k === 'value') n.value = String(v);
      else if (k === 'disabled' || k === 'hidden') n[k] = !!v;
      else n.setAttribute(k, String(v));
    }
    for (const c of kids.flat(Infinity)) {
      if (c == null || c === false) continue;
      n.appendChild(typeof c === 'string' || typeof c === 'number' ? document.createTextNode(String(c)) : c);
    }
    return n;
  }
  const str = v => (v == null ? '' : String(v));
  // fill(n, ...kids): n's children replaced by kids (arrays flattened,
  // null and false skipped: replaceChildren alone would print them).
  function fill(n, ...kids) {
    n.replaceChildren(...kids.flat(Infinity).filter(c => c != null && c !== false).map(c => (typeof c === 'number' ? String(c) : c)));
    return n;
  }
  // safeHref: an https URL as given, else null (no link).
  const safeHref = u => (typeof u === 'string' && u.slice(0, 8).toLowerCase() === 'https://' ? u : null);
  // norm: what the search compares (NFKC, lower case: a decomposed é
  // matches a precomposed one).
  const norm = v => str(v).normalize('NFKC').toLowerCase();
  // shown: the Marketplace is on screen (Apps shows #mkt-root).
  const shown = () => !!root && !root.hidden;
  const assetOK = u => typeof u === 'string' && u.slice(0, LOGO_PREFIX.length) === LOGO_PREFIX;
  function up(n, attr) {
    for (; n && n.getAttribute; n = n.parentNode) if (n.getAttribute(attr) != null) return n;
    return null;
  }
  function instCount(id) {
    const all = typeof instancesCache !== 'undefined' ? instancesCache : [];
    return (all || []).filter(i => i.template === id).length;
  }

  // ── matching ───────────────────────────────────────────────
  const FILTER_TEST = {
    works: t => !(t.compat && t.compat.status === 'refused'),
    sso: t => { const v = ((t.manifest || {}).auth || {}).sso; return v === true || v === 'partial'; },
    ai: t => !!(t.manifest.ai && (t.manifest.ai.mcp || []).length),
    multi: t => t.manifest.instances === 'multi',
    noweb: t => !!t.routerless,
    installed: t => instCount(t.id) > 0,
  };
  // matches: t passes the search, the filters and (unless anyCat) the
  // category chip.
  function catOf(t) {
    const slug = str(t.manifest.category);
    return slug ? { slug, label: str(t.category_label || slug), rank: t.category_rank } : OTHER;
  }
  function matches(t, anyCat) {
    const m = t.manifest || {};
    if (!anyCat && st.cat && catOf(t).slug !== st.cat) return false;
    if (st.q) {
      const hay = norm([m.name, m.description].concat(m.tags || []).map(str).join(' '));
      if (hay.indexOf(st.q) < 0) return false;
    }
    for (const f of st.filters) if (!FILTER_TEST[f](t)) return false;
    return true;
  }
  function byOrder(a, b) {
    const ca = catOf(a), cb = catOf(b);
    return (ca.rank - cb.rank) || ca.label.localeCompare(cb.label) ||
      str(a.manifest.name).toLowerCase().localeCompare(str(b.manifest.name).toLowerCase()) || a.id.localeCompare(b.id);
  }
  function categories() {
    const out = new Map();
    for (const t of list) {
      const c = catOf(t);
      if (!out.has(c.slug)) out.set(c.slug, { slug: c.slug, label: c.label, rank: c.rank, count: 0 });
      if (matches(t, true)) out.get(c.slug).count++;
    }
    return [...out.values()].sort((a, b) => (a.rank - b.rank) || a.label.localeCompare(b.label));
  }

  // ── pieces ─────────────────────────────────────────────────
  function logoImg(t, cls) {
    if (!assetOK(t.logo_url)) return null;
    const img = document.createElement('img');
    img.src = t.logo_url;
    img.alt = '';
    img.className = cls;
    return img;
  }
  function iconOf(t, cls) { return logoImg(t, cls + '-logo') || el('span', { class: cls, text: t.manifest.icon }); }
  function compatOf(t) {
    const c = t.compat;
    const info = c && typeof compatInfo === 'function' ? compatInfo(c) : null;
    return { c, info, refused: !!(info && c.status === 'refused') };
  }
  function compatPill(t) {
    const { c, info } = compatOf(t);
    if (!info) return null;
    const why = (c.reasons || []).join('; ');
    return el('span', { class: 'pill ' + info.cls, 'data-compat-badge': c.status, title: why || null, text: info.text });
  }
  // footer: the card's and the drawer's create buttons (a refused
  // template's are disabled, as the Hub refuses it: 409).
  function footer(t) {
    const n = instCount(t.id);
    const { c, refused } = compatOf(t);
    const off = refused ? 'Can\'t run ' + compatWhere(c) + ': ' + (c.reasons || []).join('; ') : null;
    const add = t.manifest.instances === 'multi'
      ? el('button', { type: 'button', class: 'btn btn-secondary btn-sm', 'data-add-instance': t.id, disabled: refused, title: off, text: '+ Add instance' }) : null;
    return [compatPill(t), n
      ? [el('span', { class: 'pill ok', text: 'in use · ' + n + (n === 1 ? ' instance' : ' instances') }),
        el('button', { type: 'button', class: 'btn btn-secondary btn-sm', 'data-apps-filter': t.id, text: 'Show in Apps' }), add]
      : el('button', { type: 'button', class: 'btn btn-primary btn-sm', 'data-install': t.id, disabled: refused, title: off, text: 'Install…' })];
  }
  // noteTitle: the sign-in notes' first paragraph, as plain text (the
  // method badge's tooltip).
  function noteTitle(a) {
    const first = str(a.notes).split(/\n\s*\n/)[0];
    return first.replace(/\s+/g, ' ').trim() || null;
  }
  function authBadges(t) {
    const a = t.manifest.auth || {};
    if (!a.method) return [];
    const out = [];
    if (a.sso === true) out.push(el('span', { class: 'auth-badge sso', title: 'Full Single Sign-On support', text: 'SSO' }));
    else if (a.sso === 'partial') out.push(el('span', { class: 'auth-badge sso-partial', title: 'Partial SSO via proxy auth header', text: 'SSO*' }));
    if (t.mail_provider) out.push(el('span', { class: 'auth-badge method', 'data-managed-by-portcullis': t.id, title: MAIL_TITLE, text: 'Managed by Portcullis' }));
    else if (t.routerless) out.push(el('span', { class: 'auth-badge method', 'data-no-web-page': t.id, title: NOWEB_TITLE, text: 'No web page' }));
    if (a.group_access) out.push(el('span', { class: 'auth-badge group', title: 'Access restricted by LLDAP group', text: 'Group Access' }));
    if (a.group_admin) out.push(el('span', { class: 'auth-badge group-admin', title: 'Admin role assigned by LLDAP group', text: 'Group Admin' }));
    if (a.method === 'public') out.push(el('span', { class: 'auth-badge public', text: 'Public' }));
    else out.push(el('span', { class: 'auth-badge method', title: noteTitle(a), text: a.method }));
    return out;
  }
  function card(t) {
    const m = t.manifest;
    return el('div', { class: 'app-card', 'data-mkt-card': t.id, 'data-id': t.id },
      el('div', { class: 'app-header' }, iconOf(t, 'app-icon'), el('span', { class: 'app-name', text: m.name }),
        t.mail_provider ? el('span', { class: 'pill', 'data-mail-badge': '', text: 'mail server' }) : null,
        el('span', { class: 'app-source ' + (t.source === 'portcullis' ? 'badge-builtin' : 'badge-community'), text: t.source })),
      el('div', { class: 'app-desc', text: m.description }),
      el('div', { class: 'app-auth' }, authBadges(t)),
      el('div', { class: 'app-tags' }, (m.tags || []).map(g => el('span', { class: 'tag', text: g }))),
      el('div', { class: 'app-footer', 'data-mkt-use': t.id }, footer(t),
        el('button', { type: 'button', class: 'btn btn-sm mkt-details', 'data-mkt-open': t.id, text: 'Details', on: { click: () => open(t.id) } })));
  }

  // ── the list ───────────────────────────────────────────────
  function build(r) {
    const search = el('input', { type: 'search', class: 'mkt-search', 'data-mkt-search': '', placeholder: 'Search apps by name, description or tag', 'aria-label': 'Search apps', autocomplete: 'off', value: st.raw });
    search.addEventListener('input', () => {
      clearTimeout(timer);
      timer = setTimeout(() => setSearch(search.value), 150);
    });
    parts = {
      root: r, search,
      chips: el('div', { class: 'mkt-chips', role: 'group', 'aria-label': 'Categories' }),
      toggles: el('div', { class: 'mkt-toggles', role: 'group', 'aria-label': 'Filters' }),
      results: el('div', { class: 'mkt-results', 'aria-live': 'polite' }),
    };
    fill(r, 
      el('div', { class: 'page-crumbs' }, el('a', { href: '#apps', 'data-goto-tab': 'apps', text: '← Apps' }), ' › Add an app'),
      el('div', { class: 'mkt-bar' }, search), parts.chips, parts.toggles, parts.results);
  }

  function draw() {
    if (!parts) return;
    const cats = categories();
    const all = list.filter(t => matches(t, true)).length;
    // The chips and toggles are kept across draws (focus stays on the
    // one pressed); only their counts and aria-pressed change. The
    // chips are rebuilt when the categories change (a source sync).
    const key = cats.map(c => c.slug + '\u0000' + c.label).join('\u0001');
    if (parts.chipKey !== key) {
      parts.chipKey = key;
      parts.chipBtns = [['', 'All']].concat(cats.map(c => [c.slug, c.label])).map(([slug, label]) => {
        const count = el('span', { class: 'mkt-count' });
        const b = el('button', { type: 'button', class: 'mkt-chip', 'data-mkt-cat': slug, on: { click: () => setChip(slug) } }, label, ' ', count);
        return { slug, b, count };
      });
      fill(parts.chips, parts.chipBtns.map(c => c.b));
    }
    const counts = new Map(cats.map(c => [c.slug, c.count]));
    for (const c of parts.chipBtns) {
      c.count.textContent = String(c.slug === '' ? all : counts.get(c.slug) || 0);
      c.b.setAttribute('aria-pressed', st.cat === c.slug ? 'true' : 'false');
    }
    if (!parts.toggleBtns) {
      parts.toggleBtns = FILTERS.map(([f, label]) => ({ f, b: el('button', { type: 'button', class: 'mkt-toggle', 'data-mkt-toggle': f, on: { click: () => toggle(f) } }, label) }));
      fill(parts.toggles, parts.toggleBtns.map(x => x.b));
    }
    const withCompat = list.some(t => t.compat);
    // A hidden "Works here" isn't left pressed.
    if (!withCompat) st.filters.delete('works');
    for (const x of parts.toggleBtns) {
      x.b.setAttribute('aria-pressed', st.filters.has(x.f) ? 'true' : 'false');
      x.b.hidden = x.f === 'works' && !withCompat;
    }
    const hits = list.filter(t => matches(t, false));
    // The cards are rebuilt only when what they show changed (the poll
    // redraws every 15 s): focus and the screen reader's place survive.
    const sig = listGen + '|' + st.raw + '|' + hits.map(cardSig).join(';');
    if (parts.resultsSig === sig) return;
    parts.resultsSig = sig;
    const focus = focusKey(parts.results);
    if (!hits.length) {
      fill(parts.results, el('div', { class: 'empty', 'data-mkt-empty': '' },
        el('p', { text: st.raw ? 'No app matches “' + st.raw + '” with these filters.' : 'No app matches these filters.' }),
        el('button', { type: 'button', class: 'btn btn-secondary btn-sm', 'data-mkt-clear': '', text: 'Clear filters', on: { click: clearAll } })));
    } else {
      const groups = [];
      for (const c of cats) {
        const ts = hits.filter(t => catOf(t).slug === c.slug).sort(byOrder);
        if (ts.length) groups.push(el('div', { class: 'category' }, el('div', { class: 'category-title', text: c.label }), el('div', { class: 'apps' }, ts.map(cachedCard))));
      }
      fill(parts.results, groups);
    }
    restoreFocus(parts.results, focus);
  }
  // cachedCard: t's card, the same node while its signature holds (only
  // a changed card is built again).
  const cardCache = new Map();
  function cachedCard(t) {
    const sig = listGen + '|' + cardSig(t);
    const hit = cardCache.get(t.id);
    if (hit && hit.sig === sig) return hit.node;
    const node = card(t);
    cardCache.set(t.id, { sig, node });
    return node;
  }
  // cardSig: what a card shows besides its template (instances, verdict).
  function cardSig(t) {
    const { info, refused } = compatOf(t);
    return t.id + ':' + instCount(t.id) + ':' + (info ? info.cls + info.text : '') + ':' + refused;
  }
  // focusKey(box): the focused control in box as [attribute, value], or
  // null; restoreFocus focuses its replacement after a redraw.
  function focusKey(box) {
    const a = document.activeElement;
    if (!a || !a.getAttribute || !contains(box, a)) return null;
    for (const k of FOCUS_KEYS) if (a.getAttribute(k) != null) return [k, a.getAttribute(k)];
    return null;
  }
  function contains(box, n) {
    for (; n; n = n.parentNode) if (n === box) return true;
    return false;
  }
  function find(box, k, v) {
    const want = n => n.getAttribute && n.getAttribute(k) === v;
    const stack = [box];
    while (stack.length) {
      const n = stack.pop();
      if (n !== box && want(n)) return n;
      for (const c of Array.from(n.children || [])) stack.push(c);
    }
    return null;
  }
  function restoreFocus(box, key) {
    if (!key) return;
    const n = find(box, key[0], key[1]);
    if (n && n.focus) n.focus();
  }

  function setSearch(v) {
    st.raw = str(v).trim();
    st.q = norm(st.raw);
    draw();
  }
  function setChip(slug) { st.cat = slug; draw(); }
  function toggle(f) {
    if (st.filters.has(f)) st.filters.delete(f); else st.filters.add(f);
    draw();
  }
  function clearAll() {
    st.q = ''; st.raw = ''; st.cat = ''; st.filters.clear();
    if (parts) parts.search.value = '';
    draw();
  }

  async function load() {
    const cat = await loadCatalogInfo();
    const next = Object.values(cat || {}).sort(byOrder);
    if (next.length !== list.length || next.some((t, i) => t !== list[i])) listGen++;
    list = next;
  }

  async function render(r, o) {
    const g = ++gen;
    root = r;
    if (!parts || parts.root !== r) build(r);
    if (o && o.filter) st.cat = o.filter;
    try {
      await load();
    } catch (e) {
      if (g === gen) fill(parts.results, el('p', { class: 'public-warn', text: 'Couldn’t read the templates: ' + str(e && e.message) }));
      return;
    }
    if (g !== gen || !shown()) return;
    // An unknown ?filter= category: all of them, said once.
    if (st.cat && !list.some(t => catOf(t).slug === st.cat)) {
      showToast('No category ' + st.cat, 'error');
      st.cat = '';
      if (String(location.hash).indexOf('#marketplace?') === 0) history.replaceState(null, '', '#marketplace');
    }
    draw();
    if (o && o.open) await open(o.open);
    else if (opened) close();
  }

  // ── the drawer ─────────────────────────────────────────────
  const drawer = () => document.getElementById('mkt-drawer');
  let drawerWired = null;
  function wireDrawer(d) {
    if (drawerWired === d) return;
    drawerWired = d;
    d.addEventListener('keydown', e => { if (e.key === 'Escape') { e.preventDefault(); close(); } });
    // A create button closes the drawer before the page's handler opens
    // the setup dialog (which isn't in the top layer).
    d.addEventListener('click', e => {
      if (up(e.target, 'data-install') || up(e.target, 'data-add-instance') || up(e.target, 'data-apps-filter') || up(e.target, 'data-mkt-close')) close();
    }, true);
    // Closed (Esc, ×, a create button, leaving): the hash back to the
    // list, and focus back on the template's Details — only while the
    // Marketplace is still shown.
    d.addEventListener('close', () => {
      const was = d.getAttribute('data-mkt-for');
      opened = '';
      drawerSig = '';
      if (!shown()) return;
      if (String(location.hash).indexOf('#marketplace/') === 0) history.replaceState(null, '', '#marketplace');
      if (was && parts) restoreFocus(parts.results, ['data-mkt-open', was]);
    });
  }
  async function loadHostMem() {
    if (hostMem !== undefined) return;
    hostMem = null;
    try {
      const v = await apiGet('/api/usage');
      const p = v && v.hosts && v.hosts.primary;
      if (p && typeof p.memory_bytes === 'number') hostMem = p.memory_bytes;
    } catch (_) { /* no figure: no warning */ }
  }
  function fmtMiB(mib) {
    if (mib < 1024) return mib + ' MiB';
    const g = mib / 1024;
    return (Number.isInteger(g) ? String(g) : g.toFixed(1)) + ' GiB';
  }
  function capabilities(t) {
    const m = t.manifest, a = m.auth || {}, out = [];
    if (a.sso === true) out.push('Single sign-on');
    else if (a.sso === 'partial') out.push('Partial single sign-on (through the proxy header)');
    const ai = (m.ai && m.ai.mcp) || [];
    if (ai.length) out.push('AI support: ' + ai.length + (ai.length === 1 ? ' companion' : ' companions'));
    if (m.vpn) out.push('Can be a VPN provider');
    if (t.mail_provider) out.push('Can be this server’s mail provider');
    if (m.instances === 'multi') out.push('Multi-instance');
    if (t.routerless) out.push('No web page (people use its own client)');
    if (m.placement === 'primary_only') out.push('Runs on the primary server only');
    return out;
  }
  function drawerBody(t) {
    const m = t.manifest, a = m.auth || {}, links = m.links || {};
    const home = safeHref(links.website), src = safeHref(links.source);
    const head = el('div', { class: 'mkt-drawer-head' }, iconOf(t, 'mkt-drawer-icon'), el('h3', { id: 'mkt-drawer-title', text: m.name }),
      el('button', { type: 'button', class: 'btn btn-sm mkt-close', 'data-mkt-close': '', 'aria-label': 'Close', text: '×' }));
    const linkAttrs = { target: '_blank', rel: 'noopener noreferrer' };
    const meta = el('p', { class: 'mkt-meta' },
      home ? el('a', Object.assign({ href: home, text: 'Homepage ↗' }, linkAttrs)) : null,
      home && (src || links.source_note) ? ' · ' : null,
      src ? el('a', Object.assign({ href: src, text: 'Source ↗' }, linkAttrs)) : (links.source_note ? el('span', { text: links.source_note }) : null),
      ' · ', el('span', { text: t.category_label }), ' · from ', el('span', { text: t.source }));
    let about;
    if (m.long_description_html) {
      const long = el('div', { class: 'md' });
      long.innerHTML = t.manifest.long_description_html;
      about = long;
    } else about = el('p', { text: m.description });
    let notesPart = null;
    if (a.notes_html) {
      const notes = el('div', { class: 'md' });
      notes.innerHTML = t.manifest.auth.notes_html;
      notesPart = [el('h4', { text: 'Sign-in notes' }), notes];
    }
    const opts = (m.settings && m.settings.options) || [];
    const req = opts.filter(o => o.required).map(o => str(o.label || o.key));
    const caps = capabilities(t);
    const r = m.resources || {};
    const res = [];
    if (typeof r.min_memory_mib === 'number') {
      const low = typeof hostMem === 'number' && hostMem < r.min_memory_mib * 1048576;
      res.push(el('li', null, 'needs ≥ ' + fmtMiB(r.min_memory_mib) + ' RAM',
        low ? [' ', el('span', { class: 'pill warn', text: 'more than this server has (' + fmtMiB(Math.round(hostMem / 1048576)) + ')' })] : null));
    }
    if (typeof r.min_disk_gib === 'number') res.push(el('li', { text: 'needs ≥ ' + r.min_disk_gib + ' GiB disk' }));
    const { c, info } = compatOf(t);
    const shots = (t.screenshot_urls || []).map((u, i) => {
      if (!assetOK(u)) return null;
      const cap = str(((m.screenshots || [])[i] || {}).caption);
      const s = document.createElement('img');
      s.src = u;
      s.alt = cap;
      s.className = 'mkt-shot';
      return el('figure', null, s, cap ? el('figcaption', { text: cap }) : null);
    }).filter(Boolean);
    return [head, meta, about, notesPart,
      el('h4', { text: 'Settings' }),
      el('p', { text: opts.length ? opts.length + (opts.length === 1 ? ' setting' : ' settings') + (req.length ? ' · Required: ' + req.join(', ') : '') : 'Nothing to fill in.' }),
      el('h4', { text: 'Capabilities' }),
      caps.length ? el('ul', null, caps.map(x => el('li', { text: x }))) : el('p', { class: 'settings-empty', text: 'None of note.' }),
      res.length ? [el('h4', { text: 'Resources' }), el('ul', null, res)] : null,
      info ? [el('h4', { text: 'On this server' }), el('p', null, compatPill(t)), (c.reasons || []).length ? el('ul', null, c.reasons.map(x => el('li', { text: x }))) : null] : null,
      shots.length ? [el('h4', { text: 'Screenshots' }), el('div', { class: 'mkt-shots' }, shots)] : null,
      el('div', { class: 'app-footer mkt-drawer-foot', 'data-mkt-use': t.id }, footer(t))];
  }

  function drawSig(t) { return listGen + '|' + cardSig(t) + '|' + hostMem; }
  function fillDrawer(d, t) {
    const focus = focusKey(d);
    fill(d, el('div', { class: 'mkt-drawer-box' }, drawerBody(t)));
    d.setAttribute('data-mkt-for', t.id);
    drawerSig = drawSig(t);
    restoreFocus(d, focus);
  }

  async function open(id) {
    const g = ++gen;
    if (!list.length) { try { await load(); } catch (_) { /* below: unknown */ } }
    if (g !== gen || !shown()) return false;
    const t = list.find(x => x.id === id);
    if (!t) {
      showToast('No template ' + id, 'error');
      if (String(location.hash).indexOf('#marketplace/') === 0) history.replaceState(null, '', '#marketplace');
      return false;
    }
    await loadHostMem();
    if (g !== gen || !shown()) return false;
    const d = drawer();
    if (!d) return false;
    wireDrawer(d);
    d.setAttribute('aria-labelledby', 'mkt-drawer-title');
    // The same template already open (a deep link to it again): kept.
    if (!(d.open && opened === id && drawerSig === drawSig(t))) fillDrawer(d, t);
    if (!d.open) {
      d.showModal();
      // Initial focus: the close button (the heading follows it for a
      // screen reader through aria-labelledby).
      const x = find(d, 'data-mkt-close', '');
      if (x) x.focus();
    }
    opened = id;
    history.replaceState(null, '', '#marketplace/' + encodeURIComponent(id));
    return true;
  }
  function close() {
    ++gen;
    const d = drawer();
    if (d && d.open) d.close();
    opened = '';
  }
  // refresh({reload}): redraws what changed (the instances poll); reload
  // reads the catalog again first (a template source changed) and closes
  // the drawer when its template is gone.
  async function refresh(o) {
    if (o && o.reload) {
      try {
        if (typeof refreshCatalog === 'function') await refreshCatalog();
        await load();
      } catch (_) { return; }
    }
    if (!shown()) return;
    draw();
    if (!opened) return;
    const t = list.find(x => x.id === opened), d = drawer();
    if (!t) { close(); return; }
    if (d && d.open && drawerSig !== drawSig(t)) fillDrawer(d, t);
  }

  window.PortcullisMarketplace = {
    render, open, close, refresh,
    _test: {
      search: setSearch, chip: setChip, toggle,
      state: () => ({ cat: st.cat, filters: [...st.filters], q: st.q }),
    },
  };
})();
