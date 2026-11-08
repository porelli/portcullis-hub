// Portcullis Hub: Users & Groups (People | Groups | Org chart | Setup).
//
// Served on people.<domain> (every signed-in user; people.html). The Hub
// page (index.html) loads it only for its Audit log tab (renderAudit).
// Vanilla JS, no build step.
//
// Rules of this file:
//   - every server string goes through esc() (or textContent) before it
//     reaches innerHTML;
//   - no inline event handlers: elements carry escaped data-* attributes
//     and a few delegated listeners read them back;
//   - the UI hides controls the caller may not use, but the API decides
//     (403s are shown, never assumed away).
(function () {
  'use strict';

  // ── helpers ─────────────────────────────────────────────
  // Escapes for element content and quoted attribute values alike.
  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
  const enc = encodeURIComponent;
  const PERMS = [
    ['edit_details', 'Edit details', 'change people\'s details, one by one or by CSV import'],
    ['invite', 'Invite people', 'create accounts (no groups) and re-invite the ones they created'],
    ['remove', 'Remove people', 'delete accounts'],
  ];

  // api answers the parsed JSON body, or throws an Error with .status and,
  // for rule parse errors ({error, column}), .column. Error bodies are
  // plain text except those.
  async function api(method, url, body) {
    const opts = { method, headers: {}, credentials: 'same-origin' };
    if (body !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    return finish(await fetch(url, opts));
  }
  async function finish(res) {
    const text = await res.text();
    if (!res.ok) {
      let msg = text.trim(), column;
      try {
        const j = JSON.parse(text);
        if (j && typeof j.error === 'string') { msg = j.error; column = j.column; }
      } catch (_) { /* plain text */ }
      const err = new Error(msg || ('HTTP ' + res.status));
      err.status = res.status;
      err.column = column;
      throw err;
    }
    return text ? JSON.parse(text) : {};
  }
  function errText(err) {
    const m = (err && err.message) || 'failed';
    if (err && err.status === 403) return /^not allowed/i.test(m) ? m.charAt(0).toUpperCase() + m.slice(1) : 'Not allowed: ' + m;
    if (err && err.status === 413) return 'Too large: ' + m;
    return m;
  }

  function debounce(fn, ms) {
    let t = null;
    const d = function () {
      const args = arguments;
      clearTimeout(t);
      t = setTimeout(() => fn.apply(null, args), ms);
    };
    d.cancel = () => clearTimeout(t);
    return d;
  }

  function fmtDate(s) {
    if (!s) return '';
    const d = new Date(s);
    return isNaN(d) ? String(s) : d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  }
  function fmtTime(s) {
    if (!s) return '';
    const d = new Date(s);
    return isNaN(d) ? String(s) : d.toLocaleString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  }
  // datetime-local works in the browser's local time; the API in UTC.
  function toLocalInput(iso) {
    if (!iso) return '';
    const d = new Date(iso);
    if (isNaN(d)) return '';
    const p = n => String(n).padStart(2, '0');
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + 'T' + p(d.getHours()) + ':' + p(d.getMinutes());
  }
  function fromLocalInput(v) {
    if (!v) return null;
    const d = new Date(v); // "YYYY-MM-DDTHH:MM" without a zone = local time
    if (isNaN(d)) throw new Error('invalid date/time');
    return d.toISOString();
  }
  function sameList(a, b) {
    a = a || []; b = b || [];
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
  }
  function plural(n, one, many) { return n + ' ' + (n === 1 ? one : (many || one + 's')); }
  function uid(prefix) { uid.n = (uid.n || 0) + 1; return prefix + uid.n; }

  // ── person / group picker (window.PortcullisPicker) ─────
  // One combobox for every field that takes a username or a group name
  // (WAI-ARIA combobox with a listbox popup):
  //   attach(input, {kind: 'person' | 'group', source, exclude})
  //     source: an array or a function (→ array or Promise of one) of
  //       users ({username, display_name, email}), groups ({name, rule,
  //       builtin, kind?, disabled?, reason?}) or plain names; exclude: a
  //       list, a Set or a function of names left out (any case). A
  //       textarea picks per line (the caret's line; the other lines are
  //       left out).
  //   bind(container, resolve): delegated: the first focus of an
  //     input/textarea inside container calls resolve(el) → the options
  //     (or null: not ours); the innermost bind wins.
  //   overview(): the directory overview this page shows (the people
  //     page's, or GET /api/directory once a minute at most — Hub only).
  // Matching is a case-insensitive substring (people: username, display
  // name, email; groups: name), at most PICK_MAX shown. ↑/↓ move, Enter
  // chooses, Esc closes, a click chooses; choosing sets the name (the
  // field still takes typed text) and fires input + change (the change
  // a CustomEvent with detail {picked}). Every value is escaped.
  const PortcullisPicker = (function () {
    const PICK_MAX = 8;
    const states = new WeakMap();
    let open = null;      // the state whose list is shown
    let seq = 0;
    let cache = null;     // {at, p}: overview() on a page without the directory
    let fetched = null;   // the last overview() answer
    const lower = s => String(s == null ? '' : s).toLowerCase();

    function overview() {
      if (dir) return Promise.resolve(dir);
      if (!cache || Date.now() - cache.at > 60000) {
        cache = { at: Date.now(), p: api('GET', '/api/directory').then(d => { fetched = d; return d; }).catch(() => { cache = null; return {}; }) };
      }
      return cache.p;
    }
    // knownGroup: the overview's group of that name (its kind), if loaded.
    function knownGroup(name) {
      const d = dir || fetched;
      return d ? (d.groups || []).find(y => y.name === name) || null : null;
    }
    // overviewKind: an overview group's kind.
    function overviewKind(g) {
      const k = g.rule ? 'rule-based' : g.builtin ? 'built-in' : 'manual';
      return g.admin ? k + ', administrators' : k;
    }
    // groupKind: a source item's own kind, an overview group's, or the
    // overview's for a bare {name} (unknown until it is loaded).
    function groupKind(g) {
      if (typeof g.kind === 'string') return g.kind;
      if (!('rule' in g) && !('builtin' in g) && !('members' in g)) { const k = knownGroup(g.name); return k ? overviewKind(k) : ''; }
      return overviewKind(g);
    }
    function normalize(kind, x) {
      if (kind === 'person') {
        if (typeof x === 'string') return { value: x, display: '', email: '' };
        return { value: x.username, display: x.display_name || '', email: x.email || '', disabled: !!x.disabled, reason: x.reason || '' };
      }
      if (typeof x === 'string') {
        const g = knownGroup(x);
        return { value: x, kind: g ? overviewKind(g) : '' };
      }
      return { value: x.name, kind: groupKind(x), disabled: !!x.disabled, reason: x.reason || '' };
    }
    function excluded(st) {
      const ex = typeof st.opts.exclude === 'function' ? st.opts.exclude() : st.opts.exclude;
      const out = new Set();
      for (const v of ex || []) out.add(lower(v));
      if (st.multi) {
        const { start, end } = lineAt(st.input);
        const v = st.input.value;
        (v.slice(0, start) + '\n' + v.slice(end)).split('\n').forEach(l => { if (l.trim()) out.add(lower(l.trim())); });
      }
      return out;
    }
    // lineAt: the caret's line of a textarea ({start, end} offsets).
    function lineAt(el) {
      const v = el.value, c = el.selectionStart == null ? v.length : el.selectionStart;
      const start = v.lastIndexOf('\n', c - 1) + 1;
      let end = v.indexOf('\n', c);
      if (end < 0) end = v.length;
      return { start, end };
    }
    function query(st) {
      if (!st.multi) return st.input.value.trim();
      const { start, end } = lineAt(st.input);
      return st.input.value.slice(start, end).trim();
    }
    function score(it, q) {
      if (!q) return 0;
      const fields = [it.value, it.display, it.email].map(lower);
      if (fields[0].startsWith(q)) return 1;
      if (fields.some(f => f.startsWith(q))) return 2;
      if (fields.some(f => f.includes(q))) return 3;
      return -1;
    }
    function matches(st, items) {
      const q = lower(query(st));
      const ex = excluded(st);
      const out = [];
      items.forEach((x, i) => {
        if (x == null) return;
        const it = normalize(st.opts.kind, x);
        if (!it.value || ex.has(lower(it.value))) return;
        const s = score(it, q);
        if (s >= 0) out.push({ it, s, i });
      });
      out.sort((a, b) => a.s - b.s || a.i - b.i);
      return out.slice(0, PICK_MAX).map(x => x.it);
    }

    function listboxFor(input) {
      const host = input.closest('dialog') || document.body;
      let lb = host.querySelector(':scope > .pp-list');
      if (!lb) {
        lb = document.createElement('ul');
        lb.className = 'pp-list';
        lb.id = 'pp-list-' + (++seq);
        lb.setAttribute('role', 'listbox');
        lb.hidden = true;
        lb.addEventListener('mousedown', e => e.preventDefault()); // the field keeps the focus
        lb.addEventListener('click', e => {
          const li = e.target.closest('[role="option"]');
          if (li && open && open.list === lb) choose(open, +li.dataset.i);
        });
        lb.addEventListener('mousemove', e => {
          const li = e.target.closest('[role="option"]');
          if (li && open && open.list === lb && open.active !== +li.dataset.i) setActive(open, +li.dataset.i);
        });
        host.appendChild(lb);
      }
      return lb;
    }

    function attach(input, opts) {
      if (!input || states.has(input)) return;
      const st = { input, opts: Object.assign({ kind: 'person' }, opts || {}), items: [], active: -1, list: null, ask: 0, multi: input.tagName === 'TEXTAREA' };
      states.set(input, st);
      input.setAttribute('role', 'combobox');
      input.setAttribute('aria-autocomplete', 'list');
      input.setAttribute('aria-expanded', 'false');
      input.setAttribute('autocomplete', 'off');
      input.removeAttribute('list');
      st.list = listboxFor(input);
      input.setAttribute('aria-controls', st.list.id);
      input.addEventListener('input', e => { if (!e.portcullisPick) refresh(st, false); });
      input.addEventListener('keydown', e => onKey(st, e));
      input.addEventListener('blur', () => { if (open === st) close(st); });
      input.addEventListener('click', () => { if (st.multi && open === st) refresh(st, true); });
    }

    function refresh(st, force) {
      const q = query(st);
      if (!q && !force) { close(st); return; }
      const ask = ++st.ask;
      const src = typeof st.opts.source === 'function' ? st.opts.source() : st.opts.source;
      // A list of bare group names gets its kinds from the overview.
      const kinds = st.opts.kind === 'group' && !dir ? overview() : null;
      Promise.all([src, kinds]).then(([items]) => {
        if (ask !== st.ask || document.activeElement !== st.input) return;
        st.items = matches(st, Array.isArray(items) ? items : []);
        if (!st.items.length) { close(st); return; }
        st.active = -1;
        show(st);
      });
    }
    function show(st) {
      if (open && open !== st) close(open);
      open = st;
      const lb = st.list = listboxFor(st.input);
      st.input.setAttribute('aria-controls', lb.id);
      lb.innerHTML = st.items.map((it, i) => {
        const sub = st.opts.kind === 'person' ? [it.display, it.email].filter(Boolean).join(' · ') : it.kind;
        return '<li role="option" id="' + lb.id + '-o' + i + '" data-i="' + i + '" aria-selected="false"' + (it.disabled ? ' aria-disabled="true"' : '') + '>' +
          '<span class="pp-name">' + esc(it.value) + '</span>' + (sub ? ' <span class="pp-sub">' + esc(sub) + '</span>' : '') +
          (it.disabled && it.reason ? '<span class="pp-why">' + esc(it.reason) + '</span>' : '') + '</li>';
      }).join('');
      lb.setAttribute('aria-label', st.input.getAttribute('aria-label') || (st.opts.kind === 'person' ? 'People' : 'Groups'));
      lb.hidden = false;
      place(st);
      st.input.setAttribute('aria-expanded', 'true');
      st.input.removeAttribute('aria-activedescendant');
    }
    function place(st) {
      const r = st.input.getBoundingClientRect();
      const lb = st.list;
      const host = lb.parentNode;
      // A modal dialog is the containing block of its fixed children
      // only when it is transformed; measure it either way.
      const off = host === document.body ? { left: 0, top: 0 } : host.getBoundingClientRect();
      const fixedInHost = host !== document.body && getComputedStyle(host).transform !== 'none';
      lb.style.minWidth = Math.max(r.width, 224) + 'px';
      lb.style.left = (r.left - (fixedInHost ? off.left : 0)) + 'px';
      const below = window.innerHeight - r.bottom;
      if (below < 200 && r.top > below) {
        lb.style.top = '';
        lb.style.bottom = (window.innerHeight - r.top + 2) + 'px';
      } else {
        lb.style.bottom = '';
        lb.style.top = (r.bottom + 2 - (fixedInHost ? off.top : 0)) + 'px';
      }
    }
    function close(st) {
      st.ask++;
      st.items = [];
      st.active = -1;
      st.input.setAttribute('aria-expanded', 'false');
      st.input.removeAttribute('aria-activedescendant');
      if (open === st) {
        open = null;
        st.list.hidden = true;
        st.list.innerHTML = '';
      }
    }
    function setActive(st, i) {
      st.active = i;
      st.list.querySelectorAll('[role="option"]').forEach(li => {
        const on = +li.dataset.i === i;
        li.setAttribute('aria-selected', on ? 'true' : 'false');
        li.classList.toggle('pp-active', on);
        if (on) li.scrollIntoView({ block: 'nearest' });
      });
      if (i >= 0) st.input.setAttribute('aria-activedescendant', st.list.id + '-o' + i);
      else st.input.removeAttribute('aria-activedescendant');
    }
    function onKey(st, e) {
      if (e.isComposing) return;
      const shown = open === st;
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        if (!shown) {
          if (e.key === 'ArrowDown' && (!st.multi || e.altKey || query(st))) { e.preventDefault(); refresh(st, true); }
          return;
        }
        e.preventDefault();
        // Move to the next choosable match (refused ones are only shown).
        const n = st.items.length;
        let i = st.active;
        for (let k = 0; k < n; k++) {
          i = e.key === 'ArrowDown' ? (i + 1) % n : (i <= 0 ? n - 1 : i - 1);
          if (!st.items[i].disabled) { setActive(st, i); break; }
        }
      } else if (e.key === 'Enter' && shown && st.active >= 0) {
        e.preventDefault();
        e.stopPropagation();
        choose(st, st.active);
      } else if (e.key === 'Escape' && shown) {
        e.preventDefault();
        e.stopPropagation();
        close(st);
      } else if (e.key === 'Tab' && shown) {
        close(st);
      }
    }
    function choose(st, i) {
      const it = st.items[i];
      if (!it || it.disabled) return;
      const el = st.input;
      if (st.multi) {
        const { start, end } = lineAt(el);
        el.value = el.value.slice(0, start) + it.value + el.value.slice(end);
        const c = start + it.value.length;
        el.setSelectionRange(c, c);
      } else {
        el.value = it.value;
      }
      close(st);
      const ie = new Event('input', { bubbles: true });
      ie.portcullisPick = true;
      el.dispatchEvent(ie);
      if (el.isConnected) el.dispatchEvent(new CustomEvent('change', { bubbles: true, detail: { picked: it.value } }));
    }

    function bind(container, resolve) {
      if (!container || container.ppBound) return;
      container.ppBound = true;
      container.addEventListener('focusin', e => {
        const t = e.target;
        if (!t || states.has(t) || (t.tagName !== 'INPUT' && t.tagName !== 'TEXTAREA')) return;
        const o = resolve(t);
        if (o) attach(t, o);
      });
    }
    // Lists follow their field; one whose field left the page closes.
    const follow = () => {
      if (!open) return;
      if (!open.input.isConnected) { close(open); return; }
      place(open);
    };
    window.addEventListener('resize', follow);
    document.addEventListener('scroll', follow, true);

    return { attach, bind, overview };
  })();

  // ── shared top navigation (window.PortcullisNav) ────────
  // One bar on the Hub page and on people.<domain>: Portal
  // (https://<domain>/), Hub (https://hub.<domain>/, administrators only)
  // and People (https://people.<domain>/), the current site marked. Every
  // URL comes from the configured main domain, never the browser's host;
  // hubURL / peopleURL override the Hub's and People's (the harness's
  // listeners only).
  const PortcullisNav = (function () {
    function urls(o) {
      const d = String((o && o.domain) || '');
      return {
        portal: 'https://' + d + '/',
        hub: (o && o.hubURL) || 'https://hub.' + d + '/',
        people: (o && o.peopleURL) || 'https://people.' + d + '/',
      };
    }
    // html: the bar (opts: domain, hubURL, peopleURL, current hub|people,
    // admin — the Hub link only for administrators).
    function html(o) {
      const u = urls(o);
      const links = [['portal', 'Portal', u.portal]];
      if (o && o.admin) links.push(['hub', 'Hub', u.hub]);
      links.push(['people', 'People', u.people]);
      return '<nav class="pn-nav" aria-label="Portcullis sites">' + links.map(([k, label, href]) => {
        const cur = o && o.current === k;
        return '<a class="pn-link' + (cur ? ' pn-current' : '') + '" data-site="' + esc(k) + '" href="' + esc(href) + '"' + (cur ? ' aria-current="page"' : '') + '>' + esc(label) + '</a>';
      }).join('') + '</nav>';
    }
    function render(el, o) { if (el) el.innerHTML = html(o); }
    return { urls, html, render };
  })();

  // ── state ───────────────────────────────────────────────
  let root = null;           // mount element
  let options = {};
  let me = null;             // /api/directory/me
  let dir = null;            // /api/directory
  let tab = 'people';
  let search = '';
  let orgField = '';
  let groupPage = null;      // the group whose page is shown (#groups/<name>), or null: the list
  let personPage = null;     // the person whose page is shown (#people/<name>), or null: the People list
  let personNote = null;     // {user, text}: what the invite that created them answered (not applied, warnings)
  let pendingOpen = null;    // {name, action}: an old #users/<name>[?…] link on people.<domain>, opened after the load
  let gsearch = '';          // the groups list's search
  let pick = { group: null, users: [], reason: '', until: '' }; // a group page's Add people form
  let pageNote = null;       // {group, text}: the last save there wasn't applied yet
  let extras = { group: null }; // a group page's Used by and History, or a person page's apps and History (admins)
  let extrasSeq = 0;
  let imp = null;           // import review state
  let dialogClose = null;    // cleanup of the open dialog
  let extraTabs = [];        // options.extraTabs that passed the checks
  const BUILTIN_TABS = ['people', 'groups', 'org', 'setup'];

  const isAdmin = () => !!(me && me.admin) && !!(dir && dir.admin);
  const perms = () => (me && me.perms) || (dir && dir.perms) || [];
  const can = p => isAdmin() || perms().includes(p);
  const canImport = () => isAdmin() || ['edit_details', 'invite', 'remove'].some(p => perms().includes(p));
  const fields = () => (dir && dir.fields) || [];
  const users = () => (dir && dir.users) || [];
  const groups = () => (dir && dir.groups) || [];
  const userByName = name => users().find(u => u.username === name);
  const groupByName = name => groups().find(g => g.name === name);

  // Members of any permission group (delegates can't touch them).
  function permissionMembers() {
    const out = new Set();
    for (const g of Object.values((dir && dir.permissions) || {})) {
      const grp = g && groupByName(g);
      if (grp) for (const m of grp.members || []) out.add(m);
    }
    return out;
  }
  // canEdit: may the caller change this person's details (a hint; the
  // API re-checks: delegates never edit themselves, protected accounts,
  // administrators or permission-group members).
  function canEdit(u) {
    if (!u || u.protected) return false;
    if (isAdmin()) return true;
    if (!can('edit_details')) return false;
    return !u.self && !u.admin && !permissionMembers().has(u.username);
  }
  function canRemove(u) {
    if (!u || u.protected || u.self) return false;
    if (isAdmin()) return true;
    return can('remove') && !u.admin && !permissionMembers().has(u.username);
  }

  // ── toast + secret panel ────────────────────────────────
  function toast(msg, type) {
    const t = root.querySelector('.pd-toast');
    // A modal dialog sits in the top layer: show the toast inside it.
    const d = root.querySelector('.pd-dialog');
    const host = d.open ? d : root.querySelector('.pd');
    if (t.parentNode !== host) host.appendChild(t);
    t.textContent = msg;
    t.className = 'pd-toast show ' + (type || '');
    clearTimeout(toast.t);
    toast.t = setTimeout(() => { t.className = 'pd-toast'; }, type === 'error' ? 6000 : 3000);
  }
  function warnings(res) {
    if (res && res.warnings && res.warnings.length) toast(res.warnings.join(' · '), 'error');
  }
  // Shows an invite link / password exactly once; never stored.
  function showSecret(res, who) {
    const box = root.querySelector('.pd-secret');
    let title, value, meta;
    if (res && res.invite) {
      title = 'One-time invite link for ' + who + ': send it to them now';
      value = res.invite.url;
      meta = 'Expires ' + fmtTime(res.invite.expires_at) + '. It works once and replaces any earlier invite. It won\'t be shown again.';
    } else if (res && res.server_invite) {
      title = who + ' is an administrator: onboard or recover them on the server';
      value = res.server_invite;
      meta = 'Administrators get their invite link on the server, not through the Hub. Run this command there.';
    } else if (res && res.password) {
      title = 'Password for ' + who + ': copy it now';
      value = res.password;
      meta = 'It won\'t be shown again.';
    } else {
      return;
    }
    box.querySelector('.pd-secret-title').textContent = title;
    box.querySelector('input').value = value;
    box.querySelector('.pd-secret-meta').textContent = meta;
    box.hidden = false;
    box.scrollIntoView({ behavior: 'smooth', block: 'center' });
    box.querySelector('input').focus();
  }
  function hideSecret() {
    const box = root.querySelector('.pd-secret');
    box.querySelector('input').value = '';
    box.hidden = true;
  }
  async function copyText(text) {
    try { await navigator.clipboard.writeText(text); }
    catch (_) {
      const ta = document.createElement('textarea');
      ta.value = text; document.body.appendChild(ta); ta.select();
      document.execCommand('copy'); ta.remove();
    }
    toast('Copied', 'success');
  }
  function typed(what, name) {
    const v = prompt(what + '\n\nType "' + name + '" to confirm:');
    if (v === null) return false;
    if (v !== name) { toast('Confirmation did not match: nothing changed.', 'error'); return false; }
    return true;
  }

  // act runs a mutation, toasts, reloads. Returns the result or null.
  async function act(fn, okMsg) {
    try {
      const res = await fn();
      if (okMsg) toast(okMsg, 'success');
      warnings(res);
      await load();
      return res || {};
    } catch (err) {
      toast(errText(err), 'error');
      return null;
    }
  }

  // ── dialog ──────────────────────────────────────────────
  function openDialog(title, html, onClose) {
    const d = root.querySelector('.pd-dialog');
    if (dialogClose) { const f = dialogClose; dialogClose = null; f(); }
    d.querySelector('.pd-dialog-title').textContent = title;
    d.querySelector('.pd-dialog-body').innerHTML = html;
    dialogClose = onClose || null;
    if (!d.open) d.showModal();
    return d.querySelector('.pd-dialog-body');
  }
  function closeDialog() {
    const d = root.querySelector('.pd-dialog');
    if (d.open) d.close();
  }
  function dialogBody() { return root.querySelector('.pd-dialog-body'); }

  // ── loading ─────────────────────────────────────────────
  async function load() {
    const off = root.querySelector('.pd-off');
    const main = root.querySelector('.pd-main');
    try {
      me = await api('GET', '/api/directory/me');
    } catch (err) {
      me = null;
      if (err.status !== 503) return showOff('Failed to load: ' + errText(err));
    }
    try {
      dir = await api('GET', '/api/directory');
    } catch (err) {
      return showOff('Failed to load people: ' + errText(err));
    }
    if (!dir.available) {
      return showOff('The directory is temporarily unavailable. <span class="pd-muted">' + esc(dir.reason) + '</span>', true);
    }
    if (!me) me = { user: dir.me, admin: dir.admin, perms: dir.perms || [] };
    off.hidden = true;
    main.hidden = false;
    if (options.onUser) options.onUser(me.user, isAdmin());
    if (personPage) personPage = canonPerson(personPage);
    renderAll();
    if ((tab === 'groups' && groupPage) || (tab === 'people' && personPage)) refreshExtras();
  }
  function showOff(html, trusted) {
    const off = root.querySelector('.pd-off');
    root.querySelector('.pd-main').hidden = true;
    off.hidden = false;
    off.innerHTML = trusted ? html : esc(html);
  }

  function renderAll() {
    root.querySelector('[data-pdtab="setup"]').hidden = !isAdmin();
    if (tab === 'setup' && !isAdmin()) tab = 'people';
    let warn = '';
    if (dir.keycloak_error) warn += '<div class="pd-warn">Keycloak status unavailable: ' + esc(dir.keycloak_error) + '</div>';
    if (dir.invites_error) warn += '<div class="pd-warn">Invite links unavailable (' + esc(dir.invites_error) + '). New users need the password fallback under Advanced.</div>';
    if (dir.fields_error) warn += '<div class="pd-warn">Custom fields unavailable: ' + esc(dir.fields_error) + '</div>';
    root.querySelector('.pd-warnings').innerHTML = warn;
    renderPeople();
    renderGroups();
    renderOrg();
    if (isAdmin()) renderSetup();
    selectTab(tab, false);
  }

  function selectTab(name, focus) {
    tab = name;
    root.querySelectorAll('[data-pdtab]').forEach(b => {
      const on = b.dataset.pdtab === name;
      b.classList.toggle('active', on);
      b.setAttribute('aria-selected', on ? 'true' : 'false');
      b.tabIndex = on ? 0 : -1;
      if (on && focus) b.focus();
    });
    root.querySelectorAll('.pd-panel').forEach(p => { p.hidden = p.dataset.panel !== name; });
    const x = extraTabs.find(t => t.id === name);
    if (x) {
      const panel = root.querySelector('[data-panel="' + x.id + '"]');
      try { x.render(panel); } catch (err) { panel.innerHTML = '<p class="pd-muted">' + esc((err && err.message) || 'failed') + '</p>'; }
    }
  }

  // ── People ──────────────────────────────────────────────
  function membershipPills(u) {
    const ms = u.memberships && u.memberships.length ? u.memberships : (u.groups || []).map(g => ({ group: g, how: 'manual' }));
    return ms.map(m => {
      let mark = '', title = '';
      if (m.how === 'rule') {
        mark = ' <span class="pd-bolt" aria-hidden="true">⚡</span>';
        title = u.created_by ? 'via rule, account created by ' + u.created_by : 'member through a rule';
      } else if (m.how === 'exception') {
        mark = ' <span class="pd-star" aria-hidden="true">✱</span>';
        // An include entry (a kept-out person is no member): the group
        // page's words, the reason for administrators only.
        title = 'added by hand' + (m.reason ? ': ' + m.reason : '') + (m.until ? ' (until ' + fmtTime(m.until) + ')' : '');
      } else if (m.until) {
        mark = ' <span aria-hidden="true">⏳</span>';
        title = 'until ' + fmtTime(m.until);
      }
      const cls = m.group === 'lldap_admin' ? ' info' : '';
      return '<span class="pd-pill' + cls + '"' + (title ? ' title="' + esc(title) + '"' : '') + '>' + esc(m.group) + mark +
        (title ? '<span class="pd-sr"> (' + esc(title) + ')</span>' : '') + '</span>';
    }).join('');
  }

  function keyStatus(u) {
    if (u.protected === 'service') return '<span class="pd-muted">service account (not in Keycloak)</span>';
    const kc = u.keycloak;
    if (!kc) return '<span class="pd-pill">Keycloak unknown</span>';
    if (!kc.imported) return '<span class="pd-pill" title="LDAP users are imported into Keycloak at first sign-in">not signed in yet</span>';
    let h = kc.error
      ? '<span class="pd-pill bad" title="' + esc(kc.error) + '">Keycloak status unavailable</span>'
      : kc.passkeys > 0
        ? '<span class="pd-pill ok">' + esc(kc.passkeys) + ' passkey' + (kc.passkeys === 1 ? '' : 's') + '</span>'
        : '<span class="pd-pill warn">no passkey</span>';
    if (!kc.enabled) h += '<span class="pd-pill bad">disabled in Keycloak</span>';
    for (const a of kc.required_actions || []) h += '<span class="pd-pill warn" title="pending required action">' + esc(a) + '</span>';
    return h;
  }

  function attrText(u, f) {
    const v = (u.attrs || {})[f.name] || [];
    return v.join(', ');
  }

  function matchesSearch(u, q) {
    if (!q) return true;
    const hay = [u.username, u.display_name, u.email].concat(...Object.values(u.attrs || {})).concat(u.groups || []);
    return hay.some(s => String(s || '').toLowerCase().includes(q));
  }

  function renderPeople() {
    const actions = root.querySelector('.pd-people-actions');
    let a = '';
    if (can('invite')) a += '<button type="button" class="pd-btn primary sm" data-act="invite-open">Invite</button>';
    if (canImport()) a += '<button type="button" class="pd-btn secondary sm" data-act="import-pick">Import CSV</button>';
    actions.innerHTML = a;
    renderStale();
    renderPeopleTable();
    root.querySelector('.pd-people-main').hidden = !!imp || !!personPage;
    root.querySelector('.pd-import').hidden = !imp || !!personPage;
    if (imp) renderImport();
    renderPersonPage();
  }

  function renderPeopleTable() {
    const box = root.querySelector('.pd-people-table');
    const q = search.trim().toLowerCase();
    const list = users().filter(u => matchesSearch(u, q));
    const fs = fields();
    const admin = isAdmin();
    let h = '<table class="pd-table pd-people-tbl"><thead><tr><th scope="col">User</th>';
    for (const f of fs) h += '<th scope="col">' + esc(f.label || f.name) + '</th>';
    h += '<th scope="col">Groups</th>' + (admin ? '<th scope="col">Key</th>' : '') + '</tr></thead><tbody>';
    for (const u of list) {
      h += '<tr class="pd-row" data-user="' + esc(u.username) + '"><td><button type="button" class="pd-link" data-act="open-user" data-user="' + esc(u.username) + '">' +
        esc(u.username) + '</button>';
      if (u.self) h += ' <span class="pd-pill info">you</span>';
      if (u.admin && u.protected !== 'service') h += ' <span class="pd-pill info" title="Member of an administrator group">admin</span>';
      if (u.display_name) h += '<div class="pd-muted">' + esc(u.display_name) + '</div>';
      h += '</td>';
      for (const f of fs) h += '<td>' + (attrText(u, f) ? esc(attrText(u, f)) : '<span class="pd-muted">—</span>') + '</td>';
      h += '<td>' + membershipPills(u) + '</td>';
      if (admin) h += '<td>' + keyStatus(u) + '</td>';
      h += '</tr>';
    }
    if (!list.length) h += '<tr><td colspan="' + (fs.length + (admin ? 3 : 2)) + '" class="pd-muted">' + (q ? 'Nobody matches.' : 'No people yet.') + '</td></tr>';
    box.innerHTML = h + '</tbody></table>';
    root.querySelector('.pd-people-count').textContent = q ? list.length + ' of ' + users().length : plural(users().length, 'person', 'people');
  }

  function renderStale() {
    const box = root.querySelector('.pd-stale');
    const stale = (isAdmin() && dir.stale_keycloak) || [];
    if (!stale.length) { box.innerHTML = ''; return; }
    let h = '<div class="pd-card"><h3 class="pd-h3">Stale Keycloak records</h3><p class="pd-muted">Keycloak copies of users imported from LLDAP whose LLDAP entry no longer exists (deleted outside the Hub). They can\'t sign in; removing the copy only deletes it from Keycloak.</p>' +
      '<table class="pd-table"><thead><tr><th scope="col">Keycloak user</th><th scope="col">Why</th><th scope="col"><span class="pd-sr">Actions</span></th></tr></thead><tbody>';
    for (const r of stale) {
      h += '<tr><td><b>' + esc(r.username) + '</b><div class="pd-muted">' + esc(r.id) + '</div></td><td class="pd-muted">' + esc(r.reason) +
        '</td><td><button type="button" class="pd-btn danger sm" data-act="remove-stale" data-user="' + esc(r.username) + '">Remove</button></td></tr>';
    }
    box.innerHTML = h + '</tbody></table></div>';
  }

  // ── details form ────────────────────────────────────────
  function fieldInput(f, vals, id, editable) {
    vals = vals || [];
    const dis = editable ? '' : ' disabled';
    if (f.kind === 'list' && f.multi) {
      const opts = (f.values || []).slice();
      for (const v of vals) if (!opts.includes(v)) opts.push(v);
      return '<div class="pd-checks" role="group" aria-labelledby="' + id + '-l">' + opts.map(v =>
        '<label><input type="checkbox" data-field="' + esc(f.name) + '" value="' + esc(v) + '"' + (vals.includes(v) ? ' checked' : '') + dis + '> ' + esc(v) + '</label>').join('') +
        (opts.length ? '' : '<span class="pd-muted">no values defined</span>') + '</div>';
    }
    if (f.kind === 'list') {
      const opts = (f.values || []).slice();
      if (vals[0] && !opts.includes(vals[0])) opts.push(vals[0]);
      return '<select id="' + id + '" data-field="' + esc(f.name) + '"' + dis + '><option value="">—</option>' + opts.map(v =>
        '<option value="' + esc(v) + '"' + (vals[0] === v ? ' selected' : '') + '>' + esc(v) + '</option>').join('') + '</select>';
    }
    if (f.multi) {
      return '<textarea id="' + id + '" data-field="' + esc(f.name) + '" rows="2" placeholder="one value per line"' + dis + '>' + esc(vals.join('\n')) + '</textarea>';
    }
    return '<input type="text" id="' + id + '" data-field="' + esc(f.name) + '" value="' + esc(vals[0] || '') + '"' +
      (f.kind === 'person' ? ' data-pick="person" placeholder="username"' : '') + dis + '>';
  }
  function readField(container, f) {
    const sel = '[data-field="' + CSS.escape(f.name) + '"]';
    if (f.kind === 'list' && f.multi) return Array.from(container.querySelectorAll(sel + ':checked')).map(i => i.value);
    const el = container.querySelector(sel);
    if (!el) return null;
    if (f.multi) return el.value.split('\n').map(s => s.trim()).filter(Boolean);
    const v = el.value.trim();
    return v ? [v] : [];
  }

  // The details form (Edit details): email, display name and the custom
  // fields, each disabled where the caller may not change it.
  function detailsFormHtml(u, editable) {
    const admin = isAdmin();
    let h = '<div class="pd-grid">';
    h += '<div><label for="pu-email">Email</label><input type="email" id="pu-email" value="' + esc(u.email) + '"' + (editable ? '' : ' disabled') + '></div>';
    h += '<div><label for="pu-display">Display name</label><input type="text" id="pu-display" value="' + esc(u.display_name) + '"' + (editable ? '' : ' disabled') + '></div>';
    for (const f of fields()) {
      const id = uid('pu-f-');
      const fe = editable && (!f.admin_only || admin);
      h += '<div><label for="' + id + '" id="' + id + '-l">' + esc(f.label || f.name) +
        (f.admin_only ? ' <span class="pd-muted" title="Only admins can change it">(admin-only)</span>' : '') + '</label>' + fieldInput(f, (u.attrs || {})[f.name], id, fe) + '</div>';
    }
    h += '</div>';
    if (editable) {
      h += '<div class="pd-actions"><button type="button" class="pd-btn primary sm" data-act="save-user" data-user="' + esc(u.username) + '">Save details</button>' +
        '<button type="button" class="pd-btn secondary sm" data-act="dialog-close">Cancel</button></div>';
    }
    return h;
  }
  function openDetails(name) {
    const u = userByName(name);
    if (!u || !canEdit(u)) return;
    openDialog('Edit details of ' + u.username, detailsFormHtml(u, true));
    dialogBody().querySelector('#pu-email').focus();
  }

  // ── a person's page (#people/<name>) ────────────────────
  // Header (details, Edit details), Groups (each with the group page's
  // row state, linking to it; Add to group… opens a group's page with
  // them picked), Apps and Values (admins), Sign-in (the key actions)
  // and History (admins). Membership changes only on group pages.
  const personHash = name => '#people/' + enc(name);
  function openPerson(name) {
    name = String(name || '');
    if (!name) return;
    const h = personHash(name);
    if (location.hash === h) { if (root) applyRoute({ person: name }); return; }
    location.hash = h; // hashchange routes it
  }
  function fieldValueHtml(f, vals) {
    return (vals || []).map(v => f.kind === 'person' && userByName(v)
      ? '<a class="pd-a" href="' + esc(personHash(v)) + '">' + esc(v) + '</a>' : esc(v)).join(', ');
  }
  // The key and account actions the caller may use on u (as the old
  // dialog offered them; the API re-checks).
  function personKeyActions(u) {
    const out = [];
    if (isAdmin() && !u.protected) {
      const kc = u.keycloak;
      if (!u.admin) out.push(['invite', 'Send new invite', 'primary']);
      if (!kc || !(kc.required_actions || []).includes('webauthn-register-passwordless')) out.push(['require-passkey', 'Require passkey', 'secondary']);
      if (kc && (kc.required_actions || []).length) out.push(['clear-actions', 'Clear pending', 'secondary']);
      out.push(['reset-passkeys', 'Reset passkeys', 'danger']);
      out.push(['password', 'Password…', 'danger']);
    } else if (!isAdmin() && can('invite') && u.created_by && u.created_by === (me && me.user)) {
      out.push(['invite', 'Send new invite', 'primary']);
    }
    if (canRemove(u)) out.push(['delete-user', 'Delete', 'danger']);
    return out;
  }
  // The groups u has a row in, with the group page's row (state, tags).
  function personGroupRows(u) {
    const admin = isAdmin(), k = lc(u.username), out = [];
    for (const g of groups()) {
      const r = peopleRows(g, admin).find(x => lc(x.user) === k);
      if (r) out.push({ g, r });
    }
    return out;
  }
  function addToGroupCandidates(u) {
    if (!isAdmin() || !u || u.protected) return [];
    return groups().filter(g => pickCandidates(g).some(x => x.username === u.username));
  }

  const CORE_ADMIN_NOTE = 'This is the built-in administrator. It manages Portcullis (apps, people, settings) but can\'t be added to groups, so it can\'t use your apps. ' +
    'To use apps, invite yourself as a regular person and add that account to the apps\' groups.';
  function personPageHtml(name) {
    let h = '<nav class="pd-crumb" aria-label="Breadcrumb"><button type="button" class="pd-link pd-a" data-act="people-list">People</button> › <span class="pd-mono">' + esc(name) + '</span></nav>';
    const u = userByName(name) || users().find(x => lc(x.username) === lc(name));
    if (!u) return h + '<p class="pd-muted">There is nobody named <span class="pd-mono">' + esc(name) + '</span>.</p>';
    const admin = isAdmin();
    // The bootstrap admin (the overview marks it protected core-admin):
    // every group refuses it, so it can't use any app.
    if (u.protected === 'core-admin') h += '<div class="pd-warn pd-core-admin" role="note">' + esc(CORE_ADMIN_NOTE) + '</div>';
    h += '<div class="pd-gp-head"><h2 class="pd-gp-name">' + esc(u.display_name || u.username) + '</h2><span class="pd-muted">' +
      esc(u.username) + (u.email ? ' · ' + esc(u.email) : '') + '</span>';
    if (u.self) h += '<span class="pd-pill info">you</span>';
    if (u.protected === 'service') h += '<span class="pd-pill" title="The Hub\'s own LLDAP account (read-only here)">Hub service account</span>';
    if (u.protected === 'core-admin') h += '<span class="pd-pill" title="Bootstrap LLDAP admin: Keycloak and enroll bind as it. Managed from the server only (./portcullis invite admin)">bootstrap admin (server-managed)</span>';
    if (u.admin && u.protected !== 'service') h += '<span class="pd-pill info" title="Member of an administrator group: no invites from the Hub">administrator</span>';
    h += '</div>';
    // Custom fields, then Edit details.
    const fs = fields().filter(f => ((u.attrs || {})[f.name] || []).length);
    h += '<div class="pd-gp-sub pd-pp-sub">' + (fs.length ? fs.map(f => '<span class="pd-pp-field"><span class="pd-muted">' + esc(f.label || f.name) + '</span> ' +
      fieldValueHtml(f, u.attrs[f.name]) + '</span>').join('') : '<span class="pd-muted">No details yet.</span>');
    if (canEdit(u)) h += ' <button type="button" class="pd-btn secondary xs" data-act="edit-details" data-user="' + esc(u.username) + '">Edit details</button>';
    else if (can('edit_details') && !u.protected) h += ' <span class="pd-muted pd-small">Only an admin can change ' + esc(u.username) + '.</span>';
    h += '</div>';
    if (u.created) h += '<p class="pd-muted pd-small">Since ' + esc(fmtDate(u.created)) + (u.created_by ? ' · account created by ' + esc(u.created_by) : '') + '</p>';
    if (personNote && personNote.user === u.username) h += '<div class="pd-warn" role="status">' + esc(personNote.text) + '</div>';

    h += '<div class="pd-pp-two">';
    // Groups
    const rows = personGroupRows(u);
    h += '<section class="pd-card pd-pp-card" aria-labelledby="pd-pp-groups-h"><h3 class="pd-h3" id="pd-pp-groups-h">Groups</h3>';
    if (!rows.length) h += '<p class="pd-muted">No groups.</p>';
    else {
      h += '<table class="pd-table pd-gp-people pd-pp-groups"><tbody>';
      for (const { g, r } of rows) {
        h += '<tr data-group="' + esc(g.name) + '"><td class="pd-nowrap"><a class="pd-a pd-mono" href="' + esc(groupHash(g.name)) + '">' + esc(g.name) + '</a></td><td>' +
          (r.tags || kindPill(g)) + (r.state ? '<span class="pd-gp-state">' + r.state + '</span>' : '') +
          (r.note ? '<div class="pd-muted pd-small">' + esc(r.note) + '</div>' : '') + '</td></tr>';
      }
      h += '</tbody></table>';
    }
    if (addToGroupCandidates(u).length) {
      h += '<div class="pd-actions"><button type="button" class="pd-btn secondary sm" data-act="add-to-group" data-user="' + esc(u.username) + '">Add to group…</button></div>';
    } else if (admin && u.protected === 'core-admin') {
      h += '<div class="pd-actions"><button type="button" class="pd-btn secondary sm" disabled aria-describedby="pd-core-admin-why">Add to group…</button>' +
        '<span class="pd-muted pd-small" id="pd-core-admin-why">The built-in administrator can\'t be added to groups.</span></div>';
    }
    h += '</section>';
    // Apps and Values (admins; filled by refreshExtras)
    if (admin) {
      h += '<section class="pd-card pd-pp-card" aria-labelledby="pd-pp-apps-h"><h3 class="pd-h3" id="pd-pp-apps-h">Apps</h3><div class="pd-pp-apps"><p class="pd-muted">Loading…</p></div>' +
        '<h3 class="pd-h3 pd-pp-h-next" id="pd-pp-values-h">Values</h3><div class="pd-pp-values"><p class="pd-muted">Loading…</p></div></section>';
    }
    h += '</div>';
    // Sign-in
    const acts = personKeyActions(u);
    if (admin || acts.length) {
      h += '<section class="pd-card pd-pp-card" aria-labelledby="pd-pp-sign-h"><h3 class="pd-h3" id="pd-pp-sign-h">Sign-in</h3>';
      if (admin) {
        h += '<div>' + keyStatus(u) + '</div>';
        if (u.server_invite && !u.protected) h += '<div class="pd-muted" title="Administrators are invited and recovered from the server">recover on the server: <code>' + esc(u.server_invite) + '</code></div>';
      }
      h += '<div class="pd-actions">' + acts.map(([a, label, cls]) =>
        '<button type="button" class="pd-btn ' + cls + ' sm" data-act="' + a + '" data-user="' + esc(u.username) + '">' + esc(label) + '</button>').join('') + '</div></section>';
    }
    // History (admins)
    if (admin) {
      h += '<section class="pd-sec" aria-labelledby="pd-pp-hist-h"><div class="pd-head"><h3 class="pd-h3" id="pd-pp-hist-h">History</h3>' +
        '<button type="button" class="pd-btn ghost xs" data-act="gp-hist-reload">Refresh</button></div><div class="pd-pp-hist"><p class="pd-muted">Loading…</p></div></section>';
    }
    return h;
  }
  // Add to group…: pick a group (rule-based ones too); its page opens
  // with the person picked in Add people (end, reason and save there).
  function openAddToGroup(name) {
    const u = userByName(name);
    if (!addToGroupCandidates(u).length) return;
    openDialog('Add ' + name + ' to a group',
      '<p class="pd-note">Pick a group: its page opens with ' + esc(name) + ' already picked in Add people. Set the end there (and, on a rule-based group, the reason), then Add.</p>' +
      '<div class="pd-inline"><label for="pa-group">Group</label><input type="text" id="pa-group" placeholder="group name" autocomplete="off" spellcheck="false" data-pick="group" data-user="' + esc(name) + '"></div>' +
      '<div class="pd-actions"><button type="button" class="pd-btn primary sm" data-act="add-to-group-go" data-user="' + esc(name) + '">Open the group\'s page</button>' +
      '<button type="button" class="pd-btn secondary sm" data-act="dialog-close">Cancel</button></div>');
    dialogBody().querySelector('#pa-group').focus();
  }
  // addToGroupItems: the Add to group… picker's groups, each with its kind
  // (and whether the person already matches its rule).
  function addToGroupItems(name) {
    return addToGroupCandidates(userByName(name)).map(g => {
      let k = g.rule ? 'rule-based' + ((g.matches || []).map(lc).includes(lc(name)) ? ', matches the rule' : '') : g.builtin ? 'built-in' : 'manual';
      if (g.admin) k += ', administrators';
      return { name: g.name, kind: k };
    });
  }
  function renderPersonPage() {
    const box = root.querySelector('.pd-person-page');
    box.hidden = !personPage;
    box.innerHTML = personPage ? personPageHtml(personPage) : '';
    if (personPage) renderExtras();
  }

  // Apps (via which group, until when) and Values (app · label · value ·
  // from), from GET …/users/{u}/apps. Each app and value links to the
  // Hub, each group to its page.
  function groupRef(name) {
    return groupByName(name) ? '<a class="pd-a pd-mono" href="' + esc(groupHash(name)) + '">' + esc(name) + '</a>' : '<span class="pd-mono">' + esc(name) + '</span>';
  }
  function personAppsHtml(p, err) {
    if (err) return '<p class="pd-muted">Can\'t load the apps: ' + esc(err) + '</p>';
    if (!p) return '';
    const apps = p.apps || [];
    if (!apps.length) return '<p class="pd-muted">No apps.</p>';
    let h = '<ul class="pd-uses">';
    for (const a of apps) {
      const via = (a.via || []).map(v => groupRef(v.group) + (v.until ? ' <span class="pd-muted">(until ' + esc(fmtDate(v.until)) + ')</span>' : ''));
      h += '<li>' + hubLink(appFrag(a.instance), a.name || a.instance) + ' <span class="pd-muted">' + (via.length ? 'via</span> ' + via.join(', ') : 'everyone signed in</span>') + '</li>';
    }
    return h + '</ul>';
  }
  function personValuesHtml(p, err) {
    if (err || !p) return '';
    const vals = p.values || [];
    if (!vals.length) return '<p class="pd-muted">No per-person values.</p>';
    let h = '<table class="pd-table pd-pp-values-tbl"><tbody>';
    for (const v of vals) {
      // from: a group, a combined value's groups (", "-joined), or a
      // word (default, fail-closed, own entry, set by …).
      const from = String(v.from || '');
      const parts = from.split(', ');
      const fromHtml = parts.some(x => groupByName(x)) ? 'from ' + parts.map(x => groupByName(x) ? groupRef(x) : esc(x)).join(', ') : esc(from);
      h += '<tr><td>' + esc(v.app || v.instance) + ' <span class="pd-muted">·</span> ' + esc(v.label || v.key) + '</td><td>' + hubLink(appFrag(v.instance, v.key), String(v.value)) +
        '</td><td class="pd-muted">' + fromHtml + '</td></tr>';
    }
    return h + '</tbody></table>';
  }

  function memberLocked(g, m) {
    return m === dir.service_user || m === 'admin' || (g.name === 'lldap_admin' && m === dir.me);
  }

  async function saveUser(name) {
    const u = userByName(name);
    if (!u) return;
    const body = dialogBody();
    const email = body.querySelector('#pu-email').value.trim();
    const display = body.querySelector('#pu-display').value.trim();
    const attrs = {};
    for (const f of fields()) {
      if (f.admin_only && !isAdmin()) continue;
      const v = readField(body, f);
      if (v !== null && !sameList(v, (u.attrs || {})[f.name] || [])) attrs[f.name] = v;
    }
    const tasks = [];
    if (email !== (u.email || '') || display !== (u.display_name || '')) {
      tasks.push(() => api('PUT', '/api/directory/users/' + enc(name), { email, display_name: display }));
    }
    if (Object.keys(attrs).length) tasks.push(() => api('PUT', '/api/directory/users/' + enc(name) + '/details', { attrs }));
    if (!tasks.length) { toast('Nothing changed'); return; }
    const res = await act(async () => { for (const t of tasks) await t(); return {}; }, 'Saved ' + name);
    if (res) closeDialog();
  }

  // ── invite dialog ───────────────────────────────────────
  // openInvite opens the new-person form; pre (deep link #users?create&…,
  // the Portcullis MCP's create_person form) pre-fills username, email,
  // display name and ticks groups — the admin reviews and submits it here.
  function openInvite(pre) {
    const admin = isAdmin();
    let h = '<div class="pd-grid">' +
      '<div><label for="nu-username">Username</label><input type="text" id="nu-username" autocomplete="off" placeholder="lowercase, e.g. alice" required></div>' +
      '<div><label for="nu-email">Email</label><input type="email" id="nu-email" autocomplete="off" required></div>' +
      '<div><label for="nu-display">Display name</label><input type="text" id="nu-display" autocomplete="off"></div></div>';
    if (admin) {
      const gs = groups().filter(g => !g.builtin || g.name === 'lldap_admin');
      h += '<fieldset class="pd-fieldset"><legend>Groups</legend><div class="pd-checks">' + (gs.length ? gs.map(g =>
        '<label' + (g.admin ? ' title="Administrator group: the user is onboarded from the server (./portcullis invite), not with an invite link"' : '') +
        '><input type="checkbox" name="nu-group" value="' + esc(g.name) + '" data-on="inv-group"' + (g.rule ? ' data-rule="1"' : '') + '> ' + esc(g.name) +
        (g.admin ? ' <span class="pd-pill info">admin</span>' : '') + (g.rule ? ' <span class="pd-pill info">rule-based</span>' : '') + '</label>').join('')
        : '<span class="pd-muted">No groups yet.</span>') + '</div>' + gs.filter(g => g.rule).map(inviteRuleHtml).join('') + '</fieldset>';
      h += '<p class="pd-note">The new person gets a one-time invite link: they open it, register their security key, and they\'re signed in. No password. ' +
        'A rule-based group you tick takes them in through its rule when they match it, else as added by hand, with your reason. Rule-based groups you don\'t tick add them once their details match.</p>';
      h += '<details class="pd-adv"><summary>Advanced: use a password instead of an invite</summary><div class="pd-checks">' +
        '<label><input type="checkbox" id="nu-use-password"> Onboard with a password</label></div><div class="pd-checks">' +
        '<label><input type="radio" name="nu-pwmode" value="generate" checked> Generate a strong password (shown once)</label>' +
        '<label><input type="radio" name="nu-pwmode" value="set"> Set one</label></div>' +
        '<div><label for="nu-password">Password</label><input type="password" id="nu-password" autocomplete="new-password" placeholder="at least 12 characters"></div>' +
        '<div class="pd-checks"><label><input type="checkbox" id="nu-require-passkey" checked> Require passkey registration at first login</label></div></details>';
    } else {
      h += '<p class="pd-note">The new person gets a one-time invite link and no groups. Rule-based groups add them once their details match' +
        (can('edit_details') ? ' (fill them in after the invite).' : '.') + '</p>';
    }
    h += '<div class="pd-actions"><button type="button" class="pd-btn primary sm" data-act="invite-create">Create and invite</button>' +
      '<button type="button" class="pd-btn secondary sm" data-act="dialog-close">Cancel</button></div>';
    openDialog('Invite someone', h);
    const b = dialogBody();
    if (pre) {
      b.querySelector('#nu-username').value = pre.get('username') || '';
      b.querySelector('#nu-email').value = pre.get('email') || '';
      b.querySelector('#nu-display').value = pre.get('display_name') || '';
      // A link ticks only groups the server says don't guard (guarding
      // === false, GroupView's admin-only flag): never an administrator,
      // permission, app admin or privileged-value group. A missing flag
      // counts as guarding.
      const want = (pre.get('groups') || '').split(',').filter(Boolean);
      const safe = new Set(groups().filter(g => g.guarding === false).map(g => g.name));
      b.querySelectorAll('input[name="nu-group"]').forEach(i => {
        i.checked = want.includes(i.value) && safe.has(i.value);
      });
      syncInviteRules();
    }
    b.querySelector('#nu-username').focus();
  }

  async function createUser() {
    const b = dialogBody();
    const username = b.querySelector('#nu-username').value.trim();
    if (!username) { toast('A username is required', 'error'); return; }
    const picked = Array.from(b.querySelectorAll('input[name="nu-group"]:checked'));
    const body = {
      username,
      email: b.querySelector('#nu-email').value.trim(),
      display_name: b.querySelector('#nu-display').value.trim(),
      groups: picked.map(i => i.value),
      onboarding: 'invite',
    };
    // A picked rule group they won't match needs a reason (an "added by
    // hand" entry, stored with the new person).
    const reasons = {};
    for (const i of picked) {
      const r = i.dataset.rule && b.querySelector('[data-reason-for="' + CSS.escape(i.value) + '"]');
      if (!r) continue;
      const v = r.value.trim();
      if (!v) { toast(i.value + ' is rule-based and ' + username + ' won\'t match its rule: adding them by hand needs a reason', 'error'); r.focus(); return; }
      reasons[i.value] = v;
    }
    if (Object.keys(reasons).length) body.reasons = reasons;
    const usePw = b.querySelector('#nu-use-password');
    if (usePw && usePw.checked) {
      body.onboarding = 'password';
      body.generate_password = b.querySelector('input[name="nu-pwmode"]:checked').value === 'generate';
      if (!body.generate_password) body.password = b.querySelector('#nu-password').value;
      body.require_passkey = b.querySelector('#nu-require-passkey').checked;
    }
    const res = await act(() => api('POST', '/api/directory/users', body), username + ' created');
    if (!res) return;
    closeDialog();
    // The answer's applied / why / warnings stay on the new person's page.
    const notes = (res.applied === false ? [notApplied(res.why)] : []).concat(res.warnings || []);
    personNote = notes.length ? { user: username, text: notes.join(' · ') } : null;
    if (notes.length) toast(notes.join(' · '), 'error');
    if (userByName(username)) openPerson(username);
    showSecret(res, username);
  }

  // inviteRuleHtml: under the groups pick, what a ticked rule group
  // needs. The rule is evaluated here exactly as the server's wouldMatch
  // does for an invite: rules read only custom fields, and a new account
  // has none (username, email and display name are no rule input).
  function inviteRuleHtml(g) {
    const id = uid('nu-r-');
    let h = '<div class="pd-inv-rule" data-rg="' + esc(g.name) + '" hidden><span class="pd-mono">' + esc(g.name) + '</span> <code>' + esc(g.rule.text) + '</code> ';
    if (matchesNewPerson(g.rule.expr)) {
      h += '<span class="pd-muted">they match the rule: nothing else needed.</span>';
    } else {
      h += '<span class="pd-muted">they won\'t match the rule (a new account has no details yet), so they are added by hand.</span>' +
        '<div class="pd-inline"><label for="' + id + '">Reason (required)</label><input type="text" id="' + id + '" maxlength="500" placeholder="why?" data-reason-for="' + esc(g.name) + '"></div>';
    }
    if (g.adds_blocked) h += '<div class="pd-muted pd-small">⚠ ' + esc(g.adds_blocked) + '</div>';
    return h + '</div>';
  }
  function syncInviteRules() {
    const b = dialogBody();
    b.querySelectorAll('input[name="nu-group"][data-rule]').forEach(i => {
      const box = b.querySelector('.pd-inv-rule[data-rg="' + CSS.escape(i.value) + '"]');
      if (box) box.hidden = !i.checked;
    });
  }
  // matchesNewPerson mirrors rules.Eval for a person with no field values
  // (and so no manager): an invalid tree matches nobody (fail closed, as
  // Eval validates first); not negates a node after its own result.
  function matchesNewPerson(e) {
    return validRule(e, 0, { n: 0 }) && evalNew(e);
  }
  function validRule(e, depth, count) {
    if (!e || depth > 16 || ++count.n > 256) return false;
    const vals = e.values || [], items = e.items || [];
    const field = /^[a-z][a-z0-9_]{0,30}$/.test(e.field || '');
    switch (e.op) {
      case 'all': case 'any':
        return items.length > 0 && !e.field && !vals.length && items.every(i => validRule(i, depth + 1, count));
      case 'is': case 'is_not': case 'reports_to': return !items.length && field && vals.length === 1;
      case 'in': return !items.length && field && vals.length >= 1;
      case 'empty': return !items.length && field && !vals.length;
      default: return false;
    }
  }
  function evalNew(e) {
    let r;
    switch (e.op) {
      case 'all': r = e.items.every(evalNew); break;
      case 'any': r = e.items.some(evalNew); break;
      case 'is_not': case 'empty': r = true; break; // no values at all
      default: r = false; // is, in, reports_to: nothing to match
    }
    return e.not ? !r : r;
  }

  // ── account actions (the person page's Sign-in) ─────────
  async function userAction(a, user) {
    const u = userByName(user);
    const path = '/api/directory/users/' + enc(user);
    const otherAdmin = !!u && !u.self && !!u.admin;
    switch (a) {
      case 'invite': {
        if (!confirm('Create a new one-time invite link for ' + user + '? Whoever opens it can register a key and sign in as ' + user + '. Earlier unused invites stop working.')) return;
        const res = await act(() => api('POST', path + '/invite', {}), null);
        if (res) { closeDialog(); showSecret(res, user); }
        return;
      }
      case 'require-passkey': {
        await act(() => api('POST', path + '/require-passkey', {}), user + ' will be asked to register a passkey at next sign-in');
        return;
      }
      case 'clear-actions': {
        await act(() => api('POST', path + '/clear-actions', {}), 'Cleared pending actions');
        return;
      }
      case 'reset-passkeys': {
        const withInvite = !!u && !u.admin && !dir.invites_error;
        const what = withInvite
          ? 'Remove ALL passkeys of ' + user + ', sign them out everywhere and create a new invite link so they can register a new key.'
          : 'Remove ALL passkeys of ' + user + ' and sign them out everywhere.' + (u && u.admin
            ? ' ' + user + ' is an ADMINISTRATOR: they get no invite from the Hub. Recover them on the server with ' + (u.server_invite || './portcullis invite ' + user) + '.'
            : ' They must register a new key at their next sign-in.');
        if (!typed(what, user)) return;
        const res = await act(() => api('POST', path + '/remove-passkeys', { confirm: user, invite: withInvite }), 'Passkeys removed');
        if (!res) return;
        closeDialog();
        toast((res.count || 0) + ' passkey(s) removed', 'success');
        if (!withInvite && u && u.admin) showSecret({ server_invite: u.server_invite || './portcullis invite ' + user }, user);
        else showSecret(res, user);
        return;
      }
      case 'password': {
        const choice = prompt('Fallback: set a password for ' + user + ' (signs them out).\n\nLeave empty to generate a strong one, or type the new password (at least 12 characters):', '');
        if (choice === null) return;
        const body = choice === '' ? { generate: true } : { password: choice };
        if (otherAdmin) {
          if (!typed(user + ' is an ADMINISTRATOR: you are about to take over their password.', user)) return;
          body.confirm = user;
        }
        const res = await act(() => api('POST', path + '/password', body), 'Password changed');
        if (res) { closeDialog(); showSecret(res, user); }
        return;
      }
      case 'delete-user': {
        if (!typed('Delete ' + user + ' from LLDAP and Keycloak. This cannot be undone.', user)) return;
        const res = await act(() => api('DELETE', path, { confirm: user }), 'Deleted ' + user);
        if (res && personPage && lc(personPage) === lc(user)) userSelectTab('people', false);
        return;
      }
    }
  }

  // ── rule editor (blocks ⇄ text, live preview) ───────────
  // The tree is the API's Expr: {op, field, values, not, items}. The
  // blocks always show an all/any group at the top; a top-level single
  // condition is sent unwrapped.
  const COND_OPS = [['is', 'is'], ['is_not', 'is not'], ['in', 'is one of'], ['empty', 'is empty'], ['reports_to', 'reports to']];

  function cloneExpr(e) { return JSON.parse(JSON.stringify(e)); }
  function newCond() {
    const f = fields()[0];
    return { op: 'is', field: f ? f.name : '', values: [''] };
  }
  function rootTree(expr) {
    if (!expr) return { op: 'all', items: [newCond()] };
    const e = cloneExpr(expr);
    if (e.op === 'all' || e.op === 'any') return e;
    return { op: 'all', items: [e] };
  }
  function serialize(tree) {
    if (tree.op === 'all' && !tree.not && tree.items && tree.items.length === 1) return clean(tree.items[0]);
    return clean(tree);
  }
  function clean(e) {
    const o = { op: e.op };
    if (e.not) o.not = true;
    if (e.op === 'all' || e.op === 'any') { o.items = (e.items || []).map(clean); return o; }
    o.field = e.field;
    if (e.op === 'in') o.values = (e.values || []).filter(v => v !== '');
    else if (e.op !== 'empty') o.values = [(e.values || [])[0] || ''];
    return o;
  }
  // incomplete names the first gap the server would refuse anyway.
  function incomplete(e) {
    if (e.op === 'all' || e.op === 'any') {
      if (!e.items || !e.items.length) return 'a group has no conditions';
      for (const i of e.items) { const m = incomplete(i); if (m) return m; }
      return '';
    }
    if (!e.field) return 'a condition has no field';
    if (e.op === 'empty') return '';
    const vals = (e.values || []).filter(v => v !== '');
    if (!vals.length) return 'the condition on ' + e.field + ' has no value';
    return '';
  }
  function nodeAt(tree, path) {
    if (path === '') return tree;
    let n = tree;
    for (const i of path.split('.')) n = n.items[+i];
    return n;
  }
  function parentOf(tree, path) {
    const parts = path.split('.');
    const idx = +parts.pop();
    return { parent: nodeAt(tree, parts.join('.')), idx };
  }
  // byteColToIndex maps the API's 1-based byte column to a string index.
  function byteColToIndex(text, col) {
    let bytes = 0;
    let i = 0;
    for (const ch of text) {
      if (bytes >= col - 1) return i;
      bytes += new TextEncoder().encode(ch).length;
      i += ch.length;
    }
    return text.length;
  }

  function RuleEditor(el, initial, onChange) {
    this.el = el;
    this.onChange = onChange || function () {};
    this.mode = 'blocks';
    this.tree = rootTree(initial && initial.expr);
    this.text = (initial && initial.text) || '';
    this.seq = 0;
    this.status = '';
    this.preview = debounce(() => this.runPreview(), 300);
    el.classList.add('pd-re');
    el.addEventListener('change', e => this.onEvent(e));
    el.addEventListener('input', e => this.onEvent(e));
    el.addEventListener('click', e => this.onClick(e));
    el.addEventListener('keyup', e => { if (e.target.matches('textarea[data-re="text"]')) this.renderSuggest(); });
    this.render();
    this.preview();
  }
  RuleEditor.prototype.body = function () {
    if (this.mode === 'text') return { rule: this.text };
    return { expr: serialize(this.tree) };
  };
  RuleEditor.prototype.problem = function () {
    if (this.mode === 'text') return this.text.trim() ? '' : 'the rule is empty';
    return incomplete(this.tree);
  };
  RuleEditor.prototype.render = function () {
    const textMode = this.mode === 'text';
    let h = '<div class="pd-re-bar"><span class="pd-muted">' + (textMode ? 'Rule as text' : 'Rule blocks') + '</span>' +
      '<button type="button" class="pd-btn ghost xs" data-re="toggle" aria-pressed="' + (textMode ? 'true' : 'false') + '">' +
      (textMode ? 'Show as blocks' : 'Show as text') + '</button></div>';
    h += '<div class="pd-re-body">' + (textMode ? this.textHtml() : this.groupHtml(this.tree, '', 0)) + '</div>';
    h += '<div class="pd-re-error" role="alert"></div><div class="pd-re-preview" aria-live="polite"></div>';
    this.el.innerHTML = h;
    this.showStatus();
  };
  RuleEditor.prototype.textHtml = function () {
    const id = uid('re-text-');
    const help = 'Examples: city = "Milan" and (department = "Sales" or department = "Support") · city in ("Milan", "Turin") · manager reports-to "anna" · not department = "HR" · phone is empty';
    return '<label for="' + id + '">Rule</label><textarea id="' + id + '" class="pd-re-text" data-re="text" rows="3" spellcheck="false" autocomplete="off" aria-describedby="' + id + '-h">' +
      esc(this.text) + '</textarea><div class="pd-re-suggest" aria-label="Suggestions"></div><div id="' + id + '-h" class="pd-muted pd-small">' + esc(help) + '</div>';
  };
  RuleEditor.prototype.groupHtml = function (g, path, depth) {
    const isRoot = path === '';
    let h = '<div class="pd-re-group' + (depth % 2 ? ' alt' : '') + '" data-path="' + path + '"><div class="pd-re-head">';
    const opId = uid('re-gop-');
    h += this.notHtml(g, path);
    h += '<label for="' + opId + '">' + (isRoot ? 'Members are people matching' : 'matching') + '</label> <select id="' + opId + '" data-re="gop" data-path="' + path + '">' +
      '<option value="all"' + (g.op === 'all' ? ' selected' : '') + '>all</option><option value="any"' + (g.op === 'any' ? ' selected' : '') + '>any</option></select> <span>of:</span>';
    if (!isRoot) h += '<button type="button" class="pd-btn ghost xs" data-re="remove" data-path="' + path + '" aria-label="Remove this group">✕</button>';
    h += '</div><div class="pd-re-items">';
    (g.items || []).forEach((it, i) => {
      const p = isRoot ? String(i) : path + '.' + i;
      h += (it.op === 'all' || it.op === 'any') ? this.groupHtml(it, p, depth + 1) : this.condHtml(it, p);
    });
    if (!(g.items || []).length) h += '<div class="pd-muted">No conditions yet.</div>';
    h += '</div><div class="pd-re-add"><button type="button" class="pd-btn ghost xs" data-re="add-cond" data-path="' + path + '">+ condition</button>';
    if (depth < 15) h += '<button type="button" class="pd-btn ghost xs" data-re="add-group" data-path="' + path + '">+ group</button>';
    return h + '</div></div>';
  };
  RuleEditor.prototype.notHtml = function (n, path) {
    return '<button type="button" class="pd-re-not' + (n.not ? ' on' : '') + '" data-re="not" data-path="' + path + '" aria-pressed="' + (n.not ? 'true' : 'false') +
      '" title="Negate (NOT)">not</button>';
  };
  RuleEditor.prototype.condHtml = function (c, path) {
    const fs = fields();
    const f = fs.find(x => x.name === c.field);
    const fid = uid('re-f-'), oid = uid('re-o-');
    let h = '<div class="pd-re-cond" data-path="' + path + '">' + this.notHtml(c, path);
    h += '<label class="pd-sr" for="' + fid + '">Field</label><select id="' + fid + '" data-re="field" data-path="' + path + '">';
    if (!f) h += '<option value="' + esc(c.field) + '" selected>' + esc(c.field || 'choose a field') + (c.field ? ' (unknown field)' : '') + '</option>';
    for (const x of fs) h += '<option value="' + esc(x.name) + '"' + (x.name === c.field ? ' selected' : '') + '>' + esc(x.label || x.name) + '</option>';
    h += '</select><label class="pd-sr" for="' + oid + '">Comparison</label><select id="' + oid + '" data-re="op" data-path="' + path + '">';
    for (const [op, label] of COND_OPS) {
      if (op === 'reports_to' && f && f.kind !== 'person' && c.op !== 'reports_to') continue;
      h += '<option value="' + op + '"' + (op === c.op ? ' selected' : '') + '>' + label + '</option>';
    }
    h += '</select>' + this.valueHtml(c, f, path);
    h += '<button type="button" class="pd-btn ghost xs" data-re="remove" data-path="' + path + '" aria-label="Remove this condition">✕</button></div>';
    return h;
  };
  RuleEditor.prototype.valueHtml = function (c, f, path) {
    if (c.op === 'empty') return '';
    const vals = c.values || [];
    const kind = c.op === 'reports_to' ? 'person' : (f ? f.kind : 'text');
    const one = (v, i) => {
      const id = uid('re-v-');
      const lab = '<label class="pd-sr" for="' + id + '">Value</label>';
      if (kind === 'list') {
        const opts = (f.values || []).slice();
        if (v && !opts.includes(v)) opts.push(v);
        return lab + '<select id="' + id + '" data-re="val" data-i="' + i + '" data-path="' + path + '"><option value="">choose…</option>' +
          opts.map(o => '<option value="' + esc(o) + '"' + (o === v ? ' selected' : '') + '>' + esc(o) + '</option>').join('') + '</select>';
      }
      return lab + '<input type="text" id="' + id + '" data-re="val" data-i="' + i + '" data-path="' + path + '" value="' + esc(v) + '"' +
        (kind === 'person' ? ' data-pick="person" placeholder="username"' : ' placeholder="value"') + '>';
    };
    if (c.op !== 'in') return one(vals[0] || '', 0);
    if (kind === 'list') {
      const opts = (f.values || []).slice();
      for (const v of vals) if (v && !opts.includes(v)) opts.push(v);
      return '<span class="pd-re-in" role="group" aria-label="Values">' + opts.map(o =>
        '<label><input type="checkbox" data-re="inval" data-path="' + path + '" value="' + esc(o) + '"' + (vals.includes(o) ? ' checked' : '') + '> ' + esc(o) + '</label>').join('') + '</span>';
    }
    const list = vals.length ? vals : [''];
    return '<span class="pd-re-in">' + list.map((v, i) => one(v, i) +
      (list.length > 1 ? '<button type="button" class="pd-btn ghost xs" data-re="del-val" data-i="' + i + '" data-path="' + path + '" aria-label="Remove value">−</button>' : '')).join('') +
      '<button type="button" class="pd-btn ghost xs" data-re="add-val" data-path="' + path + '">+ value</button></span>';
  };
  RuleEditor.prototype.onEvent = function (e) {
    const t = e.target;
    const kind = t.dataset && t.dataset.re;
    if (!kind) return;
    if (kind === 'text') {
      this.text = t.value;
      this.renderSuggest();
      return this.changed();
    }
    const path = t.dataset.path;
    const n = path === undefined ? null : nodeAt(this.tree, path);
    if (!n) return;
    if (kind === 'val') {
      n.values = n.values || [];
      n.values[+t.dataset.i] = t.value;
      if (e.type === 'change' && t.tagName === 'SELECT') this.changed();
      else if (e.type === 'input') this.changed();
      return;
    }
    if (e.type !== 'change') return;
    switch (kind) {
      case 'gop': n.op = t.value; break;
      case 'field': {
        const f = fields().find(x => x.name === t.value);
        n.field = t.value;
        if (n.op === 'reports_to' && f && f.kind !== 'person') n.op = 'is';
        n.values = n.op === 'empty' ? [] : [''];
        break;
      }
      case 'op': {
        const was = n.op;
        n.op = t.value;
        if (n.op === 'empty') n.values = [];
        else if (n.op === 'in') n.values = (n.values || []).filter(v => v !== '');
        else n.values = [(n.values || [])[0] || ''];
        if (was === 'reports_to' || n.op === 'reports_to') n.values = n.op === 'empty' ? [] : [''];
        break;
      }
      case 'inval': {
        const vs = new Set(n.values || []);
        if (t.checked) vs.add(t.value); else vs.delete(t.value);
        n.values = Array.from(vs);
        break;
      }
      default: return;
    }
    this.render();
    this.changed();
    // The re-render replaced the control: put the focus back on it.
    let sel = '[data-re="' + kind + '"][data-path="' + path + '"]';
    if (kind === 'inval') sel += '[value="' + CSS.escape(t.value) + '"]';
    const again = this.el.querySelector(sel);
    if (again) again.focus();
  };
  RuleEditor.prototype.onClick = function (e) {
    if (e.target.matches('textarea[data-re="text"]')) { this.renderSuggest(); return; }
    const b = e.target.closest('[data-re]');
    if (!b || b.tagName !== 'BUTTON') return;
    const kind = b.dataset.re, path = b.dataset.path;
    if (kind === 'toggle') return this.toggle();
    if (kind === 'sug') return this.insert(b.dataset.from, b.dataset.text);
    const n = path === undefined ? null : nodeAt(this.tree, path);
    switch (kind) {
      case 'not': n.not = !n.not; break;
      case 'add-cond': n.items = (n.items || []).concat([newCond()]); break;
      case 'add-group': n.items = (n.items || []).concat([{ op: n.op === 'all' ? 'any' : 'all', items: [newCond()] }]); break;
      case 'remove': { const p = parentOf(this.tree, path); p.parent.items.splice(p.idx, 1); break; }
      case 'add-val': n.values = (n.values || []).concat(['']); break;
      case 'del-val': n.values.splice(+b.dataset.i, 1); break;
      default: return;
    }
    this.render();
    this.changed();
    const again = this.el.querySelector('[data-re="' + kind + '"][data-path="' + (kind === 'remove' ? '' : path) + '"]');
    if (again && kind !== 'remove') again.focus();
  };
  RuleEditor.prototype.changed = function () {
    this.onChange();
    this.preview();
  };
  RuleEditor.prototype.setStatus = function (err, preview, column) {
    this.status = { err: err || '', preview: preview || '', column: column || 0 };
    this.showStatus();
  };
  RuleEditor.prototype.showStatus = function () {
    const s = this.status || {};
    const errBox = this.el.querySelector('.pd-re-error');
    const prev = this.el.querySelector('.pd-re-preview');
    if (!errBox) return;
    let eh = '';
    if (s.err) {
      eh = esc(s.err);
      if (s.column && this.mode === 'text') {
        const idx = byteColToIndex(this.text, s.column);
        const lineStart = this.text.lastIndexOf('\n', idx - 1) + 1;
        let lineEnd = this.text.indexOf('\n', idx);
        if (lineEnd < 0) lineEnd = this.text.length;
        const line = this.text.slice(lineStart, lineEnd);
        eh += '<pre class="pd-re-caret">' + esc(line) + '\n' + ' '.repeat(Math.max(0, idx - lineStart)) + '^ column ' + esc(s.column) + '</pre>';
      }
    }
    errBox.innerHTML = eh;
    prev.innerHTML = s.preview || '';
  };
  RuleEditor.prototype.runPreview = async function () {
    const seq = ++this.seq;
    const gap = this.problem();
    if (gap) { this.setStatus('', '<span class="pd-muted">Incomplete rule: ' + esc(gap) + '.</span>'); return; }
    this.setStatus(this.status.err, '<span class="pd-muted">Checking…</span>', this.status.column);
    try {
      const r = await api('POST', '/api/directory/rules/preview', this.body());
      if (seq !== this.seq) return;
      const us = r.users || [];
      const shown = us.slice(0, 12).map(esc).join(', ');
      this.setStatus('', 'Matches <b>' + esc(plural(us.length, 'person', 'people')) + '</b>' + (us.length ? ': ' + shown + (us.length > 12 ? ', … (+' + (us.length - 12) + ' more)' : '') : '') +
        ' <span class="pd-muted">(live)</span>');
    } catch (err) {
      if (seq !== this.seq) return;
      this.setStatus(errText(err), '', err.column);
    }
  };
  // toggle refuses to switch while the current side can't be converted:
  // nothing may be dropped silently.
  RuleEditor.prototype.toggle = async function () {
    const gap = this.problem();
    if (gap) { this.setStatus('Can\'t switch: ' + gap + '.', ''); return; }
    try {
      const r = await api('POST', '/api/directory/rules/preview', this.body());
      if (this.mode === 'blocks') { this.text = r.text; this.mode = 'text'; }
      else { this.tree = rootTree(r.expr); this.mode = 'blocks'; }
      this.render();
      this.preview();
      const first = this.el.querySelector(this.mode === 'text' ? 'textarea' : 'select, input');
      if (first) first.focus();
    } catch (err) {
      this.setStatus('Can\'t switch until the rule parses: ' + errText(err), '', err.column);
      if (this.mode === 'text' && err.column) {
        const ta = this.el.querySelector('textarea');
        const idx = byteColToIndex(this.text, err.column);
        ta.focus();
        ta.setSelectionRange(idx, idx);
      }
    }
  };
  // Autocomplete (text mode): field names and keywords, or the values of
  // the field whose string is being typed.
  RuleEditor.prototype.renderSuggest = function () {
    const ta = this.el.querySelector('textarea[data-re="text"]');
    const box = this.el.querySelector('.pd-re-suggest');
    if (!ta || !box) return;
    const before = ta.value.slice(0, ta.selectionStart);
    const sv = /([a-z][a-z0-9_]*)\s*(?:!=|=|in\s*\(\s*(?:"(?:[^"\\]|\\.)*"\s*,\s*)*|reports-to)\s*"((?:[^"\\]|\\.)*)$/i.exec(before);
    let items = [];
    if (sv) {
      const f = fields().find(x => x.name === sv[1].toLowerCase());
      const isPerson = /reports-to\s*"[^"]*$/i.test(before) || (f && f.kind === 'person');
      const pool = isPerson ? users().map(u => u.username) : (f && f.values) || [];
      const part = sv[2].toLowerCase();
      items = pool.filter(v => v.toLowerCase().startsWith(part)).slice(0, 12).map(v => ({ from: sv[2], text: v.replace(/["\\]/g, '\\$&') + '"', label: v }));
    } else if ((before.replace(/\\./g, '').match(/"/g) || []).length % 2 === 0) { // not inside a string
      const w = /([a-z_][a-z0-9_-]*)$/i.exec(before);
      const part = w ? w[1].toLowerCase() : '';
      const words = fields().map(f => f.name).concat(['and', 'or', 'not', 'in (', 'is empty', 'reports-to', '= "', '!= "']);
      items = words.filter(x => x.startsWith(part) && x !== part).slice(0, 14).map(x => ({ from: w ? w[1] : '', text: x + (x.endsWith('"') || x.endsWith('(') ? '' : ' '), label: x }));
    }
    box.innerHTML = items.map(it => '<button type="button" class="pd-chip" data-re="sug" data-from="' + esc(it.from) + '" data-text="' + esc(it.text) + '">' + esc(it.label) + '</button>').join('');
  };
  RuleEditor.prototype.insert = function (from, text) {
    const ta = this.el.querySelector('textarea[data-re="text"]');
    const pos = ta.selectionStart;
    const start = pos - (from || '').length;
    ta.value = ta.value.slice(0, start) + text + ta.value.slice(pos);
    const at = start + text.length;
    ta.focus();
    ta.setSelectionRange(at, at);
    this.text = ta.value;
    this.renderSuggest();
    this.changed();
  };

  // ── Groups ──────────────────────────────────────────────
  // Two views on one tab, both hash routes on both listeners: #groups (the
  // list) and #groups/<name> (a group's page, the only place membership
  // changes). Back and forward move between them (hashchange → onHash).
  // #people/<name> (a person's page) is a route too.
  function parseRoute(h) {
    const p = /^#people\/(.+)$/.exec(h || '');
    if (p) { try { const n = decodeURIComponent(p[1]); return n ? { person: n } : null; } catch (_) { return null; } }
    const m = /^#groups(?:\/(.+))?$/.exec(h || '');
    if (!m) return null;
    if (!m[1]) return { group: null };
    try { return { group: decodeURIComponent(m[1]) }; } catch (_) { return { group: null }; }
  }
  const groupHash = name => name ? '#groups/' + enc(name) : '#groups';
  function setHash(h, push) {
    if (location.hash === h || (!h && !location.hash)) return;
    const url = h || location.pathname + location.search;
    if (push) history.pushState(null, '', url); else history.replaceState(null, '', url);
  }
  // applyRoute shows the list or a group's page (before the first load
  // only the state is set: load renders it).
  function applyRoute(r) {
    const hadGroup = !!groupPage, hadPerson = !!personPage;
    if (r.person) r = { person: canonPerson(r.person) };
    if (r.person) {
      if (personNote && personNote.user !== r.person) personNote = null;
      groupPage = null;
      personPage = r.person;
      tab = 'people';
    } else {
      personPage = null;
      groupPage = r.group;
      tab = 'groups';
    }
    if (!dir) return;
    if (r.person || hadPerson) renderPeople();
    if (!r.person || hadGroup) renderGroups();
    selectTab(tab, false);
    if (groupPage || personPage) refreshExtras();
  }
  // canonPerson: the directory's own spelling of a username typed in a
  // link (#people/Carol → carol), the hash replaced with it. Before the
  // first load (no directory yet) the name is kept: load resolves it.
  function canonPerson(name) {
    if (!dir) return name;
    const want = String(name).toLowerCase();
    const u = users().find(x => x.username === name) || users().find(x => String(x.username).toLowerCase() === want);
    if (!u || u.username === name) return name;
    if (parseRoute(location.hash) && parseRoute(location.hash).person === name) setHash(personHash(u.username), false);
    return u.username;
  }
  // clearRoutes leaves a group's or a person's page (their tabs show
  // their lists again).
  function clearRoutes() {
    const hadGroup = !!groupPage, hadPerson = !!personPage;
    groupPage = null;
    personPage = null;
    if (!dir) return;
    if (hadPerson) renderPeople();
    if (hadGroup) renderGroups();
  }
  // legacyUser: an old person link, #users/<name>[?password|?invite]
  // (the Hub page redirects its own here, peopleRedirect).
  function legacyUser(h) {
    const m = /^#users\/([^?]+)(?:\?(password|invite))?$/.exec(h || '');
    if (!m) return null;
    try { return { name: decodeURIComponent(m[1]), action: m[2] || '' }; } catch (_) { return null; }
  }
  function onHash() {
    if (!root) return;
    const old = legacyUser(location.hash);
    if (old) { setHash(personHash(old.name), false); openAt(old.name, old.action); return; }
    let r = parseRoute(location.hash);
    if (r) {
      if (r.person) r = { person: canonPerson(r.person) };
      if (r.person ? r.person !== personPage || tab !== 'people' : r.group !== groupPage || tab !== 'groups' || personPage) applyRoute(r);
      return;
    }
    if (!dir) return;
    const t = location.hash.slice(1) || 'people';
    if (BUILTIN_TABS.includes(t) || extraTabs.some(x => x.id === t)) { clearRoutes(); selectTab(t, false); }
  }
  // userSelectTab: a tab picked by the user. Groups always opens the
  // list; leaving a group route pushes a history entry so Back returns.
  function userSelectTab(name, focus) {
    const fromGroups = !!parseRoute(location.hash);
    if (name === 'groups') {
      clearRoutes();
      renderGroups();
      selectTab('groups', focus);
      setHash('#groups', true);
      return;
    }
    clearRoutes();
    selectTab(name, focus);
    setHash(name === 'people' ? '' : '#' + name, fromGroups);
  }
  // openGroup (the person page's Add to group…): the group's page, with
  // people already picked in its Add people form.
  function openGroup(name, opts) {
    name = String(name || '');
    if (!name) return;
    const pre = opts && Array.isArray(opts.preselect) ? opts.preselect.map(String) : [];
    pick = { group: name, users: pre, reason: '', until: '' };
    const h = groupHash(name);
    if (location.hash === h) { if (root) applyRoute({ group: name }); return; }
    location.hash = h; // hashchange routes it
  }

  // Links into the Hub's app settings (admins only). people.<domain> has
  // no app pages: its links go to https://hub.<main domain>/ (options.
  // domain, the configured domain people.html is served with — never
  // the browser's host), in a new tab.
  function hubLink(frag, text, title) {
    return '<a class="pd-a" href="' + esc('https://hub.' + String(options.domain || '') + '/' + frag) + '" target="_blank" rel="noopener noreferrer" title="' +
      esc((title ? title + ' · ' : '') + 'opens the Hub') + '">' + esc(text) + ' <span aria-hidden="true">↗</span></a>';
  }
  const appFrag = (id, key) => '#app/' + enc(id) + '/settings' + (key ? '/' + enc(key) : '');

  function groupKind(g) { return g.builtin ? 'built-in' : g.rule ? 'rule-based' : 'manual'; }
  function kindPill(g) {
    const k = groupKind(g);
    return '<span class="pd-pill ' + (k === 'rule-based' ? 'info' : k === 'manual' ? 'ok' : '') + '">' + esc(k) + '</span>';
  }
  function givesAccess(g, links) {
    if (g.name === 'lldap_admin') return 'everything (administrators)';
    const apps = (g.used_by || []).map(id => links ? hubLink(appFrag(id), id) : esc(id));
    if (g.admin && !apps.length) return 'administrators';
    return apps.length ? apps.join(', ') : '<span class="pd-muted">—</span>';
  }

  function renderGroups() {
    const box = root.querySelector('.pd-groups');
    if (groupPage) { box.innerHTML = groupPageHtml(groupPage); renderExtras(); return; }
    let h = '<div class="pd-toolbar"><label class="pd-sr" for="pd-gsearch">Search groups</label>' +
      '<input type="search" id="pd-gsearch" placeholder="search groups…" autocomplete="off" value="' + esc(gsearch) + '"><span class="pd-gcount pd-muted"></span><span class="pd-spacer"></span>';
    if (isAdmin()) {
      h += '<form class="pd-inline" data-form="new-group"><label for="pd-ng-name" class="pd-sr">New group name</label>' +
        '<input type="text" id="pd-ng-name" placeholder="e.g. users_myapp" autocomplete="off"><button type="submit" class="pd-btn primary sm">New group</button></form>';
    }
    box.innerHTML = h + '</div><div class="pd-scroll pd-glist"></div>';
    renderGroupTable();
  }
  function renderGroupTable() {
    const box = root.querySelector('.pd-glist');
    if (!box) return;
    const q = gsearch.trim().toLowerCase();
    const all = groups();
    const list = all.filter(g => !q || g.name.toLowerCase().includes(q) || (g.used_by || []).some(a => a.toLowerCase().includes(q)));
    const admin = isAdmin();
    let h = '<table class="pd-table"><thead><tr><th scope="col">Group</th><th scope="col">Kind</th><th scope="col">People</th><th scope="col">Gives access to</th></tr></thead><tbody>';
    for (const g of list) {
      h += '<tr class="pd-row pd-grow" data-group="' + esc(g.name) + '"><td><a class="pd-link pd-mono" href="' + esc(groupHash(g.name)) + '">' + esc(g.name) + '</a></td>' +
        '<td>' + kindPill(g) + '</td><td>' + esc((g.members || []).length) + '</td><td>' + givesAccess(g, admin) + '</td></tr>';
    }
    if (!list.length) h += '<tr><td colspan="4" class="pd-muted">' + (q ? 'No group matches.' : 'No groups yet.') + '</td></tr>';
    box.innerHTML = h + '</tbody></table>';
    root.querySelector('.pd-gcount').textContent = q ? list.length + ' of ' + all.length : plural(all.length, 'group');
  }

  // ── a group's page ──────────────────────────────────────
  // People rows. Rule group (admins): from members, matches and the
  // entries; manual group: members with their ends; anyone else: names.
  // Usernames compare lowercased (LLDAP ids are; stored entries may not be).
  const lc = s => String(s == null ? '' : s).toLowerCase();
  function ruleRows(g) {
    const members = new Map((g.members || []).map(u => [lc(u), u]));
    const matches = new Set((g.matches || []).map(lc));
    const ex = new Map((g.exceptions || []).map(e => [lc(e.user), e]));
    const names = Array.from(new Set(Array.from(members.keys()).concat(Array.from(matches), Array.from(ex.keys())))).sort();
    return names.map(k => {
      const e = ex.get(k);
      const inLL = members.has(k), match = matches.has(k);
      const u = members.get(k) || (e && e.user) || k;
      const acct = userByName(u) || users().find(x => lc(x.username) === k);
      const r = { user: u, state: '', tags: '', note: '', acts: [] };
      const live = e && !e.expired; // an ended entry: the rule decides alone
      if (live && e.include) {
        r.tags = '<span class="pd-pill warn">added by hand</span>' + (match ? '<span class="pd-pill info">also matches the rule</span>' : '');
        r.state = (e.until ? 'until ' + esc(fmtDate(e.until)) + ' · ' : '') + '“' + esc(e.reason) + '”';
        if (match) r.note = '⚠ keeps access if they stop matching';
        if (!inLL) r.note = (r.note ? r.note + ' · ' : '') + 'not in the group yet';
        r.acts = [['gp-end', 'Change end'], ['gp-remove', 'Remove']];
      } else if (live) {
        r.tags = '<span class="pd-pill bad">kept out</span>';
        r.state = (e.until ? 'until ' + esc(fmtDate(e.until)) + ' · ' : '') + '“' + esc(e.reason) + '”';
        if (inLL) r.note = 'still in until the next sync';
        r.acts = [['gp-letin', 'Let back in']];
      } else if (match) {
        r.tags = '<span class="pd-pill info">matches the rule</span>';
        if (!inLL) r.note = 'joins at the next sync';
        r.acts = [['gp-keepout', 'Keep out…']];
      } else if (acct && acct.protected && inLL) {
        r.tags = '<span class="pd-pill">protected account</span>';
        r.note = 'the rules leave it as it is';
      } else if (inLL) {
        r.tags = '<span class="pd-pill warn">not explained by the rule</span>';
        r.note = 'leaves at the next sync';
      } else {
        r.tags = '<span class="pd-pill">not in the group</span>';
      }
      if (e && e.expired) {
        const ended = (e.include ? 'added-by-hand' : 'kept-out') + ' entry ended' + (e.until ? ' ' + fmtDate(e.until) : '');
        r.note = r.note ? ended + ' · ' + r.note : ended;
      }
      return r;
    });
  }
  function manualRows(g) {
    const expiry = new Map(Object.entries(g.expiry || {}).map(([u, t]) => [lc(u), t]));
    return (g.members || []).map(u => {
      const until = expiry.get(lc(u));
      const r = { user: u, tags: '<span class="pd-pill ok">member</span>', state: until ? 'until ' + esc(fmtDate(until)) : '', note: '', acts: [] };
      if (!memberLocked(g, u)) r.acts = (g.name === 'lldap_admin' ? [] : [['gp-end', 'Change end']]).concat([['gp-remove', 'Remove']]);
      return r;
    });
  }
  // peopleRows: a group's rows as the caller may see them (the group
  // page and the person page share them).
  function peopleRows(g, admin) {
    if (admin) return g.rule ? ruleRows(g) : manualRows(g);
    return g.rule ? (g.members || []).map(u => ({ user: u, tags: '', state: '', note: '', acts: [] }))
      : manualRows(g).map(r => Object.assign(r, { tags: '', acts: [] }));
  }
  function personCell(u) {
    const p = userByName(u);
    return '<button type="button" class="pd-link pd-mono" data-act="open-user" data-user="' + esc(u) + '">' + esc(u) + '</button>' +
      (p && p.display_name ? ' <span class="pd-muted">' + esc(p.display_name) + '</span>' : '');
  }

  function groupPageHtml(name) {
    const g = groupByName(name);
    let h = '<nav class="pd-crumb" aria-label="Breadcrumb"><a class="pd-a" href="#groups">Groups</a> › <span class="pd-mono">' + esc(name) + '</span></nav>';
    if (!g) return h + '<p class="pd-muted">There is no group named <span class="pd-mono">' + esc(name) + '</span>.</p>';
    const admin = isAdmin();
    h += '<div class="pd-gp-head"><h2 class="pd-gp-name pd-mono">' + esc(g.name) + '</h2>' + kindPill(g) + (g.admin ? '<span class="pd-pill info">administrator group</span>' : '') + '</div>';
    h += '<p class="pd-gp-sub">Gives access to ' + givesAccess(g, admin) + '</p>';
    if (g.rule) {
      h += '<div class="pd-gp-rule"><span class="pd-muted">Rule:</span> <code>' + esc(g.rule.text) + '</code>';
      if (admin) h += ' <button type="button" class="pd-btn secondary xs" data-act="rule-open" data-group="' + esc(g.name) + '">Edit rule…</button>' +
        '<button type="button" class="pd-btn ghost xs" data-act="make-manual" data-group="' + esc(g.name) + '">Make manual</button>';
      h += '</div>';
    } else if (admin && g.rule_allowed) {
      h += '<div class="pd-gp-rule"><span class="pd-muted">Manual: people are added and removed here.</span> <button type="button" class="pd-btn secondary xs" data-act="convert-open" data-group="' + esc(g.name) + '">Make rule-based…</button></div>';
    }
    if (g.adds_blocked) h += '<div class="pd-warn">' + esc(g.adds_blocked) + '</div>';
    if (pageNote && pageNote.group === g.name) h += '<div class="pd-warn" role="status">' + esc(pageNote.text) + '</div>';

    // People
    const rows = peopleRows(g, admin);
    h += '<section class="pd-sec" aria-labelledby="pd-gp-people"><h3 class="pd-h3" id="pd-gp-people">People (' + esc((g.members || []).length) + ')</h3>';
    if (!rows.length) h += '<p class="pd-muted">' + (g.rule ? 'Nobody matches yet.' : 'No members.') + '</p>';
    else {
      h += '<table class="pd-table pd-gp-people"><tbody>';
      for (const r of rows) {
        h += '<tr data-user="' + esc(r.user) + '"><td class="pd-nowrap">' + personCell(r.user) + '</td><td>' + r.tags + (r.state ? '<span class="pd-gp-state">' + r.state + '</span>' : '') +
          (r.note ? '<div class="pd-muted pd-small">' + esc(r.note) + '</div>' : '') + '</td>';
        if (admin) {
          h += '<td class="pd-nowrap pd-right">' + r.acts.map(([a, l]) => '<button type="button" class="pd-btn ' + (a === 'gp-remove' ? 'danger' : 'ghost') + ' xs" data-act="' + a +
            '" data-group="' + esc(g.name) + '" data-user="' + esc(r.user) + '">' + esc(l) + '</button>').join('') + '</td>';
        }
        h += '</tr>';
      }
      h += '</tbody></table>';
    }
    if (admin) h += addPeopleHtml(g);
    h += '</section>';
    if (admin) {
      h += '<section class="pd-sec" aria-labelledby="pd-gp-uses-h"><h3 class="pd-h3" id="pd-gp-uses-h">Used by</h3><div class="pd-gp-uses"><p class="pd-muted">Loading…</p></div></section>';
      h += '<section class="pd-sec" aria-labelledby="pd-gp-hist-h"><div class="pd-head"><h3 class="pd-h3" id="pd-gp-hist-h">History</h3>' +
        '<button type="button" class="pd-btn ghost xs" data-act="gp-hist-reload">Refresh</button></div><div class="pd-gp-hist"><p class="pd-muted">Loading…</p></div></section>';
    }
    return h;
  }

  // Add people: a multi-pick (chips), an optional end, a reason on rule
  // groups. pick keeps the form across redraws.
  function pickCandidates(g) {
    const has = g.rule ? new Set((g.exceptions || []).filter(e => e.include && !e.expired).map(e => lc(e.user))) : new Set((g.members || []).map(lc));
    return users().filter(u => !u.protected && !has.has(lc(u.username)));
  }
  function addPeopleHtml(g) {
    if (pick.group !== g.name) pick = { group: g.name, users: [], reason: '', until: '' };
    const cand = pickCandidates(g);
    const ok = new Set(cand.map(u => u.username));
    pick.users = pick.users.filter(u => ok.has(u));
    let h = '<div class="pd-gp-add" role="group" aria-labelledby="pd-gp-add-h"><h4 class="pd-h4" id="pd-gp-add-h">Add people</h4>';
    h += '<div class="pd-gp-picks">' + pickChips(g) + '</div>';
    h += '<div class="pd-inline"><label for="pd-gp-pick" class="pd-sr">Person to add</label><input type="text" id="pd-gp-pick" placeholder="name, username or email" autocomplete="off" data-on="pick-input" data-pick="person">' +
      '<button type="button" class="pd-btn ghost xs" data-act="pick-add">+ person</button>';
    if (g.name !== 'lldap_admin') h += '<label for="pd-gp-until">until (optional, local time)</label><input type="datetime-local" id="pd-gp-until" data-on="pick-until" value="' + esc(pick.until) + '">';
    if (g.rule) h += '<label for="pd-gp-reason">reason (required)</label><input type="text" id="pd-gp-reason" maxlength="500" placeholder="why?" data-on="pick-reason" value="' + esc(pick.reason) + '">';
    h += '<button type="button" class="pd-btn primary sm" data-act="pick-submit" data-group="' + esc(g.name) + '">Add</button></div>';
    if (g.rule) h += '<p class="pd-muted pd-small">People added here stay in whether or not they match the rule, until the entry ends or is removed.</p>';
    return h + '</div>';
  }
  function pickChips(g) {
    const matches = new Set((g.matches || []).map(lc));
    return pick.users.map(u => '<span class="pd-pick"><span class="pd-mono">' + esc(u) + '</span>' +
      (g.rule ? (matches.has(lc(u)) ? ' <span class="pd-muted">already matches the rule</span>' : ' <span class="pd-muted">doesn\'t match the rule</span>') : '') +
      '<button type="button" class="pd-pick-x" data-act="pick-remove" data-user="' + esc(u) + '" aria-label="Don\'t add ' + esc(u) + '">✕</button></span>').join('');
  }
  function redrawPicks() {
    const g = groupByName(pick.group);
    const box = root.querySelector('.pd-gp-picks');
    if (!g || !box) return;
    box.innerHTML = pickChips(g);
  }
  function pickAdd() {
    const g = groupByName(pick.group);
    const el = root.querySelector('#pd-gp-pick');
    if (!g || !el) return;
    const v = el.value.trim();
    if (!v) return;
    if (!pickCandidates(g).some(u => u.username === v)) { toast(v + ' can\'t be added here (unknown, protected or already added)', 'error'); return; }
    if (!pick.users.includes(v)) pick.users.push(v);
    el.value = '';
    redrawPicks();
    el.focus();
  }
  async function pickSubmit(name) {
    const g = groupByName(name);
    if (!g) return;
    const typedName = root.querySelector('#pd-gp-pick');
    if (typedName && typedName.value.trim()) pickAdd();
    if (!pick.users.length) { toast('Pick at least one person', 'error'); return; }
    const reason = pick.reason.trim();
    if (g.rule && !reason) { toast(name + ' is rule-based: adding by hand needs a reason', 'error'); root.querySelector('#pd-gp-reason').focus(); return; }
    let until = null;
    try { until = fromLocalInput(pick.until); } catch (err) { toast(errText(err), 'error'); return; }
    if (g.admin && !confirm('Make ' + pick.users.join(', ') + ' administrators (' + name + ')? Administrators can no longer be invited from the Hub; they are recovered from the server.')) return;
    const who = pick.users.slice();
    const failed = [], notes = [], warns = [];
    for (const u of who) {
      const body = { username: u };
      if (until) body.until = until;
      if (g.rule) body.reason = reason;
      try {
        const res = await api('POST', '/api/directory/groups/' + enc(name) + '/members', body);
        if (res && res.applied === false) notes.push(res.why || '');
        if (res && res.warnings) warns.push(...res.warnings);
        pick.users = pick.users.filter(x => x !== u);
      } catch (err) {
        failed.push(u + ': ' + errText(err));
      }
    }
    const done = who.length - failed.length;
    if (!pick.users.length) { pick.reason = ''; pick.until = ''; }
    settled(name, notes);
    if (failed.length) toast((done ? 'Added ' + done + ' of ' + who.length + '. ' : '') + failed.join(' · '), 'error');
    else if (!notes.length) toast('Added ' + who.join(', ') + ' to ' + name, 'success');
    warnings({ warnings: warns });
    await load();
  }

  // settled records a save's applied/why for the group's page: "saved,
  // not applied yet: <why>" until the next save there.
  function notApplied(why) {
    why = String(why || '').trim().replace(/^stored, but not applied:\s*/i, '');
    return /^saved, not applied yet/i.test(why) ? why : 'saved, not applied yet' + (why ? ': ' + why : '');
  }
  function settled(group, whys) {
    whys = whys.filter((w, i) => whys.indexOf(w) === i);
    if (!whys.length) { if (pageNote && pageNote.group === group) pageNote = null; return; }
    pageNote = { group, text: whys.map(notApplied).join(' · ') };
    toast(pageNote.text, 'error');
  }
  // groupAct: a membership change on a group's page; the page is redrawn
  // from the server afterwards.
  async function groupAct(group, fn, okMsg) {
    let res;
    try {
      res = await fn();
    } catch (err) {
      toast(errText(err), 'error');
      return null;
    }
    if (res && res.applied === false) settled(group, [res.why || '']);
    else { settled(group, []); if (okMsg) toast(okMsg, 'success'); }
    warnings(res);
    await load();
    return res || {};
  }

  function openKeepOut(group, user) {
    openDialog('Keep ' + user + ' out of ' + group,
      '<p class="pd-note">' + esc(user) + ' matches the rule of ' + esc(group) + '. Kept out, they leave the group and stay out while the entry lasts; after its end they\'re back in if they still match.</p>' +
      '<div class="pd-grid"><div><label for="pk-reason">Reason (required)</label><input type="text" id="pk-reason" maxlength="500" placeholder="why?"></div>' +
      '<div><label for="pk-until">Until (optional, local time)</label><input type="datetime-local" id="pk-until"></div></div>' +
      '<div class="pd-actions"><button type="button" class="pd-btn primary sm" data-act="keepout-save" data-group="' + esc(group) + '" data-user="' + esc(user) + '">Keep out</button>' +
      '<button type="button" class="pd-btn secondary sm" data-act="dialog-close">Cancel</button></div>');
    dialogBody().querySelector('#pk-reason').focus();
  }
  async function keepOutSave(group, user) {
    const b = dialogBody();
    const reason = b.querySelector('#pk-reason').value.trim();
    if (!reason) { toast('Keeping someone out needs a reason', 'error'); b.querySelector('#pk-reason').focus(); return; }
    let until;
    try { until = fromLocalInput(b.querySelector('#pk-until').value); } catch (err) { toast(errText(err), 'error'); return; }
    closeDialog();
    await groupAct(group, () => api('POST', '/api/directory/groups/' + enc(group) + '/exceptions', { user, include: false, reason, until }), user + ' is kept out of ' + group);
  }
  function openEnd(group, user) {
    const g = groupByName(group);
    if (!g) return;
    const e = g.rule ? (g.exceptions || []).find(x => lc(x.user) === lc(user) && x.include) : null;
    const cur = g.rule ? (e && e.until) : (Object.entries(g.expiry || {}).find(([u]) => lc(u) === lc(user)) || [])[1];
    openDialog('End of ' + user + ' in ' + group,
      '<p class="pd-note">' + (g.rule ? 'When ' + esc(user) + '\'s added-by-hand entry ends; after it the rule decides alone.' : 'When ' + esc(user) + '\'s membership ends.') +
      ' Now: ' + (cur ? esc(fmtTime(cur)) : 'no end') + '.</p>' +
      '<div class="pd-inline"><label for="pe-until">Ends at (local time)</label><input type="datetime-local" id="pe-until" value="' + esc(toLocalInput(cur)) + '"></div>' +
      '<div class="pd-actions"><button type="button" class="pd-btn primary sm" data-act="end-save" data-group="' + esc(group) + '" data-user="' + esc(user) + '">Set end</button>' +
      (cur ? '<button type="button" class="pd-btn secondary sm" data-act="end-clear" data-group="' + esc(group) + '" data-user="' + esc(user) + '">No end</button>' : '') +
      '<button type="button" class="pd-btn secondary sm" data-act="dialog-close">Cancel</button></div>');
    dialogBody().querySelector('#pe-until').focus();
  }
  async function endSave(group, user, clear) {
    let until = null;
    if (!clear) {
      try { until = fromLocalInput(dialogBody().querySelector('#pe-until').value); } catch (err) { toast(errText(err), 'error'); return; }
      if (!until) { toast('Pick a date and time first', 'error'); return; }
    }
    closeDialog();
    await groupAct(group, () => api('PUT', '/api/directory/groups/' + enc(group) + '/members/' + enc(user) + '/expiry', { until }),
      until ? user + ' stays in ' + group + ' until ' + fmtTime(until) : user + ' has no end in ' + group);
  }

  // Used by (admins, GET …/uses) and History (admins, audit?group=),
  // fetched when the page opens and after every save. A person's page:
  // their apps and values (GET …/users/{u}/apps) and audit?user=.
  async function refreshExtras() {
    if (!isAdmin()) return;
    if (personPage) {
      const who = personPage;
      if (!userByName(who)) return;
      const seq = ++extrasSeq;
      const [p, a] = await Promise.allSettled([
        api('GET', '/api/directory/users/' + enc(who) + '/apps'),
        api('GET', '/api/directory/audit?user=' + enc(who)),
      ]);
      if (seq !== extrasSeq || personPage !== who) return;
      extras = {
        person: who,
        apps: p.status === 'fulfilled' ? p.value : null, appsErr: p.status === 'rejected' ? errText(p.reason) : '',
        audit: a.status === 'fulfilled' ? a.value : null, auditErr: a.status === 'rejected' ? errText(a.reason) : '',
      };
      renderExtras();
      return;
    }
    if (!groupPage || !groupByName(groupPage)) return;
    const name = groupPage;
    const seq = ++extrasSeq;
    const [u, a] = await Promise.allSettled([
      api('GET', '/api/directory/groups/' + enc(name) + '/uses'),
      api('GET', '/api/directory/audit?group=' + enc(name)),
    ]);
    if (seq !== extrasSeq || groupPage !== name) return;
    extras = {
      group: name,
      uses: u.status === 'fulfilled' ? u.value : null, usesErr: u.status === 'rejected' ? errText(u.reason) : '',
      audit: a.status === 'fulfilled' ? a.value : null, auditErr: a.status === 'rejected' ? errText(a.reason) : '',
    };
    renderExtras();
  }
  function renderExtras() {
    if (personPage) {
      if (extras.person !== personPage) return;
      const ab = root.querySelector('.pd-pp-apps'), vb = root.querySelector('.pd-pp-values'), hb = root.querySelector('.pd-pp-hist');
      if (ab) ab.innerHTML = personAppsHtml(extras.apps, extras.appsErr);
      if (vb) vb.innerHTML = personValuesHtml(extras.apps, extras.appsErr);
      if (hb) hb.innerHTML = historyHtml(extras.audit, extras.auditErr, e => personHistoryWords(e));
      return;
    }
    if (!groupPage || extras.group !== groupPage) return;
    const ub = root.querySelector('.pd-gp-uses'), hb = root.querySelector('.pd-gp-hist');
    if (ub) ub.innerHTML = usesHtml(groupByName(groupPage), extras.uses, extras.usesErr);
    if (hb) hb.innerHTML = historyHtml(extras.audit, extras.auditErr, e => historyWords(e, groupPage));
  }
  const ROLE_TEXT = { access: 'access group', admin: 'admin group', privileged: 'privileged values' };
  const SCOPE_TEXT = { person: 'per-person row', group: 'group record', instance: 'app setting' };
  function usesHtml(g, u, err) {
    if (!g) return '';
    let h = '';
    if (err) h += '<p class="pd-muted">Can\'t load what uses ' + esc(g.name) + ': ' + esc(err) + '</p>';
    const apps = (u && u.apps) || [], sets = (u && u.settings) || [], perms = (u && u.permissions) || [];
    if (u) {
      if (!apps.length && !sets.length && !perms.length) h += '<p class="pd-muted">Nothing uses this group.</p>';
      else {
        h += '<ul class="pd-uses">';
        for (const a of apps) h += '<li>' + hubLink(appFrag(a.instance), a.name || a.instance) + ' <span class="pd-muted">' + esc(ROLE_TEXT[a.role] || a.role) + '</span></li>';
        for (const s of sets) {
          h += '<li>' + hubLink(appFrag(s.instance, s.key), (s.app || s.instance) + ' › ' + (s.label || s.key)) + ': ' + esc(s.value) +
            ' <span class="pd-muted">' + esc(SCOPE_TEXT[s.scope] || s.scope) + '</span></li>';
        }
        for (const p of perms) {
          const def = PERMS.find(x => x[0] === p);
          h += '<li><button type="button" class="pd-link pd-a" data-act="goto-setup">' + esc(def ? def[1] : p) + '</button> <span class="pd-muted">delegated permission</span></li>';
        }
        h += '</ul>';
      }
    }
    if (!g.builtin) {
      h += '<p class="pd-muted pd-small">' + esc(deleteWhat(g, u)) + '</p>' +
        '<button type="button" class="pd-btn danger sm" data-act="gp-delete" data-group="' + esc(g.name) + '">Delete group…</button>';
    }
    return h;
  }
  // deleteWhat: what deleting g removes, in words (the confirmation's
  // text too). u: its uses (null when they couldn't be read).
  function deleteWhat(g, u) {
    const parts = [plural((g.members || []).length, 'membership') + ' (they are signed out)'];
    if (g.rule) parts.push('the rule and its ' + plural((g.exceptions || []).length, 'entry', 'entries'));
    if (u) {
      if (u.settings.length) parts.push(plural(u.settings.length, 'app setting row') + ' naming it');
      if (u.permissions.length) parts.push('the ' + u.permissions.map(p => (PERMS.find(x => x[0] === p) || [p, p])[1]).join(', ') + ' permission' + (u.permissions.length > 1 ? 's' : '') + ' (nobody holds it then)');
      if (u.apps.length) parts.push('access through it to ' + Array.from(new Set(u.apps.map(a => a.name || a.instance))).join(', '));
    } else {
      parts.push('every app setting row and permission naming it');
    }
    return 'Deleting ' + g.name + ' removes ' + parts.join('; ') + '.';
  }

  // History in plain words. The raw detail stays in the title.
  function untilWords(s) { return !s || s === 'never' ? '' : ' until ' + fmtDate(s); }
  function syncWords(user, d) {
    const add = d.charAt(0) === '+', cause = d.slice(1);
    switch (cause) {
      case 'rule': return add ? user + ' joined — matches the rule' : user + ' left — no longer matches the rule';
      case 'exception': return add ? user + ' joined — added by hand' : user + ' left — kept out';
      case 'exception expired': return add ? user + ' joined — their kept-out entry ended' : user + ' left — their added-by-hand entry ended';
      case 'membership expired': return user + (add ? ' joined' : ' left') + ' — their membership ended';
      case 'reverted: outside change': return add ? user + ' joined again — undoing a change made outside the Hub' : user + ' left — undoing a change made outside the Hub';
      default: return user + (add ? ' joined' : ' left');
    }
  }
  function historyWords(e, group) {
    const d = e.detail || '';
    const target = e.target || '';
    const tu = target.startsWith(group + ':') ? target.slice(group.length + 1) : '';
    let m;
    switch (e.action) {
      case 'group.sync': return syncWords(tu || 'someone', d);
      case 'group.exception':
        if ((m = /^add user=(\S*) include=(true|false) until=(\S+) reason=([\s\S]*)$/.exec(d))) {
          return (m[2] === 'true' ? 'added ' + m[1] + ' by hand' : 'kept ' + m[1] + ' out') + untilWords(m[3]) + (m[4] ? ' — “' + m[4] + '”' : '');
        }
        if ((m = /^remove user=(\S+)/.exec(d))) return 'removed the entry of ' + m[1];
        return 'changed an entry';
      case 'group.rule':
        if (d === 'manual') return 'made the group manual';
        if ((m = /^convert rule=([\s\S]*?)(?: keep=\S*)?(?: \(stale review\))?$/.exec(d))) return 'made the group rule-based: ' + m[1];
        if ((m = /^rule=([\s\S]*)$/.exec(d))) return 'changed the rule to ' + m[1];
        return 'changed the rule';
      case 'group.add_member':
        if ((m = /^user=(\S+) until=(\S+)/.exec(d))) return 'added ' + m[1] + untilWords(m[2]);
        return 'added ' + (d || 'someone');
      case 'group.remove_member': return 'removed ' + (d || 'someone');
      case 'group.expiry':
        if ((m = /^user=(\S+) until=(\S+)/.exec(d))) return m[2] === 'never' ? 'removed the end of ' + m[1] : 'set the end of ' + m[1] + ' to ' + fmtDate(m[2]);
        return 'changed an end';
      case 'group.create': return 'created the group';
      case 'group.delete': return 'deleted the group';
      default: return e.action + (tu ? ' ' + tu : '');
    }
  }
  // A person's history: group entries name their group first (the
  // group page's words), account entries in words of their own.
  const USER_WORDS = {
    'user.create': 'created the account', 'user.update': 'changed the email or display name', 'user.details': 'changed the details',
    'user.invite': 'sent a new invite', 'user.password': 'set a password', 'user.remove_passkeys': 'reset the passkeys',
    'user.require_passkey': 'asked for a passkey at the next sign-in', 'user.clear_actions': 'cleared the pending sign-in actions',
    'user.delete': 'deleted the account',
  };
  function personHistoryWords(e) {
    const a = e.action || '', t = e.target || '';
    if (a.startsWith('group.')) {
      const g = t.includes(':') ? t.slice(0, t.lastIndexOf(':')) : t;
      return (g ? g + ': ' : '') + historyWords(e, g);
    }
    return USER_WORDS[a] || a + (t ? ' ' + t : '');
  }
  function actorWords(e) {
    const a = e.actor === 'portcullis-hub (rules)' ? 'the rules' : (e.actor || '');
    return a + (e.via === 'ai' ? ' via AI' + (e.client ? ' (' + e.client + ')' : '') : '');
  }
  function historyHtml(items, err, words) {
    if (err) return '<p class="pd-muted">Can\'t load the history: ' + esc(err) + '</p>';
    if (!items) return '';
    if (!items.length) return '<p class="pd-muted">Nothing yet.</p>';
    items = items.filter(e => e.action !== 'group.convert_preview'); // a look, not a change
    if (!items.length) return '<p class="pd-muted">Nothing yet.</p>';
    let h = '<ol class="pd-hist">';
    for (const e of items) {
      const raw = e.action + ' ' + (e.target || '') + (e.detail ? ' · ' + e.detail : '') + (e.error ? ' · ' + e.error : '');
      const res = e.result === 'ok' ? '' : '<span class="pd-pill ' + (e.result === 'refused' ? 'warn' : 'bad') + '">' + esc(e.result) + '</span>';
      h += '<li title="' + esc(raw) + '"><span class="pd-muted pd-nowrap">' + esc(fmtTime(e.time)) + '</span> <span>' + esc(words(e)) + '</span> ' + res +
        ' <span class="pd-muted">· ' + esc(actorWords(e)) + '</span>' + (e.error ? '<div class="pd-muted pd-small">' + esc(e.error) + '</div>' : '') + '</li>';
    }
    return h + '</ol>';
  }

  // Rule editing (rule groups): PUT the rule.
  function openRuleEditor(name) {
    const g = groupByName(name);
    if (!g || !g.rule) return;
    const body = openDialog('Rule of ' + name,
      '<div class="pd-re-host"></div><div class="pd-actions"><button type="button" class="pd-btn primary sm" data-act="rule-save" data-group="' + esc(name) + '">Save rule</button>' +
      '<button type="button" class="pd-btn secondary sm" data-act="dialog-close">Cancel</button></div>');
    body.editor = new RuleEditor(body.querySelector('.pd-re-host'), g.rule);
  }
  async function saveRule(name) {
    const ed = dialogBody().editor;
    if (!ed) return;
    const gap = ed.problem();
    if (gap) { toast('Incomplete rule: ' + gap, 'error'); return; }
    let res;
    try {
      res = await api('PUT', '/api/directory/groups/' + enc(name) + '/rule', ed.body());
    } catch (err) {
      ed.setStatus(errText(err), '', err.column);
      toast(errText(err), 'error');
      return;
    }
    closeDialog();
    if (res && res.applied === false) settled(name, [res.why || '']);
    else { settled(name, []); toast('Rule of ' + name + ' saved', 'success'); }
    await load();
  }

  // Convert a manual group: edit the rule, review the ConvertPreview,
  // untick kept members, apply with the preview echoed (409 = review again).
  function openConvert(name) {
    const body = openDialog('Make ' + name + ' rule-based',
      '<div class="pd-re-host"></div><div class="pd-convert-review"></div><div class="pd-actions pd-convert-actions"></div>');
    body.group = name;
    body.editor = new RuleEditor(body.querySelector('.pd-re-host'), null, () => convertInvalidate());
    convertInvalidate();
  }
  function convertInvalidate() {
    const body = dialogBody();
    body.preview = null;
    body.reviewedBody = null;
    body.querySelector('.pd-convert-review').innerHTML = '';
    body.querySelector('.pd-convert-actions').innerHTML = '<button type="button" class="pd-btn primary sm" data-act="convert-review">Review changes</button>' +
      '<button type="button" class="pd-btn secondary sm" data-act="dialog-close">Cancel</button>';
  }
  async function convertReview(note) {
    const body = dialogBody();
    const ed = body.editor;
    const gap = ed.problem();
    if (gap) { toast('Incomplete rule: ' + gap, 'error'); return; }
    const rb = ed.body();
    let p;
    try {
      p = await api('POST', '/api/directory/groups/' + enc(body.group) + '/convert-preview', rb);
    } catch (err) {
      ed.setStatus(errText(err), '', err.column);
      toast(errText(err), 'error');
      return;
    }
    body.preview = p;
    body.reviewedBody = rb;
    const list = (xs, empty) => (xs && xs.length) ? '<div>' + xs.map(x => '<span class="pd-pill">' + esc(x) + '</span>').join('') + '</div>' : '<p class="pd-muted">' + empty + '</p>';
    let h = note ? '<div class="pd-warn" role="alert">' + esc(note) + '</div>' : '';
    h += '<h4 class="pd-h4">Matching the rule (' + (p.matching || []).length + ')</h4>' + list(p.matching, 'Nobody.');
    h += '<h4 class="pd-h4">Current members who don\'t match (' + (p.kept_as_exception || []).length + ')</h4>';
    if ((p.kept_as_exception || []).length) {
      h += '<p class="pd-muted">Ticked people stay as "added" exceptions (reason: member before the rule). Untick whoever should go.</p><div class="pd-checks">' +
        p.kept_as_exception.map(u => '<label><input type="checkbox" name="cv-keep" value="' + esc(u) + '" checked> ' + esc(u) + '</label>').join('') + '</div>';
    } else h += '<p class="pd-muted">None.</p>';
    h += '<h4 class="pd-h4">Joining (' + (p.joining || []).length + ')</h4>' + list(p.joining, 'Nobody joins.');
    if ((p.expiry_dropped || []).length) h += '<h4 class="pd-h4">Membership end dates dropped (' + p.expiry_dropped.length + ')</h4>' + list(p.expiry_dropped, '');
    body.querySelector('.pd-convert-review').innerHTML = '<div class="pd-card">' + h + '</div>';
    body.querySelector('.pd-convert-actions').innerHTML = '<button type="button" class="pd-btn primary sm" data-act="convert-apply">Make rule-based</button>' +
      '<button type="button" class="pd-btn secondary sm" data-act="dialog-close">Cancel</button>';
  }
  async function convertApply() {
    const body = dialogBody();
    if (!body.preview) return;
    const keep = Array.from(body.querySelectorAll('input[name="cv-keep"]:checked')).map(i => i.value);
    const req = Object.assign({}, body.reviewedBody, { keep, preview: body.preview });
    let res;
    try {
      res = await api('POST', '/api/directory/groups/' + enc(body.group) + '/convert', req);
    } catch (err) {
      if (err.status === 409) {
        await convertReview('The group or the people changed since you reviewed it: review again.');
        return;
      }
      toast(errText(err), 'error');
      return;
    }
    const name = body.group;
    closeDialog();
    if (res && res.applied === false) settled(name, [res.why || '']);
    else { settled(name, []); toast(name + ' is now rule-based', 'success'); }
    await load();
  }

  // ── Org chart ───────────────────────────────────────────
  function personFields() { return fields().filter(f => f.kind === 'person'); }
  function renderOrg() {
    const box = root.querySelector('.pd-org');
    const pf = personFields();
    if (!pf.length) {
      box.innerHTML = '<p class="pd-muted">No person field yet, so there is no org chart.' + (isAdmin() ? ' Add a "manager" field of kind <i>person</i> under Setup.' : '') + '</p>';
      return;
    }
    if (!pf.find(f => f.name === orgField)) orgField = (pf.find(f => f.name === 'manager') || pf[0]).name;
    const mf = orgField;
    const by = new Map(users().map(u => [u.username, u]));
    const mgrOf = u => ((u.attrs || {})[mf] || [])[0] || '';
    const kids = new Map();
    for (const u of users()) {
      const m = mgrOf(u);
      if (m && by.has(m) && m !== u.username) {
        if (!kids.has(m)) kids.set(m, []);
        kids.get(m).push(u.username);
      }
    }
    for (const l of kids.values()) l.sort();
    // Loops: walk each manager chain once (no recursion, so no runaway).
    const inCycle = new Set();
    const loops = [];
    const walk = new Map(); // 1 = on the current path, 2 = done
    for (const u of users()) {
      const path = [];
      let cur = u.username;
      while (cur && by.has(cur) && !walk.get(cur)) {
        walk.set(cur, 1);
        path.push(cur);
        cur = mgrOf(by.get(cur));
      }
      if (cur && walk.get(cur) === 1) {
        const loop = path.slice(path.indexOf(cur));
        loops.push(loop);
        loop.forEach(n => inCycle.add(n));
      }
      path.forEach(n => walk.set(n, 2));
    }
    // The API's cycles (of the configured manager field) are flagged too.
    for (const c of dir.cycles || []) for (const n of c) if (by.has(n) && mgrOf(by.get(n))) inCycle.add(n);
    const seen = new Set();
    const label = n => {
      const u = by.get(n);
      return '<button type="button" class="pd-link" data-act="open-user" data-user="' + esc(n) + '">' + esc(n) + '</button>' +
        (u && u.display_name ? ' <span class="pd-muted">' + esc(u.display_name) + '</span>' : '') +
        (inCycle.has(n) ? ' <span class="pd-loop" title="Their manager chain loops back to them">⚠ manager loop</span>' : '');
    };
    // node renders n and its reports; seen stops any repeat.
    const node = n => {
      if (seen.has(n)) return '';
      seen.add(n);
      const ks = (kids.get(n) || []).filter(k => !inCycle.has(k) && !seen.has(k));
      return '<li>' + label(n) + (ks.length ? '<ul>' + ks.map(node).join('') + '</ul>' : '') + '</li>';
    };
    const roots = users().filter(u => { const m = mgrOf(u); return !m || !by.has(m); }).map(u => u.username).sort();
    let h = '';
    if (pf.length > 1) {
      h += '<div class="pd-inline"><label for="pd-orgfield">Chart by</label><select id="pd-orgfield" data-on="org-field">' + pf.map(f =>
        '<option value="' + esc(f.name) + '"' + (f.name === mf ? ' selected' : '') + '>' + esc(f.label || f.name) + '</option>').join('') + '</select></div>';
    }
    const top = roots.filter(r => (kids.get(r) || []).length);
    const alone = roots.filter(r => !(kids.get(r) || []).length);
    h += top.length ? '<div class="pd-orgtree"><ul class="pd-tree">' + top.map(node).join('') + '</ul></div>' : '<p class="pd-muted">Nobody has a ' + esc(mf) + ' yet.</p>';
    if (alone.length) h += '<h3 class="pd-h3">No ' + esc(mf) + ', no reports</h3><ul class="pd-tree flat">' + alone.map(node).join('') + '</ul>';
    if (loops.length) {
      h += '<h3 class="pd-h3 pd-loop">⚠ Manager loops</h3><p class="pd-muted">These people\'s ' + esc(mf) + ' chain goes round in a circle; change one of them to break it.</p>';
      for (const c of loops) {
        h += '<div class="pd-card pd-loopcard"><div class="pd-muted">' + c.map(esc).join(' → ') + ' → ' + esc(c[0]) + '</div><ul class="pd-tree">';
        for (const n of c) {
          seen.add(n);
          const ks = (kids.get(n) || []).filter(k => !inCycle.has(k) && !seen.has(k));
          h += '<li>' + label(n) + ' <span class="pd-muted">reports to ' + esc(mgrOf(by.get(n))) + '</span>' + (ks.length ? '<ul>' + ks.map(node).join('') + '</ul>' : '') + '</li>';
        }
        h += '</ul></div>';
      }
    }
    // Safety net: anyone not placed above (should not happen).
    const rest = users().map(u => u.username).filter(n => !seen.has(n)).sort();
    if (rest.length) {
      h += '<h3 class="pd-h3">Others</h3><ul class="pd-tree flat">' + rest.map(n => '<li>' + label(n) + ' <span class="pd-muted">reports to ' + esc(mgrOf(by.get(n))) + '</span></li>').join('') + '</ul>';
    }
    box.innerHTML = h;
  }

  // ── Setup (admins) ──────────────────────────────────────
  function renderSetup() {
    const box = root.querySelector('.pd-setup');
    // The Hub's own LLDAP account: never listed among people (the
    // overview leaves it out), named here once.
    let h = dir.service_user ? '<p class="pd-note pd-service-account">Service account: <span class="pd-mono">' + esc(dir.service_user) +
      '</span> — used by the Hub to manage users and groups; it can\'t sign in.</p>' : '';
    h += '<section class="pd-sec" aria-labelledby="pd-fields-h"><h3 class="pd-h3" id="pd-fields-h">Fields</h3>' +
      '<p class="pd-muted">Fields describe people. Everyone signed in can see them; <b>admin-only</b> fields can only be changed by admins (the rules of administrator and permission groups may only use those). <b>Share with apps</b> sends the value as an OIDC claim (<code>attr_&lt;field&gt;</code>) and as the <code>X-Forwarded-Attr-&lt;Field&gt;</code> header.</p>';
    h += '<table class="pd-table pd-fields"><thead><tr><th scope="col">Name</th><th scope="col">Label</th><th scope="col">Kind</th><th scope="col">Values</th><th scope="col">Several values</th><th scope="col">Share with apps</th><th scope="col">Admin-only</th><th scope="col"><span class="pd-sr">Actions</span></th></tr></thead><tbody>';
    for (const f of fields()) {
      const p = 'pd-fd-' + f.name;
      h += '<tr data-fieldrow="' + esc(f.name) + '"><td class="pd-mono">' + esc(f.name) + '</td>' +
        '<td><label class="pd-sr" for="' + esc(p) + '-label">Label of ' + esc(f.name) + '</label><input type="text" id="' + esc(p) + '-label" name="label" value="' + esc(f.label) + '"></td>' +
        '<td>' + esc(f.kind) + '</td><td>' + (f.kind === 'list'
          ? '<label class="pd-sr" for="' + esc(p) + '-values">Values of ' + esc(f.name) + ' (one per line)</label><textarea id="' + esc(p) + '-values" name="values" rows="3">' + esc((f.values || []).join('\n')) + '</textarea>'
          : '<span class="pd-muted">—</span>') + '</td>' +
        '<td>' + (f.multi ? 'yes' : 'no') + '</td>' +
        '<td><label><input type="checkbox" name="share"' + (f.share_with_apps ? ' checked' : '') + '><span class="pd-sr"> share ' + esc(f.name) + ' with apps</span></label></td>' +
        '<td><label><input type="checkbox" name="admin_only"' + (f.admin_only ? ' checked' : '') + '><span class="pd-sr"> ' + esc(f.name) + ' is admin-only</span></label></td>' +
        '<td class="pd-nowrap"><button type="button" class="pd-btn secondary xs" data-act="field-save" data-field="' + esc(f.name) + '">Save</button>' +
        '<button type="button" class="pd-btn danger xs" data-act="field-delete" data-field="' + esc(f.name) + '">Delete</button></td></tr>';
    }
    if (!fields().length) h += '<tr><td colspan="8" class="pd-muted">No fields yet.</td></tr>';
    h += '</tbody></table>';
    h += '<form class="pd-card" data-form="new-field"><fieldset class="pd-fieldset"><legend>New field</legend><div class="pd-grid">' +
      '<div><label for="nf-name">Name</label><input type="text" id="nf-name" name="name" placeholder="lowercase, e.g. city" autocomplete="off" required></div>' +
      '<div><label for="nf-label">Label</label><input type="text" id="nf-label" name="label" placeholder="City" required></div>' +
      '<div><label for="nf-kind">Kind</label><select id="nf-kind" name="kind"><option value="text">free text</option><option value="list">list (values you maintain)</option><option value="person">person (e.g. manager)</option></select></div>' +
      '<div class="pd-nf-values"><label for="nf-values">Values (list, one per line)</label><textarea id="nf-values" name="values" rows="3"></textarea></div></div>' +
      '<div class="pd-checks"><label><input type="checkbox" name="multi"> several values</label><label><input type="checkbox" name="share" checked> share with apps</label>' +
      '<label><input type="checkbox" name="admin_only"> admin-only</label></div><button type="submit" class="pd-btn primary sm">Add field</button></fieldset></form></section>';

    h += '<section class="pd-sec" aria-labelledby="pd-perms-h"><h3 class="pd-h3" id="pd-perms-h">Permissions</h3><p class="pd-muted">Each permission goes to the members of one group (manual or rule-based). Delegates never act on themselves, administrators or members of a permission group. Everything else stays admins only.</p>' +
      '<table class="pd-table"><thead><tr><th scope="col">Permission</th><th scope="col">Granted to</th><th scope="col"><span class="pd-sr">Actions</span></th></tr></thead><tbody>';
    const eligible = groups().filter(g => !g.builtin && !g.admin);
    for (const [perm, label, what] of PERMS) {
      const cur = (dir.permissions || {})[perm] || '';
      const id = 'pd-perm-' + perm;
      const opts = eligible.slice();
      if (cur && !opts.find(g => g.name === cur)) opts.push({ name: cur });
      h += '<tr><td><label for="' + id + '"><b>' + esc(label) + '</b></label><div class="pd-muted">' + esc(what) + '</div></td><td><select id="' + id + '"><option value="">nobody</option>' +
        opts.map(g => '<option value="' + esc(g.name) + '"' + (g.name === cur ? ' selected' : '') + '>' + esc(g.name) + (g.rule ? ' ⚡' : '') + '</option>').join('') + '</select></td>' +
        '<td><button type="button" class="pd-btn secondary xs" data-act="perm-save" data-perm="' + perm + '">Save</button></td></tr>';
    }
    h += '</tbody></table></section>';
    box.innerHTML = h;
    syncNewFieldForm();
  }
  function syncNewFieldForm() {
    const form = root.querySelector('form[data-form="new-field"]');
    if (!form) return;
    const kind = form.kind.value;
    form.querySelector('.pd-nf-values').hidden = kind !== 'list';
    form.multi.disabled = kind === 'person';
    if (kind === 'person') form.multi.checked = false;
  }
  // ── the audit log (the Hub's Audit log tab: renderAudit) ──
  // The audit view's filter (contract §9.5, §15.11): '' every change,
  // 'ai' only those made through the Portcullis MCP (?via=ai), 'access'
  // those merged with the gate's access-log lines (&include=access).
  // It lives on the Hub only (index.html's Audit log tab), apart from
  // the directory UI: renderAudit(el) mounts it into any element.
  let auditFilter = '';
  let auditEl = null;
  function renderAudit(el) {
    if (!el) return Promise.resolve();
    if (auditEl !== el) {
      auditEl = el;
      el.classList.add('pd');
      el.addEventListener('change', ev => {
        if (ev.target.closest('[data-on="audit-filter"]')) { auditFilter = ev.target.value; loadAudit(); }
      });
      el.addEventListener('click', ev => {
        if (ev.target.closest('[data-act="audit-reload"]')) loadAudit();
      });
      el.innerHTML = '<section class="pd-sec" aria-labelledby="pd-audit-h"><div class="pd-head"><h3 class="pd-h3" id="pd-audit-h">Audit log (last 100 changes)</h3><div class="pd-inline"><label for="pd-audit-filter">Show</label><select id="pd-audit-filter" data-on="audit-filter">' +
        [['', 'all changes'], ['ai', 'changes made via AI'], ['access', 'via AI, with the AI requests (access log)']].map(([v, l]) => '<option value="' + v + '"' + (auditFilter === v ? ' selected' : '') + '>' + esc(l) + '</option>').join('') +
        '</select><button type="button" class="pd-btn secondary xs" data-act="audit-reload">Refresh</button></div></div><div class="pd-audit"><p class="pd-muted">Loading…</p></div></section>';
    }
    return loadAudit();
  }
  function auditEntryRow(e) {
    const cls = e.result === 'ok' ? 'ok' : (e.result === 'refused' ? 'warn' : 'bad');
    return '<tr><td class="pd-muted pd-nowrap">' + esc(fmtTime(e.time)) + '</td><td>' + esc(e.actor) +
      (e.via === 'ai' ? '<div><span class="pd-pill info" title="Made through the Portcullis MCP">via AI</span>' + (e.client ? '<span class="pd-muted">' + esc(e.client) + '</span>' : '') + '</div>' : '') +
      '</td><td>' + esc(e.action) + (e.detail ? '<div class="pd-muted">' + esc(e.detail) + '</div>' : '') + '</td><td>' + esc(e.target) + '</td>' +
      '<td><span class="pd-pill ' + cls + '">' + esc(e.result) + '</span>' + (e.error ? '<div class="pd-muted">' + esc(e.error) + '</div>' : '') + '</td></tr>';
  }
  // An access-log line (§15.8): who, through which client, what (the
  // aggregate's <instance>__<tool> name, or the method), the decision.
  function auditAccessRow(l) {
    const what = l.tool ? (l.instance ? l.instance + '__' + l.tool : l.tool) : l.method;
    return '<tr class="pd-access"><td class="pd-muted pd-nowrap">' + esc(fmtTime(l.time)) + '</td><td>' + esc(l.user || '(no valid token)') +
      '<div><span class="pd-pill">AI request</span>' + (l.client ? '<span class="pd-muted">' + esc(l.client) + '</span>' : '') + '</div></td>' +
      '<td><code>' + esc(what) + '</code><div class="pd-muted">' + esc(l.via) + ' · ' + esc(l.method) + '</div></td><td>' + esc(l.resource) + '</td>' +
      '<td>' + aiDecision(l.decision, 'pd-pill') + (l.upstream_status ? '<div class="pd-muted">app answered ' + esc(l.upstream_status) + '</div>' : '') + '</td></tr>';
  }
  async function loadAudit() {
    const box = auditEl && auditEl.querySelector('.pd-audit');
    if (!box) return;
    const url = '/api/directory/audit' + (auditFilter === 'ai' ? '?via=ai' : auditFilter === 'access' ? '?via=ai&include=access' : '');
    const head = auditEl.querySelector('#pd-audit-h');
    if (head) {
      head.textContent = auditFilter === 'access' ? 'Audit log via AI and AI requests (last 100 of each)'
        : auditFilter === 'ai' ? 'Audit log: changes made via AI (last 100)' : 'Audit log (last 100 changes)';
    }
    let note = '';
    try {
      let items;
      try {
        items = await api('GET', url);
      } catch (err) {
        // The gate's access log can't be read (no gate data directory,
        // 503): the audit entries alone, said so.
        if (auditFilter !== 'access' || err.status !== 503) throw err;
        note = '<p class="pd-muted">The AI access log can\'t be read right now (' + esc(errText(err)) + '): showing the changes made via AI only.</p>';
        items = await api('GET', '/api/directory/audit?via=ai');
      }
      if (!items.length) {
        box.innerHTML = note + '<p class="pd-muted">' + (auditFilter ? 'Nothing made via AI yet.' : 'No changes yet.') + '</p>';
        return;
      }
      const cols = auditFilter === 'access' && !note ? ['Time', 'Who (client)', 'Action or AI request', 'Target or resource', 'Result or decision']
        : ['Time', 'Who', 'Action', 'Target', 'Result'];
      let h = note + '<table class="pd-table"><thead><tr>' + cols.map(c => '<th scope="col">' + esc(c) + '</th>').join('') + '</tr></thead><tbody>';
      for (const it of items) {
        if (it.source === 'access') h += it.line ? auditAccessRow(it.line) : '';
        else h += auditEntryRow(it.source === 'audit' ? (it.entry || {}) : it);
      }
      box.innerHTML = h + '</tbody></table>';
    } catch (err) {
      box.innerHTML = '<p class="pd-muted">Failed to load the audit log: ' + esc(errText(err)) + '</p>';
    }
  }
  async function saveField(name) {
    const row = root.querySelector('tr[data-fieldrow="' + CSS.escape(name) + '"]');
    const f = fields().find(x => x.name === name);
    if (!row || !f) return;
    const patch = {};
    const label = row.querySelector('[name="label"]').value.trim();
    if (label !== f.label) patch.label = label;
    const va = row.querySelector('[name="values"]');
    if (va) {
      const vals = va.value.split('\n').map(s => s.trim()).filter(Boolean);
      if (!sameList(vals, f.values || [])) patch.values = vals;
    }
    const share = row.querySelector('[name="share"]').checked;
    if (share !== !!f.share_with_apps) patch.share_with_apps = share;
    const ao = row.querySelector('[name="admin_only"]').checked;
    if (ao !== !!f.admin_only) patch.admin_only = ao;
    if (!Object.keys(patch).length) { toast('Nothing changed'); return; }
    await act(() => api('PUT', '/api/directory/fields/' + enc(name), patch), 'Field ' + name + ' saved');
  }
  async function createField(form) {
    const kind = form.kind.value;
    const body = {
      name: form.name.value.trim(),
      label: form.label.value.trim(),
      kind,
      multi: form.multi.checked,
      share_with_apps: form.share.checked,
      admin_only: form.admin_only.checked,
    };
    if (kind === 'list') body.values = form.values.value.split('\n').map(s => s.trim()).filter(Boolean);
    await act(() => api('POST', '/api/directory/fields', body), 'Field ' + body.name + ' added');
  }

  // ── Import review ───────────────────────────────────────
  const SPECIAL = ['username', 'display_name', 'email'];
  async function importUpload(file) {
    if (!file) return;
    if (file.size > 5 * 1024 * 1024) { toast('CSV file too large (max 5 MB)', 'error'); return; }
    const fd = new FormData();
    fd.append('file', file, file.name);
    let r;
    try {
      r = await finish(await fetch('/api/directory/import/review', { method: 'POST', body: fd, credentials: 'same-origin' }));
    } catch (err) {
      toast('Import: ' + errText(err), 'error');
      return;
    }
    imp = {
      file: file.name, header: r.header, rows: r.rows, orig: r.rows.map(x => x.slice()), review: r.review,
      tick: {}, tickMissing: {}, show: { new: true, changed: true, missing: true, same: false }, q: '',
      pending: false, seq: 0, results: null,
    };
    renderPeople();
    root.querySelector('.pd-import').scrollIntoView({ block: 'start' });
  }
  // reReview posts the edited rows for a fresh review. Edits are local
  // and win: a response is used only if no edit happened since its request
  // (imp.seq bumps on every edit) and the rows it reviewed are still the
  // current ones; the server's rows never replace the table.
  const reReview = debounce(async () => {
    if (!imp) return;
    const mine = imp;
    const seq = mine.seq;
    const sent = JSON.stringify(mine.rows);
    let r = null, error = '';
    try {
      r = await api('POST', '/api/directory/import/review', { header: mine.header, rows: JSON.parse(sent) });
    } catch (err) {
      error = errText(err);
    }
    if (imp !== mine || seq !== mine.seq || JSON.stringify(mine.rows) !== sent) return; // stale: a newer review follows
    if (r) mine.review = r.review;
    mine.error = error;
    mine.pending = false;
    renderImport(true);
  }, 400);
  function importChanged() {
    imp.seq++;
    imp.pending = true;
    reReview();
    renderImportFooter();
  }
  function colIndex(name) { return imp.header.indexOf(name); }
  function currentOf(rr, col, u) {
    if (col === 'display_name') return u ? [u.display_name || ''] : null;
    if (col === 'email') return u ? [u.email || ''] : null;
    const c = rr && rr.cells && rr.cells[col];
    return c ? (c.current || []) : null;
  }
  function splitCell(col, v) {
    if (col === 'display_name' || col === 'email') return v.trim() ? [v.trim()] : [];
    return v.split('|').map(s => s.trim()).filter(Boolean);
  }
  function rowTicked(i, rr) {
    if (rr.status === 'missing') return !!imp.tickMissing[rr.user];
    return imp.tick[i] !== false;
  }
  function importStats() {
    const rev = imp.review.rows || [];
    const s = { new: 0, changed: 0, missing: 0, same: 0, apply: 0, problems: [] };
    rev.forEach((rr, i) => {
      s[rr.status] = (s[rr.status] || 0) + 1;
      if (rr.status === 'same' || !rowTicked(i, rr)) return;
      s.apply++;
      for (const p of rr.problems || []) s.problems.push(rr.user + ': ' + p);
    });
    return s;
  }

  function renderImport(keepFocus) {
    const box = root.querySelector('.pd-import');
    if (!imp) { box.innerHTML = ''; return; }
    let focus = null;
    const a = document.activeElement;
    if (keepFocus && a && box.contains(a) && (a.dataset.r !== undefined || a.id === 'pd-imp-q')) {
      focus = { id: a.id, r: a.dataset.r, c: a.dataset.c, s: a.selectionStart, e: a.selectionEnd };
    }
    if (imp.results) { box.innerHTML = importResultsHtml(); return; }
    const rev = imp.review;
    const st = importStats();
    let h = '<div class="pd-imp-head"><h3 class="pd-h3">Import review: ' + esc(imp.file) + '</h3><p>' +
      esc(st.new + ' new · ' + st.changed + ' changed · ' + st.missing + ' not in file · ' + st.same + ' unchanged' + (imp.show.same ? '' : ' (hidden)')) + '</p>' +
      '<p class="pd-muted">Uploading changed nothing yet. Edit any cell; ↺ keeps what Portcullis has. Multiple values: separate them with |. ' +
      'An empty cell clears a field, but email and display name can\'t be cleared by import (leave them as they are). ' +
      'A leading \' before =, +, -, @ (as in the CSV this page downloads) is dropped on upload.</p></div>';
    if ((rev.unknown_columns || []).length) h += '<div class="pd-warn">Ignored columns (not a field): ' + rev.unknown_columns.map(esc).join(', ') + '</div>';
    if (imp.error) h += '<div class="pd-warn" role="alert">' + esc(imp.error) + '</div>';
    h += '<div class="pd-toolbar" role="group" aria-label="Show rows"><span>Show:</span>';
    for (const [k, label] of [['new', 'new'], ['changed', 'changed'], ['missing', 'not in file'], ['same', 'unchanged']]) {
      h += '<label class="pd-filter"><input type="checkbox" data-on="imp-show" value="' + k + '"' + (imp.show[k] ? ' checked' : '') + '> ' + label + '</label>';
    }
    h += '<label for="pd-imp-q" class="pd-sr">Filter rows</label><input type="search" id="pd-imp-q" data-on="imp-q" placeholder="filter…" value="' + esc(imp.q) + '"></div>';
    const cols = imp.header.map((c, j) => ({ c, j })).filter(x => x.c !== 'username');
    const fs = new Map(fields().map(f => [f.name, f]));
    h += '<div class="pd-scroll"><table class="pd-table pd-imp"><thead><tr><th scope="col"><span class="pd-sr">Apply</span></th><th scope="col">username</th><th scope="col">Status</th>';
    for (const { c } of cols) h += '<th scope="col">' + esc(c === 'display_name' ? 'name' : (fs.get(c) ? fs.get(c).label || c : c)) + '</th>';
    h += '</tr></thead><tbody>';
    const q = imp.q.trim().toLowerCase();
    const ucol = colIndex('username');
    let shown = 0;
    const LIMIT = 500;
    (rev.rows || []).forEach((rr, i) => {
      if (!imp.show[rr.status]) return;
      const isMissing = rr.status === 'missing';
      const row = isMissing ? null : imp.rows[i];
      if (q && !String(isMissing ? rr.user : (row[ucol] || '')).toLowerCase().includes(q)) return;
      if (++shown > LIMIT) return;
      const u = userByName(isMissing ? rr.user : String((row && row[ucol]) || '').trim());
      const probs = rr.problems || [];
      const ticked = rowTicked(i, rr);
      const key = isMissing ? 'm:' + rr.user : String(i);
      h += '<tr class="pd-imp-' + esc(rr.status) + (probs.length && ticked ? ' pd-imp-bad' : '') + (ticked ? '' : ' pd-imp-off') + '">';
      h += '<td>' + (rr.status === 'same' ? '' : '<input type="checkbox" data-on="imp-tick" data-key="' + esc(key) + '"' + (ticked ? ' checked' : '') +
        ' aria-label="' + esc((isMissing ? 'Remove ' : 'Apply ') + rr.user) + '">') + '</td>';
      if (isMissing) {
        h += '<td class="pd-mono">' + esc(rr.user) + '</td><td>not in file' + (ticked ? ' · <b>will be removed</b>' : '') + '</td>';
        h += '<td colspan="' + cols.length + '" class="pd-muted">tick to remove this person' + (u && u.display_name ? ' (' + esc(u.display_name) + ')' : '') + '</td>';
      } else {
        h += '<td>' + cellInput(i, ucol, row[ucol] || '', 'username', null, false) + '</td>';
        h += '<td>' + esc(rr.status === 'new' ? 'new · gets setup link' : rr.status) + '</td>';
        for (const { c, j } of cols) {
          const val = row[j] == null ? '' : row[j];
          const cur = rr.status === 'new' ? null : currentOf(rr, c, u);
          const known = c === 'display_name' || c === 'email' || fs.has(c);
          const diff = cur !== null && known && !sameList(cur, splitCell(c, val));
          const bad = probs.some(p => p.startsWith('field ' + c + ':') || p.startsWith('field ' + c + ' ') || (SPECIAL.includes(c) && p.includes(c)));
          const orig = imp.orig[i] ? (imp.orig[i][j] == null ? '' : imp.orig[i][j]) : null;
          h += '<td class="' + (diff ? 'pd-imp-diff' : '') + (bad ? ' pd-imp-problem' : '') + '">';
          if (diff) h += '<s class="pd-muted" title="current value">' + esc(cur.join(' | ') || '(empty)') + '</s> ';
          h += cellInput(i, j, val, c, fs.get(c), bad);
          if (diff) h += '<button type="button" class="pd-btn ghost xs" data-act="imp-keep" data-r="' + i + '" data-c="' + j + '" title="Keep the current value" aria-label="Keep the current ' + esc(c) + ' of ' + esc(rr.user) + '">↺</button>';
          if (orig !== null && orig !== val) h += '<div class="pd-small pd-muted">(' + (cur !== null && sameList(cur, splitCell(c, val)) ? 'kept current' : 'edited') + '; file said ' + esc(orig || 'nothing') + ')</div>';
          h += '</td>';
        }
      }
      h += '</tr>';
      if (probs.length) h += '<tr class="pd-imp-probrow"><td></td><td colspan="' + (cols.length + 2) + '">' + probs.map(p => '<div>⚠ ' + esc(p) + '</div>').join('') + '</td></tr>';
    });
    if (shown > LIMIT) h += '<tr><td colspan="' + (cols.length + 3) + '" class="pd-muted">' + (shown - LIMIT) + ' more rows: narrow the filter to see them.</td></tr>';
    if (!shown) h += '<tr><td colspan="' + (cols.length + 3) + '" class="pd-muted">No rows match the filters.</td></tr>';
    h += '</tbody></table></div>';
    h += '<div class="pd-actions"><button type="button" class="pd-btn secondary sm" data-act="imp-add">+ add row</button><button type="button" class="pd-btn secondary sm" data-act="imp-download">Download CSV</button></div>';
    h += '<div class="pd-effect" aria-live="polite"></div><div class="pd-imp-foot"></div>';
    box.innerHTML = h;
    renderImportFooter();
    if (focus) {
      const el = focus.id === 'pd-imp-q' ? box.querySelector('#pd-imp-q')
        : box.querySelector('input[data-r="' + CSS.escape(focus.r) + '"][data-c="' + CSS.escape(focus.c) + '"]');
      if (el) { el.focus(); try { el.setSelectionRange(focus.s, focus.e); } catch (_) { /* select */ } }
    }
  }
  function cellInput(i, j, val, col, f, bad) {
    const label = 'Row ' + (i + 1) + ' ' + col;
    let list = '';
    if (f && f.kind === 'person') list = ' data-pick="person"';
    else if (f && f.kind === 'list') list = ' list="pd-dl-' + esc(f.name) + '"';
    return '<input type="text" class="pd-cell' + (bad ? ' bad' : '') + '" data-on="imp-cell" data-r="' + i + '" data-c="' + j + '" value="' + esc(val) + '" aria-label="' + esc(label) + '"' + list + '>';
  }
  function renderImportFooter() {
    if (!imp || imp.results) return;
    const box = root.querySelector('.pd-import');
    const eff = box.querySelector('.pd-effect');
    const foot = box.querySelector('.pd-imp-foot');
    if (!eff || !foot) return;
    const effect = imp.review.effect || {};
    const names = Object.keys(effect).sort();
    eff.innerHTML = '<b>Effect on rule-based groups:</b> ' + (imp.pending ? '<span class="pd-muted">recomputing…</span>' : names.length ? names.map(g => {
      const [a, r] = effect[g];
      return '<span class="pd-mono">' + esc(g) + '</span> ' + (a ? '<span class="pd-plus">+' + esc(a) + '</span>' : '+0') + (r ? ' <span class="pd-minus">−' + esc(r) + '</span>' : '');
    }).join(' · ') : '<span class="pd-muted">no change</span>');
    const st = importStats();
    const blocked = st.problems.length > 0 || imp.pending || !!imp.error || st.apply === 0;
    let why = '';
    if (imp.pending) why = 'checking your edits…';
    else if (imp.error) why = 'fix the error above first';
    else if (st.problems.length) why = plural(st.problems.length, 'problem') + ' to fix first (' + st.problems.slice(0, 3).join('; ') + (st.problems.length > 3 ? '; …' : '') + ')';
    else if (!st.apply) why = 'nothing to apply';
    foot.innerHTML = '<button type="button" class="pd-btn primary" data-act="imp-apply"' + (blocked ? ' disabled aria-disabled="true"' : '') + '>Apply ' + esc(plural(st.apply, 'change')) + '</button>' +
      '<button type="button" class="pd-btn secondary" data-act="imp-cancel">Cancel</button>' + (why ? ' <span class="pd-muted" role="status">' + esc(why) + '</span>' : '');
    // datalists for list fields (cell pickers)
    let dl = root.querySelector('.pd-imp-dls');
    if (dl) dl.innerHTML = fields().filter(f => f.kind === 'list').map(f => '<datalist id="pd-dl-' + esc(f.name) + '">' +
      (f.values || []).map(v => '<option value="' + esc(v) + '"></option>').join('') + '</datalist>').join('');
  }

  function buildApply() {
    const out = [];
    const ucol = colIndex('username'), dcol = colIndex('display_name'), ecol = colIndex('email');
    (imp.review.rows || []).forEach((rr, i) => {
      if (rr.status === 'same' || !rowTicked(i, rr)) return;
      if (rr.status === 'missing') { out.push({ user: rr.user, remove: true }); return; }
      const row = imp.rows[i];
      const user = String(row[ucol] || '').trim();
      const u = userByName(user);
      const r = { user };
      const dn = dcol >= 0 ? String(row[dcol] || '').trim() : '';
      const em = ecol >= 0 ? String(row[ecol] || '').trim() : '';
      const attrs = {};
      for (const [name, cell] of Object.entries(rr.cells || {})) {
        if (rr.status === 'new') { if ((cell.file || []).length) attrs[name] = cell.file; }
        else if (!sameList(cell.current || [], cell.file || [])) attrs[name] = cell.file || [];
      }
      if (rr.status === 'new') {
        r.create = true;
        r.display_name = dn;
        r.email = em;
      } else {
        if (dn && (!u || dn !== u.display_name)) r.display_name = dn;
        if (em && (!u || em !== u.email)) r.email = em;
      }
      if (Object.keys(attrs).length) r.attrs = attrs;
      out.push(r);
    });
    return out;
  }
  async function importApply() {
    const st = importStats();
    if (st.problems.length || imp.pending) return;
    const rows = buildApply();
    const removing = rows.filter(r => r.remove).map(r => r.user);
    if (removing.length && !confirm('Apply also REMOVES ' + plural(removing.length, 'person', 'people') + ' (' + removing.slice(0, 10).join(', ') + (removing.length > 10 ? ', …' : '') +
      ') from LLDAP and Keycloak. This cannot be undone. Continue?')) return;
    let res;
    try {
      res = await api('POST', '/api/directory/import/apply', { rows });
    } catch (err) {
      toast('Apply: ' + errText(err), 'error');
      return;
    }
    imp.results = res.rows || [];
    renderImport();
    const ok = imp.results.filter(r => r.ok).length;
    toast(ok + ' of ' + imp.results.length + ' rows applied', ok === imp.results.length ? 'success' : 'error');
    try { dir = await api('GET', '/api/directory'); } catch (_) { /* shown on Done */ }
  }
  // Invite links are shown once here and dropped with the results.
  function importResultsHtml() {
    let h = '<div class="pd-imp-head"><h3 class="pd-h3">Import applied: ' + esc(imp.file) + '</h3><p class="pd-muted">Rows were applied one at a time. Copy the setup links now: they won\'t be shown again.</p></div>';
    h += '<table class="pd-table"><thead><tr><th scope="col">Person</th><th scope="col">Result</th><th scope="col">Setup link</th></tr></thead><tbody>';
    imp.results.forEach((r, i) => {
      h += '<tr><td class="pd-mono">' + esc(r.user) + '</td><td>' + (r.ok ? '<span class="pd-pill ok">done</span>' : '<span class="pd-pill bad">failed</span>') +
        (r.error ? '<div class="pd-muted">' + esc(r.error) + '</div>' : '') + '</td><td>' +
        (r.invite ? '<span class="pd-inline"><label class="pd-sr" for="pd-inv-' + i + '">Invite link for ' + esc(r.user) + '</label><input type="text" readonly id="pd-inv-' + i + '" value="' + esc(r.invite.url) + '">' +
          '<button type="button" class="pd-btn secondary xs" data-act="copy-input" data-input="pd-inv-' + i + '">Copy</button></span><div class="pd-muted pd-small">expires ' + esc(fmtTime(r.invite.expires_at)) + '</div>' : '') + '</td></tr>';
    });
    h += '</tbody></table><div class="pd-actions"><button type="button" class="pd-btn primary sm" data-act="imp-done">Done</button></div>';
    return h;
  }
  // CSV export: every cell quoted; cells a spreadsheet would run as a
  // formula (=, +, -, @, tab, CR) get a leading '.
  function csvCell(v) {
    let s = String(v == null ? '' : v);
    if (/^[=+\-@\t\r]/.test(s)) s = '\'' + s;
    return '"' + s.replace(/"/g, '""') + '"';
  }
  function importDownload() {
    const lines = [imp.header].concat(imp.rows).map(r => imp.header.map((_, j) => csvCell(r[j])).join(','));
    const blob = new Blob(['\ufeff' + lines.join('\r\n') + '\r\n'], { type: 'text/csv;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = (imp.file || 'people.csv').replace(/(\.csv)?$/i, '-reviewed.csv');
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 0);
  }

  // ── events ──────────────────────────────────────────────
  async function onClick(e) {
    const tabBtn = e.target.closest('[data-pdtab]');
    if (tabBtn && root.contains(tabBtn)) { userSelectTab(tabBtn.dataset.pdtab, false); return; }
    const b = e.target.closest('[data-act]');
    if (!b) {
      // A click anywhere on a person's row opens them.
      const tr = e.target.closest('tr.pd-row');
      if (!tr || e.target.closest('a, button, input, select, textarea, label')) return;
      if (tr.classList.contains('pd-grow')) location.hash = groupHash(tr.dataset.group); // a group's row opens its page
      else openPerson(tr.dataset.user);
      return;
    }
    const a = b.dataset.act, user = b.dataset.user || '', group = b.dataset.group || '';
    const gpath = '/api/directory/groups/' + enc(group);
    switch (a) {
      case 'dialog-close': return closeDialog();
      case 'copy-secret': return copyText(root.querySelector('.pd-secret input').value);
      case 'hide-secret': return hideSecret();
      case 'copy-input': { const el = document.getElementById(b.dataset.input); if (el) copyText(el.value); return; }
      case 'open-user': return openPerson(user);
      case 'people-list': return userSelectTab('people', true);
      case 'edit-details': return openDetails(user);
      case 'add-to-group': return openAddToGroup(user);
      case 'add-to-group-go': {
        const el = dialogBody().querySelector('#pa-group');
        const v = el ? el.value.trim() : '';
        if (!v) return;
        const g = addToGroupCandidates(userByName(user)).find(x => lc(x.name) === lc(v));
        if (!g) { toast(v + ' isn\'t a group ' + user + ' can be added to', 'error'); return; }
        closeDialog();
        return openGroup(g.name, { preselect: [user] });
      }
      case 'save-user': return saveUser(user);
      case 'invite-open': return openInvite(null);
      case 'invite-create': return createUser();
      case 'invite': case 'require-passkey': case 'clear-actions': case 'reset-passkeys': case 'password': case 'delete-user':
        return userAction(a, user);
      case 'remove-stale':
        if (!typed('Remove the stale Keycloak copy of ' + user + ' (LLDAP no longer has this user). This only deletes it from Keycloak.', user)) return;
        return act(() => api('DELETE', '/api/directory/keycloak-stale/' + enc(user), { confirm: user }), 'Removed the Keycloak copy of ' + user);
      case 'gp-delete': {
        const g = groupByName(group);
        if (!g) return;
        const u = extras.group === group ? extras.uses : null;
        if (!typed(deleteWhat(g, u) + ' This cannot be undone.', group)) return;
        const res = await act(() => api('DELETE', gpath, { confirm: group }), 'Deleted ' + group);
        if (res && groupPage === group) { groupPage = null; setHash('#groups', false); renderGroups(); }
        return;
      }
      case 'gp-remove': {
        const g = groupByName(group);
        const q = g && g.rule
          ? 'Remove ' + user + '\'s added-by-hand entry from ' + group + '? ' + user + ' stays only while they match the rule.'
          : 'Remove ' + user + ' from ' + group + '?';
        if (!confirm(q)) return;
        return groupAct(group, () => api('DELETE', gpath + '/members/' + enc(user), {}), g && g.rule ? user + '\'s entry removed' : user + ' removed from ' + group);
      }
      case 'gp-letin':
        if (!confirm('Let ' + user + ' back into ' + group + '? The kept-out entry goes and the rule decides again.')) return;
        return groupAct(group, () => api('DELETE', gpath + '/exceptions/' + enc(user), {}), user + ' is no longer kept out');
      case 'gp-keepout': return openKeepOut(group, user);
      case 'keepout-save': return keepOutSave(group, user);
      case 'gp-end': return openEnd(group, user);
      case 'end-save': return endSave(group, user, false);
      case 'end-clear': return endSave(group, user, true);
      case 'pick-add': return pickAdd();
      case 'pick-remove': pick.users = pick.users.filter(x => x !== user); redrawPicks(); { const el = root.querySelector('#pd-gp-pick'); if (el) el.focus(); } return;
      case 'pick-submit': return pickSubmit(group);
      case 'gp-hist-reload': return refreshExtras();
      case 'goto-setup': return userSelectTab('setup', true);
      case 'rule-open': return openRuleEditor(group);
      case 'rule-save': return saveRule(group);
      case 'convert-open': return openConvert(group);
      case 'convert-review': return convertReview('');
      case 'convert-apply': return convertApply();
      case 'make-manual':
        if (!confirm('Make ' + group + ' manual? Its current members stay as they are; the rule and its exceptions are dropped and nobody is added or removed automatically any more.')) return;
        return groupAct(group, () => api('PUT', gpath + '/rule', { manual: true }), group + ' is now manual');
      case 'field-save': return saveField(b.dataset.field);
      case 'field-delete': {
        const name = b.dataset.field;
        if (!typed('Delete the field ' + name + ' and its values from everyone. Refused while a rule uses it.', name)) return;
        return act(() => api('DELETE', '/api/directory/fields/' + enc(name), { confirm: name }), 'Field ' + name + ' deleted');
      }
      case 'perm-save': {
        const perm = b.dataset.perm;
        const sel = document.getElementById('pd-perm-' + perm);
        return act(() => api('PUT', '/api/directory/permissions/' + enc(perm), { group: sel.value }), 'Permission saved');
      }
      case 'import-pick': { const fi = root.querySelector('.pd-import-file'); fi.value = ''; fi.click(); return; }
      case 'imp-keep': {
        const i = +b.dataset.r, j = +b.dataset.c;
        const rr = imp.review.rows[i];
        const u = userByName(String(imp.rows[i][colIndex('username')] || '').trim());
        const cur = currentOf(rr, imp.header[j], u) || [];
        imp.rows[i][j] = cur.join('|');
        renderImport();
        importChanged();
        return;
      }
      case 'imp-add': {
        imp.rows.push(imp.header.map(() => ''));
        imp.orig.push(null);
        imp.show.new = true;
        importChanged();
        // Placeholder review row until the server answers.
        imp.review.rows.splice(imp.rows.length - 1, 0, { user: '(empty)', status: 'new', cells: {}, problems: ['username is required'] });
        renderImport();
        const el = root.querySelector('.pd-import [data-r="' + (imp.rows.length - 1) + '"][data-c="' + colIndex('username') + '"]');
        if (el) el.focus();
        return;
      }
      case 'imp-download': return importDownload();
      case 'imp-apply': return importApply();
      case 'imp-cancel':
        if (!imp.results && !confirm('Discard this import review? Nothing was changed.')) return;
        imp = null; reReview.cancel(); renderPeople(); return;
      case 'imp-done': imp = null; reReview.cancel(); return load();
    }
  }

  function onInput(e) {
    const t = e.target;
    if (t.id === 'pd-search') { search = t.value; renderPeopleTable(); return; }
    if (t.id === 'pd-gsearch') { gsearch = t.value; renderGroupTable(); return; }
    const on = t.dataset && t.dataset.on;
    if (on === 'pick-reason') { pick.reason = t.value; return; }
    if (on === 'pick-until') { pick.until = t.value; return; }
    if (on === 'pick-input') {
      // A person chosen from the list joins the picks at once.
      const g = groupByName(pick.group);
      if (g && e.inputType !== 'insertText' && e.inputType !== 'deleteContentBackward' && pickCandidates(g).some(u => u.username === t.value.trim())) pickAdd();
      return;
    }
    if (!on || !imp) return;
    if (on === 'imp-cell') {
      imp.rows[+t.dataset.r][+t.dataset.c] = t.value;
      importChanged();
    } else if (on === 'imp-q') {
      imp.q = t.value;
      renderImport(true);
    }
  }
  function onChange(e) {
    const t = e.target;
    if (t.classList.contains('pd-import-file')) { importUpload(t.files && t.files[0]); return; }
    if (t.name === 'kind' && t.form && t.form.dataset.form === 'new-field') { syncNewFieldForm(); return; }
    const on = t.dataset && t.dataset.on;
    if (on === 'inv-group') { syncInviteRules(); return; }
    if (on === 'org-field') { orgField = t.value; renderOrg(); return; }
    if (!imp) return;
    if (on === 'imp-show') { imp.show[t.value] = t.checked; renderImport(); }
    else if (on === 'imp-tick') {
      const k = t.dataset.key;
      if (k.startsWith('m:')) imp.tickMissing[k.slice(2)] = t.checked; else imp.tick[+k] = t.checked;
      renderImport();
    }
  }
  async function onSubmit(e) {
    const f = e.target;
    const kind = f.dataset && f.dataset.form;
    if (!kind) return;
    e.preventDefault();
    if (kind === 'new-group') {
      const name = f.querySelector('input').value.trim();
      if (!name) return;
      const res = await act(() => api('POST', '/api/directory/groups', { name }), 'Group ' + name + ' created');
      if (res) location.hash = groupHash(name);
    } else if (kind === 'new-field') {
      await createField(f);
    }
  }
  function onKeydown(e) {
    // Arrow keys move between the tabs (WAI-ARIA tabs pattern).
    const t = e.target;
    if (e.key === 'Enter' && t.id === 'pd-gp-pick') { e.preventDefault(); pickAdd(); return; }
    if (e.key === 'Enter' && t.id === 'pa-group') { e.preventDefault(); const b = dialogBody().querySelector('[data-act="add-to-group-go"]'); if (b) b.click(); return; }
    if (!t.dataset || !t.dataset.pdtab || (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft')) return;
    const tabs = Array.from(root.querySelectorAll('[data-pdtab]')).filter(x => !x.hidden);
    const i = tabs.indexOf(t);
    const n = tabs[(i + (e.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length];
    userSelectTab(n.dataset.pdtab, true);
    e.preventDefault();
  }

  const SHELL =
    '<div class="pd">' +
    '<div class="pd-off" hidden></div>' +
    '<div class="pd-main" hidden>' +
    '<div class="pd-warnings"></div>' +
    '<div class="pd-secret" hidden role="region" aria-label="One-time secret"><div class="pd-secret-title"></div><div class="pd-inline">' +
    '<label class="pd-sr" for="pd-secret-value">Secret</label><input type="text" id="pd-secret-value" readonly>' +
    '<button type="button" class="pd-btn primary sm" data-act="copy-secret">Copy</button><button type="button" class="pd-btn secondary sm" data-act="hide-secret">Done</button></div>' +
    '<div class="pd-secret-meta"></div></div>' +
    '<div class="pd-tabs" role="tablist" aria-label="Users and groups">' +
    '<button type="button" role="tab" class="pd-tab" data-pdtab="people" id="pd-tab-people" aria-controls="pd-panel-people">People</button>' +
    '<button type="button" role="tab" class="pd-tab" data-pdtab="groups" id="pd-tab-groups" aria-controls="pd-panel-groups">Groups</button>' +
    '<button type="button" role="tab" class="pd-tab" data-pdtab="org" id="pd-tab-org" aria-controls="pd-panel-org">Org chart</button>' +
    '<button type="button" role="tab" class="pd-tab" data-pdtab="setup" id="pd-tab-setup" aria-controls="pd-panel-setup" hidden>Setup ⚙</button></div>' +
    '<section class="pd-panel" data-panel="people" id="pd-panel-people" role="tabpanel" aria-labelledby="pd-tab-people">' +
    '<div class="pd-people-main"><div class="pd-toolbar"><label class="pd-sr" for="pd-search">Search people</label>' +
    '<input type="search" id="pd-search" placeholder="search people…" autocomplete="off"><span class="pd-people-count pd-muted"></span><span class="pd-spacer"></span>' +
    '<span class="pd-people-actions"></span><input type="file" class="pd-import-file" accept=".csv,text/csv" hidden aria-label="CSV file to import"></div>' +
    '<div class="pd-stale"></div><div class="pd-scroll pd-people-table"></div>' +
    '<p class="pd-legend pd-muted">⚡ = matches the rule · ✱ = added by hand · ⏳ = membership ends · click a person to open their page</p></div>' +
    '<div class="pd-import" hidden></div><div class="pd-imp-dls"></div><div class="pd-person-page" hidden></div></section>' +
    '<section class="pd-panel pd-groups" data-panel="groups" id="pd-panel-groups" role="tabpanel" aria-labelledby="pd-tab-groups" hidden></section>' +
    '<section class="pd-panel pd-org" data-panel="org" id="pd-panel-org" role="tabpanel" aria-labelledby="pd-tab-org" hidden></section>' +
    '<section class="pd-panel pd-setup" data-panel="setup" id="pd-panel-setup" role="tabpanel" aria-labelledby="pd-tab-setup" hidden></section>' +
    '</div>' +
    '<dialog class="pd-dialog" aria-labelledby="pd-dialog-title"><div class="pd-dialog-headbar"><h2 class="pd-dialog-title" id="pd-dialog-title"></h2>' +
    '<button type="button" class="pd-btn ghost sm" data-act="dialog-close" aria-label="Close">✕</button></div><div class="pd-dialog-body"></div></dialog>' +
    '<div class="pd-toast" role="status" aria-live="polite"></div>' +
    '</div>';

  // mount renders the shell into el once; show() (re)loads the data.
  // opts: domain (the main domain: links into the Hub), onUser(name, admin),
  // extraTabs [{id, label, render(panel)}] (people.html: My apps).
  function mount(el, opts) {
    if (root) return;
    root = el;
    options = opts || {};
    el.innerHTML = SHELL;
    // Extra tabs ({id, label, render(panel)}): a button before Setup and a
    // panel after Org chart; render runs each time the tab is selected.
    extraTabs = (options.extraTabs || []).filter(t => t && typeof t.render === 'function' && typeof t.label === 'string' &&
      /^[a-z][a-z0-9-]{0,30}$/.test(t.id || '') && !BUILTIN_TABS.includes(t.id));
    for (const t of extraTabs) {
      root.querySelector('[data-pdtab="setup"]').insertAdjacentHTML('beforebegin',
        '<button type="button" role="tab" class="pd-tab" data-pdtab="' + esc(t.id) + '" id="pd-tab-' + esc(t.id) + '" aria-controls="pd-panel-' + esc(t.id) + '">' + esc(t.label) + '</button>');
      root.querySelector('.pd-panel[data-panel="setup"]').insertAdjacentHTML('beforebegin',
        '<section class="pd-panel" data-panel="' + esc(t.id) + '" id="pd-panel-' + esc(t.id) + '" role="tabpanel" aria-labelledby="pd-tab-' + esc(t.id) + '" hidden></section>');
    }
    const old = legacyUser(location.hash);
    if (old) { setHash(personHash(old.name), false); pendingOpen = old; }
    const r = parseRoute(location.hash);
    if (r && r.person) { tab = 'people'; personPage = r.person; }
    else if (r) { tab = 'groups'; groupPage = r.group; }
    else {
      const h = location.hash.slice(1);
      if (BUILTIN_TABS.includes(h) || extraTabs.some(t => t.id === h)) tab = h;
    }
    window.addEventListener('hashchange', onHash);
    el.addEventListener('click', onClick);
    el.addEventListener('input', onInput);
    el.addEventListener('change', onChange);
    el.addEventListener('submit', onSubmit);
    el.addEventListener('keydown', onKeydown);
    PortcullisPicker.bind(el, resolvePick);
    root.querySelector('.pd-dialog').addEventListener('close', () => {
      // The close event is queued: a dialog opened again meanwhile stays.
      if (root.querySelector('.pd-dialog').open) return;
      if (dialogClose) { const f = dialogClose; dialogClose = null; f(); }
      const body = dialogBody();
      if (body.editor) body.editor.preview.cancel();
      body.innerHTML = '';
      body.editor = null;
    });
  }
  // resolvePick: the picker of a field on this page (PortcullisPicker):
  // only the people and groups the overview shows the caller.
  function resolvePick(t) {
    if (t.id === 'pd-gp-pick') {
      return { kind: 'person', source: () => { const g = groupByName(pick.group); return g ? pickCandidates(g) : []; }, exclude: () => pick.users };
    }
    if (t.id === 'pa-group') return { kind: 'group', source: () => addToGroupItems(t.dataset.user) };
    if (t.dataset.pick === 'person') return { kind: 'person', source: users };
    if (t.dataset.pick === 'group') return { kind: 'group', source: groups };
    return null;
  }
  let loading = null;
  function show(el, opts) {
    mount(el, opts);
    loading = load();
    if (pendingOpen) { const p = pendingOpen; pendingOpen = null; openAt(p.name, p.action); }
    return loading;
  }

  // openAt opens a person (deep link #users/<name>[?password|?invite],
  // the Portcullis MCP's set_password / send_invite forms): after the
  // current load, the person's page (#people/<name>), then the action's
  // own prompt — the secret is typed (or the link shown) here, never
  // passed through the AI. With URLSearchParams (#users?create&…): the
  // new-person form.
  async function openAt(name, action) {
    if (loading) await loading;
    if (action instanceof URLSearchParams) {
      // Only for someone who may invite (the server refuses anyway).
      if (can('invite')) openInvite(action);
      return;
    }
    name = canonPerson(name);
    if (!userByName(name)) return;
    setHash(personHash(name), false);
    applyRoute({ person: name });
    if (action === 'password' || action === 'invite') userAction(action, name);
  }

  // An access-log decision (contract §15.8) as a pill: the one rendering
  // the Hub page's AI tab and this audit view share (myai.js, the people
  // card, has its own). cls: the pill class of the page ('pill' on
  // index.html, 'pd-pill' here).
  function aiDecision(d, cls) {
    d = String(d || '');
    cls = cls || 'pd-pill';
    if (d === 'allow') return '<span class="' + cls + ' ok">✓ allowed</span>';
    if (d === 'rate_limited') return '<span class="' + cls + ' warn">rate limited</span>';
    if (d.startsWith('confirm:')) return '<span class="' + cls + ' info">⏸ waiting for confirmation</span>';
    if (d.startsWith('deny:')) return '<span class="' + cls + ' bad">✗ denied: ' + esc(d.slice(5)) + '</span>';
    return '<span class="' + cls + '">' + esc(d) + '</span>';
  }

  // Fields outside the directory UI (the Hub page: the AI tab's Revoke
  // for, settings.js's users lists) name the kind with data-pick; the
  // overview is read once when one is first used.
  PortcullisPicker.bind(document, t => {
    const k = t.dataset && t.dataset.pick;
    if (k !== 'person' && k !== 'group') return null;
    return { kind: k, source: () => PortcullisPicker.overview().then(d => (k === 'person' ? d.users : d.groups) || []) };
  });

  window.PortcullisDirectory = { show, openAt, openGroup, csvCell, renderAudit };
  window.PortcullisPicker = PortcullisPicker;
  window.PortcullisNav = PortcullisNav;
  window.PortcullisAI = { decision: aiDecision };
})();
