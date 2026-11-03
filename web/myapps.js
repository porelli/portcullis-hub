// Portcullis Hub: My apps (people.<domain> only).
//
// The signed-in person's own per-person values for the apps they can
// use (GET /api/me/apps): one card per app with its link, each value,
// why they get it ("from office_milan", "everyone with access") and when
// a change reaches the app. Values the person enters themselves (e.g.
// their account id in another service, spec call 32) get an input with
// Save and Clear (PUT / DELETE /api/me/apps/{app}/values/{key}) and a
// status line. Only the caller's own values are ever shown. Registered
// as an extra tab of PortcullisDirectory by people.html. Vanilla JS, no
// build step.
//
// Rules of this file (as directory.js):
//   - every server string goes through esc() before it reaches innerHTML;
//   - no inline event handlers: data-* attributes and one delegated
//     listener per panel.
(function () {
  'use strict';

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  // When a change of the value reaches the app.
  const APPLIES = {
    live: 'a change applies at once',
    next_request: 'a change applies at your next request',
    next_sign_in: 'a change applies at your next sign-in',
    account_creation: 'set when your account is created in the app (an existing account keeps its value)',
    reload: 'a change applies after the app reloads',
    restart: 'a change applies after the app restarts'
  };

  // When an entered value reaches the app (it goes the membership path:
  // folded within about a minute).
  const ENTRY_APPLIES = {
    live: 'the app picks it up within about a minute',
    reload: 'the app picks it up within about a minute (the app reloads)',
    restart: 'the app picks it up within about a minute (the app restarts)',
    next_sign_in: 'applies at your next sign-in to the app',
    next_request: 'applies to your next requests to the app'
  };

  function fmtDate(s) {
    const d = new Date(s);
    if (!s || isNaN(d)) return '';
    return d.toLocaleString(undefined, { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
  }

  // entryStatus is an entry's status line (text, and warn for a refusal).
  function entryStatus(e) {
    if (e.value === null || e.value === undefined) return 'Not set';
    if (e.set_by_admin) return 'Set by an administrator on ' + fmtDate(e.updated_at);
    const when = ENTRY_APPLIES[e.applies] || '';
    return 'Saved ' + fmtDate(e.updated_at) + (when ? ' · ' + when : '');
  }

  // htmlPattern is a template pattern (^…$, the whole value) as an HTML
  // pattern attribute, which the browser anchors itself: only the outer
  // ^ and $ are removed and the rest is grouped, so an alternation keeps
  // its meaning (^a|b$ → (?:a|b)).
  function htmlPattern(p) {
    let s = String(p);
    if (s.startsWith('^')) s = s.slice(1);
    if (s.endsWith('$') && !s.endsWith('\\$')) s = s.slice(0, -1);
    return '(?:' + s + ')';
  }

  // entryControl is the input for entry e (its constraints as the
  // browser can check them; the Hub checks them again).
  function entryControl(appID, e) {
    const inp = e.input || {};
    const id = 'ma-in-' + appID + '-' + e.key;
    const common = ' id="' + esc(id) + '" data-ma-input data-ma-type="' + esc(inp.type) + '" aria-label="' + esc(e.label || e.key) + '"';
    const v = e.value;
    switch (inp.type) {
      case 'bool':
        return '<label class="ma-check"><input type="checkbox"' + common + (v === true ? ' checked' : '') + '> ' + esc(e.label || e.key) + '</label>';
      case 'enum': {
        let h = '<select class="pd-input"' + common + '><option value="">— choose —</option>';
        for (const c of inp.options || []) h += '<option value="' + esc(c.value) + '"' + (c.value === v ? ' selected' : '') + '>' + esc(c.label || c.value) + '</option>';
        return h + '</select>';
      }
      case 'int': {
        let a = ' type="number" step="1" inputmode="numeric"';
        if (typeof inp.min === 'number') a += ' min="' + esc(inp.min) + '"';
        if (typeof inp.max === 'number') a += ' max="' + esc(inp.max) + '"';
        return '<input class="pd-input"' + a + common + ' value="' + esc(v == null ? '' : v) + '">' + (inp.unit ? ' <span class="pd-muted">' + esc(inp.unit) + '</span>' : '');
      }
    }
    let a = ' type="text" autocomplete="off" spellcheck="false"';
    if (inp.max_len) a += ' maxlength="' + esc(inp.max_len) + '"';
    if (inp.min_len) a += ' minlength="' + esc(inp.min_len) + '"';
    if (inp.pattern) a += ' pattern="' + esc(htmlPattern(inp.pattern)) + '"';
    return '<input class="pd-input ma-text"' + a + common + ' value="' + esc(v == null ? '' : v) + '">';
  }

  function entryHtml(appID, e) {
    const st = entryStatus(e);
    return '<div class="ma-value ma-entry" data-ma-entry data-ma-app="' + esc(appID) + '" data-ma-key="' + esc(e.key) + '">' +
      '<dt><label for="' + esc('ma-in-' + appID + '-' + e.key) + '">' + esc(e.label || e.key) + '</label></dt><dd>' +
      (e.description ? '<div class="ma-desc pd-muted">' + esc(e.description) + '</div>' : '') +
      '<div class="ma-entry-row">' + entryControl(appID, e) +
      '<button type="button" class="pd-btn sm" data-ma-act="save">Save</button>' +
      '<button type="button" class="pd-btn secondary sm" data-ma-act="clear"' + (e.value == null ? ' disabled' : '') + '>Clear</button></div>' +
      '<div class="ma-status pd-muted" data-ma-status role="status">' + esc(st) + '</div>' +
      (e.unique ? '<div class="ma-applies pd-muted">Must be yours: no two people of this app can register the same value.</div>' : '') +
      '</dd></div>';
  }

  // readEntry is the typed value of an entry's input ({value} or {error}).
  function readEntry(row) {
    const x = row.querySelector('[data-ma-input]');
    if (!x) return { error: 'no input' };
    switch (x.dataset.maType) {
      case 'bool': return { value: x.checked };
      case 'int': {
        const s = x.value.trim();
        if (s === '' || !/^-?\d+$/.test(s)) return { error: 'Enter a whole number, or Clear to remove your value.' };
        return { value: Number(s) };
      }
      default:
        if (x.value === '') return { error: 'Enter a value, or Clear to remove it.' };
        return { value: x.value };
    }
  }

  function reasonText(r) {
    r = r || {};
    switch (r.source) {
      case 'group': return r.group ? 'from ' + r.group : 'from one of your groups';
      case 'combined': return r.groups && r.groups.length ? 'from ' + r.groups.join(', ') : 'from your groups';
      case 'default': return 'everyone with access';
      case 'fail-closed': return 'the most restrictive value: your groups\' settings could not be combined safely';
    }
    return '';
  }

  // Only http(s) links are rendered as links.
  function safeURL(u) { return /^https?:\/\//i.test(u || '') ? u : ''; }

  function card(app) {
    const url = safeURL(app.url);
    const name = esc(app.name || app.id);
    let h = '<article class="pd-card ma-app" data-ma-app="' + esc(app.id) + '"><div class="ma-head">';
    if (app.icon) h += '<span class="ma-icon" aria-hidden="true">' + esc(app.icon) + '</span>';
    h += '<h3 class="ma-name">' + (url ? '<a href="' + esc(url) + '" target="_blank" rel="noopener noreferrer">' + name + '</a>' : name) + '</h3></div>';
    h += '<dl class="ma-values">';
    for (const e of app.entries || []) h += entryHtml(app.id, e);
    for (const v of app.values || []) {
      const why = reasonText(v.reason);
      const when = APPLIES[v.applies] || '';
      h += '<div class="ma-value" data-ma-key="' + esc(v.key) + '"><dt>' + esc(v.label || v.key) + '</dt><dd><strong>' + esc(v.value) + '</strong>' +
        (v.reason && v.reason.source === 'fail-closed' ? ' <span class="pd-pill warn">fail-closed</span>' : '') +
        (why ? '<span class="ma-why pd-muted"> · ' + esc(why) + '</span>' : '') +
        (when ? '<div class="ma-applies pd-muted">' + esc(when) + '</div>' : '') + '</dd></div>';
    }
    return h + '</dl></article>';
  }

  // load (re)loads the cards. Overlapping loads (Refresh pressed twice, a
  // save's reload racing a refresh): only the newest one draws (T15 M3).
  async function load(el) {
    const box = el.querySelector('[data-ma-list]');
    const seq = (el.maSeq = (el.maSeq || 0) + 1);
    box.innerHTML = '<p class="pd-muted">Loading…</p>';
    let res, text;
    try {
      res = await fetch('/api/me/apps', { credentials: 'same-origin' });
      text = await res.text();
    } catch (err) {
      if (seq !== el.maSeq) return;
      box.innerHTML = '<p class="pd-warn">Could not load your apps: ' + esc(err.message) + '</p>';
      return;
    }
    if (seq !== el.maSeq) return;
    if (!res.ok) {
      box.innerHTML = '<p class="pd-warn">Could not load your apps: ' + esc(text.trim() || ('HTTP ' + res.status)) + '</p>';
      return;
    }
    let apps = [];
    try { apps = (JSON.parse(text).apps) || []; } catch (_) { /* shown as empty */ }
    // The entries as last answered (a cleared row is redrawn from them).
    el.maEntries = new Map();
    for (const app of apps) for (const e of app.entries || []) el.maEntries.set(app.id + '\u0000' + e.key, e);
    box.innerHTML = apps.length
      ? apps.map(card).join('')
      : '<p class="pd-muted ma-empty">No apps with personal settings.</p>';
  }

  // entryAction saves or clears the entry of row; the row is redrawn
  // from the answer, the status line shows the outcome or the refusal
  // (the Hub's text: the constraint, "already registered … by another
  // person").
  async function entryAction(el, row, act) {
    const app = row.dataset.maApp, key = row.dataset.maKey;
    const status = row.querySelector('[data-ma-status]');
    const setStatus = (text, warn) => { status.textContent = text; status.classList.toggle('pd-warn', !!warn); status.classList.toggle('pd-muted', !warn); };
    let body;
    if (act === 'save') {
      const r = readEntry(row);
      if (r.error) { setStatus(r.error, true); return; }
      body = JSON.stringify({ value: r.value });
    }
    const url = '/api/me/apps/' + encodeURIComponent(app) + '/values/' + encodeURIComponent(key);
    const seq = (row.maSeq = (row.maSeq || 0) + 1);
    row.querySelectorAll('button').forEach(b => { b.disabled = true; });
    setStatus(act === 'save' ? 'Saving…' : 'Clearing…', false);
    let res, text;
    try {
      res = await fetch(url, { method: act === 'save' ? 'PUT' : 'DELETE', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body });
      text = await res.text();
    } catch (err) {
      res = null;
      text = err.message;
    }
    if (seq !== row.maSeq) return;
    if (!res || !res.ok) {
      row.querySelectorAll('button').forEach(b => { b.disabled = false; });
      setStatus((text || '').trim() || ('HTTP ' + (res ? res.status : '')), true);
      return;
    }
    const known = (el.maEntries && el.maEntries.get(app + '\u0000' + key)) || { key, label: key, input: {} };
    let e = null;
    if (act === 'save') { try { e = JSON.parse(text); } catch (_) { e = null; } }
    if (!e) e = Object.assign({}, known, { value: null, display: '', set_by_admin: false, updated_at: null });
    if (el.maEntries) el.maEntries.set(app + '\u0000' + key, e);
    const tmp = document.createElement('div');
    tmp.innerHTML = '<dl>' + entryHtml(app, e) + '</dl>';
    const next = tmp.querySelector('[data-ma-entry]');
    row.replaceWith(next);
    if (act === 'clear') {
      const s = next.querySelector('[data-ma-status]');
      s.textContent = 'Cleared · ' + s.textContent;
    }
  }

  // render (re)draws My apps into el (the tab's panel) and loads them.
  function render(el) {
    if (!el.dataset.maBound) {
      el.dataset.maBound = '1';
      el.innerHTML = '<div class="pd-head"><h2 class="pd-h3">My apps</h2>' +
        '<button type="button" class="pd-btn secondary sm" data-ma-act="reload">Refresh</button></div>' +
        '<p class="pd-muted ma-intro">Your own settings in the apps you can use, and where each comes from. Administrators set most of them; values with an input are yours to enter.</p>' +
        '<div data-ma-list></div>';
      el.addEventListener('click', e => {
        const b = e.target.closest('[data-ma-act]');
        if (!b || !el.contains(b) || b.disabled) return;
        if (b.dataset.maAct === 'reload') { load(el); return; }
        const row = b.closest('[data-ma-entry]');
        if (row && (b.dataset.maAct === 'save' || b.dataset.maAct === 'clear')) entryAction(el, row, b.dataset.maAct);
      });
      el.addEventListener('keydown', e => {
        if (e.key !== 'Enter' || !e.target.matches('[data-ma-input]')) return;
        e.preventDefault();
        const row = e.target.closest('[data-ma-entry]');
        if (row) entryAction(el, row, 'save');
      });
    }
    return load(el);
  }

  window.PortcullisMyApps = { render };
})();
