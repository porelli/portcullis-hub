// Portcullis Hub: My apps (people.<domain> only).
//
// The signed-in person's own per-person values for the apps they can
// use (GET /api/me/apps): one card per app with its link, each value,
// why they get it ("from office_milan", "everyone with access") and when
// a change reaches the app. Values the person enters themselves (e.g.
// their account id in another service, spec call 32) get an input with
// Save and Clear (PUT / DELETE /api/me/apps/{app}/values/{key}) and a
// status line. A person_secret option gets a credential card (plan 3
// Task 14, contract §5.1 / §13.16): create / regenerate the person's
// file-share password after a fresh passkey sign-in in a popup (PKCE,
// state and nonce in sessionStorage until the popup answers; the
// password itself is never stored: it lives in one dialog, shown once,
// and is dropped when the dialog closes or the cards reload), and revoke
// it (DELETE, no fresh sign-in). Only the caller's own values are ever
// shown. Registered
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

  // ── file-share passwords (person_secret, contract §13.16) ─────────

  // fmtDay is a date without the time ("5 Nov 2026").
  function fmtDay(s) {
    const d = new Date(s);
    if (!s || isNaN(d)) return '';
    return d.toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' });
  }

  // credHtml is the card row of credential c of app.
  function credHtml(app, c) {
    const name = app.name || app.id;
    let line, btns = '';
    switch (c.status) {
      case 'active':
        line = 'Password active since ' + fmtDay(c.since);
        btns = '<button type="button" class="pd-btn secondary sm" data-ma-act="cred-regen">Regenerate</button>' +
          '<button type="button" class="pd-btn danger sm" data-ma-act="cred-revoke">Revoke</button>';
        break;
      case 'voided':
        line = 'Your password was reset by a restore on ' + fmtDay(c.since) + '; create a new one.';
        btns = '<button type="button" class="pd-btn primary sm" data-ma-act="cred-create">Create password</button>';
        break;
      case 'unavailable':
        line = 'File sharing isn\'t available for your username: the username ' + (c.reason || 'can\'t be used here') + '. Ask an administrator.';
        break;
      default:
        line = 'No password yet';
        btns = '<button type="button" class="pd-btn primary sm" data-ma-act="cred-create">Create password</button>';
    }
    let h = '<div class="ma-value ma-cred" data-ma-cred data-ma-app="' + esc(app.id) + '" data-ma-key="' + esc(c.key) + '" data-ma-name="' + esc(name) + '" data-ma-status-kind="' + esc(c.status) + '">' +
      '<dt>' + esc(c.label || c.key) + '</dt><dd>' +
      '<div class="ma-entry-row"><span class="ma-cred-line' + (c.status === 'unavailable' || c.status === 'voided' ? ' ma-cred-warn' : '') + '">' + esc(line) + '</span>' + btns + '</div>' +
      '<div data-ma-cred-panel></div>' +
      '<div class="ma-status pd-muted" data-ma-cred-status role="status"></div>';
    if ((c.info || []).length) {
      h += '<dl class="ma-info">' + c.info.map(l => '<div><dt>' + esc(l.label) + '</dt><dd><code>' + esc(l.value) + '</code></dd></div>').join('') + '</dl>';
    }
    return h + '</dd></div>';
  }

  // The fresh-auth flow in progress (one at a time) and the shown-once
  // password dialog.
  const FA_KEY = 'portcullis-fresh-auth';
  let flow = null; // {el, row, instance, key, name, popup, timer}
  let shown = null; // {close()}

  function b64url(bytes) {
    let s = '';
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function randomB64(n) {
    const a = new Uint8Array(n);
    crypto.getRandomValues(a);
    return b64url(a);
  }
  async function s256(v) {
    const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(v));
    return b64url(new Uint8Array(d));
  }

  function credStatus(row, text, warn, spin) {
    const s = row && row.querySelector('[data-ma-cred-status]');
    if (!s) return;
    s.innerHTML = (spin ? '<span class="ma-spin" aria-hidden="true"></span> ' : '') + esc(text);
    s.classList.toggle('pd-warn', !!warn);
    s.classList.toggle('pd-muted', !warn);
  }
  function credBusy(row, on) {
    row.querySelectorAll('button').forEach(b => { b.disabled = on; });
  }

  // endFlow forgets the flow in progress (and its sessionStorage entry).
  function endFlow() {
    if (!flow) return;
    clearInterval(flow.timer);
    flow = null;
    sessionStorage.removeItem(FA_KEY);
  }

  // startFreshAuth opens the fresh sign-in popup for row's credential.
  // Called from the click itself: the popup is opened before any await,
  // so pop-up blockers allow it.
  async function startFreshAuth(el, row) {
    const fa = el.maFreshAuth;
    if (!fa || !/^https?:\/\//i.test(fa.authorize_url || '')) {
      credStatus(row, 'A fresh sign-in isn\'t available right now. Try again later.', true);
      return;
    }
    if (flow && flow.popup && !flow.popup.closed) flow.popup.close();
    endFlow();
    const popup = window.open('', 'portcullis-fresh-auth', 'popup,width=520,height=720');
    if (!popup) {
      credStatus(row, 'Allow pop-ups for this page: the fresh sign-in opens in a small window.', true);
      return;
    }
    const verifier = randomB64(64); // 86 characters (RFC 7636: 43–128)
    const state = randomB64(32);
    const nonce = randomB64(32);
    const pending = { state, nonce, verifier, instance: row.dataset.maApp, key: row.dataset.maKey };
    sessionStorage.setItem(FA_KEY, JSON.stringify(pending));
    flow = { el, row, instance: pending.instance, key: pending.key, name: row.dataset.maName, popup, timer: 0 };
    const mine = flow;
    credBusy(row, true);
    credStatus(row, 'Touch your passkey in the sign-in window to continue…', false, true);
    let challenge;
    try {
      challenge = await s256(verifier);
    } catch (err) {
      popup.close();
      endFlow();
      credBusy(row, false);
      credStatus(row, 'This browser can\'t start a secure sign-in: ' + err.message, true);
      return;
    }
    if (flow !== mine) return;
    const u = new URL(fa.authorize_url);
    for (const [k, v] of [
      ['response_type', 'code'],
      ['client_id', fa.client_id],
      ['redirect_uri', fa.redirect_uri],
      ['scope', 'openid'],
      ['prompt', 'login'],
      ['max_age', '0'],
      ['acr_values', 'hwk'],
      ['state', state],
      ['nonce', nonce],
      ['code_challenge', challenge],
      ['code_challenge_method', 'S256'],
    ]) u.searchParams.set(k, v);
    popup.location.href = u.toString();
    // A popup closed without an answer cancels the flow (after a grace:
    // the callback posts, then closes).
    let closedAt = 0;
    mine.timer = setInterval(() => {
      if (flow !== mine) { clearInterval(mine.timer); return; }
      if (!popup.closed) return;
      if (!closedAt) { closedAt = Date.now(); return; }
      if (Date.now() - closedAt < 1000) return;
      endFlow();
      credBusy(row, false);
      credStatus(row, 'The sign-in window was closed: nothing changed.', true);
    }, 400);
  }

  // The popup callback (people.html) posts {type, code, state, error}.
  // Accepted only from this origin, from the popup this page opened, of
  // type portcullis-fresh-auth and with the stored state; the stored
  // entry is then deleted and the proof posted.
  window.addEventListener('message', ev => {
    if (ev.origin !== location.origin) return;
    const d = ev.data;
    if (!d || typeof d !== 'object' || d.type !== 'portcullis-fresh-auth' || typeof d.state !== 'string') return;
    let pending = null;
    try { pending = JSON.parse(sessionStorage.getItem(FA_KEY) || 'null'); } catch (_) { pending = null; }
    if (!pending || !pending.state || d.state !== pending.state) return;
    if (!flow || ev.source !== flow.popup || flow.instance !== pending.instance || flow.key !== pending.key) return;
    const f = flow;
    sessionStorage.removeItem(FA_KEY);
    clearInterval(f.timer);
    flow = null;
    if (d.error || !d.code) {
      credBusy(f.row, false);
      credStatus(f.row, 'The sign-in didn\'t complete' + (d.error ? ' (' + String(d.error).slice(0, 100) + ')' : '') + ': nothing changed.', true);
      return;
    }
    submitProof(f, pending, d);
  });

  // submitProof creates or regenerates the password with the proof, then
  // reloads the cards and shows the password once.
  async function submitProof(f, pending, d) {
    credStatus(f.row, 'Creating your password…', false, true);
    const url = '/api/me/apps/' + encodeURIComponent(f.instance) + '/credentials/' + encodeURIComponent(f.key);
    let res, text;
    try {
      res = await fetch(url, {
        method: 'POST', credentials: 'same-origin', cache: 'no-store', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: d.code, code_verifier: pending.verifier, nonce: pending.nonce })
      });
      text = await res.text();
    } catch (err) {
      res = null;
      text = err.message;
    }
    if (!res || !res.ok) {
      credBusy(f.row, false);
      credStatus(f.row, (text || '').trim() || ('HTTP ' + (res ? res.status : '')), true);
      return;
    }
    let pw = '';
    try { pw = JSON.parse(text).password || ''; } catch (_) { pw = ''; }
    text = null;
    await load(f.el);
    if (pw) showPassword(f.name, pw);
    pw = null;
  }

  // closeShown closes the shown-once dialog (its node and the string go).
  function closeShown() {
    if (shown) shown.close();
  }

  // showPassword shows pw once: a modal dialog with Copy and "I've saved
  // it". Closing it (either button, Escape, a reload of the cards,
  // leaving the page) removes the node and drops the string.
  function showPassword(name, pw) {
    closeShown();
    let secret = pw;
    const dlg = document.createElement('dialog');
    dlg.className = 'pd-dialog ma-pw-dialog';
    dlg.setAttribute('aria-label', 'Your file-share password for ' + name);
    dlg.innerHTML = '<div class="pd-dialog-headbar"><h3 class="pd-dialog-title">Your file-share password for ' + esc(name) + '</h3></div>' +
      '<div class="pd-dialog-body"><div class="ma-pw-row"><code class="ma-pw" data-ma-pw></code>' +
      '<button type="button" class="pd-btn secondary sm" data-ma-pw-act="copy">Copy</button></div>' +
      '<p class="ma-pw-note"><strong>This is the only time it is shown: you won\'t see it again.</strong> Save it in your Mac\'s Keychain (or your password manager) when ' +
      esc(name) + ' asks. It works only for ' + esc(name) + ' on this server.</p>' +
      '<div class="ma-status pd-muted" data-ma-pw-status role="status"></div>' +
      '<div class="ma-pw-actions"><button type="button" class="pd-btn primary sm" data-ma-pw-act="done">I\'ve saved it</button></div></div>';
    dlg.querySelector('[data-ma-pw]').textContent = secret;
    const clear = () => {
      secret = null;
      const c = dlg.querySelector('[data-ma-pw]');
      if (c) c.textContent = '';
      dlg.remove();
      if (shown === me) shown = null;
    };
    const me = { close: () => { if (dlg.open) dlg.close(); clear(); } };
    dlg.addEventListener('click', e => {
      const b = e.target.closest('[data-ma-pw-act]');
      if (!b) return;
      if (b.dataset.maPwAct === 'done') { me.close(); return; }
      const st = dlg.querySelector('[data-ma-pw-status]');
      if (!secret || !navigator.clipboard) { st.textContent = 'Copy isn\'t available here: select the password and copy it.'; return; }
      navigator.clipboard.writeText(secret).then(
        () => { st.textContent = 'Copied.'; },
        () => { st.textContent = 'Copy failed: select the password and copy it.'; });
    });
    dlg.addEventListener('close', clear);
    shown = me;
    document.body.appendChild(dlg);
    dlg.showModal();
  }
  window.addEventListener('pagehide', closeShown);

  // credConfirm opens an inline confirm panel on row (regenerate: the
  // spec's warning; revoke: what it does).
  function credConfirm(row, act) {
    const p = row.querySelector('[data-ma-cred-panel]');
    const name = row.dataset.maName;
    p.innerHTML = act === 'regen'
      ? '<div class="pd-warn ma-confirm"><p>Your Mac will ask for the new password; running backups stop. The old password stops working at once.</p>' +
        '<button type="button" class="pd-btn primary sm" data-ma-act="cred-regen-go">Regenerate</button> <button type="button" class="pd-btn secondary sm" data-ma-act="cred-cancel">Cancel</button></div>'
      : '<div class="pd-warn ma-confirm"><p>Revoke your file-share password for ' + esc(name) + '? Everything using it loses access at once; you can create a new one later.</p>' +
        '<button type="button" class="pd-btn danger sm" data-ma-act="cred-revoke-go">Revoke</button> <button type="button" class="pd-btn secondary sm" data-ma-act="cred-cancel">Cancel</button></div>';
  }

  // revokeCred revokes row's credential (synchronous on the Hub: the
  // revocation reaches the app before the answer, up to ~30 s).
  async function revokeCred(el, row) {
    row.querySelector('[data-ma-cred-panel]').innerHTML = '';
    credBusy(row, true);
    credStatus(row, 'Revoking… this can take up to 30 seconds.', false, true);
    const url = '/api/me/apps/' + encodeURIComponent(row.dataset.maApp) + '/credentials/' + encodeURIComponent(row.dataset.maKey);
    let res, text;
    try {
      res = await fetch(url, { method: 'DELETE', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' } });
      text = await res.text();
    } catch (err) {
      res = null;
      text = err.message;
    }
    if (!res || !res.ok) {
      credBusy(row, false);
      credStatus(row, (text || '').trim() || ('HTTP ' + (res ? res.status : '')), true);
      return;
    }
    await load(el);
  }

  // credAction handles a credential button.
  function credAction(el, row, act) {
    const panel = row.querySelector('[data-ma-cred-panel]');
    switch (act) {
      case 'cred-create': panel.innerHTML = ''; startFreshAuth(el, row); break;
      case 'cred-regen': credConfirm(row, 'regen'); break;
      case 'cred-regen-go': panel.innerHTML = ''; startFreshAuth(el, row); break;
      case 'cred-revoke': credConfirm(row, 'revoke'); break;
      case 'cred-revoke-go': revokeCred(el, row); break;
      case 'cred-cancel': panel.innerHTML = ''; break;
    }
  }

  // Only http(s) links are rendered as links.
  function safeURL(u) { return /^https?:\/\//i.test(u || '') ? u : ''; }

  function card(app) {
    const url = safeURL(app.url);
    const name = esc(app.name || app.id);
    let h = '<article class="pd-card ma-app" data-ma-app="' + esc(app.id) + '"><div class="ma-head">';
    if (app.icon) h += '<span class="ma-icon" aria-hidden="true">' + esc(app.icon) + '</span>';
    h += '<h3 class="ma-name">' + (url ? '<a href="' + esc(url) + '" target="_blank" rel="noopener noreferrer">' + name + '</a>' : name) + '</h3>';
    if (!url) h += '<span class="pd-pill">No web page</span>';
    h += '</div><dl class="ma-values">';
    for (const c of app.credentials || []) h += credHtml(app, c);
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
    // A reload drops the shown-once password and any sign-in in progress.
    closeShown();
    if (flow && flow.el === el) { if (flow.popup && !flow.popup.closed) flow.popup.close(); endFlow(); }
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
    el.maFreshAuth = null;
    try {
      const v = JSON.parse(text);
      apps = v.apps || [];
      el.maFreshAuth = v.fresh_auth || null;
    } catch (_) { /* shown as empty */ }
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
        const cred = b.closest('[data-ma-cred]');
        if (cred && b.dataset.maAct.startsWith('cred-')) { credAction(el, cred, b.dataset.maAct); return; }
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
