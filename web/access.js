// Portcullis Hub — the Access tab: SSH access (ssh.js), VPN devices and
// sign-in history. Hub listener only, administrators only.
//
//   window.PortcullisAccess.render(root, section, opts)
//       section: ssh (default), vpn or signins; opts {sub, user}: the SSH
//       section to open (#access/ssh/<sub>), the person whose sign-in
//       history to show (#access/signins?user=<name>).
//
// Routes: GET /api/vpn/devices (every person's devices on every
// provider), DELETE /api/vpn/devices/{id} (a built-in device),
// GET /api/directory/users/{u}/signin/history (one person's history,
// paged with the opaque `next` cursor; there is no server-wide feed).
//
// Rules of this file:
//   - no markup from strings: every node is built with el() and every
//     server value is set as text or an attribute;
//   - the subtab in the hash is replaced, never pushed (#access/<section>);
//   - a username is checked against ^[a-z0-9._-]{1,64}$ before any request.
(function () {
  'use strict';

  const SECTIONS = [['ssh', 'SSH access'], ['vpn', 'VPN devices'], ['signins', 'Sign-in history']];
  const USER_RE = /^[a-z0-9._-]{1,64}$/;
  const HISTORY_PAGE = 20;
  const enc = encodeURIComponent;

  // el(tag, props, ...children): props {class, text, on: {event: fn},
  // value, …}; children: nodes or strings (text nodes).
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
    return put(n, kids);
  }
  function put(n, ...kids) {
    for (const c of kids.flat(Infinity)) {
      if (c == null || c === false) continue;
      n.appendChild(typeof c === 'string' || typeof c === 'number' ? document.createTextNode(String(c)) : c);
    }
    return n;
  }
  function replaceKids(n, ...kids) {
    while (n.firstChild) n.removeChild(n.firstChild);
    return put(n, kids);
  }
  function code(t) { return el('code', { text: t }); }
  function muted(t) { return el('p', { class: 'settings-empty', text: t }); }
  function warn(t) { return el('p', { class: 'public-warn', text: t }); }
  function when(t) {
    if (!t) return '—';
    const d = new Date(t);
    return isNaN(d) || d.getUTCFullYear() < 2000 ? '—' : d.toISOString().replace('T', ' ').replace(/:\d\d\.\d+Z$/, ' UTC');
  }
  function table(head, rows) {
    return el('table', { class: 'inst-table' },
      el('thead', null, el('tr', null, head.map(t => el('th', { text: t })))),
      el('tbody', null, rows));
  }
  function personLink(u) {
    if (!u) return '—';
    return el('a', { href: window.PortcullisPeople.href('#people/' + enc(u)), text: u, title: 'Open ' + u + '’s page' });
  }

  // call: a JSON request; throws Error(text) on a refusal.
  async function call(method, path) {
    const res = await fetch(path, { method, headers: {} });
    if (!res.ok) throw new Error((await res.text()).trim() || res.statusText || ('HTTP ' + res.status));
    return res.status === 204 ? null : res.json();
  }

  // ── VPN devices ────────────────────────────────────────────
  // renderVPN(box): every person's devices; Remove only on a built-in
  // device (managed), a provider app's own devices are managed there.
  async function renderVPN(box) {
    let list;
    try {
      list = await call('GET', '/api/vpn/devices');
    } catch (e) {
      replaceKids(box, warn(e.message));
      return;
    }
    const status = el('p', { class: 'settings-empty', role: 'status', 'aria-live': 'polite' });
    const rows = (list || []).map(d => el('tr', null,
      el('td', null, personLink(d.user)),
      el('td', { text: d.name }),
      el('td', { text: d.provider_label || d.provider }),
      el('td', null, d.address ? code(d.address) : '—'),
      el('td', { class: 'nowrap', text: when(d.last_seen) }),
      el('td', { class: 'nowrap', text: d.expires ? when(d.expires) : 'never' }),
      el('td', null, el('span', { class: 'pill ' + (d.online ? 'ok' : ''), text: d.online ? 'online' : 'offline' })),
      el('td', null, d.managed
        ? el('button', {
          type: 'button', class: 'btn btn-sm btn-danger', 'data-vpn-remove': d.id, text: 'Remove',
          on: { click: () => removeDevice(box, d, status) },
        })
        : el('span', { class: 'settings-empty', text: 'in ' + (d.provider_label || d.provider) }))));
    replaceKids(box,
      muted('Every person’s VPN devices on every provider. Built-in devices can be removed here; a provider app’s devices are managed in that app.'),
      status,
      rows.length ? table(['Person', 'Device', 'Provider', 'Address', 'Last seen', 'Expires', '', ''], rows) : muted('No VPN devices.'));
  }

  async function removeDevice(box, d, status) {
    if (!confirm('Remove ' + d.user + '’s VPN device “' + d.name + '”? It can’t connect any more.')) return;
    try {
      await call('DELETE', '/api/vpn/devices/' + enc(d.id));
    } catch (e) {
      status.textContent = e.message;
      status.className = 'public-warn';
      return;
    }
    await renderVPN(box);
  }

  // ── Sign-in history ────────────────────────────────────────
  // The methods and entries in words (as the person's own Sign-in page).
  const SHORT = {
    password: 'password', totp: 'authenticator code', passkey_synced: 'synced passkey', browser_cert: 'browser certificate',
    passkey_device: 'device-bound passkey', security_key: 'security key', yubikey_cert: 'YubiKey certificate',
  };
  const SOURCES = { keycloak: 'sign-ins and failed sign-ins', opened: 'apps opened', audit: 'certificate and help entries' };
  function whatText(e) {
    const ms = (e.methods || []).map(m => SHORT[m] || m).join(' + ');
    const with_ = ms ? ' · ' + ms : '';
    let t;
    switch (e.kind) {
      case 'sign_in': t = 'Signed in' + with_; break;
      case 'step_up': t = 'Signed in with a stronger method' + with_; break;
      case 'failed': t = 'Sign-in failed' + with_ + (e.reason ? ': ' + e.reason : ''); break;
      case 'confirmed': t = 'Confirmed it was them' + with_; break;
      case 'opened': t = 'Opened ' + (e.app || 'an app') + with_; break;
      case 'help': t = 'Help from ' + (e.by || 'an administrator'); break;
      case 'method': t = 'Sign-in method'; break;
      case 'certificate': t = 'Certificate'; break;
      case 'ssh_certificate': t = 'SSH certificate'; break;
      case 'impersonation': t = (e.by || 'Someone') + ' signed in as them' + (e.reason ? ' · “' + e.reason + '”' : ''); break;
      default: t = String(e.kind || 'entry');
    }
    if (e.detail) t += ' · ' + e.detail;
    return t;
  }

  function historyURL(user, before) {
    return '/api/directory/users/' + enc(user) + '/signin/history?limit=' + HISTORY_PAGE + (before ? '&before=' + enc(before) : '');
  }

  // loadHistory(box, user, more): user's first page (or, more, the page
  // before the last one shown) into box; false when user isn't a
  // username (nothing is asked).
  async function loadHistory(box, user, more) {
    if (!USER_RE.test(user || '')) {
      replaceKids(box, warn('A username is 1 to 64 characters: a-z, 0-9, “.”, “_” or “-”.'));
      return false;
    }
    const st = more && box.hist && box.hist.user === user ? box.hist : { user, entries: [], next: '', unknown: [] };
    let page;
    try {
      page = await call('GET', historyURL(user, more ? st.next : ''));
    } catch (e) {
      replaceKids(box, warn('Couldn’t load ' + user + '’s history: ' + e.message));
      return false;
    }
    st.entries = st.entries.concat(page.entries || []);
    st.next = page.next || '';
    st.unknown = Array.from(new Set(st.unknown.concat(page.unknown || [])));
    box.hist = st;
    drawHistory(box);
    return true;
  }

  function drawHistory(box) {
    const st = box.hist;
    const unknown = st.unknown.map(s => SOURCES[s] || s);
    const rows = st.entries.map(e => el('tr', { 'data-hist-kind': e.kind },
      el('td', { class: 'nowrap', text: when(e.time) }),
      el('td', { text: whatText(e) }),
      el('td', { class: 'settings-empty', text: [e.browser, e.ip].filter(Boolean).join(' · ') })));
    replaceKids(box,
      el('p', null, 'Sign-in history of ', personLink(st.user), ', newest first.'),
      unknown.length ? warn('Some of the history couldn’t be read right now (' + unknown.join(', ') + '): what’s shown may be incomplete.') : null,
      rows.length ? table(['When', 'What', 'From'], rows) : muted('Nothing yet.'),
      st.next ? el('div', null, el('button', {
        type: 'button', class: 'btn btn-sm', 'data-hist-older': '', text: 'Older',
        on: { click: () => loadHistory(box, st.user, true) },
      })) : null);
  }

  // renderSignins(box, user): the username picker and, for user, the
  // history.
  function renderSignins(box, user) {
    const out = el('div', { 'data-hist-out': '' });
    const input = el('input', { type: 'text', placeholder: 'username, e.g. alice', 'aria-label': 'Username', autocomplete: 'off', spellcheck: 'false', value: user || '' });
    const show = () => {
      const u = input.value.trim().toLowerCase();
      if (USER_RE.test(u)) history.replaceState(null, '', '#access/signins?user=' + enc(u));
      loadHistory(out, u, false);
    };
    input.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); show(); } });
    replaceKids(box,
      muted('One person’s sign-ins, failed sign-ins, apps opened, certificates and help, from their Sign-in page’s history.'),
      el('div', { class: 'access-pick' }, input, el('button', { type: 'button', class: 'btn btn-primary btn-sm', text: 'Show', on: { click: show } })),
      out);
    if (user) loadHistory(out, user, false);
  }

  // ── the tab ────────────────────────────────────────────────
  function renderSSH(box, sub) {
    const inner = el('div', { id: 'ssh-root' });
    replaceKids(box,
      el('p', { class: 'settings-empty', style: 'margin-bottom:1rem' },
        'Short-lived SSH certificates for people’s host groups, signed after a Portcullis sign-in (', code('portcullis login'), '). ',
        'Managed hosts are enrolled once and kept current; unmanaged hosts trust the CA with ', code('portcullis host trust'), '.'),
      inner);
    if (window.PortcullisSSH) window.PortcullisSSH.render(inner, sub, id => history.replaceState(null, '', '#access/ssh/' + id));
  }

  function render(root, section, opts) {
    const o = opts || {};
    const current = SECTIONS.some(s => s[0] === section) ? section : 'ssh';
    const body = el('div', { 'data-access-body': current });
    const nav = el('div', { class: 'access-nav', role: 'tablist' }, SECTIONS.map(([id, label]) => el('button', {
      type: 'button', role: 'tab', 'aria-selected': id === current ? 'true' : 'false', 'data-access-section': id, text: label,
      on: { click: () => { history.replaceState(null, '', '#access/' + id); render(root, id, {}); } },
    })));
    replaceKids(root, nav, body);
    if (current === 'ssh') renderSSH(body, o.sub || '');
    else if (current === 'vpn') renderVPN(body);
    else renderSignins(body, o.user || '');
  }

  window.PortcullisAccess = { render, _test: { renderVPN, loadHistory, whatText } };
})();
