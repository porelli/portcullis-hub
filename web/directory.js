// Portcullis Hub: Users & Groups (People | Groups | Org chart | Setup).
//
// Served on hub.<domain> (the Users & Groups tab, admins) and on
// people.<domain> (every signed-in user). Vanilla JS, no build step.
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

  // ── state ───────────────────────────────────────────────
  let root = null;           // mount element
  let options = {};
  let me = null;             // /api/directory/me
  let dir = null;            // /api/directory
  let tab = 'people';
  let search = '';
  let orgField = '';
  const openGroups = new Set();
  let imp = null;            // import review state
  let dialogClose = null;    // cleanup of the open dialog

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
      return showOff(options.listener === 'hub'
        ? '<b>User management is disabled.</b> The Hub has no LLDAP service account: core mounts its credentials as ' +
          '<code>username</code> and <code>password</code> files (default <code>/run/portcullis/lldap/</code>). Run <code>./portcullis up</code> ' +
          'on a core version that provides them. The LLDAP web UI still works.<br><span class="pd-muted">' + esc(dir.reason) + '</span>'
        : 'The directory is temporarily unavailable. <span class="pd-muted">' + esc(dir.reason) + '</span>', true);
    }
    if (!me) me = { user: dir.me, admin: dir.admin, perms: dir.perms || [] };
    off.hidden = true;
    main.hidden = false;
    if (options.onUser) options.onUser(me.user);
    renderAll();
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
    renderUserDatalist();
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
    if (options.hashTabs) history.replaceState(null, '', name === 'people' ? location.pathname : '#' + name);
    if (name === 'setup' && isAdmin()) loadAudit();
  }

  function renderUserDatalist() {
    root.querySelector('#pd-users-dl').innerHTML = users().map(u =>
      '<option value="' + esc(u.username) + '">' + esc(u.display_name || '') + '</option>').join('');
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
        title = 'exception: ' + (m.reason || '') + (m.until ? ' (until ' + fmtTime(m.until) + ')' : '');
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
    root.querySelector('.pd-people-main').hidden = !!imp;
    root.querySelector('.pd-import').hidden = !imp;
    if (imp) renderImport();
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

  // ── person dialog ───────────────────────────────────────
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
      (f.kind === 'person' ? ' list="pd-users-dl" placeholder="username"' : '') + dis + '>';
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

  function openUser(name) {
    const u = userByName(name);
    if (!u) { closeDialog(); return; }
    const admin = isAdmin();
    const editable = canEdit(u);
    let h = '<div class="pd-person" data-user="' + esc(u.username) + '">';
    h += '<div class="pd-person-head"><div><div class="pd-person-name">' + esc(u.display_name || u.username) + '</div><div class="pd-muted">' +
      esc(u.username) + (u.email ? ' · ' + esc(u.email) : '') + (u.created ? ' · since ' + esc(fmtDate(u.created)) : '') + '</div></div><div>';
    if (u.self) h += '<span class="pd-pill info">you</span>';
    if (u.protected === 'service') h += '<span class="pd-pill" title="The Hub\'s own LLDAP account (read-only here)">Hub service account</span>';
    if (u.protected === 'core-admin') h += '<span class="pd-pill" title="Bootstrap LLDAP admin: Keycloak and enroll bind as it. Managed from the server only (./portcullis invite admin)">bootstrap admin (server-managed)</span>';
    if (u.admin && u.protected !== 'service') h += '<span class="pd-pill info" title="Member of an administrator group: no invites from the Hub">administrator</span>';
    h += '</div></div>';
    if (u.created_by) h += '<p class="pd-muted">Account created by ' + esc(u.created_by) + '.</p>';

    // details
    h += '<section class="pd-sec" aria-label="Details"><h3 class="pd-h3">Details</h3><div class="pd-grid">';
    h += '<div><label for="pu-email">Email</label><input type="email" id="pu-email" value="' + esc(u.email) + '"' + (editable ? '' : ' disabled') + '></div>';
    h += '<div><label for="pu-display">Display name</label><input type="text" id="pu-display" value="' + esc(u.display_name) + '"' + (editable ? '' : ' disabled') + '></div>';
    for (const f of fields()) {
      const id = uid('pu-f-');
      const fe = editable && (!f.admin_only || admin);
      h += '<div><label for="' + id + '" id="' + id + '-l">' + esc(f.label || f.name) +
        (f.admin_only ? ' <span class="pd-muted" title="Only admins can change it">(admin-only)</span>' : '') + '</label>' + fieldInput(f, (u.attrs || {})[f.name], id, fe) + '</div>';
    }
    h += '</div>';
    if (editable) h += '<button type="button" class="pd-btn primary sm" data-act="save-user" data-user="' + esc(u.username) + '">Save details</button>';
    else if (can('edit_details') && !u.protected) h += '<p class="pd-muted">Only an admin can change ' + esc(u.username) + '.</p>';
    h += '</section>';

    // groups
    h += '<section class="pd-sec" aria-label="Groups"><h3 class="pd-h3">Groups</h3>';
    const ms = u.memberships || [];
    if (!ms.length) h += '<p class="pd-muted">No groups.</p>';
    else {
      h += '<ul class="pd-memberships">';
      for (const m of ms) {
        const g = groupByName(m.group);
        let how = m.how === 'rule' ? '⚡ via rule' + (u.created_by ? ', account created by ' + esc(u.created_by) : '')
          : m.how === 'exception' ? '✱ exception: ' + esc(m.reason || '') : 'manual';
        if (m.until) how += ' · until ' + esc(fmtTime(m.until));
        h += '<li><span class="pd-mono">' + esc(m.group) + '</span> <span class="pd-muted">' + how + '</span>';
        if (admin && g && !g.rule && !memberLocked(g, u.username)) {
          h += ' <button type="button" class="pd-btn ghost xs" data-act="remove-member" data-group="' + esc(g.name) + '" data-user="' + esc(u.username) + '">Remove</button>';
        }
        h += '</li>';
      }
      h += '</ul>';
    }
    if (admin && !u.protected) {
      const cand = groups().filter(g => !g.rule && !(g.members || []).includes(u.username));
      if (cand.length) {
        h += '<div class="pd-inline"><label for="pu-addgroup" class="pd-sr">Add to group</label><select id="pu-addgroup">' +
          cand.map(g => '<option value="' + esc(g.name) + '">' + esc(g.name) + '</option>').join('') +
          '</select><button type="button" class="pd-btn secondary sm" data-act="user-add-group" data-user="' + esc(u.username) + '">Add to group</button></div>';
      }
    }
    h += '</section>';

    // keys & account actions
    const keyActions = [];
    if (admin && !u.protected) {
      const kc = u.keycloak;
      if (!u.admin) keyActions.push(['invite', 'Send new invite', 'primary']);
      if (!kc || !(kc.required_actions || []).includes('webauthn-register-passwordless')) keyActions.push(['require-passkey', 'Require passkey', 'secondary']);
      if (kc && (kc.required_actions || []).length) keyActions.push(['clear-actions', 'Clear pending', 'secondary']);
      keyActions.push(['reset-passkeys', 'Reset passkeys', 'danger']);
      keyActions.push(['password', 'Password…', 'danger']);
    } else if (!admin && can('invite') && u.created_by && u.created_by === (me && me.user)) {
      keyActions.push(['invite', 'Send new invite', 'primary']);
    }
    if (canRemove(u)) keyActions.push(['delete-user', 'Delete', 'danger']);
    if (admin || keyActions.length) {
      h += '<section class="pd-sec" aria-label="Keys and account"><h3 class="pd-h3">' + (admin ? 'Keys' : 'Account') + '</h3>';
      if (admin) {
        h += '<div>' + keyStatus(u) + '</div>';
        if (u.server_invite && !u.protected) h += '<div class="pd-muted" title="Administrators are invited and recovered from the server">recover on the server: <code>' + esc(u.server_invite) + '</code></div>';
      }
      h += '<div class="pd-actions">' + keyActions.map(([a, label, cls]) =>
        '<button type="button" class="pd-btn ' + cls + ' sm" data-act="' + a + '" data-user="' + esc(u.username) + '">' + esc(label) + '</button>').join('') + '</div></section>';
    }
    h += '</div>';
    openDialog(u.display_name ? u.display_name + ' (' + u.username + ')' : u.username, h);
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
    if (res) openUser(name);
  }

  // ── invite dialog ───────────────────────────────────────
  function openInvite() {
    const admin = isAdmin();
    let h = '<div class="pd-grid">' +
      '<div><label for="nu-username">Username</label><input type="text" id="nu-username" autocomplete="off" placeholder="lowercase, e.g. alice" required></div>' +
      '<div><label for="nu-email">Email</label><input type="email" id="nu-email" autocomplete="off" required></div>' +
      '<div><label for="nu-display">Display name</label><input type="text" id="nu-display" autocomplete="off"></div></div>';
    if (admin) {
      const gs = groups().filter(g => !g.rule && (!g.builtin || g.name === 'lldap_admin'));
      h += '<fieldset class="pd-fieldset"><legend>Groups</legend><div class="pd-checks">' + (gs.length ? gs.map(g =>
        '<label' + (g.admin ? ' title="Administrator group: the user is onboarded from the server (./portcullis invite), not with an invite link"' : '') +
        '><input type="checkbox" name="nu-group" value="' + esc(g.name) + '"> ' + esc(g.name) + (g.admin ? ' <span class="pd-pill info">admin</span>' : '') + '</label>').join('')
        : '<span class="pd-muted">No manual groups yet.</span>') + '</div></fieldset>';
      h += '<p class="pd-note">The new person gets a one-time invite link: they open it, register their security key, and they\'re signed in. No password. Rule-based groups add them once their details match.</p>';
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
    dialogBody().querySelector('#nu-username').focus();
  }

  async function createUser() {
    const b = dialogBody();
    const username = b.querySelector('#nu-username').value.trim();
    if (!username) { toast('A username is required', 'error'); return; }
    const body = {
      username,
      email: b.querySelector('#nu-email').value.trim(),
      display_name: b.querySelector('#nu-display').value.trim(),
      groups: Array.from(b.querySelectorAll('input[name="nu-group"]:checked')).map(i => i.value),
      onboarding: 'invite',
    };
    const usePw = b.querySelector('#nu-use-password');
    if (usePw && usePw.checked) {
      body.onboarding = 'password';
      body.generate_password = b.querySelector('input[name="nu-pwmode"]:checked').value === 'generate';
      if (!body.generate_password) body.password = b.querySelector('#nu-password').value;
      body.require_passkey = b.querySelector('#nu-require-passkey').checked;
    }
    const res = await act(() => api('POST', '/api/directory/users', body), username + ' created');
    if (res) { closeDialog(); showSecret(res, username); }
  }

  // ── account actions (shared by the dialog) ──────────────
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
        const res = await act(() => api('POST', path + '/require-passkey', {}), user + ' will be asked to register a passkey at next sign-in');
        if (res) openUser(user);
        return;
      }
      case 'clear-actions': {
        const res = await act(() => api('POST', path + '/clear-actions', {}), 'Cleared pending actions');
        if (res) openUser(user);
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
        if (res) closeDialog();
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
        (kind === 'person' ? ' list="pd-users-dl" placeholder="username"' : ' placeholder="value"') + '>';
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
  function renderGroups() {
    const admin = isAdmin();
    let h = '';
    const sugg = (admin && dir.suggestions) || [];
    if (sugg.length) {
      h += '<div class="pd-card pd-missing"><h3 class="pd-h3">Missing groups</h3><p class="pd-muted">Apps you enabled grant access through a group that doesn\'t exist yet, so nobody can use them until you create it and add members.</p>';
      for (const g of sugg) {
        const app = esc(g.app_name || g.app);
        h += '<div class="pd-suggestion"><code>' + esc(g.group) + '</code><span class="pd-muted">' +
          (g.kind === 'admin' ? 'Members become ' + app + ' administrators' : 'Members can sign in to ' + app) + '</span>' +
          '<button type="button" class="pd-btn primary sm" data-act="create-group" data-group="' + esc(g.group) + '">Create</button></div>';
      }
      h += '</div>';
    }
    if (admin) {
      h += '<form class="pd-inline pd-newgroup" data-form="new-group"><label for="pd-ng-name" class="pd-sr">New group name</label>' +
        '<input type="text" id="pd-ng-name" placeholder="New group, e.g. users_myapp" autocomplete="off"><button type="submit" class="pd-btn primary sm">Create group</button></form>';
    }
    for (const g of groups()) h += groupCard(g, admin);
    if (!groups().length) h += '<p class="pd-muted">No groups yet.</p>';
    root.querySelector('.pd-groups').innerHTML = h;
  }

  function groupCard(g, admin) {
    const open = openGroups.has(g.name);
    const members = g.members || [];
    const bodyId = 'pd-g-' + g.name.replace(/[^a-z0-9_-]/gi, '_');
    let h = '<div class="pd-group' + (open ? ' open' : '') + '"><button type="button" class="pd-group-head" data-act="toggle-group" data-group="' + esc(g.name) + '" aria-expanded="' + (open ? 'true' : 'false') + '" aria-controls="' + esc(bodyId) + '">' +
      '<span class="pd-caret" aria-hidden="true">' + (open ? '▾' : '▸') + '</span><span class="pd-mono pd-gname">' + esc(g.name) + '</span>';
    h += g.rule ? '<span class="pd-rulebadge" title="Rule-based: membership is computed">⚡ <code>' + esc(g.rule.text) + '</code></span>' : '<span class="pd-pill">Manual</span>';
    h += '<span class="pd-muted">' + esc(plural(members.length, 'member')) + (g.builtin ? ' · built-in' : '') + (g.admin ? ' · administrator group' : '') +
      ((g.used_by || []).length ? ' · grants ' + g.used_by.map(esc).join(', ') : '') + '</span></button>';
    if (!open) return h + '</div>';
    h += '<div class="pd-group-body" id="' + esc(bodyId) + '">';
    if (g.adds_blocked) h += '<div class="pd-warn">' + esc(g.adds_blocked) + '</div>';
    if (g.rule) h += ruleGroupBody(g, admin);
    else h += manualGroupBody(g, admin);
    if (admin) {
      h += '<div class="pd-actions">';
      if (!g.rule && g.rule_allowed) h += '<button type="button" class="pd-btn secondary sm" data-act="convert-open" data-group="' + esc(g.name) + '">Make rule-based…</button>';
      if (g.rule) {
        h += '<button type="button" class="pd-btn secondary sm" data-act="rule-open" data-group="' + esc(g.name) + '">Edit rule…</button>';
        h += '<button type="button" class="pd-btn secondary sm" data-act="make-manual" data-group="' + esc(g.name) + '">Make manual</button>';
      }
      if (!g.builtin) h += '<button type="button" class="pd-btn danger sm" data-act="delete-group" data-group="' + esc(g.name) + '">Delete group</button>';
      h += '</div>';
    }
    return h + '</div></div>';
  }

  function manualGroupBody(g, admin) {
    const members = g.members || [];
    const expiry = g.expiry || {};
    let h = '';
    if (!members.length) h += '<p class="pd-muted">No members.</p>';
    else {
      h += '<table class="pd-table"><thead><tr><th scope="col">Member</th><th scope="col">Until</th>' + (admin ? '<th scope="col"><span class="pd-sr">Actions</span></th>' : '') + '</tr></thead><tbody>';
      for (const m of members) {
        const locked = memberLocked(g, m);
        const until = expiry[m];
        h += '<tr><td class="pd-mono">' + esc(m) + '</td><td>' + (until ? esc(fmtTime(until)) : '<span class="pd-muted">no end</span>') + '</td>';
        if (admin) {
          h += '<td>';
          if (!locked && g.name !== 'lldap_admin') {
            const id = uid('pd-exp-');
            h += '<span class="pd-inline"><label for="' + id + '" class="pd-sr">Membership of ' + esc(m) + ' ends at (local time)</label><input type="datetime-local" id="' + id + '" value="' + esc(toLocalInput(until)) + '">' +
              '<button type="button" class="pd-btn ghost xs" data-act="set-expiry" data-group="' + esc(g.name) + '" data-user="' + esc(m) + '" data-input="' + id + '">Set end</button>' +
              (until ? '<button type="button" class="pd-btn ghost xs" data-act="clear-expiry" data-group="' + esc(g.name) + '" data-user="' + esc(m) + '">No end</button>' : '') + '</span>';
          }
          if (!locked) h += '<button type="button" class="pd-btn danger xs" data-act="remove-member" data-group="' + esc(g.name) + '" data-user="' + esc(m) + '">Remove</button>';
          h += '</td>';
        }
        h += '</tr>';
      }
      h += '</tbody></table>';
    }
    if (admin) {
      const cand = users().filter(u => !u.protected && !members.includes(u.username));
      if (cand.length) {
        const sid = uid('pd-add-'), eid = uid('pd-addexp-');
        h += '<div class="pd-inline"><label for="' + sid + '" class="pd-sr">Person to add</label><select id="' + sid + '">' + cand.map(u => '<option value="' + esc(u.username) + '">' + esc(u.username) +
          (u.display_name ? ' (' + esc(u.display_name) + ')' : '') + '</option>').join('') + '</select>' +
          (g.name !== 'lldap_admin' ? '<label for="' + eid + '">until (optional)</label><input type="datetime-local" id="' + eid + '">' : '') +
          '<button type="button" class="pd-btn secondary sm" data-act="add-member" data-group="' + esc(g.name) + '" data-select="' + sid + '" data-input="' + eid + '">Add member</button></div>';
      }
    }
    return h;
  }

  function ruleGroupBody(g, admin) {
    const members = g.members || [];
    const ex = g.exceptions || [];
    let h = '<p class="pd-rule-text"><span class="pd-muted">Rule:</span> <code>' + esc(g.rule.text) + '</code></p>';
    h += '<h4 class="pd-h4">Members (' + members.length + ')</h4>';
    h += members.length ? '<div>' + members.map(m => {
      const u = userByName(m);
      const ms = ((u && u.memberships) || []).find(x => x.group === g.name);
      const how = ms ? ms.how : '';
      if (how === 'exception') {
        return '<span class="pd-pill" title="' + esc('exception: ' + (ms.reason || '') + (ms.until ? ' (until ' + fmtTime(ms.until) + ')' : '')) + '">' + esc(m) + ' ✱</span>';
      }
      if (how === 'rule') return '<span class="pd-pill" title="member through the rule">' + esc(m) + ' ⚡</span>';
      // In LLDAP but neither the rule nor an exception explains it.
      return '<span class="pd-pill warn" title="The rule doesn\'t match: the next evaluation removes them">' + esc(m) + ' (leaving)</span>';
    }).join('') + '</div>' : '<p class="pd-muted">Nobody matches yet.</p>';
    h += '<h4 class="pd-h4">Exceptions</h4>';
    if (!ex.length) h += '<p class="pd-muted">None.</p>';
    else {
      h += '<table class="pd-table"><thead><tr><th scope="col">Person</th><th scope="col">Exception</th><th scope="col">Reason</th><th scope="col">Until</th><th scope="col">Set by</th>' +
        (admin ? '<th scope="col"><span class="pd-sr">Actions</span></th>' : '') + '</tr></thead><tbody>';
      for (const e of ex) {
        h += '<tr' + (e.expired ? ' class="pd-expired"' : '') + '><td class="pd-mono">' + esc(e.user) + '</td><td>' + (e.include ? '<span class="pd-pill ok">added ✱</span>' : '<span class="pd-pill warn">kept out ✱</span>') +
          (e.expired ? '<span class="pd-pill bad">expired</span>' : '') + '</td><td>' + esc(e.reason) + '</td><td>' + (e.until ? esc(fmtTime(e.until)) : '<span class="pd-muted">no end</span>') +
          '</td><td class="pd-muted">' + esc(e.by) + (e.at ? '<br>' + esc(fmtDate(e.at)) : '') + '</td>';
        if (admin) h += '<td><button type="button" class="pd-btn danger xs" data-act="remove-exception" data-group="' + esc(g.name) + '" data-user="' + esc(e.user) + '">Remove</button></td>';
        h += '</tr>';
      }
      h += '</tbody></table>';
    }
    if (admin) {
      const p = uid('pd-ex-');
      const cand = users().filter(u => !u.protected);
      h += '<form class="pd-exform" data-form="add-exception" data-group="' + esc(g.name) + '"><fieldset class="pd-fieldset"><legend>Add an exception</legend><div class="pd-grid">' +
        '<div><label for="' + p + 'u">Person</label><select id="' + p + 'u" name="user">' + cand.map(u => '<option value="' + esc(u.username) + '">' + esc(u.username) + '</option>').join('') + '</select></div>' +
        '<div><label for="' + p + 'k">Exception</label><select id="' + p + 'k" name="include"><option value="true">add them (although they don\'t match)</option><option value="false">keep them out (although they match)</option></select></div>' +
        '<div><label for="' + p + 'r">Reason (required)</label><input type="text" id="' + p + 'r" name="reason" maxlength="500" required placeholder="why?"></div>' +
        '<div><label for="' + p + 't">Until (optional, local time)</label><input type="datetime-local" id="' + p + 't" name="until"></div></div>' +
        '<button type="submit" class="pd-btn secondary sm">Add exception</button></fieldset></form>';
    }
    return h;
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
    try {
      await api('PUT', '/api/directory/groups/' + enc(name) + '/rule', ed.body());
    } catch (err) {
      ed.setStatus(errText(err), '', err.column);
      toast(errText(err), 'error');
      return;
    }
    closeDialog();
    toast('Rule of ' + name + ' saved', 'success');
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
    try {
      await api('POST', '/api/directory/groups/' + enc(body.group) + '/convert', req);
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
    openGroups.add(name);
    toast(name + ' is now rule-based', 'success');
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
    let h = '<section class="pd-sec" aria-labelledby="pd-fields-h"><h3 class="pd-h3" id="pd-fields-h">Fields</h3>' +
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
    h += '<section class="pd-sec" aria-labelledby="pd-audit-h"><div class="pd-head"><h3 class="pd-h3" id="pd-audit-h">Audit log (last 100 changes)</h3><button type="button" class="pd-btn secondary xs" data-act="audit-reload">Refresh</button></div><div class="pd-audit"><p class="pd-muted">Loading…</p></div></section>';
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
  async function loadAudit() {
    const box = root.querySelector('.pd-audit');
    if (!box) return;
    try {
      const entries = await api('GET', '/api/directory/audit');
      if (!entries.length) { box.innerHTML = '<p class="pd-muted">No changes yet.</p>'; return; }
      let h = '<table class="pd-table"><thead><tr><th scope="col">Time</th><th scope="col">Who</th><th scope="col">Action</th><th scope="col">Target</th><th scope="col">Result</th></tr></thead><tbody>';
      for (const e of entries) {
        const cls = e.result === 'ok' ? 'ok' : (e.result === 'refused' ? 'warn' : 'bad');
        h += '<tr><td class="pd-muted pd-nowrap">' + esc(fmtTime(e.time)) + '</td><td>' + esc(e.actor) + '</td><td>' + esc(e.action) +
          (e.detail ? '<div class="pd-muted">' + esc(e.detail) + '</div>' : '') + '</td><td>' + esc(e.target) + '</td>' +
          '<td><span class="pd-pill ' + cls + '">' + esc(e.result) + '</span>' + (e.error ? '<div class="pd-muted">' + esc(e.error) + '</div>' : '') + '</td></tr>';
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
  const reReview = debounce(async () => {
    if (!imp) return;
    const seq = ++imp.seq;
    try {
      const r = await api('POST', '/api/directory/import/review', { header: imp.header, rows: imp.rows });
      if (!imp || seq !== imp.seq) return;
      imp.header = r.header;
      imp.rows = r.rows;
      imp.review = r.review;
      imp.error = '';
    } catch (err) {
      if (!imp || seq !== imp.seq) return;
      imp.error = errText(err);
    }
    imp.pending = false;
    renderImport(true);
  }, 400);
  function importChanged() {
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
      '<p class="pd-muted">Uploading changed nothing yet. Edit any cell; ↺ keeps what Portcullis has. Multiple values: separate them with |.</p></div>';
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
    if (f && f.kind === 'person') list = ' list="pd-users-dl"';
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
    try { dir = await api('GET', '/api/directory'); renderUserDatalist(); } catch (_) { /* shown on Done */ }
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
    if (tabBtn && root.contains(tabBtn)) { selectTab(tabBtn.dataset.pdtab, false); return; }
    const b = e.target.closest('[data-act]');
    if (!b) {
      // A click anywhere on a person's row opens them.
      const tr = e.target.closest('tr.pd-row');
      if (tr && !e.target.closest('a, button, input, select, textarea, label')) openUser(tr.dataset.user);
      return;
    }
    const a = b.dataset.act, user = b.dataset.user || '', group = b.dataset.group || '';
    const gpath = '/api/directory/groups/' + enc(group);
    switch (a) {
      case 'dialog-close': return closeDialog();
      case 'copy-secret': return copyText(root.querySelector('.pd-secret input').value);
      case 'hide-secret': return hideSecret();
      case 'copy-input': { const el = document.getElementById(b.dataset.input); if (el) copyText(el.value); return; }
      case 'open-user': return openUser(user);
      case 'save-user': return saveUser(user);
      case 'invite-open': return openInvite();
      case 'invite-create': return createUser();
      case 'invite': case 'require-passkey': case 'clear-actions': case 'reset-passkeys': case 'password': case 'delete-user':
        return userAction(a, user);
      case 'remove-stale':
        if (!typed('Remove the stale Keycloak copy of ' + user + ' (LLDAP no longer has this user). This only deletes it from Keycloak.', user)) return;
        return act(() => api('DELETE', '/api/directory/keycloak-stale/' + enc(user), { confirm: user }), 'Removed the Keycloak copy of ' + user);
      case 'user-add-group': {
        const sel = dialogBody().querySelector('#pu-addgroup');
        if (!sel || !sel.value) return;
        const g = groupByName(sel.value);
        if (g && g.admin && !confirm('Make ' + user + ' an administrator (' + g.name + ')? Administrators can no longer be invited from the Hub; they are recovered from the server.')) return;
        const res = await act(() => api('POST', '/api/directory/groups/' + enc(sel.value) + '/members', { username: user }), user + ' added to ' + sel.value);
        if (res) openUser(user);
        return;
      }
      case 'toggle-group':
        if (openGroups.has(group)) openGroups.delete(group); else openGroups.add(group);
        renderGroups();
        { const again = root.querySelector('.pd-groups [data-act="toggle-group"][data-group="' + CSS.escape(group) + '"]'); if (again) again.focus(); }
        return;
      case 'create-group': {
        const res = await act(() => api('POST', '/api/directory/groups', { name: group }), 'Group ' + group + ' created');
        if (res) openGroups.add(group);
        return;
      }
      case 'delete-group':
        if (!typed('Delete group ' + group + '. Members lose whatever access it grants.', group)) return;
        openGroups.delete(group);
        return act(() => api('DELETE', gpath, { confirm: group }), 'Deleted ' + group);
      case 'add-member': {
        const sel = document.getElementById(b.dataset.select);
        const exp = document.getElementById(b.dataset.input);
        const who = sel ? sel.value : '';
        if (!who) return;
        let until = null;
        try { until = exp ? fromLocalInput(exp.value) : null; } catch (err) { toast(errText(err), 'error'); return; }
        const g = groupByName(group);
        if (g && g.admin && !confirm('Make ' + who + ' an administrator (' + group + ')? Administrators can no longer be invited from the Hub; they are recovered from the server.')) return;
        return act(async () => {
          await api('POST', gpath + '/members', { username: who });
          if (until) await api('PUT', gpath + '/members/' + enc(who) + '/expiry', { until });
          return {};
        }, who + ' added to ' + group + (until ? ' until ' + fmtTime(until) : ''));
      }
      case 'remove-member': {
        if (!confirm('Remove ' + user + ' from ' + group + '?')) return;
        const res = await act(() => api('DELETE', gpath + '/members/' + enc(user), {}), user + ' removed from ' + group);
        if (res && root.querySelector('.pd-dialog').open) openUser(user);
        return;
      }
      case 'set-expiry': case 'clear-expiry': {
        let until = null;
        if (a === 'set-expiry') {
          const el = document.getElementById(b.dataset.input);
          try { until = fromLocalInput(el && el.value); } catch (err) { toast(errText(err), 'error'); return; }
          if (!until) { toast('Pick a date and time first', 'error'); return; }
        }
        return act(() => api('PUT', gpath + '/members/' + enc(user) + '/expiry', { until }),
          until ? user + ' stays in ' + group + ' until ' + fmtTime(until) : user + '\'s membership of ' + group + ' has no end');
      }
      case 'remove-exception':
        if (!confirm('Remove the exception for ' + user + ' in ' + group + '? The rule alone decides again.')) return;
        return act(() => api('DELETE', gpath + '/exceptions/' + enc(user), {}), 'Exception removed');
      case 'rule-open': return openRuleEditor(group);
      case 'rule-save': return saveRule(group);
      case 'convert-open': return openConvert(group);
      case 'convert-review': return convertReview('');
      case 'convert-apply': return convertApply();
      case 'make-manual':
        if (!confirm('Make ' + group + ' manual? Its current members stay as they are; the rule and its exceptions are dropped and nobody is added or removed automatically any more.')) return;
        return act(() => api('PUT', gpath + '/rule', { manual: true }), group + ' is now manual');
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
      case 'audit-reload': return loadAudit();
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
    const on = t.dataset && t.dataset.on;
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
      if (res) openGroups.add(name);
    } else if (kind === 'add-exception') {
      const group = f.dataset.group;
      const reason = f.reason.value.trim();
      if (!reason) { toast('An exception needs a reason', 'error'); f.reason.focus(); return; }
      let until;
      try { until = fromLocalInput(f.until.value); } catch (err) { toast(errText(err), 'error'); return; }
      await act(() => api('POST', '/api/directory/groups/' + enc(group) + '/exceptions',
        { user: f.user.value, reason, include: f.include.value === 'true', until }), 'Exception saved');
    } else if (kind === 'new-field') {
      await createField(f);
    }
  }
  function onKeydown(e) {
    // Arrow keys move between the tabs (WAI-ARIA tabs pattern).
    const t = e.target;
    if (!t.dataset || !t.dataset.pdtab || (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft')) return;
    const tabs = Array.from(root.querySelectorAll('[data-pdtab]')).filter(x => !x.hidden);
    const i = tabs.indexOf(t);
    const n = tabs[(i + (e.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length];
    selectTab(n.dataset.pdtab, true);
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
    '<p class="pd-legend pd-muted">⚡ = member through a rule · ✱ = exception (hover for the reason) · ⏳ = membership ends · click a row for details</p></div>' +
    '<div class="pd-import" hidden></div><div class="pd-imp-dls"></div></section>' +
    '<section class="pd-panel pd-groups" data-panel="groups" id="pd-panel-groups" role="tabpanel" aria-labelledby="pd-tab-groups" hidden></section>' +
    '<section class="pd-panel pd-org" data-panel="org" id="pd-panel-org" role="tabpanel" aria-labelledby="pd-tab-org" hidden></section>' +
    '<section class="pd-panel pd-setup" data-panel="setup" id="pd-panel-setup" role="tabpanel" aria-labelledby="pd-tab-setup" hidden></section>' +
    '</div>' +
    '<datalist id="pd-users-dl"></datalist>' +
    '<dialog class="pd-dialog" aria-labelledby="pd-dialog-title"><div class="pd-dialog-headbar"><h2 class="pd-dialog-title" id="pd-dialog-title"></h2>' +
    '<button type="button" class="pd-btn ghost sm" data-act="dialog-close" aria-label="Close">✕</button></div><div class="pd-dialog-body"></div></dialog>' +
    '<div class="pd-toast" role="status" aria-live="polite"></div>' +
    '</div>';

  // mount renders the shell into el once; show() (re)loads the data.
  function mount(el, opts) {
    if (root) return;
    root = el;
    options = opts || {};
    el.innerHTML = SHELL;
    if (options.hashTabs) {
      const h = location.hash.slice(1);
      if (['people', 'groups', 'org', 'setup'].includes(h)) tab = h;
    }
    el.addEventListener('click', onClick);
    el.addEventListener('input', onInput);
    el.addEventListener('change', onChange);
    el.addEventListener('submit', onSubmit);
    el.addEventListener('keydown', onKeydown);
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
  function show(el, opts) {
    mount(el, opts);
    return load();
  }

  window.PortcullisDirectory = { show, csvCell };
})();
