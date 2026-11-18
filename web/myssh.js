// Portcullis — SSH access on people.<domain> (contract §18, spec §9.11).
//
//   window.PortcullisMySSH.mountSelf(el)
//       the person's SSH access card on the Sign-in page: GET /api/me/ssh;
//       "Revoke all my SSH certificates" (I lost a device), the CLI
//       download and the two commands to start.
//   window.PortcullisMySSH.mountPerson(el, user)
//       People → person (administrators, sign_in_help holders who may
//       help them): GET /api/directory/users/{u}/ssh and Revoke all SSH
//       certificates. Any refusal (403, 404, 503) leaves el hidden.
//   window.PortcullisMySSH.renderDelegate(panel)
//       the SSH access tab for ssh_access holders: the grants of
//       delegable host groups (/api/ssh/delegated/*), their hypothetical
//       preview and who can reach each host group. No privileged option
//       is offered (the Hub refuses them from delegates anyway).
//   window.PortcullisMySSH.probeDelegate(tabButton)
//       hides the tab's button unless the caller may use it.
//
// Rules: no markup from strings (el() builds every node, server values
// are text or attributes only); a download link only when it is https.
(function () {
  'use strict';

  const enc = encodeURIComponent;
  const DELEGATED = '/api/ssh/delegated';

  function el(tag, props, ...kids) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) {
      if (v == null || v === false) continue;
      if (k === 'class') n.className = v;
      else if (k === 'text') n.textContent = String(v);
      else if (k === 'on') for (const [ev, fn] of Object.entries(v)) n.addEventListener(ev, fn);
      else if (k === 'value') n.value = String(v);
      else if (k === 'checked' || k === 'readOnly' || k === 'disabled' || k === 'hidden' || k === 'selected') n[k] = !!v;
      else n.setAttribute(k, String(v));
    }
    for (const c of kids.flat(Infinity)) {
      if (c == null || c === false) continue;
      n.appendChild(typeof c === 'string' || typeof c === 'number' ? document.createTextNode(String(c)) : c);
    }
    return n;
  }
  // put / replaceKids: append (or replace with) kids, arrays flattened,
  // null and false skipped (DOM append would print them).
  function put(n, ...kids) {
    for (const c of kids.flat(Infinity)) {
      if (c == null || c === false) continue;
      n.appendChild(typeof c === 'string' || typeof c === 'number' ? document.createTextNode(String(c)) : c);
    }
    return n;
  }
  function replaceKids(n, ...kids) {
    while (n.firstChild) n.removeChild(n.firstChild);
    return put(n, ...kids);
  }
  function code(t) { return el('code', { text: t }); }
  function list(a) { return (a || []).join(', '); }
  function words(s) { return String(s || '').split(/[\s,]+/).map(x => x.trim()).filter(Boolean); }
  function when(t) {
    if (!t) return '—';
    const d = new Date(t);
    return isNaN(d) || d.getUTCFullYear() < 2000 ? '—' : d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
  }
  function btn(text, onClick, cls) {
    return el('button', { type: 'button', class: 'pd-btn sm ' + (cls || ''), text, on: { click: onClick } });
  }
  function table(head, rows) {
    return el('table', { class: 'pd-table' },
      el('thead', null, el('tr', null, head.map(t => el('th', { text: t })))),
      el('tbody', null, rows));
  }
  function field(label, input) { return el('label', { class: 'pd-field' }, el('span', { text: label }), input); }
  async function call(method, path, body) {
    const opts = { method, headers: {} };
    if (body !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
    const res = await fetch(path, opts);
    if (!res.ok) {
      const err = new Error((await res.text()).trim() || res.statusText);
      err.status = res.status;
      throw err;
    }
    return res.status === 204 ? null : res.json();
  }
  function httpsURL(u) {
    try { return new URL(u).protocol === 'https:' ? u : ''; } catch (_) { return ''; }
  }

  // card: the SSH access card for v (GET /api/me/ssh or a person's).
  function card(v, self, revokePath, redraw) {
    const status = el('p', { class: 'pd-muted', role: 'status', 'aria-live': 'polite' });
    const groups = (v.host_groups || []).map(g => el('tr', null,
      el('td', null, code(g.id), g.label ? ' ' + g.label : ''),
      el('td', null, (g.accounts || []).map((a, i) => [i ? ', ' : '', code(a)])),
      el('td', { text: g.sudo ? 'yes' : '' }),
      el('td', { text: list(g.hosts) || '—' }),
      el('td', { text: when(g.until) })));
    const certs = (v.certificates || []).map(c => el('tr', null,
      el('td', null, code(c.host_group)), el('td', null, code(c.key_fp)), el('td', { text: when(c.valid_before) }), el('td', { text: c.flow + (c.own ? ' (own key)' : '') })));
    const box = el('div', { 'data-ssh-card': v.user },
      el('h3', { class: 'pd-h3', text: 'SSH access' }),
      groups.length ? table(['Host group', 'Accounts', 'sudo', 'Hosts', 'Certificates until'], groups)
        : el('p', { class: 'pd-muted', text: self ? 'No SSH access yet: an administrator grants it through a group.' : 'No SSH access.' }),
      certs.length ? [el('h4', { text: 'Certificates' }), table(['Host group', 'Key', 'Valid until', 'How'], certs)] : null,
      el('div', { class: 'pd-actions' }, btn(self ? 'Revoke all my SSH certificates' : 'Revoke all SSH certificates', async () => {
        const q = self ? 'Revoke all your SSH certificates? Do this when you lost a device. Sign in again with portcullis login to get new ones.'
          : 'Revoke every SSH certificate of ' + v.user + '? Hosts refuse them from their next sync.';
        if (!confirm(q)) return;
        try {
          const a = await call('POST', revokePath);
          status.textContent = 'Revoked ' + a.revoked + '.';
          redraw();
        } catch (e) { status.textContent = e.message; }
      }, 'danger')), status);
    if (self && (v.commands || []).length) {
      const dl = httpsURL(v.download);
      put(box, el('h4', { text: 'Start' }),
        el('p', null, 'Install the Portcullis CLI', dl ? [' (', el('a', { href: dl, target: '_blank', rel: 'noopener', text: 'download' }), ')'] : null, ', then run:'),
        (v.commands || []).map(c => el('pre', null, code(c))));
    }
    return box;
  }

  async function mount(el0, path, self, revokePath) {
    el0.hidden = true;
    let v;
    try { v = await call('GET', path); } catch (_) { return; }
    if (!v || !v.enabled) return;
    replaceKids(el0, card(v, self, revokePath, () => mount(el0, path, self, revokePath)));
    el0.hidden = false;
  }
  function mountSelf(el0) { return mount(el0, '/api/me/ssh', true, '/api/me/ssh/revoke-all'); }
  function mountPerson(el0, user) {
    const u = enc(user);
    return mount(el0, '/api/directory/users/' + u + '/ssh', false, '/api/directory/users/' + u + '/ssh/revoke-all');
  }

  // ── the delegates' SSH access tab ──────────────────────────
  function accessTable(rows) {
    rows = rows || [];
    if (!rows.length) return el('p', { class: 'pd-muted', text: 'Nobody.' });
    return table(['Person', 'Account', 'Host', 'sudo', 'Via', 'Status'], rows.map(r => el('tr', null,
      el('td', { text: r.person }), el('td', null, code(r.account)), el('td', { text: r.host || '—' }),
      el('td', { text: r.sudo ? 'yes' : '' }), el('td', { text: list(r.via) }), el('td', { text: r.status }))));
  }
  async function renderDelegate(panel) {
    const status = el('p', { class: 'pd-muted', role: 'status', 'aria-live': 'polite' });
    let v;
    try { v = await call('GET', DELEGATED + '/grants'); } catch (e) {
      replaceKids(panel, el('p', { class: 'pd-muted', text: e.status === 403 ? 'Granting SSH access needs the ssh_access permission.' : e.message }));
      return;
    }
    const hgs = v.host_groups || [];
    const form = el('div', { class: 'pd-card', 'data-ssh-delegate-form': '' });
    const out = el('div');
    const redraw = () => renderDelegate(panel);
    const rows = (v.grants || []).map(g => el('tr', { 'data-ssh-grant': g.id },
      el('td', null, code(g.group)), el('td', null, code(g.host_group)),
      el('td', { text: (g.accounts || []).map(a => a === '{username}' ? 'own account' : a).join(', ') }),
      el('td', { text: g.effective_ttl_hours + ' h' }),
      el('td', null, g.privileged ? el('span', { class: 'pd-pill', text: 'administrators only' }) : [
        btn('Edit', () => grantForm(form, g, hgs, status, redraw)), ' ',
        btn('Delete', async () => {
          if (!confirm('Delete this grant?')) return;
          try { await call('DELETE', DELEGATED + '/grants/' + enc(g.id)); redraw(); } catch (e) { status.textContent = e.message; }
        }, 'danger')])));
    replaceKids(panel, 
      el('h3', { class: 'pd-h3', text: 'SSH access' }),
      el('p', { class: 'pd-muted', text: 'Grant groups access to the host groups administrators made delegable. sudo, root and forwarding stay with administrators.' }),
      hgs.length ? el('div', { class: 'pd-actions' }, hgs.map(g => btn('Who can reach ' + g.id, async () => {
        try { const a = await call('GET', DELEGATED + '/hostgroups/' + enc(g.id) + '/access'); replaceKids(out, el('h4', { text: 'Who can reach ' + g.id }), accessTable(a.rows)); } catch (e) { status.textContent = e.message; }
      }))) : el('p', { class: 'pd-muted', text: 'No host group is delegable yet.' }),
      rows.length ? table(['Group', 'Host group', 'Accounts', 'Certificate lifetime', ''], rows) : el('p', { class: 'pd-muted', text: 'No grants on delegable host groups.' }),
      hgs.length ? btn('New grant', () => grantForm(form, null, hgs, status, redraw), 'primary') : null,
      form, status, out);
  }
  function grantForm(form, g, hgs, status, redraw) {
    const isNew = !g;
    g = g || { accounts: ['{username}'] };
    const group = el('input', { value: g.group || '', placeholder: 'a group' });
    const hg = el('select', null, hgs.map(x => el('option', { value: x.id, selected: x.id === g.host_group, text: x.id + (x.label ? ' — ' + x.label : '') })));
    const own = el('input', { type: 'checkbox', checked: (g.accounts || []).includes('{username}') });
    const shared = el('input', { value: (g.accounts || []).filter(a => a !== '{username}').join(', '), placeholder: 'deploy' });
    const ttl = el('input', { type: 'number', min: 0, max: 12, value: g.ttl_hours || 0 });
    const preview = el('div', { 'data-ssh-preview': '' });
    const body = () => ({ group: group.value.trim(), host_group: hg.value, accounts: (own.checked ? ['{username}'] : []).concat(words(shared.value)), sudo: 'none', ttl_hours: Number(ttl.value) || 0 });
    replaceKids(form, el('h4', { text: isNew ? 'New grant' : 'Edit grant' }),
      field('Group', group), field('Host group', hg),
      el('label', null, own, ' Each member\'s own account'),
      field('Shared accounts (comma separated)', shared),
      field('Certificate lifetime in hours (1–12; 0 = the default)', ttl),
      el('div', { class: 'pd-actions' },
        btn('Preview', async () => {
          try { const a = await call('POST', DELEGATED + '/grants/preview', body()); replaceKids(preview, el('h4', { text: 'Who could reach what with this grant' }), accessTable(a.rows)); } catch (e) { status.textContent = e.message; }
        }),
        btn('Save', async () => {
          try {
            await call(isNew ? 'POST' : 'PUT', DELEGATED + '/grants' + (isNew ? '' : '/' + enc(g.id)), body());
            redraw();
          } catch (e) { status.textContent = e.message; }
        }, 'primary'),
        btn('Cancel', () => replaceKids(form))),
      preview);
  }
  async function probeDelegate(tabButton) {
    if (!tabButton) return;
    tabButton.hidden = true;
    try { await call('GET', DELEGATED + '/grants'); tabButton.hidden = false; } catch (_) { /* stays hidden */ }
  }

  window.PortcullisMySSH = { mountSelf, mountPerson, renderDelegate, probeDelegate, _test: { card, httpsURL } };
})();
