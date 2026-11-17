// Portcullis Hub — SSH access (contract §18, spec §9.11). Hub listener
// only, administrators only.
//
//   window.PortcullisSSH.render(root)   the SSH access tab into root
//
// Sections: Hosts, Host groups, Grants (with the hypothetical preview),
// Access preview, Certificates, Settings. Routes: /api/ssh/* (§18.16).
//
// Rules of this file:
//   - no markup from strings: every node is built with el() and every
//     server value is set as text or an attribute (never innerHTML);
//   - the fresh sign-in (freshauth.js) is started from the click itself,
//     so the popup opens before any await; actions that always need it
//     (a new host or enrolment code, Remove host, a privileged grant,
//     Sign a host key) start it at once; others retry with it when the
//     Hub answers "a fresh sign-in is required";
//   - an enrolment code is shown once, in a read-only field with Copy and
//     the command to run; it is never put in a URL or the browser's
//     storage, and is dropped when the box is dismissed or the tab redrawn;
//   - a privileged grant asks for the group's name typed again.
(function () {
  'use strict';

  const API = '/api/ssh';
  const enc = encodeURIComponent;
  const FRESH_TEXT = 'a fresh sign-in is required';
  const SECTIONS = [['hosts', 'Hosts'], ['hostgroups', 'Host groups'], ['grants', 'Grants'], ['access', 'Access preview'], ['certs', 'Certificates'], ['settings', 'Settings']];

  // el(tag, props, ...children): props {class, text, on: {event: fn},
  // value, checked, type, …}; children: nodes or strings (text nodes).
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
  function pill(cls, t) { return el('span', { class: 'pill ' + (cls || ''), text: t }); }
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
  function table(head, rows) {
    return el('table', { class: 'inst-table' },
      el('thead', null, el('tr', null, head.map(t => el('th', { text: t })))),
      el('tbody', null, rows));
  }
  function btn(text, onClick, cls) {
    return el('button', { type: 'button', class: 'btn btn-sm ' + (cls || ''), text, on: { click: onClick } });
  }
  function field(label, input) { return el('label', { class: 'block' }, label, input); }

  // call: a JSON request; throws Error(text) with .status on a refusal.
  async function call(method, path, body) {
    const opts = { method, headers: {} };
    if (body !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
    const res = await fetch(path, opts);
    if (!res.ok) {
      const text = (await res.text()).trim() || res.statusText;
      const err = new Error(text);
      err.status = res.status;
      throw err;
    }
    return res.status === 204 ? null : res.json();
  }
  function needsFresh(err) { return err && err.status === 403 && String(err.message).indexOf(FRESH_TEXT) >= 0; }

  let root = null, view = null, current = 'hosts', statusBox = null, bodyBox = null;
  let hostGroups = [];

  function status(text, warn) {
    if (!statusBox) return;
    statusBox.textContent = text || '';
    statusBox.className = warn ? 'public-warn' : 'settings-empty';
  }

  // fresh(what, proof): a fresh sign-in, then proof({code, code_verifier,
  // nonce}). Call it from the click.
  function fresh(what, proof) {
    if (!window.PortcullisFreshAuth || !view || !view.fresh_auth) { status('A fresh sign-in isn\'t available on this page.', true); return; }
    window.PortcullisFreshAuth.start(view.fresh_auth, {
      ctx: { ssh: what },
      status: (t, warn) => status(t, warn),
      busy: () => {},
      end: () => {},
      proof: p => proof({ code: p.code, code_verifier: p.code_verifier, nonce: p.nonce }),
    });
  }

  // write(what, send, done): send(proof|null); a "fresh sign-in is
  // required" answer offers a button that runs it and sends again.
  async function write(what, send, done, box) {
    try {
      const out = await send(null);
      status('Saved.');
      if (done) done(out);
    } catch (err) {
      if (!needsFresh(err)) { status(err.message, true); return; }
      status('');
      const where = box || statusBox;
      const b = btn('Confirm with a fresh sign-in', () => {
        b.remove();
        fresh(what, async p => {
          try {
            const out = await send(p);
            status('Saved.');
            if (done) done(out);
          } catch (e) { status(e.message, true); }
        });
      }, 'btn-primary');
      where.appendChild(el('div', { 'data-ssh-fresh': '' }, el('p', { class: 'public-warn', text: 'This change needs a fresh sign-in.' }), b));
    }
  }

  // ── the shown-once enrolment code ──────────────────────────
  function showCode(id, codeText) {
    const ta = el('textarea', { rows: 3, readOnly: true, 'data-ssh-code': '', 'aria-label': 'Enrolment code for ' + id, spellcheck: 'false', autocomplete: 'off' });
    ta.value = codeText;
    const box = el('div', { class: 'public-warn', 'data-ssh-code-box': '' },
      el('p', null, 'Enrolment code for ', code(id), ' — shown once, valid for a short time. Save it on the host as ', code('code.txt'), ' and run:'),
      el('pre', null, code('sudo portcullis host enroll < code.txt')),
      ta,
      el('div', null,
        btn('Copy', async () => {
          try { await navigator.clipboard.writeText(ta.value); status('Copied.'); } catch (_) { ta.select(); status('Select the code and copy it.', true); }
        }),
        ' ',
        btn('Done', () => { ta.value = ''; box.remove(); })));
    bodyBox.prepend(box);
    ta.focus();
    ta.select();
  }

  // ── Hosts ──────────────────────────────────────────────────
  async function renderHosts(box) {
    const [hv, gv] = await Promise.all([call('GET', API + '/hosts'), call('GET', API + '/hostgroups')]);
    hostGroups = gv.host_groups || [];
    const trustFor = {};
    for (const g of hostGroups) trustFor[g.id] = g.trust_command;
    const rows = (hv.hosts || []).map(hst => {
      const stateCell = hst.managed
        ? el('td', null, pill(hst.state === 'ok' ? 'ok' : hst.removed ? 'bad' : 'warn', hst.state || (hst.enrolled ? 'enrolled' : 'not enrolled')),
          (hst.findings || []).length ? pill('warn', hst.findings.length + ' findings') : null)
        : el('td', null, pill('', 'unmanaged'));
      const acts = el('td', null);
      put(acts, btn('Access', () => showAccess(box, 'hosts/' + enc(hst.id) + '/access', 'who can reach ' + hst.id)));
      if (hst.managed && !hst.removed) {
        put(acts, ' ', btn('New code', () => fresh('code', async p => {
          try { const a = await call('POST', API + '/hosts/' + enc(hst.id) + '/code', p); showCode(a.id, a.code); } catch (e) { status(e.message, true); }
        })));
        put(acts, ' ', btn('Remove account…', async () => {
          const name = (prompt('Remove which Portcullis account from ' + hst.id + '? (the host locks it, ends its sessions and removes it)') || '').trim();
          if (!name) return;
          try { await call('POST', API + '/hosts/' + enc(hst.id) + '/accounts/' + enc(name) + '/remove'); status('The host removes ' + name + ' at its next sync.'); } catch (e) { status(e.message, true); }
        }));
      }
      put(acts, ' ', btn('Remove host…', () => {
        if (!confirm('Remove ' + hst.id + '? A managed host removes its Portcullis accounts and files at its next sync.')) return;
        fresh('remove-host', async p => {
          try { await call('DELETE', API + '/hosts/' + enc(hst.id), p); status('Removed ' + hst.id + '.'); draw(); } catch (e) { status(e.message, true); }
        });
      }, 'btn-danger'));
      const detail = el('td', null, list(hst.names));
      if (!hst.managed) {
        for (const g of hst.host_groups || []) {
          if (trustFor[g]) put(detail, el('pre', { 'data-ssh-trust': g }, code(trustFor[g])));
        }
      }
      return el('tr', { 'data-ssh-host': hst.id },
        el('td', null, code(hst.id)), detail, el('td', { text: list(hst.host_groups) }), stateCell,
        el('td', { text: hst.managed ? when(hst.last_sync) : '—' }),
        el('td', { text: hst.managed ? hst.applied + ' / ' + hst.serial : '—' }),
        el('td', { text: when(hst.host_cert_until) }), acts);
    });
    put(box, rows.length ? table(['Host', 'Names', 'Host groups', 'State', 'Last sync', 'Bundle (applied / current)', 'Host certificate until', ''], rows)
      : el('p', { class: 'settings-empty', text: 'No hosts yet.' }));
    // Add a host.
    const id = el('input', { placeholder: 'web-1', 'data-ssh-new-host': '' });
    const names = el('input', { placeholder: 'web-1.example.com' });
    const addrs = el('input', { placeholder: '192.0.2.10 (optional)' });
    const groups = el('input', { placeholder: 'web' });
    const managed = el('input', { type: 'checkbox', checked: true });
    put(box, el('div', { class: 'inst-form' }, el('h4', { text: 'Add a host' }),
      field('Id', id), field('Names (comma separated)', names), field('Addresses (comma separated)', addrs),
      field('Host groups (comma separated)', groups),
      el('label', null, managed, ' Managed (enrolled with a one-time code; recommended)'),
      el('div', null, btn('Add host', () => {
        const body = { id: id.value.trim(), names: words(names.value), addrs: words(addrs.value), host_groups: words(groups.value), managed: managed.checked };
        fresh('host', async p => {
          try {
            const a = await call('POST', API + '/hosts', Object.assign(body, p));
            await draw();
            if (a && a.code) showCode(a.id, a.code);
            else status('Added ' + body.id + '. Set it up with the host group\'s host trust command.');
          } catch (e) { status(e.message, true); }
        });
      }, 'btn-primary'))));
  }

  // ── Host groups ────────────────────────────────────────────
  const HG_FIELDS = ['label', 'description', 'template', 'patterns', 'source_cidrs', 'vpn_only', 'vpn_via', 'delegable', 'create_shared'];
  function hgBody(g) {
    const b = {};
    for (const k of HG_FIELDS) if (g[k] !== undefined) b[k] = g[k];
    b.host_certs = g.host_certs !== false;
    return b;
  }
  async function renderHostGroups(box) {
    const gv = await call('GET', API + '/hostgroups');
    hostGroups = gv.host_groups || [];
    const form = el('div', { class: 'inst-form', 'data-ssh-hg-form': '' });
    const rows = hostGroups.map(g => el('tr', { 'data-ssh-hg': g.id },
      el('td', null, code(g.id), g.builtin ? pill('info', 'built-in') : null),
      el('td', { text: g.label || '' }),
      el('td', { text: list(g.hosts) + (g.patterns && g.patterns.length ? ' · ' + list(g.patterns) : '') }),
      el('td', { text: list(g.source_cidrs) + (g.vpn_only ? ' (VPN only)' : '') }),
      el('td', null, g.host_certs ? pill('ok', 'host certs') : pill('', 'no host certs'), g.delegable ? pill('info', 'delegable') : null, g.create_shared ? pill('info', 'shared accounts') : null),
      el('td', { text: String(g.grants) }),
      el('td', null, g.trust_command ? el('pre', null, code(g.trust_command)) : null,
        (g.hints || []).length ? el('small', { text: 'accounts: ' + list(g.hints) }) : null),
      el('td', null, btn('Access', () => showAccess(box, 'hostgroups/' + enc(g.id) + '/access', 'who can reach ' + g.id)), ' ',
        btn('Edit', () => editHostGroup(form, g)),
        g.builtin ? null : [' ', btn('Delete', async () => {
          if (!confirm('Delete host group ' + g.id + '? Refused while grants or hosts use it.')) return;
          try { await call('DELETE', API + '/hostgroups/' + enc(g.id)); draw(); } catch (e) { status(e.message, true); }
        }, 'btn-danger')])));
    put(box, table(['Host group', 'Label', 'Hosts and patterns', 'source-address', 'Options', 'Grants', 'Unmanaged hosts: run', ''], rows));
    put(box, btn('New host group', () => editHostGroup(form, null), 'btn-primary'), form);
  }
  function editHostGroup(form, g) {
    const isNew = !g;
    g = g || { host_certs: true };
    const id = el('input', { value: g.id || '', readOnly: !isNew, placeholder: 'web' });
    const label = el('input', { value: g.label || '' });
    const desc = el('input', { value: g.description || '' });
    const patterns = el('input', { value: list(g.patterns), placeholder: '*.lab.example.com' });
    const cidrs = el('input', { value: list(g.source_cidrs), placeholder: '192.0.2.0/24' });
    const vpn = el('input', { type: 'checkbox', checked: g.vpn_only });
    const hc = el('input', { type: 'checkbox', checked: g.host_certs !== false });
    const del = el('input', { type: 'checkbox', checked: g.delegable });
    const shared = el('input', { type: 'checkbox', checked: g.create_shared });
    const out = el('div');
    replaceKids(form, el('h4', { text: isNew ? 'New host group' : 'Edit ' + g.id }),
      field('Id', id), field('Label', label), field('Description', desc),
      field('Unmanaged host name patterns (comma separated)', patterns),
      field('source-address: only from these networks (comma separated, at most 16)', cidrs),
      el('label', null, vpn, ' Only through the Portcullis VPN'), el('br'),
      el('label', null, hc, ' Host certificates (people\'s known_hosts trust the host CA)'), el('br'),
      el('label', null, del, ' Delegable (ssh_access holders may grant on it)'), el('br'),
      el('label', null, shared, ' Create shared accounts on managed hosts'),
      el('div', null, btn('Save', () => {
        const body = Object.assign(hgBody(g), { label: label.value.trim(), description: desc.value.trim(), patterns: words(patterns.value), source_cidrs: words(cidrs.value), vpn_only: vpn.checked, host_certs: hc.checked, delegable: del.checked, create_shared: shared.checked });
        if (isNew) body.id = id.value.trim();
        write('hostgroup', p => call(isNew ? 'POST' : 'PUT', API + '/hostgroups' + (isNew ? '' : '/' + enc(g.id)), Object.assign({}, body, p || {})), () => draw(), out);
      }, 'btn-primary'), ' ', btn('Cancel', () => replaceKids(form))), out);
  }

  // ── Grants ─────────────────────────────────────────────────
  // looksPrivileged: what the Hub calls privileged (sudo, root,
  // forwarding): the typed group name and a fresh sign-in come first.
  function looksPrivileged(g) {
    return g.sudo === 'full' || (g.accounts || []).includes('root') || !!g.port_forwarding || !!g.agent_forwarding;
  }
  async function renderGrants(box) {
    const [gv, hv] = await Promise.all([call('GET', API + '/grants'), call('GET', API + '/hostgroups')]);
    hostGroups = hv.host_groups || [];
    const form = el('div', { class: 'inst-form', 'data-ssh-grant-form': '' });
    const rows = (gv.grants || []).map(g => el('tr', { 'data-ssh-grant': g.id },
      el('td', null, code(g.group)), el('td', null, code(g.host_group)),
      el('td', { text: (g.accounts || []).map(a => a === '{username}' ? 'own account' : a).join(', ') }),
      el('td', { text: g.sudo === 'full' ? 'sudo' : '—' }),
      el('td', { text: g.effective_ttl_hours + ' h' }),
      el('td', { text: [g.port_forwarding ? 'ports' : '', g.agent_forwarding ? 'agent' : ''].filter(Boolean).join(', ') || '—' }),
      el('td', null, g.privileged ? pill('warn', 'privileged') : null, g.why ? el('small', { text: ' ' + g.why }) : null),
      el('td', null, btn('Edit', () => editGrant(form, g, API + '/grants', true)), ' ',
        btn('Delete', async () => {
          if (!confirm('Delete this grant? Its certificates stop working when they expire; revoke them under Certificates to end them now.')) return;
          try { await call('DELETE', API + '/grants/' + enc(g.id)); draw(); } catch (e) { status(e.message, true); }
        }, 'btn-danger'))));
    put(box, rows.length ? table(['Group', 'Host group', 'Accounts', 'sudo', 'Certificate lifetime', 'Forwarding', '', ''], rows)
      : el('p', { class: 'settings-empty', text: 'No grants yet.' }));
    put(box, btn('New grant', () => editGrant(form, null, API + '/grants', true), 'btn-primary'), form);
  }
  // editGrant: the grant form. admin: the privileged options (full sudo,
  // forwarding) are offered (myssh.js has the delegates' own form).
  function editGrant(form, g, base, admin, groupsList) {
    const isNew = !g;
    g = g || { accounts: ['{username}'], sudo: 'none' };
    const hgs = groupsList || hostGroups;
    const group = el('input', { value: g.group || '', placeholder: 'an LLDAP group' });
    const hg = el('select', null, hgs.map(x => el('option', { value: x.id, selected: x.id === g.host_group, text: x.id + (x.label ? ' — ' + x.label : '') })));
    const own = el('input', { type: 'checkbox', checked: (g.accounts || []).includes('{username}') });
    const shared = el('input', { value: (g.accounts || []).filter(a => a !== '{username}').join(', '), placeholder: 'deploy' });
    const sudo = el('select', null, el('option', { value: 'none', text: 'no sudo', selected: g.sudo !== 'full' }), admin ? el('option', { value: 'full', text: 'full sudo', selected: g.sudo === 'full' }) : null);
    const ttl = el('input', { type: 'number', min: 0, max: 12, value: g.ttl_hours || 0 });
    const pf = el('input', { type: 'checkbox', checked: g.port_forwarding });
    const af = el('input', { type: 'checkbox', checked: g.agent_forwarding });
    const typed = el('input', { placeholder: 'the group\'s name, again', 'data-ssh-confirm': '', autocomplete: 'off' });
    const typedRow = field('Privileged grant: type the group\'s name again to confirm', typed);
    const preview = el('div', { 'data-ssh-preview': '' });
    const out = el('div');
    function body() {
      const accounts = (own.checked ? ['{username}'] : []).concat(words(shared.value));
      const b = { group: group.value.trim(), host_group: hg.value, accounts, sudo: sudo.value, ttl_hours: Number(ttl.value) || 0 };
      if (admin) { b.port_forwarding = pf.checked; b.agent_forwarding = af.checked; }
      if (!isNew) b.id = g.id;
      return b;
    }
    function sync() { typedRow.hidden = !admin || !looksPrivileged(body()); }
    replaceKids(form, el('h4', { text: isNew ? 'New grant' : 'Edit grant ' + g.id }),
      field('Group', group), field('Host group', hg),
      el('label', null, own, ' Each member\'s own account'),
      field('Shared accounts (comma separated)', shared), field('sudo', sudo),
      field('Certificate lifetime in hours (1–12; 0 = the default)', ttl),
      admin ? [el('label', null, pf, ' Port forwarding'), el('br'), el('label', null, af, ' Agent forwarding')] : null,
      typedRow,
      el('div', null,
        btn('Preview', async () => {
          try {
            const v = await call('POST', base + '/preview', body());
            replaceKids(preview, el('h4', { text: 'Who could reach what with this grant' }), accessTable(v.rows));
          } catch (e) { status(e.message, true); }
        }), ' ',
        btn('Save', () => {
          const b = body();
          const path = base + (isNew ? '' : '/' + enc(g.id));
          const method = isNew ? 'POST' : 'PUT';
          const done = () => { replaceKids(form); draw(); };
          if (admin && looksPrivileged(b)) {
            if (typed.value.trim() !== b.group) { status('Type the group\'s name (' + b.group + ') again to confirm a privileged grant.', true); typed.focus(); return; }
            fresh('grant', async p => {
              try { await call(method, path, Object.assign(b, { confirm: typed.value.trim() }, p)); status('Saved.'); done(); } catch (e) { status(e.message, true); }
            });
            return;
          }
          write('grant', p => call(method, path, Object.assign({}, b, p || {})), done, out);
        }, 'btn-primary'), ' ',
        btn('Cancel', () => replaceKids(form))),
      out, preview);
    for (const n of [sudo, shared, pf, af]) n.addEventListener('change', sync);
    shared.addEventListener('input', sync);
    sync();
  }

  // ── Access preview ─────────────────────────────────────────
  function accessTable(rows) {
    rows = rows || [];
    if (!rows.length) return el('p', { class: 'settings-empty', text: 'Nobody.' });
    return table(['Person', 'Account', 'Host', 'root', 'sudo', 'Via', 'Until', 'Status'], rows.map(r => el('tr', null,
      el('td', { text: r.person }), el('td', null, code(r.account)), el('td', { text: r.host || '—' }),
      el('td', { text: r.root ? 'yes' : '' }), el('td', { text: r.sudo ? 'yes' : '' }),
      el('td', { text: list(r.via) }), el('td', { text: when(r.until) }),
      el('td', null, r.status === 'ok' ? pill('ok', 'ok') : pill('warn', r.status)))));
  }
  async function showAccess(box, path, title) {
    const out = el('div', { 'data-ssh-access': '' }, el('p', { class: 'settings-empty', text: 'Loading…' }));
    box.prepend(out);
    try {
      const v = await call('GET', API + '/' + path);
      replaceKids(out, el('h4', null, title, ' ', btn('Close', () => out.remove())), accessTable(v.rows));
    } catch (e) { replaceKids(out, el('p', { class: 'public-warn', text: e.message })); }
  }
  async function renderAccess(box) {
    const gv = await call('GET', API + '/hostgroups');
    hostGroups = gv.host_groups || [];
    const kind = el('select', null, el('option', { value: 'hostgroups', text: 'Host group' }), el('option', { value: 'hosts', text: 'Host' }), el('option', { value: 'people', text: 'Person' }));
    const id = el('input', { placeholder: 'web, web-1 or a username', list: 'ssh-hg-list' });
    const rootOnly = el('input', { type: 'checkbox' });
    const out = el('div');
    put(box, el('datalist', { id: 'ssh-hg-list' }, hostGroups.map(g => el('option', { value: g.id }))),
      el('div', { class: 'inst-form' }, field('Who can reach', kind), field('Name', id),
        el('label', null, rootOnly, ' Only as root (or with sudo)'),
        el('div', null, btn('Show', async () => {
          const name = id.value.trim();
          if (!name) return;
          try {
            const v = await call('GET', API + '/' + kind.value + '/' + enc(name) + '/access' + (rootOnly.checked ? '?root=1' : ''));
            replaceKids(out, accessTable(v.rows));
          } catch (e) { replaceKids(out, el('p', { class: 'public-warn', text: e.message })); }
        }, 'btn-primary'))), out);
  }

  // ── Certificates ───────────────────────────────────────────
  async function renderCerts(box, user) {
    const v = await call('GET', API + '/certificates' + (user ? '?user=' + enc(user) : ''));
    const who = el('input', { value: user || '', placeholder: 'a username (empty: everyone)' });
    put(box, el('div', { class: 'inst-form' }, field('Person', who),
      el('div', null, btn('Show', () => { replaceKids(bodyBox); renderCerts(bodyBox, who.value.trim()).catch(e => status(e.message, true)); }), ' ',
        btn('Revoke all of this person\'s certificates', async () => {
          const u = who.value.trim();
          if (!u) { status('Name the person.', true); return; }
          if (!confirm('Revoke every unexpired SSH certificate of ' + u + '?')) return;
          try { const a = await call('POST', API + '/certificates/revoke', { user: u }); status('Revoked ' + a.revoked + '.'); draw(); } catch (e) { status(e.message, true); }
        }, 'btn-danger'))));
    if ((v.incomplete || []).length) {
      put(box, el('p', { class: 'public-warn', 'data-ssh-incomplete': '' }, 'Revocation incomplete (key unknown): ' + v.incomplete.join(', ')));
    }
    const picks = [];
    const rows = (v.issued || []).map(c => {
      const cb = el('input', { type: 'checkbox', 'aria-label': 'Select ' + c.key_fp });
      picks.push([cb, c.key_fp]);
      return el('tr', null, el('td', null, cb), el('td', { text: when(c.time) }), el('td', { text: c.user }), el('td', null, code(c.host_group)),
        el('td', null, code(c.key_fp)), el('td', { text: list(c.principals) }), el('td', { text: when(c.valid_before) }),
        el('td', { text: c.flow + (c.own ? ' (own key)' : '') }), el('td', { text: c.addr }));
    });
    put(box, el('h4', { text: 'Issued' }), rows.length ? table(['', 'Issued', 'Person', 'Host group', 'Key', 'Principals', 'Valid until', 'How', 'From'], rows) : el('p', { class: 'settings-empty', text: 'None.' }),
      rows.length ? btn('Revoke selected', async () => {
        const fps = [...new Set(picks.filter(([cb]) => cb.checked).map(([, fp]) => fp))];
        if (!fps.length) return;
        if (!confirm('Revoke ' + fps.length + ' key(s)? Hosts refuse them from their next sync.')) return;
        try { const a = await call('POST', API + '/certificates/revoke', { fingerprints: fps }); status('Revoked ' + a.revoked + '.'); draw(); } catch (e) { status(e.message, true); }
      }, 'btn-danger') : null);
    const rv = (v.revoked || []).map(r => el('tr', null, el('td', null, code(r.fp)), el('td', { text: r.reason }), el('td', { text: r.actor }),
      el('td', { text: when(r.added) }), el('td', { text: r.until ? when(r.until) : 'never ends' }), el('td', null, r.no_key ? pill('warn', 'key unknown') : null,
        // RR-M5: an administrator takes a key off the list: the fingerprint
        // typed again, a fresh sign-in (no MCP twin).
        ' ', btn('Un-revoke…', () => {
          const typed = prompt('Type the key\'s fingerprint to take it off the revoked list:\n' + r.fp);
          if (typed === null) return;
          if (typed !== r.fp) { status('The fingerprint doesn\'t match.', true); return; }
          fresh('unrevoke', async p => {
            try { await call('POST', API + '/certificates/unrevoke', Object.assign({ fingerprint: r.fp, confirm: typed }, p)); status('Taken off the revoked list.'); draw(); } catch (e) { status(e.message, true); }
          });
        }))));
    put(box, el('h4', { text: 'Revoked keys' }), rv.length ? table(['Key', 'Why', 'By', 'Added', 'Listed until', ''], rv) : el('p', { class: 'settings-empty', text: 'None.' }));
    // Sign a host key.
    if (!hostGroups.length) hostGroups = ((await call('GET', API + '/hostgroups')).host_groups) || [];
    const hg = el('select', null, hostGroups.map(g => el('option', { value: g.id, text: g.id })));
    const pub = el('input', { placeholder: 'ssh-ed25519 AAAA… (the host\'s /etc/ssh/ssh_host_ed25519_key.pub)' });
    const names = el('input', { placeholder: 'web-1.example.com' });
    const out = el('div');
    put(box, el('div', { class: 'inst-form' }, el('h4', { text: 'Sign a host key' }), field('Host group', hg), field('Public key', pub), field('Names (comma separated)', names),
      el('div', null, btn('Sign a host key', () => {
        const body = { host_group: hg.value, public_key: pub.value.trim(), names: words(names.value) };
        fresh('host-key', async p => {
          try {
            const a = await call('POST', API + '/host-certificates', Object.assign(body, p));
            const ta = el('textarea', { rows: 4, readOnly: true });
            ta.value = a.certificate;
            replaceKids(out, el('p', null, 'Valid until ' + when(a.valid_before) + '. Save it as ', code('/etc/ssh/ssh_host_ed25519_key-cert.pub'), ' and add ', code('HostCertificate'), ' to sshd.'), ta);
          } catch (e) { status(e.message, true); }
        });
      }, 'btn-primary')), out));
  }

  // ── Settings ───────────────────────────────────────────────
  function renderSettings(box) {
    const v = view;
    const on = el('input', { type: 'checkbox', checked: v.enabled, 'data-ssh-enabled': '' });
    const ttl = el('select', null, Array.from({ length: 12 }, (_, i) => el('option', { value: i + 1, text: (i + 1) + ' h', selected: (v.default_ttl_hours || 8) === i + 1 })));
    const out = el('div');
    put(box, el('div', { class: 'inst-form' },
      el('label', null, on, ' SSH access is on'),
      field('Default certificate lifetime', ttl),
      el('div', null, btn('Save', () => {
        const b = { enabled: on.checked, default_ttl_hours: Number(ttl.value) };
        write('settings', p => call('PUT', API + '/settings', Object.assign({}, b, p || {})), nv => { if (nv) view = nv; draw(); }, out);
      }, 'btn-primary')), out),
    el('dl', { class: 'inst-facts' },
      el('dt', { text: 'User CA' }), el('dd', null, v.user_ca_fp ? code(v.user_ca_fp) : '—'),
      el('dt', { text: 'Host CA' }), el('dd', null, v.host_ca_fp ? code(v.host_ca_fp) : '—'),
      el('dt', { text: 'CLI sign-in client' }), el('dd', null, v.cli_client_ready ? pill('ok', 'ready') : pill('warn', 'not ready'))),
    (v.user_cas || []).length ? el('div', null, el('h4', { text: 'User CA public keys (for TrustedUserCAKeys)' }), v.user_cas.map(k => el('pre', null, code(k)))) : null,
    (v.host_cas || []).length ? el('div', null, el('h4', { text: 'Host CA public keys (for @cert-authority)' }), v.host_cas.map(k => el('pre', null, code(k)))) : null);
  }

  // ── the tab ────────────────────────────────────────────────
  const RENDER = { hosts: renderHosts, hostgroups: renderHostGroups, grants: renderGrants, access: renderAccess, certs: b => renderCerts(b, ''), settings: renderSettings };

  async function draw() {
    if (!root) return;
    try {
      view = await call('GET', API + '/settings');
    } catch (e) {
      replaceKids(root, el('p', { class: 'public-warn', text: e.message }));
      return;
    }
    if (!view.enabled) current = 'settings';
    const nav = el('div', { class: 'ssh-sections', role: 'tablist' }, SECTIONS.map(([id, label]) => el('button', {
      type: 'button', role: 'tab', class: 'btn btn-sm' + (id === current ? ' btn-primary' : ''), 'aria-selected': id === current ? 'true' : 'false',
      'data-ssh-section': id, text: label, disabled: !view.enabled && id !== 'settings',
      on: { click: () => { current = id; draw(); } },
    })));
    statusBox = el('p', { class: 'settings-empty', role: 'status', 'aria-live': 'polite' });
    bodyBox = el('div', { 'data-ssh-body': current });
    const problems = (view.problems || []).map(p => el('p', { class: 'public-warn', text: p }));
    replaceKids(root, nav, problems, statusBox, bodyBox);
    if (!view.enabled) put(bodyBox, el('p', { class: 'settings-empty', text: 'SSH access is off. Switch it on to sign SSH certificates for people\'s host groups (a fresh sign-in is asked).' }));
    try { await RENDER[current](bodyBox); } catch (e) { status(e.message, true); }
  }

  function render(el0) {
    root = el0;
    draw();
  }

  window.PortcullisSSH = { render, _test: { looksPrivileged, hgBody, el } };
})();
