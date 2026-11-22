// Portcullis Hub — Settings → Servers and the instance page's server
// parts (contract §17.3, Task 12). Hub listener only, administrators only.
//
//   window.PortcullisServers.render(root)          Settings → Servers into root
//   window.PortcullisServers.runsOn(inst)          the instance's "Runs on" line (HTML)
//   window.PortcullisServers.serverSelect(sel)     the setup form's server <select> (HTML)
//   window.PortcullisServers.instanceSection(inst) Move… / Undo move / old copy (HTML)
//   window.PortcullisServers.wire(root, inst, done) its buttons
//   (pure, node tests) listHtml(page), codeDialogHtml(code, expiresAt, node),
//   openCodeDialog(doc, code, expiresAt, clipboard, node), addBody(form, kind),
//   stepsHtml(rec)
//
// On Kubernetes (page.add_kind "cluster-node", contract §20.1) Add server
// adds a cluster node: role, class, site, ingress, storage; the dialog
// shows the one-liner (curl … | sudo sh, which asks for the code: never on
// its command line), the code, the cluster-admin sentence for a server
// and the enrolment's progress. Docker workers aren't offered there.
//
// GET    /api/servers                     {servers, fresh_auth}
// GET    /api/servers/{id}                one server (+ Local networks, schedule)
// POST   /api/servers †                   {id, name, proof} → {code, expires_at, op_id, poll}
//                                          + kind cluster-node: {role?, class?, site?, ingress?, storage?, public_endpoint?}
//                                          → + {role, class, site, warnings, notice, command}
// GET    /api/servers/{id}/op             the enrolment op
// POST   /api/servers/{id}/op/stop        stop the enrolment
// PUT    /api/servers/{id}/settings       {name, local_networks, backup_schedule}
// PUT    /api/servers/primary/settings    {backup_schedule}
// POST   /api/servers/{id}/revoke †       {confirm, proof}
// DELETE /api/servers/{id} †              {confirm, proof}
// POST   /api/instances/{id}/move         {server}
// POST   /api/instances/{id}/move/undo †  {confirm, proof}
// DELETE /api/instances/{id}/move-leftover † {confirm, proof}
// POST   /api/instances/{id}/quarantine/lift † {proof}
// DELETE /api/instances/{id}?forget=1       {confirm} (an orphaned instance; not †)
//
// † = a fresh sign-in first (PortcullisFreshAuth, started from the click).
//
// Rules: every value goes through esc. Typed confirmations are inline
// rows (confirm.js's pattern), never a prompt or confirm dialog: their Confirm
// click opens the fresh sign-in popup directly, so no browser blocks it. The join code is shown once, in a
// dialog built for it: it is never put in storage, never in the page
// outside that dialog, and closing the dialog drops the dialog's markup
// and the only reference to the code (Copy reads that reference).
(function () {
  'use strict';

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
  const enc = encodeURIComponent;
  const UNDO_DAYS = 7;
  const WEEKDAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];

  let page = null; // the last GET /api/servers: {servers, fresh_auth}

  function bytes(n) {
    n = Number(n) || 0;
    if (n < 1000) return n + ' B';
    const u = 'kMGTPE';
    let i = -1;
    while (n >= 1000 && i < u.length - 1) { n /= 1000; i++; }
    return n.toFixed(1) + ' ' + u[i] + 'B';
  }
  function when(t) {
    if (!t) return '—';
    const d = new Date(t);
    return isNaN(d) ? '—' : d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
  }
  function pill(cls, t) { return '<span class="pill ' + cls + '">' + esc(t) + '</span>'; }
  function statePill(s) {
    return s === 'ready' ? pill('ok', 'ready') : s === 'offline' ? pill('warn', 'offline') : s === 'enrolling' ? pill('info', 'enrolling') :
      s === 'removing' ? pill('info', 'removing') : pill('', s);
  }
  function clusterMode(p) { return !!(p && p.add_kind === 'cluster-node'); }
  // The cluster-admin sentence (contract §20.1, spec §6.2).
  const SERVER_NOTICE = 'Joining as a server gives this machine full control of the cluster (cluster-admin).';
  function serverName(id) {
    if (!id || id === 'primary') return 'the primary';
    const s = page && (page.servers || []).find(x => x.id === id);
    return s ? s.name : id;
  }
  function scheduleText(b) {
    if (!b || b.mode === 'off' || !b.mode) return 'off';
    const hh = String(b.hour).padStart(2, '0') + ':00';
    return b.mode === 'daily' ? 'daily at ' + hh : 'weekly on ' + (WEEKDAYS[b.weekday] || '?') + ' at ' + hh;
  }

  // listHtml is the Servers panel for GET /api/servers.
  function listHtml(p) {
    const list = (p && p.servers) || [];
    let h = '<table class="inst-table" data-servers><thead><tr><th>Server</th><th>State</th><th>Engine</th><th>CPUs · memory</th>' +
      '<th>Disk free</th><th>Data free</th><th>Instances</th><th>Last contact</th><th>Agent</th><th>Certificate until</th><th></th></tr></thead><tbody>';
    for (const s of list) {
      const prim = s.id === 'primary';
      h += '<tr data-server="' + esc(s.id) + '"><td><strong>' + esc(s.name) + '</strong> <code>' + esc(s.id) + '</code>' +
        (s.error ? '<br><small class="public-warn">' + esc(s.error) + '</small>' : '') + '</td>' +
        '<td>' + statePill(s.state) + '</td>' +
        '<td>' + (s.kind === 'cluster-node'
          ? esc(s.role || '—') + ' · ' + esc(s.class || '—') + ' · ' + esc(s.site || 'main') + (s.ingress ? ' · ingress' : '') + (s.storage ? ' · storage' : '')
          : esc(s.runtime || '—') + (s.rootless ? ' (rootless)' : '') + (s.arch ? ' · ' + esc(s.arch) : '')) + '</td>' +
        '<td>' + (s.cpus ? esc(s.cpus) + ' · ' + esc(bytes(s.mem_bytes)) : '—') + '</td>' +
        '<td>' + (s.disk_total ? esc(bytes(s.disk_free)) + ' of ' + esc(bytes(s.disk_total)) : '—') + '</td>' +
        '<td>' + (s.data_total ? esc(bytes(s.data_free)) + ' of ' + esc(bytes(s.data_total)) : '—') + '</td>' +
        '<td>' + esc((s.instances || []).length) + '</td>' +
        '<td>' + (prim ? '—' : esc(when(s.last_contact))) + '</td>' +
        '<td>' + esc(s.agent_version || '—') + '</td>' +
        '<td>' + (prim ? '—' : esc(when(s.cert_not_after))) + '</td>' +
        '<td><button type="button" class="btn btn-sm" data-srv-act="details">Settings</button>' +
        (prim ? '' : (s.state === 'enrolling' ? ' <button type="button" class="btn btn-sm" data-srv-act="stop-enrol">Stop enrolment</button>' : '') +
          (s.state !== 'revoked' ? ' <button type="button" class="btn btn-sm btn-danger" data-srv-act="revoke">Revoke…</button>' : '') +
          ' <button type="button" class="btn btn-sm btn-danger" data-srv-act="remove">Remove…</button>') +
        '</td></tr><tr data-server-detail="' + esc(s.id) + '" hidden><td colspan="11"></td></tr>';
    }
    h += '</tbody></table>';
    if (clusterMode(p)) return h + clusterAddHtml(siteNames(p));
    h += '<div class="inst-form" data-srv-add><label class="block" for="srv-add-id">Add a server</label>' +
      '<div class="inst-row" style="margin-top:0"><input id="srv-add-id" data-srv-add-id placeholder="id (e.g. nas)" maxlength="32" spellcheck="false">' +
      '<input data-srv-add-name placeholder="name (e.g. Attic NAS)" maxlength="64">' +
      '<button type="button" class="btn btn-primary btn-sm" data-srv-act="add">+ Add server…</button></div>' +
      '<small>Needs a fresh sign-in. You get a one-time join code for <code>./portcullis worker join</code> on the new server; it expires in 15 minutes.</small></div>';
    return h;
  }

  // siteNames are the sites of the listed cluster nodes (main first),
  // offered in the add form's Site field.
  function siteNames(p) {
    const set = new Set(['main']);
    for (const s of (p && p.servers) || []) if (s.kind === 'cluster-node' && s.site) set.add(String(s.site));
    return ['main'].concat([...set].filter(n => n !== 'main').sort());
  }

  // clusterAddHtml is the Add server form on Kubernetes: a cluster node
  // (Docker workers can't join a Kubernetes cluster). "" = the Hub's
  // suggestion; sites are the existing ones offered (a new name starts a
  // site).
  function clusterAddHtml(sites) {
    const opt = (v, t) => '<option value="' + esc(v) + '">' + esc(t) + '</option>';
    return '<div class="inst-form" data-srv-add data-srv-kind="cluster-node"><label class="block" for="srv-add-id">Add a cluster node</label>' +
      '<div class="inst-row" style="margin-top:0"><input id="srv-add-id" data-srv-add-id placeholder="id (e.g. n4)" maxlength="31" spellcheck="false">' +
      '<input data-srv-add-name placeholder="name (e.g. Attic NUC)" maxlength="64"></div>' +
      '<div class="inst-row"><label>Role <select data-srv-add-role>' + opt('', 'suggested') + opt('server', 'server') + opt('agent', 'agent') + '</select></label>' +
      ' <label>Class <select data-srv-add-class>' + opt('', 'home (default)') + opt('home', 'home') + opt('cloud', 'cloud') + opt('small', 'small') + '</select></label>' +
      ' <label>Site <input data-srv-add-site list="srv-add-sites" placeholder="main" maxlength="31" spellcheck="false" style="width:8em"></label>' +
      '<datalist id="srv-add-sites" data-srv-sites>' + (sites || ['main']).map(n => '<option value="' + esc(n) + '">').join('') + '</datalist>' +
      ' <label>Ingress <select data-srv-add-ingress>' + opt('', 'default') + opt('true', 'yes') + opt('false', 'no') + '</select></label>' +
      ' <label>Storage <select data-srv-add-storage>' + opt('', 'default') + opt('true', 'yes') + opt('false', 'no') + '</select></label></div>' +
      '<div class="inst-row"><label>Forwarded endpoint <input data-srv-add-public placeholder="optional, e.g. 203.0.113.7:51830" maxlength="21" spellcheck="false" style="width:14em"></label>' +
      ' <small>Behind NAT, the first node of a site needs one: the router\'s public address and the UDP port it forwards to this node\'s UDP 51830.</small></div>' +
      '<p class="public-warn" data-srv-server-notice><small>' + esc(SERVER_NOTICE) + ' The Hub suggests a server while the cluster has fewer than 3 healthy servers, at most 5, spread so no site holds a majority of them; storage nodes must be at the primary site (main) in this version.</small></p>' +
      '<div class="inst-row"><button type="button" class="btn btn-primary btn-sm" data-srv-act="add">+ Add node…</button></div>' +
      '<small>Needs a fresh sign-in. You get a one-line command to run on the new machine and a one-time join code it asks for; the code expires in 15 minutes. Docker workers can\'t join a Kubernetes cluster.</small></div>';
  }

  // addBody is the add request of the form f (without the proof).
  function addBody(f, kind) {
    const v = q => { const e = f.querySelector(q); return e ? String(e.value).trim() : ''; };
    const body = { id: v('[data-srv-add-id]'), name: v('[data-srv-add-name]') };
    if (kind !== 'cluster-node') return body;
    body.kind = 'cluster-node';
    for (const [k, q] of [['role', '[data-srv-add-role]'], ['class', '[data-srv-add-class]'], ['site', '[data-srv-add-site]'], ['public_endpoint', '[data-srv-add-public]']]) {
      if (v(q)) body[k] = v(q);
    }
    for (const [k, q] of [['ingress', '[data-srv-add-ingress]'], ['storage', '[data-srv-add-storage]']]) {
      if (v(q)) body[k] = v(q) === 'true';
    }
    return body;
  }

  // stepsHtml is an op record's steps (the enrolment's progress panel).
  function stepsHtml(rec) {
    if (!rec || !rec.steps) return '';
    const mark = st => st === 'done' ? '✓' : st === 'running' ? '…' : st === 'failed' ? '✗' : st === 'stopped' || st === 'undone' ? '–' : '·';
    return '<ol class="op-steps">' + rec.steps.map(s => '<li data-step="' + esc(s.key) + '" data-state="' + esc(s.state) + '">' + mark(s.state) + ' ' + esc(s.label) +
      (s.detail ? ' <small>' + esc(s.detail) + '</small>' : '') + '</li>').join('') + '</ol>' +
      (!rec.running ? (rec.ok ? '<p>' + pill('ok', 'done') + '</p>' : '<p class="public-warn">' + esc(rec.error || 'stopped') + '</p>') : '');
  }

  // detailHtml is one server's settings form (GET /api/servers/{id}).
  function detailHtml(d) {
    if (d.kind === 'cluster-node') {
      // A cluster node: its name only (no Local networks or backups).
      return '<div class="inst-form" data-srv-settings="' + esc(d.id) + '" data-srv-cluster><label class="block">Name</label><input data-srv-name value="' + esc(d.name) + '" maxlength="64">' +
        '<p><small>' + esc(d.role || '') + ' · ' + esc(d.class || '') + ' · site ' + esc(d.site || 'main') + (d.mesh_ip ? ' · mesh ' + esc(d.mesh_ip) : '') + '</small></p>' +
        '<div class="inst-row"><button type="button" class="btn btn-primary btn-sm" data-srv-act="save">Save</button></div></div>';
    }
    const prim = d.id === 'primary';
    const b = d.backup_schedule || { mode: 'off', hour: 0, weekday: 0 };
    let h = '<div class="inst-form" data-srv-settings="' + esc(d.id) + '">';
    if (!prim) {
      h += '<label class="block">Name</label><input data-srv-name value="' + esc(d.name) + '" maxlength="64">' +
        '<label class="block">Local networks (one CIDR per line)' + (d.local_networks_default ? ' — the defaults' : '') + '</label>' +
        '<textarea rows="4" data-srv-nets>' + esc((d.local_networks || []).join('\n')) + '</textarea>' +
        '<label><input type="checkbox" data-srv-nets-default' + (d.local_networks_default ? ' checked' : '') + '> Use the default list</label>' +
        '<p><small>Folder roots (set on the server: PORTCULLIS_WORKER_BIND_ROOTS): ' +
        ((d.bind_roots || []).map(r => '<code>' + esc(r) + '</code>').join(', ') || 'not reported yet') + '</small></p>';
    }
    h += '<label class="block">Scheduled backups</label><select data-srv-mode>' +
      ['off', 'daily', 'weekly'].map(m => '<option value="' + m + '"' + (b.mode === m ? ' selected' : '') + '>' + m + '</option>').join('') + '</select>' +
      ' at <input type="number" min="0" max="23" data-srv-hour value="' + esc(b.hour) + '" style="width:4em">:00' +
      ' on <select data-srv-weekday>' + WEEKDAYS.map((w, i) => '<option value="' + i + '"' + (b.weekday === i ? ' selected' : '') + '>' + w + '</option>').join('') + '</select>' +
      ' <small>(the weekday counts for weekly only; the Hub\'s time zone)</small>' +
      '<div class="inst-row"><button type="button" class="btn btn-primary btn-sm" data-srv-act="save">Save</button></div>' +
      (d.instances && d.instances.length ? '<p><small>Instances: ' + d.instances.map(i => '<code>' + esc(i) + '</code>').join(', ') + '</small></p>' : '') +
      '</div>';
    return h;
  }

  function readDetail(f, prim) {
    if (f.hasAttribute && f.hasAttribute('data-srv-cluster')) return { name: f.querySelector('[data-srv-name]').value };
    const mode = f.querySelector('[data-srv-mode]').value;
    const body = { backup_schedule: { mode, hour: parseInt(f.querySelector('[data-srv-hour]').value, 10), weekday: mode === 'weekly' ? parseInt(f.querySelector('[data-srv-weekday]').value, 10) : 0 } };
    if (!prim) {
      body.name = f.querySelector('[data-srv-name]').value;
      body.local_networks = f.querySelector('[data-srv-nets-default]').checked ? null
        : String(f.querySelector('[data-srv-nets]').value).split(/\n/).map(x => x.trim()).filter(Boolean);
    }
    return body;
  }

  // ── the join code dialog ─────────────────────────────

  // codeDialogHtml: node (a cluster node's answer: role, warnings, notice,
  // command) shows the one-liner and the progress panel instead of the
  // worker's command.
  function codeDialogHtml(code, expiresAt, node) {
    if (node && node.command) {
      return '<div class="opp-head"><h3 id="srv-code-title">Join code for a ' + esc(node.role || 'cluster') + ' node</h3></div>' +
        (node.notice ? '<p class="public-warn" data-srv-notice>' + esc(node.notice) + '</p>' : '') +
        ((node.warnings || []).length ? '<ul data-srv-warnings>' + node.warnings.map(w => '<li>' + esc(w) + '</li>').join('') + '</ul>' : '') +
        '<p>On the new machine, run:</p>' +
        '<pre data-srv-cmd><code>' + esc(node.command) + '</code></pre>' +
        '<p>and paste this code when the script asks (it is never put on the command line). It works once and expires at ' + esc(when(expiresAt)) +
        '. It is shown only here: closing this dialog forgets it.</p>' +
        '<pre data-srv-code><code>' + esc(code) + '</code></pre>' +
        '<div data-srv-progress></div>' +
        '<div class="op-modal-actions"><button type="button" class="btn btn-primary btn-sm" data-srv-code-act="copy">Copy code</button>' +
        ' <button type="button" class="btn btn-sm" data-srv-code-act="close">Close</button></div>';
    }
    return '<div class="opp-head"><h3 id="srv-code-title">Join code</h3></div>' +
      '<p>On the new server, in its Portcullis checkout, run:</p>' +
      '<pre data-srv-cmd><code>./portcullis worker join</code></pre>' +
      '<p>and paste this code when it asks. It works once and expires at ' + esc(when(expiresAt)) + '. It is shown only here: closing this dialog forgets it.</p>' +
      '<pre data-srv-code><code>' + esc(code) + '</code></pre>' +
      '<div class="op-modal-actions"><button type="button" class="btn btn-primary btn-sm" data-srv-code-act="copy">Copy code</button>' +
      ' <button type="button" class="btn btn-sm" data-srv-code-act="close">Close</button></div>';
  }

  // openCodeDialog shows code in a dialog of its own on doc; closing it
  // empties and removes the dialog and drops the code. clipboard: an
  // object with writeText (navigator.clipboard).
  function openCodeDialog(doc, code, expiresAt, clipboard, node) {
    let held = code;
    const d = doc.createElement('dialog');
    d.className = 'opp';
    d.setAttribute('aria-labelledby', 'srv-code-title');
    d.setAttribute('data-srv-code-dialog', '');
    d.innerHTML = codeDialogHtml(held, expiresAt, node);
    let closed = false;
    // The progress panel: the enrolment op polled while the dialog is
    // open (the record never holds the code).
    let timer = null;
    const poll = () => {
      if (closed || !node || !node.poll || !window.apiGet) return;
      window.apiGet(node.poll).then(rec => {
        if (closed) return;
        const el = d.querySelector && d.querySelector('[data-srv-progress]');
        if (el) el.innerHTML = stepsHtml(rec);
        if (rec && rec.running) timer = setTimeout(poll, 2000);
      }, () => { if (!closed) timer = setTimeout(poll, 5000); });
    };
    const close = () => {
      if (closed) return;
      closed = true;
      if (timer) clearTimeout(timer);
      held = null;
      d.innerHTML = '';
      if (d.open && d.close) d.close();
      d.remove();
    };
    d.addEventListener('click', e => {
      const t = e.target && e.target.closest ? e.target.closest('[data-srv-code-act]') : e.target;
      const a = t && t.getAttribute && t.getAttribute('data-srv-code-act');
      if (a === 'copy' && held && clipboard) {
        Promise.resolve(clipboard.writeText(held)).then(() => { if (window.showToast) window.showToast('Code copied.', 'success'); }, () => {});
      }
      if (a === 'close') close();
    });
    d.addEventListener('close', close);
    d.addEventListener('cancel', close);
    doc.body.appendChild(d);
    if (d.showModal) d.showModal();
    poll();
    return { close };
  }

  // ── fresh sign-in ─────────────────────────────────────

  // fresh runs the popup from the click (no await before it) and calls
  // send(proof) with {code, code_verifier, nonce}.
  function fresh(what, send) {
    const fa = page && page.fresh_auth;
    if (!fa || !window.PortcullisFreshAuth) { window.showToast('Fresh sign-in isn\'t available: try again in a moment.', 'error'); return; }
    window.PortcullisFreshAuth.start(fa, {
      ctx: { servers: what },
      status: (t, warn) => { if (warn) window.showToast(t, 'error'); },
      busy: () => {},
      end: () => {},
      proof: p => send({ code: p.code, code_verifier: p.code_verifier, nonce: p.nonce }),
    });
  }

  async function load() {
    page = await window.apiGet('/api/servers');
    return page;
  }

  async function render(root) {
    if (!root) return;
    try { await load(); } catch (e) { root.innerHTML = '<div class="public-warn">' + esc(e.message) + '</div>'; return; }
    root.innerHTML = listHtml(page);
    if (!root.dataset.srvWired) {
      root.dataset.srvWired = '1';
      root.addEventListener('click', e => act(root, e));
      confirmEvents(root, (action, typed, row) => {
        const tr = row.closest('[data-server]');
        if (tr) runListAction(root, action, tr.dataset.server, typed, row.querySelector('[data-srv-go]'));
      });
    }
  }

  function act(root, e) {
    const b = e.target.closest && e.target.closest('[data-srv-act]');
    if (!b || !root.contains(b) || b.dataset.busy) return;
    const row = b.closest('[data-server]');
    const id = row ? row.dataset.server : '';
    const fail = err => { delete b.dataset.busy; window.showToast(err.message || 'Failed', 'error'); };
    switch (b.dataset.srvAct) {
      case 'add': {
        const f = b.closest('[data-srv-add]');
        const kind = f.dataset && f.dataset.srvKind === 'cluster-node' ? 'cluster-node' : 'worker';
        const body = addBody(f, kind);
        if (!body.id) { window.showToast('Give the server an id.', 'error'); return; }
        fresh('add', async proof => {
          b.dataset.busy = '1';
          try {
            const res = await window.apiCall('/api/servers', 'POST', Object.assign(body, proof));
            const ans = await res.json();
            openCodeDialog(document, ans.code, ans.expires_at, navigator.clipboard, kind === 'cluster-node' ? ans : null);
            delete b.dataset.busy;
            render(root);
          } catch (err) { fail(err); }
        });
        return;
      }
      case 'details': {
        const tr = root.querySelector('[data-server-detail="' + CSS.escape(id) + '"]');
        if (!tr) return;
        if (!tr.hidden) { tr.hidden = true; return; }
        window.apiGet('/api/servers/' + enc(id)).then(d => { tr.firstChild.innerHTML = detailHtml(d); tr.hidden = false; }, fail);
        return;
      }
      case 'save': {
        const f = b.closest('[data-srv-settings]');
        const sid = f.dataset.srvSettings;
        b.dataset.busy = '1';
        window.apiPut('/api/servers/' + enc(sid) + '/settings', readDetail(f, sid === 'primary'))
          .then(() => { window.showToast('Saved.', 'success'); render(root); }, fail);
        return;
      }
      case 'stop-enrol':
        b.dataset.busy = '1';
        window.apiCall('/api/servers/' + enc(id) + '/op/stop', 'POST', {}).then(() => render(root), fail);
        return;
      case 'revoke':
      case 'remove': {
        // An inline typed-id row (confirm.js's pattern): its Confirm click
        // opens the fresh sign-in popup directly (no dialog before it).
        const verb = b.dataset.srvAct === 'revoke' ? 'Revoke' : 'Remove';
        const text = clusterMode(page)
          ? (verb === 'Revoke'
            ? 'Revoke node ' + serverName(id) + ' now (lost or stolen)? It is deleted from the cluster at once, its certificate and mesh peer revoked and the cluster\'s tokens rotated; nothing on the machine is cleaned up.'
            : 'Remove node ' + serverName(id) + '? It is cordoned and drained (disruption budgets respected; refused if a quorum would drop below its minimum), removed from the cluster, and k3s is uninstalled on it.')
          : verb + ' server ' + serverName(id) + '? ' + (verb === 'Revoke'
            ? 'It can\'t reach the Hub any more, its certificate is revoked and its instances are orphaned: restore each from a backup (it lands on this server; move it afterwards) or Forget it.'
            : 'Only a server without instances can be removed.');
        showConfirm(b, b.dataset.srvAct, id, text + ' Type its id to confirm:', verb);
        return;
      }
    }
  }

  // ── inline typed confirmations ───────────────────────

  // confirmHtml is an inline confirmation row: text, the typed field
  // (expect "" = none: a plain Confirm) and Confirm / Cancel. Confirm is
  // enabled once the field holds expect.
  function confirmHtml(action, expect, text, label) {
    return '<div class="inst-row" data-srv-confirm="' + esc(action) + '" data-srv-expect="' + esc(expect) + '">' +
      '<span>' + esc(text) + '</span>' +
      (expect ? ' <input data-srv-typed autocomplete="off" spellcheck="false" placeholder="' + esc(expect) + '" aria-label="Type ' + esc(expect) + ' to confirm">' : '') +
      ' <button type="button" class="btn btn-sm btn-danger" data-srv-go' + (expect ? ' disabled' : '') + '>' + esc(label || 'Confirm') + '</button>' +
      ' <button type="button" class="btn btn-sm" data-srv-cancel>Cancel</button></div>';
  }

  // showConfirm puts one confirmation row under the button b.
  function showConfirm(b, action, expect, text, label) {
    const host = b.closest('td, .inst-row, [data-srv-inst]') || b.parentNode;
    const old = host.querySelector('[data-srv-confirm]');
    if (old) old.remove();
    host.insertAdjacentHTML('beforeend', confirmHtml(action, expect, text, label));
    const inp = host.querySelector('[data-srv-confirm] [data-srv-typed]');
    if (inp) inp.focus();
  }

  // typedOf: the row's typed value when it matches (expect "" = ""), else
  // null.
  function typedOf(row) {
    const expect = row.dataset.srvExpect || '';
    const inp = row.querySelector('[data-srv-typed]');
    const typed = inp ? String(inp.value).trim() : '';
    return typed === expect ? typed : null;
  }

  // goConfirm runs a confirmation row's action from the click itself:
  // run(action, typed) opens the popup before anything else. false: the
  // typed id doesn't match (nothing runs).
  function goConfirm(row, run) {
    const typed = typedOf(row);
    if (typed === null) return false;
    run(row.dataset.srvConfirm, typed);
    return true;
  }

  // confirmEvents wires rows under root: typing enables Confirm, Cancel
  // drops the row, Confirm runs run(action, typed, row).
  function confirmEvents(root, run) {
    root.addEventListener('input', e => {
      const row = e.target.closest && e.target.closest('[data-srv-confirm]');
      if (!row) return;
      const go = row.querySelector('[data-srv-go]');
      if (go) go.disabled = typedOf(row) === null;
    });
    root.addEventListener('click', e => {
      const t = e.target.closest && e.target.closest('[data-srv-go], [data-srv-cancel]');
      if (!t || !root.contains(t)) return;
      const row = t.closest('[data-srv-confirm]');
      if (!row) return;
      if (t.hasAttribute('data-srv-cancel')) { row.remove(); return; }
      if (t.dataset.busy) return;
      goConfirm(row, (action, typed) => run(action, typed, row, t));
    });
  }

  // runListAction is a confirmed revoke or remove of server id: the fresh
  // sign-in popup first (synchronously), then the request.
  function runListAction(root, action, id, typed, btn) {
    const verb = action === 'revoke' ? 'Revoke' : 'Remove';
    fresh(action, async proof => {
      if (btn) btn.dataset.busy = '1';
      try {
        const res = await window.apiCall('/api/servers/' + enc(id) + (verb === 'Revoke' ? '/revoke' : ''), verb === 'Revoke' ? 'POST' : 'DELETE', Object.assign({ confirm: typed }, proof));
        const ans = res && res.json ? await res.json().catch(() => ({})) : {};
        window.showToast(verb === 'Revoke' ? (ans.parked ? 'Revoked; waiting for quorum to remove its etcd member. ' + (ans.warning || '') : 'Revoked.')
          : ans.op === 'node_remove' ? 'Removing: follow it on the node\'s row.' : 'Removed.', ans.parked ? 'warning' : 'success');
        render(root);
      } catch (err) {
        if (btn) delete btn.dataset.busy;
        window.showToast(err.message || 'Failed', 'error');
      }
    });
  }

  // ── the instance page ────────────────────────────────

  // runsOn is the "Runs on" line of an instance's facts.
  function runsOn(inst) {
    const s = inst.server || '';
    const st = inst.state === 'unreachable' ? ' ' + pill('warn', 'unreachable') : inst.state === 'orphaned' ? ' ' + pill('warn', 'orphaned') : inst.state === 'moving' ? ' ' + pill('info', 'moving') : '';
    return '<dt>Runs on</dt><dd data-runs-on>' + (s ? esc(serverName(s)) + ' <code>' + esc(s) + '</code>' : 'the primary') + st + '</dd>';
  }

  // serverSelect is the setup form's server choice (free disk, memory,
  // runtime, architecture of each ready server).
  function serverSelect(selected) {
    const list = ((page && page.servers) || []).filter(s => s.kind !== 'cluster-node' && (s.id === 'primary' || s.state === 'ready'));
    if (list.length < 2) return '';
    return '<label class="block" for="setup-server">Runs on</label><select id="setup-server" data-setup-server>' +
      list.map(s => '<option value="' + esc(s.id === 'primary' ? '' : s.id) + '"' + ((selected || '') === (s.id === 'primary' ? '' : s.id) ? ' selected' : '') + '>' +
        esc(s.name) + (s.id === 'primary' ? '' : ' — ' + esc(s.runtime) + ' ' + esc(s.arch) + ', ' + esc(bytes(s.data_free)) + ' free, ' + esc(bytes(s.mem_bytes)) + ' memory') +
        '</option>').join('') + '</select><small>Apps that need the primary (AI pages, VPN providers, core volumes…) are refused on a worker, with the reason.</small>';
  }

  function undoOpen(inst) {
    const mf = inst.moved_from;
    if (!mf || !mf.at) return false;
    return Date.now() - new Date(mf.at).getTime() < UNDO_DAYS * 24 * 3600 * 1000;
  }

  // instanceSection is the instance page's Servers section: Move…, the
  // undo banner while the source copy is kept, Lift quarantine on a
  // worker.
  function instanceSection(inst) {
    let h = '<div class="inst-section" data-srv-inst><h4>Server</h4>';
    if (inst.moved_from) {
      h += '<div class="public-warn" data-srv-undo>Moved from ' + esc(serverName(inst.moved_from.server)) + ' on ' + esc(when(inst.moved_from.at)) + '. ' +
        (undoOpen(inst)
          ? 'Its old copy is kept, stopped, until 7 days after the move: <button type="button" class="btn btn-sm" data-srv-iact="undo">Undo move…</button> (changes since the move are lost)'
          : 'The 7 days to undo it are over.') +
        ' <button type="button" class="btn btn-sm btn-danger" data-srv-iact="leftover">Remove the old copy…</button></div>';
    }
    const others = ((page && page.servers) || []).filter(s => s.kind !== 'cluster-node' && (s.id === 'primary' ? '' : s.id) !== (inst.server || '') && (s.id === 'primary' || s.state === 'ready'));
    if (others.length && inst.state !== 'moving' && inst.state !== 'orphaned') {
      h += '<div class="inst-row"><select data-srv-move-to>' + others.map(s => '<option value="' + esc(s.id === 'primary' ? '' : s.id) + '">' + esc(s.name) + '</option>').join('') + '</select>' +
        ' <button type="button" class="btn btn-sm" data-srv-iact="move">Move…</button></div>' +
        '<small>A move stops the app, backs it up, restores it on the other server and starts it there: it is down meanwhile. Folders must be unbound first.</small>';
    }
    if (inst.state === 'orphaned') {
      h += '<div class="public-warn" data-srv-orphaned>Its server ' + esc(serverName(inst.server)) + ' was revoked: it runs nowhere Portcullis can reach. ' +
        'Restore it from a backup (it lands on this server; move it afterwards) or Forget it. ' +
        '<button type="button" class="btn btn-sm btn-danger" data-srv-iact="forget">Forget…</button></div>';
    }
    if (inst.server && inst.state !== 'orphaned') h += '<div class="inst-row"><button type="button" class="btn btn-sm" data-srv-iact="lift">Lift quarantine…</button> <small>Only when the doctor shows the instance quarantined on its server and you fixed the cause.</small></div>';
    return h + '</div>';
  }

  // runInstanceAction is a confirmed instance action: undo, leftover and
  // lift open the fresh sign-in popup first (synchronously, from the
  // confirming click); move needs none.
  function runInstanceAction(root, inst, action, typed, btn, done) {
    const id = inst.id;
    const fail = err => { if (btn) delete btn.dataset.busy; if (!err.shown) window.showToast(err.message || 'Failed', 'error'); };
    const busy = () => { if (btn) btn.dataset.busy = '1'; };
    switch (action) {
      case 'move': {
        const sel = root.querySelector('[data-srv-move-to]');
        busy();
        window.apiCall('/api/instances/' + enc(id) + '/move', 'POST', { server: sel ? sel.value : '' })
          .then(r => r.json()).then(acc => window.awaitOp(id, acc.op_id, acc.op)).then(done, fail);
        return;
      }
      case 'undo':
        fresh('undo', proof => {
          busy();
          window.apiCall('/api/instances/' + enc(id) + '/move/undo', 'POST', Object.assign({ confirm: typed }, proof))
            .then(r => r.json()).then(acc => window.awaitOp(id, acc.op_id, acc.op)).then(done, fail);
        });
        return;
      case 'leftover':
        fresh('leftover', proof => {
          busy();
          window.apiCall('/api/instances/' + enc(id) + '/move-leftover', 'DELETE', Object.assign({ confirm: typed }, proof)).then(done, fail);
        });
        return;
      case 'forget':
        // Not † (the route needs the typed id only): no fresh sign-in.
        busy();
        window.apiCall('/api/instances/' + enc(id) + '?forget=1', 'DELETE', { confirm: typed })
          .then(r => r.json()).then(acc => window.awaitOp(id, acc.op_id, acc.op)).then(done, fail);
        return;
      case 'lift':
        fresh('lift', proof => {
          busy();
          window.apiCall('/api/instances/' + enc(id) + '/quarantine/lift', 'POST', proof)
            .then(() => { window.showToast('Quarantine lifted.', 'success'); done(); }, fail);
        });
    }
  }

  // wire binds instanceSection's buttons in root; done() re-renders. Each
  // action shows its inline confirmation first.
  function wire(root, inst, done) {
    const id = inst.id;
    root.addEventListener('click', e => {
      const b = e.target.closest && e.target.closest('[data-srv-iact]');
      if (!b || !root.contains(b) || b.dataset.busy) return;
      switch (b.dataset.srvIact) {
        case 'move': {
          const sel = root.querySelector('[data-srv-move-to]');
          showConfirm(b, 'move', id, 'Move ' + id + ' to ' + serverName(sel ? sel.value : '') + '? It is down while it moves. Type the instance id to confirm:', 'Move');
          return;
        }
        case 'undo':
          showConfirm(b, 'undo', id, 'Undo the move of ' + id + '? Changes since the move are lost. Type the instance id to confirm (a fresh sign-in follows):', 'Undo move');
          return;
        case 'leftover':
          showConfirm(b, 'leftover', id, 'Remove the old copy of ' + id + ' (its volumes on the old server)? Undo move isn\'t possible afterwards. Type the instance id to confirm (a fresh sign-in follows):', 'Remove');
          return;
        case 'forget':
          showConfirm(b, 'forget', id, 'Forget ' + id + '? Its state, Keycloak clients and groups are removed; nothing on the revoked server is touched and no backup is taken. Type the instance id to confirm:', 'Forget');
          return;
        case 'lift':
          showConfirm(b, 'lift', '', 'Lift the quarantine of ' + id + ' on ' + serverName(inst.server) + '? Its bundle is checked and sent again; the agent refuses it again if the cause remains (a fresh sign-in follows).', 'Lift');
      }
    });
    confirmEvents(root, (action, typed, row, btn) => runInstanceAction(root, inst, action, typed, btn, done));
  }

  // cached is the last list (no request): folders.js's server choice.
  function cached() { return (page && page.servers) || []; }

  window.PortcullisServers = { render, load, cached, confirmHtml, goConfirm, runListAction, runInstanceAction, listHtml, detailHtml, codeDialogHtml, openCodeDialog,
    addBody, stepsHtml, runsOn, serverSelect, instanceSection, wire };
})();
