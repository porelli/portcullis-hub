// Portcullis Hub — Settings → Shared folders and Local networks (contract
// §14, plan 2 Task 14). Hub listener only.
//
//   window.PortcullisFolders.render(el)               the Shared folders section
//   window.PortcullisFolders.renderLocalNetworks(el)  the Local networks section
//   window.PortcullisFolders.openAssign({folder, add: [{instance, key, subpath, write}], remove: [{instance, key}]})
//       the assignment preview dialog; resolves {applied} when it closes
//   window.PortcullisFolders.list()                   GET /api/folders → [FolderView]
//   window.PortcullisFolders.planHtml(plan) / runOp(acc, onTick)   shared with doctor.js
//
// GET    /api/folders                       the folders (FolderView)
// POST   /api/folders                       create {id, name, path, description, gid?, create}
// PUT    /api/folders/{id}                  update {name, path, description}
// DELETE /api/folders/{id}                  remove (409 while apps use it; files stay)
// POST   /api/folders/check                 {path, create} → PathCheck
// POST   /api/folders/{id}/assign/preview   {uses} → AssignPlan
// POST   /api/folders/{id}/assign/apply     {plan_hash, uses} → 202 {op_id, poll}
// POST   /api/folders/{id}/undo/preview     → AssignPlan (the last apply's snapshot)
// POST   /api/folders/{id}/undo/apply       {plan_hash} → 202
// GET/PUT /api/settings/local-networks      {networks, default}
//
// Rules: every interpolation goes through escapeHtml (index.html); data-*
// attributes and delegated listeners only. Nothing on disk changes
// without a preview the admin applied; removing a folder needs its id
// typed.
(function () {
  'use strict';

  const esc = s => window.escapeHtml(s);
  const enc = encodeURIComponent;
  // md renders the Hub's plain text: `code` and *emphasis*, after escaping.
  const md = s => esc(s).replace(/`([^`]+)`/g, '<code>$1</code>').replace(/\*([^*\s][^*]*)\*/g, '<em>$1</em>');
  const ID_RE = /^[a-z][a-z0-9-]{0,30}$/;
  const POLL_MS = 1000;

  let sectionEl = null; // the rendered Shared folders section
  let folders = [];
  let dialog = null;    // the open dialog's context

  function fmtTime(s) {
    if (!s) return '';
    const d = new Date(s);
    return isNaN(d) ? String(s) : d.toLocaleString();
  }

  async function list() {
    const r = await window.apiGet('/api/folders');
    folders = (r && r.folders) || [];
    return folders;
  }

  function folderName(id) {
    const f = folders.find(x => x.id === id);
    return f ? f.name : id;
  }

  // ── the dialog ─────────────────────────────────────────────────────

  function modal() {
    let m = document.getElementById('folder-modal');
    if (!m) {
      m = document.createElement('div');
      m.className = 'op-modal';
      m.id = 'folder-modal';
      m.innerHTML = '<div class="op-modal-box inst-modal-box" id="folder-modal-box" role="dialog" aria-modal="true"></div>';
      document.body.appendChild(m);
      bindModal(m);
    }
    return m;
  }

  function openDialog(ctx, html) {
    if (dialog && dialog !== ctx) closeDialog();
    dialog = ctx;
    const m = modal();
    m.querySelector('#folder-modal-box').innerHTML = html;
    m.classList.add('visible');
  }

  function dialogBox() { return document.getElementById('folder-modal-box'); }

  function closeDialog() {
    const ctx = dialog;
    if (!ctx) return;
    if (ctx.busy) return; // an apply is running: its result shows here
    dialog = null;
    clearTimeout(ctx.timer);
    const m = document.getElementById('folder-modal');
    if (m) { m.classList.remove('visible'); m.querySelector('#folder-modal-box').innerHTML = ''; }
    if (ctx.resolve) ctx.resolve({ applied: !!ctx.applied });
    if (ctx.applied || ctx.saved) refresh();
  }

  function head(title) {
    return '<div class="inst-modal-head"><span class="inst-modal-title">' + title + '</span>' +
      '<button type="button" class="detail-close" data-fd-close aria-label="Close">&times;</button></div>';
  }

  // ── plans and operations (shared with doctor.js) ───────────────────

  const CHANGE_TEXT = { add: 'added', remove: 'removed', keep: 'kept' };

  // planHtml: an AssignPlan's lines, warnings, uses, restarts, downtime.
  function planHtml(plan) {
    if (!plan) return '';
    let h = '<ul class="fd-lines">' + (plan.lines || []).map(l => '<li>' + md(l) + '</li>').join('') + '</ul>';
    h += window.warningsList(plan.warnings);
    if (plan.disk && plan.disk.partial) h += '<div class="public-warn">The scan was partial: the counts are at least these.</div>';
    const uses = plan.uses || [];
    if (uses.length) {
      h += '<table class="inst-table fd-uses"><thead><tr><th>App</th><th>Setting</th><th>Subfolder</th><th>Access</th><th>Change</th></tr></thead><tbody>';
      for (const u of uses) {
        h += '<tr><td><code>' + esc(u.instance) + '</code></td><td>' + esc(u.label || u.key) + '</td><td>' + (u.subpath ? '<code>' + esc(u.subpath) + '</code>' : '—') + '</td>' +
          '<td>' + (u.read_only ? 'read-only' : 'read/write') + (u.declared ? '' : ' <span class="pill warn" title="The template has no folder block">undeclared</span>') + '</td>' +
          '<td><span class="pill ' + (u.change === 'add' ? 'ok' : u.change === 'remove' ? 'bad' : '') + '">' + esc(CHANGE_TEXT[u.change] || u.change) + '</span></td></tr>';
      }
      h += '</tbody></table>';
    }
    if ((plan.restarts || []).length) {
      h += '<p class="fd-downtime">Downtime: ' + plan.restarts.map(r => '<code>' + esc(r) + '</code>').join(', ') + ' stopped for ' + esc(plan.downtime || 'a moment') + ', then started.</p>';
    } else {
      h += '<p class="fd-downtime">No app is stopped.</p>';
    }
    return h;
  }

  // runOp polls an accepted operation (202 {op_id, poll}) until it
  // finished: its op record (ok or not; a failure keeps its result, the
  // snapshot name). onTick(seconds) shows progress.
  async function runOp(acc, onTick) {
    const t0 = Date.now();
    for (;;) {
      await new Promise(r => setTimeout(r, POLL_MS));
      if (onTick) onTick(Math.round((Date.now() - t0) / 1000));
      let rec;
      try { rec = await window.apiGet(acc.poll); } catch (e) { if (e.status === 404) continue; throw e; }
      if (!rec || rec.op_id !== acc.op_id || rec.running) continue;
      return rec;
    }
  }

  // opResultHtml: an assignment, undo or fix's outcome.
  function opResultHtml(rec) {
    const r = rec.result || {};
    let h = '';
    if (rec.ok) {
      let msg;
      if (rec.op === 'folder_undo') {
        msg = 'Undone: ' + esc(r.entries || '0') + ' entries are back as they were before the fix' +
          (Number(r.changed_since) > 0 ? '; ' + esc(r.changed_since) + ' changed since the fix and were left alone' : '') + '.';
        if (r.undo_snapshot) msg += ' Safety copy: <code>' + esc(r.undo_snapshot) + '</code>.';
      } else if (r.entries !== undefined) {
        msg = 'verified: 0 entries differ. ' + esc(r.entries) + ' entries changed' +
          (r.add !== undefined ? ', ' + esc(r.add) + ' use(s) added, ' + esc(r.remove || '0') + ' removed' : '') + '.';
        if (r.snapshot) msg += ' Snapshot <code>' + esc(r.snapshot) + '</code> can undo it.';
      } else if (r.bind) {
        msg = esc(r.key || 'The port') + ' now binds ' + esc(r.bind) + '.';
      } else if (r.add !== undefined) {
        msg = 'Done: ' + esc(r.add) + ' use(s) added, ' + esc(r.remove || '0') + ' removed; nothing changed on disk.';
      } else {
        msg = 'Done.';
      }
      h += '<div class="inst-ok" data-fd-result="ok">' + msg + '</div>';
    } else {
      h += window.errorBox({ status: rec.status, message: rec.error || (rec.op + ' failed'), hint: rec.hint, output: rec.output, rolled_back: rec.rolled_back });
      const snap = r.snapshot || r.undo_snapshot;
      if (snap) h += '<div class="op-hint" data-fd-result="failed">Permissions snapshot <code>' + esc(snap) + '</code> was saved before anything changed.</div>';
      else h += '<div data-fd-result="failed"></div>';
    }
    h += window.warningsList(rec.warnings);
    return h;
  }

  // ── Settings → Shared folders ──────────────────────────────────────

  function render(el) {
    sectionEl = el;
    if (!el.dataset.fdBound) { el.dataset.fdBound = '1'; bindSection(el); }
    el.innerHTML = '<p class="settings-empty">Loading…</p>';
    return list().then(draw).catch(err => { el.innerHTML = window.errorBox(err); });
  }

  function refresh() {
    if (sectionEl && document.body.contains(sectionEl)) render(sectionEl);
    if (window.PortcullisDoctor) window.PortcullisDoctor.refreshBadge();
  }

  function usesText(f) {
    if (!(f.uses || []).length) return '<span class="settings-empty">no apps</span>';
    return f.uses.map(u => '<div><code>' + esc(u.instance) + '</code> → ' + esc(u.label || u.key) +
      (u.subpath ? ' <code>' + esc(u.subpath) + '</code>' : '') + ' <span class="settings-empty">(' + (u.read_only ? 'read-only' : 'read/write') + ')</span></div>').join('');
  }

  function draw() {
    const el = sectionEl;
    let h = '<div class="inst-row" style="margin-bottom:0.75rem"><button type="button" class="btn btn-primary btn-sm" data-fd-add>Add shared folder</button></div>';
    if (!folders.length) {
      h += '<p class="settings-empty">No shared folders yet.</p>';
    } else {
      h += '<table class="inst-table fd-table"><thead><tr><th>Name</th><th>Path</th><th>Group</th><th>Apps</th><th>Last check</th><th></th></tr></thead><tbody>';
      for (const f of folders) {
        const lc = f.last_check;
        const op = f.last_op;
        h += '<tr data-fd-row="' + esc(f.id) + '"><td><strong>' + esc(f.name) + '</strong> <code class="settings-empty">' + esc(f.id) + '</code>' +
          (f.description ? '<div class="settings-empty fd-desc">' + esc(f.description) + '</div>' : '') + '</td>' +
          '<td><code>' + esc(f.path) + '</code></td>' +
          '<td>' + esc(f.gid) + (f.adopted ? ' <span class="pill warn">adopted</span>' : '') + '</td>' +
          '<td>' + usesText(f) + '</td>' +
          '<td>' + (lc ? esc(fmtTime(lc.at)) + (lc.partial ? ' <span class="pill warn">partial</span>' : '') : '<span class="settings-empty">never</span>') +
          (op ? '<div>' + (op.running ? '<span class="pill info">' + esc(op.op) + ' running</span>' :
            '<span class="pill ' + (op.ok ? 'ok' : 'bad') + '" title="' + esc(op.error || '') + '">' + esc(op.op) + (op.ok ? ' ok' : ' failed') + '</span>') + '</div>' : '') + '</td>' +
          '<td class="fd-actions"><button type="button" class="btn btn-secondary btn-sm" data-fd-edit="' + esc(f.id) + '">Edit</button> ' +
          '<button type="button" class="btn btn-secondary btn-sm" data-fd-recheck="' + esc(f.id) + '" title="After a reboot on btrfs or LVM the folder\'s device number can change: check it and store the new one">Re-check identity…</button> ' +
          (f.last_apply && f.last_apply.snapshot ? '<button type="button" class="btn btn-secondary btn-sm" data-fd-undo="' + esc(f.id) + '" title="Restore the permissions the last apply changed">Undo last fix…</button> ' : '') +
          '<button type="button" class="btn btn-danger btn-sm" data-fd-remove="' + esc(f.id) + '">Remove</button></td></tr>' +
          '<tr data-fd-panel="' + esc(f.id) + '" hidden><td colspan="6"></td></tr>';
      }
      h += '</tbody></table>';
    }
    el.innerHTML = h;
  }

  function removePanel(id) {
    const row = sectionEl.querySelector('[data-fd-panel="' + CSS.escape(id) + '"]');
    if (!row) return;
    if (!row.hidden) { row.hidden = true; row.firstElementChild.innerHTML = ''; return; }
    const f = folders.find(x => x.id === id) || { id, name: id, uses: [] };
    row.firstElementChild.innerHTML = '<div class="inst-panel inst-danger">' +
      '<p>Remove shared folder <strong>' + esc(f.name) + '</strong>? Only the definition goes: its files and permissions on disk stay as they are' +
      ((f.uses || []).length ? '. It is refused while apps use it (' + f.uses.map(u => esc(u.instance)).join(', ') + ')' : '') + '.</p>' +
      '<div class="inst-row"><label class="settings-empty" for="fd-del-' + esc(id) + '">Type <code>' + esc(id) + '</code> to confirm</label>' +
      '<input type="text" id="fd-del-' + esc(id) + '" data-fd-del-input="' + esc(id) + '" autocomplete="off" spellcheck="false">' +
      '<button type="button" class="btn btn-danger btn-sm" data-fd-del-go="' + esc(id) + '" disabled>Remove</button>' +
      '<button type="button" class="btn btn-secondary btn-sm" data-fd-del-cancel="' + esc(id) + '">Cancel</button></div>' +
      '<div data-fd-del-result></div></div>';
    row.hidden = false;
    row.querySelector('input').focus();
  }

  async function removeFolder(btn) {
    const id = btn.dataset.fdDelGo;
    const panel = btn.closest('.inst-panel');
    const input = panel.querySelector('[data-fd-del-input]');
    if (input.value.trim() !== id) return;
    btn.disabled = true;
    try {
      await window.apiCall('/api/folders/' + enc(id), 'DELETE');
      window.showToast('Shared folder ' + id + ' removed', 'success');
      refresh();
    } catch (err) {
      panel.querySelector('[data-fd-del-result]').innerHTML = window.errorBox(err);
      btn.disabled = false;
    }
  }

  function bindSection(el) {
    el.addEventListener('click', e => {
      const t = e.target;
      let b;
      if (t.closest('[data-fd-add]')) { openEdit(null); return; }
      if ((b = t.closest('[data-fd-edit]'))) { openEdit(b.dataset.fdEdit); return; }
      if ((b = t.closest('[data-fd-undo]'))) { openUndo(b.dataset.fdUndo); return; }
      if ((b = t.closest('[data-fd-recheck]'))) { openRecheck(b.dataset.fdRecheck); return; }
      if ((b = t.closest('[data-fd-remove]'))) { removePanel(b.dataset.fdRemove); return; }
      if ((b = t.closest('[data-fd-del-cancel]'))) { removePanel(b.dataset.fdDelCancel); return; }
      if ((b = t.closest('[data-fd-del-go]'))) { removeFolder(b); }
    });
    el.addEventListener('input', e => {
      const t = e.target;
      if (t.dataset.fdDelInput) {
        const go = t.closest('.inst-panel').querySelector('[data-fd-del-go]');
        go.disabled = t.value.trim() !== t.dataset.fdDelInput;
      }
    });
  }

  // ── Add / Edit ─────────────────────────────────────────────────────

  // pathOptions: every instance's path options (instance scope), from the
  // catalog and the instances list.
  async function pathOptions() {
    const cat = await window.loadCatalogInfo();
    let insts = [];
    try { insts = await window.apiGet('/api/instances'); } catch (e) { /* the catalog's default instances */ }
    if (!insts.length) insts = Object.keys(cat).map(id => ({ id, template: id, default: true }));
    const out = [];
    for (const i of insts.slice().sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0)) {
      const t = cat[i.template];
      const opts = (t && t.manifest && t.manifest.settings && t.manifest.settings.options) || [];
      for (const o of opts) {
        if (o.type !== 'path' || (o.scope && o.scope !== 'instance')) continue;
        out.push({ instance: i.id, app: (t.manifest.name || i.template), key: o.key, label: o.label || o.key, folder: o.folder || null, state: i.state || '' });
      }
    }
    return out;
  }

  // usedBy: instance/key → {folder, subpath, write} over every folder.
  function usedBy() {
    const m = {};
    for (const f of folders) for (const u of f.uses || []) {
      m[u.instance + '/' + u.key] = { folder: f.id, subpath: u.subpath || '', write: !u.declared && u.access === 'write' };
    }
    return m;
  }

  function slug(name) {
    let s = String(name || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
    s = s.replace(/^[^a-z]+/, '');
    return s.slice(0, 31).replace(/-+$/, '');
  }

  async function openEdit(id) {
    const ctx = { kind: 'edit', id, isNew: !id, idEdited: false };
    openDialog(ctx, head(id ? 'Edit shared folder' : 'Add shared folder') + '<p class="settings-empty">Loading…</p>');
    let opts;
    try { await list(); opts = await pathOptions(); } catch (err) { if (dialog === ctx) dialogBox().innerHTML = head('Shared folder') + window.errorBox(err); return; }
    if (dialog !== ctx) return;
    const f = id ? folders.find(x => x.id === id) : null;
    if (id && !f) { dialogBox().innerHTML = head('Shared folder') + window.errorBox({ status: 404, message: 'no such shared folder' }); return; }
    ctx.opts = opts;
    ctx.used = usedBy();
    ctx.before = {};
    if (f) for (const u of f.uses || []) ctx.before[u.instance + '/' + u.key] = { subpath: u.subpath || '', write: !u.declared && u.access === 'write' };
    let h = head(id ? 'Edit shared folder <code>' + esc(id) + '</code>' : 'Add shared folder');
    h += '<form class="settings-form fd-form" data-fd-form novalidate>';
    h += '<div class="form-group"><label for="fd-name">Name</label><input type="text" id="fd-name" maxlength="64" required value="' + esc(f ? f.name : '') + '" placeholder="Family photos"></div>';
    if (!id) h += '<div class="form-group"><label for="fd-id">Id</label><small>Lowercase letters, digits and dashes; it never changes.</small><input type="text" id="fd-id" maxlength="31" spellcheck="false" placeholder="family-photos"></div>';
    h += '<div class="form-group"><label for="fd-path">Host path</label><small>Under one of the Hub\'s bind roots (HUB_OVERRIDE_BIND_ROOTS).</small>' +
      '<div class="inst-row" style="margin-top:0"><input type="text" id="fd-path" spellcheck="false" value="' + esc(f ? f.path : '') + '" placeholder="/srv/photos" style="flex:1">' +
      '<button type="button" class="btn btn-secondary btn-sm" data-fd-check>Check path</button></div><div data-fd-check-result></div></div>';
    h += '<div class="form-group"><label for="fd-desc">Description</label><textarea id="fd-desc" rows="2" maxlength="500">' + esc(f ? f.description : '') + '</textarea></div>';
    if (!id) {
      h += '<details class="fd-advanced"><summary>Advanced</summary><div class="form-group"><label for="fd-gid">Adopt an existing host group (gid)</label>' +
        '<small>Leave empty to allocate one (60000–60999). An adopted gid: at least 1000, not 65534, outside 60000–60999. Anything mounted with that gid becomes reachable by this folder\'s apps.</small>' +
        '<input type="number" id="fd-gid" min="1000" step="1"></div></details>';
    }
    h += '<div class="form-group"><label>Used by</label><small>Ticking an app here doesn\'t change anything yet: Save opens the assignment preview, and only its Apply changes the apps and the disk.</small>';
    if (!opts.length) h += '<p class="settings-empty">No app has a path setting.</p>';
    h += '<div class="fd-usedby">';
    for (const o of opts) {
      const k = o.instance + '/' + o.key;
      const cur = ctx.before[k];
      const other = ctx.used[k] && ctx.used[k].folder !== id ? ctx.used[k] : null;
      const access = o.folder ? (o.folder.access === 'write' ? 'writes' : 'reads') : null;
      h += '<div class="fd-use" data-fd-use="' + esc(k) + '"><label class="ps-check"><input type="checkbox" data-fd-tick' + (cur ? ' checked' : '') + (other ? ' disabled' : '') + '> ' +
        esc(o.app) + ' <code>' + esc(o.instance) + '</code> → ' + esc(o.label) + '</label>' +
        (access ? ' <span class="settings-empty">(' + access + ')</span>' :
          ' <span class="settings-empty">(read-only unless you allow writing)</span> <label class="ps-check"><input type="checkbox" data-fd-write' + (cur && cur.write ? ' checked' : '') + (other ? ' disabled' : '') + '> allow writing</label>') +
        ' <input type="text" data-fd-sub placeholder="subfolder (optional)" spellcheck="false" value="' + esc(cur ? cur.subpath : '') + '"' + (other ? ' disabled' : '') + '>' +
        (other ? ' <span class="public-warn">uses shared folder ' + esc(folderName(other.folder)) + ': unassign it there first</span>' : '') + '</div>';
    }
    h += '</div></div><div data-fd-save-result></div>';
    h += '<div class="op-modal-actions"><button type="button" class="btn btn-secondary btn-sm" data-fd-close>Cancel</button><button type="submit" class="btn btn-primary btn-sm" data-fd-save>Save</button></div></form>';
    dialogBox().innerHTML = h;
    dialogBox().querySelector('#fd-name').focus();
  }

  function collectUses(box) {
    const uses = [];
    box.querySelectorAll('[data-fd-use]').forEach(row => {
      const tick = row.querySelector('[data-fd-tick]');
      if (!tick.checked || tick.disabled) return;
      const [instance, key] = row.dataset.fdUse.split('/');
      const u = { instance, key };
      const sub = row.querySelector('[data-fd-sub]').value.trim().replace(/^\/+|\/+$/g, '');
      if (sub) u.subpath = sub;
      const w = row.querySelector('[data-fd-write]');
      if (w && w.checked) u.write = true;
      uses.push(u);
    });
    return uses;
  }

  function usesChanged(before, uses) {
    const keys = Object.keys(before);
    if (keys.length !== uses.length) return true;
    for (const u of uses) {
      const b = before[u.instance + '/' + u.key];
      if (!b || b.subpath !== (u.subpath || '') || b.write !== !!u.write) return true;
    }
    return false;
  }

  function checkLine(pc) {
    let h = '<div class="fd-check ' + (pc.exists && !(pc.problems || []).length ? 'fd-check-ok' : 'fd-check-bad') + '" data-fd-summary>' + esc(pc.summary || (pc.exists ? 'exists' : 'missing')) +
      (pc.created ? ' <span class="pill ok">created</span>' : '') + (pc.partial ? ' <span class="pill warn">partial</span>' : '') + '</div>';
    for (const p of pc.problems || []) h += '<div class="op-msg inst-error">' + esc(p) + '</div>';
    if (!pc.exists) {
      h += '<div class="inst-row" data-fd-create-ask><button type="button" class="btn btn-secondary btn-sm" data-fd-create>Create it</button></div>';
    }
    return h;
  }

  async function checkPath(create) {
    const box = dialogBox();
    const out = box.querySelector('[data-fd-check-result]');
    const p = box.querySelector('#fd-path').value.trim();
    if (!p) { out.innerHTML = '<div class="op-msg inst-error">Enter a host path first.</div>'; return; }
    out.innerHTML = '<p class="settings-empty">' + (create ? 'Creating…' : 'Checking…') + '</p>';
    try {
      const pc = await window.apiPost('/api/folders/check', { path: p, create: !!create });
      if (box !== dialogBox()) return;
      out.innerHTML = checkLine(pc);
    } catch (err) { out.innerHTML = window.errorBox(err); }
  }

  function createAsk(btn) {
    const row = btn.closest('[data-fd-create-ask]');
    const p = dialogBox().querySelector('#fd-path').value.trim();
    row.innerHTML = '<span>Create <code>' + esc(p) + '</code> on the host (an empty directory, nothing else changes)?</span>' +
      '<button type="button" class="btn btn-primary btn-sm" data-fd-create-go>Create</button><button type="button" class="btn btn-secondary btn-sm" data-fd-create-cancel>Cancel</button>';
  }

  async function saveEdit() {
    const ctx = dialog;
    const box = dialogBox();
    const out = box.querySelector('[data-fd-save-result]');
    const name = box.querySelector('#fd-name').value.trim();
    const p = box.querySelector('#fd-path').value.trim();
    const description = box.querySelector('#fd-desc').value.trim();
    const uses = collectUses(box);
    let id = ctx.id;
    const body = { name, path: p, description };
    if (ctx.isNew) {
      id = box.querySelector('#fd-id').value.trim() || slug(name);
      if (!ID_RE.test(id)) { out.innerHTML = '<div class="op-msg inst-error">The id must start with a letter and use lowercase letters, digits and dashes (at most 31).</div>'; return; }
      body.id = id;
      body.create = false;
      const gid = box.querySelector('#fd-gid').value.trim();
      if (gid !== '') {
        if (!/^\d+$/.test(gid)) { out.innerHTML = '<div class="op-msg inst-error">The gid must be a whole number.</div>'; return; }
        body.gid = Number(gid);
      }
    }
    if (!name) { out.innerHTML = '<div class="op-msg inst-error">A name is required.</div>'; return; }
    const btn = box.querySelector('[data-fd-save]');
    btn.disabled = true;
    out.innerHTML = '<p class="settings-empty">Saving…</p>';
    let warnings = [];
    try {
      if (ctx.isNew) {
        const r = await window.apiPost('/api/folders', body);
        warnings = r.warnings || [];
      } else {
        await window.apiPut('/api/folders/' + enc(id), body);
      }
    } catch (err) {
      if (dialog === ctx) { out.innerHTML = window.errorBox(err); btn.disabled = false; }
      return;
    }
    ctx.saved = true;
    window.showToast('Shared folder ' + name + ' saved', 'success');
    if (!usesChanged(ctx.before, uses)) {
      if (warnings.length) { out.innerHTML = window.warningsList(warnings); btn.disabled = false; ctx.isNew = false; ctx.id = id; return; }
      closeDialog();
      return;
    }
    // The uses changed: the assignment preview (closing it changes nothing).
    dialog = null;
    try { await list(); } catch (e) { /* the id then */ }
    openAssignWith({ folder: id, uses, notice: warnings });
    refresh();
  }

  // ── the assignment preview ─────────────────────────────────────────

  function useKey(u) { return u.instance + '/' + u.key; }

  // openAssign: the folder's current uses, minus remove, plus add (an add
  // replaces the same setting's use).
  async function openAssign(spec) {
    await list();
    const f = folders.find(x => x.id === spec.folder);
    if (!f) { window.showToast('No shared folder ' + spec.folder, 'error'); return { applied: false }; }
    const m = new Map();
    for (const u of f.uses || []) {
      const x = { instance: u.instance, key: u.key };
      if (u.subpath) x.subpath = u.subpath;
      if (!u.declared && u.access === 'write') x.write = true;
      m.set(useKey(x), x);
    }
    for (const r of spec.remove || []) m.delete(useKey(r));
    for (const a of spec.add || []) {
      const x = { instance: a.instance, key: a.key };
      if (a.subpath) x.subpath = a.subpath;
      if (a.write) x.write = true;
      m.set(useKey(x), x);
    }
    return openAssignWith({ folder: f.id, uses: [...m.values()] });
  }

  function openAssignWith(spec) {
    return new Promise(resolve => {
      const ctx = { kind: 'assign', folder: spec.folder, uses: spec.uses, resolve, notice: spec.notice || [] };
      openDialog(ctx, '');
      drawAssign(ctx);
      previewAssign(ctx);
    });
  }

  function drawAssign(ctx) {
    const name = folderName(ctx.folder);
    let h = head('Assign shared folder ' + esc(name));
    h += window.warningsList(ctx.notice);
    h += '<p class="settings-empty">Nothing changes until you click Apply. Closing this leaves the folder as it is now.</p>';
    // The uses, editable: subfolder and (undeclared) writes.
    h += '<div class="fd-assign-uses">';
    if (!ctx.uses.length) h += '<p class="settings-empty">No app will use this folder.</p>';
    for (const u of ctx.uses) {
      h += '<div class="fd-use" data-fd-auses="' + esc(useKey(u)) + '"><code>' + esc(u.instance) + '</code> → ' + esc(u.key) +
        ' <input type="text" data-fd-asub placeholder="subfolder (optional)" spellcheck="false" value="' + esc(u.subpath || '') + '">' +
        (ctx.undeclared && ctx.undeclared[useKey(u)] ? ' <label class="ps-check"><input type="checkbox" data-fd-awrite' + (u.write ? ' checked' : '') + '> allow writing</label>' : '') + '</div>';
    }
    h += '</div><div data-fd-plan><p class="settings-empty">Loading the preview…</p></div>';
    h += '<div data-fd-op></div>';
    h += '<div class="op-modal-actions" data-fd-actions><button type="button" class="btn btn-secondary btn-sm" data-fd-close>Close</button>' +
      '<button type="button" class="btn btn-primary btn-sm" data-fd-apply disabled>Apply</button></div>';
    dialogBox().innerHTML = h;
  }

  async function previewAssign(ctx) {
    ctx.plan = null;
    const seq = (ctx.seq = (ctx.seq || 0) + 1);
    const box = dialogBox();
    const planEl = box.querySelector('[data-fd-plan]');
    const apply = box.querySelector('[data-fd-apply]');
    apply.disabled = true;
    planEl.innerHTML = '<p class="settings-empty">Loading the preview…</p>';
    try {
      const plan = await window.apiPost('/api/folders/' + enc(ctx.folder) + '/assign/preview', { uses: ctx.uses });
      if (dialog !== ctx || seq !== ctx.seq) return;
      ctx.plan = plan;
      const und = {};
      for (const u of plan.uses || []) if (!u.declared) und[useKey(u)] = true;
      const redraw = JSON.stringify(und) !== JSON.stringify(ctx.undeclared || {});
      ctx.undeclared = und;
      if (redraw) { drawAssign(ctx); }
      dialogBox().querySelector('[data-fd-plan]').innerHTML = planHtml(plan);
      dialogBox().querySelector('[data-fd-apply]').disabled = false;
    } catch (err) {
      if (dialog !== ctx || seq !== ctx.seq) return;
      planEl.innerHTML = window.errorBox(err);
    }
  }

  function schedulePreview(ctx) {
    clearTimeout(ctx.timer);
    ctx.timer = setTimeout(() => { if (dialog === ctx) previewAssign(ctx); }, 400);
  }

  function readAssignUses(ctx) {
    const box = dialogBox();
    for (const u of ctx.uses) {
      const row = box.querySelector('[data-fd-auses="' + CSS.escape(useKey(u)) + '"]');
      if (!row) continue;
      const sub = row.querySelector('[data-fd-asub]').value.trim().replace(/^\/+|\/+$/g, '');
      if (sub) u.subpath = sub; else delete u.subpath;
      const w = row.querySelector('[data-fd-awrite]');
      if (w) { if (w.checked) u.write = true; else delete u.write; }
    }
  }

  // applyPlan posts the previewed hash, then polls the operation.
  async function applyPlan(ctx, url, body) {
    const box = dialogBox();
    const out = box.querySelector('[data-fd-op]');
    const apply = box.querySelector('[data-fd-apply]');
    apply.disabled = true;
    box.querySelectorAll('input').forEach(i => { i.disabled = true; });
    ctx.busy = true;
    box.querySelectorAll('[data-fd-close]').forEach(b => { b.disabled = true; });
    out.innerHTML = '<p class="fd-progress" data-fd-progress><span class="ps-spin" aria-hidden="true"></span> Applying… stopping the apps, saving the permissions snapshot, applying and verifying.</p>';
    let rec;
    try {
      const acc = await (await window.apiCall(url, 'POST', body)).json();
      rec = await runOp(acc, s => {
        const p = dialogBox() && dialogBox().querySelector('[data-fd-progress]');
        if (p) p.lastChild.textContent = ' Applying… ' + s + ' s (stopping the apps, saving the permissions snapshot, applying and verifying).';
      });
    } catch (err) {
      ctx.busy = false;
      box.querySelectorAll('[data-fd-close]').forEach(b => { b.disabled = false; });
      // A refused apply changed nothing: the uses stay editable.
      box.querySelectorAll('input').forEach(i => { i.disabled = false; });
      out.innerHTML = window.errorBox(err) + (err.status === 409 ? '<div class="inst-row"><button type="button" class="btn btn-secondary btn-sm" data-fd-repreview>Preview again</button></div>' : '');
      return;
    }
    ctx.busy = false;
    ctx.applied = true;
    box.querySelectorAll('[data-fd-close]').forEach(b => { b.disabled = false; });
    out.innerHTML = opResultHtml(rec);
    apply.hidden = true;
  }

  // ── Undo last fix ──────────────────────────────────────────────────

  function openUndo(id) {
    return new Promise(resolve => {
      const ctx = { kind: 'undo', folder: id, resolve };
      openDialog(ctx, head('Undo the last fix of ' + esc(folderName(id))) +
        '<p class="settings-empty">Nothing changes until you click Apply.</p><div data-fd-plan><p class="settings-empty">Loading the preview…</p></div><div data-fd-op></div>' +
        '<div class="op-modal-actions"><button type="button" class="btn btn-secondary btn-sm" data-fd-close>Close</button><button type="button" class="btn btn-primary btn-sm" data-fd-apply disabled>Apply</button></div>');
      window.apiPost('/api/folders/' + enc(id) + '/undo/preview', {}).then(plan => {
        if (dialog !== ctx) return;
        ctx.plan = plan;
        dialogBox().querySelector('[data-fd-plan]').innerHTML = planHtml(plan) +
          (plan.snapshot ? '<p class="settings-empty">Snapshot: <code>' + esc(plan.snapshot) + '</code></p>' : '');
        dialogBox().querySelector('[data-fd-apply]').disabled = false;
      }).catch(err => { if (dialog === ctx) dialogBox().querySelector('[data-fd-plan]').innerHTML = window.errorBox(err); });
    });
  }

  // openRecheck: Re-check identity (H2) — the stored and the current
  // device, inode and mount root; Apply stores the current ones.
  function openRecheck(id) {
    const ctx = { kind: 'recheck', folder: id };
    openDialog(ctx, head('Re-check the identity of ' + esc(folderName(id))) +
      '<p class="settings-empty">Nothing changes until you click Apply. Nothing on disk is changed, and no app is restarted.</p><div data-fd-plan><p class="settings-empty">Checking the folder…</p></div><div data-fd-op></div>' +
      '<div class="op-modal-actions"><button type="button" class="btn btn-secondary btn-sm" data-fd-close>Close</button><button type="button" class="btn btn-primary btn-sm" data-fd-apply disabled>Apply</button></div>');
    window.apiPost('/api/folders/' + enc(id) + '/recheck/preview', {}).then(plan => {
      if (dialog !== ctx) return;
      ctx.plan = plan;
      dialogBox().querySelector('[data-fd-plan]').innerHTML = planHtml(plan);
      dialogBox().querySelector('[data-fd-apply]').disabled = !plan.changed;
    }).catch(err => { if (dialog === ctx) dialogBox().querySelector('[data-fd-plan]').innerHTML = window.errorBox(err); });
  }

  async function applyRecheck(ctx) {
    const box = dialogBox();
    const ap = box.querySelector('[data-fd-apply]');
    const out = box.querySelector('[data-fd-op]');
    ap.disabled = true;
    try {
      await window.apiPost('/api/folders/' + enc(ctx.folder) + '/recheck/apply', { plan_hash: ctx.plan.plan_hash });
      if (dialog !== ctx) return;
      out.innerHTML = '<div class="inst-ok">The folder\'s new identity is stored.</div>';
      ctx.plan = null;
      refresh();
    } catch (err) {
      if (dialog !== ctx) return;
      out.innerHTML = window.errorBox(err) + (err.status === 409 ? '<div class="inst-row"><button type="button" class="btn btn-secondary btn-sm" data-fd-repreview>Check again</button></div>' : '');
    }
  }

  function bindModal(m) {
    m.addEventListener('click', e => {
      const ctx = dialog;
      const t = e.target;
      if (t === m || t.closest('[data-fd-close]')) { closeDialog(); return; }
      if (!ctx) return;
      if (t.closest('[data-fd-check]')) { checkPath(false); return; }
      if (t.closest('[data-fd-create]')) { createAsk(t.closest('[data-fd-create]')); return; }
      if (t.closest('[data-fd-create-go]')) { checkPath(true); return; }
      if (t.closest('[data-fd-create-cancel]')) { checkPath(false); return; }
      if (t.closest('[data-fd-repreview]')) {
        dialogBox().querySelector('[data-fd-op]').innerHTML = '';
        if (ctx.kind === 'assign') previewAssign(ctx); else if (ctx.kind === 'recheck') openRecheck(ctx.folder); else openUndo(ctx.folder);
        return;
      }
      const ap = t.closest('[data-fd-apply]');
      if (ap && !ap.disabled && ctx.plan) {
        if (ctx.kind === 'assign') applyPlan(ctx, '/api/folders/' + enc(ctx.folder) + '/assign/apply', { plan_hash: ctx.plan.plan_hash, uses: ctx.uses });
        else if (ctx.kind === 'undo') applyPlan(ctx, '/api/folders/' + enc(ctx.folder) + '/undo/apply', { plan_hash: ctx.plan.plan_hash });
        else if (ctx.kind === 'recheck') applyRecheck(ctx);
      }
    });
    m.addEventListener('submit', e => {
      e.preventDefault();
      if (dialog && dialog.kind === 'edit') saveEdit();
    });
    m.addEventListener('input', e => {
      const ctx = dialog;
      if (!ctx) return;
      const t = e.target;
      if (ctx.kind === 'assign' && (t.matches('[data-fd-asub]') || t.matches('[data-fd-awrite]'))) {
        if (e.type === 'input' && t.type === 'checkbox') return;
        readAssignUses(ctx);
        ctx.plan = null;
        dialogBox().querySelector('[data-fd-apply]').disabled = true;
        schedulePreview(ctx);
        return;
      }
      if (ctx.kind === 'edit') {
        if (t.id === 'fd-id') ctx.idEdited = t.value !== '';
        if (t.id === 'fd-name' && ctx.isNew && !ctx.idEdited) {
          const idIn = dialogBox().querySelector('#fd-id');
          if (idIn) idIn.value = slug(t.value);
        }
        if (t.id === 'fd-path') dialogBox().querySelector('[data-fd-check-result]').innerHTML = '';
        if (t.matches('[data-fd-sub]') || t.matches('[data-fd-write]')) {
          const tick = t.closest('[data-fd-use]').querySelector('[data-fd-tick]');
          if (!tick.disabled && (t.type !== 'checkbox' || t.checked) && t.value !== '') tick.checked = true;
        }
      }
    });
    m.addEventListener('change', e => {
      const ctx = dialog;
      if (ctx && ctx.kind === 'assign' && e.target.matches('[data-fd-awrite]')) {
        readAssignUses(ctx);
        // The plan no longer matches the uses until the preview is back.
        ctx.plan = null;
        dialogBox().querySelector('[data-fd-apply]').disabled = true;
        schedulePreview(ctx);
      }
    });
    document.addEventListener('keydown', e => {
      if (e.key === 'Escape' && dialog && m.classList.contains('visible')) closeDialog();
    });
  }

  // ── Settings → Local networks ──────────────────────────────────────

  // cidrNote: a line's problem or warning (the Hub decides; this only
  // says it early).
  function cidrNote(line) {
    const m = /^(.+)\/(\d{1,3})$/.exec(line);
    if (!m) return { bad: 'not a CIDR (address/prefix)' };
    const addr = m[1], bits = Number(m[2]);
    if (addr.includes(':')) {
      if (!/^[0-9a-fA-F:.]+$/.test(addr) || bits > 128) return { bad: 'not an IPv6 CIDR' };
      if (bits === 0) return { bad: 'a /0 prefix is refused (it is the whole internet)' };
      if (bits < 64) return { warn: 'broader than /64: more than one site\'s addresses count as local' };
      return {};
    }
    const parts = addr.split('.');
    if (parts.length !== 4 || parts.some(p => !/^\d{1,3}$/.test(p) || Number(p) > 255) || bits > 32) return { bad: 'not an IPv4 CIDR' };
    if (bits === 0) return { bad: 'a /0 prefix is refused (it is the whole internet)' };
    if (bits < 8) return { warn: 'broader than /8: a large share of the internet counts as local' };
    return {};
  }

  function netLines(el) {
    return el.querySelector('[data-ln-text]').value.split('\n').map(s => s.trim()).filter(Boolean);
  }

  function drawNetNotes(el) {
    const lines = netLines(el);
    let h = '';
    for (const l of lines) {
      const n = cidrNote(l);
      if (n.bad) h += '<li class="ln-bad"><code>' + esc(l) + '</code>: ' + esc(n.bad) + '</li>';
      else if (n.warn) h += '<li class="ln-warn" data-ln-broad><code>' + esc(l) + '</code>: ' + esc(n.warn) + '</li>';
    }
    if (!lines.length) h += '<li class="ln-warn">Empty: only loopback (127.0.0.0/8, ::1) counts as local.</li>';
    if (lines.length > 64) h += '<li class="ln-bad">At most 64 entries.</li>';
    el.querySelector('[data-ln-notes]').innerHTML = h ? '<ul class="inst-warns">' + h + '</ul>' : '';
  }

  function drawNets(el, v) {
    el.innerHTML = '<div class="settings-form" style="max-width:32rem">' +
      '<div class="form-group"><label for="ln-text">Local networks</label><small>One CIDR per line. ' +
      (v.default ? 'These are the defaults.' : 'Your own list (not the defaults).') + ' Loopback always counts as local.</small>' +
      '<textarea id="ln-text" rows="6" spellcheck="false" data-ln-text>' + esc((v.networks || []).join('\n')) + '</textarea></div>' +
      '<div data-ln-notes></div><div data-ln-result></div>' +
      '<div class="inst-row"><button type="button" class="btn btn-primary btn-sm" data-ln-save>Save</button>' +
      '<button type="button" class="btn btn-secondary btn-sm" data-ln-reset' + (v.default ? ' disabled' : '') + '>Reset to defaults</button></div></div>';
    drawNetNotes(el);
  }

  function renderLocalNetworks(el) {
    if (!el.dataset.lnBound) {
      el.dataset.lnBound = '1';
      el.addEventListener('input', e => { if (e.target.matches('[data-ln-text]')) drawNetNotes(el); });
      el.addEventListener('click', async e => {
        const save = e.target.closest('[data-ln-save]'), reset = e.target.closest('[data-ln-reset]');
        if (!save && !reset) return;
        const out = el.querySelector('[data-ln-result]');
        const lines = netLines(el);
        if (save && lines.some(l => cidrNote(l).bad)) { out.innerHTML = '<div class="op-msg inst-error">Fix the lines marked above first.</div>'; return; }
        try {
          const v = await window.apiPut('/api/settings/local-networks', { networks: reset ? null : lines });
          drawNets(el, v);
          el.querySelector('[data-ln-result]').innerHTML = '<div class="inst-ok">' + (reset ? 'Back to the defaults.' : 'Saved.') + ' The doctor uses these from its next run.</div>';
          if (window.PortcullisDoctor) window.PortcullisDoctor.refreshBadge();
        } catch (err) { out.innerHTML = window.errorBox(err); }
      });
    }
    el.innerHTML = '<p class="settings-empty">Loading…</p>';
    return window.apiGet('/api/settings/local-networks').then(v => drawNets(el, v)).catch(err => { el.innerHTML = window.errorBox(err); });
  }

  window.PortcullisFolders = { render, renderLocalNetworks, openAssign, openUndo, list, planHtml, runOp, opResultHtml, md };
})();
