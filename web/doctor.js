// Portcullis Hub — the Doctor tab (contract §14.5–14.6, plan 2 Task 14).
// Hub listener only.
//
//   window.PortcullisDoctor.render(el)        the Doctor tab
//   window.PortcullisDoctor.badge(tabEl)      Problems + Warnings on the tab
//   window.PortcullisDoctor.refreshBadge()    the badge again (after a change)
//   window.PortcullisDoctor.lineFor(instance) → Promise<string>  "Doctor: 1 warning" (HTML, escaped), '' when nothing
//   window.PortcullisDoctor.findingsFor(instance, kinds) → Promise<[finding]>  that instance's
//       unmuted findings of those kinds (with fp, severity, title, fix_class, fix_kind); [] on error (F50)
//   <a href="#doctor" data-doctor-fp="<fp>" data-doctor-fix="<kind>">  anywhere: opens the Doctor tab at
//       that finding (scrolled to, highlighted) and, with data-doctor-fix, opens that fix's panel
//
// GET    /api/doctor                          the report
// POST   /api/doctor/scan                     run the disk checks → 202 (poll /api/doctor/op)
// POST   /api/doctor/findings/{fp}/preview    {params} → FixPlan (param fix picks a kind)
// POST   /api/doctor/findings/{fp}/apply      {plan_hash, params} → 202 {op_id, poll}
// POST   /api/doctor/findings/{fp}/mute       {reason, token} (409: the finding changed since)
// DELETE /api/doctor/findings/{fp}/mute
//
// Rules: every interpolation goes through escapeHtml; data-* attributes
// and delegated listeners only. A fix is always previewed, then applied
// with the preview's hash; the doctor itself never changes anything.
(function () {
  'use strict';

  const esc = s => window.escapeHtml(s);
  const enc = encodeURIComponent;
  const md = s => esc(s).replace(/`([^`]+)`/g, '<code>$1</code>').replace(/\*([^*\s][^*]*)\*/g, '<em>$1</em>');
  const CACHE_MS = 10000;

  const SEV = [['problem', 'Problems', 'bad'], ['warning', 'Warnings', 'warn'], ['info', 'Info', 'info']];
  const COUNT_WORDS = { problem: ['problem', 'problems'], warning: ['warning', 'warnings'], info: ['note', 'notes'] };
  const FIX_LABEL = {
    rebind_port: 'Rebind…',
    manage_as_folder: 'Manage as shared folder…',
    reapply_folder: 'Apply again…',
    undo_folder: 'Undo last fix…',
    revoke_leaver: 'Revoke the password…',
    person_tree_owner: 'Fix the owner…'
  };
  // The parameters each fix kind takes (the Hub refuses others).
  const FIX_PARAMS = {
    rebind_port: [['address', 'LAN address to bind to', '192.168.1.10']],
    manage_as_folder: [['name', 'Folder name (optional)', 'Family media'], ['id', 'Folder id (optional)', 'family-media']]
  };

  let rootEl = null;
  let cache = null; // {at, report}
  let folderNames = {};
  const fixes = {}; // fp → {kind, plan, params, busy}
  let tabEl = null;

  function fmtTime(s) {
    if (!s) return '';
    const d = new Date(s);
    return isNaN(d) ? String(s) : d.toLocaleString();
  }

  async function report(fresh) {
    if (!fresh && cache && Date.now() - cache.at < CACHE_MS) return cache.report;
    const r = await window.apiGet('/api/doctor');
    cache = { at: Date.now(), report: r };
    return r;
  }

  // ── badge and the app detail line ──────────────────────────────────

  function setBadge(r) {
    if (!tabEl) return;
    let b = tabEl.querySelector('.tab-badge');
    if (!b) { b = document.createElement('span'); b.className = 'tab-badge'; tabEl.appendChild(b); }
    const c = (r && r.counts) || {};
    const n = (c.problem || 0) + (c.warning || 0);
    b.textContent = n ? String(n) : '';
    b.hidden = !n;
    b.classList.toggle('bad', (c.problem || 0) > 0);
    b.title = n ? (c.problem || 0) + ' problem(s), ' + (c.warning || 0) + ' warning(s)' : '';
  }

  function badge(el) {
    tabEl = el;
    return report(true).then(setBadge).catch(() => setBadge(null));
  }

  function refreshBadge() {
    cache = null;
    if (tabEl) badge(tabEl);
  }

  function plural(n, one, many) { return n + ' ' + (n === 1 ? one : many); }

  async function lineFor(instance) {
    let r;
    try { r = await report(false); } catch (e) { return ''; }
    const c = { problem: 0, warning: 0, info: 0 };
    for (const f of r.findings || []) if (!f.muted && (f.instances || []).includes(instance)) c[f.severity] = (c[f.severity] || 0) + 1;
    const parts = [];
    if (c.problem) parts.push(plural(c.problem, 'problem', 'problems'));
    if (c.warning) parts.push(plural(c.warning, 'warning', 'warnings'));
    if (c.info) parts.push(plural(c.info, 'note', 'notes'));
    if (!parts.length) return '';
    const cls = c.problem ? 'bad' : c.warning ? 'warn' : 'info';
    return '<a href="#doctor" class="doctor-line ' + cls + '" data-doctor-goto="' + esc(instance) + '">Doctor: ' + esc(parts.join(', ')) + '</a>';
  }

  // findingsFor resolves to instance's unmuted findings whose kind is in
  // kinds (F50: the File sharing tab's LAN-only banner links each one).
  async function findingsFor(instance, kinds) {
    let r;
    try { r = await report(false); } catch (e) { return []; }
    return (r.findings || []).filter(f => !f.muted && (f.instances || []).includes(instance) && (kinds || []).includes(f.kind));
  }

  // A finding to show once the tab has drawn ({fp, fix}).
  let focus = null;

  function applyFocus() {
    const want = focus;
    focus = null;
    if (!want || !rootEl) return;
    const c = cardOf(want.fp);
    if (!c) {
      const out = rootEl.querySelector('[data-dr-scan-result]');
      if (out) out.innerHTML = '<div class="public-warn">That finding is gone: what produced it changed since.</div>';
      return;
    }
    const d = c.closest('details');
    if (d) d.open = true;
    c.scrollIntoView({ behavior: 'smooth', block: 'center' });
    c.classList.add('flash-target');
    setTimeout(() => c.classList.remove('flash-target'), 2500);
    if (want.fix && c.querySelector('[data-dr-fix="' + CSS.escape(want.fix) + '"]')) openFix(want.fp, want.fix);
  }

  // ── the tab ────────────────────────────────────────────────────────

  async function render(el) {
    rootEl = el;
    if (!el.dataset.drBound) { el.dataset.drBound = '1'; bind(el); }
    if (!el.innerHTML) el.innerHTML = '<p class="settings-empty">Loading…</p>';
    let r;
    try {
      r = await report(true);
      try { for (const f of await window.PortcullisFolders.list()) folderNames[f.id] = f.name; } catch (e) { /* ids then */ }
    } catch (err) { el.innerHTML = window.errorBox(err); return; }
    setBadge(r);
    // H11 M7: never a full redraw while a fix runs (its result would land
    // in a detached card): only the other cards are updated in place.
    if (Object.values(fixes).some(fx => fx && fx.busy)) { patch(r); applyFocus(); return; }
    draw(r);
    applyFocus();
  }

  function patch(r) {
    const byFP = {};
    for (const f of r.findings || []) byFP[f.fp] = f;
    rootEl.querySelectorAll('[data-dr-fp]').forEach(c => {
      const fp = c.dataset.drFp;
      if (fixes[fp] && fixes[fp].busy) return;
      const f = byFP[fp];
      if (!f) { c.remove(); return; }
      delete fixes[fp];
      c.outerHTML = card(f);
    });
  }

  function lastScan(r) {
    let t = null;
    for (const s of r.scans || []) if (!t || s.at > t) t = s.at;
    return t;
  }

  function draw(r) {
    const el = rootEl;
    const c = r.counts || {};
    const last = lastScan(r);
    let h = '<div class="dr-head"><div class="dr-counts">' +
      SEV.map(([k, , cls]) => '<span class="pill ' + cls + '">' + esc(plural(c[k] || 0, ...COUNT_WORDS[k])) + '</span>').join('') +
      (r.muted ? '<span class="pill">' + esc(r.muted) + ' muted</span>' : '') + '</div>' +
      '<div class="inst-row" style="margin-top:0"><button type="button" class="btn btn-secondary btn-sm" data-dr-scan>Run disk checks</button>' +
      '<span class="settings-empty" data-dr-last>Last disk scan: ' + (last ? esc(fmtTime(last)) : 'never') + '</span></div></div>' +
      '<div data-dr-scan-result></div>';
    const findings = r.findings || [];
    const live = findings.filter(f => !f.muted), muted = findings.filter(f => f.muted);
    if (!findings.length) h += '<p class="settings-empty">The doctor found nothing.</p>';
    for (const [k, l, cls] of SEV) {
      const fs = live.filter(f => f.severity === k);
      if (!fs.length) continue;
      h += '<section class="dr-group" data-dr-sev="' + esc(k) + '"><h3 class="category-title dr-' + cls + '">' + esc(l) + ' (' + fs.length + ')</h3>' + fs.map(card).join('') + '</section>';
    }
    if (muted.length) {
      h += '<details class="dr-group dr-muted" data-dr-sev="muted"><summary class="category-title">Muted (' + muted.length + ')</summary>' + muted.map(card).join('') + '</details>';
    }
    el.innerHTML = h;
  }

  function sevPill(s) {
    const cls = s === 'problem' ? 'bad' : s === 'warning' ? 'warn' : 'info';
    return '<span class="pill ' + cls + '">' + esc(s) + '</span>';
  }

  function card(f) {
    let h = '<div class="dr-card dr-' + esc(f.severity) + '" data-dr-fp="' + esc(f.fp) + '" data-dr-token="' + esc(f.token || '') + '">';
    h += '<div class="dr-title">' + sevPill(f.severity) + ' <span data-dr-title>' + md(f.title) + '</span></div>';
    if (f.why) h += '<div class="dr-why">' + md(f.why) + '</div>';
    if (f.fix_text) h += '<div class="dr-fixtext">' + md(f.fix_text) + '</div>';
    const facts = [];
    if ((f.instances || []).length) facts.push('Apps: ' + f.instances.map(i => '<code>' + esc(i) + '</code>').join(', '));
    if ((f.folders || []).length) facts.push('Folders: ' + f.folders.map(id => esc(folderNames[id] || id)).join(', '));
    if ((f.paths || []).length) facts.push('Paths: ' + f.paths.map(p => '<code>' + esc(p) + '</code>').join(', '));
    if (facts.length) h += '<div class="dr-facts">' + facts.join(' · ') + '</div>';
    if (f.partial) h += '<div class="public-warn">Based on a partial disk scan: the real counts can be higher.</div>';
    if (f.muted) h += '<div class="dr-muted-by">Muted by ' + esc(f.muted.actor) + ' on ' + esc(fmtTime(f.muted.at)) + ': ' + esc(f.muted.reason) + '</div>';
    h += '<div class="inst-row dr-actions">';
    if (f.fix_class === 'one_click' && !f.muted) {
      for (const k of [f.fix_kind, ...(f.more_fix_kinds || [])].filter(Boolean)) {
        h += '<button type="button" class="btn btn-primary btn-sm" data-dr-fix="' + esc(k) + '">' + esc(FIX_LABEL[k] || 'Fix…') + '</button>';
      }
    }
    if ((f.steps || []).length) h += '<button type="button" class="btn btn-secondary btn-sm" data-dr-explain>Explain</button>';
    if (f.link && f.link.instance && f.link.tab) h += '<button type="button" class="btn btn-secondary btn-sm" data-dr-open-tab="' + esc(f.link.tab) + '" data-dr-open="' + esc(f.link.instance) + '">' + (f.link.tab === 'ai' ? 'Open AI tab' : 'Open app') + '</button>';
    else if (f.link && f.link.instance) h += '<button type="button" class="btn btn-secondary btn-sm" data-dr-open="' + esc(f.link.instance) + '" data-dr-option="' + esc(f.link.option || '') + '">Open setting</button>';
    h += f.muted ? '<button type="button" class="btn btn-secondary btn-sm" data-dr-unmute>Unmute</button>'
      : '<button type="button" class="btn btn-secondary btn-sm" data-dr-mute>Mute</button>';
    h += '</div>';
    if ((f.steps || []).length) h += '<ol class="dr-steps" data-dr-steps hidden>' + f.steps.map(s => '<li>' + md(s) + '</li>').join('') + '</ol>';
    h += '<div data-dr-panel></div></div>';
    return h;
  }

  function cardOf(fp) { return rootEl.querySelector('[data-dr-fp="' + CSS.escape(fp) + '"]'); }

  // ── fixes ──────────────────────────────────────────────────────────

  function openFix(fp, kind) {
    const c = cardOf(fp);
    const panel = c.querySelector('[data-dr-panel]');
    const cur = fixes[fp];
    if (cur && cur.busy) return;
    if (cur && cur.kind === kind && panel.innerHTML) { panel.innerHTML = ''; delete fixes[fp]; return; }
    fixes[fp] = { kind };
    const ps = FIX_PARAMS[kind] || [];
    let h = '<div class="inst-panel dr-fix" data-dr-fixkind="' + esc(kind) + '"><strong>' + esc((FIX_LABEL[kind] || 'Fix…').replace('…', '')) + '</strong>';
    if (ps.length) {
      h += '<div class="inst-row">' + ps.map(([k, l, ph]) => '<label class="settings-empty">' + esc(l) +
        ' <input type="text" data-dr-param="' + esc(k) + '" placeholder="' + esc(ph) + '" spellcheck="false"></label>').join('') +
        '<button type="button" class="btn btn-secondary btn-sm" data-dr-preview>Preview</button></div>';
    }
    h += '<div data-dr-plan>' + (ps.length ? '' : '<p class="settings-empty">Loading the preview…</p>') + '</div><div data-dr-op></div>' +
      '<div class="inst-row"><button type="button" class="btn btn-primary btn-sm" data-dr-apply disabled>Apply</button>' +
      '<button type="button" class="btn btn-secondary btn-sm" data-dr-cancel>Cancel</button></div></div>';
    panel.innerHTML = h;
    if (ps.length) panel.querySelector('[data-dr-param]').focus();
    else previewFix(fp);
  }

  function readParams(c, kind) {
    const p = { fix: kind };
    c.querySelectorAll('[data-dr-param]').forEach(i => { const v = i.value.trim(); if (v) p[i.dataset.drParam] = v; });
    return p;
  }

  async function previewFix(fp) {
    const fx = fixes[fp];
    const c = cardOf(fp);
    if (!fx || !c) return;
    const out = c.querySelector('[data-dr-plan]');
    const apply = c.querySelector('[data-dr-apply]');
    apply.disabled = true;
    fx.plan = null;
    fx.params = readParams(c, fx.kind);
    const seq = (fx.seq = (fx.seq || 0) + 1);
    out.innerHTML = '<p class="settings-empty">Loading the preview…</p>';
    try {
      const plan = await window.apiPost('/api/doctor/findings/' + enc(fp) + '/preview', { params: fx.params });
      if (fixes[fp] !== fx || seq !== fx.seq) return;
      fx.plan = plan;
      let h = '<ul class="fd-lines" data-dr-lines>' + (plan.lines || []).map(l => '<li>' + md(l) + '</li>').join('') + '</ul>' + window.warningsList(plan.warnings);
      if (plan.assign) {
        const a = plan.assign;
        if ((a.restarts || []).length) h += '<p class="fd-downtime">Downtime: ' + a.restarts.map(x => '<code>' + esc(x) + '</code>').join(', ') + ' stopped for ' + esc(a.downtime || 'a moment') + ', then started.</p>';
        if (a.disk && a.disk.partial) h += '<div class="public-warn">The scan was partial: the counts are at least these.</div>';
      }
      out.innerHTML = h;
      apply.disabled = false;
    } catch (err) {
      if (fixes[fp] !== fx || seq !== fx.seq) return;
      out.innerHTML = window.errorBox(err);
    }
  }

  async function applyFix(fp) {
    const fx = fixes[fp];
    const c = cardOf(fp);
    if (!fx || !fx.plan || !c) return;
    const out = c.querySelector('[data-dr-op]');
    const apply = c.querySelector('[data-dr-apply]');
    apply.disabled = true;
    fx.busy = true;
    c.querySelectorAll('[data-dr-panel] input, [data-dr-preview], [data-dr-cancel]').forEach(x => { x.disabled = true; });
    out.innerHTML = '<p class="fd-progress" data-dr-progress><span class="ps-spin" aria-hidden="true"></span> Applying…</p>';
    let rec;
    try {
      const acc = await (await window.apiCall('/api/doctor/findings/' + enc(fp) + '/apply', 'POST', { plan_hash: fx.plan.plan_hash, params: fx.params })).json();
      rec = await window.PortcullisFolders.runOp(acc, s => {
        const p = c.querySelector('[data-dr-progress]');
        if (p) p.lastChild.textContent = ' Applying… ' + s + ' s';
      });
    } catch (err) {
      fx.busy = false;
      c.querySelectorAll('[data-dr-panel] input, [data-dr-preview], [data-dr-cancel]').forEach(x => { x.disabled = false; });
      out.innerHTML = window.errorBox(err) + (err.status === 409 ? '<p class="settings-empty">Preview again: the setup changed since.</p>' : '');
      if (err.status === 409) fx.plan = null;
      return;
    }
    fx.busy = false;
    out.innerHTML = window.PortcullisFolders.opResultHtml(rec) +
      '<div class="inst-row"><button type="button" class="btn btn-secondary btn-sm" data-dr-reload>Run the doctor again</button></div>';
    apply.hidden = true;
    const cancel = c.querySelector('[data-dr-cancel]');
    if (cancel) { cancel.disabled = false; cancel.textContent = 'Close'; }
    cache = null;
    refreshBadge();
  }

  // ── mute ───────────────────────────────────────────────────────────

  function openMute(fp) {
    const c = cardOf(fp);
    const panel = c.querySelector('[data-dr-panel]');
    delete fixes[fp];
    panel.innerHTML = '<div class="inst-panel"><div class="inst-row" style="margin-top:0"><label class="settings-empty">Why mute it? ' +
      '<input type="text" data-dr-reason maxlength="200" placeholder="known, handled by the firewall" spellcheck="true" style="min-width:20rem"></label>' +
      '<button type="button" class="btn btn-primary btn-sm" data-dr-mute-go>Mute</button><button type="button" class="btn btn-secondary btn-sm" data-dr-cancel>Cancel</button></div>' +
      '<p class="settings-empty">A muted finding comes back by itself when what produced it changes.</p><div data-dr-op></div></div>';
    panel.querySelector('[data-dr-reason]').focus();
  }

  async function mute(fp, on) {
    const c = cardOf(fp);
    const out = c.querySelector('[data-dr-op]') || c.querySelector('[data-dr-panel]');
    try {
      if (on) {
        const reason = c.querySelector('[data-dr-reason]').value.trim();
        if (!reason) { out.innerHTML = '<div class="op-msg inst-error">Give a reason.</div>'; return; }
        // The token is the finding as shown: a finding that changed since
        // (a severity rise) is refused (409), never muted unseen.
        await window.apiCall('/api/doctor/findings/' + enc(fp) + '/mute', 'POST', { reason, token: c.dataset.drToken || '' });
      } else {
        await window.apiCall('/api/doctor/findings/' + enc(fp) + '/mute', 'DELETE');
      }
      render(rootEl);
    } catch (err) {
      out.innerHTML = window.errorBox(err) + (on && err.status === 409
        ? '<div class="inst-row"><button type="button" class="btn btn-secondary btn-sm" data-dr-reload>Run the doctor again</button></div>' : '');
    }
  }

  // ── scan ───────────────────────────────────────────────────────────

  async function scan(btn) {
    const out = rootEl.querySelector('[data-dr-scan-result]');
    btn.disabled = true;
    out.innerHTML = '<p class="fd-progress" data-dr-progress><span class="ps-spin" aria-hidden="true"></span> Scanning the shared folders and shared paths…</p>';
    try {
      const acc = await (await window.apiCall('/api/doctor/scan', 'POST', {})).json();
      const rec = await window.PortcullisFolders.runOp(acc, s => {
        const p = rootEl.querySelector('[data-dr-progress]');
        if (p) p.lastChild.textContent = ' Scanning… ' + s + ' s';
      });
      await render(rootEl);
      const r = rec.result || {};
      const msg = rec.ok ? '<div class="inst-ok">Disk checks done: ' + esc(r.scanned || '0') + ' of ' + esc(r.targets || '0') + ' scanned' +
        (Number(r.failed) ? ', ' + esc(r.failed) + ' failed' : '') + (Number(r.skipped) ? ', ' + esc(r.skipped) + ' skipped' : '') + '.</div>'
        : window.errorBox({ status: rec.status, message: rec.error || 'the scan failed' });
      rootEl.querySelector('[data-dr-scan-result]').innerHTML = msg + window.warningsList(rec.warnings);
    } catch (err) {
      out.innerHTML = window.errorBox(err);
      btn.disabled = false;
    }
  }

  function bind(el) {
    el.addEventListener('click', e => {
      const t = e.target;
      let b;
      if ((b = t.closest('[data-dr-scan]'))) { scan(b); return; }
      const c = t.closest('[data-dr-fp]');
      if (!c) return;
      const fp = c.dataset.drFp;
      if ((b = t.closest('[data-dr-fix]'))) { openFix(fp, b.dataset.drFix); return; }
      if (t.closest('[data-dr-preview]')) { previewFix(fp); return; }
      if ((b = t.closest('[data-dr-apply]')) && !b.disabled) { applyFix(fp); return; }
      if (t.closest('[data-dr-cancel]')) { if (!(fixes[fp] && fixes[fp].busy)) { delete fixes[fp]; c.querySelector('[data-dr-panel]').innerHTML = ''; } return; }
      if (t.closest('[data-dr-reload]')) { render(el); return; }
      if (t.closest('[data-dr-explain]')) { const s = c.querySelector('[data-dr-steps]'); s.hidden = !s.hidden; return; }
      // A tab link (AI findings): the app's tab when the page has one
      // (openAppTab, the AI tab's task), else the app itself.
      if ((b = t.closest('[data-dr-open-tab]'))) {
        if (typeof window.openAppTab === 'function') window.openAppTab(b.dataset.drOpen, b.dataset.drOpenTab);
        else window.openSettingAt(b.dataset.drOpen, '');
        return;
      }
      if ((b = t.closest('[data-dr-open]'))) { window.openSettingAt(b.dataset.drOpen, b.dataset.drOption); return; }
      if (t.closest('[data-dr-mute]')) { openMute(fp); return; }
      if (t.closest('[data-dr-mute-go]')) { mute(fp, true); return; }
      if (t.closest('[data-dr-unmute]')) { mute(fp, false); }
    });
    el.addEventListener('input', e => {
      const t = e.target;
      if (!t.matches('[data-dr-param]')) return;
      const c = t.closest('[data-dr-fp]');
      const fx = fixes[c.dataset.drFp];
      if (fx) { fx.plan = null; c.querySelector('[data-dr-apply]').disabled = true; }
    });
    el.addEventListener('keydown', e => {
      const t = e.target;
      if (e.key !== 'Enter') return;
      const c = t.closest('[data-dr-fp]');
      if (!c) return;
      if (t.matches('[data-dr-param]')) { e.preventDefault(); previewFix(c.dataset.drFp); }
      if (t.matches('[data-dr-reason]')) { e.preventDefault(); mute(c.dataset.drFp, true); }
    });
  }

  // "Doctor: …" lines and finding links anywhere: open the tab (at the
  // finding, data-doctor-fp, with its fix panel, data-doctor-fix).
  document.addEventListener('click', e => {
    const a = e.target.closest('[data-doctor-goto], [data-doctor-fp]');
    if (!a) return;
    e.preventDefault();
    e.stopPropagation();
    focus = a.dataset.doctorFp ? { fp: a.dataset.doctorFp, fix: a.dataset.doctorFix || '' } : null;
    const tab = document.querySelector('.tab[data-tab="doctor"]');
    if (tab) tab.click();
  });

  window.PortcullisDoctor = { render, badge, refreshBadge, lineFor, findingsFor };
})();
