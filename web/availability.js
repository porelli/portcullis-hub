// Portcullis Hub — an instance's availability on Kubernetes (contract
// §20.6): its priority, where it runs (Runs on) and the N−1 check
// (§20.7). Hub listener only, administrators only, Kubernetes only.
//
//   window.PortcullisAvailability.renderTab(id, pane)        the Availability tab
//   window.PortcullisAvailability.setPriority(id, priority)  the setup form's priority (after create)
//   window.PortcullisAvailability.tabHtml(view, draft)       (pure; tests)
//   window.PortcullisAvailability.bodyOf(draft)              (pure; tests)
//   window.PortcullisAvailability.n1Html(results)            (pure; tests)
//   window.PortcullisAvailability.notChanged(view)           (pure; tests)
//   window.PortcullisAvailability.readDraft(pane, draft)     (tests)
//
// GET /api/instances/{id}/availability   {priority, runs_on, nodes, n_minus_1}
// PUT /api/instances/{id}/availability   {priority, runs_on, confirm_n_minus_1?}
//     409 {error: "if <node> fails, <x> won't have room", n_minus_1}: a
//     raise to critical or high the N−1 check judges yellow, red or
//     unknown; the dialog shows it and offers "Raise anyway".
//
// Every value from the Hub (node names, classes, sites, pod names,
// refusals) is escaped (esc) before it goes into markup.
(function () {
  'use strict';

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
  const enc = encodeURIComponent;

  const PRIORITIES = [
    ['critical', 'Critical', 'kept running first: may push Normal and Low apps off a full node'],
    ['high', 'High', 'kept running before Normal and Low apps'],
    ['normal', 'Normal', 'the default'],
    ['low', 'Low', 'first to stop when the cluster is short of room; never pushes another app off'],
  ];
  const MODES = [
    ['anywhere', 'Any node', 'any node but the small ones'],
    ['prefer', 'Prefer', 'a class, a site or some nodes when they have room, else anywhere'],
    ['only', 'Only these nodes', 'never anywhere else (a small node only this way)'],
  ];
  const LEVEL_TEXT = { green: 'fine', yellow: 'degraded', red: 'not enough room', unknown: 'unknown' };

  // priorityOptions: the <option>s of a priority select (sel chosen).
  function priorityOptions(sel) {
    return PRIORITIES.map(([v, l]) => '<option value="' + v + '"' + (v === sel ? ' selected' : '') + '>' + l + '</option>').join('');
  }

  // draftOf: the editable copy of a view's choice.
  function draftOf(v) {
    const r = v.runs_on || { mode: 'anywhere' };
    const prefer = r.mode === 'prefer' ? (r.class ? 'class' : r.site ? 'site' : 'nodes') : 'class';
    return { priority: v.priority || 'normal', mode: r.mode || 'anywhere', prefer, cls: r.class || 'home', site: r.site || '', nodes: (r.nodes || []).slice() };
  }

  // bodyOf: the PUT's body for draft d (confirm: confirm_n_minus_1).
  function bodyOf(d, confirm) {
    const runs = { mode: d.mode };
    if (d.mode === 'prefer') {
      if (d.prefer === 'class') runs.class = d.cls;
      else if (d.prefer === 'site') runs.site = d.site;
      else runs.nodes = d.nodes.slice().sort();
    } else if (d.mode === 'only') runs.nodes = d.nodes.slice().sort();
    const b = { priority: d.priority, runs_on: runs };
    if (confirm) b.confirm_n_minus_1 = true;
    return b;
  }

  // n1Html: the N−1 results, one row per node.
  function n1Html(results) {
    if (!results || !results.length) return '<p class="settings-empty">No N−1 result.</p>';
    return '<ul class="policy-notes" data-avail-n1>' + results.map(r => {
      const lv = LEVEL_TEXT[r.level] ? r.level : 'unknown';
      const who = (r.unplaced || []).concat((r.evicted || []).map(p => p + ' (pushed off)'));
      return '<li data-n1-level="' + lv + '">If <code>' + esc(r.node) + '</code> fails: <strong>' + esc(LEVEL_TEXT[lv]) + '</strong>' +
        (who.length ? ' — ' + who.map(p => '<code>' + esc(p) + '</code>').join(', ') : '') + '</li>';
    }).join('') + '</ul>';
  }

  // tabHtml: the tab for view v and draft d.
  function tabHtml(v, d) {
    const sites = [...new Set((v.nodes || []).map(n => n.site).filter(Boolean))].sort();
    let h = '<div class="inst-section" data-avail-tab><h4>Priority</h4>' +
      '<label class="block" for="avail-priority">Priority</label>' +
      '<select id="avail-priority" data-avail-priority>' + priorityOptions(d.priority) + '</select>' +
      '<small>' + esc((PRIORITIES.find(p => p[0] === d.priority) || PRIORITIES[2])[2]) + '. Raising it to Critical or High first checks that the cluster still has room if any one node fails.</small>' +
      '<h4>Runs on</h4>';
    for (const [m, l, hint] of MODES) {
      h += '<label class="ps-check"><input type="radio" name="avail-mode" value="' + m + '" data-avail-mode' + (d.mode === m ? ' checked' : '') + '> ' + l +
        ' <small>(' + esc(hint) + ')</small></label>';
    }
    if (d.mode === 'prefer') {
      h += '<div class="inst-form" data-avail-prefer>' +
        '<label class="ps-check"><input type="radio" name="avail-prefer" value="class" data-avail-prefer-kind' + (d.prefer === 'class' ? ' checked' : '') + '> a class ' +
        '<select data-avail-class><option value="home"' + (d.cls === 'home' ? ' selected' : '') + '>home</option><option value="cloud"' + (d.cls === 'cloud' ? ' selected' : '') + '>cloud</option></select></label>' +
        '<label class="ps-check"><input type="radio" name="avail-prefer" value="site" data-avail-prefer-kind' + (d.prefer === 'site' ? ' checked' : '') + '> a site ' +
        '<select data-avail-site>' + sites.map(s => '<option value="' + esc(s) + '"' + (s === d.site ? ' selected' : '') + '>' + esc(s) + '</option>').join('') + '</select></label>' +
        '<label class="ps-check"><input type="radio" name="avail-prefer" value="nodes" data-avail-prefer-kind' + (d.prefer === 'nodes' ? ' checked' : '') + '> some nodes</label></div>';
    }
    if (d.mode === 'only' || (d.mode === 'prefer' && d.prefer === 'nodes')) {
      h += '<fieldset class="inst-form" data-avail-nodes><legend>Nodes</legend>';
      for (const n of v.nodes || []) {
        const off = d.mode === 'prefer' && n.small;
        h += '<label class="ps-check"><input type="checkbox" data-avail-node value="' + esc(n.name) + '"' + (d.nodes.includes(n.name) ? ' checked' : '') + (off ? ' disabled' : '') + '> <code>' +
          esc(n.name) + '</code> <small>' + esc(n.class || '—') + ' · ' + esc(n.site || '—') + (n.small ? ' · small: only with “Only these nodes”' : '') + '</small></label>';
      }
      h += '</fieldset>';
    }
    h += '<div class="inst-row"><button type="button" class="btn btn-primary btn-sm" data-avail-act="save">Save</button></div>' +
      '<small>An enabled instance restarts to apply the change.</small>' +
      '<div data-avail-status></div><div data-avail-confirm hidden></div>' +
      '<h4>If one node fails (N−1)</h4>' + n1Html(v.n_minus_1) + '</div>';
    return h;
  }

  // readDraft: d updated from the pane's inputs.
  function readDraft(pane, d) {
    const q = s => pane.querySelector(s);
    d.priority = q('[data-avail-priority]').value;
    const m = q('[data-avail-mode]:checked');
    if (m) d.mode = m.value;
    const k = q('[data-avail-prefer-kind]:checked');
    if (k) d.prefer = k.value;
    if (q('[data-avail-class]')) d.cls = q('[data-avail-class]').value;
    if (q('[data-avail-site]')) d.site = q('[data-avail-site]').value;
    // A disabled box (a small node under Prefer) is never sent.
    if (q('[data-avail-nodes]')) d.nodes = [...pane.querySelectorAll('[data-avail-node]:checked:not(:disabled)')].map(c => c.value);
    return d;
  }

  // put sends body; a 409 with n_minus_1 resolves {refused} instead of
  // throwing (the dialog's input).
  async function put(id, body) {
    const res = await fetch('/api/instances/' + enc(id) + '/availability', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const ct = res.headers.get('Content-Type') || '';
    if (res.ok) return { view: await res.json() };
    if (res.status === 409 && ct.includes('application/json')) {
      const j = await res.json().catch(() => null);
      if (j && Array.isArray(j.n_minus_1)) return { refused: j };
    }
    throw new Error((await res.text()).trim() || ('HTTP ' + res.status));
  }

  function setStatus(pane, t, warn) {
    const el = pane.querySelector('[data-avail-status]');
    if (!el) return;
    el.className = warn ? 'public-warn' : 'inst-ok';
    el.textContent = t;
  }

  // notChanged: the status after a refused (or cancelled) change: the
  // saved choice stays, and the form shows it again.
  function notChanged(v) {
    const p = PRIORITIES.find(x => x[0] === v.priority);
    return 'Not changed: still ' + (p ? p[1] : v.priority) + '.';
  }

  // confirmHtml: the N−1 dialog for a refused raise.
  function confirmHtml(j) {
    return '<div class="public-warn"><p data-avail-n1-error>' + esc(j.error) + '</p>' + n1Html(j.n_minus_1) +
      '<div class="inst-row"><button type="button" class="btn btn-danger btn-sm" data-avail-act="confirm">Raise anyway</button> ' +
      '<button type="button" class="btn btn-secondary btn-sm" data-avail-act="cancel">Cancel</button></div></div>';
  }

  async function renderTab(id, pane) {
    if (!pane) return;
    let v;
    try {
      v = await window.apiGet('/api/instances/' + enc(id) + '/availability');
    } catch (e) {
      pane.innerHTML = '<div class="public-warn" data-avail-error></div>';
      pane.firstChild.textContent = e.message;
      return;
    }
    const d = draftOf(v);
    const draw = () => { pane.innerHTML = tabHtml(v, d); };
    draw();
    pane.onchange = e => {
      if (!e.target.closest('[data-avail-tab]')) return;
      readDraft(pane, d);
      if (e.target.matches('[data-avail-mode], [data-avail-prefer-kind], [data-avail-priority]')) draw();
    };
    // refused: the body the N−1 check refused; "Raise anyway" resends
    // exactly it (never the form as edited since).
    let refused = null;
    const showRefusal = j => {
      Object.assign(d, draftOf(v));
      draw();
      setStatus(pane, notChanged(v), true);
      const box = pane.querySelector('[data-avail-confirm]');
      box.innerHTML = confirmHtml(j);
      box.hidden = false;
    };
    const send = async body => {
      setStatus(pane, 'Saving…', false);
      try {
        const r = await put(id, body);
        if (r.refused) {
          refused = Object.assign({}, body);
          delete refused.confirm_n_minus_1;
          showRefusal(r.refused);
          return;
        }
        refused = null;
        v = r.view;
        Object.assign(d, draftOf(v));
        draw();
        setStatus(pane, 'Saved.', false);
      } catch (err) {
        setStatus(pane, err.message, true);
      }
    };
    pane.onclick = e => {
      const b = e.target.closest && e.target.closest('[data-avail-act]');
      if (!b || !pane.contains(b)) return;
      switch (b.dataset.availAct) {
        case 'save': readDraft(pane, d); send(bodyOf(d, false)); break;
        case 'confirm': if (refused) send(Object.assign({}, refused, { confirm_n_minus_1: true })); break;
        case 'cancel': refused = null; Object.assign(d, draftOf(v)); draw(); setStatus(pane, notChanged(v), false); break;
      }
    };
  }

  // setPriority: the setup form's priority after the create (Runs on
  // stays Any node). A refused raise asks with the N−1 sentence; answers
  // '' (set), else why not.
  async function setPriority(id, priority) {
    if (!priority || priority === 'normal') return '';
    const body = { priority, runs_on: { mode: 'anywhere' } };
    try {
      let r = await put(id, body);
      if (r.refused) {
        if (!window.confirm(r.refused.error + '.\n\nRaise ' + id + ' to ' + priority + ' anyway?')) return 'kept at Normal: ' + r.refused.error;
        r = await put(id, Object.assign(body, { confirm_n_minus_1: true }));
        if (r.refused) return 'kept at Normal: ' + r.refused.error;
      }
      return '';
    } catch (err) {
      return 'kept at Normal: ' + err.message;
    }
  }

  const api = { renderTab, setPriority, tabHtml, bodyOf, n1Html, draftOf, priorityOptions, notChanged, readDraft };
  if (typeof window !== 'undefined') window.PortcullisAvailability = api;
  if (typeof module !== 'undefined') module.exports = api;
})();
