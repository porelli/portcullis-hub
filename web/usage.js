// Portcullis Hub — the Usage tab and the instance Usage tab (contract
// §11.11, plan 2026-11-15). Hub listener only.
//
//   window.PortcullisUsage.render(el, view)    the Usage tab: view apps | containers
//   window.PortcullisUsage.renderInstance(el, id)  an instance page's Usage tab
//   window.PortcullisUsage.stop()              stops polling (leaving the tab)
//
// GET /api/usage                       the overview (the Hub's cache; polled every 15 s while visible)
// GET /api/usage/instances/{id}        one instance with its last hour
// GET /api/usage/export.csv?view=…     the CSV download
// GET /api/usage/storage               the Storage view (the storage cache)
// POST /api/usage/storage/measure      {instance?} → 202; progress in the operation panel (key _usage),
//                                      whose Stop posts /api/usage/storage/op/stop
//
// Rules: every interpolation goes through esc() or a number formatter
// (fmtBytes, fmtCores, fmtRate, fmtPct, fmtNum) or an *Html() helper
// that does; data-* attributes and delegated listeners only; null is
// "not measured", never 0; sizes in binary units (KiB, MiB, GiB, TiB);
// sparklines are SVG built from numbers only.
(function () {
  'use strict';

  const esc = s => window.escapeHtml(s == null ? '' : String(s));
  const enc = encodeURIComponent;
  const POLL_MS = 15000;
  const UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  const NOT_MEASURED = '<span class="usage-nm" title="no figure: see the reason on the row">not measured</span>';

  let timer = null;
  let current = null; // {kind: 'tab'|'instance', el, view, id, sort, dir, filter, open}
  let visHooked = false;

  const isNum = v => typeof v === 'number' && isFinite(v);

  // fmtBytes: binary units; null → not measured.
  function fmtBytes(n) {
    if (!isNum(n)) return NOT_MEASURED;
    let v = Number(n), i = 0;
    while (v >= 1024 && i < UNITS.length - 1) { v /= 1024; i++; }
    return esc((i === 0 ? v.toFixed(0) : v.toFixed(v >= 100 ? 0 : 1)) + ' ' + UNITS[i]);
  }
  function fmtRate(n) {
    if (!isNum(n)) return NOT_MEASURED;
    return fmtBytes(n) + '/s';
  }
  function fmtCores(n) {
    if (!isNum(n)) return NOT_MEASURED;
    return esc(Number(n).toFixed(2) + ' CPU');
  }
  function fmtPct(p) { return isNum(p) ? esc(Number(p).toFixed(0) + ' %') : ''; }
  function fmtNum(n) { return isNum(n) ? esc(Number(n).toFixed(0)) : NOT_MEASURED; }

  // geHtml: "≥ " in front of a lower bound (a total with a null member).
  function geHtml(partial, innerHtml) { return partial && innerHtml !== NOT_MEASURED ? '≥ ' + innerHtml : innerHtml; }

  function fmtAge(iso) {
    if (!iso) return 'never';
    const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
    if (s < 60) return esc(Number(s).toFixed(0) + ' s ago');
    if (s < 3600) return esc(Number(s / 60).toFixed(0) + ' min ago');
    if (s < 172800) return esc(Number(s / 3600).toFixed(0) + ' h ago');
    return esc(Number(s / 86400).toFixed(0) + ' days ago');
  }

  // hostOf: the host of the server g runs on (contract §11.11 hosts).
  function hostOf(v, g) {
    return (v && v.hosts && v.hosts[(g && g.server) || 'primary']) || null;
  }

  // cpuHtml: cores, with the share of the limit, else of the host's CPUs.
  function cpuHtml(sample, host, partial) {
    if (!isNum(sample.cpu_cores)) return NOT_MEASURED;
    const of = isNum(sample.cpu_limit_cores) && sample.cpu_limit_cores > 0 ? sample.cpu_limit_cores : (host && isNum(host.cpus) ? host.cpus : null);
    const pctHtml = of ? '<span class="usage-sub">' + fmtPct(100 * sample.cpu_cores / of) + '</span>' : '';
    return geHtml(partial, fmtCores(sample.cpu_cores)) + ' ' + pctHtml;
  }

  // memBarHtml: the working set against its limit (amber 80 %, red 90 %);
  // without a limit, against the host's memory, flagged "no limit".
  function memBarHtml(sample, host, partial) {
    if (!isNum(sample.mem_bytes)) return NOT_MEASURED;
    const limited = isNum(sample.mem_limit_bytes) && sample.mem_limit_bytes > 0;
    const of = limited ? sample.mem_limit_bytes : (host && isNum(host.memory_bytes) ? host.memory_bytes : null);
    const pct = of ? Math.min(100, 100 * sample.mem_bytes / of) : 0;
    const cls = !limited ? 'usage-bar-none' : pct >= 90 ? 'usage-bar-bad' : pct >= 80 ? 'usage-bar-warn' : 'usage-bar-ok';
    let tailHtml = '';
    if (limited) tailHtml = ' / ' + fmtBytes(sample.mem_limit_bytes) + ' <span class="usage-sub">' + fmtPct(pct) + '</span>';
    else if (sample.mem_limit_bytes === 0) tailHtml = ' <span class="usage-sub">no limit</span>';
    else tailHtml = ' <span class="usage-sub">partly unlimited</span>';
    return '<div class="usage-bar ' + esc(cls) + '"><span style="width:' + esc(Number(pct).toFixed(1)) + '%"></span></div>' +
      geHtml(partial, fmtBytes(sample.mem_bytes)) + tailHtml;
  }

  function netHtml(s, partial) {
    if (!isNum(s.net_rx_bps) && !isNum(s.net_tx_bps)) return NOT_MEASURED;
    return '↓ ' + geHtml(partial, fmtRate(s.net_rx_bps)) + '<br>↑ ' + geHtml(partial, fmtRate(s.net_tx_bps));
  }
  function blkHtml(s, partial) {
    if (!isNum(s.blk_read_bps) && !isNum(s.blk_write_bps)) return NOT_MEASURED;
    return 'r ' + geHtml(partial, fmtRate(s.blk_read_bps)) + '<br>w ' + geHtml(partial, fmtRate(s.blk_write_bps));
  }
  function pidsHtml(s, partial) {
    if (!isNum(s.pids)) return NOT_MEASURED;
    return geHtml(partial, fmtNum(s.pids)) + (isNum(s.pids_limit) && s.pids_limit > 0 ? ' / ' + fmtNum(s.pids_limit) : '');
  }

  // offCellsHtml: a stopped container's cells (it isn't sampled).
  function offCellsHtml(n) { return '<td class="usage-sub">—</td>'.repeat(n); }

  // sparkHtml: an inline SVG polyline of numbers only (null: a gap).
  function sparkHtml(values, w, h) {
    const nums = values.filter(isNum);
    if (!nums.length) return '<span class="usage-sub">no history yet</span>';
    const max = Math.max.apply(null, nums) || 1;
    const step = values.length > 1 ? w / (values.length - 1) : 0;
    const lines = [];
    let pts = [];
    values.forEach((v, i) => {
      if (!isNum(v)) { if (pts.length) lines.push(pts); pts = []; return; }
      pts.push(Number(i * step).toFixed(1) + ',' + Number(h - (h - 2) * v / max - 1).toFixed(1));
    });
    if (pts.length) lines.push(pts);
    return '<svg class="usage-spark" width="' + Number(w).toFixed(0) + '" height="' + Number(h).toFixed(0) + '" viewBox="0 0 ' +
      Number(w).toFixed(0) + ' ' + Number(h).toFixed(0) + '" aria-hidden="true">' +
      lines.map(ptsHtml => '<polyline fill="none" stroke="currentColor" stroke-width="1.5" points="' + ptsHtml.join(' ') + '"></polyline>').join('') + '</svg>';
  }

  // STATUS_WORDS: a group's status in the app page's words (a failed job:
  // "setup job failed", like the instance list).
  const STATUS_WORDS = { job_failed: 'setup job failed', not_measured: 'not measured' };
  // JOB_WORDS: a job container's state (the app page's JOB_WORDS).
  const JOB_WORDS = { done: 'setup job done', failed: 'setup job failed', running: 'setup job running', pending: 'setup job pending' };

  // jobsDoneText: "setup job done" / "3 setup jobs done" ('' for none).
  function jobsDoneText(n) {
    return !n ? '' : n === 1 ? JOB_WORDS.done : n + ' setup jobs done';
  }

  function statusHtml(g) {
    const cls = g.status === 'running' ? 'ok' : g.status === 'stopped' ? 'off' : g.status === 'not_measured' ? 'info' : g.status === 'job_failed' ? 'bad' : 'warn';
    const whyHtml = g.why ? ' <span class="usage-sub">' + esc(g.why) + '</span>' : '';
    const doneHtml = g.jobs_done ? ' <span class="usage-sub">· ' + esc(jobsDoneText(g.jobs_done)) + '</span>' : '';
    return '<span class="usage-status usage-status-' + esc(cls) + '">' + esc(STATUS_WORDS[g.status] || g.status) + '</span>' + doneHtml + whyHtml;
  }

  // stateText: a container's state word (a job's in JOB_WORDS); a done
  // job's row is greyed out (usage-dim) (it ran and finished, as it should).
  function stateText(c) {
    return c.job && JOB_WORDS[c.job_state] ? JOB_WORDS[c.job_state] : c.state;
  }
  function doneJob(c) {
    return !!c.job && c.job_state === 'done';
  }

  async function getJSON(url) {
    const r = await fetch(url, { headers: { Accept: 'application/json' } });
    if (!r.ok) {
      let msg = String(r.status).concat(' ', r.statusText);
      try { const b = await r.json(); if (b && b.error) msg = b.error; } catch (_) { /* text */ }
      throw new Error(msg);
    }
    return r.json();
  }

  // ── polling ──
  function schedule() {
    clearTimeout(timer);
    timer = null;
    if (!current || document.visibilityState !== 'visible') return;
    timer = setTimeout(() => { if (current) refresh(); }, POLL_MS);
  }
  function hookVisibility() {
    if (visHooked) return;
    visHooked = true;
    document.addEventListener('visibilitychange', () => {
      if (!current) return;
      if (document.visibilityState === 'visible') refresh(); else { clearTimeout(timer); timer = null; }
    });
  }
  function stop() {
    clearTimeout(timer);
    timer = null;
    current = null;
  }
  async function refresh() {
    const c = current;
    if (!c) return;
    if (!c.el.isConnected) { stop(); return; }
    try {
      if (c.kind === 'instance') {
        if (c.el.hasAttribute('data-ipane') && !c.el.classList.contains('active')) { stop(); return; }
        const g = await getJSON('/api/usage/instances/' + enc(c.id));
        if (current !== c) return;
        let host = null;
        try { host = hostOf(await getJSON('/api/usage'), g); } catch (_) { /* the bars show no host share */ }
        if (current !== c) return;
        drawInstance(c, g, host);
      } else {
        const v = await getJSON('/api/usage');
        if (current !== c) return;
        c.data = v;
        if (c.view === 'storage') {
          try { c.storage = await getJSON('/api/usage/storage'); c.storageErr = ''; } catch (e) { c.storageErr = e.message; }
          if (current !== c) return;
        }
        draw(c);
      }
    } catch (e) {
      if (current !== c) return;
      c.el.innerHTML = '<p class="settings-empty">Usage can\'t be read: ' + esc(e.message) + '</p>';
    }
    schedule();
  }

  // ── the Usage tab ──
  const APP_COLS = [
    ['name', 'App'], ['cpu', 'CPU'], ['mem', 'Memory'], ['net', 'Net ↓/↑'], ['blk', 'Disk IO r/w'], ['pids', 'PIDs']
  ];
  function sortKey(g, k) {
    const t = g.totals || {};
    switch (k) {
      case 'cpu': return isNum(t.cpu_cores) ? t.cpu_cores : -1;
      case 'mem': return isNum(t.mem_bytes) ? t.mem_bytes : -1;
      case 'net': return (isNum(t.net_rx_bps) ? t.net_rx_bps : 0) + (isNum(t.net_tx_bps) ? t.net_tx_bps : 0);
      case 'blk': return (isNum(t.blk_read_bps) ? t.blk_read_bps : 0) + (isNum(t.blk_write_bps) ? t.blk_write_bps : 0);
      case 'pids': return isNum(t.pids) ? t.pids : -1;
    }
    return (g.name || g.instance || '').toLowerCase();
  }

  function headerHtml(v) {
    let appsMem = null, appsCPU = null;
    (v.apps || []).forEach(g => {
      if (isNum(g.totals.mem_bytes)) { appsMem = appsMem || 0; appsMem += g.totals.mem_bytes; }
      if (isNum(g.totals.cpu_cores)) { appsCPU = appsCPU || 0; appsCPU += g.totals.cpu_cores; }
    });
    const core = v.core && v.core.totals ? v.core.totals : {};
    let html = '<div class="usage-strip">';
    const host = hostOf(v, null);
    html += '<span>Host: ' + (host && isNum(host.cpus) ? fmtNum(host.cpus) + ' CPUs' : NOT_MEASURED) + ', ' + fmtBytes(host ? host.memory_bytes : null) + '</span>';
    html += '<span>Apps: ' + fmtCores(appsCPU) + ', ' + fmtBytes(appsMem) + '</span>';
    html += '<span>Core: ' + fmtCores(core.cpu_cores) + ', ' + fmtBytes(core.mem_bytes) + '</span>';
    html += '<span class="' + esc(v.stale ? 'usage-stale' : '') + '">sampled ' + fmtAge(v.sampled_at) + '</span>';
    if (v.not_shown > 0) html += '<span class="usage-sub">' + fmtNum(v.not_shown) + esc(v.not_shown === 1 ? ' other container on this engine is not shown' : ' other containers on this engine are not shown') + '</span>';
    if (v.over_limit > 0) html += '<span class="usage-sub">' + fmtNum(v.over_limit) + esc(' not measured: over the 256-container limit') + '</span>';
    if (v.metrics_scraped) html += '<a href="' + esc(grafanaURL()) + '" target="_blank" rel="noopener">History in Grafana ↗</a>';
    html += '</div>';
    if (v.engine && v.engine.verified === false) html += '<div class="usage-warn">The container engine is not verified: ' + esc(v.engine.why || '') + '. The figures below are the last ones measured.</div>';
    return html;
  }

  function grafanaURL() {
    const host = location.hostname.replace(/^hub\./, 'metrics.');
    return ['https://', host, '/d/portcullis-usage'].join('');
  }

  function navHtml(view) {
    const btnHtml = (k, label) => '<button type="button" class="btn btn-sm ' + esc(view === k ? 'btn-primary' : '') + '" data-usage-view="' + esc(k) + '">' + esc(label) + '</button>';
    return '<div class="usage-nav">' + btnHtml('apps', 'By app') + btnHtml('containers', 'By container') + btnHtml('storage', 'Storage') +
      ' <a class="btn btn-secondary btn-sm" href="/api/usage/export.csv?view=' + esc(view) + '" download>CSV</a>' +
      ' <a class="usage-sub" href="/api/usage/export.csv?view=apps" download>apps.csv</a> · <a class="usage-sub" href="/api/usage/export.csv?view=containers" download>containers.csv</a>' +
      ' · <a class="usage-sub" href="/api/usage/export.csv?view=storage" download>storage.csv</a></div>';
  }

  function containerRowsHtml(g, host, indent) {
    return (g.containers || []).map(c => {
      const errHtml = c.error ? ' <span class="usage-sub">' + esc(c.error) + '</span>' : '';
      const nameHtml = c.helper ? esc(c.service) + ' <span class="usage-sub">×' + fmtNum(c.number) + '</span>' : esc(c.service) + '<span class="usage-sub">.' + fmtNum(c.number) + '</span>';
      const oomHtml = c.oom_killed ? ' <span class="usage-status usage-status-warn">OOM killed</span>' : '';
      const rowCls = doneJob(c) ? 'usage-crow usage-dim' : 'usage-crow';
      return '<tr class="' + esc(rowCls) + '"' + (c.job ? ' data-usage-job="' + esc(c.job_state || '') + '"' : '') + '>' + '<td class="' + esc(indent ? 'usage-indent' : '') + '">' + nameHtml + ' <span class="usage-sub">' + esc(stateText(c)) + '</span>' + errHtml + oomHtml + '</td>' +
        (c.state === 'running' ? '<td>' + cpuHtml(c.sample, host, false) + '</td><td>' + memBarHtml(c.sample, host, false) + '</td>' +
        '<td>' + netHtml(c.sample, false) + '</td><td>' + blkHtml(c.sample, false) + '</td><td>' + pidsHtml(c.sample, false) + '</td>' : offCellsHtml(5)) + '</tr>';
    }).join('');
  }

  function groupRowHtml(g, host, key, open) {
    const caretHtml = '<button type="button" class="usage-caret" data-usage-toggle="' + esc(key) + '" aria-expanded="' + esc(open ? 'true' : 'false') + '">' + esc(open ? '▾' : '▸') + '</button>';
    const nameHtml = g.instance && g.instance !== 'core' ? '<a href="#apps/' + esc(enc(g.instance)) + '/usage">' + esc(g.name || g.instance) + '</a>' : esc(g.name);
    const tmplHtml = g.template ? ' <span class="usage-sub">' + esc(g.template) + '</span>' : '';
    const t = g.totals || {};
    let html = '<tr class="usage-grow">' + '<td>' + caretHtml + ' ' + nameHtml + tmplHtml + '<br>' + statusHtml(g) + '</td>' +
      '<td>' + cpuHtml(t, host, g.partial) + '</td><td>' + memBarHtml(t, host, g.partial) + '</td>' +
      '<td>' + netHtml(t, g.partial) + '</td><td>' + blkHtml(t, g.partial) + '</td><td>' + pidsHtml(t, g.partial) + '</td></tr>';
    if (open) html += containerRowsHtml(g, host, true);
    return html;
  }

  function appsTableHtml(c) {
    const v = c.data;
    const apps = (v.apps || []).slice();
    apps.sort((a, b) => {
      const x = sortKey(a, c.sort), y = sortKey(b, c.sort);
      const r = x < y ? -1 : x > y ? 1 : 0;
      return c.dir === 'desc' ? -r : r;
    });
    let html = '<table class="usage-table"><thead><tr>' + APP_COLS.map(([k, label]) =>
      '<th><button type="button" class="usage-sort" data-usage-sort="' + esc(k) + '">' + esc(label) + esc(c.sort === k ? (c.dir === 'desc' ? ' ▼' : ' ▲') : '') + '</button></th>').join('') + '</tr></thead><tbody>';
    if (!apps.length) html += '<tr><td colspan="6" class="settings-empty">No app is running.</td></tr>';
    apps.forEach(g => { const key = ['app', g.instance].join(':'); html += groupRowHtml(g, hostOf(v, g), key, !!c.open[key]); });
    (v.unknown_projects || []).forEach(g => { const key = ['unknown', g.name].join(':'); html += groupRowHtml(g, hostOf(v, g), key, !!c.open[key]); });
    if (v.core) html += groupRowHtml(v.core, hostOf(v, v.core), 'core', !!c.open.core);
    return html + '</tbody></table>';
  }

  function containersTableHtml(c) {
    const v = c.data, f = (c.filter || '').toLowerCase();
    const groups = (v.apps || []).concat(v.unknown_projects || [], v.core ? [v.core] : []);
    let html = '<input type="search" class="usage-filter" placeholder="Filter by app or service" value="' + esc(c.filter || '') + '" data-usage-filter>';
    html += '<table class="usage-table"><thead><tr><th>App</th><th>Container</th><th>CPU</th><th>Memory</th><th>Net ↓/↑</th><th>Disk IO r/w</th><th>PIDs</th><th>Limits</th></tr></thead><tbody>';
    let n = 0;
    groups.forEach(g => (g.containers || []).forEach(ct => {
      const app = g.name || g.instance || '';
      if (f && !(app.toLowerCase().includes(f) || (g.instance || '').includes(f) || (ct.service || '').toLowerCase().includes(f))) return;
      n++;
      const l = ct.limits || {};
      const limitsHtml = 'mem ' + (l.mem_bytes > 0 ? fmtBytes(l.mem_bytes) : esc('no limit')) + ', cpu ' + (isNum(l.cpu_cores) ? fmtCores(l.cpu_cores) : esc('no limit')) +
        ', pids ' + (l.pids > 0 ? fmtNum(l.pids) : esc('no limit'));
      html += '<tr' + (doneJob(ct) ? ' class="usage-dim"' : '') + (ct.job ? ' data-usage-job="' + esc(ct.job_state || '') + '"' : '') + '><td>' + esc(app) + '</td><td>' + esc(ct.service) + '<span class="usage-sub">.' + fmtNum(ct.number) + ' ' + esc(ct.id12) + ' ' + esc(stateText(ct)) + '</span>' +
        (ct.error ? ' <span class="usage-sub">' + esc(ct.error) + '</span>' : '') + '</td>' +
        (ct.state === 'running' ? '<td>' + cpuHtml(ct.sample, hostOf(v, g), false) + '</td><td>' + memBarHtml(ct.sample, hostOf(v, g), false) + '</td><td>' + netHtml(ct.sample, false) + '</td>' +
        '<td>' + blkHtml(ct.sample, false) + '</td><td>' + pidsHtml(ct.sample, false) + '</td>' : offCellsHtml(5)) + '<td class="usage-sub">' + limitsHtml + '</td></tr>';
    }));
    if (!n) html += '<tr><td colspan="8" class="settings-empty">No container matches.</td></tr>';
    return html + '</tbody></table>';
  }

  function draw(c) {
    if (!c.data && c.view !== 'storage') { c.el.innerHTML = '<p class="settings-empty">Loading…</p>'; return; }
    let bodyHtml;
    if (c.view === 'storage') bodyHtml = storageViewHtml(c);
    else bodyHtml = (c.view === 'containers' ? containersTableHtml(c) : appsTableHtml(c));
    const focus = document.activeElement && document.activeElement.hasAttribute && document.activeElement.hasAttribute('data-usage-filter');
    c.el.innerHTML = navHtml(c.view) + (c.data ? headerHtml(c.data) : '') + bodyHtml;
    if (focus) {
      const i = c.el.querySelector('[data-usage-filter]');
      if (i) { i.focus(); i.setSelectionRange(i.value.length, i.value.length); }
    }
  }

  function bind(el) {
    if (el.dataset.usageBound) return;
    el.dataset.usageBound = '1';
    el.addEventListener('click', ev => {
      const c = current;
      if (!c || c.el !== el) return;
      const v = ev.target.closest('[data-usage-view]');
      if (v) {
        c.view = v.dataset.usageView;
        history.replaceState(null, '', '#usage/' + enc(c.view));
        draw(c);
        if (c.view === 'storage') loadStorage(c);
        return;
      }
      const m = ev.target.closest('[data-usage-measure]');
      if (m) { measure(m.dataset.usageMeasure, m); return; }
      const s = ev.target.closest('[data-usage-sort]');
      if (s) {
        const k = s.dataset.usageSort;
        c.dir = c.sort === k && c.dir === 'desc' ? 'asc' : 'desc';
        if (k === 'name' && c.sort !== k) c.dir = 'asc';
        c.sort = k;
        draw(c);
        return;
      }
      const t = ev.target.closest('[data-usage-toggle]');
      if (t) { c.open[t.dataset.usageToggle] = !c.open[t.dataset.usageToggle]; draw(c); }
    });
    el.addEventListener('input', ev => {
      const c = current;
      if (!c || c.el !== el || !ev.target.hasAttribute('data-usage-filter')) return;
      c.filter = ev.target.value;
      draw(c);
    });
  }

  function render(el, view) {
    stop();
    hookVisibility();
    current = { kind: 'tab', el, view: view === 'containers' || view === 'storage' ? view : 'apps', sort: 'name', dir: 'asc', filter: '', open: {}, data: null };
    bind(el);
    draw(current);
    if (current.view === 'storage') loadStorage(current);
    refresh();
  }

  // ── the instance page's Usage tab ──
  function drawInstance(c, g, host) {
    let html = '<div class="inst-section"><h4>Usage</h4><p class="usage-sub">Live, from the Hub\'s last sample (every 15 s); the last hour below.</p>';
    html += '<table class="usage-table"><thead><tr><th>Container</th><th>CPU</th><th>Memory</th><th>Net ↓/↑</th><th>Disk IO r/w</th><th>PIDs</th></tr></thead><tbody>';
    html += groupRowHtml(g, host, 'self', true) + '</tbody></table>';
    const hist = g.history || { t: [], cpu_cores: {}, mem_bytes: {} };
    const keys = Object.keys(hist.mem_bytes || {}).sort();
    if (keys.length) {
      html += '<table class="usage-table usage-hist"><thead><tr><th>Container</th><th>CPU, last hour</th><th>Memory, last hour</th></tr></thead><tbody>';
      keys.forEach(k => {
        html += '<tr><td>' + esc(k) + '</td><td>' + sparkHtml(hist.cpu_cores[k] || [], 160, 28) + '</td><td>' + sparkHtml(hist.mem_bytes[k] || [], 160, 28) + '</td></tr>';
      });
      html += '</tbody></table>';
    }
    html += '</div>';
    html += instanceStorageHtml(g);
    c.el.innerHTML = html;
  }

  function renderInstance(el, id) {
    stop();
    hookVisibility();
    current = { kind: 'instance', el, id, open: {} };
    el.innerHTML = '<p class="settings-empty">Loading…</p>';
    bind(el);
    refresh();
  }

  // ── the Storage view ──
  const DIM_AFTER_S = 172800; // figures older than 48 h are dimmed
  const DISK_WARN = 90, DISK_BAD = 97; // used %
  const STOP_WORDS = { time: 'stopped after 2 min', entries: 'stopped after 2,000,000 entries', hard_links: 'too many hard links',
    failed: 'some entries couldn\'t be read', names: 'a directory with too many names', depth: 'too deep' };

  async function loadStorage(c) {
    try { c.storage = await getJSON('/api/usage/storage'); c.storageErr = ''; } catch (e) { c.storageErr = e.message; }
    if (current === c) draw(c);
  }

  function ageSeconds(iso) { return iso ? (Date.now() - new Date(iso).getTime()) / 1000 : Infinity; }

  // sizeHtml: an item's figure — "not measured" with why, "≥ … (stopped
  // after …)" for a capped one, dimmed past 48 h, its age beside it.
  function sizeHtml(it) {
    if (!isNum(it.alloc_bytes)) {
      const whyHtml = it.error ? ' <span class="usage-sub">' + esc(it.error.replace(/^(not measured:? ?)+/, '')) + '</span>' : (it.note ? ' <span class="usage-sub">' + esc(it.note) + '</span>' : '');
      return NOT_MEASURED + whyHtml;
    }
    let figHtml = fmtBytes(it.alloc_bytes);
    if (it.partial) figHtml = '≥ ' + figHtml + ' <span class="usage-sub">(' + esc(STOP_WORDS[it.partial_reason] || 'the figure is a lower bound') + ')</span>';
    const dimHtml = ageSeconds(it.measured_at) > DIM_AFTER_S ? 'usage-dim' : '';
    const titleHtml = isNum(it.apparent_bytes) ? ' title="apparent size ' + fmtBytes(it.apparent_bytes) + '"' : '';
    return '<span class="' + esc(dimHtml) + '"' + titleHtml + '>' + figHtml + ' <span class="usage-sub">measured ' + fmtAge(it.measured_at) + '</span></span>';
  }

  const KIND_WORDS = { volume: 'volume', bind: 'host path', folder: 'shared folder', layer: 'writable layer', image: 'image', hub_files: 'Hub-managed files' };

  function itemRowHtml(it) {
    const kindHtml = esc(KIND_WORDS[it.kind] || it.kind);
    let noteHtml = '';
    if (it.kind === 'image') noteHtml = ' <span class="usage-sub">shared, not in total</span>';
    else if (it.shared_with && it.shared_with.length) noteHtml = ' <span class="usage-sub">shared with ' + esc(it.shared_with.join(', ')) + ', not in total</span>';
    else if (it.kind === 'folder') noteHtml = ' <span class="usage-sub">shared, not in total</span>';
    const targetHtml = it.kind === 'hub_files' ? esc('Hub-managed files') : '<code>' + esc(it.target) + '</code>';
    const figHtml = it.kind === 'hub_files' ? '<span class="usage-sub">not measured (small, written by the Hub)</span>' : sizeHtml(it);
    return '<tr><td>' + kindHtml + '</td><td>' + targetHtml + noteHtml + '</td><td>' + figHtml + '</td></tr>';
  }

  function diskStripHtml(disks) {
    if (!disks || !disks.length) return '<p class="usage-sub">No filesystem measured yet.</p>';
    return '<div class="usage-disks">' + diskCellsHtml(disks) + '</div>';
  }

  function diskCellsHtml(disks) {
    return disks.map(d => {
      const pct = Number(d.used_percent) || 0;
      const cls = pct >= DISK_BAD ? 'usage-bar-bad' : pct >= DISK_WARN ? 'usage-bar-warn' : 'usage-bar-ok';
      return '<div class="usage-disk"><div class="usage-bar ' + esc(cls) + '"><span style="width:' + esc(Number(pct).toFixed(1)) + '%"></span></div>' +
        fmtBytes(d.total_bytes - d.free_bytes) + ' / ' + fmtBytes(d.total_bytes) + ' <span class="usage-sub">' + fmtPct(pct) + ' used, ' + fmtBytes(d.free_bytes) + ' free</span>' +
        '<br><span class="usage-sub">' + esc((d.owners || []).join(', ') || 'nothing measured on it') + '</span></div>';
    }).join('');
  }

  function groupStorageHtml(g, withButton) {
    const btnHtml = withButton ? ' <button type="button" class="btn btn-secondary btn-sm" data-usage-measure="' + esc(g.instance) + '">Measure</button>' : '';
    const totalHtml = isNum(g.total_alloc_bytes) ? geHtml(g.partial, fmtBytes(g.total_alloc_bytes)) : NOT_MEASURED;
    return '<h5 class="usage-h5">' + esc(g.name || g.instance) + ' <span class="usage-sub">total ' + totalHtml + '</span>' + btnHtml + '</h5>' +
      '<table class="usage-table"><tbody>' + (g.items || []).map(itemRowHtml).join('') + '</tbody></table>';
  }

  function storageViewHtml(c) {
    if (c.storageErr) return '<p class="settings-empty">Storage can\'t be read: ' + esc(c.storageErr) + '</p>';
    const v = c.storage;
    if (!v) return '<p class="settings-empty">Loading…</p>';
    let html = '<div class="usage-nav"><button type="button" class="btn btn-primary btn-sm" data-usage-measure="">Measure now</button>' +
      ' <span class="usage-sub">last full run ' + fmtAge(v.measured_at) + '</span>' +
      (v.running_op ? ' <span class="usage-status usage-status-info">' + esc('measuring…') + '</span>' : '') +
      (v.metrics_scraped ? ' <a href="' + esc(grafanaURL()) + '" target="_blank" rel="noopener">History in Grafana ↗</a>' : '') + '</div>';
    html += '<h4 class="usage-h4">Disks</h4>' + diskStripHtml(v.disks);
    html += '<h4 class="usage-h4">Apps</h4>';
    if (!(v.apps || []).length) html += '<p class="usage-sub">No app storage measured yet: Measure now.</p>';
    (v.apps || []).forEach(g => { html += groupStorageHtml(g, true); });
    html += '<h4 class="usage-h4">Shared folders</h4>';
    if (!(v.folders || []).length) html += '<p class="usage-sub">No shared folders.</p>';
    else {
      html += '<table class="usage-table"><thead><tr><th>Folder</th><th>Size</th><th>Used by</th></tr></thead><tbody>' + folderRowsHtml(v.folders) + '</tbody></table>';
    }
    html += '<h4 class="usage-h4">Core</h4>';
    if (!(v.core || []).length) html += '<p class="usage-sub">Core volumes not measured yet.</p>';
    else html += '<table class="usage-table"><tbody>' + coreRowsHtml(v.core) + '</tbody></table>';
    return html;
  }

  function coreRowsHtml(items) { return items.map(itemRowHtml).join(''); }

  function folderRowsHtml(folders) {
    return folders.map(f =>
        '<tr><td>' + esc(f.name || f.id) + ' <span class="usage-sub">' + esc(f.id) + '</span></td><td>' +
        sizeHtml({ alloc_bytes: f.alloc_bytes, partial: f.partial, measured_at: f.measured_at, note: f.note }) +
        '</td><td>' + esc((f.used_by || []).join(', ') || '—') + '</td></tr>').join('');
  }

  function instanceStorageHtml(g) {
    const st = g.storage;
    let html = '<div class="inst-section"><h4>Storage</h4>';
    if (!st) html += '<p class="usage-sub">Not measured yet. <button type="button" class="btn btn-secondary btn-sm" data-usage-measure="' + esc(g.instance) + '">Measure</button></p>';
    else html += groupStorageHtml(st, true);
    return html + '</div>';
  }

  // measure: POST the measurement, then follow it in the operation panel
  // (its Stop ends it between targets).
  async function measure(instance, btn) {
    if (btn) btn.disabled = true;
    try {
      const r = await fetch('/api/usage/storage/measure', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(instance ? { instance: instance } : {}) });
      if (!r.ok) {
        let msg = String(r.status);
        try { const b = await r.json(); if (b && b.error) msg = b.error; } catch (_) { /* text */ }
        throw new Error(msg);
      }
      const op = await r.json();
      if (typeof window.openOpPanel === 'function') window.openOpPanel('_usage', null);
      if (typeof window.showToast === 'function') window.showToast('Measuring storage', 'success');
      return op;
    } catch (e) {
      if (typeof window.showToast === 'function') window.showToast('Measure: '.concat(e.message), 'error');
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  window.PortcullisUsage = { render, renderInstance, stop };
})();
