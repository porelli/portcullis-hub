// Portcullis Hub — the Usage tab's Share view (#usage/share): who uses
// how much of each server, as donuts (donut.js) with a legend table.
//
//   PortcullisShare.render(el, {view, storage, server, window, app?, onWindow})
//       view: GET /api/usage?window=<window>; storage: GET
//       /api/usage/storage; server: a hosts key (default primary); app:
//       one app's containers instead of the server's apps; onWindow(w):
//       the admin picked another window (usage.js reads the view again).
//   PortcullisShare.update(view, storage)   new data (the 15 s poll)
//   PortcullisShare.act(kind, value)        what a click does (back, app,
//       window, server); the delegated listeners call it
//
// Donuts: CPU (of the host's CPUs), memory (of its RAM), disk IO (of its
// disk IO), network (of the apps' measured traffic: there's no host-wide
// figure) and one per disk for storage. A figure that isn't measured is
// "not measured" with its reason, never 0; a host with a why (a worker
// unreachable, Kubernetes) shows that text instead of its donuts.
// Accessibility: every slice is a row of the legend table (label, value,
// share), colour is never the only cue; an app's slice and its legend
// name are keyboard focusable and open its containers.
// Rules: markup only from esc()/num() and the *Html helpers; no inline
// styles (the colours are CSS classes); the HTML is replaced only when it
// changed, and focus is put back on the control with the same key.
(function () {
  'use strict';

  const D = window.PortcullisDonut;
  const esc = D.esc, num = D.num;
  const isNum = v => typeof v === 'number' && isFinite(v);
  const UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  const METRICS = [['cpu', 'CPU'], ['mem', 'Memory'], ['io', 'Disk IO'], ['net', 'Network']];
  const FOCUS_KEYS = ['data-share-app', 'data-share-window', 'data-share-back', 'data-share-server'];

  let st = null; // {el, view, storage, server, window, app, onWindow, html}

  function fmtBytes(n) {
    let v = Number(n), i = 0;
    while (v >= 1024 && i < UNITS.length - 1) { v /= 1024; i++; }
    return (i === 0 ? v.toFixed(0) : v.toFixed(v >= 100 ? 0 : 1)) + ' ' + UNITS[i];
  }
  function fmtVal(v, unit) {
    if (!isNum(v)) return 'not measured';
    if (unit === 'cores') return v.toFixed(2) + ' CPU';
    if (unit === 'bps') return fmtBytes(v) + '/s';
    return fmtBytes(v);
  }
  function fmtPct(v, total) {
    if (!isNum(v) || !(total > 0)) return '';
    const p = (100 * v) / total;
    return p > 0 && p < 1 ? '< 1 %' : p.toFixed(0) + ' %';
  }

  // ── markup ─────────────────────────────────────────────────
  function controlsHtml(view) {
    const hosts = Object.keys(view.hosts || {}).sort((a, b) => (a === 'primary' ? -1 : b === 'primary' ? 1 : a.localeCompare(b)));
    let h = '<div class="share-bar">';
    if (hosts.length > 1) {
      const optsHtml = hosts.map(k => '<option value="' + esc(k) + '"' + (k === st.server ? ' selected' : '') + '>' +
        esc(((view.hosts[k] || {}).name || k) + (k === 'primary' ? ' (primary)' : '')) + '</option>').join('');
      h += '<label class="share-pick">Server <select data-share-server>' + optsHtml + '</select></label>';
    }
    const winHtml = (k, label) => '<button type="button" class="share-win" data-share-window="' + esc(k) + '" aria-pressed="' + (st.window === k ? 'true' : 'false') + '">' + esc(label) + '</button>';
    h += '<span class="share-wins" role="group" aria-label="Window">' + winHtml('last', 'Last sample') + winHtml('1h', '1 h average') + '</span></div>';
    return h;
  }
  function legendHtml(d) {
    const rowsHtml = d.slices.map(s => {
      const nameHtml = s.app ? '<button type="button" class="share-link" data-share-app="' + esc(s.app) + '">' + esc(s.label) + '</button>' : esc(s.label);
      return '<tr><td><span class="share-swatch ' + esc(s.cls) + '" aria-hidden="true"></span>' + nameHtml + '</td><td>' + esc(fmtVal(s.value, d.unit)) + '</td><td>' + esc(fmtPct(s.value, d.total)) + '</td></tr>';
    });
    for (const m of d.missing) rowsHtml.push('<tr class="share-nm"><td><span class="share-swatch share-none" aria-hidden="true"></span>' + esc(m.label) + '</td><td colspan="2">not measured: ' + esc(m.why) + '</td></tr>');
    if (!rowsHtml.length) return '';
    return '<table class="share-legend"><thead><tr><th>Who</th><th>Use</th><th>Share</th></tr></thead><tbody>' + rowsHtml.join('') + '</tbody></table>';
  }
  function centerOf(d) {
    if (d.why || !(d.total > 0)) return '';
    const used = d.slices.filter(s => s.key !== 'free').reduce((a, s) => a + s.value, 0);
    return d.slices.some(s => s.key === 'free') ? fmtPct(used, d.total) + ' used' : fmtVal(used, d.unit);
  }
  function cardHtml(title, d, app) {
    const whyHtml = d.why ? '<p class="share-cap usage-nm">not measured: ' + esc(d.why) + '</p>' : '';
    return '<figure class="share-card" aria-label="' + esc(title) + '"><figcaption class="share-title">' + esc(title) + '</figcaption>' +
      D.svg(d.slices, { size: 160, hole: 0.62, total: d.total, why: d.why, center: centerOf(d), app }) +
      (d.caption ? '<p class="share-cap">' + esc(d.caption) + '</p>' : '') + whyHtml + legendHtml(d) + '</figure>';
  }
  function serverHtml(view, storage) {
    const host = (view.hosts || {})[st.server];
    if (!host) return '<p class="settings-empty">No figures for this server.</p>';
    if (host.why) return '<p class="usage-warn" data-share-why>' + esc(host.why) + '</p><p class="usage-sub">The apps\' own figures are under By app and By container.</p>';
    let h = '<div class="share-grid">' + METRICS.map(([m, label]) => cardHtml(label, D.slices(view, m, st.server, {}), '')).join('') + '</div>';
    const ds = D.disks(storage, st.server);
    h += '<h4 class="share-h">Storage</h4>';
    if (!ds.length) h += '<p class="usage-sub">Storage is not measured yet on this server (Storage → Measure now).</p>';
    else {
      const disksHtml = ds.map(k => cardHtml(['Disk', k.dev, '·', fmtBytes(k.total_bytes)].join(' '), D.slices(view, 'storage', st.server, { storage, dev: k.dev }), '')).join('');
      h += '<div class="share-grid">' + disksHtml + '</div>';
    }
    return h;
  }
  function appHtml(view, storage) {
    const g = (view.apps || []).find(x => x.instance === st.app);
    if (!g) return '<p class="settings-empty">This app has no figures any more.</p>';
    let h = '<div class="share-bar"><button type="button" class="btn btn-sm" data-share-back>← All apps</button> <strong class="share-app">' + esc(g.name || g.instance) + '</strong> <span class="usage-sub">by container</span></div>';
    h += '<div class="share-grid">' + METRICS.map(([m, label]) => cardHtml(label, D.drill(view, st.app, m, {}), st.app)).join('') +
      cardHtml('Storage', D.drill(view, st.app, 'storage', { storage }), st.app) + '</div>';
    return h;
  }
  function pageHtml() {
    const view = st.view || {}, storage = st.storage || {};
    if (!(view.hosts || {})[st.server]) st.server = 'primary';
    return '<div class="share" data-share>' + controlsHtml(view) + (st.app ? appHtml(view, storage) : serverHtml(view, storage)) + '</div>';
  }

  // ── drawing (only when the markup changed; focus kept) ─────
  function focusKey() {
    const a = document.activeElement;
    if (!a || !st || !st.el.contains(a) || !a.getAttribute) return null;
    for (const k of FOCUS_KEYS) if (a.getAttribute(k) != null) return [k, a.getAttribute(k), a.tagName];
    return null;
  }
  function draw() {
    if (!st) return;
    const html = pageHtml();
    if (html === st.html) return;
    const key = focusKey();
    st.el.innerHTML = html;
    st.html = html;
    if (key && st.el.querySelectorAll) {
      for (const n of st.el.querySelectorAll('[' + key[0] + ']')) {
        if (n.getAttribute(key[0]) === key[1] && n.tagName === key[2]) { n.focus(); break; }
      }
    }
  }

  function act(kind, value) {
    if (!st) return;
    const was = st.app;
    if (kind === 'back') st.app = '';
    else if (kind === 'app') st.app = String(value || '');
    else if (kind === 'server') { st.server = String(value || 'primary'); st.app = ''; }
    else if (kind === 'window' && (value === 'last' || value === '1h') && value !== st.window) {
      st.window = value;
      if (st.onWindow) st.onWindow(value);
    }
    draw();
    // Keyboard users land on the next thing to do: "← All apps" in an
    // app, that app's name in the legend on the way back.
    if (st.el.querySelector) {
      const n = kind === 'app' ? st.el.querySelector('[data-share-back]') : kind === 'back' && was ? st.el.querySelector('button[data-share-app="' + cssEsc(was) + '"]') : null;
      if (n) n.focus();
    }
  }
  function cssEsc(v) { return window.CSS && CSS.escape ? CSS.escape(v) : String(v).replace(/[^a-z0-9-]/gi, ''); }

  function bind(el) {
    if (el.dataset.shareBound) return;
    el.dataset.shareBound = '1';
    el.addEventListener('click', e => {
      const t = e.target;
      if (!t.closest) return;
      let n;
      if ((n = t.closest('[data-share-back]'))) act('back');
      else if ((n = t.closest('[data-share-app]'))) act('app', n.getAttribute('data-share-app'));
      else if ((n = t.closest('[data-share-window]'))) act('window', n.getAttribute('data-share-window'));
    });
    el.addEventListener('keydown', e => {
      if (e.key !== 'Enter' && e.key !== ' ') return;
      const n = e.target.closest && e.target.closest('[data-share-app]');
      // A slice (an SVG path) isn't a button: Enter and Space open it.
      if (n && n.tagName.toLowerCase() === 'path') { e.preventDefault(); act('app', n.getAttribute('data-share-app')); }
    });
    el.addEventListener('change', e => {
      if (e.target.hasAttribute && e.target.hasAttribute('data-share-server')) act('server', e.target.value);
    });
  }

  function render(el, o) {
    const same = st && st.el === el;
    st = {
      el, view: o.view, storage: o.storage, server: o.server || (same ? st.server : 'primary'), window: o.window || 'last',
      app: o.app != null ? o.app : (same ? st.app : ''), onWindow: o.onWindow, html: same ? st.html : null,
    };
    if (el.dataset) bind(el);
    draw();
  }
  function update(view, storage) {
    if (!st) return;
    st.view = view;
    if (storage !== undefined) st.storage = storage;
    draw();
  }

  window.PortcullisShare = { render, update, act, state: () => st && { server: st.server, window: st.window, app: st.app } };
})();
