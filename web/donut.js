// Portcullis Hub — inline-SVG donuts for the Usage tab's Share view
// (share.js). No chart library, no inline styles: colours are CSS
// classes (.share-c0 … .share-c7, .share-more, .share-other,
// .share-free, …), so the page's CSP needs nothing more.
//
//   PortcullisDonut.svg(slices, opts) → string
//       slices: [{key, label, value, cls, app?, text?}] (a value that
//       isn't a finite number ≥ 0 is dropped); opts {size, hole, total?,
//       center?, why?, label?, tab?}. Each slice is a stroked arc (one A
//       command; a single 100 % slice is two half arcs, an arc from a
//       point to itself drawing nothing); a 2px gap between slices. The
//       SVG is role="group" named by opts.label; an app's slice is a
//       button with an accessible name (aria-label) and a <title>,
//       in the tab order only when opts.tab (the first donut). Nothing to
//       draw: the empty ring and "nothing measured", or the reason.
//   PortcullisDonut.slices(view, metric, server, opts) → donut
//       metric cpu | mem | io | net | storage; opts {storage, dev} for
//       storage (one disk). → {slices, total, unit, caption, missing:
//       [{label, why}], why, note}. The slices sum to total.
//   PortcullisDonut.drill(view, app, metric, opts) → donut
//       one app's containers ("<service>.<number>", one colour each in
//       every metric); storage: its items by the containers mounting them.
//   PortcullisDonut.disks(storage, server) → that server's disks.
//   PortcullisDonut.shares(values, total) → [percent strings], largest
//       remainder (the column sums to exactly 100 %; never "100 %" next
//       to another non-zero row, never "0 %" for a non-zero one).
//   PortcullisDonut.nm(why) → "not measured: <why>" (once).
//
// Rules: every number written into the SVG goes through num() (fixed
// decimals, finite only); every text through esc().
(function () {
  'use strict';

  const isNum = v => typeof v === 'number' && isFinite(v);
  const esc = s => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  // num: a finite number with 2 decimals (never NaN, Infinity or an
  // exponent in the markup).
  function num(v) {
    const n = Number(v);
    if (!isFinite(n)) return '0';
    const s = n.toFixed(2);
    return s === '-0.00' ? '0.00' : s;
  }
  // nm: a reason as "not measured: …", the prefix once (the API's
  // reasons mostly start with it already).
  function nm(why) {
    const w = String(why == null || why === '' ? 'no figure' : why);
    return /^not measured/i.test(w) ? w : 'not measured: ' + w;
  }
  const APPS_SHOWN = 7; // categorical slots c1…c7; c0 is core
  const GAP_PX = 2;

  // ── geometry ───────────────────────────────────────────────
  function point(cx, cy, r, a) { return [cx + r * Math.sin(a), cy - r * Math.cos(a)]; }
  // arcHtml: one stroked arc from angle a0 to a1 (radians, clockwise
  // from 12 o'clock), a1 − a0 < 2π: numbers only.
  function arcHtml(cx, cy, r, a0, a1) {
    const [x0, y0] = point(cx, cy, r, a0), [x1, y1] = point(cx, cy, r, a1);
    const largeHtml = a1 - a0 > Math.PI ? '1' : '0';
    return 'M ' + num(x0) + ' ' + num(y0) + ' A ' + num(r) + ' ' + num(r) + ' 0 ' + largeHtml + ' 1 ' + num(x1) + ' ' + num(y1);
  }
  function svg(slices, opts) {
    const o = opts || {};
    const size = isNum(o.size) && o.size > 0 ? o.size : 160;
    const hole = isNum(o.hole) && o.hole > 0 && o.hole < 1 ? o.hole : 0.62;
    const thick = (size / 2) * (1 - hole);
    const r = size / 2 - thick / 2, c = size / 2;
    const good = (slices || []).filter(s => s && isNum(s.value) && s.value >= 0);
    const sum = good.reduce((a, s) => a + s.value, 0);
    const total = isNum(o.total) && o.total > sum ? o.total : sum;
    const nameHtml = o.label ? ' aria-label="' + esc(o.label) + '"' : '';
    let out = '<svg class="share-donut" viewBox="0 0 ' + num(size) + ' ' + num(size) + '" width="' + num(size) + '" height="' + num(size) + '" role="group"' + nameHtml + '>';
    out += '<circle class="share-track" cx="' + num(c) + '" cy="' + num(c) + '" r="' + num(r) + '" stroke-width="' + num(thick) + '"></circle>';
    if (!(total > 0)) {
      const word = o.why ? 'not measured' : 'nothing measured';
      out += '<text class="share-center share-center-nm" x="' + num(c) + '" y="' + num(c) + '" text-anchor="middle" dominant-baseline="middle">' + esc(word) +
        '<title>' + esc(o.why ? nm(o.why) : 'nothing measured') + '</title></text></svg>';
      return out;
    }
    const drawn = good.filter(s => s.value > 0);
    const gap = drawn.length > 1 ? GAP_PX / r : 0;
    let a = 0;
    for (const s of drawn) {
      const sweep = (s.value / total) * 2 * Math.PI;
      const clsHtml = 'share-slice ' + esc(s.cls || 'share-more');
      const tip = s.text ? s.label + ': ' + s.text : s.label;
      const dataHtml = s.app ? ' data-share-app="' + esc(s.app) + '" tabindex="' + (o.tab ? '0' : '-1') + '" role="button" aria-label="' + esc(tip + ', open its containers') + '"' : '';
      const titleHtml = '<title>' + esc(tip) + '</title>';
      if (sweep >= 2 * Math.PI - 1e-9) {
        // One slice of 100 %: two half arcs.
        const topHtml = num(c) + ' ' + num(c - r), bottomHtml = num(c) + ' ' + num(c + r), rrHtml = num(r) + ' ' + num(r);
        out += '<path class="' + clsHtml + '"' + dataHtml + ' stroke-width="' + num(thick) + '" d="M ' + topHtml + ' A ' + rrHtml + ' 0 0 1 ' + bottomHtml + ' A ' + rrHtml + ' 0 0 1 ' + topHtml + '">' + titleHtml + '</path>';
      } else if (sweep > gap) {
        const from = a + gap / 2, to = a + sweep - gap / 2;
        out += '<path class="' + clsHtml + '"' + dataHtml + ' stroke-width="' + num(thick) + '" d="' + arcHtml(c, c, r, from, to) + '">' + titleHtml + '</path>';
      }
      a += sweep;
    }
    if (o.center) out += '<text class="share-center" x="' + num(c) + '" y="' + num(c) + '" text-anchor="middle" dominant-baseline="middle" aria-hidden="true">' + esc(o.center) + '</text>';
    return out + '</svg>';
  }

  // shares: each value's percentage of total, by largest remainder (the
  // rounded column sums to exactly 100 when the values sum to total).
  function shares(values, total) {
    if (!(total > 0)) return values.map(() => '');
    const exact = values.map(v => (isNum(v) && v > 0 ? (100 * v) / total : 0));
    const floor = exact.map(Math.floor);
    let left = Math.round(exact.reduce((a, b) => a + b, 0)) - floor.reduce((a, b) => a + b, 0);
    const order = exact.map((x, i) => [x - Math.floor(x), i]).sort((p, q) => q[0] - p[0] || p[1] - q[1]);
    for (const [, i] of order) { if (left <= 0) break; floor[i]++; left--; }
    const nonZero = exact.filter(x => x > 0).length;
    return floor.map((p, i) => {
      if (!(exact[i] > 0)) return '0 %';
      if (p < 1) return '< 1 %';
      if (p >= 100 && nonZero > 1) return '> 99 %';
      return p + ' %';
    });
  }

  // ── data → slices ──────────────────────────────────────────
  const sumOf = (s, ks) => {
    let any = false, t = 0;
    for (const k of ks) if (isNum(s && s[k])) { any = true; t += s[k]; }
    return any ? t : null;
  };
  const FIELDS = {
    cpu: { ks: ['cpu_cores'], used: 'cpu_used_cores', cap: 'cpus', unit: 'cores' },
    mem: { ks: ['mem_bytes'], used: 'mem_used_bytes', cap: 'memory_bytes', unit: 'bytes' },
    io: { ks: ['blk_read_bps', 'blk_write_bps'], used: null, cap: null, unit: 'bps' },
    net: { ks: ['net_rx_bps', 'net_tx_bps'], used: null, cap: null, unit: 'bps' },
  };
  const OVER_NOTE = 'apps and core read above the host\'s own figure (samples taken at different moments)';
  function appsOn(view, server) { return (view.apps || []).filter(g => (g.server || 'primary') === server); }
  // colours: the server's apps by memory (largest first, then name):
  // the first seven get c1…c7 in every donut of the view (colour follows
  // the app); the rest fold into "N more apps".
  function colours(view, server) {
    const apps = appsOn(view, server).slice().sort((x, y) => {
      const a = isNum(x.totals && x.totals.mem_bytes) ? x.totals.mem_bytes : -1, b = isNum(y.totals && y.totals.mem_bytes) ? y.totals.mem_bytes : -1;
      return (b - a) || String(x.name || x.instance).localeCompare(String(y.name || y.instance));
    });
    const m = new Map();
    apps.slice(0, APPS_SHOWN).forEach((g, i) => m.set(g.instance, 'share-c' + (i + 1)));
    return m;
  }
  function whyOf(g, ks) {
    if (g.why) return g.why;
    for (const c of g.containers || []) {
      for (const k of ks) if (c.not_measured && c.not_measured[k]) return c.not_measured[k];
      if (c.why) return c.why;
    }
    return 'no figure';
  }
  // appSlices: each app's value (or its "not measured" reason), the
  // first seven coloured, the rest folded.
  function appSlices(view, server, value, ks) {
    const col = colours(view, server);
    const out = [], missing = [];
    let more = 0, moreN = 0, moreSome = false;
    for (const g of appsOn(view, server)) {
      const v = value(g);
      if (!isNum(v)) { missing.push({ label: g.name || g.instance, why: whyOf(g, ks) }); continue; }
      const cls = col.get(g.instance);
      if (cls) out.push({ key: 'app:' + g.instance, label: g.name || g.instance, value: Math.max(0, v), cls, app: g.instance });
      else { more += Math.max(0, v); moreN++; moreSome = true; }
    }
    out.sort((a, b) => b.value - a.value);
    if (moreSome) out.push({ key: 'more', label: moreN + (moreN === 1 ? ' more app' : ' more apps'), value: more, cls: 'share-more' });
    return { out, missing };
  }

  function slices(view, metric, server, opts) {
    server = server || 'primary';
    if (metric === 'storage') return storageSlices(view, server, opts || {});
    const f = FIELDS[metric];
    const host = (view.hosts || {})[server] || null;
    const d = { slices: [], total: null, unit: f.unit, caption: '', missing: [], why: '', note: '' };
    if (!host) { d.why = 'no such server'; return d; }
    const { out, missing } = appSlices(view, server, g => sumOf(g.totals, f.ks), f.ks);
    d.slices = out;
    d.missing = missing;
    const core = view.core && (view.core.server || 'primary') === server ? view.core : null;
    if (metric !== 'net' && core) {
      const v = sumOf(core.totals, f.ks);
      if (isNum(v)) d.slices.push({ key: 'core', label: 'Portcullis core', value: Math.max(0, v), cls: 'share-c0' });
      else d.missing.push({ label: 'Portcullis core', why: core.why || whyOf(core, f.ks) });
    }
    const sum = d.slices.reduce((a, s) => a + s.value, 0);
    if (metric === 'net') {
      d.caption = 'of measured app traffic (no host-wide figure)';
      d.total = sum;
      return d;
    }
    // The host's figures, against capacity: other = the host's use beyond
    // what's listed; free = capacity − the larger of the host's use and
    // the listed sum (samples taken at different moments can put the sum
    // above the host's figure: a note says so). The slices sum to total.
    const used = metric === 'io' ? sumOf(host, ['blk_read_bps', 'blk_write_bps']) : host[f.used];
    const cap = f.cap ? host[f.cap] : null;
    if (!isNum(used) || (f.cap && !isNum(cap))) {
      d.why = host.why || 'the host\'s figure is not measured';
      d.total = sum;
      return d;
    }
    if (sum > used) d.note = OVER_NOTE;
    d.slices.push({ key: 'other', label: metric === 'io' ? 'Other disk IO on the host' : 'Other use on the host', value: Math.max(0, used - sum), cls: 'share-other' });
    if (f.cap) {
      d.slices.push({ key: 'free', label: 'Free', value: Math.max(0, cap - Math.max(used, sum)), cls: 'share-free' });
      d.total = Math.max(cap, sum);
      d.caption = metric === 'cpu' ? 'of the host\'s CPUs' : 'of the host\'s memory';
    } else {
      d.total = Math.max(used, sum);
      d.caption = 'of the host\'s disk IO';
    }
    return d;
  }

  // ── storage ────────────────────────────────────────────────
  function disks(storage, server) { return ((storage && storage.disks) || []).filter(k => (k.server || 'primary') === (server || 'primary')); }
  // onDisk: an item's filesystem; writable layers and images carry none:
  // they are on the engine's data disk (role docker_data).
  function onDisk(it, disk) {
    if (isNum(it.dev)) return it.dev === disk.dev;
    return (it.kind === 'layer' || it.kind === 'image') && disk.role === 'docker_data';
  }
  function itemWhy(it) { return it.error || (it.partial && it.partial_reason) || 'not measured yet'; }
  function storageSlices(view, server, opts) {
    const storage = opts.storage || {};
    const disk = disks(storage, server).find(k => k.dev === opts.dev);
    const d = { slices: [], total: null, unit: 'bytes', caption: '', missing: [], why: '', note: '' };
    if (!disk) { d.why = 'not measured yet'; return d; }
    const col = colours(view, server);
    // The storage view names each app's server (contract §11.11): never
    // guessed from the usage view, whose read may be older or newer.
    const mine = g => (g.server || 'primary') === server;
    let more = 0, moreN = 0;
    const apps = [];
    for (const g of storage.apps || []) {
      if (!mine(g)) continue;
      let v = null;
      const nmItems = [];
      for (const it of g.items || []) {
        if (!it.in_total || !(isNum(it.dev) ? it.dev === disk.dev : onDisk(it, disk))) continue;
        if (!isNum(it.alloc_bytes)) { nmItems.push(it); continue; }
        v = (v || 0) + it.alloc_bytes;
        if (it.partial) nmItems.push(it);
      }
      if (nmItems.length) d.missing.push({ label: (g.name || g.instance) + ' · ' + nmItems[0].target + (nmItems.length > 1 ? ' (+' + (nmItems.length - 1) + ' more)' : ''), why: (isNum(nmItems[0].alloc_bytes) ? 'only partly measured: ' : '') + itemWhy(nmItems[0]) });
      if (v === null) continue;
      const cls = col.get(g.instance);
      if (cls) apps.push({ key: 'app:' + g.instance, label: g.name || g.instance, value: v, cls, app: g.instance });
      else { more += v; moreN++; }
    }
    apps.sort((a, b) => b.value - a.value);
    d.slices = apps;
    if (moreN) d.slices.push({ key: 'more', label: moreN + (moreN === 1 ? ' more app' : ' more apps'), value: more, cls: 'share-more' });
    if (server === 'primary') {
      let core = null;
      for (const it of storage.core || []) {
        if (!it.in_total || !onDisk(it, disk)) continue;
        if (!isNum(it.alloc_bytes)) { d.missing.push({ label: 'Portcullis core · ' + it.target, why: itemWhy(it) }); continue; }
        core = (core || 0) + it.alloc_bytes;
      }
      if (core !== null) d.slices.push({ key: 'core', label: 'Portcullis core', value: core, cls: 'share-c0' });
    }
    // Volumes and paths several apps use: in no app's total, once each.
    const shared = new Map();
    for (const g of storage.apps || []) {
      if (!mine(g)) continue;
      for (const it of g.items || []) {
        if ((it.kind !== 'volume' && it.kind !== 'bind') || !(it.shared_with || []).length || !onDisk(it, disk) || shared.has(it.kind + ':' + it.target)) continue;
        shared.set(it.kind + ':' + it.target, it);
      }
    }
    let sharedSum = null;
    for (const it of shared.values()) {
      if (isNum(it.alloc_bytes)) sharedSum = (sharedSum || 0) + it.alloc_bytes;
      else d.missing.push({ label: 'Shared between apps · ' + it.target, why: itemWhy(it) });
    }
    if (sharedSum !== null) d.slices.push({ key: 'shared', label: 'Shared between apps', value: sharedSum, cls: 'share-shared' });
    // Folders: by the dev their items name (the doctor's scan).
    const folderDev = {};
    for (const g of storage.apps || []) {
      if (!mine(g)) continue;
      for (const it of g.items || []) if (it.kind === 'folder' && isNum(it.dev)) folderDev[it.target] = it.dev;
    }
    let folders = null;
    for (const f of storage.folders || []) {
      if ((f.server || 'primary') !== server || folderDev[f.id] !== disk.dev) continue;
      if (isNum(f.alloc_bytes)) folders = (folders || 0) + f.alloc_bytes;
      else d.missing.push({ label: 'Shared folder · ' + (f.name || f.id), why: f.note || 'not measured yet' });
    }
    if (folders !== null) d.slices.push({ key: 'folders', label: 'Shared folders', value: folders, cls: 'share-folders' });
    // Shared images: each image once, on the engine's data disk.
    if (disk.role === 'docker_data') {
      const seen = new Map();
      const add = it => { if (it.kind === 'image' && isNum(it.alloc_bytes) && !seen.has(it.target)) seen.set(it.target, it.alloc_bytes); };
      if (server === 'primary') (storage.core || []).forEach(add);
      for (const g of storage.apps || []) if (mine(g)) (g.items || []).forEach(add);
      if (seen.size) d.slices.push({ key: 'images', label: 'Shared images', value: [...seen.values()].reduce((x, y) => x + y, 0), cls: 'share-images' });
    }
    const sum = d.slices.reduce((x, s) => x + s.value, 0);
    const used = Math.max(0, disk.total_bytes - disk.free_bytes);
    if (sum > used) d.note = 'the listed items read above the disk\'s own used figure (measured at different times)';
    d.slices.push({ key: 'other', label: 'Other used', value: Math.max(0, used - sum), cls: 'share-other' });
    d.slices.push({ key: 'free', label: 'Free', value: Math.max(0, disk.total_bytes - Math.max(used, sum)), cls: 'share-free' });
    d.total = Math.max(disk.total_bytes, sum);
    d.caption = 'of this disk';
    return d;
  }

  // ── one app's containers ───────────────────────────────────
  const ckey = c => c.service + '.' + c.number;
  // containerColours: the app's containers by memory (then key), one
  // colour each in all its donuts; past seven: "N more".
  function containerColours(g) {
    const cs = (g.containers || []).slice().sort((x, y) => {
      const a = isNum(x.sample && x.sample.mem_bytes) ? x.sample.mem_bytes : -1, b = isNum(y.sample && y.sample.mem_bytes) ? y.sample.mem_bytes : -1;
      return (b - a) || ckey(x).localeCompare(ckey(y));
    });
    const m = new Map();
    cs.slice(0, APPS_SHOWN).forEach((c, i) => m.set(ckey(c), 'share-c' + (i + 1)));
    return m;
  }
  function byColour(list, col) {
    const shown = [], rest = [];
    for (const s of list) {
      if (s.cls) shown.push(s);
      else if (col.has(s.key)) shown.push(Object.assign(s, { cls: col.get(s.key) }));
      else rest.push(s);
    }
    shown.sort((a, b) => b.value - a.value);
    if (rest.length) shown.push({ key: 'more', label: rest.length + ' more', value: rest.reduce((a, s) => a + s.value, 0), cls: 'share-more' });
    return shown;
  }
  function drill(view, app, metric, opts) {
    const g = (view.apps || []).find(x => x.instance === app) || (view.core && view.core.instance === app ? view.core : null);
    const d = { slices: [], total: null, unit: metric === 'storage' ? 'bytes' : FIELDS[metric].unit, caption: 'of the app\'s total', missing: [], why: '', note: '' };
    if (!g) { d.why = 'no such app'; return d; }
    const col = containerColours(g);
    if (metric === 'storage') {
      const sg = (((opts || {}).storage || {}).apps || []).find(x => x.instance === app);
      const by = new Map();
      for (const it of (sg && sg.items) || []) {
        if (!it.in_total) continue;
        if (!isNum(it.alloc_bytes)) { d.missing.push({ label: it.target, why: itemWhy(it) }); continue; }
        let key, label, cls;
        const ss = it.kind === 'layer' ? [it.target] : (it.services || []);
        if (ss.length === 1) { key = ss[0]; label = ss[0]; } else if (ss.length > 1) { key = 'shared:' + ss.join(','); label = 'shared by ' + ss.join(', '); cls = 'share-shared'; } else { key = 'unmounted'; label = 'not mounted by a running container'; cls = 'share-other'; }
        const s = by.get(key) || { key, label, value: 0, cls };
        s.value += it.alloc_bytes;
        by.set(key, s);
      }
      d.slices = byColour([...by.values()], col);
      d.total = d.slices.reduce((a, s) => a + s.value, 0);
      return d;
    }
    const f = FIELDS[metric];
    const list = [];
    for (const c of g.containers || []) {
      const v = sumOf(c.sample, f.ks);
      if (isNum(v)) list.push({ key: ckey(c), label: ckey(c), value: Math.max(0, v) });
      else d.missing.push({ label: ckey(c), why: (c.not_measured && f.ks.map(k => c.not_measured[k]).find(Boolean)) || c.why || c.error || 'no figure' });
    }
    d.slices = byColour(list, col);
    d.total = d.slices.reduce((a, s) => a + s.value, 0);
    return d;
  }

  window.PortcullisDonut = { svg, slices, drill, disks, shares, nm, num, esc };
})();
