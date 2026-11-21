// Portcullis Hub — inline-SVG donuts for the Usage tab's Share view
// (share.js). No chart library, no inline styles: colours are CSS
// classes (.share-c0 … .share-c7, .share-more, .share-other,
// .share-free, .share-empty), so the page's CSP needs nothing more.
//
//   PortcullisDonut.svg(slices, opts) → string
//       slices: [{key, label, value, cls}] (a value that isn't a finite
//       number ≥ 0 is dropped); opts {size, hole, total?, center?, why?,
//       app?}. Each slice is a stroked arc (one A command; a single 100 %
//       slice is two half arcs, an arc from a point to itself drawing
//       nothing); a 2px gap between slices. Labels go only into <title>
//       (esc). Nothing to draw: the empty ring and "nothing measured", or
//       "not measured" when opts.why is set.
//   PortcullisDonut.slices(view, metric, server, opts) → donut
//       metric cpu | mem | io | net | storage; opts {storage, dev} for
//       storage (one disk). → {slices, total, unit, caption, missing:
//       [{label, why}], why} (why: the whole donut isn't measured).
//   PortcullisDonut.drill(view, app, metric, opts) → donut
//       one app's containers ("<service>.<number>"); storage: its items
//       by the containers that mount them.
//   PortcullisDonut.disks(storage, server) → that server's disks.
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
  const APPS_SHOWN = 7; // categorical slots c1…c7; c0 is core
  const GAP_PX = 2;

  // ── geometry ───────────────────────────────────────────────
  function point(cx, cy, r, a) { return [cx + r * Math.sin(a), cy - r * Math.cos(a)]; }
  // arcPath: one stroked arc from angle a0 to a1 (radians, clockwise
  // from 12 o'clock), a1 − a0 < 2π.
  function arcHtml(cx, cy, r, a0, a1) {
    const [x0, y0] = point(cx, cy, r, a0), [x1, y1] = point(cx, cy, r, a1);
    const large = a1 - a0 > Math.PI ? 1 : 0;
    return 'M ' + num(x0) + ' ' + num(y0) + ' A ' + num(r) + ' ' + num(r) + ' 0 ' + large + ' 1 ' + num(x1) + ' ' + num(y1);
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
    const attrs = o.app ? ' data-share-donut="' + esc(o.app) + '"' : '';
    let out = '<svg class="share-donut" viewBox="0 0 ' + num(size) + ' ' + num(size) + '" width="' + num(size) + '" height="' + num(size) + '" role="img" aria-hidden="true"' + attrs + '>';
    out += '<circle class="share-track" cx="' + num(c) + '" cy="' + num(c) + '" r="' + num(r) + '" stroke-width="' + num(thick) + '"></circle>';
    if (!(total > 0)) {
      const word = o.why ? 'not measured' : 'nothing measured';
      const tip = o.why ? ['not measured:', o.why].join(' ') : 'nothing measured';
      out += '<text class="share-center share-center-nm" x="' + num(c) + '" y="' + num(c) + '" text-anchor="middle" dominant-baseline="middle">' + esc(word) +
        '<title>' + esc(tip) + '</title></text></svg>';
      return out;
    }
    const drawn = good.filter(s => s.value > 0);
    const gap = drawn.length > 1 ? GAP_PX / r : 0;
    let a = 0;
    for (const s of drawn) {
      const sweep = (s.value / total) * 2 * Math.PI;
      const cls = 'share-slice ' + esc(s.cls || 'share-more');
      const data = s.app ? ' data-share-app="' + esc(s.app) + '" tabindex="0" role="button"' : '';
      const title = '<title>' + esc(s.label) + (s.text ? ': ' + esc(s.text) : '') + '</title>';
      if (sweep >= 2 * Math.PI - 1e-9) {
        // One slice of 100 %: two half arcs.
        const topHtml = num(c) + ' ' + num(c - r), bottomHtml = num(c) + ' ' + num(c + r), rrHtml = num(r) + ' ' + num(r);
        out += '<path class="' + cls + '"' + data + ' stroke-width="' + num(thick) + '" d="M ' + topHtml + ' A ' + rrHtml + ' 0 0 1 ' + bottomHtml + ' A ' + rrHtml + ' 0 0 1 ' + topHtml + '">' + title + '</path>';
      } else if (sweep > gap) {
        const from = a + gap / 2, to = a + sweep - gap / 2;
        out += '<path class="' + cls + '"' + data + ' stroke-width="' + num(thick) + '" d="' + arcHtml(c, c, r, from, to) + '">' + title + '</path>';
      }
      a += sweep;
    }
    if (o.center) out += '<text class="share-center" x="' + num(c) + '" y="' + num(c) + '" text-anchor="middle" dominant-baseline="middle">' + esc(o.center) + '</text>';
    return out + '</svg>';
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
    const d = { slices: [], total: null, unit: f.unit, caption: '', missing: [], why: '' };
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
    // The host's figures: other (the host's use beyond what's listed,
    // never negative) and free.
    const used = metric === 'io' ? sumOf(host, ['blk_read_bps', 'blk_write_bps']) : host[f.used];
    const cap = f.cap ? host[f.cap] : null;
    if (!isNum(used) || (f.cap && !isNum(cap))) {
      d.why = host.why || 'the host\'s figure is not measured';
      d.caption = 'the host\'s figure is not measured';
      d.total = sum;
      return d;
    }
    d.slices.push({ key: 'other', label: metric === 'io' ? 'Other disk IO on the host' : 'Other use on the host', value: Math.max(0, used - sum), cls: 'share-other' });
    if (f.cap) {
      d.slices.push({ key: 'free', label: 'Free', value: Math.max(0, cap - used), cls: 'share-free' });
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
  // engineDev: the disk of the engine's data root on server — where its
  // volumes are (writable layers and images live there too; they carry
  // no dev of their own).
  function engineDev(view, storage, server) {
    const srv = appServers(view);
    const vols = [];
    for (const it of (storage.core || [])) if (server === 'primary' && it.kind === 'volume' && isNum(it.dev)) vols.push(it.dev);
    for (const g of storage.apps || []) {
      if ((srv[g.instance] || 'primary') !== server) continue;
      for (const it of g.items || []) if (it.kind === 'volume' && isNum(it.dev)) vols.push(it.dev);
    }
    return vols.length ? vols[0] : null;
  }
  function appServers(view) {
    const m = {};
    for (const g of view.apps || []) m[g.instance] = g.server || 'primary';
    return m;
  }
  // onDisk: an item's filesystem (layers: the engine's).
  function onDisk(it, dev, eng) {
    if (isNum(it.dev)) return it.dev === dev;
    return it.kind === 'layer' && eng === dev;
  }
  function storageSlices(view, server, opts) {
    const storage = opts.storage || {};
    const disk = disks(storage, server).find(k => k.dev === opts.dev);
    const d = { slices: [], total: null, unit: 'bytes', caption: '', missing: [], why: '' };
    if (!disk) { d.why = 'not measured yet'; return d; }
    const srv = appServers(view);
    const eng = engineDev(view, storage, server);
    const col = colours(view, server);
    let more = 0, moreN = 0;
    const apps = [];
    for (const g of storage.apps || []) {
      if ((srv[g.instance] || 'primary') !== server) continue;
      let v = null;
      for (const it of g.items || []) {
        if (!it.in_total || !isNum(it.alloc_bytes) || !onDisk(it, disk.dev, eng)) continue;
        v = (v || 0) + it.alloc_bytes;
      }
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
      for (const it of storage.core || []) if (it.in_total && isNum(it.alloc_bytes) && onDisk(it, disk.dev, eng)) core = (core || 0) + it.alloc_bytes;
      if (core !== null) d.slices.push({ key: 'core', label: 'Portcullis core', value: core, cls: 'share-c0' });
    }
    // Folders: by the dev their items name (the doctor's scan).
    const folderDev = {};
    for (const g of storage.apps || []) {
      if ((srv[g.instance] || 'primary') !== server) continue;
      for (const it of g.items || []) if (it.kind === 'folder' && isNum(it.dev)) folderDev[it.target] = it.dev;
    }
    let folders = null;
    for (const f of storage.folders || []) if (folderDev[f.id] === disk.dev && isNum(f.alloc_bytes)) folders = (folders || 0) + f.alloc_bytes;
    if (folders !== null) d.slices.push({ key: 'folders', label: 'Shared folders', value: folders, cls: 'share-folders' });
    // Shared images: each image once, on the engine's disk.
    if (eng === disk.dev) {
      const seen = new Map();
      const add = it => { if (it.kind === 'image' && isNum(it.alloc_bytes) && !seen.has(it.target)) seen.set(it.target, it.alloc_bytes); };
      if (server === 'primary') (storage.core || []).forEach(add);
      for (const g of storage.apps || []) if ((srv[g.instance] || 'primary') === server) (g.items || []).forEach(add);
      if (seen.size) d.slices.push({ key: 'images', label: 'Shared images', value: [...seen.values()].reduce((a, b) => a + b, 0), cls: 'share-images' });
    }
    const sum = d.slices.reduce((a, s) => a + s.value, 0);
    const used = Math.max(0, disk.total_bytes - disk.free_bytes);
    d.slices.push({ key: 'other', label: 'Other used', value: Math.max(0, used - sum), cls: 'share-other' });
    d.slices.push({ key: 'free', label: 'Free', value: Math.max(0, disk.free_bytes), cls: 'share-free' });
    d.total = Math.max(disk.total_bytes, sum + disk.free_bytes);
    d.caption = 'of this disk';
    return d;
  }

  // ── one app's containers ───────────────────────────────────
  const ckey = c => c.service + '.' + c.number;
  function folded(list) {
    list.sort((a, b) => b.value - a.value);
    const shown = list.slice(0, APPS_SHOWN).map((s, i) => Object.assign(s, { cls: 'share-c' + (i + 1) }));
    const rest = list.slice(APPS_SHOWN);
    if (rest.length) shown.push({ key: 'more', label: rest.length + ' more', value: rest.reduce((a, s) => a + s.value, 0), cls: 'share-more' });
    return shown;
  }
  function drill(view, app, metric, opts) {
    const g = (view.apps || []).find(x => x.instance === app) || (view.core && view.core.instance === app ? view.core : null);
    const d = { slices: [], total: null, unit: metric === 'storage' ? 'bytes' : FIELDS[metric].unit, caption: 'of the app\'s total', missing: [], why: '' };
    if (!g) { d.why = 'no such app'; return d; }
    if (metric === 'storage') {
      const sg = (((opts || {}).storage || {}).apps || []).find(x => x.instance === app);
      const by = new Map();
      for (const it of (sg && sg.items) || []) {
        if (!it.in_total || !isNum(it.alloc_bytes)) continue;
        let key, label;
        const ss = it.kind === 'layer' ? [it.target] : (it.services || []);
        if (ss.length === 1) { key = ss[0]; label = ss[0]; } else if (ss.length > 1) { key = 'shared:' + ss.join(','); label = 'shared by ' + ss.join(', '); } else { key = 'unmounted'; label = 'not mounted by a running container'; }
        const s = by.get(key) || { key, label, value: 0 };
        s.value += it.alloc_bytes;
        by.set(key, s);
      }
      d.slices = folded([...by.values()]);
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
    d.slices = folded(list);
    d.total = d.slices.reduce((a, s) => a + s.value, 0);
    return d;
  }

  window.PortcullisDonut = { svg, slices, drill, disks, num, esc };
})();
