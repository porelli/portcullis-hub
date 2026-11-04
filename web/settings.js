// Portcullis Hub — the instance settings panel (contract §13, Task 14).
//
//   window.PortcullisSettings.render(container, instanceId)
//
// GET    /api/instances/{id}/settings          the panel (hub.SettingsPanel)
// PUT    /api/instances/{id}/settings          save the draft (hub.SaveResult)
// POST   /api/instances/{id}/settings/preview  what the draft would do (hub.Preview)
// POST   /api/instances/{id}/settings/retry    run the deliveries again
//
// Rules: every interpolation goes through escapeHtml (index.html); data-*
// attributes and delegated listeners only; secret values are never put
// into the DOM (password inputs keep what the admin types, and the panel
// is rebuilt from the server after a save, so they are emptied). The
// access policy, sign-in and public-exception blocks are index.html's
// renderers (renderAppPolicy, renderSignIn, renderPublicBlock and their
// collectors) and are posted in the same body.
(function () {
  'use strict';

  const esc = s => window.escapeHtml(s);
  const PAGE = 50;
  const DEBOUNCE_MS = 400;
  const UNRESOLVED = "unresolved: the app's own default applies";

  const SIZE_MULT = { B: 1, KiB: 2 ** 10, MiB: 2 ** 20, GiB: 2 ** 30, TiB: 2 ** 40, PiB: 2 ** 50 };
  const SIZE_UNITS = ['MiB', 'GiB', 'TiB'];
  const DUR_MULT = { s: 1, m: 60, h: 3600, d: 86400, w: 604800 };
  const DUR_UNITS = [['s', 'seconds'], ['m', 'minutes'], ['h', 'hours'], ['d', 'days']];

  const RESOLVE_LABEL = {
    max: 'largest wins',
    min: 'smallest wins',
    priority: 'first matching group wins (in this order)',
    union: 'everything any of their groups gives',
    intersection: 'only what all of their groups give',
    any: 'on if any of their groups says on',
    all: 'on only if all of their groups say on'
  };
  const RULE_OF = { max: 'largest of', min: 'smallest of', priority: 'first of' };
  const APPLIES = {
    live: 'applies: at once',
    next_request: 'applies: at the next request',
    next_sign_in: 'applies: at the next sign-in',
    account_creation: 'applies: when an account is created',
    reload: 'applies: after a reload',
    restart: 'applies: after a restart'
  };
  // What a save of an option with no reload/restart effect means.
  const NO_RESTART_TEXT = {
    live: 'Takes effect at once; no restart',
    next_request: "Takes effect at each person's next request; no restart",
    next_sign_in: "Takes effect at each person's next sign-in; no restart",
    account_creation: 'Applies to accounts created from now on (existing accounts keep their value); no restart'
  };
  const SKIP_TEXT = {
    'unchanged': 'unchanged: nothing new to deliver',
    'not running': 'not running: delivered when the app starts',
    'directory unavailable': 'skipped: Users & Groups was unavailable, the last delivery is kept',
    'busy': 'skipped: the app was busy with another operation, it runs again shortly',
    'superseded': 'skipped: a newer save replaced this run, which runs again',
    'not supported': 'not supported by this app',
    'previous run still running': 'waiting: the previous run of this hook is still running'
  };

  const states = new WeakMap();
  let uidSeq = 0;
  const nextUid = () => 'r' + (++uidSeq);

  // ── values ─────────────────────────────────────────────────────────

  function sizeBytes(v) {
    if (v === 'unlimited') return 'unlimited';
    if (typeof v === 'number') return v;
    const m = /^\s*(\d+(?:\.\d+)?)\s*(B|KiB|MiB|GiB|TiB|PiB)\s*$/.exec(String(v == null ? '' : v));
    return m ? Math.round(Number(m[1]) * SIZE_MULT[m[2]]) : null;
  }

  function showSize(n) {
    if (n === 'unlimited') return 'unlimited';
    if (typeof n !== 'number') return String(n);
    let unit = 'B';
    for (const u of ['KiB', 'MiB', 'GiB', 'TiB', 'PiB']) if (n >= SIZE_MULT[u]) unit = u;
    return Number((n / SIZE_MULT[unit]).toPrecision(4)) + ' ' + unit;
  }

  function durSeconds(v) {
    if (typeof v === 'number') return v;
    const s = String(v == null ? '' : v).trim();
    if (!/^(\d+[wdhms])+$/.test(s)) return null;
    let n = 0;
    for (const m of s.matchAll(/(\d+)([wdhms])/g)) n += Number(m[1]) * DUR_MULT[m[2]];
    return n;
  }

  function showDur(n) {
    if (typeof n !== 'number') return String(n);
    if (n === 0) return '0s';
    let out = '';
    for (const [u, k] of [['d', 86400], ['h', 3600], ['m', 60], ['s', 1]]) {
      if (n >= k) { out += Math.floor(n / k) + u; n %= k; }
    }
    return out;
  }

  // canonical turns a template literal (a default, a step) into the
  // panel's canonical form (sizes in bytes, durations in seconds).
  function canonical(o, raw) {
    if (raw === undefined || raw === null) return null;
    switch (o.type) {
      case 'size': return sizeBytes(raw);
      case 'duration': return durSeconds(raw);
      case 'int': return typeof raw === 'number' ? raw : Number(raw);
      default: return raw;
    }
  }

  function choiceLabel(o, v) {
    const c = (o.options || []).find(x => x.value === v);
    return c ? (c.label || c.value) : String(v);
  }

  function display(o, v) {
    if (v === null || v === undefined) return '—';
    switch (o.type) {
      case 'size': return showSize(v);
      case 'duration': return showDur(v);
      case 'enum': return choiceLabel(o, v);
      case 'multi_enum': return (v || []).map(x => choiceLabel(o, x)).join(', ') || '(none)';
      case 'bool': return v ? 'on' : 'off';
      case 'int': return String(v) + (o.unit ? ' ' + o.unit : '');
      case 'secret': return '[set]';
    }
    if (Array.isArray(v)) return v.map(x => typeof x === 'object' ? JSON.stringify(x) : String(x)).join(', ') || '(none)';
    if (typeof v === 'object') return JSON.stringify(v);
    return String(v);
  }

  const scopeOf = o => o.scope || 'instance';
  const jsonEq = (a, b) => JSON.stringify(a) === JSON.stringify(b);
  const plural = (n, one, many) => n + ' ' + (n === 1 ? one : many);

  function fmtDate(s) {
    const d = new Date(s);
    if (isNaN(d)) return String(s || '');
    return d.toLocaleString(undefined, { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
  }

  // ── state ──────────────────────────────────────────────────────────

  function optionByKey(st, key) { return st.opts[key]; }

  function rowsFrom(list) {
    return (list || []).map(r => ({ uid: nextUid(), group: r.group, value: r.value, group0: r.group, gid0: r.group_id || 0 }));
  }

  // newState builds the draft from the panel: instance values (null =
  // the template default), per-person configurations, group records,
  // ports; the saved forms are kept to tell what changed.
  function newState(el, id, panel) {
    const st = {
      el, id, panel, opts: {}, values: {}, person: {}, groups: {}, secrets: {}, ports: Object.assign({}, panel.ports || {}),
      base: {}, errors: {}, rowErrors: {}, barError: '', preview: null, previewFor: '', previewSeq: 0, timer: 0,
      saving: false, retrying: false, who: {}, flash: null, accessBase: null, drag: null
    };
    for (const o of panel.options || []) {
      st.opts[o.key] = o;
      const sc = scopeOf(o);
      if (sc === 'instance' && o.type !== 'secret') {
        st.values[o.key] = o.key in (panel.instance || {}) ? panel.instance[o.key] : null;
      } else if (sc === 'person') {
        const p = (panel.person || {})[o.key];
        st.person[o.key] = p
          ? { default: p.default, resolve: p.resolve || '', rows: rowsFrom(p.rows) }
          : { default: canonical(o, o.default), resolve: '', rows: [] };
        st.who[o.key] = { q: '', page: 0 };
      } else if (sc === 'group') {
        st.groups[o.key] = rowsFrom((panel.groups || {})[o.key]);
      }
    }
    st.base = { values: JSON.stringify(st.values), ports: JSON.stringify(st.ports), person: {}, groups: {} };
    for (const k in st.person) st.base.person[k] = JSON.stringify(personBody(st.person[k]));
    for (const k in st.groups) st.base.groups[k] = JSON.stringify(rowsBody(st.groups[k]));
    st.baseValues = JSON.parse(st.base.values);
    return st;
  }

  // rowsBody: rows as the API takes them. A row keeps the group_id it
  // was received with while it names the same group; added rows (and
  // rows moved to another group) carry none.
  function rowsBody(rows) {
    return rows.map(r => {
      const out = { group: r.group, value: r.value };
      if (r.gid0 && r.group === r.group0) out.group_id = r.gid0;
      return out;
    });
  }

  function personBody(p) {
    const out = { default: p.default, rows: rowsBody(p.rows) };
    if (p.resolve) out.resolve = p.resolve;
    return out;
  }

  function changedValueKeys(st) {
    return Object.keys(st.values).filter(k => !jsonEq(st.values[k], st.baseValues[k]));
  }
  function changedPersonKeys(st) {
    return Object.keys(st.person).filter(k => JSON.stringify(personBody(st.person[k])) !== st.base.person[k]);
  }
  function changedGroupKeys(st) {
    return Object.keys(st.groups).filter(k => JSON.stringify(rowsBody(st.groups[k])) !== st.base.groups[k]);
  }

  // accessParts is the policy / sign-in / public part of the form, as
  // index.html's collectors read it.
  function accessParts(st) {
    const form = st.el.querySelector('form[data-ps-form]');
    const out = {};
    if (!form) return out;
    const si = form.querySelector('input[name="__signin"]:checked');
    if (si) out.sign_in = si.value;
    const pol = window.collectPolicy(form, st.id);
    if (!pol.skip) out.policy = pol.inherit ? { inherit: true } : { policy: pol.policy };
    const pub = {};
    window.collectPublic(form, pub);
    if ('_public_access' in pub) out.pub = { public_access: pub._public_access, public_mode: pub._public_mode, public_tokens: pub._public_tokens };
    return out;
  }

  function accessChanges(st) {
    const now = accessParts(st), base = st.accessBase || {};
    const out = {};
    if (now.sign_in !== undefined && now.sign_in !== base.sign_in) out.sign_in = now.sign_in;
    if (now.policy && !jsonEq(now.policy, base.policy)) out.policy = now.policy;
    if (now.pub && !jsonEq(now.pub, base.pub)) out.pub = now.pub;
    return out;
  }

  // body is the draft as a PUT / preview body: only what changed.
  function body(st) {
    const b = {};
    const vk = changedValueKeys(st);
    if (vk.length) { b.values = {}; for (const k of vk) b.values[k] = st.values[k]; }
    const pk = changedPersonKeys(st);
    if (pk.length) { b.person = {}; for (const k of pk) b.person[k] = personBody(st.person[k]); }
    const gk = changedGroupKeys(st);
    if (gk.length) { b.groups = {}; for (const k of gk) b.groups[k] = rowsBody(st.groups[k]); }
    if (Object.keys(st.secrets).length) b.secrets = Object.assign({}, st.secrets);
    if (JSON.stringify(st.ports) !== st.base.ports) b.ports = Object.assign({}, st.ports);
    const a = accessChanges(st);
    if (a.sign_in) b.sign_in = a.sign_in;
    if (a.policy) {
      if (a.policy.inherit) b.auth_policy_inherit = true; else b.auth_policy = a.policy.policy;
    }
    if (a.pub) {
      b.public_access = a.pub.public_access;
      if (a.pub.public_mode !== undefined) b.public_mode = a.pub.public_mode;
      if (a.pub.public_tokens !== undefined) b.public_tokens = a.pub.public_tokens;
    }
    return b;
  }

  // Draft keys whose option changed, for the effect wording.
  function changedOptions(st) {
    return [...changedValueKeys(st), ...changedPersonKeys(st), ...changedGroupKeys(st), ...Object.keys(st.secrets)]
      .map(k => st.opts[k]).filter(Boolean);
  }

  // ── rendering: panel ───────────────────────────────────────────────

  function render(el, id) {
    el.innerHTML = '<p class="settings-empty">Loading settings…</p>';
    bind(el);
    return window.apiGet('/api/instances/' + encodeURIComponent(id) + '/settings').then(async panel => {
      // The shared folders, for the path options' picker.
      let folders = [];
      if ((panel.options || []).some(o => o.type === 'path') && window.PortcullisFolders) {
        try { folders = await window.PortcullisFolders.list(); } catch (e) { /* custom paths only */ }
      }
      const prev = states.get(el);
      const st = newState(el, id, panel);
      st.folders = folders;
      if (prev && prev.id === id) st.flash = prev.flash;
      states.set(el, st);
      draw(st);
      runPreview(st);
    }).catch(err => {
      el.innerHTML = '<p class="settings-empty">Failed to load settings: ' + esc(err.message) + '</p>';
    });
  }

  function draw(st) {
    const p = st.panel;
    let h = '<form class="settings-form ps" data-ps-form novalidate>';
    h += '<div class="ps-strip" data-ps-strip>' + stripHtml(st) + '</div>';
    if (st.flash) h += '<div class="ps-flash" data-ps-flash>' + st.flash + '</div>';
    h += window.renderSignIn(st.id, p.sign_in);
    h += window.renderAppPolicy(st.id, p);
    h += window.renderPublicBlock(st.id, p.public_access);
    h += optionsHtml(st);
    h += portsHtml(st);
    h += '<div class="ps-bar" data-ps-bar>' + barHtml() + '</div>';
    // One group list per panel, for the free-text group editors.
    if ((p.directory_groups || []).length) h += '<datalist id="ps-groups-' + esc(st.id) + '">' + p.directory_groups.map(g => '<option value="' + esc(g) + '">').join('') + '</datalist>';
    h += '</form>';
    st.el.innerHTML = h;
    st.accessBase = accessParts(st);
    st.flash = null;
    redrawBar(st);
  }

  function optionsHtml(st) {
    const opts = st.panel.options || [];
    if (!opts.length) return '';
    const sections = st.panel.sections || [];
    const groups = [];
    const loose = opts.filter(o => !o.section || !sections.includes(o.section));
    if (loose.length) groups.push({ title: sections.length ? 'General' : '', opts: loose });
    for (const s of sections) {
      const os = opts.filter(o => o.section === s);
      if (os.length) groups.push({ title: s, opts: os });
    }
    let h = '<div class="ps-options">';
    for (const g of groups) {
      h += '<section class="ps-section">';
      if (g.title) h += '<h4 class="ps-section-title">' + esc(g.title) + '</h4>';
      h += sectionBody(st, g.opts);
      h += '</section>';
    }
    return h + '</div>';
  }

  // sectionBody lays out a section's options; an option with `requires`
  // is shown side by side with what it requires (a craft pair).
  function sectionBody(st, opts) {
    const placed = new Set();
    let h = '';
    for (const o of opts) {
      if (placed.has(o.key)) continue;
      const pair = (o.requires || []).map(k => opts.find(x => x.key === k)).filter(x => x && !placed.has(x.key));
      if (pair.length) {
        h += '<div class="ps-pair">';
        for (const x of [...pair, o]) { placed.add(x.key); h += optionHtml(st, x); }
        h += '</div>';
        continue;
      }
      // Required by a later option of this section: placed with it.
      if (opts.some(x => x !== o && (x.requires || []).includes(o.key) && !placed.has(x.key))) continue;
      placed.add(o.key);
      h += optionHtml(st, o);
    }
    return h;
  }

  function appliesBadge(o) {
    const t = o.effect === 'restart' ? APPLIES.restart : o.effect === 'reload' ? APPLIES.reload : (APPLIES[o.applies || 'restart'] || '');
    return t ? '<span class="ps-applies">' + esc(t) + '</span>' : '';
  }

  function optionHtml(st, o) {
    const sc = scopeOf(o);
    let h = '<div class="ps-opt" data-opt="' + esc(o.key) + '">';
    h += optionInner(st, o, sc);
    return h + '</div>';
  }

  function optionInner(st, o, sc) {
    let h = '<div class="ps-opt-head"><span class="ps-opt-label">' + esc(o.label || o.key) + '</span>';
    if (sc === 'person') h += '<span class="ps-scope">per person</span>';
    if (sc === 'group') h += '<span class="ps-scope">per group</span>';
    if (sc === 'person_entered') h += '<span class="ps-scope">entered by each person</span>';
    if (o.privileged) h += '<span class="ps-scope ps-priv">privileged</span>';
    h += appliesBadge(o) + '</div>';
    if (o.description) h += '<div class="ps-desc">' + esc(o.description) + '</div>';
    if ((o.requires || []).length) h += '<div class="ps-hint">Needs ' + o.requires.map(k => '<em>' + esc((st.opts[k] || {}).label || k) + '</em>').join(', ') + '.</div>';
    if (sc === 'instance') h += o.type === 'secret' ? secretHtml(st, o) : instanceHtml(st, o);
    else if (sc === 'person') h += personHtml(st, o);
    else if (sc === 'group') h += groupScopeHtml(st, o);
    else if (sc === 'person_entered') h += enteredHtml(st, o);
    for (const w of o.warnings || []) h += '<div class="ps-warn">⚠ ' + esc(w) + '</div>';
    h += '<div class="ps-err" data-err-for="' + esc(o.key) + '"' + (st.errors[o.key] ? '' : ' hidden') + '>' + esc(st.errors[o.key] || '') + '</div>';
    return h;
  }

  // redrawOption rebuilds one option's markup. A typed secret value is
  // never put into markup: redrawing a secret option with one drops it
  // from the draft too, so the (empty) input and the draft agree.
  function redrawOption(st, key) {
    const box = st.el.querySelector('[data-opt="' + CSS.escape(key) + '"]');
    const o = st.opts[key];
    if (!box || !o) return;
    if (o.type === 'secret' && st.secrets[key] && 'value' in st.secrets[key]) delete st.secrets[key];
    box.innerHTML = optionInner(st, o, scopeOf(o));
  }

  // refocus focuses the first of selectors that matches an enabled
  // control in the panel (after a redraw replaced the focused one).
  function refocus(st, ...selectors) {
    for (const sel of selectors) {
      const x = st.el.querySelector(sel);
      if (x && !x.disabled) { x.focus(); return; }
    }
  }

  // setRowError shows (msg) or clears (null) a row's error in place.
  function setRowError(st, key, uid, msg) {
    const k = key + '\u0000' + uid;
    if (msg) st.rowErrors[k] = msg; else delete st.rowErrors[k];
    const li = st.el.querySelector('[data-row][data-key="' + CSS.escape(key) + '"][data-uid="' + CSS.escape(uid) + '"]');
    if (!li) return;
    let n = li.querySelector(':scope > .ps-row-err');
    if (!msg) { if (n) n.remove(); return; }
    if (!n) { n = document.createElement('div'); n.className = 'ps-err ps-row-err'; li.appendChild(n); }
    n.textContent = String(msg);
  }

  // setOptionError shows or clears an option's error in place.
  function setOptionError(st, key, msg) {
    if (msg) st.errors[key] = msg; else delete st.errors[key];
    const n = st.el.querySelector('[data-err-for="' + CSS.escape(key) + '"]');
    if (!n) return;
    n.textContent = msg ? String(msg) : '';
    n.hidden = !msg;
  }

  // ── editors ────────────────────────────────────────────────────────

  // editorHtml is the input(s) for one value of o. data-where says
  // where the value goes: "value" (instance), "default", "row"
  // (data-uid) — read back by readEditor.
  function editorHtml(st, o, v, where, uid, extra) {
    let h = '<span class="ps-ed ps-ed-' + esc(o.type) + '" data-ed data-key="' + esc(o.key) + '" data-where="' + esc(where) + '"' + (uid ? ' data-uid="' + esc(uid) + '"' : '') + '>';
    const lbl = ' aria-label="' + esc((extra && extra.label) || o.label || o.key) + '"';
    switch (o.type) {
      case 'bool':
        h += '<label class="ps-check"><input type="checkbox" data-part="bool"' + lbl + (v ? ' checked' : '') + '> ' + (v ? 'on' : 'off') + '</label>';
        break;
      case 'enum':
        h += '<select data-part="enum"' + lbl + '>';
        for (const c of o.options || []) h += '<option value="' + esc(c.value) + '"' + (c.value === v ? ' selected' : '') + '>' + esc(c.label || c.value) + '</option>';
        h += '</select>';
        break;
      case 'multi_enum': {
        const set = new Set(v || []);
        for (const c of o.options || []) h += '<label class="ps-check"><input type="checkbox" data-part="multi" value="' + esc(c.value) + '"' + (set.has(c.value) ? ' checked' : '') + '> ' + esc(c.label || c.value) + '</label>';
        break;
      }
      case 'size': {
        const unl = v === 'unlimited';
        const n = typeof v === 'number' ? v : null;
        let unit = 'GiB';
        if (n !== null) {
          unit = 'MiB';
          for (const u of SIZE_UNITS) if (n >= SIZE_MULT[u] && n % SIZE_MULT[u] === 0) unit = u;
          if (n > 0 && n % SIZE_MULT.MiB !== 0) unit = n >= SIZE_MULT.TiB ? 'TiB' : n >= SIZE_MULT.GiB ? 'GiB' : 'MiB';
        }
        const num = n === null ? '' : Number((n / SIZE_MULT[unit]).toPrecision(12));
        const step = sizeBytes(o.step);
        const stepAttr = step ? Number((step / SIZE_MULT[unit]).toPrecision(12)) : 'any';
        h += '<input type="number" min="0" data-part="num" step="' + esc(stepAttr) + '" value="' + esc(num) + '"' + lbl + (unl ? ' disabled' : '') + '>';
        h += '<select data-part="unit" aria-label="unit">' + SIZE_UNITS.map(u => '<option value="' + u + '"' + (u === unit ? ' selected' : '') + '>' + u + '</option>').join('') + '</select>';
        if (o.allow_unlimited) h += '<label class="ps-check"><input type="checkbox" data-part="unl"' + (unl ? ' checked' : '') + '> unlimited</label>';
        break;
      }
      case 'duration': {
        const n = typeof v === 'number' ? v : null;
        let unit = 's';
        if (n) for (const [u] of DUR_UNITS) if (n % DUR_MULT[u] === 0) unit = u;
        h += '<input type="number" min="0" step="1" data-part="num" value="' + esc(n === null ? '' : n / DUR_MULT[unit]) + '"' + lbl + '>';
        h += '<select data-part="unit" aria-label="unit">' + DUR_UNITS.map(([u, l]) => '<option value="' + u + '"' + (u === unit ? ' selected' : '') + '>' + l + '</option>').join('') + '</select>';
        break;
      }
      case 'int': {
        const a = ['min', 'max', 'step'].filter(k => typeof o[k] === 'number').map(k => ' ' + k + '="' + esc(o[k]) + '"').join('');
        h += '<input type="number" data-part="int"' + a + ' value="' + esc(v === null || v === undefined ? '' : v) + '"' + lbl + '>';
        if (o.unit) h += '<span class="ps-int-unit">' + esc(o.unit) + '</span>';
        break;
      }
      case 'list': case 'groups': case 'users':
        h += '<textarea data-part="lines" rows="3" placeholder="one per line"' + lbl + '>' + esc((v || []).join('\n')) + '</textarea>';
        break;
      case 'table':
        h += '<textarea data-part="json" rows="4" placeholder="[{&quot;column&quot;: &quot;value&quot;}]"' + lbl + '>' + esc(v === null || v === undefined ? '' : JSON.stringify(v, null, 1)) + '</textarea>';
        break;
      default: {
        const ph = extra && extra.placeholder ? ' placeholder="' + esc(extra.placeholder) + '"' : '';
        const ml = typeof o.max_len === 'number' ? ' maxlength="' + esc(o.max_len) + '"' : '';
        const list = o.type === 'group' && (st.panel.directory_groups || []).length ? ' list="ps-groups-' + esc(st.id) + '"' : '';
        h += '<input type="text" data-part="text" spellcheck="false" value="' + esc(v === null || v === undefined ? '' : v) + '"' + ph + ml + list + lbl + '>';
      }
    }
    return h + '</span>';
  }

  // readEditor returns {value} or {error}.
  function readEditor(o, ed) {
    const part = p => ed.querySelector('[data-part="' + p + '"]');
    switch (o.type) {
      case 'bool': return { value: part('bool').checked };
      case 'enum': return { value: part('enum').value };
      case 'multi_enum': return { value: [...ed.querySelectorAll('[data-part="multi"]:checked')].map(x => x.value) };
      case 'size': {
        const unl = part('unl');
        part('num').disabled = !!(unl && unl.checked);
        if (unl && unl.checked) return { value: 'unlimited' };
        const raw = part('num').value.trim();
        if (raw === '') return { error: 'enter a size' };
        const n = Number(raw);
        if (!isFinite(n) || n < 0) return { error: 'not a size' };
        const unit = part('unit').value;
        const bytes = Math.round(n * SIZE_MULT[unit]);
        const step = sizeBytes(o.step);
        part('num').step = step ? String(Number((step / SIZE_MULT[unit]).toPrecision(12))) : 'any';
        if (step && bytes % step !== 0) return { error: 'must be a multiple of ' + showSize(step) };
        const min = sizeBytes(o.min), max = sizeBytes(o.max);
        if (typeof min === 'number' && bytes < min) return { error: 'at least ' + showSize(min) };
        if (typeof max === 'number' && bytes > max) return { error: 'at most ' + showSize(max) };
        return { value: bytes };
      }
      case 'duration': {
        const raw = part('num').value.trim();
        if (raw === '') return { error: 'enter a duration' };
        const n = Number(raw);
        if (!Number.isInteger(n * DUR_MULT[part('unit').value]) || n < 0) return { error: 'whole seconds only' };
        const secs = n * DUR_MULT[part('unit').value];
        const step = durSeconds(o.step);
        if (step && secs % step !== 0) return { error: 'must be a multiple of ' + showDur(step) };
        return { value: secs };
      }
      case 'int': {
        const raw = part('int').value.trim();
        if (raw === '') return { value: null, empty: true };
        const n = Number(raw);
        if (!Number.isInteger(n)) return { error: 'a whole number' };
        if (typeof o.min === 'number' && n < o.min) return { error: 'at least ' + o.min };
        if (typeof o.max === 'number' && n > o.max) return { error: 'at most ' + o.max };
        if (typeof o.step === 'number' && o.step > 0 && (n - (typeof o.min === 'number' ? o.min : 0)) % o.step !== 0) return { error: 'in steps of ' + o.step };
        return { value: n };
      }
      case 'list': case 'groups': case 'users': {
        let items = part('lines').value.split('\n').map(s => s.trim()).filter(Boolean);
        if (o.type === 'list' && o.items && o.items.type === 'int') {
          if (items.some(x => !/^-?\d+$/.test(x))) return { error: 'whole numbers, one per line' };
          items = items.map(Number);
        }
        return { value: items };
      }
      case 'table': {
        const raw = part('json').value.trim();
        if (raw === '') return { value: null, empty: true };
        try { return { value: JSON.parse(raw) }; } catch (e) { return { error: 'not valid JSON' }; }
      }
      default: {
        const s = part('text').value;
        return s === '' ? { value: null, empty: true } : { value: s };
      }
    }
  }

  // ── instance options ───────────────────────────────────────────────

  // folderRefOf: "folder:<id>[/<sub>]" → {id, sub}, else null.
  function folderRefOf(v) {
    const m = typeof v === 'string' && /^folder:([a-z][a-z0-9-]{0,30})(?:\/(.+))?$/.exec(v);
    return m ? { id: m[1], sub: m[2] || '' } : null;
  }

  // folderPickHtml: "Custom path" / "Shared folder: <name>" (plan 2 call
  // 15). Choosing or leaving a shared folder opens the assignment preview
  // (PortcullisFolders.openAssign), never the panel's save: the Hub
  // refuses folder values through the settings save.
  function folderPickHtml(st, o, ref) {
    const fs = st.folders || [];
    if (!window.PortcullisFolders || (!fs.length && !ref)) return '';
    let h = '<div class="ps-folder-pick"><select data-folder-pick data-key="' + esc(o.key) + '" aria-label="' + esc((o.label || o.key) + ': path source') + '">' +
      '<option value=""' + (ref ? '' : ' selected') + '>Custom path</option>';
    let found = false;
    for (const f of fs) {
      const sel = ref && ref.id === f.id;
      found = found || sel;
      h += '<option value="' + esc(f.id) + '"' + (sel ? ' selected' : '') + '>Shared folder: ' + esc(f.name) + '</option>';
    }
    if (ref && !found) h += '<option value="' + esc(ref.id) + '" selected>Shared folder: ' + esc(ref.id) + ' (missing)</option>';
    h += '</select>';
    if (ref) {
      const f = fs.find(x => x.id === ref.id);
      h += '<button type="button" class="btn btn-sm btn-secondary" data-action="folder-change" data-key="' + esc(o.key) + '">Change subfolder…</button></div>';
      h += '<div class="ps-hint">Uses shared folder <strong>' + esc(f ? f.name : ref.id) + '</strong>' +
        (f ? ': <code>' + esc(f.path + (ref.sub ? '/' + ref.sub : '')) + '</code>' : '') +
        '. Changes go through Settings → Shared folders (a previewed assignment).</div>';
    } else {
      h += '</div>';
    }
    return h;
  }

  function instanceHtml(st, o) {
    const v = st.values[o.key];
    if (o.type === 'path') {
      const ref = folderRefOf((st.panel.instance || {})[o.key]);
      if (ref) return folderPickHtml(st, o, ref) + pathHint(st, o);
      const pick = folderPickHtml(st, o, null);
      if (pick) return pick + instanceInner(st, o, v) + pathHint(st, o);
    }
    return instanceInner(st, o, v) + (o.type === 'path' ? pathHint(st, o) : '');
  }

  // openFolderAssign runs the assignment preview for option key (folder
  // id chosen, or "" = leave the stored folder), then redraws: the panel
  // from the server after an apply, else the option as stored.
  async function openFolderAssign(st, key, folder) {
    const ref = folderRefOf((st.panel.instance || {})[key]);
    let spec;
    if (folder) spec = { folder, add: [{ instance: st.id, key, subpath: ref && ref.id === folder ? ref.sub : '' }] };
    else if (ref) spec = { folder: ref.id, remove: [{ instance: st.id, key }] };
    else return;
    const res = await window.PortcullisFolders.openAssign(spec);
    if (res && res.applied) render(st.el, st.id);
    else redrawOption(st, key);
  }

  function instanceInner(st, o, v) {
    const isDefault = v === null || v === undefined;
    const shown = isDefault ? canonical(o, o.default) : v;
    let h = '<div class="ps-inst">';
    h += editorHtml(st, o, shown, 'value', '', { placeholder: o.default_display ? 'default: ' + o.default_display : '' });
    if (isDefault) h += '<span class="ps-hint ps-inline">' + (o.default_display ? 'template default (' + esc(o.default_display) + ')' : 'not set') + '</span>';
    else if (o.default !== undefined) h += '<button type="button" class="btn btn-sm btn-secondary" data-action="use-default" data-key="' + esc(o.key) + '">Use default</button>';
    h += '</div>';
    return h;
  }

  // pathHint: the mount and "the app writes here as uid:gid" (writes_as
  // numbers, or the value of the instance option they name).
  function pathHint(st, o) {
    let h = '';
    if (o.target) h += '<div class="ps-hint">Mounted in ' + esc(o.target.service) + ' at <code>' + esc(o.target.mount) + '</code>' + (o.mode ? ' (' + esc(o.mode) + ')' : '') + '.</div>';
    if (o.writes_as) {
      const ref = r => {
        if (typeof r === 'number') return String(r);
        const ro = st.opts[r];
        const v = ro ? (st.values[r] !== null && st.values[r] !== undefined ? st.values[r] : canonical(ro, ro.default)) : null;
        return v === null || v === undefined ? String(r) : String(v);
      };
      h += '<div class="ps-hint">The app writes here as <code>' + esc(ref(o.writes_as.uid) + ':' + ref(o.writes_as.gid)) + '</code>.</div>';
    }
    return h;
  }

  // ── secrets ────────────────────────────────────────────────────────

  function secretHtml(st, o) {
    const sv = (st.panel.secrets || {})[o.key] || { set: false };
    const pend = st.secrets[o.key];
    let h = '<div class="ps-secret">';
    h += '<div class="ps-secret-status">' + (sv.set
      ? 'Set ✓' + (sv.updated_at ? ' (updated ' + esc(fmtDate(sv.updated_at)) + (sv.generated ? ', generated' : '') + ')' : '')
      : 'Not set') + '</div>';
    if (pend && pend.generate) h += '<div class="ps-pending">A new value is generated when you save. <button type="button" class="btn btn-sm btn-secondary" data-action="secret-undo" data-key="' + esc(o.key) + '">Undo</button></div>';
    else if (pend && pend.clear) h += '<div class="ps-pending">Cleared when you save. <button type="button" class="btn btn-sm btn-secondary" data-action="secret-undo" data-key="' + esc(o.key) + '">Undo</button></div>';
    else if (st.secretOpen && st.secretOpen[o.key]) {
      h += '<div class="ps-secret-input"><input type="password" autocomplete="new-password" spellcheck="false" data-secret-input="' + esc(o.key) + '" aria-label="New value for ' + esc(o.label || o.key) + '" placeholder="new value">';
      h += '<button type="button" class="btn btn-sm btn-secondary" data-action="secret-undo" data-key="' + esc(o.key) + '">Cancel</button></div>';
    } else {
      h += '<div class="ps-secret-actions">';
      h += '<button type="button" class="btn btn-sm btn-secondary" data-action="secret-replace" data-key="' + esc(o.key) + '">' + (sv.set ? 'Replace' : 'Set') + '</button>';
      if (o.generate) h += '<button type="button" class="btn btn-sm btn-secondary" data-action="secret-generate" data-key="' + esc(o.key) + '">Generate</button>';
      if (sv.set) h += '<button type="button" class="btn btn-sm btn-danger" data-action="secret-clear" data-key="' + esc(o.key) + '">Clear</button>';
      h += '</div>';
    }
    return h + '</div>';
  }

  // ── per-person and group-scope rows ────────────────────────────────

  function groupPicker(st, o, rows, r) {
    const used = new Set(rows.filter(x => x !== r).map(x => x.group.toLowerCase()));
    const choices = o.privileged ? (o.group_choices || []).map(c => ({ name: c.name, disabled: c.disabled, reason: c.reason }))
      : (st.panel.directory_groups || []).map(g => ({ name: g }));
    const lbl = ' aria-label="Group"';
    if (!choices.length) {
      return '<input type="text" class="ps-group" data-row-group data-key="' + esc(o.key) + '" data-uid="' + esc(r.uid) + '" value="' + esc(r.group) + '" placeholder="group"' + lbl + '>';
    }
    let h = '<select class="ps-group" data-row-group data-key="' + esc(o.key) + '" data-uid="' + esc(r.uid) + '"' + lbl + '>';
    if (!r.group) h += '<option value="" selected disabled>choose a group…</option>';
    let found = false;
    for (const c of choices) {
      const sel = c.name === r.group;
      found = found || sel;
      let label = c.name, dis = false;
      if (c.disabled) { label += " — can't grant a privileged value: " + (c.reason || 'refused'); dis = true; }
      else if (used.has(c.name.toLowerCase())) { label += ' — already has a row'; dis = true; }
      h += '<option value="' + esc(c.name) + '"' + (sel ? ' selected' : '') + (dis && !sel ? ' disabled' : '') + (c.reason ? ' title="' + esc(c.reason) + '"' : '') + '>' + esc(label) + '</option>';
    }
    if (r.group && !found) h += '<option value="' + esc(r.group) + '" selected>' + esc(r.group) + ' — not in the directory</option>';
    return h + '</select>';
  }

  function rowsHtml(st, o, rows, priority) {
    let h = '<ol class="ps-rows' + (priority ? ' ps-priority' : '') + '" data-rows="' + esc(o.key) + '">';
    rows.forEach((r, i) => {
      h += '<li class="ps-row" data-row data-key="' + esc(o.key) + '" data-uid="' + esc(r.uid) + '">';
      if (priority) {
        h += '<span class="ps-handle" draggable="true" data-handle data-key="' + esc(o.key) + '" data-uid="' + esc(r.uid) + '" title="Drag to reorder" aria-hidden="true">⠿</span>';
        h += '<span class="ps-rank">' + (i + 1) + '.</span>';
      }
      h += groupPicker(st, o, rows, r);
      h += editorHtml(st, o, r.value, 'row', r.uid, { label: (o.label || o.key) + ' for ' + (r.group || 'the new row') });
      if (priority) {
        h += '<button type="button" class="btn-icon ps-move" data-action="row-up" data-key="' + esc(o.key) + '" data-uid="' + esc(r.uid) + '"' + (i === 0 ? ' disabled' : '') + ' aria-label="Move ' + esc(r.group || 'row') + ' up" title="Move up">▲</button>';
        h += '<button type="button" class="btn-icon ps-move" data-action="row-down" data-key="' + esc(o.key) + '" data-uid="' + esc(r.uid) + '"' + (i === rows.length - 1 ? ' disabled' : '') + ' aria-label="Move ' + esc(r.group || 'row') + ' down" title="Move down">▼</button>';
      }
      h += '<button type="button" class="btn-icon" data-action="row-remove" data-key="' + esc(o.key) + '" data-uid="' + esc(r.uid) + '" aria-label="Remove the row for ' + esc(r.group || 'the new group') + '" title="Remove">✕</button>';
      const err = st.rowErrors[o.key + '\u0000' + r.uid];
      if (err) h += '<div class="ps-err ps-row-err">' + esc(err) + '</div>';
      h += '</li>';
    });
    h += '</ol>';
    h += '<button type="button" class="btn btn-sm btn-secondary ps-add" data-action="row-add" data-key="' + esc(o.key) + '">+ Add group</button>';
    return h;
  }

  function personHtml(st, o) {
    const p = st.person[o.key];
    const rule = p.resolve || o.resolve || 'max';
    const priority = rule === 'priority';
    let h = '<div class="ps-person">';
    if (priority) h += '<div class="ps-hint">Order matters: the first group a person is in gives their value. Drag the handles or use ▲ ▼.</div>';
    h += rowsHtml(st, o, p.rows, priority);
    const refused = (o.group_choices || []).filter(c => c.disabled);
    if (o.privileged && refused.length) {
      h += '<div class="ps-refused"><span>Can\'t grant a privileged value:</span><ul>' + refused.map(c => '<li data-refused-group="' + esc(c.name) + '"><span class="ps-user">' + esc(c.name) + '</span> — ' + esc(c.reason || 'refused') + '</li>').join('') + '</ul></div>';
    }
    h += '<div class="ps-row ps-row-default"><span class="ps-row-label">Everyone else with access</span>' + editorHtml(st, o, p.default, 'default', '', { label: (o.label || o.key) + ' for everyone else with access' }) + '</div>';
    const choices = [o.resolve, ...(o.resolve_choices || [])].filter((x, i, a) => x && a.indexOf(x) === i);
    h += '<div class="ps-resolve">When someone is in several groups: ';
    if (choices.length > 1) {
      h += '<select data-resolve data-key="' + esc(o.key) + '" aria-label="When someone is in several groups">';
      for (const c of choices) h += '<option value="' + esc(c === o.resolve ? '' : c) + '"' + (c === rule ? ' selected' : '') + '>' + esc(RESOLVE_LABEL[c] || c) + (c === o.resolve ? ' (template)' : '') + '</option>';
      h += '</select>';
    } else {
      h += '<strong>' + esc(RESOLVE_LABEL[rule] || rule) + '</strong>';
    }
    h += '</div>';
    h += '<div class="ps-who" data-who="' + esc(o.key) + '">' + whoHead(st, o) + '<div data-who-list="' + esc(o.key) + '">' + whoList(st, o) + '</div></div>';
    return h + '</div>';
  }

  function groupScopeHtml(st, o) {
    const rows = st.groups[o.key];
    let h = '<div class="ps-person">';
    if (!rows.length) h += '<div class="ps-hint">No group has a value yet.</div>';
    h += rowsHtml(st, o, rows, false);
    return h + '</div>';
  }

  // enteredHtml: a person_entered option's stored values (spec call 32).
  // Delivered values: "N of M people with access have entered one", with
  // search; stored values that aren't delivered, with the reason (no
  // access, account changed); population members without one. Clear on
  // every value; Set / Edit only with the template's admin_override.
  // Actions go straight to the entries API, never through the draft.
  function entryState(st, key) {
    if (!st.ent) st.ent = {};
    if (!st.ent[key]) st.ent[key] = { q: '', edit: null, error: '', busy: false };
    return st.ent[key];
  }

  function entryMatch(q, r) {
    if (!q) return true;
    q = q.toLowerCase();
    return String(r.user).toLowerCase().includes(q) || String(r.display || '').toLowerCase().includes(q);
  }

  function entryEditHtml(st, o, user, v) {
    const es = entryState(st, o.key);
    return '<span class="ps-entry-edit" data-entry-edit="' + esc(user) + '">' +
      editorHtml(st, o, v, 'entry', '', { label: (o.label || o.key) + ' for ' + user }) +
      '<button type="button" class="btn btn-primary btn-sm" data-action="entry-save" data-key="' + esc(o.key) + '" data-user="' + esc(user) + '"' + (es.busy ? ' disabled' : '') + '>Save</button>' +
      '<button type="button" class="btn btn-secondary btn-sm" data-action="entry-cancel" data-key="' + esc(o.key) + '">Cancel</button></span>';
  }

  function entryRowHtml(st, o, r) {
    const es = entryState(st, o.key);
    const k = ' data-key="' + esc(o.key) + '" data-user="' + esc(r.user) + '"';
    let h = '<li data-entry-row="' + esc(r.user) + '"><span class="ps-user">' + esc(r.user) + '</span>';
    if (es.edit === r.user) {
      h += entryEditHtml(st, o, r.user, r.value);
    } else {
      h += '<span class="ps-val">' + esc(r.display) + '</span>';
      h += '<span class="ps-why">' + (r.set_by && r.set_by !== r.user ? 'set by ' + esc(r.set_by) : 'entered') + ', ' + esc(fmtDate(r.updated_at)) +
        (r.delivered ? '' : ' · not delivered: ' + esc(r.why || 'unknown')) + '</span>';
      // Set / Edit only for people in the population (the Hub refuses
      // others; with the directory down it can't tell).
      if (o.admin_override && r.why !== 'no access' && r.why !== 'directory unavailable') h += '<button type="button" class="btn btn-secondary btn-sm" data-action="entry-edit"' + k + '>Edit</button>';
      h += '<button type="button" class="btn btn-danger btn-sm" data-action="entry-clear"' + k + (es.busy ? ' disabled' : '') + '>Clear</button>';
    }
    return h + '</li>';
  }

  function enteredHtml(st, o) {
    const ev = (st.panel.entries || {})[o.key] || { rows: [], not_set: [] };
    const es = entryState(st, o.key);
    const rows = ev.rows || [], notSet = ev.not_set || [];
    const delivered = rows.filter(r => r.delivered), stored = rows.filter(r => !r.delivered);
    const total = delivered.length + notSet.length;
    let h = '<div class="ps-entries" data-entries="' + esc(o.key) + '">';
    h += '<div class="ps-hint">Each person enters their own value on My apps' + (o.admin_override ? '; administrators may set one for them' : '') + (o.unique ? '. Values are unique: no two people can register the same one' : '') + '.</div>';
    h += '<div class="ps-who-head"><span data-entries-count>' + esc(delivered.length + ' of ' + plural(total, 'person', 'people') + ' with access ' + (delivered.length === 1 ? 'has' : 'have') + ' entered one') + '</span>' +
      '<input type="search" class="ps-search" data-entry-search data-key="' + esc(o.key) + '" value="' + esc(es.q) + '" placeholder="search…" aria-label="Search entered values"></div>';
    h += '<div data-entries-list="' + esc(o.key) + '">' + entriesList(st, o, delivered, stored, notSet) + '</div>';
    if (es.error) h += '<div class="ps-err" data-entry-error>' + esc(es.error) + '</div>';
    return h + '</div>';
  }

  function entriesList(st, o, delivered, stored, notSet) {
    const es = entryState(st, o.key);
    let h = '';
    const d = delivered.filter(r => entryMatch(es.q, r));
    h += '<ul class="ps-who-rows" data-entries-delivered>' + (d.length ? d.map(r => entryRowHtml(st, o, r)).join('') : '<li class="ps-muted">' + esc(es.q ? 'No match.' : 'Nobody has entered one yet.') + '</li>') + '</ul>';
    const s = stored.filter(r => entryMatch(es.q, r));
    if (s.length) {
      h += '<div class="ps-hint">Stored, not delivered</div><ul class="ps-who-rows" data-entries-stored>' + s.map(r => entryRowHtml(st, o, r)).join('') + '</ul>';
    }
    const n = notSet.filter(u => entryMatch(es.q, { user: u }));
    if (n.length) {
      h += '<div class="ps-hint">Not set</div><ul class="ps-who-rows" data-entries-notset>';
      for (const u of n) {
        h += '<li data-entry-row="' + esc(u) + '"><span class="ps-user">' + esc(u) + '</span>';
        if (es.edit === u) h += entryEditHtml(st, o, u, null);
        else if (o.admin_override) h += '<button type="button" class="btn btn-secondary btn-sm" data-action="entry-edit" data-key="' + esc(o.key) + '" data-user="' + esc(u) + '">Set</button>';
        h += '</li>';
      }
      h += '</ul>';
    }
    return h;
  }

  function redrawEntries(st, key) {
    const o = st.opts[key];
    const box = st.el.querySelector('[data-entries-list="' + CSS.escape(key) + '"]');
    if (!o || !box) return;
    const ev = (st.panel.entries || {})[key] || { rows: [], not_set: [] };
    const rows = ev.rows || [];
    box.innerHTML = entriesList(st, o, rows.filter(r => r.delivered), rows.filter(r => !r.delivered), ev.not_set || []);
  }

  // entryRequest sets (value !== undefined) or clears user's value, then
  // reloads the panel's entries and deliveries (the draft is kept).
  async function entryRequest(st, key, user, value) {
    const es = entryState(st, key);
    const url = '/api/instances/' + encodeURIComponent(st.id) + '/settings/entries/' + encodeURIComponent(key) + '/' + encodeURIComponent(user);
    es.busy = true;
    es.error = '';
    redrawOption(st, key);
    try {
      if (value === undefined) await window.apiCall(url, 'DELETE');
      else await window.apiPut(url, { value });
      es.edit = null;
      window.showToast && window.showToast(value === undefined ? 'Value cleared' : 'Value saved', 'success');
    } catch (err) {
      es.error = err.message || 'failed';
    }
    try {
      const p = await window.apiGet('/api/instances/' + encodeURIComponent(st.id) + '/settings');
      st.panel.entries = p.entries;
      st.panel.deliveries = p.deliveries;
      redrawStrip(st);
    } catch (e) { /* keep the old lists */ }
    es.busy = false;
    redrawOption(st, key);
  }

  // ── who gets what ──────────────────────────────────────────────────

  function population(st) {
    return (st.preview && st.preview.population) || st.panel.population || { count: 0 };
  }

  function whoHead(st, o) {
    const pop = population(st);
    const w = st.who[o.key];
    return '<div class="ps-who-head"><span>Who gets what (' + esc(plural(pop.count || 0, 'person', 'people')) + ' with access)</span>' +
      '<input type="search" class="ps-search" data-who-search data-key="' + esc(o.key) + '" value="' + esc(w.q) + '" placeholder="search…" aria-label="Search people"></div>';
  }

  function reasonText(o, p) {
    const r = p.reason || {};
    switch (r.source) {
      case 'group':
        if ((r.others || []).length) {
          const all = [r.group + ' (' + p.display + ')', ...r.others.map(c => c.group + ' (' + display(o, c.value) + ')')];
          return (RULE_OF[r.rule] || r.rule + ' of') + ' ' + all.join(', ');
        }
        return 'from ' + r.group;
      case 'default': return 'everyone else with access';
      case 'combined': return 'combined from ' + (r.groups || []).join(', ');
      case 'fail-closed': return 'fail-closed: the rows could not be resolved safely' + ((r.others || []).length ? ' (' + r.others.map(c => c.group).join(', ') + ')' : '');
    }
    return '';
  }

  function personValue(p) {
    const fc = (p.reason || {}).source === 'fail-closed';
    if (p.display === UNRESOLVED) return UNRESOLVED;
    return p.display + (fc ? ' (fail-closed)' : '');
  }

  function whoList(st, o) {
    const pop = population(st);
    if (pop.why) return '<div class="ps-hint">Nobody gets a per-person value: ' + esc(pop.why) + '.</div>';
    const op = st.preview && st.preview.options && st.preview.options[o.key];
    if (!op) return '<div class="ps-hint">' + (st.previewError ? 'No preview: fix the error above.' : 'Loading the preview…') + '</div>';
    const w = st.who[o.key];
    const q = w.q.trim().toLowerCase();
    const people = q ? op.people.filter(p => p.user.toLowerCase().includes(q) || personValue(p).toLowerCase().includes(q) || reasonText(o, p).toLowerCase().includes(q)) : op.people;
    const pages = Math.max(1, Math.ceil(people.length / PAGE));
    if (w.page >= pages) w.page = pages - 1;
    let h = '';
    if (!people.length) h += '<div class="ps-hint">' + (q ? 'Nobody matches.' : 'Nobody has access.') + '</div>';
    else {
      h += '<ul class="ps-who-rows">';
      for (const p of people.slice(w.page * PAGE, (w.page + 1) * PAGE)) {
        h += '<li><span class="ps-user">' + esc(p.user) + '</span><span class="ps-val' + (p.display === UNRESOLVED ? ' ps-unresolved' : '') + '">' + esc(personValue(p)) + '</span><span class="ps-why">' + esc(reasonText(o, p)) + '</span></li>';
      }
      h += '</ul>';
    }
    if (pages > 1) {
      h += '<div class="ps-pager"><button type="button" class="btn btn-sm btn-secondary" data-action="who-prev" data-key="' + esc(o.key) + '"' + (w.page === 0 ? ' disabled' : '') + '>‹ Previous</button>';
      h += '<span>' + esc((w.page * PAGE + 1) + '–' + Math.min(people.length, (w.page + 1) * PAGE) + ' of ' + people.length) + '</span>';
      h += '<button type="button" class="btn btn-sm btn-secondary" data-action="who-next" data-key="' + esc(o.key) + '"' + (w.page >= pages - 1 ? ' disabled' : '') + '>Next ›</button></div>';
    }
    const name = st.panel.name || st.id;
    for (const [g, n] of Object.entries(op.no_access || {})) {
      if (n > 0) h += '<div class="ps-warn">⚠ ' + esc(plural(n, 'member', 'members') + ' of ' + g + ' ' + (n === 1 ? 'has' : 'have') + ' no access to ' + name + ' and ' + (n === 1 ? 'gets' : 'get') + ' nothing.') + '</div>';
    }
    return h;
  }

  function redrawWho(st) {
    for (const k in st.person) {
      const o = st.opts[k];
      const head = st.el.querySelector('[data-who="' + CSS.escape(k) + '"] .ps-who-head span');
      if (head) head.textContent = 'Who gets what (' + plural(population(st).count || 0, 'person', 'people') + ' with access)';
      const list = st.el.querySelector('[data-who-list="' + CSS.escape(k) + '"]');
      if (list) list.innerHTML = whoList(st, o);
    }
  }

  // ── ports ──────────────────────────────────────────────────────────

  function portsHtml(st) {
    const defs = st.panel.port_definitions || [];
    if (!defs.length) return '';
    let h = '<div class="ports-section"><div class="ports-title">Host Ports</div>';
    for (const p of defs) {
      const proto = String(p.protocol || 'tcp').toLowerCase();
      const bindKey = p.key + '_BIND';
      const host = p.key in st.ports ? st.ports[p.key] : (p.range ? String(p.range) : String(p.default || ''));
      const bind = st.ports[bindKey] || p.bind || '0.0.0.0';
      h += '<div class="port-row"><div class="port-meta"><span class="port-label">' + esc(p.label || p.key) + '</span>';
      h += '<span class="port-badge port-' + esc(proto) + '">' + esc(proto.toUpperCase()) + '</span>';
      if (p.network_mode_host) h += '<span class="port-badge port-host">host net</span>';
      if (p.range) h += '<span class="port-badge port-range">range</span>';
      else h += '<span class="port-container">&rarr; :' + esc(p.container || '') + '</span>';
      h += '</div>';
      if (p.description) h += '<small>' + esc(p.description) + '</small>';
      if (p.range) {
        h += '<div class="port-inputs"><input type="text" data-port="' + esc(p.key) + '" value="' + esc(host) + '" placeholder="' + esc(p.range) + '" class="port-host" aria-label="' + esc(p.label || p.key) + '"></div>';
        h += '<small class="port-hint">low-high; the app binds these host ports itself.</small>';
      } else if (p.network_mode_host) {
        h += '<div class="port-inputs"><input type="number" min="1" max="65535" data-port="' + esc(p.key) + '" value="' + esc(host) + '" placeholder="' + (p.required ? 'required' : 'disabled') + '" class="port-host" aria-label="' + esc(p.label || p.key) + '"></div>';
        h += '<small class="port-hint">Host network: the app binds this host port itself.</small>';
      } else {
        h += '<div class="port-inputs"><input type="text" data-port="' + esc(bindKey) + '" value="' + esc(bind) + '" placeholder="0.0.0.0" class="port-bind" aria-label="Bind address">';
        h += '<input type="number" min="1" max="65535" data-port="' + esc(p.key) + '" value="' + esc(host) + '" placeholder="' + (p.required ? 'required' : 'disabled') + '" class="port-host" aria-label="' + esc(p.label || p.key) + '">';
        h += '<button type="button" class="btn btn-sm" data-action="port-reset" data-key="' + esc(p.key) + '">Reset</button></div>';
        if (!p.required) h += '<small class="port-hint">Leave the host port empty to disable this binding.</small>';
      }
      h += '</div>';
    }
    return h + '</div>';
  }

  // ── deliveries strip ───────────────────────────────────────────────

  function unitLabel(u) {
    const [kind, name] = [u.split(':')[0], u.slice(u.indexOf(':') + 1)];
    switch (kind) {
      case 'env': return name === 'values' ? 'Environment values written empty' : "Environment (.env, read when the app starts)";
      case 'file': return 'Data file ' + name;
      case 'hook': return 'Hook ' + name;
      case 'claim': return 'Sign-in claim ' + name;
      case 'headers': return 'Request headers';
      case 'reload': return 'Reload';
      case 'restart': return 'Restart';
      case 'delivery': return 'Delivery';
    }
    return u;
  }

  function stripHtml(st) {
    const d = st.panel.deliveries || { units: {} };
    const units = Object.values(d.units || {}).sort((a, b) => a.unit.localeCompare(b.unit));
    const failed = units.some(u => u.error);
    let h = '<div class="ps-strip-head"><span class="ps-strip-title">Deliveries</span>';
    if (d.pending) h += '<span class="ps-hint ps-inline">a run is queued' + (d.trigger ? ' (' + esc(d.trigger) + ')' : '') + '</span>';
    h += '<button type="button" class="btn btn-sm ' + (failed ? 'btn-primary' : 'btn-secondary') + '" data-action="retry"' + (st.retrying ? ' disabled' : '') + '>' + (st.retrying ? '<span class="ps-spin" aria-hidden="true"></span> Retrying…' : 'Retry') + '</button></div>';
    if (!units.length) return h + '<div class="ps-hint">Nothing delivered yet.</div>';
    h += '<ul class="ps-units">';
    for (const u of units) {
      let cls, text;
      if (u.error) { cls = 'failed'; text = 'failed: ' + u.error; }
      else if (u.skipped) { cls = 'skipped'; text = SKIP_TEXT[u.skipped] || ('skipped: ' + u.skipped); }
      else { cls = 'ok'; text = 'last applied' + (u.message ? ': ' + u.message : ''); }
      h += '<li class="ps-unit ps-unit-' + cls + '" data-unit="' + esc(u.unit) + '"><span class="ps-unit-name">' + esc(unitLabel(u.unit)) + '</span>';
      h += '<span class="ps-unit-text">' + esc(text) + '</span><span class="ps-unit-at">' + esc(u.at ? fmtDate(u.at) : '') + '</span></li>';
    }
    return h + '</ul>';
  }

  function redrawStrip(st) {
    const s = st.el.querySelector('[data-ps-strip]');
    if (s) s.innerHTML = stripHtml(st);
  }

  // ── save bar ───────────────────────────────────────────────────────

  function effectText(st, b) {
    const name = st.panel.name || st.id;
    const enabled = !!st.panel.enabled;
    const opts = changedOptions(st);
    const hasOptions = opts.length > 0 || 'ports' in b;
    const access = 'sign_in' in b || 'auth_policy' in b || 'auth_policy_inherit' in b || 'public_access' in b;
    let base = '';
    if (hasOptions) {
      const eff = st.preview && st.previewFor === JSON.stringify(b) ? st.preview.effect : '';
      if (!eff) base = 'Checking what saving does…';
      else if (eff === 'restart' || eff === 'reload') base = enabled ? 'Saving ' + (eff === 'restart' ? 'restarts ' : 'reloads ') + name : name + ' is not running: the change applies when it starts';
      else {
        const texts = [...new Set(opts.map(o => NO_RESTART_TEXT[o.applies] || '').filter(Boolean))];
        base = texts.length ? texts.join(' · ') : (enabled ? 'No restart needed' : 'Saved for the next start');
      }
    }
    if (access) {
      const t = enabled ? 'the sign-in/access change restarts ' + name : 'the sign-in/access change applies when ' + name + ' starts';
      base = base ? base + ' and ' + t : t.charAt(0).toUpperCase() + t.slice(1);
    }
    return base;
  }

  function changesText(st, b) {
    if (!st.preview || st.previewFor !== JSON.stringify(b)) return '';
    const parts = [];
    for (const k of changedPersonKeys(st)) {
      const op = (st.preview.options || {})[k];
      if (op) parts.push({ label: st.opts[k].label || k, n: op.changes || 0 });
    }
    if (!parts.length) return '';
    const one = p => plural(p.n, 'person gets', 'people get') + ' a new value';
    if (parts.length === 1) return 'Changes: ' + one(parts[0]);
    return 'Changes: ' + parts.map(p => p.label + ': ' + one(p)).join('; ');
  }

  // The bar's buttons stay in place (redrawn in place, never replaced):
  // a preview finishing while the admin clicks Save must not swallow the
  // click.
  function barHtml() {
    return '<div class="ps-bar-actions">' +
      '<button type="submit" class="btn btn-primary btn-sm" data-action="save" disabled>Save</button>' +
      '<button type="button" class="btn btn-secondary btn-sm" data-action="discard" disabled>Discard</button></div>' +
      '<div class="ps-bar-text" data-ps-bar-text></div>';
  }

  function barText(st, b, dirty) {
    const blocked = Object.keys(st.errors).length > 0 || Object.keys(st.rowErrors).length > 0;
    let h = '';
    if (st.saving) h += '<div class="ps-effect">Saving — a reload can take up to 10 seconds…</div>';
    else if (!dirty) h += '<div class="ps-effect ps-muted">No unsaved changes.</div>';
    else {
      h += '<div class="ps-effect" data-ps-effect>' + esc(effectText(st, b)) + '</div>';
      const c = changesText(st, b);
      if (c) h += '<div class="ps-changes" data-ps-changes>' + esc(c) + '</div>';
      if (blocked && !st.barError) h += '<div class="ps-err">Fix the marked values first.</div>';
    }
    if (st.barError) h += '<div class="ps-err" data-ps-bar-error>' + esc(st.barError) + '</div>';
    return h;
  }

  function redrawBar(st) {
    const bar = st.el.querySelector('[data-ps-bar]');
    if (!bar) return;
    const b = body(st);
    const dirty = Object.keys(b).length > 0;
    const saveBtn = bar.querySelector('[data-action="save"]');
    saveBtn.disabled = st.saving || !dirty;
    saveBtn.innerHTML = st.saving ? '<span class="ps-spin" aria-hidden="true"></span> Saving…' : 'Save';
    bar.querySelector('[data-action="discard"]').disabled = st.saving || !dirty;
    bar.querySelector('[data-ps-bar-text]').innerHTML = barText(st, b, dirty);
    bar.classList.toggle('ps-busy', st.saving);
    bar.setAttribute('aria-busy', st.saving ? 'true' : 'false');
    st.el.querySelector('form[data-ps-form]')?.classList.toggle('ps-saving', st.saving);
  }

  // ── errors from the server ─────────────────────────────────────────

  // clearServerErrors drops the Hub's refusals, clearing their nodes in
  // place (no option is redrawn: focus, caret and typed secrets stay).
  function clearServerErrors(st) {
    for (const k of Object.keys(st.errors)) if (st.errors[k] && st.errors[k].server) setOptionError(st, k, null);
    for (const k of Object.keys(st.rowErrors)) {
      if (st.rowErrors[k] && st.rowErrors[k].server) {
        const [key, uid] = k.split('\u0000');
        setRowError(st, key, uid, null);
      }
    }
    st.barError = '';
  }

  // placeError shows a refusal next to what it concerns: "setting <key>:
  // group <g> …" next to that row, "setting <key>: …" next to the
  // option, anything else in the save bar. 409s say so.
  function placeError(st, err) {
    const msg = (err.status === 409 ? 'Refused (409): ' : err.status === 400 ? '' : (err.status ? 'Error ' + err.status + ': ' : '')) + (err.message || String(err));
    const m = /^setting ([a-z][a-z0-9_]*):\s*(.*)$/s.exec(err.message || '');
    if (m && st.opts[m[1]]) {
      const key = m[1];
      const g = /^group (\S+?)[:,]? /.exec(m[2]) || /group (\S+?) (?:was|is|has)/.exec(m[2]);
      const rows = st.person[key] ? st.person[key].rows : st.groups[key];
      const row = g && rows ? rows.find(r => r.group.toLowerCase() === g[1].toLowerCase()) : null;
      const e = Object.assign(new String(msg), { server: true });
      if (row) setRowError(st, key, row.uid, e);
      else setOptionError(st, key, e);
      st.barError = err.status === 409 ? 'Refused (409): see ' + (st.opts[key].label || key) + '.' : 'See ' + (st.opts[key].label || key) + '.';
      return;
    }
    st.barError = msg;
  }

  // ── preview ────────────────────────────────────────────────────────

  function schedulePreview(st) {
    clearTimeout(st.timer);
    redrawBar(st);
    st.timer = setTimeout(() => runPreview(st), DEBOUNCE_MS);
  }

  async function runPreview(st) {
    if (Object.keys(st.errors).some(k => !st.errors[k].server) || Object.keys(st.rowErrors).some(k => !st.rowErrors[k].server)) {
      redrawBar(st);
      return;
    }
    const b = body(st);
    const key = JSON.stringify(b);
    const seq = ++st.previewSeq;
    try {
      const p = await window.apiPost('/api/instances/' + encodeURIComponent(st.id) + '/settings/preview', b);
      if (seq !== st.previewSeq || states.get(st.el) !== st) return;
      clearServerErrors(st);
      st.preview = p;
      st.previewFor = key;
      st.previewError = '';
      redrawWho(st);
    } catch (err) {
      if (seq !== st.previewSeq || states.get(st.el) !== st) return;
      clearServerErrors(st);
      st.previewError = err.message;
      st.preview = null;
      placeError(st, err);
      redrawWho(st);
    }
    redrawBar(st);
  }

  // ── actions ────────────────────────────────────────────────────────

  function rowList(st, key) {
    return st.person[key] ? st.person[key].rows : st.groups[key];
  }

  function newRowValue(st, o) {
    if (st.person[o.key]) return JSON.parse(JSON.stringify(st.person[o.key].default));
    switch (o.type) {
      case 'bool': return false;
      case 'list': case 'multi_enum': case 'groups': case 'users': return [];
      case 'enum': return (o.options || [])[0] ? o.options[0].value : '';
      default: return canonical(o, o.default);
    }
  }

  function moveRow(st, key, uid, to) {
    const rows = rowList(st, key);
    const i = rows.findIndex(r => r.uid === uid);
    if (i < 0 || to < 0 || to >= rows.length || to === i) return false;
    const [r] = rows.splice(i, 1);
    rows.splice(to, 0, r);
    return true;
  }

  async function save(st) {
    if (st.saving) return;
    clearTimeout(st.timer);
    const b = body(st);
    if (!Object.keys(b).length) return;
    if (Object.keys(st.errors).some(k => !st.errors[k].server) || Object.keys(st.rowErrors).some(k => !st.rowErrors[k].server)) {
      st.barError = 'Fix the marked values first.';
      redrawBar(st);
      return;
    }
    st.saving = true;
    clearServerErrors(st);
    redrawBar(st);
    try {
      const res = await window.apiPut('/api/instances/' + encodeURIComponent(st.id) + '/settings', b);
      // The draft (typed secret values included) is dropped: the panel
      // is rebuilt from the server, its password inputs empty.
      st.secrets = {};
      let flash = '<strong>Saved.</strong> ' + esc(res.changed && res.changed.length ? 'Changed: ' + res.changed.join(', ') + '.' : '');
      for (const w of res.warnings || []) flash += '<div class="ps-warn">⚠ ' + esc(w) + '</div>';
      st.flash = flash;
      window.showToast && window.showToast('Settings saved', 'success');
      await render(st.el, st.id);
    } catch (err) {
      st.saving = false;
      placeError(st, err);
      redrawBar(st);
      window.showToast && window.showToast(err.message || 'Failed to save settings', 'error');
    }
  }

  async function retry(st) {
    if (st.retrying) return;
    st.retrying = true;
    redrawStrip(st);
    try {
      await window.apiPost('/api/instances/' + encodeURIComponent(st.id) + '/settings/retry', {});
    } catch (err) {
      window.showToast && window.showToast(err.message || 'Retry failed', 'error');
    }
    try {
      const p = await window.apiGet('/api/instances/' + encodeURIComponent(st.id) + '/settings');
      st.panel.deliveries = p.deliveries;
    } catch (e) { /* keep the old strip */ }
    st.retrying = false;
    redrawStrip(st);
  }

  // onEdit reads an edited value into the draft.
  function onEdit(st, ed) {
    const key = ed.dataset.key, o = st.opts[key];
    if (!o || ed.dataset.where === 'entry') return; // read on Save (entryRequest)
    const where = ed.dataset.where, uid = ed.dataset.uid;
    const r = readEditor(o, ed);
    const errKey = where === 'row' ? key + '\u0000' + uid : key;
    const errs = where === 'row' ? st.rowErrors : st.errors;
    let box = where === 'row' ? ed.closest('[data-row]') : ed.closest('.ps-row-default, .ps-inst');
    let errEl = box && box.querySelector(':scope > .ps-err-local');
    if (r.error) {
      errs[errKey] = new String(r.error);
      if (box && !errEl) { errEl = document.createElement('div'); errEl.className = 'ps-err ps-err-local'; box.appendChild(errEl); }
      if (errEl) errEl.textContent = r.error;
      ed.classList.add('ps-invalid');
      redrawBar(st);
      return;
    }
    delete errs[errKey];
    if (errEl) errEl.remove();
    ed.classList.remove('ps-invalid');
    const lbl = ed.querySelector('.ps-check');
    if (o.type === 'bool' && lbl) lbl.lastChild.textContent = r.value ? ' on' : ' off';
    let v = r.value;
    if (where === 'value') {
      if (r.empty) v = null;
      st.values[key] = v;
    } else if (where === 'default') {
      st.person[key].default = v;
    } else {
      const row = rowList(st, key).find(x => x.uid === uid);
      if (row) row.value = v;
    }
    schedulePreview(st);
  }

  function bind(el) {
    if (el.dataset.psBound) return;
    el.dataset.psBound = '1';
    const stOf = () => states.get(el);

    el.addEventListener('submit', e => {
      e.preventDefault();
      e.stopPropagation();
      const st = stOf();
      if (st) save(st);
    });

    const onInput = e => {
      const st = stOf();
      if (!st || st.saving) return;
      const t = e.target;
      if (t.matches('[data-folder-pick]')) {
        if (e.type === 'change') openFolderAssign(st, t.dataset.key, t.value);
        return;
      }
      if (t.matches('[data-who-search]')) {
        st.who[t.dataset.key].q = t.value;
        st.who[t.dataset.key].page = 0;
        const list = el.querySelector('[data-who-list="' + CSS.escape(t.dataset.key) + '"]');
        if (list) list.innerHTML = whoList(st, st.opts[t.dataset.key]);
        return;
      }
      if (t.matches('[data-entry-search]')) {
        entryState(st, t.dataset.key).q = t.value;
        redrawEntries(st, t.dataset.key);
        return;
      }
      if (t.matches('[data-secret-input]')) {
        const k = t.dataset.secretInput;
        if (t.value === '') delete st.secrets[k]; else st.secrets[k] = { value: t.value };
        schedulePreview(st);
        return;
      }
      if (t.matches('[data-port]')) {
        st.ports[t.dataset.port] = t.value.trim();
        schedulePreview(st);
        return;
      }
      if (t.matches('[data-row-group]')) {
        if (e.type !== 'change' && t.tagName === 'SELECT') return;
        const key = t.dataset.key, uid = t.dataset.uid;
        const row = rowList(st, key).find(r => r.uid === uid);
        if (row) row.group = t.value.trim();
        if (t.tagName === 'SELECT') {
          delete st.rowErrors[key + '\u0000' + uid];
          redrawOption(st, key);
          refocus(st, '[data-row-group][data-uid="' + CSS.escape(uid) + '"]');
        } else {
          setRowError(st, key, uid, t.value.trim() === '' ? new String('choose a group') : null);
        }
        schedulePreview(st);
        return;
      }
      if (t.matches('[data-resolve]')) {
        if (e.type !== 'change') return;
        st.person[t.dataset.key].resolve = t.value;
        redrawOption(st, t.dataset.key);
        refocus(st, '[data-resolve][data-key="' + CSS.escape(t.dataset.key) + '"]');
        schedulePreview(st);
        return;
      }
      const ed = t.closest('[data-ed]');
      if (ed) {
        if (e.type === 'input' && (t.type === 'checkbox' || t.tagName === 'SELECT')) return; // their change event follows
        onEdit(st, ed);
        return;
      }
      // The access policy, sign-in and public blocks (index.html).
      if (t.closest('.policy-section, .public-section')) schedulePreview(st);
    };
    el.addEventListener('input', onInput);
    el.addEventListener('change', onInput);

    el.addEventListener('keydown', e => {
      if (e.key === 'Enter' && e.target.matches('[data-who-search], [data-entry-search]')) e.preventDefault();
    });

    el.addEventListener('click', e => {
      const st = stOf();
      if (!st) return;
      // index.html's public-token "Remove" button edits the form inline.
      if (e.target.closest('.public-section')) setTimeout(() => schedulePreview(st), 0);
      const b = e.target.closest('[data-action]');
      if (!b || !el.contains(b) || b.disabled) return;
      const key = b.dataset.key, uid = b.dataset.uid;
      const o = key ? st.opts[key] : null;
      switch (b.dataset.action) {
        case 'save': return; // the submit handler saves
        case 'discard': {
          st.secrets = {};
          st.errors = {};
          st.rowErrors = {};
          render(el, st.id);
          return;
        }
        case 'retry': retry(st); return;
        case 'entry-edit': {
          const es = entryState(st, key);
          es.edit = b.dataset.user;
          es.error = '';
          redrawOption(st, key);
          refocus(st, '[data-entry-edit="' + CSS.escape(b.dataset.user) + '"] input, [data-entry-edit="' + CSS.escape(b.dataset.user) + '"] select');
          return;
        }
        case 'entry-cancel': {
          const es = entryState(st, key);
          es.edit = null;
          es.error = '';
          redrawOption(st, key);
          return;
        }
        case 'entry-save': {
          const ed = b.closest('[data-entry-edit]')?.querySelector('[data-ed]');
          if (!ed || !o) return;
          const r = readEditor(o, ed);
          if (r.error || r.empty) {
            entryState(st, key).error = r.error || 'enter a value (Clear removes it)';
            redrawOption(st, key);
            return;
          }
          entryRequest(st, key, b.dataset.user, r.value);
          return;
        }
        case 'entry-clear': {
          if (!window.confirm('Clear ' + b.dataset.user + "'s " + ((o && o.label) || key) + '? The app stops receiving it.')) return;
          entryRequest(st, key, b.dataset.user, undefined);
          return;
        }
        case 'row-add': {
          rowList(st, key).push({ uid: nextUid(), group: '', value: newRowValue(st, o), group0: '', gid0: 0 });
          // A row without a group can't be previewed or saved yet.
          st.rowErrors[key + '\u0000' + rowList(st, key).slice(-1)[0].uid] = new String('choose a group');
          redrawOption(st, key);
          el.querySelector('[data-rows="' + CSS.escape(key) + '"] li:last-child [data-row-group]')?.focus();
          redrawBar(st);
          return;
        }
        case 'row-remove': {
          const rows = rowList(st, key);
          const i = rows.findIndex(r => r.uid === uid);
          if (i >= 0) rows.splice(i, 1);
          delete st.rowErrors[key + '\u0000' + uid];
          redrawOption(st, key);
          schedulePreview(st);
          return;
        }
        case 'row-up': case 'row-down': {
          const rows = rowList(st, key);
          const i = rows.findIndex(r => r.uid === uid);
          if (moveRow(st, key, uid, i + (b.dataset.action === 'row-up' ? -1 : 1))) {
            redrawOption(st, key);
            // At an end the pressed button is disabled: its sibling, else
            // the row's group picker, takes the focus.
            const other = b.dataset.action === 'row-up' ? 'row-down' : 'row-up';
            const u = '[data-uid="' + CSS.escape(uid) + '"]';
            refocus(st, '[data-action="' + b.dataset.action + '"]' + u, '[data-action="' + other + '"]' + u, '[data-row-group]' + u);
            schedulePreview(st);
          }
          return;
        }
        case 'who-prev': case 'who-next': {
          st.who[key].page += b.dataset.action === 'who-next' ? 1 : -1;
          const list = el.querySelector('[data-who-list="' + CSS.escape(key) + '"]');
          if (list) list.innerHTML = whoList(st, o);
          return;
        }
        case 'folder-change': {
          const ref = folderRefOf((st.panel.instance || {})[key]);
          if (ref) openFolderAssign(st, key, ref.id);
          return;
        }
        case 'use-default': {
          st.values[key] = null;
          delete st.errors[key];
          redrawOption(st, key);
          schedulePreview(st);
          return;
        }
        case 'secret-replace': {
          st.secretOpen = Object.assign({}, st.secretOpen, { [key]: true });
          redrawOption(st, key);
          el.querySelector('[data-secret-input="' + CSS.escape(key) + '"]')?.focus();
          return;
        }
        case 'secret-generate': {
          st.secrets[key] = { generate: true };
          redrawOption(st, key);
          schedulePreview(st);
          return;
        }
        case 'secret-clear': {
          if (!window.confirm('Clear ' + (o.label || key) + '? The app loses this secret when you save.')) return;
          st.secrets[key] = { clear: true };
          redrawOption(st, key);
          schedulePreview(st);
          return;
        }
        case 'secret-undo': {
          delete st.secrets[key];
          if (st.secretOpen) delete st.secretOpen[key];
          redrawOption(st, key);
          schedulePreview(st);
          return;
        }
        case 'port-reset': {
          const def = (st.panel.port_definitions || []).find(p => p.key === key);
          if (!def) return;
          st.ports[key] = def.default ? String(def.default) : '';
          st.ports[key + '_BIND'] = def.bind || '0.0.0.0';
          const host = el.querySelector('[data-port="' + CSS.escape(key) + '"]');
          const bindEl = el.querySelector('[data-port="' + CSS.escape(key + '_BIND') + '"]');
          if (host) host.value = st.ports[key];
          if (bindEl) bindEl.value = st.ports[key + '_BIND'];
          schedulePreview(st);
          return;
        }
      }
    });

    // Priority order: drag a row by its handle onto another row.
    el.addEventListener('dragstart', e => {
      const st = stOf();
      const hdl = e.target.closest && e.target.closest('[data-handle]');
      if (!st || !hdl) return;
      st.drag = { key: hdl.dataset.key, uid: hdl.dataset.uid };
      e.dataTransfer.effectAllowed = 'move';
      e.dataTransfer.setData('text/plain', hdl.dataset.uid);
      hdl.closest('[data-row]')?.classList.add('ps-dragging');
    });
    el.addEventListener('dragover', e => {
      const st = stOf();
      const row = e.target.closest && e.target.closest('[data-row]');
      if (!st || !st.drag || !row || row.dataset.key !== st.drag.key) return;
      e.preventDefault();
      e.dataTransfer.dropEffect = 'move';
      el.querySelectorAll('.ps-drop-before, .ps-drop-after').forEach(x => x.classList.remove('ps-drop-before', 'ps-drop-after'));
      const r = row.getBoundingClientRect();
      row.classList.add(e.clientY < r.top + r.height / 2 ? 'ps-drop-before' : 'ps-drop-after');
    });
    el.addEventListener('drop', e => {
      const st = stOf();
      const row = e.target.closest && e.target.closest('[data-row]');
      if (!st || !st.drag || !row || row.dataset.key !== st.drag.key) return;
      e.preventDefault();
      const rows = rowList(st, st.drag.key);
      const from = rows.findIndex(x => x.uid === st.drag.uid);
      let to = rows.findIndex(x => x.uid === row.dataset.uid);
      const r = row.getBoundingClientRect();
      if (e.clientY >= r.top + r.height / 2) to++;
      if (from < to) to--;
      const key = st.drag.key;
      st.drag = null;
      if (moveRow(st, key, rows[from].uid, to)) schedulePreview(st);
      redrawOption(st, key);
    });
    el.addEventListener('dragend', () => {
      const st = stOf();
      if (st) st.drag = null;
      el.querySelectorAll('.ps-dragging, .ps-drop-before, .ps-drop-after').forEach(x => x.classList.remove('ps-dragging', 'ps-drop-before', 'ps-drop-after'));
    });
  }

  window.PortcullisSettings = { render };
})();
