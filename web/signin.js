// Portcullis Hub — Settings → Sign-in and the instance page's sign-in
// pick (contract §8.1, sign-in Task 9).
//
//   window.PortcullisSignIn.mount(container)   Settings → Sign-in
//   window.PortcullisSignIn.render(view)       its HTML (GET /api/signin)
//   window.PortcullisSignIn.editorHtml(tpl[, preview])  the template editor
//   window.PortcullisSignIn.ruleFromEditor(root)        the editor's rule JSON
//   window.PortcullisSignIn.blockedHtml(blocked)        "bob (password only) · …"
//   window.PortcullisSignIn.instanceHtml(panel, isv)    the instance Settings tab's block
//   window.PortcullisSignIn.pickBody(value, saved)      its part of the settings body
//   window.PortcullisSignIn.pickChanged(sel)            the drop-down changed: who the new pick blocks
//   window.PortcullisSignIn.editRule(rule, edit)        one editor change on a rule ({rule, refused})
//   window.PortcullisSignIn.impactHtml(impact, key)     who a change blocks, with Apply / Cancel
//   window.PortcullisSignIn.PICK_REFUSAL                the Hub's refusals of a template pick
//
// GET  /api/signin                         methods, templates, default, core picks
// PUT  /api/signin/methods/{m}             {on}
// POST /api/signin/templates               {id, name, rule}
// PUT  /api/signin/templates/{id}          {name, rule}
// PUT  /api/signin/templates/{id}/enabled  {on}
// DELETE /api/signin/templates/{id}
// POST /api/signin/templates/preview       {id?, name, rule}: score, sentence, who it affects
// POST /api/signin/impact                  SignInDraft: who a change would newly block (nothing changes)
// PUT  /api/signin/default                 {template}
// PUT  /api/signin/core/{key}              {template}
// PUT  /api/signin/add-stronger            {on}
// GET  /api/instances/{id}/signin          the instance's choices and who can't meet its template
//
// Rules: every value goes through escapeHtml (index.html); actions are
// data-signin-action attributes handled by delegated listeners on the
// mounted container; a refusal is shown next to the control that caused
// it and the control is put back to what the Hub holds; the editor keeps
// what the admin typed until Save succeeds or Cancel. A default or core
// page pick and a method switch-off ask the Hub who they newly block
// first: anyone (or people unknown) = the list next to the control with
// Apply / Cancel, else the change is applied at once.
(function () {
  'use strict';

  const esc = s => window.escapeHtml(s);
  const PREVIEW_MS = 300;
  const MAX_LEVEL = 3;
  const MAX_ITEMS = 8; // per group (signin.MaxItems)
  // The Hub's refusals of an instance's template pick (hub pickable /
  // pickableLocked / configCapability): shown at the drop-down.
  const PICK_REFUSAL = /^(?:sign-in template\b|no sign-in template |"[^"]*" is disabled: enable it first)/;

  // The editor's names for the methods and families (chips and "+ method").
  const METHODS = [
    ['password', 'Password'],
    ['passkey_synced', 'Synced passkey'],
    ['browser_cert', 'Browser certificate'],
    ['passkey_device', 'Device-bound passkey'],
    ['security_key', 'YubiKey touch'],
    ['yubikey_cert', 'YubiKey certificate']
  ];
  const FAMILIES = [
    ['family:yubikey', 'YubiKey (touch or certificate)'],
    ['family:certificate', 'Certificate (YubiKey or browser)'],
    ['family:passkey', 'Passkey (any kind)']
  ];
  const LEAF_LABEL = Object.fromEntries(METHODS.concat(FAMILIES));
  const CORE_PAGES = [['portal', 'Portal'], ['hub', 'Hub'], ['people', 'People'], ['directory', 'Directory'],
    ['metrics', 'Metrics'], ['traefik', 'Traefik']];

  function leafLabel(leaf) { return LEAF_LABEL[leaf] || leaf; }

  // tenths → "2.5"; a score → "2.5 / 5".
  function num(tenths) { const t = Math.max(0, tenths | 0); return Math.floor(t / 10) + '.' + (t % 10); }
  function scoreText(s) { return num(s ? s.tenths : 0) + ' / 5'; }
  function barHtml(tenths) {
    const t = Math.max(0, Math.min(50, tenths | 0));
    const color = t <= 10 ? '#ef4444' : t < 30 ? '#f59e0b' : '#22c55e';
    return '<span class="si-bar" aria-hidden="true"><i style="width:' + (t * 2) + '%;background:' + color + '"></i></span>';
  }
  function plural(n, one, many) { return n + ' ' + (n === 1 ? one : many); }

  // blockedHtml: "bob (password only) · dave (no method yet)"; with max,
  // at most max names and "and N more".
  const LIST_MAX = 12;
  function blockedHtml(blocked, max) {
    const all = blocked || [];
    const shown = max && all.length > max ? all.slice(0, max) : all;
    return shown.map(b => '<b>' + esc(b.user) + '</b> (' + esc(b.why) + ')').join(' · ') +
      (shown.length < all.length ? ' · and ' + (all.length - shown.length) + ' more' : '');
  }

  function usable(t) { return t.enabled && !t.problem; }
  function templateById(view, id) { return (view.templates || []).find(t => t.id === id); }
  function defaultLabel(view) {
    const d = templateById(view, view.default);
    return 'Default (' + (d ? d.name + ' · ' + scoreText(d.score) : view.default) + ')';
  }

  // ── Settings → Sign-in ─────────────────────────────────────────────

  function switchHtml(action, attrs, checked, disabled, label) {
    return '<label class="si-switch-wrap"><input type="checkbox" class="si-switch" data-signin-action="' + action + '"' + attrs +
      (checked ? ' checked' : '') + (disabled ? ' disabled' : '') + ' aria-label="' + esc(label) + '"><span class="si-switch-ui" aria-hidden="true"></span></label>';
  }
  // errSlot: a control's refusal and, below it, the Apply / Cancel of a
  // change that blocks people.
  function errSlot(key) {
    return '<div class="si-err" data-signin-err="' + esc(key) + '" role="alert"></div><div class="si-confirm" data-signin-confirm="' + esc(key) + '"></div>';
  }

  function methodsHtml(view) {
    const total = view.people_total;
    let h = '<section class="policy-section si-block"><div class="policy-title">Sign-in methods</div>' +
      '<p class="si-sub">What people may set up and use on this server. A method that is off is neither offered nor accepted.</p>' +
      '<table class="si-t"><thead><tr><th>Method</th><th>Strength</th><th>On</th><th>People who have it</th></tr></thead><tbody>';
    for (const m of view.methods || []) {
      let people;
      if (!m.available) people = 'not available yet';
      else if (!m.on) people = '— off: not offered, not accepted';
      else if (m.people < 0 || total < 0) people = 'not known yet';
      else people = m.people + ' of ' + total;
      h += '<tr data-signin-method-row="' + esc(m.id) + '"><td>' + esc(m.label) + '</td>' +
        '<td><span class="si-score">' + esc(num(m.tenths)) + '</span>' + barHtml(m.tenths) + '</td>' +
        '<td>' + switchHtml('method', ' data-method="' + esc(m.id) + '"', m.on && m.available, !m.available, m.label) + '</td>' +
        '<td class="si-sub">' + esc(people) + errSlot('method:' + m.id) + '</td></tr>';
    }
    h += '</tbody></table><p class="si-sub">Switching off a method an enabled template needs, or one the last administrators sign in with, is refused: the Hub says which templates, apps and people first.</p></section>';
    return h;
  }

  function usedByText(t) {
    const u = t.used_by || [];
    return u.length ? u.map(x => x.name).join(', ') : '—';
  }

  function templatesHtml(view) {
    let h = '<section class="policy-section si-block"><div class="policy-title">Templates</div>' +
      '<p class="si-sub">Named rules over the methods. Only enabled ones appear in the drop-downs; one in use can\'t be disabled.</p>' +
      '<table class="si-t"><thead><tr><th>Template</th><th>Rule</th><th>Score</th><th>Used by</th><th>On</th><th></th></tr></thead><tbody>';
    for (const t of view.templates || []) {
      const inUse = t.enabled && (t.used_by || []).length > 0;
      h += '<tr data-signin-template-row="' + esc(t.id) + '"><td><b>' + esc(t.name) + '</b>' +
        (t.built_in ? ' <span class="si-tag">built-in</span>' : '') + (t.id === view.default ? ' <span class="si-tag ok">default</span>' : '') + '</td>' +
        '<td class="si-sub">' + esc(t.sentence) + (t.problem ? '<div class="si-warn-text">' + esc(t.problem) + '</div>' : '') + '</td>' +
        '<td class="si-nowrap"><span class="si-score">' + esc(scoreText(t.score)) + '</span>' + barHtml(t.score ? t.score.tenths : 0) + '</td>' +
        '<td class="si-sub">' + esc(usedByText(t)) + '</td>' +
        '<td class="si-nowrap">' + switchHtml('template-enabled', ' data-id="' + esc(t.id) + '"' + (inUse ? ' title="In use by ' + esc(usedByText(t)) + ': pick another template there first"' : ''),
          t.enabled, inUse, (t.enabled ? 'Disable ' : 'Enable ') + t.name) + (inUse ? ' <span class="si-sub">in use</span>' : '') + errSlot('template:' + t.id) + '</td>' +
        '<td><button type="button" class="btn btn-secondary btn-sm" data-signin-action="edit" data-id="' + esc(t.id) + '">Edit</button></td></tr>';
    }
    h += '</tbody></table>';
    const opts = (view.templates || []).filter(t => usable(t) || t.id === view.default).map(t =>
      '<option value="' + esc(t.id) + '"' + (t.id === view.default ? ' selected' : '') + '>' + esc(t.name + ' · ' + scoreText(t.score)) + '</option>').join('');
    h += '<div class="si-row"><button type="button" class="btn btn-primary btn-sm" data-signin-action="new">+ New template</button>' +
      '<label class="si-sub">Default for everything: <select data-signin-action="default">' + opts + '</select></label></div>' + errSlot('default');
    h += '<div class="si-row">' + switchHtml('add-stronger', '', view.add_stronger, false, 'Adding a stronger method') +
      '<span>Let people add a stronger method than the one they signed in with</span></div>' +
      '<p class="si-sub">Off: someone signed in with a password can only add methods as strong as that; anything stronger needs an administrator\'s setup link.</p>' + errSlot('add-stronger');
    return h + '</section>';
  }

  function coreHtml(view) {
    const core = view.core || {};
    let h = '<section class="policy-section si-block"><div class="policy-title">Core pages</div>' +
      '<p class="si-sub">Portcullis\'s own pages. The Hub and the people page control everything else: keep them on a strong template.</p>' +
      '<table class="si-t"><thead><tr><th>Page</th><th>Sign-in</th></tr></thead><tbody>';
    for (const [key, label] of CORE_PAGES) {
      const pick = core[key] || '';
      let opts = '<option value=""' + (pick === '' ? ' selected' : '') + '>' + esc(defaultLabel(view)) + '</option>';
      for (const t of view.templates || []) {
        if (!usable(t) && t.id !== pick) continue;
        opts += '<option value="' + esc(t.id) + '"' + (t.id === pick ? ' selected' : '') + '>' + esc(t.name + ' · ' + scoreText(t.score)) + '</option>';
      }
      h += '<tr><td>' + esc(label) + '</td><td><select data-signin-action="core" data-key="' + esc(key) + '" aria-label="' + esc(label + ' sign-in') + '">' + opts + '</select>' + errSlot('core:' + key) + '</td></tr>';
    }
    return h + '</tbody></table></section>';
  }

  // render is Settings → Sign-in for view (GET /api/signin); notes are
  // the last change's warnings and restarts.
  function render(view, notes) {
    let h = '<div data-signin-notes>' + (notes || []).map(n => '<div class="public-warn si-note">' + esc(n) + '</div>').join('') + '</div>';
    if (view.mds_warning) h += '<div class="public-warn si-note" data-signin-mds>⚠ ' + esc(view.mds_warning) + '</div>';
    h += methodsHtml(view) + templatesHtml(view);
    h += '<div data-signin-editor></div>';
    h += coreHtml(view);
    return h;
  }

  // ── the template editor ────────────────────────────────────────────

  // marksFor: per editor node (document order), its greyed-out reason
  // and, for a group, its score — from a preview's unusable paths and
  // group scores.
  function pathKey(p) { return (p || []).join('.'); }
  function nodeList(rule) {
    const out = [];
    const walk = (n, path, level) => {
      if (typeof n === 'string') { out.push({ leaf: n, path, level }); return; }
      out.push({ op: n.op, path, level });
      (n.items || []).forEach((it, i) => walk(it, path.concat(i), level + 1));
    };
    walk(rule, [], 1);
    return out;
  }
  function whyUnusable(node) {
    if (node.leaf !== undefined) {
      if (node.leaf.startsWith('family:')) return 'none of its methods is on';
      return node.leaf === 'browser_cert' ? 'not available yet' : 'off on this server';
    }
    return node.op === 'all' ? 'a part of it can\'t be met' : 'none of its parts can be met';
  }
  function marksFor(rule, preview) {
    const nodes = nodeList(rule);
    if (!preview) return nodes.map(() => ({}));
    const bad = new Set((preview.unusable || []).map(pathKey));
    const scores = new Map((preview.groups || []).map(g => [pathKey(g.path), g.tenths]));
    // A part inside a greyed-out one is greyed out with it (no reason of its own).
    const out = [];
    for (const n of nodes) {
      const k = pathKey(n.path);
      const m = {};
      if (bad.has(k)) m.why = whyUnusable(n);
      else if (n.path.some((_, i) => bad.has(pathKey(n.path.slice(0, i))))) m.inside = true;
      if (n.op !== undefined && scores.has(k)) m.tenths = scores.get(k);
      out.push(m);
    }
    return out;
  }

  function addMethodSelect() {
    return '<select data-signin-action="add-method" aria-label="Add a method"><option value="">+ method</option>' +
      '<optgroup label="Methods">' + METHODS.map(([id, l]) => '<option value="' + esc(id) + '">' + esc(l) + '</option>').join('') + '</optgroup>' +
      '<optgroup label="Families">' + FAMILIES.map(([id, l]) => '<option value="' + esc(id) + '">' + esc(l) + '</option>').join('') + '</optgroup></select>';
  }

  function leafHtml(leaf, level, mark, path) {
    const m = mark || {};
    return '<span class="si-chip' + (m.why || m.inside ? ' si-unusable' : '') + '" data-signin-node data-depth="' + level + '" data-path="' + esc(pathKey(path)) + '" data-leaf="' + esc(leaf) + '">' +
      esc(leafLabel(leaf)) + ' <button type="button" class="si-x" data-signin-action="remove" aria-label="' + esc('Remove ' + leafLabel(leaf)) + '">×</button>' +
      '<span class="si-why" data-signin-why>' + (m.why ? ' — ' + esc(m.why) : '') + '</span></span>';
  }

  function groupHtml(node, level, marks, path) {
    const m = marks.shift() || {};
    const op = node.op === 'all' ? 'all' : 'any';
    path = path || [];
    let h = '<div class="si-g si-' + op + (m.why || m.inside ? ' si-unusable' : '') + '" data-signin-node data-depth="' + level + '" data-path="' + esc(pathKey(path)) + '" data-op="' + op + '">' +
      '<div class="si-hd">Require <select data-signin-action="op" aria-label="all of or any of">' +
      '<option value="all"' + (op === 'all' ? ' selected' : '') + '>all of</option><option value="any"' + (op === 'any' ? ' selected' : '') + '>any of</option></select>' +
      '<span class="si-why" data-signin-why>' + (m.why ? ' — ' + esc(m.why) : '') + '</span>' +
      '<span class="si-gs" data-signin-gscore>' + (m.tenths !== undefined ? esc(num(m.tenths)) : '') + '</span>' +
      (level > 1 ? '<button type="button" class="si-x" data-signin-action="remove" aria-label="Remove this group">×</button>' : '') + '</div>' +
      '<div class="si-items" data-signin-items>';
    const items = node.items || [];
    items.forEach((it, i) => {
      if (typeof it === 'string') h += leafHtml(it, level + 1, marks.shift(), path.concat(i));
      else h += groupHtml(it, level + 1, marks, path.concat(i));
    });
    // A full group (MAX_ITEMS) offers no "+ method" / "+ group".
    const full = items.length >= MAX_ITEMS;
    h += '</div><div class="si-add">' + (full ? '<span class="si-sub" data-signin-full>' + MAX_ITEMS + ' items: the most a group holds</span>' : addMethodSelect() +
      (level < MAX_LEVEL ? '<button type="button" class="btn btn-secondary btn-sm" data-signin-action="add-group">+ group</button>' : '')) +
      '<span class="si-err" data-signin-gnote role="alert"></span></div></div>';
    return h;
  }

  // editRule applies one editor change to rule (never changed in place)
  // and answers {rule} or, refused, {rule (unchanged), refused: why}:
  //   {kind: 'add-leaf', path, leaf}  a method or family into the group at path
  //   {kind: 'add-group', path}       an empty "all of" group into it
  //   {kind: 'remove', path}          the part at path (never the top group)
  //   {kind: 'op', path, op}          the group's all / any
  // The Hub's limits: MAX_ITEMS per group, MAX_LEVEL levels, no leaf
  // twice in one group.
  function editRule(rule, e) {
    const top = typeof rule === 'string' ? { op: 'any', items: [rule] } : (rule || { op: 'any', items: [] });
    const r = JSON.parse(JSON.stringify(top));
    const path = e.path || [];
    const at = p => p.reduce((n, i) => (n && typeof n !== 'string' && n.items ? n.items[i] : undefined), r);
    const g = at(path);
    const refused = why => ({ rule: top, refused: why });
    switch (e.kind) {
      case 'add-leaf':
      case 'add-group':
        if (!g || typeof g === 'string') return refused('not a group');
        g.items = g.items || [];
        if (g.items.length >= MAX_ITEMS) return refused('A group holds at most ' + MAX_ITEMS + ' items: put some in a group of their own.');
        if (e.kind === 'add-leaf') {
          if (!LEAF_LABEL[e.leaf]) return refused('unknown method');
          if (g.items.includes(e.leaf)) return refused(leafLabel(e.leaf) + ' is already in this group.');
          g.items.push(e.leaf);
        } else {
          if (path.length + 2 > MAX_LEVEL) return refused('Groups nest up to ' + MAX_LEVEL + ' levels.');
          g.items.push({ op: 'all', items: [] });
        }
        return { rule: r };
      case 'remove': {
        if (!path.length) return refused('the top group stays');
        const parent = at(path.slice(0, -1));
        if (!parent || !parent.items || path[path.length - 1] >= parent.items.length) return refused('no such part');
        parent.items.splice(path[path.length - 1], 1);
        return { rule: r };
      }
      case 'op':
        if (!g || typeof g === 'string' || (e.op !== 'all' && e.op !== 'any')) return refused('not a group');
        g.op = e.op;
        return { rule: r };
    }
    return refused('unknown change');
  }

  function treeHtml(rule, preview) {
    const r = typeof rule === 'string' ? { op: 'any', items: [rule] } : (rule || { op: 'any', items: [] });
    return groupHtml(r, 1, marksFor(r, preview));
  }

  // affectsHtml is "who it affects" for a preview (unused: no app or
  // page uses the template).
  function affectsHtml(p, unused) {
    if (!p) return '<span class="si-sub">…</span>';
    if (p.people_unknown) return '<span class="si-tag warn">Not known: ' + esc(p.people_unknown) + '</span>';
    const list = p.affected || [];
    if (!list.length) return '<span class="si-sub">' + (unused ? 'Nobody yet: no app or page uses it.' : 'Everyone who uses it can meet it.') + '</span>';
    return list.map(a => '<div class="si-affect"><span class="si-tag warn">' + esc(plural((a.blocked || []).length, 'person', 'people') + ' can\'t sign in to ' + a.name + ' with it') + '</span>' +
      '<div class="si-sub">' + blockedHtml(a.blocked) + '</div></div>').join('');
  }

  // impactHtml is who a change newly blocks (POST /api/signin/impact),
  // with Apply / Cancel for the control errKey.
  function impactHtml(imp, errKey) {
    let h = '<div class="public-warn si-impact" data-signin-impact role="alert">';
    if (imp && imp.unknown) h += '<div>Who this change blocks isn\'t known: ' + esc(imp.unknown) + '</div>';
    for (const a of (imp && imp.affected) || []) {
      h += '<div class="si-affect">' + esc(plural((a.blocked || []).length, 'person', 'people') + ' would no longer be able to sign in to ' + a.name) + ': ' + blockedHtml(a.blocked, LIST_MAX) + '</div>';
    }
    return h + '<div class="si-row"><button type="button" class="btn btn-danger btn-sm" data-signin-action="impact-apply" data-key="' + esc(errKey) + '">Apply anyway</button>' +
      '<button type="button" class="btn btn-secondary btn-sm" data-signin-action="impact-cancel" data-key="' + esc(errKey) + '">Cancel</button></div></div>';
  }
  function blocksAnyone(imp) { return !!(imp && (imp.unknown || (imp.affected || []).some(a => (a.blocked || []).length))); }

  // editorHtml is the editor for template t ({id, name, rule, built_in};
  // isNew for "+ New template"), with preview's marks when given.
  function editorHtml(t, preview) {
    const isNew = !!t.isNew;
    const unused = isNew || !(t.used_by || []).length;
    let h = '<div class="si-ed" data-signin-ed data-id="' + esc(t.id || '') + '"' + (isNew ? ' data-new="1"' : '') + (unused ? ' data-unused="1"' : '') + '>' +
      '<div class="policy-title">' + (isNew ? 'New template' : 'Edit template: ' + esc(t.name)) + (t.built_in ? ' <span class="si-tag">built-in</span>' : '') + '</div>' +
      '<div class="si-two"><div>' +
      '<label class="si-field">Name <input type="text" maxlength="48" data-signin-field="name" value="' + esc(t.name || '') + '" autocomplete="off"></label>';
    if (isNew) h += '<label class="si-field">Id <input type="text" maxlength="32" data-signin-field="id" value="' + esc(t.id || '') + '" autocomplete="off" spellcheck="false" placeholder="from the name"></label>' +
      '<p class="si-sub">The id never changes: lowercase letters, digits and -, starting with a letter.</p>';
    h += '<div class="si-tree" data-signin-tree>' + treeHtml(t.rule, preview) + '</div>' +
      '<p class="si-sub">Groups nest up to 3 levels. Greyed-out parts can\'t be met with the methods that are on: they don\'t count.</p></div>';
    const p = preview;
    h += '<div><div class="si-sub">Score</div><div class="si-big" data-signin-score>' + (p ? esc(num(p.score.tenths)) + ' <small>/ 5</small>' : '…') + '</div>' +
      '<div class="si-sub" data-signin-reason>' + (p ? esc(p.score.reason) : '') + '</div>' +
      '<div class="si-sub">all of = strongest part + 0.4 per extra part · any of = weakest part · max 5</div>' +
      '<div class="si-eng"><div class="si-sub">In plain English</div><div data-signin-sentence>' + (p ? esc(p.sentence) : '') + '</div></div>' +
      '<div class="si-warn-text" data-signin-problem role="status">' + (p && p.problem ? esc(p.problem) : '') + '</div>' +
      '<div class="si-sub si-gap">Who it affects</div><div data-signin-affects>' + affectsHtml(p, unused) + '</div>' +
      '<div class="si-row si-gap"><button type="button" class="btn btn-primary btn-sm" data-signin-action="save">Save</button>' +
      '<button type="button" class="btn btn-secondary btn-sm" data-signin-action="cancel">Cancel</button>' +
      (!isNew && !t.built_in ? '<button type="button" class="btn btn-danger btn-sm" data-signin-action="delete">Delete</button>' : '') + '</div>' +
      errSlot('save') + '</div></div></div>';
    return h;
  }

  // ruleFromEditor reads the editor's tree (in root) back into a rule:
  // the nodes in document order, each with its depth; a group's op is
  // its data-op (kept in step with its select).
  function ruleFromEditor(root) {
    const stack = [];
    let top = null;
    for (const el of root.querySelectorAll('[data-signin-node]')) {
      const d = parseInt(el.dataset.depth, 10);
      const node = el.dataset.op !== undefined ? { op: el.dataset.op, items: [] } : el.dataset.leaf;
      if (d === 1) top = node;
      else if (stack[d - 1]) stack[d - 1].items.push(node);
      if (typeof node !== 'string') { stack[d] = node; stack.length = d + 1; }
    }
    return top;
  }

  // applyPreview updates an open editor in place (no focus lost).
  function applyPreview(ed, p) {
    const tree = ed.querySelector('[data-signin-tree]');
    const marks = marksFor(ruleFromEditor(tree), p);
    tree.querySelectorAll('[data-signin-node]').forEach((el, i) => {
      const m = marks[i] || {};
      el.classList.toggle('si-unusable', !!(m.why || m.inside));
      const why = el.querySelector(':scope > [data-signin-why], :scope > .si-hd > [data-signin-why]');
      if (why) why.textContent = m.why ? ' — ' + m.why : '';
      const gs = el.querySelector(':scope > .si-hd > [data-signin-gscore]');
      if (gs) gs.textContent = m.tenths !== undefined ? num(m.tenths) : '';
    });
    ed.querySelector('[data-signin-score]').innerHTML = esc(num(p.score.tenths)) + ' <small>/ 5</small>';
    ed.querySelector('[data-signin-reason]').textContent = p.score.reason || '';
    ed.querySelector('[data-signin-sentence]').textContent = p.sentence || '';
    ed.querySelector('[data-signin-problem]').textContent = p.problem || '';
    ed.querySelector('[data-signin-affects]').innerHTML = affectsHtml(p, ed.dataset.unused === '1');
  }
  function previewFailed(ed, msg) {
    ed.querySelector('[data-signin-score]').textContent = '–';
    ed.querySelector('[data-signin-reason]').textContent = '';
    ed.querySelector('[data-signin-sentence]').textContent = '';
    ed.querySelector('[data-signin-problem]').textContent = msg;
    ed.querySelector('[data-signin-affects]').innerHTML = '';
    ed.querySelectorAll('[data-signin-gscore]').forEach(g => { g.textContent = ''; });
  }

  // The id a new template gets from its name (the admin may type another).
  function idFromName(name) {
    let s = String(name || '').normalize('NFKD').replace(/[\u0300-\u036f]/g, '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^[^a-z]+/, '');
    s = s.slice(0, 32).replace(/-+$/, '');
    return s;
  }

  // ── mounting and actions ───────────────────────────────────────────

  const states = new WeakMap();

  function mount(el) {
    let st = states.get(el);
    if (!st) {
      st = { el, view: null, notes: [], seq: 0, timer: 0, pending: {} };
      states.set(el, st);
      bind(st);
    }
    const ed = st.el.querySelector('[data-signin-ed]');
    if (!st.view) el.innerHTML = '<p class="settings-empty">Loading…</p>';
    return window.apiGet('/api/signin').then(view => {
      st.view = view;
      draw(st, ed);
    }).catch(err => {
      el.innerHTML = '<p class="settings-empty">Failed to load the sign-in settings: ' + esc(err.message) + '</p>';
    });
  }

  // draw renders the tables again; an open editor (ed) is kept as it is.
  function draw(st, ed) {
    // A change waiting for Apply / Cancel is dropped: its control is
    // drawn again as the Hub holds it.
    st.pending = {};
    st.el.innerHTML = render(st.view, st.notes);
    if (ed) st.el.querySelector('[data-signin-editor]').replaceWith(wrapEditor(ed));
  }
  function wrapEditor(ed) {
    const slot = document.createElement('div');
    slot.setAttribute('data-signin-editor', '');
    slot.appendChild(ed);
    return slot;
  }

  function setErr(st, key, msg) {
    const e = st.el.querySelector('[data-signin-err="' + CSS.escape(key) + '"]');
    if (e) e.textContent = msg || '';
  }
  function setConfirm(st, key, html) {
    const e = st.el.querySelector('[data-signin-confirm="' + CSS.escape(key) + '"]');
    if (e) e.innerHTML = html || '';
  }
  function refusal(err) {
    return (err.status === 409 ? 'Refused: ' : err.status === 503 ? 'Not possible right now: ' : '') + (err.message || String(err));
  }

  // applied takes a SignInChange (or nothing: the view is read again);
  // close drops the open editor, only once the view is read (a failed
  // read leaves it open with its message).
  async function applied(st, ch, close) {
    const notes = [];
    if (ch) {
      for (const w of ch.warnings || []) notes.push(w);
      if ((ch.restarts || []).length) notes.push('Restarting to apply the change: ' + ch.restarts.join(', '));
    }
    const view = ch && ch.view ? ch.view : await window.apiGet('/api/signin');
    st.notes = notes;
    st.view = view;
    const ed = close ? null : st.el.querySelector('[data-signin-ed]');
    draw(st, ed);
    // The switches changed what an open draft can meet: preview it again.
    if (ed) runPreview(st, ed);
  }

  // act runs a change of the control t; a refusal is shown at errKey
  // with the tables read again (what the Hub holds now: t back as it was,
  // the uses that refused it), else t is put back.
  async function act(st, t, errKey, call, restore) {
    setErr(st, errKey, '');
    t.disabled = true;
    try {
      const ch = await call();
      await applied(st, ch);
    } catch (err) {
      const msg = refusal(err);
      try {
        st.view = await window.apiGet('/api/signin');
        draw(st, st.el.querySelector('[data-signin-ed]'));
      } catch (e) {
        restore();
        t.disabled = false;
      }
      setErr(st, errKey, msg);
    }
  }

  // guarded runs a change that can block people (a default or core page
  // pick, a method switched off): the Hub says who it newly blocks
  // (draft: a SignInDraft); nobody = act at once, else the list next to
  // the control with Apply / Cancel (pending until then, t disabled). A
  // draft the Hub refuses is shown like the change's own refusal.
  async function guarded(st, t, errKey, draft, call, restore) {
    delete st.pending[errKey];
    setConfirm(st, errKey, '');
    setErr(st, errKey, '');
    t.disabled = true;
    let imp;
    try {
      imp = await window.apiPost('/api/signin/impact', draft);
    } catch (err) {
      restore();
      t.disabled = false;
      setErr(st, errKey, refusal(err));
      return;
    }
    if (!blocksAnyone(imp)) return act(st, t, errKey, call, restore);
    st.pending[errKey] = { t, call, restore };
    setConfirm(st, errKey, impactHtml(imp, errKey));
  }

  // resolvePending is Apply (apply true) or Cancel of errKey's change.
  function resolvePending(st, errKey, apply) {
    const p = st.pending[errKey];
    if (!p) return Promise.resolve();
    delete st.pending[errKey];
    setConfirm(st, errKey, '');
    if (apply) return act(st, p.t, errKey, p.call, p.restore);
    p.restore();
    p.t.disabled = false;
    return Promise.resolve();
  }

  function openEditor(st, t) {
    const slot = st.el.querySelector('[data-signin-editor]');
    slot.innerHTML = editorHtml(t);
    const ed = slot.querySelector('[data-signin-ed]');
    ed.scrollIntoView && ed.scrollIntoView({ behavior: 'smooth', block: 'start' });
    ed.querySelector('[data-signin-field="name"]').focus();
    runPreview(st, ed);
  }

  function editorBody(ed) {
    return { name: ed.querySelector('[data-signin-field="name"]').value.trim(), rule: ruleFromEditor(ed.querySelector('[data-signin-tree]')) };
  }

  function schedulePreview(st, ed) {
    clearTimeout(st.timer);
    st.seq++; // a preview still in flight is for an older draft
    setErr(st, 'save', '');
    st.timer = setTimeout(() => runPreview(st, ed), PREVIEW_MS);
  }

  async function runPreview(st, ed) {
    const isNew = ed.dataset.new === '1';
    const b = editorBody(ed);
    const body = { rule: b.rule };
    if (b.name) body.name = b.name;
    if (!isNew) body.id = ed.dataset.id;
    const seq = ++st.seq;
    try {
      const p = await window.apiPost('/api/signin/templates/preview', body);
      if (seq !== st.seq || !ed.isConnected) return;
      applyPreview(ed, p);
    } catch (err) {
      if (seq !== st.seq || !ed.isConnected) return;
      previewFailed(ed, err.message || String(err));
    }
  }

  async function saveEditor(st, ed, btn) {
    clearTimeout(st.timer);
    setErr(st, 'save', '');
    const isNew = ed.dataset.new === '1';
    const b = editorBody(ed);
    btn.disabled = true;
    try {
      let ch;
      if (isNew) {
        const idEl = ed.querySelector('[data-signin-field="id"]');
        const id = idEl.value.trim() || idFromName(b.name);
        ch = await window.apiPost('/api/signin/templates', { id, name: b.name, rule: b.rule });
        // Saved: a second Save updates it.
        ed.dataset.new = '';
        ed.dataset.id = id;
      } else {
        ch = await window.apiPut('/api/signin/templates/' + encodeURIComponent(ed.dataset.id), { name: b.name, rule: b.rule });
      }
    } catch (err) {
      btn.disabled = false;
      setErr(st, 'save', refusal(err));
      return;
    }
    window.showToast && window.showToast('Template saved', 'success');
    await closeAfter(st, ed, btn, ch, 'Saved');
  }

  // closeAfter draws the change and closes the editor; a failed re-read
  // keeps it open saying what happened.
  async function closeAfter(st, ed, btn, ch, done) {
    try {
      await applied(st, ch, true);
    } catch (err) {
      btn.disabled = false;
      setErr(st, 'save', done + ', but the sign-in settings couldn\'t be read again: ' + (err.message || String(err)) + '. Reload the page.');
    }
  }

  async function deleteTemplate(st, ed, btn) {
    const t = templateById(st.view, ed.dataset.id);
    if (!confirm('Delete the template ' + (t ? t.name : ed.dataset.id) + '? This cannot be undone.')) return;
    setErr(st, 'save', '');
    btn.disabled = true;
    try {
      await window.apiCall('/api/signin/templates/' + encodeURIComponent(ed.dataset.id), 'DELETE');
    } catch (err) {
      btn.disabled = false;
      setErr(st, 'save', refusal(err));
      return;
    }
    await closeAfter(st, ed, btn, null, 'Deleted');
  }

  // editTree applies edit to the open editor's tree (editRule), drawn
  // again from the rule; a refusal is shown at the group's add controls.
  // focus picks the control focused afterwards in the new tree.
  function editTree(st, ed, groupEl, edit, focus) {
    const tree = ed.querySelector('[data-signin-tree]');
    const res = editRule(ruleFromEditor(tree), edit);
    if (res.refused) {
      const note = groupEl && groupEl.querySelector(':scope > .si-add > [data-signin-gnote]');
      if (note) note.textContent = res.refused;
      return;
    }
    tree.innerHTML = treeHtml(res.rule);
    if (focus) {
      const el = tree.querySelector(focus);
      if (el) el.focus();
    }
    schedulePreview(st, ed);
  }
  function pathOf(el) {
    const k = el.dataset.path || '';
    return k === '' ? [] : k.split('.').map(Number);
  }
  function nodeSel(path) { return '[data-signin-node][data-path="' + pathKey(path) + '"]'; }

  function bind(st) {
    const el = st.el;
    el.addEventListener('click', e => {
      const t = e.target.closest('[data-signin-action]');
      if (!t || !el.contains(t) || t.tagName === 'SELECT' || t.tagName === 'INPUT') return;
      const a = t.dataset.signinAction;
      const ed = t.closest('[data-signin-ed]');
      if (a === 'impact-apply' || a === 'impact-cancel') { resolvePending(st, t.dataset.key, a === 'impact-apply'); return; }
      if (a === 'new') { openEditor(st, { isNew: true, name: '', id: '', rule: { op: 'any', items: ['family:passkey'] } }); return; }
      if (a === 'edit') {
        const tpl = templateById(st.view, t.dataset.id);
        if (tpl) openEditor(st, tpl);
        return;
      }
      if (!ed) return;
      if (a === 'cancel') { clearTimeout(st.timer); st.seq++; ed.remove(); return; }
      if (a === 'save') { saveEditor(st, ed, t); return; }
      if (a === 'delete') { deleteTemplate(st, ed, t); return; }
      if (a === 'remove') {
        const n = t.closest('[data-signin-node]'), path = pathOf(n);
        editTree(st, ed, null, { kind: 'remove', path }, nodeSel(path.slice(0, -1)) + ' > .si-add > [data-signin-action="add-method"]');
        return;
      }
      if (a === 'add-group') {
        const g = t.closest('[data-signin-node]'), path = pathOf(g);
        editTree(st, ed, g, { kind: 'add-group', path }, nodeSel(path) + ' > [data-signin-items] > [data-signin-node]:last-child [data-signin-action="add-method"]');
      }
    });
    el.addEventListener('change', e => {
      const t = e.target;
      if (!t.matches || !t.matches('[data-signin-action]')) return;
      const a = t.dataset.signinAction;
      const v = st.view;
      if (a === 'method') {
        const m = t.dataset.method, want = t.checked;
        const call = () => window.apiPut('/api/signin/methods/' + encodeURIComponent(m), { on: want }), restore = () => { t.checked = !want; };
        if (want) act(st, t, 'method:' + m, call, restore);
        else guarded(st, t, 'method:' + m, { method: m, on: false }, call, restore);
      } else if (a === 'template-enabled') {
        const id = t.dataset.id, want = t.checked;
        act(st, t, 'template:' + id, () => window.apiPut('/api/signin/templates/' + encodeURIComponent(id) + '/enabled', { on: want }), () => { t.checked = !want; });
      } else if (a === 'default') {
        const was = v.default, want = t.value;
        guarded(st, t, 'default', { default: want }, () => window.apiPut('/api/signin/default', { template: want }), () => { t.value = was; });
      } else if (a === 'core') {
        const key = t.dataset.key, was = (v.core || {})[key] || '', want = t.value;
        guarded(st, t, 'core:' + key, { core_page: key, core: want }, () => window.apiPut('/api/signin/core/' + encodeURIComponent(key), { template: want }), () => { t.value = was; });
      } else if (a === 'add-stronger') {
        const want = t.checked;
        act(st, t, 'add-stronger', async () => { await window.apiCall('/api/signin/add-stronger', 'PUT', { on: want }); return null; }, () => { t.checked = !want; });
      } else if (a === 'op') {
        const g = t.closest('[data-signin-node]'), path = pathOf(g);
        editTree(st, t.closest('[data-signin-ed]'), g, { kind: 'op', path, op: t.value }, nodeSel(path) + ' > .si-hd > [data-signin-action="op"]');
      } else if (a === 'add-method') {
        const leaf = t.value;
        if (!leaf) return;
        t.value = '';
        const g = t.closest('[data-signin-node]'), path = pathOf(g);
        editTree(st, t.closest('[data-signin-ed]'), g, { kind: 'add-leaf', path, leaf }, nodeSel(path) + ' > .si-add > [data-signin-action="add-method"]');
      }
    });
    el.addEventListener('input', e => {
      const t = e.target;
      if (!t.matches || !t.matches('[data-signin-field]')) return;
      const ed = t.closest('[data-signin-ed]');
      if (t.dataset.signinField === 'id') t.dataset.typed = '1';
      if (t.dataset.signinField === 'name' && ed.dataset.new === '1') {
        const idEl = ed.querySelector('[data-signin-field="id"]');
        if (idEl && !idEl.dataset.typed) idEl.value = idFromName(t.value);
      }
      schedulePreview(st, ed);
    });
  }

  // ── the instance page (Settings tab) ───────────────────────────────

  function choiceLabel(c) { return c.name + ' · ' + scoreText(c.score); }

  // instanceHtml is the instance Settings tab's sign-in block: panel is
  // the settings panel (AppSettingsView fields), isv GET
  // /api/instances/{id}/signin (or {error}).
  function instanceHtml(panel, isv) {
    let h = '<div class="policy-section si-pick" data-signin-pick-section><div class="policy-title">Sign-in</div>';
    if (panel.method === 'mtls') {
      return h + '<div class="policy-own">Client certificate required</div>' +
        '<small>This app checks a YubiKey certificate at the TLS handshake, on every request: it takes no sign-in template.</small></div>';
    }
    if (!isv || isv.error) {
      return h + '<div class="public-warn">The sign-in choices couldn\'t be loaded' + (isv && isv.error ? ': ' + esc(isv.error) : '') + '.</div></div>';
    }
    if (!isv.takes_template) {
      return h + '<div class="policy-own">No Portcullis sign-in template</div>' +
        '<small>This app handles its own sign-in (or has none): no template applies.</small></div>';
    }
    const choices = isv.choices || [];
    const pick = panel.sign_in_template || '';
    const def = choices.find(c => c.id === isv.default);
    let opts = '<option value=""' + (pick === '' ? ' selected' : '') + ' data-sentence="' + esc(def ? def.sentence : '') + '">' +
      esc('Default (' + (def ? choiceLabel(def) : isv.default) + ')') + '</option>';
    for (const c of choices) {
      opts += '<option value="' + esc(c.id) + '"' + (c.id === pick ? ' selected' : '') + ' data-sentence="' + esc(c.sentence) + '">' + esc(choiceLabel(c)) + '</option>';
    }
    if (pick && !choices.some(c => c.id === pick)) opts += '<option value="' + esc(pick) + '" selected data-sentence="">' + esc(pick + ' (not available: disabled or gone)') + '</option>';
    const shown = pick === '' ? def : choices.find(c => c.id === pick);
    h += '<select data-signin-pick data-saved="' + esc(pick) + '" data-instance="' + esc(isv.instance || '') + '" data-name="' + esc(isv.name || '') + '" aria-label="Sign-in template">' + opts + '</select>';
    h += '<small data-signin-pick-sentence>' + esc(shown ? shown.sentence : '') + '</small>';
    h += '<div class="ps-err" data-signin-pick-err role="alert"></div>';
    // The saved choice's list; while another is picked, who that one
    // newly blocks (POST /api/signin/impact) instead.
    h += '<div data-signin-pick-saved>' + blockedNote(isv) + '</div>';
    h += '<div data-signin-pick-impact role="status" hidden></div>';
    return h + '</div>';
  }

  // blockedNote: who can't meet the saved pick (isv), or — draft — who
  // the picked one newly blocks.
  function blockedNote(isv, draft) {
    if (isv.people_unknown) return '<div class="public-warn">Who ' + (draft ? 'this choice blocks' : 'can\'t meet it') + ' isn\'t known: ' + esc(isv.people_unknown) + '</div>';
    const b = isv.blocked || [];
    if (draft) {
      if (!b.length) return '<small data-signin-blocked-none>Nobody who can use ' + esc(isv.name) + ' is newly blocked by this choice.</small>';
      return '<div class="public-warn" data-signin-blocked>' + esc(plural(b.length, 'person', 'people') + ' who can use ' + isv.name + ' would no longer be able to sign in to it') + ': ' + blockedHtml(b, LIST_MAX) +
        ' <span class="si-sub">— if you save this choice</span></div>';
    }
    if (!b.length) return '<small>Everyone who can use ' + esc(isv.name) + ' can meet it.</small>';
    return '<div class="public-warn" data-signin-blocked>' + esc(plural(b.length, 'person', 'people') + ' who can use ' + isv.name + ' can\'t meet it') + ': ' + blockedHtml(b) +
      ' <span class="si-sub">— they\'ll see what\'s missing when they open ' + esc(isv.name) + '</span></div>';
  }

  // pickChanged updates the block after the drop-down changed: the
  // sentence at once, who the new pick newly blocks after PREVIEW_MS
  // (the latest change wins). Answers a promise settled once drawn.
  const pickStates = new WeakMap();
  function pickChanged(sel) {
    const box = sel.closest('[data-signin-pick-section]');
    const o = sel.selectedOptions[0];
    box.querySelector('[data-signin-pick-sentence]').textContent = o ? o.dataset.sentence || '' : '';
    box.querySelector('[data-signin-pick-err]').textContent = '';
    const saved = box.querySelector('[data-signin-pick-saved]'), out = box.querySelector('[data-signin-pick-impact]');
    let ps = pickStates.get(box);
    if (!ps) { ps = { seq: 0, timer: 0, settle: null }; pickStates.set(box, ps); }
    // A change still waiting is superseded: its promise settles now.
    clearTimeout(ps.timer);
    if (ps.settle) { ps.settle(); ps.settle = null; }
    const seq = ++ps.seq;
    const changed = sel.value !== sel.dataset.saved;
    saved.hidden = changed;
    out.hidden = !changed;
    if (!changed) { out.innerHTML = ''; return Promise.resolve(); }
    out.innerHTML = '<small class="si-sub">Checking who this choice blocks…</small>';
    const inst = sel.dataset.instance, name = sel.dataset.name, pick = sel.value;
    return new Promise(resolve => {
      ps.settle = resolve;
      ps.timer = setTimeout(async () => {
        ps.settle = null;
        let html;
        try {
          const imp = await window.apiPost('/api/signin/impact', { instance: inst, pick });
          const mine = ((imp && imp.affected) || []).find(a => a.kind === 'instance' && a.instance === inst);
          html = blockedNote({ name, people_unknown: imp && imp.unknown, blocked: mine ? mine.blocked : [] }, true);
        } catch (err) {
          html = '<div class="public-warn">' + esc((err.status === 409 ? 'Refused: ' : 'Who this choice blocks couldn\'t be worked out: ') + (err.message || String(err))) + '</div>';
        }
        if (seq === ps.seq) out.innerHTML = html;
        resolve();
      }, PREVIEW_MS);
    });
  }

  // pickBody is the settings body's sign-in part: {} unchanged, else
  // {sign_in_template: value} ("" = the default).
  function pickBody(value, saved) {
    if (value === undefined || value === null || value === (saved || '')) return {};
    return { sign_in_template: value };
  }

  window.PortcullisSignIn = {
    mount, render, editorHtml, ruleFromEditor, blockedHtml, instanceHtml, pickChanged, pickBody, marksFor, editRule, impactHtml, PICK_REFUSAL,
    // For the node tests: the confirm step over a stub container.
    _test: { guarded, resolvePending, state: (el, view) => ({ el, view, notes: [], seq: 0, timer: 0, pending: {} }) }
  };
})();
