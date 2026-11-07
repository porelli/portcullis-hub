// Portcullis Hub: "Connect your AI" (people.<domain> only; plan 4 Task 21).
//
// The card at the top of My apps, drawn from GET /api/me/apps (the
// top-level ai: the "all my apps" URL, the AI clients the administrator
// offers, the admin URL for administrators; each app's ai.companions)
// and GET /api/me/ai (the person's own AI connections and their last AI
// requests). It shows how to add the URLs to Claude desktop / claude.ai,
// Claude Code or another MCP client (tabs, copy buttons), lists the
// connections with Disconnect (DELETE /api/me/ai/connections/{client})
// and the recent activity. No card when there is neither an AI app nor
// the aggregate. The text follows the spec's "Example: the People page
// card". myapps.js calls PortcullisMyAI.render(box, view) after each load.
//
// Rules of this file (as directory.js and myapps.js):
//   - every server string goes through esc() before it reaches innerHTML;
//   - no inline event handlers: data-* attributes and one delegated
//     listener on the card's box.
(function () {
  'use strict';

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  // Only https URLs are shown as URLs (the Hub builds every one of them).
  function httpsURL(u) { return /^https:\/\/[^\s"'<>]+$/i.test(u || '') ? u : ''; }

  // domainOf is the main domain behind the aggregate URL
  // (https://mcp.<domain>/mcp → <domain>).
  function domainOf(agg) {
    try {
      const h = new URL(agg).hostname;
      return h.indexOf('mcp.') === 0 ? h.slice(4) : h;
    } catch (_) { return ''; }
  }

  // serverName is a Claude Code server name: the label lowercased,
  // reduced to [a-z0-9-] (other characters become '-').
  function serverName(label) {
    const s = String(label || '').toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/-+/g, '-').replace(/^-+|-+$/g, '');
    return s || 'portcullis-app';
  }

  // serverNames gives every companion row of apps a Claude Code server
  // name unique in the card (and never the aggregate's portcullis-apps):
  // serverName(label), with -<instance id> appended when two rows (or the
  // aggregate) would share it, and -<companion> after that if still
  // needed. Keyed by instance id + NUL + companion name.
  function serverNames(apps) {
    const rows = [];
    for (const a of apps) for (const c of a.ai.companions) rows.push({ key: a.id + '\u0000' + c.name, base: serverName(c.label), id: a.id, comp: c.name });
    const count = new Map([['portcullis-apps', 1]]);
    for (const r of rows) count.set(r.base, (count.get(r.base) || 0) + 1);
    const out = new Map(), used = new Set(['portcullis-apps']);
    for (const r of rows) {
      let n = r.base;
      if (count.get(n) > 1) n = serverName(n + '-' + r.id);
      if (used.has(n)) n = serverName(n + '-' + r.comp);
      used.add(n);
      out.set(r.key, n);
    }
    return out;
  }

  function joinNames(names) {
    if (names.length <= 1) return names.join('');
    return names.slice(0, -1).join(', ') + ' and ' + names[names.length - 1];
  }

  const MODES = { read_write: 'read and write', read_only: 'read only' };

  function copyBtn(value, what) {
    return '<button type="button" class="pd-btn secondary xs" data-mai-copy="' + esc(value) + '" aria-label="' + esc('Copy ' + (what || value)) + '">Copy</button>';
  }

  // ── the steps per client (tabs) ───────────────────────────

  // tabSeq numbers tab sets, so every tab and panel has a unique id.
  let tabSeq = 0;

  // steps is the three-tab block for one resource r: {url, name (Claude
  // Code server name), title (the connector's name in Claude), scope}.
  function steps(top, r, domain) {
    const c = top.clients || {};
    const tabs = [];
    if (c.claude) {
      tabs.push({ id: 'claude', label: 'Claude desktop / claude.ai', html:
        '<ol class="mai-steps">' +
        '<li>Open Claude → Customize → Connectors → Add custom connector.<br>' +
        '<span class="pd-muted">(Team or Enterprise plan: ask an Owner to add it in Organization settings → Connectors → Add → Custom → Web, then click Connect.)</span></li>' +
        '<li>Name: <strong>' + esc(r.title) + '</strong> · URL: <code>' + esc(r.url) + '</code> ' + copyBtn(r.url) + '</li>' +
        '<li>Open Advanced settings (or choose "Use your own OAuth client"):<br>OAuth Client ID: <code>' + esc(c.claude.client_id) + '</code> ' + copyBtn(c.claude.client_id) +
        '<br>Leave the client secret empty.</li>' +
        '<li>Click Add, then Connect. Sign in with your passkey and allow access.</li></ol>' +
        '<p class="pd-muted mai-note">Claude connects from Anthropic\'s servers, so this works only while ' + esc(domain) + ' is reachable from the internet.</p>' });
    }
    if (c.claude_code) {
      const cmd = 'claude mcp add --transport http --scope user --client-id ' + c.claude_code.client_id +
        ' --callback-port ' + c.claude_code.callback_port + ' ' + r.name + ' ' + r.url;
      tabs.push({ id: 'claude_code', label: 'Claude Code', html:
        '<p>Paste in a terminal:</p><div class="mai-cmd"><code>' + esc(cmd) + '</code> ' + copyBtn(cmd, 'the command') + '</div>' +
        '<p>Then start Claude Code, type <code>/mcp</code>, choose <code>' + esc(r.name) + '</code> and sign in with your passkey in the browser that opens.</p>' });
    }
    if (c.generic) {
      const redirect = (c.generic.redirect_uris || [])[0] || '';
      tabs.push({ id: 'generic', label: 'Other MCP clients', html:
        '<p>Server URL: <code>' + esc(r.url) + '</code> ' + copyBtn(r.url) + ' · Transport: Streamable HTTP</p>' +
        '<p>OAuth: authorization server discovered automatically (Keycloak at ' + esc('auth.' + domain) + ') · Client ID: <code>' + esc(c.generic.client_id) + '</code> ' + copyBtn(c.generic.client_id) +
        ' · no secret · PKCE S256 · redirect <code>' + esc(redirect) + '</code> · scope <code>' + esc(r.scope) + '</code></p>' });
    }
    if (!tabs.length) return '<p class="pd-muted">No AI client is offered right now; ask an administrator.</p>';
    const set = 'mai-' + (++tabSeq);
    let h = '<div class="mai-tabset" data-mai-tabs><div class="pd-tabs mai-tabs" role="tablist" aria-label="AI clients">';
    tabs.forEach((t, i) => {
      h += '<button type="button" class="pd-tab' + (i === 0 ? ' active' : '') + '" role="tab" id="' + set + '-tab-' + esc(t.id) +
        '" aria-controls="' + set + '-panel-' + esc(t.id) + '" aria-selected="' + (i === 0) + '" tabindex="' + (i === 0 ? '0' : '-1') +
        '" data-mai-tab="' + esc(t.id) + '">' + esc(t.label) + '</button>';
    });
    h += '</div>';
    tabs.forEach((t, i) => {
      h += '<div class="mai-panel" role="tabpanel" id="' + set + '-panel-' + esc(t.id) + '" aria-labelledby="' + set + '-tab-' + esc(t.id) +
        '" tabindex="0" data-mai-panel="' + esc(t.id) + '"' + (i === 0 ? '' : ' hidden') + '>' + t.html + '</div>';
    });
    return h + '</div>';
  }

  // oauthSteps: an app_oauth companion (the app signs people in itself;
  // Portcullis' AI clients aren't used).
  function oauthSteps(label, url, name) {
    const cmd = 'claude mcp add --transport http --scope user ' + name + ' ' + url;
    return '<div class="mai-oauth-steps">' +
      '<p>Claude Code: <code>' + esc(cmd) + '</code> ' + copyBtn(cmd, 'the command') + '</p>' +
      '<p>Other MCP clients: server URL <code>' + esc(url) + '</code> ' + copyBtn(url) + ' · ' + esc(label) + ' handles the sign-in.</p></div>';
  }

  // ── connections and activity (GET /api/me/ai) ─────────────

  function fmtDay(s) {
    const d = new Date(s);
    if (!s || isNaN(d)) return '';
    return d.toLocaleDateString(undefined, { day: 'numeric', month: 'short' });
  }

  function ago(s) {
    const d = new Date(s);
    if (!s || isNaN(d)) return '';
    const m = Math.round((Date.now() - d.getTime()) / 60000);
    if (m < 1) return 'just now';
    if (m < 60) return m + ' min ago';
    const h = Math.round(m / 60);
    if (h < 24) return h + ' h ago';
    return fmtDay(s);
  }

  function connHtml(c) {
    const parts = [];
    if (c.consented_at) parts.push('connected ' + fmtDay(c.consented_at));
    if (c.last_used_at) parts.push('last used ' + ago(c.last_used_at));
    if (c.expires_at) parts.push('until ' + fmtDay(c.expires_at));
    return '<li class="mai-conn" data-mai-conn data-mai-client="' + esc(c.client) + '" data-mai-label="' + esc(c.label || c.client) + '">' +
      '<span class="mai-conn-name">' + esc(c.label || c.client) + '</span> <span class="pd-muted">' + esc(parts.join(' · ')) + '</span> ' +
      '<button type="button" class="pd-btn danger xs" data-mai-act="disconnect">Disconnect</button>' +
      '<div data-mai-conn-panel></div><div class="ma-status pd-muted" data-mai-conn-status role="status"></div></li>';
  }

  // lineName is an access-log line's tool as the aggregate names it
  // (<instance>__<tool>), the method for non-tool requests.
  function lineName(l) {
    if (!l.tool) return l.method || '';
    return l.instance ? l.instance + '__' + l.tool : l.tool;
  }

  function lineMark(l) {
    const d = String(l.decision || '');
    if (d === 'allow') return { text: '✓', cls: 'ok', title: 'allowed' };
    if (d.indexOf('confirm:') === 0) return { text: '⏸ waiting for your confirmation', cls: 'warn', title: 'waiting for your confirmation' };
    if (d === 'rate_limited') return { text: '✗ rate limited', cls: 'bad', title: 'too many requests' };
    if (d.indexOf('deny:') === 0) return { text: '✗ ' + d.slice(5), cls: 'bad', title: 'refused: ' + d.slice(5) };
    return { text: d, cls: '', title: d };
  }

  function lineHtml(l) {
    const m = lineMark(l);
    const when = new Date(l.time);
    return '<li title="' + esc((isNaN(when) ? '' : when.toLocaleString()) + ' · ' + m.title + (l.client ? ' · ' + l.client : '')) + '">' +
      '<code>' + esc(lineName(l)) + '</code> <span class="mai-mark ' + esc(m.cls) + '">' + esc(m.text) + '</span></li>';
  }

  const RECENT = 3;

  function mineHtml(v) {
    const conns = v.connections || [];
    const act = v.activity || [];
    let h = '<div class="mai-sec-title">Your AI connections</div>';
    h += conns.length ? '<ul class="mai-conns">' + conns.map(connHtml).join('') + '</ul>'
      : '<p class="pd-muted">No AI connections yet.</p>';
    h += '<p class="pd-muted mai-note">Disconnect ends all your Claude connectors at once. ' +
      'It stops new sign-ins and token refreshes for that client at once; requests already signed in can keep working for up to 5 minutes.</p>';
    h += '<div class="mai-activity"><span class="mai-act-title">Recent AI activity</span>';
    if (!act.length) return h + ' <span class="pd-muted">none yet</span></div>';
    h += '<ul class="mai-lines">' + act.slice(0, RECENT).map(lineHtml).join('') + '</ul>';
    if (act.length > RECENT) {
      h += '<details class="mai-all"><summary>All ▾</summary><ul class="mai-lines">' + act.slice(RECENT).map(lineHtml).join('') + '</ul></details>';
    }
    return h + '</div>';
  }

  async function loadMine(box) {
    const mine = box.querySelector('[data-mai-mine]');
    if (!mine) return;
    const seq = (box.maiMineSeq = (box.maiMineSeq || 0) + 1);
    let res, text;
    try {
      res = await fetch('/api/me/ai', { credentials: 'same-origin', cache: 'no-store' });
      text = await res.text();
    } catch (_) { res = null; }
    if (seq !== box.maiMineSeq || !box.contains(mine)) return;
    let v = null;
    if (res && res.ok) { try { v = JSON.parse(text); } catch (_) { v = null; } }
    mine.innerHTML = v ? mineHtml(v)
      : '<div class="mai-sec-title">Your AI connections</div><p class="pd-warn">Your AI connections can\'t be read right now. Try again later.</p>';
  }

  // ── the card ──────────────────────────────────────────────

  function cardHtml(view) {
    const top = view.ai;
    const apps = (view.apps || []).filter(a => a.ai && (a.ai.companions || []).length);
    const agg = top ? httpsURL(top.aggregate_url) : '';
    const domain = domainOf(agg);
    let h = '<section class="pd-card mai-card" aria-labelledby="mai-title">' +
      '<div class="mai-head"><h3 class="ma-name" id="mai-title">Connect your AI</h3>' +
      '<details class="mai-what"><summary>ⓘ What\'s this?</summary><p class="pd-muted">An AI assistant such as Claude can use your apps through Portcullis. It signs in as you, with your passkey, so it gets exactly your access; you can disconnect it here at any time.</p></details></div>' +
      '<p class="mai-intro">Use your apps from Claude or another AI assistant, as yourself. The AI can see and change only what you can. ' +
      'What it reads is sent to the AI provider you use. Deleting things always asks for your passkey in this browser.</p>';

    const names = serverNames(apps);
    if (agg) {
      // Only companions in "all my apps" (aggregate: true) are covered;
      // the others (app_oauth, aggregate: false) are connected separately.
      const covered = [], separate = [];
      for (const a of apps) {
        for (const c of a.ai.companions) {
          if (c.aggregate === true) { if (covered.indexOf(a.name || a.id) < 0) covered.push(a.name || a.id); }
          else if (separate.indexOf(c.label) < 0) separate.push(c.label);
        }
      }
      h += '<div class="mai-sec"><div class="mai-sec-title">All my apps</div>' +
        '<div class="mai-url"><code>' + esc(agg) + '</code> ' + copyBtn(agg) + '</div><p class="pd-muted">' +
        (covered.length ? 'Covers ' + esc(joinNames(covered)) + ' (and anything added later).' : 'Covers your Portcullis account (and any app added later).') +
        (separate.length ? ' ' + esc(joinNames(separate)) + (separate.length > 1 ? ' are' : ' is') + ' connected separately (below).' : '') + '</p>' +
        steps(top, { url: agg, name: 'portcullis-apps', title: 'Portcullis apps', scope: 'mcp:all' }, domain) + '</div>';
    }

    if (apps.length) {
      h += '<div class="mai-sec"><div class="mai-sec-title">One app only</div><ul class="mai-apps">';
      for (const a of apps) {
        for (const c of a.ai.companions) {
          const url = httpsURL(c.url);
          if (!url) continue;
          const oauth = c.identity_mode === 'app_oauth';
          h += '<li class="mai-app"><div class="mai-app-row"><span class="mai-app-name">' + esc(c.label) + '</span>' +
            '<code class="mai-app-url">' + esc(url) + '</code>' +
            '<span class="pd-muted">' + esc(oauth ? 'signs in with ' + c.label : (MODES[c.mode] || c.mode)) + '</span>' +
            (c.official ? '' : ' <span class="pd-pill" title="not the app\'s official MCP server">community</span>') +
            copyBtn(url) + '</div>';
          if (oauth) {
            h += '<p class="pd-muted mai-note">Claude: add it as a custom connector with "Use Claude\'s published identity"; ' + esc(c.label) + ' asks you to sign in (passkey). ' +
              esc(c.label) + ' applies its own rules; Portcullis doesn\'t log or confirm its AI actions.</p>';
          }
          h += '<details class="mai-steps-box"><summary>Steps ▾</summary>' +
            (oauth ? oauthSteps(c.label, url, names.get(a.id + '\u0000' + c.name))
              : steps(top || {}, { url: url, name: names.get(a.id + '\u0000' + c.name), title: c.label, scope: 'mcp:' + a.id + '.' + c.name }, domain)) +
            '</details></li>';
        }
      }
      h += '</ul></div>';
    }

    if (top && httpsURL(top.admin_url)) {
      h += '<div class="mai-sec"><div class="mai-sec-title">Portcullis (administrators)</div>' +
        '<div class="mai-url"><code>' + esc(top.admin_url) + '</code> ' + copyBtn(top.admin_url) + '</div>' +
        '<p class="pd-muted">Manage Portcullis from Claude Code or another client your administrator enabled it for.</p></div>';
    }

    h += '<div class="mai-sec" data-mai-mine><div class="mai-sec-title">Your AI connections</div><p class="pd-muted">Loading…</p></div>';
    return h + '</section>';
  }

  function hasCard(view) {
    if (!view) return false;
    if (view.ai) return true;
    return (view.apps || []).some(a => a.ai && (a.ai.companions || []).length);
  }

  // ── actions ───────────────────────────────────────────────

  function connStatus(li, text, warn) {
    const s = li.querySelector('[data-mai-conn-status]');
    s.textContent = text;
    s.classList.toggle('pd-warn', !!warn);
    s.classList.toggle('pd-muted', !warn);
  }

  async function disconnect(box, li) {
    li.querySelector('[data-mai-conn-panel]').innerHTML = '';
    li.querySelectorAll('button').forEach(b => { b.disabled = true; });
    connStatus(li, 'Disconnecting…', false);
    let res, text;
    try {
      res = await fetch('/api/me/ai/connections/' + encodeURIComponent(li.dataset.maiClient), {
        method: 'DELETE', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }
      });
      text = await res.text();
    } catch (err) { res = null; text = err.message; }
    if (!res || !res.ok) {
      li.querySelectorAll('button').forEach(b => { b.disabled = false; });
      connStatus(li, (text || '').trim() || ('HTTP ' + (res ? res.status : '')), true);
      return;
    }
    await loadMine(box);
  }

  function copy(btn) {
    const v = btn.dataset.maiCopy;
    const done = t => {
      const old = btn.textContent;
      btn.textContent = t;
      setTimeout(() => { btn.textContent = old; }, 1500);
    };
    if (!navigator.clipboard) { done('Select and copy'); return; }
    navigator.clipboard.writeText(v).then(() => done('Copied'), () => done('Copy failed'));
  }

  // selectTab makes tab b the selected one of its set (and focuses it).
  function selectTab(b, focus) {
    const set = b.closest('[data-mai-tabs]');
    set.querySelectorAll('[data-mai-tab]').forEach(t => {
      const on = t === b;
      t.classList.toggle('active', on);
      t.setAttribute('aria-selected', String(on));
      t.tabIndex = on ? 0 : -1;
    });
    set.querySelectorAll('[data-mai-panel]').forEach(p => { p.hidden = p.dataset.maiPanel !== b.dataset.maiTab; });
    if (focus) b.focus();
  }

  function bind(box) {
    if (box.dataset.maiBound) return;
    box.dataset.maiBound = '1';
    // Arrow keys move between the tabs of one set (Home / End: first /
    // last), as the WAI-ARIA tabs pattern does.
    box.addEventListener('keydown', e => {
      const b = e.target.closest && e.target.closest('[data-mai-tab]');
      if (!b || !box.contains(b)) return;
      const tabs = Array.from(b.parentElement.querySelectorAll('[data-mai-tab]'));
      const i = tabs.indexOf(b);
      let j = -1;
      switch (e.key) {
        case 'ArrowRight': j = (i + 1) % tabs.length; break;
        case 'ArrowLeft': j = (i - 1 + tabs.length) % tabs.length; break;
        case 'Home': j = 0; break;
        case 'End': j = tabs.length - 1; break;
        default: return;
      }
      e.preventDefault();
      selectTab(tabs[j], true);
    });
    box.addEventListener('click', e => {
      const b = e.target.closest('button');
      if (!b || !box.contains(b) || b.disabled) return;
      if (b.dataset.maiCopy !== undefined) { copy(b); return; }
      if (b.dataset.maiTab) { selectTab(b, false); return; }
      const li = b.closest('[data-mai-conn]');
      if (!li) return;
      const panel = li.querySelector('[data-mai-conn-panel]');
      switch (b.dataset.maiAct) {
        case 'disconnect':
          panel.innerHTML = '<div class="pd-warn ma-confirm"><p>Disconnect ' + esc(li.dataset.maiLabel) + '? It must ask for your passkey and your consent again to reconnect.</p>' +
            '<button type="button" class="pd-btn danger sm" data-mai-act="disconnect-go">Disconnect</button> ' +
            '<button type="button" class="pd-btn secondary sm" data-mai-act="cancel">Cancel</button></div>';
          break;
        case 'disconnect-go': disconnect(box, li); break;
        case 'cancel': panel.innerHTML = ''; break;
      }
    });
  }

  // render draws the card for view (GET /api/me/apps' answer) into box,
  // then loads the person's connections; no card: box is emptied.
  function render(box, view) {
    bind(box);
    if (!hasCard(view)) {
      box.innerHTML = '';
      return;
    }
    box.innerHTML = cardHtml(view);
    loadMine(box);
  }

  // cardHtml and serverNames are exported for the tests (pure functions).
  window.PortcullisMyAI = { render, serverName, serverNames, cardHtml };
})();
