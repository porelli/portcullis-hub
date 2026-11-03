// Portcullis Hub: My apps (people.<domain> only).
//
// The signed-in person's own per-person values for the apps they can
// use (GET /api/me/apps): one card per app with its link, each value,
// why they get it ("from office_milan", "everyone with access") and when
// a change reaches the app. Registered as an extra tab of
// PortcullisDirectory by people.html. Vanilla JS, no build step.
//
// Rules of this file (as directory.js):
//   - every server string goes through esc() before it reaches innerHTML;
//   - no inline event handlers: data-* attributes and one delegated
//     listener per panel.
(function () {
  'use strict';

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  // When a change of the value reaches the app.
  const APPLIES = {
    live: 'a change applies at once',
    next_request: 'a change applies at your next request',
    next_sign_in: 'a change applies at your next sign-in',
    account_creation: 'set when your account is created in the app (an existing account keeps its value)',
    reload: 'a change applies after the app reloads',
    restart: 'a change applies after the app restarts'
  };

  function reasonText(r) {
    r = r || {};
    switch (r.source) {
      case 'group': return r.group ? 'from ' + r.group : 'from one of your groups';
      case 'combined': return r.groups && r.groups.length ? 'from ' + r.groups.join(', ') : 'from your groups';
      case 'default': return 'everyone with access';
      case 'fail-closed': return 'the most restrictive value: your groups\' settings could not be combined safely';
    }
    return '';
  }

  // Only http(s) links are rendered as links.
  function safeURL(u) { return /^https?:\/\//i.test(u || '') ? u : ''; }

  function card(app) {
    const url = safeURL(app.url);
    const name = esc(app.name || app.id);
    let h = '<article class="pd-card ma-app" data-ma-app="' + esc(app.id) + '"><div class="ma-head">';
    if (app.icon) h += '<span class="ma-icon" aria-hidden="true">' + esc(app.icon) + '</span>';
    h += '<h3 class="ma-name">' + (url ? '<a href="' + esc(url) + '" target="_blank" rel="noopener noreferrer">' + name + '</a>' : name) + '</h3></div>';
    h += '<dl class="ma-values">';
    for (const v of app.values || []) {
      const why = reasonText(v.reason);
      const when = APPLIES[v.applies] || '';
      h += '<div class="ma-value" data-ma-key="' + esc(v.key) + '"><dt>' + esc(v.label || v.key) + '</dt><dd><strong>' + esc(v.value) + '</strong>' +
        (v.reason && v.reason.source === 'fail-closed' ? ' <span class="pd-pill warn">fail-closed</span>' : '') +
        (why ? '<span class="ma-why pd-muted"> · ' + esc(why) + '</span>' : '') +
        (when ? '<div class="ma-applies pd-muted">' + esc(when) + '</div>' : '') + '</dd></div>';
    }
    return h + '</dl></article>';
  }

  async function load(el) {
    const box = el.querySelector('[data-ma-list]');
    box.innerHTML = '<p class="pd-muted">Loading…</p>';
    let res, text;
    try {
      res = await fetch('/api/me/apps', { credentials: 'same-origin' });
      text = await res.text();
    } catch (err) {
      box.innerHTML = '<p class="pd-warn">Could not load your apps: ' + esc(err.message) + '</p>';
      return;
    }
    if (!res.ok) {
      box.innerHTML = '<p class="pd-warn">Could not load your apps: ' + esc(text.trim() || ('HTTP ' + res.status)) + '</p>';
      return;
    }
    let apps = [];
    try { apps = (JSON.parse(text).apps) || []; } catch (_) { /* shown as empty */ }
    box.innerHTML = apps.length
      ? apps.map(card).join('')
      : '<p class="pd-muted ma-empty">No apps with personal settings.</p>';
  }

  // render (re)draws My apps into el (the tab's panel) and loads them.
  function render(el) {
    if (!el.dataset.maBound) {
      el.dataset.maBound = '1';
      el.innerHTML = '<div class="pd-head"><h2 class="pd-h3">My apps</h2>' +
        '<button type="button" class="pd-btn secondary sm" data-ma-act="reload">Refresh</button></div>' +
        '<p class="pd-muted ma-intro">Your own settings in the apps you can use, and where each comes from. Administrators set them.</p>' +
        '<div data-ma-list></div>';
      el.addEventListener('click', e => {
        const b = e.target.closest('[data-ma-act]');
        if (b && el.contains(b) && b.dataset.maAct === 'reload') load(el);
      });
    }
    return load(el);
  }

  window.PortcullisMyApps = { render };
})();
