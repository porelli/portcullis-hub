// Portcullis: the impersonation banner and the Stop page (sign-in part 3,
// contract §5 "The impersonation banner", §5.1; plan D43).
//
// Loaded first in <body> by every people-listener page (people.html: My
// apps and People; mysignin.html; impersonation-stop.html). It exposes
// nothing global:
//
//   - it asks GET /api/me/impersonation; when the browser is signed in
//     as someone else ({"active": {person, admin, reason, until,
//     stop_url}}) it inserts <div id="pc-imp-banner" role="alert"> as
//     the body's first child:
//       You are signed in as <person> (by <admin>) · reason “<reason>” · <n> min left  [Stop]
//     n = ceil(remaining / 60 s), at least 1. It counts down once a minute
//     and reloads the page when the time runs out;
//   - Stop (the banner's, or the Stop page's button) POSTs
//     /api/me/impersonation/stop and then goes to the answer's sign_out;
//   - on the Stop page (<main id="imp-stop">) it shows "Stop signing in
//     as <person>", or "Nothing to stop" when the browser isn't
//     impersonating.
//
// Rules (as directory.js and mysignin.js): every server value is set with
// textContent (no markup is ever built from data); no inline handlers:
// data-imp-act attributes and one delegated listener per container.
(function () {
  'use strict';

  const MINUTE = 60 * 1000;

  function minutesLeft(until, now) {
    const t = new Date(until).getTime();
    if (isNaN(t)) return 0;
    const rem = t - now;
    return rem <= 0 ? 0 : Math.max(1, Math.ceil(rem / MINUTE));
  }

  // bannerText is the fixed line (D43), without the Stop button.
  // At or past until (or an unreadable until): "ending…".
  function bannerText(a, now) {
    const n = minutesLeft(a.until, now);
    return 'You are signed in as ' + a.person + ' (by ' + a.admin + ') · reason “' + a.reason + '” · ' +
      (n > 0 ? n + ' min left' : 'ending…');
  }

  // safeURL: an https URL (http only on a plain-http page, the harness).
  function safeURL(u) {
    u = String(u || '');
    if (/^https:\/\//i.test(u)) return u;
    if (/^http:\/\//i.test(u) && location.protocol === 'http:') return u;
    return '';
  }

  function el(tag, attrs, kids) {
    const e = document.createElement(tag);
    for (const k of Object.keys(attrs || {})) e.setAttribute(k, attrs[k]);
    for (const c of kids || []) e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    return e;
  }

  async function readActive() {
    const res = await fetch('/api/me/impersonation', { credentials: 'same-origin', cache: 'no-store' });
    // 404: a page without the route (the Hub listener's confirmation
    // page): never impersonating there.
    if (res.status === 404) return null;
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const j = await res.json();
    const a = j && j.active;
    if (!a || typeof a !== 'object' || !a.person || !a.admin) return null;
    return { person: String(a.person), admin: String(a.admin), reason: String(a.reason || ''), until: String(a.until || '') };
  }

  // stop ends the impersonation and signs this browser out (oauth2-proxy
  // drops its session). status(text) shows a problem; busy(on) the
  // buttons' state.
  let stopping = false;
  async function stop(status, busy) {
    if (stopping) return;
    stopping = true;
    busy(true);
    status('Stopping…');
    let res, j = null;
    try {
      res = await fetch('/api/me/impersonation/stop', { method: 'POST', credentials: 'same-origin', cache: 'no-store',
        headers: { 'Content-Type': 'application/json' }, body: '{}' });
      try { j = await res.json(); } catch (_) { j = null; }
    } catch (err) {
      stopping = false;
      busy(false);
      status('Couldn\'t stop: ' + (err && err.message ? err.message : 'the Hub didn\'t answer') + '. Try again.');
      return;
    }
    if (res.status === 404) {
      // Already ended (expired, stopped elsewhere, switched off).
      stopping = false;
      status('This session has already ended.');
      location.reload();
      return;
    }
    if (!res.ok) {
      stopping = false;
      busy(false);
      status('Couldn\'t stop: ' + ((j && typeof j.error === 'string' && j.error) || ('HTTP ' + res.status)) + '. Try again.');
      return;
    }
    const out = safeURL(j && j.sign_out);
    if (out) location.assign(out);
    else location.reload();
  }

  // ── the banner ──────────────────────────────────────────────────────

  function showBanner(a) {
    if (document.getElementById('pc-imp-banner')) return;
    const text = el('span', { class: 'pc-imp-text', 'data-imp-text': '' }, [bannerText(a, Date.now())]);
    const msg = el('span', { class: 'pc-imp-msg', 'data-imp-msg': '', role: 'status' });
    const btn = el('button', { type: 'button', class: 'pc-imp-stopbtn', 'data-imp-act': 'stop' }, ['Stop']);
    const div = el('div', { id: 'pc-imp-banner', class: 'pc-imp-banner', role: 'alert' }, [
      el('span', { class: 'pc-imp-icon', 'aria-hidden': 'true' }, ['⚠']), text, msg, btn]);
    div.addEventListener('click', e => {
      const b = e.target && e.target.closest ? e.target.closest('[data-imp-act]') : null;
      if (!b || b.disabled) return;
      if (b.getAttribute('data-imp-act') === 'stop') {
        stop(t => { msg.textContent = t; }, on => { btn.disabled = on; });
      }
    });
    document.body.insertBefore(div, document.body.firstChild);
    countdown(a, text);
  }

  // countdown: once a minute, on the minute of what's left. The page
  // reloads only from a timer armed while time was left (so it reloads
  // once, when the time runs out). Already at or past until when shown
  // (a browser clock ahead of the server's, an unreadable until): the
  // banner says "ending…" and asks the Hub again every 20 s, never
  // reloading while the Hub still answers this impersonation; when it
  // answers none, the page reloads once.
  const RECHECK = 20 * 1000;
  function remaining(a) { return new Date(a.until).getTime() - Date.now(); }
  function countdown(a, text) {
    const rem = remaining(a);
    text.textContent = bannerText(a, Date.now());
    if (rem > 0) {
      setTimeout(() => {
        if (!(remaining(a) > 0)) { location.reload(); return; }
        countdown(a, text);
      }, (rem % MINUTE) || MINUTE);
      return;
    }
    setTimeout(() => {
      readActive().then(b => {
        if (!b) { location.reload(); return; }
        a.until = b.until;
        countdown(a, text);
      }, () => countdown(a, text));
    }, RECHECK);
  }

  // showUnknown: GET /api/me/impersonation failed, so whether this
  // browser is signed in as someone else isn't known: a small line keeps
  // a way to Stop (the Stop page).
  function showUnknown() {
    if (document.getElementById('pc-imp-banner') || document.getElementById('pc-imp-unknown')) return;
    const div = el('div', { id: 'pc-imp-unknown', class: 'pc-imp-unknown', role: 'status' }, [
      'Couldn\'t check whether you\'re signed in as someone else — ',
      el('a', { href: '/impersonation/stop' }, ['Stop'])]);
    document.body.insertBefore(div, document.body.firstChild);
  }

  // ── the Stop page ───────────────────────────────────────────────────

  function stopPage(main, a, failed) {
    const box = main.querySelector('[data-imp-stop-body]') || main.appendChild(el('div', { 'data-imp-stop-body': '' }));
    while (box.firstChild) box.removeChild(box.firstChild);
    if (failed) {
      box.appendChild(el('p', { class: 'pd-warn' }, ['Couldn\'t check whether this browser is signed in as someone else: ' + failed + '.']));
      box.appendChild(el('button', { type: 'button', class: 'pd-btn secondary', 'data-imp-act': 'retry' }, ['Try again']));
      return;
    }
    if (!a) {
      const domain = String(main.getAttribute('data-domain') || '');
      box.appendChild(el('p', { 'data-imp-nothing': '' }, ['Nothing to stop: this browser isn\'t signed in as someone else.']));
      if (/^[a-z0-9.-]+$/i.test(domain)) box.appendChild(el('p', {}, [el('a', { href: 'https://' + domain + '/' }, ['Back to the portal'])]));
      return;
    }
    box.appendChild(el('p', {}, ['You are signed in as ' + a.person + ' (by ' + a.admin + '), reason “' + a.reason + '”. Stopping signs this browser out; then sign in again as yourself.']));
    box.appendChild(el('button', { type: 'button', class: 'pd-btn danger', 'data-imp-act': 'stop-page' }, ['Stop signing in as ' + a.person]));
    box.appendChild(el('p', { class: 'pd-muted', 'data-imp-stop-status': '', role: 'status' }));
  }

  function initStopPage(main, first) {
    const show = p => p.then(a => stopPage(main, a, ''), err => stopPage(main, null, (err && err.message) || 'the Hub didn\'t answer'));
    main.addEventListener('click', e => {
      const b = e.target && e.target.closest ? e.target.closest('[data-imp-act]') : null;
      if (!b || b.disabled) return;
      const act = b.getAttribute('data-imp-act');
      if (act === 'retry') { show(readActive()); return; }
      if (act === 'stop-page') {
        const s = main.querySelector('[data-imp-stop-status]');
        stop(t => { if (s) s.textContent = t; }, on => { b.disabled = on; });
      }
    });
    return show(first);
  }

  // ── start ───────────────────────────────────────────────────────────

  // The question goes out at once; the page is drawn once the document
  // is parsed (this script runs first in <body>).
  const active = readActive();
  function init() {
    const main = document.getElementById('imp-stop');
    const page = main ? initStopPage(main, active) : Promise.resolve();
    // The Stop page says so itself when the check fails.
    const banner = active.then(a => { if (a) showBanner(a); }, () => { if (!main) showUnknown(); });
    return Promise.all([page, banner]);
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
