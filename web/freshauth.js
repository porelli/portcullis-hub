// freshauth.js — the opener side of the fresh-auth popup (contract §5.1
// "Fresh auth", §8; F20, G11), shared by myapps.js (file-share passwords),
// mysignin.js (the Sign-in page and a person's Sign-in tab) and
// confirm.js (confirmations) on both listeners.
//
// window.PortcullisFreshAuth.start(fa, h) opens Keycloak's authorize URL
// (fa = {authorize_url, client_id, redirect_uri}: the listener's
// fresh-auth client) in a popup with response_type code, scope openid,
// prompt login, max_age 0 (no ACR request: which methods count as fresh is
// the Hub's proof rule, pc_fresh), a random state and nonce and
// the S256 challenge of a random PKCE verifier. Call it from the click
// itself: the popup is opened before any await, so pop-up blockers allow
// it. {state, nonce, verifier, ctx} wait in sessionStorage only while the
// flow runs (dropped at load, on pagehide, at the end of every flow and
// after FLOW_DEADLINE_MS). The popup lands on the listener's redirect URI
// (https://people.<d>/signin on the people listener, https://hub.<d>/ on
// the Hub's), whose callback (freshauth-callback.js) posts {type, code, state, error} to
// this same-origin opener. A message is accepted only from this origin,
// from the popup this page opened, of type portcullis-fresh-auth, with the
// stored state and the flow's own ctx; the entry is deleted, then
// h.proof({code, code_verifier, nonce}) runs. h = {ctx (JSON-serialisable:
// what the flow is for), status(text, warn, spin), busy(on), proof(p),
// end()}. Writes no markup.
(function () {
  'use strict';
  const FA_KEY = 'portcullis-fresh-auth';
  const FLOW_DEADLINE_MS = 10 * 60 * 1000;
  let flow = null; // {popup, timer, ctx (JSON text), h}

  function b64url(bytes) {
    let s = '';
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function randomB64(n) {
    const a = new Uint8Array(n);
    crypto.getRandomValues(a);
    return b64url(a);
  }
  async function s256(v) {
    const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(v));
    return b64url(new Uint8Array(d));
  }

  // endFlow forgets the flow in progress (and its sessionStorage entry).
  function endFlow() {
    sessionStorage.removeItem(FA_KEY);
    if (!flow) return;
    const f = flow;
    clearInterval(f.timer);
    flow = null;
    if (f.h.end) f.h.end();
  }
  // A flow never outlives the page: an entry a previous page left (closed
  // mid-flow, reloaded) is dropped at load and when the page goes.
  sessionStorage.removeItem(FA_KEY);

  // fail ends the flow with a message (nothing changed).
  function fail(h, text) {
    endFlow();
    h.busy(false);
    h.status(text, true);
  }

  // cancel closes the popup and forgets the flow (no message).
  function cancel() {
    if (flow && flow.popup && !flow.popup.closed) flow.popup.close();
    endFlow();
  }

  async function start(fa, h) {
    // https only, except on a plain-http page (the local harness).
    const okURL = /^https:\/\//i.test((fa && fa.authorize_url) || '') ||
      (location.protocol === 'http:' && /^http:\/\//i.test((fa && fa.authorize_url) || ''));
    if (!fa || !okURL || !fa.client_id || !fa.redirect_uri) {
      h.status('A fresh sign-in isn\'t available right now. Try again later.', true);
      return;
    }
    cancel();
    const popup = window.open('', 'portcullis-fresh-auth', 'popup,width=520,height=720');
    if (!popup) {
      h.status('Allow pop-ups for this page: the fresh sign-in opens in a small window.', true);
      return;
    }
    const verifier = randomB64(64); // 86 characters (RFC 7636: 43–128)
    const state = randomB64(32);
    const nonce = randomB64(32);
    const ctx = JSON.stringify(h.ctx === undefined ? null : h.ctx);
    sessionStorage.setItem(FA_KEY, JSON.stringify({ state, nonce, verifier, ctx }));
    flow = { popup, timer: 0, ctx, h };
    const mine = flow;
    h.busy(true);
    h.status('Sign in again in the sign-in window to continue…', false, true);
    let challenge;
    try {
      challenge = await s256(verifier);
    } catch (err) {
      popup.close();
      if (flow === mine) fail(h, 'This browser can\'t start a secure sign-in: ' + err.message);
      return;
    }
    if (flow !== mine) return;
    const u = new URL(fa.authorize_url);
    for (const [k, v] of [
      ['response_type', 'code'],
      ['client_id', fa.client_id],
      ['redirect_uri', fa.redirect_uri],
      ['scope', 'openid'],
      ['prompt', 'login'],
      ['max_age', '0'],
      ['state', state],
      ['nonce', nonce],
      ['code_challenge', challenge],
      ['code_challenge_method', 'S256'],
    ]) u.searchParams.set(k, v);
    popup.location.href = u.toString();
    // A popup closed without an answer cancels the flow (after a grace:
    // the callback posts, then closes).
    let closedAt = 0;
    const deadline = Date.now() + FLOW_DEADLINE_MS;
    mine.timer = setInterval(() => {
      if (flow !== mine) { clearInterval(mine.timer); return; }
      if (Date.now() > deadline) {
        if (!popup.closed) popup.close();
        fail(h, 'The sign-in took too long: nothing changed. Try again.');
        return;
      }
      if (!popup.closed) return;
      if (!closedAt) { closedAt = Date.now(); return; }
      if (Date.now() - closedAt < 1000) return;
      fail(h, 'The sign-in window was closed: nothing changed.');
    }, 400);
  }

  window.addEventListener('message', ev => {
    if (ev.origin !== location.origin) return;
    const d = ev.data;
    if (!d || typeof d !== 'object' || d.type !== 'portcullis-fresh-auth' || typeof d.state !== 'string') return;
    let pending = null;
    try { pending = JSON.parse(sessionStorage.getItem(FA_KEY) || 'null'); } catch (_) { pending = null; }
    if (!pending || !pending.state || d.state !== pending.state) return;
    if (!flow || ev.source !== flow.popup || flow.ctx !== pending.ctx) return;
    const f = flow;
    sessionStorage.removeItem(FA_KEY);
    clearInterval(f.timer);
    flow = null;
    if (f.h.end) f.h.end();
    if (d.error || !d.code) {
      f.h.busy(false);
      f.h.status('The sign-in didn\'t complete' + (d.error ? ' (' + String(d.error).slice(0, 100) + ')' : '') + ': nothing changed.', true);
      return;
    }
    f.h.proof({ code: d.code, code_verifier: pending.verifier, nonce: pending.nonce });
  });

  window.addEventListener('pagehide', cancel);

  window.PortcullisFreshAuth = { start, cancel };
})();
