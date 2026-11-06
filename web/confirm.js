// confirm.js — the confirmation page (contract §15.6, §5.1 "Fresh auth").
//
// The page is the Hub's rendering of the stored request (confirm.html,
// escaped by html/template). This script reads only #confirm's data-*
// attributes and writes only textContent (never markup). Approve asks
// for the typed check, then a fresh passkey sign-in in a popup through
// portcullis-fresh-auth (response_type code, PKCE S256, prompt login,
// max_age 0, acr_values hwk, a random state and nonce kept in
// sessionStorage until the popup answers). The popup lands on this
// listener's "/" (people.html or index.html), which posts {type:
// 'portcullis-fresh-auth', code, state, error} to this same-origin
// opener and closes. Decline needs no passkey.
(function () {
  'use strict';
  const root = document.getElementById('confirm');
  if (!root) return;
  const FA_KEY = 'portcullis-confirm-fresh-auth';
  const FLOW_DEADLINE_MS = 10 * 60 * 1000;
  // A flow never outlives the page.
  sessionStorage.removeItem(FA_KEY);

  const id = root.dataset.id || '';
  const check = root.dataset.typed || '';
  const fa = {
    authorize_url: root.dataset.authorizeUrl || '',
    client_id: root.dataset.clientId || '',
    redirect_uri: root.dataset.redirectUri || '',
  };
  const typed = document.getElementById('cf-typed');
  const approve = document.getElementById('cf-approve');
  const decline = document.getElementById('cf-decline');
  const status = document.getElementById('cf-status');
  let flow = null; // {popup, timer}
  let busy = false;

  function say(text, kind) {
    status.textContent = text;
    status.classList.toggle('warn', kind === 'warn');
    status.classList.toggle('ok', kind === 'ok');
  }
  function matches() { return !!typed && typed.value.trim() === check && check !== ''; }
  function setBusy(on) {
    busy = on;
    if (approve) approve.disabled = on || !matches();
    if (decline) decline.disabled = on;
    if (typed) typed.disabled = on;
  }
  // done replaces the form with the final state.
  function done(state) {
    const box = document.getElementById('cf-decide');
    root.dataset.state = state;
    while (box.firstChild) box.removeChild(box.firstChild);
    const p = document.createElement('p');
    p.className = 'state';
    p.id = 'cf-state-text';
    p.textContent = state === 'approved'
      ? 'Approved. Go back to your AI client and ask it to try again: this approval works once, for exactly these arguments.'
      : state === 'declined'
        ? 'Declined. Nothing was done.'
        : 'This confirmation is ' + state + '. There is nothing to do here.';
    box.appendChild(p);
  }

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

  function endFlow() {
    sessionStorage.removeItem(FA_KEY);
    if (!flow) return;
    clearInterval(flow.timer);
    flow = null;
  }

  async function send(body) {
    let res, text;
    try {
      res = await fetch('/api/me/confirmations/' + encodeURIComponent(id), {
        method: 'POST', credentials: 'same-origin', cache: 'no-store',
        headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
      });
      text = await res.text();
    } catch (err) {
      res = null;
      text = err.message;
    }
    let ans = null;
    try { ans = JSON.parse(text); } catch (_) { ans = null; }
    if (res && res.ok && ans && typeof ans.state === 'string') {
      done(ans.state);
      return;
    }
    if (res && res.status === 409 && ans && typeof ans.state === 'string') {
      done(ans.state);
      return;
    }
    setBusy(false);
    say(String((text || '').trim() || ('HTTP ' + (res ? res.status : ''))).slice(0, 300), 'warn');
  }

  // startApprove opens the popup from the click itself (before any
  // await), so pop-up blockers allow it.
  async function startApprove() {
    if (busy || !matches()) return;
    const okURL = /^https:\/\//i.test(fa.authorize_url) || (location.protocol === 'http:' && /^http:\/\//i.test(fa.authorize_url));
    if (!okURL || !fa.client_id || !fa.redirect_uri) {
      say('A fresh sign-in isn\'t available right now. Try again later.', 'warn');
      return;
    }
    if (flow && flow.popup && !flow.popup.closed) flow.popup.close();
    endFlow();
    const popup = window.open('', 'portcullis-fresh-auth', 'popup,width=520,height=720');
    if (!popup) {
      say('Allow pop-ups for this page: the fresh sign-in opens in a small window.', 'warn');
      return;
    }
    const verifier = randomB64(64);
    const state = randomB64(32);
    const nonce = randomB64(32);
    sessionStorage.setItem(FA_KEY, JSON.stringify({ state, nonce, verifier, id }));
    flow = { popup, timer: 0, typed: typed.value.trim() };
    const mine = flow;
    setBusy(true);
    say('Touch your passkey in the sign-in window to continue…');
    let challenge;
    try {
      challenge = await s256(verifier);
    } catch (err) {
      popup.close();
      endFlow();
      setBusy(false);
      say('This browser can\'t start a secure sign-in: ' + err.message, 'warn');
      return;
    }
    if (flow !== mine) return;
    const u = new URL(fa.authorize_url);
    for (const [k, v] of [
      ['response_type', 'code'], ['client_id', fa.client_id], ['redirect_uri', fa.redirect_uri],
      ['scope', 'openid'], ['prompt', 'login'], ['max_age', '0'], ['acr_values', 'hwk'],
      ['state', state], ['nonce', nonce], ['code_challenge', challenge], ['code_challenge_method', 'S256'],
    ]) u.searchParams.set(k, v);
    popup.location.href = u.toString();
    let closedAt = 0;
    const deadline = Date.now() + FLOW_DEADLINE_MS;
    mine.timer = setInterval(() => {
      if (flow !== mine) { clearInterval(mine.timer); return; }
      if (Date.now() > deadline) {
        if (!popup.closed) popup.close();
        endFlow();
        setBusy(false);
        say('The sign-in took too long: nothing changed. Try again.', 'warn');
        return;
      }
      if (!popup.closed) return;
      if (!closedAt) { closedAt = Date.now(); return; }
      if (Date.now() - closedAt < 1000) return;
      endFlow();
      setBusy(false);
      say('The sign-in window was closed: nothing changed.', 'warn');
    }, 400);
  }

  // The popup callback: accepted only from this origin, from the popup
  // this page opened, of type portcullis-fresh-auth and with the stored
  // state; the stored entry is deleted, then the proof posted.
  window.addEventListener('message', ev => {
    if (ev.origin !== location.origin) return;
    const d = ev.data;
    if (!d || typeof d !== 'object' || d.type !== 'portcullis-fresh-auth' || typeof d.state !== 'string') return;
    let pending = null;
    try { pending = JSON.parse(sessionStorage.getItem(FA_KEY) || 'null'); } catch (_) { pending = null; }
    if (!pending || !pending.state || d.state !== pending.state || pending.id !== id) return;
    if (!flow || ev.source !== flow.popup) return;
    const f = flow;
    sessionStorage.removeItem(FA_KEY);
    clearInterval(f.timer);
    flow = null;
    if (d.error || !d.code) {
      setBusy(false);
      say('The sign-in didn\'t complete' + (d.error ? ' (' + String(d.error).slice(0, 100) + ')' : '') + ': nothing changed.', 'warn');
      return;
    }
    say('Recording your approval…');
    send({ decision: 'approve', typed: f.typed, code: d.code, code_verifier: pending.verifier, nonce: pending.nonce });
  });

  window.addEventListener('pagehide', () => {
    if (flow && flow.popup && !flow.popup.closed) flow.popup.close();
    endFlow();
  });

  if (root.dataset.state !== 'pending' || !approve) return;
  typed.addEventListener('input', () => { if (!busy) approve.disabled = !matches(); });
  typed.addEventListener('keydown', e => { if (e.key === 'Enter' && matches()) startApprove(); });
  approve.addEventListener('click', startApprove);
  decline.addEventListener('click', () => {
    if (busy) return;
    if (flow && flow.popup && !flow.popup.closed) flow.popup.close();
    endFlow();
    setBusy(true);
    say('Recording your decision…');
    send({ decision: 'decline' });
  });
})();
