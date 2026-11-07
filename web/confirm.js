// confirm.js — the confirmation page (contract §15.6, §5.1 "Fresh auth").
//
// The page is the Hub's rendering of the stored request (confirm.html,
// escaped by html/template). This script reads only #confirm's data-*
// attributes and writes only textContent (never markup). Approve asks
// for the typed check, then a fresh passkey sign-in in a popup through
// portcullis-fresh-auth: freshauth.js (PortcullisFreshAuth) runs the
// flow and its checks, the popup landing on this listener's "/" (whose
// freshauth-callback.js hands the code back); the proof is posted with
// the decision. Decline needs no passkey.
(function () {
  'use strict';
  const root = document.getElementById('confirm');
  if (!root) return;
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
  let flowing = false; // a sign-in flow of this page is running
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

  // startApprove starts the fresh sign-in from the click itself
  // (PortcullisFreshAuth.start opens the popup before any await).
  function startApprove() {
    if (busy || !matches()) return;
    const t = typed.value.trim();
    flowing = true;
    PortcullisFreshAuth.start(fa, {
      ctx: { confirmation: id },
      status: (text, warn) => say(text, warn ? 'warn' : ''),
      busy: setBusy,
      end: () => { flowing = false; },
      proof: p => {
        say('Recording your approval…');
        send({ decision: 'approve', typed: t, code: p.code, code_verifier: p.code_verifier, nonce: p.nonce });
      },
    });
  }

  if (root.dataset.state !== 'pending' || !approve) return;
  typed.addEventListener('input', () => { if (!busy) approve.disabled = !matches(); });
  typed.addEventListener('keydown', e => { if (e.key === 'Enter' && matches()) startApprove(); });
  approve.addEventListener('click', startApprove);
  decline.addEventListener('click', () => {
    if (busy && !flowing) return;
    if (flowing) PortcullisFreshAuth.cancel();
    setBusy(true);
    say('Recording your decision…');
    send({ decision: 'decline' });
  });
})();
