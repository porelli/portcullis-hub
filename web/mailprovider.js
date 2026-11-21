// Portcullis Hub — the mail provider slot in the UI (contract §19.9,
// spec §8): an instance's Mail tab, the switch dialog, unwire and Retry.
// Hub listener only, administrators only.
//
//   window.PortcullisMailProvider.renderTab(id, pane)   the Mail tab
//   window.PortcullisMailProvider.switchDialog(from)    Settings → Mail's Switch…
//   window.PortcullisMailProvider.unwire(id)            Settings → Mail's Unwire…
//   window.PortcullisMailProvider.retryVoid()           Retry an owed void
//   window.PortcullisMailProvider.openAdminView()       the read-only admin view (§19.13)
//   window.PortcullisMailProvider.adminViewHtml(label)  its warning and link (pure; tests)
//   window.PortcullisMailProvider.tabSkeleton(view)     (pure; tests)
//
// GET  /api/instances/{id}/mail-provider    the tab's view (+ fresh_auth)
// PUT  /api/instances/{id}/mail-provider    {wired: true, confirm, code, code_verifier, nonce, block_hash}
//                                           {wired: false, drain}
// POST /api/mail/provider/switch            {to, confirm, confirm_empty, code, code_verifier, nonce}
// POST /api/mail/provider/retry-void
// POST /api/mail/admin-view                 {} → {url} (audited)
//
// Rules: provider text (its name, version, checks, refusals, errors and
// the warning) is set with textContent only, never into innerHTML; the
// fresh sign-in popup opens from the click itself.
(function () {
  'use strict';

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
  const enc = encodeURIComponent;

  // ADMIN_VIEW_WARNING is the read-only admin view's warning (contract
  // §19.13), shown next to its link.
  const ADMIN_VIEW_WARNING = 'Stalwart\'s own admin screen is read-only here. Make changes in Portcullis (Settings → Mail); changes made elsewhere would bypass Portcullis\'s mail safeguards.';

  // adminViewHtml is the warning and the link for the provider label (the
  // label is the template's, escaped; "Stalwart" in the warning is the
  // contract's text).
  function adminViewHtml(label) {
    return '<div class="public-warn" data-mail-admin-view><p data-mail-admin-view-warning>' + esc(ADMIN_VIEW_WARNING) + '</p>' +
      '<button type="button" class="btn btn-sm" data-mail-admin-view-open>Open ' + esc(label || 'the mail server') + '\'s admin (read-only)</button></div>';
  }

  // openAdminView asks the Hub for the link (audited) and opens it in a
  // new tab, from the click itself (the tab opens first, then navigates).
  async function openAdminView() {
    const w = window.open('', '_blank');
    if (w) w.opener = null;
    try {
      const r = await (await window.apiCall('/api/mail/admin-view', 'POST', {})).json();
      if (!r || typeof r.url !== 'string' || !/^https:\/\/[a-z0-9.-]+\/admin\/$/.test(r.url)) throw new Error('the Hub returned no admin view link');
      if (w) w.location.href = r.url; else window.location.href = r.url;
    } catch (e) {
      if (w) w.close();
      window.showToast(e.message, 'error');
    }
  }

  // tabSkeleton is the Mail tab's markup for view: ids and buttons only;
  // every text that comes from the provider or the Hub's refusals is
  // filled by fillTab with textContent.
  function tabSkeleton(v) {
    let h = '<div class="inst-section" data-mail-tab>' +
      '<div class="public-warn" data-mail-warning></div>' +
      '<dl class="inst-facts"><dt>Mail server</dt><dd data-mail-mode></dd>' +
      '<dt>Provider</dt><dd data-mail-provider-info></dd></dl>';
    if (v.void) {
      h += '<div class="public-warn" data-mail-void><span data-mail-void-text></span> ' +
        '<button type="button" class="btn btn-sm" data-mailp-act="retry-void">Retry</button></div>';
    }
    if (v.held) {
      h += '<div class="public-warn" data-mail-held><span data-mail-held-reason></span> <span data-mail-hold-warning></span></div>';
    }
    h += '<ul data-mail-refused></ul>';
    const canWire = (!v.wired || v.held) && !(v.refused_because || []).length;
    if (canWire) {
      h += '<div class="inst-form" data-mail-wire-form>' +
        '<label class="block" for="mailp-confirm">Type the instance id to confirm</label>' +
        '<input id="mailp-confirm" data-mail-confirm autocomplete="off" spellcheck="false">' +
        '<div class="inst-row"><button type="button" class="btn btn-primary btn-sm" data-mailp-act="wire">' +
        (v.held ? 'Confirm the updated template' : 'Make this the mail server') + '</button></div>' +
        '<p class="settings-hint"><small>A fresh sign-in with your security key follows.</small></p></div>';
    }
    if (v.wired && v.admin_view) h += adminViewHtml(v.label);
    if (v.wired) {
      h += '<div class="inst-row"><label><input type="checkbox" data-mail-drain checked> drain first (senders keep delivering until every domain is off)</label> ' +
        '<button type="button" class="btn btn-danger btn-sm" data-mailp-act="unwire">Unwire…</button></div>';
    }
    return h + '<div data-mailp-status></div></div>';
  }

  // fillTab sets every provider-derived text with textContent.
  function fillTab(pane, v) {
    const q = s => pane.querySelector(s);
    q('[data-mail-warning]').textContent = v.warning || '';
    q('[data-mail-mode]').textContent = v.wired ? v.mode : 'not this server\'s mail server';
    const p = v.provider;
    q('[data-mail-provider-info]').textContent = p ? (p.name + ' ' + p.version + ' · checks: ' + (p.checks || []).join(', ')) : '—';
    const vt = q('[data-mail-void-text]');
    if (vt && v.void) vt.textContent = 'A void of every mail password is owed (' + v.void.reason + ', since ' + v.void.since + ')' + (v.void.error ? ': ' + v.void.error : '');
    const hr = q('[data-mail-held-reason]');
    if (hr && v.held) hr.textContent = v.held.reason + '.';
    const hw = q('[data-mail-hold-warning]');
    if (hw) hw.textContent = v.hold_warning || '';
    const ul = q('[data-mail-refused]');
    for (const r of v.refused_because || []) {
      const li = document.createElement('li');
      li.textContent = r;
      ul.appendChild(li);
    }
  }

  function setStatus(pane, t, warn) {
    const el = pane.querySelector('[data-mailp-status]');
    if (!el) return;
    el.className = warn ? 'public-warn' : 'inst-ok';
    el.textContent = t;
  }

  // fresh runs the fresh sign-in from the click and calls send(proof).
  function fresh(fa, what, onStatus, send) {
    if (!fa || !window.PortcullisFreshAuth) { onStatus('A fresh sign-in isn\'t available: try again in a moment.', true); return; }
    window.PortcullisFreshAuth.start(fa, {
      ctx: { mail_provider: what },
      status: (t, warn) => onStatus(t, warn),
      busy: () => {},
      end: () => {},
      proof: p => send({ code: p.code, code_verifier: p.code_verifier, nonce: p.nonce }),
    });
  }

  async function renderTab(id, pane) {
    if (!pane) return;
    let v;
    try {
      v = await window.apiGet('/api/instances/' + enc(id) + '/mail-provider');
    } catch (e) {
      pane.innerHTML = '<div class="public-warn" data-mail-tab-error></div>';
      pane.firstChild.textContent = e.message;
      return;
    }
    pane.innerHTML = tabSkeleton(v);
    fillTab(pane, v);
    pane.onclick = e => {
      if (e.target.closest && e.target.closest('[data-mail-admin-view-open]')) { openAdminView(); return; }
      const b = e.target.closest && e.target.closest('[data-mailp-act]');
      if (!b || !pane.contains(b)) return;
      const st = (t, warn) => setStatus(pane, t, warn);
      switch (b.dataset.mailpAct) {
        case 'wire': {
          const typed = pane.querySelector('[data-mail-confirm]').value.trim();
          if (typed !== id) { st('Type the instance id ' + id + ' to confirm.', true); return; }
          fresh(v.fresh_auth, 'wire:' + id, st, async proof => {
            try {
              await window.apiPut('/api/instances/' + enc(id) + '/mail-provider', Object.assign({ wired: true, confirm: typed, block_hash: v.block_hash || '' }, proof));
              window.showToast('Wiring ' + id + ' as the mail server…', 'success');
            } catch (err) { st(err.message, true); return; }
            renderTab(id, pane);
          });
          break;
        }
        case 'unwire':
          unwire(id, pane.querySelector('[data-mail-drain]').checked).then(() => renderTab(id, pane)).catch(err => st(err.message, true));
          break;
        case 'retry-void':
          retryVoid().then(() => renderTab(id, pane)).catch(err => st(err.message, true));
          break;
      }
    };
  }

  // unwire asks first, then PUT {wired: false, drain}.
  async function unwire(id, drain) {
    const how = drain ? 'Every mail domain drains first; the provider stops once they are all off.' : 'Mail stops now: senders may bounce.';
    if (!confirm('Unwire ' + id + ' as the mail server? ' + how + ' Every mail password is voided.')) return;
    await window.apiPut('/api/instances/' + enc(id) + '/mail-provider', { wired: false, drain: !!drain });
    window.showToast('Unwiring ' + id + '…', 'success');
  }

  async function retryVoid() {
    await window.apiCall('/api/mail/provider/retry-void', 'POST', {});
    window.showToast('Retrying the void…', 'success');
  }

  // switchDialog: the two typed fields (the target's id and "<n>
  // mailboxes start empty"), then the fresh sign-in.
  async function switchDialog(from, candidates) {
    const dlg = document.createElement('dialog');
    dlg.className = 'modal';
    dlg.setAttribute('data-mail-switch', '');
    const opts = (candidates || []).filter(c => c !== from).map(c => '<option value="' + esc(c) + '">' + esc(c) + '</option>').join('');
    dlg.innerHTML = '<form method="dialog" class="inst-form"><h3>Switch the mail server</h3>' +
      '<p class="public-warn" data-mail-warning></p>' +
      '<label class="block" for="mailsw-to">New mail server</label><select id="mailsw-to" data-mail-switch-to>' + opts + '</select>' +
      '<label class="block" for="mailsw-confirm">Type its instance id</label><input id="mailsw-confirm" data-mail-switch-confirm autocomplete="off">' +
      '<label class="block" for="mailsw-empty">Type "&lt;n&gt; mailboxes start empty"</label><input id="mailsw-empty" data-mail-switch-empty autocomplete="off">' +
      '<div data-mail-switch-status></div>' +
      '<div class="inst-row"><button type="button" class="btn btn-danger btn-sm" data-mail-switch-go>Switch</button> <button type="button" class="btn btn-secondary btn-sm" data-mail-switch-cancel>Cancel</button></div></form>';
    document.body.appendChild(dlg);
    const status = (t, warn) => { const el = dlg.querySelector('[data-mail-switch-status]'); el.className = warn ? 'public-warn' : ''; el.textContent = t; };
    let fa = null;
    const sel = dlg.querySelector('[data-mail-switch-to]');
    const load = async () => {
      fa = null;
      if (!sel.value) return;
      try {
        const v = await window.apiGet('/api/instances/' + enc(sel.value) + '/mail-provider');
        fa = v.fresh_auth;
        dlg.querySelector('[data-mail-warning]').textContent = v.warning || '';
      } catch (e) { status(e.message, true); }
    };
    sel.addEventListener('change', load);
    await load();
    dlg.querySelector('[data-mail-switch-cancel]').addEventListener('click', () => { dlg.close(); dlg.remove(); });
    dlg.querySelector('[data-mail-switch-go]').addEventListener('click', () => {
      const to = sel.value, confirmID = dlg.querySelector('[data-mail-switch-confirm]').value.trim(), empty = dlg.querySelector('[data-mail-switch-empty]').value.trim();
      if (!to || confirmID !== to) { status('Type the new mail server\'s instance id.', true); return; }
      fresh(fa, 'switch:' + to, status, async proof => {
        try {
          await window.apiCall('/api/mail/provider/switch', 'POST', Object.assign({ to, confirm: confirmID, confirm_empty: empty }, proof));
        } catch (err) { status(err.message, true); return; }
        window.showToast('Switching the mail server to ' + to + '…', 'success');
        dlg.close();
        dlg.remove();
      });
    });
    dlg.showModal();
  }

  window.PortcullisMailProvider = { renderTab, switchDialog, unwire, retryVoid, tabSkeleton, fillTab, adminViewHtml, openAdminView, ADMIN_VIEW_WARNING };
})();
