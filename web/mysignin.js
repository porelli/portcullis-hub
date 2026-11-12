// Portcullis: the Sign-in page (people.<domain>/signin, mysignin.html)
// and the person's Sign-in tab on the people page (directory.js), sign-in
// part 2 (contract §5.1 "Sign-in page", §8.2, §9.7; plan D24–D28, D32).
//
//   window.PortcullisMySignIn.mount(el, {mode: 'self', onView})
//       the caller's own page: GET /api/me/signin (MySignIn) and
//       GET /api/me/signin/history; actions under /api/me/signin/*.
//   window.PortcullisMySignIn.mount(el, {mode: 'person', user, passwordHint})
//       a person's Sign-in tab for an administrator or a sign_in_help
//       holder: GET /api/directory/users/{u}/signin (PersonSignIn) and
//       …/signin/history; only the actions its `can` allows are offered.
//       The setup link, Remove all passkeys and Reset password buttons
//       are directory.js's own actions (data-act + data-user, its
//       delegated listener); Revoke and Issue are this file's.
//       For an administrator (sign-in part 3, contract §9.7 "Signing in
//       as someone else") the tab also has "Sign in as <person>…" (the
//       reason, a fresh YubiKey touch, then the top window opens the
//       start URL), the refusal text when it can't be offered, and the
//       running line "root is signed in as alice since 14:02 UTC · …
//       · Stop" — this file's own data-msi-act buttons.
//
// The pure parts the node tests run: methodsHtml(view, ctx),
// appsHtml(view), historyHtml(entries), unknownHtml(unknown),
// openDownload(answer) (the shown-once download dialog).
//
// Rules of this file (as directory.js and myapps.js):
//   - every server string goes through esc() before it reaches
//     innerHTML, or is set with textContent / setAttribute;
//   - no inline event handlers: data-* attributes and one delegated
//     listener per mount;
//   - a new browser certificate's .p12 and password live only in the
//     download dialog's closure: shown once, downloaded through a Blob URL
//     that is revoked right after each click, dropped when the dialog
//     closes. Nothing of it is ever written to the browser's storage or a
//     URL (freshauth.js keeps only its own flow state in session
//     storage);
//   - the history cursor (`next`) is passed back as it came (opaque).
(function () {
  'use strict';

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
  const enc = encodeURIComponent;

  // The methods in words (history lines, "Signed in · security key").
  const SHORT = {
    password: 'password',
    passkey_synced: 'synced passkey',
    browser_cert: 'browser certificate',
    passkey_device: 'device-bound passkey',
    security_key: 'security key',
    yubikey_cert: 'YubiKey certificate'
  };
  const PASSKEY_KINDS = ['passkey_synced', 'passkey_device', 'security_key'];
  // What a switched-off method is, under "off on this server".
  const ABOUT = {
    password: 'the weakest method: some apps may not accept it',
    passkey_synced: 'a passkey on your phone or laptop, synced by its maker',
    browser_cert: 'a file you install in this browser / computer',
    passkey_device: 'a passkey that never leaves its device',
    security_key: 'a touch of your YubiKey (or another security key)',
    yubikey_cert: 'a certificate kept on your YubiKey'
  };
  // The history's sources (HistoryPage.unknown).
  const SOURCES = {
    keycloak: 'sign-ins and failed sign-ins',
    opened: 'apps opened',
    audit: 'certificate and help entries'
  };
  const HISTORY_PAGE = 20;

  // A zero time (Go's 0001-01-01, "not recorded") shows as nothing.
  function fmtDay(s) {
    const d = new Date(s);
    if (!s || isNaN(d) || d.getUTCFullYear() < 1970) return '';
    return d.toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' });
  }
  function fmtTime(s) {
    const d = new Date(s);
    if (!s || isNaN(d) || d.getUTCFullYear() < 1970) return '';
    return d.toLocaleString(undefined, { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
  }
  function daysLeft(s) {
    const d = new Date(s);
    if (!s || isNaN(d)) return 0;
    return Math.max(0, Math.ceil((d.getTime() - Date.now()) / 86400000));
  }
  function plural(n, one, many) { return n + ' ' + (n === 1 ? one : many); }
  // hhmmUTC: "14:02 UTC" (the Hub's impersonation times are UTC).
  function hhmmUTC(s) {
    const d = new Date(s);
    if (!s || isNaN(d)) return '';
    return String(d.getUTCHours()).padStart(2, '0') + ':' + String(d.getUTCMinutes()).padStart(2, '0') + ' UTC';
  }
  // minLeft: ceil(remaining / 60 s), at least 1 while it runs (D43).
  function minLeft(until) {
    const t = new Date(until).getTime();
    if (isNaN(t)) return 0;
    const rem = t - Date.now();
    return rem <= 0 ? 0 : Math.max(1, Math.ceil(rem / 60000));
  }
  // reasonProblem: the start's rule 4 before anything is sent: trimmed,
  // 3–200 characters (code points), one line, no control or bidi
  // characters. '' = fine.
  const REASON_BAD = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/;
  function reasonProblem(r) {
    const t = String(r || '').trim();
    const n = Array.from(t).length;
    if (n < 3 || n > 200 || REASON_BAD.test(t)) return 'Type a reason (3–200 characters, one line).';
    return '';
  }

  // protectedName: accounts whose certificates (and password) are managed
  // from the server (admin, portcullis-hub, every portcullis-* name): the
  // Hub refuses them, so the page doesn't offer it.
  function protectedName(u) {
    u = String(u || '').toLowerCase();
    return u === 'admin' || u === 'portcullis-hub' || u.startsWith('portcullis-');
  }

  // accountURL: the account console's signing-in page (where passkeys
  // and security keys are added), the view's account_url (the Hub builds
  // it from Keycloak's public URL); https only, except on a plain-http
  // page (the local harness).
  function accountURL(view) {
    const u = String((view && view.account_url) || '');
    if (/^https:\/\//i.test(u)) return u;
    if (/^http:\/\//i.test(u) && typeof location !== 'undefined' && location.protocol === 'http:') return u;
    return '';
  }

  // certFreshProblem: D26 before the popup opens. A certificate is made
  // only after a fresh sign-in with one of view.cert_fresh (the people
  // template's fresh methods but password and browser_cert); on one's own
  // page the person must have one of them set up. '' = go ahead, else
  // the Hub's 409 text.
  function certFreshProblem(view, self) {
    const ok = view.cert_fresh || [];
    const refusal = view.cert_fresh_refusal || 'creating a certificate needs a passkey or YubiKey sign-in';
    if (!ok.length) return refusal;
    if (!self) return '';
    const mine = (view.methods || []).filter(m => m.state === 'set').map(m => m.id);
    return ok.some(m => mine.includes(m)) ? '' : refusal;
  }

  function pill(cls, text) { return '<span class="pd-pill' + (cls ? ' ' + cls : '') + '">' + esc(text) + '</span>'; }
  function button(cls, attrs, label) {
    return '<button type="button" class="pd-btn ' + cls + ' sm"' + attrs + '>' + esc(label) + '</button>';
  }
  function certPill(c) {
    switch (c.status) {
      case 'valid': return pill('ok', 'valid');
      case 'expiring': { const n = daysLeft(c.not_after); return pill('warn', n ? 'expires in ' + plural(n, 'day', 'days') : 'expires today'); }
      case 'expired': return pill('bad', 'expired');
      case 'revoked': return pill('bad', 'revoked');
    }
    return pill('', c.status || 'unknown');
  }
  const activeCert = c => c.status === 'valid' || c.status === 'expiring';
  function certsOf(view, kind) {
    return (view.certificates || []).filter(c => c.kind === kind)
      .sort((a, b) => String(b.not_before || '').localeCompare(String(a.not_before || '')));
  }

  // can: what the page offers. ctx = {mode: 'self'|'person', user, can}.
  // On a person's tab exactly PersonSignIn.can; on one's own page what
  // the D25 routes allow (never for a server-managed account).
  function offers(view, ctx) {
    if (ctx.mode === 'person') {
      const c = ctx.can || {};
      return { setupLink: !!c.setup_link, removePasskeys: !!c.remove_passkeys, revoke: !!c.revoke, issue: !!c.issue, resetPassword: !!c.password };
    }
    const prot = protectedName(view.user);
    const on = id => (view.methods || []).some(m => m.id === id && m.on && m.state !== 'off');
    return {
      password: on('password') && !prot,
      addPasskey: true,
      createBrowser: on('browser_cert') && !prot,
      revokeOwnBrowser: !prot,
      renew: on('yubikey_cert') && !prot,
      managed: prot
    };
  }

  // certList: one line per certificate (newest first), with Revoke where
  // offered.
  function certList(view, ctx, kind, o) {
    const certs = certsOf(view, kind);
    if (!certs.length) return '';
    const mayRevoke = ctx.mode === 'person' ? o.revoke : (kind === 'browser' && o.revokeOwnBrowser);
    let h = '<ul class="msi-certs">';
    for (const c of certs) {
      h += '<li data-msi-cert="' + esc(c.serial) + '"><span class="pd-mono msi-serial" title="serial">' + esc(c.serial) + '</span> ' +
        '<span class="pd-muted">' + esc((c.not_before ? 'from ' + fmtDay(c.not_before) + ' ' : '') + 'until ' + fmtDay(c.not_after)) + '</span> ' + certPill(c) +
        (mayRevoke && c.status !== 'revoked' && c.status !== 'expired'
          ? ' ' + button('danger xs', ' data-msi-act="revoke" data-serial="' + esc(c.serial) + '" data-kind="' + esc(kind) + '"', 'Revoke') : '') + '</li>';
    }
    return h + '</ul>';
  }

  // methodRow is one method: name and its line, a tag, the actions, the
  // certificates (certificate methods), and a panel for its forms.
  function methodRow(view, ctx, o, m) {
    let sub = '', tag = '', acts = '', more = '';
    const self = ctx.mode === 'self';
    // An administrator resets the LLDAP password whether or not the
    // Password method is on (apps that check LDAP passwords use it).
    if (!self && m.id === 'password' && o.resetPassword) acts = button('danger', ' data-act="password" data-user="' + esc(ctx.user) + '"', 'Reset password');
    if (m.state === 'off') {
      sub = ABOUT[m.id] || '';
      tag = pill('', 'off on this server');
    } else if (m.id === 'password') {
      if (m.state === 'set') {
        sub = (m.password_set_at ? 'set ' + fmtDay(m.password_set_at) + ' · ' : '') + 'weakest: some apps may not accept it';
        tag = pill('ok', 'set');
      } else if (m.state === 'unknown') {
        sub = 'couldn\'t be read right now';
        tag = pill('warn', 'unknown');
      } else {
        sub = 'not set · weakest: some apps may not accept it';
        tag = pill('', 'none');
      }
      if (self && o.password) {
        acts = m.state === 'set'
          ? button('secondary', ' data-msi-act="pw-change"', 'Change') + button('danger', ' data-msi-act="pw-remove"', 'Remove')
          : button('secondary', ' data-msi-act="pw-change"', 'Set');
      }
    } else if (PASSKEY_KINDS.includes(m.id)) {
      const keys = m.passkeys || [];
      if (m.state === 'unknown') { sub = 'couldn\'t be read right now'; tag = pill('warn', 'unknown'); }
      else if (keys.length) {
        sub = keys.map(k => (k.label || 'unnamed') + (fmtDay(k.created_at) ? ' · added ' + fmtDay(k.created_at) : '')).join(' · ');
        tag = pill('ok', String(keys.length));
      } else { sub = 'none yet'; tag = pill('', 'none'); }
      const acct = self ? accountURL(view) : '';
      if (acct) acts = '<a class="pd-btn secondary sm" href="' + esc(acct) + '" target="_blank" rel="noopener noreferrer">+ Add</a>';
    } else if (m.id === 'browser_cert') {
      const max = ((view.limits || {}).effective || {}).browser_cert_max_active || 0;
      const active = view.active_browser_certs || 0;
      sub = ABOUT.browser_cert + (max ? ' · ' + active + ' of ' + max + ' allowed' : '');
      tag = m.state === 'unknown' ? pill('warn', 'unknown') : active ? pill('ok', String(active)) : pill('', 'none');
      if (self && o.createBrowser) {
        const full = max && active >= max;
        acts = button('primary', ' data-msi-act="bc-create"' + (full ? ' disabled title="Revoke one first: you have the most allowed"' : ''), 'Create');
      }
      more = certList(view, ctx, 'browser', o);
    } else if (m.id === 'yubikey_cert') {
      const certs = certsOf(view, 'yubikey'), cur = certs.find(activeCert);
      if (m.state === 'unknown') { sub = 'couldn\'t be read right now'; tag = pill('warn', 'unknown'); }
      else if (cur) { sub = 'valid until ' + fmtDay(cur.not_after); tag = certPill(cur); }
      else { sub = self ? 'none yet: an administrator issues it' : 'none yet'; tag = pill('', 'none'); }
      if (self && o.renew && cur) acts = button('secondary', ' data-msi-act="yk-renew"', 'Renew');
      if (!self && o.issue) acts = button('secondary', ' data-msi-act="yk-issue"', 'Issue for a YubiKey…');
      more = certList(view, ctx, 'yubikey', o);
    }
    return '<div class="msi-row" data-msi-method="' + esc(m.id) + '"><div class="msi-nm"><b>' + esc(m.label) + '</b><div class="msi-sub pd-muted">' + esc(sub) + '</div></div>' +
      '<div class="msi-tag">' + tag + '</div><div class="msi-acts">' + acts + '</div></div>' + more +
      '<div class="msi-panel" data-msi-panel="' + esc(m.id) + '"></div>';
  }

  // methodsHtml: the six rows in the view's (canonical) order and, on a
  // person's tab, the setup link and Remove all passkeys.
  function methodsHtml(view, ctx) {
    const o = offers(view, ctx);
    let h = '<div class="msi-methods">' + (view.methods || []).map(m => methodRow(view, ctx, o, m)).join('') + '</div>';
    if (ctx.mode === 'person') {
      let acts = '';
      if (o.setupLink) acts += button('primary', ' data-act="invite" data-user="' + esc(ctx.user) + '"', 'Send setup link');
      if (o.removePasskeys) acts += button('danger', ' data-act="reset-passkeys" data-user="' + esc(ctx.user) + '"', 'Remove all passkeys');
      if (acts) h += '<div class="pd-actions msi-person-acts">' + acts + '</div>';
      if (o.resetPassword && ctx.passwordHint) h += '<p class="pd-muted pd-small" data-pw-hint>' + esc(ctx.passwordHint) + '</p>';
    } else if (o.managed) {
      h += '<p class="pd-muted pd-small">This account\'s certificates and password are managed from the server.</p>';
    }
    return h;
  }

  // appsHtml: "Apps and what they need" (✓ met, ✗ not met, ? not known).
  function appsHtml(view) {
    const apps = view.apps || [];
    if (!apps.length) return '<p class="msi-apps pd-muted">No apps yet.</p>';
    return '<p class="msi-apps"><span class="pd-muted">Apps and what they need:</span> ' + apps.map(a => {
      const mark = a.ok === true ? '<span class="msi-ok" title="you can sign in to it">✓</span>'
        : a.ok === false ? '<span class="msi-no" title="none of your methods meets it">✗</span>'
          : '<span class="msi-unk" title="not known yet">?</span>';
      return '<span class="msi-app"><b>' + esc(a.name || a.id) + '</b> ' + esc(a.template_name || a.template) + ' ' + mark + '</span>';
    }).join(' · ') + '</p>';
  }

  // whatText: one history entry in words (escaped by the caller).
  function whatText(e) {
    const ms = (e.methods || []).map(m => SHORT[m] || m).join(' + ');
    const with_ = ms ? ' · ' + ms : '';
    let t;
    switch (e.kind) {
      case 'sign_in': t = 'Signed in' + with_; break;
      case 'step_up': t = 'Signed in with a stronger method' + with_; break;
      case 'failed': t = 'Sign-in failed' + with_ + (e.reason ? ': ' + e.reason : ''); break;
      case 'confirmed': t = 'Confirmed it was you' + with_; break;
      case 'opened': t = 'Opened ' + (e.app || 'an app') + with_; break;
      case 'help': t = 'Help from ' + (e.by || 'an administrator'); break;
      case 'certificate': t = 'Certificate'; break;
      case 'impersonation': t = (e.by || 'Someone') + ' signed in as you' + (e.reason ? ' · “' + e.reason + '”' : ''); break;
      default: t = String(e.kind || 'entry');
    }
    if (e.detail) t += ' · ' + e.detail;
    return t;
  }
  function historyRows(entries) {
    return (entries || []).map(e => {
      const where = [e.browser, e.ip].filter(Boolean).join(' · ');
      return '<tr class="msi-h-' + esc(e.kind) + '"><td class="pd-nowrap">' + esc(fmtTime(e.time)) + '</td><td>' + esc(whatText(e)) + '</td>' +
        '<td class="pd-muted">' + esc(where) + '</td></tr>';
    }).join('');
  }
  // historyHtml: newest first (as the Hub answers).
  function historyHtml(entries) {
    if (!(entries || []).length) return '<p class="pd-muted">Nothing yet.</p>';
    return '<table class="pd-table msi-hist"><tbody>' + historyRows(entries) + '</tbody></table>';
  }
  // unknownHtml: the line naming the sources that couldn't be read.
  function unknownHtml(unknown) {
    const u = (unknown || []).map(s => SOURCES[s] || s);
    if (!u.length) return '';
    return '<p class="pd-warn msi-unknown" role="note">Some of the history couldn\'t be read right now (' + esc(u.join(', ')) + '): what\'s shown may be incomplete.</p>';
  }

  // impersonationHtml: on a person's tab, for an administrator (a
  // sign_in_help holder's view has can.impersonate false, refusal "" and
  // impersonation null: nothing), the running line with Stop, else
  // "Sign in as <person>…" (mockup section 3) or why it can't be
  // offered. notice: 'burned' when this tab's own start link didn't
  // open the session (already used, or refused): "start again".
  // maxMinutes: the view's max_minutes (HUB_IMPERSONATION_MAX_MINUTES,
  // 1–30), else 30.
  function maxMinutes(view) {
    const n = (view && view.max_minutes) | 0;
    return n >= 1 && n <= 30 ? n : 30;
  }
  function impersonationHtml(view, ctx, notice) {
    if (ctx.mode !== 'person') return '';
    const can = ctx.can || {};
    const run = view.impersonation;
    let h = '';
    if (notice === 'burned' && run) {
      h += '<div class="pd-warn msi-imp-notice" data-msi-imp-notice role="alert">That start link was already used or didn\'t work, so you weren\'t signed in as ' + esc(ctx.user) + '. ' +
        button('secondary', ' data-msi-act="imp-again"', 'Start again') + '</div>';
    }
    if (run) {
      const line = run.admin + ' is signed in as ' + run.person + ' since ' + hhmmUTC(run.started) + ' · reason “' + run.reason + '” · ' +
        minLeft(run.until) + ' min left (until ' + hhmmUTC(run.until) + ')';
      return h + '<div class="msi-imp running" data-msi-imp-running><span data-msi-imp-line>' + esc(line) + '</span>' +
        button('danger', ' data-msi-act="imp-stop"', 'Stop') + '</div>';
    }
    if (can.impersonate) {
      return h + '<div class="msi-imp" data-msi-imp>' + button('danger', ' data-msi-act="imp-open"', 'Sign in as ' + ctx.user + '…') +
        '<span class="pd-muted pd-small">asks for your YubiKey now and a reason · ends after at most ' + maxMinutes(view) + ' min · your own session ends · ' + esc(ctx.user) + ' sees it in their history and at their next sign-in</span></div>';
    }
    if (view.impersonate_refusal) {
      return h + '<p class="pd-muted pd-small msi-imp-refusal" data-msi-imp-refusal>Signing in as ' + esc(ctx.user) + ' isn\'t possible: ' + esc(view.impersonate_refusal) + '</p>';
    }
    return h;
  }

  // ── the shown-once download dialog ─────────────────────────────────

  let shown = null; // {close()}
  function closeShown() { if (shown) shown.close(); }

  function el(tag, attrs, kids) {
    const e = document.createElement(tag);
    for (const k of Object.keys(attrs || {})) e.setAttribute(k, attrs[k]);
    for (const c of kids || []) e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    return e;
  }
  function b64Bytes(s) {
    const bin = atob(String(s || ''));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function safeFilename(s) {
    const n = String(s || '').replace(/[^A-Za-z0-9._-]/g, '');
    return n && !n.startsWith('.') ? n : 'browser-certificate.p12';
  }

  // openDownload shows a new browser certificate once (answer = the
  // create route's {p12, password, filename, certificate}): the download
  // button and the password side by side, Copy, and "I've saved both".
  // Each click on the button downloads from a Blob URL that is revoked
  // right after the click; closing the dialog (the button, Escape,
  // leaving the page) drops the bytes, the password and the node.
  function openDownload(answer) {
    closeShown();
    let secret = String(answer.password || '');
    let bytes = b64Bytes(answer.p12);
    let url = '';
    const filename = safeFilename(answer.filename);
    const title = 'Your new browser certificate';
    const link = el('a', { class: 'pd-btn primary sm', download: filename, 'data-msi-dl': '' }, ['Download ' + filename]);
    const code = el('code', { class: 'ma-pw', 'data-msi-pw': '' }, [secret]);
    const copy = el('button', { type: 'button', class: 'pd-btn secondary sm', 'data-msi-dlg': 'copy' }, ['Copy']);
    const status = el('div', { class: 'ma-status pd-muted', 'data-msi-dlg-status': '', role: 'status' });
    const done = el('button', { type: 'button', class: 'pd-btn primary sm', 'data-msi-dlg': 'done' }, ['I\'ve saved both']);
    const until = answer.certificate && answer.certificate.not_after ? ' It works until ' + fmtDay(answer.certificate.not_after) + '.' : '';
    const dlg = el('dialog', { class: 'pd-dialog ma-pw-dialog msi-dl-dialog', 'aria-label': title }, [
      el('div', { class: 'pd-dialog-headbar' }, [el('h3', { class: 'pd-dialog-title' }, [title])]),
      el('div', { class: 'pd-dialog-body' }, [
        el('div', { class: 'ma-pw-row msi-dl-row' }, [link]),
        el('div', { class: 'ma-pw-row msi-dl-row' }, [el('span', { class: 'pd-muted' }, ['Its password']), code, copy]),
        el('p', { class: 'ma-pw-note' }, [el('strong', {}, ['This password is shown only now.']),
          ' Your browser or computer asks for it when you open the file to install the certificate. The file can\'t be downloaded again later: if you lose it, revoke this certificate and create a new one.' + until]),
        status,
        el('div', { class: 'ma-pw-actions' }, [done])
      ])
    ]);
    const arm = () => {
      if (!bytes) return;
      url = URL.createObjectURL(new Blob([bytes], { type: 'application/x-pkcs12' }));
      link.setAttribute('href', url);
    };
    const disarm = () => {
      if (url) URL.revokeObjectURL(url);
      url = '';
      link.removeAttribute('href');
    };
    arm();
    link.addEventListener('click', () => {
      // The browser has taken the URL for this download: revoke it right
      // after the click, and arm a new one should it be needed again.
      setTimeout(() => {
        disarm();
        arm();
        status.textContent = 'Downloaded ' + filename + ': install it, then keep the password with it.';
      }, 0);
    });
    copy.addEventListener('click', () => {
      if (!secret || !navigator.clipboard) { status.textContent = 'Copy isn\'t available here: select the password and copy it.'; return; }
      navigator.clipboard.writeText(secret).then(
        () => { status.textContent = 'Password copied.'; },
        () => { status.textContent = 'Copy failed: select the password and copy it.'; });
    });
    const clear = () => {
      secret = null;
      code.textContent = '';
      if (bytes) bytes.fill(0);
      bytes = null;
      disarm();
      dlg.remove();
      if (shown === me) shown = null;
    };
    const me = { close: () => { if (dlg.open) dlg.close(); clear(); } };
    done.addEventListener('click', () => me.close());
    // Escape (the dialog's cancel) never closes it silently: the password
    // can't be shown again.
    dlg.addEventListener('cancel', e => {
      e.preventDefault();
      if (confirm('The password won\'t be shown again — close?')) me.close();
    });
    dlg.addEventListener('close', clear);
    shown = me;
    document.body.appendChild(dlg);
    dlg.showModal();
    return me;
  }

  // ── the issued / renewed YubiKey certificate ───────────────────────

  // pemPanel shows a certificate PEM (not a secret) with a download and
  // the import command.
  function pemPanelHtml(res, who) {
    return '<div class="msi-form msi-done"><p><b>' + esc(who) + '</b> serial <span class="pd-mono">' + esc(res.serial) + '</span>, until ' + esc(fmtDay(res.not_after)) + '.</p>' +
      '<label class="pd-small">Certificate (PEM): save as <code>/tmp/client.crt</code></label>' +
      '<textarea class="pd-input msi-pem" readonly rows="8" data-msi-pem></textarea>' +
      '<div class="pd-actions">' + button('secondary', ' data-msi-act="pem-download"', 'Download client.crt') + button('secondary', ' data-msi-act="panel-close"', 'Close') + '</div>' +
      '<p class="pd-small">Then import it into the YubiKey:</p><pre class="msi-cmd">ykman piv certificates import 9a /tmp/client.crt</pre></div>';
  }

  // ── mounting ───────────────────────────────────────────────────────

  const states = new WeakMap();

  async function call(method, url, body) {
    const opts = { method, credentials: 'same-origin', cache: 'no-store', headers: {} };
    if (method !== 'GET') opts.headers['Content-Type'] = 'application/json';
    if (body !== undefined) opts.body = JSON.stringify(body);
    const res = await fetch(url, opts);
    const text = await res.text();
    if (!res.ok) {
      let msg = text.trim();
      try { const j = JSON.parse(text); if (j && typeof j.error === 'string') msg = j.error; } catch (_) { /* plain text */ }
      const err = new Error(msg || ('HTTP ' + res.status));
      err.status = res.status;
      throw err;
    }
    return text ? JSON.parse(text) : null;
  }

  function base(st) {
    return st.opts.mode === 'person' ? '/api/directory/users/' + enc(st.opts.user) : '/api/me/signin';
  }
  function viewURL(st) { return st.opts.mode === 'person' ? base(st) + '/signin' : base(st); }
  function historyURL(st, before) {
    return viewURL(st) + '/history?limit=' + HISTORY_PAGE + (before ? '&before=' + enc(before) : '');
  }
  function revokeURL(st, serial) {
    return st.opts.mode === 'person' ? base(st) + '/certificates/' + enc(serial) : '/api/me/signin/certificates/' + enc(serial);
  }
  function ctxOf(st) {
    return st.opts.mode === 'person'
      ? { mode: 'person', user: st.opts.user, can: (st.view && st.view.can) || {}, passwordHint: st.opts.passwordHint || '' }
      : { mode: 'self', user: st.view && st.view.user };
  }

  function setStatus(st, text, warn) {
    const s = st.el.querySelector('[data-msi-status]');
    if (!s) return;
    s.textContent = text || '';
    s.classList.toggle('pd-warn', !!warn);
  }
  function panel(st, id) { return st.el.querySelector('[data-msi-panel="' + id + '"]'); }
  function panelStatus(p, text, warn, spin) {
    const s = p && p.querySelector('[data-msi-pstatus]');
    if (!s) return;
    s.innerHTML = (spin ? '<span class="ma-spin" aria-hidden="true"></span> ' : '') + esc(text);
    s.classList.toggle('pd-warn', !!warn);
  }
  function panelBusy(p, on) { if (p) p.querySelectorAll('button, input, textarea').forEach(b => { b.disabled = on; }); }
  const STATUS_SLOT = '<div class="ma-status pd-muted" data-msi-pstatus role="status"></div>';

  function draw(st) {
    const v = st.view;
    const self = st.opts.mode === 'self';
    let h = '<div class="msi-status" data-msi-status role="status"></div>';
    if (v.limits && v.limits.warning && !self) h += '<p class="pd-warn">' + esc(v.limits.warning) + '</p>';
    h += methodsHtml(v, ctxOf(st));
    h += impersonationHtml(v, ctxOf(st), st.impNotice);
    h += appsHtml(v);
    h += '<div class="pd-head msi-hist-head"><h3 class="pd-h3">Sign-in history</h3>' + button('ghost xs', ' data-msi-act="hist-reload"', 'Refresh') + '</div>' +
      '<div data-msi-hist><p class="pd-muted">Loading…</p></div>';
    st.el.innerHTML = h;
  }
  function drawHistory(st) {
    const box = st.el.querySelector('[data-msi-hist]');
    if (!box) return;
    const hi = st.hist;
    if (hi.error) { box.innerHTML = '<p class="pd-warn">Couldn\'t load the history: ' + esc(hi.error) + '</p>'; return; }
    box.innerHTML = unknownHtml(hi.unknown) + historyHtml(hi.entries) +
      (hi.next ? '<div class="pd-actions">' + button('secondary', ' data-msi-act="hist-more"', 'Show older') + '</div>' : '');
  }

  // loadHistory reads the first page, or (more) the page before the
  // cursor: one request at a time, so a cursor is never fetched twice
  // (Show older is disabled while it runs).
  async function loadHistory(st, more, btn) {
    if (st.histBusy) return;
    if (more && !st.hist.next) return;
    const seq = st.seq;
    st.histBusy = true;
    if (btn) btn.disabled = true;
    let page;
    try {
      page = await call('GET', historyURL(st, more ? st.hist.next : ''));
    } catch (err) {
      st.histBusy = false;
      if (btn) btn.disabled = false;
      if (seq !== st.seq) return;
      if (more) { setStatus(st, 'Couldn\'t load older entries: ' + err.message, true); return; }
      st.hist = { entries: [], next: '', unknown: [], error: err.message };
      drawHistory(st);
      return;
    }
    st.histBusy = false;
    if (seq !== st.seq) return;
    const unknown = new Set(more ? st.hist.unknown : []);
    for (const u of page.unknown || []) unknown.add(u);
    st.hist = {
      entries: (more ? st.hist.entries : []).concat(page.entries || []),
      next: typeof page.next === 'string' ? page.next : '',
      unknown: Array.from(unknown)
    };
    drawHistory(st);
  }

  // load (re)reads the view and the first history page. A reload drops a
  // fresh sign-in in progress (never the open download dialog: it is
  // closed only by its own buttons or by leaving the page).
  async function load(st) {
    const seq = ++st.seq;
    if (st.flow && window.PortcullisFreshAuth) window.PortcullisFreshAuth.cancel();
    if (!st.view) st.el.innerHTML = '<p class="pd-muted">Loading…</p>';
    let v;
    try {
      v = await call('GET', viewURL(st));
    } catch (err) {
      if (seq !== st.seq) return;
      st.view = null;
      if (st.opts.onError) st.opts.onError(err);
      st.el.innerHTML = st.opts.mode === 'person' && err.status === 403
        ? '<p class="pd-muted">You can\'t help with ' + esc(st.opts.user) + '\'s sign-in.</p>'
        : '<p class="pd-warn">Couldn\'t load the sign-in methods: ' + esc(err.message) + '</p>';
      return;
    }
    if (seq !== st.seq) return;
    st.view = v;
    st.impNotice = impNoticeOf(st, v);
    draw(st);
    if (st.opts.onView) st.opts.onView(v);
    loadHistory(st, false);
  }

  // fresh runs a fresh sign-in for an action of panel p (called from the
  // click: the popup opens before any await).
  function fresh(st, p, what, proof) {
    if (!window.PortcullisFreshAuth) { panelStatus(p, 'A fresh sign-in isn\'t available on this page.', true); return; }
    const f = {};
    st.flow = f;
    window.PortcullisFreshAuth.start(st.view.fresh_auth, {
      ctx: { signin: what, user: st.opts.mode === 'person' ? st.opts.user : '' },
      status: (t, warn, spin) => panelStatus(p, t, warn, spin),
      busy: on => panelBusy(p, on),
      end: () => { if (st.flow === f) st.flow = null; },
      proof: pr => proof(pr),
    });
  }

  function openPasswordForm(st) {
    const p = panel(st, 'password');
    p.innerHTML = '<div class="msi-form"><label class="pd-small" for="msi-pw1">New password (12–128 characters)</label>' +
      '<input class="pd-input" type="password" id="msi-pw1" autocomplete="new-password" data-msi-pw1>' +
      '<label class="pd-small" for="msi-pw2">Again</label><input class="pd-input" type="password" id="msi-pw2" autocomplete="new-password" data-msi-pw2>' +
      '<p class="pd-muted pd-small">You sign in again in a small window to confirm it\'s you. Changing it signs you out everywhere.</p>' +
      '<div class="pd-actions">' + button('primary', ' data-msi-act="pw-go"', 'Save password') + button('secondary', ' data-msi-act="panel-close"', 'Cancel') + '</div>' + STATUS_SLOT + '</div>';
    p.querySelector('[data-msi-pw1]').focus();
  }
  function passwordGo(st) {
    const p = panel(st, 'password');
    const a = p.querySelector('[data-msi-pw1]'), b = p.querySelector('[data-msi-pw2]');
    let pw = a.value;
    if (pw.length < 12 || pw.length > 128) { panelStatus(p, 'The password must be 12 to 128 characters.', true); return; }
    if (pw !== b.value) { panelStatus(p, 'The two passwords differ.', true); return; }
    fresh(st, p, 'password', async pr => {
      panelStatus(p, 'Saving…', false, true);
      try {
        await call('PUT', '/api/me/signin/password', { password: pw, code: pr.code, code_verifier: pr.code_verifier, nonce: pr.nonce });
      } catch (err) {
        pw = null;
        panelBusy(p, false);
        panelStatus(p, err.message, true);
        return;
      }
      pw = null;
      a.value = ''; b.value = '';
      await load(st);
      setStatus(st, 'Your password is saved. You are signed out of your other sessions.');
    });
  }

  async function removePassword(st) {
    if (!confirm('Remove your password? You then sign in with your other methods only. This signs you out everywhere.')) return;
    try {
      await call('DELETE', '/api/me/signin/password');
    } catch (err) { setStatus(st, err.message, true); return; }
    await load(st);
    setStatus(st, 'Your password is removed.');
  }

  function openCreateForm(st) {
    const p = panel(st, 'browser_cert');
    const max = ((st.view.limits || {}).effective || {}).browser_cert_days || 1;
    p.innerHTML = '<div class="msi-form"><label class="pd-small" for="msi-days">Valid for (days, 1 to ' + esc(max) + ')</label>' +
      '<input class="pd-input msi-days" type="number" id="msi-days" min="1" max="' + esc(max) + '" step="1" value="' + esc(max) + '" data-msi-days>' +
      '<p class="pd-muted pd-small">You sign in again in a small window with a passkey or your YubiKey to confirm it\'s you. Then you download the file and see its password once.</p>' +
      '<div class="pd-actions">' + button('primary', ' data-msi-act="bc-go"', 'Create and download') + button('secondary', ' data-msi-act="panel-close"', 'Cancel') + '</div>' + STATUS_SLOT + '</div>';
    p.querySelector('[data-msi-days]').focus();
  }
  function createGo(st) {
    const p = panel(st, 'browser_cert');
    const max = ((st.view.limits || {}).effective || {}).browser_cert_days || 1;
    const s = p.querySelector('[data-msi-days]').value.trim();
    const days = /^\d+$/.test(s) ? Number(s) : NaN;
    if (!(days >= 1 && days <= max)) { panelStatus(p, 'Pick 1 to ' + max + ' days.', true); return; }
    const bad = certFreshProblem(st.view, true);
    if (bad) { panelStatus(p, bad, true); return; }
    fresh(st, p, 'browser_cert', async pr => {
      panelStatus(p, 'Creating your certificate…', false, true);
      let ans;
      try {
        ans = await call('POST', '/api/me/signin/browser-certificates', { days, code: pr.code, code_verifier: pr.code_verifier, nonce: pr.nonce });
      } catch (err) {
        panelBusy(p, false);
        panelStatus(p, err.message, true);
        return;
      }
      await load(st);
      openDownload(ans);
      ans = null;
    });
  }

  async function revoke(st, serial, kind) {
    const who = st.opts.mode === 'person' ? st.opts.user + '\'s' : 'your';
    const what = kind === 'yubikey' ? 'YubiKey certificate' : 'browser certificate';
    if (!confirm('Revoke ' + who + ' ' + what + ' ' + serial + '? It stops working within a minute and can\'t be used again.')) return;
    try {
      await call('DELETE', revokeURL(st, serial));
    } catch (err) { setStatus(st, err.message, true); return; }
    await load(st);
    setStatus(st, 'Revoked ' + serial + '.');
  }

  // The CSR forms: renew (the caller's key, kept on the YubiKey) and
  // issue (an administrator, a new key generated on the person's YubiKey).
  function openCSRForm(st, issue) {
    const p = panel(st, 'yubikey_cert');
    const user = issue ? st.opts.user : st.view.user;
    const cmds = issue
      ? 'ykman piv keys generate --algorithm ECCP256 \\\n  --touch-policy CACHED 9a /tmp/pubkey.pem\nykman piv certificates request --subject "CN=' + user + '" \\\n  --hash-algorithm SHA256 9a /tmp/pubkey.pem /tmp/request.csr'
      : 'ykman piv keys export 9a /tmp/pubkey.pem\nykman piv certificates request --subject "CN=' + user + '" \\\n  --hash-algorithm SHA256 9a /tmp/pubkey.pem /tmp/request.csr';
    p.innerHTML = '<div class="msi-form"><p class="pd-small">' + (issue
      ? '1. On the computer with ' + esc(user) + '\'s YubiKey inserted, create a key and a request:'
      : '1. With your YubiKey inserted (the one you signed in with), create a request for its key:') + '</p>' +
      '<pre class="msi-cmd" data-msi-cmds></pre>' +
      '<label class="pd-small" for="msi-csr">2. Paste the request (/tmp/request.csr)</label>' +
      '<textarea class="pd-input msi-pem" id="msi-csr" rows="6" spellcheck="false" placeholder="-----BEGIN CERTIFICATE REQUEST-----" data-msi-csr></textarea>' +
      (issue ? '<p class="pd-muted pd-small">You sign in again in a small window to confirm it\'s you.</p>' : '') +
      '<div class="pd-actions">' + button('primary', ' data-msi-act="' + (issue ? 'yk-issue-go' : 'yk-renew-go') + '"', issue ? 'Issue certificate' : 'Renew certificate') +
      button('secondary', ' data-msi-act="panel-close"', 'Cancel') + '</div>' + STATUS_SLOT + '</div>';
    p.querySelector('[data-msi-cmds]').textContent = cmds;
    p.querySelector('[data-msi-csr]').focus();
  }
  function showPEM(st, p, res, who) {
    p.innerHTML = pemPanelHtml(res, who);
    p.querySelector('[data-msi-pem]').value = res.certificate || '';
  }
  async function renewGo(st) {
    const p = panel(st, 'yubikey_cert');
    const csr = p.querySelector('[data-msi-csr]').value.trim();
    if (!/-----BEGIN (NEW )?CERTIFICATE REQUEST-----/.test(csr)) { panelStatus(p, 'Paste the whole request, BEGIN and END lines included.', true); return; }
    panelBusy(p, true);
    panelStatus(p, 'Renewing…', false, true);
    let res;
    try {
      res = await call('POST', '/api/me/signin/yubikey-certificate/renew', { csr });
    } catch (err) { panelBusy(p, false); panelStatus(p, err.message, true); return; }
    await load(st);
    showPEM(st, panel(st, 'yubikey_cert'), res, 'Your new YubiKey certificate');
  }
  function issueGo(st) {
    const p = panel(st, 'yubikey_cert');
    const csr = p.querySelector('[data-msi-csr]').value.trim();
    if (!/-----BEGIN (NEW )?CERTIFICATE REQUEST-----/.test(csr)) { panelStatus(p, 'Paste the whole request, BEGIN and END lines included.', true); return; }
    const bad = certFreshProblem(st.view, false);
    if (bad) { panelStatus(p, bad, true); return; }
    fresh(st, p, 'yubikey_cert', async pr => {
      panelStatus(p, 'Issuing…', false, true);
      let res;
      try {
        res = await call('POST', base(st) + '/certificates', { csr, code: pr.code, code_verifier: pr.code_verifier, nonce: pr.nonce });
      } catch (err) { panelBusy(p, false); panelStatus(p, err.message, true); return; }
      await load(st);
      showPEM(st, panel(st, 'yubikey_cert'), res, st.opts.user + '\'s YubiKey certificate');
    });
  }
  function downloadPEM(p) {
    const t = p.querySelector('[data-msi-pem]');
    if (!t || !t.value) return;
    const url = URL.createObjectURL(new Blob([t.value], { type: 'application/x-pem-file' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = 'client.crt';
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 0);
  }

  // ── signing in as someone else (sign-in part 3) ────────────────────

  // The start this tab sent the top window to ({user, id}, session
  // storage: no secret, the id is not a bearer, D38). Coming back to the
  // tab while that impersonation is still listed as running means the
  // start link didn't open the session (opened twice, after 120 s, or
  // refused): the tab says so and offers Start again (Task 2 review M5).
  const IMP_KEY = 'portcullis-imp-start';
  function impStored() {
    try { const j = JSON.parse(sessionStorage.getItem(IMP_KEY) || 'null'); return j && typeof j === 'object' ? j : null; } catch (_) { return null; }
  }
  function impForget() { try { sessionStorage.removeItem(IMP_KEY); } catch (_) { /* nothing kept */ } }
  function impNoticeOf(st, v) {
    if (st.opts.mode !== 'person') return '';
    const s = impStored();
    if (!s || s.user !== st.opts.user) return '';
    if (v.impersonation && v.impersonation.id === s.id) return 'burned';
    impForget();
    return '';
  }

  // nextURL: the start URL the Hub answered (https only, http only on a
  // plain-http page: the harness).
  function nextURL(u) {
    u = String(u || '');
    if (/^https:\/\//i.test(u)) return u;
    if (/^http:\/\//i.test(u) && typeof location !== 'undefined' && location.protocol === 'http:') return u;
    return '';
  }

  let impDialog = null; // {close()}
  // openImpersonate: the dialog (the reason, then Continue: the fresh
  // YubiKey touch in the popup, the start, location.assign(next)).
  function openImpersonate(st) {
    if (impDialog) impDialog.close();
    const user = st.opts.user;
    const title = 'Sign in as ' + user;
    const input = el('input', { type: 'text', class: 'pd-input msi-imp-reason', id: 'msi-imp-reason', maxlength: '200', autocomplete: 'off', spellcheck: 'false', 'data-msi-imp-reason': '' });
    const go = el('button', { type: 'button', class: 'pd-btn primary sm', 'data-msi-imp': 'go' }, ['Continue with your YubiKey']);
    const cancel = el('button', { type: 'button', class: 'pd-btn secondary sm', 'data-msi-imp': 'cancel' }, ['Cancel']);
    const status = el('div', { class: 'ma-status pd-muted', 'data-msi-imp-status': '', role: 'status' });
    const dlg = el('dialog', { class: 'pd-dialog msi-imp-dialog', 'aria-label': title }, [
      el('div', { class: 'pd-dialog-headbar' }, [el('h3', { class: 'pd-dialog-title' }, [title])]),
      el('div', { class: 'pd-dialog-body' }, [
        el('p', { class: 'pd-small' }, ['You open ' + user + '\'s apps as them for at most ' + maxMinutes(st.view) + ' minutes. Your own session in this browser ends; after Stop you sign in again as yourself. ' +
          user + ' reads your reason in their history and at their next sign-in.']),
        el('label', { class: 'pd-small', for: 'msi-imp-reason' }, ['Reason (3–200 characters, one line)']),
        input,
        el('p', { class: 'pd-muted pd-small' }, ['Then sign in again in a small window with a YubiKey touch (a security key or a YubiKey certificate).']),
        el('div', { class: 'pd-actions' }, [go, cancel]),
        status
      ])
    ]);
    go.disabled = true;
    let busy = false, flow = false;
    const setStatus = (t, warn) => { status.textContent = t || ''; status.classList && status.classList.toggle('pd-warn', !!warn); };
    const check = () => { go.disabled = busy || !!reasonProblem(input.value); };
    const close = () => {
      if (flow && !st.impStarted && window.PortcullisFreshAuth) window.PortcullisFreshAuth.cancel();
      flow = false;
      if (dlg.open) dlg.close();
      dlg.remove();
      if (impDialog === me) impDialog = null;
    };
    const me = { close, dlg };
    const start = () => {
      const reason = input.value.trim();
      const bad = reasonProblem(reason);
      if (bad) { setStatus(bad, true); return; }
      if (!window.PortcullisFreshAuth) { setStatus('A fresh sign-in isn\'t available on this page.', true); return; }
      flow = true;
      // The popup opens from this click, before any await.
      window.PortcullisFreshAuth.start(st.view.fresh_auth, {
        ctx: { signin: 'impersonate', user },
        status: (t, warn) => setStatus(t, warn),
        busy: on => { busy = on; input.disabled = on; check(); },
        end: () => { flow = false; },
        proof: async pr => {
          setStatus('Starting…');
          let ans;
          try {
            ans = await call('POST', base(st) + '/impersonation', { reason, code: pr.code, code_verifier: pr.code_verifier, nonce: pr.nonce });
          } catch (err) {
            busy = false; input.disabled = false; check();
            setStatus(err.message, true);
            return;
          }
          const next = nextURL(ans && ans.next);
          if (!next) {
            busy = false; input.disabled = false; check();
            setStatus('The Hub answered no start link: try again.', true);
            return;
          }
          try { sessionStorage.setItem(IMP_KEY, JSON.stringify({ user, id: String(ans.id || '') })); } catch (_) { /* no notice then */ }
          st.impStarted = true;
          setStatus('Opening ' + user + '\'s portal…');
          location.assign(next);
        }
      });
    };
    dlg.addEventListener('input', e => { if (e.target === input) { setStatus(''); check(); } });
    dlg.addEventListener('keydown', e => {
      if (e.key === 'Enter' && e.target === input) { e.preventDefault(); if (!go.disabled) start(); }
    });
    dlg.addEventListener('click', e => {
      const b = e.target && e.target.closest ? e.target.closest('[data-msi-imp]') : null;
      if (!b || b.disabled) return;
      if (b.getAttribute('data-msi-imp') === 'go') start();
      else if (b.getAttribute('data-msi-imp') === 'cancel') close();
    });
    // Escape (the dialog's cancel) closes it like Cancel: the popup goes too.
    dlg.addEventListener('close', close);
    impDialog = me;
    document.body.appendChild(dlg);
    dlg.showModal();
    if (input.focus) input.focus();
    return me;
  }

  // stopImpersonation: an administrator's Stop of the person's running
  // impersonation (theirs or another administrator's).
  async function stopImpersonation(st, again) {
    const run = st.view && st.view.impersonation;
    if (!run) return;
    if (!again && !confirm('Stop ' + run.admin + ' signing in as ' + run.person + '? Their session as ' + run.person + ' ends at once.')) return;
    try {
      await call('POST', base(st) + '/impersonation/stop', {});
    } catch (err) {
      if (err.status !== 404) { setStatus(st, err.message, true); return; }
    }
    impForget();
    st.impNotice = '';
    await load(st);
    if (again) {
      if (st.view && st.view.can && st.view.can.impersonate) openImpersonate(st);
      else setStatus(st, st.view && st.view.impersonate_refusal ? 'Signing in as ' + st.opts.user + ' isn\'t possible: ' + st.view.impersonate_refusal : '', true);
    } else {
      setStatus(st, 'Stopped.');
    }
  }

  function onClick(st, e) {
    const b = e.target.closest('[data-msi-act]');
    if (!b || !st.el.contains(b) || b.disabled || !st.view) return;
    const p = b.closest('[data-msi-panel]');
    switch (b.dataset.msiAct) {
      case 'pw-change': return openPasswordForm(st);
      case 'pw-go': return passwordGo(st);
      case 'pw-remove': return removePassword(st);
      case 'bc-create': return openCreateForm(st);
      case 'bc-go': return createGo(st);
      case 'revoke': return revoke(st, b.dataset.serial, b.dataset.kind);
      case 'yk-renew': return openCSRForm(st, false);
      case 'yk-renew-go': return renewGo(st);
      case 'yk-issue': return openCSRForm(st, true);
      case 'yk-issue-go': return issueGo(st);
      case 'pem-download': return downloadPEM(p);
      case 'panel-close':
        if (st.flow && window.PortcullisFreshAuth) window.PortcullisFreshAuth.cancel();
        if (p) p.innerHTML = '';
        return;
      case 'hist-more': return loadHistory(st, true, b);
      case 'hist-reload': return loadHistory(st, false, b);
      case 'imp-open': return openImpersonate(st);
      case 'imp-stop': return stopImpersonation(st, false);
      case 'imp-again': return stopImpersonation(st, true);
    }
  }

  // mount draws the page (or a person's tab) into el and loads it.
  function mount(el, opts) {
    let st = states.get(el);
    if (!st) {
      st = { el, opts: opts || { mode: 'self' }, view: null, seq: 0, hist: { entries: [], next: '', unknown: [] }, flow: null, impNotice: '', impStarted: false };
      states.set(el, st);
      mounted.add(st);
      el.addEventListener('click', e => onClick(st, e));
      el.addEventListener('keydown', e => {
        if (e.key !== 'Enter' || !e.target.matches) return;
        if (e.target.matches('[data-msi-pw1], [data-msi-pw2]')) { e.preventDefault(); passwordGo(st); }
        else if (e.target.matches('[data-msi-days]')) { e.preventDefault(); createGo(st); }
      });
    } else {
      st.opts = opts || st.opts;
    }
    return load(st);
  }

  // Leaving the page drops the shown-once dialog (freshauth.js ends its
  // flow itself).
  window.addEventListener('pagehide', closeShown);
  // Back from the start link (the page restored as it was left): read
  // the tab again, so a start link that didn't open the session says so.
  const mounted = new Set();
  window.addEventListener('pageshow', e => {
    if (!e || !e.persisted) return;
    if (impDialog) impDialog.close();
    for (const st of mounted) if (st.impStarted) { st.impStarted = false; load(st); }
  });

  window.PortcullisMySignIn = { mount, methodsHtml, appsHtml, historyHtml, unknownHtml, openDownload, whatText, certFreshProblem, impersonationHtml, reasonProblem,
    // For the node tests: one mount's history paging over a stub fetch.
    _test: { loadHistory, state: (el, opts) => ({ el, opts, view: {}, seq: 0, hist: { entries: [], next: '', unknown: [] }, flow: null }) } };
})();
