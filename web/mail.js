// Portcullis Hub — Settings → Mail (contract §19.9). Hub listener only,
// administrators only.
//
//   window.PortcullisMail.render(root)   Settings → Mail into root
//   window.PortcullisMail.settingsHtml(view, status)   (pure; node tests)
//
// GET  /api/mail/settings                 the settings (+ read-only facts)
// PUT  /api/mail/settings                 {primary_domain, spam, limits, quotas}
// PUT  /api/mail/domains/{name}           {enabled, groups}
// GET  /api/mail/status                   {mail, reachable, status, domains}
//
// Rules: every value goes through esc; listeners on root only. Turning
// mail off for a domain warns first (the MX goes after the MTA-STS
// max_age, up to 7 days; mail sent meanwhile is still received).
(function () {
  'use strict';

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
  const enc = encodeURIComponent;
  const GiB = 1024 * 1024 * 1024;
  const OFF_TEXT = 'Mail is off: run ./portcullis mail enable on the host';
  const KUBE_TEXT = 'Mail isn\'t available on Kubernetes yet (Docker or rootless Podman only)';
  const DRAIN_WARNING = 'Turning mail off removes the MX after the MTA-STS max_age (up to 7 days); mail sent meanwhile is still received.';

  function pill(cls, t) { return '<span class="pill ' + cls + '">' + esc(t) + '</span>'; }
  function stateOf(s) { return s === 'on' ? pill('ok', 'on') : s === 'draining' ? pill('warn', 'draining') : pill('', 'off'); }

  // stateHtml is the slot's state (spec §8): closed; open with nothing
  // wired (the installed mail instances, a Marketplace link); wired (the
  // provider's row, Switch…, Unwire…, the void). Provider text (label,
  // version, the void's error) is filled by fillState with textContent.
  // insts: the installed instances of mail templates [{id, label}].
  function stateHtml(v, status, insts) {
    if (v.mail !== 'on') return '<div class="inst-section" data-mail-state="closed"><p class="settings-empty" data-mail-off>' + esc(OFF_TEXT) + '</p></div>';
    const p = status && status.provider;
    if (!p) {
      const list = (insts || []).map(i => '<li><a href="#apps/' + enc(i.id) + '/mail">' + esc(i.label || i.id) + '</a></li>').join('');
      return '<div class="inst-section" data-mail-state="none"><h4>No mail server is wired</h4>' +
        (list ? '<p>Installed mail servers (open one\'s Mail tab to wire it):</p><ul data-mail-instances>' + list + '</ul>' : '<p>No mail server app is installed.</p>') +
        '<p><a href="#marketplace?filter=mail" data-mail-marketplace>Find a mail server in the Marketplace</a></p></div>';
    }
    return '<div class="inst-section" data-mail-state="wired"><div class="inst-row">' +
      '<strong data-mail-label></strong> <span data-mail-version></span> · <a href="#apps/' + enc(p.instance) + '/mail" data-mail-instance>' + esc(p.instance) + '</a> ' +
      '<span class="pill" data-mail-mode></span> ' +
      '<button type="button" class="btn btn-sm" data-mail-act="switch" data-mail-from="' + esc(p.instance) + '">Switch…</button> ' +
      '<button type="button" class="btn btn-sm btn-danger" data-mail-act="unwire" data-mail-from="' + esc(p.instance) + '">Unwire…</button></div>' +
      (p.void ? '<div class="public-warn" data-mail-void><span data-mail-void-text></span> <button type="button" class="btn btn-sm" data-mail-act="retry-void">Retry</button></div>' : '') +
      (p.admin_view && window.PortcullisMailProvider ? window.PortcullisMailProvider.adminViewHtml(p.label || p.template) : '') +
      '</div>';
  }

  // fillState sets the wired provider's texts with textContent.
  function fillState(root, status) {
    const p = status && status.provider;
    if (!p) return;
    const set = (sel, t) => { const el = root.querySelector(sel); if (el) el.textContent = t; };
    set('[data-mail-label]', p.label || p.template);
    set('[data-mail-version]', p.version || '');
    set('[data-mail-mode]', p.held ? p.mode + ' · held' : p.mode);
    if (p.void) set('[data-mail-void-text]', 'A void of every mail password is owed (' + p.void.reason + ')' + (p.void.error ? ': ' + p.void.error : '') + '.');
  }

  // settingsHtml is the panel for GET /api/mail/settings (view), GET
  // /api/mail/status (status, may be null) and the installed mail
  // instances (insts).
  function settingsHtml(v, status, insts) {
    if (v.kubernetes) return '<p class="settings-empty" data-mail-kube>' + esc(KUBE_TEXT) + '</p>';
    let h = stateHtml(v, status, insts);
    if (v.problem) h += '<div class="public-warn" data-mail-problem>' + esc(v.problem) + '. <strong>Retry</strong> voids every mail password and writes a fresh secret for the wired provider (or unwire it and wire it again). ' +
      '<button type="button" class="btn btn-sm" data-mail-act="retry-void">Retry</button></div>';
    const pr = v.pending_removal;
    if (pr) {
      const accts = pr.accounts || [];
      const who = accts.map(a => esc(a.username) + ' (' + (a.revoked ? 'mail passwords revoked' : 'revoking failed: retrying') + ')');
      h += '<div class="public-warn" data-mail-pending>Removing ' + esc(accts.length) + ' mailboxes at once waits for your confirmation: ' + who.join(', ') +
        '. Their mailboxes stay until you confirm. If they shouldn\'t have left mail_users, add them back instead.' +
        (pr.confirmed ? ' <strong>Confirmed: the removal goes with the next update.</strong>'
          : ' <span data-mail-removal>Type <code>' + esc(pr.confirm_phrase) + '</code> to confirm (then a fresh sign-in): ' +
            '<input type="text" class="form-control form-control-sm" data-mail-removal-phrase autocomplete="off" aria-label="Confirmation phrase" placeholder="' + esc(pr.confirm_phrase) + '"> ' +
            '<button type="button" class="btn btn-sm btn-danger" data-mail-act="confirm-removal" data-mail-phrase="' + esc(pr.confirm_phrase) + '" data-mail-uuids="' + esc((pr.accounts || []).map(a => a.uuid).join(',')) + '">Remove the mailboxes</button></span>') + '</div>';
    }
    const reach = status && status.mail === 'on' ? (status.reachable ? pill('ok', 'reachable') : pill('warn', 'mail provider unreachable')) : '';
    h += '<dl class="inst-facts"><dt>Mail server</dt><dd><code>' + esc(v.hostname) + '</code> ' + reach + '</dd>' +
      '<dt>Relay</dt><dd data-mail-relay>' + (v.relay ? '<code>' + esc(v.relay.host) + ':' + esc(String(v.relay.port)) + '</code>' +
        (v.relay.username ? ' as <code>' + esc(v.relay.username) + '</code>' : '') + (v.relay.password_set ? ' (password set)' : '') : 'none (direct delivery)') + '</dd>' +
      '<dt>Submission</dt><dd>' + esc(v.submission_lan_only ? 'local networks only (MAIL_SUBMISSION_LAN_ONLY)' : 'from anywhere') +
        (v.submission_lan_only_refusal ? ' <small data-mail-lan-refusal>(LAN-only isn\'t possible here: ' + esc(v.submission_lan_only_refusal) + ')</small>' : '') + '</dd>' +
      '<dt>DKIM keys rotate every</dt><dd data-mail-dkim-rotate>' + esc(v.dkim_rotate) + '</dd>' +
      '<dt>Former accounts kept</dt><dd data-mail-former>' + esc(v.former_retention) + '</dd></dl>';
    h += formerHtml(status);
    h += sensitiveHtml(v);
    // Domains: on / off and groups.
    h += '<table class="inst-table" data-mail-domains><thead><tr><th>Domain</th><th>Mail</th><th>Groups (who gets an address there)</th><th></th></tr></thead><tbody>';
    for (const d of v.domains || []) {
      h += '<tr data-mail-domain="' + esc(d.name) + '"><td><code>' + esc(d.name) + '</code></td><td>' + stateOf(d.state) + '</td>' +
        '<td><input class="mail-groups" data-mail-groups value="' + esc((d.groups || []).join(', ')) + '" placeholder="every mailbox (main domain) / nobody (added domain)"></td>' +
        '<td>' + (d.enabled
          ? '<button type="button" class="btn btn-sm" data-mail-act="domain-save">Save groups</button> <button type="button" class="btn btn-sm btn-danger" data-mail-act="domain-off">Turn off</button>'
          : '<button type="button" class="btn btn-sm btn-primary" data-mail-act="domain-on">Turn on</button>') + '</td></tr>';
    }
    h += '</tbody></table><p class="settings-hint"><small>' + esc(DRAIN_WARNING) + '</small></p>';
    // Primary domain, spam, limits, quotas.
    const s = v.spam || {}, l = v.limits || {}, bl = s.dnsbl || {};
    const opts = (v.domains || []).filter(d => d.state === 'on').map(d => '<option value="' + esc(d.name) + '"' + (d.name === v.primary_domain ? ' selected' : '') + '>' + esc(d.name) + '</option>').join('');
    h += '<div class="inst-form" data-mail-settings>' +
      '<label class="block" for="mail-primary">Primary domain (every login and first address)</label><select id="mail-primary" data-mail-primary>' + opts + '</select>' +
      '<label class="block" for="mail-junk">Junk at score</label><input id="mail-junk" type="number" min="1" max="99" data-mail-junk value="' + esc(s.junk_score) + '">' +
      '<label class="block" for="mail-reject">Reject at score</label><input id="mail-reject" type="number" min="2" max="100" data-mail-reject value="' + esc(s.reject_score) + '">' +
      '<label class="block">Blocklists</label>' +
      ['spamhaus', 'spamcop', 'barracuda'].map(k => '<label><input type="checkbox" data-mail-dnsbl="' + k + '"' + (bl[k] ? ' checked' : '') + '> ' + k + '</label> ').join('') +
      '<label class="block" for="mail-allow">Always accept (domains or addresses, one per line)</label><textarea id="mail-allow" rows="3" data-mail-allow>' + esc((s.allow || []).join('\n')) + '</textarea>' +
      '<label class="block" for="mail-block">Always refuse (domains or addresses, one per line)</label><textarea id="mail-block" rows="3" data-mail-block>' + esc((s.block || []).join('\n')) + '</textarea>' +
      '<label class="block" for="mail-rph">Recipients per hour per person</label><input id="mail-rph" type="number" min="1" max="100000" data-mail-rph value="' + esc(l.recipients_per_hour) + '">' +
      '<label class="block" for="mail-rpd">Recipients per day per person</label><input id="mail-rpd" type="number" min="1" max="100000" data-mail-rpd value="' + esc(l.recipients_per_day) + '">' +
      '<label class="block" for="mail-quotas">Mailbox size per group (one per line: group = GiB; the largest row a person matches wins; default 10)</label>' +
      '<textarea id="mail-quotas" rows="3" data-mail-quotas>' + esc((v.quotas || []).map(q => q.group + ' = ' + (q.bytes / GiB)).join('\n')) + '</textarea>' +
      '<div class="inst-row"><button type="button" class="btn btn-primary btn-sm" data-mail-act="settings-save">Save</button></div><div data-mail-result></div></div>';
    return h;
  }

  // formerHtml lists the parked former accounts (GET /api/mail/status
  // status.former), read-only, with the export hint.
  function formerHtml(status) {
    const former = (status && status.status && status.status.former) || [];
    if (!former.length) return '<p class="settings-hint" data-mail-former-list><small>No former accounts.</small></p>';
    return '<div class="inst-section" data-mail-former-list><h4>Former accounts</h4><ul>' +
      former.map(f => '<li><code>' + esc(f.username) + '</code> <small>(id <code>' + esc(f.id) + '</code>, since ' + esc(String(f.since || '').slice(0, 10)) + ')</small></li>').join('') +
      '</ul><p class="settings-hint"><small>Export one with <code>./portcullis mail export &lt;id&gt;</code> on the host; they are deleted after the retention above.</small></p></div>';
  }

  // sensitiveHtml is the relay, DKIM rotation and former retention form:
  // saving it needs a fresh sign-in (the relay password is write-only).
  function sensitiveHtml(v) {
    const r = v.relay || {};
    return '<div class="inst-form" data-mail-sensitive><h4>Relay, DKIM rotation and former accounts</h4>' +
      '<label><input type="checkbox" data-mail-relay-none' + (v.relay ? '' : ' checked') + '> No relay (direct delivery)</label>' +
      '<label class="block" for="mail-relay-host">Relay host</label><input id="mail-relay-host" data-mail-relay-host value="' + esc(r.host || '') + '">' +
      '<label class="block" for="mail-relay-port">Relay port</label><input id="mail-relay-port" type="number" min="1" max="65535" data-mail-relay-port value="' + esc(r.port || 587) + '">' +
      '<label class="block" for="mail-relay-user">Relay user</label><input id="mail-relay-user" data-mail-relay-user value="' + esc(r.username || '') + '">' +
      '<label class="block" for="mail-relay-spf">SPF include (optional)</label><input id="mail-relay-spf" data-mail-relay-spf value="' + esc(r.spf_include || '') + '">' +
      '<label class="block" for="mail-relay-pw">Relay password</label><input id="mail-relay-pw" type="password" autocomplete="new-password" data-mail-relay-pw placeholder="' +
        esc(r.password_set ? 'unchanged (set)' : 'none') + '">' +
      '<label class="block" for="mail-dkim-rotate">DKIM keys rotate every (24h–8760h)</label><input id="mail-dkim-rotate" data-mail-dkim-rotate-in value="' + esc(v.dkim_rotate) + '">' +
      '<label class="block" for="mail-former-retention">Former accounts kept for (24h–8760h)</label><input id="mail-former-retention" data-mail-former-retention-in value="' + esc(v.former_retention) + '">' +
      '<div class="inst-row"><button type="button" class="btn btn-primary btn-sm" data-mail-act="sensitive-save">Save</button></div>' +
      '<p class="settings-hint"><small>A fresh sign-in with your security key follows. The password is never shown again; leave it empty to keep it.</small></p></div>';
  }

  // readSensitive reads that form (relay null for none; the password only
  // when typed).
  function readSensitive(f) {
    const out = {
      dkim_rotate: f.querySelector('[data-mail-dkim-rotate-in]').value.trim(),
      former_retention: f.querySelector('[data-mail-former-retention-in]').value.trim(),
    };
    if (f.querySelector('[data-mail-relay-none]').checked) {
      out.relay = null;
    } else {
      out.relay = {
        host: f.querySelector('[data-mail-relay-host]').value.trim(),
        port: parseInt(f.querySelector('[data-mail-relay-port]').value, 10),
        username: f.querySelector('[data-mail-relay-user]').value.trim(),
        spf_include: f.querySelector('[data-mail-relay-spf]').value.trim(),
      };
      const pw = f.querySelector('[data-mail-relay-pw]').value;
      if (pw) out.relay.password = pw;
    }
    return out;
  }

  function lines(t) { return String(t || '').split(/\n/).map(x => x.trim()).filter(Boolean); }

  // readSettings reads the form (NaN numbers stay: the Hub refuses them).
  function readSettings(f) {
    const quotas = [];
    for (const ln of lines(f.querySelector('[data-mail-quotas]').value)) {
      const [g, n] = ln.split('=').map(x => x.trim());
      quotas.push({ group: g, bytes: Math.round(Number(n) * GiB) });
    }
    const dnsbl = {};
    f.querySelectorAll('[data-mail-dnsbl]').forEach(c => { dnsbl[c.dataset.mailDnsbl] = c.checked; });
    return {
      primary_domain: f.querySelector('[data-mail-primary]').value,
      spam: {
        reject_score: parseInt(f.querySelector('[data-mail-reject]').value, 10), junk_score: parseInt(f.querySelector('[data-mail-junk]').value, 10),
        dnsbl, allow: lines(f.querySelector('[data-mail-allow]').value), block: lines(f.querySelector('[data-mail-block]').value)
      },
      limits: { recipients_per_hour: parseInt(f.querySelector('[data-mail-rph]').value, 10), recipients_per_day: parseInt(f.querySelector('[data-mail-rpd]').value, 10) },
      quotas
    };
  }

  async function render(root) {
    if (!root) return;
    let v, st = null;
    try {
      v = await window.apiGet('/api/mail/settings');
    } catch (e) { root.innerHTML = '<div class="public-warn">' + esc(e.message) + '</div>'; return; }
    try { st = await window.apiGet('/api/mail/status'); } catch (_) { st = null; }
    let insts = [];
    try {
      const [list, tpls] = await Promise.all([window.apiGet('/api/instances'), window.apiGet('/api/templates')]);
      const mailT = new Set((tpls || []).filter(t => t.mail_provider).map(t => t.id));
      insts = (list || []).filter(i => mailT.has(i.template)).map(i => ({ id: i.id, label: i.label }));
    } catch (_) { insts = []; }
    root.mailInsts = insts;
    root.mailView = v;
    root.innerHTML = settingsHtml(v, st, insts);
    fillState(root, st);
    if (!root.dataset.mailWired) {
      root.dataset.mailWired = '1';
      root.addEventListener('click', e => act(root, e));
    }
  }

  async function act(root, e) {
    if (e.target.closest && e.target.closest('[data-mail-admin-view-open]') && window.PortcullisMailProvider) {
      window.PortcullisMailProvider.openAdminView();
      return;
    }
    const b = e.target.closest && e.target.closest('[data-mail-act]');
    if (!b || !root.contains(b) || b.dataset.busy) return;
    const row = b.closest('[data-mail-domain]');
    const groups = row ? String(row.querySelector('[data-mail-groups]').value).split(',').map(x => x.trim()).filter(Boolean) : [];
    try {
      switch (b.dataset.mailAct) {
        case 'domain-on':
          b.dataset.busy = '1';
          await window.apiPut('/api/mail/domains/' + enc(row.dataset.mailDomain), { enabled: true, groups });
          window.showToast('Mail is on for ' + row.dataset.mailDomain + '.', 'success');
          break;
        case 'domain-save':
          b.dataset.busy = '1';
          await window.apiPut('/api/mail/domains/' + enc(row.dataset.mailDomain), { enabled: true, groups });
          window.showToast('Saved.', 'success');
          break;
        case 'domain-off':
          if (!confirm('Turn mail off for ' + row.dataset.mailDomain + '? ' + DRAIN_WARNING)) return;
          b.dataset.busy = '1';
          await window.apiPut('/api/mail/domains/' + enc(row.dataset.mailDomain), { enabled: false, groups });
          window.showToast('Mail for ' + row.dataset.mailDomain + ' is draining.', 'success');
          break;
        case 'confirm-removal': {
          // Destructive (Ruling R-CONFIRM-REMOVAL): the typed phrase, then
          // a fresh sign-in opened from the click (no await before it).
          const uuids = String(b.dataset.mailUuids || '').split(',').filter(Boolean);
          const want = b.dataset.mailPhrase || '';
          const typed = ((b.closest('[data-mail-removal]') || root).querySelector('[data-mail-removal-phrase]') || {}).value || '';
          if (typed.trim() !== want) { window.showToast('Type "' + want + '" to confirm.', 'error'); return; }
          const fa = root.mailView && root.mailView.fresh_auth;
          if (!fa || !window.PortcullisFreshAuth) { window.showToast('A fresh sign-in isn\'t available: try again in a moment.', 'error'); return; }
          window.PortcullisFreshAuth.start(fa, {
            ctx: { mail_confirm_removal: true },
            status: (t, warn) => { if (warn) window.showToast(t, 'error'); },
            busy: () => {},
            end: () => {},
            proof: async p => {
              try {
                await window.apiCall('/api/mail/confirm-removal', 'POST', { accounts: uuids, confirm: want, code: p.code, code_verifier: p.code_verifier, nonce: p.nonce });
                window.showToast('Confirmed: the mailboxes are removed with the next update.', 'success');
              } catch (err) { window.showToast(err.message || 'Confirming failed', 'error'); }
              render(root);
            },
          });
          return;
        }
        case 'switch':
          if (window.PortcullisMailProvider) window.PortcullisMailProvider.switchDialog(b.dataset.mailFrom, (root.mailInsts || []).map(i => i.id));
          return;
        case 'unwire':
          // Draining (the Mail tab offers stopping at once).
          b.dataset.busy = '1';
          await window.PortcullisMailProvider.unwire(b.dataset.mailFrom, true);
          break;
        case 'retry-void':
          b.dataset.busy = '1';
          await window.PortcullisMailProvider.retryVoid();
          break;
        case 'sensitive-save': {
          // The fresh sign-in opens from the click (no await before it).
          const fa = root.mailView && root.mailView.fresh_auth;
          if (!fa || !window.PortcullisFreshAuth) { window.showToast('A fresh sign-in isn\'t available: try again in a moment.', 'error'); return; }
          const main = root.querySelector('[data-mail-settings]');
          const body = Object.assign(readSettings(main), readSensitive(b.closest('[data-mail-sensitive]')));
          window.PortcullisFreshAuth.start(fa, {
            ctx: { mail_settings: true },
            status: (t, warn) => { if (warn) window.showToast(t, 'error'); },
            busy: () => {},
            end: () => {},
            proof: async p => {
              try {
                await window.apiPut('/api/mail/settings', Object.assign(body, { code: p.code, code_verifier: p.code_verifier, nonce: p.nonce }));
                window.showToast('Mail settings saved.', 'success');
              } catch (err) { window.showToast(err.message || 'Saving failed', 'error'); }
              render(root);
            },
          });
          return;
        }
        case 'settings-save': {
          const f = b.closest('[data-mail-settings]');
          b.dataset.busy = '1';
          await window.apiPut('/api/mail/settings', readSettings(f));
          window.showToast('Mail settings saved.', 'success');
          break;
        }
        default: return;
      }
    } catch (err) {
      delete b.dataset.busy;
      window.showToast(err.message || 'Saving failed', 'error');
      return;
    }
    render(root);
  }

  window.PortcullisMail = { render, settingsHtml, stateHtml, fillState, readSettings, readSensitive, sensitiveHtml, formerHtml, OFF_TEXT, DRAIN_WARNING };
})();
