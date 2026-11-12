// Portcullis Hub — Settings → Domains: the DNS panel (contract §12.3,
// DNS hardening Task 11). Hub listener only.
//
//   window.PortcullisDNS.mount(el, {name, main})
//       renders the DNS plan of an added domain (name), or with main:
//       true the main domain's read-only plan, into el
//
// GET  /api/domains/{name}/dns[?refresh=1]   an added domain's plan
// GET  /api/dns/main[?refresh=1]             the main domain's plan (can_write false)
// POST /api/domains/{name}/dns/apply         {"sets": ["<set>"]} → 202 (Fix)
// POST /api/domains/{name}/dnssec            {"enable": true} → 202 (signing, zone-wide)
//
// Rules: every value goes through escapeHtml (index.html); data-*
// attributes and listeners on the panel only. Fix appears only for items
// with fix: auto, signing only while the provider can sign and the zone
// is unsigned, both never for the main domain, whose fix is always the
// server command. There is no button to turn signing off.
(function () {
  'use strict';

  const esc = s => window.escapeHtml(s);
  const SEV_COLOR = { ok: '#4ade80', info: '#94a3b8', warning: '#fbbf24', problem: '#f87171' };
  const MAIN_FIX = 'Run <code>./portcullis dns setup</code> on the server';

  function planURL(opts, refresh) {
    const name = opts.name;
    const base = opts.main ? '/api/dns/main' : '/api/domains/' + encodeURIComponent(name) + '/dns';
    return base + (refresh ? '?refresh=1' : '');
  }

  function values(list) {
    if (!list || !list.length) return '<span style="color:#64748b">—</span>';
    return list.map(v => '<code style="word-break:break-all">' + esc(v) + '</code>').join('<br>');
  }

  function sev(s, text) {
    return '<span style="color:' + (SEV_COLOR[s] || '#94a3b8') + '">' + esc(text) + '</span>';
  }

  function itemRow(it, opts) {
    const key = it.set + ':' + it.name + ':' + it.type;
    let action = '';
    if (!opts.main && it.fix === 'auto') {
      action = '<button class="btn btn-sm" data-dns-fix="' + esc(it.set) + '">Fix</button>';
    } else if (opts.main && it.fix !== 'none' && it.status !== 'ok') {
      action = '<small>' + MAIN_FIX + '</small>';
    }
    const steps = (it.steps || []).length
      ? '<ul style="margin:0.25rem 0 0 1rem;padding:0;color:#94a3b8">' + it.steps.map(s => '<li>' + esc(s) + '</li>').join('') + '</ul>' : '';
    return '<tr data-dns-item="' + esc(key) + '" style="border-top:1px solid #334155;vertical-align:top">' +
      '<td>' + esc(it.set) + '</td><td><code>' + esc(it.name) + '</code></td><td>' + esc(it.type) + '</td>' +
      '<td>' + values(it.want) + '</td><td>' + values(it.live) + '</td>' +
      '<td>' + sev(it.severity, it.status) + steps + '</td><td style="white-space:nowrap">' + action + '</td></tr>';
  }

  function caaLine(c) {
    c = c || {};
    if (!c.issuer) return '<p data-dns-caa>CAA: skipped (unknown CA) · would issue: ' + (c.would_issue ? 'yes' : 'no') + '</p>';
    return '<p data-dns-caa>CAA: issuer <code>' + esc(c.issuer) + '</code>, ' +
      (c.account_uri ? 'account <code style="word-break:break-all">' + esc(c.account_uri) + '</code>' : 'CA-only') +
      ' · would issue: ' + sev(c.would_issue ? 'ok' : 'problem', c.would_issue ? 'yes' : 'no') + '</p>';
  }

  function dnssecBlock(d, opts) {
    d = d || {};
    const sevOf = { secure: 'ok', unsigned: 'info', ds_missing: 'warning', ds_mismatch: 'problem', bogus: 'problem', unknown: 'warning' };
    let html = '<div data-dns-dnssec><p>DNSSEC (zone <code>' + esc(d.zone || '—') + '</code>): ' + sev(sevOf[d.state] || 'info', d.state || 'not checked yet') + '</p>';
    const ds = d.ds || [];
    if (ds.length) {
      html += '<table style="border-collapse:collapse;font-size:0.8125rem;margin-bottom:0.5rem"><thead><tr style="text-align:left;color:#94a3b8">' +
        '<th>Key tag</th><th>Algorithm</th><th>Digest type</th><th>Digest</th><th></th></tr></thead><tbody>';
      ds.forEach((x, i) => {
        html += '<tr><td>' + esc(x.key_tag) + '</td><td>' + esc(x.algorithm) + '</td><td>' + esc(x.digest_type) + '</td>' +
          '<td><code style="word-break:break-all">' + esc(x.digest) + '</code></td>' +
          '<td><button class="btn btn-sm" data-dns-copy="' + i + '">Copy</button></td></tr>';
      });
      html += '</tbody></table>';
    }
    if ((d.steps || []).length) html += '<ul style="margin:0 0 0.5rem 1rem;padding:0">' + d.steps.map(s => '<li>' + esc(s) + '</li>').join('') + '</ul>';
    if (!opts.main && d.provider_can_sign && d.state === 'unsigned') {
      html += '<button class="btn btn-sm" data-dnssec-sign>Turn on DNSSEC signing</button>';
    } else if (opts.main && d.state && d.state !== 'secure') {
      html += '<p><small>' + MAIN_FIX + '</small></p>';
    }
    return html + '</div>';
  }

  function render(el, opts, plan) {
    const items = plan.items || [];
    let html = '<div class="dns-panel" style="padding:0.75rem 0">' +
      '<p style="color:#94a3b8;font-size:0.8125rem">DNS plan of <code>' + esc(plan.name || opts.name || '') + '</code>' +
      (plan.checked_at ? ', checked ' + esc(new Date(plan.checked_at).toLocaleString()) : '') +
      ' <button class="btn btn-sm" data-dns-refresh>Refresh</button></p>';
    if (opts.main) html += '<p><small>Read-only: the main domain\'s records are set on the server. ' + MAIN_FIX + '.</small></p>';
    if (items.length) {
      html += '<table style="width:100%;border-collapse:collapse;font-size:0.8125rem;margin-bottom:0.75rem"><thead><tr style="text-align:left;color:#94a3b8">' +
        '<th>Set</th><th>Name</th><th>Type</th><th>Wanted</th><th>Live</th><th>Status</th><th></th></tr></thead><tbody>' +
        items.map(it => itemRow(it, opts)).join('') + '</tbody></table>';
    } else {
      html += '<p class="settings-empty">No records in the plan.</p>';
    }
    html += caaLine(plan.caa) + dnssecBlock(plan.dnssec, opts) + '</div>';
    el.innerHTML = html;
    wire(el, opts, plan);
  }

  function wire(el, opts, plan) {
    const panel = el.querySelector('.dns-panel');
    if (!panel) return;
    panel.addEventListener('click', async e => {
      if (e.target.closest('[data-dns-refresh]')) { load(el, opts, true); return; }
      const copy = e.target.closest('[data-dns-copy]');
      if (copy) {
        const x = ((plan.dnssec || {}).ds || [])[Number(copy.dataset.dnsCopy)];
        if (!x) return;
        const line = x.key_tag + ' ' + x.algorithm + ' ' + x.digest_type + ' ' + x.digest;
        try { await navigator.clipboard.writeText(line); window.showToast('DS copied: ' + line, 'success'); }
        catch (err) { window.showToast('Copying failed: ' + (err.message || err), 'error'); }
        return;
      }
      if (opts.main) return;
      const fix = e.target.closest('[data-dns-fix]');
      if (fix) {
        const set = fix.dataset.dnsFix;
        if (fix.dataset.busy) return;
        fix.dataset.busy = '1';
        try {
          await window.apiCall('/api/domains/' + encodeURIComponent(opts.name) + '/dns/apply', 'POST', { sets: [set] });
          window.showToast('Writing the ' + set + ' records of ' + opts.name + '.', 'success');
          load(el, opts, true);
        } catch (err) { delete fix.dataset.busy; window.showToast(err.message || 'Applying failed', 'error'); }
        return;
      }
      const sign = e.target.closest('[data-dnssec-sign]');
      if (sign) {
        const zone = (plan.dnssec || {}).zone || opts.name;
        if (sign.dataset.busy || !confirm('Turns on signing for the whole zone ' + zone + '. Continue?')) return;
        sign.dataset.busy = '1';
        try {
          await window.apiCall('/api/domains/' + encodeURIComponent(opts.name) + '/dnssec', 'POST', { enable: true });
          window.showToast('Turning on DNSSEC signing for ' + zone + ': add the DS it shows at your registrar.', 'success');
          load(el, opts, true);
        } catch (err) { delete sign.dataset.busy; window.showToast(err.message || 'Turning on signing failed', 'error'); }
      }
    });
  }

  async function load(el, opts, refresh) {
    el.innerHTML = '<p class="settings-empty">Loading the DNS plan...</p>';
    try {
      const plan = await window.apiGet(planURL(opts, refresh));
      render(el, opts, plan || {});
    } catch (err) {
      el.innerHTML = '<div class="public-warn">' + esc(err.message || 'Loading the DNS plan failed') + '</div>';
    }
  }

  function mount(el, opts) {
    opts = { name: (opts && opts.name) || '', main: !!(opts && opts.main) };
    return load(el, opts, false);
  }

  window.PortcullisDNS = { mount };
})();
