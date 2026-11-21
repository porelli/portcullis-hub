// Portcullis Hub — Settings → High availability (contract §20.1 "The HA
// page"; D4, D5, D13). Hub listener only, administrators only,
// Kubernetes only (the section stays hidden elsewhere). Read-only: the
// checklist `./portcullis ha enable` needs all green, the live state
// (quorum, sites, N−1 per node, the front door and its worst-case texts,
// fencing, volumes) and the command. Turning HA on is CLI-only: there is
// no button and no enable route.
//
//   window.PortcullisHA.render(root)   load GET /api/ha and draw it
//   window.PortcullisHA.pageHtml(view) (pure; tests)
//   window.PortcullisHA.errorHtml(msg) (pure; tests: the answer failed)
//
// GET /api/ha  {experimental, enabled, checklist:[{id, ok, text}], guarantee,
//   nodes:[{name, role, class, site, ready, fencing, n_minus_1}],
//   quorum:{etcd, vault, sentinel}, sites:[{name, primary, nodes, servers,
//   gateway, ingress, rtt_ms}], dns:[{name, addresses, worst_case_text,
//   per_site:[{site, healthy, worst_case_text, ingress, addresses,
//   blind_probers}]}], credentials_note, command,
//   frontdoor:{state, error}, volumes:[{name, robustness, degraded_since}],
//   warnings:[...], known_gaps:[...]}
//
// Every value from the Hub is escaped (esc) before it goes into markup.
(function () {
  'use strict';

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
  function pill(cls, t) { return '<span class="pill ' + cls + '">' + esc(t) + '</span>'; }
  function code(t) { return '<code>' + esc(t) + '</code>'; }

  const BANNER = 'High availability is experimental';
  const ITEM_LABEL = {
    nodes: '3 or more nodes', servers: '3 or more servers', storage: 'Storage nodes', ingress: 'Ingress nodes',
    backup_destination: 'Offsite backup destination', n_minus_1: 'N−1 check', watchdog: 'Watchdogs (fencing)',
    site_gateway: 'A reachable node at every site', site_rtt: 'Servers within 100 ms of each other',
  };
  // N−1 levels: unknown (the check couldn't judge) is shown as red.
  const LEVEL = { green: ['ok', 'green'], yellow: ['warn', 'yellow'], red: ['bad', 'red'], unknown: ['bad', 'unknown'] };
  const ROBUST = { healthy: 'ok', degraded: 'warn', faulted: 'bad' };

  function checklistHtml(items) {
    return '<ul class="ha-checklist" data-ha-checklist>' + (items || []).map(it =>
      '<li data-ha-item="' + esc(it.id) + '" data-ok="' + (it.ok ? 'true' : 'false') + '">' +
        pill(it.ok ? 'ok' : 'bad', it.ok ? 'OK' : 'Not yet') + ' ' + esc(ITEM_LABEL[it.id] || it.id) +
        (it.ok ? '' : ': <span class="ha-why">' + esc(it.text) + '</span>') + '</li>').join('') + '</ul>';
  }

  function quorumHtml(q) {
    q = q || {};
    return '<div data-ha-quorum>' + [['etcd', 'etcd'], ['vault', 'Vault'], ['sentinel', 'Sentinel']].map(([k, label]) => {
      const v = q[k] || { voters: 0, healthy: 0 };
      // A majority of the voters healthy keeps the quorum.
      const ok = v.voters > 0 && v.healthy * 2 > v.voters;
      return pill(ok ? (v.healthy === v.voters ? 'ok' : 'warn') : 'bad', label + ' ' + v.healthy + '/' + v.voters);
    }).join('') + '</div>';
  }

  function nodesHtml(nodes) {
    if (!nodes || !nodes.length) return '<p class="settings-empty">No node listed.</p>';
    return '<table class="ha-table" data-ha-nodes><thead><tr><th>Node</th><th>Role</th><th>Class</th><th>Site</th><th>Ready</th><th>Fencing</th><th>If it fails (N−1)</th></tr></thead><tbody>' +
      nodes.map(n => {
        const lv = LEVEL[n.n_minus_1] ? n.n_minus_1 : 'unknown';
        return '<tr data-ha-node="' + esc(n.name) + '"><td>' + code(n.name) + '</td><td>' + esc(n.role) + '</td><td>' + esc(n.class) + '</td><td>' +
          (n.site ? esc(n.site) : '<span class="settings-empty">no record</span>') + '</td><td>' + pill(n.ready ? 'ok' : 'bad', n.ready ? 'Ready' : 'Not ready') +
          '</td><td>' + pill(n.fencing ? 'ok' : 'warn', n.fencing ? 'watchdog' : 'none') + '</td><td data-n1-level="' + lv + '">' +
          pill(LEVEL[lv][0], LEVEL[lv][1]) + '</td></tr>';
      }).join('') + '</tbody></table>';
  }

  function sitesHtml(sites) {
    if (!sites || !sites.length) return '';
    return '<table class="ha-table" data-ha-sites><thead><tr><th>Site</th><th>Nodes</th><th>Servers</th><th>Ingress</th><th>Mesh gateway</th><th>Worst round trip</th></tr></thead><tbody>' +
      sites.map(s => '<tr data-ha-site="' + esc(s.name) + '"><td>' + esc(s.name) + (s.primary ? ' ' + pill('info', 'primary') : '') + '</td><td>' +
        (s.nodes || []).map(code).join(' ') + '</td><td>' + (s.servers || []).map(code).join(' ') + '</td><td>' + (s.ingress || []).map(code).join(' ') +
        '</td><td>' + (s.gateway ? code(s.gateway) : pill('bad', 'none')) + '</td><td>' + (s.rtt_ms == null ? '—' : esc(s.rtt_ms) + ' ms') + '</td></tr>').join('') +
      '</tbody></table>';
  }

  function frontdoorHtml(v) {
    const fd = v.frontdoor || {};
    let h = '';
    if (fd.error) h += '<div class="public-warn" data-ha-frontdoor-error>' + esc(fd.error) + '</div>';
    else if (fd.state) h += '<p data-ha-frontdoor>Front door: ' + pill(fd.state === 'leading' ? 'ok' : 'warn', fd.state) + '</p>';
    if (!v.enabled) return h + '<p class="settings-empty">The front door runs once HA is on: it moves the main domain\'s addresses away from a failed ingress node.</p>';
    if (!(v.dns || []).length) return h;
    return h + '<ul class="policy-notes" data-ha-dns>' + v.dns.map(d =>
      '<li data-ha-name="' + esc(d.name) + '">' + code(d.name) + ' → ' + ((d.addresses || []).map(code).join(', ') || pill('bad', 'no address')) +
        ' — ' + esc(d.worst_case_text) + '<ul>' + (d.per_site || []).map(s =>
          '<li data-ha-dns-site="' + esc(s.site) + '">' + pill(s.healthy ? 'ok' : 'bad', s.site) + ' ' +
            ((s.addresses || []).length ? 'publishes ' + s.addresses.map(code).join(', ') : 'publishes nothing') +
            ' (' + (s.ingress || []).length + ' ingress node' + ((s.ingress || []).length === 1 ? '' : 's') +
            (s.blind_probers ? ', ' + pill('warn', s.blind_probers + ' blind prober' + (s.blind_probers === 1 ? '' : 's')) : '') + ') — ' +
            esc(s.worst_case_text) + '</li>').join('') +
        '</ul></li>').join('') + '</ul>';
  }

  function volumesHtml(vols) {
    if (!vols || !vols.length) return '';
    return '<ul class="policy-notes" data-ha-volumes>' + vols.map(x =>
      '<li>' + code(x.name) + ' ' + pill(ROBUST[x.robustness] || 'warn', x.robustness || 'unknown') +
        (x.degraded_since ? ' since ' + esc(x.degraded_since) : '') + '</li>').join('') + '</ul>';
  }

  function notesHtml(list, attr) {
    if (!list || !list.length) return '';
    return '<ul class="policy-notes" ' + attr + '>' + list.map(w => '<li>' + esc(w) + '</li>').join('') + '</ul>';
  }

  // bannerHtml: the EXPERIMENTAL banner (D13), drawn whatever happens.
  function bannerHtml() {
    return '<div class="public-warn" data-ha-banner><strong>' + esc(BANNER) + '.</strong> Try it on a test install first; leaving HA means a backup, a fresh <code>init</code> and a restore.</div>';
  }

  // errorHtml: the page when GET /api/ha itself fails: the banner, the
  // error and the command (the Hub degrades a nodeadm failure itself).
  function errorHtml(msg) {
    return bannerHtml() + '<div class="public-warn" data-ha-error>' + esc(msg) + '</div>' +
      '<p class="settings-empty">HA is turned on from the server\'s command line: <code>./portcullis ha enable</code>.</p>';
  }

  // pageHtml: the page for view v.
  function pageHtml(v) {
    const allOK = (v.checklist || []).length > 0 && v.checklist.every(it => it.ok);
    let h = bannerHtml();
    h += '<p data-ha-enabled>' + (v.enabled ? pill('ok', 'HA is on') : pill('info', 'HA is off')) + ' ' +
      pill(v.guarantee === 'Zero loss on one failure' ? 'ok' : 'warn', v.guarantee) + '</p>';
    h += '<h4>Checklist</h4>' + checklistHtml(v.checklist);
    if (!v.enabled) {
      h += '<p data-ha-command>' + (allOK ? 'Everything is ready. ' : 'Once every item is OK, ') +
        'turn HA on from the server\'s command line (it can\'t be done here): <code>' + esc(v.command) + '</code>. It shows the same checklist and asks before it changes anything; sign-in is down for a few minutes during the switch.</p>';
    }
    h += notesHtml(v.warnings, 'data-ha-warnings');
    h += '<h4>Quorum</h4>' + quorumHtml(v.quorum);
    h += '<h4>Nodes</h4>' + nodesHtml(v.nodes);
    if ((v.sites || []).length) h += '<h4>Sites</h4>' + sitesHtml(v.sites);
    h += '<h4>Front door (DNS failover)</h4>' + frontdoorHtml(v);
    if (v.credentials_note) h += '<div class="public-warn" data-ha-credentials>' + esc(v.credentials_note) + '.</div>';
    h += '<p class="settings-empty">A home node behind NAT can be an ingress node only if the public check reaches it: forward TCP 443 (and 80) on your router to it.</p>';
    if ((v.volumes || []).length) h += '<h4>Replicated volumes</h4>' + volumesHtml(v.volumes);
    if ((v.known_gaps || []).length) h += '<h4>Known gaps</h4>' + notesHtml(v.known_gaps, 'data-ha-gaps');
    return h;
  }

  async function render(root) {
    if (!root) return;
    let v;
    try { v = await window.apiGet('/api/ha'); } catch (e) { root.innerHTML = errorHtml(e.message); return; }
    root.innerHTML = pageHtml(v);
  }

  window.PortcullisHA = { render, pageHtml, errorHtml };
})();
