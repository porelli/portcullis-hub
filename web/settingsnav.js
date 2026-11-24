// Portcullis Hub — the Settings tab's subtabs (Hub listener only).
//
//   window.PortcullisSettingsNav.show(section, query)
//       shows one section (signin network storage mail ai servers ssh
//       sources; anything else → signin), loads it (each visit loads
//       fresh; the hidden ones aren't loaded) and replaces the hash with
//       #settings/<section>. query is the deep link's (the forms it opens
//       are openSettingsForm's, index.html).
//   window.PortcullisSettingsNav.current()   the section shown last
//
// The markup is index.html's: one tablist of <button data-settings-tab>
// and one <section data-settings-section> per section. Clicks and the
// arrow keys (Left/Right, Home/End, wrapping) are delegated from
// document. The loaders are the page's own (index.html's functions and
// the section scripts).
(function () {
  'use strict';

  const SECTIONS = ['signin', 'network', 'storage', 'mail', 'ai', 'servers', 'ssh', 'sources'];
  const byId = id => document.getElementById(id);
  const LOADERS = {
    signin: () => PortcullisSignIn.mount(byId('signin-root')),
    network: () => {
      loadDomains();
      PortcullisFolders.renderLocalNetworks(byId('localnets-root'));
      loadVPNSettings(byId('vpn-settings-root'));
    },
    storage: () => PortcullisFolders.render(byId('folders-root')),
    mail: () => { if (window.PortcullisMail) window.PortcullisMail.render(byId('mail-settings-root')); },
    ai: () => loadAISettings(),
    servers: () => {
      if (window.PortcullisServers) window.PortcullisServers.render(byId('servers-root'));
      // High availability (web/ha.js): Kubernetes only (Docker and Podman don't change).
      const kube = typeof runtimeIsKube === 'function' && runtimeIsKube();
      byId('ha-section').hidden = !kube;
      if (kube && window.PortcullisHA) window.PortcullisHA.render(byId('ha-root'));
    },
    ssh: () => { if (window.PortcullisSSH) window.PortcullisSSH.renderSettings(byId('ssh-settings-root')); },
    sources: () => { loadSources(); loadSourceSync(); },
  };

  let current = 'signin';

  function show(section) {
    // '' (the Settings tab itself): the section shown last.
    const slug = section === '' || section == null ? current : SECTIONS.indexOf(section) >= 0 ? section : 'signin';
    current = slug;
    document.querySelectorAll('[data-settings-tab]').forEach(b => {
      const on = b.dataset.settingsTab === slug;
      b.setAttribute('aria-selected', on ? 'true' : 'false');
      b.setAttribute('tabindex', on ? '0' : '-1');
    });
    document.querySelectorAll('[data-settings-section]').forEach(s => { s.hidden = s.dataset.settingsSection !== slug; });
    LOADERS[slug]();
    history.replaceState(null, '', '#settings/' + slug);
    return slug;
  }

  document.addEventListener('click', e => {
    const b = e.target.closest && e.target.closest('[data-settings-tab]');
    if (b) show(b.dataset.settingsTab);
  });
  document.addEventListener('keydown', e => {
    const b = e.target.closest && e.target.closest('[data-settings-tab]');
    if (!b) return;
    const i = SECTIONS.indexOf(b.dataset.settingsTab);
    const n = SECTIONS.length;
    const to = { ArrowRight: (i + 1) % n, ArrowLeft: (i + n - 1) % n, Home: 0, End: n - 1 }[e.key];
    if (to === undefined) return;
    e.preventDefault();
    show(SECTIONS[to]);
    document.querySelectorAll('[data-settings-tab]').forEach(t => { if (t.dataset.settingsTab === SECTIONS[to]) t.focus(); });
  });

  window.PortcullisSettingsNav = { show, current: () => current, SECTIONS };
})();
