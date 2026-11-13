// vpn.js — the people listener's VPN page (people.<d>/vpn/, contract
// §5.1): the caller's devices from every provider, and adding a built-in
// device. A new device needs a fresh sign-in (freshauth.js with this
// page's own redirect URI); its X25519 key pair is made here with
// WebCrypto. Only the public key is POSTed (with the name and the proof);
// the WireGuard configuration text and its QR code are assembled in this
// page, shown once, and the private key is overwritten when the panel
// closes. Nothing is stored in the browser.
(function () {
  'use strict';
  const API = '/vpn/api/devices';
  let view = null;
  let secret = null; // the private key, only while its config is shown

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
  }
  function $(id) { return document.getElementById(id); }
  function status(text, warn) {
    const el = $('vpn-status');
    el.textContent = text || '';
    el.className = warn ? 'vpn-muted vpn-warn' : 'vpn-muted';
  }
  async function call(method, path, body) {
    const opts = { method, headers: { 'Accept': 'application/json' }, credentials: 'same-origin' };
    if (body !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(path, opts);
    const text = await res.text();
    if (!res.ok) throw new Error(text.trim() || res.statusText);
    return text ? JSON.parse(text) : null;
  }
  function b64(bytes) {
    let s = '';
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s);
  }

  // keyPair makes an X25519 key pair: the raw public key, and the private
  // key as the last 32 bytes of its PKCS#8 export (WireGuard's form).
  async function keyPair() {
    const kp = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
    const pub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
    const pk8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey));
    const priv = pk8.slice(pk8.length - 32);
    pk8.fill(0);
    const out = { publicKey: b64(pub), privateKey: b64(priv) };
    priv.fill(0);
    return out;
  }

  function configText(cfg, privateKey) {
    return '[Interface]\n' +
      'PrivateKey = ' + privateKey + '\n' +
      'Address = ' + cfg.address + '/32\n' +
      'DNS = ' + cfg.dns + '\n' +
      'MTU = ' + cfg.mtu + '\n\n' +
      '[Peer]\n' +
      'PublicKey = ' + cfg.server_public_key + '\n' +
      'AllowedIPs = ' + cfg.allowed_ips + '\n' +
      'Endpoint = ' + cfg.endpoint + '\n' +
      'PersistentKeepalive = 25\n';
  }

  // showConfig shows a device's configuration once: the text and its QR,
  // both built here. Closing overwrites the key and empties the panel.
  function showConfig(name, cfg, privateKey) {
    secret = privateKey;
    const text = configText(cfg, secret);
    const panel = $('vpn-config');
    panel.hidden = false;
    panel.innerHTML = '<p><strong>' + esc(name) + '</strong>: import this configuration into WireGuard now. It is shown only once.</p>' +
      '<div class="vpn-qr" data-vpn-qr></div><div class="vpn-conf" data-vpn-conf></div>' +
      '<p><button class="pd-btn pd-btn-primary" data-vpn-act="close">Done: I saved it</button></p>';
    panel.querySelector('[data-vpn-conf]').textContent = text;
    if (typeof qrcode === 'function') {
      const qr = qrcode(0, 'M');
      qr.addData(text);
      qr.make();
      panel.querySelector('[data-vpn-qr]').innerHTML = qr.createSvgTag({ cellSize: 4, margin: 2 });
    }
  }
  function closeConfig() {
    secret = null;
    const panel = $('vpn-config');
    panel.innerHTML = '';
    panel.hidden = true;
  }

  function renderAdd() {
    const el = $('vpn-add');
    if (!view || !view.fresh_auth) {
      el.innerHTML = '<p class="vpn-muted">Adding a device isn\'t available right now.</p>';
      return;
    }
    el.innerHTML = '<label class="pd-small" for="vpn-name">New device name</label> ' +
      '<input class="pd-input" id="vpn-name" maxlength="64" autocomplete="off" data-vpn-name> ' +
      '<button class="pd-btn pd-btn-primary" data-vpn-act="add">Add device</button>' +
      '<p class="vpn-muted">You sign in again in a small window to confirm it\'s you.</p>';
  }

  function when(t) { return t ? new Date(t).toLocaleString() : 'never'; }

  function renderList() {
    const el = $('vpn-list');
    const devs = (view && view.devices) || [];
    if (!devs.length) {
      el.innerHTML = '<p class="vpn-muted">No VPN devices yet.</p>';
      return;
    }
    el.innerHTML = devs.map(d => '<div class="vpn-row" data-vpn-id="' + esc(d.id) + '">' +
      '<div class="vpn-grow"><strong>' + esc(d.name) + '</strong> <span class="vpn-muted">' + esc(d.provider_label) + ' · ' + esc(d.address) +
      ' · last seen ' + esc(when(d.last_seen)) + (d.online ? ' (online)' : '') + ' · expires ' + esc(d.expires ? when(d.expires) : 'never') + '</span></div>' +
      (d.managed
        ? '<button class="pd-btn pd-btn-secondary" data-vpn-act="rename">Rename</button>' +
          '<button class="pd-btn pd-btn-secondary" data-vpn-act="renew">Renew</button>' +
          '<button class="pd-btn pd-btn-danger" data-vpn-act="remove">Remove</button>'
        : '<span class="vpn-muted">managed in ' + esc(d.provider_label) + '</span>') +
      '</div>').join('');
  }

  async function load() {
    try {
      view = await call('GET', API);
    } catch (err) {
      status(err.message, true);
      return;
    }
    renderAdd();
    renderList();
  }

  // fresh runs a fresh sign-in, then proof(pr) (called from the click:
  // the popup opens before any await).
  function fresh(what, proof) {
    if (!window.PortcullisFreshAuth) { status('A fresh sign-in isn\'t available on this page.', true); return; }
    window.PortcullisFreshAuth.start(view.fresh_auth, {
      ctx: { vpn: what },
      status: (t, warn) => status(t, warn),
      busy: () => {},
      end: () => {},
      proof: pr => proof(pr),
    });
  }

  function add() {
    const input = document.querySelector('[data-vpn-name]');
    const name = (input.value || '').trim();
    if (!name || name.length > 64) { status('Name the device (1–64 characters).', true); return; }
    fresh('add', async pr => {
      let keys;
      try {
        keys = await keyPair();
      } catch (err) {
        status('This browser can\'t make WireGuard keys (X25519): ' + err.message, true);
        return;
      }
      let cfg;
      try {
        cfg = await call('POST', API, { name: name, public_key: keys.publicKey, code: pr.code, code_verifier: pr.code_verifier, nonce: pr.nonce });
      } catch (err) {
        keys.privateKey = null;
        status(err.message, true);
        return;
      }
      input.value = '';
      status('');
      showConfig(name, cfg, keys.privateKey);
      keys.privateKey = null;
      load();
    });
  }

  function renew(id, name) {
    fresh('renew', async pr => {
      let keys;
      try {
        keys = await keyPair();
      } catch (err) {
        status('This browser can\'t make WireGuard keys (X25519): ' + err.message, true);
        return;
      }
      let cfg;
      try {
        cfg = await call('POST', API + '/' + encodeURIComponent(id) + '/renew', { public_key: keys.publicKey, code: pr.code, code_verifier: pr.code_verifier, nonce: pr.nonce });
      } catch (err) {
        keys.privateKey = null;
        status(err.message, true);
        return;
      }
      showConfig(name, cfg, keys.privateKey);
      keys.privateKey = null;
      load();
    });
  }

  document.addEventListener('click', ev => {
    const b = ev.target.closest('[data-vpn-act]');
    if (!b) return;
    const act = b.getAttribute('data-vpn-act');
    const row = b.closest('[data-vpn-id]');
    const id = row ? row.getAttribute('data-vpn-id') : '';
    const dev = ((view && view.devices) || []).find(d => d.id === id);
    if (act === 'add') add();
    else if (act === 'close') closeConfig();
    else if (act === 'renew' && dev) renew(id, dev.name);
    else if (act === 'rename' && dev) {
      const name = (window.prompt('New name for ' + dev.name, dev.name) || '').trim();
      if (!name) return;
      call('PUT', API + '/' + encodeURIComponent(id), { name: name }).then(load, err => status(err.message, true));
    } else if (act === 'remove' && dev) {
      if (!window.confirm('Remove ' + dev.name + '? It can\'t connect any more.')) return;
      call('DELETE', API + '/' + encodeURIComponent(id)).then(load, err => status(err.message, true));
    }
  });
  window.addEventListener('pagehide', closeConfig);
  load();
})();
