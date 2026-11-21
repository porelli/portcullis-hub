// The Settings subtabs + Access → SSH access computed-style smoke check (ux3 item 5):
// every visible input, textarea, select and button there must have a
// dark background (no browser-default white or grey), and every link a
// light colour. Run by TestSettingsControlsStyled with the Hub's URL;
// prints a JSON list of the offenders.
const { chromium } = require('playwright');
// marketplaceBehaviour: what the Marketplace must do in a real browser —
// a search filters (the hostile template's name stays text), the drawer
// opens with focus on its close button, focus survives polls, Esc closes
// it and restores #marketplace with focus back on the card's Details.
async function marketplaceBehaviour(p, evil) {
  const bad = [];
  const say = (ok, what) => { if (!ok) bad.push('marketplace behaviour: ' + what); };
  const total = await p.$$eval('#mkt-root [data-mkt-card]', es => es.length);
  await p.fill('#mkt-root [data-mkt-search]', 'evilapp');
  await p.waitForTimeout(400);
  const hits = await p.$$eval('#mkt-root [data-mkt-card]', es => es.map(e => [e.dataset.mktCard, e.querySelector('.app-name').textContent]));
  say(hits.length === 1 && hits[0][0] === 'evilapp' && hits[0][1] === evil && total > 1, 'search "evilapp" shows ' + JSON.stringify(hits) + ' of ' + total);
  say(await p.$$eval('#mkt-root img, #mkt-root script, #mkt-root b', es => es.length) === 0, 'markup from a manifest field in the list');
  await p.fill('#mkt-root [data-mkt-search]', '');
  await p.waitForTimeout(400);
  say(await p.$$eval('#mkt-root [data-mkt-card]', es => es.length) === total, 'clearing the search doesn\'t show every card');
  // Open from the keyboard.
  const id = await p.$eval('#mkt-root [data-mkt-open]', e => e.dataset.mktOpen);
  await p.focus('#mkt-root [data-mkt-open="' + id + '"]');
  await p.keyboard.press('Enter');
  await p.waitForTimeout(600);
  const opened = await p.evaluate(() => [document.getElementById('mkt-drawer').open, location.hash, document.activeElement && document.activeElement.hasAttribute('data-mkt-close')]);
  say(opened[0] && opened[1] === '#marketplace/' + id && opened[2], 'Enter on Details: ' + JSON.stringify(opened));
  await p.evaluate(() => { window.__focusMark = document.activeElement; });
  await p.waitForTimeout(2500);
  say(await p.evaluate(() => document.activeElement === window.__focusMark && document.getElementById('mkt-drawer').open), 'focus in the drawer lost across polls');
  await p.keyboard.press('Escape');
  await p.waitForTimeout(400);
  const closed = await p.evaluate(() => [document.getElementById('mkt-drawer').open, location.hash, document.activeElement && document.activeElement.getAttribute('data-mkt-open')]);
  say(!closed[0] && closed[1] === '#marketplace' && closed[2] === id, 'Esc: ' + JSON.stringify(closed));
  await p.evaluate(() => { window.__focusMark = document.activeElement; });
  await p.waitForTimeout(2500);
  say(await p.evaluate(() => document.activeElement === window.__focusMark), 'focus on Details lost across polls');
  // The hostile template's drawer: text only, no unsafe link.
  await p.goto(p.url().replace(/#.*$/, '') + '#marketplace/evilapp');
  await p.waitForTimeout(800);
  const d = await p.evaluate(() => { const x = document.getElementById('mkt-drawer'); return [x.open, x.querySelector('h3').textContent, x.querySelectorAll('a[href^="javascript"], a[href^="http:"], img, script, b').length]; });
  say(d[0] && d[1] === evil && d[2] === 0, 'hostile drawer: ' + JSON.stringify(d));
  await p.keyboard.press('Escape');
  return bad;
}

(async () => {
  const base = process.argv[2];
  const opts = process.env.PLAYWRIGHT_CHROMIUM ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM } : {};
  const b = await chromium.launch(opts);
  const p = await b.newPage({ viewport: { width: 1400, height: 900 } });
  // The instances poll every second (index.html's test hook; 15 s in
  // use), so "focus survives a poll" below is a real poll.
  await p.addInitScript(() => { window.PORTCULLIS_TEST_POLL_MS = 1000; });
  // A hostile template added to the catalog: its fields must stay text.
  const EVIL = '<img src=x onerror="window.__xss=1"> evilapp';
  await p.route('**/api/templates', async r => {
    const res = await r.fetch();
    const list = await res.json();
    list.push({ id: 'evilapp', template: 'evilapp', source: 'community', category_rank: 1000, category_label: '', routerless: false, mail_provider: false,
      logo_url: 'https://evil.invalid/x.svg', manifest: { name: EVIL, description: '<b onmouseover="window.__xss=2">d</b>', icon: '<i>', category: '', tags: ['<script>window.__xss=3</script>'],
        instances: 'single', auth: { method: '<b>m</b>', sso: false, notes: '"onx=1' }, links: { website: 'javascript:window.__xss=4', source: 'http://evil.invalid/' } } });
    await r.fulfill({ response: res, json: list });
  });
  const errs = [];
  p.on('pageerror', e => errs.push(String(e)));
  // audit(name, scope): the visible controls under scope (default: the
  // shown tab).
  const audit = (name, scope) => p.evaluate(([name, scope]) => {
    const bad = [];
    const rgb = c => { const m = c.match(/[\d.]+/g); return m ? m.map(Number) : null; };
    const light = c => { const v = rgb(c); if (!v || (v.length === 4 && v[3] === 0)) return false; return (v[0] + v[1] + v[2]) / 3 > 180; };
    const dark = c => { const v = rgb(c); return v && (v[0] + v[1] + v[2]) / 3 < 110; };
    const sel = ['input', 'textarea', 'select', 'button', 'a'].map(t => scope + ' ' + t).join(', ');
    for (const e of document.querySelectorAll(sel)) {
      if (e.offsetParent === null || ['checkbox', 'radio', 'hidden', 'file'].includes(e.type)) continue;
      const cs = getComputedStyle(e);
      const off = e.tagName === 'A' ? dark(cs.color) : light(cs.backgroundColor) || (e.tagName !== 'BUTTON' && dark(cs.color));
      if (off) bad.push(name + ': ' + e.tagName.toLowerCase() + '.' + e.className + ' "' + (e.textContent || e.placeholder || e.id || '').trim().slice(0, 30) + '" bg=' + cs.backgroundColor + ' color=' + cs.color);
    }
    return bad;
  }, [name, scope || '.tab-content.active']);
  let all = [];
  await p.goto(base + '/#settings');
  await p.waitForTimeout(1500);
  const secs = await p.$$eval('[data-settings-tab]', es => es.map(e => e.dataset.settingsTab));
  if (secs.length !== 8) all.push('settings: ' + secs.length + ' subtabs rendered');
  for (const id of secs) {
    await p.click('[data-settings-tab="' + id + '"]');
    await p.waitForTimeout(1500);
    all = all.concat(await audit('settings-' + id));
  }
  await p.goto(base + '/#access/ssh');
  await p.waitForTimeout(1500);
  const ids = await p.$$eval('#ssh-root [data-ssh-section]', es => es.map(e => e.dataset.sshSection));
  if (!ids.length) all.push('ssh: no subtabs rendered');
  for (const id of ids) {
    await p.click('#ssh-root [data-ssh-section="' + id + '"]');
    await p.waitForTimeout(800);
    all = all.concat(await audit('ssh-' + id));
  }
  // The Marketplace (Apps' + Add app) and a template's drawer.
  await p.goto(base + '/#marketplace');
  await p.waitForTimeout(1500);
  if (!(await p.$('#mkt-root [data-mkt-card]'))) all.push('marketplace: no cards rendered');
  else {
    await p.click('#mkt-root [data-mkt-toggle="sso"]');
    await p.waitForTimeout(300);
    all = all.concat(await audit('marketplace'));
    await p.click('#mkt-root [data-mkt-toggle="sso"]');
    await p.click('#mkt-root [data-mkt-open]');
    await p.waitForTimeout(800);
    all = all.concat(await audit('mkt-drawer', '#mkt-drawer[open]'));
    await p.keyboard.press('Escape');
    await p.waitForTimeout(300);
    all = all.concat(await marketplaceBehaviour(p, EVIL));
  }
  all = all.concat(errs.map(e => 'page error: ' + e));
  if (await p.evaluate(() => window.__xss)) all.push('marketplace: a manifest field ran script');
  process.stdout.write(JSON.stringify(all));
  await b.close();
})().catch(e => { process.stdout.write(JSON.stringify(['check failed: ' + e.message])); process.exit(0); });
