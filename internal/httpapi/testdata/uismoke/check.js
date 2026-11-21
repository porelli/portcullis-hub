// The Settings + Access → SSH access computed-style smoke check (ux3 item 5):
// every visible input, textarea, select and button there must have a
// dark background (no browser-default white or grey), and every link a
// light colour. Run by TestSettingsControlsStyled with the Hub's URL;
// prints a JSON list of the offenders.
const { chromium } = require('playwright');
(async () => {
  const base = process.argv[2];
  const opts = process.env.PLAYWRIGHT_CHROMIUM ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM } : {};
  const b = await chromium.launch(opts);
  const p = await b.newPage({ viewport: { width: 1400, height: 900 } });
  const errs = [];
  p.on('pageerror', e => errs.push(String(e)));
  const audit = name => p.evaluate(name => {
    const bad = [];
    const rgb = c => { const m = c.match(/[\d.]+/g); return m ? m.map(Number) : null; };
    const light = c => { const v = rgb(c); if (!v || (v.length === 4 && v[3] === 0)) return false; return (v[0] + v[1] + v[2]) / 3 > 180; };
    const dark = c => { const v = rgb(c); return v && (v[0] + v[1] + v[2]) / 3 < 110; };
    for (const e of document.querySelectorAll('.tab-content.active input, .tab-content.active textarea, .tab-content.active select, .tab-content.active button, .tab-content.active a')) {
      if (e.offsetParent === null || ['checkbox', 'radio', 'hidden', 'file'].includes(e.type)) continue;
      const cs = getComputedStyle(e);
      const off = e.tagName === 'A' ? dark(cs.color) : light(cs.backgroundColor) || (e.tagName !== 'BUTTON' && dark(cs.color));
      if (off) bad.push(name + ': ' + e.tagName.toLowerCase() + '.' + e.className + ' "' + (e.textContent || e.placeholder || e.id || '').trim().slice(0, 30) + '" bg=' + cs.backgroundColor + ' color=' + cs.color);
    }
    return bad;
  }, name);
  let all = [];
  await p.goto(base + '/#settings');
  await p.waitForTimeout(2500);
  all = all.concat(await audit('settings'));
  await p.goto(base + '/#access/ssh');
  await p.waitForTimeout(1500);
  const ids = await p.$$eval('#ssh-root [data-ssh-section]', es => es.map(e => e.dataset.sshSection));
  if (!ids.length) all.push('ssh: no subtabs rendered');
  for (const id of ids) {
    await p.click('#ssh-root [data-ssh-section="' + id + '"]');
    await p.waitForTimeout(800);
    all = all.concat(await audit('ssh-' + id));
  }
  all = all.concat(errs.map(e => 'page error: ' + e));
  process.stdout.write(JSON.stringify(all));
  await b.close();
})().catch(e => { process.stdout.write(JSON.stringify(['check failed: ' + e.message])); process.exit(0); });
