// The PHP detection block must be identical across the hunts of each OS. This compares the detection filter
// lines (ignoring whitespace, trailing comments and the per-hunt 'extend' lines) and fails on any drift.
const fs = require('fs'), path = require('path');
const root = path.join(__dirname, '..', '..', 'queries');
const rules = {
  windows: { expect: 5, markers: ['FileName startswith "php" or FileName =~ "frankenphp.exe")', '(?i)^(php(-cgi|-win)?|frankenphp)\\.exe$',
                                   '(?i)^php\\d*(ts|isapi|apache', 'SoftwareName has "php" or SoftwareVendor =~ "php"',
                                   'DeviceImageLoadEvents | where Timestamp > ago(Lookback) and FileName startswith "php"'] },
  linux:   { expect: 3, markers: ['FileName startswith "php" or FileName startswith "lsphp" or FileName =~ "frankenphp")',
                                   '(?i)^(php[\\d.]*|php-(fpm|cgi)[\\d.]*|lsphp[\\d.]*|frankenphp)$',
                                   'SoftwareName contains "php" or SoftwareVendor =~ "php"'] },
};
const norm = l => l.split('//')[0].replace(/\s+/g, ' ').trim().replace(/[),]+$/, '');
let bad = 0;
for (const os of fs.readdirSync(root).sort()) {
  const rule = rules[os];
  if (!rule) { console.log(`FAIL  no consistency rule for queries/${os}`); bad++; continue; }
  const dir = path.join(root, os);
  const grab = f => fs.readFileSync(path.join(dir, f), 'utf8').split('\n').filter(l => rule.markers.some(m => l.includes(m))).map(norm);
  const files = fs.readdirSync(dir).filter(f => f.endsWith('.kql')).sort();
  const base = grab(files[0]);
  if (base.length !== rule.expect) { console.log(`FAIL  ${os}/${files[0]}: expected ${rule.expect} detection lines, found ${base.length}`); bad++; }
  for (const f of files) {
    const same = JSON.stringify(grab(f)) === JSON.stringify(base);
    console.log(`${same ? 'PASS' : 'FAIL'}  ${os}/${f} detection block ${same ? 'matches' : 'DIFFERS from'} ${os}/${files[0]}`);
    if (!same) bad++;
  }
}
process.exit(bad ? 1 : 0);
