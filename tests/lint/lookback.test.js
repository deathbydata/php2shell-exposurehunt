// Every hunt sets its event window once: `let Lookback = <N>d;` with N <= 30 (the Advanced Hunting maximum for
// Defender XDR tables). Every event filter must use ago(Lookback); the only other window allowed is the 7-day IP window.
const fs = require('fs'), path = require('path');
const root = path.join(__dirname, '..', '..', 'queries');
let bad = 0; const values = new Set();
for (const os of fs.readdirSync(root).sort()) for (const f of fs.readdirSync(path.join(root, os)).filter(f => f.endsWith('.kql')).sort()) {
  const code = fs.readFileSync(path.join(root, os, f), 'utf8').split('\n').map(l => l.split('//')[0]).join('\n');
  const defs = [...code.matchAll(/let\s+Lookback\s*=\s*(\d+)d\s*;/g)];
  const agos = [...code.matchAll(/ago\(([^)]*)\)/g)].map(m => m[1].trim());
  const stray = agos.filter(a => a !== 'Lookback' && !/^7d$/.test(a));
  const uses = agos.filter(a => a === 'Lookback').length;
  const errs = [];
  if (defs.length !== 1) errs.push(`Lookback defined ${defs.length} times (expected 1)`);
  else if (+defs[0][1] < 1 || +defs[0][1] > 30) errs.push(`Lookback = ${defs[0][1]}d (allowed 1-30d; XDR Advanced Hunting keeps 30d)`);
  if (stray.length) errs.push(`hard-coded window(s): ${stray.map(s => `ago(${s})`).join(', ')}`);
  if (uses === 0) errs.push('Lookback is never used');
  console.log(`${errs.length ? 'FAIL' : 'PASS'}  ${os}/${f} lookback${errs.length ? ': ' + errs.join('; ') : ` = ${defs[0][1]}d, used ${uses}x`}`);
  if (defs.length === 1) values.add(defs[0][1]);
  bad += errs.length;
}
if (values.size > 1) { console.log(`FAIL  hunts use different Lookback values (${[...values].map(v => v + 'd').join(', ')}): PHP-seen results would disagree between hunts`); bad++; }
else console.log(`PASS  all hunts share Lookback = ${[...values][0]}d`);
process.exit(bad ? 1 : 0);
