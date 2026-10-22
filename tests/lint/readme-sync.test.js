// Every regex the README quotes ("regex `...`") must be identical to a regex in the queries, so the docs can't drift
// from the code. KQL verbatim strings (@"...") escape a quote as "", which is unescaped before comparing.
const fs = require('fs'), path = require('path');
const base = path.join(__dirname, '..', '..');
const readme = fs.readFileSync(path.join(base, 'README.md'), 'utf8');
const live = new Set();
const qroot = path.join(base, 'queries');
for (const os of fs.readdirSync(qroot)) for (const f of fs.readdirSync(path.join(qroot, os)).filter(f => f.endsWith('.kql'))) {
  const text = fs.readFileSync(path.join(qroot, os, f), 'utf8');
  for (const m of text.matchAll(/@"((?:[^"]|"")*)"/g)) live.add(m[1].replace(/""/g, '"').replace(/^\(\?i\)/, ''));
}
const quoted = [...readme.matchAll(/regex,? `([^`]+)`/gi)].map(m => m[1].replace(/\\\|/g, '|'));
let bad = 0;
if (quoted.length === 0) { console.log('FAIL  README quotes no regexes'); bad++; }
for (const r of quoted) if (!live.has(r)) { console.log(`FAIL  README regex not found in any query: ${r}`); bad++; }
if (!bad) console.log(`PASS  README: all ${quoted.length} quoted regexes are identical to the queries`);
process.exit(bad ? 1 : 0);
