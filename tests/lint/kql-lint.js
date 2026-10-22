// Semantic check of every query in ../../queries/<os>/ using Microsoft's Kusto language service against schema.json.
// Catches unknown columns/tables/variables, wrong function arguments and syntax errors. Exit code 1 on any diagnostic.
// Each query is checked twice: as shipped (all rows) and with the evidence-only line uncommented.
global.Bridge = require('@kusto/language-service-next/bridge.js');
require('@kusto/language-service-next/Kusto.Language.Bridge.js');
const K = global.Kusto.Language, fs = require('fs'), path = require('path');
const schema = JSON.parse(fs.readFileSync(path.join(__dirname, 'schema.json'), 'utf8'));
const tables = Object.entries(schema).filter(([n]) => !n.startsWith('_'))
  .map(([n, s]) => K.Symbols.TableSymbol.From(s).WithName(n));
const globals = K.GlobalState.Default.WithDatabase(new K.Symbols.DatabaseSymbol.$ctor3('mde', null, tables, false));
const root = path.join(__dirname, '..', '..', 'queries');
let failures = 0, checked = 0;
const check = (label, text) => {
  const d = K.KustoCode.ParseAndAnalyze(text, globals).GetDiagnostics();
  console.log(`${d.Count === 0 ? 'PASS' : 'FAIL'}  ${label}`); checked++;
  for (let i = 0; i < d.Count; i++) {
    const x = d.getItem(i);
    console.log(`      line ${text.substring(0, x.Start).split('\n').length}: ${x.Message}`);
  }
  failures += d.Count;
};
for (const os of fs.readdirSync(root).sort()) {
  const dir = path.join(root, os);
  for (const f of fs.readdirSync(dir).filter(f => f.endsWith('.kql')).sort()) {
    const text = fs.readFileSync(path.join(dir, f), 'utf8');
    check(`${os}/${f} (all rows)`, text);
    const ev = text.replace(/^\/\/ (\| where .*\/\/ uncomment for evidence-only rows)$/m, '$1');
    if (ev === text) { console.log(`FAIL  ${os}/${f}: evidence-only toggle line not found`); failures++; }
    else check(`${os}/${f} (evidence-only)`, ev);
  }
}
if (checked === 0) { console.log('FAIL  no queries found'); failures++; }
process.exit(failures ? 1 : 0);
