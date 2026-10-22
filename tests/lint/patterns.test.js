// Runs the detection regexes, read straight from each OS's hunt 1, against known PHP and non-PHP file names.
// Fails if a regex edit starts missing real PHP binaries or matching non-PHP ones.
const fs = require('fs'), path = require('path');
const root = path.join(__dirname, '..', '..', 'queries');
const cases = {
  windows: {
    exe: { yes: ['php.exe', 'php-cgi.exe', 'php-win.exe', 'frankenphp.exe', 'PHP-CGI.EXE'], no: ['phpstorm64.exe', 'php-cs-fixer.exe', 'w3wp.exe'] },
    dll: { yes: ['php8.dll', 'php7.dll', 'php8ts.dll', 'php7ts.dll', 'php5ts.dll', 'php5isapi.dll', 'php8apache2_4.dll', 'php7apache2_4.dll', 'php5apache2_2.dll'], no: ['php_curl.dll', 'phpdbg.dll', 'php8.dll.bak'] },
  },
  linux: {
    bin: { yes: ['php', 'php8.3', 'php83', 'php-fpm', 'php-fpm8.3', 'php-fpm83', 'php-cgi', 'php-cgi8.2', 'lsphp', 'lsphp83', 'frankenphp'],
           no: ['phpunit', 'phpstan', 'php-config', 'phpize', 'phpdismod', 'nginx'] },
  },
};
const toJs = s => new RegExp(s.replace(/^\(\?i\)/, ''), s.startsWith('(?i)') ? 'i' : '');
let bad = 0;
for (const [os, groups] of Object.entries(cases)) {
  const text = fs.readFileSync(path.join(root, os, '01-any-php.kql'), 'utf8');
  const rx = [...text.matchAll(/matches regex @"([^"]+)"/g)].map(m => toJs(m[1]));
  if (rx.length !== Object.keys(groups).length) { console.log(`FAIL  ${os}: expected ${Object.keys(groups).length} regexes, found ${rx.length}`); bad++; continue; }
  Object.values(groups).forEach((g, i) => {
    for (const n of g.yes) if (!rx[i].test(n)) { console.log(`FAIL  ${os}: should match ${n}`); bad++; }
    for (const n of g.no) if (rx[i].test(n)) { console.log(`FAIL  ${os}: should NOT match ${n}`); bad++; }
  });
  const total = Object.values(groups).reduce((a, g) => a + g.yes.length + g.no.length, 0);
  console.log(`${bad ? 'CHECK' : 'PASS'}  ${os}: ${total} file-name cases against ${rx.length} detection regex(es)`);
}
process.exit(bad ? 1 : 0);
