# php2shell-exposurehunt

Defender XDR exposure hunting for PHP2Shell (CVE-2026-109618 / CVE-2026-109619).

v3.4 · 23 Oct 2026

**Purpose:** Find onboarded devices actively running PHP that could be exposed to PHP2Shell.

**Scope:** Defender XDR Advanced Hunting · onboarded Windows and Linux endpoints · 30-day lookback by default · active PHP only. Not covered: dormant installs and unmanaged devices. Not runnable in Sentinel, because the installed-software (TVM) table is only queryable in Defender XDR.

## Hunts (run in order, per OS)

| Hunt | Windows | Linux | Question |
| --- | --- | --- | --- |
| 1 | [`windows/01-any-php.kql`](queries/windows/01-any-php.kql) | [`linux/01-any-php.kql`](queries/linux/01-any-php.kql) | Any PHP? Yes/no per device. |
| 2 | [`windows/02-evidence-breakout.kql`](queries/windows/02-evidence-breakout.kql) | [`linux/02-evidence-breakout.kql`](queries/linux/02-evidence-breakout.kql) | Evidence breakout with versions. |
| 3 | [`windows/03-safety-net.kql`](queries/windows/03-safety-net.kql) | [`linux/03-safety-net.kql`](queries/linux/03-safety-net.kql) | Safety net: devices serving on web ports, the listening process, and PHP status. |
| 4 | [`windows/04-defender-cve-check.kql`](queries/windows/04-defender-cve-check.kql) | [`linux/04-defender-cve-check.kql`](queries/linux/04-defender-cve-check.kql) | Cross-check: does Defender Vulnerability Management flag the CVEs where the hunts see PHP? |

## What is hunted for

All event checks use one lookback window, `let Lookback = 30d;` at the top of each hunt. IP addresses come from the latest report per adapter in the last 7 days. Installed software is the current TVM snapshot. Only onboarded endpoints are checked (`OnboardingStatus == "Onboarded"`, `DeviceCategory == "Endpoint"`).

### PHP detection block (hunts 1, 2, 3 and 4)

A device counts as **PHP seen** if any one of these matches.

**How names are matched:**
- File names are matched by **regular expressions**, not fixed lists. Each regex is case-insensitive and anchored (`^…$`), so it must match the whole file name, never part of one.
- A cheap name-prefix filter runs first: `startswith "php"`, plus `frankenphp` on both OSes and `lsphp` on Linux. The regex then runs only on what's left.
- The names in the tables below are **examples** of what each pattern matches, and what it rejects. Other version numbers (for example a future `php9.dll`) match automatically.
- `patterns.test.js` runs each regex against these examples. If you change a regex, update the examples there.

**Windows**

| Check | Table | Matches | Why it matters |
| --- | --- | --- | --- |
| PHP executables started | `DeviceProcessEvents` | Regex `^(php(-cgi\|-win)?\|frankenphp)\.exe$`, which allows exactly four names: `php.exe` (CLI), `php-cgi.exe` (FastCGI worker), `php-win.exe` (CLI, no console), `frankenphp.exe` (PHP embedded in a web server). `phpstorm64.exe` and other `php*` tools don't match | Proves PHP ran. Hunt 2 shows the version from the binary's version information (`ProcessVersionInfoProductVersion`) |
| PHP engine DLLs loaded | `DeviceImageLoadEvents` | Regex `^php\d*(ts\|isapi\|apache[\w_]*)?\.dll$`: `php`, any version number, an optional `ts` / `isapi` / `apache…` suffix, then `.dll`. Examples are in the DLL table below. Extension DLLs (`php_curl.dll` and other `php_*.dll`) don't match, because the underscore isn't allowed straight after `php` | The only way to see PHP running inside another process, such as IIS or Apache, where no `php*.exe` starts. Hunt 2 shows the DLL and the process that loaded it |
| Installed software | `DeviceTvmSoftwareInventory` | Not a regex: `SoftwareName has "php"` (`php` as a whole word in the name) or `SoftwareVendor =~ "php"` (exact, case-insensitive) | Catches registered installs. Zip installs (the usual Windows method) normally don't register |

**Examples of PHP engine DLLs the Windows pattern matches**

| DLL | What it is | Typical host process (shown in hunt 2) |
| --- | --- | --- |
| `php8.dll`, `php7.dll` | Engine, non-thread-safe build | `php-cgi.exe` (FastCGI under IIS, nginx or Apache `mod_fcgid`), `php.exe` |
| `php8ts.dll`, `php7ts.dll`, `php5ts.dll` | Engine, thread-safe build | `httpd.exe` (Apache module), `php.exe` |
| `php8apache2_4.dll`, `php7apache2_4.dll`, `php5apache2_2.dll` | Apache module loader | `httpd.exe` |
| `php5isapi.dll` | Legacy IIS ISAPI module (PHP 5.2 and earlier, unsupported) | `w3wp.exe` |

The table lists common names, not an allow-list: any name fitting the pattern matches. The DLL name gives the major version only. The exact version comes from a `php-cgi.exe` or `php.exe` process row, or from installed software, on the same device.

**Linux**

| Check | Table | Matches | Why it matters |
| --- | --- | --- | --- |
| PHP binaries started | `DeviceProcessEvents` | Regex `^(php[\d.]*\|php-(fpm\|cgi)[\d.]*\|lsphp[\d.]*\|frankenphp)$`: `php`, `php-fpm`, `php-cgi` or `lsphp` (LiteSpeed), each with an optional version made of digits and dots, plus `frankenphp`. Examples: `php`, `php8.3`, `php83`, `php-fpm8.3`, `php-cgi8.2`, `lsphp83`. Tools such as `phpunit`, `phpize` and `php-config` don't match, because only digits and dots may follow the base name | Proves PHP ran. Hunt 2 shows a major.minor hint, extracted from the name, path or command line by a second regex, `php-?(?:fpm\|cgi)?/?(\d+\.\d+)` (for example `php-fpm8.3` or `/etc/php/8.3/` gives `8.3.x`) |
| Installed packages | `DeviceTvmSoftwareInventory` | Not a regex: `SoftwareName contains "php"` (substring, so versioned names such as `php8.3-fpm` and `libapache2-mod-php8.3` match) or `SoftwareVendor =~ "php"` | The only check for Apache `mod_php` and for php-fpm running since before the window: Linux has no library-load check here, and forked php-fpm workers don't create process starts |

### Hunt 3 safety-net checks

| Check | Table | Matches | Why it matters |
| --- | --- | --- | --- |
| Active web serving | `DeviceNetworkEvents` | `InboundConnectionAccepted` on a fixed list of ports: 80, 443, 8080, 8443. Loopback is excluded (`RemoteIPType != "Loopback"`). Shows distinct and public sources, plus the accepting process (`via <process>`) | Proves a device is serving, even if its web server started before the lookback window. `ntoskrnl.exe` = HTTP.sys (IIS, ADFS, RD Gateway, Windows Admin Center, SSTP) |
| Web server started | `DeviceProcessEvents` | Not a regex: a fixed list of exact names, case-insensitive (`in~`). Windows: `w3wp.exe`, `httpd.exe`, `nginx.exe`, `caddy.exe`, `lighttpd.exe`, `frankenphp.exe`. Linux: `httpd`, `apache2`, `nginx`, `lshttpd`, `litespeed`, `openlitespeed`, `caddy`, `lighttpd`, `frankenphp` | A web server that started in the window and loaded no PHP gives "Not seen" with high confidence. Windows also shows IIS app pool names, extracted from the `w3wp.exe` command line by the regex `-ap\s+"?([^"\s]+)` |

**PHP column values in hunt 3**

| Value | Meaning |
| --- | --- |
| `PHP seen (see hunt 2)` | At least one PHP detection check matched. |
| `Not seen` | No PHP evidence, and either a web server started in the window (high confidence) or the device isn't serving web. |
| `Not seen - no web server start in <N>d` (N = Lookback) | Serving on web ports, but no web-server process start to inspect. This is the residual blind spot: check the `via` process on the host. |

### Hunt 4 cross-check

Hunt 4 compares Defender Vulnerability Management findings (`DeviceTvmSoftwareVulnerabilities`, `CveId` in CVE-2026-109618 / CVE-2026-109619, current snapshot) with the PHP detection block above.

| Agreement | Meaning | Action |
| --- | --- | --- |
| `Both` | Defender flags the CVEs and the hunts see PHP | Confirmed exposure: patch first |
| `Defender only` | Defender flags software that none of the hunts' name filters match. Idle installs are already caught by the software check | Treat as vulnerable, and add the software's name to the detection block |
| `Hunt only` | PHP is present but not flagged: either a fixed build (for example an Ubuntu backport), or a package Defender doesn't map | Confirm with the version or package changelog before closing |
| `Neither` | No PHP evidence and no Defender finding | None |

It also shows severity, Defender's recommended update, and `CveTags` (for example `NoSecurityUpdate` on end-of-life branches).

## Usage

- Each hunt returns every onboarded device for its OS by default, servers first, then evidence rows first. To return evidence-only rows, uncomment the line marked `uncomment for evidence-only rows`.
- **Lookback:** change the single `let Lookback = 30d;` line at the top of each hunt, and use the same value in all of them.
  - 30 days is the maximum: Defender XDR Advanced Hunting keeps 30 days of device events. A larger value doesn't error, it just silently returns 30 days, so `npm test` rejects values over 30d and mixed values across hunts.
  - Shorter windows cut query cost, but push more servers into "no web server start" for manual checks. Use them only for re-runs on a baselined estate.
  - For compromise lookback beyond 30 days (for example the early-knowledge window from 1 Aug 2026), use Sentinel with longer retention. That's a separate task from this exposure pack.
- Compare versions against the fixed releases: 8.5.12, 8.4.27, 8.3.36, 8.2.35. Older branches have no upstream fix. On Linux, distros backport fixes without changing the upstream version, so check the package changelog or distro security tracker for the CVE IDs.

## Known limitations

**Both OSes:**
- Active PHP only. A process that started before the lookback window and never restarted leaves no process event; hunt 3 flags these as "no web server start in <N>d" for a manual check.
- Version checks are version-number based. Vendor-bundled builds may carry fixes without a version change.
- Defender's CVE mapping (hunt 4) doesn't cover every package source. Observed: Defender didn't flag two hosts running mod_php 7.4.33 from a third-party PPA, though 7.4 has no upstream fix; the cause is unconfirmed. Treat `Hunt only` as unresolved until checked.

**Windows:**
- Defender does not record every DLL load.
- Zip installs of PHP usually do not appear in installed software.

**Confirmed against real installations (Oct 2026):**
- **Windows:** IIS with FastCGI PHP 8.2 was detected by process (with version), engine DLL (`php8.dll` loaded by `php-cgi.exe`) and installed software. The listener showed as `ntoskrnl.exe` (HTTP.sys). TVM names PHP `php`.
- **Linux:** Ubuntu mod_php 7.4, 8.1 and 8.3, and php-fpm 7.4, were detected by process (with version hint) and package. TVM package names follow `<package>_for_linux`, for example `libapache2-mod-php8.3_for_linux`. Defender records `InboundConnectionAccepted` on Linux, and Linux servers report `DeviceType == "Server"`.
- **Lookback:** v3.3's parameterised `Lookback`, including hunt 3's window label, ran live on both OSes.

**Linux coverage gaps:**
- There is no library-load check. Apache mod_php, and php-fpm running since before the window (its workers are forked, not started), are found only through the package check.
- PHP built from source or run in containers may not appear as a package.
- Process versions are a major.minor hint from the binary name or path only.

## Maintenance

The PHP detection block is identical within each OS's four hunts. Change all four together; `npm test` fails if they drift. When you change a detection regex, update the expected matches and non-matches in `tests/lint/patterns.test.js`. The test reads the regex from the query, so it's checking your edit, not a copy.

## Testing

- **Offline (every change):** `cd tests/lint && npm install && npm test`. This runs:
  - Microsoft's Kusto language service against [`schema.json`](tests/lint/schema.json), for every hunt in both all-rows and evidence-only modes.
  - A detection-block consistency check per OS.
  - The detection regexes, read from the queries, against known PHP and non-PHP file names.
  - The lookback rules: defined once per hunt, used everywhere, the same value in all hunts, and at most 30d.
  - That every regex quoted in this README is identical to the one in the queries.
- **Live (before relying on results):** [`docs/positive-control-test-windows.md`](docs/positive-control-test-windows.md) and [`docs/positive-control-test-linux.md`](docs/positive-control-test-linux.md).

The offline checks prove syntax, column names, consistency and name matching, not results. Only live runs prove detection: the positive-control tests, or real installations (see Known limitations). Hunt 4 can't be exercised by the positive-control tests, because they use patched PHP builds.

## Licence and disclaimer

Released under the [MIT License](LICENSE). Provided as-is, without warranty: these hunts find exposure, not compromise. Validate them in your own tenant with the positive-control tests in `docs/` before relying on results.

## Changes

- **v3.4:**
  - Hunt 4 (Defender CVE cross-check) added for both OSes.
  - Linux and TVM assumptions moved to confirmed, after live runs against real installations.
  - Observation added that Defender may not map third-party package sources.
- **v3.3:**
  - MIT licence and disclaimer added.
  - Lookback is set once per hunt (`let Lookback = 30d;`) instead of being hard-coded in each check.
  - Hunt 3's label shows the actual window.
  - README shows the actual regex patterns, marks the listed names as examples, and is checked against the queries by `readme-sync.test.js`.
  - `lookback.test.js` enforces one definition per hunt, the same value across hunts, and a maximum of 30d.
- **v3.2:**
  - Linux hunts added, mirroring the Windows structure.
  - Queries moved to `queries/windows/` and `queries/linux/`.
  - Regex regression test added.
  - Windows test document renamed.
  - Known limitations section added.
  - Project renamed to php2shell-exposurehunt.
  - Detailed "What is hunted for" section added.
- **v3.1:** hunt 3 shows the process that accepted each web-port connection (`via <process>`); `ntoskrnl.exe` = HTTP.sys.
- **v3.0:** first release: three Windows hunts, offline lint, positive-control test.
