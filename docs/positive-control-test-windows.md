# PHP Detection Positive-Control Test (Windows)

## Purpose and scope

This test proves the three PHP2Shell Windows hunts detect what they claim, by creating a known positive on an onboarded Windows device and checking each column. Hunt 1/3 lists devices with any PHP signal; hunt 2/3 breaks that evidence out with versions; hunt 3/3 is the safety net, listing devices actively serving on web ports and whether PHP was seen. An empty result looks the same whether the estate is clean or a hunt is broken; this test tells the two apart.

- **Target:** an onboarded Windows laptop or VM you control, not a production system.
- **Not WSL:** Defender only sees WSL processes with the separate MDE WSL plug-in, and how those events are attributed is not verified here. Test the Linux hunts on an onboarded Linux VM instead.

## Before you start

- [ ] Run the hunts in the tenant the test device is onboarded to. The query logic is the same in every tenant.
- [ ] Use a **patched** PHP release only (8.4.27 or 8.3.36 or later). The test briefly exposes PHP on the local network.
- [ ] Confirm the test is allowed under internal policy and tell the SOC team. A new internet-downloaded binary listening on a port may raise an alert.
- [ ] Have a second device on the same network (PC or phone) to make an inbound connection.
- [ ] Know the test device's hostname (for the query filter) and its local IP address (`ipconfig`).

## Test steps

1. **Download PHP.** From [windows.php.net/download](https://windows.php.net/download/), get the latest 8.4 or 8.3 **VS17 x64 Non Thread Safe** zip. Check its hash against the SHA256 shown on that page (adjust the file name):

   ```powershell
   Get-FileHash .\php-8.4.27-nts-Win32-vs17-x64.zip -Algorithm SHA256
   ```
2. **Unzip** to `C:\php-test`. This only stages the test; file writes are not checked by any hunt.
3. **Run PHP once.** This creates a process event with a version and a PHP DLL load, which tests hunts 1 and 2 (`PHPProcesses`, `PHPDlls`).

   ```powershell
   C:\php-test\php.exe -v
   ```
4. **Start the built-in web server** on port 8080 (one of the ports hunt 3 watches). If Windows Firewall prompts, allow **private networks only**.

   ```powershell
   mkdir C:\php-test\www
   Set-Content C:\php-test\www\index.php '<?php echo "php2shell test";'
   C:\php-test\php.exe -S 0.0.0.0:8080 -t C:\php-test\www
   ```
5. **Connect from the second device:** browse to `http://<test-device-IP>:8080` and confirm the test page loads. This tests hunt 3 (`ActiveWebPorts`). Connections from the test device itself are loopback and are ignored by design. If VPN or firewall policy blocks it, record `ActiveWebPorts` as untested.
6. **Note the time**, leave the server running for a few minutes, then stop it with Ctrl+C.
7. **Wait about an hour** for ingestion, then run all three hunts in Defender XDR Advanced Hunting with this line added just before `project`:

   ```kql
   | where DeviceName startswith "<test-hostname>"
   ```

## Expected results

The test passes when every column matches the table below; any mismatch is a query bug to fix before the hunts are relied on.

| Hunt | Column | Expected value | What it proves |
| --- | --- | --- | --- |
| 1/3 | Row returned | Test device appears with PHP = PHP seen | Yes/no PHP detection works |
| 2/3 | `PHPProcesses` | `php.exe <version>` | Process detection and version read |
| 2/3 | `PHPDlls` | `php8.dll (php.exe)` | PHP engine DLL load and host detection |
| 2/3 | `PHPSoftware` | Not Detected (correct: zip installs do not register as software) | Expected gap, documented |
| 3/3 | `PHP` | `PHP seen (see hunt 2)` | Safety net agrees with hunts 1 and 2 |
| 3/3 | `ActiveWebPorts` | `8080 (1 sources, 0 public) via php.exe` | Inbound web serving and listening-process detection |
| 3/3 | `WebServers` | Not Detected (correct: `php.exe` is not in the web-server list) | No false web-server match |
| 3/3 | `AppPools` | Not Detected (correct: no IIS) | No false app pool match |

If `PHPProcesses` shows `php.exe` with no version after it, the version field was empty; record it and check the raw `ProcessVersionInfoProductVersion` value for `php.exe` in `DeviceProcessEvents`.

## Cleanup

- [ ] Confirm the PHP server is stopped (no `php.exe` in Task Manager).
- [ ] Delete `C:\php-test` and the downloaded zip.
- [ ] Remove any Windows Firewall rule created for `php.exe` (Windows Defender Firewall → Inbound Rules).
- [ ] Tell the SOC team the test is finished, and close any alert it raised with a note referencing this test.

## Not covered, and results record

This test does not exercise the IIS (`w3wp.exe`) or Apache (`httpd.exe`) DLL-host paths, IIS app pool extraction, or the installed-software source; record those as untested.

| Hunt | Column | Expected | Actual | Pass / Fail |
| --- | --- | --- | --- | --- |
| 1/3 | Row returned | Test device appears with PHP = PHP seen |  |  |
| 2/3 | `PHPProcesses` | `php.exe <version>` |  |  |
| 2/3 | `PHPDlls` | `php8.dll (php.exe)` |  |  |
| 2/3 | `PHPSoftware` | Not Detected |  |  |
| 3/3 | `PHP` | `PHP seen (see hunt 2)` |  |  |
| 3/3 | `ActiveWebPorts` | `8080 (1 sources, 0 public) via php.exe` |  |  |
| 3/3 | `WebServers` | Not Detected |  |  |
| 3/3 | `AppPools` | Not Detected |  |  |

Test date, device and PHP version used:
