# PHP Detection Positive-Control Test (Linux)

## Purpose and scope

This test proves the three Linux PHP2Shell hunts detect what they claim, by creating a known positive on an onboarded Linux device and checking each column. An empty result looks the same whether the estate is clean or a hunt is broken; this test tells the two apart.

- **Target:** an onboarded Linux VM you control, not a production system. Avoid WSL: Defender only sees WSL with the separate MDE WSL plug-in, and whether those events appear as a Linux device in these hunts is not verified.
- **Not exercised:** Apache mod_php and long-running php-fpm (both rely on the package check), and the `InboundConnectionAccepted` event on Linux until this test confirms it.

## Before you start

- [ ] Run the hunts in the tenant the test device is onboarded to.
- [ ] Use the distro's current PHP package (patched builds only). The test briefly exposes PHP on the local network.
- [ ] Tell the SOC team; a new listener on a server may raise an alert.
- [ ] Have a second device on the same network, and know the test device's hostname and IP (`hostname -I`).

## Test steps

1. **Install PHP CLI** (Debian/Ubuntu shown; use `dnf install php-cli` on RHEL family). This creates the package entry, which tests `PHPPackages`.

   ```bash
   sudo apt-get install -y php-cli
   ```
2. **Run PHP once.** This creates a process event, which tests hunts 1 and 2 (`PHPProcesses`).

   ```bash
   php -v
   ```
3. **Start the built-in web server** on port 8080 (one of the ports hunt 3 watches).

   ```bash
   mkdir -p /tmp/phptest && echo '<?php echo "php2shell test";' > /tmp/phptest/index.php
   php -S 0.0.0.0:8080 -t /tmp/phptest
   ```
4. **Connect from the second device:** browse to `http://<test-device-IP>:8080` and confirm the page loads. This tests hunt 3 (`ActiveWebPorts`). If a host or network firewall blocks it, record `ActiveWebPorts` as untested.
5. **Note the time**, leave the server running for a few minutes, then stop it with Ctrl+C.
6. **Wait about an hour**, then run all three Linux hunts with this line added just before `project`. The package inventory can lag behind process events; if `PHPPackages` is still empty after a day, record it as untested rather than failed.

   ```kql
   | where DeviceName startswith "<test-hostname>"
   ```

## Expected results

| Hunt | Column | Expected value | What it proves |
| --- | --- | --- | --- |
| 1/3 | Row returned | Test device appears with PHP = PHP seen | Yes/no PHP detection works |
| 2/3 | `PHPProcesses` | `php8.x (8.x.x)` on Debian/Ubuntu (versioned binary), or `php` with no hint elsewhere | Process detection and version hint |
| 2/3 | `PHPPackages` | The installed PHP packages with distro versions | Package detection |
| 3/3 | `PHP` | `PHP seen (see hunt 2)` | Safety net agrees with hunts 1 and 2 |
| 3/3 | `ActiveWebPorts` | `8080 (1 sources, 0 public) via php…` | Inbound connection events exist on Linux, with the listening process |
| 3/3 | `WebServers` | Not Detected (correct: PHP's built-in server is not in the web-server list) | No false web-server match |

## Cleanup

- [ ] Confirm the PHP server is stopped (`pgrep -a php` returns nothing).
- [ ] Remove the package and test folder: `sudo apt-get purge -y php-cli && sudo apt-get autoremove -y && rm -rf /tmp/phptest`.
- [ ] Tell the SOC team the test is finished, and close any alert it raised with a note referencing this test.

## Results record

| Hunt | Column | Expected | Actual | Pass / Fail |
| --- | --- | --- | --- | --- |
| 1/3 | Row returned | Test device appears with PHP = PHP seen |  |  |
| 2/3 | `PHPProcesses` | `php8.x (8.x.x)` or `php` |  |  |
| 2/3 | `PHPPackages` | Installed PHP packages |  |  |
| 3/3 | `PHP` | `PHP seen (see hunt 2)` |  |  |
| 3/3 | `ActiveWebPorts` | `8080 (1 sources, 0 public) via php…` |  |  |
| 3/3 | `WebServers` | Not Detected |  |  |

Test date, device, distro and PHP version used:
