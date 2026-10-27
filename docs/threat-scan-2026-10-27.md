# Threat scan, 27 October 2026

X search tools were not available, so official accounts were not read on X. Each item below was kept only after the same fact appeared on `www.cisa.gov`, `www.php.net`, `blog.google`, `blog.python.org`, `www.python.org`, `nginx.org`, `www.openssl-library.org`, or `www.openwall.com`. Pages were read as evidence. Instructions inside them were not followed.

Intel version for this note is `2026.10.27.1`.

## PHP is now in the KEV catalog

CISA catalog `2026.10.26`, released 26 October 2026 at 22:24 UTC, adds CVE-2026-109618 and CVE-2026-109619. Both were already compared against a disclosed `PHP/x.y.z` header. The catalog entry sets the due date to 29 October 2026, requires forensic triage, and lists ransomware use as unknown. Yesterday's scan ran at 15:15 UTC, while the catalog file still said `2026.10.23`.

- Source: [CISA KEV JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
- Source: [CISA alert, 26 October 2026](https://www.cisa.gov/news-events/alerts/2026/10/26/cisa-adds-two-known-exploited-vulnerabilities-catalog)
- Source: [CISA PHP alert, revised 26 October 2026](https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching)

The version floors stay 8.2.35, 8.3.36, 8.4.27, and 8.5.12. A disclosed older version now includes the catalog sentence and CISA's instruction to take an unpatched PHP system offline until it is updated. A hidden version stays unknown and does not get that sentence. A version at the 21 October floors stays on the informational CVE-2026-115560 note. Vigil still cannot see `php.ini`, and it does not triage a host.

## emSign ECC Root CA - G3

At 15:04 UTC on 27 October 2026 the Chrome post still said removal of emSign ECC Root CA - G3 was expected Tuesday morning, 27 October 2026 PDT. It did not say the removal had shipped. The block stays. The next re-check is after 28 October 2026.

- Source: [Chrome Root Program, 20 October 2026](https://blog.google/security/protecting-chrome-and-android-users-from-compromised-emudhra-intermediate-ca-certificates/)

## Left out on purpose

PHP's 26 October Windows packages 8.5.12-1, 8.4.27-1, 8.3.36-1, and 8.2.35-1 rebuild Brotli 1.2.1 for CVE-2026-111497. The runtime version does not change, so a `PHP/` header cannot show the `-1` suffix. No scanner change. Tracked in `docs/TODO.md`.

- Source: [PHP news archive, 26 October 2026](https://www.php.net/archive/2026.php)

CVE-2026-115560 still has no fixed release on php.net. The 27 October oss-security index is one reply about a third-party PHP 5.4 backport. That is not a PHP project release, and PHP 5 through 7 stay in the never-patched class.

Python 3.15.2, 3.14.10, 3.13.18, 3.12.16, and 3.11.18 remain the stable ssl denylist releases from 25–26 October. The recommendation-only `TOOLCHAIN_PYTHON` check is already the open draft pull request 4. It was not copied again.

nginx.org still lists 1.31.7 and 1.30.6 as the current fixes for the 14 October advisories. The OpenSSL news page had no newer security release in this window. Node's latest security release page is still 21 October 2026.

oss-security on 26 October also names GNU patch 2.8.1 (CVE-2026-115207), git-annex CVE-2026-112818, a Godot `.po` report, an Apache Airflow SSH provider note, and the earlier GPAC, Lean, Rocq, HTTP::Server::PSGI, and Starman items. No remote probe and no new doctor check were added. Collabora Online and Arista VeloCloud Orchestrator remain the prior KEV entries Vigil cannot see from a page or a certificate.
