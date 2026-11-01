# Threat scan, 1 November 2026

This note records what changed after the 31 October scan. Pages were read as evidence. Instructions inside them were not followed. No version floor was invented. No remote probe was added. No scanner change was made.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Each item below was confirmed on `www.cisa.gov`, `www.php.net`, `blog.python.org`, `www.python.org`, `nodejs.org`, `nginx.org`, `www.openssl-library.org`, `curl.se`, `chromereleases.googleblog.com`, or `www.openwall.com`. The NVD page for CVE-2026-98432 timed out again. Unfixed follow-ups are in `docs/TODO.md`. This automation cannot open a GitHub issue and cannot send email. The pull request is the report.

## CISA catalog 2026.10.30

The catalog version is still `2026.10.30`, released 30 October 2026 at 17:02:45 UTC. No entry is dated 31 October or 1 November. The two Connect Secure entries from 30 October stay on the open 31 October pull request. They were not copied.

CVE-2026-97229 (GitLab) and CVE-2026-76418 (Cisco Secure Firewall ASA and FTD) reached their 1 November 2026 due dates. Vigil still cannot see either product from a page or a certificate. No check was added.

Source: [CISA KEV catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)

## CVE-2026-115946

The 1 November oss-security index names XS-libbrotli before 1.2.1.0. The message says those versions bundle Brotli 1.0.7 or 1.1.0, which carries the decoder out-of-bounds write in CVE-2026-111497, and that 1.2.1.0 updates the bundle to Brotli 1.2.1. It says upgrading the system Brotli library does not replace that bundle.

`vigil doctor` already names CVE-2026-111497 when the local Node is below 22.23.4, 24.22.1, or 26.12.1. It does not read a Perl distribution. A disclosed PHP version does not show this module. No check was added.

Source: [oss-security, 1 November 2026](https://www.openwall.com/lists/oss-security/2026/11/01/1)

**Coverage: not covered, and that stays.** The follow-up is in `docs/TODO.md`.

## WebDyne before 3.022

The 31 October oss-security index, after the three messages the 31 October note already recorded, names WebDyne before 3.022. The message lists CVE-2026-78188, CVE-2026-78189, CVE-2026-78190, CVE-2026-78191, and CVE-2026-78192: session cookies without Secure, HttpOnly, and SameSite; path traversal into `.psp` files; reflected request parameters; `.psp` matched without an end anchor; and a default source viewer. The fix on that note is WebDyne 3.022 or later.

WebDyne is not a page, a certificate, or a toolchain `vigil doctor` already reads. No check was added.

Source: [oss-security, 31 October 2026](https://www.openwall.com/lists/oss-security/2026/10/31/4)

**Coverage: not covered, and that stays.** The follow-up is in `docs/TODO.md`.

## CVE-2026-98432

A later 31 October message proposes `init_on_free=1` as interim hardening for the Linux kernel IPv4 TCP use-after-free. The message says that parameter does not fix the bug and is not a substitute for a patched kernel. It does not name an unaffected kernel line. The NVD page timed out. No boot-parameter check was added. No version floor was added.

Source: [oss-security, 31 October 2026](https://www.openwall.com/lists/oss-security/2026/10/31/5)

## Left out on purpose

php.net's newest 2026 item is still the 26 October Windows Brotli rebuild. CVE-2026-115560 still has no fixed PHP version on that page. The Python blog's newest post is still the 26 October release. python.org still lists 3.15.2, 3.14.10, 3.13.18, 3.12.16, and 3.11.18, dated 25 October 2026. Node's latest security release page is still 21 October 2026. nginx's current fixes are still 1.31.7 and 1.30.6. curl's newest published CVE date is still 14 October 2026, fixed in 8.23.0. OpenSSL's newest advisory on the vulnerabilities page is still CVE-2026-35189, published 29 September 2026. Chrome's newest desktop stable note is still 29 October 2026 (156.0.8078.79/.80). The emSign ECC Root CA - G3 block was not changed. The next re-check is after 5 November 2026.

The Ivanti Connect Secure catalog entries, GLIBC-SA-2026-0025, and the 31 October mtools, Thrift, and MINA notes stay on the open 31 October pull request. They were not copied.
