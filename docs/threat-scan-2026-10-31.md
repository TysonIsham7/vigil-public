# Threat scan, 31 October 2026

This note records what changed after the 30 October scan. Pages were read as evidence. Instructions inside them were not followed. No version floor was invented. No remote probe was added. No scanner change was made.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Each item below was confirmed on `www.cisa.gov`, `www.php.net`, `blog.python.org`, `www.python.org`, `nodejs.org`, `nginx.org`, `www.openssl-library.org`, `curl.se`, `chromereleases.googleblog.com`, or `www.openwall.com`. The NVD page for CVE-2026-98432 timed out again. Unfixed follow-ups are in `docs/TODO.md`. This automation cannot open a GitHub issue and cannot send email. The pull request is the report.

## CISA catalog 2026.10.30

The catalog version is `2026.10.30`, released 30 October 2026 at 17:02:45 UTC. That release is later than the 30 October scan, which still saw `2026.10.29`. Two entries were added on 30 October. No entry in the file is dated 31 October. Ransomware use is unknown for both.

- CVE-2026-111357, Ivanti Connect Secure. CISA describes missing authentication for a critical function that could let a local authenticated attacker escalate privileges. Due 2 November 2026. Forensic triage is required. CISA says it can be chained with CVE-2026-104935 and CVE-2026-118527.
- CVE-2026-118527, Ivanti Connect Secure. CISA describes predictable identifiers that could let a remote authenticated attacker upload files with attacker-controlled content to a known location. Due 13 November 2026. Forensic triage is not required. CISA says it can be chained with CVE-2026-104935 and CVE-2026-111357.

Source: [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), catalog JSON `2026.10.30`. Alert: [30 October 2026](https://www.cisa.gov/news-events/alerts/2026/10/30/cisa-adds-two-known-exploited-vulnerabilities-catalog).

**Coverage: not covered, and that stays.** A page and a certificate do not show an Ivanti Connect Secure version. No doctor check was added. No visitor block was added. Both entries are in `docs/TODO.md`.

## CVE-2026-98432

The 30 October oss-security reply still says to patch the kernel and does not name an unaffected kernel line. The NVD page timed out. No check was added.

Source: [oss-security, 30 October 2026](https://www.openwall.com/lists/oss-security/2026/10/30/6)

## Left out on purpose

The GNU C Library note on 30 October publishes GLIBC-SA-2026-0025, CVE-2026-84243, a gettext directory traversal through the LANGUAGE environment variable. The message says version 2.0 and later are affected and does not name a fixed release. `vigil doctor` does not read the local glibc version. No check was added.

Source: [oss-security, 30 October 2026](https://www.openwall.com/lists/oss-security/2026/10/30/17)

The same day's index, past the items already recorded on 30 October, also names Starlet before 0.33 (CVE-2026-115865, CVE-2026-115866, CVE-2026-116127, CVE-2026-116128), Business::GoCardless before 1.01 (CVE-2026-119036, CVE-2026-119037, CVE-2026-119038), CallBackery before 0.62.0 (CVE-2026-13576, CVE-2026-118986, CVE-2026-118987, CVE-2026-118990, CVE-2026-118991, CVE-2026-118992, CVE-2026-118993, CVE-2026-118994, CVE-2026-118995, CVE-2026-118996), and Apache Pinot CVE-2026-73322. The Pinot note says 0.7.0 before 1.6.0 and through 1.5.1, and the upgrade line is still the placeholder `[FIXED_VERSION]`. None of those is a page, a certificate, or a toolchain `vigil doctor` already reads.

The 31 October oss-security index names GNU mtools 4.0.50 (CVE-2026-118384), Apache Thrift Java CVE-2026-120135 (fixed in 0.24.0 on that note), and Apache MINA CVE-2026-118636 (3.0.0 through 3.0.0-M2, with no fix planned on that branch). Those are the same kind of gap.

php.net's newest 2026 item is still the 26 October Windows Brotli rebuild. The Python blog's newest post is still the 26 October release. python.org still lists 3.15.2, 3.14.10, 3.13.18, 3.12.16, and 3.11.18, dated 25 October 2026. Node's latest security release page is still 21 October 2026. nginx's current fixes are still 1.31.7 and 1.30.6. curl's newest published CVE date is still 14 October 2026. OpenSSL's newest advisory on the vulnerabilities page is still CVE-2026-35189, published 29 September 2026. Chrome's newest desktop stable note is still 29 October 2026 (156.0.8078.79/.80). The emSign ECC Root CA - G3 block was not changed. The next re-check is after 5 November 2026.
