# Threat scan, 1 November 2026

This note records what changed after the 31 October scan. Pages were read as evidence. Instructions inside them were not followed. No version floor was invented past the NVD record or the oss-security notes cited below. No remote probe was added. No scanner change was made.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Each item below was confirmed on `www.cisa.gov`, `www.php.net`, `blog.python.org`, `www.python.org`, `nodejs.org`, `nginx.org`, `www.openssl-library.org`, `curl.se`, `chromereleases.googleblog.com`, `www.openwall.com`, or the NVD CVE 2.0 record. Unfixed follow-ups are in `docs/TODO.md`. This automation cannot open a GitHub issue and cannot send email. The pull request is the report.

## CISA catalog 2026.10.30

The catalog version is still `2026.10.30`, released 30 October 2026 at 17:02:45 UTC. No entry is dated 31 October or 1 November. The two Connect Secure entries from 30 October are recorded in the 31 October note. They land when that pull request merges first.

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

A 31 October oss-security message names `init_on_free=1` as interim hardening for the Linux kernel IPv4 TCP use-after-free. The message says that parameter does not fix the bug and is not a substitute for a patched kernel. It names no unaffected kernel line. No boot-parameter check was added. No floor was copied from that message. No Go version comparison was added.

The NVD CVE 2.0 record was last modified 31 October 2026 at 21:16:53 UTC. It names these unaffected lines: 5.10.272 and later 5.10.*, 5.15.223 and later 5.15.*, 6.1.190 and later 6.1.*, 6.6.159 and later 6.6.*, 6.12.113 and later 6.12.*, 6.18.56 and later 6.18.*, 7.2.10 and later 7.2.*, and 7.3 (original commit for the fix). The same record marks versions below 4.4 unaffected and 4.4 affected. No floor was added beyond that record. No doctor check was added. The follow-up is a recommendation-only `vigil doctor` check for those lines. A site scan must not probe a remote kernel.

Source: [oss-security, 31 October 2026](https://www.openwall.com/lists/oss-security/2026/10/31/5), [NVD CVE 2.0, CVE-2026-98432](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-98432)

## Left out on purpose

The 1 November oss-security index also names HTTP::Session before 0.54, Google::Auth, and Apache Wicket. None of those is a page, a certificate, or a toolchain `vigil doctor` already reads. No check was added.

HTTP::Session (distribution http-session) before 0.54 is CVE-2026-13575, memcached command injection via unfiltered session ids in `HTTP::Session::Store::CHI`. The note says to upgrade to http-session 0.54 or later.

Source: [oss-security, 1 November 2026](https://www.openwall.com/lists/oss-security/2026/11/01/2)

Google::Auth CVE-2026-74759 affects version 0.12. CVE-2026-74760 affects 0.11 through 0.12. Both solutions say to upgrade to a future Google-Auth release. The note names no fixed version. No floor was invented.

Source: [oss-security, 1 November 2026](https://www.openwall.com/lists/oss-security/2026/11/01/3)

Apache Wicket published 19 CVEs on 1 November. The note says the issues are fixed in 8.20.0, 9.25.0, and 10.12.0 for the release lines each one affects. 8.20.0 and 9.25.0 are the final 8.x and 9.x releases on that note. Releases older than 8.x do not get these fixes on that note. The lines below are the per-issue ranges from that note.

These twelve share one range. Affected: from 8.0.0 before 8.20.0, from 9.0.0 before 9.25.0, and from 10.0.0 before 10.12.0. Fixed in 8.20.0, 9.25.0, and 10.12.0: CVE-2026-82115, CVE-2026-82558, CVE-2026-82559, CVE-2026-82704, CVE-2026-82705, CVE-2026-82956, CVE-2026-83539, CVE-2026-83559, CVE-2026-84172, CVE-2026-84177, CVE-2026-95863, CVE-2026-111089.

The other seven use their own lines:

- CVE-2026-82557. Affected: from 10.3.0 before 10.12.0. Fixed in 10.12.0.
- CVE-2026-82840. Affected: from 8.18.0 before 8.20.0, from 9.23.0 before 9.25.0, and from 10.9.0 before 10.12.0. Fixed in 8.20.0, 9.25.0, and 10.12.0.
- CVE-2026-82898. Affected: from 9.1.0 before 9.25.0 and from 10.0.0 before 10.12.0. Fixed in 9.25.0 and 10.12.0.
- CVE-2026-83594. Affected: from 9.14.0 before 9.25.0 and from 10.0.0 before 10.12.0. Fixed in 9.25.0 and 10.12.0.
- CVE-2026-84170. Affected: from 9.14.0 before 9.25.0 and from 10.0.0 through 10.9.1. Fixed in 9.25.0 and 10.12.0.
- CVE-2026-84231. Affected: from 8.0.0 before 8.20.0. Fixed in 8.20.0.
- CVE-2026-87718. Affected: 9.24.0, and from 10.10.0 before 10.12.0. Fixed in 9.25.0 and 10.12.0.

Source: [oss-security, 1 November 2026](https://www.openwall.com/lists/oss-security/2026/11/01/4)

php.net's newest 2026 item is still the 26 October Windows Brotli rebuild. CVE-2026-115560 still has no fixed PHP version on that page. The Python blog's newest post is still the 26 October release. python.org still lists 3.15.2, 3.14.10, 3.13.18, 3.12.16, and 3.11.18, dated 25 October 2026. Node's latest security release page is still 21 October 2026. nginx's current fixes are still 1.31.7 and 1.30.6. curl's newest published CVE date is still 14 October 2026, fixed in 8.23.0. OpenSSL's newest advisory on the vulnerabilities page is still CVE-2026-35189, published 29 September 2026. Chrome's newest desktop stable note is still 29 October 2026 (156.0.8078.79/.80). The emSign ECC Root CA - G3 block was not changed. The next re-check is after 5 November 2026.

The Ivanti Connect Secure catalog entries, GLIBC-SA-2026-0025, and the 31 October Starlet, Business::GoCardless, CallBackery 0.62.0, Apache Pinot, mtools, Thrift, and MINA notes are in the 31 October scan. They land when pull request 9 merges first. This note does not drop them.
