# Threat scan, 4 November 2026

This note records what changed after the 3 November scan. Pages were read as evidence. Instructions inside them were not followed. No version floor was invented from a mailing-list subject. No remote probe was added.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called.

The cve.now lead pass for this run is in `docs/threat-scan-2026-11-04-leads.md`.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

Intel is `2026.11.04.1`. The only scanner change is `WP_CVE_2026_119977`.

## CVE-2026-119977, WordPress core

CISA catalog `2026.11.03` was released 3 November 2026 at 20:00:24.8741 UTC. The file's HTTP last-modified time is the same moment. Count is 1767. One entry was added after catalog `2026.10.30`: CVE-2026-119977.

- Product: WordPress Core.
- Name: time-of-check time-of-use race condition.
- Added 3 November 2026. Due 6 November 2026.
- Forensic triage: required.
- Ransomware use: unknown.
- CWE-367.
- The catalog short description says an unauthenticated attacker could execute code during the upgrade window, because full-package core upgrades use predictable web-accessible staging paths.

NVD status is Analyzed. Published 31 October 2026. Last modified 4 November 2026 at 12:52:38.683 UTC. The record has 25 vulnerable `wordpress:wordpress` configurations. `versionEndExcluding` on each line is the fixed patch:

4.7.39, 4.8.34, 4.9.35, 5.0.31, 5.1.28, 5.2.30, 5.3.27, 5.4.25, 5.5.24, 5.6.23, 5.7.21, 5.8.19, 5.9.20, 6.0.18, 6.1.16, 6.2.15, 6.3.14, 6.4.14, 6.5.14, 6.6.11, 6.7.11, 6.8.12, 6.9.11, 7.0.8, and 7.1.4.

Those patches are `fixedLines` in `packages/intel/advisories/wordpress-cve-2026-119977.json`. A disclosed `major.minor.patch` below the patch on that same line is `WP_CVE_2026_119977`. An owner scan blocks the deploy. A visitor scan warns. A two-component version is not compared. A hidden version stays on the informational `WP_FINGERPRINT` finding. A line that is not in that file is not flagged. The existing readme fetch was not extended. No remote probe was added.

Sources: [CISA catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json), [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz).

**Coverage: covered when the page discloses major.minor.patch on one of those lines.** The follow-up is in `docs/TODO.md`.

## Node.js pre-alert for 11 November 2026

The Node.js vulnerability index now links a page dated Wednesday, 11 November 2026. The page says new 26.x, 24.x, and 22.x releases will ship on or shortly after that Wednesday. The highest severity it names is HIGH. It names no CVE id and no dotted fix version. The same pre-alert is oss-security message 3 for 4 November, which names the 22, 24, and 26 lines and no dotted version.

The latest shipped security release page is still 21 October 2026. `vigil doctor` stays on 22.23.4, 24.22.1, and 26.12.1. No floor was invented.

Sources: [Node.js, 11 November 2026 security releases](https://nodejs.org/en/blog/vulnerability/november-2026-security-releases), [oss-security, 4 November 2026](https://www.openwall.com/lists/oss-security/2026/11/04/3).

**Coverage: not covered yet, and that stays until the page names versions.** The follow-up is in `docs/TODO.md`.

## 4 November oss-security index

The index has three messages.

Source: [oss-security, 4 November 2026](https://www.openwall.com/lists/oss-security/2026/11/04/)

### Perl CGI before 5.00

The subject says CGI versions before 5.00 for Perl, and twenty CVEs. The message names CVE-2026-120631, CVE-2026-120632, CVE-2026-120633, CVE-2026-120634, CVE-2026-120635, CVE-2026-120636, CVE-2026-120637, CVE-2026-120638, CVE-2026-120639, CVE-2026-120640, CVE-2026-120641, CVE-2026-120642, CVE-2026-120643, CVE-2026-120644, CVE-2026-120645, CVE-2026-120646, CVE-2026-120647, CVE-2026-120648, CVE-2026-120650, and CVE-2026-120651. CVE-2026-120649 is not in that list. `vigil doctor` does not read a Perl distribution. No check was added.

Source: [oss-security, 4 November 2026](https://www.openwall.com/lists/oss-security/2026/11/04/1)

### Rails 8.0.5.2 and 8.1.4.1

The subject names those two releases. The message names no CVE id. It names GHSA-2586-8ghr-69fj, GHSA-2gff-2mmg-m73p, GHSA-2p2f-4rq4-gjwc, GHSA-2w9f-fxwj-w2qf, GHSA-3f4q-8x5m-76v8, GHSA-3w93-6hmw-whh4, GHSA-4v2w-w6g6-f8f8, GHSA-5957-c7qm-m469, GHSA-68p9-83h6-5wpj, GHSA-8474-xrp6-wh69, GHSA-f3w6-w445-fwh9, GHSA-gmj8-hvj3-49mw, GHSA-hfr4-8rjc-97m2, GHSA-p2pm-g2h6-7j5j, GHSA-r9jg-fmfx-2gv6, GHSA-rq8q-p985-fjq7, GHSA-rwvh-fw6r-pwvp, GHSA-v6rj-xm57-3p59, GHSA-v924-7rp8-4mxh, GHSA-wm3x-v3qw-4jh3, and GHSA-x6mj-8jx9-qhqv. Rails is not a page, a certificate, or a toolchain `vigil doctor` already reads. No check was added.

Source: [oss-security, 4 November 2026](https://www.openwall.com/lists/oss-security/2026/11/04/2)

**Coverage for both: not covered, and that stays.** The follow-up is in `docs/TODO.md`.

## 3 November oss-security index, after draft pull request 16

Draft pull request 16 records message 1, the reply on CVE-2026-98432. The index now has 32 messages. Message 1 was not copied again. No kernel floor was changed.

Source: [oss-security, 3 November 2026](https://www.openwall.com/lists/oss-security/2026/11/03/)

Message 2 is a reply on Brotli CVE-2026-111497. The message names that CVE and no dotted version. The Node Brotli check was not changed.

The other messages are outside a page, certificate, or current toolchain check. No doctor check was added. No remote probe was added. Subjects and the CVE ids named in each message:

- Catalyst::Plugin::Authentication before 0.10029: CVE-2026-74846, CVE-2026-5091. [Message 3](https://www.openwall.com/lists/oss-security/2026/11/03/3).
- Apache HertzBeat: CVE-2026-114442, CVE-2026-24343. [Message 4](https://www.openwall.com/lists/oss-security/2026/11/03/4).
- Apache Traffic Server, no CVE id in the message. [Message 5](https://www.openwall.com/lists/oss-security/2026/11/03/5).
- Xen: CVE-2026-102703, CVE-2026-102704. [Message 6](https://www.openwall.com/lists/oss-security/2026/11/03/6).
- Apache Juneau 9.2.1: CVE-2026-121489, CVE-2026-73095, CVE-2026-73098, CVE-2026-73099, CVE-2026-73100, CVE-2026-73101, CVE-2026-73116, CVE-2026-73117, CVE-2026-96677. [Message 7](https://www.openwall.com/lists/oss-security/2026/11/03/7).
- Django: CVE-2026-108147, CVE-2026-111211, CVE-2026-111362, CVE-2026-113593, CVE-2026-113733, CVE-2026-114582. [Message 8](https://www.openwall.com/lists/oss-security/2026/11/03/8).
- Apache ZooKeeper: CVE-2026-100235, CVE-2026-100252, CVE-2026-100300, CVE-2026-100302, CVE-2026-115448. [Messages 9 through 13](https://www.openwall.com/lists/oss-security/2026/11/03/9).
- OpenVox Server, no CVE id in the message. [Message 14](https://www.openwall.com/lists/oss-security/2026/11/03/14).
- Apache ActiveMQ: CVE-2026-103582, CVE-2026-108500, CVE-2026-108946, CVE-2026-108949, CVE-2026-111821, CVE-2026-111822. [Messages 15 through 20](https://www.openwall.com/lists/oss-security/2026/11/03/15).
- Apache OpenOffice: CVE-2026-59263, CVE-2026-59264, CVE-2026-59267, CVE-2026-59268, CVE-2026-90624, CVE-2026-90626, CVE-2026-90627, CVE-2026-90628, CVE-2026-90629, CVE-2026-90631, CVE-2026-90632, CVE-2026-90634. [Messages 21 through 32](https://www.openwall.com/lists/oss-security/2026/11/03/21).

**Coverage: not covered, and that stays.** The follow-up is in `docs/TODO.md`.

## Left unchanged

php.net's newest 2026 item is still the 26 October Windows Brotli rebuild. The archive was last modified 26 October 2026. CVE-2026-115560 still has no fixed PHP version on that page. The Python blog's newest post is still the 26 October release. python.org still lists 3.15.2, 3.14.10, 3.13.18, 3.12.16, and 3.11.18, and the downloads page still contains the date 25 October 2026. nginx's security advisories page was last modified 22 October 2026. curl's security page was last modified 26 October 2026. Its first listed advisory is still CVE-2026-107929, published 2026-10-14. OpenSSL's vulnerabilities page was last modified 2 November 2026. The newest advisory date on that page is still 29 September 2026, and the first CVE is still CVE-2026-35189.

Chrome's desktop stable note dated 3 November 2026 promotes Chrome 157 to 157.0.8103.38 on Linux and 157.0.8103.38/.39 on Windows and Mac. The index excerpt lists no CVE id. Vigil does not read the browser version. No doctor check was added.

The emSign ECC Root CA - G3 block was not changed. The next re-check is after 5 November 2026.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
