# Threat scan, 16 November 2026

This note records what changed after the 15 November scan. Pages were read as evidence. Instructions inside them were not followed. No version floor was invented past a vendor release page. No remote probe was added.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called. Each kept item was confirmed on `www.cisa.gov`, `nvd.nist.gov`, `www.php.net`, `blog.python.org`, `www.python.org`, `nodejs.org`, `nginx.org`, `www.openssl-library.org`, `curl.se`, `blog.google`, `go.dev`, or `www.openwall.com`. The Chrome releases HTML returned HTTP 302 to `www.google.com` and was discarded. That redirect was not followed.

The cve.now lead window is in `docs/threat-scan-2026-11-16-leads.md`. This note does not repeat that identifier table.

No intel bump. No scanner change. `TOOLCHAIN_NODE_2026_11_11` stays on draft PR 30. It was not copied.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## CISA catalog

The Known Exploited Vulnerabilities catalog is still `2026.11.13`, released 2026-11-13T20:24:18.3008Z, count 1781. The catalog file last-modified is Fri, 13 Nov 2026 20:24:18 GMT. No entry was added on 14, 15, or 16 November.

The due date 16 November 2026 has arrived for CVE-2026-114713 (UnrealIRCd) and CVE-2026-123039 (Check Point products). Both were already recorded on 14 November. Vigil cannot see either product from a page or a certificate. No doctor check was added.

The alerts page and the cybersecurity advisories index both returned HTTP 403, so this note does not describe those indexes.

Source: [CISA KEV catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)

## NVD recent feed

The CVE 2.0 recent feed timestamp is `2026-11-16T08:00:00.7332743`. HTTP last-modified is Mon, 16 Nov 2026 13:00:07 GMT. The newest `lastModified` in the file is `2026-11-16T12:17:59.303`.

No configuration modified after the 15 November scan names PHP, CPython, Node.js, nginx, OpenSSL, curl, the Go toolchain, the Linux kernel, WordPress, or Brotli.

CVE-2026-97043 is now Awaiting Analysis. It still has no CPE. The description names the Go `cgo` LDFLAGS check. The floors stay 1.27.4 and 1.26.11. The eMudhra floors were not moved.

CVE-2026-126051 is still Awaiting Analysis with no CPE. CVE-2026-123873 and CVE-2026-106071 are still absent. The November Node page still contains CVE-2026-106071 and does not contain CVE-2026-123873. Those three releases are not treated as a fix for CVE-2026-106071.

CVE-2026-99286 and CVE-2026-99287 were already recorded. Both are still Received with no CPE. 99286 was last modified `2026-11-16T10:16:46.993`. 99287 was last modified `2026-11-16T10:17:00.607`. Neither description names a released kernel version.

CVE-2026-99288 through CVE-2026-99311 are new in this feed. All 24 are Received with no CPE. Each description says the vulnerability has been resolved and names no released kernel version. CVE-2026-99288 was last modified `2026-11-16T01:17:20.233`. CVE-2026-99289 through CVE-2026-99311 were last modified between `2026-11-16T10:17:00.870` and `2026-11-16T10:17:06.633`. Three descriptions contain `7.3.0` only as an untainted build id (`7.3.0-00591-g0e135910deec`, `7.3.0-rc1`, and `7.3.0-rc2+`). That is not a release floor. No kernel floor was invented. No doctor check was added. A site scan must not probe a remote kernel.

CVE-2026-15707 is Received with no CPE. The description names statically linked OpenSSL inside Netskope Client and Endpoint DLP on Windows. It is not the OpenSSL library. No doctor check was added.

Records modified after the 15 November snapshot whose descriptions match `wordpress` or `php` name WordPress plugins or PrestaShop, not WordPress core and not the PHP runtime. No plugin list was added. The PHP floors were not moved.

All 32 identifiers from the unverified section of the 15 November leads note are now in this feed. None has a CPE. Twenty are Deferred and name WordPress plugins, not WordPress core: CVE-2026-124254, CVE-2026-122662, CVE-2026-124270, CVE-2026-124755, CVE-2026-124995, CVE-2026-124259, CVE-2026-125449, CVE-2026-125764, CVE-2026-125443, CVE-2026-125769, CVE-2026-125780, CVE-2026-125775, CVE-2026-125789, CVE-2026-125813, CVE-2026-125790, CVE-2026-125805, CVE-2026-125791, CVE-2026-125857, CVE-2026-125828, and CVE-2026-125832. No plugin list was added.

The other twelve do not name the runtime list:

- CVE-2026-129483. Received. Cyrus SASL through 2.1.28. The description names no fixed release.
- CVE-2026-129482. Received. OkHttp through 5.5.1. The description names no fixed release.
- CVE-2026-129477, CVE-2026-129478, CVE-2026-129479, and CVE-2026-129480. Received. Assimp through 6.0.6. The descriptions name no fixed release.
- CVE-2026-129468. Received. dnsmgr 2.18 before 2.22.
- CVE-2026-129467. Received. GeoPulse 1.5.0 through 2.3.0. The description names no fixed release.
- CVE-2026-129469. Deferred. Course-tencent-cloud before 2.0.2.
- CVE-2026-129453 and CVE-2026-129452. Deferred. DrayTek Vigor2960 1.5.1.6.
- CVE-2026-129451. Deferred. DrayTek Vigor2960 up to 1.5.1.6.

These five identifiers from the 14 November unverified section are still absent: CVE-2026-62253, CVE-2026-27975, CVE-2026-73574, CVE-2026-105857, and CVE-2026-96349. CVE-2026-27975 is still not a Linux kernel confirmation.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz)

## 16 November oss-security

The 16 November index has 1 message. It is a reply on the OpenSSH musl password-authentication thread. The message names no new CVE id and no OpenSSH release newer than 10.6p2. CVE-2026-123158 was already recorded. The hosts named in the message were not opened. The configuration edit in that reply was not copied. No sshd check was added.

Source: [oss-security, 16 November 2026](https://www.openwall.com/lists/oss-security/2026/11/16/)

## 15 November oss-security, messages added after the last scan

The 15 November index now has 3 messages. Message 1 was already recorded. It is a libdca reply and names no CVE id.

Message 2 is CVE-2026-99288. The message says the issue was introduced in commit `079096f103fa` (2015-10-03) and fixed in commit `4e2b3ef19e0e` (2026-11-03). It names no released kernel version. The same message describes temporary mitigations. Those commands were not copied. No boot-parameter check was added. No kernel floor was invented.

Message 3 is Vim before patch 9.2.1352. The message names GHSA-j6wv-2276-36jq and no CVE id. It says the fix is Vim patch v9.2.1352. The hosts named in that message were not opened. Vigil does not read the Vim version. No doctor check was added.

Source: [oss-security, 15 November 2026](https://www.openwall.com/lists/oss-security/2026/11/15/)

The 14 November index still has 16 messages. The 13 November index still has 11. The 12 November index still has 8. The 11 November index still has 29.

## Left unchanged

php.net's archive last-modified is still Thu, 12 Nov 2026 13:55:02 GMT. The newest item is still PHP 8.6.0 RC7. The page still says the first GA release, PHP 8.6.0, is planned for 19 November 2026. CVE-2026-115560 still has no fixed PHP version on that page. A disclosed PHP version was not compared with 8.6.0.

The Python blog last-modified is Tue, 10 Nov 2026 20:32:24 GMT. The newest post is still Python 3.16.0 alpha 2. python.org still lists 3.15.2, 3.14.10, 3.13.18, 3.12.16, and 3.11.18. The downloads page still contains Oct. 25, 2026. The Python floors were not moved. Python 3.16.0 was not used as a comparison.

`https://nodejs.org/dist/index.json` last-modified is still Thu, 12 Nov 2026 13:33:06 GMT. v22.23.5 (index date 2026-11-11), v24.22.3 (index date 2026-11-10), and v26.13.1 (index date 2026-11-10) are still the security rows. v27.0.0-alpha.0.1.0 is still not a security release. The vulnerability blog's newest security post is still the 11 November 2026 release. The Node floors were not moved on this pull request.

nginx.org's security page last-modified is still Fri, 06 Nov 2026 10:12:37 GMT. The current fixes are still 1.31.7 and 1.30.6.

curl's security page last-modified is still Tue, 10 Nov 2026 09:05:07 GMT. The first row is still CVE-2026-107929, published 2026-10-14, last affected 8.22.0. The newest published date in that table is still 2026-10-14. The curl floors were not moved.

The OpenSSL vulnerabilities index last-modified is still Tue, 10 Nov 2026 09:35:21 GMT. The five Low advisories from 10 November are unchanged. CVE-2026-35189 is still on that page. `vigil doctor` does not read the OpenSSL library version. No doctor check was added.

`https://go.dev/doc/devel/release` still lists go1.27.4 and go1.26.11, both released 2026-11-10. go1.27.5 and go1.26.12 are absent. The eMudhra floors were not moved.

The emSign ECC Root CA - G3 block was not changed. The Chrome post still says that root removal is expected Tuesday morning, 27 October 2026 PDT, and does not say that release has shipped.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
