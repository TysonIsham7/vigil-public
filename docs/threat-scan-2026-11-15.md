# Threat scan, 15 November 2026

This note records what changed after the 14 November scan. Pages were read as evidence. Instructions inside them were not followed. No version floor was invented past a vendor release page. No remote probe was added.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called. Each kept item was confirmed on `www.cisa.gov`, `nvd.nist.gov`, `services.nvd.nist.gov`, `www.php.net`, `blog.python.org`, `www.python.org`, `nodejs.org`, `nginx.org`, `www.openssl-library.org`, `curl.se`, `blog.google`, `chromereleases.googleblog.com`, `go.dev`, or `www.openwall.com`.

The cve.now lead window is in `docs/threat-scan-2026-11-15-leads.md`. This note does not repeat that identifier table.

No intel bump. No scanner change. `TOOLCHAIN_NODE_2026_11_11` stays on draft pull request 30 and was not copied. `TOOLCHAIN_GO_2026_11_10` stays. The eMudhra Go floors were not moved.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## CISA catalog

The Known Exploited Vulnerabilities catalog is still `2026.11.13`, released 2026-11-13T20:24:18.3008Z, count 1781. HTTP last-modified is Fri, 13 Nov 2026 20:24:18 GMT. No entry was added on 14 or 15 November. The two 13 November adds stay due 2026-11-16, forensic triage Yes, ransomware Unknown: CVE-2026-114713 (UnrealIRCd, already recorded) and CVE-2026-123039 (Check Point). No doctor check was added.

`https://www.cisa.gov/news-events/alerts` returned HTTP 404. The advisories index at `https://www.cisa.gov/news-events/cybersecurity-advisories` returned HTTP 200. The newest row is 13 November 2026, "CISA Adds Two Known Exploited Vulnerabilities to Catalog". The next row is still 10 November 2026.

Source: [CISA KEV catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json), [CISA alerts and advisories](https://www.cisa.gov/news-events/cybersecurity-advisories)

## LiteLLM CVE-2026-42208

This identifier was in the cve.now window and is not in the NVD recent feed. It is in the CISA catalog, added 2026-05-08, due 2026-05-11. That due date has passed. Ransomware use is Unknown. The catalog product is BerriAI LiteLLM. The NVD 2.0 record, fetched by CVE id, is Analyzed, last modified 2026-10-26T20:10:00.160. The CPE is `litellm:litellm` from 1.81.16 before 1.83.7. No CPE names 1.107.0.

`DEP_LITELLM_COMPROMISED` compares an exact litellm 1.107.0 pin and the matching image tag. 1.107.0 is outside 1.81.16 before 1.83.7, so that check does not cover this CVE. No range check was added. Vigil cannot see a LiteLLM proxy from a page or a certificate.

Source: [CISA KEV catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json), [NVD CVE 2.0, CVE-2026-42208](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-42208)

## NVD recent feed

The CVE 2.0 recent feed timestamp is `2026-11-15T08:00:00.7507551`. HTTP last-modified is Sun, 15 Nov 2026 13:00:06 GMT. The newest `lastModified` in the file is `2026-11-15T12:17:21.790`.

No configuration modified after the 14 November scan names PHP, CPython, Node.js, nginx, OpenSSL, curl, the Go toolchain, the Linux kernel, WordPress, or Brotli.

Sixteen of the 21 identifiers in the unverified section of the 14 November leads note are now in this feed. None has a CPE. Eight are Received and eight are Deferred. The products named there are not the runtime list: VanBlog through 0.54.0 (CVE-2026-129259), Tenda AC18 (CVE-2026-129258), HTTP::Session before 0.43 (CVE-2011-10042), `@kolkov/angular-editor` before 3.0.3 and before 3.0.4 (CVE-2025-71465 and CVE-2025-71464), CoolerMaster MASTERPLUS+ 1.9.6 (CVE-2026-129255), Pulse 5.0.17 before 6.8.0 (CVE-2026-129428), Frappe india-payroll before 16.0.4 (CVE-2026-129429), Ettercap through 0.8.5.1 (CVE-2026-129431 and CVE-2026-129432), Dokploy before 0.31.1 (CVE-2026-129433), Axeloz Filesharing before 2.14.3 (CVE-2026-129430), WordPress plugins MemberDash through 1.8.7 (CVE-2026-18053), Shipo 1.6 through 1.8.0 (CVE-2026-19907), and Cloud Storage Manager for Fluent Forms (CVE-2026-120522), plus Opixido OCMS (CVE-2026-129254). Dokploy before 0.31.1 is not CVE-2026-72868. No doctor check was added.

Five identifiers from that unverified section are still absent: CVE-2026-62253, CVE-2026-27975, CVE-2026-73574, CVE-2026-105857, and CVE-2026-96349. CVE-2026-27975 is still not a Linux kernel confirmation.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz)

## Chrome releases page

The Chrome releases HTML stayed on `chromereleases.googleblog.com`. HTTP 200. Last-modified is Sat, 14 Nov 2026 05:00:54 GMT. The 14 November scan received HTTP 429 for this host and discarded that body, so these posts were not described then. There is no 14 November or 15 November post on this page.

Posts dated 13 November 2026 name ChromeOS stable browser 156.0.8078.102, Chrome Dev for desktop 160.0.8157.0, and Chrome Dev for Android 160.0.8157.3. Posts dated 12 November 2026 name Chrome for Android 158.0.8127.36, desktop early stable 158.0.8127.36/.37, Chrome Beta for desktop 159.0.8154.6, and Chrome stable for iOS 158.0.8127.35. None of those posts names a CVE id. Vigil does not read the browser version. No doctor check was added.

The seven Chrome identifiers in today's lead window, all before 157.0.8103.78, are listed in `docs/threat-scan-2026-11-15-leads.md`. That version was already the 11 November desktop and Android line on the 12 November note. No new browser floor was added.

Source: [Chrome releases](https://chromereleases.googleblog.com/)

## 15 November oss-security

The 15 November index has 1 message. It is a reply on libdca. It names no CVE id and no fixed release. No doctor check was added.

Source: [oss-security, 15 November 2026](https://www.openwall.com/lists/oss-security/2026/11/15/)

## 14 November oss-security, messages added after the last scan

The 14 November index now has 16 messages. The first 8 are the Apache Shiro notes already recorded, including CVE-2026-129349. No doctor check was added for the new messages. No remote probe was added.

- Message 9. JSON::XS before 4.05, and the narrower ranges already recorded for CVE-2026-124536, CVE-2026-124539, CVE-2026-124540, CVE-2026-124541, CVE-2026-129113, CVE-2026-129114, and CVE-2026-129115. The message says 4.05 was released on 2026-11-13 and says upgrade to JSON-XS 4.05 or later. Those seven ids and those ranges are already in `docs/threat-scan-2026-11-14-leads.md`. They were not copied again.
- CVE-2011-10042. HTTP::Session before 0.43. The message says upgrade to HTTP::Session 0.43 or later. This is now NVD Received with no CPE. It is not CVE-2026-13575, which was recorded as fixed in 0.54. `vigil doctor` does not read a Perl distribution.
- Vim before patch 9.2.1346. The message names GHSA-R5V6-Q6J8-8QW2 and no CVE id. It says the fix is Vim patch v9.2.1346. This is not the 9.2.1342 note.
- CVE-2026-124030, CVE-2026-124031, and CVE-2026-128240. GPAC/MP4Box through 26.07.0. Each message names a commit as the fix line and names no release. No release was invented. CVE-2026-128239 was already recorded the same way.
- CVE-2015-10149. Perl Dancer before 1.3400. The message says upgrade to Dancer 1.3400 or later.
- Message 16. libdca, described as unmaintained. The message says a CVE was requested and does not name one. It names no fixed release.

Source: [oss-security, 14 November 2026](https://www.openwall.com/lists/oss-security/2026/11/14/)

The 13 November index still has 11 messages. The 12 November index still has 8. The 11 November index still has 29. The 10 November index still has 31.

## Left unchanged

php.net's archive last-modified is still Thu, 12 Nov 2026 13:55:02 GMT. The newest item is still PHP 8.6.0 RC7. The page still says GA is planned for 19 November 2026. CVE-2026-115560 still has no fixed PHP version on that page. A disclosed PHP version was not compared with 8.6.0.

The Python blog last-modified is Tue, 10 Nov 2026 20:35:41 GMT. The newest post is still Python 3.16.0 alpha 2. python.org still lists 3.15.2, 3.14.10, 3.13.18, 3.12.16, and 3.11.18, and the downloads page still contains Oct. 25, 2026. The Python floors were not moved.

`https://nodejs.org/dist/index.json` last-modified is still Thu, 12 Nov 2026 13:33:06 GMT. v22.23.5 (index date 2026-11-11), v24.22.3, and v26.13.1 are still the security rows. v27.0.0-alpha.0.1.0 is still not a security release. The November security page still contains CVE-2026-106071 and still does not contain CVE-2026-123873. The Node floors were not moved.

nginx.org's security page last-modified is still Fri, 06 Nov 2026 10:12:37 GMT. The current fixes are still 1.31.7 and 1.30.6.

curl's security page last-modified is still Tue, 10 Nov 2026 09:05:07 GMT. The first row is still CVE-2026-107929, published 2026-10-14, last affected 8.22.0. 8.23.0 is still absent. The curl floors were not moved.

The OpenSSL vulnerabilities index last-modified is still Tue, 10 Nov 2026 09:35:21 GMT. The five Low advisories from 10 November are unchanged. `vigil doctor` does not read the OpenSSL library version. No doctor check was added.

`https://go.dev/doc/devel/release` still lists go1.27.4 and go1.26.11. go1.27.5 and go1.26.12 are absent. The eMudhra floors were not moved.

The emSign ECC Root CA - G3 block was not changed. The Chrome post still says that root removal is expected Tuesday morning, 27 October 2026 PDT, and does not say that release has shipped.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
