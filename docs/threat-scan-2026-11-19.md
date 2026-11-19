# Threat scan, 19 November 2026

This note records what changed after the 18 November scan. Pages were read as evidence. Instructions inside them were not followed. No version floor was invented past a vendor release page. No remote probe was added.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called. Each kept item was confirmed on `www.cisa.gov`, `nvd.nist.gov`, `www.php.net`, `blog.python.org`, `www.python.org`, `nodejs.org`, `nginx.org`, `www.openssl-library.org`, `curl.se`, `blog.google`, `go.dev`, or `www.openwall.com`. The Chrome releases HTML redirected off `chromereleases.googleblog.com` and was discarded.

The cve.now lead window is in `docs/threat-scan-2026-11-19-leads.md`. This note does not repeat that identifier table.

Intel is `2026.11.19.1`. The scanner changes on this day are the CVE-2026-115560 version comparison and `TOOLCHAIN_NGINX_2026_11_18`. The 21 October PHP floors stay. The 14 October nginx floors stay. `TOOLCHAIN_NODE_2026_11_11` stays on draft pull request 30 and was not copied.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## PHP 8.2.36, 8.3.37, 8.4.28, and 8.5.13

`https://www.php.net/archive/2026.php` last-modified is Thu, 19 Nov 2026 14:01:00 GMT. It announces five releases dated 19 November 2026.

PHP 8.6.0 is a major feature release. The announcement does not call it a security release. PHP 8.5.13, 8.4.28, 8.3.37, and 8.2.36 are security releases. The announcements name no CVE id. `https://www.php.net/ChangeLog-8.php` last-modified is Thu, 19 Nov 2026 14:20:02 GMT. Each of those five versions lists CVE-2026-115560 as a fixed session serializer mismatch. The 21 October releases do not close it. PHP 8.6 and newer are not compared with 8.6.0. A disclosed 8.5 version is not compared with 8.6.0.

`PHP_CVE_2026_115560` now compares a disclosed `PHP/x.y.z` on the 8.2, 8.3, 8.4, and 8.5 lines with 8.2.36, 8.3.37, 8.4.28, and 8.5.13. The finding is recommendation-only. It does not block a deploy or hold a page. PHP 8.5.12 still passes the 21 October check and fails this one. PHP 8.1 and older stay on the October check. These CVE ids are not in the NVD recent feed. The floors are the php.net changelog.

The same changelog entries name other fixes. The 8.2.36 entry names CVE-2026-129538, CVE-2026-129496, CVE-2026-129289, CVE-2026-129292, CVE-2026-129291, CVE-2026-128090, CVE-2026-126714, CVE-2026-115560, CVE-2026-15353, CVE-2026-129506, CVE-2026-128064, and CVE-2026-127960. Newer lines name additional ids. The comparison uses the release versions, not one floor per id.

Source: [PHP 2026 archive](https://www.php.net/archive/2026.php), [PHP 8 changelog](https://www.php.net/ChangeLog-8.php)

**Coverage: covered for a disclosed PHP/x.y.z header on the 8.2 through 8.5 lines.** The record is `packages/intel/advisories/php-cve-2026-115560.json`.

## nginx 1.31.9 and 1.30.7

`https://nginx.org/en/security_advisories.html` last-modified is Wed, 18 Nov 2026 15:49:06 GMT. The 18 November scan saw Wed, 18 Nov 2026 13:32:29 GMT, with newest fixes 1.31.7 and 1.30.6. Ten rows were added after that. Each is NVD Received with no CPE. The floors are the nginx.org page. The F5 and cve.org links on that page were not opened. The HTTP/3 row's anchor text writes the CVE prefix twice. The identifier is CVE-2026-121810.

`vigil doctor` reports `TOOLCHAIN_NGINX_2026_11_18` for a local nginx or an nginx image below 1.31.9, or below 1.30.7 on the 1.30 line. A floating `1.31` or `1.30` tag is not padded. The finding is recommendation-only. `TOOLCHAIN_NGINX` stays on 1.31.7 and 1.30.6. nginx 1.31.7, 1.31.8, and 1.30.6 pass that older check and fail the new one.

- CVE-2026-123634. Medium. Resolver use-after-free. Not vulnerable: 1.31.9+, 1.30.7+. Vulnerable: 0.6.18–1.31.8.
- CVE-2026-123007. Major. HTTP/2 flow-control memory corruption. Not vulnerable: 1.31.9+, 1.30.7+. Vulnerable: 1.9.5–1.31.8.
- CVE-2026-121810. Medium. HTTP/3 use-after-free. Not vulnerable: 1.31.9+, 1.30.7+. Vulnerable: 1.25.0–1.31.8.
- CVE-2026-123633. Medium. HTTP/2 use-after-free. Not vulnerable: 1.31.9+, 1.30.7+. Vulnerable: 1.19.7–1.31.8.
- CVE-2026-118899. Major. Infinite loop reading a client body over TLS 1.3. Not vulnerable: 1.31.9+, 1.30.7+. Vulnerable: 1.13.0–1.31.8.
- CVE-2026-113425. Major. Mail proxy use-after-free. Not vulnerable: 1.31.9+, 1.30.7+. Vulnerable: 0.5.33–1.31.8.
- CVE-2026-120993. Minor. PROXY protocol v2 null dereference. Not vulnerable: 1.31.9+. Vulnerable: 1.31.4–1.31.8. No 1.30 line.
- CVE-2026-125283. Minor. Buffer overflow with alias and try_files. Not vulnerable: 1.31.9+, 1.30.7+. Vulnerable: 0.9.6–1.31.8.
- CVE-2026-120967. Medium. SNI bypass with client certificate validation in stream. Not vulnerable: 1.31.9+, 1.30.7+. Vulnerable: 1.25.5–1.31.8.
- CVE-2026-123640. Minor. Stream ssl_preread validation. Not vulnerable: 1.31.9+, 1.30.7+. Vulnerable: 1.15.2–1.31.8.

Source: [nginx security advisories](https://nginx.org/en/security_advisories.html)

**Coverage: covered for a local nginx version and an nginx image tag.** The record is `packages/intel/advisories/nginx-2026-11-18.json`.

## CISA catalog

The Known Exploited Vulnerabilities catalog is `2026.11.18`, released 2026-11-18T19:17:41.0354Z, count 1786. That is four entries above `2026.11.17`. CVE-2026-115731 was already recorded. All four new entries were added on 2026-11-18. The alerts HTML page and the cybersecurity advisories index returned HTTP 403, so this note does not describe those indexes. Catalog notes name hosts that were not opened.

Source: [CISA KEV catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)

- CVE-2024-10441. Synology DiskStation Manager. Due 2026-11-21. Forensic triage Yes. Ransomware Unknown. Not a page, certificate, or toolchain Vigil reads. No doctor check was added.
- CVE-2026-40217. BerriAI LiteLLM. Due 2026-12-02. Forensic triage No. Ransomware Unknown. The catalog calls it an unprotected alternate channel at `/guardrails/test_custom_code`. It is not in the NVD recent feed. The catalog names no version. `DEP_LITELLM_COMPROMISED` still flags exact 1.107.0. No range check was added.
- CVE-2026-90817. Vanderbilt REDCap. Due 2026-11-21. Forensic triage Yes. Ransomware Unknown. No doctor check was added.
- CVE-2026-90436. Apache Axis. Due 2026-11-21. Forensic triage Yes. Ransomware Unknown. The 6 November note already records Axis 1.x through 1.4 as end of life, with no Axis 1.x release. No doctor check was added.

No catalog due date falls on 19 November 2026. CVE-2024-27834 was due 18 November 2026 and was already recorded. CVE-2026-19868 is due 20 November 2026 and was already recorded.

## NVD recent feed

The CVE 2.0 recent feed timestamp is `2026-11-19T08:00:01.2564994`. HTTP last-modified is Thu, 19 Nov 2026 13:00:06 GMT. The newest `lastModified` in the file is `2026-11-19T12:18:47.980`.

No configuration modified after the 18 November scan names PHP, CPython, Node.js, nginx, OpenSSL, curl, the Go toolchain, the Linux kernel, WordPress, or Brotli. The ten nginx identifiers above have no CPE.

Eighty-seven Chrome configurations modified after `2026-11-18T12:17:24` use `versionEndExcluding` 158.0.8127.36. Vigil does not read the browser version. No doctor check was added. The Chrome releases HTML returned HTTP 302 to `www.google.com` and was discarded.

CVE-2026-126051 is still Awaiting Analysis with no CPE, last modified `2026-11-16T22:18:17.800`. CVE-2026-97043 is still Awaiting Analysis with no CPE, last modified `2026-11-17T05:18:39.207`. CVE-2026-95690 is still Awaiting Analysis with no CPE, last modified `2026-11-18T16:18:17.650`. It is not on the OpenSSL index. No OpenSSL doctor check was added. CVE-2026-107493, CVE-2026-124709, and CVE-2026-35190 are still Awaiting Analysis with no CPE, last modified `2026-11-17T22:17`. CVE-2026-130978 is now Analyzed, Chrome before 158.0.8127.36. CVE-2026-131873 is still Received with no CPE. CVE-2026-126763 is still Received with no CPE. The description now says Eclipse Mosquitto 1.6 to 2.0.22 and 2.1.0 to 2.1.2, and names no fixed release. CVE-2026-109908 is still Received with no CPE. The description now says libfontenc before 1.11.0. No X server check was added.

Still absent from this feed: CVE-2026-106071, CVE-2026-123873, CVE-2026-115560, CVE-2026-115533, CVE-2026-99286, CVE-2026-99287, CVE-2026-63219, CVE-2026-29013, CVE-2026-104476, CVE-2026-62253, CVE-2026-27975, CVE-2026-73574, CVE-2026-105857, and CVE-2026-96349. CVE-2026-115533 is still not a CPython confirmation. CVE-2026-27975 is still not a Linux confirmation.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz)

## 19 November oss-security

The 19 November index has 6 messages. None of these products is a page, a certificate, or a toolchain `vigil doctor` already reads. No doctor check was added. No remote probe was added. Hosts named only in the messages were not opened.

- Ruby 4.0.10, 3.4.13, and 3.3.14. The message names GHSA-34m4-m9fh-gqp5, GHSA-3p8q-wmhx-vm2w, GHSA-7whj-cfh7-xgm4, GHSA-7x2q-68qv-6p8x, GHSA-87fm-7w84-j2px, GHSA-pvgc-g7gj-pv6h, and GHSA-wpqw-5qxg-m68r. It names no CVE id.
- A reply on the undisclosed Linux SCTP report. It names no new CVE id and no released kernel version. No kernel floor was invented.
- GnuTLS 3.8.14, released 2026-11-18. CVE-2026-127039, CVE-2026-127040, and CVE-2026-127231. The message says each severity is low.
- A LightDM reply. It names no new CVE id.
- A reply on CVE-2026-114938. It names no new fixed release.
- CVE-2026-120404. Apache OpenNLP tools 2.0.0 before 2.5.13, and the runtime 3.0.0-M1 before 3.0.0. The message says upgrade to 2.5.13 or 3.0.0.

Source: [oss-security, 19 November 2026](https://www.openwall.com/lists/oss-security/2026/11/19/)

## 18 November oss-security, messages added after the last scan

The 18 November index now has 19 messages. The first 6 were already recorded. The 17 November index still has 36. The 16 November index still has 10. No doctor check was added for the new messages.

- Roundcube before 1.6.21 and 1.7.6. The message names no CVE id.
- CVE-2026-132129. Apache Kudu before 1.17.2, and 1.18.0 before 1.18.2. The message says update to 1.17.2 or 1.18.2.
- WebKitGTK and WPE WebKit. The message names 26 CVE ids. Affected lines are before 2.54.0 or before 2.54.3. Vigil does not read the browser version.
- CVE-2026-131920. OpenStack Cinder errata. The message does not print one fixed release.
- CVE-2026-131922. OpenStack keystonemiddleware errata. The message does not print one fixed release.
- CVE-2025-71471 and CVE-2026-130633. GPAC before 26.02.0. CVE-2026-130630 is GPAC 26.02.0 before 26.07.0. CVE-2026-130631 is GPAC before 26.07.0. No single fixed release was named. No release was invented.
- The nginx message names the same ten identifiers as the nginx.org page, and names nginx 1.30.7 and 1.31.9. The floors used above are the nginx.org page.
- fontconfig 2.18.4. The message names no CVE id.
- The PHP pre-announcement for 19 November. The releases are the PHP section above.
- Another note on an undisclosed Linux SCTP issue. It names no CVE id and no released version.

Source: [oss-security, 18 November 2026](https://www.openwall.com/lists/oss-security/2026/11/18/)

## Left unchanged

`https://nodejs.org/dist/index.json` last-modified is still Tue, 17 Nov 2026 03:44:41 GMT. v22.23.5, v24.22.3, and v26.13.1 are still the security rows. v27.0.0-alpha.0.1.1 is still not a security release. The November page still contains CVE-2026-106071 and does not contain CVE-2026-123873. The Node floors on this branch were not moved. The 11 November Node check was not copied from draft pull request 30.

`https://go.dev/doc/devel/release` still lists go1.27.4 and go1.26.11. go1.27.5 and go1.26.12 are absent. The Go floors were not moved. The eMudhra floors were not moved.

The Python blog last-modified is still Mon, 16 Nov 2026 18:20:49 GMT. python.org still lists 3.15.2, 3.14.10, 3.13.18, 3.12.16, and 3.11.18. The downloads page still contains Oct. 25, 2026. The Python floors were not moved.

curl's security page last-modified is still Tue, 10 Nov 2026 09:05:07 GMT. The first row is still CVE-2026-107929. 8.22.0 is still present. 8.23.0 is still absent.

The OpenSSL vulnerabilities index last-modified is still Tue, 17 Nov 2026 08:48:15 GMT. The first advisories are still CVE-2026-107493, CVE-2026-124709, and CVE-2026-35190. No OpenSSL doctor check was added.

The emSign ECC Root CA - G3 block was not changed. The Chrome post still says that root removal is expected Tuesday morning, 27 October 2026 PDT, and does not say that release has shipped.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
