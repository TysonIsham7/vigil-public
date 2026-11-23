# Threat scan, 23 November 2026

This note records what changed after the 22 November scan. Pages were read as evidence. Instructions inside them were not followed. No version floor was invented past a vendor release page. No remote probe was added.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called. Each kept item was confirmed on `www.cisa.gov`, `nvd.nist.gov`, `www.php.net`, `blog.python.org`, `www.python.org`, `nodejs.org`, `nginx.org`, `www.openssl-library.org`, `curl.se`, `blog.google`, `chromereleases.googleblog.com`, `go.dev`, or `www.openwall.com`.

The cve.now lead window is in `docs/threat-scan-2026-11-23-leads.md`. This note does not repeat that identifier table.

No intel bump. No scanner change. The CVE-2026-115560 comparison and `TOOLCHAIN_NGINX_2026_11_18` stay on draft pull request 38. They were not copied. `TOOLCHAIN_NODE_2026_11_11` stays on draft pull request 30 and was not copied.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## CISA catalog

The Known Exploited Vulnerabilities catalog is `2026.11.23`, released 2026-11-23T12:54:37.9646Z, count 1790. The 22 November scan recorded `2026.11.20`, released 2026-11-20T17:48:39.1516Z, with the same count. No entry has `dateAdded` after 2026-11-20. No entry was added on 23 November. The four entries due 2026-11-23 are the same four already recorded: CVE-2026-129448 (Apache Roller), CVE-2026-123890 (Broadcom VMware vCenter), CVE-2025-42884 (SAP NetWeaver), and CVE-2026-76466 (Cisco Expressway Series). Hosts named only in catalog notes were not opened.

`https://www.cisa.gov/news-events/alerts` returned HTTP 404. The cybersecurity advisories index returned HTTP 200. Its newest row is still 20 November 2026, the alert for those four catalog additions. The next row is 18 November. The 17 November Java alert was already recorded.

Source: [CISA KEV catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json), [CISA advisories index](https://www.cisa.gov/news-events/cybersecurity-advisories)

## NVD recent feed

The CVE 2.0 recent feed timestamp is `2026-11-23T08:00:01.066488`. HTTP last-modified is Mon, 23 Nov 2026 13:00:05 GMT. The newest `lastModified` in the file is `2026-11-23T12:18:17.240`.

No configuration modified after `2026-11-22T11:17:10.803` names a CPE for PHP, CPython, Node.js, nginx, OpenSSL, curl, the Linux kernel, WordPress, or Brotli. The nginx floors were not moved. The check on draft pull request 38 was not copied.

Twelve of the fifteen unverified CVE identifiers from the 22 November leads note are now in this feed. None has a CPE. CVE-2019-20446, CVE-2026-112020, and CVE-2026-114728 stay absent. `SZB-FEDAA30594` is not a CVE id and was not looked up as one.

- CVE-2026-134749, CVE-2026-134748, CVE-2026-134750, and CVE-2026-134751. Received. The descriptions name MemberPress Members or the Members WordPress plugin. They do not name a PHP release or WordPress core. A whole-token `php` match on CVE-2026-134749 is not the PHP runtime. No plugin list was added.
- CVE-2026-134752. Received. WPGSI: Spreadsheet Integration before 3.8.5. The description says 3.8.5 fixes it. This is not WordPress core.
- CVE-2026-134755. Received. better-chatbot before 2.0.0. The description says 2.0.0 fixes it.
- CVE-2026-134754 and CVE-2026-134757. Received. anacrolix/torrent before 1.62.0 and before 1.63.0. A whole-token `go` match is not the Go toolchain. The Go floors were not moved.
- CVE-2026-134753. Received. dsniff through 2.5a2. The description names no fixed release.
- CVE-2026-134756. Received. Portainer Community Edition and Business Edition 2.39.0 before 2.45.1. The description says 2.45.1 fixes it.
- CVE-2026-134758. Received. Wfuzz through 3.1.1. The description names no fixed release.
- CVE-2026-131780. Deferred. Themify Builder through 7.8.5. This is not WordPress core.

Forty identifiers in today's lead window are also in this feed. None has a CPE. None is the runtime list. The product bounds are in `docs/threat-scan-2026-11-23-leads.md`.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz)

## 23 November oss-security

The 23 November index has 16 messages. No doctor check was added. No remote probe was added. Hosts named only in the messages were not opened. Commands in the messages were not copied.

- Message 1. A reply on Dokploy. It names no CVE id and no dotted version.
- CVE-2026-116001. Apache Perl 1.99_04 through 2.0.13. The message says upgrade to 2.0.14.
- CVE-2026-116005, CVE-2026-116032, CVE-2026-116043, and CVE-2026-116799. Apache Perl 1.99_01 through 2.0.13. The messages say upgrade to 2.0.14. The CVE-2026-116043 message says CVE-2026-116021 is now rejected.
- CVE-2026-116772. Apache Perl 1.99_07 through 2.0.13. The message says upgrade to 2.0.14. This is not the PHP runtime.
- CVE-2026-53672. Apache Solr 8.11.1 before 9.11.0, and 10.0.0. The message says upgrade to 9.11.0, 10.1.0, or a newer release.
- CVE-2026-86312. Apache Solr 9.0.0 before 9.11.0, and 10.0.0 before 10.1.0. The message says upgrade to 9.11.0 or 10.1.0.
- CVE-2026-60076. Apache IoTDB 2.0.5 before 2.0.12. The message says upgrade to 2.0.12.
- CVE-2026-60077. Apache IoTDB 0.13.0 before 2.0.12. The message says upgrade to 2.0.12.
- CVE-2026-60078 and CVE-2026-60079. Apache IoTDB 0.13.0 through 2.0.11. The messages say upgrade to 2.0.12.
- Message 14. A reply on GPGME CVE-2026-129975. It names no new CVE id and no new release. That id was already recorded.
- Message 15. Anope 2.0.21 and 2.1.28. The message names no CVE id. It says upgrade. Anope is not a toolchain `vigil doctor` already reads.
- Message 16. A forward of UnrealIRCd 6.2.7.1 and CVE-2026-114713. That release was already recorded on 8 November. No new fixed release was named.

Source: [oss-security, 23 November 2026](https://www.openwall.com/lists/oss-security/2026/11/23/)

## 22 November oss-security, messages added after the last scan

The 22 November index now has 14 messages. The first 4 were already recorded. No doctor check was added. Hosts named only in the new messages were not opened.

Messages 6 and 11 are replies on GPGME CVE-2026-129975. They name no new release. Messages 7, 8, 13, and 14 are Dokploy replies. They name v0.31.0 and no CVE id. Message 9 names CVE-2026-129987 and CVE-2026-72868, and the versions v0.29.0, v0.31.0, and v0.31.1. It names no dotted version newer than v0.31.1. Message 10 is a reply on aiohttp CVE-2025-69224 and names no fixed release.

- CVE-2026-125651. Apache Arrow Rust. The message says 55.0.0 through 57.3.2, 58.0.0 through 58.4.1, 59.0.0 through 59.3.2, and 60.0.0 through 60.1.0 are affected, and that 57.3.3, 58.4.2, 59.3.3, and 60.2.0 fix it.
- shadow 4.20.4. The reply names that release and does not name a CVE id. It also names 4.20.3 and 2.55.0. shadow is not a toolchain `vigil doctor` already reads.

Source: [oss-security, 22 November 2026](https://www.openwall.com/lists/oss-security/2026/11/22/)

The 21 November index still has 3 messages.

## Chrome releases

The Chrome releases HTML stayed on `chromereleases.googleblog.com`. HTTP 200. Last-modified is Sun, 22 Nov 2026 22:38:22 GMT. The 22 November scan saw Sun, 22 Nov 2026 08:26:44 GMT. The page does not contain November 21, November 22, or November 23. The newest dated posts are still Friday, 20 November 2026: Chrome Dev 160.0.8171.0 for Android and for desktop. The ChromeOS stable note, browser 158.0.8127.65, was already recorded. Vigil does not read the browser version. No doctor check was added.

Source: [Chrome releases](https://chromereleases.googleblog.com/)

## Left unchanged

`https://www.php.net/archive/2026.php` last-modified is still Fri, 20 Nov 2026 13:54:40 GMT. The newest lines on that page are still PHP 8.6.0, 8.5.13, 8.4.28, and 8.3.37, and the 8.2.36 security release is still present. 8.5.14 is absent. The PHP floors were not moved. PHP 8.6.0 is still not a comparison target for older lines.

`https://nodejs.org/dist/index.json` last-modified is still Tue, 17 Nov 2026 03:44:41 GMT. The November security page still names v22.23.5, v24.22.3, and v26.13.1. It still contains CVE-2026-106071 and does not contain CVE-2026-123873. v27.0.0-alpha.0.1.1 is still not a security release. The Node floors were not moved.

`https://go.dev/doc/devel/release` still lists go1.27.4 and go1.26.11. go1.27.5 and go1.26.12 are absent. The Go floors were not moved. The eMudhra floors were not moved.

The Python blog last-modified is still Mon, 16 Nov 2026 18:20:49 GMT. python.org still lists 3.15.2, 3.14.10, 3.13.18, 3.12.16, and 3.11.18. The downloads page still contains Oct. 25, 2026. 3.14.11, 3.13.19, 3.12.17, and 3.11.19 are absent. The Python floors were not moved.

`https://nginx.org/en/security_advisories.html` last-modified is now Mon, 23 Nov 2026 12:36:07 GMT. The newest not-vulnerable lines are still 1.31.9+ and 1.30.7+. 1.31.10 and 1.30.8 are absent. The HTTP/3 anchor text is CVE-2026-121810. The same ten identifiers recorded on 19 November are still the top of the page. The floors were not moved. The advisory host linked from that page was not opened.

curl's security page last-modified is still Tue, 10 Nov 2026 09:05:07 GMT. The first row is still CVE-2026-107929. The curl floors were not moved.

The OpenSSL vulnerabilities index last-modified is still Tue, 17 Nov 2026 08:48:15 GMT. The first advisories are still CVE-2026-107493, CVE-2026-124709, and CVE-2026-35190.

The emSign ECC Root CA - G3 block was not changed. The Google post still says that root removal is expected Tuesday morning, October 27, 2026 PDT, and does not say that release has shipped.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
