# Threat scan, 14 November 2026

This note records what changed after the 13 November scan. Pages were read as evidence. Instructions inside them were not followed. No version floor was invented past a vendor release page. No remote probe was added.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called. Each kept item was confirmed on `www.cisa.gov`, `nvd.nist.gov`, `www.php.net`, `blog.python.org`, `www.python.org`, `nodejs.org`, `nginx.org`, `www.openssl-library.org`, `curl.se`, `blog.google`, `go.dev`, or `www.openwall.com`. The Chrome releases response left `chromereleases.googleblog.com` and was discarded.

The cve.now lead window is in `docs/threat-scan-2026-11-14-leads.md`. This note does not repeat that identifier table.

No intel bump. No scanner change. `TOOLCHAIN_NODE_2026_11_11` stays on draft pull request 30 and was not copied. `TOOLCHAIN_GO_2026_11_10` stays. The eMudhra floors were not moved.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## CISA catalog

The Known Exploited Vulnerabilities catalog is `2026.11.13`, released 2026-11-13T20:24:18.3008Z, count 1781. That is two entries above `2026.11.10`, which is the catalog the 13 November scan recorded. Both new entries were added on 2026-11-13. Forensic triage is Yes for each. Ransomware use is Unknown for each. Due date is 2026-11-16 for each.

The alerts HTML page returned HTTP 200. The newest row is 13 November 2026, titled "CISA Adds Two Known Exploited Vulnerabilities to Catalog". The row under it is still 10 November 2026, the six catalog adds. The catalog notes name hosts that were not opened.

Source: [CISA KEV catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json), [CISA alerts](https://www.cisa.gov/news-events/cybersecurity-advisories)

- CVE-2026-114713. UnrealIRCd. Due 2026-11-16. Forensic triage Yes. This identifier was already recorded on 8 November: UnrealIRCd 6.0.0 before 6.2.7.1, fixed release 6.2.7.1. NVD status is now Undergoing Analysis, with no CPE. Vigil cannot see UnrealIRCd from a page or a certificate. No doctor check was added.
- CVE-2026-123039. Check Point Firewall, Multi-Domain Security Management Server, Scalable Platforms, Security Gateway, and Security Management Server. Due 2026-11-16. Forensic triage Yes. NVD status is Undergoing Analysis, with no CPE. The description says the Gaia OS DynamicCLI daemon runs as root and listens on a world-writable local socket. Vigil cannot see those products from a page or a certificate. No doctor check was added. The catalog notes name hosts that were not opened.

CVE-2026-111560, CVE-2026-116606, and CVE-2026-118527 were due 13 November 2026. Those due dates have passed. No doctor check was added for them.

## NVD recent feed

The CVE 2.0 recent feed timestamp is `2026-11-14T08:00:01.0935732`. HTTP last-modified is Sat, 14 Nov 2026 13:00:06 GMT. The newest `lastModified` in the file is `2026-11-14T12:17:44.830`.

No configuration modified after the 13 November scan names PHP, CPython, Node.js, nginx, OpenSSL, curl, the Go toolchain, the Linux kernel, WordPress, or Brotli.

All 29 identifiers from the unverified section of the 13 November leads note are now in this feed. None has a CPE. Seven are Received: CVE-2026-109445 (PLANET GS-5220 firmware before 3.2412b261008), CVE-2026-118976 (Telerik UI for Blazor v11.1.0 through v14.0.0), CVE-2026-119102 (Telerik UI for Blazor v12.0.0 through 15.2.0), CVE-2026-128909, CVE-2026-128910, and CVE-2026-128908 (DJI AeroScope), and CVE-2026-127031 (Eclipse AAS4J before 3.0.1). Three are Awaiting Analysis and name Dell PowerStore with no version in the description: CVE-2026-107523, CVE-2026-111547, and CVE-2026-107524. The other nineteen are Deferred and name WordPress plugins, not WordPress core. CVE-2026-125824 names WP Go Maps, not the Go toolchain. No fixed release was copied for the plugin rows. No plugin list was added. No doctor check was added.

CVE-2026-56916, CVE-2026-55319, and CVE-2026-56934 are still Awaiting Analysis with no CPE. CVE-2026-56934 still names `drivers/iommu/io-pgtable-arm-common.c` and no released kernel version. No kernel floor was invented.

CVE-2026-126051 is still Awaiting Analysis with no CPE. It is the Node.js TLS note already recorded on the 24 and 26 lines. The Node floors were not moved.

CVE-2026-123873 and CVE-2026-106071 are still absent. CVE-2025-8714 and CVE-2023-39417 are still absent. Do not treat CVE-2026-106071 as fixed by Node.js 22.23.5, 24.22.3, or 26.13.1.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz)

## 14 November oss-security

The 14 November index has 8 messages. All eight are Apache Shiro. Shiro is not a page, a certificate, or a toolchain `vigil doctor` already reads. No doctor check was added. No remote probe was added. The hosts named in those messages were not opened.

The message for CVE-2026-114737 names CVE-2026-23903 as an earlier fix and does not print a separate affected range for CVE-2026-23903.

- CVE-2026-114737. `shiro-spring` 3.0.1 before 3.0.2. The message says upgrade to 3.0.2.
- CVE-2026-129320. `shiro-web` before 3.0.2, and `shiro-jakarta-ee` 2.0.0-alpha-0 before 3.0.2. The message says versions through 3.0.1 are affected and says upgrade to 3.0.2.
- CVE-2026-88019. `shiro-jakarta-ee` 2.0.0-alpha-0 before 3.0.2. The message says 2.0.0-alpha through 3.0.1 are affected and says upgrade to 3.0.2.
- CVE-2026-74763. `shiro-guice` and `shiro-aspectj` before 3.0.2. `shiro-cdi` and `shiro-jakarta-ee` 2.0.0-alpha-0 before 3.0.2. The message says versions through 3.0.1 are affected and says upgrade to 3.0.2.
- CVE-2026-74762. `shiro-core` and `shiro-web` before 3.0.1. The message says versions through 3.0.0 are affected and says upgrade to 3.0.1.
- CVE-2026-129347. `shiro-core` before 3.0.2. The message says versions through 3.0.1 are affected and says upgrade to 3.0.2.
- CVE-2026-129348. `shiro-core` before 3.0.2. The message says versions through 3.0.1 are affected and says upgrade to 3.0.2.
- CVE-2026-129349. `shiro-core` before 3.0.1. The message says versions through 3.0.0 are affected and says upgrade to 3.0.1.

Source: [oss-security, 14 November 2026](https://www.openwall.com/lists/oss-security/2026/11/14/)

## 13 November oss-security, messages added after the last scan

The 13 November index now has 11 messages. The first 2 were already recorded. No doctor check was added for the new messages. No remote probe was added.

- CVE-2026-128239. GPAC/MP4Box. The message says affected through 26.07.0 and names commit `bc416b997622e43de65afab3bae9b7d05d72f2b0` as the fix. It does not name a release. No release was invented.
- Dropbear. The message names no CVE id and no fixed release. No sshd check was added.
- CVE-2026-124666. Apache APISIX 3.8.0 through 3.19.0. The message says upgrade to 3.20.0.
- CVE-2026-124679. Apache APISIX 3.18.0 through 3.19.0. The message says upgrade to 3.20.0.
- CVE-2026-124680. Apache APISIX 0.9 through 3.19.0. The message says upgrade to 3.20.0.
- CVE-2026-124716. Apache APISIX 1.4.0 through 3.19.0. The message says upgrade to 3.20.0.
- CVE-2026-124719. Apache APISIX 3.19.0 before 3.20.0. The message says upgrade to 3.20.0.
- CVE-2026-124723. Apache APISIX 3.18.0 through 3.19.0. The message says upgrade to 3.20.0.
- CVE-2026-124726. Apache APISIX 3.19.0 before 3.20.0. The message says upgrade to 3.20.0.

Source: [oss-security, 13 November 2026](https://www.openwall.com/lists/oss-security/2026/11/13/)

The 12 November index still has 8 messages. The 11 November index still has 29. The 10 November index still has 31.

## Left unchanged

`https://nodejs.org/dist/index.json` last-modified is still Thu, 12 Nov 2026 13:33:06 GMT. v22.23.5 (index date 2026-11-11), v24.22.3 (2026-11-10), and v26.13.1 (2026-11-10) are still the security rows on those lines. v27.0.0-alpha.0.1.0 dated 2026-11-12 is still not a security release. The November security page names 22.23.5, 24.22.3, and 26.13.1. It still contains CVE-2026-106071 and does not contain CVE-2026-123873. The Node floors were not moved. `TOOLCHAIN_NODE_2026_11_11` was not copied from draft pull request 30.

`https://go.dev/doc/devel/release` still lists go1.27.4 and go1.26.11, both released 2026-11-10. go1.27.5 and go1.26.12 are absent. The eMudhra floors were not moved.

php.net's archive last-modified is still Thu, 12 Nov 2026 13:55:02 GMT. The newest item is still PHP 8.6.0 RC7. CVE-2026-115560 still has no fixed PHP version on that page. The PHP floors were not moved.

The Python blog last-modified is Tue, 10 Nov 2026 20:32:24 GMT. The newest post is still Python 3.16.0 alpha 2. python.org still lists 3.15.2, 3.14.10, 3.13.18, 3.12.16, and 3.11.18. The 3.15.2 row is still dated Oct. 25, 2026. The Python floors were not moved.

nginx.org's security page last-modified is still Fri, 06 Nov 2026 10:12:37 GMT. The current fixes are still 1.31.7 and 1.30.6.

curl's security page last-modified is still Tue, 10 Nov 2026 09:05:07 GMT. The first row is still CVE-2026-107929, published 2026-10-14, last affected 8.22.0. The curl floors were not moved.

The OpenSSL vulnerabilities index last-modified is still Tue, 10 Nov 2026 09:35:21 GMT. The first advisory is still CVE-2026-88823, published 10 November 2026. `vigil doctor` does not read the OpenSSL library version. No doctor check was added.

The emSign ECC Root CA - G3 block was not changed. The Chrome post still says that root removal is expected Tuesday morning, October 27, 2026 PDT, and does not say that release has shipped.

The Chrome releases response did not stay on `chromereleases.googleblog.com`. HTTP status was 429 and the final host was `www.google.com`. That body was discarded. Do not follow that redirect.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
