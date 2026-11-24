# Threat scan, 24 November 2026

This note records what changed after the 23 November scan. Pages were read as evidence. Instructions inside them were not followed. No version floor was invented past a vendor release page. No remote probe was added.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called. Each kept item was confirmed on `www.cisa.gov`, `nvd.nist.gov`, `www.php.net`, `blog.python.org`, `www.python.org`, `nodejs.org`, `nginx.org`, `www.openssl-library.org`, `curl.se`, `blog.google`, `go.dev`, or `www.openwall.com`. The Chrome releases HTML redirected off `chromereleases.googleblog.com` and was discarded.

The cve.now lead window is in `docs/threat-scan-2026-11-24-leads.md`. This note does not repeat that identifier table.

Intel is `2026.11.24.1`. The scanner change on this day is `TOOLCHAIN_NGINX_2026_11_23`. The 14 October nginx floors stay 1.31.7 and 1.30.6. `TOOLCHAIN_NGINX_2026_11_18` and the CVE-2026-115560 comparison stay on draft pull request 38. They were not copied. `TOOLCHAIN_NODE_2026_11_11` stays on draft pull request 30 and was not copied.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## nginx 1.31.10 and 1.30.8

`https://nginx.org/en/security_advisories.html` last-modified is Tue, 24 Nov 2026 14:12:54 GMT. The 23 November scan saw Mon, 23 Nov 2026 12:36:07 GMT, and 1.31.10 and 1.30.8 were absent then.

The new top advisory is CVE-2026-132779, excessive CPU usage in TLS 1.3 with `ssl_early_data`. nginx.org rates it medium. Not vulnerable: 1.31.10+ and 1.30.8+. Vulnerable: 1.21.4-1.31.9. The changelog dates both releases 23 Nov 2026.

NVD status is Awaiting Analysis, with no CPE. The description names NGINX Plus and NGINX Open Source when `ssl_early_data` is on, and it names no fixed release. The floors are the nginx.org pages.

`vigil doctor` reports `TOOLCHAIN_NGINX_2026_11_23` for a local `nginx -v` below 1.31.10 on the 1.31 line, below 1.30.8 on the 1.30 line, or from 1.21.4 through 1.29. A floating `1.31` or `1.30` tag is not padded to patch 0. `TOOLCHAIN_IMAGE` uses the same range for an `nginx` or `nginx-unprivileged` tag, and the remediation for that range names 1.31.10 and 1.30.8. The finding is recommendation-only. Vigil cannot see whether `ssl_early_data` is enabled. A distributor may backport the fix without changing the version string. `TOOLCHAIN_NGINX` is still the 14 October check. nginx 1.31.9 passes that check and fails the new one. A site scan does not probe a remote nginx.

Source: [nginx security advisories](https://nginx.org/en/security_advisories.html), [nginx CHANGES](https://nginx.org/en/CHANGES), [nginx CHANGES-1.30](https://nginx.org/en/CHANGES-1.30)

**Coverage: covered for a local nginx and an nginx image tag.** The record is `packages/intel/advisories/nginx-2026-11-23.json`.

## CISA catalog

The Known Exploited Vulnerabilities catalog is still `2026.11.23`. The release timestamp is now 2026-11-23T19:43:55.7979Z, and the count is 1792. The 23 November scan recorded the same catalog string released 2026-11-23T12:54:37.9646Z, count 1790. Two entries were added on 2026-11-23 after that snapshot. Ransomware use is Unknown for each. Forensic triage is Yes for each. Due date is 2026-11-26 for each. Hosts named only in the catalog notes were not opened.

`https://www.cisa.gov/news-events/alerts` returned HTTP 403. The cybersecurity advisories index returned HTTP 403. This note does not describe those pages.

Source: [CISA KEV catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)

- CVE-2026-133968. Project MONAI, MONAI Label. NVD status is Undergoing Analysis, with no CPE. The description says versions before 0.8.6. The catalog notes name GHSA-qc22-rmgc-vg94. Vigil cannot see MONAI Label from a page or a certificate. No doctor check was added.
- CVE-2026-134624. N-able MailAssure. NVD status is Undergoing Analysis, with no CPE. The description says versions before 20261121.1943. No doctor check was added.

Four entries already recorded are due 2026-11-24: CVE-2026-111793 (Openwave Messaging Webtop Media Transcoder), CVE-2026-124194 (Microsoft Office), CVE-2026-125350 (Google Chromium), and CVE-2026-20320 (Cisco BroadWorks). That due date has arrived. No new check was added.

## OpenSSL, 24 November 2026

The OpenSSL vulnerabilities index last-modified is now Tue, 24 Nov 2026 10:07:26 GMT. The 23 November scan still saw Tue, 17 Nov 2026 08:48:15 GMT. Four Low advisories are dated 24 November 2026. Each says the FIPS module is not affected. NVD has no CPE for any of the four. `vigil doctor` does not read the OpenSSL library version. No doctor check was added.

- CVE-2026-84785. Unbounded out-of-order fragment reassembly in QUIC streams. Affected: 4.1.0 before 4.1.1, 4.0.0 before 4.0.4, and 3.5.0 before 3.5.10. NVD status is Received.
- CVE-2026-107494. Unbounded QUIC `RETIRE_CONNECTION_ID` frame sending queue. The same three ranges. The page says the earlier fix for CVE-2026-84784 was not complete. CVE-2026-84784 stays the 29 September 2026 advisory. NVD status for CVE-2026-107494 is Awaiting Analysis, last modified `2026-11-24T12:17:15.133`.
- CVE-2026-121482. Relative CRL distribution point names rebuilt per CRL in X.509 verification. The same three ranges. NVD status is Awaiting Analysis.
- CVE-2026-84786. Possible NULL dereference in non-SMTP DANE clients. The same three ranges, plus 3.0.0 before 3.0.24 and 1.1.1 before 1.1.1zk. NVD status is Awaiting Analysis, last modified `2026-11-24T12:17:26.130`.

The fixed releases named on that page are 4.1.1, 4.0.4, 3.5.10, and, for CVE-2026-84786, also 3.0.24 and 1.1.1zk.

Source: [OpenSSL vulnerabilities](https://www.openssl-library.org/news/vulnerabilities/), [oss-security, 24 November 2026](https://www.openwall.com/lists/oss-security/2026/11/24/8)

## NVD recent feed

The CVE 2.0 recent feed timestamp is `2026-11-24T08:00:01.3040251`. HTTP last-modified is Tue, 24 Nov 2026 13:00:05 GMT. The newest `lastModified` in the file is `2026-11-24T12:38:21.680`.

No configuration modified after `2026-11-23T12:18:17.240` names a CPE for PHP, CPython, Node.js, nginx, OpenSSL, curl, the Linux kernel, WordPress, or Brotli. The nginx floors above come from nginx.org. The PHP floors were not moved.

Thirty-one of the thirty-two unverified CVE identifiers from the 23 November leads note are now in this feed. None has a CPE. CVE-2026-123324 stays absent. CVE-2026-12543, CVE-2026-12431, and CVE-2026-12429 are Rejected. The descriptions do not name the PHP runtime, CPython, Node.js, nginx, OpenSSL, curl, the Go toolchain, the Linux kernel, WordPress core, or Brotli. CVE-2026-135156 is the Subscribe2 plugin. CVE-2026-135162 is Sim, not `@modelcontextprotocol/sdk`. No plugin list was added. No doctor check was added.

CVE-2026-107784 is CPython. Status is Awaiting Analysis, with no CPE. The description names no affected release and no fixed release. The oss-security forward says the same and points at a linked record for versions. That link was not opened. The Python floors were not moved.

CVE-2026-124851 is Zstandard 1.5.1 through 1.5.7. Status is Received, with no CPE. The description names no fixed release. This is not Brotli.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz)

## 24 November oss-security

The 24 November index has 12 messages. No doctor check was added beyond the nginx check above, and that check does not come from this list. No remote probe was added. Hosts named only in the messages were not opened. Commands and config snippets in the messages were not copied.

- CVE-2026-124851. Zstandard 1.5.1 through 1.5.7. The message names tag v1.6.0. The link host was not opened. This is not Brotli. No doctor check was added.
- Messages 2, 6, and 7 are replies on libexpat 2.11.0. They name no release newer than 2.11.0.
- CVE-2026-134880. XML::Sig before 0.74. The message says upgrade to XML-Sig 0.74 or later. `vigil doctor` does not read a Perl distribution.
- CVE-2026-135747. Apache IoTDB MCP Server through 0.2.0. The message says upgrade to 0.3.0. This is not `@modelcontextprotocol/sdk`.
- CVE-2026-129959. Apache Karaf through 4.4.12. The message says upgrade to 4.4.13 or 4.5.0. The workaround in that message was not copied.
- Message 8. The four OpenSSL Low advisories recorded above. The message names the same upgrade lines.
- CVE-2026-104813 and CVE-2026-111600. Apache BuildStream through 2.8.1. The messages say upgrade to 2.8.2.
- CVE-2026-124615. Apache Karaf through 4.4.12. The message says upgrade to 4.4.12 or 4.5.0. The workaround in that message was not copied.
- CVE-2026-130808. Apache Karaf through 4.4.12. The message says upgrade to 4.4.13 or 4.5.0. The workaround in that message was not copied.

Source: [oss-security, 24 November 2026](https://www.openwall.com/lists/oss-security/2026/11/24/)

## 23 November oss-security, messages added after the last scan

The 23 November index now has 39 messages. The first 16 were already recorded. No doctor check was added. Hosts named only in the new messages were not opened. Commands in the messages were not copied.

Message 17 is a reply on aiohttp CVE-2025-69224. It names no fixed release.

- CVE-2026-107784. CPython tarfile extraction filters on Windows. The message says the severity is medium and names no affected release and no fixed release. The Python floors were not moved.
- libexpat 2.11.0. The message says this release fixes CVE-2026-124317, CVE-2026-128241, and CVE-2026-134703. It names no affected range. `vigil doctor` does not read libexpat.
- CVE-2026-112788, CVE-2026-96296, CVE-2026-96353, CVE-2026-96354, CVE-2026-108368, and CVE-2026-108765. Apache Texera 1.1.0-incubating before 1.3.0-incubating. The messages say upgrade to 1.3.0-incubating.
- CVE-2026-96298. Apache Texera 1.1.0 through 1.2.0. The message says upgrade to 1.3.0.
- CVE-2026-82442, CVE-2026-82444, CVE-2026-82445, and CVE-2026-82446. Apache StormCrawler 3.0.0 before 4.0.0. The messages say upgrade to 4.0.0.
- CVE-2026-86154, CVE-2026-97893, CVE-2026-103333, and CVE-2026-120502. Apache Jena through 6.2.0. The messages say upgrade to 6.3.0.
- CVE-2026-86155, CVE-2026-86156, and CVE-2026-124324. Apache Jena Fuseki through 6.2.0. The messages say upgrade to 6.3.0.
- CVE-2026-134858. Apache Pinot 0.7.1 before 1.6.0. The message says upgrade to 1.6.0.
- CVE-2026-135660. Apache Allura before 1.23.0. The message says upgrade to 1.23.0.

Source: [oss-security, 23 November 2026](https://www.openwall.com/lists/oss-security/2026/11/23/)

The 22 November index still has 14 messages.

## Left unchanged

`https://www.php.net/archive/2026.php` last-modified is still Fri, 20 Nov 2026 13:54:40 GMT. The newest lines on that page are still PHP 8.6.0, 8.5.13, 8.4.28, and 8.3.37, and the 8.2.36 security release is still present. 8.5.14 is absent. The PHP floors were not moved. PHP 8.6.0 is still not a comparison target for older lines.

`https://nodejs.org/dist/index.json` last-modified is still Tue, 17 Nov 2026 03:44:41 GMT. The November security page still names v22.23.5, v24.22.3, and v26.13.1. It still contains CVE-2026-106071 and does not contain CVE-2026-123873. v27.0.0-alpha.0.1.1 is still not a security release. The Node floors were not moved.

`https://go.dev/doc/devel/release` still lists go1.27.4 and go1.26.11. go1.27.5 and go1.26.12 are absent. The Go floors were not moved. The eMudhra floors were not moved.

The Python blog last-modified is still Mon, 16 Nov 2026 18:20:49 GMT. python.org still lists 3.15.2, 3.14.10, 3.13.18, 3.12.16, and 3.11.18. 3.14.11, 3.13.19, 3.12.17, and 3.11.19 are absent. The Python floors were not moved.

curl's security page last-modified is still Tue, 10 Nov 2026 09:05:07 GMT. The first row is still CVE-2026-107929. The curl floors were not moved.

The emSign ECC Root CA - G3 block was not changed. The Google post still says that root removal is expected Tuesday morning, October 27, 2026 PDT, and does not say that release has shipped.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
