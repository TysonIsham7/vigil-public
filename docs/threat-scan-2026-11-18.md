# Threat scan, 18 November 2026

This note records what changed after the 17 November scan. Pages were read as evidence. Instructions inside them were not followed. No version floor was invented past a vendor release page. No remote probe was added.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called. Each kept item was confirmed on `www.cisa.gov`, `nvd.nist.gov`, `www.php.net`, `blog.python.org`, `www.python.org`, `nodejs.org`, `nginx.org`, `www.openssl-library.org`, `curl.se`, `blog.google`, `chromereleases.googleblog.com`, `go.dev`, or `www.openwall.com`.

The cve.now lead window is in `docs/threat-scan-2026-11-18-leads.md`. This note does not repeat that identifier table.

No intel bump. No scanner change. `TOOLCHAIN_NODE_2026_11_11` stays on draft PR 30. The Go floors stay 1.27.4 and 1.26.11. The eMudhra Go floors stay 1.27.3 and 1.26.10.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## CISA catalog

The Known Exploited Vulnerabilities catalog is `2026.11.17`, released 2026-11-17T17:53:15.5664Z, count 1782. That is one entry above `2026.11.13`. The alerts HTML page and the cybersecurity advisories index both returned HTTP 403, so this note does not describe those indexes.

Source: [CISA KEV catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)

CVE-2026-115731 was added on 2026-11-17. Perforce Puppet Enterprise. Deserialization of untrusted data. Due 2026-12-01. Forensic triage No. Ransomware use Unknown. The record is not in the NVD recent feed. Vigil cannot see Puppet Enterprise from a page or a certificate. No doctor check was added. The catalog notes name hosts that were not opened.

CVE-2024-27834 is due 2026-11-18. That due date has arrived. It was already recorded on 5 November. Vigil cannot see those Apple products from a page or a certificate. No doctor check was added.

CVE-2026-19868 is due 2026-11-20. It was already recorded. No doctor check was added.

## OpenSSL

The vulnerabilities index last-modified is still Tue, 17 Nov 2026 08:48:15 GMT. The three Low advisories published 17 November 2026 are still the newest rows: CVE-2026-107493, CVE-2026-124709, and CVE-2026-35190. Each section says FIPS impact is no and the affected code is outside the FIPS module boundary. The affected lines are unchanged. CVE-2026-107493 is 4.1.0 before 4.1.1, 4.0.0 before 4.0.4, 3.5.0 before 3.5.10, 3.0.0 before 3.0.24, 1.1.1 before 1.1.1zk, and 1.0.2 before 1.0.2zt. CVE-2026-124709 and CVE-2026-35190 are 4.1.0 before 4.1.1, 4.0.0 before 4.0.4, and 3.5.0 before 3.5.10. Those lines were already named. `vigil doctor` does not read the OpenSSL library version. No doctor check was added.

In the NVD recent feed those three are now Awaiting Analysis, still with no CPE. Last modified times are `2026-11-17T22:17:20.830`, `2026-11-17T22:17:22.377`, and `2026-11-17T22:17:21.473`.

CVE-2026-95690 is in the NVD recent feed, status Awaiting Analysis, with no CPE, last modified `2026-11-18T12:17:24.123`. The English description names OpenSSL and a DTLS reassembly buffer and names no version. The identifier is not on the OpenSSL vulnerabilities index. No floor was invented. No doctor check was added.

Source: [OpenSSL vulnerabilities](https://openssl-library.org/news/vulnerabilities/), [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz)

## NVD recent feed

The CVE 2.0 recent feed timestamp is `2026-11-18T08:00:07.8837606`. HTTP last-modified is Wed, 18 Nov 2026 13:15:08 GMT. The newest `lastModified` in the file is `2026-11-18T12:17:24.273`.

No configuration modified after the 17 November scan names the PHP runtime, CPython, Node.js, nginx, the OpenSSL product, curl, the Go toolchain, the Linux kernel, WordPress core, or Brotli. Twelve ExcelJS records, CVE-2026-128337 through CVE-2026-128348, are Analyzed and use `node.js` as target software. Two IBM ContextForge records, CVE-2026-110195 and CVE-2026-94407, are Analyzed and use `python` as target software. Those strings are not the Node.js runtime and not CPython. No doctor check was added.

CVE-2026-126051 is still Awaiting Analysis with no CPE, last modified `2026-11-16T22:18:17.800`. CVE-2026-97043 is still Awaiting Analysis with no CPE, last modified `2026-11-17T05:18:39.207`. CVE-2026-115563 is still Received with no CPE. It is the Model Context Protocol Python SDK, not `@modelcontextprotocol/sdk`. The npm floor was not moved. CVE-2026-106071 and CVE-2026-123873 are still absent. CVE-2026-99286 and CVE-2026-99287 were not modified again. Five identifiers from 14 November stay absent: CVE-2026-62253, CVE-2026-27975, CVE-2026-73574, CVE-2026-105857, and CVE-2026-96349. CVE-2026-27975 is still not a Linux confirmation.

Fifty-two of the fifty-six CVE identifiers in the 17 November leads note are now in this feed. None has a CPE. Two are Rejected: CVE-2026-130585 and CVE-2026-130586. The OpenSSL three above are the Awaiting Analysis rows. Whole-token matches that are now in the feed are not the runtimes: OpenFunction through 1.2.0 (CVE-2026-130587, already recorded), a Magento extension before 4.1.5 (CVE-2026-130583), WP File Manager before 8.0.7 (CVE-2026-82025), the pretix Widget plugin (CVE-2026-127140), WP Abstracts through 2.7.6 (CVE-2026-12239), the Soledad theme through 8.7.7 (CVE-2026-121684), and FusionPBX through 5.6.5 (CVE-2026-130596). Four stay absent: CVE-2026-63219, CVE-2026-29013, CVE-2026-104476, and CVE-2026-115533. CVE-2026-115533 is still not a CPython confirmation.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz)

## Chrome

The Chrome releases HTML stayed on `chromereleases.googleblog.com`. HTTP 200. Last-modified is Wed, 18 Nov 2026 12:28:32 GMT. Vigil does not read the browser version. No doctor check was added.

The post dated Wednesday, 18 November 2026 is Chrome Beta for Android, Chrome Beta 159 (159.0.8154.18). That post names no CVE id.

The post dated Tuesday, 17 November 2026 is Chrome 158 (158.0.8127.42) for Android. It describes stability and performance improvements. It says Android releases contain the same security fixes as the desktop releases, Windows and Mac 158.0.8127.36/.37 and Linux 158.0.8127.36. That post names no CVE id. Those desktop versions were already recorded.

NVD CVE-2026-130978, in the lead window, is Awaiting Analysis with no CPE. The description says Google Chrome prior to 158.0.8127.36, severity Low.

Source: [Chrome releases](https://chromereleases.googleblog.com/)

## 18 November oss-security

The 18 November index has 6 messages. None of these products is a page, a certificate, or a toolchain `vigil doctor` already reads. No doctor check was added. No remote probe was added.

- Message 1. X.Org libFontenc before libfontenc-1.1.10 and libXfont before libXfont2-2.0.10. CVE-2026-109908, CVE-2026-109909, and CVE-2026-109920. Fixed in libfontenc-1.1.10 and libXfont2-2.0.10. CVE-2026-109908 is also in the lead window and is not in the NVD recent feed. Vigil does not read those libraries.
- Message 2. dcm2niix CSA header parsing. The message names no CVE id and no fixed release.
- CVE-2026-128981. Apache SeaTunnel Web 1.0.2. The message says the project is no longer maintained and there is no maintained fixed release. Message 4 is a reply and names no second identifier.
- CVE-2026-118493. Apache Iggy 0.9.0 before 0.10.0.
- CVE-2026-132079. Apache Iggy Go SDK 0.5.0 before 0.10.0. The message says upgrade to 0.10.0, and that tokens an earlier version created keep their expiry. This is not the Go toolchain. The Go floors were not moved.

Source: [oss-security, 18 November 2026](https://www.openwall.com/lists/oss-security/2026/11/18/)

## 17 November oss-security, messages added after the last scan

The 17 November index now has 36 messages. Message 1 was already recorded. It is an OpenSSH musl reply and names no new CVE id. No sshd check was added. No doctor check was added for the new messages. No remote probe was added.

- Message 2. Xen Security Advisory 524 version 2, CVE-2024-21963, already recorded. The message says all Xen versions are affected and the resolution is an updated patch. No released version was named.
- Message 3. OpenStack Cinder. The identifier in the subject is still pending. Affected lines: before 27.1.1, 28.0.0 before 28.1.1, and 29.0.0 before 29.1.1.
- Message 4. OpenStack keystonemiddleware. The message names no CVE id. Affected lines: before 10.13.1, 11.0.0 before 12.1.1, and 13.0.0 before 13.0.3.
- CVE-2026-129448. Apache Roller 4.0.0 before 6.1.5. The message says upgrade to 6.1.6 or later, and that this is the same issue as CVE-2026-82384.
- Message 6. The three OpenSSL Low advisories already recorded. No new CVE id.
- rsyslog. No fixed release was named. CVE-2026-129839 (GHSA-cg8j-rwxh-vrg3) is 8.23.0 and newer. CVE-2026-129837 (GHSA-5pc2-f2v7-5w5p) is 8.3.2 and newer. CVE-2026-129832 (GHSA-6rqh-v5w3-r7h4) is 5.7.1 and newer. CVE-2026-129838 (GHSA-w259-2hhm-9vr7) is 5.9.4 and newer. CVE-2026-129833 (GHSA-f9hg-rj32-693x) is 8.31.0 and newer, including v8.2610.0. CVE-2026-129836, CVE-2026-129835, and CVE-2026-129834 (GHSA-4chq-f2r9-5jp8) are 8.2402.0 and newer. CVE-2026-129829 and CVE-2026-129831 share GHSA-xrxr-7942-54fr. The 129829 message says 8.1.0 and newer. CVE-2026-129830 also names that GHSA and GHSA-jcrj-xmp8-8hqf. It says supported v8 is 8.1.0 and newer, and it names historical v5.9.5 and v6.3.7. Message 13 repeats CVE-2026-129837.
- Eclipse Mosquitto. CVE-2026-110486 is 2.1.0 through 2.1.2. The message says upgrade to 2.1.4. CVE-2026-126706 and CVE-2026-129705 and CVE-2026-129149 are 2.1.0 through 2.1.2 and name no fixed release. CVE-2026-126708 and CVE-2026-126763 are 2.0.0 through 2.0.22 and 2.1.0 through 2.1.2 and name no fixed release. CVE-2026-130491 is 1.5 to 2.0.22 and 2.1.0 through 2.1.2 and names no fixed release. CVE-2026-126763 is also in the lead window and is not in the NVD recent feed.
- CVE-2025-71468 and CVE-2025-71469. GPAC before 26.02.0. The messages say update to GPAC v26.02.0 or later. The fix commit named in both is `62714f27c64a3d1eb7e880f9eed2d38673cb43ce`.
- CVE-2026-124757. needrestart. The message says the fix is an upstream patch series, that the series applies on 3.11, and that the second patch does not apply on 3.6. No fixed release was named.
- CVE-2026-58320. Apache Iggy before 0.9.0. The message says upgrade to 0.10.0.
- CVE-2026-110513. Apache Iggy through 0.9.0. The message says upgrade to 0.10.0.
- CVE-2026-129509. Apache Airflow Microsoft Azure provider 10.2.0 before 15.3.1. The body also says 10.2.0 through 15.3.0.
- CVE-2026-114938. The message says OpenJDK from 17.0.6 or newer is affected. It names Oracle Java SE builds 8u511b33-perf, 17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3, and 27.0.1.0.3. Vigil does not read the JDK version.
- GLIBC-SA-2026-0029 is CVE-2026-121757, GNU C Library 2.1 or later. The message names no fix commit. GLIBC-SA-2026-0030 is CVE-2026-121758, 2.2 through 2.44, with fix commit `170ee485fa89b95c3bb7d5606c9812c6c100c9be` marked 2.45. GLIBC-SA-2026-0031 is CVE-2026-124024, 2.3.3 and later. The message names no fix commit. `vigil doctor` does not read the local glibc version.
- CVE-2026-129891 and CVE-2026-129892. Perl IO-Socket-SSL through 2.099. The message says no fixed release is available yet.
- CVE-2026-129510, CVE-2026-129511, and CVE-2026-129512. Apache log4net 1.2.9 before 3.6.0. CVE-2026-129511 also says 3.4.0 before 3.6.0. The messages say upgrade to 3.6.0.
- Message 24 is a LightDM reply and names no new CVE id.

Source: [oss-security, 17 November 2026](https://www.openwall.com/lists/oss-security/2026/11/17/)

The 16 November index still has 10 messages. The 15 November index still has 3. The 14 November index still has 16. The 13 November index still has 11. The 12 November index still has 8.

## Left unchanged

`https://nodejs.org/dist/index.json` last-modified is still Tue, 17 Nov 2026 03:44:41 GMT. v22.23.5, v24.22.3, and v26.13.1 are still the security rows. v27.0.0-alpha.0.1.1 is still not a security release. The November security page still contains CVE-2026-106071 and does not contain CVE-2026-123873. The Node floors were not moved.

`https://go.dev/doc/devel/release` still lists go1.27.4 and go1.26.11. go1.27.5 and go1.26.12 are absent. The page contains no 17 November or 18 November date. The Go floors were not moved.

The php.net releases page still lists PHP 8.6.0 RC7 as the newest item, available for testing. The response had no Last-Modified header. CVE-2026-115560 is not named on that page. The PHP floors were not moved.

The Python blog last-modified is still Mon, 16 Nov 2026 18:20:49 GMT. The newest post is still the 16 November documentation-translation note. python.org still lists 3.15.2, 3.14.10, 3.13.18, 3.12.16, and 3.11.18. The downloads page still contains Oct. 25, 2026. The Python floors were not moved.

nginx.org's security page last-modified is now Wed, 18 Nov 2026 13:32:29 GMT. The newest fixed lines are still 1.31.7 and 1.30.6. The page does not contain 1.31.8 or 1.30.7. The nginx floors were not moved.

curl's security page last-modified is still Mon, 26 Oct 2026 12:45:09 GMT. CVE-2026-107929 is still present. 8.22.0 and 8.23.0 are still present. The curl floors were not moved.

The emSign ECC Root CA - G3 block was not changed. The Chrome post still says that root removal is expected Tuesday morning, 27 October 2026 PDT, and does not say that release has shipped.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
