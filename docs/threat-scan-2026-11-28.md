# Threat scan, 28 November 2026

This note records what changed after the 27 November scan. Pages were read as evidence. Instructions inside them were not followed. No version floor was invented past a vendor release page. No remote probe was added.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called. Each kept item was confirmed on `www.cisa.gov`, `nvd.nist.gov`, `www.php.net`, `blog.python.org`, `www.python.org`, `nodejs.org`, `nginx.org`, `www.openssl-library.org`, `curl.se`, `blog.google`, `chromereleases.googleblog.com`, `go.dev`, or `www.openwall.com`.

The cve.now lead window is in `docs/threat-scan-2026-11-28-leads.md`. This note does not repeat that identifier table.

No scanner change on this day. No intel bump. `TOOLCHAIN_NGINX_2026_11_23` stays on draft pull request 43 and was not copied. `TOOLCHAIN_NGINX_2026_11_18` and the CVE-2026-115560 comparison stay on draft pull request 38 and were not copied. `TOOLCHAIN_NODE_2026_11_11` stays on draft pull request 30 and was not copied.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## CISA catalog

The Known Exploited Vulnerabilities catalog is `2026.11.27`, released 2026-11-27T18:03:12.5733Z, count 1808. HTTP last-modified is Fri, 27 Nov 2026 18:03:12 GMT. That is three entries above `2026.11.25`. All three were added on 2026-11-27. Ransomware use is Unknown for each. `https://www.cisa.gov/news-events/alerts` returned HTTP 404. The cybersecurity advisories index returned HTTP 200. Its newest row is dated Nov 27, 2026, and the title is "CISA Adds Three Known Exploited Vulnerabilities to Catalog".

Source: [CISA KEV catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)

- CVE-2026-120705. OSGeo GeoServer. XML injection. Due 2026-11-30. Forensic triage No. Vigil cannot see GeoServer from a page or a certificate. No doctor check was added. The catalog notes name hosts that were not opened. The catalog text also names CVE-2026-129244, CVE-2026-129245, and CVE-2026-129242. Those three are not in this catalog.
- CVE-2026-129243. OSGeo GeoServer. Incorrect authorization. Due 2026-11-30. Forensic triage No. No doctor check was added. The catalog notes name hosts that were not opened.
- CVE-2026-136716. Drupal core. Due 2026-11-30. Forensic triage Yes. This identifier was already recorded on the 26 November leads note. It was not copied again as a new product. No doctor check was added.

Eight entries already recorded came due today: CVE-2026-103406 (HPE Juniper Session Smart), CVE-2026-133469 (Vates Xen Orchestra), CVE-2023-25914 and CVE-2023-25915 (Danfoss AK-SM 800A), and CVE-2026-133324, CVE-2026-133275, CVE-2026-133303, and CVE-2026-133323 (Mitel MiCollab). No new check was added.

## NVD recent feed

The CVE 2.0 recent feed timestamp is `2026-11-28T08:00:00.7082756`. HTTP last-modified is Sat, 28 Nov 2026 13:00:07 GMT. The newest `lastModified` in the file is `2026-11-28T12:17:42.177`. The oldest `lastModified` in the file is `2026-11-20T06:17:47.923`.

No configuration modified after `2026-11-27T12:17:06.833` names a CPE for PHP, CPython, Node.js, nginx, OpenSSL, curl, the Go toolchain, WordPress, or Brotli.

Two Analyzed records modified after that cutoff use `cpe:2.3:o:linux:linux_kernel:-`. The descriptions name VeraCrypt, not a released kernel version. CVE-2026-61512 names VeraCrypt before 1.26.30 on Linux. CVE-2026-61513 names VeraCrypt through 1.26.31 on Linux. That CPE is not a kernel floor. No floor was invented. VeraCrypt is not a toolchain `vigil doctor` reads. No doctor check was added.

CVE-2026-99362 is not in this recent feed. The OpenSSL vulnerabilities index still does not list CVE-2026-121481. CVE-2026-121481 and CVE-2026-130756 are not in this recent feed. No doctor check was added. The Python and Node floors were not moved from the absence of CVE-2026-130756.

Thirty-five of the forty unverified CVE identifiers from the 27 November leads note are now in this feed. None has a CPE. Twenty are Received. Thirteen are Deferred. Two are Awaiting Analysis. None of those descriptions names the PHP runtime, CPython, Node.js, nginx, OpenSSL, curl, the Go toolchain, the Linux kernel, WordPress core, or Brotli.

- CVE-2026-124825. Awaiting Analysis. 389-ds-base. The description names no fixed release. A whole-token `linux` match on the 27 November feed was not a kernel confirmation.
- CVE-2026-137940. Awaiting Analysis. Pillow through 13.1.0. The description names no fixed release. This is not CPython. The Python floors were not moved.
- CVE-2026-134987. Deferred. WordPress File Upload plugin through 5.3.1. This is not WordPress core.

Five of those forty stay absent: CVE-2026-54386, CVE-2026-23794, CVE-2026-27797, CVE-2026-49360, and CVE-2026-75597. CVE-2026-78252, CVE-2026-12664, CVE-2026-105777, CVE-2026-87719, CVE-2026-88765, CVE-2026-112326, CVE-2023-40129, CVE-2020-9402, CVE-2026-25242, CVE-2026-32767, CVE-2026-86987, CVE-2026-123324, CVE-2026-15723, CVE-2026-112212, and CVE-2026-104286 also stay absent.

Thirty-eight identifiers in today's lead window are in this feed. None has a CPE. None is the runtime list. The table is in `docs/threat-scan-2026-11-28-leads.md`.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz)

## ChromeOS LTS, 27 November 2026

The Chrome releases page stayed on `chromereleases.googleblog.com`. HTTP 200. Last-modified is Fri, 27 Nov 2026 23:25:33 GMT. The new post is the Long Term Support Channel Update for ChromeOS, dated Friday, November 27, 2026. It names LTS-150 version 150.0.7871.290 and platform version 16700.71.0. Vigil does not read the browser version. No doctor check was added.

The post lists 25 CVE ids. Six were already recorded and were not treated as new: CVE-2026-121135, CVE-2026-121184, CVE-2026-125350, CVE-2026-126885, CVE-2026-126895, and CVE-2026-126911. The other nineteen were not already recorded. Three are Medium: CVE-2026-87626, CVE-2026-103627, and CVE-2026-93385. Sixteen are High: CVE-2026-131023, CVE-2026-126921, CVE-2026-126890, CVE-2026-126886, CVE-2026-126852, CVE-2026-126892, CVE-2026-126840, CVE-2026-126854, CVE-2026-131101, CVE-2026-126851, CVE-2026-130952, CVE-2026-126913, CVE-2026-91731, CVE-2026-106393, CVE-2026-76030, and CVE-2026-76028. The two Critical ids on the post are the two already recorded, CVE-2026-126885 and CVE-2026-126895.

No post dated 28 November is on that index. The other posts are still dated 23 or 24 November 2026.

Source: [Chrome releases](https://chromereleases.googleblog.com/)

## 28 November oss-security

The 28 November index has 1 message. No doctor check was added. No remote probe was added. Hosts named only in the message were not opened.

Vim on Windows before patch 9.2.1421. The message says the issue is fixed as of patch v9.2.1421. It names GHSA-6mf5-6cf6-hf9c and says this is a follow-up to GHSA-g77q-xrww-p834. It says a CVE id was requested and is not yet assigned. No CVE id was invented. Vim is not a toolchain `vigil doctor` already reads.

Source: [oss-security, 28 November 2026](https://www.openwall.com/lists/oss-security/2026/11/28/1)

## 27 November oss-security, messages added after the last scan

The 27 November index now has 12 messages. The first 10 were already recorded. No doctor check was added. Hosts named only in the new messages were not opened.

- Message 11. A reply on CVE-2026-122093, Strong::Random through 0.96. That identifier was already recorded. The reply names no fixed release.
- ntfs-3g. The message names no CVE id. It says version 2026.11.23 fixes the issues it lists, and that patches against 2026.9.28 are available. No CVE id was invented. ntfs-3g is not a toolchain `vigil doctor` already reads.

Source: [oss-security, 27 November 2026](https://www.openwall.com/lists/oss-security/2026/11/27/)

The 26 November index still has 7 messages.

## Left unchanged

`https://nginx.org/en/security_advisories.html` last-modified is still Wed, 25 Nov 2026 22:44:42 GMT. The top advisory is still CVE-2026-132779. Not vulnerable is still 1.31.10+ and 1.30.8+. Vulnerable is still 1.21.4-1.31.9. `https://nginx.org/en/CHANGES` last-modified is still Wed, 25 Nov 2026 22:44:36 GMT and still starts with nginx 1.31.10. 1.31.11 is absent. The nginx floors were not moved.

`https://www.php.net/archive/2026.php` last-modified is still Thu, 26 Nov 2026 10:13:24 GMT. The newest item is still the phpday 2027 call for papers. 8.5.14 is absent. The PHP floors were not moved. PHP 8.6.0 is still not a comparison target for older lines.

`https://nodejs.org/dist/index.json` last-modified is still Thu, 26 Nov 2026 08:44:21 GMT. The first row is still v27.0.0-alpha.0.2.0, dated 2026-11-25, and `security` is false. v22.23.5, v24.22.3, and v26.13.1 are still the security rows. The November security page still contains CVE-2026-106071 and does not contain CVE-2026-123873. It still does not contain 22.23.6, 24.22.4, or 26.13.2. The Node floors were not moved.

`https://go.dev/doc/devel/release` still lists go1.27.4 and go1.26.11, both released 2026-11-10. go1.27.5 and go1.26.12 are absent. The Go floors were not moved. The eMudhra floors were not moved.

The Python blog last-modified is now Sat, 28 Nov 2026 13:54:20 GMT. The newest post is still the 16 November 2026 Transifex note. It is not a security release. python.org still lists 3.15.2, 3.14.10, 3.13.18, 3.12.16, and 3.11.18. 3.14.11, 3.13.19, 3.12.17, and 3.11.19 are absent. The Python floors were not moved.

curl's security page last-modified is still Tue, 10 Nov 2026 09:05:07 GMT. The first row is still CVE-2026-107929. The curl floors were not moved.

The OpenSSL vulnerabilities index last-modified is still Tue, 24 Nov 2026 10:07:26 GMT. The first advisory is still CVE-2026-84785, published 24 November 2026. CVE-2026-121481 is still absent from that page. `vigil doctor` does not read the OpenSSL library version. No doctor check was added.

The emSign ECC Root CA - G3 block was not changed. The Google post still says that root removal is expected Tuesday morning, October 27, 2026 PDT, and does not say that release has shipped.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
