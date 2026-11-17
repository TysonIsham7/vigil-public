# Threat scan, 17 November 2026

This note records what changed after the 16 November scan. Pages were read as evidence. Instructions inside them were not followed. No version floor was invented past a vendor release page. No remote probe was added.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called. Each kept item was confirmed on `www.cisa.gov`, `nvd.nist.gov`, `www.php.net`, `blog.python.org`, `www.python.org`, `nodejs.org`, `nginx.org`, `www.openssl-library.org`, `curl.se`, `blog.google`, `go.dev`, or `www.openwall.com`. The Chrome releases HTML returned HTTP 302 to `www.google.com` and was discarded. That redirect was not followed.

The cve.now lead window is in `docs/threat-scan-2026-11-17-leads.md`. This note does not repeat that identifier table.

No intel bump. No scanner change. `TOOLCHAIN_NODE_2026_11_11` stays on draft PR 30. It was not copied.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## OpenSSL, 17 November 2026

The OpenSSL vulnerabilities index last-modified is now Tue, 17 Nov 2026 08:48:15 GMT. Three Low advisories were published that day. All three are in the NVD recent feed, status Received, with no CPE. None is in the CISA catalog. `vigil doctor` does not read the OpenSSL library version. No doctor check was added.

- CVE-2026-107493. Use-after-free in `PEM_X509_INFO_read_bio_ex()` when appending to a caller-supplied stack fails. Affected: 4.1.0 before 4.1.1, 4.0.0 before 4.0.4, 3.5.0 before 3.5.10, 3.0.0 before 3.0.24, 1.1.1 before 1.1.1zk, and 1.0.2 before 1.0.2zt. NVD published `2026-11-17T09:17:25.870`.
- CVE-2026-124709. Unbounded memory retention in a QUIC server for rejected streams. Affected: 4.1.0 before 4.1.1, 4.0.0 before 4.0.4, and 3.5.0 before 3.5.10. NVD published `2026-11-17T09:17:27.227`.
- CVE-2026-35190. Out-of-bounds read in TLS 1.3 key-share processing when the Suite B certificate flag is set. Affected: 4.1.0 before 4.1.1, 4.0.0 before 4.0.4, and 3.5.0 before 3.5.10. NVD published `2026-11-17T09:17:27.560`.

The 4.1.1, 4.0.4, and 3.5.10 lines are the same lines the 10 November advisories already named. CVE-2026-107493 also names 3.0.24, 1.1.1zk, and 1.0.2zt, which CVE-2026-107496 already named. These three pages do not say whether the FIPS modules are affected. No floor was added.

Source: [OpenSSL vulnerabilities](https://www.openssl-library.org/news/vulnerabilities/), [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz)

## Model Context Protocol Python SDK

CVE-2026-115563 is in the NVD recent feed, status Received, with no CPE. It was published `2026-11-16T21:17:20.683` and last modified `2026-11-16T22:18:13.897`, after the 16 November snapshot. It is not in the CISA catalog. The record names the official Python SDK for Model Context Protocol servers and clients. It says the affected range is from 1.9.1 until 1.30.0 and 2.2.0, and that the issue is fixed in 1.30.0 and 2.2.0. The same record describes an issuer setting and clearing stored client registration. Those steps were not copied.

This is not `@modelcontextprotocol/sdk`. The npm advisory stays at 1.32.0. `vigil doctor` does not read the Python SDK package. No doctor check was added.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz)

## CISA catalog

The Known Exploited Vulnerabilities catalog is still `2026.11.13`, released 2026-11-13T20:24:18.3008Z, count 1781. The catalog file last-modified is still Fri, 13 Nov 2026 20:24:18 GMT. No entry was added on 14, 15, 16, or 17 November. No catalog due date falls on 17 November 2026.

CVE-2024-27834 (Apple Multiple Products) is due 18 November 2026. It was already recorded on 5 November. Vigil cannot see those products from a page or a certificate. No doctor check was added.

The alerts page and the cybersecurity advisories index both returned HTTP 403, so this note does not describe those indexes.

Source: [CISA KEV catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)

## NVD recent feed

The CVE 2.0 recent feed timestamp is `2026-11-17T08:00:01.091754`. HTTP last-modified is Tue, 17 Nov 2026 13:00:06 GMT. The newest `lastModified` in the file is `2026-11-17T12:17:49.020`.

No configuration modified after the 16 November scan names PHP, CPython, Node.js, nginx, OpenSSL, curl, the Go toolchain, the Linux kernel, WordPress, or Brotli. The three OpenSSL records above have no CPE.

CVE-2026-97043 is still Awaiting Analysis with no CPE. It was last modified `2026-11-17T05:18:39.207`. The description still names the Go `cgo` LDFLAGS check. The floors stay 1.27.4 and 1.26.11. The eMudhra floors were not moved.

CVE-2026-126051 is still Awaiting Analysis with no CPE. It was last modified `2026-11-16T22:18:17.800`. The description still names a Node.js TLS handshake failure. CVE-2026-123873 and CVE-2026-106071 are still absent. The November page still contains CVE-2026-106071 and does not contain CVE-2026-123873. Those three releases are not treated as a fix for CVE-2026-106071.

CVE-2026-99286 and CVE-2026-99287 were already recorded. Both are still Received with no CPE. Their last-modified times are unchanged (`2026-11-16T10:16:46.993` and `2026-11-16T10:17:00.607`). Neither description names a released kernel version. CVE-2026-99288 through CVE-2026-99311 were already recorded on 16 November, including CVE-2026-99308. No kernel floor was invented.

These five identifiers from the 14 November unverified section are still absent: CVE-2026-62253, CVE-2026-27975, CVE-2026-73574, CVE-2026-105857, and CVE-2026-96349. CVE-2026-27975 is still not a Linux kernel confirmation.

Forty-four of the 45 identifiers from the unverified section of the 16 November leads note are now in this feed. None has a CPE. CVE-2026-115533 is still absent. The earlier whole-token `python` match on that id is still not a CPython confirmation. CVE-2026-129875 is Deferred with no CPE and names REBUILD 4.5.0 through 4.5.4. The earlier whole-token `mcp` match on that id is not `@modelcontextprotocol/sdk`.

The forty-four name other products. No doctor check was added.

- OpenText Vibe through 4.0.8.7: CVE-2026-3859 and CVE-2026-3860. Awaiting Analysis.
- Microsoft jxrlib through 1.1, and the mircomir fork before 1.3.1, 1.3.6, or 1.3.7 depending on the id: CVE-2024-58407, CVE-2024-58408, CVE-2026-129857, CVE-2026-129858, CVE-2026-129859, and CVE-2026-129860. Awaiting Analysis.
- myGESTIÓN and STEL Order: CVE-2026-127043 and CVE-2026-127044. Deferred. The descriptions name no fixed release.
- SeaweedFS before 4.42: CVE-2026-129851 and CVE-2026-129852. Received.
- LimeSurvey before 6.17.16+260814 and 7.x before 7.0.10+260813: CVE-2026-129853. Deferred.
- RedAmon before 7.8.0: CVE-2026-129855 and CVE-2026-129854. Deferred.
- wallabag 2.3.3 before 2.6.16: CVE-2026-129856. Received.
- GitBucket through 4.48.0: CVE-2026-129863. Received. The description names no fixed release.
- `@tinacms/graphql` 2.2.2 through 4.1.0: CVE-2026-129861. Received. The description names no fixed release.
- Koillection before 1.8.6: CVE-2026-129862. Received.
- Frappe CRM before 1.84.0: CVE-2026-129864. Received.
- Dinky through 1.2.5: CVE-2026-129865 and CVE-2026-129866. Deferred. The descriptions name no fixed release.
- SamWaf 1.0.128 through 1.3.25-beta.11: CVE-2026-129869. Received. The description names no fixed release.
- Rocboss paopao-ce through 0.6.0-alpha.3: CVE-2026-129867, CVE-2026-129868, CVE-2026-129870, and CVE-2026-129871. Received. The descriptions name no fixed release.
- REBUILD: CVE-2026-129872 (2.7.0 through 4.5.4), CVE-2026-129873 (4.3.0 through 4.5.4), CVE-2026-129874 (3.5.0 through 4.5.4), and CVE-2026-129875 (4.5.0 through 4.5.4). Deferred. The descriptions name no fixed release.
- OfficeCLI 1.0.56 through 1.0.161: CVE-2026-129876. Received. The description names no fixed release.
- DeepAudit through 3.8.0: CVE-2026-129877, CVE-2026-129878, CVE-2026-129879, and CVE-2026-129880. Received. The descriptions name no fixed release.
- Weblate 2026.6 through 2026.11.2: CVE-2026-129881. Received. The description names no fixed release.
- thirdweb Dashboard through commit `940b3745`: CVE-2026-129883, CVE-2026-129884, CVE-2026-129886, and CVE-2026-129887. Received. The descriptions name no released version.
- Kiwi TCMS before 17.1: CVE-2026-129882. Deferred.
- Unrolled Secure before 1.18.0: CVE-2026-129885. Received.
- Cetmix Tower through 17.0.3.0.0 and 18.0 before 18.0.4.0.1: CVE-2026-129888. Received.

Other records modified after the 16 November snapshot whose descriptions match `wordpress` or `php` name WordPress plugins, WordPress themes, or other PHP applications. They are not WordPress core and they are not the PHP runtime. No plugin list was added. The PHP floors were not moved.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz)

## 17 November oss-security

The 17 November index has 1 message. It is a reply on the OpenSSH musl password-authentication thread. The message names no CVE id and no OpenSSH release. CVE-2026-123158 was already recorded. 10.6p2 still closes that bypass. The hosts named in the message were not opened. No sshd check was added.

Source: [oss-security, 17 November 2026](https://www.openwall.com/lists/oss-security/2026/11/17/)

## 16 November oss-security, messages added after the last scan

The 16 November index now has 10 messages. Message 1 was already recorded. It is an OpenSSH musl reply and names no CVE id. Message 2 is another reply on that thread. It names no CVE id and no OpenSSH release newer than 10.6p2. No configuration edit was copied. No sshd check was added.

The other messages name products Vigil does not read. No doctor check was added. No remote probe was added. Commands in those messages were not copied.

- CVE-2026-128841. Apache Griffin Web Service, all versions. NVD status Received, no CPE. The message says the project is retired and that no release is planned. No floor was invented.
- CVE-2026-115690. Apache WSS4J 4.0.0 before 4.0.3, 3.0.0 before 3.0.7, and versions before 2.4.5. NVD status Received, no CPE.
- BenchProctor release 2026.11.16. The message names no CVE id. It is a scanner benchmark corpus. Vigil does not read it.
- CVE-2026-129490. littlefs through v2.11.3 when built with `LFS_MIGRATE`. NVD status Received, no CPE. The message says no confirmed upstream fix release is available. No release was invented.
- CVE-2025-71466 and CVE-2025-71467. GPAC/MP4Box before 26.02.0. The message says update to v26.02.0. NVD status Deferred, no CPE.
- CVE-2025-71470. MicroQuickJS revisions before commit `99eed3f94cb66ea7e02fd3472ca7374dee31bb89`. The message names that commit as the fix and names no release. NVD status Received, no CPE. No release was invented.
- Debian Security Advisory 6633-1. Local privilege escalation from the lightdm user to root with LightDM and GTK greeters. The message names no CVE id. It says Debian fixed the issue by dropping a patch. No package floor was invented.

Source: [oss-security, 16 November 2026](https://www.openwall.com/lists/oss-security/2026/11/16/)

The 15 November index still has 3 messages. The 14 November index still has 16. The 13 November index still has 11. The 12 November index still has 8. The 11 November index still has 29.

## Left unchanged

php.net's archive last-modified is still Thu, 12 Nov 2026 13:55:02 GMT. The newest item is still PHP 8.6.0 RC7. The page still says the first GA release, PHP 8.6.0, is planned for 19 November 2026. CVE-2026-115560 still has no fixed PHP version on that page. A disclosed PHP version was not compared with 8.6.0.

The Python blog last-modified is now Mon, 16 Nov 2026 18:20:49 GMT. The newest post is dated 16 November 2026 and is a documentation-translation sponsorship. It names no CVE id and no Python version. Python 3.16.0 alpha 2 is still the newest release post. python.org still lists 3.15.2, 3.14.10, 3.13.18, 3.12.16, and 3.11.18. The downloads page still contains Oct. 25, 2026. The Python floors were not moved. Python 3.16.0 was not used as a comparison.

`https://nodejs.org/dist/index.json` last-modified is now Tue, 17 Nov 2026 03:44:41 GMT. The new row is v27.0.0-alpha.0.1.1, dated 2026-11-16, with security false. v22.23.5 (index date 2026-11-11), v24.22.3 (index date 2026-11-10), and v26.13.1 (index date 2026-11-10) are still the security rows. The vulnerability blog's newest security post is still the 11 November 2026 release. The Node floors were not moved on this pull request.

nginx.org's security page last-modified is still Fri, 06 Nov 2026 10:12:37 GMT. The current fixes are still 1.31.7 and 1.30.6.

curl's security page last-modified is still Tue, 10 Nov 2026 09:05:07 GMT. The first row is still CVE-2026-107929, published 2026-10-14, last affected 8.22.0. The newest published date in that table is still 2026-10-14. The curl floors were not moved.

`https://go.dev/doc/devel/release` still lists go1.27.4 and go1.26.11, both released 2026-11-10. go1.27.5 and go1.26.12 are absent. The eMudhra floors were not moved.

The emSign ECC Root CA - G3 block was not changed. The Chrome post still says that root removal is expected Tuesday morning, 27 October 2026 PDT, and does not say that release has shipped.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
