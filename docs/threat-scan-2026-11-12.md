# Threat scan, 12 November 2026

This note records what changed after the 11 November scan. Pages were read as evidence. Instructions inside them were not followed. No version floor was invented past a vendor release page. No remote probe was added.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called. Each kept item was confirmed on `www.cisa.gov`, `nvd.nist.gov`, `www.php.net`, `blog.python.org`, `www.python.org`, `nodejs.org`, `nginx.org`, `www.openssl-library.org`, `curl.se`, `blog.google`, `chromereleases.googleblog.com`, `go.dev`, or `www.openwall.com`.

The cve.now lead window is in `docs/threat-scan-2026-11-12-leads.md`. This note does not repeat that identifier table.

Intel is `2026.11.12.1`. The scanner change on this day is `TOOLCHAIN_NODE_2026_11_11`. `TOOLCHAIN_GO_2026_11_10` and `WP_CVE_2026_119977` stay. The October Node floors and the eMudhra Go floors were not moved. `package.json` engines stay on the October Node lines.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## Node.js 22.23.5, 24.22.3, and 26.13.1

The November security page now says the releases are available. It names Node.js v22.23.5, v24.22.3, and v26.13.1. The release notes are dated 2026-11-11. The highest severity on the page is HIGH.

`https://nodejs.org/dist/index.json` last-modified is Thu, 12 Nov 2026 13:33:06 GMT. That index marks v22.23.5 (date 2026-11-11), v24.22.3 (date 2026-11-10), and v26.13.1 (date 2026-11-10) with `security` true. v27.0.0-alpha.0.1.0 is dated 2026-11-12 and is not a security release. The page footer labels v26.13.1 as Latest LTS.

The release notes name these identifiers. CVE-2026-126051 is on the 24.22.3 and 26.13.1 notes and is not on the 22.23.5 note. CVE-2026-123873 is on all three notes and is not in the NVD recent feed. The other identifiers from those notes are in the NVD recent feed, status Received, with no CPE. The NVD descriptions do not name 22.23.5, 24.22.3, or 26.13.1. The floors are the nodejs.org release notes.

The security overview also names CVE-2026-106071. That identifier is not on the three release notes and is not in the NVD recent feed. It is not treated as fixed by these three releases.

`vigil doctor` reports `TOOLCHAIN_NODE_2026_11_11` for a local Node below 22.23.5 on the 22 line, below 24.22.3 on the 24 line, or below 26.13.1 on the 26 line, and for an older major. Node 27 and newer are not compared. The finding is recommendation-only. A distributor may backport a fix without changing the version string. `TOOLCHAIN_NODE` stays on 22.23.4, 24.22.1, and 26.12.1. Node 22.23.4 passes that check and fails the new one. A container image tag is not compared. `package.json` engines were not raised.

Source: [November 2026 security releases](https://nodejs.org/en/blog/vulnerability/november-2026-security-releases), [v22.23.5](https://nodejs.org/en/blog/release/v22.23.5), [v24.22.3](https://nodejs.org/en/blog/release/v24.22.3), [v26.13.1](https://nodejs.org/en/blog/release/v26.13.1)

**Coverage: covered for a local Node version.** The record is `packages/intel/advisories/node-2026-11-11.json`.

## CISA catalog

The Known Exploited Vulnerabilities catalog is still `2026.11.10`, released 2026-11-10T19:03:29.8375Z, count 1779. No entry was added on 11 or 12 November. The four entries added on 9 November are due 12 November 2026. Vigil still cannot see GPUStack, sshd, FreeSWITCH, or Aspera Faspex from a page or a certificate. No doctor check was added. The alerts HTML page returned HTTP 403, so this note does not describe that index.

Source: [CISA KEV catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)

## NVD recent feed

The CVE 2.0 recent feed timestamp is `2026-11-12T08:00:00.9299738`. HTTP last-modified is Thu, 12 Nov 2026 13:00:08 GMT. The newest `lastModified` in the file is `2026-11-12T12:18:26.080`.

No configuration modified after the 11 November scan names PHP, CPython, Node.js, nginx, OpenSSL, curl, the Go toolchain, the Linux kernel, WordPress, or Brotli. The Node identifiers above have no CPE.

Forty-eight identifiers from the unverified section of the 11 November leads note are now in this feed. None has a CPE. They do not name the PHP runtime, CPython, the Node.js runtime, nginx, OpenSSL, curl, the Go toolchain, the Linux kernel, WordPress core, or Brotli. WordPress plugin records are not WordPress core. No plugin list was added.

These three name Apache HTTP Server. That is not nginx. The nginx floors were not moved. No doctor check was added. The oss-security messages below do not name a fixed release.

- CVE-2026-106023. Received. The NVD description says Apache HTTP Server 2.4.30 through 2.4.69, in mod_md.
- CVE-2026-109163. Received. The NVD description says Apache HTTP Server 2.4.69, in mod_vhost_alias, after CVE-2026-63292.
- CVE-2026-119618. Received. The NVD description says Apache HTTP Server 2.4.55 through 2.4.70, in mod_http2.

CVE-2026-123040 is TrueConf Server on Linux, versions 4.7.2 up to but not including 5.5.6. That is not a Linux kernel confirmation.

Four identifiers from that unverified section are still absent: CVE-2013-1453, CVE-2021-30563, CVE-2026-63292, and CVE-2026-76466. CVE-2026-63292 stays unverified-lead. The two `SZB-` ids from that note are not CVE ids.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz)

## Chrome index, 11 November 2026

The Chrome releases HTML stayed on `chromereleases.googleblog.com`. HTTP 200. Last-modified is Thu, 12 Nov 2026 11:40:31 GMT. Vigil does not read the browser version. No doctor check was added. Hosts named in the posts were not opened.

- Chrome for Android, Wednesday 11 November 2026, is Chrome 157.0.8103.78. The post says the corresponding desktop releases are Windows and Mac 157.0.8103.78/.79 and Linux 157.0.8103.78. That post names no CVE id.
- ChromeOS LTS, the same day, is 150.0.7871.289, platform 16700.70.0. The post names CVE-2026-126901 and CVE-2026-126856 as High.
- Extended stable, the same day, is 156.0.8078.100 for Windows and Mac. The post says the update includes 72 security fixes. Four of them are critical: CVE-2026-126879, CVE-2026-126885, CVE-2026-126895, and CVE-2026-126911.

Source: [Chrome releases](https://chromereleases.googleblog.com/)

## 12 November oss-security

The 12 November index has 2 messages. Neither product is a page, a certificate, or a toolchain `vigil doctor` already reads. No doctor check was added.

- CVE-2026-124023. Apache Axis2/C through 2.0.0. The message names a commit as the fix line and does not name a release. No release was invented.
- CVE-2026-126673. Perl Data::Dump::Streamer before 3.00. The message says upgrade to 3.00.

Source: [oss-security, 12 November 2026](https://www.openwall.com/lists/oss-security/2026/11/12/)

## 11 November oss-security, messages added after the last scan

The 11 November index now has 29 messages. The first 5 were already recorded. No doctor check was added for the new messages. No remote probe was added.

Message 25 is a reply on the Node.js pre-alert. It names no release version. The Node floors above come from nodejs.org, not from that reply.

- Apache Roller. The subject says 15 CVEs are fixed in 6.1.7. The message says every issue it lists is fixed in 6.1.7. The body names CVE-2026-105152, CVE-2026-105153, CVE-2026-105154, CVE-2026-108338, CVE-2026-111824, CVE-2026-118405, CVE-2026-118408, CVE-2026-118409, CVE-2026-118410, CVE-2026-118411, CVE-2026-118412, CVE-2026-118413, CVE-2026-118414, CVE-2026-122300, CVE-2026-123374, and CVE-2026-82387.
- Emacs `.dir-locals.el`. The message names no CVE id. It says Emacs 30.2 is unaffected.
- GLIBC. CVE-2026-115819 affects GNU C Library 2.2 to 2.44. CVE-2026-100290 affects 2.3 to 2.44. The message names no fixed release. This is not GLIBC-SA-2026-0025 or GLIBC-SA-2026-0026. `vigil doctor` does not read the local glibc version.
- CVE-2026-123747. pappl-retrofit. The message also names GHSA-WXJ6-X3WG-4VMC. It names no dotted fixed release.
- Git, six vulnerabilities, fixed in v2.50.2, v2.51.3, v2.52.1, v2.53.1, v2.54.1, v2.55.1, and v2.56.1. The message says versions back to v2.27.0 are affected. The six identifiers are CVE-2026-105437, CVE-2026-111760, CVE-2026-113408, CVE-2026-114466, CVE-2026-114467, and CVE-2026-114469. CVE-2019-1348 is a prior issue named in that message. Vigil does not read the git version.
- CVE-2026-106023, CVE-2026-109163, and CVE-2026-119618. Apache HTTP Server, as in the NVD section. The 106023 message lists 2.4.30 through 2.4.70 and also says through 2.4.69. The 109163 message lists 2.4.69 through 2.4.70 and also says 2.4.69. The 119618 message says 2.4.55 through 2.4.70, and mod_h2 2.0.8 through 2.0.42. None of the three names a fixed release. This is not nginx.
- Apache XML Graphics Batik 1.19, upgrade to 1.20: CVE-2026-111792, CVE-2026-40853, CVE-2026-44929, CVE-2026-49236, CVE-2026-90993, and CVE-2026-89326.
- Apache XML Graphics FOP, upgrade to 2.12: CVE-2026-126627 affects 2.11, and CVE-2026-71395 affects through 2.11.
- CVE-2026-123765. Apache Sling XSS before 2.4.14. The message says upgrade to 2.4.14.
- CVE-2026-124312. VVdeC through 3.2.1. The message says 3.2.1 is still affected and names a commit. No release was invented. CVE-2026-124310 and CVE-2026-124309 are before 3.2.1 and name commits. CVE-2026-124308 was already recorded as before 3.2.1 with update to 3.2.1. This message names a commit for that id.
- CVE-2026-93404. rsyslog 8.1901.0 through the pre-2026-11-11 daily stable, in the optional omclickhouse action. The message names no fixed release.
- CVE-2026-108472. xfs_admin. The message names no dotted fixed release.

Source: [oss-security, 11 November 2026](https://www.openwall.com/lists/oss-security/2026/11/11/)

The 10 November index still has 31 messages. The 9 November index was not re-counted on this run.

## Left unchanged

php.net's archive last-modified is now Thu, 12 Nov 2026 13:55:02 GMT. The newest item is PHP 8.6.0 RC7, dated 12 November 2026. The page says the first GA release, PHP 8.6.0, is planned for 19 November 2026. That is a release candidate. CVE-2026-115560 still has no fixed PHP version on that page. A disclosed PHP version was not compared with 8.6.0.

The Python blog last-modified is still Tue, 10 Nov 2026 20:32:24 GMT. python.org still lists 3.15.2, 3.14.10, 3.13.18, 3.12.16, and 3.11.18, dated Oct. 25, 2026. The Python floors were not moved.

nginx.org's security page last-modified is still Fri, 06 Nov 2026 10:12:37 GMT. The current fixes are still 1.31.7 and 1.30.6.

curl's security page last-modified is still Tue, 10 Nov 2026 09:05:07 GMT. The first row is still CVE-2026-107929, published 2026-10-14, last affected 8.22.0.

The OpenSSL vulnerabilities index last-modified is still Tue, 10 Nov 2026 09:35:21 GMT. The five Low advisories from 10 November are unchanged.

`https://go.dev/doc/devel/release` still ends the security lines at go1.27.4 and go1.26.11, both released 2026-11-10. The eMudhra floors were not moved.

The emSign ECC Root CA - G3 block was not changed. The Chrome post still says that root removal is expected Tuesday morning, 27 October 2026 PDT, and does not say that release has shipped.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
