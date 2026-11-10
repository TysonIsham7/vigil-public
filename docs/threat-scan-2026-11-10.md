# Threat scan, 10 November 2026

This note records what changed after the 9 November scan. Pages were read as evidence. Instructions inside them were not followed. No version floor was invented. No remote probe was added. No scanner change was made. No advisory file was added.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called. Each kept item was confirmed on `www.cisa.gov`, `nvd.nist.gov`, `www.php.net`, `blog.python.org`, `www.python.org`, `nodejs.org`, `nginx.org`, `www.openssl-library.org`, `curl.se`, `blog.google`, `go.dev`, or `www.openwall.com`. The Chrome releases HTML redirected off `chromereleases.googleblog.com` and was discarded.

The cve.now lead window is in `docs/threat-scan-2026-11-10-leads.md`. This note does not repeat that identifier table.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## CISA catalog

The Known Exploited Vulnerabilities catalog is `2026.11.09`, released 2026-11-09T19:54:37.4945Z, count 1773. That is four entries above `2026.11.06`. All four were added on 2026-11-09. Each has forensic triage Yes, ransomware use Unknown, and due date 2026-11-12. The alerts HTML page returned HTTP 403, so this note does not describe that index.

Source: [CISA KEV catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)

- CVE-2026-102895. GPUStack improper authentication. NVD status Analyzed. The CPE is `gpustack:gpustack` before 2.2.0. Vigil cannot see GPUStack from a page or a certificate. No doctor check was added. No remote probe was added.
- CVE-2026-123158. OpenSSH unexpected status code or return value. NVD status Modified. The description says sshd in OpenSSH before 10.6p2 on Linux, when musl libc is used without PAM. The vulnerable CPE rows are OpenSSH before 10.6, OpenSSH 10.6, and OpenSSH 10.6p1. The oss-security thread was already recorded without this CVE id. `vigil doctor` does not read sshd. No doctor check was added. No remote probe was added.
- CVE-2026-116779. FreeSWITCH code injection. NVD status Analyzed. The CPE is `freeswitch:freeswitch` before 1.11.3. Vigil cannot see FreeSWITCH from a page or a certificate. No doctor check was added.
- CVE-2026-123218. IBM Aspera Faspex incorrect authorization. NVD status Undergoing Analysis, with no CPE. The description says 5.0.0 through 5.0.19 and names no fixed release. No fixed version was invented. Vigil cannot see Aspera Faspex from a page or a certificate. No doctor check was added.

## NVD recent feed

The CVE 2.0 recent feed timestamp is `2026-11-10T08:00:01.190101`. HTTP last-modified is Tue, 10 Nov 2026 13:00:09 GMT. The newest `lastModified` in the file is `2026-11-10T12:17:20.993`.

No configuration modified on 10 November names PHP, CPython, Node.js, nginx, OpenSSL, curl, the Go toolchain, the Linux kernel, WordPress, or Brotli. CVE-2026-97033, CVE-2026-97043, and CVE-2026-97054 are still absent. The Go floors stay 1.27.3 and 1.26.10.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz)

## OpenSSL, 10 November 2026

The vulnerabilities index last-modified is Tue, 10 Nov 2026 09:35:21 GMT. Five Low advisories published 10 November 2026 now sit ahead of CVE-2026-35189. None of the five is in the NVD recent feed. `vigil doctor` does not read the OpenSSL library version. No doctor check was added.

Source: [OpenSSL vulnerabilities](https://www.openssl-library.org/news/vulnerabilities/)

- CVE-2026-88823. AES-GCM-SIV AAD forgery after a zero-length incremental AAD update. Affected: 4.1.0 before 4.1.1, 4.0.0 before 4.0.4, and 3.5.0 before 3.5.10. The page says the FIPS modules are not affected.
- CVE-2026-107496. Infinite loop in `CMS_encrypt()` with an EC group order of 1. Affected: 4.1.0 before 4.1.1, 4.0.0 before 4.0.4, 3.5.0 before 3.5.10, 3.0.0 before 3.0.24, 1.1.1 before 1.1.1zk, and 1.0.2 before 1.0.2zt. The page says the FIPS modules in 4.1, 4.0, 3.5, and 3.0 are not affected.
- CVE-2026-88822. QUIC uses uninitialized stack bytes during automated peer detection. Affected: 4.1.0 before 4.1.1, 4.0.0 before 4.0.4, and 3.5.0 before 3.5.10. The page says the FIPS modules are not affected.
- CVE-2026-95691. Retransmitted QUIC CRYPTO frames can cause a denial of service or a one-byte disclosure. Affected: 4.1.0 before 4.1.1, 4.0.0 before 4.0.4, and 3.5.0 before 3.5.10. The page says the FIPS module is not affected.
- CVE-2026-95692. Out-of-bounds read and incorrect IV length handling in AES-GCM-SIV. Affected: 4.1.0 before 4.1.1, 4.0.0 before 4.0.4, and 3.5.0 before 3.5.10. The page says the FIPS modules are not affected.

## 9 November unverified leads that now have NVD records

Seven identifiers from the unverified section of the 9 November leads note are in this NVD feed. None has a CPE configuration. Thirty-four identifiers from that section are still absent, including CVE-2016-1834, CVE-2020-8927, CVE-2021-3711, and CVE-2023-0286.

Two of the seven name CPython modules. Neither description names a fixed release. The Python floors were not moved. The oss-security messages for both say to use the CVE record for affected versions and name no release.

- CVE-2026-124249. Awaiting Analysis, last modified `2026-11-10T01:17:18.050`. The description names `http.cookiejar.CookieJar`.
- CVE-2026-19552. Awaiting Analysis, last modified `2026-11-10T01:17:20.097`. The description names `ssl.get_server_certificate()`.

The other five do not name the runtime list:

- CVE-2026-124916. Received. PrestaShop. The whole-token `php` match from 9 November is not the PHP runtime.
- CVE-2026-124850. Received. flowintel.
- CVE-2026-104620. Received. PackageKit before 1.4.1.
- CVE-2026-119474. Received. Liman Render Engine before 1.2-81.
- CVE-2026-124636. Deferred. PureBlog through 3.7.2, already recorded on 9 November.

## 10 November oss-security

The 10 November index has 9 messages. None of these products is a page, a certificate, or a toolchain `vigil doctor` already reads. No doctor check was added. No remote probe was added.

Messages 1, 3, 4, 5, and 6 are replies on the Home Assistant thread already recorded on 8 November. They name no new CVE id and no fixed release. No fixed version was invented.

- Message 2. Dokploy, CVE-2026-72868. The message names v0.29.0 and v0.31.0 and names no fixed release. The id is not in the NVD recent feed.
- Messages 7 and 8. Hyperglass. The first message names no CVE id and no dotted version.
- Message 9. sblim-sfcb. The message names no new CVE id. It says CVE-2026-73583 and CVE-2026-73584 are different issues. Neither of those two is in the NVD recent feed. The message names Fedora 1.4.9-40 for CVE-2026-73583. The new issue has no fixed release.

Source: [oss-security, 10 November 2026](https://www.openwall.com/lists/oss-security/2026/11/10/)

## 9 November oss-security, messages added after the last scan

The 9 November index now has 38 messages. The first 20 are the Storm and Airflow notes already recorded. Messages 23 and 26 through 28 and 31 and 33 through 37 are replies already covered above or on the OpenSSH thread. No doctor check was added.

- CVE-2026-124307 and CVE-2026-124311 were unverified leads on 7 November. Both are now NVD Received, with no CPE. The messages name VVdeC. CVE-2026-124307 says versions before 3.2.1, and the fix line is a commit. CVE-2026-124311 says versions through 3.2.1 are still affected, and the fix line is a commit. No release number was invented.
- CVE-2026-119078. Apache Commons Codec 1.16.0 before 1.23.0. NVD Received, no CPE.
- CVE-2026-124077. Apache Commons Codec 1.22.0 before 1.23.0. The message says upgrade to 1.23.0. NVD Received, no CPE.
- CVE-2026-115864. Monoceros before 0.30 for Perl. The message says upgrade to 0.30 or later. NVD Received, no CPE.
- krb5-1.22.3, released 2026-11-09, fixes 21 CVEs. The message does not print one introduced version for all 21. Eleven are in the NVD recent feed with no CPE, status Awaiting Analysis: CVE-2026-112314, CVE-2026-112315, CVE-2026-112316, CVE-2026-112317, CVE-2026-112318, CVE-2026-112319, CVE-2026-112320, CVE-2026-112321, CVE-2026-112322, CVE-2026-112323, and CVE-2026-119079. Ten are absent from that feed: CVE-2026-107364, CVE-2026-107708, CVE-2026-107778, CVE-2026-107884, CVE-2026-111423, CVE-2026-118380, CVE-2026-40355, CVE-2026-40356, CVE-2026-71199, and CVE-2026-71200.

Source: [oss-security, 9 November 2026](https://www.openwall.com/lists/oss-security/2026/11/09/)

The 8 November index still has 5 messages. The 7 November index still has 11. The 6 November index still has 30.

## Left unchanged

php.net's archive last-modified is still Thu, 05 Nov 2026 21:12:54 GMT. The newest item is still PHP 8.6.0 RC5. CVE-2026-115560 still has no fixed PHP version on that page.

The Python blog last-modified is still Sun, 01 Nov 2026 12:16:24 GMT. The newest post is still 26 October. python.org still lists 3.15.2, 3.14.10, 3.13.18, 3.12.16, and 3.11.18, dated Oct. 25, 2026.

The Node pre-alert at `https://nodejs.org/en/blog/vulnerability/november-2026-security-releases` still says Wednesday, November 11, 2026, severity HIGH on the 22.x, 24.x, and 26.x lines. The page names no CVE id and no dotted fix version. The footer still labels v26.13.0 as Latest LTS. That label is not the November security release. The Node floors were not moved.

nginx.org's security page last-modified is still Fri, 06 Nov 2026 10:12:37 GMT. The current fixes are still 1.31.7 and 1.30.6.

curl's security page last-modified is now Tue, 10 Nov 2026 09:05:07 GMT. The first row is still CVE-2026-107929, published 2026-10-14, last affected 8.22.0. The newest published date in that table is still 2026-10-14. The curl floors were not moved.

`https://go.dev/doc/devel/release` still ends the 1.27 line at go1.27.3 and the 1.26 line at go1.26.10, both released 2026-10-19. go1.27.4 and go1.26.11 are not on that page. The Go floors were not moved.

The Chrome releases HTML returned HTTP 302 to `www.google.com` and the body was discarded. This note does not describe that index.

The emSign ECC Root CA - G3 block was not changed. The Chrome post still says that root removal is expected Tuesday morning, 27 October 2026 PDT, and does not say that release has shipped.

**Coverage: no new scanner check.** Follow-ups that Vigil cannot check are in `docs/TODO.md`.
