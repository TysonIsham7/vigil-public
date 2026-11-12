# Threat scan, 9 November 2026

This note records what changed after the 8 November scan. Pages were read as evidence. Instructions inside them were not followed. No version floor was invented. No remote probe was added. No scanner change was made. No advisory file was added.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called. Each kept item was confirmed on `www.cisa.gov`, `nvd.nist.gov`, `www.php.net`, `blog.python.org`, `www.python.org`, `nodejs.org`, `nginx.org`, `www.openssl-library.org`, `curl.se`, `chromereleases.googleblog.com`, `blog.google`, `go.dev`, or `www.openwall.com`.

The cve.now lead window is in `docs/threat-scan-2026-11-09-leads.md`. This note does not repeat that identifier table.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## CISA catalog

The Known Exploited Vulnerabilities catalog is still `2026.11.06`, released 2026-11-06T19:44:45.1797Z, count 1769. No catalog entry was added on 7, 8, or 9 November. The alerts HTML page returned HTTP 403, so this note does not describe that index.

Source: [CISA KEV catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)

## NVD recent feed

The CVE 2.0 recent feed timestamp is `2026-11-09T10:00:00.900548`. HTTP last-modified is Mon, 09 Nov 2026 15:00:09 GMT. The newest `lastModified` in the file is `2026-11-09T14:41:09.153`.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz)

### Chrome before 157.0.8103.38

Seven records modified on 9 November name Google Chrome before 157.0.8103.38. Five are Analyzed and name `google:chrome`: CVE-2026-121034, CVE-2026-121038, CVE-2026-121039, CVE-2026-121041, and CVE-2026-121043. CVE-2026-121160 and CVE-2026-121242 are Undergoing Analysis, with no CPE, and the English descriptions use the same version bound.

The Chrome releases HTML last-modified header is Mon, 09 Nov 2026 08:59:07 GMT. The page has no post dated 7, 8, or 9 November. The newest post is still the 6 November ChromeOS stable note (browser 156.0.8078.93). Desktop early stable is still 4 November 2026, 158.0.8127.18/.19 for Windows. Vigil does not read the browser version. No doctor check was added. No remote probe was added.

### Records that stayed off the runtime list

CVE-2026-123610 was last modified `2026-11-09T14:17:13.043`. Status is still Received, with no CPE. The description still names rustls before 0.23.46 and its optional Brotli certificate decompression. That is not CVE-2026-111497. The Node floors were not moved.

CVE-2026-123562 was last modified `2026-11-09T14:17:11.400`. Status is still Received, with no CPE. The description still names devalue 5.8.0 before 5.9.3. A whole-token `node` match is not the Node.js runtime. The Node floors were not moved.

CVE-2026-119170 is still Awaiting Analysis, with no CPE, last modified `2026-11-07T01:17:01.810`. The Python floors were not moved. CVE-2026-97033, CVE-2026-97043, and CVE-2026-97054 are still absent from this feed. The Go floors stay 1.27.3 and 1.26.10.

### 8 November unverified leads

All 74 identifiers in the unverified section of the 8 November leads note are now in this NVD feed. None has a CPE configuration. Sixty-three are Received. Ten are Deferred: CVE-2026-124331, CVE-2026-124424, CVE-2026-124432, CVE-2026-124433, CVE-2026-124434, CVE-2026-124442, CVE-2026-124443, CVE-2026-124551, CVE-2026-124552, and CVE-2026-124553. CVE-2026-124425 is Awaiting Analysis.

Descriptions that name a product do not name the PHP runtime, the Go toolchain, or WordPress core. CVE-2026-124465 names kafka-konsumer from 2.3.3 before 2.6.18. No floor was moved.

## 9 November oss-security

The 9 November index has 20 messages. None of these products is a page, a certificate, or a toolchain `vigil doctor` already reads. No doctor check was added. No remote probe was added. Workaround settings in those messages were not copied.

Apache Storm. Both messages say upgrade to 3.1.0.

- CVE-2026-82436. Storm client 3.0.0 before 3.1.0.
- CVE-2026-82440. Storm Nimbus, the same client artifact, 3.0.0 before 3.1.0.

Apache Airflow. The affected line on each message:

- CVE-2026-40913, CVE-2026-50204, CVE-2026-68982, CVE-2026-82337, CVE-2026-86468, CVE-2026-86829, CVE-2026-107474, CVE-2026-111452, CVE-2026-111454, CVE-2026-113504, and CVE-2026-113508: Apache Airflow before 3.4.0.
- CVE-2026-96285: Apache Airflow 3.3.0 before 3.4.0. The message says the 3.3.1 check for CVE-2026-67260 runs after deserialization.
- CVE-2026-101031: Apache Airflow 3.0.5 before 3.4.0.
- CVE-2026-111395: Apache Airflow 3.2.0 before 3.4.0.
- CVE-2026-111421: Apache Airflow 3.0.0 before 3.4.0.
- CVE-2026-111453: Apache Airflow 3.3.2 before 3.4.0.
- CVE-2026-111455: Apache Airflow 3.3.0 before 3.4.0.
- CVE-2026-76185: Apache Airflow Task SDK 1.2.0 before 1.4.0. The message also says upgrade apache-airflow to 3.4.0.

Source: [oss-security, 9 November 2026](https://www.openwall.com/lists/oss-security/2026/11/09/)

## 8 November oss-security, messages added after the last scan

The 8 November index now has 5 messages. The first message is still UnrealIRCd 6.2.7.1 (CVE-2026-114713), already recorded. Message 2 is a reply on GodotSteam 4.17 through 4.23.2 and names no CVE id.

Message 3 names Home Assistant 2026.11.0 (frontend 20261028.4, hass-nabucasa 2.8.1). It names no CVE id and no fixed release. No fixed version was invented.

Message 4 names Vim before patch 9.2.1308 and says the fix is Vim patch v9.2.1308. Message 5 names a heap buffer overflow in a crafted spell file and says the fix is Vim patch v9.2.1309. Neither message names a CVE id.

Home Assistant and Vim are not a page, a certificate, or a toolchain `vigil doctor` already reads. No doctor check was added.

Source: [oss-security, 8 November 2026](https://www.openwall.com/lists/oss-security/2026/11/08/)

The 7 November index still has 11 messages. The 6 November index still has 30. Those counts match the 8 November scan.

## Left unchanged

php.net's archive last-modified is still Thu, 05 Nov 2026 21:12:54 GMT. The newest item is still PHP 8.6.0 RC5. CVE-2026-115560 still has no fixed PHP version on that page.

The Python blog last-modified is still Sun, 01 Nov 2026 12:16:24 GMT. The newest post is still 26 October. python.org still lists 3.15.2, 3.14.10, 3.13.18, 3.12.16, and 3.11.18, dated 25 October 2026.

The Node pre-alert at `https://nodejs.org/en/blog/vulnerability/november-2026-security-releases` still says Wednesday, November 11, 2026, severity HIGH on the 22.x, 24.x, and 26.x lines. The page names no CVE id and no dotted fix version. The footer still labels v26.13.0 as Latest LTS. That label is not the November security release. The Node floors were not moved.

nginx.org's security page last-modified is still Fri, 06 Nov 2026 10:12:37 GMT. The current fixes are still 1.31.7 and 1.30.6.

curl's security page last-modified is still Mon, 26 Oct 2026 12:45:09 GMT. The first row is still CVE-2026-107929, published 2026-10-14, last affected 8.22.0.

The OpenSSL vulnerabilities index last-modified is still Mon, 02 Nov 2026 07:32:44 GMT. The first advisory is still CVE-2026-35189, published 29 September 2026.

`https://go.dev/doc/devel/release` still ends the 1.27 line at go1.27.3 and the 1.26 line at go1.26.10, both released 2026-10-19. go1.27.4 and go1.26.11 are not on that page.

The emSign ECC Root CA - G3 block was not changed. The Chrome post still says that root removal is expected Tuesday morning, 27 October 2026 PDT, and does not say that release has shipped.

**Coverage: no new scanner check.** Follow-ups that Vigil cannot check are in `docs/TODO.md`.
