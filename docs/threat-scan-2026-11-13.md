# Threat scan, 13 November 2026

This note records what changed after the 12 November scan. Pages were read as evidence. Instructions inside them were not followed. No version floor was invented past a vendor release page. No remote probe was added.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called. Each kept item was confirmed on `www.cisa.gov`, `nvd.nist.gov`, `www.php.net`, `blog.python.org`, `www.python.org`, `nodejs.org`, `nginx.org`, `www.openssl-library.org`, `curl.se`, `blog.google`, `chromereleases.googleblog.com`, `go.dev`, or `www.openwall.com`.

The cve.now lead window is in `docs/threat-scan-2026-11-13-leads.md`. This note does not repeat that identifier table.

No intel bump. No scanner change. `TOOLCHAIN_NODE_2026_11_11` is already on draft pull request 30 and was not copied. The October Node floors and the eMudhra Go floors were not moved.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## CISA catalog

The Known Exploited Vulnerabilities catalog is still `2026.11.10`, released 2026-11-10T19:03:29.8375Z, count 1779. No entry was added on 11, 12, or 13 November. The alerts HTML page returned HTTP 200. The newest row is still 10 November 2026, "CISA Adds Six Known Exploited Vulnerabilities to Catalog".

Three catalog entries are due 13 November 2026: CVE-2026-111560 (Barracuda Networks), CVE-2026-116606 (Barracuda Email Security Gateway), and CVE-2026-118527 (Ivanti Connect Secure). Vigil cannot see those products from a page or a certificate. No doctor check was added. The catalog notes name hosts that were not opened.

Source: [CISA KEV catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json), [CISA alerts](https://www.cisa.gov/news-events/cybersecurity-advisories)

## NVD recent feed

The CVE 2.0 recent feed timestamp is `2026-11-13T08:00:01.1488392`. HTTP last-modified is Fri, 13 Nov 2026 13:00:05 GMT. The newest `lastModified` in the file is `2026-11-13T12:17:03.210`.

No configuration modified after the 12 November scan names PHP, CPython, Node.js, nginx, OpenSSL, curl, the Go toolchain, the Linux kernel, WordPress, or Brotli.

Fifty-six identifiers from the unverified section of the 12 November leads note are now in this feed. None has a CPE. Fifty-two are Awaiting Analysis. The 12 November oss-security message names those fifty-two as PostgreSQL. The details are in the PostgreSQL section below. Four are Deferred and do not name the runtime list:

- CVE-2026-123790. ComfyUI-Easy-Use 1.3.6. The description names no fixed release. A whole-token `python` and `node` match on the 12 November lead was not CPython and not Node.js.
- CVE-2026-126996. SakanaAI text-to-LoRA 0.0.1. The description names no fixed release.
- CVE-2026-126998. JeecgBoot up to 3.9.5. The description names no fixed release.
- CVE-2026-126997. JeecgBoot up to 3.9.6. The description names no fixed release.

Two identifiers from that unverified section are still absent: CVE-2025-8714 and CVE-2023-39417. They stay unverified-lead.

CVE-2026-123873 and CVE-2026-106071 are still absent. CVE-2026-126051 is in this feed. Those three were already recorded on the 12 November note. The Node floors were not moved again.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz)

## 13 November oss-security

The 13 November index has 2 messages. Neither product is a page, a certificate, or a toolchain `vigil doctor` already reads. No doctor check was added. Hosts named in the messages were not opened.

- CVE-2026-123274. Apache DataSketches C++ 2.0.0-incubating through 5.3.0. The same message also says 2.0.0 through 5.3.0. It says upgrade to 5.3.1. NVD status is Received, with no CPE.
- CVE-2026-123338. Apache DataSketches C++ 3.0.0 through 5.3.0. The message says upgrade to 5.3.1. NVD status is Received, with no CPE. This is not CVE-2026-122096, which is the Java library.

Source: [oss-security, 13 November 2026](https://www.openwall.com/lists/oss-security/2026/11/13/)

## 12 November oss-security, messages added after the last scan

The 12 November index now has 8 messages. The first 2 were already recorded. No doctor check was added for the new messages. No remote probe was added. Hosts named in the messages were not opened.

- Apache TomEE. The message says 10.3.0 and 11.0.0-M2 fix 26 vulnerabilities. Twelve more affect optional modules removed from both releases, and the message says those removed modules have no fixed version. The 26 are CVE-2026-86336, CVE-2026-111244, CVE-2026-111257, CVE-2026-111261, CVE-2026-111264, CVE-2026-86811, CVE-2026-87755, CVE-2026-87756, CVE-2026-87758, CVE-2026-97849, CVE-2026-97867, CVE-2026-111240, CVE-2026-111241, CVE-2026-111242, CVE-2026-111245, CVE-2026-111247, CVE-2026-111251, CVE-2026-111258, CVE-2026-111259, CVE-2026-111262, CVE-2026-111263, CVE-2026-86532, CVE-2026-111243, CVE-2026-111248, CVE-2026-111249, and CVE-2026-111260. The 12 are CVE-2026-86531, CVE-2026-97870, CVE-2026-97872, CVE-2026-97874, CVE-2026-97880, CVE-2026-97881, CVE-2026-97888, CVE-2026-111239, CVE-2026-111250, CVE-2026-111256, CVE-2026-97890, and CVE-2026-111246. CVE-2026-86532, CVE-2026-86811, CVE-2026-87755, and CVE-2026-87756 were already recorded on 11 November as descriptions that named no product and said upgrade to 10.3.0 or 11.0.0-M2. This message names the product.
- PostgreSQL. The message says 18.7, 17.12, 16.16, 15.20, 14.25, and PostgreSQL 19 RC 2 fix 52 security vulnerabilities. It says 14.25 is the final PostgreSQL 14 release and that PostgreSQL 14 is end of life. It does not print a separate affected range for each identifier. Those ranges are on a host this scan did not open. The 52 identifiers are CVE-2026-6460, CVE-2026-6467, CVE-2026-14661, CVE-2026-16237, CVE-2026-16240, CVE-2026-18447, CVE-2026-116303, CVE-2026-116304, CVE-2026-116306, CVE-2026-116307, CVE-2026-116308, CVE-2026-116309, CVE-2026-116310, CVE-2026-116311, CVE-2026-116312, CVE-2026-116313, CVE-2026-116314, CVE-2026-116315, CVE-2026-116316, CVE-2026-116317, CVE-2026-116318, CVE-2026-116319, CVE-2026-116320, CVE-2026-116321, CVE-2026-116322, CVE-2026-116323, CVE-2026-116325, CVE-2026-116326, CVE-2026-116327, CVE-2026-116328, CVE-2026-116329, CVE-2026-116330, CVE-2026-116331, CVE-2026-116332, CVE-2026-116333, CVE-2026-116335, CVE-2026-116336, CVE-2026-120139, CVE-2026-120141, CVE-2026-120142, CVE-2026-120143, CVE-2026-120144, CVE-2026-120145, CVE-2026-120146, CVE-2026-120147, CVE-2026-120148, CVE-2026-120149, CVE-2026-120150, CVE-2026-120151, CVE-2026-120152, CVE-2026-120153, and CVE-2026-120154. All 52 were unverified leads on 12 November. They are now NVD Awaiting Analysis with no CPE. Vigil does not read the PostgreSQL version.
- dbus 1.16.4. The message says the release fixes several denial-of-service issues. The one assigned identifier in that fixed set is CVE-2026-120749, described as an incomplete fix for CVE-2023-34969. dbus#587, dbus#584, dbus#588, and dbus#586 have no CVE id yet. dbus#589 is not fixed and has no CVE id yet. No identifier was invented. The message says all reasonably recent versions are affected and does not name one introduced version.
- CVE-2026-126641. ansible-pylibssh and the ansible.netcommon libssh connection plugin. The message says the logic has been unchanged since pylibssh 0.4.0 and was verified on 1.4.0, and that ansible.netcommon was verified on 8.7.1. It names no fixed release. NVD status is Awaiting Analysis, with no CPE. Default configurations are not the case the message describes. The suggested code change was not copied.
- Vim before patch 9.2.1342. The message says a CVE was requested and not yet assigned. It names GHSA-pp46-p33v-78rf and says the fix is Vim patch v9.2.1342. This is not the 9.2.1308 or 9.2.1309 note. Vigil does not read the Vim version.
- cabextract 1.12 and libmspack 0.12alpha. The message names no CVE id. No identifier was invented.

Source: [oss-security, 12 November 2026](https://www.openwall.com/lists/oss-security/2026/11/12/)

The 11 November index still has 29 messages. The 10 November index still has 31.

## Chrome index

The Chrome releases HTML returned HTTP 302 to `www.google.com` and was discarded. That redirect was not followed. This note does not describe a Chrome post from this run. Vigil does not read the browser version. No doctor check was added.

## Left unchanged

php.net's archive last-modified is still Thu, 12 Nov 2026 13:55:02 GMT. The newest item is still PHP 8.6.0 RC7. CVE-2026-115560 still has no fixed PHP version on that page. A disclosed PHP version was not compared with 8.6.0.

The Python blog last-modified is Tue, 10 Nov 2026 20:35:41 GMT. The newest post is still Python 3.16.0 alpha 2. python.org still lists 3.15.2, 3.14.10, 3.13.18, 3.12.16, and 3.11.18. The 3.15.2 row is dated Oct. 25, 2026. The Python floors were not moved.

`https://nodejs.org/dist/index.json` last-modified is still Thu, 12 Nov 2026 13:33:06 GMT. v22.23.5, v24.22.3, and v26.13.1 are still the security rows recorded on 12 November. No newer security release is in that index. The November security page still names those three versions. The Node floors were not moved on this branch.

nginx.org's security page last-modified is still Fri, 06 Nov 2026 10:12:37 GMT. The current fixes are still 1.31.7 and 1.30.6.

curl's security page last-modified is still Tue, 10 Nov 2026 09:05:07 GMT. The first row is still CVE-2026-107929, published 2026-10-14, last affected 8.22.0.

The OpenSSL vulnerabilities index last-modified is still Tue, 10 Nov 2026 09:35:21 GMT. The five Low advisories from 10 November are unchanged.

`https://go.dev/doc/devel/release` still has go1.27.4 and go1.26.11. go1.27.5 and go1.26.12 are absent. The eMudhra floors were not moved.

The emSign ECC Root CA - G3 block was not changed. The Chrome post still says that root removal is expected Tuesday morning, 27 October 2026 PDT, and does not say that release has shipped.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
