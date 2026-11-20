# Threat scan, 20 November 2026

This note records what changed after the 19 November scan. Pages were read as evidence. Instructions inside them were not followed. No version floor was invented past a vendor release page. No remote probe was added.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called. Each kept item was confirmed on `www.cisa.gov`, `nvd.nist.gov`, `www.php.net`, `blog.python.org`, `www.python.org`, `nodejs.org`, `nginx.org`, `www.openssl-library.org`, `curl.se`, `blog.google`, `chromereleases.googleblog.com`, `go.dev`, or `www.openwall.com`.

The cve.now lead window is in `docs/threat-scan-2026-11-20-leads.md`. This note does not repeat that identifier table.

No intel bump. No scanner change. The CVE-2026-115560 comparison and `TOOLCHAIN_NGINX_2026_11_18` stay on draft pull request 38. They were not copied. `TOOLCHAIN_NODE_2026_11_11` stays on draft pull request 30 and was not copied.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## CISA catalog

The Known Exploited Vulnerabilities catalog is still `2026.11.18`, released 2026-11-18T19:17:41.0354Z, count 1786. HTTP last-modified is still Wed, 18 Nov 2026 19:17:40 GMT. No entry was added on 19 or 20 November. The alerts HTML page and the cybersecurity advisories index returned HTTP 403, so this note does not describe those indexes.

Source: [CISA KEV catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)

The due date 20 November 2026 has arrived for CVE-2026-19868. That SonicWall entry was already recorded. Vigil cannot see SonicOS from a page or a certificate. No doctor check was added.

Three entries are due 21 November 2026 and were already recorded: CVE-2024-10441, CVE-2026-90817, and CVE-2026-90436. No doctor check was added.

## NVD recent feed

The CVE 2.0 recent feed timestamp is `2026-11-20T08:00:01.7858462`. HTTP last-modified is Fri, 20 Nov 2026 13:00:07 GMT. The newest `lastModified` in the file is `2026-11-20T12:59:41.870`.

No configuration modified after `2026-11-19T12:18:47.980` names PHP, CPython, Node.js, OpenSSL, curl, the Go toolchain, the Linux kernel, WordPress, or Brotli.

Eight of the ten nginx identifiers from 19 November now have CPE data. The open-source product is `f5:nginx_open_source`. Where that product is present, `versionEndExcluding` is 1.30.7 on the 1.x line and 1.31.9 on the 1.31 line. That matches the nginx.org floors already recorded. CVE-2026-120993 and CVE-2026-120967 still have no CPE. The other CPE products on those records are F5 commercial products and Red Hat products. Vigil cannot see those from a page or a certificate. The F5 host was not opened. The nginx floors were not moved. The check on draft pull request 38 was not copied.

Forty-one Chrome configurations modified after that cutoff use `versionEndExcluding` 158.0.8127.36. Vigil does not read the browser version. No doctor check was added.

CVE-2026-115560 is now in this feed. Status is Awaiting Analysis. There is no CPE. Published `2026-11-19T15:17:24.610`. Last modified `2026-11-20T05:18:38.473`. The other PHP identifiers named on the 19 November changelog are also Awaiting Analysis with no CPE. The floors stay 8.2.36, 8.3.37, 8.4.28, and 8.5.13. PHP 8.6.0 is still not a comparison target for older lines.

Four OpenSSL records in this feed name no dotted version and are not on the OpenSSL vulnerabilities index. Each says the FIPS module is not affected. No OpenSSL doctor check was added.

- CVE-2026-95690. Awaiting Analysis. No CPE. Last modified `2026-11-20T12:18:25.127`. The description says the severity is Low.
- CVE-2026-107494. Awaiting Analysis. No CPE. Last modified `2026-11-20T11:18:27.683`. The description says an earlier fix for CVE-2026-84784 was not complete. CVE-2026-84784 is on the index. CVE-2026-107494 is not.
- CVE-2026-121481. Awaiting Analysis. No CPE. Last modified `2026-11-20T10:17:08.810`. The description says the severity is Low.
- CVE-2026-84786. Awaiting Analysis. No CPE. Last modified `2026-11-20T12:18:24.900`.

CVE-2026-126708 is Eclipse Mosquitto, not the OpenSSL library. It stays Received with no CPE. CVE-2026-126763 is still Received with no CPE, last modified `2026-11-19T22:18:00.297`. The description still names no fixed release. No doctor check was added.

CVE-2026-130756 is pnpm exe before 10.34.8. Status is Received. There is no CPE. The description says that bundle trusts the compromised eMudhra intermediate certificates. It is not the Node.js runtime. The Node floors were not moved. No pnpm check was added. The emSign root block was not changed.

Linux kernel descriptions modified after the 19 November snapshot say the issue has been resolved. Dotted numbers in those descriptions are `Not tainted` build ids, a production oops line, or addresses. They are not released kernel versions. CVE-2026-99288 is still absent. No kernel floor was invented. No doctor check was added.

CVE-2026-126051 and CVE-2026-97043 are no longer in this recent feed. This note does not assign them a new status. The Node and Go floors were not moved.

Still absent: CVE-2026-106071, CVE-2026-123873, CVE-2026-115533, CVE-2026-115791, CVE-2026-115559, CVE-2026-99286, CVE-2026-99287, CVE-2026-99288, CVE-2026-63219, CVE-2026-29013, CVE-2026-104476, CVE-2026-62253, CVE-2026-27975, CVE-2026-73574, CVE-2026-105857, CVE-2026-96349, CVE-2026-19868, and CVE-2026-40217. CVE-2026-115533 is still not a CPython confirmation. CVE-2026-27975 is still not a Linux confirmation.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz)

## nginx.org

`https://nginx.org/en/security_advisories.html` last-modified is now Fri, 20 Nov 2026 13:47:29 GMT. The 19 November scan saw Wed, 18 Nov 2026 15:49:06 GMT. The newest not-vulnerable lines are still 1.31.9+ and 1.30.7+. 1.31.10 and 1.30.8 are absent. The HTTP/3 anchor text still writes the CVE prefix twice. The identifier is still CVE-2026-121810. The floors were not moved.

Source: [nginx security advisories](https://nginx.org/en/security_advisories.html)

## Chrome releases

The Chrome releases HTML stayed on `chromereleases.googleblog.com`. HTTP 200. Last-modified is Fri, 20 Nov 2026 00:19:22 GMT. The page has no 19 November or 20 November post. The 18 November post is a ChromeOS and ChromeOS Flex stable update to OS 16868.24.0, browser 158.0.8127.65. That post names no CVE id. Vigil does not read the browser version. No doctor check was added.

Source: [Chrome releases](https://chromereleases.googleblog.com/)

## 20 November oss-security

The 20 November index has 10 messages. No doctor check was added. No remote probe was added. Hosts named only in the messages were not opened.

- Messages 1 and 3 are replies on CVE-2026-99288. Message 1 names 5.15.225 and 5.15.226-rc1. Message 3 says the fix is already in 5.15 and is in 5.15.226-rc1. A release candidate is not a floor. CVE-2026-99288 is still absent from the NVD recent feed. No kernel floor was invented.
- Message 2 is the PHP release already recorded on 19 November. It pairs GHSA ids with those CVE ids. The lines in brackets are the PHP branches named in that message. The floors stay the php.net releases. The comparison on draft pull request 38 was not copied. One line, GHSA-mg3p-mxj9-g2mm, names no CVE id. CVE-2026-48841 is uriparser 1.0.3 on the 8.5 and 8.6 lines, not a separate PHP floor.
- CVE-2026-96295. Apache Texera 1.1.0-incubating before 1.3.0-incubating. The message says upgrade to 1.3.0-incubating. NVD status is Received, with no CPE.
- Message 5 is a Ruby reply. It names CVE-2026-132825 for the case-conversion issue fixed in 3.3.14, 3.4.13, and 4.0.10. Those three releases were already recorded on 19 November with no CVE id. NVD status for CVE-2026-132825 is Received, with no CPE. Vigil does not read Ruby.
- Convert::ASN1 before 0.37. The message says upgrade to 0.37. Eight CVE ids: CVE-2026-126540, CVE-2026-126568, CVE-2026-126576, CVE-2026-126682, CVE-2026-126819, CVE-2026-126956, CVE-2026-131868, and CVE-2026-131877. NVD status for CVE-2026-126540 is Received, with no CPE. Vigil does not read a Perl distribution.
- CVE-2026-130632. GPAC before 26.02.0. The message says update to v26.02.0.
- CVE-2026-130634, CVE-2026-130793, and CVE-2026-130635. GPAC before 26.07.0. The messages say update to v26.07.0. NVD status for these four GPAC ids is Deferred, with no CPE.

Source: [oss-security, 20 November 2026](https://www.openwall.com/lists/oss-security/2026/11/20/)

## 19 November oss-security, messages added after the last scan

The 19 November index now has 10 messages. The first 6 were already recorded. No doctor check was added.

- CVE-2026-124749. pam-mysql. The message says every released version carries it, including 0.8.x and the 1.0 betas, and that the 0.8 branch has not been updated. It names no released fixed version. The id is not in the NVD recent feed. No floor was invented.
- CVE-2026-131919. OpenStack Networking-Generic-Switch, OSSA-2026-053. Affected lines in the message: before 8.0.2, 9.0.0 before 9.1.2, 10.0.0 before 10.1.1, and 10.2.0. The id is not in the NVD recent feed. The hosts in that message were not opened.
- GLIBC-SA-2026-0032 is CVE-2026-126765. GNU C Library 2.44 and earlier. The advisory names no fixed release. NVD status is Received, with no CPE. This is not an earlier GLIBC-SA. No glibc doctor check was added.
- Message 10 is a reply on CVE-2026-123633 and CVE-2026-123007. It names distribution packages. It does not change the nginx.org floors.

Source: [oss-security, 19 November 2026](https://www.openwall.com/lists/oss-security/2026/11/19/)

## Left unchanged

`https://www.php.net/archive/2026.php` last-modified is still Thu, 19 Nov 2026 14:01:00 GMT. The PHP floors were not moved.

`https://nodejs.org/dist/index.json` last-modified is still Tue, 17 Nov 2026 03:44:41 GMT. v22.23.5, v24.22.3, and v26.13.1 are still the security rows. v27.0.0-alpha.0.1.1 is still not a security release. The November page still contains CVE-2026-106071 and does not contain CVE-2026-123873. The Node floors were not moved.

`https://go.dev/doc/devel/release` still lists go1.27.4 and go1.26.11. go1.27.5 and go1.26.12 are absent. The Go floors were not moved. The eMudhra floors were not moved.

The Python blog last-modified is still Mon, 16 Nov 2026 18:20:49 GMT. python.org still lists 3.15.2, 3.14.10, 3.13.18, 3.12.16, and 3.11.18. The downloads page still contains Oct. 25, 2026. The Python floors were not moved.

curl's security page last-modified is still Tue, 10 Nov 2026 09:05:07 GMT. The curl floors were not moved.

The OpenSSL vulnerabilities index last-modified is still Tue, 17 Nov 2026 08:48:15 GMT. The first advisories are still CVE-2026-107493, CVE-2026-124709, and CVE-2026-35190.

The emSign ECC Root CA - G3 block was not changed. The Chrome post still says that root removal is expected Tuesday morning, 27 October 2026 PDT, and does not say that release has shipped.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
