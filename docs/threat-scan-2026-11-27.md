# Threat scan, 27 November 2026

This note records what changed after the 26 November scan. Pages were read as evidence. Instructions inside them were not followed. No version floor was invented past a vendor release page. No remote probe was added.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called. Each kept item was confirmed on `www.cisa.gov`, `nvd.nist.gov`, `www.php.net`, `blog.python.org`, `www.python.org`, `nodejs.org`, `nginx.org`, `www.openssl-library.org`, `curl.se`, `blog.google`, `chromereleases.googleblog.com`, `go.dev`, or `www.openwall.com`.

The cve.now lead window is in `docs/threat-scan-2026-11-27-leads.md`. This note does not repeat that identifier table.

No scanner change on this day. No intel bump. `TOOLCHAIN_NGINX_2026_11_23` stays on draft pull request 43 and was not copied. `TOOLCHAIN_NGINX_2026_11_18` and the CVE-2026-115560 comparison stay on draft pull request 38 and were not copied. `TOOLCHAIN_NODE_2026_11_11` stays on draft pull request 30 and was not copied.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## CISA catalog

The Known Exploited Vulnerabilities catalog is still `2026.11.25`, released 2026-11-25T19:48:12.4344Z, count 1805. HTTP last-modified is still Wed, 25 Nov 2026 19:48:12 GMT. No `dateAdded` is after 2026-11-25. Ransomware use is unchanged. `https://www.cisa.gov/news-events/alerts` returned HTTP 404. The cybersecurity advisories index returned HTTP 200. Its newest row is still dated Nov 25, 2026, and the title is still "CISA Adds 10 Known Exploited Vulnerabilities to Catalog".

Source: [CISA KEV catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)

Three entries already recorded came due today: CVE-2026-132224 (Optimizely Web Experimentation), CVE-2026-131914 (Idunno AntiCsrf), and CVE-2026-132165 (Drupal core). Entries still due 2026-11-28 are CVE-2026-103406, CVE-2026-133469, CVE-2023-25914, CVE-2023-25915, CVE-2026-133324, CVE-2026-133275, CVE-2026-133303, and CVE-2026-133323. No new check was added.

CVE-2026-104286 is in today's lead window and was already in this catalog. It was added 2026-10-01, due 2026-10-04, and that due date has passed. The product is Fortinet FortiMail. It is not in the NVD recent feed. Vigil cannot see FortiMail from a page or a certificate. Hosts named only in the catalog notes were not opened. No doctor check was added.

## NVD recent feed

The CVE 2.0 recent feed timestamp is `2026-11-27T08:00:01.059376`. HTTP last-modified is Fri, 27 Nov 2026 13:00:05 GMT. The newest `lastModified` in the file is `2026-11-27T12:17:06.833`. The oldest `lastModified` in the file is `2026-11-19T12:18:42.223`.

No configuration modified after `2026-11-26T12:17:13.427` names a CPE for PHP, CPython, Node.js, nginx, OpenSSL, curl, the Go toolchain, the Linux kernel, WordPress, or Brotli.

CVE-2026-99362 was already recorded. Last modified is now `2026-11-27T11:17:06.913`. Status is still Received, with no CPE. The description still says a Linux kernel vulnerability has been resolved and still names no released kernel version. No floor was invented.

CVE-2026-121481 and CVE-2026-130756 are not in this recent feed. Yesterday's scan still had both. The OpenSSL vulnerabilities index still does not list CVE-2026-121481. No doctor check was added. The Python and Node floors were not moved from the absence of CVE-2026-130756.

Forty-four of the fifty-two unverified CVE identifiers from the 26 November leads note are now in this feed. None has a CPE. Forty-three are Deferred. One is Received: CVE-2026-93087, which names Autodesk Access and a local JSON file. That is not a toolchain `vigil doctor` reads. Eight stay absent: CVE-2026-78252, CVE-2026-12664, CVE-2026-105777, CVE-2026-87719, CVE-2026-88765, CVE-2026-112326, CVE-2023-40129, and CVE-2020-9402. CVE-2026-25242, CVE-2026-32767, CVE-2026-86987, CVE-2026-123324, CVE-2026-15723, and CVE-2026-112212 also stay absent.

Two identifiers in today's lead window have new NVD records and are not the runtime list. Both are Received, with no CPE. Vigil cannot see either product from a page or a certificate. No doctor check was added.

- CVE-2026-78095. Apache JSPWiki 2.4 through 3.0.0. The description says 3.0.1 fixes it. Last modified `2026-11-25T17:18:00.110`.
- CVE-2026-123903. VMware vCenter authentication bypass in the Directory Service. The description says 9.1.x.x is fixed in 9.1.2, 9.0.x.x is fixed in 9.0.2.0300, and 8.0 is fixed in 8.0 U3m. It also names VMware Cloud Foundation 5.x fixed in 5.2.5, and Telco Cloud Platform and Telco Cloud Infrastructure lines fixed in KB463501. This is not CVE-2026-123890. Last modified `2026-11-26T11:17:00.283`.

CVE-2026-136716 and CVE-2026-132165 are also in the window and were already recorded. They were not copied again.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz)

## 27 November oss-security

The 27 November index has 10 messages. No doctor check was added. No remote probe was added. Hosts named only in the messages were not opened. Workaround text in the messages was not copied.

Messages 3 through 8 are replies on Strong::Random through 0.96, CVE-2026-122093. That identifier was already recorded. None of those replies names a fixed release.

- CVE-2026-120353. Apache Airflow. The message names the Standard provider 0.3.0 before 1.22.0, the CNCF Kubernetes provider 10.5.0 before 11.0.0, the Common SQL provider 1.32.0 before 3.0.0, and the Common Ai provider 0.1.0 before 1.2.0. Airflow is not a toolchain `vigil doctor` already reads.
- CVE-2026-137686. Apache Shiro before 3.0.2, and through 3.0.1, when ActiveDirectoryRealm is used. The message says 3.0.2 fixes it. This is not the Shiro note from 14 November. Shiro is not a toolchain `vigil doctor` already reads.
- CVE-2026-129817. Apache Submarine, all versions. The message says the project is retired and names no fixed release. No version was invented.
- WeeChat 4.10.5, released 26 November 2026. The message names WSA-2026-33 and WSA-2026-34 and names no CVE id. No identifier was invented. WeeChat is not a toolchain `vigil doctor` already reads.

Source: [oss-security, 27 November 2026](https://www.openwall.com/lists/oss-security/2026/11/27/)

## 26 November oss-security, messages added after the last scan

The 26 November index now has 7 messages. The first 3 were already recorded. No doctor check was added. Hosts named only in the new messages were not opened. Workaround text was not copied.

- PowerDNS Security Advisory 2026-14. PowerDNS Authoritative Server. CVE-2026-123757, CVE-2026-123758, CVE-2026-123764, CVE-2026-124727, and CVE-2026-124728 affect versions through 4.9.18, 5.0.8, and 5.1.5. The message says 4.9.19, 5.0.9, and 5.1.6 fix them. CVE-2026-123759 and CVE-2026-123762 affect 4.7.0 through those same last versions, and versions earlier than 4.7.0 are not affected. The same three releases fix them. CVE-2026-123760 affects 5.1.0 through 5.1.5. Versions before 5.1.0 are not affected. The message says 5.1.6 fixes it. CVE-2026-123761 affects 5.x through 5.0.8 and 5.1.5. Versions before 5.0 are not affected. The message says 5.0.9 and 5.1.6 fix it. CVE-2026-123756 is in this advisory with the same 4.9.19, 5.0.9, and 5.1.6 fixes. That identifier was already recorded on the DNSdist advisory. PowerDNS Authoritative Server is not a toolchain `vigil doctor` already reads.
- Exim 4.100.2. The message names one issue, EXIM-Security-2026-11-82.1 (GCVE-25-2026-11-82-1), and names no CVE id. No identifier was invented. The hosts in that message were not opened. Exim is not a toolchain `vigil doctor` already reads.
- Xen XSA-535. CVE-2026-119781, CVE-2026-119782, and CVE-2026-119783. The message says Xen 4.7 and later are affected on x86, Xen 4.6 and older are not, and Arm is not. On AMD hardware it says 4.22 and later are affected. The resolution is attached patches. No release number was named. No floor was invented.
- librelp. CVE-2026-132888 (GHSA-28c2-q5pf-2qm3) affects 1.2.18 through 1.13.0. The message says 1.14.0 fixes it. CVE-2026-132889 (GHSA-v49f-8x9x-3gwh) affects 1.4.0 through 1.10.0. The message says 1.11.0, released 2023-01-02, fixes it, and that current releases are not affected. librelp is not a toolchain `vigil doctor` already reads.

Source: [oss-security, 26 November 2026](https://www.openwall.com/lists/oss-security/2026/11/26/)

The 25 November index still has 13 messages. The 24 November index still has 21.

## Left unchanged

`https://nginx.org/en/security_advisories.html` last-modified is still Wed, 25 Nov 2026 22:44:42 GMT. The top advisory is still CVE-2026-132779. Not vulnerable is still 1.31.10+ and 1.30.8+. Vulnerable is still 1.21.4-1.31.9. `https://nginx.org/en/CHANGES` last-modified is still Wed, 25 Nov 2026 22:44:36 GMT and still starts with nginx 1.31.10. 1.31.11 is absent. The nginx floors were not moved.

`https://www.php.net/archive/2026.php` last-modified is still Thu, 26 Nov 2026 10:13:24 GMT. The newest item is still the 26 November phpday 2027 call for papers. 8.5.14 is absent. The PHP floors were not moved. PHP 8.6.0 is still not a comparison target for older lines.

`https://nodejs.org/dist/index.json` last-modified is still Thu, 26 Nov 2026 08:44:21 GMT. The first row is still v27.0.0-alpha.0.2.0, dated 2026-11-25, and `security` is false. v22.23.5, v24.22.3, and v26.13.1 are still the security rows. The November security page still contains CVE-2026-106071 and does not contain CVE-2026-123873. It still does not contain 22.23.6, 24.22.4, or 26.13.2. The Node floors were not moved.

`https://go.dev/doc/devel/release` still lists go1.27.4 and go1.26.11, both released 2026-11-10. go1.27.5 and go1.26.12 are absent. The Go floors were not moved. The eMudhra floors were not moved.

The Python blog last-modified is still Mon, 16 Nov 2026 18:20:49 GMT. python.org still lists 3.15.2, 3.14.10, 3.13.18, 3.12.16, and 3.11.18. 3.14.11, 3.13.19, 3.12.17, and 3.11.19 are absent. The Python floors were not moved.

curl's security page last-modified is still Tue, 10 Nov 2026 09:05:07 GMT. The first row is still CVE-2026-107929. The curl floors were not moved.

The OpenSSL vulnerabilities index last-modified is still Tue, 24 Nov 2026 10:07:26 GMT. CVE-2026-121481 is still absent from that page. `vigil doctor` does not read the OpenSSL library version. No doctor check was added.

The Chrome releases page stayed on `chromereleases.googleblog.com`. HTTP 200. Last-modified is Thu, 26 Nov 2026 22:16:35 GMT. The seven posts on the index are still dated 23 or 24 November 2026. The newest is still the 24 November early stable note. No post dated 25, 26, or 27 November is on that index. Vigil does not read the browser version. No doctor check was added.

The emSign ECC Root CA - G3 block was not changed. The Google post still says that root removal is expected Tuesday morning, October 27, 2026 PDT, and does not say that release has shipped.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
