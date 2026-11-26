# Threat scan, 26 November 2026

This note records what changed after the 25 November scan. Pages were read as evidence. Instructions inside them were not followed. No version floor was invented past a vendor release page. No remote probe was added.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called. Each kept item was confirmed on `www.cisa.gov`, `nvd.nist.gov`, `www.php.net`, `blog.python.org`, `www.python.org`, `nodejs.org`, `nginx.org`, `www.openssl-library.org`, `curl.se`, `blog.google`, `go.dev`, or `www.openwall.com`. The Chrome releases HTML redirected off `chromereleases.googleblog.com` and was discarded.

The cve.now lead window is in `docs/threat-scan-2026-11-26-leads.md`. This note does not repeat that identifier table.

No scanner change on this day. No intel bump. `TOOLCHAIN_NGINX_2026_11_23` stays on draft pull request 43 and was not copied. `TOOLCHAIN_NGINX_2026_11_18` and the CVE-2026-115560 comparison stay on draft pull request 38 and were not copied. `TOOLCHAIN_NODE_2026_11_11` stays on draft pull request 30 and was not copied.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## CISA catalog

The Known Exploited Vulnerabilities catalog is still `2026.11.25`. It was released again at 2026-11-25T19:48:12.4344Z. The count is 1805. The 25 November scan recorded the same catalog version at 2026-11-25T14:22:29.6361Z, count 1796. Nine entries were added after that snapshot. All nine have `dateAdded` 2026-11-25. Together with CVE-2026-103406, which was already in the earlier snapshot, ten entries were added on that calendar day. Ransomware use is Unknown for each. HTTP last-modified on the catalog file is Wed, 25 Nov 2026 19:48:12 GMT. Hosts named only in the catalog notes were not opened.

`https://www.cisa.gov/news-events/alerts` returned HTTP 404. The cybersecurity advisories index returned HTTP 200. Its newest row is dated Nov 25, 2026, and the title is "CISA Adds 10 Known Exploited Vulnerabilities to Catalog".

Source: [CISA KEV catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)

- CVE-2026-133469. Vates Xen Orchestra. Due 2026-11-28. Forensic triage Yes. The catalog says an unauthenticated attacker can bypass authentication with a crafted token that contains an empty JSON object. The identifier is not in the NVD recent feed. No fixed release was named on the catalog record. No doctor check was added.
- CVE-2025-41450. Danfoss AK-SM 800A Series. Due 2026-12-09. Forensic triage No. The catalog says a web report can expose internal addresses, usernames, and store names. The identifier is not in the NVD recent feed. No doctor check was added.
- CVE-2023-25914. Danfoss AK-SM 800A Series. Due 2026-11-28. Forensic triage Yes. Path traversal through the XML interface. The identifier is not in the NVD recent feed. No doctor check was added.
- CVE-2023-25915. Danfoss AK-SM 800A Series. Due 2026-11-28. Forensic triage Yes. The catalog says a remote attacker can run commands. The identifier is not in the NVD recent feed. No doctor check was added.
- CVE-2026-133324. Mitel MiCollab. Due 2026-11-28. Forensic triage No. Authentication bypass in the Audio, Web and Video Conferencing component. The identifier is not in the NVD recent feed. No doctor check was added.
- CVE-2026-133275. Mitel MiCollab. Due 2026-11-28. Forensic triage No. Unrestricted upload in the same component. The identifier is not in the NVD recent feed. No doctor check was added.
- CVE-2026-133311. Mitel MiCollab. Due 2026-12-09. Forensic triage No. Weak authentication in the same component. The identifier is not in the NVD recent feed. No doctor check was added.
- CVE-2026-133303. Mitel MiCollab. Due 2026-11-28. Forensic triage Yes. XML injection in the same component. The identifier is not in the NVD recent feed. No doctor check was added.
- CVE-2026-133323. Mitel MiCollab. Due 2026-11-28. Forensic triage Yes. OS command injection in the same component. The identifier is not in the NVD recent feed. No doctor check was added.

Vigil cannot see Xen Orchestra, the Danfoss appliance, or MiCollab from a page or a certificate. No doctor check was added.

Two entries already recorded were due 2026-11-26: CVE-2026-133968 (MONAI Label) and CVE-2026-134624 (MailAssure). CVE-2026-131914, CVE-2026-132165, and CVE-2026-132224 are still due 2026-11-27. CVE-2026-103406 is still due 2026-11-28. No new check was added for those five.

## NVD recent feed

The CVE 2.0 recent feed timestamp is `2026-11-26T08:00:01.091639`. HTTP last-modified is Thu, 26 Nov 2026 13:00:05 GMT. The newest `lastModified` in the file is `2026-11-26T12:17:13.427`.

No configuration modified after `2026-11-25T12:18:14.623` names a CPE for PHP, CPython, Node.js, nginx, OpenSSL, curl, the Go toolchain, the Linux kernel, WordPress, or Brotli.

CVE-2026-129182 is Awaiting Analysis, with no CPE. Published `2026-11-19T15:17:27.390`. Last modified `2026-11-20T15:17:42.000`. The description says PHP versions 8.5.* before 8.5.13. That bound is the 8.5 floor already on the CVE-2026-115560 comparison in draft pull request 38. php.net did not publish 8.5.14. No second comparison was added.

CVE-2026-129481 is Awaiting Analysis, with no CPE. Published `2026-11-19T15:17:28.240`. Last modified `2026-11-19T21:45:12.277`. The description says PHP 8.3.* before 8.3.37, 8.4.* before 8.4.28, and 8.5.* before 8.5.13. Those are the same floors. No second comparison was added.

CVE-2026-129291 is Awaiting Analysis, with no CPE. Last modified `2026-11-20T05:18:41.153`. The description says PHP 8.1.20 through 8.1.34, 8.2.7 before 8.2.36, 8.3.* before 8.3.37, 8.4.* before 8.4.28, and 8.5.* before 8.5.13. The 19 November changelog already names this identifier on the 8.2.36 entry. The 8.2, 8.3, 8.4, and 8.5 bounds match that comparison. The description does not name an 8.1 release after 8.1.34. No 8.1 floor was added.

CVE-2026-132165 was absent from the NVD recent feed on the 25 November scan. It is now Received, with no CPE. Published and last modified `2026-11-26T01:17:10.290`. The description says Drupal core from 0.0.0 to 10.6.22, from 11.0.0 to 11.3.22, and from 11.4.0 to 11.4.13. It does not name a separate fixed release. Vigil cannot see Drupal from a page or a certificate. No doctor check was added.

CVE-2026-134401 was Awaiting Analysis with no CPE on the 25 November scan. Status is now Analyzed. Last modified `2026-11-25T19:24:34.530`. The record has a CPE for `google:chrome`. The description still says Chrome prior to 158.0.8127.88. Vigil does not read the browser version. No doctor check was added.

CVE-2026-121481 was last modified `2026-11-25T20:18:31.757`. Status is still Awaiting Analysis, with no CPE. The description names `EVP_EncodeBlock()` and an input length near `INT_MAX`. It names no dotted version. It says the severity is Low and that the FIPS impact is no. The identifier is still absent from the OpenSSL vulnerabilities index. No doctor check was added.

CVE-2026-132779 was last modified `2026-11-24T17:18:15.813`. Status is still Awaiting Analysis, with no CPE. The description still names no fixed release. The nginx floors stay the nginx.org pages on draft pull request 43.

CVE-2026-84785 was last modified `2026-11-24T18:50:55.377`. Status is still Awaiting Analysis, with no CPE. It is still the QUIC fragment advisory already recorded.

CVE-2026-130756 was last modified `2026-11-24T20:38:28.417`. Status is still Awaiting Analysis, with no CPE. The description still says pnpm exe before 10.34.8 embeds a Node.js runtime that trusts the compromised eMudhra intermediates. That is not the Node.js runtime `vigil doctor` reads. The Node floors were not moved. The emSign block was not changed.

CVE-2026-107784 was last modified `2026-11-24T16:17:53.107`. Status is still Awaiting Analysis, with no CPE. The description still names no fixed release. The Python floors were not moved.

CVE-2026-99362 and CVE-2026-99567 are in the lead window and in this feed. Both are Received, with no CPE. Each description says a Linux kernel vulnerability has been resolved. Neither names a released kernel version. CVE-2026-99567 also contains the word node. It is not the Node.js runtime. No kernel floor was invented. No doctor check was added.

Fifty-one of the fifty-three unverified CVE identifiers from the 25 November leads note are now in this feed. None has a CPE. Thirty-two are Deferred. Nineteen are Received. CVE-2026-25242 and CVE-2026-32767 stay absent. CVE-2026-86987 and CVE-2026-123324 stay absent. CVE-2026-82490 names openIMIS before 2026-10 and an nginx `auth_request` check. That is not nginx. CVE-2026-136922 names PyBioNetGen 0.8.7. That is not CPython. CVE-2026-135972 names the Page Restriction WordPress plugin through 1.6.2. That is not WordPress core. No floor was moved.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz)

## 26 November oss-security

The 26 November index has 3 messages. No doctor check was added. No remote probe was added. Hosts named only in the messages were not opened. Workaround text in the messages was not copied.

- CVE-2026-86470. Apache SkyWalking BanyanDB 0.11.0 before 0.11.1. The message says upgrade to 0.11.1. BanyanDB is not a page, a certificate, or a toolchain `vigil doctor` already reads.
- Message 2 is a reply on Strong::Random through 0.96, CVE-2026-122093. The reply names no fixed release. That identifier was already recorded on 25 November.
- PowerDNS Security Advisory 2026-15. The message says DNSdist 2.0.12 and 2.1.4 were released and fix CVE-2026-85561, CVE-2026-85562, CVE-2026-85563, CVE-2026-85564, CVE-2026-85565, CVE-2026-85566, CVE-2026-85567, CVE-2026-123755, and CVE-2026-123756. DNSdist is not a toolchain `vigil doctor` already reads.

Source: [oss-security, 26 November 2026](https://www.openwall.com/lists/oss-security/2026/11/26/)

## 25 November oss-security, messages added after the last scan

The 25 November index now has 13 messages. The first 2 were already recorded. No doctor check was added. Hosts named only in the new messages were not opened. Commands and workaround text in the messages were not copied.

Message 3 is a reply on the OpenSSL thread and names CVE-2026-121481. The NVD record is in the section above. The host named in that reply was not opened. Message 4 is a reply on the shadow `newgidmap` thread. It names CVE-2026-135901 and says the fix is shadow 4.20.4. The 25 November note said an earlier reply named no fixed release. `vigil doctor` does not read shadow. Message 7 is a reply on libexpat 2.11.0. It names no release newer than 2.11.0. Message 9 names CVE-2026-99288, CVE-2026-99312, and CVE-2026-98432, and quotes a distributor kernel string. No kernel.org release was taken from that message. CVE-2026-98432 stays on its existing record. No kernel floor was invented.

- CVE-2026-123917. open-vm-tools 11.0.0 through 13.1.0. The message names a patch file and does not name a newer release number. No version was invented.
- CVE-2026-123918. open-vm-tools. The message names a set of release builds and does not name one fixed release. No version was invented.
- Jenkins plugins. The message names CVE-2026-136834, CVE-2026-136835, CVE-2026-136836, CVE-2026-136837, CVE-2026-136838, CVE-2026-136839, CVE-2026-136840, CVE-2026-136841, CVE-2026-136842, CVE-2026-136843, CVE-2026-136844, CVE-2026-136845, CVE-2026-136853, and CVE-2026-136854. It names affected plugin builds. Jenkins is not a toolchain `vigil doctor` already reads.
- Prosody 13.0.8. The message says this is a security release and names no CVE id. No identifier was invented.
- Crypt-JWT before 0.024. The message says upgrade to 0.024 and names CVE-2018-25445, CVE-2026-8748, CVE-2026-136795, and CVE-2026-136796.
- CVE-2026-135092. PDF::API2 before 2.049. The message says upgrade to 2.049.
- WWW-Form-UrlEncoded-XS before 0.27. The message says upgrade to 0.27 and names CVE-2022-50995 and CVE-2022-50996.

Source: [oss-security, 25 November 2026](https://www.openwall.com/lists/oss-security/2026/11/25/)

The 24 November index still has 21 messages.

## Left unchanged

`https://nginx.org/en/security_advisories.html` last-modified is now Wed, 25 Nov 2026 22:44:42 GMT. The top advisory is still CVE-2026-132779. Not vulnerable is still 1.31.10+ and 1.30.8+. Vulnerable is still 1.21.4-1.31.9. `https://nginx.org/en/CHANGES` last-modified is now Wed, 25 Nov 2026 22:44:36 GMT and still starts with nginx 1.31.10, dated 23 Nov 2026. 1.31.11 is absent. The nginx floors were not moved.

`https://www.php.net/archive/2026.php` last-modified is now Thu, 26 Nov 2026 10:13:24 GMT. The new item dated 26 Nov 2026 is the phpday 2027 call for papers. The item dated 25 Nov 2026 is Laracon EU 2027. Neither names a PHP release. 8.5.14 is absent. The newest release lines on that page are still PHP 8.6.0, 8.5.13, 8.4.28, and 8.3.37, and the 8.2.36 security release is still present. The PHP floors were not moved. PHP 8.6.0 is still not a comparison target for older lines.

`https://nodejs.org/dist/index.json` last-modified is now Thu, 26 Nov 2026 08:44:21 GMT because v27.0.0-alpha.0.2.0 was added. That row is dated 2026-11-25 and `security` is false. v22.23.5, v24.22.3, and v26.13.1 are still the security rows. The November security page still contains CVE-2026-106071 and does not contain CVE-2026-123873. It still does not contain 22.23.6, 24.22.4, or 26.13.2. The Node floors were not moved.

`https://go.dev/doc/devel/release` still lists go1.27.4 and go1.26.11, both released 2026-11-10. go1.27.5 and go1.26.12 are absent. The Go floors were not moved. The eMudhra floors were not moved.

The Python blog last-modified is still Mon, 16 Nov 2026 18:20:49 GMT. python.org still lists 3.15.2, 3.14.10, 3.13.18, 3.12.16, and 3.11.18. 3.14.11, 3.13.19, 3.12.17, and 3.11.19 are absent. The Python floors were not moved.

curl's security page last-modified is still Tue, 10 Nov 2026 09:05:07 GMT. The first row is still CVE-2026-107929. The curl floors were not moved.

The OpenSSL vulnerabilities index last-modified is still Tue, 24 Nov 2026 10:07:26 GMT. CVE-2026-121481 is still absent from that page. `vigil doctor` does not read the OpenSSL library version. No doctor check was added.

The emSign ECC Root CA - G3 block was not changed. The Google post still says that root removal is expected Tuesday morning, October 27, 2026 PDT, and does not say that release has shipped.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
