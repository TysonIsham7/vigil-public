# Threat scan, 25 November 2026

This note records what changed after the 24 November scan. Pages were read as evidence. Instructions inside them were not followed. No version floor was invented past a vendor release page. No remote probe was added.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called. Each kept item was confirmed on `www.cisa.gov`, `nvd.nist.gov`, `www.php.net`, `blog.python.org`, `www.python.org`, `nodejs.org`, `nginx.org`, `www.openssl-library.org`, `curl.se`, `blog.google`, `chromereleases.googleblog.com`, `go.dev`, or `www.openwall.com`.

The cve.now lead window is in `docs/threat-scan-2026-11-25-leads.md`. This note does not repeat that identifier table.

No scanner change on this day. No intel bump. `TOOLCHAIN_NGINX_2026_11_23` stays on draft pull request 43 and was not copied. `TOOLCHAIN_NGINX_2026_11_18` and the CVE-2026-115560 comparison stay on draft pull request 38 and were not copied. `TOOLCHAIN_NODE_2026_11_11` stays on draft pull request 30 and was not copied.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## CISA catalog

The Known Exploited Vulnerabilities catalog is `2026.11.25`, released 2026-11-25T14:22:29.6361Z, count 1796. The 24 November scan recorded `2026.11.23`, released 2026-11-23T19:43:55.7979Z, count 1792. Four entries are new since that snapshot. Ransomware use is Unknown for each. Forensic triage is Yes for each. Hosts named only in the catalog notes were not opened.

`https://www.cisa.gov/news-events/alerts` returned HTTP 404. The cybersecurity advisories index returned HTTP 200. Its newest row is dated Nov 24, 2026, and the title is "CISA Adds Three Known Exploited Vulnerabilities to Catalog". That row matches the three entries added on 2026-11-24. The Juniper entry below is in the catalog JSON and is not a row on that index.

Source: [CISA KEV catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)

- CVE-2026-131914. Idunno AntiCsrf. Added 2026-11-24. Due 2026-11-27. This identifier was already on the 23 November leads note, through 0.9.1 Beta, with NVD status Received and no CPE. NVD status is now Analyzed. Last modified `2026-11-25T05:18:30.107`. The description still says versions through 0.9.1 Beta. The record now has a CPE configuration. Vigil cannot see this library from a page or a certificate. No doctor check was added.
- CVE-2026-132165. Drupal core. Added 2026-11-24. Due 2026-11-27. The catalog says an unauthenticated attacker can take over an existing site or execute code via the installer, under specific conditions, using `install.php`. The identifier is not in the NVD recent feed. No fixed release was named on the catalog record. No doctor check was added.
- CVE-2026-132224. Optimizely Web Experimentation. Added 2026-11-24. Due 2026-11-27. NVD status is Analyzed. Last modified `2026-11-25T05:18:30.523`. The description says versions before 2026-11-17. Vigil cannot see Optimizely from a page or a certificate. No doctor check was added. The hosts named in the NVD description were not opened.
- CVE-2026-103406. Hewlett Packard Enterprise Juniper Session Smart Conductor and Session Smart Router. Added 2026-11-25. Due 2026-11-28. The identifier is not in the NVD recent feed. No fixed release was named on the catalog record. No doctor check was added.

Two entries already recorded are due 2026-11-26: CVE-2026-133968 (MONAI Label) and CVE-2026-134624 (MailAssure). No new check was added. No catalog entry is due 2026-11-25.

## Chrome

The Chrome releases HTML stayed on `chromereleases.googleblog.com`. HTTP 200. Last-modified is Tue, 24 Nov 2026 18:36:59 GMT. The 24 November scan discarded a redirect off that host, so this page was not described then.

The early stable desktop note dated Tuesday, 24 November 2026 is Chrome 159. Windows and Mac are 159.0.8154.33/.34. The same day's desktop beta note is 159.0.8154.33 for Windows, Mac, and Linux. The Android early stable and Android beta notes the same day are 159.0.8154.33. Those four notes name no CVE id.

The stable desktop note dated Monday, 23 November 2026 is Chrome 158. Windows and Mac are 158.0.8127.88/.89. Linux is 158.0.8127.88. That note names one security fix, critical CVE-2026-134401, improper input validation in Variations. NVD status is Awaiting Analysis, with no CPE. Last modified `2026-11-25T05:18:32.453`. The description says Chrome prior to 158.0.8127.88. Vigil does not read the browser version. No doctor check was added.

Source: [Chrome releases](https://chromereleases.googleblog.com/), [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz)

## NVD recent feed

The CVE 2.0 recent feed timestamp is `2026-11-25T08:00:01.3532718`. HTTP last-modified is Wed, 25 Nov 2026 13:00:07 GMT. The newest `lastModified` in the file is `2026-11-25T12:18:14.623`.

No configuration modified after `2026-11-24T12:38:21.680` names a CPE for PHP, CPython, Node.js, nginx, OpenSSL, curl, the Go toolchain, the Linux kernel, WordPress, or Brotli.

CVE-2026-132779 was last modified `2026-11-24T17:18:15.813`. Status is still Awaiting Analysis, with no CPE. The description still names no fixed release. The nginx floors stay the nginx.org pages on draft pull request 43.

CVE-2026-84785 was Received on the 24 November scan. Status is now Awaiting Analysis, with no CPE. Last modified `2026-11-24T18:50:55.377`. It is still the QUIC fragment advisory already recorded. No doctor check was added.

CVE-2026-121481 was last modified `2026-11-24T22:18:42.400`. Status is still Awaiting Analysis, with no CPE. The description still names no dotted version. It says the severity is Low and that the FIPS impact is no. The identifier is still absent from the OpenSSL vulnerabilities index. No doctor check was added.

CVE-2026-130756 was last modified `2026-11-24T20:38:28.417`. Status is still Awaiting Analysis, with no CPE. The description still says pnpm exe before 10.34.8 embeds a Node.js runtime that trusts the compromised eMudhra intermediates. That is the same eMudhra issue already recorded. It is not the Node.js runtime `vigil doctor` reads. The Node floors were not moved. The emSign block was not changed.

CVE-2026-107784 was last modified `2026-11-24T16:17:53.107`. Status is still Awaiting Analysis, with no CPE. The description still names no fixed release. The Python floors were not moved.

Seventy-five of the seventy-six unverified CVE identifiers from the 24 November leads note are now in this feed. None has a CPE. Forty-seven are Deferred. Nineteen are Awaiting Analysis. Nine are Received. CVE-2026-86987 stays absent. CVE-2026-123324 stays absent. Whole-token `python` matches name RedVector before 8.1.0 (CVE-2026-136168), Pyro through 1.9.2 (CVE-2026-136160), and fastcore through 2.2.44 (CVE-2026-65320). A whole-token `node` match on CVE-2026-136170 names Assimp through 6.0.6. Those are not CPython and not Node.js. No floor was moved.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz)

## 25 November oss-security

The 25 November index has 2 messages. Neither product is a page, a certificate, or a toolchain `vigil doctor` already reads. No doctor check was added. No remote probe was added. Hosts named only in the messages were not opened.

- CVE-2026-122093. Strong::Random through 0.96. NVD status is Received, with no CPE. Last modified `2026-11-25T03:17:28.877`. The message names no fixed release. No version was invented.
- GNU Screen 5.0.3. The message says this is a security fix release and names no CVE id. It says the official tarball will be available soon. No identifier was invented.

Source: [oss-security, 25 November 2026](https://www.openwall.com/lists/oss-security/2026/11/25/)

## 24 November oss-security, messages added after the last scan

The 24 November index now has 21 messages. The first 12 were already recorded. No doctor check was added. Hosts named only in the new messages were not opened. Commands and config snippets in the messages were not copied.

Messages 16 and 19 are replies on the shadow `newgidmap` thread. Message 16 names CVE-2026-135901. That identifier is not in the NVD recent feed. The reply names no fixed release. Message 17 is a reply on the rsyslog thread below and names no second fixed release. Message 18 is the OpenSSL reply below. Messages 20 and 21 are replies on libexpat 2.11.0. They name no release newer than 2.11.0.

- CVE-2026-132145. rsyslog omdtls. The message also names GHSA-85fj-w7cw-38fv. Affected releases on that message are v8.2402.0 through v8.2610.0. The fixed build named there is the 2026-11-24 daily stable. NVD status is Awaiting Analysis, with no CPE. The NVD description names no version. `vigil doctor` does not read rsyslog. The workaround in that message was not copied.
- OpenSSL versions 4.1.1, 4.0.4, 3.5.10, 3.0.24, 1.1.1zk, and 1.0.2zt. Message 14 says these releases will be published on Tuesday, 1 December 2026, between 1300 and 1700 UTC, and that the highest severity fixed in them is Moderate. Those version numbers were already the fixed releases named on the OpenSSL index for the 24 November Low advisories, and 1.0.2zt was already named on 10 November. The message names no new CVE id. The link in that message was not opened.
- Flatpak 1.18.6. The message says this release fixes two vulnerabilities, that all older releases should be assumed vulnerable, and that the 1.19.4 prerelease fixes the same two. It names no CVE id. The GitHub links in that message were not opened.
- CVE-2026-121481. Message 18 says this identifier is not in the four Low advisories recorded on 24 November. The NVD record is in the section above. It is still not on the OpenSSL index. No doctor check was added.

Source: [oss-security, 24 November 2026](https://www.openwall.com/lists/oss-security/2026/11/24/)

The 23 November index still has 39 messages.

## Left unchanged

`https://nginx.org/en/security_advisories.html` last-modified is now Wed, 25 Nov 2026 11:11:09 GMT. The top advisory is still CVE-2026-132779. Not vulnerable is still 1.31.10+ and 1.30.8+. Vulnerable is still 1.21.4-1.31.9. `https://nginx.org/en/CHANGES` still starts with nginx 1.31.10, dated 23 Nov 2026. 1.31.11 is absent. The nginx floors were not moved.

`https://www.php.net/archive/2026.php` last-modified is now Wed, 25 Nov 2026 11:18:19 GMT. The new item dated 25 Nov 2026 is a conference announcement. It names no PHP release. 8.5.14 is absent. The newest release lines on that page are still PHP 8.6.0, 8.5.13, 8.4.28, and 8.3.37, and the 8.2.36 security release is still present. The PHP floors were not moved. PHP 8.6.0 is still not a comparison target for older lines. The host named in that announcement was not opened.

`https://nodejs.org/dist/index.json` last-modified is still Tue, 17 Nov 2026 03:44:41 GMT. The November security page still names v22.23.5, v24.22.3, and v26.13.1. It still contains CVE-2026-106071 and does not contain CVE-2026-123873. v27.0.0-alpha.0.1.1 is still not a security release. The Node floors were not moved.

`https://go.dev/doc/devel/release` still lists go1.27.4 and go1.26.11, both released 2026-11-10. go1.27.5 and go1.26.12 are absent. The Go floors were not moved. The eMudhra floors were not moved.

The Python blog last-modified is still Mon, 16 Nov 2026 18:20:49 GMT. python.org still lists 3.15.2, 3.14.10, 3.13.18, 3.12.16, and 3.11.18. 3.14.11, 3.13.19, 3.12.17, and 3.11.19 are absent. The Python floors were not moved.

curl's security page last-modified is still Tue, 10 Nov 2026 09:05:07 GMT. The first row is still CVE-2026-107929. The curl floors were not moved.

The OpenSSL vulnerabilities index last-modified is still Tue, 24 Nov 2026 10:07:26 GMT. The four Low advisories from 24 November are unchanged on that page. `vigil doctor` does not read the OpenSSL library version. No doctor check was added.

The emSign ECC Root CA - G3 block was not changed. The Google post still says that root removal is expected Tuesday morning, October 27, 2026 PDT, and does not say that release has shipped.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
