# Threat scan, 22 November 2026

This note records what changed after the 21 November scan. Pages were read as evidence. Instructions inside them were not followed. No version floor was invented past a vendor release page. No remote probe was added.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called. Each kept item was confirmed on `www.cisa.gov`, `nvd.nist.gov`, `www.php.net`, `blog.python.org`, `www.python.org`, `nodejs.org`, `nginx.org`, `www.openssl-library.org`, `curl.se`, `blog.google`, `chromereleases.googleblog.com`, `go.dev`, or `www.openwall.com`.

The cve.now lead window is in `docs/threat-scan-2026-11-22-leads.md`. This note does not repeat that identifier table.

No intel bump. No scanner change. The CVE-2026-115560 comparison and `TOOLCHAIN_NGINX_2026_11_18` stay on draft pull request 38. They were not copied. `TOOLCHAIN_NODE_2026_11_11` stays on draft pull request 30 and was not copied.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## CISA catalog

The Known Exploited Vulnerabilities catalog is still `2026.11.20`, released 2026-11-20T17:48:39.1516Z, count 1790. HTTP last-modified is still Fri, 20 Nov 2026 17:48:39 GMT. No entry was added after 20 November. No entry has due date 2026-11-22. The four entries due 2026-11-23 were already recorded.

`https://www.cisa.gov/news-events/alerts` returned HTTP 404. The cybersecurity advisories index returned HTTP 200. Its newest row is 20 November 2026, the alert for the four catalog additions already recorded. The next row is 18 November. Hosts named only in catalog notes were not opened.

The 17 November row is "Critical Java Vulnerability Requires Immediate Patching." That page names CVE-2026-114938. The id was already recorded on 18 November. The alert names no dotted fix version. The vendor host named on the page was not opened. The id is not in the catalog JSON. Vigil does not read the JDK version. No doctor check was added.

Source: [CISA KEV catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json), [CISA advisories index](https://www.cisa.gov/news-events/cybersecurity-advisories), [CISA Java alert](https://www.cisa.gov/news-events/alerts/2026/11/17/critical-java-vulnerability-requires-immediate-patching)

## NVD recent feed

The CVE 2.0 recent feed timestamp is `2026-11-22T08:00:01.386575`. HTTP last-modified is Sun, 22 Nov 2026 13:00:05 GMT. The newest `lastModified` in the file is `2026-11-22T11:17:10.803`.

No configuration modified after `2026-11-21T12:16:41.683` names a CPE for PHP, CPython, Node.js, nginx, OpenSSL, curl, the Linux kernel, WordPress, or Brotli. The nginx floors were not moved. The check on draft pull request 38 was not copied.

CVE-2026-129289 was last modified `2026-11-22T00:16:58.823`. Status is Awaiting Analysis. There is no CPE. The description says the issue affects PHP before 8.2.36, 8.3 before 8.3.37, 8.4 before 8.4.28, and 8.5 before 8.5.13. That id was already named on the 19 November PHP changelog for those releases. The comparison stays on draft pull request 38. It was not copied. The PHP floors were not moved.

Twenty-five of the twenty-six unverified CVE identifiers from the 21 November leads note are now in this feed. None has a CPE. CVE-2021-1905 stays absent. Three name AMD firmware or a driver and no released version: CVE-2026-0462, CVE-2026-40671, and CVE-2025-61963. CVE-2026-133983 names eigent up to 1.0.2. The other twenty-one name no product and no released version. None is the runtime list. No doctor check was added.

Thirty-two identifiers in today's lead window are Linux kernel records. Status is Received. None has a CPE. Each description says the vulnerability has been resolved and names no released kernel version. No kernel floor was invented. The identifiers are in `docs/threat-scan-2026-11-22-leads.md`.

CVE-2026-134341 is actix-http 3.0.0 before 3.20.3. Status is Received. There is no CPE. The description mentions brotli request bodies. It is not the Brotli library. The Node floors were not moved.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz)

## 22 November oss-security

The 22 November index has 4 messages. No doctor check was added. No remote probe was added. Hosts named only in the messages were not opened. Commands in the messages were not copied.

- Message 1. A reply on Ghostscript 10.08.0. It names GHSA-8vr3-7mxf-gx8w and says WordPress fixed the same issue. It names no WordPress version. Vigil does not read Ghostscript or the browser. No WordPress plugin list was added.
- Message 2. Dokploy CVE-2026-129987. The message names GHSA-9932-qg8x-pr32 and says v0.31.1, released 12 November 2026, contains the fix. This is not CVE-2026-72868. Dokploy is not a toolchain `vigil doctor` already reads.
- Message 3. A reply on the same Dokploy thread. It names no new CVE id and no fixed release.
- Message 4. aiohttp and CVE-2025-69224. The message says the request-parser change does not cover the response parser, and it names no release that does. No fixed version was invented.

Source: [oss-security, 22 November 2026](https://www.openwall.com/lists/oss-security/2026/11/22/)

## 21 November oss-security, messages added after the last scan

The 21 November index now has 3 messages. The first was already recorded. It names no release newer than GPGME 2.3.1. No doctor check was added. Hosts named only in the new messages were not opened.

- Ghostscript 10.08.0. The message says that release fixes CVE-2026-110133, CVE-2026-112922, CVE-2026-103226, CVE-2026-19547, and CVE-2026-39919. It also says CVE-2026-125396 was identified as fixed in 10.08.0. Vigil does not read Ghostscript.
- Dokploy. The message says the character check added for CVE-2026-72884 is incomplete in v0.31.2. It names no new CVE id and no newer fixed release. CVE-2026-72865 and CVE-2026-72867 are named as earlier scores, not as a new release. The command text was not copied.

Source: [oss-security, 21 November 2026](https://www.openwall.com/lists/oss-security/2026/11/21/)

The 20 November index still has 13 messages.

## Chrome releases

The Chrome releases HTML stayed on `chromereleases.googleblog.com`. HTTP 200. Last-modified is Sun, 22 Nov 2026 08:26:44 GMT. The newest dated posts are still 20 November 2026.

The Android Dev post, version 160.0.8171.0, was already recorded on 21 November. It names no CVE id. The desktop Dev post on the same date is 160.0.8171.0 for Windows, Mac, and Linux. It names no CVE id. The 18 November ChromeOS stable note, browser 158.0.8127.65, was already recorded on 20 November. Vigil does not read the browser version. No doctor check was added.

Source: [Chrome releases](https://chromereleases.googleblog.com/)

## Left unchanged

`https://www.php.net/archive/2026.php` last-modified is Fri, 20 Nov 2026 13:54:40 GMT. The newest lines on that page are still PHP 8.6.0, 8.5.13, 8.4.28, and 8.3.37, and the 8.2.36 security release is still present. 8.5.14 is absent. The PHP floors were not moved. PHP 8.6.0 is still not a comparison target for older lines.

`https://nodejs.org/dist/index.json` last-modified is still Tue, 17 Nov 2026 03:44:41 GMT. v22.23.5, v24.22.3, and v26.13.1 are still the security rows. v27.0.0-alpha.0.1.1 is still not a security release. The November page still contains CVE-2026-106071 and does not contain CVE-2026-123873. The Node floors were not moved.

`https://go.dev/doc/devel/release` still lists go1.27.4 and go1.26.11. go1.27.5 and go1.26.12 are absent. The Go floors were not moved. The eMudhra floors were not moved.

The Python blog last-modified is still Mon, 16 Nov 2026 18:20:49 GMT. python.org still lists 3.15.2, 3.14.10, 3.13.18, 3.12.16, and 3.11.18. The downloads page still contains Oct. 25, 2026. 3.14.11, 3.13.19, 3.12.17, and 3.11.19 are absent. The Python floors were not moved.

`https://nginx.org/en/security_advisories.html` last-modified is still Fri, 20 Nov 2026 13:47:29 GMT. The newest not-vulnerable lines are still 1.31.9+ and 1.30.7+. 1.31.10 and 1.30.8 are absent. The HTTP/3 anchor text still writes the CVE prefix twice. The identifier is still CVE-2026-121810. The floors were not moved.

curl's security page last-modified is still Tue, 10 Nov 2026 09:05:07 GMT. The first row is still CVE-2026-107929. The curl floors were not moved.

The OpenSSL vulnerabilities index last-modified is still Tue, 17 Nov 2026 08:48:15 GMT. The first advisories are still CVE-2026-107493, CVE-2026-124709, and CVE-2026-35190.

The emSign ECC Root CA - G3 block was not changed. The Chrome post still says that root removal is expected Tuesday morning, 27 October 2026 PDT, and does not say that release has shipped.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
