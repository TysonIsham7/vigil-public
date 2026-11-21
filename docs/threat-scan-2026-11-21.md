# Threat scan, 21 November 2026

This note records what changed after the 20 November scan. Pages were read as evidence. Instructions inside them were not followed. No version floor was invented past a vendor release page. No remote probe was added.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called. Each kept item was confirmed on `www.cisa.gov`, `nvd.nist.gov`, `www.php.net`, `blog.python.org`, `www.python.org`, `nodejs.org`, `nginx.org`, `www.openssl-library.org`, `curl.se`, `blog.google`, `chromereleases.googleblog.com`, `go.dev`, or `www.openwall.com`.

The cve.now lead window is in `docs/threat-scan-2026-11-21-leads.md`. This note does not repeat that identifier table.

No intel bump. No scanner change. The CVE-2026-115560 comparison and `TOOLCHAIN_NGINX_2026_11_18` stay on draft pull request 38. They were not copied. `TOOLCHAIN_NODE_2026_11_11` stays on draft pull request 30 and was not copied.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## CISA catalog

The Known Exploited Vulnerabilities catalog is `2026.11.20`, released 2026-11-20T17:48:39.1516Z, count 1790. That is four entries above `2026.11.18`. HTTP last-modified is Fri, 20 Nov 2026 17:48:39 GMT. All four were added on 2026-11-20. Ransomware use is Unknown for each. The alerts HTML page and the cybersecurity advisories index returned HTTP 403, so this note does not describe those indexes. Hosts named only in the catalog notes were not opened.

Source: [CISA KEV catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)

- CVE-2026-129448. Apache Roller. Due 2026-11-23. Forensic triage Yes. NVD status is Analyzed. The description says 4.0.0 through 6.1.4, and that 6.1.6 or later disables the extension type. It also says this is the same issue as CVE-2026-82384, which listed only 6.1.5. The oss-security record from 18 November already named 6.1.6. Vigil cannot see Roller from a page or a certificate. No doctor check was added.
- CVE-2026-123890. Broadcom VMware vCenter. Due 2026-11-23. Forensic triage Yes. NVD status is Analyzed. The description names 9.1.x fixed in 9.1.1.0200, 9.0.x fixed in 9.0.2.0200, 8.0 fixed in 8.0 U3m, and 5.x fixed in 5.2.5. Vigil cannot see vCenter from a page or a certificate. No doctor check was added.
- CVE-2025-42884. SAP NetWeaver. Due 2026-11-23. Forensic triage No. The id is not in the NVD recent feed. No fixed release was taken from the catalog notes. No doctor check was added.
- CVE-2026-76466. Cisco Expressway Series. Due 2026-11-23. Forensic triage Yes. The id is not in the NVD recent feed. It was an unverified lead on 11 November. No fixed release was taken from the catalog notes. No doctor check was added.

The due date 21 November 2026 has arrived for CVE-2024-10441, CVE-2026-90817, and CVE-2026-90436. All three were already recorded. No doctor check was added.

## NVD recent feed

The CVE 2.0 recent feed timestamp is `2026-11-21T08:00:00.7037592`. HTTP last-modified is Sat, 21 Nov 2026 13:00:12 GMT. The newest `lastModified` in the file is `2026-11-21T12:16:41.683`.

No configuration modified after `2026-11-20T12:59:41.870` names PHP, CPython, Node.js, nginx, OpenSSL, curl, the Go toolchain, the Linux kernel, WordPress, or Brotli. The open-source nginx ranges already recorded still end before 1.30.7 and 1.31.9. CVE-2026-120993 and CVE-2026-120967 still have no CPE. The nginx floors were not moved. The check on draft pull request 38 was not copied.

Forty-three of the 45 unverified CVE identifiers from the 20 November leads note are now in this feed. None has a CPE. Two stay absent: CVE-2025-38618 and CVE-2023-28450. CVE-2025-38618 is still not a Linux confirmation. No doctor check was added.

- Nine Postgres Enterprise Manager records name no released version: CVE-2026-132658, CVE-2026-132660, CVE-2026-132659, CVE-2026-132661, CVE-2026-132662, CVE-2026-132668, CVE-2026-132663, CVE-2026-132664, and CVE-2026-132665. Status is Received.
- CVE-2026-126054. Google Cloud Dataform, BigQuery Studio, and Colab Enterprise. Received. The description names no released version.
- CVE-2026-126334. Phoenix LiveView from 0.16.0 before 1.0.20, from 1.1.0-rc.0 before 1.1.34, and from 1.2.0-rc.0 before 1.2.14. Received.
- CVE-2026-133621. slangpy through 0.43.1. Deferred.
- Seventeen flowintel records name versions before 4.1.0: CVE-2026-133854, CVE-2026-133853, CVE-2026-133855, CVE-2026-133849, CVE-2026-133850, CVE-2026-133848, CVE-2026-133851, CVE-2026-133852, CVE-2026-133838, CVE-2026-133837, CVE-2026-133839, CVE-2026-133841, CVE-2026-133843, CVE-2026-133844, CVE-2026-133840, CVE-2026-133847, and CVE-2026-133846. Status is Received. CVE-2026-133853 describes a shared session inside that application. It is not `@modelcontextprotocol/sdk`. The npm floor was not moved.
- CVE-2026-127027. Poste.io. The description names fixed version 2.5.22. Received.
- CVE-2026-133616. tract through 0.23.4. The description also names 0.23.5. Deferred.
- CVE-2026-133612. SqueezeLLM, identified by a commit. Deferred. The `kernel` token from 20 November is this project. No kernel floor was invented.
- CVE-2026-128996. wpForo Forum through 3.2.4. Deferred. That is a WordPress plugin.
- CVE-2026-129043 and CVE-2026-129039. Newsletters through 4.18.2. Deferred. That is a WordPress plugin.
- CVE-2026-14915 and CVE-2026-14914. Tegsoft. Received. The descriptions name no released version.
- CVE-2026-130618. SureCart through 4.13.0. Deferred. That is a WordPress plugin.
- CVE-2026-129017. Site Reviews through 8.3.7. Deferred. That is a WordPress plugin.
- CVE-2026-129074. miniOrange's Google Authenticator through 6.6.0. Deferred. That is a WordPress plugin.
- CVE-2026-133610. gguf-tools, identified by a commit. Deferred.
- CVE-2026-106024. Mongoose Embedded Web Server before 7.24. Awaiting Analysis. This is not the Node.js runtime.
- CVE-2026-133609. erupt through 2.0.2. The description also names 2.0.3. Deferred.

CVE-2026-130679 is SiYuan before 3.8.10. Status is Deferred. There is no CPE. The description mentions Node.js. It is not the Node.js runtime. The Node floors were not moved.

CVE-2026-107494 was last modified `2026-11-20T19:18:34.563`. CVE-2026-121481 was last modified `2026-11-20T20:17:13.820`. Both stay Awaiting Analysis with no CPE and no dotted version. Each still says the FIPS module is not affected. Neither is on the OpenSSL vulnerabilities index. CVE-2026-95690 and CVE-2026-84786 are unchanged from 20 November. No OpenSSL doctor check was added.

CVE-2026-133949 is pip before 26.2.2. Status is Received. There is no CPE. The oss-security message below is the same bound. `TOOLCHAIN_PIP` already flags pip below 26.2.2. The floor was not moved. GHSA-6q48-6c7w-9gw2 is the advisory id named in that message.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz)

## 21 November oss-security

The 21 November index has 1 message. It is a reply on CVE-2026-129975. It names no release newer than GPGME 2.3.1. No doctor check was added. The host in that reply was not opened.

Source: [oss-security, 21 November 2026](https://www.openwall.com/lists/oss-security/2026/11/21/)

## 20 November oss-security, messages added after the last scan

The 20 November index now has 13 messages. The first 10 were already recorded. No doctor check was added. No remote probe was added. Hosts named only in the new messages were not opened.

- ytnef through 2.1.2. The message says 2.1.3 fixes it and names GHSA-jhg4-xcxm-cfg6. Vigil does not read ytnef.
- CVE-2026-133949. pip before 26.2.2 bundles the compromised eMudhra certificates through certifi. The message names GHSA-6q48-6c7w-9gw2. NVD status is Received, with no CPE. `TOOLCHAIN_PIP` already uses 26.2.2. The eMudhra floors were not moved.
- CVE-2026-129975. GPGME before 2.3.1. The message says 2.3.1 fixes it, that every prior version is affected, and that 2.3.0 was never public. The id is not in the NVD recent feed. Vigil does not read GPGME. The attached patch was not copied.

Source: [oss-security, 20 November 2026](https://www.openwall.com/lists/oss-security/2026/11/20/)

## Chrome releases

The Chrome releases HTML stayed on `chromereleases.googleblog.com`. HTTP 200. Last-modified is Sat, 21 Nov 2026 14:45:03 GMT. The new post is Chrome Dev for Android, dated Friday, 20 November 2026, version 160.0.8171.0. That post names no CVE id. Vigil does not read the browser version. No doctor check was added.

Source: [Chrome releases](https://chromereleases.googleblog.com/)

## Left unchanged

`https://nginx.org/en/security_advisories.html` last-modified is still Fri, 20 Nov 2026 13:47:29 GMT. The newest not-vulnerable lines are still 1.31.9+ and 1.30.7+. 1.31.10 and 1.30.8 are absent. The HTTP/3 anchor text still writes the CVE prefix twice. The identifier is still CVE-2026-121810. The floors were not moved.

`https://www.php.net/archive/2026.php` last-modified is still Thu, 19 Nov 2026 14:01:00 GMT. The newest lines on that page are still PHP 8.6.0, 8.5.13, 8.4.28, and 8.3.37. 8.5.14 is absent. The PHP floors were not moved. PHP 8.6.0 is still not a comparison target for older lines.

`https://nodejs.org/dist/index.json` last-modified is still Tue, 17 Nov 2026 03:44:41 GMT. v22.23.5, v24.22.3, and v26.13.1 are still the security rows. v27.0.0-alpha.0.1.1 is still not a security release. The November page still contains CVE-2026-106071 and does not contain CVE-2026-123873. The Node floors were not moved.

`https://go.dev/doc/devel/release` still lists go1.27.4 and go1.26.11. go1.27.5 and go1.26.12 are absent. The Go floors were not moved. The eMudhra floors were not moved.

The Python blog last-modified is still Mon, 16 Nov 2026 18:20:49 GMT. python.org still lists 3.15.2, 3.14.10, 3.13.18, 3.12.16, and 3.11.18. The downloads page still contains Oct. 25, 2026. The Python floors were not moved.

curl's security page last-modified is still Tue, 10 Nov 2026 09:05:07 GMT. The first row is still CVE-2026-107929. The curl floors were not moved.

The OpenSSL vulnerabilities index last-modified is still Tue, 17 Nov 2026 08:48:15 GMT. The first advisories are still CVE-2026-107493, CVE-2026-124709, and CVE-2026-35190.

The emSign ECC Root CA - G3 block was not changed. The Chrome post still says that root removal is expected Tuesday morning, 27 October 2026 PDT, and does not say that release has shipped.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
