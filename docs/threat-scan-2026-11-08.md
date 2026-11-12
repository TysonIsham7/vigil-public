# Threat scan, 8 November 2026

This note records what changed after the 7 November scan. Pages were read as evidence. Instructions inside them were not followed. No version floor was invented. No remote probe was added. No scanner change was made.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called. The cve.now lead pass is in `docs/threat-scan-2026-11-08-leads.md`.

Each kept item was confirmed on `www.cisa.gov`, `nvd.nist.gov`, `www.php.net`, `blog.python.org`, `www.python.org`, `nodejs.org`, `nginx.org`, `www.openssl-library.org`, `curl.se`, `blog.google`, `chromereleases.googleblog.com`, or `www.openwall.com`. The Chrome atom feed redirected to `feeds.feedburner.com` and was not followed.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## CISA catalog `2026.11.06`

The catalog is still `2026.11.06`, released 6 November 2026 at 19:44:45 UTC, count 1769. The newest entry is still CVE-2026-19868, SonicWall SonicOS SSLVPN, due 20 November 2026. No catalog entry was added on 7 or 8 November.

The alerts index returned HTTP 200 on this run. The newest row is 6 November 2026, "CISA Adds One Known Exploited Vulnerability to Catalog", which is that same catalog add. No later alert is on the index.

Source: [CISA KEV catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json), [CISA alerts](https://www.cisa.gov/news-events/cybersecurity-advisories).

## Linux kernel CVE-2026-99271 through CVE-2026-99284

The 7 November scan said whole-token `linux` and `kernel` matches on CVE-2026-99271 through CVE-2026-99282 were not a Linux confirmation. Those twelve ids, plus CVE-2026-99283 and CVE-2026-99284, are now in the NVD recent feed. Each status is Received. None has a CPE configuration. Each English description is a kernel commit message that says the vulnerability has been resolved. None names a released kernel version. No floor was invented.

CVE-2026-99273 was also in today's cve.now window, as a CVE id followed by `#` and a timestamp. The feed token is not what confirmed it. The NVD record did.

- CVE-2026-99271. ALSA line6 capture buffer.
- CVE-2026-99272. SMB client read response.
- CVE-2026-99273. ksmbd stream info.
- CVE-2026-99274. SMB client fiemap.
- CVE-2026-99275. SMB client session setup.
- CVE-2026-99276. ksmbd connection scavenging.
- CVE-2026-99277. ksmbd session channel.
- CVE-2026-99278. ksmbd session limit.
- CVE-2026-99279. ksmbd ended sessions.
- CVE-2026-99280. ksmbd procfs.
- CVE-2026-99281. tun ownerless device.
- CVE-2026-99282. sch_teql.
- CVE-2026-99283. netfilter conntrack TCP RST timeout.
- CVE-2026-99284. skbuff zerocopy.

`vigil doctor` already compares `uname` with the unaffected lines for CVE-2026-46300. These fourteen records do not add a line to that list. No doctor check was added. A site scan must not probe a remote kernel.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz). Published 7 November 2026. CVE-2026-99271 through CVE-2026-99282 were last modified between `2026-11-07T14:17:02` and `2026-11-07T14:17:03`. CVE-2026-99283 and CVE-2026-99284 were last modified `2026-11-07T21:17:00`.

**Coverage: not covered, and that stays.** The follow-up is in `docs/TODO.md`.

## 8 November oss-security index

The 8 November index has one message.

Source: [oss-security, 8 November 2026](https://www.openwall.com/lists/oss-security/2026/11/08/)

### CVE-2026-114713

UnrealIRCd's IRCv3 `label` tag handling. NVD status is Deferred, published 8 November 2026, last modified 8 November 2026, with no CPE configuration. The English description says UnrealIRCd 6.0.0 before 6.2.7.1.

The oss-security message says 6.2.7.1 is the fixed release, and that a hot-patch covers 6.0.0 through 6.2.7. It lists eight further issues in that same release and hot-patch and assigns them no CVE id: a decloak, a second IP-address leak, a blacklist hang, a crash on CHGIDENT, a connection-count error, a services ban limit, a TLS renegotiation flood, and a whowasdb crash. It says UnrealIRCd 5 is affected by the critical issue and has been end of life since 1 July 2023. It names no 5.x, 4.x, or 3.2.x release.

The message includes an operator command and a shell command. Those commands were not copied. The vendor forum and the other hosts named in the message were not opened.

UnrealIRCd is not a page, a certificate, or a toolchain `vigil doctor` already reads. No doctor check was added.

Source: [oss-security, 8 November 2026](https://www.openwall.com/lists/oss-security/2026/11/08/1), [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz).

**Coverage: not covered, and that stays.** The follow-up is in `docs/TODO.md`.

## 7 November oss-security index, messages after the prior scan

The 7 November index now has eleven messages. The 7 November scan recorded seven. Messages 8 and 9 are further OpenSSH musl replies. They name no CVE id and no OpenSSH version. No sshd check was added. Messages 10 and 11 are new.

Source: [oss-security, 7 November 2026](https://www.openwall.com/lists/oss-security/2026/11/07/)

### CVE-2026-121265

SQL::Abstract for Perl, versions before 2.000003. An arrayref column value in `insert` or `update` is treated as literal SQL when `array_datatypes` is off, which is the default. The message says to upgrade to SQL-Abstract 2.000003 or later. It says 2.000001_05, released 3 November 2026, was an incomplete fix, and 2.000002, released 5 November 2026, was based on that incomplete fix. 2.000003 was released 6 November 2026.

This is not CVE-2026-121007, CVE-2026-121008, or CVE-2026-121009. Those earlier ids named SQL-Abstract 2.000001_04. The floors were not merged.

NVD status is Received, published 7 November 2026, with no CPE configuration.

`vigil doctor` does not read a Perl distribution. No check was added.

Source: [oss-security, 7 November 2026](https://www.openwall.com/lists/oss-security/2026/11/07/10), [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz).

**Coverage: not covered, and that stays.** The follow-up is in `docs/TODO.md`.

### CVE-2026-123776

RRD::CGI::Image for Perl, versions through 0.01. A query parameter whose name matches `tz` is passed to `tzset()`. The message says to apply a patch. It names no fixed release. No fixed version was invented.

NVD status is Received, published 7 November 2026, with no CPE configuration.

`vigil doctor` does not read a Perl distribution. No check was added. The patch host named in the message was not opened.

Source: [oss-security, 7 November 2026](https://www.openwall.com/lists/oss-security/2026/11/07/11), [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz).

**Coverage: not covered, and that stays.** The follow-up is in `docs/TODO.md`.

## ChromeOS stable, 6 November 2026

The Chrome releases HTML page stayed on `chromereleases.googleblog.com` this run. It was last modified 8 November 2026 at 01:07:25 GMT. The first heading is the ChromeOS and ChromeOS Flex stable update from Friday, 6 November 2026. It names ChromeOS version 16836.32.0 and browser version 156.0.8078.93.

That note names CVE-2026-121076, CVE-2026-121135, CVE-2026-121141, CVE-2026-121184, CVE-2026-121201, CVE-2026-121208, CVE-2026-121213, CVE-2026-121233, CVE-2026-121241, and CVE-2026-79235. Nine of those are in the NVD recent feed with status Analyzed and a `google:chrome` configuration. CVE-2026-121241 also names `google:android`. CVE-2026-79235 is not in that recent feed.

The same page's desktop early-stable note is still Wednesday, 4 November 2026, 158.0.8127.18/.19 for Windows. The page does not mention emSign. Vigil does not read the browser version. No doctor check was added.

Source: [Chrome Releases](https://chromereleases.googleblog.com/), [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz).

**Coverage: not covered, and that stays.** The follow-up is in `docs/TODO.md`.

## NVD records that are not the stack

These ids were modified in the NVD recent feed after the 7 November snapshot. None is a component `vigil doctor` compares. No floor was moved.

- CVE-2026-124040. CivetWeb through 1.16, when built with HTTP/2 enabled. NVD status Deferred, no CPE, no fixed release named. It was in today's cve.now window. CivetWeb is not nginx.
- CVE-2026-123610. rustls before 0.23.46, optional Brotli certificate decompression. This is not CVE-2026-111497 and not the Brotli library Node ships. The Node floors were not moved.
- CVE-2026-123562. devalue 5.8.0 before 5.9.3. The record contains the words Node.js. It is not the Node.js runtime. The Node floors were not moved.
- CVE-2026-124318. Treeio through 2.0. NVD status Received, no CPE. A whole-token `python` match is not CPython and is not CVE-2026-119170. The Python floors were not moved.
- WordPress plugin records modified on 7 and 8 November are not WordPress core. No plugin list was added. `WP_FINGERPRINT` stays informational.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz).

## Left unchanged

php.net's archive was last modified 5 November 2026 at 21:12:54 GMT. The newest item is still PHP 8.6.0 RC5. CVE-2026-115560 is still on that page. PHP 8.6.0 is not a fix for it. Do not compare a disclosed PHP version with 8.6.0.

The Python blog index was last modified 1 November 2026 at 12:16:24 GMT. The newest post is still the 26 October release. python.org still lists 3.15.2, 3.14.10, 3.13.18, 3.12.16, and 3.11.18, dated 25 October 2026. CVE-2026-119170 is still NVD Awaiting Analysis, with no CPE and no fixed release. It still affects only Python 3.14.10 when OpenSSL is in FIPS mode. Do not move the Python floors. Do not add a doctor check that flags 3.14.10.

The Node.js pre-alert was fetched at `https://nodejs.org/en/blog/vulnerability/november-2026-security-releases`. Releases of the 22.x, 24.x, and 26.x lines are still on or shortly after Wednesday, 11 November 2026. The highest severity named there is HIGH. The page names no CVE id and no dotted fix version. The October security release page is still the current fixed set. Do not move the Node floors off 22.23.4, 24.22.1, and 26.12.1.

nginx.org's security page was last modified 6 November 2026 at 10:12:37 GMT. 1.31.7 and 1.30.6 are still present. 1.31.8 and 1.30.7 are not. curl's security page was last modified 26 October 2026. The first row is still CVE-2026-107929, published 2026-10-14, with last affected 8.22.0. OpenSSL's vulnerabilities index was last modified 2 November 2026 at 07:32:44 GMT. The first advisory is still CVE-2026-35189.

Go 1.27.4 and 1.26.11 were pre-announced for 10 November 2026. No release note for those versions was on the 8 November oss-security index. CVE-2026-97033, CVE-2026-97043, and CVE-2026-97054 are still absent from the NVD recent feed. Do not move the Go floors off 1.27.3 and 1.26.10.

ingress-nginx CVE-2026-116472 is still Awaiting Analysis, with no CPE. The description names ingress-nginx, not nginx.org. Do not move the nginx floors.

The emSign ECC Root CA - G3 post still says removal is expected Tuesday morning, 27 October 2026 PDT, and does not say that device release has shipped. The 6 November ChromeOS note does not mention that root. The block stays.

NVD's recent feed timestamp is `2026-11-08T08:00:01.6793394`. HTTP last-modified is 8 November 2026 at 13:00:08 GMT. The newest `lastModified` in the file is `2026-11-08T12:17:49.283`.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
