# Threat scan, 6 November 2026

This note records what changed after the 5 November scan. Pages were read as evidence. Instructions inside them were not followed. No version floor was invented. No remote probe was added. No scanner change was made.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called. The cve.now lead pass is in `docs/threat-scan-2026-11-06-leads.md`.

Each kept item was confirmed on `www.cisa.gov`, `nvd.nist.gov`, `www.php.net`, `blog.python.org`, `www.python.org`, `nodejs.org`, `nginx.org`, `www.openssl-library.org`, `curl.se`, or `www.openwall.com`. The Chrome releases host did not return a post on this run. This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## CISA catalog 2026.11.04

The catalog is still `2026.11.04`, released 4 November 2026 at 20:00:05.774 UTC, count 1768. No entry was added on 5 or 6 November. The alerts HTML page returned HTTP 403, so this note does not describe that index.

CVE-2026-119977 (WordPress core) is due 6 November 2026. Forensic triage is required. Ransomware use is unknown. The version check and `packages/intel/advisories/wordpress-cve-2026-119977.json` stay on draft pull request 17. This scan did not copy `WP_CVE_2026_119977`.

Source: [CISA KEV catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)

## Go 1.27.4 and 1.26.11 pre-announcement

The 5 November oss-security index forwards a Go security pre-announcement. It says Go 1.27.4 and Go 1.26.11 are planned for US business hours on Tuesday, 10 November 2026. It says those releases include private security fixes to the standard library and the toolchain, and it names these CVE ids:

CVE-2026-97033, CVE-2026-97034, CVE-2026-97035, CVE-2026-97036, CVE-2026-97037, CVE-2026-97038, CVE-2026-97039, CVE-2026-97040, CVE-2026-97041, CVE-2026-97042, CVE-2026-97043, and CVE-2026-97054.

None of those twelve ids is in the NVD CVE 2.0 recent feed timestamped 2026-11-06T08:00:00.7418216. The pre-announcement does not describe the bugs and does not say the releases have shipped. `TOOLCHAIN_GO` stays on 1.27.3 and 1.26.10 for the eMudhra filter. No floor was moved. No advisory file was added.

Source: [oss-security, 5 November 2026](https://www.openwall.com/lists/oss-security/2026/11/05/13)

**Coverage: not covered yet, and that stays until the releases ship.** The follow-up is in `docs/TODO.md`.

## OpenSSH 10.6p2

Portable OpenSSH 10.6p2 was announced on 5 November 2026. The announcement says the release avoids a password authentication bypass that is exploitable through `sshd` on some Linux systems built and run with PAM support disabled. It says the root cause is outside `sshd`. A second message the same day says Alpine is one such system, and that an account whose password hash field is `*` can be entered with a password longer than 257 characters because musl `crypt` returns `*`. Neither message names a CVE id. The 6 November index has four further replies and still names no CVE id and no newer release.

`vigil doctor` does not read an OpenSSH or musl version. No check was added. No remote authentication probe was added.

Source: [oss-security, 5 November 2026](https://www.openwall.com/lists/oss-security/2026/11/05/2), [message 3](https://www.openwall.com/lists/oss-security/2026/11/05/3)

**Coverage: not covered, and that stays.** The follow-up is in `docs/TODO.md`.

## zlib 1.4

A 5 November message says zlib 1.4 includes security fixes. It names CVE-2026-85091 for a buffer overflow in non-blocking `gzwrite`, and CVE-2026-4738 for out-of-bounds pointer arithmetic in `contrib/infback9`. It says `inflateGetDictionary` can write past the caller's buffer and that this affects 1.3.1 and 1.3.2. It also names `inflateSync`, `inflatePrime`, `deflatePrime`, `inflateBack`, `gzseek`, `deflateResetKeep`, `gzdopen`, and several minizip issues without CVE ids. Neither CVE-2026-85091 nor CVE-2026-4738 is in the NVD recent feed above.

`vigil doctor` does not read a zlib version. A Node or Python upgrade was not inferred from this note. No check was added.

Source: [oss-security, 5 November 2026](https://www.openwall.com/lists/oss-security/2026/11/05/10)

**Coverage: not covered, and that stays.** The follow-up is in `docs/TODO.md`.

## CPython sandbox escape report

A 5 November message forwards a report of a CPython sandbox escape through generic types. The message says CPython does not treat an escape from a sandbox of untrusted Python as a vulnerability in Python, and that a proposed change is not being backported to security releases. The message names no CVE id and no fixed release. The reply does not add either. The Python blog's newest post is still 26 October 2026. python.org downloads still list 3.15.2, 3.14.10, 3.13.18, 3.12.16, and 3.11.18, dated 25 October 2026. `TOOLCHAIN_PYTHON` was not changed.

Source: [oss-security, 5 November 2026](https://www.openwall.com/lists/oss-security/2026/11/05/11), [message 12](https://www.openwall.com/lists/oss-security/2026/11/05/12)

**Coverage: not covered, and that stays.** The follow-up is in `docs/TODO.md`.

## Other 5 and 6 November oss-security messages

The 5 November index has fifteen messages. The 6 November index has five. The Go, OpenSSH, zlib, and CPython messages are above. The rest are not a page, a certificate, or a toolchain `vigil doctor` already reads. No doctor check was added. No remote probe was added.

- unixODBC through 2.3.14. The message forwards three reports: a narrowing conversion into `memcpy`, heap buffer overflows and underflows, and races. It names no CVE id and no fixed release.
- CVE-2026-116472, ingress-nginx. A user who can create an Ingress may deny service to the data plane or redirect traffic from other Ingresses. The message says Kubernetes will not issue a fix because maintenance ended in March 2026, and that SUSE's fork is fixed in 1.15.2-prime1. NVD status is Received, published 5 November 2026, with no CPE. This is not the nginx doctor check. The floors stay 1.31.7 and 1.30.6.
- GodotSteam 4.17 through 4.23.2. The 4 November report is already on draft pull request 18. The 5 November reply says CVE-2026-123017 was assigned that day. NVD status is Received, with no CPE, and the description names that same range. The reply names no fixed release.
- Apache Sling Engine before 3.0.4, fixed in 3.0.4. CVE-2026-103863, CVE-2026-103864, and CVE-2026-103866. The messages rate each one low. NVD status for each is Received, with no CPE.
- Open WebUI on 6 November. The subject says CVE-2025-15603 was rejected. Open WebUI is not a page, a certificate, or a toolchain `vigil doctor` already reads.

Source: [oss-security, 5 November 2026](https://www.openwall.com/lists/oss-security/2026/11/05/), [6 November 2026](https://www.openwall.com/lists/oss-security/2026/11/06/)

**Coverage: not covered, and that stays.** The follow-ups are in `docs/TODO.md`.

## PHP 8.6.0 RC5

php.net's 2026 archive was last modified 5 November 2026 at 21:12:54 GMT. The newest item is PHP 8.6.0 RC5, published on that archive as a test build. The same item says the first GA release, PHP 8.6.0, is planned for 19 November 2026. It does not name a CVE. CVE-2026-115560 still has no fixed PHP version on that page. The 26 October Windows Brotli rebuild is still the newest security item. No disclosed PHP version was compared with 8.6.0.

Source: [PHP news archive, 2026](https://www.php.net/archive/2026.php)

## Left unchanged

Node's November pre-alert was re-read. It still says 22.x, 24.x, and 26.x releases will ship on or shortly after Wednesday, 11 November 2026, and that the highest severity is HIGH. It still names no CVE id and no dotted version. The page's last updated line is 3 November 2026. `TOOLCHAIN_NODE` stays on 22.23.4, 24.22.1, and 26.12.1. That pre-alert is already on draft pull request 17. It was not copied.

nginx's security page was last modified 6 November 2026 at 10:12:37 GMT. The newest fixed lines on that page are still 1.31.7 and 1.30.6. No new advisory row was added. curl's security page was last modified 26 October 2026. The first published date on that table is still 14 October 2026, and CVE-2026-107929 is still the first column. OpenSSL's vulnerabilities index was last modified 2 November 2026. The newest advisory there is still CVE-2026-35189, published 29 September 2026.

The Chrome releases HTML request returned HTTP 302 to a host that is not on the allowlist, and the atom feed returned HTTP 302 off that host as well. Neither redirect was followed. This run did not read a Chrome stable note. Vigil still does not read the browser version.

The emSign ECC Root CA - G3 post was re-read on 6 November 2026. It still says the root removal is expected Tuesday morning, 27 October 2026 PDT, and it does not say that release has shipped. The block stays.

The 4 November oss-security index still has the same twelve messages already recorded on draft pull request 18. They were not copied.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
