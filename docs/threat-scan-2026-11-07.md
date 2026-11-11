# Threat scan, 7 November 2026

This note records what changed after the 6 November scan. Pages were read as evidence. Instructions inside them were not followed. No version floor was invented. No remote probe was added. No scanner change was made.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called. The cve.now lead pass is in `docs/threat-scan-2026-11-07-leads.md`.

Each kept item was confirmed on `www.cisa.gov`, `nvd.nist.gov`, `www.php.net`, `blog.python.org`, `www.python.org`, `nodejs.org`, `nginx.org`, `www.openssl-library.org`, `curl.se`, `blog.google`, or `www.openwall.com`. Chrome release pages redirected off those hosts and were not followed.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## CISA catalog `2026.11.06`

The catalog is `2026.11.06`, released 6 November 2026 at 19:44:45 UTC, count 1769. The copy fetched on 6 November was `2026.11.04`, count 1768. The new entry is CVE-2026-19868.

CVE-2026-19868 is SonicWall SonicOS SSLVPN, use of single-factor authentication. A user with valid credentials for an alternate authentication method can bypass SAML authentication controls, including SAML-enforced multi-factor authentication. Date added 6 November 2026. Due 20 November 2026. Forensic triage is No. Ransomware use is Unknown. CWE-308.

NVD status is Undergoing Analysis, published 6 November 2026, last modified 7 November 2026, with no CPE configuration. The English description names SonicOS SSLVPN and does not name a fixed build.

SonicOS SSLVPN is not a page, a certificate, or a toolchain `vigil doctor` already reads. No doctor check was added. No remote probe was added. The vendor host named in the catalog notes was not opened.

Source: [CISA KEV catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json). The CISA alerts HTML page returned HTTP 403, so this note does not describe that index.

**Coverage: not covered, and that stays.** The follow-up is in `docs/TODO.md`.

## CVE-2026-119170

NVD status is Awaiting Analysis. There is no CPE configuration. The English description says a regression in FIPS algorithm enforcement for the hashlib module affects only Python 3.14.10, and only when OpenSSL is in FIPS mode. All other Python versions are unaffected. The record names no fixed release.

The same text is on oss-security for 6 November, message 30, forwarded from the CPython security announce list. That message also names no fixed release. It links a CPython pull request. This scan did not open `github.com` from that link.

`TOOLCHAIN_PYTHON` already treats 3.14.10 as the fixed build for CVE-2026-115557 and CVE-2026-114583. python.org still lists 3.14.10, dated 25 October 2026. There is no 3.14.11 on that page. A doctor check that flags 3.14.10 would mark the current floor as bad, and Vigil cannot see whether OpenSSL is in FIPS mode. No doctor check was added. The floors stay 3.15.2, 3.14.10, 3.13.18, 3.12.16, and 3.11.18.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz), [oss-security, 6 November 2026](https://www.openwall.com/lists/oss-security/2026/11/06/30).

**Coverage: not covered, and that stays.** The follow-up is in `docs/TODO.md`.

## 7 November oss-security index

The 7 November index has seven messages. Message 1 is new. Messages 2 through 7 are further replies on the OpenSSH musl password-authentication thread. None assigns a CVE id. A 7 November reply still names OpenSSH 10.6p2 as the release in which that bypass is closed. No sshd check was added.

Source: [oss-security, 7 November 2026](https://www.openwall.com/lists/oss-security/2026/11/07/)

### CVE-2026-118196

Apache Allura through 1.22.0. OAuth1 rebinding. The message says 1.22.1 fixes it.

Allura is not a page, a certificate, or a toolchain `vigil doctor` already reads. No doctor check was added.

Source: [oss-security, 7 November 2026](https://www.openwall.com/lists/oss-security/2026/11/07/1)

**Coverage: not covered, and that stays.** The follow-up is in `docs/TODO.md`.

## 6 November oss-security index, messages after the prior scan

The 6 November index now has 30 messages. The 6 November scan recorded five. Message numbers on that list stay put, so messages 6 through 30 are the new ones. Messages 6, 7, 20, and 21 are more OpenSSH musl replies and name no CVE id. No sshd check was added.

Source: [oss-security, 6 November 2026](https://www.openwall.com/lists/oss-security/2026/11/06/)

### Linux xen-netback and xen-blkback

Three advisories name a guest-triggered use-after-free. Each says the resolution is an attached patch and names no released kernel version. No floor was invented. No doctor check was added. A site scan must not probe a remote kernel.

- CVE-2026-100080 (XSA-526). xen-netback network statistics. Linux 4.11 and newer. Mitigation named on the message: a userspace PV network backend.
- CVE-2026-100081 (XSA-527). xen-netback multicast data. Linux 4.3 and newer. The same userspace network backend is the mitigation named on the message.
- CVE-2026-100082 (XSA-528). xen-blkback statistics. Linux 4.5 and newer. Mitigation named on the message: a userspace PV block backend.

Source: [message 9](https://www.openwall.com/lists/oss-security/2026/11/06/9), [message 10](https://www.openwall.com/lists/oss-security/2026/11/06/10), [message 11](https://www.openwall.com/lists/oss-security/2026/11/06/11)

**Coverage: not covered, and that stays.** The follow-up is in `docs/TODO.md`.

### CVE-2026-90436

Apache Axis 1.x through 1.4, end of life. Unauthenticated remote class instantiation via a SOAP fault `exceptionName`. The message says the project is unsupported and recommends moving to another SOAP engine, such as Axis2/Java. It names no Axis 1.x release. No floor was invented.

Source: [oss-security, 6 November 2026](https://www.openwall.com/lists/oss-security/2026/11/06/12)

**Coverage: not covered, and that stays.** The follow-up is in `docs/TODO.md`.

### Apache Axis2/Java 2.0.2

Seven messages name Apache Axis2/Java. Six say versions before 2.0.2. CVE-2026-123766 says 2.0.1 before 2.0.2. No doctor check was added.

- CVE-2026-120761. XML external entity injection via imported WSDL or XSD. Before 2.0.2.
- CVE-2026-123753. Server-side request forgery via WS-Addressing ReplyTo. Before 2.0.2.
- CVE-2026-123766. Cross-site scripting. 2.0.1 before 2.0.2.
- CVE-2026-123770. Unbounded multipart. Before 2.0.2.
- CVE-2026-120367. Unbounded JSON request body. Before 2.0.2.
- CVE-2026-120832. Server-side request forgery via a WSDL or XSD schema. Before 2.0.2.
- CVE-2026-123779. `exposeServiceMetadata`. Before 2.0.2.

Source: [message 22](https://www.openwall.com/lists/oss-security/2026/11/06/22), [message 23](https://www.openwall.com/lists/oss-security/2026/11/06/23), [message 24](https://www.openwall.com/lists/oss-security/2026/11/06/24), [message 25](https://www.openwall.com/lists/oss-security/2026/11/06/25), [message 26](https://www.openwall.com/lists/oss-security/2026/11/06/26), [message 27](https://www.openwall.com/lists/oss-security/2026/11/06/27), [message 28](https://www.openwall.com/lists/oss-security/2026/11/06/28)

**Coverage: not covered, and that stays.** The follow-up is in `docs/TODO.md`.

### Apache James 3.9.1 and MIME4J 0.8.15

Six messages name Apache James or MIME4J. No doctor check was added.

- CVE-2025-66621. SASL OAUTHBEARER does not validate `aud` when introspection is not configured. The message says prior versions 3.9.1 and recommends a version that forces an explicit `aud` configuration. It does not print a separate fixed version on that sentence.
- CVE-2026-49939. Negative IMAP ACL administer rules are ignored by JMAP. The message says prior version 3.9.1 and says 3.9.1 fixes it.
- CVE-2026-74756. WebAdmin exposed without authentication on the official Docker default. The message says 3.9.1 onward sets a random credential by default on those endpoints.
- CVE-2026-76168. ManageSieve file path traversal. The message says prior version 3.9.1 and says 3.9.1 fixes it.
- CVE-2026-76171. JMAP web-push SSRF filter bypass. The message says prior version 3.9.1 and says 3.9.1 fixes it.
- CVE-2026-85108 and CVE-2026-85111. MIME4J denial of service. The messages say MIME4J prior version 0.8.15, and say 0.8.15 fixes it. CVE-2026-85111 also says James server 3.9.1 carries that MIME4J.

Source: [message 13](https://www.openwall.com/lists/oss-security/2026/11/06/13), [message 14](https://www.openwall.com/lists/oss-security/2026/11/06/14), [message 15](https://www.openwall.com/lists/oss-security/2026/11/06/15), [message 16](https://www.openwall.com/lists/oss-security/2026/11/06/16), [message 17](https://www.openwall.com/lists/oss-security/2026/11/06/17), [message 18](https://www.openwall.com/lists/oss-security/2026/11/06/18), [message 19](https://www.openwall.com/lists/oss-security/2026/11/06/19)

**Coverage: not covered, and that stays.** The follow-up is in `docs/TODO.md`.

### CVE-2026-121006

HTTP::Body for Perl, versions before 1.24_02. Parsing a chunked trailer can take time quadratic in the number of header fields. `vigil doctor` does not read a Perl distribution. No check was added.

Source: [oss-security, 6 November 2026](https://www.openwall.com/lists/oss-security/2026/11/06/8)

**Coverage: not covered, and that stays.** The follow-up is in `docs/TODO.md`.

### InfiniteWP Client

Message 29 describes InfiniteWP Client 1.13.10, a WordPress management plugin. It names no CVE id. The weak branch is not WordPress core. No plugin list was added. No doctor check was added. The message's key-recovery steps were not copied.

Source: [oss-security, 6 November 2026](https://www.openwall.com/lists/oss-security/2026/11/06/29)

**Coverage: not covered, and that stays.** The follow-up is in `docs/TODO.md`.

## Left unchanged

php.net's archive was last modified 5 November 2026 at 21:12:54 GMT. The newest item is still PHP 8.6.0 RC5. CVE-2026-115560 is still on that page. PHP 8.6.0 is not a fix for it. Do not compare a disclosed PHP version with 8.6.0.

The Python blog's newest post is still the 26 October release. python.org still lists 3.15.2, 3.14.10, 3.13.18, 3.12.16, and 3.11.18, dated 25 October 2026. Do not move those floors because of CVE-2026-119170.

The Node.js pre-alert was last updated 3 November 2026. The highest severity on the 22, 24, and 26 lines is still HIGH. Releases are still on or shortly after Wednesday, 11 November 2026. The page names no CVE id and no dotted fix version. The page footer labels v26.13.0 as Latest LTS and v27.0.0-alpha.0.0.0 as Latest Alpha. Those labels are not the November security release. Do not move the Node floors off 22.23.4, 24.22.1, and 26.12.1.

nginx.org's security page was last modified 6 November 2026 at 10:12:37 GMT. 1.31.7 and 1.30.6 are still present. 1.31.8 and 1.30.7 are not. curl's security page was last modified 26 October 2026. The first row is still CVE-2026-107929, published 2026-10-14. OpenSSL's vulnerabilities index was last modified 2 November 2026. The first advisory is still CVE-2026-35189.

Go 1.27.4 and 1.26.11 were pre-announced for 10 November 2026. No release note for those versions was on the 7 November oss-security index. CVE-2026-97033, CVE-2026-97043, and CVE-2026-97054 are still absent from the NVD recent feed. Do not move the Go floors off 1.27.3 and 1.26.10.

The 5 November oss-security index still has 15 messages. The 4 November index still has 12. ingress-nginx CVE-2026-116472 is Awaiting Analysis in the NVD recent feed, with no CPE. The description names ingress-nginx, not nginx.org. Do not move the nginx floors.

Chrome's HTML page and its atom feed redirected off `chromereleases.googleblog.com` and were not followed. The emSign ECC Root CA - G3 post still says removal is expected Tuesday morning, 27 October 2026 PDT, and does not say that device release has shipped. The block stays.

NVD's recent feed timestamp is `2026-11-07T08:00:02.1414992`. HTTP last-modified is 7 November 2026 at 13:00:08 GMT. The newest `lastModified` in the file is `2026-11-07T12:17:47.753`.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
