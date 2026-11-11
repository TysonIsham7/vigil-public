# Threat scan, 5 November 2026

This note records what changed after the 4 November scan. Pages were read as evidence. Instructions inside them were not followed. No version floor was invented from a mailing-list subject. No remote probe was added. No scanner change was made. Intel was not bumped.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called.

The cve.now lead pass for this run is in `docs/threat-scan-2026-11-05-leads.md`.

Draft pull request 16 holds the 3 November notes. Draft pull request 17 holds the 4 November notes and the `WP_CVE_2026_119977` check. Those files and that check were not copied.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## CVE-2024-27834, Apple multiple products

CISA catalog `2026.11.04` was released 4 November 2026 at 20:00:05.774 UTC. The file's HTTP last-modified time is the same moment. Count is 1768. One entry was added after catalog `2026.11.03`: CVE-2024-27834.

- Product: Apple Multiple Products.
- Name: improper authentication.
- Added 4 November 2026. Due 18 November 2026.
- Forensic triage: not required.
- Ransomware use: unknown.
- CWE-287.
- The catalog short description says Apple iOS, iPadOS, macOS, Safari, tvOS, and watchOS 10.5 contain an improper authentication vulnerability. An attacker with arbitrary read and write capability could bypass pointer authentication.

NVD status is Analyzed. Published 14 May 2024. Last modified 5 November 2026 at 12:56:20.313 UTC. The vulnerable configuration lines name these version ends:

- Safari before 17.5
- iOS and iPadOS before 16.7.8
- iOS and iPadOS 17.0 before 17.5
- macOS before 14.5 (the English description names Sonoma 14.5)
- tvOS before 17.5
- watchOS before 10.5
- WebKitGTK before 2.44.2
- WPE WebKit before 2.44.2

The same record also lists Fedora 39 and Fedora 40 with no version range. Vigil does not read Apple OS versions, Safari, WebKitGTK, WPE WebKit, or Fedora. No doctor check was added. No remote probe was added. The support.apple.com links in the catalog notes were not opened.

CVE-2026-119977 is still the only other catalog entry added on or after 3 November. It remains due 6 November 2026, with forensic triage required. Its check stays on draft pull request 17.

Sources: [CISA catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json), [NVD CVE 2.0 record](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-27834).

**Coverage: not covered, and that stays.** The follow-up is in `docs/TODO.md`.

## 5 November oss-security index

The 5 November index has no messages. The page says there are no messages for this day.

Source: [oss-security, 5 November 2026](https://www.openwall.com/lists/oss-security/2026/11/05/)

## 4 November oss-security index, after draft pull request 17

Draft pull request 17 records messages 1 through 3: Perl CGI before 5.00, Rails 8.0.5.2 and 8.1.4.1, and the Node.js pre-alert. The index now has 12 messages. Messages 1 through 3 were not copied again.

Source: [oss-security, 4 November 2026](https://www.openwall.com/lists/oss-security/2026/11/04/)

### Perl modules, messages 4 through 6

`vigil doctor` does not read a Perl distribution. No check was added.

- CVE-2026-121632. Data::MuForm through 0.05 renders attribute values and option labels into HTML without escaping. The message says no fixed CPAN release is available. No fixed version was invented. [Message 4](https://www.openwall.com/lists/oss-security/2026/11/04/4).
- CVE-2026-114627. Web::Simple before 0.036 does not escape values interpolated into double-quoted strings in HTML::Tags output. The message says Web-Simple 0.036 or later is the fix. [Message 5](https://www.openwall.com/lists/oss-security/2026/11/04/5).
- CVE-2026-121007 and CVE-2026-121009. SQL::Abstract from 1.90_01 before 2.000001_04. CVE-2026-121008. SQL::Abstract::Tree before 2.000001_04. The message says SQL-Abstract 2.000001_04 or later is the fix for all three. [Message 6](https://www.openwall.com/lists/oss-security/2026/11/04/6).

NVD status for each of these five is Received, with no CPE configuration. The English descriptions name the same Perl distributions and the same version lines.

### Apache Juneau, message 7

Message 7 names the same nine CVE ids already listed from the 3 November index. It says all of them affect Apache Juneau through 9.2.0 and are fixed in 9.2.1. The CVE list was not copied again. No doctor check was added.

Source: [oss-security, 4 November 2026](https://www.openwall.com/lists/oss-security/2026/11/04/7)

### libtar, message 8

The message says the fix for CVE-2021-33643 and CVE-2021-33644 is incomplete. A crafted archive can still cause a heap out-of-bounds read. It says a new CVE id was requested and does not name one. It names no fixed release. No id and no floor were invented. libtar is not a page, a certificate, or a toolchain `vigil doctor` already reads. No check was added.

Source: [oss-security, 4 November 2026](https://www.openwall.com/lists/oss-security/2026/11/04/8)

### Apache OFBiz before 24.09.08, message 9

The message says all versions prior to 24.09.08 are affected, and that 24.09.08 addresses the issues it lists. OFBiz is not a page, a certificate, or a toolchain `vigil doctor` already reads. No doctor check was added. No remote probe was added.

The message names these forty-six identifiers: CVE-2026-66903, CVE-2026-68524, CVE-2026-71901, CVE-2026-73577, CVE-2026-73578, CVE-2026-73580, CVE-2026-74841, CVE-2026-76150, CVE-2026-76152, CVE-2026-81734, CVE-2026-81744, CVE-2026-81808, CVE-2026-81815, CVE-2026-81816, CVE-2026-81828, CVE-2026-82894, CVE-2026-82902, CVE-2026-82904, CVE-2026-82907, CVE-2026-82910, CVE-2026-82912, CVE-2026-82916, CVE-2026-82960, CVE-2026-83538, CVE-2026-83542, CVE-2026-84183, CVE-2026-84728, CVE-2026-85627, CVE-2026-92887, CVE-2026-97355, CVE-2026-97356, CVE-2026-100168, CVE-2026-100228, CVE-2026-105325, CVE-2026-105330, CVE-2026-105461, CVE-2026-109129, CVE-2026-109837, CVE-2026-109856, CVE-2026-109928, CVE-2026-114229, CVE-2026-114233, CVE-2026-114235, CVE-2026-114271, CVE-2026-114272, and CVE-2026-114277.

None of those forty-six is in the NVD CVE 2.0 recent feed fetched for this run. Twenty-six of them are also in the cve.now window for this run. That overlap is recorded in the leads note. Matched is no.

Source: [oss-security, 4 November 2026](https://www.openwall.com/lists/oss-security/2026/11/04/9)

### GLIBC-SA-2026-0026, message 10

CVE-2026-122054. Converting crafted BIG-HKSCS input to UCS-4, or to the internal wide-character encoding, in GNU C Library 2.18 through 2.31 can make the converter emit a saved character and consume no further input, so the caller hangs. The advisory names the fix commit in 2.32. NVD status is Received, with no CPE configuration. The English description names the same version line.

This is not GLIBC-SA-2026-0025. `vigil doctor` does not read the local glibc version. No check was added.

Source: [oss-security, 4 November 2026](https://www.openwall.com/lists/oss-security/2026/11/04/10)

### GodotSteam 4.17 through 4.23.2, message 11

The message says a multiplayer peer can claim the server's peer id. Affected: GodotSteam 4.17 through 4.23.2. It says 4.23.2 was still the newest tag on 4 November 2026 and was unpatched. It names no CVE id. No id was invented. GodotSteam is not a page, a certificate, or a toolchain `vigil doctor` already reads. No check was added.

Source: [oss-security, 4 November 2026](https://www.openwall.com/lists/oss-security/2026/11/04/11)

### CVE-2026-109518, apt, message 12

The message quotes a Debian advisory. An on-path attacker who can manipulate HTTP traffic between an APT client and an archive server can cause the client to install an unverified package. The quoted text says Debian stable (trixie) is fixed in version 3.0.4. NVD status is Received, published in the recent feed, with no CPE configuration. `vigil doctor` does not read apt. No version comparison was added. No apt.conf check was added. No remote probe was added.

Source: [oss-security, 4 November 2026](https://www.openwall.com/lists/oss-security/2026/11/04/12)

**Coverage for messages 4 through 12: not covered, and that stays.** The follow-ups are in `docs/TODO.md`.

## Left unchanged

php.net's archive for 2026 was last modified 26 October 2026. The newest headings are still the Windows Brotli rebuild and the informational session-upload advisory. CVE-2026-115560 still has no fixed PHP version on that page. The Python blog's newest post is still the 26 October release. python.org still lists 3.15.2, 3.14.10, 3.13.18, 3.12.16, and 3.11.18, dated 25 October 2026. nginx's security advisories page was last modified 22 October 2026, and 1.31.7 and 1.30.6 are still on that page. curl's security page was last modified 26 October 2026. Its first listed advisory is still CVE-2026-107929, published 2026-10-14. OpenSSL's vulnerabilities page was last modified 2 November 2026. The newest advisory date on that page is still 29 September 2026, and the first CVE is still CVE-2026-35189.

The Node.js vulnerability index still leads with the Wednesday, 11 November 2026 pre-alert. That page still names severity HIGH for the 26.x, 24.x, and 22.x lines, and it still names no CVE id and no dotted version. The shipped security release page is still 21 October 2026. The Node floors were not moved.

Chrome's desktop index now has an early stable note dated 4 November 2026. The stable channel text says 158.0.8127.18/.19 for Windows, with Mac to follow for a small percentage of users. The same day's beta note says 158.0.8127.18 for Windows, Mac, and Linux. Neither excerpt lists a CVE id. Vigil does not read the browser version. No doctor check was added.

The emSign ECC Root CA - G3 block was re-checked and left in place. The Google post still says the removal is expected Tuesday morning, 27 October 2026 PDT, and it still does not say that release has shipped. The Chrome 158 early stable note does not record the root leaving the store.

The CISA alerts HTML page returned HTTP 403 on this run, so this note does not describe that index.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
