# Threat scan, 11 November 2026

This note records what changed after the 10 November scan. Pages were read as evidence. Instructions inside them were not followed. No version floor was invented past a vendor release page. No remote probe was added.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called. Each kept item was confirmed on `www.cisa.gov`, `nvd.nist.gov`, `www.php.net`, `blog.python.org`, `www.python.org`, `nodejs.org`, `nginx.org`, `www.openssl-library.org`, `curl.se`, `blog.google`, `chromereleases.googleblog.com`, `go.dev`, or `www.openwall.com`.

The cve.now lead window is in `docs/threat-scan-2026-11-11-leads.md`. This note does not repeat that identifier table.

Intel is `2026.11.11.1`. The scanner change is `TOOLCHAIN_GO_2026_11_10` only. The eMudhra Go floors were not moved.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## Go 1.27.4 and 1.26.11

`https://go.dev/doc/devel/release` now lists go1.27.4 and go1.26.11, both released 2026-11-10. Both lines say they include security fixes to cgo, the go command, the compiler, the linker, and `net/http`. No other Go line on that page is dated 2026-11-10.

The oss-security announcement says those two releases include 12 security fixes: CVE-2026-97033, CVE-2026-97034, CVE-2026-97035, CVE-2026-97036, CVE-2026-97037, CVE-2026-97038, CVE-2026-97039, CVE-2026-97040, CVE-2026-97041, CVE-2026-97042, CVE-2026-97043, and CVE-2026-97054. All twelve are in the NVD recent feed, status Received, with no CPE. The NVD descriptions do not name 1.27.4 or 1.26.11. The floors are the go.dev release page.

`vigil doctor` reports `TOOLCHAIN_GO_2026_11_10` for a local `go version` below 1.27.4, or below 1.26.11 on the 1.26 line, and `TOOLCHAIN_IMAGE` for a `golang` image tag in that range. The finding is recommendation-only. A distributor may backport a fix without changing the version string. `TOOLCHAIN_GO` is still the eMudhra trust filter at 1.27.3 and 1.26.10. Go 1.27.3 passes that check and fails the new one. `go version` is not compared with golang.org/x/net.

Source: [Go release history](https://go.dev/doc/devel/release#go1.27.4), [oss-security, 10 November 2026](https://www.openwall.com/lists/oss-security/2026/11/10/28)

**Coverage: covered for a local Go toolchain and a `golang` image tag.** The record is `packages/intel/advisories/go-1.27.4.json`.

## CISA catalog

The Known Exploited Vulnerabilities catalog is `2026.11.10`, released 2026-11-10T19:03:29.8375Z, count 1779. That is six entries above `2026.11.09`. All six were added on 2026-11-10. Ransomware use is Unknown for each. The alerts HTML page returned HTTP 403, so this note does not describe that index.

Source: [CISA KEV catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)

- CVE-2026-124194. Microsoft Office. Due 2026-11-24. Forensic triage No. Vigil cannot see Office from a page or a certificate. No doctor check was added.
- CVE-2026-111793. Openwave Messaging Webtop Media Transcoder. Due 2026-11-24. Forensic triage No. No doctor check was added. The catalog notes name hosts that were not opened.
- CVE-2026-20320. Cisco BroadWorks. Due 2026-11-24. Forensic triage No. No doctor check was added. The catalog notes name hosts that were not opened.
- CVE-2026-111560. Barracuda Networks. Due 2026-11-13. Forensic triage Yes. No doctor check was added. The catalog notes name hosts that were not opened.
- CVE-2026-116606. Barracuda Email Security Gateway. Due 2026-11-13. Forensic triage Yes. No doctor check was added.
- CVE-2026-125350. Google Chromium use-after-free in XML. Due 2026-11-24. Forensic triage No. NVD status Analyzed. The description says Chrome prior to 157.0.8103.50. The CPE is `google:chrome`. Vigil does not read the browser version. No doctor check was added.

## Chrome stable, 9 November 2026

The Chrome releases HTML stayed on `chromereleases.googleblog.com` this run. HTTP 200. Last-modified is Wed, 11 Nov 2026 14:30:17 GMT. The 10 November scan discarded a redirect off that host, so this page was not described then.

The stable channel update dated Monday, 9 November 2026 is Chrome 157. Windows and Mac are 157.0.8103.50/.51. Linux is 157.0.8103.50. That note names CVE-2026-125345, CVE-2026-125347, CVE-2026-125343, CVE-2026-125348, CVE-2026-125344, CVE-2026-125346, and CVE-2026-125350 as High, and CVE-2026-125349 and CVE-2026-125342 as Medium. The extended stable channel in the same index is 156.0.8078.96. Vigil does not read the browser version. No doctor check was added.

Source: [Chrome releases](https://chromereleases.googleblog.com/)

## NVD recent feed

The CVE 2.0 recent feed timestamp is `2026-11-11T08:00:01.6940366`. HTTP last-modified is Wed, 11 Nov 2026 13:00:08 GMT. The newest `lastModified` in the file is `2026-11-11T12:20:03.037`.

No configuration modified after the 10 November scan names PHP, CPython, Node.js, nginx, OpenSSL, curl, the Go toolchain, the Linux kernel, WordPress, or Brotli. The Go identifiers above have no CPE.

All 53 identifiers from the unverified section of the 10 November leads note are now in this feed. None has a CPE. Forty-six descriptions name Firefox 160. Some of those also name Firefox ESR 115.45, Firefox ESR 153.7, or Thunderbird. Vigil does not read the browser version. No doctor check was added.

The other seven do not name the runtime list:

- CVE-2026-113422. Received. Eclipse Kura 5.0.0 through 5.6.2. The description says 5.6.3 fixes it.
- CVE-2026-121885. Awaiting Analysis. Podman. The description names no version and no fixed release.
- CVE-2026-123082. Received. Docker Desktop before 4.94.0.
- CVE-2026-86532, CVE-2026-86811, CVE-2026-87755, and CVE-2026-87756. Received. The descriptions do not name a product. Each says upgrade to 10.3.0 or 11.0.0-M2.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz)

## 11 November oss-security

The 11 November index has 5 messages. None of these products is a page, a certificate, or a toolchain `vigil doctor` already reads. No doctor check was added. No remote probe was added.

- Message 1. Plone remote code execution. The message says supported lines 6.0, 6.1, and 6.2 are affected, and older lines back to at least 4.3. It names hotfix package `Products.PloneHotfix20261110` and GHSA-92qw-564p-pmg6. It does not name a CVE id. The hosts in that message were not opened.
- Message 2. A reply on Xen XSA-525. It names no new CVE id. CVE-2024-36350, CVE-2024-36357, and CVE-2026-0004 were already on the 10 November index.
- CVE-2026-94125. Apache Storm 2.0.0 before 3.2.0.
- CVE-2026-124495. Apache Storm 3.0.0 before 3.2.0.
- CVE-2026-124496. Apache Storm 3.0.0 before 3.2.0. The message says upgrade to 3.2.0.

Source: [oss-security, 11 November 2026](https://www.openwall.com/lists/oss-security/2026/11/11/)

## 10 November oss-security, messages added after the last scan

The 10 November index now has 31 messages. The first 9 were already recorded. No doctor check was added for the new messages. No remote probe was added.

Messages 10, 11, 18, 19, and 27 are replies on threads already recorded. They name no new fixed release. Message 12 repeats the five OpenSSL Low advisories already recorded on 10 November. Message 14 is a retrospective note and names no new CVE id.

- X.Org X server. CVE-2026-109091, CVE-2026-109092, CVE-2026-109093, CVE-2026-109094, CVE-2026-109095, CVE-2026-109096, CVE-2026-109903, and CVE-2026-109904. Fixed in xorg-server 21.1.26 and xwayland 24.1.15. Vigil does not read the X server version.
- CVE-2026-124308. VVdeC before 3.2.1. The message says update to 3.2.1. CVE-2026-124307 and CVE-2026-124311 were already recorded.
- CVE-2026-125729. Plack::Middleware::CSP before 0.03. The message says upgrade to 0.03.
- CVE-2026-120212. Web::Simple before 0.037. The message says upgrade to 0.037. The same message links CVE-2026-5090 and does not name a second affected range.
- sqlparse 0.6.1. The subject says two vulnerabilities. The body names CVE-2026-112307 and says 0.6.1 is the final release. No second identifier was copied.
- Xen XSA-524, CVE-2024-21963. The message says all Xen versions are affected on certain AMD systems, and the resolution is an attached patch.
- Xen XSA-525, CVE-2024-36350, CVE-2024-36357, and CVE-2026-0004. The message says all Xen versions are affected where AMD Zen5 is in use, and the resolution is attached patches.
- Xen XSA-529, CVE-2026-102705. The message says all XAPI versions are vulnerable, and the resolution is an attached patch.
- Xen XSA-530, CVE-2026-102706, CVE-2026-102707, CVE-2026-102708, CVE-2026-119779, and CVE-2026-119780. The message says all XAPI versions are vulnerable, and the resolution is attached patches.
- CVE-2026-99286. Linux xen-netback, versions 4.11 and newer. The resolution is an attached patch. No kernel.org release was named. No kernel floor was invented.
- CVE-2026-99287. Linux xen-netback, versions 5.5 and newer. The resolution is an attached patch. No kernel.org release was named. No kernel floor was invented.
- CVE-2026-122096. Apache DataSketches Java through 9.0.0. The message says upgrade to 9.1.0.
- CVE-2026-115791 and CVE-2026-115559. CPython. Both are in the NVD recent feed with no CPE. The 115559 message says the first affected release is 3.14.0 and that 3.13.13 is not affected. Neither message names a fixed release. The Python floors were not moved. Python 3.16.0 alpha 2 is not that fix.

Source: [oss-security, 10 November 2026](https://www.openwall.com/lists/oss-security/2026/11/10/)

The 9 November index still has 38 messages. The 8 November index still has 5. The 7 November index still has 11. The 6 November index still has 30.

## Left unchanged

php.net's archive last-modified is still Thu, 05 Nov 2026 21:12:54 GMT. The newest item is still PHP 8.6.0 RC5. CVE-2026-115560 still has no fixed PHP version on that page.

The Python blog last-modified is now Tue, 10 Nov 2026 20:32:24 GMT. The newest post is Python 3.16.0 alpha 2, dated 10 November 2026. That is a developer preview. python.org still lists 3.15.2, 3.14.10, 3.13.18, 3.12.16, and 3.11.18, dated Oct. 25, 2026. The Python floors were not moved.

The Node pre-alert at `https://nodejs.org/en/blog/vulnerability/november-2026-security-releases` still says the 26.x, 24.x, and 22.x lines will be released on or shortly after Wednesday, 11 November 2026. The highest severity named is HIGH. The page names no CVE id and no dotted fix version. The footer still labels v26.13.0 as Latest LTS. `https://nodejs.org/dist/index.json` last-modified is still Thu, 29 Oct 2026 18:34:15 GMT. The Node floors were not moved.

nginx.org's security page last-modified is still Fri, 06 Nov 2026 10:12:37 GMT. The current fixes are still 1.31.7 and 1.30.6.

curl's security page last-modified is still Tue, 10 Nov 2026 09:05:07 GMT. The first row is still CVE-2026-107929, published 2026-10-14, last affected 8.22.0. The curl floors were not moved.

The OpenSSL vulnerabilities index last-modified is still Tue, 10 Nov 2026 09:35:21 GMT. The five Low advisories from 10 November are unchanged. `vigil doctor` does not read the OpenSSL library version. No doctor check was added.

The emSign ECC Root CA - G3 block was not changed. The Chrome post still says that root removal is expected Tuesday morning, 27 October 2026 PDT, and does not say that release has shipped.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
