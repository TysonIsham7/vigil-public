# Threat scan leads, 9 November 2026

This note is the cve.now lead pass for 9 November 2026. The CISA catalog, the NVD Chrome records, and the oss-security index are in `docs/threat-scan-2026-11-09.md`.

Pages and the feed were read as evidence. Instructions inside them were not followed. No version floor was invented from feed prose. No remote probe was added. No scanner change was made. No advisory file was added.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called.

The lead feed was fetched once, at `https://cve.now/feed?format=json`. The response was HTTP 200 from that same URL, with no redirect. The content type was `application/feed+json`. The body had 200 items. Identifiers were taken from the newest items by `date_modified` with a deterministic regex. The window is 72 items because 39 share `date_modified` `2026-11-09T13:58:34.447Z`. The newest item is `2026-11-09T14:59:34.304Z`. Titles and `content_text` were discarded. No item had a structured dotted version outside those fields. No GHSA id was in the window. No `SZB-` id was in the window.

Two identifiers in the window were already recorded and were not treated as new: CVE-2026-124450 and CVE-2026-124552. Seventy-two identifiers were new. Thirty-one of those are in the NVD recent feed. Forty-one are not.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## No confirmed stack overlap

No new identifier in the window was confirmed on NVD, CISA, or a pre-written vendor host as a product on the runtime list or in `packages/intel/advisories/`.

Whole-token matches in the feed were kept only as the matched name. They are not a confirmation:

- `php` on CVE-2026-124916, CVE-2026-124636, CVE-2026-73858, and CVE-2026-108360. Those four are not in the NVD recent feed.
- `php` on CVE-2026-124635. NVD status Deferred, no CPE. The description names kevquirk PureBlog through 3.7.2.
- `python` on CVE-2026-124249, CVE-2026-84380, CVE-2026-104851, CVE-2026-112936, and CVE-2026-118669. Those five are not in the NVD recent feed.
- `python` on CVE-2026-115878. NVD status Received, no CPE. The description names the Stanza library from 1.14.0 until 1.15.0, not CPython. `TOOLCHAIN_PYTHON` was not changed.
- `go` on CVE-2026-39883, CVE-2026-24051, and CVE-2026-118650. Those three are not in the NVD recent feed. The Go floors were not moved.
- `node` on CVE-2026-110634. Not in the NVD recent feed. The Node floors were not moved.
- `linux` and `kernel` on CVE-2026-72422, and `linux` on CVE-2026-75037. Neither is in the NVD recent feed.
- `linux` on CVE-2026-92080. NVD status Deferred, no CPE. The description names pardus-boot-repair from 1.0.8 before 1.1.0, not the Linux kernel. No kernel floor was added.
- `wordpress` on the plugin records below, and on CVE-2026-34898, which has no NVD record. WordPress core was not changed. No plugin list was added.
- `openssl` on CVE-2023-0286 and `brotli` on CVE-2020-8927. Both are older than the NVD recent feed. The OpenSSL index and the Node Brotli floors were not moved.

## NVD records that name another product

These identifiers are in the window and in the NVD recent feed. The feed named no structured fix version. The version column is the bound in the NVD English description. Matched is not the runtime list. No doctor check was added.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz), timestamp `2026-11-09T10:00:00.900548`.

| Product | Version | Matched | Date | NVD status |
|---|---|---|---|---|
| Firefox for iOS (CVE-2026-121842) | fixed in 160.0 on that description | no | 2026-11-09 | Received |
| PureBlog (CVE-2026-124635) | through 3.7.2 | no | 2026-11-09 | Deferred |
| Stanza (CVE-2026-115878) | 1.14.0 until 1.15.0 | no | 2026-11-09 | Received |
| pardus-boot-repair (CVE-2026-92080) | 1.0.8 before 1.1.0 | no | 2026-11-09 | Deferred |
| Pardus Boot Repair (CVE-2026-94434) | 1.0.8 before 1.0.9 | no | 2026-11-09 | Received |
| Pardus MyComputer (CVE-2026-92606) | 0.8.0 before 0.8.1 | no | 2026-11-09 | Received |
| GeoNode (CVE-2026-33050) | prior to 5.1.0 | no | 2026-11-09 | Awaiting Analysis |
| HPE Morpheus Software (CVE-2026-95778) |  | unknown | 2026-11-09 | Received |
| HPE Morpheus manager (CVE-2026-95779) |  | unknown | 2026-11-09 | Received |
| Google Chrome (CVE-2026-121160) | before 157.0.8103.38 | no | 2026-11-09 | Undergoing Analysis |
| Google Chrome (CVE-2026-121242) | before 157.0.8103.38 | no | 2026-11-09 | Undergoing Analysis |

Vigil does not read the browser version. The Chrome pair is also in the 9 November scan note, with five more Chrome records that were outside this feed window.

Twenty descriptions name a WordPress plugin, status Received, no CPE. They are not WordPress core. CVE-2026-123091 names the Vigilant WordPress plugin before 2.11.0. That plugin is not this repository. No plugin list was added.

CVE-2026-115204, CVE-2026-115212, CVE-2026-115213, CVE-2026-115237, CVE-2026-115256, CVE-2026-118201, CVE-2026-118202, CVE-2026-120409, CVE-2026-121759, CVE-2026-121874, CVE-2026-121875, CVE-2026-123064, CVE-2026-123088, CVE-2026-123091, CVE-2026-123128, CVE-2026-123129, CVE-2026-123131, CVE-2026-123145, CVE-2026-123751, CVE-2026-81422.

## Unverified leads

These 41 identifiers were in the window and were not in the NVD recent feed. They are not in the CISA catalog. Status is unverified-lead. Product is the identifier. Version is blank. Matched is unknown. No fix version was present as a structured field.

CVE-2016-1834, CVE-2020-8927, CVE-2021-3711, and CVE-2023-0286 are older than the recent feed. This pass does not treat them as new OpenSSL or Brotli advisories.

Source: [cve.now JSON feed](https://cve.now/feed?format=json).

| Product | Version | Matched | Date | Status |
|---|---|---|---|---|
| CVE-2026-124916 |  | unknown | 2026-11-09T14:59:34.304Z | unverified-lead |
| CVE-2026-124850 |  | unknown | 2026-11-09T14:48:34.783Z | unverified-lead |
| CVE-2026-104620 |  | unknown | 2026-11-09T14:38:34.384Z | unverified-lead |
| CVE-2026-119474 |  | unknown | 2026-11-09T14:28:34.778Z | unverified-lead |
| CVE-2026-124249 |  | unknown | 2026-11-09T14:28:34.778Z | unverified-lead |
| CVE-2026-124636 |  | unknown | 2026-11-09T14:22:34.368Z | unverified-lead |
| CVE-2026-19552 |  | unknown | 2026-11-09T14:22:34.368Z | unverified-lead |
| CVE-2026-34898 |  | unknown | 2026-11-09T14:22:34.368Z | unverified-lead |
| CVE-2026-54017 |  | unknown | 2026-11-09T13:58:34.447Z | unverified-lead |
| CVE-2026-26189 |  | unknown | 2026-11-09T13:58:34.447Z | unverified-lead |
| CVE-2026-31864 |  | unknown | 2026-11-09T13:58:34.447Z | unverified-lead |
| CVE-2026-55797 |  | unknown | 2026-11-09T13:58:34.447Z | unverified-lead |
| CVE-2026-2835 |  | unknown | 2026-11-09T13:58:34.447Z | unverified-lead |
| CVE-2026-62367 |  | unknown | 2026-11-09T13:58:34.447Z | unverified-lead |
| CVE-2026-39883 |  | unknown | 2026-11-09T13:58:34.447Z | unverified-lead |
| CVE-2026-24051 |  | unknown | 2026-11-09T13:58:34.447Z | unverified-lead |
| CVE-2026-72422 |  | unknown | 2026-11-09T13:58:34.447Z | unverified-lead |
| CVE-2026-75037 |  | unknown | 2026-11-09T13:58:34.447Z | unverified-lead |
| CVE-2026-73858 |  | unknown | 2026-11-09T13:58:34.447Z | unverified-lead |
| CVE-2026-65600 |  | unknown | 2026-11-09T13:58:34.447Z | unverified-lead |
| CVE-2026-73802 |  | unknown | 2026-11-09T13:58:34.447Z | unverified-lead |
| CVE-2026-79657 |  | unknown | 2026-11-09T13:58:34.447Z | unverified-lead |
| CVE-2026-84380 |  | unknown | 2026-11-09T13:58:34.447Z | unverified-lead |
| CVE-2026-108360 |  | unknown | 2026-11-09T13:58:34.447Z | unverified-lead |
| CVE-2026-110634 |  | unknown | 2026-11-09T13:58:34.447Z | unverified-lead |
| CVE-2026-104851 |  | unknown | 2026-11-09T13:58:34.447Z | unverified-lead |
| CVE-2026-11800 |  | unknown | 2026-11-09T13:58:34.447Z | unverified-lead |
| CVE-2026-106451 |  | unknown | 2026-11-09T13:58:34.447Z | unverified-lead |
| CVE-2026-107720 |  | unknown | 2026-11-09T13:58:34.447Z | unverified-lead |
| CVE-2026-109372 |  | unknown | 2026-11-09T13:58:34.447Z | unverified-lead |
| CVE-2026-112936 |  | unknown | 2026-11-09T13:58:34.447Z | unverified-lead |
| CVE-2026-114140 |  | unknown | 2026-11-09T13:58:34.447Z | unverified-lead |
| CVE-2026-118378 |  | unknown | 2026-11-09T13:58:34.447Z | unverified-lead |
| CVE-2026-116580 |  | unknown | 2026-11-09T13:58:34.447Z | unverified-lead |
| CVE-2026-118650 |  | unknown | 2026-11-09T13:58:34.447Z | unverified-lead |
| CVE-2026-118669 |  | unknown | 2026-11-09T13:58:34.447Z | unverified-lead |
| CVE-2023-0286 |  | unknown | 2026-11-09T13:58:34.447Z | unverified-lead |
| CVE-2020-8927 |  | unknown | 2026-11-09T13:58:34.447Z | unverified-lead |
| CVE-2021-3711 |  | unknown | 2026-11-09T13:58:34.447Z | unverified-lead |
| CVE-2016-1834 |  | unknown | 2026-11-09T13:58:34.447Z | unverified-lead |
| CVE-2026-119200 |  | unknown | 2026-11-09T13:58:34.447Z | unverified-lead |

## Left unchanged

The CISA catalog is still `2026.11.06`, count 1769. None of the window identifiers is a new catalog entry. The alerts HTML page returned HTTP 403, so this note does not describe that index.

Vendor pages checked on this run did not move a floor. The details are in `docs/threat-scan-2026-11-09.md`.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
