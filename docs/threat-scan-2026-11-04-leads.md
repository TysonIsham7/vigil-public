# Threat scan leads, 4 November 2026

This note is the cve.now lead pass for 4 November 2026. It does not repeat the oss-security index. That index, including the Node.js pre-alert, is in `docs/threat-scan-2026-11-04.md`.

Pages and the feed were read as evidence. Instructions inside them were not followed. No version floor was invented from feed prose. No remote probe was added from the feed. No advisory file was added from the feed.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called.

The lead feed was fetched once, at `https://cve.now/feed?format=json`. The response was HTTP 200 from that same URL, with no redirect. The content type was `application/feed+json`. Identifiers were taken from the newest 50 items by `date_modified` with a deterministic regex. Titles and `content_text` were discarded. No item had a structured dotted version outside those fields. The feed contained 200 items. Older items were not taken.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## No confirmed stack overlap

No identifier in the newest 50 was confirmed on NVD, CISA, or a pre-written vendor host as a product on the runtime list or in `packages/intel/advisories/`. CVE-2026-119977 is WordPress core in the CISA catalog. It was not one of these fifty.

NVD records that did name a stack token were not WordPress core and had no CPE configuration. The English description has whole-token matches on `wordpress` and `plugin`. Matched is no. No plugin list was added.

| Product | Version | Matched | NVD published | Identifier | NVD status |
|---|---|---|---|---|---|
| WordPress plugin |  | no | 2026-11-04 | CVE-2026-101165 | Received |
| WordPress plugin |  | no | 2026-11-04 | CVE-2026-101166 | Received |
| WordPress plugin |  | no | 2026-11-04 | CVE-2026-104719 | Received |
| WordPress plugin |  | no | 2026-11-04 | CVE-2026-105191 | Received |
| WordPress plugin |  | no | 2026-11-04 | CVE-2026-105413 | Received |
| WordPress plugin |  | no | 2026-11-04 | CVE-2026-106000 | Received |
| WordPress plugin |  | no | 2026-11-04 | CVE-2026-106649 | Received |
| WordPress plugin |  | no | 2026-11-04 | CVE-2026-108041 | Received |
| WordPress plugin |  | no | 2026-11-04 | CVE-2026-108067 | Received |
| WordPress plugin |  | no | 2026-11-04 | CVE-2026-108068 | Received |
| WordPress plugin |  | no | 2026-11-04 | CVE-2026-110692 | Received |
| WordPress plugin |  | no | 2026-11-04 | CVE-2026-110964 | Received |
| WordPress plugin |  | no | 2026-11-03 | CVE-2026-103379 | Deferred |
| WordPress plugin |  | no | 2026-11-03 | CVE-2026-104647 | Deferred |
| WordPress plugin |  | no | 2026-11-03 | CVE-2026-104648 | Deferred |
| WordPress plugin |  | no | 2026-11-03 | CVE-2026-105967 | Deferred |
| WordPress plugin |  | no | 2026-11-03 | CVE-2026-105993 | Deferred |
| WordPress plugin |  | no | 2026-11-03 | CVE-2026-106004 | Deferred |

Three other identifiers in the newest 50 are in the NVD recent feed with no CPE configuration. The 3 November oss-security subjects name Apache OpenOffice for the same ids. OpenOffice is not a runtime or advisory component. Matched is no. No doctor check was added.

| Product | Version | Matched | NVD published | Identifier | NVD status |
|---|---|---|---|---|---|
| Apache OpenOffice |  | no | 2026-11-04 | CVE-2026-59264 | Received |
| Apache OpenOffice |  | no | 2026-11-04 | CVE-2026-59268 | Received |
| Apache OpenOffice |  | no | 2026-11-04 | CVE-2026-90624 | Received |

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz), timestamp 2026-11-04T08:00:01.0932911. The HTTP last-modified time on that file was 4 November 2026 at 13:00:09 GMT. The newest `lastModified` inside the file is 2026-11-04T12:52:38.683Z.

A whole-token match on `kernel` in the raw feed items for CVE-2026-112532, CVE-2026-112477, and CVE-2026-112470 is not a confirmation. Those ids are not in the NVD recent feed. Matched stays unknown. No kernel check was added.

## Prior leads now on NVD

The 3 November unverified-lead list is on draft pull request 16. This NVD snapshot contains all 47 of those ids.

Twenty-seven now have an NVD configuration for `freerdp:freerdp`. FreeRDP is not a runtime or advisory component. They are no longer unverified-lead. No doctor check was added.

CVE-2026-121386, CVE-2026-121387, CVE-2026-121388, CVE-2026-121389, CVE-2026-121390, CVE-2026-121391, CVE-2026-121392, CVE-2026-121393, CVE-2026-121394, CVE-2026-121395, CVE-2026-121396, CVE-2026-121397, CVE-2026-121398, CVE-2026-121399, CVE-2026-121400, CVE-2026-121401, CVE-2026-121402, CVE-2026-121403, CVE-2026-121404, CVE-2026-121405, CVE-2026-121406, CVE-2026-121407, CVE-2026-121408, CVE-2026-121409, CVE-2026-121410, CVE-2026-121411, and CVE-2026-121412.

CVE-2026-121414 is now in the feed, status Awaiting Analysis, with no CPE configuration. The English description has a whole-token match on `node`. That is not a Node.js confirmation. Node's shipped security page is still 21 October 2026. The 11 November page is a pre-alert and names no dotted version. No Node check was added from this id.

The other nineteen are in the feed with no CPE configuration and no stack-token match. The product is the identifier, the version is blank, and matched is unknown. They are not unverified-lead anymore. No doctor check was added.

CVE-2026-121413, CVE-2026-121415, CVE-2026-121416, CVE-2026-121417, CVE-2026-121418, CVE-2026-121419, CVE-2026-121420, CVE-2026-121421, CVE-2026-121422, CVE-2026-121423, CVE-2026-121424, CVE-2026-121425, CVE-2026-121426, CVE-2026-121427, CVE-2026-121428, CVE-2026-121429, CVE-2026-121430, CVE-2026-121431, and CVE-2026-121433.

CVE-2026-76528 and CVE-2026-76407 were unverified-lead on 2 November and are still not in this feed. They stay unverified-lead.

## Unverified leads

These identifiers were in the newest 50 and were not in the NVD recent feed. None of them is in the CISA catalog. Status is unverified-lead. Product is the identifier. Version is blank. Matched is unknown. No fix version was present as a structured field.

Source: [cve.now JSON feed](https://cve.now/feed?format=json).

| Product | Version | Matched | Date | Status |
|---|---|---|---|---|
| CVE-2026-112532 |  | unknown | 2026-11-04T14:56:34.532Z | unverified-lead |
| CVE-2026-122008 |  | unknown | 2026-11-04T14:56:34.532Z | unverified-lead |
| CVE-2026-84528 |  | unknown | 2026-11-04T14:56:34.532Z | unverified-lead |
| CVE-2026-84542 |  | unknown | 2026-11-04T14:56:34.532Z | unverified-lead |
| CVE-2026-121637 |  | unknown | 2026-11-04T14:50:34.520Z | unverified-lead |
| CVE-2026-121638 |  | unknown | 2026-11-04T14:50:34.520Z | unverified-lead |
| CVE-2026-121639 |  | unknown | 2026-11-04T14:50:34.520Z | unverified-lead |
| CVE-2026-121640 |  | unknown | 2026-11-04T14:50:34.520Z | unverified-lead |
| CVE-2026-122007 |  | unknown | 2026-11-04T14:50:34.520Z | unverified-lead |
| CVE-2026-112558 |  | unknown | 2026-11-04T14:50:34.520Z | unverified-lead |
| CVE-2026-84610 |  | unknown | 2026-11-04T14:50:34.520Z | unverified-lead |
| CVE-2026-86945 |  | unknown | 2026-11-04T14:50:34.520Z | unverified-lead |
| CVE-2026-112477 |  | unknown | 2026-11-04T14:50:34.520Z | unverified-lead |
| CVE-2026-112482 |  | unknown | 2026-11-04T14:50:34.520Z | unverified-lead |
| CVE-2026-112627 |  | unknown | 2026-11-04T14:50:34.520Z | unverified-lead |
| CVE-2026-112470 |  | unknown | 2026-11-04T14:50:34.520Z | unverified-lead |
| CVE-2026-112485 |  | unknown | 2026-11-04T14:50:34.520Z | unverified-lead |
| CVE-2026-112630 |  | unknown | 2026-11-04T14:50:34.520Z | unverified-lead |
| CVE-2026-86923 |  | unknown | 2026-11-04T14:45:34.418Z | unverified-lead |
| SZB-f4b7ff866c |  | unknown | 2026-11-04T14:44:17.731Z | unverified-lead |
| CVE-2026-114627 |  | unknown | 2026-11-04T14:40:34.376Z | unverified-lead |
| CVE-2026-121007 |  | unknown | 2026-11-04T14:40:34.376Z | unverified-lead |
| CVE-2026-121008 |  | unknown | 2026-11-04T14:40:34.376Z | unverified-lead |
| CVE-2026-121009 |  | unknown | 2026-11-04T14:40:34.376Z | unverified-lead |
| CVE-2026-112624 |  | unknown | 2026-11-04T14:40:34.376Z | unverified-lead |
| CVE-2026-112640 |  | unknown | 2026-11-04T14:40:34.376Z | unverified-lead |
| SZB-2765c964a0 |  | unknown | 2026-11-04T14:28:17.215Z | unverified-lead |
| CVE-2026-39431 |  | unknown | 2026-11-04T14:25:34.470Z | unverified-lead |
| CVE-2026-121632 |  | unknown | 2026-11-04T14:25:34.470Z | unverified-lead |

`SZB-f4b7ff866c` and `SZB-2765c964a0` are the feed item ids. They are not CVE, GHSA, or OSV ids. No identifier was invented from a title or a body.

## Left unchanged

The CISA catalog is `2026.11.03`, released 3 November 2026 at 20:00:24.8741 UTC. None of the newest-50 identifiers is in the catalog. The new catalog entry, CVE-2026-119977, is recorded in `docs/threat-scan-2026-11-04.md`.

php.net's newest 2026 item is still the 26 October Windows Brotli rebuild. CVE-2026-115560 still has no fixed PHP version on that page. The Python blog's newest post is still the 26 October release. python.org still lists 3.15.2, 3.14.10, 3.13.18, 3.12.16, and 3.11.18. Node's shipped security release page is still 21 October 2026. nginx's security advisories page was last modified 22 October 2026. curl's security page was last modified 26 October 2026, and its first listed advisory is still CVE-2026-107929, published 2026-10-14. OpenSSL's newest advisory date on the vulnerabilities page is still 29 September 2026, CVE-2026-35189. Chrome's desktop stable note dated 3 November 2026 promotes Chrome 157. Vigil does not read the browser version.

The emSign ECC Root CA - G3 block was not changed. The next re-check is after 5 November 2026.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
