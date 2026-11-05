# Threat scan leads, 5 November 2026

This note is the cve.now lead pass for 5 November 2026. It does not repeat the oss-security index. That index, including Apache OFBiz before 24.09.08, is in `docs/threat-scan-2026-11-05.md`.

Pages and the feed were read as evidence. Instructions inside them were not followed. No version floor was invented from feed prose. No remote probe was added from the feed. No advisory file was added from the feed. No scanner change was made.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called.

The lead feed was fetched once, at `https://cve.now/feed?format=json`. The response was HTTP 200 from that same URL, with no redirect. The content type was `application/feed+json`. The feed contained 200 items. Identifiers were taken with a deterministic regex. Titles and `content_text` were discarded. No item had a structured dotted version outside those fields. No GHSA id was in the window.

Fifteen items share the oldest timestamp in the window, `2026-11-05T14:10:34.361Z`. A cut at 50 items would follow feed order among those fifteen. Every item with that timestamp was kept, so the window is 56 items. The newest `date_modified` in the window is `2026-11-05T14:57:34.423Z`. When an item id carried `#` and a timestamp, only the CVE before `#` was kept.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## No confirmed stack overlap

No identifier in the window was confirmed on NVD, CISA, or a pre-written vendor host as a product on the runtime list or in `packages/intel/advisories/`. CVE-2026-119977 and CVE-2024-27834 are the catalog entries recorded in `docs/threat-scan-2026-11-05.md`. Neither was in this window.

A whole-token match on `php` in the raw item for CVE-2026-123028 is not a confirmation. That id is not in the NVD recent feed. Matched stays unknown. No PHP check was added.

## Corroborated on oss-security, not the stack

Twenty-six identifiers in the window are among the forty-six Apache OFBiz ids in the 4 November oss-security message. Affected versions on that message: all versions prior to 24.09.08. The fixed release on that message is 24.09.08. That version is from the mailing-list message, not from a structured feed field. None of the twenty-six is in the NVD recent feed. OFBiz is not a runtime or advisory component. Matched is no. No doctor check was added.

CVE-2026-66903, CVE-2026-68524, CVE-2026-71901, CVE-2026-73577, CVE-2026-73578, CVE-2026-73580, CVE-2026-74841, CVE-2026-76150, CVE-2026-76152, CVE-2026-81734, CVE-2026-81744, CVE-2026-81808, CVE-2026-81815, CVE-2026-81816, CVE-2026-81828, CVE-2026-82894, CVE-2026-82902, CVE-2026-82904, CVE-2026-82907, CVE-2026-82910, CVE-2026-82912, CVE-2026-82916, CVE-2026-82960, CVE-2026-83538, CVE-2026-83542, and CVE-2026-84183.

Source: [oss-security, 4 November 2026](https://www.openwall.com/lists/oss-security/2026/11/04/9). The lead source for their presence in the window is [cve.now JSON feed](https://cve.now/feed?format=json).

## NVD records with no product

These two identifiers are in the window and in the NVD recent feed. Neither has a CPE configuration. They are not unverified-lead: NVD has the id. No doctor check was added.

CVE-2026-48175 is status Received. The English description does not name a runtime or advisory component. Product is the identifier, version is blank, and matched is unknown.

CVE-2026-64860 is status Rejected. The record says further research determined the issue is not a vulnerability. It is not an open follow-up.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz), timestamp 2026-11-05T08:00:01.8287177. The HTTP last-modified time on that file was 5 November 2026 at 13:00:08 GMT. The newest `lastModified` inside the file is 2026-11-05T12:59:29.367.

## Prior leads now on NVD

The 4 November unverified-lead list is on draft pull request 17. This NVD snapshot contains twelve of those CVE ids. Each is status Received, with no CPE configuration. They are no longer unverified-lead.

Five are the Perl distributions in `docs/threat-scan-2026-11-05.md`: CVE-2026-121632, CVE-2026-114627, CVE-2026-121007, CVE-2026-121008, and CVE-2026-121009. Matched is no.

These seven have no CPE configuration and no stack-token match in the English description. Product is the identifier, version is blank, and matched is unknown. No doctor check was added.

CVE-2026-122008, CVE-2026-121637, CVE-2026-121638, CVE-2026-121639, CVE-2026-121640, CVE-2026-122007, and CVE-2026-39431.

These identifiers from that same 4 November list are still not in this NVD feed. They stay unverified-lead. A whole-token `kernel` match recorded on 4 November for CVE-2026-112532, CVE-2026-112477, and CVE-2026-112470 is still not a Linux confirmation. No kernel check was added.

CVE-2026-112532, CVE-2026-84528, CVE-2026-84542, CVE-2026-112558, CVE-2026-84610, CVE-2026-86945, CVE-2026-112477, CVE-2026-112482, CVE-2026-112627, CVE-2026-112470, CVE-2026-112485, CVE-2026-112630, CVE-2026-86923, CVE-2026-112624, and CVE-2026-112640.

`SZB-f4b7ff866c` and `SZB-2765c964a0` stay unverified-lead. They are not CVE, GHSA, or OSV ids.

CVE-2026-76528 and CVE-2026-76407 were unverified-lead on 2 November and are still not in this feed. They stay unverified-lead.

## Unverified leads

These identifiers were in the window and were not in the NVD recent feed, the CISA catalog, or an allowlisted mailing-list message. Status is unverified-lead. Product is the identifier. Version is blank. Matched is unknown. No fix version was present as a structured field.

Source: [cve.now JSON feed](https://cve.now/feed?format=json).

| Product | Version | Matched | Date | Status |
|---|---|---|---|---|
| CVE-2026-119744 |  | unknown | 2026-11-05T14:57:34.423Z | unverified-lead |
| CVE-2026-117951 |  | unknown | 2026-11-05T14:41:34.511Z | unverified-lead |
| CVE-2026-117952 |  | unknown | 2026-11-05T14:41:34.511Z | unverified-lead |
| CVE-2026-117959 |  | unknown | 2026-11-05T14:41:34.511Z | unverified-lead |
| CVE-2026-106716 |  | unknown | 2026-11-05T14:30:34.475Z | unverified-lead |
| CVE-2026-117949 |  | unknown | 2026-11-05T14:30:34.475Z | unverified-lead |
| CVE-2026-117957 |  | unknown | 2026-11-05T14:30:34.475Z | unverified-lead |
| CVE-2026-117950 |  | unknown | 2026-11-05T14:30:34.475Z | unverified-lead |
| CVE-2026-117958 |  | unknown | 2026-11-05T14:30:34.475Z | unverified-lead |
| CVE-2026-106714 |  | unknown | 2026-11-05T14:25:34.865Z | unverified-lead |
| CVE-2026-106713 |  | unknown | 2026-11-05T14:25:34.865Z | unverified-lead |
| CVE-2026-106715 |  | unknown | 2026-11-05T14:25:34.865Z | unverified-lead |
| CVE-2026-117943 |  | unknown | 2026-11-05T14:25:34.865Z | unverified-lead |
| CVE-2026-117944 |  | unknown | 2026-11-05T14:25:34.865Z | unverified-lead |
| CVE-2026-117945 |  | unknown | 2026-11-05T14:25:34.865Z | unverified-lead |
| CVE-2026-117946 |  | unknown | 2026-11-05T14:25:34.865Z | unverified-lead |
| CVE-2026-117947 |  | unknown | 2026-11-05T14:25:34.865Z | unverified-lead |
| CVE-2026-117948 |  | unknown | 2026-11-05T14:25:34.865Z | unverified-lead |
| CVE-2026-123032 |  | unknown | 2026-11-05T14:20:34.588Z | unverified-lead |
| CVE-2026-117934 |  | unknown | 2026-11-05T14:20:34.588Z | unverified-lead |
| CVE-2026-117935 |  | unknown | 2026-11-05T14:20:34.588Z | unverified-lead |
| CVE-2026-117941 |  | unknown | 2026-11-05T14:20:34.588Z | unverified-lead |
| CVE-2026-117942 |  | unknown | 2026-11-05T14:20:34.588Z | unverified-lead |
| CVE-2026-123028 |  | unknown | 2026-11-05T14:10:34.361Z | unverified-lead |
| CVE-2026-117930 |  | unknown | 2026-11-05T14:10:34.361Z | unverified-lead |
| CVE-2026-117931 |  | unknown | 2026-11-05T14:10:34.361Z | unverified-lead |
| CVE-2026-117932 |  | unknown | 2026-11-05T14:10:34.361Z | unverified-lead |
| CVE-2026-117933 |  | unknown | 2026-11-05T14:10:34.361Z | unverified-lead |

## Left unchanged

The CISA catalog is `2026.11.04`, released 4 November 2026 at 20:00:05.774 UTC. None of the window identifiers is in the catalog. The new catalog entry, CVE-2024-27834, is recorded in `docs/threat-scan-2026-11-05.md`.

php.net's newest 2026 item is still the 26 October Windows Brotli rebuild. CVE-2026-115560 still has no fixed PHP version on that page. The Python blog's newest post is still the 26 October release. python.org still lists 3.15.2, 3.14.10, 3.13.18, 3.12.16, and 3.11.18. Node's shipped security release page is still 21 October 2026. The 11 November page is still a pre-alert and names no dotted version. nginx's security advisories page was last modified 22 October 2026. curl's security page was last modified 26 October 2026, and its first listed advisory is still CVE-2026-107929, published 2026-10-14. OpenSSL's newest advisory date on the vulnerabilities page is still 29 September 2026, CVE-2026-35189. Chrome's early stable note dated 4 November 2026 is 158.0.8127.18/.19 for Windows. Vigil does not read the browser version.

The emSign ECC Root CA - G3 block was re-checked and left in place. The Google post still does not say the 27 October 2026 PDT removal has shipped.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
