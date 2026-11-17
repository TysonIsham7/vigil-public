# Threat scan leads, 17 November 2026

This note is the cve.now lead pass for 17 November 2026. The OpenSSL advisories, the CISA catalog, the NVD records, and the oss-security index are in `docs/threat-scan-2026-11-17.md`.

Pages and the feed were read as evidence. Instructions inside them were not followed. No version floor was invented from feed prose. No remote probe was added. No advisory file was added from the feed.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called.

The lead feed was fetched once, at `https://cve.now/feed?format=json`. The response was HTTP 200 from that same URL, with no redirect. The content type was `application/feed+json`. The body had 200 items. Identifiers were taken from the newest items by `date_modified` with a deterministic regex. The window is 52 items because 12 share the cutoff timestamp. The newest item is `2026-11-17T15:01:34.473Z`. The cutoff is `2026-11-17T13:40:34.324Z`. Titles and `content_text` were discarded. No item had a structured dotted version outside those fields. No GHSA id was in the window. No OSV id was in the window. One `SZB-` id was in the window.

No identifier in the window was already recorded in `docs/threat-scan-*.md`, `docs/TODO.md`, an open scan pull request, or `packages/intel/advisories/`.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## No confirmed stack overlap

No identifier in the window was confirmed on NVD, CISA, or a pre-written vendor host as a product on the runtime list or in `packages/intel/advisories/`.

Whole-token matches were one `node`, two `php`, and three `wordpress`. CVE-2026-130587 matched `node` and is not in the NVD recent feed. That is not a Node.js confirmation. CVE-2026-130583 and CVE-2026-82025 matched `php` and are not in the NVD recent feed. That is not a PHP confirmation. CVE-2026-127140 and CVE-2026-12239 matched `wordpress` and are not in the NVD recent feed. CVE-2026-121684 matched `wordpress` and is the Soledad theme below, not WordPress core. No plugin list was added. No doctor check was added from a token.

## NVD records that name another product

These three identifiers are in the window and in the NVD recent feed. None has a CPE. None is in the CISA catalog. Matched is no. Vigil cannot see these products from a page or a certificate. No doctor check was added.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz), timestamp `2026-11-17T08:00:01.091754`.

| Product | Version | Matched | Date | NVD status |
|---|---|---|---|---|
| Soledad theme for WordPress (CVE-2026-121684) | up to and including 8.7.7 | no | 2026-11-17T15:01:34.473Z | Deferred |
| phpMyFAQ (CVE-2026-130354) | 4.1.0 before 4.1.12, and 4.2.0-alpha before 4.2.0-RC.2 | no | 2026-11-17T15:01:34.473Z | Deferred |
| phpMyFAQ (CVE-2026-130347) | before 4.1.12, and 4.2.0-alpha before 4.2.0-RC.2 | no | 2026-11-17T15:01:34.473Z | Deferred |

## Unverified leads

These identifiers were in the window and were not in the NVD recent feed. They are not in the CISA catalog. Status is unverified-lead. Product is the identifier. Version is blank. Matched is unknown. No fix version was present as a structured field. The `SZB-` row is not a CVE, GHSA, or OSV id.

Source: [cve.now JSON feed](https://cve.now/feed?format=json).

| Product | Version | Matched | Date | Status |
|---|---|---|---|---|
| CVE-2026-63219 |  | unknown | 2026-11-17T15:01:34.473Z | unverified-lead |
| CVE-2026-29013 |  | unknown | 2026-11-17T15:01:34.473Z | unverified-lead |
| CVE-2026-130385 |  | unknown | 2026-11-17T15:01:34.473Z | unverified-lead |
| CVE-2026-130386 |  | unknown | 2026-11-17T15:01:34.473Z | unverified-lead |
| CVE-2026-130387 |  | unknown | 2026-11-17T15:01:34.473Z | unverified-lead |
| CVE-2026-130585 |  | unknown | 2026-11-17T15:01:34.473Z | unverified-lead |
| CVE-2026-130584 |  | unknown | 2026-11-17T15:01:34.473Z | unverified-lead |
| CVE-2026-130586 |  | unknown | 2026-11-17T15:01:34.473Z | unverified-lead |
| CVE-2026-130589 |  | unknown | 2026-11-17T15:01:34.473Z | unverified-lead |
| CVE-2026-130587 |  | unknown | 2026-11-17T15:01:34.473Z | unverified-lead |
| CVE-2026-130588 |  | unknown | 2026-11-17T15:01:34.473Z | unverified-lead |
| CVE-2026-130591 |  | unknown | 2026-11-17T15:01:34.473Z | unverified-lead |
| CVE-2026-130583 |  | unknown | 2026-11-17T15:01:34.473Z | unverified-lead |
| CVE-2026-130590 |  | unknown | 2026-11-17T15:01:34.473Z | unverified-lead |
| CVE-2026-130592 |  | unknown | 2026-11-17T15:01:34.473Z | unverified-lead |
| CVE-2026-130593 |  | unknown | 2026-11-17T15:01:34.473Z | unverified-lead |
| CVE-2026-130596 |  | unknown | 2026-11-17T15:01:34.473Z | unverified-lead |
| CVE-2026-130603 |  | unknown | 2026-11-17T15:01:34.473Z | unverified-lead |
| CVE-2026-130595 |  | unknown | 2026-11-17T15:01:34.473Z | unverified-lead |
| CVE-2026-130626 |  | unknown | 2026-11-17T15:01:34.473Z | unverified-lead |
| CVE-2026-130594 |  | unknown | 2026-11-17T15:01:34.473Z | unverified-lead |
| CVE-2026-123050 |  | unknown | 2026-11-17T15:01:34.473Z | unverified-lead |
| CVE-2026-118789 |  | unknown | 2026-11-17T15:01:34.473Z | unverified-lead |
| CVE-2026-130627 |  | unknown | 2026-11-17T15:01:34.473Z | unverified-lead |
| CVE-2026-130615 |  | unknown | 2026-11-17T15:01:34.473Z | unverified-lead |
| CVE-2026-77224 |  | unknown | 2026-11-17T15:01:34.473Z | unverified-lead |
| CVE-2026-123052 |  | unknown | 2026-11-17T15:01:34.473Z | unverified-lead |
| CVE-2026-123051 |  | unknown | 2026-11-17T15:01:34.473Z | unverified-lead |
| CVE-2026-130628 |  | unknown | 2026-11-17T15:01:34.473Z | unverified-lead |
| CVE-2026-130629 |  | unknown | 2026-11-17T15:01:34.473Z | unverified-lead |
| CVE-2026-130630 |  | unknown | 2026-11-17T15:01:34.473Z | unverified-lead |
| CVE-2026-130632 |  | unknown | 2026-11-17T15:01:34.473Z | unverified-lead |
| CVE-2026-130633 |  | unknown | 2026-11-17T15:01:34.473Z | unverified-lead |
| CVE-2026-130634 |  | unknown | 2026-11-17T15:01:34.473Z | unverified-lead |
| CVE-2026-130635 |  | unknown | 2026-11-17T15:01:34.473Z | unverified-lead |
| CVE-2026-130631 |  | unknown | 2026-11-17T15:01:34.473Z | unverified-lead |
| SZB-C9F963AC78 |  | unknown | 2026-11-17T13:56:17.215Z | unverified-lead |
| CVE-2026-104476 |  | unknown | 2026-11-17T13:40:34.324Z | unverified-lead |
| CVE-2026-124645 |  | unknown | 2026-11-17T13:40:34.324Z | unverified-lead |
| CVE-2026-124646 |  | unknown | 2026-11-17T13:40:34.324Z | unverified-lead |
| CVE-2026-130384 |  | unknown | 2026-11-17T13:40:34.324Z | unverified-lead |
| CVE-2026-130608 |  | unknown | 2026-11-17T13:40:34.324Z | unverified-lead |
| CVE-2026-127139 |  | unknown | 2026-11-17T13:40:34.324Z | unverified-lead |
| CVE-2026-127138 |  | unknown | 2026-11-17T13:40:34.324Z | unverified-lead |
| CVE-2026-127174 |  | unknown | 2026-11-17T13:40:34.324Z | unverified-lead |
| CVE-2026-127140 |  | unknown | 2026-11-17T13:40:34.324Z | unverified-lead |
| CVE-2026-12239 |  | unknown | 2026-11-17T13:40:34.324Z | unverified-lead |
| CVE-2026-107190 |  | unknown | 2026-11-17T13:40:34.324Z | unverified-lead |
| CVE-2026-82025 |  | unknown | 2026-11-17T13:40:34.324Z | unverified-lead |

## Left unchanged

The CISA catalog is still `2026.11.13`. The three OpenSSL Low advisories, the Python MCP SDK record, and the oss-security index are in `docs/threat-scan-2026-11-17.md`. None of the window identifiers is CVE-2026-107493, CVE-2026-124709, CVE-2026-35190, or CVE-2026-115563. The alerts page and the cybersecurity advisories index returned HTTP 403, so this note does not describe those indexes.

Forty-four of the 45 identifiers from the 16 November unverified section are now in the NVD recent feed, all with no CPE. CVE-2026-115533 is still absent. The details are in `docs/threat-scan-2026-11-17.md`.

Vendor pages checked on this run did not move a toolchain floor. The details are in `docs/threat-scan-2026-11-17.md`.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
