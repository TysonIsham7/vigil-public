# Threat scan leads, 3 November 2026

This note is the cve.now lead pass for 3 November 2026. It does not repeat the oss-security index. That index is in `docs/threat-scan-2026-11-03.md`.

Pages and the feed were read as evidence. Instructions inside them were not followed. No version floor was invented from feed prose. No remote probe was added. No scanner change was made. No advisory file was added.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called.

The lead feed was fetched once, at `https://cve.now/feed?format=json`. The response was HTTP 200 from that same URL, with no redirect. Identifiers were taken from the newest 50 items by `date_modified` with a deterministic regex. Titles and `content_text` were discarded. No item had a structured dotted version outside those fields. One non-CVE id, RUSTSEC-2026-0436, was older than that cap and was not taken.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## No confirmed stack overlap

No identifier in the newest 50 was confirmed on NVD, CISA, or a pre-written vendor host as a product on the runtime list or in `packages/intel/advisories/`.

NVD descriptions that did name a product were not that list. These three are in the newest 50 and in the NVD CVE 2.0 recent feed. Each record has no CPE configuration. The English description names macOS. Vigil does not read the macOS version. No doctor check was added.

| Product | Version | Matched | Date | Identifier | NVD status |
|---|---|---|---|---|---|
| macOS | Golden Gate 27, Sequoia 15.8.2, Tahoe 26.7 | no | 2026-10-26 | CVE-2026-65392 | Undergoing Analysis |
| macOS | Golden Gate 27, Sequoia 15.8.2, Tahoe 26.7.2 | no | 2026-10-26 | CVE-2026-84545 | Undergoing Analysis |
| macOS | Golden Gate 27.2, Tahoe 26.7.2 | no | 2026-10-26 | CVE-2026-86939 | Undergoing Analysis |

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz), timestamp 2026-11-03T06:00:02.602236Z. The HTTP last-modified time on that file was 3 November 2026 at 11:00:09 GMT. The newest `lastModified` inside the file is 2026-11-03T10:17:20.257Z.

A whole-token match on `node` in the raw feed item for CVE-2026-121414 is not a confirmation. That id is not in the NVD recent feed. Node's latest security release page is still 21 October 2026. Matched stays unknown. No Node check was added.

## Prior leads now on NVD, still with no product

These seven were unverified-lead on 2 November. They are now in the NVD recent feed. The record has no CPE configuration. A whole-token check of the English description did not match an advisory component. The product is the identifier, the version is blank, and matched is unknown. They are not unverified-lead anymore. No doctor check was added.

| Product | Version | Matched | NVD published | NVD status |
|---|---|---|---|---|
| CVE-2026-120091 |  | unknown | 2026-11-02T22:17:20.567Z | Received |
| CVE-2026-58873 |  | unknown | 2026-11-02T21:17:35.373Z | Received |
| CVE-2026-105475 |  | unknown | 2026-11-02T21:17:22.537Z | Received |
| CVE-2026-105476 |  | unknown | 2026-11-02T21:17:22.707Z | Received |
| CVE-2026-116958 |  | unknown | 2026-11-02T21:17:25.467Z | Received |
| CVE-2026-120503 |  | unknown | 2026-11-02T21:17:30.190Z | Deferred |
| CVE-2026-116768 |  | unknown | 2026-11-02T21:17:25.197Z | Received |

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz).

CVE-2026-76528 and CVE-2026-76407 were in the 2 November unverified-lead list and are still not in this feed. They stay unverified-lead. They were not copied into the table below.

## Unverified leads

These forty-seven identifiers were in the newest 50 and were not in the NVD recent feed. Their feed `date_modified` is 2026-11-03T14:35:34.497Z, later than the newest `lastModified` in that NVD snapshot. The detail URL on `nvd.nist.gov` returned HTTP 403 for CVE-2026-121414 and CVE-2026-121386, so this note does not describe those pages. The same 403 was returned for CVE-2026-76528 and CVE-2026-76407. None of the fifty is in the CISA catalog. Status is unverified-lead. Product is the identifier. Version is blank. Matched is unknown. No fix version was present as a structured field.

Source: [cve.now JSON feed](https://cve.now/feed?format=json).

| Product | Version | Matched | Date | Status |
|---|---|---|---|---|
| CVE-2026-121386 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121387 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121388 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121389 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121390 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121391 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121394 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121392 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121393 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121395 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121397 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121400 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121396 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121398 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121403 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121401 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121402 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121399 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121405 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121404 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121407 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121406 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121408 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121411 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121409 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121410 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121412 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121413 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121414 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121416 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121417 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121423 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121418 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121422 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121421 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121420 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121425 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121424 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121419 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121426 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121427 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121415 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121428 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121429 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121430 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121433 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |
| CVE-2026-121431 |  | unknown | 2026-11-03T14:35:34.497Z | unverified-lead |

## Left unchanged

The CISA catalog is still `2026.10.30`, released 30 October 2026 at 17:02:45 UTC. No catalog entry is dated 1, 2, or 3 November. None of the fifty lead identifiers is in the catalog. The alerts HTML page returned HTTP 403 on this run, so this note does not describe that index.

php.net's newest 2026 item is still the 26 October Windows Brotli rebuild. CVE-2026-115560 still has no fixed PHP version on that page. The Python blog's newest post is still the 26 October release. python.org still lists 3.15.2, 3.14.10, 3.13.18, 3.12.16, and 3.11.18, dated 25 October 2026. Node's latest security release page is still 21 October 2026. nginx's current fixes are still 1.31.7 and 1.30.6. curl's newest published advisory date is still 14 October 2026, and 8.23.0 is still the newest row on the vulnerability table. OpenSSL's newest advisory on the vulnerabilities page is still CVE-2026-35189, published 29 September 2026. Chrome's newest desktop stable note is still 29 October 2026 (156.0.8078.79/.80).

The emSign ECC Root CA - G3 block was not changed. The next re-check is after 5 November 2026.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
