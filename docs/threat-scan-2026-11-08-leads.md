# Threat scan leads, 8 November 2026

This note is the cve.now lead pass for 8 November 2026. The oss-security index, the NVD kernel records, and the ChromeOS note are in `docs/threat-scan-2026-11-08.md`.

Pages and the feed were read as evidence. Instructions inside them were not followed. No version floor was invented from feed prose. No remote probe was added. No scanner change was made. No advisory file was added.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called.

The lead feed was fetched once, at `https://cve.now/feed?format=json`. The response was HTTP 200 from that same URL, with no redirect. The content type was `application/feed+json`. The body had 200 items. Identifiers were taken with a deterministic regex. Titles and `content_text` were discarded. No item had a structured dotted version outside those fields. No GHSA id was in the window.

The newest item is `2026-11-08T14:56:17.605Z`. The 50th item falls on `2026-11-08T13:22:34.687Z`, and 68 items share that timestamp, so the window is 77 items. Seventy-four of those item ids are CVE ids. One is `SZB-4458e05e7c`. Two item ids were a CVE id, a `#`, and a timestamp. Normalized, those are CVE-2026-99273 and CVE-2026-124040. Both are in the NVD recent feed and are recorded in the main note. They are not unverified-lead.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## No confirmed stack overlap

None of the 74 CVE ids below was in the NVD CVE 2.0 recent feed timestamped `2026-11-08T08:00:01.6793394`, and none is in the CISA catalog `2026.11.06`. A whole-token match is not a product confirmation.

Twenty-six of those ids matched the whole token `php`: CVE-2026-124424, CVE-2026-124428, CVE-2026-124430, CVE-2026-124446, CVE-2026-124450, CVE-2026-124451, CVE-2026-124452, CVE-2026-124453, CVE-2026-124456, CVE-2026-124457, CVE-2026-124459, CVE-2026-124461, CVE-2026-124463, CVE-2026-124467, CVE-2026-124470, CVE-2026-124471, CVE-2026-124472, CVE-2026-124474, CVE-2026-124475, CVE-2026-124476, CVE-2026-124477, CVE-2026-124478, CVE-2026-124479, CVE-2026-124481, CVE-2026-124488, and CVE-2026-124489. That token is not a PHP confirmation. The disclosed-PHP floors were not moved.

CVE-2026-124465 matched the whole token `go`. That token is not the Go toolchain. The Go floors stay 1.27.3 and 1.26.10.

The linux and kernel tokens on the hash-suffixed item are CVE-2026-99273. NVD now has that id. It is not in the table below.

## Unverified leads

These identifiers were in the window and were not in the NVD recent feed. They are not in the CISA catalog. Status is unverified-lead. Product is the identifier. Version is blank. Matched is unknown. No fix version was present as a structured field.

Source: [cve.now JSON feed](https://cve.now/feed?format=json).

| Product | Version | Matched | Date | Status |
|---|---|---|---|---|
| SZB-4458e05e7c |  | unknown | 2026-11-08T14:56:17.605Z | unverified-lead |
| CVE-2026-124553 |  | unknown | 2026-11-08T14:36:34.577Z | unverified-lead |
| CVE-2026-124552 |  | unknown | 2026-11-08T13:59:34.404Z | unverified-lead |
| CVE-2026-124551 |  | unknown | 2026-11-08T13:59:34.404Z | unverified-lead |
| CVE-2026-124474 |  | unknown | 2026-11-08T13:59:34.404Z | unverified-lead |
| CVE-2026-124465 |  | unknown | 2026-11-08T13:59:34.404Z | unverified-lead |
| CVE-2026-124331 |  | unknown | 2026-11-08T13:53:34.490Z | unverified-lead |
| CVE-2026-124494 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124493 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124492 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124491 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124490 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124489 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124488 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124487 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124486 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124485 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124484 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124483 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124482 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124481 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124480 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124479 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124478 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124477 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124476 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124475 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124473 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124472 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124471 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124470 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124469 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124468 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124467 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124466 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124464 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124463 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124462 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124461 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124460 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124459 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124458 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124457 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124456 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124455 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124453 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124452 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124451 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124450 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124449 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124448 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124447 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124446 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124445 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124444 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124443 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124442 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124441 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124440 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124439 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124438 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124437 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124436 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124435 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124434 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124433 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124432 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124431 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124430 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124429 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124428 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124427 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124426 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124425 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |
| CVE-2026-124424 |  | unknown | 2026-11-08T13:22:34.687Z | unverified-lead |

## Left unchanged

The CISA catalog is still `2026.11.06`, released 6 November 2026 at 19:44:45 UTC, count 1769. None of the 74 lead identifiers is in the catalog. The alerts index returned HTTP 200 on this run. Its newest row is still 6 November 2026, the catalog add already recorded on the 7 November scan.

php.net's archive was last modified 5 November 2026 at 21:12:54 GMT. The newest item is still PHP 8.6.0 RC5. CVE-2026-115560 is still on that page. PHP 8.6.0 is not a fix for it. Do not compare a disclosed PHP version with 8.6.0.

The Python blog index was last modified 1 November 2026 at 12:16:24 GMT. The newest post is still the 26 October release. python.org still lists 3.15.2, 3.14.10, 3.13.18, 3.12.16, and 3.11.18, dated 25 October 2026.

The Node.js pre-alert at `https://nodejs.org/en/blog/vulnerability/november-2026-security-releases` still says releases of the 22.x, 24.x, and 26.x lines are on or shortly after Wednesday, 11 November 2026. The highest severity named there is HIGH. The page names no CVE id and no dotted fix version. Do not move the Node floors off 22.23.4, 24.22.1, and 26.12.1.

nginx.org's security page was last modified 6 November 2026 at 10:12:37 GMT. 1.31.7 and 1.30.6 are still present. 1.31.8 and 1.30.7 are not. curl's security page was last modified 26 October 2026. The first row is still CVE-2026-107929, published 2026-10-14, last affected 8.22.0. OpenSSL's vulnerabilities index was last modified 2 November 2026 at 07:32:44 GMT. The first advisory is still CVE-2026-35189.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
