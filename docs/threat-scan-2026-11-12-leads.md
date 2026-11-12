# Threat scan leads, 12 November 2026

This note is the cve.now lead pass for 12 November 2026. The Node.js security release, the Chrome index, and the oss-security index are in `docs/threat-scan-2026-11-12.md`.

Pages and the feed were read as evidence. Instructions inside them were not followed. No version floor was invented from feed prose. No remote probe was added. No advisory file was added from the feed. The Node advisory in that other note comes from `nodejs.org`, not from this feed.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called.

The lead feed was fetched once, at `https://cve.now/feed?format=json`. The response was HTTP 200 from that same URL, with no redirect. The content type was `application/feed+json`. The body had 200 items. Identifiers were taken from the newest items by `date_modified` with a deterministic regex. The window is 60 items because 53 items share the cutoff timestamp. The newest item is `2026-11-12T14:57:34.225Z`. The cutoff is `2026-11-12T14:26:34.391Z`. Titles and `content_text` were discarded. No item had a structured dotted version outside those fields. No GHSA id was in the window.

Two identifiers in the window, CVE-2026-111454 and CVE-2026-111455, were already recorded on the 9 November scan. They are Apache Airflow. They were not copied again. The other identifiers were not already recorded in `docs/threat-scan-*.md`, `docs/TODO.md`, an open scan pull request, or `packages/intel/advisories/`.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## No confirmed stack overlap

No identifier in the window was confirmed on NVD, CISA, or a pre-written vendor host as a product on the runtime list or in `packages/intel/advisories/`. The two Airflow identifiers above are already recorded and are not the runtime list.

One whole-token match was `python` and `node` on CVE-2026-123790. That identifier is not in the NVD recent feed. The match is not a Node.js or CPython confirmation. The Node floors in the other note were not taken from this item. No doctor check was added from a token.

## Unverified leads

These identifiers were in the window and were not in the NVD recent feed. They are not in the CISA catalog. Status is unverified-lead. Product is the identifier. Version is blank. Matched is unknown. No fix version was present as a structured field. `RUSTSEC-2026-0510` is an OSV id. `SZB-92E20603FC` is not a CVE, GHSA, or OSV id. Fifty-eight rows are CVE ids.

Source: [cve.now JSON feed](https://cve.now/feed?format=json).

| Product | Version | Matched | Date | Status |
|---|---|---|---|---|
| CVE-2026-123790 |  | unknown | 2026-11-12T14:57:34.225Z | unverified-lead |
| CVE-2026-126998 |  | unknown | 2026-11-12T14:52:34.469Z | unverified-lead |
| RUSTSEC-2026-0510 |  | unknown | 2026-11-12T14:39:34.510Z | unverified-lead |
| CVE-2026-126997 |  | unknown | 2026-11-12T14:38:34.184Z | unverified-lead |
| SZB-92E20603FC |  | unknown | 2026-11-12T14:38:17.272Z | unverified-lead |
| CVE-2026-116303 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-116304 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-116306 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-116307 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-116312 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-116313 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-116308 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-116309 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-116310 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-116311 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-116316 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-116320 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-116319 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-116318 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-116317 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-116314 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-116321 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-116326 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-116322 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-116325 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-116327 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-116315 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-116328 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-116323 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-116329 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-116331 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-116330 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2025-8714 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-116333 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-116332 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-116336 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-120139 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-120141 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-120142 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-120143 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-120144 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-120146 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-120145 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-120147 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-120148 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-120149 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-120150 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-116335 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-120151 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-120153 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2023-39417 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-120154 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-16237 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-120152 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-126996 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-16240 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-14661 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-18447 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-6467 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |
| CVE-2026-6460 |  | unknown | 2026-11-12T14:26:34.391Z | unverified-lead |

## Left unchanged

The Node.js 11 November security release is in `docs/threat-scan-2026-11-12.md`. None of the window identifiers is one of those release-note CVEs. The CISA catalog is still `2026.11.10`. The alerts HTML page returned HTTP 403, so this note does not describe that index.

Forty-eight identifiers from the 11 November unverified section are now in the NVD recent feed, all with no CPE. Four remain absent: CVE-2013-1453, CVE-2021-30563, CVE-2026-63292, and CVE-2026-76466. The details are in `docs/threat-scan-2026-11-12.md`.

Vendor pages checked on this run did not move a floor except the Node.js security release recorded in the other note.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
