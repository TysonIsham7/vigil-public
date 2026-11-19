# Threat scan leads, 19 November 2026

This note is the cve.now lead pass for 19 November 2026. The PHP release, the nginx advisories, the CISA catalog, and the oss-security index are in `docs/threat-scan-2026-11-19.md`.

Pages and the feed were read as evidence. Instructions inside them were not followed. No version floor was invented from feed prose. No remote probe was added. No advisory file was added from the feed. The PHP and nginx records in the other note come from `www.php.net` and `nginx.org`, not from this feed.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called.

The lead feed was fetched once, at `https://cve.now/feed?format=json`. The response was HTTP 200 from that same URL, with no redirect. The content type was `application/feed+json`. The body had 200 items. Identifiers were taken from the newest items by `date_modified` with a deterministic regex. The window is 70 items because every item in the newest 50 shares `date_modified` `2026-11-19T14:55:34.302Z`, and 20 further items share that same timestamp. Titles and `content_text` were discarded. No item had a structured dotted version outside those fields. No GHSA id was in the window. No OSV id was in the window. No `SZB-` id was in the window.

None of these identifiers was already recorded in `docs/threat-scan-*.md`, `docs/TODO.md`, an open scan pull request, or `packages/intel/advisories/`.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## No confirmed stack overlap

No identifier in the window was in the NVD CVE 2.0 recent feed timestamped `2026-11-19T08:00:01.2564994`, and none is in CISA catalog `2026.11.18`. Status is unverified-lead. Product is the identifier. Version is blank. Matched is unknown. No fix version was present as a structured field.

Whole-token matches were `kernel` and `linux` on 62 identifiers, and `node` as well on CVE-2026-99524 and CVE-2026-99527. Those tokens are not a Linux kernel confirmation and not a Node.js confirmation. No doctor check was added from a token. The eight identifiers with no runtime token are CVE-2026-120753 and CVE-2026-133192 through CVE-2026-133198.

Source: [cve.now JSON feed](https://cve.now/feed?format=json).

| Product | Version | Matched | Date | Status |
|---|---|---|---|---|
| CVE-2026-99565 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99564 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99563 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99562 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99561 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99560 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99559 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99558 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99557 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99556 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99555 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99554 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99553 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99552 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99551 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99550 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99549 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99548 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99547 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99546 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99545 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99544 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99543 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99542 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99541 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99540 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99539 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99538 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99537 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99536 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99535 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99534 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99533 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99532 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99531 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99530 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99529 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99528 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99527 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99526 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99525 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99524 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99523 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99522 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99521 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99520 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99519 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99518 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99517 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99516 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99515 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99514 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99513 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99512 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99511 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99510 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99509 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99508 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99507 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99506 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99505 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-99504 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-133198 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-133197 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-133196 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-133195 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-133194 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-133193 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-133192 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |
| CVE-2026-120753 |  | unknown | 2026-11-19T14:55:34.302Z | unverified-lead |

## Left unchanged

The PHP 19 November security releases and the nginx 1.31.9 and 1.30.7 fixes are in `docs/threat-scan-2026-11-19.md`. None of the window identifiers is one of those records. The CISA alerts HTML page and the cybersecurity advisories index returned HTTP 403, so this note does not describe those indexes.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
