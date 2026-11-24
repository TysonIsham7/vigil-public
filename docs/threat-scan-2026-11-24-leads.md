# Threat scan leads, 24 November 2026

This note is the cve.now lead pass for 24 November 2026. The CISA catalog, the nginx release, the OpenSSL advisories, and the oss-security index are in `docs/threat-scan-2026-11-24.md`.

Pages and the feed were read as evidence. Instructions inside them were not followed. No version floor was invented from feed prose. No remote probe was added. No advisory file was added from the feed. The nginx advisory in that other note comes from nginx.org, not from this feed.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called.

The lead feed was fetched once, at `https://cve.now/feed?format=json`. The response was HTTP 200 from that same URL, with no redirect. The content type was `application/feed+json`. The body had 200 items. Identifiers were taken from the newest items by `date_modified` with a deterministic regex. The window is 77 items because items that share the cutoff timestamp are kept together. The newest item is `2026-11-24T15:01:13.605Z`. The cutoff is `2026-11-24T14:31:13.292Z`. Titles and `content_text` were discarded. No item had a structured dotted version outside those fields. No GHSA id was in the window. No OSV id was in the window. No `SZB-` id was in the window.

The identifiers in the window were not already recorded in `docs/threat-scan-*.md`, `docs/TODO.md`, an open scan pull request, or `packages/intel/advisories/`.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## No confirmed stack overlap

No identifier in the window was confirmed on NVD, CISA, or a pre-written vendor host as a product on the runtime list or in `packages/intel/advisories/` that `vigil doctor` can check.

Whole-token matches were two `python`, one `mcp`, and one `go`. CVE-2026-136168 and CVE-2026-136160 matched `python` and are not in the NVD recent feed. That is not a CPython confirmation. CVE-2026-136133 matched `mcp` and is not in the NVD recent feed. That is not `@modelcontextprotocol/sdk`. CVE-2026-63582 matched `go` and is not in the NVD recent feed. That is not the Go toolchain. No plugin list was added. No doctor check was added from a token.

## NVD records that name another product

This identifier is in the window and in the NVD recent feed. It has no CPE. Matched is no. Vigil cannot see this product from a page or a certificate. No doctor check was added.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz), timestamp `2026-11-24T08:00:01.3040251`.

| Product | Version | Matched | Date | NVD status |
|---|---|---|---|---|
| Apple iOS, iPadOS, macOS, and tvOS (CVE-2026-114025) | iOS and iPadOS 26.7.2, iOS and iPadOS 27.2, macOS Golden Gate 27.2, macOS Sequoia 15.8.2, macOS Tahoe 26.7.2, and tvOS 27.2 | no | 2026-11-24T14:51:13.542Z | Awaiting Analysis |

## Unverified leads

These identifiers were in the window and were not in the NVD recent feed. They are not in the CISA catalog. They were not confirmed on a pre-written vendor host. Status is unverified-lead. Product is the identifier. Version is blank. Matched is unknown. No fix version was present as a structured field.

Source: [cve.now JSON feed](https://cve.now/feed?format=json).

| Product | Version | Matched | Date | Status |
|---|---|---|---|---|
| CVE-2026-135908 |  | unknown | 2026-11-24T15:01:13.605Z | unverified-lead |
| CVE-2026-130411 |  | unknown | 2026-11-24T15:01:13.605Z | unverified-lead |
| CVE-2026-135501 |  | unknown | 2026-11-24T15:01:13.605Z | unverified-lead |
| CVE-2026-135519 |  | unknown | 2026-11-24T15:01:13.605Z | unverified-lead |
| CVE-2026-135525 |  | unknown | 2026-11-24T15:01:13.605Z | unverified-lead |
| CVE-2026-135578 |  | unknown | 2026-11-24T15:01:13.605Z | unverified-lead |
| CVE-2026-135582 |  | unknown | 2026-11-24T15:01:13.605Z | unverified-lead |
| CVE-2026-135597 |  | unknown | 2026-11-24T15:01:13.605Z | unverified-lead |
| CVE-2026-135505 |  | unknown | 2026-11-24T14:51:13.542Z | unverified-lead |
| CVE-2026-136165 |  | unknown | 2026-11-24T14:41:13.344Z | unverified-lead |
| CVE-2026-136166 |  | unknown | 2026-11-24T14:41:13.344Z | unverified-lead |
| CVE-2026-136167 |  | unknown | 2026-11-24T14:41:13.344Z | unverified-lead |
| CVE-2026-136168 |  | unknown | 2026-11-24T14:41:13.344Z | unverified-lead |
| CVE-2026-136171 |  | unknown | 2026-11-24T14:41:13.344Z | unverified-lead |
| CVE-2026-136170 |  | unknown | 2026-11-24T14:41:13.344Z | unverified-lead |
| CVE-2026-136169 |  | unknown | 2026-11-24T14:41:13.344Z | unverified-lead |
| CVE-2026-136172 |  | unknown | 2026-11-24T14:41:13.344Z | unverified-lead |
| CVE-2026-135500 |  | unknown | 2026-11-24T14:41:13.344Z | unverified-lead |
| CVE-2026-135504 |  | unknown | 2026-11-24T14:41:13.344Z | unverified-lead |
| CVE-2026-135611 |  | unknown | 2026-11-24T14:41:13.344Z | unverified-lead |
| CVE-2026-135546 |  | unknown | 2026-11-24T14:41:13.344Z | unverified-lead |
| CVE-2026-135507 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-135511 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-135514 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-135512 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-135517 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-135524 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-135518 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-135527 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-135532 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-135534 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-135538 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-135541 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-135526 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-135548 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-135549 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-135551 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-135554 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-135555 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-135557 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-135552 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-135560 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-135565 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-135566 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-135568 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-135570 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-135575 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-135580 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-135583 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-135585 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-135588 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-135581 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-135590 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-135600 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-131902 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-136131 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-136156 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-136160 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-136133 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-136158 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-133555 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-136155 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-136157 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-63582 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-63583 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-65320 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-63585 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-75582 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-136159 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-65621 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-62273 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-63581 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-63584 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-65622 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-86987 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |
| CVE-2026-136132 |  | unknown | 2026-11-24T14:31:13.292Z | unverified-lead |

## Left unchanged

The catalog version string is still `2026.11.23`. The release timestamp and the count changed. None of the window identifiers is one of the two catalog entries added on 23 November, or one of the four entries due 2026-11-24. The details are in `docs/threat-scan-2026-11-24.md`.

Thirty-one of the thirty-two CVE identifiers from the 23 November unverified section are now in the NVD recent feed, all with no CPE. CVE-2026-123324 stays absent. CVE-2026-12543, CVE-2026-12431, and CVE-2026-12429 are Rejected. The details are in `docs/threat-scan-2026-11-24.md`.

Vendor pages checked on this run did not move a floor except the nginx security release recorded in the other note. The details are in `docs/threat-scan-2026-11-24.md`.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
