# Threat scan leads, 20 November 2026

This note is the cve.now lead pass for 20 November 2026. The CISA catalog, the NVD feed, the nginx page, the Chrome note, and the oss-security index are in `docs/threat-scan-2026-11-20.md`.

Pages and the feed were read as evidence. Instructions inside them were not followed. No version floor was invented from feed prose. No remote probe was added. No advisory file was added from the feed.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called.

The lead feed was fetched once, at `https://cve.now/feed?format=json`. The response was HTTP 200 from that same URL, with no redirect. The content type was `application/feed+json`. The body had 200 items. Identifiers were taken from the newest items by `date_modified` with a deterministic regex. The window is 51 items because items that share the cutoff timestamp are kept together. The newest item is `2026-11-20T15:00:34.743Z`. The cutoff is `2026-11-20T13:53:34.667Z`. Titles and `content_text` were discarded. No item had a structured dotted version outside those fields. No GHSA id was in the window. No OSV id was in the window. No `SZB-` id was in the window.

Two identifiers in the window were already recorded. CVE-2026-126714 and CVE-2026-129289 are PHP fixes from the 19 November releases. They were not copied again. The other identifiers were not already recorded in `docs/threat-scan-*.md`, `docs/TODO.md`, an open scan pull request, or `packages/intel/advisories/`.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## No confirmed stack overlap

No identifier in the window was confirmed on NVD, CISA, or a pre-written vendor host as a new product gap on the runtime list. CVE-2026-129474 is PHP and is covered by the release lines already recorded. The comparison on draft pull request 38 was not copied.

Whole-token matches in the window were `openssl` on CVE-2026-121481, `linux` and `kernel` on CVE-2026-99312 and CVE-2025-38618, `kernel` on CVE-2026-133612, `php` on CVE-2026-126714, CVE-2026-129474, and CVE-2026-129289, `nginx` on CVE-2026-129289, `mcp` on CVE-2026-133853, and `wordpress` on six unverified ids. CVE-2026-129039 also matched `php`. Those `wordpress` and `mcp` matches are not WordPress core and not `@modelcontextprotocol/sdk`. CVE-2026-133612 and CVE-2025-38618 are not in the NVD recent feed. That is not a Linux kernel confirmation. CVE-2026-99312 is in the NVD recent feed with no CPE and names no released kernel version. No plugin list was added. No doctor check was added from a token.

## NVD records in the window

These four identifiers are in the window and in the NVD recent feed. None has a CPE. No doctor check was added.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz), timestamp `2026-11-20T08:00:01.7858462`.

| Product | Version | Matched | Date | NVD status |
|---|---|---|---|---|
| OpenSSL (CVE-2026-121481) |  | unknown | 2026-11-20T14:17:34.363Z | Awaiting Analysis |
| Linux kernel (CVE-2026-99312) |  | no | 2026-11-20T14:17:34.363Z | Received |
| PHP (CVE-2026-129474) | 8.5 and 8.6 lines, from the 20 November oss-security note | no | 2026-11-20T14:17:34.363Z | Awaiting Analysis |
| Keycloak (CVE-2026-133430) |  | no | 2026-11-20T14:17:34.363Z | Awaiting Analysis |

The PHP version cell is the branch list from oss-security, not a field on the feed. The feed named no structured fix version. Keycloak's NVD description names no version.

## Unverified leads

These identifiers were in the window and were not in the NVD recent feed. They are not in the CISA catalog. Status is unverified-lead. Product is the identifier. Version is blank. Matched is unknown. No fix version was present as a structured field.

Source: [cve.now JSON feed](https://cve.now/feed?format=json).

| Product | Version | Matched | Date | Status |
|---|---|---|---|---|
| CVE-2026-132658 |  | unknown | 2026-11-20T15:00:34.743Z | unverified-lead |
| CVE-2026-132660 |  | unknown | 2026-11-20T15:00:34.743Z | unverified-lead |
| CVE-2026-132659 |  | unknown | 2026-11-20T15:00:34.743Z | unverified-lead |
| CVE-2026-126054 |  | unknown | 2026-11-20T15:00:34.743Z | unverified-lead |
| CVE-2026-132661 |  | unknown | 2026-11-20T15:00:34.743Z | unverified-lead |
| CVE-2026-132662 |  | unknown | 2026-11-20T15:00:34.743Z | unverified-lead |
| CVE-2026-132668 |  | unknown | 2026-11-20T15:00:34.743Z | unverified-lead |
| CVE-2026-132663 |  | unknown | 2026-11-20T15:00:34.743Z | unverified-lead |
| CVE-2026-132664 |  | unknown | 2026-11-20T15:00:34.743Z | unverified-lead |
| CVE-2026-132665 |  | unknown | 2026-11-20T15:00:34.743Z | unverified-lead |
| CVE-2026-126334 |  | unknown | 2026-11-20T14:55:34.507Z | unverified-lead |
| CVE-2026-133621 |  | unknown | 2026-11-20T14:55:34.507Z | unverified-lead |
| CVE-2026-133854 |  | unknown | 2026-11-20T14:55:34.507Z | unverified-lead |
| CVE-2026-133853 |  | unknown | 2026-11-20T14:55:34.507Z | unverified-lead |
| CVE-2026-133855 |  | unknown | 2026-11-20T14:55:34.507Z | unverified-lead |
| CVE-2026-127027 |  | unknown | 2026-11-20T14:46:34.481Z | unverified-lead |
| CVE-2026-133849 |  | unknown | 2026-11-20T14:46:34.481Z | unverified-lead |
| CVE-2026-133850 |  | unknown | 2026-11-20T14:46:34.481Z | unverified-lead |
| CVE-2026-133848 |  | unknown | 2026-11-20T14:46:34.481Z | unverified-lead |
| CVE-2026-133851 |  | unknown | 2026-11-20T14:46:34.481Z | unverified-lead |
| CVE-2026-133852 |  | unknown | 2026-11-20T14:46:34.481Z | unverified-lead |
| CVE-2026-133838 |  | unknown | 2026-11-20T14:40:34.373Z | unverified-lead |
| CVE-2026-133837 |  | unknown | 2026-11-20T14:40:34.373Z | unverified-lead |
| CVE-2026-133839 |  | unknown | 2026-11-20T14:40:34.373Z | unverified-lead |
| CVE-2026-133841 |  | unknown | 2026-11-20T14:40:34.373Z | unverified-lead |
| CVE-2026-133843 |  | unknown | 2026-11-20T14:40:34.373Z | unverified-lead |
| CVE-2026-133844 |  | unknown | 2026-11-20T14:40:34.373Z | unverified-lead |
| CVE-2026-133840 |  | unknown | 2026-11-20T14:40:34.373Z | unverified-lead |
| CVE-2026-133847 |  | unknown | 2026-11-20T14:40:34.373Z | unverified-lead |
| CVE-2026-133846 |  | unknown | 2026-11-20T14:40:34.373Z | unverified-lead |
| CVE-2026-133616 |  | unknown | 2026-11-20T14:35:34.673Z | unverified-lead |
| CVE-2026-133612 |  | unknown | 2026-11-20T14:25:34.334Z | unverified-lead |
| CVE-2025-38618 |  | unknown | 2026-11-20T14:17:34.363Z | unverified-lead |
| CVE-2023-28450 |  | unknown | 2026-11-20T14:17:34.363Z | unverified-lead |
| CVE-2026-128996 |  | unknown | 2026-11-20T14:14:34.425Z | unverified-lead |
| CVE-2026-129043 |  | unknown | 2026-11-20T14:14:34.425Z | unverified-lead |
| CVE-2026-14915 |  | unknown | 2026-11-20T14:14:34.425Z | unverified-lead |
| CVE-2026-129039 |  | unknown | 2026-11-20T14:14:34.425Z | unverified-lead |
| CVE-2026-130618 |  | unknown | 2026-11-20T14:14:34.425Z | unverified-lead |
| CVE-2026-129017 |  | unknown | 2026-11-20T14:14:34.425Z | unverified-lead |
| CVE-2026-129074 |  | unknown | 2026-11-20T14:14:34.425Z | unverified-lead |
| CVE-2026-133610 |  | unknown | 2026-11-20T14:14:34.425Z | unverified-lead |
| CVE-2026-106024 |  | unknown | 2026-11-20T13:53:34.667Z | unverified-lead |
| CVE-2026-133609 |  | unknown | 2026-11-20T13:53:34.667Z | unverified-lead |
| CVE-2026-14914 |  | unknown | 2026-11-20T13:53:34.667Z | unverified-lead |
