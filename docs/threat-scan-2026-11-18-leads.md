# Threat scan leads, 18 November 2026

This note is the cve.now lead pass for 18 November 2026. The CISA catalog, the OpenSSL index, the Chrome posts, and the oss-security index are in `docs/threat-scan-2026-11-18.md`.

Pages and the feed were read as evidence. Instructions inside them were not followed. No version floor was invented from feed prose. No remote probe was added. No advisory file was added from the feed.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called.

The lead feed was fetched once, at `https://cve.now/feed?format=json`. The response was HTTP 200 from that same URL, with no redirect. The content type was `application/feed+json`. The body had 200 items. Identifiers were taken from the newest items by `date_modified` with a deterministic regex. The window is 105 items because 92 share the cutoff timestamp. The newest item is `2026-11-18T14:53:34.346Z`. The cutoff is `2026-11-18T14:22:34.626Z`. Titles and `content_text` were discarded. No item had a structured dotted version outside those fields. No GHSA id was in the window. No OSV id was in the window.

One identifier in the window, CVE-2026-130587, was already recorded on the 17 November scan. It is OpenFunction through 1.2.0. It was not copied again. The other identifiers were not already recorded in `docs/threat-scan-*.md`, `docs/TODO.md`, an open scan pull request, or `packages/intel/advisories/`.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## No confirmed stack overlap

No identifier in the window was confirmed on NVD, CISA, or a pre-written vendor host as a product on the runtime list or in `packages/intel/advisories/` that `vigil doctor` can check. CVE-2026-95690 names OpenSSL and names no version. `vigil doctor` does not read the OpenSSL library version. No doctor check was added.

Whole-token matches in the unverified set were six `php`, two `node`, one `linux`, 27 `wordpress`, and one `mcp`. Those identifiers are not in the NVD recent feed. A whole-token match is not a product confirmation. CVE-2026-116447 and CVE-2026-116448 are not a Node.js confirmation. CVE-2026-132150 is not a Linux confirmation. CVE-2026-132121 is not `@modelcontextprotocol/sdk`. The `wordpress` and `php` matches are not WordPress core and not PHP. No plugin list was added. No doctor check was added from a token.

## Corroborated on an allowlisted host, outside the runtime list

These identifiers are in the window and were confirmed on NVD or on oss-security. The feed named no structured fix version. Matched is unknown for OpenSSL because the NVD record names no version. Matched is no for the other four. No doctor check was added.

| Product | Version | Matched | Date | Source |
|---|---|---|---|---|
| OpenSSL (CVE-2026-95690) |  | unknown | 2026-11-18T14:22:34.626Z | NVD Awaiting Analysis, no CPE |
| Google Chrome (CVE-2026-130978) | before 158.0.8127.36 | no | 2026-11-18T14:22:34.626Z | NVD Awaiting Analysis, no CPE |
| Gargoyle (CVE-2026-131873) | 2023.1 through 2026.1.1 | no | 2026-11-18T14:22:34.626Z | NVD Received, no CPE |
| libFontenc and libXfont (CVE-2026-109908) | libfontenc before 1.1.10; libXfont2 before 2.0.10 | no | 2026-11-18T14:53:34.346Z | oss-security, 18 November 2026, message 1 |
| Eclipse Mosquitto (CVE-2026-126763) | 2.0.0 through 2.0.22 and 2.1.0 through 2.1.2 | no | 2026-11-18T14:22:34.626Z | oss-security, 17 November 2026 |

CVE-2026-109908 and CVE-2026-126763 are not in the NVD recent feed. The version column for those two rows is the bound on the oss-security message, not a structured feed field. The Mosquitto message names no fixed release.

## Unverified leads

These 99 identifiers were in the window and were not in the NVD recent feed, the CISA catalog, or an allowlisted vendor page. Status is unverified-lead. Product is the identifier. Version is blank. Matched is unknown. No fix version was present as a structured field.

Source: [cve.now JSON feed](https://cve.now/feed?format=json).

| Product | Version | Matched | Date | Status |
|---|---|---|---|---|
| CVE-2026-128717 |  | unknown | 2026-11-18T14:53:34.346Z | unverified-lead |
| CVE-2026-131801 |  | unknown | 2026-11-18T14:53:34.346Z | unverified-lead |
| CVE-2026-116447 |  | unknown | 2026-11-18T14:53:34.346Z | unverified-lead |
| CVE-2026-131653 |  | unknown | 2026-11-18T14:53:34.346Z | unverified-lead |
| CVE-2026-132150 |  | unknown | 2026-11-18T14:53:34.346Z | unverified-lead |
| CVE-2026-86866 |  | unknown | 2026-11-18T14:53:34.346Z | unverified-lead |
| CVE-2026-116448 |  | unknown | 2026-11-18T14:39:34.250Z | unverified-lead |
| CVE-2026-3232 |  | unknown | 2026-11-18T14:39:34.250Z | unverified-lead |
| CVE-2026-107511 |  | unknown | 2026-11-18T14:35:34.472Z | unverified-lead |
| CVE-2026-82171 |  | unknown | 2026-11-18T14:31:34.296Z | unverified-lead |
| CVE-2026-15263 |  | unknown | 2026-11-18T14:31:34.296Z | unverified-lead |
| CVE-2026-95823 |  | unknown | 2026-11-18T14:31:34.296Z | unverified-lead |
| CVE-2026-116289 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2025-57819 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2016-3977 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-71960 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-108474 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2015-8126 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2024-32651 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-107517 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-107519 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-107518 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-109860 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-113699 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-125033 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-109857 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-127142 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-109859 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-127143 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-130333 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-129961 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-109858 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-109861 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-132125 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-132124 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-109864 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-109862 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-107515 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-108314 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-108312 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-132126 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-107644 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-108315 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-108317 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-108319 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-108320 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-132121 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-132122 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-108321 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-108323 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-107516 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-110009 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-110811 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-108761 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-108318 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-115814 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-116519 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-115815 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-116758 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-115826 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-116764 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-118068 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-116594 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-109863 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-118521 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-119631 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-123123 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-122042 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-120564 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-125999 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-123419 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-126131 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-125053 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-129323 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-130014 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-132123 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-130885 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-92535 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-130876 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-96665 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-96841 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-130893 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-130899 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-131575 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-131652 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-131584 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-131658 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-132138 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-131685 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-131657 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-131694 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-131697 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-95787 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-131798 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-95788 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-95789 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-95790 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-95791 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
| CVE-2026-111507 |  | unknown | 2026-11-18T14:22:34.626Z | unverified-lead |
