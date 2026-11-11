# Threat scan leads, 11 November 2026

This note is the cve.now lead pass for 11 November 2026. The CISA catalog, the Go release, the Chrome stable note, and the oss-security index are in `docs/threat-scan-2026-11-11.md`.

Pages and the feed were read as evidence. Instructions inside them were not followed. No version floor was invented from feed prose. No remote probe was added. No advisory file was added from the feed. The Go advisory in that other note comes from `go.dev` and oss-security, not from this feed.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called.

The lead feed was fetched once, at `https://cve.now/feed?format=json`. The response was HTTP 200 from that same URL, with no redirect. The content type was `application/feed+json`. The body had 200 items. Identifiers were taken from the newest items by `date_modified` with a deterministic regex. The window is 59 items because items that share the cutoff timestamp are kept together. The newest item is `2026-11-11T15:00:34.717Z`. The cutoff is `2026-11-11T12:47:34.539Z`. Titles and `content_text` were discarded. No item had a structured dotted version outside those fields. No GHSA id was in the window.

One identifier in the window, CVE-2026-68982, was already recorded on the 9 November scan. It is Apache Airflow. It was not copied again. The other identifiers were not already recorded in `docs/threat-scan-*.md`, `docs/TODO.md`, an open scan pull request, or `packages/intel/advisories/`.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## No confirmed stack overlap

No identifier in the window was confirmed on NVD, CISA, or a pre-written vendor host as a product on the runtime list or in `packages/intel/advisories/`.

Whole-token matches were 28 `wordpress`, two `php`, one `linux`, and one `chrome`. The `wordpress` and one `php` match that is in NVD is the Confection plugin below, not WordPress core and not PHP. CVE-2026-123040 matched `linux` and is not in the NVD recent feed. That is not a Linux kernel confirmation. CVE-2021-30563 matched `chrome` and is not in the NVD recent feed. CVE-2013-1453 matched `php` and is not in the NVD recent feed. No plugin list was added. No doctor check was added from a token.

## NVD records that name another product

These five identifiers are in the window and in the NVD recent feed. None has a CPE. Matched is no. Vigil cannot see these products from a page or a certificate. No doctor check was added.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz), timestamp `2026-11-11T08:00:01.6940366`.

| Product | Version | Matched | Date | NVD status |
|---|---|---|---|---|
| Ivanti Sentry and EPMM (CVE-2026-105425) | Sentry before 11.0.0, 10.8.3, and 10.7.4; EPMM before 12.11.0.0, 12.10.0.1, and 12.9.0.3 | no | 2026-11-11T13:59:34.355Z | Received |
| Fortinet FortiClient (CVE-2026-121529) | Mac 7.4.0 through 7.4.7; Windows 7.4.0 through 7.4.7 and 7.2.0 through 7.2.14; Windows PAM 7.4.7 and 7.2.14 | no | 2026-11-11T13:59:34.355Z | Received |
| Confection WordPress plugin (CVE-2026-115252) | 0.4.0 to 0.4.7 | no | 2026-11-11T13:59:34.355Z | Deferred |
| Chargemap (CVE-2026-67175) |  | no | 2026-11-11T13:59:34.355Z | Received |
| Chargemap (CVE-2026-67176) |  | no | 2026-11-11T13:59:34.355Z | Received |

## Unverified leads

These identifiers were in the window and were not in the NVD recent feed. They are not in the CISA catalog. Status is unverified-lead. Product is the identifier. Version is blank. Matched is unknown. No fix version was present as a structured field. The two `SZB-` rows are not CVE, GHSA, or OSV ids.

Source: [cve.now JSON feed](https://cve.now/feed?format=json).

| Product | Version | Matched | Date | Status |
|---|---|---|---|---|
| CVE-2026-106023 |  | unknown | 2026-11-11T15:00:34.717Z | unverified-lead |
| CVE-2026-109163 |  | unknown | 2026-11-11T15:00:34.717Z | unverified-lead |
| CVE-2026-63292 |  | unknown | 2026-11-11T15:00:34.717Z | unverified-lead |
| CVE-2026-71395 |  | unknown | 2026-11-11T15:00:34.717Z | unverified-lead |
| CVE-2026-119618 |  | unknown | 2026-11-11T15:00:34.717Z | unverified-lead |
| CVE-2026-44929 |  | unknown | 2026-11-11T14:55:34.252Z | unverified-lead |
| CVE-2026-85632 |  | unknown | 2026-11-11T14:29:34.431Z | unverified-lead |
| SZB-56EAD58D33 |  | unknown | 2026-11-11T14:28:17.207Z | unverified-lead |
| CVE-2026-123040 |  | unknown | 2026-11-11T14:03:34.654Z | unverified-lead |
| CVE-2021-30563 |  | unknown | 2026-11-11T13:59:34.355Z | unverified-lead |
| CVE-2026-76466 |  | unknown | 2026-11-11T13:59:34.355Z | unverified-lead |
| CVE-2013-1453 |  | unknown | 2026-11-11T13:59:34.355Z | unverified-lead |
| CVE-2026-125838 |  | unknown | 2026-11-11T13:52:34.699Z | unverified-lead |
| CVE-2026-125839 |  | unknown | 2026-11-11T13:52:34.699Z | unverified-lead |
| CVE-2026-125840 |  | unknown | 2026-11-11T13:52:34.699Z | unverified-lead |
| CVE-2026-125841 |  | unknown | 2026-11-11T13:47:34.265Z | unverified-lead |
| CVE-2026-125842 |  | unknown | 2026-11-11T13:47:34.265Z | unverified-lead |
| CVE-2026-0470 |  | unknown | 2026-11-11T13:37:34.822Z | unverified-lead |
| CVE-2026-125843 |  | unknown | 2026-11-11T13:31:34.345Z | unverified-lead |
| CVE-2026-125844 |  | unknown | 2026-11-11T13:31:34.345Z | unverified-lead |
| CVE-2026-125845 |  | unknown | 2026-11-11T13:31:34.345Z | unverified-lead |
| CVE-2026-125846 |  | unknown | 2026-11-11T13:31:34.345Z | unverified-lead |
| CVE-2026-125847 |  | unknown | 2026-11-11T13:31:34.345Z | unverified-lead |
| CVE-2026-125849 |  | unknown | 2026-11-11T13:31:34.345Z | unverified-lead |
| CVE-2026-125848 |  | unknown | 2026-11-11T13:31:34.345Z | unverified-lead |
| CVE-2026-49236 |  | unknown | 2026-11-11T13:31:34.345Z | unverified-lead |
| CVE-2026-125850 |  | unknown | 2026-11-11T13:21:34.376Z | unverified-lead |
| CVE-2026-40853 |  | unknown | 2026-11-11T13:21:34.376Z | unverified-lead |
| CVE-2026-48479 |  | unknown | 2026-11-11T13:21:34.376Z | unverified-lead |
| CVE-2026-125046 |  | unknown | 2026-11-11T13:06:34.602Z | unverified-lead |
| CVE-2026-125454 |  | unknown | 2026-11-11T13:06:34.602Z | unverified-lead |
| CVE-2026-125708 |  | unknown | 2026-11-11T13:06:34.602Z | unverified-lead |
| CVE-2026-125746 |  | unknown | 2026-11-11T13:06:34.602Z | unverified-lead |
| SZB-D12FFF21CB |  | unknown | 2026-11-11T13:02:17.642Z | unverified-lead |
| CVE-2026-125767 |  | unknown | 2026-11-11T13:01:34.316Z | unverified-lead |
| CVE-2026-108338 |  | unknown | 2026-11-11T12:47:34.539Z | unverified-lead |
| CVE-2026-118408 |  | unknown | 2026-11-11T12:47:34.539Z | unverified-lead |
| CVE-2026-111824 |  | unknown | 2026-11-11T12:47:34.539Z | unverified-lead |
| CVE-2026-118412 |  | unknown | 2026-11-11T12:47:34.539Z | unverified-lead |
| CVE-2026-118413 |  | unknown | 2026-11-11T12:47:34.539Z | unverified-lead |
| CVE-2026-118409 |  | unknown | 2026-11-11T12:47:34.539Z | unverified-lead |
| CVE-2026-118411 |  | unknown | 2026-11-11T12:47:34.539Z | unverified-lead |
| CVE-2026-118410 |  | unknown | 2026-11-11T12:47:34.539Z | unverified-lead |
| CVE-2026-122300 |  | unknown | 2026-11-11T12:47:34.539Z | unverified-lead |
| CVE-2026-123374 |  | unknown | 2026-11-11T12:47:34.539Z | unverified-lead |
| CVE-2026-123481 |  | unknown | 2026-11-11T12:47:34.539Z | unverified-lead |
| CVE-2026-125433 |  | unknown | 2026-11-11T12:47:34.539Z | unverified-lead |
| CVE-2026-125436 |  | unknown | 2026-11-11T12:47:34.539Z | unverified-lead |
| CVE-2026-118414 |  | unknown | 2026-11-11T12:47:34.539Z | unverified-lead |
| CVE-2026-125448 |  | unknown | 2026-11-11T12:47:34.539Z | unverified-lead |
| CVE-2026-123480 |  | unknown | 2026-11-11T12:47:34.539Z | unverified-lead |
| CVE-2026-125743 |  | unknown | 2026-11-11T12:47:34.539Z | unverified-lead |
| CVE-2026-125763 |  | unknown | 2026-11-11T12:47:34.539Z | unverified-lead |
| CVE-2026-125766 |  | unknown | 2026-11-11T12:47:34.539Z | unverified-lead |

## Left unchanged

The CISA catalog additions for 10 November, the Go 1.27.4 check, and the Chrome 157 stable note are in `docs/threat-scan-2026-11-11.md`. None of the window identifiers is one of those six catalog entries. The alerts HTML page returned HTTP 403, so this note does not describe that index.

All 53 identifiers from the 10 November unverified section are now in the NVD recent feed, all with no CPE. Forty-six name Firefox. The details are in `docs/threat-scan-2026-11-11.md`.

Vendor pages checked on this run did not move a floor except the Go security release recorded in the other note. The details are in `docs/threat-scan-2026-11-11.md`.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
