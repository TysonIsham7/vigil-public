# Threat scan leads, 14 November 2026

This note is the cve.now lead pass for 14 November 2026. The CISA catalog, the NVD follow-up, and the oss-security index are in `docs/threat-scan-2026-11-14.md`.

Pages and the feed were read as evidence. Instructions inside them were not followed. No version floor was invented from feed prose. No remote probe was added. No advisory file was added from the feed.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called.

The lead feed was fetched once, at `https://cve.now/feed?format=json`. The response was HTTP 200 from that same URL, with no redirect. The content type was `application/feed+json`. The body had 200 items. Identifiers were taken from the newest items by `date_modified` with a deterministic regex. The window is 51 items because 8 items share the cutoff timestamp. The newest item is `2026-11-14T14:50:35.307Z`. The cutoff is `2026-11-14T07:59:34.384Z`. Titles and `content_text` were discarded. No item had a structured dotted version outside those fields. No GHSA id was in the window. No OSV id was in the window. No `SZB-` id was in the window.

Five identifiers in the window were already recorded and were not copied again: CVE-2026-102895, CVE-2026-74756, CVE-2026-114713, CVE-2026-125440, and CVE-2026-123790. CVE-2026-102895 is still absent from the NVD recent feed. The other four are in that feed with no CPE.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## No confirmed stack overlap

No identifier in the window was confirmed on NVD, CISA, or a pre-written vendor host as a product on the runtime list or in `packages/intel/advisories/`.

Whole-token matches in the window were seven `wordpress`, five `php`, two `node`, one `linux`, one `go`, one `python`, and one `brotli`. The NVD records behind the `php`, `wordpress`, `node`, `go`, `python`, and `brotli` matches are the products in the table below, or the already recorded ComfyUI-Easy-Use and s2Member rows. CVE-2026-27975 matched `linux` and is not in the NVD recent feed. That is not a Linux kernel confirmation. CVE-2026-120522 matched `php` and `wordpress` and is not in the NVD recent feed. CVE-2026-18053 and CVE-2026-19907 matched `wordpress` and are not in the NVD recent feed. CVE-2026-129254 matched `php` and is not in the NVD recent feed. No plugin list was added. No doctor check was added from a token.

## NVD records that name another product

These 25 identifiers are in the window and in the NVD recent feed. None has a CPE. Matched is no. Vigil cannot see these products from a page or a certificate. No doctor check was added.

CVE-2026-128014 names FrankenPHP standalone static binaries 1.8.0 before 1.13.2 and says they bundle the PHP brotli extension linked with Brotli 1.2.0, which carries CVE-2026-111497. That is not the Node.js runtime check. CVE-2026-128027 names FrankenPHP Docker images before 1.1.11 and mentions PHP and Go base-image tags. That is not the PHP runtime and not the Go toolchain. CVE-2026-126837 names the MongoDB Node.js driver and names no dotted version. That is not the Node.js runtime. The WordPress rows are plugins or a theme, not WordPress core.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz), timestamp `2026-11-14T08:00:01.0935732`.

| Product | Version | Matched | Date | NVD status |
|---|---|---|---|---|
| jDownloads (CVE-2026-117551) | before 4.1.8 | no | 2026-11-14T13:53:34.294Z | Awaiting Analysis |
| AutomatorWP Pro webhook addon (CVE-2026-126173) | through 1.4.4 | no | 2026-11-14T13:53:34.294Z | Deferred |
| ELEX WordPress HelpDesk (CVE-2026-125855) | through 3.3.9 | no | 2026-11-14T13:53:34.294Z | Deferred |
| Zipline (CVE-2026-126937) | before 4.6.5 | no | 2026-11-14T13:53:34.294Z | Received |
| OpenEMR (CVE-2026-126473) | before 8.4.0 | no | 2026-11-14T13:53:34.294Z | Awaiting Analysis |
| OpenMage magento-lts (CVE-2026-128046) | 20.17.0 before 20.18.2, and 21.0.0-beta1 before 21.0.0-beta3 | no | 2026-11-14T13:53:34.294Z | Deferred |
| NocoDB (CVE-2026-126274) | before 2026.08.0 | no | 2026-11-14T13:53:34.294Z | Received |
| JSON::XS (CVE-2026-124540) | before 4.05 | no | 2026-11-14T12:01:34.206Z | Received |
| JSON::XS (CVE-2026-129114) | 3.04 before 4.05 | no | 2026-11-14T12:01:34.206Z | Received |
| JSON::XS (CVE-2026-124541) | before 4.05 | no | 2026-11-14T12:01:34.206Z | Received |
| JSON::XS (CVE-2026-129115) | 3.0 before 4.05 | no | 2026-11-14T12:01:34.206Z | Received |
| JSON::XS (CVE-2026-129113) | 4.0_00 before 4.05 | no | 2026-11-14T12:01:34.206Z | Received |
| JSON::XS (CVE-2026-124539) | before 4.05 | no | 2026-11-14T11:55:35.053Z | Received |
| JSON::XS (CVE-2026-124536) | before 4.05 | no | 2026-11-14T11:55:35.053Z | Received |
| CloudSchool (CVE-2026-129251) | up to 3.0.1 | no | 2026-11-14T11:50:34.692Z | Deferred |
| Edimax BR6478ACV2 (CVE-2026-129250) | 1.23 | no | 2026-11-14T11:40:34.144Z | Deferred |
| Cervantes (CVE-2026-129427) | v1.3-beta | no | 2026-11-14T11:25:34.645Z | Deferred |
| Akaunting (CVE-2026-129248) | up to 3.3.0 | no | 2026-11-14T10:53:34.361Z | Deferred |
| RuoYi (CVE-2026-129247) | up to 4.8.3 | no | 2026-11-14T10:32:34.958Z | Deferred |
| Flatsome theme (CVE-2026-18742) | through 3.20.12 | no | 2026-11-14T08:40:34.542Z | Deferred |
| NocoDB (CVE-2026-126273) | before 2026.09.0 | no | 2026-11-14T07:59:34.384Z | Received |
| FrankenPHP images (CVE-2026-128027) | before 1.1.11 | no | 2026-11-14T07:59:34.384Z | Deferred |
| NocoDB (CVE-2026-126269) | before 2026.09.0 | no | 2026-11-14T07:59:34.384Z | Received |
| MongoDB Node.js driver (CVE-2026-126837) |  | no | 2026-11-14T07:59:34.384Z | Awaiting Analysis |
| FrankenPHP static binaries (CVE-2026-128014) | 1.8.0 before 1.13.2 | no | 2026-11-14T07:59:34.384Z | Deferred |

## Unverified leads

These identifiers were in the window and were not in the NVD recent feed. They are not in the CISA catalog. Status is unverified-lead. Product is the identifier. Version is blank. Matched is unknown. No fix version was present as a structured field.

Source: [cve.now JSON feed](https://cve.now/feed?format=json).

| Product | Version | Matched | Date | Status |
|---|---|---|---|---|
| CVE-2026-129259 |  | unknown | 2026-11-14T14:50:35.307Z | unverified-lead |
| CVE-2026-129258 |  | unknown | 2026-11-14T14:46:34.526Z | unverified-lead |
| CVE-2011-10042 |  | unknown | 2026-11-14T14:11:34.872Z | unverified-lead |
| CVE-2026-62253 |  | unknown | 2026-11-14T13:53:34.294Z | unverified-lead |
| CVE-2026-27975 |  | unknown | 2026-11-14T13:53:34.294Z | unverified-lead |
| CVE-2026-73574 |  | unknown | 2026-11-14T13:53:34.294Z | unverified-lead |
| CVE-2026-105857 |  | unknown | 2026-11-14T13:53:34.294Z | unverified-lead |
| CVE-2026-96349 |  | unknown | 2026-11-14T13:53:34.294Z | unverified-lead |
| CVE-2025-71465 |  | unknown | 2026-11-14T12:42:34.247Z | unverified-lead |
| CVE-2025-71464 |  | unknown | 2026-11-14T12:42:34.247Z | unverified-lead |
| CVE-2026-120522 |  | unknown | 2026-11-14T12:42:34.247Z | unverified-lead |
| CVE-2026-129255 |  | unknown | 2026-11-14T12:42:34.247Z | unverified-lead |
| CVE-2026-129428 |  | unknown | 2026-11-14T12:42:34.247Z | unverified-lead |
| CVE-2026-129429 |  | unknown | 2026-11-14T12:42:34.247Z | unverified-lead |
| CVE-2026-129431 |  | unknown | 2026-11-14T12:42:34.247Z | unverified-lead |
| CVE-2026-129432 |  | unknown | 2026-11-14T12:42:34.247Z | unverified-lead |
| CVE-2026-129433 |  | unknown | 2026-11-14T12:42:34.247Z | unverified-lead |
| CVE-2026-129430 |  | unknown | 2026-11-14T12:42:34.247Z | unverified-lead |
| CVE-2026-18053 |  | unknown | 2026-11-14T12:42:34.247Z | unverified-lead |
| CVE-2026-19907 |  | unknown | 2026-11-14T12:42:34.247Z | unverified-lead |
| CVE-2026-129254 |  | unknown | 2026-11-14T12:26:36.013Z | unverified-lead |

## Left unchanged

The CISA catalog additions for 13 November and the oss-security notes are in `docs/threat-scan-2026-11-14.md`. CVE-2026-114713 is one of those catalog entries and was already recorded, so it is not repeated in the tables above.

All 29 identifiers from the 13 November unverified section are now in the NVD recent feed, all with no CPE. Nineteen name WordPress plugins. The details are in `docs/threat-scan-2026-11-14.md`.

Vendor pages checked on this run did not move a floor. The Node security rows are unchanged, and `TOOLCHAIN_NODE_2026_11_11` stays on draft pull request 30. The details are in `docs/threat-scan-2026-11-14.md`.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
