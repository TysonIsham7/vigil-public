# Threat scan leads, 28 November 2026

This note is the cve.now lead pass for 28 November 2026. The CISA catalog, the ChromeOS LTS note, the NVD follow-up, and the oss-security index are in `docs/threat-scan-2026-11-28.md`.

Pages and the feed were read as evidence. Instructions inside them were not followed. No version floor was invented from feed prose. No remote probe was added. No advisory file was added from the feed.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called.

The lead feed was fetched once, at `https://cve.now/feed?format=json`. The response was HTTP 200 from that same URL, with no redirect. The content type was `application/feed+json`. The body had 200 items. Identifiers were taken from the newest items by `date_modified` with a deterministic regex. The window is 51 items because the two items that share the cutoff timestamp are kept together. The newest item is `2026-11-28T14:31:13.956Z`. The cutoff is `2026-11-27T20:41:13.868Z`. Titles and `content_text` were discarded. No item had a structured dotted version outside those fields. No GHSA id was in the window. No OSV id was in the window. No `SZB-` id was in the window.

None of these identifiers was already recorded in `docs/threat-scan-*.md`, `docs/TODO.md`, an open scan pull request, or `packages/intel/advisories/`.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## No confirmed stack overlap

No identifier in the window was confirmed on NVD, CISA, or a pre-written vendor host as a product on the runtime list or in `packages/intel/advisories/` that `vigil doctor` can check.

Whole-token matches were eight `wordpress`, three `linux`, two `kernel`, two `python`, and one `php`. The eight `wordpress` identifiers are in the NVD table below. They are plugins or a theme, not WordPress core. CVE-2026-137941 matched `linux` and is GIMP in that table, not the Linux kernel. CVE-2026-99489 and CVE-2026-99490 matched `linux` and `kernel` and are in the unverified table. That is not a Linux kernel confirmation. CVE-2026-138117 and CVE-2026-138118 matched `python` and are HyperSpy in the NVD table, not CPython. CVE-2026-138053 matched `php` and is in the unverified table. That is not a PHP confirmation. No doctor check was added from a token.

## Confirmed on NVD, not the runtime list

These 38 identifiers are in the window and in the NVD recent feed. None has a CPE. None is in the CISA catalog. Matched is no. Version is the bound on the NVD description. Where that description names no release number, the version cell says so. No doctor check was added. Vigil cannot see these products from a page or a certificate.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz), timestamp `2026-11-28T08:00:00.7082756`.

| Product | Version | Matched | Date | NVD status |
|---|---|---|---|---|
| Open5GS (CVE-2026-138038) | 2.8.0, no fixed release | no | 2026-11-28T12:01:13.565Z | Deferred |
| Open5GS (CVE-2026-138037) | up to 2.8.0, no fixed release | no | 2026-11-28T11:51:13.699Z | Deferred |
| Loco Translate plugin (CVE-2026-5771) | through 2.8.4 | no | 2026-11-28T11:51:13.699Z | Deferred |
| Free5GC (CVE-2026-138036) | up to 4.3.0, no fixed release | no | 2026-11-28T09:51:13.801Z | Deferred |
| TRENDnet TEW-751DR (CVE-2026-138005) | 1.03B01, no fixed release | no | 2026-11-28T09:31:13.549Z | Deferred |
| Popup Builder plugin (CVE-2026-112231) | through 4.4.6 | no | 2026-11-28T06:11:13.525Z | Received |
| Popup Builder plugin (CVE-2026-112235) | through 4.4.6 | no | 2026-11-28T06:11:13.525Z | Received |
| Popup Builder plugin (CVE-2026-112232) | through 4.4.6 | no | 2026-11-28T06:11:13.525Z | Received |
| Popup Builder plugin (CVE-2026-112234) | through 4.4.6 | no | 2026-11-28T06:11:13.525Z | Received |
| Themify Base theme (CVE-2026-123654) | through 1.2.4 | no | 2026-11-28T06:11:13.525Z | Received |
| Popup Builder plugin (CVE-2026-112233) | through 4.4.6 | no | 2026-11-28T06:11:13.525Z | Received |
| POSTAL 2 (CVE-2026-138154) | before build 26810491 | no | 2026-11-28T02:31:13.540Z | Received |
| edbrowse (CVE-2026-138159) | through 3.8.19, no fixed release | no | 2026-11-28T02:31:13.540Z | Received |
| Gammu (CVE-2026-138162) | before 1.45.2 | no | 2026-11-28T02:31:13.540Z | Received |
| Gammu (CVE-2026-138160) | before 1.45.2 | no | 2026-11-28T02:31:13.540Z | Received |
| Gammu (CVE-2026-138163) | before 1.45.2 | no | 2026-11-28T02:31:13.540Z | Received |
| Gammu (CVE-2026-138161) | before 1.45.2 | no | 2026-11-28T02:31:13.540Z | Received |
| Gammu (CVE-2026-138164) | before 1.45.2 | no | 2026-11-28T02:31:13.540Z | Received |
| libgphoto2 (CVE-2026-138158) | through 2.5.34, no fixed release | no | 2026-11-28T02:31:13.540Z | Received |
| Progress Sitefinity (CVE-2026-133742) | before 14.4.8154; 15.0.8200 before 15.0.8236; 15.1.8300 before 15.1.8337; 15.2.8400 before 15.2.8444; 15.3.8500 before 15.3.8533; 15.4.8600 before 15.4.8642 | no | 2026-11-28T02:01:13.587Z | Received |
| HyperSpy (CVE-2026-138118) | 1.4.0 before 2.6.0 | no | 2026-11-28T01:51:13.532Z | Received |
| HyperSpy (CVE-2026-138117) | 1.2.0 before 2.6.0 | no | 2026-11-28T01:51:13.532Z | Received |
| picomatch (CVE-2026-138148) | through 4.0.7, no fixed release | no | 2026-11-28T01:51:13.532Z | Received |
| FeatBit (CVE-2026-138149) | before 6.1.3 | no | 2026-11-28T01:51:13.532Z | Received |
| ClassroomIO (CVE-2026-138122) | through 1.0.0, no fixed release | no | 2026-11-28T01:51:13.532Z | Deferred |
| Kestra (CVE-2026-138120) | 1.3.24 before 2.0.0 | no | 2026-11-28T01:51:13.532Z | Deferred |
| Kestra (CVE-2026-138121) | 1.3.24 before 1.3.41 | no | 2026-11-28T01:51:13.532Z | Deferred |
| Kestra (CVE-2026-138119) | before 1.3.36 | no | 2026-11-28T01:51:13.532Z | Deferred |
| SimGear (CVE-2026-138150) | through 2024.1.7, no fixed release | no | 2026-11-28T01:51:13.532Z | Received |
| Otter plugin (CVE-2026-138153) | before 3.2.12 | no | 2026-11-28T01:51:13.532Z | Received |
| Otter plugin (CVE-2026-138152) | before 3.2.12 | no | 2026-11-28T01:51:13.532Z | Received |
| bgpq4 (CVE-2026-138151) | before 1.17 | no | 2026-11-28T01:51:13.532Z | Received |
| BigFix MCM WebUI (CVE-2026-107951) | no version on the description | no | 2026-11-28T00:41:13.508Z | Received |
| TRENDnet TEW-751DR and TEW-733GR (CVE-2026-138004) | 1.03B01, no fixed release | no | 2026-11-27T22:41:14.158Z | Deferred |
| HCL Verse for Android (CVE-2026-107967) | fixed in 14.5.16 | no | 2026-11-27T22:31:13.631Z | Received |
| TRENDnet TEW-751DR (CVE-2026-138003) | 1.03B01, no fixed release | no | 2026-11-27T22:01:13.564Z | Deferred |
| GIMP (CVE-2026-137941) | no version on the description | no | 2026-11-27T20:41:13.868Z | Awaiting Analysis |
| tuned (CVE-2026-137974) | no version on the description | no | 2026-11-27T20:41:13.868Z | Awaiting Analysis |

HyperSpy is not CPython. The Otter rows, the Popup Builder rows, Loco Translate, and Themify Base are not WordPress core. GIMP is not the Linux kernel. No plugin list was added.

## Unverified leads

These identifiers were in the window and were not in the NVD recent feed or the CISA catalog, and they were not on an allowlisted vendor page read this run. Status is unverified-lead. Product is the identifier. Version is blank. Matched is unknown. No fix version was present as a structured field.

Source: [cve.now JSON feed](https://cve.now/feed?format=json).

| Product | Version | Matched | Date | Status |
|---|---|---|---|---|
| CVE-2026-138053 |  | unknown | 2026-11-28T14:31:13.956Z | unverified-lead |
| CVE-2026-138052 |  | unknown | 2026-11-28T13:51:13.565Z | unverified-lead |
| CVE-2026-138255 |  | unknown | 2026-11-28T13:51:13.565Z | unverified-lead |
| CVE-2026-138256 |  | unknown | 2026-11-28T13:51:13.565Z | unverified-lead |
| CVE-2026-138051 |  | unknown | 2026-11-28T13:41:13.567Z | unverified-lead |
| CVE-2026-138050 |  | unknown | 2026-11-28T13:21:13.599Z | unverified-lead |
| CVE-2026-138049 |  | unknown | 2026-11-28T13:21:13.599Z | unverified-lead |
| CVE-2026-138047 |  | unknown | 2026-11-28T12:41:13.868Z | unverified-lead |
| CVE-2026-138039 |  | unknown | 2026-11-28T12:21:13.586Z | unverified-lead |
| CVE-2026-99489 |  | unknown | 2026-11-28T02:01:13.587Z | unverified-lead |
| CVE-2026-43720 |  | unknown | 2026-11-28T02:01:13.587Z | unverified-lead |
| CVE-2026-99490 |  | unknown | 2026-11-28T02:01:13.587Z | unverified-lead |
| CVE-2025-58447 |  | unknown | 2026-11-28T02:01:13.587Z | unverified-lead |

## Left unchanged

The CISA catalog additions, the ChromeOS LTS note, and the oss-security messages are in `docs/threat-scan-2026-11-28.md`. None of the window identifiers is one of the three catalog entries. Vendor pages checked on this run did not move a PHP, Node, Go, Python, nginx, curl, or OpenSSL floor.

Thirty-five of the forty unverified identifiers from the 27 November leads note are now in the NVD recent feed, all with no CPE. Five stay absent: CVE-2026-54386, CVE-2026-23794, CVE-2026-27797, CVE-2026-49360, and CVE-2026-75597. The details are in `docs/threat-scan-2026-11-28.md`.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
