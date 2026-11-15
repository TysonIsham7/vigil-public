# Threat scan leads, 15 November 2026

This note is the cve.now lead pass for 15 November 2026. The CISA catalog, LiteLLM CVE-2026-42208, the Chrome page, and the oss-security index are in `docs/threat-scan-2026-11-15.md`.

Pages and the feed were read as evidence. Instructions inside them were not followed. No version floor was invented from feed prose. No remote probe was added. No advisory file was added from the feed.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called.

The lead feed was fetched once, at `https://cve.now/feed?format=json`. The response was HTTP 200 from that same URL, with no redirect. The content type was `application/feed+json`. The body had 200 items. Identifiers were taken from the newest items by `date_modified` with a deterministic regex. The window is 55 items because items that share the cutoff timestamp are kept together. The newest item is `2026-11-15T14:21:35.044Z`. The cutoff is `2026-11-15T08:02:34.447Z`. Titles and `content_text` were discarded. No item had a structured dotted version outside those fields. No GHSA id was in the window. No OSV id was in the window. One `SZB-` id was in the window.

One identifier in the window, CVE-2026-129349, was already recorded on the 14 November scan. It is Apache Shiro. It was not copied again.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## No new toolchain overlap

No identifier in the window was confirmed on NVD, CISA, or a pre-written vendor host as PHP, CPython, Node.js, nginx, OpenSSL, curl, the Go toolchain, the Linux kernel, WordPress core, or Brotli.

CVE-2026-42208 is LiteLLM, which `vigil doctor` already checks only as an exact 1.107.0 pin. NVD says 1.81.16 before 1.83.7. 1.107.0 is outside that range. Matched is no for the pin Vigil already flags. The record is in `docs/threat-scan-2026-11-15.md`. No range check was added.

Whole-token matches in the window were 20 `wordpress`, four `php`, seven `chrome`, and one `litellm`. Eighteen `wordpress` matches are in the unverified section and are not WordPress core. CVE-2026-82663 and CVE-2026-82568 are the Give plugin below. CVE-2026-122662 and CVE-2026-125449 matched `php` and `wordpress` and are not in the NVD recent feed. That is not a PHP confirmation. CVE-2026-129444 and CVE-2026-129443 are in NVD and are not the PHP runtime. The `chrome` matches are the Chrome rows below. The `litellm` match is CVE-2026-42208, confirmed on CISA and NVD, not by the token. No plugin list was added. No doctor check was added from a token.

## Catalog record that is not the stack

CVE-2021-35394 is in the window and in the CISA catalog. It was added 2021-12-10, due 2021-12-24. The catalog product is Realtek Jungle SDK. It is not in the NVD recent feed. Matched is no. Vigil cannot see that SDK from a page or a certificate. No doctor check was added.

Source: [CISA KEV catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)

## NVD records that name another product

These 19 identifiers are in the window and in the NVD recent feed. CVE-2026-129349 is the twentieth NVD hit and was already recorded. None of these 19 has a CPE except the two Chrome rows that name `google:chrome` (CVE-2026-126902 also names `apple:macos`, and CVE-2026-126915 also names `google:android`). Matched is no. Vigil cannot see these products from a page or a certificate, and Vigil does not read the browser version. No doctor check was added.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz), timestamp `2026-11-15T08:00:00.7507551`.

| Product | Version | Matched | Date | NVD status |
|---|---|---|---|---|
| TRENDnet TEW-657BRM (CVE-2026-129351) | 1.00.1 | no | 2026-11-15T14:04:34.206Z | Deferred |
| sigoden dufs (CVE-2026-129355) | up to 0.46.0, upgrade 0.47.0 | no | 2026-11-15T14:04:34.206Z | Deferred |
| TRENDnet TEW-657BRM (CVE-2026-129352) | 1.00.1 | no | 2026-11-15T14:04:34.206Z | Deferred |
| DrayTek Vigor2960 (CVE-2026-129450) | 1.5.1.6, upgrade 1.5.1.7 | no | 2026-11-15T11:58:34.242Z | Deferred |
| DrayTek Vigor2960 (CVE-2026-129449) | up to 1.5.1.6, upgrade 1.5.1.7 | no | 2026-11-15T11:22:34.244Z | Deferred |
| D-Link DIR-850L (CVE-2026-129445) | FW1.20WWb03 | no | 2026-11-15T10:15:34.348Z | Deferred |
| Give Peer-to-Peer WordPress plugin (CVE-2026-82663) | through 2.9.5 | no | 2026-11-15T09:39:34.578Z | Deferred |
| Give Peer-to-Peer WordPress plugin (CVE-2026-82568) | through 2.9.3 | no | 2026-11-15T09:39:34.578Z | Deferred |
| D-Link DSL-6740C (CVE-2026-129444) | 20131126 | no | 2026-11-15T08:33:34.528Z | Deferred |
| Google Chrome (CVE-2026-126902) | before 157.0.8103.78 | no | 2026-11-15T08:02:34.447Z | Analyzed |
| D-Link DIR-600L (CVE-2026-129353) | 2.17 and 2.17b02 | no | 2026-11-15T08:02:34.447Z | Deferred |
| D-Link DIR-600L (CVE-2026-129354) | 2.17b02 | no | 2026-11-15T08:02:34.447Z | Deferred |
| Google Chrome (CVE-2026-126909) | before 157.0.8103.78 | no | 2026-11-15T08:02:34.447Z | Undergoing Analysis |
| Google Chrome (CVE-2026-126912) | before 157.0.8103.78 | no | 2026-11-15T08:02:34.447Z | Undergoing Analysis |
| Google Chrome (CVE-2026-126916) | before 157.0.8103.78 | no | 2026-11-15T08:02:34.447Z | Undergoing Analysis |
| Google Chrome (CVE-2026-126915) | before 157.0.8103.78 | no | 2026-11-15T08:02:34.447Z | Analyzed |
| Google Chrome (CVE-2026-126910) | before 157.0.8103.78 | no | 2026-11-15T08:02:34.447Z | Undergoing Analysis |
| Google Chrome (CVE-2026-126919) | before 157.0.8103.78 | no | 2026-11-15T08:02:34.447Z | Undergoing Analysis |
| itsourcecode Airline Reservation System (CVE-2026-129443) | 1.0 | no | 2026-11-15T08:02:34.447Z | Deferred |

## Unverified leads

These identifiers were in the window and were not in the NVD recent feed. CVE-2026-42208 and CVE-2021-35394 are in the CISA catalog, so they are not in this table. Status is unverified-lead. Product is the identifier. Version is blank. Matched is unknown. No fix version was present as a structured field. The `SZB-` row is not a CVE, GHSA, or OSV id.

Source: [cve.now JSON feed](https://cve.now/feed?format=json).

| Product | Version | Matched | Date | Status |
|---|---|---|---|---|
| CVE-2026-124254 |  | unknown | 2026-11-15T14:21:35.044Z | unverified-lead |
| CVE-2026-122662 |  | unknown | 2026-11-15T14:21:35.044Z | unverified-lead |
| CVE-2026-124270 |  | unknown | 2026-11-15T14:21:35.044Z | unverified-lead |
| CVE-2026-124755 |  | unknown | 2026-11-15T14:21:35.044Z | unverified-lead |
| CVE-2026-124995 |  | unknown | 2026-11-15T14:21:35.044Z | unverified-lead |
| CVE-2026-124259 |  | unknown | 2026-11-15T14:21:35.044Z | unverified-lead |
| CVE-2026-125449 |  | unknown | 2026-11-15T14:21:35.044Z | unverified-lead |
| CVE-2026-125764 |  | unknown | 2026-11-15T14:21:35.044Z | unverified-lead |
| CVE-2026-125443 |  | unknown | 2026-11-15T14:21:35.044Z | unverified-lead |
| CVE-2026-125769 |  | unknown | 2026-11-15T14:21:35.044Z | unverified-lead |
| CVE-2026-125780 |  | unknown | 2026-11-15T14:21:35.044Z | unverified-lead |
| CVE-2026-125775 |  | unknown | 2026-11-15T14:21:35.044Z | unverified-lead |
| CVE-2026-125789 |  | unknown | 2026-11-15T14:21:35.044Z | unverified-lead |
| CVE-2026-125813 |  | unknown | 2026-11-15T14:21:35.044Z | unverified-lead |
| CVE-2026-125790 |  | unknown | 2026-11-15T14:21:35.044Z | unverified-lead |
| CVE-2026-125805 |  | unknown | 2026-11-15T14:21:35.044Z | unverified-lead |
| CVE-2026-125791 |  | unknown | 2026-11-15T14:21:35.044Z | unverified-lead |
| CVE-2026-125857 |  | unknown | 2026-11-15T14:21:35.044Z | unverified-lead |
| CVE-2026-125828 |  | unknown | 2026-11-15T14:21:35.044Z | unverified-lead |
| CVE-2026-125832 |  | unknown | 2026-11-15T14:21:35.044Z | unverified-lead |
| CVE-2026-129483 |  | unknown | 2026-11-15T13:50:34.687Z | unverified-lead |
| CVE-2026-129482 |  | unknown | 2026-11-15T13:50:34.687Z | unverified-lead |
| CVE-2026-129453 |  | unknown | 2026-11-15T13:46:34.490Z | unverified-lead |
| CVE-2026-129477 |  | unknown | 2026-11-15T13:20:34.640Z | unverified-lead |
| CVE-2026-129478 |  | unknown | 2026-11-15T13:20:34.640Z | unverified-lead |
| CVE-2026-129480 |  | unknown | 2026-11-15T13:20:34.640Z | unverified-lead |
| CVE-2026-129479 |  | unknown | 2026-11-15T13:20:34.640Z | unverified-lead |
| CVE-2026-129468 |  | unknown | 2026-11-15T12:49:34.525Z | unverified-lead |
| CVE-2026-129467 |  | unknown | 2026-11-15T12:49:34.525Z | unverified-lead |
| CVE-2026-129469 |  | unknown | 2026-11-15T12:49:34.525Z | unverified-lead |
| CVE-2026-129452 |  | unknown | 2026-11-15T12:33:34.416Z | unverified-lead |
| CVE-2026-129451 |  | unknown | 2026-11-15T12:23:34.421Z | unverified-lead |
| SZB-64E07C6873 |  | unknown | 2026-11-15T08:54:17.739Z | unverified-lead |

## Left unchanged

The CISA catalog is still `2026.11.13`. `https://www.cisa.gov/news-events/alerts` returned HTTP 404. The advisories index returned HTTP 200, and its newest row is still 13 November 2026. The details are in `docs/threat-scan-2026-11-15.md`.

Sixteen of the 21 identifiers from the 14 November unverified section are now in the NVD recent feed, all with no CPE. Five stay absent. The details are in `docs/threat-scan-2026-11-15.md`.

Vendor pages checked on this run did not move a floor. The Node security rows are unchanged, and `TOOLCHAIN_NODE_2026_11_11` stays on draft pull request 30. The details are in `docs/threat-scan-2026-11-15.md`.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
