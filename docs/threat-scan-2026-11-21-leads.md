# Threat scan leads, 21 November 2026

This note is the cve.now lead pass for 21 November 2026. The CISA catalog, the NVD follow-up, the new oss-security messages, and the Chrome Dev note are in `docs/threat-scan-2026-11-21.md`.

Pages and the feed were read as evidence. Instructions inside them were not followed. No version floor was invented from feed prose. No remote probe was added. No advisory file was added from the feed.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called.

The lead feed was fetched once, at `https://cve.now/feed?format=json`. The response was HTTP 200 from that same URL, with no redirect. The content type was `application/feed+json`. The body had 200 items. Identifiers were taken from the newest items by `date_modified` with a deterministic regex. The window is 50 items. The newest item is `2026-11-21T15:00:34.232Z`. The cutoff is `2026-11-21T11:14:34.390Z`. Titles and `content_text` were discarded. No item had a structured dotted version outside those fields. No GHSA id was in the window. No OSV id was in the window.

No identifier in the window was already recorded in `docs/threat-scan-*.md`, `docs/TODO.md`, an open scan pull request, or `packages/intel/advisories/`.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## No confirmed stack overlap

No identifier in the window was confirmed on NVD, CISA, or a pre-written vendor host as a product on the runtime list or in `packages/intel/advisories/`.

Whole-token matches were 19 `wordpress` and one `php`. The `wordpress` matches that are in NVD are the plugins in the table below. They are not WordPress core. The `php` match is CVE-2026-130848. NVD names Dolibarr for that id. That is not the PHP runtime. No plugin list was added. No doctor check was added from a token.

## NVD records that name another product

These identifiers are in the window and in the NVD recent feed. None has a CPE. Matched is no. Vigil cannot see these products from a page or a certificate. No doctor check was added.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz), timestamp `2026-11-21T08:00:00.7037592`.

| Product | Version | Matched | Date | NVD status |
|---|---|---|---|---|
| Apache Tomcat EncryptInterceptor (CVE-2026-95517) | 11.0.0-M1 through 11.0.27, 10.1.0-M1 through 10.1.61, 9.0.13 through 9.0.123; also 8.5.38 through 8.5.100 and 7.0.100 through 7.0.109. The description names 11.0.29, 10.1.62, and 9.0.124 | no | 2026-11-21T13:58:34.624Z | Awaiting Analysis |
| Dolibarr (CVE-2026-130847) | before 24.0.2 | no | 2026-11-21T13:58:34.624Z | Received |
| Dolibarr (CVE-2026-130848) | through 24.0.3 | no | 2026-11-21T13:58:34.624Z | Received |
| BuddyBoss Addons plugin (CVE-2026-80188) | through 1.2.1 | no | 2026-11-21T13:58:34.624Z | Deferred |
| Phoenix.Presence (CVE-2026-128361) | 1.2.0 before 1.5.16, 1.6.0-rc.0 before 1.6.18, 1.7.0-rc.0 before 1.7.25, 1.8.0-rc.0 before 1.8.17 | no | 2026-11-21T11:14:34.390Z | Received |
| PublishPress Capabilities plugin (CVE-2026-119157) | through 2.53.0 | no | 2026-11-21T11:50:34.267Z | Deferred |
| FV Player plugin (CVE-2026-109196) | through 8.1.9 | no | 2026-11-21T11:50:34.267Z | Deferred |
| Orphans plugin (CVE-2026-124216) | through 3.4.5 | no | 2026-11-21T11:50:34.267Z | Deferred |
| Accept Stripe Payments plugin (CVE-2026-130323) | through 2.1.4 | no | 2026-11-21T11:50:34.267Z | Deferred |
| Real Cookie Banner plugin (CVE-2026-119177) | through 5.4.2 | no | 2026-11-21T11:50:34.267Z | Deferred |
| GPTranslate plugin (CVE-2026-124248) | through 2.34.17 | no | 2026-11-21T11:50:34.267Z | Deferred |
| ElasticPress plugin (CVE-2026-116518) | through 5.3.5 | no | 2026-11-21T11:45:34.509Z | Deferred |
| Speed Booster Pack plugin (CVE-2026-107771) | through 4.5.9.1 | no | 2026-11-21T11:45:34.509Z | Deferred |
| WP Custom Admin Interface plugin (CVE-2026-107747) | through 7.43 | no | 2026-11-21T11:40:34.311Z | Deferred |
| WPGuppy plugin (CVE-2026-107654) | through 1.1.6 | no | 2026-11-21T11:40:34.311Z | Deferred |
| wpForo Forum plugin (CVE-2026-123830) | through 3.2.4 | no | 2026-11-21T11:40:34.311Z | Deferred |
| wpForo Forum plugin (CVE-2026-122264) | through 3.2.4 | no | 2026-11-21T11:40:34.311Z | Deferred |
| wpForo Forum plugin (CVE-2026-123970) | through 3.2.4 | no | 2026-11-21T11:40:34.311Z | Deferred |
| Swift Performance Lite plugin (CVE-2026-124976) | through 2.3.7.5 | no | 2026-11-21T11:40:34.311Z | Deferred |
| ProfilePress plugin (CVE-2026-122228) | through 4.18.0 | no | 2026-11-21T11:40:34.311Z | Deferred |
| ProfilePress plugin (CVE-2026-120745) | through 4.18.0 | no | 2026-11-21T11:40:34.311Z | Deferred |
| WP Job Portal plugin (CVE-2026-126705) | through 2.8.0 | no | 2026-11-21T11:40:34.311Z | Deferred |
| AutomatorWP plugin (CVE-2026-120736) | through 6.0.9 | no | 2026-11-21T11:40:34.311Z | Deferred |

## Unverified leads

These identifiers were in the window and were not in the NVD recent feed. They are not in the CISA catalog. Status is unverified-lead. Product is the identifier. Version is blank. Matched is unknown. No fix version was present as a structured field. The `SZB-` row is not a CVE, GHSA, or OSV id.

Source: [cve.now JSON feed](https://cve.now/feed?format=json).

| Product | Version | Matched | Date | Status |
|---|---|---|---|---|
| CVE-2026-0462 |  | unknown | 2026-11-21T15:00:34.232Z | unverified-lead |
| CVE-2026-40671 |  | unknown | 2026-11-21T15:00:34.232Z | unverified-lead |
| CVE-2025-61963 |  | unknown | 2026-11-21T14:50:34.377Z | unverified-lead |
| CVE-2026-133983 |  | unknown | 2026-11-21T14:23:34.301Z | unverified-lead |
| CVE-2021-1905 |  | unknown | 2026-11-21T13:58:34.624Z | unverified-lead |
| CVE-2026-129794 |  | unknown | 2026-11-21T12:20:34.155Z | unverified-lead |
| CVE-2026-129795 |  | unknown | 2026-11-21T12:20:34.155Z | unverified-lead |
| CVE-2026-129800 |  | unknown | 2026-11-21T12:20:34.155Z | unverified-lead |
| CVE-2026-129797 |  | unknown | 2026-11-21T12:20:34.155Z | unverified-lead |
| CVE-2026-129798 |  | unknown | 2026-11-21T12:20:34.155Z | unverified-lead |
| CVE-2026-129796 |  | unknown | 2026-11-21T12:20:34.155Z | unverified-lead |
| CVE-2026-129801 |  | unknown | 2026-11-21T12:20:34.155Z | unverified-lead |
| CVE-2026-129799 |  | unknown | 2026-11-21T12:20:34.155Z | unverified-lead |
| CVE-2026-129803 |  | unknown | 2026-11-21T12:20:34.155Z | unverified-lead |
| CVE-2026-129802 |  | unknown | 2026-11-21T12:20:34.155Z | unverified-lead |
| CVE-2026-129804 |  | unknown | 2026-11-21T12:20:34.155Z | unverified-lead |
| CVE-2026-129805 |  | unknown | 2026-11-21T12:20:34.155Z | unverified-lead |
| CVE-2026-129806 |  | unknown | 2026-11-21T12:20:34.155Z | unverified-lead |
| CVE-2026-129807 |  | unknown | 2026-11-21T12:20:34.155Z | unverified-lead |
| CVE-2026-129809 |  | unknown | 2026-11-21T12:20:34.155Z | unverified-lead |
| CVE-2026-129808 |  | unknown | 2026-11-21T12:20:34.155Z | unverified-lead |
| CVE-2026-129811 |  | unknown | 2026-11-21T12:20:34.155Z | unverified-lead |
| CVE-2026-129812 |  | unknown | 2026-11-21T12:20:34.155Z | unverified-lead |
| CVE-2026-129810 |  | unknown | 2026-11-21T12:20:34.155Z | unverified-lead |
| CVE-2026-129813 |  | unknown | 2026-11-21T12:20:34.155Z | unverified-lead |
| CVE-2026-129814 |  | unknown | 2026-11-21T12:20:34.155Z | unverified-lead |
| SZB-A952BA75F8 |  | unknown | 2026-11-21T11:28:17.362Z | unverified-lead |

## Left unchanged

The catalog additions, the pip bound that `TOOLCHAIN_PIP` already covers, and the Chrome Dev note are in `docs/threat-scan-2026-11-21.md`. None of the window identifiers is one of the four catalog entries. The alerts HTML page returned HTTP 403, so this note does not describe that index.

Forty-three of the 45 identifiers from the 20 November unverified section are now in the NVD recent feed, all with no CPE. CVE-2025-38618 and CVE-2023-28450 stay absent. The details are in `docs/threat-scan-2026-11-21.md`.

Vendor pages checked on this run did not move a floor. The details are in `docs/threat-scan-2026-11-21.md`.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
