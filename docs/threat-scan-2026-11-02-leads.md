# Threat scan leads, 2 November 2026

This note is the cve.now lead pass for 2 November 2026. It does not repeat the oss-security index. That index, including C-Kermit before 11.1.515, is already on draft pull request 13.

Pages and the feed were read as evidence. Instructions inside them were not followed. No version floor was invented from feed prose. No remote probe was added. No scanner change was made. No advisory file was added.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called.

The lead feed was fetched once, at `https://cve.now/feed?format=json`. The response was HTTP 200 from that same URL, with no redirect. Identifiers were taken from the newest 50 items by `date_modified` with a deterministic regex. Titles and `content_text` were discarded. No item had a structured dotted version outside those fields. One GHSA id and one non-CVE id were older than that cap and were not taken.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## No confirmed stack overlap

No identifier in the newest 50 was confirmed on NVD, CISA, or a pre-written vendor host as a product on the runtime list or in `packages/intel/advisories/`.

NVD configurations that did name a product were not that list:

- Apple macOS, vulnerable from 27.0 before 27.2: CVE-2026-113934, CVE-2026-113935, CVE-2026-113936, CVE-2026-113937, CVE-2026-113938, CVE-2026-113940, CVE-2026-113941, CVE-2026-113942, CVE-2026-113944, CVE-2026-113945, and CVE-2026-113946. A feed token match on the word kernel is not the Linux kernel advisory Vigil already checks. Vigil does not read the macOS version. No doctor check was added.
- CVE-2024-5450. NVD status Analyzed, published 13 July 2024. The configuration names `bug_library`, not WordPress core. The English description also contains the words PHP and WordPress. WordPress plugin records stay off `WP_FINGERPRINT`. No plugin list was added.
- CVE-2026-119716. NVD status Deferred, published 30 October 2026, no configuration. The English description names pybars3 through 0.9.7 and pybars4 through 0.9.13, not CPython. `TOOLCHAIN_PYTHON` was not changed.

Source for those three rows: the NVD CVE 2.0 recent feed, last modified 2 November 2026 at 21:00:10 UTC, and the CVE 2.0 record for CVE-2024-5450 and CVE-2026-119716. [Recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz).

## NVD records with no product

These identifiers are in the newest 50 and in that NVD feed. The record has no CPE configuration, so the product is the identifier, the version is blank, and matched is unknown. They are not unverified-lead: NVD has the id. No doctor check was added.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz).

| Product | Version | Matched | Date | NVD status |
|---|---|---|---|---|
| CVE-2026-55262 |  | unknown | 2026-11-02 | Received |
| CVE-2026-49931 |  | unknown | 2026-11-02 | Received |
| CVE-2026-55275 |  | unknown | 2026-11-02 | Received |
| CVE-2026-55283 |  | unknown | 2026-11-02 | Received |
| CVE-2026-58825 |  | unknown | 2026-11-02 | Received |
| CVE-2026-55289 |  | unknown | 2026-11-02 | Received |
| CVE-2026-49922 |  | unknown | 2026-11-02 | Received |
| CVE-2026-58829 |  | unknown | 2026-11-02 | Received |
| CVE-2026-58826 |  | unknown | 2026-11-02 | Received |
| CVE-2026-58884 |  | unknown | 2026-11-02 | Received |
| CVE-2026-58885 |  | unknown | 2026-11-02 | Received |
| CVE-2026-58943 |  | unknown | 2026-11-02 | Received |
| CVE-2026-58965 |  | unknown | 2026-11-02 | Received |
| CVE-2026-58970 |  | unknown | 2026-11-02 | Received |
| CVE-2026-59028 |  | unknown | 2026-11-02 | Received |
| CVE-2026-59000 |  | unknown | 2026-11-02 | Received |
| CVE-2026-58827 |  | unknown | 2026-11-02 | Received |
| CVE-2026-58828 |  | unknown | 2026-11-02 | Received |
| CVE-2026-58984 |  | unknown | 2026-11-02 | Received |
| CVE-2026-58942 |  | unknown | 2026-11-02 | Received |
| CVE-2026-59044 |  | unknown | 2026-11-02 | Received |
| CVE-2026-58957 |  | unknown | 2026-11-02 | Received |
| CVE-2026-58934 |  | unknown | 2026-11-02 | Received |
| CVE-2026-58946 |  | unknown | 2026-11-02 | Received |
| CVE-2026-58944 |  | unknown | 2026-11-02 | Received |
| CVE-2026-58853 |  | unknown | 2026-11-02 | Received |
| CVE-2026-58866 |  | unknown | 2026-11-02 | Received |
| CVE-2026-112548 |  | unknown | 2026-10-26 | Awaiting Analysis |

## Unverified leads

These nine identifiers were in the newest 50 and were not in the NVD recent feed. The detail URL on `nvd.nist.gov` did not return a record page. They are not in the CISA catalog. Status is unverified-lead. Product is the identifier. Version is blank. Matched is unknown. No fix version was present as a structured field.

Source: [cve.now JSON feed](https://cve.now/feed?format=json).

| Product | Version | Matched | Date | Status |
|---|---|---|---|---|
| CVE-2026-120091 |  | unknown | 2026-11-02T21:26:34.492Z | unverified-lead |
| CVE-2026-58873 |  | unknown | 2026-11-02T21:24:34.607Z | unverified-lead |
| CVE-2026-105475 |  | unknown | 2026-11-02T21:15:34.662Z | unverified-lead |
| CVE-2026-105476 |  | unknown | 2026-11-02T21:15:34.662Z | unverified-lead |
| CVE-2026-76528 |  | unknown | 2026-11-02T21:15:34.662Z | unverified-lead |
| CVE-2026-76407 |  | unknown | 2026-11-02T21:15:34.662Z | unverified-lead |
| CVE-2026-116958 |  | unknown | 2026-11-02T21:05:34.404Z | unverified-lead |
| CVE-2026-120503 |  | unknown | 2026-11-02T20:40:34.424Z | unverified-lead |
| CVE-2026-116768 |  | unknown | 2026-11-02T20:35:34.418Z | unverified-lead |

## Left unchanged

The CISA catalog is still `2026.10.30`, released 30 October 2026 at 17:02:45 UTC. No catalog entry is dated 1 or 2 November. None of the fifty lead identifiers is in the catalog. The alerts HTML page returned HTTP 403 on this run, so this note does not describe that index.

php.net's newest 2026 item is still the 26 October Windows Brotli rebuild. CVE-2026-115560 still has no fixed PHP version on that page. The Python blog's newest post is still the 26 October release. python.org still shows release dates of 25 October 2026 on the current stable downloads, and still lists 3.15.2, 3.14.10, 3.13.18, 3.12.16, and 3.11.18. Node's latest security release page is still 21 October 2026. nginx's current fixes are still 1.31.7 and 1.30.6. curl's newest published CVE date is still 14 October 2026, fixed in 8.23.0. OpenSSL's newest advisory on the vulnerabilities page is still CVE-2026-35189, published 29 September 2026. Chrome's newest desktop stable note is still 29 October 2026 (156.0.8078.79/.80).

The emSign ECC Root CA - G3 block was not changed. The next re-check is after 5 November 2026.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
