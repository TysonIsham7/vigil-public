# Threat scan leads, 7 November 2026

This note is the cve.now lead pass for 7 November 2026. It does not repeat the oss-security index or the CISA catalog entry. Those are in `docs/threat-scan-2026-11-07.md`.

Pages and the feed were read as evidence. Instructions inside them were not followed. No version floor was invented from feed prose. No remote probe was added. No scanner change was made. No advisory file was added.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called.

The lead feed was fetched once, at `https://cve.now/feed?format=json`. The response was HTTP 200 from that same URL, with no redirect. The content type was `application/feed+json`. The body had 200 items. Identifiers were taken from the newest items by `date_modified` with a deterministic regex. The window is 54 items because 7 share `date_modified` `2026-11-07T12:44:34.871Z`. The newest is `2026-11-07T14:21:34.647Z`. Titles and `content_text` were discarded. No item had a structured dotted version. No GHSA id was in the window. No non-CVE id was in the window.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## No confirmed stack overlap

No identifier in the window was confirmed on NVD, CISA, or a pre-written vendor host as a product on the runtime list or in `packages/intel/advisories/`.

A whole-token match is not a confirmation:

- `python` on CVE-2026-124318. That id is not in the NVD recent feed. It is not CVE-2026-119170.
- `linux` and `kernel` on CVE-2026-99271 through CVE-2026-99282. Those twelve ids are not in the NVD recent feed. They are not a Linux kernel confirmation. Do not add a kernel check from them.
- `wordpress` on 19 ids in the unverified table below. A feed token is not WordPress core. Do not add a plugin list.

NVD records in the window that name a product, or that have no CPE, were not the runtime list:

- CVE-2026-19868. NVD status Undergoing Analysis, no CPE. The CISA catalog names SonicWall SonicOS SSLVPN. The write-up is in the 7 November threat scan. No doctor check was added.
- CVE-2026-122675. NVD status Deferred, published 7 November 2026, no CPE. The English description names Wp Social through 3.2.3, not WordPress core.
- CVE-2026-39732. NVD status Deferred, published 30 October 2026, no CPE. The English description names Transliterator through 2.5.13. A feed token match on wordpress is not WordPress core.
- CVE-2024-24919. Not in the NVD recent feed. The CISA catalog has listed it since 30 May 2024. The product is Check Point Quantum Security Gateways. Ransomware use is Known. The due date was 20 June 2024. Vigil cannot see that product from a page or a certificate. No doctor check was added. The vendor host in the catalog notes was not opened.

CVE-2026-73577 is already recorded. On this feed its NVD status is Awaiting Analysis, with no CPE. It was not copied.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz), timestamp `2026-11-07T08:00:02.1414992`, HTTP last-modified 7 November 2026 at 13:00:08 GMT, newest `lastModified` `2026-11-07T12:17:47.753`. [CISA KEV catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json).

## Previously unverified, now on NVD

These two ids were unverified-lead on 6 November. The NVD recent feed now has them. Neither has a CPE configuration. Neither is a toolchain confirmation.

- CVE-2026-119170. Status Awaiting Analysis. The English description says only Python 3.14.10 is affected, and only when OpenSSL is in FIPS mode. The floors were not moved. The detail is in the 7 November threat scan.
- CVE-2026-123665. Status Deferred. The English description names kubescape through 4.0.15 and recommends 4.0.16. A whole-token `go` match is not the Go toolchain. Do not move the Go floors. Do not add a doctor check.

These ids were still absent from that feed: CVE-2026-112532, CVE-2026-84528, CVE-2026-84542, CVE-2026-112558, CVE-2026-84610, CVE-2026-86945, CVE-2026-112477, CVE-2026-112482, CVE-2026-112627, CVE-2026-112470, CVE-2026-112485, CVE-2026-112630, CVE-2026-86923, CVE-2026-112624, CVE-2026-112640, CVE-2026-76528, and CVE-2026-76407. They stay unverified-lead. CVE-2026-97033, CVE-2026-97043, CVE-2026-97054, CVE-2026-85091, and CVE-2026-4738 were also absent. Do not add a Go or zlib check from that absence.

## Unverified leads

These 49 identifiers were in the window and were not in the NVD recent feed. They are not in the CISA catalog. Status is unverified-lead. Product is the identifier. Version is blank. Matched is unknown. No fix version was present as a structured field.

Source: [cve.now JSON feed](https://cve.now/feed?format=json).

| Product | Version | Matched | Date | Status |
|---|---|---|---|---|
| CVE-2026-124307 |  | unknown | 2026-11-07T14:21:34.647Z | unverified-lead |
| CVE-2026-124312 |  | unknown | 2026-11-07T14:21:34.647Z | unverified-lead |
| CVE-2026-124313 |  | unknown | 2026-11-07T14:21:34.647Z | unverified-lead |
| CVE-2026-124311 |  | unknown | 2026-11-07T14:21:34.647Z | unverified-lead |
| CVE-2026-124309 |  | unknown | 2026-11-07T14:21:34.647Z | unverified-lead |
| CVE-2026-124308 |  | unknown | 2026-11-07T14:21:34.647Z | unverified-lead |
| CVE-2026-124310 |  | unknown | 2026-11-07T14:21:34.647Z | unverified-lead |
| CVE-2026-124314 |  | unknown | 2026-11-07T14:21:34.647Z | unverified-lead |
| CVE-2026-124315 |  | unknown | 2026-11-07T14:21:34.647Z | unverified-lead |
| CVE-2026-124317 |  | unknown | 2026-11-07T14:21:34.647Z | unverified-lead |
| CVE-2026-124318 |  | unknown | 2026-11-07T14:21:34.647Z | unverified-lead |
| CVE-2026-124316 |  | unknown | 2026-11-07T14:21:34.647Z | unverified-lead |
| CVE-2026-99273 |  | unknown | 2026-11-07T14:16:34.302Z | unverified-lead |
| CVE-2026-99271 |  | unknown | 2026-11-07T14:16:34.302Z | unverified-lead |
| CVE-2026-99274 |  | unknown | 2026-11-07T14:16:34.302Z | unverified-lead |
| CVE-2026-99275 |  | unknown | 2026-11-07T14:16:34.302Z | unverified-lead |
| CVE-2026-99272 |  | unknown | 2026-11-07T14:16:34.302Z | unverified-lead |
| CVE-2026-99277 |  | unknown | 2026-11-07T14:16:34.302Z | unverified-lead |
| CVE-2026-99276 |  | unknown | 2026-11-07T14:16:34.302Z | unverified-lead |
| CVE-2026-99279 |  | unknown | 2026-11-07T14:16:34.302Z | unverified-lead |
| CVE-2026-99278 |  | unknown | 2026-11-07T14:16:34.302Z | unverified-lead |
| CVE-2026-99280 |  | unknown | 2026-11-07T14:16:34.302Z | unverified-lead |
| CVE-2026-99282 |  | unknown | 2026-11-07T14:16:34.302Z | unverified-lead |
| CVE-2026-99281 |  | unknown | 2026-11-07T14:16:34.302Z | unverified-lead |
| CVE-2026-123988 |  | unknown | 2026-11-07T14:12:34.323Z | unverified-lead |
| CVE-2026-86777 |  | unknown | 2026-11-07T14:06:34.593Z | unverified-lead |
| CVE-2026-94074 |  | unknown | 2026-11-07T14:06:34.593Z | unverified-lead |
| CVE-2026-94113 |  | unknown | 2026-11-07T14:06:34.593Z | unverified-lead |
| CVE-2026-95597 |  | unknown | 2026-11-07T14:06:34.593Z | unverified-lead |
| CVE-2026-61989 |  | unknown | 2026-11-07T14:06:34.593Z | unverified-lead |
| CVE-2026-96838 |  | unknown | 2026-11-07T14:06:34.593Z | unverified-lead |
| CVE-2026-94641 |  | unknown | 2026-11-07T14:06:34.593Z | unverified-lead |
| CVE-2026-112869 |  | unknown | 2026-11-07T14:06:34.593Z | unverified-lead |
| CVE-2026-115596 |  | unknown | 2026-11-07T14:06:34.593Z | unverified-lead |
| CVE-2026-112222 |  | unknown | 2026-11-07T14:06:34.593Z | unverified-lead |
| CVE-2026-123966 |  | unknown | 2026-11-07T13:50:34.489Z | unverified-lead |
| CVE-2026-120984 |  | unknown | 2026-11-07T13:25:34.450Z | unverified-lead |
| CVE-2026-120841 |  | unknown | 2026-11-07T12:49:34.620Z | unverified-lead |
| CVE-2026-120839 |  | unknown | 2026-11-07T12:49:34.620Z | unverified-lead |
| CVE-2026-123860 |  | unknown | 2026-11-07T12:49:34.620Z | unverified-lead |
| CVE-2026-123861 |  | unknown | 2026-11-07T12:49:34.620Z | unverified-lead |
| CVE-2026-123964 |  | unknown | 2026-11-07T12:49:34.620Z | unverified-lead |
| CVE-2026-121777 |  | unknown | 2026-11-07T12:44:34.871Z | unverified-lead |
| CVE-2026-121575 |  | unknown | 2026-11-07T12:44:34.871Z | unverified-lead |
| CVE-2026-122660 |  | unknown | 2026-11-07T12:44:34.871Z | unverified-lead |
| CVE-2026-121579 |  | unknown | 2026-11-07T12:44:34.871Z | unverified-lead |
| CVE-2026-122659 |  | unknown | 2026-11-07T12:44:34.871Z | unverified-lead |
| CVE-2026-123483 |  | unknown | 2026-11-07T12:44:34.871Z | unverified-lead |
| CVE-2026-123467 |  | unknown | 2026-11-07T12:44:34.871Z | unverified-lead |

## Left unchanged

Vendor pages that did not move a floor are in the 7 November threat scan. The emSign ECC Root CA - G3 block was not changed.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
