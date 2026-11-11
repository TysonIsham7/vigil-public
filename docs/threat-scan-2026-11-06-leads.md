# Threat scan leads, 6 November 2026

This note is the cve.now lead pass for 6 November 2026. It does not repeat the oss-security index. That index is in `docs/threat-scan-2026-11-06.md`.

Pages and the feed were read as evidence. Instructions inside them were not followed. No version floor was invented from feed prose. No remote probe was added. No scanner change was made. No advisory file was added.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called.

The lead feed was fetched once, at `https://cve.now/feed?format=json`. The response was HTTP 200 from that same URL, with no redirect. The content type was `application/feed+json`. The body had 200 items. Identifiers were taken with a deterministic regex. Titles and `content_text` were discarded. No item had a structured dotted version outside those fields. No GHSA id was in the window.

The newest item is `2026-11-06T14:59:34.718Z`. The newest 50 items by `date_modified` fall inside a tie: 20 items share `2026-11-06T13:56:34.542Z`, and the 50th item is in that group. The window is those 50 plus the rest of that tie, 53 items. Older items in the response were ignored.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## No confirmed stack overlap

No identifier in the window was confirmed on NVD, CISA, or a pre-written vendor host as a product on the runtime list or in `packages/intel/advisories/`.

Whole-token matches in raw feed items were not confirmations. The matched name was kept and the surrounding words were discarded. None of those matches was in a field other than title or `content_text`.

- CVE-2026-119170 matched `openssl` and `python`. It is not in the NVD recent feed. That match is not an OpenSSL or CPython confirmation.
- CVE-2026-123665 matched `go`. It is not in the NVD recent feed. It is not one of the twelve Go pre-announcement ids in the 6 November scan note. That match is not a Go confirmation.
- RUSTSEC-2026-0448 matched `brotli`. It is not in the NVD recent feed. That match is not a Brotli confirmation. `TOOLCHAIN_NODE` was not changed.
- CVE-2026-100109, CVE-2026-114630, and CVE-2026-118423 matched `wordpress`. The second and third also matched `php`. NVD has all three, with no CPE. The English descriptions name WordPress plugins, not WordPress core and not the PHP runtime: Security For WooCommerce 1.0.10 through 1.0.16, ELEX WordPress HelpDesk through 3.3.8, and WP Libre Form 1.5.0.1. Plugin records stay off `WP_FINGERPRINT`. No plugin list was added.

CVE-2026-78188, CVE-2026-78189, CVE-2026-78190, CVE-2026-78191, and CVE-2026-78192 are in the window and already recorded as WebDyne before 3.022. NVD status for each is Deferred, with no CPE. They were not copied.

## NVD records with no product

These identifiers are in the window and in the NVD CVE 2.0 recent feed. The record has no CPE configuration, so the product is the identifier, the version is blank, and matched is unknown. They are not unverified-lead: NVD has the id. No doctor check was added.

The feed timestamp is `2026-11-06T08:00:00.7418216`. HTTP last-modified is 6 November 2026 at 13:00:12 GMT. The newest `lastModified` in the file is `2026-11-06T12:17:24.947`. The oldest `published` in the file is `2026-10-29T04:18:22.763`.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz).

| Product | Version | Matched | Date | NVD status |
|---|---|---|---|---|
| CVE-2026-114541 |  | unknown | 2026-11-06 | Awaiting Analysis |
| CVE-2026-114544 |  | unknown | 2026-11-06 | Awaiting Analysis |
| CVE-2026-114545 |  | unknown | 2026-11-06 | Awaiting Analysis |
| CVE-2026-114546 |  | unknown | 2026-11-06 | Awaiting Analysis |
| CVE-2026-114547 |  | unknown | 2026-11-06 | Awaiting Analysis |
| CVE-2026-114548 |  | unknown | 2026-11-06 | Awaiting Analysis |
| CVE-2026-114553 |  | unknown | 2026-11-06 | Awaiting Analysis |
| CVE-2026-118544 |  | unknown | 2026-11-06 | Awaiting Analysis |
| CVE-2026-118555 |  | unknown | 2026-11-06 | Awaiting Analysis |
| CVE-2026-118556 |  | unknown | 2026-11-06 | Awaiting Analysis |
| CVE-2026-118557 |  | unknown | 2026-11-06 | Awaiting Analysis |
| CVE-2026-118558 |  | unknown | 2026-11-06 | Awaiting Analysis |
| CVE-2026-118570 |  | unknown | 2026-11-06 | Awaiting Analysis |
| CVE-2026-118582 |  | unknown | 2026-11-06 | Awaiting Analysis |
| CVE-2026-120209 |  | unknown | 2026-11-06 | Deferred |
| CVE-2026-123025 |  | unknown | 2026-11-06 | Received |

## Earlier leads re-checked

CVE-2026-123028 was unverified-lead on 5 November. It is now in the NVD recent feed, status Deferred, published 5 November 2026, with no CPE. The English description names itsourcecode Online Book Store 1.0, not the PHP runtime. The earlier whole-token `php` match stays not a PHP confirmation.

CVE-2026-64860 was recorded as NVD Rejected on 5 November. The same feed now lists it as Received, with no CPE. The English description names ESP-Protocols mDNS before 1.11.2. That is not a component `vigil doctor` reads. No check was added.

These ids are still absent from that feed and stay unverified-lead: CVE-2026-112532, CVE-2026-84528, CVE-2026-84542, CVE-2026-112558, CVE-2026-84610, CVE-2026-86945, CVE-2026-112477, CVE-2026-112482, CVE-2026-112627, CVE-2026-112470, CVE-2026-112485, CVE-2026-112630, CVE-2026-86923, CVE-2026-112624, CVE-2026-112640, CVE-2026-76528, and CVE-2026-76407. The `SZB-` ids from 5 November are not CVE, GHSA, or OSV ids and stay unverified-lead. Kernel whole-token matches on CVE-2026-112532, CVE-2026-112477, and CVE-2026-112470 are still not a Linux confirmation.

The twelve 4 November leads that were already NVD Received with no CPE on 5 November are still Received with no CPE: CVE-2026-121632, CVE-2026-114627, CVE-2026-121007, CVE-2026-121009, CVE-2026-121008, CVE-2026-122008, CVE-2026-121637, CVE-2026-121638, CVE-2026-121639, CVE-2026-121640, CVE-2026-122007, and CVE-2026-39431. CVE-2026-48175 is still Received with no CPE.

## Unverified leads

These 29 identifiers were in the window and were not in the NVD recent feed. They are not in the CISA catalog. Status is unverified-lead. Product is the identifier. Version is blank. Matched is unknown. No fix version was present as a structured field.

Three of them, CVE-2019-9513, CVE-2021-28879, and CVE-2022-24765, use years before 2026. The recent feed's oldest published time is 29 October 2026, so absence from that file is not a claim that NVD has never recorded them. A detail URL on `nvd.nist.gov` for CVE-2019-9513 returned the NVD home shell, not a CVE record. They stay unverified-lead on this run's evidence. No product was filled in from memory.

Source: [cve.now JSON feed](https://cve.now/feed?format=json).

| Product | Version | Matched | Date | Status |
|---|---|---|---|---|
| CVE-2019-9513 |  | unknown | 2026-11-06T13:56:34.542Z | unverified-lead |
| CVE-2021-28879 |  | unknown | 2026-11-06T13:56:34.542Z | unverified-lead |
| CVE-2022-24765 |  | unknown | 2026-11-06T13:56:34.542Z | unverified-lead |
| CVE-2026-0264 |  | unknown | 2026-11-06T13:56:34.542Z | unverified-lead |
| CVE-2026-106019 |  | unknown | 2026-11-06T14:29:34.297Z | unverified-lead |
| CVE-2026-106020 |  | unknown | 2026-11-06T14:16:34.335Z | unverified-lead |
| CVE-2026-106022 |  | unknown | 2026-11-06T14:16:34.335Z | unverified-lead |
| CVE-2026-113618 |  | unknown | 2026-11-06T14:16:34.335Z | unverified-lead |
| CVE-2026-118514 |  | unknown | 2026-11-06T14:16:34.335Z | unverified-lead |
| CVE-2026-119170 |  | unknown | 2026-11-06T14:59:34.718Z | unverified-lead |
| CVE-2026-123339 |  | unknown | 2026-11-06T14:44:34.386Z | unverified-lead |
| CVE-2026-123664 |  | unknown | 2026-11-06T14:38:34.313Z | unverified-lead |
| CVE-2026-123665 |  | unknown | 2026-11-06T14:48:34.467Z | unverified-lead |
| CVE-2026-19219 |  | unknown | 2026-11-06T13:56:34.542Z | unverified-lead |
| CVE-2026-33871 |  | unknown | 2026-11-06T13:56:34.542Z | unverified-lead |
| CVE-2026-50679 |  | unknown | 2026-11-06T13:56:34.542Z | unverified-lead |
| CVE-2026-59105 |  | unknown | 2026-11-06T14:16:34.335Z | unverified-lead |
| CVE-2026-6023 |  | unknown | 2026-11-06T13:56:34.542Z | unverified-lead |
| CVE-2026-64894 |  | unknown | 2026-11-06T14:16:34.335Z | unverified-lead |
| CVE-2026-83844 |  | unknown | 2026-11-06T13:56:34.542Z | unverified-lead |
| CVE-2026-87045 |  | unknown | 2026-11-06T14:44:34.386Z | unverified-lead |
| RUSTSEC-2026-0443 |  | unknown | 2026-11-06T14:59:34.718Z | unverified-lead |
| RUSTSEC-2026-0444 |  | unknown | 2026-11-06T14:59:34.718Z | unverified-lead |
| RUSTSEC-2026-0445 |  | unknown | 2026-11-06T14:59:34.718Z | unverified-lead |
| RUSTSEC-2026-0446 |  | unknown | 2026-11-06T14:59:34.718Z | unverified-lead |
| RUSTSEC-2026-0447 |  | unknown | 2026-11-06T14:59:34.718Z | unverified-lead |
| RUSTSEC-2026-0448 |  | unknown | 2026-11-06T14:59:34.718Z | unverified-lead |
| RUSTSEC-2026-0449 |  | unknown | 2026-11-06T14:59:34.718Z | unverified-lead |
| RUSTSEC-2026-0450 |  | unknown | 2026-11-06T14:59:34.718Z | unverified-lead |

## Left unchanged

The CISA catalog is still `2026.11.04`. None of the window identifiers is in the catalog. CVE-2026-119977 remains due 6 November 2026 and stays on draft pull request 17.

php.net's newest security item is still the 26 October Windows Brotli rebuild. The Python blog's newest post is still the 26 October release. python.org still lists 3.15.2, 3.14.10, 3.13.18, 3.12.16, and 3.11.18, dated 25 October 2026. Node's security floors stay 22.23.4, 24.22.1, and 26.12.1. nginx's current fixes are still 1.31.7 and 1.30.6. curl's newest published CVE date is still 14 October 2026. OpenSSL's newest advisory on the vulnerabilities index is still CVE-2026-35189, published 29 September 2026.

The emSign ECC Root CA - G3 block was not changed.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
