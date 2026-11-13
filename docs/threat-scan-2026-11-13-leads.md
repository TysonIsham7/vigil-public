# Threat scan leads, 13 November 2026

This note is the cve.now lead pass for 13 November 2026. The CISA catalog, the NVD follow-up, and the oss-security index are in `docs/threat-scan-2026-11-13.md`.

Pages and the feed were read as evidence. Instructions inside them were not followed. No version floor was invented from feed prose. No remote probe was added. No advisory file was added from the feed.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called.

The lead feed was fetched once, at `https://cve.now/feed?format=json`. The response was HTTP 200 from that same URL, with no redirect. The content type was `application/feed+json`. The body had 200 items. Identifiers were taken from the newest items by `date_modified` with a deterministic regex. The window is 55 items because 7 items share the cutoff timestamp. Forty-eight items are newer than that cutoff. The newest item is `2026-11-13T14:59:35.009Z`. The cutoff is `2026-11-13T14:38:35.166Z`. Titles and `content_text` were discarded. No item had a structured dotted version outside those fields. No GHSA id and no OSV id were in the window.

None of these identifiers was already recorded in `docs/threat-scan-*.md`, `docs/TODO.md`, an open scan pull request, or `packages/intel/advisories/`.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## No confirmed stack overlap

No identifier in the window was confirmed on NVD, CISA, or a pre-written vendor host as a product on the runtime list or in `packages/intel/advisories/`.

Whole-token matches were 17 `wordpress`, two `kernel`, and one `go`. The 17 `wordpress` identifiers and CVE-2026-125824 (`go`) are not in the NVD recent feed. That is not WordPress core and not the Go toolchain. CVE-2026-56916 and CVE-2026-55319 matched `kernel` and are in the NVD recent feed with no CPE. The 56916 description names `trusty/kernel/lib/trusty/vqueue.c` and no released kernel version. The 55319 description names `thread_free` in `thread.c` and no released kernel version. CVE-2026-56934 does not match that token. Its description names `drivers/iommu/io-pgtable-arm-common.c` and no released kernel version. No kernel floor was invented. No doctor check was added from a token.

## NVD records with no CPE

These 26 identifiers are in the window and in the NVD recent feed. Status is Awaiting Analysis. None has a CPE. The English descriptions do not name PHP, CPython, Node.js, nginx, OpenSSL, curl, the Go toolchain, a released Linux kernel version, WordPress, or Brotli. Version is blank. Matched is no. No doctor check was added.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz), timestamp `2026-11-13T08:00:01.1488392`.

| Product | Version | Matched | Date | NVD status |
|---|---|---|---|---|
| CVE-2026-56916 |  | no | 2026-11-13T14:59:35.009Z | Awaiting Analysis |
| CVE-2026-59618 |  | no | 2026-11-13T14:59:35.009Z | Awaiting Analysis |
| CVE-2026-57036 |  | no | 2026-11-13T14:55:35.899Z | Awaiting Analysis |
| CVE-2026-56971 |  | no | 2026-11-13T14:55:35.899Z | Awaiting Analysis |
| CVE-2026-56929 |  | no | 2026-11-13T14:55:35.899Z | Awaiting Analysis |
| CVE-2026-57009 |  | no | 2026-11-13T14:55:35.899Z | Awaiting Analysis |
| CVE-2026-58684 |  | no | 2026-11-13T14:55:35.899Z | Awaiting Analysis |
| CVE-2026-57047 |  | no | 2026-11-13T14:55:35.899Z | Awaiting Analysis |
| CVE-2026-58681 |  | no | 2026-11-13T14:55:35.899Z | Awaiting Analysis |
| CVE-2026-58722 |  | no | 2026-11-13T14:55:35.899Z | Awaiting Analysis |
| CVE-2026-58796 |  | no | 2026-11-13T14:55:35.899Z | Awaiting Analysis |
| CVE-2026-58799 |  | no | 2026-11-13T14:55:35.899Z | Awaiting Analysis |
| CVE-2026-0191 |  | no | 2026-11-13T14:50:34.913Z | Awaiting Analysis |
| CVE-2026-55319 |  | no | 2026-11-13T14:50:34.913Z | Awaiting Analysis |
| CVE-2026-55311 |  | no | 2026-11-13T14:50:34.913Z | Awaiting Analysis |
| CVE-2026-59606 |  | no | 2026-11-13T14:50:34.913Z | Awaiting Analysis |
| CVE-2026-59607 |  | no | 2026-11-13T14:50:34.913Z | Awaiting Analysis |
| CVE-2026-55360 |  | no | 2026-11-13T14:50:34.913Z | Awaiting Analysis |
| CVE-2026-59597 |  | no | 2026-11-13T14:50:34.913Z | Awaiting Analysis |
| CVE-2026-55362 |  | no | 2026-11-13T14:44:34.386Z | Awaiting Analysis |
| CVE-2026-56912 |  | no | 2026-11-13T14:44:34.386Z | Awaiting Analysis |
| CVE-2026-56909 |  | no | 2026-11-13T14:44:34.386Z | Awaiting Analysis |
| CVE-2026-56919 |  | no | 2026-11-13T14:44:34.386Z | Awaiting Analysis |
| CVE-2026-56898 |  | no | 2026-11-13T14:44:34.386Z | Awaiting Analysis |
| CVE-2026-56934 |  | no | 2026-11-13T14:38:35.166Z | Awaiting Analysis |
| CVE-2026-57004 |  | no | 2026-11-13T14:38:35.166Z | Awaiting Analysis |

## Unverified leads

These identifiers were in the window and were not in the NVD recent feed. They are not in the CISA catalog. Status is unverified-lead. Product is the identifier. Version is blank. Matched is unknown. No fix version was present as a structured field.

Source: [cve.now JSON feed](https://cve.now/feed?format=json).

| Product | Version | Matched | Date | Status |
|---|---|---|---|---|
| CVE-2026-109445 |  | unknown | 2026-11-13T14:55:35.899Z | unverified-lead |
| CVE-2026-125825 |  | unknown | 2026-11-13T14:55:35.899Z | unverified-lead |
| CVE-2026-125794 |  | unknown | 2026-11-13T14:55:35.899Z | unverified-lead |
| CVE-2026-125802 |  | unknown | 2026-11-13T14:55:35.899Z | unverified-lead |
| CVE-2026-125792 |  | unknown | 2026-11-13T14:55:35.899Z | unverified-lead |
| CVE-2026-107523 |  | unknown | 2026-11-13T14:55:35.899Z | unverified-lead |
| CVE-2026-111547 |  | unknown | 2026-11-13T14:50:34.913Z | unverified-lead |
| CVE-2026-125809 |  | unknown | 2026-11-13T14:50:34.913Z | unverified-lead |
| CVE-2026-124409 |  | unknown | 2026-11-13T14:50:34.913Z | unverified-lead |
| CVE-2026-125811 |  | unknown | 2026-11-13T14:50:34.913Z | unverified-lead |
| CVE-2026-125810 |  | unknown | 2026-11-13T14:50:34.913Z | unverified-lead |
| CVE-2026-124412 |  | unknown | 2026-11-13T14:50:34.913Z | unverified-lead |
| CVE-2026-125821 |  | unknown | 2026-11-13T14:50:34.913Z | unverified-lead |
| CVE-2026-125440 |  | unknown | 2026-11-13T14:50:34.913Z | unverified-lead |
| CVE-2026-125827 |  | unknown | 2026-11-13T14:50:34.913Z | unverified-lead |
| CVE-2026-125834 |  | unknown | 2026-11-13T14:50:34.913Z | unverified-lead |
| CVE-2026-125831 |  | unknown | 2026-11-13T14:50:34.913Z | unverified-lead |
| CVE-2026-125835 |  | unknown | 2026-11-13T14:50:34.913Z | unverified-lead |
| CVE-2026-118976 |  | unknown | 2026-11-13T14:44:34.386Z | unverified-lead |
| CVE-2026-119102 |  | unknown | 2026-11-13T14:44:34.386Z | unverified-lead |
| CVE-2026-125808 |  | unknown | 2026-11-13T14:44:34.386Z | unverified-lead |
| CVE-2026-125807 |  | unknown | 2026-11-13T14:44:34.386Z | unverified-lead |
| CVE-2026-125824 |  | unknown | 2026-11-13T14:44:34.386Z | unverified-lead |
| CVE-2026-125819 |  | unknown | 2026-11-13T14:44:34.386Z | unverified-lead |
| CVE-2026-107524 |  | unknown | 2026-11-13T14:38:35.166Z | unverified-lead |
| CVE-2026-128909 |  | unknown | 2026-11-13T14:38:35.166Z | unverified-lead |
| CVE-2026-128910 |  | unknown | 2026-11-13T14:38:35.166Z | unverified-lead |
| CVE-2026-128908 |  | unknown | 2026-11-13T14:38:35.166Z | unverified-lead |
| CVE-2026-127031 |  | unknown | 2026-11-13T14:38:35.166Z | unverified-lead |

## Left unchanged

The PostgreSQL, TomEE, dbus, DataSketches C++, and other oss-security notes are in `docs/threat-scan-2026-11-13.md`. None of the window identifiers is one of those. The CISA catalog is still `2026.11.10`. The alerts HTML page returned HTTP 200, and the newest row is still 10 November 2026.

Fifty-six identifiers from the 12 November unverified section are now in the NVD recent feed, all with no CPE. Two remain absent: CVE-2025-8714 and CVE-2023-39417. The details are in `docs/threat-scan-2026-11-13.md`.

Vendor pages checked on this run did not move a floor. The Node.js security release recorded on 12 November is unchanged. The details are in `docs/threat-scan-2026-11-13.md`.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
