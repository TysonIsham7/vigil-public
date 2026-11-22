# Threat scan leads, 22 November 2026

This note is the cve.now lead pass for 22 November 2026. The CISA catalog, the NVD follow-up, the new oss-security messages, and the Chrome Dev note are in `docs/threat-scan-2026-11-22.md`.

Pages and the feed were read as evidence. Instructions inside them were not followed. No version floor was invented from feed prose. No remote probe was added. No advisory file was added from the feed.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called.

The lead feed was fetched once, at `https://cve.now/feed?format=json`. The response was HTTP 200 from that same URL, with no redirect. The content type was `application/feed+json`. The body had 200 items. Identifiers were taken from the newest items by `date_modified` with a deterministic regex. The window is 56 items because items that share the cutoff timestamp are kept together. The newest item is `2026-11-22T14:20:34.287Z`. The cutoff is `2026-11-22T11:18:34.341Z`. Titles and `content_text` were discarded. No item had a structured dotted version outside those fields. No GHSA id was in the window. No OSV id was in the window.

Two identifiers in the window were already recorded. CVE-2026-115563 is the Model Context Protocol Python SDK from the 17 November scan. It is not CPython, and it is not `@modelcontextprotocol/sdk`. CVE-2026-120984 was an unverified lead on 7 November. Neither was copied again. The other identifiers were not already recorded in `docs/threat-scan-*.md`, `docs/TODO.md`, an open scan pull request, or `packages/intel/advisories/`.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## No confirmed stack overlap

No identifier in the window was confirmed on NVD, CISA, or a pre-written vendor host as a product on the runtime list or in `packages/intel/advisories/` that `vigil doctor` can check.

Whole-token matches were three `wordpress`, one `go`, one `python`, and thirty-two `linux` plus `kernel`. The `wordpress` matches are CVE-2026-134748, CVE-2026-134750, and CVE-2026-131780. They are not in the NVD recent feed. That is not WordPress core. The `go` match is CVE-2026-134754. It is not in the NVD recent feed. That is not the Go toolchain. The `python` match is CVE-2026-115563, already recorded, and it is not CPython. The `linux` and `kernel` matches that are in NVD are the kernel records below. No plugin list was added. No doctor check was added from a token.

## NVD records that name another product

These identifiers are in the window and in the NVD recent feed. None has a CPE. Matched is no. Vigil cannot see these products from a page or a certificate. No doctor check was added.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz), timestamp `2026-11-22T08:00:01.386575`.

| Product | Version | Matched | Date | NVD status |
|---|---|---|---|---|
| tiny-secp256k1 (CVE-2026-107853) | 2.1.0 until 2.2.5, and @bitcoin-js/tiny-secp256k1-asmjs 2.2.2 until 2.2.5. The description says 2.2.5 fixes it | no | 2026-11-22T13:58:34.327Z | Received |
| Guard Core (CVE-2026-129302) | 3.5.0 until 3.13.0. The description says 3.13.0 fixes it | no | 2026-11-22T13:58:34.327Z | Received |
| Guard Core (CVE-2026-129303) | 1.0.0 until 3.13.0. The description says 3.13.0 fixes it | no | 2026-11-22T13:58:34.327Z | Received |
| Guard Core (CVE-2026-129304) | 1.0.0 until 3.13.0. The description says 3.13.0 fixes it | no | 2026-11-22T13:58:34.327Z | Received |
| fzf (CVE-2026-121716) | before 0.74.5. The description says 0.74.5 fixes it | no | 2026-11-22T13:58:34.327Z | Received |
| BeamNG.drive (CVE-2026-133528) | before 0.40.6 | no | 2026-11-22T13:58:34.327Z | Received |

## Linux kernel records

These thirty-two identifiers are in the window and in the NVD recent feed. Status is Received. None has a CPE. Each description says the vulnerability has been resolved and names no released kernel version. Matched is unknown. No kernel floor was invented. No doctor check was added.

CVE-2026-99674, CVE-2026-99676, CVE-2026-99678, CVE-2026-99679, CVE-2026-99680, CVE-2026-99685, CVE-2026-99686, CVE-2026-99688, CVE-2026-99690, CVE-2026-99697, CVE-2026-99707, CVE-2026-99715, CVE-2026-99724, CVE-2026-99725, CVE-2026-99728, CVE-2026-99730, CVE-2026-99735, CVE-2026-99744, CVE-2026-99746, CVE-2026-99753, CVE-2026-99754, CVE-2026-99758, CVE-2026-99760, CVE-2026-99761, CVE-2026-99773, CVE-2026-99785, CVE-2026-99792, CVE-2026-99793, CVE-2026-99794, CVE-2026-99798, CVE-2026-99800, and CVE-2026-99804.

The feed date for each is `2026-11-22T11:18:34.341Z`.

## Unverified leads

These identifiers were in the window and were not in the NVD recent feed. They are not in the CISA catalog. Status is unverified-lead. Product is the identifier. Version is blank. Matched is unknown. No fix version was present as a structured field. The `SZB-` row is not a CVE, GHSA, or OSV id.

Source: [cve.now JSON feed](https://cve.now/feed?format=json).

| Product | Version | Matched | Date | Status |
|---|---|---|---|---|
| CVE-2026-134749 |  | unknown | 2026-11-22T14:20:34.287Z | unverified-lead |
| CVE-2026-134748 |  | unknown | 2026-11-22T14:20:34.287Z | unverified-lead |
| CVE-2026-134755 |  | unknown | 2026-11-22T14:20:34.287Z | unverified-lead |
| CVE-2026-134754 |  | unknown | 2026-11-22T14:20:34.287Z | unverified-lead |
| CVE-2026-134752 |  | unknown | 2026-11-22T14:20:34.287Z | unverified-lead |
| CVE-2026-134750 |  | unknown | 2026-11-22T14:20:34.287Z | unverified-lead |
| CVE-2026-134751 |  | unknown | 2026-11-22T14:20:34.287Z | unverified-lead |
| CVE-2026-134753 |  | unknown | 2026-11-22T14:20:34.287Z | unverified-lead |
| CVE-2026-134756 |  | unknown | 2026-11-22T14:20:34.287Z | unverified-lead |
| CVE-2026-134757 |  | unknown | 2026-11-22T14:20:34.287Z | unverified-lead |
| CVE-2026-134758 |  | unknown | 2026-11-22T14:20:34.287Z | unverified-lead |
| CVE-2026-131780 |  | unknown | 2026-11-22T14:05:34.570Z | unverified-lead |
| SZB-FEDAA30594 |  | unknown | 2026-11-22T14:02:17.333Z | unverified-lead |
| CVE-2019-20446 |  | unknown | 2026-11-22T13:58:34.327Z | unverified-lead |
| CVE-2026-112020 |  | unknown | 2026-11-22T13:58:34.327Z | unverified-lead |
| CVE-2026-114728 |  | unknown | 2026-11-22T13:58:34.327Z | unverified-lead |

## Left unchanged

The catalog is still `2026.11.20`. None of the window identifiers is one of the four catalog entries recorded on 21 November. The Java alert names CVE-2026-114938, which was not in this window. The details are in `docs/threat-scan-2026-11-22.md`.

Twenty-five of the twenty-six identifiers from the 21 November unverified section are now in the NVD recent feed, all with no CPE. CVE-2021-1905 stays absent. The details are in `docs/threat-scan-2026-11-22.md`.

Vendor pages checked on this run did not move a floor. The details are in `docs/threat-scan-2026-11-22.md`.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
