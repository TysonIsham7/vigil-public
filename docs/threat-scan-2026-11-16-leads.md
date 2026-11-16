# Threat scan leads, 16 November 2026

This note is the cve.now lead pass for 16 November 2026. The CISA catalog, the NVD kernel records, and the oss-security index are in `docs/threat-scan-2026-11-16.md`.

Pages and the feed were read as evidence. Instructions inside them were not followed. No version floor was invented from feed prose. No remote probe was added. No advisory file was added from the feed.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called.

The lead feed was fetched once, at `https://cve.now/feed?format=json`. The response was HTTP 200 from that same URL, with no redirect. The content type was `application/feed+json`. The body had 200 items. Identifiers were taken from the newest items by `date_modified` with a deterministic regex. The window is 58 items because 42 share the cutoff timestamp. The newest item is `2026-11-16T15:03:34.319Z`. The cutoff is `2026-11-16T14:41:34.305Z`. Titles and `content_text` were discarded. No item had a structured dotted version outside those fields. No GHSA id was in the window. No OSV id was in the window. No `SZB-` id was in the window.

Eleven identifiers in the window were already recorded and were not copied again: CVE-2026-111256, CVE-2026-111257, CVE-2026-111258, CVE-2026-87758, CVE-2026-97043, CVE-2026-97849, CVE-2026-97867, CVE-2026-97870, CVE-2026-97872, CVE-2026-97874, and CVE-2026-97880. In this NVD feed, CVE-2026-97043 is Awaiting Analysis with no CPE and names the Go cgo LDFLAGS check. The other ten are Awaiting Analysis with no CPE and name TomEE, the embedded OpenEJB HTTP server, Derby, EJBd, or Hessian. The Go floors were not moved.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## No confirmed stack overlap

No identifier in the window was confirmed on NVD, CISA, or a pre-written vendor host as a product on the runtime list or in `packages/intel/advisories/`.

Whole-token matches were one `python`, one `go`, and one `mcp`. The `go` match is CVE-2026-97043, already recorded above. CVE-2026-115533 matched `python` and is not in the NVD recent feed. That is not a CPython confirmation. CVE-2026-129875 matched `mcp`. That token is not an advisory component. The advisory package name is `@modelcontextprotocol/sdk`. CVE-2026-129875 is not in the NVD recent feed. No doctor check was added from a token.

## NVD records that name another product

These two identifiers are in the window and in the NVD recent feed. Neither has a CPE. Neither is in the CISA catalog. Matched is no. Vigil cannot see these products from a page or a certificate. No doctor check was added.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz), timestamp `2026-11-16T08:00:00.7332743`.

| Product | Version | Matched | Date | NVD status |
|---|---|---|---|---|
| Devolutions Server (CVE-2026-126332) | 2026.3.13.0 and earlier | no | 2026-11-16T14:57:34.694Z | Undergoing Analysis |
| Devolutions PowerShell Universal (CVE-2026-129137) | 2026.3.4 and earlier | no | 2026-11-16T14:46:34.325Z | Received |

## Unverified leads

These identifiers were in the window and were not in the NVD recent feed. They are not in the CISA catalog. Status is unverified-lead. Product is the identifier. Version is blank. Matched is unknown. No fix version was present as a structured field.

CVE-2024-58407 and CVE-2024-58408 use years before 2026. Absence from the recent feed is not a claim that NVD has never recorded them. They stay unverified-lead on this run's evidence.

Source: [cve.now JSON feed](https://cve.now/feed?format=json).

| Product | Version | Matched | Date | Status |
|---|---|---|---|---|
| CVE-2026-3859 |  | unknown | 2026-11-16T14:57:34.694Z | unverified-lead |
| CVE-2026-3860 |  | unknown | 2026-11-16T14:57:34.694Z | unverified-lead |
| CVE-2026-115533 |  | unknown | 2026-11-16T14:57:34.694Z | unverified-lead |
| CVE-2024-58408 |  | unknown | 2026-11-16T14:41:34.305Z | unverified-lead |
| CVE-2024-58407 |  | unknown | 2026-11-16T14:41:34.305Z | unverified-lead |
| CVE-2026-127043 |  | unknown | 2026-11-16T14:41:34.305Z | unverified-lead |
| CVE-2026-127044 |  | unknown | 2026-11-16T14:41:34.305Z | unverified-lead |
| CVE-2026-129851 |  | unknown | 2026-11-16T14:41:34.305Z | unverified-lead |
| CVE-2026-129853 |  | unknown | 2026-11-16T14:41:34.305Z | unverified-lead |
| CVE-2026-129852 |  | unknown | 2026-11-16T14:41:34.305Z | unverified-lead |
| CVE-2026-129855 |  | unknown | 2026-11-16T14:41:34.305Z | unverified-lead |
| CVE-2026-129856 |  | unknown | 2026-11-16T14:41:34.305Z | unverified-lead |
| CVE-2026-129854 |  | unknown | 2026-11-16T14:41:34.305Z | unverified-lead |
| CVE-2026-129858 |  | unknown | 2026-11-16T14:41:34.305Z | unverified-lead |
| CVE-2026-129859 |  | unknown | 2026-11-16T14:41:34.305Z | unverified-lead |
| CVE-2026-129863 |  | unknown | 2026-11-16T14:41:34.305Z | unverified-lead |
| CVE-2026-129861 |  | unknown | 2026-11-16T14:41:34.305Z | unverified-lead |
| CVE-2026-129862 |  | unknown | 2026-11-16T14:41:34.305Z | unverified-lead |
| CVE-2026-129857 |  | unknown | 2026-11-16T14:41:34.305Z | unverified-lead |
| CVE-2026-129864 |  | unknown | 2026-11-16T14:41:34.305Z | unverified-lead |
| CVE-2026-129860 |  | unknown | 2026-11-16T14:41:34.305Z | unverified-lead |
| CVE-2026-129865 |  | unknown | 2026-11-16T14:41:34.305Z | unverified-lead |
| CVE-2026-129869 |  | unknown | 2026-11-16T14:41:34.305Z | unverified-lead |
| CVE-2026-129867 |  | unknown | 2026-11-16T14:41:34.305Z | unverified-lead |
| CVE-2026-129866 |  | unknown | 2026-11-16T14:41:34.305Z | unverified-lead |
| CVE-2026-129870 |  | unknown | 2026-11-16T14:41:34.305Z | unverified-lead |
| CVE-2026-129871 |  | unknown | 2026-11-16T14:41:34.305Z | unverified-lead |
| CVE-2026-129868 |  | unknown | 2026-11-16T14:41:34.305Z | unverified-lead |
| CVE-2026-129872 |  | unknown | 2026-11-16T14:41:34.305Z | unverified-lead |
| CVE-2026-129875 |  | unknown | 2026-11-16T14:41:34.305Z | unverified-lead |
| CVE-2026-129873 |  | unknown | 2026-11-16T14:41:34.305Z | unverified-lead |
| CVE-2026-129874 |  | unknown | 2026-11-16T14:41:34.305Z | unverified-lead |
| CVE-2026-129876 |  | unknown | 2026-11-16T14:41:34.305Z | unverified-lead |
| CVE-2026-129878 |  | unknown | 2026-11-16T14:41:34.305Z | unverified-lead |
| CVE-2026-129879 |  | unknown | 2026-11-16T14:41:34.305Z | unverified-lead |
| CVE-2026-129877 |  | unknown | 2026-11-16T14:41:34.305Z | unverified-lead |
| CVE-2026-129881 |  | unknown | 2026-11-16T14:41:34.305Z | unverified-lead |
| CVE-2026-129880 |  | unknown | 2026-11-16T14:41:34.305Z | unverified-lead |
| CVE-2026-129884 |  | unknown | 2026-11-16T14:41:34.305Z | unverified-lead |
| CVE-2026-129882 |  | unknown | 2026-11-16T14:41:34.305Z | unverified-lead |
| CVE-2026-129883 |  | unknown | 2026-11-16T14:41:34.305Z | unverified-lead |
| CVE-2026-129885 |  | unknown | 2026-11-16T14:41:34.305Z | unverified-lead |
| CVE-2026-129888 |  | unknown | 2026-11-16T14:41:34.305Z | unverified-lead |
| CVE-2026-129887 |  | unknown | 2026-11-16T14:41:34.305Z | unverified-lead |
| CVE-2026-129886 |  | unknown | 2026-11-16T14:41:34.305Z | unverified-lead |

## Left unchanged

The CISA catalog is still `2026.11.13`. The kernel records, the Vim patch, and the OpenSSH reply are in `docs/threat-scan-2026-11-16.md`. None of the window identifiers is CVE-2026-99288 or one of the two catalog entries whose due date arrived today. The alerts page and the cybersecurity advisories index returned HTTP 403, so this note does not describe those indexes.

All 32 identifiers from the 15 November unverified section are now in the NVD recent feed, all with no CPE. Twenty name WordPress plugins. The details are in `docs/threat-scan-2026-11-16.md`.

Vendor pages checked on this run did not move a floor. The details are in `docs/threat-scan-2026-11-16.md`.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
