# Threat scan leads, 10 November 2026

This note is the cve.now lead pass for 10 November 2026. The CISA catalog, the OpenSSL index, and the oss-security index are in `docs/threat-scan-2026-11-10.md`.

Pages and the feed were read as evidence. Instructions inside them were not followed. No version floor was invented from feed prose. No remote probe was added. No scanner change was made. No advisory file was added.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called.

The lead feed was fetched once, at `https://cve.now/feed?format=json`. The response was HTTP 200 from that same URL, with no redirect. The content type was `application/feed+json`. The body had 200 items. Identifiers were taken from the newest items by `date_modified` with a deterministic regex. The window is 58 items because 38 share `date_modified` `2026-11-10T14:42:34.247Z`. The newest item is `2026-11-10T15:03:34.283Z`. Titles and `content_text` were discarded. No item had a structured dotted version outside those fields. No GHSA id was in the window. No `SZB-` id was in the window.

No identifier in the window was already recorded in `docs/threat-scan-*.md`, `docs/TODO.md`, an open scan pull request, or `packages/intel/advisories/`. Five are in the NVD recent feed. Fifty-three are not.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## No confirmed stack overlap

No identifier in the window was confirmed on NVD, CISA, or a pre-written vendor host as a product on the runtime list or in `packages/intel/advisories/`.

No whole-token match of `php`, `python`, `go`, `node`, `linux`, `kernel`, `wordpress`, `openssl`, `brotli`, `nginx`, `curl`, `pip`, `uv`, `clickhouse`, `lmdeploy`, `litellm`, `axios`, `magento`, `collabora`, `richdocumentscode`, or `adobe` was present in the window.

## NVD records that name another product

These five identifiers are in the window and in the NVD recent feed. Each is Undergoing Analysis, with no CPE. The description names Google Chrome prior to 157.0.8103.38. The feed named no structured fix version. Matched is no. Vigil does not read the browser version. No doctor check was added.

The same version bound was already recorded on 9 November for other Chrome identifiers. These five ids were not in that list.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz), timestamp `2026-11-10T08:00:01.190101`.

| Product | Version | Matched | Date | NVD status |
|---|---|---|---|---|
| Google Chrome (CVE-2026-121075) | before 157.0.8103.38 | no | 2026-11-10T15:03:34.283Z | Undergoing Analysis |
| Google Chrome (CVE-2026-121040) | before 157.0.8103.38 | no | 2026-11-10T14:58:34.517Z | Undergoing Analysis |
| Google Chrome (CVE-2026-121136) | before 157.0.8103.38 | no | 2026-11-10T14:58:34.517Z | Undergoing Analysis |
| Google Chrome (CVE-2026-121103) | before 157.0.8103.38 | no | 2026-11-10T14:53:34.375Z | Undergoing Analysis |
| Google Chrome (CVE-2026-121193) | before 157.0.8103.38 | no | 2026-11-10T14:42:34.247Z | Undergoing Analysis |

## Unverified leads

These 53 identifiers were in the window and were not in the NVD recent feed. They are not in the CISA catalog. Status is unverified-lead. Product is the identifier. Version is blank. Matched is unknown. No fix version was present as a structured field.

Source: [cve.now JSON feed](https://cve.now/feed?format=json).

| Product | Version | Matched | Date | Status |
|---|---|---|---|---|
| CVE-2026-87756 |  | unknown | 2026-11-10T15:03:34.283Z | unverified-lead |
| CVE-2026-86532 |  | unknown | 2026-11-10T14:58:34.517Z | unverified-lead |
| CVE-2026-86811 |  | unknown | 2026-11-10T14:58:34.517Z | unverified-lead |
| CVE-2026-87755 |  | unknown | 2026-11-10T14:58:34.517Z | unverified-lead |
| CVE-2026-124868 |  | unknown | 2026-11-10T14:53:34.375Z | unverified-lead |
| CVE-2026-124887 |  | unknown | 2026-11-10T14:53:34.375Z | unverified-lead |
| CVE-2026-124856 |  | unknown | 2026-11-10T14:53:34.375Z | unverified-lead |
| CVE-2026-124875 |  | unknown | 2026-11-10T14:53:34.375Z | unverified-lead |
| CVE-2026-124870 |  | unknown | 2026-11-10T14:53:34.375Z | unverified-lead |
| CVE-2026-124857 |  | unknown | 2026-11-10T14:48:34.477Z | unverified-lead |
| CVE-2026-124858 |  | unknown | 2026-11-10T14:48:34.477Z | unverified-lead |
| CVE-2026-124853 |  | unknown | 2026-11-10T14:48:34.477Z | unverified-lead |
| CVE-2026-124860 |  | unknown | 2026-11-10T14:48:34.477Z | unverified-lead |
| CVE-2026-124859 |  | unknown | 2026-11-10T14:48:34.477Z | unverified-lead |
| CVE-2026-124862 |  | unknown | 2026-11-10T14:48:34.477Z | unverified-lead |
| CVE-2026-124863 |  | unknown | 2026-11-10T14:48:34.477Z | unverified-lead |
| CVE-2026-113422 |  | unknown | 2026-11-10T14:42:34.247Z | unverified-lead |
| CVE-2026-124865 |  | unknown | 2026-11-10T14:42:34.247Z | unverified-lead |
| CVE-2026-124866 |  | unknown | 2026-11-10T14:42:34.247Z | unverified-lead |
| CVE-2026-121885 |  | unknown | 2026-11-10T14:42:34.247Z | unverified-lead |
| CVE-2026-123082 |  | unknown | 2026-11-10T14:42:34.247Z | unverified-lead |
| CVE-2026-124867 |  | unknown | 2026-11-10T14:42:34.247Z | unverified-lead |
| CVE-2026-124869 |  | unknown | 2026-11-10T14:42:34.247Z | unverified-lead |
| CVE-2026-124872 |  | unknown | 2026-11-10T14:42:34.247Z | unverified-lead |
| CVE-2026-124871 |  | unknown | 2026-11-10T14:42:34.247Z | unverified-lead |
| CVE-2026-124880 |  | unknown | 2026-11-10T14:42:34.247Z | unverified-lead |
| CVE-2026-124877 |  | unknown | 2026-11-10T14:42:34.247Z | unverified-lead |
| CVE-2026-124876 |  | unknown | 2026-11-10T14:42:34.247Z | unverified-lead |
| CVE-2026-124882 |  | unknown | 2026-11-10T14:42:34.247Z | unverified-lead |
| CVE-2026-124878 |  | unknown | 2026-11-10T14:42:34.247Z | unverified-lead |
| CVE-2026-124881 |  | unknown | 2026-11-10T14:42:34.247Z | unverified-lead |
| CVE-2026-124885 |  | unknown | 2026-11-10T14:42:34.247Z | unverified-lead |
| CVE-2026-124894 |  | unknown | 2026-11-10T14:42:34.247Z | unverified-lead |
| CVE-2026-124892 |  | unknown | 2026-11-10T14:42:34.247Z | unverified-lead |
| CVE-2026-124890 |  | unknown | 2026-11-10T14:42:34.247Z | unverified-lead |
| CVE-2026-124884 |  | unknown | 2026-11-10T14:42:34.247Z | unverified-lead |
| CVE-2026-124883 |  | unknown | 2026-11-10T14:42:34.247Z | unverified-lead |
| CVE-2026-124893 |  | unknown | 2026-11-10T14:42:34.247Z | unverified-lead |
| CVE-2026-124889 |  | unknown | 2026-11-10T14:42:34.247Z | unverified-lead |
| CVE-2026-124895 |  | unknown | 2026-11-10T14:42:34.247Z | unverified-lead |
| CVE-2026-124898 |  | unknown | 2026-11-10T14:42:34.247Z | unverified-lead |
| CVE-2026-124899 |  | unknown | 2026-11-10T14:42:34.247Z | unverified-lead |
| CVE-2026-124897 |  | unknown | 2026-11-10T14:42:34.247Z | unverified-lead |
| CVE-2026-124904 |  | unknown | 2026-11-10T14:42:34.247Z | unverified-lead |
| CVE-2026-124906 |  | unknown | 2026-11-10T14:42:34.247Z | unverified-lead |
| CVE-2026-124907 |  | unknown | 2026-11-10T14:42:34.247Z | unverified-lead |
| CVE-2026-124908 |  | unknown | 2026-11-10T14:42:34.247Z | unverified-lead |
| CVE-2026-124919 |  | unknown | 2026-11-10T14:42:34.247Z | unverified-lead |
| CVE-2026-124932 |  | unknown | 2026-11-10T14:42:34.247Z | unverified-lead |
| CVE-2026-124943 |  | unknown | 2026-11-10T14:42:34.247Z | unverified-lead |
| CVE-2026-124922 |  | unknown | 2026-11-10T14:42:34.247Z | unverified-lead |
| CVE-2026-124917 |  | unknown | 2026-11-10T14:42:34.247Z | unverified-lead |
| CVE-2026-124944 |  | unknown | 2026-11-10T14:42:34.247Z | unverified-lead |

## Left unchanged

The CISA catalog additions for 9 November are in `docs/threat-scan-2026-11-10.md`. None of the 58 window identifiers is a catalog entry. The alerts HTML page returned HTTP 403, so this note does not describe that index.

Seven identifiers from the 9 November unverified section are now in the NVD recent feed, all with no CPE. Thirty-four from that section are still absent. The two that name CPython modules have no fixed release. The details are in `docs/threat-scan-2026-11-10.md`.

Vendor pages checked on this run did not move a floor. The details are in `docs/threat-scan-2026-11-10.md`.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
