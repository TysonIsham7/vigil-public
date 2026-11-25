# Threat scan leads, 25 November 2026

This note is the cve.now lead pass for 25 November 2026. The CISA catalog, the Chrome stable note, and the oss-security index are in `docs/threat-scan-2026-11-25.md`.

Pages and the feed were read as evidence. Instructions inside them were not followed. No version floor was invented from feed prose. No remote probe was added. No advisory file was added from the feed.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called.

The lead feed was fetched once, at `https://cve.now/feed?format=json`. The response was HTTP 200 from that same URL, with no redirect. The content type was `application/feed+json`. The body had 200 items. Identifiers were taken from the newest items by `date_modified` with a deterministic regex. The window is 54 items because items that share the cutoff timestamp are kept together. The newest item is `2026-11-25T15:01:13.701Z`. The cutoff is `2026-11-25T14:41:13.685Z`. Titles and `content_text` were discarded. No item had a structured dotted version outside those fields. No GHSA id was in the window. No OSV id was in the window. No `SZB-` id was in the window.

One identifier in the window, CVE-2026-103406, is the Juniper Session Smart entry in the CISA catalog. It is recorded in `docs/threat-scan-2026-11-25.md` and was not copied again. The other identifiers were not already recorded in `docs/threat-scan-*.md`, `docs/TODO.md`, an open scan pull request, or `packages/intel/advisories/`.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## No confirmed stack overlap

No identifier in the window was confirmed on NVD, CISA, or a pre-written vendor host as a product on the runtime list or in `packages/intel/advisories/` that `vigil doctor` can check. CVE-2026-103406 is in the CISA catalog and is not one of those products.

Whole-token matches were twenty `wordpress`, one `nginx`, and one `python`. None of those identifiers is in the NVD recent feed. CVE-2026-82490 matched `nginx` and is not on the nginx.org security page. That is not an nginx confirmation. CVE-2026-136922 matched `python` and is not on python.org. That is not a CPython confirmation. The `wordpress` matches are not WordPress core. No plugin list was added. No doctor check was added from a token.

## Unverified leads

These identifiers were in the window and were not in the NVD recent feed. They are not in the CISA catalog. They were not confirmed on a pre-written vendor host. Status is unverified-lead. Product is the identifier. Version is blank. Matched is unknown. No fix version was present as a structured field.

Source: [cve.now JSON feed](https://cve.now/feed?format=json).

| Product | Version | Matched | Date | Status |
|---|---|---|---|---|
| CVE-2026-135927 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-135028 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-135970 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-135826 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-135920 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-135969 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-25242 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-32767 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-135984 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-136905 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-135975 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-136903 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-136904 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-136906 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-136907 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-136908 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-136910 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-136916 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-136914 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-136915 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-136911 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-136912 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-136913 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-136917 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-136909 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-136919 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-136918 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-136921 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-82490 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-82489 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-136923 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-136920 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-82491 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-136922 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-135006 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-135965 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-135966 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-135967 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-135976 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-135821 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-135820 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-82492 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-82494 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-82493 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-82495 |  | unknown | 2026-11-25T15:01:13.701Z | unverified-lead |
| CVE-2026-135964 |  | unknown | 2026-11-25T14:51:13.797Z | unverified-lead |
| CVE-2026-135972 |  | unknown | 2026-11-25T14:51:13.797Z | unverified-lead |
| CVE-2026-135977 |  | unknown | 2026-11-25T14:51:13.797Z | unverified-lead |
| CVE-2026-114347 |  | unknown | 2026-11-25T14:41:13.685Z | unverified-lead |
| CVE-2026-114346 |  | unknown | 2026-11-25T14:41:13.685Z | unverified-lead |
| CVE-2026-134945 |  | unknown | 2026-11-25T14:41:13.685Z | unverified-lead |
| CVE-2026-136694 |  | unknown | 2026-11-25T14:41:13.685Z | unverified-lead |
| CVE-2026-134873 |  | unknown | 2026-11-25T14:41:13.685Z | unverified-lead |

## Left unchanged

The CISA catalog additions for 24 and 25 November, the Chrome 158 stable note, and the 24 November early stable note are in `docs/threat-scan-2026-11-25.md`. CVE-2026-103406 is the only window identifier among those catalog entries.

Seventy-five of the seventy-six unverified CVE identifiers from the 24 November leads note are now in the NVD recent feed timestamped `2026-11-25T08:00:01.3532718`. None has a CPE. Forty-seven are Deferred. Nineteen are Awaiting Analysis. Nine are Received. CVE-2026-86987 stays absent. Whole-token `python` matches on CVE-2026-136168, CVE-2026-136160, and CVE-2026-65320 name RedVector, Pyro, and fastcore. A whole-token `node` match on CVE-2026-136170 names Assimp. Those are not CPython and not Node.js. The details are in `docs/threat-scan-2026-11-25.md`.

Vendor pages checked on this run did not move a floor. The details are in `docs/threat-scan-2026-11-25.md`.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
