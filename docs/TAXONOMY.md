# Finding taxonomy

Every Vigil finding carries a taxonomy tag copied from [`packages/core/data/rule-catalog.json`](../packages/core/data/rule-catalog.json). That file is the source of truth. Rule code looks up an id with `createFinding`. It does not hard-code the domain or the framework mapping. A rule id missing from the catalog fails closed.

`summary.byDomain` is always the eleven domains below, in this order, with severity counts. A domain with no findings stays at zero. Saved lightweight findings keep the domain id and drop evidence.

This is a routing aid for people who already sort work by CSF or CIS. It is not a scored assessment, and a finding is not evidence that a safeguard is unmet.

## Domains

| Id | Label | What Vigil uses it for |
|---|---|---|
| `grc` | GRC | The scanner's own policy. Today this is only a fetch truncated at the size limit. |
| `identity-access` | Identity & Access | Session cookies written from script, and `Set-Cookie` missing Secure, HttpOnly, or SameSite. |
| `data-security-privacy` | Data Security & Privacy | Secrets in source, tokens in web storage, and Referrer-Policy. |
| `network-infrastructure` | Network & Infrastructure | Security headers, mixed content, TLS misconfiguration, and DNS or web-filter signals: new domains, suspicious TLDs, free hosting, deep subdomains, IP literals. |
| `endpoint-device` | Endpoint & Device | Local Node, curl, Go, nginx, and kernel versions from `vigil doctor`, and a local trust store that still contains a distrusted eMudhra key. |
| `application-software` | Application & Software | XSS and the other code-level rules, PHP and WordPress fingerprints, and OSV dependency results. This is the SBOM and dependency bucket. |
| `cloud-hybrid` | Cloud & Hybrid | Hosting-hint header notes, curl, Go, or nginx versions in container base images, and the informational shared-host note on a URL scan. That note says the host kernel was not visible. It is not a claim that the site is affected. |
| `threat-intel` | Threat Intel/Detection/Response | Distrusted CAs (including the eight eMudhra intermediates and emSign ECC Root CA - G3), missing embedded SCTs, lookalike names, and a domain younger than 7 days that also has a login form. |
| `operational-resilience` | Operational Resilience | Expired certificates, and certificates with fewer than 14 days left. |
| `human-factors` | Human Factors | Brand impersonation, credential forms posted cross-origin or over http, and a login form on an IP literal. |
| `emerging-tech` | Emerging Tech | The compromised LiteLLM 1.107.0 release. |

## NIST CSF 2.0

The catalog stores a CSF 2.0 category. The function is the category prefix.

| Function | Used for |
|---|---|
| Govern (`GV`) | `GV.SC` for the LiteLLM supply-chain compromise. `GV.PO` for a truncated fetch, which is scanner policy rather than a property of the target. |
| Identify (`ID`) | `ID.AM` for a WordPress fingerprint. `ID.RA` for PHP, OSV, curl, Go, nginx, the local kernel, a local eMudhra trust hit, and the shared-host note. |
| Protect (`PR`) | `PR.PS` for code defects and most headers. `PR.DS` for secrets and transport. `PR.AA` for cookies and cross-origin credential posts. `PR.AT` for brand impersonation. `PR.IR` for certificate lifetime. |
| Detect (`DE`) | `DE.CM` for lookalikes, DNS and web-filter signals, and CT presence. `DE.AE` for a chain that contains a distrusted CA, and for a brand-new domain with a login form. |
| Respond (`RS`), Recover (`RC`) | No current rule. Both functions are listed in the catalog so a later advisory can use them without a schema change. |

## CIS Controls v8.1

A safeguard id is stored only when that safeguard's wording is a fair description of the check. Otherwise the catalog stores the control and omits the safeguard. `cis: null` means no CIS control is a fair mapping. That is `CERT_UNAVAILABLE` (the check did not run), `FETCH_TRUNCATED` (a scanner limit), and `KERNEL_SHARED_HOST` (the host kernel was not observed).

| Control | Title | Vigil examples |
|---|---|---|
| 2 | Inventory and Control of Software Assets | WordPress fingerprint (`2.1`). Local curl, Go, nginx, or a trust store still carrying a distrusted eMudhra key (`2.2`). |
| 3 | Data Protection | Secrets and tokens (`3.1`). HSTS, mixed content, and weak TLS (`3.10`). Referrer-Policy is control 3 with no safeguard, because a DLP safeguard would overstate the check. |
| 4 | Secure Configuration of Enterprise Assets and Software | CSP, framing, Permissions-Policy, and certificate lifetime (`4.1`). |
| 6 | Access Control Management | Cookie flags. No safeguard is set: the v8.1 MFA safeguards are a different control. |
| 7 | Continuous Vulnerability Management | Confirmed PHP bugs and vulnerable base images (`7.4`). The local kernel version (`7.3`, operating-system patch management). OSV results (`7.1`). |
| 9 | Email and Web Browser Protections | Lookalikes and DNS signals (`9.2`). Distrusted CAs and URL-filter signals (`9.3`). |
| 12 | Network Infrastructure Management | Hostname mismatch, self-signed leaves, and TLS that did not validate (`12.1`). |
| 13 | Network Monitoring and Defense | CSP report-only, and missing embedded SCTs. No safeguard is set. |
| 14 | Security Awareness and Skills Training | Brand impersonation, and a login form served from an IP address (`14.2`). |
| 16 | Application Software Security | XSS and the other code-level rules (`16.12`). Untrusted LiteLLM 1.107.0 (`16.5`). |

## Adding a rule

1. Add the id under `rules` in `packages/core/data/rule-catalog.json`.
2. Use one of the eleven domain ids.
3. Set `nist` to a CSF 2.0 category already listed in `nistCategories`, or add the category there first.
4. Set `cis` to a control listed in `cisControls`. Add `safeguard` and `safeguardTitle` only when the wording matches. Use `null` when no control fits.
5. Emit the finding through `createFinding`. Call sites do not pass a taxonomy object.
