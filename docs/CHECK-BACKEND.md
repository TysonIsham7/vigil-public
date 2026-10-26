# check-backend

`vigil check-backend <url>` fingerprints backend exposure on a site you open as a visitor. Banks, vendors, and other sites you do not operate are in scope only as a client check: the result says what that server is advertising, not that you should attack it and not that you can patch it.

This page is the command's contract. The rule catalog remains the source of truth for domains. See [Finding taxonomy](TAXONOMY.md).

## Passive-only guarantee

The command sends ordinary client traffic and nothing else.

- The method is GET. There is no request body.
- The user agent is `vigil/2.0`. The Accept header is a short browser-style list. Neither header is a payload.
- One browser-style TLS handshake per HTTPS origin, with TLS 1.2 as the minimum and TLS 1.3 as the maximum. The cipher offer lists AEAD suites first, then ordinary CBC suites. It does not offer export, null, RC4, or DES suites.
- Two protocol-support handshakes after that, one capped at TLS 1.0 and one capped at TLS 1.1. They offer ordinary AES-SHA suites, because TLS 1.0 cannot negotiate the AEAD list, and they do not offer export, null, RC4, or DES. OpenSSL 3 hides TLS 1.0 at its default security level, so only these two sockets lower that level. Each handshake ends before any HTTP request. A handshake that completes is a legacy-protocol finding. A handshake the server refuses is not.
- One GET for a missing page, `/this-page-is-missing`, so a default 404 or 500 can be recognized.
- GET requests for the known paths below. Each path is short, has no query string, and contains no `..`.
- Response bodies are capped. Extra path GETs stop when the scan's time budget is spent. The handshake still runs. A TLS certificate error on the first GET skips the later GETs, because they would fail the same way, and the handshake still runs.
- Fetches use the same address checks as the rest of Vigil. A private, loopback, or metadata address is refused before the request.

The command does not send crash payloads, oversized requests, exploit bodies, or repeated timing samples. A path is reported only when a 200 response matches a signature. A 403, and a 200 page that is ordinary HTML, are not findings. A version printed only in a page body is not used for the PHP comparison.

## Permission

Active probing of a host you do not own may breach that host's terms of service or computer-misuse law. Run the command only on hosts you are allowed to test. A fingerprint is a note about what the server already gave a normal client. It is not permission to go further.

## What it checks

| Signal | What is sent | What a finding means |
|---|---|---|
| Response headers | The headers on the responses above | `Server`, `X-Powered-By`, `Via`, `X-AspNet-Version`, `X-AspNetMvc-Version`, or a framework session-cookie name is present. The cookie value is not stored. |
| Error page | The missing-page GET, plus any 404 or 5xx already returned | The body matches a default error page, a stack trace, a filesystem path, or a SQL error. Evidence is one redacted line. Connection strings, DSNs, and passwords in that line are removed. |
| TLS handshake | One browser-style handshake, plus the two version caps above | Negotiated protocol, selected cipher, and certificate names. A completed TLS 1.0 or TLS 1.1 handshake is a legacy-protocol finding. Certificate lifetime, distrust, and hostname checks reuse the existing certificate rules. |
| Timing | Time until response headers on the GETs already sent | The slowest header time is at least four times the fastest and at least 800ms slower, across three or more responses. Downloading the body does not count. Each path is requested once. |
| Known paths | The GET list below | `/.git/HEAD`, `/.svn/entries`, Apache `server-status` or `server-info`, a phpinfo page, ELMAH, or ASP.NET trace content was actually returned. |

Known paths:

- `/.git/HEAD`
- `/.svn/entries`
- `/server-status`
- `/server-info`
- `/phpinfo.php`
- `/info.php`
- `/elmah.axd`
- `/trace.axd`

Probes use the final origin of the first response. A redirect onto a private address is refused.

## PHP

The PHP check reads `X-Powered-By` and `Server` and uses the same comparison as Vigil's other header check (`parsePhpVersion` and `phpVulnerable`).

| Advertised version | Result |
|---|---|
| `8.2.35`, `8.3.36`, `8.4.27`, `8.5.12`, or a newer line | Patched for CVE-2026-109618 and CVE-2026-109619. The header is still a disclosure. `PHP_CVE_2026_115560` is an informational note. It does not block a deploy. |
| `8.2`, `8.3`, `8.4`, or `8.5` below those releases, or `8.0` / `8.1` | Below the fixed release. |
| PHP 5, 6, or 7 | Never patched for CVE-2026-109618 and CVE-2026-109619. |
| PHP is present and no `PHP/x.y.z` was advertised | Unknown. This is not a vulnerable result and not a patched result. |

A `PHPSESSID` cookie or a `PHP` token with no version is the unknown case. A version that appears only inside a phpinfo body does not change that result. The phpinfo page is an exposure finding only when a 200 response has phpinfo structure: a `phpinfo()` title or the `h1` version heading, and the configuration table cells (`class="e"` and `class="v"`). A sentence that mentions `PHP Version` is not a match.

This code does not include the Assetnote php2shell scanner. That scanner has no license and sends crash probes. Vigil stays MIT, and this command does not send those probes.

## How findings use the eleven domains

Every finding is created with `createFinding`. The domain comes from `packages/core/data/rule-catalog.json`. These are the `check-backend` rules:

| Rule | Domain | NIST CSF 2.0 | CIS |
|---|---|---|---|
| `BACKEND_HEADER_SERVER` | Application & Software | `ID.AM` | 2.1 |
| `BACKEND_HEADER_POWERED_BY` | Application & Software | `ID.AM` | 2.1 |
| `BACKEND_HEADER_ASPNET` | Application & Software | `ID.AM` | 2.1 |
| `BACKEND_COOKIE_FRAMEWORK` | Application & Software | `ID.AM` | 2.1 |
| `BACKEND_ERROR_SIGNATURE` | Application & Software | `ID.AM` | 2.1 |
| `PHP_CVE_2026_109618` | Application & Software | `ID.RA` | 7.4 |
| `PHP_CVE_2026_115560` | Application & Software | `ID.RA` | 7.4 |
| `BACKEND_PHP_VERSION_HIDDEN` | Application & Software | `ID.RA` | 7, no safeguard |
| `BACKEND_HEADER_VIA` | Cloud & Hybrid | `PR.PS` | 4.1 |
| `BACKEND_EXPOSED_VCS` | Data Security & Privacy | `PR.DS` | 3.1 |
| `BACKEND_EXPOSED_PHPINFO` | Data Security & Privacy | `PR.DS` | 3.1 |
| `BACKEND_EXPOSED_DEBUG` | Data Security & Privacy | `PR.DS` | 3.1 |
| `BACKEND_STACK_TRACE` | Data Security & Privacy | `PR.DS` | 3.1 |
| `BACKEND_TLS_INTERNAL_NAME` | Data Security & Privacy | `PR.DS` | 3, no safeguard |
| `BACKEND_EXPOSED_STATUS` | Network & Infrastructure | `PR.PS` | 4.1 |
| `BACKEND_TLS_PROTOCOL` | Network & Infrastructure | `PR.DS` | 3.10 |
| `BACKEND_TLS_CIPHER` | Network & Infrastructure | `PR.DS` | 3.10 |
| `TLS_HTTP_ONLY` | Network & Infrastructure | `PR.DS` | 3.10 |
| `BACKEND_TIMING` | Network & Infrastructure | `DE.CM` | 13, no safeguard |

The handshake also reuses the existing certificate rules when they match:

| Rule | Domain |
|---|---|
| `CERT_EXPIRED`, `CERT_EXPIRING` | Operational Resilience |
| `CERT_DISTRUSTED_CA`, `CERT_SCT_MISSING` | Threat Intel/Detection/Response |
| `CERT_HOSTNAME_MISMATCH`, `CERT_WEAK_KEY`, `CERT_SHA1`, `CERT_SELF_SIGNED`, `CERT_UNAVAILABLE` | Network & Infrastructure |
| `FETCH_TRUNCATED` | GRC |

Identity & Access, Endpoint & Device, Human Factors, and Emerging Tech stay at zero for this command. Cookie names are a software fingerprint, so they are Application & Software. Cookie flag checks already live on `check-url`. Endpoint findings are about this machine. Human Factors is a lure aimed at a person. Emerging Tech is the LiteLLM pin. The report still lists all eleven domains.

A fingerprint is `recommendationOnly`, so it does not set `block_deploy`. An existing critical certificate failure still can, because those rules are not recommendations.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | The check finished and `block_deploy` is false. |
| 2 | `block_deploy` is set. |
| 1 | Usage, a refused address, or a network failure that is not a TLS certificate error. |

If the first GET fails because the certificate is expired, untrusted, self-signed, or does not match the host name, the command does not exit 1. It reports the certificate from the handshake. An expired certificate sets `block_deploy`, so the command exits 2.

```text
vigil check-backend <url> [--json]
```

`--json` prints the report, including `summary.byDomain` for all eleven domains.
