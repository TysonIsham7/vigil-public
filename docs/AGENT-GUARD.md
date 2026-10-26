# Agent page check and outbound guard

These are two features. The page check warns about instructions on a page. The outbound guard watches HTTP that a configured client sends through a local proxy. The page check never receives the identifier list. The guard does not import the page and does not add a scan finding. Neither one blocks a deploy in this cut.

## Page check

`vigil check-url` and `vigil scan` of a URL run the same detector. A match needs both an address aimed at an agent and an ask for identity, a credential, or a behavior change, within 800 characters of normalized text. The rule id is `AGENT_DIRECTED_REQUEST`. Severity is high and `recommendationOnly` is true, so the exit code stays 0. The Chrome hold page does not hold on it.

The check reads the static response already fetched: visible text, hidden text, meta tags and the title, response headers, and same-origin `robots.txt`, `llms.txt`, `llm.txt`, and `/.well-known/llms.txt`, inside the existing size and time budget. A file the budget did not fetch is not a pass, and the report does not describe it as reviewed. A failed fetch is an informational `unverified/fetch failed` finding for that file. It is not a clean result. The finding summarizes the kind and the surface. It does not copy the page's instruction text. Patterns are English only. The finding stays `recommendationOnly`.

The check misses text created by script, hiding that depends on an external stylesheet, instructions split so neither window has both parts, other origins, and any agent that never fetches the page through Vigil.

## Outbound guard

`vigil agent-guard` listens on `127.0.0.1` only. `--ipv6` also listens on `::1`. Any other bind address is refused. A peer that is not loopback is closed. The process does not register a system proxy.

Startup prints one proxy URL, `http://<token>@127.0.0.1:<port>`. The token is the proxy username. Clients that omit it are refused. The token is not written to the decision log.

```text
HTTP_PROXY=http://<token>@127.0.0.1:<port>
HTTPS_PROXY=http://<token>@127.0.0.1:<port>
NO_PROXY=localhost,127.0.0.1,::1
```

`NO_PROXY` must not include the public hosts the guard is supposed to see. Traffic that ignores these variables is invisible to the guard.

### Identifier file

The person maintains the list. Vigil does not invent identifiers. The default path is `~/.config/vigil/identifiers`, mode `0600`. A world-readable file is a startup error that names the path and the mode, not the contents. `docs/agent-guard.sample` is placeholders on `example.invalid` and angle-bracket field names. It is not loaded.

```text
email:<user@example.com>
phone:<digits>
name:<given name and family name>
address:<a full line the person typed>
token:<the secret>
```

An empty list is valid. The guard can still block denied destinations and does not claim to know the person.

Emails, phones, and tokens are compared with HMAC-SHA256. The key is generated on first run, stored beside the list as `identifiers.key`, mode `0600`, and is not printed. The editable file stays plaintext. Values are trimmed. An empty value or a line that is not `kind: value` is a startup error, and that error does not repeat the value. Names and addresses stay in process memory only, because a hash cannot find them inside a sentence. They are never written to the log, the 403 body, or an error. A phone shorter than 10 digits, a name shorter than 8 characters, an address shorter than 16 characters, or a token shorter than 12 characters is rejected at load. The error does not repeat the value.

A token matches as a substring, including when it contains `=` or sits beside another delimiter. The same scan percent-decodes the field and decodes one layer of base64 or base64url around the token. Names and addresses are matched after form decoding (`+` to space), percent-decoding, HTML entities, and case folding.

The guard looks at the URL path and query, header names and values, and the body up to 1 MiB. Past that cap the body is not treated as clean. One percent-decode of the query and one JSON string decode. After a strip, the same scan runs again. A residual match blocks.

### Allowlist

A second file, `~/.config/vigil/allowlist`, mode `0600`, hostnames only:

```text
allow api.example.invalid
strip notes.example.invalid
block tracker.example.invalid
```

A host that is not listed is `block` when any identifier matches. The client gets a local 403 that names the kind and the host, not the matched value. `token` matches ignore `strip` and block unless the destination is `allow`. Entries are exact hosts. `example.invalid` does not allow `user-content.example.invalid`. There is no hidden vendor list.

`allow` means a matched identifier may be forwarded after the guard has read the request. It does not open an uninspected tunnel. The person has to allow the model provider's API host if the agent sends the conversation there. That host still receives the identifier. The guard has already seen the request.

Denied destinations are blocked with kind `destination` even when the allowlist names them. That includes `169.254.169.254`, `fd00:ec2::254`, `metadata.google.internal`, and the other names and ranges on Vigil's SSRF denylist. They are not identifier matches.

### Tunnel and intercept

The default mode is `tunnel`. There is no local CA. Tunnel mode is plain HTTP only. It is not an HTTPS transport.

- Plain HTTP is visible. Block and strip apply.
- Every `CONNECT` is rejected, including an allowlisted host. The 403 says HTTPS to that host is not visible in tunnel mode. The shippable guard does not open a `CONNECT` tunnel without inspection.
- `Upgrade` is refused unless the destination is allowlisted. On that path the guard forwards a rebuilt request and drops hop-by-hop and proxy headers, including `Proxy-Authorization` and `Proxy-Connection`. It does not write the raw client head.

`--mode intercept` is the HTTPS path.

- Every `CONNECT` is decrypted, including an allowlisted host. The proxy completes `CONNECT`, then a TLS handshake with a certificate minted for that hostname and signed by the local CA.
- ALPN offers `http/1.1` only. A client that requires `h2` fails closed.
- The proxy parses the inner HTTP/1.1 request, applies block or strip, then opens its own TLS connection to the origin.
- Origin verification stays on. The proxy uses the normal trust store, not the local CA, for the origin. A bad origin certificate is an error. It is not a reason to skip the identifier check.
- The proxy never disables origin certificate checks and never fetches a remote CA.

### Local CA risks

Intercept mode makes the guard a TLS terminator.

- The CA private key can sign a certificate for any hostname the proxy intercepts. Anyone who copies the key can impersonate those hosts to a client that trusts the CA, until that client stops trusting it.
- The key and certificate live in the user config directory, mode `0600`. They are not written to a repository, a scan report, the decision log, or an error message. Startup prints the certificate path only.
- Do not install the CA in the operating system trust store. That affects every application. Use a process-scoped variable: `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, or curl `--cacert`.
- Some clients ignore those variables and use the operating system store or a pinned key. They fail the handshake. A failed handshake means the request did not go out.
- The proxy sees plaintext of intercepted calls. The decision log does not record paths, queries, header values, bodies, identifiers, HMAC values, or the proxy token. Verbose logging of those values is not offered.
- `allow` still forwards a matched identifier after inspection. It does not skip the check.
- Do not copy the CA key to another machine or into a cloud build.

### Wiring

**curl**

```text
HTTPS_PROXY=http://<token>@127.0.0.1:<port> \
HTTP_PROXY=http://<token>@127.0.0.1:<port> \
NO_PROXY=localhost,127.0.0.1,::1 \
curl https://example.invalid/
```

Add `--cacert <local-ca.pem>` only in intercept mode. `--proxy` can replace the environment variables for one invocation. Do not pass `--insecure`.

**Claude Code**

Start it from an environment that has `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` set as above. If that build uses Node's fetch and only honors proxy variables behind a flag, also set `NODE_USE_ENV_PROXY=1`. For intercept mode, set `NODE_EXTRA_CA_CERTS` to the local CA certificate. A shell tool that clears the proxy variables is outside the guard. The page check is the warning for that case, not a guarantee.

**Cursor**

The local editor can set `http.proxy` to `http://<token>@127.0.0.1:<port>` when the field accepts a token, `http.proxySupport` to `override`, and `http.noProxy` to `localhost,127.0.0.1,::1`. Cursor's HTTPS calls need intercept mode and a process-scoped CA. Tunnel mode refuses `CONNECT`, so it cannot carry those calls. Do not point the editor at an uninspected tunnel to make them succeed. Intercept mode is a poor fit if the editor trusts only the operating system store.

A cloud agent does not use the laptop's loopback. `127.0.0.1` on the laptop is not an address the cloud machine can dial. A cloud environment needs its own `vigil agent-guard` process and its own identity file on that machine. Do not copy the laptop CA key there. Requests the vendor fetches from the vendor's network are not in scope.

### Logging

`~/.config/vigil/agent-guard.log` is mode `0600`, rotated at 1 MiB, and three files are kept. Each line is time, decision (`allow`, `block`, `strip`, `tunnel`), destination host, match kind or `-`, and policy (`allow`, `strip`, `block`). Startup errors can name a file path. They do not include a line from the identifier file. There is no remote log shipping.

### What the guard cannot catch

- A client that ignores `HTTP_PROXY` and `HTTPS_PROXY`, or that is started without them.
- HTTP/3 and other transports that do not use the HTTP proxy.
- Traffic from a cloud agent, a vendor backend, or another machine, unless that machine runs its own guard.
- HTTPS while the guard is in tunnel mode. `CONNECT` is refused for every host so the bytes cannot pass without inspection. Use intercept mode to see them.
- Clients that pin certificates or ship a private trust store, in intercept mode. They fail closed. If the same client then retries without the proxy, the guard never sees the retry.
- A body the agent encrypts, or a name split across requests. The guard does not correlate pieces across requests.
- Multipart uploads and bodies above 1 MiB, other than blocking that request.
- WebSocket frames after a successful upgrade, DNS, SMTP, and raw TCP that never arrives as HTTP.
- Identifiers that were not put on the list.
- The same user reading the identifier file and sending it through a channel that is not the proxy. Mode `0600` limits other users. It does not stop the same user.

The guard reduces one leak path: HTTP requests the configured client makes through the proxy, carrying values from the local list. It is not a promise that an agent cannot reveal the person.
