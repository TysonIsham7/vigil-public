import { createHmac, randomBytes } from "node:crypto";
import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { connect as netConnect, createServer, type Server } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { connect as tlsConnect, createSecureContext, createServer as tlsServer } from "node:tls";
import { afterEach, describe, expect, it } from "vitest";
import { main } from "../src/main.js";
import { createCa, mintLeaf } from "../src/agent-guard/cert.js";
import { DecisionLog } from "../src/agent-guard/log.js";
import { parseIdentity } from "../src/agent-guard/identity.js";
import { DEFAULT_BODY_CAP, DEFAULT_ROTATE_BYTES } from "../src/agent-guard/policy.js";
import {
  assertLoopbackBind,
  defaultDial,
  defaultGuardLookup,
  isLoopbackPeer,
  startAgentGuard,
  type GuardHandle,
} from "../src/agent-guard/proxy.js";

const EMAIL = "user@example.com";
const PHONE = "4155550134";
const NAME = "Test Person";
const ADDRESS = "10 Example Invalid Rd";
const TOKEN = "example-token-value";
const PROXY = "proxy-token-example";
const SENTINEL = "sentinel-file-line";
const dirs: string[] = [];

afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("agent-guard", () => {
  it("rejects a non-loopback bind and a non-loopback peer", async () => {
    expect(() => assertLoopbackBind("0.0.0.0")).toThrow(/refusing bind/);
    expect(() => assertLoopbackBind("::")).toThrow(/refusing bind/);
    expect(() => assertLoopbackBind("127.0.0.1")).not.toThrow();
    expect(() => assertLoopbackBind("::1")).not.toThrow();
    expect(isLoopbackPeer("127.0.0.1")).toBe(true);
    expect(isLoopbackPeer("::1")).toBe(true);
    expect(isLoopbackPeer("::ffff:127.0.0.1")).toBe(true);
    expect(isLoopbackPeer("203.0.113.9")).toBe(false);
    expect(isLoopbackPeer(undefined)).toBe(false);
    await expect(startAgentGuard({ bind: "0.0.0.0", token: PROXY })).rejects.toThrow(/refusing bind/);
    await expect(defaultGuardLookup("example.invalid")).rejects.toThrow(/live DNS/);
    await expect(defaultDial({ address: "203.0.113.10", port: 9 })).rejects.toThrow(/live socket/);
    expect(DEFAULT_BODY_CAP).toBe(1024 * 1024);
    expect(DEFAULT_ROTATE_BYTES).toBe(1024 * 1024);
  });

  it("stores HMAC-SHA256 rather than a bare hash, and refuses short values without echoing them", () => {
    const key = randomBytes(32);
    const identity = parseIdentity(`email:${EMAIL}\nphone:${PHONE}\ntoken:${TOKEN}\nname:${NAME}\naddress:${ADDRESS}\n`, key);
    expect(identity.emailHmac[0]?.equals(createHmac("sha256", key).update(EMAIL).digest())).toBe(true);
    expect(identity.emailHmac[0]?.equals(createHmac("sha256", Buffer.alloc(0)).update(EMAIL).digest())).toBe(false);
    expect(identity.emailHmac[0]?.toString("utf8")).not.toContain(EMAIL);
    expect(() => parseIdentity("phone:12345\n", key)).toThrow(/shorter than 10/);
    expect(() => parseIdentity("phone:12345\n", key)).not.toThrow(/12345/);
    expect(() => parseIdentity("name:Ann\n", key)).toThrow(/shorter than 8/);
    expect(() => parseIdentity("name:Ann\n", key)).not.toThrow(/Ann/);
  });

  it("trims identifier values and rejects empty or malformed lines", () => {
    const key = randomBytes(32);
    const token = "example=token-value";
    const identity = parseIdentity(`token: ${token}\nname: ${NAME}\naddress: ${ADDRESS}\n`, key);
    expect(identity.tokenLengths).toEqual([token.length]);
    expect(identity.tokenHmac[0]?.equals(createHmac("sha256", key).update(token).digest())).toBe(true);
    expect(identity.names).toEqual([NAME]);
    expect(identity.addresses).toEqual([ADDRESS]);
    expect(() => parseIdentity("token:\n", key)).toThrow(/empty/);
    expect(() => parseIdentity("name:   \n", key)).toThrow(/empty/);
    expect(() => parseIdentity("address:\n", key)).toThrow(/empty/);
    const malformed = "not-an-entry example=token-value";
    expect(() => parseIdentity(`${malformed}\n`, key)).toThrow(/malformed/);
    let message = "";
    try {
      parseIdentity(`token:   \nname:   \n${malformed}\n`, key);
    } catch (error) {
      message = error instanceof Error ? error.message : "";
    }
    expect(message).toMatch(/empty/);
    expect(message).not.toContain(token);
    expect(message).not.toContain(NAME);
    expect(message).not.toContain("not-an-entry");
  });

  it("blocks identifiers, strips one header, and keeps secrets off the origin and the log", async () => {
    const dir = tempDir();
    const identifiers = writePrivate(dir, "identifiers", [
      `# ${SENTINEL}`,
      `email:${EMAIL}`,
      `phone:${PHONE}`,
      `name:${NAME}`,
      `address:${ADDRESS}`,
      `token:${TOKEN}`,
    ].join("\n"));
    writePrivate(dir, "allowlist", "allow example.invalid\nstrip notes.example.invalid\n");
    const origin = await tcpOrigin();
    const dialed: string[] = [];
    const looked: string[] = [];
    const guard = await startAgentGuard({
      token: PROXY,
      identifiersPath: identifiers,
      allowlistPath: join(dir, "allowlist"),
      logPath: join(dir, "agent-guard.log"),
      keyPath: join(dir, "identifiers.key"),
      bodyCap: 64,
      rotateAt: 1024 * 1024,
      lookup: async (host) => {
        looked.push(host);
        return ["203.0.113.10"];
      },
      dial: async (info) => {
        dialed.push(`${info.host} ${info.address}`);
        return netConnect({ host: "127.0.0.1", port: origin.port });
      },
    });
    try {
      const missing = await exchange(guard, request("other.example.invalid", "", []));
      expect(missing).toMatch(/407/);
      expect(missing).toContain("proxy token required");
      expect(origin.requests).toHaveLength(0);

      const headerHit = await exchange(guard, request("other.example.invalid", PROXY, [`X-Mail: ${EMAIL}`]));
      const queryHit = await exchange(guard, absolute(PROXY, "other.example.invalid", `/q?mail=${encodeURIComponent(EMAIL)}`));
      const json = `{"note":"${EMAIL.replace("@", "\\u0040")}"}`;
      const jsonHit = await exchange(guard, post("other.example.invalid", PROXY, json));
      expect(headerHit).toMatch(/403/);
      expect(queryHit).toMatch(/403/);
      expect(jsonHit).toMatch(/403/);
      expect(headerHit).toContain("blocked email");
      expect(headerHit).not.toContain(EMAIL);
      expect(origin.requests.join("")).not.toContain(EMAIL);
      expect(dialed).toHaveLength(0);

      const allowed = await exchange(guard, request("example.invalid", PROXY, [`X-Mail: ${EMAIL}`, "X-Keep: stay"]));
      expect(allowed).toContain("200");
      expect(origin.requests.at(-1)).toContain(EMAIL);
      expect(origin.requests.at(-1)).toContain("X-Keep: stay");
      expect(origin.requests.at(-1)).not.toContain(PROXY);

      const wide = await exchange(guard, request("user-content.example.invalid", PROXY, [`X-Mail: ${EMAIL}`]));
      expect(wide).toMatch(/403/);
      expect(origin.requests.filter((item) => item.includes("user-content"))).toHaveLength(0);

      const stripped = await exchange(guard, request("notes.example.invalid", PROXY, [`X-Mail: ${EMAIL}`, "X-Keep: stay"]));
      expect(stripped).toContain("200");
      const strippedRequest = origin.requests.at(-1) ?? "";
      expect(strippedRequest).toContain("X-Keep: stay");
      expect(strippedRequest).not.toContain(EMAIL);
      expect(strippedRequest).not.toContain("X-Mail");

      const before = origin.requests.length;
      const residual = await exchange(guard, post("notes.example.invalid", PROXY, EMAIL, [`X-Mail: ${EMAIL}`, "X-Keep: stay"]));
      expect(residual).toMatch(/403/);
      expect(residual).not.toContain(EMAIL);
      expect(origin.requests).toHaveLength(before);

      const tokenHit = await exchange(guard, request("notes.example.invalid", PROXY, [`X-Token: ${TOKEN}`]));
      expect(tokenHit).toMatch(/403/);
      expect(tokenHit).toContain("blocked token");
      expect(tokenHit).not.toContain(TOKEN);

      const phoneHit = await exchange(guard, post("other.example.invalid", PROXY, `reach ${PHONE.slice(0, 3)}-${PHONE.slice(3, 6)}-${PHONE.slice(6)} now`));
      expect(phoneHit).toContain("blocked phone");
      expect(phoneHit).not.toContain(PHONE);
      const nameHit = await exchange(guard, post("other.example.invalid", PROXY, `hello ${NAME} today`));
      expect(nameHit).toContain("blocked name");
      expect(nameHit).not.toContain(NAME);
      const addressHit = await exchange(guard, post("other.example.invalid", PROXY, `ship to ${ADDRESS} today`));
      expect(addressHit).toContain("blocked address");
      expect(addressHit).not.toContain(ADDRESS);

      const capped = await exchange(guard, post("example.invalid", PROXY, "OVERCAP-MARKER", [], 80));
      expect(capped).toMatch(/403/);
      expect(origin.requests.join("")).not.toContain("OVERCAP-MARKER");

      const denied = await exchange(guard, request("metadata.google.internal", PROXY, []));
      expect(denied).toMatch(/403/);
      expect(denied).toContain("destination");
      expect(looked).not.toContain("metadata.google.internal");
      expect(dialed.join(" ")).not.toContain("metadata.google.internal");

      const log = readLogs(join(dir, "agent-guard.log"));
      const forwarded = origin.requests.join("\n");
      const key = readFileSync(join(dir, "identifiers.key"));
      expect(forwarded.split(EMAIL).length - 1).toBe(1);
      for (const secret of [PHONE, NAME, ADDRESS, TOKEN, PROXY, SENTINEL, key.toString("hex")]) {
        expect(log).not.toContain(secret);
        expect(forwarded).not.toContain(secret);
      }
      expect(log).not.toContain(EMAIL);
      expect(forwarded).not.toContain("PRIVATE KEY");
      expect(log).toMatch(/\temail\t/);
      expect(log).toMatch(/\tname\t/);
      expect((statSync(join(dir, "agent-guard.log")).mode & 0o077)).toBe(0);
      expect(statSync(identifiers).mode & 0o077).toBe(0);
      const rotated = [join(dir, "agent-guard.log"), join(dir, "agent-guard.log.1"), join(dir, "agent-guard.log.2")];
      expect(rotated.filter((path) => exists(path)).length).toBeGreaterThan(0);
      expect(exists(join(dir, "agent-guard.log.3"))).toBe(false);
    } finally {
      await guard.close();
      await origin.close();
    }
  });

  it("refuses a world-readable identifier file without echoing it", async () => {
    const dir = tempDir();
    const path = writePrivate(dir, "identifiers", `email:${EMAIL}\n# ${SENTINEL}\n`, 0o644);
    await expect(startAgentGuard({
      token: PROXY,
      identifiersPath: path,
      allowlistPath: join(dir, "missing-allow"),
      logPath: join(dir, "agent-guard.log"),
    })).rejects.toThrow(/0644/);
    await expect(startAgentGuard({
      token: PROXY,
      identifiersPath: path,
      logPath: join(dir, "agent-guard.log"),
    })).rejects.not.toThrow(new RegExp(SENTINEL));
  });

  it("strips proxy and hop-by-hop headers on an allowlisted Upgrade", async () => {
    const dir = tempDir();
    writePrivate(dir, "identifiers", `email:${EMAIL}\n`);
    writePrivate(dir, "allowlist", "allow allowed.example.invalid\n");
    const received: Buffer[] = [];
    const origin = createServer((socket) => {
      const chunks: Buffer[] = [];
      socket.on("data", (chunk) => {
        chunks.push(chunk);
        const text = Buffer.concat(chunks).toString("utf8");
        if (!text.includes("\r\n\r\n")) return;
        received.push(Buffer.concat(chunks));
        socket.end("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nContent-Length: 0\r\n\r\n");
      });
    });
    const port = await listen(origin);
    const guard = await startAgentGuard({
      token: PROXY,
      identifiersPath: join(dir, "identifiers"),
      allowlistPath: join(dir, "allowlist"),
      logPath: join(dir, "agent-guard.log"),
      lookup: async () => ["203.0.113.10"],
      dial: async () => netConnect({ host: "127.0.0.1", port }),
    });
    try {
      const raw = [
        "GET http://allowed.example.invalid/ws HTTP/1.1",
        "Host: allowed.example.invalid",
        "Upgrade: websocket",
        "Connection: Upgrade, X-Hop",
        basic(PROXY),
        "Proxy-Connection: keep-alive",
        "X-Hop: hop-secret",
        "X-Keep: stay",
        "",
        "",
      ].join("\r\n");
      const response = await exchange(guard, raw);
      expect(response).toContain("101");
      const forwarded = Buffer.concat(received).toString("utf8");
      expect(forwarded).toContain("Upgrade: websocket");
      expect(forwarded).toContain("X-Keep: stay");
      expect(forwarded).not.toContain("Proxy-Authorization");
      expect(forwarded).not.toContain("Proxy-Connection");
      expect(forwarded).not.toContain(PROXY);
      expect(forwarded).not.toContain("hop-secret");
      expect(forwarded).not.toContain("X-Hop:");
    } finally {
      await guard.close();
      origin.close();
    }
  });

  it("matches a token that contains equals, including base64 and percent-encoding", async () => {
    const dir = tempDir();
    const equalToken = "example=token-value";
    writePrivate(dir, "identifiers", `token: ${equalToken}\ntoken: ${TOKEN}\n`);
    const origin = await tcpOrigin();
    const guard = await startAgentGuard({
      token: PROXY,
      identifiersPath: join(dir, "identifiers"),
      allowlistPath: join(dir, "allowlist"),
      logPath: join(dir, "agent-guard.log"),
      keyPath: join(dir, "identifiers.key"),
      lookup: async () => ["203.0.113.10"],
      dial: async () => netConnect({ host: "127.0.0.1", port: origin.port }),
    });
    try {
      const wrapped = `aa=${equalToken}=zz`;
      const encoded = TOKEN.replaceAll("-", "%2D");
      const b64 = Buffer.from(TOKEN).toString("base64");
      const urlB64 = encodeURIComponent(Buffer.from(TOKEN).toString("base64url"));
      const cases = [
        post("other.example.invalid", PROXY, `note ${wrapped} end`),
        post("other.example.invalid", PROXY, `note ${encoded} end`),
        request("other.example.invalid", PROXY, [`X-Token: prefix ${b64} suffix`]),
        post("other.example.invalid", PROXY, `wrapped ${urlB64} end`),
      ];
      for (const raw of cases) {
        const response = await exchange(guard, raw);
        expect(response).toMatch(/403/);
        expect(response).toContain("blocked token");
        expect(response).not.toContain(equalToken);
        expect(response).not.toContain(TOKEN);
      }
      expect(origin.requests).toHaveLength(0);
      const log = readLogs(join(dir, "agent-guard.log"));
      expect(log).not.toContain(equalToken);
      expect(log).not.toContain(TOKEN);
      expect(log).not.toContain(b64);
    } finally {
      await guard.close();
      await origin.close();
    }
  });

  it("matches a name after form, percent, and case normalization", async () => {
    const dir = tempDir();
    writePrivate(dir, "identifiers", `name: ${NAME}\naddress: ${ADDRESS}\n`);
    const origin = await tcpOrigin();
    const guard = await startAgentGuard({
      token: PROXY,
      identifiersPath: join(dir, "identifiers"),
      allowlistPath: join(dir, "none"),
      logPath: join(dir, "agent-guard.log"),
      lookup: async () => ["203.0.113.10"],
      dial: async () => netConnect({ host: "127.0.0.1", port: origin.port }),
    });
    try {
      const plus = NAME.replaceAll(" ", "+");
      const encoded = encodeURIComponent(NAME);
      const shouted = NAME.toUpperCase();
      const entity = NAME.replace(" ", "&#32;");
      const responses = [
        await exchange(guard, post("other.example.invalid", PROXY, `hello ${plus} today`)),
        await exchange(guard, request("other.example.invalid", PROXY, [`X-Who: ${encoded}`])),
        await exchange(guard, post("other.example.invalid", PROXY, `hello ${shouted} today`)),
        await exchange(guard, post("other.example.invalid", PROXY, `hello ${entity} today`)),
        await exchange(guard, post("other.example.invalid", PROXY, `ship ${ADDRESS.replaceAll(" ", "+")} today`)),
      ];
      for (const response of responses) {
        expect(response).toMatch(/403/);
        expect(response).not.toContain(NAME);
        expect(response).not.toContain(ADDRESS);
      }
      expect(responses[0]).toContain("blocked name");
      expect(responses[4]).toContain("blocked address");
      expect(origin.requests).toHaveLength(0);
      expect(readLogs(join(dir, "agent-guard.log"))).not.toContain(NAME);
    } finally {
      await guard.close();
      await origin.close();
    }
  });

  it("blocks cloud metadata addresses even when they are allowlisted", async () => {
    const dir = tempDir();
    writePrivate(dir, "identifiers", `email:${EMAIL}\n`);
    writePrivate(dir, "allowlist", [
      "allow 169.254.169.254",
      "allow metadata.google.internal",
      "allow fd00:ec2::254",
    ].join("\n"));
    const looked: string[] = [];
    let dials = 0;
    const guard = await startAgentGuard({
      token: PROXY,
      identifiersPath: join(dir, "identifiers"),
      allowlistPath: join(dir, "allowlist"),
      logPath: join(dir, "agent-guard.log"),
      lookup: async (host) => {
        looked.push(host);
        return ["203.0.113.10"];
      },
      dial: async () => {
        dials += 1;
        throw new Error("metadata destination was dialed");
      },
    });
    try {
      const targets = [
        request("169.254.169.254", PROXY, [`X-Mail: ${EMAIL}`]),
        request("metadata.google.internal", PROXY, []),
        "GET http://[fd00:ec2::254]/latest HTTP/1.1\r\nHost: [fd00:ec2::254]\r\n" + `${basic(PROXY)}\r\nContent-Length: 0\r\n\r\n`,
        `CONNECT 169.254.169.254:80 HTTP/1.1\r\nHost: 169.254.169.254:80\r\n${basic(PROXY)}\r\n\r\n`,
      ];
      for (const raw of targets) {
        const response = await exchange(guard, raw);
        expect(response).toMatch(/403/);
        expect(response).toContain("destination");
        expect(response).not.toContain(EMAIL);
      }
      expect(dials).toBe(0);
      expect(looked).toEqual([]);
    } finally {
      await guard.close();
    }
  });

  it("refuses CONNECT without inspection, including an allowlisted host", async () => {
    const dir = tempDir();
    writePrivate(dir, "identifiers", `email:${EMAIL}\n`);
    writePrivate(dir, "allowlist", "allow allowed.example.invalid\n");
    const received: Buffer[] = [];
    const origin = createServer((socket) => {
      socket.on("data", (chunk) => {
        received.push(chunk);
        socket.write(chunk);
      });
    });
    const port = await listen(origin);
    let dials = 0;
    const guard = await startAgentGuard({
      token: PROXY,
      identifiersPath: join(dir, "identifiers"),
      allowlistPath: join(dir, "allowlist"),
      logPath: join(dir, "agent-guard.log"),
      lookup: async () => ["203.0.113.10"],
      dial: async () => {
        dials += 1;
        return netConnect({ host: "127.0.0.1", port });
      },
    });
    try {
      const allowed = await exchange(guard, `CONNECT allowed.example.invalid:443 HTTP/1.1\r\nHost: allowed.example.invalid:443\r\n${basic(PROXY)}\r\nX-Mail: ${EMAIL}\r\n\r\n`);
      const other = await exchange(guard, `CONNECT other.example.invalid:443 HTTP/1.1\r\nHost: other.example.invalid:443\r\n${basic(PROXY)}\r\n\r\n`);
      expect(allowed).toMatch(/403/);
      expect(other).toMatch(/403/);
      expect(allowed).toContain("not visible in tunnel mode");
      expect(other).toContain("not visible in tunnel mode");
      expect(allowed).not.toContain(EMAIL);
      expect(received).toHaveLength(0);
      expect(dials).toBe(0);
    } finally {
      await guard.close();
      origin.close();
    }
  });

  it("intercepts an inner header, trusts only the origin CA, and deletes its CA", async () => {
    const dir = tempDir();
    writePrivate(dir, "identifiers", `email:${EMAIL}\n`);
    const originCa = createCa("Vigil origin test CA");
    const badCa = createCa("Vigil bad origin CA");
    const goodLeaf = mintLeaf(originCa, "good.example.invalid");
    const blockedLeaf = mintLeaf(originCa, "blocked.example.invalid");
    const badLeaf = mintLeaf(badCa, "bad.example.invalid");
    const requests: string[] = [];
    const origin = tlsServer({
      cert: goodLeaf.certPem,
      key: goodLeaf.keyPem,
      ALPNProtocols: ["http/1.1"],
      SNICallback: (name, cb) => {
        if (name === "bad.example.invalid") cb(null, createSecureContext({ cert: badLeaf.certPem, key: badLeaf.keyPem }));
        else if (name === "blocked.example.invalid") cb(null, createSecureContext({ cert: blockedLeaf.certPem, key: blockedLeaf.keyPem }));
        else cb(null, createSecureContext({ cert: goodLeaf.certPem, key: goodLeaf.keyPem }));
      },
    }, (socket) => {
      const chunks: Buffer[] = [];
      socket.on("data", (chunk) => {
        chunks.push(chunk);
        const text = Buffer.concat(chunks).toString("utf8");
        if (!text.includes("\r\n\r\n")) return;
        requests.push(text);
        socket.end("HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndone");
      });
    });
    const port = await listen(origin);
    const guard = await startAgentGuard({
      mode: "intercept",
      token: PROXY,
      identifiersPath: join(dir, "identifiers"),
      allowlistPath: join(dir, "none"),
      logPath: join(dir, "agent-guard.log"),
      caCertPath: join(dir, "ca.pem"),
      caKeyPath: join(dir, "ca.key"),
      originCa: originCa.certPem,
      lookup: async () => ["203.0.113.10"],
      dial: async () => netConnect({ host: "127.0.0.1", port }),
    });
    const certPath = guard.certPath ?? "";
    try {
      expect(certPath.endsWith("ca.pem")).toBe(true);
      expect((statSync(join(dir, "ca.key")).mode & 0o077)).toBe(0);
      const interceptPem = readFileSync(certPath, "utf8");
      expect(originCa.certPem).not.toContain(interceptPem.replace(/-----[^-]+-----/g, "").trim().slice(0, 40));
      expect(interceptPem).not.toContain("PRIVATE KEY");
      const clean = await innerRequest(guard, interceptPem, "good.example.invalid", "GET /clean HTTP/1.1\r\nHost: good.example.invalid\r\n\r\n");
      expect(clean).toContain("done");
      const blocked = await innerRequest(guard, interceptPem, "blocked.example.invalid", `GET /secret HTTP/1.1\r\nHost: blocked.example.invalid\r\nX-Mail: ${EMAIL}\r\n\r\n`);
      expect(blocked).toMatch(/403/);
      expect(blocked).toContain("blocked email");
      expect(blocked).not.toContain(EMAIL);
      const bad = await innerRequest(guard, interceptPem, "bad.example.invalid", "GET /bad HTTP/1.1\r\nHost: bad.example.invalid\r\n\r\n").catch((error: Error) => error.message);
      expect(bad).not.toContain("done");
      expect(requests.some((item) => item.includes("/clean"))).toBe(true);
      expect(requests.some((item) => item.includes("/secret") || item.includes(EMAIL))).toBe(false);
      expect(requests.some((item) => item.includes("/bad"))).toBe(false);
      const log = readFileSync(join(dir, "agent-guard.log"), "utf8");
      expect(log).not.toContain(EMAIL);
      expect(log).not.toContain("PRIVATE KEY");
      expect(readFileSync(join(dir, "ca.key"), "utf8")).toContain("PRIVATE KEY");
    } finally {
      await guard.close();
      origin.close();
      rmSync(dir, { recursive: true, force: true });
      expect(exists(certPath)).toBe(false);
    }
  });

  it("inspects an allowlisted CONNECT instead of splicing it", async () => {
    const dir = tempDir();
    writePrivate(dir, "identifiers", `email:${EMAIL}\n`);
    writePrivate(dir, "allowlist", "allow good.example.invalid\n");
    const originCa = createCa("Vigil origin test CA");
    const leaf = mintLeaf(originCa, "good.example.invalid");
    const requests: string[] = [];
    const origin = tlsServer({
      cert: leaf.certPem,
      key: leaf.keyPem,
      ALPNProtocols: ["http/1.1"],
    }, (socket) => {
      const chunks: Buffer[] = [];
      socket.on("data", (chunk) => {
        chunks.push(chunk);
        const text = Buffer.concat(chunks).toString("utf8");
        if (!text.includes("\r\n\r\n")) return;
        requests.push(text);
        socket.end("HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndone");
      });
    });
    const port = await listen(origin);
    const guard = await startAgentGuard({
      mode: "intercept",
      token: PROXY,
      identifiersPath: join(dir, "identifiers"),
      allowlistPath: join(dir, "allowlist"),
      logPath: join(dir, "agent-guard.log"),
      caCertPath: join(dir, "ca.pem"),
      caKeyPath: join(dir, "ca.key"),
      originCa: originCa.certPem,
      lookup: async () => ["203.0.113.10"],
      dial: async () => netConnect({ host: "127.0.0.1", port }),
    });
    try {
      const body = await innerRequest(guard, readFileSync(guard.certPath ?? "", "utf8"), "good.example.invalid", `GET /seen HTTP/1.1\r\nHost: good.example.invalid\r\nX-Mail: ${EMAIL}\r\n\r\n`);
      expect(body).toContain("done");
      expect(requests.some((item) => item.includes("GET /seen") && item.includes(EMAIL))).toBe(true);
      expect(requests.some((item) => item.includes(PROXY) || item.includes("Proxy-Authorization"))).toBe(false);
      const log = readFileSync(join(dir, "agent-guard.log"), "utf8");
      expect(log).toMatch(/\temail\t/);
      expect(log).not.toContain(EMAIL);
    } finally {
      await guard.close();
      origin.close();
    }
  });

  it("rotates the decision log and keeps three files", () => {
    const dir = tempDir();
    const path = join(dir, "agent-guard.log");
    const log = new DecisionLog(path, 80);
    for (let i = 0; i < 12; i += 1) {
      log.write({ time: "2026-10-22T00:00:00.000Z", decision: "block", host: "example.invalid", kind: "-", policy: "block" });
    }
    expect(exists(path)).toBe(true);
    expect(exists(`${path}.1`)).toBe(true);
    expect(exists(`${path}.2`)).toBe(true);
    expect(exists(`${path}.3`)).toBe(false);
    expect(statSync(path).mode & 0o077).toBe(0);
    expect(readFileSync(path, "utf8")).not.toContain(EMAIL);
  });

  it("documents proxy wiring in the command help", async () => {
    const lines: string[] = [];
    const code = await main(["--help"], { stdout: (text) => lines.push(text), stderr: () => undefined });
    expect(code).toBe(0);
    const help = lines.join("");
    expect(help).toContain("HTTPS_PROXY=http://<token>@127.0.0.1:<port>");
    expect(help).toContain("HTTP_PROXY=http://<token>@127.0.0.1:<port>");
    expect(help).toContain("NO_PROXY=localhost,127.0.0.1,::1");
    expect(help).toContain("NODE_USE_ENV_PROXY=1");
    expect(help).toContain("NODE_EXTRA_CA_CERTS");
    expect(help).toContain("http.proxySupport");
    expect(help).toContain("http.noProxy");
    expect(help).toContain("Do not pass --insecure");
    expect(help).toContain("Do not install the local CA in the operating system trust store");
    expect(help).toContain("not the outbound guard");
    expect(help).toContain("does not open a CONNECT tunnel without inspection");
    expect(help).toContain("docs/AGENT-GUARD.md");
  });
});

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "vigil-agent-guard-"));
  dirs.push(dir);
  return dir;
}

function writePrivate(dir: string, name: string, body: string, mode = 0o600): string {
  const path = join(dir, name);
  writeFileSync(path, body.endsWith("\n") ? body : `${body}\n`, { mode });
  chmodSync(path, mode);
  return path;
}

function exists(path: string): boolean {
  try {
    statSync(path);
    return true;
  } catch {
    return false;
  }
}

function readLogs(path: string): string {
  return [path, `${path}.1`, `${path}.2`].filter(exists).map((item) => readFileSync(item, "utf8")).join("");
}

function basic(token: string): string {
  return `Proxy-Authorization: Basic ${Buffer.from(`${token}:`).toString("base64")}`;
}

function request(host: string, token: string, headers: string[], body = ""): string {
  return [
    `GET http://${host}/path HTTP/1.1`,
    `Host: ${host}`,
    token ? basic(token) : "X-No-Token: 1",
    ...headers,
    `Content-Length: ${Buffer.byteLength(body)}`,
    "Connection: close",
    "",
    body,
  ].join("\r\n");
}

function absolute(token: string, host: string, path: string): string {
  return [
    `GET http://${host}${path} HTTP/1.1`,
    `Host: ${host}`,
    basic(token),
    "Content-Length: 0",
    "Connection: close",
    "",
    "",
  ].join("\r\n");
}

function post(host: string, token: string, body: string, headers: string[] = [], declared?: number): string {
  return [
    `POST http://${host}/submit HTTP/1.1`,
    `Host: ${host}`,
    basic(token),
    "Content-Type: application/json",
    ...headers,
    `Content-Length: ${declared ?? Buffer.byteLength(body)}`,
    "Connection: close",
    "",
    body,
  ].join("\r\n");
}

function exchange(guard: GuardHandle, raw: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = netConnect(guard.port, "127.0.0.1", () => socket.write(raw));
    const chunks: Buffer[] = [];
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error("proxy response timed out"));
    }, 4_000);
    socket.on("data", (chunk) => chunks.push(chunk));
    socket.on("end", () => {
      clearTimeout(timer);
      resolve(Buffer.concat(chunks).toString("utf8"));
    });
    socket.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

function tcpOrigin(): Promise<{ port: number; requests: string[]; close: () => Promise<void> }> {
  const requests: string[] = [];
  const server = createServer((socket) => {
    const chunks: Buffer[] = [];
    let done = false;
    socket.on("data", (chunk) => {
      chunks.push(chunk);
      const text = Buffer.concat(chunks).toString("utf8");
      const end = text.indexOf("\r\n\r\n");
      if (end < 0 || done) return;
      const length = Number(/Content-Length: (\d+)/i.exec(text)?.[1] ?? 0);
      if (Buffer.byteLength(text.slice(end + 4)) < length) return;
      done = true;
      requests.push(text);
      socket.end("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      resolve({
        port: typeof address === "object" && address ? address.port : 0,
        requests,
        close: () => new Promise((done) => server.close(() => done())),
      });
    });
  });
}

function listen(server: Server): Promise<number> {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      resolve(typeof address === "object" && address ? address.port : 0);
    });
  });
}

function innerRequest(guard: GuardHandle, caPem: string, host: string, raw: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = netConnect(guard.port, "127.0.0.1", () => {
      socket.write(`CONNECT ${host}:443 HTTP/1.1\r\nHost: ${host}:443\r\n${basic(PROXY)}\r\n\r\n`);
    });
    let buf = Buffer.alloc(0);
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error("intercept timed out"));
    }, 5_000);
    const fail = (error: Error) => {
      clearTimeout(timer);
      reject(error);
    };
    socket.on("error", fail);
    socket.on("data", (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      const at = buf.indexOf("\r\n\r\n");
      if (at < 0) return;
      socket.removeAllListeners("data");
      const head = buf.subarray(0, at).toString("utf8");
      if (!head.startsWith("HTTP/1.1 200")) {
        clearTimeout(timer);
        resolve(head);
        socket.end();
        return;
      }
      const rest = buf.subarray(at + 4);
      if (rest.length > 0) socket.unshift(rest);
      const tls = tlsConnect({
        socket,
        servername: host,
        ca: caPem,
        ALPNProtocols: ["http/1.1"],
        rejectUnauthorized: true,
      });
      const chunks: Buffer[] = [];
      tls.on("secureConnect", () => tls.write(raw));
      tls.on("data", (part) => chunks.push(part));
      tls.on("end", () => {
        clearTimeout(timer);
        resolve(Buffer.concat(chunks).toString("utf8"));
      });
      tls.on("error", fail);
    });
  });
}
