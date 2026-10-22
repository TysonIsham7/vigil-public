import { createHash, X509Certificate, type KeyObject } from "node:crypto";
import tls from "node:tls";
import { matchDistrust } from "@vigil/intel";
import { isIpLiteral, type CertCheck, type Finding } from "@vigil/core";
import { pinAddress, pinnedLookup, systemLookup, type AddressLookup } from "./fetch.js";
import { netFinding } from "./finding.js";

export interface SctPresence {
  present: boolean;
  count: number;
  wellFormed: boolean;
}

export interface ParsedCert {
  subject: string;
  issuer: string;
  sanDns: string[];
  sanIp: string[];
  commonName?: string;
  notBefore: Date;
  notAfter: Date;
  sha256: string;
  spkiSha256: string;
  signatureAlgorithm: string;
  publicKeyAlgorithm: "rsa" | "ec" | "other";
  publicKeyBits: number;
  selfSigned: boolean;
  sct: SctPresence;
}

const SHA1_NAMES = new Set(["sha1WithRSAEncryption", "ecdsa-with-SHA1", "sha1"]);
const OID_NAMES: Record<string, string> = {
  "2a864886f70d010105": "sha1WithRSAEncryption",
  "2a864886f70d01010b": "sha256WithRSAEncryption",
  "2a864886f70d01010c": "sha384WithRSAEncryption",
  "2a864886f70d01010d": "sha512WithRSAEncryption",
  "2a8648ce3d0401": "ecdsa-with-SHA1",
  "2a8648ce3d040302": "ecdsa-with-SHA256",
  "2a8648ce3d040303": "ecdsa-with-SHA384",
  "2a8648ce3d040304": "ecdsa-with-SHA512",
};
const SCT_OID = Uint8Array.from([0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02]);

export function countEmbeddedScts(raw: Uint8Array): SctPresence {
  const at = indexOfBytes(raw, SCT_OID);
  if (at < 0) return { present: false, count: 0, wellFormed: true };
  const offset = at + SCT_OID.length;
  if (raw[offset] !== 0x04) return { present: true, count: 0, wellFormed: false };
  const outer = readLength(raw, offset + 1);
  if (!outer) return { present: true, count: 0, wellFormed: false };
  let inner = raw.slice(outer.next, outer.next + outer.length);
  if (inner[0] === 0x04) {
    const nested = readLength(inner, 1);
    if (!nested) return { present: true, count: 0, wellFormed: false };
    inner = inner.slice(nested.next, nested.next + nested.length);
  }
  let count = 0;
  let cursor = 0;
  while (cursor + 2 <= inner.length) {
    const length = ((inner[cursor] ?? 0) << 8) | (inner[cursor + 1] ?? 0);
    if (length <= 0 || cursor + 2 + length > inner.length) return { present: true, count, wellFormed: false };
    cursor += 2 + length;
    count += 1;
  }
  if (cursor !== inner.length || count === 0) return { present: true, count, wellFormed: false };
  return { present: true, count, wellFormed: true };
}

export function signatureAlgorithmName(raw: Uint8Array): string {
  if (raw[0] !== 0x30) return "unknown";
  const outer = readLength(raw, 1);
  if (!outer || raw[outer.next] !== 0x30) return "unknown";
  const tbs = readLength(raw, outer.next + 1);
  if (!tbs) return "unknown";
  const algAt = tbs.next + tbs.length;
  if (raw[algAt] !== 0x30) return "unknown";
  const alg = readLength(raw, algAt + 1);
  if (!alg || raw[alg.next] !== 0x06) return "unknown";
  const oid = readLength(raw, alg.next + 1);
  if (!oid) return "unknown";
  const hex = Buffer.from(raw.slice(oid.next, oid.next + oid.length)).toString("hex");
  return OID_NAMES[hex] ?? "unknown";
}

export function parseCertificate(material: string | Buffer | Uint8Array): ParsedCert {
  const cert = new X509Certificate(material);
  const spki = cert.publicKey.export({ type: "spki", format: "der" });
  const names = parseAltNames(cert.subjectAltName ?? "");
  const commonName = /(?:^|,\s*)CN=([^,\n]+)/.exec(cert.subject)?.[1]?.trim();
  const raw = new Uint8Array(cert.raw);
  const parsed: ParsedCert = {
    subject: cert.subject,
    issuer: cert.issuer,
    sanDns: names.dns,
    sanIp: names.ip,
    notBefore: new Date(cert.validFrom),
    notAfter: new Date(cert.validTo),
    sha256: cert.fingerprint256.replaceAll(":", "").toLowerCase(),
    spkiSha256: createHash("sha256").update(spki).digest("hex"),
    signatureAlgorithm: signatureAlgorithmName(raw),
    publicKeyAlgorithm: keyAlgorithm(cert.publicKey),
    publicKeyBits: keyBits(cert.publicKey),
    selfSigned: cert.subject === cert.issuer,
    sct: countEmbeddedScts(raw),
  };
  if (commonName) parsed.commonName = commonName;
  return parsed;
}

export interface ChainOptions {
  host: string;
  now: Date;
  trustedSpki: ReadonlySet<string>;
}

export interface ChainEvaluation {
  findings: Finding[];
  cert: CertCheck;
}

export function evaluateCertificateChain(chain: ParsedCert[], options: ChainOptions): ChainEvaluation {
  const leaf = chain[0];
  if (!leaf) throw new Error("Certificate chain is empty");
  const findings: Finding[] = [];
  const distrusted = chain.flatMap((cert) => {
    const hit = matchDistrust({ spkiSha256: cert.spkiSha256, sha256: cert.sha256 });
    return hit ? [{ name: hit.name, spkiSha256: hit.spkiSha256 }] : [];
  });
  const daysRemaining = Math.floor((leaf.notAfter.getTime() - options.now.getTime()) / 86_400_000);
  const hostnameMatches = nameMatches(options.host, leaf);
  const weak = chain.some((cert) => !options.trustedSpki.has(cert.spkiSha256) && isWeak(cert));
  const sha1 = chain.some(
    (cert) => SHA1_NAMES.has(cert.signatureAlgorithm) && !(cert.selfSigned && options.trustedSpki.has(cert.spkiSha256)),
  );
  const selfSignedLeaf = leaf.selfSigned && !options.trustedSpki.has(leaf.spkiSha256);
  const anchored = chain.some((cert) => options.trustedSpki.has(cert.spkiSha256));
  const expired = leaf.notAfter.getTime() < options.now.getTime();

  if (distrusted.length > 0) {
    findings.push(netFinding({
      id: "CERT_DISTRUSTED_CA",
      severity: "critical",
      title: "Certificate chain contains a distrusted key",
      summary: `The chain includes ${distrusted.map((hit) => hit.name).join(", ")}.`,
      why: "A chain that contains a leaked or removed CA key can be forged. Vigil blocks that chain even when the root is still in the pinned Mozilla bundle.",
      remediation: ["Do not send users through this host until it is reissued from a CA that is still trusted."],
      recommendationOnly: false,
      category: "certificate",
      evidence: distrusted.map((hit) => `${hit.name} ${hit.spkiSha256.slice(0, 16)}`).join("; "),
    }));
  }
  if (expired) {
    findings.push(netFinding({
      id: "CERT_EXPIRED",
      severity: "critical",
      title: "Certificate is expired",
      summary: `The leaf certificate expired on ${leaf.notAfter.toISOString()}.`,
      why: "An expired certificate is not a valid name binding.",
      remediation: ["Renew the certificate and deploy the new chain."],
      recommendationOnly: false,
      category: "certificate",
      evidence: leaf.notAfter.toISOString(),
    }));
  } else if (daysRemaining < 14) {
    findings.push(netFinding({
      id: "CERT_EXPIRING",
      severity: "high",
      title: "Certificate expires within 14 days",
      summary: `The leaf certificate has ${daysRemaining} days left.`,
      why: "A certificate that lapses during a deploy window takes the site offline or trains users to click through warnings.",
      remediation: ["Renew the certificate before it expires."],
      recommendationOnly: true,
      category: "certificate",
      evidence: `${daysRemaining} days`,
    }));
  }
  if (!hostnameMatches) {
    findings.push(netFinding({
      id: "CERT_HOSTNAME_MISMATCH",
      severity: "critical",
      title: "Certificate name does not match the host",
      summary: `The certificate presented for ${options.host} does not list that name.`,
      why: "A name mismatch means the key was issued for somewhere else.",
      remediation: ["Install a certificate whose SAN includes this hostname."],
      recommendationOnly: false,
      category: "certificate",
      evidence: options.host,
    }));
  }
  if (selfSignedLeaf) {
    findings.push(netFinding({
      id: "CERT_SELF_SIGNED",
      severity: "critical",
      title: "Leaf certificate is self-signed",
      summary: "The server certificate is signed by its own key and that key is not a pinned root.",
      why: "Anyone can mint a self-signed certificate for this name.",
      remediation: ["Replace the leaf with a certificate that chains to a pinned Mozilla root."],
      recommendationOnly: false,
      category: "certificate",
      evidence: leaf.subject,
    }));
  }
  if (weak) {
    findings.push(netFinding({
      id: "CERT_WEAK_KEY",
      severity: "high",
      title: "Certificate uses a short key",
      summary: "A certificate in the chain uses RSA shorter than 2048 bits or an elliptic curve shorter than 224 bits.",
      why: "Short keys are cheaper to attack than the rest of the TLS handshake.",
      remediation: ["Reissue the certificate with a 2048-bit or longer RSA key, or a P-256 or stronger curve."],
      recommendationOnly: true,
      category: "certificate",
      evidence: chain.filter((cert) => isWeak(cert)).map((cert) => `${cert.publicKeyAlgorithm}-${cert.publicKeyBits}`).join(", "),
    }));
  }
  if (sha1) {
    findings.push(netFinding({
      id: "CERT_SHA1",
      severity: "high",
      title: "Certificate is signed with SHA-1",
      summary: "A certificate that is not a trust-anchor self-signature uses SHA-1.",
      why: "SHA-1 signatures can be forged. Trust-anchor self-signatures are ignored because clients do not rely on them.",
      remediation: ["Reissue the certificate with SHA-256 or stronger."],
      recommendationOnly: true,
      category: "certificate",
      evidence: chain.filter((cert) => SHA1_NAMES.has(cert.signatureAlgorithm)).map((cert) => cert.signatureAlgorithm).join(", "),
    }));
  }
  if (leaf.sct.count === 0) {
    findings.push(netFinding({
      id: "CERT_SCT_MISSING",
      severity: "medium",
      title: "No embedded signed certificate timestamp",
      summary: "The leaf certificate does not contain a parsed SCT list. Signatures were not checked.",
      why: "Embedded SCTs are how a client sees that a certificate was logged. This check only looks for the extension bytes.",
      remediation: ["Ask the CA for a certificate with embedded SCTs."],
      recommendationOnly: true,
      category: "certificate",
      evidence: "sct count 0",
    }));
  }

  const authorized = anchored && distrusted.length === 0 && hostnameMatches && !expired && !selfSignedLeaf;
  const level = findings.some((finding) => finding.severity === "critical" && !finding.recommendationOnly)
    ? "block"
    : findings.length > 0
      ? "warn"
      : authorized
        ? "ok"
        : "warn";
  const cert: CertCheck = {
    host: options.host,
    level: authorized ? level : findings.some((finding) => !finding.recommendationOnly) ? "block" : "warn",
    authorized,
    issuer: leaf.issuer,
    daysRemaining,
    hostnameMatches,
    distrusted,
    selfSigned: leaf.selfSigned,
    weakKey: weak,
    sha1,
    sct: {
      present: leaf.sct.present,
      count: leaf.sct.count,
      wellFormed: leaf.sct.wellFormed,
      signaturesVerified: false,
      note: "Embedded SCT bytes were parsed for presence only. Signatures were not verified.",
    },
  };
  if (!anchored && !findings.some((finding) => finding.id === "CERT_DISTRUSTED_CA" || finding.id === "CERT_SELF_SIGNED")) {
    cert.error = "Chain does not end at a pinned Mozilla root";
  }
  return { findings, cert };
}

export function unavailableCertificate(host: string, error: string): { findings: Finding[]; cert: CertCheck } {
  const findings = [
    netFinding({
      id: "CERT_UNAVAILABLE",
      severity: "high",
      title: "Certificate could not be inspected",
      summary: error,
      why: "Vigil failed open on the certificate check. The rest of the scan still runs.",
      remediation: ["Retry the scan. A network failure here is not a trusted certificate."],
      recommendationOnly: true,
      category: "certificate",
      evidence: error,
    }),
  ];
  return {
    findings,
    cert: {
      host,
      level: "unknown",
      authorized: null,
      distrusted: [],
      selfSigned: false,
      weakKey: false,
      sha1: false,
      sct: {
        present: false,
        count: 0,
        wellFormed: false,
        signaturesVerified: false,
        note: "Embedded SCT bytes were parsed for presence only. Signatures were not verified.",
      },
      error,
    },
  };
}

export function hostnameMatches(host: string, cert: Pick<ParsedCert, "sanDns" | "sanIp" | "commonName">): boolean {
  return nameMatches(host, cert);
}

export async function connectCertificateChain(
  host: string,
  port: number,
  caPem: string,
  timeoutMs = 10_000,
  lookup?: AddressLookup,
): Promise<ParsedCert[]> {
  const pinned = await pinAddress(host, lookup ?? systemLookup);
  const servername = isIpLiteral(host) ? undefined : host;
  const peer = await new Promise<tls.PeerCertificate>((resolve, reject) => {
    const socket = tls.connect({
      host: pinned.address,
      port,
      servername,
      ca: caPem,
      rejectUnauthorized: false,
      ALPNProtocols: ["http/1.1"],
      lookup: pinnedLookup(pinned) as tls.ConnectionOptions["lookup"],
    }, () => {
      try {
        const certificate = socket.getPeerCertificate(true);
        socket.end();
        if (!certificate.raw) reject(new Error("TLS peer did not present a certificate"));
        else resolve(certificate);
      } catch (error) {
        socket.destroy();
        reject(error instanceof Error ? error : new Error("TLS inspection failed"));
      }
    });
    socket.setTimeout(timeoutMs, () => {
      socket.destroy();
      reject(new Error("TLS connection timed out"));
    });
    socket.on("error", (error) => reject(error));
  });
  return walkPeer(peer);
}

interface PeerNode {
  raw?: Buffer;
  fingerprint256?: string;
  issuerCertificate?: PeerNode;
}

function walkPeer(peer: tls.PeerCertificate): ParsedCert[] {
  const out: ParsedCert[] = [];
  const seen = new Set<string>();
  let current: PeerNode | undefined = peer;
  while (current?.raw) {
    const id = current.fingerprint256 || String(current.raw.length);
    if (seen.has(id)) break;
    seen.add(id);
    out.push(parseCertificate(current.raw));
    const next: PeerNode | undefined = current.issuerCertificate;
    if (!next || next === current || !next.raw) break;
    current = next;
  }
  return out;
}

function nameMatches(host: string, cert: Pick<ParsedCert, "sanDns" | "sanIp" | "commonName">): boolean {
  const name = host.toLowerCase().replace(/\.$/, "").replace(/^\[|\]$/g, "");
  const dns = cert.sanDns.length > 0 ? cert.sanDns : cert.commonName ? [cert.commonName] : [];
  if (cert.sanIp.some((ip) => ip.toLowerCase() === name)) return true;
  return dns.some((pattern) => dnsMatches(name, pattern.toLowerCase().replace(/\.$/, "")));
}

function dnsMatches(host: string, pattern: string): boolean {
  if (pattern.startsWith("*.")) {
    const rest = pattern.slice(1);
    return host.endsWith(rest) && host.length > rest.length && !host.slice(0, -rest.length).includes(".");
  }
  return host === pattern;
}

function isWeak(cert: ParsedCert): boolean {
  if (cert.publicKeyBits <= 0) return false;
  if (cert.publicKeyAlgorithm === "rsa") return cert.publicKeyBits < 2048;
  if (cert.publicKeyAlgorithm === "ec") return cert.publicKeyBits < 224;
  return false;
}

function keyAlgorithm(key: KeyObject): ParsedCert["publicKeyAlgorithm"] {
  if (key.asymmetricKeyType === "rsa") return "rsa";
  if (key.asymmetricKeyType === "ec") return "ec";
  return "other";
}

function keyBits(key: KeyObject): number {
  const details = key.asymmetricKeyDetails;
  if (details && "modulusLength" in details && details.modulusLength) return details.modulusLength;
  const curve = details && "namedCurve" in details ? (details.namedCurve ?? "") : "";
  if (/256|prime256v1|P-256/i.test(curve)) return 256;
  if (/384|P-384/i.test(curve)) return 384;
  if (/521|P-521/i.test(curve)) return 521;
  if (/224/.test(curve)) return 224;
  if (/192/.test(curve)) return 192;
  return 0;
}

function parseAltNames(text: string): { dns: string[]; ip: string[] } {
  const dns: string[] = [];
  const ip: string[] = [];
  for (const part of text.split(",")) {
    const dnsName = /DNS:([^,\s]+)/.exec(part)?.[1];
    const ipName = /IP Address:([^,\s]+)/.exec(part)?.[1];
    if (dnsName) dns.push(dnsName);
    if (ipName) ip.push(ipName);
  }
  return { dns, ip };
}

function readLength(raw: Uint8Array, offset: number): { length: number; next: number } | undefined {
  const first = raw[offset];
  if (first === undefined) return undefined;
  if (first < 0x80) return { length: first, next: offset + 1 };
  const bytes = first & 0x7f;
  if (bytes === 0 || offset + 1 + bytes > raw.length) return undefined;
  let length = 0;
  for (let i = 0; i < bytes; i++) length = (length << 8) | (raw[offset + 1 + i] ?? 0);
  return { length, next: offset + 1 + bytes };
}

function indexOfBytes(haystack: Uint8Array, needle: Uint8Array): number {
  if (needle.length === 0 || haystack.length < needle.length) return -1;
  for (let i = 0; i <= haystack.length - needle.length; i++) {
    let found = true;
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) {
        found = false;
        break;
      }
    }
    if (found) return i;
  }
  return -1;
}
