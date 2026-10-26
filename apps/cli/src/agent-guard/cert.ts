import { createPrivateKey, generateKeyPairSync, randomBytes, sign, X509Certificate, type KeyObject } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { assertPrivateMode, writePrivate } from "./identity.js";

export interface LocalCa {
  certPem: string;
  keyPem: string;
  publicKey: KeyObject;
  privateKey: KeyObject;
}

export function createCa(commonName: string): LocalCa {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const certPem = certificatePem({
    publicKey,
    privateKey,
    subject: commonName,
    issuer: commonName,
    signer: privateKey,
    ca: true,
    hostname: null,
  });
  const keyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  return { certPem, keyPem, publicKey, privateKey };
}

export function mintLeaf(ca: LocalCa, hostname: string): { certPem: string; keyPem: string } {
  if (!/^[A-Za-z0-9.-]+$/.test(hostname) || hostname.length > 253) {
    throw new Error("hostname was rejected");
  }
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const certPem = certificatePem({
    publicKey,
    privateKey,
    subject: hostname,
    issuer: caName(ca.certPem),
    signer: ca.privateKey,
    ca: false,
    hostname,
  });
  const keyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const parsed = new X509Certificate(certPem);
  if (!parsed.verify(ca.publicKey)) throw new Error("minted certificate did not verify");
  if (!parsed.checkHost(hostname)) throw new Error("minted certificate did not match the host");
  return { certPem, keyPem };
}

export function loadOrCreateCa(certPath: string, keyPath: string): LocalCa {
  if (existsSync(certPath) || existsSync(keyPath)) {
    if (!existsSync(certPath) || !existsSync(keyPath)) throw new Error("local CA certificate and key must both be present");
    assertPrivateMode(keyPath, statSync(keyPath).mode, "local CA key");
    const certPem = readFileSync(certPath, "utf8");
    const keyPem = readFileSync(keyPath, "utf8");
    const privateKey = createPrivateKey(keyPem);
    const publicKey = new X509Certificate(certPem).publicKey;
    return { certPem, keyPem, publicKey, privateKey };
  }
  const ca = createCa("Vigil agent-guard CA");
  writePrivate(certPath, ca.certPem);
  writePrivate(keyPath, ca.keyPem);
  return ca;
}

function caName(certPem: string): string {
  const subject = new X509Certificate(certPem).subject;
  const match = /CN=([^,\n]+)/.exec(subject);
  return match?.[1]?.trim() || "Vigil agent-guard CA";
}

function certificatePem(input: {
  publicKey: KeyObject;
  privateKey: KeyObject;
  subject: string;
  issuer: string;
  signer: KeyObject;
  ca: boolean;
  hostname: string | null;
}): string {
  const serial = randomSerial();
  const now = new Date();
  const notBefore = new Date(now.getTime() - 60 * 60 * 1000);
  const notAfter = new Date(now.getTime() + 825 * 24 * 60 * 60 * 1000);
  const spki = input.publicKey.export({ type: "spki", format: "der" });
  if (!Buffer.isBuffer(spki)) throw new Error("public key export failed");
  const tbs = sequence(Buffer.concat([
    version3(),
    integer(serial),
    ecdsaSha256(),
    directoryName(input.issuer),
    sequence(Buffer.concat([utcTime(notBefore), utcTime(notAfter)])),
    directoryName(input.subject),
    spki,
    extensions(input.ca, input.hostname),
  ]));
  const signature = sign("sha256", tbs, input.signer);
  const cert = sequence(Buffer.concat([
    tbs,
    ecdsaSha256(),
    bitString(signature),
  ]));
  return pem("CERTIFICATE", cert);
}

function randomSerial(): Buffer {
  const bytes = randomBytes(16);
  bytes[0] = (bytes[0] ?? 1) & 0x7f || 1;
  return bytes;
}

function extensions(ca: boolean, hostname: string | null): Buffer {
  const list: Buffer[] = [
    extension([2, 5, 29, 19], true, basicConstraints(ca)),
    extension([2, 5, 29, 15], true, ca ? keyUsage(0x06, 1) : keyUsage(0x80, 7)),
  ];
  if (!ca && hostname) {
    list.push(extension([2, 5, 29, 37], false, sequence(encodeOid([1, 3, 6, 1, 5, 5, 7, 3, 1]))));
    list.push(extension([2, 5, 29, 17], false, sequence(tag(0x82, Buffer.from(hostname, "ascii")))));
  }
  return tag(0xa3, sequence(Buffer.concat(list)));
}

function basicConstraints(ca: boolean): Buffer {
  return sequence(Buffer.from(ca ? [0x01, 0x01, 0xff] : [0x01, 0x01, 0x00]));
}

function keyUsage(bits: number, unused: number): Buffer {
  return Buffer.from([0x03, 0x02, unused, bits]);
}

function extension(oid: number[], critical: boolean, value: Buffer): Buffer {
  const parts = [encodeOid(oid)];
  if (critical) parts.push(Buffer.from([0x01, 0x01, 0xff]));
  parts.push(octetString(value));
  return sequence(Buffer.concat(parts));
}

function directoryName(name: string): Buffer {
  const cn = sequence(Buffer.concat([
    encodeOid([2, 5, 4, 3]),
    tag(0x13, Buffer.from(printable(name), "ascii")),
  ]));
  return sequence(tag(0x31, cn));
}

function printable(name: string): string {
  const cleaned = name.replace(/[^A-Za-z0-9 .'-]/g, " ").trim();
  return cleaned.slice(0, 64) || "Vigil";
}

function version3(): Buffer {
  return tag(0xa0, Buffer.from([0x02, 0x01, 0x02]));
}

function ecdsaSha256(): Buffer {
  return sequence(encodeOid([1, 2, 840, 10045, 4, 3, 2]));
}

function utcTime(date: Date): Buffer {
  const pad = (value: number) => String(value).padStart(2, "0");
  const text = `${pad(date.getUTCFullYear() % 100)}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}Z`;
  return tag(0x17, Buffer.from(text, "ascii"));
}

function integer(value: Buffer): Buffer {
  let body = value;
  if ((body[0] ?? 0) & 0x80) body = Buffer.concat([Buffer.from([0x00]), body]);
  return tag(0x02, body);
}

function bitString(payload: Buffer): Buffer {
  return tag(0x03, Buffer.concat([Buffer.from([0x00]), payload]));
}

function octetString(payload: Buffer): Buffer {
  return tag(0x04, payload);
}

function sequence(payload: Buffer): Buffer {
  return tag(0x30, payload);
}

function tag(tagByte: number, content: Buffer): Buffer {
  if (content.length < 128) return Buffer.concat([Buffer.from([tagByte, content.length]), content]);
  if (content.length < 256) return Buffer.concat([Buffer.from([tagByte, 0x81, content.length]), content]);
  return Buffer.concat([Buffer.from([tagByte, 0x82, content.length >> 8, content.length & 0xff]), content]);
}

function encodeOid(parts: number[]): Buffer {
  const bytes = [parts[0]! * 40 + parts[1]!];
  for (const part of parts.slice(2)) {
    const stack = [part & 0x7f];
    let value = part >> 7;
    while (value > 0) {
      stack.push((value & 0x7f) | 0x80);
      value >>= 7;
    }
    bytes.push(...stack.reverse());
  }
  return tag(0x06, Buffer.from(bytes));
}

function pem(label: string, der: Buffer): string {
  const lines = der.toString("base64").match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}
