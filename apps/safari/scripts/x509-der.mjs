import { Buffer } from "node:buffer";

/** Minimal X.509 walker. SPKI bytes match Node's publicKey.export({ type: "spki", format: "der" }). */

export function readTLV(buf, offset) {
  if (offset < 0 || offset + 2 > buf.length) return null;
  const tag = buf[offset];
  let length = buf[offset + 1];
  let header = 2;
  if (length & 0x80) {
    const count = length & 0x7f;
    if (count === 0 || count > 3 || offset + 2 + count > buf.length) return null;
    length = 0;
    for (let i = 0; i < count; i += 1) length = (length * 256) + buf[offset + 2 + i];
    header = 2 + count;
  }
  const start = offset + header;
  const end = start + length;
  if (end > buf.length) return null;
  return { tag, offset, start, end };
}

function children(buf, tlv) {
  const out = [];
  let cursor = tlv.start;
  while (cursor < tlv.end) {
    const child = readTLV(buf, cursor);
    if (!child || child.end <= cursor) return null;
    out.push(child);
    cursor = child.end;
  }
  if (cursor !== tlv.end) return null;
  return out;
}

function parseTime(buf, tlv) {
  const text = buf.subarray(tlv.start, tlv.end).toString("ascii").replace(/\..*$/, "").replace(/Z$/, "");
  const digits = text.replace(/[+-].*$/, "");
  if (tlv.tag === 0x17 && digits.length >= 12) {
    const year = Number(digits.slice(0, 2));
    return Date.UTC(
      year >= 50 ? 1900 + year : 2000 + year,
      Number(digits.slice(2, 4)) - 1,
      Number(digits.slice(4, 6)),
      Number(digits.slice(6, 8)),
      Number(digits.slice(8, 10)),
      Number(digits.slice(10, 12)),
    );
  }
  if (tlv.tag === 0x18 && digits.length >= 14) {
    return Date.UTC(
      Number(digits.slice(0, 4)),
      Number(digits.slice(4, 6)) - 1,
      Number(digits.slice(6, 8)),
      Number(digits.slice(8, 10)),
      Number(digits.slice(10, 12)),
      Number(digits.slice(12, 14)),
    );
  }
  return null;
}

const SAN_OID = Buffer.from([0x55, 0x1d, 0x11]);
const CN_OID = Buffer.from([0x55, 0x04, 0x03]);

function directoryName(buf, name) {
  const strings = [];
  const rdns = children(buf, name) ?? [];
  for (const rdn of rdns) {
    const attrs = children(buf, rdn) ?? [];
    for (const attr of attrs) {
      const parts = children(buf, attr) ?? [];
      if (parts.length < 2) continue;
      const oid = buf.subarray(parts[0].start, parts[0].end);
      if (!oid.equals(CN_OID)) continue;
      strings.push(buf.subarray(parts[1].start, parts[1].end).toString("utf8"));
    }
  }
  return strings;
}

function sanDns(buf, tbsKids) {
  const wrapper = tbsKids.find((kid) => kid.tag === 0xa3);
  if (!wrapper) return [];
  const sequence = readTLV(buf, wrapper.start);
  if (!sequence || sequence.tag !== 0x30) return [];
  const names = [];
  for (const ext of children(buf, sequence) ?? []) {
    const parts = children(buf, ext) ?? [];
    if (parts.length < 2) continue;
    const oid = buf.subarray(parts[0].start, parts[0].end);
    if (!oid.equals(SAN_OID)) continue;
    const octet = parts[parts.length - 1];
    if (octet.tag !== 0x04) continue;
    const general = readTLV(buf, octet.start);
    if (!general) continue;
    for (const name of children(buf, general) ?? []) {
      if (name.tag !== 0x82) continue;
      names.push(buf.subarray(name.start, name.end).toString("ascii").toLowerCase().replace(/\.$/, ""));
    }
  }
  return names;
}

export function parseCertificate(der) {
  const buf = Buffer.isBuffer(der) ? der : Buffer.from(der);
  const cert = readTLV(buf, 0);
  if (!cert || cert.tag !== 0x30 || cert.offset !== 0) return null;
  const outer = children(buf, cert);
  if (!outer || outer.length < 1 || outer[0].tag !== 0x30) return null;
  const tbsKids = children(buf, outer[0]);
  if (!tbsKids || tbsKids.length < 6) return null;
  const index = tbsKids[0].tag === 0xa0 ? 1 : 0;
  const issuer = tbsKids[index + 2];
  const validity = tbsKids[index + 3];
  const subject = tbsKids[index + 4];
  const spki = tbsKids[index + 5];
  if (!issuer || !validity || !subject || !spki) return null;
  if (validity.tag !== 0x30 || spki.tag !== 0x30) return null;
  const times = children(buf, validity);
  if (!times || times.length < 2) return null;
  const notBefore = parseTime(buf, times[0]);
  const notAfter = parseTime(buf, times[1]);
  if (notBefore === null || notAfter === null) return null;
  const issuerBytes = buf.subarray(issuer.offset, issuer.end);
  const subjectBytes = buf.subarray(subject.offset, subject.end);
  const commonNames = directoryName(buf, subject);
  return {
    spki: buf.subarray(spki.offset, spki.end),
    notBefore,
    notAfter,
    selfSigned: issuerBytes.equals(subjectBytes),
    sanDns: sanDns(buf, tbsKids),
    commonName: commonNames[0] ?? null,
  };
}
