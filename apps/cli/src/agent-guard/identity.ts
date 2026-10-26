import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

export const MIN_PHONE_DIGITS = 10;
export const MIN_NAME_LENGTH = 8;
export const MIN_ADDRESS_LENGTH = 16;
export const MIN_TOKEN_LENGTH = 12;

export class IdentityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "IdentityError";
  }
}

export interface Identity {
  emailHmac: Buffer[];
  phoneHmac: Buffer[];
  tokenHmac: Buffer[];
  tokenLengths: number[];
  names: string[];
  addresses: string[];
}

export function emptyIdentity(): Identity {
  return { emailHmac: [], phoneHmac: [], tokenHmac: [], tokenLengths: [], names: [], addresses: [] };
}

export function hmacSha256(key: Buffer, value: string): Buffer {
  return createHmac("sha256", key).update(value, "utf8").digest();
}

export function hmacEquals(key: Buffer, value: string, expected: readonly Buffer[]): boolean {
  const got = hmacSha256(key, value);
  return expected.some((item) => item.length === got.length && timingSafeEqual(item, got));
}

export function assertPrivateMode(path: string, mode: number, label: string): void {
  if ((mode & 0o077) === 0) return;
  const octal = (mode & 0o777).toString(8).padStart(4, "0");
  throw new IdentityError(`${label} ${path} mode ${octal} is readable by other users`);
}

export function writePrivate(path: string, data: Buffer | string): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(path, data, { mode: 0o600 });
  chmodSync(path, 0o600);
}

export function parseIdentity(text: string, key: Buffer): Identity {
  const identity = emptyIdentity();
  const lines = text.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const split = trimmed.indexOf(":");
    if (split <= 0) throw new IdentityError("identifier line is malformed");
    const kind = trimmed.slice(0, split).trim().toLowerCase();
    const value = trimmed.slice(split + 1).trim();
    if (!kind) throw new IdentityError("identifier line is malformed");
    if (!value) throw new IdentityError("identifier value is empty");
    if (kind === "email") {
      const email = value.trim().toLowerCase();
      if (!/^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/.test(email)) {
        throw new IdentityError("email is not a full address");
      }
      identity.emailHmac.push(hmacSha256(key, email));
    } else if (kind === "phone") {
      const digits = value.replace(/\D/g, "");
      if (digits.length < MIN_PHONE_DIGITS) throw new IdentityError(`phone is shorter than ${MIN_PHONE_DIGITS} digits`);
      identity.phoneHmac.push(hmacSha256(key, digits));
    } else if (kind === "token") {
      if (value.length < MIN_TOKEN_LENGTH) throw new IdentityError(`token is shorter than ${MIN_TOKEN_LENGTH} characters`);
      identity.tokenHmac.push(hmacSha256(key, value));
      identity.tokenLengths.push(value.length);
    } else if (kind === "name") {
      const name = value.normalize("NFKC");
      if ([...name].length < MIN_NAME_LENGTH) throw new IdentityError(`name is shorter than ${MIN_NAME_LENGTH} characters`);
      identity.names.push(name);
    } else if (kind === "address") {
      const address = value.normalize("NFKC");
      if ([...address].length < MIN_ADDRESS_LENGTH) throw new IdentityError(`address is shorter than ${MIN_ADDRESS_LENGTH} characters`);
      identity.addresses.push(address);
    } else {
      throw new IdentityError("unknown identifier kind");
    }
  }
  return identity;
}

export function loadKey(path: string): Buffer {
  if (existsSync(path)) {
    assertPrivateMode(path, statSync(path).mode, "hmac key");
    const raw = readFileSync(path);
    try {
      if (raw.length < 32) throw new IdentityError(`hmac key ${path} is unusable`);
      return Buffer.from(raw.subarray(0, 32));
    } finally {
      raw.fill(0);
    }
  }
  const key = randomBytes(32);
  writePrivate(path, key);
  return key;
}

export function readIdentityFile(path: string, keyPath: string): { identity: Identity; key: Buffer } {
  if (!existsSync(path)) return { identity: emptyIdentity(), key: randomBytes(32) };
  assertPrivateMode(path, statSync(path).mode, "identifier file");
  const raw = readFileSync(path);
  try {
    const key = loadKey(keyPath);
    return { identity: parseIdentity(raw.toString("utf8"), key), key };
  } finally {
    raw.fill(0);
  }
}
