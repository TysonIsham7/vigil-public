import english from "../../data/bip39-english.json" with { type: "json" };
import { sha256 } from "./sha256.js";

/** sha256 of the official bitcoin/bips bip-0039/english.txt bytes. */
export const BIP39_ENGLISH_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda";

export const BIP39_ENGLISH: readonly string[] = english;

const COUNTS = new Set([12, 15, 18, 21, 24]);

let wordMap: Map<string, number> | null = null;

export function findSeedPhrase(input: string): { count: 12 | 15 | 18 | 21 | 24 } | null {
  if (input.length === 0 || input.length > 2000) return null;
  const parts = input.trim().split(/\s+/);
  if (!COUNTS.has(parts.length)) return null;
  const words: string[] = [];
  for (const part of parts) {
    const token = part.toLowerCase().replace(/^[^a-z]+|[^a-z]+$/g, "");
    if (!/^[a-z]+$/.test(token)) return null;
    words.push(token);
  }
  const count = words.length;
  if (!checksumOk(words)) return null;
  words.length = 0;
  if (count !== 12 && count !== 15 && count !== 18 && count !== 21 && count !== 24) return null;
  return { count };
}

/** Warning copy. It takes a count, never the words. */
export function seedGuardCopy(count: number): { title: string; body: string } {
  const known = count === 12 || count === 15 || count === 18 || count === 21 || count === 24;
  return {
    title: "Recovery phrase held",
    body: known
      ? `This page was given a ${count}-word recovery phrase. Vigil did not keep the words. Continue only if you intend to enter them here.`
      : "This page was given a recovery phrase. Vigil did not keep the words.",
  };
}

function indexes(): Map<string, number> {
  if (wordMap) return wordMap;
  const next = new Map<string, number>();
  for (let i = 0; i < BIP39_ENGLISH.length; i += 1) next.set(BIP39_ENGLISH[i] ?? "", i);
  wordMap = next;
  return next;
}

function checksumOk(words: readonly string[]): boolean {
  const map = indexes();
  const bits: number[] = [];
  for (const word of words) {
    const value = map.get(word);
    if (value === undefined) return false;
    for (let shift = 10; shift >= 0; shift -= 1) bits.push((value >> shift) & 1);
  }
  const checksumBits = bits.length / 33;
  if (!Number.isInteger(checksumBits)) return false;
  const entropyBits = bits.length - checksumBits;
  if (entropyBits % 8 !== 0) return false;
  const entropy = new Uint8Array(entropyBits / 8);
  for (let i = 0; i < entropyBits; i += 1) {
    if (bits[i]) entropy[i >> 3] = (entropy[i >> 3] ?? 0) | (1 << (7 - (i & 7)));
  }
  const digest = sha256(entropy);
  let ok = true;
  for (let i = 0; i < checksumBits; i += 1) {
    const bit = ((digest[i >> 3] ?? 0) >> (7 - (i & 7))) & 1;
    if (bit !== bits[entropyBits + i]) ok = false;
  }
  entropy.fill(0);
  digest.fill(0);
  return ok;
}
