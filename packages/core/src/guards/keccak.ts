/** Keccak-256 as used by Ethereum (not NIST SHA3). Padding is 0x01 … 0x80. */

const RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];

/** r[x][y] from the Keccak permutation. Index is x + 5*y. */
const ROT: readonly (readonly number[])[] = [
  [0, 36, 3, 41, 18],
  [1, 44, 10, 45, 2],
  [62, 6, 43, 15, 61],
  [28, 55, 25, 21, 56],
  [27, 20, 39, 8, 14],
];
const MASK = (1n << 64n) - 1n;

function rotl(value: bigint, bits: number): bigint {
  if (bits === 0) return value;
  const shift = BigInt(bits);
  return ((value << shift) | (value >> (64n - shift))) & MASK;
}

function lane(x: number, y: number): number {
  return x + 5 * y;
}

function keccakF(state: BigUint64Array): void {
  const c = new BigUint64Array(5);
  const b = new BigUint64Array(25);
  for (let round = 0; round < 24; round += 1) {
    for (let x = 0; x < 5; x += 1) {
      c[x] = (state[lane(x, 0)] ?? 0n)
        ^ (state[lane(x, 1)] ?? 0n)
        ^ (state[lane(x, 2)] ?? 0n)
        ^ (state[lane(x, 3)] ?? 0n)
        ^ (state[lane(x, 4)] ?? 0n);
    }
    for (let x = 0; x < 5; x += 1) {
      const d = (c[(x + 4) % 5] ?? 0n) ^ rotl(c[(x + 1) % 5] ?? 0n, 1);
      for (let y = 0; y < 5; y += 1) state[lane(x, y)] = ((state[lane(x, y)] ?? 0n) ^ d) & MASK;
    }
    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) {
        const nextX = y;
        const nextY = (2 * x + 3 * y) % 5;
        b[lane(nextX, nextY)] = rotl(state[lane(x, y)] ?? 0n, ROT[x]?.[y] ?? 0);
      }
    }
    for (let y = 0; y < 5; y += 1) {
      for (let x = 0; x < 5; x += 1) {
        const value = (b[lane(x, y)] ?? 0n) ^ ((~(b[lane((x + 1) % 5, y)] ?? 0n)) & (b[lane((x + 2) % 5, y)] ?? 0n));
        state[lane(x, y)] = value & MASK;
      }
    }
    state[0] = ((state[0] ?? 0n) ^ (RC[round] ?? 0n)) & MASK;
  }
}

function xorBlock(state: BigUint64Array, block: Uint8Array): void {
  for (let i = 0; i < block.length; i += 1) {
    const lane = i >> 3;
    state[lane] = ((state[lane] ?? 0n) ^ (BigInt(block[i] ?? 0) << BigInt((i & 7) * 8))) & MASK;
  }
}

export function keccak256(message: Uint8Array): Uint8Array {
  const rate = 136;
  const state = new BigUint64Array(25);
  let offset = 0;
  while (offset + rate <= message.length) {
    xorBlock(state, message.subarray(offset, offset + rate));
    keccakF(state);
    offset += rate;
  }
  const block = new Uint8Array(rate);
  block.set(message.subarray(offset));
  const tail = message.length - offset;
  block[tail] ^= 0x01;
  block[rate - 1] ^= 0x80;
  xorBlock(state, block);
  keccakF(state);
  const out = new Uint8Array(32);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number(((state[i >> 3] ?? 0n) >> BigInt((i & 7) * 8)) & 0xffn);
  }
  state.fill(0n);
  block.fill(0);
  return out;
}

export function keccak256Hex(message: Uint8Array): string {
  return [...keccak256(message)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** First four bytes of keccak256(signature), lowercase hex without 0x. */
export function abiSelector(signature: string): string {
  const bytes = new Uint8Array(signature.length);
  for (let i = 0; i < signature.length; i += 1) bytes[i] = signature.charCodeAt(i);
  return keccak256Hex(bytes).slice(0, 8);
}
