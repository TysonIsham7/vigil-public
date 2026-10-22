const BASE = 36;
const TMIN = 1;
const TMAX = 26;
const SKEW = 38;
const DAMP = 700;
const INITIAL_BIAS = 72;
const INITIAL_N = 128;

function adapt(delta: number, numPoints: number, firstTime: boolean): number {
  let next = firstTime ? Math.floor(delta / DAMP) : delta >> 1;
  next += Math.floor(next / numPoints);
  let k = 0;
  while (next > Math.floor(((BASE - TMIN) * TMAX) / 2)) {
    next = Math.floor(next / (BASE - TMIN));
    k += BASE;
  }
  return k + Math.floor(((BASE - TMIN + 1) * next) / (next + SKEW));
}

function decodeDigit(code: number): number {
  if (code >= 48 && code <= 57) return code - 22;
  if (code >= 65 && code <= 90) return code - 65;
  if (code >= 97 && code <= 122) return code - 97;
  return BASE;
}

/** Decode one Punycode label, without the xn-- prefix. */
export function punycodeDecode(input: string): string {
  const basic = input.lastIndexOf("-");
  const output: number[] = [];
  let index = 0;
  if (basic > 0) {
    for (let i = 0; i < basic; i++) output.push(input.charCodeAt(i));
    index = basic + 1;
  } else if (basic === 0) {
    index = 1;
  }
  let n = INITIAL_N;
  let i = 0;
  let bias = INITIAL_BIAS;
  while (index < input.length) {
    const oldi = i;
    let w = 1;
    for (let k = BASE; ; k += BASE) {
      if (index >= input.length) return input;
      const digit = decodeDigit(input.charCodeAt(index++));
      if (digit >= BASE) return input;
      i += digit * w;
      const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
      if (digit < t) break;
      w *= BASE - t;
    }
    const outLen = output.length + 1;
    bias = adapt(i - oldi, outLen, oldi === 0);
    n += Math.floor(i / outLen);
    i %= outLen;
    output.splice(i, 0, n);
    i += 1;
  }
  return String.fromCodePoint(...output);
}

export function decodeHostname(host: string): string {
  return host
    .trim()
    .replace(/\.$/, "")
    .split(".")
    .map((label) => (label.toLowerCase().startsWith("xn--") ? punycodeDecode(label.slice(4)) : label))
    .join(".");
}
