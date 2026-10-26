import { abiSelector } from "./keccak.js";

/** Risky EIP-1193 requests. Classification is local: no spender registry and no network. */

export const WALLET_REASONS = [
  "eth_sign",
  "unlimited_approve",
  "set_approval_for_all",
  "permit",
  "permit2",
  "unknown_spender",
] as const;

export type WalletReason = (typeof WALLET_REASONS)[number];

export interface WalletRequestRisk {
  risky: boolean;
  reasons: WalletReason[];
  spender?: string;
}

const APPROVE = abiSelector("approve(address,uint256)");
const SET_APPROVAL_FOR_ALL = abiSelector("setApprovalForAll(address,bool)");
const MAX_WORD = "f".repeat(64);
const PERMIT2_TYPES = new Set(["PermitSingle", "PermitBatch", "PermitWitnessTransferFrom", "PermitBatchWitnessTransferFrom"]);

const CLEAN: WalletRequestRisk = { risky: false, reasons: [] };

export function classifyWalletRequest(request: unknown, knownSpenders: readonly string[] = []): WalletRequestRisk {
  const payload = asRecord(request);
  if (!payload || typeof payload.method !== "string") return CLEAN;
  const method = payload.method.trim().toLowerCase();
  const reasons = new Set<WalletReason>();
  let spender: string | undefined;
  if (method === "eth_sign") reasons.add("eth_sign");
  if (isTypedData(method)) readTypedData(payload.params, reasons, (found) => { spender = found; });
  for (const data of callData(method, payload.params)) {
    const decoded = decodeCall(data);
    if (!decoded) continue;
    if (decoded.kind === "approve") {
      if (decoded.unlimited) reasons.add("unlimited_approve");
      spender = spender ?? decoded.spender;
      if (decoded.spender && !isKnown(decoded.spender, knownSpenders)) reasons.add("unknown_spender");
    }
    if (decoded.kind === "approval-for-all") {
      reasons.add("set_approval_for_all");
      spender = spender ?? decoded.spender;
      if (decoded.spender && !isKnown(decoded.spender, knownSpenders)) reasons.add("unknown_spender");
    }
  }
  if (spender && (reasons.has("permit") || reasons.has("permit2")) && !isKnown(spender, knownSpenders)) {
    reasons.add("unknown_spender");
  }
  const ordered = WALLET_REASONS.filter((reason) => reasons.has(reason));
  if (ordered.length === 0) return CLEAN;
  return spender ? { risky: true, reasons: ordered, spender } : { risky: true, reasons: ordered };
}

export function walletGuardCopy(risk: Pick<WalletRequestRisk, "reasons" | "spender">): { title: string; body: string; rememberLabel?: string } {
  const lines = risk.reasons.map((reason) => reasonLine(reason, risk.spender));
  const copy: { title: string; body: string; rememberLabel?: string } = {
    title: "Wallet request held",
    body: lines.join(" ") || "This wallet request looks risky.",
  };
  if (risk.spender) copy.rememberLabel = "Remember this spender on this page";
  return copy;
}

function reasonLine(reason: WalletReason, spender: string | undefined): string {
  if (reason === "eth_sign") return "eth_sign asks the wallet to sign a raw hash the page chose.";
  if (reason === "unlimited_approve") return "This approval is for the maximum token amount.";
  if (reason === "set_approval_for_all") return "setApprovalForAll would allow that operator to move every token in the set.";
  if (reason === "permit") return "The typed data is a token permit.";
  if (reason === "permit2") return "The typed data is a Permit2 allowance.";
  if (spender) return `The spender ${spender} is not one already allowed on this page.`;
  return "The spender is not one already allowed on this page.";
}

function isTypedData(method: string): boolean {
  return method === "eth_signtypeddata" || method === "eth_signtypeddata_v1" || method === "eth_signtypeddata_v3" || method === "eth_signtypeddata_v4";
}

function readTypedData(params: unknown, reasons: Set<WalletReason>, setSpender: (spender: string) => void): void {
  const typed = typedData(params);
  if (!typed) return;
  const primary = typeof typed.primaryType === "string" ? typed.primaryType : "";
  const typeNames = typed.types && typeof typed.types === "object" ? Object.keys(typed.types as object) : [];
  const domain = asRecord(typed.domain);
  const domainName = domain && typeof domain.name === "string" ? domain.name : "";
  const permit2 = domainName === "Permit2" || PERMIT2_TYPES.has(primary) || typeNames.some((name) => PERMIT2_TYPES.has(name));
  const permit = !permit2 && (primary === "Permit" || typeNames.includes("Permit"));
  if (permit2) reasons.add("permit2");
  else if (permit) reasons.add("permit");
  if (!permit && !permit2) return;
  const found = findSpender(typed.message);
  if (found) setSpender(found);
}

function typedData(params: unknown): Record<string, unknown> | null {
  if (!Array.isArray(params)) return null;
  const candidate = params.length >= 2 ? params[1] : params[0];
  if (typeof candidate === "string") {
    try {
      return asRecord(JSON.parse(candidate));
    } catch {
      return null;
    }
  }
  return asRecord(candidate);
}

function findSpender(value: unknown, depth = 0): string | undefined {
  if (depth > 4 || !value || typeof value !== "object") return undefined;
  if (Array.isArray(value)) {
    for (const item of value.slice(0, 8)) {
      const found = findSpender(item, depth + 1);
      if (found) return found;
    }
    return undefined;
  }
  const record = value as Record<string, unknown>;
  for (const key of ["spender", "operator", "approved"]) {
    const field = record[key];
    if (typeof field === "string" && /^0x[0-9a-fA-F]{40}$/.test(field)) return field.toLowerCase();
  }
  for (const nested of Object.values(record).slice(0, 12)) {
    const found = findSpender(nested, depth + 1);
    if (found) return found;
  }
  return undefined;
}

function callData(method: string, params: unknown): string[] {
  if (method !== "eth_sendtransaction" && method !== "eth_signtransaction" && method !== "wallet_sendcalls") return [];
  if (!Array.isArray(params)) return [];
  const first = asRecord(params[0]);
  if (!first) return [];
  if (method === "wallet_sendcalls") {
    if (!Array.isArray(first.calls)) return [];
    return first.calls.flatMap((call) => {
      const record = asRecord(call);
      const data = record?.data ?? record?.input;
      return typeof data === "string" ? [data] : [];
    });
  }
  const data = first.data ?? first.input;
  return typeof data === "string" ? [data] : [];
}

function decodeCall(data: string): { kind: "approve" | "approval-for-all"; spender?: string; unlimited: boolean } | null {
  const hex = data.trim().toLowerCase();
  if (!hex.startsWith("0x")) return null;
  const body = hex.slice(2);
  if (!/^[0-9a-f]*$/.test(body) || body.length < 8 + 128 || (body.length - 8) % 64 !== 0) return null;
  const selector = body.slice(0, 8);
  const word = (index: number) => body.slice(8 + index * 64, 8 + (index + 1) * 64);
  if (selector === APPROVE) {
    return { kind: "approve", spender: addressOf(word(0)), unlimited: word(1) === MAX_WORD };
  }
  if (selector === SET_APPROVAL_FOR_ALL && /^0{63}1$/.test(word(1))) {
    return { kind: "approval-for-all", spender: addressOf(word(0)), unlimited: false };
  }
  return null;
}

function addressOf(word: string): string | undefined {
  if (!/^0{24}[0-9a-f]{40}$/.test(word)) return undefined;
  return `0x${word.slice(24)}`;
}

function isKnown(spender: string, knownSpenders: readonly string[]): boolean {
  const want = spender.toLowerCase();
  return knownSpenders.some((item) => item.toLowerCase() === want);
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}
