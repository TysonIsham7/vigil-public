import { beforeEach, describe, expect, it, vi } from "vitest";
import { installClickFixGuard } from "../src/clickfix-guard.js";
import { installWalletGuard } from "../src/wallet-guard.js";

const answers = vi.hoisted(() => ({ queue: [] as { ok: boolean; remember: boolean }[] }));

vi.mock("../src/guard-panel.js", () => ({
  claimGuard: () => true,
  chooseGuard: () => Promise.resolve(answers.queue.shift() ?? { ok: false, remember: false }),
}));

const RISKY = "cmd /c calc";

beforeEach(() => {
  answers.queue.length = 0;
});

describe("clickfix clipboard hook", () => {
  it("checks the next write after one copy is allowed", async () => {
    answers.queue.push({ ok: true, remember: false }, { ok: false, remember: false });
    const written: string[] = [];
    class Clipboard {
      writeText(data: string): Promise<void> {
        written.push(data);
        return Promise.resolve();
      }
    }
    const scope = { navigator: { clipboard: new Clipboard() }, Clipboard } as unknown as Window;
    installClickFixGuard(scope);
    await Clipboard.prototype.writeText(RISKY);
    await expect(Clipboard.prototype.writeText(RISKY)).rejects.toThrow(/held/);
    expect(written).toEqual([RISKY]);
  });

  it("does not write when a clipboard item cannot be read", async () => {
    const writes: unknown[] = [];
    class Clipboard {
      writeText(): Promise<void> {
        return Promise.resolve();
      }

      write(items: unknown[]): Promise<void> {
        writes.push(items);
        return Promise.resolve();
      }
    }
    const scope = { navigator: { clipboard: new Clipboard() }, Clipboard } as unknown as Window;
    installClickFixGuard(scope);
    const item = {
      types: ["text/plain"],
      getType: () => Promise.reject(new Error("read failed")),
    };
    await expect(Clipboard.prototype.write([item] as never)).rejects.toThrow(/held/);
    expect(writes).toHaveLength(0);
  });

  it("classifies every text clipboard type", async () => {
    answers.queue.push({ ok: false, remember: false });
    const copies: { format: string; data: string }[] = [];
    class Clipboard {
      writeText(): Promise<void> {
        return Promise.resolve();
      }
    }
    class DataTransfer {
      setData(format: string, data: string): void {
        copies.push({ format, data });
      }
    }
    const scope = { navigator: { clipboard: new Clipboard() }, Clipboard, DataTransfer } as unknown as Window;
    installClickFixGuard(scope);
    new DataTransfer().setData("text/html", RISKY);
    expect(copies).toEqual([{ format: "text/html", data: "" }]);
  });
});

describe("wallet hook", () => {
  it("retries a provider whose request could not be replaced", async () => {
    const listeners: { type: string; fn: (event: { detail?: { provider?: unknown } }) => void }[] = [];
    let current: (args: unknown) => Promise<unknown> = () => Promise.resolve("raw");
    let locked = true;
    const provider: { request?: (args: unknown) => Promise<unknown> } = {};
    Object.defineProperty(provider, "request", {
      configurable: true,
      enumerable: true,
      get: () => current,
      set: (value: (args: unknown) => Promise<unknown>) => {
        if (locked) throw new Error("cannot replace");
        current = value;
      },
    });
    const scope = {
      ethereum: provider,
      setInterval: () => 1,
      clearInterval: () => undefined,
      setTimeout: () => 1,
      addEventListener: (type: string, fn: (event: { detail?: { provider?: unknown } }) => void) => {
        listeners.push({ type, fn });
      },
      dispatchEvent: () => true,
    } as unknown as Window;
    installWalletGuard(scope);
    await expect(provider.request?.({ method: "eth_sign" })).resolves.toBe("raw");
    locked = false;
    listeners.find((item) => item.type === "eip6963:announceProvider")?.fn({ detail: { provider } });
    answers.queue.push({ ok: false, remember: false });
    await expect(provider.request?.({ method: "eth_sign" })).rejects.toThrow(/rejected/);
  });
});
