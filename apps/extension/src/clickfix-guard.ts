import { classifyClickFix, clickFixCopy, type ClickFixKind } from "@vigil/core/clickfix";
import { chooseGuard, claimGuard } from "./guard-panel.js";

/** Hooks page clipboard writes. A person's own selection copy is left alone unless the page sets the data. */
export function installClickFixGuard(scope: Window): void {
  if (!claimGuard(scope, "vigilClickFix")) return;
  let release = false;
  const ask = (kind: ClickFixKind, text: string) => chooseGuard({
    ...clickFixCopy(kind),
    allowLabel: "Copy anyway",
    blockLabel: "Don't copy",
    detail: preview(text),
  });
  const copyAllowed = (text: string) => {
    const clipboard = scope.navigator.clipboard;
    if (!clipboard?.writeText) return;
    release = true;
    void clipboard.writeText(text);
  };

  const realm = scope as unknown as {
    Clipboard?: { prototype: Clipboard & { writeText?: (data: string) => Promise<void>; write?: (items: ClipboardItem[]) => Promise<void> } };
    DataTransfer?: { prototype: DataTransfer };
    Document?: { prototype: Document };
  };
  const clipboardProto = realm.Clipboard?.prototype;
  if (clipboardProto && typeof clipboardProto.writeText === "function") {
    const orig = clipboardProto.writeText;
    clipboardProto.writeText = function (data: string) {
      const text = String(data);
      if (release) {
        release = false;
        return orig.call(this, text);
      }
      const result = classifyClickFix(text);
      if (!result.risky || !result.kind) return orig.call(this, text);
      const kind = result.kind;
      return ask(kind, text).then((choice) => {
        if (!choice.ok) return Promise.reject(held());
        release = false;
        return orig.call(this, text);
      });
    };
  }
  if (clipboardProto && typeof clipboardProto.write === "function") {
    const orig = clipboardProto.write;
    clipboardProto.write = function (items: ClipboardItem[]) {
      if (release) {
        release = false;
        return orig.call(this, items);
      }
      return textFrom(items).then((text) => {
        const result = text ? classifyClickFix(text) : { risky: false, kind: null };
        if (!result.risky || !result.kind) return orig.call(this, items);
        const kind = result.kind;
        return ask(kind, text).then((choice) => {
          if (!choice.ok) return Promise.reject(held());
          release = false;
          return orig.call(this, items);
        });
      }, () => Promise.reject(held()));
    };
  }

  const transfer = realm.DataTransfer?.prototype;
  if (transfer && typeof transfer.setData === "function") {
    const orig = transfer.setData;
    transfer.setData = function (format: string, data: string) {
      const type = String(format).toLowerCase();
      const text = String(data);
      if (!release && (type === "text" || type.startsWith("text/"))) {
        const result = classifyClickFix(text);
        if (result.risky && result.kind) {
          const kind = result.kind;
          void ask(kind, text).then((choice) => {
            if (choice.ok) copyAllowed(text);
          });
          return orig.call(this, format, "");
        }
      }
      return orig.call(this, format, data);
    };
  }

  const documents = realm.Document?.prototype;
  if (documents && typeof documents.execCommand === "function") {
    const orig = documents.execCommand;
    documents.execCommand = function (commandId: string, showUI?: boolean, value?: string) {
      if (String(commandId).toLowerCase() !== "copy") return orig.call(this, commandId, showUI, value);
      const selected = String(scope.getSelection?.() ?? "");
      const result = classifyClickFix(selected);
      if (!result.risky || !result.kind) return orig.call(this, commandId, showUI, value);
      const kind = result.kind;
      void ask(kind, selected).then((choice) => {
        if (choice.ok) copyAllowed(selected);
      });
      return false;
    };
  }
}

function preview(text: string): string {
  const flat = text.replace(/\s+/g, " ").trim();
  return flat.length > 160 ? `${flat.slice(0, 160)}…` : flat;
}

function held(): Error {
  const error = new Error("Vigil held a clipboard write");
  error.name = "NotAllowedError";
  return error;
}

async function textFrom(items: ClipboardItem[]): Promise<string> {
  const parts: string[] = [];
  for (const item of items) {
    for (const type of item.types) {
      if (!type.startsWith("text/")) continue;
      const blob = await item.getType(type);
      parts.push(await blob.text());
    }
  }
  return parts.join("\n");
}
