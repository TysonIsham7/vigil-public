import { findSeedPhrase, seedGuardCopy } from "@vigil/core/seed-phrase";
import { chooseGuard, claimGuard } from "./guard-panel.js";

/** Holds a checksum-valid recovery phrase before the page receives it. The words are not sent anywhere. */
export function installSeedGuard(scope: Window): void {
  if (!claimGuard(scope, "vigilSeed")) return;
  let pasteSeen = false;
  let suppress = false;
  let holding = false;

  const ask = (count: number, apply: () => void) => {
    if (holding) return;
    holding = true;
    void chooseGuard({
      ...seedGuardCopy(count),
      allowLabel: "Enter it here",
      blockLabel: "Keep it out",
    }).then((choice) => {
      holding = false;
      if (!choice.ok) return;
      suppress = true;
      try {
        apply();
      } finally {
        suppress = false;
      }
    });
  };

  scope.addEventListener("paste", (event) => {
    const text = event.clipboardData?.getData("text/plain") ?? "";
    const next = project(event.target, text);
    const found = findSeedPhrase(text) ?? findSeedPhrase(next);
    if (!found) return;
    pasteSeen = true;
    queueMicrotask(() => {
      pasteSeen = false;
    });
    event.preventDefault();
    event.stopImmediatePropagation();
    const target = event.target;
    ask(found.count, () => commit(target, next));
  }, true);

  scope.addEventListener("beforeinput", (event) => {
    if (pasteSeen || suppress) return;
    const input = event as InputEvent;
    if (input.inputType === "insertFromPaste" || input.inputType === "insertFromPasteAsQuotation") return;
    if (input.data == null) return;
    const next = project(input.target, input.data);
    const found = findSeedPhrase(next);
    if (!found) return;
    input.preventDefault();
    input.stopImmediatePropagation();
    const target = input.target;
    ask(found.count, () => commit(target, next));
  }, true);

  scope.addEventListener("input", (event) => {
    if (suppress || holding) return;
    const target = event.target;
    if (!target || typeof target !== "object" || !("value" in target)) return;
    const field = target as HTMLInputElement;
    if (typeof field.value !== "string") return;
    const found = findSeedPhrase(field.value);
    if (!found) return;
    const value = field.value;
    field.value = "";
    ask(found.count, () => {
      field.value = value;
      field.dispatchEvent(new Event("input", { bubbles: true }));
    });
  }, true);
}

function project(target: EventTarget | null, data: string): string {
  if (target && typeof target === "object" && "value" in target && typeof (target as HTMLInputElement).value === "string") {
    const field = target as HTMLInputElement;
    const start = field.selectionStart ?? field.value.length;
    const end = field.selectionEnd ?? field.value.length;
    return field.value.slice(0, start) + data + field.value.slice(end);
  }
  if (target && typeof target === "object" && "isContentEditable" in target && (target as HTMLElement).isContentEditable) {
    return `${(target as HTMLElement).textContent ?? ""}${data}`;
  }
  return data;
}

function commit(target: EventTarget | null, value: string): void {
  if (!target || typeof target !== "object") return;
  if ("value" in target && typeof (target as HTMLInputElement).value === "string") {
    const field = target as HTMLInputElement;
    field.value = value;
    field.dispatchEvent(new Event("input", { bubbles: true }));
    return;
  }
  if ("isContentEditable" in target && (target as HTMLElement).isContentEditable) {
    const field = target as HTMLElement;
    field.textContent = value;
    field.dispatchEvent(new Event("input", { bubbles: true }));
  }
}
