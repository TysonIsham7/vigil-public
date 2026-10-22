import { installBlankGuard, type GuardWindow } from "./blank-guard.js";

const scope = globalThis as unknown as GuardWindow;
if (typeof scope.open === "function") installBlankGuard(scope);
