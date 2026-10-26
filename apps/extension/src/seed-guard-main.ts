import { installSeedGuard } from "./seed-guard.js";

installSeedGuard(globalThis as unknown as Window);
