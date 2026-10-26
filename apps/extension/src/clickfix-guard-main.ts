import { installClickFixGuard } from "./clickfix-guard.js";

installClickFixGuard(globalThis as unknown as Window);
