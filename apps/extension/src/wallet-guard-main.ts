import { installWalletGuard } from "./wallet-guard.js";

installWalletGuard(globalThis as unknown as Window);