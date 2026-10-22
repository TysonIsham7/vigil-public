type TabId = number;

interface ChromeStorageArea {
  get(keys?: string | string[] | Record<string, unknown> | null): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(keys: string | string[]): Promise<void>;
}

interface ChromeTab {
  id?: number;
  url?: string;
  openerTabId?: number;
}

interface RegisteredScript {
  id: string;
  js: string[];
  matches: string[];
  runAt: "document_start";
  world: "MAIN";
  allFrames: boolean;
  persistAcrossSessions: boolean;
}

interface DnrRule {
  id: number;
  priority: number;
  action: { type: string; redirect?: { extensionPath: string } };
  condition: { requestDomains?: string[]; resourceTypes?: string[] };
}

declare const chrome: {
  runtime: {
    id: string;
    getURL(path: string): string;
    sendMessage(message: unknown): Promise<unknown>;
    onMessage: {
      addListener(handler: (message: unknown, sender: { url?: string; tab?: ChromeTab }, sendResponse: (response: unknown) => void) => boolean | void): void;
    };
    onInstalled: { addListener(handler: () => void): void };
    onStartup?: { addListener(handler: () => void): void };
    getManifest(): { permissions?: string[]; host_permissions?: string[] };
    getPlatformInfo?(): Promise<{ os?: string }>;
    lastError?: { message?: string };
    connectNative?(hostName: string): {
      postMessage(message: { host: string }): void;
      disconnect(): void;
      onMessage: { addListener(handler: (message: unknown) => void): void };
      onDisconnect: { addListener(handler: () => void): void };
    };
    sendNativeMessage?(hostName: string, message: { url: string } | { host: string }): Promise<unknown>;
  };
  storage: {
    local: ChromeStorageArea;
    session?: ChromeStorageArea;
  };
  tabs: {
    getCurrent(): Promise<ChromeTab>;
    query(info: { active?: boolean; currentWindow?: boolean }): Promise<ChromeTab[]>;
    update(tabId: number, props: { url: string }): Promise<ChromeTab>;
    onRemoved: { addListener(handler: (tabId: number) => void): void };
    onUpdated?: { addListener(handler: (tabId: number, info: { status?: string }) => void): void };
  };
  webNavigation: {
    onBeforeNavigate: {
      addListener(handler: (details: { tabId: TabId; frameId: number; url: string }) => void): void;
    };
    onCommitted?: {
      addListener(handler: (details: { tabId: TabId; frameId: number; url: string }) => void): void;
    };
    onCreatedNavigationTarget?: {
      addListener(handler: (details: { tabId: TabId; sourceTabId: number; url: string }) => void): void;
    };
  };
  scripting?: {
    registerContentScripts(scripts: RegisteredScript[]): Promise<void>;
    unregisterContentScripts(filter: { ids: string[] }): Promise<void>;
    executeScript?(injection: {
      target: { tabId: number; allFrames?: boolean };
      files: string[];
      world?: "MAIN" | "ISOLATED";
    }): Promise<unknown>;
  };
  action: {
    setBadgeText?(details: { text: string; tabId?: number }): Promise<void>;
    setBadgeBackgroundColor?(details: { color: string; tabId?: number }): Promise<void>;
  };
  declarativeNetRequest?: {
    updateSessionRules(options: { removeRuleIds?: number[]; addRules?: DnrRule[] }): Promise<void>;
    getSessionRules(): Promise<DnrRule[]>;
  };
};
