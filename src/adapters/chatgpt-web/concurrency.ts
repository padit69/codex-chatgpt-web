/**
 * ChatGPT Web concurrency is deliberately bounded. Every active Codex turn owns a real
 * browser document in the signed-in account, so unbounded fan-out would create account-level
 * traffic that is indistinguishable from spam.
 */
export const DEFAULT_MAX_CHATGPT_BROWSER_TABS = 5;
/**
 * Upper bound for the configurable cap. Each tab is a full ChatGPT document in a real browser, so
 * the ceiling protects memory as much as it protects the account from spam-shaped traffic.
 */
export const MAX_CHATGPT_BROWSER_TABS_LIMIT = 20;

// One daemon serves one configuration, and the two enforcement points (the worker and the session
// registry) have no shared config handle, so the resolved cap lives here and is set once at
// adapter construction.
let configuredMaxBrowserTabs = DEFAULT_MAX_CHATGPT_BROWSER_TABS;

export function resolveMaxChatGptBrowserTabs(value: unknown): number {
  if (value === undefined) return DEFAULT_MAX_CHATGPT_BROWSER_TABS;
  if (!Number.isInteger(value) || (value as number) < 1 || (value as number) > MAX_CHATGPT_BROWSER_TABS_LIMIT) {
    throw new Error(
      `Simultaneous ChatGPT browser turns must be an integer between 1 and ${MAX_CHATGPT_BROWSER_TABS_LIMIT}`,
    );
  }
  return value as number;
}

export function configureMaxChatGptBrowserTabs(value: unknown): void {
  configuredMaxBrowserTabs = resolveMaxChatGptBrowserTabs(value);
}

export function maxChatGptBrowserTabs(): number {
  return configuredMaxBrowserTabs;
}
