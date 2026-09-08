import { describe, expect, test } from "bun:test";
import {
  GatewaySessionStore,
  MAX_GATEWAY_SESSION_MESSAGES,
} from "../src/gateway-sessions";

describe("gateway session store", () => {
  test("keeps a transcript per session and isolates sessions", () => {
    const store = new GatewaySessionStore();
    store.append("a", [{ role: "user", text: "hi" }, { role: "assistant", text: "hello" }]);
    store.append("b", [{ role: "user", text: "other" }]);

    expect(store.history("a").map(m => m.text)).toEqual(["hi", "hello"]);
    expect(store.history("b").map(m => m.text)).toEqual(["other"]);
    expect(store.history("missing")).toEqual([]);
  });

  test("ignores empty text so a failed turn does not poison the transcript", () => {
    const store = new GatewaySessionStore();
    store.append("a", [{ role: "user", text: "  " }, { role: "assistant", text: "" }]);
    expect(store.history("a")).toEqual([]);
  });

  test("bounds a long session to a recent window", () => {
    const store = new GatewaySessionStore();
    for (let index = 0; index < MAX_GATEWAY_SESSION_MESSAGES + 20; index += 1) {
      store.append("a", [{ role: "user", text: `m${index}` }]);
    }
    const history = store.history("a");
    expect(history).toHaveLength(MAX_GATEWAY_SESSION_MESSAGES);
    expect(history.at(-1)!.text).toBe(`m${MAX_GATEWAY_SESSION_MESSAGES + 19}`);
  });

  test("expires a session after its ttl", () => {
    const store = new GatewaySessionStore(1_000);
    const start = Date.parse("2026-01-01T00:00:00.000Z");
    store.append("a", [{ role: "user", text: "hi" }], start);
    expect(store.history("a", start + 500)).toHaveLength(1);
    expect(store.history("a", start + 2_000)).toEqual([]);
  });

  test("evicts the least recently used session past the cap", () => {
    const store = new GatewaySessionStore(60_000, 2);
    store.append("a", [{ role: "user", text: "a" }]);
    store.append("b", [{ role: "user", text: "b" }]);
    store.append("a", [{ role: "user", text: "a2" }]);
    store.append("c", [{ role: "user", text: "c" }]);

    expect(store.size()).toBe(2);
    expect(store.history("b")).toEqual([]);
    expect(store.history("a").map(m => m.text)).toEqual(["a", "a2"]);
    expect(store.history("c")).toHaveLength(1);
  });

  test("forget drops one session", () => {
    const store = new GatewaySessionStore();
    store.append("a", [{ role: "user", text: "hi" }]);
    expect(store.forget("a")).toBe(true);
    expect(store.forget("a")).toBe(false);
    expect(store.history("a")).toEqual([]);
  });
});
