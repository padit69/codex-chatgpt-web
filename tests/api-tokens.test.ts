import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  API_TOKEN_PREFIX,
  createApiToken,
  hashApiToken,
  isApiTokenShape,
  listApiTokens,
  normalizeApiTokenName,
  resetApiTokenCaches,
  revokeAllApiTokens,
  revokeApiToken,
  touchApiToken,
  verifyApiToken,
} from "../src/api-tokens";

let home: string;
let store: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "codex-web-gpt-tokens-"));
  store = join(home, "api-tokens.json");
  resetApiTokenCaches();
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  resetApiTokenCaches();
});

describe("API token store", () => {
  test("issues a prefixed token and stores only its digest", () => {
    const { token, record } = createApiToken("laptop", store);

    expect(isApiTokenShape(token)).toBe(true);
    expect(token.startsWith(API_TOKEN_PREFIX)).toBe(true);
    expect(record.name).toBe("laptop");
    expect(record.lastUsedAt).toBeNull();

    const raw = readFileSync(store, "utf8");
    expect(raw).not.toContain(token);
    expect(raw).toContain(hashApiToken(token));
    // The truncated display value must never be enough to reconstruct the secret.
    expect(record.display.length).toBeLessThan(token.length);
  });

  test("writes the store with owner-only permissions", () => {
    createApiToken("laptop", store);
    if (process.platform === "win32") return;
    expect(statSync(store).mode & 0o777).toBe(0o600);
  });

  test("verifies a valid token and rejects everything else", () => {
    const { token, record } = createApiToken("ci", store);

    expect(verifyApiToken(token, store)?.id).toBe(record.id);
    expect(verifyApiToken(`${token}x`, store)).toBeNull();
    expect(verifyApiToken(token.slice(0, -1), store)).toBeNull();
    expect(verifyApiToken("not-a-token", store)).toBeNull();
    expect(verifyApiToken("", store)).toBeNull();
    // A digest is not a credential: presenting the stored verifier must not authenticate.
    expect(verifyApiToken(record.display, store)).toBeNull();
  });

  test("separates tokens so revoking one keeps the others valid", () => {
    const first = createApiToken("first", store);
    const second = createApiToken("second", store);

    revokeApiToken(first.record.id, store);

    expect(verifyApiToken(first.token, store)).toBeNull();
    expect(verifyApiToken(second.token, store)?.id).toBe(second.record.id);
    expect(listApiTokens(store).map(token => token.id)).toEqual([second.record.id]);
  });

  test("revoke-all empties the store", () => {
    const first = createApiToken("first", store);
    createApiToken("second", store);

    expect(revokeAllApiTokens(store)).toBe(2);
    expect(listApiTokens(store)).toEqual([]);
    expect(verifyApiToken(first.token, store)).toBeNull();
  });

  test("rejects revoking an unknown id", () => {
    expect(() => revokeApiToken("tok_000000000000000000000000", store)).toThrow(/does not exist/);
  });

  test("records last use and throttles repeated writes", () => {
    const { token, record } = createApiToken("throttled", store);
    const start = Date.parse("2026-01-01T00:00:00.000Z");

    touchApiToken(record.id, store, start);
    expect(listApiTokens(store)[0]!.lastUsedAt).toBe(new Date(start).toISOString());

    // A second use one second later must not rewrite the file.
    touchApiToken(record.id, store, start + 1_000);
    expect(listApiTokens(store)[0]!.lastUsedAt).toBe(new Date(start).toISOString());

    touchApiToken(record.id, store, start + 61_000);
    expect(listApiTokens(store)[0]!.lastUsedAt).toBe(new Date(start + 61_000).toISOString());

    // Recording use must never invalidate the credential.
    expect(verifyApiToken(token, store)?.id).toBe(record.id);
  });

  test("normalizes names and rejects empty or oversized ones", () => {
    expect(normalizeApiTokenName("  my   laptop \n")).toBe("my laptop");
    expect(normalizeApiTokenName("tab\there")).toBe("tab here");
    expect(() => normalizeApiTokenName("   ")).toThrow(/required/);
    expect(() => normalizeApiTokenName(42)).toThrow(/required/);
    expect(() => normalizeApiTokenName("x".repeat(61))).toThrow(/at most/);
  });

  test("an empty or missing store authenticates nobody", () => {
    expect(listApiTokens(store)).toEqual([]);
    expect(verifyApiToken(`${API_TOKEN_PREFIX}${"a".repeat(43)}`, store)).toBeNull();
  });

  test("refuses a corrupted store instead of silently accepting requests", () => {
    writeFileSync(store, JSON.stringify({ version: 1, tokens: [{ id: "nope" }] }));
    expect(() => listApiTokens(store)).toThrow(/Invalid API token id/);

    writeFileSync(store, JSON.stringify({ version: 2, tokens: [] }));
    expect(() => listApiTokens(store)).toThrow(/Unsupported API token store version/);
  });

  test("picks up tokens created after the store was cached", () => {
    expect(listApiTokens(store)).toEqual([]);
    const { token } = createApiToken("later", store);
    expect(verifyApiToken(token, store)).not.toBeNull();
  });
});
