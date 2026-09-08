import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync, readFileSync, rmSync, statSync } from "node:fs";
import { join } from "node:path";
import { atomicWriteFile, getConfigDir, stripUtf8Bom } from "./config";

/**
 * Public API tokens authenticate the optional gateway listener. They are deliberately separate
 * from `controlToken`: that one protects launcher lifecycle endpoints on loopback, while these
 * are handed to third-party clients and must be individually revocable.
 */
export const API_TOKEN_PREFIX = "cwg_";
const API_TOKEN_SECRET_BYTES = 32;
const API_TOKEN_PATTERN = /^cwg_[A-Za-z0-9_-]{43}$/;
const MAX_API_TOKENS = 64;
const MAX_TOKEN_NAME_LENGTH = 60;
/**
 * Every accepted request would otherwise rewrite the store. Persisting last-use at most once per
 * minute keeps a busy gateway from turning each turn into a synchronous disk write.
 */
const LAST_USED_PERSIST_INTERVAL_MS = 60_000;

export interface ApiTokenRecord {
  id: string;
  name: string;
  /** SHA-256 of the complete token. The plaintext is shown once at creation and never stored. */
  hash: string;
  /** Truncated form for the UI, e.g. `cwg_A1b2C3d4…WxYz`. */
  display: string;
  createdAt: string;
  lastUsedAt: string | null;
}

/** The shape handed to the launcher UI: identical to the record minus the verifier. */
export type ApiTokenSummary = Omit<ApiTokenRecord, "hash">;

interface ApiTokenStore {
  version: 1;
  tokens: ApiTokenRecord[];
}

export function apiTokenStorePath(home = getConfigDir()): string {
  return join(home, "api-tokens.json");
}

function emptyStore(): ApiTokenStore {
  return { version: 1, tokens: [] };
}

function isIsoTimestamp(value: unknown): value is string {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

function parseStore(value: unknown, path: string): ApiTokenStore {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`Invalid API token store in ${path}`);
  }
  const parsed = value as Partial<ApiTokenStore>;
  if (parsed.version !== 1) throw new Error(`Unsupported API token store version in ${path}`);
  if (!Array.isArray(parsed.tokens)) throw new Error(`Invalid API token list in ${path}`);
  const tokens = parsed.tokens.map(record => {
    if (!record || typeof record !== "object" || Array.isArray(record)) {
      throw new Error(`Invalid API token record in ${path}`);
    }
    const token = record as Partial<ApiTokenRecord>;
    if (typeof token.id !== "string" || !/^tok_[a-f0-9]{24}$/.test(token.id)) {
      throw new Error(`Invalid API token id in ${path}`);
    }
    if (typeof token.name !== "string" || !token.name.trim() || token.name.length > MAX_TOKEN_NAME_LENGTH) {
      throw new Error(`Invalid API token name in ${path}`);
    }
    if (typeof token.hash !== "string" || !/^[a-f0-9]{64}$/.test(token.hash)) {
      throw new Error(`Invalid API token verifier in ${path}`);
    }
    if (typeof token.display !== "string" || !token.display.startsWith(API_TOKEN_PREFIX)) {
      throw new Error(`Invalid API token display value in ${path}`);
    }
    if (!isIsoTimestamp(token.createdAt)) throw new Error(`Invalid API token creation time in ${path}`);
    if (token.lastUsedAt !== null && !isIsoTimestamp(token.lastUsedAt)) {
      throw new Error(`Invalid API token last-use time in ${path}`);
    }
    return {
      id: token.id,
      name: token.name,
      hash: token.hash,
      display: token.display,
      createdAt: token.createdAt,
      lastUsedAt: token.lastUsedAt ?? null,
    } satisfies ApiTokenRecord;
  });
  const ids = new Set(tokens.map(token => token.id));
  if (ids.size !== tokens.length) throw new Error(`Duplicate API token id in ${path}`);
  return { version: 1, tokens };
}

let cache: { key: string; store: ApiTokenStore } | undefined;

function cacheKey(path: string): string {
  try {
    const stats = statSync(path);
    return `${stats.mtimeMs}:${stats.size}:${stats.ino}`;
  } catch {
    return "missing";
  }
}

export function readApiTokenStore(path = apiTokenStorePath()): ApiTokenStore {
  if (!existsSync(path)) return emptyStore();
  // Verification runs on every gateway request. The store is tiny, but re-parsing it per request
  // is still pure overhead whenever the file has not changed.
  const key = `${path}\u0000${cacheKey(path)}`;
  if (cache?.key === key) return { version: 1, tokens: cache.store.tokens.map(token => ({ ...token })) };
  const store = parseStore(JSON.parse(stripUtf8Bom(readFileSync(path, "utf8"))), path);
  cache = { key, store: { version: 1, tokens: store.tokens.map(token => ({ ...token })) } };
  return store;
}

function writeApiTokenStore(store: ApiTokenStore, path = apiTokenStorePath()): void {
  atomicWriteFile(path, `${JSON.stringify(store, null, 2)}\n`);
  cache = undefined;
}

function summarize(record: ApiTokenRecord): ApiTokenSummary {
  const { hash: _hash, ...summary } = record;
  return summary;
}

export function listApiTokens(path = apiTokenStorePath()): ApiTokenSummary[] {
  return readApiTokenStore(path).tokens
    .map(summarize)
    .sort((left, right) => Date.parse(right.createdAt) - Date.parse(left.createdAt));
}

export function hashApiToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function displayForToken(token: string): string {
  const secret = token.slice(API_TOKEN_PREFIX.length);
  return `${API_TOKEN_PREFIX}${secret.slice(0, 8)}…${secret.slice(-4)}`;
}

export function normalizeApiTokenName(value: unknown): string {
  if (typeof value !== "string") throw new Error("API token name is required");
  // Control characters would corrupt the launcher list and CLI table without adding any value.
  const name = value.replace(/[\u0000-\u001f\u007f]/g, " ").trim().replace(/\s+/g, " ");
  if (!name) throw new Error("API token name is required");
  if (name.length > MAX_TOKEN_NAME_LENGTH) {
    throw new Error(`API token name must be at most ${MAX_TOKEN_NAME_LENGTH} characters`);
  }
  return name;
}

export function createApiToken(
  name: string,
  path = apiTokenStorePath(),
  now = new Date(),
): { token: string; record: ApiTokenSummary } {
  const store = readApiTokenStore(path);
  if (store.tokens.length >= MAX_API_TOKENS) {
    throw new Error(`At most ${MAX_API_TOKENS} API tokens can exist; revoke one first`);
  }
  const normalized = normalizeApiTokenName(name);
  const token = `${API_TOKEN_PREFIX}${randomBytes(API_TOKEN_SECRET_BYTES).toString("base64url")}`;
  const record: ApiTokenRecord = {
    id: `tok_${randomBytes(12).toString("hex")}`,
    name: normalized,
    hash: hashApiToken(token),
    display: displayForToken(token),
    createdAt: now.toISOString(),
    lastUsedAt: null,
  };
  writeApiTokenStore({ version: 1, tokens: [...store.tokens, record] }, path);
  return { token, record: summarize(record) };
}

export function revokeApiToken(id: string, path = apiTokenStorePath()): ApiTokenSummary {
  const store = readApiTokenStore(path);
  const record = store.tokens.find(token => token.id === id);
  if (!record) throw new Error(`API token does not exist: ${id}`);
  writeApiTokenStore({ version: 1, tokens: store.tokens.filter(token => token.id !== id) }, path);
  return summarize(record);
}

export function revokeAllApiTokens(path = apiTokenStorePath()): number {
  const store = readApiTokenStore(path);
  if (store.tokens.length === 0) return 0;
  writeApiTokenStore(emptyStore(), path);
  return store.tokens.length;
}

export function deleteApiTokenStore(path = apiTokenStorePath()): void {
  rmSync(path, { force: true });
  cache = undefined;
}

export function isApiTokenShape(value: string): boolean {
  return API_TOKEN_PATTERN.test(value);
}

/**
 * Resolve a presented token to its record without leaking which stored token was closest. The
 * comparison runs over SHA-256 digests so every candidate has the same length, and the loop always
 * visits every record.
 */
export function verifyApiToken(
  presented: string,
  path = apiTokenStorePath(),
): ApiTokenSummary | null {
  if (!isApiTokenShape(presented)) return null;
  const digest = Buffer.from(hashApiToken(presented), "hex");
  let matched: ApiTokenRecord | undefined;
  for (const record of readApiTokenStore(path).tokens) {
    const candidate = Buffer.from(record.hash, "hex");
    if (candidate.length === digest.length && timingSafeEqual(candidate, digest)) matched = record;
  }
  return matched ? summarize(matched) : null;
}

const lastPersistedUse = new Map<string, number>();

/**
 * Record that a token was accepted. Failures are swallowed on purpose: last-use is diagnostic
 * metadata, and a read-only or momentarily locked store must never fail an authorized request.
 */
export function touchApiToken(
  id: string,
  path = apiTokenStorePath(),
  now = Date.now(),
): void {
  const previous = lastPersistedUse.get(id);
  if (previous !== undefined && now - previous < LAST_USED_PERSIST_INTERVAL_MS) return;
  lastPersistedUse.set(id, now);
  try {
    const store = readApiTokenStore(path);
    const index = store.tokens.findIndex(token => token.id === id);
    if (index < 0) return;
    const tokens = [...store.tokens];
    tokens[index] = { ...tokens[index]!, lastUsedAt: new Date(now).toISOString() };
    writeApiTokenStore({ version: 1, tokens }, path);
  } catch {
    // Diagnostics only; the caller has already been authorized.
  }
}

/** Test seam: drop cached parse results and last-use throttling between cases. */
export function resetApiTokenCaches(): void {
  cache = undefined;
  lastPersistedUse.clear();
}
