import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  GatewayFileStore,
  gatewayFileSigningKey,
  isGatewayFileId,
  MAX_GATEWAY_FILE_BYTES,
  signGatewayFileUrl,
  verifyGatewayFileUrl,
} from "../src/gateway-files";

let root: string;
let store: GatewayFileStore;
const key = gatewayFileSigningKey("control-token-example");

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "codex-web-gpt-files-"));
  store = new GatewayFileStore(join(root, "files"));
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

describe("gateway file store", () => {
  test("stores and reads bytes back with their type", () => {
    const bytes = new Uint8Array([137, 80, 78, 71, 1, 2, 3]);
    const stored = store.store(bytes, "image/png");

    expect(isGatewayFileId(stored.id)).toBe(true);
    expect(stored.bytes).toBe(bytes.byteLength);
    const read = store.read(stored.id);
    expect(read?.contentType).toBe("image/png");
    expect([...read!.bytes]).toEqual([...bytes]);
  });

  test("writes with owner-only permissions", () => {
    const stored = store.store(new Uint8Array([1, 2, 3]), "image/png");
    if (process.platform === "win32") return;
    expect(statSync(join(root, "files", `${stored.id}.png`)).mode & 0o777).toBe(0o600);
  });

  test("rejects an empty or oversized file", () => {
    expect(() => store.store(new Uint8Array(), "image/png")).toThrow(/must not be empty/);
    expect(() => store.store(new Uint8Array(MAX_GATEWAY_FILE_BYTES + 1), "image/png")).toThrow(/at most/);
  });

  test("unknown or malformed ids read as missing", () => {
    expect(store.read("file_" + "0".repeat(32))).toBeUndefined();
    expect(store.read("../../etc/passwd")).toBeUndefined();
    expect(store.read("nope")).toBeUndefined();
  });

  test("expires files older than the ttl", () => {
    const short = new GatewayFileStore(join(root, "ttl"), 1_000, 500);
    const stored = short.store(new Uint8Array([1]), "image/png");
    expect(short.read(stored.id)).toBeDefined();
    // A later write prunes everything already past the ttl, including this entry.
    short.store(new Uint8Array([2]), "image/png", Date.now() + 5_000);
    expect(short.read(stored.id)).toBeUndefined();
  });

  test("bounds the store to its file cap", () => {
    const bounded = new GatewayFileStore(join(root, "cap"), 60_000, 2);
    const first = bounded.store(new Uint8Array([1]), "image/png");
    bounded.store(new Uint8Array([2]), "image/png");
    bounded.store(new Uint8Array([3]), "image/png");
    expect(bounded.read(first.id)).toBeUndefined();
  });
});

describe("signed file links", () => {
  const id = `file_${"a".repeat(32)}`;
  const now = Date.parse("2026-01-01T00:00:00.000Z");

  test("accepts a link it signed and rejects every alteration", () => {
    const { path } = signGatewayFileUrl(id, key, now + 60_000);
    const url = new URL(`http://127.0.0.1${path}`);
    const exp = url.searchParams.get("exp");
    const sig = url.searchParams.get("sig");

    expect(verifyGatewayFileUrl(id, exp, sig, key, now)).toEqual({ ok: true });
    // A different file, a stretched expiry, a wrong key, or a missing signature must all fail.
    expect(verifyGatewayFileUrl(`file_${"b".repeat(32)}`, exp, sig, key, now).ok).toBe(false);
    expect(verifyGatewayFileUrl(id, String(Number(exp) + 3_600), sig, key, now).ok).toBe(false);
    expect(verifyGatewayFileUrl(id, exp, sig, gatewayFileSigningKey("other"), now).ok).toBe(false);
    expect(verifyGatewayFileUrl(id, exp, null, key, now).ok).toBe(false);
    expect(verifyGatewayFileUrl(id, exp, "zz", key, now).ok).toBe(false);
  });

  test("expires", () => {
    const { path } = signGatewayFileUrl(id, key, now + 60_000);
    const url = new URL(`http://127.0.0.1${path}`);
    expect(verifyGatewayFileUrl(id, url.searchParams.get("exp"), url.searchParams.get("sig"), key, now + 61_000))
      .toEqual({ ok: false, reason: "expired" });
  });

  test("a rotated control token invalidates outstanding links", () => {
    expect(gatewayFileSigningKey("a")).not.toBe(gatewayFileSigningKey("b"));
  });
});
