import { afterEach, beforeEach, describe, expect, mock, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { answerImageUrls } from "../src/adapters/chatgpt-web/answer-images";
import { GatewayFileStore, gatewayFileSigningKey, verifyGatewayFileUrl } from "../src/gateway-files";

let root: string;
let store: GatewayFileStore;
const key = gatewayFileSigningKey("control-token-example");

const png = (byte: number) => Buffer.from([137, 80, 78, 71, byte]).toString("base64");

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "codex-web-gpt-answer-images-"));
  store = new GatewayFileStore(join(root, "files"));
});
afterEach(() => {
  rmSync(root, { recursive: true, force: true });
  mock.restore();
});

/** Load the module with the launcher fetch replaced, so no browser or launcher is required. */
async function withFetchedContent(
  responder: (url: string) => Promise<{ contentType: string; base64: string; bytes: number }>,
) {
  mock.module("../src/launcher-browser-host", () => ({
    fetchLauncherChatGptContent: (_descriptor: string, url: string) => responder(url),
  }));
  return import("../src/adapters/chatgpt-web/answer-images");
}

describe("answer image detection", () => {
  test("finds every picture and ignores non-image links", () => {
    const markdown = "![a](https://chatgpt.com/backend-api/x?id=1)\n\n"
      + "[not an image](https://example.com/page)\n\n"
      + "![b](https://chatgpt.com/backend-api/x?id=2)";
    expect(answerImageUrls(markdown)).toEqual([
      "https://chatgpt.com/backend-api/x?id=1",
      "https://chatgpt.com/backend-api/x?id=2",
    ]);
  });

  test("deduplicates a picture referenced twice", () => {
    const url = "https://chatgpt.com/backend-api/x?id=1";
    expect(answerImageUrls(`![a](${url})\n\n![again](${url})`)).toEqual([url]);
  });
});

describe("downloading answer images", () => {
  test("stores every picture and rewrites each link to a signed one", async () => {
    const { downloadAnswerImages } = await withFetchedContent(async url => ({
      contentType: "image/png",
      base64: png(url.endsWith("1") ? 1 : 2),
      bytes: 5,
    }));
    const markdown = "Hai ảnh:\n\n![one](https://chatgpt.com/backend-api/x?id=1)\n\n"
      + "![two](https://chatgpt.com/backend-api/x?id=2)";

    const result = await downloadAnswerImages(markdown, {
      descriptorPath: "/tmp/descriptor.json",
      signingKey: key,
      store,
    });

    expect(result.images).toHaveLength(2);
    expect(result.failed).toBe(0);
    expect(result.markdown).not.toContain("chatgpt.com");
    // Alt text and ordering survive the rewrite.
    expect(result.markdown).toContain("![one](/v1/files/");
    expect(result.markdown).toContain("![two](/v1/files/");

    for (const image of result.images) {
      const url = new URL(`http://127.0.0.1${image.url}`);
      const id = url.pathname.slice("/v1/files/".length);
      expect(verifyGatewayFileUrl(id, url.searchParams.get("exp"), url.searchParams.get("sig"), key))
        .toEqual({ ok: true });
      expect(store.read(id)?.contentType).toBe("image/png");
      expect(image.contentType).toBe("image/png");
    }
    // Two distinct pictures must not collapse onto one stored file.
    expect(new Set(result.images.map(image => image.url)).size).toBe(2);
  });

  test("keeps the original link for a picture that cannot be fetched", async () => {
    const { downloadAnswerImages } = await withFetchedContent(async url => {
      if (url.endsWith("2")) throw new Error("gone");
      return { contentType: "image/png", base64: png(1), bytes: 5 };
    });
    const markdown = "![one](https://chatgpt.com/backend-api/x?id=1)\n\n"
      + "![two](https://chatgpt.com/backend-api/x?id=2)";

    const result = await downloadAnswerImages(markdown, {
      descriptorPath: "/tmp/descriptor.json",
      signingKey: key,
      store,
    });

    // One failure must not discard an answer that already exists.
    expect(result.images).toHaveLength(1);
    expect(result.failed).toBe(1);
    expect(result.markdown).toContain("![one](/v1/files/");
    expect(result.markdown).toContain("![two](https://chatgpt.com/backend-api/x?id=2)");
  });

  test("refuses content that is not a supported image type", async () => {
    const { downloadAnswerImages } = await withFetchedContent(async () => ({
      contentType: "text/html",
      base64: Buffer.from("<html>").toString("base64"),
      bytes: 6,
    }));

    const result = await downloadAnswerImages("![a](https://chatgpt.com/backend-api/x?id=1)", {
      descriptorPath: "/tmp/descriptor.json",
      signingKey: key,
      store,
    });
    expect(result.images).toEqual([]);
    expect(result.failed).toBe(1);
  });

  test("an answer without pictures is returned untouched", async () => {
    const { downloadAnswerImages } = await withFetchedContent(async () => {
      throw new Error("must not fetch");
    });
    const result = await downloadAnswerImages("just text", {
      descriptorPath: "/tmp/descriptor.json",
      signingKey: key,
      store,
    });
    expect(result).toEqual({ markdown: "just text", images: [], failed: 0 });
  });
});
