import { fetchLauncherChatGptContent } from "../../launcher-browser-host";
import {
  GatewayFileStore,
  GATEWAY_FILE_URL_TTL_MS,
  MAX_GATEWAY_FILE_BYTES,
  signGatewayFileUrl,
} from "../../gateway-files";

/**
 * Copy the pictures out of a completed answer and rewrite the answer to point at local links.
 *
 * ChatGPT serves a generated image from its own content endpoint, which answers 403 without the
 * browser session. The link is therefore useless to an API caller. The bytes are fetched through
 * the launcher's authenticated browser context, stored locally, and the answer's Markdown is
 * rewritten to a signed gateway link that any client can follow.
 */
const MARKDOWN_IMAGE = /!\[([^\]]*)\]\((https:\/\/[^)\s]+)\)/g;

export interface AnswerImageRewrite {
  markdown: string;
  downloaded: number;
  failed: number;
}

export function answerImageUrls(markdown: string): string[] {
  return [...new Set([...markdown.matchAll(MARKDOWN_IMAGE)].map(match => match[2]!))];
}

function contentTypeOf(value: string | null | undefined): string | undefined {
  const type = value?.split(";")[0]?.trim().toLowerCase();
  return type && ["image/png", "image/jpeg", "image/webp", "image/gif"].includes(type) ? type : undefined;
}

/**
 * Fetch every image the answer references through the launcher, whose browser session can read
 * them. All of them are fetched, since one prompt can produce several pictures.
 */
export async function downloadAnswerImages(
  markdown: string,
  options: {
    descriptorPath: string;
    signingKey: string;
    store?: GatewayFileStore;
    now?: () => number;
    abortSignal?: AbortSignal;
  },
): Promise<AnswerImageRewrite> {
  const urls = answerImageUrls(markdown);
  if (urls.length === 0) return { markdown, downloaded: 0, failed: 0 };
  const store = options.store ?? new GatewayFileStore();
  const now = options.now ?? Date.now;
  const replacements = new Map<string, string>();
  let failed = 0;

  for (const url of urls) {
    try {
      // The daemon cannot fetch this itself: the ChatGPT session lives in the launcher's private
      // browser partition, and a second CDP connection contends with the turn's own helper.
      const content = await fetchLauncherChatGptContent(options.descriptorPath, url, options.abortSignal);
      const contentType = contentTypeOf(content.contentType);
      if (!contentType) throw new Error("A generated image was not served as a supported image type");
      const bytes = Buffer.from(content.base64, "base64");
      if (bytes.byteLength > MAX_GATEWAY_FILE_BYTES) throw new Error("A generated image exceeds the local file limit");
      const stored = store.store(new Uint8Array(bytes), contentType, now());
      replacements.set(url, signGatewayFileUrl(stored.id, options.signingKey, now() + GATEWAY_FILE_URL_TTL_MS).path);
    } catch (error) {
      // One unreachable picture must not fail a turn that already produced an answer. The original
      // link is left in place so the caller can still see what was generated.
      failed += 1;
      console.warn(
        `[chatgpt-web] a generated image could not be downloaded: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  const rewritten = markdown.replace(MARKDOWN_IMAGE, (original, alt: string, url: string) => {
    const replacement = replacements.get(url);
    return replacement ? `![${alt}](${replacement})` : original;
  });
  return { markdown: rewritten, downloaded: replacements.size, failed };
}
