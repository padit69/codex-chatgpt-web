import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createApiToken, resetApiTokenCaches } from "../src/api-tokens";
import type { AppConfig } from "../src/config";
import {
  gatewayTurnIdentity,
  normalizeGatewayRequest,
  presentedGatewayToken,
  sanitizedUpstreamHeaders,
  startApiGateway,
  type ApiGatewayServer,
} from "../src/gateway";

let home: string;
let store: string;
let gateway: ApiGatewayServer | undefined;
let token: string;
/** Every request the injected Responses handler observed, for capability assertions. */
let observed: Array<{ headers: Headers; body: string }>;

function config(overrides: Partial<AppConfig> = {}): AppConfig {
  return {
    host: "127.0.0.1",
    // The gateway binds an ephemeral port; the Responses port only has to be a different value.
    port: 17841,
    solAvailable: true,
    proAvailable: false,
    experimentalBiggerContext: false,
    browserInteractionMode: "automatic",
    zeroRiskProEnabled: false,
    gateway: { enabled: true, port: 0 },
    ...overrides,
  } as AppConfig;
}

/** A stand-in for the Responses pipeline that records what the gateway forwarded. */
async function recordingHandler(req: Request): Promise<Response> {
  const body = await req.text();
  observed.push({ headers: new Headers(req.headers), body });
  return Response.json({ ok: true, echoed: JSON.parse(body) });
}

function start(handler = recordingHandler, overrides: Partial<AppConfig> = {}): string {
  gateway = startApiGateway(config(overrides), { handleResponses: handler, tokenStorePath: store });
  if (!gateway) throw new Error("gateway did not start");
  return `http://127.0.0.1:${gateway.port}`;
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "codex-web-gpt-gateway-"));
  store = join(home, "api-tokens.json");
  observed = [];
  resetApiTokenCaches();
  token = createApiToken("test", store).token;
});

afterEach(async () => {
  await gateway?.stop(true);
  gateway = undefined;
  rmSync(home, { recursive: true, force: true });
  resetApiTokenCaches();
});

describe("API gateway authentication", () => {
  test("stays disabled unless the configuration enables it", () => {
    const disabled = startApiGateway(config({ gateway: { enabled: false, port: 0 } }), {
      handleResponses: recordingHandler,
      tokenStorePath: store,
    });
    expect(disabled).toBeUndefined();
  });

  test("refuses to share the Responses port", () => {
    expect(() => startApiGateway(config({ port: 17999, gateway: { enabled: true, port: 17999 } }), {
      handleResponses: recordingHandler,
      tokenStorePath: store,
    })).toThrow(/must differ/);
  });

  test("rejects a missing, malformed, or unknown token", async () => {
    const base = start();

    const rejected: Array<Record<string, string> | undefined> = [
      undefined,
      { authorization: "Bearer wrong" },
      { authorization: "Basic abc" },
      { "x-api-key": "nope" },
    ];
    for (const headers of rejected) {
      const response = await fetch(`${base}/v1/models`, { headers });
      expect(response.status).toBe(401);
      expect(response.headers.get("www-authenticate")).toContain("Bearer");
      await response.text();
    }
    expect(observed).toEqual([]);
  });

  test("accepts the token through Authorization and x-api-key", async () => {
    const base = start();

    const bearer = await fetch(`${base}/v1/models`, { headers: { authorization: `Bearer ${token}` } });
    expect(bearer.status).toBe(200);
    await bearer.text();

    const apiKey = await fetch(`${base}/v1/models`, { headers: { "x-api-key": token } });
    expect(apiKey.status).toBe(200);
    await apiKey.text();
  });

  test("serves the liveness probe without a token but leaks no account detail", async () => {
    const base = start();
    const response = await fetch(`${base}/healthz`);
    const payload = await response.json() as Record<string, unknown>;

    expect(response.status).toBe(200);
    expect(payload.status).toBe("ok");
    expect(Object.keys(payload).sort()).toEqual(["service", "status", "version"]);
  });

  test("answers CORS preflight without a token", async () => {
    const base = start();
    const response = await fetch(`${base}/v1/responses`, { method: "OPTIONS" });

    expect(response.status).toBe(204);
    expect(response.headers.get("access-control-allow-headers")).toContain("authorization");
  });

  test("a revoked token stops working without restarting the listener", async () => {
    const base = start();
    const second = createApiToken("second", store);

    const before = await fetch(`${base}/v1/models`, { headers: { authorization: `Bearer ${second.token}` } });
    expect(before.status).toBe(200);
    await before.text();

    const { revokeApiToken } = await import("../src/api-tokens");
    revokeApiToken(second.record.id, store);

    const after = await fetch(`${base}/v1/models`, { headers: { authorization: `Bearer ${second.token}` } });
    expect(after.status).toBe(401);
    await after.text();
  });
});

describe("API gateway routing", () => {
  test("lists only routed ChatGPT Web models", async () => {
    const base = start();
    const response = await fetch(`${base}/v1/models`, { headers: { authorization: `Bearer ${token}` } });
    const payload = await response.json() as { data: Array<{ id: string; context_window: number }> };

    expect(payload.data.length).toBeGreaterThan(0);
    for (const model of payload.data) {
      expect(model.id.startsWith("chatgpt-web/")).toBe(true);
      expect(model.context_window).toBeGreaterThan(0);
    }
    // Pro is account-gated and must not be advertised to a non-Pro account.
    expect(payload.data.some(model => model.id === "chatgpt-web/pro")).toBe(false);
  });

  test("refuses a native model instead of proxying it upstream", async () => {
    const base = start();
    const response = await fetch(`${base}/v1/responses`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ model: "gpt-5.6-sol", input: "hi" }),
    });

    expect(response.status).toBe(400);
    expect(await response.text()).toContain("chatgpt-web/");
    expect(observed).toEqual([]);
  });

  test("refuses a routed model the account cannot use", async () => {
    const base = start();
    const response = await fetch(`${base}/v1/responses`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ model: "chatgpt-web/pro", input: "hi" }),
    });

    expect(response.status).toBe(400);
    await response.text();
    expect(observed).toEqual([]);
  });

  test("forwards an accepted request without the caller credential", async () => {
    const base = start();
    const response = await fetch(`${base}/v1/responses`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
        cookie: "session=leaked",
      },
      body: JSON.stringify({ model: "chatgpt-web/medium", input: "hi" }),
    });

    expect(response.status).toBe(200);
    await response.text();
    expect(observed).toHaveLength(1);
    // The gateway token is not an upstream credential; relaying it would send a local secret to
    // ChatGPT's backend on any request the Responses handler decides to proxy.
    expect(observed[0]!.headers.get("authorization")).toBeNull();
    expect(observed[0]!.headers.get("x-api-key")).toBeNull();
    expect(observed[0]!.headers.get("cookie")).toBeNull();
    expect(JSON.parse(observed[0]!.body).model).toBe("chatgpt-web/medium");
  });

  test("rejects previous_response_id because the gateway keeps no continuation store", async () => {
    const base = start();
    const response = await fetch(`${base}/v1/responses`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ model: "chatgpt-web/medium", input: "hi", previous_response_id: "resp_1" }),
    });

    expect(response.status).toBe(400);
    expect(await response.text()).toContain("previous_response_id");
    expect(observed).toEqual([]);
  });

  test("forwards a request the adapter can identify as a native turn", async () => {
    const base = start();
    const response = await fetch(`${base}/v1/responses`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ model: "chatgpt-web/medium", input: "say hi" }),
    });
    expect(response.status).toBe(200);
    await response.text();

    const forwarded = JSON.parse(observed[0]!.body) as Record<string, unknown>;
    const metadata = (forwarded.client_metadata as Record<string, unknown>)["x-codex-turn-metadata"] as {
      thread_id: string;
      turn_id: string;
    };
    const input = forwarded.input as Array<Record<string, unknown>>;

    expect(metadata.thread_id).toMatch(/^gwthread_/);
    expect(input[0]!.internal_chat_message_metadata_passthrough).toEqual({ turn_id: metadata.turn_id });
  });

  test("returns 404 for an unknown authenticated path", async () => {
    const base = start();
    const response = await fetch(`${base}/v1/chat/completions`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: "{}",
    });

    expect(response.status).toBe(404);
    await response.text();
  });
});

describe("API gateway SSE streaming", () => {
  /** Emit two SSE frames with a gap so a buffering hop would collapse them into one read. */
  function streamingHandler(): Promise<Response> {
    const encoder = new TextEncoder();
    let release!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    const stream = new ReadableStream<Uint8Array>({
      async start(controller) {
        controller.enqueue(encoder.encode('event: response.created\ndata: {"type":"response.created"}\n\n'));
        await gate;
        controller.enqueue(encoder.encode('event: response.completed\ndata: {"type":"response.completed"}\n\n'));
        controller.close();
      },
    });
    // Release the second frame only after the test has read the first one.
    (streamingHandler as { release?: () => void }).release = release;
    return Promise.resolve(new Response(stream, {
      headers: {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no",
      },
    }));
  }

  test("passes the event stream through incrementally with its headers intact", async () => {
    const base = start(streamingHandler);
    const response = await fetch(`${base}/v1/responses`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ model: "chatgpt-web/medium", input: "hi", stream: true }),
    });

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/event-stream");
    expect(response.headers.get("cache-control")).toContain("no-cache");
    // Buffering proxies key off this header; losing it makes streaming silently batch.
    expect(response.headers.get("x-accel-buffering")).toBe("no");
    expect(response.headers.get("access-control-allow-origin")).toBe("*");

    const reader = response.body!.getReader();
    const decoder = new TextDecoder();

    const first = await reader.read();
    const firstText = decoder.decode(first.value);
    // The first frame must be readable while the handler is still holding the second one open.
    expect(first.done).toBe(false);
    expect(firstText).toContain("response.created");
    expect(firstText).not.toContain("response.completed");

    (streamingHandler as { release?: () => void }).release!();

    let rest = "";
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) break;
      rest += decoder.decode(chunk.value, { stream: true });
    }
    expect(rest).toContain("response.completed");
  });
});

describe("API gateway header helpers", () => {
  test("reads a bearer token case-insensitively and rejects other schemes", () => {
    expect(presentedGatewayToken(new Headers({ authorization: "bearer abc" }))).toBe("abc");
    expect(presentedGatewayToken(new Headers({ authorization: "Bearer   abc" }))).toBe("abc");
    expect(presentedGatewayToken(new Headers({ authorization: "Basic abc" }))).toBeNull();
    expect(presentedGatewayToken(new Headers({ "x-api-key": " abc " }))).toBe("abc");
    // An Authorization header that exists but is not Bearer must not fall through to x-api-key.
    expect(presentedGatewayToken(new Headers({ authorization: "Basic x", "x-api-key": "abc" }))).toBeNull();
    expect(presentedGatewayToken(new Headers())).toBeNull();
  });

  test("strips every caller credential from the forwarded headers", () => {
    const sanitized = sanitizedUpstreamHeaders(new Headers({
      authorization: "Bearer secret",
      "x-api-key": "secret",
      "proxy-authorization": "Basic secret",
      cookie: "session=secret",
      "x-request-id": "keep-me",
      "content-type": "text/plain",
    }));

    expect(sanitized.get("authorization")).toBeNull();
    expect(sanitized.get("x-api-key")).toBeNull();
    expect(sanitized.get("proxy-authorization")).toBeNull();
    expect(sanitized.get("cookie")).toBeNull();
    expect(sanitized.get("x-request-id")).toBe("keep-me");
    expect(sanitized.get("content-type")).toBe("application/json");
  });
});

describe("API gateway request normalization", () => {
  const identity = { threadId: "gwthread_test", turnId: "gwturn_test" };

  function turnMetadata(body: Record<string, unknown>): Record<string, unknown> {
    return (body.client_metadata as Record<string, unknown>)["x-codex-turn-metadata"] as Record<string, unknown>;
  }

  test("mints a distinct thread and turn per request", () => {
    const first = gatewayTurnIdentity();
    const second = gatewayTurnIdentity();

    expect(first.threadId).not.toBe(second.threadId);
    expect(first.turnId).not.toBe(second.turnId);
    // The admin/interrupt endpoints validate identities against this character class.
    expect(first.threadId).toMatch(/^[A-Za-z0-9_-]{6,128}$/);
    expect(first.turnId).toMatch(/^[A-Za-z0-9_-]{6,128}$/);
  });

  test("expands a plain string prompt into a turn-owned user message", () => {
    const body = normalizeGatewayRequest({ model: "chatgpt-web/medium", input: "say hi" }, identity);
    const input = body.input as Array<Record<string, unknown>>;

    expect(input).toHaveLength(1);
    expect(input[0]!.role).toBe("user");
    expect(input[0]!.content).toEqual([{ type: "input_text", text: "say hi" }]);
    expect(input[0]!.internal_chat_message_metadata_passthrough).toEqual({ turn_id: identity.turnId });
    expect(turnMetadata(body)).toEqual({ thread_id: identity.threadId, turn_id: identity.turnId });
  });

  test("marks only the final user message as the current instruction", () => {
    const body = normalizeGatewayRequest({
      model: "chatgpt-web/medium",
      input: [
        { type: "message", role: "user", content: [{ type: "input_text", text: "first" }] },
        { type: "message", role: "assistant", content: [{ type: "output_text", text: "answer" }] },
        { type: "message", role: "user", content: [{ type: "input_text", text: "second" }] },
      ],
    }, identity);
    const input = body.input as Array<Record<string, unknown>>;

    expect(input).toHaveLength(3);
    expect(input[0]!.internal_chat_message_metadata_passthrough).toBeUndefined();
    expect(input[1]!.internal_chat_message_metadata_passthrough).toBeUndefined();
    expect(input[2]!.internal_chat_message_metadata_passthrough).toEqual({ turn_id: identity.turnId });
    // Prior history must survive verbatim; only transport identity is added.
    expect(input[0]!.content).toEqual([{ type: "input_text", text: "first" }]);
  });

  test("treats a role-only message without an explicit type as a user message", () => {
    const body = normalizeGatewayRequest({
      model: "chatgpt-web/medium",
      input: [{ role: "user", content: "hi" }],
    }, identity);
    const input = body.input as Array<Record<string, unknown>>;

    expect(input[0]!.type).toBe("message");
    expect(input[0]!.internal_chat_message_metadata_passthrough).toEqual({ turn_id: identity.turnId });
  });

  test("preserves the caller's other fields and client metadata", () => {
    const body = normalizeGatewayRequest({
      model: "chatgpt-web/medium",
      input: "hi",
      stream: true,
      reasoning: { effort: "medium" },
      client_metadata: { caller: "n8n" },
    }, identity);

    expect(body.model).toBe("chatgpt-web/medium");
    expect(body.stream).toBe(true);
    expect(body.reasoning).toEqual({ effort: "medium" });
    expect((body.client_metadata as Record<string, unknown>).caller).toBe("n8n");
  });

  test("refuses a request with no user message", () => {
    expect(() => normalizeGatewayRequest({ model: "chatgpt-web/medium", input: [] }, identity))
      .toThrow(/user message is required/);
    expect(() => normalizeGatewayRequest({ model: "chatgpt-web/medium" }, identity))
      .toThrow(/user message is required/);
    expect(() => normalizeGatewayRequest({
      model: "chatgpt-web/medium",
      input: [{ type: "message", role: "assistant", content: [{ type: "output_text", text: "x" }] }],
    }, identity)).toThrow(/user message is required/);
  });
});
