import { createHash, randomBytes } from "node:crypto";
import { touchApiToken, verifyApiToken } from "./api-tokens";
import {
  availableChatGptWebModelRoutes,
  isChatGptWebModelSlug,
  requireChatGptWebModelRoute,
  resolveChatGptWebContextLimits,
} from "./chatgpt-web-models";
import type { AppConfig } from "./config";
import { GatewaySessionStore, type GatewaySessionMessage } from "./gateway-sessions";
import { formatErrorResponse } from "./bridge";
import { readJsonRequestBody } from "./http-body";
import { VERSION } from "./version";

/**
 * The Responses listener itself has no bearer secret, because Codex's built-in `openai` provider
 * cannot carry a bridge-specific credential. The gateway is the opposite trade: a second loopback
 * listener that only accepts authenticated callers, so an operator can put their own tunnel or
 * reverse proxy in front of it without exposing the unauthenticated Codex route.
 */
export const DEFAULT_GATEWAY_PORT = 17842;

export interface ApiGatewayConfig {
  enabled: boolean;
  port: number;
}

/**
 * The Responses handler this gateway fronts. It is injected rather than imported so `server.ts`
 * stays the single owner of the Responses pipeline and the two modules do not form an import cycle.
 */
export type GatewayResponsesHandler = (req: Request) => Promise<Response>;

export interface ApiGatewayDependencies {
  handleResponses: GatewayResponsesHandler;
  /** Test seam; defaults to a store private to this listener. */
  sessions?: GatewaySessionStore;
  /** Test seam for the token store location. */
  tokenStorePath?: string;
}

export interface ApiGatewayServer {
  port: number;
  stop(closeActiveConnections?: boolean): Promise<void> | void;
}

const CORS_HEADERS: Record<string, string> = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers": "authorization, content-type, x-api-key",
  "access-control-max-age": "600",
};

function withCors(response: Response): Response {
  for (const [key, value] of Object.entries(CORS_HEADERS)) response.headers.set(key, value);
  return response;
}

function unauthorized(message: string): Response {
  const response = formatErrorResponse(401, "invalid_request_error", message);
  response.headers.set("www-authenticate", 'Bearer realm="codex-chatgpt-web"');
  return withCors(response);
}

export function presentedGatewayToken(headers: Headers): string | null {
  const authorization = headers.get("authorization");
  if (authorization) {
    const match = /^Bearer\s+(\S+)$/i.exec(authorization.trim());
    if (match) return match[1]!;
    return null;
  }
  const apiKey = headers.get("x-api-key");
  return apiKey?.trim() || null;
}

/**
 * Requests reaching the Responses handlers must not carry the gateway credential. Those handlers
 * forward unrouted models to ChatGPT's official backend using the incoming Authorization header,
 * and a caller's gateway token is neither valid nor safe to relay upstream.
 */
export function sanitizedUpstreamHeaders(headers: Headers): Headers {
  const sanitized = new Headers(headers);
  sanitized.delete("authorization");
  sanitized.delete("x-api-key");
  sanitized.delete("proxy-authorization");
  sanitized.delete("cookie");
  sanitized.set("content-type", "application/json");
  return sanitized;
}

function gatewayModelCatalog(config: AppConfig): Record<string, unknown> {
  const capabilities = {
    solAvailable: config.solAvailable,
    proAvailable: config.proAvailable,
    experimentalBiggerContext: config.experimentalBiggerContext,
    browserInteractionMode: config.browserInteractionMode,
    zeroRiskProEnabled: config.zeroRiskProEnabled,
  };
  const routes = availableChatGptWebModelRoutes(capabilities);
  return {
    object: "list",
    data: routes.map(route => {
      const limits = resolveChatGptWebContextLimits(route.backendModel, route.adapterEffort, capabilities);
      return {
        id: route.slug,
        object: "model",
        owned_by: "codex-chatgpt-web",
        display_name: route.displayName,
        description: route.description,
        supported_reasoning_efforts: [route.codexEffort],
        context_window: limits.contextWindow,
        max_context_window: limits.contextWindow,
        auto_compact_token_limit: limits.autoCompactTokenLimit,
      };
    }),
  };
}

/**
 * Only routed ChatGPT Web models may run through the gateway. Without this guard a caller could
 * name any native model and have the request proxied to ChatGPT's official Codex backend.
 */
function assertRoutableModel(model: unknown, config: AppConfig): string {
  if (typeof model !== "string" || !model.trim()) {
    throw new Error("A model is required");
  }
  if (!isChatGptWebModelSlug(model)) {
    throw new Error(
      `The gateway serves only ChatGPT Web models. Use one of the chatgpt-web/ ids from GET /v1/models, not ${JSON.stringify(model)}.`,
    );
  }
  requireChatGptWebModelRoute(model, config);
  return model;
}

/**
 * Identity a single gateway call presents to the adapter. Codex supplies these from its own task
 * lifecycle; a third-party client has no equivalent, so the gateway mints one per request.
 */
export interface GatewayTurnIdentity {
  threadId: string;
  turnId: string;
}

const SESSION_ID_PATTERN = /^[A-Za-z0-9_.:-]{1,128}$/;

export function assertGatewaySessionId(value: unknown): string {
  if (typeof value !== "string" || !SESSION_ID_PATTERN.test(value)) {
    throw new Error(
      "session_id must be 1-128 characters of letters, digits, and the symbols _ . : -",
    );
  }
  return value;
}

/**
 * Derive the turn identity for one gateway call.
 *
 * The thread is what the adapter keys conversation retention on, so a caller that repeats the same
 * `session_id` lands on the same retained ChatGPT chat and only sends the new suffix. Without one,
 * every call gets its own thread and therefore its own fresh chat.
 */
export function gatewayTurnIdentity(sessionId?: string): GatewayTurnIdentity {
  return {
    threadId: sessionId
      ? `gwthread_${createHash("sha256").update(`gateway-session\u0000${sessionId}`).digest("hex").slice(0, 32)}`
      : `gwthread_${randomBytes(12).toString("hex")}`,
    turnId: `gwturn_${randomBytes(12).toString("hex")}`,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isUserMessageItem(value: unknown): value is Record<string, unknown> {
  if (!isRecord(value)) return false;
  const type = value.type;
  return (type === undefined || type === "message") && value.role === "user";
}

/**
 * Rewrite an ordinary Responses request into the exact shape the ChatGPT adapter expects.
 *
 * The adapter is built for native Codex, which stamps every request with its thread/turn identity
 * and marks which user message the current turn must execute. A plain API client sends neither, so
 * without this normalization every gateway call fails on missing turn metadata. Only transport
 * identity is added here: the caller's messages, model, and options are passed through untouched.
 */
export function normalizeGatewayRequest(
  raw: Record<string, unknown>,
  identity: GatewayTurnIdentity = gatewayTurnIdentity(),
): Record<string, unknown> {
  const input = typeof raw.input === "string"
    ? [{ type: "message", role: "user", content: [{ type: "input_text", text: raw.input }] }]
    : Array.isArray(raw.input) ? [...raw.input] : [];
  const lastUserIndex = input.findLastIndex(isUserMessageItem);
  if (lastUserIndex < 0) {
    throw new Error("A user message is required in `input`.");
  }
  // Marking only the final user message keeps every earlier item history, exactly as Codex does:
  // the adapter executes the latest instruction owned by the current turn.
  const current = input[lastUserIndex] as Record<string, unknown>;
  input[lastUserIndex] = {
    ...current,
    type: "message",
    internal_chat_message_metadata_passthrough: {
      ...(isRecord(current.internal_chat_message_metadata_passthrough)
        ? current.internal_chat_message_metadata_passthrough
        : {}),
      turn_id: identity.turnId,
    },
  };
  const { session_id: _sessionId, ...passthrough } = raw;
  return {
    ...passthrough,
    input,
    client_metadata: {
      ...(isRecord(raw.client_metadata) ? raw.client_metadata : {}),
      "x-codex-turn-metadata": { thread_id: identity.threadId, turn_id: identity.turnId },
    },
  };
}

/** Flatten one Responses input item into plain text for the session transcript. */
export function inputItemText(value: unknown): string {
  if (!isRecord(value)) return "";
  const content = value.content;
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content
    .map(part => (isRecord(part) && typeof part.text === "string" ? part.text : ""))
    .filter(Boolean)
    .join("\n");
}

/** The assistant text a completed non-streamed response returned to the caller. */
export function completedAnswerText(body: unknown): string {
  if (!isRecord(body) || !Array.isArray(body.output)) return "";
  return body.output
    .filter(item => isRecord(item) && item.type === "message" && item.phase !== "commentary")
    .map(item => (isRecord(item) && Array.isArray(item.content)
      ? item.content
        .map(part => (isRecord(part) && typeof part.text === "string" ? part.text : ""))
        .join("")
      : ""))
    .join("\n")
    .trim();
}

/** Turn a stored transcript into Responses input items the prompt compiler already understands. */
function historyItems(messages: GatewaySessionMessage[]): Array<Record<string, unknown>> {
  return messages.map(message => (message.role === "assistant"
    ? { type: "message", role: "assistant", content: [{ type: "output_text", text: message.text }] }
    : { type: "message", role: "user", content: [{ type: "input_text", text: message.text }] }));
}

/**
 * Pass an event stream through untouched while accumulating the answer it carries.
 *
 * The bytes are forwarded as they arrive, so streaming stays incremental; the accumulated text is
 * only used to record the exchange once the stream reports completion.
 */
export function streamAndRemember(
  response: Response,
  remember: (answer: string) => void,
): Response {
  const decoder = new TextDecoder();
  let pending = "";
  let answer = "";
  let completed = false;
  const consume = (chunk: string) => {
    pending += chunk;
    let newline = pending.indexOf("\n");
    while (newline >= 0) {
      const line = pending.slice(0, newline).trim();
      pending = pending.slice(newline + 1);
      newline = pending.indexOf("\n");
      if (!line.startsWith("data:")) continue;
      const payload = line.slice(5).trim();
      if (!payload || payload === "[DONE]") continue;
      let event: unknown;
      try {
        event = JSON.parse(payload);
      } catch {
        continue;
      }
      if (!isRecord(event)) continue;
      if (event.type === "response.output_text.delta" && typeof event.delta === "string") {
        answer += event.delta;
      } else if (event.type === "response.completed") {
        completed = true;
        // The terminal frame carries the authoritative output, including any part the deltas
        // did not cover; prefer it over the accumulated text when it is present.
        const final = completedAnswerText(event.response);
        if (final) answer = final;
      }
    }
  };
  const transform = new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      controller.enqueue(chunk);
      consume(decoder.decode(chunk, { stream: true }));
    },
    flush() {
      consume(decoder.decode());
      if (completed) remember(answer);
    },
  });
  return new Response(response.body!.pipeThrough(transform), {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
  });
}

export function startApiGateway(
  config: AppConfig,
  dependencies: ApiGatewayDependencies,
): ApiGatewayServer | undefined {
  const gateway = config.gateway;
  if (!gateway?.enabled) return undefined;
  if (gateway.port === config.port) {
    throw new Error("The API gateway port must differ from the Responses port");
  }
  const sessions = dependencies.sessions ?? new GatewaySessionStore();
  const authorize = (req: Request): { ok: true; tokenId: string } | { ok: false; response: Response } => {
    const presented = presentedGatewayToken(req.headers);
    if (!presented) {
      return {
        ok: false,
        response: unauthorized("Provide an API token as `Authorization: Bearer <token>` or `x-api-key`."),
      };
    }
    const record = verifyApiToken(presented, dependencies.tokenStorePath);
    if (!record) return { ok: false, response: unauthorized("The presented API token is not valid.") };
    touchApiToken(record.id, dependencies.tokenStorePath);
    return { ok: true, tokenId: record.id };
  };

  const server = Bun.serve({
    hostname: config.host,
    port: gateway.port,
    // A browser turn can legitimately stay open for minutes while Codex-side tools run.
    idleTimeout: 0,
    async fetch(req) {
      const url = new URL(req.url);
      if (req.method === "OPTIONS") return withCors(new Response(null, { status: 204 }));
      if (req.method === "GET" && url.pathname === "/healthz") {
        // Unauthenticated on purpose: an operator's tunnel or proxy needs a liveness probe, and
        // this payload deliberately carries no account, model, or token information.
        return withCors(Response.json({
          status: "ok",
          service: "codex-chatgpt-web-gateway",
          version: VERSION,
        }));
      }
      const auth = authorize(req);
      if (!auth.ok) return auth.response;

      if (config.browserInteractionMode === "manual") {
        // Zero Risk deliberately requires a person to paste and send each prompt in the launcher.
        // There is no API-shaped version of that contract, so say so instead of failing deeper in.
        return withCors(formatErrorResponse(
          503,
          "invalid_request_error",
          "The gateway cannot serve requests while the launcher is in Zero Risk mode, because every "
            + "Zero Risk turn requires a person to paste and send the prompt in the launcher. "
            + "Switch ChatGPT interaction to With Automation to use the gateway.",
        ));
      }

      if (req.method === "GET" && url.pathname === "/v1/models") {
        return withCors(Response.json(gatewayModelCatalog(config)));
      }
      if (req.method === "POST" && url.pathname === "/v1/responses") {
        let raw: Record<string, unknown>;
        try {
          const parsed = await readJsonRequestBody(req);
          if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("not an object");
          raw = parsed as Record<string, unknown>;
        } catch (error) {
          return withCors(formatErrorResponse(
            400,
            "invalid_request_error",
            error instanceof Error ? error.message : "Request body must be a JSON object",
          ));
        }
        let normalized: Record<string, unknown>;
        let sessionId: string | undefined;
        let promptText = "";
        try {
          assertRoutableModel(raw.model, config);
          if (raw.session_id !== undefined) sessionId = assertGatewaySessionId(raw.session_id);
          if (raw.previous_response_id !== undefined) {
            // The gateway keeps no continuation store, so replaying an id would silently run the
            // turn with partial context. Callers resend the full `input` instead.
            throw new Error(
              "previous_response_id is not supported by the gateway. Send the full conversation in `input`.",
            );
          }
          const requestInput = typeof raw.input === "string"
            ? [{ type: "message", role: "user", content: [{ type: "input_text", text: raw.input }] }]
            : Array.isArray(raw.input) ? raw.input : [];
          // Replay the stored transcript ahead of the caller's new items. The compiled envelope is
          // the model's only view of the conversation, so continuity has to live in `input`.
          const withHistory = sessionId
            ? { ...raw, input: [...historyItems(sessions.history(sessionId)), ...requestInput] }
            : raw;
          normalized = normalizeGatewayRequest(withHistory, gatewayTurnIdentity(sessionId));
          promptText = requestInput.map(inputItemText).filter(Boolean).join("\n");
        } catch (error) {
          return withCors(formatErrorResponse(
            400,
            "invalid_request_error",
            error instanceof Error ? error.message : String(error),
          ));
        }
        const internal = new Request("http://127.0.0.1/v1/responses", {
          method: "POST",
          headers: sanitizedUpstreamHeaders(req.headers),
          body: JSON.stringify(normalized),
          signal: req.signal,
        });
        // The Responses handler already returns a streaming `text/event-stream` body when the
        // caller asked for `stream: true`. Returning it unchanged keeps the stream unbuffered
        // end to end: no body is read, buffered, or re-encoded on this hop.
        const response = await dependencies.handleResponses(internal);
        // Echo the session back so the caller can keep using it. A header carries it for both
        // transports; a streamed body has no place to add a field.
        if (sessionId) response.headers.set("x-session-id", sessionId);
        if (!sessionId || !response.ok || !response.body) return withCors(response);
        const session = sessionId;
        const prompt = promptText;
        const remember = (answer: string) => {
          if (!answer.trim()) return;
          sessions.append(session, [
            ...(prompt ? [{ role: "user" as const, text: prompt }] : []),
            { role: "assistant" as const, text: answer },
          ]);
        };
        if (raw.stream === true) return withCors(streamAndRemember(response, remember));
        const body = await response.text();
        let parsed: unknown;
        try {
          parsed = JSON.parse(body);
        } catch {
          return withCors(new Response(body, response));
        }
        if (isRecord(parsed) && parsed.status === "completed") remember(completedAnswerText(parsed));
        // Surface the session on the body too, so a non-streaming caller sees it without headers.
        const enriched = isRecord(parsed) ? { ...parsed, session_id: session } : parsed;
        return withCors(new Response(JSON.stringify(enriched), {
          status: response.status,
          statusText: response.statusText,
          headers: response.headers,
        }));
      }
      return withCors(new Response("Not found", { status: 404 }));
    },
  });
  // Bun types `port` as optional because a unix-socket server has none. This listener always binds
  // a TCP port, so surface the resolved value rather than propagating the optionality.
  return {
    port: server.port ?? gateway.port,
    stop: closeActiveConnections => server.stop(closeActiveConnections),
  };
}
