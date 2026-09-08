import { createHash } from "node:crypto";

/**
 * Per-session conversation memory for gateway callers.
 *
 * The ChatGPT adapter is built for Codex, which resends its complete task history on every turn and
 * treats the compiled envelope as the whole truth. A gateway client that sends only its new message
 * therefore gets an amnesiac model even when the browser tab is reused, because the envelope it
 * receives contains no earlier turns. Keeping the transcript here restores continuity without
 * asking callers to resend it and without depending on a retained browser tab.
 *
 * State is in-memory on purpose: it is conversation content, so it should not outlive the process
 * that serves it or be written to disk by default.
 */
export interface GatewaySessionMessage {
  role: "user" | "assistant";
  text: string;
}

interface StoredSession {
  messages: GatewaySessionMessage[];
  updatedAt: number;
}

export const GATEWAY_SESSION_TTL_MS = 24 * 60 * 60 * 1000;
export const MAX_GATEWAY_SESSIONS = 200;
export const MAX_GATEWAY_SESSION_MESSAGES = 80;
/** Guard against one session growing until it can no longer fit in a browser turn. */
export const MAX_GATEWAY_SESSION_CHARS = 400_000;

function sessionKey(sessionId: string): string {
  // Session ids come from callers and are echoed in logs and errors; hashing keeps the raw value
  // out of the in-memory key space that diagnostics may print.
  return createHash("sha256").update(sessionId).digest("hex").slice(0, 32);
}

export class GatewaySessionStore {
  private readonly sessions = new Map<string, StoredSession>();

  constructor(
    private readonly ttlMs = GATEWAY_SESSION_TTL_MS,
    private readonly maxSessions = MAX_GATEWAY_SESSIONS,
  ) {}

  private prune(now: number): void {
    for (const [key, session] of this.sessions) {
      if (now - session.updatedAt > this.ttlMs) this.sessions.delete(key);
    }
    // Map preserves insertion order and every write re-inserts, so the front is the oldest.
    while (this.sessions.size > this.maxSessions) {
      const oldest = this.sessions.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.sessions.delete(oldest);
    }
  }

  history(sessionId: string, now = Date.now()): GatewaySessionMessage[] {
    this.prune(now);
    const session = this.sessions.get(sessionKey(sessionId));
    return session ? session.messages.map(message => ({ ...message })) : [];
  }

  append(sessionId: string, messages: GatewaySessionMessage[], now = Date.now()): void {
    const usable = messages.filter(message => message.text.trim().length > 0);
    if (usable.length === 0) return;
    const key = sessionKey(sessionId);
    const existing = this.sessions.get(key);
    let next = [...(existing?.messages ?? []), ...usable.map(message => ({ ...message }))];
    if (next.length > MAX_GATEWAY_SESSION_MESSAGES) {
      next = next.slice(next.length - MAX_GATEWAY_SESSION_MESSAGES);
    }
    // Drop from the front until the transcript fits, so a long session degrades into a recent
    // window rather than failing the next turn outright.
    while (next.length > 1 && next.reduce((total, m) => total + m.text.length, 0) > MAX_GATEWAY_SESSION_CHARS) {
      next.shift();
    }
    // Re-insert so this session becomes the most recently used entry.
    this.sessions.delete(key);
    this.sessions.set(key, { messages: next, updatedAt: now });
    this.prune(now);
  }

  forget(sessionId: string): boolean {
    return this.sessions.delete(sessionKey(sessionId));
  }

  size(): number {
    return this.sessions.size;
  }

  clear(): void {
    this.sessions.clear();
  }
}
