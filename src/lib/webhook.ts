/**
 * Outbound webhooks for monitoring alerts: URL validation at registration
 * time and a guarded, signed POST at delivery time. The destination is
 * caller-supplied, so delivery goes through the same SSRF guards as the
 * inspectors (literal check plus guarded DNS lookup), never follows
 * redirects, and discards the response body.
 */

import { createHmac, randomBytes } from "node:crypto";
import { isIP } from "node:net";
import { Agent, fetch as undiciFetch } from "undici";
import { parseDomain } from "./domain.js";
import { errorCode, errorMessage, isAbortLike, ToolError } from "./errors.js";
import { assertPublicLiteral, createGuardedLookup, isPrivateTargetError } from "./lookup.js";
import { isPrivateAddress } from "./net.js";
import { logger } from "../logger.js";

export interface WebhookPolicy {
  /** Permit http:// destinations (development only). */
  allowInsecure: boolean;
  /** Permit destinations in private address space (development only). */
  allowPrivate: boolean;
}

export interface WebhookDelivery {
  ok: boolean;
  status: number | null;
  error: string | null;
}

/** Delivers one POST; signal cancels it early (server shutdown). */
export type WebhookSender = (url: string, body: string, headers: Record<string, string>, signal?: AbortSignal) => Promise<WebhookDelivery>;

export const MAX_WEBHOOK_URL_LENGTH = 2048;

/** Validates and normalizes a webhook URL; throws INVALID_ARGUMENT with a reason the caller can act on. */
export function validateWebhookUrl(raw: string, policy: WebhookPolicy): string {
  const value = raw.trim();
  if (value.length === 0 || value.length > MAX_WEBHOOK_URL_LENGTH) throw new ToolError("INVALID_ARGUMENT", `webhookUrl must be 1-${MAX_WEBHOOK_URL_LENGTH} characters.`);
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new ToolError("INVALID_ARGUMENT", "webhookUrl is not a valid absolute URL.");
  }
  if (url.protocol !== "https:" && !(policy.allowInsecure && url.protocol === "http:")) {
    throw new ToolError("INVALID_ARGUMENT", "webhookUrl must use https.");
  }
  if (url.username || url.password) throw new ToolError("INVALID_ARGUMENT", "webhookUrl must not embed credentials; use the signature header to authenticate deliveries.");
  const host = url.hostname.replace(/^\[|\]$/g, "");
  if (!host) throw new ToolError("INVALID_ARGUMENT", "webhookUrl has no host.");
  if (!policy.allowPrivate) {
    const bare = host.replace(/\.+$/, "");
    if (isIP(bare) !== 0) {
      if (isPrivateAddress(bare)) throw new ToolError("INVALID_ARGUMENT", "webhookUrl points at a private or reserved address.");
    } else if (!parseDomain(bare, { allowPrivate: false }).ok) {
      // Single-label and reserved names (service names such as "db" or
      // "kubernetes.default.svc", .local, .internal) resolve only inside the
      // deployment; the same rules as inspected domains apply.
      throw new ToolError("INVALID_ARGUMENT", "webhookUrl must use a fully qualified public host name.");
    }
  }
  url.hash = "";
  return url.toString();
}

export function generateWebhookSecret(): string {
  return `sdm_whsec_${randomBytes(24).toString("base64url")}`;
}

/** Signature header value: "t=<unix seconds>,v1=<hex HMAC-SHA256 of `${t}.${body}`>". */
export function signWebhook(body: string, secret: string, timestampSeconds: number = Math.floor(Date.now() / 1000)): string {
  const signature = createHmac("sha256", secret).update(`${timestampSeconds}.${body}`).digest("hex");
  return `t=${timestampSeconds},v1=${signature}`;
}

/** Real sender: guarded DNS, no redirects, hard timeout, response body discarded. */
export function createWebhookSender(options: { timeoutMs: number; userAgent: string; allowPrivate: boolean }): WebhookSender {
  return async (url, body, headers, signal) => {
    const agent = new Agent({
      connect: { timeout: options.timeoutMs, lookup: createGuardedLookup(options.allowPrivate) },
      headersTimeout: options.timeoutMs,
      bodyTimeout: options.timeoutMs
    });
    try {
      assertPublicLiteral(new URL(url).hostname, options.allowPrivate);
      const response = await undiciFetch(url, {
        method: "POST",
        headers: { "content-type": "application/json", "user-agent": options.userAgent, ...headers },
        body,
        redirect: "manual",
        dispatcher: agent,
        signal: signal ? AbortSignal.any([AbortSignal.timeout(options.timeoutMs), signal]) : AbortSignal.timeout(options.timeoutMs)
      });
      try {
        await response.body?.cancel();
      } catch {
        // body already closed
      }
      const ok = response.status >= 200 && response.status < 300;
      return { ok, status: response.status, error: ok ? null : `HTTP ${response.status}` };
    } catch (err) {
      // The stored error is shown to the watch's owner: classify it rather
      // than echo resolver output, which would disclose internal names and
      // private addresses. The detail stays in the server log.
      const cause = err instanceof Error && err.cause !== undefined ? err.cause : undefined;
      const code = errorCode(cause) ?? errorCode(err);
      const error =
        isPrivateTargetError(err) || isPrivateTargetError(cause)
          ? "destination refused: non-public address"
          : code === "ENOTFOUND" || code === "EAI_AGAIN" || code === "EAI_NONAME"
            ? "DNS lookup failed"
            : isAbortLike(err) || (cause !== undefined && isAbortLike(cause))
              ? "timed out"
              : `connection failed (${code ?? "unknown"})`;
      logger.debug("webhook delivery error", { error: errorMessage(cause ?? err) });
      return { ok: false, status: null, error };
    } finally {
      agent.destroy().catch(() => undefined);
    }
  };
}
