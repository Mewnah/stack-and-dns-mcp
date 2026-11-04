/**
 * Hosted HTTP transport: Express app exposing Streamable HTTP (/mcp) and the
 * legacy SSE pair (/sse + /messages), fronted by the API-key / payment
 * middleware, with public info, health, pricing and usage endpoints, the
 * bulk-check REST API and, when configured, self-serve API key signup.
 */

import { randomUUID } from "node:crypto";
import type { Server as HttpServer } from "node:http";
import express, { type NextFunction, type Request, type Response } from "express";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerKeySignupRoutes, registerStripeWebhookRoute, type KeySignupOptions } from "../billing/keySignup.js";
import type { StripeApi } from "../billing/stripeApi.js";
import { BULK_CREDITS_PER_DOMAIN, type AppConfig } from "../config.js";
import { logger } from "../logger.js";
import { createAddressThrottle } from "../middleware/addressThrottle.js";
import { createAuthMiddleware, principalFromAuthInfo, type ApiKeyStore, type AuthenticatedRequest, type SessionTokenService } from "../middleware/auth.js";
import { encodeCredential, type PaymentManager } from "../middleware/payments.js";
import { createMcpServer, describeServer, type ServerDeps } from "../server.js";
import { toolFeatures, toolNames } from "../tools/index.js";
import { registerJobRoutes } from "./jobsApi.js";

export interface SelfServeDeps {
  stripe: StripeApi;
  options: KeySignupOptions;
}

export interface HttpDeps extends ServerDeps {
  keys: ApiKeyStore;
  sessions: SessionTokenService;
  payments: PaymentManager;
  /** Self-serve key signup; null when Stripe prices are not configured or storage is unavailable. */
  selfServe: SelfServeDeps | null;
}

interface StreamableSession {
  transport: StreamableHTTPServerTransport;
  server: McpServer;
  lastSeen: number;
  /** Standalone GET streams currently open; an idle timer must not reap a session a client is still listening on. */
  openStreams: number;
  principalId: string;
}

interface SseSession {
  transport: SSEServerTransport;
  server: McpServer;
  res: Response;
  principalId: string;
}

// Browsers hide every response header that is not CORS-safelisted unless it is named here, so each header a client is told to read must be listed:
// X-Payment-Status (why a session was served despite a stale payment header), Location (the job URL a POST /v1/jobs returns) and Content-Disposition (the CSV export's file name).
export const EXPOSED_HEADERS =
  "Mcp-Session-Id, Mcp-Protocol-Version, WWW-Authenticate, Payment-Receipt, X-Session-Token, X-RateLimit-Limit, X-RateLimit-Http-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, X-RateLimit-Plan, Retry-After, X-Payment-Challenge-Id, X-Payment-Status, Location, Content-Disposition";
const ALLOWED_HEADERS = "Content-Type, Authorization, X-API-Key, X-Payment, X-Session-Token, Mcp-Session-Id, Mcp-Protocol-Version, Last-Event-ID, Accept";

const MIB = 1024 * 1024;
/** Generous bytes per raw list entry: a domain is about 30 bytes of JSON, and a job may carry twice its distinct-domain maximum in raw entries. */
const BYTES_PER_LIST_ENTRY = 64;

/**
 * Request body limits, sized so the largest list a job accepts (2 x
 * STACKDNS_BULK_MAX_DOMAINS raw entries) fits in one JSON body or CSV upload.
 * The JSON parser runs before authentication (pricing an /mcp call needs the
 * body), so the limit only grows when an operator raises the job maximum: the
 * default of 1000 domains keeps 1 MiB for JSON and 2 MiB for CSV.
 */
export function httpBodyLimits(maxDomains: number): { json: number; text: number } {
  const list = Math.max(1, maxDomains) * 2 * BYTES_PER_LIST_ENTRY;
  return { json: Math.max(MIB, list), text: Math.max(2 * MIB, list) };
}

function formatBytes(bytes: number): string {
  return bytes % MIB === 0 ? `${bytes / MIB} MiB` : `${(bytes / MIB).toFixed(1)} MiB`;
}

export interface RebindingProtectionOptions {
  enableDnsRebindingProtection: boolean;
  allowedHosts: string[] | undefined;
  allowedOrigins: string[] | undefined;
}

/**
 * The DNS-rebinding options handed to the SDK transports. The SDK compares
 * the Origin header with each listed origin exactly, so the "*" that CORS and
 * the anonymous-origin check read as "every origin" would match no browser
 * and refuse them all. A list containing "*" is therefore not passed on: the
 * operator allowed every origin, so the SDK checks none (a mixed list behaves
 * as "*" alone does everywhere else in the server). An empty list means no
 * check, as the SDK treats it.
 */
export function rebindingProtection(http: Pick<AppConfig["http"], "enableDnsRebindingProtection" | "allowedHosts" | "allowedOrigins">): RebindingProtectionOptions {
  const origins = http.allowedOrigins.includes("*") ? [] : http.allowedOrigins;
  return {
    enableDnsRebindingProtection: http.enableDnsRebindingProtection,
    allowedHosts: http.allowedHosts.length > 0 ? http.allowedHosts : undefined,
    allowedOrigins: origins.length > 0 ? origins : undefined
  };
}

function jsonRpcError(res: Response, status: number, code: number, message: string): void {
  res.status(status).json({ jsonrpc: "2.0", error: { code, message }, id: null });
}

/** A body-parser failure the client caused (malformed JSON, too large, unsupported charset...): a 4xx status and a message safe to show. */
function clientBodyError(err: unknown): { type: string; status: number; message: string; limit: number | null } | null {
  if (!err || typeof err !== "object") return null;
  const e = err as { type?: unknown; status?: unknown; expose?: unknown; message?: unknown; limit?: unknown };
  if (typeof e.type !== "string" || typeof e.status !== "number" || e.status < 400 || e.status >= 500 || e.expose !== true) return null;
  return { type: e.type, status: e.status, message: typeof e.message === "string" ? e.message : "Bad request.", limit: typeof e.limit === "number" ? e.limit : null };
}

function createCors(allowedOrigins: string[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const origin = req.header("origin");
    if (origin) {
      const allowed = allowedOrigins.length === 0 || allowedOrigins.includes(origin) || allowedOrigins.includes("*");
      if (allowed) {
        res.setHeader("Access-Control-Allow-Origin", allowedOrigins.length === 0 ? "*" : origin);
        res.setHeader("Vary", "Origin");
        res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
        res.setHeader("Access-Control-Allow-Headers", ALLOWED_HEADERS);
        res.setHeader("Access-Control-Expose-Headers", EXPOSED_HEADERS);
        res.setHeader("Access-Control-Max-Age", "600");
      }
    }
    if (req.method === "OPTIONS") {
      res.status(204).end();
      return;
    }
    next();
  };
}

export async function startHttp(deps: HttpDeps): Promise<HttpServer> {
  const { config } = deps;
  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", config.http.trustProxy);
  app.use(createCors(config.http.allowedOrigins));
  const keyRepository = deps.services.keys;
  // Stripe signs the exact request bytes, so the webhook is mounted with its
  // own raw parser before the global JSON parser consumes the body. It stays
  // mounted after signup is switched off: keys already sold must still follow
  // their subscriptions (cancellations above all).
  const webhookSecret = config.selfServe.webhookSecret;
  if (keyRepository && webhookSecret) {
    registerStripeWebhookRoute(app, {
      keys: keyRepository,
      options: deps.selfServe?.options ?? { publicUrl: config.http.publicUrl, prices: config.selfServe.prices, webhookSecret, planLimits: config.auth.planLimits }
    });
  }
  // Without the bulk service no request carries a list, so the limits stay at their 1 MiB / 2 MiB floor.
  const bodyLimits = httpBodyLimits(deps.services.jobs ? config.bulk.maxDomains : 0);
  app.use(express.json({ limit: bodyLimits.json, type: ["application/json", "application/*+json"] }));

  const auth = createAuthMiddleware({
    config,
    keys: deps.keys,
    sessions: deps.sessions,
    payments: deps.payments,
    usage: deps.usage,
    limiter: deps.limiter
  });

  const streamableSessions = new Map<string, StreamableSession>();
  const sseSessions = new Map<string, SseSession>();
  const protection = rebindingProtection(config.http);
  const { storage, jobs, monitor, reverse, crawler } = deps.services;
  const features = toolFeatures({ storage, jobs, monitor, reverse });
  const registered = new Set(toolNames(features));

  /** Prices for what this server actually offers: tools that are not registered are not listed. */
  const pricing = (): Record<string, unknown> => {
    const base = deps.payments.pricing();
    const costs = Object.fromEntries(Object.entries((base.creditCosts ?? {}) as Record<string, number>).filter(([tool]) => registered.has(tool)));
    return {
      ...base,
      creditCosts: costs,
      ...(features.bulk ? { bulkCreditsPerDomain: BULK_CREDITS_PER_DOMAIN } : {}),
      ...(features.monitor ? { monitorCreditsPerCheck: config.monitor.creditsPerCheck, watchLimits: config.monitor.maxWatches } : {})
    };
  };

  app.get("/", (_req, res) => {
    res.json({
      ...describeServer(config, features),
      ...(jobs ? { bulkApi: `${config.http.publicUrl}/v1/jobs` } : {}),
      ...(deps.selfServe ? { signup: `${config.http.publicUrl}/signup` } : {}),
      payments: pricing(),
      sessions: { streamable: streamableSessions.size, sse: sseSessions.size }
    });
  });

  app.get("/healthz", (_req, res) => {
    res.json({
      status: "ok",
      version: config.version,
      uptimeSeconds: Math.round(process.uptime()),
      sessions: streamableSessions.size + sseSessions.size,
      ...(crawler ? { crawl: crawler.cachedStats() } : {})
    });
  });

  app.get("/pricing", (_req, res) => {
    res.json({ plans: config.auth.planLimits, payments: pricing() });
  });

  if (jobs) {
    registerJobRoutes(
      app,
      { jobs, requireAuth: config.auth.requireAuth, allowPrivateTargets: config.inspection.allowPrivateTargets, maxDomains: config.bulk.maxDomains, textLimitBytes: bodyLimits.text },
      auth
    );
  }
  if (deps.selfServe && keyRepository) {
    const throttle = createAddressThrottle(deps.limiter, config.auth.unauthenticatedPerMinute);
    registerKeySignupRoutes(app, { stripe: deps.selfServe.stripe, keys: keyRepository, options: deps.selfServe.options, throttle }, auth);
  }

  app.get("/payments/success", (req, res) => {
    const sessionId = typeof req.query.session_id === "string" ? req.query.session_id.trim() : "";
    if (!sessionId) {
      res
        .type("text/plain")
        .send(
          [
            "Payment received. Thank you.",
            "",
            "This page was opened without a session_id, so no redemption credential can be shown.",
            "Retry your MCP request with the paymentIntentId from the original challenge:",
            '  Authorization: Payment <base64url({"method":"stripe","paymentIntentId":"pi_..."})>'
          ].join("\n")
        );
      return;
    }
    res
      .type("text/plain")
      .send(
        [
          "Payment received. Thank you.",
          "",
          "To redeem your credits, retry your MCP request with this header:",
          `  Authorization: Payment ${encodeCredential({ checkoutSessionId: sessionId })}`,
          "",
          "The response will include a Payment-Receipt header containing a session token (sdm_sess.…).",
          "Use it on subsequent requests as: Authorization: Bearer <session token>"
        ].join("\n")
      );
  });

  app.get("/payments/cancel", (_req, res) => {
    res.type("text/plain").send("Payment cancelled. Retry the request to receive a new payment challenge.");
  });

  app.get("/usage", auth, (req, res) => {
    const principal = principalFromAuthInfo((req as AuthenticatedRequest).auth);
    if (!principal) {
      res.status(401).json({ error: "unauthorized", message: "No principal resolved." });
      return;
    }
    const usage = deps.usage.get(principal.id);
    const limits = deps.limiter.snapshot(principal.id, principal.plan);
    res.json({
      principal: principal.id,
      plan: principal.plan,
      label: principal.label,
      limits: config.auth.planLimits[principal.plan],
      remaining: { thisMinute: limits.remainingThisMinute, today: limits.remainingToday, credits: usage?.creditsRemaining ?? null },
      usage: usage ?? null
    });
  });

  /** Sessions are private to the principal that initialized them; a leaked session id must not let another caller drive or end them. */
  const ownsSession = (req: Request, principalId: string): boolean => {
    const principal = principalFromAuthInfo((req as AuthenticatedRequest).auth);
    return principal !== null && principal.id === principalId;
  };

  const handleSessionRequest = async (req: Request, res: Response): Promise<void> => {
    const sessionId = req.header("mcp-session-id");
    if (!sessionId) {
      jsonRpcError(res, 400, -32000, "Bad Request: Mcp-Session-Id header is required for this method.");
      return;
    }
    const session = streamableSessions.get(sessionId);
    if (!session) {
      jsonRpcError(res, 404, -32001, "Session not found or expired. Send a new initialize request.");
      return;
    }
    if (!ownsSession(req, session.principalId)) {
      jsonRpcError(res, 404, -32001, "Session not found or expired. Send a new initialize request.");
      return;
    }
    session.lastSeen = Date.now();
    if (req.method === "GET") {
      // A listening client sends nothing over the stream, so the stream
      // itself counts as activity until its socket closes.
      session.openStreams++;
      res.once("close", () => {
        session.openStreams = Math.max(0, session.openStreams - 1);
        session.lastSeen = Date.now();
      });
    }
    await session.transport.handleRequest(req, res);
  };

  app.post("/mcp", auth, async (req, res, next) => {
    try {
      const sessionId = req.header("mcp-session-id");
      const principal = principalFromAuthInfo((req as AuthenticatedRequest).auth);
      if (sessionId) {
        const session = streamableSessions.get(sessionId);
        if (!session) {
          jsonRpcError(res, 404, -32001, "Session not found or expired. Send a new initialize request.");
          return;
        }
        if (!ownsSession(req, session.principalId)) {
          jsonRpcError(res, 404, -32001, "Session not found or expired. Send a new initialize request.");
          return;
        }
        session.lastSeen = Date.now();
        await session.transport.handleRequest(req, res, req.body);
        return;
      }
      // The SDK rejects these after the transport exists; checking first
      // (with the SDK's own rules and wording) avoids building and
      // abandoning a full McpServer for every malformed initialize. The
      // media-type checks precede the shape check because a body that was
      // not JSON can never have parsed as an initialize request.
      const accept = req.header("accept") ?? "";
      if (!accept.includes("application/json") || !accept.includes("text/event-stream")) {
        jsonRpcError(res, 406, -32000, "Not Acceptable: Client must accept both application/json and text/event-stream");
        return;
      }
      if (req.is("application/json") !== "application/json") {
        jsonRpcError(res, 415, -32000, "Unsupported Media Type: Content-Type must be application/json");
        return;
      }
      if (!isInitializeRequest(req.body)) {
        jsonRpcError(res, 400, -32000, "Bad Request: no Mcp-Session-Id header and the body is not an initialize request.");
        return;
      }
      const server = createMcpServer(deps);
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        ...protection,
        onsessioninitialized: (id) => {
          streamableSessions.set(id, { transport, server, lastSeen: Date.now(), openStreams: 0, principalId: principal?.id ?? "unknown" });
          logger.info("streamable session initialized", { sessionId: id, principal: principal?.id });
        },
        onsessionclosed: (id) => {
          streamableSessions.delete(id);
          logger.info("streamable session closed", { sessionId: id });
        }
      });
      // onclose fires from transport.close(); the SDK's Protocol layer chains
      // its own cleanup after this handler, so calling server.close() here would
      // re-enter transport.close() and (for SSE, which has no re-entry guard)
      // recurse until the stack overflows.
      transport.onclose = () => {
        if (transport.sessionId) streamableSessions.delete(transport.sessionId);
      };
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (err) {
      next(err);
    }
  });

  app.get("/mcp", auth, (req, res, next) => {
    handleSessionRequest(req, res).catch(next);
  });

  app.delete("/mcp", auth, (req, res, next) => {
    handleSessionRequest(req, res).catch(next);
  });

  app.get("/sse", auth, async (req, res, next) => {
    try {
      const principal = principalFromAuthInfo((req as AuthenticatedRequest).auth);
      if (!principal) {
        jsonRpcError(res, 401, -32001, "Unauthorized.");
        return;
      }
      const transport = new SSEServerTransport("/messages", res, protection);
      const server = createMcpServer(deps);
      transport.onclose = () => {
        sseSessions.delete(transport.sessionId);
        logger.info("sse session closed", { sessionId: transport.sessionId });
      };
      await server.connect(transport);
      // The transport registers its 'close' listener inside start(); a client
      // that dropped the socket while auth was still awaiting never triggers
      // onclose, so check the socket before the session becomes reachable.
      if (res.destroyed || res.writableEnded) {
        await transport.close().catch(() => undefined);
        return;
      }
      sseSessions.set(transport.sessionId, { transport, server, res, principalId: principal.id });
      logger.info("sse session opened", { sessionId: transport.sessionId, principal: principal.id });
    } catch (err) {
      next(err);
    }
  });

  app.post("/messages", auth, async (req, res, next) => {
    try {
      const sessionId = typeof req.query.sessionId === "string" ? req.query.sessionId : "";
      const session = sseSessions.get(sessionId);
      if (!session) {
        jsonRpcError(res, 404, -32001, "SSE session not found. Reconnect to /sse.");
        return;
      }
      if (!ownsSession(req, session.principalId)) {
        jsonRpcError(res, 404, -32001, "SSE session not found. Reconnect to /sse.");
        return;
      }
      await session.transport.handlePostMessage(req, res, req.body);
    } catch (err) {
      next(err);
    }
  });

  app.use((req, res) => {
    if (jobs && req.path.toLowerCase().startsWith("/v1/")) {
      const message = "Unknown REST route. Bulk checks: POST /v1/jobs, GET /v1/jobs, GET or DELETE /v1/jobs/:id, GET /v1/jobs/:id/results.csv.";
      res.status(404).json({ error: { code: "NOT_FOUND", message, retryable: false, details: {} } });
      return;
    }
    res.status(404).json({ error: "not_found", message: "Unknown route. MCP endpoints: POST /mcp (Streamable HTTP), GET /sse + POST /messages (legacy SSE)." });
  });

  app.use((err: unknown, req: Request, res: Response, _next: NextFunction) => {
    const bodyError = clientBodyError(err);
    if (bodyError) logger.warn("http request body rejected", { path: req.path, type: bodyError.type, status: bodyError.status });
    else logger.error("http request failed", { error: err });
    if (res.headersSent) return;
    // Body-parser failures reach this handler before any route runs. The REST
    // API promises the tool error shape ({error:{code,message,retryable,details}}),
    // so its paths answer in that shape; the MCP endpoints keep JSON-RPC.
    if (req.path.toLowerCase().startsWith("/v1/")) {
      const toolError = (code: string, status: number, message: string, details: Record<string, unknown> = {}): void => {
        res.status(status).json({ error: { code, message, retryable: false, details } });
      };
      if (bodyError?.type === "entity.parse.failed") toolError("INVALID_ARGUMENT", 400, "Request body is not valid JSON.");
      else if (bodyError?.type === "entity.too.large") {
        toolError(
          "LIMIT_EXCEEDED",
          413,
          `Request body too large (JSON ${formatBytes(bodyLimits.json)}, CSV ${formatBytes(bodyLimits.text)}); split the list into smaller jobs.`,
          bodyError.limit !== null ? { limitBytes: bodyError.limit } : {}
        );
      } else if (bodyError) toolError("INVALID_ARGUMENT", bodyError.status, bodyError.message);
      else res.status(500).json({ error: { code: "INTERNAL_ERROR", message: "The request could not be completed.", retryable: true, details: {} } });
      return;
    }
    if (bodyError?.type === "entity.parse.failed") {
      jsonRpcError(res, 400, -32700, "Parse error: invalid JSON body.");
      return;
    }
    if (bodyError?.type === "entity.too.large") {
      jsonRpcError(res, 413, -32600, "Request body too large.");
      return;
    }
    if (bodyError) {
      jsonRpcError(res, bodyError.status, -32600, bodyError.message);
      return;
    }
    jsonRpcError(res, 500, -32603, "Internal server error.");
  });

  const reaper = setInterval(() => {
    const now = Date.now();
    for (const [id, session] of streamableSessions) {
      if (session.openStreams > 0) continue;
      if (now - session.lastSeen > config.http.sessionTtlMs) {
        logger.info("reaping idle streamable session", { sessionId: id });
        streamableSessions.delete(id);
        session.transport.close().catch(() => undefined);
      }
    }
    // SSE sessions are long-lived streams, so they are reaped when their
    // socket is gone rather than on an idle timer.
    for (const [id, session] of sseSessions) {
      if (session.res.destroyed || session.res.writableEnded) {
        logger.info("reaping dead sse session", { sessionId: id });
        sseSessions.delete(id);
        session.transport.close().catch(() => undefined);
      }
    }
  }, 60000);
  reaper.unref();

  const httpServer = await new Promise<HttpServer>((resolve, reject) => {
    const listener = app.listen(config.http.port, config.http.host, () => resolve(listener));
    listener.on("error", reject);
  });
  httpServer.keepAliveTimeout = 65000;
  httpServer.headersTimeout = 66000;

  logger.info("stack-and-dns-mcp listening", {
    url: config.http.publicUrl,
    host: config.http.host,
    port: config.http.port,
    requireAuth: config.auth.requireAuth,
    apiKeys: deps.keys.size,
    payments: deps.payments.availableMethods(),
    tools: registered.size,
    selfServe: deps.selfServe !== null
  });
  // Keys sold through self-serve signup authenticate as soon as they exist (the key store reads the database on every call), so a fresh self-serve deployment is not locked out.
  if (config.auth.requireAuth && !deps.keys.hasKeys && !deps.payments.enabled && deps.selfServe === null) {
    logger.warn("auth is required but no API keys, payment methods or self-serve signup are configured; every authenticated route will answer 401");
  }
  if (config.auth.sessionSecretGenerated && deps.payments.enabled) {
    logger.warn("STACKDNS_SESSION_SECRET is not set; payment session tokens will be invalidated on restart");
  }
  // The SDK checks Host only against a non-empty allowlist, so protection switched on without one blocks no rebinding attack; say so instead of implying it does.
  if (protection.enableDnsRebindingProtection && protection.allowedHosts === undefined) {
    logger.warn(
      "STACKDNS_DNS_REBINDING_PROTECTION is on but STACKDNS_ALLOWED_HOSTS is empty, so the Host header is not checked; list the Host values clients send (port included) to block DNS rebinding"
    );
  }
  if (protection.enableDnsRebindingProtection && config.http.allowedOrigins.includes("*")) {
    logger.warn('STACKDNS_ALLOWED_ORIGINS contains "*", so DNS-rebinding protection does not check the Origin header');
  }

  const originalClose = httpServer.close.bind(httpServer);
  httpServer.close = ((callback?: (err?: Error) => void) => {
    clearInterval(reaper);
    for (const session of streamableSessions.values()) session.transport.close().catch(() => undefined);
    for (const session of sseSessions.values()) session.transport.close().catch(() => undefined);
    return originalClose(callback);
  }) as typeof httpServer.close;

  return httpServer;
}
