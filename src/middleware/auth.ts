/**
 * Authentication: API keys (hashed at rest), HMAC session tokens issued after
 * a successful payment, and the Express middleware that turns a request into
 * an MCP AuthInfo carrying the resolved principal.
 */

import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { readFile } from "node:fs/promises";
import type { NextFunction, Request, RequestHandler, Response } from "express";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { httpLimitFor, PLAN_NAMES, TOOL_CREDIT_COST, type AppConfig, type PlanName } from "../config.js";
import { clientNetworkKey } from "../lib/net.js";
import { logger } from "../logger.js";
import { addressBucket } from "./addressThrottle.js";
import { encodeReceipt, type PaymentManager, type PaymentResult } from "./payments.js";
import type { RateLimiter } from "./rateLimit.js";
import type { SettlementState, UsageTracker } from "./usage.js";

export type PrincipalSource = "api-key" | "session" | "payment" | "local" | "anonymous";

export interface Principal {
  id: string;
  plan: PlanName;
  label: string;
  source: PrincipalSource;
}

export interface ApiKeyRecord {
  id: string;
  keyHash: string;
  prefix: string;
  plan: PlanName;
  label: string;
  active: boolean;
}

export const API_KEY_PREFIX = "sdm_live_";
export const SESSION_TOKEN_PREFIX = "sdm_sess.";
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const MIN_API_KEY_LENGTH = 16;
const MAX_API_KEY_LENGTH = 256;

export function hashApiKey(key: string): string {
  return createHash("sha256").update(key, "utf8").digest("hex");
}

export function generateApiKey(): string {
  return API_KEY_PREFIX + randomBytes(24).toString("base64url");
}

export function apiKeyPrefix(key: string): string {
  return key.slice(0, API_KEY_PREFIX.length + 6);
}

export function apiKeyId(keyHash: string): string {
  return `key_${keyHash.slice(0, 12)}`;
}

function hasUsableLength(key: string): boolean {
  return key.length >= MIN_API_KEY_LENGTH && key.length <= MAX_API_KEY_LENGTH;
}

/** A few leading characters for error messages; never enough of a short key to reconstruct it. */
function describeKey(key: string): string {
  return `${key.slice(0, 4)}...`;
}

function isPlanName(value: unknown): value is PlanName {
  return typeof value === "string" && (PLAN_NAMES as readonly string[]).includes(value);
}

function safeEqualHex(a: string, b: string): boolean {
  const bufferA = Buffer.from(a, "hex");
  const bufferB = Buffer.from(b, "hex");
  return bufferA.length === bufferB.length && bufferA.length > 0 && timingSafeEqual(bufferA, bufferB);
}

/** Database-backed keys (self-serve signup); implemented by KeyRepository. */
export interface KeyLookup {
  findActiveByHash(keyHash: string): ApiKeyRecord | null;
  countActive(): number;
}

export class ApiKeyStore {
  private readonly records = new Map<string, ApiKeyRecord>();
  private repository: KeyLookup | null = null;

  static parseInline(spec: string): ApiKeyRecord[] {
    const out: ApiKeyRecord[] = [];
    for (const entry of spec.split(",")) {
      const trimmed = entry.trim();
      if (!trimmed) continue;
      const [rawKey = "", rawPlan = "pro", ...labelParts] = trimmed.split(":");
      const key = rawKey.trim();
      if (!key) continue;
      // verify() refuses keys outside this range, so accepting one here would
      // configure a key that can never authenticate while still switching the
      // zero-config plan from local to free.
      if (!hasUsableLength(key)) {
        throw new Error(`STACKDNS_API_KEYS entry "${describeKey(key)}" must be between ${MIN_API_KEY_LENGTH} and ${MAX_API_KEY_LENGTH} characters.`);
      }
      const plan = rawPlan.trim().toLowerCase();
      if (!isPlanName(plan) || plan === "local" || plan === "payg") {
        throw new Error(`STACKDNS_API_KEYS entry "${describeKey(key)}" has invalid plan "${rawPlan}" (use free, pro or enterprise).`);
      }
      const keyHash = hashApiKey(key);
      out.push({ id: apiKeyId(keyHash), keyHash, prefix: apiKeyPrefix(key), plan, label: labelParts.join(":").trim() || "inline", active: true });
    }
    return out;
  }

  static async parseFile(filePath: string): Promise<ApiKeyRecord[]> {
    const raw = await readFile(filePath, "utf8");
    const parsed = JSON.parse(raw) as unknown;
    const entries = Array.isArray(parsed) ? parsed : parsed && typeof parsed === "object" && Array.isArray((parsed as { keys?: unknown }).keys) ? (parsed as { keys: unknown[] }).keys : null;
    if (!entries) throw new Error(`API key file ${filePath} must be a JSON array (or an object with a "keys" array).`);
    const out: ApiKeyRecord[] = [];
    entries.forEach((entry, index) => {
      if (!entry || typeof entry !== "object") throw new Error(`API key file entry ${index} is not an object.`);
      const obj = entry as Record<string, unknown>;
      let keyHash: string;
      let prefix: string;
      if (typeof obj.key === "string" && obj.key.length > 0) {
        if (!hasUsableLength(obj.key)) {
          throw new Error(`API key file entry ${index} ("${describeKey(obj.key)}") must be between ${MIN_API_KEY_LENGTH} and ${MAX_API_KEY_LENGTH} characters.`);
        }
        keyHash = hashApiKey(obj.key);
        prefix = apiKeyPrefix(obj.key);
      } else if (typeof obj.keyHash === "string" && /^[a-f0-9]{64}$/i.test(obj.keyHash)) {
        keyHash = obj.keyHash.toLowerCase();
        prefix = typeof obj.prefix === "string" ? obj.prefix : "sdm_live_";
      } else {
        throw new Error(`API key file entry ${index} needs a "key" or a 64-hex "keyHash".`);
      }
      const plan = typeof obj.plan === "string" ? obj.plan.toLowerCase() : "pro";
      if (!isPlanName(plan) || plan === "local" || plan === "payg") throw new Error(`API key file entry ${index} has invalid plan "${String(obj.plan)}".`);
      out.push({
        id: typeof obj.id === "string" && obj.id.length > 0 ? obj.id : apiKeyId(keyHash),
        keyHash,
        prefix,
        plan,
        label: typeof obj.label === "string" ? obj.label : "",
        active: obj.active !== false
      });
    });
    return out;
  }

  static async fromConfig(config: AppConfig): Promise<ApiKeyStore> {
    const store = new ApiKeyStore();
    for (const record of ApiKeyStore.parseInline(config.auth.apiKeysInline)) store.add(record);
    if (config.auth.apiKeysFile) {
      try {
        for (const record of await ApiKeyStore.parseFile(config.auth.apiKeysFile)) store.add(record);
      } catch (err) {
        // A key file that does not exist yet is the normal state of a fresh
        // deployment (an empty volume, a template .env): start with zero
        // file-backed keys and say so, instead of crash-looping the server.
        // A file that exists but cannot be parsed is still fatal.
        if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
        logger.warn("STACKDNS_API_KEYS_FILE does not exist; starting with no file-backed API keys", { file: config.auth.apiKeysFile });
      }
    }
    return store;
  }

  add(record: ApiKeyRecord): void {
    this.records.set(record.keyHash, record);
  }

  /** Also accepts keys issued into the database (self-serve signup and rotation). */
  attachRepository(repository: KeyLookup): void {
    this.repository = repository;
  }

  /** Keys configured through STACKDNS_API_KEYS / STACKDNS_API_KEYS_FILE. */
  get size(): number {
    return this.records.size;
  }

  /** True when any key can authenticate: configured keys, or self-serve keys issued into the database. */
  get hasKeys(): boolean {
    return this.records.size > 0 || (this.repository !== null && this.repository.countActive() > 0);
  }

  list(): ApiKeyRecord[] {
    return [...this.records.values()];
  }

  verify(rawKey: string): ApiKeyRecord | null {
    if (typeof rawKey !== "string" || rawKey.length < MIN_API_KEY_LENGTH || rawKey.length > MAX_API_KEY_LENGTH) return null;
    const hash = hashApiKey(rawKey);
    // A database error propagates: the caller answers 500 rather than
    // telling a paying customer that a valid key is unknown.
    const candidate = this.records.get(hash) ?? this.repository?.findActiveByHash(hash) ?? undefined;
    if (!candidate || !candidate.active) return null;
    return safeEqualHex(candidate.keyHash, hash) ? candidate : null;
  }
}

export interface SessionClaims {
  sub: string;
  plan: PlanName;
  label: string;
  iat: number;
  exp: number;
}

export class SessionTokenService {
  constructor(private readonly secret: string) {}

  private sign(payload: string): string {
    return createHmac("sha256", this.secret).update(payload).digest("base64url");
  }

  issue(claims: Omit<SessionClaims, "iat" | "exp">, ttlMs: number = SESSION_TTL_MS): string {
    const now = Date.now();
    const full: SessionClaims = { ...claims, iat: now, exp: now + ttlMs };
    const payload = Buffer.from(JSON.stringify(full), "utf8").toString("base64url");
    return `${SESSION_TOKEN_PREFIX}${payload}.${this.sign(payload)}`;
  }

  verify(token: string): SessionClaims | null {
    if (!token.startsWith(SESSION_TOKEN_PREFIX)) return null;
    const body = token.slice(SESSION_TOKEN_PREFIX.length);
    const dot = body.lastIndexOf(".");
    if (dot === -1) return null;
    const payload = body.slice(0, dot);
    const signature = body.slice(dot + 1);
    const expected = this.sign(payload);
    const sigBuffer = Buffer.from(signature, "base64url");
    const expBuffer = Buffer.from(expected, "base64url");
    if (sigBuffer.length !== expBuffer.length || !timingSafeEqual(sigBuffer, expBuffer)) return null;
    try {
      const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as Partial<SessionClaims>;
      if (typeof claims.sub !== "string" || !isPlanName(claims.plan) || typeof claims.exp !== "number" || typeof claims.iat !== "number") return null;
      if (claims.exp < Date.now()) return null;
      return { sub: claims.sub, plan: claims.plan, label: typeof claims.label === "string" ? claims.label : "", iat: claims.iat, exp: claims.exp };
    } catch {
      return null;
    }
  }
}

export interface ExtractedCredentials {
  apiKey: string | null;
  sessionToken: string | null;
  payment: { value: string; source: "authorization" | "x-payment" } | null;
  /** X-Session-Token sent alongside a payment credential to top up an existing prepaid principal. */
  topUpToken: string | null;
}

export function extractCredentials(req: Request): ExtractedCredentials {
  const out: ExtractedCredentials = { apiKey: null, sessionToken: null, payment: null, topUpToken: null };
  const topUp = req.header("x-session-token");
  if (topUp && topUp.trim().length > 0) out.topUpToken = topUp.trim().replace(/^bearer\s+/i, "");
  const header = req.header("authorization") ?? "";
  const space = header.indexOf(" ");
  const scheme = space === -1 ? header : header.slice(0, space);
  const value = space === -1 ? "" : header.slice(space + 1).trim();
  if (/^bearer$/i.test(scheme) && value) {
    if (value.startsWith(SESSION_TOKEN_PREFIX)) out.sessionToken = value;
    else out.apiKey = value;
  } else if (/^payment$/i.test(scheme) && value) {
    out.payment = { value, source: "authorization" };
  }
  const xApiKey = req.header("x-api-key");
  if (xApiKey && !out.apiKey) out.apiKey = xApiKey.trim();
  const xPayment = req.header("x-payment");
  if (xPayment && !out.payment) out.payment = { value: xPayment.trim(), source: "x-payment" };
  return out;
}

export function principalToAuthInfo(principal: Principal, token: string): AuthInfo {
  return {
    token: token || `anonymous:${principal.id}`,
    clientId: principal.id,
    scopes: [`plan:${principal.plan}`, "tools:call"],
    extra: { principal }
  };
}

export function principalFromAuthInfo(authInfo: AuthInfo | undefined): Principal | null {
  const candidate = authInfo?.extra?.principal;
  if (!candidate || typeof candidate !== "object") return null;
  const p = candidate as Partial<Principal>;
  if (typeof p.id !== "string" || !isPlanName(p.plan) || typeof p.source !== "string") return null;
  return { id: p.id, plan: p.plan, label: typeof p.label === "string" ? p.label : "", source: p.source as PrincipalSource };
}

export function resolveLocalPrincipal(config: AppConfig, keys: ApiKeyStore): Principal {
  if (!keys.hasKeys) {
    // STACKDNS_API_KEY only selects one of this process's own keys: a stdio server never contacts a hosted
    // deployment. Without keys it is ignored, which an operator expecting to be metered against it would
    // otherwise never learn. Called once, at startup.
    if (config.auth.clientApiKey && config.transport === "stdio") {
      logger.warn(
        "STACKDNS_API_KEY is set but no API keys are configured in this process (STACKDNS_API_KEYS or STACKDNS_API_KEYS_FILE), so it is ignored; a stdio server never contacts a hosted deployment"
      );
    }
    // With no keys configured the zero-config local plan applies, unless the
    // operator explicitly demanded authentication, in which case there is
    // nothing to authenticate against and every call must be refused.
    if (config.auth.requireAuth) {
      return { id: "unauthenticated", plan: "free", label: "auth required but no api keys configured", source: "anonymous" };
    }
    return { id: "local", plan: "local", label: "local stdio session", source: "local" };
  }
  if (config.auth.clientApiKey) {
    const record = keys.verify(config.auth.clientApiKey);
    if (record) return { id: record.id, plan: record.plan, label: record.label, source: "api-key" };
    logger.warn("STACKDNS_API_KEY does not match any configured key");
  }
  return { id: "unauthenticated", plan: "free", label: "no api key", source: "anonymous" };
}

export interface AuthMiddlewareDeps {
  config: AppConfig;
  keys: ApiKeyStore;
  sessions: SessionTokenService;
  payments: PaymentManager;
  usage: UsageTracker;
  limiter: RateLimiter;
}

export type AuthenticatedRequest = Request & { auth?: AuthInfo };

function resourceUrl(config: AppConfig, req: Request): string {
  return `${config.http.publicUrl}${req.originalUrl.split("?")[0] ?? req.path}`;
}

function deny(res: Response, status: number, code: string, message: string, extra: Record<string, unknown> = {}): void {
  if (status === 401) res.setHeader("WWW-Authenticate", `Bearer realm="stack-and-dns-mcp", error="${code}"`);
  res.status(status).json({ error: code, message, ...extra });
}

async function challenge(res: Response, deps: AuthMiddlewareDeps, req: Request, extra: Record<string, unknown>, status = 402): Promise<void> {
  const created = await deps.payments.createChallenge(resourceUrl(deps.config, req));
  for (const [name, value] of Object.entries(deps.payments.challengeHeaders(created))) res.setHeader(name, value);
  res.status(status).json({ ...deps.payments.challengeBody(created), ...extra });
}

/**
 * Answers a spending request of an exhausted session one of whose payments is still pending
 * (PaymentManager.pendingFor). Never a payment demand: the money has (or may have) moved, so an auto-paying
 * client would pay twice.
 */
function denyPendingPurchase(res: Response, pending: SettlementState | "unavailable"): void {
  switch (pending) {
    case "unavailable":
      // A payment may be pending and cannot be checked.
      res.setHeader("Retry-After", "5");
      deny(res, 503, "payment_recording_failed", "The state of this session's payments could not be checked right now. Do not pay again; retry shortly.");
      return;
    case "unknown":
      deny(res, 502, "x402_settlement_unconfirmed", "A payment for this session did not report its outcome. Do not pay again; retry with the same payment header later or contact support.");
      return;
    case "settling":
      res.setHeader("Retry-After", "2");
      deny(res, 409, "payment_redemption_in_progress", "A payment for this session is being settled right now. Do not pay again; retry this request in a moment.");
      return;
    case "settled":
      res.setHeader("Retry-After", "5");
      deny(res, 503, "payment_recording_failed", "A payment for this session settled but is not recorded yet. Do not pay again; retry shortly.");
      return;
  }
}

/**
 * Zero-cost tools that still spend credits: a bulk submission is charged per
 * accepted domain by its handler (src/store/jobs.ts), not by the meter, so
 * its TOOL_CREDIT_COST of 0 does not make it free.
 */
const SPENDING_CONTROL_TOOLS: ReadonlySet<string> = new Set(["start_bulk_check"]);

/**
 * Whether a request can spend prepaid credits: a paid tool call or a bulk
 * job submission (POST /v1/jobs or the start_bulk_check tool). An exhausted
 * prepaid session is only challenged for these, so it can still read (and
 * cancel) what it already paid for.
 */
function requestMaySpendCredits(req: Request): boolean {
  // Express routes match case-insensitively, so POST /V1/JOBS reaches the jobs handler too.
  const path = (req.originalUrl.split("?")[0] ?? req.path).replace(/\/+$/, "").toLowerCase();
  if (req.method === "POST" && path === "/v1/jobs") return true;
  if (req.method === "POST" && (path === "/mcp" || path === "/messages")) {
    const body: unknown = req.body;
    const messages = Array.isArray(body) ? body : [body];
    return messages.some((m) => {
      if (!m || typeof m !== "object" || (m as { method?: unknown }).method !== "tools/call") return false;
      const name = (m as { params?: { name?: unknown } }).params?.name;
      const cost = typeof name === "string" ? (TOOL_CREDIT_COST as Record<string, number>)[name] : undefined;
      // An unknown tool is treated as paid.
      return cost === undefined || cost > 0 || (typeof name === "string" && SPENDING_CONTROL_TOOLS.has(name));
    });
  }
  return false;
}

export function createAuthMiddleware(deps: AuthMiddlewareDeps): RequestHandler {
  const { config, keys, sessions, payments, usage, limiter } = deps;
  // The open "local" tier is only for servers that sell nothing. It is decided
  // once: a per-request check of the key table would hand anonymous callers
  // the local tier whenever the last subscriber lapsed.
  const sellsAccess = keys.hasKeys || payments.enabled || Boolean(config.payments.stripe.secretKey && (config.selfServe.prices.pro || config.selfServe.prices.enterprise));
  const anonymousPlan: PlanName = sellsAccess ? "free" : "local";
  return (req: Request, res: Response, next: NextFunction): void => {
    void (async () => {
      const credentials = extractCredentials(req);
      let principal: Principal | null = null;
      let token = "";

      // Pre-authentication flood control keyed by client address. Every path
      // that ends before a principal is resolved (bad key, bad token, payment
      // redemption, 402 challenge minting) passes through here so that
      // unauthenticated traffic cannot drive unbounded Stripe/facilitator
      // calls or key guessing.
      const clientIp = clientNetworkKey(req.ip ?? req.socket.remoteAddress ?? "unknown");
      const ipBucket = addressBucket(req);
      const throttledUnauthenticated = (): boolean => {
        const flood = limiter.consumeHttp(ipBucket, config.auth.unauthenticatedPerMinute);
        if (flood.allowed) return false;
        res.setHeader("Retry-After", String(Math.ceil(flood.retryAfterMs / 1000)));
        deny(res, 429, "rate_limited", "Too many unauthenticated requests from this address. Retry after the indicated delay.", { retryAfterMs: flood.retryAfterMs });
        return true;
      };

      if (credentials.apiKey) {
        const record = keys.verify(credentials.apiKey);
        if (!record) {
          if (throttledUnauthenticated()) return;
          deny(res, 401, "invalid_api_key", "The API key is not recognized or has been revoked.");
          return;
        }
        principal = { id: record.id, plan: record.plan, label: record.label, source: "api-key" };
        token = credentials.apiKey;
      } else if (credentials.payment) {
        // A payment credential is handled before any session token so that a
        // prepaid client whose balance ran out can keep its Bearer session
        // token and simply add X-PAYMENT / Authorization: Payment to top up.
        // A session token presented alongside the payment (X-Session-Token, or
        // Authorization: Bearer with X-PAYMENT) names the prepaid principal to
        // top up; an unverifiable one is rejected before any money moves.
        const topUpRaw = credentials.topUpToken ?? credentials.sessionToken;
        const topUp = topUpRaw ? sessions.verify(topUpRaw) : null;
        if (topUpRaw && (!topUp || topUp.plan !== "payg")) {
          if (throttledUnauthenticated()) return;
          deny(
            res,
            401,
            "invalid_session_token",
            "The session token sent with the payment is invalid, expired or not a prepaid token. Omit it to redeem onto a new principal, or send a valid prepaid token to top up."
          );
          return;
        }
        // A funded prepaid session that also carries a payment header (x402
        // client libraries re-attach the last X-PAYMENT to every request) is
        // served from its own balance whenever that payment cannot be
        // redeemed, instead of being locked out of credits it already owns.
        // An exhausted session is still served on requests that cannot spend
        // (reading or cancelling jobs it paid for), whatever payment header
        // its client re-attaches.
        const sessionBalance = topUp ? (usage.creditsRemaining(topUp.sub) ?? 0) : 0;
        const servableSession = topUp && (sessionBalance > 0 || !requestMaySpendCredits(req)) ? topUp : null;

        let outcome: PaymentResult;
        if (!payments.enabled) {
          outcome = { ok: false, code: "payments_disabled", message: "This server does not accept payment credentials." };
        } else {
          const credential = payments.parseCredential(credentials.payment.value, credentials.payment.source);
          if (!credential) {
            outcome = { ok: false, code: "invalid_payment_credential", message: "The payment credential could not be parsed. Send base64url-encoded JSON." };
          } else {
            // A servable session re-attaching a payment that is answered without an
            // upstream call (already redeemed, unconfirmed inside its re-verification
            // window or past its validBefore, and the like: PaymentManager.answersLocally)
            // is bounded by its own per-principal ceiling below, not by the
            // pre-authentication address bucket.
            if (!(servableSession && payments.answersLocally(credential)) && throttledUnauthenticated()) return;
            // The credits go to the top-up target, or to a new principal per
            // payment. The derived id is a function of the public payment id,
            // so it is flagged apart from a top-up (which names who is asking).
            outcome = await payments.redeem(credential, ({ method, paymentId }) =>
              topUp
                ? { principalId: topUp.sub, label: topUp.label, topUp: true }
                : { principalId: `pay_${createHash("sha256").update(paymentId).digest("hex").slice(0, 16)}`, label: `${method}:${paymentId}`, topUp: false }
            );
          }
        }

        if (!outcome.ok) {
          const unconfirmed = outcome.code === "x402_settlement_unconfirmed";
          let served = servableSession;
          let servedBalance = sessionBalance;
          if (unconfirmed && topUp && !served) {
            // An exhausted session on a spending request follows the same purchase rule as without the header
            // (pendingFor): an unconfirmed payment blocks its purchases for UNKNOWN_BLOCKS_PURCHASE_MS after the
            // marker's last update, not for as long as the marker is kept (400 days). Otherwise a client that
            // re-attaches the header to every request would never see a payment demand, so it would never sign
            // a new payment and replace the header.
            const pending = payments.pendingFor(topUp.sub);
            if (pending === null) {
              // As in the bare-session branch: a sibling may have just recorded one of this session's payments.
              const recheck = usage.creditsRemaining(topUp.sub) ?? 0;
              if (recheck <= 0) {
                res.setHeader("X-Payment-Status", outcome.code);
                await challenge(res, deps, req, {
                  reason: "credits_exhausted",
                  principal: topUp.sub,
                  paymentStatus: outcome.code,
                  message:
                    "This session's credits are used up. The payment header sent with this request is still unconfirmed (the operator reconciles it), and it no longer blocks buying more credits with a new payment."
                });
                return;
              }
              served = topUp;
              servedBalance = recheck;
            } else if (pending !== "unknown") {
              denyPendingPurchase(res, pending);
              return;
            }
          }
          // An unconfirmed payment is answered 502 only when nothing else can serve the request: a session that
          // can be served (funded, or exhausted on a request that cannot spend) is served from its balance and
          // told the payment's state in X-Payment-Status. Either way, never a new payment demand while the
          // payment still blocks its session's purchases.
          if (outcome.code === "payment_recording_failed" || (unconfirmed && !served)) {
            // This request presented the payment first and had it verified and
            // settled (or its own settle outcome is unknown), the same trust a
            // success mints on, so it carries the session the credits belong
            // to. A retry gets one only as the effective first presenter, when
            // the process that began the settle died before answering
            // (payments.ts settleX402); otherwise the payment payload is public
            // once settled and proves nothing. A top-up already holds its session.
            const handedBack = outcome.grant && !topUp ? sessions.issue({ sub: outcome.grant.principalId, plan: "payg", label: outcome.grant.label }) : null;
            const extra: Record<string, unknown> = {};
            if (handedBack && outcome.grant) {
              res.setHeader("X-Session-Token", handedBack);
              Object.assign(extra, { principal: outcome.grant.principalId, sessionToken: handedBack });
              logger.info("session issued with an unrecorded payment", { reason: outcome.code, principal: outcome.grant.principalId });
            }
            if (outcome.code === "payment_recording_failed") {
              // Verified (and for x402 settled) but not yet recorded: never a
              // fresh payment demand, and a retry of the same credential is safe.
              res.setHeader("Retry-After", "5");
              deny(res, 503, outcome.code, outcome.message, extra);
              return;
            }
            // Money may have moved but the facilitator gave nothing to tie it
            // to, and no session can serve this request: an upstream problem,
            // not a reason to demand payment.
            deny(res, 502, outcome.code, outcome.message, extra);
            return;
          }
          if (served) {
            principal = { id: served.sub, plan: "payg", label: served.label, source: "session" };
            token = topUpRaw as string;
            res.setHeader("X-Payment-Status", outcome.code);
            const fields = { principal: served.sub, reason: outcome.code, creditsRemaining: servedBalance };
            if (unconfirmed) logger.warn("x402 settlement unconfirmed; request served from the prepaid session", fields);
            else logger.info("payment header ignored; request served from the prepaid session", fields);
          } else if (outcome.code === "payment_redemption_in_progress") {
            // A concurrent request holds this credential; never answer with a
            // fresh payment demand.
            res.setHeader("Retry-After", "2");
            deny(res, 409, outcome.code, outcome.message);
            return;
          } else if (outcome.code === "payment_already_redeemed") {
            // The credential's credits were already delivered (and possibly
            // spent). Answer 409 so nothing auto-pays on a duplicate, but carry
            // the challenge so a client whose library re-attaches its last
            // payment header still learns how to buy more.
            if (payments.enabled) {
              await challenge(res, deps, req, { reason: outcome.code, message: outcome.message }, 409);
            } else {
              deny(res, 409, outcome.code, outcome.message);
            }
            return;
          } else if (outcome.code === "invalid_x402_payload" || outcome.code === "missing_payment_reference" || outcome.code === "invalid_payment_credential" || outcome.code === "payments_disabled") {
            if (throttledUnauthenticated()) return;
            deny(res, 400, outcome.code, outcome.message);
            return;
          } else {
            await challenge(res, deps, req, { reason: outcome.code, message: outcome.message });
            return;
          }
        } else {
          const result = outcome;
          // The credits were granted together with the redemption.
          const { principalId, label } = result;
          const sessionToken = sessions.issue({ sub: principalId, plan: "payg", label });
          principal = { id: principalId, plan: "payg", label, source: "payment" };
          token = sessionToken;
          const receipt = { ...result.receipt, principal: principalId, creditsRemaining: usage.creditsRemaining(principalId), sessionToken };
          res.setHeader("Payment-Receipt", encodeReceipt(receipt));
          res.setHeader("X-Session-Token", sessionToken);
          logger.info("payment redeemed", {
            method: result.method,
            paymentId: result.paymentId,
            credits: result.credits,
            principal: principalId,
            topUp: topUp !== null
          });
        }
      } else if (credentials.sessionToken) {
        const claims = sessions.verify(credentials.sessionToken);
        if (!claims) {
          if (throttledUnauthenticated()) return;
          deny(res, 401, "invalid_session_token", "The session token is invalid or expired. Complete a new payment to obtain a fresh token.");
          return;
        }
        principal = { id: claims.sub, plan: claims.plan, label: claims.label, source: "session" };
        token = credentials.sessionToken;
        if (claims.plan === "payg") {
          const remaining = usage.creditsRemaining(claims.sub);
          if ((remaining === null || remaining <= 0) && payments.enabled && requestMaySpendCredits(req)) {
            if (throttledUnauthenticated()) return;
            // The session a 503 or 502 handed out has no credits until its payment is recorded. A payment
            // demand now would make an auto-paying client pay again for money that has (or may have) moved,
            // so the session gets the same answer a retry of that payment's header would get.
            const pending = payments.pendingFor(claims.sub);
            if (pending !== null) {
              denyPendingPurchase(res, pending);
              return;
            }
            // Nothing pending, but a sibling may have recorded this session's payment (crediting it and removing
            // its marker) between the balance read above and that lookup. One more read closes the gap.
            const recheck = usage.creditsRemaining(claims.sub);
            if (recheck === null || recheck <= 0) {
              await challenge(res, deps, req, { reason: "credits_exhausted", principal: claims.sub });
              return;
            }
          }
        }
      } else if (!config.auth.requireAuth) {
        // An anonymous principal is keyed by client address, so a browser page
        // on another origin would act (and read results) as its visitor.
        const origin = req.header("origin");
        const allowedOrigins = config.http.allowedOrigins;
        if (origin && !allowedOrigins.includes(origin) && !allowedOrigins.includes("*")) {
          deny(res, 403, "origin_not_allowed", "Anonymous requests from a browser origin are refused. Send an API key, or list the origin in STACKDNS_ALLOWED_ORIGINS.");
          return;
        }
        // req.ip is only trustworthy when STACKDNS_TRUST_PROXY names the real
        // proxy hops; the raw address is deliberately not persisted in the label.
        const anonymousId = `anon_${createHash("sha256").update(clientIp).digest("hex").slice(0, 12)}`;
        principal = { id: anonymousId, plan: anonymousPlan, label: "anonymous", source: "anonymous" };
      } else if (payments.enabled) {
        if (throttledUnauthenticated()) return;
        await challenge(res, deps, req, {
          message: "Authenticate with an API key (Authorization: Bearer sdm_live_... or X-API-Key) or complete the payment challenge."
        });
        return;
      } else {
        if (throttledUnauthenticated()) return;
        deny(res, 401, "unauthorized", "Provide an API key via Authorization: Bearer <key> or the X-API-Key header.", {
          docs: `${config.http.publicUrl}/`
        });
        return;
      }

      const limits = config.auth.planLimits[principal.plan];
      // Coarse per-request ceiling (initialize, tools/list, ping and tool
      // calls alike); the plan's per-minute tool-call quota is enforced
      // separately by the meter and is what X-RateLimit-Limit advertises.
      const httpLimit = httpLimitFor(limits);
      const flood = limiter.consumeHttp(principal.id, httpLimit);
      res.setHeader("X-RateLimit-Limit", String(limits.perMinute));
      res.setHeader("X-RateLimit-Http-Limit", String(httpLimit));
      res.setHeader("X-RateLimit-Plan", principal.plan);
      if (!flood.allowed) {
        res.setHeader("Retry-After", String(Math.ceil(flood.retryAfterMs / 1000)));
        deny(res, 429, "rate_limited", "Too many requests. Slow down and retry after the indicated delay.", { retryAfterMs: flood.retryAfterMs });
        return;
      }
      const snapshot = limiter.snapshot(principal.id, principal.plan);
      res.setHeader("X-RateLimit-Remaining", String(snapshot.remainingThisMinute));
      res.setHeader("X-RateLimit-Reset", String(Math.ceil(snapshot.resetAtMs / 1000)));

      (req as AuthenticatedRequest).auth = principalToAuthInfo(principal, token);
      next();
    })().catch((err: unknown) => {
      logger.error("auth middleware failure", { error: err });
      if (!res.headersSent) deny(res, 500, "auth_error", "Authentication could not be completed.");
    });
  };
}
