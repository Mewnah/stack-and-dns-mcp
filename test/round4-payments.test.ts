/**
 * Regression tests for the round-4 ledger/payment fixes:
 *   G4  a settled x402 payment whose recording failed is finished on retry of the same header (and in the background)
 *   G5  a /settle transport error or gateway failure is "unconfirmed" (502), never a fresh 402
 *   G6  an exhausted prepaid session re-attaching X-PAYMENT is still served on routes that cannot spend
 *   G7  a funded session re-attaching an already-redeemed payment is not charged to the pre-auth address bucket
 *   G8  lock contention at startup makes openDatabase reject instead of silently running without the shared ledger
 *
 * Round 5 follow-ups (appended at the end):
 *   G4  a retry of a settled payment never collects a session token by its public payload alone; the first
 *       503/502 carries it instead, and durable settlement markers let a sibling process or a restart finish it
 *   G5  every answer after an unknown settle (a failed /verify, an expired authorization, success without a
 *       transaction id) stays "unconfirmed", never a fresh 402
 *   plus case-insensitive spending routes and a stdio server that runs without a locked database
 *
 * Round 6 follow-ups (appended at the end):
 *   P1  the session a 503 or 502 handed out is answered with its payment's pending state, never a fresh 402,
 *       and a restarted process records settled markers without waiting for an x402 request
 *   P2  after an unknown settle, a retry presenting the payload without the stored target's session gets no token
 *   P3  a sibling that adopts a settled marker while the settling request waits out a lock leaves that request its
 *       session, and the recording loop is bounded by wall time
 *   P4  a stdio server's default lock budget ends well inside an MCP client's initialize timeout
 *
 * Round 7 follow-ups (appended at the end):
 *   P2  a first presenter's 502 carries no session when its 'unknown' marker could not be written
 *   P1  a leftover marker of a recorded payment is not pending, the recording timer removes it (and a refused
 *       settle's marker, with a compare-and-delete), and an unreadable pending state is a 503, never a 402
 *
 * Everything runs against local stubs: a 127.0.0.1 facilitator/Stripe stub, an
 * in-memory SQLite ledger and an Express app with the real auth middleware.
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, describe, it, mock } from "node:test";
import { DatabaseSync } from "node:sqlite";
import express from "express";
import { loadConfig, type AppConfig } from "../src/config.js";
import { setLogLevel } from "../src/logger.js";
import { ApiKeyStore, createAuthMiddleware, principalFromAuthInfo, SessionTokenService, type AuthenticatedRequest } from "../src/middleware/auth.js";
import { encodeCredential, PaymentManager, x402ReplayKey, type PaymentCredential, type PaymentResult } from "../src/middleware/payments.js";
import { RateLimiter } from "../src/middleware/rateLimit.js";
import { REDEEM_LOCK_BUDGET_MS, UsageTracker, type GuardFamily, type SettlementMarker, type SettlementStart, type SettlementState, type SharedLedger } from "../src/middleware/usage.js";
import { CreditLedger } from "../src/store/credits.js";
import { BUSY_TIMEOUT_MS, MIGRATIONS, openDatabase } from "../src/store/db.js";
import { openStorage, STDIO_LOCK_BUDGET_MS } from "../src/store/index.js";

setLogLevel("silent");

const PAY_TO = "0x2222222222222222222222222222222222222222";
const PAYER = "0x1111111111111111111111111111111111111111";
const CREDITS = 100;
const SESSION_SECRET = "round4-payments-session-secret-0123456789";

// ---------------------------------------------------------------------------
// Upstream stub: an x402 facilitator (/verify, /settle) that models on-chain
// state (a spent EIP-3009 nonce can never verify or settle again), plus the
// two Stripe endpoints redemption reads.
// ---------------------------------------------------------------------------

type VerifyMode = "strict" | "lenient" | "reset" | "gateway-html";
type SettleMode = "ok" | "ok-no-tx" | "reset-after-broadcast" | "reset-before-broadcast" | "gateway-504" | "json-500" | "refuse";

interface Upstream {
  base: string;
  calls: string[];
  spent: Set<string>;
  verifyMode: VerifyMode;
  settleMode: SettleMode;
  count(pathPrefix: string): number;
  close(): Promise<void>;
}

async function startUpstream(): Promise<Upstream> {
  const state = {
    calls: [] as string[],
    spent: new Set<string>(),
    verifyMode: "strict" as VerifyMode,
    settleMode: "ok" as SettleMode
  };
  const server = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (chunk: Buffer) => (raw += chunk.toString()));
    req.on("end", () => {
      const url = new URL(req.url ?? "/", "http://stub");
      state.calls.push(url.pathname);
      const json = (status: number, body: unknown): void => {
        res.statusCode = status;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify(body));
      };
      let body: Record<string, unknown> = {};
      try {
        body = raw ? (JSON.parse(raw) as Record<string, unknown>) : {};
      } catch {
        // Stripe requests are form-encoded; they carry nothing the stub needs.
      }
      const payment = body.paymentPayload as { payload?: { authorization?: { nonce?: string; from?: string } } } | undefined;
      const nonce = String(payment?.payload?.authorization?.nonce ?? "");
      const payer = payment?.payload?.authorization?.from ?? PAYER;

      if (url.pathname === "/verify") {
        if (state.verifyMode === "reset") {
          req.socket.destroy();
          return;
        }
        if (state.verifyMode === "gateway-html") {
          res.statusCode = 502;
          res.setHeader("content-type", "text/html");
          res.end("<html><body><h1>502 Bad Gateway</h1></body></html>");
          return;
        }
        if (nonce.startsWith("0xbad")) return json(200, { isValid: false, invalidReason: "invalid_exact_evm_payload_signature", payer });
        if (state.verifyMode === "strict" && state.spent.has(nonce)) return json(200, { isValid: false, invalidReason: "invalid_exact_evm_payload_authorization_used", payer });
        return json(200, { isValid: true, payer });
      }
      if (url.pathname === "/settle") {
        const transaction = `0x${createHash("sha256").update(nonce).digest("hex")}`;
        switch (state.settleMode) {
          case "ok":
            if (state.spent.has(nonce)) return json(400, { success: false, errorReason: "invalid_exact_evm_payload_authorization_used", transaction: "" });
            state.spent.add(nonce);
            return json(200, { success: true, transaction, network: "base", payer });
          case "ok-no-tx":
            state.spent.add(nonce);
            return json(200, { success: true, network: "base", payer });
          case "reset-after-broadcast":
            state.spent.add(nonce);
            req.socket.destroy();
            return;
          case "reset-before-broadcast":
            req.socket.destroy();
            return;
          case "gateway-504":
            state.spent.add(nonce);
            res.statusCode = 504;
            res.setHeader("content-type", "text/html");
            res.end("<html><body><h1>504 Gateway Time-out</h1></body></html>");
            return;
          case "json-500":
            state.spent.add(nonce);
            return json(500, { error: "internal_error" });
          case "refuse":
            return json(400, { success: false, errorReason: "insufficient_funds", transaction: "" });
        }
      }
      const checkout = /^\/v1\/checkout\/sessions\/(.+)$/.exec(url.pathname);
      if (req.method === "GET" && checkout) {
        return json(200, { id: decodeURIComponent(checkout[1] as string), payment_status: "paid", payment_intent: "pi_old_redeemed" });
      }
      const intent = /^\/v1\/payment_intents\/(.+)$/.exec(url.pathname);
      if (req.method === "GET" && intent) {
        return json(200, {
          id: decodeURIComponent(intent[1] as string),
          status: "succeeded",
          created: Math.floor(Date.now() / 1000),
          amount: 500,
          amount_received: 500,
          currency: "usd",
          metadata: { service: "stack-and-dns-mcp", credits: String(CREDITS) }
        });
      }
      json(404, { error: { message: "unknown stub route" } });
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return {
    base,
    get calls() {
      return state.calls;
    },
    get spent() {
      return state.spent;
    },
    get verifyMode() {
      return state.verifyMode;
    },
    set verifyMode(mode: VerifyMode) {
      state.verifyMode = mode;
    },
    get settleMode() {
      return state.settleMode;
    },
    set settleMode(mode: SettleMode) {
      state.settleMode = mode;
    },
    count(pathPrefix: string): number {
      return state.calls.filter((p) => p.startsWith(pathPrefix)).length;
    },
    async close(): Promise<void> {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  };
}

// ---------------------------------------------------------------------------
// Shared ledger whose redeem-and-credit transaction can be made to fail with
// a non-lock SQLite error (SQLITE_FULL), which redeemAndGrant does not retry.
// ---------------------------------------------------------------------------

class FlakyLedger implements SharedLedger {
  failRedeem = 0;
  redeemCalls = 0;
  /** While set, redeemAndCredit fails like a write lock held by another connection, which redeemAndGrant retries. */
  lockRedeem = false;
  /** Runs on each locked attempt; it stands in for the busy timeout SQLite blocks for before it fails. */
  onLockedRedeem: (() => void) | null = null;
  /** Make the next N marker reads (getSettlement) or claims (beginSettlement) fail like a full disk. */
  failGetSettlement = 0;
  failBeginSettlement = 0;
  /** Make the next N marker removals (endSettlement) or pending-state reads (pendingSettlementState) fail like a full disk. */
  failEndSettlement = 0;
  failPendingSettlementState = 0;
  /** Marker updates (markSettlement) to these states fail like a full disk while they are in the set. */
  readonly failMark = new Set<SettlementState>();
  constructor(private readonly inner: CreditLedger) {}
  private static diskFull(): Error {
    return Object.assign(new Error("database or disk is full"), { code: "ERR_SQLITE_ERROR", errcode: 13 });
  }
  beginSettlement(start: SettlementStart, at: number): boolean {
    if (this.failBeginSettlement > 0) {
      this.failBeginSettlement -= 1;
      throw FlakyLedger.diskFull();
    }
    return this.inner.beginSettlement(start, at);
  }
  resumeSettlement(seen: SettlementMarker, at: number): boolean {
    return this.inner.resumeSettlement(seen, at);
  }
  touchSettlement(seen: SettlementMarker, at: number): boolean {
    return this.inner.touchSettlement(seen, at);
  }
  markSettlement(paymentId: string, state: SettlementState, tx: string | null, receipt: Record<string, unknown> | null, at: number): void {
    if (this.failMark.has(state)) throw FlakyLedger.diskFull();
    this.inner.markSettlement(paymentId, state, tx, receipt, at);
  }
  getSettlement(paymentId: string): SettlementMarker | null {
    if (this.failGetSettlement > 0) {
      this.failGetSettlement -= 1;
      throw FlakyLedger.diskFull();
    }
    return this.inner.getSettlement(paymentId);
  }
  endSettlement(paymentId: string, ifUpdatedAt?: number): void {
    if (this.failEndSettlement > 0) {
      this.failEndSettlement -= 1;
      throw FlakyLedger.diskFull();
    }
    this.inner.endSettlement(paymentId, ifUpdatedAt);
  }
  listSettled(updatedBefore: number, limit?: number): SettlementMarker[] {
    return this.inner.listSettled(updatedBefore, limit);
  }
  listSettledFor(transaction: string): SettlementMarker[] {
    return this.inner.listSettledFor(transaction);
  }
  pruneSettlements(updatedBefore: number): number {
    return this.inner.pruneSettlements(updatedBefore);
  }
  pendingSettlementState(principalId: string, settlingStaleBefore?: number, unknownSince?: number): SettlementState | null {
    if (this.failPendingSettlementState > 0) {
      this.failPendingSettlementState -= 1;
      throw FlakyLedger.diskFull();
    }
    return this.inner.pendingSettlementState(principalId, settlingStaleBefore, unknownSince);
  }
  balance(principalId: string): number | null {
    return this.inner.balance(principalId);
  }
  consume(principalId: string, credits: number): boolean {
    return this.inner.consume(principalId, credits);
  }
  add(principalId: string, plan: string, label: string, credits: number): number {
    return this.inner.add(principalId, plan, label, credits);
  }
  isRedeemed(paymentId: string, retentionMs: number, now?: number): boolean {
    return this.inner.isRedeemed(paymentId, retentionMs, now);
  }
  markRedeemed(paymentId: string, at?: number): boolean {
    return this.inner.markRedeemed(paymentId, at);
  }
  isRedeemedFamily(family: GuardFamily, retentionMs: number, now?: number): boolean {
    return this.inner.isRedeemedFamily(family, retentionMs, now);
  }
  redeemAndCredit(
    ids: readonly string[],
    principalId: string,
    plan: string,
    label: string,
    credits: number,
    at?: number,
    blockedBy?: readonly string[],
    blockedByFamily?: GuardFamily | null
  ): boolean {
    this.redeemCalls += 1;
    if (this.lockRedeem) {
      this.onLockedRedeem?.();
      throw Object.assign(new Error("database is locked"), { code: "ERR_SQLITE_ERROR", errcode: 5 });
    }
    if (this.failRedeem > 0) {
      this.failRedeem -= 1;
      throw Object.assign(new Error("database or disk is full"), { code: "ERR_SQLITE_ERROR", errcode: 13 });
    }
    return this.inner.redeemAndCredit(ids, principalId, plan, label, credits, at, blockedBy, blockedByFamily);
  }
  pruneRedeemed(retentionMs: number, now?: number): number {
    return this.inner.pruneRedeemed(retentionMs, now);
  }
  importOnce(source: Parameters<SharedLedger["importOnce"]>[0]): boolean {
    return this.inner.importOnce(source);
  }
}

// ---------------------------------------------------------------------------
// Harness: config + payments + ledger + the real auth middleware in Express.
// ---------------------------------------------------------------------------

interface Harness {
  upstream: Upstream;
  config: AppConfig;
  db: DatabaseSync;
  usage: UsageTracker;
  ledger: FlakyLedger;
  payments: PaymentManager;
  sessions: SessionTokenService;
  base: string;
  close(): Promise<void>;
}

const harnesses: Harness[] = [];
after(async () => {
  // Siblings first: they share the database and facilitator of the harness they were made from.
  for (const h of harnesses.splice(0).reverse()) await h.close();
});

/**
 * One server "process". With `sibling`, it shares that harness's database and
 * facilitator but has its own PaymentManager, UsageTracker and Express app:
 * a second process behind the same load balancer, or the first one after a
 * restart.
 */
async function harness(env: Record<string, string> = {}, sibling?: Harness): Promise<Harness> {
  const upstream = sibling ? sibling.upstream : await startUpstream();
  const config = loadConfig(
    {
      STACKDNS_TRANSPORT: "http",
      STACKDNS_REQUIRE_AUTH: "true",
      STACKDNS_PAYMENTS_ENABLED: "true",
      STACKDNS_PAYMENT_METHODS: "x402",
      STACKDNS_SESSION_SECRET: SESSION_SECRET,
      STACKDNS_PUBLIC_URL: "http://127.0.0.1:1",
      X402_FACILITATOR_URL: upstream.base,
      X402_PAY_TO: PAY_TO,
      X402_CREDITS_PER_PAYMENT: String(CREDITS),
      STRIPE_API_BASE: upstream.base,
      ...env
    },
    []
  );
  const db = sibling ? sibling.db : await openDatabase(":memory:");
  assert.ok(db);
  const ledger = new FlakyLedger(new CreditLedger(db));
  const usage = new UsageTracker(null);
  usage.attachLedger(ledger);
  const payments = new PaymentManager(config, usage);
  const sessions = new SessionTokenService(config.auth.sessionSecret);
  const limiter = new RateLimiter(config.auth.planLimits);

  const app = express();
  app.use(express.json());
  app.use(createAuthMiddleware({ config, keys: new ApiKeyStore(), sessions, payments, usage, limiter }));
  app.use((req, res) => {
    res.json({ served: true, principal: principalFromAuthInfo((req as AuthenticatedRequest).auth) });
  });
  const server = app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  let closed = false;
  const h: Harness = {
    upstream,
    config,
    db,
    usage,
    ledger,
    payments,
    sessions,
    base,
    async close(): Promise<void> {
      if (closed) return;
      closed = true;
      payments.close();
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      if (sibling) return;
      await upstream.close();
      try {
        db.close();
      } catch {
        // already closed
      }
    }
  };
  harnesses.push(h);
  return h;
}

let nonceCounter = 0;
/** A signed-looking x402 "exact" payload with a unique EIP-3009 nonce. */
function x402Payload(prefix = "0x"): Record<string, unknown> {
  nonceCounter += 1;
  const nonce = `${prefix}${String(nonceCounter).padStart(8, "0")}${createHash("sha256").update(String(Math.random())).digest("hex").slice(0, 24)}`;
  return {
    x402Version: 1,
    scheme: "exact",
    network: "base",
    payload: {
      signature: `0x${createHash("sha256").update(nonce).digest("hex")}`,
      authorization: {
        from: PAYER,
        to: PAY_TO,
        value: "500000",
        validAfter: "0",
        validBefore: String(Math.floor(Date.now() / 1000) + 3600),
        nonce
      }
    }
  };
}

/** The X-PAYMENT header an x402 client sends (base64 JSON). */
function header(payload: Record<string, unknown>): string {
  return Buffer.from(JSON.stringify(payload), "utf8").toString("base64");
}

function credentialFor(h: Harness, payload: Record<string, unknown>): PaymentCredential {
  const credential = h.payments.parseCredential(header(payload), "x-payment");
  assert.ok(credential, "the payload parses as an x402 credential");
  return credential;
}

const target = (principalId: string) => () => ({ principalId, label: `x402:${principalId}` });
/** The grant a top-up names: the session principal of the X-Session-Token sent with the payment. */
const topUpOf = (principalId: string) => () => ({ principalId, label: `x402:${principalId}`, topUp: true });

function failureCode(result: PaymentResult): string {
  return result.ok ? "ok" : result.code;
}

function grantOf(result: PaymentResult): string | null {
  return result.ok ? null : (result.grant?.principalId ?? null);
}

/**
 * What anyone can build once the payment settled: the EIP-3009 (from, nonce)
 * pair from the AuthorizationUsed event, with no signature and no amounts.
 */
function forgedFrom(payload: Record<string, unknown>): Record<string, unknown> {
  const authorization = (payload.payload as { authorization: { from: string; nonce: string } }).authorization;
  return { x402Version: 1, scheme: "exact", network: "base", payload: { authorization: { from: authorization.from.toUpperCase().replace("0X", "0x"), nonce: authorization.nonce } } };
}

/** Backdates every settlement marker, as if the given time had passed since it was created and last written. */
function ageMarkers(h: Harness, ms: number): void {
  h.db.prepare("UPDATE x402_settlements SET at = at - ?, updated_at = updated_at - ?").run(ms, ms);
}

/** Older than ADOPT_SETTLED_AFTER_MS (45 s, three times REDEEM_LOCK_BUDGET_MS): a sibling may adopt a 'settled' marker. */
const ADOPTABLE_AGE_MS = 50_000;

function markerOf(h: Harness, payload: Record<string, unknown>): { state: string; tx: string | null } | null {
  const id = x402ReplayKey(payload);
  assert.ok(id);
  return (h.db.prepare("SELECT state, tx FROM x402_settlements WHERE payment_id = ?").get(id) as { state: string; tx: string | null } | undefined) ?? null;
}

/** The principal auth.ts derives for a payment redeemed without a session. */
function derivedPrincipal(payload: Record<string, unknown>): string {
  const id = x402ReplayKey(payload);
  assert.ok(id);
  return `pay_${createHash("sha256").update(id).digest("hex").slice(0, 16)}`;
}

interface Reply {
  status: number;
  headers: Headers;
  body: Record<string, unknown>;
}

async function call(h: Harness, route: string, init: { method?: string; headers?: Record<string, string>; body?: unknown } = {}): Promise<Reply> {
  const headers: Record<string, string> = { ...(init.headers ?? {}) };
  let body: string | undefined;
  if (init.body !== undefined) {
    headers["content-type"] = "application/json";
    body = JSON.stringify(init.body);
  }
  const res = await fetch(`${h.base}${route}`, { method: init.method ?? "GET", headers, body });
  const text = await res.text();
  let parsed: Record<string, unknown> = {};
  try {
    parsed = text ? (JSON.parse(text) as Record<string, unknown>) : {};
  } catch {
    parsed = { raw: text };
  }
  return { status: res.status, headers: res.headers, body: parsed };
}

/** Redeems a fresh x402 payment through the HTTP stack and returns the session it opened. */
async function buyCredits(h: Harness): Promise<{ token: string; principalId: string; paymentHeader: string }> {
  const paymentHeader = header(x402Payload());
  const res = await call(h, "/v1/jobs", { headers: { "x-payment": paymentHeader } });
  assert.equal(res.status, 200, `fresh payment is redeemed: ${JSON.stringify(res.body)}`);
  const token = res.headers.get("x-session-token");
  assert.ok(token, "a session token is issued");
  const claims = h.sessions.verify(token);
  assert.ok(claims);
  assert.equal(h.usage.creditsRemaining(claims.sub), CREDITS);
  return { token, principalId: claims.sub, paymentHeader };
}

async function drainMicrotasks(rounds = 5): Promise<void> {
  for (let i = 0; i < rounds; i++) await new Promise((resolve) => setImmediate(resolve));
}

// ---------------------------------------------------------------------------
// G4
// ---------------------------------------------------------------------------

describe("G4: a settled x402 payment whose recording failed", () => {
  // Round 5 changed what a retry is answered with: the payload is public once
  // settled, so a retry finishes the recording onto the stored target but is
  // handed that target's session only when it is a top-up by that session.
  // The first answer (503) carries the session instead.
  it("is finished by a retry of the same header, onto the first attempt's target, with no facilitator call", async () => {
    const h = await harness();
    const payload = x402Payload();
    const credential = credentialFor(h, payload);

    h.ledger.failRedeem = 1;
    const first = await h.payments.redeem(credential, target("pay_first"));
    assert.equal(failureCode(first), "payment_recording_failed");
    assert.equal(grantOf(first), "pay_first", "the request that settled it is told whose session the credits belong to");
    assert.equal(h.upstream.count("/settle"), 1, "the transfer settled on the first attempt");
    assert.equal(h.usage.creditsRemaining("pay_first"), null, "the failed transaction rolled back: no credits yet");

    const upstreamCalls = h.upstream.calls.length;
    // The facilitator now rejects the spent authorization, so without the fix
    // this retry turns into x402_invalid (a fresh 402) and the money is lost.
    const retry = await h.payments.redeem(credential, target("pay_second_attempt"));
    assert.equal(failureCode(retry), "payment_already_redeemed", "recorded, but a payload alone never collects the session");
    assert.equal(grantOf(retry), null);
    assert.equal(h.upstream.calls.length, upstreamCalls, "the retry makes no facilitator call");
    assert.equal(h.usage.creditsRemaining("pay_first"), CREDITS, "credits go to the target chosen when the payment settled");
    assert.equal(h.usage.creditsRemaining("pay_second_attempt"), null);

    // A top-up by the target's own session gets the receipt.
    const own = await h.payments.redeem(credential, topUpOf("pay_first"));
    assert.ok(own.ok, `got ${failureCode(own)}`);
    assert.equal(own.principalId, "pay_first");
    assert.equal(own.credits, CREDITS);
    assert.match(String(own.receipt.transaction), /^0x[0-9a-f]{64}$/);

    const replay = await h.payments.redeem(credential, topUpOf("pay_first"));
    assert.equal(failureCode(replay), "payment_already_redeemed", "once recorded, the header alone never re-issues credits");
    assert.equal(h.usage.creditsRemaining("pay_first"), CREDITS, "credited exactly once");
  });

  it("keeps answering 'recording failed' (never a new payment demand) while the database is still failing", async () => {
    const h = await harness();
    const credential = credentialFor(h, x402Payload());
    h.ledger.failRedeem = 3;
    const first = await h.payments.redeem(credential, target("pay_slow"));
    assert.equal(failureCode(first), "payment_recording_failed");
    assert.equal(grantOf(first), "pay_slow");
    const upstreamCalls = h.upstream.calls.length;
    for (let i = 0; i < 2; i++) {
      const again = await h.payments.redeem(credential, target("pay_slow"));
      assert.equal(failureCode(again), "payment_recording_failed");
      assert.equal(grantOf(again), null, "a retry is never handed the session");
    }
    assert.equal(h.upstream.calls.length, upstreamCalls, "no retry re-verifies or re-settles");
    const healed = await h.payments.redeem(credential, target("pay_slow"));
    assert.equal(failureCode(healed), "payment_already_redeemed", "recorded once the database recovers");
    assert.equal(h.usage.creditsRemaining("pay_slow"), CREDITS);
  });

  it("is finished on retry even after the authorization's validBefore has passed", async () => {
    const h = await harness();
    const payload = x402Payload();
    const credential = credentialFor(h, payload);
    h.ledger.failRedeem = 1;
    assert.equal(failureCode(await h.payments.redeem(credential, target("pay_late_retry"))), "payment_recording_failed");
    // Two hours later the EIP-3009 deadline is long gone; the money moved before it.
    mock.timers.enable({ apis: ["Date"], now: Date.now() + 2 * 3600_000 });
    try {
      const retry = await h.payments.redeem(credential, target("pay_late_retry"));
      assert.equal(failureCode(retry), "payment_already_redeemed", "a settled payment is recorded, not refused as x402_expired");
      assert.equal(h.usage.creditsRemaining("pay_late_retry"), CREDITS);
    } finally {
      mock.timers.reset();
    }
  });

  it("is recorded in the background without a client retry, and a later retry gets no session", async () => {
    // Round 6: the recording timer starts with the PaymentManager, so it is mocked before the harness is built.
    mock.timers.enable({ apis: ["setInterval"] });
    try {
      const h = await harness();
      const credential = credentialFor(h, x402Payload());
      h.ledger.failRedeem = 1;
      assert.equal(failureCode(await h.payments.redeem(credential, target("pay_bg"))), "payment_recording_failed");
      assert.equal(h.usage.creditsRemaining("pay_bg"), null);

      mock.timers.tick(10_000);
      await drainMicrotasks();
      assert.equal(h.usage.creditsRemaining("pay_bg"), CREDITS, "the background retry granted the credits");

      mock.timers.tick(10_000);
      await drainMicrotasks();
      assert.equal(h.usage.creditsRemaining("pay_bg"), CREDITS, "a committed payment is not granted again");

      const upstreamCalls = h.upstream.calls.length;
      const retry = await h.payments.redeem(credential, target("pay_bg"));
      assert.equal(failureCode(retry), "payment_already_redeemed", "the derived principal is public, so it proves nothing");
      assert.match(retry.ok ? "" : retry.message, /earlier 503 or 502/);
      const own = await h.payments.redeem(credential, topUpOf("pay_bg"));
      assert.ok(own.ok, `the session the credits went to still gets its receipt, got ${failureCode(own)}`);
      assert.equal(own.principalId, "pay_bg");
      assert.equal(h.upstream.calls.length, upstreamCalls);
      assert.equal(h.usage.creditsRemaining("pay_bg"), CREDITS, "the retries after a background commit grant nothing twice");
    } finally {
      mock.timers.reset();
    }
  });

  it("over HTTP: the 503 carries the session; a retry of the header alone gets 409 and no token", async () => {
    const h = await harness();
    const payload = x402Payload();
    const paymentHeader = header(payload);
    h.ledger.failRedeem = 1;

    const first = await call(h, "/v1/jobs", { headers: { "x-payment": paymentHeader } });
    assert.equal(first.status, 503);
    assert.equal(first.body.error, "payment_recording_failed");
    assert.equal(first.headers.get("retry-after"), "5");
    assert.equal(first.headers.get("www-authenticate"), null, "no fresh payment demand");
    const token = first.headers.get("x-session-token");
    assert.ok(token, "the request that settled the payment is handed its session");
    assert.equal(first.body.sessionToken, token);
    const claims = h.sessions.verify(token);
    assert.equal(claims?.sub, derivedPrincipal(payload));
    assert.equal(claims?.plan, "payg");

    const retry = await call(h, "/v1/jobs", { headers: { "x-payment": paymentHeader } });
    assert.equal(retry.status, 409, `the retry finishes the recording but mints nothing: ${JSON.stringify(retry.body)}`);
    assert.equal(retry.body.reason, "payment_already_redeemed");
    assert.equal(retry.headers.get("x-session-token"), null);
    assert.equal(h.usage.creditsRemaining(derivedPrincipal(payload)), CREDITS, "the 503's session holds the credits");

    // Presenting the 503's session with the same header collects the receipt.
    const own = await call(h, "/v1/jobs", { headers: { "x-payment": paymentHeader, "x-session-token": token } });
    assert.equal(own.status, 200, JSON.stringify(own.body));
    const receipt = JSON.parse(Buffer.from(own.headers.get("payment-receipt") ?? "", "base64url").toString("utf8")) as Record<string, unknown>;
    assert.equal(receipt.creditsRemaining, CREDITS);
    assert.equal(h.sessions.verify(own.headers.get("x-session-token") ?? "")?.sub, derivedPrincipal(payload));
    assert.equal(h.upstream.count("/verify"), 1);
    assert.equal(h.upstream.count("/settle"), 1);
  });

  it("over HTTP: a funded session's top-up that failed to record is credited to that session on retry", async () => {
    const h = await harness();
    const session = await buyCredits(h);
    assert.equal(h.usage.consumeCredits(session.principalId, 40), true);
    const topUpHeader = header(x402Payload());
    const headers = { authorization: `Bearer ${session.token}`, "x-payment": topUpHeader };
    h.ledger.failRedeem = 1;

    const first = await call(h, "/v1/jobs", { headers });
    assert.equal(first.status, 503, "a settled-but-unrecorded top-up is reported even to a funded session");
    assert.equal(first.headers.get("x-session-token"), null, "a top-up already holds its session");
    assert.equal(h.usage.creditsRemaining(session.principalId), 60);

    const retry = await call(h, "/v1/jobs", { headers });
    assert.equal(retry.status, 200);
    assert.equal(retry.headers.get("x-payment-status"), null, `the top-up is redeemed, not ignored as ${retry.headers.get("x-payment-status")}`);
    assert.ok(retry.headers.get("payment-receipt"), "the retry carries the top-up's receipt");
    assert.equal(h.usage.creditsRemaining(session.principalId), 60 + CREDITS, "the paid-for credits reach the session");
    const claims = h.sessions.verify(retry.headers.get("x-session-token") ?? "");
    assert.equal(claims?.sub, session.principalId);
  });
});

// ---------------------------------------------------------------------------
// G5
// ---------------------------------------------------------------------------

describe("G5: a /settle whose outcome is unknown", () => {
  it("a connection reset after the broadcast is unconfirmed, and so is the retry the facilitator now rejects", async () => {
    const h = await harness();
    const credential = credentialFor(h, x402Payload());
    h.upstream.settleMode = "reset-after-broadcast";
    const first = await h.payments.redeem(credential, target("pay_reset"));
    assert.equal(failureCode(first), "x402_settlement_unconfirmed", "not x402_verification_failed");

    h.upstream.settleMode = "ok";
    const retry = await h.payments.redeem(credential, target("pay_reset"));
    assert.equal(failureCode(retry), "x402_settlement_unconfirmed", "the spent authorization is not reported as x402_invalid");
    assert.equal(h.usage.creditsRemaining("pay_reset"), null);
  });

  it("a non-JSON gateway 504 and a JSON 5xx from /settle are unconfirmed", async () => {
    const h = await harness();
    h.upstream.settleMode = "gateway-504";
    assert.equal(failureCode(await h.payments.redeem(credentialFor(h, x402Payload()), target("pay_504"))), "x402_settlement_unconfirmed");
    h.upstream.settleMode = "json-500";
    assert.equal(failureCode(await h.payments.redeem(credentialFor(h, x402Payload()), target("pay_500"))), "x402_settlement_unconfirmed");
  });

  it("a settle refusal after an unknown outcome stays unconfirmed even when /verify passes", async () => {
    const h = await harness();
    const credential = credentialFor(h, x402Payload());
    h.upstream.settleMode = "gateway-504";
    assert.equal(failureCode(await h.payments.redeem(credential, target("pay_lenient"))), "x402_settlement_unconfirmed");
    // Some facilitators verify only the signature; the settle then refuses the used nonce.
    h.upstream.verifyMode = "lenient";
    h.upstream.settleMode = "ok";
    assert.equal(failureCode(await h.payments.redeem(credential, target("pay_lenient"))), "x402_settlement_unconfirmed", "not x402_settlement_failed");
  });

  it("failures before any money moves keep their codes", async () => {
    const h = await harness();
    h.upstream.settleMode = "refuse";
    assert.equal(failureCode(await h.payments.redeem(credentialFor(h, x402Payload()), target("pay_refused"))), "x402_settlement_failed", "an explicit JSON refusal stays a 402");
    h.upstream.settleMode = "ok";
    h.upstream.verifyMode = "reset";
    assert.equal(failureCode(await h.payments.redeem(credentialFor(h, x402Payload()), target("pay_verify"))), "x402_verification_failed", "a /verify transport error moved nothing");
    h.upstream.verifyMode = "strict";
    assert.equal(failureCode(await h.payments.redeem(credentialFor(h, x402Payload("0xbad")), target("pay_invalid"))), "x402_invalid");
  });

  it("a settle that never broadcast completes on retry; only a top-up by the 502's session collects the receipt", async () => {
    const h = await harness();
    const credential = credentialFor(h, x402Payload());
    h.upstream.settleMode = "reset-before-broadcast";
    const first = await h.payments.redeem(credential, target("pay_late"));
    assert.equal(failureCode(first), "x402_settlement_unconfirmed");
    assert.equal(grantOf(first), "pay_late");
    h.upstream.settleMode = "ok";
    // Round 8: an 'unknown' marker is re-verified at most once a minute.
    ageMarkers(h, 61_000);
    // Round 6: the 502 already handed out pay_late's session, so a payload alone (whose derived principal is
    // public) settles and records the payment onto it but is not answered with it.
    const retry = await h.payments.redeem(credential, target("pay_late"));
    assert.equal(failureCode(retry), "payment_already_redeemed");
    assert.equal(grantOf(retry), null);
    assert.equal(h.usage.creditsRemaining("pay_late"), CREDITS);

    const second = credentialFor(h, x402Payload());
    h.upstream.settleMode = "reset-before-broadcast";
    assert.equal(failureCode(await h.payments.redeem(second, target("pay_late2"))), "x402_settlement_unconfirmed");
    h.upstream.settleMode = "ok";
    ageMarkers(h, 61_000);
    const own = await h.payments.redeem(second, topUpOf("pay_late2"));
    assert.ok(own.ok, `got ${failureCode(own)}`);
    assert.equal(own.principalId, "pay_late2");
    assert.equal(h.usage.creditsRemaining("pay_late2"), CREDITS);
  });

  it("over HTTP the client gets 502 without a payment challenge on the first attempt and the retry; a funded session is served and told", async () => {
    const h = await harness();
    const payload = x402Payload();
    const paymentHeader = header(payload);
    h.upstream.settleMode = "reset-after-broadcast";
    const first = await call(h, "/v1/jobs", { headers: { "x-payment": paymentHeader } });
    assert.equal(first.status, 502, `got ${first.status} ${JSON.stringify(first.body)}`);
    assert.equal(first.body.error, "x402_settlement_unconfirmed");
    assert.equal(first.headers.get("www-authenticate"), null);
    assert.equal(first.body.accepts, undefined, "no new payment requirement");
    // Round 5: the request whose own settle outcome is unknown is handed the
    // session any credits would belong to, for reconciliation.
    assert.equal(h.sessions.verify(first.headers.get("x-session-token") ?? "")?.sub, derivedPrincipal(payload));

    h.upstream.settleMode = "ok";
    const retry = await call(h, "/v1/jobs", { headers: { "x-payment": paymentHeader } });
    assert.equal(retry.status, 502, `a retry of the same header is not answered with a fresh 402: ${JSON.stringify(retry.body)}`);
    assert.equal(retry.headers.get("www-authenticate"), null);
    assert.equal(retry.headers.get("x-session-token"), null, "a retry is never handed the session");

    const session = await buyCredits(h);
    h.upstream.settleMode = "gateway-504";
    const funded = await call(h, "/v1/jobs", { headers: { authorization: `Bearer ${session.token}`, "x-payment": header(x402Payload()) } });
    // Round 8 (P-B): a session that can serve the request is served from its balance, with the payment's
    // state in X-Payment-Status, instead of being locked out by a 502 on every route.
    assert.equal(funded.status, 200, "a funded session is served from its balance");
    assert.equal(funded.headers.get("x-payment-status"), "x402_settlement_unconfirmed", "and told the payment is unconfirmed");
    assert.equal(funded.headers.get("www-authenticate"), null);
    assert.equal(funded.headers.get("x-session-token"), null, "a top-up already holds its session");
  });
});

// ---------------------------------------------------------------------------
// G6
// ---------------------------------------------------------------------------

describe("G6: an exhausted session that re-attaches its last X-PAYMENT", () => {
  it("is served on routes that cannot spend, and challenged (409) only on routes that can", async () => {
    const h = await harness();
    const session = await buyCredits(h);
    assert.equal(h.usage.consumeCredits(session.principalId, CREDITS), true, "a bulk job debited the balance to zero");
    assert.equal(h.usage.creditsRemaining(session.principalId), 0);
    const headers = { authorization: `Bearer ${session.token}`, "x-payment": session.paymentHeader };
    const upstreamCalls = h.upstream.calls.length;

    const free: Array<[string, string, unknown?]> = [
      ["GET", "/v1/jobs/job_123"],
      ["GET", "/v1/jobs"],
      ["GET", "/v1/jobs/job_123/results.csv"],
      ["DELETE", "/v1/jobs/job_123"],
      ["GET", "/usage"],
      ["POST", "/mcp", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "get_bulk_check", arguments: { jobId: "job_123" } } }],
      ["POST", "/mcp", { jsonrpc: "2.0", id: 2, method: "tools/list" }]
    ];
    for (const [method, route, body] of free) {
      const res = await call(h, route, { method, headers, body });
      assert.equal(res.status, 200, `${method} ${route} is served: ${JSON.stringify(res.body)}`);
      const principal = res.body.principal as { id?: string; plan?: string } | null;
      assert.equal(principal?.id, session.principalId, `${method} ${route} runs as the session's principal`);
      assert.equal(principal?.plan, "payg");
      assert.equal(res.headers.get("x-payment-status"), "payment_already_redeemed");
    }

    const paid: Array<[string, string, unknown]> = [
      ["POST", "/v1/jobs", { domains: ["example.com"], checks: ["email"] }],
      ["POST", "/mcp", { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "inspect_tech_stack", arguments: { domain: "example.com" } } }]
    ];
    for (const [method, route, body] of paid) {
      const res = await call(h, route, { method, headers, body });
      assert.equal(res.status, 409, `${method} ${route} cannot spend from an empty balance`);
      assert.equal(res.body.reason, "payment_already_redeemed");
      assert.ok(Array.isArray(res.body.accepts) && res.body.accepts.length > 0, "the 409 carries how to buy more");
    }
    assert.equal(h.upstream.calls.length, upstreamCalls, "the stale header never reached the facilitator");
  });

  it("is served on a free route with an unconfirmed settlement named in X-Payment-Status, and gets 502 on a route that spends", async () => {
    const h = await harness();
    const session = await buyCredits(h);
    h.usage.consumeCredits(session.principalId, CREDITS);
    h.upstream.settleMode = "reset-after-broadcast";
    const headers = { authorization: `Bearer ${session.token}`, "x-payment": header(x402Payload()) };
    // Round 8 (P-B): before, every route answered 502 for as long as the marker was kept.
    const res = await call(h, "/v1/jobs/job_1", { headers });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(res.headers.get("x-payment-status"), "x402_settlement_unconfirmed");
    const spend = await call(h, "/v1/jobs", { method: "POST", headers, body: { domains: ["example.com"], checks: ["email"] } });
    assert.equal(spend.status, 502, "nothing else can serve a spending request from an empty balance");
    assert.equal(spend.body.error, "x402_settlement_unconfirmed");
    assert.equal(spend.headers.get("www-authenticate"), null);
  });
});

// ---------------------------------------------------------------------------
// G7
// ---------------------------------------------------------------------------

describe("G7: pre-auth address throttle and funded sessions", () => {
  it("a funded session re-attaching its redeemed x402 payment is limited by its own ceiling, not the address bucket", async () => {
    const h = await harness({ STACKDNS_UNAUTHENTICATED_PER_MINUTE: "3" });
    const session = await buyCredits(h); // one slot of the address bucket
    const headers = { authorization: `Bearer ${session.token}`, "x-payment": session.paymentHeader };
    const statuses: number[] = [];
    for (let i = 0; i < 10; i++) statuses.push((await call(h, "/v1/jobs", { headers })).status);
    assert.deepEqual(statuses, Array(10).fill(200), "well past the 3/min pre-auth bucket, still under the payg ceiling");

    const badKey = await call(h, "/v1/jobs", { headers: { authorization: "Bearer sdm_live_not_a_real_key_000000" } });
    assert.equal(badKey.status, 401, "the paying session did not use up the address's bucket for other traffic");
    assert.equal(badKey.body.error, "invalid_api_key");
  });

  it("a funded session sending fresh payloads (each needing a facilitator call) is still throttled", async () => {
    const h = await harness({ STACKDNS_UNAUTHENTICATED_PER_MINUTE: "3" });
    const session = await buyCredits(h); // slot 1
    const verifyBefore = h.upstream.count("/verify");
    const statuses: number[] = [];
    for (let i = 0; i < 5; i++) {
      const res = await call(h, "/v1/jobs", { headers: { authorization: `Bearer ${session.token}`, "x-payment": header(x402Payload("0xbad")) } });
      statuses.push(res.status);
    }
    assert.deepEqual(statuses, [200, 200, 429, 429, 429]);
    assert.equal(h.upstream.count("/verify") - verifyBefore, 2, "throttled requests never reach the facilitator");
  });

  it("a redeemed Stripe PaymentIntent is served without the address bucket; a checkout-session-only credential stays throttled", async () => {
    const h = await harness({ STACKDNS_UNAUTHENTICATED_PER_MINUTE: "3", STACKDNS_PAYMENT_METHODS: "stripe,x402", STRIPE_SECRET_KEY: "sk_test_round4" });
    assert.ok(h.payments.stripeEnabled);
    h.usage.addCredits("pay_stripe", "payg", "stripe:pi_old_redeemed", 50);
    assert.equal(h.usage.markPaymentRedeemed("pi_old_redeemed"), true);
    const token = h.sessions.issue({ sub: "pay_stripe", plan: "payg", label: "stripe:pi_old_redeemed" });

    const known = { authorization: `Payment ${encodeCredential({ paymentIntentId: "pi_old_redeemed" })}`, "x-session-token": token };
    const statuses: number[] = [];
    for (let i = 0; i < 8; i++) statuses.push((await call(h, "/v1/jobs", { headers: known })).status);
    assert.deepEqual(statuses, Array(8).fill(200));
    assert.equal(h.upstream.count("/v1/"), 0, "no Stripe call for a payment the ledger already knows");

    const checkoutOnly = { authorization: `Payment ${encodeCredential({ checkoutSessionId: "cs_old" })}`, "x-session-token": token };
    const throttled: number[] = [];
    for (let i = 0; i < 5; i++) throttled.push((await call(h, "/v1/jobs", { headers: checkoutOnly })).status);
    assert.deepEqual(throttled, [200, 200, 200, 429, 429], "a credential that needs a Stripe call keeps the pre-auth throttle");
    assert.equal(h.upstream.count("/v1/checkout/sessions/"), 3);
  });

  it("an unrecorded settled payment is not treated as known-redeemed", async () => {
    const h = await harness();
    const payload = x402Payload();
    const credential = credentialFor(h, payload);
    h.ledger.failRedeem = 1;
    assert.equal(failureCode(await h.payments.redeem(credential, target("pay_known"))), "payment_recording_failed");
    assert.equal(h.payments.isKnownRedeemed(credential), false, "still pending: redeem() will finish it rather than answer already-redeemed");
    // Round 5: the retry records it but, being a payload alone, is not handed the session.
    assert.equal(failureCode(await h.payments.redeem(credential, target("pay_known"))), "payment_already_redeemed");
    assert.equal(h.usage.creditsRemaining("pay_known"), CREDITS);
    assert.equal(h.payments.isKnownRedeemed(credential), true);
    const id = x402ReplayKey(payload);
    assert.ok(id);
    assert.equal(h.usage.isPaymentRedeemed(id), true);
  });
});

// ---------------------------------------------------------------------------
// G8
// ---------------------------------------------------------------------------

describe("G8: openDatabase under lock contention", () => {
  const LATEST = Math.max(...MIGRATIONS.map((m) => m.version));

  it("rejects, instead of resolving to null, when another connection holds the write lock past the budget", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "sdm-r4-lock-"));
    const file = path.join(dir, "shared.db");
    const holder = await openDatabase(file);
    assert.ok(holder);
    try {
      // A release with a pending migration starts while another process
      // holds the write lock (a long transaction, a VACUUM, an import).
      holder.prepare("UPDATE meta SET value = ? WHERE key = 'schema_version'").run(String(LATEST - 1));
      holder.exec("BEGIN IMMEDIATE");
      const started = Date.now();
      await assert.rejects(openDatabase(file, 200), (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.match(err.message, /locked/i);
        assert.match(String((err.cause as Error | undefined)?.message ?? ""), /database is locked|SQLITE_BUSY/i);
        return true;
      });
      assert.ok(Date.now() - started < 8000, "the injected budget bounds the wait");
    } finally {
      try {
        holder.exec("ROLLBACK");
      } catch {
        // not in a transaction
      }
      holder.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("waits out contention that ends within the budget", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "sdm-r4-lock-"));
    const file = path.join(dir, "fresh.db");
    const holder = new DatabaseSync(file);
    try {
      holder.exec("CREATE TABLE holder (x INTEGER)");
      holder.exec("BEGIN EXCLUSIVE");
      holder.exec("INSERT INTO holder VALUES (1)");
      // Released as soon as the first (blocking) attempt yields to the event loop.
      const release = setTimeout(() => holder.exec("ROLLBACK"), 20);
      const db = await openDatabase(file, 10_000);
      clearTimeout(release);
      assert.ok(db, "storage is opened once the lock is gone");
      const version = db.prepare("SELECT value FROM meta WHERE key = 'schema_version'").get() as { value: string };
      assert.equal(version.value, String(LATEST));
      db.close();
    } finally {
      try {
        holder.exec("ROLLBACK");
      } catch {
        // already released
      }
      holder.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("still returns null for an unusable file, and STACKDNS_DB_FILE=none still disables storage", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "sdm-r4-lock-"));
    const file = path.join(dir, "junk.db");
    try {
      await writeFile(file, Buffer.alloc(4096, 0x5a));
      assert.equal(await openDatabase(file, 200), null);
      assert.equal(await openStorage(loadConfig({ STACKDNS_DB_FILE: "none" }, [])), null);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// Round 5 regressions: durable settlement markers, token binding, stdio storage
// ---------------------------------------------------------------------------

describe("Round 5 G4: a retry of a settled payment is never handed a session by its payload alone", () => {
  it("a forged (from, nonce) retry of a failed top-up gets no token; the credits still reach the session that paid", async () => {
    const h = await harness();
    const victim = await buyCredits(h);
    const payload = x402Payload();
    h.ledger.failRedeem = 1;
    const first = await call(h, "/v1/jobs", { headers: { "x-payment": header(payload), "x-session-token": victim.token } });
    assert.equal(first.status, 503);
    const verifyCalls = h.upstream.count("/verify");

    // Anyone can read the (from, nonce) pair from the chain once the transfer settled.
    const forged = await call(h, "/v1/jobs", { headers: { "x-payment": header(forgedFrom(payload)) } });
    assert.equal(forged.status, 409, `the forged payload is not served: ${JSON.stringify(forged.body)}`);
    assert.equal(forged.headers.get("x-session-token"), null, "no session token for the victim's principal");
    assert.equal(forged.headers.get("payment-receipt"), null);
    assert.equal(h.usage.creditsRemaining(victim.principalId), 2 * CREDITS, "the forged retry finished the recording onto the victim");

    // With the forger's own funded session it is served as itself, never as the victim.
    const forger = await buyCredits(h);
    const withOwnSession = await call(h, "/v1/jobs", { headers: { "x-payment": header(forgedFrom(payload)), "x-session-token": forger.token } });
    assert.equal(withOwnSession.status, 200);
    assert.equal((withOwnSession.body.principal as { id?: string }).id, forger.principalId);
    assert.equal(withOwnSession.headers.get("x-session-token"), null);
    assert.equal(h.usage.creditsRemaining(forger.principalId), CREDITS, "the forger gained nothing");

    // The victim's own retry still gets its receipt.
    const own = await call(h, "/v1/jobs", { headers: { "x-payment": header(payload), "x-session-token": victim.token } });
    assert.equal(own.status, 200);
    assert.ok(own.headers.get("payment-receipt"));
    assert.equal(h.sessions.verify(own.headers.get("x-session-token") ?? "")?.sub, victim.principalId);
    assert.equal(h.usage.creditsRemaining(victim.principalId), 2 * CREDITS, "credited once");
    assert.equal(h.upstream.count("/verify") - verifyCalls, 1, "only the forger's own purchase reached the facilitator");
  });

  it("a forged retry of a new-principal payment gets no token; only the 503 carried one", async () => {
    const h = await harness();
    const payload = x402Payload();
    h.ledger.failRedeem = 1;
    const first = await call(h, "/v1/jobs", { headers: { "x-payment": header(payload) } });
    assert.equal(first.status, 503);
    const token = first.headers.get("x-session-token");
    assert.ok(token);

    for (let i = 0; i < 2; i++) {
      const forged = await call(h, "/v1/jobs", { headers: { "x-payment": header(forgedFrom(payload)) } });
      assert.equal(forged.status, 409, JSON.stringify(forged.body));
      assert.equal(forged.headers.get("x-session-token"), null, "the derived principal is public, so it is never minted on a retry");
    }
    const payerRetry = await call(h, "/v1/jobs", { headers: { "x-payment": header(payload) } });
    assert.equal(payerRetry.status, 409);
    assert.equal(payerRetry.headers.get("x-session-token"), null);
    assert.match(String(payerRetry.body.message), /earlier 503 or 502/);

    const served = await call(h, "/usage", { headers: { authorization: `Bearer ${token}` } });
    assert.equal(served.status, 200);
    assert.equal((served.body.principal as { id?: string }).id, derivedPrincipal(payload));
    assert.equal(h.usage.creditsRemaining(derivedPrincipal(payload)), CREDITS, "the 503's session holds the credits");
  });
});

describe("Round 5 G4: settlement markers shared by every process", () => {
  it("503 at one process: the retry at a sibling gets 503 (never 402), then finishes the recording once", async () => {
    const A = await harness();
    const B = await harness({}, A);
    const payload = x402Payload();
    const paymentHeader = header(payload);
    A.ledger.failRedeem = 1;
    const first = await call(A, "/v1/jobs", { headers: { "x-payment": paymentHeader } });
    assert.equal(first.status, 503);
    const token = first.headers.get("x-session-token");
    assert.ok(token);
    assert.deepEqual(markerOf(A, payload)?.state, "settled", "the transaction is shared before the recording is attempted");

    // The settling process may still be recording: siblings wait it out.
    for (const h of [paymentHeader, header(forgedFrom(payload))]) {
      const early = await call(B, "/v1/jobs", { headers: { "x-payment": h } });
      assert.equal(early.status, 503, `never a fresh 402: ${JSON.stringify(early.body)}`);
      assert.equal(early.headers.get("www-authenticate"), null);
      assert.equal(early.headers.get("x-session-token"), null);
    }

    // Round 6: the settling request may keep recording against a locked database for about 16 s, so a
    // marker 30 s old is still left to it.
    ageMarkers(A, 30_000);
    const waiting = await call(B, "/v1/jobs", { headers: { "x-payment": header(forgedFrom(payload)) } });
    assert.equal(waiting.status, 503, `not adopted yet: ${JSON.stringify(waiting.body)}`);
    assert.equal(markerOf(A, payload)?.state, "settled");

    ageMarkers(A, ADOPTABLE_AGE_MS - 30_000);
    const forged = await call(B, "/v1/jobs", { headers: { "x-payment": header(forgedFrom(payload)) } });
    assert.equal(forged.status, 409, JSON.stringify(forged.body));
    assert.equal(forged.headers.get("x-session-token"), null);
    assert.equal(B.usage.creditsRemaining(derivedPrincipal(payload)), CREDITS, "the sibling finished the recording onto the stored target");
    assert.equal(markerOf(A, payload), null);

    const own = await call(B, "/v1/jobs", { headers: { "x-payment": paymentHeader, "x-session-token": token } });
    assert.equal(own.status, 200);
    const plain = await call(B, "/v1/jobs", { headers: { "x-payment": paymentHeader } });
    assert.equal(plain.status, 409);
    assert.equal(plain.headers.get("x-session-token"), null);
    // The settling process still holds its own entry; finishing it again grants nothing.
    const atA = await call(A, "/v1/jobs", { headers: { "x-payment": paymentHeader } });
    assert.equal(atA.status, 409);
    assert.equal(A.usage.creditsRemaining(derivedPrincipal(payload)), CREDITS, "credited exactly once");
    assert.equal(A.upstream.count("/settle"), 1);
  });

  it("502 at one process: the retry at a sibling gets 502 (never 402) however /verify answers", async () => {
    const A = await harness();
    const B = await harness({}, A);
    const payload = x402Payload();
    const paymentHeader = header(payload);
    A.upstream.settleMode = "reset-after-broadcast";
    const first = await call(A, "/v1/jobs", { headers: { "x-payment": paymentHeader } });
    assert.equal(first.status, 502);
    assert.ok(first.headers.get("x-session-token"));
    assert.equal(markerOf(A, payload)?.state, "unknown");

    A.upstream.settleMode = "ok";
    for (const mode of ["strict", "reset", "gateway-html"] as const) {
      A.upstream.verifyMode = mode;
      for (const h of [paymentHeader, header(forgedFrom(payload))]) {
        const retry = await call(B, "/v1/jobs", { headers: { "x-payment": h } });
        assert.equal(retry.status, 502, `verify ${mode}: ${JSON.stringify(retry.body)}`);
        assert.equal(retry.body.error, "x402_settlement_unconfirmed");
        assert.equal(retry.headers.get("www-authenticate"), null);
        assert.equal(retry.headers.get("x-session-token"), null);
      }
    }
    assert.equal(A.upstream.count("/settle"), 1);
  });

  it("after a restart the new process answers 503 and 502 (never 402) and finishes the settled payment", async () => {
    const A = await harness();
    const settled = x402Payload();
    const unknown = x402Payload();
    A.ledger.failRedeem = 1;
    const r503 = await call(A, "/v1/jobs", { headers: { "x-payment": header(settled) } });
    assert.equal(r503.status, 503);
    const token = r503.headers.get("x-session-token");
    assert.ok(token);
    A.upstream.settleMode = "gateway-504";
    assert.equal((await call(A, "/v1/jobs", { headers: { "x-payment": header(unknown) } })).status, 502);
    // The process is gone: its memory (the unrecorded entry) and its timer with it.
    A.payments.close();
    A.upstream.settleMode = "ok";

    const B = await harness({}, A);
    const retry503 = await call(B, "/v1/jobs", { headers: { "x-payment": header(settled) } });
    assert.equal(retry503.status, 503, JSON.stringify(retry503.body));
    assert.equal(retry503.headers.get("www-authenticate"), null);
    const retry502 = await call(B, "/v1/jobs", { headers: { "x-payment": header(unknown) } });
    assert.equal(retry502.status, 502, JSON.stringify(retry502.body));
    assert.equal(retry502.headers.get("www-authenticate"), null);

    ageMarkers(A, ADOPTABLE_AGE_MS);
    const later = await call(B, "/v1/jobs", { headers: { "x-payment": header(settled) } });
    assert.equal(later.status, 409);
    assert.equal(later.headers.get("x-session-token"), null);
    assert.equal(B.usage.creditsRemaining(derivedPrincipal(settled)), CREDITS);
    const served = await call(B, "/usage", { headers: { authorization: `Bearer ${token}` } });
    assert.equal((served.body.principal as { id?: string }).id, derivedPrincipal(settled), "the token from the 503 before the restart reaches the credits");
    assert.equal((await call(B, "/v1/jobs", { headers: { "x-payment": header(unknown) } })).status, 502, "an unknown outcome stays unconfirmed");
    assert.equal(A.upstream.count("/settle"), 2);
  });

  it("a restarted process's timer adopts a settled marker with no request at all", async () => {
    const A = await harness();
    const payload = x402Payload();
    A.ledger.failRedeem = 1;
    assert.equal(failureCode(await A.payments.redeem(credentialFor(A, payload), target("pay_adopted"))), "payment_recording_failed");
    A.payments.close();
    mock.timers.enable({ apis: ["setInterval"] });
    try {
      const B = await harness({}, A);
      // Round 6: the timer starts with the PaymentManager. Before, it waited for some x402 request to reach
      // the restarted process, and the 503's session had no credits until then.
      mock.timers.tick(10_000);
      await drainMicrotasks();
      assert.equal(B.usage.creditsRemaining("pay_adopted"), null, "a fresh marker is left to its settling process");

      ageMarkers(A, ADOPTABLE_AGE_MS);
      mock.timers.tick(10_000);
      await drainMicrotasks();
      assert.equal(B.usage.creditsRemaining("pay_adopted"), CREDITS, "adopted in the background");
      assert.equal(markerOf(A, payload), null);
      mock.timers.tick(10_000);
      await drainMicrotasks();
      assert.equal(B.usage.creditsRemaining("pay_adopted"), CREDITS, "once");
      assert.equal(failureCode(await B.payments.redeem(credentialFor(B, payload), target("pay_adopted"))), "payment_already_redeemed");
    } finally {
      mock.timers.reset();
    }
  });

  it("a live sibling's settle answers 409 in progress; one left by a crashed process is settled again", async () => {
    const A = await harness();
    const B = await harness({}, A);
    const payload = x402Payload();
    const id = x402ReplayKey(payload);
    assert.ok(id);
    assert.equal(B.usage.beginSettlement({ paymentId: id, principalId: "pay_crashed", label: "x402:crashed", credits: CREDITS }, Date.now()), true);
    const calls = A.upstream.calls.length;
    const busy = await call(A, "/v1/jobs", { headers: { "x-payment": header(payload) } });
    assert.equal(busy.status, 409);
    assert.equal(busy.body.error, "payment_redemption_in_progress");
    assert.equal(busy.headers.get("retry-after"), "2");
    assert.equal(busy.headers.get("www-authenticate"), null);
    assert.equal(A.upstream.calls.length, calls, "no facilitator call while another process settles");

    ageMarkers(A, 61_000);
    const resumed = await A.payments.redeem(credentialFor(A, payload), target("pay_crashed"));
    assert.ok(resumed.ok, `/verify passing means the earlier settle never happened: ${failureCode(resumed)}`);
    assert.equal(resumed.principalId, "pay_crashed", "the stored target keeps the credits");
    assert.equal(A.usage.creditsRemaining("pay_crashed"), CREDITS);
    assert.equal(markerOf(A, payload), null);
  });

  it("a marker that cannot be read or written answers 503 without a session, and nothing settles", async () => {
    const h = await harness();
    const payload = x402Payload();
    h.ledger.failGetSettlement = 1;
    const unread = await call(h, "/v1/jobs", { headers: { "x-payment": header(payload) } });
    assert.equal(unread.status, 503);
    assert.equal(unread.headers.get("x-session-token"), null);
    assert.equal(h.upstream.calls.length, 0);

    h.ledger.failBeginSettlement = 1;
    const unwritten = await h.payments.redeem(credentialFor(h, payload), target("pay_unwritten"));
    assert.equal(failureCode(unwritten), "payment_recording_failed");
    assert.equal(grantOf(unwritten), null);
    assert.equal(h.upstream.count("/verify"), 1);
    assert.equal(h.upstream.count("/settle"), 0, "no money moves without the marker");

    const retry = await h.payments.redeem(credentialFor(h, payload), target("pay_unwritten"));
    assert.ok(retry.ok, failureCode(retry));
    assert.equal(h.usage.creditsRemaining("pay_unwritten"), CREDITS);
  });
});

describe("Round 5 G5: every retry after an unknown settle stays unconfirmed", () => {
  it("/verify failing after an unknown settle (transport error, HTML gateway reply) is unconfirmed, not x402_verification_failed", async () => {
    const h = await harness();
    const payload = x402Payload();
    const credential = credentialFor(h, payload);
    h.upstream.settleMode = "reset-after-broadcast";
    const first = await h.payments.redeem(credential, target("pay_vf"));
    assert.equal(failureCode(first), "x402_settlement_unconfirmed");
    assert.equal(grantOf(first), "pay_vf", "the request whose own outcome is unknown learns whose session it is");

    h.upstream.settleMode = "ok";
    for (const mode of ["reset", "gateway-html"] as const) {
      h.upstream.verifyMode = mode;
      const retry = await h.payments.redeem(credential, target("pay_vf"));
      assert.equal(failureCode(retry), "x402_settlement_unconfirmed", `verify ${mode}`);
      assert.equal(grantOf(retry), null);
      const overHttp = await call(h, "/v1/jobs", { headers: { "x-payment": header(payload) } });
      assert.equal(overHttp.status, 502, `verify ${mode}: ${JSON.stringify(overHttp.body)}`);
      assert.equal(overHttp.headers.get("www-authenticate"), null);
    }
    // Control: without an earlier unknown settle a /verify transport error moved nothing.
    h.upstream.verifyMode = "reset";
    assert.equal(failureCode(await h.payments.redeem(credentialFor(h, x402Payload()), target("pay_vf2"))), "x402_verification_failed");
  });

  it("a retry after validBefore of an unknown settle is unconfirmed with no facilitator call, not x402_expired", async () => {
    const h = await harness();
    const payload = x402Payload();
    const credential = credentialFor(h, payload);
    h.upstream.settleMode = "gateway-504";
    assert.equal(failureCode(await h.payments.redeem(credential, target("pay_exp"))), "x402_settlement_unconfirmed");
    const calls = h.upstream.calls.length;
    const control = x402Payload();
    mock.timers.enable({ apis: ["Date"], now: Date.now() + 2 * 3600_000 });
    try {
      const retry = await h.payments.redeem(credential, target("pay_exp"));
      assert.equal(failureCode(retry), "x402_settlement_unconfirmed");
      assert.equal(h.upstream.calls.length, calls);
      assert.equal(failureCode(await h.payments.redeem(credentialFor(h, control), target("pay_exp2"))), "x402_expired", "an expired payment that never settled is still refused");
    } finally {
      mock.timers.reset();
    }
  });

  it("success without a transaction id is unconfirmed, and so is every retry", async () => {
    const h = await harness();
    const payload = x402Payload();
    h.upstream.settleMode = "ok-no-tx";
    const first = await call(h, "/v1/jobs", { headers: { "x-payment": header(payload) } });
    assert.equal(first.status, 502);
    assert.equal(first.body.error, "x402_settlement_unconfirmed");
    assert.equal(markerOf(h, payload)?.state, "unknown", "the transfer moved, so the marker stays");
    h.upstream.settleMode = "ok";
    const retry = await call(h, "/v1/jobs", { headers: { "x-payment": header(payload) } });
    assert.equal(retry.status, 502, `not x402_invalid: ${JSON.stringify(retry.body)}`);
    assert.equal(retry.headers.get("www-authenticate"), null);

    // An unknown settle, then a lenient verify whose settle succeeds without a tx, then a strict verify.
    const second = x402Payload();
    const credential = credentialFor(h, second);
    h.upstream.settleMode = "gateway-504";
    assert.equal(failureCode(await h.payments.redeem(credential, target("pay_c2"))), "x402_settlement_unconfirmed");
    h.upstream.verifyMode = "lenient";
    h.upstream.settleMode = "ok-no-tx";
    assert.equal(failureCode(await h.payments.redeem(credential, target("pay_c2"))), "x402_settlement_unconfirmed");
    h.upstream.verifyMode = "strict";
    h.upstream.settleMode = "ok";
    assert.equal(failureCode(await h.payments.redeem(credential, target("pay_c2"))), "x402_settlement_unconfirmed");
    assert.equal(h.usage.creditsRemaining("pay_c2"), null);
  });

  it("a settle that never broadcast completes on retry at a sibling, onto the session the 502 handed out", async () => {
    const A = await harness();
    const B = await harness({}, A);
    const payload = x402Payload();
    A.upstream.settleMode = "reset-before-broadcast";
    const first = await call(A, "/v1/jobs", { headers: { "x-payment": header(payload) } });
    assert.equal(first.status, 502);
    const token = first.headers.get("x-session-token");
    assert.equal(A.sessions.verify(token ?? "")?.sub, derivedPrincipal(payload));

    A.upstream.settleMode = "ok";
    // Round 8: an 'unknown' marker is re-verified at most once a minute.
    ageMarkers(A, 61_000);
    // Round 6: the retry carries the 502's session. The payload alone would record the payment but get no
    // token (see the P2 tests below).
    const retry = await call(B, "/v1/jobs", { headers: { "x-payment": header(payload), "x-session-token": token ?? "" } });
    assert.equal(retry.status, 200, JSON.stringify(retry.body));
    assert.ok(retry.headers.get("payment-receipt"));
    assert.equal(B.sessions.verify(retry.headers.get("x-session-token") ?? "")?.sub, derivedPrincipal(payload));
    assert.equal(B.usage.creditsRemaining(derivedPrincipal(payload)), CREDITS);
    assert.equal(markerOf(A, payload), null);
    assert.equal(A.upstream.count("/settle"), 2);
  });

  it("without a shared database the markers live in memory with the same answers", async () => {
    const h = await harness();
    const usage = new UsageTracker(null);
    const payments = new PaymentManager(h.config, usage);
    try {
      const unknown = credentialFor(h, x402Payload());
      h.upstream.settleMode = "reset-after-broadcast";
      assert.equal(failureCode(await payments.redeem(unknown, target("pay_mem"))), "x402_settlement_unconfirmed");
      h.upstream.settleMode = "ok";
      assert.equal(failureCode(await payments.redeem(unknown, target("pay_mem"))), "x402_settlement_unconfirmed");

      const noTx = credentialFor(h, x402Payload());
      h.upstream.settleMode = "ok-no-tx";
      assert.equal(failureCode(await payments.redeem(noTx, target("pay_mem"))), "x402_settlement_unconfirmed");
      h.upstream.settleMode = "ok";
      assert.equal(failureCode(await payments.redeem(noTx, target("pay_mem"))), "x402_settlement_unconfirmed");

      // Round 8: an 'unknown' marker is re-verified at most once a minute, so each retry below runs a minute later.
      const aMinuteLater = <T>(run: () => Promise<T>): Promise<T> => {
        mock.timers.enable({ apis: ["Date"], now: Date.now() + 61_000 });
        return run().finally(() => mock.timers.reset());
      };
      // Round 6: only a top-up by the 502's session collects the receipt; a payload alone is recorded without it.
      const late = credentialFor(h, x402Payload());
      h.upstream.settleMode = "reset-before-broadcast";
      assert.equal(failureCode(await payments.redeem(late, target("pay_mem_late"))), "x402_settlement_unconfirmed");
      h.upstream.settleMode = "ok";
      assert.ok((await aMinuteLater(() => payments.redeem(late, topUpOf("pay_mem_late")))).ok);
      assert.equal(usage.creditsRemaining("pay_mem_late"), CREDITS);
      assert.equal(failureCode(await payments.redeem(late, target("pay_mem_late"))), "payment_already_redeemed");

      const plain = credentialFor(h, x402Payload());
      h.upstream.settleMode = "reset-before-broadcast";
      assert.equal(failureCode(await payments.redeem(plain, target("pay_mem_plain"))), "x402_settlement_unconfirmed");
      h.upstream.settleMode = "ok";
      const retry = await aMinuteLater(() => payments.redeem(plain, target("pay_mem_plain")));
      assert.equal(failureCode(retry), "payment_already_redeemed");
      assert.equal(grantOf(retry), null);
      assert.equal(usage.creditsRemaining("pay_mem_plain"), CREDITS);
    } finally {
      payments.close();
    }
  });

  it("CreditLedger markers: one claim per payment, a compare-and-set resume, and prune keeps settled markers", async () => {
    const db = await openDatabase(":memory:");
    assert.ok(db);
    try {
      const ledger = new CreditLedger(db);
      const start = { paymentId: "x402_a", principalId: "pay_a", label: "x402:a", credits: 5 };
      assert.equal(ledger.beginSettlement(start, 1000), true);
      assert.equal(ledger.beginSettlement({ ...start, principalId: "pay_other" }, 2000), false, "a second claim loses");
      assert.equal(ledger.getSettlement("x402_a")?.principalId, "pay_a");
      ledger.markSettlement("x402_a", "unknown", null, null, 3000);
      const seen = ledger.getSettlement("x402_a");
      assert.ok(seen);
      assert.equal(ledger.resumeSettlement(seen, 4000), true);
      assert.equal(ledger.resumeSettlement(seen, 5000), false, "a process that saw the same unknown marker loses the race");
      ledger.markSettlement("x402_a", "settled", "0xabc", { method: "x402", transaction: "0xabc" }, 6000);
      ledger.markSettlement("x402_a", "settled", null, null, 7000);
      ledger.markSettlement("x402_a", "unknown", null, null, 7500);
      const settled = ledger.getSettlement("x402_a");
      assert.equal(settled?.state, "settled", "a settled marker is never moved back to unknown");
      assert.equal(settled?.updatedAt, 7000);
      assert.equal(settled?.tx, "0xabc", "a later update keeps the transaction");
      assert.deepEqual(settled?.receipt, { method: "x402", transaction: "0xabc" });
      assert.deepEqual(
        ledger.listSettled(7001).map((m) => m.paymentId),
        ["x402_a"]
      );
      assert.equal(ledger.listSettled(7000).length, 0);
      ledger.beginSettlement({ ...start, paymentId: "x402_b" }, 100);
      ledger.markSettlement("x402_b", "unknown", null, null, 100);
      ledger.beginSettlement({ ...start, paymentId: "x402_c" }, 100);
      assert.equal(ledger.pruneSettlements(10_000), 2);
      assert.ok(ledger.getSettlement("x402_a"), "moved money is never pruned");
      ledger.endSettlement("x402_a");
      assert.equal(ledger.getSettlement("x402_a"), null);
    } finally {
      db.close();
    }
  });
});

describe("Round 5: spending routes match case-insensitively, like Express", () => {
  it("POST /V1/JOBS from an exhausted session is challenged like POST /v1/jobs", async () => {
    const h = await harness();
    const session = await buyCredits(h);
    assert.equal(h.usage.consumeCredits(session.principalId, CREDITS), true);
    const stale = { authorization: `Bearer ${session.token}`, "x-payment": session.paymentHeader };
    const body = { domains: ["example.com"], checks: ["email"] };
    for (const route of ["/V1/JOBS", "/v1/Jobs/", "/V1/jobs?wait=1"]) {
      const res = await call(h, route, { method: "POST", headers: stale, body });
      assert.equal(res.status, 409, `${route}: ${JSON.stringify(res.body)}`);
      assert.equal(res.body.reason, "payment_already_redeemed");
      assert.ok(Array.isArray(res.body.accepts) && res.body.accepts.length > 0);
    }
    const bare = await call(h, "/V1/JOBS", { method: "POST", headers: { authorization: `Bearer ${session.token}` }, body });
    assert.equal(bare.status, 402);
    assert.equal(bare.body.reason, "credits_exhausted");
    const read = await call(h, "/V1/JOBS", { headers: stale });
    assert.equal(read.status, 200, "reading stays open to an exhausted session");
  });
});

describe("Round 5 G8: openStorage when the database stays locked", () => {
  it("a stdio server runs without storage; an HTTP server still refuses to start", async () => {
    const latest = Math.max(...MIGRATIONS.map((m) => m.version));
    const dir = await mkdtemp(path.join(tmpdir(), "sdm-r5-lock-"));
    const file = path.join(dir, "shared.db");
    const holder = await openDatabase(file);
    assert.ok(holder);
    try {
      holder.prepare("UPDATE meta SET value = ? WHERE key = 'schema_version'").run(String(latest - 1));
      holder.exec("BEGIN IMMEDIATE");
      const stdio = loadConfig({ STACKDNS_DB_FILE: file, STACKDNS_TRANSPORT: "stdio" }, []);
      assert.equal(stdio.transport, "stdio");
      assert.equal(await openStorage(stdio, 200), null);
      const httpConfig = loadConfig({ STACKDNS_DB_FILE: file, STACKDNS_TRANSPORT: "http", STACKDNS_SESSION_SECRET: SESSION_SECRET }, []);
      await assert.rejects(openStorage(httpConfig, 200), /locked/i);
    } finally {
      try {
        holder.exec("ROLLBACK");
      } catch {
        // not in a transaction
      }
      holder.close();
      await rm(dir, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// Round 6 regressions
// ---------------------------------------------------------------------------

const JOB_BODY = { domains: ["example.com"], checks: ["email"] };
const PAID_TOOL_CALL = { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "inspect_tech_stack", arguments: { domain: "example.com" } } };
/** The two ways to spend prepaid credits: a bulk job and a paid tool call. */
const SPENDING_CALLS = [
  ["/v1/jobs", JOB_BODY],
  ["/mcp", PAID_TOOL_CALL]
] as const;

describe("Round 6 P1: the session a 503 or 502 handed out is never asked to pay again while its payment is pending", () => {
  it("the 503's session gets 503 on spending routes, here and at a sibling, until the payment is recorded", async () => {
    const A = await harness();
    const B = await harness({}, A);
    const payload = x402Payload();
    A.ledger.failRedeem = 1000; // the database keeps failing, so nothing can record the payment yet
    const first = await call(A, "/v1/jobs", { headers: { "x-payment": header(payload) } });
    assert.equal(first.status, 503);
    const token = first.headers.get("x-session-token");
    assert.ok(token);
    const settles = A.upstream.count("/settle");

    // A answers from its own unrecorded entry, B from the shared 'settled' marker.
    for (const h of [A, B]) {
      for (const [route, body] of SPENDING_CALLS) {
        const res = await call(h, route, { method: "POST", headers: { authorization: `Bearer ${token}` }, body });
        assert.equal(res.status, 503, `${route}: never a fresh payment demand: ${JSON.stringify(res.body)}`);
        assert.equal(res.body.error, "payment_recording_failed");
        assert.equal(res.headers.get("www-authenticate"), null);
        assert.equal(res.body.accepts, undefined);
        assert.equal(res.headers.get("retry-after"), "5");
      }
    }
    assert.equal((await call(A, "/v1/jobs", { headers: { authorization: `Bearer ${token}` } })).status, 200, "reading stays open");

    A.ledger.failRedeem = 0;
    assert.equal((await call(A, "/v1/jobs", { headers: { "x-payment": header(payload) } })).status, 409, "the retry records the payment");
    const spend = await call(A, "/v1/jobs", { method: "POST", headers: { authorization: `Bearer ${token}` }, body: JOB_BODY });
    assert.equal(spend.status, 200, JSON.stringify(spend.body));
    assert.equal((spend.body.principal as { id?: string }).id, derivedPrincipal(payload));
    assert.equal(A.upstream.count("/settle"), settles, "the payer paid once");
  });

  it("the 502's session gets 502, a live settle 409 and a stale one 502; an empty session with nothing pending is still asked to pay", async () => {
    const h = await harness();
    const payload = x402Payload();
    h.upstream.settleMode = "reset-after-broadcast";
    const first = await call(h, "/v1/jobs", { headers: { "x-payment": header(payload) } });
    assert.equal(first.status, 502);
    const token = first.headers.get("x-session-token");
    assert.ok(token);
    h.upstream.settleMode = "ok";
    for (const [route, body] of SPENDING_CALLS) {
      const res = await call(h, route, { method: "POST", headers: { authorization: `Bearer ${token}` }, body });
      assert.equal(res.status, 502, `${route}: ${JSON.stringify(res.body)}`);
      assert.equal(res.body.error, "x402_settlement_unconfirmed");
      assert.equal(res.headers.get("www-authenticate"), null);
      assert.equal(res.body.accepts, undefined);
    }

    // A top-up of an exhausted session is being settled by another request right now.
    h.usage.addCredits("pay_live", "payg", "x402:live", 1);
    assert.equal(h.usage.consumeCredits("pay_live", 1), true);
    assert.equal(h.usage.beginSettlement({ paymentId: "x402_live_topup", principalId: "pay_live", label: "x402:live", credits: CREDITS }, Date.now()), true);
    const live = h.sessions.issue({ sub: "pay_live", plan: "payg", label: "x402:live" });
    const busy = await call(h, "/v1/jobs", { method: "POST", headers: { authorization: `Bearer ${live}` }, body: JOB_BODY });
    assert.equal(busy.status, 409, JSON.stringify(busy.body));
    assert.equal(busy.body.error, "payment_redemption_in_progress");
    assert.equal(busy.headers.get("retry-after"), "2");
    assert.equal(busy.headers.get("www-authenticate"), null);
    // Its process died mid-settle: the outcome is as unknown as a settle that never answered.
    ageMarkers(h, 61_000);
    const stale = await call(h, "/v1/jobs", { method: "POST", headers: { authorization: `Bearer ${live}` }, body: JOB_BODY });
    assert.equal(stale.status, 502, JSON.stringify(stale.body));

    const empty = h.sessions.issue({ sub: "pay_nothing_pending", plan: "payg", label: "" });
    const control = await call(h, "/v1/jobs", { method: "POST", headers: { authorization: `Bearer ${empty}` }, body: JOB_BODY });
    assert.equal(control.status, 402);
    assert.equal(control.body.reason, "credits_exhausted");
  });

  it("pendingSettlementState ranks a principal's markers the same in the database and in memory", async () => {
    const db = await openDatabase(":memory:");
    assert.ok(db);
    try {
      type Markers = Pick<SharedLedger, "beginSettlement" | "markSettlement" | "pendingSettlementState">;
      const stores: Array<[string, Markers]> = [
        ["CreditLedger", new CreditLedger(db)],
        ["UsageTracker without a ledger", new UsageTracker(null)]
      ];
      for (const [name, store] of stores) {
        const start = (paymentId: string, principalId = "pay_p"): SettlementStart => ({ paymentId, principalId, label: "x402:p", credits: 5 });
        assert.equal(store.pendingSettlementState("pay_p", 0), null, name);
        store.beginSettlement(start("x402_u"), 1000);
        store.markSettlement("x402_u", "unknown", null, null, 1000);
        assert.equal(store.pendingSettlementState("pay_p", 0), "unknown", name);
        store.beginSettlement(start("x402_s"), 2000);
        assert.equal(store.pendingSettlementState("pay_p", 0), "settling", `${name}: a live settle outranks an unknown one`);
        assert.equal(store.pendingSettlementState("pay_p", 5000), "unknown", `${name}: a stale settle counts as unknown`);
        assert.equal(store.pendingSettlementState("pay_p"), "settling", `${name}: no stale bound`);
        store.markSettlement("x402_s", "settled", "0xabc", null, 3000);
        assert.equal(store.pendingSettlementState("pay_p", 5000), "settled", `${name}: moved money outranks everything`);
        store.beginSettlement(start("x402_o", "pay_other"), 4000);
        assert.equal(store.pendingSettlementState("pay_other", 0), "settling", name);
        assert.equal(store.pendingSettlementState("pay_nobody", 0), null, name);
      }
    } finally {
      db.close();
    }
  });
});

describe("Round 6 P2: after an unknown settle, a retry without the stored target's session is never handed it", () => {
  it("a session-less retry of the full payload at a sibling gets no token, whether its settle succeeds, is unknown again or cannot be recorded", async () => {
    const A = await harness();
    const B = await harness({}, A);
    const expected = { settled: 409, unknown: 502, unrecorded: 503 } as const;
    for (const outcome of ["settled", "unknown", "unrecorded"] as const) {
      const payload = x402Payload();
      // Nothing consumed the nonce (the broadcast is pending or reverted), so /verify still passes for
      // anyone holding the calldata.
      A.upstream.settleMode = "reset-before-broadcast";
      const payer = await call(A, "/v1/jobs", { headers: { "x-payment": header(payload) } });
      assert.equal(payer.status, 502);
      const token = payer.headers.get("x-session-token");
      assert.equal(A.sessions.verify(token ?? "")?.sub, derivedPrincipal(payload));

      A.upstream.settleMode = outcome === "unknown" ? "reset-before-broadcast" : "ok";
      B.ledger.failRedeem = outcome === "unrecorded" ? 1 : 0;
      // Round 8: an 'unknown' marker is re-verified at most once a minute.
      ageMarkers(A, 61_000);
      const observer = await call(B, "/v1/jobs", { headers: { "x-payment": header(payload) } });
      assert.equal(observer.status, expected[outcome], `${outcome}: ${JSON.stringify(observer.body)}`);
      assert.equal(observer.headers.get("x-session-token"), null, `${outcome}: the derived principal is public, so it proves nothing`);
      assert.equal(observer.headers.get("payment-receipt"), null);
      assert.equal(observer.body.sessionToken, undefined);

      if (outcome === "settled") {
        assert.equal(A.usage.creditsRemaining(derivedPrincipal(payload)), CREDITS, "the credits land on the stored target");
        const spend = await call(A, "/v1/jobs", { method: "POST", headers: { authorization: `Bearer ${token}` }, body: JOB_BODY });
        assert.equal(spend.status, 200, "the 502's session reaches them");
        assert.equal((spend.body.principal as { id?: string }).id, derivedPrincipal(payload));
      }
    }
    B.ledger.failRedeem = 0;
  });

  it("a stale 'settling' marker hands the session to the first presenter only when no earlier answer went out", async () => {
    const h = await harness();
    const now = Date.now();

    // The first settle's process died before answering: nobody holds the session, so the retry is the first presenter.
    const crashed = x402Payload();
    const crashedId = x402ReplayKey(crashed);
    assert.ok(crashedId);
    assert.equal(h.usage.beginSettlement({ paymentId: crashedId, principalId: derivedPrincipal(crashed), label: `x402:${crashedId}`, credits: CREDITS }, now - 90_000), true);
    const first = await call(h, "/v1/jobs", { headers: { "x-payment": header(crashed) } });
    assert.equal(first.status, 200, JSON.stringify(first.body));
    assert.equal(h.sessions.verify(first.headers.get("x-session-token") ?? "")?.sub, derivedPrincipal(crashed));

    // An earlier settle answered 502 with the session; the settle that resumed it then died.
    const resumed = x402Payload();
    const resumedId = x402ReplayKey(resumed);
    assert.ok(resumedId);
    assert.equal(h.usage.beginSettlement({ paymentId: resumedId, principalId: derivedPrincipal(resumed), label: `x402:${resumedId}`, credits: CREDITS }, now - 120_000), true);
    h.usage.markSettlement(resumedId, "unknown", null, null, now - 100_000);
    const seen = h.usage.getSettlement(resumedId);
    assert.ok(seen);
    assert.equal(h.usage.resumeSettlement(seen, now - 90_000), true);
    const retry = await call(h, "/v1/jobs", { headers: { "x-payment": header(resumed) } });
    assert.equal(retry.status, 409, JSON.stringify(retry.body));
    assert.equal(retry.headers.get("x-session-token"), null);
    assert.equal(h.usage.creditsRemaining(derivedPrincipal(resumed)), CREDITS, "recorded onto the stored target");
  });
});

describe("Round 6 P3: the settling request and a sibling that adopts its marker", () => {
  it("an adopter that records the payment while the settling request waits out a lock leaves that request its session", async () => {
    const A = await harness();
    const B = await harness({}, A);
    const payload = x402Payload();
    A.ledger.lockRedeem = true; // another connection holds the write lock right after A marked the payment settled
    const firstP = call(A, "/v1/jobs", { headers: { "x-payment": header(payload) } });
    for (let i = 0; i < 400 && !(markerOf(A, payload)?.state === "settled" && A.ledger.redeemCalls > 0); i++) await new Promise((resolve) => setTimeout(resolve, 5));
    assert.equal(markerOf(A, payload)?.state, "settled");

    // A sibling adopts the marker while A is between attempts.
    ageMarkers(A, ADOPTABLE_AGE_MS);
    const adopted = await call(B, "/v1/jobs", { headers: { "x-payment": header(forgedFrom(payload)) } });
    assert.equal(adopted.status, 409, JSON.stringify(adopted.body));
    assert.equal(adopted.headers.get("x-session-token"), null);
    assert.equal(B.usage.creditsRemaining(derivedPrincipal(payload)), CREDITS);

    A.ledger.lockRedeem = false;
    const first = await firstP;
    assert.equal(first.status, 200, `the settling request keeps its answer: ${JSON.stringify(first.body)}`);
    assert.ok(first.headers.get("payment-receipt"));
    assert.equal(A.sessions.verify(first.headers.get("x-session-token") ?? "")?.sub, derivedPrincipal(payload));
    assert.equal(A.usage.creditsRemaining(derivedPrincipal(payload)), CREDITS, "credited once");
    assert.equal(A.upstream.count("/settle"), 1);
  });

  it("an idempotent settle onto a transaction credited before it still answers 'already redeemed'", async () => {
    const h = await harness();
    const payload = x402Payload();
    const nonce = (payload.payload as { authorization: { nonce: string } }).authorization.nonce;
    // The stub's transaction id for this nonce, already credited by an earlier payment.
    const tx = `0x${createHash("sha256").update(nonce).digest("hex")}`;
    assert.equal(await h.usage.redeemAndGrant([`x402_${tx}`, "x402_earlier"], "pay_earlier", "payg", "x402:earlier", CREDITS), true);
    const res = await h.payments.redeem(credentialFor(h, payload), target("pay_idempotent"));
    assert.equal(failureCode(res), "payment_already_redeemed");
    assert.match(res.ok ? "" : res.message, /^Transaction /);
    assert.equal(h.usage.creditsRemaining("pay_idempotent"), null);
  });

  it("redeemAndGrant gives up on a locked database after REDEEM_LOCK_BUDGET_MS of wall time, blocked attempts included", async () => {
    const db = await openDatabase(":memory:");
    assert.ok(db);
    const ledger = new FlakyLedger(new CreditLedger(db));
    const usage = new UsageTracker(null);
    usage.attachLedger(ledger);
    ledger.lockRedeem = true;
    // Each attempt blocks for the busy timeout before SQLite reports the lock.
    ledger.onLockedRedeem = () => mock.timers.tick(BUSY_TIMEOUT_MS);
    mock.timers.enable({ apis: ["Date", "setTimeout"], now: Date.now() });
    try {
      const started = Date.now();
      const run: { done: boolean; error: unknown } = { done: false, error: null };
      usage.redeemAndGrant(["x402_tx_wall", "x402_pid_wall"], "pay_wall", "payg", "x402:wall", CREDITS).then(
        () => (run.done = true),
        (error: unknown) => Object.assign(run, { done: true, error })
      );
      for (let i = 0; i < 2000 && !run.done; i++) {
        await new Promise((resolve) => setImmediate(resolve));
        if (!run.done) mock.timers.tick(50);
      }
      const elapsed = Date.now() - started;
      assert.ok(run.done, "it gives up");
      assert.ok(run.error instanceof Error, "the lock error surfaces");
      assert.match(run.error.message, /database is locked/);
      // Summed sleeps alone reached 15 s only after about 11 blocked attempts: about 26 s here.
      assert.ok(elapsed >= REDEEM_LOCK_BUDGET_MS, `kept trying for the budget: ${elapsed} ms`);
      assert.ok(elapsed <= REDEEM_LOCK_BUDGET_MS + BUSY_TIMEOUT_MS + 100, `at most one blocked attempt past the budget: ${elapsed} ms`);
    } finally {
      mock.timers.reset();
      db.close();
    }
  });
});

describe("Round 6 P4: a stdio server's default lock budget", () => {
  it("openStorage without a budget gives a stdio server up on a locked database well inside an MCP client's 60 s initialize timeout", { timeout: 50_000 }, async () => {
    assert.ok(STDIO_LOCK_BUDGET_MS <= 20_000, "leaves the rest of startup room inside 60 s");
    const latest = Math.max(...MIGRATIONS.map((m) => m.version));
    const dir = await mkdtemp(path.join(tmpdir(), "sdm-r6-lock-"));
    const file = path.join(dir, "shared.db");
    const holder = await openDatabase(file);
    assert.ok(holder);
    try {
      holder.prepare("UPDATE meta SET value = ? WHERE key = 'schema_version'").run(String(latest - 1));
      holder.exec("BEGIN IMMEDIATE");
      const stdio = loadConfig({ STACKDNS_DB_FILE: file, STACKDNS_TRANSPORT: "stdio" }, []);
      const started = Date.now();
      assert.equal(await openStorage(stdio), null);
      const elapsed = Date.now() - started;
      assert.ok(elapsed >= STDIO_LOCK_BUDGET_MS, `waited out the stdio budget: ${elapsed} ms`);
      assert.ok(elapsed < 30_000, `not the 120 s HTTP budget: ${elapsed} ms`);
    } finally {
      try {
        holder.exec("ROLLBACK");
      } catch {
        // not in a transaction
      }
      holder.close();
      await rm(dir, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// Round 7 regressions
// ---------------------------------------------------------------------------

/** The unknown-outcome paths of /settle: a transport error, a 5xx answer and a success without a transaction id. */
const UNKNOWN_SETTLES = ["reset-after-broadcast", "json-500", "ok-no-tx"] as const;

/** One run of the recording timer (RECORDING_RETRY_MS). The PaymentManager starts it, so mock setInterval before the harness. */
async function tickRecordingTimer(): Promise<void> {
  mock.timers.tick(10_000);
  await drainMicrotasks();
}

describe("Round 7: unconfirmed grants, leftover settlement markers and an unreadable pending state", () => {
  it("P2: a first presenter's unknown settle carries the grant only when its 'unknown' marker was written", async () => {
    const h = await harness();
    for (const mode of UNKNOWN_SETTLES) {
      h.upstream.settleMode = mode;
      const control = x402Payload();
      const marked = await h.payments.redeem(credentialFor(h, control), target(`pay_marked_${mode}`));
      assert.equal(failureCode(marked), "x402_settlement_unconfirmed", mode);
      assert.equal(grantOf(marked), `pay_marked_${mode}`, `${mode}: the marker records that an answer went out, so this answer carries the session`);
      assert.equal(markerOf(h, control)?.state, "unknown", mode);

      const payload = x402Payload();
      h.ledger.failMark.add("unknown");
      const unmarked = await h.payments.redeem(credentialFor(h, payload), target(`pay_unmarked_${mode}`));
      h.ledger.failMark.clear();
      assert.equal(failureCode(unmarked), "x402_settlement_unconfirmed", mode);
      assert.equal(grantOf(unmarked), null, `${mode}: the marker would later read as "died before answering" and hand the session out again`);
      assert.equal(markerOf(h, payload)?.state, "settling", `${mode}: the 'unknown' write failed`);
    }

    // A resumed marker was rewritten when it was resumed, so a failed 'unknown' write changes nothing for a retry:
    // a top-up by the stored target may still collect the session.
    const resumed = x402Payload();
    h.upstream.settleMode = "reset-before-broadcast";
    assert.equal(failureCode(await h.payments.redeem(credentialFor(h, resumed), target("pay_resumed"))), "x402_settlement_unconfirmed");
    // Round 8: an 'unknown' marker is re-verified at most once a minute.
    ageMarkers(h, 61_000);
    h.ledger.failMark.add("unknown");
    const again = await h.payments.redeem(credentialFor(h, resumed), topUpOf("pay_resumed"));
    h.ledger.failMark.clear();
    assert.equal(failureCode(again), "x402_settlement_unconfirmed");
    assert.equal(grantOf(again), "pay_resumed");
  });

  it("P2 over HTTP: that 502 has no X-Session-Token; the payer's own retry collects the session once the settle counts as abandoned", async () => {
    const h = await harness();
    const payload = x402Payload();
    h.upstream.settleMode = "reset-before-broadcast";
    h.ledger.failMark.add("unknown");
    const first = await call(h, "/v1/jobs", { headers: { "x-payment": header(payload) } });
    h.ledger.failMark.clear();
    assert.equal(first.status, 502, JSON.stringify(first.body));
    assert.equal(first.body.error, "x402_settlement_unconfirmed");
    assert.equal(first.headers.get("www-authenticate"), null);
    assert.equal(first.headers.get("x-session-token"), null, "no session goes out that the marker does not record");
    assert.equal(first.body.sessionToken, undefined);
    assert.equal(first.body.principal, undefined);

    // Control: with the write succeeding the 502 still carries the session.
    const control = x402Payload();
    const marked = await call(h, "/v1/jobs", { headers: { "x-payment": header(control) } });
    assert.equal(marked.status, 502);
    assert.equal(h.sessions.verify(marked.headers.get("x-session-token") ?? "")?.sub, derivedPrincipal(control));

    // Nobody holds the first payment's session, so once its 'settling' marker is stale the next presenter is its first.
    h.upstream.settleMode = "ok";
    ageMarkers(h, 61_000);
    const retry = await call(h, "/v1/jobs", { headers: { "x-payment": header(payload) } });
    assert.equal(retry.status, 200, JSON.stringify(retry.body));
    assert.equal(h.sessions.verify(retry.headers.get("x-session-token") ?? "")?.sub, derivedPrincipal(payload));
    assert.equal(h.usage.creditsRemaining(derivedPrincipal(payload)), CREDITS);
  });

  it("P1: a marker whose payment is redeemed is not pending, in the database and in memory", async () => {
    const db = await openDatabase(":memory:");
    assert.ok(db);
    try {
      type Markers = Pick<SharedLedger, "beginSettlement" | "markSettlement" | "getSettlement" | "pendingSettlementState">;
      const ledger = new CreditLedger(db);
      const tracker = new UsageTracker(null);
      const stores: Array<[string, Markers, (paymentId: string) => void]> = [
        ["CreditLedger", ledger, (id) => assert.equal(ledger.markRedeemed(id), true)],
        ["UsageTracker without a ledger", tracker, (id) => assert.equal(tracker.markPaymentRedeemed(id), true)]
      ];
      for (const [name, store, redeem] of stores) {
        const start = (paymentId: string): SettlementStart => ({ paymentId, principalId: "pay_q", label: "x402:q", credits: 5 });
        store.beginSettlement(start("x402_done"), 1000);
        store.markSettlement("x402_done", "settled", "0xdone", null, 1100);
        store.beginSettlement(start("x402_open"), 1200);
        store.markSettlement("x402_open", "unknown", null, null, 1300);
        assert.equal(store.pendingSettlementState("pay_q", 0), "settled", name);
        // Recorded, but the marker's removal failed.
        redeem("x402_done");
        assert.ok(store.getSettlement("x402_done"), `${name}: the marker is still there`);
        assert.equal(store.pendingSettlementState("pay_q", 0), "unknown", `${name}: only the unredeemed payment is pending`);
        redeem("x402_open");
        assert.equal(store.pendingSettlementState("pay_q", 0), null, `${name}: nothing is pending`);
      }
    } finally {
      db.close();
    }
  });

  it("P1: a payment recorded on retry whose marker removal failed leaves the spent session asked to pay (402), here and at a sibling", async () => {
    const A = await harness();
    const B = await harness({}, A);
    const payload = x402Payload();
    const principal = derivedPrincipal(payload);
    A.ledger.failRedeem = 1;
    const first = await call(A, "/v1/jobs", { headers: { "x-payment": header(payload) } });
    assert.equal(first.status, 503);
    const token = first.headers.get("x-session-token");
    assert.ok(token);

    // The retry records the payment; the DELETE of its marker right after fails once.
    A.ledger.failEndSettlement = 1;
    const retry = await call(A, "/v1/jobs", { headers: { "x-payment": header(payload) } });
    assert.equal(retry.status, 409, JSON.stringify(retry.body));
    assert.equal(A.ledger.failEndSettlement, 0, "the removal was attempted");
    assert.equal(markerOf(A, payload)?.state, "settled", "the marker outlived the recording");
    assert.equal(A.usage.creditsRemaining(principal), CREDITS);
    for (const h of [A, B]) assert.equal(h.payments.pendingFor(principal), null, "a redeemed payment is not pending");

    // The session spends what it bought, then needs more.
    assert.equal(A.usage.consumeCredits(principal, CREDITS), true);
    for (const h of [A, B]) {
      const res = await call(h, "/v1/jobs", { method: "POST", headers: { authorization: `Bearer ${token}` }, body: JOB_BODY });
      assert.equal(res.status, 402, `not "settled, do not pay again": ${JSON.stringify(res.body)}`);
      assert.equal(res.body.error, "payment_required");
      assert.equal(res.body.reason, "credits_exhausted");
      assert.ok(res.headers.get("www-authenticate"));
    }
  });

  it("P1: the recording timer adopts and removes a marker its own committed entry left behind; an uncommitted entry is only retried", async () => {
    mock.timers.enable({ apis: ["setInterval"] });
    try {
      const h = await harness();
      const payload = x402Payload();
      h.ledger.failRedeem = 1;
      assert.equal(failureCode(await h.payments.redeem(credentialFor(h, payload), target("pay_leftover"))), "payment_recording_failed");
      // The timer records it; the DELETE of its marker fails once.
      h.ledger.failEndSettlement = 1;
      await tickRecordingTimer();
      assert.equal(h.usage.creditsRemaining("pay_leftover"), CREDITS);
      assert.equal(h.ledger.failEndSettlement, 0, "the removal was attempted");
      assert.equal(markerOf(h, payload)?.state, "settled");
      assert.equal(h.payments.pendingFor("pay_leftover"), null);

      // Once adoptable, the timer finishes it idempotently, which removes the marker.
      ageMarkers(h, ADOPTABLE_AGE_MS);
      await tickRecordingTimer();
      assert.equal(markerOf(h, payload), null, "not left behind until the committed entry expires a day later");
      assert.equal(h.usage.creditsRemaining("pay_leftover"), CREDITS, "credited once");
      const own = await h.payments.redeem(credentialFor(h, payload), topUpOf("pay_leftover"));
      assert.ok(own.ok, `the top-up's own retry still collects its receipt: ${failureCode(own)}`);

      // An uncommitted entry is retried by its own loop, and its marker is not adopted beside it.
      const stuck = x402Payload();
      h.ledger.failRedeem = 1000;
      assert.equal(failureCode(await h.payments.redeem(credentialFor(h, stuck), target("pay_stuck"))), "payment_recording_failed");
      ageMarkers(h, ADOPTABLE_AGE_MS);
      const redeemCalls = h.ledger.redeemCalls;
      await tickRecordingTimer();
      assert.equal(h.ledger.redeemCalls - redeemCalls, 1, "one recording attempt per tick");
      assert.equal(markerOf(h, stuck)?.state, "settled");
      assert.equal(h.usage.creditsRemaining("pay_stuck"), null);
      h.ledger.failRedeem = 0;
      await tickRecordingTimer();
      assert.equal(h.usage.creditsRemaining("pay_stuck"), CREDITS);
      assert.equal(markerOf(h, stuck), null);
    } finally {
      mock.timers.reset();
    }
  });

  it("P1: a refused top-up whose marker removal failed is removed by the recording timer, so the spent session is asked to pay again", async () => {
    mock.timers.enable({ apis: ["setInterval"] });
    try {
      const h = await harness();
      const session = await buyCredits(h);
      assert.equal(h.usage.consumeCredits(session.principalId, CREDITS), true);
      const topUp = (payload: Record<string, unknown>) => call(h, "/v1/jobs", { method: "POST", headers: { authorization: `Bearer ${session.token}`, "x-payment": header(payload) }, body: JOB_BODY });
      const spend = () => call(h, "/v1/jobs", { method: "POST", headers: { authorization: `Bearer ${session.token}` }, body: JOB_BODY });

      const refused = x402Payload();
      h.upstream.settleMode = "refuse";
      h.ledger.failEndSettlement = 1;
      const answer = await topUp(refused);
      assert.equal(answer.status, 402, JSON.stringify(answer.body));
      assert.equal(answer.body.reason, "x402_settlement_failed", "nothing moved");
      assert.equal(h.ledger.failEndSettlement, 0, "the removal was attempted");
      assert.equal(markerOf(h, refused)?.state, "settling", "the claim outlived the refusal");
      assert.equal((await spend()).status, 409, "until it is removed it reads as a settle in flight");

      await tickRecordingTimer();
      assert.equal(markerOf(h, refused), null, "the timer removed the version this request wrote");
      const after = await spend();
      assert.equal(after.status, 402, JSON.stringify(after.body));
      assert.equal(after.body.reason, "credits_exhausted");
      assert.ok(after.headers.get("www-authenticate"));

      // Compare side: a marker resumed since the refusal belongs to a live settle and is kept.
      const resumed = x402Payload();
      h.ledger.failEndSettlement = 1;
      assert.equal((await topUp(resumed)).status, 402);
      const id = x402ReplayKey(resumed);
      assert.ok(id);
      const seen = h.usage.getSettlement(id);
      assert.ok(seen);
      assert.equal(h.usage.resumeSettlement(seen, seen.updatedAt + 1), true);
      await tickRecordingTimer();
      assert.equal(h.usage.getSettlement(id)?.updatedAt, seen.updatedAt + 1, "the resumed marker is not deleted");
      assert.equal(h.payments.pendingFor(session.principalId), "settling");
    } finally {
      mock.timers.reset();
    }
  });

  it("P1: endSettlement with a version deletes the marker only while it is that version, in the database and in memory", async () => {
    const db = await openDatabase(":memory:");
    assert.ok(db);
    try {
      type Markers = Pick<SharedLedger, "beginSettlement" | "resumeSettlement" | "markSettlement" | "getSettlement" | "endSettlement">;
      const stores: Array<[string, Markers]> = [
        ["CreditLedger", new CreditLedger(db)],
        ["UsageTracker without a ledger", new UsageTracker(null)]
      ];
      for (const [name, store] of stores) {
        const start: SettlementStart = { paymentId: "x402_cad", principalId: "pay_cad", label: "x402:cad", credits: 5 };
        assert.equal(store.beginSettlement(start, 1000), true, name);
        // The settle was refused and the removal failed; a retry found the marker stale and resumed it since.
        const seen = store.getSettlement("x402_cad");
        assert.ok(seen);
        assert.equal(store.resumeSettlement(seen, 70_000), true, name);
        store.endSettlement("x402_cad", 1000);
        assert.equal(store.getSettlement("x402_cad")?.updatedAt, 70_000, `${name}: the resumed marker survives the removal of the version it replaced`);
        store.markSettlement("x402_cad", "unknown", null, null, 80_000);
        store.endSettlement("x402_cad", 70_000);
        assert.equal(store.getSettlement("x402_cad")?.state, "unknown", `${name}: a later write is a newer version too`);
        store.endSettlement("x402_cad", 80_000);
        assert.equal(store.getSettlement("x402_cad"), null, `${name}: the current version is removed`);
        // Without a version the removal is unconditional.
        assert.equal(store.beginSettlement(start, 90_000), true, name);
        store.markSettlement("x402_cad", "settled", "0xcad", null, 91_000);
        store.endSettlement("x402_cad");
        assert.equal(store.getSettlement("x402_cad"), null, name);
      }
    } finally {
      db.close();
    }
  });

  it("P1: an exhausted session whose pending payments cannot be read gets 503 on spending routes, never a payment demand", async () => {
    const A = await harness();
    const B = await harness({}, A);
    // The 503's session, answered at a sibling: it has no local entry, so it must read the shared markers.
    const payload = x402Payload();
    A.ledger.failRedeem = 1000;
    const first = await call(A, "/v1/jobs", { headers: { "x-payment": header(payload) } });
    assert.equal(first.status, 503);
    const pendingToken = first.headers.get("x-session-token");
    assert.ok(pendingToken);
    B.ledger.failPendingSettlementState = 1;
    assert.equal(B.payments.pendingFor(derivedPrincipal(payload)), "unavailable");
    // A spent session with nothing pending: an unreadable state proves nothing either way.
    const spent = await buyCredits(B);
    assert.equal(B.usage.consumeCredits(spent.principalId, CREDITS), true);

    for (const token of [pendingToken, spent.token]) {
      for (const [route, body] of SPENDING_CALLS) {
        B.ledger.failPendingSettlementState = 1;
        const res = await call(B, route, { method: "POST", headers: { authorization: `Bearer ${token}` }, body });
        assert.equal(res.status, 503, `${route}: ${JSON.stringify(res.body)}`);
        assert.equal(res.body.error, "payment_recording_failed");
        assert.equal(res.headers.get("retry-after"), "5");
        assert.equal(res.headers.get("www-authenticate"), null);
        assert.equal(res.body.accepts, undefined);
        assert.equal(B.ledger.failPendingSettlementState, 0, "the read was attempted");
      }
    }
    B.ledger.failPendingSettlementState = 1;
    assert.equal((await call(B, "/v1/jobs", { headers: { authorization: `Bearer ${spent.token}` } })).status, 200, "reading never consults it");
    B.ledger.failPendingSettlementState = 0;

    // Readable again: the settled payment is still pending, and the spent session is asked to pay.
    const pending = await call(B, "/v1/jobs", { method: "POST", headers: { authorization: `Bearer ${pendingToken}` }, body: JOB_BODY });
    assert.equal(pending.status, 503);
    const control = await call(B, "/v1/jobs", { method: "POST", headers: { authorization: `Bearer ${spent.token}` }, body: JOB_BODY });
    assert.equal(control.status, 402);
    assert.equal(control.body.reason, "credits_exhausted");
    A.ledger.failRedeem = 0;
  });
});
