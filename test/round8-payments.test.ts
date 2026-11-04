/**
 * Round 8 regressions for the payments group:
 *   P-A  a 503 or 502 that hands out the session waits out a locked marker write first, and a process that
 *        answered with an unwritten marker never treats a later retry as the payment's first presenter
 *   P-B  an unconfirmed payment no longer locks a servable session out, is re-verified at most once a minute
 *        across processes, blocks its session's purchases for 24 h only, and keeps its marker 400 days
 *   P-D  the operator CLI (src/cli/settlements.ts): list, resolve --tx, resolve --failed, session
 *   P-E  two authorizations settled in one transaction are each credited; one authorization is credited once
 *   P-F  a balance recorded by a sibling between the balance read and pendingFor is served, not challenged
 *   P-H  without a database, settlement markers survive a restart in the usage file
 *   P-J  a stdio server that cannot attach the shared ledger runs without it; HTTP still refuses
 *   P-K  without a shared ledger the recording timer stops once nothing is left to record
 * and the discrepancies: Stripe's in-progress message, start_bulk_check over MCP as a spending call, the
 * billing block's daily quota after a bulk submission, and the served-session log line.
 *
 * Round 9 (at the end): X402_ASSET_VERSION reaches the requirements; an exhausted session re-attaching its
 * unconfirmed top-up follows the 24 h purchase rule; answersLocally() mirrors redeem()'s local answers; the
 * 'settled' re-mark waits for the recording; the tx guard identity is payer plus nonce; a leftover marker of
 * a recorded payment answers "already redeemed" and ends; the CLI filters before it limits and exits 2 on bad
 * usage; and a stdio STACKDNS_API_KEY without keys is warned about.
 *
 * Round 10 (last): the payer of an authorization identity is normalized (CAIP-10, 20-byte hex only), and an
 * identity without a usable payer yields to every payer-qualified guard of the same transaction and nonce, in
 * a server and in the CLI, so one authorization presented with `from` and then without it is credited once.
 * Round 11 adds the retry paths of a recording (a retry of the header, the recording timer, the answer after a
 * lock wait) to that block, and a payer-qualified identity yields to the guards of its transaction and nonce
 * whose payer part is not a 20-byte address (round 9 guards, resumed round 9 markers, the CLI).
 * Round 12: of two presentations of one authorization, the one claimed (settled) first is credited, not the one
 * recorded first, here, at a sibling and when markers are adopted; a recording whose transaction went to another
 * presentation says so instead of pointing at the earlier 503's session.
 *
 * Everything runs against local stubs: a 127.0.0.1 facilitator/Stripe stub, in-memory or temp-file SQLite
 * ledgers and an Express app with the real auth middleware.
 */

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, describe, it, mock } from "node:test";
import type { DatabaseSync } from "node:sqlite";
import type { RequestHandlerExtra } from "@modelcontextprotocol/sdk/shared/protocol.js";
import type { ServerNotification, ServerRequest } from "@modelcontextprotocol/sdk/types.js";
import express from "express";
import { DEFAULT_PLAN_LIMITS, loadConfig, type AppConfig } from "../src/config.js";
import { setLogLevel } from "../src/logger.js";
import { ApiKeyStore, createAuthMiddleware, principalFromAuthInfo, resolveLocalPrincipal, SessionTokenService, type AuthenticatedRequest, type Principal } from "../src/middleware/auth.js";
import { createMeter } from "../src/middleware/metering.js";
import {
  encodeCredential,
  PaymentManager,
  settledMarkerClaim,
  x402AuthorizationIdentity,
  x402NonceIdentity,
  x402PayerIdentity,
  x402ReplayKey,
  x402TransactionGuard,
  type PaymentCredential,
  type PaymentResult
} from "../src/middleware/payments.js";
import { RateLimiter } from "../src/middleware/rateLimit.js";
import { attachSharedLedger, inGuardFamily, UsageTracker, type GuardFamily, type SettlementMarker, type SettlementStart, type SettlementState, type SharedLedger } from "../src/middleware/usage.js";
import { CreditLedger, type LedgerImport } from "../src/store/credits.js";
import { openDatabase } from "../src/store/db.js";
import { CliError, DEFAULT_LIST_LIMIT, issueSession, listSettlements, main as settlementsCli, resolveConfirmed, resolveFailed, UsageError } from "../src/cli/settlements.js";

setLogLevel("silent");

const PAY_TO = "0x2222222222222222222222222222222222222222";
const PAYER = "0x1111111111111111111111111111111111111111";
const CREDITS = 100;
const SESSION_SECRET = "round8-payments-session-secret-0123456789";
const BATCH_TX = `0x${"ba".repeat(32)}`;
const PROJECT_ROOT = path.resolve(import.meta.dirname, "..");

// ---------------------------------------------------------------------------
// Upstream stub: an x402 facilitator that models on-chain state, plus the Stripe endpoints redemption reads.
// ---------------------------------------------------------------------------

type VerifyMode = "strict" | "lenient";
/** batch: every settle lands in one transaction (a batching facilitator). idempotent: a spent authorization settles again onto its transaction. */
type SettleMode = "ok" | "batch" | "idempotent" | "reset-after-broadcast" | "reset-before-broadcast" | "gateway-504";

interface Upstream {
  base: string;
  verifyMode: VerifyMode;
  settleMode: SettleMode;
  /** The payer /verify reports; null leaves the field out (a facilitator that does not recover it). */
  verifyPayer: string | null;
  /** The paymentRequirements of the last /verify. */
  lastRequirements: Record<string, unknown> | null;
  count(pathPrefix: string): number;
  close(): Promise<void>;
}

/** The transaction the stub settles a nonce into (outside batch mode). */
function txFor(nonce: string): string {
  return `0x${createHash("sha256").update(nonce).digest("hex")}`;
}

async function startUpstream(): Promise<Upstream> {
  const calls: string[] = [];
  const spent = new Set<string>();
  const state = { verifyMode: "strict" as VerifyMode, settleMode: "ok" as SettleMode, verifyPayer: PAYER as string | null, lastRequirements: null as Record<string, unknown> | null };
  const server = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (chunk: Buffer) => (raw += chunk.toString()));
    req.on("end", () => {
      const url = new URL(req.url ?? "/", "http://stub");
      calls.push(url.pathname);
      const json = (status: number, body: unknown): void => {
        res.statusCode = status;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify(body));
      };
      let body: Record<string, unknown> = {};
      try {
        body = raw ? (JSON.parse(raw) as Record<string, unknown>) : {};
      } catch {
        // Stripe requests are form-encoded.
      }
      const payment = body.paymentPayload as { payload?: { authorization?: { nonce?: string; from?: string } } } | undefined;
      const nonce = String(payment?.payload?.authorization?.nonce ?? "").toLowerCase();
      // The chain makes the (from, nonce) pair unique; without `from` the signer is PAYER.
      const authorization = `${String(payment?.payload?.authorization?.from ?? PAYER).toLowerCase()}:${nonce}`;
      if (url.pathname === "/verify") {
        state.lastRequirements = (body.paymentRequirements as Record<string, unknown> | undefined) ?? null;
        const payer = state.verifyPayer === null ? {} : { payer: state.verifyPayer };
        if (state.verifyMode === "strict" && spent.has(authorization)) return json(200, { isValid: false, invalidReason: "invalid_exact_evm_payload_authorization_used", ...payer });
        return json(200, { isValid: true, ...payer });
      }
      if (url.pathname === "/settle") {
        switch (state.settleMode) {
          case "ok":
            if (spent.has(authorization)) return json(400, { success: false, errorReason: "invalid_exact_evm_payload_authorization_used" });
            spent.add(authorization);
            return json(200, { success: true, transaction: txFor(nonce), network: "base", payer: PAYER });
          case "batch":
            spent.add(authorization);
            return json(200, { success: true, transaction: BATCH_TX, network: "base", payer: PAYER });
          case "idempotent":
            spent.add(authorization);
            return json(200, { success: true, transaction: txFor(nonce), network: "base", payer: PAYER });
          case "reset-after-broadcast":
            spent.add(authorization);
            req.socket.destroy();
            return;
          case "reset-before-broadcast":
            req.socket.destroy();
            return;
          case "gateway-504":
            spent.add(authorization);
            res.statusCode = 504;
            res.end("<html>504</html>");
            return;
        }
      }
      const intent = /^\/v1\/payment_intents\/(.+)$/.exec(url.pathname);
      if (req.method === "GET" && intent) {
        // Slow enough that a second request for the same payment arrives while the first holds its lock.
        setTimeout(
          () =>
            json(200, {
              id: decodeURIComponent(intent[1] as string),
              status: "succeeded",
              created: Math.floor(Date.now() / 1000),
              amount: 500,
              amount_received: 500,
              currency: "usd",
              metadata: { service: "stack-and-dns-mcp", credits: String(CREDITS) }
            }),
          100
        );
        return;
      }
      json(404, { error: { message: "unknown stub route" } });
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    base: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
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
    get verifyPayer() {
      return state.verifyPayer;
    },
    set verifyPayer(payer: string | null) {
      state.verifyPayer = payer;
    },
    get lastRequirements() {
      return state.lastRequirements;
    },
    count: (prefix) => calls.filter((p) => p.startsWith(prefix)).length,
    async close(): Promise<void> {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  };
}

// ---------------------------------------------------------------------------
// A shared ledger with failure knobs.
// ---------------------------------------------------------------------------

const lockError = (): Error => Object.assign(new Error("database is locked"), { code: "ERR_SQLITE_ERROR", errcode: 5 });
const diskFull = (): Error => Object.assign(new Error("database or disk is full"), { code: "ERR_SQLITE_ERROR", errcode: 13 });

class TestLedger implements SharedLedger {
  failRedeem = 0;
  /** redeemAndCredit fails like a held write lock this many more times. */
  lockRedeem = 0;
  /** While set, redeemAndCredit fails like a held write lock for every recording whose ids include it (others go through). */
  lockRedeemFor: string | null = null;
  /** markRedeemed (a payment id recorded alone) fails like a full disk this many more times. */
  failMarkRedeemed = 0;
  /** Every redeemAndCredit ("redeem") and markSettlement ("mark:<state>") attempt, in order, failed or not. */
  readonly events: string[] = [];
  /** markSettlement to these states fails like a held write lock this many more times. */
  readonly lockMark = new Map<SettlementState, number>();
  /** markSettlement to these states fails like a full disk while they are in the set. */
  readonly failMark = new Set<SettlementState>();
  /** Runs just before pendingSettlementState reads, as a sibling process would act in between. */
  beforePending: (() => void) | null = null;
  constructor(readonly inner: CreditLedger) {}
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
    if (this.failMarkRedeemed > 0) {
      this.failMarkRedeemed -= 1;
      throw diskFull();
    }
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
    this.events.push("redeem");
    if (this.lockRedeem > 0) {
      this.lockRedeem -= 1;
      throw lockError();
    }
    if (this.lockRedeemFor !== null && ids.includes(this.lockRedeemFor)) throw lockError();
    if (this.failRedeem > 0) {
      this.failRedeem -= 1;
      throw diskFull();
    }
    return this.inner.redeemAndCredit(ids, principalId, plan, label, credits, at, blockedBy, blockedByFamily);
  }
  pruneRedeemed(retentionMs: number, now?: number): number {
    return this.inner.pruneRedeemed(retentionMs, now);
  }
  importOnce(source: LedgerImport): boolean {
    return this.inner.importOnce(source);
  }
  beginSettlement(start: SettlementStart, at: number): boolean {
    return this.inner.beginSettlement(start, at);
  }
  resumeSettlement(seen: SettlementMarker, at: number): boolean {
    return this.inner.resumeSettlement(seen, at);
  }
  touchSettlement(seen: SettlementMarker, at: number): boolean {
    return this.inner.touchSettlement(seen, at);
  }
  markSettlement(paymentId: string, state: SettlementState, tx: string | null, receipt: Record<string, unknown> | null, at: number): void {
    this.events.push(`mark:${state}`);
    const locks = this.lockMark.get(state) ?? 0;
    if (locks > 0) {
      this.lockMark.set(state, locks - 1);
      throw lockError();
    }
    if (this.failMark.has(state)) throw diskFull();
    this.inner.markSettlement(paymentId, state, tx, receipt, at);
  }
  getSettlement(paymentId: string): SettlementMarker | null {
    return this.inner.getSettlement(paymentId);
  }
  endSettlement(paymentId: string, ifUpdatedAt?: number): void {
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
    this.beforePending?.();
    return this.inner.pendingSettlementState(principalId, settlingStaleBefore, unknownSince);
  }
}

// ---------------------------------------------------------------------------
// Harness: config + payments + ledger + the real auth middleware in Express.
// ---------------------------------------------------------------------------

interface Harness {
  upstream: Upstream;
  config: AppConfig;
  db: DatabaseSync | null;
  ledger: TestLedger | null;
  usage: UsageTracker;
  payments: PaymentManager;
  sessions: SessionTokenService;
  base: string;
  close(): Promise<void>;
}

const harnesses: Harness[] = [];
const cleanups: Array<() => Promise<void>> = [];
after(async () => {
  for (const h of harnesses.splice(0).reverse()) await h.close();
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

interface HarnessOptions {
  env?: Record<string, string>;
  /** Share this harness's facilitator (and database, unless usage is given): a sibling process, or a restart. */
  sibling?: Harness;
  /** Use this tracker as is (no shared ledger is attached): a server with STACKDNS_DB_FILE=none. */
  usage?: UsageTracker;
  /** Open this database file instead of :memory:. */
  dbFile?: string;
}

async function harness(options: HarnessOptions = {}): Promise<Harness> {
  const { sibling } = options;
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
      ...(options.env ?? {})
    },
    []
  );
  let db: DatabaseSync | null = null;
  let ledger: TestLedger | null = null;
  let usage: UsageTracker;
  let ownsDb = false;
  if (options.usage) {
    usage = options.usage;
  } else {
    db = sibling?.db ?? (await openDatabase(options.dbFile ?? ":memory:"));
    assert.ok(db);
    ownsDb = !sibling?.db;
    ledger = new TestLedger(new CreditLedger(db));
    usage = new UsageTracker(null);
    usage.attachLedger(ledger);
  }
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
  let closed = false;
  const h: Harness = {
    upstream,
    config,
    db,
    ledger,
    usage,
    payments,
    sessions,
    base: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    async close(): Promise<void> {
      if (closed) return;
      closed = true;
      payments.close();
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      if (!sibling) await upstream.close();
      if (ownsDb && db) {
        try {
          db.close();
        } catch {
          // already closed
        }
      }
    }
  };
  harnesses.push(h);
  return h;
}

let nonceCounter = 0;
function x402Payload(prefix = "0x"): Record<string, unknown> {
  nonceCounter += 1;
  const nonce = `${prefix}${String(nonceCounter).padStart(8, "0")}${createHash("sha256").update(String(Math.random())).digest("hex").slice(0, 56)}`;
  return {
    x402Version: 1,
    scheme: "exact",
    network: "base",
    payload: {
      signature: `0x${createHash("sha256").update(nonce).digest("hex")}`,
      authorization: { from: PAYER, to: PAY_TO, value: "500000", validAfter: "0", validBefore: String(Math.floor(Date.now() / 1000) + 3600), nonce }
    }
  };
}

function nonceOf(payload: Record<string, unknown>): string {
  return (payload.payload as { authorization: { nonce: string } }).authorization.nonce;
}

/** The same authorization without `from` (a facilitator recovers it from the signature): a different replay key. */
function withoutFrom(payload: Record<string, unknown>): Record<string, unknown> {
  const inner = payload.payload as { signature: string; authorization: Record<string, unknown> };
  const authorization = { ...inner.authorization };
  delete authorization.from;
  return { ...payload, payload: { signature: inner.signature, authorization } };
}

function header(payload: Record<string, unknown>): string {
  return Buffer.from(JSON.stringify(payload), "utf8").toString("base64");
}

function credentialFor(h: Harness, payload: Record<string, unknown>): PaymentCredential {
  const credential = h.payments.parseCredential(header(payload), "x-payment");
  assert.ok(credential);
  return credential;
}

const target = (principalId: string) => () => ({ principalId, label: `x402:${principalId}` });
const topUpOf = (principalId: string) => () => ({ principalId, label: `x402:${principalId}`, topUp: true });

function failureCode(result: PaymentResult): string {
  return result.ok ? "ok" : result.code;
}

function replayKey(payload: Record<string, unknown>): string {
  const id = x402ReplayKey(payload);
  assert.ok(id);
  return id;
}

function derivedPrincipal(payload: Record<string, unknown>): string {
  return `pay_${createHash("sha256").update(replayKey(payload)).digest("hex").slice(0, 16)}`;
}

function ageMarkers(db: DatabaseSync, ms: number): void {
  db.prepare("UPDATE x402_settlements SET at = at - ?, updated_at = updated_at - ?").run(ms, ms);
}

function markerOf(db: DatabaseSync, payload: Record<string, unknown>): { state: string; tx: string | null; at: number; updated_at: number } | null {
  return (
    (db.prepare("SELECT state, tx, at, updated_at FROM x402_settlements WHERE payment_id = ?").get(replayKey(payload)) as
      { state: string; tx: string | null; at: number; updated_at: number } | undefined) ?? null
  );
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

async function buyCredits(h: Harness): Promise<{ token: string; principalId: string; paymentHeader: string }> {
  const paymentHeader = header(x402Payload());
  const res = await call(h, "/v1/jobs", { headers: { "x-payment": paymentHeader } });
  assert.equal(res.status, 200, `fresh payment is redeemed: ${JSON.stringify(res.body)}`);
  const token = res.headers.get("x-session-token");
  assert.ok(token);
  const claims = h.sessions.verify(token);
  assert.ok(claims);
  return { token, principalId: claims.sub, paymentHeader };
}

async function drainMicrotasks(rounds = 5): Promise<void> {
  for (let i = 0; i < rounds; i++) await new Promise((resolve) => setImmediate(resolve));
}

function privateField<T>(payments: PaymentManager, name: string): T {
  return (payments as unknown as Record<string, T>)[name] as T;
}

const JOB_BODY = { domains: ["example.com"], checks: ["email"] };
const toolCall = (name: string, args: Record<string, unknown> = {}) => ({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } });

// ---------------------------------------------------------------------------
// P-A
// ---------------------------------------------------------------------------

describe("P-A: the marker write behind an answer that carries the session", () => {
  it("a 503 waits out a locked 'settled' write, so the marker is settled before the session goes out", async () => {
    const h = await harness();
    assert.ok(h.ledger && h.db);
    const payload = x402Payload();
    h.ledger.lockMark.set("settled", 2);
    h.ledger.failRedeem = 1;
    const first = await call(h, "/v1/jobs", { headers: { "x-payment": header(payload) } });
    assert.equal(first.status, 503, JSON.stringify(first.body));
    assert.equal(h.sessions.verify(first.headers.get("x-session-token") ?? "")?.sub, derivedPrincipal(payload));
    assert.equal(h.ledger.lockMark.get("settled"), 0, "the write was retried through the lock");
    // Without the retry the marker stays 'settling' as claimed until the timer runs, and a crash in between
    // makes it read as "died before answering".
    assert.equal(markerOf(h.db, payload)?.state, "settled");
    assert.equal(markerOf(h.db, payload)?.tx, `${txFor(nonceOf(payload))}:${x402AuthorizationIdentity(payload)}`);
  });

  it("a 502 to the first presenter waits out a locked 'unknown' write and still carries the session", async () => {
    const h = await harness();
    assert.ok(h.ledger && h.db);
    const payload = x402Payload();
    h.upstream.settleMode = "reset-after-broadcast";
    h.ledger.lockMark.set("unknown", 2);
    const first = await call(h, "/v1/jobs", { headers: { "x-payment": header(payload) } });
    assert.equal(first.status, 502, JSON.stringify(first.body));
    // Before, a failed write withheld the session (round 7), even though the lock cleared a moment later.
    assert.equal(h.sessions.verify(first.headers.get("x-session-token") ?? "")?.sub, derivedPrincipal(payload));
    assert.equal(markerOf(h.db, payload)?.state, "unknown");
  });

  it("a write that keeps failing still hands out the 503's session, and this process never hands it to a later presenter", async () => {
    const h = await harness();
    assert.ok(h.ledger && h.db);
    const payload = x402Payload();
    h.ledger.failMark.add("settled");
    h.ledger.failRedeem = 1000;
    const first = await call(h, "/v1/jobs", { headers: { "x-payment": header(payload) } });
    assert.equal(first.status, 503);
    const token = first.headers.get("x-session-token");
    assert.ok(token, "credits must stay reachable");
    const marker = markerOf(h.db, payload);
    assert.equal(marker?.state, "settling");
    assert.equal(marker?.at, marker?.updated_at, "the marker reads as never resumed");

    // The facilitator settles a spent authorization again (idempotent) and the local entry is gone: only the
    // local record of the answer now keeps a presenter of the public payload from being its "first".
    privateField<Map<string, unknown>>(h.payments, "unrecorded").clear();
    h.ledger.failRedeem = 0;
    h.ledger.failMark.clear();
    h.upstream.verifyMode = "lenient";
    h.upstream.settleMode = "idempotent";
    ageMarkers(h.db, 61_000);
    const later = await call(h, "/v1/jobs", { headers: { "x-payment": header(payload) } });
    assert.equal(later.status, 409, JSON.stringify(later.body));
    assert.equal(later.headers.get("x-session-token"), null, "the session already went out with the 503");
    assert.equal(h.usage.creditsRemaining(derivedPrincipal(payload)), CREDITS, "the credits reach the 503's session");
    const spend = await call(h, "/v1/jobs", { method: "POST", headers: { authorization: `Bearer ${token}` }, body: JOB_BODY });
    assert.equal(spend.status, 200);
  });
});

// ---------------------------------------------------------------------------
// P-B
// ---------------------------------------------------------------------------

describe("P-B: unconfirmed payments neither lock sessions out nor load the facilitator", () => {
  it("a session re-attaching an unconfirmed top-up is served wherever its balance allows, with X-Payment-Status", async () => {
    const h = await harness();
    const session = await buyCredits(h);
    const topUp = header(x402Payload());
    h.upstream.settleMode = "reset-after-broadcast";
    const headers = { authorization: `Bearer ${session.token}`, "x-payment": topUp };
    const first = await call(h, "/v1/jobs", { method: "POST", headers, body: JOB_BODY });
    assert.equal(first.status, 200, JSON.stringify(first.body));
    assert.equal(first.headers.get("x-payment-status"), "x402_settlement_unconfirmed");
    // Its client re-attaches the header to every request: still served, on every route.
    for (const [method, route, body] of [
      ["GET", "/v1/jobs/job_1", undefined],
      ["DELETE", "/v1/jobs/job_1", undefined],
      ["POST", "/mcp", toolCall("inspect_tech_stack", { domain: "example.com" })]
    ] as const) {
      const res = await call(h, route, { method, headers, body });
      assert.equal(res.status, 200, `${method} ${route}: ${JSON.stringify(res.body)}`);
      assert.equal(res.headers.get("x-payment-status"), "x402_settlement_unconfirmed");
    }
    // Exhausted: served where nothing is spent, 502 (never 402) where it would be.
    assert.equal(h.usage.consumeCredits(session.principalId, CREDITS), true);
    const read = await call(h, "/v1/jobs", { headers });
    assert.equal(read.status, 200);
    assert.equal(read.headers.get("x-payment-status"), "x402_settlement_unconfirmed");
    for (const [route, body] of [
      ["/v1/jobs", JOB_BODY],
      ["/mcp", toolCall("inspect_tech_stack", { domain: "example.com" })]
    ] as const) {
      const res = await call(h, route, { method: "POST", headers, body });
      assert.equal(res.status, 502, `${route}: ${JSON.stringify(res.body)}`);
      assert.equal(res.headers.get("www-authenticate"), null);
    }
  });

  it("an 'unknown' marker is re-verified at most once a minute, by one process", async () => {
    const A = await harness();
    const B = await harness({ sibling: A });
    assert.ok(A.db);
    const payload = x402Payload();
    A.upstream.settleMode = "reset-after-broadcast";
    assert.equal((await call(A, "/v1/jobs", { headers: { "x-payment": header(payload) } })).status, 502);
    const verifies = A.upstream.count("/verify");
    for (const h of [A, B, A, B]) {
      const retry = await call(h, "/v1/jobs", { headers: { "x-payment": header(payload) } });
      assert.equal(retry.status, 502);
      assert.equal(retry.body.error, "x402_settlement_unconfirmed");
    }
    assert.equal(A.upstream.count("/verify"), verifies, "answered from the marker, with no facilitator call");

    ageMarkers(A.db, 61_000);
    assert.equal((await call(A, "/v1/jobs", { headers: { "x-payment": header(payload) } })).status, 502);
    assert.equal(A.upstream.count("/verify"), verifies + 1, "one re-verification once the window passed");
    assert.equal((await call(B, "/v1/jobs", { headers: { "x-payment": header(payload) } })).status, 502);
    assert.equal(A.upstream.count("/verify"), verifies + 1, "the sibling sees the claimed window");

    ageMarkers(A.db, 61_000);
    const both = await Promise.all([A, B, A, B].map((h) => call(h, "/v1/jobs", { headers: { "x-payment": header(payload) } })));
    assert.deepEqual(
      both.map((r) => r.status),
      [502, 502, 502, 502]
    );
    assert.equal(A.upstream.count("/verify"), verifies + 2, "concurrent processes re-verify it once");
  });

  it("re-attaching an unconfirmed payment inside its window is not charged to the pre-auth address bucket", async () => {
    const h = await harness({ env: { STACKDNS_UNAUTHENTICATED_PER_MINUTE: "3" } });
    const session = await buyCredits(h);
    const topUp = header(x402Payload());
    h.upstream.settleMode = "reset-after-broadcast";
    const headers = { authorization: `Bearer ${session.token}`, "x-payment": topUp };
    const statuses: number[] = [];
    for (let i = 0; i < 8; i++) statuses.push((await call(h, "/v1/jobs", { headers })).status);
    // The first request settles (one slot); every retry is answered from the marker.
    assert.deepEqual(statuses, Array(8).fill(200));
  });

  it("an unconfirmed payment blocks its session's purchases for 24 hours, while its header stays unconfirmed", async () => {
    const h = await harness();
    assert.ok(h.db);
    const payload = x402Payload();
    h.upstream.settleMode = "reset-after-broadcast";
    const first = await call(h, "/v1/jobs", { headers: { "x-payment": header(payload) } });
    const token = first.headers.get("x-session-token");
    assert.ok(token);
    const spend = () => call(h, "/v1/jobs", { method: "POST", headers: { authorization: `Bearer ${token}` }, body: JOB_BODY });
    assert.equal((await spend()).status, 502);
    ageMarkers(h.db, 23 * 3600_000);
    assert.equal((await spend()).status, 502, "still within the day");
    ageMarkers(h.db, 2 * 3600_000);
    const later = await spend();
    assert.equal(later.status, 402, `the session may buy again: ${JSON.stringify(later.body)}`);
    assert.equal(later.body.reason, "credits_exhausted");
    // The payment itself keeps its answer.
    const retry = await call(h, "/v1/jobs", { headers: { "x-payment": header(payload) } });
    assert.equal(retry.status, 502, JSON.stringify(retry.body));

    // A 'settling' marker left by a crashed process counts as unknown, for a day as well.
    const crashed = x402Payload();
    assert.equal(h.usage.beginSettlement({ paymentId: replayKey(crashed), principalId: "pay_crashed", label: "x402:crashed", credits: CREDITS }, Date.now() - 2 * 3600_000), true);
    assert.equal(h.payments.pendingFor("pay_crashed"), "unknown");
    ageMarkers(h.db, 23 * 3600_000);
    assert.equal(h.payments.pendingFor("pay_crashed"), null);
  });

  it("markers are kept as long as redeemed payments: a retry a month later is unconfirmed, never x402_expired", async () => {
    const h = await harness();
    const payload = x402Payload();
    h.upstream.settleMode = "gateway-504";
    assert.equal(failureCode(await h.payments.redeem(credentialFor(h, payload), target("pay_month"))), "x402_settlement_unconfirmed");
    mock.timers.enable({ apis: ["Date"], now: Date.now() + 30 * 86_400_000 });
    try {
      // This redeem also runs the marker prune (it last ran a month ago); a 7-day retention removed the marker.
      const retry = await h.payments.redeem(credentialFor(h, payload), target("pay_month"));
      assert.equal(failureCode(retry), "x402_settlement_unconfirmed");
      assert.ok(h.usage.getSettlement(replayKey(payload)), "the marker survived the prune");
    } finally {
      mock.timers.reset();
    }
  });
});

// ---------------------------------------------------------------------------
// P-E
// ---------------------------------------------------------------------------

describe("P-E: the transaction guard is qualified by the authorization", () => {
  it("two authorizations settled in one transaction are each credited", async () => {
    const h = await harness();
    h.upstream.settleMode = "batch";
    const a = x402Payload();
    const b = x402Payload();
    for (const payload of [a, b]) {
      const res = await call(h, "/v1/jobs", { headers: { "x-payment": header(payload) } });
      assert.equal(res.status, 200, JSON.stringify(res.body));
      assert.equal(h.usage.creditsRemaining(derivedPrincipal(payload)), CREDITS);
    }
    assert.equal(h.usage.isPaymentRedeemed(`x402_${BATCH_TX}`), false, "the bare transaction id is never written");
    assert.equal(h.usage.isPaymentRedeemed(x402TransactionGuard(BATCH_TX, x402AuthorizationIdentity(a) as string).guard), true);
  });

  it("the same, without a shared database", async () => {
    const h = await harness({ usage: new UsageTracker(null) });
    h.upstream.settleMode = "batch";
    for (const payload of [x402Payload(), x402Payload()]) {
      const res = await h.payments.redeem(credentialFor(h, payload), target(derivedPrincipal(payload)));
      assert.ok(res.ok, failureCode(res));
      assert.equal(h.usage.creditsRemaining(derivedPrincipal(payload)), CREDITS);
    }
  });

  it("one authorization presented with and without `from` (two replay keys) is credited once", async () => {
    const h = await harness();
    h.upstream.verifyMode = "lenient";
    h.upstream.settleMode = "idempotent";
    const payload = x402Payload();
    const bare = withoutFrom(payload);
    assert.notEqual(replayKey(payload), replayKey(bare));
    // Without `from`, the payer /verify recovered qualifies the nonce (round 9): the same identity.
    assert.equal(x402AuthorizationIdentity(payload), x402AuthorizationIdentity(bare, PAYER));
    assert.equal((await call(h, "/v1/jobs", { headers: { "x-payment": header(payload) } })).status, 200);
    const again = await call(h, "/v1/jobs", { headers: { "x-payment": header(bare) } });
    assert.equal(again.status, 409, JSON.stringify(again.body));
    assert.match(String(again.body.message), /^Transaction /);
    assert.equal(h.usage.creditsRemaining(derivedPrincipal(bare)), null, "no second credit");
  });

  it("a guard id written before round 8 still blocks", async () => {
    const h = await harness();
    const payload = x402Payload();
    assert.equal(h.usage.markPaymentRedeemed(`x402_${txFor(nonceOf(payload))}`), true);
    const res = await h.payments.redeem(credentialFor(h, payload), target("pay_legacy"));
    assert.equal(failureCode(res), "payment_already_redeemed");
    assert.equal(h.usage.creditsRemaining("pay_legacy"), null);
  });

  it("a sibling adopting a settled marker claims the settling process's guard, so the payment is credited once", async () => {
    const A = await harness();
    const B = await harness({ sibling: A });
    assert.ok(A.db && A.ledger);
    const payload = x402Payload();
    A.ledger.failRedeem = 1000;
    assert.equal((await call(A, "/v1/jobs", { headers: { "x-payment": header(payload) } })).status, 503);
    const marker = markerOf(A.db, payload);
    const { markerTx, guard } = x402TransactionGuard(txFor(nonceOf(payload)), x402AuthorizationIdentity(payload) as string);
    assert.equal(marker?.tx, markerTx);
    // Code from before round 8 adopts a marker under `x402_<tx>`: the same guard.
    assert.equal(`x402_${markerTx.toLowerCase()}`, guard);
    ageMarkers(A.db, 50_000);
    assert.equal((await call(B, "/v1/jobs", { headers: { "x-payment": header(payload) } })).status, 409);
    assert.equal(B.usage.creditsRemaining(derivedPrincipal(payload)), CREDITS);
    A.ledger.failRedeem = 0;
    assert.equal((await call(A, "/v1/jobs", { headers: { "x-payment": header(payload) } })).status, 409);
    assert.equal(A.usage.creditsRemaining(derivedPrincipal(payload)), CREDITS, "credited once");
  });

  it("redeemAndCredit grants nothing when any id or blocker was redeemed, and records every id", async () => {
    const db = await openDatabase(":memory:");
    assert.ok(db);
    try {
      const ledger = new CreditLedger(db);
      assert.equal(ledger.markRedeemed("x402_pid_seen"), true);
      assert.equal(ledger.redeemAndCredit(["x402_guard_new", "x402_pid_seen"], "pay_any", "payg", "", 5), false, "the second id was redeemed");
      assert.equal(ledger.balance("pay_any"), null);
      assert.equal(ledger.isRedeemed("x402_guard_new", 86_400_000), true, "the first id is still recorded");
      ledger.markRedeemed("x402_legacy");
      assert.equal(ledger.redeemAndCredit(["x402_g2", "x402_p2"], "pay_blocked", "payg", "", 5, Date.now(), ["x402_legacy"]), false);
      assert.equal(ledger.isRedeemed("x402_p2", 86_400_000), true);
      assert.equal(ledger.redeemAndCredit(["x402_g3", "x402_p3"], "pay_ok", "payg", "", 5, Date.now(), ["x402_unseen"]), true);
      assert.equal(ledger.balance("pay_ok"), 5);
    } finally {
      db.close();
    }
  });
});

// ---------------------------------------------------------------------------
// P-F
// ---------------------------------------------------------------------------

describe("P-F: a payment recorded between the balance read and the pending lookup", () => {
  it("is served instead of answered with a payment demand", async () => {
    const h = await harness();
    assert.ok(h.ledger);
    const ledger = h.ledger;
    const payload = x402Payload();
    const principal = derivedPrincipal(payload);
    h.usage.beginSettlement({ paymentId: replayKey(payload), principalId: principal, label: "x402:race", credits: CREDITS }, Date.now());
    h.usage.markSettlement(replayKey(payload), "settled", "0xrace:identity", null, Date.now());
    const token = h.sessions.issue({ sub: principal, plan: "payg", label: "x402:race" });
    // A sibling records the payment (and removes its marker) right after this process read an empty balance.
    ledger.beforePending = () => {
      ledger.beforePending = null;
      assert.equal(ledger.inner.redeemAndCredit(["x402_0xrace:identity", replayKey(payload)], principal, "payg", "x402:race", CREDITS), true);
      ledger.inner.endSettlement(replayKey(payload));
    };
    const res = await call(h, "/v1/jobs", { method: "POST", headers: { authorization: `Bearer ${token}` }, body: JOB_BODY });
    assert.equal(res.status, 200, `not credits_exhausted: ${JSON.stringify(res.body)}`);
    assert.equal((res.body.principal as { id?: string }).id, principal);
  });
});

// ---------------------------------------------------------------------------
// P-H
// ---------------------------------------------------------------------------

async function tempDir(prefix: string): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), prefix));
  cleanups.push(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

describe("P-H: settlement markers in the usage file", () => {
  it("survive a restart, so the 502's session is answered 502 and never asked to pay again", async () => {
    const dir = await tempDir("sdm-r8-usage-");
    const file = path.join(dir, "usage.json");
    const before = new UsageTracker(file);
    await before.load();
    const A = await harness({ usage: before });
    const payload = x402Payload();
    A.upstream.settleMode = "reset-after-broadcast";
    const first = await call(A, "/v1/jobs", { headers: { "x-payment": header(payload) } });
    assert.equal(first.status, 502);
    const token = first.headers.get("x-session-token");
    assert.ok(token);
    A.payments.close();
    await before.close();
    const stored = JSON.parse(await readFile(file, "utf8")) as { version: number; settlements: Array<{ paymentId: string; state: string; identity: string }> };
    assert.equal(stored.version, 3);
    assert.deepEqual(
      stored.settlements.map((m) => [m.paymentId, m.state, m.identity]),
      [[replayKey(payload), "unknown", x402AuthorizationIdentity(payload)]]
    );

    const restarted = new UsageTracker(file);
    await restarted.load();
    const B = await harness({ usage: restarted, sibling: A });
    const spend = await call(B, "/v1/jobs", { method: "POST", headers: { authorization: `Bearer ${token}` }, body: JOB_BODY });
    assert.equal(spend.status, 502, `not a fresh 402: ${JSON.stringify(spend.body)}`);
    const retry = await call(B, "/v1/jobs", { headers: { "x-payment": header(payload) } });
    assert.equal(retry.status, 502);
    assert.equal(retry.headers.get("www-authenticate"), null);
  });

  it("older files still load, malformed markers are skipped, and attaching a database moves the markers into it", async () => {
    const dir = await tempDir("sdm-r8-usage-");
    const file = path.join(dir, "usage.json");
    await writeFile(file, JSON.stringify({ version: 2, principals: {}, redeemedPayments: [{ id: "x402_old", at: new Date().toISOString() }] }));
    const v2 = new UsageTracker(file);
    await v2.load();
    assert.equal(v2.isPaymentRedeemed("x402_old"), true);

    const good = { paymentId: "x402_kept", principalId: "pay_kept", label: "x402:kept", credits: 5, state: "unknown", tx: null, receipt: null, identity: "abc", at: 1000, updatedAt: 2000 };
    await writeFile(file, JSON.stringify({ version: 3, principals: {}, redeemedPayments: [], settlements: [good, { paymentId: 5 }, { ...good, paymentId: "x402_bad", state: "lost" }] }));
    const v3 = new UsageTracker(file);
    await v3.load();
    assert.deepEqual(v3.getSettlement("x402_kept"), good);
    assert.equal(v3.getSettlement("x402_bad"), null);

    const db = await openDatabase(":memory:");
    assert.ok(db);
    try {
      const ledger = new CreditLedger(db);
      v3.attachLedger(ledger);
      assert.deepEqual(ledger.getSettlement("x402_kept"), good, "moved with its state, times and identity");
      assert.deepEqual(v3.snapshot().settlements, [], "and no longer kept in the file");
    } finally {
      db.close();
    }
  });
});

// ---------------------------------------------------------------------------
// P-J
// ---------------------------------------------------------------------------

class LockedImportLedger extends CreditLedger {
  lockedFor = Number.POSITIVE_INFINITY;
  error: () => Error = lockError;
  override importOnce(source: LedgerImport): boolean {
    if (this.lockedFor > 0) {
      this.lockedFor -= 1;
      throw this.error();
    }
    return super.importOnce(source);
  }
}

describe("P-J: attaching the shared ledger", () => {
  it("a process that sells nothing gives up after its budget and runs without it; one that sells refuses to start", async () => {
    const db = await openDatabase(":memory:");
    assert.ok(db);
    try {
      const ledger = new LockedImportLedger(db);
      const stdio = new UsageTracker(null);
      const started = Date.now();
      assert.equal(await attachSharedLedger(stdio, ledger, { required: false, budgetMs: 300 }), false);
      assert.ok(Date.now() - started >= 300, "the budget was waited out");
      assert.equal(stdio.hasSharedLedger, false);

      await assert.rejects(attachSharedLedger(new UsageTracker(null), ledger, { required: true, budgetMs: 200 }), /refusing to run on a private file ledger/);

      ledger.lockedFor = 2;
      const transient = new UsageTracker(null);
      assert.equal(await attachSharedLedger(transient, ledger, { required: true, budgetMs: 5_000 }), true, "a lock that clears is waited out");
      assert.equal(transient.hasSharedLedger, true);

      ledger.lockedFor = 1;
      ledger.error = diskFull;
      const quick = Date.now();
      assert.equal(await attachSharedLedger(new UsageTracker(null), ledger, { required: false, budgetMs: 5_000 }), false);
      assert.ok(Date.now() - quick < 1_000, "an error that is not lock contention is not retried");
    } finally {
      db.close();
    }
  });
});

// ---------------------------------------------------------------------------
// P-K
// ---------------------------------------------------------------------------

class FailingOnceTracker extends UsageTracker {
  failures = 1;
  override async redeemAndGrant(...args: Parameters<UsageTracker["redeemAndGrant"]>): Promise<boolean> {
    if (this.failures > 0) {
      this.failures -= 1;
      throw diskFull();
    }
    return super.redeemAndGrant(...args);
  }
}

describe("P-K: the recording timer without a shared ledger", () => {
  it("stops once every entry is committed, restarts on the next failure, and committed entries still expire", async () => {
    mock.timers.enable({ apis: ["setInterval", "Date"], now: Date.now() });
    try {
      const usage = new FailingOnceTracker(null);
      const h = await harness({ usage });
      const timer = () => privateField<NodeJS.Timeout | null>(h.payments, "recordingTimer");
      const payload = x402Payload();
      assert.equal(timer(), null, "nothing to do yet");
      assert.equal(failureCode(await h.payments.redeem(credentialFor(h, payload), target("pay_k"))), "payment_recording_failed");
      assert.notEqual(timer(), null);
      mock.timers.tick(10_000);
      await drainMicrotasks();
      assert.equal(usage.creditsRemaining("pay_k"), CREDITS, "recorded by the timer");
      mock.timers.tick(10_000);
      await drainMicrotasks();
      assert.equal(timer(), null, "only a committed entry is left: nothing for the timer to do");
      const own = await h.payments.redeem(credentialFor(h, payload), topUpOf("pay_k"));
      assert.ok(own.ok, `the committed entry still hands the top-up its receipt: ${failureCode(own)}`);

      usage.failures = 1;
      assert.equal(failureCode(await h.payments.redeem(credentialFor(h, x402Payload()), target("pay_k2"))), "payment_recording_failed");
      assert.notEqual(timer(), null, "restarted lazily");
      mock.timers.tick(10_000);
      await drainMicrotasks();
      mock.timers.tick(10_000);
      await drainMicrotasks();
      assert.equal(timer(), null);
      const unrecorded = privateField<Map<string, { committed: boolean }>>(h.payments, "unrecorded");
      assert.deepEqual(
        [...unrecorded.values()].map((e) => e.committed),
        [true]
      );
      // With the timer stopped, the prune drops a committed entry after its day.
      mock.timers.setTime(Date.now() + 25 * 3600_000);
      await h.payments.createChallenge("http://127.0.0.1:1/mcp");
      assert.equal(unrecorded.size, 0);
    } finally {
      mock.timers.reset();
    }
  });
});

// ---------------------------------------------------------------------------
// P-D: the operator CLI
// ---------------------------------------------------------------------------

function cliEnv(extra: Record<string, string>): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (!/^(STACKDNS_|X402_|STRIPE_)/.test(key)) env[key] = value;
  }
  return { ...env, ...extra };
}

function runCli(args: string[], env: NodeJS.ProcessEnv): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    execFile(process.execPath, ["--import", "tsx", path.join(PROJECT_ROOT, "src", "cli", "settlements.ts"), ...args], { cwd: PROJECT_ROOT, env, timeout: 60_000 }, (error, stdout, stderr) => {
      const code = error ? (typeof (error as { code?: unknown }).code === "number" ? ((error as { code: number }).code as number) : 1) : 0;
      resolve({ code, stdout, stderr });
    });
  });
}

describe("P-D: settlement reconciliation CLI", () => {
  it("lists what needs an operator, records confirmed transfers once, ends failed ones for good and issues sessions", async () => {
    const dir = await tempDir("sdm-r8-cli-");
    const h = await harness({ dbFile: path.join(dir, "shared.db") });
    assert.ok(h.db && h.ledger);
    const ledger = h.ledger.inner;

    // An unknown settle (the 502's session), a settled-but-unrecorded payment, and a live settle.
    const unknown = x402Payload();
    h.upstream.settleMode = "reset-after-broadcast";
    const r502 = await call(h, "/v1/jobs", { headers: { "x-payment": header(unknown) } });
    assert.equal(r502.status, 502);
    const token502 = r502.headers.get("x-session-token");
    assert.ok(token502);
    h.upstream.settleMode = "ok";
    const settled = x402Payload();
    h.ledger.failRedeem = 1000;
    assert.equal((await call(h, "/v1/jobs", { headers: { "x-payment": header(settled) } })).status, 503);
    const live = x402Payload();
    h.usage.beginSettlement({ paymentId: replayKey(live), principalId: "pay_live", label: "x402:live", credits: CREDITS, identity: x402AuthorizationIdentity(live) }, Date.now());

    const listed = listSettlements(ledger).rows;
    assert.deepEqual(
      listed.map((r) => [r.paymentId, r.state]).sort(),
      [
        [replayKey(settled), "settled"],
        [replayKey(unknown), "unknown"]
      ].sort()
    );
    assert.equal(listed.find((r) => r.state === "settled")?.transaction, txFor(nonceOf(settled)), "the bare transaction is shown");
    assert.equal(listSettlements(ledger, { all: true }).rows.length, 3, "--all adds the live settle");

    // The operator confirmed the unknown transfer on-chain.
    const credited = resolveConfirmed(ledger, replayKey(unknown), { tx: txFor(nonceOf(unknown)) });
    assert.deepEqual(credited, { outcome: "credited", paymentId: replayKey(unknown), principalId: derivedPrincipal(unknown), credits: CREDITS, transaction: txFor(nonceOf(unknown)) });
    assert.equal(h.usage.isPaymentRedeemed(x402TransactionGuard(txFor(nonceOf(unknown)), x402AuthorizationIdentity(unknown) as string).guard), true, "recorded under the guard a server uses");
    assert.equal(h.usage.getSettlement(replayKey(unknown)), null);
    assert.throws(
      () => resolveConfirmed(ledger, replayKey(unknown), { tx: txFor(nonceOf(unknown)) }),
      (err: unknown) => err instanceof CliError && /already recorded/.test(err.message)
    );
    const spend = await call(h, "/v1/jobs", { method: "POST", headers: { authorization: `Bearer ${token502}` }, body: JOB_BODY });
    assert.equal(spend.status, 200, "the 502's session reaches the reconciled credits");

    // A settled marker must match its own transaction; recording it races the server's retry harmlessly.
    assert.throws(() => resolveConfirmed(ledger, replayKey(settled), { tx: "0xdifferent" }), /settled as transaction/);
    assert.throws(() => resolveFailed(ledger, replayKey(settled)), /money moved/);
    assert.equal(resolveConfirmed(ledger, replayKey(settled), { tx: txFor(nonceOf(settled)) }).outcome, "credited");
    h.ledger.failRedeem = 0;
    assert.equal((await call(h, "/v1/jobs", { headers: { "x-payment": header(settled) } })).status, 409);
    assert.equal(h.usage.creditsRemaining(derivedPrincipal(settled)), CREDITS, "credited once");

    // A live settle is left to its server; once stale, the operator may end it.
    assert.throws(() => resolveFailed(ledger, replayKey(live)), /being settled by a server right now/);
    ageMarkers(h.db, 61_000);
    assert.deepEqual(resolveFailed(ledger, replayKey(live)), { outcome: "failed", paymentId: replayKey(live), principalId: "pay_live" });
    const never = await h.payments.redeem(credentialFor(h, live), target("pay_live"));
    assert.equal(failureCode(never), "payment_already_redeemed", "the authorization can never settle into credits here");
    assert.equal(h.upstream.count("/settle"), 2, "and is never sent to the facilitator again");

    // A marker from before round 8 has no identity: the nonce must be given.
    const legacy = x402Payload();
    const legacyTx = txFor(nonceOf(legacy));
    h.usage.beginSettlement({ paymentId: replayKey(legacy), principalId: "pay_legacy", label: "x402:legacy", credits: CREDITS }, Date.now() - 120_000);
    h.usage.markSettlement(replayKey(legacy), "unknown", null, null, Date.now() - 100_000);
    assert.throws(() => resolveConfirmed(ledger, replayKey(legacy), { tx: legacyTx }), /--nonce/);
    assert.throws(() => resolveConfirmed(ledger, replayKey(unknown) + "_missing", { tx: legacyTx }), /no settlement marker/);
    assert.equal(resolveConfirmed(ledger, replayKey(legacy), { tx: legacyTx, nonce: nonceOf(legacy).toUpperCase().replace("0X", "0x") }).outcome, "credited");
    assert.equal(ledger.balance("pay_legacy"), CREDITS);

    // A session token for a principal whose answer was lost.
    const session = issueSession(SESSION_SECRET, derivedPrincipal(settled), { ledger });
    assert.equal(session.balance, CREDITS);
    assert.equal(h.sessions.verify(session.token)?.sub, derivedPrincipal(settled));
    assert.equal(h.sessions.verify(session.token)?.plan, "payg");
    const served = await call(h, "/v1/jobs", { method: "POST", headers: { authorization: `Bearer ${session.token}` }, body: JOB_BODY });
    assert.equal(served.status, 200);
  });

  it("runs as a script against STACKDNS_DB_FILE", { timeout: 120_000 }, async () => {
    const dir = await tempDir("sdm-r8-cli-");
    const file = path.join(dir, "shared.db");
    const h = await harness({ dbFile: file });
    const payload = x402Payload();
    h.upstream.settleMode = "gateway-504";
    assert.equal((await call(h, "/v1/jobs", { headers: { "x-payment": header(payload) } })).status, 502);
    const env = cliEnv({ STACKDNS_DB_FILE: file });

    const listed = await runCli(["list", "--json"], env);
    assert.equal(listed.code, 0, listed.stderr);
    const rows = JSON.parse(listed.stdout) as Array<{ paymentId: string; state: string; principalId: string; credits: number }>;
    assert.deepEqual(
      rows.map((r) => [r.paymentId, r.state, r.principalId, r.credits]),
      [[replayKey(payload), "unknown", derivedPrincipal(payload), CREDITS]]
    );

    const resolved = await runCli(["resolve", replayKey(payload), "--tx", txFor(nonceOf(payload))], env);
    assert.equal(resolved.code, 0, resolved.stderr);
    assert.match(resolved.stdout, new RegExp(`${CREDITS} credits granted to ${derivedPrincipal(payload)}`));
    assert.equal(h.usage.creditsRemaining(derivedPrincipal(payload)), CREDITS, "a server sharing the database sees the credits");

    const noSecret = await runCli(["session", derivedPrincipal(payload)], env);
    assert.equal(noSecret.code, 1);
    assert.match(noSecret.stderr, /STACKDNS_SESSION_SECRET is required/);
    const session = await runCli(["session", derivedPrincipal(payload)], { ...env, STACKDNS_SESSION_SECRET: SESSION_SECRET });
    assert.equal(session.code, 0, session.stderr);
    assert.equal(h.sessions.verify(session.stdout.trim())?.sub, derivedPrincipal(payload));
    assert.match(session.stderr, new RegExp(`balance: ${CREDITS} credits`));

    // The same entry point in-process: the table, a second resolve, a usage error and a missing file.
    const out: string[] = [];
    const err: string[] = [];
    const io = { out: (t: string) => void out.push(t), err: (t: string) => void err.push(t) };
    const payload2 = x402Payload();
    assert.equal((await call(h, "/v1/jobs", { headers: { "x-payment": header(payload2) } })).status, 502);
    assert.equal(await settlementsCli(["list"], env, io), 0);
    assert.match(out.join(""), new RegExp(`${replayKey(payload2)}\\s+unknown\\s+${derivedPrincipal(payload2)}\\s+${CREDITS}`));
    assert.equal(await settlementsCli(["resolve", replayKey(payload), "--tx", txFor(nonceOf(payload))], env, io), 1);
    assert.match(err.join(""), /already recorded/);
    // A missing flag is bad usage (exit 2, round 9).
    assert.equal(await settlementsCli(["resolve", replayKey(payload2)], env, io), 2);
    assert.match(err.join(""), /--tx <hash> or --failed/);
    assert.equal(await settlementsCli(["resolve", replayKey(payload2), "--failed", "--json"], env, io), 0);
    assert.match(out.join(""), /"outcome": "failed"/);
    assert.equal(await settlementsCli(["list"], cliEnv({ STACKDNS_DB_FILE: path.join(dir, "nope.db") }), io), 1);
    assert.match(err.join(""), /does not exist/);
    await h.close();
  });

  it("main() answers usage errors and --help without touching a database", async () => {
    const out: string[] = [];
    const err: string[] = [];
    const io = { out: (t: string) => void out.push(t), err: (t: string) => void err.push(t) };
    assert.equal(await settlementsCli(["--help"], cliEnv({}), io), 0);
    assert.match(out.join(""), /resolve <paymentId> --tx <hash>/);
    assert.equal(await settlementsCli([], cliEnv({}), io), 2);
    assert.equal(await settlementsCli(["bogus"], cliEnv({ STACKDNS_DB_FILE: "none" }), io), 2);
    assert.equal(await settlementsCli(["list", "--frobnicate"], cliEnv({}), io), 2);
    assert.equal(await settlementsCli(["list"], cliEnv({ STACKDNS_DB_FILE: "none" }), io), 1);
    assert.match(err.join(""), /usage file/);
  });
});

// ---------------------------------------------------------------------------
// Discrepancies
// ---------------------------------------------------------------------------

describe("Stripe: a concurrent redemption's message", () => {
  it("never promises that a retry re-issues the session token", async () => {
    const h = await harness({ env: { STACKDNS_PAYMENT_METHODS: "stripe,x402", STRIPE_SECRET_KEY: "sk_test_round8" } });
    assert.ok(h.payments.stripeEnabled);
    const credential: PaymentCredential = { method: "stripe", challengeId: null, paymentIntentId: "pi_concurrent", checkoutSessionId: null, x402Payload: null };
    const [first, second] = await Promise.all([h.payments.redeem(credential, target("pay_stripe")), h.payments.redeem(credential, target("pay_stripe"))]);
    assert.ok(first.ok, failureCode(first));
    assert.equal(failureCode(second), "payment_redemption_in_progress");
    assert.ok(!second.ok);
    assert.doesNotMatch(second.message, /re-issues its session token/);
    assert.match(second.message, /never re-issues/);
    assert.match(second.message, /Do not pay again/);

    // Over HTTP the 409 carries that message, and the retry it prompts is refused without a token.
    const auth = `Payment ${encodeCredential({ paymentIntentId: "pi_concurrent_http" })}`;
    const [a, b] = await Promise.all([call(h, "/v1/jobs", { headers: { authorization: auth } }), call(h, "/v1/jobs", { headers: { authorization: auth } })]);
    const busy = a.status === 409 ? a : b;
    assert.equal(busy.status, 409, JSON.stringify([a.body, b.body]));
    assert.doesNotMatch(String(busy.body.message), /re-issues its session token/);
    const retry = await call(h, "/v1/jobs", { headers: { authorization: auth } });
    assert.equal(retry.status, 409);
    assert.equal(retry.headers.get("x-session-token"), null);
  });
});

describe("start_bulk_check over MCP is a spending call", () => {
  it("an exhausted session is challenged for it like POST /v1/jobs, and still served for the bulk read and cancel tools", async () => {
    const h = await harness();
    const session = await buyCredits(h);
    assert.equal(h.usage.consumeCredits(session.principalId, CREDITS), true);
    const bare = { authorization: `Bearer ${session.token}` };
    const submit = await call(h, "/mcp", { method: "POST", headers: bare, body: toolCall("start_bulk_check", { domains: ["example.com"] }) });
    assert.equal(submit.status, 402, `not served into INSUFFICIENT_CREDITS: ${JSON.stringify(submit.body)}`);
    assert.equal(submit.body.reason, "credits_exhausted");
    const batch = await call(h, "/mcp", { method: "POST", headers: bare, body: [toolCall("list_bulk_checks"), toolCall("start_bulk_check", { domains: ["example.com"] })] });
    assert.equal(batch.status, 402, "a JSON-RPC batch carrying a submission is challenged too");

    const stale = { ...bare, "x-payment": session.paymentHeader };
    const withHeader = await call(h, "/mcp", { method: "POST", headers: stale, body: toolCall("start_bulk_check", { domains: ["example.com"] }) });
    assert.equal(withHeader.status, 409, JSON.stringify(withHeader.body));
    assert.equal(withHeader.body.reason, "payment_already_redeemed");
    assert.ok(Array.isArray(withHeader.body.accepts) && withHeader.body.accepts.length > 0);

    for (const name of ["get_bulk_check", "list_bulk_checks", "cancel_bulk_check"]) {
      for (const headers of [bare, stale]) {
        const res = await call(h, "/mcp", { method: "POST", headers, body: toolCall(name, { jobId: "job_1" }) });
        assert.equal(res.status, 200, `${name}: ${JSON.stringify(res.body)}`);
      }
    }
  });
});

function fakeExtra(): RequestHandlerExtra<ServerRequest, ServerNotification> {
  return {
    signal: new AbortController().signal,
    requestId: 1,
    sendNotification: async () => undefined,
    sendRequest: async () => {
      throw new Error("not used");
    }
  } as unknown as RequestHandlerExtra<ServerRequest, ServerNotification>;
}

describe("billing after a bulk submission", () => {
  it("requestsRemainingToday counts the daily-quota units the submission charged", async () => {
    const config = loadConfig({ STACKDNS_TRANSPORT: "stdio" }, []);
    config.auth.planLimits = { ...DEFAULT_PLAN_LIMITS, pro: { perMinute: 60, perDay: 100, maxConcurrent: 4 } };
    const usage = new UsageTracker(null);
    const limiter = new RateLimiter(config.auth.planLimits);
    const principal: Principal = { id: "key_bulk", plan: "pro", label: "test", source: "api-key" };
    const meter = createMeter({ config, usage, limiter, localPrincipal: principal });
    // Like jobs.submit: one daily-quota unit per accepted domain, charged inside the handler.
    const submit = meter("start_bulk_check", async (_args: Record<string, never>, ctx) => {
      assert.equal(limiter.consumeDayUnits(ctx.principal.id, ctx.principal.plan, 4).allowed, true);
      return { job: { quotaUnitsCharged: 4 } };
    });
    const result = await submit({}, fakeExtra());
    assert.ok(!result.isError);
    const billing = (result.structuredContent as { billing: { requestsRemainingToday: number; requestsRemainingThisMinute: number } }).billing;
    assert.equal(billing.requestsRemainingToday, 96, "not the 100 read before the handler ran");
    assert.equal(billing.requestsRemainingThisMinute, 59);
    const poll = await meter("get_bulk_check", async () => ({ job: {} }))({}, fakeExtra());
    assert.equal((poll.structuredContent as { billing: { requestsRemainingToday: number } }).billing.requestsRemainingToday, 96, "the next call agrees");
  });
});

describe("the served-session log line", () => {
  it("does not call an exhausted session funded, and logs its balance", async () => {
    const h = await harness();
    const session = await buyCredits(h);
    assert.equal(h.usage.consumeCredits(session.principalId, CREDITS), true);
    const lines: string[] = [];
    const capture = ((chunk: unknown) => {
      lines.push(String(chunk));
      return true;
    }) as typeof process.stderr.write;
    const write = mock.method(process.stderr, "write", capture);
    setLogLevel("info");
    try {
      const res = await call(h, "/v1/jobs", { headers: { authorization: `Bearer ${session.token}`, "x-payment": session.paymentHeader } });
      assert.equal(res.status, 200);
    } finally {
      setLogLevel("silent");
      write.mock.restore();
    }
    const parsed = lines.flatMap((line) => {
      try {
        return [JSON.parse(line) as Record<string, unknown>];
      } catch {
        return [];
      }
    });
    const entry = parsed.find((l) => String(l.msg).includes("prepaid session"));
    assert.ok(entry, lines.join(""));
    assert.equal(entry.msg, "payment header ignored; request served from the prepaid session");
    assert.equal(entry.creditsRemaining, 0);
    assert.equal(entry.reason, "payment_already_redeemed");
  });
});

// ---------------------------------------------------------------------------
// Round 9
// ---------------------------------------------------------------------------

const OTHER_PAYER = "0x3333333333333333333333333333333333333333";

/** Runs fn with Date (only) moved forward by ms: the network and the timers keep real time. */
async function later<T>(ms: number, fn: () => Promise<T>): Promise<T> {
  mock.timers.enable({ apis: ["Date"], now: Date.now() + ms });
  try {
    return await fn();
  } finally {
    mock.timers.reset();
  }
}

/** The same nonce signed by another payer: a different authorization. */
function withFrom(payload: Record<string, unknown>, from: string): Record<string, unknown> {
  const inner = payload.payload as { signature: string; authorization: Record<string, unknown> };
  return { ...payload, payload: { signature: `0x${createHash("sha256").update(`${from}:${inner.signature}`).digest("hex")}`, authorization: { ...inner.authorization, from } } };
}

/** The JSON log lines fn writes at the given level. */
async function captureLogs(fn: () => unknown, level: "info" | "warn" = "warn"): Promise<Array<Record<string, unknown>>> {
  const lines: string[] = [];
  const capture = ((chunk: unknown) => {
    lines.push(String(chunk));
    return true;
  }) as typeof process.stderr.write;
  const write = mock.method(process.stderr, "write", capture);
  setLogLevel(level);
  try {
    await fn();
  } finally {
    setLogLevel("silent");
    write.mock.restore();
  }
  return lines.flatMap((line) => {
    try {
      return [JSON.parse(line) as Record<string, unknown>];
    } catch {
      return [];
    }
  });
}

describe("Round 9 x402-asset-version-inert: X402_ASSET_VERSION reaches the payment requirements", () => {
  it("the challenge, the requirements sent to the facilitator and the pricing carry the configured version", async () => {
    // A token of the operator's own (config refuses another name or version for the built-in USDC contracts).
    const h = await harness({ env: { X402_ASSET: "0x4444444444444444444444444444444444444444", X402_ASSET_NAME: "Euro Coin", X402_ASSET_VERSION: "1" } });
    const challenge = await h.payments.createChallenge("http://127.0.0.1:1/mcp");
    assert.deepEqual(challenge.x402?.accepts.extra, { name: "Euro Coin", version: "1", service: "stack-and-dns-mcp" });
    assert.equal((h.payments.pricing().x402 as { assetVersion?: string }).assetVersion, "1");
    // A payment presented without a challenge id is verified against the same requirements.
    assert.equal((await call(h, "/v1/jobs", { headers: { "x-payment": header(x402Payload()) } })).status, 200);
    assert.deepEqual((h.upstream.lastRequirements as { extra?: unknown } | null)?.extra, { name: "Euro Coin", version: "1", service: "stack-and-dns-mcp" });

    const defaults = await harness();
    assert.equal((await defaults.payments.createChallenge("http://127.0.0.1:1/mcp")).x402?.accepts.extra.version, "2", "USDC's version stays the default");
  });
});

describe("Round 9 PB-header-lockout-400d: an exhausted session re-attaching its unconfirmed top-up", () => {
  it("gets 502 for a day after the payment's last update, then the credits_exhausted 402 with X-Payment-Status; the header alone stays 502", async () => {
    const h = await harness();
    const session = await buyCredits(h);
    assert.equal(h.usage.consumeCredits(session.principalId, CREDITS), true);
    // Valid for an hour, so two hours on nothing re-verifies (and touches) the marker any more.
    const topUp = x402Payload();
    h.upstream.settleMode = "reset-after-broadcast";
    const withHeader = { authorization: `Bearer ${session.token}`, "x-payment": header(topUp) };
    const spend = (headers: Record<string, string>) => call(h, "/v1/jobs", { method: "POST", headers, body: JOB_BODY });
    const first = await spend(withHeader);
    assert.equal(first.status, 502, JSON.stringify(first.body));
    const verifies = h.upstream.count("/verify");

    const inside = await later(2 * 3600_000, () => spend(withHeader));
    assert.equal(inside.status, 502, `still blocked within the day: ${JSON.stringify(inside.body)}`);
    assert.equal(inside.headers.get("www-authenticate"), null);

    await later(25 * 3600_000, async () => {
      const res = await spend(withHeader);
      // Before, this stayed 502 for as long as the marker is kept (400 days), so the client never signed a new payment.
      assert.equal(res.status, 402, JSON.stringify(res.body));
      assert.equal(res.body.reason, "credits_exhausted");
      assert.equal(res.body.principal, session.principalId);
      assert.equal(res.body.paymentStatus, "x402_settlement_unconfirmed");
      assert.equal(res.headers.get("x-payment-status"), "x402_settlement_unconfirmed");
      assert.ok(res.headers.get("www-authenticate"));
      assert.equal((await spend({ authorization: `Bearer ${session.token}` })).status, 402, "the same answer as without the header");
      const alone = await call(h, "/v1/jobs", { headers: { "x-payment": header(topUp) } });
      assert.equal(alone.status, 502, `the header without a session keeps its answer: ${JSON.stringify(alone.body)}`);
      assert.equal(alone.headers.get("www-authenticate"), null);
    });
    assert.equal(h.upstream.count("/verify"), verifies, "answered from the marker throughout");
    assert.ok(h.usage.getSettlement(replayKey(topUp)), "the marker is still kept");
  });

  it("answers like the bare session while another of its payments is pending", async () => {
    const h = await harness();
    const session = await buyCredits(h);
    assert.equal(h.usage.consumeCredits(session.principalId, CREDITS), true);
    const topUp = x402Payload();
    h.upstream.settleMode = "reset-after-broadcast";
    const withHeader = { authorization: `Bearer ${session.token}`, "x-payment": header(topUp) };
    assert.equal((await call(h, "/v1/jobs", { method: "POST", headers: withHeader, body: JOB_BODY })).status, 502);
    await later(25 * 3600_000, async () => {
      // Another payment of this session settled but is not recorded yet.
      h.usage.beginSettlement({ paymentId: "x402_r9_other", principalId: session.principalId, label: "x402:other", credits: CREDITS, identity: "abc" }, Date.now());
      h.usage.markSettlement("x402_r9_other", "settled", "0xother:abc", null, Date.now());
      const res = await call(h, "/v1/jobs", { method: "POST", headers: withHeader, body: JOB_BODY });
      assert.equal(res.status, 503, JSON.stringify(res.body));
      assert.equal(res.body.error, "payment_recording_failed");
      assert.equal(res.headers.get("retry-after"), "5");
    });
  });
});

describe("Round 9 PB-answersLocally-misses-validBefore: payments answered without an upstream call", () => {
  it("a funded session re-attaching a header past its validBefore is never charged to the address bucket", async () => {
    const h = await harness({ env: { STACKDNS_UNAUTHENTICATED_PER_MINUTE: "3" } });
    const session = await buyCredits(h);
    const unconfirmed = x402Payload();
    // Never presented: past its validBefore it is refused as x402_expired, also without a facilitator call.
    const neverSettled = x402Payload();
    h.upstream.settleMode = "reset-after-broadcast";
    const headers = { authorization: `Bearer ${session.token}`, "x-payment": header(unconfirmed) };
    const first = await call(h, "/v1/jobs", { headers });
    assert.equal(first.headers.get("x-payment-status"), "x402_settlement_unconfirmed");
    const verifies = h.upstream.count("/verify");
    await later(2 * 3600_000, async () => {
      // validBefore has passed and the marker is far past its 60 s re-verification window.
      const statuses: Array<[number, string | null]> = [];
      for (let i = 0; i < 6; i++) {
        for (const payload of [unconfirmed, neverSettled]) {
          const res = await call(h, "/v1/jobs", { headers: { ...headers, "x-payment": header(payload) } });
          statuses.push([res.status, res.headers.get("x-payment-status")]);
        }
      }
      assert.deepEqual(
        statuses,
        Array.from({ length: 12 }, (_, i) => [200, i % 2 === 0 ? "x402_settlement_unconfirmed" : "x402_expired"])
      );
    });
    assert.equal(h.upstream.count("/verify"), verifies, "no facilitator call was made");
  });

  it("answersLocally() agrees with redeem() on which payloads need the facilitator", async () => {
    const h = await harness();
    const fresh = x402Payload();
    assert.equal(h.payments.answersLocally(credentialFor(h, fresh)), false, "a fresh payment is settled");
    h.upstream.settleMode = "reset-after-broadcast";
    assert.equal(failureCode(await h.payments.redeem(credentialFor(h, fresh), target("pay_r9_local"))), "x402_settlement_unconfirmed");
    assert.equal(h.payments.answersLocally(credentialFor(h, fresh)), true, "inside the re-verification window");
    assert.ok(h.db);
    ageMarkers(h.db, 61_000);
    assert.equal(h.payments.answersLocally(credentialFor(h, fresh)), false, "past the window it is verified again");
    await later(2 * 3600_000, async () => {
      assert.equal(h.payments.answersLocally(credentialFor(h, fresh)), true, "past validBefore it never is");
      assert.equal(failureCode(await h.payments.redeem(credentialFor(h, fresh), target("pay_r9_local"))), "x402_settlement_unconfirmed");
    });
  });
});

describe("Round 9 PA-remark-doubles-event-loop-freeze: the 'settled' re-mark waits for the recording", () => {
  it("a failed 'settled' write is not retried beside a recording that is waiting out a lock", async () => {
    const h = await harness();
    assert.ok(h.ledger && h.db);
    const payload = x402Payload();
    h.ledger.lockMark.set("settled", 1);
    h.ledger.lockRedeem = 2;
    const res = await call(h, "/v1/jobs", { headers: { "x-payment": header(payload) } });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    // Before, the re-mark ran in lockstep with the recording's retries: mark, redeem, mark, redeem, redeem.
    assert.deepEqual(
      h.ledger.events.filter((e) => e === "redeem" || e === "mark:settled"),
      ["mark:settled", "redeem", "redeem", "redeem"]
    );
    assert.equal(markerOf(h.db, payload), null, "the recording removed the marker");
    assert.equal(h.usage.creditsRemaining(derivedPrincipal(payload)), CREDITS);
  });
});

describe("Round 9 P-E: the authorization identity is the payer and the nonce", () => {
  it("two payers whose authorizations reuse a nonce in one batched transaction are both credited", async () => {
    const h = await harness();
    h.upstream.settleMode = "batch";
    const a = x402Payload();
    const b = withFrom(a, OTHER_PAYER);
    assert.equal(nonceOf(a), nonceOf(b));
    assert.notEqual(x402AuthorizationIdentity(a), x402AuthorizationIdentity(b));
    for (const payload of [a, b]) {
      const res = await call(h, "/v1/jobs", { headers: { "x-payment": header(payload) } });
      assert.equal(res.status, 200, JSON.stringify(res.body));
      assert.equal(h.usage.creditsRemaining(derivedPrincipal(payload)), CREDITS);
    }
  });

  it("the same, without a shared database", async () => {
    const h = await harness({ usage: new UsageTracker(null) });
    h.upstream.settleMode = "batch";
    const a = x402Payload();
    for (const payload of [a, withFrom(a, OTHER_PAYER)]) {
      const res = await h.payments.redeem(credentialFor(h, payload), target(derivedPrincipal(payload)));
      assert.ok(res.ok, failureCode(res));
    }
  });

  it("a payer-qualified guard yields to the nonce-only guard written when the payer was unknown", async () => {
    const h = await harness();
    h.upstream.verifyMode = "lenient";
    h.upstream.settleMode = "idempotent";
    h.upstream.verifyPayer = null;
    const payload = x402Payload();
    const bare = withoutFrom(payload);
    assert.equal((await call(h, "/v1/jobs", { headers: { "x-payment": header(bare) } })).status, 200);
    const nonceOnly = x402TransactionGuard(txFor(nonceOf(payload)), x402NonceIdentity(nonceOf(payload)) as string).guard;
    assert.equal(h.usage.isPaymentRedeemed(nonceOnly), true, "recorded under the nonce alone");
    h.upstream.verifyPayer = PAYER;
    const again = await call(h, "/v1/jobs", { headers: { "x-payment": header(payload) } });
    assert.equal(again.status, 409, JSON.stringify(again.body));
    assert.equal(h.usage.creditsRemaining(derivedPrincipal(payload)), null, "no second credit");
  });

  it("x402AuthorizationIdentity: `from` first, else the payer /verify reported, else the nonce alone", () => {
    const payload = x402Payload();
    const nonce = nonceOf(payload).toLowerCase().replace(/^0x/, "");
    const from = PAYER.slice(2);
    assert.equal(x402AuthorizationIdentity(payload), `${from}.${nonce}`);
    assert.equal(x402AuthorizationIdentity(payload, OTHER_PAYER), `${from}.${nonce}`, "the signed `from` wins");
    assert.equal(x402AuthorizationIdentity(withoutFrom(payload), PAYER.toUpperCase()), `${from}.${nonce}`);
    assert.equal(x402AuthorizationIdentity(withoutFrom(payload)), nonce);
    const tx = "0xABC";
    assert.deepEqual(x402TransactionGuard(tx, `${from}.${nonce}`), {
      markerTx: `0xABC:${from}.${nonce}`,
      guard: `x402_0xabc:${from}.${nonce}`,
      legacy: "x402_0xabc",
      blockedBy: ["x402_0xabc", `x402_0xabc:${nonce}`],
      // Round 11: a known payer yields to the guards of its transaction and nonce whose payer part is not an address.
      blockedByFamily: { prefix: "x402_0xabc:", suffix: `.${nonce}`, unknownPayersOnly: true }
    });
    assert.deepEqual(x402TransactionGuard(tx, nonce).blockedBy, ["x402_0xabc"]);
  });
});

describe("Round 9: a leftover marker of a recorded payment", () => {
  it("is answered 'already redeemed' and removed, instead of 'unconfirmed' for as long as markers are kept", async () => {
    for (const shared of [true, false]) {
      const h = shared ? await harness() : await harness({ usage: new UsageTracker(null) });
      for (const state of ["unknown", "settling"] as const) {
        const payload = x402Payload();
        const id = replayKey(payload);
        const principal = derivedPrincipal(payload);
        h.usage.beginSettlement({ paymentId: id, principalId: principal, label: "x402:leftover", credits: CREDITS, identity: x402AuthorizationIdentity(payload) }, Date.now() - 3 * 3600_000);
        if (state === "unknown") h.usage.markSettlement(id, "unknown", null, null, Date.now() - 2 * 3600_000);
        // Recorded (credits granted), but the marker's removal failed.
        assert.equal(await h.usage.redeemAndGrant([id], principal, "payg", "x402:leftover", CREDITS), true);
        // Past validBefore, so the marker alone used to answer "unconfirmed".
        await later(2 * 3600_000, async () => {
          assert.equal(h.payments.answersLocally(credentialFor(h, payload)), true);
          const retry = await h.payments.redeem(credentialFor(h, payload), target(principal));
          assert.equal(failureCode(retry), "payment_already_redeemed", `${shared ? "database" : "memory"}, ${state}`);
        });
        assert.equal(h.usage.getSettlement(id), null, `${shared ? "database" : "memory"}, ${state}: the marker is gone`);
        assert.equal(h.usage.creditsRemaining(principal), CREDITS, "credited once");
      }
    }
  });

  it("a settled marker whose transaction guard the other presentation already credited is finished at once, crediting nothing", async () => {
    const h = await harness();
    const payload = x402Payload();
    const bare = withoutFrom(payload);
    const identity = x402AuthorizationIdentity(payload) as string;
    assert.equal(x402AuthorizationIdentity(bare, PAYER), identity);
    const { markerTx, guard } = x402TransactionGuard(txFor(nonceOf(payload)), identity);
    // The presentation with `from` was recorded; the one without settled onto the same transaction elsewhere and
    // could not be recorded there.
    assert.equal(await h.usage.redeemAndGrant([guard, replayKey(payload)], derivedPrincipal(payload), "payg", "x402:with", CREDITS), true);
    h.usage.beginSettlement({ paymentId: replayKey(bare), principalId: derivedPrincipal(bare), label: "x402:without", credits: CREDITS, identity }, Date.now());
    h.usage.markSettlement(replayKey(bare), "settled", markerTx, null, Date.now());
    // Not left "being recorded" until it is adoptable (45 s): adopting now only records this payment id.
    const res = await h.payments.redeem(credentialFor(h, bare), target(derivedPrincipal(bare)));
    assert.equal(failureCode(res), "payment_already_redeemed");
    assert.equal(h.usage.getSettlement(replayKey(bare)), null);
    assert.equal(h.usage.isPaymentRedeemed(replayKey(bare)), true, "its payment id is recorded");
    assert.equal(h.usage.creditsRemaining(derivedPrincipal(bare)), null, "and nothing is credited twice");
  });

  it("over HTTP the header alone gets 409 with a challenge, and a sibling's settled leftover too", async () => {
    const A = await harness();
    const B = await harness({ sibling: A });
    assert.ok(A.db);
    const payload = x402Payload();
    A.upstream.settleMode = "gateway-504";
    assert.equal((await call(A, "/v1/jobs", { headers: { "x-payment": header(payload) } })).status, 502);
    assert.equal(await A.usage.redeemAndGrant([replayKey(payload)], derivedPrincipal(payload), "payg", "x402:leftover", CREDITS), true);
    const res = await call(B, "/v1/jobs", { headers: { "x-payment": header(payload) } });
    assert.equal(res.status, 409, JSON.stringify(res.body));
    assert.equal(res.body.reason, "payment_already_redeemed");
    assert.equal(markerOf(A.db, payload), null);

    // A 'settled' marker whose payment is recorded is done too, even before it would be adoptable.
    const settled = x402Payload();
    A.usage.beginSettlement(
      { paymentId: replayKey(settled), principalId: derivedPrincipal(settled), label: "x402:settled", credits: CREDITS, identity: x402AuthorizationIdentity(settled) },
      Date.now()
    );
    const { markerTx, guard } = x402TransactionGuard(txFor(nonceOf(settled)), x402AuthorizationIdentity(settled) as string);
    A.usage.markSettlement(replayKey(settled), "settled", markerTx, null, Date.now());
    assert.equal(await A.usage.redeemAndGrant([guard, replayKey(settled)], derivedPrincipal(settled), "payg", "x402:settled", CREDITS), true);
    assert.equal((await call(B, "/v1/jobs", { headers: { "x-payment": header(settled) } })).status, 409);
    assert.equal(markerOf(A.db, settled), null);
  });
});

describe("Round 9: the settlements CLI", () => {
  it("list filters before it limits, and says so when more rows remain", async () => {
    const dir = await tempDir("sdm-r9-cli-");
    const file = path.join(dir, "shared.db");
    const db = await openDatabase(file);
    assert.ok(db);
    cleanups.push(async () => db.close());
    const ledger = new CreditLedger(db);
    const now = Date.now();
    // A full page of old leftovers (recorded payments whose marker removal failed), then two that need an operator.
    db.exec("BEGIN");
    for (let i = 0; i < DEFAULT_LIST_LIMIT; i++) {
      ledger.beginSettlement({ paymentId: `x402_r9_done_${i}`, principalId: "pay_done", label: "x402:done", credits: 1 }, now - 10 * 86_400_000 + i);
      ledger.markRedeemed(`x402_r9_done_${i}`);
    }
    db.exec("COMMIT");
    for (const [id, age] of [
      ["x402_r9_open_a", 7200_000],
      ["x402_r9_open_b", 3600_000]
    ] as const) {
      ledger.beginSettlement({ paymentId: id, principalId: "pay_open", label: "x402:open", credits: 5, identity: "abc" }, now - age);
      ledger.markSettlement(id, "unknown", null, null, now - age);
    }
    const page = listSettlements(ledger, { now });
    assert.deepEqual(
      page.rows.map((r) => r.paymentId),
      ["x402_r9_open_a", "x402_r9_open_b"],
      "not hidden behind a page of leftovers"
    );
    assert.equal(page.truncated, false);
    const one = listSettlements(ledger, { now, limit: 1 });
    assert.deepEqual(
      one.rows.map((r) => r.paymentId),
      ["x402_r9_open_a"]
    );
    assert.equal(one.truncated, true);
    const all = listSettlements(ledger, { now, all: true, limit: 3 });
    assert.equal(all.rows.length, 3);
    assert.equal(all.truncated, true);

    const out: string[] = [];
    const err: string[] = [];
    const io = { out: (t: string) => void out.push(t), err: (t: string) => void err.push(t) };
    const env = cliEnv({ STACKDNS_DB_FILE: file });
    assert.equal(await settlementsCli(["list", "--limit", "1", "--json"], env, io), 0);
    assert.deepEqual(
      (JSON.parse(out.join("")) as Array<{ paymentId: string }>).map((r) => r.paymentId),
      ["x402_r9_open_a"]
    );
    assert.match(err.join(""), /Showing the 1 oldest; more markers need attention/);
    err.length = 0;
    assert.equal(await settlementsCli(["list"], env, io), 0);
    assert.equal(err.join(""), "", "no notice when nothing more remains");
  });

  it("bad usage exits 2, checked before any database is opened; a refusal exits 1", async () => {
    const dir = await tempDir("sdm-r9-cli-");
    const out: string[] = [];
    const err: string[] = [];
    const io = { out: (t: string) => void out.push(t), err: (t: string) => void err.push(t) };
    const absent = cliEnv({ STACKDNS_DB_FILE: path.join(dir, "absent.db") });
    for (const argv of [
      ["resolve"],
      ["resolve", "x402_a", "x402_b", "--failed"],
      ["resolve", "x402_a"],
      ["resolve", "x402_a", "--tx", "0x1", "--failed"],
      ["session"],
      ["session", "pay_a", "pay_b"],
      ["list", "extra"],
      ["list", "--limit", "0"],
      ["list", "--limit", "ten"],
      ["list", "--limit"]
    ]) {
      assert.equal(await settlementsCli(argv, absent, io), 2, argv.join(" "));
    }
    assert.doesNotMatch(err.join(""), /does not exist/, "the usage is checked before the database");
    assert.equal(await settlementsCli(["list"], absent, io), 1);
    assert.match(err.join(""), /does not exist/);

    // On a real database: a marker from before round 8 needs --nonce (bad usage); a --nonce naming another
    // authorization is refused; the nonce part of a payer-qualified identity is accepted.
    const file = path.join(dir, "shared.db");
    const db = await openDatabase(file);
    assert.ok(db);
    cleanups.push(async () => db.close());
    const ledger = new CreditLedger(db);
    const env = cliEnv({ STACKDNS_DB_FILE: file });
    const legacy = x402Payload();
    ledger.beginSettlement({ paymentId: replayKey(legacy), principalId: "pay_r9_legacy", label: "x402:legacy", credits: 5 }, Date.now() - 120_000);
    ledger.markSettlement(replayKey(legacy), "unknown", null, null, Date.now() - 100_000);
    assert.equal(await settlementsCli(["resolve", replayKey(legacy), "--tx", txFor(nonceOf(legacy))], env, io), 2);
    assert.match(err.join(""), /--nonce/);
    assert.throws(
      () => resolveConfirmed(ledger, replayKey(legacy), { tx: txFor(nonceOf(legacy)) }),
      (e: unknown) => e instanceof UsageError
    );

    const current = x402Payload();
    const identity = x402AuthorizationIdentity(current) as string;
    assert.match(identity, /\./, "payer-qualified");
    ledger.beginSettlement({ paymentId: replayKey(current), principalId: "pay_r9_current", label: "x402:current", credits: 5, identity }, Date.now() - 120_000);
    ledger.markSettlement(replayKey(current), "unknown", null, null, Date.now() - 100_000);
    assert.equal(await settlementsCli(["resolve", replayKey(current), "--tx", txFor(nonceOf(current)), "--nonce", nonceOf(legacy)], env, io), 1);
    assert.match(err.join(""), /does not match/);
    assert.equal(await settlementsCli(["resolve", replayKey(current), "--tx", txFor(nonceOf(current)), "--nonce", nonceOf(current)], env, io), 0);
    assert.equal(ledger.balance("pay_r9_current"), 5);
    assert.equal(ledger.isRedeemed(x402TransactionGuard(txFor(nonceOf(current)), identity).guard, 86_400_000), true, "under the guard a server uses");
  });
});

describe("Round 9: STACKDNS_API_KEY in a stdio process without keys", () => {
  it("logs one warning at startup that the key is ignored", async () => {
    const key = "sdm_live_round9_client_key_0123456789";
    const stdio = loadConfig({ STACKDNS_TRANSPORT: "stdio", STACKDNS_API_KEY: key }, []);
    let principal: Principal | null = null;
    const logs = await captureLogs(() => {
      principal = resolveLocalPrincipal(stdio, new ApiKeyStore());
    });
    const warnings = logs.filter((l) => String(l.msg).includes("STACKDNS_API_KEY"));
    assert.equal(warnings.length, 1, JSON.stringify(logs));
    assert.equal(warnings[0]?.level, "warn");
    assert.match(String(warnings[0]?.msg), /no API keys are configured in this process.*ignored/);
    assert.equal((principal as Principal | null)?.id, "local", "the open local plan still applies");

    // No key set, or keys to check it against: no such warning.
    const quiet = await captureLogs(() => resolveLocalPrincipal(loadConfig({ STACKDNS_TRANSPORT: "stdio" }, []), new ApiKeyStore()));
    assert.equal(quiet.filter((l) => String(l.msg).includes("STACKDNS_API_KEY")).length, 0);
    const keyedConfig = loadConfig({ STACKDNS_TRANSPORT: "stdio", STACKDNS_API_KEY: key, STACKDNS_API_KEYS: `${key}:pro` }, []);
    const keys = await ApiKeyStore.fromConfig(keyedConfig);
    let keyedPrincipal: Principal | null = null;
    const keyed = await captureLogs(() => {
      keyedPrincipal = resolveLocalPrincipal(keyedConfig, keys);
    });
    assert.equal(keyed.filter((l) => String(l.msg).includes("STACKDNS_API_KEY")).length, 0, JSON.stringify(keyed));
    assert.equal((keyedPrincipal as Principal | null)?.source, "api-key");
  });
});

// ---------------------------------------------------------------------------
// Round 10
// ---------------------------------------------------------------------------

/** A harness whose facilitator verifies and settles a spent authorization again, and reports no payer. */
async function strippedFromHarness(options: HarnessOptions = {}): Promise<Harness & { ledger: TestLedger }> {
  const h = await harness(options);
  assert.ok(h.ledger);
  h.upstream.verifyMode = "lenient";
  h.upstream.settleMode = "idempotent";
  h.upstream.verifyPayer = null;
  return h as Harness & { ledger: TestLedger };
}

/** The guard a presentation is recorded under when /verify reports no payer: `from` and the nonce, else the nonce alone. */
function unverifiedGuard(payload: Record<string, unknown>): string {
  return x402TransactionGuard(txFor(nonceOf(payload)), x402AuthorizationIdentity(payload) as string).guard;
}

/**
 * A later presentation of an authorization whose first settlement is still being recorded is refused: 409 without a
 * session or credits, recorded under its payment id, and its guard (guardOf) stays unwritten.
 */
async function laterRefused(h: Harness, later: Record<string, unknown>, guardOf: (payload: Record<string, unknown>) => string = unverifiedGuard): Promise<void> {
  const res = await call(h, "/v1/jobs", { headers: { "x-payment": header(later) } });
  assert.equal(res.status, 409, JSON.stringify(res.body));
  assert.equal(res.body.reason, "payment_already_redeemed");
  assert.match(String(res.body.message), /^Transaction /);
  assert.equal(res.headers.get("x-session-token"), null);
  assert.equal(h.usage.creditsRemaining(derivedPrincipal(later)), null, "the later presentation is credited nothing");
  assert.equal(h.usage.isPaymentRedeemed(replayKey(later)), true, "recorded, so it is never settled again");
  assert.equal(h.usage.isPaymentRedeemed(guardOf(later)), false, "its guard stays unwritten: it would block the first settlement");
}

describe("Round 10 P-E: an authorization without a usable payer yields to every payer-qualified guard of its transaction", () => {
  for (const [label, verifyPayer] of [
    ["/verify omits the payer", null],
    ["/verify reports the payer as a CAIP-10 account id", `eip155:8453:${PAYER}`],
    ["/verify reports the payer in no usable form", "the-payer"]
  ] as const) {
    it(`presented with \`from\` first and without it second, it is credited once: ${label}`, async () => {
      const h = await harness();
      h.upstream.verifyMode = "lenient";
      h.upstream.settleMode = "idempotent";
      h.upstream.verifyPayer = verifyPayer;
      const payload = x402Payload();
      const bare = withoutFrom(payload);
      assert.equal((await call(h, "/v1/jobs", { headers: { "x-payment": header(payload) } })).status, 200);
      const again = await call(h, "/v1/jobs", { headers: { "x-payment": header(bare) } });
      // Before, the second presentation was guarded by the nonce alone (or by a hash of the payer's other form),
      // which no payer-qualified guard blocked: 200 and a second 100 credits for one transfer.
      assert.equal(again.status, 409, JSON.stringify(again.body));
      assert.match(String(again.body.message), /^Transaction /);
      assert.equal(again.headers.get("x-session-token"), null);
      assert.equal(h.usage.creditsRemaining(derivedPrincipal(bare)), null, "no second credit");
      assert.equal(h.usage.creditsRemaining(derivedPrincipal(payload)), CREDITS);
      assert.equal(h.usage.isPaymentRedeemed(replayKey(bare)), true, "recorded, so it is never settled again");
      assert.equal((await call(h, "/v1/jobs", { headers: { "x-payment": header(bare) } })).status, 409);
      assert.equal(h.upstream.count("/settle"), 2);
    });
  }

  it("a stranger cannot top up an exhausted session with a settled authorization stripped of `from`", async () => {
    const h = await harness();
    h.upstream.verifyMode = "lenient";
    h.upstream.settleMode = "idempotent";
    h.upstream.verifyPayer = null;
    const victim = x402Payload();
    assert.equal((await call(h, "/v1/jobs", { headers: { "x-payment": header(victim) } })).status, 200);
    const attacker = await buyCredits(h);
    assert.equal(h.usage.consumeCredits(attacker.principalId, CREDITS), true);
    const stolen = await call(h, "/v1/jobs", { method: "POST", headers: { authorization: `Bearer ${attacker.token}`, "x-payment": header(withoutFrom(victim)) }, body: JOB_BODY });
    // Before: 200, served on 100 credits the payer's single transfer had already bought once.
    assert.equal(stolen.status, 409, JSON.stringify(stolen.body));
    assert.equal(stolen.body.reason, "payment_already_redeemed");
    assert.equal(h.usage.creditsRemaining(attacker.principalId), 0, "the top-up credited nothing");
    assert.equal(h.usage.creditsRemaining(derivedPrincipal(victim)), CREDITS);
  });

  it("the same without a shared database, in either order", async () => {
    const h = await harness({ usage: new UsageTracker(null) });
    h.upstream.verifyMode = "lenient";
    h.upstream.settleMode = "idempotent";
    h.upstream.verifyPayer = null;
    const payload = x402Payload();
    const first = await h.payments.redeem(credentialFor(h, payload), target("pay_r10_from"));
    assert.ok(first.ok, failureCode(first));
    assert.equal(failureCode(await h.payments.redeem(credentialFor(h, withoutFrom(payload)), target("pay_r10_bare"))), "payment_already_redeemed");
    assert.equal(h.usage.creditsRemaining("pay_r10_bare"), null);
    const other = x402Payload();
    const bareFirst = await h.payments.redeem(credentialFor(h, withoutFrom(other)), target("pay_r10_bare2"));
    assert.ok(bareFirst.ok, failureCode(bareFirst));
    assert.equal(failureCode(await h.payments.redeem(credentialFor(h, other), target("pay_r10_from2"))), "payment_already_redeemed");
    assert.equal(h.usage.creditsRemaining("pay_r10_from2"), null);
  });

  it("a settled marker of the presentation without a payer is finished at once when the payer-qualified guard is already credited", async () => {
    for (const shared of [true, false]) {
      const h = shared ? await harness() : await harness({ usage: new UsageTracker(null) });
      const payload = x402Payload();
      const bare = withoutFrom(payload);
      const tx = txFor(nonceOf(payload));
      const withPayer = x402TransactionGuard(tx, x402AuthorizationIdentity(payload) as string);
      assert.equal(await h.usage.redeemAndGrant([withPayer.guard, replayKey(payload)], derivedPrincipal(payload), "payg", "x402:with", CREDITS), true);
      // The presentation without `from` settled onto the same transaction elsewhere, its payer unknown, and was not recorded there.
      const identity = x402AuthorizationIdentity(bare) as string;
      assert.equal(identity, x402NonceIdentity(nonceOf(payload)));
      h.usage.beginSettlement({ paymentId: replayKey(bare), principalId: derivedPrincipal(bare), label: "x402:without", credits: CREDITS, identity }, Date.now());
      h.usage.markSettlement(replayKey(bare), "settled", x402TransactionGuard(tx, identity).markerTx, null, Date.now());
      const res = await h.payments.redeem(credentialFor(h, bare), target(derivedPrincipal(bare)));
      const where = shared ? "database" : "memory";
      assert.equal(failureCode(res), "payment_already_redeemed", where);
      assert.equal(h.usage.getSettlement(replayKey(bare)), null, `${where}: finished at once, not left "being recorded"`);
      assert.equal(h.usage.creditsRemaining(derivedPrincipal(bare)), null, `${where}: nothing is credited twice`);
    }
  });

  it("a nonce-only authorization in a batch is still credited beside the batch's other authorizations", async () => {
    const h = await harness();
    h.upstream.settleMode = "batch";
    h.upstream.verifyPayer = null;
    const a = x402Payload();
    // A second payer reusing a's nonce (both payer-qualified), and an authorization without `from` with its own nonce.
    for (const payload of [a, withFrom(a, OTHER_PAYER), withoutFrom(x402Payload())]) {
      const res = await call(h, "/v1/jobs", { headers: { "x-payment": header(payload) } });
      assert.equal(res.status, 200, JSON.stringify(res.body));
      assert.equal(h.usage.creditsRemaining(derivedPrincipal(payload)), CREDITS);
    }
  });

  it("x402PayerIdentity: a 20-byte address, also from a CAIP-10 account id; anything else is unknown", () => {
    const address = PAYER.slice(2);
    for (const value of [PAYER, PAYER.toUpperCase(), ` ${PAYER} `, address, `eip155:8453:${PAYER}`, `EIP155:1:${PAYER.toUpperCase()}`]) {
      assert.equal(x402PayerIdentity(value), address, value);
    }
    for (const value of [null, undefined, 42, "", "the-payer", "eip155:8453:", "0x1234", `${PAYER}00`, `0x${"00".repeat(12)}${address}`, `eip155:8453:${PAYER}:x`]) {
      assert.equal(x402PayerIdentity(value), null, String(value));
    }
    const payload = x402Payload();
    const nonce = nonceOf(payload).toLowerCase().replace(/^0x/, "");
    assert.equal(x402AuthorizationIdentity(withoutFrom(payload), `eip155:8453:${PAYER}`), x402AuthorizationIdentity(payload), "one identity for both presentations");
    assert.equal(x402AuthorizationIdentity(withoutFrom(payload), "the-payer"), nonce, "an unusable payer is unknown, never hashed into an identity of its own");
    const inner = payload.payload as { signature: string; authorization: Record<string, unknown> };
    const oddFrom = { ...payload, payload: { ...inner, authorization: { ...inner.authorization, from: "not-an-address" } } };
    assert.equal(x402AuthorizationIdentity(oddFrom, PAYER), `${address}.${nonce}`, "an unusable `from` falls back to the verified payer");
  });

  it("x402TransactionGuard: an identity without a 20-byte payer yields to the payer-qualified guards of its transaction and nonce", () => {
    const payer = PAYER.slice(2);
    const nonce = "abc123";
    const family = { prefix: "x402_0xabc:", suffix: `.${nonce}` };
    assert.deepEqual(x402TransactionGuard("0xABC", nonce), { markerTx: `0xABC:${nonce}`, guard: `x402_0xabc:${nonce}`, legacy: "x402_0xabc", blockedBy: ["x402_0xabc"], blockedByFamily: family });
    // Two known payers never block each other (round 11: the family it checks leaves out every 20-byte payer part).
    const known = x402TransactionGuard("0xABC", `${payer}.${nonce}`).blockedByFamily;
    assert.deepEqual(known, { ...family, unknownPayersOnly: true });
    assert.equal(inGuardFamily(`x402_0xabc:${OTHER_PAYER.slice(2)}.${nonce}`, known as GuardFamily), false, "two known payers never block each other");
    // A payer part stored before payers were normalized (a hashed CAIP-10 id, say) is as good as unknown.
    assert.deepEqual(x402TransactionGuard("0xABC", `h${"e".repeat(40)}.${nonce}`).blockedByFamily, family);
    assert.equal(inGuardFamily(`x402_0xabc:${payer}.${nonce}`, family), true);
    assert.equal(inGuardFamily(`x402_0xabc:h${"e".repeat(40)}.${nonce}`, family), true);
    assert.equal(inGuardFamily(`x402_0xabc:${nonce}`, family), false, "not the nonce-only guard");
    assert.equal(inGuardFamily(`x402_0xabc:${payer}.${nonce}9`, family), false, "another nonce");
    assert.equal(inGuardFamily(`x402_0xabc:def:${payer}.${nonce}`, family), false, "another transaction (0xabc:def)");
    assert.equal(inGuardFamily(`x402_0xabcd:${payer}.${nonce}`, family), false, "another transaction (0xabcd)");
    // An adopter and the CLI take it from a settled marker.
    const marker: SettlementMarker = {
      paymentId: "x402_pid",
      principalId: "pay_x",
      label: "",
      credits: 1,
      state: "settled",
      tx: `0xABC:${nonce}`,
      receipt: null,
      identity: nonce,
      at: 0,
      updatedAt: 0
    };
    assert.deepEqual(settledMarkerClaim(marker)?.blockedByFamily, family);
  });

  it("CreditLedger checks the family in the recording's transaction, matching only that transaction's ids whatever it contains", async () => {
    const db = await openDatabase(":memory:");
    assert.ok(db);
    try {
      const ledger = new CreditLedger(db);
      const payer = PAYER.slice(2);
      // GLOB metacharacters in a facilitator's transaction id match only themselves.
      const tx = "0x[a-f]*";
      const guardOf = (identity: string) => x402TransactionGuard(tx, identity);
      for (const decoy of [`x402_0xb:${payer}.n1`, `x402_${tx}x:${payer}.n1`, `x402_${tx}:9:${payer}.n1`, `x402_${tx}:${payer}.n2`]) ledger.markRedeemed(decoy);
      const n1 = guardOf("n1");
      assert.ok(n1.blockedByFamily);
      assert.equal(ledger.isRedeemedFamily(n1.blockedByFamily, 86_400_000), false);
      assert.equal(ledger.redeemAndCredit([n1.guard, "x402_pid_n1"], "pay_r10_n1", "payg", "", 5, Date.now(), n1.blockedBy, n1.blockedByFamily), true, "no decoy blocks");

      ledger.markRedeemed(`x402_${tx}:${payer}.n3`);
      const n3 = guardOf("n3");
      assert.ok(n3.blockedByFamily);
      assert.equal(ledger.isRedeemedFamily(n3.blockedByFamily, 86_400_000), true);
      assert.equal(ledger.isRedeemedFamily(n3.blockedByFamily, 86_400_000, Date.now() + 2 * 86_400_000), false, "past the retention, like isRedeemed");
      assert.equal(ledger.redeemAndCredit([n3.guard, "x402_pid_n3"], "pay_r10_n3", "payg", "", 5, Date.now(), n3.blockedBy, n3.blockedByFamily), false);
      assert.equal(ledger.balance("pay_r10_n3"), null);
      assert.equal(ledger.isRedeemed("x402_pid_n3", 86_400_000), true, "its ids are still recorded");
    } finally {
      db.close();
    }
  });

  it("the CLI records a legacy marker under the nonce-only guard, which yields to a payer-qualified guard of the transaction, and the reverse", async () => {
    const h = await harness();
    assert.ok(h.ledger);
    const ledger = h.ledger.inner;
    h.upstream.verifyMode = "lenient";
    h.upstream.settleMode = "idempotent";
    // A server credited the authorization presented with `from`; a marker from before round 8 (no identity) of
    // the same authorization presented without it waits for an operator.
    const payload = x402Payload();
    assert.equal((await call(h, "/v1/jobs", { headers: { "x-payment": header(payload) } })).status, 200);
    const bare = withoutFrom(payload);
    ledger.beginSettlement({ paymentId: replayKey(bare), principalId: "pay_r10_cli", label: "x402:cli", credits: CREDITS }, Date.now() - 120_000);
    ledger.markSettlement(replayKey(bare), "unknown", null, null, Date.now() - 100_000);
    const resolved = resolveConfirmed(ledger, replayKey(bare), { tx: txFor(nonceOf(payload)), nonce: nonceOf(payload) });
    assert.equal(resolved.outcome, "already-recorded");
    assert.equal(ledger.balance("pay_r10_cli"), null, "not credited a second time");
    assert.equal(ledger.getSettlement(replayKey(bare)), null, "the marker ends");

    // The reverse: the operator records the nonce-only guard first, and the presentation with `from` is refused.
    const other = x402Payload();
    const otherBare = withoutFrom(other);
    ledger.beginSettlement({ paymentId: replayKey(otherBare), principalId: "pay_r10_cli2", label: "x402:cli2", credits: CREDITS }, Date.now() - 120_000);
    ledger.markSettlement(replayKey(otherBare), "unknown", null, null, Date.now() - 100_000);
    assert.equal(resolveConfirmed(ledger, replayKey(otherBare), { tx: txFor(nonceOf(other)), nonce: nonceOf(other) }).outcome, "credited");
    const res = await call(h, "/v1/jobs", { headers: { "x-payment": header(other) } });
    assert.equal(res.status, 409, JSON.stringify(res.body));
    assert.equal(h.usage.creditsRemaining(derivedPrincipal(other)), null);
  });

  // Round 11 made the retry paths of a recording (a retry of its header, the recording timer, the answer after a
  // lock wait) check the family. Round 12: the presentation without `from` settles first, the payer's, but is not
  // recorded yet (its first recording failed, 503 with the session, or it waits out a lock); the presentation with
  // `from`, which anyone can make once the authorization is public, settles onto the same transaction meanwhile.
  // The first settlement is credited, not the first recording: the later presentation is refused, and the kept
  // recording is credited by a retry of its header (finishPending), the timer (recordInBackground) or after the
  // lock wait. Before, the later presentation was credited with a session, and the payer got nothing.

  /** The presentation without `from` settles but is not recorded (a non-lock failure), then the one with `from` is refused. Returns the 503's session principal. */
  async function bareKeptThenWithPayerRefused(h: Harness & { ledger: TestLedger }, payload: Record<string, unknown>): Promise<string> {
    const bare = withoutFrom(payload);
    h.ledger.failRedeem = 1;
    const first = await call(h, "/v1/jobs", { headers: { "x-payment": header(bare) } });
    assert.equal(first.status, 503, JSON.stringify(first.body));
    const session = h.sessions.verify(first.headers.get("x-session-token") ?? "")?.sub;
    assert.equal(session, derivedPrincipal(bare), "the 503 carries the payer's session");
    assert.equal(privateField<Map<string, unknown>>(h.payments, "unrecorded").has(replayKey(bare)), true, "kept to be recorded later");
    await laterRefused(h, payload, unverifiedGuard);
    return session;
  }

  it("a kept recording without a payer settled first: the presentation with `from` is refused, and a retry of its header credits it", async () => {
    const h = await strippedFromHarness();
    const payload = x402Payload();
    const bare = withoutFrom(payload);
    const session = await bareKeptThenWithPayerRefused(h, payload);
    const retry = await call(h, "/v1/jobs", { headers: { "x-payment": header(bare) } });
    assert.equal(retry.status, 409, JSON.stringify(retry.body));
    assert.equal(retry.body.reason, "payment_already_redeemed");
    // Before, this answer said the credits went to the 503's session while that principal held nothing.
    assert.match(String(retry.body.message), /is recorded\. Its credits went to the principal whose session token was returned with the earlier 503/);
    assert.equal(h.usage.creditsRemaining(session), CREDITS, "the first settlement is credited, once");
    assert.equal(h.usage.creditsRemaining(derivedPrincipal(payload)), null);
    assert.equal(privateField<Map<string, { committed: boolean }>>(h.payments, "unrecorded").get(replayKey(bare))?.committed, true);
    assert.equal(h.upstream.count("/settle"), 2);
  });

  it("the same when the recording timer finishes it", async () => {
    const h = await strippedFromHarness();
    const payload = x402Payload();
    const bare = withoutFrom(payload);
    const session = await bareKeptThenWithPayerRefused(h, payload);
    (h.payments as unknown as { recordInBackground(): void }).recordInBackground();
    // Its ledger write runs synchronously; what follows it (committing the entry) only awaits microtasks.
    await drainMicrotasks();
    assert.equal(h.usage.creditsRemaining(session), CREDITS, "the first settlement is credited, once");
    assert.equal(h.usage.creditsRemaining(derivedPrincipal(payload)), null);
    assert.equal(privateField<Map<string, { committed: boolean }>>(h.payments, "unrecorded").get(replayKey(bare))?.committed, true, "committed as credited");
    assert.equal((await call(h, "/v1/jobs", { headers: { "x-payment": header(payload) } })).status, 409);
    assert.equal(h.usage.creditsRemaining(session), CREDITS);
  });

  it("a recording without a payer that waits out a locked database keeps its answer and its session; the presentation with `from` meanwhile is refused at once", async () => {
    const h = await strippedFromHarness();
    const payload = x402Payload();
    const bare = withoutFrom(payload);
    h.ledger.lockRedeemFor = replayKey(bare);
    const pending = call(h, "/v1/jobs", { headers: { "x-payment": header(bare) } });
    // Its recording has read creditedBefore (nothing was credited yet) and now sleeps between attempts.
    for (const started = Date.now(); !h.ledger.events.includes("redeem");) {
      assert.ok(Date.now() - started < 10_000, "the recording never started");
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    // Before: 200 with a session and the credits, after which the first settler got 409 and nothing.
    await laterRefused(h, payload, unverifiedGuard);
    h.ledger.lockRedeemFor = null;
    const first = await pending;
    assert.equal(first.status, 200, JSON.stringify(first.body));
    assert.equal(h.sessions.verify(first.headers.get("x-session-token") ?? "")?.sub, derivedPrincipal(bare));
    assert.equal(h.usage.creditsRemaining(derivedPrincipal(bare)), CREDITS, "the first settlement is credited, once");
    assert.equal(h.usage.creditsRemaining(derivedPrincipal(payload)), null);
  });
});

// ---------------------------------------------------------------------------
// Round 11
// ---------------------------------------------------------------------------

describe("Round 11 P-E: a known payer yields to the guards of its transaction and nonce whose payer part is not an address", () => {
  const CAIP_PAYER = `eip155:8453:${PAYER}`;

  /** The payer part round 9 code (identityPart) gave a payer: lowercased without 0x when short and alphanumeric, else a hash. */
  function round9PayerPart(value: string): string {
    const text = value.trim().toLowerCase().replace(/^0x/, "");
    return /^[0-9a-z]{1,80}$/.test(text) ? text : `h${createHash("sha256").update(text).digest("hex").slice(0, 40)}`;
  }

  /** The identity a round 9 marker of the presentation without `from` stored when /verify reported this payer. */
  function round9Identity(payload: Record<string, unknown>, payer: string): string {
    return `${round9PayerPart(payer)}.${x402NonceIdentity(nonceOf(payload)) as string}`;
  }

  for (const [label, odd] of [
    ["a hashed CAIP-10 payer", CAIP_PAYER],
    ["a payer in no usable form", "the-payer"]
  ] as const) {
    it(`a guard round 9 wrote for the presentation without \`from\` (${label}) blocks the presentation with it`, async () => {
      for (const shared of [true, false]) {
        const h = shared ? await harness() : await harness({ usage: new UsageTracker(null) });
        const where = shared ? "database" : "memory";
        h.upstream.verifyMode = "lenient";
        h.upstream.settleMode = "idempotent";
        const payload = x402Payload();
        const bare = withoutFrom(payload);
        const roundNine = x402TransactionGuard(txFor(nonceOf(payload)), round9Identity(payload, odd)).guard;
        assert.match(roundNine, /:h[0-9a-f]{40}\./, "its payer part is a hash, not an address");
        assert.equal(await h.usage.redeemAndGrant([roundNine, replayKey(bare)], derivedPrincipal(bare), "payg", "x402:r9", CREDITS), true);
        // Before, a payer-qualified identity checked only the nonce-only guard by name: 200 and a second 100 credits.
        if (shared) {
          const res = await call(h, "/v1/jobs", { headers: { "x-payment": header(payload) } });
          assert.equal(res.status, 409, JSON.stringify(res.body));
          assert.equal(res.headers.get("x-session-token"), null);
        } else {
          assert.equal(failureCode(await h.payments.redeem(credentialFor(h, payload), target(derivedPrincipal(payload)))), "payment_already_redeemed", where);
        }
        assert.equal(h.usage.creditsRemaining(derivedPrincipal(payload)), null, `${where}: no second credit`);
        assert.equal(h.usage.isPaymentRedeemed(replayKey(payload)), true, `${where}: recorded, so it is never settled again`);
      }
    });
  }

  it("a round 9 marker with such an identity, resumed here, and the presentation with `from` are credited once", async () => {
    const h = await harness();
    assert.ok(h.db);
    h.upstream.verifyMode = "lenient";
    h.upstream.settleMode = "idempotent";
    h.upstream.verifyPayer = CAIP_PAYER;
    const payload = x402Payload();
    const bare = withoutFrom(payload);
    const identity = round9Identity(payload, CAIP_PAYER);
    h.usage.beginSettlement({ paymentId: replayKey(bare), principalId: derivedPrincipal(bare), label: "x402:r9", credits: CREDITS, identity }, Date.now());
    h.usage.markSettlement(replayKey(bare), "unknown", null, null, Date.now());
    ageMarkers(h.db, 10 * 60_000);
    // Re-verified and settled under the identity the marker was claimed with, onto the principal it stored.
    const resumed = await call(h, "/v1/jobs", { headers: { "x-payment": header(bare) } });
    assert.equal(resumed.status, 409, JSON.stringify(resumed.body));
    assert.equal(h.usage.creditsRemaining(derivedPrincipal(bare)), CREDITS);
    assert.equal(h.usage.isPaymentRedeemed(x402TransactionGuard(txFor(nonceOf(payload)), identity).guard), true, "recorded under the stored identity");
    const withPayer = await call(h, "/v1/jobs", { headers: { "x-payment": header(payload) } });
    assert.equal(withPayer.status, 409, JSON.stringify(withPayer.body));
    assert.equal(h.usage.creditsRemaining(derivedPrincipal(payload)), null, "credited once");
  });

  it("the CLI resolving such a marker, then the presentation with `from`, credit once", async () => {
    const h = await harness();
    assert.ok(h.ledger);
    const ledger = h.ledger.inner;
    h.upstream.verifyMode = "lenient";
    h.upstream.settleMode = "idempotent";
    const payload = x402Payload();
    const bare = withoutFrom(payload);
    ledger.beginSettlement({ paymentId: replayKey(bare), principalId: "pay_r11_cli", label: "x402:cli", credits: CREDITS, identity: round9Identity(payload, CAIP_PAYER) }, Date.now() - 600_000);
    ledger.markSettlement(replayKey(bare), "unknown", null, null, Date.now() - 600_000);
    assert.equal(resolveConfirmed(ledger, replayKey(bare), { tx: txFor(nonceOf(payload)) }).outcome, "credited");
    const res = await call(h, "/v1/jobs", { headers: { "x-payment": header(payload) } });
    assert.equal(res.status, 409, JSON.stringify(res.body));
    assert.equal(h.usage.creditsRemaining(derivedPrincipal(payload)), null, "credited once");
    assert.equal(ledger.balance("pay_r11_cli"), CREDITS);
  });

  it("inGuardFamily with unknownPayersOnly matches a payer part that is not a 20-byte address, never an address, in memory and in the ledger", async () => {
    const nonce = "abc123";
    const family: GuardFamily = { prefix: "x402_0xabc:", suffix: `.${nonce}`, unknownPayersOnly: true };
    assert.equal(inGuardFamily(`x402_0xabc:h${"e".repeat(40)}.${nonce}`, family), true, "a hashed CAIP-10 payer");
    assert.equal(inGuardFamily(`x402_0xabc:thepayer.${nonce}`, family), true);
    assert.equal(inGuardFamily(`x402_0xabc:${"0".repeat(24)}${PAYER.slice(2)}.${nonce}`, family), true, "a 32-byte word is not an address");
    assert.equal(inGuardFamily(`x402_0xabc:${OTHER_PAYER.slice(2)}.${nonce}`, family), false, "another payer's address");
    assert.equal(inGuardFamily(`x402_0xabc:${PAYER.slice(2)}.${nonce}`, family), false, "its own guard");
    assert.equal(inGuardFamily(`x402_0xabc:${nonce}`, family), false, "the nonce-only guard is checked by name (blockedBy)");
    assert.equal(inGuardFamily(`x402_0xabc:h${"e".repeat(40)}.${nonce}9`, family), false, "another nonce");
    assert.equal(inGuardFamily(`x402_0xabc:${OTHER_PAYER.slice(2)}.${nonce}`, { prefix: family.prefix, suffix: family.suffix }), true, "without the flag every payer part matches");

    const db = await openDatabase(":memory:");
    assert.ok(db);
    try {
      const ledger = new CreditLedger(db);
      const known = x402TransactionGuard("0xabc", `${PAYER.slice(2)}.n1`);
      ledger.markRedeemed(x402TransactionGuard("0xabc", `${OTHER_PAYER.slice(2)}.n1`).guard);
      assert.equal(ledger.redeemAndCredit([known.guard, "x402_pid_r11_a"], "pay_r11_a", "payg", "", 5, Date.now(), known.blockedBy, known.blockedByFamily), true, "a batch's other payer never blocks");
      const second = x402TransactionGuard("0xabc", `${PAYER.slice(2)}.n2`);
      ledger.markRedeemed(x402TransactionGuard("0xabc", `h${"e".repeat(40)}.n2`).guard);
      // A round 9 payer part that is not an address blocks.
      assert.equal(ledger.redeemAndCredit([second.guard, "x402_pid_r11_b"], "pay_r11_b", "payg", "", 5, Date.now(), second.blockedBy, second.blockedByFamily), false);
      assert.equal(ledger.balance("pay_r11_b"), null);
    } finally {
      db.close();
    }
  });
});

// ---------------------------------------------------------------------------
// Round 12
// ---------------------------------------------------------------------------

describe("Round 12 P-E: of two presentations of one authorization, the one settled first is credited, not the one recorded first", () => {
  /** A 'settled' marker of the presentation, as a process that settled it and stopped before recording it leaves behind. */
  function settledMarker(h: Harness, payload: Record<string, unknown>, identity: string, at: number, updatedAt: number): void {
    h.usage.beginSettlement({ paymentId: replayKey(payload), principalId: derivedPrincipal(payload), label: "x402:r12", credits: CREDITS, identity }, at);
    h.usage.markSettlement(replayKey(payload), "settled", x402TransactionGuard(txFor(nonceOf(payload)), identity).markerTx, null, updatedAt);
  }

  async function waitForRecording(h: Harness & { ledger: TestLedger }): Promise<void> {
    for (const started = Date.now(); !h.ledger.events.includes("redeem");) {
      assert.ok(Date.now() - started < 10_000, "the recording never started");
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
  }

  for (const [label, verifyPayer] of [
    ["guarded by its nonce alone", null],
    ["guarded like the payer's, as its /verify reports the payer", PAYER]
  ] as const) {
    it(`the payer sends \`from\` and its recording fails once; the presentation stripped of \`from\` (${label}) is refused, and the payer is credited once`, async () => {
      const h = await strippedFromHarness();
      h.upstream.verifyPayer = verifyPayer;
      const payload = x402Payload();
      const stripped = withoutFrom(payload);
      h.ledger.failRedeem = 1;
      const payer = await call(h, "/v1/jobs", { headers: { "x-payment": header(payload) } });
      assert.equal(payer.status, 503, JSON.stringify(payer.body));
      const session = payer.headers.get("x-session-token");
      assert.equal(h.sessions.verify(session ?? "")?.sub, derivedPrincipal(payload), "the 503 carries the payer's session");
      // Before: 200 with a session and the 100 credits, and the payer's retry got 409 and nothing.
      await laterRefused(h, stripped, (p) => x402TransactionGuard(txFor(nonceOf(p)), x402AuthorizationIdentity(p, verifyPayer ?? undefined) as string).guard);
      const retry = await call(h, "/v1/jobs", { headers: { "x-payment": header(payload) } });
      assert.equal(retry.status, 409, JSON.stringify(retry.body));
      assert.match(String(retry.body.message), /Its credits went to the principal whose session token was returned with the earlier 503/);
      assert.equal(h.usage.creditsRemaining(derivedPrincipal(payload)), CREDITS, "the payer is credited once");
      assert.equal(h.usage.creditsRemaining(derivedPrincipal(stripped)), null);
      const spend = await call(h, "/v1/jobs", { method: "POST", headers: { authorization: `Bearer ${session}` }, body: JOB_BODY });
      assert.equal(spend.status, 200, `the 503's session reaches the credits: ${JSON.stringify(spend.body)}`);
      assert.equal((await call(h, "/v1/jobs", { headers: { "x-payment": header(stripped) } })).status, 409, "the stripped header stays refused");
      assert.equal(h.upstream.count("/settle"), 2, "and is never settled again");
    });
  }

  it("the payer's recording waits out a locked database: the presentation stripped of `from` is refused at once, and the payer keeps its 200 and its session", async () => {
    const h = await strippedFromHarness();
    const payload = x402Payload();
    const stripped = withoutFrom(payload);
    h.ledger.lockRedeemFor = replayKey(payload);
    const pending = call(h, "/v1/jobs", { headers: { "x-payment": header(payload) } });
    await waitForRecording(h);
    // Before: 200 with a session and the credits, and the payer, once the lock cleared, 409 and nothing.
    await laterRefused(h, stripped);
    h.ledger.lockRedeemFor = null;
    const payer = await pending;
    assert.equal(payer.status, 200, JSON.stringify(payer.body));
    assert.equal(h.sessions.verify(payer.headers.get("x-session-token") ?? "")?.sub, derivedPrincipal(payload));
    assert.equal(h.usage.creditsRemaining(derivedPrincipal(payload)), CREDITS, "the payer is credited once");
    assert.equal(h.usage.creditsRemaining(derivedPrincipal(stripped)), null);
  });

  it("the payer's 'settled' write fails and its recording waits out a lock: only this process knows, and the stripped presentation here still yields", async () => {
    const h = await strippedFromHarness();
    const payload = x402Payload();
    const stripped = withoutFrom(payload);
    h.ledger.failMark.add("settled");
    h.ledger.lockRedeemFor = replayKey(payload);
    const pending = call(h, "/v1/jobs", { headers: { "x-payment": header(payload) } });
    await waitForRecording(h);
    assert.equal(h.usage.listSettledFor(txFor(nonceOf(payload))).length, 0, "no 'settled' marker tells a sibling");
    await laterRefused(h, stripped);
    h.ledger.lockRedeemFor = null;
    h.ledger.failMark.delete("settled");
    const payer = await pending;
    assert.equal(payer.status, 200, JSON.stringify(payer.body));
    assert.equal(h.usage.creditsRemaining(derivedPrincipal(payload)), CREDITS, "the payer is credited once");
    assert.equal(h.usage.creditsRemaining(derivedPrincipal(stripped)), null);
  });

  it("the payer's 'settled' write and its recording both fail: only its kept entry knows, and the stripped presentation here still yields to it", async () => {
    // The test above covers an entry still in `recording`; this one is kept in `unrecorded` for a retry.
    const h = await strippedFromHarness();
    const payload = x402Payload();
    const stripped = withoutFrom(payload);
    h.ledger.failMark.add("settled");
    h.ledger.failRedeem = 1;
    const payer = await call(h, "/v1/jobs", { headers: { "x-payment": header(payload) } });
    assert.equal(payer.status, 503, JSON.stringify(payer.body));
    assert.equal(h.sessions.verify(payer.headers.get("x-session-token") ?? "")?.sub, derivedPrincipal(payload), "the 503 carries the payer's session");
    assert.equal(h.usage.listSettledFor(txFor(nonceOf(payload))).length, 0, "no 'settled' marker: only the kept entry knows");
    // Without the kept entry: 200 with a session and the credits, and the payer's retry 409 and nothing.
    await laterRefused(h, stripped);
    h.ledger.failMark.delete("settled");
    const retry = await call(h, "/v1/jobs", { headers: { "x-payment": header(payload) } });
    assert.equal(retry.status, 409, JSON.stringify(retry.body));
    assert.match(String(retry.body.message), /Its credits went to the principal whose session token was returned with the earlier 503/);
    assert.equal(h.usage.creditsRemaining(derivedPrincipal(payload)), CREDITS, "the payer is credited once");
    assert.equal(h.usage.creditsRemaining(derivedPrincipal(stripped)), null);
  });

  it("a resumed settle keeps the claim time of the settle it resumes, so it is credited before a presentation claimed in between", async () => {
    const h = await strippedFromHarness();
    assert.ok(h.db);
    const payload = x402Payload();
    const stripped = withoutFrom(payload);
    // The payer's settle moves the money but answers 504: unconfirmed, 502 with the session.
    h.upstream.settleMode = "gateway-504";
    const unconfirmed = await call(h, "/v1/jobs", { headers: { "x-payment": header(payload) } });
    assert.equal(unconfirmed.status, 502, JSON.stringify(unconfirmed.body));
    ageMarkers(h.db, 61_000);
    // The authorization is public now: a stranger strips `from` and settles it, but is not recorded yet.
    h.upstream.settleMode = "idempotent";
    h.ledger.failRedeem = 1;
    assert.equal((await call(h, "/v1/jobs", { headers: { "x-payment": header(stripped) } })).status, 503);
    // The payer's header, re-verified and settled again, is recorded under its first claim, before the stranger's.
    const resumed = await call(h, "/v1/jobs", { headers: { "x-payment": header(payload) } });
    assert.equal(resumed.status, 409, JSON.stringify(resumed.body));
    assert.match(String(resumed.body.message), /is recorded\./);
    assert.equal(h.usage.creditsRemaining(derivedPrincipal(payload)), CREDITS, "the 502's session gets the credits");
    const stranger = await call(h, "/v1/jobs", { headers: { "x-payment": header(stripped) } });
    assert.equal(stranger.status, 409, JSON.stringify(stranger.body));
    assert.match(String(stranger.body.message), /^Transaction /);
    assert.equal(h.usage.creditsRemaining(derivedPrincipal(stripped)), null);
  });

  it("a sibling process sees the payer's 'settled' marker: the stripped presentation there is refused, and the payer's retry credits it", async () => {
    const A = await strippedFromHarness();
    const B = await harness({ sibling: A });
    assert.ok(A.db);
    const payload = x402Payload();
    const stripped = withoutFrom(payload);
    A.ledger.failRedeem = 1;
    assert.equal((await call(A, "/v1/jobs", { headers: { "x-payment": header(payload) } })).status, 503);
    assert.equal(markerOf(A.db, payload)?.state, "settled");
    await laterRefused(B, stripped);
    assert.equal(markerOf(A.db, stripped), null, "its marker is removed");
    assert.equal((await call(A, "/v1/jobs", { headers: { "x-payment": header(payload) } })).status, 409);
    assert.equal(A.usage.creditsRemaining(derivedPrincipal(payload)), CREDITS, "the payer is credited once");
    assert.equal(markerOf(A.db, payload), null);
  });

  for (const mode of ["a retry of the later header", "the recording timer, handed the later marker first"] as const) {
    it(`adopting 'settled' markers, the later presentation yields to the earlier one not recorded yet: ${mode}`, async () => {
      const h = await harness();
      assert.ok(h.db);
      const payload = x402Payload();
      const bare = withoutFrom(payload);
      const bareIdentity = x402NonceIdentity(nonceOf(payload)) as string;
      const now = Date.now();
      // Both settled in processes that stopped before recording them: the payer's presentation first, then a
      // stranger's without `from`, whose marker was updated earlier, so listSettled hands it over first.
      settledMarker(h, payload, x402AuthorizationIdentity(payload) as string, now - 120_000, now - 60_000);
      settledMarker(h, bare, bareIdentity, now - 100_000, now - 90_000);
      if (mode === "a retry of the later header") {
        const res = await h.payments.redeem(credentialFor(h, bare), target(derivedPrincipal(bare)));
        assert.equal(failureCode(res), "payment_already_redeemed");
        assert.match(res.ok ? "" : res.message, /^Transaction /);
        assert.equal(markerOf(h.db, bare), null);
      }
      (h.payments as unknown as { recordInBackground(): void }).recordInBackground();
      await drainMicrotasks();
      assert.equal(h.usage.creditsRemaining(derivedPrincipal(payload)), CREDITS, "the first settlement is credited");
      assert.equal(h.usage.creditsRemaining(derivedPrincipal(bare)), null, "the later one is not");
      assert.equal(h.usage.isPaymentRedeemed(replayKey(bare)), true);
      assert.equal(h.usage.isPaymentRedeemed(x402TransactionGuard(txFor(nonceOf(payload)), bareIdentity).guard), false, "its guard stays unwritten");
      assert.equal(markerOf(h.db, payload), null);
      assert.equal(markerOf(h.db, bare), null);
    });
  }

  it("without a shared database too: a settled marker kept over a restart is credited before a later presentation's", async () => {
    const h = await harness({ usage: new UsageTracker(null) });
    const payload = x402Payload();
    const bare = withoutFrom(payload);
    const now = Date.now();
    settledMarker(h, payload, x402AuthorizationIdentity(payload) as string, now - 120_000, now - 60_000);
    settledMarker(h, bare, x402NonceIdentity(nonceOf(payload)) as string, now - 100_000, now - 60_000);
    const later = await h.payments.redeem(credentialFor(h, bare), target(derivedPrincipal(bare)));
    assert.equal(failureCode(later), "payment_already_redeemed");
    assert.match(later.ok ? "" : later.message, /^Transaction /);
    const first = await h.payments.redeem(credentialFor(h, payload), target(derivedPrincipal(payload)));
    assert.equal(failureCode(first), "payment_already_redeemed", "recorded onto its stored target; a payload alone collects no session");
    assert.equal(h.usage.creditsRemaining(derivedPrincipal(payload)), CREDITS);
    assert.equal(h.usage.creditsRemaining(derivedPrincipal(bare)), null);
    assert.equal(h.usage.getSettlement(replayKey(payload)), null);
    assert.equal(h.usage.getSettlement(replayKey(bare)), null);
  });

  it("two payers reusing a nonce in one batch: the second is credited while the first is still being recorded, and the first after", async () => {
    const h = await harness();
    assert.ok(h.ledger);
    h.upstream.settleMode = "batch";
    const a = x402Payload();
    const b = withFrom(a, OTHER_PAYER);
    h.ledger.failRedeem = 1;
    assert.equal((await call(h, "/v1/jobs", { headers: { "x-payment": header(a) } })).status, 503);
    const second = await call(h, "/v1/jobs", { headers: { "x-payment": header(b) } });
    assert.equal(second.status, 200, JSON.stringify(second.body));
    assert.equal(h.usage.creditsRemaining(derivedPrincipal(b)), CREDITS);
    assert.equal((await call(h, "/v1/jobs", { headers: { "x-payment": header(a) } })).status, 409);
    assert.equal(h.usage.creditsRemaining(derivedPrincipal(a)), CREDITS);
  });

  it("a later presentation that yields but cannot be recorded yet is kept, refused, and credited nothing once the first settlement is", async () => {
    const h = await strippedFromHarness();
    const payload = x402Payload();
    const stripped = withoutFrom(payload);
    h.ledger.failRedeem = 1;
    assert.equal((await call(h, "/v1/jobs", { headers: { "x-payment": header(payload) } })).status, 503);
    h.ledger.failMarkRedeemed = 1;
    const res = await call(h, "/v1/jobs", { headers: { "x-payment": header(stripped) } });
    assert.equal(res.status, 409, JSON.stringify(res.body));
    assert.match(String(res.body.message), /^Transaction /);
    assert.equal(res.headers.get("x-session-token"), null);
    const unrecorded = privateField<Map<string, { committed: boolean }>>(h.payments, "unrecorded");
    assert.equal(unrecorded.get(replayKey(stripped))?.committed, false, "kept to be recorded");
    (h.payments as unknown as { recordInBackground(): void }).recordInBackground();
    await drainMicrotasks();
    assert.equal(h.usage.creditsRemaining(derivedPrincipal(payload)), CREDITS, "the payer is credited once");
    assert.equal(h.usage.creditsRemaining(derivedPrincipal(stripped)), null);
    assert.equal(unrecorded.has(replayKey(stripped)), false);
    assert.equal(h.usage.isPaymentRedeemed(replayKey(stripped)), true);
  });

  for (const mode of ["a retry of its header", "the recording timer"] as const) {
    it(`a later presentation kept because its refusal could not be recorded yields again when ${mode} finishes it, while the payer's recording waits out a lock`, async () => {
      const h = await strippedFromHarness();
      const payload = x402Payload();
      const stripped = withoutFrom(payload);
      h.ledger.lockRedeemFor = replayKey(payload);
      const pending = call(h, "/v1/jobs", { headers: { "x-payment": header(payload) } });
      await waitForRecording(h);
      h.ledger.failMarkRedeemed = 1;
      assert.equal((await call(h, "/v1/jobs", { headers: { "x-payment": header(stripped) } })).status, 409);
      const unrecorded = privateField<Map<string, { committed: boolean }>>(h.payments, "unrecorded");
      assert.equal(unrecorded.get(replayKey(stripped))?.committed, false, "kept to be recorded");
      if (mode === "a retry of its header") {
        const retry = await call(h, "/v1/jobs", { headers: { "x-payment": header(stripped) } });
        assert.equal(retry.status, 409, JSON.stringify(retry.body));
        assert.match(String(retry.body.message), /^Transaction /);
      } else {
        (h.payments as unknown as { recordInBackground(): void }).recordInBackground();
        await drainMicrotasks();
      }
      // The payer's recording is not in `unrecorded` yet: it is still waiting out the lock.
      assert.equal(unrecorded.has(replayKey(stripped)), false, "recorded and dropped");
      assert.equal(h.usage.isPaymentRedeemed(replayKey(stripped)), true);
      assert.equal(h.usage.creditsRemaining(derivedPrincipal(stripped)), null, "credited nothing");
      h.ledger.lockRedeemFor = null;
      const payer = await pending;
      assert.equal(payer.status, 200, JSON.stringify(payer.body));
      assert.equal(h.usage.creditsRemaining(derivedPrincipal(payload)), CREDITS, "the payer is credited once");
    });
  }

  it("nothing yields to an earlier settlement that a recorded guard already blocks: a batch's other payer is still credited", async () => {
    const h = await harness();
    assert.ok(h.ledger);
    h.upstream.verifyMode = "lenient";
    h.upstream.settleMode = "batch";
    h.upstream.verifyPayer = null;
    const a = x402Payload();
    assert.equal((await call(h, "/v1/jobs", { headers: { "x-payment": header(a) } })).status, 200);
    // A stranger presents a's authorization without `from`: blocked by a's guard, but its recording fails, so it
    // stays an unrecorded settlement of the batch, guarded by the nonce alone.
    h.ledger.failRedeem = 1;
    assert.equal((await call(h, "/v1/jobs", { headers: { "x-payment": header(withoutFrom(a)) } })).status, 503);
    // Another payer reusing the nonce in the batch yields to the nonce-only guard once recorded, but this
    // settlement will never be credited, so it is not waited for.
    const b = withFrom(a, OTHER_PAYER);
    const res = await call(h, "/v1/jobs", { headers: { "x-payment": header(b) } });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(h.usage.creditsRemaining(derivedPrincipal(b)), CREDITS);
    assert.equal(h.usage.creditsRemaining(derivedPrincipal(withoutFrom(a))), null);
  });

  it("a presentation already blocked when it settles still yields to the first settlement of its own authorization: a batch's other payer keeps its credits", async () => {
    const h = await harness();
    assert.ok(h.ledger);
    h.upstream.verifyMode = "lenient";
    h.upstream.settleMode = "batch";
    h.upstream.verifyPayer = null;
    const a = x402Payload();
    assert.equal((await call(h, "/v1/jobs", { headers: { "x-payment": header(a) } })).status, 200);
    // Another payer reusing a's nonce in the batch settles; its recording fails once (503 with its session).
    const b = withFrom(a, OTHER_PAYER);
    h.ledger.failRedeem = 1;
    assert.equal((await call(h, "/v1/jobs", { headers: { "x-payment": header(b) } })).status, 503);
    // A stranger strips `from` from b's public authorization: guarded by the nonce alone, it is blocked by a's guard
    // already (creditedBefore), and must still not write the nonce-only guard, which is in b's blockedBy.
    const stranger = withoutFrom(b);
    const res = await call(h, "/v1/jobs", { headers: { "x-payment": header(stranger) } });
    assert.equal(res.status, 409, JSON.stringify(res.body));
    assert.match(String(res.body.message), /^Transaction /);
    assert.equal(h.usage.isPaymentRedeemed(x402TransactionGuard(BATCH_TX, x402AuthorizationIdentity(stranger) as string).guard), false, "the nonce-only guard stays unwritten");
    // Before: b's retry was blocked by that guard, and b was credited nothing.
    assert.equal((await call(h, "/v1/jobs", { headers: { "x-payment": header(b) } })).status, 409);
    assert.equal(h.usage.creditsRemaining(derivedPrincipal(b)), CREDITS, "the batch's other payer is credited");
    assert.equal(h.usage.creditsRemaining(derivedPrincipal(a)), CREDITS);
    assert.equal(h.usage.creditsRemaining(derivedPrincipal(stranger)), null);
  });

  it("a recording finished after its transaction went to another presentation says so, never that its credits went to the earlier 503's session", async () => {
    // From a kept recording (finishPending): the presentation with `from` was credited where this process could not
    // see the kept one (a sibling whose 'settled' write failed, or an operator).
    for (const verifyPayer of [null, PAYER]) {
      const where = verifyPayer === null ? "nonce-only guard" : "the same guard";
      const h = await strippedFromHarness();
      h.upstream.verifyPayer = verifyPayer;
      const payload = x402Payload();
      const bare = withoutFrom(payload);
      h.ledger.failRedeem = 1;
      assert.equal((await call(h, "/v1/jobs", { headers: { "x-payment": header(bare) } })).status, 503);
      assert.equal(await h.usage.redeemAndGrant([unverifiedGuard(payload), replayKey(payload)], derivedPrincipal(payload), "payg", "x402:elsewhere", CREDITS), true);
      const retry = await call(h, "/v1/jobs", { headers: { "x-payment": header(bare) } });
      assert.equal(retry.status, 409, `${where}: ${JSON.stringify(retry.body)}`);
      assert.match(String(retry.body.message), /^Transaction .* has already been redeemed\.$/, where);
      assert.equal(h.usage.creditsRemaining(derivedPrincipal(bare)), null, `${where}: nothing went to the 503's session`);
    }
    // From a 'settled' marker (finishMarker).
    for (const verifyPayer of [undefined, PAYER]) {
      const where = verifyPayer === undefined ? "marker, nonce-only guard" : "marker, the same guard";
      const h = await harness();
      const payload = x402Payload();
      const bare = withoutFrom(payload);
      assert.equal(await h.usage.redeemAndGrant([unverifiedGuard(payload), replayKey(payload)], derivedPrincipal(payload), "payg", "x402:elsewhere", CREDITS), true);
      settledMarker(h, bare, x402AuthorizationIdentity(bare, verifyPayer) as string, Date.now(), Date.now());
      const res = await h.payments.redeem(credentialFor(h, bare), target(derivedPrincipal(bare)));
      assert.equal(failureCode(res), "payment_already_redeemed", where);
      assert.match(res.ok ? "" : res.message, /^Transaction .* has already been redeemed\.$/, where);
      assert.equal(h.usage.getSettlement(replayKey(bare)), null, where);
      assert.equal(h.usage.creditsRemaining(derivedPrincipal(bare)), null, where);
    }
  });

  it("a kept recording a sibling credited is not told its transaction was redeemed because a later presentation's blocked recording wrote a blocker", async () => {
    const A = await strippedFromHarness();
    const B = await harness({ sibling: A });
    assert.ok(A.db);
    const payload = x402Payload();
    const stripped = withoutFrom(payload);
    A.ledger.failRedeem = 1000;
    assert.equal((await call(A, "/v1/jobs", { headers: { "x-payment": header(payload) } })).status, 503);
    // The sibling's timer adopts the payer's 'settled' marker and credits the 503's session.
    ageMarkers(A.db, 120_000);
    (B.payments as unknown as { recordInBackground(): void }).recordInBackground();
    await drainMicrotasks();
    assert.equal(A.usage.creditsRemaining(derivedPrincipal(payload)), CREDITS, "the sibling credited the payer");
    // A stranger strips `from` at the sibling: blocked by the payer's guard, nothing left to yield to, so its
    // recording writes its ids, the nonce-only guard among them, which is in the payer's blockedBy.
    const stranger = await call(B, "/v1/jobs", { headers: { "x-payment": header(stripped) } });
    assert.equal(stranger.status, 409, JSON.stringify(stranger.body));
    assert.equal(A.usage.isPaymentRedeemed(unverifiedGuard(stripped)), true);
    // A recovers, and the payer's retry reaches A's kept entry. Before: "Transaction ... has already been redeemed."
    A.ledger.failRedeem = 0;
    const retry = await call(A, "/v1/jobs", { headers: { "x-payment": header(payload) } });
    assert.equal(retry.status, 409, JSON.stringify(retry.body));
    assert.match(String(retry.body.message), /is recorded\. Its credits went to the principal whose session token was returned with the earlier 503/);
    assert.equal(A.usage.creditsRemaining(derivedPrincipal(payload)), CREDITS, "the payer is credited once");
    assert.equal(A.usage.creditsRemaining(derivedPrincipal(stripped)), null);
  });

  it("a kept recording whose 'settled' marker a sibling adopted by yielding is told its transaction was redeemed, never that its credits went to the earlier 503's session", async () => {
    const A = await strippedFromHarness();
    const B = await harness({ sibling: A });
    assert.ok(A.db);
    const payload = x402Payload();
    const stripped = withoutFrom(payload);
    const strippedIdentity = x402NonceIdentity(nonceOf(payload)) as string;
    // A stranger's presentation without `from` is claimed first; while it settles, its marker names no transaction.
    A.usage.beginSettlement({ paymentId: replayKey(stripped), principalId: derivedPrincipal(stripped), label: "x402:r12", credits: CREDITS, identity: strippedIdentity }, Date.now() - 1000);
    A.ledger.failRedeem = 1000;
    assert.equal((await call(A, "/v1/jobs", { headers: { "x-payment": header(payload) } })).status, 503);
    ageMarkers(A.db, 120_000);
    // The stranger's settle completes after the payer's, so the sibling's timer is handed the payer's marker first.
    A.usage.markSettlement(replayKey(stripped), "settled", x402TransactionGuard(txFor(nonceOf(payload)), strippedIdentity).markerTx, null, Date.now() - 100_000);
    (B.payments as unknown as { recordInBackground(): void }).recordInBackground();
    await drainMicrotasks();
    assert.equal(A.usage.creditsRemaining(derivedPrincipal(stripped)), CREDITS, "the settlement claimed first is credited");
    assert.equal(A.usage.isPaymentRedeemed(replayKey(payload)), true, "the payer's payment is recorded by the sibling, which yielded");
    assert.equal(A.usage.isPaymentRedeemed(unverifiedGuard(payload)), false, "and its guard stays unwritten");
    A.ledger.failRedeem = 0;
    const retry = await call(A, "/v1/jobs", { headers: { "x-payment": header(payload) } });
    assert.equal(retry.status, 409, JSON.stringify(retry.body));
    assert.match(String(retry.body.message), /^Transaction .* has already been redeemed\.$/);
    assert.equal(A.usage.creditsRemaining(derivedPrincipal(payload)), null, "nothing went to the 503's session");
  });

  it("listSettledFor returns the unrecorded 'settled' markers of one transaction, bare or qualified, whatever its case", async () => {
    const db = await openDatabase(":memory:");
    assert.ok(db);
    try {
      const ledger = new CreditLedger(db);
      const memory = new UsageTracker(null);
      const stores = [
        { name: "database", store: ledger as Pick<SharedLedger, "beginSettlement" | "markSettlement" | "listSettledFor">, redeem: (id: string) => ledger.markRedeemed(id) },
        { name: "memory", store: memory, redeem: (id: string) => memory.markPaymentRedeemed(id) }
      ];
      for (const { name, store, redeem } of stores) {
        const add = (paymentId: string, state: SettlementState, tx: string | null): void => {
          store.beginSettlement({ paymentId, principalId: "pay_r12", label: "", credits: 1 }, Date.now());
          store.markSettlement(paymentId, state, tx, null, Date.now());
        };
        add("x402_r12_bare", "settled", "0xAB");
        add("x402_r12_qualified", "settled", "0xAB:1111.n1");
        add("x402_r12_case", "settled", "0xab:N2");
        add("x402_r12_prefix", "settled", "0xABC:1111.n1");
        add("x402_r12_unknown", "unknown", null);
        add("x402_r12_recorded", "settled", "0xab:2222.n3");
        redeem("x402_r12_recorded");
        const ids = (markers: SettlementMarker[]): string[] => markers.map((m) => m.paymentId).sort();
        assert.deepEqual(ids(store.listSettledFor("0xAb")), ["x402_r12_bare", "x402_r12_case", "x402_r12_qualified"], name);
        assert.deepEqual(ids(store.listSettledFor("0xabc")), ["x402_r12_prefix"], name);
      }
    } finally {
      db.close();
    }
  });
});
