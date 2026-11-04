/**
 * Regression tests for the round-8 monitor group: the entitlement pass under
 * a locked database (M-A) and without needless write locks, delivery results
 * that cannot revive a cancelled delivery (M-C), the anonymous-watch index
 * (v10), checkout keys for a deleted or otherwise ended subscription, the
 * success page for an ended subscription, and bulk finalization committing
 * its refund.
 */

import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { after, before, describe, it } from "node:test";
import express, { type RequestHandler } from "express";
import { registerKeySignupRoutes, type KeySignupOptions } from "../src/billing/keySignup.js";
import { StripeApi, StripeApiError } from "../src/billing/stripeApi.js";
import { DEFAULT_PLAN_LIMITS, DEFAULT_WATCH_LIMITS, loadConfig } from "../src/config.js";
import type { WebhookDelivery, WebhookSender } from "../src/lib/webhook.js";
import { logger, setLogLevel } from "../src/logger.js";
import type { Principal } from "../src/middleware/auth.js";
import { RateLimiter } from "../src/middleware/rateLimit.js";
import { UsageTracker } from "../src/middleware/usage.js";
import { CreditLedger } from "../src/store/credits.js";
import { MIGRATIONS, migrate, openDatabase, type Database } from "../src/store/db.js";
import { BulkJobs } from "../src/store/jobs.js";
import { KeyRepository } from "../src/store/keyStore.js";
import { Monitor, type MonitorDeps, type MonitorOptions } from "../src/store/monitor.js";

setLogLevel("silent");

const HOUR = 3_600_000;
const payer: Principal = { id: "pay_round8", plan: "payg", label: "r8", source: "session" };
const okSender: WebhookSender = async () => ({ ok: true, status: 200, error: null });
const ALERT_COLUMNS = "watch_id, principal_id, domain, kind, change, subject, old_value, new_value, severity, at, created_at, delivery_status, next_delivery_at";
const RECONCILE_DEFERRED = "watch entitlements could not be reconciled this round; the rest wait for the next round";
const RESUME_DEFERRED = "paused watches could not be resumed this round; the rest wait for the next round";

function options(overrides: Partial<MonitorOptions> = {}): MonitorOptions {
  return {
    intervalMs: 24 * HOUR,
    retryMs: HOUR,
    creditsPerCheck: 1,
    concurrency: 1,
    checkTimeoutMs: 2000,
    tickMs: 60_000,
    maxWatches: { ...DEFAULT_WATCH_LIMITS },
    webhook: { allowInsecure: false, allowPrivate: false },
    deliveryBackoffMs: [60_000],
    alertRetentionDays: 90,
    ...overrides
  };
}

function monitorOn(db: Database, clock: { now: number }, deps: Partial<Omit<MonitorDeps, "db" | "clock">> = {}): Monitor {
  return new Monitor({
    db,
    clock: () => clock.now,
    usage: new UsageTracker(null),
    runner: async () => undefined,
    sender: okSender,
    options: options(),
    ...deps
  });
}

async function withTempDir<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(path.join(tmpdir(), "sdm-r8-monitor-"));
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  }
}

/** Records logger.warn messages until restore() is called. */
function captureWarnings(): { messages: string[]; restore: () => void } {
  const original = logger.warn;
  const messages: string[] = [];
  logger.warn = (msg: string) => {
    messages.push(msg);
  };
  return {
    messages,
    restore: () => {
      logger.warn = original;
    }
  };
}

function pausedReason(db: Database, domain: string): string | null {
  return (db.prepare("SELECT paused_reason FROM watches WHERE domain = ?").get(domain) as { paused_reason: string | null }).paused_reason;
}

function reconcile(monitor: Monitor, now: number): void {
  (monitor as unknown as { reconcileEntitlements(now: number): void }).reconcileEntitlements(now);
}

function rollback(db: Database): void {
  try {
    db.exec("ROLLBACK");
  } catch {
    // not in a transaction, or already closed
  }
}

describe("M-A: the entitlement pass under a locked database", () => {
  it("a write lock held by another connection defers the entitlement pass and the resumes to the next round instead of failing it", async () => {
    await withTempDir(async (dir) => {
      const file = path.join(dir, "busy.db");
      const db = await openDatabase(file);
      const holder = await openDatabase(file);
      assert.ok(db && holder);
      const warnings = captureWarnings();
      let release: NodeJS.Timeout | undefined;
      try {
        db.exec("PRAGMA busy_timeout = 20;");
        const keys = new KeyRepository(db);
        const lapsed = keys.issueForCheckout({ checkoutSession: "cs_r8_lapsed", plan: "pro", label: "l", stripeCustomer: "cus_r8l", stripeSubscription: "sub_r8_lapsed" }, 1);
        assert.ok(lapsed);
        keys.applySubscriptionEvent({ id: "evt_r8_lapsed", type: "customer.subscription.updated", created: 10 }, { id: "sub_r8_lapsed", status: "past_due", plan: null }, 10);
        const lapsedP: Principal = { id: lapsed.record.id, plan: "pro", label: "l", source: "api-key" };
        const configured: Principal = { id: "acct_r8_configured", plan: "pro", label: "c", source: "api-key" };

        const clock = { now: 5_000_000 };
        const usage = new UsageTracker(null);
        usage.addCredits(payer.id, payer.plan, payer.label, 5);
        const runs: string[] = [];
        let lockTaken = false;
        const monitor = monitorOn(db, clock, {
          usage,
          runner: async (check, domain) => {
            runs.push(`${check}:${domain}`);
          },
          entitlement: (principalId) => {
            if (!lockTaken) {
              // Another process takes the write lock as the pass begins. It is
              // released only once the round yields to the event loop (the
              // first claim's retry), so every write of the pass meets it.
              lockTaken = true;
              holder.exec("BEGIN IMMEDIATE");
              release = setTimeout(() => rollback(holder), 50);
            }
            return keys.currentPlan(principalId);
          },
          terminated: (principalId) => keys.isTerminated(principalId)
        });
        monitor.watch(lapsedP, "lapsed8.com", ["tech"], null, false);
        monitor.watch(configured, "configured8.com", ["tech"], null, false);
        monitor.watch(payer, "credits8.com", ["tech"], null, false);
        // Only the configured key's domain is due; the payer's watch waits paused for credits it now has.
        db.prepare("UPDATE monitor_schedule SET next_at = ? WHERE domain IN ('lapsed8.com', 'credits8.com')").run(clock.now + 12 * HOUR);
        db.prepare("UPDATE watches SET paused_reason = 'insufficient_credits' WHERE domain = 'credits8.com'").run();

        await monitor.tick(clock.now); // rejected with "database is locked" before the guard
        assert.ok(lockTaken);
        assert.ok(warnings.messages.includes(RECONCILE_DEFERRED), warnings.messages.join(" | "));
        assert.ok(warnings.messages.includes(RESUME_DEFERRED), warnings.messages.join(" | "));
        assert.deepEqual(runs, ["tech:configured8.com"], "the round's due checks still ran once the lock was gone");
        assert.equal(pausedReason(db, "lapsed8.com"), null, "the lapsed account keeps its state until the next round");
        assert.equal(pausedReason(db, "credits8.com"), "insufficient_credits", "and so does the funded payer");

        warnings.messages.length = 0;
        clock.now += 60_000;
        await monitor.tick(clock.now);
        assert.deepEqual(warnings.messages, []);
        assert.equal(pausedReason(db, "lapsed8.com"), "plan_inactive", "the next round applies the entitlement");
        assert.equal(pausedReason(db, "credits8.com"), null, "and the resume");
        assert.deepEqual(runs, ["tech:configured8.com", "tech:credits8.com"]);
        await monitor.stop();
      } finally {
        clearTimeout(release);
        warnings.restore();
        rollback(holder);
        db.close();
        holder.close();
      }
    });
  });

  it("a round whose entitlements need no change takes no write lock, and one that needs a change only defers it", async () => {
    await withTempDir(async (dir) => {
      const file = path.join(dir, "steady.db");
      const db = await openDatabase(file);
      const holder = await openDatabase(file);
      assert.ok(db && holder);
      let warnings: ReturnType<typeof captureWarnings> | null = null;
      try {
        const keys = new KeyRepository(db);
        const issue = (name: string, plan: "pro" | "enterprise"): Principal => {
          const issued = keys.issueForCheckout({ checkoutSession: `cs_r8_${name}`, plan, label: name, stripeCustomer: `cus_r8_${name}`, stripeSubscription: `sub_r8_${name}` }, 1);
          assert.ok(issued);
          return { id: issued.record.id, plan, label: name, source: "api-key" };
        };
        const lapsed = issue("steady_lapsed", "pro");
        const within = issue("steady_within", "pro");
        const over = issue("steady_over", "enterprise");
        const clock = { now: 5_000_000 };
        const monitor = monitorOn(db, clock, {
          options: options({ concurrency: 4, maxWatches: { ...DEFAULT_WATCH_LIMITS, pro: 2 } }),
          entitlement: (principalId) => keys.currentPlan(principalId),
          terminated: (principalId) => keys.isTerminated(principalId)
        });
        // One millisecond apart: the plan limit keeps the oldest watches, and equal times would fall back to random ids.
        const watch = (owner: Principal, domain: string): void => {
          clock.now += 1;
          monitor.watch(owner, domain, ["tech"], null, false);
        };
        watch(lapsed, "steady-lapsed.com");
        for (let i = 0; i < 2; i++) watch(within, `steady-within-${i}.com`);
        for (let i = 0; i < 3; i++) watch(over, `steady-over-${i}.com`);
        keys.applySubscriptionEvent({ id: "evt_r8_steady_lapsed", type: "customer.subscription.updated", created: 10 }, { id: "sub_r8_steady_lapsed", status: "past_due", plan: null }, 10);
        // A downgrade from enterprise to pro: the newest of its three watches goes over the limit.
        keys.applySubscriptionEvent({ id: "evt_r8_steady_over", type: "customer.subscription.updated", created: 10 }, { id: "sub_r8_steady_over", status: "active", plan: "pro" }, 10);

        await monitor.tick(clock.now);
        clock.now += 60_000;
        await monitor.tick(clock.now);
        assert.equal(pausedReason(db, "steady-lapsed.com"), "plan_inactive");
        assert.deepEqual(
          [0, 1, 2].map((i) => pausedReason(db, `steady-over-${i}.com`)),
          [null, null, "over_plan_limit"]
        );
        assert.equal(Number((db.prepare("SELECT COUNT(*) AS n FROM watches WHERE principal_id = ? AND principal_plan = 'pro'").get(over.id) as { n: number }).n), 3, "re-planned");

        // Steady state: another connection holds the write lock and this one
        // does not wait for it at all, so any write attempt would fail at once.
        holder.exec("BEGIN IMMEDIATE");
        db.exec("PRAGMA busy_timeout = 0;");
        warnings = captureWarnings();
        assert.doesNotThrow(() => reconcile(monitor, clock.now));
        assert.deepEqual(warnings.messages, [], "nothing changed, so no write was attempted");

        // The probe does see a write attempt: a change that is needed meets the lock and waits for a later round.
        rollback(holder);
        keys.applySubscriptionEvent({ id: "evt_r8_steady_within", type: "customer.subscription.updated", created: 20 }, { id: "sub_r8_steady_within", status: "past_due", plan: null }, 20);
        holder.exec("BEGIN IMMEDIATE");
        assert.doesNotThrow(() => reconcile(monitor, clock.now));
        assert.deepEqual(warnings.messages, [RECONCILE_DEFERRED]);
        assert.deepEqual(
          [0, 1].map((i) => pausedReason(db, `steady-within-${i}.com`)),
          [null, null]
        );
        rollback(holder);
        reconcile(monitor, clock.now);
        assert.deepEqual(
          [0, 1].map((i) => pausedReason(db, `steady-within-${i}.com`)),
          ["plan_inactive", "plan_inactive"]
        );
        await monitor.stop();
      } finally {
        warnings?.restore();
        rollback(holder);
        db.close();
        holder.close();
      }
    });
  });
});

describe("M-C: a delivery result applies only to an alert still pending", () => {
  for (const outcome of [
    { name: "a failed", result: { ok: false, status: 503, error: "HTTP 503" } satisfies WebhookDelivery },
    { name: "a successful", result: { ok: true, status: 204, error: null } satisfies WebhookDelivery }
  ]) {
    it(`${outcome.name} POST does not bring back a delivery cancelled while it was in flight`, async () => {
      const db = await openDatabase(":memory:");
      assert.ok(db);
      const principal: Principal = { id: "acct_r8_hook", plan: "pro", label: "h", source: "api-key" };
      const clock = { now: 10_000_000 };
      let sends = 0;
      const monitor = monitorOn(db, clock, {
        sender: async () => {
          sends++;
          // Meanwhile a round ends the account and drops its pending
          // deliveries (the statement the terminated-account pass runs).
          db.prepare("UPDATE alerts SET delivery_status = 'none', next_delivery_at = NULL WHERE principal_id = ? AND delivery_status = 'pending'").run(principal.id);
          return outcome.result;
        }
      });
      const watch = monitor.watch(principal, "inflight8.com", ["tech"], "https://hooks.example.com/r8", false).watch;
      db.prepare(`INSERT INTO alerts (${ALERT_COLUMNS}) VALUES (?, ?, 'inflight8.com', 'tech', 'tech_added', 'x', NULL, 'x', 'medium', ?, ?, 'pending', ?)`).run(
        watch.id,
        principal.id,
        clock.now,
        clock.now,
        clock.now
      );
      await monitor.deliver();
      assert.equal(sends, 1);
      const row = db.prepare("SELECT delivery_status, delivery_attempts, next_delivery_at, last_delivery_error FROM alerts WHERE watch_id = ?").get(watch.id);
      assert.deepEqual({ ...row }, { delivery_status: "none", delivery_attempts: 0, next_delivery_at: null, last_delivery_error: null }, "the cancellation stands");
      clock.now += 10 * 60_000;
      await monitor.deliver();
      assert.equal(sends, 1, "and the alert is never posted again");
      db.close();
    });
  }
});

describe("v10: anonymous watches are indexed for the per-round sweep", () => {
  const CHECK = "SELECT 1 FROM watches WHERE principal_source = 'anonymous' LIMIT 1";
  const CHUNK = "DELETE FROM watches WHERE id IN (SELECT id FROM watches WHERE principal_source = 'anonymous' LIMIT ?)";

  it("the sweep's existence check and its chunked DELETE use watches_anonymous instead of scanning every watch", async () => {
    const db = await openDatabase(":memory:");
    assert.ok(db);
    const latest = Math.max(...MIGRATIONS.map((m) => m.version));
    assert.equal((db.prepare("SELECT value FROM meta WHERE key = 'schema_version'").get() as { value: string }).value, String(latest));
    for (const [sql, params] of [
      [CHECK, []],
      [CHUNK, [200]]
    ] as Array<[string, number[]]>) {
      const details = (db.prepare(`EXPLAIN QUERY PLAN ${sql}`).all(...params) as Array<{ detail: string }>).map((r) => r.detail);
      assert.ok(
        details.some((d) => /\bUSING (COVERING )?INDEX watches_anonymous\b/.test(d)),
        `${sql}: ${details.join(" | ")}`
      );
      assert.ok(!details.some((d) => d === "SCAN watches"), `${sql}: ${details.join(" | ")}`);
    }
    db.close();
  });

  it("a database at v9 gains the index when it is opened", async () => {
    await withTempDir(async (dir) => {
      const file = path.join(dir, "v9.db");
      const raw = new DatabaseSync(file);
      try {
        assert.equal(
          migrate(
            raw,
            MIGRATIONS.filter((m) => m.version <= 9)
          ),
          9
        );
        assert.equal(raw.prepare("SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = 'watches_anonymous'").get(), undefined);
      } finally {
        raw.close();
      }
      const db = await openDatabase(file);
      assert.ok(db);
      try {
        assert.ok(db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = 'watches_anonymous'").get());
        // Derived, not "10": a later migration must not break a test about v10's index.
        const latest = Math.max(...MIGRATIONS.map((m) => m.version));
        assert.ok(latest >= 10);
        assert.equal((db.prepare("SELECT value FROM meta WHERE key = 'schema_version'").get() as { value: string }).value, String(latest));
      } finally {
        db.close();
      }
    });
  });
});

describe("checkout keys for a subscription deleted before the key was stored", () => {
  async function repo(): Promise<{ db: Database; keys: KeyRepository }> {
    const db = await openDatabase(":memory:");
    assert.ok(db);
    return { db, keys: new KeyRepository(db) };
  }

  for (const pending of [false, true]) {
    it(`stores the key dead for good (pending: ${pending}), so the account is terminated and nothing can turn it on`, async () => {
      const { db, keys } = await repo();
      keys.applySubscriptionEvent({ id: "evt_r8_del", type: "customer.subscription.deleted", created: 100 }, { id: "sub_r8_del", status: "canceled", plan: null }, 100);
      const issued = keys.issueForCheckout({ checkoutSession: "cs_r8_deleted", plan: "pro", label: "d", stripeCustomer: "cus_r8d", stripeSubscription: "sub_r8_del", pending }, 200);
      assert.ok(issued);
      assert.equal(issued.subscriptionEnded, true);
      assert.equal(issued.record.active, false);
      assert.equal(keys.currentPlan(issued.record.id), null);
      assert.equal(keys.isTerminated(issued.record.id), true, "so the monitor retires its watches");
      assert.equal(
        (db.prepare("SELECT deactivated_reason FROM api_keys WHERE checkout_session = 'cs_r8_deleted'").get() as { deactivated_reason: string }).deactivated_reason,
        "subscription_deleted",
        "the label a deletion gives every key of the subscription"
      );
      assert.equal(keys.activatePendingCheckout("cs_r8_deleted"), false);
      assert.equal(keys.applySubscriptionEvent({ id: "evt_r8_late", type: "customer.subscription.updated", created: 300 }, { id: "sub_r8_del", status: "active", plan: null }, 300), "terminal");
      assert.equal(keys.currentPlan(issued.record.id), null, "a later webhook cannot revive it");
      db.close();
    });
  }

  for (const status of ["incomplete_expired", "canceled"]) {
    for (const pending of [false, true]) {
      it(`flags a key stored after a webhook recorded '${status}', a status Stripe never leaves (pending: ${pending})`, async () => {
        const { db, keys } = await repo();
        keys.applySubscriptionEvent({ id: "evt_r8_ended", type: "customer.subscription.updated", created: 100 }, { id: "sub_r8_ended", status, plan: null }, 100);
        const issued = keys.issueForCheckout({ checkoutSession: "cs_r8_ended", plan: "pro", label: "e", stripeCustomer: "cus_r8e", stripeSubscription: "sub_r8_ended", pending }, 200);
        assert.ok(issued);
        assert.equal(issued.subscriptionEnded, true, "so the success page does not show it as a key that will start working");
        assert.equal(issued.record.active, false);
        assert.equal(
          (db.prepare("SELECT deactivated_reason FROM api_keys WHERE checkout_session = 'cs_r8_ended'").get() as { deactivated_reason: string }).deactivated_reason,
          `subscription_${status}`,
          "it keeps the label the webhook gives the subscription's other keys"
        );
        assert.equal(keys.activatePendingCheckout("cs_r8_ended"), false, "a confirmed payment cannot turn it on");
        db.close();
      });
    }
  }

  it("a key stored while the subscription is only suspended is not flagged: it can still recover", async () => {
    const { db, keys } = await repo();
    keys.applySubscriptionEvent({ id: "evt_r8_due", type: "customer.subscription.updated", created: 100 }, { id: "sub_r8_due", status: "past_due", plan: null }, 100);
    const issued = keys.issueForCheckout({ checkoutSession: "cs_r8_due", plan: "pro", label: "p", stripeCustomer: "cus_r8p", stripeSubscription: "sub_r8_due" }, 200);
    assert.ok(issued);
    assert.equal(issued.subscriptionEnded, false);
    assert.equal(issued.record.active, false);
    db.close();
  });

  it("a live subscription's key is not flagged", async () => {
    const { db, keys } = await repo();
    const issued = keys.issueForCheckout({ checkoutSession: "cs_r8_live", plan: "pro", label: "v", stripeCustomer: "cus_r8v", stripeSubscription: "sub_r8_live" }, 1);
    assert.ok(issued);
    assert.equal(issued.subscriptionEnded, false);
    assert.equal(issued.record.active, true);
    db.close();
  });
});

/** A Stripe client that answers checkout lookups from memory and makes no requests. */
class FakeStripe extends StripeApi {
  readonly sessions = new Map<string, Record<string, unknown>>();
  /** Runs once while the lookup of that session is in flight, after Stripe built its answer. */
  readonly duringLookup = new Map<string, () => void>();

  constructor() {
    super("sk_test_r8", "http://127.0.0.1:9");
  }

  override async request(): Promise<Record<string, unknown>> {
    throw new Error("the fake Stripe client makes no requests");
  }

  override async getCheckoutSession(id: string): Promise<Record<string, unknown>> {
    const session = this.sessions.get(id);
    if (!session) throw new StripeApiError("No such checkout.session", 404, null);
    const hook = this.duringLookup.get(id);
    this.duringLookup.delete(id);
    hook?.();
    return session;
  }
}

type SubscriptionEvent = { type: string; status: string };

/** A repository whose status read is followed at once by another process applying a subscription event. */
class RacyKeys extends KeyRepository {
  readonly afterRead = new Map<string, SubscriptionEvent>();

  override subscriptionStatus(subscriptionId: string): string | null {
    const status = super.subscriptionStatus(subscriptionId);
    const event = this.afterRead.get(subscriptionId);
    if (event) {
      this.afterRead.delete(subscriptionId);
      this.applySubscriptionEvent({ id: `evt_race_${subscriptionId}`, type: event.type, created: 100 }, { id: subscriptionId, status: event.status, plan: null });
    }
    return status;
  }
}

describe("the success page for a subscription that has ended", () => {
  let server: http.Server;
  let base = "";
  let db: Database;
  let keys: RacyKeys;
  const stripe = new FakeStripe();

  before(async () => {
    const opened = await openDatabase(":memory:");
    assert.ok(opened);
    db = opened;
    keys = new RacyKeys(db);
    const app = express();
    const options: KeySignupOptions = { publicUrl: "http://127.0.0.1", prices: { pro: "price_r8_pro" }, webhookSecret: null, planLimits: loadConfig({}, []).auth.planLimits };
    const auth: RequestHandler = (_req, res) => {
      res.status(401).end();
    };
    registerKeySignupRoutes(app, { stripe, keys, options, throttle: () => false }, auth);
    server = app.listen(0, "127.0.0.1");
    await new Promise<void>((resolve) => server.once("listening", resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  after(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    db.close();
  });

  const checkout = (id: string, subscription: Record<string, unknown>, overrides: Record<string, unknown> = {}): void => {
    stripe.sessions.set(id, {
      id,
      mode: "subscription",
      status: "complete",
      payment_status: "paid",
      customer: "cus_r8",
      subscription,
      metadata: { service: "stack-and-dns-mcp", kind: "api_key", plan: "pro" },
      ...overrides
    });
  };
  const keyRows = (session: string): number => Number((db.prepare("SELECT COUNT(*) AS n FROM api_keys WHERE checkout_session = ?").get(session) as { n: number }).n);

  it("answers 410, not 'reload once Stripe confirms the payment', when Stripe reports the subscription canceled or expired", async () => {
    checkout("cs_test_r8canceled", { id: "sub_r8_canceled", status: "canceled" });
    checkout("cs_test_r8expired1", { id: "sub_r8_expired", status: "incomplete_expired" }, { payment_status: "unpaid" });
    for (const session of ["cs_test_r8canceled", "cs_test_r8expired1"]) {
      const res = await fetch(`${base}/keys/success?session_id=${session}`);
      const html = await res.text();
      assert.equal(res.status, 410, `${session}: ${html}`);
      assert.match(html, /This subscription has ended/);
      assert.ok(!html.includes("sdm_live_"));
      assert.equal(keyRows(session), 0, "no key is issued");
    }
  });

  it("still answers 410 when a webhook recorded the deletion while Stripe's copy reads live", async () => {
    keys.applySubscriptionEvent({ id: "evt_r8_gone", type: "customer.subscription.deleted", created: 100 }, { id: "sub_r8_gone", status: "canceled", plan: null });
    checkout("cs_test_r8gone0001", { id: "sub_r8_gone", status: "active" });
    const res = await fetch(`${base}/keys/success?session_id=cs_test_r8gone0001`);
    assert.equal(res.status, 410);
    assert.equal(keyRows("cs_test_r8gone0001"), 0);
  });

  it("does not show a key minted into a subscription another process deleted just before the insert", async () => {
    checkout("cs_test_r8race0001", { id: "sub_r8_race", status: "active" });
    keys.afterRead.set("sub_r8_race", { type: "customer.subscription.deleted", status: "canceled" });
    const res = await fetch(`${base}/keys/success?session_id=cs_test_r8race0001`);
    const html = await res.text();
    assert.equal(res.status, 410, html);
    assert.ok(!html.includes("sdm_live_"), "the dead key is never shown");
    const row = db.prepare("SELECT account_id, active, deactivated_reason FROM api_keys WHERE checkout_session = 'cs_test_r8race0001'").get() as {
      account_id: string;
      active: number;
      deactivated_reason: string;
    };
    assert.equal(Number(row.active), 0);
    assert.equal(row.deactivated_reason, "subscription_deleted");
    assert.equal(keys.isTerminated(row.account_id), true);
    const reload = await fetch(`${base}/keys/success?session_id=cs_test_r8race0001`);
    assert.equal(reload.status, 410, "a reload says the same");
  });

  it("answers 410 when this process recorded the expiry while Stripe's answer, built before it, was in flight", async () => {
    // Stripe built this answer while the delayed payment was still pending; the
    // expiry webhook is handled by this same process during the await.
    checkout("cs_test_r8transit1", { id: "sub_r8_transit", status: "incomplete" }, { payment_status: "unpaid" });
    stripe.duringLookup.set("cs_test_r8transit1", () => {
      keys.applySubscriptionEvent({ id: "evt_r8_transit", type: "customer.subscription.updated", created: 100 }, { id: "sub_r8_transit", status: "incomplete_expired", plan: null });
    });
    const res = await fetch(`${base}/keys/success?session_id=cs_test_r8transit1`);
    const html = await res.text();
    assert.equal(res.status, 410, html);
    assert.ok(!html.includes("sdm_live_"), "no key is shown with a promise that it will start working");
    assert.equal(keyRows("cs_test_r8transit1"), 0, "and none is issued");
  });

  for (const [n, event] of [
    { type: "customer.subscription.updated", status: "incomplete_expired" },
    { type: "customer.subscription.updated", status: "canceled" }
  ].entries()) {
    it(`does not show a key minted into a subscription another process recorded '${event.status}' for just before the insert`, async () => {
      const session = `cs_test_r8ended00${n}`;
      const subscription = `sub_r8_ended_${n}`;
      // A delayed payment for the expiry, a paid one for the cancellation: either way Stripe's copy still reads as one that will work.
      if (event.status === "incomplete_expired") checkout(session, { id: subscription, status: "incomplete" }, { payment_status: "unpaid" });
      else checkout(session, { id: subscription, status: "active" });
      keys.afterRead.set(subscription, event);
      const res = await fetch(`${base}/keys/success?session_id=${session}`);
      const html = await res.text();
      assert.equal(res.status, 410, html);
      assert.ok(!html.includes("sdm_live_"), "the dead key is never shown");
      const row = db.prepare("SELECT active, deactivated_reason FROM api_keys WHERE checkout_session = ?").get(session) as { active: number; deactivated_reason: string };
      assert.deepEqual({ active: Number(row.active), reason: row.deactivated_reason }, { active: 0, reason: `subscription_${event.status}` });
      const reload = await fetch(`${base}/keys/success?session_id=${session}`);
      assert.equal(reload.status, 410, "a reload says the subscription ended, not that the key was already shown");
    });
  }
});

describe("bulk finalization commits the credit refund with it", () => {
  it("a failure inside finalization neither loses the refund nor applies it twice", async () => {
    const db = await openDatabase(":memory:");
    assert.ok(db);
    class CrashingUsage extends UsageTracker {
      crash = false;
      override addCredits(...args: Parameters<UsageTracker["addCredits"]>): ReturnType<UsageTracker["addCredits"]> {
        if (this.crash) throw new Error("process died mid-finalization");
        return super.addCredits(...args);
      }
    }
    const usage = new CrashingUsage(null);
    usage.attachLedger(new CreditLedger(db));
    usage.addCredits(payer.id, payer.plan, payer.label, 10);
    const limiter = new RateLimiter({ ...loadConfig({}, []).auth.planLimits, pro: { ...DEFAULT_PLAN_LIMITS.pro } });
    const make = (): BulkJobs =>
      new BulkJobs({
        db,
        usage,
        limiter,
        runner: async () => ({}),
        options: { creditsPerDomain: { email: 1, tech: 1, audit: 2 }, maxDomains: 50, concurrency: 1, itemTimeoutMs: 5000, maxActiveJobsPerPrincipal: 3, retentionDays: 30, pollMs: 60_000 }
      });
    const jobs = make();
    const { job } = jobs.submit(payer, "email", ["a.com", "b.com"], false);
    assert.equal(usage.creditsRemaining(payer.id), 8);
    db.prepare("UPDATE job_items SET status = 'failed', error_code = 'NETWORK_ERROR' WHERE job_id = ?").run(job.jobId);

    usage.crash = true;
    assert.throws(() => (jobs as unknown as { maybeFinalize(jobId: string): void }).maybeFinalize(job.jobId), /process died/);
    const row = (): { finalized_at: number | null; credits_refunded: number } =>
      db.prepare("SELECT finalized_at, credits_refunded FROM jobs WHERE id = ?").get(job.jobId) as { finalized_at: number | null; credits_refunded: number };
    assert.equal(row().finalized_at, null, "the finalization rolled back with the refund");
    assert.equal(usage.creditsRemaining(payer.id), 8);

    usage.crash = false;
    const successor = make();
    successor.start();
    await successor.whenIdle();
    assert.notEqual(row().finalized_at, null);
    assert.equal(Number(row().credits_refunded), 2);
    assert.equal(usage.creditsRemaining(payer.id), 10, "the refund was not lost");
    await successor.stop();
    successor.start();
    await successor.whenIdle();
    assert.equal(usage.creditsRemaining(payer.id), 10, "and is applied once");
    await successor.stop();
    db.close();
  });
});
