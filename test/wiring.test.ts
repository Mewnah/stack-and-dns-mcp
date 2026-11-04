import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import type { RequestHandlerExtra } from "@modelcontextprotocol/sdk/shared/protocol.js";
import type { ServerNotification, ServerRequest } from "@modelcontextprotocol/sdk/types.js";
import { DEFAULT_PLAN_LIMITS, DEFAULT_WATCH_LIMITS, loadConfig } from "../src/config.js";
import { setLogLevel } from "../src/logger.js";
import { ApiKeyStore, type Principal } from "../src/middleware/auth.js";
import { createMeter } from "../src/middleware/metering.js";
import { RateLimiter } from "../src/middleware/rateLimit.js";
import { UsageTracker } from "../src/middleware/usage.js";
import { openDatabase } from "../src/store/db.js";
import { KeyRepository } from "../src/store/keyStore.js";
import { WorkerLease } from "../src/store/lease.js";
import { toolNames } from "../src/tools/index.js";
import { parseDomainList } from "../src/transports/jobsApi.js";

setLogLevel("silent");

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

describe("control calls", () => {
  it("a minute-only evaluation neither checks nor spends the daily quota", () => {
    const limiter = new RateLimiter({ ...DEFAULT_PLAN_LIMITS, free: { perMinute: 5, perDay: 1, maxConcurrent: 2 } });
    assert.equal(limiter.consume("p", "free").allowed, true);
    assert.equal(limiter.consume("p", "free").scope, "day", "the day is spent");
    const control = limiter.consume("p", "free", { countDay: false });
    assert.equal(control.allowed, true, "a control call still works after the day is spent");
    assert.equal(limiter.snapshot("p", "free").remainingThisMinute, 3);
    for (let i = 0; i < 3; i++) limiter.consume("p", "free", { countDay: false });
    assert.equal(limiter.consume("p", "free", { countDay: false }).scope, "minute", "control calls are still rate limited per minute");
  });

  it("zero-cost tools are free for prepaid callers with no balance and leave the day untouched", async () => {
    const config = loadConfig({ STACKDNS_TRANSPORT: "stdio" }, []);
    const usage = new UsageTracker(null);
    const limiter = new RateLimiter(config.auth.planLimits);
    const payg: Principal = { id: "pay_zero", plan: "payg", label: "test", source: "session" };
    const meter = createMeter({ config, usage, limiter, localPrincipal: payg });
    const poll = meter("get_bulk_check", async () => ({ ok: true }));
    const result = await poll({}, fakeExtra());
    assert.equal(result.isError, undefined, JSON.stringify(result.content));
    assert.equal((result.structuredContent as { billing: { creditsCharged: number } }).billing.creditsCharged, 0);
    const paid = await meter("inspect_tech_stack", async () => ({ ok: true }))({}, fakeExtra());
    assert.equal(paid.isError, true, "a paid tool still needs credits");
    assert.equal(limiter.snapshot("pay_zero", "payg").remainingToday, config.auth.planLimits.payg.perDay);
  });
});

describe("worker lease", () => {
  it("admits one holder, renews it, and hands over on expiry or release", async () => {
    const db = await openDatabase(":memory:");
    assert.ok(db);
    const a = new WorkerLease(db, "workers", 1000, "a");
    const b = new WorkerLease(db, "workers", 1000, "b");
    assert.equal(a.tryAcquire(0), true);
    assert.equal(b.tryAcquire(10), false, "held by a");
    assert.equal(a.tryAcquire(900), true, "a renews");
    assert.equal(b.tryAcquire(1500), false, "the renewal moved the expiry");
    assert.equal(b.tryAcquire(1901), true, "b takes over after expiry");
    assert.equal(a.tryAcquire(1902), false);
    b.release();
    assert.equal(a.tryAcquire(1903), true, "a released lease is free at once");
    b.release();
    assert.equal(b.tryAcquire(1904), false, "releasing a lease you do not hold is a no-op");
  });

  it("works across connections to one file", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "sdm-lease-"));
    try {
      const file = path.join(dir, "lease.db");
      const one = await openDatabase(file);
      const two = await openDatabase(file);
      assert.ok(one && two);
      assert.equal(new WorkerLease(one, "workers", 60000, "one").tryAcquire(), true);
      assert.equal(new WorkerLease(two, "workers", 60000, "two").tryAcquire(), false);
      one.close();
      two.close();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("database-backed API keys", () => {
  it("authenticate through the configured key store, and rotation revokes the old key", async () => {
    const db = await openDatabase(":memory:");
    assert.ok(db);
    const repo = new KeyRepository(db);
    const store = new ApiKeyStore();
    assert.equal(store.hasKeys, false);
    store.attachRepository(repo);
    assert.equal(store.hasKeys, false, "an empty key table is not a key");
    const issued = repo.issueForCheckout({ checkoutSession: "cs_test_12345678", plan: "pro", label: "Acme", stripeCustomer: "cus_1", stripeSubscription: "sub_1" });
    assert.ok(issued);
    assert.equal(store.hasKeys, true);
    const record = store.verify(issued.apiKey);
    assert.equal(record?.plan, "pro");
    assert.equal(record?.id, issued.record.id, "the principal id is the stable account id");
    const rotated = repo.rotate(issued.record.id);
    assert.ok(rotated);
    assert.equal(store.verify(issued.apiKey), null, "the old key stops working");
    assert.equal(store.verify(rotated.apiKey)?.id, issued.record.id, "the new key keeps the account");
  });

  it("configured keys take precedence and are checked without the database", () => {
    const store = new ApiKeyStore();
    const [record] = ApiKeyStore.parseInline("sdm_live_inline_key_0123456789:enterprise:ops");
    assert.ok(record);
    store.add(record);
    store.attachRepository({
      findActiveByHash: () => {
        throw new Error("database should not be consulted");
      },
      countActive: () => 0
    });
    assert.equal(store.verify("sdm_live_inline_key_0123456789")?.plan, "enterprise");
  });
});

describe("REST domain lists", () => {
  it("takes the first column, strips quotes, skips comments and a header row", () => {
    const csv = ["Website,Company", "example.com,Example", '"iana.org",IANA', "# a comment", "", "a.io;x", "b.io\tx", "domain"].join("\r\n");
    assert.deepEqual(parseDomainList(csv), ["example.com", "iana.org", "a.io", "b.io", "domain"], "only the first line can be a header");
  });
});

describe("feature-dependent surface", () => {
  it("lists only the tools a server registers", () => {
    assert.deepEqual(toolNames({ history: false, bulk: false, monitor: false, reverse: false }), ["inspect_tech_stack", "verify_email_infrastructure", "comprehensive_audit"]);
    const all = toolNames({ history: true, bulk: true, monitor: true, reverse: true });
    assert.equal(all.length, 14);
    assert.ok(all.includes("start_bulk_check") && all.includes("get_alerts") && all.includes("find_domains_using"));
  });

  it("parses monitoring and self-serve settings", () => {
    const config = loadConfig(
      {
        STACKDNS_MONITOR_INTERVAL_HOURS: "6",
        STACKDNS_MONITOR_WATCH_LIMITS_JSON: '{"free":0,"pro":250}',
        STRIPE_PRICE_PRO: "price_ABC123",
        STRIPE_WEBHOOK_SECRET: "whsec_test123",
        STACKDNS_BULK_ENABLED: "off"
      },
      []
    );
    assert.equal(config.monitor.intervalMs, 6 * 60 * 60 * 1000);
    assert.deepEqual(config.monitor.maxWatches, { ...DEFAULT_WATCH_LIMITS, free: 0, pro: 250 });
    assert.deepEqual(config.selfServe.prices, { pro: "price_ABC123" });
    assert.equal(config.selfServe.webhookSecret, "whsec_test123");
    assert.equal(config.bulk.enabled, false);
    assert.throws(() => loadConfig({ STRIPE_PRICE_PRO: "prod_123" }, []), /Stripe Price id/);
    assert.throws(() => loadConfig({ STACKDNS_MONITOR_WATCH_LIMITS_JSON: '{"gold":5}' }, []), /WATCH_LIMITS_JSON is invalid/);
  });
});
