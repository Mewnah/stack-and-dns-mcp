import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { DEFAULT_PLAN_LIMITS, DEFAULT_WATCH_LIMITS, loadConfig } from "../src/config.js";
import { parseDomain } from "../src/lib/domain.js";
import { ToolError } from "../src/lib/errors.js";
import { isAllowed, parseRobots } from "../src/lib/robots.js";
import { validateWebhookUrl } from "../src/lib/webhook.js";
import { clientNetworkKey } from "../src/lib/net.js";
import { setLogLevel } from "../src/logger.js";
import type { Principal } from "../src/middleware/auth.js";
import { RateLimiter } from "../src/middleware/rateLimit.js";
import { UsageTracker } from "../src/middleware/usage.js";
import { CreditLedger } from "../src/store/credits.js";
import { openDatabase } from "../src/store/db.js";
import { BulkJobs } from "../src/store/jobs.js";
import { KeyRepository } from "../src/store/keyStore.js";
import { Monitor } from "../src/store/monitor.js";
import { ReverseLookup } from "../src/store/reverse.js";
import { ScanStore, type TechScanInput } from "../src/store/scanStore.js";

setLogLevel("silent");

const HOUR = 3600_000;

function tech(domain: string, ids: string[]): TechScanInput {
  return {
    domain,
    partial: false,
    fetch: { ok: true, status: 200, finalHost: domain, truncated: false, error: null },
    blocked: { blocked: false, vendor: null, challengeType: null, reason: null },
    technologies: ids.map((id) => ({ id, name: id, category: "ecommerce", version: null, implied: false })),
    security: { score: 70, grade: "C" }
  } as unknown as TechScanInput;
}

describe("input handling", () => {
  it("rejects a long run of dots in linear time", () => {
    const input = `x${".".repeat(2040)}0`;
    const started = performance.now();
    for (let i = 0; i < 200; i++) assert.equal(parseDomain(input).ok, false);
    assert.ok(performance.now() - started < 200, "200 hostile inputs parse in well under a second");
  });

  it("keys IPv6 clients by /64 and unwraps IPv4-mapped addresses", () => {
    assert.equal(clientNetworkKey("2001:db8:1:2:aaaa::1"), clientNetworkKey("2001:db8:1:2:ffff::9"));
    assert.notEqual(clientNetworkKey("2001:db8:1:2::1"), clientNetworkKey("2001:db8:1:3::1"));
    assert.equal(clientNetworkKey("::ffff:192.0.2.7"), "192.0.2.7");
    assert.equal(clientNetworkKey("192.0.2.7"), "192.0.2.7");
  });

  it("refuses webhook hosts that only resolve inside the deployment", () => {
    const policy = { allowInsecure: false, allowPrivate: false };
    for (const url of ["https://db/x", "https://kubernetes.default.svc/x", "https://printer.local/x", "https://api.internal/x", "https://localhost./x"]) {
      assert.throws(
        () => validateWebhookUrl(url, policy),
        (err: unknown) => err instanceof ToolError && err.code === "INVALID_ARGUMENT",
        url
      );
    }
    assert.equal(validateWebhookUrl("https://hooks.example.com/in", policy), "https://hooks.example.com/in");
  });

  it("honours robots.txt groups written with a version or a comment", () => {
    for (const text of ["User-agent: StackAndDnsBot/1.0\nDisallow: /", "User-agent: StackAndDnsBot 1.0\nDisallow: /", "User-agent: * (all bots)\nDisallow: /"]) {
      assert.equal(isAllowed(parseRobots(text), "stackanddnsbot", "/"), false, text);
    }
    assert.equal(isAllowed(parseRobots("User-agent: Crawler9000\nDisallow: /"), "crawler9000", "/"), false);
  });
});

describe("bulk hardening", () => {
  const pro: Principal = { id: "acct_p", plan: "pro", label: "p", source: "api-key" };

  async function jobsFor(perDay = 10, maxDomains = 50) {
    const db = await openDatabase(":memory:");
    assert.ok(db);
    const usage = new UsageTracker(null);
    usage.attachLedger(new CreditLedger(db));
    const limiter = new RateLimiter({ ...loadConfig({}, []).auth.planLimits, pro: { ...DEFAULT_PLAN_LIMITS.pro, perDay } });
    const jobs = new BulkJobs({
      db,
      usage,
      limiter,
      runner: async () => ({}),
      options: { creditsPerDomain: { email: 1, tech: 1, audit: 2 }, maxDomains, concurrency: 1, itemTimeoutMs: 1000, maxActiveJobsPerPrincipal: 3, retentionDays: 30, pollMs: 60_000 }
    });
    return { db, limiter, jobs };
  }

  it("refuses lists that are mostly junk and keeps stored inputs small", async () => {
    const { db, jobs } = await jobsFor(10, 200);
    const junk = Array.from({ length: 99 }, (_, i) => `not a domain ${i} ${"x".repeat(900)}`);
    assert.throws(() => jobs.submit(pro, "email", ["a.com", ...junk, ...junk.slice(0, 5)], false), /Too many invalid/);
    const { job } = jobs.submit(pro, "email", ["a.com", ...junk.slice(0, 50)], false);
    const longest = (db.prepare("SELECT MAX(LENGTH(input)) AS n FROM job_items WHERE job_id = ?").get(job.jobId) as { n: number }).n;
    assert.ok(longest <= 256);
  });

  it("finishes a cancelled job whose running item was requeued, and refunds it", async () => {
    const { db, limiter, jobs } = await jobsFor();
    const { job } = jobs.submit(pro, "email", ["a.com", "b.com"], false);
    db.prepare("UPDATE job_items SET status = 'running' WHERE job_id = ? AND idx = 0").run(job.jobId);
    jobs.cancel(pro, job.jobId);
    // A restart requeues the running item.
    jobs.start();
    await jobs.whenIdle();
    const view = jobs.get(pro, job.jobId);
    assert.equal(view.status, "cancelled");
    assert.ok(view.finishedAt, "finalized");
    assert.equal(view.quotaUnitsRefunded, 2);
    assert.equal(limiter.snapshot(pro.id, "pro").remainingToday, 10);
    await jobs.stop();
  });

  it("clamps paging values SQLite cannot take", async () => {
    const { jobs } = await jobsFor();
    const { job } = jobs.submit(pro, "email", ["a.com"], false);
    assert.equal(jobs.list(pro, 2.5).length, 1);
    assert.deepEqual(jobs.get(pro, job.jobId, { offset: 1e300 }).items, []);
  });

  it("refunds only the day units the job charged", () => {
    const limiter = new RateLimiter({ ...DEFAULT_PLAN_LIMITS, pro: { ...DEFAULT_PLAN_LIMITS.pro, perDay: 5 } });
    const chargedAt = Date.now();
    limiter.consumeDayUnits("k", "pro", 3, chargedAt);
    limiter.refundDayUnits("k", 3, chargedAt + 1);
    assert.equal(limiter.snapshot("k", "pro").remainingToday, 2, "units charged at another time are not removed");
    limiter.refundDayUnits("k", 3, chargedAt);
    assert.equal(limiter.snapshot("k", "pro").remainingToday, 5);
  });
});

describe("reverse lookup privacy", () => {
  it("never answers from customer, bulk or monitor scans, even for a seed-list domain", async () => {
    const db = await openDatabase(":memory:");
    assert.ok(db);
    const store = new ScanStore(db, { retentionDays: 365 });
    const reverse = new ReverseLookup(db);
    db.prepare("INSERT INTO crawl_targets (domain, added_at, next_at) VALUES ('optedout.com', 0, 0)").run();
    store.recordTech(tech("optedout.com", ["shopify"]), "call", 10);
    store.recordTech(tech("optedout.com", ["shopify"]), "monitor", 20);
    store.recordTech(tech("optedout.com", ["shopify"]), "bulk", 30);
    assert.equal(reverse.findDomains({ techId: "shopify" }).total, 0);
    assert.deepEqual(reverse.universe(), { domains: 1, scanned: 0 });
    store.recordTech(tech("optedout.com", ["shopify"]), "crawl", 40);
    const found = reverse.findDomains({ techId: "shopify" });
    assert.equal(found.total, 1);
    assert.equal(found.domains[0]?.lastSeen, new Date(40).toISOString(), "only the crawl's own timestamp");
  });
});

describe("monitor entitlements and fairness", () => {
  async function monitorWith(entitlement: (id: string) => "pro" | "free" | null | undefined, sender = async () => ({ ok: true, status: 200, error: null })) {
    const db = await openDatabase(":memory:");
    assert.ok(db);
    const clock = { now: 1_000_000 };
    const runs: string[] = [];
    const monitor = new Monitor({
      db,
      clock: () => clock.now,
      usage: new UsageTracker(null),
      runner: async (_check, domain) => {
        runs.push(domain);
      },
      sender,
      entitlement,
      options: {
        intervalMs: 24 * HOUR,
        retryMs: HOUR,
        creditsPerCheck: 1,
        concurrency: 2,
        checkTimeoutMs: 1000,
        tickMs: 60_000,
        maxWatches: { ...DEFAULT_WATCH_LIMITS, free: 1, pro: 3 },
        webhook: { allowInsecure: false, allowPrivate: false },
        deliveryBackoffMs: [60_000],
        alertRetentionDays: 90
      }
    });
    return { db, clock, runs, monitor };
  }

  it("pauses a lapsed account's watches and trims a downgraded one to its plan", async () => {
    let plan: "pro" | "free" | null = "pro";
    const h = await monitorWith(() => plan);
    const owner: Principal = { id: "acct_sub", plan: "pro", label: "s", source: "api-key" };
    for (const d of ["a.com", "b.com", "c.com"]) h.monitor.watch(owner, d, ["tech"], null, false);
    await h.monitor.tick(h.clock.now);
    assert.equal(h.runs.length, 3);
    plan = null;
    h.clock.now += 25 * HOUR;
    await h.monitor.tick(h.clock.now);
    assert.equal(h.runs.length, 3, "a cancelled subscription gets no more checks");
    assert.ok(h.monitor.list(owner).every((w) => w.pausedReason === "plan_inactive"));
    plan = "free";
    h.clock.now += 25 * HOUR;
    await h.monitor.tick(h.clock.now);
    const watches = h.monitor.list(owner);
    assert.deepEqual(
      watches.map((w) => w.pausedReason),
      [null, "over_plan_limit", "over_plan_limit"],
      "the oldest watch within the free limit resumes"
    );
  });

  it("an unwatch and re-watch cycle cannot force an early scan", async () => {
    const h = await monitorWith(() => undefined);
    const owner: Principal = { id: "acct_x", plan: "pro", label: "x", source: "api-key" };
    h.monitor.watch(owner, "cycle.com", ["tech"], null, false);
    await h.monitor.tick(h.clock.now);
    for (let i = 0; i < 3; i++) {
      h.monitor.unwatch(owner, { domain: "cycle.com" });
      h.monitor.watch(owner, "cycle.com", ["tech"], null, false);
      h.clock.now += 60_000;
      await h.monitor.tick(h.clock.now);
    }
    assert.equal(h.runs.length, 1);
  });

  it("webhook delivery runs beside scheduling, so a slow endpoint cannot hold up checks", async () => {
    let release: () => void = () => undefined;
    const stall = new Promise<void>((resolve) => {
      release = resolve;
    });
    const h = await monitorWith(
      () => undefined,
      async () => {
        await stall;
        return { ok: true, status: 200, error: null };
      }
    );
    const store = new ScanStore(h.db, { retentionDays: 30 });
    const owner: Principal = { id: "acct_w", plan: "pro", label: "w", source: "api-key" };
    h.monitor.watch(owner, "hook.com", ["tech"], "https://hooks.example.com/in", false);
    store.recordTech(tech("hook.com", ["a"]), "call", 1);
    store.recordTech(tech("hook.com", ["a", "b"]), "call", 2);
    await h.monitor.tick(h.clock.now);
    h.monitor.watch(owner, "other.com", ["tech"], null, false);
    h.clock.now += 1000;
    await h.monitor.tick(h.clock.now);
    assert.ok(h.runs.includes("other.com"), "the next round ran while the webhook was still stalled");
    release();
    await h.monitor.whenDelivered();
  });
});

describe("key issuance follows the subscription", () => {
  it("uses a plan a webhook already recorded, and issues a pending checkout inactive", async () => {
    const db = await openDatabase(":memory:");
    assert.ok(db);
    const keys = new KeyRepository(db);
    keys.applySubscriptionEvent({ id: "evt_1", type: "customer.subscription.updated", created: 10 }, { id: "sub_1", status: "active", plan: "pro" });
    const issued = keys.issueForCheckout({ checkoutSession: "cs_test_aaaaaaaa", plan: "enterprise", label: "x", stripeCustomer: null, stripeSubscription: "sub_1" });
    assert.equal(issued?.record.plan, "pro");
    const pending = keys.issueForCheckout({ checkoutSession: "cs_test_bbbbbbbb", plan: "pro", label: "y", stripeCustomer: null, stripeSubscription: "sub_2", pending: true });
    assert.equal(pending?.record.active, false);
    assert.equal(keys.currentPlan(pending?.record.id as string), null);
    assert.equal(keys.activatePendingCheckout("cs_test_bbbbbbbb"), true);
    assert.equal(keys.currentPlan(pending?.record.id as string), "pro");
    assert.equal(keys.currentPlan("not-an-account"), undefined);
  });
});
