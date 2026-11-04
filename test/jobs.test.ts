import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { DEFAULT_PLAN_LIMITS, loadConfig } from "../src/config.js";
import { ToolError } from "../src/lib/errors.js";
import { setLogLevel } from "../src/logger.js";
import type { Principal } from "../src/middleware/auth.js";
import { RateLimiter } from "../src/middleware/rateLimit.js";
import { UsageTracker } from "../src/middleware/usage.js";
import { openDatabase } from "../src/store/db.js";
import { BulkJobs, csvCell, normalizeBulkInputs, type BulkCheckRunner, type BulkJobsOptions } from "../src/store/jobs.js";

setLogLevel("silent");

const payg: Principal = { id: "pay_1", plan: "payg", label: "stripe:pi_1", source: "session" };
const pro: Principal = { id: "key_pro", plan: "pro", label: "Acme", source: "api-key" };

const OPTIONS: BulkJobsOptions = {
  creditsPerDomain: { email: 1, tech: 1, audit: 2 },
  maxDomains: 50,
  concurrency: 2,
  itemTimeoutMs: 2000,
  maxActiveJobsPerPrincipal: 3,
  retentionDays: 30
};

async function setup(runner: BulkCheckRunner, options: Partial<BulkJobsOptions> = {}) {
  const db = await openDatabase(":memory:");
  assert.ok(db);
  const usage = new UsageTracker(null);
  const config = loadConfig({}, []);
  const limiter = new RateLimiter({ ...config.auth.planLimits, pro: { ...DEFAULT_PLAN_LIMITS.pro, perDay: 10 } });
  const jobs = new BulkJobs({ db, usage, limiter, runner, options: { ...OPTIONS, ...options } });
  return { db, usage, limiter, jobs };
}

const okRunner: BulkCheckRunner = async (check, domain) => ({ domain, check, score: domain.length });

describe("normalizeBulkInputs", () => {
  it("skips invalid, private and duplicate inputs and keeps the first of each site", () => {
    const result = normalizeBulkInputs(["example.com", "https://www.example.com/pricing", "not a domain", "10.0.0.1", "jane@acme.io", "ACME.io", "foo.localhost"], false);
    assert.deepEqual(
      result.accepted.map((a) => [a.index, a.domain]),
      [
        [0, "example.com"],
        [4, "acme.io"]
      ]
    );
    assert.deepEqual(
      result.skipped.map((s) => [s.index, s.code]),
      [
        [1, "DUPLICATE"],
        [2, "INVALID_DOMAIN"],
        [3, "INVALID_DOMAIN"],
        [5, "DUPLICATE"],
        [6, "PRIVATE_TARGET"]
      ]
    );
  });
});

describe("BulkJobs billing", () => {
  it("charges prepaid credits per accepted domain and never for skipped inputs", async () => {
    const { usage, jobs } = await setup(okRunner);
    usage.addCredits(payg.id, "payg", payg.label, 10);
    const { job, skipped } = jobs.submit(payg, "audit", ["a.com", "b.com", "a.com", "bad input"], false);
    assert.equal(job.accepted, 2);
    assert.equal(skipped.length, 2);
    assert.equal(job.creditsCharged, 4, "audit costs 2 per domain");
    assert.equal(usage.creditsRemaining(payg.id), 6);
  });

  it("refuses a job the balance cannot cover without charging anything", async () => {
    const { usage, jobs, db } = await setup(okRunner);
    usage.addCredits(payg.id, "payg", payg.label, 1);
    assert.throws(
      () => jobs.submit(payg, "email", ["a.com", "b.com"], false),
      (err: unknown) => err instanceof ToolError && err.code === "INSUFFICIENT_CREDITS"
    );
    assert.equal(usage.creditsRemaining(payg.id), 1);
    assert.equal(Number((db.prepare("SELECT COUNT(*) AS n FROM jobs").get() as { n: number }).n), 0);
  });

  it("spends one unit of a plan's daily quota per domain, all or nothing", async () => {
    const { limiter, jobs } = await setup(okRunner);
    jobs.submit(pro, "email", ["a.com", "b.com", "c.com"], false);
    assert.equal(limiter.snapshot(pro.id, "pro").remainingToday, 7);
    assert.throws(
      () =>
        jobs.submit(
          pro,
          "email",
          Array.from({ length: 8 }, (_, i) => `d${i}.com`),
          false
        ),
      (err: unknown) => err instanceof ToolError && err.code === "RATE_LIMITED"
    );
    assert.equal(limiter.snapshot(pro.id, "pro").remainingToday, 7, "a refused job consumes nothing");
  });

  it("rejects empty, all-invalid and oversized submissions", async () => {
    const { jobs } = await setup(okRunner);
    assert.throws(
      () => jobs.submit(pro, "email", [], false),
      (err: unknown) => err instanceof ToolError && err.code === "INVALID_ARGUMENT"
    );
    assert.throws(
      () => jobs.submit(pro, "email", ["nope", "also nope"], false),
      (err: unknown) => err instanceof ToolError && err.code === "INVALID_ARGUMENT"
    );
    assert.throws(
      () =>
        jobs.submit(
          pro,
          "email",
          Array.from({ length: 51 }, (_, i) => `x${i}.com`),
          false
        ),
      (err: unknown) => err instanceof ToolError && err.code === "LIMIT_EXCEEDED"
    );
  });

  it("limits how many jobs one caller can have running", async () => {
    const block = new Promise<Record<string, unknown>>(() => undefined);
    const { usage, jobs } = await setup(() => block);
    usage.addCredits(payg.id, "payg", payg.label, 100);
    for (let i = 0; i < 3; i++) jobs.submit(payg, "email", [`j${i}.com`], false);
    assert.throws(
      () => jobs.submit(payg, "email", ["j9.com"], false),
      (err: unknown) => err instanceof ToolError && err.code === "LIMIT_EXCEEDED" && err.retryable
    );
  });
});

describe("BulkJobs processing", () => {
  it("runs every item, charges definitive answers and refunds retryable failures", async () => {
    const runner: BulkCheckRunner = async (_check, domain) => {
      if (domain === "gone.com") throw new ToolError("DOMAIN_NOT_FOUND", "NXDOMAIN");
      if (domain === "flaky.com") throw new ToolError("NETWORK_ERROR", "resolver down", { retryable: true });
      if (domain === "boom.com") throw new TypeError("bug");
      return { domain, score: 90 };
    };
    const { usage, jobs } = await setup(runner);
    usage.addCredits(payg.id, "payg", payg.label, 10);
    const { job } = jobs.submit(payg, "email", ["ok.com", "gone.com", "flaky.com", "boom.com"], false);
    assert.equal(usage.creditsRemaining(payg.id), 6);
    jobs.start();
    await jobs.whenIdle();
    const view = jobs.get(payg, job.jobId);
    assert.equal(view.status, "completed");
    assert.deepEqual(view.counts, { pending: 0, running: 0, done: 2, failed: 2, skipped: 0, cancelled: 0 });
    const byDomain = new Map(view.items.map((i) => [i.domain, i]));
    assert.equal(byDomain.get("ok.com")?.result?.score, 90);
    assert.equal(byDomain.get("gone.com")?.status, "done");
    assert.equal(byDomain.get("gone.com")?.error?.code, "DOMAIN_NOT_FOUND");
    assert.equal(byDomain.get("flaky.com")?.error?.code, "NETWORK_ERROR");
    assert.equal(byDomain.get("boom.com")?.error?.code, "INTERNAL_ERROR");
    assert.equal(view.creditsRefunded, 2);
    assert.equal(usage.creditsRemaining(payg.id), 8, "two failures refunded, two answers charged");
    assert.ok(view.finishedAt);
  });

  it("refunds a plan's daily quota for failed items", async () => {
    const runner: BulkCheckRunner = async (_c, domain) => {
      if (domain === "bad.com") throw new ToolError("TOOL_TIMEOUT", "slow", { retryable: true });
      return { domain };
    };
    const { limiter, jobs } = await setup(runner);
    const { job } = jobs.submit(pro, "tech", ["good.com", "bad.com"], false);
    assert.equal(limiter.snapshot(pro.id, "pro").remainingToday, 8);
    jobs.start();
    await jobs.whenIdle();
    assert.equal(jobs.get(pro, job.jobId).quotaUnitsRefunded, 1);
    assert.equal(limiter.snapshot(pro.id, "pro").remainingToday, 9);
  });

  it("times out a hung check as a refundable failure", async () => {
    const { usage, jobs } = await setup(() => new Promise(() => undefined), { itemTimeoutMs: 50 });
    usage.addCredits(payg.id, "payg", payg.label, 5);
    const { job } = jobs.submit(payg, "email", ["hang.com"], false);
    jobs.start();
    await jobs.whenIdle();
    const view = jobs.get(payg, job.jobId);
    assert.equal(view.items[0]?.status, "failed");
    assert.equal(view.items[0]?.error?.code, "TOOL_TIMEOUT");
    assert.equal(usage.creditsRemaining(payg.id), 5);
  });

  it("alternates between jobs so a large job cannot starve a small one", async () => {
    const order: string[] = [];
    const { jobs } = await setup(
      async (_c, domain) => {
        order.push(domain);
        return {};
      },
      { concurrency: 1 }
    );
    jobs.submit(pro, "email", ["a1.com", "a2.com", "a3.com"], false);
    jobs.submit({ ...pro, id: "key_other" }, "email", ["b1.com", "b2.com"], false);
    jobs.start();
    await jobs.whenIdle();
    assert.deepEqual(order.slice(0, 4), ["a1.com", "b1.com", "a2.com", "b2.com"]);
  });

  it("cancels pending items, lets running ones finish, and refunds the cancelled ones", async () => {
    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const { usage, jobs } = await setup(
      async (_c, domain) => {
        await gate;
        return { domain };
      },
      { concurrency: 1 }
    );
    usage.addCredits(payg.id, "payg", payg.label, 10);
    const { job } = jobs.submit(payg, "email", ["one.com", "two.com", "three.com"], false);
    jobs.start();
    await new Promise((resolve) => setImmediate(resolve));
    const cancelled = jobs.cancel(payg, job.jobId);
    assert.equal(cancelled.status, "cancelled");
    assert.equal(cancelled.counts.cancelled, 2);
    assert.equal(cancelled.counts.running, 1);
    release();
    await jobs.whenIdle();
    const view = jobs.get(payg, job.jobId);
    assert.equal(view.status, "cancelled");
    assert.equal(view.counts.done, 1);
    assert.equal(view.creditsRefunded, 2);
    assert.equal(usage.creditsRemaining(payg.id), 9);
  });

  it("hides another caller's job behind NOT_FOUND", async () => {
    const { jobs } = await setup(okRunner);
    const { job } = jobs.submit(pro, "email", ["a.com"], false);
    for (const action of [() => jobs.get(payg, job.jobId), () => jobs.cancel(payg, job.jobId), () => jobs.resultsCsv(payg, job.jobId), () => jobs.get(pro, "job_nope")]) {
      assert.throws(action, (err: unknown) => err instanceof ToolError && err.code === "NOT_FOUND");
    }
    assert.equal(jobs.list(payg).length, 0);
    assert.equal(jobs.list(pro).length, 1);
  });

  it("requeues interrupted items on stop and finishes them after a restart", async () => {
    let calls = 0;
    const slow: BulkCheckRunner = (_c, _d, _p, signal) =>
      new Promise((resolve, reject) => {
        calls++;
        const timer = setTimeout(() => resolve({ ok: true }), 5000);
        signal.addEventListener("abort", () => {
          clearTimeout(timer);
          reject(signal.reason);
        });
      });
    const { db, usage, limiter, jobs } = await setup(slow, { concurrency: 1 });
    const { job } = jobs.submit(pro, "email", ["r1.com", "r2.com"], false);
    jobs.start();
    await new Promise((resolve) => setImmediate(resolve));
    await jobs.stop();
    assert.equal(calls, 1);
    assert.equal(jobs.get(pro, job.jobId).counts.pending, 2, "the interrupted item is pending again");
    const restarted = new BulkJobs({ db, usage, limiter, runner: okRunner, options: OPTIONS });
    restarted.start();
    await restarted.whenIdle();
    assert.equal(restarted.get(pro, job.jobId).counts.done, 2);
  });

  it("pages results and filters by status", async () => {
    const { jobs } = await setup(async (_c, domain) => {
      if (domain.startsWith("f")) throw new ToolError("NETWORK_ERROR", "x", { retryable: true });
      return {};
    });
    const { job } = jobs.submit(pro, "email", ["a.com", "f1.com", "b.com", "f2.com", "c.com"], false);
    jobs.start();
    await jobs.whenIdle();
    const first = jobs.get(pro, job.jobId, { limit: 2 });
    assert.deepEqual(
      first.items.map((i) => i.index),
      [0, 1]
    );
    assert.equal(first.nextOffset, 2);
    const last = jobs.get(pro, job.jobId, { offset: 4, limit: 2 });
    assert.equal(last.nextOffset, null);
    assert.deepEqual(
      jobs.get(pro, job.jobId, { status: "failed" }).items.map((i) => i.domain),
      ["f1.com", "f2.com"]
    );
  });
});

describe("BulkJobs CSV and retention", () => {
  it("writes one row per input with formula injection neutralized", async () => {
    const { jobs } = await setup(async () => ({ score: 80, grade: "B", mxProvider: '=HYPERLINK("x")', highRisks: ["SPF_PASS_ALL", "DMARC_MISSING"], summary: 'says "hi", ok' }));
    const { job } = jobs.submit(pro, "email", ["a.com", "not valid"], false);
    jobs.start();
    await jobs.whenIdle();
    const csv = jobs.resultsCsv(pro, job.jobId);
    const lines = csv.trimEnd().split("\r\n");
    assert.equal(lines[0], "index,input,domain,status,error_code,error_message,score,grade,exists,mxProvider,spfPolicy,dmarcPolicy,dkimFound,disposable,highRisks,summary");
    assert.equal(lines.length, 3);
    assert.ok(lines[1]?.includes(`"'=HYPERLINK(""x"")"`), lines[1]);
    assert.ok(lines[1]?.includes("SPF_PASS_ALL; DMARC_MISSING"));
    assert.ok(lines[1]?.includes('"says ""hi"", ok"'));
    assert.ok(lines[2]?.startsWith("1,not valid,,skipped,INVALID_DOMAIN,"));
    assert.equal(csvCell("-1+2"), "'-1+2");
    assert.equal(csvCell("@cmd"), "'@cmd");
    assert.equal(csvCell(null), "");
  });

  it("prunes finished jobs past retention with their items", async () => {
    const { db, jobs } = await setup(okRunner);
    const { job } = jobs.submit(pro, "email", ["a.com"], false);
    jobs.start();
    await jobs.whenIdle();
    assert.equal(jobs.prune(Date.now() + 31 * 24 * 60 * 60 * 1000), 1);
    assert.equal(Number((db.prepare("SELECT COUNT(*) AS n FROM job_items WHERE job_id = ?").get(job.jobId) as { n: number }).n), 0);
  });
});
