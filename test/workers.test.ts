import assert from "node:assert/strict";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { DEFAULT_PLAN_LIMITS, DEFAULT_WATCH_LIMITS, loadConfig } from "../src/config.js";
import { setLogLevel } from "../src/logger.js";
import type { Principal } from "../src/middleware/auth.js";
import { RateLimiter } from "../src/middleware/rateLimit.js";
import { UsageTracker } from "../src/middleware/usage.js";
import { CreditLedger } from "../src/store/credits.js";
import { openDatabase, type Database } from "../src/store/db.js";
import { BulkJobs, type BulkCheckRunner, type BulkJobsOptions } from "../src/store/jobs.js";
import { Monitor } from "../src/store/monitor.js";
import { ScanStore } from "../src/store/scanStore.js";

setLogLevel("silent");

const payg: Principal = { id: "pay_w", plan: "payg", label: "w", source: "session" };
const OPTIONS: BulkJobsOptions = {
  creditsPerDomain: { email: 1, tech: 1, audit: 2 },
  maxDomains: 50,
  concurrency: 1,
  itemTimeoutMs: 5000,
  maxActiveJobsPerPrincipal: 3,
  retentionDays: 30,
  pollMs: 60_000
};

function worker(db: Database, usage: UsageTracker, runner: BulkCheckRunner): BulkJobs {
  const limiter = new RateLimiter({ ...loadConfig({}, []).auth.planLimits, pro: { ...DEFAULT_PLAN_LIMITS.pro } });
  return new BulkJobs({ db, usage, limiter, runner, options: OPTIONS });
}

function ledgerUsage(db: Database): UsageTracker {
  const usage = new UsageTracker(null);
  usage.attachLedger(new CreditLedger(db));
  return usage;
}

describe("shared credit ledger", () => {
  it("gives every tracker on one database the same balance and a single winner per payment", async () => {
    const db = await openDatabase(":memory:");
    assert.ok(db);
    const a = ledgerUsage(db);
    const b = ledgerUsage(db);
    a.addCredits("pay_1", "payg", "x", 10);
    assert.equal(b.creditsRemaining("pay_1"), 10);
    assert.equal(b.consumeCredits("pay_1", 4), true);
    assert.equal(a.creditsRemaining("pay_1"), 6);
    assert.equal(a.consumeCredits("pay_1", 7), false, "never below zero");
    assert.equal(a.markPaymentRedeemed("pi_1"), true);
    assert.equal(b.markPaymentRedeemed("pi_1"), false, "the second redemption loses");
    assert.equal(b.isPaymentRedeemed("pi_1"), true);
  });

  it("imports the file ledger once, without rolling balances back", async () => {
    const db = await openDatabase(":memory:");
    assert.ok(db);
    const first = new UsageTracker(null);
    first.addCredits("pay_old", "payg", "old", 25);
    first.markPaymentRedeemed("pi_old");
    first.attachLedger(new CreditLedger(db));
    assert.equal(first.creditsRemaining("pay_old"), 25);
    assert.equal(first.isPaymentRedeemed("pi_old"), true);
    first.consumeCredits("pay_old", 5);
    const stale = new UsageTracker(null);
    stale.addCredits("pay_old", "payg", "old", 25);
    stale.attachLedger(new CreditLedger(db));
    assert.equal(stale.creditsRemaining("pay_old"), 20, "a second process's older file does not overwrite the database");
  });
});

describe("bulk worker fencing and recovery", () => {
  it("a worker that lost its items cannot overwrite the successor's results", async () => {
    const db = await openDatabase(":memory:");
    assert.ok(db);
    const usage = ledgerUsage(db);
    usage.addCredits(payg.id, payg.plan, payg.label, 10);
    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const slow = worker(db, usage, async (_c, domain) => {
      await gate;
      return { domain, from: "old" };
    });
    slow.start();
    const { job } = slow.submit(payg, "email", ["a.com"], false);
    await new Promise((resolve) => setTimeout(resolve, 20));
    // A successor takes over (lease handover): it requeues and finishes the item.
    const successor = worker(db, usage, async (_c, domain) => ({ domain, from: "new" }));
    successor.start();
    await successor.whenIdle();
    assert.equal(successor.get(payg, job.jobId).status, "completed");
    release();
    await new Promise((resolve) => setTimeout(resolve, 50));
    const view = successor.get(payg, job.jobId);
    assert.equal((view.items[0]?.result as { from: string }).from, "new", "the stale result was discarded");
    assert.equal(view.status, "completed");
    await slow.stop();
    await successor.stop();
  });

  it("finalizes stranded jobs on start and refunds them exactly once", async () => {
    const db = await openDatabase(":memory:");
    assert.ok(db);
    const usage = ledgerUsage(db);
    usage.addCredits(payg.id, payg.plan, payg.label, 10);
    const jobs = worker(db, usage, async () => {
      throw new Error("resolver down");
    });
    const { job } = jobs.submit(payg, "email", ["a.com", "b.com"], false);
    assert.equal(usage.creditsRemaining(payg.id), 8);
    // Simulate a crash after both items failed but before finalization.
    db.prepare("UPDATE job_items SET status = 'failed', error_code = 'NETWORK_ERROR' WHERE job_id = ?").run(job.jobId);
    jobs.start();
    await jobs.whenIdle();
    assert.equal(jobs.get(payg, job.jobId).status, "completed");
    assert.equal(usage.creditsRemaining(payg.id), 10, "both failed items refunded");
    await jobs.stop();
    jobs.start();
    await jobs.whenIdle();
    assert.equal(usage.creditsRemaining(payg.id), 10, "and not twice");
    await jobs.stop();
  });

  it("a dispatch failure after the job is committed does not fail the submission", async () => {
    const db = await openDatabase(":memory:");
    assert.ok(db);
    const usage = ledgerUsage(db);
    usage.addCredits(payg.id, payg.plan, payg.label, 10);
    const jobs = worker(db, usage, async (_c, domain) => ({ domain }));
    jobs.start();
    (jobs as unknown as { claimNext: () => never }).claimNext = () => {
      throw new Error("database is locked");
    };
    const submission = jobs.submit(payg, "email", ["a.com"], false);
    assert.equal(submission.job.status, "queued");
    assert.equal(usage.creditsRemaining(payg.id), 9, "charged once, and the caller was not told it failed");
    await jobs.stop();
  });

  it("charges atomically with the job: an insufficient balance charges nothing", async () => {
    const db = await openDatabase(":memory:");
    assert.ok(db);
    const usage = ledgerUsage(db);
    usage.addCredits(payg.id, payg.plan, payg.label, 1);
    const jobs = worker(db, usage, async () => ({}));
    assert.throws(() => jobs.submit(payg, "audit", ["a.com"], false), /costs 2 credit/);
    assert.equal(usage.creditsRemaining(payg.id), 1);
    assert.equal(Number((db.prepare("SELECT COUNT(*) AS n FROM jobs").get() as { n: number }).n), 0);
  });
});

describe("monitor shutdown", () => {
  it("stop() cancels an in-flight webhook delivery and leaves the alerts pending without a penalty", async () => {
    const db = await openDatabase(":memory:");
    assert.ok(db);
    const store = new ScanStore(db, { retentionDays: 30 });
    const principal: Principal = { id: "acct_m", plan: "pro", label: "m", source: "api-key" };
    let sends = 0;
    const monitor = new Monitor({
      db,
      usage: new UsageTracker(null),
      runner: async () => undefined,
      sender: (_url, _body, _headers, signal) =>
        new Promise((resolve) => {
          sends++;
          signal?.addEventListener("abort", () => resolve({ ok: false, status: null, error: "aborted" }), { once: true });
        }),
      options: {
        intervalMs: 24 * 3600_000,
        retryMs: 3600_000,
        creditsPerCheck: 1,
        concurrency: 1,
        checkTimeoutMs: 1000,
        tickMs: 60_000,
        maxWatches: DEFAULT_WATCH_LIMITS,
        webhook: { allowInsecure: false, allowPrivate: false },
        deliveryBackoffMs: [60_000],
        alertRetentionDays: 90
      }
    });
    monitor.watch(principal, "hooked.com", ["tech"], "https://hooks.example.com/x", false);
    store.recordTech(
      {
        domain: "hooked.com",
        partial: false,
        fetch: { ok: true, status: 200, finalHost: "hooked.com", truncated: false, error: null },
        blocked: { blocked: false, vendor: null, challengeType: null, reason: null },
        technologies: [],
        security: { score: 1, grade: "F" }
      } as never,
      "call",
      1
    );
    store.recordTech(
      {
        domain: "hooked.com",
        partial: false,
        fetch: { ok: true, status: 200, finalHost: "hooked.com", truncated: false, error: null },
        blocked: { blocked: false, vendor: null, challengeType: null, reason: null },
        technologies: [{ id: "x", name: "X", category: "cms", version: null, implied: false }],
        security: { score: 1, grade: "F" }
      } as never,
      "call",
      2
    );
    monitor.collectAlerts();
    const delivering = monitor.deliver();
    await new Promise((resolve) => setTimeout(resolve, 10));
    assert.equal(sends, 1);
    const started = Date.now();
    await monitor.stop();
    await delivering;
    assert.ok(Date.now() - started < 1000, "shutdown did not wait for the endpoint");
    const alert = monitor.alerts(principal, { markRead: false }).alerts[0];
    assert.equal(alert?.delivery.status, "pending");
    assert.equal(alert?.delivery.attempts, 0);
  });
});

describe("storage pruning", () => {
  it("prunes a large backlog in bounded batches", async () => {
    const db = await openDatabase(":memory:");
    assert.ok(db);
    const store = new ScanStore(db, { retentionDays: 30 });
    const insert = db.prepare("INSERT INTO scans (domain, kind, source, scanned_at, ok, summary) VALUES ('old.com', 'tech', 'call', 1, 1, '{}')");
    for (let i = 0; i < 2500; i++) insert.run();
    const first = store.pruneBatch(Date.now());
    assert.equal(first.scans, 1000);
    const rest = await store.pruneAsync(Date.now());
    assert.equal(rest.scans, 1500);
    assert.equal(Number((db.prepare("SELECT COUNT(*) AS n FROM scans").get() as { n: number }).n), 0);
  });
});

/** The exit code, or "timeout" after ms; the timer never outlives the race. */
async function exitWithin(exited: Promise<unknown[]>, ms: number): Promise<number | null | "timeout"> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      exited.then(([code]) => code as number | null),
      new Promise<"timeout">((resolve) => {
        timer = setTimeout(() => resolve("timeout"), ms);
      })
    ]);
  } finally {
    clearTimeout(timer);
  }
}

/** Variables Node and tsx need to start: the executable search path, the home and temp directories (tsx caches in the temp one), and SystemRoot, without which Windows networking and crypto can fail to initialise. */
const PROCESS_BASICS = ["PATH", "SystemRoot", "HOME", "USERPROFILE", "TEMP", "TMP", "TMPDIR"];

/**
 * A child's whole environment: the process basics plus exactly the settings
 * given. Nothing else of the developer's environment is passed on, because
 * the config also validates variables outside STACKDNS_* (PORT, STRIPE_*,
 * X402_*), and one invalid inherited value fails the child's startup.
 */
function childEnv(settings: Record<string, string>): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const key of PROCESS_BASICS) {
    const value = process.env[key];
    if (value !== undefined) env[key] = value;
  }
  return { ...env, ...settings };
}

/** Runs fn with these variables set in this process's environment, then puts the old values back. */
function withProcessEnv<T>(vars: Record<string, string>, fn: () => T): T {
  const saved = Object.keys(vars).map((key) => [key, process.env[key]] as const);
  Object.assign(process.env, vars);
  try {
    return fn();
  } finally {
    for (const [key, value] of saved) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

describe("stdio shutdown", () => {
  it("closing stdin runs the shutdown: the worker lease is released", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "sdm-stdio-"));
    const dbFile = path.join(dir, "s.db");
    const entry = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "src", "index.ts");
    // The developer's own settings must not reach the child: with bulk and
    // monitoring switched off it never logs the line awaited below, an
    // inherited seed file starts a real crawler, and any invalid value fails
    // its config. Everything it needs is set here, and the spawn runs with
    // values its config rejects in this process's environment, so a child
    // that inherits them fails to start instead of passing by luck.
    const shellLeftovers = { PORT: "not-a-port", STACKDNS_PORT: "0", STRIPE_API_BASE: "not a url" };
    let child: ChildProcessWithoutNullStreams | undefined;
    try {
      child = withProcessEnv(shellLeftovers, () =>
        spawn(process.execPath, ["--import", "tsx", entry, "--stdio"], {
          env: childEnv({
            STACKDNS_TRANSPORT: "stdio",
            STACKDNS_DB_FILE: dbFile,
            STACKDNS_USAGE_FILE: path.join(dir, "usage.json"),
            STACKDNS_LOG_LEVEL: "info",
            STACKDNS_BULK_ENABLED: "true",
            STACKDNS_MONITOR_ENABLED: "false",
            STACKDNS_CRAWL_SEED_FILE: "none"
          }),
          stdio: ["pipe", "pipe", "pipe"]
        })
      );
      const proc = child;
      let log = "";
      proc.stderr.on("data", (chunk: Buffer) => (log += chunk.toString()));
      const exited = once(proc, "exit");
      const deadline = Date.now() + 20_000;
      while (!log.includes("background workers started") && proc.exitCode === null && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 100));
      assert.ok(log.includes("background workers started"), log.slice(-500));
      proc.stdin.end();
      assert.equal(await exitWithin(exited, 20_000), 0, log.slice(-500));
      assert.ok(log.includes("shutting down"), "shutdown ran");
      const db = await openDatabase(dbFile);
      assert.ok(db);
      const lease = db.prepare("SELECT value FROM meta WHERE key = 'lease:workers'").get();
      assert.equal(lease, undefined, "the lease was released, so the next server starts workers at once");
      db.close();
    } finally {
      // A failed assertion must not leave the child running: its pipes would
      // keep this test file alive, and on Windows the s.db it holds open
      // would make rm fail and hide the original error.
      if (child && child.pid !== undefined && child.exitCode === null && child.signalCode === null) {
        const gone = once(child, "exit");
        child.kill();
        await gone;
      }
      await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });
});
