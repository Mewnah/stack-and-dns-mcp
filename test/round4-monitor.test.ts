/**
 * Regression tests for the round-4 fixes to domain parsing (G9), the v7
 * migration (G10) and the monitor (G12-G15), with their round-5 and round-6
 * residuals.
 */

import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { describe, it } from "node:test";
import { domainToASCII } from "node:url";
import { DEFAULT_WATCH_LIMITS } from "../src/config.js";
import { parseDomain } from "../src/lib/domain.js";
import { isToolError } from "../src/lib/errors.js";
import type { WebhookSender } from "../src/lib/webhook.js";
import { setLogLevel } from "../src/logger.js";
import type { Principal } from "../src/middleware/auth.js";
import { UsageTracker } from "../src/middleware/usage.js";
import { CreditLedger } from "../src/store/credits.js";
import { MIGRATIONS, migrate, openDatabase, transaction, type Database } from "../src/store/db.js";
import { normalizeBulkInputs } from "../src/store/jobs.js";
import { KeyRepository } from "../src/store/keyStore.js";
import { Monitor, type MonitorDeps, type MonitorOptions } from "../src/store/monitor.js";

setLogLevel("silent");

const HOUR = 3_600_000;
const payer: Principal = { id: "pay_round4", plan: "payg", label: "r4", source: "session" };
const okSender: WebhookSender = async () => ({ ok: true, status: 200, error: null });

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

function count(db: Database, sql: string, ...params: Array<string | number>): number {
  return Number((db.prepare(sql).get(...params) as { n: number }).n);
}

function nextAt(db: Database, domain: string, kind: string): number | undefined {
  const row = db.prepare("SELECT next_at FROM monitor_schedule WHERE domain = ? AND kind = ?").get(domain, kind) as { next_at: number } | undefined;
  return row === undefined ? undefined : Number(row.next_at);
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Settles with the promise, or with "timeout" after ms; the timer never outlives the race. */
async function within<T>(promise: Promise<T>, ms: number): Promise<T | "timeout"> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<"timeout">((resolve) => {
        timer = setTimeout(() => resolve("timeout"), ms);
      })
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function withTempDir<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(path.join(tmpdir(), "sdm-r4-monitor-"));
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  }
}

/** length distinct Hangul syllables, starting offset code points into the block. */
function hangul(length: number, offset = 0): string {
  let out = "";
  for (let i = 0; i < length; i++) out += String.fromCodePoint(0xac00 + offset + i);
  return out;
}

const ALERT_COLUMNS = "watch_id, principal_id, domain, kind, change, subject, old_value, new_value, severity, at, created_at, delivery_status, next_delivery_at";

describe("G9: hosts are bounded before IDNA, whatever their script", () => {
  it("rejects an over-long non-ASCII host in microseconds, bare, as an email and as a URL", () => {
    const host = hangul(2000);
    const inputs = [host, `someone@${host}`, `https://${host}/`, `https://user@${host}:8443/path`, `//${host}`];
    for (const input of inputs) {
      const result = parseDomain(input);
      assert.equal(result.ok, false, input.slice(0, 12));
      assert.equal(result.ok ? null : result.code, "INVALID_DOMAIN");
    }
    const started = performance.now();
    for (let round = 0; round < 40; round++) for (const input of inputs) parseDomain(input);
    const elapsed = performance.now() - started;
    // Punycode-encoding one such label costs about 5 ms, so 200 of them would take about a second.
    assert.ok(elapsed < 150, `200 hostile hosts took ${elapsed.toFixed(0)} ms`);
  });

  it("refuses a near-2 MB bulk list of 342 such lines without stalling the event loop", () => {
    const lines = Array.from({ length: 342 }, (_, n) => (n % 2 === 0 ? hangul(2040, n * 16) : `https://${hangul(2030, n * 16)}/`));
    assert.ok(lines.reduce((sum, line) => sum + Buffer.byteLength(line) + 1, 0) < 2 * 1024 * 1024, "fits the bulk body limit");
    const started = performance.now();
    const { accepted, skipped } = normalizeBulkInputs(lines, false);
    const elapsed = performance.now() - started;
    assert.equal(accepted.length, 0);
    assert.equal(skipped.length, 342);
    assert.ok(skipped.every((s) => s.code === "INVALID_DOMAIN"));
    assert.ok(elapsed < 250, `a free, uncharged submission blocked the event loop for ${elapsed.toFixed(0)} ms`);
  });

  it("still accepts real internationalized names up to the DNS limits", () => {
    // 222 code points and 438 UTF-16 units, but 250 characters once encoded.
    const emoji = `${Array.from({ length: 4 }, () => "\u{1F600}".repeat(54)).join(".")}.ws`;
    assert.equal(emoji.length, 438);
    for (const input of [emoji, `https://${emoji}/`]) {
      const result = parseDomain(input);
      assert.ok(result.ok, result.ok ? "" : result.error);
      assert.equal(result.domain.length, 250);
    }

    const idn = parseDomain("https://user@Bücher.münchen.de:8080/path?q=1");
    assert.ok(idn.ok, idn.ok ? "" : idn.error);
    assert.equal(idn.domain, domainToASCII("bücher.münchen.de"));
    assert.ok(idn.domain.startsWith("xn--"));

    // IDNA label separators other than "." end a label too.
    for (const separator of ["。", "．", "｡"]) {
      const result = parseDomain(`${"a".repeat(40)}${separator}${"b".repeat(40)}.com`);
      assert.ok(result.ok, `separator U+${separator.codePointAt(0)?.toString(16)}: ${result.ok ? "" : result.error}`);
      assert.equal(result.domain, `${"a".repeat(40)}.${"b".repeat(40)}.com`);
    }

    // ASCII limits are unchanged: 63 per label, 253 in all.
    assert.equal(parseDomain(`${"a".repeat(63)}.com`).ok, true);
    assert.equal(parseDomain(`${"a".repeat(64)}.com`).ok, false);
    const longest = `${"a".repeat(63)}.${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(57)}.com`;
    assert.equal(longest.length, 253);
    assert.equal(parseDomain(longest).ok, true);
    assert.equal(parseDomain(`${"a".repeat(63)}.${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(58)}.com`).ok, false);
  });
});

describe("G10: the v7 migration retires anonymous watches", () => {
  it("removes anonymous watches with their alerts, so they are never scanned or posted again", async () => {
    await withTempDir(async (dir) => {
      const file = path.join(dir, "v6.db");
      const raw = new DatabaseSync(file);
      try {
        raw.exec("PRAGMA foreign_keys = ON;");
        assert.equal(
          migrate(
            raw,
            MIGRATIONS.filter((m) => m.version <= 6)
          ),
          6
        );
        const insertWatch = raw.prepare(
          "INSERT INTO watches (id, principal_id, principal_plan, principal_label, principal_source, domain, checks, webhook_url, webhook_secret, created_at, alert_cursor) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'whsec_test', 1000, 0)"
        );
        insertWatch.run("watch_anon", "anon_203.0.113.9", "free", "", "anonymous", "anon-watched.com", "tech,email", "https://hooks.example.com/anon");
        insertWatch.run("watch_keyed", "acct_keyed", "pro", "k", "api-key", "keyed.com", "tech", null);
        insertWatch.run("watch_local", "local", "local", "l", "local", "local-watched.com", "tech", null);
        const schedule = raw.prepare("INSERT INTO monitor_schedule (domain, kind, next_at) VALUES (?, ?, 1000)");
        schedule.run("anon-watched.com", "tech");
        schedule.run("anon-watched.com", "email");
        schedule.run("keyed.com", "tech");
        schedule.run("local-watched.com", "tech");
        raw
          .prepare(`INSERT INTO alerts (${ALERT_COLUMNS}) VALUES ('watch_anon', 'anon_203.0.113.9', 'anon-watched.com', 'tech', 'tech_added', 'x', NULL, 'x', 'medium', 1000, 1000, 'pending', 1000)`)
          .run();
      } finally {
        raw.close();
      }

      const db = await openDatabase(file);
      assert.ok(db);
      try {
        assert.equal((db.prepare("SELECT value FROM meta WHERE key = 'schema_version'").get() as { value: string }).value, String(MIGRATIONS.length));
        assert.equal(count(db, "SELECT COUNT(*) AS n FROM watches WHERE principal_source = 'anonymous'"), 0);
        assert.equal(count(db, "SELECT COUNT(*) AS n FROM alerts WHERE watch_id = 'watch_anon'"), 0, "their alerts (and pending deliveries) go with them");
        assert.deepEqual(
          (db.prepare("SELECT id FROM watches ORDER BY id").all() as Array<{ id: string }>).map((r) => r.id),
          ["watch_keyed", "watch_local"],
          "identified watches are kept"
        );

        const clock = { now: 1000 + 25 * HOUR };
        const runs: string[] = [];
        const posts: string[] = [];
        const monitor = monitorOn(db, clock, {
          options: options({ concurrency: 2 }),
          runner: async (check, domain) => {
            runs.push(`${check}:${domain}`);
          },
          sender: async (url) => {
            posts.push(url);
            return { ok: true, status: 200, error: null };
          }
        });
        await monitor.tick(clock.now);
        await monitor.whenDelivered();
        assert.deepEqual(runs.sort(), ["tech:keyed.com", "tech:local-watched.com"], "the anonymous watch's domain is not scanned");
        assert.deepEqual(posts, [], "nothing is posted to the anonymous watch's webhook");
        assert.equal(count(db, "SELECT COUNT(*) AS n FROM monitor_schedule WHERE domain = 'anon-watched.com'"), 0, "its schedule rows are dropped once due");
        await monitor.stop();
      } finally {
        db.close();
      }
    });
  });
});

describe("G12: a claim re-checks that its schedule row is still due", () => {
  it("two monitors sharing one database file run and charge each due check once when their rounds overlap", async () => {
    await withTempDir(async (dir) => {
      const file = path.join(dir, "shared.db");
      const dbA = await openDatabase(file);
      const dbB = await openDatabase(file);
      assert.ok(dbA && dbB);
      try {
        const clock = { now: 5_000_000 };
        const usageA = new UsageTracker(null);
        usageA.attachLedger(new CreditLedger(dbA));
        const usageB = new UsageTracker(null);
        usageB.attachLedger(new CreditLedger(dbB));
        usageA.addCredits(payer.id, payer.plan, payer.label, 10);

        const runs: Array<{ by: "A" | "B"; domain: string }> = [];
        let markBStarted: () => void = () => undefined;
        const bStarted = new Promise<void>((resolve) => {
          markBStarted = resolve;
        });
        const make = (by: "A" | "B", db: Database, usage: UsageTracker): Monitor =>
          monitorOn(db, clock, {
            usage,
            options: options({ concurrency: 1 }),
            runner: async (_check, domain) => {
              runs.push({ by, domain });
              if (by === "B") markBStarted();
              // A's first check spans B's round, as in a lease handover.
              else await within(bStarted, 1000);
            }
          });
        const a = make("A", dbA, usageA);
        const b = make("B", dbB, usageB);
        a.watch(payer, "first.com", ["tech"], null, false);
        a.watch(payer, "second.com", ["tech"], null, false);

        // A selects both rows and claims one; B then selects (and claims) the
        // other while A's batch still lists it.
        await Promise.all([a.tick(clock.now), b.tick(clock.now)]);
        await Promise.all([a.whenDelivered(), b.whenDelivered()]);

        assert.ok(runs.some((r) => r.by === "A") && runs.some((r) => r.by === "B"), `the rounds overlapped: ${JSON.stringify(runs)}`);
        for (const domain of ["first.com", "second.com"]) {
          assert.equal(runs.filter((r) => r.domain === domain).length, 1, `${domain} checked once: ${JSON.stringify(runs)}`);
          assert.equal(nextAt(dbA, domain, "tech"), clock.now + 24 * HOUR, `${domain} is next due after a full interval`);
        }
        assert.equal(usageA.creditsRemaining(payer.id), 8, "one credit per check, not one per process");
        await Promise.all([a.stop(), b.stop()]);
      } finally {
        dbA.close();
        dbB.close();
      }
    });
  });
});

describe("G13: stop() while a claim is waiting or landing", () => {
  it("stop() does not wait out a claim blocked by another connection's write lock, and that check is neither charged nor run", async () => {
    await withTempDir(async (dir) => {
      const file = path.join(dir, "locked.db");
      const db = await openDatabase(file);
      const holder = await openDatabase(file);
      assert.ok(db && holder);
      try {
        db.exec("PRAGMA busy_timeout = 20;");
        const clock = { now: 5_000_000 };
        const usage = new UsageTracker(null);
        usage.addCredits(payer.id, payer.plan, payer.label, 5);
        const runs: string[] = [];
        const runner = async (_check: string, domain: string): Promise<void> => {
          runs.push(domain);
        };
        const monitor = monitorOn(db, clock, { usage, runner });
        monitor.watch(payer, "locked.com", ["tech"], null, false);

        // Another process holds the write lock (a migration, a VACUUM, a lost lease).
        holder.exec("BEGIN IMMEDIATE");
        try {
          const ticking = monitor.tick(clock.now);
          await delay(40); // the claim has hit the lock and is waiting to retry
          const started = performance.now();
          const outcome = await within(
            monitor.stop().then(() => "stopped" as const),
            2500
          );
          assert.equal(outcome, "stopped", "stop() returns while the lock is still held");
          assert.ok(performance.now() - started < 1000, `stop() took ${(performance.now() - started).toFixed(0)} ms`);
          await ticking;
        } finally {
          holder.exec("ROLLBACK");
        }
        assert.deepEqual(runs, [], "the blocked check never ran");
        assert.equal(usage.creditsRemaining(payer.id), 5, "and was not charged");
        assert.equal(nextAt(db, "locked.com", "tech"), clock.now, "the row stays due");

        // The next holder picks it up normally.
        const successor = monitorOn(db, clock, { usage, runner });
        await successor.tick(clock.now);
        assert.deepEqual(runs, ["locked.com"]);
        assert.equal(usage.creditsRemaining(payer.id), 4);
        await successor.stop();
      } finally {
        db.close();
        holder.close();
      }
    });
  });

  it("a claim that commits after stop() aborts its check at once and refunds the charge", async () => {
    const db = await openDatabase(":memory:");
    assert.ok(db);
    class HookedUsage extends UsageTracker {
      onConsume: () => void = () => undefined;
      override consumeCredits(principalId: string, credits: number): boolean {
        const ok = super.consumeCredits(principalId, credits);
        this.onConsume();
        return ok;
      }
    }
    const clock = { now: 5_000_000 };
    const usage = new HookedUsage(null);
    usage.addCredits(payer.id, payer.plan, payer.label, 5);
    const signals: boolean[] = [];
    const monitor = monitorOn(db, clock, {
      usage,
      options: options({ checkTimeoutMs: 3000 }),
      // An un-abortable check (DNS lookups cannot be interrupted): it never settles on its own.
      runner: (_check, _domain, signal) => {
        signals.push(signal.aborted);
        return new Promise<void>(() => undefined);
      }
    });
    monitor.watch(payer, "late.com", ["tech"], null, false);
    // stop() lands while the claim transaction is still open, after its halted check.
    const hook: { stopping?: Promise<void> } = {};
    usage.onConsume = () => {
      hook.stopping ??= monitor.stop();
    };
    const ticking = monitor.tick(clock.now);
    const started = performance.now();
    assert.notEqual(await within(ticking, 1500), "timeout", "the round ends without waiting for the check's timeout");
    assert.ok(hook.stopping, "stop() was called during the claim");
    assert.notEqual(await within(hook.stopping, 1500), "timeout");
    assert.ok(performance.now() - started < 1000, `stop() took ${(performance.now() - started).toFixed(0)} ms`);
    assert.ok(
      signals.every((aborted) => aborted),
      "the late check starts already aborted"
    );
    assert.equal(usage.creditsRemaining(payer.id), 5, "its charge is refunded");
    db.close();
  });

  it("a refund owed at shutdown is still retried through a locked database", async () => {
    await withTempDir(async (dir) => {
      const file = path.join(dir, "refund.db");
      const db = await openDatabase(file);
      const holder = await openDatabase(file);
      assert.ok(db && holder);
      try {
        db.exec("PRAGMA busy_timeout = 20;");
        const clock = { now: 5_000_000 };
        const usage = new UsageTracker(null);
        usage.addCredits(payer.id, payer.plan, payer.label, 5);
        let started = 0;
        const monitor = monitorOn(db, clock, {
          usage,
          runner: () => {
            started++;
            return new Promise<void>(() => undefined);
          }
        });
        monitor.watch(payer, "refund.com", ["tech"], null, false);
        const ticking = monitor.tick(clock.now);
        for (let i = 0; i < 100 && started === 0; i++) await delay(5);
        assert.equal(started, 1, "the check is running");
        assert.equal(usage.creditsRemaining(payer.id), 4, "and was charged");

        holder.exec("BEGIN IMMEDIATE");
        const stopping = monitor.stop(); // aborts the check; its refund meets the lock
        try {
          await delay(150);
          assert.equal(usage.creditsRemaining(payer.id), 4, "the refund waits for the lock");
        } finally {
          holder.exec("ROLLBACK");
        }
        assert.notEqual(await within(stopping, 3000), "timeout");
        await ticking;
        assert.equal(usage.creditsRemaining(payer.id), 5, "the refund is applied, not dropped");
      } finally {
        db.close();
        holder.close();
      }
    });
  });
});

describe("G14: webhook delivery takes principals in turn", () => {
  function seed(db: Database, principal: string, watches: number, firstDue: number, url: string): void {
    const watch = db.prepare(
      "INSERT INTO watches (id, principal_id, principal_plan, principal_label, principal_source, domain, checks, webhook_url, webhook_secret, created_at) VALUES (?, ?, 'enterprise', '', 'api-key', ?, 'tech', ?, 'whsec_test', 0)"
    );
    const alert = db.prepare(`INSERT INTO alerts (${ALERT_COLUMNS}) VALUES (?, ?, ?, 'tech', 'tech_added', 'x', NULL, 'x', 'medium', ?, ?, 'pending', ?)`);
    transaction(db, () => {
      for (let i = 0; i < watches; i++) {
        const id = `watch_${principal}_${i}`;
        const domain = `${principal}-${i}.com`;
        watch.run(id, principal, domain, url);
        alert.run(id, principal, domain, firstDue + i, firstDue + i, firstDue + i);
      }
    });
  }

  it("one account with more than 500 due watches cannot keep other tenants' webhooks out of the round", async () => {
    const db = await openDatabase(":memory:");
    assert.ok(db);
    // Every one of big's alerts is older than the other tenants'.
    seed(db, "big", 600, 1000, "https://big.example.com/hook");
    seed(db, "small1", 1, 50_000, "https://small1.example.com/hook");
    seed(db, "small2", 1, 60_000, "https://small2.example.com/hook");
    let inFlight = 0;
    let maxInFlight = 0;
    const posts: string[] = [];
    const monitor = monitorOn(
      db,
      { now: 10_000_000 },
      {
        options: options({ deliveryConcurrency: 2, deliveryBudgetMs: 120 }),
        // big's receiver is slow and failing.
        sender: async (url) => {
          inFlight++;
          maxInFlight = Math.max(maxInFlight, inFlight);
          posts.push(url);
          try {
            if (url.includes("big")) {
              await delay(15);
              return { ok: false, status: null, error: "timeout" };
            }
            return { ok: true, status: 204, error: null };
          } finally {
            inFlight--;
          }
        }
      }
    );
    await monitor.deliver();
    for (const principal of ["small1", "small2"]) {
      assert.equal(count(db, "SELECT COUNT(*) AS n FROM alerts WHERE principal_id = ? AND delivery_status = 'delivered'", principal), 1, `${principal} is delivered in the first round`);
    }
    assert.equal(maxInFlight, 2, "two workers were busy at once");
    assert.ok(
      posts.some((url) => url.includes("big")),
      "the big account is still served"
    );
    db.close();
  });

  it("deliver() reports every alert it delivered when workers overlap", async () => {
    const db = await openDatabase(":memory:");
    assert.ok(db);
    seed(db, "slow", 1, 1000, "https://slow.example.com/hook");
    seed(db, "fast1", 1, 2000, "https://fast1.example.com/hook");
    seed(db, "fast2", 1, 3000, "https://fast2.example.com/hook");
    const monitor = monitorOn(
      db,
      { now: 10_000_000 },
      {
        options: options({ deliveryConcurrency: 2, deliveryBudgetMs: 5000 }),
        sender: async (url) => {
          if (url.includes("slow")) {
            await delay(20);
            return { ok: false, status: null, error: "timeout" };
          }
          return { ok: true, status: 204, error: null };
        }
      }
    );
    const reported = await monitor.deliver();
    const delivered = count(db, "SELECT COUNT(*) AS n FROM alerts WHERE delivery_status = 'delivered'");
    assert.equal(delivered, 2);
    assert.equal(reported, delivered, "the slow worker's result must not overwrite the fast worker's count");
    db.close();
  });

  it("an account that is alone with due alerts still fills the whole round", async () => {
    const db = await openDatabase(":memory:");
    assert.ok(db);
    seed(db, "solo", 520, 1000, "https://solo.example.com/hook");
    const monitor = monitorOn(db, { now: 10_000_000 }, { options: options({ deliveryBudgetMs: 30_000 }) });
    assert.equal(await monitor.deliver(), 500);
    assert.equal(count(db, "SELECT COUNT(*) AS n FROM alerts WHERE delivery_status = 'pending'"), 20, "the rest waits for the next round");
    db.close();
  });
});

describe("G15: a terminated account's watches are removed", () => {
  it("isTerminated is true only once the account's subscription was deleted", async () => {
    const db = await openDatabase(":memory:");
    assert.ok(db);
    const keys = new KeyRepository(db);
    assert.equal(keys.isTerminated("acct_unknown"), false);
    const issued = keys.issueForCheckout({ checkoutSession: "cs_t", plan: "pro", label: "t", stripeCustomer: "cus_t", stripeSubscription: "sub_t" }, 1);
    assert.ok(issued);
    const id = issued.record.id;
    assert.equal(keys.isTerminated(id), false, "active");
    keys.applySubscriptionEvent({ id: "evt_t1", type: "customer.subscription.updated", created: 10 }, { id: "sub_t", status: "past_due", plan: null }, 10);
    assert.equal(keys.currentPlan(id), null);
    assert.equal(keys.isTerminated(id), false, "a suspended account can still recover");
    keys.applySubscriptionEvent({ id: "evt_t2", type: "customer.subscription.updated", created: 20 }, { id: "sub_t", status: "active", plan: null }, 20);
    assert.ok(keys.rotate(id, 25));
    assert.equal(keys.isTerminated(id), false, "a rotated-out key does not end the account");
    keys.applySubscriptionEvent({ id: "evt_t3", type: "customer.subscription.deleted", created: 30 }, { id: "sub_t", status: "canceled", plan: null }, 30);
    assert.equal(keys.isTerminated(id), true);
    assert.equal(keys.applySubscriptionEvent({ id: "evt_t4", type: "customer.subscription.updated", created: 40 }, { id: "sub_t", status: "active", plan: null }, 40), "terminal");
    assert.equal(keys.isTerminated(id), true, "a late event cannot revive it");
    db.close();
  });

  it("removes a deleted subscription's watches and alerts, stops re-reading it, and only pauses a suspended one", async () => {
    const db = await openDatabase(":memory:");
    assert.ok(db);
    const keys = new KeyRepository(db);
    const gone = keys.issueForCheckout({ checkoutSession: "cs_gone", plan: "pro", label: "g", stripeCustomer: "cus_g", stripeSubscription: "sub_gone" }, 1);
    const lapsed = keys.issueForCheckout({ checkoutSession: "cs_lapsed", plan: "pro", label: "l", stripeCustomer: "cus_l", stripeSubscription: "sub_lapsed" }, 1);
    assert.ok(gone && lapsed);
    const goneP: Principal = { id: gone.record.id, plan: "pro", label: "g", source: "api-key" };
    const lapsedP: Principal = { id: lapsed.record.id, plan: "pro", label: "l", source: "api-key" };

    const clock = { now: 1_000_000 };
    const runs: string[] = [];
    const posts: string[] = [];
    const lookups = new Map<string, number>();
    const monitor = monitorOn(db, clock, {
      options: options({ concurrency: 2 }),
      runner: async (_check, domain) => {
        runs.push(domain);
      },
      sender: async (url) => {
        posts.push(url);
        return { ok: true, status: 200, error: null };
      },
      entitlement: (principalId) => {
        lookups.set(principalId, (lookups.get(principalId) ?? 0) + 1);
        return keys.currentPlan(principalId);
      },
      terminated: (principalId) => keys.isTerminated(principalId)
    });
    const tick = async (): Promise<void> => {
      await monitor.tick(clock.now);
      await monitor.whenDelivered();
    };

    monitor.watch(goneP, "gone-a.com", ["tech"], "https://hooks.example.com/gone", false);
    monitor.watch(goneP, "gone-b.com", ["tech", "email"], null, false);
    monitor.watch(lapsedP, "lapsed.com", ["tech"], null, false);
    await tick();
    assert.equal(runs.length, 4, "baseline checks");

    const hooked = monitor.list(goneP).find((w) => w.domain === "gone-a.com");
    assert.ok(hooked);
    db.prepare(`INSERT INTO alerts (${ALERT_COLUMNS}) VALUES (?, ?, 'gone-a.com', 'tech', 'tech_added', 'x', NULL, 'x', 'medium', ?, ?, 'pending', ?)`).run(
      hooked.id,
      goneP.id,
      clock.now,
      clock.now,
      clock.now
    );

    keys.applySubscriptionEvent({ id: "evt_gone", type: "customer.subscription.deleted", created: 100 }, { id: "sub_gone", status: "canceled", plan: null }, clock.now);
    keys.applySubscriptionEvent({ id: "evt_lapsed1", type: "customer.subscription.updated", created: 100 }, { id: "sub_lapsed", status: "past_due", plan: null }, clock.now);
    clock.now += 25 * HOUR;
    await tick();

    assert.equal(count(db, "SELECT COUNT(*) AS n FROM watches WHERE principal_id = ?", goneP.id), 0, "the terminated account's watches are removed");
    assert.equal(count(db, "SELECT COUNT(*) AS n FROM alerts WHERE principal_id = ?", goneP.id), 0, "with their alerts");
    assert.deepEqual(posts, [], "its pending webhook alert is never posted");
    assert.equal(count(db, "SELECT COUNT(*) AS n FROM monitor_schedule WHERE domain LIKE 'gone-%'"), 0, "its schedule rows are dropped once due");
    assert.deepEqual(
      monitor.list(lapsedP).map((w) => w.pausedReason),
      ["plan_inactive"],
      "a suspended account is only paused"
    );
    assert.equal(runs.length, 4, "neither account is checked");

    lookups.clear();
    clock.now += 60_000;
    await tick();
    assert.equal(lookups.has(goneP.id), false, "a removed account costs nothing on later rounds");
    assert.equal(lookups.get(lapsedP.id), 1);

    keys.applySubscriptionEvent({ id: "evt_lapsed2", type: "customer.subscription.updated", created: 200 }, { id: "sub_lapsed", status: "active", plan: null }, clock.now);
    clock.now += 60_000;
    await tick();
    assert.deepEqual(
      monitor.list(lapsedP).map((w) => w.pausedReason),
      [null],
      "the suspended account resumes when it pays again"
    );
    assert.deepEqual(runs.slice(4), ["lapsed.com"]);
    await monitor.stop();
    db.close();
  });
});

// Round 5: residuals of the fixes above.

const BS = "\\";

describe("G9 (round 5): a URL's host is found the way the URL parser finds it before it is bounded", () => {
  it("rejects over-long hosts behind extra slashes, backslashes, tabs or newlines, and a file URL's '@', before IDNA runs", () => {
    const host = hangul(2030);
    const inputs = [
      `https:///${host}`,
      `https://${BS}${host}`,
      `///${host}`,
      `//${BS}${host}`,
      `https://\t${host}`,
      `https://\n/${host}`,
      `https://\t/${host}`,
      `https://\n${BS}${host}`,
      `https://\r\n\t/${BS}/${host}/x`,
      `https:////${host}/x`,
      // A file URL's host has no userinfo: IDNA runs over all of "<host>@x.com".
      `file://${host}@x.com`,
      // The host is parsed before the bad port fails the URL.
      `https://x@${host}:abc`
    ];
    for (const input of inputs) {
      const result = parseDomain(input);
      assert.equal(result.ok ? null : result.code, "INVALID_DOMAIN", JSON.stringify(input.slice(0, 12)));
    }
    const started = performance.now();
    for (let round = 0; round < 15; round++) for (const input of inputs) parseDomain(input);
    const elapsed = performance.now() - started;
    // new URL() spends about 5 ms of IDNA on each, so 180 parses would take about 0.9 s.
    assert.ok(elapsed < 150, `180 hostile URLs took ${elapsed.toFixed(0)} ms`);
  });

  it("refuses a near-2 MB bulk list of 342 extra-slash URLs without stalling the event loop", () => {
    const lines = Array.from({ length: 342 }, (_, n) => `${n % 2 === 0 ? "https:///" : `https://${BS}`}${hangul(2030, n * 16)}`);
    assert.ok(lines.reduce((sum, line) => sum + Buffer.byteLength(line) + 1, 0) < 2 * 1024 * 1024, "fits the bulk body limit");
    const started = performance.now();
    const { accepted, skipped } = normalizeBulkInputs(lines, false);
    const elapsed = performance.now() - started;
    assert.equal(accepted.length, 0);
    assert.equal(skipped.length, 342);
    assert.ok(skipped.every((s) => s.code === "INVALID_DOMAIN"));
    assert.ok(elapsed < 250, `a free, uncharged submission blocked the event loop for ${elapsed.toFixed(0)} ms`);
  });

  it("still parses valid names in every URL form the parser accepts", () => {
    const emoji = `${Array.from({ length: 4 }, () => "\u{1F600}".repeat(54)).join(".")}.ws`;
    const cases: Array<[string, string]> = [
      ["https:///example.com/a", "example.com"],
      [`https://${BS}example.com`, "example.com"],
      [`//${BS}example.com`, "example.com"],
      ["//example.com/path", "example.com"],
      ["https://\texample.com", "example.com"],
      ["https://\n/ex\tample.com", "example.com"],
      ["https:///user:pw@Bücher.münchen.de:8443/x?y", domainToASCII("bücher.münchen.de")],
      [`https:///${emoji}/`, domainToASCII(emoji)],
      [`//${emoji}`, domainToASCII(emoji)],
      [`https://${"a".repeat(40)}。${"b".repeat(40)}．example｡com/`, `${"a".repeat(40)}.${"b".repeat(40)}.example.com`],
      ["http://example.com:", "example.com"],
      ["file://example.com/x", "example.com"]
    ];
    for (const [input, domain] of cases) {
      const result = parseDomain(input);
      assert.ok(result.ok, `${JSON.stringify(input)}: ${result.ok ? "" : result.error}`);
      assert.equal(result.domain, domain, JSON.stringify(input));
    }
    assert.equal(domainToASCII(emoji).length, 250);
  });
});

// Round 6: Node's parser (ada) departs from the spec once a host contains "[":
// it looks for the closing "]" past the "/", "?" or "\" that ends the host, so
// IDNA runs over the rest of the URL although the bound only measured "x[".

describe("G9 (round 6): a host with '[' after its first character is refused before the URL parser runs IDNA over the rest of the URL", () => {
  it("rejects every unmatched-'[' form in microseconds, whichever delimiter follows it", () => {
    const host = hangul(2030);
    const inputs = [
      `https://x[/${host}`,
      `https://x[?${host}`,
      `https://x[${BS}${host}`,
      `https://u@x[/${host}`,
      `//x[/${host}`,
      `ws://x[/${host}`,
      `https://x[:1/${host}`,
      `https://x[/${host}]`,
      `https://a.com[/${host}`,
      `https://a@b@x[/${host}`
    ];
    for (const input of inputs) {
      const label = JSON.stringify(input.slice(0, 14));
      const result = parseDomain(input);
      assert.equal(result.ok ? null : result.code, "INVALID_DOMAIN", label);
      // Timed per input, so one form that regresses cannot hide among fast ones; the best of three runs keeps a GC pause out of it.
      let best = Infinity;
      for (let trial = 0; trial < 3; trial++) {
        const started = performance.now();
        for (let i = 0; i < 5; i++) parseDomain(input);
        best = Math.min(best, performance.now() - started);
      }
      // new URL() spends about 5 ms of IDNA on each, so 5 parses would take about 25 ms.
      assert.ok(best < 10, `5 parses of ${label} took ${best.toFixed(1)} ms`);
    }
  });

  it("refuses a near-2 MB bulk list of 342 unmatched-'[' URLs, or 1000 with a ':digits' tail, without stalling the event loop", () => {
    const lines = Array.from({ length: 342 }, (_, n) => `https://x[/${hangul(2030, n * 16)}`);
    assert.ok(lines.reduce((sum, line) => sum + Buffer.byteLength(line) + 1, 0) < 2 * 1024 * 1024, "fits the bulk body limit");
    const started = performance.now();
    const { accepted, skipped } = normalizeBulkInputs(lines, false);
    const elapsed = performance.now() - started;
    assert.equal(accepted.length, 0);
    assert.equal(skipped.length, 342);
    assert.ok(skipped.every((s) => s.code === "INVALID_DOMAIN"));
    assert.ok(elapsed < 250, `a free, uncharged submission blocked the event loop for ${elapsed.toFixed(0)} ms`);

    // A milder form: the bound drops the ":digits" that the parser keeps inside the brackets, so every label looked short enough.
    const ported = Array.from({ length: 1000 }, (_, n) => `https://x[${hangul(61, (n * 61) % 10000)}:${"1".repeat(1900)}`);
    assert.ok(ported.reduce((sum, line) => sum + Buffer.byteLength(line) + 1, 0) < 2 * 1024 * 1024, "fits the bulk body limit");
    const portStarted = performance.now();
    const portResult = normalizeBulkInputs(ported, false);
    const portElapsed = performance.now() - portStarted;
    assert.equal(portResult.skipped.length, 1000);
    assert.ok(portResult.skipped.every((s) => s.code === "INVALID_DOMAIN"));
    // About 220 ms when the parser sees these hosts, about 10 ms when they are refused first.
    assert.ok(portElapsed < 100, `1000 bracket-and-port lines blocked the event loop for ${portElapsed.toFixed(0)} ms`);
  });

  it("still reports an IP literal as an IP address, and ignores a '[' outside the host", () => {
    // "[" at the start of the host is an IP literal, which must keep its own message rather than a generic parse failure.
    for (const input of ["https://[::1]/x", "https://[::1]:8443/x", "//[2001:db8::1]/", "https://u@[::1]/"]) {
      const result = parseDomain(input);
      assert.equal(result.ok ? null : result.error, "IP addresses are not supported. Pass a DNS hostname such as example.com.", input);
    }
    for (const input of ["https://u[x@example.com/", "https://u:p[w@example.com/", "https://example.com/[x", "https://example.com/?q=[1]", "https://example.com#[", "https://example.com:443/["]) {
      const result = parseDomain(input);
      assert.ok(result.ok, `${input}: ${result.ok ? "" : result.error}`);
      assert.equal(result.domain, "example.com", input);
    }
  });
});

describe("G10 (round 5): anonymous watches are refused, and retired every round", () => {
  const anon: Principal = { id: "anon_5f5f5f5f5f5f", plan: "free", label: "anonymous", source: "anonymous" };

  it("Monitor.watch refuses an anonymous principal", async () => {
    const db = await openDatabase(":memory:");
    assert.ok(db);
    const monitor = monitorOn(db, { now: 1000 });
    assert.throws(
      () => monitor.watch(anon, "anon.com", ["tech"], "https://hooks.example.com/anon", false),
      (err: unknown) => isToolError(err) && err.code === "UNAUTHORIZED"
    );
    assert.equal(count(db, "SELECT COUNT(*) AS n FROM watches"), 0);
    db.close();
  });

  it("anonymous watches an older process adds after the migration are never scanned, alerted or posted, and are removed a chunk per round", async () => {
    const db = await openDatabase(":memory:");
    assert.ok(db);
    // A v6 process still serving during a rolling deploy inserts these after v7 ran.
    const insertWatch = db.prepare(
      "INSERT INTO watches (id, principal_id, principal_plan, principal_label, principal_source, domain, checks, webhook_url, webhook_secret, created_at, alert_cursor) VALUES (?, ?, 'free', 'anonymous', 'anonymous', ?, 'tech', 'https://hooks.example.com/anon', 'whsec_test', 1000, 0)"
    );
    const insertAlert = db.prepare(`INSERT INTO alerts (${ALERT_COLUMNS}) VALUES (?, ?, ?, 'tech', 'tech_added', 'x', NULL, 'x', 'medium', 1000, 1000, 'pending', 1000)`);
    const insertChange = db.prepare("INSERT INTO changes (domain, kind, change, subject, old_value, new_value, severity, at) VALUES (?, 'tech', 'tech_removed', 'y', 'y', NULL, 'medium', 1000)");
    const schedule = db.prepare("INSERT INTO monitor_schedule (domain, kind, next_at) VALUES (?, 'tech', 1000)");
    transaction(db, () => {
      for (let i = 0; i < 205; i++) {
        insertWatch.run(`watch_anon5_${i}`, `anon_${i}`, `anon5-${i}.com`);
        insertAlert.run(`watch_anon5_${i}`, `anon_${i}`, `anon5-${i}.com`);
        insertChange.run(`anon5-${i}.com`);
        schedule.run(`anon5-${i}.com`);
      }
    });
    const anonymous = (): number => count(db, "SELECT COUNT(*) AS n FROM watches WHERE principal_source = 'anonymous'");

    const clock = { now: 1000 + 25 * HOUR };
    const runs: string[] = [];
    const posts: string[] = [];
    const monitor = monitorOn(db, clock, {
      options: options({ concurrency: 8 }),
      runner: async (check, domain) => {
        runs.push(`${check}:${domain}`);
      },
      sender: async (url) => {
        posts.push(url);
        return { ok: true, status: 200, error: null };
      }
    });
    const keyed: Principal = { id: "acct_keyed5", plan: "pro", label: "k", source: "api-key" };
    monitor.watch(keyed, "keyed5.com", ["tech"], null, false);

    await monitor.tick(clock.now);
    await monitor.whenDelivered();
    assert.equal(anonymous(), 5, "one bounded chunk is removed per round");
    assert.deepEqual(runs, ["tech:keyed5.com"], "no anonymous watch's domain is scanned");
    assert.deepEqual(posts, [], "nothing is posted to an anonymous watch's webhook");
    assert.equal(count(db, "SELECT COUNT(*) AS n FROM alerts WHERE principal_id LIKE 'anon_%' AND change = 'tech_removed'"), 0, "no alerts are raised for the rest");
    assert.equal(count(db, "SELECT COUNT(*) AS n FROM alerts WHERE principal_id LIKE 'anon_%' AND delivery_status = 'pending'"), 0, "their pending deliveries are dropped");
    assert.equal(count(db, "SELECT COUNT(*) AS n FROM monitor_schedule WHERE domain LIKE 'anon5-%'"), 0, "their schedule rows are dropped");

    clock.now += 60_000;
    await monitor.tick(clock.now);
    await monitor.whenDelivered();
    assert.equal(anonymous(), 0);
    assert.equal(count(db, "SELECT COUNT(*) AS n FROM alerts WHERE principal_id LIKE 'anon_%'"), 0, "their alerts go with them");
    assert.deepEqual(posts, []);
    await monitor.stop();
    db.close();
  });
});

describe("G14 (round 5): principals take turns watch by watch", () => {
  it("a healthy tenant is delivered in the first round even when more tenants than workers have slow receivers", async () => {
    const db = await openDatabase(":memory:");
    assert.ok(db);
    const watch = db.prepare(
      "INSERT INTO watches (id, principal_id, principal_plan, principal_label, principal_source, domain, checks, webhook_url, webhook_secret, created_at) VALUES (?, ?, 'enterprise', '', 'api-key', ?, 'tech', ?, 'whsec_test', 0)"
    );
    const alert = db.prepare(`INSERT INTO alerts (${ALERT_COLUMNS}) VALUES (?, ?, ?, 'tech', 'tech_added', 'x', NULL, 'x', 'medium', ?, ?, 'pending', ?)`);
    const seed = (principal: string, watches: number, firstDue: number): void => {
      transaction(db, () => {
        for (let i = 0; i < watches; i++) {
          watch.run(`watch_${principal}_${i}`, principal, `${principal}-${i}.com`, `https://${principal}.example.com/hook`);
          alert.run(`watch_${principal}_${i}`, principal, `${principal}-${i}.com`, firstDue + i, firstDue + i, firstDue + i);
        }
      });
    };
    // deliveryConcurrency + 1 tenants with slow, failing receivers and older backlogs.
    for (const principal of ["slow1", "slow2", "slow3"]) seed(principal, 30, 1000);
    seed("healthy", 1, 90_000);

    const order: string[] = [];
    const busy = new Map<string, number>();
    let inFlight = 0;
    let maxInFlight = 0;
    let doubled = false;
    const monitor = monitorOn(
      db,
      { now: 10_000_000 },
      {
        options: options({ deliveryConcurrency: 2, deliveryBudgetMs: 150 }),
        sender: async (url) => {
          const tenant = new URL(url).hostname.split(".")[0] as string;
          order.push(tenant);
          busy.set(tenant, (busy.get(tenant) ?? 0) + 1);
          if ((busy.get(tenant) ?? 0) > 1) doubled = true;
          maxInFlight = Math.max(maxInFlight, ++inFlight);
          try {
            if (tenant.startsWith("slow")) {
              await delay(15);
              return { ok: false, status: null, error: "timeout" };
            }
            return { ok: true, status: 204, error: null };
          } finally {
            inFlight--;
            busy.set(tenant, (busy.get(tenant) ?? 1) - 1);
          }
        }
      }
    );
    assert.equal(await monitor.deliver(), 1);
    assert.equal(count(db, "SELECT COUNT(*) AS n FROM alerts WHERE principal_id = 'healthy' AND delivery_status = 'delivered'"), 1, "the healthy tenant is delivered in the first round");
    const turn = order.indexOf("healthy");
    // Before the fix each worker drained one slow tenant's 30 watches (450 ms), so the round ended first.
    assert.ok(turn >= 0 && turn < 4, `the healthy tenant waited behind ${turn} POSTs: ${order.join(",")}`);
    assert.equal(maxInFlight, 2, "both workers were busy at once");
    assert.equal(doubled, false, "no tenant ever held two workers");
    db.close();
  });
});

describe("G15 (round 5): termination follows the subscription's status", () => {
  it("an account whose subscription was deleted while billing had suspended its key is terminated, and its key is relabelled", async () => {
    const db = await openDatabase(":memory:");
    assert.ok(db);
    const keys = new KeyRepository(db);
    const keyRow = (accountId: string): { active: number; reason: string | null; at: number | null } => {
      const row = db.prepare("SELECT active, deactivated_reason, deactivated_at FROM api_keys WHERE account_id = ?").get(accountId) as {
        active: number;
        deactivated_reason: string | null;
        deactivated_at: number | null;
      };
      return { active: Number(row.active), reason: row.deactivated_reason, at: row.deactivated_at === null ? null : Number(row.deactivated_at) };
    };

    // The dunning path: past_due, then unpaid or canceled, then deleted.
    for (const status of ["past_due", "unpaid", "canceled"]) {
      const issued = keys.issueForCheckout({ checkoutSession: `cs_${status}`, plan: "pro", label: status, stripeCustomer: `cus_${status}`, stripeSubscription: `sub_${status}` }, 1);
      assert.ok(issued);
      const id = issued.record.id;
      keys.applySubscriptionEvent({ id: `evt_${status}_1`, type: "customer.subscription.updated", created: 10 }, { id: `sub_${status}`, status, plan: null }, 10);
      assert.equal(keys.isTerminated(id), false, `${status}: suspended, not ended`);
      assert.equal(keys.applySubscriptionEvent({ id: `evt_${status}_2`, type: "customer.subscription.deleted", created: 20 }, { id: `sub_${status}`, status: "canceled", plan: null }, 20), "applied");
      assert.equal(keys.isTerminated(id), true, `${status} -> deleted`);
      assert.deepEqual(keyRow(id), { active: 0, reason: "subscription_deleted", at: 10 }, `${status}: relabelled, keeping when the key stopped working`);
    }

    // A key issued while its payment was pending cannot be turned on once the subscription is deleted.
    const pending = keys.issueForCheckout({ checkoutSession: "cs_pending5", plan: "pro", label: "p", stripeCustomer: "cus_p5", stripeSubscription: "sub_pending5", pending: true }, 1);
    assert.ok(pending);
    keys.applySubscriptionEvent({ id: "evt_pending5", type: "customer.subscription.deleted", created: 20 }, { id: "sub_pending5", status: "canceled", plan: null }, 20);
    assert.equal(keys.isTerminated(pending.record.id), true);
    assert.equal(keyRow(pending.record.id).reason, "subscription_deleted");
    assert.equal(keys.activatePendingCheckout("cs_pending5"), false);

    // Rows written before deletions relabelled suspended keys still count as ended.
    const legacy = keys.issueForCheckout({ checkoutSession: "cs_legacy5", plan: "pro", label: "l", stripeCustomer: "cus_l5", stripeSubscription: "sub_legacy5" }, 1);
    assert.ok(legacy);
    keys.applySubscriptionEvent({ id: "evt_legacy5_1", type: "customer.subscription.updated", created: 10 }, { id: "sub_legacy5", status: "past_due", plan: null }, 10);
    keys.applySubscriptionEvent({ id: "evt_legacy5_2", type: "customer.subscription.deleted", created: 20 }, { id: "sub_legacy5", status: "canceled", plan: null }, 20);
    db.prepare("UPDATE api_keys SET deactivated_reason = 'subscription_past_due' WHERE account_id = ?").run(legacy.record.id);
    assert.equal(keys.isTerminated(legacy.record.id), true);

    // A rotated-out key keeps its reason, and an account with a live key is not ended.
    const live = keys.issueForCheckout({ checkoutSession: "cs_live5", plan: "pro", label: "v", stripeCustomer: "cus_v5", stripeSubscription: "sub_live5" }, 1);
    assert.ok(live);
    assert.ok(keys.rotate(live.record.id, 5));
    assert.equal(keys.isTerminated(live.record.id), false);
    keys.applySubscriptionEvent({ id: "evt_live5", type: "customer.subscription.deleted", created: 20 }, { id: "sub_live5", status: "canceled", plan: null }, 20);
    assert.equal(keys.isTerminated(live.record.id), true);
    assert.deepEqual(
      (db.prepare("SELECT deactivated_reason AS reason FROM api_keys WHERE account_id = ? ORDER BY created_at, source").all(live.record.id) as Array<{ reason: string }>).map((r) => r.reason),
      ["rotated", "subscription_deleted"]
    );
    db.close();
  });

  it("removes the watches of an account that lapsed through failed payments before its subscription was deleted", async () => {
    const db = await openDatabase(":memory:");
    assert.ok(db);
    const keys = new KeyRepository(db);
    const issued = keys.issueForCheckout({ checkoutSession: "cs_dunning", plan: "pro", label: "d", stripeCustomer: "cus_d", stripeSubscription: "sub_dunning" }, 1);
    assert.ok(issued);
    const principal: Principal = { id: issued.record.id, plan: "pro", label: "d", source: "api-key" };
    const clock = { now: 1_000_000 };
    const posts: string[] = [];
    const lookups: string[] = [];
    const monitor = monitorOn(db, clock, {
      sender: async (url) => {
        posts.push(url);
        return { ok: true, status: 200, error: null };
      },
      entitlement: (principalId) => {
        lookups.push(principalId);
        return keys.currentPlan(principalId);
      },
      terminated: (principalId) => keys.isTerminated(principalId)
    });
    const tick = async (): Promise<void> => {
      await monitor.tick(clock.now);
      await monitor.whenDelivered();
    };
    const hooked = monitor.watch(principal, "dunning-a.com", ["tech"], "https://hooks.example.com/dunning", false).watch;
    monitor.watch(principal, "dunning-b.com", ["tech"], null, false);
    await tick();

    keys.applySubscriptionEvent({ id: "evt_dunning1", type: "customer.subscription.updated", created: 100 }, { id: "sub_dunning", status: "past_due", plan: null }, clock.now);
    clock.now += 25 * HOUR;
    await tick();
    assert.deepEqual(
      monitor.list(principal).map((w) => w.pausedReason),
      ["plan_inactive", "plan_inactive"],
      "a suspended account is only paused"
    );

    db.prepare(`INSERT INTO alerts (${ALERT_COLUMNS}) VALUES (?, ?, 'dunning-a.com', 'tech', 'tech_added', 'x', NULL, 'x', 'medium', ?, ?, 'pending', ?)`).run(
      hooked.id,
      principal.id,
      clock.now,
      clock.now,
      clock.now
    );
    keys.applySubscriptionEvent({ id: "evt_dunning2", type: "customer.subscription.deleted", created: 200 }, { id: "sub_dunning", status: "canceled", plan: null }, clock.now);
    clock.now += 60_000;
    await tick();
    assert.equal(count(db, "SELECT COUNT(*) AS n FROM watches WHERE principal_id = ?", principal.id), 0, "its watches are removed, not paused forever");
    assert.equal(count(db, "SELECT COUNT(*) AS n FROM alerts WHERE principal_id = ?", principal.id), 0, "with their alerts");
    assert.deepEqual(posts, [], "its pending webhook alert is never posted");

    lookups.length = 0;
    clock.now += 60_000;
    await tick();
    assert.equal(lookups.includes(principal.id), false, "and it is not re-read on later rounds");
    await monitor.stop();
    db.close();
  });
});

describe("Terminated accounts (round 5): removal is bounded per round and cascades through alerts_by_watch", () => {
  it("every statement that removes watches reaches their alerts through alerts_by_watch, not a scan of all alerts", async () => {
    const db = await openDatabase(":memory:");
    assert.ok(db);
    const statements: Array<[string, Array<string | number>]> = [
      // A terminated account's chunk, the anonymous sweep, and unwatch().
      ["DELETE FROM watches WHERE id IN (SELECT id FROM watches WHERE principal_id = ? LIMIT ?)", ["acct_x", 200]],
      ["DELETE FROM watches WHERE id IN (SELECT id FROM watches WHERE principal_source = 'anonymous' LIMIT ?)", [200]],
      ["DELETE FROM watches WHERE id = ?", ["watch_x"]]
    ];
    for (const [sql, params] of statements) {
      const details = (db.prepare(`EXPLAIN QUERY PLAN ${sql}`).all(...params) as Array<{ detail: string }>).map((r) => r.detail);
      assert.ok(
        details.some((d) => /^SEARCH alerts USING (COVERING )?INDEX alerts_by_watch\b/.test(d)),
        `${sql}: ${details.join(" | ")}`
      );
      assert.ok(!details.some((d) => /^SCAN alerts\b/.test(d)), `${sql}: ${details.join(" | ")}`);
    }
    db.close();
  });

  it("removes at most 200 watches per round, pausing the rest and dropping their pending deliveries until their turn", async () => {
    const db = await openDatabase(":memory:");
    assert.ok(db);
    const keys = new KeyRepository(db);
    const big = keys.issueForCheckout({ checkoutSession: "cs_big5", plan: "enterprise", label: "b", stripeCustomer: "cus_b5", stripeSubscription: "sub_big5" }, 1);
    const small = keys.issueForCheckout({ checkoutSession: "cs_small5", plan: "pro", label: "s", stripeCustomer: "cus_s5", stripeSubscription: "sub_small5" }, 1);
    assert.ok(big && small);
    const bigP: Principal = { id: big.record.id, plan: "enterprise", label: "b", source: "api-key" };
    const smallP: Principal = { id: small.record.id, plan: "pro", label: "s", source: "api-key" };
    const other: Principal = { id: "acct_other5", plan: "pro", label: "o", source: "api-key" };

    const clock = { now: 1_000_000 };
    const runs: string[] = [];
    const posts: string[] = [];
    const monitor = monitorOn(db, clock, {
      options: options({ concurrency: 8 }),
      runner: async (_check, domain) => {
        runs.push(domain);
      },
      sender: async (url) => {
        posts.push(url);
        return { ok: true, status: 200, error: null };
      },
      entitlement: (principalId) => keys.currentPlan(principalId),
      terminated: (principalId) => keys.isTerminated(principalId)
    });
    for (let i = 0; i < 430; i++) monitor.watch(bigP, `big5-${i}.com`, ["tech"], "https://hooks.example.com/big", false);
    for (let i = 0; i < 30; i++) monitor.watch(smallP, `small5-${i}.com`, ["tech"], "https://hooks.example.com/small", false);
    monitor.watch(other, "other5.com", ["tech"], null, false);
    db.prepare(
      `INSERT INTO alerts (${ALERT_COLUMNS}) SELECT id, principal_id, domain, 'tech', 'tech_added', 'x', NULL, 'x', 'medium', 1000, 1000, 'pending', 1000 FROM watches WHERE principal_id IN (?, ?)`
    ).run(bigP.id, smallP.id);

    for (const sub of ["sub_big5", "sub_small5"]) {
      keys.applySubscriptionEvent({ id: `evt_${sub}`, type: "customer.subscription.deleted", created: 10 }, { id: sub, status: "canceled", plan: null }, clock.now);
    }
    const left = (): number => count(db, "SELECT COUNT(*) AS n FROM watches WHERE principal_id IN (?, ?)", bigP.id, smallP.id);
    const active = (): number => count(db, "SELECT COUNT(*) AS n FROM watches WHERE principal_id IN (?, ?) AND paused_reason IS NULL", bigP.id, smallP.id);
    const pending = (): number => count(db, "SELECT COUNT(*) AS n FROM alerts WHERE principal_id IN (?, ?) AND delivery_status = 'pending'", bigP.id, smallP.id);
    const tick = async (): Promise<void> => {
      await monitor.tick(clock.now);
      await monitor.whenDelivered();
    };

    clock.now += 25 * HOUR;
    await tick();
    assert.equal(left(), 460 - 200, "one chunk of 200 in the first round, across both accounts");
    assert.equal(active(), 0, "the rest are paused until their turn");
    assert.equal(pending(), 0, "and their pending deliveries dropped");
    assert.deepEqual(runs, ["other5.com"], "only the live tenant's domain is scanned");
    assert.deepEqual(posts, [], "nothing is posted for the terminated accounts");

    clock.now += 60_000;
    await tick();
    assert.equal(left(), 60);
    clock.now += 60_000;
    await tick();
    assert.equal(left(), 0);
    assert.equal(count(db, "SELECT COUNT(*) AS n FROM alerts WHERE principal_id IN (?, ?)", bigP.id, smallP.id), 0, "their alerts went with them");
    assert.equal(count(db, "SELECT COUNT(*) AS n FROM watches WHERE principal_id = ?", other.id), 1, "the live tenant keeps its watch");
    assert.deepEqual(posts, []);
    await monitor.stop();
    db.close();
  });
});
