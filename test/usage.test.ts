import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { setLogLevel } from "../src/logger.js";
import { REDEEMED_PAYMENT_RETENTION_MS, UsageTracker } from "../src/middleware/usage.js";

setLogLevel("silent");

describe("UsageTracker", () => {
  it("records calls, credits and redeemed payments in memory", () => {
    const usage = new UsageTracker(null);
    usage.record("p1", "pro", "Acme", "inspect_tech_stack", 1);
    usage.record("p1", "pro", "Acme", "comprehensive_audit", 2);
    const record = usage.get("p1");
    assert.equal(record?.totalCalls, 2);
    assert.equal(record?.totalCredits, 3);
    assert.deepEqual(record?.byTool, { inspect_tech_stack: 1, comprehensive_audit: 1 });
    assert.equal(usage.creditsRemaining("p1"), null);

    usage.addCredits("pay1", "payg", "stripe:pi_1", 5);
    assert.equal(usage.consumeCredits("pay1", 2), true);
    assert.equal(usage.creditsRemaining("pay1"), 3);
    assert.equal(usage.consumeCredits("pay1", 4), false);
    assert.equal(usage.creditsRemaining("pay1"), 3);
    assert.equal(usage.consumeCredits("unknown", 1), false);

    assert.equal(usage.isPaymentRedeemed("pi_1"), false);
    usage.markPaymentRedeemed("pi_1");
    assert.equal(usage.isPaymentRedeemed("pi_1"), true);
    assert.deepEqual(usage.stats(), { principals: 2, totalCalls: 2, totalCredits: 3 });
  });

  it("persists to disk and reloads", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "sdm-usage-"));
    const file = path.join(dir, "nested", "usage.json");
    try {
      const writer = new UsageTracker(file);
      await writer.load();
      writer.record("p1", "free", "Trial", "verify_email_infrastructure", 1);
      writer.addCredits("pay1", "payg", "x402:tx", 10);
      writer.markPaymentRedeemed("x402_tx");
      await writer.close();

      const raw = JSON.parse(await readFile(file, "utf8")) as { version: number; principals: Record<string, unknown>; redeemedPayments: Array<{ id: string; at: string }>; settlements: unknown[] };
      // Round 8 (P-H): version 3 also carries the x402 settlement markers kept without a database.
      assert.equal(raw.version, 3);
      assert.deepEqual(raw.settlements, []);
      assert.ok("p1" in raw.principals);
      assert.equal(raw.redeemedPayments.length, 1);
      assert.equal(raw.redeemedPayments[0]?.id, "x402_tx");
      assert.ok(Number.isFinite(Date.parse(raw.redeemedPayments[0]?.at ?? "")), "redeemed ids carry their redemption time");

      const reader = new UsageTracker(file);
      await reader.load();
      assert.equal(reader.get("p1")?.totalCalls, 1);
      assert.equal(reader.creditsRemaining("pay1"), 10);
      assert.equal(reader.isPaymentRedeemed("x402_tx"), true);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("loads version 1 ledgers whose redeemed ids are bare strings", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "sdm-usage-"));
    const file = path.join(dir, "usage.json");
    try {
      await writeFile(file, JSON.stringify({ version: 1, updatedAt: "2026-01-01T00:00:00.000Z", principals: {}, redeemedPayments: ["pi_legacy", "x402_legacy"] }), "utf8");
      const reader = new UsageTracker(file);
      await reader.load();
      assert.equal(reader.isPaymentRedeemed("pi_legacy"), true);
      assert.equal(reader.isPaymentRedeemed("x402_legacy"), true);
      assert.equal(reader.redeemedCount, 2);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("starts empty when the file is missing or corrupt", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "sdm-usage-"));
    try {
      const missing = new UsageTracker(path.join(dir, "missing.json"));
      await missing.load();
      assert.equal(missing.stats().principals, 0);
      const corruptPath = path.join(dir, "corrupt.json");
      await writeFile(corruptPath, "{not json", "utf8");
      const corrupt = new UsageTracker(corruptPath);
      await corrupt.load();
      assert.equal(corrupt.stats().principals, 0);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("keeps the ledger dirty when a write fails so close() persists it later", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "sdm-usage-"));
    try {
      // The parent of the target path is a regular file, so mkdir/write fail.
      const blocker = path.join(dir, "blocker");
      await writeFile(blocker, "x", "utf8");
      const target = path.join(blocker, "usage.json");
      const tracker = new UsageTracker(target);
      tracker.addCredits("pay1", "payg", "stripe:pi_1", 100);
      tracker.markPaymentRedeemed("pi_1");
      await assert.rejects(() => tracker.flush(), "a write into a non-directory fails");
      // Unblock the path and close: the state must still be written.
      await rm(blocker, { force: true });
      await tracker.close();
      const raw = JSON.parse(await readFile(target, "utf8")) as { principals: Record<string, { creditsRemaining: number }>; redeemedPayments: Array<{ id: string }> };
      assert.equal(raw.principals.pay1?.creditsRemaining, 100);
      assert.deepEqual(
        raw.redeemedPayments.map((r) => r.id),
        ["pi_1"]
      );
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("close() waits for a flush that is already in flight even when nothing new is dirty", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "sdm-usage-"));
    const file = path.join(dir, "usage.json");
    try {
      const tracker = new UsageTracker(file);
      // Enough state that the write is genuinely asynchronous.
      for (let i = 0; i < 20000; i++) tracker.record(`key_${i}`, "pro", "bulk", "inspect_tech_stack", 1);
      tracker.addCredits("pay_last", "payg", "stripe:pi_last", 500);
      tracker.markPaymentRedeemed("pi_last");
      const background = tracker.flush();
      // close() lands while the background write is in flight and dirty is already false.
      await tracker.close();
      const raw = JSON.parse(await readFile(file, "utf8")) as { principals: Record<string, { creditsRemaining: number | null }>; redeemedPayments: Array<{ id: string }> };
      assert.equal(raw.principals.pay_last?.creditsRemaining, 500);
      assert.ok(raw.redeemedPayments.some((r) => r.id === "pi_last"));
      assert.equal(Object.keys(raw.principals).length, 20001);
      await background;
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("sweeps temp files left by a crashed writer and persists mutations that land during close()", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "sdm-usage-"));
    const file = path.join(dir, "usage.json");
    try {
      await writeFile(`${file}.4242.deadbeef.tmp`, "{", "utf8");
      await writeFile(path.join(dir, "unrelated.tmp"), "{", "utf8");
      const tracker = new UsageTracker(file);
      await tracker.load();
      const { readdir } = await import("node:fs/promises");
      const entries = await readdir(dir);
      assert.ok(!entries.includes("usage.json.4242.deadbeef.tmp"), "orphaned temp files of this ledger are removed at load");
      assert.ok(entries.includes("unrelated.tmp"), "other files are left alone");

      for (let i = 0; i < 20000; i++) tracker.record(`key_${i}`, "pro", "bulk", "inspect_tech_stack", 1);
      const closing = tracker.close();
      // Lands after close() started its final write.
      tracker.addCredits("pay_late", "payg", "stripe:pi_late", 7);
      await closing;
      const raw = JSON.parse(await readFile(file, "utf8")) as { principals: Record<string, { creditsRemaining: number | null }> };
      assert.equal(raw.principals.pay_late?.creditsRemaining, 7, "a mutation during the final write is flushed by close()");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("retains redeemed ids by age rather than by count", () => {
    const usage = new UsageTracker(null, { redeemedRetentionMs: 1000 });
    const now = Date.now();
    usage.markPaymentRedeemed("old", now - 5000);
    usage.markPaymentRedeemed("fresh", now);
    assert.equal(usage.isPaymentRedeemed("fresh"), true);
    assert.equal(usage.isPaymentRedeemed("old"), false, "an id past the retention window is forgotten");
    assert.equal(REDEEMED_PAYMENT_RETENTION_MS >= 365 * 24 * 60 * 60 * 1000, true, "the default retention outlives card dispute windows");
    // Volume alone never evicts: many fresh ids all stay redeemed.
    for (let i = 0; i < 5000; i++) usage.markPaymentRedeemed(`pi_${i}`, now);
    assert.equal(usage.isPaymentRedeemed("pi_0"), true);
    assert.equal(usage.isPaymentRedeemed("fresh"), true);
  });

  it("drops idle unfunded per-payment principals but never API-key principals", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "sdm-usage-"));
    const file = path.join(dir, "usage.json");
    try {
      const stale = new Date(Date.now() - 200 * 24 * 60 * 60 * 1000).toISOString();
      const principals = {
        key_abc: { principalId: "key_abc", plan: "pro", label: "Acme", totalCalls: 3, totalCredits: 3, byTool: {}, creditsRemaining: null, firstSeen: stale, lastSeen: stale },
        pay_spent: { principalId: "pay_spent", plan: "payg", label: "stripe:pi_1", totalCalls: 100, totalCredits: 100, byTool: {}, creditsRemaining: 0, firstSeen: stale, lastSeen: stale },
        pay_funded: { principalId: "pay_funded", plan: "payg", label: "stripe:pi_2", totalCalls: 1, totalCredits: 1, byTool: {}, creditsRemaining: 99, firstSeen: stale, lastSeen: stale },
        anon_old: { principalId: "anon_old", plan: "free", label: "anonymous", totalCalls: 1, totalCredits: 1, byTool: {}, creditsRemaining: null, firstSeen: stale, lastSeen: stale }
      };
      await writeFile(file, JSON.stringify({ version: 2, updatedAt: stale, principals, redeemedPayments: [] }), "utf8");
      const tracker = new UsageTracker(file);
      await tracker.load();
      assert.ok(tracker.get("key_abc"), "API-key counters are permanent");
      assert.ok(tracker.get("pay_funded"), "a principal holding credits is kept");
      assert.equal(tracker.get("pay_spent"), undefined);
      assert.equal(tracker.get("anon_old"), undefined);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
