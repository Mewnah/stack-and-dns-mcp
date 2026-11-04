import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { describe, it } from "node:test";
import { DEFAULT_WATCH_LIMITS } from "../src/config.js";
import { ToolError } from "../src/lib/errors.js";
import type { WebhookDelivery } from "../src/lib/webhook.js";
import { setLogLevel } from "../src/logger.js";
import type { Principal } from "../src/middleware/auth.js";
import { UsageTracker } from "../src/middleware/usage.js";
import { openDatabase } from "../src/store/db.js";
import { Monitor, type MonitorCheck, type MonitorOptions } from "../src/store/monitor.js";
import { ScanStore, type TechScanInput } from "../src/store/scanStore.js";

setLogLevel("silent");

const HOUR = 60 * 60 * 1000;
const alice: Principal = { id: "acct_alice", plan: "pro", label: "Alice", source: "api-key" };
const bob: Principal = { id: "acct_bob", plan: "pro", label: "Bob", source: "api-key" };
const payer: Principal = { id: "pay_carol", plan: "payg", label: "Carol", source: "session" };

function tech(domain: string, ids: string[]): TechScanInput {
  return {
    domain,
    partial: false,
    fetch: { ok: true, status: 200, finalHost: domain, truncated: false, error: null },
    blocked: { blocked: false, vendor: null, challengeType: null, reason: null },
    technologies: ids.map((id) => ({ id, name: id.toUpperCase(), category: "analytics", version: null, implied: false })),
    security: { score: 70, grade: "C" }
  } as unknown as TechScanInput;
}

interface Harness {
  monitor: Monitor;
  store: ScanStore;
  usage: UsageTracker;
  /** Technologies the fake site serves; change it between ticks. */
  site: Map<string, string[]>;
  runs: Array<{ check: MonitorCheck; domain: string }>;
  deliveries: Array<{ url: string; body: string; headers: Record<string, string> }>;
  clock: { now: number };
  /** Make the next run of a domain fail with this error. */
  failNext: Map<string, Error>;
  delivery: { result: WebhookDelivery };
}

async function harness(options: Partial<MonitorOptions> = {}): Promise<Harness> {
  const db = await openDatabase(":memory:");
  assert.ok(db);
  const store = new ScanStore(db, { retentionDays: 30 });
  const usage = new UsageTracker(null);
  const site = new Map<string, string[]>();
  const runs: Harness["runs"] = [];
  const deliveries: Harness["deliveries"] = [];
  const clock = { now: 1_000_000 };
  const failNext = new Map<string, Error>();
  const delivery = { result: { ok: true, status: 200, error: null } as WebhookDelivery };
  const monitor = new Monitor({
    clock: () => clock.now,
    db,
    usage,
    runner: async (check, domain) => {
      runs.push({ check, domain });
      const failure = failNext.get(domain);
      if (failure) {
        failNext.delete(domain);
        throw failure;
      }
      store.recordTech(tech(domain, site.get(domain) ?? []), "monitor", clock.now);
    },
    sender: async (url, body, headers) => {
      deliveries.push({ url, body, headers });
      return delivery.result;
    },
    options: {
      intervalMs: 24 * HOUR,
      retryMs: HOUR,
      creditsPerCheck: 1,
      concurrency: 2,
      checkTimeoutMs: 2000,
      tickMs: 60_000,
      maxWatches: { ...DEFAULT_WATCH_LIMITS, pro: 3 },
      webhook: { allowInsecure: false, allowPrivate: false },
      deliveryBackoffMs: [60_000, 300_000],
      alertRetentionDays: 90,
      ...options
    }
  });
  return { monitor, store, usage, site, runs, deliveries, clock, failNext, delivery };
}

/** Advances the clock and runs one scheduling round. */
async function tickAt(h: Harness, at: number): Promise<void> {
  h.clock.now = at;
  await h.monitor.tick(at);
  await h.monitor.whenDelivered();
}

describe("Monitor alerts", () => {
  it("turns changes found by scheduled checks into alerts for the watcher", async () => {
    const h = await harness();
    h.site.set("acme.com", ["ga"]);
    h.monitor.watch(alice, "https://www.acme.com/pricing", ["tech"], null, false);
    await tickAt(h, h.clock.now);
    assert.deepEqual(h.runs, [{ check: "tech", domain: "acme.com" }], "the first check runs right away and is a baseline");
    assert.equal(h.monitor.alerts(alice, {}).alerts.length, 0);
    h.site.set("acme.com", ["ga", "klaviyo"]);
    await tickAt(h, h.clock.now + HOUR);
    assert.equal(h.runs.length, 1, "not due again for a day");
    await tickAt(h, h.clock.now + 24 * HOUR);
    assert.equal(h.runs.length, 2);
    const { alerts } = h.monitor.alerts(alice, {});
    assert.deepEqual(
      alerts.map((a) => [a.domain, a.change, a.subject]),
      [["acme.com", "tech_added", "klaviyo"]]
    );
    assert.equal(alerts[0]?.delivery.status, "none", "no webhook configured");
    assert.equal(h.monitor.alerts(alice, {}).alerts.length, 0, "read alerts are not returned again");
    assert.equal(h.monitor.alerts(alice, { unreadOnly: false }).alerts.length, 1);
  });

  it("a new watch only hears about changes recorded after it was created", async () => {
    const h = await harness();
    h.store.recordTech(tech("old.com", ["a"]), "call", 1);
    h.store.recordTech(tech("old.com", ["a", "b"]), "call", 2);
    h.monitor.watch(alice, "old.com", ["tech"], null, false);
    h.monitor.collectAlerts();
    assert.equal(h.monitor.alerts(alice, {}).alerts.length, 0);
    h.store.recordTech(tech("old.com", ["a", "b", "c"]), "call", 3);
    assert.deepEqual(
      h.monitor.alerts(alice, {}).alerts.map((a) => a.subject),
      ["c"],
      "a change from a direct call reaches the watcher"
    );
  });

  it("checks a domain once however many callers watch it, and filters alerts by each watch's checks", async () => {
    const h = await harness();
    h.site.set("shared.com", ["ga"]);
    h.monitor.watch(alice, "shared.com", ["tech"], null, false);
    h.monitor.watch(bob, "shared.com", ["email"], null, false);
    await tickAt(h, h.clock.now);
    assert.equal(h.runs.filter((r) => r.check === "tech").length, 1);
    h.site.set("shared.com", []);
    await tickAt(h, h.clock.now + 24 * HOUR);
    await tickAt(h, h.clock.now + 24 * HOUR);
    assert.equal(h.runs.filter((r) => r.check === "tech").length, 3, "one tech check per interval, not one per watcher");
    assert.deepEqual(
      h.monitor.alerts(alice, {}).alerts.map((a) => a.change),
      ["tech_removed"]
    );
    assert.equal(h.monitor.alerts(bob, {}).alerts.length, 0, "bob watches email only");
  });

  it("raises domain_not_found once per transition and retries retryable failures sooner", async () => {
    const h = await harness();
    h.site.set("gone.com", ["ga"]);
    h.monitor.watch(alice, "gone.com", ["tech"], null, false);
    await tickAt(h, h.clock.now);
    h.failNext.set("gone.com", new ToolError("NETWORK_ERROR", "resolver down", { retryable: true }));
    await tickAt(h, h.clock.now + 24 * HOUR);
    assert.equal(h.monitor.alerts(alice, {}).alerts.length, 0, "a retryable failure is not an alert");
    const nextAt = Date.parse(h.monitor.list(alice)[0]?.nextCheckAt ?? "");
    assert.equal(nextAt, h.clock.now + HOUR, "retried after retryMs, not a full interval");
    h.failNext.set("gone.com", new ToolError("DOMAIN_NOT_FOUND", "NXDOMAIN"));
    await tickAt(h, nextAt);
    h.failNext.set("gone.com", new ToolError("DOMAIN_NOT_FOUND", "NXDOMAIN"));
    await tickAt(h, h.clock.now + 24 * HOUR);
    const alerts = h.monitor.alerts(alice, {}).alerts;
    assert.deepEqual(
      alerts.map((a) => [a.change, a.severity]),
      [["domain_not_found", "high"]],
      "raised once, not on every failed check"
    );
  });
});

describe("Monitor billing and limits", () => {
  it("charges prepaid watchers per check, pauses when unfunded, and resumes after a top-up", async () => {
    const h = await harness();
    h.site.set("paid.com", ["ga"]);
    h.usage.addCredits(payer.id, payer.plan, payer.label, 1);
    h.monitor.watch(payer, "paid.com", ["tech"], null, false);
    await tickAt(h, h.clock.now);
    assert.equal(h.usage.creditsRemaining(payer.id), 0, "one credit per scheduled check");
    await tickAt(h, h.clock.now + 24 * HOUR);
    assert.equal(h.runs.length, 1, "no credits, no check");
    const watch = h.monitor.list(payer)[0];
    assert.equal(watch?.paused, true);
    assert.deepEqual(
      h.monitor.alerts(payer, {}).alerts.map((a) => a.change),
      ["watch_paused"]
    );
    h.usage.addCredits(payer.id, payer.plan, payer.label, 5);
    await tickAt(h, h.clock.now + 60_000);
    assert.equal(h.monitor.list(payer)[0]?.paused, false, "resumed on the next tick after the top-up");
    assert.equal(h.runs.length, 2, "and checked right away");
    assert.equal(h.usage.creditsRemaining(payer.id), 4);
  });

  it("refunds prepaid watchers when a check fails for a retryable reason", async () => {
    const h = await harness();
    h.usage.addCredits(payer.id, payer.plan, payer.label, 3);
    h.monitor.watch(payer, "flaky.com", ["tech"], null, false);
    h.failNext.set("flaky.com", new Error("socket hang up"));
    await tickAt(h, h.clock.now);
    assert.equal(h.usage.creditsRemaining(payer.id), 3);
  });

  it("enforces the plan's watch limit and keeps watches private", async () => {
    const h = await harness();
    for (const d of ["a.com", "b.com", "c.com"]) h.monitor.watch(alice, d, ["email"], null, false);
    assert.throws(
      () => h.monitor.watch(alice, "d.com", ["email"], null, false),
      (err: unknown) => err instanceof ToolError && err.code === "LIMIT_EXCEEDED"
    );
    const again = h.monitor.watch(alice, "a.com", ["email", "tech"], null, false);
    assert.equal(again.created, false, "re-watching updates instead of counting against the limit");
    assert.deepEqual(again.watch.checks, ["email", "tech"]);
    const id = again.watch.id;
    assert.equal(h.monitor.unwatch(bob, { watchId: id }), false, "another caller cannot remove it");
    assert.equal(h.monitor.list(bob).length, 0);
    assert.equal(h.monitor.unwatch(alice, { domain: "WWW.A.COM" }), true);
    assert.equal(h.monitor.list(alice).length, 2);
  });

  it("rejects insecure, private and credential-bearing webhook URLs", async () => {
    const h = await harness();
    const code = (url: string): string | null => {
      try {
        h.monitor.watch(alice, "hook.com", ["email"], url, false);
        return null;
      } catch (err) {
        return err instanceof ToolError ? err.code : "other";
      }
    };
    assert.equal(code("http://hooks.example.com/x"), "INVALID_ARGUMENT");
    assert.equal(code("https://10.0.0.5/x"), "INVALID_ARGUMENT");
    assert.equal(code("https://[::1]/x"), "INVALID_ARGUMENT");
    assert.equal(code("https://metadata.internal/x"), "INVALID_ARGUMENT");
    assert.equal(code("https://user:pw@hooks.example.com/x"), "INVALID_ARGUMENT");
    assert.equal(code("https://hooks.example.com/x"), null);
  });
});

describe("Monitor webhooks", () => {
  it("signs deliveries with the watch secret and retries failures with backoff", async () => {
    const h = await harness();
    h.site.set("hooked.com", ["ga"]);
    const { webhookSecret } = h.monitor.watch(alice, "hooked.com", ["tech"], "https://hooks.example.com/in#frag", false);
    assert.ok(webhookSecret);
    await tickAt(h, h.clock.now);
    h.site.set("hooked.com", ["ga", "hotjar"]);
    h.delivery.result = { ok: false, status: 503, error: "HTTP 503" };
    await tickAt(h, h.clock.now + 24 * HOUR);
    assert.equal(h.deliveries.length, 1);
    const first = h.deliveries[0];
    assert.ok(first);
    assert.equal(first.url, "https://hooks.example.com/in", "the fragment is dropped");
    const signature = first.headers["x-stackdns-signature"] ?? "";
    const [, t, v1] = /^t=(\d+),v1=([0-9a-f]{64})$/.exec(signature) ?? [];
    assert.ok(t && v1, signature);
    assert.equal(createHmac("sha256", webhookSecret).update(`${t}.${first.body}`).digest("hex"), v1, "receivers can verify the body");
    const body = JSON.parse(first.body) as { type: string; alerts: Array<{ change: string; subject: string }> };
    assert.equal(body.type, "domain.changes");
    assert.deepEqual(
      body.alerts.map((a) => [a.change, a.subject]),
      [["tech_added", "hotjar"]]
    );
    assert.equal(h.monitor.alerts(alice, { markRead: false }).alerts[0]?.delivery.status, "pending");

    await tickAt(h, h.clock.now + 30_000);
    assert.equal(h.deliveries.length, 1, "not retried before the first backoff");
    await tickAt(h, h.clock.now + 31_000);
    assert.equal(h.deliveries.length, 2, "retried after 60s");
    await tickAt(h, h.clock.now + 300_000);
    assert.equal(h.deliveries.length, 3, "retried after the second backoff");
    const failed = h.monitor.alerts(alice, { markRead: false }).alerts[0];
    assert.equal(failed?.delivery.status, "failed", "given up after the last backoff");
    assert.equal(failed?.delivery.attempts, 3);

    h.site.set("hooked.com", ["ga"]);
    h.delivery.result = { ok: true, status: 204, error: null };
    await tickAt(h, h.clock.now + 24 * HOUR);
    await tickAt(h, h.clock.now + 24 * HOUR);
    const latest = h.monitor.alerts(alice, { unreadOnly: false, markRead: false }).alerts.at(-1);
    assert.equal(latest?.change, "tech_removed");
    assert.equal(latest?.delivery.status, "delivered");
  });
});
