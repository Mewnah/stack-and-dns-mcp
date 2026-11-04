import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { RequestHandlerExtra } from "@modelcontextprotocol/sdk/shared/protocol.js";
import type { ServerNotification, ServerRequest } from "@modelcontextprotocol/sdk/types.js";
import { DEFAULT_PLAN_LIMITS, loadConfig } from "../src/config.js";
import { setLogLevel } from "../src/logger.js";
import type { Principal } from "../src/middleware/auth.js";
import { createMeter } from "../src/middleware/metering.js";
import { RateLimiter } from "../src/middleware/rateLimit.js";
import { UsageTracker } from "../src/middleware/usage.js";

setLogLevel("silent");

function fakeExtra(signal: AbortSignal = new AbortController().signal): RequestHandlerExtra<ServerRequest, ServerNotification> {
  return {
    signal,
    requestId: 1,
    sendNotification: async () => undefined,
    sendRequest: async () => {
      throw new Error("not used");
    }
  } as unknown as RequestHandlerExtra<ServerRequest, ServerNotification>;
}

describe("createMeter gate ordering", () => {
  it("does not consume minute/day quota when the concurrency gate rejects", async () => {
    const config = loadConfig({ STACKDNS_TRANSPORT: "stdio" }, []);
    config.auth.planLimits = { ...DEFAULT_PLAN_LIMITS, free: { perMinute: 10, perDay: 100, maxConcurrent: 1 } };
    const usage = new UsageTracker(null);
    const limiter = new RateLimiter(config.auth.planLimits);
    const principal: Principal = { id: "p1", plan: "free", label: "test", source: "api-key" };
    const meter = createMeter({ config, usage, limiter, localPrincipal: principal });

    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const tool = meter("inspect_tech_stack", async () => {
      await gate;
      return { ok: true };
    });

    const calls = [tool({}, fakeExtra()), tool({}, fakeExtra()), tool({}, fakeExtra())];
    assert.equal(limiter.snapshot("p1", "free").remainingThisMinute, 9, "only the call that acquired the slot consumed quota");
    release();
    const results = await Promise.all(calls);
    assert.equal(results.filter((r) => r.isError).length, 2);
    assert.equal(limiter.snapshot("p1", "free").remainingThisMinute, 9);
    assert.equal(limiter.snapshot("p1", "free").remainingToday, 99);
  });

  it("rejects on the pre-flight window without charging credits", async () => {
    const config = loadConfig({ STACKDNS_TRANSPORT: "stdio" }, []);
    config.auth.planLimits = { ...DEFAULT_PLAN_LIMITS, payg: { perMinute: 1, perDay: 100, maxConcurrent: 4 } };
    const usage = new UsageTracker(null);
    usage.addCredits("pay1", "payg", "test", 5);
    const limiter = new RateLimiter(config.auth.planLimits);
    const principal: Principal = { id: "pay1", plan: "payg", label: "test", source: "session" };
    const meter = createMeter({ config, usage, limiter, localPrincipal: principal });
    const tool = meter("inspect_tech_stack", async () => ({ ok: true }));

    const first = await tool({}, fakeExtra());
    assert.equal(first.isError, undefined);
    assert.equal(usage.creditsRemaining("pay1"), 4);
    const second = await tool({}, fakeExtra());
    assert.equal(second.isError, true);
    assert.equal(usage.creditsRemaining("pay1"), 4, "a rate-limited call is not charged");
  });

  it("never runs or bills a call whose request was already cancelled", async () => {
    const config = loadConfig({ STACKDNS_TRANSPORT: "stdio" }, []);
    config.auth.planLimits = { ...DEFAULT_PLAN_LIMITS, payg: { perMinute: 60, perDay: 100, maxConcurrent: 1 } };
    const usage = new UsageTracker(null);
    usage.addCredits("pay1", "payg", "test", 10);
    const limiter = new RateLimiter(config.auth.planLimits);
    const principal: Principal = { id: "pay1", plan: "payg", label: "test", source: "session" };
    const meter = createMeter({ config, usage, limiter, localPrincipal: principal });
    let ran = false;
    const tool = meter("inspect_tech_stack", async () => {
      ran = true;
      return { ok: true };
    });

    const controller = new AbortController();
    controller.abort("Request cancelled by client");
    const result = await tool({}, fakeExtra(controller.signal));
    assert.equal(result.isError, true);
    assert.equal((result._meta as { error: { code: string } }).error.code, "CANCELLED");
    assert.equal(ran, false, "the handler must not run for a cancelled request");
    assert.equal(usage.creditsRemaining("pay1"), 10, "nothing is charged");
    assert.equal(limiter.snapshot("pay1", "payg").remainingThisMinute, 60, "no quota is consumed");
    const next = await tool({}, fakeExtra());
    assert.equal(next.isError, undefined, "the concurrency slot was not leaked");
  });

  it("returns CANCELLED and refunds when the client cancels a call that folds aborts into a result", async () => {
    const config = loadConfig({ STACKDNS_TRANSPORT: "stdio" }, []);
    const usage = new UsageTracker(null);
    usage.addCredits("pay2", "payg", "test", 10);
    const limiter = new RateLimiter(config.auth.planLimits);
    const principal: Principal = { id: "pay2", plan: "payg", label: "test", source: "session" };
    const meter = createMeter({ config, usage, limiter, localPrincipal: principal });
    // Mirrors the inspectors: an aborted socket becomes a "partial" result rather than a throw.
    const tool = meter("comprehensive_audit", async (_args, ctx) => {
      await new Promise<void>((resolve) => ctx.signal.addEventListener("abort", () => resolve(), { once: true }));
      return { ok: false, partial: true };
    });
    const controller = new AbortController();
    const pending = tool({}, fakeExtra(controller.signal));
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(usage.creditsRemaining("pay2"), 8, "credits are held while the call runs");
    controller.abort("Request cancelled by client");
    const result = await pending;
    assert.equal(result.isError, true);
    assert.equal((result._meta as { error: { code: string } }).error.code, "CANCELLED");
    assert.equal(result.structuredContent, undefined, "the partial report is discarded, not billed");
    assert.equal(usage.creditsRemaining("pay2"), 10, "the hold is refunded");
    assert.equal(usage.get("pay2")?.totalCalls ?? 0, 0, "no usage is recorded for a cancelled call");
  });

  it("does not consume daily quota when credits are insufficient", async () => {
    const config = loadConfig({ STACKDNS_TRANSPORT: "stdio" }, []);
    const usage = new UsageTracker(null);
    usage.addCredits("broke", "payg", "test", 0);
    const limiter = new RateLimiter(config.auth.planLimits);
    const principal: Principal = { id: "broke", plan: "payg", label: "test", source: "session" };
    const meter = createMeter({ config, usage, limiter, localPrincipal: principal });
    const tool = meter("comprehensive_audit", async () => ({ ok: true }));
    const result = await tool({}, fakeExtra());
    assert.equal(result.isError, true);
    assert.equal(limiter.snapshot("broke", "payg").remainingToday, config.auth.planLimits.payg.perDay);
  });
});
