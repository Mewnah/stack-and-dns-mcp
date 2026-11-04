import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { DEFAULT_PLAN_LIMITS } from "../src/config.js";
import { RateLimiter } from "../src/middleware/rateLimit.js";

describe("RateLimiter", () => {
  it("enforces the per-minute quota", () => {
    const limiter = new RateLimiter({ ...DEFAULT_PLAN_LIMITS, free: { perMinute: 3, perDay: 100, maxConcurrent: 2 } });
    for (let i = 0; i < 3; i++) assert.equal(limiter.consume("p1", "free").allowed, true);
    const blocked = limiter.consume("p1", "free");
    assert.equal(blocked.allowed, false);
    assert.equal(blocked.scope, "minute");
    assert.ok(blocked.retryAfterMs > 0);
    assert.equal(limiter.consume("p2", "free").allowed, true, "other principals are independent");
  });

  it("enforces the per-day quota", () => {
    const limiter = new RateLimiter({ ...DEFAULT_PLAN_LIMITS, free: { perMinute: 100, perDay: 2, maxConcurrent: 2 } });
    assert.equal(limiter.consume("p", "free").allowed, true);
    assert.equal(limiter.consume("p", "free").allowed, true);
    const blocked = limiter.consume("p", "free");
    assert.equal(blocked.allowed, false);
    assert.equal(blocked.scope, "day");
    assert.equal(blocked.remainingToday, 0);
  });

  it("caps concurrency and releases slots", () => {
    const limiter = new RateLimiter({ ...DEFAULT_PLAN_LIMITS, free: { perMinute: 100, perDay: 100, maxConcurrent: 1 } });
    const first = limiter.acquire("p", "free");
    assert.equal(first.ok, true);
    assert.equal(limiter.acquire("p", "free").ok, false);
    first.release();
    first.release();
    assert.equal(limiter.acquire("p", "free").ok, true);
  });

  it("tracks the coarse HTTP limiter separately", () => {
    const limiter = new RateLimiter(DEFAULT_PLAN_LIMITS);
    assert.equal(limiter.consumeHttp("p", 2).allowed, true);
    assert.equal(limiter.consumeHttp("p", 2).allowed, true);
    assert.equal(limiter.consumeHttp("p", 2).allowed, false);
    assert.equal(limiter.check("p", "free").remainingThisMinute, DEFAULT_PLAN_LIMITS.free.perMinute);
  });
});
