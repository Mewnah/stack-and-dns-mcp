/**
 * In-process sliding-window rate limiter with per-plan minute and day
 * quotas plus a concurrency cap. State is per principal and pruned lazily.
 */

import type { PlanLimits, PlanName } from "../config.js";

export interface RateLimitDecision {
  allowed: boolean;
  scope: "minute" | "day" | "concurrent" | null;
  limitPerMinute: number;
  remainingThisMinute: number;
  limitPerDay: number;
  remainingToday: number;
  retryAfterMs: number;
  resetAtMs: number;
}

interface PrincipalWindow {
  minute: number[];
  day: number[];
  http: number[];
  active: number;
  lastSeen: number;
}

const MINUTE_MS = 60000;
const DAY_MS = 86400000;
const PRUNE_INTERVAL_MS = 60000;
const IDLE_EVICT_MS = DAY_MS + MINUTE_MS;

function trim(timestamps: number[], threshold: number): void {
  let drop = 0;
  while (drop < timestamps.length && (timestamps[drop] as number) <= threshold) drop++;
  if (drop > 0) timestamps.splice(0, drop);
}

export class RateLimiter {
  private readonly windows = new Map<string, PrincipalWindow>();
  private readonly limits: Record<PlanName, PlanLimits>;
  private lastPrune = Date.now();

  constructor(limits: Record<PlanName, PlanLimits>) {
    this.limits = limits;
  }

  limitsFor(plan: PlanName): PlanLimits {
    return this.limits[plan];
  }

  private window(principalId: string, now: number): PrincipalWindow {
    this.maybePrune(now);
    let entry = this.windows.get(principalId);
    if (!entry) {
      entry = { minute: [], day: [], http: [], active: 0, lastSeen: now };
      this.windows.set(principalId, entry);
    }
    entry.lastSeen = now;
    trim(entry.minute, now - MINUTE_MS);
    trim(entry.day, now - DAY_MS);
    trim(entry.http, now - MINUTE_MS);
    return entry;
  }

  private maybePrune(now: number): void {
    if (now - this.lastPrune < PRUNE_INTERVAL_MS) return;
    this.lastPrune = now;
    for (const [id, entry] of this.windows) {
      if (entry.active !== 0) continue;
      if (now - entry.lastSeen > IDLE_EVICT_MS) {
        this.windows.delete(id);
        continue;
      }
      // Entries whose every window has drained (typical for per-address
      // pre-auth buckets) carry no state worth keeping past one idle minute.
      trim(entry.minute, now - MINUTE_MS);
      trim(entry.day, now - DAY_MS);
      trim(entry.http, now - MINUTE_MS);
      if (entry.minute.length === 0 && entry.day.length === 0 && entry.http.length === 0 && now - entry.lastSeen > MINUTE_MS) {
        this.windows.delete(id);
      }
    }
  }

  /**
   * countDay=false evaluates and consumes only the minute window: control
   * calls (polling a bulk check, reading alerts) must keep working after the
   * day's quota is spent and must not spend it.
   */
  private evaluate(principalId: string, plan: PlanName, consume: boolean, countDay = true): RateLimitDecision {
    const now = Date.now();
    const limits = this.limits[plan];
    const entry = this.window(principalId, now);
    const minuteUsed = entry.minute.length;
    const dayUsed = entry.day.length;
    const decision: RateLimitDecision = {
      allowed: true,
      scope: null,
      limitPerMinute: limits.perMinute,
      remainingThisMinute: Math.max(0, limits.perMinute - minuteUsed),
      limitPerDay: limits.perDay,
      remainingToday: Math.max(0, limits.perDay - dayUsed),
      retryAfterMs: 0,
      resetAtMs: now + MINUTE_MS
    };
    if (minuteUsed >= limits.perMinute) {
      const oldest = entry.minute[0] ?? now;
      decision.allowed = false;
      decision.scope = "minute";
      decision.retryAfterMs = Math.max(1000, oldest + MINUTE_MS - now);
      decision.resetAtMs = oldest + MINUTE_MS;
      return decision;
    }
    if (countDay && dayUsed >= limits.perDay) {
      const oldest = entry.day[0] ?? now;
      decision.allowed = false;
      decision.scope = "day";
      decision.retryAfterMs = Math.max(1000, oldest + DAY_MS - now);
      decision.resetAtMs = oldest + DAY_MS;
      return decision;
    }
    if (consume) {
      entry.minute.push(now);
      if (countDay) entry.day.push(now);
      decision.remainingThisMinute = Math.max(0, limits.perMinute - entry.minute.length);
      decision.remainingToday = Math.max(0, limits.perDay - entry.day.length);
    }
    return decision;
  }

  check(principalId: string, plan: PlanName, options: { countDay?: boolean } = {}): RateLimitDecision {
    return this.evaluate(principalId, plan, false, options.countDay ?? true);
  }

  consume(principalId: string, plan: PlanName, options: { countDay?: boolean } = {}): RateLimitDecision {
    return this.evaluate(principalId, plan, true, options.countDay ?? true);
  }

  /**
   * Coarse per-minute HTTP request limiter used in front of the JSON-RPC
   * endpoint (covers initialize/list/ping traffic as well as tool calls).
   */
  consumeHttp(principalId: string, limitPerMinute: number): { allowed: boolean; remaining: number; retryAfterMs: number } {
    const now = Date.now();
    const entry = this.window(principalId, now);
    if (entry.http.length >= limitPerMinute) {
      const oldest = entry.http[0] ?? now;
      return { allowed: false, remaining: 0, retryAfterMs: Math.max(1000, oldest + MINUTE_MS - now) };
    }
    entry.http.push(now);
    return { allowed: true, remaining: Math.max(0, limitPerMinute - entry.http.length), retryAfterMs: 0 };
  }

  acquire(principalId: string, plan: PlanName): { ok: boolean; release: () => void } {
    const now = Date.now();
    const entry = this.window(principalId, now);
    const limits = this.limits[plan];
    if (entry.active >= limits.maxConcurrent) {
      return { ok: false, release: () => undefined };
    }
    entry.active++;
    let released = false;
    return {
      ok: true,
      release: () => {
        if (released) return;
        released = true;
        entry.active = Math.max(0, entry.active - 1);
      }
    };
  }

  snapshot(principalId: string, plan: PlanName): RateLimitDecision {
    return this.evaluate(principalId, plan, false);
  }

  /**
   * Charges several units against the daily window at once (a bulk job
   * counts each domain as one call). All-or-nothing: when the remaining
   * daily quota is smaller than the request, nothing is consumed.
   */
  consumeDayUnits(principalId: string, plan: PlanName, units: number, now: number = Date.now()): RateLimitDecision {
    const limits = this.limits[plan];
    const entry = this.window(principalId, now);
    const remaining = Math.max(0, limits.perDay - entry.day.length);
    const decision: RateLimitDecision = {
      allowed: true,
      scope: null,
      limitPerMinute: limits.perMinute,
      remainingThisMinute: Math.max(0, limits.perMinute - entry.minute.length),
      limitPerDay: limits.perDay,
      remainingToday: remaining,
      retryAfterMs: 0,
      resetAtMs: now + DAY_MS
    };
    if (units > remaining) {
      const oldest = entry.day[0] ?? now;
      decision.allowed = false;
      decision.scope = "day";
      decision.retryAfterMs = entry.day.length > 0 ? Math.max(1000, oldest + DAY_MS - now) : DAY_MS;
      decision.resetAtMs = entry.day.length > 0 ? oldest + DAY_MS : now + DAY_MS;
      return decision;
    }
    for (let i = 0; i < units; i++) entry.day.push(now);
    decision.remainingToday = remaining - units;
    return decision;
  }

  /**
   * Returns units charged at chargedAt (bulk items that failed or were
   * cancelled). Only the entries that charge pushed are removed: units that
   * have already aged out of the window are not handed back again.
   */
  refundDayUnits(principalId: string, units: number, chargedAt: number): void {
    const entry = this.windows.get(principalId);
    if (!entry || units <= 0) return;
    let left = units;
    for (let i = entry.day.length - 1; i >= 0 && left > 0; i--) {
      if (entry.day[i] === chargedAt) {
        entry.day.splice(i, 1);
        left--;
      }
    }
  }
}
