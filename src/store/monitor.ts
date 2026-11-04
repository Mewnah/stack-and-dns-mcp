/**
 * Domain monitoring. A caller watches a domain for email and/or technology
 * changes; the monitor re-scans every watched domain on a fixed interval
 * (once per domain and check, however many callers watch it) and turns new
 * entries in the shared change log into alerts for each watcher. Because
 * alerts come from the change log, a change found by any scan of a watched
 * domain (a direct call, a bulk job or the monitor itself) reaches every
 * watcher exactly once.
 *
 * Alerts are always available through get_alerts; a watch with a webhook
 * URL also receives them as signed POSTs, retried with backoff.
 *
 * Billing: plan principals get a number of watches included in their plan.
 * Prepaid principals pay per scheduled check; a watch whose owner cannot
 * pay is paused (with an alert) and resumes automatically once the balance
 * covers a check again.
 */

import { randomBytes } from "node:crypto";
import type { PlanName } from "../config.js";
import { untilAborted, withTimeout } from "../lib/async.js";
import { parseDomain } from "../lib/domain.js";
import { errorMessage, isToolError, ToolError } from "../lib/errors.js";
import type { Severity } from "../lib/findings.js";
import { generateWebhookSecret, signWebhook, validateWebhookUrl, type WebhookDelivery, type WebhookPolicy, type WebhookSender } from "../lib/webhook.js";
import { logger } from "../logger.js";
import type { Principal, PrincipalSource } from "../middleware/auth.js";
import type { UsageTracker } from "../middleware/usage.js";
import { isLockContention, transaction, type Database } from "./db.js";
import { siteKey } from "./scanStore.js";

export const MONITOR_CHECKS = ["email", "tech"] as const;
export type MonitorCheck = (typeof MONITOR_CHECKS)[number];

/** Runs one scheduled check and records it in the scan store; throws on failure (retryable ToolErrors are retried sooner). */
export type MonitorRunner = (check: MonitorCheck, domain: string, signal: AbortSignal) => Promise<void>;

export interface MonitorOptions {
  intervalMs: number;
  retryMs: number;
  creditsPerCheck: number;
  concurrency: number;
  checkTimeoutMs: number;
  tickMs: number;
  maxWatches: Record<PlanName, number>;
  webhook: WebhookPolicy;
  /** Delay before each redelivery attempt; the alert is marked failed after the last one. */
  deliveryBackoffMs: number[];
  alertRetentionDays: number;
  /** Webhook POSTs in flight at once (one per principal at most); default 8. */
  deliveryConcurrency?: number;
  /** How long one delivery round may keep picking up new watches; default tickMs. */
  deliveryBudgetMs?: number;
}

export interface MonitorDeps {
  db: Database;
  usage: UsageTracker;
  runner: MonitorRunner;
  sender: WebhookSender;
  options: MonitorOptions;
  /** Time source, for tests; defaults to Date.now. */
  clock?: () => number;
  /**
   * The current plan of a billing-managed account: undefined when the
   * principal is not one (configured keys, prepaid sessions), null when it
   * has no active key. Watches follow it.
   */
  entitlement?: (principalId: string) => PlanName | null | undefined;
  /** True when a billing-managed account has ended for good (its subscription was deleted); its watches are removed. */
  terminated?: (principalId: string) => boolean;
}

export interface WatchView {
  id: string;
  domain: string;
  checks: MonitorCheck[];
  webhookUrl: string | null;
  createdAt: string;
  lastCheckedAt: string | null;
  nextCheckAt: string | null;
  paused: boolean;
  pausedReason: string | null;
}

export interface AlertView {
  id: number;
  watchId: string;
  domain: string;
  kind: string;
  change: string;
  subject: string | null;
  oldValue: string | null;
  newValue: string | null;
  severity: Severity;
  at: string;
  createdAt: string;
  read: boolean;
  delivery: {
    status: "none" | "pending" | "delivered" | "failed";
    attempts: number;
    lastError: string | null;
  };
}

interface WatchRow {
  id: string;
  principal_id: string;
  principal_plan: PlanName;
  principal_label: string;
  principal_source: PrincipalSource;
  domain: string;
  checks: string;
  webhook_url: string | null;
  webhook_secret: string;
  created_at: number;
  paused_reason: string | null;
  last_checked_at: number | null;
  alert_cursor: number;
}

interface AlertRow {
  id: number;
  watch_id: string;
  principal_id: string;
  domain: string;
  kind: string;
  change: string;
  subject: string | null;
  old_value: string | null;
  new_value: string | null;
  severity: Severity;
  at: number;
  created_at: number;
  read_at: number | null;
  delivery_status: AlertView["delivery"]["status"];
  delivery_attempts: number;
  next_delivery_at: number | null;
  last_delivery_error: string | null;
}

const INSUFFICIENT_CREDITS = "insufficient_credits";
/** The owner's subscription ended or is suspended. */
const PLAN_INACTIVE = "plan_inactive";
/** The owner's plan now includes fewer watches than it has. */
const OVER_PLAN_LIMIT = "over_plan_limit";
const ALERTS_PER_DELIVERY = 50;
const DELIVERY_WATCHES_PER_ROUND = 500;
const PRUNE_BATCH = 5000;
/**
 * Watches of terminated accounts removed per round (and anonymous ones,
 * separately). Each removal cascades to the watch's alerts inside one
 * synchronous statement, so a large account is removed over several rounds
 * rather than holding the write lock and the event loop in one go.
 */
const RETIRED_WATCHES_PER_ROUND = 200;

function iso(ms: number | null): string | null {
  return ms === null ? null : new Date(ms).toISOString();
}

function parseChecks(value: string): MonitorCheck[] {
  return value.split(",").filter((c): c is MonitorCheck => (MONITOR_CHECKS as readonly string[]).includes(c));
}

interface EntitlementChange {
  watch: WatchRow;
  replan: boolean;
  pause: string | null;
  resume: boolean;
}

/**
 * What an account's watches (oldest first) need to match its plan: the
 * oldest `limit` may run and the newer ones are paused as over the limit. A
 * pause for credits is left alone; the plan only moves the pauses it set.
 */
function entitlementChanges(rows: readonly WatchRow[], plan: PlanName, limit: number): EntitlementChange[] {
  const changes: EntitlementChange[] = [];
  rows.forEach((watch, index) => {
    const planPaused = watch.paused_reason === PLAN_INACTIVE || watch.paused_reason === OVER_PLAN_LIMIT;
    const want = index >= limit ? OVER_PLAN_LIMIT : null;
    const replan = watch.principal_plan !== plan;
    const pause = want !== null && (watch.paused_reason === null || planPaused) && watch.paused_reason !== want ? want : null;
    const resume = want === null && planPaused;
    if (replan || pause !== null || resume) changes.push({ watch, replan, pause, resume });
  });
  return changes;
}

export class Monitor {
  private readonly db: Database;
  private readonly options: MonitorOptions;
  private timer: NodeJS.Timeout | null = null;
  private ticking: Promise<void> | null = null;
  private delivering: Promise<void> | null = null;
  /** Timers are running (start() was called and stop() was not). */
  private running = false;
  /** stop() was called: in-flight rounds wind down without writing further results. */
  private halted = false;
  private readonly controllers = new Set<AbortController>();

  private readonly clock: () => number;

  constructor(private readonly deps: MonitorDeps) {
    this.db = deps.db;
    this.options = deps.options;
    this.clock = deps.clock ?? Date.now;
  }

  private watchRow(id: string): WatchRow | undefined {
    return this.db.prepare("SELECT * FROM watches WHERE id = ?").get(id) as unknown as WatchRow | undefined;
  }

  private view(row: WatchRow): WatchView {
    const checks = parseChecks(row.checks);
    const next = this.db.prepare(`SELECT MIN(next_at) AS next FROM monitor_schedule WHERE domain = ? AND kind IN (${checks.map(() => "?").join(",") || "''"})`).get(row.domain, ...checks) as
      { next: number | null } | undefined;
    return {
      id: row.id,
      domain: row.domain,
      checks,
      webhookUrl: row.webhook_url,
      createdAt: iso(row.created_at) as string,
      lastCheckedAt: iso(row.last_checked_at),
      nextCheckAt: row.paused_reason ? null : iso(next?.next ?? null),
      paused: row.paused_reason !== null,
      pausedReason: row.paused_reason
    };
  }

  /**
   * Adds schedule rows for a domain's checks. An existing row keeps its
   * next_at, so unwatching and watching again (both free) cannot force an
   * early scan; rows nobody watches any more are removed when they come due.
   */
  private ensureSchedule(domain: string, checks: MonitorCheck[], now: number): void {
    const insert = this.db.prepare("INSERT INTO monitor_schedule (domain, kind, next_at) VALUES (?, ?, ?) ON CONFLICT(domain, kind) DO NOTHING");
    for (const check of checks) insert.run(domain, check, now);
  }

  private latestChangeId(domain: string): number {
    return Number((this.db.prepare("SELECT COALESCE(MAX(id), 0) AS m FROM changes WHERE domain = ?").get(domain) as { m: number }).m);
  }

  /**
   * Creates a watch, or updates the caller's existing watch on the same
   * domain. The webhook signing secret is returned only when the watch is
   * created; later updates keep it.
   */
  watch(
    principal: Principal,
    domainInput: string,
    checksInput: readonly string[],
    webhookUrl: string | null,
    allowPrivateTargets: boolean
  ): { watch: WatchView; webhookSecret: string | null; created: boolean } {
    // The tools refuse anonymous callers too; this covers any other caller of
    // the store. Their address-based identity cannot list or unwatch later,
    // and every round removes such watches anyway.
    if (principal.source === "anonymous") throw new ToolError("UNAUTHORIZED", "Monitoring needs an API key or a prepaid session; anonymous callers share an address-based identity.");
    const parsed = parseDomain(domainInput, {
      allowPrivate: allowPrivateTargets
    });
    if (!parsed.ok)
      throw new ToolError(parsed.code, parsed.error, {
        details: { input: domainInput }
      });
    const domain = siteKey(parsed.domain);
    const checks = [...new Set(checksInput)].filter((c): c is MonitorCheck => (MONITOR_CHECKS as readonly string[]).includes(c));
    if (checks.length === 0) throw new ToolError("INVALID_ARGUMENT", `checks must include at least one of ${MONITOR_CHECKS.join(", ")}.`);
    const url = webhookUrl === null ? null : validateWebhookUrl(webhookUrl, this.options.webhook);
    const now = this.clock();
    return transaction(this.db, () => {
      const existing = this.db.prepare("SELECT * FROM watches WHERE principal_id = ? AND domain = ?").get(principal.id, domain) as unknown as WatchRow | undefined;
      if (existing) {
        // Re-watching resumes a watch paused for credits; changes recorded
        // while it was paused are skipped rather than delivered as a backlog.
        // A pause the plan imposes stays until the plan allows the watch.
        const planPaused = existing.paused_reason === PLAN_INACTIVE || existing.paused_reason === OVER_PLAN_LIMIT;
        const resume = existing.paused_reason !== null && !planPaused;
        this.db
          .prepare("UPDATE watches SET checks = ?, webhook_url = ?, principal_plan = ?, principal_label = ?, paused_reason = ?, alert_cursor = ? WHERE id = ?")
          .run(checks.join(","), url, principal.plan, principal.label, planPaused ? existing.paused_reason : null, resume ? this.latestChangeId(domain) : existing.alert_cursor, existing.id);
        this.ensureSchedule(domain, checks, now);
        return {
          watch: this.view(this.watchRow(existing.id) as WatchRow),
          webhookSecret: null,
          created: false
        };
      }
      const limit = this.options.maxWatches[principal.plan];
      const count = Number((this.db.prepare("SELECT COUNT(*) AS n FROM watches WHERE principal_id = ?").get(principal.id) as { n: number }).n);
      if (count >= limit) {
        throw new ToolError("LIMIT_EXCEEDED", `Plan "${principal.plan}" includes ${limit} watched domain(s); unwatch one first.`, { details: { maxWatches: limit, watches: count } });
      }
      const id = `watch_${randomBytes(12).toString("hex")}`;
      const secret = generateWebhookSecret();
      // Start after every change already recorded, so a new watch only hears about the future.
      this.db
        .prepare(
          "INSERT INTO watches (id, principal_id, principal_plan, principal_label, principal_source, domain, checks, webhook_url, webhook_secret, created_at, alert_cursor) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .run(id, principal.id, principal.plan, principal.label, principal.source, domain, checks.join(","), url, secret, now, this.latestChangeId(domain));
      this.ensureSchedule(domain, checks, now);
      logger.info("domain watch created", {
        watchId: id,
        principal: principal.id,
        domain,
        checks
      });
      this.kick();
      return {
        watch: this.view(this.watchRow(id) as WatchRow),
        webhookSecret: secret,
        created: true
      };
    });
  }

  unwatch(principal: Principal, target: { watchId?: string | undefined; domain?: string | undefined }): boolean {
    let row: WatchRow | undefined;
    if (target.watchId) {
      row = this.watchRow(target.watchId);
    } else if (target.domain) {
      const parsed = parseDomain(target.domain, { allowPrivate: true });
      if (parsed.ok) row = this.db.prepare("SELECT * FROM watches WHERE principal_id = ? AND domain = ?").get(principal.id, siteKey(parsed.domain)) as unknown as WatchRow | undefined;
    } else {
      throw new ToolError("INVALID_ARGUMENT", "Pass watchId or domain.");
    }
    if (!row || row.principal_id !== principal.id) return false;
    // The schedule row stays until it comes due (then it is dropped if nobody
    // watches the domain), so a free unwatch/watch cycle cannot force a scan.
    this.db.prepare("DELETE FROM watches WHERE id = ?").run(row.id);
    logger.info("domain watch removed", {
      watchId: row.id,
      principal: principal.id,
      domain: row.domain
    });
    return true;
  }

  list(principal: Principal): WatchView[] {
    const rows = this.db.prepare("SELECT * FROM watches WHERE principal_id = ? ORDER BY created_at, id").all(principal.id) as unknown as WatchRow[];
    return rows.map((r) => this.view(r));
  }

  watchLimit(plan: PlanName): number {
    return this.options.maxWatches[plan];
  }

  /** Alerts for the caller, oldest first after sinceId; optionally marks the returned ones read. */
  alerts(
    principal: Principal,
    query: {
      sinceId?: number;
      limit?: number;
      unreadOnly?: boolean;
      markRead?: boolean;
    }
  ): { alerts: AlertView[]; nextSinceId: number | null } {
    // Only the caller's own watches: a free call must not scan every tenant's.
    this.collectAlerts(this.clock(), { principalId: principal.id });
    const limit = Math.max(1, Math.min(200, Math.floor(query.limit ?? 50)));
    const rows = this.db
      .prepare(`SELECT * FROM alerts WHERE principal_id = ? AND id > ? ${query.unreadOnly === false ? "" : "AND read_at IS NULL"} ORDER BY id LIMIT ?`)
      .all(principal.id, Math.max(0, Math.floor(query.sinceId ?? 0)), limit + 1) as unknown as AlertRow[];
    const page = rows.slice(0, limit);
    if (query.markRead !== false && page.length > 0) {
      const mark = this.db.prepare("UPDATE alerts SET read_at = ? WHERE id = ? AND read_at IS NULL");
      const now = this.clock();
      transaction(this.db, () => {
        for (const r of page) mark.run(now, r.id);
      });
    }
    return {
      alerts: page.map((r) => ({
        id: r.id,
        watchId: r.watch_id,
        domain: r.domain,
        kind: r.kind,
        change: r.change,
        subject: r.subject,
        oldValue: r.old_value,
        newValue: r.new_value,
        severity: r.severity,
        at: iso(r.at) as string,
        createdAt: iso(r.created_at) as string,
        read: r.read_at !== null,
        delivery: {
          status: r.delivery_status,
          attempts: r.delivery_attempts,
          lastError: r.last_delivery_error
        }
      })),
      nextSinceId: rows.length > limit ? (page.at(-1)?.id ?? null) : null
    };
  }

  private insertAlert(
    watch: WatchRow,
    alert: {
      kind: string;
      change: string;
      subject: string | null;
      oldValue: string | null;
      newValue: string | null;
      severity: Severity;
      at: number;
    },
    now: number
  ): void {
    this.db
      .prepare(
        "INSERT INTO alerts (watch_id, principal_id, domain, kind, change, subject, old_value, new_value, severity, at, created_at, delivery_status, next_delivery_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
      )
      .run(
        watch.id,
        watch.principal_id,
        watch.domain,
        alert.kind,
        alert.change,
        alert.subject,
        alert.oldValue,
        alert.newValue,
        alert.severity,
        alert.at,
        now,
        watch.webhook_url ? "pending" : "none",
        watch.webhook_url ? now : null
      );
  }

  /**
   * Turns change-log entries newer than each watch's cursor into alerts.
   * scope.principalId limits the pass to one caller's watches; alsoPaused
   * includes watches paused during the current round, whose paid check's
   * change must still reach them. Returns how many alerts were created.
   */
  collectAlerts(now: number = this.clock(), scope: { principalId?: string; alsoPaused?: readonly string[] } = {}): number {
    const extra = scope.alsoPaused ?? [];
    // An anonymous watch (left by an older process) gets no alerts before the round's sweep removes it.
    const conditions = [`(paused_reason IS NULL${extra.length > 0 ? ` OR id IN (${extra.map(() => "?").join(",")})` : ""})`, "principal_source <> 'anonymous'"];
    const params: string[] = [...extra];
    if (scope.principalId !== undefined) {
      conditions.push("principal_id = ?");
      params.push(scope.principalId);
    }
    const watchesStmt = this.db.prepare(`SELECT * FROM watches WHERE ${conditions.join(" AND ")}`);
    const changesStmt = this.db.prepare("SELECT * FROM changes WHERE domain = ? AND id > ? ORDER BY id LIMIT 1000");
    const cursorStmt = this.db.prepare("UPDATE watches SET alert_cursor = ? WHERE id = ?");
    return transaction(this.db, () => {
      let created = 0;
      const watches = watchesStmt.all(...params) as unknown as WatchRow[];
      for (const watch of watches) {
        const checks = new Set(parseChecks(watch.checks));
        const changes = changesStmt.all(watch.domain, watch.alert_cursor) as unknown as Array<{
          id: number;
          kind: string;
          change: string;
          subject: string | null;
          old_value: string | null;
          new_value: string | null;
          severity: Severity;
          at: number;
        }>;
        if (changes.length === 0) continue;
        for (const c of changes) {
          if (!checks.has(c.kind as MonitorCheck)) continue;
          this.insertAlert(
            watch,
            {
              kind: c.kind,
              change: c.change,
              subject: c.subject,
              oldValue: c.old_value,
              newValue: c.new_value,
              severity: c.severity,
              at: c.at
            },
            now
          );
          created++;
        }
        cursorStmt.run((changes.at(-1) as { id: number }).id, watch.id);
      }
      return created;
    });
  }

  /**
   * Keeps watches in step with their owner's current entitlement (self-serve
   * accounts): all paused while a non-terminated account has no active key,
   * re-planned on a plan change, the newest beyond the plan's limit paused,
   * and resumed when the plan allows them again. Watches of a terminated
   * account (its subscription was deleted for good) are removed instead,
   * their alerts cascading, within a budget of RETIRED_WATCHES_PER_ROUND
   * shared by all such accounts per round; the rest stay paused as
   * plan_inactive, with their pending deliveries dropped, until a later round
   * removes them. Runs in the lease holder every round, so it works whichever
   * process received the billing webhook.
   *
   * Each account is read first, and a write is opened only when something
   * changes: in SQLite even an UPDATE that matches no row takes the write
   * lock, and this runs for every account every round. When another
   * connection holds that lock, the rest of the pass waits for the next round
   * instead of failing this one (each further attempt would block the event
   * loop for the busy timeout); until then an account keeps its previous
   * state, as it does anyway between a billing change and the next round.
   */
  private reconcileEntitlements(now: number): void {
    const entitlement = this.deps.entitlement;
    if (!entitlement) return;
    // Shared by every terminated account this round.
    let retireBudget = RETIRED_WATCHES_PER_ROUND;
    let current: string | null = null;
    try {
      const owners = this.db.prepare("SELECT DISTINCT principal_id FROM watches WHERE principal_plan != 'payg'").all() as unknown as Array<{ principal_id: string }>;
      for (const { principal_id } of owners) {
        current = principal_id;
        const plan = entitlement(principal_id);
        if (plan === undefined) continue; // not a billing-managed account
        if (plan === null && this.deps.terminated?.(principal_id)) {
          retireBudget -= this.retireTerminated(principal_id, retireBudget);
          continue;
        }
        if (plan === null) {
          if (this.db.prepare("SELECT 1 FROM watches WHERE principal_id = ? AND (paused_reason IS NULL OR paused_reason = ?) LIMIT 1").get(principal_id, OVER_PLAN_LIMIT)) {
            this.db.prepare("UPDATE watches SET paused_reason = ? WHERE principal_id = ? AND (paused_reason IS NULL OR paused_reason = ?)").run(PLAN_INACTIVE, principal_id, OVER_PLAN_LIMIT);
          }
          continue;
        }
        this.applyPlan(principal_id, plan, now);
      }
    } catch (err) {
      if (!isLockContention(err)) throw err;
      logger.warn("watch entitlements could not be reconciled this round; the rest wait for the next round", { principal: current, error: err });
    }
  }

  /**
   * Removes up to budget watches of a terminated account (their alerts
   * cascade) and returns how many went. The account can never authenticate
   * again to unwatch, so its watches are removed instead of paused forever.
   */
  private retireTerminated(principalId: string, budget: number): number {
    // Until a later round removes them, nothing is scanned, alerted or posted for the rest.
    const pauseRest = (): void => {
      this.db.prepare("UPDATE watches SET paused_reason = ? WHERE principal_id = ? AND (paused_reason IS NULL OR paused_reason <> ?)").run(PLAN_INACTIVE, principalId, PLAN_INACTIVE);
      this.db.prepare("UPDATE alerts SET delivery_status = 'none', next_delivery_at = NULL WHERE principal_id = ? AND delivery_status = 'pending'").run(principalId);
    };
    if (budget === 0) {
      // Nothing can be removed this round: write only when something is left to pause or cancel.
      const unpaused = this.db.prepare("SELECT 1 FROM watches WHERE principal_id = ? AND (paused_reason IS NULL OR paused_reason <> ?) LIMIT 1").get(principalId, PLAN_INACTIVE);
      const pending = this.db.prepare("SELECT 1 FROM alerts WHERE principal_id = ? AND delivery_status = 'pending' LIMIT 1").get(principalId);
      if (unpaused || pending) transaction(this.db, pauseRest);
      return 0;
    }
    // One transaction, so a removal never lands without the pause of what it left.
    const removed = transaction(this.db, () => {
      const n = Number(this.db.prepare("DELETE FROM watches WHERE id IN (SELECT id FROM watches WHERE principal_id = ? LIMIT ?)").run(principalId, budget).changes);
      if (n === budget) pauseRest(); // a full chunk may have left more for later rounds
      return n;
    });
    if (removed > 0) logger.info("watches of a terminated account removed", { principal: principalId, watches: removed, more: removed === budget });
    return removed;
  }

  /** Re-plans, pauses and resumes an account's watches for its current plan, taking the write lock only when one of them changes. */
  private applyPlan(principalId: string, plan: PlanName, now: number): void {
    const select = this.db.prepare("SELECT * FROM watches WHERE principal_id = ? ORDER BY created_at, id");
    const limit = this.options.maxWatches[plan];
    if (entitlementChanges(select.all(principalId) as unknown as WatchRow[], plan, limit).length === 0) return;
    transaction(this.db, () => {
      // Re-read under the write lock: the rows may have changed since the check above.
      for (const change of entitlementChanges(select.all(principalId) as unknown as WatchRow[], plan, limit)) {
        const { watch } = change;
        if (change.replan) this.db.prepare("UPDATE watches SET principal_plan = ? WHERE id = ?").run(plan, watch.id);
        if (change.pause !== null) {
          this.db.prepare("UPDATE watches SET paused_reason = ? WHERE id = ?").run(change.pause, watch.id);
        } else if (change.resume) {
          this.db.prepare("UPDATE watches SET paused_reason = NULL, alert_cursor = ? WHERE id = ?").run(this.latestChangeId(watch.domain), watch.id);
          this.ensureSchedule(watch.domain, parseChecks(watch.checks), now);
        }
      }
    });
  }

  /**
   * Removes watches owned by anonymous principals, a bounded chunk per round.
   * The v7 migration removed those that existed, but an older process still
   * sharing the database during a rolling deploy can create more; until
   * removed they are neither scanned, alerted nor posted to.
   */
  private retireAnonymousWatches(): void {
    // Read first: a DELETE takes the write lock even when it matches nothing,
    // and this runs every round. The partial index watches_anonymous (v10)
    // keeps this check and the DELETE's subquery off a scan of every watch,
    // as long as both say exactly principal_source = 'anonymous'.
    if (!this.db.prepare("SELECT 1 FROM watches WHERE principal_source = 'anonymous' LIMIT 1").get()) return;
    try {
      const removed = Number(this.db.prepare("DELETE FROM watches WHERE id IN (SELECT id FROM watches WHERE principal_source = 'anonymous' LIMIT ?)").run(RETIRED_WATCHES_PER_ROUND).changes);
      logger.info("watches of anonymous principals removed", { watches: removed });
    } catch (err) {
      // Another connection holds the write lock: they stay inert until a later round removes them.
      if (!isLockContention(err)) throw err;
      logger.warn("anonymous watches could not be removed this round", { error: err });
    }
  }

  /**
   * Resumes watches paused for credits once their owner can pay again. Each
   * owner's balance is spent down as its watches resume, and only the
   * resumed watch's own kinds are brought forward, and only where no other
   * active watcher already has them scheduled, so nobody else is checked
   * (and charged) before their interval.
   */
  private resumeFundedWatches(now: number): void {
    const paused = this.db.prepare("SELECT * FROM watches WHERE paused_reason = ? ORDER BY created_at, id").all(INSUFFICIENT_CREDITS) as unknown as WatchRow[];
    const budget = new Map<string, number>();
    for (const watch of paused) {
      const checks = parseChecks(watch.checks);
      const needed = this.options.creditsPerCheck * checks.length;
      const available = budget.get(watch.principal_id) ?? this.deps.usage.creditsRemaining(watch.principal_id) ?? 0;
      if (available < needed) continue;
      budget.set(watch.principal_id, available - needed);
      try {
        transaction(this.db, () => {
          this.db.prepare("UPDATE watches SET paused_reason = NULL, alert_cursor = ? WHERE id = ?").run(this.latestChangeId(watch.domain), watch.id);
          this.ensureSchedule(watch.domain, checks, now);
          const others = this.db.prepare("SELECT checks FROM watches WHERE domain = ? AND id <> ? AND paused_reason IS NULL").all(watch.domain, watch.id) as unknown as Array<{ checks: string }>;
          const watchedByOthers = new Set(others.flatMap((w) => parseChecks(w.checks)));
          for (const check of checks) {
            if (!watchedByOthers.has(check)) this.db.prepare("UPDATE monitor_schedule SET next_at = MIN(next_at, ?) WHERE domain = ? AND kind = ?").run(now, watch.domain, check);
          }
        });
      } catch (err) {
        // Like the entitlement pass: a locked database defers the resumes to a
        // later round rather than failing this one before any check runs.
        if (!isLockContention(err)) throw err;
        logger.warn("paused watches could not be resumed this round; the rest wait for the next round", { watchId: watch.id, error: err });
        return;
      }
      logger.info("domain watch resumed after top-up", { watchId: watch.id });
    }
  }

  /** Runs a billing or schedule write, retrying (bounded, so shutdown cannot hang) while another connection holds the write lock. */
  private async durably<T>(write: () => T, untilHalted = false): Promise<T> {
    for (let attempt = 1; ; attempt++) {
      try {
        return write();
      } catch (err) {
        if (!isLockContention(err) || attempt >= 60 || (untilHalted && this.halted)) throw err;
        if (attempt === 1 || attempt % 10 === 0)
          logger.warn("monitor write hit a locked database; retrying", {
            attempt,
            error: err
          });
        await new Promise((resolve) => setTimeout(resolve, Math.min(2000, 100 * attempt)));
      }
    }
  }

  /**
   * Runs one scheduled check for a domain. Charging the prepaid watchers and
   * claiming the schedule row happen in one transaction before the check, so
   * a check is never charged twice for one interval; refunds for a retryable
   * failure commit together with the result.
   */
  private async runScheduled(domain: string, check: MonitorCheck, now: number, pausedThisRound: string[]): Promise<void> {
    let claim: { watchers: WatchRow[]; charged: WatchRow[] } | null;
    try {
      claim = await this.durably(
        () =>
          // A stopping round claims nothing more: a claim that lands after
          // stop() would run unaborted, charge, and never write its result.
          this.halted
            ? null
            : transaction(this.db, () => {
                // The batch was selected outside this transaction: another process's
                // overlapping round may have claimed (or dropped) the row since, and
                // BEGIN IMMEDIATE makes this re-check pick a single winner.
                const scheduled = this.db.prepare("SELECT next_at FROM monitor_schedule WHERE domain = ? AND kind = ?").get(domain, check) as { next_at: number } | undefined;
                if (!scheduled || scheduled.next_at > now) return null;
                // An anonymous watch left by an older process is never charged or scanned for.
                const watchers = (this.db.prepare("SELECT * FROM watches WHERE domain = ? AND paused_reason IS NULL AND principal_source <> 'anonymous'").all(domain) as unknown as WatchRow[]).filter(
                  (w) => parseChecks(w.checks).includes(check)
                );
                if (watchers.length === 0) {
                  this.db.prepare("DELETE FROM monitor_schedule WHERE domain = ? AND kind = ?").run(domain, check);
                  return null;
                }
                const charged: WatchRow[] = [];
                const active: WatchRow[] = [];
                for (const watch of watchers) {
                  if (watch.principal_plan !== "payg" || this.options.creditsPerCheck === 0) {
                    active.push(watch);
                  } else if (this.deps.usage.consumeCredits(watch.principal_id, this.options.creditsPerCheck)) {
                    charged.push(watch);
                    active.push(watch);
                  } else {
                    this.db.prepare("UPDATE watches SET paused_reason = ? WHERE id = ?").run(INSUFFICIENT_CREDITS, watch.id);
                    this.insertAlert(
                      watch,
                      {
                        kind: "monitor",
                        change: "watch_paused",
                        subject: INSUFFICIENT_CREDITS,
                        oldValue: null,
                        newValue: null,
                        severity: "medium",
                        at: now
                      },
                      now
                    );
                    pausedThisRound.push(watch.id);
                    logger.info("domain watch paused for insufficient credits", { watchId: watch.id, principal: watch.principal_id });
                  }
                }
                // Claim the row: while the check runs, and if its result cannot be
                // written, it is not picked (and charged) again before retryMs.
                this.db
                  .prepare("UPDATE monitor_schedule SET next_at = ? WHERE domain = ? AND kind = ?")
                  .run(now + (active.length === 0 ? this.options.intervalMs : this.options.retryMs), domain, check);
                return active.length === 0 ? null : { watchers: active, charged };
              }),
        true
      );
    } catch (err) {
      logger.warn("monitor check could not be claimed; it stays due", {
        domain,
        check,
        error: err
      });
      return;
    }
    if (!claim) return;
    const { watchers, charged } = claim;

    const controller = new AbortController();
    this.controllers.add(controller);
    // A claim that committed after stop() fails fast; its charge is refunded below.
    if (this.halted) controller.abort();
    let nextAt = now + this.options.intervalMs;
    let lastError: string | null = null;
    let refund: WatchRow[] = [];
    try {
      // Raced against stop(): DNS lookups cannot be interrupted, and shutdown must not wait them out.
      await withTimeout(untilAborted(this.deps.runner(check, domain, controller.signal), controller.signal), this.options.checkTimeoutMs, `monitor ${check} ${domain}`);
    } catch (err) {
      controller.abort();
      const definitive = isToolError(err) && !err.retryable;
      lastError = isToolError(err) ? err.code : "CHECK_FAILED";
      if (!definitive) {
        nextAt = now + this.options.retryMs;
        refund = charged;
        logger.warn("monitor check failed; retrying sooner", {
          domain,
          check,
          error: errorMessage(err)
        });
      }
    } finally {
      this.controllers.delete(controller);
    }
    const applyRefunds = (): void => {
      for (const watch of refund) this.deps.usage.addCredits(watch.principal_id, watch.principal_plan, watch.principal_label, this.options.creditsPerCheck);
    };
    if (this.halted) {
      if (refund.length > 0) await this.durably(() => transaction(this.db, applyRefunds));
      return;
    }
    await this.durably(() =>
      transaction(this.db, () => {
        applyRefunds();
        const previous = this.db.prepare("SELECT last_error FROM monitor_schedule WHERE domain = ? AND kind = ?").get(domain, check) as { last_error: string | null } | undefined;
        this.db.prepare("UPDATE monitor_schedule SET next_at = ?, last_at = ?, last_error = ? WHERE domain = ? AND kind = ?").run(nextAt, now, lastError, domain, check);
        if (lastError === null || nextAt === now + this.options.intervalMs) {
          for (const watch of watchers) this.db.prepare("UPDATE watches SET last_checked_at = ? WHERE id = ?").run(now, watch.id);
        }
        // A domain disappearing from DNS is itself an alert, raised once per transition.
        if (lastError === "DOMAIN_NOT_FOUND" && previous?.last_error !== "DOMAIN_NOT_FOUND") {
          for (const watch of watchers) {
            const current = this.watchRow(watch.id);
            if (!current) continue; // unwatched while the check ran
            this.insertAlert(
              current,
              {
                kind: check,
                change: "domain_not_found",
                subject: domain,
                oldValue: null,
                newValue: "NXDOMAIN",
                severity: "high",
                at: now
              },
              now
            );
          }
        }
      })
    );
  }

  /** Delivers one watch's due alerts as a single signed POST. */
  private async deliverWatch(watchId: string): Promise<number> {
    const watch = this.watchRow(watchId);
    const due = this.db
      .prepare("SELECT * FROM alerts WHERE watch_id = ? AND delivery_status = 'pending' AND next_delivery_at <= ? ORDER BY id LIMIT ?")
      .all(watchId, this.clock(), ALERTS_PER_DELIVERY) as unknown as AlertRow[];
    if (due.length === 0) return 0;
    if (!watch || !watch.webhook_url || watch.principal_source === "anonymous") {
      this.db.prepare(`UPDATE alerts SET delivery_status = 'none', next_delivery_at = NULL WHERE id IN (${due.map(() => "?").join(",")})`).run(...due.map((a) => a.id));
      return 0;
    }
    // Signed at send time: receivers reject stale timestamps.
    const sentAt = this.clock();
    const body = JSON.stringify({
      type: "domain.changes",
      watchId,
      domain: watch.domain,
      sentAt: new Date(sentAt).toISOString(),
      alerts: due.map((a) => ({
        id: a.id,
        kind: a.kind,
        change: a.change,
        subject: a.subject,
        oldValue: a.old_value,
        newValue: a.new_value,
        severity: a.severity,
        at: new Date(a.at).toISOString()
      }))
    });
    const controller = new AbortController();
    this.controllers.add(controller);
    let result: WebhookDelivery;
    try {
      result = await this.deps.sender(
        watch.webhook_url,
        body,
        {
          "x-stackdns-signature": signWebhook(body, watch.webhook_secret, Math.floor(sentAt / 1000)),
          "x-stackdns-watch-id": watchId
        },
        controller.signal
      );
    } finally {
      this.controllers.delete(controller);
    }
    // Cancelled by shutdown: the alerts stay pending with their attempt
    // count unchanged, so the next round retries without a penalty.
    if (this.halted && !result.ok) return 0;
    const finishedAt = this.clock();
    // Only alerts still pending take the result: a round may have cancelled
    // the delivery while the POST was in flight (the watch's account ended, or
    // the watch is anonymous), and a failure must not schedule it again.
    transaction(this.db, () => {
      for (const alert of due) {
        const attempts = alert.delivery_attempts + 1;
        if (result.ok) {
          this.db
            .prepare("UPDATE alerts SET delivery_status = 'delivered', delivery_attempts = ?, next_delivery_at = NULL, last_delivery_error = NULL WHERE id = ? AND delivery_status = 'pending'")
            .run(attempts, alert.id);
        } else {
          const backoff = this.options.deliveryBackoffMs[attempts - 1];
          this.db
            .prepare("UPDATE alerts SET delivery_status = ?, delivery_attempts = ?, next_delivery_at = ?, last_delivery_error = ? WHERE id = ? AND delivery_status = 'pending'")
            .run(backoff === undefined ? "failed" : "pending", attempts, backoff === undefined ? null : finishedAt + backoff, result.error, alert.id);
        }
      }
    });
    if (!result.ok)
      logger.warn("webhook delivery failed", {
        watchId,
        alerts: due.length,
        error: result.error
      });
    return result.ok ? due.length : 0;
  }

  /**
   * Delivers pending webhook alerts, fairly: principals take turns one watch
   * at a time, oldest-due first, until the time budget is spent. A principal
   * is out of the queue while its POST is in flight, so one tenant's slow
   * endpoints occupy at most one worker, and however many tenants are slow,
   * every other tenant's next watch is at most one turn away.
   */
  async deliver(): Promise<number> {
    const started = performance.now();
    // Principals take turns: each one's oldest due watch comes before any
    // principal's second, so one account's backlog cannot fill the round.
    const rows = this.db
      .prepare(
        "SELECT watch_id, principal_id FROM (SELECT watch_id, principal_id, MIN(next_delivery_at) AS due, ROW_NUMBER() OVER (PARTITION BY principal_id ORDER BY MIN(next_delivery_at), watch_id) AS rn FROM alerts WHERE delivery_status = 'pending' AND next_delivery_at <= ? GROUP BY watch_id) ORDER BY rn, due LIMIT ?"
      )
      .all(this.clock(), DELIVERY_WATCHES_PER_ROUND) as unknown as Array<{
      watch_id: string;
      principal_id: string;
    }>;
    const byPrincipal = new Map<string, string[]>();
    for (const row of rows) byPrincipal.set(row.principal_id, [...(byPrincipal.get(row.principal_id) ?? []), row.watch_id]);
    const queue = [...byPrincipal.values()];
    let delivered = 0;
    const budgetMs = this.options.deliveryBudgetMs ?? this.options.tickMs;
    // A worker stops when the queue is empty, which means every principal
    // with watches left is held by another worker: no parallelism is lost.
    const workers = Array.from({ length: Math.min(this.options.deliveryConcurrency ?? 8, queue.length) }, async () => {
      for (let watches = queue.shift(); watches && !this.halted; watches = queue.shift()) {
        const watchId = watches.shift();
        if (watchId === undefined) continue;
        if (performance.now() - started >= budgetMs) return;
        try {
          // Read the total only after the await: `delivered += await ...` would
          // add to the value from before it and drop other workers' counts.
          const sent = await this.deliverWatch(watchId);
          delivered += sent;
        } catch (err) {
          logger.error("webhook delivery crashed", { watchId, error: err });
        }
        if (watches.length > 0) queue.push(watches); // back of the line
      }
    });
    await Promise.all(workers);
    return delivered;
  }

  /** Starts a delivery round unless one is running; it runs beside scheduling, never inside it. */
  private startDelivery(): void {
    if (this.delivering || this.halted) return;
    this.delivering = this.deliver()
      .then(() => undefined)
      .catch((err: unknown) => logger.error("webhook delivery round failed", { error: err }))
      .finally(() => {
        this.delivering = null;
      });
  }

  /** Resolves when the current delivery round (if any) has finished. */
  whenDelivered(): Promise<void> {
    return this.delivering ?? Promise.resolve();
  }

  /**
   * One scheduling round: retire anonymous watches, follow entitlements
   * (removing terminated accounts' watches), resume funded watches, run
   * every due check (in batches, within a time budget), raise alerts, then
   * start webhook delivery in the background.
   */
  async tick(now: number = this.clock()): Promise<void> {
    if (this.ticking) return this.ticking;
    // Deferred to a microtask: a round with nothing to do would otherwise finish
    // (and clear this.ticking in its finally) before the assignment below,
    // leaving a settled promise in place that blocks every later round.
    this.ticking = Promise.resolve().then(async () => {
      try {
        this.retireAnonymousWatches();
        this.reconcileEntitlements(now);
        this.resumeFundedWatches(now);
        const started = performance.now();
        const seen = new Set<string>();
        const pausedThisRound: string[] = [];
        while (!this.halted) {
          const due = (
            this.db.prepare("SELECT domain, kind FROM monitor_schedule WHERE next_at <= ? ORDER BY next_at LIMIT ?").all(now, this.options.concurrency * 8) as unknown as Array<{
              domain: string;
              kind: MonitorCheck;
            }>
          ).filter((row) => !seen.has(`${row.domain}\u0000${row.kind}`));
          if (due.length === 0) break;
          // A row whose check crashed before its schedule was updated must not loop within the round.
          for (const row of due) seen.add(`${row.domain}\u0000${row.kind}`);
          let index = 0;
          const workers = Array.from({ length: Math.min(this.options.concurrency, due.length) }, async () => {
            while (index < due.length && !this.halted) {
              const item = due[index++] as {
                domain: string;
                kind: MonitorCheck;
              };
              try {
                await this.runScheduled(item.domain, item.kind, now, pausedThisRound);
              } catch (err) {
                logger.error("monitor check crashed", {
                  domain: item.domain,
                  check: item.kind,
                  error: err
                });
              }
            }
          });
          await Promise.all(workers);
          if (performance.now() - started >= this.options.tickMs) break; // the rest waits for the next round
        }
        // Watches paused this round still hear about the check they paid for,
        // before a later resume moves their cursor past it (even on shutdown).
        if (pausedThisRound.length > 0) this.collectAlerts(now, { alsoPaused: pausedThisRound });
        if (this.halted) return;
        this.collectAlerts(now);
        this.startDelivery();
      } finally {
        this.ticking = null;
      }
    });
    return this.ticking;
  }

  private kick(): void {
    if (!this.running) return;
    setImmediate(() => {
      void this.tick().catch((err: unknown) => logger.error("monitor tick failed", { error: err }));
    });
  }

  start(): void {
    if (this.running) return;
    this.running = true;
    this.halted = false;
    this.timer = setInterval(() => {
      void this.tick().catch((err: unknown) => logger.error("monitor tick failed", { error: err }));
    }, this.options.tickMs);
    this.timer.unref();
    this.kick();
  }

  async stop(): Promise<void> {
    this.running = false;
    this.halted = true;
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    for (const controller of this.controllers) controller.abort();
    if (this.ticking) await this.ticking.catch(() => undefined);
    if (this.delivering) await this.delivering.catch(() => undefined);
  }

  /** Deletes finished alerts past retention in bounded batches, yielding between them. */
  async pruneAsync(now: number = this.clock(), shouldStop: () => boolean = () => false): Promise<number> {
    const cutoff = now - this.options.alertRetentionDays * 24 * 60 * 60 * 1000;
    const batch = this.db.prepare("DELETE FROM alerts WHERE id IN (SELECT id FROM alerts WHERE created_at < ? AND delivery_status IN ('none', 'delivered', 'failed') LIMIT ?)");
    let removed = 0;
    while (!shouldStop()) {
      const n = Number(batch.run(cutoff, PRUNE_BATCH).changes);
      removed += n;
      if (n < PRUNE_BATCH) break;
      await new Promise((resolve) => setImmediate(resolve));
    }
    return removed;
  }

  prune(now: number = this.clock()): number {
    const cutoff = now - this.options.alertRetentionDays * 24 * 60 * 60 * 1000;
    const batch = this.db.prepare("DELETE FROM alerts WHERE id IN (SELECT id FROM alerts WHERE created_at < ? AND delivery_status IN ('none', 'delivered', 'failed') LIMIT ?)");
    let removed = 0;
    for (;;) {
      const n = Number(batch.run(cutoff, PRUNE_BATCH).changes);
      removed += n;
      if (n < PRUNE_BATCH) return removed;
    }
  }
}

export { MIGRATION_MONITORING } from "./migrations.js";
