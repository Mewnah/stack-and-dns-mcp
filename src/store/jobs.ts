/**
 * Bulk checks: a list of domains is submitted as a job, charged once up
 * front, and worked through in the background by a small pool shared by all
 * jobs (round-robin, so one large job cannot starve the others). Jobs and
 * their per-domain results live in SQLite, survive restarts, and are only
 * visible to the principal that submitted them.
 *
 * Billing rules:
 *   - Invalid and duplicate inputs are skipped and never charged.
 *   - Prepaid (payg) principals are charged credits per accepted domain;
 *     plan principals spend one unit of their daily quota per domain.
 *   - A check that reached a definitive answer is charged, including a
 *     definitive negative such as DOMAIN_NOT_FOUND.
 *   - Items that fail in a way a retry could fix (timeouts, resolver
 *     outages) and items cancelled before they ran are refunded when the job
 *     finishes. Finalization and the credit refund commit in one transaction
 *     on the shared ledger, so a credit refund is applied exactly once.
 *     Daily-quota units live in memory and are returned after the commit,
 *     only by the process that charged them, so a crash or a lease handover
 *     can lose those but never doubles them.
 */

import { randomBytes } from "node:crypto";
import type { PlanName } from "../config.js";
import { untilAborted, withTimeout } from "../lib/async.js";
import { parseDomain } from "../lib/domain.js";
import { errorMessage, isAbortLike, isToolError, ToolError } from "../lib/errors.js";
import { logger } from "../logger.js";
import type { Principal, PrincipalSource } from "../middleware/auth.js";
import type { RateLimiter } from "../middleware/rateLimit.js";
import type { UsageTracker } from "../middleware/usage.js";
import { isLockContention, transaction, type Database } from "./db.js";
import { siteKey } from "./scanStore.js";

export const BULK_CHECKS = ["email", "tech", "audit"] as const;
const PRUNE_ITEMS = 5000;
export type BulkCheck = (typeof BULK_CHECKS)[number];

export type JobStatus = "queued" | "running" | "completed" | "cancelled";
export type ItemStatus = "pending" | "running" | "done" | "failed" | "skipped" | "cancelled";

export { MIGRATION_BULK_JOBS } from "./migrations.js";

export interface NormalizedInputs {
  accepted: Array<{ index: number; input: string; domain: string }>;
  skipped: Array<{ index: number; input: string; code: "INVALID_DOMAIN" | "PRIVATE_TARGET" | "DUPLICATE"; message: string }>;
}

/** Validates and de-duplicates bulk inputs (by site, so www.example.com and example.com count once). */
export function normalizeBulkInputs(inputs: readonly string[], allowPrivate: boolean): NormalizedInputs {
  const accepted: NormalizedInputs["accepted"] = [];
  const skipped: NormalizedInputs["skipped"] = [];
  const firstIndex = new Map<string, number>();
  inputs.forEach((raw, index) => {
    const full = String(raw).slice(0, 2048);
    // Skipped entries are stored for the caller's report; keep them small.
    const input = full.slice(0, 256);
    const parsed = parseDomain(full, { allowPrivate });
    if (!parsed.ok) {
      skipped.push({ index, input, code: parsed.code, message: parsed.error.slice(0, 300) });
      return;
    }
    const key = siteKey(parsed.domain);
    const seen = firstIndex.get(key);
    if (seen !== undefined) {
      skipped.push({ index, input, code: "DUPLICATE", message: `Duplicate of item ${seen} (${key}).` });
      return;
    }
    firstIndex.set(key, index);
    accepted.push({ index, input, domain: parsed.domain });
  });
  return { accepted, skipped };
}

/**
 * Runs one check. Resolving means the domain was checked (charged). Throwing
 * a ToolError with retryable=false means a definitive answer such as
 * DOMAIN_NOT_FOUND (also charged); any other throw is a failure (refunded).
 */
export type BulkCheckRunner = (check: BulkCheck, domain: string, principal: Principal, signal: AbortSignal) => Promise<Record<string, unknown>>;

export interface BulkJobsOptions {
  creditsPerDomain: Record<BulkCheck, number>;
  maxDomains: number;
  concurrency: number;
  itemTimeoutMs: number;
  maxActiveJobsPerPrincipal: number;
  retentionDays: number;
  /** How often the worker looks for work submitted by another process sharing the database (default 5s). */
  pollMs?: number;
}

export interface BulkJobsDeps {
  db: Database;
  usage: UsageTracker;
  limiter: RateLimiter;
  runner: BulkCheckRunner;
  options: BulkJobsOptions;
}

export interface JobCounts {
  pending: number;
  running: number;
  done: number;
  failed: number;
  skipped: number;
  cancelled: number;
}

export interface JobSummary {
  jobId: string;
  check: BulkCheck;
  status: JobStatus;
  submitted: number;
  accepted: number;
  counts: JobCounts;
  creditsPerDomain: number;
  creditsCharged: number;
  creditsRefunded: number;
  quotaUnitsCharged: number;
  quotaUnitsRefunded: number;
  createdAt: string;
  startedAt: string | null;
  finishedAt: string | null;
}

export interface JobItemView {
  index: number;
  input: string;
  domain: string | null;
  status: ItemStatus;
  result: Record<string, unknown> | null;
  error: { code: string; message: string } | null;
}

export interface JobView extends JobSummary {
  items: JobItemView[];
  nextOffset: number | null;
}

export interface JobSubmission {
  job: JobSummary;
  skipped: NormalizedInputs["skipped"];
}

interface JobRow {
  id: string;
  principal_id: string;
  principal_plan: PlanName;
  principal_label: string;
  principal_source: PrincipalSource;
  check_kind: BulkCheck;
  status: JobStatus;
  submitted: number;
  accepted: number;
  credits_per_domain: number;
  credits_charged: number;
  day_units_charged: number;
  credits_refunded: number;
  day_units_refunded: number;
  created_at: number;
  started_at: number | null;
  finished_at: number | null;
  finalized_at: number | null;
  charged_by: string | null;
}

interface ItemRow {
  job_id: string;
  idx: number;
  input: string;
  domain: string | null;
  status: ItemStatus;
  result: string | null;
  error_code: string | null;
  error_message: string | null;
}

function iso(ms: number | null): string | null {
  return ms === null ? null : new Date(ms).toISOString();
}

function newJobId(): string {
  return `job_${randomBytes(12).toString("hex")}`;
}

const CSV_COLUMNS: Record<BulkCheck, string[]> = {
  email: ["score", "grade", "exists", "mxProvider", "spfPolicy", "dmarcPolicy", "dkimFound", "disposable", "highRisks", "summary"],
  tech: ["reachable", "blocked", "httpStatus", "securityScore", "securityGrade", "cms", "ecommerce", "cdn", "technologies"],
  audit: ["overall", "grade", "email", "security", "infrastructure", "highlights"]
};

/** Quotes a CSV cell and neutralizes spreadsheet formula injection. */
export function csvCell(value: unknown): string {
  let text = value === null || value === undefined ? "" : Array.isArray(value) ? value.join("; ") : String(value);
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

export class BulkJobs {
  private readonly db: Database;
  private readonly options: BulkJobsOptions;
  private active = 0;
  private stopped = true;
  private lastServedJob = "";
  private readonly inFlight = new Map<string, AbortController>();
  private idleWaiters: Array<() => void> = [];
  private poller: NodeJS.Timeout | null = null;
  /**
   * Fences this instance's writes: an item is claimed with this token, and
   * its result (or requeue) is only written while the claim still holds, so
   * a worker that lost the lease cannot overwrite what a successor wrote.
   */
  private readonly claimer = randomBytes(8).toString("hex");

  constructor(private readonly deps: BulkJobsDeps) {
    this.db = deps.db;
    this.options = deps.options;
  }

  /** Validates, charges and queues a job. Throws ToolError for anything the caller must fix. */
  submit(principal: Principal, check: BulkCheck, inputs: readonly string[], allowPrivate: boolean): JobSubmission {
    if (!BULK_CHECKS.includes(check)) throw new ToolError("INVALID_ARGUMENT", `Unknown check "${String(check)}"; use email, tech or audit.`);
    if (inputs.length === 0) throw new ToolError("INVALID_ARGUMENT", "Provide at least one domain.");
    if (inputs.length > this.options.maxDomains * 2) {
      throw new ToolError("LIMIT_EXCEEDED", `A job accepts at most ${this.options.maxDomains} domains.`, { details: { maxDomains: this.options.maxDomains } });
    }
    const normalized = normalizeBulkInputs(inputs, allowPrivate);
    const count = normalized.accepted.length;
    if (count === 0) {
      throw new ToolError("INVALID_ARGUMENT", "None of the inputs is a valid public domain.", { details: { skipped: normalized.skipped.slice(0, 20) } });
    }
    // Uncharged rows are stored too: a list that is mostly junk would let a
    // caller fill the database for the price of one domain.
    if (normalized.skipped.length > Math.max(100, count)) {
      throw new ToolError("INVALID_ARGUMENT", `Too many invalid or duplicate inputs (${normalized.skipped.length}) for ${count} accepted domain(s); clean the list and resubmit.`, {
        details: { accepted: count, skipped: normalized.skipped.length }
      });
    }
    if (count > this.options.maxDomains) {
      throw new ToolError("LIMIT_EXCEEDED", `A job accepts at most ${this.options.maxDomains} distinct domains; this one has ${count}.`, {
        details: { maxDomains: this.options.maxDomains, accepted: count }
      });
    }
    const activeJobs = Number((this.db.prepare("SELECT COUNT(*) AS n FROM jobs WHERE principal_id = ? AND status IN ('queued', 'running')").get(principal.id) as { n: number }).n);
    if (activeJobs >= this.options.maxActiveJobsPerPrincipal) {
      throw new ToolError("LIMIT_EXCEEDED", `At most ${this.options.maxActiveJobsPerPrincipal} bulk checks can run at once; wait for one to finish or cancel it.`, {
        retryable: true,
        details: { activeJobs }
      });
    }

    const submittedAt = Date.now();
    const perDomain = this.options.creditsPerDomain[check];
    const creditsCharged = principal.plan === "payg" ? count * perDomain : 0;
    let dayUnits = 0;
    if (principal.plan !== "payg") {
      const decision = this.deps.limiter.consumeDayUnits(principal.id, principal.plan, count, submittedAt);
      if (!decision.allowed) {
        throw new ToolError("RATE_LIMITED", `This job needs ${count} checks but only ${decision.remainingToday} remain in today's quota for plan "${principal.plan}".`, {
          retryable: true,
          details: { scope: "day", remainingToday: decision.remainingToday, requested: count, retryAfterMs: decision.retryAfterMs }
        });
      }
      dayUnits = count;
    }

    const id = newJobId();
    const now = submittedAt;
    try {
      transaction(this.db, () => {
        // The debit is a single statement on the shared ledger, so it commits
        // (or rolls back) together with the job it pays for.
        if (creditsCharged > 0 && !this.deps.usage.consumeCredits(principal.id, creditsCharged)) {
          const balance = this.deps.usage.creditsRemaining(principal.id) ?? 0;
          throw new ToolError("INSUFFICIENT_CREDITS", `This job costs ${creditsCharged} credit(s) (${count} domain(s) x ${perDomain}) but the balance is ${balance}. Top up or submit fewer domains.`, {
            details: { cost: creditsCharged, creditsRemaining: balance, domains: count }
          });
        }
        this.db
          .prepare(
            "INSERT INTO jobs (id, principal_id, principal_plan, principal_label, principal_source, check_kind, status, submitted, accepted, credits_per_domain, credits_charged, day_units_charged, created_at, charged_by) VALUES (?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?, ?, ?, ?, ?)"
          )
          .run(id, principal.id, principal.plan, principal.label, principal.source, check, inputs.length, count, perDomain, creditsCharged, dayUnits, now, this.claimer);
        const item = this.db.prepare("INSERT INTO job_items (job_id, idx, input, domain, status, error_code, error_message) VALUES (?, ?, ?, ?, ?, ?, ?)");
        for (const a of normalized.accepted) item.run(id, a.index, a.input, a.domain, "pending", null, null);
        for (const s of normalized.skipped) item.run(id, s.index, s.input, null, "skipped", s.code, s.message);
      });
    } catch (err) {
      // With the shared ledger the debit rolled back with the job; an
      // in-memory balance has to be restored by hand. Daily-quota units always
      // live in memory.
      const debited = creditsCharged > 0 && !(err instanceof ToolError && err.code === "INSUFFICIENT_CREDITS");
      if (debited && !this.deps.usage.hasSharedLedger) this.deps.usage.addCredits(principal.id, principal.plan, principal.label, creditsCharged);
      if (dayUnits > 0) this.deps.limiter.refundDayUnits(principal.id, dayUnits, submittedAt);
      throw err;
    }
    logger.info("bulk check queued", { jobId: id, principal: principal.id, check, accepted: count, skipped: normalized.skipped.length });
    // The job is committed and charged: dispatch is best-effort (the poller
    // and finishing items pump again), so a claim failure must not reach the
    // caller, who would otherwise retry and pay for a duplicate job.
    try {
      this.pump();
    } catch (err) {
      logger.warn("bulk check dispatch deferred to the poller", { jobId: id, error: err });
    }
    return { job: this.summary(this.row(id) as JobRow), skipped: normalized.skipped };
  }

  private row(jobId: string): JobRow | undefined {
    return this.db.prepare("SELECT * FROM jobs WHERE id = ?").get(jobId) as unknown as JobRow | undefined;
  }

  /** Loads a job owned by the principal; another principal's job is reported exactly like a missing one. */
  private owned(principal: Principal, jobId: string): JobRow {
    const row = typeof jobId === "string" && /^job_[0-9a-f]{24}$/.test(jobId) ? this.row(jobId) : undefined;
    if (!row || row.principal_id !== principal.id) throw new ToolError("NOT_FOUND", `No bulk check ${String(jobId).slice(0, 64)} exists for this caller.`);
    return row;
  }

  private counts(jobId: string): JobCounts {
    const counts: JobCounts = { pending: 0, running: 0, done: 0, failed: 0, skipped: 0, cancelled: 0 };
    const rows = this.db.prepare("SELECT status, COUNT(*) AS n FROM job_items WHERE job_id = ? GROUP BY status").all(jobId) as unknown as Array<{ status: ItemStatus; n: number }>;
    for (const r of rows) counts[r.status] = Number(r.n);
    return counts;
  }

  private summary(row: JobRow): JobSummary {
    return {
      jobId: row.id,
      check: row.check_kind,
      status: row.status,
      submitted: row.submitted,
      accepted: row.accepted,
      counts: this.counts(row.id),
      creditsPerDomain: row.credits_per_domain,
      creditsCharged: row.credits_charged,
      creditsRefunded: row.credits_refunded,
      quotaUnitsCharged: row.day_units_charged,
      quotaUnitsRefunded: row.day_units_refunded,
      createdAt: iso(row.created_at) as string,
      startedAt: iso(row.started_at),
      finishedAt: iso(row.finished_at)
    };
  }

  get(principal: Principal, jobId: string, options: { offset?: number; limit?: number; status?: ItemStatus } = {}): JobView {
    const row = this.owned(principal, jobId);
    const offset = Math.min(Number.MAX_SAFE_INTEGER, Math.max(0, Math.floor(Number.isFinite(options.offset) ? (options.offset as number) : 0)));
    const limit = Math.max(1, Math.min(500, Math.floor(Number.isFinite(options.limit) ? (options.limit as number) : 100)));
    const rows = (options.status
      ? this.db.prepare("SELECT * FROM job_items WHERE job_id = ? AND status = ? ORDER BY idx LIMIT ? OFFSET ?").all(row.id, options.status, limit + 1, offset)
      : this.db.prepare("SELECT * FROM job_items WHERE job_id = ? ORDER BY idx LIMIT ? OFFSET ?").all(row.id, limit + 1, offset)) as unknown as ItemRow[];
    const more = rows.length > limit;
    return { ...this.summary(row), items: rows.slice(0, limit).map((r) => this.itemView(r)), nextOffset: more ? offset + limit : null };
  }

  private itemView(r: ItemRow): JobItemView {
    return {
      index: r.idx,
      input: r.input,
      domain: r.domain,
      status: r.status,
      result: r.result ? (JSON.parse(r.result) as Record<string, unknown>) : null,
      error: r.error_code ? { code: r.error_code, message: r.error_message ?? "" } : null
    };
  }

  list(principal: Principal, limit = 20): JobSummary[] {
    const rows = this.db
      .prepare("SELECT * FROM jobs WHERE principal_id = ? ORDER BY created_at DESC, id DESC LIMIT ?")
      .all(principal.id, Math.max(1, Math.min(100, Math.floor(Number.isFinite(limit) ? limit : 20)))) as unknown as JobRow[];
    return rows.map((r) => this.summary(r));
  }

  /** Cancels the job's pending items (refunded when the job finishes); items already running complete normally. */
  cancel(principal: Principal, jobId: string): JobSummary {
    const row = this.owned(principal, jobId);
    if (row.status === "queued" || row.status === "running") {
      transaction(this.db, () => {
        this.db.prepare("UPDATE job_items SET status = 'cancelled', finished_at = ? WHERE job_id = ? AND status = 'pending'").run(Date.now(), row.id);
        this.db.prepare("UPDATE jobs SET status = 'cancelled' WHERE id = ?").run(row.id);
      });
      try {
        this.maybeFinalize(row.id);
      } catch (err) {
        // The cancellation is committed; the stranded-job sweep applies the refund.
        logger.warn("bulk check finalization deferred", { jobId: row.id, error: err });
      }
    }
    return this.summary(this.row(row.id) as JobRow);
  }

  /** Every item as CSV, one row per submitted input in submission order. */
  resultsCsv(principal: Principal, jobId: string): string {
    const row = this.owned(principal, jobId);
    const columns = CSV_COLUMNS[row.check_kind];
    const lines = [["index", "input", "domain", "status", "error_code", "error_message", ...columns].join(",")];
    const items = this.db.prepare("SELECT * FROM job_items WHERE job_id = ? ORDER BY idx").all(row.id) as unknown as ItemRow[];
    for (const item of items) {
      const result = item.result ? (JSON.parse(item.result) as Record<string, unknown>) : {};
      lines.push([item.idx, item.input, item.domain, item.status, item.error_code, item.error_message, ...columns.map((c) => result[c])].map(csvCell).join(","));
    }
    return `${lines.join("\r\n")}\r\n`;
  }

  /** Begins (or resumes after a restart) background processing. */
  start(): void {
    if (!this.stopped) return;
    this.stopped = false;
    // Only the lease holder calls start(), so any 'running' item belongs to a
    // worker that is gone: requeue it and void its claim.
    const reset = this.db.prepare("UPDATE job_items SET status = 'pending', claimed_by = NULL WHERE status = 'running'").run();
    if (Number(reset.changes) > 0) logger.info("resuming interrupted bulk check items", { items: Number(reset.changes) });
    this.finalizeStranded();
    // Jobs submitted through another process sharing the database never
    // call this instance's pump(), so the worker also polls, and sweeps up
    // jobs whose finalization failed.
    this.poller = setInterval(() => {
      try {
        this.finalizeStranded();
        this.pump();
      } catch (err) {
        logger.warn("bulk check poll failed", { error: err });
      }
    }, this.options.pollMs ?? 5000);
    this.poller.unref();
    this.pump();
  }

  /** Stops dispatching, aborts in-flight checks and waits for them to settle. Interrupted items resume on the next start(). */
  async stop(): Promise<void> {
    this.stopped = true;
    if (this.poller) clearInterval(this.poller);
    this.poller = null;
    for (const controller of this.inFlight.values()) controller.abort(new ToolError("CANCELLED", "server shutting down", { retryable: true }));
    if (this.active === 0) return;
    await new Promise<void>((resolve) => this.idleWaiters.push(resolve));
  }

  /** Resolves when no item is running (for tests and orderly shutdown). */
  whenIdle(): Promise<void> {
    if (this.active === 0 && !this.claimable()) return Promise.resolve();
    return new Promise<void>((resolve) => this.idleWaiters.push(resolve));
  }

  private claimable(): boolean {
    if (this.stopped) return false;
    const row = this.db.prepare("SELECT 1 AS x FROM job_items i JOIN jobs j ON j.id = i.job_id WHERE i.status = 'pending' AND j.status IN ('queued', 'running') LIMIT 1").get();
    return row !== undefined;
  }

  private pump(): void {
    if (this.stopped) return;
    while (this.active < this.options.concurrency) {
      const claim = this.claimNext();
      if (!claim) break;
      this.active++;
      void this.runItem(claim)
        .catch((err: unknown) => logger.error("bulk check item state could not be saved", { jobId: claim.job.id, index: claim.idx, error: err }))
        .finally(() => {
          this.active--;
          try {
            this.pump();
          } catch (err) {
            // Dispatch is best-effort: the poller (and other finishing items) pump again.
            logger.warn("bulk check dispatch deferred to the poller", { error: err });
          }
          try {
            if (this.active === 0 && !this.claimable()) {
              const waiters = this.idleWaiters;
              this.idleWaiters = [];
              for (const resolve of waiters) resolve();
            }
          } catch (err) {
            logger.warn("bulk check idle check failed", { error: err });
          }
        });
    }
  }

  /** Atomically moves the next pending item to running, rotating across active jobs for fairness. */
  private claimNext(): { job: JobRow; idx: number; domain: string } | null {
    return transaction(this.db, () => {
      const jobs = this.db.prepare("SELECT * FROM jobs WHERE status IN ('queued', 'running') ORDER BY created_at, rowid").all() as unknown as JobRow[];
      if (jobs.length === 0) return null;
      const start = jobs.findIndex((j) => j.id === this.lastServedJob) + 1;
      for (let i = 0; i < jobs.length; i++) {
        const job = jobs[(start + i) % jobs.length] as JobRow;
        const item = this.db.prepare("SELECT idx, domain FROM job_items WHERE job_id = ? AND status = 'pending' ORDER BY idx LIMIT 1").get(job.id) as unknown as
          { idx: number; domain: string } | undefined;
        if (!item) continue;
        this.db.prepare("UPDATE job_items SET status = 'running', claimed_by = ? WHERE job_id = ? AND idx = ?").run(this.claimer, job.id, item.idx);
        if (job.status === "queued") this.db.prepare("UPDATE jobs SET status = 'running', started_at = ? WHERE id = ?").run(Date.now(), job.id);
        this.lastServedJob = job.id;
        return { job, idx: item.idx, domain: item.domain };
      }
      return null;
    });
  }

  private async runItem(claim: { job: JobRow; idx: number; domain: string }): Promise<void> {
    const { job, idx, domain } = claim;
    const key = `${job.id}:${idx}`;
    const controller = new AbortController();
    this.inFlight.set(key, controller);
    const principal: Principal = { id: job.principal_id, plan: job.principal_plan, label: job.principal_label, source: job.principal_source };
    let status: ItemStatus;
    let result: string | null = null;
    let errorCode: string | null = null;
    let message: string | null = null;
    try {
      const output = await withTimeout(
        untilAborted(this.deps.runner(job.check_kind, domain, principal, controller.signal), controller.signal),
        this.options.itemTimeoutMs,
        `bulk ${job.check_kind} ${domain}`
      );
      status = "done";
      result = JSON.stringify(output);
    } catch (err) {
      controller.abort();
      if (this.stopped) {
        // Interrupted by shutdown: requeue so the next start() runs it again,
        // unless another worker has taken the item over meanwhile.
        this.inFlight.delete(key);
        this.db.prepare("UPDATE job_items SET status = 'pending', claimed_by = NULL WHERE job_id = ? AND idx = ? AND status = 'running' AND claimed_by = ?").run(job.id, idx, this.claimer);
        return;
      }
      const definitive = isToolError(err) && !err.retryable;
      status = definitive ? "done" : "failed";
      errorCode = isToolError(err) ? err.code : isAbortLike(err) ? "TOOL_TIMEOUT" : "INTERNAL_ERROR";
      message = isToolError(err) ? err.message : `Check did not complete: ${errorMessage(err)}`;
    }
    // The result write is retried through lock contention (another process's
    // prune or migration): dropping it would leave the item 'running' and the
    // job unfinished and unrefunded. The claim fence discards a result that a
    // successor worker has already superseded.
    let written = false;
    await this.durably(() => {
      written =
        Number(
          this.db
            .prepare("UPDATE job_items SET status = ?, result = ?, error_code = ?, error_message = ?, finished_at = ? WHERE job_id = ? AND idx = ? AND status = 'running' AND claimed_by = ?")
            .run(status, result, errorCode, message, Date.now(), job.id, idx, this.claimer).changes
        ) === 1;
    });
    this.inFlight.delete(key);
    if (!written) {
      logger.warn("bulk check item was taken over by another worker; its result is discarded", { jobId: job.id, index: idx });
      return;
    }
    await this.durably(() => this.maybeFinalize(job.id));
  }

  /** Runs a job-state write, retrying while another connection holds the write lock. */
  private async durably(write: () => void): Promise<void> {
    for (let attempt = 1; ; attempt++) {
      try {
        write();
        return;
      } catch (err) {
        if (this.stopped || !isLockContention(err)) throw err;
        if (attempt === 1 || attempt % 10 === 0) logger.warn("bulk check state write hit a locked database; retrying", { attempt, error: err });
        await new Promise((resolve) => setTimeout(resolve, Math.min(5000, 100 * attempt)));
      }
    }
  }

  /** Finalizes every job with nothing left to run whose finalization never happened (a crash, a failed write). */
  private finalizeStranded(): void {
    // An item requeued after its job was cancelled (shutdown, lease handover,
    // crash recovery) is never claimed again: cancel it so the job can finish.
    this.db
      .prepare("UPDATE job_items SET status = 'cancelled', finished_at = ? WHERE status = 'pending' AND job_id IN (SELECT id FROM jobs WHERE status = 'cancelled' AND finalized_at IS NULL)")
      .run(Date.now());
    const rows = this.db
      .prepare("SELECT j.id FROM jobs j WHERE j.finalized_at IS NULL AND NOT EXISTS (SELECT 1 FROM job_items i WHERE i.job_id = j.id AND i.status IN ('pending', 'running'))")
      .all() as unknown as Array<{ id: string }>;
    for (const row of rows) this.maybeFinalize(row.id);
  }

  /** Completes a job with nothing left to run and applies its refunds exactly once. */
  private maybeFinalize(jobId: string): void {
    const refund = transaction(this.db, () => {
      const row = this.row(jobId);
      if (!row || row.finalized_at !== null) return null;
      const counts = this.counts(jobId);
      if (counts.pending > 0 || counts.running > 0) return null;
      const refundable = counts.failed + counts.cancelled;
      const credits = row.credits_charged > 0 ? refundable * row.credits_per_domain : 0;
      const units = row.day_units_charged > 0 ? refundable : 0;
      const now = Date.now();
      this.db
        .prepare(
          "UPDATE jobs SET status = CASE WHEN status = 'cancelled' THEN 'cancelled' ELSE 'completed' END, finished_at = COALESCE(finished_at, ?), finalized_at = ?, credits_refunded = ?, day_units_refunded = ? WHERE id = ?"
        )
        .run(now, now, credits, units, jobId);
      // A single statement on the shared ledger: the refund commits with the
      // finalization, exactly once, whichever process finalizes.
      if (credits > 0) this.deps.usage.addCredits(row.principal_id, row.principal_plan, row.principal_label, credits);
      return { row, credits, units, counts };
    });
    if (!refund) return;
    const { row, credits, units, counts } = refund;
    // Daily-quota windows are per process: units go back only in the process that charged them.
    if (units > 0 && row.charged_by === this.claimer) this.deps.limiter.refundDayUnits(row.principal_id, units, row.created_at);
    logger.info("bulk check finished", { jobId, principal: row.principal_id, ...counts, creditsRefunded: credits, quotaUnitsRefunded: units });
  }

  /**
   * Deletes finished jobs past retention in bounded statements, yielding
   * between them, so a backlog never holds the write lock for long.
   */
  async pruneAsync(now: number = Date.now(), shouldStop: () => boolean = () => false): Promise<number> {
    const cutoff = now - this.options.retentionDays * 24 * 60 * 60 * 1000;
    const nextJob = this.db.prepare("SELECT id FROM jobs WHERE finalized_at IS NOT NULL AND finished_at < ? LIMIT 1");
    const deleteItems = this.db.prepare("DELETE FROM job_items WHERE rowid IN (SELECT rowid FROM job_items WHERE job_id = ? LIMIT ?)");
    const deleteJob = this.db.prepare("DELETE FROM jobs WHERE id = ? AND finalized_at IS NOT NULL");
    const yieldNow = (): Promise<void> => new Promise((resolve) => setImmediate(resolve));
    let removed = 0;
    while (!shouldStop()) {
      const row = nextJob.get(cutoff) as { id: string } | undefined;
      if (!row) break;
      // A finalized job has no pending or running items, so no worker writes them.
      while (!shouldStop() && Number(deleteItems.run(row.id, PRUNE_ITEMS).changes) === PRUNE_ITEMS) await yieldNow();
      if (shouldStop()) break;
      removed += Number(deleteJob.run(row.id).changes);
      await yieldNow();
    }
    return removed;
  }

  /** Deletes finished jobs (and their items) older than the retention window. */
  prune(now: number = Date.now()): number {
    const cutoff = now - this.options.retentionDays * 24 * 60 * 60 * 1000;
    return Number(this.db.prepare("DELETE FROM jobs WHERE finalized_at IS NOT NULL AND finished_at < ?").run(cutoff).changes);
  }
}
