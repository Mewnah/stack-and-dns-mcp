/**
 * Bulk checks for lead lists: the per-domain runner that the job worker
 * calls, the compact per-domain summaries stored with each job, and the MCP
 * tool handlers (start, poll, list, cancel). Charging and scheduling live in
 * src/store/jobs.ts so the MCP tools and the REST API share one path.
 */

import { ToolError } from "../lib/errors.js";
import { logger } from "../logger.js";
import type { ToolContext } from "../middleware/metering.js";
import type { Storage } from "../store/index.js";
import type { BulkCheck, BulkCheckRunner, BulkJobs, ItemStatus, JobSummary, JobView, NormalizedInputs } from "../store/jobs.js";
import { comprehensiveAudit, type AuditResult } from "./comprehensiveAudit.js";
import type { ToolDeps } from "./deps.js";
import { inspectTechStack, type TechStackResult } from "./inspectTechStack.js";
import { emailLookupFailures, ownFindings, verifyEmailInfrastructure, type EmailResult } from "./verifyEmailInfrastructure.js";

export function summarizeEmail(r: EmailResult): Record<string, unknown> {
  // A lookup that failed is reported as unknown, never as missing.
  const failed = emailLookupFailures(r);
  return {
    exists: true,
    score: r.score,
    grade: r.grade,
    mxProvider: r.mx.nullMx ? "null MX (no mail)" : failed.mx ? "unknown" : r.providers.mailbox,
    spfPolicy: r.spf.found ? (failed.spfPolicy ? "unknown" : r.spf.allPolicy) : failed.spf ? "unknown" : "missing",
    dmarcPolicy: r.dmarc.found ? (failed.dmarcPolicy ? "unknown" : (r.dmarc.effectivePolicy ?? "invalid")) : failed.dmarc ? "unknown" : "missing",
    dkimFound: r.dkim.found,
    disposable: r.disposable.disposable,
    // The organizational record's DMARC findings are not the subdomain's own when its lookup failed.
    highRisks: ownFindings(r.risks, r)
      .filter((f) => f.severity === "critical" || f.severity === "high")
      .map((f) => f.code),
    summary: r.summary
  };
}

export function summarizeTech(r: TechStackResult): Record<string, unknown> {
  return {
    reachable: r.fetch.ok,
    blocked: r.blocked.blocked,
    httpStatus: r.fetch.status,
    securityScore: r.security.score,
    securityGrade: r.security.grade,
    cms: r.summary.cms,
    ecommerce: r.summary.ecommerce,
    cdn: r.summary.cdn,
    technologies: r.technologies.map((t) => t.name)
  };
}

export function summarizeAudit(r: AuditResult): Record<string, unknown> {
  return {
    overall: r.scores.overall,
    grade: r.scores.grade,
    email: r.scores.email,
    security: r.scores.security,
    infrastructure: r.scores.infrastructure,
    highlights: r.highlights.slice(0, 5)
  };
}

/**
 * Runs one bulk item with the same inspectors as the single-domain tools,
 * recording the scan like a direct call would. An item that hit its deadline
 * or was cancelled may hold lookups that were cut short, so it is not
 * recorded.
 */
export function createBulkRunner(toolDeps: ToolDeps, storage: Storage): BulkCheckRunner {
  return async (check, domain, principal, signal) => {
    const remember = (fn: () => unknown): void => {
      if (signal.aborted) return;
      try {
        fn();
      } catch (err) {
        logger.warn("bulk scan could not be stored", { error: err });
      }
    };
    const ctx: ToolContext = { principal, signal, requestId: "bulk" };
    if (check === "email") {
      const result = await verifyEmailInfrastructure({ domain, dkimSelectors: storage.scans.knownDkimSelectors(domain), checkMtaSts: true }, toolDeps, ctx);
      remember(() => storage.scans.recordEmail(result, "bulk"));
      return summarizeEmail(result);
    }
    if (check === "tech") {
      const result = await inspectTechStack({ domain, includeRawHeaders: false, includeEvidence: false }, toolDeps, ctx);
      remember(() => storage.scans.recordTech(result, "bulk"));
      return summarizeTech(result);
    }
    const result = await comprehensiveAudit({ domain, dkimSelectors: storage.scans.knownDkimSelectors(domain), includeRawHeaders: false, includeEvidence: false }, toolDeps, ctx);
    if (result.techStack) {
      const techStack = result.techStack;
      remember(() => storage.scans.recordTech(techStack, "bulk"));
    }
    if (result.email) {
      const email = result.email;
      remember(() => storage.scans.recordEmail(email, "bulk"));
    }
    return summarizeAudit(result);
  };
}

const SKIPPED_SHOWN = 100;

export interface StartBulkCheckOutput {
  job: JobSummary;
  skipped: NormalizedInputs["skipped"];
  skippedTotal: number;
  next: string;
  billing: null;
}

/** Anonymous principals are shared by everyone behind one address, so private job lists need an identified caller. */
export function requireIdentifiedCaller(ctx: ToolContext, feature: string): void {
  if (ctx.principal.source === "anonymous") {
    throw new ToolError("UNAUTHORIZED", `${feature} needs an API key or a prepaid session; anonymous callers share an address-based identity.`);
  }
}

export async function startBulkCheck(args: { check: BulkCheck; domains: string[] }, deps: ToolDeps, jobs: BulkJobs, ctx: ToolContext): Promise<StartBulkCheckOutput> {
  requireIdentifiedCaller(ctx, "Bulk checks");
  const submission = jobs.submit(ctx.principal, args.check, args.domains, deps.config.inspection.allowPrivateTargets);
  return {
    job: submission.job,
    skipped: submission.skipped.slice(0, SKIPPED_SHOWN),
    skippedTotal: submission.skipped.length,
    next: `Poll get_bulk_check with jobId "${submission.job.jobId}" until status is completed or cancelled; results are paged with offset/limit.`,
    billing: null
  };
}

export async function getBulkCheck(args: { jobId: string; offset: number; limit: number; status?: ItemStatus | undefined }, jobs: BulkJobs, ctx: ToolContext): Promise<JobView & { billing: null }> {
  requireIdentifiedCaller(ctx, "Bulk checks");
  return { ...jobs.get(ctx.principal, args.jobId, { offset: args.offset, limit: args.limit, ...(args.status ? { status: args.status } : {}) }), billing: null };
}

export async function listBulkChecks(args: { limit: number }, jobs: BulkJobs, ctx: ToolContext): Promise<{ jobs: JobSummary[]; billing: null }> {
  requireIdentifiedCaller(ctx, "Bulk checks");
  return { jobs: jobs.list(ctx.principal, args.limit), billing: null };
}

export async function cancelBulkCheck(args: { jobId: string }, jobs: BulkJobs, ctx: ToolContext): Promise<{ job: JobSummary; billing: null }> {
  requireIdentifiedCaller(ctx, "Bulk checks");
  return { job: jobs.cancel(ctx.principal, args.jobId), billing: null };
}

/** Maps a ToolError from the bulk service to the HTTP status the REST API answers with. */
export function httpStatusFor(err: ToolError): number {
  switch (err.code) {
    case "INVALID_ARGUMENT":
    case "INVALID_DOMAIN":
    case "PRIVATE_TARGET":
      return 400;
    case "UNAUTHORIZED":
      return 401;
    case "INSUFFICIENT_CREDITS":
    case "PAYMENT_REQUIRED":
      return 402;
    case "NOT_FOUND":
      return 404;
    case "LIMIT_EXCEEDED":
      return err.retryable ? 429 : 413;
    case "RATE_LIMITED":
      return 429;
    default:
      return 500;
  }
}
