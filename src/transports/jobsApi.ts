/**
 * REST API for bulk checks, for callers that work with spreadsheets and
 * CSV rather than MCP tool calls. It shares the job service (and therefore
 * billing, ownership and limits) with the start/get/cancel MCP tools.
 *
 *   POST   /v1/jobs?check=email          JSON {domains:[...], check?} or a CSV / text body (first column)
 *   GET    /v1/jobs                      the caller's recent jobs
 *   GET    /v1/jobs/:id                  status plus one page of results (?offset, ?limit, ?status)
 *   GET    /v1/jobs/:id/results.csv      every result as CSV
 *   DELETE /v1/jobs/:id                  cancel pending items (refunded when the job finishes)
 */

import express, { type Express, type Request, type RequestHandler, type Response } from "express";
import { parseDomainList } from "../lib/domainList.js";
import { isToolError, ToolError } from "../lib/errors.js";
import { logger } from "../logger.js";
import { principalFromAuthInfo, type AuthenticatedRequest, type Principal } from "../middleware/auth.js";
import { BULK_CHECKS, type BulkCheck, type BulkJobs, type ItemStatus } from "../store/jobs.js";
import { httpStatusFor } from "../tools/bulk.js";

export interface JobsApiDeps {
  jobs: BulkJobs;
  requireAuth: boolean;
  allowPrivateTargets: boolean;
  maxDomains: number;
  /** Largest CSV / plain-text body accepted, in bytes; defaults to 2 MiB. */
  textLimitBytes?: number;
}

const ITEM_STATUSES: readonly ItemStatus[] = ["pending", "running", "done", "failed", "skipped", "cancelled"];
const SKIPPED_SHOWN = 100;

/**
 * A query parameter that must be a non-negative integer when present. A
 * malformed value is refused, as the MCP tools' schemas refuse it, rather
 * than silently replaced by the default; in-range clamping stays with the
 * job service. An empty value counts as absent.
 */
function intParam(value: unknown, name: string, fallback: number): number {
  if (value === undefined || value === "") return fallback;
  if (typeof value !== "string" || !/^\d{1,15}$/.test(value.trim())) throw new ToolError("INVALID_ARGUMENT", `${name} must be a non-negative integer.`);
  return Number(value.trim());
}

/** ?status filters the page; an unknown or repeated value is refused instead of returning the unfiltered page as if it were filtered. */
function statusParam(value: unknown): ItemStatus | undefined {
  if (value === undefined || value === "") return undefined;
  if (typeof value !== "string" || !(ITEM_STATUSES as readonly string[]).includes(value)) throw new ToolError("INVALID_ARGUMENT", `status must be one of ${ITEM_STATUSES.join(", ")}.`);
  return value as ItemStatus;
}

export { parseDomainList } from "../lib/domainList.js";

function sendError(res: Response, err: unknown): void {
  if (isToolError(err)) {
    res.status(httpStatusFor(err)).json({ error: err.toJSON() });
    return;
  }
  logger.error("jobs api request failed", { error: err });
  res.status(500).json({ error: { code: "INTERNAL_ERROR", message: "The request could not be completed.", retryable: true, details: {} } });
}

export function registerJobRoutes(app: Express, deps: JobsApiDeps, auth: RequestHandler): void {
  const principalOf = (req: Request): Principal => {
    const principal = principalFromAuthInfo((req as AuthenticatedRequest).auth);
    if (!principal) throw new ToolError("UNAUTHORIZED", "No principal resolved for this request.");
    // Anonymous principals are shared by everyone behind one address, so
    // private job lists and results need an identified caller.
    if (principal.source === "anonymous") throw new ToolError("UNAUTHORIZED", "Bulk checks need an API key or a prepaid session; anonymous callers share an address-based identity.");
    return principal;
  };

  const textBody = express.text({ type: ["text/csv", "text/plain", "application/csv"], limit: deps.textLimitBytes ?? 2 * 1024 * 1024 });

  app.post("/v1/jobs", auth, textBody, (req, res) => {
    try {
      const principal = principalOf(req);
      const body: unknown = req.body;
      let domains: string[];
      let check: unknown = req.query.check;
      if (typeof body === "string") {
        domains = parseDomainList(body);
      } else if (body && typeof body === "object" && Array.isArray((body as { domains?: unknown }).domains)) {
        const list = (body as { domains: unknown[] }).domains;
        if (!list.every((d) => typeof d === "string")) throw new ToolError("INVALID_ARGUMENT", "domains must be an array of strings.");
        domains = list as string[];
        check = (body as { check?: unknown }).check ?? check;
      } else {
        throw new ToolError("INVALID_ARGUMENT", 'Send JSON {"domains": [...], "check": "email"} or a CSV / plain-text body with one domain per line (?check=email|tech|audit).');
      }
      // Only an absent check falls back to email; anything malformed is refused, never substituted.
      if (check === undefined || check === null) check = "email";
      if (typeof check !== "string" || !(BULK_CHECKS as readonly string[]).includes(check)) {
        throw new ToolError("INVALID_ARGUMENT", `check must be one of ${BULK_CHECKS.join(", ")}.`);
      }
      const kind = check as BulkCheck;
      if (domains.length > deps.maxDomains * 2) throw new ToolError("LIMIT_EXCEEDED", `A job accepts at most ${deps.maxDomains} domains.`, { details: { maxDomains: deps.maxDomains } });
      const submission = deps.jobs.submit(principal, kind, domains, deps.allowPrivateTargets);
      const id = submission.job.jobId;
      res
        .status(202)
        .location(`/v1/jobs/${id}`)
        .json({
          job: submission.job,
          skipped: submission.skipped.slice(0, SKIPPED_SHOWN),
          skippedTotal: submission.skipped.length,
          links: { self: `/v1/jobs/${id}`, results: `/v1/jobs/${id}/results.csv` }
        });
    } catch (err) {
      sendError(res, err);
    }
  });

  app.get("/v1/jobs", auth, (req, res) => {
    try {
      const principal = principalOf(req);
      res.json({ jobs: deps.jobs.list(principal, intParam(req.query.limit, "limit", 20)) });
    } catch (err) {
      sendError(res, err);
    }
  });

  app.get("/v1/jobs/:id/results.csv", auth, (req, res) => {
    try {
      const id = String(req.params.id);
      const csv = deps.jobs.resultsCsv(principalOf(req), id);
      res.set({ "Content-Type": "text/csv; charset=utf-8", "Content-Disposition": `attachment; filename="${id}.csv"`, "Cache-Control": "no-store" }).send(csv);
    } catch (err) {
      sendError(res, err);
    }
  });

  app.get("/v1/jobs/:id", auth, (req, res) => {
    try {
      // The caller is resolved first, so an anonymous request is told it needs a key (401) before anything about its parameters.
      const principal = principalOf(req);
      const offset = intParam(req.query.offset, "offset", 0);
      const limit = intParam(req.query.limit, "limit", 100);
      const status = statusParam(req.query.status);
      res.json(deps.jobs.get(principal, String(req.params.id), { offset, limit, ...(status ? { status } : {}) }));
    } catch (err) {
      sendError(res, err);
    }
  });

  app.delete("/v1/jobs/:id", auth, (req, res) => {
    try {
      res.json({ job: deps.jobs.cancel(principalOf(req), String(req.params.id)) });
    } catch (err) {
      sendError(res, err);
    }
  });
}
