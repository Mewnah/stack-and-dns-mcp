/**
 * Tool-call meter: resolves the calling principal, enforces plan rate limits
 * and concurrency, charges prepaid credits, bounds execution time, records
 * usage and converts every failure into a structured isError result so the
 * server never surfaces an unhandled exception to the transport.
 */

import type { RequestHandlerExtra } from "@modelcontextprotocol/sdk/shared/protocol.js";
import type { CallToolResult, ServerNotification, ServerRequest } from "@modelcontextprotocol/sdk/types.js";
import { TOOL_CREDIT_COST, type AppConfig, type ToolName } from "../config.js";
import { untilAborted, withTimeout } from "../lib/async.js";
import { errorMessage, isAbortLike, isToolError, ToolError } from "../lib/errors.js";
import { logger } from "../logger.js";
import type { Billing } from "../schemas.js";
import { principalFromAuthInfo, type Principal } from "./auth.js";
import type { RateLimitDecision, RateLimiter } from "./rateLimit.js";
import type { UsageTracker } from "./usage.js";

export interface ToolContext {
  principal: Principal;
  signal: AbortSignal;
  requestId: string | number;
  /** Optional check before every outbound page request (the crawler's robots.txt guard). */
  fetchGuard?: (url: URL) => Promise<void>;
}

export type MeteredHandler<Args, Output extends object> = (args: Args, ctx: ToolContext) => Promise<Output>;

export type ToolCallback<Args> = (args: Args, extra: RequestHandlerExtra<ServerRequest, ServerNotification>) => Promise<CallToolResult>;

export interface MeterDeps {
  config: AppConfig;
  usage: UsageTracker;
  limiter: RateLimiter;
  localPrincipal: Principal;
}

/**
 * Error results deliberately omit structuredContent: MCP clients validate
 * structuredContent against the tool's output schema even when isError is
 * set, and the error envelope intentionally has a different shape. The JSON
 * error body lives in the text content and in _meta.error.
 */
export function errorResult(error: ToolError): CallToolResult {
  const body = { error: error.toJSON() };
  return {
    isError: true,
    content: [{ type: "text", text: JSON.stringify(body, null, 2) }],
    _meta: body
  };
}

export function toToolError(err: unknown, toolName: string, timeoutMs: number): ToolError {
  if (isToolError(err)) return err;
  if (isAbortLike(err)) {
    return new ToolError("TOOL_TIMEOUT", `${toolName} did not complete within ${timeoutMs}ms. The target may be slow or unreachable; retry later.`, {
      retryable: true
    });
  }
  return new ToolError("INTERNAL_ERROR", `Unexpected failure in ${toolName}: ${errorMessage(err)}`, { retryable: true });
}

export function createMeter(deps: MeterDeps) {
  const { config, usage, limiter } = deps;

  return function meter<Args, Output extends object>(toolName: ToolName, handler: MeteredHandler<Args, Output>): ToolCallback<Args> {
    const cost: number = TOOL_CREDIT_COST[toolName];
    // Zero-cost tools are control calls: rate limited per minute, never charged and never counted against the day.
    const countDay = cost > 0;
    return async (args, extra) => {
      const started = Date.now();
      const resolved = principalFromAuthInfo(extra.authInfo);
      const principal = resolved ?? deps.localPrincipal;

      // Over HTTP every route runs the auth middleware, so a request that
      // resolves no principal could only come from a new route that skipped
      // it (or attached a partial AuthInfo); under requireAuth that must fail
      // closed rather than fall back to the process-wide local principal.
      const missingHttpAuth = config.transport === "http" && resolved === null;
      if (config.auth.requireAuth && (principal.source === "anonymous" || missingHttpAuth)) {
        return errorResult(new ToolError("UNAUTHORIZED", "This server requires an API key. Set STACKDNS_API_KEY in the MCP client environment or send Authorization: Bearer <key> over HTTP."));
      }

      const cancelled = (): CallToolResult => errorResult(new ToolError("CANCELLED", `${toolName} was cancelled by the client before it completed.`, { retryable: true }));
      // A cancellation that arrived in the same stdin chunk as the request
      // has already fired the SDK signal; nothing may run or be charged.
      if (extra.signal.aborted) return cancelled();

      const rateLimitError = (decision: RateLimitDecision): CallToolResult =>
        errorResult(
          new ToolError("RATE_LIMITED", `Rate limit exceeded for plan "${principal.plan}" (${decision.scope} window). Retry in ${Math.ceil(decision.retryAfterMs / 1000)}s.`, {
            retryable: true,
            details: {
              scope: decision.scope,
              retryAfterMs: decision.retryAfterMs,
              limitPerMinute: decision.limitPerMinute,
              limitPerDay: decision.limitPerDay,
              resetAt: new Date(decision.resetAtMs).toISOString()
            }
          })
        );

      // Pre-flight only: the minute/day windows are consumed after the
      // concurrency and credit gates pass, so a rejected call never burns quota.
      const preflight = limiter.check(principal.id, principal.plan, { countDay });
      if (!preflight.allowed) return rateLimitError(preflight);

      const slot = limiter.acquire(principal.id, principal.plan);
      if (!slot.ok) {
        return errorResult(
          new ToolError("RATE_LIMITED", `Too many concurrent requests for plan "${principal.plan}". Wait for in-flight calls to finish.`, {
            retryable: true,
            details: { scope: "concurrent", maxConcurrent: limiter.limitsFor(principal.plan).maxConcurrent }
          })
        );
      }

      // The shared credit ledger lives in the database; a refund that cannot
      // be written is logged rather than allowed to fail the response.
      const refund = (): void => {
        try {
          usage.addCredits(principal.id, principal.plan, principal.label, cost);
        } catch (err) {
          logger.error("credit refund failed", { tool: toolName, principal: principal.id, cost, error: err });
        }
      };

      let charged = false;
      if (principal.plan === "payg" && cost > 0) {
        let debited: boolean;
        try {
          debited = usage.consumeCredits(principal.id, cost);
        } catch (err) {
          slot.release();
          logger.error("credit ledger unavailable", { tool: toolName, principal: principal.id, error: err });
          return errorResult(new ToolError("INTERNAL_ERROR", "The credit ledger is temporarily unavailable; nothing was charged. Retry shortly.", { retryable: true }));
        }
        if (!debited) {
          slot.release();
          return errorResult(
            new ToolError("INSUFFICIENT_CREDITS", `This call costs ${cost} credit(s) but the balance is ${usage.creditsRemaining(principal.id) ?? 0}. Complete a new payment challenge to top up.`, {
              details: { cost, creditsRemaining: usage.creditsRemaining(principal.id) ?? 0 }
            })
          );
        }
        charged = true;
      }

      const decision = limiter.consume(principal.id, principal.plan, { countDay });
      if (!decision.allowed) {
        if (charged) refund();
        slot.release();
        return rateLimitError(decision);
      }

      const controller = new AbortController();
      const abortFromClient = (): void => controller.abort(extra.signal.reason);
      extra.signal.addEventListener("abort", abortFromClient, { once: true });
      const timeoutMs = config.inspection.toolTimeoutMs;

      try {
        // The handler races both the deadline and the client's cancellation:
        // inspectors fold aborted sockets into partial results rather than
        // throwing, so without the race a cancelled call would be billed for
        // a plausible-looking but empty report.
        const work = untilAborted(handler(args, { principal, signal: controller.signal, requestId: extra.requestId }), extra.signal);
        const output = await withTimeout(work, timeoutMs, toolName);
        const record = usage.record(principal.id, principal.plan, principal.label, toolName, cost);
        // The windows as they stand after the call: a bulk submission charges its daily-quota units in the
        // handler (one per accepted domain), after `decision` was taken. A non-consuming read.
        const after = limiter.snapshot(principal.id, principal.plan);
        const billing: Billing = {
          principal: principal.id,
          plan: principal.plan,
          creditsCharged: charged ? cost : 0,
          creditsRemaining: record.creditsRemaining,
          requestsRemainingThisMinute: Math.min(decision.remainingThisMinute, after.remainingThisMinute),
          requestsRemainingToday: Math.min(decision.remainingToday, after.remainingToday)
        };
        const structured = { ...output, billing };
        logger.info("tool call completed", { tool: toolName, principal: principal.id, plan: principal.plan, durationMs: Date.now() - started });
        return {
          content: [{ type: "text", text: JSON.stringify(structured, null, 2) }],
          structuredContent: structured
        };
      } catch (err) {
        // Stops the handler's remaining fan-out (DNS probes, fetch retries)
        // once the deadline has passed, so timed-out work does not keep
        // running in the background against the concurrency budget.
        controller.abort();
        if (charged) refund();
        if (extra.signal.aborted) {
          logger.info("tool call cancelled by the client", { tool: toolName, principal: principal.id, durationMs: Date.now() - started });
          return cancelled();
        }
        const toolError = toToolError(err, toolName, timeoutMs);
        logger.warn("tool call failed", { tool: toolName, principal: principal.id, code: toolError.code, message: toolError.message, durationMs: Date.now() - started });
        return errorResult(toolError);
      } finally {
        extra.signal.removeEventListener("abort", abortFromClient);
        slot.release();
      }
    };
  };
}

export type Meter = ReturnType<typeof createMeter>;
