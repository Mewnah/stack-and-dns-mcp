/**
 * MCP tool handlers for domain monitoring. Scheduling, alert collection,
 * billing and webhook delivery live in src/store/monitor.ts.
 */

import { ToolError } from "../lib/errors.js";
import type { ToolContext } from "../middleware/metering.js";
import type { AlertView, Monitor, MonitorCheck, WatchView } from "../store/monitor.js";
import { requireIdentifiedCaller } from "./bulk.js";
import type { ToolDeps } from "./deps.js";

export async function watchDomain(
  args: { domain: string; checks: MonitorCheck[]; webhookUrl?: string | undefined },
  deps: ToolDeps,
  monitor: Monitor,
  ctx: ToolContext
): Promise<{ watch: WatchView; created: boolean; webhookSecret: string | null; watchLimit: number; billing: null }> {
  requireIdentifiedCaller(ctx, "Monitoring");
  const result = monitor.watch(ctx.principal, args.domain, args.checks, args.webhookUrl ?? null, deps.config.inspection.allowPrivateTargets);
  return { watch: result.watch, created: result.created, webhookSecret: result.webhookSecret, watchLimit: monitor.watchLimit(ctx.principal.plan), billing: null };
}

export async function unwatchDomain(args: { watchId?: string | undefined; domain?: string | undefined }, monitor: Monitor, ctx: ToolContext): Promise<{ removed: boolean; billing: null }> {
  requireIdentifiedCaller(ctx, "Monitoring");
  if (!args.watchId && !args.domain) throw new ToolError("INVALID_ARGUMENT", "Pass watchId or domain.");
  return { removed: monitor.unwatch(ctx.principal, { watchId: args.watchId, domain: args.domain }), billing: null };
}

export async function listWatches(monitor: Monitor, ctx: ToolContext): Promise<{ watches: WatchView[]; watchLimit: number; billing: null }> {
  requireIdentifiedCaller(ctx, "Monitoring");
  return { watches: monitor.list(ctx.principal), watchLimit: monitor.watchLimit(ctx.principal.plan), billing: null };
}

export async function getAlerts(
  args: { sinceId: number; limit: number; unreadOnly: boolean; markRead: boolean },
  monitor: Monitor,
  ctx: ToolContext
): Promise<{ alerts: AlertView[]; nextSinceId: number | null; billing: null }> {
  requireIdentifiedCaller(ctx, "Monitoring");
  return { ...monitor.alerts(ctx.principal, args), billing: null };
}
