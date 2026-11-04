/**
 * domain_history: what this server has recorded about a domain across every
 * scan it has run: current and past technologies with first/last-seen
 * dates, the latest email posture, and the change log. It reads stored data
 * only and never touches the network.
 */

import { parseDomain } from "../lib/domain.js";
import { ToolError } from "../lib/errors.js";
import type { ToolContext } from "../middleware/metering.js";
import type { DomainHistoryInput, DomainHistoryOutput } from "../schemas.js";
import type { ScanStore } from "../store/scanStore.js";
import type { ToolDeps } from "./deps.js";

export type DomainHistoryResult = Omit<DomainHistoryOutput, "billing"> & { billing: null };

export async function domainHistory(args: DomainHistoryInput, deps: ToolDeps, scans: ScanStore, _ctx: ToolContext): Promise<DomainHistoryResult> {
  const parsed = parseDomain(args.domain, { allowPrivate: deps.config.inspection.allowPrivateTargets });
  if (!parsed.ok) throw new ToolError(parsed.code, parsed.error, { details: { input: args.domain } });
  return { ...scans.history(parsed.domain, args.changesLimit), billing: null };
}
