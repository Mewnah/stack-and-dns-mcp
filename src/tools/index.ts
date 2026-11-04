/**
 * Registers the public tools on an McpServer instance, wrapping each handler
 * with the metering layer. Storage-backed tools are only registered when a
 * database is available (and their feature is enabled), so agents never see
 * a tool that cannot work.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { AppConfig } from "../config.js";
import { DEFAULT_DKIM_SELECTORS } from "../lib/dkim.js";
import type { DnsClient } from "../lib/dns.js";
import { logger } from "../logger.js";
import type { Meter } from "../middleware/metering.js";
import {
  CancelBulkCheckInputSchema,
  CancelBulkCheckOutputSchema,
  ComprehensiveAuditInputSchema,
  ComprehensiveAuditOutputSchema,
  DomainHistoryInputSchema,
  DomainHistoryOutputSchema,
  FindDomainsUsingInputSchema,
  FindDomainsUsingOutputSchema,
  GetAlertsInputSchema,
  GetAlertsOutputSchema,
  GetBulkCheckInputSchema,
  GetBulkCheckOutputSchema,
  InspectTechStackInputSchema,
  InspectTechStackOutputSchema,
  ListBulkChecksInputSchema,
  ListBulkChecksOutputSchema,
  ListTechnologiesInputSchema,
  ListTechnologiesOutputSchema,
  ListWatchesInputSchema,
  ListWatchesOutputSchema,
  BULK_RESULT_VALUES,
  BULK_SKIP_RULE,
  startBulkCheckInputSchema,
  StartBulkCheckOutputSchema,
  UnwatchDomainInputSchema,
  UnwatchDomainOutputSchema,
  VerifyEmailInfrastructureInputSchema,
  VerifyEmailInfrastructureOutputSchema,
  WatchDomainInputSchema,
  WatchDomainOutputSchema
} from "../schemas.js";
import { signatureCount } from "../signatures/index.js";
import type { Storage } from "../store/index.js";
import type { Crawler } from "../store/crawler.js";
import type { BulkJobs } from "../store/jobs.js";
import type { Monitor } from "../store/monitor.js";
import type { ReverseLookup } from "../store/reverse.js";
import { cancelBulkCheck, getBulkCheck, listBulkChecks, startBulkCheck } from "./bulk.js";
import { comprehensiveAudit } from "./comprehensiveAudit.js";
import type { ToolDeps } from "./deps.js";
import { domainHistory } from "./domainHistory.js";
import { inspectTechStack } from "./inspectTechStack.js";
import { getAlerts, listWatches, unwatchDomain, watchDomain } from "./monitor.js";
import { findDomainsUsing, listTechnologies } from "./reverse.js";
import { verifyEmailInfrastructure } from "./verifyEmailInfrastructure.js";

export interface RegisterToolsDeps {
  config: AppConfig;
  dns: DnsClient;
  meter: Meter;
  storage: Storage | null;
  jobs: BulkJobs | null;
  monitor: Monitor | null;
  reverse: ReverseLookup | null;
  crawler: Crawler | null;
}

/** Which optional tool groups a server exposes. */
export interface ToolFeatures {
  history: boolean;
  bulk: boolean;
  monitor: boolean;
  reverse: boolean;
}

export function toolFeatures(deps: Pick<RegisterToolsDeps, "storage" | "jobs" | "monitor" | "reverse">): ToolFeatures {
  return { history: deps.storage !== null, bulk: deps.jobs !== null, monitor: deps.monitor !== null, reverse: deps.reverse !== null };
}

export function registerTools(server: McpServer, deps: RegisterToolsDeps): void {
  const toolDeps: ToolDeps = { config: deps.config, dns: deps.dns, ...(deps.storage ? { knownDkimSelectors: (domain: string) => (deps.storage as Storage).scans.knownDkimSelectors(domain) } : {}) };
  const signatures = signatureCount();
  const storage = deps.storage;

  /**
   * Storing a scan is a side effect of a paid call and must never fail it.
   * A call that was cancelled or hit its deadline may carry lookups that were
   * cut short, which would read as removed technologies or lost records, so
   * its result is returned to the caller but not recorded.
   */
  const remember = (signal: AbortSignal, what: string, record: (store: Storage) => unknown): void => {
    if (!storage || signal.aborted) return;
    try {
      record(storage);
    } catch (err) {
      logger.warn("scan could not be stored", { what, error: err });
    }
  };

  // Each attempt gets the configured timeout and the whole fetch (insecure-TLS
  // retry and http:// fallback included) is bounded to twice that (src/lib/http.ts),
  // so the description is derived from config rather than a fixed "3-second" claim.
  const perAttemptSeconds = deps.config.inspection.fetchTimeoutMs / 1000;
  server.registerTool(
    "inspect_tech_stack",
    {
      title: "Inspect Web Technology Stack",
      description:
        `Fetch a company's homepage (${perAttemptSeconds}-second deadline per attempt, at most ${perAttemptSeconds * 2} s including the insecure-TLS retry and the http:// fallback; transparent bot User-Agent) and fingerprint its technology stack against ${signatures} signatures: CMS / site builder, e-commerce platform, JavaScript framework, CDN & hosting, WAF, analytics, tag manager, marketing automation, CRM, live chat, payments, advertising pixels, consent management and more. ` +
        "Also inspects the TLS certificate (validity, expiry, issuer, hostname match) and grades HTTP security headers (HSTS, CSP, X-Frame-Options, cookies) into a 0-100 security score. " +
        "Handles redirects, WAF challenge pages (reported as blocked=true), timeouts and unreachable hosts gracefully. " +
        'Use it to qualify prospects ("is this a Shopify store using Klaviyo?"), research competitors, or pre-screen leads. Cost: 1 credit.',
      inputSchema: InspectTechStackInputSchema,
      outputSchema: InspectTechStackOutputSchema,
      annotations: { title: "Inspect Web Technology Stack", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }
    },
    deps.meter("inspect_tech_stack", async (args, ctx) => {
      const result = await inspectTechStack(args, toolDeps, ctx);
      remember(ctx.signal, "tech", (s) => s.scans.recordTech(result, "call"));
      return result;
    })
  );

  server.registerTool(
    "verify_email_infrastructure",
    {
      title: "Verify Email Infrastructure & Deliverability",
      description:
        `Run live DNS checks on a domain's email setup: MX records with provider identification (Google Workspace, Microsoft 365, Proofpoint...), SPF parsing with recursive include resolution and the 10-lookup limit, DKIM key discovery across ${DEFAULT_DKIM_SELECTORS.length} common selectors (key type and length), DMARC policy and reporting configuration (with organizational-domain fallback), MTA-STS, TLS-RPT, BIMI and disposable-domain detection. ` +
        "Returns a severity-sorted list of deliverability and spoofing risks with remediation advice, the detected sending platforms, and a 0-100 deliverability score with a per-component breakdown. " +
        "Use it before outbound campaigns, to validate lead domains, or to audit a prospect's email security. Cost: 1 credit.",
      inputSchema: VerifyEmailInfrastructureInputSchema,
      outputSchema: VerifyEmailInfrastructureOutputSchema,
      annotations: { title: "Verify Email Infrastructure", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }
    },
    deps.meter("verify_email_infrastructure", async (args, ctx) => {
      const result = await verifyEmailInfrastructure(args, toolDeps, ctx);
      remember(ctx.signal, "email", (s) => s.scans.recordEmail(result, "call"));
      return result;
    })
  );

  server.registerTool(
    "comprehensive_audit",
    {
      title: "Comprehensive Domain Audit",
      description:
        "Run inspect_tech_stack and verify_email_infrastructure concurrently and aggregate them into a single 0-100 health score (email deliverability 40%, security posture 35%, infrastructure maturity 25%) with a letter grade, merged severity-sorted findings, and human-readable highlights suitable for a research brief or CRM enrichment. " +
        "Includes the full output of both underlying tools. If one inspection fails the other still completes and the error is reported inline. Cost: 2 credits.",
      inputSchema: ComprehensiveAuditInputSchema,
      outputSchema: ComprehensiveAuditOutputSchema,
      annotations: { title: "Comprehensive Domain Audit", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }
    },
    deps.meter("comprehensive_audit", async (args, ctx) => {
      const result = await comprehensiveAudit(args, toolDeps, ctx);
      if (result.techStack) {
        const techStack = result.techStack;
        remember(ctx.signal, "tech", (s) => s.scans.recordTech(techStack, "call"));
      }
      if (result.email) {
        const email = result.email;
        remember(ctx.signal, "email", (s) => s.scans.recordEmail(email, "call"));
      }
      return result;
    })
  );

  if (storage) {
    server.registerTool(
      "domain_history",
      {
        title: "Domain Change History",
        description:
          "Return everything this server has recorded about a domain from earlier scans, without running a new one: current and past technologies with first-seen and last-seen dates, the latest email posture (MX provider, SPF and DMARC policy, DKIM selectors, high risks), and a dated change log (technologies added or removed, DMARC weakened, DKIM key lost, MX provider changed, score drops). " +
          "Use it to spot a prospect that just adopted or dropped a tool, or to see how a domain's email security has moved over time. known=false means the domain has never been scanned here; run inspect_tech_stack or verify_email_infrastructure first. Cost: 1 credit.",
        inputSchema: DomainHistoryInputSchema,
        outputSchema: DomainHistoryOutputSchema,
        annotations: { title: "Domain Change History", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
      },
      deps.meter("domain_history", (args, ctx) => domainHistory(args, toolDeps, storage.scans, ctx))
    );
  }

  const jobs = deps.jobs;
  if (jobs) {
    const bulkNote = `Charged when the job is accepted, per accepted domain, at the matching single-domain tool's price (email 1, tech 1, audit 2 credits, or one daily-quota unit per domain on plan keys); items that fail for retryable reasons or are cancelled are refunded when the job finishes; the charge shows in job.creditsCharged or job.quotaUnitsCharged, not in billing.creditsCharged. Invalid and duplicate inputs are never charged, but ${BULK_SKIP_RULE}`;
    server.registerTool(
      "start_bulk_check",
      {
        title: "Start Bulk Domain Check",
        description:
          `Queue a lead list for background checking: email (deliverability), tech (technology stack) or audit (both) for up to ${deps.config.bulk.maxDomains} domains. Returns a job id immediately; poll get_bulk_check for progress and paged results. ` +
          `Every scan is also recorded for domain_history. ${bulkNote}`,
        inputSchema: startBulkCheckInputSchema(deps.config.bulk.maxDomains),
        outputSchema: StartBulkCheckOutputSchema,
        annotations: { title: "Start Bulk Domain Check", readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true }
      },
      deps.meter("start_bulk_check", (args, ctx) => startBulkCheck(args, toolDeps, jobs, ctx))
    );
    server.registerTool(
      "get_bulk_check",
      {
        title: "Get Bulk Check Status and Results",
        description: `Status, counts and one page of per-domain results for a bulk check started by this caller. Results are compact summaries (score, grade, providers, policies, technologies). ${BULK_RESULT_VALUES} Free.`,
        inputSchema: GetBulkCheckInputSchema,
        outputSchema: GetBulkCheckOutputSchema,
        annotations: { title: "Get Bulk Check", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
      },
      deps.meter("get_bulk_check", (args, ctx) => getBulkCheck(args, jobs, ctx))
    );
    server.registerTool(
      "list_bulk_checks",
      {
        title: "List Bulk Checks",
        description: "This caller's most recent bulk checks, newest first, with status and counts. Free.",
        inputSchema: ListBulkChecksInputSchema,
        outputSchema: ListBulkChecksOutputSchema,
        annotations: { title: "List Bulk Checks", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
      },
      deps.meter("list_bulk_checks", (args, ctx) => listBulkChecks(args, jobs, ctx))
    );
    server.registerTool(
      "cancel_bulk_check",
      {
        title: "Cancel Bulk Check",
        description: "Cancel the pending items of a bulk check; items already running finish normally. Cancelled items are refunded when the job finishes. Free.",
        inputSchema: CancelBulkCheckInputSchema,
        outputSchema: CancelBulkCheckOutputSchema,
        annotations: { title: "Cancel Bulk Check", readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false }
      },
      deps.meter("cancel_bulk_check", (args, ctx) => cancelBulkCheck(args, jobs, ctx))
    );
  }

  const monitor = deps.monitor;
  if (monitor) {
    const hours = Math.round((deps.config.monitor.intervalMs / 3600000) * 10) / 10;
    const perCheck = deps.config.monitor.creditsPerCheck;
    server.registerTool(
      "watch_domain",
      {
        title: "Watch Domain for Changes",
        description:
          `Re-check a domain every ${hours} hour(s) and raise an alert when its email posture (DMARC or SPF weakened, DKIM key lost, MX provider changed, score drop...) or technology stack (tool added or removed) changes. Alerts are read with get_alerts and can also be pushed to a signed webhook. ` +
          `Watching a domain again updates its checks and webhook. Plan keys include a number of watched domains; prepaid callers pay ${perCheck} credit(s) per scheduled check, and a watch pauses (with an alert) when the balance runs out and resumes after a top-up. Watching itself is free.`,
        inputSchema: WatchDomainInputSchema,
        outputSchema: WatchDomainOutputSchema,
        annotations: { title: "Watch Domain", readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true }
      },
      deps.meter("watch_domain", (args, ctx) => watchDomain(args, toolDeps, monitor, ctx))
    );
    server.registerTool(
      "unwatch_domain",
      {
        title: "Stop Watching Domain",
        description: "Stop watching a domain (by watchId or domain); its alerts are deleted with it. Free.",
        inputSchema: UnwatchDomainInputSchema,
        outputSchema: UnwatchDomainOutputSchema,
        annotations: { title: "Stop Watching Domain", readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false }
      },
      deps.meter("unwatch_domain", (args, ctx) => unwatchDomain(args, monitor, ctx))
    );
    server.registerTool(
      "list_watches",
      {
        title: "List Watched Domains",
        description: "This caller's watched domains with their checks, last and next check times and pause state. Free.",
        inputSchema: ListWatchesInputSchema,
        outputSchema: ListWatchesOutputSchema,
        annotations: { title: "List Watched Domains", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
      },
      deps.meter("list_watches", (_args, ctx) => listWatches(monitor, ctx))
    );
    server.registerTool(
      "get_alerts",
      {
        title: "Get Change Alerts",
        description:
          "Alerts raised for this caller's watched domains, oldest first. Each names the domain, what changed (e.g. dmarc_policy reject -> none, tech_added Klaviyo, dkim_lost), the old and new values and a severity. By default returns unread alerts and marks them read. Free.",
        inputSchema: GetAlertsInputSchema,
        outputSchema: GetAlertsOutputSchema,
        annotations: { title: "Get Change Alerts", readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false }
      },
      deps.meter("get_alerts", (args, ctx) => getAlerts(args, monitor, ctx))
    );
  }

  const reverse = deps.reverse;
  if (reverse) {
    const crawler = deps.crawler;
    server.registerTool(
      "find_domains_using",
      {
        title: "Find Domains Using a Technology",
        description:
          "Reverse lookup: list domains that run a given technology (e.g. Shopify, Klaviyo, HubSpot, Cloudflare), most recently seen first, with the version and first-seen and last-seen dates. " +
          "Answers come from this server's crawl of an operator-curated domain list (universe.domains says how large it is), never from other customers' lookups, so results are a sample rather than the whole internet. " +
          "Use it to build lead lists by stack or to size a technology's footprint. Set activeOnly=false to include domains that removed it. Cost: 2 credits per page.",
        inputSchema: FindDomainsUsingInputSchema,
        outputSchema: FindDomainsUsingOutputSchema,
        annotations: { title: "Find Domains Using a Technology", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
      },
      deps.meter("find_domains_using", (args, ctx) => findDomainsUsing(args, reverse, crawler, ctx))
    );
    server.registerTool(
      "list_technologies",
      {
        title: "List Detectable Technologies",
        description:
          "Browse the technologies this server detects (id, name, category) with how many crawled domains currently use each; filter by name or category. Use the id with find_domains_using. Free.",
        inputSchema: ListTechnologiesInputSchema,
        outputSchema: ListTechnologiesOutputSchema,
        annotations: { title: "List Detectable Technologies", readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
      },
      deps.meter("list_technologies", (args, ctx) => listTechnologies(args, reverse, ctx))
    );
  }
}

/** Names of the tools registerTools exposes for the given features. */
export function toolNames(features: ToolFeatures): string[] {
  const names = ["inspect_tech_stack", "verify_email_infrastructure", "comprehensive_audit"];
  if (features.history) names.push("domain_history");
  if (features.bulk) names.push("start_bulk_check", "get_bulk_check", "list_bulk_checks", "cancel_bulk_check");
  if (features.monitor) names.push("watch_domain", "unwatch_domain", "list_watches", "get_alerts");
  if (features.reverse) names.push("find_domains_using", "list_technologies");
  return names;
}
