/**
 * McpServer factory. The HTTP transport creates one server per session, so
 * everything expensive (DNS client, usage store, limiter, database) lives in
 * the shared deps object and the server itself is cheap to construct.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { AppConfig } from "./config.js";
import type { DnsClient } from "./lib/dns.js";
import type { Principal } from "./middleware/auth.js";
import { createMeter } from "./middleware/metering.js";
import type { RateLimiter } from "./middleware/rateLimit.js";
import type { UsageTracker } from "./middleware/usage.js";
import type { Services } from "./services.js";
import { signatureCount } from "./signatures/index.js";
import { registerTools, toolFeatures, toolNames, type ToolFeatures } from "./tools/index.js";

export interface ServerDeps {
  config: AppConfig;
  usage: UsageTracker;
  limiter: RateLimiter;
  localPrincipal: Principal;
  dns: DnsClient;
  /** Database-backed features (stored scans, bulk checks, monitoring); each is null when unavailable. */
  services: Services;
}

const BASE_INSTRUCTIONS = `stack-and-dns-mcp inspects public domains for B2B research, lead qualification and outbound readiness.

Tools:
- inspect_tech_stack(domain): homepage technology fingerprinting (CMS, e-commerce, frameworks, CDN, analytics, marketing automation, CRM, payments, chat, pixels) plus TLS and HTTP security-header grading. 1 credit.
- verify_email_infrastructure(domain): MX / SPF / DKIM / DMARC / MTA-STS / TLS-RPT / BIMI checks with deliverability risks, sending-platform detection and a 0-100 score. 1 credit.
- comprehensive_audit(domain): both of the above concurrently, merged into one 0-100 health score with highlights. 2 credits.`;

const HISTORY_INSTRUCTIONS = `
- domain_history(domain): stored technologies, email posture and dated changes from earlier scans, without a new scan. 1 credit.`;

const BULK_INSTRUCTIONS = `
- start_bulk_check(check, domains[]): queue a lead list (email, tech or audit per domain) as a background job, charged per accepted domain up front with refunds for retryable failures; then poll get_bulk_check(jobId) for paged results. list_bulk_checks and cancel_bulk_check manage jobs. Polling is free.`;

const REVERSE_INSTRUCTIONS = `
- find_domains_using(technology): domains on this server's crawl list that run a technology, for stack-based lead lists; list_technologies browses what can be detected (free). 2 credits per page.`;

const MONITOR_INSTRUCTIONS = `
- watch_domain(domain, checks, webhookUrl?): re-check a domain on a schedule and raise alerts when its email posture or technology stack changes; read them with get_alerts (free) or receive them on a signed webhook. unwatch_domain and list_watches manage watches.`;

const COMMON_INSTRUCTIONS = `

Pass a bare domain, a URL or an email address; the server normalizes it. Results are JSON in both the text content and structuredContent. Errors are returned as isError results with an "error" object ({code, message, retryable, details}); never retry INVALID_DOMAIN, PRIVATE_TARGET or DOMAIN_NOT_FOUND. RATE_LIMITED and TOOL_TIMEOUT are retryable after the indicated delay; CANCELLED means the request was cancelled before completion and nothing was charged. Arguments that do not match a tool's input schema (an empty or whitespace-only domain included), and unknown tool names, are rejected before the tool runs with a plain-text isError result ("MCP error -32602: ...") that has no error object and is not charged; correct the arguments rather than retrying unchanged. Each result includes a "billing" object with the remaining quota.`;

const NO_FEATURES: ToolFeatures = { history: false, bulk: false, monitor: false, reverse: false };

export function serverInstructions(features: ToolFeatures): string {
  return (
    BASE_INSTRUCTIONS +
    (features.history ? HISTORY_INSTRUCTIONS : "") +
    (features.bulk ? BULK_INSTRUCTIONS : "") +
    (features.monitor ? MONITOR_INSTRUCTIONS : "") +
    (features.reverse ? REVERSE_INSTRUCTIONS : "") +
    COMMON_INSTRUCTIONS
  );
}

/** Instructions for a server without storage; kept for callers that describe the base toolset. */
export const SERVER_INSTRUCTIONS = serverInstructions(NO_FEATURES);

export function createMcpServer(deps: ServerDeps): McpServer {
  const { storage, jobs, monitor, reverse, crawler } = deps.services;
  const server = new McpServer(
    { name: deps.config.name, version: deps.config.version, title: "Stack & DNS Inspector" },
    { capabilities: { tools: {}, logging: {} }, instructions: serverInstructions(toolFeatures({ storage, jobs, monitor, reverse })) }
  );
  const meter = createMeter({ config: deps.config, usage: deps.usage, limiter: deps.limiter, localPrincipal: deps.localPrincipal });
  registerTools(server, { config: deps.config, dns: deps.dns, meter, storage, jobs, monitor, reverse, crawler });
  return server;
}

export function describeServer(config: AppConfig, features: ToolFeatures): Record<string, unknown> {
  return {
    name: config.name,
    version: config.version,
    protocol: "Model Context Protocol",
    signatures: signatureCount(),
    tools: toolNames(features),
    endpoints: {
      streamableHttp: `${config.http.publicUrl}/mcp`,
      sse: `${config.http.publicUrl}/sse`,
      health: `${config.http.publicUrl}/healthz`,
      pricing: `${config.http.publicUrl}/pricing`,
      usage: `${config.http.publicUrl}/usage`
    },
    authentication: {
      apiKey: "Authorization: Bearer sdm_live_... (or X-API-Key header)",
      payment: "HTTP 402 challenge with WWW-Authenticate: Payment (Stripe / x402); redeem with Authorization: Payment <base64url json> or X-PAYMENT",
      sessionToken: "Authorization: Bearer sdm_sess.<token> (issued in the Payment-Receipt header after a successful payment)"
    }
  };
}
