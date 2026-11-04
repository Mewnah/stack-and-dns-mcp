/**
 * Runs the tool handlers directly (no MCP transport) for quick manual checks.
 *
 *   npm run smoke -- example.com            # comprehensive audit
 *   npm run smoke -- example.com --tech     # inspect_tech_stack only
 *   npm run smoke -- example.com --email    # verify_email_infrastructure only
 */

import { loadConfig } from "../src/config.js";
import { DnsClient } from "../src/lib/dns.js";
import { setLogLevel } from "../src/logger.js";
import type { ToolContext } from "../src/middleware/metering.js";
import { comprehensiveAudit } from "../src/tools/comprehensiveAudit.js";
import { inspectTechStack } from "../src/tools/inspectTechStack.js";
import { verifyEmailInfrastructure } from "../src/tools/verifyEmailInfrastructure.js";

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const domain = argv.find((a) => !a.startsWith("--"));
  if (!domain) {
    process.stderr.write("Usage: npm run smoke -- <domain> [--tech|--email|--audit]\n");
    process.exit(2);
  }
  const mode = argv.includes("--tech") ? "tech" : argv.includes("--email") ? "email" : "audit";
  const config = loadConfig(process.env, []);
  setLogLevel(argv.includes("--verbose") ? "debug" : "warn");
  const dns = new DnsClient({
    servers: config.inspection.dnsServers,
    fallbackServers: config.inspection.dnsFallbackServers,
    timeoutMs: config.inspection.dnsTimeoutMs,
    tries: 2
  });
  const deps = { config, dns };
  const ctx: ToolContext = {
    principal: { id: "smoke", plan: "local", label: "smoke test", source: "local" },
    signal: new AbortController().signal,
    requestId: "smoke"
  };
  const started = Date.now();
  let result: unknown;
  if (mode === "tech") result = await inspectTechStack({ domain, includeRawHeaders: false, includeEvidence: true }, deps, ctx);
  else if (mode === "email") result = await verifyEmailInfrastructure({ domain, dkimSelectors: [], checkMtaSts: true }, deps, ctx);
  else result = await comprehensiveAudit({ domain, dkimSelectors: [], includeRawHeaders: false, includeEvidence: false }, deps, ctx);
  process.stdout.write(JSON.stringify(result, null, 2) + "\n");
  process.stderr.write(`completed in ${Date.now() - started}ms\n`);
}

main().catch((err: unknown) => {
  process.stderr.write(`${err instanceof Error ? (err.stack ?? err.message) : String(err)}\n`);
  process.exit(1);
});
