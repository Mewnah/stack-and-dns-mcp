import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

// Usage:
//   node scripts/e2e-client.mjs stdio [domain]
//   SDM_KEY=sdm_live_... [SDM_URL=http://localhost:3333/mcp] node scripts/e2e-client.mjs http [domain]
const mode = process.argv[2] ?? "stdio";
const domain = process.argv[3] ?? "example.com";
/** Matches the server's default port (STACKDNS_PORT=3333); override with SDM_URL. */
const DEFAULT_HTTP_URL = "http://localhost:3333/mcp";

async function run(transport, label) {
  const client = new Client({ name: "e2e-client", version: "1.0.0" });
  await client.connect(transport);
  const server = client.getServerVersion();
  console.log(`[${label}] connected to ${server?.name}@${server?.version}`);
  const tools = await client.listTools();
  console.log(`[${label}] tools: ${tools.tools.map((t) => t.name).join(", ")}`);
  const schemaSizes = tools.tools.map((t) => `${t.name}: in=${JSON.stringify(t.inputSchema).length}B out=${JSON.stringify(t.outputSchema ?? {}).length}B`);
  console.log(`[${label}] schema sizes: ${schemaSizes.join(" | ")}`);

  const email = await client.callTool({ name: "verify_email_infrastructure", arguments: { domain } });
  const emailStructured = email.structuredContent;
  console.log(
    `[${label}] verify_email_infrastructure isError=${Boolean(email.isError)} score=${emailStructured?.score} grade=${emailStructured?.grade} billing=${JSON.stringify(emailStructured?.billing)}`
  );
  console.log(
    `[${label}] text preview: ${String(email.content?.[0]?.text ?? "")
      .slice(0, 120)
      .replace(/\s+/g, " ")}`
  );

  const bad = await client.callTool({ name: "inspect_tech_stack", arguments: { domain: "127.0.0.1" } });
  console.log(`[${label}] invalid input isError=${Boolean(bad.isError)} code=${bad._meta?.error?.code} structuredContent=${bad.structuredContent === undefined ? "omitted" : "present"}`);

  const tech = await client.callTool({ name: "inspect_tech_stack", arguments: { domain, includeEvidence: false } });
  const ts = tech.structuredContent;
  console.log(
    `[${label}] inspect_tech_stack isError=${Boolean(tech.isError)} status=${ts?.fetch?.status} techs=${ts?.summary?.total} security=${ts?.security?.score}/${ts?.security?.grade} partial=${ts?.partial}`
  );

  if (tools.tools.some((t) => t.name === "domain_history")) {
    const history = await client.callTool({ name: "domain_history", arguments: { domain } });
    const h = history.structuredContent;
    console.log(
      `[${label}] domain_history isError=${Boolean(history.isError)} known=${h?.known} technologies=${h?.technologies?.length} email=${h?.email ? `${h.email.score}/${h.email.grade}` : "none"} scans=${h?.recentScans?.length} changes=${h?.changes?.length}`
    );
  } else {
    console.log(`[${label}] domain_history not offered (storage disabled on this server)`);
  }

  if (tools.tools.some((t) => t.name === "start_bulk_check")) {
    const start = await client.callTool({ name: "start_bulk_check", arguments: { check: "email", domains: [domain, `www.${domain}`, "example.org", "not a domain"] } });
    const s = start.structuredContent;
    console.log(
      `[${label}] start_bulk_check isError=${Boolean(start.isError)} job=${s?.job?.jobId} accepted=${s?.job?.accepted} skipped=${s?.skippedTotal} (${(s?.skipped ?? []).map((k) => k.code).join(",")}) charged=${s?.job?.creditsCharged}/${s?.job?.quotaUnitsCharged}`
    );
    let view = null;
    for (let i = 0; i < 60 && s?.job?.jobId; i++) {
      const poll = await client.callTool({ name: "get_bulk_check", arguments: { jobId: s.job.jobId } });
      view = poll.structuredContent;
      if (poll.isError || view?.status === "completed" || view?.status === "cancelled") break;
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
    console.log(`[${label}] get_bulk_check status=${view?.status} counts=${JSON.stringify(view?.counts)} billing.creditsCharged=${view?.billing?.creditsCharged}`);
    for (const item of view?.items ?? []) {
      console.log(`[${label}]   #${item.index} ${item.input} -> ${item.status} ${item.result ? `score=${item.result.score} dmarc=${item.result.dmarcPolicy}` : (item.error?.code ?? "")}`);
    }
    const list = await client.callTool({ name: "list_bulk_checks", arguments: {} });
    console.log(`[${label}] list_bulk_checks isError=${Boolean(list.isError)} jobs=${list.structuredContent?.jobs?.length}`);
  }

  if (tools.tools.some((t) => t.name === "watch_domain")) {
    const watch = await client.callTool({ name: "watch_domain", arguments: { domain, checks: ["email"] } });
    const w = watch.structuredContent;
    console.log(`[${label}] watch_domain isError=${Boolean(watch.isError)} created=${w?.created} secret=${w?.webhookSecret ? "issued" : "none"} limit=${w?.watchLimit} next=${w?.watch?.nextCheckAt}`);
    const badHook = await client.callTool({ name: "watch_domain", arguments: { domain, checks: ["email"], webhookUrl: "http://127.0.0.1/hook" } });
    console.log(`[${label}] watch_domain with a private webhook isError=${Boolean(badHook.isError)} code=${badHook._meta?.error?.code}`);
    const watches = await client.callTool({ name: "list_watches", arguments: {} });
    console.log(`[${label}] list_watches isError=${Boolean(watches.isError)} watches=${watches.structuredContent?.watches?.length}`);
    const alerts = await client.callTool({ name: "get_alerts", arguments: {} });
    console.log(`[${label}] get_alerts isError=${Boolean(alerts.isError)} alerts=${alerts.structuredContent?.alerts?.length}`);
    const unwatch = await client.callTool({ name: "unwatch_domain", arguments: { domain } });
    console.log(`[${label}] unwatch_domain isError=${Boolean(unwatch.isError)} removed=${unwatch.structuredContent?.removed}`);
  }

  if (tools.tools.some((t) => t.name === "find_domains_using")) {
    const listed = await client.callTool({ name: "list_technologies", arguments: { limit: 5 } });
    const top = (listed.structuredContent?.technologies ?? []).map((t) => `${t.id}:${t.domains}`).join(", ");
    console.log(`[${label}] list_technologies isError=${Boolean(listed.isError)} total=${listed.structuredContent?.total} top=${top}`);
    const technology = listed.structuredContent?.technologies?.[0]?.id ?? "cloudflare";
    const found = await client.callTool({ name: "find_domains_using", arguments: { technology, limit: 10 } });
    const f = found.structuredContent;
    console.log(
      `[${label}] find_domains_using(${technology}) isError=${Boolean(found.isError)} universe=${JSON.stringify(f?.universe)} total=${f?.total} domains=${(f?.domains ?? []).map((d) => d.domain).join(",")}`
    );
    const ambiguous = await client.callTool({ name: "find_domains_using", arguments: { technology: "google" } });
    console.log(`[${label}] find_domains_using(google) isError=${Boolean(ambiguous.isError)} code=${ambiguous._meta?.error?.code} candidates=${ambiguous._meta?.error?.details?.candidates?.length}`);
  }

  await client.close();
}

if (mode === "stdio") {
  const { fileURLToPath } = await import("node:url");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const transport = new StdioClientTransport({
    command: process.execPath,
    // --stdio and STACKDNS_TRANSPORT=stdio pin the transport even when the
    // parent shell exported STACKDNS_TRANSPORT=http (as the Dockerfile does),
    // which would otherwise start an HTTP listener and hang the handshake.
    args: [fileURLToPath(new URL("../dist/index.js", import.meta.url)), "--stdio"],
    env: {
      ...process.env,
      STACKDNS_TRANSPORT: "stdio",
      STACKDNS_LOG_LEVEL: "warn",
      STACKDNS_USAGE_FILE: join(tmpdir(), "stack-and-dns-e2e-usage.json"),
      STACKDNS_DB_FILE: process.env.STACKDNS_DB_FILE ?? join(tmpdir(), "stack-and-dns-e2e.db")
    },
    stderr: "pipe"
  });
  transport.stderr?.on("data", (chunk) => process.stderr.write(`[server] ${chunk}`));
  await run(transport, "stdio");
} else {
  const key = process.env.SDM_KEY ?? "sdm_live_testkey_0123456789abcdef";
  const url = process.env.SDM_URL ?? DEFAULT_HTTP_URL;
  const transport = new StreamableHTTPClientTransport(new URL(url), {
    requestInit: { headers: { authorization: `Bearer ${key}` } }
  });
  await run(transport, "http");
  console.log(`[http] session id after close: ${transport.sessionId ?? "n/a"}`);
}
