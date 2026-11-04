#!/usr/bin/env node
/**
 * Entrypoint. Selects the transport from CLI flags / environment, wires the
 * shared services and installs process-level guards so an unexpected error
 * is logged instead of crashing the server.
 *
 *   stack-and-dns-mcp            -> stdio (default, for local MCP clients)
 *   stack-and-dns-mcp --http     -> Express: Streamable HTTP + SSE
 */

import { StripeApi } from "./billing/stripeApi.js";
import { loadConfig } from "./config.js";
import { DnsClient } from "./lib/dns.js";
import { logger, setLogLevel } from "./logger.js";
import { ApiKeyStore, resolveLocalPrincipal, SessionTokenService } from "./middleware/auth.js";
import { PaymentManager } from "./middleware/payments.js";
import { RateLimiter } from "./middleware/rateLimit.js";
import { ATTACH_LOCK_BUDGET_MS, attachSharedLedger, UsageTracker } from "./middleware/usage.js";
import { createServices } from "./services.js";
import { loadSignatureDatabase } from "./signatures/index.js";
import { CreditLedger } from "./store/credits.js";
import { openStorage, STDIO_LOCK_BUDGET_MS } from "./store/index.js";
import { startHttp, type SelfServeDeps } from "./transports/http.js";
import { startStdio } from "./transports/stdio.js";

async function main(): Promise<void> {
  const config = loadConfig();
  setLogLevel(config.logLevel);

  process.on("uncaughtException", (err) => {
    logger.error("uncaught exception (server continues)", { error: err });
  });
  process.on("unhandledRejection", (reason) => {
    logger.error("unhandled promise rejection (server continues)", { error: reason });
  });

  const db = loadSignatureDatabase();
  logger.info("signature database ready", { version: db.version, signatures: db.signatures.length });

  const usage = new UsageTracker(config.auth.usageFile);
  await usage.load();
  const limiter = new RateLimiter(config.auth.planLimits);
  const keys = await ApiKeyStore.fromConfig(config);
  const localPrincipal = resolveLocalPrincipal(config, keys);
  const dns = new DnsClient({
    servers: config.inspection.dnsServers,
    fallbackServers: config.inspection.dnsFallbackServers,
    timeoutMs: config.inspection.dnsTimeoutMs,
    tries: 2,
    cacheTtlMs: config.inspection.dnsCacheTtlMs
  });
  logger.info("dns resolvers", { servers: dns.servers, fallback: config.inspection.dnsFallbackServers });
  let storage = await openStorage(config);
  if (storage) {
    // Balances and redeemed payments move to the database, so every process
    // sharing it (a rolling deploy, the worker that finalizes a bulk job)
    // works on one ledger. A process must never run on a private file ledger
    // next to a shared one (a payment could be redeemed once in each), so a
    // locked database is waited out and a lasting failure stops an HTTP
    // server. A stdio server sells nothing: it waits at most
    // STDIO_LOCK_BUDGET_MS (an MCP client's initialize times out after 60 s)
    // and then runs without storage. Not just without the ledger: holding the
    // worker lease it could finalize another process's prepaid bulk job and
    // put that job's refund on its private file ledger.
    const ledger = new CreditLedger(storage.db);
    const http = config.transport === "http";
    let attached: boolean;
    try {
      attached = await attachSharedLedger(usage, ledger, { required: http, budgetMs: http ? ATTACH_LOCK_BUDGET_MS : STDIO_LOCK_BUDGET_MS });
    } catch (err) {
      storage.close();
      throw err;
    }
    if (!attached) {
      logger.warn("credit ledger could not be attached to the shared database; running without storage (stored scans, bulk checks, monitoring and reverse lookup are disabled)", {
        file: config.storage.dbFile
      });
      storage.close();
      storage = null;
    }
  }
  const services = createServices({ config, dns, usage, limiter, storage });

  let shuttingDown = false;
  let closeTransport: (() => Promise<void>) | null = null;
  let payments: PaymentManager | null = null;
  // Order matters: stop taking requests, stop the workers (in-flight bulk
  // items are requeued for the next start), flush usage, then close the
  // database the workers were writing to.
  const shutdown = async (reason: string): Promise<void> => {
    if (shuttingDown) return;
    shuttingDown = true;
    logger.info("shutting down", { reason });
    try {
      if (closeTransport) await closeTransport();
      // Settled payments this process could not record stay in their shared
      // markers; a sibling or the next start finishes them.
      payments?.close();
      await services.stop();
      await usage.close();
    } catch (err) {
      logger.warn("shutdown encountered an error", { error: err });
    } finally {
      storage?.close();
      process.exit(0);
    }
  };
  process.on("SIGINT", () => void shutdown("SIGINT"));
  process.on("SIGTERM", () => void shutdown("SIGTERM"));

  if (config.transport === "http") {
    payments = new PaymentManager(config, usage);
    const sessions = new SessionTokenService(config.auth.sessionSecret);
    // Keys sold through self-serve signup live in the database; they keep
    // working even if signup is later switched off.
    if (services.keys) keys.attachRepository(services.keys);
    let selfServe: SelfServeDeps | null = null;
    const { prices, webhookSecret } = config.selfServe;
    if (services.keys && config.payments.stripe.secretKey && (prices.pro || prices.enterprise)) {
      selfServe = {
        stripe: new StripeApi(config.payments.stripe.secretKey, config.payments.stripe.apiBase),
        options: { publicUrl: config.http.publicUrl, prices, webhookSecret, planLimits: config.auth.planLimits }
      };
      if (!webhookSecret) logger.warn("STRIPE_WEBHOOK_SECRET is not set; self-serve keys will not follow subscription cancellations or plan changes");
    } else if (prices.pro || prices.enterprise) {
      logger.warn("self-serve signup needs STRIPE_SECRET_KEY and a working database; /signup is disabled");
    }
    const httpServer = await startHttp({ config, usage, limiter, localPrincipal, dns, services, keys, sessions, payments, selfServe });
    closeTransport = (): Promise<void> =>
      new Promise((resolve) => {
        httpServer.close(() => resolve());
        setTimeout(resolve, 5000).unref();
      });
  } else {
    await startStdio({ config, usage, limiter, localPrincipal, dns, services }, () => void shutdown("stdin closed"));
  }
  services.start();
}

main().catch((err: unknown) => {
  logger.error("fatal startup error", { error: err });
  process.exit(1);
});
