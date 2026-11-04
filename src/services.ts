/**
 * Long-lived services built on the database: bulk checks, domain
 * monitoring, the reverse-lookup crawler and self-serve key storage, plus
 * the background workers and maintenance that drive them. Everything here
 * is optional; without storage the server offers the live inspection tools
 * only.
 *
 * Only one process sharing a database runs the workers at a time (see
 * WorkerLease). Every process can still accept submissions and answer
 * reads, because all state lives in the database.
 */

import { BULK_CREDITS_PER_DOMAIN, type AppConfig } from "./config.js";
import type { DnsClient } from "./lib/dns.js";
import { checkRobots, fetchRobots, robotsVerdict, type RobotsFile, type RobotsResult } from "./lib/robots.js";
import { createWebhookSender } from "./lib/webhook.js";
import { logger } from "./logger.js";
import type { Principal } from "./middleware/auth.js";
import type { RateLimiter } from "./middleware/rateLimit.js";
import type { UsageTracker } from "./middleware/usage.js";
import { Crawler, type CrawlRunner, type RobotsChecker } from "./store/crawler.js";
import type { Storage } from "./store/index.js";
import { BulkJobs } from "./store/jobs.js";
import { KeyRepository } from "./store/keyStore.js";
import { WorkerLease } from "./store/lease.js";
import { Monitor, type MonitorRunner } from "./store/monitor.js";
import { ReverseLookup } from "./store/reverse.js";
import { createBulkRunner } from "./tools/bulk.js";
import type { ToolDeps } from "./tools/deps.js";
import { inspectTechStack } from "./tools/inspectTechStack.js";
import { verifyEmailInfrastructure } from "./tools/verifyEmailInfrastructure.js";

export interface Services {
  storage: Storage | null;
  jobs: BulkJobs | null;
  monitor: Monitor | null;
  crawler: Crawler | null;
  reverse: ReverseLookup | null;
  keys: KeyRepository | null;
  /** Starts competing for the worker lease; the holder runs the bulk pool, the monitor and the crawler. */
  start(): void;
  /** Stops the workers (in-flight items are requeued), releases the lease and closes nothing else. */
  stop(): Promise<void>;
}

export interface ServicesDeps {
  config: AppConfig;
  dns: DnsClient;
  usage: UsageTracker;
  limiter: RateLimiter;
  storage: Storage | null;
}

const LEASE_TTL_MS = 60_000;
const LEASE_RENEW_MS = 15_000;
const MAINTENANCE_MS = 6 * 60 * 60 * 1000;
const MINUTE = 60_000;

/** Scans run by the monitor on behalf of every watcher of a domain. */
const MONITOR_PRINCIPAL: Principal = { id: "monitor", plan: "local", label: "domain monitor", source: "local" };

export function createMonitorRunner(toolDeps: ToolDeps, storage: Storage): MonitorRunner {
  return async (check, domain, signal) => {
    const ctx = { principal: MONITOR_PRINCIPAL, signal, requestId: "monitor" };
    if (check === "email") {
      const result = await verifyEmailInfrastructure({ domain, dkimSelectors: storage.scans.knownDkimSelectors(domain), checkMtaSts: true }, toolDeps, ctx);
      // A check that hit its deadline may hold lookups that were cut short.
      if (!signal.aborted) storage.scans.recordEmail(result, "monitor");
      return;
    }
    const result = await inspectTechStack({ domain, includeRawHeaders: false, includeEvidence: false }, toolDeps, ctx);
    if (!signal.aborted) storage.scans.recordTech(result, "monitor");
  };
}

/** Scans run by the crawler; recorded like any other scan, with source "crawl". */
const CRAWL_PRINCIPAL: Principal = { id: "crawler", plan: "local", label: "reverse-lookup crawler", source: "local" };

export function createCrawlRunner(toolDeps: ToolDeps, storage: Storage): CrawlRunner {
  const { config } = toolDeps;
  return async (domain, signal, seedRobots) => {
    // Every request the fetch makes (redirect targets, the http:// fallback)
    // is checked against its own origin's robots.txt, not just the seed's.
    // Each origin's file is downloaded once per crawl; the seed's is the one
    // the crawler already checked.
    const files = new Map<string, Promise<RobotsFile>>();
    if (seedRobots) files.set(new URL(`https://${domain}/`).origin, Promise.resolve(seedRobots));
    let refusal: RobotsResult | null = null;
    const fetchGuard = async (url: URL): Promise<void> => {
      let file = files.get(url.origin);
      if (!file) {
        file = fetchRobots(url, { timeoutMs: config.inspection.fetchTimeoutMs, userAgent: config.inspection.userAgent, allowPrivate: config.inspection.allowPrivateTargets, signal });
        files.set(url.origin, file);
      }
      const verdict = robotsVerdict(await file, url, config.inspection.userAgent);
      if (verdict.verdict === "allowed") return;
      refusal = verdict;
      const why = verdict.verdict === "unreachable" ? `could not be fetched (${verdict.error ?? "unknown error"})` : `does not allow ${url.pathname}`;
      // Either way the fetch stops here, without the http:// fallback.
      throw Object.assign(new Error(`robots.txt of ${url.origin} ${why}`), { code: "EROBOTS" });
    };
    const result = await inspectTechStack({ domain, includeRawHeaders: false, includeEvidence: false }, toolDeps, { principal: CRAWL_PRINCIPAL, signal, requestId: "crawl", fetchGuard });
    if (result.fetch.error?.kind === "robots") {
      // The first refusal ends the fetch, so it is the one recorded. An
      // unreachable file means "not now" (RFC 9309), not an opt-out: the
      // site keeps its data and is retried on the failure schedule.
      const why = refusal as RobotsResult | null;
      return why?.verdict === "unreachable" ? { status: "robots_unreachable", error: result.fetch.error.message } : "robots_disallowed";
    }
    if (!signal.aborted) storage.scans.recordTech(result, "crawl");
    if (result.blocked.blocked) return "blocked";
    if (result.fetch.ok) return "ok";
    // The scan record keeps only the error's kind; the crawler records the
    // message (for example that the http:// fallback was refused by robots.txt).
    const error = result.fetch.error;
    return error ? { status: "unreachable", error: `${error.kind}: ${error.message}` } : "unreachable";
  };
}

/**
 * The crawler's robots.txt check of https://<domain>/. A host that does not
 * resolve may not exist at all: our resolver confirms it, so a dead seed is
 * reported not_found and waits a full refresh instead of being retried on
 * the failure schedule.
 */
export function createRobotsChecker(config: AppConfig, dns: DnsClient): RobotsChecker {
  return async (domain, signal) => {
    const result = await checkRobots(domain, { timeoutMs: config.inspection.fetchTimeoutMs, userAgent: config.inspection.userAgent, allowPrivate: config.inspection.allowPrivateTargets, signal });
    if (result.verdict === "unreachable" && result.dnsFailure) {
      const existence = await dns.exists(domain);
      if (existence.nxdomain) return { ...result, verdict: "not_found" };
    }
    return result;
  };
}

/** How long the crawler gives one domain: the robots.txt check plus the inspection. */
export function crawlCheckTimeoutMs(config: AppConfig): number {
  return config.inspection.toolTimeoutMs + config.inspection.fetchTimeoutMs;
}

export function createServices(deps: ServicesDeps): Services {
  const { config, storage } = deps;
  const toolDeps: ToolDeps = { config, dns: deps.dns, ...(storage ? { knownDkimSelectors: (domain: string) => storage.scans.knownDkimSelectors(domain) } : {}) };
  if (!storage) {
    return { storage: null, jobs: null, monitor: null, crawler: null, reverse: null, keys: null, start: () => undefined, stop: async () => undefined };
  }

  const keys = new KeyRepository(storage.db);
  const jobs = config.bulk.enabled
    ? new BulkJobs({
        db: storage.db,
        usage: deps.usage,
        limiter: deps.limiter,
        runner: createBulkRunner(toolDeps, storage),
        options: {
          creditsPerDomain: { ...BULK_CREDITS_PER_DOMAIN },
          maxDomains: config.bulk.maxDomains,
          concurrency: config.bulk.concurrency,
          itemTimeoutMs: config.inspection.toolTimeoutMs,
          maxActiveJobsPerPrincipal: config.bulk.maxActiveJobsPerPrincipal,
          retentionDays: config.bulk.retentionDays
        }
      })
    : null;
  const allowPrivate = config.inspection.allowPrivateTargets;
  const monitor = config.monitor.enabled
    ? new Monitor({
        db: storage.db,
        usage: deps.usage,
        runner: createMonitorRunner(toolDeps, storage),
        sender: createWebhookSender({ timeoutMs: 10_000, userAgent: config.inspection.userAgent, allowPrivate }),
        entitlement: (principalId) => keys.currentPlan(principalId),
        terminated: (principalId) => keys.isTerminated(principalId),
        options: {
          intervalMs: config.monitor.intervalMs,
          retryMs: Math.min(config.monitor.intervalMs, 30 * MINUTE),
          creditsPerCheck: config.monitor.creditsPerCheck,
          concurrency: config.monitor.concurrency,
          checkTimeoutMs: config.inspection.toolTimeoutMs,
          tickMs: MINUTE,
          maxWatches: config.monitor.maxWatches,
          webhook: { allowInsecure: config.monitor.webhookAllowInsecure, allowPrivate },
          deliveryBackoffMs: [MINUTE, 5 * MINUTE, 30 * MINUTE, 2 * 60 * MINUTE, 12 * 60 * MINUTE],
          alertRetentionDays: config.monitor.alertRetentionDays
        }
      })
    : null;

  const seedFile = config.crawl.seedFile;
  const reverse = seedFile ? new ReverseLookup(storage.db) : null;
  const crawler = seedFile
    ? new Crawler({
        db: storage.db,
        runner: createCrawlRunner(toolDeps, storage),
        robots: createRobotsChecker(config, deps.dns),
        options: {
          seedFile,
          ratePerMinute: config.crawl.ratePerMinute,
          refreshMs: config.crawl.refreshMs,
          retryMs: 60 * MINUTE,
          concurrency: config.crawl.concurrency,
          tickMs: 15_000,
          maxTargets: config.crawl.maxTargets,
          checkTimeoutMs: crawlCheckTimeoutMs(config)
        }
      })
    : null;

  const lease = new WorkerLease(storage.db, "workers", LEASE_TTL_MS);
  let running = false;
  let lastRenewed = 0;
  let transition: Promise<void> = Promise.resolve();
  let leaseTimer: NodeJS.Timeout | null = null;
  let maintenanceTimer: NodeJS.Timeout | null = null;
  let stopped = true;

  const startWorkers = (): void => {
    running = true;
    jobs?.start();
    monitor?.start();
    crawler?.start();
    logger.info("background workers started", { bulk: jobs !== null, monitor: monitor !== null, crawler: crawler !== null, lease: lease.owner });
  };
  const stopWorkers = async (): Promise<void> => {
    running = false;
    await Promise.all([jobs?.stop(), monitor?.stop(), crawler?.stop()]);
  };

  const coordinate = (): void => {
    if (!jobs && !monitor && !crawler) return;
    // Transitions are serialized: a stop must finish before a later start.
    transition = transition
      .then(async () => {
        if (stopped) return;
        let held = false;
        try {
          held = lease.tryAcquire();
          if (held) lastRenewed = Date.now();
        } catch (err) {
          logger.warn("worker lease check failed", { error: err });
          // A holder that cannot renew must stop before its lease can expire
          // and another process takes over the same work.
          if (running && Date.now() - lastRenewed >= LEASE_TTL_MS - LEASE_RENEW_MS) {
            logger.warn("worker lease could not be renewed; stopping background workers");
            await stopWorkers();
          }
          return;
        }
        if (held && !running) {
          try {
            startWorkers();
          } catch (err) {
            // Roll back a half-started pool and give the lease up, so this
            // process (or another) starts cleanly on a later check.
            logger.error("background workers failed to start; retrying on the next lease check", { error: err });
            await stopWorkers();
            try {
              lease.release();
            } catch (releaseErr) {
              logger.warn("worker lease release failed", { error: releaseErr });
            }
          }
        } else if (!held && running) {
          logger.warn("worker lease lost to another process; stopping background workers");
          await stopWorkers();
        }
      })
      // The chain must never stay rejected: every later check would be skipped.
      .catch((err: unknown) => logger.error("worker lease coordination failed", { error: err }));
  };

  // Batched and asynchronous, so a backlog never holds the write lock long
  // enough to fail other processes' writes; runs in the transition chain, so
  // stop() waits for it.
  const maintenance = async (): Promise<void> => {
    if (!running) return;
    const now = Date.now();
    const halt = (): boolean => !running || stopped;
    const removed: Record<string, number> = {};
    try {
      if (jobs) removed.jobs = await jobs.pruneAsync(now, halt);
      if (monitor) removed.alerts = await monitor.pruneAsync(now, halt);
      removed.stripeEvents = keys.pruneEvents(now);
    } catch (err) {
      logger.warn("maintenance failed", { error: err });
      return;
    }
    if (Object.values(removed).some((n) => n > 0)) logger.info("pruned expired jobs, alerts and webhook events", removed);
  };
  const queueMaintenance = (): void => {
    transition = transition.then(maintenance).catch((err: unknown) => logger.error("maintenance failed", { error: err }));
  };

  return {
    storage,
    jobs,
    monitor,
    crawler,
    reverse,
    keys,
    start(): void {
      if (!stopped) return;
      stopped = false;
      coordinate();
      leaseTimer = setInterval(coordinate, LEASE_RENEW_MS);
      leaseTimer.unref();
      maintenanceTimer = setInterval(queueMaintenance, MAINTENANCE_MS);
      maintenanceTimer.unref();
      queueMaintenance();
    },
    async stop(): Promise<void> {
      if (stopped) return;
      stopped = true;
      if (leaseTimer) clearInterval(leaseTimer);
      if (maintenanceTimer) clearInterval(maintenanceTimer);
      await transition.catch(() => undefined);
      if (running) await stopWorkers();
      try {
        lease.release();
      } catch (err) {
        logger.warn("worker lease release failed", { error: err });
      }
    }
  };
}
