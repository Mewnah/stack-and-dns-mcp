/**
 * Round-4 regressions for the reverse-lookup crawler (G11, G16-G20).
 *
 * The end-to-end tests drive the real crawl runner (inspectTechStack,
 * fetchHomepage, the robots.txt fetch guard) against loopback servers. Crawl
 * targets are .test names: a fake network routes those names to the local
 * servers (443 to the HTTPS server, 80 to the plain one) and answers every
 * other name lookup with ENOTFOUND, so nothing ever leaves the machine.
 */

import assert from "node:assert/strict";
import dns from "node:dns";
import { mkdtemp, open, rm, writeFile } from "node:fs/promises";
import http from "node:http";
import https from "node:https";
import net, { type AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, before, describe, it } from "node:test";
import tls from "node:tls";
import { Worker } from "node:worker_threads";
import { loadConfig } from "../src/config.js";
import type { DnsClient } from "../src/lib/dns.js";
import { parseDomain } from "../src/lib/domain.js";
import { domainListLines } from "../src/lib/domainList.js";
import { ToolError } from "../src/lib/errors.js";
import { classifyFetchError, fetchHomepage, type FetchOptions } from "../src/lib/http.js";
import { checkRobots, isAllowed, parseRobots, robotsVerdict, type RobotsResult } from "../src/lib/robots.js";
import { setLogLevel } from "../src/logger.js";
import { crawlCheckTimeoutMs, createCrawlRunner, createRobotsChecker } from "../src/services.js";
import { Crawler, type CrawlerOptions, type CrawlRunner } from "../src/store/crawler.js";
import { openDatabase, type Database } from "../src/store/db.js";
import type { Storage } from "../src/store/index.js";
import { ReverseLookup } from "../src/store/reverse.js";
import { ScanStore, type TechScanInput } from "../src/store/scanStore.js";
import type { ToolDeps } from "../src/tools/deps.js";
import { loopbackCert } from "./fixtures/loopback-cert.js";

setLogLevel("silent");

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;
const UA = "Mozilla/5.0 (compatible; StackAndDnsBot/1.0; +https://github.com/Mewnah/stack-and-dns-mcp)";
const ALLOWED: RobotsResult = { verdict: "allowed", status: 200, error: null };

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

type RunnerOutcome = Awaited<ReturnType<CrawlRunner>>;

function tech(domain: string, ids: string[]): TechScanInput {
  return {
    domain,
    partial: false,
    fetch: { ok: true, status: 200, finalHost: domain, truncated: false, error: null },
    blocked: { blocked: false, vendor: null, challengeType: null, reason: null },
    technologies: ids.map((id) => ({ id, name: id, category: "ecommerce", version: null, implied: false })),
    security: { score: 70, grade: "C" }
  } as unknown as TechScanInput;
}

interface TargetRow {
  last_status: string | null;
  last_error: string | null;
  failures: number;
  next_at: number;
  tech_ok_at: number | null;
}

function target(db: Database, domain: string): TargetRow {
  const row = db.prepare("SELECT last_status, last_error, failures, next_at, tech_ok_at FROM crawl_targets WHERE domain = ?").get(domain) as TargetRow | undefined;
  assert.ok(row, `${domain} is a crawl target`);
  return row;
}

function countTargets(db: Database): number {
  return Number((db.prepare("SELECT COUNT(*) AS n FROM crawl_targets").get() as { n: number }).n);
}

function techRows(db: Database, domain: string): number {
  return Number((db.prepare("SELECT COUNT(*) AS n FROM crawl_tech WHERE domain = ?").get(domain) as { n: number }).n);
}

function seedLines(n: number): string {
  return Array.from({ length: n }, (_, i) => `site${i}.com`).join("\n");
}

/**
 * A Crawler with scripted robots verdicts and runner outcomes. A domain
 * without a scripted outcome is crawled OK and recorded as using "shopify".
 */
async function stubCrawler(seeds: string, options: Partial<CrawlerOptions> = {}, dbName: string | null = null) {
  const dir = await mkdtemp(path.join(tmpdir(), "sdm-r4-crawl-"));
  const seedFile = path.join(dir, "seeds.csv");
  await writeFile(seedFile, seeds, "utf8");
  const dbFile = dbName ? path.join(dir, dbName) : ":memory:";
  const db = await openDatabase(dbFile);
  assert.ok(db);
  const store = new ScanStore(db, { retentionDays: 365 });
  const clock = { now: 1_000_000 };
  const robots = new Map<string, RobotsResult>();
  const outcomes = new Map<string, RunnerOutcome | Error>();
  const calls: Array<{ domain: string; targets: number }> = [];
  const crawler = new Crawler({
    db,
    clock: () => clock.now,
    robots: async (domain) => robots.get(domain) ?? ALLOWED,
    runner: async (domain) => {
      calls.push({ domain, targets: countTargets(db) });
      const outcome = outcomes.get(domain);
      if (outcome instanceof Error) throw outcome;
      if (outcome !== undefined && outcome !== "ok") return outcome;
      store.recordTech(tech(domain, ["shopify"]), "crawl", clock.now);
      return "ok";
    },
    options: { seedFile, ratePerMinute: 60, refreshMs: 30 * DAY, retryMs: HOUR, concurrency: 2, tickMs: 60_000, maxTargets: 1_000_000, checkTimeoutMs: 5000, ...options }
  });
  const cleanup = async (): Promise<void> => {
    await crawler.stop();
    db.close();
    await rm(dir, { recursive: true, force: true });
  };
  return { dir, dbFile, db, store, crawler, clock, robots, outcomes, calls, reverse: new ReverseLookup(db), cleanup };
}

// ---------------------------------------------------------------------------
// Fake network: loopback HTTPS and HTTP servers behind .test host names.
// ---------------------------------------------------------------------------

type Route = (req: http.IncomingMessage, res: http.ServerResponse) => void;

const WORDPRESS = '<!doctype html><html><head><meta name="generator" content="WordPress 6.5"><title>home</title></head><body>hello</body></html>';

function reply(status: number, body = "", headers: Record<string, string> = {}, delayMs = 0): Route {
  return (_req, res) => {
    const send = (): void => {
      if (res.destroyed || res.writableEnded) return;
      res.writeHead(status, { "content-type": "text/plain; charset=utf-8", ...headers });
      res.end(body);
    };
    if (delayMs > 0) setTimeout(send, delayMs);
    else send();
  };
}
const homepage = (delayMs = 0): Route => reply(200, WORDPRESS, { "content-type": "text/html; charset=utf-8" }, delayMs);
const moved = (location: string, delayMs = 0): Route => reply(301, "", { location }, delayMs);
const robotsTxt = (body: string, delayMs = 0): Route => reply(200, body, {}, delayMs);
/** Accepts the request and never answers. */
const hang: Route = () => undefined;
/** The first request gets the first route, later ones the next, and so on; the last one repeats. */
function sequence(...steps: Route[]): Route {
  let index = 0;
  return (req, res) => (steps[Math.min(index++, steps.length - 1)] as Route)(req, res);
}

const routes = new Map<string, Route>();
/** Every request the servers received, as scheme://host/path. */
const hits: string[] = [];
/** Host names routed to the loopback servers; any other name fails to resolve. */
const fakeHosts = new Set<string>();
/** Host names whose port 443 speaks plain HTTP, so the TLS handshake fails. */
const brokenTls = new Set<string>();
const ports = { https: 0, http: 0 };

function site(name: string, table: Record<string, Route>, scheme: "https" | "http" = "https"): void {
  fakeHosts.add(name);
  for (const [urlPath, route] of Object.entries(table)) routes.set(`${scheme}://${name}${urlPath}`, route);
}

const hitCount = (url: string): number => hits.filter((h) => h === url).length;
const hitsOn = (name: string): string[] => hits.filter((h) => new URL(h).hostname === name);

function serve(scheme: "https" | "http"): Route {
  return (req, res) => {
    const name = (req.headers.host ?? "").replace(/:\d+$/, "").toLowerCase();
    const key = `${scheme}://${name}${req.url ?? "/"}`;
    hits.push(key);
    const route = routes.get(key);
    if (route) route(req, res);
    else if (scheme === "https") reply(404, "not found")(req, res);
    // An unexpected plain-HTTP request (the http:// fallback) finds nothing there.
    else req.socket.destroy();
  };
}

type AnyFn = (...args: unknown[]) => unknown;
const tlsModule = tls as unknown as { connect: AnyFn };
const netModule = net as unknown as { connect: AnyFn };
const dnsModule = dns as unknown as { lookup: AnyFn };
const original = { tls: tlsModule.connect, net: netModule.connect, lookup: dnsModule.lookup };

function reroute(args: unknown[], secure: boolean): unknown[] {
  const [first, ...rest] = args;
  if (!first || typeof first !== "object") return args;
  const options = first as { host?: string; port?: number | string };
  const name = (options.host ?? "").toLowerCase();
  if (!fakeHosts.has(name)) return args;
  const port = Number(options.port ?? (secure ? 443 : 80));
  let targetPort = port;
  if (secure && port === 443) targetPort = brokenTls.has(name) ? ports.http : ports.https;
  if (!secure && port === 80) targetPort = ports.http;
  return [{ ...options, host: "127.0.0.1", port: targetPort, ...(secure ? { rejectUnauthorized: false } : {}) }, ...rest];
}

function installFakeNetwork(): void {
  tlsModule.connect = (...args: unknown[]) => original.tls.apply(tls, reroute(args, true));
  netModule.connect = (...args: unknown[]) => original.net.apply(net, reroute(args, false));
  dnsModule.lookup = (hostname: unknown, options: unknown, callback?: unknown) => {
    const done = (typeof options === "function" ? options : callback) as (err: Error) => void;
    const err = Object.assign(new Error(`getaddrinfo ENOTFOUND ${String(hostname)}`), { code: "ENOTFOUND", hostname });
    process.nextTick(() => done(err));
  };
}

function restoreNetwork(): void {
  tlsModule.connect = original.tls;
  netModule.connect = original.net;
  dnsModule.lookup = original.lookup;
}

let secureServer: https.Server | null = null;
let plainServer: http.Server | null = null;

before(async () => {
  secureServer = https.createServer(loopbackCert(), serve("https"));
  plainServer = http.createServer(serve("http"));
  await new Promise<void>((resolve) => (secureServer as https.Server).listen(0, "127.0.0.1", resolve));
  await new Promise<void>((resolve) => (plainServer as http.Server).listen(0, "127.0.0.1", resolve));
  ports.https = (secureServer.address() as AddressInfo).port;
  ports.http = (plainServer.address() as AddressInfo).port;
  installFakeNetwork();
});

after(async () => {
  restoreNetwork();
  for (const server of [secureServer, plainServer]) {
    if (!server) continue;
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

const fakeDns = { exists: async () => ({ exists: false, nxdomain: true, error: null }) } as unknown as DnsClient;

function liveDeps(fetchTimeoutMs = 1000): ToolDeps {
  const config = loadConfig({ STACKDNS_ALLOW_PRIVATE_TARGETS: "true", STACKDNS_FETCH_TIMEOUT_MS: String(fetchTimeoutMs), STACKDNS_TLS_TIMEOUT_MS: "1000" }, []);
  return { config, dns: fakeDns };
}

async function memoryStorage(): Promise<Storage> {
  const db = await openDatabase(":memory:");
  assert.ok(db);
  return { db, scans: new ScanStore(db, { retentionDays: 365 }), close: () => db.close() };
}

function robotsCheck(deps: ToolDeps, domain: string) {
  return checkRobots(domain, { timeoutMs: deps.config.inspection.fetchTimeoutMs, userAgent: deps.config.inspection.userAgent, allowPrivate: true });
}

/** What crawlOne does for one domain: check the seed's robots.txt, then run the real crawl runner with that file. */
async function crawlWithRunner(domain: string, fetchTimeoutMs = 1000): Promise<RunnerOutcome> {
  const deps = liveDeps(fetchTimeoutMs);
  const storage = await memoryStorage();
  try {
    const robots = await robotsCheck(deps, domain);
    assert.equal(robots.verdict, "allowed", `${domain}'s own robots.txt allows the homepage`);
    return await createCrawlRunner(deps, storage)(domain, new AbortController().signal, robots.file);
  } finally {
    storage.close();
  }
}

/**
 * A Crawler wired like services.ts (its robots checker, which confirms a
 * DNS failure as not_found, its runner and its per-domain deadline) over
 * targets inserted directly (.test names are not valid seeds).
 */
async function liveCrawler(domains: string[], fetchTimeoutMs = 1000) {
  const deps = liveDeps(fetchTimeoutMs);
  const storage = await memoryStorage();
  const db = storage.db;
  const insert = db.prepare("INSERT INTO crawl_targets (domain, added_at, next_at) VALUES (?, 0, 0)");
  for (const domain of domains) insert.run(domain);
  const clock = { now: 1_000_000 };
  const crawler = new Crawler({
    db,
    clock: () => clock.now,
    runner: createCrawlRunner(deps, storage),
    robots: createRobotsChecker(deps.config, deps.dns),
    // No seed file: the sync keeps the targets inserted above.
    options: {
      seedFile: path.join(tmpdir(), `sdm-r4-no-seeds-${process.pid}.csv`),
      ratePerMinute: 60,
      refreshMs: 30 * DAY,
      retryMs: HOUR,
      concurrency: 1,
      tickMs: 60_000,
      maxTargets: 100,
      checkTimeoutMs: crawlCheckTimeoutMs(deps.config)
    }
  });
  const cleanup = async (): Promise<void> => {
    await crawler.stop();
    storage.close();
  };
  return { db, crawler, clock, reverse: new ReverseLookup(db), cleanup };
}

// ---------------------------------------------------------------------------
// G11: seed sync yields and leaves the write lock free between chunks.
// ---------------------------------------------------------------------------

/**
 * Another connection in its own thread, with a busy handler like a second
 * process's. Before each write it waits for the sync to commit one more
 * chunk, so every write has to win a fresh gap on the lock (once it holds
 * the lock, the sync's own busy wait would otherwise let the next write in
 * for free). workerData.finished is set by the main thread when the sync is
 * over; it ends the waiting, and writes after it see the complete list.
 */
const PROBE_WORKER = `
const { parentPort, workerData } = require("node:worker_threads");
const { DatabaseSync } = require("node:sqlite");
const db = new DatabaseSync(workerData.file);
db.exec("PRAGMA busy_timeout = 5000");
const nap = new Int32Array(new SharedArrayBuffer(4));
const finished = new Int32Array(workerData.finished);
const count = () => Number(db.prepare("SELECT COUNT(*) AS n FROM crawl_targets").get().n);
parentPort.postMessage({ type: "ready" });
const writes = [];
let last = 0;
for (let i = 0; i < workerData.writes; i++) {
  while (count() <= last && Atomics.load(finished, 0) === 0) Atomics.wait(nap, 0, 0, 1);
  const started = Date.now();
  try {
    db.exec("BEGIN IMMEDIATE");
    const n = count();
    db.prepare("INSERT INTO probe (n) VALUES (?)").run(n);
    db.exec("COMMIT");
    writes.push({ n, waitedMs: Date.now() - started });
    last = n;
  } catch (err) {
    writes.push({ error: String((err && err.message) || err), waitedMs: Date.now() - started });
    try { db.exec("ROLLBACK"); } catch {}
  }
}
db.close();
parentPort.postMessage({ type: "done", writes });
`;

interface ProbeWrite {
  n?: number;
  error?: string;
  waitedMs: number;
}

describe("G11: Crawler.syncSeeds does not monopolise the event loop or the write lock", () => {
  it("yields while parsing and between write chunks, and another connection writes in the gaps without waiting", async () => {
    const total = 25_000;
    const h = await stubCrawler(seedLines(total), {}, "crawl.db");
    const other = await openDatabase(h.dbFile);
    assert.ok(other);
    try {
      other.exec("CREATE TABLE probe (n INTEGER NOT NULL)");
      // No busy wait at all: the write fails outright if the sync holds the lock.
      other.exec("PRAGMA busy_timeout = 0");
      const landed: number[] = [];
      const failures: string[] = [];
      const timer = setInterval(() => {
        try {
          other.exec("BEGIN IMMEDIATE");
          const n = countTargets(other);
          other.prepare("INSERT INTO probe (n) VALUES (?)").run(n);
          other.exec("COMMIT");
          landed.push(n);
        } catch (err) {
          failures.push(err instanceof Error ? err.message : String(err));
          try {
            other.exec("ROLLBACK");
          } catch {
            // no transaction open
          }
        }
      }, 1);
      let result: Awaited<ReturnType<Crawler["syncSeeds"]>>;
      try {
        result = await h.crawler.syncSeeds(true);
      } finally {
        clearInterval(timer);
      }
      assert.equal(result?.total, total);
      assert.equal(countTargets(h.db), total);
      assert.deepEqual(failures, [], "the other connection never found the write lock taken");
      // The read itself and the parse can both let a probe in here; the parse yields alone are checked in round8-crawler.test.ts.
      assert.ok(landed.includes(0), `the event loop ran before the first chunk was written (probes saw ${landed.length} states)`);
      assert.ok(
        landed.some((n) => n > 0 && n < total),
        `another connection wrote between the sync's chunks, not only before or after it (saw ${[...new Set(landed)].join(", ")})`
      );
    } finally {
      other.close();
      await h.cleanup();
    }
  });

  it("gives another thread's busy-waiting writer a real gap: its writes land mid-sync instead of queueing behind the whole list", async () => {
    const total = 30_000;
    const h = await stubCrawler(seedLines(total), {}, "crawl.db");
    h.db.exec("CREATE TABLE probe (n INTEGER NOT NULL)");
    const finished = new SharedArrayBuffer(4);
    const worker = new Worker(PROBE_WORKER, { eval: true, workerData: { file: path.join(h.dir, "crawl.db"), writes: 4, finished }, execArgv: [] });
    try {
      let onReady: () => void = () => undefined;
      let onDone: (writes: ProbeWrite[]) => void = () => undefined;
      const ready = new Promise<void>((resolve) => (onReady = resolve));
      const done = new Promise<ProbeWrite[]>((resolve, reject) => {
        onDone = resolve;
        worker.once("error", reject);
      });
      worker.on("message", (message: { type: string; writes?: ProbeWrite[] }) => {
        if (message.type === "ready") onReady();
        if (message.type === "done") onDone(message.writes ?? []);
      });
      await ready;
      let result: Awaited<ReturnType<Crawler["syncSeeds"]>>;
      try {
        result = await h.crawler.syncSeeds(true);
      } finally {
        Atomics.store(new Int32Array(finished), 0, 1);
      }
      const writes = await done;
      assert.equal(result?.total, total);
      assert.equal(writes.length, 4);
      assert.deepEqual(
        writes.filter((w) => w.error !== undefined),
        [],
        "no write from the other thread failed with 'database is locked'"
      );
      assert.ok(
        writes.every((w) => w.n !== undefined && w.n > 0 && w.n < total),
        `each of the other thread's writes won a gap while the sync was still running, none had to queue behind the whole list (saw ${JSON.stringify(writes)})`
      );
    } finally {
      await worker.terminate();
      await h.cleanup();
    }
  });

  it("stops between chunks when told to, and the next sync redoes the interrupted one", async () => {
    const total = 3000;
    const h = await stubCrawler(seedLines(total));
    try {
      let checks = 0;
      const interrupted = await h.crawler.syncSeeds(true, () => ++checks > 1);
      assert.equal(interrupted, null, "an interrupted sync reports no result");
      const partial = countTargets(h.db);
      assert.ok(partial > 0 && partial < total, `the sync stopped part way (${partial} of ${total})`);
      // The file has not changed since, yet the interrupted run must not count as applied.
      const redone = (await h.crawler.syncSeeds()) ?? (await h.crawler.syncSeeds());
      assert.deepEqual(redone, { added: total - partial, removed: 0, total, invalid: 0 });
      assert.equal(countTargets(h.db), total);
    } finally {
      await h.cleanup();
    }
  });

  it("start() returns before the initial sync writes, stop() halts it between chunks, and a tick never overlaps it", async () => {
    const total = 20_000;
    const h = await stubCrawler(seedLines(total), { ratePerMinute: 2 });
    try {
      h.crawler.start();
      assert.equal(countTargets(h.db), 0, "start() did not run the seed sync on the startup path");
      const deadline = Date.now() + 10_000;
      while (countTargets(h.db) === 0 && Date.now() < deadline) await sleep(1);
      assert.ok(countTargets(h.db) > 0, "the initial sync runs in the background");
      await h.crawler.stop();
      const atStop = countTargets(h.db);
      assert.ok(atStop < total, `stop() halted the initial sync (${atStop} of ${total} written)`);
      await sleep(50);
      assert.equal(countTargets(h.db), atStop, "nothing is written after stop() resolved");

      // A restart redoes the interrupted sync; a tick waits for it instead of crawling a half-written list.
      h.crawler.start();
      await h.crawler.tick(h.clock.now);
      assert.equal(countTargets(h.db), total);
      await h.crawler.tick(h.clock.now);
      assert.ok(h.calls.length > 0, "later ticks crawl");
      assert.ok(
        h.calls.every((c) => c.targets === total),
        "every crawl ran against the complete target list"
      );
    } finally {
      await h.cleanup();
    }
  });
});

// ---------------------------------------------------------------------------
// G16: an unreachable robots.txt is "not now", never an opt-out.
// ---------------------------------------------------------------------------

describe("G16: a redirect target's unreachable robots.txt is not an opt-out", () => {
  it("the crawler keeps the data of a site whose runner reports robots_unreachable and retries it on the failure schedule", async () => {
    const h = await stubCrawler("a.com\nx.com\n");
    try {
      await h.crawler.syncSeeds(true);
      await h.crawler.tick(h.clock.now);
      assert.deepEqual(h.reverse.universe(), { domains: 2, scanned: 2 });
      assert.equal(techRows(h.db, "x.com"), 1);

      h.outcomes.set("x.com", { status: "robots_unreachable", error: "robots.txt of https://www.x.com could not be fetched (HTTP 503)" });
      h.clock.now += 31 * DAY;
      await h.crawler.tick(h.clock.now);
      const row = target(h.db, "x.com");
      assert.equal(row.last_status, "robots_unreachable");
      assert.match(row.last_error ?? "", /HTTP 503/);
      assert.equal(row.failures, 1);
      assert.equal(row.next_at, h.clock.now + HOUR, "retried after retryMs, not after a full refresh");
      assert.equal(techRows(h.db, "x.com"), 1, "the site's reverse-lookup data is kept");
      assert.equal(row.tech_ok_at !== null, true, "and it still counts as scanned");
      assert.equal(h.reverse.findDomains({ techId: "shopify" }).total, 2);

      h.clock.now += HOUR;
      await h.crawler.tick(h.clock.now);
      assert.equal(target(h.db, "x.com").failures, 2);
      assert.equal(target(h.db, "x.com").next_at, h.clock.now + 2 * HOUR, "the retry delay backs off");
    } finally {
      await h.cleanup();
    }
  });

  const variants: Array<{ label: string; seed: string; setup: (www: string) => void; fetchTimeoutMs?: number; error?: RegExp }> = [
    { label: "503", seed: "g16-503.test", setup: (www) => site(www, { "/robots.txt": reply(503, "busy"), "/": homepage() }), error: /503/ },
    { label: "429", seed: "g16-429.test", setup: (www) => site(www, { "/robots.txt": reply(429, "slow down"), "/": homepage() }), error: /429/ },
    { label: "timeout", seed: "g16-slow.test", setup: (www) => site(www, { "/robots.txt": hang, "/": homepage() }), fetchTimeoutMs: 500 },
    {
      label: "TLS failure",
      seed: "g16-tls.test",
      setup: (www) => {
        site(www, { "/": homepage() });
        brokenTls.add(www);
      }
    },
    // www.g16-dns.test is never registered, so it does not resolve.
    { label: "DNS failure", seed: "g16-dns.test", setup: () => undefined }
  ];

  for (const variant of variants) {
    it(`a ${variant.label} on the redirect target's robots.txt makes the runner report robots_unreachable, not robots_disallowed`, async () => {
      const www = `www.${variant.seed}`;
      site(variant.seed, { "/": moved(`https://${www}/`) });
      variant.setup(www);
      const outcome = await crawlWithRunner(variant.seed, variant.fetchTimeoutMs);
      assert.equal(typeof outcome, "object", `a transient robots.txt failure is not an opt-out (got ${JSON.stringify(outcome)})`);
      const unreachable = outcome as { status: string; error: string };
      assert.equal(unreachable.status, "robots_unreachable");
      assert.ok(unreachable.error.length > 0, "the reason is kept for the operator");
      if (variant.error) assert.match(unreachable.error, variant.error);
      assert.equal(hitCount(`https://${www}/`), 0, "the page behind the unreadable robots.txt was not fetched");
      assert.deepEqual(
        hits.filter((h) => h.startsWith("http://")),
        [],
        "no http:// fallback after a robots refusal"
      );
    });
  }

  it("end to end: a site crawled OK keeps its reverse-lookup data when its www robots.txt answers 503", async () => {
    let wwwRobots = "ok";
    site("keep.test", { "/": moved("https://www.keep.test/") });
    site("www.keep.test", {
      "/robots.txt": (req, res) => (wwwRobots === "ok" ? robotsTxt("User-agent: *\nAllow: /\n") : reply(503, "maintenance"))(req, res),
      "/": homepage()
    });
    const h = await liveCrawler(["keep.test"]);
    try {
      await h.crawler.tick(h.clock.now);
      assert.equal(target(h.db, "keep.test").last_status, "ok");
      const before = techRows(h.db, "keep.test");
      assert.ok(before > 0, "the first crawl recorded technologies");
      assert.equal(h.reverse.findDomains({ techId: "wordpress" }).total, 1);

      wwwRobots = "503";
      h.clock.now += 31 * DAY;
      await h.crawler.tick(h.clock.now);
      const row = target(h.db, "keep.test");
      assert.equal(row.last_status, "robots_unreachable");
      assert.match(row.last_error ?? "", /503/);
      assert.equal(row.failures, 1);
      assert.equal(row.next_at, h.clock.now + HOUR, "retried on the failure schedule, not parked for a full refresh");
      assert.equal(techRows(h.db, "keep.test"), before, "crawl_tech rows were not deleted");
      assert.ok(row.tech_ok_at !== null);
      assert.equal(h.reverse.findDomains({ techId: "wordpress" }).total, 1, "the site is still found by the reverse lookup");
    } finally {
      await h.cleanup();
    }
  });

  it("end to end: a transient failure on a second download of the seed's own robots.txt cannot turn into an opt-out", async () => {
    site("flip.test", {
      "/robots.txt": sequence(robotsTxt("User-agent: *\nAllow: /\n"), reply(503, "flapping")),
      "/": homepage()
    });
    const h = await liveCrawler(["flip.test"]);
    try {
      await h.crawler.tick(h.clock.now);
      const row = target(h.db, "flip.test");
      assert.equal(row.last_status, "ok", `the crawl used the robots.txt it had already checked (got ${row.last_status}: ${row.last_error})`);
      assert.ok(techRows(h.db, "flip.test") > 0);
    } finally {
      await h.cleanup();
    }
  });
});

// ---------------------------------------------------------------------------
// G17: RFC 9309 percent-encoding in robots path matching.
// ---------------------------------------------------------------------------

describe("G17: robots.txt rules and paths are compared in one percent-encoded form", () => {
  it("matches the RFC 9309 examples whatever side is encoded", () => {
    const umlaut = parseRobots("User-agent: *\nDisallow: /über/\n");
    assert.equal(isAllowed(umlaut, "bot", "/%C3%BCber/"), false, "a UTF-8 rule matches the URL parser's encoded path");
    assert.equal(isAllowed(umlaut, "bot", "/%c3%bcber/page"), false, "lowercase escapes are the same path");
    assert.equal(isAllowed(umlaut, "bot", "/uber/"), true);

    const tilde = parseRobots("User-agent: *\nDisallow: /%7Ejoe/\n");
    assert.equal(isAllowed(tilde, "bot", "/~joe/"), false, "an escaped unreserved character equals the literal");
    assert.equal(isAllowed(tilde, "bot", "/%7ejoe/index.html"), false);

    const baz = parseRobots("User-agent: *\nDisallow: /foo/bar/%62%61%7A\n");
    assert.equal(isAllowed(baz, "bot", "/foo/bar/baz"), false, "RFC 9309's own /foo/bar/%62%61%7A example");

    const encodedRule = parseRobots("User-agent: *\nDisallow: /%C3%BCber/\n");
    assert.equal(isAllowed(encodedRule, "bot", "/über/"), false, "an encoded rule matches a raw non-ASCII path");

    const reserved = parseRobots("User-agent: *\nDisallow: /a%2Fb\n");
    assert.equal(isAllowed(reserved, "bot", "/a/b"), true, "an escaped reserved character stays distinct");
    assert.equal(isAllowed(reserved, "bot", "/a%2fb"), false);
  });

  it("judges URLs as the URL parser encodes them", () => {
    const file = { groups: parseRobots("User-agent: *\nDisallow: /über/\nDisallow: /%7Ejoe/\n"), status: 200 };
    assert.equal(robotsVerdict(file, new URL("https://uber.test/über/"), UA).verdict, "disallowed");
    assert.equal(robotsVerdict(file, new URL("https://uber.test/%C3%BCber/deep"), UA).verdict, "disallowed");
    assert.equal(robotsVerdict(file, new URL("https://uber.test/~joe/"), UA).verdict, "disallowed");
    assert.equal(robotsVerdict(file, new URL("https://uber.test/"), UA).verdict, "allowed");
  });

  it("end to end: a redirect to a page disallowed by a non-ASCII rule is refused, not fetched", async () => {
    site("uber.test", {
      "/robots.txt": robotsTxt("User-agent: *\nDisallow: /über/\n"),
      "/": moved("/%C3%BCber/"),
      "/%C3%BCber/": homepage()
    });
    const outcome = await crawlWithRunner("uber.test");
    assert.equal(outcome, "robots_disallowed");
    assert.equal(hitCount("https://uber.test/%C3%BCber/"), 0, "the disallowed page was never requested");
  });

  it("end to end: a redirect to /~joe/ is refused by 'Disallow: /%7Ejoe/'", async () => {
    site("tilde.test", {
      "/robots.txt": robotsTxt("User-agent: *\nDisallow: /%7Ejoe/\n"),
      "/": moved("/~joe/"),
      "/~joe/": homepage()
    });
    const outcome = await crawlWithRunner("tilde.test");
    assert.equal(outcome, "robots_disallowed");
    assert.equal(hitCount("https://tilde.test/~joe/"), 0, "the disallowed page was never requested");
  });
});

// ---------------------------------------------------------------------------
// G18: our own refusals are classified by code, whatever their text says.
// ---------------------------------------------------------------------------

describe("G18: robots and redirect refusals are never classified as timeouts", () => {
  it("classifies EROBOTS and EREDIRECT by code even when the message reads like a timeout", () => {
    const robots = (message: string): Error => Object.assign(new Error(message), { code: "EROBOTS" });
    for (const message of [
      "robots.txt of https://www.timeout-shop.test does not allow /",
      "robots.txt of https://timed-out.test does not allow /timed out/",
      "robots.txt of https://aborted.test could not be fetched (ETIMEDOUT: request timed out)"
    ]) {
      const failure = classifyFetchError(robots(message));
      assert.equal(failure.kind, "robots", message);
      assert.equal(failure.code, "EROBOTS");
    }
    const redirect = classifyFetchError(Object.assign(new Error('Redirect target "https://timeout.test:99999/" is not a valid URL'), { code: "EREDIRECT" }));
    assert.equal(redirect.kind, "redirect");
    const scheme = classifyFetchError(Object.assign(new Error("Redirected to unsupported scheme aborted:"), { code: "EREDIRECT" }));
    assert.equal(scheme.kind, "redirect");
  });

  it("fetchHomepage stops at a robots refusal for a 'timeout' host: kind robots, and no http:// fallback attempt", async () => {
    const seen: string[] = [];
    const options: FetchOptions = {
      timeoutMs: 1000,
      maxBodyBytes: 100_000,
      userAgent: UA,
      allowPrivate: true,
      beforeRequest: async (url) => {
        seen.push(url.href);
        throw Object.assign(new Error(`robots.txt of ${url.origin} does not allow ${url.pathname}`), { code: "EROBOTS" });
      }
    };
    const result = await fetchHomepage("timeout-shop.test", options);
    assert.equal(result.ok, false);
    assert.equal(result.error?.kind, "robots");
    assert.equal(result.timings.attempts, 1, "a refusal is final: no insecure retry and no http:// downgrade");
    assert.deepEqual(seen, ["https://timeout-shop.test/"]);
  });

  it("end to end: an opt-out on www.timeout-shop.test is reported as robots_disallowed and nothing is fetched over http://", async () => {
    site("timeout-shop.test", { "/": moved("https://www.timeout-shop.test/") });
    site("www.timeout-shop.test", { "/robots.txt": robotsTxt("User-agent: StackAndDnsBot\nDisallow: /\n"), "/": homepage() });
    const outcome = await crawlWithRunner("timeout-shop.test");
    assert.equal(outcome, "robots_disallowed");
    assert.equal(hitCount("https://www.timeout-shop.test/"), 0);
    assert.deepEqual(
      hitsOn("timeout-shop.test").filter((h) => h.startsWith("http://")),
      [],
      "no http:// fallback request"
    );
  });
});

// ---------------------------------------------------------------------------
// G19: robots.txt once per origin per crawl, outside the page deadline.
// ---------------------------------------------------------------------------

describe("G19: the fetch guard downloads each origin's robots.txt once, and not on the page's time", () => {
  it("reuses the seed's robots.txt from the crawler's own check and fetches each other origin's file once", async () => {
    site("count.test", {
      "/robots.txt": robotsTxt("User-agent: *\nDisallow: /private/\n"),
      "/": moved("/en/"),
      "/en/": moved("https://www.count.test/a")
    });
    site("www.count.test", {
      "/robots.txt": robotsTxt("User-agent: *\nDisallow: /private/\n"),
      "/a": moved("/b"),
      "/b": homepage()
    });
    const h = await liveCrawler(["count.test"]);
    try {
      await h.crawler.tick(h.clock.now);
      assert.equal(target(h.db, "count.test").last_status, "ok");
      assert.equal(hitCount("https://www.count.test/b"), 1, "the chain was followed to the end");
      assert.equal(hitCount("https://count.test/robots.txt"), 1, "the seed's robots.txt was downloaded once, by the crawler's check");
      assert.equal(hitCount("https://www.count.test/robots.txt"), 1, "a same-origin redirect reuses the file");
    } finally {
      await h.cleanup();
    }
  });

  it("crawls a site whose robots.txt is slow (but within its timeout) and whose homepage redirects", async () => {
    site("slowseed.test", {
      "/robots.txt": robotsTxt("User-agent: *\nAllow: /\n", 700),
      "/": moved("/en/", 500),
      "/en/": homepage()
    });
    const h = await liveCrawler(["slowseed.test"], 1000);
    try {
      await h.crawler.tick(h.clock.now);
      const row = target(h.db, "slowseed.test");
      assert.equal(row.last_status, "ok", `a slow robots.txt did not make the site uncrawlable (got ${row.last_status}: ${row.last_error})`);
      assert.equal(hitCount("https://slowseed.test/en/"), 1);
      assert.equal(hitCount("https://slowseed.test/robots.txt"), 1);
      assert.deepEqual(
        hitsOn("slowseed.test").filter((h) => h.startsWith("http://")),
        [],
        "no http:// fallback was needed"
      );
    } finally {
      await h.cleanup();
    }
  });

  it("does not charge a redirect target's slow robots.txt download against the homepage deadline", async () => {
    site("credit.test", { "/": moved("https://www.credit.test/", 250) });
    site("www.credit.test", {
      "/robots.txt": robotsTxt("User-agent: *\nAllow: /\n", 700),
      "/": moved("/en/", 250),
      "/en/": homepage()
    });
    const h = await liveCrawler(["credit.test"], 1000);
    try {
      await h.crawler.tick(h.clock.now);
      const row = target(h.db, "credit.test");
      assert.equal(row.last_status, "ok", `the guard's 700 ms did not use up the 1000 ms page budget (got ${row.last_status}: ${row.last_error})`);
      assert.equal(hitCount("https://www.credit.test/en/"), 1);
    } finally {
      await h.cleanup();
    }
  });

  it("fetchHomepage credits the time spent in beforeRequest back to the attempt deadline", async () => {
    site("guard.test", { "/": moved("/home"), "/home": homepage() });
    let calls = 0;
    const result = await fetchHomepage("guard.test", {
      timeoutMs: 500,
      maxBodyBytes: 100_000,
      userAgent: UA,
      allowPrivate: true,
      beforeRequest: async () => {
        if (calls++ === 0) await sleep(600);
      }
    });
    assert.equal(result.error, null, `no deadline error (got ${JSON.stringify(result.error)})`);
    assert.equal(result.ok, true);
    assert.equal(result.protocol, "https");
    assert.equal(result.finalUrl, "https://guard.test/home");
    assert.equal(result.status, 200);
  });
});

// ---------------------------------------------------------------------------
// G20: opt-outs and dead domains stop counting as scanned.
// ---------------------------------------------------------------------------

describe("G20: universe().scanned counts only domains that are still searchable", () => {
  const cases: Array<{ label: string; apply: (h: Awaited<ReturnType<typeof stubCrawler>>) => void; status: string }> = [
    { label: "its robots.txt now disallows us", apply: (h) => h.robots.set("x.com", { verdict: "disallowed", status: 200, error: null }), status: "robots_disallowed" },
    { label: "a redirect target's robots.txt disallows us", apply: (h) => h.outcomes.set("x.com", "robots_disallowed"), status: "robots_disallowed" },
    { label: "its robots.txt host does not exist", apply: (h) => h.robots.set("x.com", { verdict: "not_found", status: null, error: "ENOTFOUND" }), status: "not_found" },
    { label: "the homepage fetch finds NXDOMAIN", apply: (h) => h.outcomes.set("x.com", new ToolError("DOMAIN_NOT_FOUND", "x.com does not exist in DNS (NXDOMAIN).")), status: "not_found" }
  ];

  for (const c of cases) {
    it(`a crawled site stops counting as scanned when ${c.label}`, async () => {
      const h = await stubCrawler("a.com\nx.com\n");
      try {
        await h.crawler.syncSeeds(true);
        await h.crawler.tick(h.clock.now);
        assert.deepEqual(h.reverse.universe(), { domains: 2, scanned: 2 });

        c.apply(h);
        h.clock.now += 31 * DAY;
        await h.crawler.tick(h.clock.now);
        assert.equal(target(h.db, "x.com").last_status, c.status);
        assert.equal(techRows(h.db, "x.com"), 0, "its reverse-lookup data is gone");
        assert.equal(target(h.db, "x.com").tech_ok_at, null);
        assert.deepEqual(h.reverse.universe(), { domains: 2, scanned: 1 }, "scanned matches what find_domains_using can return");
        assert.equal(h.reverse.findDomains({ techId: "shopify" }).total, 1);
      } finally {
        await h.cleanup();
      }
    });
  }

  it("a later usable crawl makes the domain count as scanned again", async () => {
    const h = await stubCrawler("a.com\nx.com\n");
    try {
      await h.crawler.syncSeeds(true);
      await h.crawler.tick(h.clock.now);
      h.robots.set("x.com", { verdict: "disallowed", status: 200, error: null });
      h.clock.now += 31 * DAY;
      await h.crawler.tick(h.clock.now);
      assert.deepEqual(h.reverse.universe(), { domains: 2, scanned: 1 });
      h.robots.delete("x.com");
      h.clock.now += 31 * DAY;
      await h.crawler.tick(h.clock.now);
      assert.deepEqual(h.reverse.universe(), { domains: 2, scanned: 2 });
    } finally {
      await h.cleanup();
    }
  });
});

// ---------------------------------------------------------------------------
// Round 8: end to end through the services.ts wiring (they need the fake
// network above, so they live here rather than in round8-crawler.test.ts).
// ---------------------------------------------------------------------------

describe("Round 8: the crawler as services.ts wires it", () => {
  it("a seed whose host does not resolve is confirmed NXDOMAIN and reported not_found, waiting a full refresh", async () => {
    // gone-r8.test is never registered, so its robots.txt fetch fails to resolve.
    const h = await liveCrawler(["gone-r8.test"]);
    try {
      await h.crawler.tick(h.clock.now);
      const row = target(h.db, "gone-r8.test");
      assert.equal(row.last_status, "not_found", `the checker turned the DNS failure into not_found (got ${row.last_status}: ${row.last_error})`);
      assert.equal(row.failures, 0, "a definitive answer is not a failure");
      assert.equal(row.next_at, h.clock.now + 30 * DAY, "it waits a full refresh, not the failure schedule");
      assert.deepEqual(hitsOn("gone-r8.test"), [], "nothing was fetched");
    } finally {
      await h.cleanup();
    }
  });

  it("an unreachable homepage records why, including an http:// fallback that robots.txt refused", async () => {
    site("fallback-r8.test", { "/robots.txt": robotsTxt("User-agent: *\nAllow: /\n"), "/": (req) => req.socket.destroy() });
    site("fallback-r8.test", { "/robots.txt": robotsTxt("User-agent: *\nDisallow: /\n") }, "http");
    const h = await liveCrawler(["fallback-r8.test"]);
    try {
      await h.crawler.tick(h.clock.now);
      const row = target(h.db, "fallback-r8.test");
      assert.equal(row.last_status, "unreachable", "HTTPS failed though its robots.txt allowed the fetch: the status stays unreachable");
      assert.match(row.last_error ?? "", /^connection: /, "the HTTPS failure leads the reason");
      assert.match(row.last_error ?? "", /the http:\/\/ fallback was refused \(robots\.txt of http:\/\/fallback-r8\.test does not allow \/\)/);
      assert.equal(row.failures, 1);
      assert.equal(row.next_at, h.clock.now + HOUR, "retried on the failure schedule");
      assert.equal(hitCount("http://fallback-r8.test/robots.txt"), 1, "the http:// origin's own robots.txt was consulted");
      assert.equal(hitCount("http://fallback-r8.test/"), 0, "and the refused page was never requested");
    } finally {
      await h.cleanup();
    }
  });

  it("records the whole refusal for a long host name, whose robots.txt could not be fetched", async () => {
    // Four labels near the 63-character limit: the note names the host, and
    // last_error was cut at 300 characters.
    const host = `${"a".repeat(60)}.${"b".repeat(60)}.${"c".repeat(60)}.fallback-r9.test`;
    site(host, { "/robots.txt": robotsTxt("User-agent: *\nAllow: /\n"), "/": (req) => req.socket.destroy() });
    site(host, { "/robots.txt": reply(503, "busy") }, "http");
    const h = await liveCrawler([host]);
    try {
      await h.crawler.tick(h.clock.now);
      const row = target(h.db, host);
      assert.equal(row.last_status, "unreachable");
      const note = `; the http:// fallback was refused (robots.txt of http://${host} could not be fetched (HTTP 503))`;
      assert.ok((row.last_error ?? "").length > 300, `longer than the old cut (${row.last_error?.length} characters)`);
      assert.match(row.last_error ?? "", /^connection: /);
      assert.ok(row.last_error?.endsWith(note), `the note is whole (got ${JSON.stringify(row.last_error)})`);
      assert.equal(hitCount(`http://${host}/`), 0, "the refused page was never requested");
    } finally {
      await h.cleanup();
    }
  });
});

// ---------------------------------------------------------------------------
// Round 5, G11: reading back and diffing the existing targets yields too.
// ---------------------------------------------------------------------------

/** Inserts site0.com .. site<n-1>.com as crawl targets in one statement: a seed sync of that many lines would spend seconds in its chunk pauses. */
function insertTargets(db: Database, n: number): void {
  db.exec(`WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < ${n - 1}) INSERT INTO crawl_targets (domain, added_at, next_at) SELECT 'site' || i || '.com', 0, 0 FROM n`);
}

function targetDomains(db: Database): string[] {
  return (db.prepare("SELECT domain FROM crawl_targets").all() as unknown as Array<{ domain: string }>).map((r) => r.domain);
}

describe("G11 (round 5): a re-sync against many existing targets does not stall the event loop", () => {
  it("re-syncing ~300k existing targets after a one-line edit never blocks the event loop for as long as one unsliced pass over them", async () => {
    const existing = 300_000;
    const h = await stubCrawler(`${seedLines(existing)}\nbrand-new-site.com\n`);
    try {
      insertTargets(h.db, existing);
      assert.equal(countTargets(h.db), existing);
      // What the cheapest unsliced pass over the targets costs on this
      // machine: one statement that visits each and looks it up in the index.
      // It is timed without the crawler's code, so the limit below scales
      // with the machine: a diff that walks either side in one SQL statement
      // costs about twice this and fails, the sliced one stays far below it.
      const baselineStarted = performance.now();
      const visited = (h.db.prepare("SELECT COUNT(*) AS n FROM crawl_targets c WHERE EXISTS (SELECT 1 FROM crawl_targets d WHERE d.domain = c.domain)").get() as { n: number }).n;
      const baseline = performance.now() - baselineStarted;
      assert.equal(Number(visited), existing);
      // The longest gap between 1 ms timer callbacks is the longest time the sync kept the event loop to itself.
      let last = performance.now();
      let worst = 0;
      const timer = setInterval(() => {
        const now = performance.now();
        worst = Math.max(worst, now - last);
        last = now;
      }, 1);
      let result: Awaited<ReturnType<Crawler["syncSeeds"]>>;
      try {
        result = await h.crawler.syncSeeds(true);
      } finally {
        clearInterval(timer);
      }
      worst = Math.max(worst, performance.now() - last);
      assert.deepEqual(result, { added: 1, removed: 0, total: existing + 1, invalid: 0 });
      // Here the baseline took ~60-95 ms and a one-pass SQL diff 150-190 ms (2.0-2.7 times the baseline); sliced,
      // the longest stall is one range (~10-30 ms). The 50 ms floor keeps a very fast machine clear of timer
      // noise, where this can no longer tell the two apart: round8-crawler.test.ts's 2M re-sync is the main
      // guard against an unsliced diff.
      const limit = Math.max(50, baseline);
      assert.ok(worst < limit, `the longest event-loop stall during the re-sync was ${worst.toFixed(0)} ms (limit ${limit.toFixed(0)} ms; one unsliced pass took ${baseline.toFixed(0)} ms)`);
    } finally {
      await h.cleanup();
    }
  });

  it("reads the seed file line by line in slices: a 1.5M-line list gets no single blocking pass over the whole text", async () => {
    // A list far past maxTargets stores almost nothing, so only the parse is measured: a
    // split-everything-first pass over 1.5M lines took ~200 ms here, the lazy reader stops at line two.
    const h = await stubCrawler(seedLines(1_500_000), { maxTargets: 1 });
    try {
      let last = performance.now();
      let worst = 0;
      const timer = setInterval(() => {
        const now = performance.now();
        worst = Math.max(worst, now - last);
        last = now;
      }, 1);
      let result: Awaited<ReturnType<Crawler["syncSeeds"]>>;
      try {
        result = await h.crawler.syncSeeds(true);
      } finally {
        clearInterval(timer);
      }
      worst = Math.max(worst, performance.now() - last);
      assert.deepEqual(result, { added: 1, removed: 0, total: 1, invalid: 0 });
      assert.deepEqual(targetDomains(h.db), ["site0.com"]);
      assert.ok(worst < 100, `the longest event-loop stall while parsing was ${worst.toFixed(0)} ms`);
    } finally {
      await h.cleanup();
    }
  });

  it("the event loop runs while the seed domains and the existing targets are diffed, even when nothing changes", async () => {
    const existing = 20_000;
    const h = await stubCrawler(seedLines(existing));
    try {
      insertTargets(h.db, existing);
      // shouldStop() is asked once per yield. A timer would also fire during
      // the file read, so the hook's count is what isolates the diff's yields:
      // the parse of 20k lines makes 2 of them, and each side of the diff (20k
      // seed domains, 20k targets) at least one more.
      let checks = 0;
      const result = await h.crawler.syncSeeds(true, () => {
        checks++;
        return false;
      });
      assert.deepEqual(result, { added: 0, removed: 0, total: existing, invalid: 0 });
      assert.equal(countTargets(h.db), existing);
      assert.ok(checks >= 4, `the diff yielded between its ranges, not only the parse (${checks} yields in all; the parse alone makes 2)`);
    } finally {
      await h.cleanup();
    }
  });

  it("a stop requested before the first write ends the sync with nothing written, and the next sync redoes it", async () => {
    const existing = 20_000;
    const h = await stubCrawler("new-a.com\nsite1.com\nnew-b.com\n");
    try {
      insertTargets(h.db, existing);
      // A three-line file parses without a yield, so the first check comes before the first write.
      const interrupted = await h.crawler.syncSeeds(true, () => true);
      assert.equal(interrupted, null, "an interrupted sync reports no result");
      assert.equal(countTargets(h.db), existing, "nothing was written");
      const redone = (await h.crawler.syncSeeds()) ?? (await h.crawler.syncSeeds());
      assert.deepEqual(redone, { added: 2, removed: existing - 1, total: 3, invalid: 0 });
      assert.deepEqual(new Set(targetDomains(h.db)), new Set(["new-a.com", "site1.com", "new-b.com"]));
    } finally {
      await h.cleanup();
    }
  });
});

// ---------------------------------------------------------------------------
// Round 5, G17: '^' and RFC 9309 section 2.2.3's %2A and %24.
// ---------------------------------------------------------------------------

/** The verdict a robots.txt made of one "User-agent: *" group with these rules gives a URL, as the crawler judges it. */
const verdict = (rules: string, url: string): string => robotsVerdict({ groups: parseRobots(`User-agent: *\n${rules}\n`), status: 200 }, new URL(url), UA).verdict;

describe("G17 (round 5): '^' and escaped '*' and '$' are compared in the same encoding on both sides", () => {
  it("matches RFC 9309 section 2.2.3's examples: %2A and %24 in a rule name a literal '*' and '$'", () => {
    const rules = "Disallow: /path/file-with-a-%2A.html\nDisallow: /path/foo-%24";
    assert.equal(verdict(rules, "https://www.example.com/path/file-with-a-*.html"), "disallowed", "RFC 9309 2.2.3: /path/file-with-a-%2A.html");
    assert.equal(verdict(rules, "https://www.example.com/path/foo-$"), "disallowed", "RFC 9309 2.2.3: /path/foo-%24");
    assert.equal(verdict(rules, "https://www.example.com/path/file-with-a-%2A.html"), "disallowed", "the escaped form in the URL is the same path");
    assert.equal(verdict(rules, "https://www.example.com/path/foo-%24"), "disallowed");
    assert.equal(verdict(rules, "https://www.example.com/path/file-with-a-x.html"), "allowed", "%2A is a literal '*', not a wildcard");
    assert.equal(verdict(rules, "https://www.example.com/path/foo-$/more"), "disallowed", "%24 is a literal '$', not an end anchor");
    assert.equal(verdict(rules, "https://www.example.com/path/foo-"), "allowed");
    const raw = parseRobots(`User-agent: *\n${rules}\n`);
    assert.equal(isAllowed(raw, "bot", "/path/file-with-a-*.html"), false);
    assert.equal(isAllowed(raw, "bot", "/path/foo-$"), false);
    // The other way round: a rule's literal mid-pattern '$' covers a URL that escapes it.
    assert.equal(verdict("Disallow: /a$b", "https://e.test/a%24b/c"), "disallowed");
    // A wildcard next to an escaped '*': only a literal '*' before ".html" matches.
    assert.equal(verdict("Disallow: /*-%2A.html", "https://e.test/x/y-*.html"), "disallowed");
    assert.equal(verdict("Disallow: /*-%2A.html", "https://e.test/x/y-z.html"), "allowed");
  });

  it("matches a rule with '^' against the URL parser's %5E, in either case and either encoding", () => {
    assert.equal(new URL("https://site.test/a^b/").pathname, "/a%5Eb/", "the URL parser encodes '^' in a path");
    for (const rule of ["Disallow: /a^b/", "Disallow: /a%5Eb/", "Disallow: /a%5eb/"]) {
      for (const url of ["https://site.test/a^b/", "https://site.test/a%5Eb/page", "https://site.test/a%5eb/"]) {
        assert.equal(verdict(rule, url), "disallowed", `${rule} covers ${url}`);
      }
      assert.equal(verdict(rule, "https://site.test/ab/"), "allowed");
    }
    assert.equal(isAllowed(parseRobots("User-agent: *\nDisallow: /a^b/\n"), "bot", "/a^b/"), false, "a raw '^' path");
    // The URL parser leaves '^' in a query as it is; both sides still meet.
    assert.equal(verdict("Disallow: /s?q=a^b", "https://site.test/s?q=a^b"), "disallowed");
    assert.equal(verdict("Disallow: /s?q=a^b", "https://site.test/s?q=a%5Eb"), "disallowed");
  });

  it("keeps wildcards, end anchors, literal mid-pattern '$' and the round-4 encodings working", () => {
    const table: Array<[rule: string, url: string, expected: "allowed" | "disallowed"]> = [
      ["Disallow: /*.php$", "https://e.test/x/index.php", "disallowed"],
      ["Disallow: /*.php$", "https://e.test/x/index.php?x=1", "allowed"],
      ["Disallow: /*.php$", "https://e.test/x/index.phps", "allowed"],
      ["Disallow: /fish*", "https://e.test/fish", "disallowed"],
      ["Disallow: /fish*", "https://e.test/fish.html", "disallowed"],
      ["Disallow: /fish*", "https://e.test/fish*and*chips", "disallowed"],
      ["Disallow: /fish*", "https://e.test/Fish.asp", "allowed"],
      ["Disallow: /a$b", "https://e.test/a$b", "disallowed"],
      ["Disallow: /a$b", "https://e.test/a$bc", "disallowed"],
      ["Disallow: /a$b", "https://e.test/a", "allowed"],
      ["Disallow: /exact$", "https://e.test/exact", "disallowed"],
      ["Disallow: /exact$", "https://e.test/exactly", "allowed"],
      ["Disallow: /über/", "https://e.test/%C3%BCber/", "disallowed"],
      ["Disallow: /%7Ejoe/", "https://e.test/~joe/", "disallowed"],
      ["Disallow: /foo/bar/%62%61%7A", "https://e.test/foo/bar/baz", "disallowed"],
      ["Disallow: /a%2Fb", "https://e.test/a/b", "allowed"],
      ["Disallow: /a%2Fb", "https://e.test/a%2fb", "disallowed"]
    ];
    for (const [rule, url, expected] of table) assert.equal(verdict(rule, url), expected, `${rule} on ${url}`);
    // Longest match still decides between an allow and a disallow that both match.
    assert.equal(verdict("Disallow: /*.php$\nAllow: /index.php$", "https://e.test/index.php"), "allowed");
    assert.equal(verdict("Disallow: /a$b\nAllow: /a", "https://e.test/a$b"), "disallowed", "the literal '$' rule is the longer match");
  });

  it("end to end: a redirect to /a^b/ is refused by 'Disallow: /a^b/', not fetched as /a%5Eb/", async () => {
    site("caret.test", {
      "/robots.txt": robotsTxt("User-agent: *\nDisallow: /a^b/\n"),
      "/": moved("/a^b/"),
      "/a%5Eb/": homepage()
    });
    const outcome = await crawlWithRunner("caret.test");
    assert.equal(outcome, "robots_disallowed");
    assert.equal(hitCount("https://caret.test/a%5Eb/"), 0, "the disallowed page was never requested");
  });

  it("end to end: a redirect to /path/file-with-a-*.html is refused by 'Disallow: /path/file-with-a-%2A.html'", async () => {
    site("star.test", {
      "/robots.txt": robotsTxt("User-agent: *\nDisallow: /path/file-with-a-%2A.html\n"),
      "/": moved("/path/file-with-a-*.html"),
      "/path/file-with-a-*.html": homepage()
    });
    const outcome = await crawlWithRunner("star.test");
    assert.equal(outcome, "robots_disallowed");
    assert.equal(hitCount("https://star.test/path/file-with-a-*.html"), 0, "the disallowed page was never requested");
  });
});

// ---------------------------------------------------------------------------
// Round 6, G11: the seed file is read off the event loop and decoded a line at a time.
// ---------------------------------------------------------------------------

/**
 * Writes a ranked-domain CSV with the domain first and nine more columns
 * (about 92 bytes a row, like a Majestic Million export), a chunk at a time so
 * the test never holds the whole text.
 */
async function writeWideCsv(file: string, rows: number): Promise<void> {
  const handle = await open(file, "w");
  try {
    await handle.write("Domain,GlobalRank,TldRank,TLD,RefSubNets,RefIPs,PrevGlobalRank,PrevTldRank,PrevRefSubNets,PrevRefIPs\n");
    for (let from = 0; from < rows; from += 100_000) {
      let chunk = "";
      for (let i = from; i < Math.min(rows, from + 100_000); i++) {
        chunk += `www.example-site-${i}.com,${i + 1},${i + 1},com,${rows - i},${rows - i + 7},${i + 3},${i + 3},${rows - i + 2},${rows - i + 9}\n`;
      }
      await handle.write(chunk);
    }
  } finally {
    await handle.close();
  }
}

/** A small seeded PRNG (mulberry32), so a failing random input can be reproduced. */
function seededRandom(seed: number): () => number {
  let state = seed;
  return () => {
    state = (state + 0x6d2b79f5) | 0;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

describe("G11 (round 6): the seed file is read on the thread pool and decoded a line at a time", () => {
  it("a ~2M-row wide CSV keeps the longest 1 ms timer gap under 100 ms: no blocking read or decode of the whole file", async () => {
    const rows = 2_000_000;
    // maxTargets 1: the parse stops at the second domain, so what is measured is getting the file in.
    const h = await stubCrawler("", { maxTargets: 1 });
    try {
      await writeWideCsv(path.join(h.dir, "seeds.csv"), rows);
      let last = performance.now();
      let worst = 0;
      const timer = setInterval(() => {
        const now = performance.now();
        worst = Math.max(worst, now - last);
        last = now;
      }, 1);
      let result: Awaited<ReturnType<Crawler["syncSeeds"]>>;
      try {
        result = await h.crawler.syncSeeds(true);
      } finally {
        clearInterval(timer);
      }
      worst = Math.max(worst, performance.now() - last);
      assert.deepEqual(result, { added: 1, removed: 0, total: 1, invalid: 0 }, "the header row was skipped and the first domain kept");
      assert.deepEqual(targetDomains(h.db), ["example-site-0.com"]);
      // readFileSync(file, "utf8") of these ~185 MB blocked for ~150-170 ms here; read on the thread pool, the longest gap is a few ms.
      assert.ok(worst < 100, `the longest event-loop stall while reading the seed file was ${worst.toFixed(0)} ms`);
    } finally {
      await h.cleanup();
    }
  });

  it("the file's bytes give exactly the steps of its decoded text: BOM, CRLF, bare CR, comments, quotes, header, multi-byte and invalid UTF-8", () => {
    const same = (bytes: Buffer, label: string): void => assert.deepEqual([...domainListLines(bytes)], [...domainListLines(bytes.toString("utf8"))], label);
    const cells = (bytes: Buffer): string[] => [...domainListLines(bytes)].filter((cell): cell is string => cell !== null);

    const bom = Buffer.from("\uFEFFDomain,Rank\r\na.com,1\r\n", "utf8");
    same(bom, "a BOM before the header and CRLF line endings");
    assert.deepEqual(cells(bom), ["a.com"], "trim() drops the BOM (so the header is still recognised) and each CRLF's CR");
    const bareCr = Buffer.from("a.com\rb.com\nc.com\r", "utf8");
    same(bareCr, "a bare CR");
    assert.deepEqual(cells(bareCr), ["a.com\rb.com", "c.com"], "a bare CR does not end a line in either form");
    const comments = Buffer.from("# ranked list\n\n   \n#x.com\n d.com \n", "utf8");
    same(comments, "comments and blank lines");
    assert.deepEqual(cells(comments), ["d.com"]);
    const quotes = Buffer.from('"q.com, inc",1\n"open.com\n""\n\'s.com\',2\n', "utf8");
    same(quotes, "quoted cells");
    assert.deepEqual(cells(quotes), ["q.com, inc", "open.com", "'s.com'"]);
    same(Buffer.from("a.com\ndomain\nWebsite\n", "utf8"), "only the first line can be a header");
    const multiByte = Buffer.from("bücher.de\n日本.jp\t1\n😀.com;2\n\u2028x.com\u00a0\n", "utf8");
    same(multiByte, "multi-byte characters, U+2028 and NBSP");
    assert.deepEqual(cells(multiByte), ["bücher.de", "日本.jp", "😀.com", "x.com"]);
    // Latin-1 é, a truncated 2-byte and 3-byte sequence right before a line break, a stray 0xFF and a lone continuation byte.
    const invalid = Buffer.from([0x63, 0x61, 0x66, 0xe9, 0x2e, 0x63, 0x6f, 0x6d, 0x0a, 0xc3, 0x0a, 0xe2, 0x80, 0x0a, 0xff, 0x61, 0x2e, 0x63, 0x6f, 0x6d, 0x0a, 0x80, 0x0d, 0x0a]);
    same(invalid, "invalid UTF-8");
    assert.deepEqual(cells(invalid), ["caf\uFFFD.com", "\uFFFD", "\uFFFD", "\uFFFDa.com", "\uFFFD"]);
    same(Buffer.alloc(0), "an empty file");
    same(Buffer.from("\uFEFF", "utf8"), "a file holding only a BOM");

    // And random mixes of all of them.
    const texts = ["a.com", "b.org", "\n", "\r\n", "\r", " ", "\t", ",", ";", '"', "#", "domain", "Website", "\uFEFF", "\u2028", "\u00a0", "ü", "😀", "\n\n", "\r\r\n"];
    const atoms = texts.map((s) => Buffer.from(s, "utf8"));
    for (const bytes of [[0xff], [0x80], [0xc3], [0xe2, 0x80], [0xf0, 0x9f], [0xed, 0xa0, 0x80], [0xc0, 0xaf]]) atoms.push(Buffer.from(bytes));
    const random = seededRandom(0x5eed);
    for (let k = 0; k < 20_000; k++) {
      const parts = Array.from({ length: Math.floor(random() * 14) }, () => atoms[Math.floor(random() * atoms.length)] as Buffer);
      const bytes = Buffer.concat(parts);
      same(bytes, `random input ${k}: ${bytes.toString("hex")}`);
    }
  });

  it("syncSeeds takes the same targets from a file with a BOM header, CRLF, a comment, a quoted cell, an IDN, a bare CR and an invalid byte", async () => {
    const h = await stubCrawler("");
    try {
      const file = Buffer.concat([
        Buffer.from('\uFEFFDomain,Rank\r\n# ranked list\r\n"quoted-site.com",1\r\nbücher.de,2\r\na.com\rb.com,3\nwww.site.org\t4\n', "utf8"),
        // "café.com" written in Latin-1: not valid UTF-8, so it decodes to "caf\uFFFD.com" and is skipped as invalid.
        Buffer.from([0x63, 0x61, 0x66, 0xe9, 0x2e, 0x63, 0x6f, 0x6d, 0x0a])
      ]);
      await writeFile(path.join(h.dir, "seeds.csv"), file);
      const result = await h.crawler.syncSeeds(true);
      assert.deepEqual(result, { added: 4, removed: 0, total: 4, invalid: 1 });
      // The URL parser drops the bare CR inside "a.com\rb.com", as it did when the file was decoded whole.
      assert.deepEqual(new Set(targetDomains(h.db)), new Set(["quoted-site.com", "xn--bcher-kva.de", "a.comb.com", "site.org"]));
    } finally {
      await h.cleanup();
    }
  });
});

// ---------------------------------------------------------------------------
// Round 6, G17: longest-match precedence counts octets, not the rewrites.
// ---------------------------------------------------------------------------

describe("G17 (round 6): a rule weighs the octets it names, each escape counted once, not its rewritten length", () => {
  it("a Disallow with more octets beats an Allow whose literal '$' or '^' is stored as an escape", () => {
    // RFC 9309 2.2.2: the match with the most octets wins. '/a$b' is 4 octets and '/a*bc' 5, though '/a$b' is stored as '/a%24b' (6 characters).
    assert.equal(verdict("Allow: /a$b\nDisallow: /a*bc", "https://e.test/a$bc"), "disallowed");
    assert.equal(verdict("Allow: /cart$id\nDisallow: /cart*id=", "https://e.test/cart$id=1"), "disallowed", "'/cart$id' is 8 octets, '/cart*id=' 9");
    assert.equal(verdict("Allow: /a^\nDisallow: /a*b", "https://e.test/a^b"), "disallowed", "'/a^' is 3 octets (stored as '/a%5E'), '/a*b' 4");
    assert.equal(verdict("Disallow: /a*bc\nAllow: /a$b", "https://e.test/a$bc"), "disallowed", "the order of the rules does not matter");
    assert.equal(isAllowed(parseRobots("User-agent: *\nAllow: /a$b\nDisallow: /a*bc\n"), "bot", "/a$bc"), false, "a raw path");
    // Where the Allow really is the longer rule, it still wins.
    assert.equal(verdict("Allow: /a$bcd\nDisallow: /a*bc", "https://e.test/a$bcd"), "allowed");
    assert.equal(verdict("Allow: /a^bc\nDisallow: /a*b", "https://e.test/a^bc"), "allowed");
  });

  it("keeps the controls: the literal '$' rule, '/*.php$' against '/index.php$', allow wins a tie, RFC 2.2.3's %2A, and one weight however a path is spelled", () => {
    const table: Array<[rules: string, url: string, expected: "allowed" | "disallowed"]> = [
      ["Disallow: /a$b\nAllow: /a", "https://e.test/a$b", "disallowed"],
      ["Disallow: /*.php$\nAllow: /index.php$", "https://e.test/index.php", "allowed"],
      ["Disallow: /a\nAllow: /a", "https://e.test/a", "allowed"],
      ["Disallow: /path/file-with-a-%2A.html\nAllow: /path/", "https://e.test/path/file-with-a-*.html", "disallowed"],
      // The same path written raw or escaped is one rule length, so these are ties and the allow wins.
      ["Disallow: /~joe/\nAllow: /%7Ejoe/", "https://e.test/~joe/", "allowed"],
      ["Disallow: /%C3%BCber/\nAllow: /über/", "https://e.test/über/", "allowed"],
      ["Disallow: /a%24b\nAllow: /a$b", "https://e.test/a$b", "allowed"],
      ["Disallow: /a%5Eb\nAllow: /a^b", "https://e.test/a^b", "allowed"],
      // A non-ASCII character weighs its UTF-8 octets: '/über' is 6, '/*berx' 6 (a tie), '/*berxy' 7.
      ["Disallow: /*berx\nAllow: /über", "https://e.test/überx", "allowed"],
      ["Disallow: /*berxy\nAllow: /über", "https://e.test/überxy", "disallowed"]
    ];
    for (const [rules, url, expected] of table) assert.equal(verdict(rules, url), expected, `${JSON.stringify(rules)} on ${url}`);
  });
});

// ---------------------------------------------------------------------------
// Round 7, G11: long lines. At most 16 KiB of each line is decoded, and only
// its first cell is cut out, so neither a file without line breaks nor very
// wide rows make one slice of the seed sync long.
// ---------------------------------------------------------------------------

describe("G11 (round 7): long lines do not stall the seed sync", () => {
  async function longestGap(run: () => Promise<unknown>): Promise<{ worst: number; result: unknown }> {
    let last = performance.now();
    let worst = 0;
    const timer = setInterval(() => {
      const now = performance.now();
      worst = Math.max(worst, now - last);
      last = now;
    }, 1);
    try {
      const result = await run();
      return { worst: Math.max(worst, performance.now() - last), result };
    } finally {
      clearInterval(timer);
    }
  }

  it("a CSV saved with bare CR line endings (one ~110 MB line) is not decoded in one blocking call", async () => {
    const h = await stubCrawler("", { maxTargets: 100_000 });
    try {
      // Written a chunk at a time: 2M rows held in an array while the sync is
      // timed would make any garbage collection in it mark them all, a pause
      // of the test's own making that a loaded runner stretches past 100 ms.
      const handle = await open(path.join(h.dir, "seeds.csv"), "w");
      try {
        await handle.write("Domain,GlobalRank,TldRank,TLD,RefSubNets,RefIPs");
        for (let from = 0; from < 2_000_000; from += 100_000) {
          let chunk = "";
          for (let i = from; i < from + 100_000; i++) chunk += `\rwww.example-site-${i}.com,${i + 1},${i + 1},com,${i + 7},${i + 9}`;
          await handle.write(chunk);
        }
      } finally {
        await handle.close();
      }
      const { worst, result } = await longestGap(() => h.crawler.syncSeeds(true));
      // A bare CR is not a line break (as before): the whole file is one line whose first cell is the header.
      assert.deepEqual(result, { added: 0, removed: 0, total: 0, invalid: 0 });
      assert.ok(worst < 100, `the longest event-loop stall was ${worst.toFixed(0)} ms`);
    } finally {
      await h.cleanup();
    }
  });

  it("rows of 200 columns keep each slice short: only the first cell is cut out", async () => {
    const h = await stubCrawler("", { maxTargets: 100_000 });
    try {
      const columns = Array.from({ length: 199 }, (_, i) => String(i % 97)).join(",");
      // Built inside the call, so no 60k-row array stays alive (for the garbage collector to mark) while the sync is timed.
      await writeFile(path.join(h.dir, "seeds.csv"), `Domain,${columns}\n${Array.from({ length: 60_000 }, (_, i) => `site-${i}.com,${columns}`).join("\n")}\n`);
      // The same 60k domains as narrow lines, parsed in one synchronous pass:
      // with no columns to cut, this does not depend on the column handling,
      // and it scales with the machine, so a slow runner raises the limit.
      // Cutting only the first cell, the longest stall is about one slice of
      // 10k narrow lines (~15-20 ms here, against ~95 ms for the whole pass).
      // That only the first cell is cut is checked directly in
      // round8-crawler.test.ts: splitting all 200 columns costs ~50 ms a
      // slice here, too little against this limit to tell apart reliably.
      const narrow = Buffer.from(Array.from({ length: 60_000 }, (_, i) => `site-${i}.com`).join("\n"), "utf8");
      const baselineStarted = performance.now();
      let parsed = 0;
      for (const cell of domainListLines(narrow)) if (cell !== null && parseDomain(cell, { allowPrivate: false }).ok) parsed++;
      const baseline = performance.now() - baselineStarted;
      assert.equal(parsed, 60_000);
      const { worst, result } = await longestGap(() => h.crawler.syncSeeds(true));
      assert.deepEqual(result, { added: 60_000, removed: 0, total: 60_000, invalid: 0 });
      const limit = Math.max(100, baseline);
      assert.ok(worst < limit, `the longest event-loop stall was ${worst.toFixed(0)} ms (limit ${limit.toFixed(0)} ms; the narrow pass took ${baseline.toFixed(0)} ms)`);
    } finally {
      await h.cleanup();
    }
  });

  // The cap's documented exceptions (whitespace in or before the first cell that carries some of the cell past it) are in round8-crawler.test.ts.
  it("the 16 KiB decode cap does not change what a line yields as a target", () => {
    const hangul = (n: number): string => Array.from({ length: n }, (_, i) => String.fromCodePoint(0xac00 + (i % 11_000))).join("");
    const long = "x".repeat(40_000);
    const lines = [
      `a.com,${long}`, // long trailing columns
      `${hangul(9000)}.com,1`, // a first cell far past the cap, cut inside a multi-byte character
      `https://${"sub.".repeat(6000)}b.com/path`, // a URL past the cap
      `"quoted.com",${long}`, // a quoted cell closing before the cap
      `"${long}.com",1`, // a quoted cell closing after it
      `# ${long}`, // a long comment
      `   c.com   ,${long}`, // surrounding whitespace
      `${"😀".repeat(20)}.ws,${long}` // a valid emoji name
    ];
    const bytes = Buffer.from(lines.join("\n") + "\n", "utf8");
    const fromBytes = [...domainListLines(bytes)];
    const fromText = [...domainListLines(bytes.toString("utf8"))];
    assert.equal(fromBytes.length, fromText.length);
    const target = (cell: string | null): string | null => {
      if (cell === null) return null;
      const parsed = parseDomain(cell, { allowPrivate: false });
      return parsed.ok ? parsed.domain : "invalid";
    };
    for (let i = 0; i < fromText.length; i++) assert.equal(target(fromBytes[i] ?? null), target(fromText[i] ?? null), `line ${i + 1}`);
    const valid = fromText.map(target).filter((t): t is string => t !== null && t !== "invalid");
    assert.deepEqual(valid.slice(0, 3), ["a.com", "quoted.com", "c.com"], "the lines with a usable first cell keep it");
    assert.match(valid[3] ?? "", /^xn--[a-z0-9]+.ws$/, "and so does the long-row emoji name");
    assert.equal(valid.length, 4, "the cells past the cap stay invalid");
  });
});
