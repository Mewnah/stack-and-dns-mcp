/**
 * Background crawler behind the reverse "who uses X" lookup. It works
 * through an operator-supplied seed list of domains, checks each site's
 * robots.txt, fetches only the homepage (the same inspection as
 * inspect_tech_stack, with the same transparent User-Agent and SSRF guard)
 * and records the result in the scan store, at a fixed rate and once per
 * refresh period per domain.
 *
 * The seed list is the reverse lookup's universe: find_domains_using only
 * ever returns domains that are on it, so it never reveals which domains
 * customers happened to look up.
 */

import { statSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { untilAborted } from "../lib/async.js";
import { parseDomain } from "../lib/domain.js";
import { domainListLines } from "../lib/domainList.js";
import { errorMessage, isToolError } from "../lib/errors.js";
import type { RobotsFile, RobotsResult } from "../lib/robots.js";
import { logger } from "../logger.js";
import { transaction, type Database } from "./db.js";
import { siteKey } from "./scanStore.js";

/** Seed-list rows written per transaction: short lock holds... */
const SEED_CHUNK = 1000;
/** ...with a real gap between them, in which other processes' writes get the lock. */
const SEED_PAUSE_MS = 10;
/** Seed lines parsed, or seed domains and targets diffed, between yields to the event loop. */
const SEED_PARSE_SLICE = 10_000;
/**
 * Seed domains staged per INSERT into the scratch table. Each costs a few
 * microseconds in a table of millions (a random b-tree insert), so a batch
 * stays near 10 ms; the sync yields after each one (a stop is still checked
 * once per slice).
 */
const SEED_STAGE_BATCH = 2_500;
/**
 * The in-memory database a seed sync stages the list in. It is attached to
 * the crawler's connection only for the duration of one sync, so it is
 * private to that connection, takes no lock on the shared database file,
 * and is freed in one step when detached.
 */
const SCRATCH = "crawl_seed";
/**
 * The most of a crawl's error kept as last_error (read only by operators).
 * An HTTPS failure whose http:// fallback robots.txt refused ends in a note
 * saying why, after the HTTPS error's own message; both can name the host
 * (up to 253 characters), and at 300 characters the note was cut off for a
 * host of about 60. fetchHomepage keeps the HTTPS part to 300 characters,
 * so the whole message fits for any host (about 980 characters at most).
 */
const MAX_ERROR_CHARS = 1000;

export type CrawlStatus = "ok" | "blocked" | "unreachable" | "not_found" | "failed" | "robots_disallowed" | "robots_unreachable";

/**
 * Fetches and records one homepage; resolves with how the fetch went. Throws
 * on failure. seedRobots is the robots.txt of https://<domain>/ that already
 * allowed the homepage, when the checker returned it. An outcome given as an
 * object carries the reason, which the crawler records as last_error.
 */
export type CrawlRunner = (
  domain: string,
  signal: AbortSignal,
  seedRobots?: RobotsFile
) => Promise<"ok" | "blocked" | "unreachable" | "robots_disallowed" | { status: "unreachable" | "robots_unreachable"; error: string }>;
export type RobotsChecker = (domain: string, signal: AbortSignal) => Promise<RobotsResult & { file?: RobotsFile }>;

export interface CrawlerOptions {
  seedFile: string;
  ratePerMinute: number;
  refreshMs: number;
  /** First retry delay after a failure; doubles per consecutive failure, capped at refreshMs. */
  retryMs: number;
  concurrency: number;
  tickMs: number;
  maxTargets: number;
  checkTimeoutMs: number;
}

export interface CrawlerDeps {
  db: Database;
  runner: CrawlRunner;
  robots: RobotsChecker;
  options: CrawlerOptions;
  clock?: () => number;
}

export interface CrawlStats {
  targets: number;
  crawled: number;
  due: number;
  byStatus: Partial<Record<CrawlStatus, number>>;
  lastCrawlAt: string | null;
}

export class Crawler {
  private readonly db: Database;
  private readonly options: CrawlerOptions;
  private readonly clock: () => number;
  private timer: NodeJS.Timeout | null = null;
  private ticking: Promise<void> | null = null;
  private running = false;
  private halted = false;
  private seedMtime = -1;
  /** The next seed sync skips the settle wait (set by start()). */
  private forceSync = false;
  /** A changed seed file is applied only once its size and mtime have held for one round (it may be mid-rewrite). */
  private pendingSeed: { mtime: number; size: number } | null = null;
  /** A seed sync is under way: syncs stage the list in the connection's one scratch table, so they never overlap. */
  private syncing = false;
  private statsCache: { at: number; value: CrawlStats } | null = null;
  /** Fractional fetch allowance carried between ticks, so low rates still make progress. */
  private allowance = 0;
  private readonly controllers = new Set<AbortController>();

  constructor(private readonly deps: CrawlerDeps) {
    this.db = deps.db;
    this.options = deps.options;
    this.clock = deps.clock ?? Date.now;
  }

  /**
   * Makes the crawl targets match the seed file: new domains are added (due
   * now), domains no longer listed are dropped. Invalid lines are skipped.
   * Returns null, and changes nothing, when the file is unchanged since the
   * last sync, was just seen changing (it is applied once its size and mtime
   * hold for one round), changed while it was read, or cannot be read (the
   * current targets are kept). It also returns null when shouldStop()
   * interrupted the sync; the next sync redoes it. And it returns null, at
   * once, while another sync is still running.
   *
   * A large list is read off the event loop, parsed in slices into a scratch
   * table, diffed against the targets in key ranges inside SQLite, and
   * applied in short transactions with pauses between them, so it neither
   * blocks this process's event loop nor starves other processes' writes to
   * the shared database. No step holds the list in a JavaScript Set: at a few
   * million entries, a Set's rehash on growth and the garbage collection of
   * its strings each stall the event loop for 100 ms and more.
   */
  async syncSeeds(force = false, shouldStop: () => boolean = () => this.halted): Promise<{ added: number; removed: number; total: number; invalid: number } | null> {
    // The crawler's own rounds already run one at a time, but this method is
    // public. Two syncs would share the connection's one scratch table: the
    // second would empty it while the first still diffs against it, and the
    // first would delete every target the second had not staged yet.
    if (this.syncing) return null;
    this.syncing = true;
    try {
      return await this.syncSeedsOnce(force, shouldStop);
    } finally {
      this.syncing = false;
    }
  }

  private async syncSeedsOnce(force: boolean, shouldStop: () => boolean): Promise<{ added: number; removed: number; total: number; invalid: number } | null> {
    let mtime: number;
    let bytes: Buffer;
    try {
      const stat = statSync(this.options.seedFile);
      mtime = stat.mtimeMs;
      if (!force && mtime === this.seedMtime) return null;
      // An in-place rewrite (truncate, then write) must not be read half
      // written: wait until mtime and size have held for one round.
      if (!force && (this.pendingSeed?.mtime !== mtime || this.pendingSeed?.size !== stat.size)) {
        this.pendingSeed = { mtime, size: stat.size };
        return null;
      }
      // Read on the thread pool and kept as bytes: the parse below decodes
      // each line only when it reaches it. A synchronous read-and-decode of
      // a ranked-domain CSV of a few million rows would hold this process's
      // event loop for 100-300 ms before the first slice.
      bytes = await readFile(this.options.seedFile);
      const after = statSync(this.options.seedFile);
      if (after.mtimeMs !== mtime || after.size !== stat.size) {
        this.pendingSeed = null;
        return null;
      }
    } catch (err) {
      if (this.seedMtime !== -2) logger.warn("crawl seed file could not be read; keeping the current targets", { file: this.options.seedFile, error: err });
      this.seedMtime = -2;
      return null;
    }
    // Every step below (parse, diff) yields to the event loop once per
    // SEED_PARSE_SLICE items and stops there when asked: with millions of
    // targets, any one of them done in a single pass would stall this
    // process's requests for seconds, even when the diff itself is tiny.
    const turn = (): Promise<void> => new Promise((resolve) => setImmediate(resolve));
    const yieldAndCheck = async (): Promise<boolean> => {
      await turn();
      return shouldStop();
    };
    // The code after readFile resumes from an I/O callback, where a
    // setImmediate runs in the same loop turn: without this yield the first
    // slice's yield would let no timer or request in, and the first two
    // slices would run back to back.
    await turn();
    try {
      this.openScratch();
      const staged = await this.stageSeeds(bytes, turn, yieldAndCheck);
      if (!staged) return null;
      const applied = await this.applySeedDiff(this.clock(), shouldStop, yieldAndCheck);
      if (!applied) return null;
      const result = { added: applied.added, removed: applied.removed, total: staged.total, invalid: staged.invalid };
      this.pendingSeed = null;
      this.seedMtime = mtime;
      logger.info("crawl seed list synced", { file: this.options.seedFile, ...result });
      return result;
    } finally {
      this.closeScratch();
    }
  }

  private scratchAttached(): boolean {
    return (this.db.prepare("PRAGMA database_list").all() as unknown as Array<{ name: string }>).some((row) => row.name === SCRATCH);
  }

  /**
   * Attaches the scratch database with an empty seed table, reusing one that
   * a failed detach left attached (syncs never overlap, so an attached one is
   * always a leftover).
   */
  private openScratch(): void {
    if (!this.scratchAttached()) this.db.exec(`ATTACH DATABASE ':memory:' AS ${SCRATCH}`);
    this.db.exec(`DROP TABLE IF EXISTS ${SCRATCH}.wanted; CREATE TABLE ${SCRATCH}.wanted (domain TEXT PRIMARY KEY) WITHOUT ROWID`);
  }

  /** Detaches the scratch database, which frees all of its memory at once. */
  private closeScratch(): void {
    try {
      if (this.scratchAttached()) this.db.exec(`DETACH DATABASE ${SCRATCH}`);
    } catch (err) {
      // The next sync reuses it (openScratch); nothing else reads it.
      logger.warn("crawl seed scratch database could not be detached", { error: err });
    }
  }

  /**
   * Parses the seed file into the scratch table: the distinct targets it
   * names, up to maxTargets, plus the count of invalid lines up to that
   * point. Null when told to stop.
   */
  private async stageSeeds(bytes: Buffer, turn: () => Promise<void>, yieldAndCheck: () => Promise<boolean>): Promise<{ total: number; invalid: number } | null> {
    // A statement on the scratch database alone, in autocommit: it never
    // takes a lock on the shared database file.
    const stage = this.db.prepare(`INSERT OR IGNORE INTO ${SCRATCH}.wanted (domain) SELECT value FROM json_each(?)`);
    let pending: string[] = [];
    let total = 0;
    let invalid = 0;
    let lines = 0;
    const flush = (): void => {
      if (pending.length === 0) return;
      // Sorted, a batch descends the b-tree in key order instead of jumping
      // around it; with 4.5M domains in rank order that halved the slowest batch.
      pending.sort();
      total += Number(stage.run(JSON.stringify(pending)).changes);
      pending = [];
    };
    // Lines are found and decoded lazily (at most 16 KiB of each), so a slice
    // costs 10k bounded lines however long the file or its rows are.
    for (const input of domainListLines(bytes)) {
      if (++lines % SEED_PARSE_SLICE === 0 && (await yieldAndCheck())) return null;
      if (input === null) continue;
      const parsed = parseDomain(input, { allowPrivate: false });
      if (!parsed.ok) {
        invalid++;
        continue;
      }
      // pending may repeat staged domains: near the cap, staging it gives
      // the exact count, so the list stops at the same line as it always has.
      if (total + pending.length >= this.options.maxTargets) {
        flush();
        if (total >= this.options.maxTargets) break;
      }
      pending.push(siteKey(parsed.domain));
      if (pending.length >= SEED_STAGE_BATCH) {
        flush();
        await turn();
      }
    }
    flush();
    return { total, invalid };
  }

  /**
   * Makes crawl_targets match the scratch table: missing domains are added
   * (due now), targets no longer listed are dropped with their crawl_tech
   * rows. Each side is walked in key ranges of SEED_PARSE_SLICE, one short
   * read statement per range, so no read snapshot stays open across the
   * yields; what a range finds is written in transactions of SEED_CHUNK rows
   * with a pause between any two. Both steps are idempotent, so an
   * interrupted sync is simply redone. Null when told to stop.
   */
  private async applySeedDiff(now: number, shouldStop: () => boolean, yieldAndCheck: () => Promise<boolean>): Promise<{ added: number; removed: number } | null> {
    const db = this.db;
    const insert = db.prepare("INSERT INTO crawl_targets (domain, added_at, next_at) VALUES (?, ?, ?) ON CONFLICT(domain) DO NOTHING");
    const remove = db.prepare("DELETE FROM crawl_targets WHERE domain = ?");
    const removeTech = db.prepare("DELETE FROM crawl_tech WHERE domain = ?");
    const pause = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, SEED_PAUSE_MS));
    let wrote = false;
    /** Writes, range by range, the keys of `table` that `other` lacks; resolves with how many. */
    const walk = async (table: string, other: string, write: (domain: string) => void): Promise<number | null> => {
      const missing = `SELECT k.domain FROM ${table} k WHERE k.domain > ? AND NOT EXISTS (SELECT 1 FROM ${other} o WHERE o.domain = k.domain)`;
      // Both bounds are on the key, so a range reads only its own index entries.
      const bound = db.prepare(`SELECT domain FROM ${table} WHERE domain > ? ORDER BY domain LIMIT 1 OFFSET ${SEED_PARSE_SLICE - 1}`);
      const inRange = db.prepare(`${missing} AND k.domain <= ?`);
      const rest = db.prepare(missing);
      let changed = 0;
      for (let after = ""; ;) {
        const upto = (bound.get(after) as { domain: string } | undefined)?.domain;
        const rows = (upto === undefined ? rest.all(after) : inRange.all(after, upto)) as unknown as Array<{ domain: string }>;
        for (let i = 0; i < rows.length; i += SEED_CHUNK) {
          if (wrote) await pause();
          if (shouldStop()) return null;
          transaction(db, () => {
            for (const row of rows.slice(i, i + SEED_CHUNK)) write(row.domain);
          });
          wrote = true;
        }
        changed += rows.length;
        if (upto === undefined) return changed;
        after = upto;
        if (await yieldAndCheck()) return null;
      }
    };
    const added = await walk(`${SCRATCH}.wanted`, "main.crawl_targets", (domain) => insert.run(domain, now, now));
    if (added === null) return null;
    const removed = await walk("main.crawl_targets", `${SCRATCH}.wanted`, (domain) => {
      remove.run(domain);
      removeTech.run(domain);
    });
    if (removed === null) return null;
    return { added, removed };
  }

  /** Answers (including "blocked" and "robots_disallowed") wait a full refresh; failures retry sooner, backing off. */
  private static isFailure(status: CrawlStatus): boolean {
    return status === "failed" || status === "unreachable" || status === "robots_unreachable";
  }

  private async crawlOne(domain: string, now: number): Promise<void> {
    const controller = new AbortController();
    this.controllers.add(controller);
    const timer = setTimeout(() => controller.abort(new Error("crawl deadline")), this.options.checkTimeoutMs);
    let status: CrawlStatus;
    let error: string | null = null;
    try {
      // Raced against the deadline and stop(): lookups cannot be interrupted.
      const robots = await untilAborted(this.deps.robots(domain, controller.signal), controller.signal);
      if (robots.verdict === "disallowed") {
        status = "robots_disallowed";
      } else if (robots.verdict === "not_found") {
        status = "not_found";
      } else if (robots.verdict === "unreachable") {
        // RFC 9309: an unreachable robots.txt means complete disallow for now.
        status = "robots_unreachable";
        error = robots.error;
      } else {
        const outcome = await untilAborted(this.deps.runner(domain, controller.signal, robots.file), controller.signal);
        if (typeof outcome === "object") {
          // An unreachable homepage, or a redirect target whose robots.txt
          // could not be fetched (disallowed for now, not an opt-out).
          status = outcome.status;
          error = outcome.error;
        } else {
          status = outcome;
        }
      }
    } catch (err) {
      if (isToolError(err) && err.code === "DOMAIN_NOT_FOUND") status = "not_found";
      else {
        status = "failed";
        error = isToolError(err) ? err.code : errorMessage(err);
      }
    } finally {
      clearTimeout(timer);
      this.controllers.delete(controller);
    }
    if (this.halted) return;
    // A site that opts out (or no longer exists) leaves the reverse lookup
    // and stops counting as scanned; a later usable crawl sets tech_ok_at again.
    if (status === "robots_disallowed" || status === "not_found") {
      transaction(this.db, () => {
        this.db.prepare("DELETE FROM crawl_tech WHERE domain = ?").run(domain);
        this.db.prepare("UPDATE crawl_targets SET tech_ok_at = NULL WHERE domain = ?").run(domain);
      });
    }
    const row = this.db.prepare("SELECT failures FROM crawl_targets WHERE domain = ?").get(domain) as { failures: number } | undefined;
    if (!row) return; // dropped from the seed list while it was being crawled
    const failures = Crawler.isFailure(status) ? Number(row.failures) + 1 : 0;
    const delay = failures > 0 ? Math.min(this.options.refreshMs, this.options.retryMs * 2 ** Math.min(failures - 1, 20)) : this.options.refreshMs;
    this.db
      .prepare("UPDATE crawl_targets SET last_at = ?, last_status = ?, last_error = ?, failures = ?, next_at = ? WHERE domain = ?")
      .run(now, status, error ? error.slice(0, MAX_ERROR_CHARS) : null, failures, now + delay, domain);
  }

  /** One round: pick up seed-file edits, then crawl as many due targets as the rate allows. */
  tick(now: number = this.clock()): Promise<void> {
    return this.round(now, true);
  }

  /** Applies seed-file changes; a sync that fails is retried next round, and the round goes on with the current targets. */
  private async applySeeds(): Promise<void> {
    try {
      await this.syncSeeds(this.forceSync);
      this.forceSync = false;
    } catch (err) {
      logger.warn("crawl seed list could not be synced; retrying next round", { file: this.options.seedFile, error: err });
    }
  }

  /** Rounds run one at a time (the seed sync included), so stop() can wait for and halt whichever is running. */
  private round(now: number, crawl: boolean): Promise<void> {
    if (this.ticking) return this.ticking;
    // Deferred to a microtask: a round with nothing to do would otherwise finish
    // (and clear this.ticking in its finally) before the assignment below,
    // leaving a settled promise in place that blocks every later round.
    this.ticking = Promise.resolve().then(async () => {
      try {
        await this.applySeeds();
        if (!crawl || this.halted) return;
        this.allowance = Math.min(this.allowance + (this.options.ratePerMinute * this.options.tickMs) / 60_000, Math.max(1, this.options.ratePerMinute));
        const budget = Math.floor(this.allowance);
        if (budget < 1) return;
        const due = this.db.prepare("SELECT domain FROM crawl_targets WHERE next_at <= ? ORDER BY next_at, domain LIMIT ?").all(now, budget) as unknown as Array<{ domain: string }>;
        this.allowance -= due.length;
        let index = 0;
        const workers = Array.from({ length: Math.min(this.options.concurrency, due.length) }, async () => {
          while (index < due.length && !this.halted) {
            const item = due[index++] as { domain: string };
            try {
              await this.crawlOne(item.domain, now);
            } catch (err) {
              logger.error("crawl of one domain crashed", { domain: item.domain, error: err });
            }
          }
        });
        await Promise.all(workers);
      } finally {
        this.ticking = null;
      }
    });
    return this.ticking;
  }

  start(): void {
    if (this.running) return;
    this.running = true;
    this.halted = false;
    // The initial sync runs as a round of its own, off the startup path.
    this.forceSync = true;
    void this.round(this.clock(), false).catch((err: unknown) => logger.error("crawl seed sync failed", { error: err }));
    this.timer = setInterval(() => {
      void this.tick().catch((err: unknown) => logger.error("crawler tick failed", { error: err }));
    }, this.options.tickMs);
    this.timer.unref();
  }

  async stop(): Promise<void> {
    this.running = false;
    this.halted = true;
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    for (const controller of this.controllers) controller.abort();
    if (this.ticking) await this.ticking.catch(() => undefined);
  }

  /** stats(), computed at most once per maxAgeMs: for unauthenticated or frequent callers such as /healthz. */
  cachedStats(maxAgeMs = 30_000): CrawlStats {
    const now = this.clock();
    if (this.statsCache && now - this.statsCache.at < maxAgeMs) return this.statsCache.value;
    const value = this.stats(now);
    this.statsCache = { at: now, value };
    return value;
  }

  /** The most recent crawl time (an indexed lookup). */
  lastCrawlAt(): string | null {
    const last = (this.db.prepare("SELECT MAX(last_at) AS at FROM crawl_targets").get() as { at: number | null }).at;
    return last === null ? null : new Date(last).toISOString();
  }

  stats(now: number = this.clock()): CrawlStats {
    const rows = this.db.prepare("SELECT last_status AS status, COUNT(*) AS n FROM crawl_targets GROUP BY last_status").all() as unknown as Array<{ status: CrawlStatus | null; n: number }>;
    const byStatus: Partial<Record<CrawlStatus, number>> = {};
    let targets = 0;
    let crawled = 0;
    for (const row of rows) {
      targets += Number(row.n);
      if (row.status) {
        byStatus[row.status] = Number(row.n);
        crawled += Number(row.n);
      }
    }
    const due = Number((this.db.prepare("SELECT COUNT(*) AS n FROM crawl_targets WHERE next_at <= ?").get(now) as { n: number }).n);
    const last = (this.db.prepare("SELECT MAX(last_at) AS at FROM crawl_targets").get() as { at: number | null }).at;
    return { targets, crawled, due, byStatus, lastCrawlAt: last === null ? null : new Date(last).toISOString() };
  }
}
