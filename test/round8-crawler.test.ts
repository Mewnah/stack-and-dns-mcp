/**
 * Round-8 regressions for the crawler's seed sync and the homepage fetcher.
 *
 * C-A: the seed sync diffs in SQLite (a scratch in-memory database attached
 * for the sync) instead of JavaScript Sets. C-B: a robots.txt refusal of the
 * http:// fallback is named in the error. C-C: the robots.txt guard's time is
 * credited to the overall deadline too. Plus the first parse slice's yield
 * and the domain list's documented limits. Round 9: a sync never overlaps
 * another, and last_error keeps C-B's note whole. Round 10: leading
 * whitespace short of the 16 KiB decode cap that still pushes part of the
 * first cell past it. Round 11: a multi-byte whitespace character split by
 * the cap, and a first cell cut by it (a different step, the same target).
 * Round 12: the split character's U+FFFD dropped with a path, and a leading
 * line the two forms skip differently moving the header row.
 *
 * Everything runs against :memory: or temporary databases and 127.0.0.1.
 */

import assert from "node:assert/strict";
import fsPromises from "node:fs/promises";
import { mkdtemp, open, rm, writeFile } from "node:fs/promises";
import http from "node:http";
import { syncBuiltinESMExports } from "node:module";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, before, describe, it } from "node:test";
import tls from "node:tls";
import v8 from "node:v8";
import vm from "node:vm";
import { parseDomain } from "../src/lib/domain.js";
import { domainListLines } from "../src/lib/domainList.js";
import { fetchHomepage, type FetchOptions } from "../src/lib/http.js";
import { setLogLevel } from "../src/logger.js";
import { Crawler, type CrawlerOptions } from "../src/store/crawler.js";
import { openDatabase, type Database } from "../src/store/db.js";
import { siteKey } from "../src/store/scanStore.js";

setLogLevel("silent");

// A full garbage collection on demand, so a heap check measures what is
// retained rather than when the collector last happened to run.
v8.setFlagsFromString("--expose-gc");
const gc = vm.runInNewContext("gc") as () => void;

const DAY = 24 * 60 * 60 * 1000;
const MiB = 1024 * 1024;
const UA = "Mozilla/5.0 (compatible; StackAndDnsBot/1.0; +https://github.com/Mewnah/stack-and-dns-mcp)";
const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

type SyncResult = Awaited<ReturnType<Crawler["syncSeeds"]>>;

/** A Crawler over a temporary seed file; nothing is crawled, only syncSeeds is exercised. */
async function seedHarness(seeds: string, options: Partial<CrawlerOptions> = {}, dbName: string | null = null) {
  const dir = await mkdtemp(path.join(tmpdir(), "sdm-r8-crawl-"));
  const seedFile = path.join(dir, "seeds.csv");
  await writeFile(seedFile, seeds, "utf8");
  const dbFile = dbName ? path.join(dir, dbName) : ":memory:";
  const db = await openDatabase(dbFile);
  assert.ok(db);
  const crawler = new Crawler({
    db,
    clock: () => 1_000_000,
    robots: async () => ({ verdict: "allowed", status: 200, error: null }),
    runner: async () => "ok",
    options: { seedFile, ratePerMinute: 60, refreshMs: 30 * DAY, retryMs: 60 * 60 * 1000, concurrency: 1, tickMs: 60_000, maxTargets: 5_000_000, checkTimeoutMs: 5000, ...options }
  });
  const cleanup = async (): Promise<void> => {
    await crawler.stop();
    db.close();
    await rm(dir, { recursive: true, force: true });
  };
  return { dir, seedFile, dbFile, db, crawler, cleanup };
}

function countTargets(db: Database): number {
  return Number((db.prepare("SELECT COUNT(*) AS n FROM crawl_targets").get() as { n: number }).n);
}

function targetDomains(db: Database): string[] {
  return (db.prepare("SELECT domain FROM crawl_targets ORDER BY domain").all() as unknown as Array<{ domain: string }>).map((r) => r.domain);
}

/** The databases attached to a connection: after a sync, only main is left. */
function attached(db: Database): string[] {
  return (db.prepare("PRAGMA database_list").all() as unknown as Array<{ name: string }>).map((r) => r.name);
}

/** Inserts site0.com .. site<n-1>.com as crawl targets in one statement (a sync of that many new lines would spend minutes in its chunk pauses). */
function insertTargets(db: Database, n: number): void {
  db.exec(`WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < ${n - 1}) INSERT INTO crawl_targets (domain, added_at, next_at) SELECT 'site' || i || '.com', 0, 0 FROM n`);
}

/** A small seeded PRNG (mulberry32), so a failing input can be reproduced. */
function seededRandom(seed: number): () => number {
  let state = seed;
  return () => {
    state = (state + 0x6d2b79f5) | 0;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** The result and the target list a sync must produce: the pre-round-8 algorithm, with JavaScript Sets. */
function expectedSync(text: string, existing: string[], maxTargets: number): { result: NonNullable<SyncResult>; targets: string[] } {
  const wanted = new Set<string>();
  let invalid = 0;
  for (const input of domainListLines(text)) {
    if (input === null) continue;
    const parsed = parseDomain(input, { allowPrivate: false });
    if (!parsed.ok) {
      invalid++;
      continue;
    }
    if (wanted.size >= maxTargets) break;
    wanted.add(siteKey(parsed.domain));
  }
  const before = new Set(existing);
  const added = [...wanted].filter((domain) => !before.has(domain)).length;
  const removed = existing.filter((domain) => !wanted.has(domain)).length;
  return { result: { added, removed, total: wanted.size, invalid }, targets: [...wanted].sort() };
}

// ---------------------------------------------------------------------------
// C-A: the seed list is diffed in SQLite, not in JavaScript Sets.
// ---------------------------------------------------------------------------

describe("C-A: a seed sync of millions of targets keeps the list out of the JavaScript heap", () => {
  it("re-syncing 2M existing targets after a one-line edit keeps the event loop free and retains nothing on the heap", async () => {
    const existing = 2_000_000;
    const h = await seedHarness("");
    try {
      // Written a chunk at a time, so the test never holds the whole text.
      const handle = await open(h.seedFile, "w");
      try {
        for (let from = 0; from < existing; from += 100_000) {
          let chunk = "";
          for (let i = from; i < Math.min(existing, from + 100_000); i++) chunk += `site${i}.com\n`;
          await handle.write(chunk);
        }
        await handle.write("brand-new-site.com\n");
      } finally {
        await handle.close();
      }
      insertTargets(h.db, existing);
      // What one unsliced pass over the targets costs on this machine: one
      // statement that visits each and looks it up in the index. A slow
      // runner raises the gap limit below with it.
      const baselineStarted = performance.now();
      const visited = (h.db.prepare("SELECT COUNT(*) AS n FROM crawl_targets c WHERE EXISTS (SELECT 1 FROM crawl_targets d WHERE d.domain = c.domain)").get() as { n: number }).n;
      const baseline = performance.now() - baselineStarted;
      assert.equal(Number(visited), existing);
      // The heap is measured after full collections, so it shows what the
      // sync holds, not how much garbage the collector has yet to free (a
      // sampled peak varied from 0 to 54 MiB between runs of the same build).
      gc();
      const heapBefore = v8.getHeapStatistics().used_heap_size;
      let retained = heapBefore;
      let collections = 0;
      let checks = 0;
      // The longest gap between 1 ms timer callbacks is the longest time the sync kept the event loop to itself.
      let last = performance.now();
      let worst = 0;
      const timer = setInterval(() => {
        const now = performance.now();
        worst = Math.max(worst, now - last);
        last = now;
      }, 1);
      let result: SyncResult;
      try {
        result = await h.crawler.syncSeeds(true, () => {
          // Every 50th check (each 500k lines parsed or keys diffed), with the
          // collection's own pause taken out of the gap being measured.
          if (++checks % 50 === 0) {
            const started = performance.now();
            gc();
            retained = Math.max(retained, v8.getHeapStatistics().used_heap_size);
            collections++;
            last += performance.now() - started;
          }
          return false;
        });
      } finally {
        clearInterval(timer);
      }
      worst = Math.max(worst, performance.now() - last);
      assert.deepEqual(result, { added: 1, removed: 0, total: existing + 1, invalid: 0 });
      assert.equal(countTargets(h.db), existing + 1);
      // Measured here: diffed in SQLite, the worst gap was 12-17 ms (up to ~56
      // ms with other test runs loading the machine) against a baseline of
      // 430-730 ms. Diffing either side in one statement stalled for 1000-1570
      // ms, over twice the baseline and so over 8 times the limit. With two
      // Sets of 2M domains it was 43-76 ms, which this does not catch (at 4.5M
      // a Set's rehash alone passes 100 ms); the heap check below does.
      const limit = Math.max(100, baseline / 4);
      assert.ok(worst < limit, `the longest event-loop stall during the re-sync was ${worst.toFixed(0)} ms (limit ${limit.toFixed(0)} ms; one unsliced pass took ${baseline.toFixed(0)} ms)`);
      // The parse alone makes 200 checks.
      assert.ok(collections >= 4, `the heap was measured during the sync (${collections} times in ${checks} checks)`);
      // Retained here: under 1 MiB. The two Sets held 104-106 MiB at the end of
      // the parse and 202 MiB once both were built.
      const growth = (retained - heapBefore) / MiB;
      assert.ok(growth < 32, `the sync retained ${growth.toFixed(1)} MiB of JavaScript heap at its peak`);
      assert.deepEqual(attached(h.db), ["main"], "the scratch database was detached");
    } finally {
      await h.cleanup();
    }
  });

  it("gives the same counts, targets and maxTargets cut as the Set-based sync, around every batch and slice boundary", async () => {
    const random = seededRandom(0xc0a);
    const pool = Array.from({ length: 14_000 }, (_, i) => `d${i}.example`);
    const lines: string[] = ["Domain,Rank"];
    for (let i = 0; i < 26_000; i++) {
      const roll = random();
      const domain = pool[Math.floor(random() * pool.length)] as string;
      if (roll < 0.08) lines.push(`not_a_domain_${i}`);
      else if (roll < 0.12) lines.push("");
      else if (roll < 0.16) lines.push(`www.${domain.toUpperCase()},${i}`);
      else if (roll < 0.2) lines.push(`https://${domain}/page?x=${i}`);
      else lines.push(`${domain},${i}`);
    }
    const text = lines.join("\n");
    // Half of the existing targets are on the list, half are not; the latter lose their crawl_tech rows too.
    const existing = [...pool.slice(0, 3000), ...Array.from({ length: 3000 }, (_, i) => `gone${i}.example`)];
    for (const maxTargets of [1, 2499, 2500, 2501, 9_999, 10_000, 10_001, 12_345, 1_000_000]) {
      const h = await seedHarness(text, { maxTargets });
      try {
        h.db.exec("BEGIN");
        const insert = h.db.prepare("INSERT INTO crawl_targets (domain, added_at, next_at) VALUES (?, 0, 0)");
        const tech = h.db.prepare("INSERT INTO crawl_tech (domain, tech_id, first_seen, last_seen) VALUES (?, 'shopify', 0, 0)");
        for (const domain of existing) {
          insert.run(domain);
          tech.run(domain);
        }
        h.db.exec("COMMIT");
        const expected = expectedSync(text, existing, maxTargets);
        const result = await h.crawler.syncSeeds(true);
        assert.deepEqual(result, expected.result, `maxTargets ${maxTargets}`);
        assert.deepEqual(targetDomains(h.db), expected.targets, `maxTargets ${maxTargets}: the targets`);
        const orphans = Number((h.db.prepare("SELECT COUNT(*) AS n FROM crawl_tech WHERE domain NOT IN (SELECT domain FROM crawl_targets)").get() as { n: number }).n);
        assert.equal(orphans, 0, `maxTargets ${maxTargets}: a dropped target's crawl_tech rows went with it`);
        assert.deepEqual(attached(h.db), ["main"]);
      } finally {
        await h.cleanup();
      }
    }
  });

  it("stages the list where the shared database never sees it, and leaves its write lock free while it does", async () => {
    const total = 25_000;
    const h = await seedHarness(Array.from({ length: total }, (_, i) => `site${i}.com`).join("\n"), {}, "crawl.db");
    const other = await openDatabase(h.dbFile);
    assert.ok(other);
    try {
      other.exec("CREATE TABLE probe (n INTEGER NOT NULL)");
      // No busy wait at all: the write fails outright if the sync holds the lock.
      other.exec("PRAGMA busy_timeout = 0");
      const duringStaging: Array<{ staged: number; visible: number; wrote: boolean }> = [];
      const result = await h.crawler.syncSeeds(true, () => {
        const staged = Number((h.db.prepare("SELECT COUNT(*) AS n FROM crawl_seed.wanted").get() as { n: number }).n);
        if (staged === 0 || staged >= total || countTargets(h.db) > 0) return false;
        // The parse is under way and part of the list is staged.
        const visible = Number((other.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE name LIKE '%seed%' OR name = 'wanted'").get() as { n: number }).n);
        let wrote = true;
        try {
          other.exec("BEGIN IMMEDIATE");
          other.prepare("INSERT INTO probe (n) VALUES (?)").run(staged);
          other.exec("COMMIT");
        } catch {
          wrote = false;
          try {
            other.exec("ROLLBACK");
          } catch {
            // no transaction open
          }
        }
        duringStaging.push({ staged, visible, wrote });
        return false;
      });
      assert.equal(result?.total, total);
      assert.ok(duringStaging.length >= 2, `the parse yielded while staging (${JSON.stringify(duringStaging)})`);
      assert.ok(
        duringStaging.every((s) => s.visible === 0 && s.wrote),
        `the staged list is invisible to another connection, which wrote without waiting (${JSON.stringify(duringStaging)})`
      );
    } finally {
      other.close();
      await h.cleanup();
    }
  });

  it("detaches the scratch database after an interrupted or failed sync, and reuses one a failed detach left attached", async () => {
    const h = await seedHarness("a.com\nb.com\nc.com\n", {}, "crawl.db");
    try {
      assert.equal(await h.crawler.syncSeeds(true, () => true), null, "interrupted before its first write");
      assert.deepEqual(attached(h.db), ["main"], "detached after an interrupted sync");
      assert.equal(countTargets(h.db), 0);

      // Another connection holds the write lock past the sync's busy timeout, so its first write fails.
      const other = await openDatabase(h.dbFile);
      assert.ok(other);
      try {
        other.exec("BEGIN IMMEDIATE");
        await assert.rejects(h.crawler.syncSeeds(true), /locked|busy/i);
        other.exec("ROLLBACK");
      } finally {
        other.close();
      }
      assert.deepEqual(attached(h.db), ["main"], "detached after a failed sync");

      // A scratch database left attached, with a stale table in it, is emptied and reused.
      h.db.exec("ATTACH DATABASE ':memory:' AS crawl_seed");
      h.db.exec("CREATE TABLE crawl_seed.wanted (domain TEXT PRIMARY KEY) WITHOUT ROWID; INSERT INTO crawl_seed.wanted VALUES ('stale.com')");
      assert.deepEqual(await h.crawler.syncSeeds(true), { added: 3, removed: 0, total: 3, invalid: 0 });
      assert.deepEqual(targetDomains(h.db), ["a.com", "b.com", "c.com"]);
      assert.deepEqual(attached(h.db), ["main"]);
    } finally {
      await h.cleanup();
    }
  });

  it("a sync called while another is running returns null at once and changes nothing", async () => {
    // The replay that found it: an unchanged list of 300k targets that all
    // have crawl_tech rows, and a second sync started from the first one's
    // 61st check (30 parse slices and 30 ranges of seed domains in, so at the
    // start of the walk over the targets). Sharing the scratch table, the
    // second emptied it and the first deleted 55,400 targets and their rows.
    const existing = 300_000;
    const h = await seedHarness(Array.from({ length: existing }, (_, i) => `site${i}.com`).join("\n"));
    try {
      insertTargets(h.db, existing);
      h.db.exec("INSERT INTO crawl_tech (domain, tech_id, first_seen, last_seen) SELECT domain, 'shopify', 0, 0 FROM crawl_targets");
      const events: string[] = [];
      const overlap: { second?: Promise<SyncResult> } = {};
      let checks = 0;
      const first = await h.crawler.syncSeeds(true, () => {
        if (++checks === 61) {
          overlap.second = h.crawler.syncSeeds(true, () => false);
          const settled = (): number => events.push("second settled");
          void overlap.second.then(settled, settled);
        }
        return false;
      });
      events.push("first settled");
      assert.ok(checks > 61 && overlap.second, `the second sync started part way through the first (${checks} checks)`);
      const second = await overlap.second.catch((err: unknown) => `rejected: ${String(err)}`);
      assert.deepEqual(first, { added: 0, removed: 0, total: existing, invalid: 0 }, "the first sync was not disturbed");
      assert.equal(countTargets(h.db), existing, "no target was deleted");
      assert.equal(Number((h.db.prepare("SELECT COUNT(*) AS n FROM crawl_tech").get() as { n: number }).n), existing, "nor any crawl_tech row");
      assert.equal(second, null, "the overlapping sync did nothing");
      assert.deepEqual(events, ["second settled", "first settled"], "and returned before the first one ended");
      assert.deepEqual(attached(h.db), ["main"]);
      // Once the first has ended, a sync runs again.
      assert.deepEqual(await h.crawler.syncSeeds(true), { added: 0, removed: 0, total: existing, invalid: 0 });
    } finally {
      await h.cleanup();
    }
  });
});

// ---------------------------------------------------------------------------
// The first parse slice gets a yield of its own.
// ---------------------------------------------------------------------------

describe("seed sync: the event loop runs before the first parse slice ends", () => {
  it("lets a timer in between the end of the file read and the first slice's check, and checks once per 10k lines", async () => {
    const lines = 25_000;
    // Invalid lines: nothing is staged, so the only yields are the parse slices' own.
    const h = await seedHarness(Array.from({ length: lines }, (_, i) => `not_a_domain_${i}`).join("\n"));
    const events: string[] = [];
    // The read resolves in an I/O callback; recording it there marks where the sync resumes.
    const files = fsPromises as { readFile: typeof fsPromises.readFile };
    const originalReadFile = files.readFile;
    files.readFile = (async (...args: Parameters<typeof fsPromises.readFile>) => {
      const content = await originalReadFile(...args);
      if (args[0] === h.seedFile) events.push("read");
      return content;
    }) as typeof fsPromises.readFile;
    syncBuiltinESMExports();
    const timer = setInterval(() => events.push("tick"), 1);
    try {
      const result = await h.crawler.syncSeeds(true, () => {
        events.push("check");
        return false;
      });
      assert.deepEqual(result, { added: 0, removed: 0, total: 0, invalid: lines });
      assert.equal(events.filter((e) => e === "check").length, 2, "one check per 10k lines parsed (at 10k and 20k), and none elsewhere: nothing was staged or diffed");
      const read = events.indexOf("read");
      const firstCheck = events.indexOf("check");
      assert.ok(read !== -1 && firstCheck > read, `the read came first (${events.join(" ")})`);
      // Without a yield before the parse, slice 1 runs in the read's callback and its own
      // setImmediate in the same loop turn, so no timer can run until slice 2 is done.
      assert.ok(events.slice(read, firstCheck).includes("tick"), `a timer ran between the read and the first slice's check (${events.slice(read, firstCheck + 2).join(" ")})`);
    } finally {
      clearInterval(timer);
      files.readFile = originalReadFile;
      syncBuiltinESMExports();
      await h.cleanup();
    }
  });
});

// ---------------------------------------------------------------------------
// C-B and C-C: fetchHomepage's fallbacks with a robots.txt guard.
// ---------------------------------------------------------------------------

/** A plain HTTP loopback server: the https attempts fail their TLS handshake against it, and the http:// fallback reaches it. */
let plain: http.Server;
let plainOrigin = "";
const homepageHits: string[] = [];

before(async () => {
  plain = http.createServer((req, res) => {
    homepageHits.push(req.url ?? "/");
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end('<html><head><meta name="generator" content="WordPress 6.5"></head></html>');
  });
  await new Promise<void>((resolve) => plain.listen(0, "127.0.0.1", resolve));
  plainOrigin = `127.0.0.1:${(plain.address() as AddressInfo).port}`;
});

after(async () => {
  plain.closeAllConnections();
  await new Promise<void>((resolve) => plain.close(() => resolve()));
});

const fetchOptions = (extra: Partial<FetchOptions>): FetchOptions => ({ timeoutMs: 1000, maxBodyBytes: 100_000, userAgent: UA, allowPrivate: true, ...extra });

describe("C-B: an http:// fallback refused by robots.txt is named in the error", () => {
  it("keeps the HTTPS failure as the outcome and appends the refusal to its message", async () => {
    homepageHits.length = 0;
    const result = await fetchHomepage(
      plainOrigin,
      fetchOptions({
        beforeRequest: async (url) => {
          if (url.protocol === "http:") throw Object.assign(new Error(`robots.txt of ${url.origin} does not allow ${url.pathname}`), { code: "EROBOTS" });
        }
      })
    );
    assert.equal(result.ok, false);
    assert.equal(result.error?.kind, "tls", "the HTTPS failure stays the outcome (its robots.txt allowed the fetch)");
    assert.equal(result.httpsDowngraded, false);
    assert.equal(result.timings.attempts, 3, "strict, insecure-TLS retry, http:// fallback");
    const refusal = `; the http:// fallback was refused (robots.txt of http://${plainOrigin} does not allow /)`;
    assert.ok(result.error?.message.endsWith(refusal), `the message says why no http:// result follows (got ${JSON.stringify(result.error?.message)})`);
    assert.ok((result.error?.message.length ?? 0) > refusal.length, "after the HTTPS error's own message");
    assert.ok(!result.error?.message.includes("\n"), "on one line (OpenSSL's message ends in a line break)");
    assert.deepEqual(homepageHits, [], "the refused page was never requested");
  });

  it("the crawler stores the whole note for a 60-character host, after OpenSSL's message", async () => {
    const host = `${"long-shop-name-".repeat(3)}storefronts.com`;
    assert.equal(host.length, 60);
    // The guard's refusal as services.ts words it, for a robots.txt whose
    // connection timed out (undici's message names the host again).
    const why = `could not be fetched (UND_ERR_CONNECT_TIMEOUT: Connect Timeout Error (attempted address: ${host}:80, timeout: 3000ms))`;
    const fetched = await fetchHomepage(
      plainOrigin,
      fetchOptions({
        beforeRequest: async (url) => {
          if (url.protocol === "http:") throw Object.assign(new Error(`robots.txt of http://${host} ${why}`), { code: "EROBOTS" });
        }
      })
    );
    const failure = fetched.error;
    assert.ok(failure);
    assert.equal(failure.kind, "tls");
    // What createCrawlRunner returns for it.
    const error = `${failure.kind}: ${failure.message}`;
    const note = `; the http:// fallback was refused (robots.txt of http://${host} ${why})`;
    assert.ok(error.endsWith(note), error);
    assert.ok(error.length > 300, `past crawlOne's old 300-character cut (${error.length} characters)`);
    const db = await openDatabase(":memory:");
    assert.ok(db);
    try {
      db.prepare("INSERT INTO crawl_targets (domain, added_at, next_at) VALUES (?, 0, 0)").run(host);
      const crawler = new Crawler({
        db,
        clock: () => 1_000_000,
        robots: async () => ({ verdict: "allowed", status: 200, error: null }),
        runner: async () => ({ status: "unreachable", error }),
        // No seed file: the sync keeps the target inserted above.
        options: {
          seedFile: path.join(tmpdir(), `sdm-r8-no-seeds-${process.pid}.csv`),
          ratePerMinute: 60,
          refreshMs: 30 * DAY,
          retryMs: 60 * 60 * 1000,
          concurrency: 1,
          tickMs: 60_000,
          maxTargets: 10,
          checkTimeoutMs: 5000
        }
      });
      await crawler.tick(1_000_000);
      await crawler.stop();
      const row = db.prepare("SELECT last_status, last_error FROM crawl_targets WHERE domain = ?").get(host) as { last_status: string; last_error: string | null };
      assert.equal(row.last_status, "unreachable");
      assert.equal(row.last_error, error, "last_error keeps the whole message, the refusal included");
    } finally {
      db.close();
    }
  });

  it("cuts a long HTTPS message short, so the note after it stays inside the crawler's cap", async () => {
    // A connect timeout lists every address it tried; here, a reset whose
    // message is over 400 characters long.
    const long = `connect ECONNRESET ${"2001:db8:0:0:0:0:0:1, ".repeat(18)}`;
    type AnyFn = (...args: unknown[]) => unknown;
    const tlsModule = tls as unknown as { connect: AnyFn };
    const originalConnect = tlsModule.connect;
    tlsModule.connect = (...args: unknown[]) => {
      const socket = originalConnect.apply(tls, args) as tls.TLSSocket;
      process.nextTick(() => socket.destroy(Object.assign(new Error(long), { code: "ECONNRESET" })));
      return socket;
    };
    let result: Awaited<ReturnType<typeof fetchHomepage>>;
    try {
      result = await fetchHomepage(
        plainOrigin,
        fetchOptions({
          beforeRequest: async (url) => {
            if (url.protocol === "http:") throw Object.assign(new Error(`robots.txt of ${url.origin} does not allow /`), { code: "EROBOTS" });
          }
        })
      );
    } finally {
      tlsModule.connect = originalConnect;
    }
    const failure = result.error;
    assert.ok(failure);
    assert.equal(failure.kind, "connection", failure.message);
    const message = failure.message;
    const note = `; the http:// fallback was refused (robots.txt of http://${plainOrigin} does not allow /)`;
    assert.ok(message.endsWith(note), message);
    const head = message.slice(0, -note.length);
    assert.ok(head.length <= 300, `the HTTPS part is at most 300 characters (${head.length})`);
    assert.ok(head.endsWith("...") && long.startsWith(head.slice(0, -3)), `and is the start of the original message, marked as cut (${JSON.stringify(head)})`);
  });

  it("leaves the message alone when the fallback fails for any other reason", async () => {
    const result = await fetchHomepage(
      plainOrigin,
      fetchOptions({
        beforeRequest: async (url) => {
          if (url.protocol === "http:") throw Object.assign(new Error("guard broke"), { code: "EGUARD" });
        }
      })
    );
    assert.equal(result.error?.kind, "tls");
    assert.ok(!result.error?.message.includes("fallback"), result.error?.message);
  });
});

describe("C-C: the robots.txt guard's time does not use up the budget of the fallback attempts", () => {
  it("still runs the insecure-TLS retry and the http:// fallback after a guard slower than the whole fetch budget", async () => {
    homepageHits.length = 0;
    const guarded: string[] = [];
    const started = Date.now();
    // timeoutMs 300 gives fallbacks until 600 ms; the first guard call alone takes 900.
    const result = await fetchHomepage(
      plainOrigin,
      fetchOptions({
        timeoutMs: 300,
        beforeRequest: async (url) => {
          guarded.push(url.href);
          if (guarded.length === 1) await sleep(900);
        }
      })
    );
    assert.equal(result.error, null, `no error (got ${JSON.stringify(result.error)})`);
    assert.equal(result.ok, true);
    assert.equal(result.tlsError?.kind, "tls", "the insecure-TLS retry ran");
    assert.equal(result.httpsDowngraded, true, "and so did the http:// fallback, which reached the page");
    assert.equal(result.timings.attempts, 3);
    assert.deepEqual(guarded, [`https://${plainOrigin}/`, `https://${plainOrigin}/`, `http://${plainOrigin}/`]);
    assert.deepEqual(homepageHits, ["/"]);
    assert.ok(Date.now() - started < 900 + 600 + 500, "within 2 * timeoutMs plus the guard's time (and some slack)");
  });
});

// ---------------------------------------------------------------------------
// The domain list's documented limits (src/lib/domainList.ts).
// ---------------------------------------------------------------------------

describe("domainListLines: the first cell only, and the 16 KiB decode cap's exceptions", () => {
  it("cuts out only the first cell: a row of 4M columns costs well under a millisecond", () => {
    const row = `a.com${",7".repeat(4_000_000)}`;
    assert.equal(row.trim().length, row.length, "the row is flat before timing");
    // The best of three, so a stray pause elsewhere cannot fail it. A split of
    // every column takes ~70 ms here, cutting the first cell ~0.3 ms.
    let best = Infinity;
    for (let k = 0; k < 3; k++) {
      const started = performance.now();
      const cells = [...domainListLines(row)];
      best = Math.min(best, performance.now() - started);
      assert.deepEqual(cells, ["a.com"]);
    }
    assert.ok(best < 20, `reading the first cell of the row took ${best.toFixed(2)} ms`);
  });

  it("a valid cell of ~6 KiB (a URL with a long non-ASCII path) gives the same target from the bytes as from the text", () => {
    const url = `https://example.com/${"漢".repeat(2000)}`;
    assert.ok(Buffer.byteLength(url) > 6000);
    const bytes = Buffer.from(`${url},${"x".repeat(20_000)}\n`, "utf8");
    const target = (cell: string | null | undefined): string | null => {
      if (!cell) return null;
      const parsed = parseDomain(cell, { allowPrivate: false });
      return parsed.ok ? parsed.domain : null;
    };
    assert.equal(target([...domainListLines(bytes)][0]), "example.com");
    assert.equal(target([...domainListLines(bytes.toString("utf8"))][0]), "example.com");
  });

  it("the documented exceptions: whitespace in or before the first cell that carries some of the cell past the 16 KiB mark", () => {
    const pad = " ".repeat(17_000);
    // Leading whitespace, before the cell or inside its opening quote, pushes it out of the decoded part.
    for (const line of [`${pad}example.com,1`, `"${pad}example.com"`]) {
      const bytes = Buffer.from(`${line}\n`, "utf8");
      assert.equal([...domainListLines(bytes.toString("utf8"))][0], "example.com", "the text keeps the cell");
      assert.equal([...domainListLines(bytes)][0], null, "the byte form decodes only whitespace of it");
    }
    const target = (cell: string | null | undefined): string | null => {
      if (!cell) return null;
      const parsed = parseDomain(cell, { allowPrivate: false });
      return parsed.ok ? parsed.domain : "invalid";
    };
    // Round 10: leading whitespace that stops short of the mark still pushes the cell's tail past it, so the
    // bytes keep only the cell's head. Here that head is another valid domain, which the crawler would stage.
    for (const [line, lead, fromText, fromBytes] of [
      [`${" ".repeat(16_375)}shop.example.com,1`, 16_375, "shop.example.com", "shop.exam"],
      [`"${" ".repeat(16_377)}example.com",1`, 16_378, "example.com", "invalid"]
    ] as const) {
      assert.ok(Buffer.byteLength(line.slice(0, lead)) < 16 * 1024, "the whitespace ends before the mark");
      const bytes = Buffer.from(`${line}\n`, "utf8");
      assert.equal(target([...domainListLines(bytes.toString("utf8"))][0]), fromText, "the text keeps the whole cell");
      assert.equal(target([...domainListLines(bytes)][0]), fromBytes, "the byte form keeps the part before the mark");
    }
    // A run of whitespace inside the cell cuts off the rest of it: the bytes give the valid start.
    for (const line of [`example.com${pad}x,1`, `"example.com${pad}x",1`]) {
      const bytes = Buffer.from(`${line}\n`, "utf8");
      assert.equal(target([...domainListLines(bytes.toString("utf8"))][0]), "invalid", "the text's cell is rejected");
      assert.equal(target([...domainListLines(bytes)][0]), "example.com", "the byte form keeps the part before the mark");
    }
  });

  // Round 11: the cut that splits a multi-byte whitespace character, and the steps-against-targets wording.
  it("the documented exceptions: a multi-byte whitespace character split at the 16 KiB mark leaves U+FFFD, which spoils the cell short of a path, query or fragment", () => {
    const target = (cell: string | null | undefined): string | null => {
      if (!cell) return null;
      const parsed = parseDomain(cell, { allowPrivate: false });
      return parsed.ok ? parsed.domain : "invalid";
    };
    const ideographic = "　".repeat(6000);
    // Between the cell's content and its separator: the content ends long before the mark, yet the bytes reject it.
    for (const line of [`example.com${ideographic},1`, `example.com${" ".repeat(16_372)}　,1`, `example.com${" ".repeat(8200)},1`]) {
      const bytes = Buffer.from(`${line}\n`, "utf8");
      const cell = [...domainListLines(bytes)][0];
      assert.equal(target([...domainListLines(bytes.toString("utf8"))][0]), "example.com", "the text keeps the cell");
      assert.ok(cell?.endsWith("�"), `the byte form's cell ends in U+FFFD: ${JSON.stringify(cell?.slice(-2))}`);
      assert.equal(target(cell), "invalid", "so the crawler counts the line invalid");
    }
    // A header cell followed by such a run is counted invalid instead of skipped.
    const header = Buffer.from(`domain${ideographic},x\na.com`, "utf8");
    assert.deepEqual([...domainListLines(header.toString("utf8"))], [null, "a.com"]);
    const [headerCell, next] = [...domainListLines(header)];
    assert.ok(headerCell?.startsWith("domain") && headerCell.endsWith("�"));
    assert.equal(target(headerCell), "invalid");
    assert.equal(next, "a.com");
    // In leading whitespace reaching the mark it gives an invalid cell instead of nothing, even on a blank or comment line.
    for (const [line, fromText] of [
      [`${ideographic}example.com,1`, "example.com"],
      [ideographic, null],
      [`${ideographic}# note`, null]
    ] as const) {
      const bytes = Buffer.from(`a.com\n${line}\n`, "utf8");
      assert.equal(target([...domainListLines(bytes.toString("utf8"))][1]), fromText);
      assert.equal([...domainListLines(bytes)][1], "�", "the byte form keeps only the split character");
    }
    // After a closing quote the split does not matter: the quote has already ended the cell.
    const quoted = Buffer.from(`"example.com"${ideographic},1\n`, "utf8");
    assert.equal([...domainListLines(quoted)][0], "example.com");
    // Round 12: unless parseDomain drops the U+FFFD with the rest of a path, query or fragment. Leading whitespace,
    // which trim() removes, brings a short cell up to the mark, so the cell stays under parseDomain's 2048 characters
    // and the bytes still give the text's target. The query and fragment rows have no '/' at all.
    for (const [line, domain] of [
      [`${" ".repeat(16_370)}example.com/${"　".repeat(10)},1`, "example.com"],
      [`${" ".repeat(16_362)}https://example.com/${"　".repeat(10)},1`, "example.com"],
      [`${" ".repeat(16_362)}www.example.com/about${" ".repeat(10)}`, "www.example.com"],
      [`${" ".repeat(16_369)}example.com?a${"　".repeat(10)},1`, "example.com"],
      [`${" ".repeat(16_369)}example.com#a${"　".repeat(10)},1`, "example.com"]
    ] as const) {
      const bytes = Buffer.from(`${line}\n`, "utf8");
      const cell = [...domainListLines(bytes)][0];
      assert.ok(cell?.endsWith("�") && cell.length < 2048, `the byte form's cell is short and ends in U+FFFD: ${JSON.stringify(cell?.slice(-3))}`);
      assert.equal(target(cell), domain, "so parseDomain drops the U+FFFD with the path, query or fragment");
      assert.equal(target([...domainListLines(bytes.toString("utf8"))][0]), domain);
    }
  });

  // Round 12: a line one form skips and the other does not also decides whether the next line that is neither blank nor
  // a comment can be the header row, because only such a line ends the search for it. Blank and comment lines in
  // between do not protect the header.
  it("the documented exceptions' knock-on: a leading line the forms skip differently moves the header row, though the header has no whitespace", async () => {
    const ideographic = "　".repeat(6000);
    for (const [list, fromText, fromBytes, invalid] of [
      // The text skips the first line, so 'domain' is still its header; the bytes yield U+FFFD and then 'domain'.
      [`${ideographic}\ndomain\na.com\n`, [null, null, "a.com", null], ["�", "domain", "a.com", null], 2],
      [`${ideographic}# note\nWebsite\na.com\n`, [null, null, "a.com", null], ["�", "Website", "a.com", null], 2],
      // Blank and comment lines between the stray line and the header do not end the search, so the outcome is the same.
      [`${ideographic}\n\n# exported\ndomain\na.com\n`, [null, null, null, null, "a.com", null], ["�", null, null, "domain", "a.com", null], 2],
      // The other way round (round 10's class): the bytes skip the first line, so 'domain' is their header.
      [`${" ".repeat(17_000)}example.com\ndomain\na.com\n`, ["example.com", "domain", "a.com", null], [null, null, "a.com", null], 0],
      [`${" ".repeat(17_000)}example.com\n# exported\ndomain\na.com\n`, ["example.com", null, "domain", "a.com", null], [null, null, null, "a.com", null], 0]
    ] as const) {
      assert.ok(!/\s/.test(list.split("\n").find((l) => /^(domain|website)$/i.test(l))!), "the header line has no whitespace at all");
      const bytes = Buffer.from(list, "utf8");
      assert.deepEqual([...domainListLines(bytes.toString("utf8"))], fromText);
      assert.deepEqual([...domainListLines(bytes)], fromBytes);
      // The crawler reads the byte form, so the header line is counted invalid (or not) by its sync.
      const h = await seedHarness(list);
      try {
        assert.deepEqual(await h.crawler.syncSeeds(true), { added: 1, removed: 0, total: 1, invalid });
        assert.deepEqual(targetDomains(h.db), ["a.com"]);
      } finally {
        await h.cleanup();
      }
    }
  });

  it("a first cell running past the 16 KiB mark comes out cut from the bytes: a different step, the same rejected target", () => {
    const rejected = (cell: string | null | undefined): boolean => typeof cell === "string" && !parseDomain(cell, { allowPrivate: false }).ok;
    for (const [line, textLength, byteLength] of [
      [`${"x".repeat(20_000)},1`, 20_000, 16_384],
      // 16,384 bytes of 3-byte characters end inside the 5,462nd, which decodes as U+FFFD.
      [`${"가".repeat(9000)}.com,1`, 9004, 5462]
    ] as const) {
      assert.ok(!/\s/.test(line), "no whitespace anywhere in the line");
      const bytes = Buffer.from(`${line}\n`, "utf8");
      const fromText = [...domainListLines(bytes.toString("utf8"))][0];
      const fromBytes = [...domainListLines(bytes)][0];
      assert.equal(fromText?.length, textLength);
      assert.equal(fromBytes?.length, byteLength, "the byte form's step is the cut prefix, not the text's cell");
      assert.ok(rejected(fromText) && rejected(fromBytes), "both are rejected, so the crawler's outcome is the same");
    }
  });
});
