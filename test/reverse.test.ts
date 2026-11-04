import assert from "node:assert/strict";
import { mkdtemp, rm, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { ToolError } from "../src/lib/errors.js";
import { isAllowed, parseRobots, productToken, type RobotsResult } from "../src/lib/robots.js";
import { setLogLevel } from "../src/logger.js";
import { Crawler, type CrawlerOptions } from "../src/store/crawler.js";
import { openDatabase, type Database } from "../src/store/db.js";
import { ReverseLookup } from "../src/store/reverse.js";
import { ScanStore, type TechScanInput } from "../src/store/scanStore.js";
import { listTechnologies, resolveTechnology } from "../src/tools/reverse.js";

setLogLevel("silent");

const DAY = 24 * 60 * 60 * 1000;
const UA = "Mozilla/5.0 (compatible; StackAndDnsBot/1.0; +https://github.com/Mewnah/stack-and-dns-mcp)";

function tech(domain: string, ids: string[], versions: Record<string, string> = {}): TechScanInput {
  return {
    domain,
    partial: false,
    fetch: { ok: true, status: 200, finalHost: domain, truncated: false, error: null },
    blocked: { blocked: false, vendor: null, challengeType: null, reason: null },
    technologies: ids.map((id) => ({ id, name: id, category: "ecommerce", version: versions[id] ?? null, implied: false })),
    security: { score: 70, grade: "C" }
  } as unknown as TechScanInput;
}

describe("robots.txt", () => {
  it("uses our product token, falls back to *, and applies the longest matching rule", () => {
    assert.equal(productToken(UA), "stackanddnsbot");
    const robots = parseRobots(["User-agent: *", "Disallow: /", "", "User-agent: Googlebot", "User-agent: StackAndDnsBot", "Allow: /$", "Disallow: /private"].join("\n"));
    assert.equal(isAllowed(robots, "stackanddnsbot", "/"), true, "our group allows the homepage");
    assert.equal(isAllowed(robots, "stackanddnsbot", "/private/x"), false);
    assert.equal(isAllowed(robots, "otherbot", "/"), false, "everyone else falls back to *");
  });

  it("handles wildcards, end anchors, ties and empty disallows", () => {
    const groups = parseRobots(["user-agent: *", "disallow: /*.php$", "allow: /index.php$", "disallow:", "# comment", "Sitemap: https://x/sitemap.xml"].join("\r\n"));
    assert.equal(isAllowed(groups, "bot", "/"), true);
    assert.equal(isAllowed(groups, "bot", "/a.php"), false);
    assert.equal(isAllowed(groups, "bot", "/a.php?x=1"), true, "$ anchors the end");
    assert.equal(isAllowed(groups, "bot", "/index.php"), true, "the longer allow wins");
    const tie = parseRobots("User-agent: *\nDisallow: /a\nAllow: /a\n");
    assert.equal(isAllowed(tie, "bot", "/a"), true, "allow wins a tie");
    assert.equal(isAllowed(parseRobots(""), "bot", "/"), true, "no file content, no restriction");
    assert.equal(isAllowed(parseRobots("User-agent: *\nDisallow: /\n"), "bot", "/"), false);
  });
});

async function setup(): Promise<{ db: Database; store: ScanStore; reverse: ReverseLookup }> {
  const db = await openDatabase(":memory:");
  assert.ok(db);
  return { db, store: new ScanStore(db, { retentionDays: 365 }), reverse: new ReverseLookup(db) };
}

function seed(db: Database, domains: string[]): void {
  const insert = db.prepare("INSERT INTO crawl_targets (domain, added_at, next_at) VALUES (?, 0, 0)");
  for (const d of domains) insert.run(d);
}

describe("ReverseLookup", () => {
  it("only answers from the crawl list, never from other customers' lookups", async () => {
    const { db, store, reverse } = await setup();
    seed(db, ["crawled.com"]);
    store.recordTech(tech("crawled.com", ["shopify"]), "crawl", 10);
    store.recordTech(tech("someones-prospect.com", ["shopify"]), "call", 20);
    const result = reverse.findDomains({ techId: "shopify" });
    assert.deepEqual(
      result.domains.map((d) => d.domain),
      ["crawled.com"]
    );
    assert.equal(result.total, 1);
    assert.deepEqual(reverse.universe(), { domains: 1, scanned: 1 });
    assert.equal(reverse.counts().get("shopify"), 1);
  });

  it("filters removed technologies and old sightings, and pages with a cursor", async () => {
    const { db, store, reverse } = await setup();
    const domains = ["a.com", "b.com", "c.com", "d.com", "e.com"];
    seed(db, domains);
    domains.forEach((d, i) => store.recordTech(tech(d, ["klaviyo"], { klaviyo: `1.${i}` }), "crawl", 1000 + i));
    // e.com drops Klaviyo (two clean misses).
    store.recordTech(tech("e.com", []), "crawl", 2000);
    store.recordTech(tech("e.com", []), "crawl", 3000);
    assert.equal(reverse.findDomains({ techId: "klaviyo" }).total, 4);
    assert.equal(reverse.findDomains({ techId: "klaviyo", activeOnly: false }).total, 5);
    assert.deepEqual(
      reverse.findDomains({ techId: "klaviyo", seenSince: 1002 }).domains.map((d) => d.domain),
      ["d.com", "c.com"]
    );
    const first = reverse.findDomains({ techId: "klaviyo", limit: 3 });
    assert.deepEqual(
      first.domains.map((d) => d.domain),
      ["d.com", "c.com", "b.com"],
      "most recently seen first"
    );
    assert.equal(first.domains[0]?.version, "1.3");
    assert.ok(first.nextCursor);
    const second = reverse.findDomains({ techId: "klaviyo", limit: 3, cursor: first.nextCursor });
    assert.deepEqual(
      second.domains.map((d) => d.domain),
      ["a.com"]
    );
    assert.equal(second.nextCursor, null);
    assert.throws(
      () => reverse.findDomains({ techId: "klaviyo", cursor: "garbage" }),
      (err: unknown) => err instanceof ToolError && err.code === "INVALID_ARGUMENT"
    );
  });
});

describe("technology names", () => {
  it("resolves ids, names and unique partial matches, and lists candidates when ambiguous", () => {
    assert.equal(resolveTechnology("shopify").id, "shopify");
    assert.equal(resolveTechnology("Klaviyo").id, "klaviyo");
    assert.equal(resolveTechnology("Google Tag Manager").id, "google-tag-manager");
    assert.equal(resolveTechnology("googletagmanager").id, "google-tag-manager", "punctuation and spacing are ignored");
    assert.throws(
      () => resolveTechnology("hubspot c"),
      (err: unknown) => err instanceof ToolError && err.code === "INVALID_ARGUMENT" && Array.isArray((err.details as { candidates?: unknown[] }).candidates)
    );
    assert.throws(
      () => resolveTechnology("definitely-not-a-real-tech"),
      (err: unknown) => err instanceof ToolError && /list_technologies/.test(err.message)
    );
  });

  it("lists technologies by crawl-list usage and filters by category", async () => {
    const { db, store, reverse } = await setup();
    seed(db, ["x.com", "y.com"]);
    store.recordTech(tech("x.com", ["shopify", "klaviyo"]), "crawl", 1);
    store.recordTech(tech("y.com", ["shopify"]), "crawl", 1);
    const ctx = { principal: { id: "p", plan: "pro" as const, label: "", source: "api-key" as const }, signal: new AbortController().signal, requestId: 1 };
    const listed = await listTechnologies({ limit: 3 }, reverse, ctx);
    assert.deepEqual(
      listed.technologies.slice(0, 2).map((t) => [t.id, t.domains]),
      [
        ["shopify", 2],
        ["klaviyo", 1]
      ]
    );
    const ecommerce = await listTechnologies({ category: "ecommerce", limit: 1000 }, reverse, ctx);
    assert.ok(ecommerce.technologies.every((t) => t.category === "ecommerce"));
    assert.ok(ecommerce.categories.includes("E-commerce Platform"));
  });
});

describe("Crawler", () => {
  async function harness(seeds: string, options: Partial<CrawlerOptions> = {}) {
    const dir = await mkdtemp(path.join(tmpdir(), "sdm-crawl-"));
    const seedFile = path.join(dir, "seeds.csv");
    await writeFile(seedFile, seeds, "utf8");
    const { db, store, reverse } = await setup();
    const clock = { now: 1_000_000 };
    const fetched: string[] = [];
    const robots = new Map<string, RobotsResult>();
    const failing = new Map<string, Error>();
    const crawler = new Crawler({
      db,
      clock: () => clock.now,
      robots: async (domain) => robots.get(domain) ?? { verdict: "allowed", status: 200, error: null },
      runner: async (domain) => {
        fetched.push(domain);
        const failure = failing.get(domain);
        if (failure) throw failure;
        store.recordTech(tech(domain, ["shopify"]), "crawl", clock.now);
        return "ok";
      },
      options: { seedFile, ratePerMinute: 60, refreshMs: 30 * DAY, retryMs: 60 * 60 * 1000, concurrency: 2, tickMs: 60_000, maxTargets: 100, checkTimeoutMs: 5000, ...options }
    });
    const cleanup = () => rm(dir, { recursive: true, force: true });
    return { db, crawler, reverse, clock, fetched, robots, failing, seedFile, cleanup };
  }

  it("syncs the seed file, crawls due targets once per refresh, and respects robots.txt", async () => {
    const h = await harness("website,company\nhttps://www.Alpha.com,A\nbeta.com\nnot a domain\n10.0.0.1\nalpha.com\ngamma.com\n");
    try {
      assert.deepEqual(await h.crawler.syncSeeds(true), { added: 3, removed: 0, total: 3, invalid: 2 });
      h.robots.set("gamma.com", { verdict: "disallowed", status: 200, error: null });
      await h.crawler.tick(h.clock.now);
      assert.deepEqual(h.fetched.sort(), ["alpha.com", "beta.com"], "gamma.com's robots.txt forbids the homepage");
      const stats = h.crawler.stats(h.clock.now);
      assert.equal(stats.targets, 3);
      assert.equal(stats.byStatus.ok, 2);
      assert.equal(stats.byStatus.robots_disallowed, 1);
      assert.equal(stats.due, 0);
      assert.equal(h.reverse.findDomains({ techId: "shopify" }).total, 2);
      await h.crawler.tick(h.clock.now + DAY);
      assert.equal(h.fetched.length, 2, "nothing is due again within the refresh period");
      await h.crawler.tick(h.clock.now + 31 * DAY);
      assert.equal(h.fetched.length, 4);
    } finally {
      await h.cleanup();
    }
  });

  it("drops targets removed from the seed file and caps the list", async () => {
    const h = await harness("a.com\nb.com\nc.com\n", { maxTargets: 2 });
    try {
      assert.equal((await h.crawler.syncSeeds(true))?.total, 2);
      await writeFile(h.seedFile, "c.com\n", "utf8");
      const later = new Date(Date.now() + 5000);
      await utimes(h.seedFile, later, later);
      assert.equal(await h.crawler.syncSeeds(), null, "a changed file waits one round to settle (it may be mid-rewrite)");
      assert.deepEqual(await h.crawler.syncSeeds(), { added: 1, removed: 2, total: 1, invalid: 0 });
      assert.equal(await h.crawler.syncSeeds(), null, "an unchanged file is not re-read");
    } finally {
      await h.cleanup();
    }
  });

  it("paces fetches to the configured rate", async () => {
    const h = await harness(Array.from({ length: 20 }, (_, i) => `site${i}.com`).join("\n"), { ratePerMinute: 4, tickMs: 15_000 });
    try {
      await h.crawler.syncSeeds(true);
      for (let i = 0; i < 4; i++) await h.crawler.tick(h.clock.now + i * 15_000);
      assert.equal(h.fetched.length, 4, "4 per minute across four 15-second ticks");
    } finally {
      await h.cleanup();
    }
  });

  it("backs off failures and treats an unreachable robots.txt as a disallow for now", async () => {
    const h = await harness("down.com\nshy.com\ngone.com\n");
    try {
      await h.crawler.syncSeeds(true);
      h.failing.set("down.com", new Error("socket hang up"));
      h.failing.set("gone.com", new ToolError("DOMAIN_NOT_FOUND", "NXDOMAIN"));
      h.robots.set("shy.com", { verdict: "unreachable", status: 503, error: "HTTP 503" });
      await h.crawler.tick(h.clock.now);
      assert.deepEqual(h.fetched.sort(), ["down.com", "gone.com"], "shy.com is not fetched while its robots.txt is unreachable");
      const rows = h.db.prepare("SELECT domain, last_status, failures, next_at FROM crawl_targets ORDER BY domain").all() as unknown as Array<{
        domain: string;
        last_status: string;
        failures: number;
        next_at: number;
      }>;
      const by = new Map(rows.map((r) => [r.domain, r]));
      assert.equal(by.get("down.com")?.last_status, "failed");
      assert.equal(by.get("down.com")?.next_at, h.clock.now + 60 * 60 * 1000, "first retry after retryMs");
      assert.equal(by.get("shy.com")?.last_status, "robots_unreachable");
      assert.equal(by.get("gone.com")?.last_status, "not_found");
      assert.equal(by.get("gone.com")?.next_at, h.clock.now + 30 * DAY, "a definitive answer waits a full refresh");
      h.clock.now += 60 * 60 * 1000;
      await h.crawler.tick(h.clock.now);
      const down = h.db.prepare("SELECT failures, next_at FROM crawl_targets WHERE domain = 'down.com'").get() as { failures: number; next_at: number };
      assert.equal(down.failures, 2);
      assert.equal(down.next_at, h.clock.now + 2 * 60 * 60 * 1000, "the retry delay doubles");
    } finally {
      await h.cleanup();
    }
  });
});
