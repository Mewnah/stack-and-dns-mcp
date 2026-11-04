import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { setLogLevel } from "../src/logger.js";
import { MIGRATIONS, migrate, openDatabase, type Database } from "../src/store/db.js";
import { componentTrust, ScanStore, type EmailScanInput, type TechScanInput } from "../src/store/scanStore.js";

setLogLevel("silent");

const DAY = 24 * 60 * 60 * 1000;
const LATEST_SCHEMA = Math.max(...MIGRATIONS.map((m) => m.version));

async function memoryStore(): Promise<{ db: Database; store: ScanStore }> {
  const db = await openDatabase(":memory:");
  assert.ok(db, "node:sqlite is available in the test runtime");
  return { db, store: new ScanStore(db, { retentionDays: 30 }) };
}

function tech(domain: string, ids: string[], options: { ok?: boolean; blocked?: boolean; truncated?: boolean; versions?: Record<string, string> } = {}): TechScanInput {
  return {
    domain,
    partial: false,
    fetch: { ok: options.ok ?? true, status: 200, finalHost: domain, truncated: options.truncated ?? false, error: null },
    blocked: { blocked: options.blocked ?? false, vendor: options.blocked ? "Cloudflare" : null, challengeType: null, reason: null },
    technologies: ids.map((id) => ({ id, name: id.toUpperCase(), category: "analytics", version: options.versions?.[id] ?? null, implied: false })),
    security: { score: 70, grade: "C" }
  } as unknown as TechScanInput;
}

interface EmailOptions {
  score?: number;
  mxProvider?: string | null;
  spfPolicy?: string;
  dmarcPolicy?: string | null;
  dkimFound?: string[];
  dkimChecked?: string[];
  /** Selectors whose lookup failed this time. */
  dkimErrored?: string[];
  mtaStsMode?: "enforce" | "testing" | "none" | null;
  /** How the MTA-STS policy fetch failed, or "skipped" when the caller turned the check off. */
  mtaSts?: "transient" | "definitive" | "skipped";
  risks?: Array<{ code: string; severity: string }>;
  /** The MX lookup itself failed. */
  mxDnsError?: boolean;
}

function email(domain: string, o: EmailOptions = {}): EmailScanInput {
  const found = o.dkimFound ?? ["google"];
  const checked = o.dkimChecked ?? ["google", "selector1", "k1"];
  const errored = new Set(o.dkimErrored ?? []);
  const mode = o.mtaStsMode ?? null;
  const policy =
    o.mtaSts === "skipped"
      ? { fetched: false, mode: null, error: "skipped", failure: null }
      : o.mtaSts
        ? { fetched: false, mode: null, error: o.mtaSts === "transient" ? "HTTP 503" : "HTTP 404", failure: o.mtaSts }
        : { fetched: mode !== null, mode, error: null, failure: null };
  return {
    domain,
    score: o.score ?? 90,
    grade: "A",
    mx: { found: true, nullMx: false, provider: o.mxProvider === undefined ? "Google Workspace" : o.mxProvider, dnsError: o.mxDnsError ? { code: "ESERVFAIL", message: "x" } : null },
    spf: { found: true, valid: true, allPolicy: o.spfPolicy ?? "fail" },
    dmarc: { found: o.dmarcPolicy !== null, effectivePolicy: o.dmarcPolicy === undefined ? "reject" : o.dmarcPolicy },
    dkim: {
      checkedSelectors: checked,
      selectors: checked.map((selector) => ({ selector, found: !errored.has(selector) && found.includes(selector), revoked: false, error: errored.has(selector) ? "ESERVFAIL" : null }))
    },
    mtaSts: { policy },
    risks: o.risks ?? []
  } as unknown as EmailScanInput;
}

describe("ScanStore technology tracking", () => {
  it("treats the first successful scan as a baseline and reports later additions", async () => {
    const { store } = await memoryStore();
    assert.deepEqual(store.recordTech(tech("www.Example.com", ["ga", "gtm"]), "call", 1000), [], "baseline reports nothing");
    const added = store.recordTech(tech("example.com", ["ga", "gtm", "klaviyo"], { versions: { klaviyo: "2.1" } }), "call", 2000);
    assert.deepEqual(
      added.map((c) => [c.change, c.subject, c.newValue]),
      [["tech_added", "klaviyo", "KLAVIYO 2.1"]]
    );
    const history = store.history("EXAMPLE.com");
    assert.equal(history.domain, "example.com", "www and case are normalized to one site key");
    assert.equal(history.technologies.filter((t) => t.active).length, 3);
    assert.equal(history.technologies.find((t) => t.id === "klaviyo")?.firstSeen, new Date(2000).toISOString());
  });

  it("reports a removal only after two consecutive clean misses", async () => {
    const { store } = await memoryStore();
    store.recordTech(tech("a.com", ["ga", "hotjar"]), "call", 1000);
    assert.deepEqual(store.recordTech(tech("a.com", ["ga"]), "call", 2000), [], "one miss is not a removal");
    assert.equal(store.history("a.com").technologies.find((t) => t.id === "hotjar")?.active, true);
    const removed = store.recordTech(tech("a.com", ["ga"]), "call", 3000);
    assert.deepEqual(
      removed.map((c) => [c.change, c.subject]),
      [["tech_removed", "hotjar"]]
    );
    const hotjar = store.history("a.com").technologies.find((t) => t.id === "hotjar");
    assert.equal(hotjar?.active, false);
    assert.equal(hotjar?.removedAt, new Date(3000).toISOString());
    const back = store.recordTech(tech("a.com", ["ga", "hotjar"]), "call", 4000);
    assert.deepEqual(
      back.map((c) => [c.change, c.subject]),
      [["tech_added", "hotjar"]],
      "a re-installed tool is reported again"
    );
  });

  it("a flapping tag seen every other scan is never reported removed", async () => {
    const { store } = await memoryStore();
    store.recordTech(tech("f.com", ["ga", "ab"]), "call", 1);
    const all = [
      ...store.recordTech(tech("f.com", ["ga"]), "call", 2),
      ...store.recordTech(tech("f.com", ["ga", "ab"]), "call", 3),
      ...store.recordTech(tech("f.com", ["ga"]), "call", 4),
      ...store.recordTech(tech("f.com", ["ga", "ab"]), "call", 5)
    ];
    assert.deepEqual(all, []);
  });

  it("ignores blocked and failed scans, and never removes on a truncated body", async () => {
    const { store } = await memoryStore();
    store.recordTech(tech("b.com", ["ga", "hubspot"]), "call", 1);
    assert.deepEqual(store.recordTech(tech("b.com", [], { blocked: true }), "call", 2), []);
    assert.deepEqual(store.recordTech(tech("b.com", [], { ok: false }), "call", 3), []);
    assert.deepEqual(store.recordTech(tech("b.com", ["ga"], { truncated: true }), "call", 4), []);
    assert.deepEqual(store.recordTech(tech("b.com", ["ga"], { truncated: true }), "call", 5), []);
    assert.ok(
      store.history("b.com").technologies.every((t) => t.active),
      "nothing was removed"
    );
    const scans = store.history("b.com").recentScans;
    assert.equal(scans.length, 5);
    assert.deepEqual(
      scans.map((s) => s.ok),
      [true, true, false, false, true],
      "blocked and failed scans are stored as not ok"
    );
  });

  it("a blocked first scan does not count as the baseline", async () => {
    const { store } = await memoryStore();
    store.recordTech(tech("c.com", [], { blocked: true }), "call", 1);
    assert.deepEqual(store.recordTech(tech("c.com", ["ga"]), "call", 2), [], "the first usable scan is the baseline");
  });
});

describe("ScanStore email tracking", () => {
  it("reports weakened policies with high severity and strengthened ones as info", async () => {
    const { store } = await memoryStore();
    assert.deepEqual(store.recordEmail(email("m.com"), "call", 1), []);
    const weakened = store.recordEmail(email("m.com", { dmarcPolicy: "none", spfPolicy: "softfail", mxProvider: "Microsoft 365" }), "call", 2);
    const byChange = new Map(weakened.map((c) => [c.change, c]));
    assert.equal(byChange.get("dmarc_policy")?.severity, "high");
    assert.equal(byChange.get("dmarc_policy")?.oldValue, "reject");
    assert.equal(byChange.get("dmarc_policy")?.newValue, "none");
    assert.equal(byChange.get("spf_policy")?.severity, "high");
    assert.equal(byChange.get("mx_provider")?.newValue, "Microsoft 365");
    const restored = store.recordEmail(email("m.com", { dmarcPolicy: "reject", mxProvider: "Microsoft 365" }), "call", 3);
    assert.equal(restored.find((c) => c.change === "dmarc_policy")?.severity, "info");
    const removed = store.recordEmail(email("m.com", { dmarcPolicy: null, mxProvider: "Microsoft 365" }), "call", 4);
    assert.equal(removed.find((c) => c.change === "dmarc_removed")?.severity, "high");
  });

  it("a failed lookup freezes only its own component", async () => {
    const { store } = await memoryStore();
    store.recordEmail(email("d.com"), "call", 1);
    // The DMARC lookup failed, but MX answered and really did move.
    const mixed = email("d.com", { dmarcPolicy: null, mxProvider: "Microsoft 365", score: 40, risks: [{ code: "DMARC_DNS_ERROR", severity: "medium" }] });
    const changes = store.recordEmail(mixed, "call", 2);
    assert.deepEqual(
      changes.map((c) => c.change),
      ["mx_provider"],
      "the MX move is reported, the unanswered DMARC and the score are not"
    );
    const posture = store.history("d.com").email;
    assert.equal(posture?.dmarcPolicy, "reject", "DMARC keeps its last known policy");
    assert.equal(posture?.mxProvider, "Microsoft 365");
    assert.equal(posture?.score, 90, "only a complete scan moves the score");
    assert.deepEqual(store.recordEmail(email("d.com", { mxProvider: "Microsoft 365" }), "call", 3), [], "the next clean scan sees no change");
  });

  it("an MX lookup failure is not an MX removal", async () => {
    const { store } = await memoryStore();
    store.recordEmail(email("x.com"), "call", 1);
    const failed = { ...email("x.com", { mxDnsError: true }), mx: { found: false, nullMx: false, provider: null, dnsError: { code: "ETIMEOUT", message: "x" } } } as unknown as EmailScanInput;
    assert.deepEqual(store.recordEmail(failed, "call", 2), []);
    assert.equal(store.history("x.com").email?.mxFound, true);
    assert.equal(store.history("x.com").email?.mxProvider, "Google Workspace");
  });

  it("an SPF lookup failure neither weakens the policy nor resolves its risks", async () => {
    const { store } = await memoryStore();
    store.recordEmail(email("s.com", { spfPolicy: "pass", risks: [{ code: "SPF_PASS_ALL", severity: "critical" }] }), "call", 1);
    const failed = email("s.com", {
      spfPolicy: "none",
      risks: [
        { code: "SPF_DNS_ERROR", severity: "medium" },
        { code: "SPF_MISSING", severity: "high" }
      ]
    });
    assert.deepEqual(store.recordEmail(failed, "call", 2), []);
    const posture = store.history("s.com").email;
    assert.equal(posture?.spfPolicy, "pass");
    assert.deepEqual(posture?.highRisks, ["SPF_PASS_ALL"], "the old risk stands and the error-induced SPF_MISSING is not recorded");
    const fixed = store.recordEmail(email("s.com", { spfPolicy: "fail" }), "call", 3);
    assert.deepEqual(fixed.map((c) => [c.change, c.subject]).sort(), [
      ["risk_resolved", "SPF_PASS_ALL"],
      ["spf_policy", "spf"]
    ]);
  });

  it("a selector whose lookup errored is not a miss", async () => {
    const { store } = await memoryStore();
    store.recordEmail(email("e.com", { dkimFound: ["google", "k1"] }), "call", 1);
    for (let at = 2; at <= 4; at++) {
      assert.deepEqual(store.recordEmail(email("e.com", { dkimFound: ["google"], dkimErrored: ["k1"] }), "call", at), []);
    }
    assert.deepEqual(store.history("e.com").email?.dkimSelectors, ["google", "k1"]);
  });

  it("a selector that errored in the baseline is not reported added once it answers", async () => {
    const { store } = await memoryStore();
    store.recordEmail(email("g.com", { dkimFound: ["google"], dkimErrored: ["k1"] }), "call", 1);
    assert.deepEqual(store.recordEmail(email("g.com", { dkimFound: ["google", "k1"] }), "call", 2), [], "k1 was there all along");
    const added = store.recordEmail(email("g.com", { dkimFound: ["google", "k1", "selector1"] }), "call", 3);
    assert.deepEqual(
      added.map((c) => [c.change, c.subject]),
      [["dkim_added", "selector1"]],
      "later additions are reported"
    );
  });

  it("an unanswered component in the baseline is established silently by the next clean scan", async () => {
    const { store } = await memoryStore();
    store.recordEmail(email("b.com", { dmarcPolicy: null, score: 50, risks: [{ code: "DMARC_DNS_ERROR", severity: "medium" }] }), "call", 1);
    assert.deepEqual(store.recordEmail(email("b.com", { dmarcPolicy: "none", score: 80 }), "call", 2), [], "no DMARC or score baseline existed to compare against");
    const stronger = store.recordEmail(email("b.com", { dmarcPolicy: "reject", score: 80 }), "call", 3);
    assert.deepEqual(
      stronger.map((c) => [c.change, c.severity]),
      [["dmarc_policy", "info"]]
    );
  });

  it("MTA-STS changes only on a definitive answer", async () => {
    const { store } = await memoryStore();
    store.recordEmail(email("t.com", { mtaStsMode: "enforce" }), "call", 1);
    assert.deepEqual(store.recordEmail(email("t.com", { mtaSts: "transient" }), "call", 2), [], "a 503 or timeout is not a removal");
    assert.deepEqual(store.recordEmail(email("t.com", { mtaSts: "skipped" }), "call", 3), [], "a skipped check is not a removal");
    assert.equal(store.history("t.com").email?.mtaStsMode, "enforce");
    const gone = store.recordEmail(email("t.com", { mtaSts: "definitive" }), "call", 4);
    assert.deepEqual(
      gone.map((c) => [c.change, c.oldValue, c.newValue, c.severity]),
      [["mta_sts_mode", "enforce", null, "medium"]]
    );
  });

  it("stores scans with errors as not ok and names the unanswered components", async () => {
    const { db, store } = await memoryStore();
    store.recordEmail(email("o.com"), "call", 1);
    store.recordEmail(email("o.com", { dkimErrored: ["k1"], mtaSts: "transient", risks: [{ code: "DKIM_DNS_ERROR", severity: "low" }] }), "call", 2);
    assert.deepEqual(
      store.history("o.com").recentScans.map((s) => s.ok),
      [false, true]
    );
    const latest = db.prepare("SELECT summary FROM scans WHERE domain = 'o.com' ORDER BY id DESC LIMIT 1").get() as { summary: string };
    const summary = JSON.parse(latest.summary) as { complete: boolean; untrusted: string[] };
    assert.equal(summary.complete, false);
    assert.deepEqual(summary.untrusted.sort(), ["dkim", "mtaSts"]);
  });

  it("componentTrust reads every error signal", () => {
    assert.equal(componentTrust(email("a.com")).complete, true);
    assert.equal(componentTrust(email("a.com", { mxDnsError: true })).mx, false);
    assert.equal(componentTrust(email("a.com", { risks: [{ code: "MX_DNS_ERROR", severity: "medium" }] })).mx, false);
    assert.equal(componentTrust(email("a.com", { risks: [{ code: "MTA_STS_DNS_ERROR", severity: "low" }] })).mtaSts, false);
    assert.equal(componentTrust(email("a.com", { mtaSts: "definitive" })).mtaSts, true, "a definitive policy failure is an answer");
    assert.deepEqual([...componentTrust(email("a.com", { dkimErrored: ["k1"] })).dkimErrored], ["k1"]);
    assert.equal(componentTrust(email("a.com", { risks: [{ code: "DKIM_DNS_ERROR", severity: "low" }] })).complete, false);
  });

  it("reports moving to a Null MX once, as high", async () => {
    const { store } = await memoryStore();
    store.recordEmail(email("n.com"), "call", 1);
    const nullMx = { ...email("n.com"), mx: { found: true, nullMx: true, provider: null, dnsError: null } } as unknown as EmailScanInput;
    const changes = store.recordEmail(nullMx, "call", 2);
    assert.deepEqual(
      changes.map((c) => [c.change, c.severity]),
      [["null_mx", "high"]]
    );
  });

  it("reports a lost DKIM selector only after two probed misses", async () => {
    const { store } = await memoryStore();
    store.recordEmail(email("k.com", { dkimFound: ["google", "k1"] }), "call", 1);
    assert.deepEqual(store.recordEmail(email("k.com", { dkimFound: ["google"] }), "call", 2), []);
    // A scan that did not probe k1 at all is not evidence either way.
    assert.deepEqual(store.recordEmail(email("k.com", { dkimFound: ["google"], dkimChecked: ["google"] }), "call", 3), []);
    const lost = store.recordEmail(email("k.com", { dkimFound: ["google"] }), "call", 4);
    assert.deepEqual(
      lost.map((c) => [c.change, c.subject, c.severity]),
      [["dkim_lost", "k1", "medium"]]
    );
    const added = store.recordEmail(email("k.com", { dkimFound: ["google", "selector1"] }), "call", 5);
    assert.deepEqual(
      added.map((c) => [c.change, c.subject]),
      [["dkim_added", "selector1"]]
    );
    assert.deepEqual(store.history("k.com").email?.dkimSelectors, ["google", "selector1"]);
  });

  it("a lost selector is high severity when no other selector is live", async () => {
    const { store } = await memoryStore();
    store.recordEmail(email("l.com", { dkimFound: ["google", "k1"] }), "call", 1);
    store.recordEmail(email("l.com", { dkimFound: [] }), "call", 2);
    const lost = store.recordEmail(email("l.com", { dkimFound: [] }), "call", 3);
    assert.deepEqual(lost.map((c) => [c.change, c.subject, c.severity]).sort(), [
      ["dkim_lost", "google", "high"],
      ["dkim_lost", "k1", "high"]
    ]);
  });

  it("treats selector names as plain keys", async () => {
    const { store } = await memoryStore();
    store.recordEmail(email("p.com", { dkimFound: ["google"], dkimChecked: ["google", "constructor", "__proto__"] }), "call", 1);
    const added = store.recordEmail(email("p.com", { dkimFound: ["google", "constructor", "__proto__"], dkimChecked: ["google", "constructor", "__proto__"] }), "call", 2);
    assert.deepEqual(added.map((c) => c.subject).sort(), ["__proto__", "constructor"]);
    assert.deepEqual(store.history("p.com").email?.dkimSelectors, ["__proto__", "constructor", "google"]);
  });

  it("reports new and resolved high risks and large score moves", async () => {
    const { store } = await memoryStore();
    store.recordEmail(email("r.com", { score: 90 }), "call", 1);
    const worse = store.recordEmail(
      email("r.com", {
        score: 70,
        risks: [
          { code: "SPF_PASS_ALL", severity: "critical" },
          { code: "MX_SINGLE", severity: "info" }
        ]
      }),
      "call",
      2
    );
    assert.deepEqual(
      worse.map((c) => [c.change, c.subject, c.severity]).sort(),
      [
        ["risk_new", "SPF_PASS_ALL", "critical"],
        ["score_drop", "score", "medium"]
      ].sort()
    );
    const better = store.recordEmail(email("r.com", { score: 90 }), "call", 3);
    assert.deepEqual(better.map((c) => c.change).sort(), ["risk_resolved", "score_rise"]);
  });

  it("reads email states stored before per-component tracking existed", async () => {
    const { db, store } = await memoryStore();
    store.recordEmail(email("legacy.com"), "call", 1);
    const row = db.prepare("SELECT email_state FROM domains WHERE domain = 'legacy.com'").get() as { email_state: string };
    const legacy = JSON.parse(row.email_state) as Record<string, unknown>;
    delete legacy.unknown;
    db.prepare("UPDATE domains SET email_state = ? WHERE domain = 'legacy.com'").run(JSON.stringify(legacy));
    const changes = store.recordEmail(email("legacy.com", { dmarcPolicy: "none" }), "call", 2);
    assert.deepEqual(
      changes.map((c) => c.change),
      ["dmarc_policy"]
    );
  });
});

describe("ScanStore history and retention", () => {
  it("returns an empty, unknown history for a domain never scanned", async () => {
    const { store } = await memoryStore();
    const history = store.history("never.example");
    assert.equal(history.known, false);
    assert.deepEqual(history.technologies, []);
    assert.equal(history.email, null);
  });

  it("orders changes newest first and honours the limit", async () => {
    const { store } = await memoryStore();
    store.recordTech(tech("h.com", ["a"]), "call", 1);
    store.recordTech(tech("h.com", ["a", "b"]), "call", 2);
    store.recordTech(tech("h.com", ["a", "b", "c"]), "call", 3);
    const history = store.history("h.com", 1);
    assert.deepEqual(
      history.changes.map((c) => c.subject),
      ["c"]
    );
    assert.equal(store.history("h.com").changes.length, 2);
  });

  it("prunes scans, changes and removed technologies past retention", async () => {
    const { store } = await memoryStore();
    const now = 100 * DAY;
    store.recordTech(tech("old.com", ["a", "b"]), "call", now - 60 * DAY);
    store.recordTech(tech("old.com", ["a"]), "call", now - 59 * DAY);
    store.recordTech(tech("old.com", ["a"]), "call", now - 58 * DAY);
    store.recordTech(tech("old.com", ["a"]), "call", now - DAY);
    const removed = store.prune(now);
    assert.equal(removed.scans, 3);
    assert.equal(removed.changes, 1);
    assert.equal(removed.technologies, 1);
    const history = store.history("old.com");
    assert.deepEqual(
      history.technologies.map((t) => t.id),
      ["a"],
      "active technologies are kept however old"
    );
    assert.equal(history.recentScans.length, 1);
  });
});

describe("database lifecycle", () => {
  it("migrates a file database once and reopens it without re-running migrations", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "sdm-db-"));
    const file = path.join(dir, "nested", "store.db");
    try {
      const first = await openDatabase(file);
      assert.ok(first);
      new ScanStore(first, { retentionDays: 30 }).recordTech(tech("persist.com", ["a"]), "call", 1);
      first.close();
      const second = await openDatabase(file);
      assert.ok(second);
      const version = second.prepare("SELECT value FROM meta WHERE key = 'schema_version'").get() as { value: string };
      assert.equal(version.value, String(LATEST_SCHEMA));
      assert.equal(migrate(second), LATEST_SCHEMA, "a second migrate is a no-op");
      assert.equal(new ScanStore(second, { retentionDays: 30 }).history("persist.com").known, true);
      second.close();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("skips a migration another connection applied after this one read the version", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "sdm-db-"));
    const file = path.join(dir, "race.db");
    try {
      const a = await openDatabase(file);
      assert.ok(a);
      const extra = { version: LATEST_SCHEMA + 1, description: "test", sql: "CREATE TABLE race_marker (x INTEGER)" };
      const b = await openDatabase(file);
      assert.ok(b);
      // b reads the old version, then connection a migrates in the window
      // before b takes its write lock; b must notice under the lock rather
      // than re-run the migration.
      const exec = b.exec.bind(b);
      let raced = false;
      b.exec = (sql: string): void => {
        if (sql === "BEGIN IMMEDIATE" && !raced) {
          raced = true;
          migrate(a, [...MIGRATIONS, extra]);
        }
        exec(sql);
      };
      assert.doesNotThrow(() => migrate(b, [...MIGRATIONS, extra]), "re-running CREATE TABLE would throw");
      assert.ok(raced, "the interleaving happened");
      a.close();
      b.close();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("several processes opening one fresh file all get storage", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "sdm-db-"));
    const file = path.join(dir, "shared.db");
    const srcDir = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "src");
    const dbModule = pathToFileURL(path.join(srcDir, "store", "db.ts")).href;
    const loggerModule = pathToFileURL(path.join(srcDir, "logger.ts")).href;
    // The logger only listens to setLogLevel (STACKDNS_LOG_LEVEL is applied by
    // index.ts, which this script never loads), so the child silences itself.
    // Each child's stderr is kept, so one that fails explains why.
    const script = [
      `const { setLogLevel } = await import(${JSON.stringify(loggerModule)}); setLogLevel("silent");`,
      `const { openDatabase } = await import(${JSON.stringify(dbModule)}); const db = await openDatabase(${JSON.stringify(file)}); process.stdout.write(db ? "ok" : "null"); db?.close();`
    ].join(" ");
    const run = (): Promise<{ out: string; err: string }> =>
      new Promise((resolve, reject) => {
        const child = spawn(process.execPath, ["--import", "tsx", "--input-type=module", "-e", script]);
        let out = "";
        let err = "";
        child.stdout.on("data", (chunk: Buffer) => (out += chunk.toString()));
        child.stderr.on("data", (chunk: Buffer) => (err += chunk.toString()));
        child.on("error", reject);
        child.on("close", () => resolve({ out: out.trim(), err: err.trim() }));
      });
    try {
      const results = await Promise.all([run(), run(), run(), run()]);
      assert.deepEqual(
        results.map((r) => r.out),
        ["ok", "ok", "ok", "ok"],
        results
          .filter((r) => r.out !== "ok")
          .map((r) => r.err)
          .join("\n---\n")
      );
      // The child that migrates logs "database migrated" at info unless the override takes effect.
      assert.ok(
        results.every((r) => !r.err.includes('"level":')),
        `the children are silenced (got ${JSON.stringify(results.map((r) => r.err))})`
      );
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("ScanStore email trust across failures and probes", () => {
  const HOUR = 60 * 60 * 1000;

  it("an MX host lookup failure is not an MX change", async () => {
    const { store } = await memoryStore();
    store.recordEmail(email("h.com"), "call", 1);
    const failed = email("h.com", { score: 72, risks: [{ code: "MX_HOST_DNS_ERROR", severity: "medium" }] });
    assert.deepEqual(store.recordEmail(failed, "call", 2), []);
    assert.equal(store.history("h.com").email?.score, 90);
  });

  it("a failed include keeps the domain's own SPF policy comparable but holds validity and the score", async () => {
    const { store } = await memoryStore();
    store.recordEmail(email("i.com", { spfPolicy: "fail" }), "call", 1);
    const weakened = email("i.com", {
      spfPolicy: "pass",
      score: 40,
      risks: [
        { code: "SPF_INCLUDE_DNS_ERROR", severity: "medium" },
        { code: "SPF_PASS_ALL", severity: "critical" }
      ]
    });
    const changes = store.recordEmail(weakened, "call", 2);
    assert.deepEqual(changes.map((c) => c.change).sort(), ["risk_new", "spf_policy"], "the +all is reported; no score_drop from an incomplete scan");
    assert.equal(store.history("i.com").email?.score, 90);
  });

  it("TLS-RPT or BIMI lookup failures hold the score", async () => {
    const { store } = await memoryStore();
    store.recordEmail(email("t.com", { score: 95 }), "call", 1);
    assert.deepEqual(store.recordEmail(email("t.com", { score: 80, risks: [{ code: "TLS_RPT_DNS_ERROR", severity: "info" }] }), "call", 2), []);
  });

  it("never stores lookup-error codes as risks, even in a baseline", async () => {
    const { store } = await memoryStore();
    store.recordEmail(email("b.com", { mxDnsError: true, risks: [{ code: "MX_DNS_ERROR", severity: "high" }] }), "call", 1);
    const snapshot = store.history("b.com").email;
    assert.deepEqual(snapshot?.highRisks, []);
    assert.deepEqual(snapshot?.unverified, ["mx", "mxHosts", "score"]);
    assert.equal(snapshot?.score, null, "no complete scan yet");
  });

  it("marks components whose latest lookups failed", async () => {
    const { store } = await memoryStore();
    store.recordEmail(email("f.com"), "call", 1);
    store.recordEmail(email("f.com", { risks: [{ code: "DMARC_DNS_ERROR", severity: "medium" }] }), "call", 2);
    assert.deepEqual(store.history("f.com").email?.lookupsFailing, ["dmarc"]);
    store.recordEmail(email("f.com"), "call", 3);
    assert.deepEqual(store.history("f.com").email?.lookupsFailing, []);
  });

  it("accepts a failure that persists for three scans over a day", async () => {
    const { store } = await memoryStore();
    store.recordEmail(email("p.com", { mtaStsMode: "enforce", score: 90 }), "monitor", 0);
    const down = (at: number) => store.recordEmail(email("p.com", { mtaSts: "transient", score: 85 }), "monitor", at);
    assert.deepEqual(down(1 * HOUR), []);
    assert.deepEqual(down(2 * HOUR), [], "three scans, but not yet a day");
    assert.deepEqual(down(12 * HOUR), []);
    const accepted = down(25 * HOUR);
    assert.deepEqual(
      accepted.map((c) => [c.change, c.oldValue, c.newValue]),
      [["mta_sts_mode", "enforce", null]]
    );
    assert.equal(store.history("p.com").email?.score, 85, "the score moves again");
    assert.deepEqual(down(26 * HOUR), [], "and it is not reported twice");
  });

  it("a skipped MTA-STS check never counts toward a failure streak", async () => {
    const { store } = await memoryStore();
    store.recordEmail(email("s.com", { mtaStsMode: "enforce" }), "call", 0);
    for (let i = 1; i <= 5; i++) assert.deepEqual(store.recordEmail(email("s.com", { mtaSts: "skipped" }), "call", i * 12 * HOUR), []);
    assert.equal(store.history("s.com").email?.mtaStsMode, "enforce");
  });

  it("an errored selector with no known key does not hold DKIM or the score", async () => {
    const { store } = await memoryStore();
    store.recordEmail(email("k.com", { score: 90, dkimFound: ["google"] }), "call", 1);
    const weak = email("k.com", {
      score: 70,
      dkimFound: ["google"],
      dkimErrored: ["k1"],
      risks: [
        { code: "DKIM_DNS_ERROR", severity: "low" },
        { code: "DKIM_KEY_TOO_SHORT", severity: "high" }
      ]
    });
    const changes = store.recordEmail(weak, "call", 2);
    assert.deepEqual(changes.map((c) => c.change).sort(), ["risk_new", "score_drop"]);
  });

  it("an errored selector that holds a known key does hold DKIM", async () => {
    const { store } = await memoryStore();
    store.recordEmail(email("q.com", { dkimFound: ["google", "k1"] }), "call", 1);
    const changes = store.recordEmail(email("q.com", { dkimFound: ["google"], dkimErrored: ["k1"], score: 70, risks: [{ code: "DKIM_KEY_TOO_SHORT", severity: "high" }] }), "call", 2);
    assert.deepEqual(changes, []);
  });

  it("a custom selector seen by a call and not by bulk scans never flips alerts", async () => {
    const { store } = await memoryStore();
    const bulk = () => email("c.com", { score: 76, dkimFound: [], dkimChecked: ["google", "selector1", "k1"] });
    const call = () => email("c.com", { score: 90, dkimFound: ["acme"], dkimChecked: ["google", "selector1", "k1", "acme"] });
    store.recordEmail(bulk(), "bulk", 1);
    assert.deepEqual(store.recordEmail(call(), "call", 2), [], "acme was never probed before: not an addition, and not a score rise");
    assert.deepEqual(store.recordEmail(bulk(), "bulk", 3), [], "a scan that did not probe acme is not a score drop");
    assert.deepEqual(store.recordEmail(call(), "call", 4), []);
    assert.deepEqual(store.knownDkimSelectors("c.com"), ["acme"], "scheduled scans will probe it from now on");
  });

  it("still reports a selector newly published under a probed name", async () => {
    const { store } = await memoryStore();
    store.recordEmail(email("n.com", { dkimFound: ["google"] }), "call", 1);
    const added = store.recordEmail(email("n.com", { dkimFound: ["google", "k1"] }), "call", 2);
    assert.deepEqual(
      added.map((c) => [c.change, c.subject]),
      [["dkim_added", "k1"]]
    );
  });

  it("ranks MTA-STS downgrades as medium and upgrades as info", async () => {
    const { store } = await memoryStore();
    store.recordEmail(email("m.com", { mtaStsMode: "enforce" }), "call", 1);
    assert.deepEqual(
      store.recordEmail(email("m.com", { mtaStsMode: "testing" }), "call", 2).map((c) => c.severity),
      ["medium"]
    );
    assert.deepEqual(
      store.recordEmail(email("m.com", { mtaStsMode: "enforce" }), "call", 3).map((c) => c.severity),
      ["info"]
    );
  });
});
