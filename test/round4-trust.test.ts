/**
 * Round-4 regression tests for the trust analyzers:
 *   G1 - failure kinds name the lookup that failed (SPF apex vs redirect=
 *        target, DMARC own lookup vs organizational fallback), so one timeout
 *        of a different lookup never extends an accepted streak.
 *   G2 - accepted lame exchanges (MX_ALL_UNRESOLVABLE) also move the stored
 *        score, like the same posture with exchanges that do not resolve.
 *   G3 - a failed redirect= target leaves the SPF policy unknown in the
 *        status labels, bulk summaries and score notes, never "none".
 *   Round 5:
 *   G2 - any accepted lame exchange (a lame backup next to a working MX
 *        too) is scored as dangling, with or without a score breakdown.
 *   G3 - a subdomain whose own _dmarc lookup failed is never credited with
 *        the organizational policy: labels, bulk summaries, the audit
 *        highlight, the score and the stored posture all say "unknown".
 *   Round 6:
 *   G3 - nor are the organizational record's DMARC findings taken as the
 *        subdomain's: the store keeps its last known DMARC risks, and the
 *        bulk item lists none of the fallback record's.
 *
 * Every scan goes through the real analyzers (verifyEmailInfrastructure)
 * against a scripted in-memory DnsClient; nothing touches the network.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { loadConfig } from "../src/config.js";
import { evaluateDmarc } from "../src/lib/dmarc.js";
import type { DnsClient, DnsErrorInfo, MxRecord } from "../src/lib/dns.js";
import { scoreEmail, type EmailScoreInput } from "../src/lib/scoring.js";
import { setLogLevel } from "../src/logger.js";
import type { ToolContext } from "../src/middleware/metering.js";
import { openDatabase } from "../src/store/db.js";
import { ScanStore, type DomainChange, type EmailScanInput } from "../src/store/scanStore.js";
import { summarizeEmail } from "../src/tools/bulk.js";
import { emailHighlight, topRisksHighlight } from "../src/tools/comprehensiveAudit.js";
import { describeEmailStatus, emailLookupFailures, verifyEmailInfrastructure, type EmailResult } from "../src/tools/verifyEmailInfrastructure.js";

setLogLevel("silent");

const HOUR = 60 * 60 * 1000;
const TIMEOUT: DnsErrorInfo = { code: "ETIMEOUT", message: "timeout" };
const PUBLIC_IP = "142.250.150.26";

/**
 * A scripted DNS view. TXT and MX answers come from the maps, names listed
 * in failTxt / failAddresses time out, and every other name is NXDOMAIN.
 */
interface Zones {
  txt: Record<string, string[]>;
  mx: Record<string, Array<{ exchange: string; priority: number }>>;
  /** Exchange (or host) addresses; a missing host is NXDOMAIN. */
  addresses: Record<string, string[]>;
  failTxt?: string[];
  failAddresses?: string[];
}

function fakeDns(zones: Zones): DnsClient {
  const failTxt = new Set((zones.failTxt ?? []).map((n) => n.toLowerCase()));
  const failAddresses = new Set((zones.failAddresses ?? []).map((n) => n.toLowerCase()));
  const nx = { records: [], nxdomain: true, error: null, durationMs: 1 };
  const hostAnswer = async (name: string) => {
    const key = name.toLowerCase();
    if (failAddresses.has(key)) return { records: [], nxdomain: false, error: TIMEOUT, durationMs: 1 };
    const records = zones.addresses[key];
    return records ? { records, nxdomain: false, error: null, durationMs: 1 } : nx;
  };
  return {
    exists: async () => ({ exists: true, nxdomain: false, error: null }),
    txt: async (name: string) => {
      const key = name.toLowerCase();
      if (failTxt.has(key)) return { records: [], nxdomain: false, error: TIMEOUT, durationMs: 1 };
      const records = zones.txt[key];
      return records ? { records, nxdomain: false, error: null, durationMs: 1 } : nx;
    },
    mx: async (name: string) => {
      const records = zones.mx[name.toLowerCase()];
      return records ? { records: records as MxRecord[], nxdomain: false, error: null, durationMs: 1 } : nx;
    },
    cname: async () => nx,
    a: hostAnswer,
    aaaa: async (name: string) => {
      const key = name.toLowerCase();
      if (failAddresses.has(key)) return { records: [], nxdomain: false, error: TIMEOUT, durationMs: 1 };
      return zones.addresses[key] ? { records: [], nxdomain: false, error: null, durationMs: 1 } : nx;
    },
    addresses: async (name: string) => {
      const key = name.toLowerCase();
      if (failAddresses.has(key)) return { v4: [], v6: [], errors: [TIMEOUT, TIMEOUT] };
      return { v4: zones.addresses[key] ?? [], v6: [], errors: [] };
    }
  } as unknown as DnsClient;
}

const ctx: ToolContext = { principal: { id: "p", plan: "local", label: "", source: "local" }, signal: new AbortController().signal, requestId: "round4" };
const config = loadConfig({}, []);

/** One full email scan through the real analyzers, MTA-STS included. */
function scan(domain: string, zones: Zones): Promise<EmailResult> {
  return verifyEmailInfrastructure({ domain, dkimSelectors: [], checkMtaSts: true }, { config, dns: fakeDns(zones) }, ctx);
}

async function memoryStore(): Promise<ScanStore> {
  const db = await openDatabase(":memory:");
  assert.ok(db);
  return new ScanStore(db, { retentionDays: 30 });
}

const kinds = (changes: DomainChange[]): string[][] => changes.map((c) => [c.change, c.subject ?? "", c.severity]);

/** A domain whose mail is otherwise healthy: one resolving MX, DMARC p=reject with reporting. */
function healthy(domain: string, spf: string, extra: Partial<Zones> = {}): Zones {
  return {
    txt: {
      [domain]: [spf],
      [`_dmarc.${domain}`]: [`v=DMARC1; p=reject; rua=mailto:dmarc@${domain}`],
      ...(extra.txt ?? {})
    },
    mx: { [domain]: [{ exchange: "aspmx.l.google.com", priority: 1 }], ...(extra.mx ?? {}) },
    addresses: { "aspmx.l.google.com": [PUBLIC_IP], ...(extra.addresses ?? {}) },
    ...(extra.failTxt ? { failTxt: extra.failTxt } : {}),
    ...(extra.failAddresses ? { failAddresses: extra.failAddresses } : {})
  };
}

// ---------------------------------------------------------------------------
// G1
// ---------------------------------------------------------------------------

describe("G1: an accepted failure streak only grows while the same lookup keeps failing", () => {
  it("an accepted lame redirect= target plus one apex TXT timeout records nothing, and the next lame scan records nothing", async () => {
    const store = await memoryStore();
    const domain = "redirected-spf.com";
    const target = "_spf.vendor.net";
    const zones = healthy(domain, `v=spf1 redirect=${target}`, { txt: { [target]: ["v=spf1 ip4:203.0.113.0/24 ~all"] } });
    const lame: Zones = { ...zones, failTxt: [target] };
    const apexDown: Zones = { ...zones, failTxt: [domain] };

    const baseline = await scan(domain, zones);
    assert.equal(baseline.spf.allPolicy, "softfail");
    store.recordEmail(baseline, "monitor", 0);

    // The vendor's zone goes lame: the redirect target times out on every scan.
    const lameScan = await scan(domain, lame);
    assert.ok(
      lameScan.risks.some((r) => r.code === "SPF_DNS_ERROR"),
      "a failed redirect target is reported as SPF_DNS_ERROR"
    );
    assert.equal(lameScan.spf.found, true);
    assert.deepEqual(store.recordEmail(lameScan, "monitor", 1 * HOUR), []);
    assert.deepEqual(store.recordEmail(await scan(domain, lame), "monitor", 12 * HOUR), []);
    const accepted = store.recordEmail(await scan(domain, lame), "monitor", 25 * HOUR);
    assert.ok(
      kinds(accepted).some(([change, , severity]) => change === "spf_policy" && severity === "high"),
      `after 3 scans over 24h the lame target is taken at its word (got ${JSON.stringify(kinds(accepted))})`
    );

    // One timeout of the domain's own TXT lookup is a different failure: it
    // starts a new streak and is held, not read as SPF removed.
    const apexScan = await scan(domain, apexDown);
    assert.equal(apexScan.spf.found, false);
    assert.ok(apexScan.risks.some((r) => r.code === "SPF_DNS_ERROR"));
    const afterApex = store.recordEmail(apexScan, "monitor", 26 * HOUR);
    assert.deepEqual(kinds(afterApex), [], "a single apex timeout must not extend the redirect streak (no spf_removed)");

    // The lame target again: the apex streak replaced it, so this is a new streak too.
    const again = store.recordEmail(await scan(domain, lame), "monitor", 27 * HOUR);
    assert.deepEqual(kinds(again), [], "the next lame scan starts over instead of flipping SPF back");

    const snapshot = store.history(domain).email;
    assert.ok(snapshot);
    assert.equal(snapshot.spfFound, true, "SPF is still known to exist");
    // Round 8: the accepted reading of the lame target is an unknown policy, not "none".
    assert.equal(snapshot.spfPolicy, "unknown", "the accepted reading of the lame target is kept");
    assert.ok(snapshot.lookupsFailing.includes("spf"));
  });

  it("a single apex timeout cannot finish off an accepted redirect streak even many scans later", async () => {
    const store = await memoryStore();
    const domain = "redirect-many.com";
    const target = "_spf.vendor.net";
    const zones = healthy(domain, `v=spf1 redirect=${target}`, { txt: { [target]: ["v=spf1 ip4:203.0.113.0/24 -all"] } });
    const lame: Zones = { ...zones, failTxt: [target] };
    store.recordEmail(await scan(domain, zones), "monitor", 0);
    for (const at of [1, 12, 25, 30, 40, 50]) store.recordEmail(await scan(domain, lame), "monitor", at * HOUR);
    const apex = store.recordEmail(await scan(domain, { ...zones, failTxt: [domain] }), "monitor", 51 * HOUR);
    assert.ok(!apex.some((c) => c.change === "spf_removed"), `no spf_removed from one apex timeout (got ${JSON.stringify(kinds(apex))})`);
    assert.deepEqual(kinds(apex), []);
    assert.equal(store.history(domain).email?.spfFound, true);
  });

  it("on a subdomain, an accepted failing own _dmarc plus one timeout of the organizational _dmarc records nothing, and the next scan records nothing", async () => {
    const store = await memoryStore();
    const org = "orgfallback.com";
    const domain = `news.${org}`;
    const zones = healthy(domain, "v=spf1 -all", {
      txt: {
        [`_dmarc.${domain}`]: [`v=DMARC1; p=quarantine; rua=mailto:dmarc@${org}`],
        [`_dmarc.${org}`]: [`v=DMARC1; p=reject; rua=mailto:dmarc@${org}`]
      }
    });
    const ownDown: Zones = { ...zones, failTxt: [`_dmarc.${domain}`] };
    const bothDown: Zones = { ...zones, failTxt: [`_dmarc.${domain}`, `_dmarc.${org}`] };

    const baseline = await scan(domain, zones);
    assert.equal(baseline.organizationalDomain, org);
    assert.equal(baseline.dmarc.effectivePolicy, "quarantine");
    store.recordEmail(baseline, "monitor", 0);

    // The subdomain's own _dmarc lookup keeps timing out; the org fallback answers p=reject.
    const ownScan = await scan(domain, ownDown);
    assert.equal(ownScan.dmarc.found, true);
    assert.equal(ownScan.dmarc.inheritedFromOrganizationalDomain, true);
    assert.ok(ownScan.risks.some((r) => r.code === "DMARC_DNS_ERROR"));
    assert.deepEqual(store.recordEmail(ownScan, "monitor", 1 * HOUR), []);
    assert.deepEqual(store.recordEmail(await scan(domain, ownDown), "monitor", 12 * HOUR), []);
    const accepted = store.recordEmail(await scan(domain, ownDown), "monitor", 25 * HOUR);
    assert.ok(
      kinds(accepted).some(([change]) => change === "dmarc_policy"),
      `after 3 scans over 24h the fallback reading is accepted (got ${JSON.stringify(kinds(accepted))})`
    );

    // One timeout of the organizational lookup as well: a different failure, held.
    const both = await scan(domain, bothDown);
    assert.equal(both.dmarc.found, false);
    const afterBoth = store.recordEmail(both, "monitor", 26 * HOUR);
    assert.deepEqual(kinds(afterBoth), [], "one org _dmarc timeout must not extend the streak (no dmarc_removed)");

    // Back to the own-lookup failure: a new streak again, held.
    const again = store.recordEmail(await scan(domain, ownDown), "monitor", 27 * HOUR);
    assert.deepEqual(kinds(again), [], "the next scan starts over instead of reporting dmarc_added");

    const snapshot = store.history(domain).email;
    assert.ok(snapshot);
    assert.equal(snapshot.dmarcFound, true);
    // Round 5 (G3 for DMARC): the accepted reading of a failing own lookup
    // is an unknown subdomain policy, not the organizational p=reject.
    assert.equal(snapshot.dmarcPolicy, "unknown");
  });

  it("an accepted apex SPF failure is still held when a redirect target fails instead", async () => {
    // The mirror of the first case: the long-running failure is the domain's
    // own TXT lookup, and a different lookup (the redirect target) fails once.
    const store = await memoryStore();
    const domain = "apex-lame.com";
    const target = "_spf.vendor.net";
    const zones = healthy(domain, `v=spf1 redirect=${target}`, { txt: { [target]: ["v=spf1 ip4:203.0.113.0/24 -all"] } });
    store.recordEmail(await scan(domain, zones), "monitor", 0);
    for (const at of [1, 12]) assert.deepEqual(store.recordEmail(await scan(domain, { ...zones, failTxt: [domain] }), "monitor", at * HOUR), []);
    const accepted = store.recordEmail(await scan(domain, { ...zones, failTxt: [domain] }), "monitor", 25 * HOUR);
    assert.ok(
      kinds(accepted).some(([change]) => change === "spf_removed"),
      `the persistent apex failure is accepted (got ${JSON.stringify(kinds(accepted))})`
    );
    const redirectOnce = store.recordEmail(await scan(domain, { ...zones, failTxt: [target] }), "monitor", 26 * HOUR);
    assert.deepEqual(kinds(redirectOnce), [], "a redirect-target timeout is a different lookup and is held (no spf_added)");
    assert.equal(store.history(domain).email?.spfFound, false);
  });
});

// ---------------------------------------------------------------------------
// G2
// ---------------------------------------------------------------------------

describe("G2: accepted lame exchanges move the stored score", () => {
  it("accepting MX_ALL_UNRESOLVABLE records a score drop to what the same posture with non-resolving exchanges scores", async () => {
    const store = await memoryStore();
    const domain = "lame-exchange.com";
    const exchange = "mx.oldhost.net";
    const zones = healthy(domain, "v=spf1 -all", { mx: { [domain]: [{ exchange, priority: 10 }] }, addresses: { [exchange]: [PUBLIC_IP] } });
    const lame: Zones = { ...zones, failAddresses: [exchange] };
    const nxdomain: Zones = { ...zones, addresses: {} };

    const baseline = await scan(domain, zones);
    store.recordEmail(baseline, "monitor", 0);
    const lameScan = await scan(domain, lame);
    assert.equal(lameScan.score, baseline.score, "the analyzer scores exchanges it could not check as resolving");
    // The same posture with an exchange that answers NXDOMAIN.
    const dangling = await scan(domain, nxdomain);
    assert.ok(dangling.risks.some((r) => r.code === "MX_ALL_UNRESOLVABLE"));
    assert.ok(dangling.score <= baseline.score - 10, "precondition: an unresolvable MX set costs at least 10 points");

    assert.deepEqual(store.recordEmail(lameScan, "monitor", 1 * HOUR), []);
    assert.deepEqual(store.recordEmail(await scan(domain, lame), "monitor", 12 * HOUR), []);
    const accepted = store.recordEmail(await scan(domain, lame), "monitor", 25 * HOUR);
    assert.deepEqual(kinds(accepted), [
      ["risk_new", "MX_ALL_UNRESOLVABLE", "critical"],
      ["score_drop", "score", "medium"]
    ]);
    const drop = accepted.find((c) => c.change === "score_drop");
    assert.equal(drop?.oldValue, String(baseline.score));
    assert.equal(drop?.newValue, String(dangling.score));

    const snapshot = store.history(domain).email;
    assert.ok(snapshot);
    assert.equal(snapshot.score, dangling.score, "the stored score matches the unresolvable reading");
    assert.equal(snapshot.grade, dangling.grade);
    assert.ok(snapshot.highRisks.includes("MX_ALL_UNRESOLVABLE"));

    assert.deepEqual(store.recordEmail(await scan(domain, lame), "monitor", 26 * HOUR), [], "reported once");
    assert.equal(store.history(domain).email?.score, dangling.score, "later lame scans keep the accepted score");

    const recovered = store.recordEmail(await scan(domain, zones), "monitor", 27 * HOUR);
    assert.deepEqual(kinds(recovered), [
      ["risk_resolved", "MX_ALL_UNRESOLVABLE", "info"],
      ["score_rise", "score", "info"]
    ]);
    assert.equal(store.history(domain).email?.score, baseline.score);
    assert.equal(store.history(domain).email?.grade, baseline.grade);
  });

  it("a lame exchange next to a non-resolving one is accepted with the score of an all-unresolvable set", async () => {
    const store = await memoryStore();
    const domain = "mixed-exchanges.com";
    const lameHost = "mx1.oldhost.net";
    const deadHost = "mx2.oldhost.net";
    const zones = healthy(domain, "v=spf1 -all", {
      mx: {
        [domain]: [
          { exchange: lameHost, priority: 10 },
          { exchange: deadHost, priority: 20 }
        ]
      },
      addresses: { [lameHost]: [PUBLIC_IP], [deadHost]: [PUBLIC_IP] }
    });
    const mixed: Zones = { ...zones, addresses: { [lameHost]: [PUBLIC_IP] }, failAddresses: [lameHost] };
    const allDead: Zones = { ...zones, addresses: {} };

    const baseline = await scan(domain, zones);
    store.recordEmail(baseline, "monitor", 0);
    const reference = await scan(domain, allDead);
    assert.ok(reference.risks.some((r) => r.code === "MX_ALL_UNRESOLVABLE"));
    const mixedScan = await scan(domain, mixed);
    assert.ok(mixedScan.score > reference.score, "precondition: the analyzer gives the mixed set partial MX points");

    for (const at of [1, 12]) store.recordEmail(await scan(domain, mixed), "monitor", at * HOUR);
    const accepted = store.recordEmail(await scan(domain, mixed), "monitor", 25 * HOUR);
    assert.ok(kinds(accepted).some(([change, subject]) => change === "risk_new" && subject === "MX_ALL_UNRESOLVABLE"));
    assert.ok(kinds(accepted).some(([change]) => change === "score_drop"));
    assert.equal(store.history(domain).email?.score, reference.score);
    assert.equal(store.history(domain).email?.grade, reference.grade);
  });
});

// ---------------------------------------------------------------------------
// G3
// ---------------------------------------------------------------------------

function spfNote(result: EmailResult): { points: number; note: string } {
  const item = result.scoreBreakdown.find((b) => b.component === "spf");
  assert.ok(item);
  return { points: item.points, note: item.note };
}

describe("G3: a failed redirect= target leaves the SPF policy unknown, never 'none'", () => {
  const domain = "vendor-redirect.com";
  const target = "_spf.vendor.net";
  const zones = healthy(domain, `v=spf1 redirect=${target}`, { txt: { [target]: ["v=spf1 ip4:203.0.113.0/24 -all"] } });

  it("describes, summarizes and scores the policy as unknown when the redirect target times out", async () => {
    const result = await scan(domain, { ...zones, failTxt: [target] });
    assert.equal(result.spf.found, true);
    assert.equal(result.spf.allQualifier, null);
    assert.ok(result.risks.some((r) => r.code === "SPF_DNS_ERROR"));

    const status = describeEmailStatus(result);
    assert.equal(status.spf, "unknown (lookup failed)", "the audit highlight must not say 'SPF none'");
    assert.equal(summarizeEmail(result).spfPolicy, "unknown", "bulk email items must not store 'none'");
    const spf = spfNote(result);
    assert.notEqual(spf.note, "SPF has no terminal all mechanism.");
    assert.match(spf.note, /lookup failed/i);
    assert.equal(spf.points, 10, "the points are unchanged; only the explanation says the policy is unknown");
  });

  it("reports the real policy once the redirect target answers", async () => {
    const result = await scan(domain, zones);
    assert.equal(describeEmailStatus(result).spf, "fail");
    assert.equal(summarizeEmail(result).spfPolicy, "fail");
    assert.equal(spfNote(result).note, "SPF ends with -all.");
  });

  it("treats a failure at a later redirect hop the same way", async () => {
    const hop = "_spf2.vendor.net";
    const chained = healthy(domain, `v=spf1 redirect=${target}`, { txt: { [target]: [`v=spf1 redirect=${hop}`], [hop]: ["v=spf1 -all"] } });
    const answered = await scan(domain, chained);
    assert.equal(describeEmailStatus(answered).spf, "fail", "precondition: the chain resolves to -all");
    const failed = await scan(domain, { ...chained, failTxt: [hop] });
    assert.equal(describeEmailStatus(failed).spf, "unknown (lookup failed)");
    assert.equal(summarizeEmail(failed).spfPolicy, "unknown");
    assert.match(spfNote(failed).note, /lookup failed/i);
  });

  it("still reports a confirmed 'none' when no lookup the policy depends on failed", async () => {
    // A record without all or redirect=.
    const plain = await scan("no-all.com", healthy("no-all.com", "v=spf1 ip4:203.0.113.1"));
    assert.equal(describeEmailStatus(plain).spf, "none");
    assert.equal(summarizeEmail(plain).spfPolicy, "none");
    assert.equal(spfNote(plain).note, "SPF has no terminal all mechanism.");

    // A failed include next to a redirect target that answers without all:
    // the policy really is none, and only the include is unknown.
    const withInclude = await scan(
      "include-lame.com",
      healthy("include-lame.com", `v=spf1 include:lame-include.net redirect=${target}`, {
        txt: { [target]: ["v=spf1 ip4:203.0.113.0/24"] },
        failTxt: ["lame-include.net"]
      })
    );
    assert.ok(withInclude.risks.some((r) => r.code === "SPF_INCLUDE_DNS_ERROR"));
    assert.ok(!withInclude.risks.some((r) => r.code === "SPF_DNS_ERROR"));
    assert.equal(describeEmailStatus(withInclude).spf, "none");
    assert.equal(summarizeEmail(withInclude).spfPolicy, "none");
  });

  it("keeps a policy the record states itself when only an include fails", async () => {
    const result = await scan("own-all.com", healthy("own-all.com", "v=spf1 include:lame-include.net -all", { failTxt: ["lame-include.net"] }));
    assert.equal(describeEmailStatus(result).spf, "fail");
    assert.equal(summarizeEmail(result).spfPolicy, "fail");
  });

  it("still describes a failed apex lookup as unknown rather than missing", async () => {
    const result = await scan(domain, { ...zones, failTxt: [domain] });
    assert.equal(result.spf.found, false);
    assert.equal(describeEmailStatus(result).spf, "unknown (lookup failed)");
    assert.equal(summarizeEmail(result).spfPolicy, "unknown");
  });
});

// ---------------------------------------------------------------------------
// Round 5, G2: a lame exchange next to a working one
// ---------------------------------------------------------------------------

/** The scan as a caller that passes no scoreBreakdown records it. */
function withoutBreakdown(result: EmailResult): EmailScanInput {
  const input: EmailScanInput = { ...result };
  delete input.scoreBreakdown;
  return input;
}

/** Records a failing scan at 1h and 12h (both held) and at 25h, which accepts the persistent failure. */
async function recordUntilAccepted(store: ScanStore, next: () => Promise<EmailScanInput>): Promise<DomainChange[]> {
  for (const at of [1, 12]) assert.deepEqual(store.recordEmail(await next(), "monitor", at * HOUR), [], `a failure at ${at}h is held`);
  return store.recordEmail(await next(), "monitor", 25 * HOUR);
}

describe("Round 5 G2: an accepted lame exchange is scored as dangling, even next to a working one", () => {
  const primary = "mx1.mailhost.net";
  const backup = "mx2.oldhost.net";
  const twoExchanges = (domain: string): Zones =>
    healthy(domain, "v=spf1 -all", {
      mx: {
        [domain]: [
          { exchange: primary, priority: 10 },
          { exchange: backup, priority: 20 }
        ]
      },
      addresses: { [primary]: [PUBLIC_IP], [backup]: [PUBLIC_IP] }
    });

  it("a lame backup next to a working MX is stored with the score of the same posture with an NXDOMAIN backup", async () => {
    const store = await memoryStore();
    const domain = "lame-backup.com";
    const zones = twoExchanges(domain);
    const lame: Zones = { ...zones, failAddresses: [backup] };
    const nxBackup: Zones = { ...zones, addresses: { [primary]: [PUBLIC_IP] } };

    const baseline = await scan(domain, zones);
    const lameScan = await scan(domain, lame);
    const reference = await scan(domain, nxBackup);
    assert.equal(lameScan.score, baseline.score, "precondition: the analyzer gives the lame backup full MX points");
    assert.ok(
      reference.risks.some((r) => r.code === "MX_DANGLING"),
      "precondition: the NXDOMAIN backup is dangling"
    );
    assert.ok(reference.score < baseline.score, "precondition: a dangling backup costs MX points");

    store.recordEmail(baseline, "monitor", 0);
    const accepted = await recordUntilAccepted(store, () => scan(domain, lame));
    assert.ok(!kinds(accepted).some(([, subject]) => subject === "MX_ALL_UNRESOLVABLE"), "the primary still resolves");
    const snapshot = store.history(domain).email;
    assert.ok(snapshot);
    assert.equal(snapshot.score, reference.score, "the lame backup costs what an NXDOMAIN backup costs");
    assert.equal(snapshot.grade, reference.grade);
    assert.ok(snapshot.lookupsFailing.includes("mxHosts"));

    store.recordEmail(await scan(domain, lame), "monitor", 26 * HOUR);
    assert.equal(store.history(domain).email?.score, reference.score, "later lame scans keep the accepted score");
    store.recordEmail(await scan(domain, zones), "monitor", 27 * HOUR);
    assert.equal(store.history(domain).email?.score, baseline.score, "recovery restores the full MX points");
  });

  it("without a score breakdown, the points taken away follow the analyzer's rule, not a flat 20", async () => {
    // A lame backup next to a working MX: the analyzer awarded 20.
    const partialStore = await memoryStore();
    const partial = "lame-backup-nobreakdown.com";
    const partialZones = twoExchanges(partial);
    const partialReference = await scan(partial, { ...partialZones, addresses: { [primary]: [PUBLIC_IP] } });
    partialStore.recordEmail(withoutBreakdown(await scan(partial, partialZones)), "monitor", 0);
    await recordUntilAccepted(partialStore, async () => withoutBreakdown(await scan(partial, { ...partialZones, failAddresses: [backup] })));
    assert.equal(partialStore.history(partial).email?.score, partialReference.score);

    // A lame exchange next to an NXDOMAIN one: the analyzer awarded 14, not 20.
    const mixedStore = await memoryStore();
    const mixed = "mixed-nobreakdown.com";
    const mixedZones = twoExchanges(mixed);
    const allDead = await scan(mixed, { ...mixedZones, addresses: {} });
    assert.ok(
      allDead.risks.some((r) => r.code === "MX_ALL_UNRESOLVABLE"),
      "precondition: the all-NXDOMAIN reference"
    );
    mixedStore.recordEmail(withoutBreakdown(await scan(mixed, mixedZones)), "monitor", 0);
    const accepted = await recordUntilAccepted(mixedStore, async () => withoutBreakdown(await scan(mixed, { ...mixedZones, addresses: { [primary]: [PUBLIC_IP] }, failAddresses: [primary] })));
    assert.ok(kinds(accepted).some(([change, subject]) => change === "risk_new" && subject === "MX_ALL_UNRESOLVABLE"));
    assert.equal(mixedStore.history(mixed).email?.score, allDead.score);
    assert.equal(mixedStore.history(mixed).email?.grade, allDead.grade);
  });

  it("a disposable domain keeps its capped score instead of dropping to 0, with or without a breakdown", async () => {
    const domain = "mailinator.com";
    const exchange = "mx.oldhost.net";
    const zones = healthy(domain, "v=spf1 -all", { mx: { [domain]: [{ exchange, priority: 10 }] }, addresses: { [exchange]: [PUBLIC_IP] } });
    const baseline = await scan(domain, zones);
    assert.equal(baseline.disposable.disposable, true, "precondition: a listed disposable domain");
    assert.equal(baseline.score, 10, "precondition: the disposable cap");
    for (const strip of [true, false]) {
      const store = await memoryStore();
      const shape = (r: EmailResult): EmailScanInput => (strip ? withoutBreakdown(r) : r);
      store.recordEmail(shape(baseline), "monitor", 0);
      const accepted = await recordUntilAccepted(store, async () => shape(await scan(domain, { ...zones, failAddresses: [exchange] })));
      assert.ok(
        kinds(accepted).some(([, subject]) => subject === "MX_ALL_UNRESOLVABLE"),
        "precondition: the lame exchange is accepted"
      );
      assert.equal(store.history(domain).email?.score, 10, `the cap still decides the score (${strip ? "no breakdown" : "with breakdown"})`);
    }
  });
});

// ---------------------------------------------------------------------------
// Round 5, G3 for DMARC: a failed own _dmarc lookup on a subdomain
// ---------------------------------------------------------------------------

describe("Round 5 G3: a subdomain whose own _dmarc lookup failed is never credited with the organizational policy", () => {
  const org = "shopfallback.com";
  const sub = `shop.${org}`;
  const zones = healthy(sub, "v=spf1 -all", {
    txt: {
      [`_dmarc.${sub}`]: [`v=DMARC1; p=none; rua=mailto:dmarc@${org}`],
      [`_dmarc.${org}`]: [`v=DMARC1; p=reject; rua=mailto:dmarc@${org}`]
    }
  });
  const ownDown: Zones = { ...zones, failTxt: [`_dmarc.${sub}`] };
  // The subdomain publishes no record of its own and legitimately inherits p=reject.
  const noOwn: Zones = { ...zones, txt: Object.fromEntries(Object.entries(zones.txt).filter(([name]) => name !== `_dmarc.${sub}`)) };
  const notDmarc: Zones = { ...zones, txt: { ...zones.txt, [`_dmarc.${sub}`]: ["google-site-verification=abc"] } };

  function dmarcItem(result: EmailResult): { points: number; note: string } {
    const item = result.scoreBreakdown.find((b) => b.component === "dmarc");
    assert.ok(item);
    return { points: item.points, note: item.note };
  }

  it("evaluateDmarc tells an own-lookup failure from an absent own record", async () => {
    const failed = await evaluateDmarc(sub, org, fakeDns(ownDown));
    const inherited = await evaluateDmarc(sub, org, fakeDns(noOwn));
    for (const r of [failed, inherited]) {
      assert.equal(r.found, true);
      assert.equal(r.inheritedFromOrganizationalDomain, true);
      assert.equal(r.effectivePolicy, "reject");
    }
    const errors = failed.findings.filter((f) => f.code === "DMARC_DNS_ERROR");
    assert.equal(errors.length, 1);
    assert.match(errors[0]?.message ?? "", /_dmarc\.shop\.shopfallback\.com failed \(ETIMEOUT\); the organizational record at _dmarc\.shopfallback\.com was used/);
    assert.equal(inherited.findings.filter((f) => f.code === "DMARC_DNS_ERROR").length, 0, "an absent own record is not an error");
    const both = await evaluateDmarc(sub, org, fakeDns({ ...zones, failTxt: [`_dmarc.${sub}`, `_dmarc.${org}`] }));
    assert.equal(both.found, false, "both lookups failing stays the ordinary unknown case");
  });

  it("labels, summarizes, highlights and scores the policy as unknown when the own lookup times out", async () => {
    const answered = await scan(sub, zones);
    assert.equal(describeEmailStatus(answered).dmarc, "p=none", "precondition: the subdomain's own policy");
    const failed = await scan(sub, ownDown);
    assert.equal(failed.dmarc.found, true);
    assert.equal(failed.dmarc.inheritedFromOrganizationalDomain, true);
    assert.equal(failed.dmarc.effectivePolicy, "reject", "precondition: the analyzer evaluated the organizational record");
    assert.ok(failed.risks.some((r) => r.code === "DMARC_DNS_ERROR"));

    assert.equal(emailLookupFailures(failed).dmarcPolicy, true);
    assert.equal(emailLookupFailures(failed).dmarc, false, "the record was found; only its policy is unknown");
    assert.equal(describeEmailStatus(failed).dmarc, "unknown (lookup failed)");
    assert.equal(summarizeEmail(failed).dmarcPolicy, "unknown", "bulk email items must not store 'reject'");
    const highlight = emailHighlight(failed);
    assert.match(highlight, /DMARC unknown \(lookup failed\)/, "the audit highlight (kept in bulk audit items) must not say p=reject");
    assert.doesNotMatch(highlight, /p=reject/);

    const item = dmarcItem(failed);
    assert.ok(item.points <= dmarcItem(answered).points, `no more points than a confirmed p=none (got ${item.points})`);
    assert.match(item.note, /own _dmarc lookup failed/i);
    assert.match(item.note, /unknown/);
    assert.doesNotMatch(item.note, /p=reject/);
    assert.equal(failed.score, answered.score, "a timeout cannot raise the score above the subdomain's real p=none");
    assert.equal(failed.grade, answered.grade);
    // Round 8 (T-B): the summary says unknown too, like describeEmailStatus.
    assert.match(failed.summary, /DMARC unknown \(own _dmarc lookup failed; organizational p=reject\)/);
  });

  it("still credits a legitimately inherited policy when the subdomain has no record of its own", async () => {
    const views: Array<[string, Zones]> = [
      ["NXDOMAIN", noOwn],
      ["non-DMARC TXT only", notDmarc]
    ];
    for (const [label, view] of views) {
      const result = await scan(sub, view);
      assert.equal(result.dmarc.inheritedFromOrganizationalDomain, true, label);
      assert.ok(!result.risks.some((r) => r.code === "DMARC_DNS_ERROR"), label);
      assert.equal(emailLookupFailures(result).dmarcPolicy, false, label);
      assert.equal(describeEmailStatus(result).dmarc, "p=reject", label);
      assert.equal(summarizeEmail(result).dmarcPolicy, "reject", label);
      assert.match(emailHighlight(result), /DMARC p=reject/, label);
      assert.deepEqual(dmarcItem(result), { points: 28, note: "p=reject at 100%." }, label);
      assert.match(result.summary, /DMARC p=reject \(inherited\)/, label);

      const store = await memoryStore();
      store.recordEmail(result, "monitor", 0);
      assert.equal(store.history(sub).email?.dmarcPolicy, "reject", label);
    }
  });

  it("scoreEmail scores an unknown subdomain policy exactly as p=none, whatever the organizational record says", () => {
    const base: EmailScoreInput = {
      exists: true,
      disposable: false,
      mx: { found: true, nullMx: false, usesImplicitA: false, records: [{ resolvable: true }] },
      spf: { found: true, valid: true, records: ["v=spf1 -all"], allPolicy: "fail", lookupLimitExceeded: false, syntaxErrorCount: 0 },
      dkim: { found: false, selectors: [] },
      dmarc: { found: true, valid: true, effectivePolicy: "reject", pct: 100, ruaCount: 1 },
      mtaSts: { found: false, mode: null },
      tlsRpt: { found: false },
      bimi: { found: false }
    };
    const points = (dmarc: Partial<EmailScoreInput["dmarc"]>): number | undefined => scoreEmail({ ...base, dmarc: { ...base.dmarc, ...dmarc } }).breakdown.find((b) => b.component === "dmarc")?.points;
    const none = points({ effectivePolicy: "none" });
    assert.equal(none, 10);
    for (const effectivePolicy of ["reject", "quarantine", "none"] as const) assert.equal(points({ effectivePolicy, policyLookupFailed: true }), none, effectivePolicy);
    assert.equal(points({ effectivePolicy: "reject", pct: 50, policyLookupFailed: true }), none);
    assert.equal(points({ effectivePolicy: "reject", ruaCount: 0, policyLookupFailed: true }), none, "the organizational record’s reporting is not the subdomain’s");
    assert.equal(points({ valid: false, effectivePolicy: null, policyLookupFailed: true }), none, "nor is its validity");
    assert.equal(points({ valid: false, effectivePolicy: null }), 4, "a malformed own record keeps its lower points");
  });

  it("stores an unknown policy, never the organizational one, and a score that agrees", async () => {
    // First scan ever with the own lookup failing: tracked, unverified, and unknown.
    const fresh = await memoryStore();
    fresh.recordEmail(await scan(sub, ownDown), "monitor", 0);
    const first = fresh.history(sub).email;
    assert.ok(first);
    assert.equal(first.dmarcPolicy, "unknown");
    assert.ok(first.unverified.includes("dmarc"));

    // An established p=none: one failure is held, a persistent one is accepted as unknown.
    const store = await memoryStore();
    const answered = await scan(sub, zones);
    store.recordEmail(answered, "monitor", 0);
    assert.deepEqual(store.recordEmail(await scan(sub, ownDown), "monitor", 1 * HOUR), []);
    const held = store.history(sub).email;
    assert.equal(held?.dmarcPolicy, "none", "one failure keeps the last known policy");
    assert.ok(held?.lookupsFailing.includes("dmarc"));
    assert.deepEqual(store.recordEmail(await scan(sub, ownDown), "monitor", 12 * HOUR), []);
    const accepted = store.recordEmail(await scan(sub, ownDown), "monitor", 25 * HOUR);
    // Round 8: an unknown policy is scored like p=none, so none -> unknown is not a weakening (info, not high).
    assert.deepEqual(
      accepted.map((c) => [c.change, c.oldValue, c.newValue, c.severity]),
      [["dmarc_policy", "none", "unknown", "info"]],
      "the accepted reading is an unknown policy: no strengthening to reject and no score rise"
    );
    const snapshot = store.history(sub).email;
    assert.ok(snapshot);
    assert.equal(snapshot.dmarcFound, true);
    assert.equal(snapshot.dmarcPolicy, "unknown");
    assert.equal(snapshot.score, answered.score, "the stored score gives the fallback no more than p=none");

    const recovered = store.recordEmail(await scan(sub, zones), "monitor", 26 * HOUR);
    assert.deepEqual(
      recovered.map((c) => [c.change, c.oldValue, c.newValue]),
      [["dmarc_policy", "unknown", "none"]]
    );
  });
});

// ---------------------------------------------------------------------------
// Round 6, G3 for DMARC risks: the fallback record's findings on a subdomain
// ---------------------------------------------------------------------------

describe("Round 6 G3: while a subdomain's own _dmarc lookup fails, the organizational record's DMARC findings are not taken as its own", () => {
  const org = "riskfallback.com";
  const sub = `shop.${org}`;
  const clean = `v=DMARC1; p=reject; rua=mailto:dmarc@${org}`;
  const malformed = `v=DMARC1; p=rejct; rua=mailto:dmarc@${org}`;
  /** An otherwise healthy subdomain with the given own and organizational _dmarc records. */
  const zonesFor = (own: string[], orgRecords: string[], spf = "v=spf1 -all"): Zones => healthy(sub, spf, { txt: { [`_dmarc.${sub}`]: own, [`_dmarc.${org}`]: orgRecords } });
  const ownDown = (zones: Zones): Zones => ({ ...zones, failTxt: [`_dmarc.${sub}`] });
  const changes = (list: DomainChange[]): Array<Array<string | null>> => list.map((c) => [c.change, c.subject, c.oldValue, c.newValue]);

  it("an accepted own-lookup failure keeps the subdomain's own DMARC_MULTIPLE_RECORDS instead of reporting it resolved", async () => {
    const zones = zonesFor([clean, `v=DMARC1; p=none; rua=mailto:dmarc@${org}`], [clean]);
    const baseline = await scan(sub, zones);
    assert.ok(
      baseline.risks.some((r) => r.code === "DMARC_MULTIPLE_RECORDS" && r.severity === "critical"),
      "precondition: the subdomain publishes two records of its own"
    );
    const failed = await scan(sub, ownDown(zones));
    assert.equal(emailLookupFailures(failed).dmarcPolicy, true, "precondition: own lookup failed, organizational record used");
    assert.ok(!failed.risks.some((r) => r.code === "DMARC_MULTIPLE_RECORDS"), "precondition: the analyzer only saw the clean organizational record");

    const store = await memoryStore();
    store.recordEmail(baseline, "monitor", 0);
    const before = store.history(sub).email;
    assert.ok(before?.highRisks.includes("DMARC_MULTIPLE_RECORDS"));
    const accepted = await recordUntilAccepted(store, () => scan(sub, ownDown(zones)));
    // A lookup that stopped answering says nothing about whether the subdomain removed its duplicate record.
    assert.ok(!accepted.some((c) => c.change === "risk_resolved"), `no risk_resolved (got ${JSON.stringify(changes(accepted))})`);
    assert.deepEqual(changes(accepted), [["dmarc_policy", "dmarc", before?.dmarcPolicy ?? null, "unknown"]]);
    const snapshot = store.history(sub).email;
    assert.ok(snapshot);
    assert.equal(snapshot.dmarcPolicy, "unknown");
    assert.ok(snapshot.highRisks.includes("DMARC_MULTIPLE_RECORDS"), `the last known own risk is kept (got ${JSON.stringify(snapshot.highRisks)})`);

    // Still kept while the lookup keeps failing, and not reported as new once it answers again with the same two records.
    assert.deepEqual(changes(store.recordEmail(await scan(sub, ownDown(zones)), "monitor", 26 * HOUR)), []);
    const recovered = store.recordEmail(await scan(sub, zones), "monitor", 27 * HOUR);
    assert.ok(!recovered.some((c) => c.change === "risk_new" || c.change === "risk_resolved"), `the unchanged record is not a new problem (got ${JSON.stringify(changes(recovered))})`);
    assert.ok(store.history(sub).email?.highRisks.includes("DMARC_MULTIPLE_RECORDS"));
  });

  it("a malformed organizational record's DMARC_SYNTAX_ERROR is not reported new, stored or listed in the bulk item of a subdomain whose own record is clean", async () => {
    // SPF ?all gives the subdomain a high risk of its own, which must survive both filters.
    const zones = zonesFor([clean], [malformed], "v=spf1 ?all");
    const baseline = await scan(sub, zones);
    assert.deepEqual(summarizeEmail(baseline).highRisks, ["SPF_NEUTRAL_ALL"], "precondition: the subdomain's own DMARC record is clean");
    const failed = await scan(sub, ownDown(zones));
    assert.equal(emailLookupFailures(failed).dmarcPolicy, true, "precondition: own lookup failed, organizational record used");
    assert.ok(
      failed.risks.some((r) => r.code === "DMARC_SYNTAX_ERROR" && r.severity === "high"),
      "precondition: the analyzer evaluated the malformed organizational record"
    );

    // A single own-lookup timeout: the live bulk item says the policy is unknown, so it must not list the fallback record's risks either.
    const item = summarizeEmail(failed);
    assert.equal(item.dmarcPolicy, "unknown");
    assert.deepEqual(item.highRisks, ["SPF_NEUTRAL_ALL"], "the organizational record's DMARC risks are dropped and the subdomain's own risks are kept");

    const store = await memoryStore();
    store.recordEmail(baseline, "monitor", 0);
    const accepted = await recordUntilAccepted(store, () => scan(sub, ownDown(zones)));
    assert.ok(!accepted.some((c) => c.change === "risk_new"), `no risk_new (got ${JSON.stringify(changes(accepted))})`);
    assert.ok(
      accepted.some((c) => c.change === "dmarc_policy" && c.newValue === "unknown"),
      "the failure itself is still accepted"
    );
    const snapshot = store.history(sub).email;
    assert.ok(snapshot);
    assert.equal(snapshot.dmarcPolicy, "unknown");
    assert.deepEqual(snapshot.highRisks, ["SPF_NEUTRAL_ALL"], "DMARC_SYNTAX_ERROR belongs to the organizational record");
  });

  it("a subdomain with no record of its own still takes on the organizational record's DMARC risks", async () => {
    // The contrast: inheriting a malformed record is the subdomain's real posture, not a failed lookup.
    const result = await scan(sub, zonesFor([], [malformed]));
    assert.equal(result.dmarc.inheritedFromOrganizationalDomain, true);
    assert.equal(emailLookupFailures(result).dmarcPolicy, false);
    const listed = summarizeEmail(result).highRisks;
    assert.ok(Array.isArray(listed) && listed.includes("DMARC_SYNTAX_ERROR"), `the bulk item lists the inherited record's risk (got ${JSON.stringify(listed)})`);
    const store = await memoryStore();
    store.recordEmail(result, "monitor", 0);
    assert.ok(store.history(sub).email?.highRisks.includes("DMARC_SYNTAX_ERROR"));
  });
});

describe("Round 7 G3: the audit highlight and the stored score follow the same rule", () => {
  const org = "scorefallback.com";
  const sub = `shop.${org}`;
  const malformed = `v=DMARC1; p=rejct; rua=mailto:dmarc@${org}`;
  const zonesFor = (own: string[], orgRecords: string[], spf = "v=spf1 -all"): Zones => healthy(sub, spf, { txt: { [`_dmarc.${sub}`]: own, [`_dmarc.${org}`]: orgRecords } });
  const ownDown = (zones: Zones): Zones => ({ ...zones, failTxt: [`_dmarc.${sub}`] });

  it("comprehensive_audit's Top risks line leaves out the organizational record's DMARC findings when the own lookup failed", async () => {
    const zones = zonesFor([`v=DMARC1; p=reject; rua=mailto:dmarc@${org}`], [malformed], "v=spf1 ?all");
    const failed = await scan(sub, ownDown(zones));
    assert.ok(
      failed.risks.some((r) => r.code === "DMARC_SYNTAX_ERROR"),
      "precondition: the analyzer evaluated the malformed organizational record"
    );
    assert.equal(topRisksHighlight(failed.risks, failed), "Top risks: SPF_NEUTRAL_ALL.");
    // A subdomain with no record of its own inherits the malformed one: that is its real posture.
    const inherited = await scan(sub, zonesFor([], [malformed], "v=spf1 ?all"));
    assert.match(topRisksHighlight(inherited.risks, inherited) ?? "", /DMARC_SYNTAX_ERROR/);
    assert.equal(topRisksHighlight([], null), null);
  });

  it("an accepted own-lookup failure is scored as p=none whatever the organizational record is, so its defect raises no score_drop", async () => {
    const own = [`v=DMARC1; p=quarantine; pct=50; rua=mailto:dmarc@${org}`];
    for (const orgRecords of [[`v=DMARC1; p=reject; rua=mailto:dmarc@${org}`], [malformed], [`v=DMARC1; p=reject`]]) {
      const zones = zonesFor(own, orgRecords);
      const store = await memoryStore();
      store.recordEmail(await scan(sub, zones), "monitor", 0);
      const accepted = await recordUntilAccepted(store, () => scan(sub, ownDown(zones)));
      assert.deepEqual(
        accepted.map((c) => [c.change, c.oldValue, c.newValue]),
        [["dmarc_policy", "quarantine", "unknown"]],
        `organizational record ${orgRecords[0]}`
      );
      const points = (await scan(sub, ownDown(zones))).scoreBreakdown.find((b) => b.component === "dmarc")?.points;
      assert.equal(points, 10, `organizational record ${orgRecords[0]}`);
    }
  });
});
