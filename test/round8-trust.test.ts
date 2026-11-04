/**
 * Round-8 regression tests for the trust group:
 *   T-A - the one-line summaries (verify_email_infrastructure and
 *         comprehensive_audit) do not count the organizational record's DMARC
 *         findings when a subdomain's own _dmarc lookup failed.
 *   T-B - that summary says "DMARC unknown (own _dmarc lookup failed;
 *         organizational p=<x>)".
 *   T-C - a failed redirect= target reads "SPF policy unknown (redirect=<target>
 *         lookup failed)" in the summary.
 *   T-D - states stored by earlier code are re-baselined silently: the
 *         organizational policy and findings stored for an accepted own-lookup
 *         failure, and "none" stored for an accepted redirect= failure.
 *   T-E - a DMARC component only the fallback ever answered is established by
 *         its first own answer without change records.
 *   T-F - while the own _dmarc lookup fails, the stored score keeps the
 *         subdomain's last known DMARC points.
 *   The stored SPF policy reads 'unknown' behind a failed redirect= target,
 *   'unknown' ranks with none/p=none, and an SPF void-lookup or circular-include
 *   permerror costs points like the lookup-limit permerror.
 *   Round 9 (r9-trust-1..5): a basis-less state that already reads 'unknown'
 *   keeps its own DMARC findings; a score re-baseline waits for a scan that
 *   can rewrite the score; a move away from unknown is ranked against the
 *   policy last read; the SCORE_RULES re-baseline needs a permerror on both
 *   sides; SPF that only a failed redirect= target answered stays unverified
 *   until its first real answer, which is a baseline.
 *   Round 10: the SCORE_RULES decision is taken once, by the first
 *   post-upgrade scan, from the risks stored with the score (r10-trust-4); an
 *   accepted redirect= failure establishes SPF again, so the domain's own
 *   record is compared while only the never-read policy, its findings and
 *   the target's include tree wait for a baseline (r10-trust-5).
 *   Round 11: only a record that still delegates to that target waits; one
 *   replaced while the target is lame is compared as usual, and the include
 *   tree's baseline is the first scan in which it answers, which can follow
 *   the policy's first read (r11-trust-5).
 *   Round 12: an accepted failure of the domain's own lookup is a removal and
 *   drops the markers, as a deletion does; behind a redirect= chain whose
 *   later hop stays lame, the tree read once that failure is accepted is a
 *   baseline too, and the markers wait for the whole chain. Only the first
 *   such reading is (spfLookupsPartial), so later ones are compared, and a
 *   top-level include: next to the redirect= is not the target answering.
 *
 * Every scan goes through the real analyzers against a scripted in-memory
 * DnsClient, and the one test that reaches the fetchers answers the OS
 * resolver itself; nothing touches the network.
 */

import assert from "node:assert/strict";
import dns from "node:dns";
import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { loadConfig } from "../src/config.js";
import type { DnsClient, DnsErrorInfo, MxRecord } from "../src/lib/dns.js";
import { countBySeverity } from "../src/lib/findings.js";
import { gradeFromScore, scoreEmail, type EmailScoreInput } from "../src/lib/scoring.js";
import { setLogLevel } from "../src/logger.js";
import type { ToolContext } from "../src/middleware/metering.js";
import { openDatabase, type Database } from "../src/store/db.js";
import { ScanStore, type DomainChange, type EmailScanInput } from "../src/store/scanStore.js";
import { summarizeEmail } from "../src/tools/bulk.js";
import { comprehensiveAudit } from "../src/tools/comprehensiveAudit.js";
import { emailLookupFailures, verifyEmailInfrastructure, type EmailResult } from "../src/tools/verifyEmailInfrastructure.js";

setLogLevel("silent");

const HOUR = 60 * 60 * 1000;
const TIMEOUT: DnsErrorInfo = { code: "ETIMEOUT", message: "timeout" };
const PUBLIC_IP = "142.250.150.26";

/** TXT and MX answers come from the maps, names in failTxt time out, every other name is NXDOMAIN. */
interface Zones {
  txt: Record<string, string[]>;
  mx: Record<string, Array<{ exchange: string; priority: number }>>;
  addresses: Record<string, string[]>;
  failTxt?: string[];
}

function fakeDns(zones: Zones): DnsClient {
  const failTxt = new Set((zones.failTxt ?? []).map((n) => n.toLowerCase()));
  const nx = { records: [], nxdomain: true, error: null, durationMs: 1 };
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
    a: async (name: string) => {
      const records = zones.addresses[name.toLowerCase()];
      return records ? { records, nxdomain: false, error: null, durationMs: 1 } : nx;
    },
    aaaa: async (name: string) => (zones.addresses[name.toLowerCase()] ? { records: [], nxdomain: false, error: null, durationMs: 1 } : nx),
    addresses: async (name: string) => ({ v4: zones.addresses[name.toLowerCase()] ?? [], v6: [], errors: [] })
  } as unknown as DnsClient;
}

const ctx: ToolContext = { principal: { id: "p", plan: "local", label: "", source: "local" }, signal: new AbortController().signal, requestId: "round8" };
const config = loadConfig({}, []);

function scan(domain: string, zones: Zones): Promise<EmailResult> {
  return verifyEmailInfrastructure({ domain, dkimSelectors: [], checkMtaSts: true }, { config, dns: fakeDns(zones) }, ctx);
}

/** A domain whose mail is otherwise healthy: one resolving MX, DMARC p=reject with reporting. */
function healthy(domain: string, spf: string, txt: Record<string, string[]> = {}): Zones {
  return {
    txt: { [domain]: [spf], [`_dmarc.${domain}`]: [`v=DMARC1; p=reject; rua=mailto:dmarc@${domain}`], ...txt },
    mx: { [domain]: [{ exchange: "aspmx.l.google.com", priority: 1 }] },
    addresses: { "aspmx.l.google.com": [PUBLIC_IP] }
  };
}

async function memoryStore(): Promise<{ db: Database; store: ScanStore }> {
  const db = await openDatabase(":memory:");
  assert.ok(db);
  return { db, store: new ScanStore(db, { retentionDays: 30 }) };
}

/** Rewrites a stored state, e.g. into the shape earlier code left behind. */
function editState(db: Database, domain: string, edit: (state: Record<string, unknown>) => void): void {
  const row = db.prepare("SELECT email_state FROM domains WHERE domain = ?").get(domain) as { email_state: string };
  const state = JSON.parse(row.email_state) as Record<string, unknown>;
  edit(state);
  db.prepare("UPDATE domains SET email_state = ? WHERE domain = ?").run(JSON.stringify(state), domain);
}

/** Drops the markers the current rules write, as in a state stored by earlier code. */
function asLegacy(state: Record<string, unknown>): void {
  delete state.basis;
  delete state.scoreRules;
  delete state.dmarcPoints;
  delete state.spfPolicyKnown;
  delete state.dmarcPolicyKnown;
  delete state.scoreRebaseline;
}

function readState(db: Database, domain: string): Record<string, unknown> {
  const row = db.prepare("SELECT email_state FROM domains WHERE domain = ?").get(domain) as { email_state: string };
  return JSON.parse(row.email_state) as Record<string, unknown>;
}

const changes = (list: DomainChange[]): Array<Array<string | null>> => list.map((c) => [c.change, c.subject, c.oldValue, c.newValue, c.severity]);

function withoutBreakdown(result: EmailResult): EmailScanInput {
  const input: EmailScanInput = { ...result };
  delete input.scoreBreakdown;
  return input;
}

/** The counts a summary should give: every finding except the organizational record's DMARC findings. */
function ownCounts(findings: EmailResult["risks"]): string {
  const counts = countBySeverity(findings.filter((f) => !(f.code.startsWith("DMARC_") && f.code !== "DMARC_DNS_ERROR")));
  return `${counts.critical} critical, ${counts.high} high, ${counts.medium} medium`;
}

// A subdomain whose own _dmarc lookup times out while the organizational record answers.
const ORG = "trustfallback.com";
const SUB = `shop.${ORG}`;
const MALFORMED_ORG = `v=DMARC1; p=rejct; rua=mailto:dmarc@${ORG}`;
const subZones = (own: string[], orgRecords: string[], spf = "v=spf1 -all"): Zones => healthy(SUB, spf, { [`_dmarc.${SUB}`]: own, [`_dmarc.${ORG}`]: orgRecords });
const ownDown = (zones: Zones): Zones => ({ ...zones, failTxt: [`_dmarc.${SUB}`] });

// ---------------------------------------------------------------------------
// T-A, T-B, T-C: the live one-line summaries
// ---------------------------------------------------------------------------

describe("T-A / T-B: the summary of a subdomain whose own _dmarc lookup failed", () => {
  it("counts no organizational DMARC finding and says the policy is unknown, while riskCounts keeps everything", async () => {
    const failed = await scan(SUB, ownDown(subZones([`v=DMARC1; p=none; rua=mailto:dmarc@${ORG}`], [MALFORMED_ORG])));
    assert.equal(emailLookupFailures(failed).dmarcPolicy, true, "precondition: own lookup failed, organizational record used");
    assert.ok(
      failed.risks.some((r) => r.code === "DMARC_SYNTAX_ERROR" && r.severity === "high"),
      "precondition: the organizational record is malformed"
    );
    assert.equal(failed.riskCounts.high, 1, "riskCounts still counts every finding in risks");
    assert.match(failed.summary, /; 0 critical, 0 high, \d+ medium risk\(s\)\.$/, "the summary agrees with the bulk item's highRisks");
    assert.ok(failed.summary.endsWith(`${ownCounts(failed.risks)} risk(s).`), "the own lookup's DMARC_DNS_ERROR is still counted");
    assert.deepEqual(summarizeEmail(failed).highRisks, []);
    assert.match(failed.summary, /DMARC unknown \(own _dmarc lookup failed; organizational p=invalid\)/);
    assert.doesNotMatch(failed.summary, /inherited/);

    const reject = await scan(SUB, ownDown(subZones([`v=DMARC1; p=none; rua=mailto:dmarc@${ORG}`], [`v=DMARC1; p=reject; rua=mailto:dmarc@${ORG}`])));
    assert.match(reject.summary, /DMARC unknown \(own _dmarc lookup failed; organizational p=reject\)/);
  });

  it("still counts and credits an organizational record the subdomain legitimately inherits", async () => {
    const inherited = await scan(SUB, subZones([], [MALFORMED_ORG]));
    assert.equal(emailLookupFailures(inherited).dmarcPolicy, false);
    assert.match(inherited.summary, /; 0 critical, 1 high, /, "an inherited malformed record is the subdomain's real posture");
    const rejecting = await scan(SUB, subZones([], [`v=DMARC1; p=reject; rua=mailto:dmarc@${ORG}`]));
    assert.match(rejecting.summary, /DMARC p=reject \(inherited\)/);
  });

  it("comprehensive_audit's summary sentence follows the same rule; findingCounts keeps everything", async (t) => {
    // The website half reaches the fetchers, which resolve through the OS
    // resolver: it answers NXDOMAIN here, so nothing leaves the process and
    // the audit carries on with the email half.
    const looked: string[] = [];
    t.mock.method(dns, "lookup", (host: string, _options: unknown, callback: (err: Error) => void) => {
      looked.push(host);
      process.nextTick(callback, Object.assign(new Error(`getaddrinfo ENOTFOUND ${host}`), { code: "ENOTFOUND", hostname: host }));
    });
    const zones = ownDown(subZones([`v=DMARC1; p=none; rua=mailto:dmarc@${ORG}`], [MALFORMED_ORG]));
    const audit = await comprehensiveAudit({ domain: SUB, dkimSelectors: [], includeRawHeaders: false, includeEvidence: false }, { config, dns: fakeDns(zones) }, ctx);
    assert.ok(audit.email, "the email half answered");
    assert.ok(looked.length > 0 && looked.every((h) => h === SUB || h.endsWith(`.${SUB}`)), `only the audited host was resolved (got ${JSON.stringify(looked)})`);
    assert.ok(
      audit.findings.some((f) => f.code === "DMARC_SYNTAX_ERROR"),
      "precondition: the merged findings carry the organizational record's finding"
    );
    assert.equal(audit.findingCounts.high, countBySeverity(audit.findings).high, "findingCounts is unchanged");
    assert.ok(audit.summary.endsWith(`${ownCounts(audit.findings)} finding(s).`), audit.summary);
    assert.ok(countBySeverity(audit.findings).high > Number(/(\d+) high/.exec(audit.summary)?.[1]), "the organizational DMARC_SYNTAX_ERROR is left out of the sentence");
  });
});

describe("T-C: the summary of a record whose redirect= target failed", () => {
  const domain = "vendor-redirect8.com";
  const target = "_spf.vendor.net";

  it("says the policy is unknown and names the target, while the live allPolicy enum still reads none", async () => {
    const zones = healthy(domain, `v=spf1 redirect=${target}`, { [target]: ["v=spf1 ip4:203.0.113.0/24 -all"] });
    const failed = await scan(domain, { ...zones, failTxt: [target] });
    assert.match(failed.summary, /SPF policy unknown \(redirect=_spf\.vendor\.net lookup failed\)/);
    assert.doesNotMatch(failed.summary, /SPF redirect=/);
    assert.equal(failed.spf.allPolicy, "none", "the output schema's enum is unchanged");
    assert.equal(failed.spf.allQualifier, null);

    const answered = await scan(domain, zones);
    assert.match(answered.summary, /SPF -all via redirect=_spf\.vendor\.net \(\d+ lookups\)/);
  });

  it("names the hop whose lookup failed in a redirect chain", async () => {
    const hop = "_spf2.vendor.net";
    const zones = healthy(domain, `v=spf1 redirect=${target}`, { [target]: [`v=spf1 redirect=${hop}`], [hop]: ["v=spf1 -all"] });
    const failed = await scan(domain, { ...zones, failTxt: [hop] });
    assert.match(failed.summary, /SPF policy unknown \(redirect=_spf2\.vendor\.net lookup failed\)/);
  });
});

// ---------------------------------------------------------------------------
// SPF permerrors in the score
// ---------------------------------------------------------------------------

describe("an SPF void-lookup or circular-include permerror costs points like the lookup-limit permerror", () => {
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
  const spfItem = (spf: Partial<EmailScoreInput["spf"]>) => scoreEmail({ ...base, spf: { ...base.spf, ...spf } }).breakdown.find((b) => b.component === "spf");

  it("scoreEmail caps SPF at 6 with the note ' SPF permerror.'", () => {
    assert.deepEqual(spfItem({}), { component: "spf", points: 22, maxPoints: 22, note: "SPF ends with -all." });
    assert.deepEqual(spfItem({ valid: false, voidLookupsExceeded: true }), { component: "spf", points: 6, maxPoints: 22, note: "SPF ends with -all. SPF permerror." });
    assert.deepEqual(spfItem({ valid: false, circularInclude: true }), { component: "spf", points: 6, maxPoints: 22, note: "SPF ends with -all. SPF permerror." });
    assert.equal(spfItem({ valid: false, allPolicy: "pass", voidLookupsExceeded: true })?.points, 2, "a cap never raises points");
    assert.deepEqual(
      spfItem({ valid: false, lookupLimitExceeded: true, voidLookupsExceeded: true }),
      { component: "spf", points: 6, maxPoints: 22, note: "SPF ends with -all. Exceeds the 10 DNS lookup limit (permerror)." },
      "one permerror note"
    );
  });

  it("verify_email_infrastructure scores a record with more than 2 void lookups or a circular include as a permerror", async () => {
    const voids = await scan("voids.com", healthy("voids.com", "v=spf1 include:a.voids.net include:b.voids.net include:c.voids.net -all"));
    assert.ok(
      voids.risks.some((r) => r.code === "SPF_VOID_LOOKUPS"),
      "precondition: three void lookups"
    );
    assert.equal(voids.spf.valid, false);
    assert.deepEqual(
      voids.scoreBreakdown.find((b) => b.component === "spf"),
      { component: "spf", points: 6, maxPoints: 22, note: "SPF ends with -all. SPF permerror." }
    );

    const loop = await scan("loop.com", healthy("loop.com", "v=spf1 include:_spf.loop.com -all", { "_spf.loop.com": ["v=spf1 include:loop.com -all"] }));
    assert.ok(
      loop.risks.some((r) => r.code === "SPF_CIRCULAR_INCLUDE"),
      "precondition: the chain loops"
    );
    assert.equal(loop.scoreBreakdown.find((b) => b.component === "spf")?.points, 6);
  });

  it("a stored score from the earlier rules is re-baselined silently, while a state under the current rules reports a real drop", async () => {
    const domain = "voids-stored.com";
    const zones = healthy(domain, "v=spf1 include:a.voids.net include:b.voids.net include:c.voids.net -all");
    const result = await scan(domain, zones);
    for (const legacy of [true, false]) {
      const { db, store } = await memoryStore();
      store.recordEmail(result, "monitor", 0);
      // Earlier rules gave this record its full 22 SPF points.
      editState(db, domain, (state) => {
        if (legacy) asLegacy(state);
        state.score = result.score + 16;
        state.grade = gradeFromScore(result.score + 16);
      });
      const next = store.recordEmail(await scan(domain, zones), "monitor", 1 * HOUR);
      if (legacy) {
        assert.deepEqual(changes(next), [], "the rule change is not a score drop");
        assert.equal(store.history(domain).email?.score, result.score);
        assert.deepEqual(store.recordEmail(await scan(domain, zones), "monitor", 2 * HOUR), []);
      } else {
        assert.deepEqual(
          next.map((c) => c.change),
          ["score_drop"],
          "a state already scored under the current rules compares as usual"
        );
      }
    }
  });
});

// ---------------------------------------------------------------------------
// The stored SPF policy behind a failed redirect= target
// ---------------------------------------------------------------------------

describe("the stored SPF policy reads 'unknown' when a redirect= target's lookup failed", () => {
  const domain = "stored-redirect.com";
  const target = "_spf.vendor.net";
  const zonesWith = (targetRecord: string): Zones => healthy(domain, `v=spf1 redirect=${target}`, { [target]: [targetRecord] });
  const lame = (zones: Zones): Zones => ({ ...zones, failTxt: [target] });

  it("a first scan stores 'unknown' (unverified), never 'none'", async () => {
    const { store } = await memoryStore();
    store.recordEmail(await scan(domain, lame(zonesWith("v=spf1 -all"))), "monitor", 0);
    const snapshot = store.history(domain).email;
    assert.equal(snapshot?.spfFound, true);
    assert.equal(snapshot?.spfPolicy, "unknown");
    assert.ok(snapshot?.unverified.includes("spf"));
  });

  it("an accepted failure records fail -> unknown as high, and recovery restores the real policy as info", async () => {
    const { store } = await memoryStore();
    const zones = zonesWith("v=spf1 -all");
    store.recordEmail(await scan(domain, zones), "monitor", 0);
    for (const at of [1, 12]) assert.deepEqual(store.recordEmail(await scan(domain, lame(zones)), "monitor", at * HOUR), []);
    const accepted = store.recordEmail(await scan(domain, lame(zones)), "monitor", 25 * HOUR);
    assert.deepEqual(
      changes(accepted).filter(([change]) => change === "spf_policy"),
      [["spf_policy", "spf", "fail", "unknown", "high"]]
    );
    assert.equal(store.history(domain).email?.spfPolicy, "unknown");
    const recovered = store.recordEmail(await scan(domain, zones), "monitor", 26 * HOUR);
    assert.deepEqual(
      changes(recovered).filter(([change]) => change === "spf_policy"),
      [["spf_policy", "spf", "unknown", "fail", "info"]]
    );
    assert.equal(store.history(domain).email?.spfPolicy, "fail");
  });

  it("none -> unknown is info, never high", async () => {
    const { store } = await memoryStore();
    const zones = zonesWith("v=spf1 ip4:203.0.113.0/24");
    const baseline = await scan(domain, zones);
    assert.equal(baseline.spf.allPolicy, "none", "precondition: the target has no all");
    store.recordEmail(baseline, "monitor", 0);
    for (const at of [1, 12]) store.recordEmail(await scan(domain, lame(zones)), "monitor", at * HOUR);
    const accepted = store.recordEmail(await scan(domain, lame(zones)), "monitor", 25 * HOUR);
    assert.deepEqual(changes(accepted), [["spf_policy", "spf", "none", "unknown", "info"]]);
  });

  it("keeps the last known all-policy risks while the policy is unknown, so neither acceptance nor recovery flips them", async () => {
    const { store } = await memoryStore();
    const zones = zonesWith("v=spf1 ip4:203.0.113.0/24 ?all");
    store.recordEmail(await scan(domain, zones), "monitor", 0);
    assert.ok(store.history(domain).email?.highRisks.includes("SPF_NEUTRAL_ALL"), "precondition: the target's ?all is a high risk");
    for (const at of [1, 12]) store.recordEmail(await scan(domain, lame(zones)), "monitor", at * HOUR);
    const accepted = store.recordEmail(await scan(domain, lame(zones)), "monitor", 25 * HOUR);
    assert.deepEqual(changes(accepted), [["spf_policy", "spf", "neutral", "unknown", "info"]], "no risk_resolved for a policy nobody could read");
    assert.ok(store.history(domain).email?.highRisks.includes("SPF_NEUTRAL_ALL"));
    const recovered = store.recordEmail(await scan(domain, zones), "monitor", 26 * HOUR);
    assert.deepEqual(changes(recovered), [["spf_policy", "spf", "unknown", "neutral", "info"]], "no risk_new for a risk that was there all along");
  });

  it("a state earlier code stored as 'none' under an accepted failure is re-baselined to 'unknown' silently", async () => {
    const { db, store } = await memoryStore();
    const zones = zonesWith("v=spf1 -all");
    store.recordEmail(await scan(domain, zones), "monitor", 0);
    for (const at of [1, 12, 25]) store.recordEmail(await scan(domain, lame(zones)), "monitor", at * HOUR);
    // What earlier code stored once it accepted the failure.
    editState(db, domain, (state) => {
      asLegacy(state);
      state.spfPolicy = "none";
    });
    assert.deepEqual(changes(store.recordEmail(await scan(domain, lame(zones)), "monitor", 26 * HOUR)), [], "no spf_policy none -> unknown");
    assert.equal(store.history(domain).email?.spfPolicy, "unknown");
  });

  it("a legacy state whose streak was not yet accepted is compared as usual once it is", async () => {
    const { db, store } = await memoryStore();
    const zones = zonesWith("v=spf1 -all");
    store.recordEmail(await scan(domain, zones), "monitor", 0);
    for (const at of [1, 12]) store.recordEmail(await scan(domain, lame(zones)), "monitor", at * HOUR);
    editState(db, domain, asLegacy);
    const accepted = store.recordEmail(await scan(domain, lame(zones)), "monitor", 25 * HOUR);
    assert.deepEqual(
      changes(accepted).filter(([change]) => change === "spf_policy"),
      [["spf_policy", "spf", "fail", "unknown", "high"]]
    );
  });
});

// ---------------------------------------------------------------------------
// DMARC: ranks, legacy states (T-D), never-established components (T-E) and
// the stored score (T-F)
// ---------------------------------------------------------------------------

/** Records an established own record at 0h and own-lookup failures at 1h, 12h and 25h (accepted); returns the changes of the last. */
async function acceptOwnFailure(store: ScanStore, zones: Zones, shape: (r: EmailResult) => EmailScanInput = (r) => r): Promise<DomainChange[]> {
  store.recordEmail(shape(await scan(SUB, zones)), "monitor", 0);
  for (const at of [1, 12]) assert.deepEqual(store.recordEmail(shape(await scan(SUB, ownDown(zones))), "monitor", at * HOUR), [], `a failure at ${at}h is held`);
  return store.recordEmail(shape(await scan(SUB, ownDown(zones))), "monitor", 25 * HOUR);
}

describe("DMARC: an unknown policy ranks with p=none", () => {
  it("own p=none -> unknown is info; quarantine -> unknown stays high", async () => {
    const none = await acceptOwnFailure((await memoryStore()).store, subZones([`v=DMARC1; p=none; rua=mailto:dmarc@${ORG}`], [`v=DMARC1; p=reject; rua=mailto:dmarc@${ORG}`]));
    assert.deepEqual(changes(none), [["dmarc_policy", "dmarc", "none", "unknown", "info"]]);
    const quarantine = await acceptOwnFailure((await memoryStore()).store, subZones([`v=DMARC1; p=quarantine; rua=mailto:dmarc@${ORG}`], [`v=DMARC1; p=reject; rua=mailto:dmarc@${ORG}`]));
    assert.deepEqual(changes(quarantine), [["dmarc_policy", "dmarc", "quarantine", "unknown", "high"]]);
  });
});

describe("T-D: states earlier code stored under an accepted own-lookup failure are re-baselined silently", () => {
  const ownQuarantine = [`v=DMARC1; p=quarantine; rua=mailto:dmarc@${ORG}`];

  it("the organizational policy and score earlier code stored raise no dmarc_policy or score_drop, and recovery none either", async () => {
    const { db, store } = await memoryStore();
    const zones = subZones(ownQuarantine, [`v=DMARC1; p=reject; rua=mailto:dmarc@${ORG}`]);
    await acceptOwnFailure(store, zones);
    const live = await scan(SUB, ownDown(zones));
    // Earlier code stored the organizational p=reject and credited its 28 points instead of the fallback's 10.
    editState(db, SUB, (state) => {
      asLegacy(state);
      state.dmarcPolicy = "reject";
      state.score = live.score + 18;
      state.grade = gradeFromScore(live.score + 18);
    });
    assert.deepEqual(changes(store.recordEmail(live, "monitor", 26 * HOUR)), [], "no dmarc_policy reject -> unknown, no score_drop");
    const snapshot = store.history(SUB).email;
    assert.equal(snapshot?.dmarcPolicy, "unknown");
    assert.equal(snapshot?.score, live.score);
    assert.ok(snapshot?.unverified.includes("dmarc"), "the subdomain's own DMARC is not known until its lookup answers");
    assert.deepEqual(changes(store.recordEmail(await scan(SUB, ownDown(zones)), "monitor", 27 * HOUR)), []);
    assert.deepEqual(changes(store.recordEmail(await scan(SUB, zones), "monitor", 28 * HOUR)), [], "the first own answer is a baseline");
    assert.equal(store.history(SUB).email?.dmarcPolicy, "quarantine");
  });

  it("drops the organizational record's findings earlier code stored, without a false risk_resolved on recovery", async () => {
    const { db, store } = await memoryStore();
    const zones = subZones([`v=DMARC1; p=reject; rua=mailto:dmarc@${ORG}`], [MALFORMED_ORG]);
    await acceptOwnFailure(store, zones);
    const live = await scan(SUB, ownDown(zones));
    // Earlier code stored the organizational record's policy (never "unknown") and its findings.
    editState(db, SUB, (state) => {
      asLegacy(state);
      state.dmarcPolicy = live.dmarc.effectivePolicy ?? null;
      state.risks = [...(state.risks as Array<{ code: string; severity: string }>), { code: "DMARC_SYNTAX_ERROR", severity: "high" }];
    });
    assert.ok(store.history(SUB).email?.highRisks.includes("DMARC_SYNTAX_ERROR"), "precondition: the legacy state lists the organizational finding");
    assert.deepEqual(changes(store.recordEmail(await scan(SUB, ownDown(zones)), "monitor", 26 * HOUR)), []);
    assert.ok(!store.history(SUB).email?.highRisks.includes("DMARC_SYNTAX_ERROR"), "the organizational finding is not the subdomain's");
    const recovered = store.recordEmail(await scan(SUB, zones), "monitor", 27 * HOUR);
    assert.ok(!recovered.some((c) => c.subject === "DMARC_SYNTAX_ERROR"), `no risk_resolved DMARC_SYNTAX_ERROR (got ${JSON.stringify(changes(recovered))})`);
    assert.deepEqual(changes(recovered), []);
  });

  it("leaves a legacy state alone whose streak was not yet accepted when it was written", async () => {
    const { db, store } = await memoryStore();
    const zones = subZones(ownQuarantine, [`v=DMARC1; p=reject; rua=mailto:dmarc@${ORG}`]);
    store.recordEmail(await scan(SUB, zones), "monitor", 0);
    for (const at of [1, 12]) store.recordEmail(await scan(SUB, ownDown(zones)), "monitor", at * HOUR);
    editState(db, SUB, asLegacy);
    const accepted = store.recordEmail(await scan(SUB, ownDown(zones)), "monitor", 25 * HOUR);
    assert.deepEqual(changes(accepted), [["dmarc_policy", "dmarc", "quarantine", "unknown", "high"]], "its stored policy was the subdomain's own");
  });
});

describe("T-E: DMARC that only the organizational fallback ever answered is established by its first own answer, silently", () => {
  it("own findings first seen after an accepted fallback reading are a baseline, not risk_new", async () => {
    const { store } = await memoryStore();
    const zones = subZones([`v=DMARC1; p=reject; rua=mailto:dmarc@${ORG}`, `v=DMARC1; p=none; rua=mailto:dmarc@${ORG}`], [`v=DMARC1; p=reject; rua=mailto:dmarc@${ORG}`]);
    for (const at of [0, 12]) assert.deepEqual(store.recordEmail(await scan(SUB, ownDown(zones)), "monitor", at * HOUR), []);
    assert.deepEqual(store.recordEmail(await scan(SUB, ownDown(zones)), "monitor", 25 * HOUR), [], "accepting a fallback reading records nothing");
    const accepted = store.history(SUB).email;
    assert.equal(accepted?.dmarcPolicy, "unknown");
    assert.ok(accepted?.unverified.includes("dmarc"), "still unverified: the subdomain's own record never answered");
    assert.notEqual(accepted?.score, null, "the score is established");

    const recovered = await scan(SUB, zones);
    assert.ok(
      recovered.risks.some((r) => r.code === "DMARC_MULTIPLE_RECORDS"),
      "precondition: the own lookup now shows two records"
    );
    assert.deepEqual(changes(store.recordEmail(recovered, "monitor", 26 * HOUR)), [], "newly observed, not newly introduced");
    const snapshot = store.history(SUB).email;
    assert.ok(snapshot?.highRisks.includes("DMARC_MULTIPLE_RECORDS"));
    assert.ok(!snapshot?.unverified.includes("dmarc"));
    assert.equal(snapshot?.score, recovered.score);

    // From now on DMARC is established and compared as usual.
    const fixed = store.recordEmail(await scan(SUB, subZones([`v=DMARC1; p=reject; rua=mailto:dmarc@${ORG}`], [`v=DMARC1; p=reject; rua=mailto:dmarc@${ORG}`])), "monitor", 27 * HOUR);
    assert.ok(changes(fixed).some(([change, subject]) => change === "risk_resolved" && subject === "DMARC_MULTIPLE_RECORDS"));
  });
});

describe("T-F: while the own _dmarc lookup fails, the stored score keeps the subdomain's last known DMARC points", () => {
  it("a broken own record is not lifted to the fallback's p=none points, and a strong one is not lowered", async () => {
    for (const own of [`v=DMARC1; p=rejct; rua=mailto:dmarc@${ORG}`, `v=DMARC1; p=reject; rua=mailto:dmarc@${ORG}`]) {
      for (const strip of [false, true]) {
        const label = `${own} (${strip ? "no breakdown" : "with breakdown"})`;
        const { store } = await memoryStore();
        const zones = subZones([own], [`v=DMARC1; p=reject; rua=mailto:dmarc@${ORG}`]);
        const baseline = await scan(SUB, zones);
        const live = await scan(SUB, ownDown(zones));
        assert.notEqual(live.score, baseline.score, `precondition: the live score moves (${label})`);
        const accepted = await acceptOwnFailure(store, zones, strip ? withoutBreakdown : (r) => r);
        assert.ok(!accepted.some((c) => c.change === "score_drop" || c.change === "score_rise"), `${label}: ${JSON.stringify(changes(accepted))}`);
        assert.equal(store.history(SUB).email?.score, baseline.score, label);
        assert.deepEqual(changes(store.recordEmail(strip ? withoutBreakdown(live) : live, "monitor", 26 * HOUR)), [], label);
        assert.equal(store.history(SUB).email?.score, baseline.score, label);
        const recovered = store.recordEmail(strip ? withoutBreakdown(baseline) : baseline, "monitor", 27 * HOUR);
        assert.ok(!recovered.some((c) => c.change.startsWith("score_")), label);
      }
    }
  });

  it("a malformed own record keeps the score while its own DMARC_SYNTAX_ERROR is kept as last known", async () => {
    const { store } = await memoryStore();
    const zones = subZones([`v=DMARC1; p=rejct; rua=mailto:dmarc@${ORG}`], [`v=DMARC1; p=reject; rua=mailto:dmarc@${ORG}`]);
    const baseline = await scan(SUB, zones);
    const live = await scan(SUB, ownDown(zones));
    assert.equal(live.score, baseline.score + 6, "precondition: the fallback's 10 points against the malformed record's 4");
    const accepted = await acceptOwnFailure(store, zones);
    assert.deepEqual(changes(accepted), [["dmarc_policy", "dmarc", null, "unknown", "info"]]);
    const snapshot = store.history(SUB).email;
    assert.equal(snapshot?.score, baseline.score, "the timeout does not lift the stored score");
    assert.ok(snapshot?.highRisks.includes("DMARC_SYNTAX_ERROR"));
  });

  it("a state from before dmarcPoints existed takes the fallback's points once, silently, then compares as usual", async () => {
    const { db, store } = await memoryStore();
    const zones = subZones([`v=DMARC1; p=reject; rua=mailto:dmarc@${ORG}`], [`v=DMARC1; p=reject; rua=mailto:dmarc@${ORG}`]);
    const baseline = await scan(SUB, zones);
    store.recordEmail(baseline, "monitor", 0);
    editState(db, SUB, asLegacy);
    for (const at of [1, 12]) assert.deepEqual(store.recordEmail(await scan(SUB, ownDown(zones)), "monitor", at * HOUR), []);
    const live = await scan(SUB, ownDown(zones));
    const accepted = store.recordEmail(live, "monitor", 25 * HOUR);
    assert.deepEqual(changes(accepted), [["dmarc_policy", "dmarc", "reject", "unknown", "high"]], "no score_drop from points this state never recorded");
    assert.equal(store.history(SUB).email?.score, live.score);
    assert.deepEqual(changes(store.recordEmail(await scan(SUB, ownDown(zones)), "monitor", 26 * HOUR)), []);
  });
});

// ---------------------------------------------------------------------------
// Round 9: states the round-7 build wrote, re-baselines a scan could not
// finish, ranks away from unknown, the SCORE_RULES trigger, and the SPF
// analog of T-E
// ---------------------------------------------------------------------------

const tlsRptDown = (zones: Zones): Zones => ({ ...zones, failTxt: [...(zones.failTxt ?? []), `_smtp._tls.${SUB}`] });

describe("r9-trust-1: a basis-less state that already reads 'unknown' is not a fallback state", () => {
  // What the round-7 build stored under an accepted own-lookup failure: the
  // policy 'unknown', the subdomain's OWN DMARC findings kept as last known,
  // the fallback's points in the score, and no basis or dmarcPoints.
  async function roundSevenState(own: string[]): Promise<{ db: Database; store: ScanStore }> {
    const { db, store } = await memoryStore();
    const zones = subZones(own, [`v=DMARC1; p=reject; rua=mailto:dmarc@${ORG}`]);
    await acceptOwnFailure(store, zones);
    const live = await scan(SUB, ownDown(zones));
    editState(db, SUB, (state) => {
      asLegacy(state);
      state.score = live.score;
      state.grade = live.grade;
    });
    assert.equal(readState(db, SUB).dmarcPolicy, "unknown", "precondition: the state reads unknown");
    return { db, store };
  }

  it("keeps the subdomain's own DMARC_SYNTAX_ERROR while the failure lasts and reports its recovery", async () => {
    const own = [`v=DMARC1; p=rejct; rua=mailto:dmarc@${ORG}`];
    const { store } = await roundSevenState(own);
    const live = await scan(SUB, ownDown(subZones(own, [`v=DMARC1; p=reject; rua=mailto:dmarc@${ORG}`])));
    assert.deepEqual(changes(store.recordEmail(live, "monitor", 26 * HOUR)), []);
    const during = store.history(SUB).email;
    assert.ok(during?.highRisks.includes("DMARC_SYNTAX_ERROR"), "the subdomain's own finding is kept");
    assert.ok(!during?.unverified.includes("dmarc"), "its own DMARC was established before the failure");
    const fixed = await scan(SUB, subZones([`v=DMARC1; p=reject; rua=mailto:dmarc@${ORG}`], [`v=DMARC1; p=reject; rua=mailto:dmarc@${ORG}`]));
    assert.deepEqual(changes(store.recordEmail(fixed, "monitor", 27 * HOUR)), [
      ["dmarc_policy", "dmarc", "unknown", "reject", "info"],
      ["risk_resolved", "DMARC_SYNTAX_ERROR", "DMARC_SYNTAX_ERROR", null, "info"],
      ["score_rise", "score", String(live.score), String(fixed.score), "info"]
    ]);
  });

  it("reports a critical DMARC_MULTIPLE_RECORDS that appears when the own lookup answers again", async () => {
    const { store } = await roundSevenState([`v=DMARC1; p=reject; rua=mailto:dmarc@${ORG}`]);
    const doubled = subZones([`v=DMARC1; p=reject; rua=mailto:dmarc@${ORG}`, `v=DMARC1; p=none; rua=mailto:dmarc@${ORG}`], [`v=DMARC1; p=reject; rua=mailto:dmarc@${ORG}`]);
    assert.deepEqual(changes(store.recordEmail(await scan(SUB, ownDown(doubled)), "monitor", 26 * HOUR)), []);
    const recovered = store.recordEmail(await scan(SUB, doubled), "monitor", 27 * HOUR);
    assert.ok(
      changes(recovered).some(([change, subject, , , severity]) => change === "risk_new" && subject === "DMARC_MULTIPLE_RECORDS" && severity === "critical"),
      JSON.stringify(changes(recovered))
    );
  });
});

describe("r9-trust-2: a score re-baseline survives a scan that cannot rewrite the score", () => {
  it("T-D: a legacy fallback state whose first post-upgrade scan also has a TLS-RPT timeout raises no score_drop later", async () => {
    const { db, store } = await memoryStore();
    const zones = subZones([`v=DMARC1; p=quarantine; rua=mailto:dmarc@${ORG}`], [`v=DMARC1; p=reject; rua=mailto:dmarc@${ORG}`]);
    await acceptOwnFailure(store, zones);
    const live = await scan(SUB, ownDown(zones));
    editState(db, SUB, (state) => {
      asLegacy(state);
      state.dmarcPolicy = "reject";
      state.score = live.score + 18;
      state.grade = gradeFromScore(live.score + 18);
    });
    assert.deepEqual(changes(store.recordEmail(await scan(SUB, tlsRptDown(ownDown(zones))), "monitor", 26 * HOUR)), []);
    assert.equal(store.history(SUB).email?.score, live.score + 18, "precondition: that scan could not rewrite the score");
    assert.equal(readState(db, SUB).scoreRebaseline, true);
    assert.deepEqual(changes(store.recordEmail(live, "monitor", 27 * HOUR)), [], "no score_drop from the organizational points earlier code credited");
    assert.equal(store.history(SUB).email?.score, live.score);
    assert.equal(readState(db, SUB).scoreRebaseline, undefined, "cleared once the score is rewritten");
    assert.deepEqual(changes(store.recordEmail(await scan(SUB, ownDown(zones)), "monitor", 28 * HOUR)), []);
  });

  it("T-E: the first own answer arriving with a TLS-RPT timeout raises no score_rise on the next complete scan", async () => {
    const { db, store } = await memoryStore();
    const zones = subZones([`v=DMARC1; p=reject; rua=mailto:dmarc@${ORG}`], [`v=DMARC1; p=reject; rua=mailto:dmarc@${ORG}`]);
    for (const at of [0, 12, 25]) store.recordEmail(await scan(SUB, ownDown(zones)), "monitor", at * HOUR);
    assert.deepEqual(changes(store.recordEmail(await scan(SUB, tlsRptDown(zones)), "monitor", 26 * HOUR)), []);
    assert.equal(readState(db, SUB).scoreRebaseline, true);
    const complete = await scan(SUB, zones);
    assert.deepEqual(changes(store.recordEmail(complete, "monitor", 27 * HOUR)), [], "nothing changed");
    assert.equal(store.history(SUB).email?.score, complete.score);
    assert.equal(readState(db, SUB).scoreRebaseline, undefined);
  });
});

describe("r9-trust-3: a move away from unknown is ranked against the policy last actually read", () => {
  const domain = "ranked-redirect.com";
  const target = "_spf.vendor.net";
  const spfZones = (record: string): Zones => healthy(domain, `v=spf1 redirect=${target}`, { [target]: [record] });
  const lame = (zones: Zones): Zones => ({ ...zones, failTxt: [target] });

  it("a malformed own DMARC record that reads the same after the failure is info, not high", async () => {
    const { store } = await memoryStore();
    const zones = subZones([`v=DMARC1; p=rejct; rua=mailto:dmarc@${ORG}`], [`v=DMARC1; p=reject; rua=mailto:dmarc@${ORG}`]);
    assert.deepEqual(changes(await acceptOwnFailure(store, zones)), [["dmarc_policy", "dmarc", null, "unknown", "info"]]);
    assert.deepEqual(changes(store.recordEmail(await scan(SUB, ownDown(zones)), "monitor", 26 * HOUR)), [], "the last read policy is carried");
    assert.deepEqual(changes(store.recordEmail(await scan(SUB, zones), "monitor", 27 * HOUR)), [["dmarc_policy", "dmarc", "unknown", null, "info"]]);
  });

  it("p=quarantine that reads p=none after the failure is still a weakening", async () => {
    const { store } = await memoryStore();
    const org = [`v=DMARC1; p=reject; rua=mailto:dmarc@${ORG}`];
    await acceptOwnFailure(store, subZones([`v=DMARC1; p=quarantine; rua=mailto:dmarc@${ORG}`], org));
    const recovered = store.recordEmail(await scan(SUB, subZones([`v=DMARC1; p=none; rua=mailto:dmarc@${ORG}`], org)), "monitor", 26 * HOUR);
    assert.deepEqual(
      changes(recovered).filter(([change]) => change === "dmarc_policy"),
      [["dmarc_policy", "dmarc", "unknown", "none", "high"]]
    );
  });

  it("an SPF +all that reads the same once its redirect= target answers is info, while -all coming back as +all is high", async () => {
    for (const [before, after, severity] of [
      ["v=spf1 ip4:203.0.113.0/24 +all", "v=spf1 ip4:203.0.113.0/24 +all", "info"],
      ["v=spf1 ip4:203.0.113.0/24 -all", "v=spf1 ip4:203.0.113.0/24 +all", "high"]
    ] as const) {
      const { store } = await memoryStore();
      store.recordEmail(await scan(domain, spfZones(before)), "monitor", 0);
      for (const at of [1, 12, 25, 26]) store.recordEmail(await scan(domain, lame(spfZones(before))), "monitor", at * HOUR);
      assert.equal(store.history(domain).email?.spfPolicy, "unknown", "precondition: accepted as unknown");
      const recovered = store.recordEmail(await scan(domain, spfZones(after)), "monitor", 27 * HOUR);
      assert.deepEqual(
        changes(recovered).filter(([change]) => change === "spf_policy"),
        [["spf_policy", "spf", "unknown", "pass", severity]],
        `${before} -> ${after}`
      );
    }
  });
});

describe("r9-trust-4: the SCORE_RULES re-baseline only covers a stored score that came from a permerror scan", () => {
  it("a void-lookup permerror that first appears after the upgrade is a real score_drop", async () => {
    const domain = "newly-void.com";
    const { db, store } = await memoryStore();
    // A clean -all record scores the same under both rule sets.
    const clean = await scan(domain, healthy(domain, "v=spf1 -all"));
    store.recordEmail(clean, "monitor", 0);
    editState(db, domain, asLegacy);
    const voids = await scan(domain, healthy(domain, "v=spf1 include:a.voids.net include:b.voids.net include:c.voids.net -all"));
    assert.ok(voids.score <= clean.score - 10, "precondition: the permerror costs a score_drop's worth");
    assert.deepEqual(changes(store.recordEmail(voids, "monitor", HOUR)), [
      ["spf_broken", "spf", "true", "false", "high"],
      ["risk_new", "SPF_VOID_LOOKUPS", null, "SPF_VOID_LOOKUPS", "high"],
      ["score_drop", "score", String(clean.score), String(voids.score), "medium"]
    ]);
  });

  // r10-trust-4: stored risks follow spfLookups while the stored score only moves in a complete scan, so
  // the first post-upgrade scan decides from the risks stored with the score, once.
  const reportingDown = (domain: string, zones: Zones): Zones => ({ ...zones, failTxt: [...(zones.failTxt ?? []), `_smtp._tls.${domain}`] });
  const voidRecord = "v=spf1 include:a.voids.net include:b.voids.net include:c.voids.net -all";

  it("A: a permerror first stored by a scan that cannot rewrite the score is a real score_drop once the score moves", async () => {
    const domain = "void-after-gap.com";
    const { db, store } = await memoryStore();
    const clean = await scan(domain, healthy(domain, "v=spf1 -all"));
    store.recordEmail(clean, "monitor", 0);
    editState(db, domain, asLegacy);
    assert.deepEqual(changes(store.recordEmail(await scan(domain, reportingDown(domain, healthy(domain, voidRecord))), "monitor", HOUR)), [
      ["spf_broken", "spf", "true", "false", "high"],
      ["risk_new", "SPF_VOID_LOOKUPS", null, "SPF_VOID_LOOKUPS", "high"]
    ]);
    const gap = readState(db, domain);
    assert.equal(gap.score, clean.score, "precondition: that scan could not rewrite the score");
    assert.deepEqual(gap.risks, [{ code: "SPF_VOID_LOOKUPS", severity: "high" }], "precondition: the permerror is stored next to a clean score");
    assert.equal(gap.scoreRules, 2, "the clean legacy score was decided to be unaffected by the rule change");
    const voids = await scan(domain, healthy(domain, voidRecord));
    assert.deepEqual(changes(store.recordEmail(voids, "monitor", 2 * HOUR)), [["score_drop", "score", String(clean.score), String(voids.score), "medium"]]);
  });

  it("B: an old-rules permerror score is re-baselined when the permerror returns after a scan that fixed it but could not rewrite the score", async () => {
    const domain = "void-returns.com";
    const { db, store } = await memoryStore();
    const voids = await scan(domain, healthy(domain, voidRecord));
    store.recordEmail(voids, "monitor", 0);
    // Earlier rules gave this record its full 22 SPF points.
    editState(db, domain, (state) => {
      asLegacy(state);
      state.score = voids.score + 16;
      state.grade = gradeFromScore(voids.score + 16);
    });
    assert.deepEqual(changes(store.recordEmail(await scan(domain, reportingDown(domain, healthy(domain, "v=spf1 -all"))), "monitor", HOUR)), [
      ["spf_fixed", "spf", "false", "true", "info"],
      ["risk_resolved", "SPF_VOID_LOOKUPS", "SPF_VOID_LOOKUPS", null, "info"]
    ]);
    const gap = readState(db, domain);
    assert.equal(gap.score, voids.score + 16, "precondition: the old-rules score is still stored");
    assert.deepEqual(gap.risks, [], "precondition: no permerror is stored next to it");
    assert.equal(gap.scoreRules, undefined, "still an old-rules permerror score");
    assert.deepEqual(
      changes(store.recordEmail(voids, "monitor", 2 * HOUR)),
      [
        ["spf_broken", "spf", "true", "false", "high"],
        ["risk_new", "SPF_VOID_LOOKUPS", null, "SPF_VOID_LOOKUPS", "high"]
      ],
      "the rule change alone is not a score_drop"
    );
    assert.equal(store.history(domain).email?.score, voids.score);
    assert.equal(readState(db, domain).scoreRules, 2);
  });
});

describe("r9-trust-5: SPF that only a failed redirect= target ever answered is established by its first real answer, silently", () => {
  const domain = "first-seen-lame.com";
  const target = "_spf.vendor.net";

  it("the policy and findings first read once the target answers are a baseline, score included", async () => {
    for (const record of ["v=spf1 ip4:203.0.113.0/24 +all", "v=spf1 ip4:203.0.113.0/24 ?all", "v=spf1 ip4:203.0.113.0/24 -all"]) {
      const zones = healthy(domain, `v=spf1 redirect=${target}`, { [target]: [record] });
      const { db, store } = await memoryStore();
      for (const at of [0, 12]) store.recordEmail(await scan(domain, { ...zones, failTxt: [target] }), "monitor", at * HOUR);
      assert.deepEqual(changes(store.recordEmail(await scan(domain, { ...zones, failTxt: [target] }), "monitor", 25 * HOUR)), [], record);
      const accepted = store.history(domain).email;
      assert.equal(accepted?.spfPolicy, "unknown", record);
      // r10-trust-5: the domain's own record answered, so the accepted failure establishes SPF; only the policy was never read.
      assert.ok(!accepted?.unverified.includes("spf") && !accepted?.unverified.includes("spfLookups"), `${record}: the own record was read`);
      assert.ok(accepted?.lookupsFailing.includes("spf"), record);
      assert.equal(readState(db, domain).spfPolicyUnread, true, `${record}: the policy was never read`);
      assert.notEqual(accepted?.score, null, `${record}: the score is established`);

      const answered = await scan(domain, zones);
      assert.deepEqual(changes(store.recordEmail(answered, "monitor", 26 * HOUR)), [], `${record}: newly observed, not newly introduced`);
      const snapshot = store.history(domain).email;
      assert.ok(!snapshot?.unverified.includes("spf"), record);
      assert.equal(snapshot?.score, answered.score, record);
      assert.equal(readState(db, domain).spfPolicyUnread, undefined, `${record}: cleared once the policy is read`);
      // From now on SPF is established and compared as usual.
      const strict = store.recordEmail(await scan(domain, healthy(domain, `v=spf1 redirect=${target}`, { [target]: ["v=spf1 ip4:198.51.100.0/24 -all"] })), "monitor", 27 * HOUR);
      const policyChanges = changes(strict).filter(([change]) => change === "spf_policy");
      assert.equal(policyChanges.length, record.endsWith("-all") ? 0 : 1, `${record}: ${JSON.stringify(changes(strict))}`);
    }
  });

  it("a first answer that arrives with a TLS-RPT timeout re-baselines the score on the next complete scan", async () => {
    const zones = healthy(domain, `v=spf1 redirect=${target}`, { [target]: ["v=spf1 ip4:203.0.113.0/24 -all"] });
    const { db, store } = await memoryStore();
    for (const at of [0, 12, 25]) store.recordEmail(await scan(domain, { ...zones, failTxt: [target] }), "monitor", at * HOUR);
    assert.deepEqual(changes(store.recordEmail(await scan(domain, { ...zones, failTxt: [`_smtp._tls.${domain}`] }), "monitor", 26 * HOUR)), []);
    assert.equal(readState(db, domain).scoreRebaseline, true);
    assert.deepEqual(changes(store.recordEmail(await scan(domain, zones), "monitor", 27 * HOUR)), [], "no score_rise from the unknown policy's placeholder points");
  });
});

describe("r10-trust-5: while a redirect= target that never answered stays lame, the domain's own SPF record is compared as usual", () => {
  const domain = "lame-from-start.com";
  const target = "_spf.vendor.net";
  const zones = healthy(domain, `v=spf1 redirect=${target}`, { [target]: ["v=spf1 ip4:203.0.113.0/24 -all"] });
  const lame = (z: Zones): Zones => ({ ...z, failTxt: [...(z.failTxt ?? []), target] });

  /** The target times out at 0h, 12h and 25h, so its failure is accepted at 25h; nothing is recorded. */
  async function acceptedLameFromStart(base: Zones = zones): Promise<{ db: Database; store: ScanStore }> {
    const { db, store } = await memoryStore();
    for (const at of [0, 12, 25]) assert.deepEqual(store.recordEmail(await scan(domain, lame(base)), "monitor", at * HOUR), [], `${at}h`);
    assert.equal(readState(db, domain).spfPolicyUnread, true, "precondition: no policy was ever read");
    return { db, store };
  }

  it("(a) deleting the apex record is spf_removed, risk_new SPF_MISSING and a score_drop, and its re-publication is compared as usual", async () => {
    const { db, store } = await acceptedLameFromStart();
    const before = store.history(domain).email;
    const txt = { ...zones.txt };
    delete txt[domain];
    const removed = await scan(domain, lame({ ...zones, txt }));
    assert.deepEqual(changes(store.recordEmail(removed, "monitor", 26 * HOUR)), [
      ["spf_removed", "spf", "true", "false", "high"],
      ["risk_new", "SPF_MISSING", null, "SPF_MISSING", "high"],
      ["score_drop", "score", String(before?.score), String(removed.score), "medium"]
    ]);
    const snapshot = store.history(domain).email;
    assert.equal(snapshot?.spfFound, false);
    assert.deepEqual(snapshot?.unverified, []);
    assert.ok(snapshot?.highRisks.includes("SPF_MISSING"));
    // r12-trust-deleted-record-marker-clear-unpinned: the policy marker goes anyway (the policy reads none), so all three are pinned.
    const state = readState(db, domain);
    assert.deepEqual([state.spfPolicyUnread, state.spfLookupsUnread, state.spfUnreadTarget], [undefined, undefined, undefined], "a record that is gone leaves nothing waiting on the target");
    // Re-published, delegating to the target that now answers: a new record, not the target's first answer, so the score_drop is matched.
    const back = await scan(domain, zones);
    assert.deepEqual(changes(store.recordEmail(back, "monitor", 52 * HOUR)), [
      ["spf_added", "spf", "false", "true", "info"],
      ["risk_resolved", "SPF_MISSING", "SPF_MISSING", null, "info"],
      ["score_rise", "score", String(removed.score), String(back.score), "info"]
    ]);
  });

  it("(b) publishing a second record is spf_broken and a critical risk_new SPF_MULTIPLE_RECORDS that highRisks shows", async () => {
    const { db, store } = await acceptedLameFromStart();
    const doubled = await scan(domain, lame({ ...zones, txt: { ...zones.txt, [domain]: [`v=spf1 redirect=${target}`, "v=spf1 ~all"] } }));
    assert.equal(emailLookupFailures(doubled).spfPolicy, true, "precondition: the target is still lame");
    assert.deepEqual(changes(store.recordEmail(doubled, "monitor", 26 * HOUR)), [
      ["spf_broken", "spf", "true", "false", "high"],
      ["risk_new", "SPF_MULTIPLE_RECORDS", null, "SPF_MULTIPLE_RECORDS", "critical"]
    ]);
    const snapshot = store.history(domain).email;
    assert.deepEqual(snapshot?.unverified, []);
    assert.deepEqual(snapshot?.highRisks, ["SPF_MULTIPLE_RECORDS"]);
    assert.equal(snapshot?.spfPolicy, "unknown");
    assert.equal(readState(db, domain).spfPolicyUnread, true, "the policy is still unread");
  });

  it("the marker survives scans in which the target stays lame, and the first policy read after them is still a baseline", async () => {
    const { db, store } = await acceptedLameFromStart();
    assert.deepEqual(changes(store.recordEmail(await scan(domain, lame(zones)), "monitor", 26 * HOUR)), []);
    assert.equal(readState(db, domain).spfPolicyUnread, true);
    const passAll = healthy(domain, `v=spf1 redirect=${target}`, { [target]: ["v=spf1 ip4:203.0.113.0/24 +all"] });
    const answered = await scan(domain, passAll);
    assert.ok(
      answered.risks.some((r) => r.code === "SPF_PASS_ALL" && r.severity === "critical"),
      "precondition: the target ends with +all"
    );
    assert.deepEqual(changes(store.recordEmail(answered, "monitor", 27 * HOUR)), [], "no spf_policy unknown -> pass, no risk_new SPF_PASS_ALL, no score change");
    const snapshot = store.history(domain).email;
    assert.equal(snapshot?.spfPolicy, "pass");
    assert.ok(snapshot?.highRisks.includes("SPF_PASS_ALL"));
    assert.equal(snapshot?.score, answered.score);
    assert.equal(readState(db, domain).spfPolicyUnread, undefined);
    // From now on the policy and its findings are compared as usual.
    const strict = store.recordEmail(await scan(domain, zones), "monitor", 28 * HOUR);
    assert.ok(
      changes(strict).some(([change, , , , severity]) => change === "spf_policy" && severity === "info"),
      JSON.stringify(changes(strict))
    );
    assert.ok(
      changes(strict).some(([change, subject]) => change === "risk_resolved" && subject === "SPF_PASS_ALL"),
      JSON.stringify(changes(strict))
    );
  });

  it("the include tree behind the target is first read with the policy: a void-lookup permerror in it is a baseline, then compared", async () => {
    const { store } = await acceptedLameFromStart();
    const voidTarget = healthy(domain, `v=spf1 redirect=${target}`, { [target]: ["v=spf1 include:a.voids.net include:b.voids.net include:c.voids.net -all"] });
    const answered = await scan(domain, voidTarget);
    assert.ok(answered.risks.some((r) => r.code === "SPF_VOID_LOOKUPS") && answered.spf.valid === false, "precondition: the target's include tree has three void lookups");
    assert.equal(store.history(domain).email?.spfValid, true, "precondition: the accepted reading stored a valid record");
    assert.deepEqual(changes(store.recordEmail(answered, "monitor", 26 * HOUR)), [], "no spf_broken, no risk_new SPF_VOID_LOOKUPS");
    assert.ok(store.history(domain).email?.highRisks.includes("SPF_VOID_LOOKUPS"));
    const fixed = store.recordEmail(await scan(domain, zones), "monitor", 27 * HOUR);
    assert.ok(
      changes(fixed).some(([change]) => change === "spf_fixed"),
      JSON.stringify(changes(fixed))
    );
    assert.ok(
      changes(fixed).some(([change, subject]) => change === "risk_resolved" && subject === "SPF_VOID_LOOKUPS"),
      JSON.stringify(changes(fixed))
    );
  });

  // r11-trust-5-apex-replaced-silenced: the target never answers here, so nothing in these scans is its first answer.
  it("(c) replacing the apex record with one that no longer delegates to the lame target is compared like any other change", async () => {
    const voids = "v=spf1 include:a.voids.net include:b.voids.net include:c.voids.net -all";
    const cases: Array<[record: string, extra: Record<string, string[]>, expected: Array<Array<string | null>>]> = [
      [
        "v=spf1 +all",
        {},
        [
          ["spf_policy", "spf", "unknown", "pass", "info"],
          ["risk_new", "SPF_PASS_ALL", null, "SPF_PASS_ALL", "critical"]
        ]
      ],
      [
        "v=spf1 ?all",
        {},
        [
          ["spf_policy", "spf", "unknown", "neutral", "info"],
          ["risk_new", "SPF_NEUTRAL_ALL", null, "SPF_NEUTRAL_ALL", "high"]
        ]
      ],
      // The apex's own all overrides the redirect=, which is then never followed.
      [
        `v=spf1 redirect=${target} +all`,
        {},
        [
          ["spf_policy", "spf", "unknown", "pass", "info"],
          ["risk_new", "SPF_PASS_ALL", null, "SPF_PASS_ALL", "critical"]
        ]
      ],
      [
        "v=spf1 redirect=_spf.other.net",
        { "_spf.other.net": ["v=spf1 +all"] },
        [
          ["spf_policy", "spf", "unknown", "pass", "info"],
          ["risk_new", "SPF_PASS_ALL", null, "SPF_PASS_ALL", "critical"]
        ]
      ],
      [
        voids,
        {},
        [
          ["spf_policy", "spf", "unknown", "fail", "info"],
          ["spf_broken", "spf", "true", "false", "high"],
          ["risk_new", "SPF_VOID_LOOKUPS", null, "SPF_VOID_LOOKUPS", "high"]
        ]
      ]
    ];
    for (const [record, extra, expected] of cases) {
      const { db, store } = await acceptedLameFromStart();
      const replaced = await scan(domain, lame({ ...zones, txt: { ...zones.txt, ...extra, [domain]: [record] } }));
      assert.deepEqual(changes(store.recordEmail(replaced, "monitor", 26 * HOUR)), expected, record);
      const state = readState(db, domain);
      assert.deepEqual([state.spfPolicyUnread, state.spfLookupsUnread, state.spfUnreadTarget], [undefined, undefined, undefined], `${record}: nothing waits on the target any more`);
    }
  });

  it("(c) a held failure of the domain's own SPF lookup says nothing about the delegation: the target's later first answer is still a baseline", async () => {
    const { db, store } = await acceptedLameFromStart();
    const apexDown = await scan(domain, { ...zones, failTxt: [domain, target] });
    assert.equal(apexDown.spf.found, false, "precondition: the domain's own TXT lookup failed");
    assert.deepEqual(changes(store.recordEmail(apexDown, "monitor", 26 * HOUR)), []);
    const state = readState(db, domain);
    assert.deepEqual([state.spfPolicyUnread, state.spfLookupsUnread, state.spfUnreadTarget], [true, true, target]);
    const answered = await scan(domain, healthy(domain, `v=spf1 redirect=${target}`, { [target]: ["v=spf1 ip4:203.0.113.0/24 +all"] }));
    assert.deepEqual(changes(store.recordEmail(answered, "monitor", 27 * HOUR)), [], "no spf_policy unknown -> pass, no risk_new SPF_PASS_ALL");
  });

  // r12-trust-accepted-apex-failure-keeps-tree-marker: an accepted own-lookup failure is recorded as spf_removed, so it drops the markers like a deletion.
  it("(c) once that failure is accepted it is spf_removed and nothing waits on the target: the record's return is compared as usual", async () => {
    const voids = "v=spf1 include:a.voids.net include:b.voids.net include:c.voids.net +all";
    const cases: Array<[targetRecord: string, expected: (removed: number, back: EmailResult) => Array<Array<string | null>>]> = [
      [
        "v=spf1 ip4:203.0.113.0/24 -all",
        (removed, back) => [
          ["spf_added", "spf", "false", "true", "info"],
          ["score_rise", "score", String(removed), String(back.score), "info"]
        ]
      ],
      [
        voids,
        () => [
          ["spf_added", "spf", "false", "true", "info"],
          ["risk_new", "SPF_PASS_ALL", null, "SPF_PASS_ALL", "critical"],
          ["risk_new", "SPF_VOID_LOOKUPS", null, "SPF_VOID_LOOKUPS", "high"]
        ]
      ]
    ];
    for (const [targetRecord, expected] of cases) {
      const { db, store } = await acceptedLameFromStart();
      const apexDown = { ...zones, failTxt: [domain, target] };
      for (const at of [26, 38]) assert.deepEqual(changes(store.recordEmail(await scan(domain, apexDown), "monitor", at * HOUR)), [], `${targetRecord} at ${at}h`);
      const before = store.history(domain).email?.score;
      const accepted = changes(store.recordEmail(await scan(domain, apexDown), "monitor", 51 * HOUR));
      const removed = store.history(domain).email?.score ?? NaN;
      assert.deepEqual(
        accepted,
        [
          ["spf_removed", "spf", "true", "false", "high"],
          ["score_drop", "score", String(before), String(removed), "medium"]
        ],
        targetRecord
      );
      const state = readState(db, domain);
      assert.deepEqual([state.spfPolicyUnread, state.spfLookupsUnread, state.spfUnreadTarget], [undefined, undefined, undefined], `${targetRecord}: nothing waits on the target any more`);
      const back = await scan(domain, healthy(domain, `v=spf1 redirect=${target}`, { [target]: [targetRecord] }));
      assert.deepEqual(changes(store.recordEmail(back, "monitor", 52 * HOUR)), expected(removed, back), `${targetRecord}: as for a deleted record that is re-published`);
    }
  });

  // r11-trust-5-include-tree-split-read: the tree's baseline no longer hangs on the policy's first read.
  it("(d) the include tree behind the target is a baseline in the first scan in which it answers, even when that follows the policy's first read", async () => {
    const flaky = "flaky.vendor.net";
    const tree = healthy(domain, `v=spf1 redirect=${target}`, {
      [target]: [`v=spf1 include:a.voids.net include:b.voids.net include:c.voids.net include:${flaky} -all`],
      [flaky]: ["v=spf1 ip4:198.51.100.0/24 -all"]
    });
    for (const [label, partialAt, wholeAt] of [
      ["the include answers one scan later", [26], 27],
      ["the include stays lame until its own failure is accepted", [26, 38, 51], 52]
    ] as const) {
      const { db, store } = await acceptedLameFromStart();
      for (const at of partialAt) {
        const partial = await scan(domain, { ...tree, failTxt: [flaky] });
        assert.ok(
          partial.risks.some((r) => r.code === "SPF_INCLUDE_DNS_ERROR") && !emailLookupFailures(partial).spfPolicy,
          `${label}: precondition: the target answers, one include behind it does not`
        );
        assert.deepEqual(changes(store.recordEmail(partial, "monitor", at * HOUR)), [], `${label} at ${at}h`);
        assert.equal(readState(db, domain).spfPolicyUnread, undefined, `${label}: the policy was read`);
      }
      if (partialAt.length === 1) {
        const held = readState(db, domain);
        assert.deepEqual([held.spfLookupsUnread, held.spfValid], [true, true], `${label}: the tree is unread and its lame reading still stored`);
      }
      const whole = await scan(domain, tree);
      assert.ok(whole.risks.some((r) => r.code === "SPF_VOID_LOOKUPS") && !whole.spf.valid, "precondition: three void lookups in the target's tree");
      assert.deepEqual(changes(store.recordEmail(whole, "monitor", wholeAt * HOUR)), [], `${label}: no spf_broken, no risk_new SPF_VOID_LOOKUPS, no score change`);
      const snapshot = store.history(domain).email;
      assert.equal(snapshot?.spfValid, false, label);
      assert.ok(snapshot?.highRisks.includes("SPF_VOID_LOOKUPS"), label);
      assert.equal(snapshot?.score, whole.score, label);
      assert.equal(readState(db, domain).spfLookupsUnread, undefined, label);
      // From now on the tree is compared as usual.
      const fixed = store.recordEmail(await scan(domain, zones), "monitor", (wholeAt + 1) * HOUR);
      assert.ok(
        changes(fixed).some(([change]) => change === "spf_fixed"),
        `${label}: ${JSON.stringify(changes(fixed))}`
      );
      assert.ok(
        changes(fixed).some(([change, subject]) => change === "risk_resolved" && subject === "SPF_VOID_LOOKUPS"),
        `${label}: ${JSON.stringify(changes(fixed))}`
      );
    }
  });

  it("(d) the tree's first read re-baselines the score even when the target went lame again after the policy's first read", async () => {
    const flaky = "flaky.vendor.net";
    const tree = healthy(domain, `v=spf1 redirect=${target}`, { [target]: [`v=spf1 ip4:203.0.113.0/24 include:${flaky} -all`], [flaky]: ["v=spf1 ip4:198.51.100.0/24 -all"] });
    const { db, store } = await acceptedLameFromStart();
    assert.deepEqual(changes(store.recordEmail(await scan(domain, { ...tree, failTxt: [flaky] }), "monitor", 26 * HOUR)), [], "the policy is read, the tree is not");
    for (const at of [27, 38]) assert.deepEqual(changes(store.recordEmail(await scan(domain, lame(tree)), "monitor", at * HOUR)), [], `${at}h`);
    // Accepting the target's failure again rewrites the score from the lame reading's placeholder points.
    assert.deepEqual(changes(store.recordEmail(await scan(domain, lame(tree)), "monitor", 52 * HOUR)), [["spf_policy", "spf", "fail", "unknown", "high"]]);
    assert.deepEqual([readState(db, domain).spfLookupsUnread, readState(db, domain).scoreRebaseline], [true, undefined], "precondition: the tree is still unread, the score was rewritten");
    const whole = await scan(domain, tree);
    assert.deepEqual(changes(store.recordEmail(whole, "monitor", 53 * HOUR)), [["spf_policy", "spf", "unknown", "fail", "info"]], "no score_rise from the placeholder points");
    assert.equal(store.history(domain).email?.score, whole.score);
  });

  // r12-trust-multihop-tree-compared-before-first-read: a later hop that stays lame keeps the policy unknown, so the tree can be read before the policy.
  it("(d) behind a two-hop redirect= chain, the tree read once a later hop's failure is accepted is a baseline too, and the marker waits for the whole chain", async () => {
    const hop2 = "_spf2.vendor.net";
    const chain = healthy(domain, `v=spf1 redirect=${target}`, {
      [target]: [`v=spf1 include:a.voids.net include:b.voids.net include:c.voids.net redirect=${hop2}`],
      [hop2]: ["v=spf1 ip4:198.51.100.0/24 -all"]
    });
    for (const [label, alsoDown] of [
      ["the second hop's failure is accepted", []],
      ["a TLS-RPT timeout in the accepting scan defers the score's re-baseline", [`_smtp._tls.${domain}`]]
    ] as const) {
      const { db, store } = await acceptedLameFromStart(chain);
      let partial: EmailResult | undefined;
      for (const at of [26, 38, 51]) {
        partial = await scan(domain, { ...chain, failTxt: [hop2, ...(at === 51 ? alsoDown : [])] });
        assert.ok(
          emailLookupFailures(partial).spfPolicy && partial.risks.some((r) => r.code === "SPF_VOID_LOOKUPS"),
          `${label}: precondition: the target answers with three void lookups, the hop behind it does not`
        );
        assert.deepEqual(changes(store.recordEmail(partial, "monitor", at * HOUR)), [], `${label} at ${at}h: no spf_broken, no risk_new SPF_VOID_LOOKUPS`);
      }
      const held = readState(db, domain);
      assert.deepEqual(
        [held.spfPolicy, held.spfValid, held.spfPolicyUnread, held.spfLookupsUnread, held.spfUnreadTarget],
        ["unknown", false, true, true, target],
        `${label}: the tree read so far is stored, and the marker waits for the whole chain`
      );
      if (alsoDown.length > 0) assert.equal(held.scoreRebaseline, true, `${label}: the score is re-baselined by the next scan that rewrites it`);
      else assert.equal(store.history(domain).email?.score, partial?.score, `${label}: the score is re-baselined with the tree`);
      const whole = await scan(domain, chain);
      assert.equal(emailLookupFailures(whole).spfPolicy, false, "precondition: the whole chain answers");
      assert.deepEqual(changes(store.recordEmail(whole, "monitor", 52 * HOUR)), [], `${label}: the policy's first read is a baseline`);
      const read = readState(db, domain);
      assert.deepEqual([read.spfPolicy, read.spfPolicyUnread, read.spfLookupsUnread, read.spfUnreadTarget], ["fail", undefined, undefined, undefined], label);
      assert.equal(store.history(domain).email?.score, whole.score, label);
      // From now on the tree is compared as usual.
      const fixed = store.recordEmail(await scan(domain, zones), "monitor", 53 * HOUR);
      assert.ok(
        changes(fixed).some(([change]) => change === "spf_fixed"),
        `${label}: ${JSON.stringify(changes(fixed))}`
      );
      assert.ok(
        changes(fixed).some(([change, subject]) => change === "risk_resolved" && subject === "SPF_VOID_LOOKUPS"),
        `${label}: ${JSON.stringify(changes(fixed))}`
      );
    }
  });

  // r12v-trust-partial-read-rebaselines-every-scan: the partial reading is a baseline once. A second hop that stays lame for good is
  // exactly the accepted-failure case, and re-baselining every such scan silenced every tree and score change for as long as it lasted.
  const secondHop = "_spf2.vendor.net";
  const voidsThenHop = `v=spf1 include:a.voids.net include:b.voids.net include:c.voids.net redirect=${secondHop}`;
  const cleanThenHop = `v=spf1 ip4:203.0.113.0/24 redirect=${secondHop}`;
  /** The apex redirects to the target, whose record redirects to secondHop; DMARC keeps reporting. */
  const twoHop = (targetRecord: string, dmarc = "p=reject"): Zones =>
    healthy(domain, `v=spf1 redirect=${target}`, {
      [target]: [targetRecord],
      [secondHop]: ["v=spf1 ip4:198.51.100.0/24 -all"],
      [`_dmarc.${domain}`]: [`v=DMARC1; ${dmarc}; rua=mailto:dmarc@${domain}`]
    });
  const secondHopLame = (z: Zones): Zones => ({ ...z, failTxt: [...(z.failTxt ?? []), secondHop] });

  /** Records one scan: its changes, with the stored score before and after it. */
  async function step(store: ScanStore, z: Zones, at: number): Promise<{ list: Array<Array<string | null>>; before: string; after: string }> {
    const before = String(store.history(domain).email?.score);
    const list = changes(store.recordEmail(await scan(domain, z), "monitor", at * HOUR));
    return { list, before, after: String(store.history(domain).email?.score) };
  }

  /** The target is lame until 25h, then answers while secondHop is lame from 26h: accepted at 51h, a partial baseline. */
  async function partialBaseline(base: Zones): Promise<{ db: Database; store: ScanStore }> {
    const { db, store } = await acceptedLameFromStart(base);
    for (const at of [26, 38, 51]) assert.deepEqual(changes(store.recordEmail(await scan(domain, secondHopLame(base)), "monitor", at * HOUR)), [], `${at}h`);
    const held = readState(db, domain);
    assert.deepEqual([held.spfPolicy, held.spfLookupsUnread, held.spfLookupsPartial, held.spfUnreadTarget], ["unknown", true, true, target], "precondition: the tree was read up to the target");
    return { db, store };
  }

  it("(d) (P) only the first partial reading is a baseline: while the second hop stays lame, later tree and score changes are reported", async () => {
    const { db, store } = await partialBaseline(twoHop(voidsThenHop));
    const fixed = await step(store, secondHopLame(twoHop(cleanThenHop, "p=none")), 63);
    assert.deepEqual(
      fixed.list,
      [
        ["spf_fixed", "spf", "false", "true", "info"],
        ["dmarc_policy", "dmarc", "reject", "none", "high"],
        ["risk_resolved", "SPF_VOID_LOOKUPS", "SPF_VOID_LOOKUPS", null, "info"],
        ["score_drop", "score", fixed.before, fixed.after, "medium"]
      ],
      "63h: the target fixed its void includes and DMARC was weakened"
    );
    assert.deepEqual(
      (await step(store, secondHopLame(twoHop(voidsThenHop, "p=none")), 75)).list,
      [
        ["spf_broken", "spf", "true", "false", "high"],
        ["risk_new", "SPF_VOID_LOOKUPS", null, "SPF_VOID_LOOKUPS", "high"]
      ],
      "75h: the void includes are back"
    );
    const restored = await step(store, secondHopLame(twoHop(voidsThenHop)), 87);
    assert.deepEqual(
      restored.list,
      [
        ["dmarc_policy", "dmarc", "none", "reject", "info"],
        ["score_rise", "score", restored.before, restored.after, "info"]
      ],
      "87h: DMARC is back to reject"
    );
    assert.equal(readState(db, domain).spfLookupsPartial, true, "carried with the tree marker");
    // The first scan in which the whole chain answers is still the policy's baseline, and nothing waits after it.
    assert.deepEqual((await step(store, twoHop(voidsThenHop), 88)).list, [], "88h: the whole chain answers");
    const read = readState(db, domain);
    assert.deepEqual([read.spfPolicy, read.spfPolicyUnread, read.spfLookupsUnread, read.spfLookupsPartial, read.spfUnreadTarget], ["fail", undefined, undefined, undefined, undefined]);
  });

  it("(d) (R) a target that answered in the scan that set the markers was read there: the next partial reading is compared, score included", async () => {
    const { db, store } = await memoryStore();
    for (const at of [0, 12, 25]) assert.deepEqual(changes(store.recordEmail(await scan(domain, secondHopLame(twoHop(voidsThenHop))), "monitor", at * HOUR)), [], `${at}h`);
    const marked = readState(db, domain);
    assert.deepEqual(
      [marked.spfPolicy, marked.spfValid, marked.spfPolicyUnread, marked.spfLookupsUnread, marked.spfLookupsPartial, marked.spfUnreadTarget],
      ["unknown", false, true, true, true, target],
      "the scan that accepted the second hop's failure stored the tree up to the target"
    );
    const weakened = await step(store, secondHopLame(twoHop(voidsThenHop, "p=none")), 26);
    assert.deepEqual(weakened.list, [
      ["dmarc_policy", "dmarc", "reject", "none", "high"],
      ["score_drop", "score", weakened.before, weakened.after, "medium"]
    ]);
    const restored = await step(store, secondHopLame(twoHop(voidsThenHop)), 37);
    assert.deepEqual(restored.list, [
      ["dmarc_policy", "dmarc", "none", "reject", "info"],
      ["score_rise", "score", restored.before, restored.after, "info"]
    ]);
    const fixed = await step(store, secondHopLame(twoHop(cleanThenHop, "p=none")), 49);
    assert.deepEqual(fixed.list, [
      ["spf_fixed", "spf", "false", "true", "info"],
      ["dmarc_policy", "dmarc", "reject", "none", "high"],
      ["risk_resolved", "SPF_VOID_LOOKUPS", "SPF_VOID_LOOKUPS", null, "info"],
      ["score_drop", "score", fixed.before, fixed.after, "medium"]
    ]);
  });

  it("(d) (S) after the partial baseline, void includes the domain's own record adds while it still delegates are reported", async () => {
    const base = twoHop(cleanThenHop);
    const { store } = await partialBaseline(base);
    const own = { ...base, txt: { ...base.txt, [domain]: [`v=spf1 include:a.voids.net include:b.voids.net include:c.voids.net redirect=${target}`] } };
    assert.deepEqual((await step(store, secondHopLame(own), 63)).list, [
      ["spf_broken", "spf", "true", "false", "high"],
      ["risk_new", "SPF_VOID_LOOKUPS", null, "SPF_VOID_LOOKUPS", "high"]
    ]);
  });

  // r12v-trust-awaited-domain-check-unpinned: only the awaited target answering at top level reads its part of the tree.
  const mailInclude = "_spf.mail.net";
  const includeAndRedirect = (base: Zones, includeRecord: string): Zones => ({
    ...base,
    txt: { ...base.txt, [domain]: [`v=spf1 include:${mailInclude} redirect=${target}`], [mailInclude]: [includeRecord] }
  });

  it("(d) (Q) a top-level include: next to the redirect= is not the awaited target: its tree and the score are compared while the target stays lame", async () => {
    const { store } = await acceptedLameFromStart(includeAndRedirect(zones, "v=spf1 ip4:192.0.2.0/24 -all"));
    const weakened = { ...zones, txt: { ...zones.txt, [`_dmarc.${domain}`]: [`v=DMARC1; p=none; rua=mailto:dmarc@${domain}`] } };
    const changed = await step(store, lame(includeAndRedirect(weakened, "v=spf1 include:a.voids.net include:b.voids.net include:c.voids.net -all")), 26);
    assert.deepEqual(changed.list, [
      ["spf_broken", "spf", "true", "false", "high"],
      ["dmarc_policy", "dmarc", "reject", "none", "high"],
      ["risk_new", "SPF_VOID_LOOKUPS", null, "SPF_VOID_LOOKUPS", "high"],
      ["score_drop", "score", changed.before, changed.after, "medium"]
    ]);
  });

  it("(d) (T) a marking scan in which only that include answered did not read the target: the first partial reading is still a baseline", async () => {
    const base = includeAndRedirect(twoHop(voidsThenHop), "v=spf1 ip4:192.0.2.0/24 -all");
    const { db } = await partialBaseline(base);
    assert.equal(readState(db, domain).spfValid, false, "the target's three void lookups are the baseline, not spf_broken");
  });

  // r11-trust-docsnotes-first-read-overclaim: pins the scope the README gives the target's first answer.
  it("the scan that first reads the target still reports findings of the domain's own record and changes to other components", async () => {
    const cases: Array<[label: string, txt: Record<string, string[]>, expected: Array<Array<string | null>>]> = [
      ["a second apex record", { [domain]: [`v=spf1 redirect=${target}`, "v=spf1 ~all"] }, [["risk_new", "SPF_MULTIPLE_RECORDS", null, "SPF_MULTIPLE_RECORDS", "critical"]]],
      ["DMARC p=reject -> p=none", { [`_dmarc.${domain}`]: ["v=DMARC1; p=none"] }, [["dmarc_policy", "dmarc", "reject", "none", "high"]]]
    ];
    for (const [label, txt, expected] of cases) {
      const { store } = await acceptedLameFromStart();
      assert.deepEqual(changes(store.recordEmail(await scan(domain, { ...zones, txt: { ...zones.txt, ...txt } }), "monitor", 26 * HOUR)), expected, label);
    }
  });
});

// ---------------------------------------------------------------------------
// Repository hygiene in this group's files
// ---------------------------------------------------------------------------

describe("docblocks", () => {
  it("no docblock in the trust group's files is stacked on another, where it would document nothing", () => {
    const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "src");
    for (const file of ["store/scanStore.ts", "tools/comprehensiveAudit.ts", "tools/verifyEmailInfrastructure.ts", "tools/bulk.ts", "lib/scoring.ts", "lib/dmarc.ts", "lib/spf.ts"]) {
      const source = readFileSync(path.join(root, file), "utf8");
      assert.doesNotMatch(source, /\*\/\s*\n\s*\/\*\*/, `${file} has a docblock directly followed by another`);
    }
  });
});
