import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { loadConfig } from "../src/config.js";
import { detectBlock } from "../src/lib/blockDetection.js";
import type { DnsClient } from "../src/lib/dns.js";
import { evaluateSpf } from "../src/lib/spf.js";
import { setLogLevel } from "../src/logger.js";
import { openDatabase } from "../src/store/db.js";
import { ScanStore, type EmailScanInput } from "../src/store/scanStore.js";
import { describeEmailStatus, verifyEmailInfrastructure } from "../src/tools/verifyEmailInfrastructure.js";

setLogLevel("silent");

const HOUR = 60 * 60 * 1000;
const TIMEOUT = { code: "ETIMEOUT", message: "timeout" };

async function memoryStore(): Promise<{ db: NonNullable<Awaited<ReturnType<typeof openDatabase>>>; store: ScanStore }> {
  const db = await openDatabase(":memory:");
  assert.ok(db);
  return { db, store: new ScanStore(db, { retentionDays: 30 }) };
}

interface Options {
  score?: number;
  mx?: Partial<EmailScanInput["mx"]>;
  dkimFound?: string[];
  dkimChecked?: string[];
  dkimErrored?: string[];
  risks?: Array<{ code: string; severity: string }>;
}

function email(domain: string, o: Options = {}): EmailScanInput {
  const found = o.dkimFound ?? ["google"];
  const checked = o.dkimChecked ?? ["google", "selector1", "k1"];
  const errored = new Set(o.dkimErrored ?? []);
  return {
    domain,
    score: o.score ?? 90,
    grade: "A",
    mx: {
      found: true,
      nullMx: false,
      provider: "Google Workspace",
      dnsError: null,
      usesImplicitA: false,
      records: [{ exchange: "aspmx.l.google.com", resolvable: true, lookupFailed: false }],
      ...o.mx
    },
    spf: { found: true, valid: true, allPolicy: "fail", includeChain: [] },
    dmarc: { found: true, effectivePolicy: "reject" },
    dkim: {
      checkedSelectors: checked,
      selectors: checked.map((selector) => ({ selector, found: !errored.has(selector) && found.includes(selector), revoked: false, error: errored.has(selector) ? "ESERVFAIL" : null }))
    },
    mtaSts: { policy: { fetched: false, mode: null, error: null, failure: null } },
    risks: o.risks ?? []
  } as unknown as EmailScanInput;
}

const lameHosts = (domain: string, records = [{ exchange: "mx.lame.net", resolvable: false, lookupFailed: true }], provider = "Google Workspace") =>
  email(domain, { risks: [{ code: "MX_HOST_DNS_ERROR", severity: "medium" }], mx: { provider, records } as never });

describe("MX host failures", () => {
  it("a lasting exchange lookup failure is eventually reported as unresolvable MX, once", async () => {
    const { store } = await memoryStore();
    store.recordEmail(email("lame.com"), "monitor", 0);
    assert.deepEqual(store.recordEmail(lameHosts("lame.com"), "monitor", 1 * HOUR), []);
    assert.deepEqual(store.recordEmail(lameHosts("lame.com"), "monitor", 12 * HOUR), []);
    const accepted = store.recordEmail(lameHosts("lame.com"), "monitor", 25 * HOUR);
    // The accepted reading also takes the MX points away (90 - 20 + 2).
    assert.deepEqual(
      accepted.map((c) => [c.change, c.subject, c.severity]),
      [
        ["risk_new", "MX_ALL_UNRESOLVABLE", "critical"],
        ["score_drop", "score", "medium"]
      ]
    );
    assert.equal(accepted.find((c) => c.change === "score_drop")?.newValue, "72");
    assert.deepEqual(store.recordEmail(lameHosts("lame.com"), "monitor", 26 * HOUR), [], "reported once");
    const recovered = store.recordEmail(email("lame.com"), "monitor", 27 * HOUR);
    assert.deepEqual(
      recovered.map((c) => [c.change, c.subject]),
      [
        ["risk_resolved", "MX_ALL_UNRESOLVABLE"],
        ["score_rise", "score"]
      ]
    );
  });

  it("a failing backup exchange does not hide a change of MX provider", async () => {
    const { store } = await memoryStore();
    store.recordEmail(email("mv.com"), "call", 1);
    const moved = lameHosts(
      "mv.com",
      [
        { exchange: "x.mail.protection.outlook.com", resolvable: true, lookupFailed: false },
        { exchange: "mx.lame.net", resolvable: false, lookupFailed: true }
      ],
      "Microsoft 365"
    );
    assert.deepEqual(
      store.recordEmail(moved, "call", 2).map((c) => [c.change, c.newValue]),
      [["mx_provider", "Microsoft 365"]]
    );
  });

  it("once a failure is accepted, a different failure starts a new streak and is held", async () => {
    const { store } = await memoryStore();
    store.recordEmail(email("st.com"), "monitor", 0);
    for (const at of [1, 12, 25, 30]) store.recordEmail(lameHosts("st.com"), "monitor", at * HOUR);
    const queryDown = email("st.com", { score: 70, risks: [{ code: "MX_DNS_ERROR", severity: "high" }], mx: { found: false, provider: null, dnsError: TIMEOUT, records: [] } as never });
    assert.deepEqual(store.recordEmail(queryDown, "monitor", 31 * HOUR), [], "a single timeout of the MX query is held, not accepted");
  });
});

describe("DKIM baselines", () => {
  it("an errored selector blocks DKIM and the score until DKIM is established", async () => {
    const { store } = await memoryStore();
    store.recordEmail(email("dk.com", { dkimFound: [], dkimErrored: ["google"], score: 76, risks: [{ code: "DKIM_DNS_ERROR", severity: "medium" }] }), "call", 1);
    const snapshot = store.history("dk.com").email;
    assert.equal(snapshot?.score, null);
    assert.ok(snapshot?.unverified.includes("dkim"));
    assert.ok(snapshot?.lookupsFailing.includes("dkim"));
  });

  it("a legacy state holding a custom selector is re-baselined, not reported", async () => {
    const { db, store } = await memoryStore();
    store.recordEmail(email("lg.com", { score: 76, dkimFound: ["acme"], dkimChecked: ["google", "acme"] }), "call", 1);
    const row = db.prepare("SELECT email_state FROM domains WHERE domain = 'lg.com'").get() as { email_state: string };
    const legacy = JSON.parse(row.email_state) as Record<string, unknown>;
    delete legacy.dkimProbed;
    delete legacy.scoreProbed;
    db.prepare("UPDATE domains SET email_state = ? WHERE domain = 'lg.com'").run(JSON.stringify(legacy));
    const next = store.recordEmail(email("lg.com", { score: 90, dkimFound: ["acme"], dkimChecked: ["google", "acme"], risks: [{ code: "DKIM_KEY_TOO_SHORT", severity: "high" }] }), "monitor", 2);
    assert.deepEqual(next, []);
  });
});

/** TXT zones; everything else answers NXDOMAIN. */
function txtDns(zones: Record<string, string[]>): DnsClient {
  return {
    txt: async (name: string) => ({ records: zones[name.toLowerCase()] ?? [], nxdomain: !(name.toLowerCase() in zones), error: null, durationMs: 1 })
  } as unknown as DnsClient;
}

describe("second-round analyzer fixes", () => {
  it("evaluates the same record whatever order the resolver returns the RRset in", async () => {
    const records = ["v=spf1 include:_spf.google.com ~all", "v=spf1 ip4:192.0.2.1 -all"];
    const a = await evaluateSpf("dup.example", txtDns({ "dup.example": records }));
    const b = await evaluateSpf("dup.example", txtDns({ "dup.example": [...records].reverse() }));
    assert.equal(a.allPolicy, b.allPolicy);
    assert.equal(a.record, b.record);
  });

  it("treats the passive Cloudflare detection script as an ordinary page, but still sees a challenge", () => {
    const page = '<html><body>Not found<script src="/cdn-cgi/challenge-platform/scripts/jsd/main.js"></script></body></html>';
    assert.equal(detectBlock(404, {}, page).blocked, false);
    const challenge = '<html><script src="/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1"></script></html>';
    assert.equal(detectBlock(403, {}, challenge).blocked, true);
  });

  it("describes failed lookups as unknown, never as missing", () => {
    const failed = describeEmailStatus({
      mx: { found: false, nullMx: false, usesImplicitA: false, dnsError: TIMEOUT },
      spf: { found: false },
      dmarc: { found: false },
      risks: [{ code: "SPF_DNS_ERROR" }, { code: "DMARC_DNS_ERROR" }],
      providers: { mailbox: null }
    } as never);
    assert.deepEqual(failed, { mx: "MX unknown (lookup failed)", spf: "unknown (lookup failed)", dmarc: "unknown (lookup failed)" });
    const noMx = describeEmailStatus({
      mx: { found: false, nullMx: false, usesImplicitA: false, dnsError: null },
      spf: { found: false },
      dmarc: { found: false },
      risks: [],
      providers: { mailbox: null }
    } as never);
    assert.equal(noMx.mx, "no MX", "a domain without MX is never described as 'MX present'");
  });

  it("probes the selectors already known for a domain on every email scan", async () => {
    const queried: string[] = [];
    const empty = async () => ({ records: [], nxdomain: false, error: null, durationMs: 1 });
    const dns = {
      exists: async () => ({ exists: true, nxdomain: false, error: null }),
      mx: empty,
      txt: async (name: string) => {
        queried.push(name);
        return { records: [], nxdomain: false, error: null, durationMs: 1 };
      },
      cname: empty,
      a: empty,
      aaaa: empty,
      addresses: async () => ({ v4: [], v6: [], errors: [] })
    } as unknown as DnsClient;
    await verifyEmailInfrastructure(
      { domain: "known-selectors.com", dkimSelectors: [], checkMtaSts: false },
      { config: loadConfig({}, []), dns, knownDkimSelectors: () => ["acme"] },
      { principal: { id: "p", plan: "local", label: "", source: "local" }, signal: new AbortController().signal, requestId: 1 }
    );
    assert.ok(queried.includes("acme._domainkey.known-selectors.com"));
  });
});
