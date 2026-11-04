import assert from "node:assert/strict";
import dns from "node:dns";
import { describe, it } from "node:test";
import type { DnsClient, MxRecord } from "../src/lib/dns.js";
import { evaluateBimi, evaluateMtaSts, evaluateTlsRpt } from "../src/lib/mailPolicies.js";
import { evaluateMx } from "../src/lib/mx.js";
import { scoreEmail } from "../src/lib/scoring.js";
import { evaluateSpf } from "../src/lib/spf.js";

const TIMEOUT = { code: "ETIMEOUT", message: "timeout" };

/** TXT zones plus a set of names whose lookups fail; everything else is NXDOMAIN. */
function txtDns(zones: Record<string, string[]>, failing: string[] = [], delays: Record<string, number> = {}): DnsClient {
  return {
    txt: async (name: string) => {
      const key = name.toLowerCase();
      const delay = delays[key];
      if (delay) await new Promise((resolve) => setTimeout(resolve, delay));
      if (failing.includes(key)) return { records: [], nxdomain: false, error: TIMEOUT, durationMs: 1 };
      return { records: zones[key] ?? [], nxdomain: !(key in zones), error: null, durationMs: 1 };
    }
  } as unknown as DnsClient;
}

describe("SPF lookup failures and redirects", () => {
  it("follows a redirect chain to the final all", async () => {
    const result = await evaluateSpf(
      "chain.example",
      txtDns({ "chain.example": ["v=spf1 redirect=_a.example"], "_a.example": ["v=spf1 ip4:192.0.2.0/24 redirect=_b.example"], "_b.example": ["v=spf1 -all"] })
    );
    assert.equal(result.allPolicy, "fail");
    assert.equal(result.allQualifier, "-");
  });

  it("a failed redirect target leaves the policy unknown (SPF_DNS_ERROR); a failed include does not", async () => {
    const redirect = await evaluateSpf("r.example", txtDns({ "r.example": ["v=spf1 redirect=_spf.r.example"] }, ["_spf.r.example"]));
    assert.ok(redirect.findings.some((f) => f.code === "SPF_DNS_ERROR"));
    const include = await evaluateSpf("i.example", txtDns({ "i.example": ["v=spf1 include:gone.example -all"] }, ["gone.example"]));
    assert.ok(include.findings.some((f) => f.code === "SPF_INCLUDE_DNS_ERROR"));
    assert.ok(!include.findings.some((f) => f.code === "SPF_DNS_ERROR"));
    assert.equal(include.allPolicy, "fail", "the domain's own policy is still known");
  });

  it("reports an unconfirmed absence at medium when the SPF lookup itself failed", async () => {
    const result = await evaluateSpf("down.example", txtDns({}, ["down.example"]));
    const missing = result.findings.find((f) => f.code === "SPF_MISSING");
    assert.equal(missing?.severity, "medium");
    assert.match(missing?.message ?? "", /unconfirmed/);
    assert.ok(result.findings.some((f) => f.code === "SPF_DNS_ERROR"));
  });

  it("spends the expansion budget in record order, whatever order the answers arrive in", async () => {
    // 6 includes x 5 nested includes = 36 targets > the 25-expansion budget; 10 nested targets are void.
    const zones: Record<string, string[]> = { "big.example": [`v=spf1 ${Array.from({ length: 6 }, (_, i) => `include:i${i}.example`).join(" ")} -all`] };
    for (let i = 0; i < 6; i++) zones[`i${i}.example`] = [`v=spf1 ${Array.from({ length: 5 }, (_, j) => `include:n${i}-${j}.example`).join(" ")} -all`];
    for (let i = 0; i < 6; i++) for (let j = 0; j < 5; j++) if ((i + j) % 3 !== 0) zones[`n${i}-${j}.example`] = ["v=spf1 ip4:192.0.2.1 -all"];
    const shapes = new Set<string>();
    for (let run = 0; run < 4; run++) {
      const delays: Record<string, number> = {};
      for (let i = 0; i < 6; i++) delays[`i${i}.example`] = ((i * 7 + run * 3) % 5) * 3;
      const result = await evaluateSpf("big.example", txtDns(zones, [], delays));
      shapes.add(JSON.stringify([result.voidLookups, result.lookupCount, result.includeTree.map((n) => n.children.map((c) => c.error ?? "ok"))]));
    }
    assert.equal(shapes.size, 1, "identical DNS answers always produce the identical tree");
  });
});

function mxDns(mx: MxRecord[], addresses: Record<string, string[] | "fail">, mxError = false): DnsClient {
  return {
    mx: async () => ({ records: mxError ? [] : mx, nxdomain: false, error: mxError ? TIMEOUT : null, durationMs: 1 }),
    addresses: async (name: string) => {
      const entry = addresses[name.toLowerCase()];
      if (entry === "fail") return { v4: [], v6: [], errors: [TIMEOUT, TIMEOUT] };
      return { v4: entry ?? [], v6: [], errors: [] };
    }
  } as unknown as DnsClient;
}

describe("MX lookup failures", () => {
  it("an exchange whose address lookup failed is unknown, not unresolvable", async () => {
    const result = await evaluateMx("a.example", mxDns([{ exchange: "aspmx.l.google.com", priority: 1 }], { "aspmx.l.google.com": "fail" }));
    const codes = result.findings.map((f) => f.code);
    assert.ok(codes.includes("MX_HOST_DNS_ERROR"));
    assert.ok(!codes.includes("MX_ALL_UNRESOLVABLE") && !codes.includes("MX_DANGLING"));
    assert.equal(result.records[0]?.lookupFailed, true);
    const mixed = await evaluateMx(
      "b.example",
      mxDns(
        [
          { exchange: "mx1.b.example", priority: 1 },
          { exchange: "mx2.b.example", priority: 2 },
          { exchange: "gone.b.example", priority: 3 }
        ],
        { "mx1.b.example": ["192.0.2.1"], "mx2.b.example": "fail" }
      )
    );
    const dangling = mixed.findings.find((f) => f.code === "MX_DANGLING");
    assert.match(dangling?.message ?? "", /^1 MX exchange/, "only the definitively unresolvable exchange is dangling");
  });

  it("does not count unknown exchanges against the score", () => {
    const base = {
      exists: true,
      disposable: false,
      spf: { found: false } as never,
      dkim: { found: false, selectors: [] },
      dmarc: { found: false } as never,
      mtaSts: { found: false, mode: null },
      tlsRpt: { found: false },
      bimi: { found: false }
    };
    const mxPoints = (records: Array<{ resolvable: boolean; lookupFailed?: boolean }>): number =>
      scoreEmail({ ...base, mx: { found: true, nullMx: false, usesImplicitA: false, records } } as never).breakdown.find((b) => b.component === "mx")?.points ?? -1;
    assert.equal(mxPoints([{ resolvable: false, lookupFailed: true }]), 20);
    assert.equal(mxPoints([{ resolvable: false }]), 2);
  });

  it("a failed MX query is not an absence, and a failed implicit-A fallback is not MX_MISSING", async () => {
    const failed = await evaluateMx("c.example", mxDns([], {}, true));
    const missing = failed.findings.find((f) => f.code === "MX_MISSING");
    assert.equal(missing?.severity, "medium");
    assert.equal(failed.usesImplicitA, false);
    assert.ok(failed.findings.some((f) => f.code === "MX_DNS_ERROR"));
    const fallback = await evaluateMx("d.example", mxDns([], { "d.example": "fail" }));
    const codes = fallback.findings.map((f) => f.code);
    assert.deepEqual(codes, ["MX_HOST_DNS_ERROR"]);
  });
});

describe("MTA-STS, TLS-RPT and BIMI lookup failures", () => {
  const options = { timeoutMs: 2000, userAgent: "test", allowPrivate: false };

  it("a policy host that does not exist is definitive once our resolver confirms NXDOMAIN", async (t) => {
    // The policy fetch resolves the host through the OS resolver (dns.lookup)
    // before the scripted a/aaaa check runs. Answer it here, so the test never
    // queries real DNS and does not depend on how an offline machine fails.
    const looked: string[] = [];
    t.mock.method(dns, "lookup", (host: string, _options: unknown, callback: (err: Error) => void) => {
      looked.push(host);
      process.nextTick(callback, Object.assign(new Error(`getaddrinfo ENOTFOUND ${host}`), { code: "ENOTFOUND", hostname: host }));
    });
    const domain = "no-policy-host-3f9c.invalid";
    const base = { txt: async () => ({ records: ["v=STSv1; id=1"], nxdomain: false, error: null, durationMs: 1 }) };
    const nx = {
      ...base,
      a: async () => ({ records: [], nxdomain: true, error: null, durationMs: 1 }),
      aaaa: async () => ({ records: [], nxdomain: true, error: null, durationMs: 1 })
    } as unknown as DnsClient;
    const confirmed = await evaluateMtaSts(domain, [], nx, options);
    assert.equal(confirmed.policy.failure, "definitive", confirmed.policy.error ?? "");
    const trouble = {
      ...base,
      a: async () => ({ records: [], nxdomain: false, error: TIMEOUT, durationMs: 1 }),
      aaaa: async () => ({ records: [], nxdomain: false, error: TIMEOUT, durationMs: 1 })
    } as unknown as DnsClient;
    const unconfirmed = await evaluateMtaSts(domain, [], trouble, options);
    assert.equal(unconfirmed.policy.failure, "transient", "resolver trouble is not proof the host is gone");
    assert.deepEqual(looked, [`mta-sts.${domain}`, `mta-sts.${domain}`], "both policy fetches went through the stubbed OS resolver");
  });

  it("reports failed TLS-RPT and BIMI lookups as errors, not as absent records", async () => {
    const dns = txtDns({}, ["_smtp._tls.e.example", "default._bimi.e.example"]);
    const tls = await evaluateTlsRpt("e.example", dns);
    assert.deepEqual(
      tls.findings.map((f) => f.code),
      ["TLS_RPT_DNS_ERROR"]
    );
    const bimi = await evaluateBimi("e.example", dns);
    assert.deepEqual(
      bimi.findings.map((f) => f.code),
      ["BIMI_DNS_ERROR"]
    );
  });
});
