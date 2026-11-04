import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { DnsClient } from "../src/lib/dns.js";
import { evaluateSpf, parseSpfRecord } from "../src/lib/spf.js";

function fakeDns(zones: Record<string, string[]>): DnsClient {
  return {
    txt: async (name: string) => ({ records: zones[name.toLowerCase()] ?? [], nxdomain: !(name.toLowerCase() in zones), error: null, durationMs: 1 })
  } as unknown as DnsClient;
}

describe("parseSpfRecord", () => {
  it("parses qualifiers, mechanisms, cidr and modifiers", () => {
    const parsed = parseSpfRecord("v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 include:_spf.google.com a mx:mail.example.com/24 -all redirect=other.example exp=explain.example");
    assert.equal(parsed.errors.length, 0);
    assert.deepEqual(
      parsed.mechanisms.map((m) => [m.qualifier, m.type, m.value]),
      [
        ["+", "ip4", "192.0.2.0/24"],
        ["+", "ip6", "2001:db8::/32"],
        ["+", "include", "_spf.google.com"],
        ["+", "a", null],
        ["+", "mx", "mail.example.com/24"],
        ["-", "all", null]
      ]
    );
    assert.deepEqual(
      parsed.modifiers.map((m) => [m.name, m.value]),
      [
        ["redirect", "other.example"],
        ["exp", "explain.example"]
      ]
    );
  });

  it("reports syntax problems", () => {
    const parsed = parseSpfRecord("v=spf1 include: ip4:999.1.1 bogus ~all");
    assert.ok(parsed.errors.some((e) => e.includes('"include"')));
    assert.ok(parsed.errors.some((e) => e.includes("ip4")));
    assert.ok(parsed.errors.some((e) => e.includes("bogus")));
  });
});

describe("evaluateSpf", () => {
  it("counts lookups recursively and detects senders", async () => {
    const dns = fakeDns({
      "example.com": ["v=spf1 include:_spf.google.com include:sendgrid.net a mx -all"],
      "_spf.google.com": ["v=spf1 include:_netblocks.google.com include:_netblocks2.google.com ~all"],
      "_netblocks.google.com": ["v=spf1 ip4:35.190.247.0/24 ~all"],
      "_netblocks2.google.com": ["v=spf1 ip6:2001:4860:4000::/36 ~all"],
      "sendgrid.net": ["v=spf1 ip4:167.89.0.0/17 ~all"]
    });
    const result = await evaluateSpf("example.com", dns);
    assert.equal(result.found, true);
    assert.equal(result.allPolicy, "fail");
    assert.equal(result.lookupCount, 6);
    assert.equal(result.lookupLimitExceeded, false);
    assert.deepEqual(result.detectedSenders, ["Google Workspace", "SendGrid"]);
    assert.equal(result.valid, true);
    assert.equal(result.includeTree.length, 2);
  });

  it("flags +all, missing records and multiple records", async () => {
    const plusAll = await evaluateSpf("bad.example", fakeDns({ "bad.example": ["v=spf1 +all"] }));
    assert.ok(plusAll.findings.some((f) => f.code === "SPF_PASS_ALL" && f.severity === "critical"));
    const missing = await evaluateSpf("none.example", fakeDns({ "none.example": ["some other txt"] }));
    assert.equal(missing.found, false);
    assert.ok(missing.findings.some((f) => f.code === "SPF_MISSING"));
    const multi = await evaluateSpf("multi.example", fakeDns({ "multi.example": ["v=spf1 -all", "v=spf1 ~all"] }));
    assert.equal(multi.valid, false);
    assert.ok(multi.findings.some((f) => f.code === "SPF_MULTIPLE_RECORDS"));
  });

  it("detects too many lookups, void lookups and circular includes", async () => {
    const zones: Record<string, string[]> = { "loop.example": ["v=spf1 include:a.example include:void1.example include:void2.example include:void3.example ptr -all"] };
    zones["a.example"] = ["v=spf1 include:b.example a mx exists:x.example include:c.example include:d.example include:e.example -all"];
    zones["b.example"] = ["v=spf1 include:a.example -all"];
    for (const z of ["c", "d", "e"]) zones[`${z}.example`] = ["v=spf1 ip4:192.0.2.1 -all"];
    const result = await evaluateSpf("loop.example", fakeDns(zones));
    assert.equal(result.lookupLimitExceeded, true);
    assert.equal(result.voidLookups, 3);
    assert.ok(result.findings.some((f) => f.code === "SPF_TOO_MANY_LOOKUPS"));
    assert.ok(result.findings.some((f) => f.code === "SPF_VOID_LOOKUPS"));
    assert.ok(result.findings.some((f) => f.code === "SPF_PTR_DEPRECATED"));
    const a = result.includeTree.find((n) => n.domain === "a.example");
    const b = a?.children.find((n) => n.domain === "b.example");
    assert.ok(b?.children.some((n) => n.error === "circular include detected"));
    const loop = result.findings.find((f) => f.code === "SPF_CIRCULAR_INCLUDE");
    assert.equal(loop?.severity, "high");
    assert.match(loop?.message ?? "", /a\.example/);
    assert.equal(result.valid, false);
  });

  it("invalidates a record whose redirect points back at itself", async () => {
    const result = await evaluateSpf("self.example", fakeDns({ "self.example": ["v=spf1 redirect=self.example"] }));
    assert.ok(result.findings.some((f) => f.code === "SPF_CIRCULAR_INCLUDE"));
    assert.equal(result.valid, false);
  });

  it("counts a shared include once per branch instead of calling it circular", async () => {
    const dns = fakeDns({
      "root.example": ["v=spf1 include:a.example include:b.example -all"],
      "a.example": ["v=spf1 include:shared.example -all"],
      "b.example": ["v=spf1 include:shared.example -all"],
      "shared.example": ["v=spf1 include:x.example include:y.example include:z.example -all"],
      "x.example": ["v=spf1 ip4:192.0.2.1 -all"],
      "y.example": ["v=spf1 ip4:192.0.2.2 -all"],
      "z.example": ["v=spf1 ip4:192.0.2.3 -all"]
    });
    const result = await evaluateSpf("root.example", dns);
    // RFC 7208: 2 (root) + 1 (a) + 1 (b) + 3 (shared via a) + 3 (shared via b) = 10.
    assert.equal(result.lookupCount, 10);
    assert.equal(result.lookupLimitExceeded, false);
    const flatten = (nodes: typeof result.includeTree): string[] => nodes.flatMap((n) => [n.error ?? "ok", ...flatten(n.children)]);
    assert.ok(!flatten(result.includeTree).includes("circular include detected"));
    const b = result.includeTree.find((n) => n.domain === "b.example");
    assert.equal(b?.children[0]?.record, "v=spf1 include:x.example include:y.example include:z.example -all", "the shared include is expanded on the second branch too");
    assert.equal(
      result.findings.some((f) => f.code === "SPF_LOOKUPS_NEAR_LIMIT"),
      true
    );
  });

  it("inherits the terminal policy through redirect=", async () => {
    const dns = fakeDns({
      "redir.example": ["v=spf1 redirect=_spf.redir.example"],
      "_spf.redir.example": ["v=spf1 ip4:203.0.113.0/24 ~all"]
    });
    const result = await evaluateSpf("redir.example", dns);
    assert.equal(result.redirect, "_spf.redir.example");
    assert.equal(result.allPolicy, "softfail");
    assert.equal(result.allQualifier, "~");
    assert.equal(result.lookupCount, 1);
    assert.ok(!result.findings.some((f) => f.code === "SPF_NO_ALL"));
  });
});

describe("evaluateSpf lookup failures", () => {
  it("reports a failed include lookup as a DNS error, not a void lookup", async () => {
    const dns = {
      txt: async (name: string) => {
        const key = name.toLowerCase();
        if (key === "broken.example") return { records: [], nxdomain: false, error: { code: "ETIMEOUT", message: "timeout" }, durationMs: 1 };
        const zones: Record<string, string[]> = { "top.example": ["v=spf1 include:broken.example include:ok.example -all"], "ok.example": ["v=spf1 ip4:192.0.2.1 -all"] };
        return { records: zones[key] ?? [], nxdomain: !(key in zones), error: null, durationMs: 1 };
      }
    } as unknown as DnsClient;
    const result = await evaluateSpf("top.example", dns);
    assert.equal(result.voidLookups, 0);
    assert.equal(result.includeTree.find((n) => n.domain === "broken.example")?.error, "DNS error ETIMEOUT");
    const finding = result.findings.find((f) => f.code === "SPF_INCLUDE_DNS_ERROR");
    assert.equal(finding?.severity, "medium");
    assert.ok(finding?.message.includes("broken.example (ETIMEOUT)"));
  });
});
