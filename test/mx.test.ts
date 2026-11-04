import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { DnsClient, MxRecord } from "../src/lib/dns.js";
import { evaluateMx, identifyMailProvider } from "../src/lib/mx.js";

function fakeDns(mx: MxRecord[], addresses: Record<string, string[]> = {}): DnsClient {
  return {
    mx: async () => ({ records: mx, nxdomain: false, error: null, durationMs: 1 }),
    addresses: async (name: string) => ({ v4: addresses[name.toLowerCase()] ?? [], v6: [], errors: [] })
  } as unknown as DnsClient;
}

describe("evaluateMx", () => {
  it("flags IPv4 and IPv6 literal exchanges and ignores out-of-range dotted quads", async () => {
    const v4 = await evaluateMx("example.com", fakeDns([{ exchange: "192.0.2.10", priority: 10 }], { "192.0.2.10": ["192.0.2.10"] }));
    assert.ok(v4.findings.some((f) => f.code === "MX_IP_LITERAL"));
    const v6 = await evaluateMx("example.com", fakeDns([{ exchange: "2001:db8::25", priority: 10 }]));
    assert.ok(
      v6.findings.some((f) => f.code === "MX_IP_LITERAL"),
      "an IPv6 literal is an IP literal too"
    );
    const bogus = await evaluateMx("example.com", fakeDns([{ exchange: "999.999.999.999", priority: 10 }]));
    assert.ok(!bogus.findings.some((f) => f.code === "MX_IP_LITERAL"), "999.999.999.999 is a (bad) hostname, not an address");
    const host = await evaluateMx("example.com", fakeDns([{ exchange: "mx.example.com", priority: 10 }], { "mx.example.com": ["192.0.2.1"] }));
    assert.ok(!host.findings.some((f) => f.code === "MX_IP_LITERAL"));
    const tagged = await evaluateMx("example.com", fakeDns([{ exchange: "[IPv6:2001:db8::25]", priority: 10 }]));
    assert.ok(
      tagged.findings.some((f) => f.code === "MX_IP_LITERAL"),
      "the RFC 5321 tagged literal form is an IP literal"
    );
    const many = Array.from({ length: 10 }, (_, i) => ({ exchange: `mx${i}.example.com`, priority: i }));
    const beyondTen = await evaluateMx("example.com", fakeDns([...many, { exchange: "203.0.113.9", priority: 99 }]));
    assert.ok(
      beyondTen.findings.some((f) => f.code === "MX_IP_LITERAL"),
      "literals past the tenth record are still flagged"
    );
  });

  it("names vendors consistently with the SPF and DKIM tables", () => {
    assert.equal(identifyMailProvider("smtp.secureserver.net."), "GoDaddy");
    assert.equal(identifyMailProvider("mx.yandex.net"), "Yandex");
    assert.equal(identifyMailProvider("mx1.titan.email"), "Titan");
    assert.equal(identifyMailProvider("d123.a.ess.barracudanetworks.com"), "Barracuda");
    assert.equal(identifyMailProvider("aspmx.l.google.com"), "Google Workspace");
    assert.equal(identifyMailProvider("mail.unknown-host.example"), null);
  });
});
