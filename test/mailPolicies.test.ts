import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { DnsClient } from "../src/lib/dns.js";
import { evaluateBimi, evaluateMtaSts, evaluateTlsRpt } from "../src/lib/mailPolicies.js";

function fakeDns(zones: Record<string, string[]>): DnsClient {
  return {
    txt: async (name: string) => ({ records: zones[name.toLowerCase()] ?? [], nxdomain: !(name.toLowerCase() in zones), error: null, durationMs: 1 })
  } as unknown as DnsClient;
}

const fetchOptions = { timeoutMs: 500, userAgent: "test", allowPrivate: false };

describe("TLS-RPT and BIMI", () => {
  it("parses rua destinations and BIMI logo / VMC tags", async () => {
    const dns = fakeDns({
      "_smtp._tls.example.com": ["v=TLSRPTv1; rua=mailto:tls@example.com, https://reports.example.com/tlsrpt"],
      "default._bimi.example.com": ["v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"]
    });
    const tlsRpt = await evaluateTlsRpt("example.com", dns);
    assert.equal(tlsRpt.found, true);
    assert.deepEqual(tlsRpt.rua, ["mailto:tls@example.com", "https://reports.example.com/tlsrpt"]);
    assert.equal(tlsRpt.findings.length, 0);
    const bimi = await evaluateBimi("example.com", dns);
    assert.equal(bimi.found, true);
    assert.equal(bimi.logoUrl, "https://example.com/logo.svg");
    assert.equal(bimi.vmcUrl, "https://example.com/vmc.pem");
    assert.equal(bimi.findings.length, 0);
  });

  it("flags a TLS-RPT record without rua and a BIMI logo that is not https", async () => {
    const dns = fakeDns({
      "_smtp._tls.example.com": ["v=TLSRPTv1"],
      "default._bimi.example.com": ["v=BIMI1; l=http://example.com/logo.svg"]
    });
    const tlsRpt = await evaluateTlsRpt("example.com", dns);
    assert.ok(tlsRpt.findings.some((f) => f.code === "TLS_RPT_NO_RUA"));
    const bimi = await evaluateBimi("example.com", dns);
    assert.ok(bimi.findings.some((f) => f.code === "BIMI_LOGO_NOT_HTTPS"));
    assert.ok(bimi.findings.some((f) => f.code === "BIMI_NO_VMC"));
    const none = await evaluateTlsRpt("example.com", fakeDns({}));
    assert.ok(none.findings.some((f) => f.code === "TLS_RPT_MISSING"));
  });
});

describe("evaluateMtaSts", () => {
  it("returns early without a record and never leaves a rejecting MX promise unhandled", async () => {
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown): void => {
      unhandled.push(reason);
    };
    process.on("unhandledRejection", onUnhandled);
    try {
      const mx = Promise.reject(new Error("mx failed"));
      const result = await evaluateMtaSts("example.com", mx, fakeDns({}), fetchOptions);
      assert.equal(result.found, false);
      assert.ok(result.findings.some((f) => f.code === "MTA_STS_MISSING"));
      await new Promise((resolve) => setTimeout(resolve, 20));
      assert.deepEqual(unhandled, []);
    } finally {
      process.off("unhandledRejection", onUnhandled);
    }
  });
});

describe("evaluateMtaSts lookup failures", () => {
  it("treats a failed TXT lookup as unevaluated rather than missing", async () => {
    const dns = { txt: async () => ({ records: [], nxdomain: false, error: { code: "ESERVFAIL", message: "x" }, durationMs: 1 }) } as unknown as DnsClient;
    const result = await evaluateMtaSts("example.com", [], dns, fetchOptions);
    assert.ok(result.findings.some((f) => f.code === "MTA_STS_DNS_ERROR"));
    assert.ok(!result.findings.some((f) => f.code === "MTA_STS_MISSING"));
    assert.equal(result.policy.failure, "transient");
  });
});
