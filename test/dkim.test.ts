import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { describe, it } from "node:test";
import { DEFAULT_DKIM_SELECTORS, decodeDkimKey, evaluateDkim, isDkimRecord, normalizeSelectors, parseDkimTags } from "../src/lib/dkim.js";
import type { DnsClient } from "../src/lib/dns.js";

function rsaPublicKeyBase64(bits: number): string {
  const { publicKey } = generateKeyPairSync("rsa", { modulusLength: bits });
  return publicKey.export({ type: "spki", format: "der" }).toString("base64");
}

function fakeDns(txt: Record<string, string[]>, cname: Record<string, string[]> = {}): DnsClient {
  return {
    txt: async (name: string) => ({ records: txt[name.toLowerCase()] ?? [], nxdomain: false, error: null, durationMs: 1 }),
    cname: async (name: string) => ({ records: cname[name.toLowerCase()] ?? [], nxdomain: false, error: null, durationMs: 1 })
  } as unknown as DnsClient;
}

/** Like fakeDns, but names absent from both maps answer NXDOMAIN (the common case for probed selectors); counts queries. */
function countingDns(txt: Record<string, string[]>, cname: Record<string, string[]> = {}): DnsClient & { calls: string[] } {
  const calls: string[] = [];
  const exists = (name: string): boolean => name in txt || name in cname;
  return {
    calls,
    txt: async (name: string) => {
      calls.push(`TXT ${name}`);
      const key = name.toLowerCase();
      return { records: txt[key] ?? [], nxdomain: !exists(key), error: null, durationMs: 1 };
    },
    cname: async (name: string) => {
      calls.push(`CNAME ${name}`);
      const key = name.toLowerCase();
      return { records: cname[key] ?? [], nxdomain: !exists(key), error: null, durationMs: 1 };
    }
  } as unknown as DnsClient & { calls: string[] };
}

describe("dkim helpers", () => {
  it("normalizes and dedupes selectors", () => {
    assert.deepEqual(normalizeSelectors([" Google ", "google", "selector1._domainkey.example.com", "bad selector", ""]), ["google", "selector1"]);
  });

  it("parses tags and recognizes records", () => {
    const tags = parseDkimTags("v=DKIM1; k=rsa; t=y; p=MIIB");
    assert.equal(tags.k, "rsa");
    assert.equal(tags.t, "y");
    assert.equal(isDkimRecord("v=DKIM1; p=abc"), true);
    assert.equal(isDkimRecord("v=spf1 -all"), false);
  });

  it("decodes RSA key length and ed25519", () => {
    assert.equal(decodeDkimKey("rsa", rsaPublicKeyBase64(2048)).bits, 2048);
    assert.equal(decodeDkimKey("rsa", rsaPublicKeyBase64(1024)).bits, 1024);
    assert.equal(decodeDkimKey("ed25519", Buffer.alloc(32).toString("base64")).bits, 256);
    assert.ok(decodeDkimKey("rsa", "notakey").error);
  });
});

describe("evaluateDkim", () => {
  it("finds keys, identifies providers and flags weak / revoked / testing keys", async () => {
    const strong = rsaPublicKeyBase64(2048);
    const weak = rsaPublicKeyBase64(1024);
    const dns = fakeDns(
      {
        "google._domainkey.example.com": [`v=DKIM1; k=rsa; p=${strong}`],
        "k1._domainkey.example.com": [`v=DKIM1; k=rsa; t=y; p=${weak}`],
        "old._domainkey.example.com": ["v=DKIM1; k=rsa; p="]
      },
      { "k1._domainkey.example.com": ["dkim.mcsv.net"] }
    );
    const result = await evaluateDkim("example.com", ["google", "k1", "old", "missing"], dns);
    assert.equal(result.found, true);
    assert.deepEqual(result.checkedSelectors, ["google", "k1", "old", "missing"]);
    const google = result.selectors.find((s) => s.selector === "google");
    assert.equal(google?.keyBits, 2048);
    assert.equal(google?.provider, "Google Workspace");
    const k1 = result.selectors.find((s) => s.selector === "k1");
    assert.equal(k1?.keyBits, 1024);
    assert.equal(k1?.testing, true);
    assert.equal(k1?.provider, "Mailchimp");
    assert.deepEqual(result.weakKeys, ["k1"]);
    assert.equal(result.selectors.find((s) => s.selector === "old")?.revoked, true);
    assert.equal(result.selectors.find((s) => s.selector === "missing")?.found, false);
    assert.ok(result.findings.some((f) => f.code === "DKIM_KEY_WEAK"));
    assert.ok(result.findings.some((f) => f.code === "DKIM_TESTING_MODE"));
    assert.ok(result.findings.some((f) => f.code === "DKIM_KEY_REVOKED"));
  });

  it("reports when nothing is found", async () => {
    const result = await evaluateDkim("example.com", ["google"], fakeDns({}));
    assert.equal(result.found, false);
    assert.ok(result.findings.some((f) => f.code === "DKIM_NOT_FOUND"));
  });

  it("spends one query on NXDOMAIN selectors and two on names that exist", async () => {
    const strong = rsaPublicKeyBase64(2048);
    const dns = countingDns(
      { "google._domainkey.example.com": [`v=DKIM1; k=rsa; p=${strong}`], "nodata._domainkey.example.com": [] },
      { "nodata._domainkey.example.com": ["dkim.mcsv.net"], "google._domainkey.example.com": [] }
    );
    const result = await evaluateDkim("example.com", ["google", "nodata", "missing"], dns);
    assert.equal(result.selectors.find((s) => s.selector === "google")?.found, true);
    assert.equal(result.selectors.find((s) => s.selector === "nodata")?.provider, "Mailchimp", "a NODATA name still yields its CNAME vendor");
    assert.equal(result.selectors.find((s) => s.selector === "missing")?.found, false);
    assert.deepEqual(
      dns.calls.filter((c) => c.endsWith("missing._domainkey.example.com")),
      ["TXT missing._domainkey.example.com"]
    );
    assert.equal(dns.calls.filter((c) => c.startsWith("CNAME")).length, 2);

    const empty = countingDns({});
    await evaluateDkim("example.com", DEFAULT_DKIM_SELECTORS, empty);
    assert.equal(empty.calls.length, DEFAULT_DKIM_SELECTORS.length, "an unsigned domain costs one query per selector, not two");
  });

  it("stops probing once the owning call is aborted", async () => {
    const controller = new AbortController();
    controller.abort();
    const dns = countingDns({});
    await assert.rejects(() => evaluateDkim("example.com", DEFAULT_DKIM_SELECTORS, dns, controller.signal), /abort/i);
    assert.equal(dns.calls.length, 0);
  });
});

describe("evaluateDkim lookup failures", () => {
  function failingDns(failing: string[], txt: Record<string, string[]> = {}): DnsClient {
    return {
      txt: async (name: string) => {
        const key = name.toLowerCase();
        if (failing.includes(key)) return { records: [], nxdomain: false, error: { code: "ESERVFAIL", message: "server failure" }, durationMs: 1 };
        return { records: txt[key] ?? [], nxdomain: !(key in txt), error: null, durationMs: 1 };
      },
      cname: async () => ({ records: [], nxdomain: true, error: null, durationMs: 1 })
    } as unknown as DnsClient;
  }

  it("marks a selector whose lookup failed as unchecked instead of not found", async () => {
    const key = rsaPublicKeyBase64(2048);
    const dns = failingDns(["k1._domainkey.example.com"], { "google._domainkey.example.com": [`v=DKIM1; k=rsa; p=${key}`] });
    const result = await evaluateDkim("example.com", ["google", "k1", "selector1"], dns);
    const bySelector = new Map(result.selectors.map((s) => [s.selector, s]));
    assert.equal(bySelector.get("k1")?.error, "ESERVFAIL");
    assert.equal(bySelector.get("k1")?.found, false);
    assert.equal(bySelector.get("selector1")?.error, null, "an NXDOMAIN answer is a real answer");
    const finding = result.findings.find((f) => f.code === "DKIM_DNS_ERROR");
    assert.equal(finding?.severity, "low", "a key was still found");
    assert.ok(!result.findings.some((f) => f.code === "DKIM_NOT_FOUND"));
  });

  it("does not claim DKIM is missing when every lookup failed", async () => {
    const dns = failingDns(["google._domainkey.example.com", "k1._domainkey.example.com"]);
    const result = await evaluateDkim("example.com", ["google", "k1"], dns);
    assert.equal(result.findings.find((f) => f.code === "DKIM_DNS_ERROR")?.severity, "medium");
    assert.ok(!result.findings.some((f) => f.code === "DKIM_NOT_FOUND"));
  });
});
