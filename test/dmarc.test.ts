import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { evaluateDmarc, parseDmarcRecord } from "../src/lib/dmarc.js";
import type { DnsClient } from "../src/lib/dns.js";

function fakeDns(zones: Record<string, string[]>): DnsClient {
  return {
    txt: async (name: string) => ({ records: zones[name.toLowerCase()] ?? [], nxdomain: !(name.toLowerCase() in zones), error: null, durationMs: 1 })
  } as unknown as DnsClient;
}

describe("parseDmarcRecord", () => {
  it("parses tags and validates values", () => {
    const parsed = parseDmarcRecord("v=DMARC1; p=reject; sp=quarantine; pct=50; rua=mailto:a@example.com; adkim=s; aspf=r; ri=3600");
    assert.equal(parsed.errors.length, 0);
    assert.equal(parsed.tags.p, "reject");
    assert.equal(parsed.tags.pct, "50");
  });

  it("reports invalid tags and ordering", () => {
    const parsed = parseDmarcRecord("p=none; v=DMARC1; pct=150; adkim=x");
    assert.ok(parsed.errors.some((e) => e.includes("must appear first")));
    assert.ok(parsed.errors.some((e) => e.includes("pct")));
    assert.ok(parsed.errors.some((e) => e.includes("adkim")));
  });
});

describe("evaluateDmarc", () => {
  it("evaluates a fully enforced policy", async () => {
    const dns = fakeDns({ "_dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"] });
    const result = await evaluateDmarc("example.com", "example.com", dns);
    assert.equal(result.found, true);
    assert.equal(result.policy, "reject");
    assert.equal(result.enforcement, "full");
    assert.equal(result.valid, true);
    assert.equal(result.rua[0]?.external, false);
    assert.ok(!result.findings.some((f) => f.code === "DMARC_POLICY_NONE"));
  });

  it("falls back to the organizational domain and applies sp=", async () => {
    const dns = fakeDns({ "_dmarc.example.com": ["v=DMARC1; p=reject; sp=none; rua=mailto:dmarc@example.com"] });
    const result = await evaluateDmarc("mail.example.com", "example.com", dns);
    assert.equal(result.inheritedFromOrganizationalDomain, true);
    assert.equal(result.location, "_dmarc.example.com");
    assert.equal(result.effectivePolicy, "none");
    assert.equal(result.enforcement, "none");
    assert.ok(result.findings.some((f) => f.code === "DMARC_SUBDOMAIN_POLICY_WEAKER"));
  });

  it("checks external report destination authorization", async () => {
    const dns = fakeDns({
      "_dmarc.example.com": ["v=DMARC1; p=quarantine; pct=80; rua=mailto:reports@dmarcvendor.test,mailto:x@unauthorized.test"],
      "example.com._report._dmarc.dmarcvendor.test": ["v=DMARC1"]
    });
    const result = await evaluateDmarc("example.com", "example.com", dns);
    assert.equal(result.enforcement, "partial");
    assert.equal(result.rua.find((d) => d.domain === "dmarcvendor.test")?.authorized, true);
    assert.equal(result.rua.find((d) => d.domain === "unauthorized.test")?.authorized, false);
    assert.ok(result.findings.some((f) => f.code === "DMARC_EXTERNAL_REPORT_UNAUTHORIZED"));
    assert.ok(result.findings.some((f) => f.code === "DMARC_PCT_BELOW_100"));
  });

  it("authorizes external reports against the domain that published the record", async () => {
    // RFC 7489 section 7.1: mail.example.com publishes its own policy, so the
    // vendor must authorize mail.example.com, not the organizational domain.
    const own = fakeDns({
      "_dmarc.mail.example.com": ["v=DMARC1; p=reject; rua=mailto:reports@dmarcvendor.test"],
      "mail.example.com._report._dmarc.dmarcvendor.test": ["v=DMARC1"]
    });
    const ownResult = await evaluateDmarc("mail.example.com", "example.com", own);
    assert.equal(ownResult.inheritedFromOrganizationalDomain, false);
    assert.equal(ownResult.rua[0]?.authorized, true);
    assert.ok(!ownResult.findings.some((f) => f.code === "DMARC_EXTERNAL_REPORT_UNAUTHORIZED"));

    // When the record is inherited from the organizational domain, that is the
    // domain the vendor must authorize, and the remediation names it.
    const inherited = fakeDns({
      "_dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:reports@dmarcvendor.test"],
      "mail.example.com._report._dmarc.dmarcvendor.test": ["v=DMARC1"]
    });
    const inheritedResult = await evaluateDmarc("mail.example.com", "example.com", inherited);
    assert.equal(inheritedResult.inheritedFromOrganizationalDomain, true);
    assert.equal(inheritedResult.rua[0]?.authorized, false);
    const finding = inheritedResult.findings.find((f) => f.code === "DMARC_EXTERNAL_REPORT_UNAUTHORIZED");
    assert.match(finding?.recommendation ?? "", /example\.com\._report\._dmarc\.dmarcvendor\.test/);
    assert.doesNotMatch(finding?.recommendation ?? "", /mail\.example\.com\._report/);
  });

  it("reports a failed organizational-domain lookup instead of asserting absence", async () => {
    const errored: DnsClient = {
      txt: async (name: string) =>
        name.toLowerCase() === "_dmarc.example.com"
          ? { records: [], nxdomain: false, error: { code: "ESERVFAIL", message: "servfail" }, durationMs: 1 }
          : { records: [], nxdomain: false, error: null, durationMs: 1 }
    } as unknown as DnsClient;
    const result = await evaluateDmarc("MAIL.Example.com", "example.com", errored);
    assert.equal(result.found, false);
    const dnsError = result.findings.find((f) => f.code === "DMARC_DNS_ERROR");
    assert.match(dnsError?.message ?? "", /_dmarc\.example\.com failed \(ESERVFAIL\)/);
    const missing = result.findings.find((f) => f.code === "DMARC_MISSING");
    assert.equal(missing?.severity, "medium", "absence is unconfirmed, so it is not reported as a high-severity fact");
    assert.match(missing?.message ?? "", /unconfirmed/);
    assert.equal(result.queriedName, "_dmarc.mail.example.com", "the domain is normalised to lower case");

    const clean = await evaluateDmarc("mail.example.com", "example.com", fakeDns({}));
    assert.equal(clean.findings.find((f) => f.code === "DMARC_MISSING")?.severity, "high");
    assert.ok(!clean.findings.some((f) => f.code === "DMARC_DNS_ERROR"));
  });

  it("flags missing, duplicate and monitoring-only records", async () => {
    const missing = await evaluateDmarc("none.example", "none.example", fakeDns({}));
    assert.equal(missing.found, false);
    assert.ok(missing.findings.some((f) => f.code === "DMARC_MISSING"));
    const dup = await evaluateDmarc("dup.example", "dup.example", fakeDns({ "_dmarc.dup.example": ["v=DMARC1; p=none", "v=DMARC1; p=reject"] }));
    assert.equal(dup.valid, false);
    assert.ok(dup.findings.some((f) => f.code === "DMARC_MULTIPLE_RECORDS"));
    assert.ok(dup.findings.some((f) => f.code === "DMARC_POLICY_NONE"));
    assert.ok(dup.findings.some((f) => f.code === "DMARC_NO_RUA"));
  });
});
