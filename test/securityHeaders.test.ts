import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { analyzeSecurityHeaders } from "../src/lib/securityHeaders.js";

describe("analyzeSecurityHeaders", () => {
  it("grades a hardened response as A", () => {
    const report = analyzeSecurityHeaders(
      {
        "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
        "content-security-policy": "default-src 'self'; script-src 'self' 'nonce-abc'; frame-ancestors 'none'; upgrade-insecure-requests",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "camera=(), microphone=(), geolocation=()",
        "cross-origin-opener-policy": "same-origin",
        "cross-origin-resource-policy": "same-origin",
        server: "cloudflare"
      },
      { https: true, setCookies: ["session=abc; Secure; HttpOnly; SameSite=Lax"] }
    );
    assert.equal(report.score, 100);
    assert.equal(report.grade, "A");
    assert.equal(report.hsts.preload, true);
    assert.equal(report.csp.frameAncestors, true);
    assert.equal(report.cookies.secure, 1);
    assert.equal(report.findings.length, 0);
  });

  it("flags a bare HTTP response", () => {
    const report = analyzeSecurityHeaders({ server: "Apache/2.4.41 (Ubuntu)", "x-powered-by": "PHP/7.4.3" }, { https: false, setCookies: ["PHPSESSID=abc"] });
    assert.ok(report.score < 20, `score ${report.score}`);
    assert.equal(report.grade, "F");
    assert.ok(report.findings.some((f) => f.code === "NO_HTTPS" && f.severity === "critical"));
    assert.ok(report.findings.some((f) => f.code === "HSTS_MISSING"));
    assert.ok(report.findings.some((f) => f.code === "CSP_MISSING"));
    assert.ok(report.findings.some((f) => f.code === "VERSION_DISCLOSURE"));
    assert.ok(report.infoLeaks.some((l) => l.includes("Apache/2.4.41")));
  });

  it("recognizes report-only CSP, short HSTS and unsafe sources", () => {
    const report = analyzeSecurityHeaders(
      {
        "strict-transport-security": "max-age=300",
        "content-security-policy-report-only": "default-src 'self'",
        "x-frame-options": "SAMEORIGIN"
      },
      { https: true }
    );
    assert.equal(report.csp.reportOnly, true);
    assert.ok(report.findings.some((f) => f.code === "CSP_REPORT_ONLY"));
    assert.ok(report.findings.some((f) => f.code === "HSTS_SHORT_MAX_AGE"));
    assert.equal(report.checks.find((c) => c.header === "x-frame-options")?.status, "pass");
    const unsafe = analyzeSecurityHeaders({ "content-security-policy": "script-src 'unsafe-inline' 'unsafe-eval'" }, { https: true });
    assert.equal(unsafe.csp.unsafeInline, true);
    assert.equal(unsafe.csp.unsafeEval, true);
    assert.ok(unsafe.findings.some((f) => f.code === "CSP_UNSAFE_SOURCES"));
  });

  it("gives HSTS no credit when it was only seen over plaintext HTTP", () => {
    const header = "max-age=63072000; includeSubDomains; preload";
    const plaintext = analyzeSecurityHeaders({ "strict-transport-security": header }, { https: false });
    const hsts = plaintext.checks.find((c) => c.header === "strict-transport-security");
    assert.equal(hsts?.points, 0);
    assert.equal(hsts?.status, "warn");
    assert.equal(plaintext.hsts.present, true, "the header is still parsed and reported");
    assert.equal(plaintext.hsts.preload, true);
    assert.ok(plaintext.findings.some((f) => f.code === "HSTS_OVER_HTTP"));
    assert.ok(!plaintext.findings.some((f) => f.code === "HSTS_MISSING"));
    const secure = analyzeSecurityHeaders({ "strict-transport-security": header }, { https: true });
    assert.equal(secure.checks.find((c) => c.header === "strict-transport-security")?.points, 15);
  });

  it("scores Referrer-Policy by the effective whole token, not by prefix", () => {
    const points = (value: string): number => analyzeSecurityHeaders({ "referrer-policy": value }, { https: true }).checks.find((c) => c.header === "referrer-policy")?.points ?? -1;
    assert.equal(points("no-referrer"), 8);
    assert.equal(points("no-referrer-when-downgrade"), 3, "the leaky default policy must not match the no-referrer prefix");
    assert.equal(points("unsafe-url"), 3);
    assert.equal(points("Strict-Origin-When-Cross-Origin"), 8);
    assert.equal(points("origin"), 8);
    assert.equal(points("unsafe-url, strict-origin"), 8, "browsers apply the last recognised token");
    assert.equal(points("strict-origin, unsafe-url"), 3);
    assert.equal(points("strict-origin, not-a-policy"), 8, "unknown tokens are skipped when picking the effective policy");
    assert.equal(points("bogus"), 3);
    const unknown = analyzeSecurityHeaders({ "referrer-policy": "bogus" }, { https: true });
    assert.equal(unknown.checks.find((c) => c.header === "referrer-policy")?.status, "warn");
    assert.match(unknown.checks.find((c) => c.header === "referrer-policy")?.note ?? "", /not a recognized/);
    assert.ok(
      unknown.findings.some((f) => f.code === "REFERRER_POLICY_WEAK"),
      "an unrecognised policy raises a finding, like a missing one does"
    );
    const leaky = analyzeSecurityHeaders({ "referrer-policy": "no-referrer-when-downgrade" }, { https: true });
    assert.ok(leaky.findings.some((f) => f.code === "REFERRER_POLICY_WEAK"));
    const empty = analyzeSecurityHeaders({ "referrer-policy": "" }, { https: true });
    assert.match(empty.checks.find((c) => c.header === "referrer-policy")?.note ?? "", /empty/);
    const strong = analyzeSecurityHeaders({ "referrer-policy": "no-referrer" }, { https: true });
    assert.ok(!strong.findings.some((f) => f.code === "REFERRER_POLICY_WEAK"));
  });

  it("flags a present but unusable HSTS header instead of silently scoring it above a missing one", () => {
    for (const value of ["", "max-age=0", "bogus"]) {
      const report = analyzeSecurityHeaders({ "strict-transport-security": value }, { https: true });
      assert.equal(report.checks.find((c) => c.header === "strict-transport-security")?.points, 3, `value "${value}"`);
      assert.ok(
        report.findings.some((f) => f.code === "HSTS_INVALID"),
        `value "${value}" raises HSTS_INVALID`
      );
      assert.ok(!report.findings.some((f) => f.code === "HSTS_MISSING"));
    }
    const good = analyzeSecurityHeaders({ "strict-transport-security": "max-age=31536000" }, { https: true });
    assert.ok(!good.findings.some((f) => f.code === "HSTS_INVALID"));
  });
});
