import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { gradeFromScore, scoreEmail, scoreInfrastructure, scoreOverall, scoreSecurity, type EmailScoreInput } from "../src/lib/scoring.js";

const strongEmail: EmailScoreInput = {
  exists: true,
  disposable: false,
  mx: { found: true, nullMx: false, usesImplicitA: false, records: [{ resolvable: true }, { resolvable: true }] },
  spf: { found: true, valid: true, records: ["v=spf1 -all"], allPolicy: "fail", lookupLimitExceeded: false, syntaxErrorCount: 0 },
  dkim: { found: true, selectors: [{ found: true, keyType: "rsa", keyBits: 2048, revoked: false }] },
  dmarc: { found: true, valid: true, effectivePolicy: "reject", pct: 100, ruaCount: 1 },
  mtaSts: { found: true, mode: "enforce" },
  tlsRpt: { found: true },
  bimi: { found: true }
};

describe("scoreEmail", () => {
  it("awards full marks to a hardened domain", () => {
    const result = scoreEmail(strongEmail);
    assert.equal(result.score, 100);
    assert.equal(result.grade, "A");
    assert.equal(
      result.breakdown.reduce((s, b) => s + b.maxPoints, 0),
      100
    );
  });

  it("penalizes weak configurations and caps disposable domains", () => {
    const weak = scoreEmail({
      ...strongEmail,
      spf: { ...strongEmail.spf, allPolicy: "pass" },
      dkim: { found: false, selectors: [] },
      dmarc: { found: true, valid: true, effectivePolicy: "none", pct: 100, ruaCount: 0 },
      mtaSts: { found: false, mode: null },
      tlsRpt: { found: false },
      bimi: { found: false }
    });
    assert.ok(weak.score < 50, `expected weak score, got ${weak.score}`);
    const disposable = scoreEmail({ ...strongEmail, disposable: true });
    assert.equal(disposable.score, 10);
    const missing = scoreEmail({ ...strongEmail, exists: false });
    assert.equal(missing.score, 0);
  });

  it("does not penalize DKIM on null-MX domains", () => {
    const nullMx = scoreEmail({ ...strongEmail, mx: { found: false, nullMx: true, usesImplicitA: false, records: [] }, dkim: { found: false, selectors: [] } });
    assert.equal(nullMx.breakdown.find((b) => b.component === "dkim")?.points, 20);
    assert.equal(nullMx.breakdown.find((b) => b.component === "mx")?.points, 20);
  });
});

describe("scoreSecurity", () => {
  it("combines header and TLS components", () => {
    const strong = scoreSecurity({
      fetchOk: true,
      https: true,
      headersScore: 100,
      tls: { reachable: true, valid: true, expired: false, hostnameMatches: true, selfSigned: false, daysUntilExpiry: 60 }
    });
    assert.equal(strong.score, 100);
    const expiring = scoreSecurity({
      fetchOk: true,
      https: true,
      headersScore: 100,
      tls: { reachable: true, valid: true, expired: false, hostnameMatches: true, selfSigned: false, daysUntilExpiry: 5 }
    });
    assert.equal(expiring.score, 92);
    const broken = scoreSecurity({
      fetchOk: false,
      https: false,
      headersScore: null,
      tls: { reachable: true, valid: false, expired: true, hostnameMatches: true, selfSigned: false, daysUntilExpiry: -3 }
    });
    assert.equal(broken.score, 8);
  });
});

describe("scoreInfrastructure / scoreOverall", () => {
  it("credits detected categories and marks blocked fetches", () => {
    const full = scoreInfrastructure({
      fetchOk: true,
      blocked: false,
      categories: ["cdn", "analytics", "tag-manager", "crm", "js-framework", "cms", "consent-management", "error-tracking", "live-chat", "ab-testing"]
    });
    assert.equal(full.score, 100);
    const none = scoreInfrastructure({ fetchOk: true, blocked: false, categories: [] });
    assert.equal(none.score, 0);
    const blocked = scoreInfrastructure({ fetchOk: true, blocked: true, categories: ["cdn"] });
    assert.ok(blocked.breakdown.some((b) => b.component === "blocked"));
    assert.equal(scoreInfrastructure({ fetchOk: false, blocked: false, categories: [] }).score, 0);
  });

  it("weights the overall score 40/35/25", () => {
    assert.equal(scoreOverall(100, 100, 100).score, 100);
    assert.equal(scoreOverall(100, 0, 0).score, 40);
    assert.equal(scoreOverall(0, 100, 0).score, 35);
    assert.equal(scoreOverall(0, 0, 100).score, 25);
    assert.equal(gradeFromScore(89), "B");
    assert.equal(gradeFromScore(59), "F");
  });
});
