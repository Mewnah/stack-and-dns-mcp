/**
 * Transparent 0-100 scoring for email deliverability, security posture and
 * infrastructure maturity, plus the weighted overall score used by
 * comprehensive_audit. Every score returns a breakdown so agents can explain
 * the number to a human.
 */

export type Grade = "A" | "B" | "C" | "D" | "F";

export function gradeFromScore(score: number): Grade {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

export interface ScoreBreakdownItem {
  component: string;
  points: number;
  maxPoints: number;
  note: string;
}

export interface ScoreResult {
  score: number;
  grade: Grade;
  breakdown: ScoreBreakdownItem[];
}

export interface EmailScoreInput {
  exists: boolean;
  disposable: boolean;
  /** lookupFailed: the absence was not confirmed (the lookup failed); it still scores as absent, but the note says so. */
  mx: { found: boolean; nullMx: boolean; usesImplicitA: boolean; records: Array<{ resolvable: boolean; lookupFailed?: boolean }>; lookupFailed?: boolean };
  spf: {
    found: boolean;
    lookupFailed?: boolean;
    /** The policy lives behind a redirect= target whose lookup failed. */
    policyLookupFailed?: boolean;
    valid: boolean;
    records: string[];
    allPolicy: "fail" | "softfail" | "neutral" | "pass" | "none";
    lookupLimitExceeded: boolean;
    /** More than 2 void lookups (RFC 7208 section 4.6.4): a permerror. */
    voidLookupsExceeded?: boolean;
    /** The include or redirect chain loops back on itself: a permerror. */
    circularInclude?: boolean;
    syntaxErrorCount: number;
  };
  dkim: { found: boolean; selectors: Array<{ found: boolean; keyType: string | null; keyBits: number | null; revoked: boolean }> };
  dmarc: {
    found: boolean;
    lookupFailed?: boolean;
    /** A subdomain's own _dmarc lookup failed and the record is the organizational fallback, so the subdomain's policy is unknown. */
    policyLookupFailed?: boolean;
    valid: boolean;
    effectivePolicy: "none" | "quarantine" | "reject" | null;
    pct: number;
    ruaCount: number;
  };
  mtaSts: { found: boolean; mode: "enforce" | "testing" | "none" | null };
  tlsRpt: { found: boolean };
  bimi: { found: boolean };
}

function clamp(value: number, min = 0, max = 100): number {
  return Math.max(min, Math.min(max, Math.round(value)));
}

/**
 * MX points for a published (non-null) MX set, by how many of its exchanges
 * do not resolve. Exported so the scan store's accepted reading of lame
 * exchanges scores them exactly as this function scores dangling ones.
 */
export function mxSetPoints(exchanges: number, dangling: number): number {
  return dangling === 0 ? 20 : dangling < exchanges ? 14 : 2;
}

/**
 * DMARC points for a subdomain whose own _dmarc lookup failed (its policy is
 * unknown and scored as p=none). Exported so the scan store can take them
 * back out of a score that comes without a breakdown.
 */
export const DMARC_POLICY_UNKNOWN_POINTS = 10;

/**
 * DMARC points (of 28) and their note. Exported so the scan store can
 * record a subdomain's own DMARC points from a scan that carries no
 * breakdown, exactly as scoreEmail awards them.
 */
export function scoreDmarc(dmarc: EmailScoreInput["dmarc"]): { points: number; note: string } {
  let points = 0;
  let note: string;
  if (!dmarc.found) {
    note = dmarc.lookupFailed ? "DMARC lookup failed; absence unconfirmed (scored as absent)." : "No DMARC record.";
  } else if (dmarc.policyLookupFailed) {
    // The subdomain may publish a weaker policy of its own that the failed
    // lookup hid, and nothing about the organizational record (its policy,
    // validity or reporting) is the subdomain's: an unknown policy is
    // scored as p=none, never above or below it.
    points = DMARC_POLICY_UNKNOWN_POINTS;
    note = "Own _dmarc lookup failed; organizational policy used (subdomain policy unknown, scored as p=none).";
  } else if (!dmarc.valid) {
    points = 4;
    note = "DMARC record is malformed.";
  } else if (dmarc.effectivePolicy === "reject") {
    points = dmarc.pct >= 100 ? 28 : 18;
    note = dmarc.pct >= 100 ? "p=reject at 100%." : `p=reject applied to ${dmarc.pct}% of mail.`;
  } else if (dmarc.effectivePolicy === "quarantine") {
    points = dmarc.pct >= 100 ? 22 : 16;
    note = dmarc.pct >= 100 ? "p=quarantine at 100%." : `p=quarantine applied to ${dmarc.pct}% of mail.`;
  } else {
    points = 10;
    note = "p=none (monitoring only).";
  }
  if (dmarc.found && dmarc.ruaCount === 0 && !dmarc.policyLookupFailed) {
    points = Math.max(0, points - 2);
    note += " No aggregate reporting address.";
  }
  return { points, note };
}

export function scoreEmail(input: EmailScoreInput): ScoreResult {
  const breakdown: ScoreBreakdownItem[] = [];
  if (!input.exists) {
    breakdown.push({ component: "domain", points: 0, maxPoints: 100, note: "Domain does not resolve in DNS." });
    return { score: 0, grade: "F", breakdown };
  }

  // MX (20)
  {
    let points = 0;
    let note: string;
    if (input.mx.nullMx) {
      points = 20;
      note = "Null MX explicitly declares the domain does not receive mail.";
    } else if (input.mx.found) {
      // An exchange whose address lookup failed is unknown, not dangling.
      const unchecked = input.mx.records.filter((r) => r.lookupFailed === true).length;
      const dangling = input.mx.records.filter((r) => !r.resolvable && r.lookupFailed !== true).length;
      points = mxSetPoints(input.mx.records.length, dangling);
      if (dangling === 0) {
        note = unchecked > 0 ? `MX records present; ${unchecked} exchange(s) could not be checked.` : "MX records present and all exchanges resolve.";
      } else if (dangling < input.mx.records.length) {
        note = `${dangling} MX exchange(s) do not resolve.`;
      } else {
        note = "No MX exchange resolves.";
      }
    } else if (input.mx.usesImplicitA) {
      points = 6;
      note = "No MX; delivery falls back to the A record.";
    } else {
      note = input.mx.lookupFailed ? "MX lookup failed; absence unconfirmed (scored as absent)." : "No MX records and no fallback address.";
    }
    breakdown.push({ component: "mx", points, maxPoints: 20, note });
  }

  // SPF (22)
  {
    let points = 0;
    let note: string;
    if (!input.spf.found) {
      note = input.spf.lookupFailed ? "SPF lookup failed; absence unconfirmed (scored as absent)." : "No SPF record.";
    } else if (input.spf.records.length > 1) {
      points = 3;
      note = "Multiple SPF records cause a permerror.";
    } else {
      switch (input.spf.allPolicy) {
        case "fail":
          points = 22;
          note = "SPF ends with -all.";
          break;
        case "softfail":
          points = 20;
          note = "SPF ends with ~all.";
          break;
        case "none":
          points = 10;
          note = input.spf.policyLookupFailed ? "SPF redirect target lookup failed; terminal all unknown (scored as no all)." : "SPF has no terminal all mechanism.";
          break;
        case "neutral":
          points = 8;
          note = "SPF ends with ?all (no protection).";
          break;
        case "pass":
          points = 2;
          note = "SPF ends with +all (authorizes everyone).";
          break;
      }
      if (input.spf.lookupLimitExceeded) {
        points = Math.min(points, 6);
        note += " Exceeds the 10 DNS lookup limit (permerror).";
      } else if (input.spf.voidLookupsExceeded || input.spf.circularInclude) {
        // Receivers return permerror for these exactly as they do past the
        // lookup limit, so SPF fails just the same and costs the same.
        points = Math.min(points, 6);
        note += " SPF permerror.";
      }
      if (input.spf.syntaxErrorCount > 0) {
        points = Math.min(points, 8);
        note += ` ${input.spf.syntaxErrorCount} syntax error(s).`;
      }
    }
    breakdown.push({ component: "spf", points, maxPoints: 22, note });
  }

  // DKIM (20)
  {
    let points = 0;
    let note: string;
    const found = input.dkim.selectors.filter((s) => s.found && !s.revoked);
    if (input.mx.nullMx) {
      points = 20;
      note = "Not applicable for a non-mailing domain.";
    } else if (found.length === 0) {
      points = 6;
      note = "No DKIM key found under common selectors; the domain may sign with a custom selector (pass it via dkimSelectors to confirm).";
    } else if (found.some((s) => s.keyType === "ed25519" || (s.keyType === "rsa" && s.keyBits !== null && s.keyBits >= 2048))) {
      points = 20;
      note = "Strong DKIM key published.";
    } else if (found.some((s) => s.keyType === "rsa" && s.keyBits !== null && s.keyBits >= 1024)) {
      points = 14;
      note = "DKIM key is 1024-bit; 2048-bit recommended.";
    } else if (found.some((s) => s.keyBits === null)) {
      points = 16;
      note = "DKIM key published (length could not be decoded).";
    } else {
      points = 4;
      note = "Only weak (<1024-bit) DKIM keys found.";
    }
    breakdown.push({ component: "dkim", points, maxPoints: 20, note });
  }

  // DMARC (28)
  {
    const { points, note } = scoreDmarc(input.dmarc);
    breakdown.push({ component: "dmarc", points, maxPoints: 28, note });
  }

  // MTA-STS (5)
  {
    // A DNS record whose policy file could not be fetched or validated gives
    // senders nothing to enforce, so it earns nothing; "none" is an explicit
    // opt-out and earns 1 for at least publishing a valid policy.
    let points = 0;
    let note = "No MTA-STS.";
    if (input.mtaSts.found) {
      points = input.mtaSts.mode === "enforce" ? 5 : input.mtaSts.mode === "testing" ? 3 : input.mtaSts.mode === "none" ? 1 : 0;
      note = input.mtaSts.mode === null ? "MTA-STS record present but no valid policy file." : `MTA-STS mode ${input.mtaSts.mode}.`;
    }
    breakdown.push({ component: "mta-sts", points, maxPoints: 5, note });
  }
  breakdown.push({ component: "tls-rpt", points: input.tlsRpt.found ? 3 : 0, maxPoints: 3, note: input.tlsRpt.found ? "TLS-RPT published." : "No TLS-RPT." });
  breakdown.push({ component: "bimi", points: input.bimi.found ? 2 : 0, maxPoints: 2, note: input.bimi.found ? "BIMI published." : "No BIMI." });

  let score = clamp(breakdown.reduce((sum, item) => sum + item.points, 0));
  if (input.disposable) {
    score = Math.min(score, 10);
    breakdown.push({ component: "disposable", points: 0, maxPoints: 0, note: "Disposable email domain: score capped at 10." });
  }
  return { score, grade: gradeFromScore(score), breakdown };
}

export interface SecurityScoreInput {
  fetchOk: boolean;
  https: boolean;
  headersScore: number | null;
  tls: {
    reachable: boolean;
    valid: boolean;
    expired: boolean;
    hostnameMatches: boolean;
    selfSigned: boolean;
    daysUntilExpiry: number | null;
  } | null;
}

export function scoreSecurity(input: SecurityScoreInput): ScoreResult {
  const breakdown: ScoreBreakdownItem[] = [];
  const headerPoints = input.headersScore === null ? 0 : Math.round(input.headersScore * 0.65);
  breakdown.push({
    component: "http-headers",
    points: headerPoints,
    maxPoints: 65,
    note: input.headersScore === null ? "Homepage could not be fetched; header analysis unavailable." : `Security header score ${input.headersScore}/100.`
  });

  let tlsPoints = 0;
  let tlsNote: string;
  if (!input.tls || !input.tls.reachable) {
    tlsNote = "TLS on port 443 is unreachable.";
  } else if (input.tls.valid) {
    tlsPoints = 35;
    tlsNote = "Certificate chain, hostname and validity window are all valid.";
    if (input.tls.daysUntilExpiry !== null && input.tls.daysUntilExpiry <= 14) {
      tlsPoints -= 8;
      tlsNote += ` Expires in ${input.tls.daysUntilExpiry} day(s).`;
    } else if (input.tls.daysUntilExpiry !== null && input.tls.daysUntilExpiry <= 30) {
      tlsPoints -= 3;
      tlsNote += ` Expires in ${input.tls.daysUntilExpiry} day(s).`;
    }
  } else {
    tlsPoints = 8;
    const reasons: string[] = [];
    if (input.tls.expired) reasons.push("expired");
    if (!input.tls.hostnameMatches) reasons.push("hostname mismatch");
    if (input.tls.selfSigned) reasons.push("self-signed");
    if (reasons.length === 0) reasons.push("chain not trusted");
    tlsNote = `Certificate is invalid (${reasons.join(", ")}).`;
  }
  breakdown.push({ component: "tls", points: tlsPoints, maxPoints: 35, note: tlsNote });

  const score = clamp(headerPoints + tlsPoints);
  return { score, grade: gradeFromScore(score), breakdown };
}

export interface InfrastructureScoreInput {
  fetchOk: boolean;
  blocked: boolean;
  categories: string[];
}

const INFRASTRUCTURE_WEIGHTS: Array<{ component: string; categories: string[]; points: number; note: string }> = [
  { component: "edge-protection", categories: ["cdn", "waf"], points: 15, note: "CDN or WAF in front of the origin" },
  { component: "analytics", categories: ["analytics", "product-analytics"], points: 15, note: "Web or product analytics" },
  { component: "tag-management", categories: ["tag-manager"], points: 10, note: "Tag manager / CDP" },
  { component: "go-to-market-stack", categories: ["marketing-automation", "crm", "email-marketing", "abm"], points: 15, note: "Marketing automation, CRM or ABM tooling" },
  { component: "modern-framework", categories: ["js-framework", "web-framework"], points: 10, note: "Modern JavaScript or web framework" },
  { component: "platform", categories: ["cms", "ecommerce", "site-builder", "headless-cms", "ssg"], points: 10, note: "Recognized CMS, commerce or site platform" },
  { component: "privacy-compliance", categories: ["consent-management"], points: 8, note: "Consent management platform" },
  { component: "observability", categories: ["error-tracking", "session-replay"], points: 7, note: "Error tracking, RUM or session replay" },
  { component: "customer-engagement", categories: ["live-chat", "customer-support", "scheduling"], points: 5, note: "Live chat, support or scheduling widget" },
  { component: "experimentation", categories: ["ab-testing", "feature-flags", "onboarding"], points: 5, note: "A/B testing, feature flags or onboarding" }
];

export function scoreInfrastructure(input: InfrastructureScoreInput): ScoreResult {
  const breakdown: ScoreBreakdownItem[] = [];
  if (!input.fetchOk) {
    breakdown.push({ component: "fetch", points: 0, maxPoints: 100, note: "Homepage could not be fetched." });
    return { score: 0, grade: "F", breakdown };
  }
  const present = new Set(input.categories);
  for (const weight of INFRASTRUCTURE_WEIGHTS) {
    const hit = weight.categories.some((c) => present.has(c));
    breakdown.push({
      component: weight.component,
      points: hit ? weight.points : 0,
      maxPoints: weight.points,
      note: hit ? `${weight.note}: detected.` : `${weight.note}: not detected.`
    });
  }
  let score = clamp(breakdown.reduce((sum, item) => sum + item.points, 0));
  if (input.blocked) {
    breakdown.push({ component: "blocked", points: 0, maxPoints: 0, note: "Bot protection blocked the fetch; detection is partial and the score is a lower bound." });
    score = Math.max(score, 15);
  }
  return { score, grade: gradeFromScore(score), breakdown };
}

export const OVERALL_WEIGHTS = { email: 0.4, security: 0.35, infrastructure: 0.25 } as const;

export function scoreOverall(email: number, security: number, infrastructure: number): { score: number; grade: Grade } {
  const score = clamp(email * OVERALL_WEIGHTS.email + security * OVERALL_WEIGHTS.security + infrastructure * OVERALL_WEIGHTS.infrastructure);
  return { score, grade: gradeFromScore(score) };
}
