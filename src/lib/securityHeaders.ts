/**
 * HTTP response security-header analysis with a weighted 0-100 score.
 *
 * Weights (sum = 100):
 *   HTTPS served ............ 15
 *   Strict-Transport-Security 15
 *   Content-Security-Policy . 15
 *   Clickjacking protection . 10  (X-Frame-Options or CSP frame-ancestors)
 *   X-Content-Type-Options .. 10
 *   Referrer-Policy .........  8
 *   Permissions-Policy ......  7
 *   Cross-Origin-Opener-Policy 4
 *   Cross-Origin-Resource-Policy 3
 *   No version disclosure ...  5
 *   Cookie hardening ........  8
 */

import type { Finding } from "./findings.js";
import { parseSafeInteger } from "./numbers.js";
import { gradeFromScore, type Grade } from "./scoring.js";

/** Values that keep at least the path out of cross-origin Referer headers. */
const STRONG_REFERRER_POLICIES = new Set(["no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin", "origin", "origin-when-cross-origin"]);
/** Every token defined by the Referrer Policy specification, including the leaky ones. */
const KNOWN_REFERRER_POLICIES = new Set([...STRONG_REFERRER_POLICIES, "no-referrer-when-downgrade", "unsafe-url"]);

export interface HeaderCheck {
  header: string;
  present: boolean;
  value: string | null;
  status: "pass" | "warn" | "fail" | "info";
  points: number;
  maxPoints: number;
  note: string;
}

export interface SecurityHeadersReport {
  score: number;
  grade: Grade;
  https: boolean;
  hsts: {
    present: boolean;
    maxAge: number | null;
    includeSubDomains: boolean;
    preload: boolean;
  };
  csp: {
    present: boolean;
    reportOnly: boolean;
    unsafeInline: boolean;
    unsafeEval: boolean;
    frameAncestors: boolean;
    upgradeInsecureRequests: boolean;
    directiveCount: number;
  };
  cookies: {
    total: number;
    secure: number;
    httpOnly: number;
    sameSite: number;
  };
  infoLeaks: string[];
  checks: HeaderCheck[];
  findings: Finding[];
}

export type HeaderMap = Record<string, string | string[] | undefined>;

function first(headers: HeaderMap, name: string): string | null {
  const raw = headers[name.toLowerCase()];
  if (raw === undefined) return null;
  if (Array.isArray(raw)) return raw.length > 0 ? raw.join(", ") : null;
  return raw;
}

function list(headers: HeaderMap, name: string): string[] {
  const raw = headers[name.toLowerCase()];
  if (raw === undefined) return [];
  return Array.isArray(raw) ? raw : [raw];
}

function truncate(value: string | null, max = 300): string | null {
  if (value === null) return null;
  return value.length > max ? `${value.slice(0, max)}...` : value;
}

export function analyzeSecurityHeaders(headers: HeaderMap, options: { https: boolean; setCookies?: string[] }): SecurityHeadersReport {
  const checks: HeaderCheck[] = [];
  const findings: Finding[] = [];
  const infoLeaks: string[] = [];
  let score = 0;

  const add = (check: HeaderCheck): void => {
    checks.push(check);
    score += check.points;
  };

  // HTTPS
  add({
    header: "https",
    present: options.https,
    value: options.https ? "served over TLS" : "served over plaintext HTTP",
    status: options.https ? "pass" : "fail",
    points: options.https ? 15 : 0,
    maxPoints: 15,
    note: options.https ? "Final response was delivered over HTTPS." : "Final response was delivered over HTTP."
  });
  if (!options.https) {
    findings.push({
      severity: "critical",
      code: "NO_HTTPS",
      message: "The homepage is served over plaintext HTTP.",
      recommendation: "Serve the site over HTTPS and redirect all HTTP requests to HTTPS."
    });
  }

  // HSTS
  const hstsRaw = first(headers, "strict-transport-security");
  const hsts = { present: hstsRaw !== null, maxAge: null as number | null, includeSubDomains: false, preload: false };
  if (hstsRaw) {
    const maxAgeMatch = /max-age\s*=\s*"?(\d+)"?/i.exec(hstsRaw);
    hsts.maxAge = maxAgeMatch ? parseSafeInteger(maxAgeMatch[1]) : null;
    hsts.includeSubDomains = /includesubdomains/i.test(hstsRaw);
    hsts.preload = /preload/i.test(hstsRaw);
  }
  {
    let points = 0;
    let status: HeaderCheck["status"] = "fail";
    let note = "Missing. Browsers will accept downgrade to HTTP on later visits.";
    if (hsts.present && !options.https) {
      // RFC 6797 section 8.1: a user agent must ignore a Strict-Transport-Security
      // header received over a non-secure transport, so the header earns
      // nothing on a plaintext page.
      status = "warn";
      note = "Present, but browsers ignore Strict-Transport-Security received over plaintext HTTP.";
      findings.push({
        severity: "low",
        code: "HSTS_OVER_HTTP",
        message: "Strict-Transport-Security was only observed on a plaintext HTTP response, where browsers must ignore it.",
        recommendation: "Serve the site over HTTPS and send Strict-Transport-Security on the HTTPS response."
      });
    } else if (hsts.present) {
      if (hsts.maxAge !== null && hsts.maxAge >= 15552000) {
        points = 15;
        status = "pass";
        note = `max-age is ${hsts.maxAge}s (>= 180 days).`;
      } else if (hsts.maxAge !== null && hsts.maxAge > 0) {
        points = 10;
        status = "warn";
        note = `max-age is only ${hsts.maxAge}s; 31536000 (1 year) is recommended.`;
        findings.push({
          severity: "low",
          code: "HSTS_SHORT_MAX_AGE",
          message: `HSTS max-age is ${hsts.maxAge} seconds, below the recommended 1 year.`,
          recommendation: "Set Strict-Transport-Security: max-age=31536000; includeSubDomains; preload."
        });
      } else {
        points = 3;
        status = "warn";
        note = "Header present but max-age is zero or unparseable.";
        findings.push({
          severity: "low",
          code: "HSTS_INVALID",
          message: "Strict-Transport-Security is present but its max-age is zero, missing or unparseable, so browsers apply no HSTS policy.",
          recommendation: "Set Strict-Transport-Security: max-age=31536000; includeSubDomains; preload."
        });
      }
    } else {
      findings.push({
        severity: "medium",
        code: "HSTS_MISSING",
        message: "Strict-Transport-Security header is missing.",
        recommendation: "Add Strict-Transport-Security: max-age=31536000; includeSubDomains."
      });
    }
    add({ header: "strict-transport-security", present: hsts.present, value: truncate(hstsRaw), status, points, maxPoints: 15, note });
  }

  // CSP
  const cspEnforced = first(headers, "content-security-policy");
  const cspReportOnly = first(headers, "content-security-policy-report-only");
  const cspValue = cspEnforced ?? cspReportOnly;
  const csp = {
    present: cspValue !== null,
    reportOnly: cspEnforced === null && cspReportOnly !== null,
    unsafeInline: false,
    unsafeEval: false,
    frameAncestors: false,
    upgradeInsecureRequests: false,
    directiveCount: 0
  };
  if (cspValue) {
    const directives = cspValue
      .split(";")
      .map((d) => d.trim())
      .filter((d) => d.length > 0);
    csp.directiveCount = directives.length;
    csp.unsafeInline = /'unsafe-inline'/i.test(cspValue);
    csp.unsafeEval = /'unsafe-eval'/i.test(cspValue);
    csp.frameAncestors = /(^|;)\s*frame-ancestors\b/i.test(cspValue);
    csp.upgradeInsecureRequests = /upgrade-insecure-requests/i.test(cspValue);
  }
  {
    let points = 0;
    let status: HeaderCheck["status"] = "fail";
    let note = "Missing. No browser-side mitigation against XSS or injected resources.";
    if (csp.present && !csp.reportOnly) {
      if (csp.unsafeInline && csp.unsafeEval) {
        points = 8;
        status = "warn";
        note = "Enforced, but allows both 'unsafe-inline' and 'unsafe-eval'.";
      } else if (csp.unsafeInline || csp.unsafeEval) {
        points = 11;
        status = "warn";
        note = `Enforced, but allows ${csp.unsafeInline ? "'unsafe-inline'" : "'unsafe-eval'"}.`;
      } else {
        points = 15;
        status = "pass";
        note = `Enforced with ${csp.directiveCount} directives and no unsafe-* sources.`;
      }
      if (csp.unsafeInline || csp.unsafeEval) {
        findings.push({
          severity: "low",
          code: "CSP_UNSAFE_SOURCES",
          message: "Content-Security-Policy permits unsafe-inline and/or unsafe-eval.",
          recommendation: "Move inline scripts to nonced or hashed sources and remove 'unsafe-eval'."
        });
      }
    } else if (csp.present && csp.reportOnly) {
      points = 5;
      status = "warn";
      note = "Only a report-only policy is deployed; nothing is enforced.";
      findings.push({
        severity: "low",
        code: "CSP_REPORT_ONLY",
        message: "Content-Security-Policy is deployed in report-only mode.",
        recommendation: "Promote the policy to an enforced Content-Security-Policy header once reports are clean."
      });
    } else {
      findings.push({
        severity: "medium",
        code: "CSP_MISSING",
        message: "No Content-Security-Policy header is set.",
        recommendation: "Deploy a Content-Security-Policy that restricts script and frame sources."
      });
    }
    add({ header: "content-security-policy", present: csp.present, value: truncate(cspValue), status, points, maxPoints: 15, note });
  }

  // Clickjacking
  const xfo = first(headers, "x-frame-options");
  {
    const protectedByCsp = csp.present && !csp.reportOnly && csp.frameAncestors;
    const xfoValid = xfo !== null && /^(deny|sameorigin)$/i.test(xfo.trim());
    let points = 0;
    let status: HeaderCheck["status"] = "fail";
    let note = "No X-Frame-Options and no CSP frame-ancestors directive.";
    if (protectedByCsp) {
      points = 10;
      status = "pass";
      note = "Protected by CSP frame-ancestors.";
    } else if (xfoValid) {
      points = 10;
      status = "pass";
      note = `X-Frame-Options is ${xfo?.trim().toUpperCase()}.`;
    } else if (xfo !== null) {
      points = 4;
      status = "warn";
      note = `X-Frame-Options value "${xfo}" is non-standard (ALLOW-FROM is ignored by modern browsers).`;
    } else {
      findings.push({
        severity: "medium",
        code: "CLICKJACKING_UNPROTECTED",
        message: "No clickjacking protection (X-Frame-Options or CSP frame-ancestors).",
        recommendation: "Add X-Frame-Options: DENY or a CSP frame-ancestors directive."
      });
    }
    add({ header: "x-frame-options", present: xfo !== null || protectedByCsp, value: truncate(xfo), status, points, maxPoints: 10, note });
  }

  // X-Content-Type-Options
  const xcto = first(headers, "x-content-type-options");
  {
    const ok = xcto !== null && /nosniff/i.test(xcto);
    if (!ok) {
      findings.push({
        severity: "low",
        code: "XCTO_MISSING",
        message: "X-Content-Type-Options: nosniff is not set.",
        recommendation: "Add X-Content-Type-Options: nosniff to prevent MIME sniffing."
      });
    }
    add({
      header: "x-content-type-options",
      present: xcto !== null,
      value: truncate(xcto),
      status: ok ? "pass" : "fail",
      points: ok ? 10 : 0,
      maxPoints: 10,
      note: ok ? "nosniff is set." : "Missing or not set to nosniff."
    });
  }

  // Referrer-Policy
  const referrer = first(headers, "referrer-policy");
  {
    let points = 0;
    let status: HeaderCheck["status"] = "fail";
    let note = "Missing. Full URLs may leak to third parties via the Referer header.";
    if (referrer !== null) {
      // The header is a comma-separated fallback list and browsers apply the
      // last token they recognise, so the effective policy is the last known
      // token. Tokens are compared whole: "no-referrer" must never match the
      // prefix of the leaky "no-referrer-when-downgrade".
      const tokens = referrer
        .toLowerCase()
        .split(",")
        .map((t) => t.trim())
        .filter((t) => t.length > 0);
      const effective = [...tokens].reverse().find((t) => KNOWN_REFERRER_POLICIES.has(t)) ?? null;
      if (effective !== null && STRONG_REFERRER_POLICIES.has(effective)) {
        points = 8;
        status = "pass";
        note = `Policy "${effective}" limits referrer leakage.`;
      } else {
        points = 3;
        status = "warn";
        note =
          effective !== null
            ? `Policy "${effective}" still leaks full URLs in some contexts.`
            : tokens.length === 0
              ? "Header is empty; browsers apply their default policy, which sends the full URL on same-protocol cross-origin requests."
              : `Policy "${referrer}" is not a recognized Referrer-Policy value; browsers apply their default policy, which sends the full URL on same-protocol cross-origin requests.`;
        findings.push({
          severity: "low",
          code: "REFERRER_POLICY_WEAK",
          message:
            effective !== null ? `Referrer-Policy "${effective}" still leaks full URLs cross-origin.` : "Referrer-Policy is set to an empty or unrecognized value, so the browser default applies.",
          recommendation: "Set Referrer-Policy: strict-origin-when-cross-origin (or stricter)."
        });
      }
    } else {
      findings.push({
        severity: "low",
        code: "REFERRER_POLICY_MISSING",
        message: "Referrer-Policy header is missing.",
        recommendation: "Add Referrer-Policy: strict-origin-when-cross-origin."
      });
    }
    add({ header: "referrer-policy", present: referrer !== null, value: truncate(referrer), status, points, maxPoints: 8, note });
  }

  // Permissions-Policy
  const permissions = first(headers, "permissions-policy") ?? first(headers, "feature-policy");
  {
    const ok = permissions !== null;
    if (!ok) {
      findings.push({
        severity: "info",
        code: "PERMISSIONS_POLICY_MISSING",
        message: "Permissions-Policy header is missing.",
        recommendation: "Add a Permissions-Policy that disables unused browser features (camera, microphone, geolocation)."
      });
    }
    add({
      header: "permissions-policy",
      present: ok,
      value: truncate(permissions),
      status: ok ? "pass" : "warn",
      points: ok ? 7 : 0,
      maxPoints: 7,
      note: ok ? "Browser feature access is restricted." : "Missing."
    });
  }

  // COOP
  const coop = first(headers, "cross-origin-opener-policy");
  {
    const ok = coop !== null && /same-origin/i.test(coop);
    add({
      header: "cross-origin-opener-policy",
      present: coop !== null,
      value: truncate(coop),
      status: ok ? "pass" : "info",
      points: ok ? 4 : 0,
      maxPoints: 4,
      note: ok ? "Isolates the browsing context group." : "Missing or permissive."
    });
  }

  // CORP
  const corp = first(headers, "cross-origin-resource-policy");
  {
    const ok = corp !== null;
    add({
      header: "cross-origin-resource-policy",
      present: ok,
      value: truncate(corp),
      status: ok ? "pass" : "info",
      points: ok ? 3 : 0,
      maxPoints: 3,
      note: ok ? "Set." : "Missing."
    });
  }

  // Information disclosure
  {
    const server = first(headers, "server");
    const poweredBy = first(headers, "x-powered-by");
    const aspNet = first(headers, "x-aspnet-version") ?? first(headers, "x-aspnetmvc-version");
    const generator = first(headers, "x-generator");
    let points = 5;
    let status: HeaderCheck["status"] = "pass";
    const notes: string[] = [];
    const versionPattern = /\d+\.\d+/;
    for (const [name, value] of [
      ["server", server],
      ["x-powered-by", poweredBy],
      ["x-aspnet-version", aspNet],
      ["x-generator", generator]
    ] as Array<[string, string | null]>) {
      if (value === null) continue;
      infoLeaks.push(`${name}: ${value}`);
      if (versionPattern.test(value)) {
        points = 0;
        status = "fail";
        notes.push(`${name} discloses a version number.`);
      } else if (name !== "server") {
        points = Math.min(points, 3);
        if (status === "pass") status = "warn";
        notes.push(`${name} discloses the technology in use.`);
      }
    }
    if (status === "fail") {
      findings.push({
        severity: "low",
        code: "VERSION_DISCLOSURE",
        message: `Response headers disclose software versions (${infoLeaks.join("; ")}).`,
        recommendation: "Suppress version numbers in Server / X-Powered-By headers."
      });
    }
    add({
      header: "server / x-powered-by",
      present: infoLeaks.length > 0,
      value: truncate(infoLeaks.join("; ") || null),
      status,
      points,
      maxPoints: 5,
      note: notes.length > 0 ? notes.join(" ") : "No version information disclosed."
    });
  }

  // Cookies
  const setCookies = options.setCookies ?? list(headers, "set-cookie");
  const cookies = { total: setCookies.length, secure: 0, httpOnly: 0, sameSite: 0 };
  for (const cookie of setCookies) {
    if (/;\s*secure(\s*;|\s*$)/i.test(cookie)) cookies.secure++;
    if (/;\s*httponly(\s*;|\s*$)/i.test(cookie)) cookies.httpOnly++;
    if (/;\s*samesite\s*=/i.test(cookie)) cookies.sameSite++;
  }
  {
    let points = 8;
    let status: HeaderCheck["status"] = "pass";
    let note = "No cookies are set on the homepage response.";
    if (cookies.total > 0) {
      const ratio = (cookies.secure + cookies.httpOnly + cookies.sameSite) / (cookies.total * 3);
      points = Math.round(ratio * 8);
      status = ratio >= 0.99 ? "pass" : ratio >= 0.5 ? "warn" : "fail";
      note = `${cookies.total} cookie(s): ${cookies.secure} Secure, ${cookies.httpOnly} HttpOnly, ${cookies.sameSite} SameSite.`;
      if (cookies.secure < cookies.total && options.https) {
        findings.push({
          severity: "low",
          code: "COOKIE_MISSING_SECURE",
          message: `${cookies.total - cookies.secure} cookie(s) are set without the Secure attribute.`,
          recommendation: "Add the Secure attribute to every cookie on HTTPS sites."
        });
      }
      if (cookies.sameSite < cookies.total) {
        findings.push({
          severity: "info",
          code: "COOKIE_MISSING_SAMESITE",
          message: `${cookies.total - cookies.sameSite} cookie(s) do not declare SameSite.`,
          recommendation: "Declare SameSite=Lax or Strict explicitly on each cookie."
        });
      }
    }
    add({ header: "set-cookie", present: cookies.total > 0, value: cookies.total > 0 ? `${cookies.total} cookie(s)` : null, status, points, maxPoints: 8, note });
  }

  // Legacy header, informational only
  const xss = first(headers, "x-xss-protection");
  if (xss !== null) {
    add({
      header: "x-xss-protection",
      present: true,
      value: truncate(xss),
      status: "info",
      points: 0,
      maxPoints: 0,
      note: "Deprecated header; modern browsers ignore it. Prefer a Content-Security-Policy."
    });
  }

  const finalScore = Math.max(0, Math.min(100, Math.round(score)));
  return {
    score: finalScore,
    grade: gradeFromScore(finalScore),
    https: options.https,
    hsts,
    csp,
    cookies,
    infoLeaks,
    checks,
    findings
  };
}
