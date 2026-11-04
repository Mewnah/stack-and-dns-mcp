/**
 * Detects bot-mitigation challenge pages and WAF blocks so the tech-stack
 * inspector can report "blocked" honestly instead of mis-detecting the
 * challenge page as the site's real stack.
 */

export type ChallengeType = "javascript" | "captcha" | "access_denied" | "rate_limited";

export interface BlockDetection {
  blocked: boolean;
  vendor: string | null;
  challengeType: ChallengeType | null;
  reason: string | null;
}

const NOT_BLOCKED: BlockDetection = { blocked: false, vendor: null, challengeType: null, reason: null };

function block(vendor: string, challengeType: ChallengeType, reason: string): BlockDetection {
  return { blocked: true, vendor, challengeType, reason };
}

export function detectBlock(status: number | null, headers: Record<string, string>, html: string): BlockDetection {
  const sample = html.length > 200000 ? html.slice(0, 200000) : html;
  const lower = sample.toLowerCase();
  const header = (name: string): string => headers[name] ?? "";

  // Cloudflare
  const cfMitigated = header("cf-mitigated").toLowerCase();
  if (cfMitigated === "challenge") return block("Cloudflare", "javascript", "cf-mitigated: challenge header present");
  if (
    lower.includes("cf-browser-verification") ||
    lower.includes("cf_chl_opt") ||
    // The passive JS-detection script (/cdn-cgi/challenge-platform/scripts/jsd/) is injected into ordinary pages too.
    /\/cdn-cgi\/challenge-platform\/(?!scripts\/jsd\/)/.test(lower) ||
    lower.includes("cf-challenge-running") ||
    (lower.includes("<title>just a moment") && lower.includes("cloudflare"))
  ) {
    return block("Cloudflare", "javascript", "Cloudflare managed challenge page detected in HTML");
  }
  if (status === 403 && lower.includes("cf-error-details") && /error code:\s*10\d\d/.test(lower)) {
    return block("Cloudflare", "access_denied", "Cloudflare firewall rule blocked the request");
  }
  if (status === 403 && lower.includes("challenges.cloudflare.com/turnstile")) {
    return block("Cloudflare", "captcha", "Cloudflare Turnstile interstitial");
  }

  // Akamai Bot Manager
  if ((status === 403 || status === 503) && (/reference(?:&#32;|\s)#18\./i.test(sample) || lower.includes("errors.edgesuite.net") || lower.includes("akamaighost"))) {
    return block("Akamai", "access_denied", "Akamai Bot Manager / Kona Site Defender denied the request");
  }

  // Imperva / Incapsula
  if (lower.includes("_incapsula_resource") || lower.includes("incapsula incident id") || (header("x-cdn").toLowerCase() === "imperva" && status === 403)) {
    return block("Imperva", status === 403 ? "access_denied" : "javascript", "Imperva Incapsula challenge or block page");
  }

  // DataDome
  if (lower.includes("captcha-delivery.com") || (status === 403 && (header("x-datadome").length > 0 || lower.includes("datadome")))) {
    return block("DataDome", "captcha", "DataDome bot protection challenge");
  }

  // PerimeterX / HUMAN
  if (lower.includes("px-captcha") || (lower.includes("_pxappid") && (status === 403 || lower.includes("press & hold")))) {
    return block("HUMAN (PerimeterX)", "captcha", "HUMAN / PerimeterX challenge page");
  }

  // AWS WAF
  const wafAction = header("x-amzn-waf-action").toLowerCase();
  if (wafAction === "challenge" || wafAction === "captcha") {
    return block("AWS WAF", wafAction === "captcha" ? "captcha" : "javascript", `x-amzn-waf-action: ${wafAction}`);
  }
  if ((status === 405 || status === 403) && lower.includes("awswaf") && lower.includes("challenge")) {
    return block("AWS WAF", "javascript", "AWS WAF challenge script detected");
  }

  // Kasada
  if ((status === 429 || status === 403) && lower.includes("kpsdk")) {
    return block("Kasada", "javascript", "Kasada client-side challenge");
  }

  // Vercel Attack Challenge Mode
  if (header("x-vercel-mitigated").toLowerCase() === "challenge") {
    return block("Vercel", "javascript", "Vercel attack challenge mode active");
  }

  // Sucuri
  if (status === 403 && lower.includes("sucuri") && lower.includes("access denied")) {
    return block("Sucuri", "access_denied", "Sucuri Website Firewall denied the request");
  }

  // F5 / Shape
  if (status === 403 && (lower.includes("the requested url was rejected") || lower.includes("your support id is"))) {
    return block("F5 BIG-IP ASM", "access_denied", "F5 Application Security Manager rejected the request");
  }

  // Fastly / generic 429
  if (status === 429) {
    return block(header("server") ? header("server") : "Unknown", "rate_limited", "HTTP 429 Too Many Requests");
  }

  // Generic access denied with a very short body
  if (status === 403 && sample.length < 4000 && /access denied|forbidden|not authorized/i.test(sample)) {
    return block(header("server") ? header("server") : "Unknown", "access_denied", "HTTP 403 with a generic access-denied body");
  }

  return NOT_BLOCKED;
}
