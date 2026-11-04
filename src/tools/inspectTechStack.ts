/**
 * inspect_tech_stack: fetches the homepage with a hard deadline, fingerprints
 * the technology stack against the signature database, inspects TLS and
 * grades the security headers.
 */

import { throwIfAborted } from "../lib/async.js";
import { parseDomain, registrableDomain } from "../lib/domain.js";
import { ToolError } from "../lib/errors.js";
import { sortFindings, type Finding } from "../lib/findings.js";
import { fetchHomepage } from "../lib/http.js";
import { scoreSecurity } from "../lib/scoring.js";
import { analyzeSecurityHeaders } from "../lib/securityHeaders.js";
import { inspectTls, type TlsInspection } from "../lib/tls.js";
import type { ToolContext } from "../middleware/metering.js";
import type { InspectTechStackInput, InspectTechStackOutput } from "../schemas.js";
import { detectTechnologies, extractEvidence, loadSignatureDatabase, type Detection } from "../signatures/index.js";
import type { ToolDeps } from "./deps.js";

export type { ToolDeps };

export type TechStackResult = Omit<InspectTechStackOutput, "billing"> & { billing: null };

function tlsFindings(tls: TlsInspection, protocol: "https" | "http" | null, httpsDowngraded: boolean): Finding[] {
  const findings: Finding[] = [];
  if (!tls.reachable) {
    findings.push({
      severity: httpsDowngraded ? "high" : "medium",
      code: "TLS_UNREACHABLE",
      message: `Port 443 did not complete a TLS handshake (${tls.error?.code ?? "unknown"}: ${tls.error?.message ?? "no details"}).`,
      recommendation: "Serve the site over HTTPS with a valid certificate."
    });
    return findings;
  }
  if (tls.expired) {
    findings.push({
      severity: "critical",
      code: "TLS_CERT_EXPIRED",
      message: `The TLS certificate expired on ${tls.validTo ?? "an unknown date"}.`,
      recommendation: "Renew the certificate immediately; browsers block expired certificates."
    });
  } else if (tls.daysUntilExpiry !== null && tls.daysUntilExpiry <= 14) {
    findings.push({
      severity: "high",
      code: "TLS_CERT_EXPIRING",
      message: `The TLS certificate expires in ${tls.daysUntilExpiry} day(s).`,
      recommendation: "Renew the certificate or verify automated renewal is working."
    });
  } else if (tls.daysUntilExpiry !== null && tls.daysUntilExpiry <= 30) {
    findings.push({
      severity: "low",
      code: "TLS_CERT_EXPIRING_SOON",
      message: `The TLS certificate expires in ${tls.daysUntilExpiry} day(s).`,
      recommendation: "Confirm renewal is scheduled."
    });
  }
  if (tls.notYetValid) {
    findings.push({
      severity: "critical",
      code: "TLS_CERT_NOT_YET_VALID",
      message: "The TLS certificate's validity period has not started.",
      recommendation: "Check the server clock and certificate issuance."
    });
  }
  if (!tls.hostnameMatches) {
    findings.push({
      severity: "high",
      code: "TLS_HOSTNAME_MISMATCH",
      message: `The certificate does not cover this hostname (subject: ${tls.subject ?? "unknown"}).`,
      recommendation: "Issue a certificate whose SAN list includes the domain and the www subdomain."
    });
  }
  if (tls.selfSigned) {
    findings.push({
      severity: "high",
      code: "TLS_SELF_SIGNED",
      message: "The certificate is self-signed.",
      recommendation: "Use a certificate from a publicly trusted CA (for example Let's Encrypt)."
    });
  } else if (!tls.authorized && !tls.expired) {
    findings.push({
      severity: "high",
      code: "TLS_CHAIN_UNTRUSTED",
      message: `The certificate chain could not be validated (${tls.authorizationError ?? "unknown reason"}).`,
      recommendation: "Serve the full intermediate chain and use a publicly trusted CA."
    });
  }
  if (tls.protocol && /^(TLSv1|TLSv1\.1|SSLv3)$/i.test(tls.protocol)) {
    findings.push({ severity: "medium", code: "TLS_LEGACY_PROTOCOL", message: `The server negotiated ${tls.protocol}.`, recommendation: "Disable TLS 1.0/1.1 and prefer TLS 1.3." });
  }
  if (tls.keyType === "RSA" && tls.keyBits !== null && tls.keyBits < 2048) {
    findings.push({ severity: "medium", code: "TLS_WEAK_KEY", message: `The certificate uses a ${tls.keyBits}-bit RSA key.`, recommendation: "Re-issue with a 2048-bit RSA or P-256 EC key." });
  }
  if (protocol === "http") {
    findings.push({ severity: "high", code: "HTTPS_NOT_SERVED", message: "The homepage was only reachable over plaintext HTTP.", recommendation: "Enable HTTPS and redirect HTTP to HTTPS." });
  }
  return findings;
}

function pickFirst(detections: Detection[], categories: string[]): string | null {
  const direct = detections.find((d) => categories.includes(d.category) && !d.implied);
  if (direct) return direct.name;
  return detections.find((d) => categories.includes(d.category))?.name ?? null;
}

function pickAll(detections: Detection[], categories: string[]): string[] {
  return detections.filter((d) => categories.includes(d.category)).map((d) => d.name);
}

export async function inspectTechStack(args: InspectTechStackInput, deps: ToolDeps, ctx: ToolContext): Promise<TechStackResult> {
  const started = Date.now();
  const { config } = deps;
  const parsed = parseDomain(args.domain, { allowPrivate: config.inspection.allowPrivateTargets });
  if (!parsed.ok) throw new ToolError(parsed.code, parsed.error, { details: { input: args.domain } });
  const domain = parsed.domain;
  const warnings: string[] = [];
  const tlsOptions = { timeoutMs: config.inspection.tlsTimeoutMs, allowPrivate: config.inspection.allowPrivateTargets, signal: ctx.signal };

  const [page, apexTls] = await Promise.all([
    fetchHomepage(domain, {
      timeoutMs: config.inspection.fetchTimeoutMs,
      maxBodyBytes: config.inspection.maxBodyBytes,
      userAgent: config.inspection.userAgent,
      allowPrivate: config.inspection.allowPrivateTargets,
      signal: ctx.signal,
      ...(ctx.fetchGuard ? { beforeRequest: ctx.fetchGuard } : {})
    }),
    inspectTls(domain, tlsOptions)
  ]);

  // The fetcher and the TLS probe fold an aborted socket into their result
  // objects; a cancelled call must not proceed to detection on that basis.
  throwIfAborted(ctx.signal);

  if (page.error?.kind === "private_target") {
    throw new ToolError("PRIVATE_TARGET", page.error.message, { details: { domain } });
  }
  if (page.error?.kind === "dns") {
    // The fetcher's resolver failed; only a definitive NXDOMAIN means the
    // domain does not exist. A resolver outage is a retryable network
    // error, and a name that does exist is inspected as a partial result.
    const existence = await deps.dns.exists(domain);
    throwIfAborted(ctx.signal);
    if (existence.nxdomain) {
      throw new ToolError("DOMAIN_NOT_FOUND", `${domain} does not exist in DNS (NXDOMAIN).`, { details: { domain, dns: existence } });
    }
    if (!existence.exists && existence.error) {
      throw new ToolError("NETWORK_ERROR", `DNS resolution for ${domain} failed (${existence.error.code}: ${existence.error.message}).`, {
        retryable: true,
        details: { domain, dns: existence.error }
      });
    }
  }

  let tls = apexTls;
  if (!tls.reachable && page.finalHost && page.finalHost !== domain && page.protocol === "https") {
    const finalTls = await inspectTls(page.finalHost, tlsOptions);
    if (finalTls.reachable) {
      tls = finalTls;
      warnings.push(`TLS on ${domain} was unreachable; certificate details are for ${page.finalHost}.`);
    }
  }

  const detectStarted = Date.now();
  let technologies: Detection[] = [];
  if (page.ok) {
    const evidence = extractEvidence(page.html, page.headers, page.setCookies);
    technologies = detectTechnologies(evidence);
  }
  if (!args.includeEvidence) technologies = technologies.map((t) => ({ ...t, evidence: [] }));
  const detectMs = Date.now() - detectStarted;

  if (!page.ok && page.error) {
    warnings.push(`Homepage fetch failed (${page.error.kind}: ${page.error.message}); technology detection was skipped.`);
  }
  if (page.block.blocked) {
    warnings.push(`Request was blocked by ${page.block.vendor ?? "a WAF"} (${page.block.challengeType ?? "challenge"}); detection reflects the challenge page only.`);
  }
  if (page.truncated) warnings.push(`HTML body was truncated at ${config.inspection.maxBodyBytes} bytes; late-loading tags may be missed.`);
  if (page.httpsDowngraded) warnings.push("HTTPS was unreachable; content was fetched over plaintext HTTP.");
  if (page.tlsError) warnings.push(`TLS validation failed on first attempt (${page.tlsError.code}); the page was fetched with certificate validation disabled.`);
  if (page.ok && page.status !== null && page.status >= 400 && !page.block.blocked) warnings.push(`Homepage responded with HTTP ${page.status}.`);

  const categories: Record<string, string[]> = {};
  for (const t of technologies) (categories[t.category] ??= []).push(t.name);
  const byCategory: Record<string, number> = {};
  for (const [category, names] of Object.entries(categories)) byCategory[category] = names.length;

  const headersReport = page.ok ? analyzeSecurityHeaders(page.headers, { https: page.protocol === "https", setCookies: page.setCookies }) : null;
  const securityScore = scoreSecurity({
    fetchOk: page.ok,
    https: page.protocol === "https",
    headersScore: headersReport?.score ?? null,
    tls: {
      reachable: tls.reachable,
      valid: tls.valid,
      expired: tls.expired,
      hostnameMatches: tls.hostnameMatches,
      selfSigned: tls.selfSigned,
      daysUntilExpiry: tls.daysUntilExpiry
    }
  });
  const securityFindings = sortFindings([...(headersReport?.findings ?? []), ...tlsFindings(tls, page.protocol, page.httpsDowngraded)]);

  const redirectedOffDomain = page.finalHost !== null && registrableDomain(page.finalHost) !== parsed.registrable;
  if (redirectedOffDomain) warnings.push(`The homepage redirected to a different registrable domain (${page.finalHost}).`);

  const db = loadSignatureDatabase();

  return {
    domain,
    inputDomain: parsed.input,
    fetchedAt: new Date(started).toISOString(),
    fetch: {
      ok: page.ok,
      requestedUrl: page.requestedUrl,
      finalUrl: page.finalUrl,
      finalHost: page.finalHost,
      protocol: page.protocol,
      status: page.status,
      statusText: page.statusText,
      contentType: page.contentType,
      bodyBytes: page.bodyBytes,
      truncated: page.truncated,
      responseTimeMs: page.timings.totalMs,
      attempts: page.timings.attempts,
      redirectChain: page.redirectChain,
      redirectedOffDomain,
      httpsDowngraded: page.httpsDowngraded,
      tlsError: page.tlsError,
      error: page.error
    },
    blocked: page.block,
    partial: !page.ok || page.block.blocked || page.truncated,
    technologies,
    categories,
    summary: {
      total: technologies.length,
      byCategory,
      cms: pickFirst(technologies, ["cms", "site-builder", "headless-cms", "ssg"]),
      ecommerce: pickFirst(technologies, ["ecommerce"]),
      framework: pickFirst(technologies, ["web-framework", "js-framework"]),
      cdn: pickFirst(technologies, ["cdn"]),
      hosting: pickFirst(technologies, ["hosting"]),
      webServer: pickFirst(technologies, ["web-server"]),
      tagManager: pickFirst(technologies, ["tag-manager"]),
      analytics: pickAll(technologies, ["analytics", "product-analytics"]),
      marketingAutomation: pickAll(technologies, ["marketing-automation", "email-marketing"]),
      crm: pickAll(technologies, ["crm"]),
      payments: pickAll(technologies, ["payments", "subscription-billing", "bnpl"]),
      liveChat: pickAll(technologies, ["live-chat", "customer-support"]),
      advertising: pickAll(technologies, ["advertising"]),
      waf: pickAll(technologies, ["waf", "captcha"])
    },
    security: {
      score: securityScore.score,
      grade: securityScore.grade,
      breakdown: securityScore.breakdown,
      tls,
      headers: headersReport,
      findings: securityFindings
    },
    rawHeaders: args.includeRawHeaders && page.ok ? { ...page.headers, ...(page.setCookies.length > 0 ? { "set-cookie": page.setCookies.join("\n") } : {}) } : null,
    signatureDatabase: { version: db.version, count: db.signatures.length },
    timings: { totalMs: Date.now() - started, fetchMs: page.timings.totalMs, tlsMs: tls.durationMs, detectMs },
    warnings,
    billing: null
  };
}
