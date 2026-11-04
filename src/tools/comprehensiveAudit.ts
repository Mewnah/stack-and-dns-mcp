/**
 * comprehensive_audit: runs the tech-stack and email inspections
 * concurrently and folds them into one 0-100 health score with merged,
 * severity-sorted findings and agent-friendly highlights.
 */

import { settle, type Settled } from "../lib/async.js";
import { parseDomain } from "../lib/domain.js";
import { isToolError, ToolError, errorMessage } from "../lib/errors.js";
import { countBySeverity, sortFindings, type Finding } from "../lib/findings.js";
import { OVERALL_WEIGHTS, scoreInfrastructure, scoreOverall } from "../lib/scoring.js";
import type { ToolContext } from "../middleware/metering.js";
import type { ComprehensiveAuditInput, ComprehensiveAuditOutput } from "../schemas.js";
import type { ToolDeps } from "./deps.js";
import { inspectTechStack } from "./inspectTechStack.js";
import { describeEmailStatus, ownFindings, verifyEmailInfrastructure, type EmailResult } from "./verifyEmailInfrastructure.js";

export type AuditResult = Omit<ComprehensiveAuditOutput, "billing"> & { billing: null };

/**
 * The "Top risks" highlight. When a subdomain's own _dmarc lookup failed, the
 * organizational record's DMARC findings are not the subdomain's own (the
 * same rule as bulk summarizeEmail and the stored posture).
 */
export function topRisksHighlight(findings: Finding[], emailResult: EmailResult | null): string | null {
  const top = ownFindings(findings, emailResult).filter((f) => f.severity === "critical" || f.severity === "high");
  return top.length > 0
    ? `Top risks: ${top
        .slice(0, 4)
        .map((f) => f.code)
        .join(", ")}.`
    : null;
}

/**
 * The audit's email highlight. bulk audit items keep it verbatim, so it is
 * built from describeEmailStatus and never states a policy that a failed
 * lookup left unknown.
 */
export function emailHighlight(result: EmailResult): string {
  const status = describeEmailStatus(result);
  return `Email: ${status.mx}; SPF ${status.spf}; DKIM ${result.dkim.found ? "found" : "not found"}; DMARC ${status.dmarc} (score ${result.score}/100, ${result.grade}).`;
}

function describeError(err: unknown): { code: string; message: string } {
  if (isToolError(err)) return { code: err.code, message: err.message };
  return { code: "INTERNAL_ERROR", message: errorMessage(err) };
}

/** Settles a branch and measures its own wall-clock time from its own start. */
async function timed<T>(run: () => Promise<T>): Promise<{ outcome: Settled<T>; ms: number }> {
  const started = Date.now();
  const outcome = await settle(run());
  return { outcome, ms: Date.now() - started };
}

export async function comprehensiveAudit(args: ComprehensiveAuditInput, deps: ToolDeps, ctx: ToolContext): Promise<AuditResult> {
  const started = Date.now();
  const parsed = parseDomain(args.domain, { allowPrivate: deps.config.inspection.allowPrivateTargets });
  if (!parsed.ok) throw new ToolError(parsed.code, parsed.error, { details: { input: args.domain } });

  // Both children receive the caller's original input so that their
  // inputDomain fields report the same string as this audit's, while each
  // still applies its own normalization (the email check strips www.).
  const [tech, email] = await Promise.all([
    timed(() => inspectTechStack({ domain: args.domain, includeRawHeaders: args.includeRawHeaders, includeEvidence: args.includeEvidence }, deps, ctx)),
    timed(() => verifyEmailInfrastructure({ domain: args.domain, dkimSelectors: args.dkimSelectors, checkMtaSts: true }, deps, ctx))
  ]);
  const techOutcome = tech.outcome;
  const emailOutcome = email.outcome;

  const techStack = techOutcome.ok ? techOutcome.value : null;
  const emailResult = emailOutcome.ok ? emailOutcome.value : null;
  const techStackError = techOutcome.ok ? null : describeError(techOutcome.error);
  const emailError = emailOutcome.ok ? null : describeError(emailOutcome.error);

  if (!techStack && !emailResult) {
    // Surface whichever branch carries a typed ToolError (INVALID_DOMAIN,
    // DOMAIN_NOT_FOUND, NETWORK_ERROR); an untyped failure must not hide it.
    for (const outcome of [techOutcome, emailOutcome]) {
      if (!outcome.ok && isToolError(outcome.error)) throw outcome.error;
    }
    throw new ToolError("INTERNAL_ERROR", `Both inspections failed: ${techStackError?.message ?? ""} / ${emailError?.message ?? ""}`, { retryable: true });
  }

  const infrastructure = scoreInfrastructure({
    fetchOk: techStack?.fetch.ok ?? false,
    blocked: techStack?.blocked.blocked ?? false,
    categories: techStack ? techStack.technologies.map((t) => t.category) : []
  });
  const emailScore = emailResult?.score ?? 0;
  const securityScore = techStack?.security.score ?? 0;
  const overall = scoreOverall(emailScore, securityScore, infrastructure.score);

  const findings: Finding[] = sortFindings([...(emailResult?.risks ?? []), ...(techStack?.security.findings ?? [])]);
  const findingCounts = countBySeverity(findings);

  const highlights: string[] = [];
  if (techStack) {
    const platform = techStack.summary.ecommerce ?? techStack.summary.cms ?? techStack.summary.framework;
    const infra = [techStack.summary.cdn, techStack.summary.hosting].filter((x): x is string => x !== null);
    highlights.push(
      `Platform: ${platform ?? "not identified"}${infra.length > 0 ? ` on ${infra.join(" / ")}` : ""} (${techStack.summary.total} technologies detected${techStack.partial ? ", partial" : ""}).`
    );
    if (techStack.blocked.blocked) highlights.push(`Homepage fetch was blocked by ${techStack.blocked.vendor ?? "bot protection"}; stack detection is incomplete.`);
    if (!techStack.fetch.ok && techStack.fetch.error) highlights.push(`Homepage unreachable: ${techStack.fetch.error.kind} (${techStack.fetch.error.message}).`);
    const gtm = [techStack.summary.tagManager, ...techStack.summary.analytics].filter((x): x is string => x !== null);
    if (gtm.length > 0) highlights.push(`Analytics & tags: ${gtm.slice(0, 5).join(", ")}.`);
    const gtmStack = [...techStack.summary.marketingAutomation, ...techStack.summary.crm].filter((x, i, arr) => arr.indexOf(x) === i);
    if (gtmStack.length > 0) highlights.push(`Go-to-market stack: ${gtmStack.slice(0, 5).join(", ")}.`);
    if (techStack.summary.payments.length > 0) highlights.push(`Payments: ${techStack.summary.payments.join(", ")}.`);
    highlights.push(
      `Security: ${techStack.security.grade} (${techStack.security.score}/100); TLS ${techStack.security.tls.valid ? "valid" : techStack.security.tls.reachable ? "INVALID" : "unreachable"}${
        techStack.security.headers ? `, HSTS ${techStack.security.headers.hsts.present ? "on" : "off"}, CSP ${techStack.security.headers.csp.present ? "on" : "off"}` : ""
      }.`
    );
  } else if (techStackError) {
    highlights.push(`Tech stack inspection failed: ${techStackError.code} (${techStackError.message}).`);
  }
  if (emailResult) {
    highlights.push(emailHighlight(emailResult));
    if (emailResult.providers.sendingServices.length > 0) highlights.push(`Authorized senders: ${emailResult.providers.sendingServices.slice(0, 6).join(", ")}.`);
    if (emailResult.disposable.disposable) highlights.push("Disposable email domain detected.");
  } else if (emailError) {
    highlights.push(`Email inspection failed: ${emailError.code} (${emailError.message}).`);
  }
  const topRisks = topRisksHighlight(findings, emailResult);
  if (topRisks) highlights.push(topRisks);

  // Like the email summary, the sentence does not count the organizational record's DMARC findings
  // when a subdomain's own lookup failed; findingCounts still counts every finding in findings.
  const ownCounts = countBySeverity(ownFindings(findings, emailResult));
  const summary = `${parsed.domain} scores ${overall.score}/100 (${overall.grade}): email ${emailScore}, security ${securityScore}, infrastructure ${infrastructure.score}. ${ownCounts.critical} critical, ${ownCounts.high} high, ${ownCounts.medium} medium finding(s).`;

  return {
    domain: parsed.domain,
    inputDomain: parsed.input,
    auditedAt: new Date(started).toISOString(),
    scores: {
      overall: overall.score,
      grade: overall.grade,
      email: emailScore,
      security: securityScore,
      infrastructure: infrastructure.score,
      weights: { ...OVERALL_WEIGHTS },
      infrastructureBreakdown: infrastructure.breakdown
    },
    techStack: techStack ? { ...techStack, billing: null } : null,
    techStackError,
    email: emailResult ? { ...emailResult, billing: null } : null,
    emailError,
    findings,
    findingCounts,
    highlights,
    summary,
    timings: { totalMs: Date.now() - started, techStackMs: tech.ms, emailMs: email.ms },
    billing: null
  };
}
