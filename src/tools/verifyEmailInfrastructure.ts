/**
 * verify_email_infrastructure: live DNS evaluation of MX, SPF, DKIM, DMARC,
 * MTA-STS, TLS-RPT and BIMI with disposable-domain detection, risk findings
 * and a transparent deliverability score.
 */

import { throwIfAborted } from "../lib/async.js";
import { DEFAULT_DKIM_SELECTORS, evaluateDkim } from "../lib/dkim.js";
import { checkDisposableDomain } from "../lib/disposable.js";
import { dmarcOwnLookupFailed, evaluateDmarc, isFallbackDmarcFinding } from "../lib/dmarc.js";
import { parseDomain, registrableDomain, stripWww } from "../lib/domain.js";
import { ToolError } from "../lib/errors.js";
import { countBySeverity, sortFindings, type Finding } from "../lib/findings.js";
import { evaluateBimi, evaluateMtaSts, evaluateTlsRpt, type MtaStsEvaluation } from "../lib/mailPolicies.js";
import { evaluateMx } from "../lib/mx.js";
import { scoreEmail } from "../lib/scoring.js";
import { evaluateSpf, spfPolicyLookupFailed, type SpfIncludeNode } from "../lib/spf.js";
import type { ToolContext } from "../middleware/metering.js";
import type { VerifyEmailInfrastructureInput, VerifyEmailInfrastructureOutput } from "../schemas.js";
import type { ToolDeps } from "./deps.js";

export type EmailResult = Omit<VerifyEmailInfrastructureOutput, "billing"> & { billing: null };

/** The parts of a result emailLookupFailures reads. */
export interface EmailLookupView {
  mx: { found: boolean; nullMx: boolean; dnsError: unknown };
  spf: { found: boolean; allQualifier?: string | null; redirect?: string | null };
  dmarc: { found: boolean; inheritedFromOrganizationalDomain?: boolean };
  risks: ReadonlyArray<{ code: string }>;
}

/**
 * Which absences in a result are unconfirmed because the lookup failed.
 * Every place that describes a result (the summary, bulk summaries, audit
 * highlights, score notes) uses this, so none of them claims "missing" for a
 * lookup that never answered.
 */
export function emailLookupFailures(result: EmailLookupView): { mx: boolean; spf: boolean; spfPolicy: boolean; dmarc: boolean; dmarcPolicy: boolean } {
  const codes = new Set(result.risks.map((r) => r.code));
  return {
    mx: !result.mx.found && !result.mx.nullMx && (result.mx.dnsError !== null || codes.has("MX_HOST_DNS_ERROR")),
    spf: !result.spf.found && codes.has("SPF_DNS_ERROR"),
    // The record exists but its policy lives behind a redirect= target whose lookup failed.
    spfPolicy: spfPolicyLookupFailed(result.spf, result.risks),
    dmarc: !result.dmarc.found && codes.has("DMARC_DNS_ERROR"),
    // A subdomain's own _dmarc lookup failed and the organizational record answered.
    dmarcPolicy: dmarcOwnLookupFailed(result.dmarc, result.risks)
  };
}

/**
 * The findings that describe the domain itself. When a subdomain's own
 * _dmarc lookup failed, its DMARC findings (other than that lookup's own
 * DMARC_DNS_ERROR) are the organizational record's and are left out. The
 * one-line summaries, bulk items, the audit's Top risks line and the stored
 * posture all follow this rule; the raw risks and riskCounts keep everything.
 */
export function ownFindings<T extends { code: string }>(findings: readonly T[], result: EmailLookupView | null): T[] {
  if (result === null || !emailLookupFailures(result).dmarcPolicy) return [...findings];
  return findings.filter((f) => !isFallbackDmarcFinding(f.code));
}

/** Short labels for a result's MX, SPF and DMARC state that never claim an absence a failed lookup did not confirm. */
export function describeEmailStatus(result: Pick<EmailResult, "mx" | "spf" | "dmarc" | "risks" | "providers">): { mx: string; spf: string; dmarc: string } {
  const failed = emailLookupFailures(result);
  return {
    mx: result.mx.nullMx
      ? "does not receive mail"
      : result.mx.found
        ? (result.providers.mailbox ?? "MX present")
        : failed.mx
          ? "MX unknown (lookup failed)"
          : result.mx.usesImplicitA
            ? "no MX (implicit A fallback)"
            : "no MX",
    spf: result.spf.found ? (failed.spfPolicy ? "unknown (lookup failed)" : result.spf.allPolicy) : failed.spf ? "unknown (lookup failed)" : "missing",
    dmarc: result.dmarc.found ? (failed.dmarcPolicy ? "unknown (lookup failed)" : `p=${result.dmarc.effectivePolicy ?? "invalid"}`) : failed.dmarc ? "unknown (lookup failed)" : "missing"
  };
}

function flattenIncludeTree(nodes: SpfIncludeNode[], parent: string | null, out: VerifyEmailInfrastructureOutput["spf"]["includeChain"]): void {
  for (const node of nodes) {
    out.push({ domain: node.domain, parent, depth: node.depth, record: node.record, lookups: node.lookups, error: node.error });
    flattenIncludeTree(node.children, node.domain, out);
  }
}

function describeDkim(found: EmailResult["dkim"]["selectors"]): string {
  const hits = found.filter((s) => s.found);
  if (hits.length === 0) return "DKIM not found under common selectors";
  const first = hits[0] as EmailResult["dkim"]["selectors"][number];
  const key = first.keyType === "rsa" && first.keyBits ? `${first.keyBits}-bit RSA` : (first.keyType ?? "unknown key");
  return `DKIM found (${hits.map((h) => h.selector).join(", ")}; ${key})`;
}

export async function verifyEmailInfrastructure(args: VerifyEmailInfrastructureInput, deps: ToolDeps, ctx: ToolContext): Promise<EmailResult> {
  const started = Date.now();
  const { config, dns } = deps;
  const parsed = parseDomain(args.domain, { allowPrivate: config.inspection.allowPrivateTargets });
  if (!parsed.ok) throw new ToolError(parsed.code, parsed.error, { details: { input: args.domain } });
  const domain = stripWww(parsed.domain);
  const organizationalDomain = registrableDomain(domain);

  throwIfAborted(ctx.signal);
  const existence = await dns.exists(domain);
  throwIfAborted(ctx.signal);
  if (existence.nxdomain) {
    throw new ToolError("DOMAIN_NOT_FOUND", `${domain} does not exist in DNS (NXDOMAIN).`, { details: { domain } });
  }
  if (!existence.exists && existence.error) {
    throw new ToolError("NETWORK_ERROR", `DNS resolution for ${domain} failed (${existence.error.code}: ${existence.error.message}).`, {
      retryable: true,
      details: { domain, dns: existence.error }
    });
  }

  // Storage trouble must never fail a paid call; it only means fewer selectors are probed.
  let known: string[] = [];
  try {
    known = deps.knownDkimSelectors?.(domain) ?? [];
  } catch {
    known = [];
  }
  const selectors = [...DEFAULT_DKIM_SELECTORS, ...config.inspection.extraDkimSelectors, ...args.dkimSelectors, ...known];
  // MTA-STS only needs the MX list for its final coverage check, so it runs
  // alongside the other evaluations and waits for the MX promise itself
  // rather than adding its DNS lookup and policy fetch after them.
  throwIfAborted(ctx.signal);
  const mxPromise = evaluateMx(domain, dns, ctx.signal);
  const mtaStsPromise: Promise<MtaStsEvaluation> = args.checkMtaSts
    ? evaluateMtaSts(
        domain,
        mxPromise.then((mx) => mx.records.map((r) => r.exchange)),
        dns,
        { timeoutMs: config.inspection.fetchTimeoutMs, userAgent: config.inspection.userAgent, allowPrivate: config.inspection.allowPrivateTargets, signal: ctx.signal }
      )
    : Promise.resolve({
        found: false,
        record: null,
        id: null,
        policy: {
          fetched: false,
          url: `https://mta-sts.${domain}/.well-known/mta-sts.txt`,
          version: null,
          mode: null,
          mx: [],
          maxAge: null,
          mxCoversAllExchanges: null,
          error: "skipped",
          failure: null
        },
        findings: []
      });
  const [mx, spf, dkim, dmarc, tlsRpt, bimi, mtaSts] = await Promise.all([
    mxPromise,
    evaluateSpf(domain, dns, ctx.signal),
    evaluateDkim(domain, selectors, dns, ctx.signal),
    evaluateDmarc(domain, organizationalDomain, dns, ctx.signal),
    evaluateTlsRpt(domain, dns),
    evaluateBimi(domain, dns),
    mtaStsPromise
  ]);
  throwIfAborted(ctx.signal);

  const disposable = checkDisposableDomain(domain);
  const extraFindings: Finding[] = [];
  if (disposable.disposable) {
    extraFindings.push({
      severity: "high",
      code: "DISPOSABLE_DOMAIN",
      message: `${domain} is a disposable / temporary email provider (${disposable.matchedDomain}).`,
      recommendation: "Treat addresses on this domain as low-quality leads and exclude them from outreach."
    });
  }
  if (parsed.isSubdomain && domain !== organizationalDomain) {
    extraFindings.push({
      severity: "info",
      code: "SUBDOMAIN_CHECKED",
      message: `${domain} is a subdomain of ${organizationalDomain}; DMARC falls back to the organizational domain when absent.`,
      recommendation: "Inspect the organizational domain as well for the complete picture."
    });
  }

  const risks = sortFindings([...mx.findings, ...spf.findings, ...dkim.findings, ...dmarc.findings, ...mtaSts.findings, ...tlsRpt.findings, ...bimi.findings, ...extraFindings]);
  const riskCounts = countBySeverity(risks);

  const failed = emailLookupFailures({ mx, spf, dmarc, risks });
  const score = scoreEmail({
    exists: true,
    disposable: disposable.disposable,
    mx: { found: mx.found, nullMx: mx.nullMx, usesImplicitA: mx.usesImplicitA, records: mx.records, lookupFailed: failed.mx },
    spf: {
      found: spf.found,
      lookupFailed: failed.spf,
      policyLookupFailed: failed.spfPolicy,
      valid: spf.valid,
      records: spf.records,
      allPolicy: spf.allPolicy,
      lookupLimitExceeded: spf.lookupLimitExceeded,
      voidLookupsExceeded: spf.voidLookups > 2,
      circularInclude: spf.findings.some((f) => f.code === "SPF_CIRCULAR_INCLUDE"),
      syntaxErrorCount: spf.findings.filter((f) => f.code === "SPF_SYNTAX_ERROR").length
    },
    dkim: { found: dkim.found, selectors: dkim.selectors },
    dmarc: {
      found: dmarc.found,
      lookupFailed: failed.dmarc,
      policyLookupFailed: failed.dmarcPolicy,
      valid: dmarc.valid,
      effectivePolicy: dmarc.effectivePolicy,
      pct: dmarc.pct,
      ruaCount: dmarc.rua.length
    },
    // A record whose policy file was not fetched (or was not a policy) has no
    // usable mode; only a fetched policy's mode earns points.
    mtaSts: { found: mtaSts.found, mode: mtaSts.policy.fetched ? mtaSts.policy.mode : null },
    tlsRpt: { found: tlsRpt.found },
    bimi: { found: bimi.found }
  });

  const includeChain: VerifyEmailInfrastructureOutput["spf"]["includeChain"] = [];
  flattenIncludeTree(spf.includeTree, null, includeChain);

  // A lookup that failed says nothing about absence; the summary must not claim "no X", nor state a
  // policy the failed lookup left unknown (the same wording as describeEmailStatus).
  const summaryParts = [
    mx.nullMx ? "Null MX (does not receive mail)" : mx.found ? `MX: ${mx.provider ?? mx.records[0]?.exchange ?? "present"}` : failed.mx ? "MX unknown (lookup failed)" : "no MX",
    spf.found
      ? failed.spfPolicy
        ? `SPF policy unknown (redirect=${spf.failedRedirect ?? spf.redirect} lookup failed)`
        : `SPF ${spf.allQualifier !== null ? `${spf.allQualifier}all` : spf.redirect ? `redirect=${spf.redirect}` : "without all"}${spf.redirect && spf.allQualifier !== null ? ` via redirect=${spf.redirect}` : ""} (${spf.lookupCount} lookups)`
      : failed.spf
        ? "SPF unknown (lookup failed)"
        : "no SPF",
    describeDkim(dkim.selectors),
    dmarc.found
      ? failed.dmarcPolicy
        ? `DMARC unknown (own _dmarc lookup failed; organizational p=${dmarc.effectivePolicy ?? "invalid"})`
        : `DMARC p=${dmarc.effectivePolicy ?? "invalid"}${dmarc.pct < 100 ? ` pct=${dmarc.pct}` : ""}${dmarc.inheritedFromOrganizationalDomain ? " (inherited)" : ""}`
      : failed.dmarc
        ? "DMARC unknown (lookup failed)"
        : "no DMARC",
    mtaSts.found ? `MTA-STS ${mtaSts.policy.mode ?? "unknown"}` : null,
    disposable.disposable ? "DISPOSABLE DOMAIN" : null
  ].filter((p): p is string => p !== null);
  // The organizational record's findings are not the subdomain's own (bulk items list none of them), so
  // the summary does not count them either; riskCounts still counts every finding in risks.
  const ownCounts = countBySeverity(ownFindings(risks, { mx, spf, dmarc, risks }));
  const summary = `${domain}: ${summaryParts.join("; ")}. Deliverability score ${score.score}/100 (${score.grade}); ${ownCounts.critical} critical, ${ownCounts.high} high, ${ownCounts.medium} medium risk(s).`;

  return {
    domain,
    inputDomain: parsed.input,
    organizationalDomain,
    isSubdomain: domain !== organizationalDomain,
    checkedAt: new Date(started).toISOString(),
    exists: true,
    nxdomain: false,
    mx: {
      found: mx.found,
      nullMx: mx.nullMx,
      provider: mx.provider,
      providers: mx.providers,
      usesImplicitA: mx.usesImplicitA,
      fallbackAddresses: mx.fallbackAddresses,
      records: mx.records,
      dnsError: mx.dnsError
    },
    spf: {
      found: spf.found,
      record: spf.record,
      records: spf.records,
      valid: spf.valid,
      allQualifier: spf.allQualifier,
      allPolicy: spf.allPolicy,
      includes: spf.includes,
      redirect: spf.redirect,
      ip4: spf.ip4,
      ip6: spf.ip6,
      lookupCount: spf.lookupCount,
      lookupLimitExceeded: spf.lookupLimitExceeded,
      voidLookups: spf.voidLookups,
      detectedSenders: spf.detectedSenders,
      mechanisms: spf.mechanisms,
      modifiers: spf.modifiers,
      includeChain
    },
    dkim: {
      found: dkim.found,
      checkedSelectors: dkim.checkedSelectors,
      providers: dkim.providers,
      weakKeys: dkim.weakKeys,
      selectors: dkim.selectors
    },
    dmarc: {
      found: dmarc.found,
      record: dmarc.record,
      records: dmarc.records,
      queriedName: dmarc.queriedName,
      location: dmarc.location,
      inheritedFromOrganizationalDomain: dmarc.inheritedFromOrganizationalDomain,
      valid: dmarc.valid,
      policy: dmarc.policy,
      subdomainPolicy: dmarc.subdomainPolicy,
      effectivePolicy: dmarc.effectivePolicy,
      pct: dmarc.pct,
      adkim: dmarc.adkim,
      aspf: dmarc.aspf,
      rua: dmarc.rua,
      ruf: dmarc.ruf,
      fo: dmarc.fo,
      rf: dmarc.rf,
      ri: dmarc.ri,
      tags: dmarc.tags,
      enforcement: dmarc.enforcement
    },
    mtaSts: { found: mtaSts.found, record: mtaSts.record, id: mtaSts.id, policy: mtaSts.policy },
    tlsRpt: { found: tlsRpt.found, record: tlsRpt.record, rua: tlsRpt.rua },
    bimi: { found: bimi.found, record: bimi.record, logoUrl: bimi.logoUrl, vmcUrl: bimi.vmcUrl },
    disposable,
    providers: { mailbox: mx.provider, sendingServices: spf.detectedSenders, dkimServices: dkim.providers },
    score: score.score,
    grade: score.grade,
    scoreBreakdown: score.breakdown,
    risks,
    riskCounts,
    summary,
    timings: { totalMs: Date.now() - started },
    billing: null
  };
}
