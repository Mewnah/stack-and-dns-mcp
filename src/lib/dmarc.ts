/**
 * DMARC (RFC 7489) discovery, parsing and policy evaluation, including
 * organizational-domain fallback for subdomains and external report
 * destination authorization checks.
 */

import { mapConcurrent, throwIfAborted } from "./async.js";
import type { DnsClient } from "./dns.js";
import type { Finding } from "./findings.js";
import { parseSafeInteger } from "./numbers.js";

export type DmarcPolicy = "none" | "quarantine" | "reject";
export type DmarcAlignment = "r" | "s";
export type DmarcEnforcement = "none" | "partial" | "full";

export interface DmarcParsedRecord {
  tags: Record<string, string>;
  errors: string[];
}

export interface DmarcReportDestination {
  uri: string;
  domain: string | null;
  external: boolean;
  authorized: boolean | null;
}

export interface DmarcEvaluation {
  found: boolean;
  record: string | null;
  records: string[];
  queriedName: string;
  location: string | null;
  inheritedFromOrganizationalDomain: boolean;
  valid: boolean;
  policy: DmarcPolicy | null;
  subdomainPolicy: DmarcPolicy | null;
  effectivePolicy: DmarcPolicy | null;
  pct: number;
  adkim: DmarcAlignment;
  aspf: DmarcAlignment;
  rua: DmarcReportDestination[];
  ruf: DmarcReportDestination[];
  fo: string;
  rf: string;
  ri: number;
  tags: Record<string, string>;
  enforcement: DmarcEnforcement;
  findings: Finding[];
}

const POLICIES = new Set<DmarcPolicy>(["none", "quarantine", "reject"]);

export function isDmarcRecord(value: string): boolean {
  return /^v=dmarc1(\s*;|\s*$)/i.test(value.trim());
}

/**
 * True when a subdomain's own _dmarc lookup failed and the organizational
 * record answered instead: the record, its policy and its findings are the
 * organizational domain's, and the subdomain's own policy is unknown.
 * evaluateDmarc only reports the organizational lookup's error when that
 * lookup returned no record, so an inherited record next to DMARC_DNS_ERROR
 * always means the own lookup failed; an own lookup that answered with no
 * record (legitimate inheritance) has no error. The status labels,
 * summaries, the score and the stored posture all use this one rule.
 */
export function dmarcOwnLookupFailed(dmarc: { found: boolean; inheritedFromOrganizationalDomain?: boolean }, risks: ReadonlyArray<{ code: string }>): boolean {
  return dmarc.found && dmarc.inheritedFromOrganizationalDomain === true && risks.some((r) => r.code === "DMARC_DNS_ERROR");
}

/**
 * Whether a finding belongs to the organizational record rather than to the
 * subdomain once dmarcOwnLookupFailed holds: every DMARC finding except the
 * DMARC_DNS_ERROR that reports the subdomain's own failed lookup.
 */
export function isFallbackDmarcFinding(code: string): boolean {
  return code.startsWith("DMARC_") && code !== "DMARC_DNS_ERROR";
}

export function parseDmarcRecord(record: string): DmarcParsedRecord {
  // Null prototype: tag names come from a remote TXT record, so "constructor"
  // or "__proto__" must not resolve through Object.prototype.
  const tags: Record<string, string> = Object.create(null) as Record<string, string>;
  const errors: string[] = [];
  const parts = record
    .split(";")
    .map((p) => p.trim())
    .filter((p) => p.length > 0);
  parts.forEach((part, index) => {
    const eq = part.indexOf("=");
    if (eq === -1) {
      errors.push(`Tag "${part}" has no value.`);
      return;
    }
    const name = part.slice(0, eq).trim().toLowerCase();
    const value = part.slice(eq + 1).trim();
    if (index === 0 && name !== "v") errors.push("The v=DMARC1 tag must appear first.");
    if (Object.hasOwn(tags, name)) errors.push(`Duplicate tag "${name}".`);
    tags[name] = value;
  });
  if (tags.v === undefined || !/^dmarc1$/i.test(tags.v)) errors.push("Missing or invalid v=DMARC1 tag.");
  if (tags.p === undefined) errors.push("Required p= tag is missing.");
  else if (!POLICIES.has(tags.p.toLowerCase() as DmarcPolicy)) errors.push(`Invalid p= value "${tags.p}" (expected none, quarantine or reject).`);
  if (tags.sp !== undefined && !POLICIES.has(tags.sp.toLowerCase() as DmarcPolicy)) errors.push(`Invalid sp= value "${tags.sp}".`);
  if (tags.pct !== undefined && !(/^\d{1,3}$/.test(tags.pct) && Number(tags.pct) <= 100)) errors.push(`Invalid pct= value "${tags.pct}".`);
  if (tags.adkim !== undefined && !/^[rs]$/i.test(tags.adkim)) errors.push(`Invalid adkim= value "${tags.adkim}".`);
  if (tags.aspf !== undefined && !/^[rs]$/i.test(tags.aspf)) errors.push(`Invalid aspf= value "${tags.aspf}".`);
  if (tags.ri !== undefined && !/^\d+$/.test(tags.ri)) errors.push(`Invalid ri= value "${tags.ri}".`);
  return { tags, errors };
}

function parseDestinations(raw: string | undefined, organizationalDomain: string): DmarcReportDestination[] {
  if (!raw) return [];
  const out: DmarcReportDestination[] = [];
  for (const item of raw.split(",")) {
    const uri = item.trim().replace(/!\d+[kmgt]?$/i, "");
    if (!uri) continue;
    let domain: string | null = null;
    const mailto = /^mailto:([^@\s]+)@([^\s>]+)$/i.exec(uri);
    if (mailto) domain = (mailto[2] as string).toLowerCase();
    const external = domain !== null && domain !== organizationalDomain && !domain.endsWith(`.${organizationalDomain}`);
    out.push({ uri, domain, external, authorized: external ? null : true });
  }
  return out;
}

/**
 * RFC 7489 section 7.1: the report receiver authorizes the domain whose
 * DMARC record names it, i.e. the domain the policy was actually found at,
 * which is the subdomain itself when it publishes its own record and the
 * organizational domain only when the record was inherited from there.
 */
function externalAuthorizationName(policyDomain: string, destinationDomain: string): string {
  return `${policyDomain}._report._dmarc.${destinationDomain}`;
}

async function checkExternalAuthorization(destinations: DmarcReportDestination[], policyDomain: string, dns: DnsClient, signal: AbortSignal | undefined): Promise<void> {
  const external = destinations.filter((d) => d.external && d.domain).slice(0, 3);
  await mapConcurrent(
    external,
    3,
    async (destination) => {
      const name = externalAuthorizationName(policyDomain, destination.domain as string);
      const txt = await dns.txt(name);
      if (txt.error) {
        destination.authorized = null;
        return;
      }
      destination.authorized = txt.records.some(isDmarcRecord);
    },
    signal
  );
}

export async function evaluateDmarc(domainInput: string, organizationalDomainInput: string, dns: DnsClient, signal?: AbortSignal): Promise<DmarcEvaluation> {
  throwIfAborted(signal);
  // DNS names are case-insensitive; normalise so labels, comparisons and
  // remediation text do not echo the caller's casing.
  const domain = domainInput.toLowerCase().replace(/\.$/, "");
  const organizationalDomain = organizationalDomainInput.toLowerCase().replace(/\.$/, "");
  const findings: Finding[] = [];
  const queriedName = `_dmarc.${domain}`;
  const evaluation: DmarcEvaluation = {
    found: false,
    record: null,
    records: [],
    queriedName,
    location: null,
    inheritedFromOrganizationalDomain: false,
    valid: false,
    policy: null,
    subdomainPolicy: null,
    effectivePolicy: null,
    pct: 100,
    adkim: "r",
    aspf: "r",
    rua: [],
    ruf: [],
    fo: "0",
    rf: "afrf",
    ri: 86400,
    tags: {},
    enforcement: "none",
    findings
  };

  const lookup = await dns.txt(queriedName);
  // Sorted: resolvers return RRsets in any order, and the record evaluated must not depend on it.
  let records = lookup.records.filter(isDmarcRecord).sort();
  let location = queriedName;
  // Every lookup that errored is reported, including the organizational
  // fallback: an unanswered org query must never be read as "no record".
  const lookupErrors: Array<{ name: string; code: string }> = [];
  if (lookup.error) lookupErrors.push({ name: queriedName, code: lookup.error.code });
  if (records.length === 0 && organizationalDomain !== domain) {
    const orgName = `_dmarc.${organizationalDomain}`;
    const orgLookup = await dns.txt(orgName);
    const orgRecords = orgLookup.records.filter(isDmarcRecord).sort();
    if (orgRecords.length > 0) {
      records = orgRecords;
      location = orgName;
      evaluation.inheritedFromOrganizationalDomain = true;
    } else if (orgLookup.error) {
      lookupErrors.push({ name: orgName, code: orgLookup.error.code });
    }
  }
  // The organizational lookup's error is only recorded when it found no
  // record, so an inherited record next to DMARC_DNS_ERROR always means the
  // subdomain's own lookup failed. dmarcOwnLookupFailed relies on this to
  // tell "own lookup failed, organizational record used" (policy unknown)
  // from "no own record, organizational record inherited" (no error at all).
  for (const failed of lookupErrors) {
    const usedFallback = evaluation.inheritedFromOrganizationalDomain && failed.name === queriedName;
    findings.push({
      severity: "medium",
      code: "DMARC_DNS_ERROR",
      message: usedFallback
        ? `TXT lookup for ${failed.name} failed (${failed.code}); the organizational record at ${location} was used, so ${domain}'s own policy is unknown.`
        : `TXT lookup for ${failed.name} failed (${failed.code}).`,
      recommendation: "Verify the authoritative nameservers respond correctly and retry."
    });
  }
  evaluation.records = records;
  if (records.length === 0) {
    const where = `${queriedName}${organizationalDomain !== domain ? ` or _dmarc.${organizationalDomain}` : ""}`;
    findings.push(
      lookupErrors.length > 0
        ? {
            severity: "medium",
            code: "DMARC_MISSING",
            message: `No DMARC record was found at ${where}, but a lookup failed (${lookupErrors.map((f) => f.code).join(", ")}), so its absence is unconfirmed.`,
            recommendation: 'Retry once the nameservers answer; if no record exists, publish "v=DMARC1; p=none; rua=mailto:dmarc@yourdomain" to start monitoring.'
          }
        : {
            severity: "high",
            code: "DMARC_MISSING",
            message: `No DMARC record is published at ${where}.`,
            recommendation: 'Publish "v=DMARC1; p=none; rua=mailto:dmarc@yourdomain" to start monitoring, then move to quarantine/reject.'
          }
    );
    return evaluation;
  }

  evaluation.found = true;
  evaluation.location = location;
  const record = records[0] as string;
  evaluation.record = record;
  if (records.length > 1) {
    findings.push({
      severity: "critical",
      code: "DMARC_MULTIPLE_RECORDS",
      message: `${records.length} DMARC records were found at ${location}; receivers ignore DMARC entirely in this case.`,
      recommendation: "Remove duplicates so exactly one v=DMARC1 record remains."
    });
  }

  const parsed = parseDmarcRecord(record);
  evaluation.tags = parsed.tags;
  for (const error of parsed.errors) {
    findings.push({
      severity: "high",
      code: "DMARC_SYNTAX_ERROR",
      message: `DMARC syntax problem: ${error}`,
      recommendation: "Correct the record; malformed DMARC records are ignored by receivers."
    });
  }

  const p = parsed.tags.p?.toLowerCase();
  evaluation.policy = p && POLICIES.has(p as DmarcPolicy) ? (p as DmarcPolicy) : null;
  const sp = parsed.tags.sp?.toLowerCase();
  evaluation.subdomainPolicy = sp && POLICIES.has(sp as DmarcPolicy) ? (sp as DmarcPolicy) : null;
  evaluation.effectivePolicy = evaluation.inheritedFromOrganizationalDomain ? (evaluation.subdomainPolicy ?? evaluation.policy) : evaluation.policy;
  evaluation.pct = parsed.tags.pct !== undefined && /^\d{1,3}$/.test(parsed.tags.pct) ? Math.min(100, Number(parsed.tags.pct)) : 100;
  evaluation.adkim = /^s$/i.test(parsed.tags.adkim ?? "") ? "s" : "r";
  evaluation.aspf = /^s$/i.test(parsed.tags.aspf ?? "") ? "s" : "r";
  evaluation.fo = parsed.tags.fo ?? "0";
  evaluation.rf = parsed.tags.rf ?? "afrf";
  evaluation.ri = parseSafeInteger(parsed.tags.ri) ?? 86400;
  evaluation.rua = parseDestinations(parsed.tags.rua, organizationalDomain);
  evaluation.ruf = parseDestinations(parsed.tags.ruf, organizationalDomain);
  const policyDomain = evaluation.inheritedFromOrganizationalDomain ? organizationalDomain : domain;
  await Promise.all([checkExternalAuthorization(evaluation.rua, policyDomain, dns, signal), checkExternalAuthorization(evaluation.ruf, policyDomain, dns, signal)]);

  const effective = evaluation.effectivePolicy;
  if (effective === "none") {
    evaluation.enforcement = "none";
    findings.push({
      severity: "medium",
      code: "DMARC_POLICY_NONE",
      message: "DMARC policy is p=none: spoofed mail is reported but still delivered.",
      recommendation: "Move to p=quarantine and then p=reject once aggregate reports show all legitimate mail is aligned."
    });
  } else if (effective === "quarantine" || effective === "reject") {
    evaluation.enforcement = evaluation.pct >= 100 ? "full" : "partial";
    if (effective === "quarantine") {
      findings.push({
        severity: "info",
        code: "DMARC_QUARANTINE",
        message: "DMARC policy is p=quarantine; unauthenticated mail goes to spam rather than being rejected.",
        recommendation: "Upgrade to p=reject for maximum spoofing protection."
      });
    }
  }
  if (evaluation.pct < 100 && effective !== "none") {
    findings.push({
      severity: "low",
      code: "DMARC_PCT_BELOW_100",
      message: `Only ${evaluation.pct}% of failing messages are subject to the policy (pct=${evaluation.pct}).`,
      recommendation: "Raise pct to 100 once the rollout is complete."
    });
  }
  if (evaluation.rua.length === 0) {
    findings.push({
      severity: "low",
      code: "DMARC_NO_RUA",
      message: "No aggregate report address (rua=) is configured, so authentication failures are invisible.",
      recommendation: "Add rua=mailto:<reports@yourdomain> and monitor the reports."
    });
  }
  for (const destination of [...evaluation.rua, ...evaluation.ruf]) {
    if (destination.external && destination.authorized === false) {
      findings.push({
        severity: "low",
        code: "DMARC_EXTERNAL_REPORT_UNAUTHORIZED",
        message: `Report destination ${destination.uri} is on an external domain that has not published an authorization record.`,
        recommendation: `Ask the report processor to publish ${externalAuthorizationName(policyDomain, destination.domain as string)} TXT "v=DMARC1".`
      });
    }
    if (destination.domain === null) {
      findings.push({
        severity: "low",
        code: "DMARC_INVALID_REPORT_URI",
        message: `Report destination "${destination.uri}" is not a valid mailto: URI.`,
        recommendation: "Use mailto:address@domain URIs for rua and ruf."
      });
    }
  }
  if (
    evaluation.policy !== null &&
    evaluation.subdomainPolicy !== null &&
    ((evaluation.policy === "reject" && evaluation.subdomainPolicy !== "reject") || (evaluation.policy === "quarantine" && evaluation.subdomainPolicy === "none"))
  ) {
    findings.push({
      severity: "low",
      code: "DMARC_SUBDOMAIN_POLICY_WEAKER",
      message: `Subdomain policy sp=${evaluation.subdomainPolicy} is weaker than the organizational policy p=${evaluation.policy}.`,
      recommendation: "Align sp with p unless subdomains intentionally send unauthenticated mail."
    });
  }

  evaluation.valid = parsed.errors.length === 0 && records.length === 1 && evaluation.policy !== null;
  return evaluation;
}
