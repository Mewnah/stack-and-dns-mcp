/**
 * SPF (RFC 7208) record discovery, parsing and evaluation.
 *
 * Counts DNS-querying terms recursively through include: and redirect=
 * (with loop and depth protection), tracks void lookups, classifies the
 * terminal "all" policy and identifies well-known sending platforms.
 */

import { mapConcurrent, throwIfAborted } from "./async.js";
import type { DnsClient } from "./dns.js";
import type { Finding } from "./findings.js";
import { matchProvider, type ProviderTable } from "./providers.js";

export type SpfQualifier = "+" | "-" | "~" | "?";
export type SpfMechanismType = "all" | "include" | "a" | "mx" | "ptr" | "ip4" | "ip6" | "exists";
export type SpfAllPolicy = "fail" | "softfail" | "neutral" | "pass" | "none";

export interface SpfMechanism {
  qualifier: SpfQualifier;
  type: SpfMechanismType;
  value: string | null;
  raw: string;
}

export interface SpfModifier {
  name: string;
  value: string;
  raw: string;
}

export interface SpfParsedRecord {
  mechanisms: SpfMechanism[];
  modifiers: SpfModifier[];
  errors: string[];
}

export interface SpfIncludeNode {
  domain: string;
  record: string | null;
  lookups: number;
  depth: number;
  error: string | null;
  children: SpfIncludeNode[];
}

export interface SpfEvaluation {
  found: boolean;
  record: string | null;
  records: string[];
  valid: boolean;
  mechanisms: SpfMechanism[];
  modifiers: SpfModifier[];
  allQualifier: SpfQualifier | null;
  allPolicy: SpfAllPolicy;
  includes: string[];
  redirect: string | null;
  /** The redirect= hop whose lookup failed, leaving the terminal policy unknown (allPolicy then keeps its default "none"); null otherwise. */
  failedRedirect: string | null;
  ip4: string[];
  ip6: string[];
  lookupCount: number;
  lookupLimitExceeded: boolean;
  voidLookups: number;
  includeTree: SpfIncludeNode[];
  detectedSenders: string[];
  findings: Finding[];
}

const MECHANISM_TYPES = new Set<SpfMechanismType>(["all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"]);
const LOOKUP_MECHANISMS = new Set<SpfMechanismType>(["include", "a", "mx", "ptr", "exists"]);
const MAX_DEPTH = 10;
const EXPANSION_BUDGET = 25;

const KNOWN_SENDERS: ProviderTable = [
  [/(^|\.)_spf\.google\.com$/i, "Google Workspace"],
  [/(^|\.)spf\.protection\.outlook\.com$/i, "Microsoft 365"],
  [/(^|\.)sendgrid\.net$/i, "SendGrid"],
  [/(^|\.)servers\.mcsv\.net$/i, "Mailchimp"],
  [/(^|\.)spf\.mandrillapp\.com$/i, "Mandrill"],
  [/(^|\.)mail\.zendesk\.com$/i, "Zendesk"],
  [/(^|\.)_spf\.salesforce\.com$/i, "Salesforce"],
  [/(^|\.)pardot\.com$/i, "Salesforce Pardot"],
  [/(^|\.)exacttarget\.com$/i, "Salesforce Marketing Cloud"],
  [/(^|\.)mailgun\.org$/i, "Mailgun"],
  [/(^|\.)amazonses\.com$/i, "Amazon SES"],
  [/(^|\.)hubspotemail\.net$/i, "HubSpot"],
  [/(^|\.)_spf\.klaviyo\.com$/i, "Klaviyo"],
  [/(^|\.)(spf\.brevo\.com|spf\.sendinblue\.com)$/i, "Brevo"],
  [/(^|\.)spf\.constantcontact\.com$/i, "Constant Contact"],
  [/(^|\.)_spf\.intercom\.io$/i, "Intercom"],
  [/(^|\.)(spf\.postmarkapp\.com|spf\.mtasv\.net)$/i, "Postmark"],
  [/(^|\.)mktomail\.com$/i, "Marketo"],
  [/(^|\.)_spf\.mailjet\.com$/i, "Mailjet"],
  [/(^|\.)(zoho\.com|zohomail\.com|zoho\.eu)$/i, "Zoho Mail"],
  [/(^|\.)_spf\.freshdesk\.com$/i, "Freshdesk"],
  [/(^|\.)_spf\.atlassian\.net$/i, "Atlassian"],
  [/(^|\.)spf\.sparkpostmail\.com$/i, "SparkPost"],
  [/(^|\.)_spf\.qualtrics\.com$/i, "Qualtrics"],
  [/(^|\.)mailsenders\.netsuite\.com$/i, "NetSuite"],
  [/(^|\.)_netblocks\.mimecast\.com$/i, "Mimecast"],
  [/(^|\.)pphosted\.com$/i, "Proofpoint"],
  [/(^|\.)customeriomail\.com$/i, "Customer.io"],
  [/(^|\.)_spf\.drift\.com$/i, "Drift"],
  [/(^|\.)spf\.outreach\.io$/i, "Outreach"],
  [/(^|\.)_spf\.salesloft\.com$/i, "Salesloft"],
  [/(^|\.)_spf\.smtp\.com$/i, "SMTP.com"],
  [/(^|\.)(spf\.mailerlite\.com|_spf\.mlsend\.com)$/i, "MailerLite"],
  [/(^|\.)emsend\d*\.com$/i, "ActiveCampaign"],
  [/(^|\.)_spf\.elasticemail\.com$/i, "Elastic Email"],
  [/(^|\.)spf\.sendpulse\.com$/i, "SendPulse"],
  [/(^|\.)_spf\.mailtrap\.io$/i, "Mailtrap"],
  [/(^|\.)spf\.resend\.com$/i, "Resend"],
  [/(^|\.)_spf\.protonmail\.ch$/i, "Proton Mail"],
  [/(^|\.)spf\.messagingengine\.com$/i, "Fastmail"],
  [/(^|\.)secureserver\.net$/i, "GoDaddy"],
  [/(^|\.)(_spf\.ionos\.com|_spf\.perfora\.net|_spf\.kundenserver\.de)$/i, "IONOS"],
  [/(^|\.)mx\.ovh\.com$/i, "OVH"],
  [/(^|\.)_spf\.titan\.email$/i, "Titan"],
  [/(^|\.)(_spf\.yandex\.net|_spf\.yandex\.ru)$/i, "Yandex"],
  [/(^|\.)spf\.mail\.ru$/i, "Mail.ru"],
  [/(^|\.)_spf\.improvmx\.com$/i, "ImprovMX"],
  [/(^|\.)_spf\.mx\.cloudflare\.net$/i, "Cloudflare Email Routing"],
  [/(^|\.)spf\.forwardemail\.net$/i, "Forward Email"],
  [/(^|\.)_spf\.barracudanetworks\.com$/i, "Barracuda"],
  [/(^|\.)emailsrvr\.com$/i, "Rackspace Email"],
  [/(^|\.)shops\.shopify\.com$/i, "Shopify"],
  [/(^|\.)_spf\.github\.com$/i, "GitHub"],
  [/(^|\.)_spf\.stripe\.com$/i, "Stripe"],
  [/(^|\.)_spf\.docusign\.net$/i, "DocuSign"],
  [/(^|\.)_spf\.gong\.io$/i, "Gong"],
  [/(^|\.)_spf\.zoom\.us$/i, "Zoom"],
  [/(^|\.)spf\.workday\.com$/i, "Workday"],
  [/(^|\.)_spf\.greenhouse\.io$/i, "Greenhouse"],
  [/(^|\.)_spf\.lever\.co$/i, "Lever"],
  [/(^|\.)_spf\.gusto\.com$/i, "Gusto"],
  [/(^|\.)_spf\.rippling\.com$/i, "Rippling"],
  [/(^|\.)_spf\.slack\.com$/i, "Slack"],
  [/(^|\.)mail\.notion\.so$/i, "Notion"],
  [/(^|\.)_spf\.hey\.com$/i, "HEY"],
  [/(^|\.)_spf\.mailchimp\.com$/i, "Mailchimp"]
];

export function isSpfRecord(value: string): boolean {
  return /^v=spf1(\s|$)/i.test(value.trim());
}

/**
 * True when the record exists but its terminal policy sits behind a redirect=
 * target whose lookup failed, so the policy is unknown rather than the "none"
 * allPolicy defaults to. evaluateSpf reports SPF_DNS_ERROR next to a found
 * record only in that case (a failed include is SPF_INCLUDE_DNS_ERROR). The
 * status labels, summaries and the stored posture all use this one rule.
 */
export function spfPolicyLookupFailed(spf: { found: boolean; allQualifier?: string | null; redirect?: string | null }, risks: ReadonlyArray<{ code: string }>): boolean {
  return spf.found && (spf.allQualifier ?? null) === null && (spf.redirect ?? null) !== null && risks.some((r) => r.code === "SPF_DNS_ERROR");
}

export function parseSpfRecord(record: string): SpfParsedRecord {
  const mechanisms: SpfMechanism[] = [];
  const modifiers: SpfModifier[] = [];
  const errors: string[] = [];
  const terms = record.trim().split(/\s+/);
  const version = terms[0] ?? "";
  if (!/^v=spf1$/i.test(version)) {
    errors.push(`Record must begin with "v=spf1" (found "${version}").`);
  }
  for (const term of terms.slice(1)) {
    if (term.length === 0) continue;
    const modifierMatch = /^([a-z][a-z0-9_.-]*)=(.*)$/i.exec(term);
    if (modifierMatch) {
      const name = (modifierMatch[1] as string).toLowerCase();
      const value = modifierMatch[2] as string;
      if ((name === "redirect" || name === "exp") && value.length === 0) {
        errors.push(`Modifier "${name}" requires a value.`);
      }
      modifiers.push({ name, value, raw: term });
      continue;
    }

    let qualifier: SpfQualifier = "+";
    let body = term;
    const firstChar = term.charAt(0);
    if (firstChar === "+" || firstChar === "-" || firstChar === "~" || firstChar === "?") {
      qualifier = firstChar;
      body = term.slice(1);
    }

    let typeToken = body;
    let value: string | null = null;
    const separatorIndex = body.search(/[:/]/);
    if (separatorIndex !== -1) {
      typeToken = body.slice(0, separatorIndex);
      const remainder = body.slice(separatorIndex);
      value = remainder.startsWith(":") ? remainder.slice(1) : remainder;
      if (value.length === 0) value = null;
    }
    const type = typeToken.toLowerCase() as SpfMechanismType;
    if (!MECHANISM_TYPES.has(type)) {
      errors.push(`Unknown term "${term}".`);
      continue;
    }
    if ((type === "include" || type === "exists" || type === "ip4" || type === "ip6") && (value === null || value.startsWith("/"))) {
      errors.push(`Mechanism "${type}" requires a value (found "${term}").`);
      continue;
    }
    if (type === "ip4" && value !== null && !/^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(value)) {
      errors.push(`ip4 mechanism "${term}" is not a valid IPv4 address or CIDR.`);
    }
    if (type === "ip6" && value !== null && !/^[0-9a-f:.]+(\/\d{1,3})?$/i.test(value)) {
      errors.push(`ip6 mechanism "${term}" is not a valid IPv6 address or CIDR.`);
    }
    mechanisms.push({ qualifier, type, value, raw: term });
  }
  return { mechanisms, modifiers, errors };
}

interface LookupState {
  count: number;
  voidLookups: number;
  expansions: number;
  /** Include targets whose lookup failed (a temperror, not a void lookup). */
  dnsErrors: string[];
}

function containsMacro(value: string): boolean {
  return value.includes("%{");
}

function stripCidr(value: string): string {
  const slash = value.indexOf("/");
  return slash === -1 ? value : value.slice(0, slash);
}

/** Maps an "all" qualifier to the policy receivers apply to unlisted senders. */
function policyForQualifier(qualifier: SpfQualifier): SpfAllPolicy {
  switch (qualifier) {
    case "-":
      return "fail";
    case "~":
      return "softfail";
    case "?":
      return "neutral";
    default:
      return "pass";
  }
}

interface PendingInclude {
  node: SpfIncludeNode;
  ancestors: ReadonlySet<string>;
}

/**
 * Expands include: (and redirect=) targets one tree level at a time. At each
 * level every guard, including the expansion budget, is applied in record
 * order before any lookup is sent, so the same DNS answers always produce
 * the same tree; lookups within a level still run concurrently. Were budget
 * decisions made as answers arrived, which targets got expanded (and so the
 * void-lookup count and loop detection) would depend on response timing.
 *
 * A cycle is a target that is already on the current include path (its
 * ancestors), not one that was merely seen on a sibling branch: RFC 7208
 * counts every evaluation of a shared include, so a target reached through
 * two branches is expanded (and counted) twice.
 */
async function expandIncludes(targets: readonly string[], rootAncestors: ReadonlySet<string>, state: LookupState, dns: DnsClient, signal: AbortSignal | undefined): Promise<SpfIncludeNode[]> {
  const makeNode = (domain: string, depth: number): SpfIncludeNode => ({ domain, record: null, lookups: 0, depth, error: null, children: [] });
  const top = targets.map((target) => makeNode(target, 1));
  let level: PendingInclude[] = top.map((node) => ({ node, ancestors: rootAncestors }));
  while (level.length > 0) {
    const toFetch: PendingInclude[] = [];
    for (const item of level) {
      const { node, ancestors } = item;
      if (containsMacro(node.domain)) node.error = "macro expansion is not evaluated";
      else if (node.depth > MAX_DEPTH) node.error = `maximum include depth of ${MAX_DEPTH} exceeded`;
      else if (ancestors.has(node.domain)) node.error = CIRCULAR_INCLUDE;
      else if (state.expansions >= EXPANSION_BUDGET) node.error = "expansion budget exhausted";
      else {
        state.expansions++;
        toFetch.push(item);
      }
    }
    const answers = await mapConcurrent(toFetch, 4, (item) => dns.txt(item.node.domain), signal);
    const next: PendingInclude[] = [];
    toFetch.forEach(({ node, ancestors }, index) => {
      const txt = answers[index];
      if (!txt) return;
      if (txt.error) {
        // RFC 7208 section 4.6.4 counts NXDOMAIN and empty answers as void
        // lookups; a failed query is a temperror and says nothing about the
        // target's record.
        node.error = `DNS error ${txt.error.code}`;
        state.dnsErrors.push(`${node.domain} (${txt.error.code})`);
        return;
      }
      // Sorted: resolvers return RRsets in any order, and the first record must not depend on it.
      const spfRecords = txt.records.filter(isSpfRecord).sort();
      if (spfRecords.length === 0) {
        state.voidLookups++;
        node.error = "no SPF record published";
        return;
      }
      node.record = spfRecords[0] as string;
      const parsed = parseSpfRecord(node.record);
      const children: string[] = [];
      for (const mechanism of parsed.mechanisms) {
        if (LOOKUP_MECHANISMS.has(mechanism.type)) {
          state.count++;
          node.lookups++;
        }
        if (mechanism.type === "include" && mechanism.value) children.push(stripCidr(mechanism.value).toLowerCase());
      }
      const redirect = parsed.modifiers.find((m) => m.name === "redirect");
      if (redirect && !parsed.mechanisms.some((m) => m.type === "all")) {
        state.count++;
        node.lookups++;
        children.push(redirect.value.toLowerCase());
      }
      const path = new Set(ancestors).add(node.domain);
      for (const child of children) {
        const childNode = makeNode(child, node.depth + 1);
        node.children.push(childNode);
        next.push({ node: childNode, ancestors: path });
      }
    });
    level = next;
  }
  return top;
}

function collectDomains(nodes: SpfIncludeNode[], out: Set<string>): void {
  for (const node of nodes) {
    out.add(node.domain);
    collectDomains(node.children, out);
  }
}

const CIRCULAR_INCLUDE = "circular include detected";

function circularIncludes(nodes: SpfIncludeNode[], out: string[] = []): string[] {
  for (const node of nodes) {
    if (node.error === CIRCULAR_INCLUDE) out.push(node.domain);
    circularIncludes(node.children, out);
  }
  return out;
}

export async function evaluateSpf(domain: string, dns: DnsClient, signal?: AbortSignal): Promise<SpfEvaluation> {
  throwIfAborted(signal);
  const findings: Finding[] = [];
  const evaluation: SpfEvaluation = {
    found: false,
    record: null,
    records: [],
    valid: false,
    mechanisms: [],
    modifiers: [],
    allQualifier: null,
    allPolicy: "none",
    includes: [],
    redirect: null,
    failedRedirect: null,
    ip4: [],
    ip6: [],
    lookupCount: 0,
    lookupLimitExceeded: false,
    voidLookups: 0,
    includeTree: [],
    detectedSenders: [],
    findings
  };

  const txt = await dns.txt(domain);
  if (txt.error) {
    findings.push({
      severity: "medium",
      code: "SPF_DNS_ERROR",
      message: `TXT lookup for ${domain} failed (${txt.error.code}); SPF could not be evaluated reliably.`,
      recommendation: "Verify the authoritative nameservers respond correctly and retry."
    });
  }
  // Sorted: resolvers return RRsets in any order, and the record evaluated must not depend on it.
  const records = txt.records.filter(isSpfRecord).sort();
  evaluation.records = records;
  if (records.length === 0) {
    findings.push(
      txt.error
        ? {
            severity: "medium",
            code: "SPF_MISSING",
            message: `No SPF record was found for ${domain}, but the TXT lookup failed (${txt.error.code}), so its absence is unconfirmed.`,
            recommendation: "Retry once the nameservers answer; if no record exists, publish a v=spf1 TXT record listing every authorized sender."
          }
        : {
            severity: "high",
            code: "SPF_MISSING",
            message: `No SPF record is published for ${domain}.`,
            recommendation: 'Publish a TXT record such as "v=spf1 include:<your-provider> -all" listing every authorized sending service.'
          }
    );
    return evaluation;
  }
  evaluation.found = true;
  const record = records[0] as string;
  evaluation.record = record;

  if (records.length > 1) {
    findings.push({
      severity: "critical",
      code: "SPF_MULTIPLE_RECORDS",
      message: `${records.length} SPF records are published; receivers treat this as a permanent error and SPF fails.`,
      recommendation: "Merge all mechanisms into a single v=spf1 TXT record."
    });
  }
  if (record.length > 450) {
    findings.push({
      severity: "low",
      code: "SPF_RECORD_TOO_LONG",
      message: `The SPF record is ${record.length} characters long and may exceed UDP DNS response limits.`,
      recommendation: "Flatten or consolidate includes so the record stays well below 512 bytes."
    });
  }

  const parsed = parseSpfRecord(record);
  evaluation.mechanisms = parsed.mechanisms;
  evaluation.modifiers = parsed.modifiers;
  for (const error of parsed.errors) {
    findings.push({
      severity: "high",
      code: "SPF_SYNTAX_ERROR",
      message: `SPF syntax problem: ${error}`,
      recommendation: "Correct the record; receivers return permerror for malformed SPF and may reject mail."
    });
  }

  const state: LookupState = { count: 0, voidLookups: 0, expansions: 0, dnsErrors: [] };
  const root = new Set([domain.toLowerCase()]);
  const children: string[] = [];
  for (const mechanism of parsed.mechanisms) {
    if (LOOKUP_MECHANISMS.has(mechanism.type)) state.count++;
    if (mechanism.type === "include" && mechanism.value) {
      const target = stripCidr(mechanism.value).toLowerCase();
      evaluation.includes.push(target);
      children.push(target);
    }
    if (mechanism.type === "ip4" && mechanism.value) evaluation.ip4.push(mechanism.value);
    if (mechanism.type === "ip6" && mechanism.value) evaluation.ip6.push(mechanism.value);
  }
  const allIndex = parsed.mechanisms.findIndex((m) => m.type === "all");
  const allMechanism = allIndex === -1 ? null : (parsed.mechanisms[allIndex] as SpfMechanism);
  const redirect = parsed.modifiers.find((m) => m.name === "redirect");
  if (redirect) {
    evaluation.redirect = redirect.value.toLowerCase();
    if (!allMechanism) {
      state.count++;
      children.push(redirect.value.toLowerCase());
    } else {
      findings.push({
        severity: "info",
        code: "SPF_REDIRECT_IGNORED",
        message: 'A redirect= modifier is present alongside an "all" mechanism, so the redirect is ignored.',
        recommendation: "Remove the redirect modifier or the all mechanism to make intent explicit."
      });
    }
  }
  evaluation.includeTree = await expandIncludes(children, root, state, dns, signal);
  evaluation.lookupCount = state.count;
  evaluation.voidLookups = state.voidLookups;
  evaluation.lookupLimitExceeded = state.count > 10;

  // A redirect= modifier hands evaluation to another record; its terminal
  // "all" mechanism becomes this domain's effective policy.
  let redirectAll: SpfMechanism | null = null;
  // Set when the effective policy depends on a redirect target whose lookup failed.
  let redirectLookupFailed = false;
  if (!allMechanism && redirect) {
    // Follow redirect= hop by hop: a target without its own "all" that
    // redirects again hands evaluation on to the next record. The walk stops
    // at any node without a record (DNS error, void target, loop, depth or
    // budget limit); each of those has its own finding.
    let target = evaluation.includeTree.find((node) => node.domain === evaluation.redirect);
    const visited = new Set<string>();
    while (target && !visited.has(target.domain)) {
      visited.add(target.domain);
      if (!target.record) {
        redirectLookupFailed = target.error?.startsWith("DNS error") === true;
        if (redirectLookupFailed) evaluation.failedRedirect = target.domain;
        break;
      }
      const targetParsed = parseSpfRecord(target.record);
      redirectAll = targetParsed.mechanisms.find((m) => m.type === "all") ?? null;
      if (redirectAll) break;
      const next = targetParsed.modifiers.find((m) => m.name === "redirect");
      if (!next) break;
      const nextDomain = next.value.toLowerCase();
      target = target.children.find((child) => child.domain === nextDomain);
    }
  }

  if (allMechanism) {
    evaluation.allQualifier = allMechanism.qualifier;
    evaluation.allPolicy = policyForQualifier(allMechanism.qualifier);
    if (allIndex < parsed.mechanisms.length - 1) {
      findings.push({
        severity: "low",
        code: "SPF_TERMS_AFTER_ALL",
        message: 'Mechanisms appear after the "all" term and are never evaluated.',
        recommendation: 'Move "all" to the end of the record.'
      });
    }
  } else if (redirectAll) {
    evaluation.allQualifier = redirectAll.qualifier;
    evaluation.allPolicy = policyForQualifier(redirectAll.qualifier);
  } else if (!redirect) {
    findings.push({
      severity: "medium",
      code: "SPF_NO_ALL",
      message: 'The SPF record has no terminal "all" mechanism, so unlisted senders receive a neutral result.',
      recommendation: "End the record with -all (or ~all while validating senders)."
    });
  }

  switch (evaluation.allPolicy) {
    case "pass":
      findings.push({
        severity: "critical",
        code: "SPF_PASS_ALL",
        message: "The record ends with +all, which authorizes every host on the internet to send as this domain.",
        recommendation: "Replace +all with -all immediately."
      });
      break;
    case "neutral":
      findings.push({
        severity: "high",
        code: "SPF_NEUTRAL_ALL",
        message: "The record ends with ?all, which provides no protection against spoofing.",
        recommendation: "Use -all (or ~all during rollout)."
      });
      break;
    case "softfail":
      findings.push({
        severity: "info",
        code: "SPF_SOFTFAIL_ALL",
        message: "The record ends with ~all (softfail). This is acceptable when DMARC is enforced, but -all is stricter.",
        recommendation: "Consider -all once all legitimate senders are listed."
      });
      break;
    default:
      break;
  }

  if (state.dnsErrors.length > 0) {
    // Only a failed redirect target leaves the effective "all" unknown
    // (SPF_DNS_ERROR, like a failed top-level lookup). A failed include
    // leaves the domain's own record and policy known and affects only the
    // lookup count and validity.
    findings.push({
      severity: "medium",
      code: redirectLookupFailed ? "SPF_DNS_ERROR" : "SPF_INCLUDE_DNS_ERROR",
      message: `Lookups for ${state.dnsErrors.length} included domain(s) failed (${state.dnsErrors.slice(0, 5).join(", ")}); receivers would return a temporary error, and the lookup count may be understated.`,
      recommendation: "Verify the included domains' nameservers respond correctly and retry."
    });
  }

  const loops = [...new Set(circularIncludes(evaluation.includeTree))];
  if (loops.length > 0) {
    // A loop never terminates on a real receiver: it burns the 10-lookup
    // budget and ends in permerror, so it invalidates the record outright.
    findings.push({
      severity: "high",
      code: "SPF_CIRCULAR_INCLUDE",
      message: `The include chain loops back through ${loops.join(", ")}; receivers exhaust the lookup limit and return permerror.`,
      recommendation: "Remove the include (or redirect) that points back to a domain already on the chain."
    });
  }

  if (parsed.mechanisms.some((m) => m.type === "ptr")) {
    findings.push({
      severity: "medium",
      code: "SPF_PTR_DEPRECATED",
      message: "The record uses the ptr mechanism, which is deprecated, slow and unreliable.",
      recommendation: "Replace ptr with explicit ip4/ip6 or include mechanisms."
    });
  }
  if (evaluation.lookupLimitExceeded) {
    findings.push({
      severity: "critical",
      code: "SPF_TOO_MANY_LOOKUPS",
      message: `The record requires ${state.count} DNS lookups; the RFC 7208 limit is 10, so receivers return permerror.`,
      recommendation: "Flatten includes, remove unused senders, or use a managed SPF flattening service."
    });
  } else if (state.count >= 8) {
    findings.push({
      severity: "low",
      code: "SPF_LOOKUPS_NEAR_LIMIT",
      message: `The record uses ${state.count} of the 10 permitted DNS lookups.`,
      recommendation: "Audit includes before adding any new sending service."
    });
  }
  if (state.voidLookups > 2) {
    findings.push({
      severity: "high",
      code: "SPF_VOID_LOOKUPS",
      message: `${state.voidLookups} included domains publish no SPF record; more than 2 void lookups cause a permerror.`,
      recommendation: "Remove includes that point to domains without SPF records."
    });
  } else if (state.voidLookups > 0) {
    findings.push({
      severity: "medium",
      code: "SPF_INCLUDE_NO_RECORD",
      message: `${state.voidLookups} include target(s) publish no SPF record.`,
      recommendation: "Remove or correct includes that resolve to domains without SPF."
    });
  }

  const allDomains = new Set<string>();
  collectDomains(evaluation.includeTree, allDomains);
  const senders = new Set<string>();
  for (const candidate of allDomains) {
    const sender = matchProvider(KNOWN_SENDERS, candidate);
    if (sender) senders.add(sender);
  }
  evaluation.detectedSenders = [...senders].sort();
  evaluation.valid = parsed.errors.length === 0 && records.length === 1 && !evaluation.lookupLimitExceeded && state.voidLookups <= 2 && loops.length === 0;
  return evaluation;
}
