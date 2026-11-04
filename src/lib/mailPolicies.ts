/**
 * Supplementary mail transport policies: MTA-STS (RFC 8461), TLS-RPT
 * (RFC 8460) and BIMI. These are bonus signals on top of SPF/DKIM/DMARC.
 */

import { Agent, fetch as undiciFetch } from "undici";
import { deadlineSignal } from "./async.js";
import { parseDkimTags as parseTags } from "./dkim.js";
import type { DnsClient } from "./dns.js";
import type { Finding } from "./findings.js";
import { detectBlock } from "./blockDetection.js";
import { readBodyCapped } from "./http.js";
import { assertPublicLiteral, createGuardedLookup, isPrivateTargetError } from "./lookup.js";
import { parseSafeInteger } from "./numbers.js";

/** RFC 8461 policy files are a few hundred bytes; anything larger is hostile or broken. */
const MAX_POLICY_BYTES = 65536;

/**
 * Fetch failures that describe the domain's setup rather than a hiccup: the
 * policy host does not exist (getaddrinfo NXDOMAIN; a resolver timeout
 * surfaces as EAI_AGAIN and stays transient) or its certificate is invalid.
 */
const DEFINITIVE_FETCH_CODES = new Set([
  "ENOTFOUND",
  "CERT_HAS_EXPIRED",
  "CERT_NOT_YET_VALID",
  "CERT_REVOKED",
  "CERT_UNTRUSTED",
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "SELF_SIGNED_CERT_IN_CHAIN",
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  "UNABLE_TO_GET_ISSUER_CERT",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
  "ERR_TLS_CERT_ALTNAME_INVALID"
]);

export interface MtaStsPolicy {
  fetched: boolean;
  url: string;
  version: string | null;
  mode: "enforce" | "testing" | "none" | null;
  mx: string[];
  maxAge: number | null;
  mxCoversAllExchanges: boolean | null;
  error: string | null;
  /**
   * transient: timeouts, resets, resolver trouble, HTTP 408/425/429/5xx or a bot challenge (a retry may succeed).
   * definitive: the policy host does not exist, its certificate is invalid, another 4xx, not a policy, too large.
   */
  failure: "transient" | "definitive" | null;
}

export interface MtaStsEvaluation {
  found: boolean;
  record: string | null;
  id: string | null;
  policy: MtaStsPolicy;
  findings: Finding[];
}

export interface TlsRptEvaluation {
  found: boolean;
  record: string | null;
  rua: string[];
  findings: Finding[];
}

export interface BimiEvaluation {
  found: boolean;
  record: string | null;
  logoUrl: string | null;
  vmcUrl: string | null;
  findings: Finding[];
}

export interface PolicyFetchOptions {
  timeoutMs: number;
  userAgent: string;
  allowPrivate: boolean;
  /** Cancels the policy fetch when the owning tool call is aborted. */
  signal?: AbortSignal;
}

function mxPatternMatches(pattern: string, host: string): boolean {
  const p = pattern.toLowerCase().replace(/\.$/, "");
  const h = host.toLowerCase().replace(/\.$/, "");
  if (p.startsWith("*.")) {
    const suffix = p.slice(1);
    return h.endsWith(suffix) && h.slice(0, -suffix.length).split(".").length === 1 && h.length > suffix.length;
  }
  return p === h;
}

async function fetchMtaStsPolicy(domain: string, options: PolicyFetchOptions): Promise<Omit<MtaStsPolicy, "mxCoversAllExchanges">> {
  const url = `https://mta-sts.${domain}/.well-known/mta-sts.txt`;
  const policy: Omit<MtaStsPolicy, "mxCoversAllExchanges"> = { fetched: false, url, version: null, mode: null, mx: [], maxAge: null, error: null, failure: null };
  const agent = new Agent({
    connect: { timeout: options.timeoutMs, lookup: createGuardedLookup(options.allowPrivate) },
    headersTimeout: options.timeoutMs,
    bodyTimeout: options.timeoutMs
  });
  try {
    // parseDomain never admits an IP literal here, but every socket site
    // carries the literal check so a future caller cannot regress it.
    assertPublicLiteral(new URL(url).hostname, options.allowPrivate);
    const response = await undiciFetch(url, {
      method: "GET",
      headers: { "user-agent": options.userAgent, accept: "text/plain" },
      redirect: "manual",
      dispatcher: agent,
      signal: deadlineSignal(options.timeoutMs, options.signal)
    });
    if (response.status !== 200) {
      const status = response.status;
      policy.error = `HTTP ${status}`;
      // 408, 425, 429 and 5xx say "try again later"; a retry may succeed.
      let transient = status >= 500 || status === 408 || status === 425 || status === 429;
      if (!transient && (status === 401 || status === 403 || status === 405)) {
        // A bot challenge aimed at the scanner says nothing about the domain's
        // policy. Challenges use 401/403/405; a 404 or 410 stays definitive
        // even when a CDN injects its detection script into the error page.
        const { bytes } = await readBodyCapped(response, MAX_POLICY_BYTES);
        const block = detectBlock(status, Object.fromEntries(response.headers), bytes.toString("utf8"));
        if (block.blocked && block.challengeType !== "access_denied") {
          transient = true;
          policy.error = `HTTP ${status} (${block.vendor ?? "bot protection"} challenge)`;
        }
      }
      policy.failure = transient ? "transient" : "definitive";
      try {
        await response.body?.cancel();
      } catch {
        // already consumed
      }
      return policy;
    }
    const { bytes, truncated } = await readBodyCapped(response, MAX_POLICY_BYTES);
    if (truncated) {
      policy.error = `policy file exceeds ${MAX_POLICY_BYTES} bytes`;
      policy.failure = "definitive";
      return policy;
    }
    const text = bytes.toString("utf8");
    for (const rawLine of text.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line || line.startsWith("#")) continue;
      const colon = line.indexOf(":");
      if (colon === -1) continue;
      const key = line.slice(0, colon).trim().toLowerCase();
      const value = line.slice(colon + 1).trim();
      if (key === "version") policy.version = value;
      else if (key === "mode") policy.mode = /^(enforce|testing|none)$/i.test(value) ? (value.toLowerCase() as MtaStsPolicy["mode"]) : null;
      else if (key === "mx") policy.mx.push(value.toLowerCase());
      else if (key === "max_age") policy.maxAge = parseSafeInteger(value);
    }
    // RFC 8461 section 3.2: a policy must declare version: STSv1. A parked
    // page or an HTML error document that happens to answer 200 is not a
    // policy and must not earn the domain any MTA-STS credit, so nothing
    // parsed from such a body is kept.
    if (policy.version === null || !/^stsv1$/i.test(policy.version)) {
      return { ...policy, version: null, mode: null, mx: [], maxAge: null, error: 'response is not an MTA-STS policy (missing "version: STSv1")', failure: "definitive" };
    }
    policy.fetched = true;
  } catch (err) {
    const cause = (err as { cause?: unknown }).cause;
    const code = (cause as { code?: unknown } | undefined)?.code ?? (err as { code?: unknown }).code;
    policy.error = typeof code === "string" ? `${code}: ${(cause instanceof Error ? cause : (err as Error)).message}` : (err as Error).message;
    // A refused private target, a policy host that does not exist or an
    // invalid certificate is a property of the domain, not a hiccup; senders
    // fail the same way. Timeouts, resets and resolver trouble stay transient.
    policy.failure = isPrivateTargetError(err) || isPrivateTargetError(cause) || (typeof code === "string" && DEFINITIVE_FETCH_CODES.has(code)) ? "definitive" : "transient";
  } finally {
    agent.destroy().catch(() => undefined);
  }
  return policy;
}

/**
 * The MX list is only needed for the final coverage comparison, so callers
 * may pass the pending MX evaluation and let the DNS record lookup and the
 * policy fetch run concurrently with it instead of after it.
 */
export async function evaluateMtaSts(domain: string, mxHosts: string[] | Promise<string[]>, dns: DnsClient, options: PolicyFetchOptions): Promise<MtaStsEvaluation> {
  // Observed synchronously on entry: the early "no record" return below
  // must not leave a rejecting MX promise unhandled.
  const hosts = Promise.resolve(mxHosts).catch((): string[] => []);
  const findings: Finding[] = [];
  const txt = await dns.txt(`_mta-sts.${domain}`);
  const records = txt.records.filter((r) => /^v=STSv1(\s*;|\s*$)/i.test(r.trim()));
  const record = records[0] ?? null;
  const evaluation: MtaStsEvaluation = {
    found: record !== null,
    record,
    id: null,
    policy: { fetched: false, url: `https://mta-sts.${domain}/.well-known/mta-sts.txt`, version: null, mode: null, mx: [], maxAge: null, mxCoversAllExchanges: null, error: null, failure: null },
    findings
  };
  if (txt.error) {
    // An unanswered TXT query is not evidence that MTA-STS is absent.
    evaluation.policy.error = `DNS error ${txt.error.code}`;
    evaluation.policy.failure = "transient";
    findings.push({
      severity: "low",
      code: "MTA_STS_DNS_ERROR",
      message: `TXT lookup for _mta-sts.${domain} failed (${txt.error.code}); MTA-STS could not be evaluated.`,
      recommendation: "Verify the authoritative nameservers respond correctly and retry."
    });
    return evaluation;
  }
  if (record === null) {
    findings.push({
      severity: "info",
      code: "MTA_STS_MISSING",
      message: "No MTA-STS policy is published; inbound SMTP TLS is opportunistic and can be downgraded.",
      recommendation: "Publish _mta-sts TXT and an https://mta-sts.<domain>/.well-known/mta-sts.txt policy in enforce mode."
    });
    return evaluation;
  }
  evaluation.id = parseTags(record).id ?? null;
  if (records.length > 1) {
    findings.push({
      severity: "low",
      code: "MTA_STS_MULTIPLE_RECORDS",
      message: "Multiple _mta-sts TXT records are published; receivers ignore the policy.",
      recommendation: "Keep exactly one v=STSv1 record."
    });
  }
  const fetched = await fetchMtaStsPolicy(domain, options);
  if (fetched.failure === "definitive" && fetched.error?.startsWith("ENOTFOUND")) {
    // Confirm "the policy host does not exist" with our own resolver before
    // trusting it: some platforms' getaddrinfo reports resolver trouble the
    // same way. NXDOMAIN, or a name with no addresses at all, is definitive.
    const host = `mta-sts.${domain}`;
    const [a, aaaa] = await Promise.all([dns.a(host), dns.aaaa(host)]);
    const absent = a.nxdomain || aaaa.nxdomain || (!a.error && !aaaa.error && a.records.length === 0 && aaaa.records.length === 0);
    if (!absent) fetched.failure = "transient";
  }
  const exchanges = await hosts;
  let covers: boolean | null = null;
  if (fetched.fetched && fetched.mx.length > 0 && exchanges.length > 0) {
    covers = exchanges.every((host) => fetched.mx.some((pattern) => mxPatternMatches(pattern, host)));
  }
  evaluation.policy = { ...fetched, mxCoversAllExchanges: covers };
  if (!fetched.fetched) {
    findings.push({
      severity: "low",
      code: "MTA_STS_POLICY_UNREACHABLE",
      message: `The MTA-STS DNS record exists but a valid policy file could not be fetched (${fetched.error ?? "unknown error"}).`,
      recommendation: 'Serve https://mta-sts.<domain>/.well-known/mta-sts.txt with a valid certificate, starting with "version: STSv1".'
    });
  } else {
    // RFC 8461 section 3.2 also requires a mode and at least one mx entry.
    if (fetched.mode === null || fetched.mx.length === 0) {
      findings.push({
        severity: "low",
        code: "MTA_STS_POLICY_INVALID",
        message: `The MTA-STS policy file is incomplete (${fetched.mode === null ? "missing or invalid mode" : "no mx entries"}); senders treat an invalid policy as absent.`,
        recommendation: "Publish mode: enforce (or testing) and one mx: line per MX host in the policy file."
      });
    }
    if (fetched.mode === "testing") {
      findings.push({
        severity: "info",
        code: "MTA_STS_TESTING",
        message: "MTA-STS is in testing mode; TLS failures are only reported, not enforced.",
        recommendation: "Switch mode to enforce after reviewing TLS-RPT reports."
      });
    } else if (fetched.mode === "none") {
      findings.push({
        severity: "info",
        code: "MTA_STS_MODE_NONE",
        message: "MTA-STS policy mode is none, which disables the policy.",
        recommendation: "Set mode: enforce."
      });
    }
    if (covers === false) {
      findings.push({
        severity: "medium",
        code: "MTA_STS_MX_MISMATCH",
        message: "One or more MX hosts are not covered by the MTA-STS policy mx list; senders enforcing the policy will refuse delivery to them.",
        recommendation: "Add every MX host (or a matching wildcard) to the policy file."
      });
    }
  }
  return evaluation;
}

export async function evaluateTlsRpt(domain: string, dns: DnsClient): Promise<TlsRptEvaluation> {
  const findings: Finding[] = [];
  const txt = await dns.txt(`_smtp._tls.${domain}`);
  const records = txt.records.filter((r) => /^v=TLSRPTv1(\s*;|\s*$)/i.test(r.trim()));
  const record = records[0] ?? null;
  const rua = record
    ? (parseTags(record).rua ?? "")
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean)
    : [];
  if (record === null && txt.error) {
    // A failed query is not an empty answer.
    findings.push({
      severity: "info",
      code: "TLS_RPT_DNS_ERROR",
      message: `TXT lookup for _smtp._tls.${domain} failed (${txt.error.code}); TLS-RPT could not be checked.`,
      recommendation: "Verify the authoritative nameservers respond correctly and retry."
    });
  } else if (record === null) {
    findings.push({
      severity: "info",
      code: "TLS_RPT_MISSING",
      message: "No TLS-RPT record is published, so SMTP TLS failures are not reported to you.",
      recommendation: 'Publish _smtp._tls TXT "v=TLSRPTv1; rua=mailto:tlsrpt@<domain>".'
    });
  } else if (rua.length === 0) {
    findings.push({
      severity: "low",
      code: "TLS_RPT_NO_RUA",
      message: "The TLS-RPT record has no rua= destination.",
      recommendation: "Add rua=mailto:<address> to receive reports."
    });
  }
  return { found: record !== null, record, rua, findings };
}

export async function evaluateBimi(domain: string, dns: DnsClient): Promise<BimiEvaluation> {
  const findings: Finding[] = [];
  const txt = await dns.txt(`default._bimi.${domain}`);
  const records = txt.records.filter((r) => /^v=BIMI1(\s*;|\s*$)/i.test(r.trim()));
  const record = records[0] ?? null;
  const tags = record ? parseTags(record) : {};
  const logoUrl = tags.l && tags.l.length > 0 ? tags.l : null;
  const vmcUrl = tags.a && tags.a.length > 0 ? tags.a : null;
  if (record === null && txt.error) {
    findings.push({
      severity: "info",
      code: "BIMI_DNS_ERROR",
      message: `TXT lookup for default._bimi.${domain} failed (${txt.error.code}); BIMI could not be checked.`,
      recommendation: "Verify the authoritative nameservers respond correctly and retry."
    });
  }
  if (record !== null) {
    if (logoUrl !== null && !/^https:\/\//i.test(logoUrl)) {
      findings.push({
        severity: "low",
        code: "BIMI_LOGO_NOT_HTTPS",
        message: "The BIMI logo URL must use HTTPS.",
        recommendation: "Host the SVG Tiny PS logo on an HTTPS URL."
      });
    }
    if (vmcUrl === null) {
      findings.push({
        severity: "info",
        code: "BIMI_NO_VMC",
        message: "BIMI is published without a Verified Mark Certificate; Gmail and Apple Mail require a VMC/CMC to display the logo.",
        recommendation: "Obtain a VMC or CMC and reference it with the a= tag."
      });
    }
  }
  return { found: record !== null, record, logoUrl, vmcUrl, findings };
}
