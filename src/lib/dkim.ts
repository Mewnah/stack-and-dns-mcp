/**
 * DKIM selector probing. Because selectors are not discoverable from DNS,
 * we probe a curated list of the selectors used by the most common email
 * platforms, plus any operator- or caller-supplied selectors, and decode the
 * public key to report the algorithm and key length.
 */

import { createPublicKey } from "node:crypto";
import { mapConcurrent, throwIfAborted } from "./async.js";
import type { DnsClient } from "./dns.js";
import type { Finding } from "./findings.js";
import { matchProvider, type ProviderTable } from "./providers.js";

export const DEFAULT_DKIM_SELECTORS: readonly string[] = [
  "google",
  "selector1",
  "selector2",
  "k1",
  "k2",
  "k3",
  "s1",
  "s2",
  "s3",
  "mandrill",
  "mte1",
  "mte2",
  "zendesk1",
  "zendesk2",
  "zendesk",
  "pm",
  "mailjet",
  "kl",
  "kl2",
  "cm",
  "sib",
  "mail",
  "email",
  "default",
  "dkim",
  "dkim1",
  "dkim2",
  "smtp",
  "zoho",
  "zmail",
  "protonmail",
  "protonmail2",
  "protonmail3",
  "fm1",
  "fm2",
  "fm3",
  "amazonses",
  "ses",
  "mg",
  "mailgun",
  "ctct1",
  "ctct2",
  "sendgrid",
  "krs",
  "sig1",
  "m1",
  "mailo",
  "everlytickey1",
  "everlytickey2",
  "sparkpost",
  "postmark",
  "s1024",
  "sel1",
  "sel2",
  "key1",
  "key2",
  "mailerlite",
  "ml",
  "sendpulse",
  "hubspot",
  "hs1",
  "hs2",
  "intercom",
  "customerio",
  "cio",
  "drift",
  "outreach",
  "salesloft",
  "marketo",
  "mkt",
  "pardot",
  "sfmc",
  "exacttarget",
  "et",
  "mimecast",
  "proofpoint",
  "pp",
  "mxvault",
  "resend",
  "loops",
  "brevo",
  "smtpapi",
  "spop",
  "dk",
  "x",
  "mx"
];

export interface DkimSelectorResult {
  selector: string;
  name: string;
  found: boolean;
  record: string | null;
  cname: string | null;
  keyType: string | null;
  keyBits: number | null;
  hashAlgorithms: string[];
  testing: boolean;
  revoked: boolean;
  provider: string | null;
  issues: string[];
  /** DNS error code when the selector could not be checked (SERVFAIL, timeout); null when the lookup answered. */
  error: string | null;
}

export interface DkimEvaluation {
  checkedSelectors: string[];
  selectors: DkimSelectorResult[];
  found: boolean;
  weakKeys: string[];
  providers: string[];
  findings: Finding[];
}

/** CNAME targets. Every pattern is anchored at a label boundary so look-alike hosts (notgoogle.com) are not attributed to the vendor. */
const CNAME_PROVIDERS: ProviderTable = [
  [/(^|\.)dkim\.mcsv\.net$/i, "Mailchimp"],
  [/(^|\.)mandrillapp\.com$/i, "Mandrill"],
  [/(^|\.)sendgrid\.net$/i, "SendGrid"],
  [/(^|\.)dkim\.amazonses\.com$/i, "Amazon SES"],
  [/(^|\.)hubspotemail\.net$/i, "HubSpot"],
  [/(^|\.)(klaviyomail|klaviyo)\.com$/i, "Klaviyo"],
  [/(^|\.)mailgun\.org$/i, "Mailgun"],
  [/(^|\.)zendesk\.com$/i, "Zendesk"],
  [/(^|\.)zoho(?:mail)?\.(?:com|eu|in)$/i, "Zoho Mail"],
  [/(^|\.)pardot\.com$/i, "Salesforce Pardot"],
  [/(^|\.)exacttarget\.com$/i, "Salesforce Marketing Cloud"],
  [/(^|\.)(mktomail|marketo)\.com$/i, "Marketo"],
  [/(^|\.)(mtasv\.net|postmarkapp\.com)$/i, "Postmark"],
  [/(^|\.)mailjet\.com$/i, "Mailjet"],
  [/(^|\.)(sendinblue|brevo)\.com$/i, "Brevo"],
  [/(^|\.)freshdesk\.com$/i, "Freshdesk"],
  [/(^|\.)(customeriomail\.com|customer\.io)$/i, "Customer.io"],
  [/(^|\.)(intercom\.io|intercom-mail\.com)$/i, "Intercom"],
  [/(^|\.)protonmail\.ch$/i, "Proton Mail"],
  [/(^|\.)mimecast\.com$/i, "Mimecast"],
  [/(^|\.)(pphosted|proofpoint)\.com$/i, "Proofpoint"],
  [/(^|\.)onmicrosoft\.com$/i, "Microsoft 365"],
  [/(^|\.)(googlemail|google)\.com$/i, "Google Workspace"],
  [/(^|\.)sparkpostmail\.com$/i, "SparkPost"],
  [/(^|\.)(mailerlite|mlsend)\.com$/i, "MailerLite"],
  [/(^|\.)sendpulse\.com$/i, "SendPulse"],
  [/(^|\.)constantcontact\.com$/i, "Constant Contact"],
  [/(^|\.)(campaignmonitor|createsend)\.com$/i, "Campaign Monitor"],
  [/(^|\.)drift\.com$/i, "Drift"],
  [/(^|\.)outreach\.io$/i, "Outreach"],
  [/(^|\.)salesloft\.com$/i, "Salesloft"],
  [/(^|\.)resend\.com$/i, "Resend"],
  [/(^|\.)loops\.so$/i, "Loops"],
  [/(^|\.)messagingengine\.com$/i, "Fastmail"],
  [/(^|\.)emailsrvr\.com$/i, "Rackspace Email"],
  [/(^|\.)titan\.email$/i, "Titan"]
];

const SELECTOR_PROVIDERS: ProviderTable = [
  [/^google$/i, "Google Workspace"],
  [/^selector[12]$/i, "Microsoft 365"],
  [/^k[123]$/i, "Mailchimp / Mandrill"],
  [/^s[123]$/i, "SendGrid"],
  [/^mandrill$/i, "Mandrill"],
  [/^mte[12]$/i, "Mailtrap"],
  [/^zendesk[12]?$/i, "Zendesk"],
  [/^pm$/i, "Postmark"],
  [/^mailjet$/i, "Mailjet"],
  [/^kl2?$/i, "Klaviyo"],
  [/^cm$/i, "Campaign Monitor"],
  [/^sib$/i, "Brevo"],
  [/^zoho$|^zmail$/i, "Zoho Mail"],
  [/^protonmail[23]?$/i, "Proton Mail"],
  [/^fm[123]$/i, "Fastmail"],
  [/^amazonses$|^ses$/i, "Amazon SES"],
  [/^mg$|^mailgun$/i, "Mailgun"],
  [/^ctct[12]$/i, "Constant Contact"],
  [/^sendgrid$/i, "SendGrid"],
  [/^krs$/i, "Klaviyo"],
  [/^everlytickey[12]$/i, "Everlytic"],
  [/^sparkpost$/i, "SparkPost"],
  [/^postmark$/i, "Postmark"],
  [/^mailerlite$|^ml$/i, "MailerLite"],
  [/^sendpulse$/i, "SendPulse"],
  [/^hubspot$|^hs[12]$/i, "HubSpot"],
  [/^intercom$/i, "Intercom"],
  [/^customerio$|^cio$/i, "Customer.io"],
  [/^drift$/i, "Drift"],
  [/^outreach$/i, "Outreach"],
  [/^salesloft$/i, "Salesloft"],
  [/^marketo$|^mkt$/i, "Marketo"],
  [/^pardot$/i, "Salesforce Pardot"],
  [/^sfmc$|^exacttarget$|^et$/i, "Salesforce Marketing Cloud"],
  [/^mimecast$/i, "Mimecast"],
  [/^proofpoint$|^pp$/i, "Proofpoint"],
  [/^mxvault$/i, "MXroute"],
  [/^resend$/i, "Resend"],
  [/^loops$/i, "Loops"],
  [/^brevo$/i, "Brevo"]
];

export function normalizeSelectors(input: readonly string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of input) {
    const selector = raw
      .trim()
      .toLowerCase()
      .replace(/\._domainkey.*$/i, "");
    if (!selector || selector.length > 63 || !/^[a-z0-9_-]+(\.[a-z0-9_-]+)*$/.test(selector)) continue;
    if (seen.has(selector)) continue;
    seen.add(selector);
    out.push(selector);
  }
  return out;
}

export function parseDkimTags(record: string): Record<string, string> {
  const tags: Record<string, string> = {};
  for (const part of record.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    const name = part.slice(0, eq).trim().toLowerCase();
    const value = part.slice(eq + 1).trim();
    if (name) tags[name] = value;
  }
  return tags;
}

export function isDkimRecord(value: string): boolean {
  const lower = value.toLowerCase();
  return lower.includes("v=dkim1") || (/(^|;)\s*p=/.test(lower) && /(^|;)\s*k=/.test(lower)) || /(^|;)\s*p=[a-z0-9+/=]{40,}/i.test(value);
}

export function decodeDkimKey(keyType: string, base64: string): { bits: number | null; error: string | null } {
  const cleaned = base64.replace(/\s+/g, "");
  if (cleaned.length === 0) return { bits: null, error: null };
  let der: Buffer;
  try {
    der = Buffer.from(cleaned, "base64");
  } catch {
    return { bits: null, error: "public key is not valid base64" };
  }
  if (keyType === "ed25519") {
    return der.length === 32 ? { bits: 256, error: null } : { bits: null, error: "ed25519 key must be 32 bytes" };
  }
  try {
    const key = createPublicKey({ key: der, format: "der", type: "spki" });
    const details = key.asymmetricKeyDetails;
    const bits = details && typeof details.modulusLength === "number" ? details.modulusLength : null;
    return { bits, error: null };
  } catch (err) {
    return { bits: null, error: `public key could not be decoded (${(err as Error).message})` };
  }
}

function providerFor(selector: string, cname: string | null): string | null {
  return matchProvider(CNAME_PROVIDERS, cname) ?? matchProvider(SELECTOR_PROVIDERS, selector);
}

async function probeSelector(domain: string, selector: string, dns: DnsClient, signal: AbortSignal | undefined): Promise<DkimSelectorResult> {
  const name = `${selector}._domainkey.${domain}`;
  const result: DkimSelectorResult = {
    selector,
    name,
    found: false,
    record: null,
    cname: null,
    keyType: null,
    keyBits: null,
    hashAlgorithms: [],
    testing: false,
    revoked: false,
    provider: null,
    issues: [],
    error: null
  };
  // TXT first: the common outcome for a probed selector is NXDOMAIN, and the
  // CNAME query is only spent on names that exist. The CNAME is kept for
  // found and NODATA selectors because it names the signing vendor more
  // reliably than the selector string does. Known trade-off: a selector that
  // exists only as a CNAME to a name that no longer exists also answers
  // NXDOMAIN (RFC 6604, the rcode is the chain's final name), so that stale
  // vendor pointer is reported as not found instead of by vendor.
  const txt = await dns.txt(name);
  // The owning call may have been cancelled while the TXT query was in flight.
  throwIfAborted(signal);
  // A failed lookup (SERVFAIL, timeout) says nothing about the selector; it
  // is reported as unchecked rather than as "not found".
  if (txt.error) {
    result.error = txt.error.code;
    return result;
  }
  const cname = txt.nxdomain ? null : await dns.cname(name);
  result.cname = cname?.records[0] ?? null;
  // Sorted: resolvers return RRsets in any order, and the key evaluated must not depend on it.
  const records = txt.records.filter(isDkimRecord).sort();
  if (records.length === 0) {
    if (result.cname) result.provider = providerFor(selector, result.cname);
    return result;
  }
  result.found = true;
  result.record = records[0] as string;
  if (records.length > 1) result.issues.push(`${records.length} DKIM records published at ${name}; only one is allowed.`);
  const tags = parseDkimTags(result.record);
  const keyType = (tags.k ?? "rsa").toLowerCase();
  result.keyType = keyType;
  result.testing = /(^|:)y(:|$)/i.test(tags.t ?? "");
  result.hashAlgorithms = tags.h
    ? tags.h
        .split(":")
        .map((h) => h.trim().toLowerCase())
        .filter(Boolean)
    : [];
  if (tags.v !== undefined && !/^dkim1$/i.test(tags.v)) result.issues.push(`Unexpected v= value "${tags.v}".`);
  const publicKey = tags.p ?? "";
  if (publicKey.length === 0) {
    result.revoked = true;
    result.issues.push("Empty p= tag: this selector's key has been revoked.");
  } else {
    const decoded = decodeDkimKey(keyType, publicKey);
    result.keyBits = decoded.bits;
    if (decoded.error) result.issues.push(decoded.error);
    if (keyType === "rsa" && decoded.bits !== null && decoded.bits < 1024) {
      result.issues.push(`RSA key is only ${decoded.bits} bits; receivers ignore keys shorter than 1024 bits.`);
    } else if (keyType === "rsa" && decoded.bits !== null && decoded.bits < 2048) {
      result.issues.push(`RSA key is ${decoded.bits} bits; 2048 bits is the current recommendation.`);
    }
  }
  if (result.testing) result.issues.push("Selector is in testing mode (t=y); receivers treat signatures as unverified.");
  if (result.hashAlgorithms.length > 0 && !result.hashAlgorithms.includes("sha256")) {
    result.issues.push(`Hash algorithms restricted to ${result.hashAlgorithms.join(", ")}; sha256 is required by modern receivers.`);
  }
  result.provider = providerFor(selector, result.cname);
  return result;
}

export async function evaluateDkim(domain: string, selectors: readonly string[], dns: DnsClient, signal?: AbortSignal): Promise<DkimEvaluation> {
  const findings: Finding[] = [];
  const checked = normalizeSelectors(selectors);
  const results = await mapConcurrent(checked, 10, (selector) => probeSelector(domain, selector, dns, signal), signal);
  const found = results.filter((r) => r.found);
  const weakKeys = found.filter((r) => r.keyType === "rsa" && r.keyBits !== null && r.keyBits < 2048).map((r) => r.selector);
  const providers = [...new Set(found.map((r) => r.provider).filter((p): p is string => p !== null))].sort();

  const errored = results.filter((r) => r.error !== null);
  if (errored.length > 0) {
    const codes = [...new Set(errored.map((r) => r.error))].join(", ");
    findings.push({
      severity: found.length === 0 ? "medium" : "low",
      code: "DKIM_DNS_ERROR",
      message: `${errored.length} of ${checked.length} DKIM selector lookups failed (${codes}); those selectors could not be checked.`,
      recommendation: "Verify the authoritative nameservers respond correctly and retry."
    });
  }
  if (found.length === 0 && errored.length === 0) {
    findings.push({
      severity: "medium",
      code: "DKIM_NOT_FOUND",
      message: `No DKIM key was found under any of ${checked.length} common selectors. The domain may use a custom selector or may not sign mail.`,
      recommendation: "Enable DKIM signing in your mail provider and pass the exact selector via the dkimSelectors argument to confirm."
    });
  }
  for (const result of found) {
    if (result.revoked) {
      findings.push({
        severity: "low",
        code: "DKIM_KEY_REVOKED",
        message: `Selector ${result.selector} publishes a revoked (empty) key.`,
        recommendation: "Remove stale selectors or rotate to a new key."
      });
    }
    if (result.keyType === "rsa" && result.keyBits !== null && result.keyBits < 1024) {
      findings.push({
        severity: "high",
        code: "DKIM_KEY_TOO_SHORT",
        message: `Selector ${result.selector} uses a ${result.keyBits}-bit RSA key that receivers reject.`,
        recommendation: "Rotate to a 2048-bit RSA key."
      });
    } else if (result.keyType === "rsa" && result.keyBits !== null && result.keyBits < 2048) {
      findings.push({
        severity: "low",
        code: "DKIM_KEY_WEAK",
        message: `Selector ${result.selector} uses a ${result.keyBits}-bit RSA key.`,
        recommendation: "Rotate to a 2048-bit RSA key."
      });
    }
    if (result.testing) {
      findings.push({
        severity: "low",
        code: "DKIM_TESTING_MODE",
        message: `Selector ${result.selector} is flagged t=y (testing).`,
        recommendation: "Remove the t=y flag once signing is verified."
      });
    }
  }

  return { checkedSelectors: checked, selectors: results, found: found.length > 0, weakKeys, providers, findings };
}
