/**
 * Zod contracts for every tool input and output. The MCP SDK validates
 * arguments against the input schemas before a handler runs and validates
 * structuredContent against the output schemas before a result is returned,
 * so agents always receive a stable, documented shape.
 */

import { z } from "zod";
import { DEFAULT_DKIM_SELECTORS } from "./lib/dkim.js";

export const DomainInputSchema = z
  .string()
  .trim()
  .min(1)
  .max(2048)
  .describe(
    'Domain to inspect. Accepts a bare hostname ("example.com"), a URL ("https://www.example.com/pricing") or an email address ("jane@example.com"). Scheme, path, port and query are stripped; IDN names are accepted.'
  );

export const InspectTechStackInputSchema = z.object({
  domain: DomainInputSchema,
  includeRawHeaders: z.boolean().default(false).describe("Include the full lower-cased response header map in the result."),
  includeEvidence: z.boolean().default(true).describe("Include the matched pattern and HTML snippet for every detected technology.")
});

export const VerifyEmailInfrastructureInputSchema = z.object({
  domain: DomainInputSchema,
  dkimSelectors: z
    .array(z.string().trim().min(1).max(63))
    .max(50)
    .default([])
    .describe(`Extra DKIM selectors to probe, e.g. ["google", "selector1", "k1"]. ${DEFAULT_DKIM_SELECTORS.length} common provider selectors are always probed.`),
  checkMtaSts: z.boolean().default(true).describe("Fetch and validate the MTA-STS policy file over HTTPS when a _mta-sts record exists.")
});

export const ComprehensiveAuditInputSchema = z.object({
  domain: DomainInputSchema,
  dkimSelectors: z.array(z.string().trim().min(1).max(63)).max(50).default([]).describe("Extra DKIM selectors to probe."),
  includeRawHeaders: z.boolean().default(false).describe("Include the raw response header map in the tech-stack section."),
  includeEvidence: z.boolean().default(false).describe("Include detection evidence snippets in the tech-stack section.")
});

export type InspectTechStackInput = z.infer<typeof InspectTechStackInputSchema>;
export type VerifyEmailInfrastructureInput = z.infer<typeof VerifyEmailInfrastructureInputSchema>;
export type ComprehensiveAuditInput = z.infer<typeof ComprehensiveAuditInputSchema>;

export const SeveritySchema = z.enum(["critical", "high", "medium", "low", "info"]);
export const GradeSchema = z.enum(["A", "B", "C", "D", "F"]);

export const FindingSchema = z.object({
  severity: SeveritySchema,
  code: z.string(),
  message: z.string(),
  recommendation: z.string()
});

export const ErrorInfoSchema = z.object({
  code: z.string(),
  message: z.string()
});

export const BillingSchema = z.object({
  principal: z.string(),
  plan: z.string(),
  creditsCharged: z
    .number()
    .describe(
      "Prepaid credits this call itself charged: 0 for plan keys (they spend daily quota instead) and 0 for start_bulk_check, whose up-front charge is reported in job.creditsCharged and job.quotaUnitsCharged; creditsRemaining already reflects it."
    ),
  creditsRemaining: z.number().nullable(),
  requestsRemainingThisMinute: z.number().nullable(),
  requestsRemainingToday: z.number().nullable()
});

export const ScoreBreakdownItemSchema = z.object({
  component: z.string(),
  points: z.number(),
  maxPoints: z.number(),
  note: z.string()
});

export const FetchErrorSchema = z.object({
  kind: z.enum(["timeout", "dns", "tls", "connection", "private_target", "redirect", "aborted", "robots", "unknown"]),
  code: z.string(),
  message: z.string()
});

export const RedirectHopSchema = z.object({
  url: z.string(),
  status: z.number(),
  location: z.string()
});

export const BlockDetectionSchema = z.object({
  blocked: z.boolean(),
  vendor: z.string().nullable(),
  challengeType: z.enum(["javascript", "captcha", "access_denied", "rate_limited"]).nullable(),
  reason: z.string().nullable()
});

export const EvidenceSchema = z.object({
  type: z.enum(["html", "script", "header", "cookie", "meta", "implied"]),
  pattern: z.string(),
  sample: z.string()
});

export const DetectionSchema = z.object({
  id: z.string(),
  name: z.string(),
  category: z.string(),
  categoryLabel: z.string(),
  website: z.string().nullable(),
  confidence: z.number(),
  version: z.string().nullable(),
  implied: z.boolean(),
  evidence: z.array(EvidenceSchema)
});

export const TlsInspectionSchema = z.object({
  reachable: z.boolean(),
  valid: z.boolean(),
  authorized: z.boolean(),
  authorizationError: z.string().nullable(),
  hostnameMatches: z.boolean(),
  protocol: z.string().nullable(),
  cipher: z.string().nullable(),
  subject: z.string().nullable(),
  issuer: z.string().nullable(),
  subjectAltNames: z.array(z.string()),
  validFrom: z.string().nullable(),
  validTo: z.string().nullable(),
  daysUntilExpiry: z.number().nullable(),
  expired: z.boolean(),
  notYetValid: z.boolean(),
  selfSigned: z.boolean(),
  keyType: z.string().nullable(),
  keyBits: z.number().nullable(),
  serialNumber: z.string().nullable(),
  fingerprint256: z.string().nullable(),
  chainLength: z.number(),
  error: ErrorInfoSchema.nullable(),
  durationMs: z.number()
});

export const HeaderCheckSchema = z.object({
  header: z.string(),
  present: z.boolean(),
  value: z.string().nullable(),
  status: z.enum(["pass", "warn", "fail", "info"]),
  points: z.number(),
  maxPoints: z.number(),
  note: z.string()
});

export const SecurityHeadersReportSchema = z.object({
  score: z.number(),
  grade: GradeSchema,
  https: z.boolean(),
  hsts: z.object({
    present: z.boolean(),
    maxAge: z.number().nullable(),
    includeSubDomains: z.boolean(),
    preload: z.boolean()
  }),
  csp: z.object({
    present: z.boolean(),
    reportOnly: z.boolean(),
    unsafeInline: z.boolean(),
    unsafeEval: z.boolean(),
    frameAncestors: z.boolean(),
    upgradeInsecureRequests: z.boolean(),
    directiveCount: z.number()
  }),
  cookies: z.object({
    total: z.number(),
    secure: z.number(),
    httpOnly: z.number(),
    sameSite: z.number()
  }),
  infoLeaks: z.array(z.string()),
  checks: z.array(HeaderCheckSchema),
  findings: z.array(FindingSchema)
});

export const InspectTechStackOutputSchema = z.object({
  domain: z.string(),
  inputDomain: z.string(),
  fetchedAt: z.string(),
  fetch: z.object({
    ok: z.boolean(),
    requestedUrl: z.string(),
    finalUrl: z.string(),
    finalHost: z.string().nullable(),
    protocol: z.enum(["https", "http"]).nullable(),
    status: z.number().nullable(),
    statusText: z.string().nullable(),
    contentType: z.string().nullable(),
    bodyBytes: z.number(),
    truncated: z.boolean(),
    responseTimeMs: z.number(),
    attempts: z.number(),
    redirectChain: z.array(RedirectHopSchema),
    redirectedOffDomain: z.boolean(),
    httpsDowngraded: z.boolean(),
    tlsError: FetchErrorSchema.nullable(),
    error: FetchErrorSchema.nullable()
  }),
  blocked: BlockDetectionSchema,
  partial: z.boolean(),
  technologies: z.array(DetectionSchema),
  categories: z.record(z.string(), z.array(z.string())),
  summary: z.object({
    total: z.number(),
    byCategory: z.record(z.string(), z.number()),
    cms: z.string().nullable(),
    ecommerce: z.string().nullable(),
    framework: z.string().nullable(),
    cdn: z.string().nullable(),
    hosting: z.string().nullable(),
    webServer: z.string().nullable(),
    tagManager: z.string().nullable(),
    analytics: z.array(z.string()),
    marketingAutomation: z.array(z.string()),
    crm: z.array(z.string()),
    payments: z.array(z.string()),
    liveChat: z.array(z.string()),
    advertising: z.array(z.string()),
    waf: z.array(z.string())
  }),
  security: z.object({
    score: z.number(),
    grade: GradeSchema,
    breakdown: z.array(ScoreBreakdownItemSchema),
    tls: TlsInspectionSchema,
    headers: SecurityHeadersReportSchema.nullable(),
    findings: z.array(FindingSchema)
  }),
  rawHeaders: z.record(z.string(), z.string()).nullable(),
  signatureDatabase: z.object({ version: z.string(), count: z.number() }),
  timings: z.object({ totalMs: z.number(), fetchMs: z.number(), tlsMs: z.number(), detectMs: z.number() }),
  warnings: z.array(z.string()),
  billing: BillingSchema.nullable()
});

export type InspectTechStackOutput = z.infer<typeof InspectTechStackOutputSchema>;

export const SpfMechanismSchema = z.object({
  qualifier: z.enum(["+", "-", "~", "?"]),
  type: z.enum(["all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"]),
  value: z.string().nullable(),
  raw: z.string()
});

export const SpfIncludeEntrySchema = z.object({
  domain: z.string(),
  parent: z.string().nullable(),
  depth: z.number(),
  record: z.string().nullable(),
  lookups: z.number(),
  error: z.string().nullable()
});

export const DmarcDestinationSchema = z.object({
  uri: z.string(),
  domain: z.string().nullable(),
  external: z.boolean(),
  authorized: z.boolean().nullable()
});

export const DkimSelectorSchema = z.object({
  selector: z.string(),
  name: z.string(),
  found: z.boolean(),
  record: z.string().nullable(),
  cname: z.string().nullable(),
  keyType: z.string().nullable(),
  keyBits: z.number().nullable(),
  hashAlgorithms: z.array(z.string()),
  testing: z.boolean(),
  revoked: z.boolean(),
  provider: z.string().nullable(),
  issues: z.array(z.string()),
  error: z.string().nullable().describe("DNS error code when the selector could not be checked; null when the lookup answered.")
});

export const VerifyEmailInfrastructureOutputSchema = z.object({
  domain: z.string(),
  inputDomain: z.string(),
  organizationalDomain: z.string(),
  isSubdomain: z.boolean(),
  checkedAt: z.string(),
  exists: z.boolean(),
  nxdomain: z.boolean(),
  mx: z.object({
    found: z.boolean(),
    nullMx: z.boolean(),
    provider: z.string().nullable(),
    providers: z.array(z.string()),
    usesImplicitA: z.boolean(),
    fallbackAddresses: z.array(z.string()),
    records: z.array(
      z.object({
        exchange: z.string(),
        priority: z.number(),
        addresses: z.array(z.string()),
        resolvable: z.boolean(),
        lookupFailed: z.boolean().describe("The A/AAAA lookups failed, so whether this exchange resolves is unknown."),
        provider: z.string().nullable()
      })
    ),
    dnsError: ErrorInfoSchema.nullable()
  }),
  spf: z.object({
    found: z.boolean(),
    record: z.string().nullable(),
    records: z.array(z.string()),
    valid: z.boolean(),
    allQualifier: z.enum(["+", "-", "~", "?"]).nullable(),
    allPolicy: z
      .enum(["fail", "softfail", "neutral", "pass", "none"])
      .describe(
        "Terminal all policy, following redirect=. 'none' when there is no SPF record or no all term, and also when the policy sits behind a redirect= target whose lookup failed (allQualifier null, redirect set, SPF_DNS_ERROR in risks): the policy is then unknown, not none. Stored snapshots and bulk summaries report that case as 'unknown'."
      ),
    includes: z.array(z.string()),
    redirect: z.string().nullable(),
    ip4: z.array(z.string()),
    ip6: z.array(z.string()),
    lookupCount: z.number(),
    lookupLimitExceeded: z.boolean(),
    voidLookups: z.number(),
    detectedSenders: z.array(z.string()),
    mechanisms: z.array(SpfMechanismSchema),
    modifiers: z.array(z.object({ name: z.string(), value: z.string(), raw: z.string() })),
    includeChain: z.array(SpfIncludeEntrySchema)
  }),
  dkim: z.object({
    found: z.boolean(),
    checkedSelectors: z.array(z.string()),
    providers: z.array(z.string()),
    weakKeys: z.array(z.string()),
    selectors: z.array(DkimSelectorSchema)
  }),
  dmarc: z.object({
    found: z.boolean(),
    record: z.string().nullable(),
    records: z.array(z.string()),
    queriedName: z.string(),
    location: z.string().nullable(),
    inheritedFromOrganizationalDomain: z
      .boolean()
      .describe(
        "The record is the organizational domain's. Together with DMARC_DNS_ERROR in risks it means the subdomain's own _dmarc lookup failed: record, policy and effectivePolicy are the organizational domain's, and the subdomain's own policy is unknown (scored like p=none; stored snapshots and bulk summaries report it as 'unknown')."
      ),
    valid: z.boolean(),
    policy: z.enum(["none", "quarantine", "reject"]).nullable(),
    subdomainPolicy: z.enum(["none", "quarantine", "reject"]).nullable(),
    effectivePolicy: z
      .enum(["none", "quarantine", "reject"])
      .nullable()
      .describe(
        "The policy that applies to this domain (sp=, else p=, when inherited by a subdomain); null when there is no record or no valid policy tag. Not the subdomain's own policy when inheritedFromOrganizationalDomain is true and DMARC_DNS_ERROR is in risks."
      ),
    pct: z.number(),
    adkim: z.enum(["r", "s"]),
    aspf: z.enum(["r", "s"]),
    rua: z.array(DmarcDestinationSchema),
    ruf: z.array(DmarcDestinationSchema),
    fo: z.string(),
    rf: z.string(),
    ri: z.number(),
    tags: z.record(z.string(), z.string()),
    enforcement: z.enum(["none", "partial", "full"])
  }),
  mtaSts: z.object({
    found: z.boolean(),
    record: z.string().nullable(),
    id: z.string().nullable(),
    policy: z.object({
      fetched: z.boolean(),
      url: z.string(),
      version: z.string().nullable(),
      mode: z.enum(["enforce", "testing", "none"]).nullable(),
      mx: z.array(z.string()),
      maxAge: z.number().nullable(),
      mxCoversAllExchanges: z.boolean().nullable(),
      error: z.string().nullable(),
      failure: z
        .enum(["transient", "definitive"])
        .nullable()
        .describe(
          "Why the policy was not fetched: transient (timeout, connection reset, resolver trouble, HTTP 408/425/429/5xx or a bot challenge; a retry may succeed) or definitive (the policy host does not exist, an invalid certificate, a private address, a redirect or another non-200 status such as 404, not a policy, too large); null when fetched or not attempted."
        )
    })
  }),
  tlsRpt: z.object({
    found: z.boolean(),
    record: z.string().nullable(),
    rua: z.array(z.string())
  }),
  bimi: z.object({
    found: z.boolean(),
    record: z.string().nullable(),
    logoUrl: z.string().nullable(),
    vmcUrl: z.string().nullable()
  }),
  disposable: z.object({
    disposable: z.boolean(),
    matchedDomain: z.string().nullable()
  }),
  providers: z.object({
    mailbox: z.string().nullable(),
    sendingServices: z.array(z.string()),
    dkimServices: z.array(z.string())
  }),
  score: z.number(),
  grade: GradeSchema,
  scoreBreakdown: z.array(ScoreBreakdownItemSchema),
  risks: z.array(FindingSchema),
  riskCounts: z.object({
    critical: z.number(),
    high: z.number(),
    medium: z.number(),
    low: z.number(),
    info: z.number()
  }),
  summary: z.string(),
  timings: z.object({ totalMs: z.number() }),
  billing: BillingSchema.nullable()
});

export type VerifyEmailInfrastructureOutput = z.infer<typeof VerifyEmailInfrastructureOutputSchema>;

export const ComprehensiveAuditOutputSchema = z.object({
  domain: z.string(),
  inputDomain: z.string(),
  auditedAt: z.string(),
  scores: z.object({
    overall: z.number(),
    grade: GradeSchema,
    email: z.number(),
    security: z.number(),
    infrastructure: z.number(),
    weights: z.object({ email: z.number(), security: z.number(), infrastructure: z.number() }),
    infrastructureBreakdown: z.array(ScoreBreakdownItemSchema)
  }),
  techStack: InspectTechStackOutputSchema.nullable(),
  techStackError: ErrorInfoSchema.nullable(),
  email: VerifyEmailInfrastructureOutputSchema.nullable(),
  emailError: ErrorInfoSchema.nullable(),
  findings: z.array(FindingSchema),
  findingCounts: z.object({
    critical: z.number(),
    high: z.number(),
    medium: z.number(),
    low: z.number(),
    info: z.number()
  }),
  highlights: z.array(z.string()),
  summary: z.string(),
  timings: z.object({ totalMs: z.number(), techStackMs: z.number(), emailMs: z.number() }),
  billing: BillingSchema.nullable()
});

export type ComprehensiveAuditOutput = z.infer<typeof ComprehensiveAuditOutputSchema>;

export const DomainHistoryInputSchema = z.object({
  domain: DomainInputSchema,
  changesLimit: z.number().int().min(1).max(200).default(50).describe("Maximum number of recorded changes to return, newest first.")
});

export type DomainHistoryInput = z.infer<typeof DomainHistoryInputSchema>;

export const ScanKindSchema = z.enum(["tech", "email"]);
export const ScanSourceSchema = z.enum(["call", "bulk", "monitor", "crawl"]);

export const EmailComponentSchema = z.enum(["mx", "mxHosts", "spf", "spfLookups", "dmarc", "dkim", "mtaSts", "reporting", "score", "other"]);

export const EmailSnapshotSchema = z.object({
  score: z.number().nullable().describe("Null until a scan in which every lookup answered or whose remaining failures were accepted as persistent (three scans over at least a day)."),
  grade: GradeSchema.nullable(),
  mxFound: z.boolean(),
  nullMx: z.boolean(),
  mxProvider: z.string().nullable(),
  spfFound: z.boolean(),
  spfValid: z.boolean(),
  spfPolicy: z
    .string()
    .describe(
      "fail | softfail | neutral | pass | none; unknown when an SPF redirect= target's lookup failed, so the terminal all policy could not be read. Read spfFound first: without a record this reads none."
    ),
  dmarcFound: z.boolean(),
  dmarcPolicy: z
    .string()
    .nullable()
    .describe(
      "reject | quarantine | none; unknown when a subdomain's own _dmarc lookup failed and only the organizational record answered; null when there is no record (dmarcFound false) or the record has no valid policy."
    ),
  dkimSelectors: z.array(z.string()),
  mtaStsMode: z.string().nullable(),
  highRisks: z.array(z.string()),
  // The SPF clause follows scanStore's unread markers (spfPolicyUnread, spfLookupsUnread, spfUnreadTarget, spfLookupsPartial) and resetsScore:
  // an agent watching for score_drop must know which scans skip the score comparison.
  unverified: z
    .array(EmailComponentSchema)
    .describe(
      "Components not yet established: no lookup has answered them and their failure has not yet been accepted as persistent (three scans over at least a day); their fields come from a failed lookup, not the domain's real posture. An empty list therefore does not mean every component has answered: check lookupsFailing. Even once accepted, DMARC stays here while only the organizational fallback of a failed own _dmarc lookup has answered. SPF whose redirect= target has never answered leaves this list once the failure is accepted (spfPolicy reads unknown), so changes to the domain's own record are still reported, including its removal (an accepted failure of its own TXT lookup reads as one) and one that stops delegating to that target. While the record still delegates to it, the first scan in which the whole redirect= chain answers is a baseline, not a change, for the terminal policy and the findings that describe it, and the first such scan with spfLookups established is the include tree's baseline; until then, the first reading in which the target answered but a later hop's failure was accepted is a baseline too, and later such readings are compared with it. Each also re-baselines the score: no score_drop or score_rise for that scan or, when another lookup failed in it, for the next scan that rewrites the score."
    ),
  lookupsFailing: z
    .array(EmailComponentSchema)
    .describe(
      "Components whose latest lookups failed. Their fields are the last known values while the failure is held, or the current (failed) reading once it was accepted as persistent (three scans over at least a day). A component also listed in unverified has no last known value."
    )
});

export const DomainChangeSchema = z.object({
  kind: ScanKindSchema,
  change: z.string().describe("What changed, e.g. tech_added, tech_removed, dmarc_policy, spf_policy, mx_provider, dkim_lost, risk_new, score_drop."),
  subject: z.string().nullable(),
  oldValue: z.string().nullable(),
  newValue: z.string().nullable(),
  severity: SeveritySchema,
  at: z.string()
});

export const StoredTechnologySchema = z.object({
  id: z.string(),
  name: z.string(),
  category: z.string(),
  version: z.string().nullable(),
  implied: z.boolean(),
  active: z.boolean(),
  firstSeen: z.string(),
  lastSeen: z.string(),
  removedAt: z.string().nullable()
});

export const DomainHistoryOutputSchema = z.object({
  domain: z.string(),
  known: z.boolean().describe("False when this server has never scanned the domain; every other field is then empty."),
  firstSeen: z.string().nullable(),
  lastTechScanAt: z.string().nullable(),
  lastEmailScanAt: z.string().nullable(),
  technologies: z.array(StoredTechnologySchema),
  email: EmailSnapshotSchema.nullable(),
  changes: z.array(DomainChangeSchema),
  recentScans: z.array(z.object({ kind: ScanKindSchema, source: ScanSourceSchema, at: z.string(), ok: z.boolean(), score: z.number().nullable(), grade: z.string().nullable() })),
  billing: BillingSchema.nullable()
});

export type DomainHistoryOutput = z.infer<typeof DomainHistoryOutputSchema>;

export type Billing = z.infer<typeof BillingSchema>;

// ---------------------------------------------------------------------------
// Bulk checks

export const BulkCheckKindSchema = z.enum(["email", "tech", "audit"]);
export const JobStatusSchema = z.enum(["queued", "running", "completed", "cancelled"]);
export const JobItemStatusSchema = z.enum(["pending", "running", "done", "failed", "skipped", "cancelled"]);
const JobIdSchema = z
  .string()
  .regex(/^job_[0-9a-f]{24}$/)
  .describe("Job id returned by start_bulk_check (job_ followed by 24 hex characters).");

/** Mirrors the store's rule (src/store/jobs.ts): skipped entries are free, but a list that is mostly junk is refused outright. */
export const BULK_SKIP_RULE = "a list with more invalid or duplicate entries than max(100, accepted domains) is refused with INVALID_ARGUMENT.";
const BULK_DOMAINS_DESCRIPTION = `Domains, URLs or email addresses. Duplicates (by site) and invalid entries are skipped and never charged; ${BULK_SKIP_RULE}`;

/** The sentinel values a compact bulk result can carry, beyond what the single-domain tools return. */
export const BULK_RESULT_VALUES =
  "For email checks spfPolicy and dmarcPolicy can also be missing (no record) or unknown (the lookup failed, an SPF redirect= target's lookup failed, or a subdomain's own _dmarc lookup failed), dmarcPolicy invalid (a record without a valid policy), and mxProvider unknown (the MX lookup failed) or 'null MX (no mail)'.";

export const StartBulkCheckInputSchema = z.object({
  check: BulkCheckKindSchema.describe("email = verify_email_infrastructure, tech = inspect_tech_stack, audit = comprehensive_audit, for every domain."),
  domains: z.array(z.string().max(2048)).min(1).max(50000).describe(BULK_DOMAINS_DESCRIPTION)
});

/** The fixed list cap the schema had before it followed STACKDNS_BULK_MAX_DOMAINS; the hard cap never drops below it. */
const BULK_SCHEMA_ENTRY_FLOOR = 50000;

/**
 * The start_bulk_check input for a server whose job maximum is maxDomains.
 * The store accepts up to twice that many raw entries (duplicates and invalid
 * entries are skipped before the distinct count is checked), and the describe
 * states that bound. The schema's hard cap is max(50000, 2 x maxDomains)
 * rather than the bound itself: the SDK answers a schema rejection with plain
 * text and no error object, so a list just over the bound must reach the job
 * service, whose LIMIT_EXCEEDED carries details.maxDomains for the agent to
 * split on (and matches what the REST API answers for the same list). Above
 * 25000 domains the cap grows with the bound, so the REST API never accepts a
 * list this schema refuses.
 */
export function startBulkCheckInputSchema(maxDomains: number) {
  const maxEntries = Math.max(1, Math.floor(maxDomains)) * 2;
  const hardCap = Math.max(BULK_SCHEMA_ENTRY_FLOOR, maxEntries);
  // Only claim LIMIT_EXCEEDED for lists that can reach the job service: at the hard cap the schema itself refuses them.
  const overLimit =
    hardCap > maxEntries
      ? `a list over either limit (up to ${hardCap} entries) is refused with LIMIT_EXCEEDED (details.maxDomains)`
      : "more distinct domains are refused with LIMIT_EXCEEDED (details.maxDomains)";
  return StartBulkCheckInputSchema.extend({
    domains: z.array(z.string().max(2048)).min(1).max(hardCap).describe(`${BULK_DOMAINS_DESCRIPTION} At most ${maxDomains} distinct domains per job, in at most ${maxEntries} entries; ${overLimit}.`)
  });
}

export const GetBulkCheckInputSchema = z.object({
  jobId: JobIdSchema,
  offset: z.number().int().min(0).default(0).describe("Index of the first result to return."),
  limit: z.number().int().min(1).max(500).default(100).describe("Results per page."),
  status: JobItemStatusSchema.optional().describe("Only return items in this state, e.g. failed.")
});

export const ListBulkChecksInputSchema = z.object({
  limit: z.number().int().min(1).max(100).default(20)
});

export const CancelBulkCheckInputSchema = z.object({ jobId: JobIdSchema });

export const JobSummarySchema = z.object({
  jobId: z.string(),
  check: BulkCheckKindSchema,
  status: JobStatusSchema,
  submitted: z.number(),
  accepted: z.number(),
  counts: z.object({ pending: z.number(), running: z.number(), done: z.number(), failed: z.number(), skipped: z.number(), cancelled: z.number() }),
  creditsPerDomain: z.number(),
  creditsCharged: z.number().describe("Prepaid credits charged up front; failed and cancelled items are refunded when the job finishes."),
  creditsRefunded: z.number(),
  quotaUnitsCharged: z.number().describe("Daily-quota units charged up front for plan keys; refunded like credits."),
  quotaUnitsRefunded: z.number(),
  createdAt: z.string(),
  startedAt: z.string().nullable(),
  finishedAt: z.string().nullable()
});

export const JobItemSchema = z.object({
  index: z.number(),
  input: z.string(),
  domain: z.string().nullable(),
  status: JobItemStatusSchema,
  result: z.record(z.string(), z.unknown()).nullable().describe(`Compact per-domain summary; use the single-domain tool for the full report. ${BULK_RESULT_VALUES}`),
  error: z.object({ code: z.string(), message: z.string() }).nullable()
});

export const SkippedInputSchema = z.object({
  index: z.number(),
  input: z.string(),
  code: z.enum(["INVALID_DOMAIN", "PRIVATE_TARGET", "DUPLICATE"]),
  message: z.string()
});

export const StartBulkCheckOutputSchema = z.object({
  job: JobSummarySchema,
  skipped: z.array(SkippedInputSchema).describe("The first 100 skipped inputs."),
  skippedTotal: z.number(),
  next: z.string(),
  billing: BillingSchema.nullable()
});

export const GetBulkCheckOutputSchema = JobSummarySchema.extend({
  items: z.array(JobItemSchema),
  nextOffset: z.number().nullable().describe("Pass as offset to fetch the next page; null when this is the last page."),
  billing: BillingSchema.nullable()
});

export const ListBulkChecksOutputSchema = z.object({ jobs: z.array(JobSummarySchema), billing: BillingSchema.nullable() });
export const CancelBulkCheckOutputSchema = z.object({ job: JobSummarySchema, billing: BillingSchema.nullable() });

// ---------------------------------------------------------------------------
// Monitoring

export const MonitorCheckSchema = z.enum(["email", "tech"]);

export const WatchDomainInputSchema = z.object({
  domain: DomainInputSchema,
  checks: z.array(MonitorCheckSchema).min(1).max(2).default(["email", "tech"]).describe("What to re-check on schedule."),
  webhookUrl: z
    .string()
    .max(2048)
    .optional()
    .describe("Optional https URL that receives each batch of alerts as a signed POST (header x-stackdns-signature: t=<unix>,v1=<hex HMAC-SHA256 of `${t}.${body}`>). Omit to use get_alerts only.")
});

export const UnwatchDomainInputSchema = z.object({
  watchId: z.string().max(64).optional(),
  domain: z.string().max(2048).optional().describe("Alternative to watchId.")
});

export const ListWatchesInputSchema = z.object({});

export const GetAlertsInputSchema = z.object({
  sinceId: z.number().int().min(0).default(0).describe("Only alerts with a larger id; pass the previous nextSinceId to page."),
  limit: z.number().int().min(1).max(200).default(50),
  unreadOnly: z.boolean().default(true),
  markRead: z.boolean().default(true).describe("Mark the returned alerts read, so the next unread call skips them.")
});

export const WatchSchema = z.object({
  id: z.string(),
  domain: z.string(),
  checks: z.array(MonitorCheckSchema),
  webhookUrl: z.string().nullable(),
  createdAt: z.string(),
  lastCheckedAt: z.string().nullable(),
  nextCheckAt: z.string().nullable(),
  paused: z.boolean(),
  pausedReason: z.string().nullable()
});

export const AlertSchema = z.object({
  id: z.number(),
  watchId: z.string(),
  domain: z.string(),
  kind: z.string().describe("email, tech, or monitor for notices about the watch itself."),
  change: z.string(),
  subject: z.string().nullable(),
  oldValue: z.string().nullable(),
  newValue: z.string().nullable(),
  severity: SeveritySchema,
  at: z.string(),
  createdAt: z.string(),
  read: z.boolean(),
  delivery: z.object({ status: z.enum(["none", "pending", "delivered", "failed"]), attempts: z.number(), lastError: z.string().nullable() })
});

export const WatchDomainOutputSchema = z.object({
  watch: WatchSchema,
  created: z.boolean(),
  webhookSecret: z.string().nullable().describe("Signing secret for webhook deliveries, shown only when the watch is created. Store it now."),
  watchLimit: z.number(),
  billing: BillingSchema.nullable()
});

export const UnwatchDomainOutputSchema = z.object({ removed: z.boolean(), billing: BillingSchema.nullable() });
export const ListWatchesOutputSchema = z.object({ watches: z.array(WatchSchema), watchLimit: z.number(), billing: BillingSchema.nullable() });
export const GetAlertsOutputSchema = z.object({ alerts: z.array(AlertSchema), nextSinceId: z.number().nullable(), billing: BillingSchema.nullable() });

// ---------------------------------------------------------------------------
// Reverse technology lookup

export const TechnologyRefSchema = z.object({ id: z.string(), name: z.string(), category: z.string(), categoryLabel: z.string() });

export const FindDomainsUsingInputSchema = z.object({
  technology: z.string().min(1).max(200).describe('Technology id or name, e.g. "shopify", "Klaviyo", "HubSpot". Use list_technologies to browse.'),
  activeOnly: z.boolean().default(true).describe("Only domains where the technology is still detected; false also returns domains that removed it."),
  seenWithinDays: z.number().int().min(1).max(3650).optional().describe("Only domains where the technology was seen within this many days."),
  limit: z.number().int().min(1).max(500).default(50),
  cursor: z.string().max(512).optional().describe("nextCursor from the previous page.")
});

export const FindDomainsUsingOutputSchema = z.object({
  technology: TechnologyRefSchema,
  universe: z
    .object({ domains: z.number(), scanned: z.number(), lastCrawlAt: z.string().nullable() })
    .describe("The searchable set: domains on this server's crawl list and how many have been scanned. Results only ever come from this list."),
  total: z.number().describe("Matching domains across all pages."),
  domains: z.array(z.object({ domain: z.string(), version: z.string().nullable(), active: z.boolean(), firstSeen: z.string(), lastSeen: z.string(), removedAt: z.string().nullable() })),
  nextCursor: z.string().nullable(),
  billing: BillingSchema.nullable()
});

export const ListTechnologiesInputSchema = z.object({
  query: z.string().max(200).optional().describe('Filter by id or name, e.g. "shop".'),
  category: z.string().max(100).optional().describe('Filter by category id or label, e.g. "ecommerce" or "Marketing automation".'),
  limit: z.number().int().min(1).max(1000).default(100)
});

export const ListTechnologiesOutputSchema = z.object({
  technologies: z.array(TechnologyRefSchema.extend({ domains: z.number().describe("Crawl-list domains currently using it.") })),
  total: z.number(),
  categories: z.array(z.string()),
  billing: BillingSchema.nullable()
});
