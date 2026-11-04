/**
 * Stored scans: every tech-stack and email inspection is recorded, the
 * current technology set of each domain is maintained, and differences
 * between consecutive scans are written to a change log. The change log
 * feeds domain history and monitoring alerts. Tech scans by the crawler also
 * maintain crawl_tech, the only state behind the reverse "who uses X"
 * lookup; domain_tech and scans from calls, bulk jobs or the monitor never
 * surface there.
 *
 * Scans are stored per site, keyed by the domain with any leading "www."
 * removed, and never record which caller requested them.
 *
 * Flapping is damped deliberately: a technology or DKIM selector must be
 * missing from two consecutive clean scans before it is reported as removed,
 * because lazily loaded tags and transient DNS failures would otherwise
 * produce a stream of false removals. Tech scans that were blocked or failed
 * never update state, and an email component whose lookup failed keeps its
 * last known value, instead of being read as removed, until the failure is
 * accepted as persistent.
 */

import { DEFAULT_DKIM_SELECTORS } from "../lib/dkim.js";
import { dmarcOwnLookupFailed } from "../lib/dmarc.js";
import { stripWww } from "../lib/domain.js";
import type { Severity } from "../lib/findings.js";
import { DMARC_POLICY_UNKNOWN_POINTS, gradeFromScore, mxSetPoints, scoreDmarc, type Grade } from "../lib/scoring.js";
import { spfPolicyLookupFailed } from "../lib/spf.js";
import type { InspectTechStackOutput, VerifyEmailInfrastructureOutput } from "../schemas.js";
import { transaction, type Database } from "./db.js";

export type ScanKind = "tech" | "email";
export type ScanSource = "call" | "bulk" | "monitor" | "crawl";

export interface DomainChange {
  id?: number;
  domain: string;
  kind: ScanKind;
  change: string;
  subject: string | null;
  oldValue: string | null;
  newValue: string | null;
  severity: Severity;
  at: number;
}

export type TechScanInput = Pick<InspectTechStackOutput, "domain" | "fetch" | "blocked" | "technologies" | "security" | "partial">;
export type EmailScanInput = Pick<VerifyEmailInfrastructureOutput, "domain" | "score" | "grade" | "mx" | "spf" | "dmarc" | "dkim" | "mtaSts" | "risks"> &
  Partial<Pick<VerifyEmailInfrastructureOutput, "scoreBreakdown">>;

/**
 * The parts of an email posture whose lookups can fail independently.
 * mxHosts covers resolving the exchanges (and the implicit-A fallback) as
 * opposed to the domain's own MX records (mx); spfLookups covers what depends
 * on include: expansion (validity, lookup count, void lookups) as opposed to
 * the domain's own record (spf); reporting covers TLS-RPT and BIMI.
 */
export type EmailComponent = "mx" | "mxHosts" | "spf" | "spfLookups" | "dmarc" | "dkim" | "mtaSts" | "reporting" | "score" | "other";
const EMAIL_COMPONENTS: readonly EmailComponent[] = ["mx", "mxHosts", "spf", "spfLookups", "dmarc", "dkim", "mtaSts", "reporting", "score", "other"];
/** Components with their own lookups (score and other are derived). */
const LOOKUP_COMPONENTS = ["mx", "mxHosts", "spf", "spfLookups", "dmarc", "dkim", "mtaSts", "reporting"] as const;
type LookupComponent = (typeof LOOKUP_COMPONENTS)[number];

/**
 * How one scan answered for a component: answered (a real answer, even
 * "absent"), failed (the lookup did not answer), or skipped (the caller
 * turned the check off, which says nothing either way).
 */
export type ComponentAnswer = "answered" | "failed" | "skipped";

/** Internal email posture kept per domain; dkim maps each known selector to its consecutive-miss count. */
export interface EmailState {
  score: number;
  grade: Grade;
  mxFound: boolean;
  nullMx: boolean;
  mxProvider: string | null;
  spfFound: boolean;
  spfValid: boolean;
  spfPolicy: string;
  dmarcFound: boolean;
  dmarcPolicy: string | null;
  dkim: Record<string, number>;
  mtaStsMode: string | null;
  risks: Array<{ code: string; severity: Severity }>;
  /** Components whose value has never been established by an answer (absent in states stored before this field existed). */
  unknown?: EmailComponent[];
  /**
   * Components whose lookups have failed on consecutive scans: since when,
   * for how many scans, and which lookup failed (a streak only grows while
   * the same lookup keeps failing).
   */
  failing?: Partial<Record<EmailComponent, { since: number; scans: number; kind?: string }>>;
  /** Selectors that answered in the scan the stored DKIM risks come from. */
  dkimProbed?: string[];
  /** Selectors that answered in the scan the stored score comes from. */
  scoreProbed?: string[];
  /**
   * The subdomain's DMARC points from the latest scan in which its own DMARC
   * answered. While its own _dmarc lookup fails, the stored score keeps these
   * instead of the fallback's p=none points, so an unknown policy neither
   * raises nor lowers it. Null once the stored score holds the fallback's
   * points because no own points were ever recorded (a state from before
   * this field); absent when DMARC never answered.
   */
  dmarcPoints?: number | null;
  /**
   * Version of the rules the stored policies follow (STATE_BASIS). States
   * stored by earlier code lack it: their next scan re-baselines what those
   * rules stored differently, silently, and sets it.
   */
  basis?: number;
  /** Version of the scoring rules behind the stored score (SCORE_RULES); absent in scores from earlier code. */
  scoreRules?: number;
  /**
   * While spfPolicy / dmarcPolicy is unknown, the policy last actually read
   * before it, so that a move away from unknown is ranked against what was
   * really there. Absent when none was read (the stored reading was never
   * the domain's own, there was no record, or the state predates the field).
   */
  spfPolicyKnown?: string;
  dmarcPolicyKnown?: string | null;
  /**
   * Set while the stored SPF policy is unknown and no policy was ever read:
   * SPF was established by accepting the failure of the redirect= chain
   * behind spfUnreadTarget before it ever answered whole. The domain's own
   * record was read and is compared as usual; only the policy and the
   * findings that describe it wait for the first scan in which the whole
   * chain answers, which is their baseline and the score's.
   */
  spfPolicyUnread?: true;
  /**
   * Set with spfPolicyUnread: the include tree behind that target (validity,
   * lookup count, void lookups) was never read whole either. Carried until
   * the first scan in which the whole chain answers and spfLookups is
   * established, which is the tree's baseline and the score's; that can
   * follow the policy's first read when an include failed in it. Before then,
   * the first scan in which the target answers but spfLookups is established
   * only by accepting a later hop's failure (or the scan that set the
   * markers, if the target answered in it) is a baseline too, score
   * included; later such readings are compared with it, and the marker stays.
   */
  spfLookupsUnread?: true;
  /**
   * Set with spfLookupsUnread once the stored include tree holds the awaited
   * target's part, read while a later hop's accepted failure kept the policy
   * unknown: later such readings are compared with it as usual, and only the
   * first scan in which the whole chain answers is a baseline again.
   */
  spfLookupsPartial?: true;
  /**
   * The domain's own redirect= target spfPolicyUnread and spfLookupsUnread
   * wait on (spfLookupsPartial goes with the latter). They hold only while
   * the domain's own record still hands its policy to that target (redirect=
   * it and no all of its own), or while a failure of its own TXT lookup is
   * held. A record that stops handing it over chose its own policy and
   * include tree, compared like any other change; an accepted own-lookup
   * failure is recorded as spf_removed and drops them as a deletion does.
   */
  spfUnreadTarget?: string;
  /**
   * Set when a scan re-baselined DMARC or SPF from a placeholder reading but
   * could not rewrite the score (another lookup failed), so the stored score
   * still holds the placeholder's points: the next scan that rewrites the
   * score re-baselines it silently and clears this.
   */
  scoreRebaseline?: true;
}

/** The email posture as reported to callers. */
export interface EmailSnapshot {
  /** Null until a scan in which every lookup answered (a skipped check does not count) or its failure was accepted as persistent. */
  score: number | null;
  grade: Grade | null;
  mxFound: boolean;
  nullMx: boolean;
  mxProvider: string | null;
  spfFound: boolean;
  spfValid: boolean;
  spfPolicy: string;
  dmarcFound: boolean;
  dmarcPolicy: string | null;
  dkimSelectors: string[];
  mtaStsMode: string | null;
  highRisks: string[];
  /**
   * Components no lookup has answered yet and whose failure has not been
   * accepted as persistent; their fields come from a failed lookup, not the
   * domain's real posture. DMARC stays here even once accepted while only the
   * organizational fallback of a failed own _dmarc lookup has answered. SPF
   * behind a redirect= target that never answered leaves once the failure is
   * accepted, because the domain's own record did answer: its policy then
   * reads unknown. While that record still delegates to the target, the
   * first scan in which the whole redirect= chain answers is a baseline for
   * the policy and its findings, and the first such scan with spfLookups
   * established is one for the include tree, as is the first earlier reading
   * of it in which the target answered but a later hop's failure was
   * accepted (later such readings are compared with it); the score is
   * re-baselined with them. A record that stops delegating to it is
   * compared as usual, and so is one that returns after an accepted failure
   * of its own lookup, which reads as spf_removed.
   */
  unverified: EmailComponent[];
  /** Components whose latest lookups failed; their fields are the last known values, or the current reading once the failure was accepted as persistent. */
  lookupsFailing: EmailComponent[];
}

export interface StoredTechnology {
  id: string;
  name: string;
  category: string;
  version: string | null;
  implied: boolean;
  active: boolean;
  firstSeen: string;
  lastSeen: string;
  removedAt: string | null;
}

export interface StoredScanSummary {
  kind: ScanKind;
  source: ScanSource;
  at: string;
  ok: boolean;
  score: number | null;
  grade: string | null;
}

export interface PublicChange {
  kind: ScanKind;
  change: string;
  subject: string | null;
  oldValue: string | null;
  newValue: string | null;
  severity: Severity;
  at: string;
}

export interface DomainHistory {
  domain: string;
  known: boolean;
  firstSeen: string | null;
  lastTechScanAt: string | null;
  lastEmailScanAt: string | null;
  technologies: StoredTechnology[];
  email: EmailSnapshot | null;
  changes: PublicChange[];
  recentScans: StoredScanSummary[];
}

export interface ScanStoreOptions {
  /** Scans, changes and removed technologies older than this are deleted by prune(). */
  retentionDays: number;
}

/** A technology or DKIM selector must be absent from this many consecutive clean scans before it counts as removed. */
export const MISSES_BEFORE_REMOVAL = 2;
const RECENT_SCANS = 20;
const PRUNE_BATCH = 1000;

// An unknown policy (a failed redirect= target, a subdomain's failed own
// _dmarc lookup) is scored like no all / p=none, so it ranks with none: a
// stronger policy becoming unknown is a weakening, none -> unknown is not.
// A move away from unknown is ranked against the policy last actually read
// (spfPolicyKnown / dmarcPolicyKnown), never against unknown itself: a +all
// or malformed record that reads the same after the failure did not weaken.
const SPF_POLICY_RANK: Record<string, number> = { fail: 4, softfail: 3, neutral: 1, none: 1, unknown: 1, pass: 0 };
const DMARC_POLICY_RANK: Record<string, number> = { reject: 3, quarantine: 2, none: 1, unknown: 1 };
const MTA_STS_MODE_RANK: Record<string, number> = { enforce: 3, testing: 2, none: 1 };

/**
 * Version of the rules stored policies follow. 1: a subdomain's DMARC
 * policy and findings are never the organizational fallback of its failed
 * own lookup, and an SPF policy behind a failed redirect= target is stored
 * as unknown. Earlier code stored the fallback's policy and findings, and
 * "none", once such a failure was accepted.
 */
const STATE_BASIS = 1;
/** Version of the scoring rules. 2: more than 2 SPF void lookups or a circular include is a permerror that costs SPF points. */
const SCORE_RULES = 2;
/** SPF findings that only describe the terminal all policy, so they say nothing while that policy is unknown. */
const SPF_POLICY_RISKS = new Set(["SPF_PASS_ALL", "SPF_NEUTRAL_ALL", "SPF_SOFTFAIL_ALL"]);

function iso(ms: number | null | undefined): string | null {
  return typeof ms === "number" && Number.isFinite(ms) ? new Date(ms).toISOString() : null;
}

/** Normalizes a domain to the key scans are stored under. */
export function siteKey(domain: string): string {
  return stripWww(domain.trim().toLowerCase().replace(/\.$/, ""));
}

/** Lookup errors are scan trouble, not posture: they are never stored as risks. */
function highRisks(risks: EmailScanInput["risks"]): Array<{ code: string; severity: Severity }> {
  const seen = new Map<string, Severity>();
  for (const risk of risks) {
    if (risk.code.endsWith("_DNS_ERROR")) continue;
    if (risk.severity === "critical" || risk.severity === "high") seen.set(risk.code, risk.severity);
  }
  return [...seen].map(([code, severity]) => ({ code, severity })).sort((a, b) => a.code.localeCompare(b.code));
}

/** SPF findings that depend on include: expansion rather than on the domain's own record. */
const SPF_LOOKUP_RISKS = new Set(["SPF_INCLUDE_DNS_ERROR", "SPF_TOO_MANY_LOOKUPS", "SPF_LOOKUPS_NEAR_LIMIT", "SPF_VOID_LOOKUPS", "SPF_INCLUDE_NO_RECORD", "SPF_CIRCULAR_INCLUDE"]);
/** MX findings that depend on resolving the exchanges (or the implicit-A fallback) rather than on the MX records. */
const MX_HOST_RISKS = new Set(["MX_HOST_DNS_ERROR", "MX_DANGLING", "MX_ALL_UNRESOLVABLE", "MX_PRIVATE_ADDRESS", "MX_MISSING_IMPLICIT_A", "MX_MISSING"]);

/** Which component a finding code belongs to, so its presence is only trusted when that component's lookups answered. */
export function riskComponent(code: string): EmailComponent {
  if (MX_HOST_RISKS.has(code)) return "mxHosts";
  if (code.startsWith("MX_")) return "mx";
  if (SPF_LOOKUP_RISKS.has(code)) return "spfLookups";
  if (code.startsWith("SPF_")) return "spf";
  if (code.startsWith("DMARC_")) return "dmarc";
  if (code.startsWith("DKIM_")) return "dkim";
  if (code.startsWith("MTA_STS_")) return "mtaSts";
  if (code.startsWith("TLS_RPT_") || code.startsWith("BIMI_")) return "reporting";
  return "other";
}

export interface ComponentTrust {
  /** How this scan answered for each component with its own lookups (DKIM is per selector: see dkimErrored). */
  answers: Record<Exclude<LookupComponent, "dkim">, ComponentAnswer>;
  /** For a failed component, which lookup failed; a persistent-failure streak only grows while this stays the same. */
  failureKinds: Record<Exclude<LookupComponent, "dkim">, string>;
  mx: boolean;
  spf: boolean;
  dmarc: boolean;
  mtaSts: boolean;
  /** Selectors whose lookup failed; they were not checked this time. */
  dkimErrored: Set<string>;
  /** Every lookup answered. */
  complete: boolean;
}

/**
 * Decides, per component, whether this scan answered. A failed lookup
 * (SERVFAIL, timeout), a policy fetch that failed for a transient reason, or
 * a check the caller skipped is not evidence that anything changed.
 */
export function componentTrust(result: EmailScanInput): ComponentTrust {
  const codes = new Set(result.risks.map((r) => r.code));
  const failedIf = (failed: boolean): ComponentAnswer => (failed ? "failed" : "answered");
  const mx = failedIf(result.mx.dnsError !== null || codes.has("MX_DNS_ERROR"));
  const spf = failedIf(codes.has("SPF_DNS_ERROR"));
  const policy = result.mtaSts.policy;
  const answers = {
    mx,
    mxHosts: mx === "failed" ? "failed" : failedIf(codes.has("MX_HOST_DNS_ERROR")),
    spf,
    spfLookups: spf === "failed" ? "failed" : failedIf(codes.has("SPF_INCLUDE_DNS_ERROR")),
    dmarc: failedIf(codes.has("DMARC_DNS_ERROR")),
    mtaSts: policy.error === "skipped" ? "skipped" : failedIf(policy.failure === "transient" || codes.has("MTA_STS_DNS_ERROR")),
    reporting: failedIf(codes.has("TLS_RPT_DNS_ERROR") || codes.has("BIMI_DNS_ERROR"))
  } satisfies ComponentTrust["answers"];
  const failedHosts = (result.mx.records ?? [])
    .filter((r) => r.lookupFailed)
    .map((r) => r.exchange)
    .sort();
  const failedIncludes = (result.spf.includeChain ?? [])
    .filter((e) => e.error?.startsWith("DNS error"))
    .map((e) => e.domain)
    .sort();
  const failureKinds = {
    mx: "query",
    mxHosts: mx === "failed" ? "query" : failedHosts.length > 0 ? `hosts:${failedHosts.join(",")}` : "fallback",
    // A DNS error returns no records: found=false means the domain's own TXT
    // lookup failed, found=true that a redirect= target did.
    spf: result.spf.found ? `redirect:${failedIncludes.join(",")}` : "apex",
    spfLookups: spf === "failed" ? (result.spf.found ? `redirect:${failedIncludes.join(",")}` : "apex") : `includes:${failedIncludes.join(",")}`,
    // A found record with an error means the domain's own lookup failed and
    // the organizational fallback answered; otherwise the count tells one
    // failed lookup from both.
    dmarc: result.dmarc.found ? "own" : `lookups:${result.risks.filter((r) => r.code === "DMARC_DNS_ERROR").length}`,
    mtaSts: codes.has("MTA_STS_DNS_ERROR") ? "txt" : "fetch",
    reporting: `${codes.has("TLS_RPT_DNS_ERROR") ? "tlsrpt" : ""}+${codes.has("BIMI_DNS_ERROR") ? "bimi" : ""}`
  } satisfies ComponentTrust["failureKinds"];
  const dkimErrored = new Set(result.dkim.selectors.filter((s) => s.error !== null).map((s) => s.selector));
  return {
    answers,
    failureKinds,
    mx: answers.mx === "answered",
    spf: answers.spf === "answered",
    dmarc: answers.dmarc === "answered",
    mtaSts: answers.mtaSts === "answered",
    dkimErrored,
    complete: Object.values(answers).every((a) => a === "answered") && dkimErrored.size === 0 && !codes.has("DKIM_DNS_ERROR")
  };
}

/**
 * A component whose lookups keep failing for this many consecutive scans,
 * spanning at least PERSISTENT_FAILURE_MS, is taken at its word: receivers
 * see the same failure, and waiting forever would freeze the stored posture
 * and score for good (a lame third-party include, a policy host that always
 * times out).
 */
export const PERSISTENT_FAILURE_SCANS = 3;
export const PERSISTENT_FAILURE_MS = 24 * 60 * 60 * 1000;

interface EmailStateUpdate {
  state: EmailState;
  /** Components whose old and new values may be compared: answered now, established before, and probed alike. */
  comparable: Set<EmailComponent>;
  /** Fields this scan re-baselined silently: earlier code stored them under other rules, or they are read for the first time. */
  rebaselined?: ReadonlySet<"spfPolicy">;
  /** Finding codes this scan reads for the first time: their presence or absence is a baseline, neither risk_new nor risk_resolved. */
  baselineRisks?: ReadonlySet<string>;
  dkimAdded: string[];
  dkimLost: string[];
}

/** The analyzer's points for one score component, and the points the stored reading awards instead. */
interface PointSubstitution {
  component: string;
  analyzer: number;
  stored: number;
}

/**
 * The score with some components' points replaced. With a breakdown the
 * replaced component's awarded points are taken from it; without one the
 * analyzer's points are assumed, except for a disposable domain, whose score
 * is already capped at 10 over an unknown uncapped total (subtracting from it
 * would drive it to 0), so it is kept.
 */
function substitutedScore(result: EmailScanInput, substitutions: PointSubstitution[]): { score: number; grade: Grade } | null {
  if (substitutions.length === 0) return null;
  const clamp = (value: number): number => Math.max(0, Math.min(100, Math.round(value)));
  const breakdown = result.scoreBreakdown;
  let score: number;
  if (breakdown) {
    let total = breakdown.reduce((sum, b) => sum + b.points, 0);
    for (const s of substitutions) total += s.stored - (breakdown.find((b) => b.component === s.component)?.points ?? s.analyzer);
    score = clamp(total);
    if (breakdown.some((b) => b.component === "disposable")) score = Math.min(score, 10);
  } else if (result.risks.some((r) => r.code === "DISPOSABLE_DOMAIN")) {
    score = result.score;
  } else {
    score = clamp(substitutions.reduce((sum, s) => sum + s.stored - s.analyzer, result.score));
  }
  return { score, grade: gradeFromScore(score) };
}

/**
 * The DMARC points of a scan whose DMARC reading is the domain's own: what
 * the analyzer awarded, or, for a scan recorded without a breakdown, the
 * same points recomputed from its DMARC result.
 */
function ownDmarcPoints(result: EmailScanInput): number {
  const awarded = result.scoreBreakdown?.find((b) => b.component === "dmarc")?.points;
  if (awarded !== undefined) return awarded;
  const dmarc = result.dmarc;
  return scoreDmarc({
    found: dmarc.found,
    lookupFailed: !dmarc.found && result.risks.some((r) => r.code === "DMARC_DNS_ERROR"),
    valid: dmarc.valid === true,
    effectivePolicy: dmarc.effectivePolicy ?? null,
    pct: dmarc.pct ?? 100,
    ruaCount: dmarc.rua?.length ?? 0
  }).points;
}

/**
 * Builds the next stored state from a scan. previousAt is when the previous
 * state was written (the domain's last email scan), which tells whether a
 * stored failure streak had already been accepted when it was written.
 */
function nextEmailState(result: EmailScanInput, previous: EmailState | null, now: number, previousAt: number | null = null): EmailStateUpdate {
  const trust = componentTrust(result);
  const prevDkim = previous?.dkim ?? {};
  // An errored selector with no known key contributed nothing to the stored
  // DKIM risks or score, so the selectors that answered still compare like
  // for like; only an errored selector that holds a known key blocks DKIM.
  // Until DKIM is established, though, any errored selector decides the
  // baseline (it would be scored as holding no key), so it blocks too.
  const dkimBaseline = previous === null || (previous.unknown ?? []).includes("dkim");
  const blockingSelectors = [...trust.dkimErrored].filter((s) => dkimBaseline || Object.hasOwn(prevDkim, s)).sort();
  const answers: Record<LookupComponent, ComponentAnswer> = { ...trust.answers, dkim: blockingSelectors.length > 0 ? "failed" : "answered" };

  const failing: NonNullable<EmailState["failing"]> = { ...(previous?.failing ?? {}) };
  const accepted = new Set<EmailComponent>();
  for (const component of LOOKUP_COMPONENTS) {
    const answer = answers[component];
    if (answer === "answered") {
      delete failing[component];
    } else if (answer === "failed") {
      // A streak only grows while the same lookup keeps failing: a different
      // failure (the MX query itself timing out while a lame backup host has
      // been failing for days) starts a new streak and is held.
      const kind = component === "dkim" ? `selectors:${blockingSelectors.join(",")}` : trust.failureKinds[component];
      const previousStreak = failing[component];
      const streak = previousStreak && previousStreak.kind === kind ? previousStreak : { since: now, scans: 0 };
      failing[component] = { since: streak.since, scans: streak.scans + 1, kind };
      if (streak.scans + 1 >= PERSISTENT_FAILURE_SCANS && now - streak.since >= PERSISTENT_FAILURE_MS) accepted.add(component);
    }
    // A skipped check neither extends nor ends a failure streak.
  }
  const usable = (component: EmailComponent): boolean => {
    if (component === "other") return true;
    if (component === "score") return LOOKUP_COMPONENTS.every((c) => answers[c] === "answered" || accepted.has(c));
    return answers[component] === "answered" || accepted.has(component);
  };

  // DKIM is tracked per selector. A selector counts as missing only when it
  // was probed and answered (or its failures were accepted as persistent).
  const acceptedErrored = new Set(accepted.has("dkim") ? blockingSelectors : []);
  const found = new Set(result.dkim.selectors.filter((s) => s.found && !s.revoked).map((s) => s.selector));
  const checked = new Set(result.dkim.checkedSelectors.filter((s) => !trust.dkimErrored.has(s) || acceptedErrored.has(s)));
  // DKIM risks and the score depend on which selectors were probed: a call
  // that passes a custom selector sees a key a bulk scan does not. They are
  // only compared with a stored value built from the same probes of every
  // known selector; otherwise the new value is a fresh baseline.
  const known = new Set([...Object.keys(prevDkim), ...found]);
  // States stored before probe bases existed came from scans that probed
  // only the default selectors.
  const sameProbes = (basis: string[] | undefined): boolean =>
    basis === undefined ? [...known].every((s) => DEFAULT_DKIM_SELECTORS.includes(s)) : [...known].every((s) => basis.includes(s) === checked.has(s));
  const probesMatch: Partial<Record<EmailComponent, boolean>> = { dkim: sameProbes(previous?.dkimProbed), score: sameProbes(previous?.scoreProbed) };

  // A subdomain whose own _dmarc lookup failed was evaluated against the
  // organizational record, whose policy and findings say nothing about the
  // subdomain's own (possibly weaker) record; an SPF policy behind a failed
  // redirect= target is unknown, not the "none" the analyzer defaults to. The
  // same rules as emailLookupFailures, so the stored posture agrees with the
  // live labels and the score.
  const dmarcPolicyUnknown = dmarcOwnLookupFailed(result.dmarc, result.risks);
  const spfPolicyUnknown = spfPolicyLookupFailed(result.spf, result.risks);

  // States stored by earlier code (no basis) took an accepted failure at a
  // different word: a failed own _dmarc lookup as the organizational
  // record's policy and findings, a failed redirect= target as "none". Those
  // readings are re-baselined silently, not reported as changes. Only a
  // streak that was already accepted when the state was written can have
  // stored them; previousAt is when that was.
  const legacy = previous !== null && previous.basis === undefined;
  const wasAccepted = (component: EmailComponent, kindMatches: (kind: string | undefined) => boolean): boolean => {
    const streak = previous?.failing?.[component];
    return streak !== undefined && kindMatches(streak.kind) && streak.scans >= PERSISTENT_FAILURE_SCANS && (previousAt ?? now) - streak.since >= PERSISTENT_FAILURE_MS;
  };
  // Streaks stored before failure kinds existed carry none; a found record
  // under an accepted failure can only be the organizational fallback. The
  // code that stored the fallback's policy never stored "unknown": a
  // basis-less state that reads "unknown" was written by later code that
  // already kept the subdomain's own DMARC findings, and they stay.
  const legacyFallbackDmarc = legacy && previous?.dmarcPolicy !== "unknown" && wasAccepted("dmarc", (kind) => kind === "own" || (kind === undefined && previous?.dmarcFound === true));
  const legacySpfNone = legacy && spfPolicyUnknown && wasAccepted("spf", (kind) => kind?.startsWith("redirect:") === true);

  const unknown = new Set<EmailComponent>(previous?.unknown ?? []);
  // States stored before spfLookups and mxHosts existed tracked them as part of spf and mx.
  if (unknown.has("spf")) unknown.add("spfLookups");
  if (unknown.has("mx")) unknown.add("mxHosts");
  const dkimEstablished = previous !== null && !unknown.has("dkim");
  // DMARC whose stored reading is not the subdomain's own answer: never
  // answered, or the fallback stored by earlier code.
  const dmarcUnestablished = unknown.has("dmarc") || legacyFallbackDmarc;
  const spfUnestablished = unknown.has("spf");
  // A fallback reading of a failed own lookup says nothing about the
  // subdomain's own record, so even once accepted it never establishes
  // DMARC: the first own answer is then a baseline, not a change (its
  // findings were newly observed, not newly introduced). SPF behind a failed
  // redirect= target is different: the domain's own record answered, so an
  // accepted failure establishes SPF and its own record is compared from
  // then on (a deleted record or a second one must be reported); only what
  // the target holds was never read, and the unread markers defer that.
  const establishes = (component: EmailComponent): boolean => {
    if (!usable(component)) return false;
    if (component === "dmarc") return !(dmarcPolicyUnknown && dmarcUnestablished);
    return true;
  };
  // The unread markers wait on the redirect= target the domain's own record
  // handed its policy to when they were set. A record that no longer does
  // (it is gone, names another target, or has an all of its own, which
  // overrides redirect=) has a policy and include tree of the owner's
  // choosing, not the target's: what it reads is a real change, compared as
  // usual, and the markers are dropped. A scan whose own TXT lookup failed
  // shows no record, which says nothing either way while that failure is
  // held; once it is accepted the store records spf_removed, so the markers
  // go as for a deleted record. Markers stored without a target (before
  // spfUnreadTarget existed) wait on nothing. Inputs recorded without
  // mechanisms are read as having no all.
  const awaitedTarget = previous?.spfUnreadTarget;
  const delegatesToAwaited = awaitedTarget !== undefined && result.spf.redirect === awaitedTarget && !(result.spf.mechanisms ?? []).some((m) => m.type === "all");
  const stillAwaited = delegatesToAwaited || (awaitedTarget !== undefined && !result.spf.found && answers.spf === "failed" && !accepted.has("spf"));
  // The first scan that reads the policy behind that target: the policy and
  // the findings that describe it are newly observed, not newly changed.
  const spfPolicyFirstRead = previous?.spfPolicyUnread === true && delegatesToAwaited && establishes("spf") && !spfPolicyUnknown;
  // The first scan that reads the include tree behind it (spfLookups
  // established while the whole chain answers): what it says about validity,
  // lookup counts and void lookups is newly observed too. It is tracked apart
  // from the policy because an include behind the target can fail in the
  // scan that first reads the policy; the tree is then read once it answers,
  // or once that failure is accepted.
  const spfLookupsFirstRead = previous?.spfLookupsUnread === true && delegatesToAwaited && establishes("spfLookups") && !spfPolicyUnknown;
  const comparable = new Set<EmailComponent>();
  const fromCurrent = new Map<EmailComponent, boolean>();
  for (const component of EMAIL_COMPONENTS) {
    const neverEstablished = !previous || unknown.has(component) || (component === "dmarc" && legacyFallbackDmarc);
    if (establishes(component)) {
      if (!neverEstablished && probesMatch[component] !== false) comparable.add(component);
      unknown.delete(component);
      fromCurrent.set(component, true);
    } else if (neverEstablished) {
      // Never established: track the latest scan, still marked unverified.
      unknown.add(component);
      fromCurrent.set(component, true);
    } else {
      fromCurrent.set(component, false);
    }
  }
  // A redirect= chain with a later hop that stays lame: once that hop's
  // failure is accepted, spfLookups is established from a tree read only up
  // to the awaited target. The first such reading is a baseline too (and
  // re-baselines the score), since the target's part was never read before.
  // It is one-shot: a later hop that stays lame for good would otherwise
  // re-baseline every scan and silence every change to the tree and the
  // score, so once the stored tree holds the target's part (spfLookupsPartial)
  // later partial readings are compared with it. The marker stays until the
  // whole chain answers and the policy is read. The target is matched by
  // name: a top-level include: next to the redirect= answers at the top
  // level too, and says nothing about the target's part.
  const targetAnswered = (target: string | null | undefined): boolean => (result.spf.includeChain ?? []).some((e) => e.parent === null && e.domain === target && e.record !== null);
  const spfLookupsPartialRead =
    previous?.spfLookupsUnread === true && previous.spfLookupsPartial !== true && delegatesToAwaited && establishes("spfLookups") && spfPolicyUnknown && targetAnswered(awaitedTarget);
  if (spfLookupsFirstRead || spfLookupsPartialRead) comparable.delete("spfLookups");
  // The stored score's DMARC points were the fallback's (or, in a legacy
  // state, the organizational record's), or its SPF points those of an
  // unknown policy and an unread include tree: a scan that sets that
  // component's baseline (or first reads that policy or tree) sets the
  // score's too. When that scan cannot rewrite the score (another lookup
  // failed), the next scan that does re-baselines it instead.
  const resetsScore =
    legacyFallbackDmarc ||
    (dmarcUnestablished && establishes("dmarc")) ||
    (spfUnestablished && establishes("spf")) ||
    spfPolicyFirstRead ||
    spfLookupsFirstRead ||
    spfLookupsPartialRead ||
    previous?.scoreRebaseline === true;
  if (resetsScore) comparable.delete("score");
  const current = (component: EmailComponent): boolean => fromCurrent.get(component) === true;
  const prior = previous as EmailState;

  // Null prototype: selectors are caller-supplied strings, and a selector
  // named "constructor" or "__proto__" must be an ordinary key.
  const dkim: Record<string, number> = Object.assign(Object.create(null) as Record<string, number>, prevDkim);
  const dkimAdded: string[] = [];
  const dkimLost: string[] = [];
  for (const selector of found) {
    // A selector first seen without having been probed before (a new custom
    // selector, or one that errored until now) may have held its key all
    // along: that is a baseline, not an addition.
    const probedBefore = previous?.dkimProbed === undefined ? DEFAULT_DKIM_SELECTORS.includes(selector) : previous.dkimProbed.includes(selector);
    if (dkimEstablished && probedBefore && !Object.hasOwn(dkim, selector)) dkimAdded.push(selector);
    dkim[selector] = 0;
  }
  for (const selector of Object.keys(dkim)) {
    if (found.has(selector) || !checked.has(selector)) continue;
    const misses = (dkim[selector] ?? 0) + 1;
    if (misses >= MISSES_BEFORE_REMOVAL) {
      delete dkim[selector];
      dkimLost.push(selector);
    } else {
      dkim[selector] = misses;
    }
  }

  // A persistent failure is taken at its word: exchanges (or an implicit-A
  // fallback) that never answer are, for receivers, exchanges that do not
  // resolve. The analyzer reports the failure as unknown, so the posture
  // risk receivers actually see is added here.
  const acceptedHostRisks: Array<{ code: string; severity: Severity }> = [];
  if (accepted.has("mxHosts") && result.mx.dnsError === null && !result.mx.nullMx) {
    if (result.mx.found && result.mx.records.length > 0 && result.mx.records.every((r) => !r.resolvable)) acceptedHostRisks.push({ code: "MX_ALL_UNRESOLVABLE", severity: "critical" });
    else if (!result.mx.found && !result.mx.usesImplicitA) acceptedHostRisks.push({ code: "MX_MISSING", severity: "high" });
  }
  // The analyzer scores exchanges it could not check as resolving; under the
  // accepted reading they do not resolve, so the score is recomputed with
  // them counted as dangling. This applies to any lame exchange, not only an
  // all-lame set: a lame backup next to a working MX must cost what the same
  // posture with an NXDOMAIN backup costs.
  const substitutions: PointSubstitution[] = [];
  const records = result.mx.records ?? [];
  if (accepted.has("mxHosts") && result.mx.dnsError === null && !result.mx.nullMx && result.mx.found && records.some((r) => r.lookupFailed)) {
    // What the analyzer awarded (lame exchanges counted as resolving) and
    // what the accepted reading awards (lame exchanges counted as dangling).
    const analyzerPoints = mxSetPoints(records.length, records.filter((r) => !r.resolvable && !r.lookupFailed).length);
    substitutions.push({ component: "mx", analyzer: analyzerPoints, stored: mxSetPoints(records.length, records.filter((r) => !r.resolvable).length) });
  }

  // The subdomain's own DMARC points, from the latest scan in which its own
  // DMARC answered (or its failure was accepted as a reading). While only the
  // fallback answers, the stored score keeps them instead of the fallback's
  // p=none points: an unknown policy neither raises nor lowers it.
  let dmarcPoints = establishes("dmarc") && !dmarcPolicyUnknown ? ownDmarcPoints(result) : previous?.dmarcPoints;
  let rebaselineScore = false;
  if (current("score") && dmarcPolicyUnknown) {
    if (typeof previous?.dmarcPoints === "number") {
      substitutions.push({ component: "dmarc", analyzer: DMARC_POLICY_UNKNOWN_POINTS, stored: previous.dmarcPoints });
    } else if (previous !== null && previous.dmarcPoints === undefined && !dmarcUnestablished) {
      // The stored score holds own DMARC points this state never recorded
      // (it predates dmarcPoints), so they cannot be kept: the score takes
      // the fallback's, re-baselined silently once.
      rebaselineScore = true;
      dmarcPoints = null;
    }
  }
  // Earlier scoring rules gave a void-lookup or circular-include permerror
  // full SPF points. The rule change alone moves the score only when both
  // the stored score and this one come from a permerror scan, so only that
  // comparison is re-baselined silently; a permerror that first appears now
  // is a real drop. Both findings are high, so stored risks carry them, but
  // stored risks follow spfLookups while the score only moves in a scan in
  // which every lookup answered: after the first post-upgrade scan they need
  // not describe the stored score. So that scan (the state has no basis yet)
  // decides once, from the risks stored with the score: without a permerror
  // the rule change cannot have touched it, and it counts as scored under
  // the current rules from then on. A scoreRules still missing after that
  // scan means an old-rules permerror score, re-baselined by the first scan
  // that rewrites it while carrying a permerror.
  const permerror = (risks: ReadonlyArray<{ code: string }>): boolean => risks.some((r) => r.code === "SPF_VOID_LOOKUPS" || r.code === "SPF_CIRCULAR_INCLUDE");
  const legacyRules = previous !== null && previous.scoreRules === undefined;
  const rulesUnaffected = legacyRules && previous.basis === undefined && !permerror(previous.risks);
  if (legacyRules && !rulesUnaffected && permerror(result.risks)) rebaselineScore = true;
  if (rebaselineScore) comparable.delete("score");
  const storedScore = substitutedScore(result, substitutions);

  // Nor are the fallback record's findings the subdomain's: its own DMARC
  // risks stay as last known, and the organizational record's are not
  // taken. Likewise the findings that only describe an SPF policy that is
  // now unknown. A legacy state's DMARC risks were the fallback's: dropped.
  const keepsLastKnown = (code: string): boolean => (dmarcPolicyUnknown && riskComponent(code) === "dmarc") || (spfPolicyUnknown && SPF_POLICY_RISKS.has(code));
  const riskCurrent = (code: string): boolean => current(riskComponent(code)) && !keepsLastKnown(code);
  const priorRisks = (previous?.risks ?? []).filter((r) => !(legacyFallbackDmarc && riskComponent(r.code) === "dmarc"));
  const risks = [
    ...acceptedHostRisks,
    ...highRisks(result.risks).filter((r) => riskCurrent(r.code) && !acceptedHostRisks.some((a) => a.code === r.code)),
    ...priorRisks.filter((r) => !riskCurrent(r.code))
  ].sort((a, b) => a.code.localeCompare(b.code));

  const spfPolicy = current("spf") ? (spfPolicyUnknown ? "unknown" : result.spf.allPolicy) : prior.spfPolicy;
  const dmarcPolicy = current("dmarc") ? (result.dmarc.found ? (dmarcPolicyUnknown ? "unknown" : result.dmarc.effectivePolicy) : null) : prior.dmarcPolicy;
  // The policy last actually read is carried while the stored one is
  // unknown. Nothing is carried from a reading that was never the domain's
  // own (never established, or what earlier code stored for an accepted
  // failure) or from a domain that had no SPF record.
  const spfPolicyKnown =
    spfPolicy === "unknown" && previous !== null && !spfUnestablished && !legacySpfNone
      ? previous.spfPolicy === "unknown"
        ? previous.spfPolicyKnown
        : previous.spfFound
          ? previous.spfPolicy
          : undefined
      : undefined;
  const dmarcPolicyKnown = dmarcPolicy === "unknown" && previous !== null && !dmarcUnestablished ? (previous.dmarcPolicy === "unknown" ? previous.dmarcPolicyKnown : previous.dmarcPolicy) : undefined;
  // Set by the scan that establishes SPF from an unknown policy (the policy
  // and the include tree behind the redirect= target were never read whole),
  // with that target. Each is carried until its first read, while the record
  // still delegates to the target or its own failed lookup is held (and, for
  // the policy, it stays unknown).
  const marksUnread = spfPolicy === "unknown" && spfUnestablished && establishes("spf");
  const spfPolicyUnread = marksUnread || (previous?.spfPolicyUnread === true && stillAwaited && spfPolicy === "unknown") ? true : undefined;
  const spfLookupsUnread = marksUnread || (previous?.spfLookupsUnread === true && stillAwaited && !spfLookupsFirstRead) ? true : undefined;
  // Whether the stored tree already holds the target's part. The marking scan
  // stores it when the target answered there (only a later hop failed): that
  // scan was the tree's and the score's first baseline, so the next partial
  // reading is compared with it, not another baseline. Otherwise the first
  // partial reading sets it, and it is carried with the tree marker.
  const spfLookupsPartial =
    spfLookupsUnread && (marksUnread ? current("spfLookups") && targetAnswered(result.spf.redirect) : spfLookupsPartialRead || previous?.spfLookupsPartial === true) ? true : undefined;
  const spfUnreadTarget = marksUnread ? (result.spf.redirect ?? undefined) : spfPolicyUnread || spfLookupsUnread ? awaitedTarget : undefined;

  const probed = [...checked].sort();
  return {
    state: {
      score: current("score") ? (storedScore?.score ?? result.score) : prior.score,
      grade: current("score") ? (storedScore?.grade ?? result.grade) : prior.grade,
      mxFound: current("mx") ? result.mx.found : prior.mxFound,
      nullMx: current("mx") ? result.mx.nullMx : prior.nullMx,
      mxProvider: current("mx") ? result.mx.provider : prior.mxProvider,
      spfFound: current("spf") ? result.spf.found : prior.spfFound,
      spfValid: current("spfLookups") ? result.spf.valid : prior.spfValid,
      spfPolicy,
      dmarcFound: current("dmarc") ? result.dmarc.found : prior.dmarcFound,
      dmarcPolicy,
      dkim,
      mtaStsMode: current("mtaSts") ? (result.mtaSts.policy.fetched ? result.mtaSts.policy.mode : null) : prior.mtaStsMode,
      risks,
      unknown: [...unknown].sort(),
      failing,
      dkimProbed: current("dkim") ? probed : previous?.dkimProbed,
      scoreProbed: current("score") ? probed : previous?.scoreProbed,
      dmarcPoints,
      basis: STATE_BASIS,
      scoreRules: current("score") || rulesUnaffected ? SCORE_RULES : previous?.scoreRules,
      spfPolicyKnown,
      dmarcPolicyKnown,
      spfPolicyUnread,
      spfLookupsUnread,
      spfUnreadTarget,
      spfLookupsPartial,
      scoreRebaseline: resetsScore && !current("score") ? true : undefined
    },
    comparable,
    rebaselined: new Set<"spfPolicy">(legacySpfNone || spfPolicyFirstRead ? ["spfPolicy"] : []),
    baselineRisks: spfPolicyFirstRead ? SPF_POLICY_RISKS : undefined,
    dkimAdded: dkimAdded.sort(),
    dkimLost: dkimLost.sort()
  };
}

export function toEmailSnapshot(state: EmailState): EmailSnapshot {
  const unknown = new Set<EmailComponent>(state.unknown ?? []);
  return {
    score: unknown.has("score") ? null : state.score,
    grade: unknown.has("score") ? null : state.grade,
    mxFound: state.mxFound,
    nullMx: state.nullMx,
    mxProvider: state.mxProvider,
    spfFound: state.spfFound,
    spfValid: state.spfValid,
    spfPolicy: state.spfPolicy,
    dmarcFound: state.dmarcFound,
    dmarcPolicy: state.dmarcPolicy,
    dkimSelectors: Object.entries(state.dkim)
      .filter(([, misses]) => misses === 0)
      .map(([selector]) => selector)
      .sort(),
    mtaStsMode: state.mtaStsMode,
    highRisks: state.risks.filter((r) => !unknown.has(riskComponent(r.code))).map((r) => r.code),
    unverified: [...unknown].sort(),
    lookupsFailing: (Object.keys(state.failing ?? {}) as EmailComponent[]).sort()
  };
}

/** Compares two email states, component by component, and describes every meaningful difference. */
export function diffEmailState(domain: string, before: EmailState, update: EmailStateUpdate, at: number): DomainChange[] {
  const after = update.state;
  const comparable = update.comparable;
  const changes: DomainChange[] = [];
  const push = (change: string, subject: string | null, oldValue: unknown, newValue: unknown, severity: Severity): void => {
    const fmt = (v: unknown): string | null => (v === null || v === undefined ? null : String(v));
    changes.push({ domain, kind: "email", change, subject, oldValue: fmt(oldValue), newValue: fmt(newValue), severity, at });
  };

  if (comparable.has("mx")) {
    // Moving to (or off) a Null MX is one deliberate change, reported once.
    if (before.nullMx !== after.nullMx) push("null_mx", "mx", before.nullMx, after.nullMx, after.nullMx ? "high" : "info");
    else if (before.mxFound !== after.mxFound) push(after.mxFound ? "mx_added" : "mx_removed", "mx", before.mxFound, after.mxFound, after.mxFound ? "info" : "critical");
    else if (after.mxFound && before.mxProvider !== after.mxProvider) push("mx_provider", "mx", before.mxProvider, after.mxProvider, "medium");
  }

  if (comparable.has("spf")) {
    if (before.spfFound !== after.spfFound) {
      push(after.spfFound ? "spf_added" : "spf_removed", "spf", before.spfFound, after.spfFound, after.spfFound ? "info" : "high");
    } else if (after.spfFound && before.spfPolicy !== after.spfPolicy && !update.rebaselined?.has("spfPolicy")) {
      // Away from unknown, against the policy last read; with none read, it is no weakening.
      const from = before.spfPolicy === "unknown" ? before.spfPolicyKnown : before.spfPolicy;
      const weaker = from !== undefined && (SPF_POLICY_RANK[after.spfPolicy] ?? 0) < (SPF_POLICY_RANK[from] ?? 0);
      push("spf_policy", "spf", before.spfPolicy, after.spfPolicy, weaker ? "high" : "info");
    }
  }
  // Validity depends on the include tree, which is compared separately.
  if (comparable.has("spf") && comparable.has("spfLookups") && before.spfFound && after.spfFound && before.spfValid !== after.spfValid) {
    push(after.spfValid ? "spf_fixed" : "spf_broken", "spf", before.spfValid, after.spfValid, after.spfValid ? "info" : "high");
  }

  if (comparable.has("dmarc")) {
    if (before.dmarcFound !== after.dmarcFound) {
      push(after.dmarcFound ? "dmarc_added" : "dmarc_removed", "dmarc", before.dmarcPolicy, after.dmarcPolicy, after.dmarcFound ? "info" : "high");
    } else if (after.dmarcFound && before.dmarcPolicy !== after.dmarcPolicy) {
      const from = before.dmarcPolicy === "unknown" ? before.dmarcPolicyKnown : before.dmarcPolicy;
      const weaker = from !== undefined && (DMARC_POLICY_RANK[after.dmarcPolicy ?? ""] ?? 0) < (DMARC_POLICY_RANK[from ?? ""] ?? 0);
      push("dmarc_policy", "dmarc", before.dmarcPolicy, after.dmarcPolicy, weaker ? "high" : "info");
    }
  }

  for (const selector of update.dkimAdded) push("dkim_added", selector, null, selector, "info");
  // Selectors still pending removal (one miss) are not "remaining": the key is at risk either way.
  const live = Object.values(after.dkim).filter((misses) => misses === 0).length;
  for (const selector of update.dkimLost) push("dkim_lost", selector, selector, null, live === 0 ? "high" : "medium");

  if (comparable.has("mtaSts") && before.mtaStsMode !== after.mtaStsMode) {
    const weaker = (MTA_STS_MODE_RANK[after.mtaStsMode ?? ""] ?? 0) < (MTA_STS_MODE_RANK[before.mtaStsMode ?? ""] ?? 0);
    push("mta_sts_mode", "mta-sts", before.mtaStsMode, after.mtaStsMode, weaker ? "medium" : "info");
  }

  const beforeRisks = new Set(before.risks.map((r) => r.code));
  const afterRisks = new Set(after.risks.map((r) => r.code));
  const comparableRisk = (code: string): boolean => comparable.has(riskComponent(code)) && !update.baselineRisks?.has(code);
  for (const risk of after.risks) {
    if (comparableRisk(risk.code) && !beforeRisks.has(risk.code)) push("risk_new", risk.code, null, risk.code, risk.severity);
  }
  for (const risk of before.risks) {
    if (comparableRisk(risk.code) && !afterRisks.has(risk.code)) push("risk_resolved", risk.code, risk.code, null, "info");
  }

  if (comparable.has("score")) {
    if (after.score <= before.score - 10) push("score_drop", "score", before.score, after.score, "medium");
    else if (after.score >= before.score + 10) push("score_rise", "score", before.score, after.score, "info");
  }
  return changes;
}

interface DomainRow {
  domain: string;
  first_seen: number;
  tech_scanned_at: number | null;
  tech_ok_at: number | null;
  email_scanned_at: number | null;
  email_state: string | null;
}

interface TechRow {
  tech_id: string;
  name: string;
  category: string;
  version: string | null;
  implied: number;
  first_seen: number;
  last_seen: number;
  missed: number;
  active: number;
  removed_at: number | null;
}

interface ChangeRow {
  id: number;
  domain: string;
  kind: ScanKind;
  change: string;
  subject: string | null;
  old_value: string | null;
  new_value: string | null;
  severity: Severity;
  at: number;
}

export function toPublicChange(row: DomainChange): PublicChange {
  return { kind: row.kind, change: row.change, subject: row.subject, oldValue: row.oldValue, newValue: row.newValue, severity: row.severity, at: new Date(row.at).toISOString() };
}

export class ScanStore {
  private readonly retentionMs: number;

  constructor(
    private readonly db: Database,
    options: ScanStoreOptions
  ) {
    this.retentionMs = options.retentionDays * 24 * 60 * 60 * 1000;
  }

  private touchDomain(domain: string, now: number): DomainRow {
    this.db.prepare("INSERT INTO domains (domain, first_seen) VALUES (?, ?) ON CONFLICT(domain) DO NOTHING").run(domain, now);
    return this.db.prepare("SELECT * FROM domains WHERE domain = ?").get(domain) as unknown as DomainRow;
  }

  private insertScan(domain: string, kind: ScanKind, source: ScanSource, now: number, ok: boolean, score: number | null, grade: string | null, summary: unknown): void {
    this.db
      .prepare("INSERT INTO scans (domain, kind, source, scanned_at, ok, score, grade, summary) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
      .run(domain, kind, source, now, ok ? 1 : 0, score, grade, JSON.stringify(summary));
  }

  private insertChanges(changes: DomainChange[]): void {
    const statement = this.db.prepare("INSERT INTO changes (domain, kind, change, subject, old_value, new_value, severity, at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
    for (const change of changes) {
      const info = statement.run(change.domain, change.kind, change.change, change.subject, change.oldValue, change.newValue, change.severity, change.at);
      change.id = Number(info.lastInsertRowid);
    }
  }

  /**
   * Records a tech-stack scan and returns the technology changes it revealed.
   * The first successful scan of a domain is a baseline and reports none.
   */
  recordTech(result: TechScanInput, source: ScanSource, now: number = Date.now()): DomainChange[] {
    const domain = siteKey(result.domain);
    const usable = result.fetch.ok && !result.blocked.blocked;
    const summary = {
      ok: result.fetch.ok,
      status: result.fetch.status,
      finalHost: result.fetch.finalHost,
      blocked: result.blocked.blocked,
      blockedBy: result.blocked.vendor,
      truncated: result.fetch.truncated,
      error: result.fetch.error?.kind ?? null,
      technologies: result.technologies.map((t) => ({ id: t.id, name: t.name, category: t.category, version: t.version, implied: t.implied }))
    };
    return transaction(this.db, () => {
      const row = this.touchDomain(domain, now);
      this.insertScan(domain, "tech", source, now, usable, result.security.score, result.security.grade, summary);
      this.db.prepare("UPDATE domains SET tech_scanned_at = ? WHERE domain = ?").run(now, domain);
      if (!usable) return [];

      const baseline = row.tech_ok_at === null;
      const existing = new Map((this.db.prepare("SELECT * FROM domain_tech WHERE domain = ?").all(domain) as unknown as TechRow[]).map((r) => [r.tech_id, r]));
      const detected = new Map(result.technologies.map((t) => [t.id, t]));
      const changes: DomainChange[] = [];
      const insert = this.db.prepare(
        "INSERT INTO domain_tech (domain, tech_id, name, category, version, implied, first_seen, last_seen, missed, active, removed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 1, NULL)"
      );
      const refresh = this.db.prepare(
        "UPDATE domain_tech SET name = ?, category = ?, version = COALESCE(?, version), implied = ?, last_seen = ?, missed = 0, active = 1, removed_at = NULL WHERE domain = ? AND tech_id = ?"
      );
      for (const tech of detected.values()) {
        const previous = existing.get(tech.id);
        if (!previous) {
          insert.run(domain, tech.id, tech.name, tech.category, tech.version, tech.implied ? 1 : 0, now, now);
        } else {
          refresh.run(tech.name, tech.category, tech.version, tech.implied ? 1 : 0, now, domain, tech.id);
        }
        if (!baseline && (!previous || previous.active === 0)) {
          changes.push({
            domain,
            kind: "tech",
            change: "tech_added",
            subject: tech.id,
            oldValue: null,
            newValue: tech.version ? `${tech.name} ${tech.version}` : tech.name,
            severity: "info",
            at: now
          });
        }
      }
      // A truncated body may simply have stopped before a late tag, so it
      // can add technologies but never count toward removing them.
      if (!result.fetch.truncated) {
        const miss = this.db.prepare("UPDATE domain_tech SET missed = ? WHERE domain = ? AND tech_id = ?");
        const remove = this.db.prepare("UPDATE domain_tech SET missed = ?, active = 0, removed_at = ? WHERE domain = ? AND tech_id = ?");
        for (const previous of existing.values()) {
          if (previous.active === 0 || detected.has(previous.tech_id)) continue;
          const misses = previous.missed + 1;
          if (misses >= MISSES_BEFORE_REMOVAL) {
            remove.run(misses, now, domain, previous.tech_id);
            changes.push({ domain, kind: "tech", change: "tech_removed", subject: previous.tech_id, oldValue: previous.name, newValue: null, severity: "info", at: now });
          } else {
            miss.run(misses, domain, previous.tech_id);
          }
        }
      }
      this.db.prepare("UPDATE domains SET tech_ok_at = ? WHERE domain = ?").run(now, domain);
      // The reverse lookup answers only from what the crawler itself saw, so
      // customers' calls, bulk jobs and monitor scans never surface there.
      if (source === "crawl") this.recordCrawlTech(domain, result, now);
      this.insertChanges(changes);
      return changes;
    });
  }

  /** Maintains crawl_tech (the reverse lookup's own state) with the same miss damping as domain_tech. */
  private recordCrawlTech(domain: string, result: TechScanInput, now: number): void {
    const existing = new Map(
      (this.db.prepare("SELECT tech_id, missed, active FROM crawl_tech WHERE domain = ?").all(domain) as unknown as Array<{ tech_id: string; missed: number; active: number }>).map((r) => [
        r.tech_id,
        r
      ])
    );
    const detected = new Map(result.technologies.map((t) => [t.id, t]));
    const upsert = this.db.prepare(
      "INSERT INTO crawl_tech (domain, tech_id, version, first_seen, last_seen) VALUES (?, ?, ?, ?, ?) ON CONFLICT(domain, tech_id) DO UPDATE SET version = COALESCE(excluded.version, version), last_seen = excluded.last_seen, missed = 0, active = 1, removed_at = NULL"
    );
    for (const tech of detected.values()) upsert.run(domain, tech.id, tech.version, now, now);
    if (!result.fetch.truncated) {
      for (const previous of existing.values()) {
        if (previous.active === 0 || detected.has(previous.tech_id)) continue;
        const misses = previous.missed + 1;
        if (misses >= MISSES_BEFORE_REMOVAL)
          this.db.prepare("UPDATE crawl_tech SET missed = ?, active = 0, removed_at = ? WHERE domain = ? AND tech_id = ?").run(misses, now, domain, previous.tech_id);
        else this.db.prepare("UPDATE crawl_tech SET missed = ? WHERE domain = ? AND tech_id = ?").run(misses, domain, previous.tech_id);
      }
    }
    this.db.prepare("UPDATE crawl_targets SET tech_ok_at = ? WHERE domain = ?").run(now, domain);
  }

  /**
   * Records an email scan and returns the posture changes it revealed. Each
   * component (MX, SPF, DMARC, DKIM selector, MTA-STS) only updates, and is
   * only compared, when its own lookups answered; a component whose lookup
   * failed keeps its last known value until the failure is accepted as
   * persistent (PERSISTENT_FAILURE_SCANS scans over PERSISTENT_FAILURE_MS).
   * Only a scan whose lookups all answered, or whose failures were all
   * accepted, may move the score; while a subdomain's own _dmarc lookup
   * fails, the score keeps the subdomain's last known DMARC points.
   */
  recordEmail(result: EmailScanInput, source: ScanSource, now: number = Date.now()): DomainChange[] {
    const domain = siteKey(result.domain);
    const trust = componentTrust(result);
    return transaction(this.db, () => {
      const row = this.touchDomain(domain, now);
      const previous = row.email_state ? (JSON.parse(row.email_state) as EmailState) : null;
      const update = nextEmailState(result, previous, now, row.email_scanned_at);
      const untrusted: string[] = (Object.entries(trust.answers) as Array<[string, ComponentAnswer]>).filter(([, answer]) => answer !== "answered").map(([component]) => component);
      if (trust.dkimErrored.size > 0) untrusted.push("dkim");
      this.insertScan(domain, "email", source, now, trust.complete, result.score, result.grade, { ...toEmailSnapshot(update.state), complete: trust.complete, untrusted });
      this.db.prepare("UPDATE domains SET email_scanned_at = ? WHERE domain = ?").run(now, domain);
      const changes = previous ? diffEmailState(domain, previous, update, now) : [];
      this.db.prepare("UPDATE domains SET email_state = ? WHERE domain = ?").run(JSON.stringify(update.state), domain);
      this.insertChanges(changes);
      return changes;
    });
  }

  /**
   * DKIM selectors known to hold a key for the domain. Scheduled and bulk
   * scans probe them alongside the defaults, so a selector a caller once
   * named keeps being checked and compared like for like.
   */
  knownDkimSelectors(domainInput: string, limit = 20): string[] {
    const row = this.db.prepare("SELECT email_state FROM domains WHERE domain = ?").get(siteKey(domainInput)) as { email_state: string | null } | undefined;
    if (!row?.email_state) return [];
    const state = JSON.parse(row.email_state) as EmailState;
    return Object.keys(state.dkim).sort().slice(0, limit);
  }

  /** Everything stored about a domain: current technologies, email posture, recent changes and scans. */
  history(domainInput: string, changesLimit = 50): DomainHistory {
    const domain = siteKey(domainInput);
    const row = this.db.prepare("SELECT * FROM domains WHERE domain = ?").get(domain) as unknown as DomainRow | undefined;
    if (!row) {
      return { domain, known: false, firstSeen: null, lastTechScanAt: null, lastEmailScanAt: null, technologies: [], email: null, changes: [], recentScans: [] };
    }
    const techs = this.db.prepare("SELECT * FROM domain_tech WHERE domain = ? ORDER BY active DESC, category ASC, name ASC").all(domain) as unknown as TechRow[];
    const changes = this.db.prepare("SELECT * FROM changes WHERE domain = ? ORDER BY at DESC, id DESC LIMIT ?").all(domain, Math.max(1, Math.min(500, changesLimit))) as unknown as ChangeRow[];
    const scans = this.db
      .prepare("SELECT kind, source, scanned_at, ok, score, grade FROM scans WHERE domain = ? ORDER BY scanned_at DESC, id DESC LIMIT ?")
      .all(domain, RECENT_SCANS) as unknown as Array<{ kind: ScanKind; source: ScanSource; scanned_at: number; ok: number; score: number | null; grade: string | null }>;
    return {
      domain,
      known: true,
      firstSeen: iso(row.first_seen),
      lastTechScanAt: iso(row.tech_scanned_at),
      lastEmailScanAt: iso(row.email_scanned_at),
      technologies: techs.map((t) => ({
        id: t.tech_id,
        name: t.name,
        category: t.category,
        version: t.version,
        implied: t.implied === 1,
        active: t.active === 1,
        firstSeen: iso(t.first_seen) as string,
        lastSeen: iso(t.last_seen) as string,
        removedAt: iso(t.removed_at)
      })),
      email: row.email_state ? toEmailSnapshot(JSON.parse(row.email_state) as EmailState) : null,
      changes: changes.map((c) =>
        toPublicChange({ domain: c.domain, kind: c.kind, change: c.change, subject: c.subject, oldValue: c.old_value, newValue: c.new_value, severity: c.severity, at: c.at })
      ),
      recentScans: scans.map((s) => ({ kind: s.kind, source: s.source, at: iso(s.scanned_at) as string, ok: s.ok === 1, score: s.score, grade: s.grade }))
    };
  }

  /**
   * Deletes at most `limit` expired rows per table, each table in its own
   * short transaction, so pruning a large backlog never holds the write lock
   * for long (other processes' writes only wait BUSY_TIMEOUT_MS).
   */
  pruneBatch(now: number = Date.now(), limit = PRUNE_BATCH): { scans: number; changes: number; technologies: number } {
    const cutoff = now - this.retentionMs;
    const run = (sql: string): number => Number(transaction(this.db, () => this.db.prepare(sql).run(cutoff, limit).changes));
    return {
      scans: run("DELETE FROM scans WHERE id IN (SELECT id FROM scans WHERE scanned_at < ? LIMIT ?)"),
      changes: run("DELETE FROM changes WHERE id IN (SELECT id FROM changes WHERE at < ? LIMIT ?)"),
      technologies:
        run("DELETE FROM domain_tech WHERE rowid IN (SELECT rowid FROM domain_tech WHERE active = 0 AND removed_at < ? LIMIT ?)") +
        run("DELETE FROM crawl_tech WHERE rowid IN (SELECT rowid FROM crawl_tech WHERE active = 0 AND removed_at < ? LIMIT ?)")
    };
  }

  /** Prunes in batches, yielding to the event loop between them; stops early when shouldStop() turns true. */
  async pruneAsync(now: number = Date.now(), shouldStop: () => boolean = () => false): Promise<{ scans: number; changes: number; technologies: number }> {
    const total = { scans: 0, changes: 0, technologies: 0 };
    while (!shouldStop()) {
      const batch = this.pruneBatch(now);
      total.scans += batch.scans;
      total.changes += batch.changes;
      total.technologies += batch.technologies;
      if (batch.scans < PRUNE_BATCH && batch.changes < PRUNE_BATCH && batch.technologies < PRUNE_BATCH) break;
      await new Promise((resolve) => setImmediate(resolve));
    }
    return total;
  }

  /** Synchronous prune of everything expired, in batches. */
  prune(now: number = Date.now()): { scans: number; changes: number; technologies: number } {
    const total = { scans: 0, changes: 0, technologies: 0 };
    for (;;) {
      const batch = this.pruneBatch(now);
      total.scans += batch.scans;
      total.changes += batch.changes;
      total.technologies += batch.technologies;
      if (batch.scans < PRUNE_BATCH && batch.changes < PRUNE_BATCH && batch.technologies < PRUNE_BATCH) return total;
    }
  }

  stats(): { domains: number; scans: number; activeTechnologies: number } {
    const count = (sql: string): number => Number((this.db.prepare(sql).get() as { n: number }).n);
    return {
      domains: count("SELECT COUNT(*) AS n FROM domains"),
      scans: count("SELECT COUNT(*) AS n FROM scans"),
      activeTechnologies: count("SELECT COUNT(*) AS n FROM domain_tech WHERE active = 1")
    };
  }
}
