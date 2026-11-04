/**
 * Usage tracker: per-principal call counts, per-tool counters, prepaid credit
 * balances, redeemed payment ids and (when no shared database holds them) x402
 * settlement markers, persisted atomically to a JSON file with debounced
 * writes. Runs fully in memory when no file path is configured.
 *
 * Redeemed payment ids are the only double-spend guard for both payment
 * providers, so they are retained by age (long past any provider's dispute
 * window) rather than evicted by insertion order: a payment reference that
 * is old enough to have been forgotten here is also too old to be redeemed
 * at all, which the payment layer enforces independently. A very large
 * safety bound (MAX_REDEEMED_PAYMENTS) is the one exception; crossing it
 * drops the oldest ids early and is logged.
 */

import { randomBytes } from "node:crypto";
import { mkdir, readdir, readFile, rename, unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import { logger } from "../logger.js";
import { isLockContention } from "../store/db.js";

export interface PrincipalUsage {
  principalId: string;
  plan: string;
  label: string;
  totalCalls: number;
  totalCredits: number;
  byTool: Record<string, number>;
  creditsRemaining: number | null;
  firstSeen: string;
  lastSeen: string;
}

interface RedeemedPaymentRecord {
  id: string;
  at: string;
}

/**
 * Version 3 added the settlement markers: without a shared database they
 * lived only in memory, so a restart forgot a payment whose settle never
 * answered and the session its 502 handed out could be asked to pay again.
 * Versions 1 and 2 still load.
 */
interface UsageFile {
  version: 3;
  updatedAt: string;
  principals: Record<string, PrincipalUsage>;
  redeemedPayments: RedeemedPaymentRecord[];
  /** Unfinished x402 settlements when no shared database holds them (STACKDNS_DB_FILE=none). */
  settlements: SettlementMarker[];
}

/**
 * Where an x402 settlement stands. 'settling': a /settle request may be in
 * flight. 'unknown': it went out and its outcome was never learned.
 * 'settled': the transfer moved (tx is known) but its credits may not be
 * recorded yet.
 */
export type SettlementState = "settling" | "unknown" | "settled";

/** The payment a settlement marker is for, and the principal its credits belong to. */
export interface SettlementStart {
  paymentId: string;
  principalId: string;
  label: string;
  credits: number;
  /**
   * The authorization's identity (x402AuthorizationIdentity: `<payer>.<nonce>` for an EIP-3009 authorization,
   * the nonce alone when the payer was unknown, else a hash of its signature), which qualifies the transaction
   * in the double-spend guard id. Kept so that an operator can record an unconfirmed payment later without the
   * payload (see src/cli/settlements.ts). Markers written before round 8 have none.
   */
  identity?: string | null;
}

/**
 * A durable "money may have moved" marker for one x402 payment, written
 * before /settle is called. Every process sharing the database (and a
 * restarted one) reads it, so a retry that lands elsewhere is never answered
 * with a fresh payment demand.
 */
export interface SettlementMarker extends SettlementStart {
  state: SettlementState;
  /**
   * The settled transaction. Since round 8 it is qualified by the authorization's identity
   * (`<tx>:<identity>`), so `x402_<tx>` is the double-spend guard id for every version of the code that
   * adopts the marker; markers written before carry the bare transaction.
   */
  tx: string | null;
  receipt: Record<string, unknown> | null;
  identity: string | null;
  at: number;
  updatedAt: number;
}

/**
 * Guard ids that block a grant by their shape instead of by name: every recorded id made of `prefix`, a payer
 * part of lowercase letters and digits, and `suffix`. An x402 authorization whose payer is not known is recorded
 * under its nonce alone, and must yield to the payer-qualified guards `x402_<tx>:<payer>.<nonce>` of the same
 * transaction and nonce (see x402TransactionGuard). Matching them by shape finds every such guard, whichever
 * process, code version or tool wrote it, where a companion record would have to be written by each of them.
 * The prefix ends with ':', so its members are one range of the redeemed ids' primary key.
 */
export interface GuardFamily {
  prefix: string;
  suffix: string;
  /**
   * Only members whose payer part is not a 20-byte address (40 lowercase hex digits). A payer-qualified
   * identity yields to these: a guard a resumed marker or the CLI wrote with a payer part stored before payers
   * were normalized (a hashed CAIP-10 id, say) is as good as unknown, and may be the same authorization. Two
   * 20-byte payers whose authorizations reuse a nonce in one batch are two payments and never match.
   */
  unknownPayersOnly?: boolean;
}

/** The one form a normalized payer part takes (x402PayerIdentity in payments.ts). */
const ADDRESS_PAYER_PART = /^[0-9a-f]{40}$/;

/**
 * Whether a marker's tx belongs to the transaction (lowercase): the transaction itself, as markers written before
 * round 8 store it, or the transaction qualified by an authorization identity (`<tx>:<identity>`).
 */
function settledTxOf(markerTx: string, transaction: string): boolean {
  const tx = markerTx.toLowerCase();
  return tx === transaction || tx.startsWith(`${transaction}:`);
}

/** Whether a redeemed id belongs to the family (see GuardFamily). */
export function inGuardFamily(id: string, family: GuardFamily): boolean {
  if (id.length <= family.prefix.length + family.suffix.length || !id.startsWith(family.prefix) || !id.endsWith(family.suffix)) return false;
  const payer = id.slice(family.prefix.length, id.length - family.suffix.length);
  return /^[0-9a-z]+$/.test(payer) && !(family.unknownPayersOnly === true && ADDRESS_PAYER_PART.test(payer));
}

/** Shared, database-backed credit balances, redeemed payment ids and x402 settlement markers (implemented by CreditLedger). */
export interface SharedLedger {
  balance(principalId: string): number | null;
  consume(principalId: string, credits: number): boolean;
  add(principalId: string, plan: string, label: string, credits: number): number;
  isRedeemed(paymentId: string, retentionMs: number, now?: number): boolean;
  /** Like isRedeemed, for any id of the family. */
  isRedeemedFamily(family: GuardFamily, retentionMs: number, now?: number): boolean;
  markRedeemed(paymentId: string, at?: number): boolean;
  /**
   * Records every id and grants the credits in one transaction. Grants nothing (and returns false) when any id
   * was already redeemed, any blockedBy id is, or any id of blockedByFamily is; the ids are recorded either way.
   */
  redeemAndCredit(ids: readonly string[], principalId: string, plan: string, label: string, credits: number, at?: number, blockedBy?: readonly string[], blockedByFamily?: GuardFamily | null): boolean;
  pruneRedeemed(retentionMs: number, now?: number): number;
  importOnce(source: { balances: Array<{ principalId: string; plan: string; label: string; balance: number }>; redeemed: Array<{ id: string; at: number }> }): boolean;
  /** Inserts a 'settling' marker; false when one already exists (another request or process owns the payment). */
  beginSettlement(start: SettlementStart, at: number): boolean;
  /** Moves an 'unknown' (or stale 'settling') marker back to 'settling', only if it is still exactly as seen; false when another process got there first. */
  resumeSettlement(seen: SettlementMarker, at: number): boolean;
  /** Moves a marker's updated_at forward without changing its state, only if it is still exactly as seen (one re-verification per window). */
  touchSettlement(seen: SettlementMarker, at: number): boolean;
  /** Updates a marker's state; tx, receipt and identity are kept when not given, and a 'settled' marker is never moved back. */
  markSettlement(paymentId: string, state: SettlementState, tx: string | null, receipt: Record<string, unknown> | null, at: number): void;
  getSettlement(paymentId: string): SettlementMarker | null;
  /** Deletes the marker; with ifUpdatedAt, only while it is still the version last written at that time. */
  endSettlement(paymentId: string, ifUpdatedAt?: number): void;
  /** 'settled' markers last updated before the given time, oldest first. */
  listSettled(updatedBefore: number, limit?: number): SettlementMarker[];
  /** The 'settled' markers of one transaction whose payment is not recorded yet (see UsageTracker.listSettledFor). */
  listSettledFor(transaction: string): SettlementMarker[];
  /** Deletes 'unknown' and 'settling' markers last updated before the given time. */
  pruneSettlements(updatedBefore: number): number;
  /**
   * The most pressing unfinished settlement whose credits go to the principal: 'settled' first, then a live
   * 'settling', then 'unknown'. A 'settling' marker last updated before settlingStaleBefore counts as 'unknown',
   * and an 'unknown' one last updated before unknownSince no longer counts at all (the payment keeps its own
   * answer, but the session may buy again). A marker whose payment is already redeemed (its removal failed) is
   * finished, not pending.
   */
  pendingSettlementState(principalId: string, settlingStaleBefore?: number, unknownSince?: number): SettlementState | null;
}

/** Ranks a principal's unfinished settlements for pendingSettlementState: lower wins, null does not count. */
export function settlementUrgency(
  state: SettlementState,
  updatedAt: number,
  settlingStaleBefore: number,
  unknownSince: number = Number.MIN_SAFE_INTEGER
): { rank: number; state: SettlementState } | null {
  if (state === "settled") return { rank: 0, state };
  if (state === "settling" && updatedAt >= settlingStaleBefore) return { rank: 1, state };
  // A settle that never answered, or whose process died mid-settle (nothing will move it on, so it is as
  // unknown), blocks the session from buying again only for a while.
  if (updatedAt < unknownSince) return null;
  return { rank: 2, state: "unknown" };
}

export interface UsageTrackerOptions {
  /** How long a redeemed payment id is remembered. */
  redeemedRetentionMs?: number;
  /** How long an idle, unfunded anonymous or prepaid principal is kept before its counters are dropped. */
  idlePrincipalRetentionMs?: number;
}

const MIN_FLUSH_DEBOUNCE_MS = 2000;
const MAX_FLUSH_DEBOUNCE_MS = 60000;
/** A flush costing N ms of synchronous serialization is not repeated more often than every 20 x N ms. */
const FLUSH_COST_MULTIPLIER = 20;
const FLUSH_RETRY_MS = 10000;
const PRUNE_INTERVAL_MS = 60000;
/** Comfortably beyond card-network dispute windows and any x402 authorization validity. */
export const REDEEMED_PAYMENT_RETENTION_MS = 400 * 24 * 60 * 60 * 1000;
/** Anonymous and prepaid principals are unreachable long before this (session tokens last 30 days). */
export const IDLE_PRINCIPAL_RETENTION_MS = 90 * 24 * 60 * 60 * 1000;
/** Hard safety bound; above it the oldest ids (by redemption time) are dropped in bulk with a warning. */
const MAX_REDEEMED_PAYMENTS = 2000000;
/** Principal ids minted per client address or per payment; API-key principals are never pruned. */
const PRUNABLE_PRINCIPAL_PREFIXES = ["anon_", "pay_"];
/**
 * Wall time redeemAndGrant keeps retrying a locked shared database. It is wall time, not summed sleeps:
 * every attempt also blocks for up to BUSY_TIMEOUT_MS inside SQLite. The last attempt may add one such wait.
 */
export const REDEEM_LOCK_BUDGET_MS = 15_000;
/** Wall time an HTTP server keeps retrying the first attach to a locked shared ledger before it refuses to start. */
export const ATTACH_LOCK_BUDGET_MS = 15_000;

const SETTLEMENT_STATES: readonly SettlementState[] = ["settling", "unknown", "settled"];

/** A settlement marker read back from the usage file, or null when the entry is malformed. */
function parseMarker(value: unknown): SettlementMarker | null {
  if (!value || typeof value !== "object") return null;
  const m = value as Record<string, unknown>;
  const finite = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v);
  if (typeof m.paymentId !== "string" || typeof m.principalId !== "string" || typeof m.label !== "string") return null;
  if (!finite(m.credits) || !finite(m.at) || !finite(m.updatedAt)) return null;
  if (!SETTLEMENT_STATES.includes(m.state as SettlementState)) return null;
  return {
    paymentId: m.paymentId,
    principalId: m.principalId,
    label: m.label,
    credits: m.credits,
    state: m.state as SettlementState,
    tx: typeof m.tx === "string" ? m.tx : null,
    receipt: m.receipt && typeof m.receipt === "object" && !Array.isArray(m.receipt) ? (m.receipt as Record<string, unknown>) : null,
    identity: typeof m.identity === "string" ? m.identity : null,
    at: m.at,
    updatedAt: m.updatedAt
  };
}

function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    // EPERM means the process exists but belongs to another user.
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

function parseTime(value: unknown): number | null {
  if (typeof value !== "string") return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

export class UsageTracker {
  private readonly filePath: string | null;
  private readonly principals = new Map<string, PrincipalUsage>();
  /** Redeemed payment id to the time it was redeemed (ms since epoch). */
  private readonly redeemedPayments = new Map<string, number>();
  private readonly redeemedRetentionMs: number;
  private readonly idlePrincipalRetentionMs: number;
  private flushTimer: NodeJS.Timeout | null = null;
  private retryTimer: NodeJS.Timeout | null = null;
  private flushing: Promise<void> | null = null;
  private dirty = false;
  private closed = false;
  private lastPrune = 0;
  private debounceMs = MIN_FLUSH_DEBOUNCE_MS;
  private ledger: SharedLedger | null = null;
  /**
   * Settlement markers when no shared ledger is attached (a single process owns every payment). They are
   * persisted in the usage file like redeemed payment ids, so a restart still knows money may have moved.
   */
  private readonly settlements = new Map<string, SettlementMarker>();

  constructor(filePath: string | null, options: UsageTrackerOptions = {}) {
    this.filePath = filePath ? path.resolve(filePath) : null;
    this.redeemedRetentionMs = options.redeemedRetentionMs ?? REDEEMED_PAYMENT_RETENTION_MS;
    this.idlePrincipalRetentionMs = options.idlePrincipalRetentionMs ?? IDLE_PRINCIPAL_RETENTION_MS;
  }

  /**
   * Removes temp files left behind by a process that died mid-write; nothing
   * else ever cleans them up. Files whose embedded pid is still alive belong
   * to a running writer and are left alone.
   */
  private async sweepTempFiles(): Promise<void> {
    if (!this.filePath) return;
    const dir = path.dirname(this.filePath);
    const prefix = `${path.basename(this.filePath)}.`;
    try {
      for (const entry of await readdir(dir)) {
        if (!entry.startsWith(prefix) || !entry.endsWith(".tmp")) continue;
        const pid = Number(entry.slice(prefix.length).split(".")[0]);
        if (Number.isInteger(pid) && pid !== process.pid && processAlive(pid)) continue;
        await unlink(path.join(dir, entry)).catch(() => undefined);
      }
    } catch {
      // The directory does not exist yet; the first flush creates it.
    }
  }

  async load(): Promise<void> {
    if (!this.filePath) return;
    await this.sweepTempFiles();
    try {
      const raw = await readFile(this.filePath, "utf8");
      const parsed = JSON.parse(raw) as Partial<UsageFile> & { redeemedPayments?: unknown };
      const nowIso = new Date().toISOString();
      if (parsed && typeof parsed === "object" && parsed.principals && typeof parsed.principals === "object") {
        for (const [id, usage] of Object.entries(parsed.principals)) {
          if (usage && typeof usage === "object" && typeof usage.principalId === "string") {
            this.principals.set(id, {
              principalId: usage.principalId,
              plan: typeof usage.plan === "string" ? usage.plan : "free",
              label: typeof usage.label === "string" ? usage.label : "",
              totalCalls: Number(usage.totalCalls) || 0,
              totalCredits: Number(usage.totalCredits) || 0,
              byTool: usage.byTool && typeof usage.byTool === "object" ? { ...usage.byTool } : {},
              creditsRemaining: typeof usage.creditsRemaining === "number" ? usage.creditsRemaining : null,
              // Timestamps that do not parse are aged from now so a hand-edited
              // or corrupt entry cannot become immortal.
              firstSeen: parseTime(usage.firstSeen) !== null ? usage.firstSeen : nowIso,
              lastSeen: parseTime(usage.lastSeen) !== null ? usage.lastSeen : nowIso
            });
          }
        }
      }
      if (Array.isArray(parsed?.redeemedPayments)) {
        const now = Date.now();
        for (const entry of parsed.redeemedPayments as unknown[]) {
          // Version 1 files stored bare ids; they are aged from the moment they
          // are first seen here, which only ever keeps them longer.
          if (typeof entry === "string") {
            this.redeemedPayments.set(entry, now);
          } else if (entry && typeof entry === "object" && typeof (entry as RedeemedPaymentRecord).id === "string") {
            const record = entry as Partial<RedeemedPaymentRecord>;
            this.redeemedPayments.set(record.id as string, parseTime(record.at) ?? now);
          }
        }
      }
      // Version 3 and later; older files simply have none.
      if (Array.isArray(parsed?.settlements)) {
        for (const entry of parsed.settlements as unknown[]) {
          const marker = parseMarker(entry);
          if (marker) this.settlements.set(marker.paymentId, marker);
        }
      }
      this.prune(Date.now(), true);
      logger.info("usage state loaded", { file: this.filePath, principals: this.principals.size, redeemedPayments: this.redeemedPayments.size, settlements: this.settlements.size });
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === "ENOENT") {
        logger.info("usage file does not exist yet; starting empty", { file: this.filePath });
      } else {
        logger.warn("usage file could not be read; starting empty", { file: this.filePath, error: err });
      }
    }
  }

  /**
   * Moves prepaid balances and redeemed payment ids to the shared database,
   * so processes sharing it see one ledger. The file keeps a mirror as a
   * backup, but balances and redemptions are read from the database from
   * now on.
   */
  attachLedger(ledger: SharedLedger): void {
    ledger.importOnce({
      balances: [...this.principals.values()]
        .filter((u) => u.creditsRemaining !== null)
        .map((u) => ({ principalId: u.principalId, plan: u.plan, label: u.label, balance: u.creditsRemaining as number })),
      redeemed: [...this.redeemedPayments].map(([id, at]) => ({ id, at }))
    });
    this.ledger = ledger;
    this.importSettlements(ledger);
  }

  /**
   * Moves settlement markers kept in the usage file (a run with STACKDNS_DB_FILE=none) into the shared
   * database, so a payment whose settle never answered keeps its answer after the switch. A marker the
   * database already has wins. Best effort: one that cannot be moved stays in the file for the next start.
   */
  private importSettlements(ledger: SharedLedger): void {
    for (const [paymentId, marker] of this.settlements) {
      try {
        if (ledger.beginSettlement(marker, marker.at) && (marker.state !== "settling" || marker.updatedAt !== marker.at)) {
          ledger.markSettlement(paymentId, marker.state, marker.tx, marker.receipt, marker.updatedAt);
        }
        this.settlements.delete(paymentId);
        this.markDirty();
      } catch (err) {
        logger.warn("x402 settlement marker from the usage file could not be moved to the database", { paymentId, error: err });
      }
    }
  }

  /** True when balances live in the shared database, so credit changes commit with the surrounding transaction. */
  get hasSharedLedger(): boolean {
    return this.ledger !== null;
  }

  /** Refreshes the mirrored balance of a principal from the shared ledger. */
  private mirror(usage: PrincipalUsage | undefined): PrincipalUsage | undefined {
    if (!usage || !this.ledger) return usage;
    try {
      usage.creditsRemaining = this.ledger.balance(usage.principalId);
    } catch (err) {
      // Display only: keep the last mirrored value.
      logger.warn("credit balance could not be read", { principal: usage.principalId, error: err });
    }
    return usage;
  }

  private ensure(principalId: string, plan: string, label: string): PrincipalUsage {
    let usage = this.principals.get(principalId);
    const now = new Date().toISOString();
    if (!usage) {
      usage = {
        principalId,
        plan,
        label,
        totalCalls: 0,
        totalCredits: 0,
        byTool: {},
        creditsRemaining: null,
        firstSeen: now,
        lastSeen: now
      };
      this.principals.set(principalId, usage);
    }
    usage.plan = plan;
    if (label) usage.label = label;
    usage.lastSeen = now;
    return usage;
  }

  get(principalId: string): PrincipalUsage | undefined {
    return this.mirror(this.principals.get(principalId));
  }

  record(principalId: string, plan: string, label: string, tool: string, credits: number): PrincipalUsage {
    const usage = this.ensure(principalId, plan, label);
    usage.totalCalls += 1;
    usage.totalCredits += credits;
    usage.byTool[tool] = (usage.byTool[tool] ?? 0) + 1;
    this.markDirty();
    this.mirror(usage);
    return usage;
  }

  creditsRemaining(principalId: string): number | null {
    if (this.ledger) return this.ledger.balance(principalId);
    return this.principals.get(principalId)?.creditsRemaining ?? null;
  }

  addCredits(principalId: string, plan: string, label: string, credits: number): PrincipalUsage {
    const usage = this.ensure(principalId, plan, label);
    usage.creditsRemaining = this.ledger ? this.ledger.add(principalId, plan, label, credits) : (usage.creditsRemaining ?? 0) + credits;
    this.markDirty();
    return usage;
  }

  /**
   * Atomically consumes credits. Returns false (and leaves the balance
   * untouched) when the balance is insufficient.
   */
  consumeCredits(principalId: string, credits: number): boolean {
    if (this.ledger) {
      if (!this.ledger.consume(principalId, credits)) return false;
      this.mirror(this.principals.get(principalId));
      this.markDirty();
      return true;
    }
    const usage = this.principals.get(principalId);
    if (!usage || usage.creditsRemaining === null) return false;
    if (usage.creditsRemaining < credits) return false;
    usage.creditsRemaining -= credits;
    this.markDirty();
    return true;
  }

  isPaymentRedeemed(paymentId: string): boolean {
    if (this.ledger) return this.ledger.isRedeemed(paymentId, this.redeemedRetentionMs);
    const at = this.redeemedPayments.get(paymentId);
    if (at === undefined) return false;
    if (Date.now() - at > this.redeemedRetentionMs) {
      this.redeemedPayments.delete(paymentId);
      this.markDirty();
      return false;
    }
    return true;
  }

  /** Like isPaymentRedeemed, for any id of the family (see GuardFamily). */
  isGuardFamilyRedeemed(family: GuardFamily): boolean {
    if (this.ledger) return this.ledger.isRedeemedFamily(family, this.redeemedRetentionMs);
    return this.holdsFamily(family, Date.now() - this.redeemedRetentionMs);
  }

  /**
   * Whether a redeemed id held in memory, recorded at or after `since`, belongs to the family. It scans every id,
   * but only while an x402 payment is recorded or its answer chosen, and only without a shared database.
   */
  private holdsFamily(family: GuardFamily, since = Number.NEGATIVE_INFINITY): boolean {
    for (const [id, at] of this.redeemedPayments) {
      if (at >= since && inGuardFamily(id, family)) return true;
    }
    return false;
  }

  /**
   * Records a redeemed payment id. Returns false when it was already
   * redeemed, including by another process sharing the database, so exactly
   * one redemption grants credits.
   */
  markPaymentRedeemed(paymentId: string, at: number = Date.now()): boolean {
    const fresh = this.ledger ? this.ledger.markRedeemed(paymentId, at) : !this.redeemedPayments.has(paymentId);
    this.redeemedPayments.set(paymentId, at);
    this.prune(Date.now(), this.redeemedPayments.size > MAX_REDEEMED_PAYMENTS);
    this.markDirty();
    return fresh;
  }

  /**
   * Claims a payment and grants its credits together, exactly once. Money has
   * already moved when this is called, so with the shared ledger a locked
   * database is waited out (REDEEM_LOCK_BUDGET_MS of wall time, plus at most
   * one blocked attempt) rather than given up on. Returns false, granting
   * nothing, when any of the ids was already redeemed, any blockedBy id is
   * (a guard id written by older code, or by the other presentation of the
   * same authorization) or any id of blockedByFamily is; the ids are
   * recorded either way.
   */
  async redeemAndGrant(
    ids: readonly string[],
    principalId: string,
    plan: string,
    label: string,
    credits: number,
    blockedBy: readonly string[] = [],
    blockedByFamily: GuardFamily | null = null
  ): Promise<boolean> {
    const at = Date.now();
    if (this.ledger) {
      const ledger = this.ledger;
      const deadline = at + REDEEM_LOCK_BUDGET_MS;
      for (let attempt = 1; ; attempt++) {
        try {
          const fresh = ledger.redeemAndCredit(ids, principalId, plan, label, credits, at, blockedBy, blockedByFamily);
          for (const id of ids) this.redeemedPayments.set(id, at);
          this.mirror(this.ensure(principalId, plan, label));
          this.markDirty();
          return fresh;
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err);
          // Counted in wall time: each failed attempt has already blocked for the busy timeout, which summed
          // sleeps ignore (the loop then ran about 28 s). A sibling adopts a 'settled' marker only well after this.
          const left = deadline - Date.now();
          if (!/database is locked|SQLITE_BUSY/i.test(message) || left <= 0) throw err;
          const delay = Math.min(2000, 100 * 2 ** Math.min(attempt, 5), left);
          await new Promise((resolve) => setTimeout(resolve, delay));
        }
      }
    }
    // The same rule as CreditLedger.redeemAndCredit: any id already redeemed (or any blocker) grants nothing.
    const fresh = ids.every((id) => !this.redeemedPayments.has(id)) && !blockedBy.some((id) => this.redeemedPayments.has(id)) && (blockedByFamily === null || !this.holdsFamily(blockedByFamily));
    for (const id of ids) this.redeemedPayments.set(id, at);
    if (fresh) this.addCredits(principalId, plan, label, credits);
    this.markDirty();
    return fresh;
  }

  // x402 settlement markers. They live in the shared database when one is
  // attached, so every process (and a restarted one) sees them; otherwise in
  // memory, where this process owns every payment, and in the usage file, so a
  // restart still knows them. Database errors propagate: the payment layer
  // decides what a failed write means for the payer.

  beginSettlement(start: SettlementStart, at: number = Date.now()): boolean {
    if (this.ledger) return this.ledger.beginSettlement(start, at);
    if (this.settlements.has(start.paymentId)) return false;
    this.settlements.set(start.paymentId, { ...start, identity: start.identity ?? null, state: "settling", tx: null, receipt: null, at, updatedAt: at });
    this.markDirty();
    return true;
  }

  resumeSettlement(seen: SettlementMarker, at: number = Date.now()): boolean {
    if (this.ledger) return this.ledger.resumeSettlement(seen, at);
    const current = this.settlements.get(seen.paymentId);
    if (!current || current.state !== seen.state || current.updatedAt !== seen.updatedAt) return false;
    current.state = "settling";
    current.updatedAt = at;
    this.markDirty();
    return true;
  }

  touchSettlement(seen: SettlementMarker, at: number = Date.now()): boolean {
    if (this.ledger) return this.ledger.touchSettlement(seen, at);
    const current = this.settlements.get(seen.paymentId);
    if (!current || current.state !== seen.state || current.updatedAt !== seen.updatedAt) return false;
    current.updatedAt = at;
    this.markDirty();
    return true;
  }

  markSettlement(paymentId: string, state: SettlementState, tx: string | null = null, receipt: Record<string, unknown> | null = null, at: number = Date.now()): void {
    if (this.ledger) {
      this.ledger.markSettlement(paymentId, state, tx, receipt, at);
      return;
    }
    const current = this.settlements.get(paymentId);
    // A settled marker's transaction is known; it is never downgraded.
    if (!current || (current.state === "settled" && state !== "settled")) return;
    current.state = state;
    if (tx !== null) current.tx = tx;
    if (receipt !== null) current.receipt = receipt;
    current.updatedAt = at;
    this.markDirty();
  }

  getSettlement(paymentId: string): SettlementMarker | null {
    if (this.ledger) return this.ledger.getSettlement(paymentId);
    const current = this.settlements.get(paymentId);
    return current ? { ...current } : null;
  }

  endSettlement(paymentId: string, ifUpdatedAt?: number): void {
    if (this.ledger) {
      this.ledger.endSettlement(paymentId, ifUpdatedAt);
      return;
    }
    if (ifUpdatedAt !== undefined && this.settlements.get(paymentId)?.updatedAt !== ifUpdatedAt) return;
    if (this.settlements.delete(paymentId)) this.markDirty();
  }

  listSettled(updatedBefore: number, limit = 100): SettlementMarker[] {
    if (this.ledger) return this.ledger.listSettled(updatedBefore, limit);
    return [...this.settlements.values()]
      .filter((m) => m.state === "settled" && m.updatedAt < updatedBefore)
      .sort((a, b) => a.updatedAt - b.updatedAt)
      .slice(0, limit)
      .map((m) => ({ ...m }));
  }

  /**
   * The 'settled' markers of one transaction whose payment is not recorded yet, compared without regard to case
   * (see settledTxOf). The first-settlement rule in payments.ts reads them: a later presentation of the same
   * authorization yields to an earlier one still being recorded. Only unfinished markers are kept, so this is cheap.
   */
  listSettledFor(transaction: string): SettlementMarker[] {
    if (this.ledger) return this.ledger.listSettledFor(transaction);
    const tx = transaction.toLowerCase();
    return [...this.settlements.values()].filter((m) => m.state === "settled" && m.tx !== null && settledTxOf(m.tx, tx) && !this.redeemedPayments.has(m.paymentId)).map((m) => ({ ...m }));
  }

  pruneSettlements(updatedBefore: number): number {
    if (this.ledger) return this.ledger.pruneSettlements(updatedBefore);
    let removed = 0;
    for (const [id, marker] of this.settlements) {
      if (marker.state !== "settled" && marker.updatedAt < updatedBefore) {
        this.settlements.delete(id);
        removed += 1;
      }
    }
    if (removed > 0) this.markDirty();
    return removed;
  }

  /**
   * Whether a payment whose credits go to this principal is still unfinished, so an empty balance is not
   * yet final. The map holds only unfinished settlements, so a scan is cheap.
   */
  pendingSettlementState(principalId: string, settlingStaleBefore: number = Number.MIN_SAFE_INTEGER, unknownSince: number = Number.MIN_SAFE_INTEGER): SettlementState | null {
    if (this.ledger) return this.ledger.pendingSettlementState(principalId, settlingStaleBefore, unknownSince);
    let best: { rank: number; state: SettlementState } | null = null;
    for (const marker of this.settlements.values()) {
      if (marker.principalId !== principalId || this.redeemedPayments.has(marker.paymentId)) continue;
      const ranked = settlementUrgency(marker.state, marker.updatedAt, settlingStaleBefore, unknownSince);
      if (ranked && (!best || ranked.rank < best.rank)) best = ranked;
    }
    return best?.state ?? null;
  }

  /** Number of redeemed payment ids currently remembered. */
  get redeemedCount(): number {
    return this.redeemedPayments.size;
  }

  /**
   * Drops redeemed ids past their retention and idle, unfunded per-address or
   * per-payment principals that nothing can reach any more. Rate limited so
   * hot paths never pay for a full scan; forced at load, at flush and when
   * the ledger crosses its safety bound.
   */
  private prune(now: number, force = false): void {
    if (!force && now - this.lastPrune < PRUNE_INTERVAL_MS) return;
    this.lastPrune = now;
    let changed = false;
    for (const [id, at] of this.redeemedPayments) {
      if (now - at > this.redeemedRetentionMs) {
        this.redeemedPayments.delete(id);
        changed = true;
      }
    }
    if (this.redeemedPayments.size > MAX_REDEEMED_PAYMENTS) {
      // Drop the oldest one percent by redemption time in one pass so the
      // bound is not re-crossed (and re-logged) on every subsequent payment.
      const excess = this.redeemedPayments.size - Math.floor(MAX_REDEEMED_PAYMENTS * 0.99);
      const oldest = [...this.redeemedPayments].sort((a, b) => a[1] - b[1]).slice(0, excess);
      for (const [id] of oldest) this.redeemedPayments.delete(id);
      logger.warn("redeemed payment ledger exceeded its safety bound; dropped the oldest ids", { dropped: oldest.length, remaining: this.redeemedPayments.size });
      changed = true;
    }
    if (this.ledger) {
      try {
        this.ledger.pruneRedeemed(this.redeemedRetentionMs, now);
      } catch (err) {
        logger.warn("pruning redeemed payments failed", { error: err });
      }
    }
    for (const [id, usage] of this.principals) {
      if (!PRUNABLE_PRINCIPAL_PREFIXES.some((prefix) => id.startsWith(prefix))) continue;
      if ((usage.creditsRemaining ?? 0) > 0) continue;
      const lastSeen = parseTime(usage.lastSeen);
      if (lastSeen === null || now - lastSeen > this.idlePrincipalRetentionMs) {
        this.principals.delete(id);
        changed = true;
      }
    }
    // markDirty (not a bare flag) so a load-time prune on a quiet server is
    // still written out instead of waiting for the next request.
    if (changed) this.markDirty();
  }

  snapshot(): UsageFile {
    return {
      version: 3,
      updatedAt: new Date().toISOString(),
      principals: Object.fromEntries(this.principals),
      redeemedPayments: [...this.redeemedPayments].map(([id, at]) => ({ id, at: new Date(at).toISOString() })),
      settlements: [...this.settlements.values()].map((m) => ({ ...m }))
    };
  }

  stats(): { principals: number; totalCalls: number; totalCredits: number } {
    let totalCalls = 0;
    let totalCredits = 0;
    for (const usage of this.principals.values()) {
      totalCalls += usage.totalCalls;
      totalCredits += usage.totalCredits;
    }
    return { principals: this.principals.size, totalCalls, totalCredits };
  }

  private markDirty(): void {
    this.dirty = true;
    if (!this.filePath || this.closed || this.flushTimer) return;
    this.flushTimer = setTimeout(() => {
      this.flushTimer = null;
      this.flush().catch((err: unknown) => logger.warn("usage flush failed", { error: err }));
    }, this.debounceMs);
    this.flushTimer.unref();
  }

  private scheduleRetry(): void {
    if (this.retryTimer || this.closed) return;
    this.retryTimer = setTimeout(() => {
      this.retryTimer = null;
      this.flush().catch((err: unknown) => logger.warn("usage flush retry failed", { error: err }));
    }, FLUSH_RETRY_MS);
    this.retryTimer.unref();
  }

  /** Serializes the current state and renames it into place; restores dirtiness on failure. */
  private async write(target: string): Promise<void> {
    const started = Date.now();
    this.prune(started, true);
    const payload = JSON.stringify(this.snapshot());
    // Cleared before the write so a mutation that lands during the write
    // re-dirties the tracker; restored on failure so credits and redeemed
    // ids are retried by the next flush (or by close()) instead of being
    // silently dropped.
    this.dirty = false;
    const tmp = `${target}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`;
    try {
      await mkdir(path.dirname(target), { recursive: true });
      await writeFile(tmp, payload, "utf8");
      await rename(tmp, target);
    } catch (err) {
      this.dirty = true;
      await unlink(tmp).catch(() => undefined);
      this.scheduleRetry();
      throw err;
    }
    // A large ledger costs a synchronous JSON.stringify plus a full rewrite;
    // spacing flushes in proportion to that cost keeps the event loop free.
    const cost = Date.now() - started;
    this.debounceMs = Math.min(MAX_FLUSH_DEBOUNCE_MS, Math.max(MIN_FLUSH_DEBOUNCE_MS, cost * FLUSH_COST_MULTIPLIER));
  }

  /**
   * Persists pending state. Always waits for a flush that is already in
   * flight, even when nothing new is dirty, so a caller such as close() can
   * rely on the bytes being on disk when the promise settles.
   */
  async flush(): Promise<void> {
    if (!this.filePath) return;
    const target = this.filePath;
    for (;;) {
      if (this.flushing) {
        try {
          await this.flushing;
        } catch {
          // The failed write restored the dirty flag; the loop retries below.
        }
        continue;
      }
      if (!this.dirty) return;
      this.flushing = this.write(target);
      try {
        await this.flushing;
      } finally {
        this.flushing = null;
      }
      return;
    }
  }

  /**
   * Persists everything and stops the timers. Mutations that land while the
   * final write is in flight (a request finishing during shutdown) re-dirty
   * the tracker, so the flush is repeated until nothing is pending.
   */
  async close(): Promise<void> {
    this.closed = true;
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }
    if (this.retryTimer) {
      clearTimeout(this.retryTimer);
      this.retryTimer = null;
    }
    for (let attempt = 0; attempt < 5; attempt++) {
      await this.flush();
      if (!this.dirty) return;
    }
    await this.flush();
    if (this.dirty) logger.warn("usage ledger still receiving writes at close; the last mutations were not persisted", { file: this.filePath });
  }
}

/**
 * Attaches the shared credit ledger, waiting out a locked database for at most budgetMs of wall time (the
 * first attach of a database imports the file ledger under BEGIN IMMEDIATE). A process that sells credits
 * (required) must never run on a private file ledger next to a shared one, where a payment could be redeemed
 * once in each, so it rethrows. One that sells nothing (stdio) is told false and runs without it.
 */
export async function attachSharedLedger(usage: UsageTracker, ledger: SharedLedger, options: { required: boolean; budgetMs: number }): Promise<boolean> {
  const started = Date.now();
  for (let attempt = 1; ; attempt++) {
    try {
      usage.attachLedger(ledger);
      return true;
    } catch (err) {
      const left = options.budgetMs - (Date.now() - started);
      if (isLockContention(err) && left > 0) {
        await new Promise((resolve) => setTimeout(resolve, Math.min(100 * attempt + Math.floor(Math.random() * 100), 1000, left)));
        continue;
      }
      if (options.required) throw new Error("credit ledger could not be attached to the shared database; refusing to run on a private file ledger", { cause: err });
      return false;
    }
  }
}
