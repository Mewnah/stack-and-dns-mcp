/**
 * Prepaid credit balances, redeemed payment ids and x402 settlement markers
 * (x402_settlements) in the shared database. A marker is written before
 * /settle is called, so every process sharing the database, and a restarted
 * one, knows money may have moved for a payment.
 *
 * The usage ledger file is a whole-state snapshot written by each process,
 * so two processes sharing it (a rolling deploy, a bulk job charged in one
 * process and refunded in the lease holder) would erase each other's
 * balance changes. Every credit movement here is a single SQL statement, so
 * it is atomic on its own and, called inside a transaction, commits or rolls
 * back with the write that justifies it (a job insert, a job finalization).
 */

import { logger } from "../logger.js";
import { inGuardFamily, settlementUrgency, type GuardFamily, type SettlementMarker, type SettlementStart, type SettlementState } from "../middleware/usage.js";
import { transaction, type Database } from "./db.js";

interface SettlementRow {
  payment_id: string;
  principal_id: string;
  label: string;
  credits: number;
  state: SettlementState;
  tx: string | null;
  receipt: string | null;
  at: number;
  updated_at: number;
}

/**
 * The authorization identity rides in the receipt column (the schema has no column for it, and older code
 * only ever reads the receipt of a 'settled' marker, where a stray key is harmless). It is written with the
 * claim and kept by every later update.
 */
const IDENTITY_KEY = "_identity";

function parseReceipt(raw: string | null): { receipt: Record<string, unknown> | null; identity: string | null } {
  if (raw === null) return { receipt: null, identity: null };
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return { receipt: null, identity: null };
    const { [IDENTITY_KEY]: identity, ...receipt } = parsed as Record<string, unknown>;
    return { receipt: Object.keys(receipt).length > 0 ? receipt : null, identity: typeof identity === "string" ? identity : null };
  } catch {
    return { receipt: null, identity: null };
  }
}

function toMarker(row: SettlementRow): SettlementMarker {
  const { receipt, identity } = parseReceipt(row.receipt);
  return {
    paymentId: row.payment_id,
    principalId: row.principal_id,
    label: row.label,
    credits: Number(row.credits),
    state: row.state,
    tx: row.tx,
    receipt,
    identity,
    at: Number(row.at),
    updatedAt: Number(row.updated_at)
  };
}

/** A marker as an operator sees it: also whether its payment is already redeemed (a leftover whose removal failed). */
export interface SettlementListing extends SettlementMarker {
  redeemed: boolean;
}

const IMPORTED_KEY = "credits_imported";

export interface LedgerImport {
  balances: Array<{ principalId: string; plan: string; label: string; balance: number }>;
  redeemed: Array<{ id: string; at: number }>;
}

export class CreditLedger {
  constructor(private readonly db: Database) {}

  balance(principalId: string): number | null {
    const row = this.db.prepare("SELECT balance FROM credits WHERE principal_id = ?").get(principalId) as { balance: number } | undefined;
    return row ? Number(row.balance) : null;
  }

  /** Debits the balance when it covers the amount; returns false (and changes nothing) otherwise. */
  consume(principalId: string, credits: number): boolean {
    return Number(this.db.prepare("UPDATE credits SET balance = balance - ? WHERE principal_id = ? AND balance >= ?").run(credits, principalId, credits).changes) === 1;
  }

  add(principalId: string, plan: string, label: string, credits: number): number {
    this.db
      .prepare(
        "INSERT INTO credits (principal_id, plan, label, balance) VALUES (?, ?, ?, ?) ON CONFLICT(principal_id) DO UPDATE SET balance = balance + excluded.balance, plan = excluded.plan, label = CASE WHEN excluded.label = '' THEN label ELSE excluded.label END"
      )
      .run(principalId, plan, label, credits);
    return this.balance(principalId) ?? credits;
  }

  isRedeemed(paymentId: string, retentionMs: number, now: number = Date.now()): boolean {
    const row = this.db.prepare("SELECT at FROM redeemed_payments WHERE id = ?").get(paymentId) as { at: number } | undefined;
    return row !== undefined && now - Number(row.at) <= retentionMs;
  }

  /** Like isRedeemed, for any id of the family (see GuardFamily). */
  isRedeemedFamily(family: GuardFamily, retentionMs: number, now: number = Date.now()): boolean {
    return this.familyMembers(family).some((member) => now - member.at <= retentionMs);
  }

  /**
   * The recorded ids of a guard family. Every member starts with the prefix, so the members are one range of
   * the primary key index, from the prefix up to the prefix with its last character (':') incremented: an index
   * range, never a table scan, and no GLOB pattern whose metacharacters a facilitator's transaction id could
   * carry. Only ids of the prefix's transaction fall in the range (a batch at most), and the shape is checked here.
   */
  private familyMembers(family: GuardFamily): Array<{ id: string; at: number }> {
    const { prefix } = family;
    const end = `${prefix.slice(0, -1)}${String.fromCharCode(prefix.charCodeAt(prefix.length - 1) + 1)}`;
    const rows = this.db.prepare("SELECT id, at FROM redeemed_payments WHERE id > ? AND id < ?").all(prefix, end) as Array<{ id: string; at: number }>;
    return rows.filter((row) => inGuardFamily(row.id, family)).map((row) => ({ id: row.id, at: Number(row.at) }));
  }

  /** Records a redemption; returns false when the id was already redeemed (by this or another process). */
  markRedeemed(paymentId: string, at: number = Date.now()): boolean {
    return Number(this.db.prepare("INSERT INTO redeemed_payments (id, at) VALUES (?, ?) ON CONFLICT(id) DO NOTHING").run(paymentId, at).changes) === 1;
  }

  /**
   * Claims a payment (all its ids) and grants its credits in one
   * transaction: either both happen or neither, so a payment is never
   * recorded without its credits, nor credited twice. Returns false, granting
   * nothing, when any id was already redeemed, any blockedBy id is (a guard
   * id older code wrote, or the other presentation's, checked here but never
   * written) or any id of blockedByFamily is. Every id is still recorded, so
   * the same payload cannot be retried. Any id counts, not just the first: a
   * payment id recorded under one guard form is never credited again under
   * another.
   */
  redeemAndCredit(
    ids: readonly string[],
    principalId: string,
    plan: string,
    label: string,
    credits: number,
    at: number = Date.now(),
    blockedBy: readonly string[] = [],
    blockedByFamily: GuardFamily | null = null
  ): boolean {
    return transaction(this.db, () => this.redeemAndCreditInTransaction(ids, principalId, plan, label, credits, at, blockedBy, blockedByFamily));
  }

  private redeemAndCreditInTransaction(
    ids: readonly string[],
    principalId: string,
    plan: string,
    label: string,
    credits: number,
    at: number,
    blockedBy: readonly string[],
    blockedByFamily: GuardFamily | null
  ): boolean {
    const exists = this.db.prepare("SELECT 1 FROM redeemed_payments WHERE id = ?");
    let fresh = !blockedBy.some((id) => exists.get(id) !== undefined) && (blockedByFamily === null || this.familyMembers(blockedByFamily).length === 0);
    for (const id of ids) {
      if (!this.markRedeemed(id, at)) fresh = false;
    }
    if (fresh) this.add(principalId, plan, label, credits);
    return fresh;
  }

  pruneRedeemed(retentionMs: number, now: number = Date.now()): number {
    return Number(this.db.prepare("DELETE FROM redeemed_payments WHERE at < ?").run(now - retentionMs).changes);
  }

  /**
   * Inserts a 'settling' marker before any money moves. The primary key makes
   * this the cross-process claim on the payment: false means another request
   * (here or in a sibling process) already owns it.
   */
  beginSettlement(start: SettlementStart, at: number = Date.now()): boolean {
    const identity = start.identity ? JSON.stringify({ [IDENTITY_KEY]: start.identity }) : null;
    const result = this.db
      .prepare(
        "INSERT INTO x402_settlements (payment_id, principal_id, label, credits, state, tx, receipt, at, updated_at) VALUES (?, ?, ?, ?, 'settling', NULL, ?, ?, ?) ON CONFLICT(payment_id) DO NOTHING"
      )
      .run(start.paymentId, start.principalId, start.label, start.credits, identity, at, at);
    return Number(result.changes) === 1;
  }

  /** Compare-and-set back to 'settling', so two processes retrying the same unknown settlement cannot both call /settle. */
  resumeSettlement(seen: SettlementMarker, at: number = Date.now()): boolean {
    const result = this.db
      .prepare("UPDATE x402_settlements SET state = 'settling', updated_at = ? WHERE payment_id = ? AND state = ? AND updated_at = ?")
      .run(at, seen.paymentId, seen.state, seen.updatedAt);
    return Number(result.changes) === 1;
  }

  /** Compare-and-set of updated_at alone, so of the processes that see the same 'unknown' marker only one re-verifies it per window. */
  touchSettlement(seen: SettlementMarker, at: number = Date.now()): boolean {
    const result = this.db.prepare("UPDATE x402_settlements SET updated_at = ? WHERE payment_id = ? AND state = ? AND updated_at = ?").run(at, seen.paymentId, seen.state, seen.updatedAt);
    return Number(result.changes) === 1;
  }

  /**
   * A 'settled' marker never goes back to 'settling' or 'unknown': its transaction is known and only adoption may end it.
   * A new receipt keeps the identity the claim stored.
   */
  markSettlement(paymentId: string, state: SettlementState, tx: string | null = null, receipt: Record<string, unknown> | null = null, at: number = Date.now()): void {
    const json = receipt === null ? null : JSON.stringify(receipt);
    this.db
      .prepare(
        `UPDATE x402_settlements SET state = ?, tx = COALESCE(?, tx), receipt = CASE WHEN ? IS NULL THEN receipt ELSE json_set(?, '$.${IDENTITY_KEY}', CASE WHEN json_valid(receipt) THEN json_extract(receipt, '$.${IDENTITY_KEY}') END) END, updated_at = ? WHERE payment_id = ? AND (state <> 'settled' OR ? = 'settled')`
      )
      .run(state, tx, json, json, at, paymentId, state);
  }

  getSettlement(paymentId: string): SettlementMarker | null {
    const row = this.db.prepare("SELECT * FROM x402_settlements WHERE payment_id = ?").get(paymentId) as SettlementRow | undefined;
    return row ? toMarker(row) : null;
  }

  endSettlement(paymentId: string, ifUpdatedAt?: number): void {
    if (ifUpdatedAt === undefined) this.db.prepare("DELETE FROM x402_settlements WHERE payment_id = ?").run(paymentId);
    else this.db.prepare("DELETE FROM x402_settlements WHERE payment_id = ? AND updated_at = ?").run(paymentId, ifUpdatedAt);
  }

  listSettled(updatedBefore: number, limit = 100): SettlementMarker[] {
    const rows = this.db.prepare("SELECT * FROM x402_settlements WHERE state = 'settled' AND updated_at < ? ORDER BY updated_at LIMIT ?").all(updatedBefore, limit) as unknown as SettlementRow[];
    return rows.map(toMarker);
  }

  /**
   * The 'settled' markers of one transaction whose payment is not recorded yet (see UsageTracker.listSettledFor).
   * The state index narrows the read to the unfinished 'settled' markers, a handful, and the tx is matched on
   * them. SQLite's lower() folds only ASCII letters, which is all a hex transaction id holds.
   */
  listSettledFor(transaction: string): SettlementMarker[] {
    const tx = transaction.toLowerCase();
    const prefix = `${tx}:`;
    const rows = this.db
      .prepare(
        "SELECT * FROM x402_settlements s WHERE s.state = 'settled' AND (lower(s.tx) = ? OR substr(lower(s.tx), 1, ?) = ?) AND NOT EXISTS (SELECT 1 FROM redeemed_payments r WHERE r.id = s.payment_id)"
      )
      .all(tx, prefix.length, prefix) as unknown as SettlementRow[];
    return rows.map(toMarker);
  }

  /** 'settled' markers are never pruned: they hold moved money whose credits are not recorded yet. */
  pruneSettlements(updatedBefore: number): number {
    return Number(this.db.prepare("DELETE FROM x402_settlements WHERE state IN ('unknown', 'settling') AND updated_at < ?").run(updatedBefore).changes);
  }

  /**
   * The most pressing unfinished settlement whose credits go to the principal (see SharedLedger), found
   * through the x402_settlements_by_principal index (migration v9).
   */
  pendingSettlementState(principalId: string, settlingStaleBefore: number = Number.MIN_SAFE_INTEGER, unknownSince: number = Number.MIN_SAFE_INTEGER): SettlementState | null {
    const row = this.db
      .prepare(
        "SELECT state, updated_at FROM x402_settlements WHERE principal_id = ? AND (state = 'settled' OR (state = 'settling' AND updated_at >= ?) OR updated_at >= ?) AND NOT EXISTS (SELECT 1 FROM redeemed_payments r WHERE r.id = x402_settlements.payment_id) ORDER BY CASE WHEN state = 'settled' THEN 0 WHEN state = 'settling' AND updated_at >= ? THEN 1 ELSE 2 END LIMIT 1"
      )
      .get(principalId, settlingStaleBefore, unknownSince, settlingStaleBefore) as { state: SettlementState; updated_at: number } | undefined;
    return row ? (settlementUrgency(row.state, Number(row.updated_at), settlingStaleBefore, unknownSince)?.state ?? null) : null;
  }

  /**
   * Markers for operator reconciliation (src/cli/settlements.ts), oldest update first, at most `limit`. With
   * settlingStaleBefore, only those an operator has to look at: not recorded yet, and not a 'settling' marker
   * updated at or after that time (a live settle). The filter runs before the limit, so live settles and
   * leftovers of recorded payments never crowd out the markers that need attention.
   */
  listSettlements(options: { limit?: number; settlingStaleBefore?: number } = {}): SettlementListing[] {
    const attentionOnly = options.settlingStaleBefore !== undefined;
    const rows = this.db
      .prepare(
        "SELECT s.*, EXISTS (SELECT 1 FROM redeemed_payments r WHERE r.id = s.payment_id) AS redeemed FROM x402_settlements s WHERE ? = 0 OR (NOT EXISTS (SELECT 1 FROM redeemed_payments r WHERE r.id = s.payment_id) AND (s.state <> 'settling' OR s.updated_at < ?)) ORDER BY s.updated_at LIMIT ?"
      )
      .all(attentionOnly ? 1 : 0, options.settlingStaleBefore ?? 0, options.limit ?? 1000) as unknown as Array<SettlementRow & { redeemed: number }>;
    return rows.map((row) => ({ ...toMarker(row), redeemed: Number(row.redeemed) === 1 }));
  }

  /** The prepaid account of a principal, or null when it has never held credits. */
  account(principalId: string): { plan: string; label: string; balance: number } | null {
    const row = this.db.prepare("SELECT plan, label, balance FROM credits WHERE principal_id = ?").get(principalId) as { plan: string; label: string; balance: number } | undefined;
    return row ? { plan: row.plan, label: row.label, balance: Number(row.balance) } : null;
  }

  /**
   * An operator confirmed the transfer: records the payment under the given ids (crediting the marker's target
   * unless an id, a blocker or a member of blockedByFamily was already redeemed) and removes the marker, in one
   * transaction. Returns null, changing nothing, when the marker is no longer exactly as seen (a server touched
   * it meanwhile).
   */
  resolveSettlement(seen: SettlementMarker, ids: readonly string[], blockedBy: readonly string[], at: number = Date.now(), blockedByFamily: GuardFamily | null = null): { fresh: boolean } | null {
    return transaction(this.db, () => {
      if (!this.unchanged(seen)) return null;
      const fresh = this.redeemAndCreditInTransaction(ids, seen.principalId, "payg", seen.label, seen.credits, at, blockedBy, blockedByFamily);
      this.db.prepare("DELETE FROM x402_settlements WHERE payment_id = ?").run(seen.paymentId);
      return { fresh };
    });
  }

  /**
   * An operator confirmed nothing moved: removes the marker and records the payment id as redeemed, so that
   * authorization can never settle into credits here later. False, changing nothing, when the marker changed.
   */
  abandonSettlement(seen: SettlementMarker, at: number = Date.now()): boolean {
    return transaction(this.db, () => {
      if (!this.unchanged(seen)) return false;
      this.markRedeemed(seen.paymentId, at);
      this.db.prepare("DELETE FROM x402_settlements WHERE payment_id = ?").run(seen.paymentId);
      return true;
    });
  }

  private unchanged(seen: SettlementMarker): boolean {
    return this.db.prepare("SELECT 1 FROM x402_settlements WHERE payment_id = ? AND state = ? AND updated_at = ?").get(seen.paymentId, seen.state, seen.updatedAt) !== undefined;
  }

  /**
   * Moves balances and redeemed ids from the ledger file into the database,
   * once per database (a meta key records it). Rows already present win, so
   * a second process importing an older file cannot roll balances back.
   */
  importOnce(source: LedgerImport): boolean {
    // A plain read first: once imported (the common case), attaching needs no
    // write lock, so a busy database cannot push a process off the shared ledger.
    if (this.db.prepare("SELECT 1 FROM meta WHERE key = ?").get(IMPORTED_KEY)) return false;
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const done = this.db.prepare("SELECT value FROM meta WHERE key = ?").get(IMPORTED_KEY);
      if (done) {
        this.db.exec("COMMIT");
        return false;
      }
      const balance = this.db.prepare("INSERT INTO credits (principal_id, plan, label, balance) VALUES (?, ?, ?, ?) ON CONFLICT(principal_id) DO NOTHING");
      for (const b of source.balances) balance.run(b.principalId, b.plan, b.label, b.balance);
      const redeemed = this.db.prepare("INSERT INTO redeemed_payments (id, at) VALUES (?, ?) ON CONFLICT(id) DO NOTHING");
      for (const r of source.redeemed) redeemed.run(r.id, r.at);
      this.db.prepare("INSERT INTO meta (key, value) VALUES (?, ?)").run(IMPORTED_KEY, new Date().toISOString());
      this.db.exec("COMMIT");
      logger.info("moved prepaid balances and redeemed payments into the database", { balances: source.balances.length, redeemed: source.redeemed.length });
      return true;
    } catch (err) {
      try {
        this.db.exec("ROLLBACK");
      } catch {
        // the failed statement may already have ended the transaction
      }
      throw err;
    }
  }
}
