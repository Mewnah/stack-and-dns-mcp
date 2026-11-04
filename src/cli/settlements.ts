#!/usr/bin/env node
/**
 * Operator reconciliation of x402 settlements whose outcome a server could
 * not confirm (a /settle that timed out or failed, success without a
 * transaction id, or a settled payment that could not be recorded).
 *
 *   npm run settlements -- list [--all] [--json] [--limit <n>]
 *   npm run settlements -- resolve <paymentId> --tx <hash> [--nonce <nonce>]
 *   npm run settlements -- resolve <paymentId> --failed
 *   npm run settlements -- session <principalId> [--label <text>] [--json]
 *
 * It works on the shared database named by STACKDNS_DB_FILE (or --db <file>),
 * next to running servers: every write is one transaction that first checks
 * the marker is still exactly as listed. Settlement markers kept in the usage
 * file (STACKDNS_DB_FILE=none) are not supported, because the running server
 * rewrites that file whole.
 *
 * `list` shows the markers that need an operator: 'unknown' ones, 'settling'
 * ones whose process died mid-settle, and 'settled' ones whose credits are not
 * recorded. `--all` adds live settles and leftovers of recorded payments. At
 * most --limit rows (1000) are shown, oldest update first, with a notice on
 * stderr when more remain.
 *
 * `resolve --tx` records a transfer the operator confirmed on-chain, exactly
 * as a server's recording timer would: the credits go to the principal the
 * marker names, once, however often it is run. `resolve --failed` records that
 * nothing moved: the marker ends and the payment id is recorded as redeemed,
 * so that authorization can never settle into credits here later (a payer
 * whose authorization is still valid can pay again with a new one).
 *
 * `session` issues a prepaid session token for a principal, signed with
 * STACKDNS_SESSION_SECRET (the HTTP server's secret, required), so a payer
 * whose 502 or 503 answer was lost can reach credits granted here.
 */

import { existsSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { loadConfig } from "../config.js";
import { parseSafeInteger } from "../lib/numbers.js";
import { getLogLevel, setLogLevel } from "../logger.js";
import { SessionTokenService } from "../middleware/auth.js";
import { settledMarkerClaim, SETTLING_STALE_MS, x402IdentityNonce, x402NonceIdentity, x402TransactionGuard, type X402Claim } from "../middleware/payments.js";
import { REDEEMED_PAYMENT_RETENTION_MS, type SettlementMarker, type SettlementState } from "../middleware/usage.js";
import { CreditLedger, type SettlementListing } from "../store/credits.js";
import { isLockContention, openDatabase } from "../store/db.js";

/** A failure the operator can act on: printed without a stack trace (exit code 1). */
export class CliError extends Error {}

/** A command line that cannot run as given (a missing or extra argument, a missing flag): exit code 2. */
export class UsageError extends CliError {}

/** Rows `list` shows at most unless --limit says otherwise. */
export const DEFAULT_LIST_LIMIT = 1000;

export interface SettlementRow {
  paymentId: string;
  state: SettlementState;
  /** A 'settling' marker whose process stopped updating it: as unknown as a settle that never answered. */
  stale: boolean;
  principalId: string;
  label: string;
  credits: number;
  /** The settled transaction, when one is known. */
  transaction: string | null;
  /** Since the marker was created. */
  ageMs: number;
  /** Since it was last updated. */
  idleMs: number;
  /** Its payment is already recorded (the marker's removal failed): nothing to do. */
  redeemed: boolean;
  /** Whether an operator has to look at it. */
  needsAttention: boolean;
}

function toRow(marker: SettlementListing, now: number): SettlementRow {
  const idleMs = Math.max(0, now - marker.updatedAt);
  const stale = marker.state === "settling" && idleMs > SETTLING_STALE_MS;
  return {
    paymentId: marker.paymentId,
    state: marker.state,
    stale,
    principalId: marker.principalId,
    label: marker.label,
    credits: marker.credits,
    transaction: settledMarkerClaim(marker)?.transaction ?? null,
    ageMs: Math.max(0, now - marker.at),
    idleMs,
    redeemed: marker.redeemed,
    needsAttention: !marker.redeemed && (marker.state !== "settling" || stale)
  };
}

export interface SettlementList {
  /** At most `limit` rows, oldest update first. */
  rows: SettlementRow[];
  /** More rows than `limit` match. */
  truncated: boolean;
  limit: number;
}

/**
 * Unfinished settlement markers that need an operator, oldest update first; with all, also live settles and
 * leftovers of recorded payments. The database filters before it limits, so with 400-day retention a pile of
 * old live or recorded markers cannot hide the ones that need attention.
 */
export function listSettlements(ledger: CreditLedger, options: { all?: boolean; now?: number; limit?: number } = {}): SettlementList {
  const now = options.now ?? Date.now();
  const limit = options.limit ?? DEFAULT_LIST_LIMIT;
  // One row more than shown tells whether any remain.
  const markers = ledger.listSettlements({ limit: limit + 1, settlingStaleBefore: options.all ? undefined : now - SETTLING_STALE_MS });
  const rows = markers.map((marker) => toRow(marker, now)).filter((row) => options.all || row.needsAttention);
  return { rows: rows.slice(0, limit), truncated: rows.length > limit, limit };
}

export type ResolveResult =
  | { outcome: "credited"; paymentId: string; principalId: string; credits: number; transaction: string }
  | { outcome: "already-recorded"; paymentId: string; principalId: string; transaction: string }
  | { outcome: "failed"; paymentId: string; principalId: string };

/** Runs a write, waiting out a briefly locked database (each attempt already blocks for the busy timeout). */
function withLockRetry<T>(write: () => T, attempts = 5): T {
  for (let attempt = 1; ; attempt++) {
    try {
      return write();
    } catch (err) {
      if (attempt >= attempts || !isLockContention(err)) throw err;
    }
  }
}

function markerToResolve(ledger: CreditLedger, paymentId: string, now: number): SettlementMarker {
  const marker = ledger.getSettlement(paymentId);
  if (!marker) {
    if (ledger.isRedeemed(paymentId, REDEEMED_PAYMENT_RETENTION_MS, now)) throw new CliError(`${paymentId} is already recorded; there is nothing to resolve.`);
    throw new CliError(`There is no settlement marker for ${paymentId}. Run "list --all" to see every marker.`);
  }
  // A server is between /verify and /settle right now; its own answer decides.
  if (marker.state === "settling" && now - marker.updatedAt <= SETTLING_STALE_MS) {
    throw new CliError(`${paymentId} is being settled by a server right now (updated ${formatDuration(now - marker.updatedAt)} ago). Run the command again in a minute.`);
  }
  return marker;
}

/**
 * The operator confirmed the transfer on-chain: records the payment under its transaction guard (the
 * transaction qualified by the authorization's identity, as a server records it) and the payment id, credits
 * the marker's principal unless either was already recorded, and ends the marker. Idempotent.
 */
export function resolveConfirmed(ledger: CreditLedger, paymentId: string, options: { tx: string; nonce?: string | null; now?: number }): ResolveResult {
  const now = options.now ?? Date.now();
  const tx = options.tx.trim();
  if (!tx) throw new UsageError("--tx needs the transaction hash.");
  const marker = markerToResolve(ledger, paymentId, now);
  let claim: X402Claim;
  const settled = marker.state === "settled" ? settledMarkerClaim(marker) : null;
  if (settled) {
    // The server learned the transaction itself; the operator's must be the same one.
    if (settled.transaction.toLowerCase() !== tx.toLowerCase() && marker.tx?.toLowerCase() !== tx.toLowerCase()) {
      throw new CliError(`${paymentId} settled as transaction ${settled.transaction}, not ${tx}.`);
    }
    claim = settled;
  } else {
    const given = options.nonce ? x402NonceIdentity(options.nonce) : null;
    if (options.nonce && !given) throw new UsageError("--nonce needs the authorization's nonce.");
    // A stored identity is `<payer>.<nonce>` (or the nonce alone when the payer was unknown); --nonce names the nonce part.
    if (marker.identity && given && x402IdentityNonce(marker.identity) !== given) throw new CliError(`--nonce does not match the authorization ${paymentId} was claimed with.`);
    // Without a stored identity the payer is not known here, so the payment is recorded under the nonce-only guard.
    // Every payer-qualified guard of the same transaction and nonce yields to it, and it yields to every such
    // guard already recorded (x402TransactionGuard's blockedByFamily): a server that credited the same
    // authorization presented with its payer means this one is not credited again, and the reverse.
    const identity = marker.identity ?? given;
    if (!identity) {
      throw new UsageError(`${paymentId} predates markers that record their authorization. Pass --nonce <the EIP-3009 nonce from the payer's X-PAYMENT header or the AuthorizationUsed event>.`);
    }
    const guard = x402TransactionGuard(tx, identity);
    claim = { ids: [guard.guard, paymentId], blockedBy: guard.blockedBy, blockedByFamily: guard.blockedByFamily, transaction: tx };
  }
  const result = withLockRetry(() => ledger.resolveSettlement(marker, claim.ids, claim.blockedBy, now, claim.blockedByFamily));
  if (result === null) throw new CliError(`The marker for ${paymentId} changed while it was being resolved (a server is working on it). Run "list" and try again.`);
  return result.fresh
    ? { outcome: "credited", paymentId, principalId: marker.principalId, credits: marker.credits, transaction: claim.transaction }
    : { outcome: "already-recorded", paymentId, principalId: marker.principalId, transaction: claim.transaction };
}

/**
 * The operator confirmed nothing moved: ends the marker and records the payment id as redeemed, so the same
 * authorization can never settle into credits here later. A 'settled' marker records a transaction (money
 * moved), so it is refused.
 */
export function resolveFailed(ledger: CreditLedger, paymentId: string, options: { now?: number } = {}): ResolveResult {
  const now = options.now ?? Date.now();
  const marker = markerToResolve(ledger, paymentId, now);
  if (marker.state === "settled") {
    const transaction = settledMarkerClaim(marker)?.transaction ?? "unknown";
    throw new CliError(`${paymentId} settled as transaction ${transaction}: money moved. Record it with --tx ${transaction}.`);
  }
  if (!withLockRetry(() => ledger.abandonSettlement(marker, now))) {
    throw new CliError(`The marker for ${paymentId} changed while it was being resolved (a server is working on it). Run "list" and try again.`);
  }
  return { outcome: "failed", paymentId, principalId: marker.principalId };
}

/** Issues a prepaid session token for a principal; its label and balance come from the ledger when one is given. */
export function issueSession(
  secret: string,
  principalId: string,
  options: { ledger?: CreditLedger | null; label?: string | null } = {}
): { token: string; principalId: string; label: string; balance: number | null } {
  const sub = principalId.trim();
  if (!sub) throw new UsageError("session needs a principal id.");
  const account = options.ledger ? options.ledger.account(sub) : null;
  const label = options.label ?? account?.label ?? "";
  const token = new SessionTokenService(secret).issue({ sub, plan: "payg", label });
  return { token, principalId: sub, label, balance: account?.balance ?? null };
}

export function formatDuration(ms: number): string {
  const s = Math.floor(Math.max(0, ms) / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h ${m % 60}m`;
  return `${Math.floor(h / 24)}d ${h % 24}h`;
}

function formatRows(rows: SettlementRow[]): string {
  if (rows.length === 0) return "No settlement markers need attention.\n";
  const table = [
    ["PAYMENT ID", "STATE", "PRINCIPAL", "CREDITS", "AGE", "IDLE", "TX"],
    ...rows.map((r) => [
      r.paymentId,
      r.redeemed ? `${r.state} (recorded)` : r.stale ? "settling (stale)" : r.state,
      r.principalId,
      String(r.credits),
      formatDuration(r.ageMs),
      formatDuration(r.idleMs),
      r.transaction ?? "-"
    ])
  ];
  const widths = table[0]?.map((_, column) => Math.max(...table.map((line) => (line[column] ?? "").length))) ?? [];
  return table.map((line) => line.map((cell, column) => (column === line.length - 1 ? cell : cell.padEnd(widths[column] ?? 0))).join("  ")).join("\n") + "\n";
}

const USAGE = `Usage: settlements <command> [options]

  list [--all] [--json] [--limit <n>]            markers that need an operator, oldest first (--all: every marker)
  resolve <paymentId> --tx <hash> [--nonce <n>]  the transfer happened: credit the marker's principal once
  resolve <paymentId> --failed                   nothing moved: end the marker; the payment can never be credited
  session <principalId> [--label <text>]         issue a prepaid session token (needs STACKDNS_SESSION_SECRET)

Options: --db <file> (default: STACKDNS_DB_FILE), --json, --help
`;

interface ParsedArgs {
  command: string | null;
  positional: string[];
  flags: Map<string, string | true>;
}

const VALUE_FLAGS = new Set(["--db", "--tx", "--nonce", "--label", "--limit"]);
const BOOLEAN_FLAGS = new Set(["--all", "--json", "--failed", "--help", "-h"]);

function parseArgs(argv: string[]): ParsedArgs {
  const parsed: ParsedArgs = { command: null, positional: [], flags: new Map() };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] as string;
    if (VALUE_FLAGS.has(arg)) {
      const value = argv[i + 1];
      if (value === undefined || value.startsWith("--")) throw new UsageError(`${arg} needs a value. Run with --help.`);
      parsed.flags.set(arg, value);
      i++;
    } else if (BOOLEAN_FLAGS.has(arg)) {
      parsed.flags.set(arg, true);
    } else if (arg.startsWith("-")) {
      throw new UsageError(`Unknown option "${arg}". Run with --help.`);
    } else if (parsed.command === null) {
      parsed.command = arg;
    } else {
      parsed.positional.push(arg);
    }
  }
  return parsed;
}

/** A command with its arguments checked, before any database is opened. */
type Command =
  | { name: "list"; all: boolean; limit: number }
  /** tx is null for --failed. */
  | { name: "resolve"; paymentId: string; tx: string | null; nonce: string | null }
  | { name: "session"; principalId: string; label: string | null };

function parseCommand(args: ParsedArgs & { command: string }): Command {
  const flag = (name: string): string | null => {
    const value = args.flags.get(name);
    return typeof value === "string" ? value : null;
  };
  switch (args.command) {
    case "list": {
      if (args.positional.length > 0) throw new UsageError("list takes no arguments. Run with --help.");
      const raw = flag("--limit");
      const limit = raw === null ? DEFAULT_LIST_LIMIT : parseSafeInteger(raw);
      if (limit === null || limit < 1) throw new UsageError("--limit needs a positive whole number.");
      return { name: "list", all: args.flags.has("--all"), limit };
    }
    case "resolve": {
      const paymentId = args.positional[0];
      if (!paymentId || args.positional.length > 1) throw new UsageError("resolve needs exactly one payment id. Run with --help.");
      const tx = flag("--tx");
      if ((tx === null) === !args.flags.has("--failed")) throw new UsageError("resolve needs either --tx <hash> or --failed.");
      return { name: "resolve", paymentId, tx, nonce: flag("--nonce") };
    }
    case "session": {
      const principalId = args.positional[0];
      if (!principalId || args.positional.length > 1) throw new UsageError("session needs exactly one principal id. Run with --help.");
      return { name: "session", principalId, label: flag("--label") };
    }
    default:
      throw new UsageError(`Unknown command "${args.command}".\n\n${USAGE}`);
  }
}

export interface CliIo {
  out(text: string): void;
  err(text: string): void;
}

/** Runs one command; returns the process exit code (0 done, 1 refused or failed, 2 bad usage). */
export async function main(argv: string[], env: NodeJS.ProcessEnv, io: CliIo): Promise<number> {
  let args: ParsedArgs;
  let command: Command;
  try {
    args = parseArgs(argv);
    if (args.flags.has("--help") || args.flags.has("-h")) {
      io.out(USAGE);
      return 0;
    }
    if (args.command === null) {
      io.err(USAGE);
      return 2;
    }
    command = parseCommand({ ...args, command: args.command });
  } catch (err) {
    io.err(`${(err as Error).message}\n`);
    return 2;
  }
  const json = args.flags.has("--json");
  const dbFlag = args.flags.get("--db");

  let ledger: CreditLedger | null = null;
  let close = (): void => undefined;
  // Startup chatter (a migration applied on open) would bury the answer; warnings still show.
  const previousLevel = getLogLevel();
  if (previousLevel === "debug" || previousLevel === "info") setLogLevel("warn");
  try {
    const config = loadConfig(env, []);
    const dbFile = typeof dbFlag === "string" ? dbFlag : config.storage.dbFile;
    const needsDb = command.name !== "session";
    if (dbFile === null) {
      if (needsDb) throw new CliError("STACKDNS_DB_FILE is disabled: settlement markers then live in the server's usage file, which this tool does not edit. Point --db at the shared database.");
    } else if (dbFile !== ":memory:" && !existsSync(dbFile)) {
      if (needsDb) throw new CliError(`Database file ${path.resolve(dbFile)} does not exist. Set STACKDNS_DB_FILE (or --db) to the servers' database.`);
    } else {
      const db = await openDatabase(dbFile);
      if (!db) throw new CliError(`Database file ${path.resolve(dbFile)} could not be opened.`);
      ledger = new CreditLedger(db);
      close = () => db.close();
    }

    if (command.name === "list") {
      const list = listSettlements(ledger as CreditLedger, { all: command.all, limit: command.limit });
      io.out(json ? `${JSON.stringify(list.rows, null, 2)}\n` : formatRows(list.rows));
      if (list.truncated) {
        io.err(`Showing the ${list.limit} oldest; more markers ${command.all ? "exist" : "need attention"}. Resolve these first, or run with --limit <n> to see more.\n`);
      }
      return 0;
    }

    if (command.name === "resolve") {
      const { paymentId, tx } = command;
      const result = tx === null ? resolveFailed(ledger as CreditLedger, paymentId) : resolveConfirmed(ledger as CreditLedger, paymentId, { tx, nonce: command.nonce });
      if (json) io.out(`${JSON.stringify(result, null, 2)}\n`);
      else if (result.outcome === "credited") io.out(`Recorded ${paymentId} (transaction ${result.transaction}): ${result.credits} credits granted to ${result.principalId}.\n`);
      else if (result.outcome === "already-recorded") io.out(`Recorded ${paymentId} (transaction ${result.transaction}); no credits granted: the transaction or payment was already recorded.\n`);
      else io.out(`Marked ${paymentId} as failed: it can never be credited. A payer whose authorization is still valid can pay again with a new authorization.\n`);
      return 0;
    }

    if (config.auth.sessionSecretGenerated) throw new CliError("STACKDNS_SESSION_SECRET is required: the token must be signed with the secret the HTTP servers use.");
    const session = issueSession(config.auth.sessionSecret, command.principalId, { ledger, label: command.label });
    if (json) io.out(`${JSON.stringify(session, null, 2)}\n`);
    else {
      io.out(`${session.token}\n`);
      io.err(`Session token for ${session.principalId} (balance: ${session.balance === null ? "no prepaid account" : `${session.balance} credits`}). Send it as Authorization: Bearer <token>.\n`);
    }
    return 0;
  } catch (err) {
    io.err(`${err instanceof CliError ? err.message : `settlements failed: ${(err as Error).message}`}\n`);
    // A flag the command turned out to need (--nonce for a marker that predates them) is bad usage too.
    return err instanceof UsageError ? 2 : 1;
  } finally {
    close();
    setLogLevel(previousLevel);
  }
}

function invokedDirectly(): boolean {
  const script = process.argv[1];
  if (!script) return false;
  return pathToFileURL(path.resolve(script)).href.toLowerCase() === import.meta.url.toLowerCase();
}

if (invokedDirectly()) {
  void main(process.argv.slice(2), process.env, { out: (text) => process.stdout.write(text), err: (text) => process.stderr.write(text) }).then((code) => {
    process.exitCode = code;
  });
}
