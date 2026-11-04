/**
 * Storage bundle: one SQLite database shared by every storage-backed
 * feature. It is optional; when it cannot be opened the server runs the
 * live inspection tools only.
 */

import type { AppConfig } from "../config.js";
import { logger } from "../logger.js";
import { OPEN_LOCK_BUDGET_MS, openDatabase, type Database } from "./db.js";
import { ScanStore } from "./scanStore.js";

export interface Storage {
  db: Database;
  scans: ScanStore;
  close(): void;
}

const PRUNE_INTERVAL_MS = 24 * 60 * 60 * 1000;
const STARTUP_PRUNE_DELAY_MS = 5_000;

export function createStorage(db: Database, config: AppConfig): Storage {
  const scans = new ScanStore(db, { retentionDays: config.storage.scanRetentionDays });
  let closed = false;
  let pruning = false;
  // Batched and asynchronous: a large backlog never blocks startup or holds
  // the write lock long enough to fail other processes' writes.
  const prune = (): void => {
    if (pruning || closed) return;
    pruning = true;
    scans
      .pruneAsync(Date.now(), () => closed)
      .then(
        (removed) => {
          if (removed.scans + removed.changes + removed.technologies > 0) logger.info("pruned stored scans", removed);
        },
        (err: unknown) => logger.warn("pruning stored scans failed", { error: err })
      )
      .finally(() => {
        pruning = false;
      });
  };
  // Prune shortly after startup as well: stdio servers are respawned per
  // client session and hosted servers restart on deploys, so a daily timer
  // alone might never fire.
  const startup = setTimeout(prune, STARTUP_PRUNE_DELAY_MS);
  startup.unref();
  const timer = setInterval(prune, PRUNE_INTERVAL_MS);
  timer.unref();
  return {
    db,
    scans,
    close(): void {
      if (closed) return;
      closed = true;
      clearTimeout(startup);
      clearInterval(timer);
      try {
        db.close();
      } catch (err) {
        logger.warn("database close failed", { error: err });
      }
    }
  };
}

/** How long a stdio server waits out a locked database before running without storage. */
export const STDIO_LOCK_BUDGET_MS = 15_000;

/**
 * Opens the configured database, or returns null when storage is disabled or
 * unavailable. A database that stays locked past the budget stops an HTTP
 * server (it sells credits, which must live on the shared ledger); a stdio
 * server sells nothing, so it runs without storage instead of exiting.
 */
export async function openStorage(config: AppConfig, lockBudgetMs?: number): Promise<Storage | null> {
  if (config.storage.dbFile === null) {
    logger.info("storage disabled by STACKDNS_DB_FILE=none; only live inspection tools are available");
    return null;
  }
  let db: Database | null;
  try {
    // HTTP waits out a long lock (it refuses to run beside the shared ledger
    // without it); stdio sells nothing and must answer initialize well inside
    // an MCP client's 60 s request timeout, so it gives up sooner.
    db = await openDatabase(config.storage.dbFile, lockBudgetMs ?? (config.transport === "http" ? OPEN_LOCK_BUDGET_MS : STDIO_LOCK_BUDGET_MS));
  } catch (err) {
    if (config.transport === "http") throw err;
    logger.warn("database stayed locked by another process; running without storage (stored scans, bulk checks, monitoring and reverse lookup are disabled)", {
      file: config.storage.dbFile,
      error: err
    });
    return null;
  }
  if (!db) return null;
  const storage = createStorage(db, config);
  logger.info("storage ready", { file: config.storage.dbFile, ...storage.scans.stats() });
  return storage;
}
