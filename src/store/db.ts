/**
 * SQLite storage via the built-in node:sqlite module.
 *
 * The module is loaded dynamically so the server still starts on Node.js
 * releases that lack it (or where opening the file fails): storage-backed
 * features are then disabled with a warning instead of crashing the process.
 * Schema changes are applied as numbered migrations recorded in the meta
 * table, so an existing database upgrades in place.
 */

import { mkdirSync } from "node:fs";
import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { logger } from "../logger.js";
import { MIGRATIONS } from "./migrations.js";

export type Database = DatabaseSync;

export interface Migration {
  version: number;
  description: string;
  sql: string;
}

export { MIGRATIONS } from "./migrations.js";

function schemaVersion(db: Database): number {
  db.exec("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)");
  const row = db.prepare("SELECT value FROM meta WHERE key = 'schema_version'").get() as { value?: string } | undefined;
  const version = Number(row?.value ?? 0);
  return Number.isInteger(version) && version >= 0 ? version : 0;
}

/**
 * Applies every migration newer than the database's recorded version, each
 * in its own transaction. The version is re-read after the write lock is
 * taken, so a second process that starts while the first is migrating skips
 * what the first already applied instead of re-running it.
 */
export function migrate(db: Database, migrations: Migration[] = MIGRATIONS): number {
  let current = schemaVersion(db);
  for (const migration of [...migrations].sort((a, b) => a.version - b.version)) {
    if (migration.version <= current) continue;
    const applied = transaction(db, () => {
      if (schemaVersion(db) >= migration.version) return false;
      db.exec(migration.sql);
      db.prepare("INSERT INTO meta (key, value) VALUES ('schema_version', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").run(String(migration.version));
      return true;
    });
    if (applied) logger.info("database migrated", { version: migration.version, description: migration.description });
    current = Math.max(current, migration.version);
  }
  return current;
}

/**
 * Runs fn inside a write transaction. fn must be synchronous: node:sqlite is
 * synchronous, and an await inside would let another request interleave
 * statements into this transaction.
 */
export function transaction<T>(db: Database, fn: () => T): T {
  db.exec("BEGIN IMMEDIATE");
  try {
    const result = fn();
    db.exec("COMMIT");
    return result;
  } catch (err) {
    try {
      db.exec("ROLLBACK");
    } catch {
      // the failed statement may already have ended the transaction
    }
    throw err;
  }
}

/** How long a statement waits for another connection's write lock before failing; recording is best-effort, so this stays short. */
export const BUSY_TIMEOUT_MS = 1000;
const OPEN_RETRY_BASE_MS = 100;
/** How long a locked database is waited out at startup (a sibling's migration, a VACUUM). */
export const OPEN_LOCK_BUDGET_MS = 120_000;

export function isLockContention(err: unknown): boolean {
  const message = err instanceof Error ? err.message : String(err);
  return /database is locked|SQLITE_BUSY|database table is locked/i.test(message);
}

/**
 * Opens (creating if needed) and migrates the database, or returns null when
 * SQLite is unavailable or the file cannot be used. Several processes may
 * open the same new file at once: switching it to WAL and migrating it need
 * a brief exclusive lock that a busy handler does not wait for, so lock
 * contention is retried with backoff instead of disabling storage.
 */
export async function openDatabase(file: string, lockBudgetMs: number = OPEN_LOCK_BUDGET_MS): Promise<Database | null> {
  let sqlite: typeof import("node:sqlite");
  try {
    sqlite = await import("node:sqlite");
  } catch (err) {
    logger.warn("node:sqlite is unavailable (Node.js 22.13 or later is required); stored scans, bulk checks, monitoring and reverse lookup are disabled", { error: err });
    return null;
  }
  try {
    if (file !== ":memory:") mkdirSync(path.dirname(path.resolve(file)), { recursive: true });
  } catch (err) {
    logger.warn("database directory could not be created; storage-backed features are disabled", { file, error: err });
    return null;
  }
  const started = Date.now();
  for (let attempt = 1; ; attempt++) {
    let db: Database | null = null;
    try {
      db = new sqlite.DatabaseSync(file);
      db.exec(`PRAGMA busy_timeout = ${BUSY_TIMEOUT_MS};`);
      db.exec("PRAGMA journal_mode = WAL;");
      db.exec("PRAGMA synchronous = NORMAL; PRAGMA foreign_keys = ON;");
      migrate(db);
      return db;
    } catch (err) {
      // Always release the handle: on Windows an open handle keeps a corrupt file undeletable.
      try {
        db?.close();
      } catch {
        // already closed or never opened
      }
      if (isLockContention(err)) {
        if (Date.now() - started < lockBudgetMs) {
          await new Promise((resolve) => setTimeout(resolve, Math.min(OPEN_RETRY_BASE_MS * attempt, 2000) + Math.floor(Math.random() * OPEN_RETRY_BASE_MS)));
          continue;
        }
        // Running without the shared database next to processes that use it
        // would put credits and redeemed payments on a private ledger.
        throw new Error("database stayed locked by another process; refusing to start without the shared database", { cause: err });
      }
      logger.warn("database could not be opened; storage-backed features are disabled", { file, error: err, attempts: attempt });
      return null;
    }
  }
}
