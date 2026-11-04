/**
 * A time-limited lease stored in the database, so that exactly one process
 * sharing a database file runs the background workers (the bulk-check pool
 * and the domain monitor). Several stdio servers spawned by one MCP client,
 * or a rolling deploy that briefly runs two HTTP servers, would otherwise
 * claim the same work twice.
 *
 * The holder renews the lease well inside its lifetime; if it dies, another
 * process takes over once the lease expires.
 */

import { randomBytes } from "node:crypto";
import { transaction, type Database } from "./db.js";

interface LeaseValue {
  owner: string;
  expiresAt: number;
}

export class WorkerLease {
  readonly owner: string;
  private readonly key: string;

  constructor(
    private readonly db: Database,
    name: string,
    private readonly ttlMs: number,
    owner: string = `${process.pid}:${randomBytes(6).toString("hex")}`
  ) {
    this.owner = owner;
    this.key = `lease:${name}`;
  }

  private read(): LeaseValue | null {
    const row = this.db.prepare("SELECT value FROM meta WHERE key = ?").get(this.key) as { value: string } | undefined;
    if (!row) return null;
    try {
      const parsed = JSON.parse(row.value) as Partial<LeaseValue>;
      return typeof parsed.owner === "string" && typeof parsed.expiresAt === "number" ? { owner: parsed.owner, expiresAt: parsed.expiresAt } : null;
    } catch {
      return null;
    }
  }

  /** Takes or renews the lease. Returns true while this process holds it. */
  tryAcquire(now: number = Date.now()): boolean {
    return transaction(this.db, () => {
      const current = this.read();
      if (current && current.owner !== this.owner && current.expiresAt > now) return false;
      const value: LeaseValue = { owner: this.owner, expiresAt: now + this.ttlMs };
      this.db.prepare("INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").run(this.key, JSON.stringify(value));
      return true;
    });
  }

  /** Gives the lease up so another process can take over at once instead of waiting for it to expire. */
  release(): void {
    transaction(this.db, () => {
      if (this.read()?.owner === this.owner) this.db.prepare("DELETE FROM meta WHERE key = ?").run(this.key);
    });
  }
}
