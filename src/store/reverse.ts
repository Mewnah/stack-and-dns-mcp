/**
 * Reverse technology lookup: which domains use a given technology. Answers
 * come only from crawl_tech, which the crawler alone writes, for domains on
 * its seed list: customers' lookups, bulk jobs and monitor scans never
 * surface here, not even their timestamps for a seed-list domain.
 */

import { ToolError } from "../lib/errors.js";
import type { Database } from "./db.js";

export interface TechnologyUser {
  domain: string;
  version: string | null;
  active: boolean;
  firstSeen: string;
  lastSeen: string;
  removedAt: string | null;
}

export interface ReverseQuery {
  techId: string;
  /** Only domains where the technology is still present (default true). */
  activeOnly?: boolean;
  /** Only domains where the technology was seen at or after this time. */
  seenSince?: number | null;
  limit?: number;
  cursor?: string | null;
}

interface Row {
  domain: string;
  version: string | null;
  active: number;
  first_seen: number;
  last_seen: number;
  removed_at: number | null;
}

function iso(ms: number): string {
  return new Date(ms).toISOString();
}

/** Opaque keyset cursor: the (last_seen, domain) of the last row returned. */
function encodeCursor(lastSeen: number, domain: string): string {
  return Buffer.from(JSON.stringify([lastSeen, domain]), "utf8").toString("base64url");
}

function decodeCursor(cursor: string): { lastSeen: number; domain: string } {
  try {
    const value = JSON.parse(Buffer.from(cursor, "base64url").toString("utf8")) as unknown;
    if (Array.isArray(value) && typeof value[0] === "number" && Number.isFinite(value[0]) && typeof value[1] === "string") return { lastSeen: value[0], domain: value[1] };
  } catch {
    // fall through
  }
  throw new ToolError("INVALID_ARGUMENT", "cursor is not a value returned by a previous call.");
}

export class ReverseLookup {
  constructor(private readonly db: Database) {}

  /** Domains on the crawl list that use the technology, most recently seen first. */
  findDomains(query: ReverseQuery): { domains: TechnologyUser[]; total: number; nextCursor: string | null } {
    const limit = Math.max(1, Math.min(500, Math.floor(query.limit ?? 50)));
    const activeOnly = query.activeOnly !== false;
    const since = query.seenSince ?? 0;
    const where = ["t.tech_id = ?", "t.last_seen >= ?"];
    const params: Array<string | number> = [query.techId, since];
    if (activeOnly) where.push("t.active = 1");
    const total = Number((this.db.prepare(`SELECT COUNT(*) AS n FROM crawl_tech t JOIN crawl_targets c ON c.domain = t.domain WHERE ${where.join(" AND ")}`).get(...params) as { n: number }).n);
    if (query.cursor) {
      const after = decodeCursor(query.cursor);
      where.push("(t.last_seen < ? OR (t.last_seen = ? AND t.domain > ?))");
      params.push(after.lastSeen, after.lastSeen, after.domain);
    }
    const rows = this.db
      .prepare(
        `SELECT t.domain, t.version, t.active, t.first_seen, t.last_seen, t.removed_at FROM crawl_tech t JOIN crawl_targets c ON c.domain = t.domain WHERE ${where.join(" AND ")} ORDER BY t.last_seen DESC, t.domain ASC LIMIT ?`
      )
      .all(...params, limit + 1) as unknown as Row[];
    const page = rows.slice(0, limit);
    const last = page.at(-1);
    return {
      domains: page.map((r) => ({
        domain: r.domain,
        version: r.version,
        active: r.active === 1,
        firstSeen: iso(r.first_seen),
        lastSeen: iso(r.last_seen),
        removedAt: r.removed_at === null ? null : iso(r.removed_at)
      })),
      total,
      nextCursor: rows.length > limit && last ? encodeCursor(last.last_seen, last.domain) : null
    };
  }

  /** How many crawl-list domains currently use each technology. */
  counts(): Map<string, number> {
    const rows = this.db
      .prepare("SELECT t.tech_id AS id, COUNT(*) AS n FROM crawl_tech t JOIN crawl_targets c ON c.domain = t.domain WHERE t.active = 1 GROUP BY t.tech_id")
      .all() as unknown as Array<{ id: string; n: number }>;
    return new Map(rows.map((r) => [r.id, Number(r.n)]));
  }

  /** The size of the searchable universe: domains on the crawl list, and how many have a successful homepage scan. */
  universe(): { domains: number; scanned: number } {
    const domains = Number((this.db.prepare("SELECT COUNT(*) AS n FROM crawl_targets").get() as { n: number }).n);
    const scanned = Number((this.db.prepare("SELECT COUNT(*) AS n FROM crawl_targets WHERE tech_ok_at IS NOT NULL").get() as { n: number }).n);
    return { domains, scanned };
  }
}
