/**
 * MCP tool handlers for the reverse technology lookup. A technology can be
 * named by signature id ("shopify") or display name ("Shopify"); anything
 * ambiguous is answered with the candidates so the agent can pick one.
 */

import { ToolError } from "../lib/errors.js";
import type { ToolContext } from "../middleware/metering.js";
import { loadSignatureDatabase } from "../signatures/index.js";
import type { Crawler } from "../store/crawler.js";
import type { ReverseLookup, TechnologyUser } from "../store/reverse.js";

export interface TechnologyRef {
  id: string;
  name: string;
  category: string;
  categoryLabel: string;
}

const DAY_MS = 24 * 60 * 60 * 1000;
const CANDIDATES_SHOWN = 10;

function catalog(): TechnologyRef[] {
  const db = loadSignatureDatabase();
  return db.signatures.map((s) => ({ id: s.id, name: s.name, category: s.category, categoryLabel: db.categories[s.category] ?? s.category }));
}

function normalize(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "");
}

/** Resolves a technology by exact id, exact name, or a single partial match. */
export function resolveTechnology(query: string): TechnologyRef {
  const all = catalog();
  const wanted = query.trim().toLowerCase();
  const exact = all.find((t) => t.id.toLowerCase() === wanted) ?? all.find((t) => t.name.toLowerCase() === wanted);
  if (exact) return exact;
  const key = normalize(query);
  if (!key) throw new ToolError("INVALID_ARGUMENT", 'Name a technology, e.g. "Shopify" or "klaviyo".');
  const normalizedExact = all.filter((t) => normalize(t.id) === key || normalize(t.name) === key);
  if (normalizedExact.length === 1) return normalizedExact[0] as TechnologyRef;
  const partial = all.filter((t) => normalize(t.id).includes(key) || normalize(t.name).includes(key));
  if (partial.length === 1) return partial[0] as TechnologyRef;
  if (partial.length === 0) {
    throw new ToolError("INVALID_ARGUMENT", `No technology matches "${query.slice(0, 100)}". Use list_technologies to browse the ${all.length} known technologies.`);
  }
  throw new ToolError("INVALID_ARGUMENT", `"${query.slice(0, 100)}" matches ${partial.length} technologies; pass one of the ids in details.candidates.`, {
    details: { candidates: partial.slice(0, CANDIDATES_SHOWN).map((t) => ({ id: t.id, name: t.name, category: t.categoryLabel })) }
  });
}

export async function findDomainsUsing(
  args: { technology: string; activeOnly: boolean; seenWithinDays?: number | undefined; limit: number; cursor?: string | undefined },
  reverse: ReverseLookup,
  crawler: Crawler | null,
  _ctx: ToolContext
): Promise<{
  technology: TechnologyRef;
  universe: { domains: number; scanned: number; lastCrawlAt: string | null };
  total: number;
  domains: TechnologyUser[];
  nextCursor: string | null;
  billing: null;
}> {
  const technology = resolveTechnology(args.technology);
  const result = reverse.findDomains({
    techId: technology.id,
    activeOnly: args.activeOnly,
    seenSince: args.seenWithinDays ? Date.now() - args.seenWithinDays * DAY_MS : null,
    limit: args.limit,
    cursor: args.cursor ?? null
  });
  return {
    technology,
    universe: { ...reverse.universe(), lastCrawlAt: crawler?.lastCrawlAt() ?? null },
    total: result.total,
    domains: result.domains,
    nextCursor: result.nextCursor,
    billing: null
  };
}

export async function listTechnologies(
  args: { query?: string | undefined; category?: string | undefined; limit: number },
  reverse: ReverseLookup,
  _ctx: ToolContext
): Promise<{ technologies: Array<TechnologyRef & { domains: number }>; total: number; categories: string[]; billing: null }> {
  const counts = reverse.counts();
  const key = args.query ? normalize(args.query) : "";
  const category = args.category?.trim().toLowerCase() ?? "";
  const all = catalog();
  const matching = all
    .filter((t) => !key || normalize(t.id).includes(key) || normalize(t.name).includes(key))
    .filter((t) => !category || t.category.toLowerCase() === category || t.categoryLabel.toLowerCase() === category)
    .map((t) => ({ ...t, domains: counts.get(t.id) ?? 0 }))
    .sort((a, b) => b.domains - a.domains || a.name.localeCompare(b.name));
  return {
    technologies: matching.slice(0, args.limit),
    total: matching.length,
    categories: [...new Set(all.map((t) => t.categoryLabel))].sort(),
    billing: null
  };
}
