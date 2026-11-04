/**
 * Signature loading, compilation and matching engine.
 *
 * Patterns follow the Wappalyzer convention: a regular expression string,
 * optionally followed by "\;version:\N" to capture a version from group N.
 * All patterns are compiled case-insensitively at load time; invalid
 * patterns are logged and skipped so one bad entry cannot disable detection.
 */

import { logger } from "../logger.js";
import { SignatureDatabaseSchema, type Signature } from "./schema.js";
import rawDatabase from "./signatures.json" with { type: "json" };

export type EvidenceType = "html" | "script" | "header" | "cookie" | "meta" | "implied";

export interface CompiledPattern {
  source: string;
  regex: RegExp;
  versionGroup: number | null;
}

export interface CompiledSignature {
  id: string;
  name: string;
  category: string;
  website: string | null;
  confidence: number;
  html: CompiledPattern[];
  scripts: CompiledPattern[];
  headers: Array<{ name: string; pattern: CompiledPattern | null }>;
  cookies: CompiledPattern[];
  meta: Array<{ name: string; pattern: CompiledPattern }>;
  implies: string[];
  excludes: string[];
}

export interface Evidence {
  type: EvidenceType;
  pattern: string;
  sample: string;
}

export interface Detection {
  id: string;
  name: string;
  category: string;
  categoryLabel: string;
  website: string | null;
  confidence: number;
  version: string | null;
  implied: boolean;
  evidence: Evidence[];
}

export interface PageEvidence {
  html: string;
  scripts: string[];
  headers: Record<string, string>;
  cookies: string[];
  meta: Record<string, string[]>;
}

const MAX_HTML_SCAN_BYTES = 1000000;
const MAX_SAMPLE_LENGTH = 120;
const MAX_SCRIPTS = 600;
const MAX_META = 300;

let cachedDatabase: { version: string; categories: Record<string, string>; signatures: CompiledSignature[] } | null = null;

function compilePattern(source: string, context: string): CompiledPattern | null {
  const segments = source.split("\\;");
  const regexSource = segments[0] ?? "";
  let versionGroup: number | null = null;
  for (const segment of segments.slice(1)) {
    const match = /^version:\\(\d+)$/.exec(segment.trim());
    if (match) versionGroup = Number(match[1]);
  }
  if (regexSource.length === 0) return null;
  try {
    return { source, regex: new RegExp(regexSource, "i"), versionGroup };
  } catch (err) {
    logger.warn("signature pattern failed to compile", { context, pattern: source, error: (err as Error).message });
    return null;
  }
}

function compileSignature(signature: Signature): CompiledSignature {
  const ctx = signature.id;
  const compileList = (patterns: string[], kind: string): CompiledPattern[] => patterns.map((p) => compilePattern(p, `${ctx}.${kind}`)).filter((p): p is CompiledPattern => p !== null);
  // An empty pattern means "header present"; a non-empty pattern that fails
  // to compile is dropped entirely rather than degrading to a presence match.
  const headers = Object.entries(signature.headers)
    .map(([name, pattern]) => ({
      name: name.toLowerCase(),
      pattern: pattern.length === 0 ? null : compilePattern(pattern, `${ctx}.headers.${name}`),
      presence: pattern.length === 0
    }))
    .filter((h) => h.presence || h.pattern !== null)
    .map(({ name, pattern }) => ({ name, pattern }));
  const meta = Object.entries(signature.meta)
    .map(([name, pattern]) => ({ name: name.toLowerCase(), pattern: compilePattern(pattern, `${ctx}.meta.${name}`) }))
    .filter((m): m is { name: string; pattern: CompiledPattern } => m.pattern !== null);
  return {
    id: signature.id,
    name: signature.name,
    category: signature.category,
    website: signature.website ?? null,
    confidence: signature.confidence,
    html: compileList(signature.html, "html"),
    scripts: compileList(signature.scripts, "scripts"),
    headers,
    cookies: compileList(signature.cookies, "cookies"),
    meta,
    implies: signature.implies,
    excludes: signature.excludes
  };
}

export function loadSignatureDatabase(): { version: string; categories: Record<string, string>; signatures: CompiledSignature[] } {
  if (cachedDatabase) return cachedDatabase;
  const parsed = SignatureDatabaseSchema.safeParse(rawDatabase);
  if (!parsed.success) {
    throw new Error(`signatures.json is invalid: ${parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ")}`);
  }
  const ids = new Set<string>();
  for (const signature of parsed.data.signatures) {
    if (ids.has(signature.id)) throw new Error(`signatures.json contains duplicate id "${signature.id}"`);
    ids.add(signature.id);
    if (!(signature.category in parsed.data.categories)) {
      throw new Error(`signature "${signature.id}" uses unknown category "${signature.category}"`);
    }
  }
  cachedDatabase = {
    version: parsed.data.version,
    categories: parsed.data.categories,
    signatures: parsed.data.signatures.map(compileSignature)
  };
  logger.debug("signature database loaded", { version: cachedDatabase.version, count: cachedDatabase.signatures.length });
  return cachedDatabase;
}

export function signatureCount(): number {
  return loadSignatureDatabase().signatures.length;
}

function decodeEntities(value: string): string {
  return value
    .replace(/&amp;/g, "&")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">");
}

function attribute(tag: string, name: string): string | null {
  const match = new RegExp(`\\s${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s"'>]+))`, "i").exec(tag);
  if (!match) return null;
  return decodeEntities(match[1] ?? match[2] ?? match[3] ?? "");
}

export function extractEvidence(html: string, headers: Record<string, string>, setCookies: string[]): PageEvidence {
  const scanned = html.length > MAX_HTML_SCAN_BYTES ? html.slice(0, MAX_HTML_SCAN_BYTES) : html;
  const scripts: string[] = [];
  const scriptTag = /<script\b[^>]*>/gi;
  let match: RegExpExecArray | null;
  while ((match = scriptTag.exec(scanned)) !== null && scripts.length < MAX_SCRIPTS) {
    const src = attribute(match[0], "src");
    if (src) scripts.push(src);
  }
  const linkTag = /<link\b[^>]*>/gi;
  while ((match = linkTag.exec(scanned)) !== null && scripts.length < MAX_SCRIPTS) {
    const href = attribute(match[0], "href");
    const rel = (attribute(match[0], "rel") ?? "").toLowerCase();
    if (href && (rel.includes("preload") || rel.includes("modulepreload") || rel.includes("stylesheet") || rel.includes("preconnect") || rel.includes("dns-prefetch"))) {
      scripts.push(href);
    }
  }

  // Null prototype: meta names are attacker-controlled page content, so
  // "constructor" or "__proto__" must not resolve through Object.prototype.
  const meta: Record<string, string[]> = Object.create(null) as Record<string, string[]>;
  const metaTag = /<meta\b[^>]*>/gi;
  let metaCount = 0;
  while ((match = metaTag.exec(scanned)) !== null && metaCount < MAX_META) {
    const name = (attribute(match[0], "name") ?? attribute(match[0], "property") ?? attribute(match[0], "http-equiv") ?? "").toLowerCase();
    const content = attribute(match[0], "content");
    if (!name || content === null) continue;
    (meta[name] ??= []).push(content);
    metaCount++;
  }

  const cookies = setCookies.map((cookie) => cookie.split(";")[0]?.split("=")[0]?.trim() ?? "").filter((name) => name.length > 0);

  // Null prototype for the same reason as meta: a header (or a signature)
  // named "constructor" must not resolve through Object.prototype.
  const normalizedHeaders: Record<string, string> = Object.create(null) as Record<string, string>;
  for (const [key, value] of Object.entries(headers)) if (typeof value === "string") normalizedHeaders[key.toLowerCase()] = value;

  return { html: scanned, scripts, headers: normalizedHeaders, cookies, meta };
}

function sampleAround(text: string, index: number, length: number): string {
  const start = Math.max(0, index - 30);
  const end = Math.min(text.length, index + length + 60);
  const snippet = text.slice(start, end).replace(/\s+/g, " ").trim();
  return snippet.length > MAX_SAMPLE_LENGTH ? `${snippet.slice(0, MAX_SAMPLE_LENGTH)}...` : snippet;
}

function extractVersion(pattern: CompiledPattern, match: RegExpExecArray): string | null {
  if (pattern.versionGroup === null) return null;
  const value = match[pattern.versionGroup];
  if (typeof value !== "string" || value.length === 0) return null;
  const cleaned = value.trim().replace(/^v/i, "");
  return /^[\w.+-]{1,32}$/.test(cleaned) ? cleaned : null;
}

interface MatchState {
  evidence: Evidence[];
  version: string | null;
}

/** Records one successful pattern hit and keeps the first version any pattern captured. */
function recordMatch(state: MatchState, type: EvidenceType, pattern: CompiledPattern, match: RegExpExecArray, patternLabel: string, sample: string): void {
  state.evidence.push({ type, pattern: patternLabel, sample });
  const version = extractVersion(pattern, match);
  if (version && !state.version) state.version = version;
}

function execPattern(pattern: CompiledPattern, target: string): RegExpExecArray | null {
  pattern.regex.lastIndex = 0;
  return pattern.regex.exec(target);
}

function testPatterns(patterns: CompiledPattern[], type: EvidenceType, targets: string[], state: MatchState): void {
  for (const pattern of patterns) {
    for (const target of targets) {
      const match = execPattern(pattern, target);
      if (!match) continue;
      recordMatch(state, type, pattern, match, pattern.source, sampleAround(target, match.index, match[0].length));
      break;
    }
  }
}

export function matchSignature(signature: CompiledSignature, evidence: PageEvidence): MatchState | null {
  const state: MatchState = { evidence: [], version: null };
  testPatterns(signature.html, "html", [evidence.html], state);
  testPatterns(signature.scripts, "script", evidence.scripts, state);
  testPatterns(signature.cookies, "cookie", evidence.cookies, state);
  for (const header of signature.headers) {
    const value = evidence.headers[header.name];
    if (value === undefined) continue;
    const sample = `${header.name}: ${value.slice(0, MAX_SAMPLE_LENGTH)}`;
    if (header.pattern === null) {
      state.evidence.push({ type: "header", pattern: `${header.name}: *`, sample });
      continue;
    }
    const match = execPattern(header.pattern, value);
    if (match) recordMatch(state, "header", header.pattern, match, `${header.name}: ${header.pattern.source}`, sample);
  }
  for (const meta of signature.meta) {
    const values = evidence.meta[meta.name];
    if (!values) continue;
    for (const value of values) {
      const match = execPattern(meta.pattern, value);
      if (!match) continue;
      recordMatch(state, "meta", meta.pattern, match, `${meta.name}: ${meta.pattern.source}`, `${meta.name}: ${value.slice(0, MAX_SAMPLE_LENGTH)}`);
      break;
    }
  }
  return state.evidence.length > 0 ? state : null;
}

/** Builds a detection from a signature; direct and implied detections differ only in the fields passed here. */
function toDetection(signature: CompiledSignature, categories: Record<string, string>, fields: { confidence: number; version: string | null; implied: boolean; evidence: Evidence[] }): Detection {
  return {
    id: signature.id,
    name: signature.name,
    category: signature.category,
    categoryLabel: categories[signature.category] ?? signature.category,
    website: signature.website,
    ...fields
  };
}

export function detectTechnologies(evidence: PageEvidence): Detection[] {
  const db = loadSignatureDatabase();
  const byId = new Map(db.signatures.map((s) => [s.id, s] as const));
  const detections = new Map<string, Detection>();

  for (const signature of db.signatures) {
    const match = matchSignature(signature, evidence);
    if (!match) continue;
    detections.set(signature.id, toDetection(signature, db.categories, { confidence: signature.confidence, version: match.version, implied: false, evidence: match.evidence }));
  }

  // Resolve implications transitively.
  let changed = true;
  let guard = 0;
  while (changed && guard++ < 10) {
    changed = false;
    for (const detection of [...detections.values()]) {
      const signature = byId.get(detection.id);
      if (!signature) continue;
      for (const impliedId of signature.implies) {
        if (detections.has(impliedId)) continue;
        const implied = byId.get(impliedId);
        if (!implied) continue;
        detections.set(
          impliedId,
          toDetection(implied, db.categories, {
            confidence: Math.min(detection.confidence, implied.confidence, 90),
            version: null,
            implied: true,
            evidence: [{ type: "implied", pattern: `implied by ${detection.name}`, sample: detection.name }]
          })
        );
        changed = true;
      }
    }
  }

  // Apply exclusions: a directly-detected signature removes the ones it excludes.
  for (const detection of [...detections.values()]) {
    if (detection.implied) continue;
    const signature = byId.get(detection.id);
    if (!signature) continue;
    for (const excludedId of signature.excludes) {
      const excluded = detections.get(excludedId);
      if (excluded && (excluded.implied || excluded.confidence <= detection.confidence)) detections.delete(excludedId);
    }
  }

  return [...detections.values()].sort((a, b) => {
    if (a.categoryLabel !== b.categoryLabel) return a.categoryLabel.localeCompare(b.categoryLabel);
    if (a.confidence !== b.confidence) return b.confidence - a.confidence;
    return a.name.localeCompare(b.name);
  });
}
