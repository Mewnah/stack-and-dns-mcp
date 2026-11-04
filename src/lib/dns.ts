/**
 * Bounded DNS client built on node:dns/promises with automatic fallback and
 * a short answer cache.
 *
 * Every query is bounded twice: c-ares enforces a per-try timeout and a hard
 * Promise race guarantees a single resolver attempt never blocks longer than
 * (timeout * tries). A query that fails on one resolver may be retried once
 * on the other, so the worst case for one query is two attempts. Missing
 * records (ENODATA / NXDOMAIN) are reported as empty results, never as
 * exceptions.
 *
 * Many hosts (Windows VPN clients, container stubs, systemd-resolved) expose
 * a local resolver that the OS lookup path can use but that refuses raw UDP
 * from c-ares. When the primary resolver proves *unreachable* (connection
 * refused/reset, unroutable, or hard timeouts on several distinct names), the
 * client prefers the fallback resolvers for a bounded window; during that
 * window a failing fallback is still retried on the primary, and the first
 * successful primary answer ends the window early. Per-zone answers such as
 * SERVFAIL, or timeouts on a single lame zone, only trigger a one-off retry
 * for that query and never switch the client away from the operator's
 * configured resolvers.
 *
 * Operators running split-horizon resolvers should set
 * STACKDNS_DNS_FALLBACK_SERVERS=none: while the window is active, the public
 * resolvers' NXDOMAIN answers for internal zones are accepted as final.
 *
 * Answers are cached for a short TTL and identical in-flight queries are
 * coalesced, because one audit asks the same questions several times: the
 * existence probe, the MX evaluation and the SPF evaluation all query the
 * apex, and comprehensive_audit runs two tools over one domain. Negative
 * answers (NXDOMAIN / NODATA) are cached too, so an answer obtained from a
 * fallback resolver can outlive the fallback window by up to one TTL;
 * errors are never cached. Cache hits do not touch the fallback state.
 */

import { Resolver } from "node:dns/promises";
import type { CaaRecord, MxRecord, SoaRecord } from "node:dns";
import { logger } from "../logger.js";
import { withTimeout } from "./async.js";
import { registrableDomain } from "./domain.js";
import { errorCode, errorMessage } from "./errors.js";

export type { CaaRecord, MxRecord, SoaRecord };

export interface DnsErrorInfo {
  code: string;
  message: string;
}

export interface DnsResult<T> {
  records: T[];
  nxdomain: boolean;
  error: DnsErrorInfo | null;
  durationMs: number;
}

export interface DnsClientOptions {
  servers?: string[];
  fallbackServers?: string[];
  timeoutMs?: number;
  tries?: number;
  /** How long to prefer the fallback resolvers after the primary proved unreachable. */
  fallbackWindowMs?: number;
  /** How long a successful answer is reused for an identical query; 0 disables the cache. */
  cacheTtlMs?: number;
  /** Builds the underlying resolvers; exists so tests can substitute a scripted resolver. */
  resolverFactory?: (options: { timeout: number; tries: number }) => Resolver;
}

export interface DnsExistence {
  exists: boolean;
  nxdomain: boolean;
  error: DnsErrorInfo | null;
}

export const DEFAULT_FALLBACK_SERVERS: readonly string[] = ["1.1.1.1", "8.8.8.8", "9.9.9.9"];
export const DEFAULT_FALLBACK_WINDOW_MS = 5 * 60 * 1000;
export const DEFAULT_CACHE_TTL_MS = 30 * 1000;
/** Distinct registrable zones that must time out on the primary (with no primary success in between) before it is considered unreachable. */
export const PRIMARY_TIMEOUT_ZONES_BEFORE_FALLBACK = 3;
/** Bound on the zone set so a primary that never answers cannot make it grow without limit. */
const MAX_TRACKED_TIMEOUT_ZONES = 64;
/** Bound on cached answers; one audit touches a few hundred names at most. */
const MAX_CACHE_ENTRIES = 5000;

const EMPTY_RESULT_CODES = new Set(["ENODATA", "ENOTFOUND"]);

/** Errors worth retrying once on the other resolver for this query only. */
const RETRY_CODES = new Set(["ECONNREFUSED", "ECONNRESET", "ETIMEOUT", "EREFUSED", "ESERVFAIL", "ENETUNREACH", "EHOSTUNREACH", "ECANCELLED", "EBADRESP", "ENOTINITIALIZED", "ENOMEM", "EDESTRUCTION"]);

/** Errors that by themselves prove the primary resolver is unreachable. */
const PRIMARY_UNREACHABLE_CODES = new Set(["ECONNREFUSED", "ECONNRESET", "ENETUNREACH", "EHOSTUNREACH", "ENOTINITIALIZED", "EDESTRUCTION"]);

interface Attempt {
  resolver: Resolver;
  isPrimary: boolean;
}

interface CacheEntry {
  expiresAt: number;
  result: DnsResult<unknown>;
}

function copyResult<T>(result: DnsResult<T>, durationMs = result.durationMs): DnsResult<T> {
  return { ...result, records: [...result.records], durationMs };
}

export class DnsClient {
  private readonly primary: Resolver;
  private readonly fallback: Resolver | null;
  private readonly fallbackServers: string[];
  private readonly hardTimeoutMs: number;
  private readonly fallbackWindowMs: number;
  private readonly cacheTtlMs: number;
  private fallbackUntil = 0;
  /** Distinct registrable zones whose names timed out on the primary since its last successful answer. */
  private readonly primaryTimeoutZones = new Set<string>();
  private readonly cache = new Map<string, CacheEntry>();
  private readonly inFlight = new Map<string, Promise<DnsResult<unknown>>>();

  constructor(options: DnsClientOptions = {}) {
    const timeout = options.timeoutMs ?? 3000;
    const tries = options.tries ?? 2;
    const factory = options.resolverFactory ?? ((opts: { timeout: number; tries: number }) => new Resolver(opts));
    this.primary = factory({ timeout, tries });
    if (options.servers && options.servers.length > 0) {
      this.primary.setServers(options.servers);
    }
    this.fallbackServers = (options.fallbackServers ?? [...DEFAULT_FALLBACK_SERVERS]).filter((s) => s.length > 0);
    const primaryServers = this.primary.getServers();
    const sameAsPrimary = this.fallbackServers.length > 0 && this.fallbackServers.every((s) => primaryServers.includes(s));
    if (this.fallbackServers.length > 0 && !sameAsPrimary) {
      this.fallback = factory({ timeout, tries });
      this.fallback.setServers(this.fallbackServers);
    } else {
      this.fallback = null;
    }
    this.hardTimeoutMs = timeout * tries + 250;
    this.fallbackWindowMs = options.fallbackWindowMs ?? DEFAULT_FALLBACK_WINDOW_MS;
    this.cacheTtlMs = Math.max(0, options.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS);
  }

  get servers(): string[] {
    return (this.fallbackActive && this.fallback ? this.fallback : this.primary).getServers();
  }

  /** True while the client prefers the fallback resolvers because the primary was unreachable. */
  get fallbackActive(): boolean {
    return this.fallback !== null && Date.now() < this.fallbackUntil;
  }

  /** Number of cached answers currently held. */
  get cacheSize(): number {
    return this.cache.size;
  }

  private preferFallback(primaryCode: string): void {
    if (!this.fallback) return;
    const wasActive = this.fallbackActive;
    this.fallbackUntil = Date.now() + this.fallbackWindowMs;
    if (!wasActive) {
      logger.warn("primary DNS resolver is unreachable; preferring fallback resolvers for a while", {
        primaryError: primaryCode,
        primary: this.primary.getServers(),
        fallback: this.fallbackServers,
        windowMs: this.fallbackWindowMs
      });
    }
  }

  private notePrimarySuccess(): void {
    this.primaryTimeoutZones.clear();
    if (this.fallbackUntil !== 0) {
      this.fallbackUntil = 0;
      logger.info("primary DNS resolver answered; resuming primary resolvers", { primary: this.primary.getServers() });
    }
  }

  private notePrimaryFailure(code: string, name: string): void {
    if (code === "ETIMEOUT") {
      // Count distinct registrable zones, not queries or names: exists() fires
      // six lookups for one name in parallel and an audit probes dozens of
      // names under one domain, and one lame zone must not flip the client.
      if (!this.fallback) return;
      if (this.fallbackUntil !== 0 && Date.now() >= this.fallbackUntil) {
        // A lapsed window starts a fresh count so stale zones from the
        // previous outage cannot re-arm it on the next single lame zone.
        this.fallbackUntil = 0;
        this.primaryTimeoutZones.clear();
      }
      if (this.primaryTimeoutZones.size >= MAX_TRACKED_TIMEOUT_ZONES) this.primaryTimeoutZones.clear();
      this.primaryTimeoutZones.add(registrableDomain(name));
      if (this.primaryTimeoutZones.size >= PRIMARY_TIMEOUT_ZONES_BEFORE_FALLBACK) this.preferFallback(code);
      return;
    }
    if (PRIMARY_UNREACHABLE_CODES.has(code)) this.preferFallback(code);
  }

  private attemptOrder(): Attempt[] {
    const primary: Attempt = { resolver: this.primary, isPrimary: true };
    if (!this.fallback) return [primary];
    const fallback: Attempt = { resolver: this.fallback, isPrimary: false };
    return this.fallbackActive ? [fallback, primary] : [primary, fallback];
  }

  private async resolve<T>(label: string, name: string, fn: (resolver: Resolver) => Promise<T[]>): Promise<DnsResult<T>> {
    const started = Date.now();
    let firstError: DnsErrorInfo | null = null;
    const attempts = this.attemptOrder();
    for (let i = 0; i < attempts.length; i++) {
      const attempt = attempts[i] as Attempt;
      try {
        const raw: unknown = await withTimeout(fn(attempt.resolver), this.hardTimeoutMs, i === 0 ? label : `${label} (retry)`);
        // node's Resolver always resolves to an array; guard anyway so a
        // malformed answer can never be cached and thrown for a whole TTL.
        const records = Array.isArray(raw) ? (raw as T[]) : [];
        if (attempt.isPrimary) this.notePrimarySuccess();
        return { records, nxdomain: false, error: null, durationMs: Date.now() - started };
      } catch (err) {
        const code = errorCode(err) ?? "EUNKNOWN";
        if (EMPTY_RESULT_CODES.has(code)) {
          if (attempt.isPrimary) this.notePrimarySuccess();
          return { records: [], nxdomain: code === "ENOTFOUND", error: null, durationMs: Date.now() - started };
        }
        if (attempt.isPrimary) this.notePrimaryFailure(code, name);
        if (firstError === null) firstError = { code, message: errorMessage(err) };
        if (!RETRY_CODES.has(code)) break;
      }
    }
    return { records: [], nxdomain: false, error: firstError, durationMs: Date.now() - started };
  }

  private remember(label: string, result: DnsResult<unknown>): void {
    if (this.cacheTtlMs === 0 || result.error !== null) return;
    if (this.cache.size >= MAX_CACHE_ENTRIES) {
      const oldest = this.cache.keys().next().value;
      if (oldest !== undefined) this.cache.delete(oldest);
    }
    this.cache.set(label, { expiresAt: Date.now() + this.cacheTtlMs, result });
  }

  /**
   * Serves an identical query from the cache while its answer is fresh, or
   * joins the identical query already in flight; errors are never cached so
   * a transient failure is retried on the next call.
   */
  private async query<T>(label: string, name: string, fn: (resolver: Resolver) => Promise<T[]>): Promise<DnsResult<T>> {
    const cached = this.cache.get(label);
    if (cached) {
      // A hit did no network work, so it reports zero latency rather than
      // the cold query's.
      if (cached.expiresAt > Date.now()) return copyResult(cached.result as DnsResult<T>, 0);
      this.cache.delete(label);
    }
    const pending = this.inFlight.get(label);
    if (pending) return copyResult((await pending) as DnsResult<T>);
    const run = this.resolve(label, name, fn)
      .then((result) => {
        this.remember(label, result);
        return result as DnsResult<unknown>;
      })
      .finally(() => this.inFlight.delete(label));
    this.inFlight.set(label, run);
    return copyResult((await run) as DnsResult<T>);
  }

  txt(name: string): Promise<DnsResult<string>> {
    return this.query(`TXT ${name}`, name, async (r) => (await r.resolveTxt(name)).map((chunks) => chunks.join("")));
  }

  mx(name: string): Promise<DnsResult<MxRecord>> {
    return this.query(`MX ${name}`, name, (r) => r.resolveMx(name));
  }

  a(name: string): Promise<DnsResult<string>> {
    return this.query(`A ${name}`, name, (r) => r.resolve4(name));
  }

  aaaa(name: string): Promise<DnsResult<string>> {
    return this.query(`AAAA ${name}`, name, (r) => r.resolve6(name));
  }

  cname(name: string): Promise<DnsResult<string>> {
    return this.query(`CNAME ${name}`, name, (r) => r.resolveCname(name));
  }

  ns(name: string): Promise<DnsResult<string>> {
    return this.query(`NS ${name}`, name, (r) => r.resolveNs(name));
  }

  caa(name: string): Promise<DnsResult<CaaRecord>> {
    return this.query(`CAA ${name}`, name, (r) => r.resolveCaa(name));
  }

  soa(name: string): Promise<DnsResult<SoaRecord>> {
    return this.query(`SOA ${name}`, name, async (r) => [await r.resolveSoa(name)]);
  }

  async addresses(name: string): Promise<{ v4: string[]; v6: string[]; errors: DnsErrorInfo[] }> {
    const [a, aaaa] = await Promise.all([this.a(name), this.aaaa(name)]);
    const errors: DnsErrorInfo[] = [];
    if (a.error) errors.push(a.error);
    if (aaaa.error) errors.push(aaaa.error);
    return { v4: a.records, v6: aaaa.records, errors };
  }

  /**
   * A name exists when any common record type resolves or when at least one
   * lookup returns NOERROR with no data. It is NXDOMAIN only when every
   * lookup reports ENOTFOUND.
   */
  async exists(name: string): Promise<DnsExistence> {
    const results = await Promise.all([this.a(name), this.aaaa(name), this.mx(name), this.ns(name), this.txt(name), this.soa(name)]);
    if (results.some((r) => r.records.length > 0)) return { exists: true, nxdomain: false, error: null };
    if (results.every((r) => r.nxdomain)) return { exists: false, nxdomain: true, error: null };
    if (results.some((r) => !r.nxdomain && !r.error)) return { exists: true, nxdomain: false, error: null };
    const firstError = results.find((r) => r.error !== null)?.error ?? null;
    return { exists: false, nxdomain: false, error: firstError };
  }
}
