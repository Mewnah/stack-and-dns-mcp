/**
 * Environment and CLI configuration, validated with Zod at startup.
 *
 * Every knob has a safe default so the server boots with zero configuration
 * in local stdio mode, while hosted deployments can turn on API keys, Stripe
 * or x402 payment challenges, custom rate limits and DNS resolvers.
 */

import { randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import { isIP, isIPv4 } from "node:net";
import proxyAddr from "proxy-addr";
import { z } from "zod";
import type { LogLevel } from "./logger.js";

export const PLAN_NAMES = ["free", "pro", "enterprise", "payg", "local"] as const;
export type PlanName = (typeof PLAN_NAMES)[number];

export interface PlanLimits {
  /** Tool calls per minute. */
  perMinute: number;
  /** Tool calls per day. */
  perDay: number;
  /** Tool calls in flight at once. */
  maxConcurrent: number;
  /** HTTP requests per minute of any kind (initialize, tools/list, ping, tool calls); defaults to max(30, 5 x perMinute). */
  httpPerMinute?: number;
}

/**
 * Stock quotas. httpPerMinute is deliberately left unset here and derived
 * after any operator override is merged, so raising perMinute alone also
 * raises the request ceiling instead of leaving a stale stock value behind.
 */
export const DEFAULT_PLAN_LIMITS: Record<PlanName, PlanLimits> = {
  free: { perMinute: 10, perDay: 100, maxConcurrent: 2 },
  pro: { perMinute: 60, perDay: 5000, maxConcurrent: 8 },
  enterprise: { perMinute: 300, perDay: 100000, maxConcurrent: 32 },
  payg: { perMinute: 60, perDay: 1000000, maxConcurrent: 8 },
  local: { perMinute: 120, perDay: 1000000, maxConcurrent: 8 }
};

/** The HTTP request ceiling for a plan, derived from the tool-call quota when not set explicitly. */
export function httpLimitFor(limits: PlanLimits): number {
  return limits.httpPerMinute ?? Math.max(30, limits.perMinute * 5);
}

/** Returns the limits with the effective httpPerMinute materialized, so /pricing and headers report the value actually enforced. */
function withHttpLimit(limits: PlanLimits): PlanLimits {
  return { ...limits, httpPerMinute: httpLimitFor(limits) };
}

/**
 * Credits charged per call. Zero-cost tools are control calls (starting,
 * polling or cancelling work that is billed on its own terms); they still
 * count against the per-minute limit but never against credits or the daily
 * quota.
 */
export const TOOL_CREDIT_COST = {
  inspect_tech_stack: 1,
  verify_email_infrastructure: 1,
  comprehensive_audit: 2,
  domain_history: 1,
  start_bulk_check: 0,
  get_bulk_check: 0,
  list_bulk_checks: 0,
  cancel_bulk_check: 0,
  watch_domain: 0,
  unwatch_domain: 0,
  list_watches: 0,
  get_alerts: 0,
  find_domains_using: 2,
  list_technologies: 0
} as const;

/** Credits (or daily-quota units) per domain in a bulk check, matching the single-domain tools. */
export const BULK_CREDITS_PER_DOMAIN = {
  email: TOOL_CREDIT_COST.verify_email_infrastructure,
  tech: TOOL_CREDIT_COST.inspect_tech_stack,
  audit: TOOL_CREDIT_COST.comprehensive_audit
} as const;

/** Domains each plan may watch at once. */
export const DEFAULT_WATCH_LIMITS: Record<PlanName, number> = { free: 5, pro: 100, enterprise: 2000, payg: 500, local: 1000 };

export type ToolName = keyof typeof TOOL_CREDIT_COST;

export const PAYMENT_METHODS = ["stripe", "x402"] as const;
export type PaymentMethod = (typeof PAYMENT_METHODS)[number];

export const LOG_LEVELS = ["debug", "info", "warn", "error", "silent"] as const satisfies readonly LogLevel[];

/** The token x402 charges in on a network, and its EIP-712 domain (requirements.extra.name / extra.version). */
export interface X402AssetDefaults {
  asset: string;
  name: string;
  version: string;
}

const BASE_USDC: X402AssetDefaults = { asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", name: "USD Coin", version: "2" };
const BASE_SEPOLIA_USDC: X402AssetDefaults = { asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e", name: "USDC", version: "2" };

/**
 * USDC on the networks this server has built-in defaults for, by x402 name
 * and CAIP-2 id. Clients sign transferWithAuthorization over the EIP-712
 * domain, so name and version must equal the token contract's name() and
 * version(): native USDC on Base mainnet reports "USD Coin", the Base Sepolia
 * test token "USDC". The address differs per network too, so a Sepolia setup
 * must not inherit the mainnet contract.
 */
const X402_NETWORK_DEFAULTS: Readonly<Record<string, X402AssetDefaults>> = {
  base: BASE_USDC,
  "eip155:8453": BASE_USDC,
  "base-sepolia": BASE_SEPOLIA_USDC,
  "eip155:84532": BASE_SEPOLIA_USDC
};

/** The built-in USDC asset and EIP-712 domain for an x402 network, or null for a network without defaults (X402_ASSET and X402_ASSET_NAME must then be set). */
export function x402NetworkDefaults(network: string): X402AssetDefaults | null {
  return X402_NETWORK_DEFAULTS[network.trim().toLowerCase()] ?? null;
}

/** EIP-712 domain name an unset X402_ASSET_NAME falls back to: the network's USDC name, or Base mainnet's for a network without defaults. */
export function defaultX402AssetName(network: string): string {
  return (x402NetworkDefaults(network) ?? BASE_USDC).name;
}

interface X402AssetEnv {
  X402_NETWORK: string;
  X402_ASSET?: string | undefined;
  X402_ASSET_NAME?: string | undefined;
  X402_ASSET_VERSION?: string | undefined;
}

/** The resolved asset and EIP-712 domain, with the network id as it is sent in the 402 challenge and to the facilitator. */
interface X402Asset extends X402AssetDefaults {
  network: string;
}

/**
 * Resolves X402_ASSET, X402_ASSET_NAME and X402_ASSET_VERSION; each unset one
 * follows X402_NETWORK. A network the defaults table recognises in another
 * spelling (" Base-Sepolia ") is sent in its canonical form, because clients
 * and facilitators match network ids exactly: taking the Sepolia defaults
 * while still announcing "Base-Sepolia" would look valid and fail every
 * payment. Any other id is only trimmed, since CAIP-2 references (a Solana
 * genesis hash, for one) are case-sensitive.
 *
 * The checks below run only when x402 is switched on (with it off the values
 * are never sent, so the Base mainnet ones stand in rather than failing
 * startup over unused settings), and each refuses a setup in which every
 * payment would fail on chain:
 * - A network without built-in defaults would charge in the Base mainnet
 *   contract under its name, which no client there can pay, so the asset and
 *   its name must be set (the version still defaults to "2", as every USDC
 *   deployment uses).
 * - A built-in USDC contract fixes its network and its EIP-712 domain, so
 *   naming it on the other network (an X402_ASSET copied from a mainnet
 *   template onto base-sepolia) or with another name or version is refused.
 * - Any other token on a network with defaults would otherwise sign over
 *   that network's USDC domain ("USD Coin" on base), which is not the token's,
 *   so its name must be set, as on a network without defaults.
 */
function resolveX402Asset(e: X402AssetEnv, x402On: boolean): X402Asset {
  const known = x402NetworkDefaults(e.X402_NETWORK);
  const network = known ? e.X402_NETWORK.trim().toLowerCase() : e.X402_NETWORK.trim();
  const fallback = known ?? BASE_USDC;
  const resolved: X402Asset = { network, asset: e.X402_ASSET?.trim() ?? fallback.asset, name: e.X402_ASSET_NAME ?? fallback.name, version: e.X402_ASSET_VERSION ?? fallback.version };
  if (!x402On) return resolved;
  if (!known) {
    const missing = [e.X402_ASSET ? null : "X402_ASSET", e.X402_ASSET_NAME ? null : "X402_ASSET_NAME"].filter((v) => v !== null);
    if (missing.length > 0) {
      throw new Error(
        `X402_NETWORK "${e.X402_NETWORK}" has no built-in asset defaults (known: ${Object.keys(X402_NETWORK_DEFAULTS).join(", ")}); set ${missing.join(" and ")} (the token contract address and its EIP-712 name()) to use x402 on it`
      );
    }
    return resolved;
  }
  const usdc = [BASE_USDC, BASE_SEPOLIA_USDC].find((u) => u.asset.toLowerCase() === resolved.asset.toLowerCase());
  if (!usdc && !e.X402_ASSET_NAME) {
    throw new Error(
      `X402_ASSET ${resolved.asset} is not the built-in USDC for X402_NETWORK "${e.X402_NETWORK}" (${known.asset}), so its EIP-712 domain is unknown; set X402_ASSET_NAME (the token's EIP-712 name()), and X402_ASSET_VERSION if its version() is not "${known.version}"`
    );
  }
  if (usdc && usdc !== known) {
    throw new Error(`X402_ASSET ${resolved.asset} is USDC on ${usdc === BASE_USDC ? "base" : "base-sepolia"}, not on X402_NETWORK "${e.X402_NETWORK}"; leave X402_ASSET blank to use ${known.asset}`);
  }
  if (usdc && (resolved.name !== usdc.name || resolved.version !== usdc.version)) {
    throw new Error(
      `X402_ASSET_NAME "${resolved.name}" / X402_ASSET_VERSION "${resolved.version}" do not match the EIP-712 domain of USDC on "${e.X402_NETWORK}" ("${usdc.name}" / "${usdc.version}"), so every x402 signature would fail; leave them blank to follow X402_NETWORK`
    );
  }
  return resolved;
}

/**
 * Whether Resolver.setServers accepts an entry as written: an IP, ipv4:port,
 * or a bracketed IP ([ipv6], [ipv4]) with an optional :port. It is checked
 * here rather than by calling setServers, because setServers aborts the whole
 * process on port 0, wraps ports above 65535, ignores junk after "]", and
 * reinterprets "::1:53" as a different address.
 */
export function isResolverAddress(entry: string): boolean {
  const validPort = (p: string | undefined): boolean => p === undefined || (/^\d{1,5}$/.test(p) && Number(p) >= 1 && Number(p) <= 65535);
  const bracketed = /^\[([^\]]+)\](?::([^:]*))?$/.exec(entry);
  if (bracketed) return isIP(bracketed[1] ?? "") !== 0 && validPort(bracketed[2]);
  if (isIP(entry) !== 0) return true;
  const withPort = /^([^:]+):([^:]*)$/.exec(entry);
  return withPort !== null && isIPv4(withPort[1] ?? "") && validPort(withPort[2]);
}

function resolverList(variable: string, entries: string[]): string[] {
  for (const entry of entries) {
    if (!isResolverAddress(entry)) throw new Error(`${variable} entry "${entry}" is not an IP address (use ip, ipv4:port or [ipv6]:port, port 1-65535, comma-separated)`);
  }
  return entries;
}

// Blank values never reach the schema (loadConfig drops them so defaults apply), so "" is deliberately not a falsy spelling here.
const boolish = z.stringbool({
  truthy: ["1", "true", "yes", "on", "y", "enabled"],
  falsy: ["0", "false", "no", "off", "n", "disabled"]
});

/** Values that explicitly switch off a list- or path-valued setting. */
const DISABLED_SPELLINGS = new Set(["none", "off", "disabled", "false", "no", "0"]);

/** Comma-separated list where "none" / "off" explicitly mean an empty list. */
const csvOrNone = (value: string): string[] => {
  const trimmed = value.trim().toLowerCase();
  if (DISABLED_SPELLINGS.has(trimmed)) return [];
  return csv(value);
};

const csv = (value: string | undefined): string[] =>
  (value ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);

const EnvSchema = z.object({
  STACKDNS_TRANSPORT: z.enum(["stdio", "http"]).default("stdio"),
  PORT: z.coerce.number().int().min(1).max(65535).optional(),
  STACKDNS_PORT: z.coerce.number().int().min(1).max(65535).default(3333),
  STACKDNS_HOST: z.string().min(1).default("0.0.0.0"),
  STACKDNS_PUBLIC_URL: z.url().optional(),
  STACKDNS_ALLOWED_HOSTS: z.string().optional(),
  STACKDNS_ALLOWED_ORIGINS: z.string().optional(),
  STACKDNS_DNS_REBINDING_PROTECTION: boolish.optional(),
  STACKDNS_TRUST_PROXY: z.string().default("false"),
  STACKDNS_SESSION_TTL_MS: z.coerce
    .number()
    .int()
    .min(60000)
    .default(30 * 60 * 1000),

  STACKDNS_API_KEYS: z.string().default(""),
  STACKDNS_API_KEYS_FILE: z.string().optional(),
  STACKDNS_API_KEY: z.string().optional(),
  STACKDNS_REQUIRE_AUTH: boolish.optional(),
  STACKDNS_SESSION_SECRET: z.string().min(16).optional(),
  STACKDNS_RATE_LIMITS_JSON: z.string().optional(),
  STACKDNS_UNAUTHENTICATED_PER_MINUTE: z.coerce.number().int().min(1).max(100000).default(60),
  STACKDNS_USAGE_FILE: z.string().default("./data/usage.json"),
  STACKDNS_DB_FILE: z.string().default("./data/stackdns.db"),
  STACKDNS_SCAN_RETENTION_DAYS: z.coerce.number().int().min(7).max(3650).default(365),

  STACKDNS_BULK_ENABLED: boolish.default(true),
  STACKDNS_BULK_MAX_DOMAINS: z.coerce.number().int().min(1).max(50000).default(1000),
  STACKDNS_BULK_CONCURRENCY: z.coerce.number().int().min(1).max(64).default(4),
  STACKDNS_BULK_MAX_ACTIVE_JOBS: z.coerce.number().int().min(1).max(100).default(3),
  STACKDNS_JOB_RETENTION_DAYS: z.coerce.number().int().min(1).max(3650).default(30),

  STACKDNS_MONITOR_ENABLED: boolish.default(true),
  STACKDNS_MONITOR_INTERVAL_HOURS: z.coerce.number().min(1).max(720).default(24),
  STACKDNS_MONITOR_CONCURRENCY: z.coerce.number().int().min(1).max(32).default(2),
  STACKDNS_MONITOR_CREDITS_PER_CHECK: z.coerce.number().int().min(0).max(100).default(1),
  STACKDNS_MONITOR_WATCH_LIMITS_JSON: z.string().optional(),
  STACKDNS_ALERT_RETENTION_DAYS: z.coerce.number().int().min(1).max(3650).default(90),
  STACKDNS_WEBHOOK_ALLOW_INSECURE: boolish.default(false),

  STACKDNS_CRAWL_SEED_FILE: z.string().optional(),
  STACKDNS_CRAWL_RATE_PER_MINUTE: z.coerce.number().min(0.1).max(600).default(20),
  STACKDNS_CRAWL_REFRESH_DAYS: z.coerce.number().min(1).max(365).default(30),
  STACKDNS_CRAWL_CONCURRENCY: z.coerce.number().int().min(1).max(16).default(2),
  STACKDNS_CRAWL_MAX_TARGETS: z.coerce.number().int().min(1).max(5000000).default(100000),

  STACKDNS_PAYMENTS_ENABLED: boolish.default(false),
  // Refused rather than filtered: a misspelt method used to fall back to stripe silently, so an operator enabling x402 got Stripe challenges (or none).
  STACKDNS_PAYMENT_METHODS: z
    .string()
    .default("stripe")
    .transform((value, ctx) => {
      const methods = [...new Set(csv(value.toLowerCase()))];
      const unknown = methods.filter((m) => !(PAYMENT_METHODS as readonly string[]).includes(m));
      if (methods.length === 0 || unknown.length > 0) {
        ctx.addIssue({ code: "custom", message: `must be ${PAYMENT_METHODS.join(", ")} or a comma-separated list of them (got "${value}")` });
        return z.NEVER;
      }
      return methods as PaymentMethod[];
    }),
  STACKDNS_PAYMENT_CHALLENGE_TTL_MS: z.coerce
    .number()
    .int()
    .min(60000)
    .default(15 * 60 * 1000),

  STRIPE_SECRET_KEY: z.string().optional(),
  STRIPE_PRICE_CENTS: z.coerce.number().int().positive().default(500),
  STRIPE_CURRENCY: z.string().length(3).default("usd"),
  STRIPE_CREDITS_PER_PURCHASE: z.coerce.number().int().positive().default(100),
  STRIPE_SUCCESS_URL: z.url().optional(),
  STRIPE_CANCEL_URL: z.url().optional(),
  STRIPE_API_BASE: z.url().default("https://api.stripe.com"),
  STRIPE_PRICE_PRO: z
    .string()
    .regex(/^price_[A-Za-z0-9]+$/, "must be a Stripe Price id (price_...)")
    .optional(),
  STRIPE_PRICE_ENTERPRISE: z
    .string()
    .regex(/^price_[A-Za-z0-9]+$/, "must be a Stripe Price id (price_...)")
    .optional(),
  STRIPE_WEBHOOK_SECRET: z
    .string()
    .regex(/^whsec_[A-Za-z0-9+/=_-]+$/, "must be a Stripe webhook signing secret (whsec_...)")
    .optional(),

  X402_FACILITATOR_URL: z.url().optional(),
  X402_PAY_TO: z.string().optional(),
  X402_NETWORK: z.string().default("base"),
  // The asset and its EIP-712 domain (extra.name and extra.version, which must equal the token contract's name() and version()); each unset one follows X402_NETWORK (resolveX402Asset).
  X402_ASSET: z.string().optional(),
  X402_ASSET_NAME: z.string().min(1).optional(),
  X402_ASSET_VERSION: z.string().min(1).optional(),
  X402_PRICE_ATOMIC: z.string().regex(/^\d+$/).default("500000"),
  X402_CREDITS_PER_PAYMENT: z.coerce.number().int().positive().default(100),

  STACKDNS_FETCH_TIMEOUT_MS: z.coerce.number().int().min(500).max(30000).default(3000),
  STACKDNS_DNS_TIMEOUT_MS: z.coerce.number().int().min(500).max(30000).default(3000),
  STACKDNS_TLS_TIMEOUT_MS: z.coerce.number().int().min(500).max(30000).default(3000),
  STACKDNS_TOOL_TIMEOUT_MS: z.coerce.number().int().min(2000).max(120000).default(20000),
  STACKDNS_MAX_BODY_BYTES: z.coerce.number().int().min(10000).max(20000000).default(1500000),
  STACKDNS_DNS_SERVERS: z.string().optional(),
  STACKDNS_DNS_FALLBACK_SERVERS: z.string().default("1.1.1.1,8.8.8.8,9.9.9.9"),
  STACKDNS_DNS_CACHE_TTL_MS: z.coerce.number().int().min(0).max(600000).default(30000),
  STACKDNS_USER_AGENT: z.string().min(1).default("Mozilla/5.0 (compatible; StackAndDnsBot/1.0; +https://github.com/Mewnah/stack-and-dns-mcp)"),
  STACKDNS_ALLOW_PRIVATE_TARGETS: boolish.default(false),
  STACKDNS_DKIM_SELECTORS: z.string().optional(),
  STACKDNS_LOG_LEVEL: z.enum(LOG_LEVELS).default("info")
});

export interface StripeConfig {
  secretKey: string | undefined;
  priceCents: number;
  currency: string;
  creditsPerPurchase: number;
  successUrl: string | undefined;
  cancelUrl: string | undefined;
  apiBase: string;
}

export interface X402Config {
  facilitatorUrl: string | undefined;
  payTo: string | undefined;
  /** Sent as requirements.network and to the facilitator: a network with built-in defaults in its canonical lowercase spelling, any other id trimmed (resolveX402Asset). */
  network: string;
  asset: string;
  /** EIP-712 domain name of the asset, sent as requirements.extra.name. */
  assetName: string;
  /** EIP-712 domain version of the asset, sent as requirements.extra.version. */
  assetVersion: string;
  priceAtomic: string;
  creditsPerPayment: number;
}

export interface AppConfig {
  name: string;
  version: string;
  transport: "stdio" | "http";
  logLevel: LogLevel;
  http: {
    host: string;
    port: number;
    publicUrl: string;
    allowedHosts: string[];
    allowedOrigins: string[];
    enableDnsRebindingProtection: boolean;
    /** Express "trust proxy" value: false, a hop count, or a comma-separated list of subnets/keywords. Never the literal true. */
    trustProxy: boolean | number | string;
    sessionTtlMs: number;
  };
  auth: {
    requireAuth: boolean;
    apiKeysInline: string;
    apiKeysFile: string | undefined;
    clientApiKey: string | undefined;
    sessionSecret: string;
    sessionSecretGenerated: boolean;
    planLimits: Record<PlanName, PlanLimits>;
    /** Per-client-address ceiling for requests that end before a principal is resolved. */
    unauthenticatedPerMinute: number;
    usageFile: string;
  };
  payments: {
    enabled: boolean;
    methods: PaymentMethod[];
    challengeTtlMs: number;
    stripe: StripeConfig;
    x402: X402Config;
  };
  storage: {
    /** SQLite file for stored scans and every feature built on them; null disables storage. */
    dbFile: string | null;
    scanRetentionDays: number;
  };
  bulk: {
    enabled: boolean;
    maxDomains: number;
    concurrency: number;
    maxActiveJobsPerPrincipal: number;
    retentionDays: number;
  };
  selfServe: {
    /** Stripe Price ids of the subscriptions sold on /signup; a plan without one is not offered. */
    prices: { pro?: string; enterprise?: string };
    webhookSecret: string | null;
  };
  monitor: {
    enabled: boolean;
    intervalMs: number;
    concurrency: number;
    creditsPerCheck: number;
    maxWatches: Record<PlanName, number>;
    alertRetentionDays: number;
    /** Permit http:// webhook destinations (development only). */
    webhookAllowInsecure: boolean;
  };
  crawl: {
    /** Operator-supplied list of domains to crawl for reverse lookup; null disables the crawler and the reverse-lookup tools. */
    seedFile: string | null;
    ratePerMinute: number;
    refreshMs: number;
    concurrency: number;
    maxTargets: number;
  };
  inspection: {
    fetchTimeoutMs: number;
    dnsTimeoutMs: number;
    tlsTimeoutMs: number;
    toolTimeoutMs: number;
    maxBodyBytes: number;
    dnsServers: string[];
    dnsFallbackServers: string[];
    /** How long a successful DNS answer is reused for identical queries; 0 disables the cache. */
    dnsCacheTtlMs: number;
    userAgent: string;
    allowPrivateTargets: boolean;
    extraDkimSelectors: string[];
  };
}

function readPackageVersion(): string {
  try {
    const require = createRequire(import.meta.url);
    const pkg = require("../package.json") as { version?: string };
    return typeof pkg.version === "string" ? pkg.version : "0.0.0";
  } catch {
    return "0.0.0";
  }
}

interface CliOverrides {
  transport?: "stdio" | "http";
  port?: number;
  host?: string;
  logLevel?: LogLevel;
}

/**
 * Flags: --http (aliases --sse, --remote), --stdio, --host <h>, --port <n> and
 * --log-level <level>, each value also accepted as --flag=value. A bad or
 * missing value fails startup like the matching environment variable does,
 * instead of being ignored in favour of a default the operator did not ask
 * for. Unrecognised arguments are still ignored, so wrappers that append
 * their own arguments keep working.
 */
function parseArgs(argv: string[]): CliOverrides {
  const out: CliOverrides = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] ?? "";
    const eq = arg.startsWith("--") ? arg.indexOf("=") : -1;
    const name = eq > 0 ? arg.slice(0, eq) : arg;
    const inline = eq > 0 ? arg.slice(eq + 1) : undefined;
    // A following flag is never taken as the value: "--port --http" would otherwise swallow --http.
    const value = (): string => {
      let v = inline;
      const next = argv[i + 1];
      if (v === undefined && next !== undefined && !next.startsWith("--")) {
        v = next;
        i++;
      }
      if (v === undefined || v.trim().length === 0) throw new Error(`${name} needs a value`);
      return v.trim();
    };
    if (name === "--http" || name === "--sse" || name === "--remote") out.transport = "http";
    else if (name === "--stdio") out.transport = "stdio";
    else if (name === "--port") {
      const raw = value();
      const n = /^\d+$/.test(raw) ? Number(raw) : NaN;
      if (!(Number.isInteger(n) && n >= 1 && n <= 65535)) throw new Error(`--port must be an integer 1-65535 (got "${raw}")`);
      out.port = n;
    } else if (name === "--host") out.host = value();
    else if (name === "--log-level") {
      const level = value();
      if (!(LOG_LEVELS as readonly string[]).includes(level)) throw new Error(`--log-level must be one of ${LOG_LEVELS.join(", ")} (got "${level}")`);
      out.logLevel = level as LogLevel;
    }
  }
  return out;
}

function parseWatchLimits(json: string | undefined): Record<PlanName, number> {
  const limits: Record<PlanName, number> = { ...DEFAULT_WATCH_LIMITS };
  if (!json) return limits;
  let raw: unknown;
  try {
    raw = JSON.parse(json);
  } catch (err) {
    throw new Error(`STACKDNS_MONITOR_WATCH_LIMITS_JSON is not valid JSON: ${(err as Error).message}`);
  }
  const parsed = z.partialRecord(z.enum(PLAN_NAMES), z.number().int().min(0).max(1000000)).safeParse(raw);
  if (!parsed.success) throw new Error(`STACKDNS_MONITOR_WATCH_LIMITS_JSON is invalid: ${parsed.error.message}`);
  for (const [plan, limit] of Object.entries(parsed.data) as Array<[PlanName, number]>) limits[plan] = limit;
  return limits;
}

function parsePlanLimits(json: string | undefined): Record<PlanName, PlanLimits> {
  const limits: Record<PlanName, PlanLimits> = { ...DEFAULT_PLAN_LIMITS };
  const materialize = (): Record<PlanName, PlanLimits> => {
    for (const plan of PLAN_NAMES) limits[plan] = withHttpLimit(limits[plan]);
    return limits;
  };
  if (!json) return materialize();
  const LimitSchema = z.object({
    perMinute: z.number().int().positive().optional(),
    perDay: z.number().int().positive().optional(),
    maxConcurrent: z.number().int().positive().optional(),
    httpPerMinute: z.number().int().positive().optional()
  });
  let raw: unknown;
  try {
    raw = JSON.parse(json);
  } catch (err) {
    throw new Error(`STACKDNS_RATE_LIMITS_JSON is not valid JSON: ${(err as Error).message}`);
  }
  // partialRecord: an enum-keyed z.record is exhaustive in Zod 4 and would reject overrides that name only some plans.
  const parsed = z.partialRecord(z.enum(PLAN_NAMES), LimitSchema).safeParse(raw);
  if (!parsed.success) {
    throw new Error(`STACKDNS_RATE_LIMITS_JSON is invalid: ${parsed.error.message}`);
  }
  for (const [plan, override] of Object.entries(parsed.data) as Array<[PlanName, z.infer<typeof LimitSchema>]>) {
    limits[plan] = { ...limits[plan], ...override };
  }
  return materialize();
}

/**
 * Express accepts false, a hop count, or subnet/keyword lists for "trust proxy".
 * The literal `true` trusts every hop and lets clients forge X-Forwarded-For,
 * so "true"/"yes"/"on" are mapped to a single trusted hop instead.
 */
export function parseTrustProxy(raw: string): boolean | number | string {
  const value = raw.trim().toLowerCase();
  if (value === "" || value === "false" || value === "0" || value === "no" || value === "off") return false;
  if (value === "true" || value === "yes" || value === "on") return 1;
  if (/^\d+$/.test(value)) return Number(value);
  const tokens = value
    .split(",")
    .map((t) => t.trim())
    .filter((t) => t.length > 0);
  if (tokens.length === 0) return false;
  // Validate with the exact parser Express uses so anything accepted here is
  // guaranteed to work in app.set("trust proxy", ...) and anything Express
  // would reject fails at config time with a message naming the variable.
  try {
    proxyAddr.compile(tokens);
  } catch (err) {
    throw new Error(
      `STACKDNS_TRUST_PROXY must be false, a hop count, or a comma-separated list of IPs, CIDRs (prefix or netmask) or keywords (loopback, linklocal, uniquelocal); got "${raw}": ${(err as Error).message}`
    );
  }
  return tokens.join(", ");
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env, argv: string[] = process.argv.slice(2)): AppConfig {
  // Env files and PaaS dashboards commonly set variables to the empty string.
  // Zod's .optional()/.default() only apply to undefined, so blank values are
  // dropped before parsing to fall back to the documented defaults.
  const definedEnv: NodeJS.ProcessEnv = {};
  for (const [key, value] of Object.entries(env)) {
    if (typeof value !== "string") continue;
    // docker --env-file passes KEY="" through as the two-character string "";
    // only an empty quoted pair is treated as blank, so quotes that are part of
    // a real value (a secret, for example) are never stripped.
    const trimmed = value.trim();
    if (trimmed.length === 0 || trimmed === '""' || trimmed === "''") continue;
    definedEnv[key] = value;
  }
  const parsed = EnvSchema.safeParse(definedEnv);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
    throw new Error(`Invalid environment configuration: ${issues}`);
  }
  const e = parsed.data;
  const cli = parseArgs(argv);
  const transport = cli.transport ?? e.STACKDNS_TRANSPORT;
  const port = cli.port ?? e.PORT ?? e.STACKDNS_PORT;
  const host = cli.host ?? e.STACKDNS_HOST;
  const displayHost = host === "0.0.0.0" || host === "::" ? "localhost" : host;
  const publicUrl = e.STACKDNS_PUBLIC_URL ?? `http://${displayHost}:${port}`;

  const requireAuth = e.STACKDNS_REQUIRE_AUTH ?? transport === "http";
  const sessionSecretGenerated = !e.STACKDNS_SESSION_SECRET;
  const sessionSecret = e.STACKDNS_SESSION_SECRET ?? randomBytes(32).toString("hex");
  const x402Asset = resolveX402Asset(e, e.STACKDNS_PAYMENTS_ENABLED && e.STACKDNS_PAYMENT_METHODS.includes("x402"));

  return {
    name: "stack-and-dns-mcp",
    version: readPackageVersion(),
    transport,
    logLevel: cli.logLevel ?? e.STACKDNS_LOG_LEVEL,
    http: {
      host,
      port,
      publicUrl: publicUrl.replace(/\/+$/, ""),
      allowedHosts: csv(e.STACKDNS_ALLOWED_HOSTS),
      allowedOrigins: csv(e.STACKDNS_ALLOWED_ORIGINS),
      enableDnsRebindingProtection: e.STACKDNS_DNS_REBINDING_PROTECTION ?? false,
      trustProxy: parseTrustProxy(e.STACKDNS_TRUST_PROXY),
      sessionTtlMs: e.STACKDNS_SESSION_TTL_MS
    },
    auth: {
      requireAuth,
      apiKeysInline: e.STACKDNS_API_KEYS,
      apiKeysFile: e.STACKDNS_API_KEYS_FILE,
      clientApiKey: e.STACKDNS_API_KEY,
      sessionSecret,
      sessionSecretGenerated,
      planLimits: parsePlanLimits(e.STACKDNS_RATE_LIMITS_JSON),
      unauthenticatedPerMinute: e.STACKDNS_UNAUTHENTICATED_PER_MINUTE,
      usageFile: e.STACKDNS_USAGE_FILE
    },
    payments: {
      enabled: e.STACKDNS_PAYMENTS_ENABLED,
      methods: e.STACKDNS_PAYMENT_METHODS,
      challengeTtlMs: e.STACKDNS_PAYMENT_CHALLENGE_TTL_MS,
      stripe: {
        secretKey: e.STRIPE_SECRET_KEY,
        priceCents: e.STRIPE_PRICE_CENTS,
        currency: e.STRIPE_CURRENCY.toLowerCase(),
        creditsPerPurchase: e.STRIPE_CREDITS_PER_PURCHASE,
        successUrl: e.STRIPE_SUCCESS_URL,
        cancelUrl: e.STRIPE_CANCEL_URL,
        apiBase: e.STRIPE_API_BASE.replace(/\/+$/, "")
      },
      x402: {
        facilitatorUrl: e.X402_FACILITATOR_URL?.replace(/\/+$/, ""),
        payTo: e.X402_PAY_TO,
        network: x402Asset.network,
        asset: x402Asset.asset,
        assetName: x402Asset.name,
        assetVersion: x402Asset.version,
        priceAtomic: e.X402_PRICE_ATOMIC,
        creditsPerPayment: e.X402_CREDITS_PER_PAYMENT
      }
    },
    storage: {
      dbFile: DISABLED_SPELLINGS.has(e.STACKDNS_DB_FILE.trim().toLowerCase()) ? null : e.STACKDNS_DB_FILE.trim(),
      scanRetentionDays: e.STACKDNS_SCAN_RETENTION_DAYS
    },
    bulk: {
      enabled: e.STACKDNS_BULK_ENABLED,
      maxDomains: e.STACKDNS_BULK_MAX_DOMAINS,
      concurrency: e.STACKDNS_BULK_CONCURRENCY,
      maxActiveJobsPerPrincipal: e.STACKDNS_BULK_MAX_ACTIVE_JOBS,
      retentionDays: e.STACKDNS_JOB_RETENTION_DAYS
    },
    selfServe: {
      prices: {
        ...(e.STRIPE_PRICE_PRO ? { pro: e.STRIPE_PRICE_PRO } : {}),
        ...(e.STRIPE_PRICE_ENTERPRISE ? { enterprise: e.STRIPE_PRICE_ENTERPRISE } : {})
      },
      webhookSecret: e.STRIPE_WEBHOOK_SECRET ?? null
    },
    monitor: {
      enabled: e.STACKDNS_MONITOR_ENABLED,
      intervalMs: Math.round(e.STACKDNS_MONITOR_INTERVAL_HOURS * 60 * 60 * 1000),
      concurrency: e.STACKDNS_MONITOR_CONCURRENCY,
      creditsPerCheck: e.STACKDNS_MONITOR_CREDITS_PER_CHECK,
      maxWatches: parseWatchLimits(e.STACKDNS_MONITOR_WATCH_LIMITS_JSON),
      alertRetentionDays: e.STACKDNS_ALERT_RETENTION_DAYS,
      webhookAllowInsecure: e.STACKDNS_WEBHOOK_ALLOW_INSECURE
    },
    crawl: {
      seedFile: e.STACKDNS_CRAWL_SEED_FILE && !DISABLED_SPELLINGS.has(e.STACKDNS_CRAWL_SEED_FILE.trim().toLowerCase()) ? e.STACKDNS_CRAWL_SEED_FILE.trim() : null,
      ratePerMinute: e.STACKDNS_CRAWL_RATE_PER_MINUTE,
      refreshMs: Math.round(e.STACKDNS_CRAWL_REFRESH_DAYS * 24 * 60 * 60 * 1000),
      concurrency: e.STACKDNS_CRAWL_CONCURRENCY,
      maxTargets: e.STACKDNS_CRAWL_MAX_TARGETS
    },
    inspection: {
      fetchTimeoutMs: e.STACKDNS_FETCH_TIMEOUT_MS,
      dnsTimeoutMs: e.STACKDNS_DNS_TIMEOUT_MS,
      tlsTimeoutMs: e.STACKDNS_TLS_TIMEOUT_MS,
      toolTimeoutMs: e.STACKDNS_TOOL_TIMEOUT_MS,
      maxBodyBytes: e.STACKDNS_MAX_BODY_BYTES,
      // Validated here so a bad entry names its variable instead of failing later inside Resolver.setServers as a bare "fatal startup error".
      dnsServers: resolverList("STACKDNS_DNS_SERVERS", csv(e.STACKDNS_DNS_SERVERS)),
      dnsFallbackServers: resolverList("STACKDNS_DNS_FALLBACK_SERVERS", csvOrNone(e.STACKDNS_DNS_FALLBACK_SERVERS)),
      dnsCacheTtlMs: e.STACKDNS_DNS_CACHE_TTL_MS,
      userAgent: e.STACKDNS_USER_AGENT,
      allowPrivateTargets: e.STACKDNS_ALLOW_PRIVATE_TARGETS,
      extraDkimSelectors: csv(e.STACKDNS_DKIM_SELECTORS)
    }
  };
}
