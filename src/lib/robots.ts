/**
 * robots.txt (RFC 9309) for the background crawler: fetching with the same
 * SSRF guard as every other outbound request, parsing into groups, and
 * matching a path with longest-match precedence.
 *
 * The crawler requests a site's homepage and follows its redirects; every
 * URL it fetches is judged against the robots.txt of that URL's origin.
 */

import { Agent, fetch as undiciFetch } from "undici";
import { deadlineSignal } from "./async.js";
import { classifyFetchError, readBodyCapped } from "./http.js";
import { assertPublicLiteral, createGuardedLookup } from "./lookup.js";

/** RFC 9309 section 2.5: crawlers must parse at least 500 KiB. */
const MAX_ROBOTS_BYTES = 512 * 1024;
/** RFC 9309 section 2.3.1.2: follow at least five consecutive redirects. */
const MAX_REDIRECTS = 5;

export interface RobotsRule {
  allow: boolean;
  /** Canonical form (canonicalRule), compared against canonicalTarget(path). */
  pattern: string;
  /** The rule's length in octets, each escape counted once however it was written: the longest match wins. */
  octets: number;
}

export interface RobotsGroup {
  agents: string[];
  rules: RobotsRule[];
}

/**
 * allowed: rules permit the path. disallowed: rules forbid it.
 * unreachable: the file could not be fetched because of a 5xx or a network
 * failure, which RFC 9309 treats as complete disallow, or a 429, which this
 * crawler treats the same way; the site must not be fetched this time.
 * not_found: the host is confirmed NXDOMAIN. It is set by the crawler's
 * checker (createRobotsChecker in services.ts); fetchRobots itself never
 * returns it.
 */
export type RobotsVerdict = "allowed" | "disallowed" | "unreachable" | "not_found";

export interface RobotsResult {
  verdict: RobotsVerdict;
  status: number | null;
  error: string | null;
  /** The fetch failed resolving the host name (the site may not exist). */
  dnsFailure?: boolean;
}

/** "*" (optionally followed by a comment) is the global group; otherwise only the leading product token counts ("StackAndDnsBot/1.0" matches "stackanddnsbot"). */
function normalizeAgent(value: string): string {
  if (value[0] === "*" && (value.length === 1 || /\s/.test(value[1] as string))) return "*";
  return (/^[A-Za-z0-9_-]+/.exec(value)?.[0] ?? "").toLowerCase();
}

export function parseRobots(text: string): RobotsGroup[] {
  const groups: RobotsGroup[] = [];
  let current: RobotsGroup | null = null;
  // Consecutive user-agent lines share one group; a rule line closes the agent list.
  let collectingAgents = false;
  for (const rawLine of text.split(/\r?\n|\r/)) {
    const line = rawLine.replace(/#.*$/, "").trim();
    if (!line) continue;
    const colon = line.indexOf(":");
    if (colon === -1) continue;
    const key = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    if (key === "user-agent") {
      if (!collectingAgents || !current) {
        current = { agents: [], rules: [] };
        groups.push(current);
        collectingAgents = true;
      }
      current.agents.push(normalizeAgent(value));
    } else if (key === "allow" || key === "disallow") {
      collectingAgents = false;
      if (!current) continue;
      // An empty Disallow allows everything; it adds no rule.
      if (value === "") continue;
      const pattern = canonicalRule(value);
      current.rules.push({ allow: key === "allow", pattern, octets: pattern.replace(/%[0-9A-F]{2}/g, "%").length });
    } else {
      // Other records (sitemap, crawl-delay) do not end the agent list.
    }
  }
  return groups;
}

/** The product token a robots.txt group is matched against, e.g. "stackanddnsbot" from our User-Agent. */
export function productToken(userAgent: string): string {
  const compatible = /compatible;\s*([A-Za-z0-9_-]+)/.exec(userAgent);
  const token = compatible?.[1] ?? /^([A-Za-z0-9_-]+)/.exec(userAgent)?.[1] ?? userAgent;
  return token.toLowerCase();
}

function percentEncode(ch: string): string {
  if (ch === "'") return "%27"; // encodeURIComponent leaves it as is
  try {
    return encodeURIComponent(ch);
  } catch {
    return "%EF%BF%BD"; // a lone surrogate: U+FFFD
  }
}

/**
 * RFC 9309 section 2.2.2: a rule and a path are compared in one
 * percent-encoded form. Non-ASCII, whitespace and the other characters the
 * URL parser encodes (including ' in a query and ^ in a path) become %XX,
 * existing escapes get uppercase hex, and escaped unreserved characters are
 * decoded, so "/über/", "/%c3%bcber/" and "/%C3%BCber/" are one path, as are
 * "/~joe/" and "/%7Ejoe/", and "/a^b/" and "/a%5Eb/". Escaped reserved
 * characters stay escaped: "/a%2Fb" is not "/a/b".
 */
export function canonicalPath(value: string): string {
  return value
    .replace(/%([0-9A-Fa-f]{2})/g, (_match, hex: string) => {
      const ch = String.fromCharCode(Number.parseInt(hex, 16));
      return /[A-Za-z0-9\-._~]/.test(ch) ? ch : `%${hex.toUpperCase()}`;
    })
    .replace(/[^\x21-\x7e]|["'<>`{}^]/gu, percentEncode);
}

/**
 * A rule's pattern in canonical form. In a rule, "*" is always the wildcard
 * and only a trailing "$" is the end anchor, so any other "$" is a literal
 * and becomes %24, the form the path side uses for it. RFC 9309 section
 * 2.2.3: a rule names a literal "*" or "$" by its escape (%2A, %24), which
 * canonicalPath already keeps as it is.
 */
function canonicalRule(value: string): string {
  const canonical = canonicalPath(value);
  const anchored = canonical.endsWith("$");
  const body = (anchored ? canonical.slice(0, -1) : canonical).replace(/\$/g, "%24");
  return anchored ? `${body}$` : body;
}

/**
 * A URL path in canonical form, with its literal "*" and "$" escaped: they
 * carry no special meaning in a URL, and escaped is how a rule has to name
 * them (RFC 9309 section 2.2.3), so "/foo-$" meets "Disallow: /foo-%24". A
 * rule's wildcard still spans the escapes, and its trailing anchor still
 * anchors.
 */
function canonicalTarget(value: string): string {
  return canonicalPath(value).replace(/\*/g, "%2A").replace(/\$/g, "%24");
}

function patternToRegex(pattern: string): RegExp {
  const anchored = pattern.endsWith("$");
  const body = (anchored ? pattern.slice(0, -1) : pattern)
    .split("*")
    .map((part) => part.replace(/[.+?^${}()|[\]\\]/g, "\\$&"))
    .join(".*");
  return new RegExp(`^${body}${anchored ? "$" : ""}`);
}

/**
 * RFC 9309 section 2.2.2: the group whose user-agent matches the product
 * token applies (all such groups combined), else the "*" groups; the most
 * specific (longest) matching rule wins, and allow wins a tie.
 */
export function isAllowed(groups: RobotsGroup[], token: string, path: string): boolean {
  const lower = token.toLowerCase();
  let applicable = groups.filter((g) => g.agents.some((a) => a !== "*" && a === lower));
  if (applicable.length === 0) applicable = groups.filter((g) => g.agents.includes("*"));
  // Patterns are stored in canonical form (parseRobots); the path joins them there.
  const target = canonicalTarget(path);
  let best: RobotsRule | null = null;
  for (const group of applicable) {
    for (const rule of group.rules) {
      if (!patternToRegex(rule.pattern).test(target)) continue;
      if (!best || rule.octets > best.octets || (rule.octets === best.octets && rule.allow && !best.allow)) best = rule;
    }
  }
  return best ? best.allow : true;
}

export interface RobotsFetchOptions {
  timeoutMs: number;
  userAgent: string;
  allowPrivate: boolean;
  signal?: AbortSignal;
}

/**
 * An origin's robots.txt: its parsed groups, or one verdict that holds for
 * every path (no usable file, or the file could not be fetched).
 */
export type RobotsFile = { groups: RobotsGroup[]; status: number } | { fixed: RobotsResult };

/**
 * Fetches https://<host>/robots.txt and decides whether the homepage may be
 * crawled; the file comes back too, so the pages fetched next on the same
 * origin are judged without downloading it again.
 */
export async function checkRobots(host: string, options: RobotsFetchOptions): Promise<RobotsResult & { file: RobotsFile }> {
  const target = new URL(`https://${host}/`);
  const file = await fetchRobots(target, options);
  return { ...robotsVerdict(file, target, options.userAgent), file };
}

/**
 * Decides whether one URL may be fetched, from the robots.txt of that URL's
 * own origin (RFC 9309: robots.txt applies per scheme, host and port).
 */
export async function checkRobotsForUrl(target: URL, options: RobotsFetchOptions): Promise<RobotsResult> {
  return robotsVerdict(await fetchRobots(target, options), target, options.userAgent);
}

/** The verdict an origin's robots.txt gives one URL on that origin. */
export function robotsVerdict(file: RobotsFile, target: URL, userAgent: string): RobotsResult {
  if ("fixed" in file) return file.fixed;
  const path = `${target.pathname || "/"}${target.search}`;
  return { verdict: isAllowed(file.groups, productToken(userAgent), path) ? "allowed" : "disallowed", status: file.status, error: null };
}

/** Fetches the robots.txt of a URL's origin, following up to five redirects. */
export async function fetchRobots(target: URL, options: RobotsFetchOptions): Promise<RobotsFile> {
  const agent = new Agent({
    connect: { timeout: options.timeoutMs, lookup: createGuardedLookup(options.allowPrivate) },
    headersTimeout: options.timeoutMs,
    bodyTimeout: options.timeoutMs
  });
  try {
    let url = new URL(`${target.protocol}//${target.host}/robots.txt`);
    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      assertPublicLiteral(url.hostname, options.allowPrivate);
      const response = await undiciFetch(url, {
        method: "GET",
        headers: { "user-agent": options.userAgent, accept: "text/plain" },
        redirect: "manual",
        dispatcher: agent,
        signal: deadlineSignal(options.timeoutMs, options.signal)
      });
      const location = response.headers.get("location");
      if (response.status >= 300 && response.status < 400 && location) {
        await response.body?.cancel().catch(() => undefined);
        const next = new URL(location, url);
        if (next.protocol !== "https:" && next.protocol !== "http:") return { fixed: { verdict: "allowed", status: response.status, error: "redirect to a non-http scheme" } };
        url = next;
        continue;
      }
      if (response.status >= 300 && response.status < 400) {
        await response.body?.cancel().catch(() => undefined);
        return { fixed: { verdict: "allowed", status: response.status, error: "redirect without a location" } };
      }
      if (response.status >= 500 || response.status === 429) {
        await response.body?.cancel().catch(() => undefined);
        return { fixed: { verdict: "unreachable", status: response.status, error: `HTTP ${response.status}` } };
      }
      if (response.status >= 400) {
        // "Unavailable": no robots.txt means no restrictions.
        await response.body?.cancel().catch(() => undefined);
        return { fixed: { verdict: "allowed", status: response.status, error: null } };
      }
      const { bytes, truncated } = await readBodyCapped(response, MAX_ROBOTS_BYTES);
      // A cut at the byte cap can land mid-line; a partial rule ("Allow: /"
      // from "Allow: /blog") must not be parsed as if it were complete.
      const usable = truncated ? bytes.subarray(0, Math.max(bytes.lastIndexOf(0x0a), bytes.lastIndexOf(0x0d)) + 1) : bytes;
      return { groups: parseRobots(usable.toString("utf8")), status: response.status };
    }
    // Too many redirects: RFC 9309 lets the crawler treat the file as unavailable.
    return { fixed: { verdict: "allowed", status: null, error: "too many redirects" } };
  } catch (err) {
    const failure = classifyFetchError(err);
    return { fixed: { verdict: "unreachable", status: null, error: `${failure.code}: ${failure.message}`, dnsFailure: failure.kind === "dns" } };
  } finally {
    agent.destroy().catch(() => undefined);
  }
}
