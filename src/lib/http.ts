/**
 * Homepage fetcher built on undici with hard deadlines, manual redirect
 * handling, body-size caps, charset-aware decoding, SSRF-guarded DNS and
 * automatic fallbacks (insecure TLS retry, HTTP downgrade).
 *
 * Budget model: the primary HTTPS attempt gets `timeoutMs`; fallback attempts
 * only run while the overall wall clock is below `2 * timeoutMs`. Time spent
 * in options.beforeRequest (the crawler's robots.txt check, which has its own
 * timeout) is not charged to the budget: each attempt's deadline and the
 * overall deadline are both extended by it. The worst case for an
 * unreachable host is therefore 2 * timeoutMs plus the guard time.
 */

import { Agent, fetch as undiciFetch } from "undici";
import type { Response as UndiciResponse } from "undici";
import { deadlineSignal } from "./async.js";
import { detectBlock, type BlockDetection } from "./blockDetection.js";
import { errorCode, errorMessage, isAbortLike, isTlsError } from "./errors.js";
import { assertPublicLiteral, createGuardedLookup, isPrivateTargetError } from "./lookup.js";

export interface FetchOptions {
  timeoutMs: number;
  maxBodyBytes: number;
  userAgent: string;
  allowPrivate: boolean;
  maxRedirects?: number;
  /** Aborts every in-flight attempt when the owning tool call is cancelled or times out. */
  signal?: AbortSignal;
  /**
   * Called before every request the fetch makes (the first URL, each
   * redirect hop, the http:// fallback). Throwing an error with code
   * EROBOTS refuses the request; the crawler uses it to honour robots.txt
   * on every origin it actually touches.
   */
  beforeRequest?: (url: URL) => Promise<void>;
}

export type FetchErrorKind = "timeout" | "dns" | "tls" | "connection" | "private_target" | "redirect" | "aborted" | "robots" | "unknown";

export interface FetchError {
  kind: FetchErrorKind;
  code: string;
  message: string;
}

export interface RedirectHop {
  url: string;
  status: number;
  location: string;
}

export interface PageFetchResult {
  ok: boolean;
  requestedUrl: string;
  finalUrl: string;
  finalHost: string | null;
  protocol: "https" | "http" | null;
  status: number | null;
  statusText: string | null;
  headers: Record<string, string>;
  setCookies: string[];
  html: string;
  bodyBytes: number;
  truncated: boolean;
  contentType: string | null;
  redirectChain: RedirectHop[];
  httpsDowngraded: boolean;
  tlsError: FetchError | null;
  error: FetchError | null;
  block: BlockDetection;
  timings: { totalMs: number; attempts: number };
}

interface ChainResult {
  finalUrl: string;
  status: number;
  statusText: string;
  headers: Record<string, string>;
  setCookies: string[];
  bytes: Buffer;
  truncated: boolean;
  contentType: string | null;
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
/** The most of an HTTPS failure's message kept ahead of the note on a refused http:// fallback. */
const MAX_PRIMARY_MESSAGE = 300;

function withCode(message: string, code: string): Error {
  return Object.assign(new Error(message), { code });
}

export function classifyFetchError(err: unknown): FetchError {
  const cause = err instanceof Error && err.cause !== undefined ? err.cause : undefined;
  if (cause !== undefined && isPrivateTargetError(cause)) {
    return { kind: "private_target", code: "EPRIVATETARGET", message: errorMessage(cause) };
  }
  if (isPrivateTargetError(err)) return { kind: "private_target", code: "EPRIVATETARGET", message: errorMessage(err) };
  const code = errorCode(err) ?? "EUNKNOWN";
  const message = errorMessage(err);
  // Our own refusals are known by their code alone: their messages embed a
  // host, path or Location that may read like a timeout ("timeout.com").
  if (code === "EREDIRECT") return { kind: "redirect", code, message };
  if (code === "EROBOTS") return { kind: "robots", code, message };
  const causeMessage = cause instanceof Error ? cause.message : "";
  if (isAbortLike(err) || (cause !== undefined && isAbortLike(cause))) {
    return { kind: "timeout", code: code === "EUNKNOWN" ? "ETIMEDOUT" : code, message: causeMessage || message || "request timed out" };
  }
  if (code === "ENOTFOUND" || code === "EAI_AGAIN" || code === "EAI_NONAME") return { kind: "dns", code, message: causeMessage || message };
  if (isTlsError(err) || (cause !== undefined && isTlsError(cause))) return { kind: "tls", code, message: causeMessage || message };
  if (
    code === "ECONNREFUSED" ||
    code === "ECONNRESET" ||
    code === "EHOSTUNREACH" ||
    code === "ENETUNREACH" ||
    code === "EPIPE" ||
    code === "UND_ERR_SOCKET" ||
    code === "UND_ERR_DESTROYED" ||
    code === "ECONNABORTED"
  ) {
    return { kind: "connection", code, message: causeMessage || message };
  }
  return { kind: "unknown", code, message: causeMessage ? `${message}: ${causeMessage}` : message };
}

function buildRequestHeaders(userAgent: string): Record<string, string> {
  return {
    "user-agent": userAgent,
    accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "accept-language": "en-US,en;q=0.9",
    "cache-control": "no-cache",
    pragma: "no-cache",
    "upgrade-insecure-requests": "1",
    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": "none",
    "sec-fetch-user": "?1"
  };
}

export async function readBodyCapped(response: UndiciResponse, maxBytes: number): Promise<{ bytes: Buffer; truncated: boolean }> {
  const body = response.body;
  if (!body) return { bytes: Buffer.alloc(0), truncated: false };
  const reader = body.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  let truncated = false;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value || value.byteLength === 0) continue;
      const room = maxBytes - total;
      if (value.byteLength > room) {
        if (room > 0) {
          chunks.push(Buffer.from(value.buffer, value.byteOffset, room));
          total += room;
        }
        truncated = true;
        break;
      }
      chunks.push(Buffer.from(value.buffer, value.byteOffset, value.byteLength));
      total += value.byteLength;
    }
  } finally {
    if (truncated) {
      try {
        await reader.cancel();
      } catch {
        // stream already closed
      }
    } else {
      try {
        reader.releaseLock();
      } catch {
        // lock already released
      }
    }
  }
  return { bytes: Buffer.concat(chunks, total), truncated };
}

function detectCharset(contentType: string | null, bytes: Buffer): string {
  const fromHeader = contentType ? /charset\s*=\s*"?([\w.:-]+)"?/i.exec(contentType)?.[1] : undefined;
  if (fromHeader) return fromHeader.toLowerCase();
  const head = bytes.subarray(0, 4096).toString("latin1");
  const fromMeta = /<meta[^>]+charset\s*=\s*["']?\s*([\w.:-]+)/i.exec(head)?.[1];
  return fromMeta ? fromMeta.toLowerCase() : "utf-8";
}

export function decodeBody(bytes: Buffer, contentType: string | null): string {
  const charset = detectCharset(contentType, bytes);
  try {
    return new TextDecoder(charset, { fatal: false }).decode(bytes);
  } catch {
    return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  }
}

/** Milliseconds spent in options.beforeRequest so far, shared by every attempt of one fetchHomepage call. */
interface GuardTime {
  ms: number;
}

async function followChain(startUrl: string, agent: Agent, attemptDeadline: number, options: FetchOptions, chain: RedirectHop[], guard: GuardTime): Promise<ChainResult> {
  const maxRedirects = options.maxRedirects ?? 5;
  let url = startUrl;
  let deadline = attemptDeadline;
  for (let hop = 0; hop <= maxRedirects; hop++) {
    // IP-literal targets bypass the guarded lookup, so they are checked here
    // on every hop; a redirect into private space is refused before connect.
    assertPublicLiteral(new URL(url).hostname, options.allowPrivate);
    if (options.beforeRequest) {
      // The guard (a robots.txt download) has its own timeout: its time is
      // not taken from the page's, or a slow robots.txt would starve it. It
      // is credited to this attempt and, through `guard`, to the overall
      // deadline, so it cannot crowd out the fallback attempts either.
      const guardStarted = Date.now();
      try {
        await options.beforeRequest(new URL(url));
      } finally {
        const spent = Date.now() - guardStarted;
        deadline += spent;
        guard.ms += spent;
      }
    }
    const remaining = deadline - Date.now();
    if (remaining <= 0) throw withCode("Request deadline exceeded before the response arrived", "ETIMEDOUT");

    const response = await undiciFetch(url, {
      method: "GET",
      headers: buildRequestHeaders(options.userAgent),
      redirect: "manual",
      dispatcher: agent,
      signal: deadlineSignal(remaining, options.signal)
    });

    const location = response.headers.get("location");
    if (REDIRECT_STATUSES.has(response.status) && location) {
      let next: string;
      try {
        next = new URL(location, url).toString();
      } catch {
        throw withCode(`Redirect target "${location}" is not a valid URL`, "EREDIRECT");
      }
      chain.push({ url, status: response.status, location: next });
      try {
        await response.body?.cancel();
      } catch {
        // body already consumed or closed
      }
      const protocol = new URL(next).protocol;
      if (protocol !== "http:" && protocol !== "https:") {
        throw withCode(`Redirected to unsupported scheme ${protocol}`, "EREDIRECT");
      }
      url = next;
      continue;
    }

    const { bytes, truncated } = await readBodyCapped(response, options.maxBodyBytes);
    const headers: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      const name = key.toLowerCase();
      if (name !== "set-cookie") headers[name] = value;
    });
    const setCookies = typeof response.headers.getSetCookie === "function" ? response.headers.getSetCookie() : [];
    return {
      finalUrl: url,
      status: response.status,
      statusText: response.statusText,
      headers,
      setCookies,
      bytes,
      truncated,
      contentType: response.headers.get("content-type")
    };
  }
  throw withCode(`Exceeded the maximum of ${maxRedirects} redirects`, "EREDIRECT");
}

/** One attempt's result together with the redirect hops that attempt actually followed. */
type AttemptOutcome = ({ chain: ChainResult } | { error: FetchError }) & { hops: RedirectHop[] };

export async function fetchHomepage(domain: string, options: FetchOptions): Promise<PageFetchResult> {
  const started = Date.now();
  const guard: GuardTime = { ms: 0 };
  const overallDeadline = (): number => started + options.timeoutMs * 2 + guard.ms;
  const lookup = createGuardedLookup(options.allowPrivate);
  const requestedUrl = `https://${domain}/`;

  const result: PageFetchResult = {
    ok: false,
    requestedUrl,
    finalUrl: requestedUrl,
    finalHost: null,
    protocol: null,
    status: null,
    statusText: null,
    headers: {},
    setCookies: [],
    html: "",
    bodyBytes: 0,
    truncated: false,
    contentType: null,
    redirectChain: [],
    httpsDowngraded: false,
    tlsError: null,
    error: null,
    block: { blocked: false, vendor: null, challengeType: null, reason: null },
    timings: { totalMs: 0, attempts: 0 }
  };

  const makeAgent = (rejectUnauthorized: boolean): Agent =>
    new Agent({
      connect: { timeout: options.timeoutMs, lookup, rejectUnauthorized },
      headersTimeout: options.timeoutMs,
      bodyTimeout: options.timeoutMs,
      connections: 4,
      pipelining: 1
    });

  const run = async (url: string, rejectUnauthorized: boolean): Promise<AttemptOutcome> => {
    result.timings.attempts++;
    const agent = makeAgent(rejectUnauthorized);
    const deadline = Math.min(Date.now() + options.timeoutMs, overallDeadline());
    const hops: RedirectHop[] = [];
    try {
      const chainResult = await followChain(url, agent, deadline, options, hops, guard);
      return { chain: chainResult, hops };
    } catch (err) {
      // undici rejects with the caller's abort reason verbatim (the MCP SDK
      // passes the client's free-text cancellation reason), which no error
      // classifier can recognise; the signal itself is the authority.
      if (options.signal?.aborted) {
        return { error: { kind: "aborted", code: "EABORTED", message: "The homepage fetch was cancelled before it completed" }, hops };
      }
      return { error: classifyFetchError(err), hops };
    } finally {
      agent.destroy().catch(() => undefined);
    }
  };

  let outcome = await run(requestedUrl, true);

  if ("error" in outcome && outcome.error.kind === "tls" && Date.now() < overallDeadline() && !options.signal?.aborted) {
    result.tlsError = outcome.error;
    outcome = await run(requestedUrl, false);
  }

  if (
    "error" in outcome &&
    outcome.error.kind !== "private_target" &&
    outcome.error.kind !== "dns" &&
    outcome.error.kind !== "redirect" &&
    outcome.error.kind !== "aborted" &&
    outcome.error.kind !== "robots" &&
    Date.now() < overallDeadline() &&
    !options.signal?.aborted
  ) {
    const primary = outcome;
    const fallback = await run(`http://${domain}/`, true);
    if ("chain" in fallback) {
      result.httpsDowngraded = true;
      outcome = fallback;
    } else if (fallback.error.kind === "aborted") {
      // A cancellation that landed during the downgrade is the real outcome,
      // not the earlier HTTPS failure it was trying to work around.
      outcome = fallback;
    } else if (fallback.error.kind === "robots") {
      // HTTPS failed (its robots.txt had allowed the fetch), so that failure
      // stays the outcome; the message says why no http:// result follows.
      // (OpenSSL's messages end in a line break.) The HTTPS part is cut short
      // when long (a connect timeout names the host, or every address it
      // tried), so the note after it stays inside the crawler's last_error cap.
      const head = primary.error.message.trimEnd();
      const cut = head.length > MAX_PRIMARY_MESSAGE ? `${head.slice(0, MAX_PRIMARY_MESSAGE - 3).trimEnd()}...` : head;
      const message = `${cut}; the http:// fallback was refused (${fallback.error.message})`;
      outcome = { ...primary, error: { ...primary.error, message } };
    } else {
      outcome = primary;
    }
  }

  // Only the attempt that produced the reported outcome contributes hops:
  // a retried attempt would otherwise list the same redirect twice, and a
  // discarded fallback would attach hops from a URL the result never used.
  result.redirectChain = outcome.hops;

  if ("error" in outcome) {
    result.error = outcome.error;
    // A failed fetch that followed redirects still pointed somewhere; report
    // that location so off-domain redirects are visible on failures too. Only
    // an http(s) target with a hostname qualifies: a redirect to javascript:,
    // data: or mailto: is a rejected hop, not a destination.
    const lastHop = outcome.hops[outcome.hops.length - 1];
    if (lastHop) {
      try {
        const target = new URL(lastHop.location);
        if ((target.protocol === "http:" || target.protocol === "https:") && target.hostname.length > 0) {
          result.finalUrl = lastHop.location;
          result.finalHost = target.hostname;
        }
      } catch {
        // unparseable target: leave the requested URL in place
      }
    }
  } else {
    const chain = outcome.chain;
    result.ok = true;
    result.status = chain.status;
    result.statusText = chain.statusText;
    result.headers = chain.headers;
    result.setCookies = chain.setCookies;
    result.finalUrl = chain.finalUrl;
    result.contentType = chain.contentType;
    result.bodyBytes = chain.bytes.length;
    result.truncated = chain.truncated;
    result.html = decodeBody(chain.bytes, chain.contentType);
    try {
      const parsed = new URL(chain.finalUrl);
      result.finalHost = parsed.hostname;
      result.protocol = parsed.protocol === "https:" ? "https" : "http";
    } catch {
      result.finalHost = null;
    }
    result.block = detectBlock(chain.status, chain.headers, result.html);
  }

  result.timings.totalMs = Date.now() - started;
  return result;
}
