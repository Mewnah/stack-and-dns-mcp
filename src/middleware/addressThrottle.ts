/**
 * Per-client-address throttle for requests that are handled before (or
 * without) an authenticated principal: bad credentials, payment redemption,
 * 402 challenge minting, key signup and Stripe checkout creation. All of
 * them share one bucket per address so an abuser cannot multiply the limit
 * by spreading requests across endpoints.
 */

import { createHash } from "node:crypto";
import type { Request, Response } from "express";
import { clientNetworkKey } from "../lib/net.js";
import type { RateLimiter } from "./rateLimit.js";

/** One bucket per client network (IPv4 address, or IPv6 /64). */
export function addressBucket(req: Request): string {
  const ip = clientNetworkKey(req.ip ?? req.socket.remoteAddress ?? "unknown");
  return `ip_${createHash("sha256").update(ip).digest("hex").slice(0, 16)}`;
}

/** Returns a function that answers 429 (and returns true) once the caller's address exceeds the per-minute ceiling. */
export function createAddressThrottle(limiter: RateLimiter, perMinute: number): (req: Request, res: Response) => boolean {
  return (req, res) => {
    const flood = limiter.consumeHttp(addressBucket(req), perMinute);
    if (flood.allowed) return false;
    res.setHeader("Retry-After", String(Math.ceil(flood.retryAfterMs / 1000)));
    res.status(429).json({ error: "rate_limited", message: "Too many requests from this address. Retry after the indicated delay.", retryAfterMs: flood.retryAfterMs });
    return true;
  };
}
