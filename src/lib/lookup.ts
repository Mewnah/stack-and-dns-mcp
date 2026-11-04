/**
 * Guarded hostname resolution for outbound sockets.
 *
 * Both the HTTP fetcher (undici Agent) and the TLS inspector (tls.connect)
 * are given this lookup so a domain that resolves to loopback, RFC 1918,
 * link-local or cloud-metadata space is refused at connect time. Doing the
 * check inside the lookup closes the DNS-rebinding window that a separate
 * pre-flight resolve would leave open.
 */

import dns from "node:dns";
import { isIP, type LookupFunction } from "node:net";
import { isPrivateAddress } from "./net.js";

export class PrivateTargetError extends Error {
  readonly code = "EPRIVATETARGET";
  readonly hostname: string;
  readonly address: string;

  constructor(hostname: string, address: string) {
    super(`Refusing to connect to ${hostname}: it resolves to the non-public address ${address}`);
    this.name = "PrivateTargetError";
    this.hostname = hostname;
    this.address = address;
  }
}

export function isPrivateTargetError(err: unknown): err is PrivateTargetError {
  if (err instanceof PrivateTargetError) return true;
  if (err && typeof err === "object") {
    const code = (err as { code?: unknown }).code;
    if (code === "EPRIVATETARGET") return true;
    const cause = (err as { cause?: unknown }).cause;
    if (cause && typeof cause === "object" && (cause as { code?: unknown }).code === "EPRIVATETARGET") return true;
  }
  return false;
}

/**
 * Node skips the lookup function entirely when the host is already an IP
 * literal, so the guard inside createGuardedLookup never sees it. Every
 * socket site therefore runs this check on the target host first; it
 * refuses literals in private space (including bracketed and zone-scoped
 * IPv6 forms) so a redirect to http://169.254.169.254/ cannot be followed.
 */
export function assertPublicLiteral(host: string, allowPrivate: boolean): void {
  if (allowPrivate) return;
  const literal = host.replace(/^\[|\]$/g, "").replace(/%.*$/, "");
  if (isIP(literal) !== 0 && isPrivateAddress(literal)) throw new PrivateTargetError(host, literal);
}

export function createGuardedLookup(allowPrivate: boolean): LookupFunction {
  return (hostname, options, callback) => {
    const wantAll = Boolean((options as { all?: boolean }).all);
    const allOptions: dns.LookupAllOptions = { ...(options as dns.LookupOptions), all: true };
    dns.lookup(hostname, allOptions, (err, addresses) => {
      if (err) {
        callback(err, wantAll ? [] : "", undefined);
        return;
      }
      const list: dns.LookupAddress[] = Array.isArray(addresses) ? addresses : [];
      if (!allowPrivate) {
        const blocked = list.find((entry) => isPrivateAddress(entry.address));
        if (blocked) {
          callback(new PrivateTargetError(hostname, blocked.address), wantAll ? [] : "", undefined);
          return;
        }
      }
      if (wantAll) {
        callback(null, list, undefined);
        return;
      }
      const first = list[0];
      if (!first) {
        const notFound = Object.assign(new Error(`getaddrinfo ENOTFOUND ${hostname}`), { code: "ENOTFOUND" });
        callback(notFound, "", undefined);
        return;
      }
      callback(null, first.address, first.family);
    });
  };
}
