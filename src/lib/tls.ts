/**
 * TLS certificate inspection over a raw tls.connect() handshake.
 *
 * We connect with rejectUnauthorized=false so that broken chains can still be
 * described, then evaluate validity ourselves from socket.authorized, the
 * hostname check and the certificate validity window.
 */

import { isIP } from "node:net";
import tls from "node:tls";
import type { DetailedPeerCertificate } from "node:tls";
import { errorCode, errorMessage } from "./errors.js";
import { assertPublicLiteral, createGuardedLookup, isPrivateTargetError } from "./lookup.js";

export interface TlsInspection {
  reachable: boolean;
  valid: boolean;
  authorized: boolean;
  authorizationError: string | null;
  hostnameMatches: boolean;
  protocol: string | null;
  cipher: string | null;
  subject: string | null;
  issuer: string | null;
  subjectAltNames: string[];
  validFrom: string | null;
  validTo: string | null;
  daysUntilExpiry: number | null;
  expired: boolean;
  notYetValid: boolean;
  selfSigned: boolean;
  keyType: string | null;
  keyBits: number | null;
  serialNumber: string | null;
  fingerprint256: string | null;
  chainLength: number;
  error: { code: string; message: string } | null;
  durationMs: number;
}

export interface TlsInspectOptions {
  timeoutMs: number;
  allowPrivate: boolean;
  port?: number;
  /** Cancels the handshake early when the owning tool call is aborted. */
  signal?: AbortSignal;
}

function emptyInspection(): TlsInspection {
  return {
    reachable: false,
    valid: false,
    authorized: false,
    authorizationError: null,
    hostnameMatches: false,
    protocol: null,
    cipher: null,
    subject: null,
    issuer: null,
    subjectAltNames: [],
    validFrom: null,
    validTo: null,
    daysUntilExpiry: null,
    expired: false,
    notYetValid: false,
    selfSigned: false,
    keyType: null,
    keyBits: null,
    serialNumber: null,
    fingerprint256: null,
    chainLength: 0,
    error: null,
    durationMs: 0
  };
}

function formatDistinguishedName(name: Record<string, string | string[]> | undefined): string | null {
  if (!name || typeof name !== "object") return null;
  const parts: string[] = [];
  for (const [key, raw] of Object.entries(name)) {
    const values = Array.isArray(raw) ? raw : [raw];
    for (const value of values) parts.push(`${key}=${value}`);
  }
  return parts.length > 0 ? parts.join(", ") : null;
}

function parseSubjectAltNames(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw
    .split(",")
    .map((entry) => entry.trim())
    .map((entry) =>
      entry
        .replace(/^DNS:/i, "")
        .replace(/^IP Address:/i, "")
        .replace(/^URI:/i, "")
    )
    .filter((entry) => entry.length > 0);
}

function computeChainLength(cert: DetailedPeerCertificate): number {
  let length = 0;
  const seen = new Set<string>();
  let current: DetailedPeerCertificate | undefined = cert;
  while (current && typeof current.fingerprint256 === "string" && !seen.has(current.fingerprint256)) {
    seen.add(current.fingerprint256);
    length++;
    current = current.issuerCertificate;
  }
  return length;
}

function detectSelfSigned(cert: DetailedPeerCertificate, chainLength: number): boolean {
  if (cert.issuerCertificate && cert.issuerCertificate.fingerprint256 === cert.fingerprint256) return true;
  const subject = formatDistinguishedName(cert.subject as Record<string, string | string[]>);
  const issuer = formatDistinguishedName(cert.issuer as Record<string, string | string[]>);
  return chainLength <= 1 && subject !== null && subject === issuer;
}

function describeAuthorizationError(raw: unknown): string | null {
  if (!raw) return null;
  if (typeof raw === "string") return raw;
  if (typeof raw === "object") {
    const code = (raw as { code?: unknown }).code;
    if (typeof code === "string") return code;
    const message = (raw as { message?: unknown }).message;
    if (typeof message === "string") return message;
  }
  return String(raw);
}

function classifyTlsError(err: unknown, host: string, port: number, timeoutMs: number): { code: string; message: string } {
  if (isPrivateTargetError(err)) return { code: "EPRIVATETARGET", message: errorMessage(err) };
  const code = errorCode(err) ?? "ETLS";
  let message = errorMessage(err);
  if (code === "ETIMEDOUT" || code === "ETIMEOUT") {
    return { code: "ETIMEDOUT", message: `TLS handshake with ${host}:${port} timed out after ${timeoutMs}ms` };
  }
  // A refused connection surfaces as node's happy-eyeballs AggregateError,
  // whose own message is empty; the first inner error carries the detail.
  if (message.length === 0 && err instanceof AggregateError) {
    const inner = err.errors.find((e) => e instanceof Error) as Error | undefined;
    message = inner?.message ?? "";
  }
  if (message.length === 0) message = `connection to ${host}:${port} failed (${code})`;
  return { code, message };
}

export function inspectTls(hostInput: string, options: TlsInspectOptions): Promise<TlsInspection> {
  const port = options.port ?? 443;
  // A bracketed IPv6 literal (as it appears in a URL host) is a literal, not
  // a name: brackets are stripped so it is neither sent as SNI nor looked up.
  const host = hostInput.replace(/^\[|\]$/g, "");
  return new Promise((resolve) => {
    const started = Date.now();
    const result = emptyInspection();
    let settled = false;
    let socket: tls.TLSSocket | null = null;

    const onAbort = (): void => {
      if (!result.reachable) result.error = { code: "EABORTED", message: `TLS inspection of ${host}:${port} was cancelled` };
      finish();
    };

    const finish = (): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", onAbort);
      result.durationMs = Date.now() - started;
      if (socket && !socket.destroyed) socket.destroy();
      resolve(result);
    };

    // A single wall-clock deadline armed before the socket exists bounds
    // lookup, connect and handshake together. The socket's own idle timer
    // resets on every handshake round trip and could only fire later, so it
    // is deliberately not armed.
    const timer = setTimeout(() => {
      if (!result.reachable) {
        result.error = { code: "ETIMEDOUT", message: `TLS handshake with ${host}:${port} timed out after ${options.timeoutMs}ms` };
      }
      finish();
    }, options.timeoutMs);

    if (options.signal?.aborted) {
      onAbort();
      return;
    }
    options.signal?.addEventListener("abort", onAbort, { once: true });

    try {
      // An IP-literal host never reaches the guarded lookup, so the private
      // space check must happen before the socket is opened.
      assertPublicLiteral(host, options.allowPrivate);
      socket = tls.connect(
        {
          host,
          port,
          // SNI carries hostnames only; an IP literal target is probed without it.
          ...(isIP(host) === 0 ? { servername: host } : {}),
          rejectUnauthorized: false,
          lookup: createGuardedLookup(options.allowPrivate),
          ALPNProtocols: ["http/1.1"]
        },
        () => {
          if (!socket) return;
          try {
            result.reachable = true;
            result.authorized = socket.authorized;
            result.authorizationError = socket.authorized ? null : describeAuthorizationError(socket.authorizationError);
            result.protocol = socket.getProtocol();
            const cipher = socket.getCipher();
            result.cipher = cipher ? cipher.name : null;

            const cert = socket.getPeerCertificate(true);
            if (cert && typeof cert === "object" && Object.keys(cert).length > 0) {
              result.subject = formatDistinguishedName(cert.subject as Record<string, string | string[]>);
              result.issuer = formatDistinguishedName(cert.issuer as Record<string, string | string[]>);
              result.subjectAltNames = parseSubjectAltNames(cert.subjectaltname);
              result.serialNumber = cert.serialNumber ?? null;
              result.fingerprint256 = cert.fingerprint256 ?? null;
              result.chainLength = computeChainLength(cert);
              result.selfSigned = detectSelfSigned(cert, result.chainLength);
              result.keyBits = typeof cert.bits === "number" ? cert.bits : null;
              result.keyType = cert.asn1Curve ? `EC (${cert.asn1Curve})` : cert.modulus ? "RSA" : null;

              const from = cert.valid_from ? new Date(cert.valid_from) : null;
              const to = cert.valid_to ? new Date(cert.valid_to) : null;
              const now = Date.now();
              if (from && !Number.isNaN(from.getTime())) {
                result.validFrom = from.toISOString();
                result.notYetValid = from.getTime() > now;
              }
              if (to && !Number.isNaN(to.getTime())) {
                result.validTo = to.toISOString();
                result.expired = to.getTime() < now;
                result.daysUntilExpiry = Math.floor((to.getTime() - now) / 86400000);
              }
              const identityError = tls.checkServerIdentity(host, cert);
              result.hostnameMatches = identityError === undefined;
            }
            result.valid = result.authorized && result.hostnameMatches && !result.expired && !result.notYetValid;
          } catch (err) {
            result.error = classifyTlsError(err, host, port, options.timeoutMs);
          }
          finish();
        }
      );

      socket.on("error", (err: unknown) => {
        if (!result.reachable) result.error = classifyTlsError(err, host, port, options.timeoutMs);
        finish();
      });

      socket.on("close", () => {
        if (!result.reachable && result.error === null) {
          result.error = { code: "ECONNCLOSED", message: `${host}:${port} closed the connection before the TLS handshake completed` };
        }
        finish();
      });
    } catch (err) {
      result.error = classifyTlsError(err, host, port, options.timeoutMs);
      finish();
    }
  });
}
