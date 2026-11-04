/**
 * Typed error hierarchy. Tool handlers never let these escape as protocol
 * errors; they are converted into structured isError tool results so the
 * calling agent gets an actionable message instead of a transport failure.
 */

export type ToolErrorCode =
  | "INVALID_DOMAIN"
  | "PRIVATE_TARGET"
  | "DOMAIN_NOT_FOUND"
  | "NETWORK_TIMEOUT"
  | "NETWORK_ERROR"
  | "TLS_ERROR"
  | "BLOCKED_BY_WAF"
  | "RATE_LIMITED"
  | "UNAUTHORIZED"
  | "PAYMENT_REQUIRED"
  | "INSUFFICIENT_CREDITS"
  | "TOOL_TIMEOUT"
  | "CANCELLED"
  | "INVALID_ARGUMENT"
  | "NOT_FOUND"
  | "LIMIT_EXCEEDED"
  | "INTERNAL_ERROR";

export class ToolError extends Error {
  readonly code: ToolErrorCode;
  readonly retryable: boolean;
  readonly details: Record<string, unknown>;

  constructor(code: ToolErrorCode, message: string, options: { retryable?: boolean; details?: Record<string, unknown>; cause?: unknown } = {}) {
    super(message, options.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = "ToolError";
    this.code = code;
    this.retryable = options.retryable ?? false;
    this.details = options.details ?? {};
  }

  toJSON(): { code: ToolErrorCode; message: string; retryable: boolean; details: Record<string, unknown> } {
    return { code: this.code, message: this.message, retryable: this.retryable, details: this.details };
  }
}

export function isToolError(value: unknown): value is ToolError {
  return value instanceof ToolError;
}

export function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  if (typeof err === "string") return err;
  try {
    return JSON.stringify(err);
  } catch {
    return String(err);
  }
}

export function errorCode(err: unknown): string | undefined {
  if (err && typeof err === "object") {
    const anyErr = err as { code?: unknown; cause?: unknown; name?: unknown };
    if (typeof anyErr.code === "string") return anyErr.code;
    if (anyErr.cause && typeof anyErr.cause === "object") {
      const causeCode = (anyErr.cause as { code?: unknown }).code;
      if (typeof causeCode === "string") return causeCode;
    }
    if (typeof anyErr.name === "string") return anyErr.name;
  }
  return undefined;
}

export function isAbortLike(err: unknown): boolean {
  const code = errorCode(err);
  const msg = errorMessage(err).toLowerCase();
  return (
    code === "AbortError" ||
    code === "TimeoutError" ||
    code === "UND_ERR_CONNECT_TIMEOUT" ||
    code === "UND_ERR_HEADERS_TIMEOUT" ||
    code === "UND_ERR_BODY_TIMEOUT" ||
    code === "ETIMEDOUT" ||
    code === "ETIMEOUT" ||
    msg.includes("timeout") ||
    msg.includes("timed out") ||
    msg.includes("aborted")
  );
}

export function isTlsError(err: unknown): boolean {
  const code = errorCode(err) ?? "";
  const msg = errorMessage(err).toLowerCase();
  return (
    code.startsWith("ERR_TLS_") ||
    code === "CERT_HAS_EXPIRED" ||
    code === "CERT_NOT_YET_VALID" ||
    code === "DEPTH_ZERO_SELF_SIGNED_CERT" ||
    code === "SELF_SIGNED_CERT_IN_CHAIN" ||
    code === "UNABLE_TO_VERIFY_LEAF_SIGNATURE" ||
    code === "UNABLE_TO_GET_ISSUER_CERT_LOCALLY" ||
    code === "UNABLE_TO_GET_ISSUER_CERT" ||
    code === "CERT_UNTRUSTED" ||
    code === "ERR_SSL_WRONG_VERSION_NUMBER" ||
    code === "EPROTO" ||
    msg.includes("certificate") ||
    msg.includes("ssl") ||
    msg.includes("tls") ||
    msg.includes("handshake")
  );
}
