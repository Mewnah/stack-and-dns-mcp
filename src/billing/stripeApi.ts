/**
 * Minimal Stripe REST client for self-serve API key subscriptions, plus
 * webhook signature verification. Stripe's form encoding and error shape
 * are handled here so the key-signup routes stay declarative.
 */

import { createHmac, timingSafeEqual } from "node:crypto";
import { fetch as undiciFetch } from "undici";

export function flattenForm(prefix: string, value: unknown, out: URLSearchParams): void {
  if (value === null || value === undefined) return;
  if (Array.isArray(value)) {
    value.forEach((item, index) => flattenForm(`${prefix}[${index}]`, item, out));
    return;
  }
  if (typeof value === "object") {
    for (const [key, nested] of Object.entries(value as Record<string, unknown>)) flattenForm(prefix ? `${prefix}[${key}]` : key, nested, out);
    return;
  }
  out.append(prefix, String(value));
}

export class StripeApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly stripeCode: string | null
  ) {
    super(message);
    this.name = "StripeApiError";
  }
}

export class StripeApi {
  constructor(
    private readonly secretKey: string,
    private readonly apiBase: string,
    private readonly userAgent = "stack-and-dns-mcp/keys"
  ) {}

  async request(method: "GET" | "POST", path: string, params?: Record<string, unknown>): Promise<Record<string, unknown>> {
    const encoded = new URLSearchParams();
    if (params) flattenForm("", params, encoded);
    const query = method === "GET" && params ? `?${encoded.toString()}` : "";
    const response = await undiciFetch(`${this.apiBase}${path}${query}`, {
      method,
      headers: {
        authorization: `Bearer ${this.secretKey}`,
        "content-type": "application/x-www-form-urlencoded",
        "stripe-version": "2024-06-20",
        "user-agent": this.userAgent
      },
      body: method === "POST" ? encoded.toString() : undefined,
      signal: AbortSignal.timeout(15000)
    });
    let json: Record<string, unknown>;
    try {
      json = (await response.json()) as Record<string, unknown>;
    } catch {
      throw new StripeApiError(`Stripe ${method} ${path} returned a non-JSON response (${response.status})`, response.status, null);
    }
    if (!response.ok) {
      const error = (json.error as { message?: string; code?: string } | undefined) ?? {};
      throw new StripeApiError(`Stripe ${method} ${path} failed (${response.status}): ${error.message ?? "unknown error"}`, response.status, error.code ?? null);
    }
    return json;
  }

  /** Creates a hosted Checkout Session that starts a subscription to one price. */
  createSubscriptionCheckout(input: { priceId: string; successUrl: string; cancelUrl: string; metadata: Record<string, string> }): Promise<Record<string, unknown>> {
    return this.request("POST", "/v1/checkout/sessions", {
      mode: "subscription",
      line_items: [{ price: input.priceId, quantity: 1 }],
      success_url: input.successUrl,
      cancel_url: input.cancelUrl,
      metadata: input.metadata,
      subscription_data: { metadata: input.metadata }
    });
  }

  getCheckoutSession(id: string, expand: string[] = []): Promise<Record<string, unknown>> {
    return this.request("GET", `/v1/checkout/sessions/${encodeURIComponent(id)}`, expand.length > 0 ? { expand } : undefined);
  }
}

export interface WebhookVerification {
  ok: boolean;
  event: Record<string, unknown> | null;
  error: string | null;
}

/**
 * Verifies a Stripe-Signature header ("t=<unix>,v1=<hex>[,v1=...]") over the
 * exact raw body, with a replay window. Only v1 (HMAC-SHA256) signatures are
 * accepted.
 */
export function verifyStripeWebhook(rawBody: Buffer | string, header: string | undefined, secret: string, toleranceSeconds = 300, nowMs: number = Date.now()): WebhookVerification {
  if (!header) return { ok: false, event: null, error: "missing Stripe-Signature header" };
  let timestamp: number | null = null;
  const signatures: string[] = [];
  for (const part of header.split(",")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    const key = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (key === "t" && /^\d{1,12}$/.test(value)) timestamp = Number(value);
    else if (key === "v1" && /^[0-9a-f]{64}$/i.test(value)) signatures.push(value.toLowerCase());
  }
  if (timestamp === null || signatures.length === 0) return { ok: false, event: null, error: "malformed Stripe-Signature header" };
  if (Math.abs(nowMs / 1000 - timestamp) > toleranceSeconds) return { ok: false, event: null, error: "signature timestamp outside the tolerance window" };
  const body = typeof rawBody === "string" ? Buffer.from(rawBody, "utf8") : rawBody;
  const expected = createHmac("sha256", secret).update(`${timestamp}.`).update(body).digest();
  const matched = signatures.some((sig) => {
    const given = Buffer.from(sig, "hex");
    return given.length === expected.length && timingSafeEqual(given, expected);
  });
  if (!matched) return { ok: false, event: null, error: "signature mismatch" };
  try {
    const event = JSON.parse(body.toString("utf8")) as unknown;
    if (!event || typeof event !== "object" || Array.isArray(event)) return { ok: false, event: null, error: "payload is not a JSON object" };
    return { ok: true, event: event as Record<string, unknown>, error: null };
  } catch {
    return { ok: false, event: null, error: "payload is not valid JSON" };
  }
}

/** Builds a valid Stripe-Signature header for a payload (used by tests and local tooling). */
export function signStripePayload(payload: string, secret: string, timestampSeconds: number = Math.floor(Date.now() / 1000)): string {
  const signature = createHmac("sha256", secret).update(`${timestampSeconds}.${payload}`).digest("hex");
  return `t=${timestampSeconds},v1=${signature}`;
}
