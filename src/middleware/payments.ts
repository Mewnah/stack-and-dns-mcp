/**
 * HTTP 402 payment challenges and credential redemption.
 *
 * Two providers are supported and can be enabled together:
 *   - Stripe: the challenge carries a PaymentIntent client secret and a hosted
 *     Checkout URL; the agent (or its operator) pays, then presents the
 *     PaymentIntent id or Checkout Session id as a credential which is verified
 *     server-side through the Stripe API.
 *   - x402 / Machine Payments Protocol: the challenge carries an "accepts"
 *     requirement (exact-amount stablecoin transfer); the agent signs a payment
 *     payload which is verified and settled through a facilitator service.
 *
 * Challenges are advertised with an MPP-style WWW-Authenticate: Payment header
 * and an x402-compatible JSON body so both agent ecosystems can parse them.
 */

import { createHash, randomUUID } from "node:crypto";
import { fetch as undiciFetch } from "undici";
import { TOOL_CREDIT_COST, type AppConfig, type PaymentMethod } from "../config.js";
import { errorMessage } from "../lib/errors.js";
import { parseSafeInteger } from "../lib/numbers.js";
import { logger } from "../logger.js";
import { isLockContention } from "../store/db.js";
import { inGuardFamily, REDEEM_LOCK_BUDGET_MS, REDEEMED_PAYMENT_RETENTION_MS, type GuardFamily, type SettlementMarker, type SettlementState, type UsageTracker } from "./usage.js";

export const SERVICE_TAG = "stack-and-dns-mcp";

export interface X402Requirements {
  scheme: "exact";
  network: string;
  maxAmountRequired: string;
  resource: string;
  description: string;
  mimeType: string;
  payTo: string;
  maxTimeoutSeconds: number;
  asset: string;
  extra: Record<string, unknown>;
}

export interface StripeChallengeDetails {
  paymentIntentId: string;
  clientSecret: string;
  checkoutUrl: string | null;
  checkoutSessionId: string | null;
  amount: number;
  currency: string;
  credits: number;
}

export interface PaymentChallenge {
  id: string;
  expiresAt: number;
  resource: string;
  description: string;
  stripe: StripeChallengeDetails | null;
  x402: { accepts: X402Requirements; credits: number } | null;
}

export interface PaymentCredential {
  method: PaymentMethod | null;
  challengeId: string | null;
  paymentIntentId: string | null;
  checkoutSessionId: string | null;
  x402Payload: Record<string, unknown> | null;
}

export interface PaymentSuccess {
  ok: true;
  method: PaymentMethod;
  paymentId: string;
  credits: number;
  /** The prepaid principal the credits were granted to (already applied). */
  principalId: string;
  label: string;
  receipt: Record<string, unknown>;
}

/** The prepaid principal a payment's credits belong to. */
export interface PaymentGrant {
  principalId: string;
  label: string;
}

/**
 * Decides which prepaid principal a verified payment credits: the session a
 * top-up names (topUp: true), or a principal derived from the payment itself.
 * The derived id is a pure function of the public payment id, so only a
 * top-up target says anything about who is asking.
 */
export type GrantTarget = (payment: { method: PaymentMethod; paymentId: string }) => PaymentGrant & { topUp?: boolean };

export interface PaymentFailure {
  ok: false;
  code: string;
  message: string;
  /**
   * The principal the payment's credits belong to, so the answer can carry
   * its session token. Set on the answer to the request that settles the
   * payment as its first presenter (a fresh payment, or a retry that finds a
   * never-resumed 'settling' marker whose process died before answering; see
   * settleX402), when the principal it asks for is the stored target. For an
   * unconfirmed outcome it is set only if the marker records that an answer
   * went out (unconfirmedGrant). A later retry gets one only as a top-up by
   * the stored target, and auth.ts issues no token on a failure answer to a
   * top-up, which already holds its session. The payload alone proves
   * nothing once settled.
   */
  grant?: PaymentGrant;
}

export type PaymentResult = PaymentSuccess | PaymentFailure;

function base64UrlEncode(value: string): string {
  return Buffer.from(value, "utf8").toString("base64url");
}

function base64UrlDecode(value: string): string {
  return Buffer.from(value, "base64url").toString("utf8");
}

/** Fields a client may present to redeem a Stripe payment; the single source of the credential's wire shape. */
export interface StripeCredentialInput {
  challengeId?: string;
  paymentIntentId?: string;
  checkoutSessionId?: string;
}

/** Encodes a Stripe redemption credential exactly as parseCredential expects it (base64url JSON). */
export function encodeCredential(input: StripeCredentialInput): string {
  const body: Record<string, string> = { method: "stripe" };
  if (input.challengeId) body.challengeId = input.challengeId;
  if (input.paymentIntentId) body.paymentIntentId = input.paymentIntentId;
  if (input.checkoutSessionId) body.checkoutSessionId = input.checkoutSessionId;
  return base64UrlEncode(JSON.stringify(body));
}

/** Days a Stripe PaymentIntent stays redeemable; matches how long redeemed ids are remembered. */
const PAYMENT_MAX_AGE_DAYS = Math.floor(REDEEMED_PAYMENT_RETENTION_MS / 86400000);

const MAX_CANONICAL_DEPTH = 32;

/** Deterministic JSON with recursively sorted object keys. Throws on pathological nesting. */
export function canonicalJson(value: unknown, depth = 0): string {
  if (depth > MAX_CANONICAL_DEPTH) throw new RangeError(`payload nests deeper than ${MAX_CANONICAL_DEPTH} levels`);
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item, depth + 1)).join(",")}]`;
  if (value && typeof value === "object") {
    const entries = Object.keys(value as Record<string, unknown>)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson((value as Record<string, unknown>)[key], depth + 1)}`);
    return `{${entries.join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

/** Lowercased hex (without 0x) or decimal form of a value, for identity comparison. */
function hexIdentity(value: unknown): string {
  if (typeof value === "number" || typeof value === "bigint") return String(value).toLowerCase();
  if (typeof value !== "string") return "";
  return value.trim().toLowerCase().replace(/^0x/, "");
}

function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

/**
 * The replay identity of an x402 credential is the on-chain authorization it
 * carries, never a byte encoding the payer controls: for the "exact" scheme
 * that is the (from, nonce) pair of the EIP-3009 authorization, else the
 * signature, else a canonical hash of the signed inner payload. Wrapper
 * fields (challengeId, junk keys) and hex-case or number/string variants of
 * the same authorization therefore map to one key.
 */
export function x402ReplayKey(payload: Record<string, unknown>): string | null {
  const inner = payload.payload;
  if (!inner || typeof inner !== "object" || Array.isArray(inner)) return null;
  const record = inner as Record<string, unknown>;
  const authorization = record.authorization && typeof record.authorization === "object" && !Array.isArray(record.authorization) ? (record.authorization as Record<string, unknown>) : null;
  // The chain enforces uniqueness on the EIP-3009 (from, nonce) pair, so that
  // pair identifies the transfer regardless of how the rest of the
  // authorization is encoded or which optional fields the wrapper carries.
  // When a client omits `from` (facilitators can recover it from the
  // signature) the nonce alone is used; the settled transaction id remains the
  // second line of defence for either shape.
  const nonce = authorization ? hexIdentity(authorization.nonce) : "";
  const from = authorization ? hexIdentity(authorization.from) : "";
  const signature = hexIdentity(record.signature);
  let identity: string;
  if (nonce) {
    identity = from ? `auth:${from}:${nonce}` : `nonce:${nonce}`;
  } else if (signature) {
    identity = `sig:${signature}`;
  } else {
    try {
      identity = `payload:${canonicalJson(record)}`;
    } catch {
      return null;
    }
  }
  return `x402_${createHash("sha256").update(identity).digest("hex").slice(0, 32)}`;
}

/**
 * A value the payer controls, as one part of an authorization identity:
 * lowercased and without 0x, or a hash when it is not a short alphanumeric
 * value, so the guard id stays bounded whatever the payer sends. It never
 * contains ':' or '.'.
 */
function identityPart(value: unknown): string | null {
  const text = hexIdentity(value);
  if (!text) return null;
  return /^[0-9a-z]{1,80}$/.test(text) ? text : `h${sha256Hex(text).slice(0, 40)}`;
}

/** An EIP-3009 nonce as the nonce part of an authorization identity (lowercased, without 0x, bounded). */
export function x402NonceIdentity(nonce: unknown): string | null {
  return identityPart(nonce);
}

/** The one form a payer part of an authorization identity takes: a 20-byte address, lowercase hex without 0x. */
const PAYER_PART = /^[0-9a-f]{40}$/;

/**
 * A payer as the payer part of an authorization identity: a 20-byte hex address, lowercased and without 0x.
 * A CAIP-10 account id (`eip155:8453:0x...`) names the address in its last ':' segment. Anything else is
 * unknown (null): one payer written in two forms would give one authorization two identities, two guards
 * that do not see each other, and two credits.
 */
export function x402PayerIdentity(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const account = value.trim();
  const address = account
    .slice(account.lastIndexOf(":") + 1)
    .toLowerCase()
    .replace(/^0x/, "");
  return PAYER_PART.test(address) ? address : null;
}

/**
 * The part of an x402 authorization that is the same however it is
 * presented; it qualifies the settled transaction in the double-spend guard
 * id. The replay key is not it: one authorization has two replay keys (with
 * and without `from`, see x402ReplayKey).
 *
 * For an EIP-3009 authorization it is `<payer>.<nonce>`. The chain makes the
 * (from, nonce) pair unique, not the nonce, so two payers whose
 * authorizations reuse a nonce and land in one batched transaction are two
 * payments, each credited. The payer is the authorization's `from`, else the
 * payer the facilitator's /verify recovered from the signature (`payer`),
 * both normalized (x402PayerIdentity), so both presentations of one
 * authorization map to one identity. When neither is a usable address it is
 * the nonce alone, which yields to every payer-qualified guard of that
 * transaction and nonce, and which every such guard yields to (see
 * x402TransactionGuard), as it does to a payer part stored in any other
 * form. Without a nonce it is a hash of the signature, else
 * the replay key's own hash of the canonical payload (which has no variants).
 */
export function x402AuthorizationIdentity(payload: Record<string, unknown>, payer?: unknown): string | null {
  const inner = payload.payload;
  if (!inner || typeof inner !== "object" || Array.isArray(inner)) return null;
  const record = inner as Record<string, unknown>;
  const authorization = record.authorization && typeof record.authorization === "object" && !Array.isArray(record.authorization) ? (record.authorization as Record<string, unknown>) : null;
  const nonce = authorization ? identityPart(authorization.nonce) : null;
  if (nonce) {
    const who = (authorization ? x402PayerIdentity(authorization.from) : null) ?? x402PayerIdentity(payer);
    return who ? `${who}.${nonce}` : nonce;
  }
  const signature = hexIdentity(record.signature);
  if (signature) return `sig${sha256Hex(signature).slice(0, 40)}`;
  const key = x402ReplayKey(payload);
  return key ? `key${key.slice("x402_".length)}` : null;
}

/** The nonce part of an authorization identity: the whole identity when it is not payer-qualified. */
export function x402IdentityNonce(identity: string): string {
  const dot = identity.indexOf(".");
  return dot === -1 ? identity : identity.slice(dot + 1);
}

/** The ids a settled x402 payment is recorded under (`ids`) and the ones that, already recorded, mean it was credited before. */
export interface X402Claim {
  /** The transaction guard, then the replay key. */
  ids: string[];
  /** Checked, never written (see x402TransactionGuard). */
  blockedBy: string[];
  /** Checked, never written: the guards of the same transaction and nonce matched by shape that this identity yields to (see x402TransactionGuard). */
  blockedByFamily: GuardFamily | null;
  /** The bare settled transaction. */
  transaction: string;
}

/**
 * The ids a settled transaction is recorded under. The guard is
 * `x402_<tx>:<identity>`: a batching facilitator settles several
 * authorizations in one transaction, and each must be credited once, where
 * the bare `x402_<tx>` credited only the first. markerTx is what a 'settled'
 * marker stores as its tx, so that adopting the marker (`x402_<tx>` in every
 * version of the code) claims the same guard.
 *
 * blockedBy and blockedByFamily are checked, never written. blockedBy holds
 * legacy, the bare id written before round 8, and for a payer-qualified
 * identity the nonce-only guard, which a presentation whose payer was not
 * known records and which may be the same authorization. That presentation
 * yields in turn to every payer-qualified guard of the same transaction and
 * nonce (blockedByFamily, matched by shape), whichever order the two come
 * in: anyone can strip `from` from a settled, public authorization and
 * present it again to a facilitator that settles a spent authorization onto
 * its transaction. A payer part that is not a 20-byte address (an identity a
 * resumed marker or the CLI stored before payers were normalized) is as good
 * as unknown, in both directions: such an identity yields to every
 * payer-qualified guard, and a 20-byte payer yields to the guards whose payer
 * part is not one (the same family, unknownPayersOnly), so the round 9 guards
 * of a hashed CAIP-10 payer still block the authorization presented with
 * `from`. Two known payers whose authorizations reuse a nonce in one batch
 * never block each other, so both are credited. Of two settlements that do
 * block each other and are both still unrecorded, the one claimed first is
 * credited, not the one recorded first (see SettlementClaimant).
 */
export function x402TransactionGuard(transaction: string, identity: string): { markerTx: string; guard: string; legacy: string; blockedBy: string[]; blockedByFamily: GuardFamily | null } {
  const markerTx = `${transaction}:${identity}`;
  const bare = transaction.toLowerCase();
  const legacy = `x402_${bare}`;
  const dot = identity.indexOf(".");
  const payer = dot === -1 ? null : identity.slice(0, dot);
  const nonce = x402IdentityNonce(identity);
  const blockedBy = payer === null ? [legacy] : [legacy, `x402_${bare}:${nonce}`];
  const family: GuardFamily = { prefix: `x402_${bare}:`, suffix: `.${nonce}` };
  const blockedByFamily = payer !== null && PAYER_PART.test(payer) ? { ...family, unknownPayersOnly: true } : family;
  return { markerTx, guard: `x402_${markerTx.toLowerCase()}`, legacy, blockedBy, blockedByFamily };
}

/**
 * The ids a 'settled' marker is recorded under, and its bare transaction. A
 * marker written before round 8 (a bare tx and no identity) is claimed under
 * the legacy id its settling process claims, so the two never both credit it.
 */
export function settledMarkerClaim(marker: SettlementMarker): X402Claim | null {
  if (!marker.tx) return null;
  const suffix = marker.identity ? `:${marker.identity}` : null;
  if (marker.identity && suffix && marker.tx.length > suffix.length && marker.tx.endsWith(suffix)) {
    const transaction = marker.tx.slice(0, -suffix.length);
    const { guard, blockedBy, blockedByFamily } = x402TransactionGuard(transaction, marker.identity);
    return { ids: [guard, marker.paymentId], blockedBy, blockedByFamily, transaction };
  }
  return { ids: [`x402_${marker.tx.toLowerCase()}`, marker.paymentId], blockedBy: [], blockedByFamily: null, transaction: marker.tx };
}

/** The EIP-3009 validBefore deadline (unix seconds) carried by an "exact" payload, when present and numeric. */
export function x402ValidBefore(payload: Record<string, unknown>): number | null {
  const inner = payload.payload;
  if (!inner || typeof inner !== "object" || Array.isArray(inner)) return null;
  const authorization = (inner as Record<string, unknown>).authorization;
  if (!authorization || typeof authorization !== "object" || Array.isArray(authorization)) return null;
  const raw = (authorization as Record<string, unknown>).validBefore;
  const value = typeof raw === "number" ? raw : typeof raw === "string" && /^\d+$/.test(raw.trim()) ? Number(raw.trim()) : Number.NaN;
  return Number.isFinite(value) ? value : null;
}

function x402AlreadyRedeemed(): PaymentResult {
  return {
    ok: false,
    code: "payment_already_redeemed",
    message: "This x402 payment has already been redeemed. Use the session token from its Payment-Receipt; a payment payload alone never re-issues a token."
  };
}

/**
 * A presentation credited nothing because its transaction's credits went, or go, to another presentation of the
 * same authorization: one credited before it, or one that settled first and is still being recorded.
 */
function x402TransactionRedeemed(transaction: string): PaymentFailure {
  return { ok: false, code: "payment_already_redeemed", message: `Transaction ${transaction} has already been redeemed.` };
}

/**
 * A retry of a payment whose recording was finished for the principal chosen when it settled. Never the answer
 * when that principal was given nothing (x402TransactionRedeemed).
 */
function x402RecordedForFirstRequest(): PaymentResult {
  return {
    ok: false,
    code: "payment_already_redeemed",
    message:
      "This x402 payment is recorded. Its credits went to the principal whose session token was returned with the earlier 503 or 502 answer (or to the prepaid session it topped up); a payment payload alone never re-issues a token."
  };
}

/** The payment settled (or may have) but its credits are not recorded yet; the grant is set only for the request that settled it. */
function x402RecordingPending(grant?: PaymentGrant): PaymentFailure {
  return {
    ok: false,
    code: "payment_recording_failed",
    message: grant
      ? "The payment settled but could not be recorded right now. Do not pay again: it is recorded automatically and its credits go to the session token returned with this answer (X-Session-Token), or to the prepaid session this payment tops up. Retrying the same payment header also finishes the recording."
      : "The payment settled but is not recorded yet. Do not pay again: it is recorded automatically; retry the same payment header shortly.",
    ...(grant ? { grant } : {})
  };
}

/** The shared marker could not be read, so whether money moved is not known here. */
function x402StateUnavailable(): PaymentFailure {
  return { ok: false, code: "payment_recording_failed", message: "The payment's state could not be checked right now. Do not pay again; retry the same request shortly." };
}

/** A database failure before any money moved. */
function x402NotStarted(): PaymentFailure {
  return { ok: false, code: "payment_recording_failed", message: "The payment could not be processed right now and nothing was charged. Retry the same request shortly." };
}

function x402Unconfirmed(reason: string, grant?: PaymentGrant): PaymentFailure {
  return {
    ok: false,
    code: "x402_settlement_unconfirmed",
    message: `${reason} The payment may have moved: do not pay again. Retry with the same payment header later, or contact support with it.`,
    ...(grant ? { grant } : {})
  };
}

function x402EarlierUnconfirmed(): PaymentFailure {
  return x402Unconfirmed("An earlier settlement of this payment did not report its outcome.");
}

function x402InProgress(): PaymentFailure {
  return { ok: false, code: "payment_redemption_in_progress", message: "This payment is being settled by a concurrent request. Do not pay again; retry this same request in a moment." };
}

const TRANSACTION_KEYS = /^(transaction|txHash|transactionHash|tx_hash|txid|transactionId|hash)$/i;

/** Finds the settled transaction id in a facilitator response, tolerating the field names in circulation and one level of nesting. */
export function settledTransactionId(settle: unknown, depth = 0): string | null {
  if (!settle || typeof settle !== "object" || Array.isArray(settle) || depth > 4) return null;
  const record = settle as Record<string, unknown>;
  for (const [key, value] of Object.entries(record)) {
    if (TRANSACTION_KEYS.test(key) && typeof value === "string" && value.trim().length > 0) return value.trim();
  }
  for (const value of Object.values(record)) {
    const nested = settledTransactionId(value, depth + 1);
    if (nested) return nested;
  }
  return null;
}

function flattenForm(prefix: string, value: unknown, out: URLSearchParams): void {
  if (value === null || value === undefined) return;
  if (typeof value === "object" && !Array.isArray(value)) {
    for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
      flattenForm(prefix ? `${prefix}[${key}]` : key, nested, out);
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => flattenForm(`${prefix}[${index}]`, item, out));
    return;
  }
  out.append(prefix, String(value));
}

class StripeClient {
  constructor(
    private readonly secretKey: string,
    private readonly apiBase: string
  ) {}

  private async request(method: "GET" | "POST", path: string, form?: Record<string, unknown>): Promise<Record<string, unknown>> {
    const body = form ? new URLSearchParams() : undefined;
    if (form && body) flattenForm("", form, body);
    const response = await undiciFetch(`${this.apiBase}${path}`, {
      method,
      headers: {
        authorization: `Bearer ${this.secretKey}`,
        "content-type": "application/x-www-form-urlencoded",
        "stripe-version": "2024-06-20",
        "user-agent": `${SERVICE_TAG}/payments`
      },
      body: body ? body.toString() : undefined,
      signal: AbortSignal.timeout(15000)
    });
    const json = (await response.json()) as Record<string, unknown>;
    if (!response.ok) {
      const error = (json.error as { message?: string; type?: string; code?: string } | undefined) ?? {};
      throw new Error(`Stripe ${method} ${path} failed (${response.status}): ${error.message ?? "unknown error"}`);
    }
    return json;
  }

  createPaymentIntent(input: { amount: number; currency: string; description: string; metadata: Record<string, string> }): Promise<Record<string, unknown>> {
    return this.request("POST", "/v1/payment_intents", {
      amount: input.amount,
      currency: input.currency,
      description: input.description,
      metadata: input.metadata,
      automatic_payment_methods: { enabled: true }
    });
  }

  createCheckoutSession(input: { amount: number; currency: string; productName: string; successUrl: string; cancelUrl: string; metadata: Record<string, string> }): Promise<Record<string, unknown>> {
    return this.request("POST", "/v1/checkout/sessions", {
      mode: "payment",
      success_url: input.successUrl,
      cancel_url: input.cancelUrl,
      line_items: [
        {
          quantity: 1,
          price_data: {
            currency: input.currency,
            unit_amount: input.amount,
            product_data: { name: input.productName }
          }
        }
      ],
      metadata: input.metadata,
      payment_intent_data: { metadata: input.metadata }
    });
  }

  getPaymentIntent(id: string): Promise<Record<string, unknown>> {
    return this.request("GET", `/v1/payment_intents/${encodeURIComponent(id)}`);
  }

  getCheckoutSession(id: string): Promise<Record<string, unknown>> {
    return this.request("GET", `/v1/checkout/sessions/${encodeURIComponent(id)}`);
  }
}

/** A settled x402 payment this process recorded or is still recording; committed entries wait up to UNRECORDED_RETENTION_MS for a top-up's retry. */
interface UnrecordedSettlement {
  /** The guard id (x402TransactionGuard) and the replay key. */
  ids: string[];
  /** The guard ids it yields to (x402TransactionGuard's blockedBy): checked, never written. */
  blockedBy: string[];
  /** The guards of the same transaction and nonce matched by shape that this identity yields to (x402TransactionGuard's blockedByFamily): checked, never written. */
  blockedByFamily: GuardFamily | null;
  target: PaymentGrant;
  credits: number;
  receipt: Record<string, unknown>;
  committed: boolean;
  at: number;
  /** When the payment was claimed: its marker's `at`, which orders the settlements of one authorization (see SettlementClaimant). */
  claimedAt: number;
  tx: string;
  /** The tx the 'settled' marker stores: the transaction qualified by the authorization's identity. */
  markerTx: string;
  /** Whether the shared marker holds the transaction, so another process (or a restart) can finish the recording. */
  markerSettled: boolean;
}

/**
 * A settled payment whose credits are not recorded yet, as the first-settlement rule sees it
 * (PaymentManager.yieldsToEarlierSettlement): an entry of this process, or a 'settled' marker.
 *
 * Before an authorization settles only its payer holds it; once settled, the chain carries all of it, so anyone
 * can present it again, with or without `from`, to a facilitator that verifies leniently and settles a spent
 * authorization onto its transaction. The presentations have two replay keys, and each guard blocks the other
 * (x402TransactionGuard), so on its own the guard credits whichever is recorded first. Recording can be held up (a
 * database error kept for a retry, or a write lock waited out), and a stranger's presentation recorded meanwhile
 * would take the credits from the payer, whose answer already carried the session. The settlement claimed first
 * is credited instead. A payment's claim time (`at`, written before /settle and kept when a settle is resumed) is
 * earlier for the payer's presentation than for any presentation made after the authorization went public.
 * Processes compare claim times from their own clocks, which is sound while their skew stays below the time from
 * the payer's settle to a re-presentation (the settle itself, then a /verify).
 */
interface SettlementClaimant {
  paymentId: string;
  /** Its transaction guard (x402TransactionGuard), which its recording writes. */
  guard: string;
  blockedBy: readonly string[];
  blockedByFamily: GuardFamily | null;
  /** When its payment was claimed (the marker's `at`). */
  at: number;
}

/** Whether a recorded guard keeps the claimant from being credited: its own guard (another replay key, same identity), a guard it yields to by name, or one of its family. */
function guardBlocks(guard: string, claimant: SettlementClaimant): boolean {
  return guard === claimant.guard || claimant.blockedBy.includes(guard) || (claimant.blockedByFamily !== null && inGuardFamily(guard, claimant.blockedByFamily));
}

/**
 * What adopting a 'settled' marker did (PaymentManager.adoptMarker): credited its target; recorded it but credited
 * nothing, because an id it holds or yields to was already recorded; or yielded to an earlier settlement of the same
 * authorization, recording its payment id alone.
 */
type Adoption = "credited" | "uncredited" | "yielded";

/** Claim order: the claim time, then the payment id, so that every process orders the same settlements alike and no two yield to each other. */
function claimedFirst(a: SettlementClaimant, b: SettlementClaimant): number {
  return a.at - b.at || (a.paymentId < b.paymentId ? -1 : a.paymentId > b.paymentId ? 1 : 0);
}

const RECORDING_RETRY_MS = 10_000;
const UNRECORDED_RETENTION_MS = 24 * 60 * 60 * 1000;
/**
 * A 'settling' marker older than this belongs to a process that died
 * mid-settle: /verify (15 s) and /settle (30 s) time out well before it.
 */
export const SETTLING_STALE_MS = 60_000;
/**
 * An 'unknown' marker is re-verified with the facilitator at most once per
 * this long, across processes (its updated_at is claimed by compare-and-set).
 * Inside the window a retry is answered "unconfirmed" from the marker alone:
 * a client re-attaching the header to every request would otherwise cost a
 * /verify call each time.
 */
export const UNKNOWN_REVERIFY_MS = 60_000;
/**
 * How long after its last update an unconfirmed payment keeps blocking its
 * session's spending routes (502 instead of a payment demand). After that the
 * session may buy again; the payment's own header still answers "unconfirmed"
 * for as long as its marker is kept.
 */
export const UNKNOWN_BLOCKS_PURCHASE_MS = 24 * 60 * 60 * 1000;
/** Local records of a session that went out with an unwritten marker are capped; they only ever accumulate on database failures. */
const MAX_ANSWERED_UNMARKED = 10_000;
/**
 * A 'settled' marker is finished by another request or process only after
 * this long. The settling request records it right after marking it and keeps
 * retrying a locked database for REDEEM_LOCK_BUDGET_MS of wall time, plus one
 * last attempt that can block for BUSY_TIMEOUT_MS (about 16 s in all). Three
 * times the budget leaves room for a stalled event loop. recordSettlement
 * still answers correctly if an adopter wins anyway.
 */
const ADOPT_SETTLED_AFTER_MS = 3 * REDEEM_LOCK_BUDGET_MS;
/**
 * 'unknown' and stale 'settling' markers are kept as long as redeemed payment
 * ids, so a late retry of the header is answered "unconfirmed", never with a
 * fresh payment demand (x402_expired). Markers are tiny, and
 * UNKNOWN_BLOCKS_PURCHASE_MS keeps their sessions from being blocked that long.
 * Operators reconcile them with src/cli/settlements.ts.
 */
const SETTLEMENT_MARKER_RETENTION_MS = REDEEMED_PAYMENT_RETENTION_MS;

/**
 * What redeemX402 does with a payload, decided from local state alone (PaymentManager.routeX402). Only
 * "reverify" and "settle" call the facilitator; answersLocally() counts every other route as local, except an
 * unreadable marker.
 */
type X402Route =
  | { kind: "invalid" }
  /** (1) Settled by this process and not yet recorded (or recorded, waiting for a top-up's retry). */
  | { kind: "pending"; paymentId: string; entry: UnrecordedSettlement }
  /** The marker could not be read. */
  | { kind: "unavailable"; paymentId: string; error: unknown }
  /** A marker whose payment is already recorded: its removal failed, or the recording process is about to remove it. */
  | { kind: "leftover"; paymentId: string; marker: SettlementMarker }
  /** (3) Settled, credits not recorded yet. credited: its transaction guard is already redeemed, so adopting only records this payment id. */
  | { kind: "finish"; paymentId: string; marker: SettlementMarker; credited: boolean }
  /** (5) A settle is in flight in some process. */
  | { kind: "in-progress" }
  /** (4) Answered "unconfirmed" from the marker: past validBefore, or inside the re-verification window. */
  | { kind: "unconfirmed" }
  /** (4) Asked about again: an 'unknown' marker past its window, or a stale 'settling' one. */
  | { kind: "reverify"; paymentId: string; marker: SettlementMarker }
  /** (6) */
  | { kind: "redeemed" }
  /** (7) */
  | { kind: "expired" }
  /** (8) A fresh payment. */
  | { kind: "settle"; paymentId: string };

/**
 * Lets due timers and pending I/O run before the caller goes on: the timer fires in the next loop iteration's
 * timers phase, and the immediate after that iteration's poll phase (a bare setImmediate would skip both).
 */
function yieldToEventLoop(): Promise<void> {
  return new Promise((resolve) => setTimeout(() => setImmediate(resolve), 0));
}

/** The receipt a marker or a pending entry answers with; the stored copy never carries a session token. */
function x402Success(paymentId: string, target: PaymentGrant, credits: number, receipt: Record<string, unknown>): PaymentResult {
  return { ok: true, method: "x402", paymentId, credits, principalId: target.principalId, label: target.label, receipt: { ...receipt, redeemedAt: new Date().toISOString() } };
}

export class PaymentManager {
  private readonly challenges = new Map<string, PaymentChallenge>();
  /** Settled x402 payments by replay key: uncommitted ones are retried; committed ones wait for a top-up's retry. */
  private readonly unrecorded = new Map<string, UnrecordedSettlement>();
  /**
   * Settled x402 payments whose settling request is recording them right now (recordSettlement), by replay key:
   * the first-settlement rule must see a recording that waits out a locked database before it lands in `unrecorded`.
   */
  private readonly recording = new Map<string, UnrecordedSettlement>();
  /** Markers whose removal failed (a refused settlement, or a payment a sibling recorded meanwhile), with the version to remove; a later resume keeps its marker. */
  private readonly unended = new Map<string, number>();
  /**
   * Payments this process answered with their session while the 'settled' marker could not be written, so the
   * marker still reads as a never-resumed 'settling' one (see the first-presenter rule in settleX402). Only this
   * process knows, but the check is cheap. By replay key, with the time of the answer.
   */
  private readonly answeredUnmarked = new Map<string, number>();
  private recordingTimer: NodeJS.Timeout | null = null;
  private closed = false;
  private readonly stripe: StripeClient | null;
  private lastPrune = Date.now();

  constructor(
    private readonly config: AppConfig,
    private readonly usage: UsageTracker
  ) {
    const stripeKey = config.payments.stripe.secretKey;
    this.stripe = config.payments.methods.includes("stripe") && stripeKey ? new StripeClient(stripeKey, config.payments.stripe.apiBase) : null;
    // A restarted fleet must record 'settled' markers left by a process that died, without waiting for
    // some x402 request to arrive: until then the session handed out with their 503 has no credits.
    if (usage.hasSharedLedger && this.x402Enabled) this.ensureRecordingTimer();
  }

  get stripeEnabled(): boolean {
    return this.config.payments.enabled && this.stripe !== null;
  }

  get x402Enabled(): boolean {
    const x = this.config.payments.x402;
    return this.config.payments.enabled && this.config.payments.methods.includes("x402") && Boolean(x.facilitatorUrl && x.payTo);
  }

  get enabled(): boolean {
    return this.stripeEnabled || this.x402Enabled;
  }

  availableMethods(): PaymentMethod[] {
    const methods: PaymentMethod[] = [];
    if (this.stripeEnabled) methods.push("stripe");
    if (this.x402Enabled) methods.push("x402");
    return methods;
  }

  pricing(): Record<string, unknown> {
    const { stripe, x402 } = this.config.payments;
    return {
      enabled: this.enabled,
      methods: this.availableMethods(),
      stripe: this.stripeEnabled ? { amount: stripe.priceCents, currency: stripe.currency, credits: stripe.creditsPerPurchase, unit: "minor currency units" } : null,
      x402: this.x402Enabled
        ? { network: x402.network, asset: x402.asset, assetName: x402.assetName, assetVersion: x402.assetVersion, amountAtomic: x402.priceAtomic, credits: x402.creditsPerPayment, payTo: x402.payTo }
        : null,
      creditCosts: TOOL_CREDIT_COST
    };
  }

  private prune(): void {
    const now = Date.now();
    if (now - this.lastPrune < 60000) return;
    this.lastPrune = now;
    for (const [id, challenge] of this.challenges) {
      if (challenge.expiresAt < now) this.challenges.delete(id);
    }
    // Here rather than in the recording timer, which stops once nothing is left to record.
    for (const [id, entry] of this.unrecorded) {
      if (entry.committed && now - entry.at > UNRECORDED_RETENTION_MS) this.unrecorded.delete(id);
    }
    for (const [id, at] of this.answeredUnmarked) {
      if (now - at > SETTLEMENT_MARKER_RETENTION_MS) this.answeredUnmarked.delete(id);
    }
    try {
      this.usage.pruneSettlements(now - SETTLEMENT_MARKER_RETENTION_MS);
    } catch (err) {
      logger.warn("pruning x402 settlement markers failed", { error: err });
    }
  }

  /**
   * Whether an x402 payment whose credits go to this principal is still unfinished, so an empty balance
   * must not be answered with a new payment demand. It returns 'settled' when the money moved but the
   * credits are not recorded, 'settling' while a settle is in flight, and 'unknown' when a settle never
   * reported its outcome, for UNKNOWN_BLOCKS_PURCHASE_MS after the marker's last update. It returns null when
   * nothing is pending, and "unavailable" when the state cannot be read: that must not become a payment
   * demand either.
   */
  pendingFor(principalId: string): SettlementState | "unavailable" | null {
    for (const entry of this.unrecorded.values()) {
      if (!entry.committed && entry.target.principalId === principalId) return "settled";
    }
    try {
      const now = Date.now();
      return this.usage.pendingSettlementState(principalId, now - SETTLING_STALE_MS, now - UNKNOWN_BLOCKS_PURCHASE_MS);
    } catch (err) {
      logger.warn("pending x402 settlements could not be read", { principal: principalId, error: err });
      return "unavailable";
    }
  }

  /** Stops the background recording timer (shutdown). Pending recordings are finished by another process or after a restart. */
  close(): void {
    this.closed = true;
    if (this.recordingTimer) {
      clearInterval(this.recordingTimer);
      this.recordingTimer = null;
    }
  }

  /**
   * Serializes redemption per payment reference. The redeemed check and the
   * redeemed mark are separated by awaited network calls, so without this
   * lock two concurrent requests carrying the same payment would both pass
   * the check and both be granted credits.
   */
  private readonly inFlight = new Set<string>();

  private async withRedemptionLock(key: string, fn: () => Promise<PaymentResult>, busy?: () => PaymentResult): Promise<PaymentResult> {
    if (this.inFlight.has(key)) {
      if (busy) return busy();
      // Only Stripe uses this default (x402 passes x402InProgress). A retry after the holder redeemed the payment
      // gets payment_already_redeemed and no token, so the message must not promise one.
      return {
        ok: false,
        code: "payment_redemption_in_progress",
        message:
          "This payment is being verified by a concurrent request. Do not pay again; retry this same request in a moment. The session token is returned only with the answer that redeems the payment (Payment-Receipt / X-Session-Token); a payment reference alone never re-issues one."
      };
    }
    this.inFlight.add(key);
    try {
      return await fn();
    } finally {
      this.inFlight.delete(key);
    }
  }

  private buildX402Requirements(resource: string): X402Requirements {
    const x = this.config.payments.x402;
    return {
      scheme: "exact",
      network: x.network,
      maxAmountRequired: x.priceAtomic,
      resource,
      description: `${x.creditsPerPayment} ${SERVICE_TAG} inspection credits`,
      mimeType: "application/json",
      payTo: x.payTo ?? "",
      maxTimeoutSeconds: 300,
      asset: x.asset,
      // The asset's EIP-712 domain, which the payer signs over: it must equal the token's name() and version().
      extra: { name: x.assetName, version: x.assetVersion, service: SERVICE_TAG }
    };
  }

  async createChallenge(resource: string): Promise<PaymentChallenge> {
    this.prune();
    const id = `chl_${randomUUID().replace(/-/g, "")}`;
    const expiresAt = Date.now() + this.config.payments.challengeTtlMs;
    const challenge: PaymentChallenge = {
      id,
      expiresAt,
      resource,
      description: `Prepaid inspection credits for ${SERVICE_TAG}`,
      stripe: null,
      x402: null
    };

    if (this.stripeEnabled && this.stripe) {
      const stripeCfg = this.config.payments.stripe;
      const publicUrl = this.config.http.publicUrl;
      const metadata = { service: SERVICE_TAG, challenge_id: id, credits: String(stripeCfg.creditsPerPurchase) };
      // The PaymentIntent and the Checkout Session are independent Stripe
      // objects that share only the metadata, so they are created in
      // parallel: a 402 costs one Stripe round trip instead of two.
      const [intentOutcome, sessionOutcome] = await Promise.allSettled([
        this.stripe.createPaymentIntent({
          amount: stripeCfg.priceCents,
          currency: stripeCfg.currency,
          description: `${stripeCfg.creditsPerPurchase} ${SERVICE_TAG} credits`,
          metadata
        }),
        this.stripe.createCheckoutSession({
          amount: stripeCfg.priceCents,
          currency: stripeCfg.currency,
          productName: `${stripeCfg.creditsPerPurchase} ${SERVICE_TAG} credits`,
          successUrl: stripeCfg.successUrl ?? `${publicUrl}/payments/success?session_id={CHECKOUT_SESSION_ID}`,
          cancelUrl: stripeCfg.cancelUrl ?? `${publicUrl}/payments/cancel`,
          metadata
        })
      ]);
      if (intentOutcome.status === "rejected") {
        logger.error("stripe payment intent creation failed", { error: intentOutcome.reason });
      } else {
        const intent = intentOutcome.value;
        let checkoutUrl: string | null = null;
        let checkoutSessionId: string | null = null;
        if (sessionOutcome.status === "fulfilled") {
          checkoutUrl = typeof sessionOutcome.value.url === "string" ? sessionOutcome.value.url : null;
          checkoutSessionId = typeof sessionOutcome.value.id === "string" ? sessionOutcome.value.id : null;
        } else {
          logger.warn("stripe checkout session creation failed; challenge will only carry the payment intent", { error: sessionOutcome.reason });
        }
        challenge.stripe = {
          paymentIntentId: String(intent.id),
          clientSecret: String(intent.client_secret),
          checkoutUrl,
          checkoutSessionId,
          amount: stripeCfg.priceCents,
          currency: stripeCfg.currency,
          credits: stripeCfg.creditsPerPurchase
        };
      }
    }

    if (this.x402Enabled) {
      challenge.x402 = { accepts: this.buildX402Requirements(resource), credits: this.config.payments.x402.creditsPerPayment };
    }

    this.challenges.set(id, challenge);
    return challenge;
  }

  challengeHeaders(challenge: PaymentChallenge): Record<string, string> {
    const methods = this.availableMethods().join(" ");
    const request = base64UrlEncode(JSON.stringify(this.challengeBody(challenge)));
    const params = [`id="${challenge.id}"`, `realm="${SERVICE_TAG}"`, `methods="${methods}"`, `intent="charge"`, `expires="${new Date(challenge.expiresAt).toISOString()}"`, `request="${request}"`];
    return {
      "WWW-Authenticate": `Payment ${params.join(", ")}`,
      "Cache-Control": "no-store",
      "X-Payment-Challenge-Id": challenge.id
    };
  }

  challengeBody(challenge: PaymentChallenge): Record<string, unknown> {
    const accepts: unknown[] = [];
    if (challenge.x402) accepts.push(challenge.x402.accepts);
    if (challenge.stripe) {
      accepts.push({
        scheme: "stripe",
        network: "stripe",
        maxAmountRequired: String(challenge.stripe.amount),
        asset: challenge.stripe.currency,
        payTo: "stripe",
        resource: challenge.resource,
        description: challenge.description,
        mimeType: "application/json",
        maxTimeoutSeconds: Math.floor((challenge.expiresAt - Date.now()) / 1000),
        extra: {
          paymentIntentId: challenge.stripe.paymentIntentId,
          clientSecret: challenge.stripe.clientSecret,
          checkoutUrl: challenge.stripe.checkoutUrl,
          checkoutSessionId: challenge.stripe.checkoutSessionId,
          credits: challenge.stripe.credits
        }
      });
    }
    return {
      x402Version: 1,
      error: "payment_required",
      accepts,
      challenge: {
        id: challenge.id,
        expiresAt: new Date(challenge.expiresAt).toISOString(),
        resource: challenge.resource,
        methods: this.availableMethods(),
        instructions: {
          topUp:
            "To add credits to an existing prepaid session, send the payment credential together with X-Session-Token: <your sdm_sess token>; the balance is added to that principal and the token stays valid. Duplicate submissions of an already-redeemed payment answer 409, never a new payment demand.",
          stripe: challenge.stripe
            ? `Pay ${challenge.stripe.amount} ${challenge.stripe.currency.toUpperCase()} minor units via the checkoutUrl or by confirming the PaymentIntent with the clientSecret, then retry with header "Authorization: Payment ${encodeCredential({ challengeId: challenge.id, paymentIntentId: challenge.stripe.paymentIntentId })}" (base64url of {"method":"stripe","challengeId":...,"paymentIntentId":...}). The response includes a Payment-Receipt header with a session token good for ${challenge.stripe.credits} credits.`
            : null,
          x402: challenge.x402
            ? `Sign an x402 "exact" payment for ${challenge.x402.accepts.maxAmountRequired} atomic units of ${challenge.x402.accepts.asset} on ${challenge.x402.accepts.network} to ${challenge.x402.accepts.payTo}, then retry with the X-PAYMENT header (base64 JSON payload). ${challenge.x402.credits} credits are granted per settled payment.`
            : null
        }
      }
    };
  }

  parseCredential(rawValue: string, source: "authorization" | "x-payment"): PaymentCredential | null {
    const raw = rawValue.trim();
    if (!raw) return null;
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw.startsWith("{") ? raw : base64UrlDecode(raw));
    } catch {
      return null;
    }
    if (!parsed || typeof parsed !== "object") return null;
    const obj = parsed as Record<string, unknown>;
    const isX402 = source === "x-payment" || typeof obj.x402Version === "number" || (typeof obj.scheme === "string" && typeof obj.payload === "object");
    if (isX402) {
      return { method: "x402", challengeId: typeof obj.challengeId === "string" ? obj.challengeId : null, paymentIntentId: null, checkoutSessionId: null, x402Payload: obj };
    }
    const method = obj.method === "stripe" || obj.method === "x402" ? (obj.method as PaymentMethod) : null;
    return {
      method: method ?? (typeof obj.paymentIntentId === "string" || typeof obj.checkoutSessionId === "string" ? "stripe" : null),
      challengeId: typeof obj.challengeId === "string" ? obj.challengeId : null,
      paymentIntentId: typeof obj.paymentIntentId === "string" ? obj.paymentIntentId : null,
      checkoutSessionId: typeof obj.checkoutSessionId === "string" ? obj.checkoutSessionId : null,
      x402Payload: null
    };
  }

  /**
   * Verifies a payment and, in the same step, claims it and grants its
   * credits to the principal grantTo names, so a payment can never be
   * recorded without its credits or credited twice.
   */
  async redeem(credential: PaymentCredential, grantTo: GrantTarget): Promise<PaymentResult> {
    this.prune();
    const challenge = credential.challengeId ? (this.challenges.get(credential.challengeId) ?? null) : null;
    if (credential.method === "stripe") return this.redeemStripe(credential, challenge, grantTo);
    if (credential.method === "x402") return this.redeemX402(credential, challenge, grantTo);
    return { ok: false, code: "unsupported_payment_method", message: "The payment credential does not identify a supported method (stripe or x402)." };
  }

  private async redeemStripe(credential: PaymentCredential, challenge: PaymentChallenge | null, grantTo: GrantTarget): Promise<PaymentResult> {
    if (!this.stripe || !this.stripeEnabled) return { ok: false, code: "stripe_disabled", message: "Stripe payments are not enabled on this server." };
    const stripeCfg = this.config.payments.stripe;
    const stripe = this.stripe;
    const initialReference = credential.paymentIntentId ?? challenge?.stripe?.paymentIntentId ?? credential.checkoutSessionId;
    if (!initialReference) {
      return { ok: false, code: "missing_payment_reference", message: "Provide paymentIntentId, checkoutSessionId or the challengeId of a paid challenge." };
    }

    const alreadyRedeemed = (paymentIntentId: string): PaymentResult => ({
      ok: false,
      code: "payment_already_redeemed",
      message: `Payment ${paymentIntentId} has already been redeemed. Use the session token from its Payment-Receipt; a payment reference alone never re-issues a token.`
    });

    const verifyAndGrant = async (paymentIntentId: string): Promise<PaymentResult> => {
      if (this.usage.isPaymentRedeemed(paymentIntentId)) return alreadyRedeemed(paymentIntentId);
      const intent = await stripe.getPaymentIntent(paymentIntentId);
      if (this.usage.isPaymentRedeemed(paymentIntentId)) return alreadyRedeemed(paymentIntentId);
      if (intent.status !== "succeeded") {
        return { ok: false, code: "payment_not_succeeded", message: `PaymentIntent ${paymentIntentId} has status ${String(intent.status)}.` };
      }
      // Redeemed ids are remembered for the retention window (and, past a
      // very large safety bound, the oldest are dropped), so a payment older
      // than that window is refused outright: otherwise an id that aged out
      // of the ledger could be presented again for fresh credits.
      const createdSeconds = typeof intent.created === "number" ? intent.created : parseSafeInteger(typeof intent.created === "string" ? intent.created : null);
      if (createdSeconds !== null && Date.now() - createdSeconds * 1000 > REDEEMED_PAYMENT_RETENTION_MS) {
        return { ok: false, code: "payment_too_old", message: `PaymentIntent ${paymentIntentId} was created more than ${PAYMENT_MAX_AGE_DAYS} days ago and can no longer be redeemed.` };
      }
      const metadata = (intent.metadata as Record<string, string> | undefined) ?? {};
      if (metadata.service !== SERVICE_TAG) {
        return { ok: false, code: "payment_not_for_service", message: "The payment was not created for this service." };
      }
      const amountReceived = Number(intent.amount_received ?? intent.amount ?? 0);
      const expectedAmount = challenge?.stripe?.amount ?? stripeCfg.priceCents;
      if (amountReceived < expectedAmount) {
        return { ok: false, code: "payment_amount_insufficient", message: `Payment amount ${amountReceived} is below the required ${expectedAmount}.` };
      }
      if (String(intent.currency).toLowerCase() !== stripeCfg.currency) {
        return { ok: false, code: "payment_currency_mismatch", message: `Payment currency ${String(intent.currency)} does not match ${stripeCfg.currency}.` };
      }
      const credits = Number(metadata.credits) > 0 ? Number(metadata.credits) : stripeCfg.creditsPerPurchase;
      // Claiming and crediting together is the double-spend guard: another
      // request (or process) that verified the same payment concurrently loses here.
      const target = grantTo({ method: "stripe", paymentId: paymentIntentId });
      let fresh: boolean;
      try {
        fresh = await this.usage.redeemAndGrant([paymentIntentId], target.principalId, "payg", target.label, credits);
      } catch (err) {
        logger.error("verified stripe payment could not be recorded; reconcile manually", { paymentIntentId, principal: target.principalId, credits, error: err });
        return { ok: false, code: "payment_recording_failed", message: "The payment is verified but could not be recorded right now. Retry the same request shortly; it will not be charged twice." };
      }
      if (!fresh) return alreadyRedeemed(paymentIntentId);
      if (challenge) this.challenges.delete(challenge.id);
      return {
        ok: true,
        method: "stripe",
        paymentId: paymentIntentId,
        credits,
        principalId: target.principalId,
        label: target.label,
        receipt: { method: "stripe", paymentIntentId, amount: amountReceived, currency: String(intent.currency), credits, redeemedAt: new Date().toISOString() }
      };
    };

    try {
      return await this.withRedemptionLock(`stripe:${initialReference}`, async () => {
        let paymentIntentId = credential.paymentIntentId ?? challenge?.stripe?.paymentIntentId ?? null;
        if (!paymentIntentId && credential.checkoutSessionId) {
          const session = await stripe.getCheckoutSession(credential.checkoutSessionId);
          if (session.payment_status !== "paid") {
            return { ok: false, code: "checkout_not_paid", message: `Checkout session ${credential.checkoutSessionId} is not paid (status: ${String(session.payment_status)}).` };
          }
          const pi = session.payment_intent;
          paymentIntentId = typeof pi === "string" ? pi : pi && typeof pi === "object" && typeof (pi as { id?: unknown }).id === "string" ? (pi as { id: string }).id : null;
        }
        if (!paymentIntentId) {
          return { ok: false, code: "missing_payment_reference", message: "Provide paymentIntentId, checkoutSessionId or the challengeId of a paid challenge." };
        }
        if (paymentIntentId === initialReference) return verifyAndGrant(paymentIntentId);
        return this.withRedemptionLock(`stripe:${paymentIntentId}`, () => verifyAndGrant(paymentIntentId as string));
      });
    } catch (err) {
      logger.warn("stripe verification failed", { error: err });
      return { ok: false, code: "stripe_verification_failed", message: errorMessage(err) };
    }
  }

  private async redeemX402(credential: PaymentCredential, challenge: PaymentChallenge | null, grantTo: GrantTarget): Promise<PaymentResult> {
    if (!this.x402Enabled) return { ok: false, code: "x402_disabled", message: "x402 payments are not enabled on this server." };
    const payload = credential.x402Payload;
    if (!payload) return { ok: false, code: "invalid_x402_payload", message: "The X-PAYMENT payload could not be parsed." };
    const facilitator = this.config.payments.x402.facilitatorUrl as string;
    const requirements = challenge?.x402?.accepts ?? this.buildX402Requirements(this.config.http.publicUrl + "/mcp");
    const route = this.routeX402(payload);
    if (route.kind === "invalid") {
      return {
        ok: false,
        code: "invalid_x402_payload",
        message: "The X-PAYMENT payload must carry a signed inner payload (payload.authorization / payload.signature) and must not be pathologically nested."
      };
    }
    // With a shared database every process adopts settled markers that their
    // settling process could not record (it failed, or it is gone).
    if (this.usage.hasSharedLedger) this.ensureRecordingTimer();

    switch (route.kind) {
      case "pending":
        return this.withRedemptionLock(route.paymentId, () => this.finishPending(route.paymentId, route.entry, grantTo), x402InProgress);
      case "unavailable":
        logger.error("x402 settlement marker could not be read", { paymentId: route.paymentId, error: route.error });
        return x402StateUnavailable();
      case "leftover":
        // Without this the marker would answer "unconfirmed" (or "in progress") for as long as markers are
        // kept, for a payment that is done. Only the version read is removed.
        this.endSettlementQuietly(route.paymentId, route.marker.updatedAt);
        return x402AlreadyRedeemed();
      case "finish":
        return this.withRedemptionLock(route.paymentId, () => this.finishMarker(route.marker, grantTo, route.credited), x402InProgress);
      case "in-progress":
        return x402InProgress();
      case "unconfirmed":
        return x402EarlierUnconfirmed();
      case "reverify": {
        const { paymentId, marker: seen } = route;
        return this.withRedemptionLock(
          paymentId,
          async () => {
            const prior = seen.state === "unknown" ? this.claimReverification(seen) : seen;
            if (!prior) return x402EarlierUnconfirmed();
            return this.settleX402(payload, requirements, paymentId, challenge, facilitator, grantTo, prior);
          },
          x402InProgress
        );
      }
      case "redeemed":
        return x402AlreadyRedeemed();
      case "expired":
        return { ok: false, code: "x402_expired", message: "The x402 authorization's validBefore deadline has passed; sign a fresh payment for the current challenge." };
      case "settle":
        return this.withRedemptionLock(route.paymentId, () => this.settleX402(payload, requirements, route.paymentId, challenge, facilitator, grantTo, null), x402InProgress);
    }
  }

  /**
   * How redeemX402 answers a payload, from local state alone and without side effects, so that answersLocally()
   * cannot drift from it. A failed read of the redeemed ledger throws, as in redeemX402 (except beside a
   * marker, whose own answer is kept).
   */
  private routeX402(payload: Record<string, unknown>): X402Route {
    const paymentId = x402ReplayKey(payload);
    if (paymentId === null) return { kind: "invalid" };
    // (1) A payment this process settled but has not recorded is finished from
    // memory: the facilitator would reject the spent authorization on a new verify.
    const entry = this.unrecorded.get(paymentId);
    if (entry) return { kind: "pending", paymentId, entry };

    // (2) The shared marker says whether money may have moved for this payment,
    // wherever it was settled. Without it a retry could get a fresh 402.
    let marker: SettlementMarker | null;
    try {
      marker = this.usage.getSettlement(paymentId);
    } catch (error) {
      return { kind: "unavailable", paymentId, error };
    }
    const validBefore = x402ValidBefore(payload);
    const expired = validBefore !== null && validBefore * 1000 < Date.now();
    if (marker) {
      // A recorded payment's marker is a leftover whatever its state: recording and granting are one transaction.
      if (this.redeemedQuietly([paymentId])) return { kind: "leftover", paymentId, marker };
      // (3) Settled with a known transaction: finish the recording onto the stored target.
      if (marker.state === "settled") {
        const claim = settledMarkerClaim(marker);
        return { kind: "finish", paymentId, marker, credited: claim !== null && this.redeemedQuietly([claim.ids[0] as string, ...claim.blockedBy], claim.blockedByFamily) };
      }
      const age = Date.now() - marker.updatedAt;
      // (5) A settle is in flight in some process.
      if (marker.state === "settling" && age <= SETTLING_STALE_MS) return { kind: "in-progress" };
      // (4) The earlier settle's outcome is unknown (or its process died mid-settle).
      // Past validBefore it either happened or never can, so only "unconfirmed" is safe.
      if (expired) return { kind: "unconfirmed" };
      // An 'unknown' marker is asked about again at most once per UNKNOWN_REVERIFY_MS, by whichever process
      // claims it first; everyone else answers from the marker. (A stale 'settling' marker is not touched: its
      // never-resumed state is what the first-presenter rule in settleX402 reads.)
      if (marker.state === "unknown" && age < UNKNOWN_REVERIFY_MS) return { kind: "unconfirmed" };
      return { kind: "reverify", paymentId, marker };
    }

    // (6)
    if (this.usage.isPaymentRedeemed(paymentId)) return { kind: "redeemed" };
    // (7) An authorization past its validBefore can never settle again, so it is
    // refused before any facilitator call; this also closes the replay window
    // for ids that have aged out of the redeemed ledger.
    if (expired) return { kind: "expired" };
    // (8)
    return { kind: "settle", paymentId };
  }

  /**
   * Verifies and settles a payment. `prior` is the marker of an earlier
   * settle whose outcome is unknown: its target and credits are kept (that
   * request may already hold the session token), and any answer that cannot
   * prove the money did not move is "unconfirmed", never a new 402.
   */
  private async settleX402(
    payload: Record<string, unknown>,
    requirements: X402Requirements,
    paymentId: string,
    challenge: PaymentChallenge | null,
    facilitator: string,
    grantTo: GrantTarget,
    prior: SettlementMarker | null
  ): Promise<PaymentResult> {
    if (this.usage.isPaymentRedeemed(paymentId)) return x402AlreadyRedeemed();
    const requested = grantTo({ method: "x402", paymentId });
    const target: PaymentGrant = prior ? { principalId: prior.principalId, label: prior.label } : { principalId: requested.principalId, label: requested.label };
    const credits = prior ? prior.credits : (challenge?.x402?.credits ?? this.config.payments.x402.creditsPerPayment);
    // This request settles the payment itself, which is the trust a success
    // mints a token on, but only as the payment's first presenter. After an
    // earlier settle the target's session may already be out: a 502 handed it
    // to that request. The derived principal is public (a hash of the replay
    // key), so matching it proves nothing, and only a top-up by the stored
    // target may collect it again. A 'settling' marker that was never
    // resumed (at equals updatedAt) belongs to a process that died before
    // answering, so nobody holds the session and this retry is, in effect,
    // the first presenter, unless this process itself answered with the
    // session while its 'settled' write failed (answeredUnmarked).
    //
    // What remains: the 'settled' write and the recording both fail (a
    // database outage), the 503 goes out with the session, and this process
    // dies before its timer re-marks the payment. The marker then reads as
    // never resumed, and after SETTLING_STALE_MS the next presenter of the
    // public payload is its first presenter again. That presenter is handed
    // the session only if /verify passes and /settle succeeds for a spent
    // authorization (a facilitator that settles idempotently, or a transfer
    // still pending), so all three must coincide.
    const firstPresenter = !prior || (prior.state === "settling" && prior.at === prior.updatedAt && !this.answeredUnmarked.has(paymentId));
    const grant = (firstPresenter ? requested.principalId === target.principalId : PaymentManager.retryMayCollect(requested, target)) ? target : undefined;

    // Verification: no money has moved yet, so a failure here is safe to report as such,
    // unless an earlier settle may have spent the authorization.
    let verify: { isValid?: boolean; invalidReason?: string; payer?: string };
    let verifyResponse: Awaited<ReturnType<typeof undiciFetch>>;
    try {
      verifyResponse = await undiciFetch(`${facilitator}/verify`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({ x402Version: 1, paymentPayload: payload, paymentRequirements: requirements }),
        signal: AbortSignal.timeout(15000)
      });
      verify = (await verifyResponse.json()) as typeof verify;
    } catch (err) {
      logger.warn("x402 verification failed", { paymentId, afterUnknownSettle: prior !== null, error: err });
      if (prior) return x402EarlierUnconfirmed();
      return { ok: false, code: "x402_verification_failed", message: errorMessage(err) };
    }
    if (!verifyResponse.ok || verify.isValid !== true) {
      // The earlier settle may have spent the authorization, which is then rejected as used.
      if (prior) return x402EarlierUnconfirmed();
      return { ok: false, code: "x402_invalid", message: `Facilitator rejected the payment: ${verify.invalidReason ?? `HTTP ${verifyResponse.status}`}.` };
    }
    // Known only now: the payer /verify recovered qualifies an authorization presented without `from`. A resumed
    // marker keeps the identity it was claimed with. The x402ReplayKey fallback is never reached in practice
    // (paymentId is that key, so x402AuthorizationIdentity has its fallback too).
    const identity = prior?.identity ?? x402AuthorizationIdentity(payload, verify.payer) ?? paymentId;

    // Claim the payment durably before any money moves: other processes and a
    // restart then answer "in progress" or "unconfirmed", never a new 402.
    // After an unknown outcome, /verify passing means that settle never
    // happened, so settling again is correct.
    const claimedAt = Date.now();
    try {
      const claimed = prior
        ? this.usage.resumeSettlement(prior, claimedAt)
        : this.usage.beginSettlement({ paymentId, principalId: target.principalId, label: target.label, credits, identity }, claimedAt);
      if (!claimed) return x402InProgress();
      // A sibling may have settled and recorded it while this request verified.
      if (!prior && this.usage.isPaymentRedeemed(paymentId)) {
        if (!this.endSettlementQuietly(paymentId, claimedAt)) {
          this.unended.set(paymentId, claimedAt);
          this.ensureRecordingTimer();
        }
        return x402AlreadyRedeemed();
      }
    } catch (err) {
      logger.error("x402 settlement marker could not be written; not settling", { paymentId, error: err });
      return x402NotStarted();
    }

    // Settlement: once the request is sent the transfer may be broadcast, so
    // a transport error or a gateway failure is "unconfirmed", never a new 402.
    const reconcile = {
      paymentId,
      payer: verify.payer ?? null,
      amount: requirements.maxAmountRequired,
      network: requirements.network,
      payTo: requirements.payTo,
      principal: target.principalId,
      facilitator
    };
    let settleResponse: Awaited<ReturnType<typeof undiciFetch>>;
    let settle: Record<string, unknown> & { success?: boolean; errorReason?: string; network?: string };
    try {
      settleResponse = await undiciFetch(`${facilitator}/settle`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({ x402Version: 1, paymentPayload: payload, paymentRequirements: requirements }),
        signal: AbortSignal.timeout(30000)
      });
      settle = (await settleResponse.json()) as typeof settle;
    } catch (err) {
      const marked = await this.markUnknown(paymentId, grant !== undefined && prior === null);
      logger.error("x402 settle outcome unknown; reconcile manually", { ...reconcile, markerWritten: marked, error: err });
      return x402Unconfirmed("The facilitator did not confirm settlement.", this.unconfirmedGrant(grant, marked, prior));
    }
    if (settleResponse.status >= 500) {
      const marked = await this.markUnknown(paymentId, grant !== undefined && prior === null);
      logger.error("x402 settle answered a server error; outcome unknown, reconcile manually", { ...reconcile, markerWritten: marked, status: settleResponse.status });
      return x402Unconfirmed(`The facilitator answered HTTP ${settleResponse.status} to the settlement.`, this.unconfirmedGrant(grant, marked, prior));
    }
    if (!settleResponse.ok || settle.success !== true) {
      if (prior) {
        // A refusal now may be the earlier settle having spent the authorization.
        this.markSettlementQuietly(paymentId, "unknown");
        return x402EarlierUnconfirmed();
      }
      // Nothing moved. A marker left behind would read as a pending payment
      // for the principal, so a failed removal is retried (see recordInBackground).
      if (!this.endSettlementQuietly(paymentId, claimedAt)) {
        this.unended.set(paymentId, claimedAt);
        this.ensureRecordingTimer();
      }
      return { ok: false, code: "x402_settlement_failed", message: `Facilitator could not settle the payment: ${settle.errorReason ?? `HTTP ${settleResponse.status}`}.` };
    }
    const transaction = settledTransactionId(settle);
    if (transaction === null) {
      // Fail closed: without a transaction id the settlement cannot be tied to
      // an on-chain transfer, so a repeat settle could not be detected. The
      // transfer did move, so the marker stays: a retry is "unconfirmed" too.
      const marked = await this.markUnknown(paymentId, grant !== undefined && prior === null);
      logger.error("x402 facilitator reported success without a transaction id; credits withheld, reconcile manually", { ...reconcile, markerWritten: marked, keys: Object.keys(settle) });
      return x402Unconfirmed("The facilitator reported success without a transaction id; credits cannot be granted until settlement is confirmed.", this.unconfirmedGrant(grant, marked, prior));
    }

    // The money has moved: from here a failure is never reported as a
    // verification failure (which would prompt the client to pay again).
    const receipt = { method: "x402", transaction, network: settle.network ?? requirements.network, payer: verify.payer ?? null, credits };
    const { markerTx, guard, blockedBy, blockedByFamily } = x402TransactionGuard(transaction, identity);
    const markError = this.tryMarkSettlement(paymentId, "settled", markerTx, receipt);
    const entry: UnrecordedSettlement = {
      ids: [guard, paymentId],
      blockedBy,
      blockedByFamily,
      target,
      credits,
      receipt,
      committed: false,
      at: Date.now(),
      // The marker's `at`: a resumed settle keeps the time of the claim it resumes.
      claimedAt: prior ? prior.at : claimedAt,
      tx: transaction,
      markerTx,
      markerSettled: markError === null
    };
    if (challenge) this.challenges.delete(challenge.id);
    return this.recordSettlement(paymentId, entry, grant, { ...reconcile, transaction });
  }

  /**
   * Records a payment this request just settled and grants its credits. When
   * the database write fails the settlement is kept here and in its shared
   * marker: a retry of the same header (the facilitator would now reject the
   * spent authorization), the background timer and any sibling process all
   * finish the recording, so the payer gets the credits they paid for and
   * never a new payment demand. `grant` is set when this request may be handed
   * the target's session. Another presentation of the same authorization that
   * settled first and is still being recorded gets the credits instead (see
   * SettlementClaimant).
   */
  private async recordSettlement(paymentId: string, entry: UnrecordedSettlement, grant: PaymentGrant | undefined, reconcile: Record<string, unknown>): Promise<PaymentResult> {
    // While it waits out a locked database, every later presentation of the authorization yields to it.
    this.recording.set(paymentId, entry);
    try {
      return await this.recordSettled(paymentId, entry, grant, reconcile);
    } finally {
      this.recording.delete(paymentId);
    }
  }

  /** recordSettlement, once the entry is registered as recording. */
  private async recordSettled(paymentId: string, entry: UnrecordedSettlement, grant: PaymentGrant | undefined, reconcile: Record<string, unknown>): Promise<PaymentResult> {
    // Read before the first await. The 'settled' marker was written in this tick (or not at all yet), so no
    // adopter can have run yet. A transaction already credited now under this guard (an idempotent
    // facilitator), under the legacy id or under a guard of the same authorization presented the other way
    // (blockedBy, blockedByFamily) was credited before this settle, and one credited later was adopted
    // onto entry.target while this request was still recording. A failed read keeps the "already redeemed" answer.
    let creditedBefore = true;
    try {
      creditedBefore =
        [entry.ids[0] as string, ...entry.blockedBy].some((id) => this.usage.isPaymentRedeemed(id)) || (entry.blockedByFamily !== null && this.usage.isGuardFamilyRedeemed(entry.blockedByFamily));
    } catch {
      // unknown: keep the current answer
    }
    // The settlement claimed first is credited, not the one recorded first: a presentation of the same authorization
    // that settled before this one and is not recorded yet (its recording failed, or waits out a lock) gets the
    // transaction's credits, so this one records its payment id alone and is refused. A later presentation that
    // arrives while this one records finds it in `recording` (or its 'settled' marker) and yields to it in turn.
    if (this.yieldsToEarlierSettlement(this.entryClaimant(paymentId, entry), entry.tx)) return this.yieldEntry(paymentId, entry);
    // The recording and a retry of a failed 'settled' write share one wall-clock budget, so the answer is never
    // held for more than one. The retry waits until the recording has given up rather than running beside it:
    // both need the same write lock, every attempt blocks the event loop for up to BUSY_TIMEOUT_MS (synchronous
    // node:sqlite), so attempts in lockstep doubled the stall, and once the lock clears the recording succeeds
    // and removes the marker anyway. A 503 that hands out the session still leaves the marker settled behind it
    // whenever the database lets it.
    const deadline = Date.now() + REDEEM_LOCK_BUDGET_MS;
    // The 'settled' write just failed, typically after blocking for BUSY_TIMEOUT_MS on a held lock: let the event
    // loop run before the recording's first attempt blocks again. (No adopter can take a marker that is not
    // 'settled', and creditedBefore is already read.)
    if (!entry.markerSettled) await yieldToEventLoop();
    let fresh: boolean;
    try {
      // Claiming the transaction guard is the double-spend guard. When the
      // facilitator settled idempotently onto a transaction that was already
      // credited, this payload is still recorded so it cannot be retried, but
      // no credits are granted twice.
      fresh = await this.usage.redeemAndGrant(entry.ids, entry.target.principalId, "payg", entry.target.label, entry.credits, entry.blockedBy, entry.blockedByFamily);
    } catch (err) {
      if (!entry.markerSettled) {
        const again = this.tryMarkSettlement(paymentId, "settled", entry.markerTx, entry.receipt);
        entry.markerSettled = again === null || (await this.markSettlementDurably(paymentId, "settled", entry.markerTx, entry.receipt, again, deadline));
      }
      logger.error("settled x402 payment could not be recorded yet; will retry", { ...reconcile, credits: entry.credits, markerSettled: entry.markerSettled, error: err });
      if (grant && !entry.markerSettled) {
        // The session still goes out: it is the only way to the credits the timer records onto the target.
        // The timer keeps trying to publish the marker; until it does, only this process knows an answer went out.
        this.rememberAnsweredUnmarked(paymentId);
        logger.error("settled x402 payment answered with its session, but its 'settled' marker could not be written; if this process stops before recording it, reconcile it manually", {
          ...reconcile,
          credits: entry.credits
        });
      }
      this.unrecorded.set(paymentId, entry);
      this.ensureRecordingTimer();
      return x402RecordingPending(grant);
    }
    this.endSettlementQuietly(paymentId);
    if (!fresh) {
      // A sibling adopted the marker while this request waited out a locked database. The credits are on
      // this payment's target, so the settling request keeps the answer (and the session) it earned.
      if (!creditedBefore && !this.redeemedAny(entry.blockedBy, entry.blockedByFamily))
        return grant ? x402Success(paymentId, entry.target, entry.credits, entry.receipt) : x402RecordedForFirstRequest();
      return x402TransactionRedeemed(entry.tx);
    }
    if (!grant) return x402RecordedForFirstRequest();
    return x402Success(paymentId, entry.target, entry.credits, entry.receipt);
  }

  /** Whether any of the ids (or of the family) is redeemed now; a failed read counts as redeemed (the cautious answer). */
  private redeemedAny(ids: readonly string[], family: GuardFamily | null = null): boolean {
    try {
      return ids.some((id) => this.usage.isPaymentRedeemed(id)) || (family !== null && this.usage.isGuardFamilyRedeemed(family));
    } catch {
      return true;
    }
  }

  /** Whether any of the ids (or of the family) is redeemed now; a failed read counts as not redeemed, so a marker keeps its own (safe) answer. */
  private redeemedQuietly(ids: readonly string[], family: GuardFamily | null = null): boolean {
    try {
      return ids.some((id) => this.usage.isPaymentRedeemed(id)) || (family !== null && this.usage.isGuardFamilyRedeemed(family));
    } catch {
      return false;
    }
  }

  private rememberAnsweredUnmarked(paymentId: string): void {
    if (this.answeredUnmarked.size >= MAX_ANSWERED_UNMARKED) {
      const oldest = this.answeredUnmarked.keys().next();
      if (!oldest.done) this.answeredUnmarked.delete(oldest.value);
    }
    this.answeredUnmarked.set(paymentId, Date.now());
  }

  /**
   * Whether a retry may be answered with the target's session. The payload is
   * public once the payment settles (the chain carries the whole signed
   * authorization, and the derived principal id is a function of it), so it
   * proves nothing. Only a top-up whose own session already is the target
   * gains nothing by being answered with it.
   */
  private static retryMayCollect(requested: ReturnType<GrantTarget>, target: PaymentGrant): boolean {
    return requested.topUp === true && requested.principalId === target.principalId;
  }

  /** (1) A retry of a payment this process settled but has not recorded yet (or recorded after its first answer). */
  private async finishPending(paymentId: string, entry: UnrecordedSettlement, grantTo: GrantTarget): Promise<PaymentResult> {
    if (!entry.committed) {
      // The first-settlement rule, as when the payment settled (recordSettlement).
      if (this.yieldsToEarlierSettlement(this.entryClaimant(paymentId, entry), entry.tx)) return this.yieldEntry(paymentId, entry);
      // Read before recording: this payment's guard recorded while its payment id is not was credited to another
      // presentation of the same authorization (another replay key, the same identity). This payment id already
      // recorded means another process adopted its 'settled' marker before this retry.
      const recordedElsewhere = this.redeemedQuietly([paymentId]);
      const guardRecorded = this.redeemedQuietly([entry.ids[0] as string]);
      const guardTaken = guardRecorded && !recordedElsewhere;
      let fresh: boolean;
      try {
        fresh = await this.usage.redeemAndGrant(entry.ids, entry.target.principalId, "payg", entry.target.label, entry.credits, entry.blockedBy, entry.blockedByFamily);
      } catch (err) {
        logger.warn("recording a settled x402 payment failed again on retry", { paymentId, error: err });
        return x402RecordingPending();
      }
      this.endSettlementQuietly(paymentId);
      if (!fresh) {
        this.unrecorded.delete(paymentId);
        // The adopter credited this payment's target unless it yielded, which leaves the guard unwritten. A blocker
        // recorded after it (a later presentation's blocked recording writes its ids too) says nothing about this
        // payment, so it must not turn the answer into "already redeemed" for a payer whose session holds the credits.
        if (recordedElsewhere) return guardRecorded ? x402RecordedForFirstRequest() : x402TransactionRedeemed(entry.tx);
        // A guard of the same authorization was credited first, so this payment's target was given nothing.
        // Otherwise another process finished it from the shared marker after the read above, onto that target.
        return guardTaken || this.redeemedAny(entry.blockedBy, entry.blockedByFamily) ? x402TransactionRedeemed(entry.tx) : x402RecordedForFirstRequest();
      }
      entry.committed = true;
      entry.at = Date.now();
      logger.info("settled x402 payment recorded on retry", { paymentId, principal: entry.target.principalId, credits: entry.credits });
    }
    if (!PaymentManager.retryMayCollect(grantTo({ method: "x402", paymentId }), entry.target)) return x402RecordedForFirstRequest();
    this.unrecorded.delete(paymentId);
    return x402Success(paymentId, entry.target, entry.credits, entry.receipt);
  }

  /**
   * (3) A retry of a payment another process (or this one before a restart) settled but did not record. It is
   * left to the settling request for a while, unless its transaction guard is already credited (`credited`, the
   * same authorization presented the other way): the settling request then answers "already redeemed" anyway,
   * and adopting only records this payment id and removes the marker. `credited` is read while this payment id
   * is not recorded (routeX402), so the guard it saw went to another presentation.
   */
  private async finishMarker(marker: SettlementMarker, grantTo: GrantTarget, credited = false): Promise<PaymentResult> {
    const claim = settledMarkerClaim(marker);
    if (!claim) return x402RecordingPending();
    if (!credited && Date.now() - marker.updatedAt < ADOPT_SETTLED_AFTER_MS) return x402RecordingPending();
    const target: PaymentGrant = { principalId: marker.principalId, label: marker.label };
    let adoption: Adoption;
    try {
      adoption = await this.adoptMarker(marker);
    } catch (err) {
      logger.warn("recording a settled x402 payment from its marker failed; will retry", { paymentId: marker.paymentId, error: err });
      return x402RecordingPending();
    }
    // Its target was given nothing: another presentation of the authorization was credited first, or settled first.
    if (adoption === "yielded" || (adoption === "uncredited" && (credited || this.redeemedAny(claim.blockedBy, claim.blockedByFamily)))) return x402TransactionRedeemed(claim.transaction);
    // Otherwise a concurrent adopter recorded it onto that target.
    if (adoption === "uncredited" || !PaymentManager.retryMayCollect(grantTo({ method: "x402", paymentId: marker.paymentId }), target)) return x402RecordedForFirstRequest();
    return x402Success(marker.paymentId, target, marker.credits, marker.receipt ?? { method: "x402", transaction: claim.transaction, credits: marker.credits });
  }

  /**
   * Records a settled marker onto its stored target (idempotent on its transaction guard) and removes it. It yields
   * when an earlier settlement of the same authorization is not recorded yet (the first-settlement rule, see
   * SettlementClaimant). Throws when the database write fails; the marker then stays for a later attempt.
   */
  private async adoptMarker(marker: SettlementMarker): Promise<Adoption> {
    const claim = settledMarkerClaim(marker);
    if (!claim) return "uncredited";
    const self: SettlementClaimant = { paymentId: marker.paymentId, guard: claim.ids[0] as string, blockedBy: claim.blockedBy, blockedByFamily: claim.blockedByFamily, at: marker.at };
    if (this.yieldsToEarlierSettlement(self, claim.transaction)) {
      this.recordYielded(marker.paymentId, claim.transaction);
      return "yielded";
    }
    const fresh = await this.usage.redeemAndGrant(claim.ids, marker.principalId, "payg", marker.label, marker.credits, claim.blockedBy, claim.blockedByFamily);
    this.endSettlementQuietly(marker.paymentId);
    if (fresh) logger.info("settled x402 payment recorded from its shared marker", { paymentId: marker.paymentId, principal: marker.principalId, credits: marker.credits });
    return fresh ? "credited" : "uncredited";
  }

  private entryClaimant(paymentId: string, entry: UnrecordedSettlement): SettlementClaimant {
    return { paymentId, guard: entry.ids[0] as string, blockedBy: entry.blockedBy, blockedByFamily: entry.blockedByFamily, at: entry.claimedAt };
  }

  /**
   * The first-settlement rule (see SettlementClaimant): whether another settlement of the transaction, claimed
   * before `self` and not recorded yet, is to be credited and would block `self` once recorded. The others are
   * this process's entries that are being recorded or wait for a retry, and the 'settled' markers of the
   * transaction, which cover every process. They are taken in claim order: one that is already blocked by a
   * recorded guard, or that yields to an earlier one itself, is never credited, so nothing yields to it. Two
   * known payers whose authorizations reuse a nonce in one batch never block each other, so neither yields.
   *
   * An unreadable marker table counts as holding none, so only this process's entries are compared. A settlement
   * whose own marker never became 'settled' (its write failed) is seen only by its own process, and an 'unknown'
   * or 'settling' marker names no transaction, so a presentation recorded while the payer's settle is unconfirmed
   * is still credited before it.
   */
  private yieldsToEarlierSettlement(self: SettlementClaimant, transaction: string): boolean {
    const tx = transaction.toLowerCase();
    const others = new Map<string, SettlementClaimant>();
    for (const entries of [this.recording, this.unrecorded]) {
      for (const [paymentId, entry] of entries) {
        if (paymentId !== self.paymentId && !entry.committed && entry.tx.toLowerCase() === tx) others.set(paymentId, this.entryClaimant(paymentId, entry));
      }
    }
    let markers: SettlementMarker[] = [];
    try {
      markers = this.usage.listSettledFor(transaction);
    } catch (err) {
      logger.warn("x402 settlement markers of a transaction could not be read; recording without comparing earlier settlements", { transaction, error: err });
    }
    for (const marker of markers) {
      const claim = settledMarkerClaim(marker);
      if (!claim || marker.paymentId === self.paymentId || others.has(marker.paymentId) || claim.transaction.toLowerCase() !== tx) continue;
      others.set(marker.paymentId, { paymentId: marker.paymentId, guard: claim.ids[0] as string, blockedBy: claim.blockedBy, blockedByFamily: claim.blockedByFamily, at: marker.at });
    }
    if (others.size === 0) return false;
    const creditable: SettlementClaimant[] = [];
    for (const claimant of [...others.values(), self].sort(claimedFirst)) {
      const yields = creditable.some((earlier) => guardBlocks(earlier.guard, claimant));
      if (claimant === self) return yields;
      if (!yields && !this.redeemedQuietly([claimant.guard, ...claimant.blockedBy], claimant.blockedByFamily)) creditable.push(claimant);
    }
    return false;
  }

  /**
   * Records a settlement that yields (yieldsToEarlierSettlement) under its payment id alone, so the payload never
   * settles into credits again, and removes its marker. Its transaction guard stays unwritten: recorded, it would
   * block the earlier settlement it yields to. Throws when the write fails.
   */
  private recordYielded(paymentId: string, transaction: string): void {
    this.usage.markPaymentRedeemed(paymentId);
    this.endSettlementQuietly(paymentId);
    logger.warn("settled x402 payment credited nothing: an earlier settlement of the same authorization gets the transaction's credits", { paymentId, transaction });
  }

  /**
   * An entry of this process that yields: recorded by recordYielded and dropped, and refused. When the write fails
   * it is kept as an uncommitted entry, and the timer (or a retry of its header) applies the rule again.
   */
  private yieldEntry(paymentId: string, entry: UnrecordedSettlement): PaymentFailure {
    try {
      this.recordYielded(paymentId, entry.tx);
      this.unrecorded.delete(paymentId);
    } catch (err) {
      logger.warn("an x402 payment that yields to an earlier settlement could not be recorded yet; will retry", { paymentId, transaction: entry.tx, error: err });
      this.unrecorded.set(paymentId, entry);
      this.ensureRecordingTimer();
    }
    return x402TransactionRedeemed(entry.tx);
  }

  /** One marker write; returns why it failed, or null. */
  private tryMarkSettlement(paymentId: string, state: SettlementState, tx: string | null, receipt: Record<string, unknown> | null): unknown {
    try {
      this.usage.markSettlement(paymentId, state, tx, receipt, Date.now());
      return null;
    } catch (err) {
      logger.warn("x402 settlement marker could not be updated", { paymentId, state, error: err });
      return err ?? new Error("marker write failed");
    }
  }

  /** Best effort: a failed write leaves the marker in a state that still answers "in progress", "unconfirmed" or "being recorded". */
  private markSettlementQuietly(paymentId: string, state: SettlementState, tx: string | null = null, receipt: Record<string, unknown> | null = null): boolean {
    return this.tryMarkSettlement(paymentId, state, tx, receipt) === null;
  }

  /**
   * Retries a marker write that failed with `error`, while the failure is lock contention and the deadline (wall
   * time) has not passed, sleeping between attempts so the event loop stays free between them. A write to a
   * marker that is gone changes nothing (markSettlement never inserts one).
   */
  private async markSettlementDurably(paymentId: string, state: SettlementState, tx: string | null, receipt: Record<string, unknown> | null, error: unknown, deadline: number): Promise<boolean> {
    let last = error;
    for (let attempt = 1; isLockContention(last); attempt++) {
      const left = deadline - Date.now();
      if (left <= 0) return false;
      await new Promise((resolve) => setTimeout(resolve, Math.min(2000, 100 * 2 ** Math.min(attempt, 5), left)));
      last = this.tryMarkSettlement(paymentId, state, tx, receipt);
      if (last === null) return true;
    }
    return false;
  }

  /**
   * Marks a settle whose outcome is unknown. When that answer would carry the session (a first presenter), a
   * write that fails on lock contention is retried for REDEEM_LOCK_BUDGET_MS of wall time before answering:
   * without the write the session is withheld (see unconfirmedGrant).
   */
  private async markUnknown(paymentId: string, guardsSession: boolean): Promise<boolean> {
    const error = this.tryMarkSettlement(paymentId, "unknown", null, null);
    if (error === null) return true;
    if (!guardsSession) return false;
    return this.markSettlementDurably(paymentId, "unknown", null, null, error, Date.now() + REDEEM_LOCK_BUDGET_MS);
  }

  /**
   * Claims the one re-verification of an 'unknown' marker allowed per UNKNOWN_REVERIFY_MS (compare-and-set on
   * its updated_at), returning the marker as claimed, or null when another process got there first or the
   * marker cannot be written; the caller then answers "unconfirmed" from the marker.
   */
  private claimReverification(seen: SettlementMarker): SettlementMarker | null {
    const at = Math.max(Date.now(), seen.updatedAt + 1);
    try {
      return this.usage.touchSettlement(seen, at) ? { ...seen, updatedAt: at } : null;
    } catch (err) {
      logger.warn("x402 settlement marker could not be claimed for re-verification", { paymentId: seen.paymentId, error: err });
      return null;
    }
  }

  private endSettlementQuietly(paymentId: string, ifUpdatedAt?: number): boolean {
    try {
      this.usage.endSettlement(paymentId, ifUpdatedAt);
      return true;
    } catch (err) {
      // A leftover 'settled' marker is adopted again (idempotently) and removed
      // later, and one of a redeemed payment no longer reads as pending.
      logger.warn("x402 settlement marker could not be removed", { paymentId, error: err });
      return false;
    }
  }

  /**
   * The session goes out with a 502 only when the marker records that an
   * answer went out: a first presenter's marker that stays 'settling' as
   * written (its 'unknown' write failed) later counts as "died before
   * answering", and would then hand the same session to whoever presents
   * the public authorization next. A resumed marker was already rewritten,
   * so only a top-up by its target can collect it anyway.
   */
  private unconfirmedGrant(grant: PaymentGrant | undefined, marked: boolean, prior: SettlementMarker | null): PaymentGrant | undefined {
    return marked || prior ? grant : undefined;
  }

  private ensureRecordingTimer(): void {
    if (this.recordingTimer || this.closed) return;
    this.recordingTimer = setInterval(() => this.recordInBackground(), RECORDING_RETRY_MS);
    this.recordingTimer.unref();
  }

  /**
   * Retries recording settled payments until they are committed: this
   * process's own, and (with a shared database) any 'settled' marker whose
   * settling process could not record it.
   */
  private recordInBackground(): void {
    const now = Date.now();
    for (const [paymentId, entry] of this.unrecorded) {
      // A committed entry waits for a top-up's own retry (to hand back its
      // receipt); after a day the credits simply stay on the principal (prune()
      // also drops it, as this timer stops once nothing is left to record).
      if (entry.committed) {
        if (now - entry.at > UNRECORDED_RETENTION_MS) this.unrecorded.delete(paymentId);
        continue;
      }
      if (this.inFlight.has(paymentId)) continue;
      void this.withRedemptionLock(paymentId, async () => {
        // Publish the transaction so a sibling or a restart can finish it if this process cannot.
        if (!entry.markerSettled) entry.markerSettled = this.markSettlementQuietly(paymentId, "settled", entry.markerTx, entry.receipt);
        // The first-settlement rule, as when the payment settled (recordSettlement).
        if (this.yieldsToEarlierSettlement(this.entryClaimant(paymentId, entry), entry.tx)) {
          this.yieldEntry(paymentId, entry);
          return { ok: false, code: "payment_recording_retry", message: "" };
        }
        try {
          const fresh = await this.usage.redeemAndGrant(entry.ids, entry.target.principalId, "payg", entry.target.label, entry.credits, entry.blockedBy, entry.blockedByFamily);
          this.endSettlementQuietly(paymentId);
          if (fresh) {
            entry.committed = true;
            entry.at = Date.now();
            logger.info("settled x402 payment recorded on retry", { paymentId, principal: entry.target.principalId, credits: entry.credits });
          } else {
            this.unrecorded.delete(paymentId);
          }
        } catch (err) {
          logger.warn("recording a settled x402 payment failed again; will retry", { paymentId, error: err });
        }
        return { ok: false, code: "payment_recording_retry", message: "" };
      });
    }
    for (const [paymentId, updatedAt] of this.unended) {
      if (this.inFlight.has(paymentId)) continue;
      if (this.endSettlementQuietly(paymentId, updatedAt)) this.unended.delete(paymentId);
    }
    if (this.usage.hasSharedLedger) {
      let adoptable: SettlementMarker[] = [];
      try {
        adoptable = this.usage.listSettled(now - ADOPT_SETTLED_AFTER_MS);
      } catch (err) {
        logger.warn("x402 settlement markers could not be listed", { error: err });
      }
      for (const marker of adoptable) {
        // A committed local entry no longer records anything: adopting finds the
        // payment redeemed and removes a marker whose removal failed.
        const local = this.unrecorded.get(marker.paymentId);
        if (!marker.tx || this.inFlight.has(marker.paymentId) || (local && !local.committed)) continue;
        void this.withRedemptionLock(marker.paymentId, async () => {
          try {
            await this.adoptMarker(marker);
          } catch (err) {
            logger.warn("recording a settled x402 payment from its marker failed; will retry", { paymentId: marker.paymentId, error: err });
          }
          return { ok: false, code: "payment_recording_retry", message: "" };
        });
      }
    } else if (!this.hasUncommitted() && this.unended.size === 0 && this.recordingTimer) {
      // Without a shared database there is nothing to adopt: once this process's own entries are all committed
      // (they only wait for a top-up's retry) and every leftover marker is removed, the timer has nothing to
      // do. ensureRecordingTimer starts it again when a recording fails.
      clearInterval(this.recordingTimer);
      this.recordingTimer = null;
    }
  }

  private hasUncommitted(): boolean {
    for (const entry of this.unrecorded.values()) {
      if (!entry.committed) return true;
    }
    return false;
  }

  /**
   * True when redeem() answers from local state alone, with no Stripe or facilitator call: a payment already
   * redeemed, or any x402 route of routeX402 but a re-verification or a fresh settle (for example an unconfirmed
   * payment inside its re-verification window or past its validBefore, a settle in flight, or a settled
   * payment still being recorded). A prepaid session re-attaching such a header then costs no upstream call,
   * so it is not charged to the pre-auth address bucket. A state that cannot be read counts as an upstream call.
   */
  answersLocally(credential: PaymentCredential): boolean {
    try {
      if (this.isKnownRedeemed(credential)) return true;
      if (credential.method !== "x402" || !credential.x402Payload) return false;
      if (!this.x402Enabled) return true;
      const { kind } = this.routeX402(credential.x402Payload);
      return kind !== "reverify" && kind !== "settle" && kind !== "unavailable";
    } catch {
      return false;
    }
  }

  /** True when redeem() would answer payment_already_redeemed from the local ledger, before any Stripe or facilitator call. */
  isKnownRedeemed(credential: PaymentCredential): boolean {
    if (credential.method === "x402" && credential.x402Payload) {
      const id = x402ReplayKey(credential.x402Payload);
      if (id === null) return false;
      // A settlement still waiting to be recorded is finished by redeem(), not refused.
      const pending = this.unrecorded.get(id);
      if (pending && !pending.committed) return false;
      return this.usage.isPaymentRedeemed(id);
    }
    if (credential.method === "stripe") {
      const challenge = credential.challengeId ? this.challenges.get(credential.challengeId) : undefined;
      const paymentIntentId = credential.paymentIntentId ?? challenge?.stripe?.paymentIntentId ?? null;
      // A checkout-session-only credential still needs a Stripe call to resolve, so it stays throttled.
      return paymentIntentId !== null && this.usage.isPaymentRedeemed(paymentIntentId);
    }
    return false;
  }
}

export function encodeReceipt(receipt: Record<string, unknown>): string {
  return base64UrlEncode(JSON.stringify(receipt));
}
