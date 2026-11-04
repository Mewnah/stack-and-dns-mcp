/**
 * Database-backed API keys issued through self-serve signup (and key
 * rotation). Only the SHA-256 hash of a key is stored; the raw key is shown
 * to the buyer exactly once.
 *
 * Every key belongs to an account id that stays the same across rotations,
 * and that account id is the principal id the rest of the server sees, so a
 * rotated key keeps its owner's bulk jobs, watches, alerts and usage. At
 * most one key per account is active at a time.
 *
 * Keys are tied to the Stripe subscription that pays for them, so
 * subscription webhooks can suspend, restore or re-plan every key of a
 * subscription.
 */

import type { PlanName } from "../config.js";
import { apiKeyId, apiKeyPrefix, generateApiKey, hashApiKey, type ApiKeyRecord } from "../middleware/auth.js";
import { transaction, type Database } from "./db.js";

export { MIGRATION_API_KEYS } from "./migrations.js";

export type SubscriptionAction = "applied" | "stale" | "terminal" | "duplicate";

/** Subscription statuses under which the subscription's keys work. */
export const LIVE_SUBSCRIPTION_STATUSES = new Set(["active", "trialing"]);
/** Statuses that suspend keys until the subscription recovers. */
export const SUSPENDED_SUBSCRIPTION_STATUSES = new Set(["past_due", "unpaid", "paused", "incomplete_expired", "canceled"]);
/**
 * The suspended statuses Stripe never moves a subscription out of: a canceled subscription cannot be
 * resumed, and an expired first payment cannot be retried. Their keys stay suspended rather than ended
 * (only a deletion ends a key here), but a key is never shown as one that will start working under them.
 */
export const ENDED_SUBSCRIPTION_STATUSES = new Set(["canceled", "incomplete_expired"]);

/** True for a recorded deletion and for a Stripe status the subscription never leaves. */
export function subscriptionHasEnded(status: string | null | undefined): boolean {
  return status === "deleted" || (status != null && ENDED_SUBSCRIPTION_STATUSES.has(status));
}

/** Deactivation reasons set by billing webhooks; only these are undone when a subscription recovers. */
const BILLING_REASON_PREFIX = "subscription_";

interface KeyRow {
  key_hash: string;
  account_id: string;
  prefix: string;
  plan: PlanName;
  label: string;
  active: number;
  source: "checkout" | "rotation";
  checkout_session: string | null;
  stripe_customer: string | null;
  stripe_subscription: string | null;
  created_at: number;
  deactivated_at: number | null;
  deactivated_reason: string | null;
}

export interface IssuedKey {
  apiKey: string;
  record: ApiKeyRecord;
}

export interface CheckoutIssuedKey extends IssuedKey {
  /**
   * The subscription was deleted, or a terminal Stripe status (canceled, incomplete_expired) was recorded,
   * before the key was stored: the key is inactive, no payment will turn it on, and it must not be shown.
   */
  subscriptionEnded: boolean;
}

export interface CheckoutKeyInput {
  checkoutSession: string;
  plan: PlanName;
  label: string;
  stripeCustomer: string | null;
  stripeSubscription: string | null;
  /** The checkout completed but the payment has not cleared yet: the key is issued inactive and turns on when the subscription goes live. */
  pending?: boolean;
}

/** The record the auth layer sees: id is the stable account id, not a per-key id. */
function toRecord(row: KeyRow): ApiKeyRecord {
  return { id: row.account_id, keyHash: row.key_hash, prefix: row.prefix, plan: row.plan, label: row.label, active: row.active === 1 };
}

function isUniqueViolation(err: unknown): boolean {
  return err instanceof Error && /UNIQUE constraint failed/i.test(err.message);
}

export class KeyRepository {
  constructor(private readonly db: Database) {}

  /** The active key with this hash, or null. Inactive keys never authenticate. */
  findActiveByHash(keyHash: string): ApiKeyRecord | null {
    const row = this.db.prepare("SELECT * FROM api_keys WHERE key_hash = ? AND active = 1").get(keyHash) as unknown as KeyRow | undefined;
    return row ? toRecord(row) : null;
  }

  /** The account's active key, or null when the account has none (or is not database-backed). */
  findActiveByAccount(accountId: string): (ApiKeyRecord & { stripeSubscription: string | null }) | null {
    const row = this.db.prepare("SELECT * FROM api_keys WHERE account_id = ? AND active = 1").get(accountId) as unknown as KeyRow | undefined;
    return row ? { ...toRecord(row), stripeSubscription: row.stripe_subscription } : null;
  }

  countActive(): number {
    return Number((this.db.prepare("SELECT COUNT(*) AS n FROM api_keys WHERE active = 1").get() as { n: number }).n);
  }

  /**
   * Issues the key for a paid Checkout Session. Returns null when that
   * session already produced a key, so a reloaded or replayed success page
   * can never mint a second one. A subscription already deleted (another
   * process may apply the deletion between the caller's status read and this
   * transaction) gets its key stored inactive with the label endSubscription
   * uses, flagged subscriptionEnded: nothing can turn it on later, since
   * activatePendingCheckout needs payment_pending and every later event for
   * the subscription is 'terminal', and isTerminated holds for the account.
   * A recorded canceled or incomplete_expired status is flagged the same way,
   * because Stripe never leaves it, but the key keeps the suspended label the
   * webhook gave the subscription's other keys.
   */
  issueForCheckout(input: CheckoutKeyInput, now: number = Date.now()): CheckoutIssuedKey | null {
    const apiKey = generateApiKey();
    const keyHash = hashApiKey(apiKey);
    const accountId = apiKeyId(keyHash);
    return transaction(this.db, () => {
      // Whatever a subscription webhook already recorded wins over the
      // checkout-time plan and status: the buyer may have changed plans, or
      // stopped paying, before opening the success page.
      const state = input.stripeSubscription
        ? (this.db.prepare("SELECT status, plan FROM subscription_state WHERE subscription_id = ?").get(input.stripeSubscription) as { status: string; plan: PlanName | null } | undefined)
        : undefined;
      const plan = state?.plan ?? input.plan;
      const ended = subscriptionHasEnded(state?.status);
      let reason: string | null = null;
      if (state?.status === "deleted") reason = `${BILLING_REASON_PREFIX}deleted`;
      else if (state && SUSPENDED_SUBSCRIPTION_STATUSES.has(state.status)) reason = `${BILLING_REASON_PREFIX}${state.status}`;
      else if (!(state && LIVE_SUBSCRIPTION_STATUSES.has(state.status)) && input.pending) reason = `${BILLING_REASON_PREFIX}payment_pending`;
      try {
        this.db
          .prepare(
            "INSERT INTO api_keys (key_hash, account_id, prefix, plan, label, active, source, checkout_session, stripe_customer, stripe_subscription, created_at, deactivated_at, deactivated_reason) VALUES (?, ?, ?, ?, ?, ?, 'checkout', ?, ?, ?, ?, ?, ?)"
          )
          .run(keyHash, accountId, apiKeyPrefix(apiKey), plan, input.label, reason ? 0 : 1, input.checkoutSession, input.stripeCustomer, input.stripeSubscription, now, reason ? now : null, reason);
      } catch (err) {
        if (isUniqueViolation(err)) return null;
        throw err;
      }
      return { apiKey, record: { id: accountId, keyHash, prefix: apiKeyPrefix(apiKey), plan, label: input.label, active: reason === null }, subscriptionEnded: ended };
    });
  }

  /** Turns on a checkout's key that was issued while its payment was pending; true when one was activated. */
  activatePendingCheckout(checkoutSession: string): boolean {
    return (
      Number(
        this.db
          .prepare("UPDATE api_keys SET active = 1, deactivated_at = NULL, deactivated_reason = NULL WHERE checkout_session = ? AND active = 0 AND deactivated_reason = ?")
          .run(checkoutSession, `${BILLING_REASON_PREFIX}payment_pending`).changes
      ) === 1
    );
  }

  /**
   * Replaces the account's active key with a fresh one on the same plan,
   * account and subscription, deactivating the old key in the same
   * transaction. Returns null when the account has no active
   * database-backed key.
   */
  rotate(accountId: string, now: number = Date.now()): IssuedKey | null {
    return transaction(this.db, () => {
      const row = this.db.prepare("SELECT * FROM api_keys WHERE account_id = ? AND active = 1").get(accountId) as unknown as KeyRow | undefined;
      if (!row) return null;
      const apiKey = generateApiKey();
      const keyHash = hashApiKey(apiKey);
      this.db.prepare("UPDATE api_keys SET active = 0, deactivated_at = ?, deactivated_reason = 'rotated' WHERE key_hash = ?").run(now, row.key_hash);
      this.db
        .prepare(
          "INSERT INTO api_keys (key_hash, account_id, prefix, plan, label, active, source, checkout_session, stripe_customer, stripe_subscription, created_at) VALUES (?, ?, ?, ?, ?, 1, 'rotation', NULL, ?, ?, ?)"
        )
        .run(keyHash, accountId, apiKeyPrefix(apiKey), row.plan, row.label, row.stripe_customer, row.stripe_subscription, now);
      return { apiKey, record: { id: accountId, keyHash, prefix: apiKeyPrefix(apiKey), plan: row.plan, label: row.label, active: true } };
    });
  }

  /** Deactivates every active key of a subscription; returns how many changed. */
  deactivateSubscription(subscriptionId: string, reason: string, now: number = Date.now()): number {
    return Number(
      this.db
        .prepare("UPDATE api_keys SET active = 0, deactivated_at = ?, deactivated_reason = ? WHERE stripe_subscription = ? AND active = 1")
        .run(now, `${BILLING_REASON_PREFIX}${reason}`, subscriptionId).changes
    );
  }

  /**
   * Reactivates the subscription's keys that billing deactivated. Rotated
   * keys stay dead, so a recovered subscription gets back exactly the keys
   * it lost to billing (one per account).
   */
  reactivateSubscription(subscriptionId: string): number {
    return Number(
      this.db
        .prepare("UPDATE api_keys SET active = 1, deactivated_at = NULL, deactivated_reason = NULL WHERE stripe_subscription = ? AND active = 0 AND deactivated_reason LIKE ?")
        .run(subscriptionId, `${BILLING_REASON_PREFIX}%`).changes
    );
  }

  /**
   * The current plan of a database-backed account: undefined when the
   * principal is not one (configured keys, prepaid sessions), null when it
   * has no active key, else the active key's plan.
   */
  currentPlan(accountId: string): PlanName | null | undefined {
    if (!this.db.prepare("SELECT 1 FROM api_keys WHERE account_id = ? LIMIT 1").get(accountId)) return undefined;
    const row = this.db.prepare("SELECT plan FROM api_keys WHERE account_id = ? AND active = 1").get(accountId) as { plan: PlanName } | undefined;
    return row ? row.plan : null;
  }

  /**
   * True when the account has no active key and its subscription was deleted: it can never be used again.
   * Decided by the subscription's recorded status, not a key's deactivation reason: a key that billing had
   * already suspended (past_due, unpaid, canceled) kept that reason when the subscription was deleted
   * before deletions relabelled it, and such rows may still exist.
   */
  isTerminated(accountId: string): boolean {
    return (
      this.db
        .prepare(
          "SELECT 1 FROM api_keys k JOIN subscription_state s ON s.subscription_id = k.stripe_subscription WHERE k.account_id = ? AND s.status = 'deleted' AND NOT EXISTS (SELECT 1 FROM api_keys WHERE account_id = ? AND active = 1) LIMIT 1"
        )
        .get(accountId, accountId) !== undefined
    );
  }

  /**
   * Ends every key of a deleted subscription for good. Active keys and keys billing had suspended are all
   * marked subscription_deleted, so the reason says why the key is dead and a key still waiting for its
   * checkout payment can no longer be turned on. A suspended key keeps the time it stopped working; rotated
   * keys keep their reason.
   */
  private endSubscription(subscriptionId: string, now: number): number {
    return Number(
      this.db
        .prepare("UPDATE api_keys SET active = 0, deactivated_at = COALESCE(deactivated_at, ?), deactivated_reason = ? WHERE stripe_subscription = ? AND (active = 1 OR deactivated_reason LIKE ?)")
        .run(now, `${BILLING_REASON_PREFIX}deleted`, subscriptionId, `${BILLING_REASON_PREFIX}%`).changes
    );
  }

  /** Moves every key of a subscription (active or billing-suspended) to a new plan. */
  setSubscriptionPlan(subscriptionId: string, plan: PlanName): number {
    return Number(
      this.db.prepare("UPDATE api_keys SET plan = ? WHERE stripe_subscription = ? AND (active = 1 OR deactivated_reason LIKE ?)").run(plan, subscriptionId, `${BILLING_REASON_PREFIX}%`).changes
    );
  }

  /**
   * Applies one subscription webhook event exactly once and in order. Stripe
   * retries deliveries and does not guarantee ordering, so the event id is
   * recorded in the same transaction as its effect, an event older than the
   * last one applied to the subscription is ignored, and a deleted
   * subscription can never be revived by a late "active" update.
   */
  applySubscriptionEvent(event: { id: string; type: string; created: number }, subscription: { id: string; status: string; plan: PlanName | null }, now: number = Date.now()): SubscriptionAction {
    return transaction(this.db, () => {
      try {
        this.db.prepare("INSERT INTO stripe_events (id, type, received_at) VALUES (?, ?, ?)").run(event.id, event.type, now);
      } catch (err) {
        if (isUniqueViolation(err)) return "duplicate";
        throw err;
      }
      const state = this.db.prepare("SELECT status, event_created FROM subscription_state WHERE subscription_id = ?").get(subscription.id) as unknown as
        { status: string; event_created: number } | undefined;
      if (state?.status === "deleted") return "terminal";
      if (state && state.event_created > event.created) return "stale";
      const status = event.type === "customer.subscription.deleted" ? "deleted" : subscription.status;
      this.db
        .prepare(
          "INSERT INTO subscription_state (subscription_id, status, plan, event_created) VALUES (?, ?, ?, ?) ON CONFLICT(subscription_id) DO UPDATE SET status = excluded.status, plan = COALESCE(excluded.plan, subscription_state.plan), event_created = excluded.event_created"
        )
        .run(subscription.id, status, subscription.plan, event.created);
      if (subscription.plan) this.setSubscriptionPlan(subscription.id, subscription.plan);
      if (status === "deleted") this.endSubscription(subscription.id, now);
      else if (LIVE_SUBSCRIPTION_STATUSES.has(status)) this.reactivateSubscription(subscription.id);
      else if (SUSPENDED_SUBSCRIPTION_STATUSES.has(status)) this.deactivateSubscription(subscription.id, status, now);
      return "applied";
    });
  }

  /** Records a non-subscription webhook event id; false when it was already seen. */
  recordEvent(eventId: string, type: string, now: number = Date.now()): boolean {
    try {
      this.db.prepare("INSERT INTO stripe_events (id, type, received_at) VALUES (?, ?, ?)").run(eventId, type, now);
      return true;
    } catch (err) {
      if (isUniqueViolation(err)) return false;
      throw err;
    }
  }

  /** The last status a webhook reported for a subscription, if any. */
  subscriptionStatus(subscriptionId: string): string | null {
    const row = this.db.prepare("SELECT status FROM subscription_state WHERE subscription_id = ?").get(subscriptionId) as unknown as { status: string } | undefined;
    return row?.status ?? null;
  }

  /** Forgets processed webhook ids older than Stripe's retry horizon. */
  pruneEvents(now: number = Date.now()): number {
    return Number(this.db.prepare("DELETE FROM stripe_events WHERE received_at < ?").run(now - 30 * 24 * 60 * 60 * 1000).changes);
  }
}
