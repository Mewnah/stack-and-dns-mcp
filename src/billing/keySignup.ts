/**
 * Self-serve API keys: a signup page, Stripe Checkout (subscription mode),
 * a success page that issues the key exactly once, key rotation, and the
 * Stripe webhook that keeps keys in step with their subscription.
 *
 * The raw key is shown only on the success page response that minted it.
 * The Checkout Session id in that page's URL is a payment reference, and
 * payment references leak through logs and dashboards, so a second visit
 * never shows or re-issues a key. A buyer who still has the key rotates it
 * with POST /v1/keys/rotate; a lost key is re-issued by the operator.
 */

import express, { type Express, type Request, type RequestHandler, type Response } from "express";
import type { PlanLimits, PlanName } from "../config.js";
import { errorMessage } from "../lib/errors.js";
import { logger } from "../logger.js";
import { principalFromAuthInfo, type AuthenticatedRequest } from "../middleware/auth.js";
import { SERVICE_TAG } from "../middleware/payments.js";
import { LIVE_SUBSCRIPTION_STATUSES, subscriptionHasEnded, type KeyRepository } from "../store/keyStore.js";
import { StripeApiError, verifyStripeWebhook, type StripeApi } from "./stripeApi.js";

export const SELF_SERVE_PLANS = ["pro", "enterprise"] as const;
export type SelfServePlan = (typeof SELF_SERVE_PLANS)[number];

export interface KeySignupOptions {
  publicUrl: string;
  /** Stripe Price ids per plan; a plan without a price is not offered. */
  prices: Partial<Record<SelfServePlan, string>>;
  webhookSecret: string | null;
  planLimits: Record<PlanName, PlanLimits>;
}

export interface KeySignupDeps {
  stripe: StripeApi;
  keys: KeyRepository;
  options: KeySignupOptions;
  /** Per-address throttle shared with the other pre-authentication endpoints; answers 429 itself and returns true when exceeded. */
  throttle: (req: Request, res: Response) => boolean;
}

const CHECKOUT_SESSION_ID = /^cs_[A-Za-z0-9_]{8,255}$/;
const PRICE_CACHE_MS = 10 * 60 * 1000;

export function escapeHtml(value: unknown): string {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const PAGE_STYLE = `
  :root { color-scheme: light dark; --fg: #1d2330; --muted: #5b6475; --bg: #f7f8fa; --card: #ffffff; --line: #d9dde5; --accent: #2554c7; }
  @media (prefers-color-scheme: dark) { :root { --fg: #e7eaf0; --muted: #a3acbd; --bg: #12151b; --card: #1b2029; --line: #2e3542; --accent: #7aa2ff; } }
  body { margin: 0; font: 16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; color: var(--fg); background: var(--bg); }
  main { max-width: 760px; margin: 0 auto; padding: 32px 16px 48px; }
  h1 { font-size: 1.7rem; margin: 0 0 8px; }
  p.lead { color: var(--muted); margin: 0 0 24px; }
  .plans { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px; }
  .plan { background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 20px; display: flex; flex-direction: column; }
  .plan h2 { margin: 0 0 4px; font-size: 1.2rem; }
  .price { font-size: 1.4rem; font-weight: 600; margin: 4px 0 12px; }
  .plan ul { padding-left: 18px; margin: 0 0 16px; color: var(--muted); flex: 1; }
  button { font: inherit; padding: 10px 14px; border-radius: 8px; border: 0; background: var(--accent); color: #fff; cursor: pointer; }
  code, pre { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }
  pre { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 12px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
  .key { font-size: 1.05rem; }
  .warn { border-left: 4px solid #d97706; padding: 8px 12px; background: var(--card); }
`;

function page(res: Response, status: number, title: string, body: string): void {
  res
    .status(status)
    .set({
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff",
      "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https://checkout.stripe.com; frame-ancestors 'none'; base-uri 'none'"
    })
    .send(
      `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${escapeHtml(title)}</title><style>${PAGE_STYLE}</style></head><body><main>${body}</main></body></html>`
    );
}

function subscriptionEndedPage(res: Response): void {
  page(res, 410, "Subscription ended", '<h1>This subscription has ended</h1><p class="lead">Start a new subscription from the signup page.</p>');
}

function formatNumber(n: number): string {
  return n >= 1000000 ? "unlimited" : n.toLocaleString("en-US");
}

interface PriceLabel {
  label: string;
  fetchedAt: number;
}

export function registerKeySignupRoutes(app: Express, deps: KeySignupDeps, auth: RequestHandler): void {
  const { stripe, keys, options, throttle } = deps;
  const offered = SELF_SERVE_PLANS.filter((plan) => options.prices[plan]);
  const priceLabels = new Map<SelfServePlan, PriceLabel>();

  const priceLabel = async (plan: SelfServePlan): Promise<string> => {
    const cached = priceLabels.get(plan);
    if (cached && Date.now() - cached.fetchedAt < PRICE_CACHE_MS) return cached.label;
    try {
      const price = await stripe.request("GET", `/v1/prices/${encodeURIComponent(options.prices[plan] as string)}`);
      const amount = typeof price.unit_amount === "number" ? price.unit_amount : null;
      const currency = typeof price.currency === "string" ? price.currency.toUpperCase() : "";
      const recurring = price.recurring as { interval?: string } | null | undefined;
      const label =
        amount === null
          ? "See checkout"
          : `${new Intl.NumberFormat("en-US", { style: "currency", currency: currency || "USD" }).format(amount / 100)}${recurring?.interval ? ` / ${recurring.interval}` : ""}`;
      priceLabels.set(plan, { label, fetchedAt: Date.now() });
      return label;
    } catch (err) {
      logger.warn("stripe price lookup failed; showing a generic label", { plan, error: err });
      return "See checkout";
    }
  };

  app.get("/signup", async (req, res) => {
    if (throttle(req, res)) return;
    if (offered.length === 0) {
      page(res, 404, "Signup unavailable", '<h1>Signup is not available</h1><p class="lead">This server does not sell API keys directly. Contact its operator.</p>');
      return;
    }
    const cards = await Promise.all(
      offered.map(async (plan) => {
        const limits = options.planLimits[plan];
        return `<form class="plan" method="post" action="/v1/keys/checkout"><input type="hidden" name="plan" value="${escapeHtml(plan)}"><h2>${escapeHtml(plan[0]?.toUpperCase() + plan.slice(1))}</h2><div class="price">${escapeHtml(await priceLabel(plan))}</div><ul><li>${formatNumber(limits.perMinute)} checks per minute</li><li>${formatNumber(limits.perDay)} checks per day, including bulk-list domains</li><li>${formatNumber(limits.maxConcurrent)} checks at once</li><li>Stored history, bulk lead-list checks and domain monitoring</li></ul><button type="submit">Subscribe</button></form>`;
      })
    );
    page(
      res,
      200,
      "Get an API key",
      `<h1>Get an API key</h1><p class="lead">Subscribe to a plan and your key is shown right after checkout. Use it as <code>Authorization: Bearer &lt;key&gt;</code> from any MCP client or the REST API.</p><div class="plans">${cards.join("")}</div>`
    );
  });

  app.post("/v1/keys/checkout", express.urlencoded({ extended: false, limit: "4kb" }), async (req, res) => {
    if (throttle(req, res)) return;
    const wantsJson = req.is("application/json") === "application/json" || (req.header("accept") ?? "").includes("application/json");
    const plan = (req.body as { plan?: unknown } | undefined)?.plan;
    if (typeof plan !== "string" || !(SELF_SERVE_PLANS as readonly string[]).includes(plan) || !options.prices[plan as SelfServePlan]) {
      res.status(400).json({ error: "invalid_plan", message: `Choose one of: ${offered.join(", ") || "(none offered)"}.` });
      return;
    }
    try {
      const session = await stripe.createSubscriptionCheckout({
        priceId: options.prices[plan as SelfServePlan] as string,
        successUrl: `${options.publicUrl}/keys/success?session_id={CHECKOUT_SESSION_ID}`,
        cancelUrl: `${options.publicUrl}/signup`,
        metadata: { service: SERVICE_TAG, kind: "api_key", plan }
      });
      const url = typeof session.url === "string" ? session.url : null;
      if (!url) throw new Error("Stripe returned a Checkout Session without a URL");
      if (wantsJson) res.json({ url, checkoutSessionId: session.id ?? null });
      else res.redirect(303, url);
    } catch (err) {
      logger.error("stripe subscription checkout creation failed", { plan, error: err });
      res.status(502).json({ error: "checkout_unavailable", message: "Checkout could not be started. Try again shortly." });
    }
  });

  app.get("/keys/success", async (req, res) => {
    if (throttle(req, res)) return;
    const sessionId = typeof req.query.session_id === "string" ? req.query.session_id : "";
    if (!CHECKOUT_SESSION_ID.test(sessionId)) {
      page(res, 400, "Invalid link", '<h1>This link is not valid</h1><p class="lead">Open the page Stripe redirected you to after checkout.</p>');
      return;
    }
    let session: Record<string, unknown>;
    try {
      session = await stripe.getCheckoutSession(sessionId, ["subscription"]);
    } catch (err) {
      const notFound = err instanceof StripeApiError && err.status === 404;
      if (!notFound) logger.error("stripe checkout session lookup failed", { error: err });
      page(
        res,
        notFound ? 404 : 502,
        "Checkout not found",
        notFound ? "<h1>Checkout not found</h1>" : '<h1>Stripe is unavailable</h1><p class="lead">Reload this page in a minute; your key has not been issued yet.</p>'
      );
      return;
    }
    const metadata = (session.metadata as Record<string, string> | null) ?? {};
    const plan = metadata.plan as SelfServePlan | undefined;
    if (metadata.service !== SERVICE_TAG || metadata.kind !== "api_key" || session.mode !== "subscription" || !plan || !(SELF_SERVE_PLANS as readonly string[]).includes(plan)) {
      page(res, 404, "Checkout not found", '<h1>Checkout not found</h1><p class="lead">This checkout was not an API key purchase on this server.</p>');
      return;
    }
    const subscription = session.subscription as { id?: unknown; status?: unknown } | string | null;
    const subscriptionId = typeof subscription === "string" ? subscription : typeof subscription?.id === "string" ? subscription.id : null;
    const subscriptionStatus = typeof subscription === "object" && subscription && typeof subscription.status === "string" ? subscription.status : null;
    const paid = session.status === "complete" && (session.payment_status === "paid" || session.payment_status === "no_payment_required");
    const live = paid && subscriptionId !== null && (subscriptionStatus === null || LIVE_SUBSCRIPTION_STATUSES.has(subscriptionStatus));
    // A completed checkout whose payment is still clearing (bank debits and
    // other delayed methods) gets its key now, inactive: this first visit is
    // Stripe redirecting the buyer's own browser, and a session id that
    // leaked into logs later cannot be used to claim the key first.
    const pending = !live && session.status === "complete" && subscriptionId !== null && session.payment_status === "unpaid" && (subscriptionStatus === null || subscriptionStatus === "incomplete");
    // Checked before the 402: a subscription that ended before the buyer
    // opened this page will never confirm a payment, so "reload this page
    // later" would be a promise that cannot come true. Stripe's copy can be
    // older than the recorded status: this process may have handled the
    // webhook that canceled, expired or deleted it while the lookup above was
    // in flight. Either one having ended is enough, since neither comes back.
    const recordedStatus = subscriptionId !== null ? keys.subscriptionStatus(subscriptionId) : null;
    if (subscriptionHasEnded(subscriptionStatus) || subscriptionHasEnded(recordedStatus)) {
      subscriptionEndedPage(res);
      return;
    }
    if ((!live && !pending) || !subscriptionId) {
      page(res, 402, "Payment not complete", '<h1>Payment is not complete yet</h1><p class="lead">Reload this page once Stripe confirms the payment. No key has been issued.</p>');
      return;
    }
    const customer = typeof session.customer === "string" ? session.customer : null;
    // The plan follows the subscription's current price (the buyer may have
    // switched plans since checkout); a webhook-recorded plan wins in the store.
    const items = (typeof subscription === "object" && subscription ? (subscription as { items?: { data?: Array<{ price?: { id?: unknown } }> } }).items?.data : undefined) ?? [];
    const livePrice = typeof items[0]?.price?.id === "string" ? (items[0].price.id as string) : null;
    const issuePlan = planForPrice(options.prices, livePrice) ?? plan;
    const issued = keys.issueForCheckout({
      checkoutSession: sessionId,
      plan: issuePlan,
      label: `self-serve ${issuePlan}${customer ? ` ${customer}` : ""}`,
      stripeCustomer: customer,
      stripeSubscription: subscriptionId,
      pending
    });
    if (issued?.subscriptionEnded) {
      // Another process recorded the deletion, cancellation or expiry between
      // the status read above and the insert: the key was stored dead, so it
      // is not shown, and the key page's "starts working once Stripe confirms"
      // would be false.
      logger.info("self-serve checkout reached an ended subscription; no working key issued", { keyId: issued.record.id, subscription: subscriptionId });
      subscriptionEndedPage(res);
      return;
    }
    if (!issued && live && keys.activatePendingCheckout(sessionId)) {
      page(res, 200, "Key active", '<h1>Your API key is now active</h1><p class="lead">Stripe confirmed the payment. Use the key shown on your first visit to this page.</p>');
      return;
    }
    if (!issued) {
      page(
        res,
        409,
        "Key already issued",
        `<h1>Your key was already issued</h1><p class="lead">For security it is shown only once. If you saved it, you're set. If you lost it, contact the operator of ${escapeHtml(options.publicUrl)} with your Stripe receipt to have it re-issued.</p>`
      );
      return;
    }
    logger.info("self-serve api key issued", { keyId: issued.record.id, plan: issued.record.plan, subscription: subscriptionId, active: issued.record.active });
    const mcpUrl = `${options.publicUrl}/mcp`;
    const config = JSON.stringify({ mcpServers: { "stack-and-dns": { url: mcpUrl, headers: { Authorization: `Bearer ${issued.apiKey}` } } } }, null, 2);
    page(
      res,
      201,
      "Your API key",
      `<h1>Your API key</h1><p class="warn">Copy it now. It is shown only once and cannot be recovered from this page.${issued.record.active ? "" : " It starts working as soon as Stripe confirms your payment."}</p><pre class="key">${escapeHtml(issued.apiKey)}</pre><p>Plan: <strong>${escapeHtml(issued.record.plan)}</strong>. Send it as <code>Authorization: Bearer &lt;key&gt;</code> to <code>${escapeHtml(mcpUrl)}</code>, or add this to your MCP client configuration:</p><pre>${escapeHtml(config)}</pre><p>To replace it later, send <code>POST ${escapeHtml(options.publicUrl)}/v1/keys/rotate</code> with the current key; the old key stops working immediately. Cancelling the subscription in Stripe disables the key.</p>`
    );
  });

  app.post("/v1/keys/rotate", auth, (req, res) => {
    const principal = principalFromAuthInfo((req as AuthenticatedRequest).auth);
    if (!principal || principal.source !== "api-key") {
      res.status(401).json({ error: "unauthorized", message: "Rotate with the API key you want to replace: Authorization: Bearer sdm_live_..." });
      return;
    }
    const issued = keys.rotate(principal.id);
    if (!issued) {
      res.status(400).json({ error: "not_rotatable", message: "Only keys issued through self-serve signup can be rotated here; ask the operator to rotate this key." });
      return;
    }
    logger.info("api key rotated", { oldKeyId: principal.id, newKeyId: issued.record.id });
    res.set("Cache-Control", "no-store").json({ apiKey: issued.apiKey, keyId: issued.record.id, plan: issued.record.plan, replaced: principal.id });
  });
}

/** Maps a Stripe Price id back to the plan it sells. */
export function planForPrice(prices: Partial<Record<SelfServePlan, string>>, priceId: string | null): SelfServePlan | null {
  if (!priceId) return null;
  for (const plan of SELF_SERVE_PLANS) if (prices[plan] === priceId) return plan;
  return null;
}

/**
 * The webhook needs the exact bytes Stripe signed, so it is mounted with its
 * own raw body parser before the global JSON parser.
 */
export function registerStripeWebhookRoute(app: Express, deps: Pick<KeySignupDeps, "keys" | "options">): void {
  app.post("/v1/stripe/webhook", express.raw({ type: "*/*", limit: "1mb" }), (req, res) => {
    const secret = deps.options.webhookSecret;
    if (!secret) {
      res.status(404).json({ error: "not_found", message: "Webhooks are not configured on this server." });
      return;
    }
    const body = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
    const verification = verifyStripeWebhook(body, req.header("stripe-signature"), secret);
    if (!verification.ok || !verification.event) {
      logger.warn("stripe webhook rejected", { reason: verification.error });
      res.status(400).json({ error: "invalid_signature", message: verification.error });
      return;
    }
    const event = verification.event;
    const id = typeof event.id === "string" ? event.id : "";
    const type = typeof event.type === "string" ? event.type : "";
    const created = typeof event.created === "number" ? event.created : 0;
    const object = ((event.data as { object?: unknown } | undefined)?.object ?? null) as Record<string, unknown> | null;
    if (!id || !type || !object) {
      res.status(400).json({ error: "invalid_event", message: "Event is missing id, type or data.object." });
      return;
    }
    try {
      if (type === "customer.subscription.updated" || type === "customer.subscription.deleted" || type === "customer.subscription.created") {
        const subscriptionId = typeof object.id === "string" ? object.id : "";
        const status = typeof object.status === "string" ? object.status : "";
        const items = (object.items as { data?: Array<{ price?: { id?: unknown } }> } | undefined)?.data ?? [];
        const priceId = typeof items[0]?.price?.id === "string" ? (items[0].price.id as string) : null;
        if (!subscriptionId) {
          res.status(400).json({ error: "invalid_event", message: "Subscription event without a subscription id." });
          return;
        }
        const action = deps.keys.applySubscriptionEvent({ id, type, created }, { id: subscriptionId, status, plan: planForPrice(deps.options.prices, priceId) });
        logger.info("stripe subscription event", { event: id, type, subscription: subscriptionId, status, action });
        res.json({ received: true, action });
        return;
      }
      const fresh = deps.keys.recordEvent(id, type);
      res.json({ received: true, action: fresh ? "ignored" : "duplicate" });
    } catch (err) {
      // A non-2xx answer makes Stripe retry, which is what we want when the
      // database write failed; the event id was rolled back with it.
      logger.error("stripe webhook processing failed", { event: id, type, error: errorMessage(err) });
      res.status(500).json({ error: "processing_failed" });
    }
  });
}
