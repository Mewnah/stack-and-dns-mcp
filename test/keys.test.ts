import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, describe, it } from "node:test";
import express, { type RequestHandler } from "express";
import { registerKeySignupRoutes, registerStripeWebhookRoute, type KeySignupOptions } from "../src/billing/keySignup.js";
import { signStripePayload, StripeApi, verifyStripeWebhook } from "../src/billing/stripeApi.js";
import { loadConfig } from "../src/config.js";
import { setLogLevel } from "../src/logger.js";
import { hashApiKey, principalToAuthInfo, type AuthenticatedRequest } from "../src/middleware/auth.js";
import { openDatabase } from "../src/store/db.js";
import { KeyRepository } from "../src/store/keyStore.js";

setLogLevel("silent");

const SECRET = "whsec_test_secret_value";

async function repo(): Promise<KeyRepository> {
  const db = await openDatabase(":memory:");
  assert.ok(db);
  return new KeyRepository(db);
}

describe("verifyStripeWebhook", () => {
  const payload = JSON.stringify({ id: "evt_1", type: "customer.subscription.deleted", created: 1, data: { object: { id: "sub_1" } } });
  const now = 1_800_000_000_000;

  it("accepts a correctly signed payload within the tolerance window", () => {
    const header = signStripePayload(payload, SECRET, now / 1000 - 10);
    const result = verifyStripeWebhook(payload, header, SECRET, 300, now);
    assert.equal(result.ok, true);
    assert.equal(result.event?.id, "evt_1");
  });

  it("accepts a header carrying several v1 signatures when one matches (secret rotation)", () => {
    const good = signStripePayload(payload, SECRET, now / 1000).split(",")[1] as string;
    const header = `t=${now / 1000},v1=${"0".repeat(64)},${good}`;
    assert.equal(verifyStripeWebhook(payload, header, SECRET, 300, now).ok, true);
  });

  it("rejects wrong secrets, tampered bodies, stale timestamps and malformed headers", () => {
    const header = signStripePayload(payload, SECRET, now / 1000);
    assert.equal(verifyStripeWebhook(payload, header, "whsec_other", 300, now).error, "signature mismatch");
    assert.equal(verifyStripeWebhook(`${payload} `, header, SECRET, 300, now).error, "signature mismatch");
    assert.match(verifyStripeWebhook(payload, signStripePayload(payload, SECRET, now / 1000 - 301), SECRET, 300, now).error ?? "", /tolerance/);
    assert.match(verifyStripeWebhook(payload, "v1=abc", SECRET, 300, now).error ?? "", /malformed/);
    assert.match(verifyStripeWebhook(payload, undefined, SECRET, 300, now).error ?? "", /missing/);
    const v0Only = `t=${now / 1000},v0=${"a".repeat(64)}`;
    assert.match(verifyStripeWebhook(payload, v0Only, SECRET, 300, now).error ?? "", /malformed/);
  });
});

describe("KeyRepository", () => {
  it("issues exactly one key per Checkout Session", async () => {
    const keys = await repo();
    const input = { checkoutSession: "cs_test_1234567890", plan: "pro" as const, label: "self-serve pro", stripeCustomer: "cus_1", stripeSubscription: "sub_1" };
    const issued = keys.issueForCheckout(input);
    assert.ok(issued);
    assert.match(issued.apiKey, /^sdm_live_/);
    assert.equal(keys.issueForCheckout(input), null, "a replayed success page cannot mint a second key");
    assert.equal(keys.findActiveByHash(hashApiKey(issued.apiKey))?.plan, "pro");
    assert.equal(keys.countActive(), 1);
  });

  it("rotates a key: the new key works, the old one stops, plan and subscription carry over", async () => {
    const keys = await repo();
    const issued = keys.issueForCheckout({ checkoutSession: "cs_test_rotate0001", plan: "enterprise", label: "x", stripeCustomer: null, stripeSubscription: "sub_r" });
    assert.ok(issued);
    const rotated = keys.rotate(issued.record.id);
    assert.ok(rotated);
    assert.equal(keys.findActiveByHash(hashApiKey(issued.apiKey)), null);
    assert.equal(keys.findActiveByHash(hashApiKey(rotated.apiKey))?.plan, "enterprise");
    assert.equal(rotated.record.id, issued.record.id, "the account id, and so the principal id, survives rotation");
    assert.equal(keys.findActiveByAccount(issued.record.id)?.stripeSubscription, "sub_r");
    assert.equal(keys.findActiveByAccount(issued.record.id)?.keyHash, hashApiKey(rotated.apiKey));
    const again = keys.rotate(issued.record.id);
    assert.ok(again, "the account can rotate again; only one key per account is ever active");
    assert.equal(keys.findActiveByHash(hashApiKey(rotated.apiKey)), null);
    assert.equal(keys.countActive(), 1);
    keys.applySubscriptionEvent({ id: "evt_a", type: "customer.subscription.updated", created: 10 }, { id: "sub_r", status: "past_due", plan: null });
    keys.applySubscriptionEvent({ id: "evt_b", type: "customer.subscription.updated", created: 11 }, { id: "sub_r", status: "active", plan: null });
    assert.equal(keys.findActiveByHash(hashApiKey(issued.apiKey)), null, "recovery never revives a rotated-away key");
    assert.ok(keys.findActiveByHash(hashApiKey(again.apiKey)));
    assert.equal(keys.findActiveByHash(hashApiKey(rotated.apiKey)), null);
  });

  it("applies subscription events once, in order, and treats deletion as final", async () => {
    const keys = await repo();
    const issued = keys.issueForCheckout({ checkoutSession: "cs_test_events0001", plan: "pro", label: "x", stripeCustomer: null, stripeSubscription: "sub_e" });
    assert.ok(issued);
    const hash = hashApiKey(issued.apiKey);
    const event = (id: string, created: number, type = "customer.subscription.updated") => ({ id, type, created });

    assert.equal(keys.applySubscriptionEvent(event("e1", 100), { id: "sub_e", status: "past_due", plan: null }), "applied");
    assert.equal(keys.findActiveByHash(hash), null, "past_due suspends the key");
    assert.equal(keys.applySubscriptionEvent(event("e1", 100), { id: "sub_e", status: "past_due", plan: null }), "duplicate");
    assert.equal(keys.applySubscriptionEvent(event("e0", 50), { id: "sub_e", status: "active", plan: null }), "stale", "an older event cannot undo a newer one");
    assert.equal(keys.findActiveByHash(hash), null);
    assert.equal(keys.applySubscriptionEvent(event("e2", 200), { id: "sub_e", status: "active", plan: "enterprise" }), "applied");
    assert.equal(keys.findActiveByHash(hash)?.plan, "enterprise", "recovery reactivates and a price change re-plans");
    assert.equal(keys.applySubscriptionEvent(event("e3", 300, "customer.subscription.deleted"), { id: "sub_e", status: "canceled", plan: null }), "applied");
    assert.equal(keys.findActiveByHash(hash), null);
    assert.equal(keys.applySubscriptionEvent(event("e4", 400), { id: "sub_e", status: "active", plan: null }), "terminal", "a deleted subscription never comes back");
    assert.equal(keys.findActiveByHash(hash), null);
    assert.equal(keys.subscriptionStatus("sub_e"), "deleted");
  });
});

describe("self-serve signup routes", () => {
  let stripeServer: http.Server;
  let appServer: http.Server;
  let base = "";
  let keys: KeyRepository;
  const sessions = new Map<string, Record<string, unknown>>();
  const created: string[] = [];

  const options = (): KeySignupOptions => ({ publicUrl: base, prices: { pro: "price_pro_1" }, webhookSecret: SECRET, planLimits: loadConfig({}, []).auth.planLimits });

  before(async () => {
    stripeServer = http.createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        res.setHeader("content-type", "application/json");
        const url = new URL(req.url ?? "/", "http://stub");
        if (req.method === "POST" && url.pathname === "/v1/checkout/sessions") {
          created.push(body);
          res.end(JSON.stringify({ id: "cs_test_created0001", url: "https://checkout.stripe.test/pay/cs_test_created0001" }));
          return;
        }
        const match = /^\/v1\/checkout\/sessions\/(.+)$/.exec(url.pathname);
        if (req.method === "GET" && match) {
          const session = sessions.get(decodeURIComponent(match[1] as string));
          res.statusCode = session ? 200 : 404;
          res.end(JSON.stringify(session ?? { error: { message: "No such checkout.session" } }));
          return;
        }
        if (req.method === "GET" && url.pathname.startsWith("/v1/prices/")) {
          res.end(JSON.stringify({ unit_amount: 4900, currency: "usd", recurring: { interval: "month" } }));
          return;
        }
        res.statusCode = 404;
        res.end(JSON.stringify({ error: { message: "unknown" } }));
      });
    });
    await new Promise<void>((resolve) => stripeServer.listen(0, "127.0.0.1", resolve));
    const stripe = new StripeApi("sk_test_x", `http://127.0.0.1:${(stripeServer.address() as AddressInfo).port}`);

    keys = await repo();
    const app = express();
    // Test auth: the bearer token is looked up in the repository.
    const auth: RequestHandler = (req, res, next) => {
      const token = (req.header("authorization") ?? "").replace(/^Bearer\s+/i, "");
      const record = token ? keys.findActiveByHash(hashApiKey(token)) : null;
      if (!record) {
        res.status(401).json({ error: "invalid_api_key" });
        return;
      }
      (req as AuthenticatedRequest).auth = principalToAuthInfo({ id: record.id, plan: record.plan, label: record.label, source: "api-key" }, token);
      next();
    };
    const deps = { stripe, keys, options: options(), throttle: () => false };
    registerStripeWebhookRoute(app, deps);
    app.use(express.json());
    appServer = app.listen(0, "127.0.0.1");
    await new Promise<void>((resolve) => appServer.once("listening", resolve));
    base = `http://127.0.0.1:${(appServer.address() as AddressInfo).port}`;
    deps.options.publicUrl = base;
    registerKeySignupRoutes(app, deps, auth);
  });

  after(async () => {
    await new Promise<void>((resolve) => appServer.close(() => resolve()));
    await new Promise<void>((resolve) => stripeServer.close(() => resolve()));
  });

  const paidSession = (id: string, overrides: Record<string, unknown> = {}): Record<string, unknown> => ({
    id,
    mode: "subscription",
    status: "complete",
    payment_status: "paid",
    customer: "cus_9",
    subscription: { id: `sub_${id}`, status: "active" },
    metadata: { service: "stack-and-dns-mcp", kind: "api_key", plan: "pro" },
    ...overrides
  });

  it("renders the signup page with live prices and a strict content security policy", async () => {
    const res = await fetch(`${base}/signup`);
    assert.equal(res.status, 200);
    const html = await res.text();
    assert.ok(html.includes("$49.00 / month"));
    assert.ok(html.includes('value="pro"'));
    assert.ok(!html.includes('value="enterprise"'), "a plan without a configured price is not offered");
    assert.match(res.headers.get("content-security-policy") ?? "", /default-src 'none'/);
  });

  it("starts a subscription checkout from the form and rejects unknown plans", async () => {
    const res = await fetch(`${base}/v1/keys/checkout`, { method: "POST", body: new URLSearchParams({ plan: "pro" }), redirect: "manual" });
    assert.equal(res.status, 303);
    assert.equal(res.headers.get("location"), "https://checkout.stripe.test/pay/cs_test_created0001");
    const sent = new URLSearchParams(created.at(-1));
    assert.equal(sent.get("mode"), "subscription");
    assert.equal(sent.get("line_items[0][price]"), "price_pro_1");
    assert.equal(sent.get("metadata[kind]"), "api_key");
    assert.equal(sent.get("subscription_data[metadata][plan]"), "pro");
    assert.match(sent.get("success_url") ?? "", /\/keys\/success\?session_id=\{CHECKOUT_SESSION_ID\}$/);
    const bad = await fetch(`${base}/v1/keys/checkout`, { method: "POST", body: new URLSearchParams({ plan: "enterprise" }) });
    assert.equal(bad.status, 400);
  });

  it("shows the key once, then refuses to show or re-issue it", async () => {
    sessions.set("cs_test_success0001", paidSession("cs_test_success0001"));
    const first = await fetch(`${base}/keys/success?session_id=cs_test_success0001`);
    assert.equal(first.status, 201);
    assert.equal(first.headers.get("cache-control"), "no-store");
    const key = /(sdm_live_[A-Za-z0-9_-]+)/.exec(await first.text())?.[1];
    assert.ok(key);
    assert.equal(keys.findActiveByHash(hashApiKey(key))?.plan, "pro");
    const second = await fetch(`${base}/keys/success?session_id=cs_test_success0001`);
    assert.equal(second.status, 409);
    assert.ok(!(await second.text()).includes("sdm_live_"));
  });

  it("refuses unpaid, foreign and malformed checkouts", async () => {
    sessions.set("cs_test_unpaid0001", paidSession("cs_test_unpaid0001", { payment_status: "unpaid", status: "open" }));
    sessions.set("cs_test_credits001", paidSession("cs_test_credits001", { mode: "payment", metadata: { service: "stack-and-dns-mcp", kind: "credits" } }));
    sessions.set("cs_test_pastdue01", paidSession("cs_test_pastdue01", { subscription: { id: "sub_pd", status: "past_due" } }));
    assert.equal((await fetch(`${base}/keys/success?session_id=cs_test_unpaid0001`)).status, 402);
    assert.equal((await fetch(`${base}/keys/success?session_id=cs_test_credits001`)).status, 404);
    assert.equal((await fetch(`${base}/keys/success?session_id=cs_test_pastdue01`)).status, 402);
    assert.equal((await fetch(`${base}/keys/success?session_id=cs_test_missing01`)).status, 404);
    assert.equal((await fetch(`${base}/keys/success?session_id=<script>`)).status, 400);
  });

  it("rotates a self-serve key through the API", async () => {
    sessions.set("cs_test_rotate0002", paidSession("cs_test_rotate0002"));
    const html = await (await fetch(`${base}/keys/success?session_id=cs_test_rotate0002`)).text();
    const key = /(sdm_live_[A-Za-z0-9_-]+)/.exec(html)?.[1] as string;
    const res = await fetch(`${base}/v1/keys/rotate`, { method: "POST", headers: { authorization: `Bearer ${key}` } });
    assert.equal(res.status, 200);
    const body = (await res.json()) as { apiKey: string; plan: string; keyId: string; replaced: string };
    assert.equal(body.plan, "pro");
    assert.equal(body.keyId, body.replaced, "the principal id is unchanged by rotation");
    assert.equal(keys.findActiveByHash(hashApiKey(key)), null);
    assert.ok(keys.findActiveByHash(hashApiKey(body.apiKey)));
    assert.equal((await fetch(`${base}/v1/keys/rotate`, { method: "POST", headers: { authorization: `Bearer ${key}` } })).status, 401);
  });

  it("verifies webhook signatures and suspends keys when a subscription lapses", async () => {
    sessions.set("cs_test_webhook001", paidSession("cs_test_webhook001"));
    const html = await (await fetch(`${base}/keys/success?session_id=cs_test_webhook001`)).text();
    const key = /(sdm_live_[A-Za-z0-9_-]+)/.exec(html)?.[1] as string;
    const send = (payload: object, secret = SECRET) => {
      const body = JSON.stringify(payload);
      return fetch(`${base}/v1/stripe/webhook`, { method: "POST", headers: { "content-type": "application/json", "stripe-signature": signStripePayload(body, secret) }, body });
    };
    const unpaid = {
      id: "evt_w1",
      type: "customer.subscription.updated",
      created: Math.floor(Date.now() / 1000),
      data: { object: { id: "sub_cs_test_webhook001", status: "unpaid", items: { data: [{ price: { id: "price_pro_1" } }] } } }
    };
    assert.equal((await send(unpaid, "whsec_wrong")).status, 400);
    assert.ok(keys.findActiveByHash(hashApiKey(key)), "a forged event changes nothing");
    const applied = await send(unpaid);
    assert.equal(applied.status, 200);
    assert.equal(((await applied.json()) as { action: string }).action, "applied");
    assert.equal(keys.findActiveByHash(hashApiKey(key)), null);
    const again = await send(unpaid);
    assert.equal(((await again.json()) as { action: string }).action, "duplicate");
    const other = await send({ id: "evt_w2", type: "invoice.paid", created: 1, data: { object: { id: "in_1" } } });
    assert.equal(((await other.json()) as { action: string }).action, "ignored");
  });
});
