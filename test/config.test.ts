import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { DEFAULT_PLAN_LIMITS, httpLimitFor, loadConfig, parseTrustProxy } from "../src/config.js";

describe("loadConfig", () => {
  it("accepts partial STACKDNS_RATE_LIMITS_JSON overrides", () => {
    const config = loadConfig({ STACKDNS_RATE_LIMITS_JSON: '{"free":{"perMinute":5},"pro":{"perDay":20000}}' }, []);
    assert.equal(config.auth.planLimits.free.perMinute, 5);
    assert.equal(config.auth.planLimits.free.perDay, 100);
    assert.equal(config.auth.planLimits.pro.perDay, 20000);
    assert.equal(config.auth.planLimits.pro.perMinute, 60);
    assert.equal(config.auth.planLimits.enterprise.perMinute, 300);
  });

  it("exposes and overrides the per-plan HTTP request ceiling", () => {
    const stock = loadConfig({}, []).auth.planLimits;
    for (const [plan, limits] of Object.entries(stock)) {
      assert.equal(limits.httpPerMinute, Math.max(30, limits.perMinute * 5), `${plan} publishes its derived HTTP ceiling`);
      assert.equal(httpLimitFor(limits), limits.httpPerMinute);
    }
    assert.equal(stock.free.httpPerMinute, 50);
    assert.equal(stock.enterprise.httpPerMinute, 1500);
    assert.equal(DEFAULT_PLAN_LIMITS.free.httpPerMinute, undefined, "the stock table leaves the ceiling to be derived after overrides");
    assert.equal(httpLimitFor({ perMinute: 2, perDay: 10, maxConcurrent: 1 }), 30, "derived ceiling floors at 30 when unset");
    const explicit = loadConfig({ STACKDNS_RATE_LIMITS_JSON: '{"free":{"httpPerMinute":7}}' }, []);
    assert.equal(explicit.auth.planLimits.free.httpPerMinute, 7);
    assert.equal(explicit.auth.planLimits.free.perMinute, 10);
    const raised = loadConfig({ STACKDNS_RATE_LIMITS_JSON: '{"free":{"perMinute":100}}' }, []);
    assert.equal(raised.auth.planLimits.free.httpPerMinute, 500, "raising perMinute alone raises the derived ceiling too");
  });

  it("rejects unknown plans and malformed JSON in the override", () => {
    assert.throws(() => loadConfig({ STACKDNS_RATE_LIMITS_JSON: '{"platinum":{"perMinute":5}}' }, []), /invalid/);
    assert.throws(() => loadConfig({ STACKDNS_RATE_LIMITS_JSON: "{not json" }, []), /not valid JSON/);
  });

  it("treats empty-string env values as unset", () => {
    const config = loadConfig(
      {
        STACKDNS_TRANSPORT: "http",
        STACKDNS_SESSION_SECRET: "",
        STRIPE_SUCCESS_URL: "",
        STRIPE_CANCEL_URL: "",
        X402_FACILITATOR_URL: "",
        STACKDNS_PUBLIC_URL: "",
        PORT: "",
        STACKDNS_PORT: "",
        STRIPE_CURRENCY: "   ",
        STACKDNS_LOG_LEVEL: ""
      },
      []
    );
    assert.equal(config.http.port, 3333);
    assert.equal(config.auth.sessionSecretGenerated, true);
    assert.equal(config.payments.stripe.successUrl, undefined);
    assert.equal(config.payments.stripe.currency, "usd");
    assert.equal(config.payments.x402.facilitatorUrl, undefined);
    assert.equal(config.logLevel, "info");
  });

  it("parses STACKDNS_TRUST_PROXY into Express-safe values", () => {
    assert.equal(parseTrustProxy("false"), false);
    assert.equal(parseTrustProxy(""), false);
    assert.equal(parseTrustProxy("off"), false);
    assert.equal(parseTrustProxy("true"), 1);
    assert.equal(parseTrustProxy("2"), 2);
    assert.equal(parseTrustProxy("loopback, 10.0.0.0/8"), "loopback, 10.0.0.0/8");
    assert.equal(parseTrustProxy("203.0.113.7,2001:db8::/32"), "203.0.113.7, 2001:db8::/32");
    assert.equal(loadConfig({ STACKDNS_TRUST_PROXY: "true" }, []).http.trustProxy, 1);
    assert.equal(loadConfig({ STACKDNS_TRUST_PROXY: "" }, []).http.trustProxy, false);
  });

  it("rejects trust-proxy values Express would choke on and accepts what it accepts", () => {
    assert.throws(() => parseTrustProxy("banana"), /STACKDNS_TRUST_PROXY/);
    assert.throws(() => parseTrustProxy("-1"), /STACKDNS_TRUST_PROXY/);
    assert.throws(() => parseTrustProxy("10.0.0.0/33"), /STACKDNS_TRUST_PROXY/);
    assert.throws(() => loadConfig({ STACKDNS_TRUST_PROXY: "banana" }, []), /STACKDNS_TRUST_PROXY/);
    assert.equal(parseTrustProxy(","), false);
    assert.equal(parseTrustProxy("10.0.0.0/255.0.0.0"), "10.0.0.0/255.0.0.0");
    assert.equal(parseTrustProxy("uniquelocal, 2001:db8::1"), "uniquelocal, 2001:db8::1");
  });

  it("treats quoted blanks as unset, keeps quotes that are part of a value, and leaves blank booleans on their defaults", () => {
    const config = loadConfig({ STACKDNS_TRANSPORT: "http", STACKDNS_SESSION_SECRET: '""', STRIPE_SUCCESS_URL: "''", STACKDNS_REQUIRE_AUTH: "", STACKDNS_USER_AGENT: '"quoted agent"' }, []);
    assert.equal(config.auth.sessionSecretGenerated, true);
    assert.equal(config.payments.stripe.successUrl, undefined);
    assert.equal(config.auth.requireAuth, true, "blank means default, and the http default is true");
    assert.equal(config.inspection.userAgent, '"quoted agent"', "quotes inside a real value are data");
    assert.equal(loadConfig({ STACKDNS_TRANSPORT: "http", STACKDNS_REQUIRE_AUTH: "false" }, []).auth.requireAuth, false);
  });

  it("lets operators disable DNS fallback explicitly and exposes the pre-auth ceiling", () => {
    assert.deepEqual(loadConfig({ STACKDNS_DNS_FALLBACK_SERVERS: "none" }, []).inspection.dnsFallbackServers, []);
    assert.deepEqual(loadConfig({ STACKDNS_DNS_FALLBACK_SERVERS: "9.9.9.9" }, []).inspection.dnsFallbackServers, ["9.9.9.9"]);
    assert.deepEqual(loadConfig({}, []).inspection.dnsFallbackServers, ["1.1.1.1", "8.8.8.8", "9.9.9.9"]);
    assert.equal(loadConfig({}, []).auth.unauthenticatedPerMinute, 60);
    assert.equal(loadConfig({ STACKDNS_UNAUTHENTICATED_PER_MINUTE: "5" }, []).auth.unauthenticatedPerMinute, 5);
    assert.equal(loadConfig({}, []).inspection.dnsCacheTtlMs, 30000);
    assert.equal(loadConfig({ STACKDNS_DNS_CACHE_TTL_MS: "0" }, []).inspection.dnsCacheTtlMs, 0);
    assert.throws(() => loadConfig({ STACKDNS_DNS_CACHE_TTL_MS: "-1" }, []), /Invalid environment/);
  });
});
